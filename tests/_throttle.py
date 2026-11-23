"""Transport-level enforcement of the bug bounty scope and rate limit (see _scope.py).

`install(scope)` patches the Python standard library so that EVERY in-process HTTP request, whichever
module made it, is checked and paced centrally:

  * http.client.HTTPConnection.putrequest: runs once per request on the wire (requests, urllib3 and
    urllib all end here, including each redirect hop and each retry). A request to a host outside the
    scope raises ScopeViolation before anything is sent; otherwise it waits for its slot so that the
    traffic never exceeds `max_rps` requests per second in total (spaced evenly, no bursts).
  * socket.create_connection: scope check only (used by raw TLS probes such as webstack).

Nothing is installed unless install() is called, so normal (non-bounty) runs are unchanged.
Tools that run outside this process (Docker scanners, ProjectDiscovery binaries) are not covered here.
"""
from __future__ import annotations

import http.client
import socket
import threading
import time

import _scope


class ScopeViolation(ConnectionError):
    """A request was blocked because its host is outside the bounty scope."""


class RateLimiter:
    """Global pacing: consecutive calls to wait() are at least 1/rate seconds apart (thread-safe)."""

    def __init__(self, rate, clock=time.monotonic, sleep=time.sleep):
        if rate <= 0:
            raise ValueError("rate must be greater than 0")
        self.interval = 1.0 / rate
        self._clock, self._sleep = clock, sleep
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> float:
        """Block until this request's slot; returns the seconds slept."""
        with self._lock:
            now = self._clock()
            slot = max(now, self._next)
            self._next = slot + self.interval
        delay = slot - now
        if delay > 0:
            self._sleep(delay)
        return max(delay, 0.0)


_state = {"scope": None, "limiter": None, "orig": None}


def active() -> bool:
    return _state["scope"] is not None


def _target_host(conn, url) -> str:
    """Host a request is really for: the absolute URL (plain HTTP via a proxy), else the tunnel
    target (HTTPS via a proxy), else the connection host."""
    u = str(url or "")
    if u.lower().startswith(("http://", "https://")):
        return _scope.host_of(u)
    return _scope.host_of(getattr(conn, "_tunnel_host", None) or getattr(conn, "host", ""))


def _block(host, scope):
    raise ScopeViolation(f"mode bounty: host '{host or '?'}' di luar scope, request tidak dikirim "
                         f"(in_scope: {', '.join(scope.in_scope)})")


def install(scope, clock=time.monotonic, sleep=time.sleep):
    """Activate scope enforcement and pacing for this process; replaces an earlier install."""
    uninstall()
    limiter = RateLimiter(scope.max_rps, clock, sleep)
    orig = {"putrequest": http.client.HTTPConnection.putrequest,
            "create_connection": socket.create_connection}

    def putrequest(self, method, url, *args, **kwargs):
        host = _target_host(self, url)
        if not scope.allows_host(host):
            _block(host, scope)
        limiter.wait()
        return orig["putrequest"](self, method, url, *args, **kwargs)

    def create_connection(address, *args, **kwargs):
        host = _scope.host_of(address[0] if isinstance(address, tuple) else address)
        if not scope.allows_host(host):
            _block(host, scope)
        return orig["create_connection"](address, *args, **kwargs)

    http.client.HTTPConnection.putrequest = putrequest
    socket.create_connection = create_connection
    _state.update(scope=scope, limiter=limiter, orig=orig)
    return limiter


def uninstall():
    orig = _state["orig"]
    if orig:
        http.client.HTTPConnection.putrequest = orig["putrequest"]
        socket.create_connection = orig["create_connection"]
    _state.update(scope=None, limiter=None, orig=None)


def guard_context(ctx):
    """Route every request of a Playwright browser context through the scope check and the limiter.

    No-op outside bounty mode. Do not use it where the HTTP cache is what is being tested: Playwright
    routing disables the browser cache."""
    scope, limiter = _state["scope"], _state["limiter"]
    if scope is None:
        return ctx

    def handler(route):
        url = route.request.url
        if url.startswith(("data:", "blob:", "about:")):
            return route.continue_()
        if not scope.allows_host(url):
            return route.abort()
        limiter.wait()
        return route.continue_()

    ctx.route("**/*", handler)
    return ctx
