"""Bug bounty scope guard.

Enabled by a `bounty:` block in targets.yml. When it is present the kit only talks to hosts that are
in scope, refuses modules that send attack-like or state-changing traffic (unless the program rules
allow them and they are listed in `allow_active`), and recon drops out-of-scope hosts before probing.

    bounty:
      enabled: true
      in_scope: ["app.example.com", "*.example.com"]
      out_of_scope: ["admin.example.com"]
      max_rps: 5
      allow_active: []

Matching is by hostname only (scheme, port and path are ignored). `*.example.com` matches any
subdomain but NOT the apex `example.com`; list the apex separately. `out_of_scope` always wins.
"""
from __future__ import annotations

import fnmatch
from urllib.parse import urlparse

# Names that need an explicit `allow_active` entry. Python modules use their CLI name; the others are
# `zap-api`, `zap-full` and `recon-active` (port scan, nuclei, crawl, fuzz).
ACTIVE_NAMES = frozenset({
    "injection", "ratelimit", "session-mgmt", "mass-assignment", "upload", "ssrf", "auth-policy", "jwt",
    "zap-api", "zap-full", "recon-active",
})
DEFAULT_MAX_RPS = 5.0


class ScopeError(ValueError):
    """The bounty block is present but unusable."""


def host_of(value) -> str:
    """Lower-case hostname of a URL, `host:port` or bare host; empty string if there is none."""
    v = str(value or "").strip().lower()
    if not v:
        return ""
    if "://" not in v:
        v = "//" + v
    try:
        host = urlparse(v).hostname or ""
    except ValueError:
        return ""
    return host.rstrip(".")


def _match(host: str, pattern: str) -> bool:
    if pattern.startswith("*."):
        suffix = pattern[1:]                      # ".example.com"
        return host.endswith(suffix) and len(host) > len(suffix)
    if "*" in pattern:
        return fnmatch.fnmatchcase(host, pattern)
    return host == pattern


class Scope:
    def __init__(self, in_scope, out_of_scope=(), max_rps=None, allow_active=()):
        self.in_scope = [p for p in (host_of(x) for x in in_scope) if p]
        self.out_of_scope = [p for p in (host_of(x) for x in out_of_scope) if p]
        if not self.in_scope:
            raise ScopeError("bounty.in_scope kosong; isi minimal satu host atau pola *.domain")
        try:
            self.max_rps = float(max_rps) if max_rps is not None else DEFAULT_MAX_RPS
        except (TypeError, ValueError):
            raise ScopeError(f"bounty.max_rps tidak valid: {max_rps!r}") from None
        if self.max_rps <= 0:
            raise ScopeError("bounty.max_rps harus lebih besar dari 0")
        self.allow_active = {str(a) for a in (allow_active or ())}
        unknown = sorted(self.allow_active - ACTIVE_NAMES)
        if unknown:
            raise ScopeError(f"bounty.allow_active tidak dikenal: {', '.join(unknown)}. "
                             f"Pilihan: {', '.join(sorted(ACTIVE_NAMES))}")

    def allows_host(self, value) -> bool:
        host = host_of(value)
        if not host:
            return False
        if any(_match(host, p) for p in self.out_of_scope):
            return False
        return any(_match(host, p) for p in self.in_scope)

    def partition(self, items):
        """Split hosts/URLs into (kept, dropped) by scope, preserving order."""
        kept, dropped = [], []
        for it in items:
            (kept if self.allows_host(it) else dropped).append(it)
        return kept, dropped

    def allows_active(self, name: str) -> bool:
        """True if `name` is not an active check, or the program rules allow it (allow_active)."""
        return name not in ACTIVE_NAMES or name in self.allow_active

    def describe(self) -> str:
        return (f"in_scope={self.in_scope} out_of_scope={self.out_of_scope} "
                f"max_rps={self.max_rps:g} allow_active={sorted(self.allow_active)}")


def load(cfg):
    """Scope from a parsed targets.yml dict; None when bounty mode is not enabled."""
    block = (cfg or {}).get("bounty")
    if not isinstance(block, dict) or not block.get("enabled"):
        return None
    return Scope(block.get("in_scope") or [], block.get("out_of_scope") or [],
                 block.get("max_rps"), block.get("allow_active") or [])
