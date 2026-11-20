"""Unit tests for the openapi-coverage module: pure, no network (sender is stubbed)."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


OC = _load("run_openapi_coverage_t", "tests/openapi-coverage/run_openapi_coverage.py")
RP = _load("report_oc_t", "report.py")

SPEC = {
    "openapi": "3.0.0",
    "security": [{"cookieAuth": []}],
    "paths": {
        "/users": {"get": {}, "post": {}},                                  # inherits global security (protected)
        "/users/{id}": {"get": {}, "delete": {}},
        "/login": {"post": {"security": []}},                               # explicitly public
        "/captcha": {"get": {"security": []}},
        "/laporan": {"get": {"security": [{"cookieAuth": []}]}},
    },
}
CFG = {"base_url": "http://t.example/api"}


# is_protected / operations
def test_is_protected():
    assert OC.is_protected([{"bearer": []}]) is True
    assert OC.is_protected([]) is False and OC.is_protected(None) is False
    assert OC.is_protected([{}]) is False                  # {} = optional auth
    assert OC.is_protected([{"a": []}, {}]) is False       # one alternative is optional


def test_operations_inherit_global_security():
    ops = {(o["method"], o["path"]): o for o in OC.operations(SPEC)}
    assert ops[("GET", "/users")]["declared"] is True                  # inherited from global security
    assert ops[("POST", "/login")]["declared"] is False
    assert ops[("POST", "/login")]["explicit_public"] is True
    assert ops[("GET", "/laporan")]["declared"] is True
    no_global = OC.operations({"paths": {"/x": {"get": {}}}})
    assert no_global[0]["declared"] is False and no_global[0]["explicit_public"] is False


def test_fill_path():
    assert OC.fill_path("/users/{id}", {}) == "/users/" + OC.PLACEHOLDER_ID
    assert OC.fill_path("/a/{slug}", {}) == "/a/x"
    assert OC.fill_path("/a/{id}/b/{name}", {"id": "7", "name": "n"}) == "/a/7/b/n"


def test_classify():
    assert OC.classify(401) == "enforced" and OC.classify(403) == "enforced"
    assert OC.classify(200) == "open" and OC.classify(204) == "open"
    assert OC.classify(500) == "error" and OC.classify(None) == "inconclusive"
    assert OC.classify(404) == "inconclusive" and OC.classify(422) == "inconclusive"


# analyze
def _run(spec, answers, cfg=None):
    sent = []

    def send(url):
        sent.append(url)
        for suffix, st in answers.items():
            if url.endswith(suffix):
                return st
        return 401
    rows = OC.analyze(OC.operations(spec), send, {**CFG, **(cfg or {})})
    return rows, sent


def test_all_enforced_no_findings():
    rows, sent = _run(SPEC, {"/captcha": 200})
    assert not [r for r in rows if not r["ok"]]
    assert any("penegakan autentikasi" in r["check"] for r in rows)


def test_protected_per_spec_but_open():
    rows, _ = _run(SPEC, {"/laporan": 200})
    f = [r for r in rows if not r["ok"]]
    assert len(f) == 1 and f[0]["kind"] == "auth-coverage-gap"
    assert "dilindungi menurut spesifikasi" in f[0]["check"] and f[0]["status"] == 200


def test_allowlisted_public_but_spec_says_protected_is_spec_mismatch():
    # /captcha is in the default allowlist, but the spec (global security) treats it as protected.
    spec = {"security": [{"cookieAuth": []}], "paths": {"/captcha": {"get": {}},
                                                         "/health": {"get": {}}}}
    rows, _ = _run(spec, {"/captcha": 200, "/health": 200})
    f = [r for r in rows if not r["ok"]]
    assert len(f) == 1 and f[0]["kind"] == "spec-mismatch"           # not auth-coverage-gap
    assert "2 operasi GET publik" in f[0]["note"] and "security: []" in f[0]["note"]


def test_5xx_on_anonymous_request_is_finding():
    rows, _ = _run(SPEC, {"/laporan": 500})
    f = [r for r in rows if not r["ok"]]
    assert len(f) == 1 and f[0]["kind"] == "anon-server-error" and f[0]["status"] == 500
    assert "error server" in f[0]["check"]


def test_open_without_declaration_and_outside_allowlist():
    spec = {"paths": {"/rahasia": {"get": {}}, "/health": {"get": {}}}}
    rows, _ = _run(spec, {"/rahasia": 200, "/health": 200})
    f = [r for r in rows if not r["ok"]]
    assert len(f) == 1 and f[0]["kind"] == "unauthenticated-endpoint"
    assert "/rahasia" in f[0]["check"]            # /health is in the default allowlist


def test_inaccurate_spec_is_aggregated():
    spec = {"paths": {"/a": {"get": {}}, "/b": {"get": {}}, "/c": {"get": {}}}}
    rows, _ = _run(spec, {})                                    # all 401, no declarations
    f = [r for r in rows if not r["ok"]]
    assert len(f) == 1 and f[0]["kind"] == "spec-mismatch" and "3 operasi" in f[0]["note"]


def test_write_operations_are_never_sent():
    rows, sent = _run(SPEC, {})
    assert all("/login" not in u or u.endswith("/captcha") for u in sent)
    methods_get = {o["path"] for o in OC.operations(SPEC) if o["method"] == "GET"}
    assert len(sent) == len(methods_get)                       # GET operations only


def test_max_requests_limits_probes():
    spec = {"paths": {f"/p{i}": {"get": {}} for i in range(10)}}
    _, sent = _run(spec, {}, {"max_requests": 3})
    assert len(sent) == 3


def test_inconclusive_404_is_not_a_finding():
    rows, _ = _run(SPEC, {"/laporan": 404, "/users/" + OC.PLACEHOLDER_ID: 404})
    assert not [r for r in rows if not r["ok"] and r["kind"] == "auth-coverage-gap"]


def test_custom_allowlist():
    spec = {"paths": {"/katalog": {"get": {}}}}
    rows, _ = _run(spec, {"/katalog": 200}, {"public_allowlist": ["/katalog"]})
    assert not [r for r in rows if not r["ok"]]


# run_spec (spec loaded from file, base_url from servers)
def test_run_spec_from_file_and_servers(tmp_path, monkeypatch):
    spec = {**SPEC, "servers": [{"url": "http://t.example/api"}]}
    p = tmp_path / "o.json"
    p.write_text(json.dumps(spec), encoding="utf-8")

    class _R:
        status_code = 401

    class _S:
        verify = True

        def get(self, url, **kw):
            return _R()
    monkeypatch.setattr(OC.requests, "Session", lambda: _S())
    rows = OC.run_spec({"openapi": str(p), "name": "svc"})
    assert any(r["check"].startswith("[svc] cakupan spesifikasi") for r in rows)


# report integration
def test_report_includes_openapi_coverage(tmp_path):
    rows, _ = _run(SPEC, {"/laporan": 200})
    (tmp_path / "openapi_coverage.json").write_text(json.dumps(
        {"module": "openapi-coverage", "failures": 1, "results": rows}), encoding="utf-8")
    f = RP.collect(tmp_path)
    failed = [x for x in f if not x["passed"]]
    assert failed and failed[0]["kind"] == "auth-coverage-gap" and failed[0]["severity"] == "high"
    assert RP.cvss_for("unauthenticated-endpoint", "medium")[0] == 5.3
    assert {"auth-coverage-gap", "unauthenticated-endpoint", "spec-mismatch"} <= set(RP.KIND_LABEL)
