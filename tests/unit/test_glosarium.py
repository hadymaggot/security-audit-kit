"""Glossary tests: loading, language selection, italics, and a guard that no display string
still uses a word the glossary maps to a canonical technical term."""
import ast
import importlib.util
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


G = _load("glossary_t", "glossary.py")


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SAK_LANG", "SAK_PROJECT_DIR"):
        monkeypatch.delenv(k, raising=False)
    G.reset_cache()
    yield
    G.reset_cache()


# --- loading and language selection ---------------------------------------------------------
def test_languages_match_documentation():
    assert G.languages() == ["de", "en", "id"]
    assert G.default_lang() == "id"


def test_requested_vs_effective_language(monkeypatch):
    assert (G.requested_lang(), G.effective_lang()) == ("id", "id")
    monkeypatch.setenv("SAK_LANG", "de")
    G.reset_cache()
    assert (G.requested_lang(), G.effective_lang()) == ("de", "de")     # the en and de text catalogs are complete


def test_unknown_language_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("SAK_LANG", "xx")
    assert G.requested_lang() == "id"


def test_project_language_and_glossary_override(tmp_path, monkeypatch):
    (tmp_path / "config").mkdir()
    (tmp_path / "config" / "targets.yml").write_text("report:\n  language: de\n", encoding="utf-8")
    (tmp_path / "config" / "glosarium.yml").write_text(
        "languages:\n  id:\n    terms: [webhook]\n    map:\n      gawai: device\n", encoding="utf-8")
    assert G.requested_lang(tmp_path) == "de"
    assert "webhook" in G.load("id", tmp_path)["terms"]
    assert G.load("id", tmp_path)["map"]["gawai"] == "device"
    assert "response" in G.load("id", tmp_path)["terms"]       # kit terms are kept
    assert G.italic_html("a webhook call", "id", tmp_path) == "a <i>webhook</i> call"


# --- italics ----------------------------------------------------------------------------------
def test_italic_html_skips_code_attributes_and_identifiers():
    out = G.italic_html('Cookie sesi di response. <code>response</code> <a href="/response">x</a> '
                        'Set-Cookie /api/session session_id password.', "id")
    assert out.startswith("<i>Cookie</i> sesi di <i>response</i>.")
    assert "<code>response</code>" in out and 'href="/response"' in out
    assert "Set-Cookie" in out and "/api/session" in out and "session_id" in out
    assert out.endswith("<i>password</i>.")


def test_italic_html_multiword_plural_and_case():
    assert G.italic_html("Information disclosure on two Requests", "id") == \
        "<i>Information disclosure</i> on two <i>Requests</i>"


def test_italic_md_skips_code_links_urls_and_emphasis():
    src = "Lihat `response.json`, [response](http://x/response) dan https://x.io/response. **Request** ok.\n" \
          "```\nresponse = 1\n```\npassword lemah."
    out = G.italic_md(src, "id")
    assert "`response.json`" in out and "[response](http://x/response)" in out
    assert "https://x.io/response." in out and "**Request**" in out and "response = 1" in out
    assert out.endswith("*password* lemah.")


def test_adjacent_terms_share_one_italic_span():
    assert G.italic_html("Security header response ok", "id") == "Security <i>header response</i> ok"
    assert G.italic_md("Security header response ok", "id") == "Security *header response* ok"


def test_english_text_is_not_italicized():
    assert G.italic_html("The response and password.", "en") == "The response and password."
    assert G.italic_md("The response.", "en") == "The response."


def test_italics_follow_effective_language_by_default(monkeypatch):
    assert G.italic_html("response") == "<i>response</i>"      # default en -> text is still id
    monkeypatch.setattr(G, "effective_lang", lambda project=None: "en")
    assert G.italic_html("response") == "response"


# --- canonical-term mapping -------------------------------------------------------------------
def test_canonicalize_keeps_case_and_applies_phrases_first():
    assert G.canonicalize("Kebocoran info: sandi bocor di respons; Berkas terekspos", "id") == \
        "Information disclosure: password breached di response; File exposed"
    assert G.canonicalize("kata sandi lemah, header pembocor info", "id") == \
        "password lemah, header information disclosure"


def test_canonicalize_whole_words_only():
    assert G.canonicalize("responsif dan sesinya", "id") == "responsif dan sesinya"


# --- reports and CLI --------------------------------------------------------------------------
def _headers_report(tmp_path):
    rd = tmp_path / "reports"
    rd.mkdir()
    (rd / "headers.json").write_text(
        '{"module": "headers", "failures": 1, "results": [{"label": "Header hilang: x-frame-options", '
        '"status": null, "ok": false, "note": "header x-frame-options tidak diset pada response"}]}',
        encoding="utf-8")
    return rd


def test_reports_italicize_terms_in_every_format(tmp_path, monkeypatch):
    import sys
    rp = _load("report_gl_t", "report.py")
    rd = _headers_report(tmp_path)
    monkeypatch.setenv("SAK_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(sys, "argv", ["report.py", "--dir", str(rd)])
    rp.main()
    md = (rd / "laporan.md").read_text(encoding="utf-8")
    html = (rd / "laporan.html").read_text(encoding="utf-8")
    slides = (rd / "laporan-slides.html").read_text(encoding="utf-8")
    assert "*response*" in md.lower() or "*header*" in md.lower()
    assert "<i>" in html and "<i>" in slides
    assert "<code>" in html and "<i>x-frame-options" not in html        # identifiers stay plain
    assert "<i>" not in (rd / "headers.json").read_text(encoding="utf-8")  # stored data untouched


def test_reports_are_plain_for_an_english_catalog(tmp_path, monkeypatch):
    import sys
    rp = _load("report_gl_en_t", "report.py")
    rd = _headers_report(tmp_path)
    monkeypatch.setenv("SAK_PROJECT_DIR", str(tmp_path))
    monkeypatch.setattr(rp.glossary, "effective_lang", lambda project=None: "en")
    monkeypatch.setattr(sys, "argv", ["report.py", "--dir", str(rd)])
    rp.main()
    assert "<i>" not in (rd / "laporan.html").read_text(encoding="utf-8")


def test_lang_option(monkeypatch):
    au = _load("audit_gl_t", "audit.py")
    assert au.pop_lang_arg(["--lang", "DE", "all"]) == ("de", ["all"])
    assert au.pop_lang_arg(["all", "--lang=id"]) == ("id", ["all"])
    assert au.pop_lang_arg(["all"]) == (None, ["all"])
    with pytest.raises(SystemExit) as e:
        au.pop_lang_arg(["--lang", "xx"])
    assert e.value.code == 2


def test_main_exports_lang_to_children(monkeypatch):
    au = _load("audit_gl_main_t", "audit.py")
    monkeypatch.setattr(au, "mod_clean", lambda: 0)
    au.PROJECT = au.ROOT
    assert au.main(["--lang", "de", "clean"]) == 0
    assert os.environ["SAK_LANG"] == "de"
    for k in ("SAK_LANG", "SAK_PROJECT_DIR"):
        os.environ.pop(k, None)


# --- guard: display text must use the canonical terms -----------------------------------------
DISPLAY_CALLS = {"print", "echo", "row", "row_info", "row_other_sessions", "row_old_password",
                 "SnapshotError", "ArgumentParser", "add_argument"}
STORE_KEYS = {"note", "label", "check", "case", "endpoint", "expected", "name", "description", "impact",
              "severity_basis", "recommendation", "references", "title"}
ASSIGN_NAMES = {"note", "mark", "verdict", "label", "msg", "message"}
REGEX_CALLS = {"compile", "search", "match", "sub", "findall", "split", "fullmatch", "finditer"}
FULL_FILES = {"remediation.py", "report.py"}      # every string is display text (or a classifier keyword)


def _docstrings(tree):
    ids = set()
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.body:
            b = n.body[0]
            if isinstance(b, ast.Expr) and isinstance(getattr(b, "value", None), ast.Constant):
                ids.add(id(b.value))
    return ids


def _is_display(node, parents, full):
    n = node
    while n in parents:
        p = parents[n]
        if isinstance(p, ast.Call):
            fn = getattr(p.func, "id", None) or getattr(p.func, "attr", "")
            if fn in REGEX_CALLS:
                return False
            if fn in DISPLAY_CALLS or fn.endswith("Error"):
                return True
        elif isinstance(p, ast.Dict):
            for k, v in zip(p.keys, p.values):
                if v is n or any(x is n for x in ast.walk(v)):
                    return isinstance(k, ast.Constant) and (k.value in STORE_KEYS or full)
        elif isinstance(p, ast.Assign):
            name = getattr(p.targets[0], "id", getattr(p.targets[0], "attr", ""))
            return False if name.endswith(("_RE", "RX")) else (name in ASSIGN_NAMES or full)
        elif isinstance(p, ast.Compare):
            return full
        elif isinstance(p, (ast.Return, ast.Tuple)):    # (ok, note) pairs, labels, return messages
            return True
        n = p
    return full


def _display_files():
    files = [ROOT / "audit.py", ROOT / "report.py", ROOT / "remediation.py"]
    files += sorted((ROOT / "tests").glob("*/run_*.py"))
    files += [ROOT / "tests" / n for n in ("_fixture.py", "_rollback.py", "_snapshot.py", "_sanctum.py", "_screenshot.py")]
    return files


def test_display_text_uses_canonical_terms():
    offenders = []
    for f in _display_files():
        tree = ast.parse(f.read_text(encoding="utf-8"))
        parents = {c: p for p in ast.walk(tree) for c in ast.iter_child_nodes(p)}
        docs = _docstrings(tree)
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in docs \
                    and _is_display(n, parents, f.name in FULL_FILES):
                fixed = G.canonicalize(n.value, "id")
                if fixed != n.value:
                    offenders.append(f"{f.relative_to(ROOT).as_posix()}:{n.lineno}: {n.value.strip()[:70]!r}")
    assert not offenders, "use the glossary term (see glosarium.yml):\n" + "\n".join(offenders)
