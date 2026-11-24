"""Report text catalogs (locales/): complete, placeholder safe, consistent with the glossary, and really used."""
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

import catalog_status as CS  # noqa: E402
import glossary as G  # noqa: E402
import i18n  # noqa: E402
import remediation  # noqa: E402

LANGS = ["en", "de"]


def _report():
    spec = importlib.util.spec_from_file_location("report_i18n_t", ROOT / "report.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RP = _report()


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    for k in ("SAK_LANG", "SAK_PROJECT_DIR"):
        monkeypatch.delenv(k, raising=False)
    G.reset_cache()
    i18n.reset_cache()
    yield
    G.reset_cache()
    i18n.reset_cache()


def test_source_strings_are_found():
    sources = CS.source_strings()
    assert "Ringkasan Eksekutif" in sources and RP.METHODOLOGY in sources
    assert set(RP.KIND_LABEL.values()) <= set(sources)
    assert len(sources) == len(set(sources)) > 80


@pytest.mark.parametrize("lang", LANGS)
def test_catalog_is_complete_and_valid(lang):
    """Same rules as `python scripts/catalog_status.py`: nothing missing, obsolete, or with broken placeholders."""
    assert CS.check(lang) == []


@pytest.mark.parametrize("lang", LANGS)
def test_complete_languages_are_declared_in_the_glossary(lang):
    assert lang in G._raw()["complete_text"] and lang in i18n.available()


@pytest.mark.parametrize("lang", LANGS)
def test_translations_keep_code_samples_identical(lang):
    """Code in a recommendation may only differ in its comments."""
    kb = i18n._load("kb", lang)
    for kind, entry in remediation.KB.items():
        for src, tr in zip(entry["recommendation"], kb[kind]["recommendation"]):
            if src.startswith("    "):
                strip = lambda text: [re.split(r"(//|#|--|<!--)", ln)[0].rstrip() for ln in text.split("\n")]
                assert strip(src) == strip(tr), f"{lang} {kind}: code changed"


@pytest.mark.parametrize("lang", LANGS)
def test_translations_keep_product_and_standard_names(lang):
    """Names that must never be translated stay exactly as in the source (glossary rule)."""
    names = ("OWASP", "ZAP", "Trivy", "testssl.sh", "ASVS", "CVSS", "JWT", "CORS", "TLS", "IDOR", "BOPLA", "SAST")
    text = i18n._load("text", lang)
    for src, tr in text.items():
        for name in names:
            assert src.count(name) == tr.count(name), f"{lang}: '{name}' differs in: {src[:50]}"


def test_source_language_returns_the_source_and_unknown_strings_fall_back():
    assert i18n.T("Ringkasan Eksekutif") == "Ringkasan Eksekutif"
    assert i18n.T("Ringkasan Eksekutif", "en") == "Executive Summary"
    assert i18n.T("teks yang tidak ada di katalog", "en") == "teks yang tidak ada di katalog"
    assert i18n.kb_entry("idor", remediation.KB["idor"], "id") is remediation.KB["idor"]


def test_kb_entry_translates_text_and_keeps_severity_and_references():
    src = remediation.KB["idor"]
    out = i18n.kb_entry("idor", src, "en")
    assert out["description"] != src["description"] and out["severity"] == src["severity"]
    assert out["references"] == src["references"] and len(out["recommendation"]) == len(src["recommendation"])
    assert i18n.kb_entry("no-such-kind", {"description": "x", "recommendation": []}, "en")["description"] == "x"


@pytest.mark.parametrize("lang,title,heading,label", [
    ("id", "Laporan Hasil Uji Keamanan", "Ringkasan Eksekutif", "Dampak"),
    ("en", "Security Test Report", "Executive Summary", "Impact"),
    ("de", "Bericht zum Sicherheitstest", "Management Summary", "Auswirkung"),
])
def test_report_is_written_in_the_requested_language(tmp_path, monkeypatch, lang, title, heading, label):
    monkeypatch.setenv("SAK_LANG", lang)
    G.reset_cache()
    i18n.reset_cache()
    (tmp_path / "upload.json").write_text(json.dumps({"results": [
        {"case": "PDF", "status": 201, "ok": False, "note": "x", "url": "POST http://t/upload"}]}), encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["report.py", "--dir", str(tmp_path)])
    RP.main()
    md = (tmp_path / "laporan.md").read_text(encoding="utf-8")
    html_text = (tmp_path / "laporan.html").read_text(encoding="utf-8")
    slides = (tmp_path / "laporan-slides.html").read_text(encoding="utf-8")
    assert f"# {title}" in md and f"## 1. {heading}" in md and f"**{label}:**" in md
    assert f'<html lang="{lang}">' in html_text and heading in html_text and heading in slides
    if lang != "id":
        assert "Ringkasan Eksekutif" not in md and "Rincian Temuan" not in html_text
        assert remediation.KB["upload-accepted"]["description"][:40] not in md
