"""Website tests: build is current, dictionaries are complete, the site glossary is obeyed."""
import importlib.util
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


B = _load("build_site_t", "scripts/build_site.py")
G = B.glossary
LANGS = list(B.LANGS)
PAGES = list(B.PAGES)
I18N = {c: json.loads((ROOT / "site" / "i18n" / f"{c}.json").read_text(encoding="utf-8")) for c in LANGS}
FILES = B.build_all()


def test_committed_site_is_up_to_date():
    stale = []
    for rel, text in FILES.items():
        p = ROOT / "docs" / rel
        if not p.exists() or p.read_bytes().decode("utf-8").replace("\r\n", "\n") != text:
            stale.append(rel)
    assert not stale, f"run `python scripts/build_site.py` (stale: {stale})"


def test_all_language_pages_and_sitemap_exist():
    assert set(FILES) == {"index.html", "scan.html", "id/index.html", "id/scan.html",
                          "de/index.html", "de/scan.html", "sitemap.xml"}


@pytest.mark.parametrize("section", ["common", "index", "scan"])
def test_dictionaries_have_the_same_keys_in_every_language(section):
    keys = {c: set(I18N[c][section]) for c in LANGS}
    assert keys["en"] == keys["id"] == keys["de"], {c: keys[c] ^ keys["en"] for c in LANGS}
    assert all(str(v).strip() for c in LANGS for v in I18N[c][section].values())


@pytest.mark.parametrize("rel", [r for r in FILES if r.endswith(".html")])
def test_page_metadata_and_switcher(rel):
    page = FILES[rel]
    lang = rel.split("/")[0] if "/" in rel else "en"
    kind = "scan" if rel.endswith("scan.html") else "index"
    assert "{{" not in page and f'<html lang="{lang}">' in page
    assert f'<link rel="canonical" href="{B.page_url(lang, kind)}">' in page
    assert page.count('rel="alternate" hreflang=') == len(LANGS) + 1           # + x-default
    assert page.count("aria-current=") == 1 and f'hreflang="{lang}" lang="{lang}"' in page


def test_sitemap_lists_every_language_with_alternates():
    sm = FILES["sitemap.xml"]
    for lang in LANGS:
        assert f"<loc>{B.page_url(lang, 'index')}</loc>" in sm and f"<loc>{B.page_url(lang, 'scan')}</loc>" in sm
    assert sm.count('hreflang="x-default"') == 6          # one per language entry of index and scan


def test_english_pages_have_no_glossary_italics_and_others_do():
    plain = re.compile(r"<i>")                                      # glossary italics have no attributes
    assert not plain.search(FILES["index.html"]) and not plain.search(FILES["scan.html"])
    assert plain.search(FILES["id/index.html"]) and plain.search(FILES["de/index.html"])


def test_dictionaries_obey_the_site_glossary():
    """Non-English text must not use a word the site glossary maps to a canonical term."""
    key = G.use_standalone(ROOT / "site" / "glosarium.yml")
    bad = []
    for lang in ("id", "de"):
        for sec in ("index", "scan"):
            for k, v in I18N[lang][sec].items():
                text = re.sub(r"<[^>]+>", "", v)
                if G.canonicalize(text, lang, key) != text:
                    bad.append(f"{lang}.json {sec}.{k}")
    assert not bad, "use the glossary term (site/glosarium.yml): " + ", ".join(bad)


def test_site_glossary_is_separate_from_the_kit_glossary():
    key = G.use_standalone(ROOT / "site" / "glosarium.yml")
    assert "entry point" in G.load("id", key)["terms"]
    assert "entry point" not in G.load("id", ROOT)["terms"]          # kit glossary is untouched


def test_template_placeholders_are_all_resolved_and_keys_used():
    for page in PAGES:
        tpl = (ROOT / "site" / f"{page}.template.html").read_text(encoding="utf-8")
        used = set(re.findall(r"\{\{(\w+)\}\}", tpl)) | set(re.findall(r"\bT\.(\w+)", tpl))
        computed = {"lang", "canonical", "og_locale", "hreflangs", "langswitch", "base", "t_json", "ld_desc_json"}
        missing = used - computed - set(I18N["en"]["common"]) - set(I18N["en"][page])
        assert not missing, f"{page}: keys without a dictionary entry: {missing}"


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("rel", [r for r in FILES if r.endswith(".html")])
def test_page_javascript_is_syntactically_valid(rel):
    scripts = re.findall(r"<script(?![^>]*\bsrc=)(?![^>]*ld\+json)[^>]*>(.*?)</script>", FILES[rel], re.S)
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "page.js"
        p.write_text("\n;\n".join(scripts), encoding="utf-8")
        r = subprocess.run(["node", "--check", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[:400]


def test_json_ld_is_valid_json():
    for rel in [r for r in FILES if r.endswith("index.html")]:
        m = re.search(r'<script type="application/ld\+json">(.*?)</script>', FILES[rel], re.S)
        data = json.loads(m.group(1))
        assert data["@type"] == "SoftwareApplication" and data["inLanguage"] in LANGS
