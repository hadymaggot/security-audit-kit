#!/usr/bin/env python3
"""Build the multilingual static site into docs/ from site/ (templates + dictionaries + glossary).

    python scripts/build_site.py           # write docs/, docs/id/, docs/de/ and docs/sitemap.xml
    python scripts/build_site.py --check   # exit 1 if the committed output is stale

Edit site/*.template.html and site/i18n/<lang>.json, then rebuild. GitHub Pages serves docs/ as is.
"""
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import glossary  # noqa: E402

SITE, DOCS = ROOT / "site", ROOT / "docs"
BASE_URL = "https://hadymaggot.github.io/security-audit-kit/"
# The default language (en) lives at the root; the others in a sub folder.
LANGS = {
    "en": {"dir": "", "locale": "en_US", "flag": "gb", "label": "English"},
    "id": {"dir": "id/", "locale": "id_ID", "flag": "id", "label": "Indonesia"},
    "de": {"dir": "de/", "locale": "de_DE", "flag": "de", "label": "Deutsch"},
}
DEFAULT = "en"
PAGES = {"index": "index.html", "scan": "scan.html"}
STATIC_URLS = [("contoh-laporan.html", "0.7"), ("contoh-laporan-html.html", "0.7"),
               ("contoh-laporan-slides.html", "0.6")]
# Keys that go into attributes or plain text: never italicized.
PLAIN = re.compile(r"^(meta_|og_|ld_|aria_|title$|placeholder$|code_|copy|copied$|term_title$|lg_map$|close$|minimize$)")


def page_url(lang: str, page: str) -> str:
    return BASE_URL + LANGS[lang]["dir"] + ("" if page == "index" else PAGES[page])


def rel_link(frm: str, to: str, page: str) -> str:
    base = "" if LANGS[frm]["dir"] == "" else "../"
    return base + LANGS[to]["dir"] + ("" if page == "index" else PAGES[page])


def hreflangs(page: str) -> str:
    rows = [f'<link rel="alternate" hreflang="{c}" href="{page_url(c, page)}">' for c in LANGS]
    rows.append(f'<link rel="alternate" hreflang="x-default" href="{page_url(DEFAULT, page)}">')
    return "\n".join(rows)


def langswitch(lang: str, page: str) -> str:
    links = []
    for code, meta in LANGS.items():
        cur = ' aria-current="page"' if code == lang else ""
        links.append(f'<a href="{rel_link(lang, code, page)}" hreflang="{code}" lang="{code}" title="{meta["label"]}"{cur}>'
                     f'<img src="https://flagcdn.com/{meta["flag"]}.svg" width="20" alt="{meta["label"]}"></a>')
    return '<span class="tb-lang">\n    ' + "\n    ".join(links) + "\n  </span>"


def build_page(lang: str, page: str, gkey: Path) -> str:
    tpl = (SITE / f"{page}.template.html").read_text(encoding="utf-8")
    data = json.loads((SITE / "i18n" / f"{lang}.json").read_text(encoding="utf-8"))
    values = {**data["common"], **data[page]}

    def render(key: str) -> str:
        v = values[key]
        return html.escape(v, quote=True) if PLAIN.match(key) else glossary.italic_html(v, lang, gkey)

    t_keys = sorted(set(re.findall(r"\bT\.([A-Za-z_0-9]+)", tpl)))
    t_json = json.dumps({k: (values[k] if PLAIN.match(k) else glossary.italic_html(values[k], lang, gkey))
                         for k in t_keys}, ensure_ascii=False).replace("</", "<\\/")
    computed = {
        "lang": lang, "canonical": page_url(lang, page), "og_locale": LANGS[lang]["locale"],
        "hreflangs": hreflangs(page), "langswitch": langswitch(lang, page),
        "base": "" if LANGS[lang]["dir"] == "" else "../", "t_json": t_json,
        "ld_desc_json": json.dumps(values.get("ld_desc", ""), ensure_ascii=False),
    }

    def sub(m: re.Match) -> str:
        key = m.group(1)
        if key in computed:
            return computed[key]
        if key not in values:
            raise KeyError(f"{page}.template.html uses {{{{{key}}}}} but {lang}.json has no such key")
        return render(key)

    return re.sub(r"\{\{([A-Za-z_0-9]+)\}\}", sub, tpl)


def sitemap() -> str:
    def entry(loc: str, prio: str, alts: str = "") -> str:
        return f"  <url><loc>{loc}</loc><priority>{prio}</priority>{alts}</url>"

    rows = []
    for page, prio in (("index", "1.0"), ("scan", "0.9")):
        alts = "".join(f'<xhtml:link rel="alternate" hreflang="{c}" href="{page_url(c, page)}"/>' for c in LANGS)
        alts += f'<xhtml:link rel="alternate" hreflang="x-default" href="{page_url(DEFAULT, page)}"/>'
        rows += [entry(page_url(c, page), prio, alts) for c in LANGS]
    rows += [entry(BASE_URL + name, prio) for name, prio in STATIC_URLS]
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
            + "\n".join(rows) + "\n</urlset>\n")


def build_all() -> dict[str, str]:
    """Relative path (under docs/) -> file content."""
    gkey = glossary.use_standalone(SITE / "glosarium.yml")
    out = {}
    for lang, meta in LANGS.items():
        for page, name in PAGES.items():
            out[meta["dir"] + name] = build_page(lang, page, gkey)
    out["sitemap.xml"] = sitemap()
    return out


def main(argv: list[str]) -> int:
    files = build_all()
    stale = []
    for rel, text in files.items():
        path = DOCS / rel
        current = path.read_bytes().decode("utf-8").replace("\r\n", "\n") if path.exists() else None
        if current != text:
            stale.append(rel)
            if "--check" not in argv:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(text.encode("utf-8"))
    if "--check" in argv:
        print("stale: " + ", ".join(stale) if stale else "site is up to date")
        return 1 if stale else 0
    print(f"built {len(files)} files" + (f" ({len(stale)} changed)" if stale else " (no changes)"))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
