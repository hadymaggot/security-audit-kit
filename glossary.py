"""Per-language technical glossary loaded from glosarium.yml.

Language: --lang (sets SAK_LANG) > SAK_LANG > report.language in targets.yml > glossary default.
Terms live in the YAML (kit root, plus optional <project>/config/glosarium.yml); no code changes
are needed to add a term or a language.
"""
from __future__ import annotations

import os
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
FALLBACK_DEFAULT = "en"
_cache: dict = {}
_rx_cache: dict = {}


def _read(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
    except Exception:  # noqa: BLE001 - a broken file must never break a report
        data = {}
    return data if isinstance(data, dict) else {}


def project_dir() -> Path:
    return Path(os.environ.get("SAK_PROJECT_DIR") or ROOT)


def reset_cache() -> None:
    _cache.clear()
    _rx_cache.clear()


def _raw(project: Path | None = None) -> dict:
    """Kit glossary merged with the project's (if any), cached per project."""
    proj = Path(project) if project else project_dir()
    key = str(proj)
    if key in _cache:
        return _cache[key]
    base = _read(ROOT / "glosarium.yml")
    merged = {"default": str(base.get("default") or FALLBACK_DEFAULT),
              "complete_text": [str(x) for x in (base.get("complete_text") or [])],
              "languages": {}}
    extra = _read(proj / "config" / "glosarium.yml") if proj.resolve() != ROOT else {}
    for src in (base, extra):
        for code, blk in (src.get("languages") or {}).items():
            blk = blk or {}
            cur = merged["languages"].setdefault(
                str(code), {"terms": [], "map": {}, "phrases": [], "italic": True})
            if "italic" in blk:
                cur["italic"] = bool(blk["italic"])
            cur["terms"] += [str(x) for x in (blk.get("terms") or []) if str(x).strip()]
            cur["map"].update({str(k).lower(): str(v) for k, v in (blk.get("map") or {}).items()})
            cur["phrases"] += [tuple(x) for x in (blk.get("phrases") or [])
                             if isinstance(x, (list, tuple)) and len(x) == 2]
    if extra.get("default"):
        merged["default"] = str(extra["default"])
    _cache[key] = merged
    return merged


def languages(project: Path | None = None) -> list[str]:
    return sorted(_raw(project)["languages"])


def default_lang(project: Path | None = None) -> str:
    return _raw(project)["default"]


def _project_language(project: Path | None = None) -> str:
    cfg = _read((Path(project) if project else project_dir()) / "config" / "targets.yml")
    rep = cfg.get("report") if isinstance(cfg.get("report"), dict) else {}
    return str(rep.get("language") or cfg.get("language") or "").strip().lower()


def requested_lang(project: Path | None = None) -> str:
    """Language asked for: SAK_LANG, then targets.yml, then the glossary default."""
    langs = languages(project)
    for cand in (os.environ.get("SAK_LANG", "").strip().lower(), _project_language(project)):
        if cand in langs:
            return cand
    d = default_lang(project)
    return d if d in langs else (langs[0] if langs else FALLBACK_DEFAULT)


def effective_lang(project: Path | None = None) -> str:
    """Language of the text actually produced: the requested one if its catalog is complete."""
    req = requested_lang(project)
    complete = _raw(project)["complete_text"]
    return req if not complete or req in complete else complete[0]


def load(lang: str | None = None, project: Path | None = None) -> dict:
    """One language's glossary: istilah (italic terms), padanan, frasa, miring."""
    lang = (lang or effective_lang(project)).lower()
    blk = _raw(project)["languages"].get(lang) or {"terms": [], "map": {}, "phrases": [], "italic": False}
    terms = list(blk["terms"]) + [v for v in blk["map"].values() if re.search(r"[A-Za-z]", v)]
    return {"terms": terms if blk.get("italic", True) else [], "map": dict(blk["map"]),
            "phrases": list(blk["phrases"]), "italic": bool(blk.get("italic", True))}


# Skip terms that are part of an identifier, path, URL, or e-mail; a sentence-final dot is fine.
_BEFORE = r"(?<![\w\-/.@:\\])"
_AFTER = r"(?![\w\-/@\\]|\.\w)"


def _term_rx(lang: str | None = None, project: Path | None = None):
    g = load(lang, project)
    key = (str(project or project_dir()), (lang or effective_lang(project)).lower(), len(g["terms"]))
    if key not in _rx_cache:
        # Longest first so "information disclosure" wins over a shorter overlap.
        terms = sorted({t.strip().lower() for t in g["terms"] if t.strip()}, key=lambda s: (-len(s), s))
        alt = "|".join(re.escape(t).replace(r"\ ", r"\s+") for t in terms)
        _rx_cache[key] = re.compile(rf"{_BEFORE}(?:{alt})(?:e?s)?{_AFTER}", re.I) if terms else None
    return _rx_cache[key]


_SKIP_TAGS = {"code", "pre", "script", "style", "kbd", "samp"}
_TAG_RE = re.compile(r"(<[^>]*>)")


def italic_html(html_text: str, lang: str | None = None, project: Path | None = None) -> str:
    """Wrap terms in <i> on already-escaped HTML; tags and code-like elements are left alone."""
    rx = _term_rx(lang, project)
    if rx is None or not html_text:
        return html_text
    out, skip = [], 0
    for part in _TAG_RE.split(html_text):
        if part.startswith("<") and part.endswith(">"):
            m = re.match(r"</?\s*([A-Za-z0-9]+)", part)
            if m and m.group(1).lower() in _SKIP_TAGS and not part.rstrip().endswith("/>"):
                skip = max(0, skip + (-1 if part.startswith("</") else 1))
            out.append(part)
        elif skip or not part:
            out.append(part)
        else:
            out.append(rx.sub(lambda m: f"<i>{m.group(0)}</i>", part).replace("</i> <i>", " "))
    return "".join(out)


# Markdown spans to leave untouched: code fences, inline code, links/images, URLs.
_MD_SKIP = re.compile(
    r"(```.*?```|~~~.*?~~~|`[^`\n]+`|!?\[[^\]]*\]\([^)]*\)|<https?://[^>]+>|https?://[^\s)>\]]+)", re.S)
_EMPH = re.compile(r"(\*\*[^*]+\*\*|\*[^*\n]+\*|_[^_\n]+_)")


def italic_md(text: str, lang: str | None = None, project: Path | None = None) -> str:
    """Wrap terms in *...* on Markdown; code, links, URLs, and existing emphasis are skipped."""
    rx = _term_rx(lang, project)
    if rx is None or not text:
        return text
    out = []
    for i, part in enumerate(_MD_SKIP.split(text)):
        if i % 2:
            out.append(part)
            continue
        for j, seg in enumerate(_EMPH.split(part)):
            out.append(seg if j % 2 else re.sub(r"\* \*", " ", rx.sub(lambda m: f"*{m.group(0)}*", seg)))
    return "".join(out)


def _keep_case(src: str, dst: str) -> str:
    return dst[:1].upper() + dst[1:] if src[:1].isupper() else dst


def padankan(text: str, lang: str | None = None, project: Path | None = None) -> str:
    """Rewrite words to their canonical terms: ordered `frasa` first, then whole-word `padanan`."""
    g = load(lang, project)
    for pat, rep in g["phrases"]:
        text = re.sub(pat, lambda m, r=rep: _keep_case(m.group(0), r), text)
    for src in sorted(g["map"], key=len, reverse=True):
        text = re.sub(rf"(?<![\w-]){re.escape(src)}(?![\w-])",
                      lambda m, s=src: _keep_case(m.group(0), g["map"][s]), text, flags=re.I)
    return text
