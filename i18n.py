#!/usr/bin/env python3
"""Report text catalog, in the style of gettext/Transifex.

The Indonesian text in the code is the SOURCE string and also the lookup key. Each other language
has resource files under locales/:
  locales/text.<lang>.yml   text: { "<source string>": "<translation>" }
  locales/kb.<lang>.yml     kb:   { <kind>: {description, impact, severity_basis, recommendation[]} }
  locales/evidence.<lang>.yml  evidence: { rules: [[regex, replacement], ...] } for text built at run time

`T(source)` returns the translation for the requested report language, or the source itself when
there is none, so a missing entry never breaks a report. Placeholders such as {total} are kept in
both strings and filled by the caller with str.format. Technical terms follow glosarium.yml.

Language: --lang (sets SAK_LANG) > SAK_LANG > report.language in targets.yml > glossary default.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

import glossary

ROOT = Path(__file__).resolve().parent
LOCALES = ROOT / "locales"
SOURCE_LANG = "id"
_cache: dict[tuple[str, str], dict] = {}
PLACEHOLDER = re.compile(r"\{[a-z_]+\}")


def reset_cache() -> None:
    _cache.clear()
    _rules_cache.clear()


def language() -> str:
    """Language of the report text for this run."""
    return glossary.effective_lang()


def _load(resource: str, lang: str) -> dict:
    key = (resource, lang)
    if key not in _cache:
        path = LOCALES / f"{resource}.{lang}.yml"
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) if path.exists() else {}
        except Exception:  # noqa: BLE001 - a broken catalog must never break a report
            data = {}
        block = (data or {}).get(resource) if isinstance(data, dict) else {}
        _cache[key] = block if isinstance(block, dict) else {}
    return _cache[key]


def T(source: str, lang: str | None = None) -> str:
    """Translation of a source string; the source itself when the language has no entry."""
    lang = lang or language()
    if lang == SOURCE_LANG or not source:
        return source
    found = _load("text", lang).get(source)
    return found if isinstance(found, str) and found else source


def kb_entry(kind: str, entry: dict, lang: str | None = None) -> dict:
    """A knowledge base entry with its text fields translated; untranslated fields keep the source."""
    lang = lang or language()
    if lang == SOURCE_LANG:
        return entry
    translated = _load("kb", lang).get(kind)
    if not isinstance(translated, dict):
        return entry
    out = dict(entry)
    for field in ("description", "impact", "severity_basis"):
        if isinstance(translated.get(field), str) and translated[field]:
            out[field] = translated[field]
    rec = translated.get("recommendation")
    if isinstance(rec, list) and len(rec) == len(entry.get("recommendation") or []):
        out["recommendation"] = [str(x) for x in rec]
    return out


_rules_cache: dict[str, list] = {}


def _rules(lang: str) -> list:
    """Compiled (pattern, replacement) rules of locales/evidence.<lang>.yml; a broken rule is skipped."""
    if lang not in _rules_cache:
        compiled = []
        for rule in _load("evidence", lang).get("rules") or []:
            if isinstance(rule, (list, tuple)) and len(rule) == 2:
                try:
                    compiled.append((re.compile(str(rule[0])), str(rule[1])))
                except re.error:
                    continue
        _rules_cache[lang] = compiled
    return _rules_cache[lang]


def dynamic(text: str, lang: str | None = None) -> str:
    """Translate text built at run time by the test modules (check names, evidence notes).

    The modules always write Indonesian, which the classifier relies on. Their sentences carry values
    (URLs, statuses, counts), so they are translated by ordered regex rules instead of exact strings.
    Text that no rule matches stays as it is."""
    lang = lang or language()
    if lang == SOURCE_LANG or not text:
        return text
    for pattern, replacement in _rules(lang):
        try:
            text = pattern.sub(replacement, text)
        except re.error:
            continue
    return text


def available() -> list[str]:
    """Languages that have a text catalog, the source language first."""
    found = sorted(p.name.split(".")[1] for p in LOCALES.glob("text.*.yml"))
    return [SOURCE_LANG] + [x for x in found if x != SOURCE_LANG]
