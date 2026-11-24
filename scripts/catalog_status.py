#!/usr/bin/env python3
"""Status of the report text catalogs, like `tx status`: which source strings lack a translation.

Source strings are the Indonesian texts passed to i18n.T() in report.py, plus the named constants
and the alert labels. Exit code 1 when a language is incomplete or a translation breaks a rule:
  - missing     source string without a translation
  - obsolete    translation whose source string no longer exists
  - placeholder translation whose {placeholders} differ from the source
  - kb          knowledge base entry missing, or with a different number of recommendation items

Usage:
  python scripts/catalog_status.py              # all languages under locales/
  python scripts/catalog_status.py --sources    # print the source strings (to start a new language)
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import i18n  # noqa: E402
import remediation  # noqa: E402

# Module-level names in report.py whose value is a source string (or a dict of them).
NAMED = ("METHODOLOGY", "LIMITATIONS", "CLASSIFICATION", "CVSS_NOTE", "REFERENCE_NOTE", "KIND_LABEL")


def _constant(node, env):
    """String value of a literal, an implicit concatenation, or a known module constant; else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.Name) and isinstance(env.get(node.id), str):
        return env[node.id]
    return None


def source_strings(path: Path | None = None) -> list[str]:
    """Every source string of report.py, in order of first appearance, without duplicates."""
    tree = ast.parse((path or ROOT / "report.py").read_text(encoding="utf-8"))
    env: dict = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            try:
                env[node.targets[0].id] = ast.literal_eval(node.value)
            except (ValueError, SyntaxError):
                pass
    found: list[str] = []

    def add(text):
        if isinstance(text, str) and text and text not in found:
            found.append(text)

    for name in NAMED:
        value = env.get(name)
        for item in (value.values() if isinstance(value, dict) else [value]):
            add(item)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "T" and node.args:
            add(_constant(node.args[0], env))
    return found


def check(lang: str) -> list[str]:
    """Problems of one language; an empty list means the catalog is complete."""
    problems = []
    sources = source_strings()
    text = i18n._load("text", lang)
    for src in sources:
        tr = text.get(src)
        if not isinstance(tr, str) or not tr.strip():
            problems.append(f"missing: {src[:70]}")
        elif sorted(i18n.PLACEHOLDER.findall(src)) != sorted(i18n.PLACEHOLDER.findall(tr)):
            problems.append(f"placeholder: {src[:70]}")
    for key in text:
        if key not in sources:
            problems.append(f"obsolete: {str(key)[:70]}")
    kb = i18n._load("kb", lang)
    for kind, entry in remediation.KB.items():
        tr = kb.get(kind)
        if not isinstance(tr, dict):
            problems.append(f"kb missing: {kind}")
            continue
        for field in ("description", "impact", "severity_basis"):
            if not str(tr.get(field) or "").strip():
                problems.append(f"kb {kind}: {field} is empty")
        rec = tr.get("recommendation") or []
        if len(rec) != len(entry["recommendation"]):
            problems.append(f"kb {kind}: {len(rec)} recommendation items, source has {len(entry['recommendation'])}")
            continue
        for src, item in zip(entry["recommendation"], rec):
            if src.startswith("    ") and (not str(item).startswith("    ") or src.count("\n") != str(item).count("\n")):
                problems.append(f"kb {kind}: code sample changed shape")
    for kind in kb:
        if kind not in remediation.KB:
            problems.append(f"kb obsolete: {kind}")
    return problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Status katalog teks report per bahasa.")
    ap.add_argument("--sources", action="store_true", help="cetak string sumber sebagai YAML")
    args = ap.parse_args(argv)
    if args.sources:
        print(yaml.safe_dump({"text": {s: "" for s in source_strings()}}, allow_unicode=True, sort_keys=False, width=1000))
        return 0
    failed = False
    for lang in [x for x in i18n.available() if x != i18n.SOURCE_LANG]:
        problems = check(lang)
        total = len(source_strings())
        print(f"{lang}: {total - sum(p.startswith('missing') for p in problems)}/{total} string, "
              f"{len(problems)} masalah")
        for p in problems:
            print("  " + p)
        failed = failed or bool(problems)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
