#!/usr/bin/env python3
"""Italicize technical terms in the Indonesian docs using the kit glossary (idempotent).

    python scripts/italicize_docs.py          # rewrite the files in place
    python scripts/italicize_docs.py --check  # exit 1 if any file would change

Code blocks, inline code, links, URLs, and text that is already emphasized are left alone.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import glossary  # noqa: E402

FILES = ["README.md", "CONTRIBUTING.md", "docs/panduan-penggunaan.md", "docs/metodologi.md",
         "docs/temuan-to-test-mapping.md", "docs/glosarium.md"]


def main(argv: list[str]) -> int:
    changed = []
    for rel in FILES:
        path = ROOT / rel
        old = path.read_bytes().decode("utf-8")
        nl = "\r\n" if "\r\n" in old else "\n"
        new = glossary.italic_md(old.replace("\r\n", "\n"), "id").replace("\n", nl)
        if new != old:
            changed.append(rel)
            if "--check" not in argv:
                path.write_bytes(new.encode("utf-8"))
    print(("would change: " if "--check" in argv else "updated: ") + (", ".join(changed) or "nothing"))
    return 1 if changed and "--check" in argv else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
