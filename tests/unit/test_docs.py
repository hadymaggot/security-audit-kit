"""Documentation quality guards: three-language parity, valid links, real commands, Indonesian italics."""
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# Each family: the same document in id (no suffix), en, de.
FAMILIES = {
    "README": ["README.md", "README.en.md", "README.de.md"],
    "CONTRIBUTING": ["CONTRIBUTING.md", "CONTRIBUTING.en.md", "CONTRIBUTING.de.md"],
    "usage-guide": [f"docs/panduan-penggunaan{s}.md" for s in ("", ".en", ".de")],
    "methodology": [f"docs/metodologi{s}.md" for s in ("", ".en", ".de")],
    "finding-to-test-mapping": [f"docs/temuan-to-test-mapping{s}.md" for s in ("", ".en", ".de")],
    "glossary": [f"docs/glosarium{s}.md" for s in ("", ".en", ".de")],
}
ALL_DOCS = [p for fam in FAMILIES.values() for p in fam] + ["docs/contoh-laporan.md", "worker/README.md"]
FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.S | re.M)


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8").replace("\r\n", "\n")


def _commands(text):
    """Command lines of all fenced blocks, comments and blank lines dropped (language independent)."""
    out = []
    for block in FENCE.findall(text):
        for ln in block.splitlines():
            ln = re.sub(r"\s+#.*$", "", ln).rstrip()
            if ln.strip() and not ln.lstrip().startswith("#"):
                out.append(ln.strip())
    return out


def _h2(text):
    return [m for m in re.findall(r"^## .+$", FENCE.sub("", text), re.M)]


def _slug(title):
    t = re.sub(r"[*_`]", "", title.strip().lower())
    t = re.sub(r"[^\w\s-]", "", t, flags=re.U)
    return re.sub(r"\s", "-", t)


@pytest.mark.parametrize("family", FAMILIES)
def test_languages_have_the_same_structure(family):
    id_, en, de = (_read(p) for p in FAMILIES[family])
    assert len(_h2(id_)) == len(_h2(en)) == len(_h2(de)), \
        f"{family}: section count differs id/en/de = {len(_h2(id_))}/{len(_h2(en))}/{len(_h2(de))}"


@pytest.mark.parametrize("family", FAMILIES)
def test_languages_show_the_same_commands(family):
    """Same commands in the same order; only comments and prose are translated."""
    id_, en, de = (_commands(_read(p)) for p in FAMILIES[family])
    assert id_ == en == de, f"{family}: fenced commands differ between languages"


@pytest.mark.parametrize("rel", ALL_DOCS)
def test_relative_links_and_anchors_resolve(rel):
    text = FENCE.sub("", _read(rel))
    base = (ROOT / rel).parent
    bad = []
    for target in re.findall(r"\]\(([^)\s]+)\)", text):
        if re.match(r"^(https?:|mailto:)", target):
            continue
        path, _, anchor = target.partition("#")
        dest = (base / path).resolve() if path else (ROOT / rel)
        if not dest.exists():
            bad.append(f"missing file: {target}")
        elif anchor and dest.suffix == ".md":
            slugs = {_slug(h[h.index(" ") + 1:]) for h in re.findall(r"^#{1,6} .+$", FENCE.sub("", dest.read_text(encoding="utf-8")), re.M)}
            if anchor not in slugs:
                bad.append(f"missing anchor: {target}")
    assert not bad, f"{rel}: " + "; ".join(bad)


def test_documented_audit_commands_exist():
    spec = importlib.util.spec_from_file_location("audit_docs_t", ROOT / "audit.py")
    au = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(au)
    valid = {"all", "init", "zap", "tls", "headers", "deps", *au.PY_MODULES, "recon", "rollback", "report", "clean"}
    bad = []
    for rel in ALL_DOCS:
        for cmd in _commands(_read(rel)):
            m = re.match(r"^(?:python3?|py)\s+(?:\S*audit\.py)\s+(?:--\S+\s+\S+\s+|--\S+\s+)*([a-z][a-z-]*)", cmd)
            if m and m.group(1) not in valid:
                bad.append(f"{rel}: {cmd[:60]}")
    assert not bad, "unknown audit.py module in docs:\n" + "\n".join(bad)


@pytest.mark.parametrize("rel", ["README.md", "CONTRIBUTING.md", "docs/panduan-penggunaan.md", "docs/metodologi.md",
                                 "docs/temuan-to-test-mapping.md", "docs/glosarium.md"])
def test_indonesian_docs_italicize_technical_terms(rel):
    """Run `python scripts/italicize_docs.py` if this fails."""
    spec = importlib.util.spec_from_file_location("glossary_docs_t", ROOT / "glossary.py")
    glossary = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(glossary)
    text = _read(rel)
    assert glossary.italic_md(text, "id") == text, f"{rel}: technical terms must be *italic* (see glosarium.yml)"
