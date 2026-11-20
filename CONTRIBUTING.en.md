[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](CONTRIBUTING.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](CONTRIBUTING.de.md)

# Contributing

This toolkit is reused across projects. A new check must be **generic** (configured by files, not hardcoded to a target), **non-destructive**, and ship with a **remediation you can stand behind**.

## Set up in 3 minutes

Requirements: Python 3.10+ (CI uses 3.12) and git. Docker is needed only to run the scanners (ZAP, Trivy, ...), not the unit tests.

```bash
git clone https://github.com/hadymaggot/security-audit-kit.git
cd security-audit-kit
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest tests/unit -q
```

Expected: all tests pass in about a minute, with no live target. Then branch from `main`, one branch per topic.

## Project layout

| Path | What lives there |
|---|---|
| `audit.py` | CLI entry point; the module registry `PY_MODULES` |
| `tests/<folder>/` | One check: `run_<x>.py` runner + `<x>.example.yml` config (model: `tests/cors/`) |
| `tests/_*.py` | Shared helpers (color, fixture, rollback, snapshot, Sanctum login, screenshot) |
| `tests/unit/` | Unit tests; this is the CI gate |
| `config/targets.example.yml` | Example target config; copy to the gitignored `config/targets.yml` |
| `scanners/` | Wrappers for ZAP, testssl, headers, trivy/semgrep/gitleaks |
| `remediation.py` | Remediation knowledge base `KB` and `classify()` |
| `report.py` | `collect()` and the HTML/Markdown/slide report |
| `glossary.py`, `glosarium.yml` | Glossary loader and per-language glossary data |
| `site/`, `scripts/` | Website sources; `build_site.py`, `italicize_docs.py` |
| `docs/` | Markdown docs (hand-written) and the built website |
| `worker/` | Cloudflare Worker for the passive open scanner demo |
| `.github/workflows/` | `ci.yml`, `release.yml`, `security-audit.yml` |

Final report shape: [docs/contoh-laporan.md](docs/contoh-laporan.md).

## Add a new check

Rules every check follows:

- **Config-driven.** Targets and endpoints go in `*.yml`; credentials only via environment variables, never committed.
- **Read-only by default.** `GET`/reads only. A state-changing action is off by default, with a clear warning, and its writes go through `tests/_rollback.py`.
- **Timeout = skip, not a finding.** Mark it `ok` with a `skip:` note.
- **Authorized targets only.** Point active scans at dev/staging.

Checklist (`<x>` = file name part, `<folder>` = folder under `tests/`, `<kind>` = KB key):

1. **Runner.** Create `tests/<folder>/run_<x>.py` and `tests/<folder>/<x>.example.yml`. The runner accepts `--config` and `--json <out>`, prints a table, and exits 1 when there are findings. Each result is `{"label", "status", "ok": bool, "note"}`; the JSON file is `{"module", "failures", "results"}`.
2. **audit.py.** Add one entry to `PY_MODULES`. This enables `python audit.py <name>`, `init`, and `all` (which runs the module when its config exists in the project). If the check writes to the target, also add `<name>` to `ROLLBACK_AFTER`.
3. **report.py.** Add `("<x>.json", "<folder>")` to the tuple in `collect()`.
4. **remediation.py, KB (mandatory).** Add `KB["<kind>"]` with exactly these keys.
5. **remediation.py, classify.** Map the result to `<kind>` in `classify(module, title)`. Alternatively set `kind` on each result and add the module to the kind-hint branch in `collect()`. An unmapped result falls back to `zap-generic`.
6. **Tests.** Add `tests/unit/test_<x>.py` for the runner logic without network (fake session, see `_Sess`/`_Resp` in `tests/unit/test_authz_matrix.py`), a `classify()` assertion and a `collect()` case in `tests/unit/test_report.py`. `test_all_kb_entries_wellformed` already checks every KB entry.
7. **Docs.** Add a row in the module table of `README.md`/`.en.md`/`.de.md`, in `docs/temuan-to-test-mapping*.md`, and in the stages of `docs/metodologi*.md` (all three languages). A `Makefile` or `audit.ps1` shortcut is optional.

```python
"<name>": ("<folder>", "run_<x>.py", "<x>.yml", "<x>.json"),
```

```python
"<kind>": {
    "description": "...",
    "impact": "...",
    "severity": "Medium",
    "severity_basis": "...",
    "recommendation": ["...", "..."],
    "references": ["..."],
},
```

KB rules: `severity` is one of Critical, High, Medium, Low, Info; `severity_basis` states Likelihood x Impact; `recommendation` is a non-empty list that may include an example fix; `references` is a non-empty list (OWASP, BSSN).

## Language and glossary rules

1. Code comments and docstrings are in English, short, and explain why.
2. Identifiers and schema keys (config, JSON, KB) are in English. `tests/unit/test_english_code.py` guards this.
3. Displayed text (console, reports, recommendations) follows the [glossary](docs/glosarium.en.md): sentences in the document language, technical terms in English. Today the text catalog exists in Indonesian only.
4. Add a term with one line in `glosarium.yml`. `tests/unit/test_glosarium.py` fails if displayed text still uses a word the glossary standardizes.
5. Docs: `tests/unit/test_docs.py` requires the same `##` sections and the same commands in all three languages, and valid links. After editing an Indonesian doc, run:

```bash
python scripts/italicize_docs.py
```

## Website

`docs/index.html`, `docs/scan.html`, `docs/id/`, `docs/de/`, and `docs/sitemap.xml` are generated; do not edit them. Sources are in `site/`: templates (`*.template.html`), dictionaries (`site/i18n/id|en|de.json`), and the site glossary (`site/glosarium.yml`), which is separate from the kit glossary.

1. Edit a template or dictionary. Add the same key in all three languages.
2. Build the site.
3. Run the site test; it fails if the build is stale or a dictionary is incomplete.

```bash
python scripts/build_site.py
python -m pytest tests/unit/test_site.py -q
```

## Commits and PRs

1. Use Conventional Commits: `type(scope): description`, with types `feat`, `fix`, `docs`, `test`, `ci`, `refactor`, `chore`. `feat` bumps minor, `fix` patch, `!` or `BREAKING CHANGE` major.
2. Keep the subject short; add a body only to explain why. One PR, one intent; reference the issue with `Closes #N`.
3. Fill in the PR template checklist.
4. CI (`ci.yml`) runs on every PR and push to `main`: `py_compile` of `audit.py`, `report.py`, `remediation.py`, and all runners, then `pytest -q tests/unit`. `security-audit.yml` also runs the static scan (`deps`) on PRs; it is informational.
5. A release and SemVer tag are created automatically each month when `main` has new commits (`release.yml`).
