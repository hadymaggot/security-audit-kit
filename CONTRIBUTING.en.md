[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](CONTRIBUTING.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](CONTRIBUTING.de.md)

# Contributing

Thanks for wanting to help. This toolkit is reused across projects, so the priorities
are: a new check should be **generic** (configured via files, not hardcoded to a target),
**non-destructive**, and every finding must have a **remediation you can stand behind**.

## Quick flow

1. Fork / branch from `main`. One branch = one issue/topic.
2. Make the change + its test.
3. `python -m pytest -q tests/unit` must be green (this is also the CI gate).
4. Open a PR to `main`, fill it in per the template. CI runs automatically.

## Check principles

- **Generic & config-driven.** Targets, endpoints, and credentials go into `*.yml` files
  (e.g. `*.example.yml`) or environment variables — don't embed them in code.
  Credentials **always** go through env vars, never committed.
- **Non-destructive.** By default, only `GET`/reads. If a check genuinely needs an action
  that changes state, turn it off by default and give a clear warning.
- **Timeout = skip, not a finding.** If the target can't be reached, mark it `ok` with a
  `skip:` note; don't count it as a vulnerability.
- **Owned / authorized targets.** Point active scans at dev/staging.

## Adding a new check

One check = one runner at `tests/<name>/run_<name>.py` + an entry in `remediation.py`.

1. **Runner.** Read config via `--config`, support `--json <out>`. Output pattern per
   item: `{"label", "status", "ok": bool, "note"}`. See `tests/cors/run_cors.py`
   as the most compact example. Include `<name>.example.yml`.
2. **Remediation (mandatory).** Add a `KB` entry in `remediation.py` with `description`,
   `impact`, `severity`, `severity_basis`, `recommendation` (a list, may include an
   example fix/code), and `references` (OWASP/BSSN). Map it in `classify()`.
3. **report.py.** Register its JSON file in `collect()` so it is included in the combined report.
4. **audit.py.** Register the module so `python audit.py <name>` works.
5. **Test.** Add a unit test in `tests/unit/` — the runner logic is tested without the
   network (see `_Sess`/`_Resp` in `test_report.py`). `classify()` and `KB` completeness
   must be covered by a test.
6. **Docs.** Update the module table in `README.md` and `docs/temuan-to-test-mapping.md`.

## Language and glossary

- **Code comments and docstrings are in English**, short and clear (explain *why*, do not restate
  the code). Variable, function, and schema key names are English too.
- **Displayed text** (console, reports, recommendations) follows the [glossary](docs/glosarium.en.md):
  sentences in the document language, technical terms stay English and are italicized in reports.
- Adding a term takes one line in `glosarium.yml`; `tests/unit/test_glosarium.py` fails if any
  displayed text still uses a word that has been standardized.

## Website (GitHub Pages)

The site in `docs/` is built; do not edit it directly. Its sources are in `site/`: templates
(`*.template.html`), language dictionaries (`site/i18n/id|en|de.json`), and the site glossary, which
is separate from the kit glossary (`site/glosarium.yml`).

1. Change the template or dictionaries. Add the same key in all three languages.
2. Build: `python scripts/build_site.py` (writes `docs/`, `docs/id/`, `docs/de/`, `sitemap.xml`).
3. Run `python -m pytest tests/unit/test_site.py`; it fails if the build is stale or a dictionary is incomplete.

## Commits & PRs

- **Conventional Commits:** `feat:`, `fix:`, `docs:`, `test:`, `ci:`, `refactor:`,
  `chore:`. Scope optional, e.g. `feat(cors): …`. `feat` → minor, `fix` → patch,
  `!`/`BREAKING CHANGE` → major (SemVer release & tag are created automatically).
- Keep the message short and clear: one subject line, details in the body if needed.
- One PR focuses on one thing. Reference the related issue (`Closes #N`).

## Example output

See [docs/contoh-laporan.md](docs/contoh-laporan.md) for a sense of the final report
shape — severity summary, finding details + recommendations, and the CVE list.
