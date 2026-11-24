# Glossary and language

The kit keeps one glossary per language, [`glosarium.yml`](../glosarium.yml), so technical terms stay consistent across the console, reports, and documentation.

## Writing rules

- Sentences use the document language; **technical terms keep their original (English) form**, for example response, request, password, session, file, header, endpoint.
- In languages other than English, technical terms are italicized in HTML, Markdown, and slide reports. Product names (OWASP ZAP, Docker, Trivy) and acronyms (CVE, XSS, RCE) are not italicized; code, URLs, and header/path names stay plain.
- One concept, one term. The Indonesian `respons`, `sandi`, `sesi`, `galat`, and `berkas` are always written response, password, session, error, and file; the "bocor" family becomes information disclosure, exposed, or expose.
- Code comments and docstrings are in English, short and clear.

## Choosing the language

Priority: the `--lang id|en|de` option, the `SAK_LANG` environment variable, `report.language` in the project's `targets.yml`, then the glossary default (`id`).

```
python audit.py --project my-app --lang de report
```

The glossary exists for `id`, `en`, and `de`. The report text catalog is complete for `id`, `en`, and `de`. The source text is Indonesian in the code; the translations live in `locales/text.<lang>.yml` (report text) and `locales/kb.<lang>.yml` (description, impact, and recommendation per finding type), working like gettext or Transifex. Per instance evidence produced by the test modules and the console messages stay Indonesian. Languages with a complete catalog are listed in `complete_text` in `glosarium.yml`.

## `glosarium.yml` keys

| Key | Purpose |
|---|---|
| `default` | Default language (`id`). |
| `complete_text` | Languages whose report/console text catalog is complete. |
| `languages.<code>.italic` | `false` when the text is already English so nothing is italicized (default `true`). |
| `languages.<code>.terms` | Terms printed in italics; case-insensitive, plurals and multi-word phrases are matched. |
| `languages.<code>.map` | Local word to canonical term; used by the guard test. |
| `languages.<code>.phrases` | Ordered `[regex, replacement]` pairs for context-dependent words. |

## Adding terms, languages, or a project glossary

Add a term:

1. Add one line to `terms` of the right language.
2. If a local word must be replaced by that term, add a `word: term` pair to `map`.
3. Run `python -m pytest tests/unit/test_glosarium.py`. It fails when display text (console, report, recommendations) still uses a word mapped by `map` or `phrases`.

Other cases:

- **New language:** add one block under `languages` (ISO 639-1 code).
- **One project only:** create `<project-folder>/config/glosarium.yml` with the same structure; it is merged with the kit glossary.
- **The website:** has its own glossary in `site/glosarium.yml` (same structure, not merged with the kit glossary); see the website section of the [contributing guide](../CONTRIBUTING.en.md).

## Language roadmap

1. Per-language glossary, term standardization, and italics (done).
2. English and German report text catalogs (done). Check them with `python scripts/catalog_status.py`, which reports text that is untranslated, obsolete, or has different placeholders.
3. Translation of the per instance evidence from the test modules and of the console messages.
