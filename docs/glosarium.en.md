# Glossary and language

The kit uses one glossary per language, [`glosarium.yml`](../glosarium.yml), so technical terms
stay consistent across the console, reports, and documentation.

## Writing rules

- Sentences use the document language; **technical terms keep their original (English) form**,
  for example response, request, password, session, file, header, endpoint.
- In languages other than English, technical terms are printed in *italics* in HTML, Markdown, and
  slide reports. Product names (OWASP ZAP, Docker, Trivy) and acronyms (CVE, XSS, RCE) are not
  italicized; code, URLs, and header/path names stay plain.
- One concept, one term. For example the Indonesian `respons`, `sandi`, `sesi`, `galat`, and `berkas`
  are always written response, password, session, error, and file, and the "bocor" family is
  standardized to information disclosure, exposed, or expose.
- Code comments and docstrings are written in English, short and clear.

## Choosing the language

Priority: the `--lang id|en|de` option, the `SAK_LANG` environment variable, `report.language`
in the project's `targets.yml`, then the glossary default (`en`).

```
python audit.py --project my-app --lang de report
```

The glossary exists for `id`, `en`, and `de` (the documentation languages). The report and console
text catalog is currently complete for `id` only; other languages temporarily reuse the `id`
text while still using their own glossary. Once a language's catalog is finished, add its code to
`complete_text` in `glosarium.yml`.

## `glosarium.yml` keys

| Key | Purpose |
|---|---|
| `default` | Default language (`en`). |
| `complete_text` | Languages whose report/console text catalog is complete. |
| `languages.<code>.italic` | `false` when the text is already English so nothing is italicized (default `true`). |
| `languages.<code>.terms` | Terms printed in italics; case-insensitive, plurals and multi-word phrases are matched. |
| `languages.<code>.map` | Local word to canonical term; used by the guard test. |
| `languages.<code>.phrases` | Ordered `[regex, replacement]` pairs for context-dependent words. |

## Adding terms, languages, or a project glossary

- **New term:** add one line to `terms` of the right language.
- **Word that must be standardized:** add a `word: term` pair to `map`.
- **New language:** add one block under `languages` (ISO 639-1 code).
- **One project only:** create `<project-folder>/config/glosarium.yml` with the same structure; it is
  merged with the kit glossary.
- **The website:** has its own glossary in `site/glosarium.yml` (same structure, not merged with the
  kit glossary); see the website section of the contributing guide.

After changing it, run `python -m pytest tests/unit/test_glosarium.py`. The test fails when display
text (console, report, recommendations) still uses a word mapped by `map` or `phrases`, so nothing
is missed.

## Language roadmap

1. Per-language glossary, term standardization, and italics (done).
2. English report and console text catalog, then add `en` to `complete_text`.
3. German catalog.
