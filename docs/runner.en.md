[<img src="https://flagcdn.com/id.svg" width="18" alt="ID"> Indonesia](runner.md) · **<img src="https://flagcdn.com/gb.svg" width="18" alt="EN"> English** · [<img src="https://flagcdn.com/de.svg" width="18" alt="DE"> Deutsch](runner.de.md)

# Autonomous audit runner

`runner.py` runs the whole audit flow from start to report with no manual steps and no AI: it starts the stack, logs in every account, generates the module configs, runs the scans and the dynamic tests, then builds the report. Everything that depends on the project lives in one YAML file, so the same runner serves existing and new projects.

## Prerequisites

- [ ] Python 3.10+ and `pip install -r requirements.txt`.
- [ ] Docker for `zap`, `tls`, `deps`, and for targets that use a container stack.
- [ ] A project config file (see [Adding a new project](#adding-a-new-project)).
- [ ] Test account credentials in an env file or a seeder, never in the config.

## Quick start

```bash
python runner.py init --config projects/example-app/audit.config.yml
python runner.py check --config projects/example-app/audit.config.yml
python runner.py run --config projects/example-app/audit.config.yml --target local
python runner.py run --config projects/example-app/audit.config.yml --target dev --skip ratelimit
python runner.py down --config projects/example-app/audit.config.yml
```

Result: a uniquely named report folder under `project.output` with HTML, Markdown, slides, per module evidence, and a run summary. Exit code 2 means an error stopped the run; security findings do not change the exit code, because they are in the report.

## What a run does

1. Checks prerequisites and loads the config.
2. Target `stack`: starts the stack through the `stack.up` steps. Steps are idempotent, a healthy service is left alone.
3. Logs in every account, pacing around the login rate limit, then reads the permissions each account really has.
4. Generates the module configs and the access matrix from those permissions.
5. Runs the modules in `pipeline` order. One failing module does not stop the others.
6. Builds the report, scans it for leaked secrets, and copies the result to the output folder.
7. Optional `--down-after`: stops the stack.

## Configuration

A complete commented example is in [config/runner.example.yml](../config/runner.example.yml).

Keep the config in `projects/<name>/audit.config.yml` in the kit, a folder that is not committed like every other kit project, and set `project.repo` to the location of the application repo. That repo receives the report copy and is the base of the `stack` step paths.

`project.language` selects the report language (`id`, `en`, or `de`) and defaults to `id`; the `--lang` option overrides it. The report text and the per instance evidence are available in all three languages; data from the config and text from third-party tools are not translated. The run summary and the runner's own console messages are in Indonesian.

| Section | Content |
|---|---|
| `project` | Name, short key for file names, and the output folder |
| `api` | Login, profile, refresh, logout, change password endpoints, and the OpenAPI location |
| `accounts` | Account source per target kind, low and high privilege roles |
| `stack` | Steps to start and stop the stack, plus database access |
| `targets` | Targets with `kind` `stack` or `remote` |
| `pipeline` | Module order |
| `modules` | Settings per module, the `targets` that run it, and `by_target` |

```yaml
modules:
  injection:
    targets: [local, dev]
    time_based: false
    by_target: { local: { time_based: true } }
```

## Targets and safety levels

- **`stack`:** the runner starts the stack and tests it. Accounts are read from the database through the query in `accounts.stack`.
- **`remote`:** tests a host that already exists. URL, level, and accounts are read from the target env file: `APP_USER_<ROLE>` and `APP_PASS_<ROLE>`.
- **Level `prod`:** only passive modules run (`safety.passive_modules`). Use `--force-active` only if you own the system and have written permission.
- **Modules that write data:** `upload`, `mass-assignment`, `ssrf`, `session`, `auth-policy`, and `zap` only run on targets you enable yourself in the config, and usually only on `stack`.

## Report names and location

Every run creates a new folder and new files named `security-audit-kit_<project>_<target>_<YYYYMMDD-HHMMSS>`, so a rerun after a fix never overwrites an earlier report. It contains:

- `<name>.html`, `<name>.md`, and `<name>-slides.html`: the full report and the slides.
- `<name>-ringkasan.md`: which modules ran, were skipped, or failed, with the toolkit version.
- A `data/` folder with the raw output of every module (JSON and ZAP output) and a static README in three languages (`README.md`, `README.en.md`, `README.de.md`) that explains it. The evidence folder, when screenshots exist, stays at the top level because the report links to it.

`RIWAYAT.md` in the parent folder holds one line per run so runs are easy to compare. Before copying, the whole report is scanned for known passwords, tokens, and keys; if anything leaked, only that run folder is deleted.

## Rate limit and login quota

Logging in to an application that limits attempts can fail with HTTP 429. The runner reads `Retry-After` and waits, and `authz` repeats a request that hit 429 instead of reporting it as a finding. For a target with dozens of accounts a run can take a while because it waits for rate limit windows. Use `--roles-limit` when you only need some of the accounts.

## Adding a new project

1. Run `init` to create the config skeleton from the example.
2. Fill in `api`, `accounts`, `targets`, and the modules that apply. Start with the passive modules and add the rest step by step.
3. Run `check` until it reports no problems.
4. Run `run` on a safe target, then read the run summary.

A new target, such as staging, is added under `targets` with its own env file.

## Limitations

- Scanner results still need verification; business logic flaws are only found when the case is written in the config.
- `session` checks bearer authentication with refresh tokens, and needs a high privilege account to create a one-off test account.
- `tls` is for HTTPS targets only, and `deps` scans code, so it usually runs on the `stack` target.
- The runner creates its working projects in `work/kit/` next to the config, so `projects/` keeps one folder per project.
