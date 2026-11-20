# Configuration

`.security-audit.conf` settings, the config check, and triage exclusions. Start with the [README](../README.md).

## Configuration (per project)

The kit runs **zero-config** (default `SAST_PATHS=.` whole repo, semgrep skips
node_modules/.git/.venv; `TF_DIR` auto from the first `*.tf`; js/py package manager
auto-detected). **Semgrep rulesets are stack-aware**: with `SEMGREP_CONFIGS` unset, `scan.sh`
auto-selects packs from what's in the repo — base `p/owasp-top-ten` + `p/secrets`, plus the
detected language/framework packs (`p/python`/`p/django`, `p/javascript`/`p/typescript`/`p/react`,
`p/golang`, `p/java`, `p/php`, `p/ruby`, `p/csharp`) — so each project gets its own injection
rules. `scan.sh doctor` prints the resolved set. For customization, one file per project:

1. On setup, `install.sh` creates **`.security-audit.conf`** at the repo root
   (template: `security-audit.conf.example`).
2. Tune the values for your project and **commit it** (team-shared):
   ```sh
   : "${SAST_PATHS:=backend frontend}"     # narrow source directories (a missing one is skipped, and said)
   : "${TF_DIR:=infra/terraform}"          # terraform directory
   # : "${JS_DIRS:=frontend}"              # js-deps: where the JS app is (see below)
   # : "${PY_VENV:=/opt/venvs/myapp}"      # py-deps: audit a venv outside the repo (see below)
   # : "${SEMGREP_CONFIGS:=--config p/python --config p/react ...}"  # leave unset = stack-auto; set to override
   ```
3. `scan.sh` reads it automatically, as data (see below).

**`js-deps` picks its directory by lockfile, not by luck.** Every tracked `package.json` is
considered, minus vendor paths (`JS_SKIP_RE`: `node_modules`, `vendor`, `static`, `assets`,
`dist`, …) and minus any directory without a lockfile — there are no resolved versions to audit
there, so it is skipped with a note rather than failed. Every remaining directory is audited, not
just the first. If your app lives somewhere the heuristic will not find it (or the only
`package.json` files in the repo are checked-in front-end assets), set **`JS_DIRS`** and the
search is bypassed entirely.

**`py-deps` never reports green about an environment it could not find.** With a `.venv` in the
repo, pip-audit audits it. An active `VIRTUAL_ENV` counts only if it is a real venv (it has a
`pyvenv.cfg`) **inside this repo**; another project's venv or a pyenv global interpreter is ignored
with a warning, because its result would say nothing about this repo. To audit a venv that lives
elsewhere on purpose, set **`PY_VENV`**; the run names the env it audited and why. Without one — the normal shape for a project that
runs in a container — auditing the ambient interpreter would mean auditing *nothing*, so the kit
reads the committed manifests (`requirements*.txt`, `uv.lock`, `Pipfile.lock`, `poetry.lock`,
`pdm.lock`) with **osv-scanner** instead: statically, nothing is built or installed. (`pip-audit -r`
is deliberately not used — it creates a virtualenv and installs the file, i.e. runs the dependency
tree's build scripts, which is the same thing the kit refuses for `OSV_CALL_ANALYSIS=rust`.) If
there is neither an environment nor a readable manifest — a bare `pyproject.toml`, say — the
dimension reports **`indeterminate`** (exit code 3): it does not block, it does not count as a pass,
and the run says so out loud. `summary.json` records it as `"status": "indeterminate"`.

**The config is data, never code** (since 1.22). `.security-audit.conf` is committed, so on a
checked-out branch it belongs to whoever wrote that branch. `scan.sh` therefore parses it line by
line and never sources it. Accepted lines: `: "${NAME:=value}"`, `: ${NAME:=value}`, `NAME=value`,
`NAME="value"`, `NAME='value'`, each optionally with `export` and a trailing `# comment`. Values are
literal: no `$` expansion, no command substitution. The environment always wins over the file, for
every form. A line that is anything else is **not applied**, and the kit names it with its line:
- a line that runs a command, or a setting followed by a command (`SARIF=0 touch x`, `X=1 && cmd`);
- a command substitution or a `$` expansion in a value;
- a setting `scan.sh` does not read (a typo, or a name such as `PATH`);
- `SKIP_SECURITY`, which is read from the environment only;
- a value of the wrong type (a non-integer wait, `SCAN_OFFLINE=yes`) is applied, and named.

Upgrading from 1.21 or older: a config that used `$VAR` in a value, or a plain `NAME=value` that
was meant to override the environment, now behaves differently; `scan.sh doctor` lists such lines.

These are warnings, never a block. They appear in the closing summary as `── config: N warning(s)`,
in `summary.json` under `config.warnings`, and in full in `scan.sh doctor` / `scan.sh verify`.

**Precedence:** `env > .security-audit.conf > default`. Thanks to the `:=` form,
use env for a one-off override: `SAST_PATHS="lib" bash scan.sh sast`.

Pins live in the same file too: `GITLEAKS_VER` / `TRIVY_VER` / `SYFT_VER`.

### Triage exclusions (signal control)
`install.sh` also creates **`.security-exclusions.md`** (template:
`exclusions.example.md`). The Claude triage skills read it **first** and auto-drop findings
matching a do-not-report class (DoS, test-only files, memory-safe languages, UUID-guessing,
trusted env vars…) or a precedent assumption — then run a **confidence-scored verification
pass** and report only findings ≥ 0.7 (the rest go to a "Suppressed" section, on record). Tune
and commit it per project; it kills recurring false-positive noise deterministically.

## Gate profile: `GATE_STRICT`

By default a dimension that could not inspect (no docker, no uvx, a crashed scanner, an
indeterminate result) is named loudly, `NOT inspected. Not a pass.`, but does not block. With
`GATE_STRICT=1`, in the environment or in `.security-audit.conf`, it blocks the commit or push, soft
dimensions included. A hard dimension's crash blocks in both profiles. For a team, set it in the
config, so "not scanned" means "not pushed" for everyone.

## What a change does to the gate: `policy_changes`

Every run compares the range under review (merge-base with `BASE_REF` or the default branch, up to
`HEAD`, plus what is staged) for changes to the gate itself: the config, the exclusions, the
scanners' allowlists and configs, repo-local rules, the vendored kit, and added inline suppression
markers. They are listed in `summary.json` (`policy_changes`) and as one `── policy:` line in the
closing summary. A signal for review, never a block. Schema: [docs/schema/summary.md](schema/summary.md).
