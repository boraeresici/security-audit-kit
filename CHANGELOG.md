# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed (v1.18.0-rc.2 — CI action pin)
- **The `pytest` and `e2e` jobs can start on GitHub Actions.** `v1.18.0-rc.1` pinned
  `actions/setup-python` to two invalid commit SHAs, so both jobs failed while resolving the action
  before any tests ran. Both jobs now use the verified immutable commit behind `setup-python@v6`,
  which also removes the Node.js 20 deprecation warning emitted by current GitHub runners.
- The RC.1 source itself passes locally: 234 unit tests and 93 offline e2e assertions. RC.2 is
  required because an RC whose required test jobs never executed cannot be promoted as tested.

### Added (#R5.2, slice A — a run lock, so two scans cannot write one record)
- **The failure it removes.** `raw-<date>.log` is appended by every run and `summary.json` is
  truncated and rewritten by every run. Two overlapping scans — a pre-push `all` while someone runs
  a dimension by hand, or a pre-commit firing during a push — interleaved their lines into one log
  and could truncate `summary.json` while `/sec-triage` was reading it. Nothing warned; the record
  simply disagreed with itself.
- **`mkdir` as the lock.** It either creates the directory or fails, with no window between the
  check and the create — the same primitive `spotify/git-test` uses. The lock lives in
  `.git/security-audit-cache/scan.lock` (never in the repo tree, never in `CHECKSUMS`) and carries
  its owner's pid, timestamp and command so a wait message can name who holds it.
- **The lock serializes writers, it does not gate scans.** A second run waits `SCAN_LOCK_WAIT`
  seconds (30); if it still cannot take the lock it **runs anyway**, into its own
  `raw-<date>.<pid>.log`, and says so twice. Blocking a push because a colleague's scan is running
  would be a security gate failing for a reason that has nothing to do with security.
- **`summary.json` is written then renamed.** `rename(2)` is atomic, so a reader gets the previous
  record or the new one — never half of one — even in the unlocked-concurrent case.
- **A crashed run cannot leave a permanent lock**: the directory outlives the process, so it is
  reclaimed when the owner PID is gone or after `SCAN_LOCK_STALE_MIN` (60) minutes, with a line
  saying which lock was reclaimed.
- **`doctor` shows the lock** as free / held by whom / held-but-stale, plus the wait setting — an
  invisible lock is how a stale one becomes permanent.
- Coverage: 8 new e2e assertions — released after a normal run, valid JSON summary with no temp
  files left, a live holder pushes the second run into its own log **without skipping its scan** and
  without touching the shared log, a dead owner's lock is reclaimed rather than waited on, and
  `doctor` reports it.
- Deliberately **not** in this slice: the per-dimension result cache (#R5.2 slice B). v1.17.0 found
  three dimensions that had silently switched themselves off — a cache is a machine for making a
  false "clean" sticky, so it ships separately, opt-in, and only for dimensions whose input set can
  be proven. The lock was always independent of it.

### Added (eval harness — calibration scoring and thinking-model support)
- **Calibration metrics in `score.mjs`** (F12a): Brier score, ECE, reliability table (5 confidence
  bins), and threshold-cost analysis at the 0.7 cutoff (suppressed REALs, noise FPs). These answer
  "is the model's confidence a trustworthy probability?" and "does the 0.7 threshold hurt users?" —
  questions that were previously unmeasured. Calibration is appended to the existing precision/recall
  output; `grade.mjs` is untouched so past runs remain comparable.
- **`extractJsonBlock()` in `score.mjs`**: models with chain-of-thought reasoning (Qwen, GLM)
  prepend free-text thinking before the structured JSON verdict. The scorer now locates the last
  balanced `{...}` block in the output, so confidence is correctly parsed even when the model
  reasons out loud. Regex-fallback verdicts (no JSON) still work as before.
- **Eval backend configs**: `promptfooconfig.qwen.yaml` (Qwen 3.7 Max via DashScope Standard) and
  `promptfooconfig.glm-ds.yaml` (GLM-5.1 via DashScope Standard, replacing the EOL NVIDIA NIM
  GLM-5.2 endpoint). Same corpus, same prompt, same grader — only the provider differs.
- Coverage: 2 new e2e assertions — missing-confidence mock prints "not available" without crashing;
  calibration mock with known confidence values produces correct Brier, ECE, and threshold-cost
  numbers.

### Fixed (eval harness — failed-run artifact protection)
- **`run.sh` no longer destroys the previous good output on a failed run.** Writes to a temp file
  first (`output.*.tmp.$$.json`), moves to the target only on success. The old `rm -f "$OUT"` wiped
  the only copy of a measured run when the API key expired (observed 2026-08-11: Claude 401).
- Temp file suffix goes before `.json` (not after) so promptfoo's extension validation accepts it.

### Added (CI — PR test gates)
- **`pytest` job** in CI: runs `tests/unit/` against `lib/` modules (evidence, report_html,
  kit_sarif, pkgcheck). Pure stdlib + pytest, no external tools needed.
- **`e2e` job** in CI: runs `tests/e2e.sh` with a restricted `PATH` (no docker, no uvx) so
  external-tool assertions skip gracefully. This is the offline deterministic gate that was
  previously only run locally before releases.
- Both added to branch protection required checks (`main.json`) and PR template checklist.

## [1.17.0] - 2026-08-27

### Fixed (gates that silenced themselves)

- **`py-deps` was green on a repo with 208 dependency advisories.** Found while dogfooding
  `v1.17.0-rc.1`: the consumer runs in a container, so there is no `.venv` in the repo. pip-audit
  then audited the ambient (empty) interpreter and printed *"No known vulnerabilities found"* — while
  the committed `requirements.txt` carried **208 advisories across 37 packages, one of them CVSS
  9.8** (pyopenssl), which `scan.sh osv` found immediately. The dimension warned that it had no venv,
  but still reported **pass**, and `osv` is not part of `all` — so the default gate was green about a
  file it never opened. Same class as the SIGPIPE bug in 1.17.0, one layer up.
  - **No venv now means the committed manifests get read**, statically, with the already-pinned
    osv-scanner (`requirements*.txt`, `uv.lock`, `Pipfile.lock`, `poetry.lock`, `pdm.lock`).
    `pip-audit -r` is deliberately NOT used: its requirement source creates a virtualenv and
    installs the file to resolve it (`--no-deps` does not avoid this), so it executes the dependency
    tree's build scripts — the same own-goal the kit already refuses for `OSV_CALL_ANALYSIS=rust`.
    Verified against the same repo: the default `scan.sh deps` now blocks with the real findings.
  - **New third verdict: `indeterminate`** (exit code 3). When there is neither an environment nor a
    manifest readable without building the project (a bare `pyproject.toml`, or no docker to read
    them with), the dimension reports `indeterminate` instead of `pass`. It does not block — refusing
    what we failed to look at would block ordinary work — but it is never counted as coverage:
    `summary.json` records `"status": "indeterminate"` and the run prints a banner saying the green
    is not coverage. Documented in `docs/schema/evidence.md`.
  - Coverage: 6 new e2e assertions (INDETERMINATE is reported, does not block, reaches
    `summary.json`, prints the banner; and a committed manifest is read statically and its
    known-vulnerable pin reported).

- **`git ls-files | grep -q` was a silent false negative on any large repo — and it switched whole
  dimensions off.** `grep -q` exits at the first match, git is still writing, takes SIGPIPE, and
  `set -o pipefail` turns the pipeline's status into 141 — so the `||` branch ran and the gate
  reported "not present". It is size-dependent: it passes on every small fixture and starts lying
  once the repo outgrows a pipe buffer, which is why it shipped. Measured on a 22,972-file
  production repo, **three** things had quietly switched themselves off while the scan reported
  green: `py-deps` (pip-audit never ran against a tracked `pyproject.toml` + `requirements.txt`),
  `zizmor` (12 workflow files, "nothing to scan"), and the **semgrep stack auto-select** — `_hasf`
  used the same shape, so `p/python`, `p/django` and `p/javascript` were never added and SAST ran
  with base rules only. `doctor`'s stack list was wrong for the same reason. Every call site now
  goes through `has_tracked` (command substitution + here-string: no pipe, nothing to kill), the
  `find | grep -q .` pair became `find -print -quit`, and the pre-commit hook's
  `git diff --cached --name-only | grep -q` — which would skip the dependency gate exactly when a
  large vendored tree is landing — was rewritten the same way.
- **`js-deps` audited the first tracked `package.json`, which in a backend repo is a vendored
  asset.** In a Django repo that is `static/assets/plugins/fullcalendar/packages/bootstrap/
  package.json`: no lockfile, so `npm audit` exits ENOLOCK=1 and the gate **blocked every commit
  that touched any manifest**, over a third-party file nobody in the repo maintains — while the
  real front-end was never audited, because only the first hit ever was. Directory selection is now
  by lockfile, not by luck: vendor paths are dropped (`JS_SKIP_RE`), a directory without a lockfile
  is skipped with a note instead of failed (no resolved versions = nothing to report, and "cannot
  audit" must not read as "vulnerable"), and **every** remaining directory is audited. New
  **`JS_DIRS`** bypasses the search outright for a layout the heuristic cannot find.
- **The pre-commit hook's manifest regex was unanchored**, so `requirements.*\.txt` also matched
  `requirements.txt.tpl` (a template) and `package\.json` matched `package.json.bak` — each one
  triggering a dependency scan nothing asked for. Anchored per alternative, matching the form
  `scan.sh` already used. The same anchoring fixes `scan_py_deps`, which counted a `.tpl` fixture
  as a Python project.
- Coverage: **14 new e2e assertions**. A static guard fails the build if a file listing is piped
  into `grep -q` again; a **>6000-file fixture repo** reproduces the original failure (verified: the
  old code returns 141 and misses both python and the workflows at that size, the new code detects
  both); the js-deps cases assert that a lockfile-less vendored asset neither fails the gate nor
  gets audited, and that `JS_DIRS` overrides the search. e2e: 87 -> 101 assertions, 0 failed.

### Added (#R5.1 — `scan.sh pkgcheck` + an agent hook: the package is checked BEFORE it runs)
- **The window this closes.** Every other dependency dimension reads a manifest that is already in
  the repo. `npm i <pkg>` and `pip install <pkg>` run the package's install script the moment they
  resolve it, so `pre-commit` — which only fires once the changed manifest is staged — sees a
  malicious package **after** it has executed. The `guarddog` dimension existed to catch exactly
  that class and was structurally too late. A git hook cannot see an install; an agent tool-call
  hook can.
- **`scan.sh pkgcheck <pypi|npm> <pkg>[@version] ...`** checks a named package that is not installed
  yet (`guarddog <eco> scan`, same pin as the `guarddog` dimension). `--hook` reads an agent
  PreToolUse payload instead, takes the package names off the install command line and checks those.
- **`hooks/pre-tool-install.sh`** is the thin `PreToolUse(Bash)` wrapper — fast-path substring test
  first so an ordinary Bash call never pays for a python start-up; exit 2 (block) only on a flagged
  package, with the rule names and an instruction not to retry. Wire it with
  **`install.sh --with-agent-hook`** (idempotent, merges into `.claude/settings.json`, and **opt-in**:
  it fires on every Bash tool call, and an installer should not silently edit a consumer's agent
  settings).
- **The block list is measured, not assumed — and this is the load-bearing decision.** guarddog
  reports `capability-*` (what a package *can* do; `requests` fires three) and `threat-*`/metadata
  rules under one `issues` count, and `--exit-non-zero-on-finding` fires on both. Measured on
  2026-08-24 against the 18 most-installed pypi/npm packages: **15 distinct non-capability rules
  fired on 8 of them** — `threat-process-download-exec` on pandas and setuptools,
  `threat-filesystem-destruction` on next, `metadata_mismatch` on typescript and webpack. Blocking
  on "not a capability rule" would have refused `pip install django`; a gate that blocks Django is
  a gate that gets uninstalled, and an uninstalled gate protects nothing. So the kit blocks on an
  explicit list of 24 malice-specific rules (typosquatting, dependency confusion, install-time
  network, reverse shell, exfiltration, cryptomining, keylogging, maintainer-domain takeover), each
  of which fired on **none** of those 18 packages; everything else prints as a note. Tunable via
  `PKGCHECK_BLOCK_EXTRA` / `PKGCHECK_REPORT_EXTRA`, and the pinned guarddog version means the rule
  set cannot drift underneath the list.
- **A failed download is never "clean".** When guarddog cannot fetch the package it prints
  *"No risks found"*, exits 0 and omits `results` entirely (reproduced with
  `npm scan flatmap-stream -v 0.1.1`). The kit reads `errors` and reports `INDETERMINATE` — allowed,
  loudly, never cleared. Same for anything else it cannot inspect: no network, no uvx/pipx, a
  VCS/local-path install, an unreadable hook payload. Refusing what the kit failed to look at would
  block ordinary work, and a gate people route around protects nothing.
- **Verdict cache** in `.git/security-audit-cache/pkgcheck` (never in the repo tree, so it cannot
  reach `CHECKSUMS`), keyed by ecosystem, package, version **and the pinned guarddog version** — a
  pin bump can never read an old verdict. An exact `pkg@version` verdict is immutable and never
  expires; an unversioned one expires after a day. First check ~15-20s, a cache hit ~0.2s.
- **`doctor` says whether the window is guarded**, where the cache lives and how many rules block —
  an unwired hook is otherwise invisible, which is the failure mode round 4 named (*forbid nothing,
  hide nothing*).
- Coverage: e2e grew by 9 assertions, all offline (fixtures of real guarddog output shapes) —
  including the FP regression guard that a `threat-*` rule firing on a popular package must report
  rather than block, and that a failed download is not reported as clean. `uvx`/`pipx run` are
  deliberately **not** treated as installs: the kit runs every python tool through `uvx`, so it
  would scan itself on every scan.
- Docs: READMEs en+tr carry the section (what it blocks, the measurement, and plainly what it does
  *not* cover — the agent's tool calls only, never a human typing `npm i`).
  **Not swept yet, for release prep:** `docs/compare/*` row and `landing/`.

### Documentation

- **`--expect=<sha>` now says where the SHA comes from.** Release tags are annotated, so the obvious
  `git rev-parse <tag>` returns the tag OBJECT and `bootstrap.sh` correctly refuses it — which reads
  like a tag-repoint alarm and invites `--allow-ref-change`, defeating the pin. README (en+tr) and
  RELEASING.md now show `git rev-parse <tag>^{commit}` (and the `gh api` equivalent). Hit during the
  v1.17.0-rc.1 dogfood.
- **"I installed the kit but the skills do not show up in Claude Code."** The READMEs (en+tr) and
  the `install.sh` summary now say what actually governs it: Claude Code scans only
  `<working-root>/.claude/skills`, so opening a *container* folder that holds several repos side by
  side loads none of the skills installed into one of them (`--add-dir` does not extend the scan),
  and skills are enumerated at session start, so a newly installed one needs a new session. Also
  states plainly that committing is what carries the skills to TEAMMATES — it is not what makes
  them visible to you — and that the kit is repo-scoped: a backend and a frontend in two repos
  need two installs.

## [1.16.1] - 2026-08-24

### Fixed (docs — the flow diagrams described less than the kit does)
- The lifecycle diagram and the finding-loop sketch had fallen behind three releases of behaviour,
  which is worse than merely stale: a reader took the wrong mental model from the most-looked-at
  part of the README.
  - **The `verify` gate was invisible.** `pre-push` has run `scan.sh verify` since v1.12.0 — an
    edited vendored kit blocks the push — and neither flow showed it. Both now do, including the
    restore path and the rule that kit bugs go upstream rather than being patched in place.
  - **The artifacts were missing.** The diagram claimed the scan writes `raw-DATE.log +
    summary.json`; `evidence.json`, `sarif/kit.sarif` and `report-DATE.html` (v1.13.0) were absent.
    The judgment findings reaching GitHub Code Scanning is now drawn, not just described in prose.
  - **The verification loop was missing.** "An unrun suppression is a hypothesis" is a rule the
    skills state twice, and the flow still ended at *write the allowlist entry*. Both flows now end
    at **prove it**: `scan.sh allowlist` plus re-running the affected dimension, with the expiry
    requirement on each entry.
- Verified by rendering: the diagram was run through the official mermaid CLI and produces a valid
  SVG. A README diagram that fails to parse degrades silently on GitHub, so "it looks right" is not
  a check.
- No code changes — the doc sweep that should have ridden along with v1.14.0–v1.16.0, applied late.

## [1.16.0] - 2026-08-23

### Added (#7, free slice — reachability for dependency CVEs, no new tool)
- **`OSV_CALL_ANALYSIS=go` turns on osv-scanner's call analysis**, which marks whether a vulnerable
  symbol is actually *called*. This needed no new dependency: the pinned osv-scanner image we
  already ship supports it. Checking that first changed the shape of this item — the heavy
  `dep-scan` tool is now only needed for Python/JS, not for reachability as such.
- **The gate does not loosen.** With call analysis on, osv-scanner drops uncalled vulnerabilities by
  default — a security gate that silently reports less is the wrong trade. The kit always pairs it
  with `--all-vulns`, so the finding set and the exit code are unchanged; what you gain is a
  called/uncalled **signal for the judgment layer**, not fewer findings.
- **Rust is refused by default.** `--call-analysis=rust` works by *running the dependency tree's
  build scripts*. A scanner that executes untrusted code to decide what to report is an own-goal
  and contradicts the kit's stated boundary (scan and judge, never execute). It requires an explicit
  second opt-in, `OSV_ALLOW_BUILD_SCRIPTS=1`, and says plainly what will happen.
- **`sec-triage` uses the marking honestly**: an "uncalled" result is a heavy thumb on the scale for
  the reachability gate, never a verdict — call graphs miss reflection, dynamic dispatch and plugin
  loading. A "called" marking is the stronger of the two signals.
- Still not shipped: Python/JS reachability, which needs `dep-scan` (heavy, minutes, overlapping
  output). That decision stays open rather than being made by accident here.

### Changed (#8, first half — remediation: the cost of the bump is the decision)
- **`sec-triage` step 6 now tells you how to fix a dependency CVE, not just that you should.**
  "Bump it" is not an instruction. The skill asks three questions in order: is the package **direct
  or transitive** (read the manifest, not the lockfile — you cannot upgrade what you do not
  declare); **does the fixed version fit the parent's declared range** (`npm ls` / `pnpm why` /
  `uv pip tree` / `pip show`), in which case bumping the *parent* resolves it cleanly; and only if
  the parent will not carry the fix, pin it yourself — knowing that an override runs the parent
  against a version its maintainers never tested with it.
- A **per-ecosystem command table** (pnpm / npm / yarn / uv / pip / poetry), with the direct-dep
  form and the transitive-forcing form side by side, so the findings row carries the exact command
  for *this* repo rather than a generic one. Then re-run that dimension: an unverified fix is the
  same class of claim as an unverified suppression.
- This is deliberately the **judgment half** of T2.2. The kit does **not** compute the parent-range
  answer — that needs per-ecosystem resolver calls, and it stays tracked as its own item rather than
  being half-built here. The skill says so instead of implying automation that does not exist.

## [1.15.0] - 2026-08-23

### Changed (process)
- **`RELEASING.md` now describes the release prep as a PR**, not a direct commit to `main`. `main` is
  protected (PR + required checks) and the prep step was telling us to push straight to it — which
  bypasses the very gate this repo asks its consumers to keep. The doc sweep is written into that
  step as a standing rule (READMEs en+tr, `docs/compare/*` + `landing/build.py`, diagrams, then
  regenerate `CHECKSUMS` because docs live inside the manifest).

### Added (#13 — `scan.sh allowlist`: the decay detector for accepted risks)
- **A suppression is an accepted risk with a shelf life, and both ways it rots are silent and fail in
  the dangerous direction** — the suppression stays, the protection goes. (1) The fix ships, the
  entry is never deleted, and a *future, real* CVE in that package is silenced. (2) The same advisory
  is suppressed on one dimension's path but not the others, so the record disagrees with itself.
  `scan.sh allowlist` audits the files offline — no scan, no network — and **exits non-zero** on
  either, so a team can wire it wherever they want it enforced.
- Reports: **expired** deferrals by id and date; a count of entries carrying **no expiry at all**
  (those never become loud again); and an advisory suppressed in one dependency path but **absent
  from another**. Expiries are read natively where the tool has them (`ignoreUntil` in
  `osv-scanner.toml`, `expiredAt` in `.trivyignore.yaml`) and by the kit's `# expires YYYY-MM-DD`
  convention elsewhere. ISO dates compare lexically — no date arithmetic, no locale.
- **Only package-advisory namespaces are cross-checked** (`CVE-` / `GHSA-` / `PYSEC-` / `OSV-`).
  `.trivyignore.yaml` also carries trivy's misconfiguration checks (`AVD-…`/`DS-…`/`KSV-…`) and
  license ids (`LGPL-3.0-or-later`); pip-audit can never report those, so comparing them
  manufactures a gap that cannot exist. Caught by dogfooding rc.1 on a real repo, where two of the
  three warnings were exactly that — a detector two-thirds noise is one nobody reads.
- **Deliberately under-reports.** The cross-path check compares **exact ids**, so alias pairs
  (`PYSEC-…` / `CVE-…` / `GHSA-…` of one advisory) are not matched and their gaps are missed. That
  is the intended trade: a false "you are covered" is worse than a missed hint, and a detector that
  cries wolf is one people stop reading — the same reasoning that rejected the "0-match ⇒ stale
  rule" idea in v1.14.0. The output says so rather than implying coverage.
- `doctor` carries a **one-line verdict** (the detail lives in the subcommand), and `sec-triage`
  step 5 now ends with "then prove it with `scan.sh allowlist`" — the cheapest check that the record
  you just wrote agrees with itself.

### Added (#10 — one run, every backend: the head-to-head eval table)
- **`tests/eval/promptfooconfig.matrix.yaml`** runs all candidate backends against the same corpus,
  prompt, grader and split **in a single run**. Comparing separate per-backend runs by hand is where
  a comparison quietly stops being one.
- **`run.sh` now checks provider keys per provider, not all-or-nothing.** Backends whose key env var
  is unset are dropped (via `--filter-providers`) and the rest still run; only an empty set skips.
  The old behaviour meant one absent key skipped the entire matrix — which is how a comparison
  harness ends up never being run. Keys resolve from `apiKeyEnvar:` in the provider block, else from
  the id prefix (`anthropic:` / `openai:` / `mistral:`).
- **`score.mjs` groups results per provider** and prints one row each. This is a correctness fix, not
  cosmetics: pooling two backends into one confusion matrix reports a model that does not exist. A
  backend that errored out is printed as **"not measured"** rather than scored 0% — a dead provider
  is not a bad model, and a 0% row would drag the whole table. Regression gates (`EVAL_MIN_RECALL` /
  `EVAL_MIN_PRECISION`) now apply per backend and name which one failed. Single-provider output is
  unchanged.
- The table prints `differences under ~1 case are noise` — with 30 held-out cases one flip moves
  recall by ~3-7 points, and a ranking read off that would be fiction.

### Added (#9 — Windows: the WSL2 path, and `doctor` naming which shell you are in)
- **Platform notes in both READMEs**: Linux/macOS native, **WSL2 the supported Windows path**, Git
  Bash **partial** (uvx/pipx dimensions and hooks work; docker dimensions mangle the `/repo` mount
  because MSYS rewrites it to a Windows path before docker sees it — `MSYS_NO_PATHCONV=1` or move to
  WSL2), PowerShell/cmd unsupported. Plus the two WSL2 habits that actually bite: keep the repo on
  the Linux side (scanning across `/mnt/c` is slow enough to change behaviour), and enable Docker
  Desktop's WSL integration or the docker dimensions skip themselves with a notice.
- **`scan.sh doctor` detects and names the platform** (MSYS/Git Bash vs WSL2), so a mangled docker
  mount is reported rather than debugged.
- The comparison doc's platform row says **documented, not yet verified by us** — we have no WSL2
  machine here, and claiming a verified path we have not run would be exactly the kind of unearned
  ✓ this doc exists to avoid.

## [1.14.0] - 2026-08-23

### Added (#14 — repo-local custom rules: the kit's engine, pointed at *your* invariants)
- **`semgrep-rules/` at the repo root is now a supported entry point** (`.semgrep/`, `.semgrep.yml`,
  `.semgrep.yaml` also work). The kit shipped the best custom-rule engine in the category and gave
  you no way to use it: the only way to reach a hand-written rule was `SEMGREP_CONFIGS`, which
  **wins verbatim** — you gained one rule and silently lost `p/owasp-top-ten`, `p/secrets` and every
  stack pack, and that frozen list then rotted as the stack grew. Rules are now **composed**:
  `SEMGREP_CONFIGS` sets only the *base*, and local rules are appended to it either way. This is the
  difference between "we run the OWASP packs" and "we gate *your* invariants" — an unscoped ORM
  lookup, a banned field type, a helper that must never be called from a request handler are exactly
  what no registry pack can know.
- **`doctor` surfaces the traps that made custom rules unreliable**: how many rules load, **how many
  actually gate**, and which ones do not — `scan.sh sast` runs `--severity ERROR`, so a rule written
  at `WARNING`/`INFO` loads and is then ignored ("the rule exists, it just never fails anything").
  It also reports whether rule **tests** exist, and says `DISABLED` when the mechanism is switched
  off. There is deliberately **no advisory/warn tier** — a gate that does not gate is the hole this
  closes.
- **`scan.sh rules-test`** wraps semgrep's native test runner (`# ruleid:` / `# ok:` fixtures). A
  custom rule is code: after a refactor the pattern quietly stops matching and the gate goes silent,
  so an untested rule decays without ever failing. `semgrep-rules/` is recommended over `.semgrep/`
  precisely because semgrep's test runner **skips hidden directories** — rules there scan fine but
  their tests are never discovered, and `rules-test` now says so instead of reporting "all clear".
- **`doctor` also reports what a frozen override is missing.** Found in the field: a consumer's
  `.security-audit.conf` pinned four packs while stack-auto computed seven — `p/python` absent in a
  repo with 959 python files, plus `p/react` and `p/php` (an entire payment-gateway SDK). The line
  now names them, which is the difference between an override being a *decision* and a *fossil*.
- **Discovery is anchored at literal paths under the repo root — never a tree search.** Two
  regressions are asserted in e2e: rule files inside the **vendored kit** can never become the
  consumer's rules (the v1.12.0 `p/python` class), and a rule's own **test fixture** never counts
  toward stack detection (one `.py` fixture would otherwise pull `p/python` into a repo with no
  python). Off switch: `SEMGREP_LOCAL_RULES=off`; relocate with `SEMGREP_LOCAL_RULES=<paths>`.
- READMEs (en/tr) ship a **skeleton, not content**: a rule + its test fixture, and a `.gitleaks.toml`
  plaintext-password rule (gitleaks' entropy rules miss a flat `PASSWORD=hunter2`; the mechanism was
  already wired, the rule was simply absent). **The kit owns the mechanism, the consumer owns the
  rules** — nothing org- or stack-specific ships here. `security-audit.conf.example` documents the knob.

### Added (#15 — `sec-threat-model`: the availability questions a static scan cannot answer)
- Three vendor-neutral questions in the STRIDE-D checklist, for the failure mode where a control
  exists on paper and nobody would notice it stopping: (1) do scheduled/background jobs alarm on
  **non-execution** (a dead man's switch) or only on error — a cron that stops firing is invisible
  to error-only alerting; (2) has a backup **restore** ever been executed and verified, or is the
  existence of backups being mistaken for recoverability; (3) do critical external dependencies have
  health checks **with alerting** and a defined degraded-mode behaviour ("undefined" is the finding).
  Skill text only — no dimension, no dependency, no runtime.

## [1.13.1] - 2026-08-23

### Fixed (suppression fan-out — a triage decision must stick on every path that reports the finding)
- **The allowlist model was per-tool while a triage decision is per-finding.** A dependency CVE is
  read out of the same lockfile by **pip-audit, osv-scanner and trivy** — three dimensions that
  overlap by design and report the advisory under different ids (`PYSEC-…`, `CVE-…`, `GHSA-…` are
  aliases of one vulnerability). `sec-triage` named only `.gitleaks.toml`, `nosemgrep` and
  `.pip-audit-ignore`, so an accepted, documented risk silenced in one path **came back as an
  unresolved HIGH from another** — and with `SARIF=1` now reaches GitHub Code Scanning carrying no
  trace of the decision, since `kit.sarif` cannot dismiss another tool's run. Found while
  dogfooding v1.13.0 in a real consumer: an accepted CVE (unreachable sink, not in KEV, EPSS
  0.0018, fix needs a major bump) reappeared at CVSS 8.2 through the `osv` path.
- `sec-triage` step 5 is now a **map of every suppression path** (`.gitleaks.toml` / `nosemgrep` /
  `.pip-audit-ignore` + `osv-scanner.toml` + `.trivyignore.yaml` / checkov + zizmor inline comments
  / `.security-exclusions.md`), with the dependency-CVE fan-out called out explicitly, the alias
  problem named, a **re-run requirement** ("a suppression you did not re-run is a hypothesis"), and
  an **expiry requirement** (`ignoreUntil`, or an `# expires … — fixed in <ver>` comment) so a
  deferral cannot silently outlive its fix and mask a future real CVE.
- `scan.sh doctor` gained an **allowlists** section listing which of those files exist in the repo,
  so a half-applied suppression is visible instead of implied. `osv-scanner.toml` needs no kit flag
  — osv-scanner discovers it at the repo root, is alias-aware, and prints why it filtered a finding
  rather than dropping it silently.
- READMEs (en/tr): the suppression map, the re-run and expiry habits, and the corrected flow
  diagrams (the old ones implied one allowlist entry closed a finding).

## [1.13.0] - 2026-08-12

### Added (T3.1c — `report-<date>.html`: one file, offline, printable)
- **A human-readable rendering of the same record**, opt-in via `REPORT=html` on a scan or
  `scan.sh report` to re-render. One self-contained file: no server, no JS, no external fetch, no
  fonts, no build step — it opens offline from a USB stick and the browser's print dialog is the PDF
  story. Not a report platform, and deliberately not a `view`-style local web server.
- **It shows what SARIF cannot**: the triage decision and confidence on each *scanner* finding
  (`kit.sarif` leaves those to each tool's own run), plus the suppressed set on record with reasons.
  Sections: scan header (scope, gate, dimensions with pass/fail), severity breakdown, findings
  table, Suppressed, builder warnings.
- **All tool- and skill-supplied text is HTML-escaped** and asserted in e2e. A scanner message
  containing markup is data, not markup; a security tool whose own report is injectable would be an
  embarrassment.
- Deterministic: the only date shown is the scan's own, so re-rendering unchanged input produces a
  byte-identical file.

### Added (T3.1b — `kit.sarif`: the judgment layer reaches Code Scanning)
- **The skills' findings now land where the scanners' already are.** An IDOR `sec-sast-deep` traced
  through the call path, or a prompt-injection sink `sec-ai-review` found, lived only in
  `findings-<date>.md` — invisible to GitHub Code Scanning, to IDE SARIF viewers, to everything.
  `lib/kit_sarif.py` renders them as SARIF 2.1.0 (`sarif/kit.sarif`, driver `SecurityAuditKit`, rule
  ids `SAK-<skill>-<class>`). The self-audit workflow already uploads the whole `sarif/` directory,
  so nothing needed wiring — and GitHub validates the document on every push.
- **Scanner findings are not re-reported.** A semgrep hit is already in `semgrep.sarif`; a second
  copy under a kit rule id would double every alert. Their triage decisions are recorded in
  `evidence.json` instead.
- **Suppressed findings are emitted as suppressed** (`kind: external`, justification = the triage
  note) — on record, not silently absent. Documented caveat: SARIF suppressions are scoped to their
  own run, so this cannot dismiss another tool's alert.
- **An empty run is never written.** Zero judgment findings almost always means no judgment pass
  ran, not that the findings are gone — and uploading an empty run closes every open kit alert. With
  nothing to report, the previous `kit.sarif` is left untouched.
- No `security-severity` property on judgment rules: that number reads as a CVSS score and we have
  not measured one. Ranking rides on the SARIF `level`. Results carry a stable
  `partialFingerprints.sakFindingId` so a re-scan updates an alert instead of creating a new one.
- **Decisions get in by parsing the findings file** (`scan.sh evidence --findings`), because the
  skills should write **one** artifact — the one a human reads — not a markdown report plus a JSON
  sidecar that drifts from it. Tables are read **by header name**, so a skill may reorder or add
  columns; `### Suppressed` sections mark their rows suppressed, `### Kit issues` is skipped, and a
  triage row about a scanner finding fills that finding in rather than becoming a duplicate. The
  contract is now stated in `sec-triage`, `sec-sast-deep` and `sec-ai-review`.
- `decision` gains `uncertain` (the skills' third verdict) alongside `real` / `fp` / `suppressed`.

### Added (T3.1a — `evidence.json`, the normalized per-finding record)
- **One shape for every dimension.** `evidence.json` (written next to `summary.json` when `SARIF=1`,
  rebuildable with `scan.sh evidence`) carries each finding as `id / dimension / tool / rule_id /
  file / line / message / severity / severity_source / cvss / decision / confidence / evidence`.
  `summary.json` says whether the scan passed; this says *what was found, where, and how bad*.
- **Severity is normalized, never invented.** `severity` is one of `critical|high|medium|low|info`,
  derived numeric-first (a rule's `security-severity`, CVSS bands) then from the SARIF level, then a
  documented per-tool default; `severity_source` keeps the tool's own value verbatim so the
  derivation stays auditable. This is the point of the record: osv-scanner marks *every* result
  `warning` regardless of a CVSS 9.1, semgrep says `ERROR`, gitleaks has no severity at all — so
  ranking findings across tools is impossible on raw output. `cvss` is passed through **only** where
  a tool supplied a CVSS-derived score (trivy, osv-scanner); semgrep's rule metadata bands the
  severity but never populates it, and judgment findings never get one.
- **Guarantees:** deterministic and diffable (sorted, no timestamp — two runs over unchanged code
  are byte-identical); deduplicated by identity (osv-scanner repeats an advisory per affected
  version); repo-relative paths (the docker `/repo` mount is stripped); scoped to the dimensions
  this run actually executed, so a `secret`-only scan cannot resurface yesterday's `sast` findings;
  nothing is dropped — an unmappable value becomes `info` plus a `warnings` entry.
- **Spec:** [`docs/schema/evidence.md`](docs/schema/evidence.md) — field table, per-tool mapping
  tables, versioned `schema` string, and the known gap (checkov/guarddog/pip-audit/js-audit emit no
  SARIF today, so they contribute dimension status but no per-finding rows).
- Requires `python3`; missing it skips the step with a notice, never fails the scan (`lib/evidence.py`,
  stdlib only, no network). This is the object the planned `kit.sarif` emitter (T3.1b) and the
  single-file HTML report (T3.1c) will both render from.

## [1.12.0] - 2026-08-11

> Includes the **1.11.2** eval-harness work, which landed on `main` but was never released as its
> own tag — it ships here instead of as a retroactive release.

### Changed (Phase A — sharper judgment: `sec-triage` + `sec-sast-deep`)
- **Hard-evidence bar for a REAL verdict.** Both skills now default to **FP** and require, to call a
  finding REAL, that you name all three: the **sink** (`file:line`), the **untrusted source** (a
  specific attacker-controlled input — not a constant/enum/framework-metadata/trusted-process
  output), and an **unbroken path** with no effective mitigation. A pattern match is not evidence of
  exploitability. An enumerated mitigation that actually covers the path (parameterization, argv +
  no `shell=True`, escaping / safe API / sanitizer, allow-list / constant, path-root or scheme/host
  validation, an authz decorator or ownership filter, a non-privileged trigger context) forces FP —
  credited only when genuinely present, never invented, never ignored. Folds in the
  claude-code-security-review FP-filtering patterns (C1). Credit seclab-taskflow-agent + claude-code-security-review.
- **Consistency-validation pass** before writing the findings file: re-read the REAL/UNCERTAIN list
  adversarially — every REAL must carry a concrete sink + named source; no double standard (same
  sink+mitigation ⇒ same verdict); severity ranks, never decides. Failing findings are corrected
  before the file is written.
- **Context-slice hygiene + codified funnel** in `sec-triage`: read `summary.json` / the raw log
  *through tools* per finding (never paste whole dumps); only `scan.sh` survivors enter triage.
- The daily findings table now records the **untrusted source** alongside the sink, so each REAL
  carries its evidence chain on the page.
- **`sec-audit` gains an opt-in whole-repo blueprint** — a 3-stage deep mode (threat-model the repo
  → per-component name the vuln classes worth auditing → audit each at the hard-evidence bar, with a
  cross-set consistency sweep), distinct from the routine scan+triage default. Most token-costly
  path; announced, scoped, and targeted (not file-by-file, not exhaustive — carries a "not audited +
  why" note). Credit seclab-taskflow-agent's threat-model→plan→audit shape.

### Added (measured before/after — the Phase-A acceptance gate)
- Re-measured the judgment prompt (`tests/eval/triage_prompt.md`, the eval mirror of the skills)
  on GLM-5.2 via NIM. **Held-out FP rate 3 → 0 with recall held at 100%** (precision 83.3% → 100%);
  dev split held at 31/31 (no recall regression). Three fixed cases were seen during earlier
  debugging (confirmatory), so **six fresh held-out twins in classes the prompt never names (LDAP /
  CRLF / XPath) were added after freezing the prompt** as a blind generalization check — GLM scored
  6/6. Full held-out now 36 cases at precision/recall 100%. Documented in `docs/compare/aikido-semgrep.md`.

### Changed (eval harness — corpus expansion + measurement hardening; still dev-only, not in the scan path)
- **Corpus grown 10 → 61 cases, split dev / held-out.** `cases.yaml` is now a **31-case dev (tuning)
  split** and `cases.holdout.yaml` a **30-case held-out split** that produces the reportable number
  and must not be read while tuning the prompt. Coverage spans **21 vuln classes** (sqli, command/
  code injection, path traversal, SSRF, deserialization, SSTI, XSS, XXE, weak-crypto, broken-auth,
  mass-assignment, IaC misconfig, CI injection, prompt-injection / insecure-output-handling,
  dependency-CVE, NoSQL, open-redirect, …) and **11 FP classes**. Most REAL cases have an FP **twin**
  (same class, one decisive difference: sanitizer / allow-list / reachability / safe API variant),
  tagged `difficulty: hard` — this is what gives the corpus resolving power the old 10-case set lacked.
- **Split enforced mechanically.** Every config loads both files; `run.sh` selects one via
  `--filter-metadata split=<dev|holdout>` (new `EVAL_SPLIT`, default `dev`; held-out writes
  `output.holdout.json`).
- **`score.mjs` no longer charges provider errors to the model.** A case that never reached the model
  (auth/billing/network — promptfoo `failureReason=2`) is excluded; an all-errored run now **refuses
  to report and exits 2** instead of printing a plausible-looking `0%`. New `EVAL_ALLOW_PARTIAL=1`
  scores only the cases that ran. Exit codes: 0 ok / 1 regression gate unmet / 2 no usable data.
- **Shared grader.** All configs point at one `grade.mjs` (`file://`) so a scoring change can never
  land on some backends and not others (keeps cross-backend scores comparable). New `EVAL_CONCURRENCY`
  knob (default 4) to dodge free-tier rate limits.
- **New backend variants** (OpenAI-compatible, key-gated, same corpus/prompt/grader): GLM-5.2 via
  NVIDIA NIM (`promptfooconfig.nim.yaml`), GLM-5.2 via Z.ai (`.glm.yaml`), Mistral Large 3 (`.mistral.yaml`).

### Added (eval harness — first held-out measurement)
- **First held-out measurement** (GLM-5.2 via NIM, 2026-07-10): dev split 31/31; **held-out split
  precision 83.3%, recall 100%, F1 90.9%, accuracy 90%** (TP=15, FP=3, FN=0, TN=12). All three misses
  are `difficulty: hard` FP twins the model over-flagged — the harness can now *see* a precision failure,
  the precondition for measuring Phase-A prompt changes. Documented in `docs/compare/aikido-semgrep.md`
  ("Measured triage quality"). The default backend (Claude) stays unmeasured pending API credit.

### Added (integrity — the tamper gate is now automatic)
- **`pre-push` runs `scan.sh verify` before the scan.** The manifest existed but sat on no automatic
  path in a consumer: a hand-edited vendored kit was invisible until someone happened to run
  `verify`. Now an edited copy blocks the push, with instructions to restore it via `bootstrap.sh`
  and to report kit bugs upstream. Sub-second; `SKIP_SECURITY=1` / `--no-verify` still bypass.
  Prompted by a real case — an AI assistant triaging findings in a consumer repo patched the
  vendored `scan.sh` in place (a correct fix, in the wrong layer: lost on the next bootstrap,
  and a per-repo fork of the deterministic scan layer in the meantime).
- **All five skills carry a hard read-only boundary** for `tools/security-audit-kit/`: never edit
  `scan.sh`, hooks, skills or `CHECKSUMS`, not even to fix a genuine bug. Kit bugs are recorded in
  the findings file under a new **Kit issues** section (observed / expected / effect), and the fix
  goes upstream behind a bumped pin.

### Added (integrity — Tier S: the pin now binds to the content)
- **`.kit-version` gains a third field: sha256 of the vendored `CHECKSUMS`**, written by
  `bootstrap.sh`. `scan.sh verify` recomputes it and **fails when the pin claims a release the
  vendored files aren't**. CHECKSUMS alone only proved the tree was *self-consistent*: because
  `.kit-version` is untracked in most consumers, a `git checkout` of the vendored directory
  restores older files together with their matching manifest while the newer pin file survives —
  verify passed, and the team believed it ran a release it didn't. Found in a real consumer repo
  (pin said v1.10.0, the files were v1.9.1 — 9 files apart, including `scan.sh` and two skills).
- **Fallback for pins written by an older bootstrap** (two fields, no digest): the pinned tag is
  compared against the newest version in the vendored `CHANGELOG`, so existing consumers get the
  check without re-vendoring first. A branch/SHA pin (`main`, a raw commit) has no version label
  and is left alone.
- e2e coverage for all three paths (digest mismatch, legacy label mismatch, branch pin no-op).

### Changed (docs kept in step with the release)
- READMEs (en/tr): install / `--check` / bump examples now pin **v1.12.0** instead of the
  long-stale v1.0.0–v1.6.0; the `uvx or pipx` requirement line finally lists **guarddog + zizmor**
  (shipped in v1.11.0); the lifecycle diagram's triage node shows the evidence bar; the `sec-triage`
  summary states the bar and the FP default.
- `docs/compare/aikido-semgrep.md`: the false-positive-triage row flips **🔜 → shipped** (the
  evidence bar is in), the tool's own supply-chain row records the pin-to-content binding, header
  re-dated. `landing/index.html` regenerated from it via `landing/build.py`.

### Fixed
- **`py-deps` audited the wrong environment when another venv was active.** `scan_py_deps` preferred
  `$VIRTUAL_ENV` over the repo's own `.venv`, so a scan started from another project's shell audited
  *that* project and reported a py-deps result saying nothing about this repo — a silently wrong
  answer from a gate. The repo's `.venv` now wins; an active venv is used only when the repo has
  none, and a mismatch is warned about. (Diagnosed by the same consumer-repo triage session
  mentioned above; the fix lands here rather than in that repo's vendored copy.)
- **`RELEASING.md` documented a `bootstrap.sh` invocation that cannot work** — `--ref <tag>` is
  rejected by the arg parser (`unknown flag`, exit 2). The correct form is a positional ref plus
  `--expect=<sha>`.
- **The vendored kit no longer defines the target repo's stack.** Adding the landing page put a
  `landing/build.py` in the kit, and `detect_semgrep_configs` scans `git ls-files` — so any consumer
  vendoring the kit got `--config p/python` appended to *every* semgrep run, even a pure JS/Go repo
  (slower scans, extra false-positive surface). The kit's own directory is now excluded from stack
  detection whenever it lives inside, but is not equal to, the repo root; a self-scan of the kit is
  unaffected. Caught by `tests/e2e.sh` ("cfg: python pack on non-python repo").
- **`tests/eval/run.sh` can no longer be forced into a live, costed run by a local `.env.local`.**
  The env-file loader sourced the file unconditionally, overriding provider keys the caller had
  deliberately blanked — which is exactly how `tests/e2e.sh` guarantees a test run never calls a
  paid API. On a dev box holding a valid key, `bash tests/e2e.sh` would have quietly executed 31
  billed API calls. Caller-set variables now win, including ones set to an empty value on purpose.
- **Nunjucks templating collision in fixtures.** promptfoo renders case code through Nunjucks, so a
  JSX `dangerouslySetInnerHTML={{ __html: … }}` brace-pair with a colon was a template syntax error.
  Fixtures now avoid literal `{{ }}` except valid GitHub Actions `${{ … }}` expressions.

## [1.11.1] - 2026-07-03

### Added (eval harness — dev-only skill-quality regression; not in the scan path)
- **`tests/eval/`** — a promptfoo-based (`@0.121.17`, pinned) harness that grades the `sec-triage`
  **REAL/FP judgment** against a labeled corpus (`cases.yaml`: 5 real exploitable findings + 5
  false positives across the classes triage must suppress — test-only, not-reachable, dev-placeholder,
  safe-parameterized, allow-listed). `run.sh` feeds each case + a provider-neutral distillation of the
  skill's Pass 1/2 (`triage_prompt.md`) to a model and `score.mjs` reports precision / recall / F1 /
  accuracy for the REAL class. This is roadmap **Tier-L L1** — the gate for Phase-A prompt changes and
  any future local / other-provider backend (change `providers:` to grade a candidate on the SAME
  corpus). Optional regression gates: `EVAL_MIN_RECALL` / `EVAL_MIN_PRECISION`. **Dev-only:** needs
  `node`/`npx` + a provider key (`ANTHROPIC_API_KEY`); skips cleanly (exit 0) otherwise, so it never
  hard-fails CI/e2e. CI `shellcheck` now also lints `tests/eval/run.sh`; e2e smoke-tests the skip path
  + `score.mjs` math; `output.json`/`.promptfoo/` gitignored.

## [1.11.0] - 2026-07-03

### Added (two new optional scan dimensions — supply-chain + CI/CD coverage)
- **`scan.sh guarddog`** — malicious/typosquat **dependency** detection via **GuardDog**
  (`==3.0.2`, Apache-2.0), run through uvx/pipx. `guarddog verify` checks each declared dependency
  (`requirements*.txt` → PyPI, `package.json` → npm) against the live registry for typosquatting,
  compromised-maintainer metadata, and malicious install scripts — the blind spot of the CVE
  scanners (osv/pip-audit/npm only find *known* CVEs). **HARD when run; standalone (not in `all`);
  needs network.** `GUARDDOG_VER` pin; `doctor` + conf + READMEs + e2e updated.
- **`scan.sh zizmor`** — GitHub Actions security via **zizmor** (`==1.26.1`, MIT), run through
  uvx/pipx, **offline** (no GitHub API → deterministic/air-gap friendly). Flags template injection,
  dangerous triggers (`pull_request_target`), token over-permissioning, credential persistence,
  unpinned actions. Runs only when `.github/workflows/` is present. **HARD when run; standalone
  (not in `all`).** SARIF supported (`SARIF=1`). `ZIZMOR_VER` pin + `ZIZMOR_ARGS` passthrough
  (e.g. `--min-severity medium`); `doctor` + conf + READMEs + e2e updated.

### Changed (self-dogfooding — the kit now passes its own zizmor gate)
- Hardened the kit's **own GitHub Actions workflows** to pass `scan.sh zizmor`: least-privilege
  `permissions:` blocks (top-level `contents: read` + job-scoped `security-events: write` only where
  SARIF upload needs it) and `persist-credentials: false` on all `actions/checkout` steps.

## [1.10.1] - 2026-07-03

### Added (maintainer tooling — no change to scan behavior or skills)
- **`RELEASING.md` + `scripts/release.sh`** — RC-gated release flow. Consumers pin to release tags,
  so every stable `vX.Y.Z` is gated behind a dogfooded `vX.Y.Z-rc.N` **pre-release**, and the final
  tag is cut on the **exact tested RC commit**. `release.sh` runs a preflight (on `main`, clean tree,
  in sync with origin, `scan.sh verify`, `e2e`, required CI checks green via `gh`) then cuts
  `rc` / `final` tags + GitHub releases (`preflight` / `rc [X.Y.Z]` / `final X.Y.Z`; `--yes`/`--skip-e2e`/`--no-gh`).
- **e2e stack fixture matrix** — `tests/fixtures/stacks/{django,react,terraform,monorepo}` (benign
  `.tpl` fixtures, materialized per-stack into throwaway repos) assert stack-aware detection in
  isolation; catches "wrong packs in a real project" before merge. 5 new assertions (36/0 total).
- **`.github/rulesets/main.json`** — importable branch-protection ruleset for `main` (PR required;
  required checks `shellcheck`/`checksums`/`self-audit`; no force-push/delete) + a README with UI/`gh`/manual apply steps.

### Changed
- CI `shellcheck` job now also lints `scripts/release.sh`.

## [1.10.0] - 2026-06-25

### Added (stack-aware injection coverage)
- **`scan.sh` now auto-selects semgrep packs from the repo's stack.** With `SEMGREP_CONFIGS`
  unset, it builds the ruleset from what's actually present: base `p/owasp-top-ten` + `p/secrets`,
  plus the detected language/framework packs — `p/python`/`p/django`/`p/flask`,
  `p/javascript`/`p/typescript`/`p/react`, `p/golang`, `p/java`, `p/php`, `p/ruby`, `p/csharp`.
  So a Django project gets Django's ORM-injection rules, a React project gets its XSS rules, etc.,
  instead of a one-size config. Only registry packs verified to exist are referenced (a missing
  pack would hard-fail this deterministic gate). Detection is git-based + manifest-content for
  frameworks; `node_modules` excluded. **Override unchanged:** set `SEMGREP_CONFIGS` (env/conf) and
  it wins verbatim — nothing is appended. `scan.sh doctor` now prints the resolved set and whether
  it is `stack-auto` or `from env/conf`; the `sast` log line shows the packs used.
- **`sec-sast-deep` gains Class 4 — semantic/stack-specific injection** (semgrep's blind spot):
  second-order/stored injection, wrapper-hidden sinks, and stack idioms the pattern packs miss
  (Django/SQLAlchemy `.raw()`/`.extra()`/`text()`, Flask `render_template_string` SSTI, Node
  `child_process`/`eval`/NoSQL operator injection, Java `Statement`/OGNL, unsafe deserialization).
  It reads the stack `scan.sh` detected and explicitly defers single-sink findings to `scan.sh sast`
  (no double-reporting). `sec-audit` now also triggers `sec-sast-deep` on raw-injection-sink signals.

### Changed
- `security-audit.conf.example`: `SEMGREP_CONFIGS` is now commented out by default (leave unset =
  stack-auto); documented that setting it overrides auto-selection verbatim. READMEs (en/tr) updated.

## [1.9.2] - 2026-06-25

### Fixed (secret scan in a git worktree — silent false-clean)
- **gitleaks now works in a git worktree.** A worktree's `.git` is a *file* pointing to a gitdir
  outside the worktree, so gitleaks-in-docker (mounting only the worktree) couldn't reach the
  history and silently reported "no leaks" (exit 0) — a dangerous false-clean. `scan.sh` now also
  mounts the common gitdir (`git rev-parse --git-common-dir`) when `.git` is a file. **No-op for a
  normal repo** (`.git` is a directory). Covers `secret` + `staged`. New e2e: a committed secret
  is caught when scanned from a worktree. (Found via a dogfooding question.)

> Note: normal branches were never affected — `scan.sh` scans the current checkout / branch (not
> `main`); semgrep/trivy/checkov already worked in worktrees too.

## [1.9.1] - 2026-06-24

### Fixed (dependency-scan reliability — found via dogfooding)
- **pip-audit now audits the project's environment, not uvx's empty one.** It points
  `PIPAPI_PYTHON_LOCATION` at an active `$VIRTUAL_ENV` (else the repo's `.venv`); without one it
  says so and suggests `scan.sh osv`. Previously "No known vulnerabilities found" was effectively
  auditing nothing for venv/uv projects.
- **JS audit now includes dev/build dependencies** (dropped `--prod` / `--omit=dev`). Vulns in
  build tooling (vite, undici, …) are real and were silently skipped; the triage layer decides
  reachability. **Note:** this may surface previously-missed dev-dep vulns and block a pre-push —
  that's the fix working; allowlist/triage as needed.
- **trivy skips build-output dirs** (`TRIVY_SKIP_DIRS`, default `**/.next,**/dist,**/build,…`) —
  removes the noise/memory/slowness from scanning `.next` etc. (which also contributed to a
  concurrent-run log garble). Configurable in `.security-audit.conf`.

> For lockfile-accurate, all-ecosystem dependency CVEs (incl. transitive + dev), `scan.sh osv`
> remains the most reliable — it reads `uv.lock`/`pnpm-lock` directly.

## [1.9.0] - 2026-06-24

### Added
- **`sec-audit` orchestrator skill** — a one-command entry point: runs `scan.sh all` + triage,
  then runs **only the deep passes the repo calls for** (signal-gated: `sec-sast-deep` on authz
  surfaces, `sec-ai-review` if the code calls an LLM, `sec-threat-model` for a new subsystem; all
  on `deep`), and consolidates into one `findings-<DATE>.md`. Cost-aware + transparent: announces
  which deep pass runs and why before spending tokens; default = scan + triage only (respects the
  cadence). Installed into `.claude/skills/`; READMEs + e2e updated.

## [1.8.0] - 2026-06-24

### Added
- **`scan.sh osv`** — optional broad multi-ecosystem dependency-CVE dimension via **OSV-Scanner**
  (Google), pinned by docker digest (`v2.4.0`). Scans lockfiles across py/js/go/rust/… against
  OSV.dev; HARD when run (exit 1 = vulnerabilities). Standalone / opt-in (NOT in `all`) so it does
  not double-gate with pip-audit/npm/trivy. SARIF supported (`SARIF=1`). `OSV_VER`/`OSV_DIGEST`
  pins; `doctor` + conf example + e2e + READMEs updated.

## [1.7.0] - 2026-06-23

### Added (adoption / interop)
- **`.pre-commit-hooks.yaml`** — use the kit via the [pre-commit](https://pre-commit.com)
  framework: `sec-staged` (every commit), `sec-deps` (on a manifest change), `sec-all`
  (pre-push / manual). An alternative to the kit's own git hooks.
- **`install.sh --skills-only`** — installs the skills + config WITHOUT setting
  `core.hooksPath`, so pre-commit-framework users get the Claude skills without a hooks clash.
- e2e covers both (`.pre-commit-hooks.yaml` validity + `--skills-only` leaves hooksPath unset).

## [1.6.0] - 2026-06-23

### Added (supply-chain hardening — Tier S Layer 0)
- **`bootstrap.sh --expect=<sha>`** (or `KIT_EXPECT_SHA`) — *enforces* the pin: refuses to vendor
  if the ref resolves to a different commit than you reviewed (defends against a wrong ref).
- **Tag-repoint guard** — re-vendoring an already-pinned ref that now resolves to a *different*
  commit is refused (the tag/branch moved) unless you pass `--allow-ref-change`. Turns the pin
  from a recorded value into an enforced one. e2e covers both (refuse + accept) offline.

## [1.5.0] - 2026-06-23

### Changed (skill content enrichment — no new infra)
- **`sec-triage`:** before deferring/allowlisting a *dependency CVE*, check **CISA KEV** +
  **EPSS** on demand (just those CVEs) — in KEV / high EPSS → do not defer. Lightweight close of
  the KEV/EPSS idea (no vendored feeds; the kit stays offline, the lookup stays fresh).
- **`sec-sast-deep`:** added a "past-fix recurrence & incomplete patches" bonus pass — diff recent
  security commits for incomplete fixes; grep the codebase for siblings of a past finding's pattern.
- **`sec-ai-review`:** added an explicit untrusted-text-surfaces checklist (8 surfaces, from Lyrie's
  "Shield Doctrine") + named attack classes (crescendo / tap / pair / gcg / autodan) for static review.

## [1.4.0] - 2026-06-23

### Added
- **`sec-threat-model` skill** — STRIDE + data-flow threat modeling of the repo's attack surface
  and trust boundaries (higher-altitude than `sec-sast-deep`). Judgment-only; installed into
  `.claude/skills/`; writes a living `docs/security/threat-model-<DATE>.md` and promotes concrete
  gaps into the `sec-triage` flow. READMEs (intro, lifecycle diagram, cadence table) + e2e updated.

## [1.3.1] - 2026-06-17

### Changed (supply-chain hardening of the kit's own CI/test tooling)
- Pin the CI shellcheck image by **immutable digest** (was the `:v0.10.0` tag).
- Pin all **GitHub Actions by commit SHA** (`actions/checkout`, `astral-sh/setup-uv`,
  `github/codeql-action/upload-sarif`) with a `# vX.Y.Z` comment — mutable tags can be repointed.
- Fix the `install.sh` summary wording: pre-commit runs a staged-secret scan on every commit
  (+ `deps` on a manifest change), not `fast`; add `changed` to the listed scopes.

> Note: the kit's docker scan tools (gitleaks/trivy/syft) were already digest-pinned. The
> Python tools (semgrep/checkov/pip-audit) remain **version-pinned, not hash-pinned** — tracked
> as a roadmap item to discuss before implementing.

## [1.3.0] - 2026-06-17

### Added — triage v2 (higher signal, less noise)
- `.security-exclusions.md` (template `exclusions.example.md`, installed by `install.sh`): a
  per-project list of do-not-report classes + precedent assumptions the triage skills read first.
- **Confidence-scored verification pass** in `sec-triage`: every surviving finding is judged
  independently with a `[0,1]` confidence; only ≥ 0.7 is reported, the rest go to a "Suppressed"
  section (on record, not silently dropped). New confidence column in the findings template.
- **Reachability / attacker-control gate** across `sec-triage` and `sec-sast-deep`: a finding not
  reachable from untrusted input is dropped as FP.
- **`tests/e2e.sh`** — end-to-end local test: vendors the working tree into a throwaway repo,
  runs `install.sh`, and asserts each gate fires (install/hooks/skills/config, secret + pre-commit
  gate, SAST via a fixture rule, summary.json). Tests the scriptable plumbing, not AI judgment.
- **Supply-chain integrity (Tier S Layer 2):** a `CHECKSUMS` manifest + `scan.sh verify` (detects
  tampered files / a rogue skill in a vendored copy) + `scan.sh checksums` to (re)generate it.
  `install.sh` runs verify (advisory); CI fails if the manifest is stale.

### Changed
- `sec-sast-deep` reframed as an explicit 3-phase **baseline → compare → assess** flow (map the
  project's known-correct patterns, flag deviations, then assess) + the reachability + confidence
  gates and a Suppressed sub-list.
- `sec-ai-review` gains the exclusions read + confidence gate (its data/authority flow already is
  the reachability gate).

## [1.2.0] - 2026-06-16

### Added
- `sec-ai-review` skill — semantic AI/LLM security review mapped to the OWASP LLM Top 10
  (prompt injection, insecure output handling, excessive agency, disclosure, supply chain).
  Sourced from `utkusen/awesome-ai-security`. Installed into `.claude/skills/` like the others.
- `scan.sh changed` — diff-aware SAST that runs semgrep only on files changed vs a base
  (`$BASE_REF`, else merge-base with `origin/main`, else staged + unstaged).
- Status badges in the README (ci, self-audit, license, release).
- `self-audit` workflow (dogfooding): the kit runs its own `secret` + `sast` scans on this
  repo and uploads SARIF to GitHub code scanning; weekly schedule + on push/PR.

### Changed
- Skill source templates moved from the repo root into `skills/` (organizational only; they
  are still installed into the target repo's `.claude/skills/<name>/SKILL.md`).
- CI split: `ci.yml` is shellcheck-only; the self-scan moved to `self-audit.yml`.
- Bumped `actions/checkout` v4 → v5.

## [1.1.0] - 2026-06-16

### Added
- `scan.sh staged` — sub-second secret scan of staged changes (`gitleaks protect --staged`).
- `scan.sh doctor` — reports toolchain availability, resolved pins, and detected projects.
- `summary.json` — every scan writes a machine-readable summary alongside the raw log.
- Optional SARIF output (`SARIF=1`) for GitHub code scanning / IDE ingestion.
- Version pinning for the Python tools: `SEMGREP_VER`, `CHECKOV_VER`, `PIP_AUDIT_VER`.
- Immutable digest pinning for the docker tools: `GITLEAKS_DIGEST`, `TRIVY_DIGEST`, `SYFT_DIGEST`.
- CI: shellcheck on all scripts + a dogfood job that runs the kit's own secret scan.

### Changed
- **pre-commit** now runs a staged-secret scan on *every* commit (previously secrets were
  only caught at push time), and runs `scan.sh deps` only when a dependency manifest changes.
- `fast` scope is now `staged + deps` (was full-history `secret + deps`).
- README restructured: bootstrap-from-repo is the primary install; the lateral `cp` method
  is now explicitly labeled "offline copy from another local project", plus a clone variant.

### Fixed
- The pinning claim is now true end-to-end: semgrep/checkov/pip-audit were previously run
  unpinned via `uvx`. The new `pyrun` helper pins them and also fixes the pipx fallback
  (`--from` vs `--spec`).

## [1.0.0] - 2026-06-16

### Added
- Initial public release: portable, CI-independent local security scanning across secrets
  (gitleaks), SAST (semgrep), dependency CVE (pip-audit + js audit), IaC (checkov),
  container/fs (trivy), and SBOM (syft).
- Git-hook triggers (pre-commit / pre-push) and `bootstrap.sh` pinned-vendor installer.
- Two Claude skills: `sec-triage` (finding triage) and `sec-sast-deep` (semantic SAST).

[1.9.2]: https://github.com/boraeresici/security-audit-kit/compare/v1.9.1...v1.9.2
[1.9.1]: https://github.com/boraeresici/security-audit-kit/compare/v1.9.0...v1.9.1
[1.9.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.8.0...v1.9.0
[1.8.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.7.0...v1.8.0
[1.7.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/boraeresici/security-audit-kit/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/boraeresici/security-audit-kit/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/boraeresici/security-audit-kit/releases/tag/v1.0.0
