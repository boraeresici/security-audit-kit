# Usage

Every `scan.sh` command, what each run records, and the install-time package check. Start with the [README](../README.md).

## Usage

```
bash tools/security-audit-kit/scan.sh all        # full (before a PR)
bash tools/security-audit-kit/scan.sh fast       # staged-secret + deps (after adding a package)
bash tools/security-audit-kit/scan.sh staged     # sub-second secret scan of staged changes
bash tools/security-audit-kit/scan.sh changed    # SAST on changed files only (diff-aware, fast)
bash tools/security-audit-kit/scan.sh secret|sast|deps|iac|container|sbom
bash tools/security-audit-kit/scan.sh osv        # optional: broad multi-ecosystem dep CVE (OSV-Scanner)
bash tools/security-audit-kit/scan.sh guarddog   # optional: malicious/typosquat deps (GuardDog; needs network)
bash tools/security-audit-kit/scan.sh zizmor     # optional: GitHub Actions security (zizmor; offline)
bash tools/security-audit-kit/scan.sh pkgcheck npm lodash    # optional: check ONE package BEFORE installing it
bash tools/security-audit-kit/scan.sh doctor     # report toolchain, pins, detected projects
bash tools/security-audit-kit/scan.sh verify     # check kit files against CHECKSUMS (integrity)
bash tools/security-audit-kit/scan.sh evidence   # rebuild evidence.json from the SARIF on disk
bash tools/security-audit-kit/scan.sh report     # render one self-contained HTML report
bash tools/security-audit-kit/scan.sh help       # commands, gate tags, prerequisites, what `all` leaves out
```

**First run:** `scan.sh doctor` → `scan.sh all` → read the closing summary → `/sec-triage`. Every
scan ends with one screen, the closing summary:

```
── run: 20261102T193745-5208 · scan all · 70.5s
   secret     pass             2.8s
   sast       error            4.7s  semgrep exit 2 (scan error, not a finding)
   js-deps    skipped          0.1s  package.json found but none is auditable ...
   container  findings         4.5s  CRITICAL/HIGH findings (soft, not blocking) · trivy DB 3h old
   iac        not_applicable   0.0s  no terraform
── not in 'all': osv guarddog zizmor sbom — run scan.sh <name> for those
── BLOCKED (rc=1): sast (error) — commit/push is blocked.
── scanner FAILED: sast — this is not a finding; do not allowlist it. Fix the scan (see the raw log) and re-run.
```

It lists each dimension with its status, time and reason, and names what the command does not
cover. When Docker or uvx/pipx is missing, one line names the dimensions left uninspected and how
to fix that. This is repeated on every hook run, because the day you install is not the day you
push. When something blocks, the summary says whether it was a finding (with the ways to unblock)
or a scanner that failed (fix the scan, never allowlist it).

A scan reads the code that is checked out. When the branch is behind its upstream, it judged older
code than the remote has: findings already fixed upstream look open, and upstream code went
unscanned. The closing summary then says
`── git: main is 12 commit(s) behind origin/main (as of the last fetch, 3h ago) — this scan saw older code …`,
and `doctor` says it before you scan. It is a warning, never a block. The kit does not fetch, so
"behind" is as of your last fetch, and the line gives its age.

`scan.sh changed` scans the files that differ from the merge-base with the remote's default branch
(`origin/HEAD`, else `origin/main`, else `origin/master`). `BASE_REF=<ref>` sets the base instead.
With neither, it looks only at uncommitted changes. The run names its base (`vs origin/master`)
either way.

Every run writes a machine-readable `docs/security/scan-findings/summary.json`: the gate's decision
(`gate.exit_code`, `gate.blocked_by`), the `run_id` of the run that wrote it (see *Two scans at
once* below), and per dimension what actually happened — `pass`, `findings`, `error`, `skipped`,
`indeterminate` or `not_applicable`, with the reason. A dimension whose tool was missing or crashed
is `skipped`/`error`, never `pass`. It also records what was scanned, with what (`provenance`:
commit, dirty tree, kit version, config, rules, tool pins, scope) and which SARIF files this run
produced (`artifacts`, with sha256). Contract and migration from the old `pass`/`fail` form:
[docs/schema/summary.md](schema/summary.md). Set `SARIF=1` to also emit per-tool SARIF (for GitHub code scanning / IDE) into
`.../sarif/` (replaced on every `SARIF=1` run: it holds that run's files only, never an earlier
run's) — and, alongside it, **`evidence.json`**, built only from this run's listed SARIF files, of
dimensions that actually inspected something: every finding from every dimension in **one
shape**, with severity normalized to `critical|high|medium|low|info` and the tool's own value kept
verbatim next to it. It exists because the tools disagree: osv-scanner labels a CVSS 9.1 advisory
`warning`, semgrep says `ERROR`, gitleaks has no severity at all — so "sort by how bad it is" is
impossible over raw output. Fields, per-tool mapping tables and the guarantees (deterministic and
diffable, deduplicated, repo-relative paths, never invents a score) are specified in
[docs/schema/evidence.md](schema/evidence.md). Needs `python3`; without it the step is skipped,
never failed.

Once a judgment pass has written `findings-<date>.md`, the same step folds those decisions in and
emits **`sarif/kit.sarif`** — the skills' own findings (an IDOR traced through the call path, a
prompt-injection sink) as SARIF 2.1.0, so they reach GitHub Code Scanning like any scanner alert.
Scanner findings are not re-reported (their own SARIF already covers them); suppressed findings are
emitted *as suppressed*, with the triage reason, rather than vanishing. The existing self-audit
workflow uploads the whole `sarif/` directory, so nothing needs wiring.

For a human audience, `REPORT=html` (or `scan.sh report`) renders the same record as **one
self-contained `report-<date>.html`** — no server, no JS, no external fetch, so it opens offline and
prints straight to PDF. It shows what SARIF can't: the triage decision on each scanner finding, and
the suppressed ones on record. Its header says only what it can vouch for: *clean* only when every
dimension that applies inspected something and nothing is reported. Otherwise it says *NOT complete*
(naming what was skipped or crashed), *blocked* (naming each blocker, a crash as "scan error, not a
finding") or *unknown*. Scan time and report date are shown apart. `scan.sh report` /
`scan.sh evidence` exit 1 when they cannot produce their file; a report failure after a scan is
printed but does not change the scan's exit code.

Automatic triggers (after install):
- **pre-commit** — always a sub-second staged-secret scan (`scan.sh staged`); plus
  `scan.sh deps` when a dependency manifest is staged (both HARD). **During a merge** the whole
  other branch is staged. A secret in a line that branch already had is *reported*: it is already
  upstream, so triage it there, and it does not block. Only a secret in a line the merge itself
  adds (a conflict resolution, an edit made while merging) blocks.
- **pre-push** — runs `scan.sh verify` (integrity, sub-second) and then `scan.sh all` (both HARD).
  Right before a PR. Verify runs first because a scan is only worth its exit code if the kit that
  produced it is the one you pinned.
- Bypass (emergency): `SKIP_SECURITY=1 git commit` / `git push --no-verify`.

**Two scans at once.** A pre-push running `all` while you run `scan.sh sast` by hand is ordinary,
and both used to write the same `raw-<date>.log` (interleaved lines) and the same `summary.json` —
which `/sec-triage` could read mid-write. A `mkdir`-based lock in `.git/security-audit-cache/` now
serializes the *writers*: `summary.json` is written to a temp file and renamed (a reader sees the old
record or the new one, never half of one), and a second run waits `SCAN_LOCK_WAIT` seconds (30 by
default) for the lock. If it cannot take it, **the scan still runs** — a push is never blocked because
someone else is scanning — it just writes its own record and says so. A lock is reclaimed only
when its owner is gone, never for age alone (a long scan stays protected): the owner's PID is dead,
or alive but a different process (PID reuse, told apart by start time), or the lock was taken on
another host and its heartbeat (refreshed every `SCAN_LOCK_HEARTBEAT_SEC`, 30) has been silent for
`SCAN_LOCK_STALE_MIN` (60) minutes. An unreadable lock is reclaimed after a few seconds instead of
being waited on. When several runs find the same stale lock, exactly one reclaims it. A run removes
the lock only while it still holds its own token, and it publishes only under that token. A run whose lock was taken over keeps its
record in `runs/<run-id>/`. `scan.sh doctor` prints whether the lock is free, held (by whom), or stale (and why).

Every run gets an id (`run_id` in `summary.json`) and builds its record in its own
`scan-findings/runs/<run-id>/` first. Only the lock holder then publishes it into the shared
record (`summary.json`, `sarif/`, `evidence.json`, `report-<date>.html`), in one short step at the
very end that a Ctrl-C cannot split; `summary.json` goes last. A run without the lock never
touches the shared record. It keeps its own complete record (raw log, summary, SARIF, evidence)
in `runs/<run-id>/` for `SCAN_RUNS_KEEP_DAYS` (7) days. A cancelled run stops, publishes nothing
and leaves the previous record as it was. `scan.sh evidence` / `report` rewrite the shared record,
so without the lock they refuse (exit 1) instead of writing.

> **The vendored kit is read-only.** Don't hand-edit `tools/security-audit-kit/` — not you, not a
> teammate, not an AI assistant "fixing" the scanner mid-triage. The edit is lost on the next
> `bootstrap.sh`, and until then pre-push blocks for everyone. Found a real bug? Report it upstream
> and bump the pin. The kit's own skills carry this as a hard rule.

## The install-time window — `scan.sh pkgcheck` and the agent hook

Every other dependency dimension reads a manifest that is **already in the repo**. That is one step
too late for a malicious package: `npm i <pkg>` and `pip install <pkg>` run the package's install
script the moment they resolve it, and the kit's pre-commit hook only sees the changed manifest
afterwards. Git hooks cannot see an install; an agent tool-call hook can.

```bash
bash tools/security-audit-kit/scan.sh pkgcheck npm lodash react@18.2.0   # ad-hoc, any time
bash tools/security-audit-kit/install.sh --with-agent-hook               # opt-in: wire it to the agent
```

`--with-agent-hook` adds a `PreToolUse` hook for the `Bash` tool to `.claude/settings.json` (idempotent;
it never rewrites anything else). Before the agent runs an install command, the hook takes the package
names off that command line and asks guarddog about them — while nothing has executed. A flagged
package blocks the tool call; the agent is told what fired and told not to retry.

**What it blocks, and why the list is short.** guarddog reports two different things under one
count: `capability-*` rules (what a package *can* do — `requests` fires three) and `threat-*`/metadata
rules (what looks wrong). Neither maps cleanly to "block". Measured on 2026-08-24 against the 18
most-installed pypi/npm packages, **15 distinct non-capability rules fired on 8 of them** — including
`threat-process-download-exec` on pandas and setuptools, and `metadata_mismatch` on typescript. A gate
that refuses `pip install django` gets uninstalled, and an uninstalled gate protects nothing. So the
kit blocks on an explicit list of ~24 malice-specific rules (typosquatting, dependency confusion,
install-time network access, reverse shells, exfiltration, cryptomining, keylogging, maintainer-domain
takeover) — every one of which fired on **none** of those 18 packages. Everything else is printed as a
note and allowed. Tune with `PKGCHECK_BLOCK_EXTRA` / `PKGCHECK_REPORT_EXTRA` in `.security-audit.conf`.

**What it does not do, stated plainly:**
- It guards the **agent's** tool calls. A human typing `npm i` in a terminal is not covered — nothing
  in a hook can see that.
- Anything it cannot inspect is **allowed, loudly**: no network, no `uvx`/`pipx`, a VCS or local-path
  install, a package the registry 404s. guarddog itself prints *"No risks found"* when the download
  failed, so the kit treats a failed download as `INDETERMINATE` — never as clean.
- It is not a CVE check. `pkgcheck` asks "is this package malicious?"; `deps`/`osv` ask "does it have
  known vulnerabilities?" Both, or neither.
- First check of a package costs ~15-20s (guarddog downloads and analyses it). What guarddog *found*
  is cached in `.git/security-audit-cache/`, keyed by package, version **and the pinned guarddog
  version**. Every later check re-judges those findings with the policy in force, so adding a rule
  to `PKGCHECK_BLOCK_EXTRA` blocks a package that was allowed yesterday, with no re-download. An
  exact `pkg@version` entry never expires; an unversioned one expires after a day.
  `PKGCHECK_CACHE=refresh` re-scans and replaces the entry, and `PKGCHECK_CACHE=off` skips the cache.
  A half-written entry is a miss, and an INDETERMINATE result is never stored. `scan.sh doctor` prints
  whether the hook is wired, where the cache is, and how many rules block.
