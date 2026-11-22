# Install, update and platforms

Other install paths, making the skills visible, the skills in Codex, the Skills CLI, the pre-commit framework, updates, reachability, platform notes and requirements. Start with the [README](../README.md).

## Other ways to install

Both land the kit at `tools/security-audit-kit/` in the target repo, then run
`install.sh` from the repo root (the hooks hard-code that path).

**Clone, then copy it in** — air-gapped, or you want to inspect the full repo first:
```bash
git clone https://github.com/boraeresici/security-audit-kit.git
mkdir -p /target/project/tools
cp -R security-audit-kit /target/project/tools/security-audit-kit
cd /target/project && bash tools/security-audit-kit/install.sh
```

**Copy from a project that already has it** — offline, no network; propagate the same
vendored copy laterally to another local repo:
```bash
cp -R /project-a/tools/security-audit-kit /project-b/tools/
cd /project-b && bash tools/security-audit-kit/install.sh
```

## After install: making the skills visible in Claude Code

The five `sec-*` skills are plain files at `<repo-root>/.claude/skills/<name>/SKILL.md`.
Claude Code reads them off disk, so **you do not need to commit anything to see them**.
Two things decide whether they show up:

1. **Claude Code's working root must BE the repo root** that holds `.claude/skills`. Only
   `<root>/.claude/skills` is scanned — subdirectories are not, and `--add-dir` does not
   extend the scan. If you keep several repos side by side under a container folder and
   open the **container** in your editor, skills installed into one of the repos will not
   load:

   ```
   work/acme/                 <- opening THIS in the editor: no skills
     backend/                 <- opening THIS: skills load
       tools/security-audit-kit/
       .claude/skills/sec-*/
     frontend/                <- needs its own install
   ```

2. **Start a new session.** Skills are enumerated at session start; toggling them in
   `/skills` mid-session does not discover newly installed ones.

Confirm with `/skills` — `sec-audit`, `sec-triage`, `sec-sast-deep`, `sec-ai-review` and
`sec-threat-model` should all be listed.

**Committing is for your teammates, not for you.** The skills reach the rest of the team
the way any other file does, through git:

```bash
git add .claude/skills tools/security-audit-kit .security-audit.conf .security-exclusions.md
git commit -m "chore(sec): add security-audit-kit"
```

**One install per repository.** The kit is repo-scoped by design: hooks are wired through
that repo's `core.hooksPath`, `.security-audit.conf` carries that repo's SAST paths, and
findings land in that repo's `docs/security/scan-findings/`. A backend and a frontend in
two repos need two installs — there is no cross-repo mode.

## The skills in Codex

Codex reads the same plugin, so the skills install there with no separate package. From a
terminal:

```bash
codex plugin marketplace add boraeresici/security-audit-kit --ref v1.22.0
codex plugin add security-audit-kit@security-audit-kit
```

`--ref` pins a release; without it Codex follows the default branch. A local checkout works in
place of `boraeresici/security-audit-kit`. Start a new Codex session afterwards. The skills load as
`security-audit-kit:sec-triage`, `security-audit-kit:sec-audit`, and so on, the same names as in
Claude Code. Undo: `codex plugin remove security-audit-kit@security-audit-kit`, then
`codex plugin marketplace remove security-audit-kit`.

The scanner contract is the same as with the Claude Code plugin: the skills use the repo's vendored
scanner and never download one, so vendor it too (`bash bootstrap.sh <tag> --no-skills`).

Codex reads `plugin/.codex-plugin/plugin.json`. The plugin has no hook since 1.22.1; the edit check
is wired per project with `install.sh --with-edit-hook`, which writes Claude Code's
`.claude/settings.json` only.

What is not there yet: `install.sh --with-agent-hook` wires the package pre-install check for
Claude Code only, and the kit is not listed in the OpenAI plugin directory yet. The package for it is
built by `scripts/build_codex_zip.py` (the manifest, the icon and the skills; no hooks, which that
directory refuses); submitting it is the maintainer's step in [RELEASING.md](../RELEASING.md). Installed
from the repo, Codex caches the plugin folder (`plugin/`: the manifests, the icon, the skills, the
hook and the licence), not the scanner or the docs.

## The skills with the Skills CLI

The [Skills CLI](https://github.com/vercel-labs/skills) (`npx skills`) installs `SKILL.md` folders
for many agents at once, Claude Code and Codex among them. It is a third-party tool, not part of
the kit. Tried with `skills@1.7.4`:

```bash
DISABLE_TELEMETRY=1 npx -y skills@1.7.4 add boraeresici/security-audit-kit#v1.22.0 -s '*' -a claude-code -a codex
```

- **Pin both.** `#v1.22.0` pins the skills; `skills-lock.json` records that ref and a hash per
  skill. `skills@1.7.4` pins the CLI: `npx skills` alone runs its newest release, which may be days
  old.
- **Telemetry is on by default.** The CLI reports installs, with the repo and skill names for a
  public GitHub source. `DISABLE_TELEMETRY=1` (or `DO_NOT_TRACK=1`) turns it off; see
  [data flow](data-flow.md).
- **Where the files go.** Each skill is copied to `.agents/skills/<name>/` and linked from
  `.claude/skills/<name>`. With `-a '*'` it also creates folders for every agent it knows, including
  an `agent/skills/` folder at the repo root; name the agents you use instead.
- **Only the skills.** The scanner is not installed, and the skills say so when it is missing, as
  with the plugin. Vendor it with `bash bootstrap.sh <tag> --no-skills`. `install.sh` leaves skill
  folders that are links alone in every mode: it neither overwrites nor removes them.

## Using the pre-commit framework (alternative to the kit's own hooks)

Already on [pre-commit](https://pre-commit.com)? Add the kit to your `.pre-commit-config.yaml`
instead of using its git hooks:

```yaml
- repo: https://github.com/boraeresici/security-audit-kit
  rev: v1.22.0          # pin a tag
  hooks:
    - id: sec-staged   # every commit: staged-secret scan
    - id: sec-deps     # on a dependency-manifest change: CVE audit
    - id: sec-all      # pre-push / manual: full scan
```
```bash
pre-commit install                         # sec-staged + sec-deps
pre-commit install --hook-type pre-push    # sec-all
```

Use **either** the pre-commit framework **or** the kit's own hooks (`install.sh` / `core.hooksPath`),
not both (`core.hooksPath` would shadow pre-commit). For the Claude skills + config without
touching hooks: `bash tools/security-audit-kit/install.sh --skills-only`.

Why this shape (consistent with the kit's own ethos):
- **No `curl | bash`.** This is a *security* tool — download, review, then run. Piping
  a remote script straight into a shell is the exact anti-pattern the kit warns against.
- **Pinning is required in practice.** A moving ref (`main`) breaks the "no drift vs.
  CI" promise; bootstrap warns if you don't pass a tag/SHA. It writes a `.kit-version`
  (ref + resolved SHA) you can commit so the whole team shares one pinned version. Pass
  `--expect=<sha>` — the **full** commit id the tag resolves to (40 hex characters; a prefix is
  refused since 1.22), not the annotated tag's own object id
  (`git rev-parse <tag>^{commit}`) — to **enforce** the pin (refuse if the ref resolves elsewhere), and a
  re-vendor of an already-pinned ref that now points to a different commit is refused
  (tag-repoint guard) unless you pass `--allow-ref-change`.
- **Auto-scan is opt-in** (`--scan`), not the default — it respects the kit's split
  between the gate (hooks, deterministic) and judgment (`/sec-triage`, needs Claude).
- **Idempotent.** Re-run `bash tools/security-audit-kit/bootstrap.sh <new-tag>` to
  update to a newer pinned version (overwrites the vendored copy, preserves your
  `.security-audit.conf`).

**Alternative for teams wanting upstream updates:** vendor the kit as a git
`submodule`/`subtree` instead of a bootstrap copy. Heavier (submodule friction);
only worth it if you want `git`-tracked updates from the kit repo.

### Detecting & applying updates

The bootstrap **vendors a copy**, so your project's `git` does not track the kit
repo — it won't tell you upstream changed. Two ways to find out:

1. **`--check` (built in, read-only).** Compares the vendored `.kit-version`
   against the newest **stable** release tag in the kit repo via `git ls-remote`. Release
   candidates are offered only on the rc channel, which you opt into with `--check --channel=rc`
   or `KIT_CHANNEL=rc`. On stable, a newer RC is mentioned but never offered. It then prints the **upgrade notes** of every version
   in between, read from that tag's CHANGELOG with a one-commit shallow fetch. Your vendored copy
   is not touched:
   ```bash
   bash tools/security-audit-kit/bootstrap.sh --check
   # vendored version : v1.19.1
   # latest tag       : v1.22.0
   # !! UPDATE AVAILABLE -> bash tools/security-audit-kit/bootstrap.sh v1.22.0
   # upgrade notes v1.21.0 -> v1.22.0 (do these when you update):
   #   [1.20.0]
   #     Read the first three before updating: they change what scripts that read the kit's output see.
   #     - **`summary.json` schema 2 (breaking for parsers of `status`).** The value "fail" is gone: ...
   ```
   Exit code: `0` = up to date, `1` = update available, `2` = cannot tell (kit repo unreachable,
   no release tags), so you can wire it into a periodic check or a `make` target. Every release carries an *Upgrade notes* section (the release
   script refuses to tag without one), so "nothing to do" is stated rather than implied. Re-running
   `install.sh` after an update keeps your `.security-audit.conf` and names any setting the new
   example has that your config does not.
2. **Watch the kit repo's releases** on GitHub (Watch → Custom → Releases) for a push
   notification when a new tag ships.

**Apply the update** (idempotent — overwrites the vendored copy, preserves your
`.security-audit.conf`):
```bash
bash tools/security-audit-kit/bootstrap.sh v1.22.0   # the new pinned tag
git diff -- tools/security-audit-kit                 # review what changed
git add tools/security-audit-kit && git commit -m "chore(sec): bump security-audit-kit to v1.22.0"
```
The committed `.kit-version` (ref + SHA + a content digest) is the team's shared record of which
pinned version is in use, and what `--check` compares against next time. The third field binds the
pin to the files: `scan.sh verify` recomputes it and **fails if the pin claims a release the
vendored files aren't** — the case where an untracked `.kit-version` outlives a checkout that
reverted the vendored tree, leaving the team convinced they run a version they don't. A pin written
by an older bootstrap has no digest; verify then falls back to comparing the tag against the
vendored `CHANGELOG`. Re-run `bootstrap.sh <tag> --expect=<sha>` to resolve a mismatch.

### Reachability for dependency CVEs (opt-in)

`OSV_CALL_ANALYSIS=go bash scan.sh osv` asks osv-scanner whether the vulnerable symbol is actually
**called** in your code. Two rules make it safe to turn on:

- **The gate does not loosen.** With call analysis on, osv-scanner drops uncalled vulnerabilities by
  default; the kit always pairs it with `--all-vulns`, so the finding set and the exit code are
  unchanged. What you gain is a *called / uncalled* signal for triage — not fewer findings.
- **No build scripts.** Rust call analysis works by running the dependency tree's build scripts. A
  scanner that executes untrusted code to decide what to report is an own-goal, so it is **refused**
  unless you explicitly accept it with `OSV_ALLOW_BUILD_SCRIPTS=1`.

Go is the ecosystem osv-scanner supports without executing anything. Python and JS reachability
needs a heavier tool (`dep-scan`) and is not shipped — an "uncalled" marking is also not proof:
call graphs miss reflection, dynamic dispatch and plugin loading, so `sec-triage` treats it as a
heavy thumb on the scale, never a verdict.

## Platform notes (Windows: use WSL2)

The kit is bash-first. Linux and macOS are native; on Windows the supported path is **WSL2**.

| Environment | Status | Notes |
|---|---|---|
| Linux | ✓ full | native |
| macOS | ✓ full | native (bash 3.2 — the scripts stay POSIX-ish on purpose); CI runs the offline e2e on `macos-latest` |
| **WSL2** | Expected, **not verified** | should work *inside* the WSL filesystem, with docker dimensions through Docker Desktop's WSL integration; no WSL2 run has been recorded yet (see below) |
| Git Bash / MSYS | Partial | `uvx`/`pipx` dimensions and the git hooks work; **docker** dimensions (secret, container, sbom, osv) are unreliable — MSYS rewrites the `/repo` mount into a Windows path before docker sees it. Prefix `MSYS_NO_PATHCONV=1`, or move to WSL2 |
| PowerShell / cmd | ✗ | not supported — no bash |

`scan.sh doctor` prints which of these it is running under, so a mangled mount is named rather than
debugged. Two WSL2 habits that matter:

- **Keep the repo on the Linux side** (`~/code/...`, not `/mnt/c/...`). Scanning across the
  `/mnt/c` bridge is slow enough to change behaviour — gitleaks over a large history goes from
  seconds to minutes.
- **Enable Docker Desktop's WSL integration** for your distro, otherwise `docker info` fails inside
  WSL and the kit skips those dimensions with a notice (the missing-toolchain contract, working as
  intended — but you will be scanning less than you think).

> **Not yet verified by us on a real WSL2 machine.** The path above follows from how the scripts
> work, and `doctor` will tell you what it detected; if you run it under WSL2 or Git Bash, the
> result is worth reporting back.

## Requirements (a missing one only skips that dimension)
- **docker** — gitleaks / trivy / syft / osv-scanner (pinned images, no install)
- **uvx or pipx** — semgrep / checkov / pip-audit / guarddog / zizmor (no install, on-demand)
- **pnpm / yarn / npm** — JS dep audit (whichever the project uses)
- **python3** *(optional)*, **3.9 or newer** (macOS's own `/usr/bin/python3` is 3.9) —
  `evidence.json`, `kit.sarif` and the HTML report; stdlib only, no packages to install. Without it
  the scan runs exactly as before, minus those artifacts. CI tests 3.9 and 3.13.

**Paths.** File and folder names with spaces or non-ASCII characters (`güvenlik modülü/`) are
scanned like any other. The lists you write in `.security-audit.conf` (`SAST_PATHS`, `JS_DIRS`,
`DEP_ALLOWLISTS`) are space-separated, so a path in them cannot contain a space; name a parent
folder instead.

You don't need to permanently install any tool. Every version is pinned — Python tools
(semgrep/checkov/pip-audit) by version, docker tools (gitleaks/trivy/syft) by **immutable
digest** — so there is no drift vs. CI. Run `scan.sh doctor` to print the resolved pins.

**trivy's vulnerability DB is downloaded once and reused.** It lives in a docker volume
(`security-audit-trivy`, ~1.7 GB on disk once unpacked from a ~130 MiB download), not in your repo.
It is refreshed when it is older than `TRIVY_DB_MAX_AGE_H` (default 24: upstream rebuilds it once a
day). Measured on this repo, `scan.sh all` went from 46–58 s to 6.5–9.6 s; the container scan went
from 39–49 s to ~2 s, with the same findings. The first run downloads the DB and says so;
`scan.sh warm` does that and pulls the pinned images ahead of time, so the first pre-push does not.
`SCAN_OFFLINE=1` never downloads: it uses the cached DB at any age, and with none the container
dimension is `skipped` (not a pass). For CI, set `TRIVY_CACHE` to an absolute path and cache that
directory. `scan.sh doctor` shows the cached DB and its age. `summary.json` records the DB's
`updated_at` in `provenance` (so in `evidence.json`) and its age in `trivy_db`. To reclaim the
space: `docker volume rm security-audit-trivy`.
