# Contributing to security-audit-kit

Thanks for helping improve the kit. It is a small, dependency-light set of bash scripts
plus two Claude skills, so contributing is straightforward.

## Ground rules (the kit's ethos)
- **No `curl | bash`.** This is a security tool; anything that fetches remote code must be
  downloaded, reviewable, and run as a separate step.
- **Everything is pinned.** Python tools by version, docker images by **immutable digest**.
  A change that bumps a tool must update both the pin and `scan.sh doctor`'s output.
- **Portable bash.** Target `bash` 3.2 (macOS default) — no associative arrays, no `mapfile`.
- **A missing tool skips its dimension; it never hard-fails the kit.**

## Local development
```bash
# Lint (CI runs the same; .shellcheckrc disables intentional word-splitting warnings):
shellcheck scan.sh install.sh bootstrap.sh hooks/pre-commit hooks/pre-push

# Smoke-test without scanning anything:
bash scan.sh doctor

# Run a real dimension against this repo (dogfooding):
bash scan.sh secret
SARIF=1 bash scan.sh secret   # also writes docs/security/scan-findings/sarif/

# End-to-end: vendor the working tree into a throwaway repo, install, and assert each
# gate fires (install/hooks/skills/config, secret + pre-commit gate, SAST, summary.json).
# Tests the scriptable plumbing, not the AI skills' judgment. Needs docker + uvx for full
# coverage (missing tools skip their asserts).
bash tests/e2e.sh
```

## Bumping a pinned tool version
1. Update the default in `scan.sh` and the commented example in `security-audit.conf.example`.
2. For a docker tool, also update the digest. Resolve it with:
   ```bash
   docker buildx imagetools inspect <image>:<tag> --format '{{.Manifest.Digest}}'
   ```
3. Note the change in `CHANGELOG.md`.

## Pull requests
- Keep changes focused. Update `README.md` **and** `README-tr.md` when behavior changes, including
  the lifecycle diagram and the finding loop if the flow changed.
- Add a `CHANGELOG.md` entry under `## [Unreleased]`. If consumers must know or do something, add
  it under `### Upgrade notes`; `bootstrap.sh --check` shows that section to them.
- A new setting in `scan.sh` goes into `security-audit.conf.example` too (e2e checks it).
- Skills live in `skills/<name>/SKILL.md`: the plugin loads them from there and `install.sh` copies
  them from there. A new skill also goes into `install.sh`'s `SKILLS` list (e2e checks both).
- Make sure `shellcheck`, `python3 -m pytest`, `bash tests/e2e.sh` and `bash scan.sh verify` pass
  (run `bash scan.sh checksums` after changing kit files).

## Releasing (maintainers)
Follow [RELEASING.md](RELEASING.md). Do not tag by hand. In short:
1. A release-prep PR turns `[Unreleased]` into `[X.Y.Z]` with an `### Upgrade notes` section
   (`- None.` if nothing changes for consumers), sets the same version in
   `.claude-plugin/plugin.json`, and sweeps the README pins, docs/compare and the landing page.
2. `scripts/release.sh rc X.Y.Z` cuts a release candidate. It checks the CHANGELOG, the
   CHECKSUMS, e2e and CI.
3. `scripts/dogfood.sh vX.Y.Z-rc.N <consumer repos...>` tries it on clones of real repos and on a
   fresh install. Then do the manual checklist.
4. `scripts/release.sh final X.Y.Z` promotes the tested RC commit. The stable gate stops if CI
   cannot be verified.
