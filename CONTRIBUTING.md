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
```

## Bumping a pinned tool version
1. Update the default in `scan.sh` and the commented example in `security-audit.conf.example`.
2. For a docker tool, also update the digest. Resolve it with:
   ```bash
   docker buildx imagetools inspect <image>:<tag> --format '{{.Manifest.Digest}}'
   ```
3. Note the change in `CHANGELOG.md`.

## Pull requests
- Keep changes focused; update `README.md` **and** `README-tr.md` when behavior changes.
- Add a `CHANGELOG.md` entry under `## [Unreleased]`.
- Make sure `shellcheck` and `bash scan.sh doctor` pass.

## Releasing (maintainers)
1. Move the `Unreleased` notes into a versioned `CHANGELOG.md` section.
2. Tag: `git tag -a vX.Y.Z -m "vX.Y.Z" && git push origin vX.Y.Z`.
3. Create a GitHub Release from the tag (this is what `bootstrap.sh --check` and
   Watch → Releases rely on).
