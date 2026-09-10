# Branch protection ruleset for `main`

`main.json` is an importable GitHub **repository ruleset** that enforces the release model in
[`RELEASING.md`](../../RELEASING.md): nothing reaches `main` without a PR + green CI, and the branch
can't be force-pushed or deleted.

## What it enforces (on the default branch, `main`)
- **Pull request required** — no direct pushes. `required_approving_review_count: 0` so a solo
  maintainer can still self-merge once checks pass (raise it to `1` if/when there are co-maintainers).
- **Required status checks** (must pass, and the branch must be up to date — `strict` policy):
  `shellcheck`, `pytest`, `e2e`, `checksums`, `self-audit` (our CI jobs in `.github/workflows/`).
- **No force-push** (`non_fast_forward`) and **no branch deletion** (`deletion`).
- **Admin bypass** (`RepositoryRole` id 5 = Admin, `bypass_mode: always`) so the maintainer isn't
  locked out for an emergency. Remove the `bypass_actors` entry if you want it enforced for everyone.

> Tags are **not** covered by a branch ruleset — release tags (`v*`) are pushed by the maintainer
> (see `scripts/release.sh`). Add a separate **tag ruleset** later if you want to restrict who can push `v*`.

## Apply it

**Option A — UI import (simplest):**
Repo → **Settings → Rules → Rulesets → New ruleset → Import a ruleset** → select `main.json` → **Create**.

**Option B — `gh` CLI:**
```sh
gh api -X POST repos/{owner}/{repo}/rulesets \
  --input .github/rulesets/main.json
```
To update an existing ruleset, find its id (`gh api repos/{owner}/{repo}/rulesets`) and `PUT`:
```sh
gh api -X PUT repos/{owner}/{repo}/rulesets/<id> --input .github/rulesets/main.json
```

## Manual fallback (classic branch protection)
Settings → Branches → Add rule for `main`:
- ☑ Require a pull request before merging (approvals: 0)
- ☑ Require status checks to pass — add `shellcheck`, `pytest`, `e2e`, `checksums`, `self-audit`; ☑ Require branches up to date
- ☑ Do not allow force pushes · ☑ Do not allow deletions

## Note
Check names must match the CI **job names** exactly. If you rename a job in
`.github/workflows/ci.yml` or `self-audit.yml`, update the `context` values here (and in
`scripts/release.sh`'s `REQUIRED_CHECKS`).
