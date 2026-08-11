# Releasing security-audit-kit

This kit is **vendored into other repos** and consumers **pin to a release tag** (recorded in their
`.kit-version` as `ref` + resolved `SHA` + a content digest, enforced by `bootstrap.sh --expect=<sha>`
and re-checked by `scan.sh verify`). That gives us a simple,
low-friction release model:

> **Consumers only ever get a *blessed* release tag — never `main` HEAD. So `main` can move freely;
> instability reaches consumers only when we cut a new *stable* tag.** Every stable release is gated
> behind a **release candidate (RC)** that we test in real projects first.

`main` does **not** have to be perfect at every commit — the **last non-prerelease tag is "stable."**

---

## Version scheme (SemVer)
- **MAJOR.MINOR.PATCH** — feature ⇒ MINOR (`1.10.0` → `1.11.0`), fix ⇒ PATCH (`1.11.0` → `1.11.1`).
- **Release candidates:** `vX.Y.Z-rc.N` (`v1.11.0-rc.1`, `-rc.2`, …). Marked **pre-release** on GitHub
  so they never become "Latest".
- The **final** `vX.Y.Z` tag is cut on the **exact commit** of the last green RC — we ship what we tested.

---

## The flow

### 1. Land the work on `main`
Feature branches → PR → CI green (shellcheck / self-audit / checksums) → merge. (Same as today.)

### 2. Prep the release commit
On `main`, up to date:
```sh
git checkout main && git pull --ff-only
# 1) finalize the CHANGELOG section header for this version (keep the date for step 6/promote)
# 2) regenerate + verify the integrity manifest (kit files changed)
bash scan.sh checksums
bash scan.sh verify
# 3) full local e2e must pass
bash tests/e2e.sh
git add -A && git commit -m "chore: prep vX.Y.Z (checksums)"   # if checksums/CHANGELOG changed
git push origin main
```
Wait for CI to go green on `main`.

### 3. Cut the RC and mark it pre-release
```sh
VER=v1.11.0
git tag -a ${VER}-rc.1 -m "${VER}-rc.1 — <one-line summary>"
git push origin ${VER}-rc.1
gh release create ${VER}-rc.1 --prerelease \
  --title "${VER}-rc.1" \
  --notes "Release candidate for ${VER}. Testing in real projects before promotion."
```
`--prerelease` keeps GitHub's "Latest" pointing at the previous **stable** release.

### 4. Dogfood the RC in real projects (the actual gate)
In **≥1 real consumer project** (ideally 2–3 across stacks), pin to the RC and exercise it:
```sh
# in the consumer repo — point the vendored kit at the RC tag + verify the exact SHA
bash tools/security-audit-kit/bootstrap.sh ${VER}-rc.1 --expect=<rc_sha>
bash tools/security-audit-kit/scan.sh all
bash tools/security-audit-kit/scan.sh doctor
# run at least one skill pass (e.g. /sec-audit) if the change touches the AI layer
```
Use the **dogfood checklist** below.

### 5. Bugs found? → fix on `main` → new RC
Fix on `main` via PR (CI green), then cut the next candidate and re-test:
```sh
git tag -a ${VER}-rc.2 -m "${VER}-rc.2 — <what changed>"; git push origin ${VER}-rc.2
gh release create ${VER}-rc.2 --prerelease --title "${VER}-rc.2" --notes "..."
```
Repeat step 4. **Never promote a commit you didn't test.**

### 6. Promote: cut the final stable tag
On the **exact commit** the last green RC points to:
```sh
git checkout main && git pull --ff-only
# ensure HEAD == the tested RC commit:
test "$(git rev-parse HEAD)" = "$(git rev-parse ${VER}-rc.2^{commit})" || echo "WARN: HEAD != tested RC"
# finalize CHANGELOG date for [X.Y.Z] if not already, commit if needed
git tag -a ${VER} -m "${VER} — <summary>"
git push origin ${VER}
gh release create ${VER} --latest \
  --title "${VER}" \
  --notes-file <(sed -n "/## \[${VER#v}\]/,/## \[/p" CHANGELOG.md | sed '$d')
```
`--latest` blesses it as the stable release consumers pick up.

### 7. Consumers update on their own schedule
Downstream repos bump their `.kit-version` (`ref` + new `SHA`) / re-run `bootstrap.sh ${VER} --expect=<sha>`
when they choose. Nothing is forced on them.

---

## Dogfood checklist (before promoting)
- [ ] `scan.sh all` runs clean (or only expected findings) on ≥1 real project.
- [ ] `scan.sh doctor` shows the expected toolchain + resolved config (e.g. `semgrep cfg … (stack-auto)`).
- [ ] New/changed dimension actually fires on a known-bad fixture and is quiet on clean input.
- [ ] `scan.sh verify` passes on the vendored copy (integrity intact after vendoring).
- [ ] If the AI layer changed: one skill pass (`/sec-audit` or the specific skill) produces a sane findings file.
- [ ] No regression in an unrelated stack (test both a Python and a JS project when touching SAST).

---

## Branch protection (recommended, one-time)
On GitHub → Settings → Rules/Branch protection for `main`:
- Require a pull request before merging.
- Require status checks to pass (shellcheck, self-audit, checksums).
- Disallow direct pushes / force-pushes to `main`.
Tags are not protected by default; only maintainers should push `v*` tags.

## Hotfix
For an urgent fix to the latest stable: branch from the stable tag, fix, PR to `main`, then run this
same flow as `vX.Y.(Z+1)` (a quick `-rc.1` dogfood is still worth it).

## Notes
- Keep `CHANGELOG.md` the source of truth for release notes; the promote step extracts that section.
- Always regenerate `CHECKSUMS` (`scan.sh checksums`) whenever kit files change, before tagging —
  a stale manifest makes `scan.sh verify` fail for consumers.
