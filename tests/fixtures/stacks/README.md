# Stack detection fixtures (e2e)

Minimal, **benign** project skeletons used by `tests/e2e.sh` to assert that `scan.sh`'s
stack-aware detection (`doctor` → `semgrep cfg` + "detected in this repo") picks the right
language/framework packs and dimensions per stack, in isolation.

Files use a **`.tpl` suffix on purpose** so they do NOT trigger the kit's OWN self-audit
(`scan.sh` detection matches `package.json` / `requirements.txt` / `*.tf`, not `*.tpl`).
`tests/e2e.sh` materializes each fixture into a throwaway git repo (stripping `.tpl`) and runs
`scan.sh doctor` against it. Keep fixtures benign — no real vulnerabilities or secrets.

Matrix: `django` (python+django) · `react` (js+ts+react) · `terraform` (iac, base-only packs) ·
`monorepo` (python+react+terraform together).
