# Your own rules and suppressions

Repo-local semgrep and gitleaks rules, and how to suppress a finding on every path that reports it. Start with the [README](../README.md).

## Your own rules — `semgrep-rules/` + a `.gitleaks.toml` entry

The kit runs registry packs, which know nothing about *your* invariants: every ORM lookup must be
tenant-scoped, this field type is banned, that helper must never be called from a request handler.
Semgrep is very good at exactly this, so the kit gives the mechanism a supported entry point. **The
kit owns the mechanism, you own the rules** — nothing project-specific ships here.

Drop rules in **`semgrep-rules/`** at the repo root (`.semgrep/`, `.semgrep.yml`, `.semgrep.yaml`
also work). They are **appended** to whatever the base is — registry packs stay:

```
semgrep cfg --config p/owasp-top-ten --config p/secrets --config p/javascript --config semgrep-rules (stack-auto + local)
```

That composition is the point. Before, the only way to reach a hand-written rule was to set
`SEMGREP_CONFIGS`, which **replaces** the list — you gained one rule and silently lost OWASP, secrets
and every stack pack, and that frozen list then rotted as the stack grew. Now `SEMGREP_CONFIGS` sets
only the *base*; local rules are added on top of it either way, and `doctor` tells you which packs a
frozen override is now missing.

A rule and its test, side by side:

```yaml
# semgrep-rules/tenant-scope.yaml
rules:
  - id: unscoped-tenant-lookup
    pattern: Model.objects.get(id=$X)
    message: ORM lookup without a tenant filter — cross-tenant read
    severity: ERROR          # <- ERROR or it will NOT gate (see below)
    languages: [python]
```
```python
# semgrep-rules/tenant-scope.py
# ruleid: unscoped-tenant-lookup
Model.objects.get(id=order_id)
# ok: unscoped-tenant-lookup
Model.objects.filter(id=order_id, tenant=current_tenant)
```

Then `scan.sh rules-test` runs semgrep's own test runner over them. A custom rule is code: after a
refactor the pattern quietly stops matching and the gate goes silent, so an untested rule decays
without ever failing.

**Two traps `doctor` now surfaces for you:**

```
local semgrep rules (yours, not shipped by the kit):
  ok  semgrep-rules — 2 rule(s), 1 gating
  !!  1 rule(s) NOT at ERROR -> WILL NOT GATE: bare-except-pass
  ok  rule tests present -> verify with: scan.sh rules-test
```

- `scan.sh sast` runs `--severity ERROR`, so a rule written at `WARNING`/`INFO` **loads and is then
  ignored** — the rule exists, it just never fails anything. There is deliberately no "advisory"
  tier: a gate that does not gate is the hole this feature closes.
- Rules with no tests are called out, because that is how a rule dies quietly.

Turn it all off with `SEMGREP_LOCAL_RULES=off`; point it elsewhere with `SEMGREP_LOCAL_RULES=<paths>`.
Discovery is anchored at those literal paths — it never searches the tree, so a vendored copy of the
kit can never contribute rules to your config, and a rule's own test fixture never counts as part of
your stack.

**Secrets, same idea.** `.gitleaks.toml` is already wired in; gitleaks' entropy rules miss a flat
`PASSWORD=hunter2`, so add the rule you actually want:

```toml
# .gitleaks.toml
[extend]
useDefault = true

[[rules]]
id = "plaintext-password-assignment"
description = "Plaintext password assigned in config or code"
regex = '''(?i)\b(password|passwd|pwd)\s*[:=]\s*['"]?[^\s'"$#{}]{6,}'''
[rules.allowlist]
regexes = ['''(?i)(example|dummy|changeme|placeholder|\$\{|process\.env|os\.getenv)''']
```

### Suppressing a finding: cover every path that reports it

An allowlist is per **tool**; a triage decision is about a **finding** — and several dimensions
overlap by design. A dependency CVE is read out of the same lockfile by **pip-audit, osv-scanner and
trivy**, which report it under different ids (`PYSEC-…`, `CVE-…`, `GHSA-…` are aliases of one
advisory). Silence it in one place and it returns as an unresolved HIGH from another — and with
`SARIF=1` it reaches Code Scanning carrying no trace of the decision, because `kit.sarif` cannot
dismiss another tool's run.

| Finding | Reported by | Suppression goes in |
|---|---|---|
| secret | `secret`, `staged` | `# gitleaks:allow` on the line, or a narrow `.gitleaks.toml` rule |
| SAST | `sast`, `changed` | `# nosemgrep: <rule-id>` + rationale |
| **dependency CVE** | **`py-deps` + `osv` + `container`** | **`.pip-audit-ignore` + `osv-scanner.toml` + `.trivyignore.yaml`** |
| IaC | `iac` | `#checkov:skip=<CHECK_ID>:<reason>` |
| CI workflow | `zizmor` | `# zizmor: ignore[<rule>]` |
| recurring *judgment* FP | the AI layer | `.security-exclusions.md` |

`scan.sh allowlist` audits them — offline, no scan. It names **expired** deferrals with their date,
counts entries carrying **no expiry at all** (those never become loud again), and flags an advisory
suppressed in one dependency path but **absent from another**; it exits non-zero on either. Its
honest limit: the cross-path check compares **exact ids**, so alias pairs (`PYSEC-…` / `CVE-…` /
`GHSA-…` of one advisory) are not matched — silence means "no gap found", never "you are covered".
`doctor` carries the one-line verdict.

```
== allowlist audit (2026-08-23) ==
  !!  .pip-audit-ignore      EXPIRED GHSA-aaaa-bbbb-cccc (2026-07-01) — the deferral outlived its date
  ok  .pip-audit-ignore      3 entr(y|ies) · 1 expired · 1 with no expiry
  !!  GHSA-aaaa-bbbb-cccc is suppressed in .pip-audit-ignore but not in osv-scanner.toml
```

`scan.sh doctor` lists which of these files exist in your repo, so a half-applied suppression is
visible. Two habits keep it honest: **re-run the affected dimensions** after writing the entries (a
suppression you did not re-run is a hypothesis), and **give every deferral an expiry** —
`ignoreUntil` in `osv-scanner.toml`, an `# expires YYYY-MM-DD — fixed in <ver>` comment elsewhere.
Hand-synced allowlists decay: when the fix lands the entry must go from *all* of them, and a
forgotten one silently suppresses a future, real CVE in that package.
