---
name: sec-triage
description: Runs the local security scan (tools/security-audit-kit/scan.sh), triages each finding real-vs-false-positive with a confidence-scored verification pass (drops low-confidence noise and anything matching .security-exclusions.md), writes a daily findings file, applies an allowlist for FPs and a fix for real findings, and promotes real findings to the project's tracking list. Use it when a pre-push is blocked, after installing a package, or to process findings after a periodic scan.
---

# sec-triage — local security scan finding triage (portable)

Turns the output of a CI-independent local security scan into something **actionable and
high-signal**: raw scan -> exclusions + reachability filter -> confidence-scored verification
-> triaged record -> fix/allowlist. Works in any project.

## When
- When the `git push` pre-push hook is blocked (the full scan produced findings).
- After installing a new package (`scan.sh fast` / `deps`).
- After a periodic (e.g. weekly) full scan.
- When the user says "triage the security findings / update the audit log".

## Steps

1. **Scan / get the output.** Priority order: (a) if output was passed as an argument, use it;
   (b) else check `docs/security/scan-findings/raw-<TODAY>.log` (every scan writes its raw output
   there) — also read `summary.json` if present (machine-readable per-dimension status); (c) if
   neither exists, run `bash tools/security-audit-kit/scan.sh <scope>` — pre-PR=`all`,
   post-package=`fast`, single dimension=`secret|sast|deps|iac|container`. Tool->dimension:
   semgrep=SAST, gitleaks=secret, trivy=dep/OS/misconfig, checkov=IaC, pip-audit/js-audit=dep CVE.

2. **Load the exclusions.** READ `.security-exclusions.md` at the repo root first (if present;
   template ships as `exclusions.example.md`). It lists do-not-report classes and precedent
   assumptions. Any finding that falls **only** into an exclusion is marked FP with the rule
   cited — do not spend judgment on it. (A real, high-confidence finding still surfaces even if
   it brushes a rule; when in doubt, keep it.)

3. **Triage each surviving finding — two passes. This is the core; no blind copying.**

   **Pass 1 — exploitability filter** (cheap, drops noise). For each finding, LOOK at the
   file:line and ask:
   - **Reachable from untrusted input?** Trace the path from an attacker-controlled source to
     this sink. If it is NOT reachable (dead code, never called with untrusted data, behind an
     unreachable flag) -> FP (reason: not reachable).
   - **Matches an exclusion / precedent?** (step 2) -> FP.
   - **Obvious FP** — dev placeholder, test/doc path, fake sandbox value, tool mismatch
     (evidence: a `# noqa`/dev-only comment, a `tests/`/`docs/` path, a known example PAN) -> FP.

   **Pass 2 — independent verification with a confidence score** (for what survives Pass 1).
   Judge each finding *independently* as if trying to disprove it. Assign a confidence in
   `[0,1]` that it is a **real, exploitable** issue:
   - `≥0.9` certain exploit path · `0.8–0.9` known-bad pattern, clear sink ·
     `0.7–0.8` conditional/needs a precondition · `<0.7` speculative.
   - **Gate: only findings with confidence ≥ 0.7 are reported as REAL/UNCERTAIN.** Below 0.7 go
     to the **Suppressed** list (with the score + one-line reason), NOT the main table.
   - Bar to clear: *"would a security team confidently raise this in a PR review?"* If not, suppress.
   - Still genuinely uncertain at ≥0.7 -> keep as UNCERTAIN (safe side), don't silently drop.

4. **Write the daily file:** `docs/security/scan-findings/findings-<TODAY>.md` (create if absent,
   template below). One row per reported finding: tool | file:line | severity | confidence |
   decision (REAL/UNCERTAIN) | action. Add a **Suppressed** section listing what Pass 1/2 dropped
   and why (auditability — so a dropped finding is a decision on record, not a silent omission).
   A second round the same day -> append `## Round N (HH:MM)`, do NOT overwrite.

5. **Close FPs (allowlist)** — for tool-level FPs you want the scanner to stop re-flagging:
   gitleaks -> a narrow `.gitleaks.toml` entry or `# gitleaks:allow` on the line. semgrep ->
   `# nosemgrep: <rule-id>` + rationale. pip-audit -> `GHSA-xxxx  # rationale` in `.pip-audit-ignore`.
   Rule: ONLY a proven fake/dev value; never a real secret. (Recurring judgment FPs belong in
   `.security-exclusions.md`, not an allowlist.)

6. **Process real findings:**
   - High-confidence + small -> apply the patch (rotate secret + .env; dep bump/override;
     sanitize injection). Show the diff and, if possible, re-run the scan to confirm it is clean.
   - Not directly fixable / cross-cutting -> add an entry to the project's security tracking list
     (a `security-followups.md`-style registry if one exists; else mark it "OPEN" + a follow-up note).
   - **Before deferring/allowlisting a *dependency CVE*, check its exploit signals** — look them up
     on demand for just those few CVEs: **CISA KEV** (is it actively exploited in the wild?) and
     **EPSS** (exploit-probability score). **In KEV or high EPSS -> do NOT defer**; fix or escalate
     now. A not-in-KEV, low-EPSS CVE with no available patch is safer to defer with a follow-up.
     (On-demand lookup only — the kit does not vendor these feeds; they must stay fresh.)

7. **Summary:** counts of REAL / UNCERTAIN / FP / suppressed; which allowlists; which fixes; which
   entries opened. If the pre-push was blocked: after FP allowlist + real fix, `scan.sh all` must
   pass clean again -> then push.

## Boundaries (HARD)
- These tools produce **internal evidence**; they do NOT replace an external ASV scan or a
  pentest. Those remain external-authority, gated activities.
- NEVER use an allowlist or an exclusion to silence a **real secret** or a confirmed exploit.
- The confidence gate trims *noise*, not severity: a HIGH-severity finding you're <0.7 sure is
  *real* is suppressed (with a note), but if you ARE sure, severity never lowers the decision.

## Daily file template
```markdown
# Security Scan Findings — <TODAY>

## Round 1 (<HH:MM>) — scope: <all|fast|...>

| Tool | Location | Sev | Conf | Decision | Action |
|------|----------|-----|------|----------|--------|
| gitleaks | path/x:29 | HIGH | 0.95 | REAL | rotated + .env; .gitleaks.toml allow (dummy var) |
| semgrep  | path/y:88 | ERROR | 0.85 | REAL | fix applied (sanitize) |
| js-audit | pkg X 1.2 | HIGH | 0.80 | REAL | override -> 1.3; confirmed |

### Suppressed (Pass 1/2 — on record, not reported)
| Tool | Location | Why | Conf |
|------|----------|-----|------|
| semgrep | tests/foo:12 | exclusion: test-only file | — |
| semgrep | lib/z:5 | not reachable from untrusted input | 0.4 |

**Summary:** N real / U uncertain / M FP / S suppressed. Opened follow-ups: ... Allowlist: ...
```
