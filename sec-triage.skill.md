---
name: sec-triage
description: Runs the local security scan (tools/security-audit-kit/scan.sh), triages each finding as real-vs-false-positive, writes a daily findings file, applies an allowlist for FPs and a fix for real findings, and promotes real findings to the project's tracking list. Use it when a pre-push is blocked, after installing a package, or to process findings after a periodic scan.
---

# sec-triage — local security scan finding triage (portable)

Turns the output of a CI-independent local security scan into something **actionable**:
raw scan -> triaged record -> fix/allowlist. Works in any project.

## When
- When the `git push` pre-push hook is blocked (the full scan produced findings).
- After installing a new package (`scan.sh fast` / `deps`).
- After a periodic (e.g. weekly) full scan.
- When the user says "triage the security findings / update the audit log".

## Steps

1. **Scan / get the output.** Priority order: (a) if output was passed as an
   argument, use it; (b) otherwise check whether `docs/security/scan-findings/raw-<TODAY>.log`
   EXISTS — every scan writes its raw output there; if it exists, READ it (no need to
   re-scan); (c) if neither exists, run: `bash tools/security-audit-kit/scan.sh <scope>` —
   pre-PR=`all`, post-package=`fast`, single dimension=`secret|sast|deps|iac|container`.
   Tool->dimension: semgrep=SAST, gitleaks=secret, trivy=dep/OS/misconfig, checkov=IaC,
   pip-audit/js-audit=dep CVE.

2. **Triage each finding — real or false-positive?** This is the core of the skill; no
   blind copying. For each finding, LOOK at the file:line:
   - **FP:** dev placeholder, test fixture, doc example, fake sandbox value, tool
     mismatch (evidence: a `# noqa`/dev-only comment, a tests/docs path, a known example PAN).
   - **Real:** a secret leaked into a prod path, a real injection/authz flaw, a CVE with
     a fixed version available, a live IaC misconfig.
   - **Uncertain:** trace the call site; if still uncertain, treat it as real (safe side).

3. **Write the daily file:** `docs/security/scan-findings/findings-<TODAY>.md`
   (YYYY-MM-DD; create it if absent, template below). One line per finding: tool | file:line |
   severity | decision (REAL/FP/UNCERTAIN) | action. A second round the same day -> append
   `## Round N (HH:MM)` to the existing file, do NOT overwrite.

4. **Close FPs (allowlist):** minimum scope, apply after confirmation.
   gitleaks -> a narrow `.gitleaks.toml` regexes/paths entry or `# gitleaks:allow` on the line.
   semgrep -> `# nosemgrep: <rule-id>` on the line + a rationale. pip-audit -> `GHSA-xxxx  # rationale`
   in `.pip-audit-ignore`. Rule: ONLY a proven fake/dev value; never a real secret.

5. **Process real findings:**
   - High-confidence + small -> apply the patch (rotate secret + .env; dep bump/override;
     sanitize injection). Show the diff and, if possible, re-run the scan to confirm it is clean.
   - Not directly fixable / cross-cutting -> add an entry to the project's security tracking
     list (a `security-followups.md`-style registry if one exists; otherwise mark it "OPEN"
     in the daily file and leave a follow-up note).

6. **Summary:** how many REAL/FP/UNCERTAIN; which allowlists; which fixes; which entries
   opened. If the pre-push was blocked: after FP allowlist + real fix, `scan.sh all` must
   pass clean again -> then push.

## Boundaries (HARD)
- These tools produce **internal evidence**; they do NOT replace an external ASV scan or
  a pentest. Those remain external-authority, gated activities.
- NEVER use the allowlist to silence a real secret.

## Daily file template
```markdown
# Security Scan Findings — <TODAY>

## Round 1 (<HH:MM>) — scope: <all|fast|...>

| Tool | Location | Sev | Decision | Action |
|------|----------|-----|----------|--------|
| gitleaks | path/x:29 | HIGH | FP | .gitleaks.toml regex (dev placeholder) |
| semgrep  | path/y:88 | ERROR | REAL | fix applied (sanitize) |
| js-audit | pkg X 1.2 | HIGH | REAL | override -> 1.3; confirmed |

**Summary:** N real / M FP / K uncertain. Opened follow-ups: ... Allowlist: ...
```
