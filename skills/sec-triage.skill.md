---
name: sec-triage
description: Runs the local security scan (tools/security-audit-kit/scan.sh), triages each finding real-vs-false-positive with a confidence-scored verification pass (drops low-confidence noise and anything matching .security-exclusions.md), writes a daily findings file, applies an allowlist for FPs and a fix for real findings, and promotes real findings to the project's tracking list. Use it when a pre-push is blocked, after installing a package, or to process findings after a periodic scan.
---

# sec-triage — local security scan finding triage (portable)

Turns the output of a CI-independent local security scan into something **actionable and
high-signal**: raw scan -> exclusions + reachability filter -> confidence-scored verification
-> triaged record -> fix/allowlist. Works in any project.

## Hard boundary — never edit the kit itself
`tools/security-audit-kit/` (and any copy of it under `.claude/skills/`) is **read-only**. Do not
edit `scan.sh`, the hooks, the skills or `CHECKSUMS` — not to fix a bug, not to silence a noisy
dimension, not "just this once". The kit is the instrument that judges this repo; an instrument
edited by the thing being judged proves nothing, and `scan.sh verify` (run by the pre-push hook)
will fail for everyone on the team afterwards. Local edits are also **lost without warning** on the
next `bootstrap.sh`, so the fix evaporates while people believe it is in place.

Found a real bug in the kit? Say so in the findings file under **Kit issues**: what it does, what it
should do, the file and line. The fix belongs upstream, in a release, behind a bumped pin — never in
the vendored copy. The only files you write are the project's own: the findings file, allowlists
(`.gitleaks.toml`, `nosemgrep` comments, `.pip-audit-ignore`, `osv-scanner.toml`,
`.trivyignore.yaml`), `.security-exclusions.md`, `.security-audit.conf`, and the code being fixed.

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
   **Context-slice hygiene:** read `summary.json` and the raw log *through tools* (grep/read the
   finding's file:line, the per-dimension count) — pull the slice you need per finding; never paste
   a whole `raw-<TODAY>.log` or `summary.json` dump into reasoning. The **funnel** starts here: only
   `scan.sh` survivors enter triage — you are not re-scanning, you are judging what the tools flagged.

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

   **Pass 2 — independent verification against the evidence bar** (for what survives Pass 1).
   Judge each finding *independently* as if trying to disprove it. The scanner already matched a
   pattern — that is not evidence of exploitability. **Default to FP; a finding earns REAL only by
   clearing the evidence bar.**

   **Evidence bar — to call it REAL you must name all three (else FP):**
   1. **Sink** — the dangerous operation at its `file:line` (SQL exec, shell call, deserialize,
      file open, redirect, privileged mutation, …).
   2. **Untrusted source** — the specific attacker-controlled input (request param/body/header,
      uploaded file, webhook field, fork-authored PR). A server-side constant, an allow-listed
      enum, framework-supplied metadata, or another trusted process's output is **not** untrusted.
   3. **Unbroken path** — source reaches sink with **no effective mitigation on the way**.

   **Mitigations that force FP** (credit one only if it actually covers *this* path — don't invent
   one, don't ignore one that's present): parameterization/bound params; `subprocess` with an
   **argv list and no `shell=True`**; auto-escaping / safe API / a sanitizer on the path
   (`safe_load`, `literal_eval`, DOMPurify, entity resolution off, CSPRNG); allow-list / constant
   controlling the dangerous part; validation that blocks the attack (path-root membership,
   scheme/host check, field allow-list, int-coercion); an authz decorator or ownership/tenant
   filter guarding the op (even if a pattern scanner didn't follow it); not reachable (dead/test/
   doc/vendored/self-written data, or a trigger context without privilege — CI `pull_request` with
   a read-only token, not `pull_request_target`).

   **Then score confidence in `[0,1]`:**
   - `≥0.9` certain exploit path · `0.8–0.9` known-bad pattern, clear sink, no mitigation ·
     `0.7–0.8` conditional/needs a precondition · `<0.7` speculative or a mitigation may cover it.
   - **Gate: only findings with confidence ≥ 0.7 are reported as REAL/UNCERTAIN.** Below 0.7 go
     to the **Suppressed** list (with the score + one-line reason), NOT the main table.
   - Bar to clear: *"would a security team confidently raise this in a PR review, given the
     mitigations actually present in the code?"* A mitigation that covers the path → low confidence
     → FP, regardless of how dangerous the bare pattern looks.
   - Still genuinely uncertain at ≥0.7 -> keep as UNCERTAIN (safe side), don't silently drop.

   **Pass 3 — consistency validation (one sweep before you write anything).** Re-read your own
   REAL/UNCERTAIN list as an adversary would:
   - **Evidence completeness:** every REAL must carry a concrete sink `file:line` *and* a named
     untrusted source. A REAL with no source named, or whose "source" is actually a constant/enum/
     trusted-metadata, is not REAL — downgrade to FP (or UNCERTAIN if genuinely open).
   - **No double standard:** if two findings share the same sink and mitigation, they must get the
     same verdict; a mitigation you credited to suppress finding A must not be ignored for finding B.
   - **Severity ≠ decision:** confirm you did not upgrade a finding to REAL because it was HIGH, nor
     suppress a well-evidenced one because it was LOW. Severity ranks, it does not decide.
   Findings that fail this sweep get corrected here — the written file reflects the post-validation
   verdicts only.

4. **Write the daily file:** `docs/security/scan-findings/findings-<TODAY>.md` (create if absent,
   template below). One row per reported finding: tool | file:line | severity | confidence |
   decision (REAL/UNCERTAIN) | action. Add a **Suppressed** section listing what Pass 1/2 dropped
   and why (auditability — so a dropped finding is a decision on record, not a silent omission).
   A second round the same day -> append `## Round N (HH:MM)`, do NOT overwrite.

5. **Close FPs (allowlist) — write the decision to EVERY path that can report the finding.**
   Your decision is about a *finding*; a suppression is applied per *tool*. Several dimensions
   overlap by design, so one entry does not settle it: an accepted, documented risk silenced in one
   path comes back as an unresolved HIGH in another — and with `SARIF=1` it reaches GitHub Code
   Scanning carrying no trace of your reasoning (`kit.sarif` cannot dismiss another tool's run).

   | Finding type | Dimension(s) that can report it | Where the suppression goes |
   |---|---|---|
   | secret | `secret`, `staged` | `# gitleaks:allow` on the line, or a narrow `.gitleaks.toml` rule |
   | SAST | `sast`, `changed` | `# nosemgrep: <rule-id>` + rationale, on the line |
   | **dependency CVE** | **`py-deps` + `osv` + `container`** | **`.pip-audit-ignore` AND `osv-scanner.toml` AND `.trivyignore.yaml`** |
   | IaC | `iac` | `#checkov:skip=<CHECK_ID>:<reason>` on the resource |
   | CI workflow | `zizmor` | `# zizmor: ignore[<rule>]` on the line |
   | recurring *judgment* FP (not a tool rule) | — | `.security-exclusions.md` |

   **Dependency CVEs are the trap.** pip-audit, osv-scanner and trivy read the same lockfiles and
   report the same advisory under **different ids** — `PYSEC-…`, `CVE-…`, `GHSA-…` are aliases of
   one vulnerability. Use the id each tool prints. `osv-scanner.toml` is alias-aware (one entry
   covers the aliases and it prints why it filtered); the others are not. Write the entry for every
   dimension the project actually runs — and check whether it runs them: `osv` and `guarddog` are
   standalone, `container` is in `all`.

   **Verification is the only proof.** After writing the entries, re-run *those dimensions*
   (`scan.sh py-deps`, `scan.sh osv`, `scan.sh container`) and confirm each is clean. A suppression
   you did not re-run is a hypothesis.

   **Give every deferral an exit.** Record the fixing version and an expiry in the entry
   (`ignoreUntil` in `osv-scanner.toml`, `expiredAt` in `.trivyignore.yaml`, a
   `# expires YYYY-MM-DD — fixed in <ver>` comment in the others). Hand-synced allowlists decay:
   when the fix lands the entry must be deleted from *all* of them, and a forgotten one silently
   suppresses a future, real CVE in that package.

   **Then prove it with `scan.sh allowlist`** (offline, no scan). It reports expired deferrals by
   name and date, counts entries that carry no expiry at all, and flags an id suppressed in one
   dependency path but absent from another — and it exits non-zero on either. Run it after writing
   the entries: it is the cheapest check that the record you just wrote agrees with itself. Note its
   honest limit: it compares **exact ids**, so alias pairs (`PYSEC-…` / `CVE-…` / `GHSA-…` of one
   advisory) are not matched — silence means "no gap found", never "you are covered".

   Rule: ONLY a proven fake/dev value or a judged-and-documented accepted risk; never a real secret
   or a confirmed exploit. (Recurring judgment FPs belong in `.security-exclusions.md`, not an
   allowlist.) Every entry carries its rationale inline — a suppression without a reason is
   indistinguishable from an accident.

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

   **Fixing a dependency CVE — answer three questions in order.** "Bump it" is not an instruction;
   the cost of the bump is the decision.

   1. **Is the vulnerable package a DIRECT dependency or a transitive one?** Check the manifest, not
      the lockfile: if it is not listed there, something else pulls it in. This changes everything
      below — you cannot upgrade what you do not declare.
   2. **Does the fixed version fit the parent's declared range?** For a transitive dep, read the
      parent's constraint (`npm ls <pkg>` / `pnpm why <pkg>` / `uv pip tree` / `pip show <parent>`).
      If the fix is inside the range, bumping the **parent** resolves it cleanly. If it is outside —
      the fix is a major and the parent has not adopted it — that is a **different decision** with
      its own risk, not a bump: record it as such rather than forcing it.
   3. **Only if the parent will not carry the fix**, pin it yourself — and know what you are doing:
      an override runs the parent against a version its maintainers never tested with it.

   Command shape per ecosystem (use the one this repo actually uses; `scan.sh doctor` names the
   detected package manager):

   | Ecosystem | Direct dependency | Forcing a transitive version |
   |---|---|---|
   | pnpm | `pnpm up <pkg>@<ver>` | `pnpm.overrides` in `package.json` |
   | npm | `npm install <pkg>@<ver>` | `overrides` in `package.json` |
   | yarn | `yarn up <pkg>@<ver>` | `resolutions` in `package.json` |
   | uv | `uv lock --upgrade-package <pkg>` | a `>=` floor in `pyproject.toml` |
   | pip / requirements | `pip install -U <pkg>` + repin | a constraints file (`-c`) |
   | poetry | `poetry update <pkg>` | an explicit dependency entry |

   Write the **exact command for this repo** into the findings row, not a generic one — the next
   person should be able to paste it. Then **re-run that dimension** (`scan.sh py-deps` / `osv` /
   `container`) and confirm it is clean: an unverified fix is the same class of claim as an
   unverified suppression.

   > Not yet automated: the kit does **not** compute the parent-range answer for you (question 2).
   > That needs per-ecosystem resolver calls and is tracked separately; today it is a lookup you run.

7. **Summary:** counts of REAL / UNCERTAIN / FP / suppressed; which allowlists (name every file you
   wrote to, and for a dependency CVE state explicitly which of the three paths are now covered and
   which dimensions you re-ran to prove it); which fixes; which
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

| Tool | Sink (file:line) | Untrusted source | Sev | Conf | Decision | Action |
|------|------------------|------------------|-----|------|----------|--------|
| gitleaks | path/x:29 | live caller reads token | HIGH | 0.95 | REAL | rotated + .env; .gitleaks.toml allow (dummy var) |
| semgrep  | path/y:88 | request.GET["id"] → f-string | ERROR | 0.85 | REAL | fix applied (sanitize) |
| js-audit | pkg X 1.2 | vuln fn called on req body | HIGH | 0.80 | REAL | override -> 1.3; confirmed |

### Suppressed (Pass 1/2 — on record, not reported)
| Tool | Location | Why | Conf |
|------|----------|-----|------|
| semgrep | tests/foo:12 | exclusion: test-only file | — |
| semgrep | lib/z:5 | not reachable from untrusted input | 0.4 |

### Kit issues (report only — never edit the vendored kit)
| Kit file:line | Observed | Expected | Effect on this scan |
|---|---|---|---|
| scan.sh:140 | prefers $VIRTUAL_ENV over the repo's .venv | repo .venv wins | py-deps audited an unrelated project |

**Summary:** N real / U uncertain / M FP / S suppressed. Opened follow-ups: ... Allowlist: ...
```
Omit the **Kit issues** section when there are none. When there are, the fix path is upstream +
a pin bump — the vendored copy stays untouched.

**These tables are a machine contract too.** `scan.sh evidence` parses this file to fill in
`evidence.json` and to emit `sarif/kit.sarif` for GitHub Code Scanning. It reads columns **by header
name** (`Sink (file:line)` / `Location`, `Tool`, `Untrusted source`, `Sev`, `Conf`, `Decision`,
`Action`, `Why`, `Class`), so you may reorder or add columns — but keep the header names, keep one
`file:line` per row, and keep `### Suppressed` as its own heading (everything under it is recorded
as suppressed, with its reason). Rows without a parseable location are dropped. Spec:
`docs/schema/evidence.md`.
