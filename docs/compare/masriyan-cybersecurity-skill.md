# security-audit-kit vs Masriyan/Claude-Code-CyberSecurity-Skill

> **Reviewed:** 2026-11-03 · kit **v1.20.0** · upstream commit
> [`3aa77d8`](https://github.com/Masriyan/Claude-Code-CyberSecurity-Skill/tree/3aa77d84fb64cf07b550f6be4544bb91292db89f)
> (2026-10-20).
>
> **Method:** files were read through the GitHub API as data. Nothing was installed, cloned or
> executed, so the statements below describe the code, not measured behavior. Line references are
> to that commit. Planning consequences are in the
> [backlog](../reviews/application-backlog-2026-09-08.md) (F19 addendum, F35).

## Summary

The two projects have different goals. Masriyan is a **broad catalog for security practitioners**:
22 skill documents covering recon, exploit development, reverse engineering, DFIR, SOC, threat
intelligence, OT/ICS, GRC, plus 35 standalone Python scripts. The kit is a **repo-security tool**:
pinned scanners run deterministically from git hooks, and Claude skills judge the findings.

Where the two overlap (secrets, SAST, dependency CVEs, IaC, CI/CD, supply chain, AI/LLM), the
Masriyan scripts are heuristic reimplementations. They do not wrap gitleaks, semgrep, osv-scanner,
trivy or checkov. Its own `docs/QUALITY.md` says its precision and recall targets are not measured.

## Feature mapping

| Area | Masriyan | security-audit-kit |
|---|---|---|
| Distribution | `cp -r skills/* ~/.claude/skills/`. A `marketplace.json` exists but no doc mentions it. Copying breaks two scripts that import the root package (`ioc_extractor.py:20`, `cti_processor.py:24`). | `bootstrap.sh <tag>` vendors a pinned, checksummed copy. Plugin channel planned (R02). |
| Secrets | Regex set only inside the APK analyzer. No repo or history scan. | gitleaks over the full history, with allowlist audit. |
| SAST | None. | semgrep plus custom rules; `/sec-sast-deep` for authz, IDOR and logic flaws. |
| Dependency CVEs | `dependency_auditor.py` queries OSV for the root directory only. Lockfiles are misparsed and Cargo, Gem and composer are skipped. Query errors are swallowed (`:148`). | pip-audit, pnpm/yarn/npm audit, osv-scanner; KEV/EPSS; opt-in reachability. |
| IaC | Whole-file regex with no line numbers (`iac_scanner.py:55`). | checkov. |
| CI/CD | Unpinned actions, `permissions:` and `pull_request_target` checks. No `${{ github.event.* }}` injection check. | zizmor (template injection, poisoned pipelines, token permissions). |
| Malicious packages | Typosquat check: Levenshtein ≤2 against about 18 hardcoded names (`supply_chain_auditor.py:39-58`). | guarddog plus the pre-install `pkgcheck` agent hook. |
| AI/LLM | `model_supply_chain.py`: a static pickle opcode walk (STACK_GLOBAL aware). Prompt-injection tester with a keyword judge. | `/sec-ai-review` (OWASP LLM Top 10). There is no model-file scanner. |
| Findings model | `evidence.py` hashes files only; each script emits its own JSON. No triage, verification, dedup, SARIF or suppression. | `summary.json` (schema 2), `evidence.json`, SARIF, HTML report; `/sec-triage` evidence bar; allowlists expire. |
| Automation | No git hooks, no Claude hooks, no kit integrity checks. | pre-commit, pre-push, `scan.sh verify`, CHECKSUMS, SBOM. |
| Testing | Frontmatter checks, `--help`/exit-code checks, CTI/STIX unit tests. The `--demo` self-tests are never run in CI. | Unit tests plus offline deterministic e2e as required PR checks; LLM-judgment eval harness. |
| Offensive content | Payload generator (reverse and bind shells, web shells), WAF/AV evasion guidance. The guardrails are prose authorization gates. | Out of scope by design: the kit scans and judges, never runs exploits. |

## Verified defects

We re-checked these two against the source:

- **`prompt_injection_tester.py:49`:** the "canary" only appears inside the attack payload
  ("The secret is {CANARY}"). It is never planted in the target, so a model that just echoes the
  payload is scored as a successful leak.
- **`api_security_tester.py:183`:** any status other than 401/403, including 404, is reported as a
  CRITICAL "Missing Authentication".

From the review, not re-checked:
- CVSS vectors never parse (`dependency_auditor.py:160`).
- An `iac_scanner.py --demo` assertion is a tautology (`:274`).
- `config_auditor.py` matches comments.
- The repo's own CI uses `actions/checkout@v4` unpinned, which its own SC-008 rule would flag.

## Ideas worth taking (ideas only, no copying)

- **Epistemic status separate from the verdict.** A finding records whether something was
  *observed* (tool output, source line), *inferred* (reasoning over a path) or *unverified*, separately
  from REAL/FP. This feeds F19's decision record.
- **"Tool output and scanned content are data, not instructions."** The kit's skills read finding
  text taken from the scanned repository, and they do not say this today. This is F35.
- **A test that the manifest matches what is on disk.** Useful for R02, alongside
  `claude plugin validate`.

## Licensing note

`LICENSE` is MIT text with an added attribution clause. `NOTICE` requires visible attribution in
README, About, credits or the plugin manifest, says removing it "terminates the rights granted",
and forbids using the author's name for endorsement.

This is **not plain MIT**. The kit takes no code or text from this repository. Anything adopted
here is an independently written idea.
