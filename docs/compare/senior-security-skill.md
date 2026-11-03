# security-audit-kit vs alirezarezvani/claude-skills `senior-security`

> **Reviewed:** 2026-11-03 · kit **v1.20.0** · upstream commit
> [`7f92eda`](https://github.com/alirezarezvani/claude-skills/tree/7f92edacf8510771db03672232ca14471ff69c47/engineering-team/skills/senior-security)
> (2026-11-03). The skill is also listed on
> [qai.io](https://qai.io/skills/alirezarezvani/claude-skills/senior-security). That listing reports
> "Pattern check: nothing flagged" at an earlier commit and shows no install count or rating.
>
> **Method:** files were read through the GitHub API as data. Nothing was installed or executed.
> Planning consequences are in the [backlog](../reviews/application-backlog-2026-09-08.md) (F36).

## Summary

`senior-security` is a 64-line playbook inside a repository of about 380 skills. It is distributed
as part of the `engineering-skills` plugin, through a marketplace of 110 plugins and mirrored
directories for Codex, Gemini and other agents.

Most of the skill is a routing table that sends the agent to sibling skills: pen-testing, cloud
security, AI security, SecOps, incident response and others. It owns two workflows itself, STRIDE
with DREAD threat modeling and a "quick secret scan". Each is backed by a script, and neither
script has tests.

## Feature mapping

| Area | senior-security | security-audit-kit |
|---|---|---|
| Distribution | Plugin marketplace; symlinked copies for other agents | Pinned vendoring; plugin channel planned (R02) |
| Secrets | `secret_scanner.py`: details below | gitleaks over the full history, with allowlist audit |
| Threat modeling | `threat_modeler.py`: details below | `/sec-threat-model`: STRIDE per trust boundary over a data-flow map built from the repo, with gaps promoted into triage |
| Findings model | Fixed severity per pattern; exit 1 on high or critical. No triage, SARIF or allowlist. | Evidence bar, expiring allowlists, SARIF/HTML |
| Hooks and CI | None for this skill. The repo's CI checks skill metadata, not user code. | Git hooks plus the `pkgcheck` agent hook |
| Tests | None for either script | Unit tests, e2e, eval harness |

**`secret_scanner.py`** has 20 regexes, no entropy check, no git history and no allowlist.

**`threat_modeler.py`** is a lookup in a fixed table of 18 threats (`THREAT_DATABASE`, L62-343),
chosen by matching words in `--component`.
- The `--assets` option is parsed but never used.
- DREAD scores are computed from constants (L403-407).

## Verified defects

We re-checked this one against the source:
- **`.env` files are never scanned.** The directory walk admits `.env` by name (L321), but
  `scan_file` filters patterns by `file_path.suffix` (L253, L262), and `Path(".env").suffix` is the
  empty string.

From the review, not re-checked:
- **Blanket line skip:** any line containing "regex" or "pattern" is skipped (L270), which hides
  real secrets on those lines.
- **Case-insensitive matching:** all patterns are compiled with `re.IGNORECASE`, so the
  prefix-based patterns (Twilio `AC`/`SK`) also match lowercase strings.
- **Publishable keys rated CRITICAL:** Stripe `pk_` keys, which are public by design, are rated
  CRITICAL.
- **The maintainers don't use it:** their own pre-push command uses gitleaks rather than this
  scanner.

## Ideas worth taking

- **A STRIDE-per-element applicability matrix (F36).** For each DFD element type (external entity,
  process, data store, data flow), list which STRIDE categories apply, and use the matrix to check
  that the model is complete. `/sec-threat-model` already walks STRIDE per trust boundary. What it
  lacks is a check that every inventoried element was covered.

Two other ideas are **already in the kit**:
- **Re-running the tool as the "done" signal:** `/sec-triage` requires re-running the dimension
  after a fix or allowlist entry.
- **Owner-and-expiry on accepted risks:** the follow-up registry and allowlist decay cover this.
