# security-audit-kit vs Phoenix Security's security-skills-claude-code

> **Reviewed:** 2026-11-03 · kit **v1.20.0** · upstream commit
> [`40ace4a`](https://github.com/Security-Phoenix-demo/security-skills-claude-code/tree/40ace4aa71017b8214fd9d1a071de235a1abc022)
> (2026-09-11).
>
> **Method:** files were read through the GitHub API as data. Nothing was installed or executed,
> so hook timing and behavior below come from reading the code, not from running it. Planning
> consequences are in the [backlog](../reviews/application-backlog-2026-09-08.md) (F33, F34, R02
> addendum).

## Summary

The repo is a Claude Code plugin marketplace with six plugins, all at version 1.0.0. Three are
security related: `phoenix-security-review`, `phoenix-sast-rules` and `phoenix-readiness-reviews`.
The other three are documentation and research, PRD generation, and threat-intel search. It also
works as a showcase for Phoenix's commercial products.

Almost all of the security work is LLM prompting. No SAST or secret scanner is executed. The
"0-day scanner", "assessment" and threat-model flows call MCP tools and REST endpoints of a Phoenix
backend that is not shipped. Without it, they fall back to a checklist review by the model.

**Phoenix leads the kit on two things:**
- **A plugin channel** with one-command install.
- **A full set of Claude Code hooks:** SessionStart, PreToolUse, PostToolUse and SessionEnd.

## Feature mapping

| Area | Phoenix | security-audit-kit |
|---|---|---|
| Distribution | `/plugin marketplace add …`. Codex and Windsurf get snippets only. | Pinned `bootstrap.sh` vendoring; plugin channel planned (R02). |
| Deterministic scanning | SessionStart runs `osv-scanner` or the ecosystem auditor **if already on PATH**, with a 30 s timeout. Nothing is installed or pinned. | 10+ pinned tools across secrets, SAST, deps, IaC, container, SBOM, CI and malicious packages. |
| SAST | None executed. semgrep/opengrep are listed as "if installed" escalation (`agents/security-reviewer.md:34-42`). | semgrep plus custom rules; `/sec-sast-deep`. |
| Pre-install package guard | `pre-bash-package-guard.sh`; details in the next section. | `pkgcheck`: guarddog analysis, about 24 malice-specific blocking rules, cached verdicts, indeterminate results never treated as clean. |
| Post-edit check | `post-edit-quickscan.sh`: about 5-8 `rg` regexes per file type, advisory only. | None today. Planned as F33. |
| Session context | SessionStart fingerprints manifests and injects a dependency audit, with a 15-minute cache. | None today. Planned as F33. |
| Findings model | One Markdown block per finding. No SARIF, baseline, suppression or dedup. FP control is a prompt sentence. | `summary.json`/`evidence.json`/SARIF/HTML; `/sec-triage` evidence bar; expiring allowlists. |
| Custom rules | Opengrep rule generator (prompt only). Requires a test file with `ruleid:` and `ok:` markers, but nothing runs it. | User `semgrep-rules/` directory. |
| Kit integrity | No checksums or signatures. CI is structural only (`claude plugin validate --strict`, shellcheck, `py_compile`). | Pinned tag + SHA + content digest; `scan.sh verify` at pre-push; CHECKSUMS; SBOM. |

## The package guard, side by side

| | Phoenix `pre-bash-package-guard.sh` | kit `pkgcheck` |
|---|---|---|
| What it checks | An exact-name blocklist (12 names plus an optional user file); typosquat distance ≤2 against 16 npm and 16 PyPI names; for npm only, registry age under 7 days and install-script declaration | guarddog source and metadata analysis of the actual package |
| Decision | deny for a blocklist hit; **ask** for typosquat, new package or install script | block on about 24 malice-specific rules, otherwise allow with a note |
| Chained commands | Stops at the first matching package manager (`break`, l.95), so `pip install x && npm i y` checks one ecosystem | Splits on `&&`, `\|\|`, `;`, `\|` and newlines (`lib/pkgcheck.py:78`) |
| Failure mode | A timeout (15 s budget, up to 2×5 s curls plus one python process per comparison) is non-blocking, so it fails open. Below bash 4 it allows with a message. | A failed download is `INDETERMINATE`, allowed loudly and never cached as clean |
| Cost | Cheap, metadata only | About 15-20 s on first check, then cached |

The kit's check goes deeper. Phoenix has two cheap signals the kit lacks: **package age** and
**install-script declaration**. It also has an **ask** outcome that sits between allow and block.
F34 covers all three.

## Verified defects

We re-checked this one by running the regex locally:
- **`scan_repo.sh:94`:** the "Injection-prone patterns" regex contains a PCRE lookahead,
  `yaml\.load\((?!.*Loader)`.
  - Both `rg` (without `--pcre2`) and ERE `grep` reject the whole pattern.
  - Because stderr is discarded (l.40-42), this check **always reports zero hits** and never errors.

From the review, not re-checked:
- **Installer overwrites hooks:** `install/install.sh:165` merges settings with
  `jq -s '.[0] * .[1]'`. That **replaces** any `hooks.PreToolUse` and similar arrays the user
  already has.
- **The two opengrep rule-generator skills are identical:** the "research" variant matches the
  plain one apart from its frontmatter.
- **The reviewer agent is not read-only:** it describes itself as read-only, but it is granted
  `Edit`.

## Ideas worth taking

- **SessionStart context (F33).** Inject the latest `summary.json` statuses and open follow-ups, with
  a TTL cache. Finding text comes from the scanned code, so it must be framed as data (F35).
- **PostToolUse single-file check (F33).** Advisory only, and it should run the kit's pinned semgrep
  on the one edited file rather than regexes.
- **Ship hooks in the plugin's `hooks.json` (F33/R02).** Never merge them into the user's
  `settings.json`; Phoenix's installer shows what goes wrong otherwise.
- **Cheap registry signals and an "ask" outcome in `pkgcheck` (F34).**
- **Validate the plugin in CI (R02).** Run `claude plugin validate --strict` and check that every
  referenced path exists.
