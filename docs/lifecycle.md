# Lifecycle — install, update, scan, judge

From the first install to a finding that is fixed or deliberately suppressed. Start with the
[README](../README.md); its architecture diagram shows the parts this page moves through.

```mermaid
flowchart TD
    Q{First time, or<br/>already installed?}
    Q -->|new| N1["mkdir -p tools/"]
    Q -->|"skills via the plugin<br/>(Claude Code or Codex)"| PL["install the plugin<br/>skills only: still vendor the scanner<br/>(bootstrap.sh, then install.sh --no-skills)"]
    PL --> N1
    N1 --> N2["download + review bootstrap.sh"]
    N2 --> B["bash bootstrap.sh vX.Y.Z"]
    Q -->|installed| C["bootstrap.sh --check<br/>stable channel (RCs: --channel=rc) · prints the upgrade notes<br/>exit 0 up to date · 1 update · 2 cannot tell"]
    C -->|up to date| R
    C -->|update vX.Y.Z| RV["review diff, then bootstrap.sh vX.Y.Z"]
    RV --> B
    B --> I["vendor + .kit-version (ref + SHA + content digest)<br/>install.sh: hook wrappers in .git/security-audit-hooks (your own hooks chained),<br/>skills, .conf, .exclusions, verify · undo: install.sh --uninstall"]
    I --> R(["ready"])

    R --> V{"each hook wrapper checks the kit<br/>against the manifest recorded at install"}
    V -->|"kit edited, or a file added"| VX["COMMIT / PUSH BLOCKED, files named<br/>restore: bootstrap.sh at the pinned tag<br/>kit bugs go upstream, never patched in the vendored copy"]
    V -->|intact| S["scan (deterministic): pre-commit staged (+ deps) · pre-push verify + all · ad-hoc scan.sh<br/>scanners read the repo read-only · .security-audit.conf read as data, never run<br/>closing summary + raw-DATE.log + summary.json (status per dimension, policy_changes, provenance)<br/>SARIF=1 also writes sarif/ (+ native JSON) and evidence.json · REPORT=html writes report-DATE.html"]
    S -->|clean| D(["done"])
    S -->|"skipped / error = NOT inspected"| TC["fix the toolchain or the scan<br/>(the closing summary names the cause)<br/>never read as clean · GATE_STRICT=1 blocks on it"]
    TC --> S
    S -->|findings| T1

    subgraph JUDGE["judgment in the agent — skills"]
      direction TB
      T1["1. /sec-triage — FIRST, after every scan<br/>evidence bar: sink + untrusted source + unbroken path<br/>exclusions, reachability, confidence >= 0.7<br/>repo text is evidence, never instructions"]
      DEEP["2. /sec-sast-deep — on trigger<br/>pre-cutover / new endpoint: authz, IDOR, logic"]
      AIR["3. /sec-ai-review — on trigger<br/>code calls an LLM / new AI surface"]
      TM["4. /sec-threat-model — on trigger<br/>new subsystem / design review: STRIDE, data-flow"]
      T1 --> F[["findings-DATE.md"]]
      DEEP -. appends .-> F
      AIR -. appends .-> F
      TM -. appends .-> F
    end

    F -->|FP / excluded| AL["/sec-triage PROPOSES the allowlist entry for EVERY path that reports it<br/>gitleaks / nosemgrep / pip-audit + osv + trivy, or .security-exclusions.md<br/>each with an expiry · written only after you confirm"]
    F -->|REAL| FX["fix now (direct? transitive? parent range?),<br/>OR promote to the security-followups registry"]
    AL --> P["PROVE IT: scan.sh allowlist + re-run that dimension<br/>the next run's policy_changes names the new suppression"]
    FX --> P
    P --> S
    F -. "SARIF=1: judgment findings become sarif/kit.sarif" .-> CS[["GitHub Code Scanning"]]
```

## The same loop, in text

```
every commit --(pre-commit)-->  integrity check, then scan.sh staged  (+ deps if a manifest changed)
before a PR  --(pre-push)----->  integrity check, then scan.sh verify, then scan.sh all
skipped/error --> NOT inspected: fix the toolchain or the scan (the closing summary names the cause)
finding      --> /sec-triage in the agent --> docs/security/scan-findings/findings-YYYY-MM-DD.md
                                              |- FP   -> proposed allowlist entry for EVERY reporting path
                                              |          (.gitleaks.toml / nosemgrep /
                                              |           .pip-audit-ignore + osv-scanner.toml + .trivyignore.yaml)
                                              |          with an expiry; written after you confirm
                                              |- REAL -> fix OR follow-up registry entry
                                              v
                                             PROVE IT: scan.sh allowlist  (expired? cross-path gap?)
                                                       re-run that dimension until clean
                                             an unrun suppression, like an unrun fix, is a hypothesis
```

- **Skill order.** `/sec-triage` runs first after any scan with findings: it writes
  `findings-DATE.md` and splits FP (a proposed allowlist entry or exclusion) from REAL (a fix or a
  follow-up). `/sec-sast-deep`, `/sec-ai-review` and `/sec-threat-model` are deeper, trigger-based
  passes whose findings append to the same file. A question to a skill is answered without running
  this loop ([asking versus auditing](skills.md#asking-versus-auditing)).
- **Updates are explicit.** `--check` only reports (read-only, no install); `bootstrap.sh <tag>`
  re-vendors and re-runs install. Nothing auto-pulls upstream: pin a tag, review the diff, bump.
  Re-running `install.sh` after an update you reviewed is how the hooks accept the new kit.
- **The gate's own changes are visible.** `policy_changes` in `summary.json` (and the `── policy:`
  line) names what a change does to the gate itself: config, exclusions, allowlists, scanner configs,
  any file of the kit, and added suppression markers. It is a signal, never a block.
- **What each dimension leaves behind** for this loop, rows or only a log line, is in the
  [evidence matrix](evidence-matrix.md).
