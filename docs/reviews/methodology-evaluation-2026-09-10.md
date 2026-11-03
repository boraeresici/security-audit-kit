# Security Audit Kit — Methodology and Usability Evaluation

Date: 2026-09-10 · Base: `main / 48fad91` (v1.17.0 + unreleased run lock)

This evaluation is not a scan of the project's code; it analyzes the kit **as a product**, within a
security-audit methodology framework, for its usability by security and development teams.
Complementary code-level findings are taken from the SAST notes (Appendix A).

---

## 1. Product Identity and Positioning

Security audit kit occupies a different niche from traditional security tools (Snyk, Checkmarx,
Veracode):

| Traditional SAST/DAST | Security Audit Kit |
|---|---|
| Requires SaaS or a server | Local, CI-independent |
| Central dashboard | In-repo, distributed |
| Monthly license cost | MIT, free |
| Managed by an expert team | Developer self-service |
| Runs as a separate tool | Integrated with git hooks + AI |

**Assessment:** The positioning is clear — "developer-first, offline, vendored security gate." It
does not compete with SaaS products; it runs **before** and **alongside** them, not instead of them.
This is a strong value proposition for small-to-mid teams and budget-constrained organizations.
However, for enterprise security teams the lack of central visibility may be an adoption blocker.

---

## 2. Methodology Coverage — Security Team Perspective

### 2.1 Mapping to Standard Security Audit Frameworks

| Audit Phase | Kit's Counterpart | Status |
|---|---|---|
| **Asset discovery** (code, dependencies, infrastructure) | `doctor`, `sbom`, stack auto-detect | ✅ Sufficient |
| **Vulnerability scanning** (SAST, secret, deps, IaC, container) | `sast`, `secret`, `deps`, `iac`, `container`, `osv` | ✅ Comprehensive |
| **Supply chain** | `guarddog`, `pkgcheck`, pin/digest mechanism | ✅ Strong |
| **AI/LLM security** | `sec-ai-review` (OWASP LLM Top 10) | ✅ Pioneering |
| **Threat modeling** | `sec-threat-model` (STRIDE) | ✅ Present |
| **Deep analysis** (authz, business logic) | `sec-sast-deep` | ✅ Original |
| **DAST / Runtime testing** | None | ⛔ Deliberately out of scope |
| **API security testing** | None | ⛔ Missing |
| **Compliance mapping** (PCI-DSS, SOC2, HIPAA) | None | ⛔ Missing |
| **Risk prioritization** (business context) | Severity normalization + AI triage | ⚠️ Partial |
| **SLA / remediation tracking** | Allowlist decay detection | ⚠️ Partial |
| **Central reporting** (multi-repo) | None — single-repo HTML | ⛔ Missing |
| **Penetration testing** | None | ⛔ Deliberately out of scope |

**Conclusion:** The kit is strong in the **Identification + Detection** phases; it is deliberately
lacking in the **Governance, Compliance, Response** phases. The security team should position it not
as a single tool but as the **first line of defense**.

### 2.2 Fit with the Security Team's Workflow

**Strengths:**

- **Reduces triage load:** The AI layer (`sec-triage`) classifies raw findings; only `REAL` and
  `UNCERTAIN` findings reach the security team. Delivers direct value for security engineers in
  large teams who deal with hundreds of false positives a day.

- **Evidence quality:** The `evidence.json` → SARIF → HTML chain shows where, when, with which tool
  and with which verdict a finding was detected. The security team can use this evidence in front of
  an auditor.

- **Allowlist management:** `scan.sh allowlist` detects the decay of accepted risks over time —
  valuable from a governance standpoint.

- **In-repo control:** The security team versions rules (`semgrep-rules/`), the allowlist and
  exclusions by keeping them in the repo. Provides "transparent security" instead of "shadow
  security."

**Weaknesses:**

- **No central visibility:** An organization using the kit in 10 repos cannot see at a glance how
  many open findings each repo has. The security team must open SARIF files one by one or check Code
  Scanning panels repo by repo.

- **No compliance report:** Findings cannot be mapped to controls such as PCI-DSS Requirement 6.5 or
  SOC2 CC8.1. The security team must prepare a manual mapping table during the audit period.

- **Vulnerability aging:** Allowlist decay exists, but there is no "this finding has been open for 90
  days, SLA breach" warning. One of the metrics the security team needs most.

- **Risk context:** There is a CVSS score, but the question "which asset in this organization does
  this CVE affect?" cannot be answered. The security team needs business context when making risk
  acceptance decisions.

### 2.3 Recommended Improvements for the Security Team

| # | Improvement | Existing card | Priority |
|---|---|---|---|
| 1 | Multi-repo finding aggregation (SARIF merge + summary) | Not in backlog — **F26 proposed** | P1 |
| 2 | Compliance mapping table (CWE → PCI/SOC2/HIPAA) | Not in backlog — **R12 proposed** | P2 |
| 3 | Finding aging and SLA warning | Could be added to F19 | P2 |
| 4 | Executive summary output (single page, non-technical summary) | Could be added to F04 | P2 |

---

## 3. Methodology Coverage — Development Team Perspective

### 3.1 Developer Workflow Integration

```
Developer Workflow:
  write code → git add → [pre-commit: staged + deps] → git commit
     → [pre-push: verify + all] → git push → CI → PR → merge
```

| Stage | What the Kit Provides | Developer Experience |
|---|---|---|
| **Writing code** | None (no IDE integration) | ⛔ No instant feedback on findings |
| **Staging** | `pre-commit` → staged secret + deps | ✅ Fast (sub-second secret scan) |
| **Commit** | Gate: stops if a secret is present | ✅ Clear and fast |
| **Push** | `pre-push` → verify + all | ⚠️ Docker pull time on first run |
| **PR** | CI: shellcheck + checksums + self-audit | ✅ Automatic |
| **Triage** | Automatic classification via AI skills | ✅ Frees the developer from triage |
| **Remediation** | AI suggestions (findings.md) | ⚠️ Suggestions exist, no automatic fix |

### 3.2 Developer Experience Assessment

**Strengths:**

- **Zero-configuration start:** Install in 2 commands with `bootstrap.sh` + `install.sh`. The
  developer does not need to know Docker, Python, or npm — tools are fetched automatically via
  `uvx`/Docker.

- **CI independence:** The developer can run a full scan locally; no waiting on the CI bill.
  Especially valuable for small startups and open-source projects.

- **Fail-fast culture:** `pre-commit` returns results within seconds, `pre-push` within minutes.
  A "learn at push time" experience instead of "learn in CI 30 minutes later."

- **AI triage:** AI answers the question "is this finding real?" The developer does not have to be a
  security expert.

- **`doctor` command:** Shows the tool chain, pins and detected stacks. The answer to "why isn't it
  working?" in a single command.

**Weaknesses:**

- **No IDE integration:** The developer cannot see a vulnerability while writing code; they learn of
  it only at commit/push time. Modern SAST tools (Semgrep, SonarQube) offer IDE plugins.

- **Bash-only interface:** No CLI UX beyond `scan.sh <command>`. Modern CLI ergonomics such as
  `--help`, `--json`, `--format` are missing. No tab completion, no interactive mode.

- **First-run friction:** On the first `scan.sh all` run, Docker images are downloaded — this can
  take minutes. A developer who thinks "installation is done" and then waits on the first scan will
  be disappointed.

- **Error messages:** Some error cases end up in `raw-*.log`; the output the developer sees directly
  can be insufficient (F02, F04).

- **Lacking remediation guidance:** AI triage says "this is real, fix it" but leaves only a short
  note for the "how to fix it" question. There is no mechanism like Snyk's "fix PR" or Dependabot's
  automatic PR.

### 3.3 Recommended Improvements for Developers

| # | Improvement | Existing card | Priority |
|---|---|---|---|
| 1 | `scan.sh help` — interactive help | F14 | P1 |
| 2 | Tool-download warning before first run | Not in backlog | P1 |
| 3 | Enrich remediation suggestions | R01 | P2 |
| 4 | VS Code / JetBrains extension | Not in backlog | P2 |
| 5 | `scan.sh --format json` — machine-readable output | Related to F02 | P1 |

---

## 4. Methodological Strengths and Weaknesses

### 4.1 Strong Methodological Decisions

**a) Deterministic Gate + Judgment Separation**

The kit's most original decision. Traditional tools work on "finding exists → stop" or "finding
exists → report" logic. The kit separates the **deterministic scan** (unchanging rules, fixed output)
layer from the **AI judgment** (triage that requires context) layer.

- Lowers the false-positive rate (AI can say "this is in test code")
- Reduces the security team's triage load
- Does not wear the developer out with needless stops

**b) Indeterminate Verdict Model**

`exit code 3` — "I scanned but there was nothing to look at." Far more honest than a silent `pass`.
The `py-deps` bug in v1.17.0 (empty venv = false clean) proves why this approach is necessary.

**c) Supply Chain Awareness**

Tool pinning (digest), CHECKSUMS, `scan.sh verify`, pre-push integrity, tag-repair guard. It would be
ironic and dangerous for a security tool not to protect its own integrity; the kit takes this
seriously.

**d) Fail-Open Design (Deliberate)**

Missing tool → dimension is skipped, scan does not stop. The kit's philosophy is explicit: "a gate
people route around is a gate that doesn't protect."

### 4.2 Methodological Risks and Gaps

**a) Dependence on AI Judgment**

If `sec-triage`'s default verdict is FP (false positive) — this tendency is noted in
`sec-triage.skill.md:69` — a real finding may be marked FP and end up in the allowlist.

- **Risk:** Developer ran `sec-triage` → AI said "FP" → added to allowlist → security team never saw
  it.
- **Mitigation:** The `UNCERTAIN` category and allowlist decay detection (`scan.sh allowlist`)
  partially protect against this. This risk remains open until the F12 calibration work is done.

**b) Coverage Illusion**

The `scan.sh all` command does **not include** OSV, GuardDog, zizmor and SBOM. The developer may
think "I ran a full scan" but in fact:
- Multi-ecosystem dep CVE (osv) → opt-in
- Malicious deps (guarddog) → opt-in
- GitHub Actions security (zizmor) → opt-in

The "coverage summary" proposal in F14 will solve this.

**c) Single-Repo Limit**

The kit scans a single repo's security. It does not show organization-level security posture. An
enterprise security team cannot answer "we have 50 repos, which is the riskiest?" with the kit.

**d) Absence of DAST**

A deliberate decision. Most of the OWASP Testing Guide requires runtime testing. The kit should be
positioned not as a replacement for penetration testing but as the **filter that precedes it**.

**e) Integrity Gap in Python Tools**

While Docker tools are protected by digest, Python tools (semgrep, checkov, pip-audit, guarddog,
zizmor) are fetched from PyPI by version number — no hash verification. In a PyPI-compromise
scenario, Docker tools are immune, Python tools are not. Cards R06 and R11 address this gap.

**f) Executable Nature of the Config File**

`.security-audit.conf` is loaded with shell `source` — it is not a plain data file but executable
code. Anyone with write access to the repo can add arbitrary commands to the config. The F11 threat
model and F24 config validation cards address this risk.

---

## 5. Target Audience Fit Matrix

| User Profile | Fit | Why |
|---|---|---|
| **Solo developer / indie hacker** | ⭐⭐⭐⭐⭐ | Perfect fit — low cost, zero infrastructure, self-service |
| **Small startup (2-10 dev)** | ⭐⭐⭐⭐ | Very good fit — no CI cost, fast setup |
| **Mid-size team (10-50 dev)** | ⭐⭐⭐ | Fits, but the lack of central reporting and compliance is felt |
| **Enterprise security team** | ⭐⭐ | Valuable as first line of defense; governance layer missing |
| **Open-source project** | ⭐⭐⭐⭐⭐ | Perfect fit — free, local, Code Scanning integration |
| **Regulated industry** (fintech, health) | ⭐⭐ | Fits, but not sufficient without PCI-DSS/HIPAA mapping |
| **Security consultant / pentester** | ⭐⭐⭐ | Fast initial assessment; DAST needed for deep analysis |

---

## 6. Conclusion and Recommendations

### Strengths as a Product

1. **Clear positioning** — runs in front of SaaS competitors, not against them
2. **Deterministic + AI separation** — an original methodological approach in the industry
3. **Supply chain awareness** — a security tool that protects its own integrity
4. **Developer-first design** — git hooks, zero config, fast feedback
5. **Indeterminate model** — an honest "couldn't look" instead of a silent pass

### What Needs Improvement as a Product

1. **Central visibility** (P1) — enterprise sales are hard without multi-repo aggregation
2. **IDE integration** (P2) — a pre-commit feedback loop is a modern expectation
3. **Compliance mapping** (P2) — a must-have for regulated industries
4. **Coverage communication** (P1, F14) — what the "all" command does not cover must be stated clearly
5. **AI calibration** (P1, F12) — the product cannot be considered stable until the FP-default risk is measured

### Cards Proposed Within the Methodology Scope

In addition to the existing F23–F25 + R11, the methodology evaluation proposes two new cards:

| ID | Work | Type | Priority | Why |
|---|---|---|---|---|
| **F26** | Multi-repo finding aggregation | Improvement | P1 | The security team's basic visibility need; the single-repo limit is an enterprise adoption blocker |
| **R12** | Compliance framework mapping (CWE → PCI/SOC2/HIPAA) | Conditional | P2 | Needed for regulated-industry adoption; not opened without concrete consumer demand |

---

## Appendix A — SAST Findings (Code-Level Complement)

These findings are taken from the static code analysis performed on 2026-09-10. Findings that confirm
the risks in the methodology evaluation have been prioritized.

### A1 — Executable nature of the config file (HIGH)

**File:** `scan.sh:52` — `. "$CONF"`

`.security-audit.conf` is sourced directly into the shell. The file can contain arbitrary commands
(`curl | bash`, `eval`, etc.). An attacker with write access to the repo can execute code on every
developer machine and CI runner.

**Related card:** F11 (threat model) + F24 (config validation). This finding confirms the priority of
both cards.

### A2 — Read-write repo mount of Docker containers (MEDIUM)

**File:** `scan.sh:304, 381, 391, 451, 459, 495` — `-v "$ROOT:/repo"`

All six Docker container invocations mount the repo read-write. A third-party container image (if
compromised) could modify repo files. A `:ro` mount, which would suffice for most dimensions, appears
not to be applied.

**Related card:** F11 (threat model).

### A3 — Absence of hash verification in Python tools (MEDIUM)

**File:** `scan.sh:204-211` — `pyrun` function

Python tools are fetched from PyPI by version number; while Docker tools are protected by an
immutable digest, Python tools are not. In a PyPI-compromise scenario, `semgrep==1.166.0` could be
replaced with a malicious package.

**Related card:** R06 (Python hash-pin decision) + R11 (pin update automation).

### A4 — Lock reclaim TOCTOU window (MEDIUM)

**File:** `scan.sh:1098-1108`

In stale lock reclaim there is a TOCTOU window between the PID-death check and `rm -rf`. In a PID
recycling scenario, two processes could take ownership of the same lock.

**Related card:** F05 (lock lifecycle). This finding independently confirms the F05 finding from the
2026-09-08 review.

### A5 — Guarddog argument injection (MEDIUM)

**File:** `scan.sh:567-569` — `$gargs` word-split

The package name and version are embedded in `$gargs` and passed to guarddog via word-splitting. A
package name with spaces or metacharacters could produce extra arguments.

**Related card:** F18 (platform/path matrix). Should be handled within the scope of path/argument
safety with spaces.

### A6 — `bootstrap.sh --expect` prefix match (LOW)

**File:** `bootstrap.sh:97-99` — `case "$SHA" in "$EXPECT_SHA"*)`

The SHA comparison uses a prefix match. Collision is possible with a short prefix. There is no risk
when the full 40-character SHA is used; however, if short prefixes are accepted for convenience,
security is weakened.

---

## Appendix B — Backlog Mapping Table

Mapping of the findings from this evaluation to existing backlog cards:

| Methodology Finding | Backlog Card | Status |
|---|---|---|
| Coverage illusion | **F14** — Coverage summary | In backlog, priority correct |
| AI judgment dependence | **F12** — Calibration | In backlog, priority correct |
| Config executable | **F11 + F24** | F11 exists, F24 added with this evaluation |
| Central visibility missing | **F26 proposed** | Not in backlog — new card proposal |
| Compliance mapping missing | **R12 proposed** | Not in backlog — conditional card proposal |
| IDE integration missing | — | Not in backlog — P2 future plan |
| Python integrity gap | **R06 + R11** | In backlog, confirmed by SAST |
| Docker read-write mount | **F11** | In backlog, confirmed by SAST |
| Lock TOCTOU | **F05** | In backlog, confirmed by SAST |
| Remediation guidance | **R01** | In backlog, awaiting scope decision |
| First-run friction | — | Not in backlog — UX improvement |
| Finding aging / SLA | Could be added to **F19** | Partially in backlog |
| Executive summary | Could be added to **F04** | Partially in backlog |
