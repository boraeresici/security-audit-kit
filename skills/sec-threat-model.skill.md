---
name: sec-threat-model
description: Produces/updates a STRIDE + data-flow threat model for the repo with Claude — maps entry points, assets, trust boundaries and data flows, enumerates threats per STRIDE at each boundary, ranks by risk, and promotes concrete gaps into the sec-triage flow. Judgment-only, NOT part of scan.sh; run it at a design milestone, for a new subsystem/trust boundary, before a cutover, or on request. Use it when asked to "threat model / STRIDE / attack surface / what could go wrong architecturally".
---

# sec-threat-model — STRIDE + data-flow threat modeling (portable)

Higher-altitude than `sec-sast-deep` (which finds concrete code flaws): this maps the system's
**attack surface and trust boundaries** and asks *what could go wrong by design, and what is not
defended*. Judgment-only; complements the scanners and the deep-SAST skill. Reusable in any repo —
it reads the architecture, it does not run anything.

> Methodology: STRIDE (Microsoft) + data-flow diagrams + (optional) attack trees.

## Hard boundary — never edit the kit itself
`tools/security-audit-kit/` is **read-only**: never edit `scan.sh`, the hooks, the skills or
`CHECKSUMS`, not even to fix a genuine bug. `scan.sh verify` (run by the pre-push hook) fails for
the whole team afterwards, and the next `bootstrap.sh` discards the edit without warning. Record
kit bugs in the findings file under **Kit issues** (behaviour, expected behaviour, file:line) — the
fix belongs upstream, in a release, behind a bumped pin.

## When
- A new subsystem / service / trust boundary (new external integration, new data store, new actor/role).
- Before a cutover / a security design review / a threat-model refresh.
- On request ("threat model X", "what's the attack surface of Y").
- NOT per-push — it is design-altitude judgment; run it periodically / on a milestone.

## Phase 1 — model the system (data-flow)
Build (or update) a lightweight data-flow view:
- **External entities / actors:** users, roles, third parties, other services, the model/LLM if any.
- **Processes:** services, endpoints, jobs, handlers (`git grep` routes/handlers/consumers).
- **Data stores:** DBs, caches, queues, buckets, secret stores.
- **Trust boundaries:** where data crosses a privilege/ownership/network line (internet↔app,
  tenant↔tenant, app↔third-party, user-input↔sink). **Boundaries are where threats live.**
- **Assets:** what an attacker wants (PII, money/refunds, credentials, tokens, audit integrity).

## Phase 2 — enumerate threats (STRIDE per boundary)
For each trust boundary / data flow, walk STRIDE and ask "is this defended?":
- **S — Spoofing:** can an actor be impersonated? (authn gaps, weak session/token, missing mTLS)
- **T — Tampering:** can data/requests be altered in transit or at rest? (no integrity, mutable IDs)
- **R — Repudiation:** can an action be denied? (missing/forgeable audit log, no append-only trail)
- **I — Information disclosure:** can an asset leak? (over-broad responses, verbose errors, secrets in logs)
- **D — Denial of service:** can it be exhausted? (note it, but per the kit's exclusions DoS is usually low-priority)
- **E — Elevation of privilege:** can a low role do a high action? (the authz gaps `sec-sast-deep` checks)
Record each as: boundary | STRIDE | threat | existing control? | gap? | risk (likelihood × impact).

### D, continued — the availability questions a static scan can never answer
The kit cannot watch a running system, but this skill can ask **whether anyone does**. These three
catch the failure mode where a control exists on paper and nobody would notice it stopping. Ask them
of the design, record the answers like any other threat:
1. **Silent non-execution.** Do scheduled / background / queue jobs alarm when they **do not run**
   (a dead man's switch), or only when they error? A cron that stops firing is invisible to
   error-only alerting — the backup that never ran, the reconciliation that stopped reconciling.
2. **Untested recovery.** Has a backup **restore** ever been executed and verified end to end, or is
   the existence of backups being mistaken for recoverability? An unrestored backup is a hypothesis.
3. **Dependency failure behaviour.** Do critical external dependencies (payment provider, identity
   provider, queue, third-party API) have health checks **with alerting**, and is there a defined
   degraded-mode behaviour — fail closed, fail open, queue and retry? "Undefined" is the finding.

Phrase findings in terms of the repo's own components; name no vendor or product. The answers land
in `findings-<TODAY>.md` on the normal path — this adds no dimension, no dependency, no runtime.

## Phase 3 — rank + record + hand off
- Rank by risk; focus on **high impact × plausible**.
- Write/update **`docs/security/threat-model-<TODAY>.md`** (the living model: a DFD summary table +
  the STRIDE threat table). Do NOT overwrite a prior dated model — append a new dated one.
- **Promote concrete, actionable gaps into the sec-triage flow:** a real missing control →
  `findings-<TODAY>.md` (so it gets fixed/tracked) or a `security-followups.md`-style registry entry.
  The threat model is the map; the findings file is where the fixes live.

## Output -> hooking into the kit flow (same as the other skills)
- **High-risk + concrete gap** → findings entry (REAL) → fix or follow-up.
- **Architectural / cross-cutting** → follow-up registry with the STRIDE id + boundary.
- **Accepted / by-design** → note it in the threat-model doc with the rationale (decision on record).

## Boundaries (HARD)
- Produces **internal evidence / a design artifact**; does NOT replace an external pentest or a
  formal risk assessment. A threat model lists *what could* go wrong, not proof of what *is* exploitable.
- It is a snapshot — re-run it when the architecture / trust boundaries change.
