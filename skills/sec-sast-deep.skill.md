---
name: sec-sast-deep
description: Deep-scans with Claude for SEMANTIC security flaws that semgrep cannot see (horizontal authz/IDOR, vertical authz/missing-role, business-logic, semantic/stack-specific injection). Follows the call path, not a pattern; three-phase recon -> verify -> record. Output feeds the sec-triage flow (docs/security/scan-findings + follow-up registry). NOT part of scan.sh; run it periodically / pre-cutover / after a new authz surface. Use it when asked to "deep SAST / look for IDOR / authz / logic / injection flaws".
---

# sec-sast-deep — semantic SAST (semgrep's blind spot)

`scan.sh sast` (semgrep) is **pattern-based**: it catches known bad signatures, BUT
*authorization* and *business-rule* flaws depend on the **intent** in the code — a matter
of the **call path**, not a pattern. This skill deep-scans those 4 classes with Claude. It
**complements semgrep, it does not replace it**.

> Independently written; inspired by `github.com/utkusen/sast-skills` (its three-phase
> recon->verify->merge structure). Adapted to the kit's `sec-triage` flow and narrowed to the 4
> most critical classes — no code or text is copied from it.

## When
- **Before a cutover** (phase exit / version bump) — semgrep is clean but authz is not "deep".
- **After a new authz surface** — a new REST/GraphQL endpoint, a new admin/cross-tenant
  viewer, a new resolver, a new four-eyes/approval flow, a new FK-ownership relation.
- When the user says "look for IDOR / authz / logic flaws, deep SAST".
- **NOT on every push** — it costs tokens and needs judgment; run it periodically/on-trigger.

## Phase 1 — baseline: map the architecture & the project's known-correct patterns
Before judging anything, establish what *correct* looks like in THIS codebase, then flag
**deviations** from it (a deviation is far higher-signal than a context-free pattern match).
Produce a **scope map** (if you don't have one). Goal: which endpoint touches which resource,
under which ownership/scope rule.
- Endpoint inventory: `git grep -nE '@router\.(get|post|put|patch|delete)|@api\.|path\(|re_path\(|class .*View' <src-dir>`
- Authz primitives: the tenant/owner scope helper, `request.user`/actor resolution, the
  `@PreAuthorize`-equivalent decorator/permission class, the four-eyes approval service, the
  secret/credential resolver.
- Establish the project's **known-correct pattern** as your reference, e.g. queries scoped to
  the tenant (`...filter(tenant=...)`) + FK-ownership + append-only audit. Compare against it.

---

## Class 1 — IDOR / horizontal authz (same role, another tenant's/customer's resource)
An authenticated actor reaches a resource **they do not own** by changing an identifier in
the request (id/slug/order_no/file_id/session header/email_fingerprint).

**A flaw** (flag it):
- `Model.objects.get(id=...)` / `get_object_or_404(Model, pk=...)` — NO tenant/owner filter,
  and no ownership check afterwards.
- A resolver/serializer returns a resource without binding it to the actor's scope.
- A cross-tenant admin viewer does not validate the tenant parameter against the actor's authority.

**Not a flaw** (do NOT flag — the correct pattern):
- `...filter(id=order_id, tenant=current_tenant)` / `...filter(..., owner=request.user.org)`
- an explicit `if obj.tenant_id != actor.tenant_id: raise Forbidden` after fetch
- a deliberately public resource (documented), or a read-only cross-tenant **admin** view
  gated by a platform-admin check — those are by design.

## Class 2 — missing/broken function-level authz (vertical: role bypass)
The endpoint either **requires no auth at all** or has **no role/permission check** — a normal
actor can call an admin/privileged function.

**A flaw:**
- A sensitive operation (mutate/delete/config/credential/refund-approve) has NO auth
  decorator/permission.
- GET has a role check but the POST/DELETE counterpart does not (asymmetric protection).
- In a four-eyes approval the **same** actor can be both requester and approver.
- A permission string exists but is not assigned to any role -> a silent bypass.

**Not a flaw:** auth+role middleware on the route group; consistent `has_perm`/permission_classes;
four-eyes enforces requester != approver.

## Class 3 — business-logic (syntactically valid, violates a business rule)
Input passes auth/authz but violates a business rule that is **not enforced anywhere in the
code**. High-value examples (adapt to your domain):
- **Amount/money:** negative/zero refund or capture; a partial-capture total exceeding the
  authorized amount (cumulative validation); currency/cent confusion; float precision; a sign
  error in a reserve/commission calculation.
- **Workflow/FSM:** a terminal transition that skips an intermediate state (capture/void/refund
  FSM); replay of a previous step's completion token; an action outside its allowed window.
- **Single-use/idempotency:** the same refund/coupon/OTP processed twice by parallel requests;
  an idempotency-key bypass (does a DB unique backstop exist if the Redis check fails open?).
- **Self-referral / consent:** dequeuing a customer-initiated reversal without approval; a
  saved-card charge without a consent/mandate record.

**Not a flaw:** server-side amount recomputation (does not trust the client); FSM transition
guards; an idempotency unique constraint; tested cumulative validation.

## Class 4 — injection (semantic / stack-specific, semgrep's blind spot)
`scan.sh sast` already runs the **stack-aware semgrep packs** (`p/owasp-top-ten` + the detected
language/framework packs: `p/python`/`p/django`, `p/javascript`/`p/react`, `p/java`, …), so the
**single-sink, in-function** injection patterns (raw SQL string-concat, `os.system(userinput)`,
reflected XSS) are already covered there. This class targets only what those patterns **miss** —
injection that depends on the **call path** or on a **stack idiom** the rule set doesn't model.
First read the stack scan.sh detected (`scan.sh doctor` → `semgrep cfg`) so you hunt the **right
idioms** for that stack; don't re-report what semgrep already flagged.

**A flaw** (flag it — pattern scanners typically don't):
- **Second-order / stored injection:** untrusted input is stored, then later read and passed to a
  sink **in another request/function** without re-sanitization (taint crosses a persistence boundary).
- **Wrapper-hidden sink:** the dangerous call sits in a helper (`run_cmd()`, `raw_query()`,
  `build_html()`); the taint enters several frames up at a caller — no single line looks unsafe.
- **Stack-idiom injection** (use the detected stack):
  - *Django/SQLAlchemy:* `.extra()`, `.raw()`, `RawSQL(...)`, `cursor.execute(f"...")`,
    `text("..."+x)` with interpolated input; `.order_by(request.GET[...])`.
  - *Flask/Jinja:* `render_template_string(user_input)` / a user-controlled template name → **SSTI**.
  - *Node/JS:* `sequelize.query`/`.literal` with interpolation; `child_process.exec(`...${x}`)`;
    `eval`/`Function` reaching user data; `$where`/operator **NoSQL** injection into Mongo.
  - *Java:* `Statement` + concatenation, `Runtime.exec`, OGNL/SpEL/EL evaluation of user input.
- **Deserialization → execution:** `pickle.loads`, `yaml.load` (unsafe loader), Java native deser
  of untrusted bytes; or path/`include` built from user input (path traversal / LFI as injection).

**Not a flaw** (do NOT flag — the correct pattern):
- Parameterized queries / bound params / the ORM's safe query builder (no string interpolation).
- Auto-escaping templates with input rendered as data (not `| safe` / `mark_safe` / `dangerouslySetInnerHTML`).
- A sink whose only input is a server-side constant / allow-listed enum — untrusted input can't reach it.
- A finding semgrep **already reported** for the same sink — that belongs to `scan.sh sast`, not here.

## Bonus pass — past-fix recurrence & incomplete patches
Cheap and high-signal: a real flaw is usually fixed in ONE place, but the same bug-class often
lives elsewhere. Run this alongside the 4 classes.
- **Incomplete fix:** read recent security commits/patches (`git log --grep` for fix/CVE/security/
  CVE-IDs) — does the patch cover *every* call path, or only the reported one? Look for the same
  sink hardened here but left raw next door.
- **Recurrence:** take the *pattern* of a past finding/CVE (unscoped query, missing role check,
  unsanitized sink) and grep the codebase for siblings that match it.
- Record matches as normal findings (location | class | severity | confidence | REAL/UNCERTAIN).

---

## Flow (three phases: baseline -> compare -> assess)
0. **Read `.security-exclusions.md`** at the repo root first (if present) — drop candidates that
   match a do-not-report class or precedent assumption before spending judgment on them.
1. **Phase 2 — compare (recon):** with Phase 1's baseline in hand, produce a *candidate* list per
   class — each candidate is a **deviation** from the known-correct pattern (endpoint/function +
   why it deviates). If there are many candidates, fan out with Explore/subagents.
2. **Phase 3 — assess (verify):** for each candidate READ the call path (file:line) and apply two gates:
   - **Reachability:** can untrusted input actually reach this sink? If not -> FP (not reachable).
   - **Flaw vs. correct pattern:** is protection missing/avoidable, or is this one of the "not a
     flaw" cases above? Justify against the baseline.
   Then assign a **confidence in `[0,1]`** that it is a real, exploitable flaw. Report only
   `≥0.7` (bar: "would a security team raise this in PR review?"); `<0.7` goes to **Suppressed**
   with the score + reason. Genuinely uncertain at ≥0.7 -> keep as UNCERTAIN (safe side).
3. **Record** — append a `## Round N — sec-sast-deep` section to the same
   `docs/security/scan-findings/findings-<TODAY>.md` (do NOT overwrite). Per finding:
   location | class | severity | confidence | REAL/UNCERTAIN | action. Add a **Suppressed**
   sub-list for what the gates dropped (auditability).

## Output -> hooking into the kit flow
This skill **feeds the raw-scan step of `sec-triage` with a deep SAST pass**; the triage/
allowlist/follow-up promotion rules are the same:
- **REAL + small + high-confidence** -> apply the patch (add a tenant filter, enforce a
  permission, validate the amount server-side), show the diff, and run the relevant test if possible.
- **REAL + cross-cutting** -> add an entry to the project's security follow-up registry (a
  `security-followups.md`-style file, if one exists), with severity + the relevant trigger.
- **FP** -> mark it in the findings file with a rationale. (There is NO allowlist file for a
  semantic finding — this is not semgrep; the decision is documented, not the code.)

## Boundaries (HARD)
- Produces **internal evidence**; does NOT replace an external ASV scan or a pentest.
- AI-assisted scanning is not deterministic: a clean result is NOT proof of "no flaws", only
  "nothing found this round". A cutover gate still needs a pentest.
- If a generative-LLM endpoint shows up at runtime, prompt injection is a separate class/tool
  (out of scope here).
