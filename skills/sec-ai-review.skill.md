---
name: sec-ai-review
description: Deep-scans with Claude for SEMANTIC AI/LLM security flaws that pattern tools miss — prompt injection (direct/indirect), insecure output handling, excessive agency, sensitive-info / system-prompt disclosure, and model/data supply chain. Follows the data/trust flow from untrusted input to a powerful sink, mapped to the OWASP LLM Top 10. NOT part of scan.sh; run it when a codebase calls an LLM / exposes tools or agents. Output feeds the sec-triage flow. Use it when asked to "review AI/LLM security / prompt injection / agent safety".
---

# sec-ai-review — semantic AI/LLM security review (OWASP LLM Top 10)

Static tools (semgrep/gitleaks) catch code-level bugs, but LLM-application risk lives in
the **trust boundary between untrusted text and a powerful action** — a matter of data
flow and granted authority, not a regex. This skill reviews that boundary with Claude. It
**complements** `sec-sast-deep` (code authz/logic) and `scan.sh` (secrets/SAST/deps); it
does not replace them.

> Source/inspiration: `github.com/utkusen/awesome-ai-security` (curated AI-security
> resources) and the **OWASP Top 10 for LLM Applications**. Use those as the living
> checklist; this skill adapts them to the kit's `sec-triage` output flow.

## When
- The codebase **calls an LLM** (chat/completion/embeddings), exposes **tools/function
  calling**, runs an **agent**, or does **RAG** over external/user content.
- Before shipping a new AI surface: a new tool the model can invoke, a new data source fed
  into a prompt, a new autonomous/scheduled agent, a new MCP server.
- When the user says "review prompt injection / agent safety / LLM security".
- **NOT on every push** — judgment, token-costly; run it on-trigger like `sec-sast-deep`.

## Prerequisite: map the LLM data + authority flow
Before judging, map three things:
- **Untrusted inputs into prompts:** end-user text, retrieved documents/web pages, tool
  results, file contents, email/issue bodies, prior turns — anything not author-controlled.
  `git grep -nE 'messages=|system\s*=|prompt|invoke_model|chat\.completions|generate_content|tools=|tool_call'`
- **Sinks the model can reach:** shell/exec, SQL, HTTP requests, file writes, code eval,
  payments/refunds, email/send, infra changes, and any tool exposed via function calling/MCP.
- **The authority granted to the model:** which tools, with what scope, and whether a human
  approves side effects. The risk is `untrusted input × powerful sink × no gate`.

---

## LLM01 — Prompt injection (direct & indirect)
Untrusted text changes the model's behavior. **Indirect** (the dangerous one): the payload
arrives via retrieved/tool content (a web page, a doc, an email), not the user typing it.

**A flaw** (flag it):
- Retrieved/RAG/tool content is concatenated into the same context as instructions with no
  separation, and the model can then call a sink (exfiltrate data, send mail, run a tool).
- A system prompt is the *only* control preventing a harmful action ("never reveal X" /
  "only answer about Y") — prompt instructions are not a security boundary.
- Tool-call arguments derived from model output flow into exec/SQL/HTTP without validation.

**Not a flaw:** untrusted content is clearly delimited AND the model has no powerful sink;
side effects require an out-of-band check (allowlist, schema validation, human approval),
not just prompt wording.

## LLM02 — Insecure output handling
Model output is **trusted** by a downstream component.
- Output rendered as HTML/markdown without sanitizing → XSS; written into SQL → injection;
  passed to `eval`/`exec`/a shell → RCE; used as a URL/redirect/path without validation.
- **Treat LLM output exactly like untrusted user input** at every sink.

## LLM06 — Excessive agency
The model/agent can do more than the task requires.
- Broad tools (arbitrary shell, unrestricted HTTP, delete/refund) exposed when a narrow one
  would do; no human-in-the-loop for irreversible/high-value side effects.
- An autonomous loop that can spend money, modify infra, or email externally without a gate.
- **Least privilege for tools**, and an approval step for irreversible actions.

## LLM07 — System-prompt / sensitive-info disclosure
- Secrets, API keys, internal URLs, or other users' data placed in the prompt/context and
  thus leakable via injection or a verbose error.
- Relying on "don't reveal the system prompt" — assume it is recoverable; keep nothing
  sensitive there. (For literal secrets in code, that's `scan.sh secret` / gitleaks.)

## LLM03/LLM05 — Model & data supply chain
- An **unpinned** model/endpoint, or a model/weights pulled from an untrusted source.
- RAG indexing untrusted content that later steers behavior (poisoning) — same root as
  indirect injection; check what can enter the index and whether it is attributable.
- Third-party tool/plugin/MCP server trusted with credentials or data without review.

---

## Flow (three phases) — mirrors sec-sast-deep
0. **Read `.security-exclusions.md`** at the repo root first (if present) — drop candidates
   matching a do-not-report class / precedent before judging them.
1. **Recon** — from the map, list *candidates* per category (input source → sink, why
   suspicious). Fan out with Explore/subagents if there are many.
2. **Verify** — for each candidate, READ the data flow (file:line). The reachability gate IS the
   core question here: **can untrusted text reach a powerful sink without an out-of-band gate?**
   If not -> FP. Justify against the "not a flaw" cases, then assign a **confidence in `[0,1]`**
   that it is real and exploitable. Report only `≥0.7` (bar: "would a security team raise this in
   PR review?"); `<0.7` -> **Suppressed** with score + reason; uncertain at ≥0.7 -> UNCERTAIN.
3. **Record** — append a `## Round N — sec-ai-review` section to the same
   `docs/security/scan-findings/findings-<TODAY>.md` (do NOT overwrite). Per finding:
   location | OWASP-LLM id | severity | confidence | REAL/UNCERTAIN | action + a **Suppressed**
   sub-list for what the gates dropped.

## Output -> hooking into the kit flow (same as sec-triage)
- **REAL + small + high-confidence** → apply the fix (delimit + ignore-instructions-in-data,
  validate tool args against a schema/allowlist, add a human-approval gate, move secrets out
  of context, pin the model), show the diff.
- **REAL + cross-cutting** → add a `security-followups.md`-style registry entry with the
  OWASP-LLM id + trigger.
- **FP** → mark it in the findings file with a rationale (no allowlist file — judgment, not a
  pattern).

## Boundaries (HARD)
- Produces **internal evidence**; does NOT replace an external AI red-team / pentest.
- LLM defenses are **probabilistic** — a clean review is "nothing found this round", not a
  proof of safety. Never let a prompt instruction be the only thing standing between
  untrusted input and an irreversible action.
