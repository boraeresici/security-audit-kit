# security-audit-kit — triage exclusions & precedents (EXAMPLE)
#
# Usage: copy this file to the repo ROOT as `.security-exclusions.md`, tune it for your
# project, and COMMIT it (team-shared). The Claude triage skills (sec-triage, sec-sast-deep,
# sec-ai-review) READ this file FIRST and auto-mark any matching finding as FP (with the rule
# cited), before spending judgment on it. This kills deterministic noise and keeps the signal
# high. It is advisory to the AI, not a hard scanner allowlist — a real, high-confidence
# finding still surfaces even if it brushes a rule; when in doubt, the skill keeps it.
#
# Two sections: (A) DO-NOT-REPORT classes, (B) PRECEDENT assumptions. Edit freely.

## A. Do-not-report classes
A finding is suppressed (marked FP) if it falls only into one of these. Adapted from the
Claude Code security-review methodology.

- **Denial of service / resource exhaustion** — rate-limiting, unbounded loops, ReDoS, large
  input handling. (Out of scope unless it's a trivial, remotely-triggerable crash on a critical path.)
- **Memory safety in memory-safe languages** — GC'd/managed languages (Python, JS/TS, Go, Java,
  C#…); only report in C/C++/unsafe blocks.
- **Test-only / fixture / example code** — files under `test/`, `tests/`, `__tests__/`,
  `*_test.*`, `spec/`, `fixtures/`, `examples/`, `docs/`. Secrets/issues confined here are FP.
- **Log spoofing / log injection** — CRLF into logs without a downstream sink.
- **Path-only SSRF / open redirect** — a redirect/URL that only controls the path, not host.
- **Regex injection** — user-controlled regex without catastrophic backtracking on a hot path.
- **Insecure documentation / comments** — examples in README/comments, not executed code.
- **Secrets already secured on disk** — values in `.env`/secret stores that are gitignored and
  not committed; a placeholder/dummy/sandbox value (proven).
- **Generic CI/workflow hardening nits** — most GitHub Actions workflow lint (unless a real
  secret exfiltration / `pull_request_target` + untrusted checkout pattern).
- **Defense-in-depth / hardening suggestions with no concrete exploit path** — "could add X".
- **Low severity by policy** — anything you've decided not to gate on (state it here).

## B. Precedent assumptions
Treat these as true unless there is concrete evidence otherwise (don't flag them):

- **UUIDs/v4 tokens are unguessable** — an IDOR needs an enumerable/guessable id, not a UUID.
- **Environment variables are trusted** — values from `process.env`/`os.environ` are operator-
  controlled, not attacker input.
- **Client-side permission checks** are UX, not security — only flag the *server-side* gap.
- **Framework defaults are on** — e.g. ORM parameterization, template auto-escaping, CSRF
  middleware — unless the code explicitly disables them.
- **Internal-only / authenticated-admin surfaces** — a documented platform-admin tool isn't an
  authz bug just for crossing tenants by design.

## C. Project-specific (add your own)
# - <path/or pattern>  —  <why it is acceptable>
# - <rule id / finding> —  <rationale>
