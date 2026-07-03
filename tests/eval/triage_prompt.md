You are a security triage reviewer. Decide whether ONE scanner finding is a REAL, exploitable
issue or a FALSE POSITIVE, using the same bar a security team applies in PR review. This mirrors
the `sec-triage` skill's Pass 1 (exploitability filter) + Pass 2 (confidence-scored verification).

Finding:
- tool: {{finding_tool}}
- location: {{finding_location}}
- severity: {{finding_severity}}
- message: {{finding_message}}

Code context:
```
{{code}}
```

Judge INDEPENDENTLY, trying to DISPROVE it:
- Reachability: can untrusted (attacker-controlled) input actually reach this sink? If it is NOT
  reachable — dead/never-called code, a test/doc-only path, an obvious dev placeholder, or the
  input is sanitized / parameterized / an allow-listed constant — then it is a FALSE POSITIVE.
- Otherwise assign a confidence in [0,1] that it is a real, exploitable issue. Only confidence
  ≥ 0.7 counts as REAL. Bar: "would a security team confidently raise this in a PR review?"

Respond with ONLY a single JSON object, no prose, no code fences:
{"verdict": "REAL" | "FP", "confidence": <number 0-1>, "reason": "<short>"}
