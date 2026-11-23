# security-audit-kit — plugin

Five skills that judge what a pinned, local security scan found. This folder is the whole plugin:
the skills, a manifest, an icon and the licence. It has no hooks, scripts or MCP servers, and it
runs nothing by itself.

| Skill | What it does |
|---|---|
| `sec-triage` | Sorts scanner findings into real and false positive, at an evidence bar: a named sink, an untrusted source and an unbroken path between them. |
| `sec-sast-deep` | Semantic review for what pattern scanners miss: horizontal and vertical authorization, IDOR, business logic, stack-specific injection. |
| `sec-ai-review` | AI/LLM security review mapped to the OWASP Top 10 for LLM Applications. |
| `sec-threat-model` | STRIDE and data-flow threat model of the repository. |
| `sec-audit` | One-command audit: the scan, triage, and only the deep passes the repository calls for. |

## The scanner is not in the plugin

The skills drive the scanner that the repository itself has vendored and pinned, at
`tools/security-audit-kit/`. Each skill tells the agent to use only that copy, to check whether it
is current, and never to download, clone or install anything. If the repository has no vendored
scanner, the skill says so and continues with what does not need it. Setting the scanner up is the
repository owner's decision; see the [kit's README](https://github.com/boraeresici/security-audit-kit#readme).

## Code patterns named in the skills

Three skills (`sec-ai-review`, `sec-audit`, `sec-sast-deep`) name dangerous calls such as `eval`,
`exec`, `child_process.exec(...)`, `Runtime.exec` and `pickle.loads`. These are what a reviewer
looks for in the user's code, the sinks of injection and deserialization flaws; `sec-audit` also
searches the repository for them. They are detection patterns, not commands the plugin runs.

## Data

The plugin sends nothing anywhere and keeps nothing. What the vendored scanner looks up on the
network (package names and versions sent to advisory services, rule packs and a vulnerability
database downloaded) is listed in
[docs/data-flow.md](https://github.com/boraeresici/security-audit-kit/blob/main/docs/data-flow.md).
Privacy policy: [PRIVACY.md](https://github.com/boraeresici/security-audit-kit/blob/main/PRIVACY.md).

## Licence

MIT, see [LICENSE](LICENSE).
