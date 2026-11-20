# Privacy

This policy covers security-audit-kit: the Claude Code plugin (its skills) and the scanner kit
that a repo vendors under `tools/security-audit-kit/`.

**We collect nothing.** The kit and the plugin have no server, no account, no telemetry and no
analytics. The maintainers receive no data from your use of them.

**The plugin** is five skills (instructions for your coding agent) and one hook. It ships no MCP
servers. It reads no credentials and sends no data anywhere itself. The skills tell the agent to
run the scanner that your repo has vendored, and to read its output. The hook
(`hooks/post-edit-check.sh`, a readable shell script) runs after the agent edits a file: it asks
that same vendored scanner to check that one file, and adds what it finds to the agent's context.
Turn it off with `EDIT_CHECK=0`.

**The scanner** runs on your machine. No scanner sends your source code. Some of its checks
contact public services:
- **Dependency checks** send package names and versions to advisory services: PyPI's advisory
  API, osv.dev, and your package registry's audit endpoint.
- **SAST** downloads rule packs from the semgrep registry. The names of the packs it asks for
  reflect your detected stack.
- **Container and supply-chain checks** download tool images, a vulnerability database, and the
  packages they analyse.

[docs/data-flow.md](docs/data-flow.md) lists exactly what each command sends, and where. It also
explains how to run without a network.

**Your coding agent.** What the agent reads while it runs a skill goes to the model provider your
agent uses, under that provider's terms. This includes source files, findings and scan output.
The kit does not control this flow.

**What is stored.** Scan output and triage notes are written into your own repo, under
`docs/security/`. You decide whether to commit them. Nothing is stored anywhere else.

**Questions:** open an issue on the
[repository](https://github.com/boraeresici/security-audit-kit/issues). To report a security
problem, follow [SECURITY.md](SECURITY.md).
