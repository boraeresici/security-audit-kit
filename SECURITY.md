# Security Policy & Trust Model

## License & what it means
security-audit-kit is licensed under the [MIT License](LICENSE). In plain terms: you may use,
copy, modify, and redistribute it — including in **forks** and in commercial products —
provided you keep the copyright and license notice. It is provided **"AS IS", without warranty
of any kind**; see the disclaimer in [LICENSE](LICENSE).

## This is a public, forkable project
Because the project is open source under MIT, **anyone may fork it and change any file —
including the Claude skills** (which are plain-text instructions an AI follows). A fork is a
separate, independent copy: its changes are **not reviewed, endorsed, or controlled** by this
project.

We cannot prevent forks, and no hash or signature can — that is inherent to open source. What
integrity mechanisms *can* do is let you verify that **what you run matches what the official
project published**. They prove provenance, not safety.

## The only official source
The single canonical repository is:

> **https://github.com/boraeresici/security-audit-kit**

- `bootstrap.sh` defaults `KIT_REPO` to this repository. You must **deliberately** override
  `KIT_REPO` to install from anywhere else — do that only for a fork you personally trust.
- Treat any other host, mirror, or similarly-named repository as **unofficial** until you have
  reviewed it yourself.

## No warranty / scope boundary
- The kit produces **internal evidence only**. It does **not** replace an external ASV scan, a
  penetration test, or any required compliance control. A clean scan means "nothing found by
  these tools, this run" — not proof of safety.
- You run it **at your own risk**. To the extent permitted by law, the authors are not liable
  for missed findings, false positives, broken builds, or any damage — per the MIT disclaimer.

## Using it safely (supply-chain guidance)
1. **Download, review, then run.** Never pipe a remote script into a shell. `bootstrap.sh` is
   meant to be read before it is executed.
2. **Pin a tag or commit SHA.** `bootstrap.sh` writes a `.kit-version` (ref + resolved SHA);
   commit it so your whole team shares one reviewed, pinned version. A git commit SHA is a
   content hash of the entire tree — pinning it is your strongest built-in integrity control.
3. **Review the skills.** Files under `.claude/skills/` are instructions an AI will follow.
   Read them like any code you grant access to. A hash proves a skill is *unchanged from
   upstream*; it does **not** prove it is *safe* — that is what review is for.
4. **Review diffs on update.** `bootstrap.sh <new-tag>` overwrites the vendored copy; run
   `git diff -- tools/security-audit-kit` before committing the bump.

### Planned integrity tooling
A `CHECKSUMS` manifest (SHA-256 of every kit file) plus a `scan.sh verify` command are planned,
so you can detect tampering or a rogue skill added to a vendored copy. Transparency-logged
signed releases may follow if adoption warrants. See the project roadmap.

## Reporting a vulnerability
Please report security issues **privately**, not in a public issue:

- Open a [private GitHub security advisory](https://github.com/boraeresici/security-audit-kit/security/advisories/new), or
- email **eresicibora@gmail.com**.

Include the affected version/SHA, reproduction steps, and impact. We aim to acknowledge within a
reasonable time and will credit reporters who wish to be credited.

## Supported versions
Only the **latest release** receives fixes. Pin a release tag and update to the newest one to
stay current (`bootstrap.sh --check` tells you when a newer tag exists).
