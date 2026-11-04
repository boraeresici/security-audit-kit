# Dimension adapters — the contract

Every scan dimension in `scan.sh` is an **adapter**: one shell function plus one line in the
registry. Dispatch, `scan.sh help` and the closing summary read the registry. No other part of the
script names dimensions, so adding one does not mean editing five places that then drift apart.

This document is the contract. `tests/e2e.sh` enforces its static parts (section "dimension
registry").

## The registry

Two text tables near the end of `scan.sh`. They are plain text because bash 3.2 on macOS has no
associative arrays.

### `DIM_UNITS`: one adapter per line

| column   | meaning |
|----------|---------|
| `unit`   | Registry key, unique. |
| `record` | The name `summary.json` and the closing table use. Two units may share one: `sast-changed` records as `sast`. |
| `entry`  | The adapter function, `scan_<x>`. |
| `gate`   | `hard`: findings block. `soft`: findings are reported and never block. `artifact`: the dimension writes a file and has no findings. |
| `needs`  | `docker`, `pyrun` (uvx or pipx), or `-` when the adapter finds its own toolchain. |

### `SCAN_COMMANDS`: one command per line

```
command | units, in run order | what the command leaves out (shown in the closing summary)
```

Every unit of a command runs, even after an earlier one blocks. The gate is the OR of all of them.
A command that is not in the table is "unknown". The error message lists the table's commands,
followed by the non-scan commands.

## The adapter function

```bash
scan_<x>(){ ...; }
```

**Arguments:** none. Read configuration from the environment, with precedence
env > `.security-audit.conf` > default.

**Return code.** This is the gate, and `_dim` records it:

| rc | meaning | gate |
|----|---------|------|
| `0` | It looked and found nothing that blocks. | allow |
| `1` | Findings. | block |
| `$RC_INDETERMINATE` (3) | It ran but had nothing to inspect. This is **not** a pass. | allow |
| any other | The tool failed. | block |

A `soft` adapter returns `0` on findings and records them with
`dim_mark findings "<why>"` instead.

**Status.** Optional. It overrides what the return code implies, and `summary.json` stores it apart
from the gate:

| helper | use when | return |
|--------|----------|--------|
| `dim_skip <rec> "<why>"` | It could have run, but a tool is missing (no docker, no uvx). | `return 0` |
| `dim_na <rec> "<why>"` | The repo has nothing of this kind (no terraform, no workflows). | `return 0` |
| `dim_error <rec> "<why>"` | The tool ran and failed. This is not a finding. | `return 1`, or `0` for a soft adapter |
| `dim_mark <status> "<why>"` | Any other status, or a reason without a status (`dim_mark "" "<why>"`). | n/a |

Keep `<why>` to one line of prose. A reason that names `no docker` or `no uvx/pipx` is grouped into
the closing summary's toolchain hint.

**Output:**
- Progress goes to stdout or stderr through `say <rec> "<msg>"`. It reaches the raw log through `tee`.
- When `$SARIF = 1`, write SARIF to `$SARIF_DIR/<tool>.sarif` (on the host) or to
  `/repo/$(sarif_rel <tool>.sarif)` (inside docker). `evidence.json` and the report are built from
  whatever lands there.
- Write nothing else into the repo, except the declared artifact of an `artifact` adapter.
- Per-run side data that the summary needs goes in `$RUN_DIR` (see `scan_container` and `trivy-db`).
  The adapter runs inside the `tee` subshell, so a variable it sets is lost.

**Rules that already cost us a release.** Each one is guarded in `tests/e2e.sh`.
- **Consume your input.** Never write `git ls-files | grep -q`. Use `has_tracked` or a here-string.
  A SIGPIPE turns "present" into "absent" on large repos.
- **Pin the tool.** Use a docker image by digest (`img <image> <tag> <digest>`) or a Python CLI by
  version (`pyrun <pkg> <ver> <cmd>`). Add the pin to `provenance_json` and, for images, to
  `scan_warm`.
- **Never execute the target's code to decide what to report** (build scripts, installs). Refuse
  it, or require an explicit opt-in env var, as `OSV_ALLOW_BUILD_SCRIPTS` does.
- **Exclude the kit's own record** (`$(record_rel)`) and, when vendored, the kit itself.

## Adding a dimension

1. Write `scan_<x>` to this contract.
2. Add a line to `DIM_UNITS`.
3. Add a command line to `SCAN_COMMANDS`. Put the unit in `all` or `fast` only if it is
   deterministic, finishes in seconds and needs no network. Otherwise add it to their "leaves out"
   column.
4. Add the command to the `# Usage:` block at the top of `scan.sh`, which is the help text.
5. Run `tests/e2e.sh` and `scan.sh checksums`.

A dimension that needs a live target, has an LLM in the loop or attacks something is **not** a
`scan.sh` dimension: the kit scans and judges, it does not attack. Such tools are composed from
outside, never run from a hook.
