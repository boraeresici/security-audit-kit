#!/usr/bin/env python3
"""pkgcheck helper — the two jobs shell cannot do safely, for `scan.sh pkgcheck`
and `hooks/pre-tool-install.sh`.

    --parse       stdin = an agent tool-call hook payload (JSON) -> install targets
    --command CMD same, but for a raw command line (no JSON)
    --classify    stdin = one `guarddog ... --output-format json` document -> a verdict

Both are pure text-in/text-out: no network, no writes, no imports beyond the stdlib, so the
decision path can be tested offline with fixtures.

Output of --parse / --command, one target per line, tab separated:

    <ecosystem>\t<package>\t<version-or-empty>     scannable target (ecosystem: pypi | npm)
    unverifiable\t<raw-token>\t<reason>            named on the install line, cannot be scanned

Exit codes of --classify:  0 = clean or informational, 1 = BLOCK, 2 = indeterminate.
"""

import argparse
import json
import re
import shlex
import sys

# --- what counts as an install command -------------------------------------------------------
# Only commands that FETCH A NAMED PACKAGE FROM A REGISTRY. `npm install` with no arguments
# installs the lockfile that is already in the repo — that is `scan.sh deps`' job, not this one.
#
# Deliberately NOT here: `uvx` / `pipx run`. They fetch and execute too, but the kit itself runs
# every python tool through `uvx` (scan.sh pyrun), so treating them as installs would make the kit
# scan itself on every scan. Named tools in the kit's own pins are reviewed at pin-bump time.
NPM_CMDS = {
    "npm": {"install", "i", "add"},
    "pnpm": {"install", "i", "add"},
    "yarn": {"add"},
    "bun": {"add", "install"},
}
PY_CMDS = {
    "pip": {"install"},
    "pip3": {"install"},
    "pipx": {"install"},
    "poetry": {"add"},
    "uv": {"add"},  # `uv pip install` handled separately below
}

# Tokens that name something other than a registry package.
_LOCAL_PREFIXES = ("./", "../", "/", "~", ".")
_URL_RE = re.compile(r"^(git\+|https?://|ssh://|file:|github:|git@)")
_ARCHIVE_RE = re.compile(r"\.(whl|tar\.gz|tgz|tar\.bz2|zip)$", re.I)
# A range/wildcard cannot be handed to guarddog's -v, which wants one exact version.
_EXACT_VER_RE = re.compile(r"^[0-9][0-9A-Za-z.\-+]*$")


def _command_from_payload(doc):
    """Agent hook payloads differ per platform; take the first field that carries a command."""
    if not isinstance(doc, dict):
        return ""
    for path in (
        ("tool_input", "command"),
        ("tool_input", "cmd"),
        ("input", "command"),
        ("input", "cmd"),
        ("toolCall", "args", "CommandLine"),
        ("params", "command"),
    ):
        cur = doc
        for key in path:
            cur = cur.get(key) if isinstance(cur, dict) else None
            if cur is None:
                break
        if isinstance(cur, str) and cur.strip():
            return cur
    return ""


def _segments(command):
    """Split a command line into individually-executed segments (&&, ||, ;, |, newline)."""
    return [s for s in re.split(r"&&|\|\||[;\n|]", command) if s.strip()]


def _npm_spec(token):
    """lodash@4.17.21 -> (lodash, 4.17.21); @scope/pkg@1.2.3 -> (@scope/pkg, 1.2.3)."""
    name, ver = token, ""
    at = token.rfind("@")
    if at > 0:  # index 0 is the scope marker, never a version separator
        name, ver = token[:at], token[at + 1:]
    return name, ver if _EXACT_VER_RE.match(ver) else ""


def _pypi_spec(token):
    """requests==2.32.3 -> (requests, 2.32.3); django>=5 -> (django, ''); pkg[extra] -> pkg."""
    m = re.split(r"(==|>=|<=|~=|!=|>|<|@)", token, maxsplit=1)
    name = m[0]
    ver = m[2] if len(m) > 2 and m[1] == "==" else ""
    name = re.sub(r"\[.*?\]", "", name)
    return name, ver if _EXACT_VER_RE.match(ver) else ""


def _targets_in_segment(segment):
    try:
        words = shlex.split(segment)
    except ValueError:  # unbalanced quotes — not a command we can read; say so, do not guess
        return [("unverifiable", segment.strip()[:80], "unparseable command")]
    if not words:
        return []

    # Strip leading env assignments and `sudo`, which precede the real argv.
    while words and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", words[0]) or words[0] == "sudo"):
        words = words[1:]
    if not words:
        return []

    tool, rest = words[0].rsplit("/", 1)[-1], words[1:]
    eco = None

    if tool in ("python", "python3") and rest[:2] == ["-m", "pip"]:
        tool, rest = "pip", rest[2:]
    if tool == "uv" and rest[:2] == ["pip", "install"]:
        eco, rest = "pypi", rest[2:]
    elif tool in NPM_CMDS and rest and rest[0] in NPM_CMDS[tool]:
        eco, rest = "npm", rest[1:]
    elif tool in PY_CMDS and rest and rest[0] in PY_CMDS[tool]:
        eco, rest = "pypi", rest[1:]
    if eco is None:
        return []

    targets, skip_next = [], False
    for token in rest:
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            # -r requirements.txt / -c constraints.txt: a FILE of pins, already covered by
            # `scan.sh deps`; the flag's argument must not be read as a package name.
            if token in ("-r", "--requirement", "-c", "--constraint", "-e", "--editable"):
                skip_next = True
            continue
        if _URL_RE.match(token):
            targets.append(("unverifiable", token, "installed from a URL/VCS, not a registry"))
            continue
        if _ARCHIVE_RE.search(token) or token.startswith(_LOCAL_PREFIXES):
            targets.append(("unverifiable", token, "local path or archive"))
            continue
        name, ver = _npm_spec(token) if eco == "npm" else _pypi_spec(token)
        if name:
            targets.append((eco, name, ver))
    return targets


def parse(command):
    seen, out = set(), []
    for segment in _segments(command):
        for target in _targets_in_segment(segment):
            if target not in seen:
                seen.add(target)
                out.append(target)
    return out


# --- verdict ----------------------------------------------------------------------------------
# guarddog reports two very different things under one `issues` count, and neither maps to
# "block" on its own:
#
#   capability-*   what the package CAN do (spawn a process, write a file). `requests` fires
#                  three. Purely informational.
#   threat-* / metadata rules   what looks WRONG — but most of them also fire on entirely
#                  legitimate software.
#
# MEASURED, 2026-08-24, guarddog 3.0.2, 18 of the most-installed pypi/npm packages (requests,
# numpy, cryptography, django, flask, pandas, psycopg2-binary, boto3, pytest, setuptools, react,
# express, axios, sharp, webpack, eslint, next, typescript, esbuild): **15 distinct
# non-capability rules fired**, on 8 of those packages — `threat-process-download-exec` on
# pandas and setuptools, `threat-filesystem-destruction` and `threat-runtime-obfuscation-*` on
# next, `metadata_mismatch` on typescript and webpack, and so on. So "block on anything that is
# not a capability rule" would have blocked `pip install django`. A gate that blocks Django is a
# gate that gets uninstalled, and an uninstalled gate protects nothing.
#
# Hence: an explicit BLOCK list of malice-specific rules — every one of which fired on NONE of
# those 18 packages — and everything else is printed as a NOTE, not blocked. The tool version is
# pinned (GUARDDOG_VER), so this list cannot silently drift; when the pin is bumped, any new rule
# reports until someone measures it and moves it here.
#
# Re-derive with: for each popular package, `guarddog <eco> scan <pkg> --output-format json`,
# then count non-capability rules that fired. A rule that fires on a package no one would call
# malicious does not belong in this set.
BLOCK_RULES = {
    # the reason this hook exists: the wrong name, or a name aimed at an internal registry
    "typosquatting",
    "threat-npm-dependency-confusion",
    # code that runs at INSTALL time — precisely the window a pre-install check protects
    "threat-setup-network-in-install",
    "threat-npm-preinstall-script",
    "threat-setup-import-aliasing",
    # payload behaviour with no benign reading in a freshly installed dependency
    "threat-network-reverse-shell",
    "threat-network-exfiltration",
    "threat-network-exfil-sysinfo",
    "threat-network-exfil-messenger",
    "threat-network-dns-exfil",
    "threat-network-outbound-shady-links",
    "threat-process-cryptomining",
    "threat-runtime-keylogging",
    "threat-runtime-screencapture",
    "threat-runtime-self-propagation",
    "threat-process-injection-dll",
    "threat-process-powershell-encoded",
    "threat-runtime-obfuscation-hidden-code",
    "threat-runtime-obfuscation-log-suppress",
    "threat-runtime-obfuscation-import-exec",
    "threat-runtime-obfuscation-pyarmor",
    # maintainer-account signals: an unclaimed or expired maintainer domain is how a takeover
    # starts, and none of the 18 tripped these
    "deceptive_author",
    "potentially_compromised_email_domain",
    "unclaimed_maintainer_email_domain",
}


def classify(doc, block_extra=(), report_extra=()):
    """-> (verdict, exit_code, detail). verdict in BLOCK | NOTE | CLEAN | INDETERMINATE."""
    if not isinstance(doc, dict):
        return "INDETERMINATE", 2, "guarddog output was not a JSON object"

    errors = doc.get("errors") or {}
    results = doc.get("results")
    # The dangerous case, and it is real: when the download fails, guarddog prints "No risks
    # found" and returns 0 with no `results` key at all. Reporting that as clean would be a lie
    # the caller cannot detect. (Reproduced with `npm scan flatmap-stream -v 0.1.1`.)
    if errors or results is None:
        why = "; ".join(f"{k}: {v}" for k, v in errors.items()) or "no results in guarddog output"
        return "INDETERMINATE", 2, f"NOT SCANNED — {why}"

    fired = [rule for rule, hits in results.items() if hits]
    block_set = BLOCK_RULES.union(block_extra).difference(report_extra)
    blocking = [r for r in fired if r in block_set]
    if blocking:
        return "BLOCK", 1, ", ".join(sorted(blocking))
    if fired:
        return "NOTE", 0, ", ".join(sorted(fired))
    return "CLEAN", 0, "no rules fired"


def _csv(value):
    return tuple(x.strip() for x in (value or "").split(",") if x.strip())


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--parse", action="store_true", help="stdin = agent hook payload (JSON)")
    ap.add_argument("--command", help="parse this raw command line instead of stdin")
    ap.add_argument("--classify", action="store_true", help="stdin = guarddog JSON")
    ap.add_argument("--block-extra", default="", help="comma-separated rules to force-block")
    ap.add_argument("--report-extra", default="", help="comma-separated rules to demote to NOTE")
    args = ap.parse_args()

    if args.classify:
        try:
            doc = json.load(sys.stdin)
        except (ValueError, OSError) as exc:
            print(f"INDETERMINATE\tguarddog output unreadable: {exc}")
            return 2
        verdict, code, detail = classify(doc, _csv(args.block_extra), _csv(args.report_extra))
        print(f"{verdict}\t{detail}")
        return code

    if args.command is not None:
        command = args.command
    elif args.parse:
        raw = sys.stdin.read()
        try:
            command = _command_from_payload(json.loads(raw))
        except ValueError:
            command = ""  # not JSON: a payload we do not understand names no install we can trust
    else:
        ap.error("one of --parse, --command or --classify is required")
        return 2

    for eco, name, ver in parse(command):
        print(f"{eco}\t{name}\t{ver}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
