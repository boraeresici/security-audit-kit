#!/usr/bin/env python3
"""Finding fingerprints (F19a, slice 1): an identity that survives what does not change the finding.

`id` is `sha1(dimension|rule|file|line)`: insert one line above a finding and it is a new finding,
so a decision made about it is lost. `fingerprint` is what a decision record keys on instead.
Three bases, named in `fingerprint_basis` so a reader can tell how much a match means:

- `line-content`  code findings. The rule, the file, the text of the reported line with whitespace
                  collapsed, and which occurrence of that text this is among the rule's findings
                  in the file (0, 1, ... in line order). Moving the line keeps the fingerprint;
                  editing it or renaming the file does not. This is the method GitHub code scanning
                  uses for `primaryLocationLineHash`.
- `package`       dependency findings (a row with `package`). Advisory, ecosystem, package name and
                  manifest. The advisory is one name chosen from the row's own id and aliases
                  (`canonical_advisory`), so two tools that name it differently agree when one of
                  them knows the other's name. The version is NOT part of it: a version bump that does not fix the
                  advisory is the same finding, and one that fixes it makes the row disappear. Two
                  packages with the same advisory in one manifest are two findings.
- `location`      everything else, and every case where the line cannot be read safely: the same
                  inputs as `id`. Secret findings are always here, on purpose — a hash of the line
                  would be a hash of the secret, in a report that gets mailed around.

Stdlib only. The file read is the only thing here that touches the scanned repo, so it is narrow:
a repo-relative path with no `..`, resolving inside the root, a regular file under a size cap.
"""
import hashlib
import os
import re

MAX_FILE_BYTES = 5 * 1024 * 1024
FP_CHARS = 20                       # 80 bits of sha256
PYTHON_ENV = "python-env"           # pip-audit audits an environment, not a manifest: a venv's path
                                    # differs per machine, so it cannot be part of an identity
NO_LINE_HASH = {"secret", "staged"}  # dimensions whose reported line IS the secret


def _h(*parts) -> str:
    return hashlib.sha256("\x1f".join(str(p) for p in parts).encode("utf-8")).hexdigest()[:FP_CHARS]


def package_name(ecosystem: str, name: str) -> str:
    """The name two tools would agree on. PyPI names compare case-insensitively with runs of
    `-`, `_`, `.` equal (PEP 503); other ecosystems are left as written."""
    if (ecosystem or "").lower() == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def canonical_advisory(rule_id: str, aliases) -> str:
    """One name for an advisory that has several (PYSEC-2021-108 = CVE-2021-33503 = GHSA-q2q7-...).

    Chosen from THIS row's id and aliases only: the CVE if there is one, else the GHSA, else the
    first id in sort order. Never from what another tool said in the same run — a fingerprint that
    changed with the set of dimensions that ran would move decisions around. So a tool that gives
    no aliases matches another only when its id is already the canonical one (trivy reports the
    CVE; pip-audit and osv-scanner list it as an alias). Two rows that do not meet stay two
    findings: a missed merge costs a second decision, a wrong merge would suppress a finding."""
    ids = sorted({str(i).strip() for i in [rule_id, *(aliases or [])] if isinstance(i, str) and i.strip()})
    for prefix in ("CVE-", "GHSA-"):
        hit = [i for i in ids if i.upper().startswith(prefix)]
        if hit:
            return hit[0]
    return ids[0] if ids else ""


# A SARIF row names the manifest but not the ecosystem (trivy, osv-scanner). The file name says it.
_MANIFEST_ECOSYSTEM = (
    (re.compile(r"(^|/)(requirements[^/]*\.txt|uv\.lock|poetry\.lock|Pipfile\.lock|pdm\.lock)$"), "pypi"),
    (re.compile(r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml)$"), "npm"),
    (re.compile(r"(^|/)(go\.mod|go\.sum)$"), "go"),
    (re.compile(r"(^|/)Cargo\.lock$"), "crates.io"),
    (re.compile(r"(^|/)Gemfile\.lock$"), "rubygems"),
    (re.compile(r"(^|/)composer\.lock$"), "packagist"),
    (re.compile(r"(^|/)(pom\.xml|gradle\.lockfile|buildscript-gradle\.lockfile)$"), "maven"),
)


def manifest_ecosystem(path) -> str:
    """The ecosystem a lock file or manifest belongs to, or "" when the name does not say."""
    for pattern, eco in _MANIFEST_ECOSYSTEM:
        if pattern.search(path or ""):
            return eco
    return ""


class Lines:
    """Reported lines of repo files, read once per file and only if the path is safe to read."""

    def __init__(self, root: str):
        self.root = os.path.realpath(root)
        self.cache = {}

    def _load(self, path: str):
        if not path or os.path.isabs(path) or "\x00" in path or ".." in path.replace("\\", "/").split("/"):
            return None
        full = os.path.realpath(os.path.join(self.root, path))
        if full != self.root and not full.startswith(self.root + os.sep):
            return None                                   # a link that leaves the repo
        try:
            if not os.path.isfile(full) or os.path.getsize(full) > MAX_FILE_BYTES:
                return None
            with open(full, "rb") as fh:
                data = fh.read(MAX_FILE_BYTES + 1)
        except OSError:
            return None
        if len(data) > MAX_FILE_BYTES:
            return None
        # Split on \n only: that is how every scanner counts lines (str.splitlines also splits on
        # form feeds and U+2028, which would shift the numbers).
        return data.split(b"\n")

    def text(self, path: str, line):
        """The line with whitespace collapsed, or None if it cannot identify anything."""
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            return None
        if path not in self.cache:
            self.cache[path] = self._load(path)
        lines = self.cache[path]
        if lines is None or line > len(lines):
            return None
        text = " ".join(lines[line - 1].decode("utf-8", "replace").split())
        return text or None                               # a blank line is the same everywhere


def assign(findings: list, root: str = ".") -> None:
    """Set `fingerprint` and `fingerprint_basis` on every finding, in place."""
    lines = Lines(root)
    groups = {}
    for f in findings:
        dim, rule = str(f.get("dimension") or ""), str(f.get("rule_id") or "")
        path, line = f.get("file"), f.get("line")
        pkg = f.get("package")
        if isinstance(pkg, dict) and pkg.get("name"):
            eco = str(pkg.get("ecosystem") or "").lower()
            advisory = canonical_advisory(rule, f.get("aliases"))
            f["fingerprint"] = _h("package", advisory, eco, package_name(eco, str(pkg["name"])), path or PYTHON_ENV)
            f["fingerprint_basis"] = "package"
            continue
        text = None if dim in NO_LINE_HASH else lines.text(path, line) if path else None
        if text is None:
            f["fingerprint"] = _h("location", dim, rule, path or "", "" if line is None else line)
            f["fingerprint_basis"] = "location"
            continue
        groups.setdefault((dim, rule, path, _h(text)), []).append(f)
    for (dim, rule, path, line_hash), group in groups.items():
        # Occurrence index: the same text reported twice by one rule in one file (two identical
        # calls) is two findings, told apart by their order, which a shift of both preserves.
        for index, f in enumerate(sorted(group, key=lambda g: g["line"])):
            f["fingerprint"] = _h("line-content", dim, rule, path, line_hash, index)
            f["fingerprint_basis"] = "line-content"
