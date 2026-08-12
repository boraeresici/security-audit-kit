#!/usr/bin/env bash
# tests/e2e.sh — end-to-end local test.
#
# Vendors the CURRENT working tree of the kit into a throwaway git repo, runs install.sh,
# then exercises the deterministic plumbing and asserts each gate fires:
#   install -> hooksPath/skills/config  ·  doctor  ·  secret (gitleaks) + pre-commit gate
#   ·  SAST (semgrep, fixture ERROR rule)  ·  summary.json validity.
#
# Tests the SCRIPTABLE plumbing — NOT the AI skills' judgment (that needs an LLM in the loop).
# Requires git; docker (gitleaks) and uvx/pipx (semgrep) are used if present, else skipped.
# Usage:  bash tests/e2e.sh        (exit 0 = all assertions passed)
set -uo pipefail

KIT_SRC="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
no(){ FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
skip(){ printf '  \033[33mSKIP\033[0m %s\n' "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }
docker_ok(){ have docker && docker info >/dev/null 2>&1; }

TARGET="$(mktemp -d)"
trap 'rm -rf "$TARGET"' EXIT
echo "== e2e target: $TARGET =="

# --- vendor the current working tree (not a released tag) ---
mkdir -p "$TARGET/tools/security-audit-kit"
if have rsync; then
  rsync -a --exclude '.git' --exclude 'docs/security' "$KIT_SRC"/ "$TARGET/tools/security-audit-kit"/
else
  cp -R "$KIT_SRC"/. "$TARGET/tools/security-audit-kit"/; rm -rf "$TARGET/tools/security-audit-kit/.git"
fi

cd "$TARGET" || exit 1
git init -q
git -c user.email=e2e@test -c user.name=e2e add -A
git -c user.email=e2e@test -c user.name=e2e commit -qm init

SCAN="bash tools/security-audit-kit/scan.sh"

echo "-- install --"
bash tools/security-audit-kit/install.sh >/dev/null 2>&1 && ok "install.sh ran" || no "install.sh failed"
[ "$(git config core.hooksPath)" = "tools/security-audit-kit/hooks" ] && ok "hooksPath set" || no "hooksPath not set"
for s in sec-triage sec-sast-deep sec-ai-review sec-threat-model sec-audit; do
  [ -f ".claude/skills/$s/SKILL.md" ] && ok "skill installed: $s" || no "skill missing: $s"
done
[ -f .security-audit.conf ] && ok ".security-audit.conf created" || no ".security-audit.conf missing"
[ -f .security-exclusions.md ] && ok ".security-exclusions.md created" || no ".security-exclusions.md missing"

echo "-- doctor --"
$SCAN doctor >/dev/null 2>&1 && ok "doctor ran" || no "doctor failed"

echo "-- allowlist surface (doctor lists every suppression path) --"
# A dependency CVE is reported by py-deps + osv + container, so a suppression written to one file
# leaves the others firing. doctor has to make a half-applied suppression visible.
ADOC="$($SCAN doctor 2>/dev/null)"
printf '%s' "$ADOC" | grep -q 'allowlists (a suppression must cover every path' \
  && ok "doctor: allowlist section present" || no "doctor: allowlist section missing"
for f in .gitleaks.toml .pip-audit-ignore osv-scanner.toml .trivyignore.yaml .security-exclusions.md; do
  printf '%s' "$ADOC" | grep -q -- "$f" || { no "doctor: $f not listed"; break; }
done
printf '%s' "$ADOC" | grep -q 'osv-scanner.toml' && printf '%s' "$ADOC" | grep -q '.trivyignore.yaml' \
  && ok "doctor: the two paths triage used to forget are listed" || no "doctor: osv/trivy paths missing"

echo "-- stack-aware semgrep config --"
# A bash/markdown repo -> base packs only (owasp-top-ten + secrets), no language packs.
DOC="$($SCAN doctor 2>/dev/null)"
printf '%s' "$DOC" | grep -q 'semgrep cfg .*owasp-top-ten.*secrets.*(stack-auto)' && ok "cfg: base packs auto" || no "cfg: base packs missing"
printf '%s' "$DOC" | grep -q 'semgrep cfg.*p/python' && no "cfg: python pack on non-python repo" || ok "cfg: no language pack on bash repo"
# Plant a python+react stack -> should pull p/python and p/react.
mkdir -p stack/backend stack/frontend
echo 'django==5.0' > stack/backend/requirements.txt
echo 'def x(): pass' > stack/backend/manage.py
printf '{ "dependencies": { "react": "^18" } }\n' > stack/package.json
echo 'export const A=1' > stack/frontend/app.tsx
git -c user.email=e2e@test -c user.name=e2e add stack >/dev/null 2>&1
DOC2="$($SCAN doctor 2>/dev/null)"
printf '%s' "$DOC2" | grep -q 'p/python' && printf '%s' "$DOC2" | grep -q 'p/django' \
  && printf '%s' "$DOC2" | grep -q 'p/react' && ok "cfg: stack packs auto-selected (python+django+react)" || no "cfg: stack packs not selected"
# Explicit override wins verbatim, nothing appended. Capture first (env-prefixed pipeline +
# pipefail is fragile) — same command-substitution form as the base/stack assertions above.
OVR="$(SEMGREP_CONFIGS='--config p/custom' $SCAN doctor 2>/dev/null)"
printf '%s' "$OVR" | grep -q 'semgrep cfg --config p/custom (from env/conf)' && ok "cfg: env override wins" || no "cfg: env override ignored"
# Robust cleanup: `git rm` fails silently on staged-but-uncommitted paths (no -f), leaving them
# tracked. Remove the working tree then `git add -A` the path to stage its removal from the index.
rm -rf stack; git -c user.email=e2e@test -c user.name=e2e add -A stack >/dev/null 2>&1

echo "-- stack fixture matrix (per-stack detection isolation) --"
# Materialize each benign fixture (tests/fixtures/stacks/<stack>/*.tpl, .tpl stripped) into a
# fresh throwaway git repo and assert scan.sh detects the right packs/dimensions — in isolation.
KIT_FX="$TARGET/tools/security-audit-kit/tests/fixtures/stacks"
if [ -d "$KIT_FX" ]; then
  # doctor output of a fresh repo populated from fixture stack $1
  doctor_of(){
    local src="$KIT_FX/$1" dst; dst="$(mktemp -d)"
    ( cd "$src" && find . -type f -name '*.tpl' | while IFS= read -r f; do
        out="$dst/${f#./}"; out="${out%.tpl}"; mkdir -p "$(dirname "$out")"; cp "$f" "$out"; done )
    ( cd "$dst" && git init -q \
        && git -c user.email=e2e@test -c user.name=e2e add -A >/dev/null 2>&1 \
        && git -c user.email=e2e@test -c user.name=e2e commit -qm init >/dev/null 2>&1
      bash "$TARGET/tools/security-audit-kit/scan.sh" doctor 2>/dev/null )
    rm -rf "$dst"
  }
  D="$(doctor_of django)"
  { printf '%s' "$D" | grep -q 'p/python' && printf '%s' "$D" | grep -q 'p/django'; } \
    && ok "matrix django: python+django packs" || no "matrix django: python+django packs"
  D="$(doctor_of react)"
  { printf '%s' "$D" | grep -q 'p/javascript' && printf '%s' "$D" | grep -q 'p/react'; } \
    && ok "matrix react: js+react packs" || no "matrix react: js+react packs"
  D="$(doctor_of terraform)"
  printf '%s' "$D" | grep -qi 'terraform' && ok "matrix terraform: detected" || no "matrix terraform: detected"
  { printf '%s' "$D" | grep -q 'p/python' || printf '%s' "$D" | grep -q 'p/javascript'; } \
    && no "matrix terraform: leaked a language pack" || ok "matrix terraform: base-only packs"
  D="$(doctor_of monorepo)"
  { printf '%s' "$D" | grep -q 'p/python' && printf '%s' "$D" | grep -q 'p/react'; } \
    && ok "matrix monorepo: python+react packs" || no "matrix monorepo: python+react packs"
else
  skip "stack fixture matrix (fixtures dir missing)"
fi

echo "-- integrity (verify / CHECKSUMS) --"
if [ -f tools/security-audit-kit/CHECKSUMS ]; then
  $SCAN verify >/dev/null 2>&1 && ok "verify: clean vendored copy passes" || no "verify: clean copy should pass"
  echo "malicious instructions" > tools/security-audit-kit/skills/evil.skill.md
  $SCAN verify >/dev/null 2>&1 && no "verify: rogue skill NOT detected" || ok "verify: rogue skill detected"
  rm -f tools/security-audit-kit/skills/evil.skill.md
  $SCAN verify >/dev/null 2>&1 && ok "verify: passes again after cleanup" || no "verify: should pass after cleanup"
  # Pin cross-check: a .kit-version that claims a release the vendored files aren't must FAIL,
  # even though CHECKSUMS itself still matches (the real-world case: an untracked pin file
  # outliving a checkout that reverted the vendored tree to an older release).
  KV=tools/security-audit-kit/.kit-version
  [ -f "$KV" ] && cp "$KV" "$KV.bak"
  # NOTE: capture first — `verify` exits non-zero here, and under `pipefail` a pipeline into grep
  # would inherit that failure and mask the assertion.
  printf 'v0.0.1 %s %s\n' "$(printf '0%.0s' $(seq 40))" "$(printf 'f%.0s' $(seq 64))" > "$KV"
  VOUT="$($SCAN verify 2>&1)"
  printf '%s' "$VOUT" | grep -q '^PIN ' && ok "verify: pin/content mismatch detected (digest)" || no "verify: pin digest mismatch NOT detected"
  # Legacy 2-field pin (no digest): falls back to comparing the tag against the CHANGELOG.
  printf 'v0.0.1 %s\n' "$(printf '0%.0s' $(seq 40))" > "$KV"
  VOUT="$($SCAN verify 2>&1)"
  printf '%s' "$VOUT" | grep -q '^PIN ' && ok "verify: pin/content mismatch detected (legacy label)" || no "verify: legacy pin mismatch NOT detected"
  # A branch pin has no version label to compare -> must stay quiet, not false-positive.
  printf 'main %s\n' "$(printf '0%.0s' $(seq 40))" > "$KV"
  $SCAN verify >/dev/null 2>&1 && ok "verify: branch pin does not false-positive" || no "verify: branch pin should pass"
  rm -f "$KV"; [ -f "$KV.bak" ] && mv "$KV.bak" "$KV"
  # pre-push runs verify BEFORE the scan: a hand-edited vendored kit must block the push, and
  # SKIP_SECURITY must still bypass. (Tampering used to be invisible until someone ran verify.)
  printf '\n# tampered by e2e\n' >> tools/security-audit-kit/scan.sh
  bash tools/security-audit-kit/hooks/pre-push >/dev/null 2>&1 && no "pre-push: tampered kit NOT blocked" || ok "pre-push: tampered kit blocked by verify"
  SKIP_SECURITY=1 bash tools/security-audit-kit/hooks/pre-push >/dev/null 2>&1 && ok "pre-push: SKIP_SECURITY bypass" || no "pre-push: bypass failed"
  perl -0pi -e 's/\n# tampered by e2e\n$//' tools/security-audit-kit/scan.sh
  $SCAN verify >/dev/null 2>&1 && ok "verify: passes after untampering" || no "verify: untamper restore failed"
else
  skip "verify tests (no CHECKSUMS in working tree yet)"
fi

echo "-- evidence.json (normalized per-finding record; schema: docs/schema/evidence.md) --"
if have python3; then
  EVD="$TARGET/docs/security/scan-findings/evidence.json"
  ESAR="$TARGET/docs/security/scan-findings/sarif"
  mkdir -p "$ESAR"
  # A hand-written SARIF exercising every mapping branch without needing the tools: a numeric
  # CVSS (osv), a level-only rule (semgrep), a container-mount path, and a duplicate result.
  cat > "$ESAR/osv.sarif" <<'SARIF'
{"runs":[{"tool":{"driver":{"name":"osv-scanner","rules":[
  {"id":"CVE-1","properties":{"security-severity":"9.1"}},
  {"id":"CVE-2","properties":{"security-severity":"4.2"}}]}},
 "results":[
  {"ruleId":"CVE-1","level":"warning","message":{"text":"crit dep"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///repo/requirements.txt"},"region":{"startLine":2}}}]},
  {"ruleId":"CVE-1","level":"warning","message":{"text":"crit dep"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///repo/requirements.txt"},"region":{"startLine":2}}}]},
  {"ruleId":"CVE-2","level":"warning","message":{"text":"med dep"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///repo/requirements.txt"},"region":{"startLine":3}}}]}]}]}
SARIF
  printf '{"command":"osv","exit_code":1,"raw_log":"r.log","dimensions":[{"name":"osv","exit_code":1,"status":"fail"}]}\n' \
    > "$TARGET/docs/security/scan-findings/summary.json"
  $SCAN evidence >/dev/null 2>&1
  python3 - "$EVD" <<'PY' && ok "evidence: severity normalized, CVSS passed through, dupes dropped, paths repo-relative" || no "evidence: schema/mapping wrong"
import json, sys
d = json.load(open(sys.argv[1]))
assert d["schema"] == "security-audit-kit/evidence@1", d["schema"]
f = {x["rule_id"]: x for x in d["findings"]}
assert len(d["findings"]) == 2, f"dupe not dropped: {len(d['findings'])}"          # 3 results -> 2
assert f["CVE-1"]["severity"] == "critical", f["CVE-1"]["severity"]                # 9.1 beats level=warning
assert f["CVE-2"]["severity"] == "medium", f["CVE-2"]["severity"]                  # 4.2
assert f["CVE-1"]["cvss"] == 9.1                                                   # osv = real CVSS
assert f["CVE-1"]["file"] == "requirements.txt", f["CVE-1"]["file"]                # /repo/ stripped
assert f["CVE-1"]["decision"] is None and f["CVE-1"]["confidence"] is None         # undecided until triage
assert d["counts"]["by_severity"]["critical"] == 1
assert d["counts"]["by_decision"]["undecided"] == 2
assert any("duplicate" in w for w in d["warnings"]), d["warnings"]
PY
  # Deterministic: same input, byte-identical output (the file is diffable by design).
  cp "$EVD" "$EVD.first"; $SCAN evidence >/dev/null 2>&1
  cmp -s "$EVD" "$EVD.first" && ok "evidence: rebuild is byte-identical" || no "evidence: output not deterministic"
  # Scope: a dimension that did NOT run must not contribute leftover SARIF findings.
  printf '{"command":"secret","exit_code":0,"raw_log":"r.log","dimensions":[{"name":"secret","exit_code":0,"status":"pass"}]}\n' \
    > "$TARGET/docs/security/scan-findings/summary.json"
  $SCAN evidence >/dev/null 2>&1
  python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d['counts']['total']==0 else 1)" "$EVD" \
    && ok "evidence: stale SARIF from another scope excluded" || no "evidence: stale findings leaked in"
  # kit.sarif: the judgment layer's findings, rendered as SARIF 2.1.0 for Code Scanning.
  KSAR="$ESAR/kit.sarif"
  cat > "$TARGET/docs/security/scan-findings/findings-$(date +%F).md" <<'MD'
# Security Scan Findings — test

## Round 1 (10:00) — scope: osv

| Tool | Sink (file:line) | Untrusted source | Sev | Conf | Decision | Action |
|------|------------------|------------------|-----|------|----------|--------|
| osv-scanner | requirements.txt:2 | vuln fn called on request body | HIGH | 0.9 | REAL | bumped |

## Round 2 — sec-sast-deep

| Sink (file:line) | Class | Untrusted source | Sev | Conf | Decision | Action |
|---|---|---|---|---|---|---|
| app/api.py:88 | horizontal-authz/IDOR | path param account_id | HIGH | 0.85 | REAL | ownership filter |

### Suppressed
| Sink (file:line) | Class | Why | Conf |
|---|---|---|---|
| app/admin.py:9 | vertical-authz | @require_admin present | 0.4 |

### Kit issues (report only — never edit the vendored kit)
| Kit file:line | Observed | Expected | Effect on this scan |
|---|---|---|---|
| scan.sh:1 | example | example | none |
MD
  cat > "$ESAR/osv.sarif" <<'SARIF'
{"runs":[{"tool":{"driver":{"name":"osv-scanner","rules":[{"id":"CVE-1","properties":{"security-severity":"9.1"}}]}},
 "results":[{"ruleId":"CVE-1","level":"warning","message":{"text":"crit dep"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///repo/requirements.txt"},"region":{"startLine":2}}}]}]}]}
SARIF
  printf '{"command":"osv","exit_code":1,"raw_log":"r.log","dimensions":[{"name":"osv","exit_code":1,"status":"fail"}]}\n' \
    > "$TARGET/docs/security/scan-findings/summary.json"
  $SCAN evidence >/dev/null 2>&1
  python3 - "$EVD" "$KSAR" <<'PY' && ok "kit.sarif: judgment findings emitted as valid SARIF 2.1.0, scanner rows merged not duplicated" || no "kit.sarif: wrong shape"
import json, sys
ev = json.load(open(sys.argv[1]))
sarif = json.load(open(sys.argv[2]))
# The triage row is ABOUT the osv finding -> it fills that finding in, it does not add a second one.
osv = [f for f in ev["findings"] if f["dimension"] == "osv"]
assert len(osv) == 1 and osv[0]["decision"] == "real" and osv[0]["confidence"] == 0.9, osv
# Deep-pass findings have no scanner counterpart -> they become judgment findings.
judgment = [f for f in ev["findings"] if f["dimension"] == "judgment"]
assert len(judgment) == 2, [f["rule_id"] for f in judgment]           # 1 REAL + 1 suppressed
assert not any("kit issue" in (f["message"] or "").lower() for f in judgment)   # Kit issues skipped
assert sarif["version"] == "2.1.0" and "$schema" in sarif
run = sarif["runs"][0]
assert run["tool"]["driver"]["name"] == "SecurityAuditKit"
rules, results = run["tool"]["driver"]["rules"], run["results"]
assert len(results) == 2, len(results)                                # scanner findings NOT re-reported
for r in results:                                                     # SARIF invariants
    assert rules[r["ruleIndex"]]["id"] == r["ruleId"]
    assert r["level"] in ("error", "warning", "note", "none")
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert r["partialFingerprints"]["sakFindingId"]
supp = [r for r in results if "suppressions" in r]
assert len(supp) == 1 and supp[0]["suppressions"][0]["kind"] == "external"
assert supp[0]["suppressions"][0]["justification"]                    # on record, with a reason
PY
  # No judgment pass -> refuse to emit an empty run (uploading one closes every open kit alert).
  rm -f "$TARGET/docs/security/scan-findings/findings-$(date +%F).md"
  cp "$KSAR" "$KSAR.prev"; $SCAN evidence >/dev/null 2>&1
  cmp -s "$KSAR" "$KSAR.prev" && ok "kit.sarif: empty run refused (stale alerts not closed)" || no "kit.sarif: emitted an empty run"
  # HTML report: one self-contained file. The whole point is that it opens offline in five years,
  # so the test is about self-containment and escaping, not looks.
  cat > "$TARGET/docs/security/scan-findings/findings-$(date +%F).md" <<'MD'
# Security Scan Findings — test

## Round 2 — sec-sast-deep

| Sink (file:line) | Class | Untrusted source | Sev | Conf | Decision | Action |
|---|---|---|---|---|---|---|
| app/api.py:88 | horizontal-authz/IDOR | <script>alert(1)</script> | HIGH | 0.85 | REAL | ownership filter |

### Suppressed
| Sink (file:line) | Class | Why | Conf |
|---|---|---|---|
| app/admin.py:9 | vertical-authz | @require_admin present | 0.4 |
MD
  cat > "$ESAR/osv.sarif" <<'SARIF'
{"runs":[{"tool":{"driver":{"name":"osv-scanner","rules":[{"id":"CVE-1","properties":{"security-severity":"9.1"}}]}},
 "results":[{"ruleId":"CVE-1","level":"warning","message":{"text":"crit dep"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///repo/requirements.txt"},"region":{"startLine":2}}}]}]}]}
SARIF
  printf '{"command":"osv","exit_code":1,"raw_log":"r.log","dimensions":[{"name":"osv","exit_code":1,"status":"fail"}]}\n' \
    > "$TARGET/docs/security/scan-findings/summary.json"
  REPORT=html $SCAN evidence >/dev/null 2>&1
  RPT="$TARGET/docs/security/scan-findings/report-$(date +%F).html"
  python3 - "$RPT" <<'PY' && ok "report.html: self-contained, escaped, renders scanner + judgment findings" || no "report.html: wrong shape"
import re, sys
h = open(sys.argv[1], encoding="utf-8").read()
assert h.startswith("<!doctype html>")
# Self-contained: no script tags, and no src/href pointing anywhere but an in-page anchor.
assert "<script" not in h, "report must not carry JS"
external = [u for u in re.findall(r'(?:src|href)=["\'](?!#)([^"\']+)', h)]
assert not external, f"external references: {external}"
# Untrusted tool/skill text must be escaped — this is a security tool's own report.
assert "<script>alert(1)</script>" not in h and "&lt;script&gt;" in h
assert "@media print" in h, "must be printable to PDF"
# Renders BOTH halves: the scanner CVE and the deep-pass judgment finding, plus the suppressed one.
assert "CVE-1" in h and "requirements.txt" in h
assert "SAK-sast-deep-horizontal-authz-idor" in h and "app/api.py:88" in h
assert "Suppressed (1)" in h and "app/admin.py:9" in h
PY
  cp "$RPT" "$RPT.first"; REPORT=html $SCAN evidence >/dev/null 2>&1
  cmp -s "$RPT" "$RPT.first" && ok "report.html: re-render is byte-identical" || no "report.html: not deterministic"
  rm -f "$RPT" "$RPT.first" "$TARGET/docs/security/scan-findings/findings-$(date +%F).md"
  rm -f "$EVD.first" "$KSAR" "$KSAR.prev" "$ESAR/osv.sarif"
else skip "evidence.json tests (no python3)"; fi

echo "-- py-deps venv selection (this repo's .venv wins over an unrelated active one) --"
# Built OUTSIDE $TARGET on purpose: a requirements.txt inside the target repo would become a
# lockfile for the later osv/guarddog assertions.
VP="$(mktemp -d)"
mkdir -p "$VP/repo/.venv/bin" "$VP/foreign/bin"
printf '#!/bin/sh\nexit 0\n' > "$VP/repo/.venv/bin/python"; chmod +x "$VP/repo/.venv/bin/python"
printf '#!/bin/sh\nexit 0\n' > "$VP/foreign/bin/python";    chmod +x "$VP/foreign/bin/python"
echo 'requests==2.31.0' > "$VP/repo/requirements.txt"
( cd "$VP/repo" && git init -q . && git -c user.email=e2e@test -c user.name=e2e add -A >/dev/null 2>&1
  # An unrelated venv is active: the repo's own .venv must still be the one audited.
  DOUT="$(VIRTUAL_ENV="$VP/foreign" bash "$KIT_SRC/scan.sh" deps 2>&1 || true)"
  printf '%s' "$DOUT" | grep -q 'env \.venv' \
    && ok "py-deps: repo .venv wins over active VIRTUAL_ENV" || no "py-deps: wrong venv selected"
  printf '%s' "$DOUT" | grep -q 'is not this repo.s venv' \
    && ok "py-deps: mismatch warned" || no "py-deps: mismatch not warned" )
cd "$TARGET" || exit 1

echo "-- secret (gitleaks) + pre-commit gate --"
if docker_ok; then
  $SCAN secret >/dev/null 2>&1 && ok "secret: clean repo passes" || no "secret: clean repo should pass"
  # Assemble the test key so no contiguous AKIA+16 literal exists in any vendored file.
  AK="AKIA"; PLANT="${AK}1234567890ABCDEF"
  printf 'aws_key = "%s"\n' "$PLANT" > leak.txt
  git -c user.email=e2e@test -c user.name=e2e add leak.txt
  $SCAN staged >/dev/null 2>&1 && no "staged: planted secret NOT caught" || ok "staged: planted secret caught"
  bash tools/security-audit-kit/hooks/pre-commit >/dev/null 2>&1 && no "pre-commit: secret NOT blocked" || ok "pre-commit: secret blocked"
  SKIP_SECURITY=1 bash tools/security-audit-kit/hooks/pre-commit >/dev/null 2>&1 && ok "pre-commit: SKIP_SECURITY bypass" || no "pre-commit: bypass failed"
  git rm -q --cached leak.txt >/dev/null 2>&1; rm -f leak.txt
else
  skip "secret/pre-commit tests (docker unavailable)"
fi

echo "-- SAST (semgrep, fixture ERROR rule) --"
if have uvx || have pipx; then
  mkdir -p src
  export SEMGREP_CONFIGS="--config $TARGET/tools/security-audit-kit/tests/fixtures/semgrep-error.yaml"
  export SAST_PATHS="src"
  printf 'nothing here\n' > src/clean.txt
  $SCAN sast >/dev/null 2>&1 && ok "sast: clean passes" || no "sast: clean should pass"
  printf 'E2E_INSECURE_MARKER\n' > src/bad.txt
  $SCAN sast >/dev/null 2>&1 && no "sast: planted bug NOT caught" || ok "sast: planted bug caught"
  unset SEMGREP_CONFIGS SAST_PATHS
else
  skip "sast tests (uvx/pipx unavailable)"
fi

echo "-- summary.json --"
SUM="docs/security/scan-findings/summary.json"
if [ -f "$SUM" ]; then
  if have python3; then
    python3 -c "import json;json.load(open('$SUM'))" 2>/dev/null && ok "summary.json is valid JSON" || no "summary.json invalid"
  else skip "summary.json validity (no python3)"; fi
else no "summary.json not written"; fi

echo "-- bootstrap SHA-verify (--expect enforcement, offline local repo) --"
# Build a throwaway 'kit repo' (local, offline) with a tag, then bootstrap from it.
KITREPO="$(mktemp -d)"
if have rsync; then rsync -a --exclude '.git' "$KIT_SRC"/ "$KITREPO"/; else cp -R "$KIT_SRC"/. "$KITREPO"/ && rm -rf "$KITREPO/.git"; fi
( cd "$KITREPO" && git init -q && git -c user.email=e2e@test -c user.name=e2e add -A \
    && git -c user.email=e2e@test -c user.name=e2e commit -qm kit && git tag v0.0.0-test )
GOOD="$(git -C "$KITREPO" rev-parse HEAD)"
# wrong --expect -> must REFUSE and must NOT vendor
T1="$(mktemp -d)"; ( cd "$T1" && git init -q )
if ( cd "$T1" && KIT_REPO="$KITREPO" bash "$KIT_SRC/bootstrap.sh" v0.0.0-test --expect=deadbeefdeadbeef ) >/dev/null 2>&1; then
  no "bootstrap: wrong --expect should be REFUSED"
else
  [ -d "$T1/tools/security-audit-kit" ] && no "bootstrap: refused but still vendored" || ok "bootstrap: wrong --expect refused (no vendor)"
fi
# correct --expect -> succeeds + vendors
T2="$(mktemp -d)"; ( cd "$T2" && git init -q )
if ( cd "$T2" && KIT_REPO="$KITREPO" bash "$KIT_SRC/bootstrap.sh" v0.0.0-test --expect="$GOOD" ) >/dev/null 2>&1; then
  [ -f "$T2/tools/security-audit-kit/.kit-version" ] && ok "bootstrap: correct --expect succeeds + vendors" || no "bootstrap: succeeded but no vendor"
else
  no "bootstrap: correct --expect should succeed"
fi
rm -rf "$KITREPO" "$T1" "$T2"

echo "-- osv (OSV-Scanner optional dimension) --"
if docker_ok; then
  # target has no lockfiles -> osv-scanner exits 128 -> scan.sh maps that to a clean pass (0)
  $SCAN osv >/dev/null 2>&1 && ok "osv: wired + clean on a lockfile-less repo" || no "osv: should pass (exit 0) with no lockfiles"
else
  skip "osv (docker unavailable)"
fi

echo "-- guarddog (malicious/typosquat deps, optional) --"
if have uvx || have pipx; then
  # target has no requirements*.txt / package.json -> scan.sh skips cleanly (exit 0)
  $SCAN guarddog >/dev/null 2>&1 && ok "guarddog: wired + clean on a manifest-less repo" || no "guarddog: should pass (exit 0) with no manifests"
else
  skip "guarddog (uvx/pipx unavailable)"
fi

echo "-- zizmor (GitHub Actions security, optional) --"
if have uvx || have pipx; then
  $SCAN zizmor >/dev/null 2>&1 && ok "zizmor: clean pass when no workflows" || no "zizmor: should pass (exit 0) with no workflows"
  mkdir -p .github/workflows
  cat > .github/workflows/vuln.yml <<'YAML'
name: vuln
on: pull_request_target
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.pull_request.title }}"
YAML
  git -c user.email=e2e@test -c user.name=e2e add .github/workflows/vuln.yml >/dev/null 2>&1
  $SCAN zizmor >/dev/null 2>&1 && no "zizmor: planted vulnerable workflow NOT caught" || ok "zizmor: planted vulnerable workflow caught"
  git -c user.email=e2e@test -c user.name=e2e rm -q .github/workflows/vuln.yml >/dev/null 2>&1; rm -rf .github
else
  skip "zizmor (uvx/pipx unavailable)"
fi

echo "-- eval harness (dev-only skill regression) --"
if have node; then
  # run.sh MUST skip cleanly (exit 0) with no provider key — force the key empty so e2e never
  # triggers a live/costed eval even if the environment happens to have one set.
  ( cd tools/security-audit-kit && env ANTHROPIC_API_KEY= bash tests/eval/run.sh >/dev/null 2>&1 ) \
    && ok "eval: run.sh skips cleanly without a key" || no "eval: run.sh should exit 0 when key absent"
  # score.mjs metric math on a fixed mock (1 TP, 1 FN, 1 TN, 1 FP -> recall 50%, precision 50%)
  cat > eval_mock.json <<'JSON'
{"results":{"results":[
 {"vars":{"expected":"REAL"},"response":{"output":"{\"verdict\":\"REAL\"}"}},
 {"vars":{"expected":"REAL"},"response":{"output":"{\"verdict\":\"FP\"}"}},
 {"vars":{"expected":"FP"},"response":{"output":"{\"verdict\":\"FP\"}"}},
 {"vars":{"expected":"FP"},"response":{"output":"{\"verdict\":\"REAL\"}"}}
]}}
JSON
  node tools/security-audit-kit/tests/eval/score.mjs eval_mock.json 2>/dev/null | grep -q 'recall:     50.0%' \
    && ok "eval: score.mjs precision/recall math" || no "eval: score.mjs math wrong"
  rm -f eval_mock.json
else
  skip "eval harness (node unavailable)"
fi

echo "-- pre-commit framework integration --"
if have python3; then
  python3 -c "import yaml; d=yaml.safe_load(open('$KIT_SRC/.pre-commit-hooks.yaml')); ids={h['id'] for h in d}; assert {'sec-staged','sec-deps','sec-all'} <= ids; assert all(h['entry']=='scan.sh' for h in d)" 2>/dev/null \
    && ok ".pre-commit-hooks.yaml valid (sec-staged/deps/all -> scan.sh)" || no ".pre-commit-hooks.yaml invalid"
else skip ".pre-commit-hooks.yaml (no python3)"; fi
# install --skills-only: skills present, but core.hooksPath NOT set
TSO="$(mktemp -d)"
mkdir -p "$TSO/tools/security-audit-kit"
if have rsync; then rsync -a --exclude '.git' --exclude 'docs/security' "$KIT_SRC"/ "$TSO/tools/security-audit-kit"/; else cp -R "$KIT_SRC"/. "$TSO/tools/security-audit-kit"/; fi
( cd "$TSO" && git init -q && bash tools/security-audit-kit/install.sh --skills-only ) >/dev/null 2>&1
[ -f "$TSO/.claude/skills/sec-triage/SKILL.md" ] && ok "--skills-only: skills installed" || no "--skills-only: skills missing"
[ -z "$(git -C "$TSO" config core.hooksPath 2>/dev/null || true)" ] && ok "--skills-only: core.hooksPath NOT set" || no "--skills-only: hooksPath should be unset"
rm -rf "$TSO"

echo "-- worktree: gitleaks reaches history (no silent false-clean) --"
if docker_ok; then
  AK="AKIA"; PLANT="${AK}1234567890ABCDEF"
  printf 'k = "%s"\n' "$PLANT" > wt-leak.txt
  git -c user.email=e2e@test -c user.name=e2e add wt-leak.txt
  # --no-verify: the kit's own pre-commit hook (installed earlier) would otherwise block this.
  git -c user.email=e2e@test -c user.name=e2e commit --no-verify -qm "planted secret (worktree test)"
  WTBASE="$(mktemp -d)"; WT="$WTBASE/wt"
  git worktree add -q "$WT" -b e2e-wt >/dev/null 2>&1
  if ( cd "$WT" && bash tools/security-audit-kit/scan.sh secret ) >/dev/null 2>&1; then
    no "worktree: gitleaks MISSED the committed secret (silent false-clean)"
  else
    ok "worktree: gitleaks catches committed secret (history reachable)"
  fi
  git worktree remove --force "$WT" >/dev/null 2>&1; rm -rf "$WTBASE"; git branch -D e2e-wt >/dev/null 2>&1
else
  skip "worktree gitleaks (docker unavailable)"
fi

echo ""
echo "== e2e: $PASS passed, $FAIL failed =="
[ "$FAIL" -eq 0 ]
