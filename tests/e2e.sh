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

echo "-- repo-local custom rules (the consumer's own invariants) --"
mkdir -p semgrep-rules
cat > semgrep-rules/local.yaml <<'YAML'
rules:
  - id: local-gating-rule
    pattern: eval(...)
    message: local rule that must gate
    severity: ERROR
    languages: [python]
  - id: local-warning-rule
    pattern: print(...)
    message: local rule at WARNING — loaded but never gates
    severity: WARNING
    languages: [python]
YAML
# A rule's test fixture is material for the RULE, not the project's stack: this .py must not pull
# p/python into a repo that has no python (same class as the vendored-kit leak).
cat > semgrep-rules/local.py <<'PY'
# ruleid: local-gating-rule
eval("1")
# ok: local-gating-rule
int("1")
PY
git -c user.email=e2e@test -c user.name=e2e add semgrep-rules >/dev/null 2>&1
RDOC="$($SCAN doctor 2>/dev/null)"
printf '%s' "$RDOC" | grep -q 'semgrep cfg .*--config semgrep-rules' \
  && ok "rules: local rules appended to the stack-auto packs" || no "rules: local rules not composed"
printf '%s' "$RDOC" | grep -q 'semgrep cfg .*p/python' \
  && no "rules: a rule test fixture leaked into stack detection" || ok "rules: rule fixtures do not define the stack"
printf '%s' "$RDOC" | grep -q 'WILL NOT GATE: local-warning-rule' \
  && ok "rules: a non-ERROR rule is reported as non-gating" || no "rules: silent non-gating rule not surfaced"
printf '%s' "$RDOC" | grep -q 'rule tests present' \
  && ok "rules: rule tests detected" || no "rules: rule tests not detected"
# The whole point of the composition: adding one local rule must NOT cost you the registry packs.
ODOC="$(SEMGREP_CONFIGS='--config p/owasp-top-ten' $SCAN doctor 2>/dev/null)"
printf '%s' "$ODOC" | grep -q 'semgrep cfg .*p/owasp-top-ten --config semgrep-rules' \
  && ok "rules: local rules append even when SEMGREP_CONFIGS overrides the base" || no "rules: override drops local rules"
printf '%s' "$ODOC" | grep -q 'OVERRIDE is missing what stack-auto would add' \
  && ok "rules: a frozen override reports the packs it now misses" || no "rules: override rot not surfaced"
printf '%s' "$(SEMGREP_LOCAL_RULES=off $SCAN doctor 2>/dev/null)" | grep -q 'DISABLED by SEMGREP_LOCAL_RULES=off' \
  && ok "rules: off switch honoured" || no "rules: off switch ignored"
# Regression (v1.12.0 class): rule files shipped INSIDE the vendored kit must never become the
# consumer's rules — discovery is anchored at $ROOT literally, not by searching the tree.
mkdir -p tools/security-audit-kit/semgrep-rules
cp semgrep-rules/local.yaml tools/security-audit-kit/semgrep-rules/kit-own.yaml
printf '%s' "$($SCAN doctor 2>/dev/null)" | grep -q 'config tools/security-audit-kit/semgrep-rules' \
  && no "rules: the vendored kit's own rules reached the consumer" || ok "rules: vendored kit's own rules stay out of the consumer's config"
rm -rf tools/security-audit-kit/semgrep-rules
rm -rf semgrep-rules && git -c user.email=e2e@test -c user.name=e2e add -A >/dev/null 2>&1

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

echo "-- allowlist audit (decay detection) --"
# A suppression is an accepted risk with a shelf life. Both decay modes are silent and both fail
# in the dangerous direction: the suppression stays, the protection goes.
cat > .pip-audit-ignore <<'EOF'
GHSA-aaaa-bbbb-cccc  # unreachable; expires 2020-01-01 — fixed in 50.0.0
GHSA-dddd-eeee-ffff  # no fix yet; expires 2099-01-01
GHSA-9999-9999-9999  # no expiry recorded
EOF
cat > osv-scanner.toml <<'EOF'
[[IgnoredVulns]]
id = "GHSA-dddd-eeee-ffff"
ignoreUntil = 2099-01-01
EOF
AOUT="$($SCAN allowlist 2>&1)"; ARC=$?
[ "$ARC" -ne 0 ] && ok "allowlist: exits non-zero when a suppression has decayed" || no "allowlist: decay not gated"
printf '%s' "$AOUT" | grep -q 'EXPIRED GHSA-aaaa-bbbb-cccc' \
  && ok "allowlist: an expired deferral is named with its date" || no "allowlist: expired entry not caught"
printf '%s' "$AOUT" | grep -q 'GHSA-aaaa-bbbb-cccc is suppressed in .pip-audit-ignore but not in osv-scanner.toml' \
  && ok "allowlist: cross-path gap reported (an entry in one path does not silence the others)" || no "allowlist: cross-path gap missed"
# The id present in BOTH files must not be reported — a detector that cries wolf stops being read.
printf '%s' "$AOUT" | grep -q 'GHSA-dddd-eeee-ffff is suppressed' \
  && no "allowlist: false positive on an id covered in both paths" || ok "allowlist: no false positive on a fully-covered id"
printf '%s' "$AOUT" | grep -q 'with no expiry' \
  && ok "allowlist: entries with no expiry are counted" || no "allowlist: missing-expiry count absent"
# .trivyignore.yaml also carries misconfig checks (AVD-/DS-/KSV-) and license ids. pip-audit can
# never report those, so comparing them manufactures a gap that cannot exist — the noise that made
# two of the first three real-repo warnings worthless.
cat > .trivyignore.yaml <<'EOF'
misconfigurations:
  - id: AVD-DS-0002
licenses:
  - id: LGPL-3.0-or-later
EOF
TOUT="$($SCAN allowlist 2>&1)"
printf '%s' "$TOUT" | grep -qE '(AVD-DS-0002|LGPL-3.0-or-later) is suppressed' \
  && no "allowlist: non-advisory ids (misconfig/license) compared across paths" \
  || ok "allowlist: only package-advisory namespaces are cross-checked (no misconfig/license noise)"
rm -f .trivyignore.yaml
# In sync + unexpired -> clean and quiet.
cat > .pip-audit-ignore <<'EOF'
GHSA-dddd-eeee-ffff  # no fix yet; expires 2099-01-01
EOF
$SCAN allowlist >/dev/null 2>&1 && ok "allowlist: clean when every path agrees and nothing expired" || no "allowlist: false alarm on a clean set"
printf '%s' "$($SCAN doctor 2>/dev/null)" | grep -q 'audit: nothing expired' \
  && ok "allowlist: doctor carries a one-line verdict" || no "allowlist: doctor summary missing"
rm -f .pip-audit-ignore osv-scanner.toml

echo "-- stack-aware semgrep config --"
# A bash/markdown repo -> base packs only (owasp-top-ten + secrets), no language packs.
DOC="$($SCAN doctor 2>/dev/null)"
printf '%s' "$DOC" | grep -q 'semgrep cfg .*owasp-top-ten.*secrets.*(stack-auto' && ok "cfg: base packs auto" || no "cfg: base packs missing"
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
printf '%s' "$OVR" | grep -q 'semgrep cfg --config p/custom (base from env/conf' && ok "cfg: env override wins" || no "cfg: env override ignored"
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
    && git -c user.email=e2e@test -c user.name=e2e commit -qm kit && git tag v1.18.0-rc.99 )
GOOD="$(git -C "$KITREPO" rev-parse HEAD)"
# wrong --expect -> must REFUSE and must NOT vendor
T1="$(mktemp -d)"; ( cd "$T1" && git init -q )
if ( cd "$T1" && KIT_REPO="$KITREPO" bash "$KIT_SRC/bootstrap.sh" v1.18.0-rc.99 --expect=deadbeefdeadbeef ) >/dev/null 2>&1; then
  no "bootstrap: wrong --expect should be REFUSED"
else
  [ -d "$T1/tools/security-audit-kit" ] && no "bootstrap: refused but still vendored" || ok "bootstrap: wrong --expect refused (no vendor)"
fi
# correct --expect -> succeeds + vendors
T2="$(mktemp -d)"; ( cd "$T2" && git init -q )
if ( cd "$T2" && KIT_REPO="$KITREPO" bash "$KIT_SRC/bootstrap.sh" v1.18.0-rc.99 --expect="$GOOD" ) >/dev/null 2>&1; then
  [ -f "$T2/tools/security-audit-kit/.kit-version" ] && ok "bootstrap: correct --expect succeeds + vendors" || no "bootstrap: succeeded but no vendor"
else
  no "bootstrap: correct --expect should succeed"
fi
if [ -f "$T2/tools/security-audit-kit/.kit-version" ]; then
  awk 'NR==1{print $1, $2}' "$T2/tools/security-audit-kit/.kit-version" > "$T2/tools/security-audit-kit/.kit-version.legacy"
  mv "$T2/tools/security-audit-kit/.kit-version.legacy" "$T2/tools/security-audit-kit/.kit-version"
  if ( cd "$T2" && bash tools/security-audit-kit/scan.sh verify ) >/dev/null 2>&1; then
    ok "bootstrap: legacy two-field RC pin matches the released CHANGELOG version"
  else
    no "bootstrap: legacy two-field RC pin rejected the matching released files"
  fi
fi
rm -rf "$KITREPO" "$T1" "$T2"

echo "-- release metadata gate --"
RELTEST="$(mktemp -d)"
mkdir -p "$RELTEST/scripts"
cp "$KIT_SRC/scripts/release.sh" "$RELTEST/scripts/release.sh"
cp "$KIT_SRC/scan.sh" "$RELTEST/scan.sh"
awk '!done && $0 == "## [1.18.0]" {$0="## [Unreleased]"; done=1} {print}' \
  "$KIT_SRC/CHANGELOG.md" > "$RELTEST/CHANGELOG.md"
( cd "$RELTEST" && git init -q )
ROUT="$(cd "$RELTEST" && bash scripts/release.sh rc 1.18.0 --yes --no-gh 2>&1 || true)"
printf '%s' "$ROUT" | grep -q "CHANGELOG top version is '1.17.0', expected '1.18.0'" \
  && ok "release: refuses an RC while CHANGELOG still stops at Unreleased" \
  || no "release: accepted an RC without its CHANGELOG version section"
rm -rf "$RELTEST"

echo "-- osv (OSV-Scanner optional dimension) --"
if docker_ok; then
  # target has no lockfiles -> osv-scanner exits 128 -> scan.sh maps that to a clean pass (0)
  $SCAN osv >/dev/null 2>&1 && ok "osv: wired + clean on a lockfile-less repo" || no "osv: should pass (exit 0) with no lockfiles"
  # Reachability is opt-in and must NOT loosen the gate: call analysis drops uncalled vulns by
  # default, so it is always paired with --all-vulns — the finding set and exit code stay the same,
  # and what you gain is a called/uncalled signal for triage.
  printf '%s' "$($SCAN osv 2>&1)" | grep -q 'reachability:' \
    && no "osv: call analysis on by default (would silently shrink the finding set)" \
    || ok "osv: reachability is opt-in, off by default"
  printf '%s' "$(OSV_CALL_ANALYSIS=go $SCAN osv 2>&1)" | grep -q 'reachability: go, gate unchanged' \
    && ok "osv: OSV_CALL_ANALYSIS=go enables the reachability signal" || no "osv: call analysis not wired"
  # Rust call analysis works by RUNNING the dependency tree's build scripts. A scanner that
  # executes untrusted code to decide what to report is an own-goal — refuse unless asked twice.
  ROUT="$(OSV_CALL_ANALYSIS=rust $SCAN osv 2>&1)"; RRC=$?
  printf '%s' "$ROUT" | grep -q 'RUNS dependency build scripts' && [ "$RRC" -ne 0 ] \
    && ok "osv: rust call analysis refused (executes dependency build scripts)" || no "osv: rust refusal missing"
  printf '%s' "$(OSV_CALL_ANALYSIS=rust OSV_ALLOW_BUILD_SCRIPTS=1 $SCAN osv 2>&1)" | grep -q 'WILL execute' \
    && ok "osv: the rust override is allowed but says what it does" || no "osv: rust override missing"
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
  # Mock without confidence must print "not available" and NOT crash.
  node tools/security-audit-kit/tests/eval/score.mjs eval_mock.json 2>/dev/null | grep -q 'calibration: not available' \
    && ok "eval: score.mjs handles missing confidence gracefully" || no "eval: score.mjs crashes on no-confidence mock"
  # Calibration metrics: a mock with known confidence values must produce correct Brier, ECE, and
  # threshold-cost numbers. 6 cases: 2 TP@0.9, 1 TP@0.6(suppressed), 1 FN@0.3, 1 TN@0.1, 1 FP@0.8(noise).
  cat > eval_cal_mock.json <<'JSON'
{"results":{"results":[
 {"vars":{"expected":"REAL"},"response":{"output":"{\"verdict\":\"REAL\",\"confidence\":0.90}"}},
 {"vars":{"expected":"REAL"},"response":{"output":"{\"verdict\":\"REAL\",\"confidence\":0.95}"}},
 {"vars":{"expected":"REAL"},"response":{"output":"{\"verdict\":\"REAL\",\"confidence\":0.60}"}},
 {"vars":{"expected":"REAL"},"response":{"output":"{\"verdict\":\"FP\",\"confidence\":0.30}"}},
 {"vars":{"expected":"FP"},"response":{"output":"{\"verdict\":\"FP\",\"confidence\":0.10}"}},
 {"vars":{"expected":"FP"},"response":{"output":"{\"verdict\":\"REAL\",\"confidence\":0.80}"}}
]}}
JSON
  CALOUT="$(node tools/security-audit-kit/tests/eval/score.mjs eval_cal_mock.json 2>/dev/null)"
  printf '%s' "$CALOUT" | grep -q 'Brier:' \
    && printf '%s' "$CALOUT" | grep -q 'ECE:' \
    && printf '%s' "$CALOUT" | grep -q 'suppressed REALs: 1' \
    && printf '%s' "$CALOUT" | grep -q 'noise FPs:        1' \
    && ok "eval: score.mjs calibration metrics (Brier, ECE, threshold cost)" \
    || no "eval: score.mjs calibration metrics wrong"
  rm -f eval_cal_mock.json
  # Head-to-head: results MUST be grouped per provider — pooling two backends into one confusion
  # matrix reports a model that does not exist. A dead backend is "not measured", never 0%.
  cat > eval_matrix_mock.json <<'JSON'
{"results":{"results":[
 {"provider":{"label":"alpha"},"vars":{"expected":"REAL"},"response":{"output":"{\"verdict\":\"REAL\"}"}},
 {"provider":{"label":"alpha"},"vars":{"expected":"FP"},"response":{"output":"{\"verdict\":\"FP\"}"}},
 {"provider":{"label":"beta"},"vars":{"expected":"REAL"},"response":{"output":"{\"verdict\":\"FP\"}"}},
 {"provider":{"label":"beta"},"vars":{"expected":"FP"},"response":{"output":"{\"verdict\":\"FP\"}"}},
 {"provider":{"label":"dead"},"vars":{"expected":"REAL"},"failureReason":2,"error":"401"}
]}}
JSON
  MOUT="$(node tools/security-audit-kit/tests/eval/score.mjs eval_matrix_mock.json 2>/dev/null)"
  printf '%s' "$MOUT" | grep -q '3 backends' \
    && printf '%s' "$MOUT" | grep -qE 'alpha +2 +100\.0%' \
    && printf '%s' "$MOUT" | grep -qE 'beta +2 +.*0\.0%' \
    && printf '%s' "$MOUT" | grep -q 'dead.*not measured' \
    && ok "eval: head-to-head table scores each backend separately, dead one not scored 0%" \
    || no "eval: multi-provider scoring wrong"
  rm -f eval_matrix_mock.json
  rm -f eval_mock.json
else
  skip "eval harness (node unavailable)"
fi

echo "-- run lock (one writer for raw-<date>.log + summary.json) --"
LOCK=".git/security-audit-cache/scan.lock"
DAYLOG="docs/security/scan-findings/raw-$(date +%F).log"
$SCAN iac >/dev/null 2>&1
[ ! -d "$LOCK" ] && ok "lock: released after a normal run" || no "lock: left behind after a run"
python3 -c "import json;json.load(open('docs/security/scan-findings/summary.json'))" 2>/dev/null \
  && ok "lock: summary.json is valid JSON after a run" || no "lock: summary.json unreadable"
ls docs/security/scan-findings/summary.json.*.tmp >/dev/null 2>&1 \
  && no "lock: a summary temp file was left behind" \
  || ok "lock: no summary temp files left (write-then-rename)"

# A live holder must NOT make the second run skip its scan — it must scan into its own log, so
# the shared record stays coherent while the gate keeps working.
mkdir -p "$LOCK" && printf 'pid=%s date=%s cmd=all\n' "$$" "$(date +%FT%T)" > "$LOCK/owner"
BEFORE="$(wc -c < "$DAYLOG" 2>/dev/null || echo 0)"
LOCKOUT="$(SCAN_LOCK_WAIT=1 $SCAN iac 2>&1)"
AFTER="$(wc -c < "$DAYLOG" 2>/dev/null || echo 0)"
printf '%s' "$LOCKOUT" | grep -q 'SEPARATE log' \
  && [ "$BEFORE" = "$AFTER" ] \
  && ls docs/security/scan-findings/raw-"$(date +%F)".*.log >/dev/null 2>&1 \
  && ok "lock: a second run scans anyway, into its own log (shared log untouched)" \
  || no "lock: contention handling wrong (interleaved or scan skipped)"
rm -rf "$LOCK"; rm -f docs/security/scan-findings/raw-"$(date +%F)".*.log

# A lock directory outlives a killed scan; if that were permanent, every later run would be
# pushed out of the shared record forever.
mkdir -p "$LOCK" && printf 'pid=999999 date=2020-01-01T00:00:00 cmd=all\n' > "$LOCK/owner"
# Capture, then grep: `| grep -q` exits at the first match, the scan takes SIGPIPE and pipefail
# turns that into 141 — the exact false-negative shape v1.17.0 removed from the kit itself.
STALEOUT="$(SCAN_LOCK_WAIT=1 $SCAN iac 2>&1 || true)"
printf '%s' "$STALEOUT" | grep -q 'stale lock reclaimed' \
  && ok "lock: a dead owner's lock is reclaimed, not waited on" || no "lock: stale lock not reclaimed"
[ ! -d "$LOCK" ] && ok "lock: released again after the reclaiming run" || no "lock: not released after reclaim"
grep -q 'run lock' <($SCAN doctor 2>/dev/null) && ok "doctor: reports the run lock" || no "doctor: no run-lock line"

echo "-- pkgcheck: the pre-install gate (offline; fixtures, no network) --"
PKGCHECK="tools/security-audit-kit/lib/pkgcheck.py"
if have python3; then
  # 1) command parsing: what gets checked, and what must NOT be mistaken for a package name.
  PARSED="$(python3 $PKGCHECK --command 'npm i lodash react@18.2.0 && pip install requests==2.32.3 -r reqs.txt')"
  printf '%s' "$PARSED" | grep -q '^npm	lodash	$' \
    && printf '%s' "$PARSED" | grep -q '^npm	react	18.2.0$' \
    && printf '%s' "$PARSED" | grep -q '^pypi	requests	2.32.3$' \
    && ! printf '%s' "$PARSED" | grep -q 'reqs.txt' \
    && ok "pkgcheck: parses install targets, ignores -r <file> (that is scan.sh deps' job)" \
    || no "pkgcheck: install-target parsing wrong"
  # `npm install` with no argument installs the lockfile that is already in the repo, and a
  # non-install command must never reach the scanner — otherwise the hook taxes every Bash call.
  [ -z "$(python3 $PKGCHECK --command 'npm install && npm run build && git commit -m "install"')" ] \
    && ok "pkgcheck: bare 'npm install' / non-install commands yield no targets" \
    || no "pkgcheck: false-positive install target"

  # 2) verdicts. The fixtures are real guarddog 3.0.2 output shapes.
  echo '{"package":"lodahs","issues":1,"errors":{},"results":{"typosquatting":["lodash"],"capability-network-outbound":[]}}' \
    > gd_block.json
  # `--classify` exits 1 on BLOCK and 2 on INDETERMINATE by design (the hook reads that code),
  # and this harness runs with pipefail — so capture the verdict, never grep through the pipe.
  V_BLOCK="$(python3 $PKGCHECK --classify < gd_block.json || true)"
  printf '%s' "$V_BLOCK" | grep -q '^BLOCK	typosquatting' \
    && ok "pkgcheck: typosquat blocks" || no "pkgcheck: typosquat did not block"
  # The FP guard, and it is the load-bearing one: measured on 18 of the most-installed packages,
  # threat-* rules fire on django/pandas/next/webpack. Blocking on them would block `pip install
  # django`, the gate would be uninstalled, and an uninstalled gate protects nothing.
  echo '{"package":"pandas","issues":2,"errors":{},"results":{"threat-process-download-exec":[{"l":1}],"capability-process-spawn":[{"l":2}]}}' \
    > gd_note.json
  V_NOTE="$(python3 $PKGCHECK --classify < gd_note.json || true)"
  printf '%s' "$V_NOTE" | grep -q '^NOTE' \
    && ok "pkgcheck: threat-* rules that fire on popular packages report, never block" \
    || no "pkgcheck: over-blocking — a legitimate package would be refused"
  # guarddog prints "No risks found" and exits 0 when the DOWNLOAD failed; reporting that as
  # clean would be a lie the caller cannot detect.
  echo '{"package":"x","issues":0,"errors":{"download-package":"404"}}' > gd_err.json
  V_ERR="$(python3 $PKGCHECK --classify < gd_err.json || true)"
  printf '%s' "$V_ERR" | grep -q '^INDETERMINATE' \
    && ok "pkgcheck: a failed download is INDETERMINATE, never 'clean'" \
    || no "pkgcheck: failed download reported as clean"
  rm -f gd_block.json gd_note.json gd_err.json

  # 3) the hook: allow-by-default, and no scanner start-up for ordinary commands.
  HOOK="tools/security-audit-kit/hooks/pre-tool-install.sh"
  echo '{"tool_name":"Bash","tool_input":{"command":"git status"}}' | bash $HOOK >/dev/null 2>&1 \
    && ok "agent hook: non-install command passes (fast path)" || no "agent hook: fast path broken"
  echo 'not json at all' | bash $HOOK >/dev/null 2>&1 \
    && ok "agent hook: unreadable payload is allowed, never blocked" || no "agent hook: fails closed on junk"
else
  skip "pkgcheck (no python3)"
fi

echo "-- agent hook wiring (opt-in) --"
grep -q 'NOT wired' <($SCAN doctor 2>/dev/null) \
  && ok "doctor: says the pre-install window is unguarded when the hook is not wired" \
  || no "doctor: missing/incorrect agent-hook line"
if have python3; then
  TAH="$(mktemp -d)"
  mkdir -p "$TAH/tools/security-audit-kit"
  if have rsync; then rsync -a --exclude '.git' --exclude 'docs/security' "$KIT_SRC"/ "$TAH/tools/security-audit-kit"/; else cp -R "$KIT_SRC"/. "$TAH/tools/security-audit-kit"/; fi
  ( cd "$TAH" && git init -q && bash tools/security-audit-kit/install.sh --with-agent-hook \
      && bash tools/security-audit-kit/install.sh --with-agent-hook ) >/dev/null 2>&1
  python3 -c "
import json,sys
d=json.load(open('$TAH/.claude/settings.json'))
hooks=[h for m in d['hooks']['PreToolUse'] if m.get('matcher')=='Bash' for h in m['hooks']]
sys.exit(0 if len(hooks)==1 and 'pre-tool-install.sh' in hooks[0]['command'] else 1)" 2>/dev/null \
    && ok "--with-agent-hook: PreToolUse(Bash) wired once (idempotent on re-run)" \
    || no "--with-agent-hook: settings.json wiring wrong"
  [ -z "$(git -C "$TAH" config core.hooksPath >/dev/null 2>&1; python3 -c "import json;d=json.load(open('$TAH/.claude/settings.json'));print('' if d.get('hooks') else 'x')")" ] \
    && ok "--with-agent-hook: settings.json remains valid JSON" || no "--with-agent-hook: settings.json broken"
  rm -rf "$TAH"
else skip "--with-agent-hook (no python3)"; fi

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

echo "-- gate honesty: no file listing piped into 'grep -q' (SIGPIPE -> silent false negative) --"
# `git ls-files | grep -q` exits at the first match, git takes SIGPIPE, and pipefail turns the
# pipeline into 141 -> the `||` branch runs and the dimension reports "not present". It is
# size-dependent, so every small fixture passes. This static guard is the cheap half of the
# regression; the fixture repo below is the expensive half. Comments are stripped first — the
# scan.sh comment that NAMES the forbidden pattern must not read as an offence.
offenders="$(grep -hvE '^[[:space:]]*#' \
    "$KIT_SRC/scan.sh" "$KIT_SRC/hooks/pre-commit" "$KIT_SRC/hooks/pre-push" 2>/dev/null \
  | grep -E '\|[[:space:]]*grep -q' | grep -E 'ls-files|--name-only|find ' || true)"
[ -z "$offenders" ] && ok "no file listing is piped into 'grep -q'" \
  || no "a file listing is piped into 'grep -q' again: $offenders"

# The hook's manifest regex must be anchored per alternative: unanchored it fires on a template
# (requirements.txt.tpl) or a backup (package.json.bak) and runs a dependency scan nothing asked for.
mre="$(grep -m1 '^manifests=' "$KIT_SRC/hooks/pre-commit" | cut -d= -f2- | tr -d "'")"
grep -qE "$mre" <<<"tools/security-audit-kit/tests/fixtures/stacks/django/requirements.txt.tpl" \
  && no "hook regex: a .tpl template still triggers a dependency scan" \
  || ok "hook regex: requirements.txt.tpl does NOT trigger a dependency scan"
grep -qE "$mre" <<<"backend/requirements-dev.txt" \
  && ok "hook regex: a real requirements-dev.txt still triggers" \
  || no "hook regex: requirements-dev.txt no longer triggers (over-anchored)"
grep -qE "$mre" <<<"apps/web/package.json" \
  && ok "hook regex: a nested package.json still triggers" \
  || no "hook regex: nested package.json no longer triggers (over-anchored)"

echo "-- large repo: the gates must not silence themselves (SIGPIPE regression) --"
# 6000 tracked files is comfortably past a 64 KiB pipe buffer, which is what it takes to reproduce.
# Every manifest here sorts BEFORE the filler, so a `grep -q` would exit while git is still writing.
BIG="$(mktemp -d)"
(
  cd "$BIG" || exit 1
  git init -q .
  mkdir -p tools/security-audit-kit .github/workflows zz_filler
  if have rsync; then rsync -a --exclude '.git' "$KIT_SRC"/ tools/security-audit-kit/
  else cp -R "$KIT_SRC"/. tools/security-audit-kit/; rm -rf tools/security-audit-kit/.git; fi
  printf '[project]\nname = "big"\nversion = "0.1.0"\n' > pyproject.toml
  printf 'x = 1\n' > app.py
  # package.json with NO lockfile: enough for stack detection, and js-deps then skips it instead of
  # reaching for the network — the assertion is about detection at scale, not about npm.
  mkdir -p frontend && printf '{"name":"big-fe","version":"1.0.0"}\n' > frontend/package.json
  printf 'name: ok\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n' \
    > .github/workflows/ok.yml
  i=0; while [ "$i" -lt 6000 ]; do printf 'x\n' > "zz_filler/f$i.txt"; i=$((i+1)); done
  git -c user.email=e2e@test -c user.name=e2e add -A >/dev/null 2>&1
  git -c user.email=e2e@test -c user.name=e2e commit -qm big >/dev/null 2>&1
) || no "large-repo fixture could not be built"
BIGFILES="$(git -C "$BIG" ls-files | wc -l | tr -d ' ')"
[ "$BIGFILES" -gt 6000 ] && ok "large-repo fixture: $BIGFILES tracked files" \
  || no "large-repo fixture too small ($BIGFILES) to reproduce the bug"
BIGDOC="$(cd "$BIG" && bash tools/security-audit-kit/scan.sh doctor 2>&1)"
grep -q '^  python'         <<<"$BIGDOC" && ok "large repo: python detected"         || no "large repo: python NOT detected (SIGPIPE regression)"
grep -q '^  javascript'     <<<"$BIGDOC" && ok "large repo: javascript detected"     || no "large repo: javascript NOT detected (SIGPIPE regression)"
grep -q '^  github-actions' <<<"$BIGDOC" && ok "large repo: github-actions detected" || no "large repo: github-actions NOT detected (SIGPIPE regression)"
BIGDEPS="$(cd "$BIG" && bash tools/security-audit-kit/scan.sh deps 2>&1 || true)"
grep -q 'no Python project' <<<"$BIGDEPS" \
  && no "large repo: py-deps gate reported 'no Python project' with a tracked pyproject.toml" \
  || ok "large repo: py-deps gate reaches pip-audit"
if have uvx || have pipx; then
  BIGZIZ="$(cd "$BIG" && bash tools/security-audit-kit/scan.sh zizmor 2>&1 || true)"
  grep -q 'nothing to scan' <<<"$BIGZIZ" \
    && no "large repo: zizmor skipped itself with 12 workflow files present" \
    || ok "large repo: zizmor gate reaches the workflows"
else
  skip "large repo: zizmor gate (uvx/pipx unavailable)"
fi
rm -rf "$BIG"

echo "-- py-deps: a dimension that inspected nothing is INDETERMINATE, never a pass --"
# Measured failure this guards: on a containerised repo (no local .venv) pip-audit audited the empty
# ambient interpreter and printed "No known vulnerabilities found" while the committed
# requirements.txt carried 208 advisories, one CVSS 9.8.
PYR="$(mktemp -d)"
(
  cd "$PYR" || exit 1
  git init -q .
  mkdir -p tools/security-audit-kit
  if have rsync; then rsync -a --exclude '.git' "$KIT_SRC"/ tools/security-audit-kit/
  else cp -R "$KIT_SRC"/. tools/security-audit-kit/; rm -rf tools/security-audit-kit/.git; fi
  printf '[project]\nname = "noenv"\nversion = "0.1.0"\n' > pyproject.toml
  git -c user.email=e2e@test -c user.name=e2e add -A >/dev/null 2>&1
  git -c user.email=e2e@test -c user.name=e2e commit -qm py >/dev/null 2>&1
) || no "py-deps fixture could not be built"
# (a) pyproject.toml only, no venv: nothing can be read without building the project.
PYOUT="$(cd "$PYR" && bash tools/security-audit-kit/scan.sh deps 2>&1)"; PYRC=$?
grep -q 'INDETERMINATE' <<<"$PYOUT" && ok "py-deps: no venv + no readable manifest -> INDETERMINATE" \
  || no "py-deps: reported a verdict without inspecting anything"
[ "$PYRC" -eq 0 ] && ok "py-deps: INDETERMINATE does not block the gate" \
  || no "py-deps: INDETERMINATE blocked the gate (rc=$PYRC) — it is 'no opinion', not a finding"
PYSUM="$(cat "$PYR/docs/security/scan-findings/summary.json" 2>/dev/null || echo '')"
grep -q '"status": "indeterminate"' <<<"$PYSUM" \
  && ok "py-deps: summary.json records indeterminate, not pass" \
  || no "py-deps: summary.json still calls it pass/fail"
grep -q 'NOT a pass' <<<"$PYOUT" && ok "py-deps: the run says out loud that green is not coverage" \
  || no "py-deps: no INDETERMINATE banner on the run"
# (b) a committed requirements.txt IS readable — statically, by osv-scanner (pip-audit -r would
#     build a venv and install it, i.e. run the dependency tree's build scripts).
printf 'requests==2.19.0\n' > "$PYR/requirements.txt"
git -C "$PYR" -c user.email=e2e@test -c user.name=e2e add requirements.txt >/dev/null 2>&1
if docker_ok; then
  REQOUT="$(cd "$PYR" && bash tools/security-audit-kit/scan.sh deps 2>&1 || true)"
  grep -q 'osv-scanner reads the committed manifests' <<<"$REQOUT" \
    && ok "py-deps: no venv + a manifest -> read statically instead of reporting nothing" \
    || no "py-deps: a committed requirements.txt was still not inspected"
  grep -qE 'requests' <<<"$REQOUT" && ok "py-deps: the manifest's known-vulnerable pin is reported" \
    || no "py-deps: requests==2.19.0 (known vulnerable) was not reported"
else
  skip "py-deps: manifest fallback (docker unavailable)"
fi
rm -rf "$PYR"

echo "-- js-deps: audit the app, never a vendored asset, never block on 'cannot audit' --"
# The reported failure: the first tracked package.json was a checked-in fullcalendar asset with no
# lockfile, so npm audit exited ENOLOCK=1 and BLOCKED every commit that touched any manifest.
JSR="$(mktemp -d)"
(
  cd "$JSR" || exit 1
  git init -q .
  mkdir -p tools/security-audit-kit static/assets/plugins/fullcalendar
  if have rsync; then rsync -a --exclude '.git' "$KIT_SRC"/ tools/security-audit-kit/
  else cp -R "$KIT_SRC"/. tools/security-audit-kit/; rm -rf tools/security-audit-kit/.git; fi
  printf '{"name":"fullcalendar-vendored","version":"1.0.0"}\n' > static/assets/plugins/fullcalendar/package.json
  git -c user.email=e2e@test -c user.name=e2e add -A >/dev/null 2>&1
  git -c user.email=e2e@test -c user.name=e2e commit -qm js >/dev/null 2>&1
) || no "js-deps fixture could not be built"
JSOUT="$(cd "$JSR" && bash tools/security-audit-kit/scan.sh deps 2>&1)"; JSRC=$?
[ "$JSRC" -eq 0 ] && ok "js-deps: a lockfile-less vendored asset does not fail the gate" \
  || no "js-deps: gate failed (rc=$JSRC) on a vendored asset — the ENOLOCK block is back"
grep -q 'none is auditable' <<<"$JSOUT" && ok "js-deps: says WHY it audited nothing" \
  || no "js-deps: did not explain why nothing was audited"
grep -qE 'npm audit \(static/' <<<"$JSOUT" \
  && no "js-deps: audited the vendored asset directory" \
  || ok "js-deps: vendor path skipped"
JSOVR="$(cd "$JSR" && JS_DIRS=static/assets/plugins/fullcalendar bash tools/security-audit-kit/scan.sh deps 2>&1 || true)"
grep -q 'static/assets/plugins/fullcalendar' <<<"$JSOVR" \
  && ok "js-deps: JS_DIRS overrides the search" \
  || no "js-deps: JS_DIRS was ignored"
rm -rf "$JSR"

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
