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
# Hermetic: an active VIRTUAL_ENV inside a fixture repo would be audited by py-deps, and a foreign
# one adds an "ignored" warning, so the caller's shell would shape what the py-deps fixtures see.
# Tests that need one set it themselves.
unset VIRTUAL_ENV

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
grep -q 'semgrep cfg .*--config semgrep-rules' <<<"$RDOC" \
  && ok "rules: local rules appended to the stack-auto packs" || no "rules: local rules not composed"
grep -q 'semgrep cfg .*p/python' <<<"$RDOC" \
  && no "rules: a rule test fixture leaked into stack detection" || ok "rules: rule fixtures do not define the stack"
grep -q 'WILL NOT GATE: local-warning-rule' <<<"$RDOC" \
  && ok "rules: a non-ERROR rule is reported as non-gating" || no "rules: silent non-gating rule not surfaced"
grep -q 'rule tests present' <<<"$RDOC" \
  && ok "rules: rule tests detected" || no "rules: rule tests not detected"
# The whole point of the composition: adding one local rule must NOT cost you the registry packs.
ODOC="$(SEMGREP_CONFIGS='--config p/owasp-top-ten' $SCAN doctor 2>/dev/null)"
grep -q 'semgrep cfg .*p/owasp-top-ten --config semgrep-rules' <<<"$ODOC" \
  && ok "rules: local rules append even when SEMGREP_CONFIGS overrides the base" || no "rules: override drops local rules"
grep -q 'OVERRIDE is missing what stack-auto would add' <<<"$ODOC" \
  && ok "rules: a frozen override reports the packs it now misses" || no "rules: override rot not surfaced"
grep -q 'DISABLED by SEMGREP_LOCAL_RULES=off' <<<"$(SEMGREP_LOCAL_RULES=off $SCAN doctor 2>/dev/null)" \
  && ok "rules: off switch honoured" || no "rules: off switch ignored"
# Regression (v1.12.0 class): rule files shipped INSIDE the vendored kit must never become the
# consumer's rules — discovery is anchored at $ROOT literally, not by searching the tree.
mkdir -p tools/security-audit-kit/semgrep-rules
cp semgrep-rules/local.yaml tools/security-audit-kit/semgrep-rules/kit-own.yaml
grep -q 'config tools/security-audit-kit/semgrep-rules' <<<"$($SCAN doctor 2>/dev/null)" \
  && no "rules: the vendored kit's own rules reached the consumer" || ok "rules: vendored kit's own rules stay out of the consumer's config"
rm -rf tools/security-audit-kit/semgrep-rules
rm -rf semgrep-rules && git -c user.email=e2e@test -c user.name=e2e add -A >/dev/null 2>&1

echo "-- allowlist surface (doctor lists every suppression path) --"
# A dependency CVE is reported by py-deps + osv + container, so a suppression written to one file
# leaves the others firing. doctor has to make a half-applied suppression visible.
ADOC="$($SCAN doctor 2>/dev/null)"
grep -q 'allowlists (a suppression must cover every path' <<<"$ADOC" \
  && ok "doctor: allowlist section present" || no "doctor: allowlist section missing"
for f in .gitleaks.toml .pip-audit-ignore osv-scanner.toml .trivyignore.yaml .security-exclusions.md; do
  grep -q -- "$f" <<<"$ADOC" || { no "doctor: $f not listed"; break; }
done
grep -q 'osv-scanner.toml' <<<"$ADOC" && grep -q '.trivyignore.yaml' <<<"$ADOC" \
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
grep -q 'EXPIRED GHSA-aaaa-bbbb-cccc' <<<"$AOUT" \
  && ok "allowlist: an expired deferral is named with its date" || no "allowlist: expired entry not caught"
grep -q 'GHSA-aaaa-bbbb-cccc is suppressed in .pip-audit-ignore but not in osv-scanner.toml' <<<"$AOUT" \
  && ok "allowlist: cross-path gap reported (an entry in one path does not silence the others)" || no "allowlist: cross-path gap missed"
# The id present in BOTH files must not be reported — a detector that cries wolf stops being read.
grep -q 'GHSA-dddd-eeee-ffff is suppressed' <<<"$AOUT" \
  && no "allowlist: false positive on an id covered in both paths" || ok "allowlist: no false positive on a fully-covered id"
grep -q 'with no expiry' <<<"$AOUT" \
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
grep -qE '(AVD-DS-0002|LGPL-3.0-or-later) is suppressed' <<<"$TOUT" \
  && no "allowlist: non-advisory ids (misconfig/license) compared across paths" \
  || ok "allowlist: only package-advisory namespaces are cross-checked (no misconfig/license noise)"
rm -f .trivyignore.yaml
# In sync + unexpired -> clean and quiet.
cat > .pip-audit-ignore <<'EOF'
GHSA-dddd-eeee-ffff  # no fix yet; expires 2099-01-01
EOF
$SCAN allowlist >/dev/null 2>&1 && ok "allowlist: clean when every path agrees and nothing expired" || no "allowlist: false alarm on a clean set"
grep -q 'audit: nothing expired' <<<"$($SCAN doctor 2>/dev/null)" \
  && ok "allowlist: doctor carries a one-line verdict" || no "allowlist: doctor summary missing"
rm -f .pip-audit-ignore osv-scanner.toml

echo "-- stack-aware semgrep config --"
# A bash/markdown repo -> base packs only (owasp-top-ten + secrets), no language packs.
DOC="$($SCAN doctor 2>/dev/null)"
grep -q 'semgrep cfg .*owasp-top-ten.*secrets.*(stack-auto' <<<"$DOC" && ok "cfg: base packs auto" || no "cfg: base packs missing"
grep -q 'semgrep cfg.*p/python' <<<"$DOC" && no "cfg: python pack on non-python repo" || ok "cfg: no language pack on bash repo"
# Plant a python+react stack -> should pull p/python and p/react.
mkdir -p stack/backend stack/frontend
echo 'django==5.0' > stack/backend/requirements.txt
echo 'def x(): pass' > stack/backend/manage.py
printf '{ "dependencies": { "react": "^18" } }\n' > stack/package.json
echo 'export const A=1' > stack/frontend/app.tsx
git -c user.email=e2e@test -c user.name=e2e add stack >/dev/null 2>&1
DOC2="$($SCAN doctor 2>/dev/null)"
grep -q 'p/python' <<<"$DOC2" && grep -q 'p/django' <<<"$DOC2" \
  && grep -q 'p/react' <<<"$DOC2" && ok "cfg: stack packs auto-selected (python+django+react)" || no "cfg: stack packs not selected"
# Explicit override wins verbatim, nothing appended. Capture first (env-prefixed pipeline +
# pipefail is fragile) — same command-substitution form as the base/stack assertions above.
OVR="$(SEMGREP_CONFIGS='--config p/custom' $SCAN doctor 2>/dev/null)"
grep -q 'semgrep cfg --config p/custom (base from env/conf' <<<"$OVR" && ok "cfg: env override wins" || no "cfg: env override ignored"
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
  { grep -q 'p/python' <<<"$D" && grep -q 'p/django' <<<"$D"; } \
    && ok "matrix django: python+django packs" || no "matrix django: python+django packs"
  D="$(doctor_of react)"
  { grep -q 'p/javascript' <<<"$D" && grep -q 'p/react' <<<"$D"; } \
    && ok "matrix react: js+react packs" || no "matrix react: js+react packs"
  D="$(doctor_of terraform)"
  grep -qi 'terraform' <<<"$D" && ok "matrix terraform: detected" || no "matrix terraform: detected"
  { grep -q 'p/python' <<<"$D" || grep -q 'p/javascript' <<<"$D"; } \
    && no "matrix terraform: leaked a language pack" || ok "matrix terraform: base-only packs"
  D="$(doctor_of monorepo)"
  { grep -q 'p/python' <<<"$D" && grep -q 'p/react' <<<"$D"; } \
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
  grep -q '^PIN ' <<<"$VOUT" && ok "verify: pin/content mismatch detected (digest)" || no "verify: pin digest mismatch NOT detected"
  # Legacy 2-field pin (no digest): falls back to comparing the tag against the CHANGELOG.
  printf 'v0.0.1 %s\n' "$(printf '0%.0s' $(seq 40))" > "$KV"
  VOUT="$($SCAN verify 2>&1)"
  grep -q '^PIN ' <<<"$VOUT" && ok "verify: pin/content mismatch detected (legacy label)" || no "verify: legacy pin mismatch NOT detected"
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
  grep -q 'env \.venv' <<<"$DOUT" \
    && ok "py-deps: repo .venv wins over active VIRTUAL_ENV" || no "py-deps: wrong venv selected"
  grep -q 'is not this repo.s venv' <<<"$DOUT" \
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
# Cut the fixture the way scripts/release.sh cuts a tag: the newest CHANGELOG section carries the
# tag's version and CHECKSUMS is regenerated. Taking the working tree as-is would tie this test to
# whatever the CHANGELOG says today — an open `[Unreleased]` (every PR adds one) or a stale
# CHECKSUMS would fail the legacy-pin check below for a reason that has nothing to do with bootstrap.
# Fixed fixture version 99.0.0: never a real release, independent of the repo's state.
awk '!done && /^## \[/ { if ($0 ~ /^## \[Unreleased\]/) { print "## [99.0.0]"; done=1; next }
                          print "## [99.0.0]"; print ""; done=1 } { print }' \
  "$KITREPO/CHANGELOG.md" > "$KITREPO/CHANGELOG.md.e2e" && mv "$KITREPO/CHANGELOG.md.e2e" "$KITREPO/CHANGELOG.md"
# `checksums` lists tracked files -> stage first, then hash, then stage the new CHECKSUMS.
( cd "$KITREPO" && git init -q && git add -A && bash scan.sh checksums >/dev/null 2>&1 \
    && git -c user.email=e2e@test -c user.name=e2e add -A \
    && git -c user.email=e2e@test -c user.name=e2e commit -qm kit && git tag v99.0.0-rc.99 )
GOOD="$(git -C "$KITREPO" rev-parse HEAD)"
# wrong --expect -> must REFUSE and must NOT vendor
T1="$(mktemp -d)"; ( cd "$T1" && git init -q )
if ( cd "$T1" && KIT_REPO="$KITREPO" bash "$KIT_SRC/bootstrap.sh" v99.0.0-rc.99 --expect=deadbeefdeadbeef ) >/dev/null 2>&1; then
  no "bootstrap: wrong --expect should be REFUSED"
else
  [ -d "$T1/tools/security-audit-kit" ] && no "bootstrap: refused but still vendored" || ok "bootstrap: wrong --expect refused (no vendor)"
fi
# correct --expect -> succeeds + vendors
T2="$(mktemp -d)"; ( cd "$T2" && git init -q )
if ( cd "$T2" && KIT_REPO="$KITREPO" bash "$KIT_SRC/bootstrap.sh" v99.0.0-rc.99 --expect="$GOOD" ) >/dev/null 2>&1; then
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
echo "-- dogfood.sh: an RC tried on a consumer clone + a fresh install, one verdict --"
if [ -f "$T2/tools/security-audit-kit/.kit-version" ]; then
  ( cd "$T2" && git -c user.email=e2e@test -c user.name=e2e add -A >/dev/null 2>&1 \
      && git -c user.email=e2e@test -c user.name=e2e commit -qm consumer >/dev/null 2>&1 )
  T2HEAD="$(git -C "$T2" rev-parse HEAD)"
  dfsnap(){ (cd "$T2" && find . -path ./.git -prune -o -type f -print | sort | xargs cksum 2>/dev/null | cksum); }
  T2SNAP="$(dfsnap)"
  DFRC=0; DFOUT="$(KIT_REPO="$KITREPO" bash "$KIT_SRC/scripts/dogfood.sh" v99.0.0-rc.99 "$T2" 2>&1)" || DFRC=$?
  [ "$DFRC" -eq 0 ] && grep -q '(fresh install)' <<<"$DFOUT" && grep -q "$(basename "$T2")" <<<"$DFOUT" \
    && grep -q 'dogfood\] OK' <<<"$DFOUT" \
    && ok "dogfood: a clean consumer + a fresh install pass, in one table" || no "dogfood: clean run rc=$DFRC: $(tail -8 <<<"$DFOUT")"
  [ "$(git -C "$T2" rev-parse HEAD)" = "$T2HEAD" ] && [ "$(dfsnap)" = "$T2SNAP" ] \
    && ok "dogfood: the consumer repo itself is untouched (it works on a clone)" || no "dogfood: touched the consumer repo"
  # a consumer whose scan crashes a scanner must FAIL the dogfood (v1.20.0's SAST_PATHS bug shape)
  if have uvx || have pipx; then
    # shellcheck disable=SC2016  # a literal config line; scan.sh expands it
    printf ': "${SEMGREP_CONFIGS:=--config /nonexistent-dogfood-rules.yml}"\n' >> "$T2/.security-audit.conf"
    ( cd "$T2" && git -c user.email=e2e@test -c user.name=e2e commit -qam broken >/dev/null 2>&1 )
    DFRC=0; DFOUT="$(KIT_REPO="$KITREPO" bash "$KIT_SRC/scripts/dogfood.sh" v99.0.0-rc.99 "$T2" --no-fresh 2>&1)" || DFRC=$?
    [ "$DFRC" -eq 1 ] && grep -q 'error:sast' <<<"$DFOUT" && grep -q 'do not promote' <<<"$DFOUT" \
      && ok "dogfood: a scanner error on a consumer fails the dogfood" || no "dogfood: scanner error not caught (rc=$DFRC): $(tail -6 <<<"$DFOUT")"
  else skip "dogfood: scanner-error case (no uvx/pipx)"; fi
  # --check after the upgrade offering an OLDER tag = v1.20.0-rc.1's downgrade bug: dogfood FAILs it.
  # That bug no longer reproduces against real tags, so the classification rule is tested directly.
  DFRULE="$(bash -c 'eval "$(sed -n "/^release_key()/,/^}/p; /^older_than()/,/^}/p" "$1")"; older_than v1.0.0 v99.0.0-rc.99 && echo older; older_than v99.0.0 v99.0.0-rc.99 || echo newer-ok' _ "$KIT_SRC/scripts/dogfood.sh")"
  [ "$DFRULE" = "$(printf 'older\nnewer-ok')" ] \
    && ok "dogfood: an offer older than the installed tag is classed as a downgrade" || no "dogfood: downgrade rule wrong: $DFRULE"
else skip "dogfood (no vendored fixture)"; fi
rm -rf "$KITREPO" "$T1" "$T2"

echo "-- release metadata gate --"
RELTEST="$(mktemp -d)"
mkdir -p "$RELTEST/scripts"
cp "$KIT_SRC/scripts/release.sh" "$RELTEST/scripts/release.sh"
cp "$KIT_SRC/scan.sh" "$RELTEST/scan.sh"
# A synthetic CHANGELOG, not the kit's own: tied to a real version header, this check breaks the
# moment the next release is prepared (the header it rewrites is no longer the top one).
printf '# Changelog\n\n## [Unreleased]\n\n### Fixed\n- pending\n\n## [98.0.0] - 2026-01-01\n' \
  > "$RELTEST/CHANGELOG.md"
( cd "$RELTEST" && git init -q )
ROUT="$(cd "$RELTEST" && bash scripts/release.sh rc 99.0.0 --yes --no-gh 2>&1 || true)"
grep -q "CHANGELOG top version is '98.0.0', expected '99.0.0'" <<<"$ROUT" \
  && ok "release: refuses an RC while CHANGELOG still stops at Unreleased" \
  || no "release: accepted an RC without its CHANGELOG version section"
rm -rf "$RELTEST"

echo "-- F07: a stable release stops when CI cannot be verified (gh / API / runs / remote HEAD) --"
# A release repo built from this kit: main + a bare origin, in sync. gh is a shim answering with
# check-runs as TSV (name, status, conclusion, id). Nothing is tagged: only `preflight` runs.
F07="$(mktemp -d)"; F07S="$F07/shims"; mkdir -p "$F07S" "$F07/kit"
if have rsync; then rsync -a --exclude '.git' "$KIT_SRC"/ "$F07/kit"/; else cp -R "$KIT_SRC"/. "$F07/kit"/; fi
( cd "$F07/kit" && git init -q -b main 2>/dev/null || { git init -q && git checkout -q -b main; }
  git add -A && bash scan.sh checksums >/dev/null 2>&1 && git add -A \
  && git -c user.email=e2e@test -c user.name=e2e commit -qm kit \
  && git init -q --bare "$F07/origin.git" && git remote add origin "$F07/origin.git" && git push -q origin main ) >/dev/null 2>&1
# shellcheck disable=SC2016
printf '#!/bin/sh\n[ -n "$GH_OUT" ] && printf "%%b" "$GH_OUT"\nexit "${GH_RC:-0}"\n' > "$F07S/gh"; chmod +x "$F07S/gh"
f07ok(){ printf 'shellcheck\tcompleted\tsuccess\t11\npytest\tcompleted\tsuccess\t12\ne2e\tcompleted\tsuccess\t13\nchecksums\tcompleted\tsuccess\t14\nself-audit\tcompleted\tsuccess\t15\n'; }
# f07 <with-gh:1|0> [VAR=val ...] -- [release.sh args]: runs preflight, F07RC + "$F07/out"
f07(){ local g="$1"; shift; local envs=(); while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do envs+=("$1"); shift; done; shift
  local path="$F02SYS"; [ "$g" = 1 ] && path="$F07S:$F02SYS"
  (cd "$F07/kit" && env PATH="$path" "${envs[@]+"${envs[@]}"}" "$BASH" scripts/release.sh preflight --skip-e2e "$@" >"$F07/out" 2>&1); F07RC=$?; }
F02SYS="${F02SYS:-/usr/bin:/bin:/usr/sbin:/sbin}"
f07 1 GH_OUT="$(f07ok)" -- --stable
[ "$F07RC" -eq 0 ] && ok "F07: all required checks green -> stable preflight passes" || no "F07: green CI refused (rc=$F07RC): $(tail -3 "$F07/out")"
f07 0 -- --stable
[ "$F07RC" -ne 0 ] && grep -q 'gh' "$F07/out" && ok "F07: no gh -> a stable release stops" || no "F07: stable passed without gh"
f07 0 --
[ "$F07RC" -eq 0 ] && ok "F07: no gh on an RC preflight -> warning only (RC dogfood is the gate there)" || no "F07: RC refused without gh (rc=$F07RC)"
f07 1 GH_RC=1 -- --stable
[ "$F07RC" -ne 0 ] && grep -qi 'api' "$F07/out" && ok "F07: a failed GitHub API call stops a stable release" || no "F07: API failure passed"
f07 1 GH_OUT="" -- --stable
[ "$F07RC" -ne 0 ] && ok "F07: no check-runs at all stops a stable release" || no "F07: empty check-runs passed"
f07 1 GH_OUT="$(f07ok | sed 's/^e2e\tcompleted\tsuccess/e2e\tin_progress\t/')" -- --stable
[ "$F07RC" -ne 0 ] && grep -q 'pending\|in_progress' "$F07/out" && ok "F07: a pending required check stops a stable release" || no "F07: pending check passed"
f07 1 GH_OUT="$(f07ok | grep -v '^pytest')" -- --stable
[ "$F07RC" -ne 0 ] && grep -q "pytest" "$F07/out" && ok "F07: a missing required check stops a stable release" || no "F07: missing check passed"
# reruns: the NEWEST run (highest id) of a check decides, whatever order the API lists them in
f07 1 GH_OUT="$(f07ok)e2e\tcompleted\tfailure\t3\n" -- --stable
[ "$F07RC" -eq 0 ] && ok "F07: an old failed run, rerun green, does not block (newest run wins)" || no "F07: stale failure blocked (rc=$F07RC)"
f07 1 GH_OUT="e2e\tcompleted\tfailure\t99\n$(f07ok)" -- --stable
[ "$F07RC" -ne 0 ] && ok "F07: a newer failed rerun blocks, even listed first" || no "F07: newest failure ignored"
# the remote HEAD must be verifiable for a stable release
git -C "$F07/kit" remote remove origin >/dev/null 2>&1
f07 1 GH_OUT="$(f07ok)" -- --stable
[ "$F07RC" -ne 0 ] && grep -qi 'origin' "$F07/out" && ok "F07: an unverifiable remote HEAD stops a stable release" || no "F07: no origin passed (rc=$F07RC)"
git -C "$F07/kit" remote add origin "$F07/origin.git" >/dev/null 2>&1; git -C "$F07/kit" fetch -q origin >/dev/null 2>&1
# the exception: only with a reason, and the reason is said
f07 0 -- --stable --ci-unverified="GitHub API outage; CI green in the UI at 12:00"
[ "$F07RC" -eq 0 ] && grep -q 'GitHub API outage' "$F07/out" && ok "F07: --ci-unverified=<reason> lets it through and repeats the reason" \
  || no "F07: exception path (rc=$F07RC): $(tail -3 "$F07/out")"
f07 0 -- --stable --ci-unverified=
[ "$F07RC" -ne 0 ] && ok "F07: --ci-unverified with no reason is refused" || no "F07: empty reason accepted"
rm -rf "$F07"

echo "-- F25: upgrade notes reach the consumer (release gate, bootstrap --check, install re-run) --"
# release: a version section without "### Upgrade notes" is not cut (write "- None." if nothing breaks)
RELTEST="$(mktemp -d)"; mkdir -p "$RELTEST/scripts"
cp "$KIT_SRC/scripts/release.sh" "$RELTEST/scripts/release.sh"; cp "$KIT_SRC/scan.sh" "$RELTEST/scan.sh"
printf '# Changelog\n\n## [99.0.0] - 2026-01-01\n\n### Fixed\n- x\n\n## [98.0.0] - 2025-01-01\n' > "$RELTEST/CHANGELOG.md"
( cd "$RELTEST" && git init -q )
ROUT="$(cd "$RELTEST" && bash scripts/release.sh rc 99.0.0 --yes --no-gh 2>&1 || true)"
grep -q "no '### Upgrade notes' in \[99.0.0\]" <<<"$ROUT" \
  && ok "F25: release refuses a version with no Upgrade notes section" || no "F25: release cut a version without Upgrade notes"
rm -rf "$RELTEST"
# bootstrap --check: the upgrade notes between the pinned version and the latest tag
F25K="$(mktemp -d)"; F25C="$(mktemp -d)"
printf '%s\n' '# Changelog' '' '## [Unreleased]' '' '### Upgrade notes' '- unreleased-note' '' \
  '## [3.0.0] - 2026-03-01' '' '### Upgrade notes' '- breaking-A: summary schema 3' '' '### Fixed' '- fix-3' '' \
  '## [2.1.0] - 2026-02-01' '' '### Upgrade notes' '- note-B: new PY_VENV' '' \
  '## [2.0.0] - 2026-01-01' '' '### Upgrade notes' '- old-C' > "$F25K/CHANGELOG.md"
( cd "$F25K" && git init -q && git add -A && git -c user.email=e2e@test -c user.name=e2e commit -qm k \
    && git tag v2.0.0 && git tag v2.1.0-rc.1 && git tag v3.0.0-rc.1 && git tag v3.0.0 )
mkdir -p "$F25C/tools/security-audit-kit"; ( cd "$F25C" && git init -q )
printf 'v2.0.0 0000000000000000000000000000000000000000\n' > "$F25C/tools/security-audit-kit/.kit-version"
F25RC=0; F25OUT="$(cd "$F25C" && KIT_REPO="$F25K" bash "$KIT_SRC/bootstrap.sh" --check 2>&1)" || F25RC=$?
[ "$F25RC" -eq 1 ] && grep -q 'breaking-A' <<<"$F25OUT" && grep -q 'note-B' <<<"$F25OUT" \
  && ! grep -q 'old-C' <<<"$F25OUT" && ! grep -q 'unreleased-note' <<<"$F25OUT" \
  && ok "F25: --check shows the upgrade notes from the pin (excl.) up to the latest tag (incl.)" \
  || no "F25: --check upgrade notes wrong (rc=$F25RC): $(tr '\n' '|' <<<"$F25OUT")"
# sort -V orders v3.0.0-rc.1 AFTER v3.0.0: --check used to offer the final's own RC as "latest".
grep -q 'latest tag *: v3.0.0$' <<<"$F25OUT" \
  && ok "F25: --check offers the final release, not its older RC" || no "F25: --check offered an RC over its final: $(grep 'latest tag' <<<"$F25OUT")"
grep -q '\[3.0.0\]' <<<"$F25OUT" && grep -q '\[2.1.0\]' <<<"$F25OUT" \
  && ok "F25: each note is labelled with its version" || no "F25: notes not labelled by version"
printf 'v2.1.0-rc.1 0000000000000000000000000000000000000000\n' > "$F25C/tools/security-audit-kit/.kit-version"
F25OUT="$(cd "$F25C" && KIT_REPO="$F25K" bash "$KIT_SRC/bootstrap.sh" --check 2>&1 || true)"
grep -q 'note-B' <<<"$F25OUT" && grep -q 'breaking-A' <<<"$F25OUT" \
  && ok "F25: an RC pin also gets its own final version's notes" || no "F25: RC pin skipped its final's notes"
# An RC tester's pin is NEWER than the latest final (v1.20.0-rc.1 vs v1.19.1, found dogfooding
# v1.20.0-rc.1): --check said "UPDATE AVAILABLE -> v1.19.1", i.e. a downgrade.
F25K2="$(mktemp -d)"
printf '# Changelog\n\n## [4.0.0] - 2026-04-01\n\n### Upgrade notes\n- note-4\n\n## [3.0.0] - 2026-03-01\n\n### Upgrade notes\n- note-3\n' > "$F25K2/CHANGELOG.md"
( cd "$F25K2" && git init -q && git add -A && git -c user.email=e2e@test -c user.name=e2e commit -qm k \
    && git tag v3.0.0 && git tag v4.0.0-rc.1 )
printf 'v4.0.0-rc.1 0000000000000000000000000000000000000000\n' > "$F25C/tools/security-audit-kit/.kit-version"
F25RC=0; F25OUT="$(cd "$F25C" && KIT_REPO="$F25K2" bash "$KIT_SRC/bootstrap.sh" --check 2>&1)" || F25RC=$?
[ "$F25RC" -eq 0 ] && ! grep -q 'UPDATE AVAILABLE' <<<"$F25OUT" && grep -q 'ahead of the latest release' <<<"$F25OUT" \
  && ok "F25: an RC pin newer than the latest final is not told to 'update' (downgrade) to it" \
  || no "F25: RC pin offered a downgrade (rc=$F25RC): $(tr '\n' '|' <<<"$F25OUT")"
# F08: a newer RC is offered ONLY on the rc channel, chosen explicitly; the default (stable) says
# it exists and how to opt in, and never offers it.
( cd "$F25K2" && git tag v4.0.0-rc.2 )
F25RC=0; F25OUT="$(cd "$F25C" && KIT_REPO="$F25K2" bash "$KIT_SRC/bootstrap.sh" --check 2>&1)" || F25RC=$?
[ "$F25RC" -eq 0 ] && ! grep -q 'UPDATE AVAILABLE' <<<"$F25OUT" && grep -q 'v4.0.0-rc.2.*--channel=rc' <<<"$F25OUT" \
  && ok "F08: on the default (stable) channel a newer RC is mentioned, never offered" \
  || no "F08: stable channel offered an RC (rc=$F25RC): $(tr '\n' '|' <<<"$F25OUT")"
F25RC=0; F25OUT="$(cd "$F25C" && KIT_REPO="$F25K2" bash "$KIT_SRC/bootstrap.sh" --check --channel=rc 2>&1)" || F25RC=$?
[ "$F25RC" -eq 1 ] && grep -q 'UPDATE AVAILABLE -> .*v4.0.0-rc.2' <<<"$F25OUT" \
  && ok "F08: --channel=rc offers the newer RC" || no "F08: rc channel did not offer the newer RC (rc=$F25RC): $(tr '\n' '|' <<<"$F25OUT")"
F25RC=0; F25OUT="$(cd "$F25C" && KIT_CHANNEL=rc KIT_REPO="$F25K2" bash "$KIT_SRC/bootstrap.sh" --check 2>&1)" || F25RC=$?
[ "$F25RC" -eq 1 ] && ok "F08: KIT_CHANNEL=rc selects the rc channel too" || no "F08: KIT_CHANNEL ignored (rc=$F25RC)"
# ...and the final, once it exists (rc.10 > rc.2 numerically, final > every rc)
( cd "$F25K2" && git tag v4.0.0-rc.10 && git tag v4.0.0 )
F25OUT="$(cd "$F25C" && KIT_REPO="$F25K2" bash "$KIT_SRC/bootstrap.sh" --check 2>&1 || true)"
grep -q 'UPDATE AVAILABLE -> .*v4.0.0$' <<<"$F25OUT" && ok "F25: an RC pin is offered its final once released" \
  || no "F25: RC pin not offered the final: $(tr '\n' '|' <<<"$F25OUT")"
# a final pin at the latest final is up to date (exit 0)
printf 'v4.0.0 0000000000000000000000000000000000000000\n' > "$F25C/tools/security-audit-kit/.kit-version"
F25RC=0; (cd "$F25C" && KIT_REPO="$F25K2" bash "$KIT_SRC/bootstrap.sh" --check >/dev/null 2>&1) || F25RC=$?
[ "$F25RC" -eq 0 ] && ok "F25: a pin at the latest final is up to date" || no "F25: latest final pin rc=$F25RC"
# F08 card fixture: v1.17.0 / v1.18.0-rc.1 / v1.18.0 -> a v1.17.0 pin is offered v1.18.0, not the RC
F08K="$(mktemp -d)"; printf '# Changelog\n\n## [1.18.0] - 2026-01-01\n\n### Upgrade notes\n- None.\n' > "$F08K/CHANGELOG.md"
( cd "$F08K" && git init -q && git add -A && git -c user.email=e2e@test -c user.name=e2e commit -qm k \
    && git tag v1.17.0 && git tag v1.18.0-rc.1 && git tag v1.18.0 )
printf 'v1.17.0 0000000000000000000000000000000000000000\n' > "$F25C/tools/security-audit-kit/.kit-version"
F25RC=0; F25OUT="$(cd "$F25C" && KIT_REPO="$F08K" bash "$KIT_SRC/bootstrap.sh" --check 2>&1)" || F25RC=$?
[ "$F25RC" -eq 1 ] && grep -q 'UPDATE AVAILABLE -> .*v1.18.0$' <<<"$F25OUT" \
  && ok "F08: card fixture — the stable v1.18.0 is offered, not v1.18.0-rc.1" || no "F08: card fixture (rc=$F25RC): $(tr '\n' '|' <<<"$F25OUT")"
# unreachable repo / no tags: "cannot tell" (2), never confused with "update available" (1)
F25RC=0; (cd "$F25C" && KIT_REPO="$F08K.missing" bash "$KIT_SRC/bootstrap.sh" --check >/dev/null 2>&1) || F25RC=$?
[ "$F25RC" -eq 2 ] && ok "F08: an unreachable kit repo exits 2, not 1 (update available)" || no "F08: unreachable repo rc=$F25RC"
F08E="$(mktemp -d)"; ( cd "$F08E" && git init -q && git commit -q --allow-empty -m e -c user.email=e2e@test -c user.name=e2e 2>/dev/null \
  || git -c user.email=e2e@test -c user.name=e2e commit -q --allow-empty -m e )
F25RC=0; (cd "$F25C" && KIT_REPO="$F08E" bash "$KIT_SRC/bootstrap.sh" --check >/dev/null 2>&1) || F25RC=$?
[ "$F25RC" -eq 2 ] && ok "F08: a kit repo with no release tags exits 2" || no "F08: no-tags repo rc=$F25RC"
F25RC=0; (cd "$F25C" && KIT_REPO="$F08K" bash "$KIT_SRC/bootstrap.sh" --check --channel=beta >/dev/null 2>&1) || F25RC=$?
[ "$F25RC" -eq 2 ] && ok "F08: an unknown channel is refused" || no "F08: unknown channel rc=$F25RC"
rm -rf "$F25K" "$F25C" "$F25K2" "$F08K" "$F08E"
# install.sh re-run: an existing config is kept, and settings added since are named
F25I="$(mktemp -d)"
# shellcheck disable=SC2016  # the config line is a literal: its ${...} is for scan.sh to expand
( cd "$F25I" && git init -q && mkdir -p tools/security-audit-kit \
  && cp -R "$KIT_SRC"/. tools/security-audit-kit/ && rm -rf tools/security-audit-kit/.git \
  && printf ': "${SAST_PATHS:=src}"\n' > .security-audit.conf ) >/dev/null 2>&1
F25OUT="$(cd "$F25I" && bash tools/security-audit-kit/install.sh 2>&1 || true)"
# shellcheck disable=SC2016
grep -q 'PY_VENV' <<<"$F25OUT" && grep -q 'not in your .security-audit.conf' <<<"$F25OUT" \
  && [ "$(cat "$F25I/.security-audit.conf")" = ': "${SAST_PATHS:=src}"' ] \
  && ok "F25: install re-run keeps the config and names settings added since" || no "F25: install re-run did not report new settings"
grep -q 'new setting.*SAST_PATHS' <<<"$F25OUT" && no "F25: a setting already in the config was reported as new" \
  || ok "F25: settings already present are not reported"
rm -rf "$F25I"

echo "-- osv (OSV-Scanner optional dimension) --"
if docker_ok; then
  # target has no lockfiles -> osv-scanner exits 128 -> scan.sh maps that to a clean pass (0)
  $SCAN osv >/dev/null 2>&1 && ok "osv: wired + clean on a lockfile-less repo" || no "osv: should pass (exit 0) with no lockfiles"
  # Reachability is opt-in and must NOT loosen the gate: call analysis drops uncalled vulns by
  # default, so it is always paired with --all-vulns — the finding set and exit code stay the same,
  # and what you gain is a called/uncalled signal for triage.
  grep -q 'reachability:' <<<"$($SCAN osv 2>&1)" \
    && no "osv: call analysis on by default (would silently shrink the finding set)" \
    || ok "osv: reachability is opt-in, off by default"
  grep -q 'reachability: go, gate unchanged' <<<"$(OSV_CALL_ANALYSIS=go $SCAN osv 2>&1)" \
    && ok "osv: OSV_CALL_ANALYSIS=go enables the reachability signal" || no "osv: call analysis not wired"
  # Rust call analysis works by RUNNING the dependency tree's build scripts. A scanner that
  # executes untrusted code to decide what to report is an own-goal — refuse unless asked twice.
  ROUT="$(OSV_CALL_ANALYSIS=rust $SCAN osv 2>&1)"; RRC=$?
  grep -q 'RUNS dependency build scripts' <<<"$ROUT" && [ "$RRC" -ne 0 ] \
    && ok "osv: rust call analysis refused (executes dependency build scripts)" || no "osv: rust refusal missing"
  grep -q 'WILL execute' <<<"$(OSV_CALL_ANALYSIS=rust OSV_ALLOW_BUILD_SCRIPTS=1 $SCAN osv 2>&1)" \
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
  grep -q 'recall:     50.0%' <<<"$(node tools/security-audit-kit/tests/eval/score.mjs eval_mock.json 2>/dev/null)" \
    && ok "eval: score.mjs precision/recall math" || no "eval: score.mjs math wrong"
  # Mock without confidence must print "not available" and NOT crash.
  grep -q 'calibration: not available' <<<"$(node tools/security-audit-kit/tests/eval/score.mjs eval_mock.json 2>/dev/null)" \
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
  grep -q 'Brier:' <<<"$CALOUT" \
    && grep -q 'ECE:' <<<"$CALOUT" \
    && grep -q 'suppressed REALs: 1' <<<"$CALOUT" \
    && grep -q 'noise FPs:        1' <<<"$CALOUT" \
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
  grep -q '3 backends' <<<"$MOUT" \
    && grep -qE 'alpha +2 +100\.0%' <<<"$MOUT" \
    && grep -qE 'beta +2 +.*0\.0%' <<<"$MOUT" \
    && grep -q 'dead.*not measured' <<<"$MOUT" \
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
grep -q 'SEPARATE run directory' <<<"$LOCKOUT" \
  && [ "$BEFORE" = "$AFTER" ] \
  && ls docs/security/scan-findings/runs/*/raw.log >/dev/null 2>&1 \
  && ok "lock: a second run scans anyway, into its own log (shared log untouched)" \
  || no "lock: contention handling wrong (interleaved or scan skipped)"
rm -rf "$LOCK" docs/security/scan-findings/runs

# A lock directory outlives a killed scan; if that were permanent, every later run would be
# pushed out of the shared record forever.
mkdir -p "$LOCK" && printf 'pid=999999 date=2020-01-01T00:00:00 cmd=all\n' > "$LOCK/owner"
# Capture, then grep: `| grep -q` exits at the first match, the scan takes SIGPIPE and pipefail
# turns that into 141 — the exact false-negative shape v1.17.0 removed from the kit itself.
STALEOUT="$(SCAN_LOCK_WAIT=1 $SCAN iac 2>&1 || true)"
grep -q 'stale lock reclaimed' <<<"$STALEOUT" \
  && ok "lock: a dead owner's lock is reclaimed, not waited on" || no "lock: stale lock not reclaimed"
[ ! -d "$LOCK" ] && ok "lock: released again after the reclaiming run" || no "lock: not released after reclaim"
grep -q 'run lock' <($SCAN doctor 2>/dev/null) && ok "doctor: reports the run lock" || no "doctor: no run-lock line"

echo "-- run isolation: every run its own directory; only the lock holder publishes (F01) --"
# A separate throwaway repo, so the record here is ours alone. zizmor is the one SARIF-writing
# dimension whose tool runs through uvx -> a PATH shim stands in for it: no docker, no network,
# and each run stamps its own marker into the SARIF it writes, so we can tell whose file is where.
if have python3; then
  F01="$(mktemp -d)"; F01BIN="$(mktemp -d)"
  F01SCAN="bash $TARGET/tools/security-audit-kit/scan.sh"
  cat > "$F01BIN/uvx" <<'SH'
#!/bin/sh
[ -n "${F01_SLEEP:-}" ] && sleep "$F01_SLEEP"
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"zizmor","rules":[]}},"results":[],"properties":{"marker":"%s"}}]}\n' "${F01_MARK:-none}"
SH
  chmod +x "$F01BIN/uvx"
  (
    cd "$F01" || exit 1
    git init -q && mkdir -p .github/workflows && printf 'on: push\njobs: {}\n' > .github/workflows/ci.yml
    git -c user.email=e2e@test -c user.name=e2e add -A && git -c user.email=e2e@test -c user.name=e2e commit -qm init
  )
  F01FD="$F01/docs/security/scan-findings"
  F01LOCK="$F01/.git/security-audit-cache/scan.lock"
  # Run a scan in the F01 repo: f01run <marker> [extra env...]
  f01run(){ local m="$1"; shift; ( cd "$F01" && exec env PATH="$F01BIN:$PATH" SARIF=1 F01_MARK="$m" "$@" $F01SCAN zizmor ); }
  # One fingerprint over the whole shared record: summary, sarif/, evidence, report.
  f01snap(){ ( cd "$F01FD" && find summary.json evidence.json sarif report-*.html -type f 2>/dev/null \
    | LC_ALL=C sort | xargs cat 2>/dev/null ) | cksum; }
  f01runs(){ find "$F01FD/runs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' '; }

  # 1) An uncontended run publishes the shared record and leaves no staging behind.
  OUTA="$(f01run A REPORT=html 2>&1)"
  RIDA="$(printf '%s' "$OUTA" | sed -n 's/.*── run: \([0-9T]*-[0-9]*\).*/\1/p' | head -1)"
  grep -q '"marker":"A"' "$F01FD/sarif/zizmor.sarif" 2>/dev/null \
    && ok "isolation: the lock holder publishes its SARIF to the shared record" \
    || no "isolation: holder's SARIF missing from the shared record"
  [ -n "$RIDA" ] && python3 -c "import json,sys;d=json.load(open(sys.argv[1]));sys.exit(d.get('run_id')!=sys.argv[2])" \
      "$F01FD/summary.json" "$RIDA" 2>/dev/null \
    && ok "isolation: shared summary.json names the run that wrote it (run_id)" \
    || no "isolation: summary.json run_id missing or wrong (run '${RIDA:-?}')"
  [ -f "$F01FD/evidence.json" ] && ls "$F01FD"/report-*.html >/dev/null 2>&1 \
    && ok "isolation: evidence.json + HTML report published" || no "isolation: evidence/report not published"
  # The artifacts are transient; only the triage file is the record. A plain `git add -A` in a
  # consumer repo committed the raw log, SARIF, evidence and report (v1.19.0 dogfood).
  # The .gitignore itself is meant to be committed: everything else must stay invisible to git.
  ( cd "$F01" && git status --porcelain --untracked-files=all docs/security ) 2>/dev/null \
    | grep -v 'scan-findings/\.gitignore$' > "$F01.st"
  [ -f "$F01FD/.gitignore" ] && [ ! -s "$F01.st" ] \
    && ( cd "$F01" && ! git check-ignore -q docs/security/scan-findings/findings-2026-01-01.md ) \
    && ok "gitignore: scan artifacts stay out of git; findings-*.md stays trackable" \
    || no "gitignore: scan artifacts would be committed ($(wc -l < "$F01.st" | tr -d ' ') untracked)"
  printf '# mine\n' > "$F01FD/.gitignore"
  f01run K >/dev/null 2>&1
  [ "$(cat "$F01FD/.gitignore")" = "# mine" ] \
    && ok "gitignore: an existing scan-findings/.gitignore is never overwritten" \
    || no "gitignore: the user's own .gitignore was overwritten"
  rm -f "$F01FD/.gitignore" "$F01.st"; f01run K >/dev/null 2>&1
  # No judgment findings is the common case: kit_sarif.py then deliberately writes nothing, and the
  # temp-then-rename must not turn that into an error. Paths the user reads are the final ones,
  # never a temp name or the holder's staging dir (rc.1 dogfood).
  ! grep -qE 'No such file|kit\.sarif not emitted|\.tmp|/publish/' <<<"$OUTA" \
    && ok "isolation: no rename error, temp name or staging path in the run's output" \
    || no "isolation: output leaks a staging/temp path or a rename error"
  [ "$(f01runs)" = 0 ] && ! ls "$F01FD"/*.tmp "$F01FD"/sarif/*.tmp >/dev/null 2>&1 \
    && ok "isolation: the holder leaves no run/staging dir or temp file behind" \
    || no "isolation: holder left staging behind"

  # 2) A run that cannot take the lock must not touch ONE byte of the shared record — summary,
  #    SARIF, evidence, report — and keeps a complete record of its own under runs/<id>/.
  SNAP="$(f01snap)"
  mkdir -p "$F01LOCK" && printf 'pid=%s date=%s cmd=all\n' "$$" "$(date +%FT%T)" > "$F01LOCK/owner"
  OUTB="$(f01run B SCAN_LOCK_WAIT=0 REPORT=html 2>&1)"
  RIDB="$(printf '%s' "$OUTB" | sed -n 's/.*── run: \([0-9T]*-[0-9]*\).*/\1/p' | head -1)"
  [ "$(f01snap)" = "$SNAP" ] \
    && ok "isolation: a lock-less run leaves summary/sarif/evidence/report untouched" \
    || no "isolation: a lock-less run CHANGED the shared record"
  RDB="$F01FD/runs/$RIDB"
  [ -n "$RIDB" ] && grep -q '"marker":"B"' "$RDB/sarif/zizmor.sarif" 2>/dev/null \
    && [ -f "$RDB/evidence.json" ] && [ -f "$RDB/raw.log" ] \
    && python3 -c "import json,sys;d=json.load(open(sys.argv[1]));sys.exit(d.get('run_id')!=sys.argv[2])" "$RDB/summary.json" "$RIDB" \
    && ok "isolation: the lock-less run keeps its own complete record in runs/<id>/" \
    || no "isolation: lock-less run's own record incomplete (runs/${RIDB:-?})"
  grep -q "runs/$RIDB" <<<"$OUTB" \
    && ok "isolation: the lock-less run says where its record went" || no "isolation: lock-less run did not name its run dir"

  # 3) evidence/report re-render the SHARED record; without the lock they must refuse, not write.
  EVRC=0; ( cd "$F01" && SCAN_LOCK_WAIT=0 $F01SCAN evidence ) >/dev/null 2>&1 || EVRC=$?
  RPRC=0; ( cd "$F01" && SCAN_LOCK_WAIT=0 $F01SCAN report ) >/dev/null 2>&1 || RPRC=$?
  [ "$EVRC" -ne 0 ] && [ "$RPRC" -ne 0 ] && [ "$(f01snap)" = "$SNAP" ] \
    && ok "isolation: evidence/report refuse to rewrite the shared record without the lock" \
    || no "isolation: evidence/report wrote without the lock (rc=$EVRC/$RPRC)"
  rm -rf "$F01LOCK"

  # 4) Two real runs overlapping: the holder publishes, the other stays in its own dir, ids differ.
  f01run D F01_SLEEP=4 > "$F01.d.out" 2>&1 &
  DPID=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -f "$F01LOCK/owner" ] && break; sleep 1; done
  f01run E SCAN_LOCK_WAIT=0 > "$F01.e.out" 2>&1
  wait "$DPID"
  RIDD="$(sed -n 's/.*── run: \([0-9T]*-[0-9]*\).*/\1/p' "$F01.d.out" | head -1)"
  RIDE="$(sed -n 's/.*── run: \([0-9T]*-[0-9]*\).*/\1/p' "$F01.e.out" | head -1)"
  [ -n "$RIDD" ] && [ -n "$RIDE" ] && [ "$RIDD" != "$RIDE" ] \
    && grep -q '"marker":"D"' "$F01FD/sarif/zizmor.sarif" \
    && grep -q '"marker":"E"' "$F01FD/runs/$RIDE/sarif/zizmor.sarif" 2>/dev/null \
    && python3 -c "import json,sys;d=json.load(open(sys.argv[1]));sys.exit(d.get('run_id')!=sys.argv[2])" "$F01FD/summary.json" "$RIDD" \
    && ok "isolation: overlapping runs — holder published, the other kept to runs/<id>, distinct ids" \
    || no "isolation: overlapping runs mixed their records (D=${RIDD:-?} E=${RIDE:-?})"
  rm -rf "$F01FD/runs"

  # 5) A cancelled holder (Ctrl-C reaches the whole process group) must not publish a half run,
  #    and must stop — not release the lock and carry on writing without it.
  SNAP="$(f01snap)"
  # Not via f01run: a backgrounded function is a subshell of its own, and `wait` would return as
  # soon as THAT dies, before scan.sh has finished cleaning up. Here the job's pid is scan.sh.
  set -m
  ( cd "$F01" && exec env PATH="$F01BIN:$PATH" SARIF=1 F01_MARK=C F01_SLEEP=20 $F01SCAN zizmor ) > "$F01.c.out" 2>&1 &
  CPID=$!
  set +m
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -f "$F01LOCK/owner" ] && break; sleep 1; done
  kill -TERM -- "-$CPID" 2>/dev/null
  CRC=0; wait "$CPID" || CRC=$?
  [ "$CRC" -ne 0 ] && [ "$(f01snap)" = "$SNAP" ] \
    && ok "isolation: a cancelled run exits non-zero and leaves the last record intact" \
    || no "isolation: a cancelled run published or carried on (rc=$CRC)"
  [ ! -d "$F01LOCK" ] && [ "$(f01runs)" = 0 ] \
    && ok "isolation: a cancelled holder releases its lock and drops its staging" \
    || no "isolation: cancelled holder left its lock or staging behind"
  grep -q 'NEXT STEP' "$F01.c.out" \
    && no "isolation: a cancelled run went on to the end of the script" \
    || ok "isolation: a cancelled run stops where it was cancelled"

  echo "-- lock lifecycle: liveness, not age; release only your own token (F05) --"
  # f05lock <pid> <host> <pstart> <heartbeat-epoch> <token>: plant a lock as another run would.
  f05lock(){
    rm -rf "$F01LOCK"; mkdir -p "$F01LOCK"
    printf 'pid=%s\ntoken=%s\nhost=%s\npstart=%s\nstarted=%s\ncmd=all\n' "$1" "$5" "$2" "$3" "$4" > "$F01LOCK/owner"
    printf '%s\n' "$4" > "$F01LOCK/heartbeat"
  }
  f05token(){ sed -n 's/^token=//p' "$F01LOCK/owner" 2>/dev/null; }
  f05sum(){ python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get('run_id',''))" "$F01FD/summary.json" 2>/dev/null; }
  f05rid(){ sed -n 's/.*── run: \([0-9T]*-[0-9]*\).*/\1/p' | head -1; }
  NOW="$(date +%s)"; ME="$(hostname 2>/dev/null || uname -n)"
  MYSTART="$(ps -o lstart= -p $$ 2>/dev/null | sed 's/  *$//')"

  # 1) A live, long-running holder: lock dir hours old, but its process is alive, it is the same
  #    process (start time matches) and its heartbeat is fresh -> never reclaimed for age.
  f05lock "$$" "$ME" "$MYSTART" "$NOW" f05-live
  touch -t 202001010000 "$F01LOCK" "$F01LOCK/owner"
  OUT="$(f01run L SCAN_LOCK_WAIT=1 SCAN_LOCK_STALE_MIN=1 2>&1)"
  ! grep -q 'reclaimed' <<<"$OUT" && [ "$(f05token)" = f05-live ] \
    && ok "lock: a live long-running holder is not reclaimed for its age" \
    || no "lock: a LIVE holder's lock was taken because it was old"

  # 2) PID reuse: the pid is alive, but it is not the process that took the lock (start differs).
  if [ -n "$MYSTART" ]; then
    f05lock "$$" "$ME" "Thu Jan  1 00:00:00 2015" "$NOW" f05-reused
    OUT="$(f01run R SCAN_LOCK_WAIT=5 2>&1)"
    grep -q 'stale lock reclaimed (pid reused' <<<"$OUT" && [ "$(f05sum)" = "$(f05rid <<<"$OUT")" ] \
      && ok "lock: a reused pid is detected (start time) and the lock reclaimed" \
      || no "lock: pid reuse not detected"
  else
    skip "lock: pid reuse (ps -o lstart unavailable)"
  fi

  # 3) Another host (shared .git, container): its pid means nothing here, so liveness is the
  #    heartbeat alone — fresh: wait; silent past SCAN_LOCK_STALE_MIN: reclaim.
  f05lock 1 elsewhere.invalid "-" "$NOW" f05-remote
  OUT="$(f01run H SCAN_LOCK_WAIT=1 SCAN_LOCK_STALE_MIN=1 2>&1)"
  ! grep -q 'reclaimed' <<<"$OUT" && [ "$(f05token)" = f05-remote ] \
    && ok "lock: another host's lock with a fresh heartbeat is respected" \
    || no "lock: a remote holder with a live heartbeat was reclaimed"
  f05lock 1 elsewhere.invalid "-" "$((NOW - 7200))" f05-remote-dead
  OUT="$(f01run H SCAN_LOCK_WAIT=5 SCAN_LOCK_STALE_MIN=1 2>&1)"
  grep -q 'stale lock reclaimed (no heartbeat' <<<"$OUT" \
    && ok "lock: a silent heartbeat (>SCAN_LOCK_STALE_MIN) is reclaimed" \
    || no "lock: a dead remote holder's lock was not reclaimed"

  # 4) An unreadable owner: reclaimed once past a short grace (it may be a lock being created
  #    this instant), not after the full stale window — and never waited on forever.
  rm -rf "$F01LOCK"; mkdir -p "$F01LOCK"; printf 'garbage\n' > "$F01LOCK/owner"
  OUT="$(f01run G SCAN_LOCK_WAIT=1 2>&1)"
  ! grep -q 'reclaimed' <<<"$OUT" && grep -q 'SEPARATE run directory' <<<"$OUT" \
    && ok "lock: a just-created lock without a readable owner gets a grace period" \
    || no "lock: a lock being created was reclaimed under its creator"
  touch -t 202001010000 "$F01LOCK" "$F01LOCK/owner"
  T0="$(date +%s)"
  OUT="$(f01run G SCAN_LOCK_WAIT=30 2>&1)"
  T1="$(date +%s)"
  grep -q 'stale lock reclaimed (unreadable owner' <<<"$OUT" && [ $((T1 - T0)) -lt 20 ] \
    && [ "$(f05sum)" = "$(f05rid <<<"$OUT")" ] \
    && ok "lock: a corrupt lock is reclaimed promptly, not waited out" \
    || no "lock: corrupt lock waited on or not reclaimed ($((T1 - T0))s)"
  rm -rf "$F01LOCK"

  # 5) The holder keeps a heartbeat while it runs, and nothing of it outlives the run.
  f01run B F01_SLEEP=4 SCAN_LOCK_HEARTBEAT_SEC=1 > "$F01.b.out" 2>&1 &
  BPID=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -f "$F01LOCK/owner" ] && break; sleep 1; done
  sleep 3
  HB="$(cat "$F01LOCK/heartbeat" 2>/dev/null || echo 0)"
  AGE=$(( $(date +%s) - ${HB:-0} ))
  wait "$BPID"
  sleep 2
  [ "$AGE" -le 2 ] && [ ! -d "$F01LOCK" ] \
    && ok "lock: the holder heartbeats while running; the heartbeat stops with the run" \
    || no "lock: heartbeat stale (${AGE}s) or it outlived the run"

  # 6) A holder whose lock was taken over must neither delete the new owner's lock nor publish.
  SNAP="$(f01snap)"
  f01run T F01_SLEEP=4 > "$F01.t.out" 2>&1 &
  TPID=$!
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -f "$F01LOCK/owner" ] && break; sleep 1; done
  f05lock "$$" "$ME" "$MYSTART" "$(date +%s)" f05-usurper
  wait "$TPID"
  [ "$(f05token)" = f05-usurper ] && [ "$(f01snap)" = "$SNAP" ] && grep -q 'lock is no longer ours' "$F01.t.out" \
    && ok "lock: a holder releases and publishes only under its own token" \
    || no "lock: a run deleted another owner's lock or published without it"
  rm -rf "$F01LOCK"

  # 7) Three runs find the same dead lock at once: exactly one reclaims it, and the three then
  #    take the lock one after another — nobody runs lock-less, nobody holds it twice.
  mkdir -p "$F01LOCK" && printf 'pid=999999 date=2020-01-01T00:00:00 cmd=all\n' > "$F01LOCK/owner"
  for m in X Y Z; do f01run "$m" SCAN_LOCK_WAIT=30 F01_SLEEP=1 > "$F01.$m.out" 2>&1 & done
  wait
  RECL="$(cat "$F01".[XYZ].out | grep -c 'stale lock reclaimed')"
  SEP="$(cat "$F01".[XYZ].out | grep -c 'SEPARATE run directory')"
  [ "$RECL" = 1 ] && [ "$SEP" = 0 ] && [ ! -d "$F01LOCK" ] \
    && ok "lock: concurrent reclaim of one stale lock — one reclaim, three serialized holders" \
    || no "lock: concurrent reclaim raced (reclaims=$RECL, lock-less=$SEP)"

  rm -rf "$F01" "$F01BIN" "$F01".?.out
else
  skip "run isolation (python3 unavailable)"
fi

echo "-- pkgcheck: the pre-install gate (offline; fixtures, no network) --"
PKGCHECK="tools/security-audit-kit/lib/pkgcheck.py"
if have python3; then
  # 1) command parsing: what gets checked, and what must NOT be mistaken for a package name.
  PARSED="$(python3 $PKGCHECK --command 'npm i lodash react@18.2.0 && pip install requests==2.32.3 -r reqs.txt')"
  grep -q '^npm	lodash	$' <<<"$PARSED" \
    && grep -q '^npm	react	18.2.0$' <<<"$PARSED" \
    && grep -q '^pypi	requests	2.32.3$' <<<"$PARSED" \
    && ! grep -q 'reqs.txt' <<<"$PARSED" \
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
  grep -q '^BLOCK	typosquatting' <<<"$V_BLOCK" \
    && ok "pkgcheck: typosquat blocks" || no "pkgcheck: typosquat did not block"
  # The FP guard, and it is the load-bearing one: measured on 18 of the most-installed packages,
  # threat-* rules fire on django/pandas/next/webpack. Blocking on them would block `pip install
  # django`, the gate would be uninstalled, and an uninstalled gate protects nothing.
  echo '{"package":"pandas","issues":2,"errors":{},"results":{"threat-process-download-exec":[{"l":1}],"capability-process-spawn":[{"l":2}]}}' \
    > gd_note.json
  V_NOTE="$(python3 $PKGCHECK --classify < gd_note.json || true)"
  grep -q '^NOTE' <<<"$V_NOTE" \
    && ok "pkgcheck: threat-* rules that fire on popular packages report, never block" \
    || no "pkgcheck: over-blocking — a legitimate package would be refused"
  # guarddog prints "No risks found" and exits 0 when the DOWNLOAD failed; reporting that as
  # clean would be a lie the caller cannot detect.
  echo '{"package":"x","issues":0,"errors":{"download-package":"404"}}' > gd_err.json
  V_ERR="$(python3 $PKGCHECK --classify < gd_err.json || true)"
  grep -q '^INDETERMINATE' <<<"$V_ERR" \
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

echo "-- F10: install keeps the hooks a repo already has, says so, and can be undone --"
# f10repo <dir>: a repo with the kit vendored and one commit.
f10repo(){ mkdir -p "$1/tools/security-audit-kit"
  if have rsync; then rsync -a --exclude '.git' --exclude 'docs/security' "$KIT_SRC"/ "$1/tools/security-audit-kit"/; else cp -R "$KIT_SRC"/. "$1/tools/security-audit-kit"/; fi
  ( cd "$1" && git init -q && git -c user.email=e2e@test -c user.name=e2e commit -q --allow-empty -m init ); }
f10hook(){ printf '#!/bin/sh\necho "%s $*" >> "%s"\ncat >> "%s" 2>/dev/null\nexit %s\n' "$2" "$3" "$3" "${4:-0}" > "$1"; chmod +x "$1"; }
f10commit(){ (cd "$1" && echo "$2" > "f$2.txt" && git add "f$2.txt" && SKIP_SECURITY=1 git -c user.email=e2e@test -c user.name=e2e commit -qm "c$2") >/dev/null 2>&1; }
# (a) hooks in .git/hooks: kept running, after the kit's; install says what it found
T10="$(mktemp -d)"; f10repo "$T10"; M10="$T10/.markers"
f10hook "$T10/.git/hooks/pre-commit" user-pre-commit "$M10"; f10hook "$T10/.git/hooks/commit-msg" user-commit-msg "$M10"
f10hook "$T10/.git/hooks/pre-push" user-pre-push "$M10"
I10="$(cd "$T10" && bash tools/security-audit-kit/install.sh 2>&1)"
grep -q 'pre-commit' <<<"$I10" && grep -qi 'keep running' <<<"$I10" \
  && ok "F10: install names the repo's existing hooks and says they keep running" || no "F10: existing hooks not reported: $(grep -i hook <<<"$I10" | head -3)"
f10commit "$T10" 1
grep -q '^user-pre-commit' "$M10" && grep -q '^user-commit-msg' "$M10" \
  && ok "F10: after install the repo's own pre-commit and commit-msg still run" || no "F10: user hooks silenced: $(cat "$M10" 2>/dev/null)"
git init -q --bare "$T10/remote.git"; git -C "$T10" remote add origin "$T10/remote.git"
(cd "$T10" && SKIP_SECURITY=1 git push -q origin HEAD:refs/heads/main) >/dev/null 2>&1
grep -q '^user-pre-push origin' "$M10" && grep -q 'refs/heads/main' "$M10" \
  && ok "F10: a chained pre-push gets its args and the refs on stdin" || no "F10: pre-push chain lost args/stdin: $(cat "$M10")"
f10hook "$T10/.git/hooks/pre-commit" user-pre-commit "$M10" 1
f10commit "$T10" 2
if git -C "$T10" log --format=%s | grep -qx c2; then no "F10: a failing user pre-commit no longer blocks the commit"
elif [ "$(grep -c '^user-pre-commit' "$M10")" -ge 2 ]; then ok "F10: a failing user pre-commit still blocks the commit"
else no "F10: the user pre-commit did not run on the second commit"; fi
f10hook "$T10/.git/hooks/pre-commit" user-pre-commit "$M10"
# uninstall: hooksPath back to what it was (unset), user hooks untouched, unmodified skills removed,
# a modified one kept, config kept; a second run has nothing to undo
printf '\nlocal note\n' >> "$T10/.claude/skills/sec-triage/SKILL.md"
U10="$(cd "$T10" && bash tools/security-audit-kit/install.sh --uninstall 2>&1)"; U10RC=$?
[ "$U10RC" -eq 0 ] && [ -z "$(git -C "$T10" config core.hooksPath || true)" ] && [ -x "$T10/.git/hooks/pre-commit" ] \
  && ok "F10: uninstall restores the previous hooksPath (unset) and leaves the repo's hooks" || no "F10: uninstall hooks (rc=$U10RC): $(git -C "$T10" config core.hooksPath)"
[ ! -e "$T10/.claude/skills/sec-audit/SKILL.md" ] && [ -f "$T10/.claude/skills/sec-triage/SKILL.md" ] && grep -q 'sec-triage' <<<"$U10" \
  && [ -f "$T10/.security-audit.conf" ] \
  && ok "F10: uninstall removes unmodified skills, keeps a modified one (and says so), keeps the config" \
  || no "F10: uninstall skills/config: $(find "$T10/.claude/skills" -mindepth 1 -maxdepth 1 2>&1 | tr '\n' ' ')"
U10B="$(cd "$T10" && bash tools/security-audit-kit/install.sh --uninstall 2>&1)"; U10RC=$?
[ "$U10RC" -eq 0 ] && grep -qi 'nothing to undo' <<<"$U10B" && ok "F10: uninstall is idempotent" || no "F10: second uninstall (rc=$U10RC)"
f10commit "$T10" 3; grep -c '^user-pre-commit' "$M10" | grep -q '^[2-9]' && ok "F10: after uninstall the repo's own hooks run as before" || no "F10: user hooks broken after uninstall"
rm -rf "$T10"
# (b) a custom hooksPath (husky-style .husky/): chained, and restored by uninstall
T10="$(mktemp -d)"; f10repo "$T10"; M10="$T10/.markers"; mkdir -p "$T10/.husky"
f10hook "$T10/.husky/pre-commit" husky-pre-commit "$M10"; git -C "$T10" config core.hooksPath .husky
(cd "$T10" && bash tools/security-audit-kit/install.sh) >/dev/null 2>&1; f10commit "$T10" 1
grep -q '^husky-pre-commit' "$M10" && ok "F10: a custom core.hooksPath keeps running after install" || no "F10: custom hooksPath silenced"
(cd "$T10" && bash tools/security-audit-kit/install.sh --uninstall) >/dev/null 2>&1
[ "$(git -C "$T10" config core.hooksPath)" = ".husky" ] && ok "F10: uninstall restores a custom hooksPath" || no "F10: custom hooksPath not restored: $(git -C "$T10" config core.hooksPath)"
rm -rf "$T10"
# (c) pre-commit framework: its hook is kept, and the alternative (--skills-only) is named
T10="$(mktemp -d)"; f10repo "$T10"; M10="$T10/.markers"
printf 'repos: []\n' > "$T10/.pre-commit-config.yaml"
printf '#!/bin/sh\n# File generated by pre-commit: https://pre-commit.com\necho framework >> "%s"\n' "$M10" > "$T10/.git/hooks/pre-commit"; chmod +x "$T10/.git/hooks/pre-commit"
I10="$(cd "$T10" && bash tools/security-audit-kit/install.sh 2>&1)"; f10commit "$T10" 1
grep -qi 'pre-commit framework' <<<"$I10" && grep -q -- '--skills-only' <<<"$I10" && grep -q '^framework' "$M10" \
  && ok "F10: a pre-commit framework hook keeps running; the --skills-only alternative is named" || no "F10: pre-commit framework handling"
rm -rf "$T10"
# (d) a fresh repo: no question, no chain — the kit's hooks dir directly (as before)
T10="$(mktemp -d)"; f10repo "$T10"
I10="$(cd "$T10" && bash tools/security-audit-kit/install.sh </dev/null 2>&1)"; I10RC=$?
[ "$I10RC" -eq 0 ] && [ "$(git -C "$T10" config core.hooksPath)" = "tools/security-audit-kit/hooks" ] \
  && ok "F10: a fresh repo installs without a question, hooksPath -> the kit's hooks" || no "F10: fresh install (rc=$I10RC): $(git -C "$T10" config core.hooksPath)"
(cd "$T10" && bash tools/security-audit-kit/install.sh --uninstall) >/dev/null 2>&1
[ -z "$(git -C "$T10" config core.hooksPath || true)" ] && [ ! -d "$T10/.claude/skills/sec-audit" ] \
  && ok "F10: uninstall of a fresh install leaves no hooksPath and no kit skills" || no "F10: fresh uninstall left state"
rm -rf "$T10"
# (e) an install made before F10 has no record: hooksPath = the kit's dir and unedited kit skills
#     are recognisably the kit's, so they are undone; nothing else is touched
T10="$(mktemp -d)"; f10repo "$T10"
(cd "$T10" && bash tools/security-audit-kit/install.sh) >/dev/null 2>&1; rm -f "$T10/.git/security-audit-install.state"
U10="$(cd "$T10" && bash tools/security-audit-kit/install.sh --uninstall 2>&1)"
[ -z "$(git -C "$T10" config core.hooksPath || true)" ] && [ ! -d "$T10/.claude/skills/sec-audit" ] && grep -qi 'older' <<<"$U10" \
  && ok "F10: an install made before the record existed is still undone (hooksPath, unedited skills)" || no "F10: legacy uninstall: $U10"
rm -rf "$T10"

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
# F29 — an active VIRTUAL_ENV is this repo's environment only if it is a venv AND lives inside the
# repo. Measured failure: a developer shell with VIRTUAL_ENV=~/.pyenv/versions/3.12.9 (a global
# interpreter, no pyvenv.cfg) got the pyproject-only fixture above audited against that
# interpreter, and pip-audit's error HARD-blocked the gate instead of reporting INDETERMINATE.
F29="$(mktemp -d)"
mkdir -p "$F29/foreign/bin" "$F29/pyenv-global/bin"
printf '#!/bin/sh\nexit 0\n' > "$F29/foreign/bin/python"; chmod +x "$F29/foreign/bin/python"
printf 'home = /usr/bin\n' > "$F29/foreign/pyvenv.cfg"
printf '#!/bin/sh\nexit 0\n' > "$F29/pyenv-global/bin/python"; chmod +x "$F29/pyenv-global/bin/python"
f29(){ (cd "$PYR" && env "$@" bash tools/security-audit-kit/scan.sh deps 2>&1); }
# (c) no repo .venv + a REAL venv that belongs to another project -> not audited.
F29OUT="$(f29 VIRTUAL_ENV="$F29/foreign")"; F29RC=$?
grep -q 'INDETERMINATE' <<<"$F29OUT" && ! grep -q 'pip-audit --strict' <<<"$F29OUT" \
  && ok "F29: a foreign venv is not audited as this repo's" || no "F29: foreign venv audited as this repo's"
grep -q 'not inside this repo' <<<"$F29OUT" && ok "F29: says why the active venv was ignored" \
  || no "F29: foreign venv ignored silently"
[ "$F29RC" -eq 0 ] && ok "F29: foreign venv does not block the gate" || no "F29: foreign venv blocked (rc=$F29RC)"
# (d) no repo .venv + VIRTUAL_ENV pointing at an interpreter that is not a venv (pyenv global).
F29OUT="$(f29 VIRTUAL_ENV="$F29/pyenv-global")"; F29RC=$?
grep -q 'INDETERMINATE' <<<"$F29OUT" && ! grep -q 'pip-audit --strict' <<<"$F29OUT" \
  && ok "F29: a non-venv VIRTUAL_ENV is not audited" || no "F29: non-venv interpreter audited"
grep -q 'not a venv' <<<"$F29OUT" && ok "F29: says the VIRTUAL_ENV is not a venv" \
  || no "F29: non-venv VIRTUAL_ENV ignored silently"
[ "$F29RC" -eq 0 ] && ok "F29: pyenv-global case does not block (the measured rc=1)" \
  || no "F29: pyenv-global case blocked (rc=$F29RC)"
# (e) no repo .venv + an active venv INSIDE the repo (any name) -> it is the project's env. Passed
#     through the unresolved mktemp path: on macOS /var -> /private/var, ROOT is the resolved one.
mkdir -p "$PYR/venv/bin"; printf 'home = /usr/bin\n' > "$PYR/venv/pyvenv.cfg"
printf '#!/bin/sh\nexit 0\n' > "$PYR/venv/bin/python"; chmod +x "$PYR/venv/bin/python"
F29OUT="$(f29 VIRTUAL_ENV="$PYR/venv")"
grep -q 'pip-audit --strict.*env venv' <<<"$F29OUT" && ok "F29: an active venv inside the repo is audited" \
  || no "F29: the repo's own (non-.venv) venv was not selected"
rm -rf "$PYR/venv"
# (f) explicit opt-in: PY_VENV names the env to audit, wherever it lives, and the run says so.
F29OUT="$(f29 PY_VENV="$F29/foreign" VIRTUAL_ENV="$F29/pyenv-global")"
grep -q "pip-audit --strict.*env $F29/foreign.*PY_VENV" <<<"$F29OUT" \
  && ok "F29: PY_VENV opt-in audits the named env and says why" || no "F29: PY_VENV not honoured"
F29OUT="$(f29 PY_VENV="$F29/missing")"; F29RC=$?
grep -q 'PY_VENV.*no bin/python' <<<"$F29OUT" && [ "$F29RC" -ne 0 ] \
  && ok "F29: a broken PY_VENV is an error, not a silent fallback" || no "F29: broken PY_VENV accepted (rc=$F29RC)"
grep -q '"name": "py-deps", "exit_code": 1, "status": "error"' "$PYR/docs/security/scan-findings/summary.json" 2>/dev/null \
  && ok "F29+F02: a broken PY_VENV is recorded as error, not findings" || no "F29+F02: broken PY_VENV not recorded as error"
rm -rf "$F29"
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

echo "-- F02: a dimension's status says what happened; the gate is computed apart from it --"
# Before F02 "no docker -> skipped", "osv-scanner exit 2 (scan error)" and "no terraform" all
# returned 0 and summary.json called them "pass". Tools are shimmed so every case is deterministic
# and offline; PATH holds only the shims + the system dirs, so a real uvx/docker never leaks in.
F02="$(mktemp -d)"; F02S="$F02/shims"; mkdir -p "$F02S"
(
  cd "$F02" && mkdir repo && cd repo || exit 1
  git init -q .
  mkdir -p tools/security-audit-kit infra
  if have rsync; then rsync -a --exclude '.git' "$KIT_SRC"/ tools/security-audit-kit/
  else cp -R "$KIT_SRC"/. tools/security-audit-kit/; rm -rf tools/security-audit-kit/.git; fi
  printf 'print(1)\n' > app.py
  git -c user.email=e2e@test -c user.name=e2e add -A >/dev/null 2>&1
  git -c user.email=e2e@test -c user.name=e2e commit -qm f02 >/dev/null 2>&1
) || no "F02 fixture could not be built"
# uvx shim: prints $F02_OUT, exits $F02_RC. docker shim: `info` exits $F02_DINFO, `run` like uvx.
# shellcheck disable=SC2016  # the $vars belong to the shim, expanded when it runs
printf '#!/bin/sh\n[ -n "$F02_OUT" ] && printf "%%s\\n" "$F02_OUT"\np=""; for a in "$@"; do [ "$p" = --output ] && [ -n "$F02_SARIF" ] && printf "%%s" "$F02_SARIF" > "$a"; p="$a"; done\nexit "${F02_RC:-0}"\n' > "$F02S/uvx"
# shellcheck disable=SC2016
printf '#!/bin/sh\n[ "$1" = info ] && exit "${F02_DINFO:-0}"\n[ -n "$F02_OUT" ] && printf "%%s\\n" "$F02_OUT"\nexit "${F02_RC:-0}"\n' > "$F02S/docker"
chmod +x "$F02S/uvx" "$F02S/docker"
F02SYS="/usr/bin:/bin:/usr/sbin:/sbin"
# f02 <cmd> [VAR=val ...] -> runs the scan; F02RC = its exit, F02SUM = summary.json.
f02(){ local cmd="$1"; shift
  (cd "$F02/repo" && env PATH="$F02S:$F02SYS" "$@" "$BASH" tools/security-audit-kit/scan.sh "$cmd" >"$F02/out" 2>&1); F02RC=$?
  F02SUM="$(cat "$F02/repo/docs/security/scan-findings/summary.json" 2>/dev/null)"; }
# f02dim <name> -> "status gate reason" for that dimension (python3 parses the JSON).
f02dim(){ /usr/bin/python3 -I -c 'import json,sys
d=json.loads(sys.argv[1])
for x in d.get("dimensions",[]):
    if x.get("name")==sys.argv[2]: print(x.get("status"),x.get("gate"),x.get("reason") or "")' "$F02SUM" "$1" 2>/dev/null; }
f02top(){ /usr/bin/python3 -I -c 'import json,sys
d=json.loads(sys.argv[1]); g=d.get("gate") or {}
print(d.get("schema_version"), g.get("exit_code"), ",".join(g.get("blocked_by") or []) or "-")' "$F02SUM" 2>/dev/null; }
if [ -x /usr/bin/python3 ]; then
  # missing docker -> skipped, never pass; gate unchanged (allow)
  f02 secret F02_DINFO=1; D="$(f02dim secret)"
  [[ "$D" == "skipped allow "*docker* ]] && [ "$F02RC" -eq 0 ] \
    && ok "F02: no docker -> secret is skipped (with reason), gate allows" || no "F02: no docker -> got '$D' rc=$F02RC"
  [ "$(f02top)" = "2 0 -" ] && ok "F02: schema_version 2 + top-level gate (exit 0, nothing blocking)" \
    || no "F02: top-level gate wrong: '$(f02top)'"
  # missing uvx -> skipped (PATH without the uvx shim)
  (cd "$F02/repo" && env PATH="$F02SYS" "$BASH" tools/security-audit-kit/scan.sh sast >/dev/null 2>&1)
  F02SUM="$(cat "$F02/repo/docs/security/scan-findings/summary.json" 2>/dev/null)"; D="$(f02dim sast)"
  [[ "$D" == "skipped allow "*uvx* ]] && ok "F02: no uvx/pipx -> sast is skipped" || no "F02: no uvx -> got '$D'"
  # nothing to inspect -> not_applicable
  f02 iac; D="$(f02dim iac)"
  [[ "$D" == "not_applicable allow "* ]] && ok "F02: no terraform -> iac is not_applicable" || no "F02: no terraform -> got '$D'"
  f02 deps; D="$(f02dim js-deps)"
  [[ "$D" == "not_applicable allow "* ]] && ok "F02: no JS project -> js-deps is not_applicable" || no "F02: no JS -> got '$D'"
  [[ "$(f02dim py-deps)" == "not_applicable allow "* ]] && ok "F02: no Python project -> py-deps is not_applicable" \
    || no "F02: no Python -> got '$(f02dim py-deps)'"
  # semgrep: 1 = findings, anything else = the tool failed. Both still block (gate unchanged).
  f02 sast F02_RC=1; D="$(f02dim sast)"
  [[ "$D" == "findings block"* ]] && [ "$F02RC" -eq 1 ] && ok "F02: semgrep exit 1 -> findings, blocks" \
    || no "F02: semgrep findings -> got '$D' rc=$F02RC"
  [ "$(f02top)" = "2 1 sast" ] && ok "F02: top-level gate names the blocking dimension" || no "F02: blocked_by wrong: '$(f02top)'"
  # the old vocabulary is gone: a blocking finding is "findings", never "fail"
  grep -q '"status": "fail"' <<<"$F02SUM" && no "F02: legacy status 'fail' still written" || ok "F02: no legacy 'fail' status"
  f02 sast F02_RC=2; D="$(f02dim sast)"
  [[ "$D" == "error block "*exit\ 2* ]] && [ "$F02RC" -eq 1 ] && ok "F02: semgrep crash -> error (not findings), still blocks" \
    || no "F02: semgrep crash -> got '$D' rc=$F02RC"
  grep -q 'BLOCKED (rc=1): sast (error)' "$F02/out" && ! grep -q 'HARD finding' "$F02/out" \
    && ok "F02: the block line says a crash blocked, not a finding" || no "F02: block line still calls a crash a finding"
  # soft-fail findings: reported as findings, the gate still allows
  mkdir -p "$F02/repo/infra"; printf 'resource "x" "y" {}\n' > "$F02/repo/infra/main.tf"
  git -C "$F02/repo" add infra/main.tf >/dev/null 2>&1
  f02 iac F02_OUT="Passed checks: 3, Failed checks: 2, Skipped checks: 0"; D="$(f02dim iac)"
  [[ "$D" == "findings allow "* ]] && [ "$F02RC" -eq 0 ] && ok "F02: checkov soft-fail with failed checks -> findings, gate allows" \
    || no "F02: checkov soft-fail -> got '$D' rc=$F02RC"
  f02 iac F02_OUT="Passed checks: 3, Failed checks: 0, Skipped checks: 0"
  [[ "$(f02dim iac)" == "pass allow"* ]] && ok "F02: checkov with no failed checks -> pass" || no "F02: checkov clean -> got '$(f02dim iac)'"
  f02 iac F02_RC=1; D="$(f02dim iac)"
  [[ "$D" == "error allow "* ]] && [ "$F02RC" -eq 0 ] && ok "F02: checkov crash -> error, gate unchanged (allows)" \
    || no "F02: checkov crash -> got '$D' rc=$F02RC"
  git -C "$F02/repo" rm -q --cached infra/main.tf >/dev/null 2>&1; rm -f "$F02/repo/infra/main.tf"
  # trivy (soft): findings are recorded, the gate allows; a failed container run still blocks
  f02 container F02_RC=5; D="$(f02dim container)"
  [[ "$D" == "findings allow"* ]] && [ "$F02RC" -eq 0 ] && ok "F02: trivy findings (soft) -> findings, gate allows" \
    || no "F02: trivy soft findings -> got '$D' rc=$F02RC"
  f02 container F02_RC=125; D="$(f02dim container)"
  [[ "$D" == "error block "* ]] && ok "F02: trivy/docker failure -> error, blocks as before" || no "F02: trivy failure -> got '$D'"
  # osv: 128 = no lockfiles (not_applicable), other non-1 codes = scan error; neither blocks
  f02 osv F02_RC=128; [[ "$(f02dim osv)" == "not_applicable allow "* ]] && ok "F02: osv no lockfiles -> not_applicable" \
    || no "F02: osv 128 -> got '$(f02dim osv)'"
  f02 osv F02_RC=2; D="$(f02dim osv)"
  [[ "$D" == "error allow "* ]] && [ "$F02RC" -eq 0 ] && ok "F02: osv scan error -> error, gate unchanged (allows)" \
    || no "F02: osv error -> got '$D' rc=$F02RC"
  grep -q 'NOT inspected' "$F02/out" && ok "F02: the run names what was not inspected" || no "F02: no not-inspected banner"
  echo "-- F03: evidence uses only what THIS run produced, and says where it came from --"
  F03SARIF='{"runs":[{"tool":{"driver":{"name":"semgrep"}},"results":[{"ruleId":"R1","level":"error","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":1}}}]}]}]}'
  F03D="$F02/repo/docs/security/scan-findings"
  f03ev(){ /usr/bin/python3 -I -c 'import json,sys
d=json.load(open(sys.argv[1])); print(d["counts"]["total"]); print("\n".join(d.get("warnings") or []))' "$F03D/evidence.json" 2>/dev/null; }
  f02 sast SARIF=1 F02_RC=1 F02_SARIF="$F03SARIF"
  F03P="$(/usr/bin/python3 -I -c 'import json,sys
d=json.loads(sys.argv[1]); p=d.get("provenance") or {}; a=d.get("artifacts") or []
print(p.get("commit"), p.get("dirty"), (p.get("kit") or {}).get("version") or "-", (p.get("scope") or {}).get("command"),
      ",".join(x["path"] for x in a), all(len(x.get("sha256") or "")==64 for x in a) and bool(a))' "$F02SUM" 2>/dev/null)"
  F03HEAD="$(git -C "$F02/repo" rev-parse HEAD)"
  [[ "$F03P" == "$F03HEAD False "*" sast sarif/semgrep.sarif True" ]] && [[ "$F03P" != *" - sast "* ]] \
    && ok "F03: summary.json carries provenance (commit, clean tree, kit version, scope) + this run's SARIF with sha256" \
    || no "F03: provenance/artifacts wrong: '$F03P' (HEAD $F03HEAD)"
  [ "$(f03ev | head -1)" = 1 ] && ok "F03: this run's SARIF becomes evidence" || no "F03: evidence total '$(f03ev | head -1)', want 1"
  grep -q "\"commit\": \"$F03HEAD\"" "$F03D/evidence.json" && ok "F03: evidence.json carries the commit it describes" \
    || no "F03: evidence.json has no provenance"
  # tampered after the scan -> a rebuild refuses it, out loud
  printf ' ' >> "$F03D/sarif/semgrep.sarif"
  (cd "$F02/repo" && env PATH="$F02S:$F02SYS" "$BASH" tools/security-audit-kit/scan.sh evidence >"$F02/out" 2>&1)
  [ "$(f03ev | head -1)" = 0 ] && grep -q 'changed since this run wrote it' "$F02/out" \
    && ok "F03: a SARIF changed after the scan is not used, and the rebuild says so" || no "F03: tampered SARIF still used"
  # next run: sast is SKIPPED (no uvx). Yesterday's semgrep.sarif must not resurface as current.
  (cd "$F02/repo" && env PATH="$F02SYS" SARIF=1 "$BASH" tools/security-audit-kit/scan.sh sast >"$F02/out" 2>&1)
  [ ! -f "$F03D/sarif/semgrep.sarif" ] && ok "F03: the shared sarif/ holds only this run's output (no carry-over)" \
    || no "F03: an earlier run's semgrep.sarif was carried into this run's record"
  [ "$(f03ev | head -1)" = 0 ] && ok "F03: a skipped dimension's old findings are not current evidence" \
    || no "F03: skipped sast still produced $(f03ev | head -1) finding(s) from an older run"
  # a dirty tree is recorded as such
  printf 'x\n' >> "$F02/repo/app.py"
  f02 secret F02_DINFO=1
  grep -q '"dirty": true' <<<"$F02SUM" && ok "F03: uncommitted changes -> provenance.dirty true" || no "F03: dirty tree not recorded"
  git -C "$F02/repo" checkout -q -- app.py
  echo "-- F04: the report says what it can vouch for; explicit report/evidence failures are visible --"
  F04R="$F03D/report-$(date +%F).html"
  f04(){ (cd "$F02/repo" && env PATH="$F02S:$F02SYS" "$@" >"$F02/out" 2>&1); }
  # a scan with secret skipped (no docker) and sast passing -> report must not say clean
  f04 env F02_DINFO=1 SARIF=1 REPORT=html F02_SARIF="$F03SARIF" "$BASH" tools/security-audit-kit/scan.sh all
  if [ -f "$F04R" ]; then
    grep -q 'NOT complete' "$F04R" && ! grep -q 'clean (exit 0)' "$F04R" \
      && ok "F04: a run with a skipped dimension is reported as NOT complete, never clean" || no "F04: incomplete run reported as clean"
    grep -q "Scanned $(date +%F)T" "$F04R" && grep -q "report generated $(date +%F)" "$F04R" \
      && ok "F04: scan time (from its own summary) and report date are shown apart" || no "F04: scan/report dates missing"
  else no "F04: REPORT=html wrote no report"; fi
  # a later SARIF=0 run publishes a new summary; re-rendering must not borrow its time
  f02 secret F02_DINFO=1
  f04 "$BASH" tools/security-audit-kit/scan.sh report
  grep -q 'scan time unknown' "$F04R" && ok "F04: a later run's summary.json is not taken as this report's scan time" \
    || no "F04: report borrowed another run's scan time"
  # explicit commands fail visibly
  rm -f "$F03D/evidence.json"
  F04RC=0; f04 "$BASH" tools/security-audit-kit/scan.sh report || F04RC=$?
  [ "$F04RC" -eq 1 ] && ok "F04: 'scan.sh report' with no evidence.json exits 1" || no "F04: report without evidence rc=$F04RC"
  rm -rf "$F03D/sarif"
  F04RC=0; f04 "$BASH" tools/security-audit-kit/scan.sh evidence || F04RC=$?
  [ "$F04RC" -eq 1 ] && ok "F04: 'scan.sh evidence' with no SARIF exits 1" || no "F04: evidence without SARIF rc=$F04RC"
  # post-scan report failure: noted, gate unchanged (the scan itself passed)
  mv "$F02/repo/tools/security-audit-kit/lib/report_html.py" "$F02/report_html.py.bak"
  F04RC=0; f04 env F02_DINFO=1 SARIF=1 REPORT=html "$BASH" tools/security-audit-kit/scan.sh secret || F04RC=$?
  [ "$F04RC" -eq 0 ] && grep -q 'gate result is unchanged' "$F02/out" \
    && ok "F04: a failed post-scan report is reported, and does not change the gate" || no "F04: post-scan report failure rc=$F04RC or silent"
  mv "$F02/report_html.py.bak" "$F02/repo/tools/security-audit-kit/lib/report_html.py"
  echo "-- F14a: one closing summary — per-dimension status + time, coverage, why, what next --"
  f04 env F02_DINFO=1 "$BASH" tools/security-audit-kit/scan.sh all
  F14SUM="$(cat "$F03D/summary.json" 2>/dev/null)"
  /usr/bin/python3 -I -c 'import json,sys
d=json.loads(sys.argv[1]); ds=d["dimensions"]
assert ds and all(isinstance(x.get("seconds"),(int,float)) and x["seconds"]>=0 for x in ds), ds
assert isinstance(d.get("seconds"),(int,float))' "$F14SUM" 2>/dev/null \
    && ok "F14a: summary.json times every dimension and the run (seconds)" || no "F14a: seconds missing in summary.json"
  F14OUT="$(sed 's/\x1b\[[0-9;]*m//g' "$F02/out")"
  grep -qE '^   secret +skipped +[0-9]+\.[0-9]s +no docker' <<<"$F14OUT" \
    && grep -qE '^   sast +pass +[0-9]+\.[0-9]s' <<<"$F14OUT" \
    && ok "F14a: closing table lists each dimension with status, time and reason" || no "F14a: no closing table"
  grep -q "not in 'all': osv guarddog zizmor sbom" <<<"$F14OUT" \
    && ok "F14a: the summary names the dimensions this command does not cover" || no "F14a: coverage gap not shown"
  grep -q 'Docker is not running: secret container' <<<"$F14OUT" && grep -q 'start Docker' <<<"$F14OUT" \
    && ok "F14a: one Docker line says what was not inspected and how to fix it" || no "F14a: no Docker line"
  F14RC=0; f04 "$BASH" tools/security-audit-kit/scan.sh help || F14RC=$?
  [ "$F14RC" -eq 0 ] && grep -q 'container' "$F02/out" && grep -q "not in 'all'" "$F02/out" \
    && ok "F14a: scan.sh help lists commands, gate and coverage" || no "F14a: scan.sh help missing (rc=$F14RC)"
  # pre-push blocked by a CRASHED scanner: say so, and do not suggest allowlisting it
  f04 env F02_DINFO=1 F02_RC=2 "$BASH" tools/security-audit-kit/hooks/pre-push
  grep -q 'scanner FAILED' "$F02/out" && grep -q 'not a finding' "$F02/out" && grep -q 'do not allowlist' "$F02/out" \
    && ok "F14a: pre-push blocked by a crash says it is not a finding" || no "F14a: pre-push crash message missing"
  f04 env F02_DINFO=1 F02_RC=1 "$BASH" tools/security-audit-kit/hooks/pre-push
  grep -q 'allowlist with an expiry' "$F02/out" && grep -q -- '--no-verify' "$F02/out" && ! grep -q 'scanner FAILED' "$F02/out" \
    && ok "F14a: pre-push blocked by findings lists the options" || no "F14a: pre-push findings message missing"
  echo "-- F30: trivy DB cached between runs; refreshed by age; identity in provenance, age in summary --"
  F30S="$F02/f30shims"; mkdir -p "$F30S"; F30LOG="$F02/f30.log"
  # docker shim: logs every call; `trivy version --format json` answers with $F30_META (or "no DB").
  # shellcheck disable=SC2016
  printf '#!/bin/sh\n[ "$1" = info ] && exit 0\nprintf "%%s\\n" "$*" >> "$F30_LOG"\ncase " $* " in *" version --format json "*) [ -n "$F30_META" ] && printf "%%s\\n" "$F30_META" || printf "%%s\\n" "{\\"Version\\":\\"0.58.0\\"}"; exit 0 ;; esac\nexit "${F30_RC:-0}"\n' > "$F30S/docker"
  chmod +x "$F30S/docker"
  f30(){ : > "$F30LOG"; (cd "$F02/repo" && env PATH="$F30S:$F02S:$F02SYS" F30_LOG="$F30LOG" "$@" >"$F02/out" 2>&1); F02SUM="$(cat "$F03D/summary.json" 2>/dev/null)"; }
  f30iso(){ /usr/bin/python3 -I -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=float(sys.argv[1]))).strftime("%Y-%m-%dT%H:%M:%S.123456789Z"))' "$1"; }
  f30meta(){ printf '{"Version":"0.58.0","VulnerabilityDB":{"Version":2,"NextUpdate":"2099-01-01T00:00:00Z","UpdatedAt":"2026-11-03T01:30:30.031564361Z","DownloadedAt":"%s"}}' "$(f30iso "$1")"; }
  f30fs(){ grep ' fs ' "$F30LOG"; }
  # (a) first run: no DB in the cache -> say so, download into the persistent cache, never the bundle
  f30 "$BASH" tools/security-audit-kit/scan.sh container
  grep -q 'first run: downloading the trivy vulnerability DB' "$F02/out" && f30fs | grep -q -- '-v security-audit-trivy:/root/.cache/trivy' \
    && f30fs | grep -q -- '--skip-check-update' && f30fs | grep -q -- '--no-progress' && ! f30fs | grep -q -- '--skip-db-update' \
    && ok "F30: first run downloads the DB into the persistent cache volume, and says so" || no "F30: first run: $(f30fs)"
  f30fs | grep -qE -- '--skip-dirs [^ ]*docs/security/scan-findings' \
    && ok "scan record: trivy never scans docs/security/scan-findings" || no "scan record: trivy scans the kit's own logs: $(f30fs)"
  # (b) fresh DB (1h) -> no download at all
  f30 env F30_META="$(f30meta 1)" "$BASH" tools/security-audit-kit/scan.sh container
  f30fs | grep -q -- '--skip-db-update' && ok "F30: a fresh cached DB is used without any download" || no "F30: fresh DB still updated: $(f30fs)"
  /usr/bin/python3 -I -c 'import json,sys
d=json.loads(sys.argv[1]); t=d.get("trivy_db") or {}; p=(d.get("provenance") or {}).get("trivy_db") or {}
assert p.get("updated_at")=="2026-11-03T01:30:30.031564361Z", p
assert "age_hours" not in p and "downloaded_at" not in p, p
assert 0.5 <= t.get("age_hours", -1) <= 1.5, t' "$F02SUM" 2>/dev/null \
    && ok "F30: DB identity in provenance, its age only in summary.json run metadata" || no "F30: trivy_db fields wrong: $F02SUM"
  grep -qE 'container +pass .*trivy DB 1h old' <<<"$(sed 's/\x1b\[[0-9;]*m//g' "$F02/out")" \
    && ok "F30: the closing table shows the DB age" || no "F30: DB age not in closing table"
  # soft findings keep the DB age visible in the closing table (rc.1 dogfood: a 72-char cut hid it)
  f30 env F30_META="$(f30meta 1)" F30_RC=5 "$BASH" tools/security-audit-kit/scan.sh container
  grep -qE 'container +findings .*trivy DB 1h old' <<<"$(sed 's/\x1b\[[0-9;]*m//g' "$F02/out")" \
    && ok "F30: with soft findings the closing table still shows the DB age" || no "F30: DB age cut off on a findings row"
  # (c) stale DB (48h > 24h) -> let trivy refresh it, and say why
  f30 env F30_META="$(f30meta 48)" "$BASH" tools/security-audit-kit/scan.sh container
  ! f30fs | grep -q -- '--skip-db-update' && grep -q 'refreshing' "$F02/out" \
    && ok "F30: a DB older than TRIVY_DB_MAX_AGE_H is refreshed" || no "F30: stale DB not refreshed: $(f30fs)"
  # (d) offline + no DB -> not inspected, never a pass; (e) offline + DB -> offline scan, no download
  f30 env SCAN_OFFLINE=1 "$BASH" tools/security-audit-kit/scan.sh container
  [[ "$(f02dim container)" == "skipped allow "*SCAN_OFFLINE* ]] && [ -z "$(f30fs)" ] \
    && ok "F30: SCAN_OFFLINE=1 with no cached DB -> skipped (not a pass), nothing run" || no "F30: offline/no-DB -> '$(f02dim container)'"
  f30 env SCAN_OFFLINE=1 F30_META="$(f30meta 200)" "$BASH" tools/security-audit-kit/scan.sh container
  f30fs | grep -q -- '--skip-db-update' && f30fs | grep -q -- '--offline-scan' \
    && ok "F30: SCAN_OFFLINE=1 with a cached DB scans offline, whatever its age" || no "F30: offline scan args: $(f30fs)"
  # (f) TRIVY_CACHE as an absolute path -> bind mount (CI caches a directory)
  f30 env TRIVY_CACHE="$F02/trivy-cache" F30_META="$(f30meta 1)" "$BASH" tools/security-audit-kit/scan.sh container
  f30fs | grep -q -- "-v $F02/trivy-cache:/root/.cache/trivy" && ok "F30: TRIVY_CACHE=/abs/path bind-mounts that directory" \
    || no "F30: TRIVY_CACHE path not used: $(f30fs)"
  # (g) evidence carries the identity, never the age (it must diff to nothing on unchanged code)
  f30 env SARIF=1 F30_META="$(f30meta 1)" "$BASH" tools/security-audit-kit/scan.sh container
  grep -q '"updated_at": "2026-11-03T01:30:30.031564361Z"' "$F03D/evidence.json" && ! grep -q 'age_hours' "$F03D/evidence.json" \
    && ok "F30: evidence.json carries the DB identity, not its age" || no "F30: evidence trivy_db wrong"
  # (h) doctor + warm
  f30 env F30_META="$(f30meta 3)" "$BASH" tools/security-audit-kit/scan.sh doctor
  grep -qE 'trivy DB +: .*updated 2026-11-03T01:30:30.*3h ago' "$F02/out" && ok "F30: doctor shows the cached DB and its age" \
    || no "F30: doctor has no trivy DB line"
  f30 "$BASH" tools/security-audit-kit/scan.sh warm
  grep -q -- '--download-db-only' "$F30LOG" && grep -q 'pull' "$F30LOG" \
    && ok "F30: scan.sh warm pulls the pinned images and the trivy DB" || no "F30: warm did not pull/download: $(cat "$F30LOG")"
  echo "-- SAST_PATHS: a configured root that does not exist is skipped, never a crash (v1.20.0-rc.2 dogfood) --"
  # The example config shipped `SAST_PATHS:=backend frontend` ACTIVE since v1.0: every install without
  # both dirs ran semgrep on a missing root -> exit 2 -> the gate blocked every push.
  SPS="$F02/spshims"; mkdir -p "$SPS"; SPLOG="$F02/sp.log"
  # shellcheck disable=SC2016
  printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "$SP_LOG"\nexit 0\n' > "$SPS/uvx"; chmod +x "$SPS/uvx"
  fsp(){ : > "$SPLOG"; (cd "$F02/repo" && env PATH="$SPS:$F02SYS" SP_LOG="$SPLOG" "$@" "$BASH" tools/security-audit-kit/scan.sh sast >"$F02/out" 2>&1); F02SUM="$(cat "$F03D/summary.json" 2>/dev/null)"; }
  fsp SAST_PATHS="backend frontend"
  grep -qE 'semgrep scan .* \.$' "$SPLOG" && [[ "$(f02dim sast)" == "pass allow "*"not found"* ]] \
    && ok "SAST_PATHS: none of the roots exist -> whole repo scanned, and the reason says why" \
    || no "SAST_PATHS: missing roots -> '$(f02dim sast)' args: $(cat "$SPLOG")"
  mkdir -p "$F02/repo/backend"; printf 'x = 1\n' > "$F02/repo/backend/a.py"
  fsp SAST_PATHS="backend frontend"
  grep -qE 'semgrep scan .* backend$' "$SPLOG" && grep -q 'frontend' "$F02/out" \
    && ok "SAST_PATHS: only the existing root is scanned; the missing one is named" \
    || no "SAST_PATHS: partial roots -> args: $(cat "$SPLOG")"
  # The kit's own record (raw logs, SARIF, reports) is not source: a repo that once committed it got
  # its logs scanned by semgrep (a timeout in the v1.20.0 dogfood), and trivy fs reads it untracked.
  fsp
  grep -q -- '--exclude docs/security/scan-findings' "$SPLOG" \
    && ok "scan record: semgrep never scans docs/security/scan-findings" || no "scan record: semgrep scans the kit's own logs: $(cat "$SPLOG")"
  rm -rf "$F02/repo/backend"
  F14EX="$(grep -n 'SAST_PATHS:=' "$F02/repo/tools/security-audit-kit/security-audit.conf.example" | grep -v '^[0-9]*:#' || true)"
  [ -z "$F14EX" ] && ok "SAST_PATHS: the example config no longer sets it (default: whole repo)" \
    || no "SAST_PATHS: the example still sets it: $F14EX"
  echo "-- F06: the pkgcheck cache keeps guarddog's findings, and the CURRENT policy judges them --"
  PKS="$F02/pkshims"; mkdir -p "$PKS"; PKLOG="$F02/pk.log"
  # guarddog shim: counts calls, answers with $PK_OUT (a real guarddog 3.0.2 JSON shape).
  # shellcheck disable=SC2016
  printf '#!/bin/sh\necho call >> "$PK_LOG"\n[ -n "$PK_SLEEP" ] && sleep "$PK_SLEEP"\nprintf "%%s\\n" "$PK_OUT"\n' > "$PKS/uvx"; chmod +x "$PKS/uvx"
  PKCACHE="$(git -C "$F02/repo" rev-parse --git-common-dir)"; case "$PKCACHE" in /*) ;; *) PKCACHE="$F02/repo/$PKCACHE" ;; esac
  PKCACHE="$PKCACHE/security-audit-cache/pkgcheck"
  PKEVAL='{"package":"foo","issues":1,"errors":{},"results":{"threat-runtime-obfuscation-dynamic-eval":[{"l":1}]}}'
  fpk(){ (cd "$F02/repo" && env PATH="$PKS:$F02SYS" PK_LOG="$PKLOG" "$@" "$BASH" tools/security-audit-kit/scan.sh pkgcheck pypi foo==1.0.0 >"$F02/out" 2>&1); F06RC=$?; F06CALLS="$(wc -l < "$PKLOG" 2>/dev/null | tr -d ' ')"; }
  rm -rf "$PKCACHE"; : > "$PKLOG"
  fpk PK_OUT="$PKEVAL"
  [ "$F06RC" -eq 0 ] && grep -q 'note  pypi/foo' "$F02/out" && ok "F06: a threat-* rule reports (default policy) and is cached" \
    || no "F06: first check rc=$F06RC: $(cat "$F02/out")"
  # the measured bug: same package, policy now blocks that rule -> must BLOCK, from the cache
  fpk PK_OUT="$PKEVAL" PKGCHECK_BLOCK_EXTRA=threat-runtime-obfuscation-dynamic-eval
  [ "$F06RC" -eq 1 ] && grep -q 'BLOCK' "$F02/out" && [ "$F06CALLS" = 1 ] \
    && ok "F06: BLOCK_EXTRA added later blocks a cached package, without re-downloading it" \
    || no "F06: cached ALLOW survived a stricter policy (rc=$F06RC, guarddog calls=$F06CALLS): $(cat "$F02/out")"
  # and the other way: a rule moved to report-only stops blocking a cached BLOCK
  PKTYPO='{"package":"foo","issues":1,"errors":{},"results":{"typosquatting":["fooo"]}}'
  rm -rf "$PKCACHE"; : > "$PKLOG"
  fpk PK_OUT="$PKTYPO"; F06A="$F06RC"
  grep -qE 'BLOCK.* pypi/foo@1.0.0 -> typosquatting' "$F02/out" && ! grep -q 'clean' "$F02/out" \
    && ok "F06: a first-time BLOCK is shown as BLOCK (it printed 'ok ... clean' while blocking)" \
    || no "F06: first-time BLOCK mislabelled: $(cat "$F02/out")"
  fpk PK_OUT="$PKTYPO" PKGCHECK_REPORT_EXTRA=typosquatting
  [ "$F06A" -eq 1 ] && [ "$F06RC" -eq 0 ] && [ "$F06CALLS" = 1 ] \
    && ok "F06: REPORT_EXTRA added later un-blocks a cached BLOCK, from the cache" || no "F06: report-only not applied to cache (rc $F06A/$F06RC calls $F06CALLS)"
  # a truncated cache entry is a miss (re-scan), never a verdict
  for f in "$PKCACHE"/*; do printf '{"package":"foo","res' > "$f"; done
  fpk PK_OUT="$PKTYPO"
  [ "$F06CALLS" = 2 ] && [ "$F06RC" -eq 1 ] && ok "F06: a half-written cache entry is re-scanned, not trusted" \
    || no "F06: corrupt cache used (calls=$F06CALLS rc=$F06RC)"
  # INDETERMINATE is never remembered
  rm -rf "$PKCACHE"; : > "$PKLOG"
  fpk PK_OUT='{"package":"foo","issues":0,"errors":{"download-package":"404"}}'
  fpk PK_OUT='{"package":"foo","issues":0,"errors":{"download-package":"404"}}'
  [ "$F06CALLS" = 2 ] && ok "F06: INDETERMINATE is not cached (asked again next time)" || no "F06: INDETERMINATE cached (calls=$F06CALLS)"
  # refresh: re-scan on request and replace the entry
  rm -rf "$PKCACHE"; : > "$PKLOG"
  fpk PK_OUT="$PKEVAL"; fpk PK_OUT="$PKTYPO" PKGCHECK_CACHE=refresh
  [ "$F06CALLS" = 2 ] && [ "$F06RC" -eq 1 ] && ok "F06: PKGCHECK_CACHE=refresh re-scans and replaces the entry" \
    || no "F06: refresh did not re-scan (calls=$F06CALLS rc=$F06RC)"
  fpk PK_OUT="$PKEVAL"
  [ "$F06CALLS" = 2 ] && [ "$F06RC" -eq 1 ] && ok "F06: the refreshed entry is what later checks read" || no "F06: refreshed entry not used"
  # an entry written by an older kit (a stored verdict, not findings) is never read as one
  rm -rf "$PKCACHE"; mkdir -p "$PKCACHE"; : > "$PKLOG"
  # shellcheck disable=SC2016  # the sed pattern matches a literal ${GUARDDOG_VER:-...} in scan.sh
  printf 'CLEAN\tcached by an older kit' > "$PKCACHE/pypi__foo__1.0.0__$(sed -n 's/^GUARDDOG_VER="${GUARDDOG_VER:-\([^}]*\)}"/\1/p' "$KIT_SRC/scan.sh")"
  fpk PK_OUT="$PKTYPO"
  [ "$F06CALLS" = 1 ] && [ "$F06RC" -eq 1 ] && ok "F06: an old-format cached verdict is ignored, the package re-scanned" \
    || no "F06: old cached verdict trusted (calls=$F06CALLS rc=$F06RC)"
  # two checks of one package at once: both answer, the entry is whole, no temp file left
  rm -rf "$PKCACHE"; : > "$PKLOG"
  (fpk PK_OUT="$PKTYPO" PK_SLEEP=1) & (fpk PK_OUT="$PKTYPO" PK_SLEEP=1) & wait
  F06N="$(find "$PKCACHE" -type f | wc -l | tr -d ' ')"; F06TMP="$(find "$PKCACHE" -name '*.tmp*' | wc -l | tr -d ' ')"
  /usr/bin/python3 -I -c 'import json,sys,glob; [json.load(open(f)) for f in glob.glob(sys.argv[1]+"/*")]' "$PKCACHE" 2>/dev/null \
    && [ "$F06N" = 1 ] && [ "$F06TMP" = 0 ] && ok "F06: concurrent writes leave one whole entry, no temp files" \
    || no "F06: concurrent cache writes: $F06N file(s), $F06TMP tmp"
else skip "F02 status tests (no /usr/bin/python3)"; fi
rm -rf "$F02"

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
