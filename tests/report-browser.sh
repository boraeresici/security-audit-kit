#!/usr/bin/env bash
# tests/report-browser.sh — the HTML report's filter script runs in a REAL browser, under the
# report's own CSP (F26). The Python tests prove the CSP hash equals the script; only a browser
# proves the browser agrees. jsdom does not enforce CSP, which is why this is headless Chrome and
# not an npm test dependency. Two cases: the rendered report unhides its filter form; the same
# report with one byte of the script changed keeps it hidden (the CSP blocked it — the check is
# not vacuous).
# Usage: bash tests/report-browser.sh   (exit 0 = all passed; no browser = skip, exit 0,
#        unless REQUIRE_BROWSER=1, as in CI, where a missing browser is a failure)
set -uo pipefail
KIT_SRC="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
no(){ FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }

CHROME=""
for c in "${CHROME_BIN:-}" google-chrome google-chrome-stable chromium chromium-browser \
         "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"; do
  [ -n "$c" ] || continue
  if command -v "$c" >/dev/null 2>&1; then CHROME="$(command -v "$c")"; break; fi
  if [ -x "$c" ]; then CHROME="$c"; break; fi
done
if [ -z "$CHROME" ]; then
  if [ "${REQUIRE_BROWSER:-0}" = "1" ]; then echo "report-browser: no Chrome/Chromium found" >&2; exit 1; fi
  echo "report-browser: skipped (no Chrome/Chromium; set CHROME_BIN)"; exit 0
fi

W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
python3 - "$W/evidence.json" <<'EOPY'
import json, sys
f = lambda i, sev, tool, dec=None: {
    "id": f"{i:012x}", "dimension": "sast", "tool": tool, "rule_id": f"r{i}", "file": "app/x.py",
    "line": i, "message": "<script>alert(1)</script>", "severity": sev, "severity_source": "t",
    "cvss": None, "decision": dec, "confidence": None, "evidence": None}
json.dump({"schema": "security-audit-kit/evidence@1",
           "scan": {"command": "all", "exit_code": 1, "dimensions": []},
           "counts": {}, "warnings": [],
           "findings": [f(1, "high", "semgrep"), f(2, "low", "gitleaks"), f(3, "medium", "semgrep", "suppressed")]},
          open(sys.argv[1], "w"))
EOPY
python3 "$KIT_SRC/lib/report_html.py" --evidence "$W/evidence.json" --out "$W/report.html" \
  --repo demo --date 2026-01-01 >/dev/null 2>&1 || { echo "report-browser: render failed" >&2; exit 1; }
# One byte of the script changed -> its hash no longer matches the CSP.
sed 's/<script>(function/<script> (function/' "$W/report.html" > "$W/tampered.html"
grep -q '<script> (function' "$W/tampered.html" || { echo "report-browser: tamper did not apply" >&2; exit 1; }

FLAGS=(--headless=new --disable-gpu --no-first-run --no-default-browser-check --user-data-dir="$W/profile")
# Linux CI runners restrict the user namespaces Chrome's sandbox needs; the page is our own fixture.
[ "$(uname -s)" = "Linux" ] && FLAGS+=(--no-sandbox)
form(){ "$CHROME" "${FLAGS[@]}" --dump-dom "file://$1" 2>/dev/null | grep -o '<form[^>]*id="filters"[^>]*>'; }

F="$(form "$W/report.html")"
case "$F" in
  *hidden*|"") no "report: the filter script did not run under the CSP ($F)" ;;
  *) ok "report: the filter script runs under its hash-pinned CSP (form shown)" ;;
esac
F="$(form "$W/tampered.html")"
case "$F" in
  *hidden*) ok "report: a script that does not match the CSP hash is blocked (form stays hidden)" ;;
  *) no "report: a tampered script was not blocked ($F)" ;;
esac

echo "report-browser: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
