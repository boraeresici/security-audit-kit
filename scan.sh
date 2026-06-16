#!/usr/bin/env bash
# security-audit-kit / scan.sh — portable, CI-independent local security scanning.
# Assumes no installation: auto-detects the toolchain and runs pinned versions via
# uvx (semgrep/checkov/pip-audit) + docker (gitleaks/trivy/syft).
#
# Usage:  ./scan.sh <command>
#   deps     Dependency CVE (pip-audit + js audit)          [HARD]  fast
#   secret   Secret scan (gitleaks, history included)       [HARD]
#   sast     Static analysis (semgrep ERROR)                [HARD]
#   iac      IaC misconfig (checkov, if terraform present)  [soft]
#   container  Dep+OS+secret+misconfig (trivy fs)           [soft]
#   sbom     Software inventory (syft CycloneDX+SPDX)        [artifact]
#   fast     deps + secret  (pre-commit / package install)
#   all      secret + sast + deps + container + iac         (pre-push / pre-PR)
#
# Env override: SAST_PATHS, TF_DIR, GITLEAKS_VER, TRIVY_VER, SYFT_VER,
#               SEMGREP_CONFIGS, SKIP_SECURITY=1 (skip all scans).
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

# Per-project config (committed to the repo, shared with the team). Precedence is
# env > conf > default: the conf only affects variables you did NOT set; env always wins.
CONF="${SECURITY_AUDIT_CONF:-$ROOT/.security-audit.conf}"
if [ -f "$CONF" ]; then
  # shellcheck disable=SC1090
  . "$CONF"
fi

GITLEAKS_VER="${GITLEAKS_VER:-v8.21.2}"
TRIVY_VER="${TRIVY_VER:-0.58.0}"
SYFT_VER="${SYFT_VER:-v1.18.0}"
SEMGREP_CONFIGS="${SEMGREP_CONFIGS:---config p/owasp-top-ten --config p/secrets --config p/javascript}"

have(){ command -v "$1" >/dev/null 2>&1; }
say(){ printf '\033[36m[scan:%s]\033[0m %s\n' "$1" "$2"; }
warn(){ printf '\033[33m[scan:%s] SKIP: %s\033[0m\n' "$1" "$2"; }

# uvx OR pipx run; if neither exists, skip (not HARD, just a missing tool).
uvx_run(){ if have uvx; then uvx "$@"; elif have pipx; then pipx run "$@"; else return 127; fi; }
docker_ok(){ have docker && docker info >/dev/null 2>&1; }

# ---- python deps (pip-audit) ----
scan_py_deps(){
  git ls-files | grep -qE 'pyproject\.toml|requirements.*\.txt|uv\.lock|Pipfile' || { warn deps "no Python project"; return 0; }
  local flags=""
  [ -f .pip-audit-ignore ] && flags="$(awk '/^[^#]/{printf " --ignore-vuln %s",$1}' .pip-audit-ignore)"
  say deps "pip-audit --strict"
  uvx_run pip-audit --strict $flags || { [ $? -eq 127 ] && { warn deps "no uvx/pipx -> pip-audit skipped"; return 0; }; return 1; }
}

# ---- js deps (pnpm/yarn/npm auto) ----
scan_js_deps(){
  local pj; pj="$(git ls-files '*package.json' | grep -v node_modules | head -1)"
  [ -z "$pj" ] && { warn deps "no JS project"; return 0; }
  local dir; dir="$(dirname "$pj")"
  ( cd "$dir"
    if [ -f pnpm-lock.yaml ] && have pnpm;  then say deps "pnpm audit ($dir)";  pnpm audit --prod --audit-level high
    elif [ -f yarn.lock ] && have yarn;     then say deps "yarn audit ($dir)";  yarn npm audit --severity high
    elif have npm;                          then say deps "npm audit ($dir)";   npm audit --omit=dev --audit-level=high
    else warn deps "no JS package manager"; fi )
}

# ---- secret (gitleaks) ----
scan_secret(){
  docker_ok || { warn secret "no docker -> gitleaks skipped"; return 0; }
  local cfg=""; [ -f .gitleaks.toml ] && cfg="--config /repo/.gitleaks.toml"
  say secret "gitleaks detect (history included)"
  docker run --rm -v "$ROOT:/repo" -w /repo ghcr.io/gitleaks/gitleaks:"$GITLEAKS_VER" \
    detect --source /repo $cfg --redact --exit-code 1 --verbose
}

# ---- sast (semgrep) ----
scan_sast(){
  # Default: whole repo (semgrep's default .semgrepignore skips node_modules/.git/.venv).
  # Override SAST_PATHS via env to narrow/speed up the scan.
  local paths="${SAST_PATHS:-.}"
  say sast "semgrep ($paths)"
  uvx_run --from semgrep semgrep scan $SEMGREP_CONFIGS --metrics off --error --severity ERROR $paths \
    || { [ $? -eq 127 ] && { warn sast "no uvx/pipx -> semgrep skipped"; return 0; }; return 1; }
}

# ---- iac (checkov) ----
scan_iac(){
  local tf="${TF_DIR:-}"
  [ -z "$tf" ] && tf="$(git ls-files '*.tf' | head -1 | xargs -r dirname)"
  [ -z "$tf" ] && { warn iac "no terraform"; return 0; }
  say iac "checkov ($tf)"
  uvx_run --from checkov checkov --directory "$tf" --framework terraform --soft-fail \
    || { [ $? -eq 127 ] && warn iac "no uvx/pipx -> checkov skipped"; return 0; }
}

# ---- container/fs (trivy) — soft ----
scan_container(){
  docker_ok || { warn container "no docker -> trivy skipped"; return 0; }
  say container "trivy fs (report, soft)"
  # .trivyignore.yaml auto-detect does not work in this docker setup -> pass it explicitly
  # (only if present; for deliberately accepted findings, committed to the repo).
  local ign=""; [ -f "$ROOT/.trivyignore.yaml" ] && ign="--ignorefile /repo/.trivyignore.yaml"
  docker run --rm -v "$ROOT:/repo" -w /repo aquasec/trivy:"$TRIVY_VER" fs \
    --scanners vuln,secret,misconfig,license --severity CRITICAL,HIGH --ignore-unfixed --exit-code 0 $ign /repo
}

# ---- sbom (syft) ----
scan_sbom(){
  docker_ok || { warn sbom "no docker -> syft skipped"; return 0; }
  say sbom "syft -> sbom.cyclonedx.json + sbom.spdx.json"
  docker run --rm -v "$ROOT:/repo" -w /repo anchore/syft:"$SYFT_VER" dir:/repo \
    -o cyclonedx-json=/repo/sbom.cyclonedx.json -o spdx-json=/repo/sbom.spdx.json
}

[ "${SKIP_SECURITY:-0}" = "1" ] && { say skip "SKIP_SECURITY=1 -> all scans skipped"; exit 0; }

run_scans(){
  local rc=0
  case "${1:-all}" in
    deps)      scan_py_deps || rc=1; scan_js_deps || rc=1 ;;
    secret)    scan_secret || rc=1 ;;
    sast)      scan_sast || rc=1 ;;
    iac)       scan_iac || rc=1 ;;
    container) scan_container || rc=1 ;;
    sbom)      scan_sbom || rc=1 ;;
    fast)      scan_secret || rc=1; scan_py_deps || rc=1; scan_js_deps || rc=1 ;;
    all)       scan_secret || rc=1; scan_sast || rc=1; scan_py_deps || rc=1; scan_js_deps || rc=1; scan_container || rc=1; scan_iac || rc=1 ;;
    *) echo "unknown command: $1 (deps|secret|sast|iac|container|sbom|fast|all)"; return 2 ;;
  esac
  return $rc
}

# Every scan: write raw output to a per-day file (persistent trail) + print a triage
# instruction at the end. So the user does not have to remember "what next" — the scan
# itself says it. raw-*.log is transient (gitignored); the persistent record is the
# triage's findings-*.md.
CMD="${1:-all}"
TODAY="$(date +%F)"
LOG_DIR="$ROOT/docs/security/scan-findings"
LOG="$LOG_DIR/raw-$TODAY.log"
mkdir -p "$LOG_DIR"
printf '\n===== %s  scan.sh %s =====\n' "$(date +%FT%T)" "$CMD" >> "$LOG"

run_scans "$CMD" 2>&1 | tee -a "$LOG"
rc=${PIPESTATUS[0]}

printf '\n\033[36m── raw report: %s\033[0m\n' "${LOG#"$ROOT"/}"
printf '\033[36m── NEXT STEP — for triage + findings-%s.md, in Claude Code:  /sec-triage\033[0m\n' "$TODAY"
[ "$rc" -ne 0 ] && printf '\033[31m── HARD finding (rc=%s): commit/push is blocked; allowlist if FP, fix if real.\033[0m\n' "$rc"
exit "$rc"
