#!/usr/bin/env bash
# security-audit-kit / scan.sh — portable, CI-independent local security scanning.
# Assumes no installation: auto-detects the toolchain and runs PINNED versions via
# uvx/pipx (semgrep/checkov/pip-audit) + docker (gitleaks/trivy/syft).
#
# Usage:  ./scan.sh <command>
#   deps      Dependency CVE (pip-audit + js audit)         [HARD]  fast
#   secret    Secret scan (gitleaks, full history)          [HARD]
#   staged    Secret scan of STAGED changes only            [HARD]  sub-second
#   sast      Static analysis (semgrep ERROR)               [HARD]
#   changed   SAST on CHANGED files only (diff-aware)        [HARD]  fast
#   iac       IaC misconfig (checkov, if terraform present) [soft]
#   container Dep+OS+secret+misconfig (trivy fs)            [soft]
#   sbom      Software inventory (syft CycloneDX+SPDX)       [artifact]
#   fast      staged + deps  (pre-commit / package install)
#   all       secret + sast + deps + container + iac         (pre-push / pre-PR)
#   doctor    Report toolchain, pins and detected projects   (no scan, no logs)
#
# Env override: SAST_PATHS, TF_DIR, SEMGREP_CONFIGS, SKIP_SECURITY=1 (skip all),
#   SARIF=1 (also emit SARIF into docs/security/scan-findings/sarif/),
#   pins: GITLEAKS_VER/_DIGEST, TRIVY_VER/_DIGEST, SYFT_VER/_DIGEST,
#         SEMGREP_VER, CHECKOV_VER, PIP_AUDIT_VER.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || exit 1

# Per-project config (committed to the repo, shared with the team). Precedence is
# env > conf > default: the conf only affects variables you did NOT set; env always wins.
CONF="${SECURITY_AUDIT_CONF:-$ROOT/.security-audit.conf}"
if [ -f "$CONF" ]; then
  # shellcheck disable=SC1090
  . "$CONF"
fi

# Docker tools — pinned by IMMUTABLE digest (preferred) with a human-readable tag.
# To bump: set both the *_VER and *_DIGEST (or clear the digest to fall back to the tag).
GITLEAKS_VER="${GITLEAKS_VER:-v8.21.2}"
GITLEAKS_DIGEST="${GITLEAKS_DIGEST:-sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46}"
TRIVY_VER="${TRIVY_VER:-0.58.0}"
TRIVY_DIGEST="${TRIVY_DIGEST:-sha256:b88012e2a0a309d6a8a00463d4e63e5e513377fb74eccbc8f9b0f8f81940ebeb}"
SYFT_VER="${SYFT_VER:-v1.18.0}"
SYFT_DIGEST="${SYFT_DIGEST:-sha256:a2066c7d582669db5c9191ed8b8055766a63a3c231b4134a5c75e65a70f30b23}"

# Python tools — pinned by version (no drift vs. CI). Empty = latest (not recommended).
SEMGREP_VER="${SEMGREP_VER:-1.166.0}"
CHECKOV_VER="${CHECKOV_VER:-3.3.1}"
PIP_AUDIT_VER="${PIP_AUDIT_VER:-2.10.1}"

SEMGREP_CONFIGS="${SEMGREP_CONFIGS:---config p/owasp-top-ten --config p/secrets --config p/javascript}"

have(){ command -v "$1" >/dev/null 2>&1; }
say(){ printf '\033[36m[scan:%s]\033[0m %s\n' "$1" "$2"; }
warn(){ printf '\033[33m[scan:%s] SKIP: %s\033[0m\n' "$1" "$2"; }

# Run a pinned Python CLI on-demand via uvx OR pipx (different spec flags).
# args: <package> <version> <command> [args...]
pyrun(){
  local pkg="$1" ver="$2" cmd="$3"; shift 3
  local spec="$pkg"; [ -n "$ver" ] && spec="$pkg==$ver"
  if have uvx; then uvx --from "$spec" "$cmd" "$@"
  elif have pipx; then pipx run --spec "$spec" "$cmd" "$@"
  else return 127; fi
}
docker_ok(){ have docker && docker info >/dev/null 2>&1; }

# Resolve an image reference: prefer the immutable digest over the mutable tag.
# args: <image> <tag> <digest>
img(){ if [ -n "${3:-}" ]; then printf '%s@%s' "$1" "$3"; else printf '%s:%s' "$1" "$2"; fi; }

# SARIF (opt-in): repo-relative path of a SARIF file under the findings dir.
sarif_rel(){ printf '%s/%s' "${SARIF_DIR#"$ROOT"/}" "$1"; }

# ---- python deps (pip-audit) ----
scan_py_deps(){
  git ls-files | grep -qE 'pyproject\.toml|requirements.*\.txt|uv\.lock|Pipfile' || { warn deps "no Python project"; return 0; }
  local flags=""
  [ -f .pip-audit-ignore ] && flags="$(awk '/^[^#]/{printf " --ignore-vuln %s",$1}' .pip-audit-ignore)"
  say deps "pip-audit --strict (==$PIP_AUDIT_VER)"
  # shellcheck disable=SC2086
  pyrun pip-audit "$PIP_AUDIT_VER" pip-audit --strict $flags || { [ $? -eq 127 ] && { warn deps "no uvx/pipx -> pip-audit skipped"; return 0; }; return 1; }
}

# ---- js deps (pnpm/yarn/npm auto) ----
scan_js_deps(){
  local pj; pj="$(git ls-files '*package.json' | grep -v node_modules | head -1)"
  [ -z "$pj" ] && { warn deps "no JS project"; return 0; }
  local dir; dir="$(dirname "$pj")"
  ( cd "$dir" || exit 1
    if [ -f pnpm-lock.yaml ] && have pnpm;  then say deps "pnpm audit ($dir)";  pnpm audit --prod --audit-level high
    elif [ -f yarn.lock ] && have yarn;     then say deps "yarn audit ($dir)";  yarn npm audit --severity high
    elif have npm;                          then say deps "npm audit ($dir)";   npm audit --omit=dev --audit-level=high
    else warn deps "no JS package manager"; fi )
}

# ---- secret, full history (gitleaks detect) ----
scan_secret(){
  docker_ok || { warn secret "no docker -> gitleaks skipped"; return 0; }
  local cfg=""; [ -f .gitleaks.toml ] && cfg="--config /repo/.gitleaks.toml"
  local rep=""; [ "$SARIF" = "1" ] && rep="--report-format sarif --report-path /repo/$(sarif_rel gitleaks.sarif)"
  say secret "gitleaks detect (full history)"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo" -w /repo "$(img ghcr.io/gitleaks/gitleaks "$GITLEAKS_VER" "$GITLEAKS_DIGEST")" \
    detect --source /repo $cfg $rep --redact --exit-code 1 --verbose
}

# ---- secret, staged changes only (gitleaks protect --staged) — sub-second ----
scan_secret_staged(){
  docker_ok || { warn secret "no docker -> staged secret scan skipped"; return 0; }
  local cfg=""; [ -f .gitleaks.toml ] && cfg="--config /repo/.gitleaks.toml"
  say secret "gitleaks protect --staged"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo" -w /repo "$(img ghcr.io/gitleaks/gitleaks "$GITLEAKS_VER" "$GITLEAKS_DIGEST")" \
    protect --staged --source /repo $cfg --redact --exit-code 1 --verbose
}

# ---- sast (semgrep) ----
scan_sast(){
  # Default: whole repo (semgrep's default .semgrepignore skips node_modules/.git/.venv).
  # Override SAST_PATHS via env to narrow/speed up the scan.
  local paths="${SAST_PATHS:-.}"
  local out=""; [ "$SARIF" = "1" ] && out="--sarif --output $SARIF_DIR/semgrep.sarif"
  say sast "semgrep ($paths, ==$SEMGREP_VER)"
  # shellcheck disable=SC2086
  pyrun semgrep "$SEMGREP_VER" semgrep scan $SEMGREP_CONFIGS --metrics off --error --severity ERROR $out $paths \
    || { [ $? -eq 127 ] && { warn sast "no uvx/pipx -> semgrep skipped"; return 0; }; return 1; }
}

# ---- sast on changed files only (diff-aware, fast) ----
# Base ref: $BASE_REF, else merge-base with origin/main, else staged + unstaged changes.
changed_files(){
  local base="${BASE_REF:-}"
  if [ -z "$base" ] && git rev-parse --verify -q origin/main >/dev/null 2>&1; then
    base="$(git merge-base HEAD origin/main 2>/dev/null || true)"
  fi
  if [ -n "$base" ]; then
    git diff --name-only --diff-filter=ACMR "$base"
  else
    git diff --name-only --diff-filter=ACMR --cached
    git diff --name-only --diff-filter=ACMR
  fi
}
scan_sast_changed(){
  local files; files="$(changed_files | sort -u | while IFS= read -r f; do [ -f "$f" ] && printf '%s\n' "$f"; done)"
  [ -z "$files" ] && { warn sast "no changed files vs base -> semgrep skipped"; return 0; }
  local out=""; [ "$SARIF" = "1" ] && out="--sarif --output $SARIF_DIR/semgrep.sarif"
  say sast "semgrep (changed files, ==$SEMGREP_VER)"
  # shellcheck disable=SC2086
  pyrun semgrep "$SEMGREP_VER" semgrep scan $SEMGREP_CONFIGS --metrics off --error --severity ERROR $out $files \
    || { [ $? -eq 127 ] && { warn sast "no uvx/pipx -> semgrep skipped"; return 0; }; return 1; }
}

# ---- iac (checkov) ----
scan_iac(){
  local tf="${TF_DIR:-}"
  [ -z "$tf" ] && tf="$(git ls-files '*.tf' | head -1 | xargs -r dirname)"
  [ -z "$tf" ] && { warn iac "no terraform"; return 0; }
  say iac "checkov ($tf, ==$CHECKOV_VER)"
  pyrun checkov "$CHECKOV_VER" checkov --directory "$tf" --framework terraform --soft-fail \
    || { [ $? -eq 127 ] && warn iac "no uvx/pipx -> checkov skipped"; return 0; }
}

# ---- container/fs (trivy) — soft ----
scan_container(){
  docker_ok || { warn container "no docker -> trivy skipped"; return 0; }
  say container "trivy fs (report, soft)"
  # .trivyignore.yaml auto-detect does not work in this docker setup -> pass it explicitly
  # (only if present; for deliberately accepted findings, committed to the repo).
  local ign=""; [ -f "$ROOT/.trivyignore.yaml" ] && ign="--ignorefile /repo/.trivyignore.yaml"
  local out="--exit-code 0"; [ "$SARIF" = "1" ] && out="--exit-code 0 --format sarif --output /repo/$(sarif_rel trivy.sarif)"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo" -w /repo "$(img aquasec/trivy "$TRIVY_VER" "$TRIVY_DIGEST")" fs \
    --scanners vuln,secret,misconfig,license --severity CRITICAL,HIGH --ignore-unfixed $out $ign /repo
}

# ---- sbom (syft) ----
scan_sbom(){
  docker_ok || { warn sbom "no docker -> syft skipped"; return 0; }
  say sbom "syft -> sbom.cyclonedx.json + sbom.spdx.json"
  docker run --rm -v "$ROOT:/repo" -w /repo "$(img anchore/syft "$SYFT_VER" "$SYFT_DIGEST")" dir:/repo \
    -o cyclonedx-json=/repo/sbom.cyclonedx.json -o spdx-json=/repo/sbom.spdx.json
}

# ---- doctor: report environment, pins and detected projects (no scan) ----
scan_doctor(){
  printf '== security-audit-kit doctor ==\n'
  printf 'root   : %s\n' "$ROOT"
  printf 'config : %s\n\n' "$([ -f "$CONF" ] && echo "$CONF" || echo '(none; using defaults)')"
  printf 'toolchain (a missing one only skips that dimension):\n'
  docker_ok && echo "  ok  docker        (gitleaks/trivy/syft)" || echo "  --  docker        MISSING/not running -> secret/container/sbom skipped"
  { have uvx || have pipx; } && echo "  ok  uvx/pipx      (semgrep/checkov/pip-audit)" || echo "  --  uvx/pipx      MISSING -> sast/iac/py-deps skipped"
  { have pnpm || have yarn || have npm; } && echo "  ok  js pkg mgr    (js-deps)" || echo "  --  js pkg mgr    MISSING -> js-deps skipped"
  printf '\npins:\n'
  printf '  gitleaks   %s @ %s\n' "$GITLEAKS_VER" "${GITLEAKS_DIGEST:-<tag>}"
  printf '  trivy      %s @ %s\n' "$TRIVY_VER" "${TRIVY_DIGEST:-<tag>}"
  printf '  syft       %s @ %s\n' "$SYFT_VER" "${SYFT_DIGEST:-<tag>}"
  printf '  semgrep    %s\n' "${SEMGREP_VER:-<latest>}"
  printf '  checkov    %s\n' "${CHECKOV_VER:-<latest>}"
  printf '  pip-audit  %s\n' "${PIP_AUDIT_VER:-<latest>}"
  printf '\ndetected in this repo:\n'
  git ls-files 2>/dev/null | grep -qE 'pyproject\.toml|requirements.*\.txt|Pipfile|uv\.lock' && echo "  python"     || true
  git ls-files 2>/dev/null | grep -q  'package\.json'                                        && echo "  javascript" || true
  git ls-files 2>/dev/null | grep -q  '\.tf$'                                                && echo "  terraform"  || true
}

SARIF="${SARIF:-0}"

[ "${1:-}" = "doctor" ] && { scan_doctor; exit 0; }
[ "${SKIP_SECURITY:-0}" = "1" ] && { say skip "SKIP_SECURITY=1 -> all scans skipped"; exit 0; }

# Record each dimension's exit code to RESULTS_FILE (survives the tee subshell).
_dim(){ local name="$1"; shift; "$@"; local c=$?; printf '%s\t%s\n' "$name" "$c" >> "$RESULTS_FILE"; [ "$c" -ne 0 ] && return 1; return 0; }

run_scans(){
  local rc=0
  case "${1:-all}" in
    deps)      _dim py-deps scan_py_deps || rc=1; _dim js-deps scan_js_deps || rc=1 ;;
    secret)    _dim secret scan_secret || rc=1 ;;
    staged)    _dim staged scan_secret_staged || rc=1 ;;
    sast)      _dim sast scan_sast || rc=1 ;;
    changed)   _dim sast scan_sast_changed || rc=1 ;;
    iac)       _dim iac scan_iac || rc=1 ;;
    container) _dim container scan_container || rc=1 ;;
    sbom)      _dim sbom scan_sbom || rc=1 ;;
    fast)      _dim staged scan_secret_staged || rc=1; _dim py-deps scan_py_deps || rc=1; _dim js-deps scan_js_deps || rc=1 ;;
    all)       _dim secret scan_secret || rc=1; _dim sast scan_sast || rc=1; _dim py-deps scan_py_deps || rc=1; _dim js-deps scan_js_deps || rc=1; _dim container scan_container || rc=1; _dim iac scan_iac || rc=1 ;;
    *) echo "unknown command: $1 (deps|secret|staged|sast|changed|iac|container|sbom|fast|all|doctor)"; return 2 ;;
  esac
  return $rc
}

# Every scan: write raw output to a per-day file (persistent trail) + a machine-readable
# summary.json + (opt-in) SARIF, then print a triage instruction. raw-*.log/summary.json
# are transient (gitignored); the persistent record is the triage's findings-*.md.
CMD="${1:-all}"
TODAY="$(date +%F)"
LOG_DIR="$ROOT/docs/security/scan-findings"
LOG="$LOG_DIR/raw-$TODAY.log"
SUMMARY="$LOG_DIR/summary.json"
SARIF_DIR="$LOG_DIR/sarif"
RESULTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE"' EXIT
mkdir -p "$LOG_DIR"
[ "$SARIF" = "1" ] && mkdir -p "$SARIF_DIR"
printf '\n===== %s  scan.sh %s =====\n' "$(date +%FT%T)" "$CMD" >> "$LOG"

run_scans "$CMD" 2>&1 | tee -a "$LOG"
rc=${PIPESTATUS[0]}

# Machine-readable summary (consumed by /sec-triage; safe to parse).
{
  printf '{\n'
  printf '  "timestamp": "%s",\n' "$(date +%FT%T)"
  printf '  "command": "%s",\n' "$CMD"
  printf '  "exit_code": %s,\n' "$rc"
  printf '  "raw_log": "%s",\n' "${LOG#"$ROOT"/}"
  printf '  "sarif": %s,\n' "$([ "$SARIF" = "1" ] && echo true || echo false)"
  printf '  "dimensions": [\n'
  first=1
  while IFS="$(printf '\t')" read -r dim code; do
    [ -z "$dim" ] && continue
    [ "$first" = 1 ] || printf ',\n'
    first=0
    st=pass; [ "$code" -ne 0 ] && st=fail
    printf '    {"name": "%s", "exit_code": %s, "status": "%s"}' "$dim" "$code" "$st"
  done < "$RESULTS_FILE"
  printf '\n  ]\n}\n'
} > "$SUMMARY"

printf '\n\033[36m── raw report: %s   summary: %s\033[0m\n' "${LOG#"$ROOT"/}" "${SUMMARY#"$ROOT"/}"
[ "$SARIF" = "1" ] && printf '\033[36m── SARIF: %s/\033[0m\n' "${SARIF_DIR#"$ROOT"/}"
printf '\033[36m── NEXT STEP — for triage + findings-%s.md, in Claude Code:  /sec-triage\033[0m\n' "$TODAY"
[ "$rc" -ne 0 ] && printf '\033[31m── HARD finding (rc=%s): commit/push is blocked; allowlist if FP, fix if real.\033[0m\n' "$rc"
exit "$rc"
