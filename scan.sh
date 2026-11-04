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
#   osv       Broad multi-ecosystem dep CVE (osv-scanner)    [HARD]  optional (not in 'all')
#   guarddog  Malicious/typosquat deps (guarddog verify)     [HARD]  optional (not in 'all'; needs network)
#   zizmor    GitHub Actions security (zizmor, if workflows) [HARD]  optional (not in 'all')
#   pkgcheck  ONE named package BEFORE install (guarddog)   [HARD]  optional; agent-hook entry point
#   fast      staged + deps  (pre-commit / package install)
#   all       secret + sast + deps + container + iac         (pre-push / pre-PR)
#   doctor    Report toolchain, pins and detected projects   (no scan, no logs)
#   warm      Pull the pinned images + the trivy DB now        (one-time downloads; no scan)
#   verify    Check the kit's files against CHECKSUMS         (integrity; no scan)
#   checksums (Re)generate the CHECKSUMS manifest             (maintainer)
#   rules-test Run semgrep --test over the repo's OWN rules    (no scan)
#   allowlist Audit suppressions: expired + cross-path gaps    (no scan; exit 1 on either)
#   evidence  Rebuild evidence.json from the SARIF on disk    (normalized findings; no scan)
#   report    Render evidence.json as one HTML file           (offline, print-to-PDF; no scan)
#
# Env override: SAST_PATHS, TF_DIR, SEMGREP_CONFIGS, SKIP_SECURITY=1 (skip all),
#   SARIF=1 (also emit SARIF into docs/security/scan-findings/sarif/),
#   REPORT=html (also render docs/security/scan-findings/report-<date>.html),
#   SEMGREP_LOCAL_RULES=<paths|off> (repo-local rule dirs; default: auto-discover .semgrep/),
#   OSV_CALL_ANALYSIS=go (reachability signal in scan.sh osv; adds --all-vulns so the gate is
#     unchanged. rust also works but RUNS dependency build scripts -> refused unless
#     OSV_ALLOW_BUILD_SCRIPTS=1),
#   TRIVY_CACHE=<volume|/abs/path>, TRIVY_DB_MAX_AGE_H=24, SCAN_OFFLINE=1 (trivy DB cache: never download),
#   pins: GITLEAKS_VER/_DIGEST, TRIVY_VER/_DIGEST, SYFT_VER/_DIGEST,
#         SEMGREP_VER, CHECKOV_VER, PIP_AUDIT_VER, GUARDDOG_VER, ZIZMOR_VER.
set -uo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT" || exit 1

# Directory of the kit itself (where this script lives) — distinct from ROOT, which is the
# TARGET repo. Used by `verify`/`checksums` so integrity is checked against the kit's files.
KIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

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
OSV_VER="${OSV_VER:-v2.4.0}"
OSV_DIGEST="${OSV_DIGEST:-sha256:5116601dedc01c1c580eb92371883ec052fc4c13c3fbc109d621a63ac416d475}"

# A dimension that could not LOOK at anything is not a pass. `pass` and `fail` both claim the tool
# formed an opinion; there has to be a third answer for "it ran and had nothing to read", or the
# gate goes green on a repo it never inspected. Same principle the pkgcheck gate already uses for a
# package it could not fetch: allowed, loudly, never cleared. Non-blocking by design — refusing what
# we failed to look at would block ordinary work, and a gate people route around protects nothing.
RC_INDETERMINATE=3

# trivy: skip build-output dirs (noise + memory + speed). Comma-separated glob patterns.
TRIVY_SKIP_DIRS="${TRIVY_SKIP_DIRS:-**/.next,**/dist,**/build,**/.nuxt,**/.svelte-kit,**/.turbo}"
# The exit code trivy is told to use for findings — internal, so container (soft) can tell findings
# from a clean run and from a failed one.
TRIVY_FINDINGS_RC=5
# trivy keeps its vulnerability DB (~130 MiB) in a cache dir. Without a persistent one, every run
# re-downloaded it: measured 36–51 s of the container scan, against ~1 s with the DB cached (same
# findings). A named docker volume lives in the docker VM (fast on macOS, nothing written to the
# repo); an absolute path bind-mounts that directory instead, for a CI cache.
TRIVY_CACHE="${TRIVY_CACHE:-security-audit-trivy}"
# The DB is rebuilt upstream once a day (its NextUpdate is UpdatedAt + 24h): refreshing more often
# buys nothing, waiting longer lets new advisories lag. Older than this -> trivy refreshes it.
TRIVY_DB_MAX_AGE_H="${TRIVY_DB_MAX_AGE_H:-24}"
# 1 = never download a scanner database: use the cached one at any age; none cached -> "skipped".
SCAN_OFFLINE="${SCAN_OFFLINE:-0}"

# js-deps: which directories hold a JS project. JS_DIRS (space separated) overrides the search
# outright; otherwise every tracked package.json is considered except the paths JS_SKIP_RE drops —
# vendored front-end assets checked into a backend repo are third-party files nobody here maintains.
JS_DIRS="${JS_DIRS:-}"
JS_SKIP_RE="${JS_SKIP_RE:-(^|/)(node_modules|bower_components|vendor|third[_-]party|static|assets|public|dist|build|coverage|\.venv|site-packages)/}"

# py-deps: the environment pip-audit inspects. Empty = the repo's .venv, else an active VIRTUAL_ENV
# that is a real venv inside this repo, else the static-manifest path. Set it to audit an env that
# lives elsewhere (a shared venv, a container-built one); the run names it and says why.
PY_VENV="${PY_VENV:-}"

# Python tools — pinned by version (no drift vs. CI). Empty = latest (not recommended).
SEMGREP_VER="${SEMGREP_VER:-1.166.0}"
CHECKOV_VER="${CHECKOV_VER:-3.3.1}"
PIP_AUDIT_VER="${PIP_AUDIT_VER:-2.10.1}"
GUARDDOG_VER="${GUARDDOG_VER:-3.0.2}"
ZIZMOR_VER="${ZIZMOR_VER:-1.26.1}"
# zizmor extra args (persona/severity tuning). Runs offline by default (no GitHub API).
ZIZMOR_ARGS="${ZIZMOR_ARGS:-}"

# Stack-aware semgrep rulesets. If SEMGREP_CONFIGS is set (env/conf) it wins verbatim;
# otherwise we auto-select language/framework packs from what's actually in the repo, so each
# project gets its own injection rules (Django ORM, React XSS, …) instead of a one-size config.
# Base packs (always): owasp-top-ten (incl. injection A03) + secrets. Only registry packs that
# exist are referenced (a missing pack would hard-fail this deterministic gate).
# `semgrep-rules/` is listed first and is the RECOMMENDED home: semgrep's own test runner skips
# HIDDEN directories, so rules under `.semgrep/` scan fine but their tests are never discovered —
# and an untested rule is exactly the thing that rots. `.semgrep*` stays supported for repos that
# already use it.
LOCAL_RULES_ANCHORS="semgrep-rules .semgrep .semgrep.yml .semgrep.yaml"

detect_semgrep_configs(){
  local cfg="--config p/owasp-top-ten --config p/secrets"
  local files; files="$(git ls-files 2>/dev/null | grep -v node_modules)"
  # The VENDORED kit's own files must not define the target repo's stack: the kit ships
  # landing/build.py + python tooling, which would pull p/python into every consumer, even a
  # pure JS/Go repo. Only strip when the kit lives inside the target repo (self-scan, where
  # KIT_DIR == ROOT, must keep seeing its own files).
  case "$KIT_DIR" in
    "$ROOT") ;;
    "$ROOT"/*) files="$(printf '%s\n' "$files" | awk -v p="${KIT_DIR#"$ROOT"/}/" 'index($0,p)!=1')" ;;
  esac
  # Same reasoning for the repo's own rule directory: a rule's TEST FIXTURE (`.semgrep/foo.py`
  # next to `foo.yaml`) is material for the rule, not the project's stack. Left in, one python
  # fixture pulls p/python into a repo with no python at all.
  local anchor
  for anchor in $LOCAL_RULES_ANCHORS; do
    files="$(printf '%s\n' "$files" | awk -v p="$anchor/" 'index($0,p)!=1')"
  done
  # Dependency-manifest contents (small files only) — used to detect frameworks by package name.
  local manifests mtext=""
  manifests="$(printf '%s\n' "$files" | grep -E '(^|/)(requirements[^/]*\.txt|pyproject\.toml|Pipfile|package\.json|composer\.json|Gemfile)$')"
  [ -n "$manifests" ] && mtext="$(printf '%s\n' "$manifests" | while IFS= read -r m; do [ -f "$m" ] && cat "$m"; done)"
  # here-strings, not pipes — see has_tracked: `printf | grep -q` loses the same way, and losing
  # here means semgrep silently drops p/python, p/django, p/javascript and scans with base rules.
  _hasf(){ grep -qE "$1" <<<"$files"; }
  _dep(){ grep -qiE "$1" <<<"$mtext"; }

  if _hasf '\.py$' || _hasf '(^|/)(pyproject\.toml|requirements[^/]*\.txt|Pipfile|uv\.lock)$'; then
    cfg="$cfg --config p/python"
    { _hasf '(^|/)(manage|settings|asgi|wsgi)\.py$' || _dep '(^|[^a-z])django'; } && cfg="$cfg --config p/django"
    _dep '(^|[^a-z])flask' && cfg="$cfg --config p/flask"
  fi
  if _hasf '(^|/)package\.json$'; then
    cfg="$cfg --config p/javascript"
    _hasf '\.tsx?$' && cfg="$cfg --config p/typescript"
    { _hasf '\.(jsx|tsx)$' || _dep '"react"'; } && cfg="$cfg --config p/react"
  fi
  _hasf '\.go$|(^|/)go\.mod$'                          && cfg="$cfg --config p/golang"
  _hasf '\.java$|(^|/)pom\.xml$|(^|/)build\.gradle'    && cfg="$cfg --config p/java"
  _hasf '\.php$|(^|/)composer\.json$'                  && cfg="$cfg --config p/php"
  _hasf '\.rb$|(^|/)Gemfile$'                          && cfg="$cfg --config p/ruby"
  _hasf '\.cs$|\.csproj$'                              && cfg="$cfg --config p/csharp"
  printf '%s' "$cfg"
}
# ---- repo-local custom rules (the consumer's own invariants) ----
# The kit owns the MECHANISM, the consumer owns the RULES: nothing project-specific ships here.
# Discovery is anchored at literal paths under $ROOT — never `git ls-files | grep`, which would let
# the VENDORED kit's own rule files define the consumer's ruleset (the v1.12.0 p/python class).
# `SEMGREP_LOCAL_RULES=<path...>` overrides discovery; `=off` disables it entirely.

local_rules_paths(){   # -> the anchors that actually exist, space separated, relative to $ROOT
  [ "${SEMGREP_LOCAL_RULES:-}" = "off" ] && return 0
  if [ -n "${SEMGREP_LOCAL_RULES:-}" ]; then printf '%s' "$SEMGREP_LOCAL_RULES"; return 0; fi
  local out="" p
  for p in $LOCAL_RULES_ANCHORS; do
    [ -e "$ROOT/$p" ] && out="$out $p"
  done
  printf '%s' "${out# }"
}

local_rules_files(){   # -> every rule FILE under the anchors (for counting/inspection)
  local p
  for p in $(local_rules_paths); do
    if [ -d "$ROOT/$p" ]; then
      find "$ROOT/$p" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null
    elif [ -f "$ROOT/$p" ]; then
      printf '%s\n' "$ROOT/$p"
    fi
  done
}

# id + severity per rule. `scan_sast` runs `--severity ERROR`, so a rule written at WARNING/INFO is
# loaded and then silently ignored — "the rule exists, it just never gates". doctor must say so.
local_rules_index(){
  local f
  for f in $(local_rules_files); do
    awk '
      /^[[:space:]]*-?[[:space:]]*id:[[:space:]]*/ {
        id = $0; sub(/.*id:[[:space:]]*/, "", id); gsub(/["'"'"']/, "", id); gsub(/[[:space:]]+$/, "", id)
      }
      /^[[:space:]]*severity:[[:space:]]*/ {
        sev = $0; sub(/.*severity:[[:space:]]*/, "", sev); gsub(/[^A-Za-z]/, "", sev)
        if (id != "") { print id "\t" toupper(sev); id = "" }
      }
    ' "$f"
  done
}

[ -n "${SEMGREP_CONFIGS:-}" ] && SEMGREP_CONFIGS_OVERRIDDEN=1
# BASE = the override verbatim, else the stack-auto packs. LOCAL is appended to EITHER: adding one
# hand-written rule must never cost you the OWASP/stack packs (before, setting SEMGREP_CONFIGS to
# reach a local rule silently replaced the whole list, and that list then rotted as the stack moved).
SEMGREP_CONFIGS_BASE="${SEMGREP_CONFIGS:-$(detect_semgrep_configs)}"
SEMGREP_CONFIGS_LOCAL=""
for _p in $(local_rules_paths); do SEMGREP_CONFIGS_LOCAL="$SEMGREP_CONFIGS_LOCAL --config $_p"; done
unset _p
SEMGREP_CONFIGS="$SEMGREP_CONFIGS_BASE$SEMGREP_CONFIGS_LOCAL"

have(){ command -v "$1" >/dev/null 2>&1; }
say(){ printf '\033[36m[scan:%s]\033[0m %s\n' "$1" "$2"; }
warn(){ printf '\033[33m[scan:%s] SKIP: %s\033[0m\n' "$1" "$2"; DIM_WARN="$2"; }
# What a dimension's outcome WAS, for summary.json (F02) — separate from the gate. The return code
# still decides the gate exactly as before; these only stop "docker missing" or "the tool crashed"
# from being recorded as a pass. Unmarked: 0 pass, 1 findings, 3 indeterminate, other error.
dim_mark(){ DIM_STATUS="$1"; [ -n "${2:-}" ] && DIM_REASON="$2"; return 0; }
dim_skip(){ warn "$1" "$2"; dim_mark skipped "$2"; }          # could have run, a tool was missing
dim_na(){ warn "$1" "$2"; dim_mark not_applicable "$2"; }     # nothing of this kind in the repo
dim_error(){ warn "$1" "$2"; dim_mark error "$2"; }           # the tool ran and failed
# Same colour, no "SKIP:" — for things that were not skipped but must not go unread (the lock).
note(){ printf '\033[33m[scan:%s] %s\033[0m\n' "$1" "$2"; }

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

# ---- tracked-file matching: never `git ls-files | grep -q` --------------------------------------
# That pipeline is a SILENT FALSE NEGATIVE on a large repo, and it silences whole dimensions.
# `grep -q` exits at the FIRST match; git is still writing, gets SIGPIPE, and `set -o pipefail`
# (line 38) turns the pipeline's status into 141 -> the `||` branch runs -> "no Python project".
# It is size-dependent, so it PASSES on every small fixture repo and starts lying once a real repo
# outgrows the pipe buffer: measured on a 22,972-file repo, py-deps (pip-audit), zizmor AND the
# semgrep stack auto-select had all quietly switched themselves off while the scan reported green.
# The rule this file follows now: whatever decides that a dimension runs must CONSUME its input.
# A command substitution reads git to completion, and a here-string feeds grep from a temp file —
# no pipe anywhere, so nothing can be killed out from under the match. tests/e2e.sh enforces both
# the rule (a static guard) and the behaviour (a >6000-file fixture repo).
has_tracked(){ grep -qE "$1" <<<"$(git ls-files 2>/dev/null)"; }

# A directory's physical path (symlinks resolved: macOS /var -> /private/var), or the input as-is
# if it does not exist — so "is X inside the repo" compares like with like.
real_dir(){ (cd -P -- "$1" 2>/dev/null && pwd -P) || printf '%s\n' "$1"; }

# ---- python deps (pip-audit) ----
# Tracked python dependency manifests osv-scanner can read STATICALLY, minus the vendored kit's own
# fixtures (material for a test, not this project's dependencies).
py_manifests(){
  local kit_rel="" f out=""
  case "$KIT_DIR" in "$ROOT"/*) kit_rel="${KIT_DIR#"$ROOT"/}/" ;; esac
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if [ -n "$kit_rel" ]; then case "$f" in "$kit_rel"*) continue ;; esac; fi
    out="$out $f"
  done <<<"$(git ls-files -- '*requirements*.txt' '*uv.lock' '*Pipfile.lock' '*poetry.lock' '*pdm.lock' 2>/dev/null)"
  # shellcheck disable=SC2086
  printf '%s\n' $out
}

scan_py_deps(){
  has_tracked '(^|/)(pyproject\.toml|requirements[^/]*\.txt|uv\.lock|Pipfile)$' \
    || { dim_na deps "no Python project"; return 0; }
  local flags=""
  [ -f .pip-audit-ignore ] && flags="$(awk '/^[^#]/{printf " --ignore-vuln %s",$1}' .pip-audit-ignore)"
  # Audit THIS repo's environment — not uvx's ephemeral one, and not whatever venv the caller
  # happens to have active. pip-audit defaults to the running interpreter (empty under uvx), so we
  # point it somewhere explicitly. Auditing another project's environment reports a green (or red)
  # py-deps saying nothing about this repo — a silently wrong answer, the worst kind for a gate.
  # Order: PY_VENV (explicit opt-in, any path) > the repo's .venv > an active VIRTUAL_ENV, and the
  # last only if it is a real venv (pyvenv.cfg) that lives INSIDE this repo. Anything else falls
  # through to the no-env path (static manifests or INDETERMINATE) and the run says why.
  local venv="" why=""
  if [ -n "$PY_VENV" ]; then
    [ -x "$PY_VENV/bin/python" ] \
      || { dim_error deps "PY_VENV=$PY_VENV has no bin/python -> cannot audit the env you named"; return 1; }
    venv="$PY_VENV"; why="PY_VENV"
  elif [ -x "$ROOT/.venv/bin/python" ]; then
    venv="$ROOT/.venv"; why="repo .venv"
    [ -n "${VIRTUAL_ENV:-}" ] && [ "$(real_dir "$VIRTUAL_ENV")" != "$(real_dir "$venv")" ] \
      && warn deps "active VIRTUAL_ENV ($VIRTUAL_ENV) is not this repo's venv -> auditing .venv"
  elif [ -n "${VIRTUAL_ENV:-}" ]; then
    local ve; ve="$(real_dir "$VIRTUAL_ENV")"
    if [ ! -f "$VIRTUAL_ENV/pyvenv.cfg" ] || [ ! -x "$VIRTUAL_ENV/bin/python" ]; then
      warn deps "active VIRTUAL_ENV ($VIRTUAL_ENV) is not a venv (no pyvenv.cfg) -> ignored"
    else
      case "$ve" in
        "$(real_dir "$ROOT")"/*) venv="$VIRTUAL_ENV"; why="active venv inside the repo" ;;
        *) warn deps "active VIRTUAL_ENV ($VIRTUAL_ENV) is not inside this repo -> ignored (set PY_VENV to audit it anyway)" ;;
      esac
    fi
  fi
  if [ -z "$venv" ]; then scan_py_deps_no_env; return $?; fi

  local label="$venv" rv rr; rv="$(real_dir "$venv")"; rr="$(real_dir "$ROOT")"
  case "$rv" in "$rr"/*) label="${rv#"$rr"/}" ;; esac
  export PIPAPI_PYTHON_LOCATION="$venv/bin/python"
  say deps "pip-audit --strict (==$PIP_AUDIT_VER, env $label — $why)"
  # shellcheck disable=SC2086
  pyrun pip-audit "$PIP_AUDIT_VER" pip-audit --strict $flags || { [ $? -eq 127 ] && { dim_skip deps "no uvx/pipx -> pip-audit skipped"; return 0; }; return 1; }
}

# No environment to inspect — the normal shape for a project that runs in a container. Auditing the
# ambient interpreter here is what produced the failure this exists to prevent: measured on a
# containerised Django repo, pip-audit reported "No known vulnerabilities found" against an EMPTY
# environment while the committed requirements.txt carried 208 advisories across 37 packages, one of
# them CVSS 9.8. A gate is not allowed to be green about something it never looked at.
#
# The obvious repair — `pip-audit -r requirements.txt` — is NOT usable here: pip-audit's requirement
# source creates a virtualenv and installs the file to resolve it (`--no-deps` does not avoid it),
# so it executes the dependency tree's build scripts. Running untrusted code to decide what to
# report is the same own-goal the kit already refuses for `OSV_CALL_ANALYSIS=rust`. osv-scanner
# reads the same manifests statically — no build, no install — and is already pinned in this kit, so
# the no-venv path delegates to it instead of reaching for a new tool.
scan_py_deps_no_env(){
  local man; man="$(py_manifests)"
  if [ -z "$man" ]; then
    warn deps "INDETERMINATE — no project venv, and no manifest that can be read without building the project (pyproject.toml alone is not one). pip-audit had nothing to inspect; this is NOT a clean result."
    return "$RC_INDETERMINATE"
  fi
  if ! docker_ok; then
    warn deps "INDETERMINATE — no project venv, and no docker to read the manifests with osv-scanner. Nothing was inspected; this is NOT a clean result."
    return "$RC_INDETERMINATE"
  fi
  local f targets=""
  for f in $man; do targets="$targets -L /repo/$f"; done
  # shellcheck disable=SC2086
  say deps "no project venv -> osv-scanner reads the committed manifests (static; nothing is built or installed):$(printf ' %s' $man)"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo:ro" -w /repo "$(img ghcr.io/google/osv-scanner "$OSV_VER" "$OSV_DIGEST")" \
    scan source $targets
  local rc=$?
  case "$rc" in
    0) return 0 ;;
    1) return 1 ;;
    128) warn deps "INDETERMINATE — osv-scanner could not parse any of those manifests; nothing was inspected."; return "$RC_INDETERMINATE" ;;
    *)  warn deps "INDETERMINATE — osv-scanner exit $rc (scan error, not a finding); nothing was inspected."; return "$RC_INDETERMINATE" ;;
  esac
}

# ---- js deps (pnpm/yarn/npm auto) ----
# WHICH directory gets audited is a correctness question, not a detail. Taking the first tracked
# package.json walks straight into vendored front-end assets — in a Django repo that is
# `static/assets/plugins/fullcalendar/packages/bootstrap/package.json`, a third-party file with no
# lockfile, so `npm audit` exits ENOLOCK=1 and the gate BLOCKS EVERY COMMIT that touches a manifest
# over a package nobody in the repo owns. Worse, it hides the real front-end: only the first hit was
# ever audited. Two rules now: vendor paths are dropped (JS_SKIP_RE), and a directory is auditable
# only if it carries a LOCKFILE — without one there are no resolved versions, so there is nothing to
# report and "cannot audit" must not read as "vulnerable". Every remaining directory is audited, not
# just the first. JS_DIRS overrides the search entirely.
js_dirs(){
  # shellcheck disable=SC2086  # word splitting is the point: a space-separated list -> one per line
  [ -n "$JS_DIRS" ] && { printf '%s\n' $JS_DIRS; return 0; }
  local pj dir out=""
  while IFS= read -r pj; do
    [ -n "$pj" ] || continue
    grep -qE "$JS_SKIP_RE" <<<"$pj" && continue
    dir="$(dirname "$pj")"
    [ -f "$ROOT/$dir/pnpm-lock.yaml" ] || [ -f "$ROOT/$dir/yarn.lock" ] || [ -f "$ROOT/$dir/package-lock.json" ] || continue
    case " $out " in *" $dir "*) ;; *) out="$out $dir" ;; esac
  done <<<"$(git ls-files '*package.json' 2>/dev/null)"
  # shellcheck disable=SC2086
  printf '%s\n' $out
}

scan_js_deps(){
  local dirs; dirs="$(js_dirs)"
  if [ -z "$dirs" ]; then
    if has_tracked '(^|/)package\.json$'; then
      dim_skip deps "package.json found but none is auditable (vendor path, or no lockfile) -> set JS_DIRS to point at the real JS project"
    else
      dim_na deps "no JS project"
    fi
    return 0
  fi
  local rc=0 dir n=0 skipped=0 c
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    n=$((n+1))
    ( cd "$ROOT/$dir" || exit 1
      # Audit ALL deps (incl. dev/build) — vulns in build tooling (vite/undici/…) are real; the
      # triage layer decides reachability. (Previously --prod/--omit=dev hid them.)
      if   [ -f pnpm-lock.yaml ]    && have pnpm; then say deps "pnpm audit ($dir)"; pnpm audit --audit-level high
      elif [ -f yarn.lock ]         && have yarn; then say deps "yarn audit ($dir)"; yarn npm audit --severity high
      elif [ -f package-lock.json ] && have npm;  then say deps "npm audit ($dir)";  npm audit --audit-level=high
      else warn deps "$dir: no lockfile with an installed package manager (pnpm/yarn/npm) -> skipped"; exit 4; fi )
    c=$?
    # 4 = this directory was not audited (the subshell's warn cannot reach DIM_* out here)
    if [ "$c" -eq 4 ]; then skipped=$((skipped+1)); elif [ "$c" -ne 0 ]; then rc=1; fi
  done <<<"$dirs"
  if [ "$skipped" -gt 0 ] && [ "$skipped" -eq "$n" ]; then
    dim_mark skipped "no installed package manager for any JS project's lockfile -> nothing audited"
  elif [ "$skipped" -gt 0 ]; then
    dim_mark "" "$skipped of $n JS project(s) not audited (no installed package manager for the lockfile)"
  fi
  return $rc
}

# Extra docker mounts so gitleaks can reach git history in a git WORKTREE — whose .git is a
# FILE pointing to a gitdir OUTSIDE the worktree (else gitleaks silently scans 0 commits and
# reports "no leaks", a false-clean). No-op for a normal repo (.git is a directory).
git_extra_mounts(){
  [ -f "$ROOT/.git" ] || return 0
  local common; common="$(git rev-parse --git-common-dir 2>/dev/null)" || return 0
  case "$common" in /*) ;; *) common="$ROOT/$common" ;; esac
  [ -n "$common" ] && [ -d "$common" ] && printf -- '-v %s:%s:ro' "$common" "$common"
}

# Docker scanners read the repo READ-ONLY (F11): a scanner is handed attacker-controllable files
# and has no business writing into the tree it reads. Output goes to a separate writable mount, this
# run's own dir, mounted at /out. (Docker is isolation from the host's processes, not a sandbox
# claim: the container still has the network, and runs as root, so files it writes to /out are
# owned by root on Linux.) out_mount <dir> -> fills OUTM, an argument array for `docker run`.
out_mount(){ OUTM=(); [ -n "${1:-}" ] || return 0; mkdir -p "$1" && OUTM=(-v "$1:/out"); }

# ---- secret, full history (gitleaks detect) ----
scan_secret(){
  docker_ok || { dim_skip secret "no docker -> gitleaks skipped"; return 0; }
  local cfg=""; [ -f .gitleaks.toml ] && cfg="--config /repo/.gitleaks.toml"
  local rep="" OUTM=()
  if [ "$SARIF" = "1" ]; then rep="--report-format sarif --report-path /out/gitleaks.sarif"; out_mount "$SARIF_DIR"; fi
  say secret "gitleaks detect (full history)"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo:ro" $(git_extra_mounts) "${OUTM[@]+"${OUTM[@]}"}" -w /repo "$(img ghcr.io/gitleaks/gitleaks "$GITLEAKS_VER" "$GITLEAKS_DIGEST")" \
    detect --source /repo $cfg $rep --redact --exit-code 1 --verbose
}

# ---- secret, staged changes only (gitleaks protect --staged) — sub-second ----
scan_secret_staged(){
  docker_ok || { dim_skip secret "no docker -> staged secret scan skipped"; return 0; }
  local cfg=""; [ -f .gitleaks.toml ] && cfg="--config /repo/.gitleaks.toml"
  # A merge stages the whole other branch. Blocking the merger on content already committed there
  # protects nothing (it is upstream already) and teaches SKIP_SECURITY=1. Seen on a real repo: a
  # 1389-commit merge blocked on QA digests and test data that dev had carried for months.
  if git rev-parse -q --verify MERGE_HEAD >/dev/null 2>&1; then
    if have python3; then scan_secret_merge "$cfg"; return $?; fi
    warn secret "merge in progress, but no python3 to tell incoming lines from yours -> every staged finding blocks"
  fi
  say secret "gitleaks protect --staged"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo:ro" $(git_extra_mounts) -w /repo "$(img ghcr.io/gitleaks/gitleaks "$GITLEAKS_VER" "$GITLEAKS_DIGEST")" \
    protect --staged --source /repo $cfg --redact --exit-code 1 --verbose
}

# During a merge: a finding whose line exists verbatim in the merged branch's version of that file
# came in with the merge. It is reported (triage it on that branch), but does not block. A finding
# in a line neither side had (a conflict resolution, an edit made during the merge) is the merger's
# own, and blocks as any commit would.
scan_secret_merge(){
  local cfg="$1" od="$RUN_DIR/merge-scan" OUTM=() rc from
  from="$(git name-rev --name-only --exclude='tags/*' MERGE_HEAD 2>/dev/null || git rev-parse --short MERGE_HEAD)"
  out_mount "$od"
  say secret "gitleaks protect --staged (merge of $from in progress: what it brings in vs. what you add)"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo:ro" $(git_extra_mounts) "${OUTM[@]}" -w /repo "$(img ghcr.io/gitleaks/gitleaks "$GITLEAKS_VER" "$GITLEAKS_DIGEST")" \
    protect --staged --source /repo $cfg --redact --exit-code 0 --report-format json --report-path /out/staged.json >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 0 ] && [ -f "$od/staged.json" ] || { rm -rf "$od"; dim_error secret "gitleaks exit $rc (staged scan of a merge failed)"; return 1; }
  local lines own=0 inc=0
  lines="$(python3 - "$od/staged.json" <<'PY'
import json, subprocess, sys
def lines(spec):
    r = subprocess.run(["git", "show", spec], capture_output=True)
    return r.stdout.decode("utf-8", "replace").splitlines() if r.returncode == 0 else []
seen = {}
for f in json.load(open(sys.argv[1])) or []:
    path = f.get("File") or ""
    path = path[len("/repo/"):] if path.startswith("/repo/") else path
    n = int(f.get("StartLine") or 0)
    if path not in seen:
        seen[path] = (lines(":" + path), set(lines("MERGE_HEAD:" + path)))
    staged, theirs = seen[path]
    line = staged[n - 1] if 0 < n <= len(staged) else None
    kind = "in" if line is not None and line in theirs else "own"
    print(f"{kind}\t{path}:{n}\t{f.get('RuleID')}")
PY
)"
  rm -rf "$od"
  own="$(grep -c '^own' <<<"$lines" || true)"; inc="$(grep -c '^in' <<<"$lines" || true)"
  if [ "$inc" -gt 0 ]; then
    note secret "$inc finding(s) came in with the merge of $from — already in that branch, so not blocking here; triage them there (scan.sh secret on $from):"
    grep '^in' <<<"$lines" | cut -f2,3 | sed 's/\t/  /; s/^/        /'
  fi
  if [ "$own" -gt 0 ]; then
    printf '\033[31m[scan:secret] BLOCK: %s finding(s) in lines this merge adds (in neither branch before):\033[0m\n' "$own"
    grep '^own' <<<"$lines" | cut -f2,3 | sed 's/\t/  /; s/^/        /'
    dim_mark findings "$own in lines this merge adds; $inc came in with $from (reported only)"
    return 1
  fi
  [ "$inc" -gt 0 ] && dim_mark findings "$inc came in with the merge of $from (already there; reported, not blocking)"
  return 0
}

# The kit's own record (raw logs, SARIF, reports under docs/security/scan-findings) is output, not
# source. A repo that once committed it had semgrep scan its logs (a timeout in the v1.20.0 dogfood),
# and trivy fs reads it even untracked; findings "in" a raw log are noise about the scan itself.
record_rel(){ printf '%s' "${LOG_DIR#"$ROOT"/}"; }

# ---- sast (semgrep) ----
scan_sast(){
  # Default: whole repo (semgrep's default .semgrepignore skips node_modules/.git/.venv).
  # Override SAST_PATHS via env to narrow/speed up the scan. A root that does not exist is dropped
  # with a reason: semgrep exits 2 on one, and until v1.20.0 the example config shipped
  # `backend frontend` active, so every install without both dirs crashed sast on every push.
  local paths="" missing="" p
  for p in ${SAST_PATHS:-.}; do
    if [ -e "$ROOT/$p" ]; then paths="$paths $p"; else missing="$missing $p"; fi
  done
  paths="${paths# }"
  if [ -n "$missing" ] && [ -z "$paths" ]; then
    paths="."
    dim_mark "" "SAST_PATHS:$missing not found -> scanned the whole repo (fix SAST_PATHS in .security-audit.conf)"
    warn sast "SAST_PATHS:$missing not found -> scanning the whole repo instead"
  elif [ -n "$missing" ]; then
    dim_mark "" "SAST_PATHS:$missing not found -> not scanned (fix SAST_PATHS in .security-audit.conf)"
    warn sast "SAST_PATHS:$missing not found -> skipped; scanning $paths"
  fi
  local out=""; [ "$SARIF" = "1" ] && out="--sarif --output $SARIF_DIR/semgrep.sarif"
  say sast "semgrep ($paths, ==$SEMGREP_VER) [$SEMGREP_CONFIGS]"
  # shellcheck disable=SC2086
  pyrun semgrep "$SEMGREP_VER" semgrep scan $SEMGREP_CONFIGS --metrics off --error --severity ERROR --exclude "$(record_rel)" $out $paths
  semgrep_rc $?
}

# semgrep --error: 1 = findings at the gated severity; 2+ = the scan itself failed (bad config,
# parse/network error). Both block, as they always did — but a crash is not a finding.
semgrep_rc(){
  case "$1" in
    0) return 0 ;;
    1) return 1 ;;
    127) dim_skip sast "no uvx/pipx -> semgrep skipped"; return 0 ;;
    *) dim_error sast "semgrep exit $1 (scan error, not a finding)"; return 1 ;;
  esac
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
  local files rec; rec="$(record_rel)/"
  files="$(changed_files | sort -u | while IFS= read -r f; do
    case "$f" in "$rec"*) continue ;; esac   # explicit targets bypass --exclude: drop them here
    [ -f "$f" ] && printf '%s\n' "$f"; done)"
  [ -z "$files" ] && { dim_na sast "no changed files vs base -> semgrep skipped"; return 0; }
  local out=""; [ "$SARIF" = "1" ] && out="--sarif --output $SARIF_DIR/semgrep.sarif"
  say sast "semgrep (changed files, ==$SEMGREP_VER) [$SEMGREP_CONFIGS]"
  # shellcheck disable=SC2086
  pyrun semgrep "$SEMGREP_VER" semgrep scan $SEMGREP_CONFIGS --metrics off --error --severity ERROR --exclude "$(record_rel)" $out $files
  semgrep_rc $?
}

# ---- iac (checkov) ----
scan_iac(){
  local tf="${TF_DIR:-}"
  [ -z "$tf" ] && tf="$(git ls-files '*.tf' | head -1 | xargs -r dirname)"
  [ -z "$tf" ] && { dim_na iac "no terraform"; return 0; }
  say iac "checkov ($tf, ==$CHECKOV_VER)"
  # Soft: --soft-fail keeps the gate open, so the exit code no longer says whether checks failed;
  # the summary line does. Read it, so failed checks are recorded as findings and not as a pass.
  local out rc failed
  out="$(pyrun checkov "$CHECKOV_VER" checkov --directory "$tf" --framework terraform --soft-fail)"; rc=$?
  [ -n "$out" ] && printf '%s\n' "$out"
  case "$rc" in
    0) ;;
    127) dim_skip iac "no uvx/pipx -> checkov skipped"; return 0 ;;
    *) dim_error iac "checkov exit $rc (scan error, not a finding)"; return 0 ;;
  esac
  failed="$(awk -F'Failed checks: ' 'NF>1{split($2,a,","); n+=a[1]} END{print n+0}' <<<"$out")"
  [ "$failed" -gt 0 ] && dim_mark findings "$failed failed check(s) (soft, not blocking)"
  return 0
}

# ---- trivy DB cache (F30) ----
trivy_cache_mount(){
  case "$TRIVY_CACHE" in /*) mkdir -p "$TRIVY_CACHE" 2>/dev/null ;; esac
  printf -- '-v %s:/root/.cache/trivy' "$TRIVY_CACHE"
}
# The cached DB as "UpdatedAt<TAB>DownloadedAt", or nothing when the cache holds no DB. Read with
# trivy itself (`version` reports the DB it would use), so no other image is involved.
trivy_db_meta(){
  local out db u d
  # shellcheck disable=SC2046
  out="$(docker run --rm $(trivy_cache_mount) "$(img aquasec/trivy "$TRIVY_VER" "$TRIVY_DIGEST")" version --format json 2>/dev/null)" || return 0
  db="$(sed -n 's/.*"VulnerabilityDB":{\([^}]*\)}.*/\1/p' <<<"$out")"
  [ -n "$db" ] || return 0
  u="$(sed -n 's/.*"UpdatedAt":"\([^"]*\)".*/\1/p' <<<"$db")"
  d="$(sed -n 's/.*"DownloadedAt":"\([^"]*\)".*/\1/p' <<<"$db")"
  [ -n "$u" ] && printf '%s\t%s\n' "$u" "$d"
}
iso_epoch(){   # 2026-11-03T05:44:24.577Z -> epoch seconds (GNU date, else BSD date)
  local t="${1%%.*}"; t="${t%Z}"
  date -u -d "$t" +%s 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%S' "$t" +%s 2>/dev/null
}
db_age_h(){   # <DownloadedAt> -> hours, one decimal; nothing if it cannot be parsed
  local e; e="$(iso_epoch "$1")" || return 0
  [ -n "$e" ] && awk -v s="$(( $(date +%s) - e ))" 'BEGIN{printf "%.1f", s/3600}'
}

# ---- container/fs (trivy) — soft ----
scan_container(){
  docker_ok || { dim_skip container "no docker -> trivy skipped"; return 0; }
  # The DB is reused while younger than TRIVY_DB_MAX_AGE_H. The misconfig check bundle is NEVER
  # downloaded: the checks built into the pinned trivy match it, while a newer bundle failed to parse
  # in 0.58 (rego ERROR lines on every run) — and pinned checks keep the result reproducible.
  local meta u="" d="" age="" upd="--skip-check-update"
  meta="$(trivy_db_meta)"
  if [ -n "$meta" ]; then
    IFS="$(printf '\t')" read -r u d <<<"$meta"
    age="$(db_age_h "$d")"
  fi
  if [ "$SCAN_OFFLINE" = "1" ]; then
    [ -n "$meta" ] || { dim_skip container "SCAN_OFFLINE=1 and no cached trivy DB -> not inspected (run scan.sh warm while online)"; return 0; }
    upd="$upd --skip-db-update --offline-scan"
  elif [ -n "$age" ] && awk -v a="$age" -v m="$TRIVY_DB_MAX_AGE_H" 'BEGIN{exit !(a < m)}'; then
    upd="$upd --skip-db-update"
  elif [ -n "$meta" ]; then
    say container "trivy DB is ${age:-?}h old (> ${TRIVY_DB_MAX_AGE_H}h) -> refreshing"
  else
    say container "first run: downloading the trivy vulnerability DB (~130 MiB, once; cached in $TRIVY_CACHE)"
  fi
  say container "trivy fs (report, soft)"
  # .trivyignore.yaml auto-detect does not work in this docker setup -> pass it explicitly
  # (only if present; for deliberately accepted findings, committed to the repo).
  local ign=""; [ -f "$ROOT/.trivyignore.yaml" ] && ign="--ignorefile /repo/.trivyignore.yaml"
  local skip; skip="--skip-dirs ${TRIVY_SKIP_DIRS:+$TRIVY_SKIP_DIRS,}$(record_rel)"
  # Soft: findings must not block, but they must be told apart from a clean run — so trivy exits
  # TRIVY_FINDINGS_RC on findings and that code is recorded as findings, then mapped back to 0.
  local out="--exit-code $TRIVY_FINDINGS_RC" OUTM=()
  if [ "$SARIF" = "1" ]; then out="$out --format sarif --output /out/trivy.sarif"; out_mount "$SARIF_DIR"; fi
  # shellcheck disable=SC2086,SC2046
  docker run --rm -v "$ROOT:/repo:ro" $(trivy_cache_mount) "${OUTM[@]+"${OUTM[@]}"}" -w /repo "$(img aquasec/trivy "$TRIVY_VER" "$TRIVY_DIGEST")" fs \
    --no-progress $upd --scanners vuln,secret,misconfig,license --severity CRITICAL,HIGH --ignore-unfixed $out $ign $skip /repo
  local rc=$?
  # Which DB this result came from: identity -> provenance, age -> summary.json (see the summary).
  # This runs inside the tee subshell, so it travels to the summary writer through the run dir.
  case "$upd" in *--skip-db-update*) ;; *) meta="$(trivy_db_meta)"; u=""; d=""
    [ -n "$meta" ] && IFS="$(printf '\t')" read -r u d <<<"$meta"; age="$(db_age_h "$d")" ;; esac
  local dbnote=""
  if [ -n "$u" ]; then
    printf '%s\t%s\t%s\n' "$u" "$d" "${age:-}" > "$RUN_DIR/trivy-db" 2>/dev/null
    [ -n "$age" ] && dbnote="trivy DB $(awk -v a="$age" 'BEGIN{printf "%d", a}')h old"
  fi
  case "$rc" in
    0) [ -n "$dbnote" ] && dim_mark "" "$dbnote"; return 0 ;;
    "$TRIVY_FINDINGS_RC") dim_mark findings "CRITICAL/HIGH findings (soft, not blocking)${dbnote:+ · $dbnote}"; return 0 ;;
    *) dim_error container "trivy exit $rc (scan error, not a finding)"; return "$rc" ;;
  esac
}

# ---- sbom (syft) ----
scan_sbom(){
  docker_ok || { dim_skip sbom "no docker -> syft skipped"; return 0; }
  say sbom "syft -> sbom.cyclonedx.json + sbom.spdx.json"
  # Written to this run's dir, then moved to the repo root where it always landed.
  local OUTM=() sb="$RUN_DIR/sbom"; out_mount "$sb"
  docker run --rm -v "$ROOT:/repo:ro" "${OUTM[@]}" -w /repo "$(img anchore/syft "$SYFT_VER" "$SYFT_DIGEST")" dir:/repo \
    -o cyclonedx-json=/out/sbom.cyclonedx.json -o spdx-json=/out/sbom.spdx.json
  local rc=$? f
  for f in sbom.cyclonedx.json sbom.spdx.json; do [ -f "$sb/$f" ] && mv -f "$sb/$f" "$ROOT/$f"; done
  rmdir "$sb" 2>/dev/null || true
  # syft produces an inventory, not findings: any non-zero is a failure (it blocks, as before).
  [ "$rc" -eq 0 ] || dim_error sbom "syft exit $rc (SBOM not produced)"
  return "$rc"
}

# ---- osv (OSV-Scanner) — broad multi-ecosystem dep CVE, OPTIONAL (not in 'all') ----
# Complements pip-audit/npm: scans lockfiles across ecosystems (py/js/go/rust/...) against
# OSV.dev. Standalone + opt-in so it doesn't double-gate with the other dep scanners.
scan_osv(){
  docker_ok || { dim_skip osv "no docker -> osv-scanner skipped"; return 0; }

  # Reachability (opt-in): osv-scanner can tell whether a vulnerable symbol is actually CALLED.
  # Two rules make this safe to offer:
  #
  #   1. THE GATE DOES NOT LOOSEN. With call analysis on, osv-scanner drops uncalled vulnerabilities
  #      by default — a security gate that silently reports less is the wrong trade. We always pair
  #      it with --all-vulns, so everything is still reported and the exit code is unchanged; what
  #      you gain is a called/uncalled SIGNAL for the judgment layer, not fewer findings.
  #   2. NO BUILD SCRIPTS. Rust call analysis works by running the dependency tree's build scripts.
  #      A scanner that executes untrusted code to decide what to report is an own-goal, so it is
  #      refused unless someone explicitly accepts that with OSV_ALLOW_BUILD_SCRIPTS=1.
  local call=""
  if [ -n "${OSV_CALL_ANALYSIS:-}" ]; then
    case "$OSV_CALL_ANALYSIS" in
      *rust*)
        if [ "${OSV_ALLOW_BUILD_SCRIPTS:-0}" != "1" ]; then
          dim_error osv "call-analysis=rust RUNS dependency build scripts (executing untrusted code to decide reachability) -> refused; set OSV_ALLOW_BUILD_SCRIPTS=1 to accept that"
          return 1
        fi
        warn osv "call-analysis=rust with OSV_ALLOW_BUILD_SCRIPTS=1 — build scripts from the dependency tree WILL execute"
        call="--call-analysis=$OSV_CALL_ANALYSIS --all-vulns" ;;
      *) call="--call-analysis=$OSV_CALL_ANALYSIS --all-vulns" ;;
    esac
  fi
  say osv "osv-scanner scan source (all lockfile ecosystems)${call:+ [reachability: $OSV_CALL_ANALYSIS, gate unchanged]}"
  local out="" OUTM=()
  if [ "$SARIF" = "1" ]; then out="--format sarif --output /out/osv.sarif"; out_mount "$SARIF_DIR"; fi
  # Read-only, except when the user accepted rust call analysis: that RUNS the dependency tree's build
  # scripts, which write into the tree (cargo's target/). That mode already warns it executes code.
  local ro=":ro"; case "${OSV_CALL_ANALYSIS:-}" in *rust*) ro="" ;; esac
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo$ro" "${OUTM[@]+"${OUTM[@]}"}" -w /repo "$(img ghcr.io/google/osv-scanner "$OSV_VER" "$OSV_DIGEST")" \
    scan source --recursive $call $out /repo
  local rc=$?
  case "$rc" in
    0) return 0 ;;                                              # scanned, clean
    1) return 1 ;;                                              # vulnerabilities found (HARD)
    128) dim_na osv "no lockfiles found -> nothing to scan"; return 0 ;;
    *) dim_error osv "osv-scanner exit $rc (scan error, not a finding)"; return 0 ;;
  esac
}

# ---- guarddog — malicious/typosquat dependency detection, OPTIONAL (not in 'all'; needs network) ----
# Complements osv/pip-audit/npm (which only find KNOWN CVEs) by catching *malicious* packages:
# typosquats, compromised-maintainer metadata, malicious install scripts. `verify` checks each
# declared dependency against the LIVE registry, so this dimension needs network. Standalone + opt-in.
scan_guarddog(){
  { have uvx || have pipx; } || { dim_skip guarddog "no uvx/pipx -> guarddog skipped"; return 0; }
  local pyreqs npmpkgs rc=0 f
  pyreqs="$(git ls-files | grep -E '(^|/)requirements[^/]*\.txt$' | grep -v node_modules || true)"
  npmpkgs="$(git ls-files | grep -E '(^|/)package\.json$' | grep -v node_modules || true)"
  [ -z "$pyreqs" ] && [ -z "$npmpkgs" ] && { dim_na guarddog "no requirements*.txt or package.json -> nothing to verify"; return 0; }
  say guarddog "guarddog verify (malicious/typosquat deps, ==$GUARDDOG_VER, needs network)"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    say guarddog "pypi verify $f"
    pyrun guarddog "$GUARDDOG_VER" guarddog pypi verify "$f" --exit-non-zero-on-finding || rc=1
  done <<EOF
$pyreqs
EOF
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    say guarddog "npm verify $f"
    pyrun guarddog "$GUARDDOG_VER" guarddog npm verify "$f" --exit-non-zero-on-finding || rc=1
  done <<EOF
$npmpkgs
EOF
  return $rc
}

# ---- pkgcheck — ONE named package, BEFORE it is installed (agent hook / ad-hoc) ----
# Every other dependency dimension reads a manifest that is already in the repo, i.e. after
# `npm i <pkg>` has already run the package's install script. This one takes the name off the
# install command and asks guarddog about it while nothing has executed yet.
#   scan.sh pkgcheck npm lodash react@18.2.0      # explicit
#   scan.sh pkgcheck --hook  < payload.json        # agent tool-call hook (hooks/pre-tool-install.sh)
# Exit: 1 if any target BLOCKS, else 0. Never blocks on "could not scan" — see below.
PKGCHECK_CACHE_TTL_MIN="${PKGCHECK_CACHE_TTL_MIN:-1440}"

pkgcheck_cache_dir(){
  [ "${PKGCHECK_CACHE:-on}" = "off" ] && return 1
  local common; common="$(git rev-parse --git-common-dir 2>/dev/null)" || return 1
  case "$common" in /*) ;; *) common="$ROOT/$common" ;; esac
  printf '%s/security-audit-cache/pkgcheck' "$common"
}

# guarddog's JSON -> a verdict line under the CURRENT policy (BLOCK_EXTRA / REPORT_EXTRA).
pkgcheck_classify(){
  python3 "$KIT_DIR/lib/pkgcheck.py" --classify \
    --block-extra "${PKGCHECK_BLOCK_EXTRA:-}" --report-extra "${PKGCHECK_REPORT_EXTRA:-}"
}

# One target -> a verdict line on stdout ("BLOCK\t<rules>"), exit 1 when it blocks. stdout is the
# verdict and nothing else: the caller reads it whole (a progress line here once made every
# first-time check print "clean", BLOCK included).
#
# The cache (F06) keeps what guarddog FOUND, not what the policy said about it: the network scan is
# the slow part (15-20 s), judging it is not. A stored verdict outlived the policy that made it — a
# package allowed once stayed allowed after PKGCHECK_BLOCK_EXTRA named its rule. Now every read is
# re-judged by today's policy, and an entry that is not a whole guarddog document is a miss.
pkgcheck_one(){
  local eco="$1" name="$2" ver="$3" out verdict dir key f="" raw
  if dir="$(pkgcheck_cache_dir)"; then
    # findings-v2: the key also carries the pinned guarddog version (its rules decide the findings).
    key="$(printf 'findings-v2__%s__%s__%s__%s' "$eco" "$name" "${ver:-latest}" "$GUARDDOG_VER" | tr -c 'A-Za-z0-9_.@-' '_')"
    f="$dir/$key"
    # An unversioned request means "whatever the registry serves now", which changes under us —
    # those entries expire; an exact version is immutable on both registries, so it does not.
    if [ "${PKGCHECK_CACHE:-on}" != "refresh" ] && [ -f "$f" ] \
       && { [ -n "$ver" ] || [ -z "$(find "$f" -mmin "+$PKGCHECK_CACHE_TTL_MIN" 2>/dev/null)" ]; }; then
      out="$(pkgcheck_classify < "$f")"
      verdict="${out%%	*}"
      if [ -n "$out" ] && [ "$verdict" != "INDETERMINATE" ]; then
        printf '%s (cached findings)\n' "$out"
        [ "$verdict" = "BLOCK" ] && return 1
        return 0
      fi
      rm -f "$f"   # half-written or unreadable: not an answer, ask again
    fi
  fi
  say pkgcheck "guarddog ==$GUARDDOG_VER scan (needs network)" >&2
  local gargs="scan $name"
  [ -n "$ver" ] && gargs="$gargs -v $ver"
  # shellcheck disable=SC2086
  raw="$(pyrun guarddog "$GUARDDOG_VER" guarddog "$eco" $gargs --output-format json 2>/dev/null)"
  out="$(printf '%s' "$raw" | pkgcheck_classify)"
  [ -z "$out" ] && out="INDETERMINATE	guarddog produced no output"
  verdict="${out%%	*}"
  # Only a real answer is worth remembering; INDETERMINATE is a failure to look. Written to a temp
  # file and renamed: a reader never sees half a document, and two writers each leave a whole one.
  if [ -n "$f" ] && [ "$verdict" != "INDETERMINATE" ] && mkdir -p "$dir" 2>/dev/null; then
    printf '%s\n' "$raw" > "$f.tmp.$$" 2>/dev/null && mv -f "$f.tmp.$$" "$f" 2>/dev/null || rm -f "$f.tmp.$$"
  fi
  printf '%s\n' "$out"
  [ "$verdict" = "BLOCK" ] && return 1
  return 0
}

scan_pkgcheck(){
  have python3 || { warn pkgcheck "no python3 -> package pre-install check skipped"; return 0; }
  [ -f "$KIT_DIR/lib/pkgcheck.py" ] || { warn pkgcheck "lib/pkgcheck.py missing -> skipped"; return 0; }

  local targets=""
  if [ "${1:-}" = "--hook" ]; then
    targets="$(python3 "$KIT_DIR/lib/pkgcheck.py" --parse 2>/dev/null)"
  elif [ "${1:-}" = "--command" ]; then
    shift
    targets="$(python3 "$KIT_DIR/lib/pkgcheck.py" --command "${1:-}" 2>/dev/null)"
  else
    local eco="${1:-}"; shift 2>/dev/null || true
    case "$eco" in
      pypi|npm) ;;
      *) echo "usage: scan.sh pkgcheck <pypi|npm> <package>[@version] ...   |   scan.sh pkgcheck --hook" >&2; return 2 ;;
    esac
    local spec name ver
    for spec in "$@"; do
      case "$eco" in
        npm) name="${spec%@*}"; ver="${spec##*@}"; [ "$name" = "$spec" ] && ver="" ;;
        *)   name="${spec%%[=><~]*}"; ver="${spec##*==}"; [ "$ver" = "$spec" ] && ver="" ;;
      esac
      [ -n "$name" ] && targets="$targets$eco	$name	$ver
"
    done
  fi
  [ -n "$(printf '%s' "$targets" | tr -d '[:space:]')" ] || return 0

  { have uvx || have pipx; } || { warn pkgcheck "no uvx/pipx -> guarddog unavailable, package NOT checked"; return 0; }

  local rc=0 eco name ver line
  while IFS='	' read -r eco name ver; do
    [ -n "$eco" ] || continue
    if [ "$eco" = "unverifiable" ]; then
      # Fail OPEN, loudly: refusing an install the kit cannot inspect would block ordinary local
      # and VCS installs, and a gate people route around protects nothing.
      warn pkgcheck "$name -> NOT a registry package ($ver) — nothing was checked"
      continue
    fi
    say pkgcheck "$eco/$name${ver:+@$ver}"
    line="$(pkgcheck_one "$eco" "$name" "$ver")" || rc=1
    case "$line" in
      BLOCK*)         printf '\033[31m  BLOCK\033[0m %s/%s%s -> %s\n' "$eco" "$name" "${ver:+@$ver}" "${line#*	}" ;;
      INDETERMINATE*) warn pkgcheck "$eco/$name: ${line#*	} (allowed — not checked, not cleared)" ;;
      NOTE*)          printf '  note  %s/%s%s -> %s\n' "$eco" "$name" "${ver:+@$ver}" "${line#*	}" ;;
      *)              printf '  ok    %s/%s%s -> clean\n' "$eco" "$name" "${ver:+@$ver}" ;;
    esac
  done <<EOF
$targets
EOF
  return $rc
}

# ---- zizmor — GitHub Actions security, OPTIONAL (not in 'all') ----
# Static analysis of GitHub Actions workflows/actions (template injection, dangerous triggers,
# token over-permissioning, unpinned actions). Runs OFFLINE by default (no GitHub API), so it is
# deterministic and air-gap friendly. Standalone + opt-in. Tune with ZIZMOR_ARGS (e.g. --min-severity).
scan_zizmor(){
  { have uvx || have pipx; } || { dim_skip zizmor "no uvx/pipx -> zizmor skipped"; return 0; }
  has_tracked '^\.github/workflows/.*\.(yml|yaml)$' \
    || { dim_na zizmor "no .github/workflows -> nothing to scan"; return 0; }
  say zizmor "zizmor --offline (.github, ==$ZIZMOR_VER)"
  local rc
  if [ "$SARIF" = "1" ]; then
    pyrun zizmor "$ZIZMOR_VER" zizmor --offline --format sarif $ZIZMOR_ARGS .github/ > "$SARIF_DIR/zizmor.sarif"
    rc=$?
  else
    pyrun zizmor "$ZIZMOR_VER" zizmor --offline $ZIZMOR_ARGS .github/
    rc=$?
  fi
  # zizmor: 0 clean, 10-14 findings (by highest severity), anything else = it failed. Every
  # non-zero blocks, as before; only the label differs.
  case "$rc" in
    0) return 0 ;;
    1[0-4]) return 1 ;;
    *) dim_error zizmor "zizmor exit $rc (scan error, not a finding)"; return 1 ;;
  esac
}

# ---- rules-test: run semgrep's own rule tests over the repo's local rules ----
# A custom rule is code, and untested code rots: the pattern stops matching after a refactor and the
# gate goes quiet without ever failing. semgrep has a native test runner (rule + a fixture file
# annotated with `# ruleid:` / `# ok:`); this just points it at the local rules.
scan_rules_test(){
  local paths; paths="$(local_rules_paths)"
  [ -n "$paths" ] || { warn rules-test "no local rules found (${LOCAL_RULES_ANCHORS}) -> nothing to test"; return 0; }
  local rc=0 p
  for p in $paths; do
    # semgrep's test runner skips hidden paths: rules under `.semgrep/` scan normally but their
    # fixtures are invisible to `--test`, which would report "all clear" while testing nothing.
    case "$p" in
      .*) if [ -n "$(find "$ROOT/$p" -type f ! -name '*.yml' ! -name '*.yaml' -print -quit 2>/dev/null)" ]; then
            warn rules-test "$p is HIDDEN — semgrep --test cannot discover fixtures there; move rules+tests to semgrep-rules/"
            continue
          fi ;;
    esac
    say rules-test "semgrep --test $p (==$SEMGREP_VER)"
    pyrun semgrep "$SEMGREP_VER" semgrep --test --config "$p" "$p" \
      || { [ $? -eq 127 ] && { warn rules-test "no uvx/pipx -> skipped"; return 0; }; rc=1; }
  done
  return $rc
}

# ---- doctor: report environment, pins and detected projects (no scan) ----
scan_doctor(){
  printf '== security-audit-kit doctor ==\n'
  printf 'root   : %s\n' "$ROOT"
  printf 'config : %s\n\n' "$([ -f "$CONF" ] && echo "$CONF" || echo '(none; using defaults)')"
  # Platform: on Windows the difference between WSL2 and Git Bash is invisible until a docker
  # dimension silently misbehaves (MSYS rewrites /repo into a Windows path before docker sees it),
  # so name it here rather than letting someone debug a mangled mount.
  case "$(uname -s 2>/dev/null)" in
    MINGW*|MSYS*|CYGWIN*)
      printf 'platform: Git Bash/MSYS — PARTIAL. uvx/pipx dimensions + hooks work; docker ones\n'
      printf '          (secret/container/sbom/osv) mangle the /repo mount — prefix MSYS_NO_PATHCONV=1,\n'
      printf '          or use WSL2, which is the supported Windows path.\n\n' ;;
    Linux)
      if grep -qi microsoft /proc/version 2>/dev/null; then
        printf 'platform: WSL2 — full support (docker via Docker Desktop WSL integration).\n\n'
      fi ;;
  esac
  local hp_warn gf; hp_warn="$(hookspath_check)"
  gf="$(git_freshness_line "$(git_freshness)" doctor)"; [ -n "$gf" ] && printf '!!  %s\n\n' "$gf"
  if [ -n "$hp_warn" ]; then printf '!!  %s\n\n' "$hp_warn"; fi
  printf 'toolchain (a missing one only skips that dimension):\n'
  docker_ok && echo "  ok  docker        (gitleaks/trivy/syft)" || echo "  --  docker        MISSING/not running -> secret/container/sbom skipped"
  { have uvx || have pipx; } && echo "  ok  uvx/pipx      (semgrep/checkov/pip-audit/guarddog/zizmor)" || echo "  --  uvx/pipx      MISSING -> sast/iac/py-deps/guarddog/zizmor skipped"
  { have pnpm || have yarn || have npm; } && echo "  ok  js pkg mgr    (js-deps)" || echo "  --  js pkg mgr    MISSING -> js-deps skipped"
  if docker_ok; then
    local tm tu td
    tm="$(trivy_db_meta)"
    if [ -n "$tm" ]; then
      IFS="$(printf '\t')" read -r tu td <<<"$tm"
      printf '  trivy DB    : %s, updated %s, downloaded %sh ago (refreshed after %sh)\n' \
        "$TRIVY_CACHE" "$tu" "$(db_age_h "$td" | awk '{printf "%d", $1}')" "$TRIVY_DB_MAX_AGE_H"
    else
      printf '  trivy DB    : none cached in %s -> the first container scan downloads ~130 MiB (scan.sh warm does it now)\n' "$TRIVY_CACHE"
    fi
  fi
  printf '\npins:\n'
  printf '  gitleaks   %s @ %s\n' "$GITLEAKS_VER" "${GITLEAKS_DIGEST:-<tag>}"
  printf '  trivy      %s @ %s\n' "$TRIVY_VER" "${TRIVY_DIGEST:-<tag>}"
  printf '  syft       %s @ %s\n' "$SYFT_VER" "${SYFT_DIGEST:-<tag>}"
  printf '  osv-scanner %s @ %s\n' "$OSV_VER" "${OSV_DIGEST:-<tag>}"
  printf '  semgrep    %s\n' "${SEMGREP_VER:-<latest>}"
  printf '  semgrep cfg %s%s\n' "$SEMGREP_CONFIGS" "$([ -n "${SEMGREP_CONFIGS_OVERRIDDEN:-}" ] && echo ' (base from env/conf + local)' || echo ' (stack-auto + local)')"
  # An override freezes the pack list at the moment it was written; the repo then grows and the
  # list rots silently ("from env/conf" told you nothing about what it now MISSES). Say it.
  if [ -n "${SEMGREP_CONFIGS_OVERRIDDEN:-}" ]; then
    local auto missing="" pack
    auto="$(detect_semgrep_configs)"
    for pack in $auto; do
      case "$pack" in --config) continue ;; esac
      case " $SEMGREP_CONFIGS_BASE " in *" $pack "*) ;; *) missing="$missing $pack" ;; esac
    done
    [ -n "$missing" ] && printf '  semgrep cfg OVERRIDE is missing what stack-auto would add:%s\n' "$missing"
  fi
  printf '  checkov    %s\n' "${CHECKOV_VER:-<latest>}"
  printf '  pip-audit  %s\n' "${PIP_AUDIT_VER:-<latest>}"
  printf '  guarddog   %s\n' "${GUARDDOG_VER:-<latest>}"
  printf '  zizmor     %s\n' "${ZIZMOR_VER:-<latest>}"
  printf '\ndetected in this repo:\n'
  has_tracked '(^|/)(pyproject\.toml|requirements[^/]*\.txt|Pipfile|uv\.lock)$' && echo "  python"     || true
  has_tracked '(^|/)package\.json$'                                            && echo "  javascript" || true
  has_tracked '\.tf$'                                                          && echo "  terraform"  || true
  has_tracked '^\.github/workflows/.*\.(yml|yaml)$'                            && echo "  github-actions (zizmor)" || true

  # Allowlists are per-TOOL while a triage decision is per-FINDING, and the dependency-CVE
  # dimensions overlap: pip-audit, osv-scanner and trivy read the same lockfiles and report the
  # same advisory under different ids. Listing which files exist makes a half-applied suppression
  # visible — otherwise an accepted risk silenced in one path returns as a HIGH in another.
  # Repo-local rules: the kit's own engine pointed at YOUR invariants. Three things a maintainer
  # cannot otherwise see: how many rules load, how many actually GATE, and whether they are tested.
  printf '\nlocal semgrep rules (yours, not shipped by the kit):\n'
  if [ "${SEMGREP_LOCAL_RULES:-}" = "off" ]; then
    printf '  --  DISABLED by SEMGREP_LOCAL_RULES=off (.security-audit.conf or env)\n'
  elif [ -z "$(local_rules_paths)" ]; then
    printf '  --  none found (looked for: %s) — see README "repo-local rules"\n' "$LOCAL_RULES_ANCHORS"
  else
    local idx total gating nogate names
    idx="$(local_rules_index)"
    total="$(printf '%s' "$idx" | grep -c . || true)"
    gating="$(printf '%s' "$idx" | grep -c 'ERROR$' || true)"
    nogate=$(( total - gating ))
    printf '  ok  %s — %s rule(s), %s gating\n' "$(local_rules_paths)" "$total" "$gating"
    if [ "$nogate" -gt 0 ]; then
      names="$(printf '%s' "$idx" | grep -v 'ERROR$' | cut -f1 | tr '\n' ' ')"
      # scan_sast runs --severity ERROR: a WARNING/INFO rule loads and is then ignored. Without
      # this line you would believe a rule guards you while it silently never fails a scan.
      printf '  !!  %s rule(s) NOT at ERROR -> WILL NOT GATE: %s\n' "$nogate" "$names"
    fi
    if [ -n "$(local_rules_files)" ] && [ -n "$(find $(local_rules_paths) -type f ! -name '*.yml' ! -name '*.yaml' -print -quit 2>/dev/null)" ]; then
      printf '  ok  rule tests present -> verify with: scan.sh rules-test\n'
    else
      printf '  --  no rule tests found (a rule with no test decays silently) -> scan.sh rules-test\n'
    fi
  fi

  printf '\nallowlists (a suppression must cover every path that reports the finding):\n'
  for f in .gitleaks.toml .pip-audit-ignore osv-scanner.toml .trivyignore.yaml .security-exclusions.md; do
    [ -f "$ROOT/$f" ] && printf '  ok  %-24s\n' "$f" || printf '  --  %-24s (absent)\n' "$f"
  done
  printf '  note: dependency CVEs are reported by py-deps + osv + container — an entry in one\n'
  printf '        does not silence the others; semgrep/checkov/zizmor use inline comments.\n'
  # One line, not a report: doctor stays worth reading. `scan.sh allowlist` has the detail.
  if scan_allowlist >/dev/null 2>&1; then
    printf '  ok  audit: nothing expired, no exact-id gap  (detail: scan.sh allowlist)\n'
  else
    printf '  !!  audit: expired entries or a cross-path gap -> run: scan.sh allowlist\n'
  fi

  # Two overlapping runs used to interleave the same raw log and truncate summary.json under a
  # reader. Whether a lock is held right now (or left behind by a crash) is otherwise invisible.
  printf '\nrun lock (one writer for raw-<date>.log + the shared record):\n'
  local lk lkst
  lk="$(scan_lock_path)"
  lkst="$(scan_lock_state "$lk")"
  case "${lkst%%	*}" in
    gone)  printf '  ok  free (%s)\n' "${lk#"$ROOT"/}" ;;
    stale) printf '  !!  HELD but stale (%s) — next run reclaims it\n' "${lkst#*	}" ;;
    *)     printf '  ok  held right now (%s)\n' "${lkst#*	}" ;;
  esac
  printf '      stale = owner gone, pid reused, or no heartbeat for %s min — never age alone\n' "$SCAN_LOCK_STALE_MIN"
  printf '      a second run waits %ss, then scans anyway into its own runs/<run-id>/ (shared record untouched)\n' "$SCAN_LOCK_WAIT"

  # The git hooks cannot see `npm i <pkg>`: the install script has already run by the time a
  # manifest reaches the index. Whether that window is guarded is invisible unless it is said.
  printf '\nagent pre-install check (pkgcheck):\n'
  if grep -q 'pre-tool-install\.sh' "$ROOT/.claude/settings.json" 2>/dev/null; then
    printf '  ok  wired: .claude/settings.json PreToolUse(Bash) -> hooks/pre-tool-install.sh\n'
  else
    printf '  --  NOT wired — an agent can install a package before any kit gate sees it.\n'
    printf '      enable: install.sh --with-agent-hook   ad-hoc: scan.sh pkgcheck npm <pkg>\n'
  fi
  printf '      guards the AGENT tool call only; a human typing npm i is not covered\n'
  local pcd
  if pcd="$(pkgcheck_cache_dir)"; then
    printf '  ok  findings cache (re-judged by the current policy): %s (unversioned entries expire after %s min)\n' \
      "${pcd#"$ROOT"/}" "$PKGCHECK_CACHE_TTL_MIN"
  else
    printf '  --  findings cache off (PKGCHECK_CACHE=off or not a git repo) — every check re-scans\n'
  fi
  printf '      blocks on %s malice-specific guarddog rules; everything else prints as a note\n' \
    "$(PYTHONDONTWRITEBYTECODE=1 python3 -B -c 'import sys;sys.path.insert(0,"'"$KIT_DIR"'/lib");import pkgcheck;print(len(pkgcheck.BLOCK_RULES))' 2>/dev/null || echo '?')"
}

# ---- allowlist audit: the decay detector ----
# A suppression is an accepted risk with a shelf life. Two ways it rots, both silent and both in the
# dangerous direction (the suppression stays, the protection goes):
#   1. The fix ships, the entry is never deleted -> a FUTURE, real CVE in that package is silenced.
#   2. The same advisory is suppressed on one dimension's path and not the others -> either the risk
#      was accepted twice over or one path is still firing; both mean the record disagrees with itself.
# This audits the FILES, offline — no scan, no network.
#
# The three dependency-CVE paths carry advisory ids; each supports an expiry natively
# (`ignoreUntil` in osv-scanner.toml, `expiredAt` in .trivyignore.yaml) or by the kit's convention
# (`# expires YYYY-MM-DD` in .pip-audit-ignore and anywhere else). Dates are ISO, so a lexical
# compare against `date +%F` is exact — no date arithmetic, no locale.
allowlist_entries(){   # <file> -> "<id>\t<expiry|->" per entry
  local f="$ROOT/$1"
  [ -f "$f" ] || return 0
  case "$1" in
    .pip-audit-ignore)
      awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        { id = $1
          xpiry = "-"
          if (match($0, /expires[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}/))
            xpiry = substr($0, RSTART + RLENGTH - 10, 10)
          print id "\t" xpiry }
      ' "$f" ;;
    osv-scanner.toml)
      awk '
        /^[[:space:]]*\[\[IgnoredVulns\]\]/ { if (id != "") print id "\t" xpiry; id = ""; xpiry = "-"; next }
        /^[[:space:]]*id[[:space:]]*=/ { id = $0; gsub(/.*=[[:space:]]*"?/, "", id); gsub(/".*/, "", id); gsub(/[[:space:]]+$/, "", id) }
        /ignoreUntil/ { if (match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}/)) xpiry = substr($0, RSTART, 10) }
        END { if (id != "") print id "\t" (xpiry == "" ? "-" : xpiry) }
      ' "$f" ;;
    .trivyignore.yaml)
      awk '
        /^[[:space:]]*-[[:space:]]*id:/ { if (id != "") print id "\t" xpiry; xpiry = "-"
          id = $0; gsub(/.*id:[[:space:]]*/, "", id); gsub(/["'"'"']/, "", id); gsub(/[[:space:]]+$/, "", id); next }
        /expiredAt:/ { if (match($0, /[0-9]{4}-[0-9]{2}-[0-9]{2}/)) xpiry = substr($0, RSTART, 10) }
        END { if (id != "") print id "\t" (xpiry == "" ? "-" : xpiry) }
      ' "$f" ;;
    *)
      # Any other allowlist: no id vocabulary, so only the expiry convention is checked.
      awk '
        match($0, /expires[[:space:]]+[0-9]{4}-[0-9]{2}-[0-9]{2}/) {
          print "(entry)\t" substr($0, RSTART + RLENGTH - 10, 10) }
      ' "$f" ;;
  esac
}

DEP_ALLOWLISTS=".pip-audit-ignore osv-scanner.toml .trivyignore.yaml"
OTHER_ALLOWLISTS=".gitleaks.toml .security-exclusions.md"

scan_allowlist(){
  local today; today="$(date +%F)"
  local rc=0 f id exp total expired noexp present=""
  printf '== allowlist audit (%s) ==\n' "$today"
  for f in $DEP_ALLOWLISTS $OTHER_ALLOWLISTS; do
    if [ ! -f "$ROOT/$f" ]; then printf '  --  %-22s absent\n' "$f"; continue; fi
    present="$present $f"
    total=0; expired=0; noexp=0
    while IFS="$(printf '\t')" read -r id exp; do
      [ -n "${id:-}" ] || continue
      total=$((total + 1))
      if [ "$exp" = "-" ]; then noexp=$((noexp + 1))
      elif [ "$exp" \< "$today" ]; then
        expired=$((expired + 1))
        printf '  !!  %-22s EXPIRED %s (%s) — the deferral outlived its date; delete it or renew it\n' "$f" "$id" "$exp"
        rc=1
      fi
    done <<EOF
$(allowlist_entries "$f")
EOF
    printf '  ok  %-22s %s entr(y|ies) · %s expired · %s with no expiry\n' "$f" "$total" "$expired" "$noexp"
    [ "$noexp" -gt 0 ] && printf '      note: an entry with no expiry never becomes loud again — add "expires YYYY-MM-DD"\n'
  done

  # Cross-path: the same advisory id present in one dependency path and literally absent from
  # another. EXACT ids only — PYSEC-…/CVE-…/GHSA-… aliases of one advisory are NOT resolved here, so
  # silence is not proof of coverage. Deliberately under-reports: a false "you're covered" is worse
  # than a missed hint, and a noisy detector is one people stop reading.
  #
  # ONLY package-advisory namespaces are compared. `.trivyignore.yaml` also carries trivy's
  # misconfiguration checks (AVD-…/DS-…/KSV-…) and license ids (LGPL-3.0-or-later) — pip-audit can
  # never report those, so comparing them manufactures a gap that cannot exist. Two of the three
  # warnings on the first real repo were exactly that; a detector two-thirds noise gets ignored.
  local ADVISORY_NS='^(CVE|GHSA|PYSEC|OSV)-'
  local a b ids_a ids_b missing_any=0
  for a in $DEP_ALLOWLISTS; do
    [ -f "$ROOT/$a" ] || continue
    ids_a="$(allowlist_entries "$a" | cut -f1 | grep -Ex "$ADVISORY_NS.*" || true)"
    [ -n "$ids_a" ] || continue
    for b in $DEP_ALLOWLISTS; do
      [ "$a" = "$b" ] && continue
      [ -f "$ROOT/$b" ] || continue
      ids_b="$(allowlist_entries "$b" | cut -f1 || true)"
      while IFS= read -r id; do
        [ -n "${id:-}" ] || continue
        grep -qxF "$id" <<<"$ids_b" || {
          printf '  !!  %s is suppressed in %s but not in %s\n' "$id" "$a" "$b"
          missing_any=1
        }
      done <<EOF
$ids_a
EOF
    done
  done
  if [ "$missing_any" = 1 ]; then
    printf '      A dependency CVE is reported by py-deps + osv + container: an entry in one path\n'
    printf '      does not silence the others. Compared: CVE/GHSA/PYSEC/OSV ids only (trivy misconfig\n'
    printf '      and license ids are out of scope). Exact ids — aliases of one advisory are not\n'
    printf '      resolved, and an OS-package CVE has no pip-audit counterpart, so a warning is a\n'
    printf '      prompt to check, and silence does NOT prove coverage.\n'
    rc=1
  fi
  [ -z "$present" ] && printf '  (no allowlists in this repo — nothing to audit)\n'
  [ "$rc" = 0 ] && printf '  clean: nothing expired, no exact-id gap across the dependency paths\n'
  return $rc
}

# ---- integrity: CHECKSUMS manifest + verify (Tier S Layer 2) ----
CHECKSUMS_FILE="$KIT_DIR/CHECKSUMS"

sha256_of(){ # <file> -> the hex digest only
  if have shasum; then shasum -a 256 "$1" | awk '{print $1}'
  elif have sha256sum; then sha256sum "$1" | awk '{print $1}'
  elif have openssl; then openssl dgst -sha256 "$1" | awk '{print $NF}'
  else return 127; fi
}
have_sha(){ have shasum || have sha256sum || have openssl; }

# The files that make up the kit (for manifest generation), from the kit's own git tree.
# Excludes the manifest itself and local-only notes; per-project/generated files are not
# tracked here so they never appear.
kit_files(){ git -C "$KIT_DIR" ls-files 2>/dev/null | grep -vE '(^|/)CHECKSUMS$|\.local\.md$'; }

# (Re)generate CHECKSUMS — maintainer action, run from the kit's git repo.
scan_checksums(){
  have_sha || { warn checksums "no sha256 tool (shasum/sha256sum/openssl)"; return 1; }
  git -C "$KIT_DIR" rev-parse --show-toplevel >/dev/null 2>&1 || { warn checksums "not a git repo: $KIT_DIR"; return 1; }
  local tmp; tmp="$(mktemp)"
  ( cd "$KIT_DIR" && kit_files | while IFS= read -r f; do
      [ -f "$f" ] && printf '%s  %s\n' "$(sha256_of "$f")" "$f"
    done ) | LC_ALL=C sort -k2 > "$tmp"
  mv "$tmp" "$CHECKSUMS_FILE"
  say checksums "wrote ${CHECKSUMS_FILE#"$ROOT"/} ($(grep -c '' "$CHECKSUMS_FILE") files)"
}

# Cross-check the PIN against the vendored CONTENT.
# CHECKSUMS alone only proves the tree is SELF-consistent: `.kit-version` is not tracked by the
# consumer's git, so a `git checkout` of the vendored dir restores older files AND their matching
# CHECKSUMS while the newer pin file survives — verify passes, and the team believes it runs a
# release it does not. Observed in the wild (pin said v1.10.0, files were v1.9.1, 9 files apart).
# Two checks, best available first:
#   (1) digest binding — bootstrap records sha256(CHECKSUMS) as a 3rd field; recompute it here.
#   (2) label check — for a legacy 2-field pin, the pinned tag must match the newest version in
#       the vendored CHANGELOG. Coarser, but it needs nothing the old vendor didn't already write.
# A branch/SHA pin (`main`, a raw sha) has no version label to compare, so (2) stays quiet.
kit_pin_check(){
  local pin="$KIT_DIR/.kit-version" ref want got top reff
  [ -f "$pin" ] || return 0
  ref="$(awk 'NR==1{print $1}' "$pin")"
  want="$(awk 'NR==1{print $3}' "$pin")"
  if [ -n "${want:-}" ]; then
    got="$(sha256_of "$CHECKSUMS_FILE")"
    [ "$got" = "$want" ] && return 0
    printf 'PIN       .kit-version pins %s, but CHECKSUMS hashes to %s (pin recorded %s) -> the vendored files are NOT that release. Re-run: bootstrap.sh %s\n' \
      "$ref" "${got:0:12}" "${want:0:12}" "$ref"
    return 1
  fi
  case "$ref" in v[0-9]*|[0-9]*) ;; *) return 0 ;; esac
  [ -f "$KIT_DIR/CHANGELOG.md" ] || return 0
  top="$(awk -F'[][]' '/^## \[/{print $2; exit}' "$KIT_DIR/CHANGELOG.md")"
  [ -n "${top:-}" ] || return 0
  reff="${ref#v}"; reff="${reff%%-rc.*}"
  [ "$reff" = "$top" ] && return 0
  printf 'PIN       .kit-version pins %s, but the vendored CHANGELOG stops at %s -> the pin does not match the files. Re-run: bootstrap.sh %s\n' \
    "$ref" "$top" "$ref"
  return 1
}

# Verify the kit's files against CHECKSUMS: MODIFIED / MISSING listed files, plus EXTRA
# files under skills/ (a rogue skill dropped into a vendored copy), plus the pin cross-check
# above. Exit non-zero on any.
scan_verify(){
  [ -f "$CHECKSUMS_FILE" ] || { warn verify "no CHECKSUMS manifest (run: scan.sh checksums)"; return 1; }
  have_sha || { warn verify "no sha256 tool (shasum/sha256sum/openssl)"; return 1; }
  local issues; issues="$(mktemp)"
  local want path got
  while read -r want path; do
    [ -z "${want:-}" ] && continue
    if [ ! -f "$KIT_DIR/$path" ]; then printf 'MISSING   %s\n' "$path" >> "$issues"; continue; fi
    got="$(cd "$KIT_DIR" && sha256_of "$path")"
    [ "$got" = "$want" ] || printf 'MODIFIED  %s\n' "$path" >> "$issues"
  done < "$CHECKSUMS_FILE"
  if [ -d "$KIT_DIR/skills" ]; then
    while IFS= read -r f; do
      grep -qF "  $f" "$CHECKSUMS_FILE" || printf 'EXTRA     %s\n' "$f" >> "$issues"
    done <<EOF
$(cd "$KIT_DIR" && find skills -type f)
EOF
  fi
  kit_pin_check >> "$issues" || true
  if [ -s "$issues" ]; then
    printf '\033[31m[scan:verify] integrity FAILED:\033[0m\n'; cat "$issues"; rm -f "$issues"; return 1
  fi
  rm -f "$issues"; say verify "integrity OK ($(grep -c '' "$CHECKSUMS_FILE") files match CHECKSUMS)"; return 0
}

# ---- evidence.json: the normalized per-finding record (spec: docs/schema/evidence.md) ----
# One shape for every dimension — the object the planned renderers (kit.sarif, HTML report) read,
# so neither has to know a tool's native output. Optional by design: it needs python3 and SARIF
# output, and a missing prerequisite is a notice, never a scan failure (same contract as every
# other optional piece of the kit).
# The builders print the path they wrote. Show the one the user will actually find: no temp
# suffix, and the shared path instead of the holder's staging dir (published a moment later).
py_say(){ sed -e "s|\.$$\.tmp||g" -e "s|${RUN_DIR:-/nonexistent}/publish/|$LOG_DIR/|g"; }

# Exit status (F04): 0 = written; 1 = it could not be. `scan.sh evidence` / `scan.sh report` exit with
# it, so a caller can tell. At the end of a scan (SARIF=1 / REPORT=html) it is reported, not gated:
# the gate is the scan's verdict, and a missing report does not change what the scanners found.
scan_evidence(){
  have python3 || { warn evidence "no python3 -> evidence.json NOT written"; return 1; }
  [ -f "$KIT_DIR/lib/evidence.py" ] || { warn evidence "lib/evidence.py missing -> evidence.json NOT written"; return 1; }
  [ -d "$SARIF_DIR" ] || { warn evidence "no SARIF output yet (re-run with SARIF=1) -> evidence.json NOT written"; return 1; }
  # The judgment layer's decisions live in the findings file a human reads; fold them in when it
  # exists so evidence.json carries both halves (what the tools found, what we decided).
  local fargs=""
  [ -f "$FINDINGS_MD" ] && fargs="--findings $FINDINGS_MD"
  # Write-then-rename, like summary.json: a builder that dies (or is cancelled) mid-write must
  # leave the previous file whole, never half of a new one.
  # shellcheck disable=SC2086
  python3 "$KIT_DIR/lib/evidence.py" --sarif-dir "$SARIF_DIR" --summary "$SUMMARY" --out "$EVIDENCE.$$.tmp" $fargs | py_say \
    && mv -f "$EVIDENCE.$$.tmp" "$EVIDENCE" \
    || { rm -f "$EVIDENCE.$$.tmp"; warn evidence "builder failed -> evidence.json NOT updated"; return 1; }
  # The skills' own findings have no other SARIF home -> put them on the same review surface.
  # With no judgment findings kit_sarif.py writes NOTHING on purpose (an empty upload would close
  # every open kit alert) — so rename only what it actually wrote.
  local rc=0
  if [ -f "$KIT_DIR/lib/kit_sarif.py" ]; then
    if python3 "$KIT_DIR/lib/kit_sarif.py" --evidence "$EVIDENCE" --out "$SARIF_DIR/kit.sarif.$$.tmp" | py_say; then
      [ -f "$SARIF_DIR/kit.sarif.$$.tmp" ] && mv -f "$SARIF_DIR/kit.sarif.$$.tmp" "$SARIF_DIR/kit.sarif"
    else
      rm -f "$SARIF_DIR/kit.sarif.$$.tmp"; warn evidence "kit.sarif NOT emitted"; rc=1
    fi
  fi
  if [ "$REPORT" = "html" ]; then scan_report || rc=1; fi
  return $rc
}

# One self-contained HTML file to attach, mail, or print to PDF — opt-in via REPORT=html, or
# `scan.sh report` to re-render. No server, no JS framework, no external fetch: it must open
# offline in five years. Renders MORE than kit.sarif — including the triage decisions on scanner
# findings, which SARIF leaves to each tool's own run.
scan_report(){
  have python3 || { warn report "no python3 -> HTML report NOT written"; return 1; }
  [ -f "$KIT_DIR/lib/report_html.py" ] || { warn report "lib/report_html.py missing -> report NOT written"; return 1; }
  [ -f "$EVIDENCE" ] || { warn report "no evidence.json yet (re-run with SARIF=1) -> report NOT written"; return 1; }
  # --date is when the report is generated; the scan's own time comes from summary.json, and only
  # when that summary is the evidence's own run (report_html.py checks).
  python3 "$KIT_DIR/lib/report_html.py" --evidence "$EVIDENCE" --out "$REPORT_HTML.$$.tmp" \
    --repo "$(basename "$ROOT")" --date "$TODAY" --summary "$SUMMARY" | py_say \
    && mv -f "$REPORT_HTML.$$.tmp" "$REPORT_HTML" \
    || { rm -f "$REPORT_HTML.$$.tmp"; warn report "report NOT written"; return 1; }
  return 0
}

SARIF="${SARIF:-0}"
CMD="${1:-all}"
TODAY="$(date +%F)"
LOG_DIR="$ROOT/docs/security/scan-findings"

# ---- run lock — one writer at a time for the shared record ----------------------------------
# Two scans can overlap for entirely ordinary reasons: a pre-push runs `all` while someone runs
# `scan.sh sast` by hand, or a pre-commit fires while the previous push is still scanning. They
# then write the SAME `raw-<date>.log` (interleaved lines) and the same `summary.json` (one
# truncates it while /sec-triage is reading it — a half-written record the reader cannot detect).
# The lock serializes the writers; it deliberately does NOT gate the scan itself: refusing to scan
# because someone else is scanning would block a push for a reason that has nothing to do with
# security. If the lock cannot be taken, the run continues into its OWN run directory and says so.
#
# What the lock protects is the SHARED record — summary.json, sarif/, evidence.json, report-*.html
# (what /sec-triage, Code Scanning upload and humans read). Every run, holder or not, first writes
# into its own runs/<run-id>/; only the holder then publishes that into the shared record, at the
# very end, in one short step that a Ctrl-C cannot split. A run without the lock never touches it.
#
# Liveness, not age, decides whether a lock is stale. A scan can legitimately run for longer than
# any fixed limit (a monorepo, a cold docker pull), and taking a LIVE run's lock because it is old
# puts two writers back on the shared record. So the owner file records who took the lock — pid,
# a random token, host, and the process start time — and the holder refreshes a heartbeat while it
# runs. A lock is reclaimed only when its owner is provably gone: the pid is dead, or alive but a
# different process (pid reuse: the start time differs), or — where the pid cannot be checked (a
# lock taken on another host sharing this .git) — the heartbeat has been silent for
# SCAN_LOCK_STALE_MIN. An unreadable owner file is reclaimed after a short grace (it may be a lock
# being created this instant), never waited on forever. Reclaiming happens under a second, short
# lock with the state re-read inside it, so two runs that both saw the stale lock cannot each
# delete it and end up holding it twice. Release, and publishing, happen only under our own token.
SCAN_LOCK_WAIT="${SCAN_LOCK_WAIT:-30}"                     # seconds to wait for the other run
SCAN_LOCK_STALE_MIN="${SCAN_LOCK_STALE_MIN:-60}"           # silent heartbeat this long = crashed run
SCAN_LOCK_HEARTBEAT_SEC="${SCAN_LOCK_HEARTBEAT_SEC:-30}"   # how often the holder says it is alive
SCAN_LOCK_GRACE_SEC=10                                     # a lock younger than this may still be writing its owner file
LOCK_DIR=""
LOCK_HELD=0
LOCK_TOKEN=""
LOCK_HB_PID=""
LOCK_HOST="$(hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)"

file_mtime(){ stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null; }
# `kill -0` fails on another user's live process too (EPERM) -> fall back to ps before calling it dead.
proc_alive(){ kill -0 "$1" 2>/dev/null || ps -p "$1" >/dev/null 2>&1; }
proc_start(){ ps -o lstart= -p "$1" 2>/dev/null | sed 's/  *$//'; }
lock_field(){ sed -n "s/^$1=//p" "$2/owner" 2>/dev/null | head -1; }

scan_lock_path(){
  local common
  if common="$(git rev-parse --git-common-dir 2>/dev/null)"; then
    case "$common" in /*) ;; *) common="$ROOT/$common" ;; esac
    printf '%s/security-audit-cache/scan.lock' "$common"
  else
    # No .git (a tarball checkout): keep the lock beside the artifacts it protects.
    printf '%s/.scan.lock' "$LOG_DIR"
  fi
}

# Classify a lock dir. Prints "<state><TAB><why>": state is live | stale | gone.
scan_lock_state(){
  local d="$1" now pid host pstart cur hb age mt omt who
  [ -d "$d" ] || { printf 'gone\t-'; return; }
  now="$(date +%s)"
  pid="$(sed -n 's/^pid=\([0-9][0-9]*\).*/\1/p' "$d/owner" 2>/dev/null | head -1)"
  if [ -z "$pid" ]; then
    mt="$(file_mtime "$d")"; omt="$(file_mtime "$d/owner")"
    [ -n "$omt" ] && [ "${omt:-0}" -gt "${mt:-0}" ] && mt="$omt"
    age=$(( now - ${mt:-$now} ))
    if [ "$age" -ge "$SCAN_LOCK_GRACE_SEC" ]; then printf 'stale\tunreadable owner, %ss old' "$age"
    else printf 'live\tbeing created'; fi
    return
  fi
  host="$(lock_field host "$d")"
  who="pid=$pid host=${host:-?} cmd=$(lock_field cmd "$d" | sed 's/ .*//')"
  hb="$(cat "$d/heartbeat" 2>/dev/null)"
  case "$hb" in ''|*[!0-9]*) hb="$(file_mtime "$d/owner")" ;; esac
  age=$(( now - ${hb:-$now} ))
  if [ -z "$(lock_field token "$d")" ]; then
    # Written by a kit older than the heartbeat (one-line owner). Keep that kit's rule: a dead pid,
    # or a lock dir older than SCAN_LOCK_STALE_MIN.
    who="$(head -1 "$d/owner" 2>/dev/null)"
    proc_alive "$pid" || { printf 'stale\towner process gone: %s' "$who"; return; }
    [ -n "$(find "$d" -maxdepth 0 -mmin "+$SCAN_LOCK_STALE_MIN" 2>/dev/null)" ] \
      && { printf 'stale\tpre-heartbeat lock older than %s min: %s' "$SCAN_LOCK_STALE_MIN" "$who"; return; }
    printf 'live\t%s' "$who"; return
  fi
  if [ "$host" != "$LOCK_HOST" ]; then
    # Another host's pid means nothing here: the heartbeat is the only liveness signal.
    [ "$age" -gt $(( SCAN_LOCK_STALE_MIN * 60 )) ] \
      && { printf 'stale\tno heartbeat for %ss (>%s min): %s' "$age" "$SCAN_LOCK_STALE_MIN" "$who"; return; }
    printf 'live\t%s, heartbeat %ss ago' "$who" "$age"; return
  fi
  proc_alive "$pid" || { printf 'stale\towner process gone: %s' "$who"; return; }
  pstart="$(lock_field pstart "$d")"; cur="$(proc_start "$pid")"
  if [ -n "$pstart" ] && [ "$pstart" != "-" ] && [ -n "$cur" ]; then
    [ "$pstart" != "$cur" ] && { printf 'stale\tpid reused (started %s, lock taken by one started %s): %s' "$cur" "$pstart" "$who"; return; }
    printf 'live\t%s, heartbeat %ss ago' "$who" "$age"; return
  fi
  # Alive, but cannot tell whether it is the same process: a live holder heartbeats, so silence decides.
  [ "$age" -gt $(( SCAN_LOCK_STALE_MIN * 60 )) ] \
    && { printf 'stale\tno heartbeat for %ss (>%s min), pid unverifiable: %s' "$age" "$SCAN_LOCK_STALE_MIN" "$who"; return; }
  printf 'live\t%s, heartbeat %ss ago' "$who" "$age"
}

# Reclaim a stale lock under a short guard lock, re-reading the state inside it: between our first
# look and now, another run may already have reclaimed it and taken a fresh one.
scan_lock_reclaim(){
  local guard="$LOCK_DIR.reclaim" st mt
  if ! mkdir "$guard" 2>/dev/null; then
    # A reclaim takes milliseconds; a guard a minute old belongs to a reclaimer that died mid-way.
    mt="$(file_mtime "$guard")"
    [ -n "$mt" ] && [ $(( $(date +%s) - mt )) -gt 60 ] && rm -rf "$guard" 2>/dev/null
    return 1
  fi
  st="$(scan_lock_state "$LOCK_DIR")"
  if [ "${st%%	*}" = stale ]; then
    note lock "stale lock reclaimed (${st#*	})"
    rm -rf "$LOCK_DIR" 2>/dev/null
  fi
  rmdir "$guard" 2>/dev/null
  return 0
}

# The heartbeat: a background loop that refreshes $LOCK_DIR/heartbeat while this run is alive and
# still owns the lock. It never holds our stdout (it would keep `tee` and callers waiting) and it
# exits by itself if this shell is SIGKILLed.
scan_lock_heartbeat_start(){
  local dir="$LOCK_DIR" tok="$LOCK_TOKEN" parent="$$" iv="$SCAN_LOCK_HEARTBEAT_SEC"
  (
    trap - EXIT INT TERM
    while sleep "$iv"; do
      kill -0 "$parent" 2>/dev/null || exit 0
      [ "$(lock_field token "$dir")" = "$tok" ] || exit 0
      date +%s > "$dir/heartbeat.tmp" 2>/dev/null && mv -f "$dir/heartbeat.tmp" "$dir/heartbeat" 2>/dev/null
    done
  ) </dev/null >/dev/null 2>&1 &
  LOCK_HB_PID=$!
}

scan_lock_owned(){ [ -n "$LOCK_TOKEN" ] && [ "$(lock_field token "$LOCK_DIR")" = "$LOCK_TOKEN" ]; }

# `mkdir` is the atomic primitive here: it either creates the directory or fails, with no window
# between the check and the create that a second process could slip through.
scan_lock_acquire(){
  local st waited=0 ps0
  LOCK_DIR="$(scan_lock_path)"
  mkdir -p "$(dirname "$LOCK_DIR")" 2>/dev/null || return 1
  LOCK_TOKEN="$$-$(date +%s)-$RANDOM$RANDOM"
  while :; do
    if mkdir "$LOCK_DIR" 2>/dev/null; then
      ps0="$(proc_start "$$")"
      # Owner written whole or not at all: a reader never parses half of it.
      printf 'pid=%s\ntoken=%s\nhost=%s\npstart=%s\nstarted=%s\ncmd=%s\ndate=%s\n' \
        "$$" "$LOCK_TOKEN" "$LOCK_HOST" "${ps0:--}" "$(date +%s)" "$CMD" "$(date +%FT%T)" \
        > "$LOCK_DIR/owner.tmp" 2>/dev/null && mv -f "$LOCK_DIR/owner.tmp" "$LOCK_DIR/owner"
      date +%s > "$LOCK_DIR/heartbeat" 2>/dev/null
      LOCK_HELD=1
      scan_lock_heartbeat_start
      return 0
    fi
    st="$(scan_lock_state "$LOCK_DIR")"
    case "${st%%	*}" in
      gone)  continue ;;
      stale) scan_lock_reclaim && continue ;;
    esac
    if [ "$waited" -ge "$SCAN_LOCK_WAIT" ]; then return 1; fi
    [ "$waited" -eq 0 ] && say lock "another scan holds the lock (${st#*	}) — waiting up to ${SCAN_LOCK_WAIT}s"
    sleep 1
    waited=$((waited + 1))
  done
}

scan_lock_stop_heartbeat(){
  [ -n "$LOCK_HB_PID" ] && kill "$LOCK_HB_PID" 2>/dev/null
  LOCK_HB_PID=""
}

# Remove the lock only if it is still ours. If another run took it over (it judged us stale), it
# is theirs now: deleting it would put two writers back on the record.
scan_lock_release(){
  scan_lock_stop_heartbeat
  if [ "$LOCK_HELD" = "1" ] && [ -n "$LOCK_DIR" ]; then
    if scan_lock_owned; then
      rm -rf "$LOCK_DIR" 2>/dev/null
    elif [ -d "$LOCK_DIR" ]; then
      note lock "the lock is no longer ours — left in place for its current owner"
    fi
  fi
  LOCK_HELD=0
}

REPORT="${REPORT:-}"

# ---- dimension registry: the adapter contract (docs/adapters.md) ----
# What runs is data, not a case statement: dispatch, the help text and the closing summary all read
# these two tables, so adding a dimension is one adapter function + one line in each — not five
# edits that drift apart. bash 3.2 (macOS) has no associative arrays, hence plain text tables.
#
# DIM_UNITS — one adapter per line:
#   unit     the registry key (unique)
#   record   the name summary.json gives it; two units may share one (`changed` is sast on a diff)
#   entry    the adapter function: scan_<x>, no arguments, return 0/1/RC_INDETERMINATE/other
#   gate     hard (findings block) · soft (findings reported, never block) · artifact (writes a file)
#   needs    docker · pyrun (uvx or pipx) · - (finds its own toolchain)
DIM_UNITS='
secret        secret     scan_secret          hard      docker
staged        staged     scan_secret_staged   hard      docker
sast          sast       scan_sast            hard      pyrun
sast-changed  sast       scan_sast_changed    hard      pyrun
py-deps       py-deps    scan_py_deps         hard      pyrun
js-deps       js-deps    scan_js_deps         hard      -
iac           iac        scan_iac             soft      pyrun
container     container  scan_container       soft      docker
sbom          sbom       scan_sbom            artifact  docker
osv           osv        scan_osv             hard      docker
guarddog      guarddog   scan_guarddog        hard      pyrun
zizmor        zizmor     scan_zizmor          hard      pyrun
'
# SCAN_COMMANDS — command | the units it runs, in order | what it leaves out (closing summary).
SCAN_COMMANDS='
deps      | py-deps js-deps |
secret    | secret |
staged    | staged |
sast      | sast |
changed   | sast-changed |
iac       | iac |
container | container |
sbom      | sbom |
osv       | osv |
guarddog  | guarddog |
zizmor    | zizmor |
fast      | staged py-deps js-deps | secret (full history) sast container iac osv guarddog zizmor sbom
all       | secret sast py-deps js-deps container iac | osv guarddog zizmor sbom
'
# <command> <field 2|3> -> that field, trimmed; exit 1 for a command the table does not know.
scan_command_field(){
  awk -F'|' -v c="$1" -v f="$2" '{k=$1; gsub(/[[:space:]]/,"",k)} k==c && k!="" {
    v=$f; gsub(/^[[:space:]]+|[[:space:]]+$/,"",v); print v; found=1; exit } END{exit !found}' <<<"$SCAN_COMMANDS"
}
scan_commands(){ awk -F'|' '{k=$1; gsub(/[[:space:]]/,"",k)} k!=""{print k}' <<<"$SCAN_COMMANDS"; }
# <unit> -> "record entry gate needs"; exit 1 for an unknown unit.
dim_unit(){ awk -v u="$1" '$1==u{print $2, $3, $4, $5; found=1; exit} END{exit !found}' <<<"$DIM_UNITS"; }

# A core.hooksPath that points at a directory which does not exist makes git run NO hooks, with no
# message. Seen on a repo with ~50 worktrees sharing one config: the path led into one worktree's
# copy of the kit, whose branch had dropped it. Printed by doctor and in every closing summary.
hookspath_check(){
  local hp abs
  hp="$(git -C "$ROOT" config --get core.hooksPath 2>/dev/null)" || return 0
  [ -n "$hp" ] || return 0
  case "$hp" in /*) abs="$hp" ;; \~/*) abs="$HOME/${hp#\~/}" ;; *) abs="$ROOT/$hp" ;; esac
  [ -d "$abs" ] && return 0
  printf 'core.hooksPath -> %s, which does not exist here: git runs NO hooks in this worktree (no kit checks, none of your own). Fix: bash %s/install.sh' \
    "$hp" "${KIT_DIR#"$ROOT"/}"
}

# Is the scanned branch behind its upstream? Then the scan judged older code than the remote has:
# things fixed upstream look open, code added upstream went unscanned. Seen on a real repo, 1389
# commits behind. Read-only: no fetch, so "behind" is as of the last fetch, and its age is said.
# -> "branch<TAB>upstream<TAB>ahead<TAB>behind<TAB>hours since the last fetch", or nothing.
git_freshness(){
  local br up ab fh="" fm
  br="$(git -C "$ROOT" symbolic-ref -q --short HEAD 2>/dev/null)" || br="(detached)"
  up="$(git -C "$ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null)" || return 0
  ab="$(git -C "$ROOT" rev-list --left-right --count 'HEAD...@{u}' 2>/dev/null)" || return 0
  fm="$(file_mtime "$(git -C "$ROOT" rev-parse --git-common-dir 2>/dev/null | sed "s|^\([^/]\)|$ROOT/\1|")/FETCH_HEAD" 2>/dev/null)"
  [ -n "$fm" ] && fh="$(( ( $(date +%s) - fm ) / 3600 ))"
  printf '%s\t%s\t%s\t%s\t%s\n' "$br" "$up" "$(awk '{print $1}' <<<"$ab")" "$(awk '{print $2}' <<<"$ab")" "$fh"
}
git_freshness_line(){   # <freshness> [doctor] -> the warning, or nothing when not behind
  local br up behind fh what="this scan saw older code than the upstream has; pull, then scan again"
  [ "${2:-}" = doctor ] && what="a scan now sees older code than the upstream has; pull first"
  IFS="$(printf '\t')" read -r br up _ behind fh <<<"$1"
  [ -n "$behind" ] && [ "$behind" -gt 0 ] 2>/dev/null || return 0
  printf 'git: %s is %s commit(s) behind %s%s — %s' \
    "$br" "$behind" "$up" "${fh:+ (as of the last fetch, ${fh}h ago)}" "$what"
}

# ---- config check (F24) ----------------------------------------------------------------------
# .security-audit.conf is SOURCED: it is bash, and runs with your privileges on every scan and hook.
# Nothing here refuses to load it (fail-open, as the gate is). It says out loud what the file does
# beyond setting values: a syntax error, a setting scan.sh does not read (a typo is otherwise silently
# ignored), a line that runs a command, a command substitution in a value, a value of the wrong type.
# One line per warning, on stdout. Known names come from security-audit.conf.example, plus the
# per-run env knobs that also work from the config.
CONFIG_ENV_KNOBS="SARIF REPORT BASE_REF SKIP_SECURITY"
config_check(){
  [ -f "$CONF" ] || return 0
  local known err v val
  known=" $(grep -oE '\$\{[A-Z][A-Z0-9_]*:=|^#? *[A-Z][A-Z0-9_]*=' "$KIT_DIR/security-audit.conf.example" 2>/dev/null \
            | grep -oE '[A-Z][A-Z0-9_]*' | sort -u | tr '\n' ' ')$CONFIG_ENV_KNOBS "
  err="$(bash -n "$CONF" 2>&1 | head -1)"
  [ -n "$err" ] && printf 'syntax error: %s\n' "${err#"$CONF": }"
  awk -v known="$known" '
    { line = $0; sub(/^[ \t]+/, "", line) }
    line == "" || line ~ /^#/ { next }
    {
      name = ""
      if (match(line, /^:[ \t]+"?\$\{[A-Za-z_][A-Za-z0-9_]*:?[=-]/)) {
        name = substr(line, RSTART, RLENGTH); sub(/^:[ \t]+"?\$\{/, "", name); sub(/:?[=-]$/, "", name)
      } else if (match(line, /^(export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*=/)) {
        name = substr(line, RSTART, RLENGTH); sub(/^export[ \t]+/, "", name); sub(/=$/, "", name)
      } else {
        split(line, w, /[ \t;|&<>]+/)
        printf "line %d runs a command (%s), not a setting: %s\n", NR, w[1], substr(line, 1, 60); next
      }
      if (index(known, " " name " ") == 0) printf "line %d: unknown setting %s (a typo? scan.sh does not read it)\n", NR, name
      if (line ~ /\$\(|`/) printf "line %d: command substitution in %s runs code when the config is loaded\n", NR, name
      else if (line ~ /;[ \t]*[A-Za-z]/) printf "line %d: more than one statement on the line (;)\n", NR
    }' "$CONF"
  # Types, on the values in force (env > config > default).
  for v in SCAN_LOCK_WAIT SCAN_LOCK_STALE_MIN SCAN_LOCK_HEARTBEAT_SEC SCAN_RUNS_KEEP_DAYS PKGCHECK_CACHE_TTL_MIN TRIVY_DB_MAX_AGE_H; do
    val="${!v:-}"; [ -z "$val" ] && continue
    case "$val" in *[!0-9]*) printf '%s=%s: must be a whole number (integer)\n' "$v" "$val" ;; esac
  done
  case "${SCAN_OFFLINE:-0}" in 0|1) ;; *) printf 'SCAN_OFFLINE=%s: must be 0 or 1\n' "$SCAN_OFFLINE" ;; esac
  case "${SARIF:-0}" in 0|1) ;; *) printf 'SARIF=%s: must be 0 or 1\n' "$SARIF" ;; esac
  case "${PKGCHECK_CACHE:-on}" in on|off|refresh) ;; *) printf 'PKGCHECK_CACHE=%s: must be on, off or refresh\n' "$PKGCHECK_CACHE" ;; esac
  case "${REPORT:-}" in ""|html) ;; *) printf 'REPORT=%s: must be empty or html\n' "$REPORT" ;; esac
  return 0
}
CONFIG_WARNINGS="$(config_check)"
config_report(){   # the full list, for doctor / verify
  [ -f "$CONF" ] || return 0
  local n=0; [ -n "$CONFIG_WARNINGS" ] && n="$(printf '%s\n' "$CONFIG_WARNINGS" | wc -l | tr -d ' ')"
  if [ "$n" = 0 ]; then printf '  ok  config %s: settings only, all known\n' "${CONF#"$ROOT"/}"; return 0; fi
  printf '  !!  config %s: %s warning(s) — it is bash, sourced on every scan and hook:\n' "${CONF#"$ROOT"/}" "$n"
  printf '%s\n' "$CONFIG_WARNINGS" | sed 's/^/        /'
}

# help: the usage block at the top of this file, plus what `all` leaves out and what the tags mean.
scan_help(){
  awk '/^# Usage:/{on=1} on && /^#$/{exit} on{sub(/^# ?/,""); print}' "$KIT_DIR/scan.sh"
  printf '\n  [HARD] blocks commit/push on a finding · [soft] reported, never blocks · [artifact] writes a file\n'
  printf "  not in 'all': %s — run them by name (or /sec-audit)\n" "$(scan_command_field all 3)"
  printf '  Needs docker: secret staged container sbom osv · needs uvx or pipx: sast changed iac deps(pip-audit) guarddog zizmor\n'
  printf '  Missing docker or uvx/pipx -> that dimension is "skipped" (not a pass); the run says which.\n'
  printf '  Start here: scan.sh doctor -> scan.sh all -> read the closing summary -> /sec-triage\n'
}
# warm: pay the one-time downloads now (pinned images + the trivy DB), not on the first pre-push.
scan_warm(){
  docker_ok || { warn warm "no docker -> nothing to warm"; return 1; }
  local i rc=0
  for i in "$(img ghcr.io/gitleaks/gitleaks "$GITLEAKS_VER" "$GITLEAKS_DIGEST")" "$(img aquasec/trivy "$TRIVY_VER" "$TRIVY_DIGEST")" \
           "$(img anchore/syft "$SYFT_VER" "$SYFT_DIGEST")" "$(img ghcr.io/google/osv-scanner "$OSV_VER" "$OSV_DIGEST")"; do
    say warm "docker pull $i"
    docker pull -q "$i" >/dev/null || { warn warm "pull failed: $i"; rc=1; }
  done
  say warm "trivy vulnerability DB -> $TRIVY_CACHE (~130 MiB, refreshed after ${TRIVY_DB_MAX_AGE_H}h)"
  # shellcheck disable=SC2046
  docker run --rm $(trivy_cache_mount) "$(img aquasec/trivy "$TRIVY_VER" "$TRIVY_DIGEST")" image --download-db-only --no-progress || rc=1
  return $rc
}
case "${1:-}" in help|-h|--help) scan_help; exit 0 ;; esac
[ "${1:-}" = "warm" ]      && { scan_warm; exit $?; }
[ "${1:-}" = "doctor" ]    && { scan_doctor; config_report; exit 0; }
[ "${1:-}" = "verify" ]    && { scan_verify; vrc=$?; config_report; exit "$vrc"; }
[ "${1:-}" = "checksums" ] && { scan_checksums; exit $?; }
[ "${1:-}" = "rules-test" ] && { scan_rules_test; exit $?; }
[ "${1:-}" = "allowlist" ] && { scan_allowlist; exit $?; }
[ "${SKIP_SECURITY:-0}" = "1" ] && { say skip "SKIP_SECURITY=1 -> all scans skipped"; exit 0; }
[ "${1:-}" = "pkgcheck" ] && { shift; scan_pkgcheck "$@"; exit $?; }

# Wall clock in milliseconds: bash 5's EPOCHREALTIME, else perl, else whole seconds (bash 3.2 on
# macOS has neither %N nor EPOCHREALTIME; a duration rounded to the second is still a duration).
now_ms(){
  if [ -n "${EPOCHREALTIME:-}" ]; then local t="${EPOCHREALTIME/[.,]/}"; printf '%s\n' "$((10#$t / 1000))"
  elif have perl; then perl -MTime::HiRes=time -e 'printf "%d\n", time()*1000'
  else printf '%s\n' "$(( $(date +%s) * 1000 ))"; fi
}

# Record each dimension's exit code to RESULTS_FILE (survives the tee subshell).
# Columns: name, exit code, status, gate, milliseconds, reason (last: it is prose and may be empty).
_dim(){ local name="$1"; shift; DIM_STATUS=""; DIM_REASON=""; DIM_WARN=""
  local t0; t0="$(now_ms)"
  "$@"; local c=$? st gate=allow ms
  ms=$(( $(now_ms) - t0 ))
  st="$DIM_STATUS"
  if [ -z "$st" ]; then
    case "$c" in 0) st=pass ;; 1) st=findings ;; "$RC_INDETERMINATE") st=indeterminate ;; *) st=error ;; esac
  fi
  [ "$c" -ne 0 ] && [ "$c" -ne "$RC_INDETERMINATE" ] && gate=block
  # Tabs/newlines would break the record; the reason is one line of prose.
  # A warn line explains a dimension that did not inspect; on pass/findings the last warn is just a
  # notice (e.g. "VIRTUAL_ENV ignored") and would read as the cause of the result — so only an
  # explicit dim_mark reason is kept there.
  local why="$DIM_REASON"
  case "$st" in pass|findings) ;; *) [ -n "$why" ] || why="$DIM_WARN" ;; esac
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$name" "$c" "$st" "$gate" "$ms" "$(printf '%s' "$why" | tr '\t\n' '  ')" >> "$RESULTS_FILE"
  # RC_INDETERMINATE is recorded but never blocks: it says "no opinion", not "finding".
  [ "$c" -ne 0 ] && [ "$c" -ne "$RC_INDETERMINATE" ] && return 1; return 0; }

# Every unit of the command runs, in table order, even after one blocks: the gate is the OR of them.
run_scans(){
  local rc=0 units u row rec entry
  if ! units="$(scan_command_field "${1:-all}" 2)"; then
    echo "unknown command: $1 ($(scan_commands | paste -sd'|' -)|doctor|verify|checksums|rules-test|allowlist|evidence|report|warm|help)"
    return 2
  fi
  for u in $units; do
    row="$(dim_unit "$u")" || { echo "registry: unit '$u' of '$1' is not in DIM_UNITS"; return 2; }
    read -r rec entry _ <<<"$row"
    _dim "$rec" "$entry" || rc=1
  done
  return $rc
}

# Every scan: write raw output to a per-day file (persistent trail) + a machine-readable
# summary.json + (opt-in) SARIF, then print a triage instruction. raw-*.log/summary.json
# are transient (gitignored); the persistent record is the triage's findings-*.md.
#
# The shared record (PUB_*) is what readers use; this run's own copy (RUN_DIR) is where it is
# built. The run id is in summary.json, never in evidence.json: that one must diff to nothing
# across two runs over unchanged code.
RUN_ID="$(date +%Y%m%dT%H%M%S)-$$"
RUNS_DIR="$LOG_DIR/runs"
RUN_DIR="$RUNS_DIR/$RUN_ID"
SCAN_RUNS_KEEP_DAYS="${SCAN_RUNS_KEEP_DAYS:-7}"   # a lock-less run's own record is kept this long
PUB_SUMMARY="$LOG_DIR/summary.json"
PUB_SARIF="$LOG_DIR/sarif"
PUB_EVIDENCE="$LOG_DIR/evidence.json"
PUB_REPORT="$LOG_DIR/report-$TODAY.html"
LOG="$LOG_DIR/raw-$TODAY.log"
SUMMARY="$RUN_DIR/summary.json"
SARIF_DIR="$RUN_DIR/sarif"
EVIDENCE="$RUN_DIR/evidence.json"
FINDINGS_MD="$LOG_DIR/findings-$TODAY.md"
REPORT_HTML="$RUN_DIR/report-$TODAY.html"
RESULTS_FILE="$(mktemp)"

# The holder's run dir is only a staging area (its log goes to the daily trail): drop it on any
# exit, published or not. A lock-less run's dir IS its record, so it stays — without summary.json
# when the run was cut short. The dir goes BEFORE the lock, so no other run sees it half-removed.
scan_exit_cleanup(){
  rm -f "$RESULTS_FILE"
  [ "$LOCK_HELD" = "1" ] && rm -rf "$RUN_DIR" 2>/dev/null
  scan_lock_release
}
# A trapped INT/TERM must END the run. Without the `exit`, bash runs the handler and carries on:
# the lock is released and the rest of the script then writes the shared record without it.
scan_abort(){
  trap - EXIT INT TERM
  note run "cancelled (signal) -> nothing published; the previous record is unchanged"
  scan_exit_cleanup
  exit "$1"
}
trap 'scan_exit_cleanup' EXIT
trap 'scan_abort 130' INT
trap 'scan_abort 143' TERM
mkdir -p "$LOG_DIR"
# Everything this script writes here is transient and regenerated on the next run; the record a
# team keeps is the triage file. Without this, a plain `git add -A` in a consumer repo commits raw
# logs, SARIF and per-run records. Written once, before any artifact exists, and never over a
# .gitignore the repo already has there (a team may have chosen to track more).
[ -e "$LOG_DIR/.gitignore" ] || cat > "$LOG_DIR/.gitignore" 2>/dev/null <<'EOF'
# Written by security-audit-kit (scan.sh). Scan artifacts here are transient and regenerated on
# every run: raw logs, summary.json, sarif/, evidence.json, HTML reports, runs/<run-id>/.
# The persistent record is the triage file, findings-<date>.md, which stays tracked.
# Edit freely: scan.sh never overwrites this file once it exists.
*
!.gitignore
!findings-*.md
EOF

# Take the writer lock before ANY artifact is touched — `evidence`/`report` included, since they
# read summary.json + sarif/ and would otherwise be able to read a record mid-write.
if ! scan_lock_acquire; then
  # evidence/report exist only to rewrite the SHARED record; without the lock that is exactly the
  # write we must not make. Unlike a scan, refusing costs nothing: re-run it once the other is done.
  case "$CMD" in evidence|report)
    note lock "could not take the lock in ${SCAN_LOCK_WAIT}s -> '$CMD' not run (it rewrites the shared record); retry when the other scan is done"
    exit 1 ;;
  esac
  note lock "could not take the lock in ${SCAN_LOCK_WAIT}s -> running anyway, into a SEPARATE run directory"
  note lock "(the scan is never skipped for a lock; the shared record stays the other run's: ${RUN_DIR#"$ROOT"/})"
  LOG="$RUN_DIR/raw.log"
fi

# Rebuild the record / re-render the report from what is already on disk, without re-scanning.
# Holding the lock, these work on the shared record directly (each write is write-then-rename).
if [ "$CMD" = "evidence" ] || [ "$CMD" = "report" ]; then
  SUMMARY="$PUB_SUMMARY"; SARIF_DIR="$PUB_SARIF"; EVIDENCE="$PUB_EVIDENCE"; REPORT_HTML="$PUB_REPORT"
  [ "$CMD" = "evidence" ] && { scan_evidence; exit $?; }
  scan_report; exit $?
fi

# JSON string or null: free prose (a warn line, a path, a config string).
json_str(){ [ -n "$1" ] || { printf 'null'; return; }
  local v="${1//\\/\\\\}"; v="${v//\"/\\\"}"; printf '"%s"' "$v"; }

# ---- provenance (F03): what this run looked at, with what — taken BEFORE any scan, because some
# dimensions write into the tree (sbom) and would make every run look dirty. Content identity only:
# no time, no run id, so evidence.json can carry it and still diff to nothing on unchanged code.
kit_version(){
  if [ -f "$KIT_DIR/.kit-version" ]; then awk '{print $1; exit}' "$KIT_DIR/.kit-version"
  else awk '/^## \[[0-9]/{v=$2; gsub(/[][]/,"",v); print v; exit}' "$KIT_DIR/CHANGELOG.md" 2>/dev/null; fi
}
local_rules_sha(){   # one digest over every local rule file (path + content), or nothing
  local f list; list="$(local_rules_files 2>/dev/null | sort)"
  [ -n "$list" ] && have_sha || return 0
  local tmp; tmp="$(mktemp)"
  while IFS= read -r f; do
    [ -f "$f" ] && printf '%s %s\n' "${f#"$ROOT"/}" "$(sha256_of "$f")"
  done <<<"$list" > "$tmp"
  sha256_of "$tmp"; rm -f "$tmp"
}
tool_ref(){ printf '%s:%s%s' "$1" "$2" "${3:+@$3}"; }   # image:tag@digest — both, for a reader
provenance_json(){
  local commit dirty="null" conf_sha="" kit_sha=""
  commit="$(git -C "$ROOT" rev-parse -q --verify HEAD 2>/dev/null)"
  if [ -n "$commit" ]; then
    # The record itself lives in the tree; its churn is not a change to what was scanned.
    if [ -n "$(git -C "$ROOT" status --porcelain -- . ":(exclude)${LOG_DIR#"$ROOT"/}" 2>/dev/null)" ]; then dirty=true
    else dirty=false; fi
  fi
  have_sha && [ -f "$CONF" ] && conf_sha="$(sha256_of "$CONF")"
  have_sha && [ -f "$CHECKSUMS_FILE" ] && kit_sha="$(sha256_of "$CHECKSUMS_FILE")"
  printf '{"commit": %s, "dirty": %s,\n' "$(json_str "$commit")" "$dirty"
  printf '    "kit": {"version": %s, "checksums_sha256": %s},\n' "$(json_str "$(kit_version)")" "$(json_str "$kit_sha")"
  printf '    "config_sha256": %s,\n' "$(json_str "$conf_sha")"
  printf '    "scope": {"command": %s, "sast_paths": %s, "tf_dir": %s, "base_ref": %s},\n' \
    "$(json_str "$CMD")" "$(json_str "${SAST_PATHS:-.}")" "$(json_str "${TF_DIR:-}")" "$(json_str "${BASE_REF:-}")"
  printf '    "rules": {"semgrep_configs": %s, "local_rules_sha256": %s},\n' \
    "$(json_str "$SEMGREP_CONFIGS")" "$(json_str "$(local_rules_sha)")"
  printf '    "tools": {"semgrep": %s, "checkov": %s, "pip-audit": %s, "guarddog": %s, "zizmor": %s,\n' \
    "$(json_str "$SEMGREP_VER")" "$(json_str "$CHECKOV_VER")" "$(json_str "$PIP_AUDIT_VER")" \
    "$(json_str "$GUARDDOG_VER")" "$(json_str "$ZIZMOR_VER")"
  printf '      "gitleaks": %s, "trivy": %s, "syft": %s, "osv-scanner": %s}}' \
    "$(json_str "$(tool_ref ghcr.io/gitleaks/gitleaks "$GITLEAKS_VER" "$GITLEAKS_DIGEST")")" \
    "$(json_str "$(tool_ref aquasec/trivy "$TRIVY_VER" "$TRIVY_DIGEST")")" \
    "$(json_str "$(tool_ref anchore/syft "$SYFT_VER" "$SYFT_DIGEST")")" \
    "$(json_str "$(tool_ref ghcr.io/google/osv-scanner "$OSV_VER" "$OSV_DIGEST")")"
}
PROVENANCE="$(provenance_json)"
GIT_FRESH="$(git_freshness)"

# This run's SARIF, by name and digest — what evidence.py may treat as this run's findings.
artifacts_json(){
  local f first=1
  printf '['
  if [ "$SARIF" = "1" ]; then
    for f in "$SARIF_DIR"/*.sarif; do
      [ -f "$f" ] || continue
      [ "$first" = 1 ] || printf ', '; first=0
      printf '{"path": "sarif/%s", "sha256": %s}' "${f##*/}" "$(json_str "$(sha256_of "$f" 2>/dev/null)")"
    done
  fi
  printf ']'
}

mkdir -p "$RUN_DIR"
[ "$SARIF" = "1" ] && mkdir -p "$SARIF_DIR"

printf '\n===== %s  scan.sh %s  run %s =====\n' "$(date +%FT%T)" "$CMD" "$RUN_ID" >> "$LOG"

RUN_T0="$(now_ms)"
run_scans "$CMD" 2>&1 | tee -a "$LOG"
rc=${PIPESTATUS[0]}
RUN_SECONDS="$(awk -v ms="$(( $(now_ms) - RUN_T0 ))" 'BEGIN{printf "%.1f", ms/1000}')"

# Machine-readable summary (consumed by /sec-triage; safe to parse). Schema 2 (F02): each dimension
# says what happened (status + reason) and, separately, what it did to the gate. Contract in
# docs/schema/summary.md.
blocked="$(awk -F'\t' '$4=="block"{printf "%s%s", (n++?",":""), "\""$1"\""}' "$RESULTS_FILE")"
# The trivy DB this run used (F30): its identity is part of WHAT was scanned with (provenance, and so
# evidence.json); its age is run metadata, summary.json only.
TRIVY_DB_JSON="null"
if [ -s "$RUN_DIR/trivy-db" ]; then
  IFS="$(printf '\t')" read -r tdb_u tdb_d tdb_a < "$RUN_DIR/trivy-db"
  PROVENANCE="${PROVENANCE%\}}, \"trivy_db\": {\"updated_at\": $(json_str "$tdb_u")}}"
  TRIVY_DB_JSON="{\"updated_at\": $(json_str "$tdb_u"), \"downloaded_at\": $(json_str "$tdb_d"), \"age_hours\": ${tdb_a:-null}, \"cache\": $(json_str "$TRIVY_CACHE")}"
fi
{
  printf '{\n'
  printf '  "schema_version": 2,\n'
  printf '  "timestamp": "%s",\n' "$(date +%FT%T)"
  printf '  "run_id": "%s",\n' "$RUN_ID"
  printf '  "command": "%s",\n' "$CMD"
  printf '  "exit_code": %s,\n' "$rc"
  printf '  "seconds": %s,\n' "$RUN_SECONDS"
  printf '  "raw_log": "%s",\n' "${LOG#"$ROOT"/}"
  printf '  "sarif": %s,\n' "$([ "$SARIF" = "1" ] && echo true || echo false)"
  printf '  "gate": {"exit_code": %s, "blocked_by": [%s]},\n' "$rc" "$blocked"
  printf '  "provenance": %s,\n' "$PROVENANCE"
  printf '  "trivy_db": %s,\n' "$TRIVY_DB_JSON"
  if [ -n "$GIT_FRESH" ]; then
    IFS="$(printf '\t')" read -r gf_br gf_up gf_ahead gf_behind gf_fh <<<"$GIT_FRESH"
    printf '  "git": {"branch": %s, "upstream": %s, "ahead": %s, "behind": %s, "last_fetch_hours": %s},\n' \
      "$(json_str "$gf_br")" "$(json_str "$gf_up")" "${gf_ahead:-0}" "${gf_behind:-0}" "${gf_fh:-null}"
  else
    printf '  "git": null,\n'
  fi
  if [ -f "$CONF" ]; then
    printf '  "config": {"path": %s, "warnings": [' "$(json_str "${CONF#"$ROOT"/}")"
    cfirst=1
    while IFS= read -r cw; do
      [ -n "$cw" ] || continue
      [ "$cfirst" = 1 ] || printf ', '; cfirst=0
      printf '%s' "$(json_str "$cw")"
    done <<<"$CONFIG_WARNINGS"
    printf ']},\n'
  else
    printf '  "config": null,\n'
  fi
  printf '  "artifacts": %s,\n' "$(artifacts_json)"
  printf '  "dimensions": [\n'
  first=1
  while IFS="$(printf '\t')" read -r dim code st gate ms why; do
    [ -z "$dim" ] && continue
    [ "$first" = 1 ] || printf ',\n'
    first=0
    printf '    {"name": "%s", "exit_code": %s, "status": "%s", "gate": "%s", "seconds": %s, "reason": %s}' \
      "$dim" "$code" "$st" "$gate" "$(awk -v ms="$ms" 'BEGIN{printf "%.1f", ms/1000}')" "$(json_str "$why")"
  done < "$RESULTS_FILE"
  printf '\n  ]\n}\n'
} > "$SUMMARY.$$.tmp" && mv -f "$SUMMARY.$$.tmp" "$SUMMARY"

# Publish this run into the shared record — the holder only. Everything slow (the evidence builder,
# the report) happens before, in this run's staging dir; what remains is a handful of renames, with
# INT/TERM held off so a Ctrl-C lands before the first or after the last, never between. summary.json
# goes last: it is the file a reader checks first, so it never names a run whose SARIF is not there.
# sarif/ is replaced, not merged (F03): it holds this run's SARIF only, the files summary.json's
# `artifacts` lists. A SARIF=0 run leaves sarif/ and evidence.json alone; their provenance says
# which commit they describe.
scan_publish(){
  local stage="$RUN_DIR/publish" f
  if [ "$SARIF" = "1" ]; then
    mkdir -p "$stage/sarif"
    for f in "$SARIF_DIR"/*; do
      [ -f "$f" ] && cp -p "$f" "$stage/sarif/"
    done
    SARIF_DIR="$stage/sarif"; EVIDENCE="$stage/evidence.json"; REPORT_HTML="$stage/report-$TODAY.html"
    scan_evidence || note evidence "post-scan evidence/report NOT complete (see above) — the gate result is unchanged"
  fi
  trap '' INT TERM
  if [ "$SARIF" = "1" ]; then
    mkdir -p "$PUB_SARIF"
    # The shared sarif/ is this run's output only: an earlier run's file left beside it would be
    # read (by an upload, by a person) as a current result for a dimension this run never ran.
    for f in "$PUB_SARIF"/*; do
      [ -f "$f" ] && [ ! -f "$stage/sarif/${f##*/}" ] && rm -f "$f"
    done
    for f in "$stage/sarif"/*; do
      [ -f "$f" ] && mv -f "$f" "$PUB_SARIF/"
    done
  fi
  [ -f "$EVIDENCE" ] && mv -f "$EVIDENCE" "$PUB_EVIDENCE"
  [ -f "$REPORT_HTML" ] && mv -f "$REPORT_HTML" "$PUB_REPORT"
  mv -f "$SUMMARY" "$PUB_SUMMARY"
  trap 'scan_abort 130' INT
  trap 'scan_abort 143' TERM
  SUMMARY="$PUB_SUMMARY"; SARIF_DIR="$PUB_SARIF"; EVIDENCE="$PUB_EVIDENCE"; REPORT_HTML="$PUB_REPORT"
  # Lock-less runs' own records, once old enough that nobody is still reading them.
  find "$RUNS_DIR" -mindepth 1 -maxdepth 1 -type d -mtime "+$SCAN_RUNS_KEEP_DAYS" -exec rm -rf {} + 2>/dev/null
  return 0
}

# Still ours? Another run may have judged this one stale while it ran (a laptop asleep past
# SCAN_LOCK_STALE_MIN on a lock it could not pid-check). Then the record is theirs: keep ours aside.
if [ "$LOCK_HELD" = "1" ] && ! scan_lock_owned; then
  note lock "the lock is no longer ours (taken over while this run scanned) -> NOT publishing"
  scan_lock_stop_heartbeat
  LOCK_HELD=0
fi
if [ "$LOCK_HELD" = "1" ]; then
  scan_publish
else
  if [ "$SARIF" = "1" ]; then
    scan_evidence || note evidence "post-scan evidence/report NOT complete (see above) — the gate result is unchanged"
  fi
  note lock "this run's record: ${RUN_DIR#"$ROOT"/}/ — the shared summary.json is still the other run's"
fi

# ---- closing summary (F14a): one screen — every dimension with its status, time and why; what
# this command does not cover; what was not inspected and how to fix it; what blocked; what next.
printf '\n\033[36m── run: %s · scan %s · %ss\033[0m\n' "$RUN_ID" "$CMD" "$RUN_SECONDS"
awk -F'\t' '{ why=$6; if (length(why) > 72) why=substr(why,1,69) "..."
  printf "   %-10s %-14s %5.1fs  %s\n", $1, $3, $5/1000, why }' "$RESULTS_FILE"
not_covered="$(scan_command_field "$CMD" 3 2>/dev/null)"
[ -n "$not_covered" ] && printf "\033[36m── not in '%s': %s — run scan.sh <name> for those\033[0m\n" "$CMD" "$not_covered"
GF_WARN="$(git_freshness_line "$GIT_FRESH")"
[ -n "$GF_WARN" ] && printf '\033[33m── %s\033[0m\n' "$GF_WARN"
HP_WARN="$(hookspath_check)"
[ -n "$HP_WARN" ] && printf '\033[33m── %s\033[0m\n' "$HP_WARN"
if [ -n "$CONFIG_WARNINGS" ]; then
  printf '\033[33m── config: %s warning(s) in %s (it is bash, run on every scan) — scan.sh doctor lists them\033[0m\n' \
    "$(printf '%s\n' "$CONFIG_WARNINGS" | wc -l | tr -d ' ')" "${CONF#"$ROOT"/}"
fi
# The usual reason for a hole in coverage is the toolchain, not the repo: name the cause once.
no_docker="$(awk -F'\t' '$3=="skipped" && $6 ~ /no docker/{printf " %s",$1}' "$RESULTS_FILE")"
[ -n "$no_docker" ] && printf '\033[33m── Docker is not running:%s NOT inspected — start Docker and re-run "scan.sh %s"\033[0m\n' "$no_docker" "$CMD"
no_uvx="$(awk -F'\t' '$3=="skipped" && $6 ~ /no uvx\/pipx/{printf " %s",$1}' "$RESULTS_FILE")"
[ -n "$no_uvx" ] && printf '\033[33m── uvx/pipx not found:%s NOT inspected — install uv (https://docs.astral.sh/uv/) and re-run "scan.sh %s"\033[0m\n' "$no_uvx" "$CMD"
printf '\033[36m── raw log: %s   summary: %s\033[0m\n' "${LOG#"$ROOT"/}" "${SUMMARY#"$ROOT"/}"
[ "$SARIF" = "1" ] && printf '\033[36m── SARIF: %s/\033[0m\n' "${SARIF_DIR#"$ROOT"/}"
# Only a SARIF=1 run (re)builds evidence.json; after a SARIF=0 run the file on disk is an older run's.
[ "$SARIF" = "1" ] && [ -f "$EVIDENCE" ] && printf '\033[36m── evidence: %s (normalized findings; schema: docs/schema/evidence.md)\033[0m\n' "${EVIDENCE#"$ROOT"/}"
indet="$(awk -F'\t' -v k="$RC_INDETERMINATE" '$2==k{printf " %s",$1}' "$RESULTS_FILE")"
[ -n "$indet" ] && printf '\033[33m── INDETERMINATE:%s — the dimension had nothing to inspect. NOT a pass; do not read the green as coverage.\033[0m\n' "$indet"
uninspected="$(awk -F'\t' '$3=="skipped"||$3=="error"{printf " %s (%s)",$1,$3}' "$RESULTS_FILE")"
[ -n "$uninspected" ] && printf '\033[33m── NOT inspected:%s — see "reason" in summary.json. Not a pass.\033[0m\n' "$uninspected"
# Name what blocked, and as what: a crashed tool is not a finding to allowlist.
blockers="$(awk -F'\t' '$4=="block"{printf " %s (%s)",$1,$3}' "$RESULTS_FILE")"
[ "$rc" -ne 0 ] && printf '\033[31m── BLOCKED (rc=%s):%s — commit/push is blocked.\033[0m\n' "$rc" "$blockers"
crashed="$(awk -F'\t' '$4=="block" && $3=="error"{printf " %s",$1}' "$RESULTS_FILE")"
found="$(awk -F'\t' '$4=="block" && $3!="error"{printf " %s",$1}' "$RESULTS_FILE")"
[ -n "$crashed" ] && printf '\033[31m── scanner FAILED:%s — this is not a finding; do not allowlist it. Fix the scan (see the raw log) and re-run.\033[0m\n' "$crashed"
[ -n "$found" ] && printf '\033[31m── to unblock%s: fix it · allowlist with an expiry if it is a false positive (nosemgrep / .gitleaks.toml / .pip-audit-ignore) · triage: /sec-triage in Claude Code · emergency: git commit/push --no-verify\033[0m\n' "$found"
printf '\033[36m── NEXT STEP — for triage + findings-%s.md, in Claude Code:  /sec-triage\033[0m\n' "$TODAY"
exit "$rc"
