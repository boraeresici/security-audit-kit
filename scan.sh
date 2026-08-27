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

# trivy: skip build-output dirs (noise + memory + speed). Comma-separated glob patterns.
TRIVY_SKIP_DIRS="${TRIVY_SKIP_DIRS:-**/.next,**/dist,**/build,**/.nuxt,**/.svelte-kit,**/.turbo}"

# js-deps: which directories hold a JS project. JS_DIRS (space separated) overrides the search
# outright; otherwise every tracked package.json is considered except the paths JS_SKIP_RE drops —
# vendored front-end assets checked into a backend repo are third-party files nobody here maintains.
JS_DIRS="${JS_DIRS:-}"
JS_SKIP_RE="${JS_SKIP_RE:-(^|/)(node_modules|bower_components|vendor|third[_-]party|static|assets|public|dist|build|coverage|\.venv|site-packages)/}"

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

# ---- python deps (pip-audit) ----
scan_py_deps(){
  has_tracked '(^|/)(pyproject\.toml|requirements[^/]*\.txt|uv\.lock|Pipfile)$' \
    || { warn deps "no Python project"; return 0; }
  local flags=""
  [ -f .pip-audit-ignore ] && flags="$(awk '/^[^#]/{printf " --ignore-vuln %s",$1}' .pip-audit-ignore)"
  # Audit THIS repo's environment — not uvx's ephemeral one, and not whatever venv the caller
  # happens to have active. pip-audit defaults to the running interpreter (empty under uvx), so we
  # point it somewhere explicitly, and the repo's own .venv WINS: preferring $VIRTUAL_ENV means a
  # scan started from another project's shell audits THAT project and reports a green (or red)
  # py-deps saying nothing about this repo — a silently wrong answer, the worst kind for a gate.
  local venv=""
  [ -x "$ROOT/.venv/bin/python" ] && venv="$ROOT/.venv"
  if [ -z "$venv" ] && [ -n "${VIRTUAL_ENV:-}" ] && [ -x "$VIRTUAL_ENV/bin/python" ]; then
    venv="$VIRTUAL_ENV"   # no repo venv -> an active one still beats uvx's interpreter
  elif [ -n "$venv" ] && [ -n "${VIRTUAL_ENV:-}" ] && [ "$VIRTUAL_ENV" != "$venv" ]; then
    warn deps "active VIRTUAL_ENV ($VIRTUAL_ENV) is not this repo's venv -> auditing ${venv#"$ROOT"/}"
  fi
  if [ -n "$venv" ] && [ -x "$venv/bin/python" ]; then
    export PIPAPI_PYTHON_LOCATION="$venv/bin/python"
    say deps "pip-audit --strict (==$PIP_AUDIT_VER, env ${venv#"$ROOT"/})"
  else
    say deps "pip-audit --strict (==$PIP_AUDIT_VER) — no project venv found; for lockfile-accurate deps run 'scan.sh osv'"
  fi
  # shellcheck disable=SC2086
  pyrun pip-audit "$PIP_AUDIT_VER" pip-audit --strict $flags || { [ $? -eq 127 ] && { warn deps "no uvx/pipx -> pip-audit skipped"; return 0; }; return 1; }
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
      warn deps "package.json found but none is auditable (vendor path, or no lockfile) -> set JS_DIRS to point at the real JS project"
    else
      warn deps "no JS project"
    fi
    return 0
  fi
  local rc=0 dir
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    ( cd "$ROOT/$dir" || exit 1
      # Audit ALL deps (incl. dev/build) — vulns in build tooling (vite/undici/…) are real; the
      # triage layer decides reachability. (Previously --prod/--omit=dev hid them.)
      if   [ -f pnpm-lock.yaml ]    && have pnpm; then say deps "pnpm audit ($dir)"; pnpm audit --audit-level high
      elif [ -f yarn.lock ]         && have yarn; then say deps "yarn audit ($dir)"; yarn npm audit --severity high
      elif [ -f package-lock.json ] && have npm;  then say deps "npm audit ($dir)";  npm audit --audit-level=high
      else warn deps "$dir: no lockfile with an installed package manager (pnpm/yarn/npm) -> skipped"; fi ) || rc=1
  done <<<"$dirs"
  return $rc
}

# Extra docker mounts so gitleaks can reach git history in a git WORKTREE — whose .git is a
# FILE pointing to a gitdir OUTSIDE the worktree (else gitleaks silently scans 0 commits and
# reports "no leaks", a false-clean). No-op for a normal repo (.git is a directory).
git_extra_mounts(){
  [ -f "$ROOT/.git" ] || return 0
  local common; common="$(git rev-parse --git-common-dir 2>/dev/null)" || return 0
  case "$common" in /*) ;; *) common="$ROOT/$common" ;; esac
  [ -n "$common" ] && [ -d "$common" ] && printf -- '-v %s:%s' "$common" "$common"
}

# ---- secret, full history (gitleaks detect) ----
scan_secret(){
  docker_ok || { warn secret "no docker -> gitleaks skipped"; return 0; }
  local cfg=""; [ -f .gitleaks.toml ] && cfg="--config /repo/.gitleaks.toml"
  local rep=""; [ "$SARIF" = "1" ] && rep="--report-format sarif --report-path /repo/$(sarif_rel gitleaks.sarif)"
  say secret "gitleaks detect (full history)"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo" $(git_extra_mounts) -w /repo "$(img ghcr.io/gitleaks/gitleaks "$GITLEAKS_VER" "$GITLEAKS_DIGEST")" \
    detect --source /repo $cfg $rep --redact --exit-code 1 --verbose
}

# ---- secret, staged changes only (gitleaks protect --staged) — sub-second ----
scan_secret_staged(){
  docker_ok || { warn secret "no docker -> staged secret scan skipped"; return 0; }
  local cfg=""; [ -f .gitleaks.toml ] && cfg="--config /repo/.gitleaks.toml"
  say secret "gitleaks protect --staged"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo" $(git_extra_mounts) -w /repo "$(img ghcr.io/gitleaks/gitleaks "$GITLEAKS_VER" "$GITLEAKS_DIGEST")" \
    protect --staged --source /repo $cfg --redact --exit-code 1 --verbose
}

# ---- sast (semgrep) ----
scan_sast(){
  # Default: whole repo (semgrep's default .semgrepignore skips node_modules/.git/.venv).
  # Override SAST_PATHS via env to narrow/speed up the scan.
  local paths="${SAST_PATHS:-.}"
  local out=""; [ "$SARIF" = "1" ] && out="--sarif --output $SARIF_DIR/semgrep.sarif"
  say sast "semgrep ($paths, ==$SEMGREP_VER) [$SEMGREP_CONFIGS]"
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
  say sast "semgrep (changed files, ==$SEMGREP_VER) [$SEMGREP_CONFIGS]"
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
  local skip=""; [ -n "$TRIVY_SKIP_DIRS" ] && skip="--skip-dirs $TRIVY_SKIP_DIRS"
  local out="--exit-code 0"; [ "$SARIF" = "1" ] && out="--exit-code 0 --format sarif --output /repo/$(sarif_rel trivy.sarif)"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo" -w /repo "$(img aquasec/trivy "$TRIVY_VER" "$TRIVY_DIGEST")" fs \
    --scanners vuln,secret,misconfig,license --severity CRITICAL,HIGH --ignore-unfixed $out $ign $skip /repo
}

# ---- sbom (syft) ----
scan_sbom(){
  docker_ok || { warn sbom "no docker -> syft skipped"; return 0; }
  say sbom "syft -> sbom.cyclonedx.json + sbom.spdx.json"
  docker run --rm -v "$ROOT:/repo" -w /repo "$(img anchore/syft "$SYFT_VER" "$SYFT_DIGEST")" dir:/repo \
    -o cyclonedx-json=/repo/sbom.cyclonedx.json -o spdx-json=/repo/sbom.spdx.json
}

# ---- osv (OSV-Scanner) — broad multi-ecosystem dep CVE, OPTIONAL (not in 'all') ----
# Complements pip-audit/npm: scans lockfiles across ecosystems (py/js/go/rust/...) against
# OSV.dev. Standalone + opt-in so it doesn't double-gate with the other dep scanners.
scan_osv(){
  docker_ok || { warn osv "no docker -> osv-scanner skipped"; return 0; }

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
          warn osv "call-analysis=rust RUNS dependency build scripts (executing untrusted code to decide reachability) -> refused; set OSV_ALLOW_BUILD_SCRIPTS=1 to accept that"
          return 1
        fi
        warn osv "call-analysis=rust with OSV_ALLOW_BUILD_SCRIPTS=1 — build scripts from the dependency tree WILL execute"
        call="--call-analysis=$OSV_CALL_ANALYSIS --all-vulns" ;;
      *) call="--call-analysis=$OSV_CALL_ANALYSIS --all-vulns" ;;
    esac
  fi
  say osv "osv-scanner scan source (all lockfile ecosystems)${call:+ [reachability: $OSV_CALL_ANALYSIS, gate unchanged]}"
  local out=""; [ "$SARIF" = "1" ] && out="--format sarif --output /repo/$(sarif_rel osv.sarif)"
  # shellcheck disable=SC2086
  docker run --rm -v "$ROOT:/repo" -w /repo "$(img ghcr.io/google/osv-scanner "$OSV_VER" "$OSV_DIGEST")" \
    scan source --recursive $call $out /repo
  local rc=$?
  case "$rc" in
    0) return 0 ;;                                              # scanned, clean
    1) return 1 ;;                                              # vulnerabilities found (HARD)
    128) warn osv "no lockfiles found -> nothing to scan"; return 0 ;;
    *) warn osv "osv-scanner exit $rc (scan error, not a finding)"; return 0 ;;
  esac
}

# ---- guarddog — malicious/typosquat dependency detection, OPTIONAL (not in 'all'; needs network) ----
# Complements osv/pip-audit/npm (which only find KNOWN CVEs) by catching *malicious* packages:
# typosquats, compromised-maintainer metadata, malicious install scripts. `verify` checks each
# declared dependency against the LIVE registry, so this dimension needs network. Standalone + opt-in.
scan_guarddog(){
  { have uvx || have pipx; } || { warn guarddog "no uvx/pipx -> guarddog skipped"; return 0; }
  local pyreqs npmpkgs rc=0 f
  pyreqs="$(git ls-files | grep -E '(^|/)requirements[^/]*\.txt$' | grep -v node_modules || true)"
  npmpkgs="$(git ls-files | grep -E '(^|/)package\.json$' | grep -v node_modules || true)"
  [ -z "$pyreqs" ] && [ -z "$npmpkgs" ] && { warn guarddog "no requirements*.txt or package.json -> nothing to verify"; return 0; }
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

# One target -> a verdict line on stdout ("BLOCK\t<rules>"), exit 1 when it blocks.
pkgcheck_one(){
  local eco="$1" name="$2" ver="$3" out verdict rc dir key f
  # The key carries the pinned tool version: bumping guarddog must not read old verdicts.
  if dir="$(pkgcheck_cache_dir)"; then
    key="$(printf '%s__%s__%s__%s' "$eco" "$name" "${ver:-latest}" "$GUARDDOG_VER" | tr -c 'A-Za-z0-9_.@-' '_')"
    f="$dir/$key"
    # An unversioned request means "whatever the registry serves now", which changes under us —
    # those entries expire; an exact version is immutable on both registries, so it does not.
    if [ -f "$f" ] && { [ -n "$ver" ] || [ -z "$(find "$f" -mmin "+$PKGCHECK_CACHE_TTL_MIN" 2>/dev/null)" ]; }; then
      out="$(cat "$f")"
      printf '%s (cached)\n' "$out"
      case "$out" in BLOCK*) return 1 ;; *) return 0 ;; esac
    fi
  fi
  say pkgcheck "guarddog ==$GUARDDOG_VER scan (needs network)"
  local gargs="scan $name"
  [ -n "$ver" ] && gargs="$gargs -v $ver"
  # shellcheck disable=SC2086
  out="$(pyrun guarddog "$GUARDDOG_VER" guarddog "$eco" $gargs --output-format json 2>/dev/null \
        | python3 "$KIT_DIR/lib/pkgcheck.py" --classify \
            --block-extra "${PKGCHECK_BLOCK_EXTRA:-}" --report-extra "${PKGCHECK_REPORT_EXTRA:-}")"
  rc=$?
  [ -z "$out" ] && { out="INDETERMINATE	guarddog produced no output"; rc=2; }
  verdict="${out%%	*}"
  # Only a real verdict is worth remembering; INDETERMINATE is a failure to look, not an answer.
  if [ -n "${f:-}" ] && [ "$verdict" != "INDETERMINATE" ]; then
    mkdir -p "$dir" 2>/dev/null && printf '%s' "$out" > "$f" 2>/dev/null || true
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
  { have uvx || have pipx; } || { warn zizmor "no uvx/pipx -> zizmor skipped"; return 0; }
  has_tracked '^\.github/workflows/.*\.(yml|yaml)$' \
    || { warn zizmor "no .github/workflows -> nothing to scan"; return 0; }
  say zizmor "zizmor --offline (.github, ==$ZIZMOR_VER)"
  local rc
  if [ "$SARIF" = "1" ]; then
    pyrun zizmor "$ZIZMOR_VER" zizmor --offline --format sarif $ZIZMOR_ARGS .github/ > "$SARIF_DIR/zizmor.sarif"
    rc=$?
  else
    pyrun zizmor "$ZIZMOR_VER" zizmor --offline $ZIZMOR_ARGS .github/
    rc=$?
  fi
  # zizmor exits non-zero when it has findings (it warns, not errors, on workflow syntax by default).
  [ "$rc" -eq 0 ] && return 0 || return 1
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
  printf 'toolchain (a missing one only skips that dimension):\n'
  docker_ok && echo "  ok  docker        (gitleaks/trivy/syft)" || echo "  --  docker        MISSING/not running -> secret/container/sbom skipped"
  { have uvx || have pipx; } && echo "  ok  uvx/pipx      (semgrep/checkov/pip-audit/guarddog/zizmor)" || echo "  --  uvx/pipx      MISSING -> sast/iac/py-deps/guarddog/zizmor skipped"
  { have pnpm || have yarn || have npm; } && echo "  ok  js pkg mgr    (js-deps)" || echo "  --  js pkg mgr    MISSING -> js-deps skipped"
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
    printf '  ok  verdict cache: %s (unversioned entries expire after %s min)\n' \
      "${pcd#"$ROOT"/}" "$PKGCHECK_CACHE_TTL_MIN"
  else
    printf '  --  verdict cache off (PKGCHECK_CACHE=off or not a git repo) — every check re-scans\n'
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
scan_evidence(){
  have python3 || { warn evidence "no python3 -> evidence.json skipped"; return 0; }
  [ -f "$KIT_DIR/lib/evidence.py" ] || { warn evidence "lib/evidence.py missing -> skipped"; return 0; }
  [ -d "$SARIF_DIR" ] || { warn evidence "no SARIF output yet (re-run with SARIF=1) -> evidence.json skipped"; return 0; }
  # The judgment layer's decisions live in the findings file a human reads; fold them in when it
  # exists so evidence.json carries both halves (what the tools found, what we decided).
  local fargs=""
  [ -f "$FINDINGS_MD" ] && fargs="--findings $FINDINGS_MD"
  # shellcheck disable=SC2086
  python3 "$KIT_DIR/lib/evidence.py" --sarif-dir "$SARIF_DIR" --summary "$SUMMARY" --out "$EVIDENCE" $fargs \
    || { warn evidence "builder failed -> evidence.json not updated"; return 0; }
  # The skills' own findings have no other SARIF home -> put them on the same review surface.
  if [ -f "$KIT_DIR/lib/kit_sarif.py" ]; then
    python3 "$KIT_DIR/lib/kit_sarif.py" --evidence "$EVIDENCE" --out "$SARIF_DIR/kit.sarif" \
      || warn evidence "kit.sarif not emitted"
  fi
  [ "$REPORT" = "html" ] && scan_report
  return 0
}

# One self-contained HTML file to attach, mail, or print to PDF — opt-in via REPORT=html, or
# `scan.sh report` to re-render. No server, no JS framework, no external fetch: it must open
# offline in five years. Renders MORE than kit.sarif — including the triage decisions on scanner
# findings, which SARIF leaves to each tool's own run.
scan_report(){
  have python3 || { warn report "no python3 -> HTML report skipped"; return 0; }
  [ -f "$KIT_DIR/lib/report_html.py" ] || { warn report "lib/report_html.py missing -> skipped"; return 0; }
  [ -f "$EVIDENCE" ] || { warn report "no evidence.json yet (re-run with SARIF=1) -> report skipped"; return 0; }
  python3 "$KIT_DIR/lib/report_html.py" --evidence "$EVIDENCE" --out "$REPORT_HTML" \
    --repo "$(basename "$ROOT")" --date "$TODAY" || warn report "report not written"
  return 0
}

SARIF="${SARIF:-0}"
REPORT="${REPORT:-}"

[ "${1:-}" = "doctor" ]    && { scan_doctor; exit 0; }
[ "${1:-}" = "verify" ]    && { scan_verify; exit $?; }
[ "${1:-}" = "checksums" ] && { scan_checksums; exit $?; }
[ "${1:-}" = "rules-test" ] && { scan_rules_test; exit $?; }
[ "${1:-}" = "allowlist" ] && { scan_allowlist; exit $?; }
[ "${SKIP_SECURITY:-0}" = "1" ] && { say skip "SKIP_SECURITY=1 -> all scans skipped"; exit 0; }
[ "${1:-}" = "pkgcheck" ] && { shift; scan_pkgcheck "$@"; exit $?; }

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
    osv)       _dim osv scan_osv || rc=1 ;;
    guarddog)  _dim guarddog scan_guarddog || rc=1 ;;
    zizmor)    _dim zizmor scan_zizmor || rc=1 ;;
    fast)      _dim staged scan_secret_staged || rc=1; _dim py-deps scan_py_deps || rc=1; _dim js-deps scan_js_deps || rc=1 ;;
    all)       _dim secret scan_secret || rc=1; _dim sast scan_sast || rc=1; _dim py-deps scan_py_deps || rc=1; _dim js-deps scan_js_deps || rc=1; _dim container scan_container || rc=1; _dim iac scan_iac || rc=1 ;;
    *) echo "unknown command: $1 (deps|secret|staged|sast|changed|iac|container|sbom|osv|guarddog|zizmor|fast|all|doctor|verify|checksums|rules-test|allowlist|evidence|report)"; return 2 ;;
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
EVIDENCE="$LOG_DIR/evidence.json"
FINDINGS_MD="$LOG_DIR/findings-$TODAY.md"
REPORT_HTML="$LOG_DIR/report-$TODAY.html"
RESULTS_FILE="$(mktemp)"
trap 'rm -f "$RESULTS_FILE"' EXIT
mkdir -p "$LOG_DIR"
[ "$SARIF" = "1" ] && mkdir -p "$SARIF_DIR"
# Rebuild the record / re-render the report from what is already on disk, without re-scanning.
[ "$CMD" = "evidence" ] && { scan_evidence; exit $?; }
[ "$CMD" = "report" ]   && { scan_report; exit $?; }

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

[ "$SARIF" = "1" ] && scan_evidence

printf '\n\033[36m── raw report: %s   summary: %s\033[0m\n' "${LOG#"$ROOT"/}" "${SUMMARY#"$ROOT"/}"
[ "$SARIF" = "1" ] && printf '\033[36m── SARIF: %s/\033[0m\n' "${SARIF_DIR#"$ROOT"/}"
[ -f "$EVIDENCE" ] && printf '\033[36m── evidence: %s (normalized findings; schema: docs/schema/evidence.md)\033[0m\n' "${EVIDENCE#"$ROOT"/}"
printf '\033[36m── NEXT STEP — for triage + findings-%s.md, in Claude Code:  /sec-triage\033[0m\n' "$TODAY"
[ "$rc" -ne 0 ] && printf '\033[31m── HARD finding (rc=%s): commit/push is blocked; allowlist if FP, fix if real.\033[0m\n' "$rc"
exit "$rc"
