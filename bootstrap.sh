#!/usr/bin/env bash
# security-audit-kit / bootstrap.sh — fetches the kit from ITS OWN repo, vendors it
# into the target project (tools/security-audit-kit/), and runs install.sh. One command.
#
# Philosophy (consistent with the kit itself): NO REMOTE PIPE. Download this file
# first, REVIEW it, then run it. The version is PINNED (tag/SHA) — "main" means drift.
#
# Usage (from the target repo root):
#   # 1) Download this file + read it (do not pipe):
#   curl -fsSL https://raw.githubusercontent.com/boraeresici/security-audit-kit/main/bootstrap.sh -o bootstrap.sh && less bootstrap.sh
#   # 2) Run pinned to a tag:
#   bash bootstrap.sh v1.0.0
#   bash bootstrap.sh v1.0.0 --scan          # also run a full scan after install
#   bash bootstrap.sh v1.0.0 --expect=<sha>  # REFUSE unless the ref resolves to <sha> (enforce the pin)
#   bash bootstrap.sh --check                # IS THERE AN UPDATE? (no clone, read-only)
#
# Override (env): KIT_REPO, KIT_REF, DEST_REL, KIT_EXPECT_SHA.
set -euo pipefail

# --- configurable ---
KIT_REPO="${KIT_REPO:-https://github.com/boraeresici/security-audit-kit.git}"
DEST_REL="${DEST_REL:-tools/security-audit-kit}"

# --- arg parse: first positional = ref (tag/SHA); --scan first scan; --check check;
#     --expect=<sha> enforce the pin; --allow-ref-change permit a moved ref ---
RUN_SCAN=0
DO_CHECK=0
ALLOW_REF_CHANGE=0
EXPECT_SHA=""
REF_ARG=""
for a in "$@"; do
  case "$a" in
    --scan) RUN_SCAN=1 ;;
    --check|check) DO_CHECK=1 ;;
    --allow-ref-change) ALLOW_REF_CHANGE=1 ;;
    --expect=*) EXPECT_SHA="${a#--expect=}" ;;
    -*) echo "unknown flag: $a (--scan | --check | --expect=<sha> | --allow-ref-change)"; exit 2 ;;
    *) REF_ARG="$a" ;;
  esac
done
KIT_REF="${KIT_REF:-${REF_ARG:-}}"
EXPECT_SHA="${EXPECT_SHA:-${KIT_EXPECT_SHA:-}}"

ok(){ printf '  \033[32mok\033[0m  %s\n' "$1"; }
warn(){ printf '  \033[33m!!\033[0m  %s\n' "$1"; }
die(){ printf '\033[31mERROR:\033[0m %s\n' "$1"; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

have git || die "git is missing."
have rsync || true   # if rsync is absent we fall back to cp

# Target = the ROOT of the git repo you are inside (the kit is vendored there).
ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || die "not a git repo. Run inside the target project (run 'git init' first)."
cd "$ROOT"

# --- --check: read-only update check (NO CLONE; just git ls-remote) ---
# The vendored copy is a static copy git cannot see; this mode tells you "did an
# update land": compares the local .kit-version against the newest remote semver tag.
if [ "$DO_CHECK" = "1" ]; then
  cur="(no vendor)"; [ -f "$ROOT/$DEST_REL/.kit-version" ] && cur="$(awk '{print $1}' "$ROOT/$DEST_REL/.kit-version")"
  latest="$(git ls-remote --tags --refs "$KIT_REPO" 2>/dev/null | awk -F/ '{print $NF}' | grep -E '^v?[0-9]+' | sort -V | tail -1)"
  [ -z "$latest" ] && die "no remote tag found (repo unreachable or no tags at all)."
  echo "vendored version : $cur"
  echo "latest tag       : $latest"
  if [ "$cur" = "$latest" ]; then ok "up to date."; exit 0; fi
  warn "UPDATE AVAILABLE -> bash $DEST_REL/bootstrap.sh $latest"
  exit 1   # usable in automation: 0=up to date, 1=update available
fi

# Pinning is not mandatory but strongly recommended; warn on a moving ref.
if [ -z "$KIT_REF" ]; then
  KIT_REF="main"
  warn "no ref given -> using 'main'. PINNING RECOMMENDED: bash bootstrap.sh <tag>"
elif printf '%s' "$KIT_REF" | grep -qiE '^(main|master|head)$'; then
  warn "moving ref ('$KIT_REF') -> drift risk. Pin a tag/SHA in production."
fi

echo "== fetching kit: $KIT_REPO @ $KIT_REF =="
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# --branch works for both tag AND branch; for a SHA it falls back to clone then checkout.
if ! git clone --depth 1 --branch "$KIT_REF" "$KIT_REPO" "$TMP" 2>/dev/null; then
  git clone "$KIT_REPO" "$TMP" >/dev/null 2>&1 || die "clone failed: $KIT_REPO"
  git -C "$TMP" checkout --quiet "$KIT_REF" || die "ref not found: $KIT_REF"
fi
SHA="$(git -C "$TMP" rev-parse HEAD)"
ok "fetched @ $KIT_REF ($SHA)"

# --- SHA verification (Layer 0 hardening): ENFORCE the pin, don't just record it. ---
# Runs BEFORE the vendor step (the rsync --delete below would remove the old .kit-version).
# (a) --expect / KIT_EXPECT_SHA: refuse if the resolved SHA isn't the one you reviewed.
if [ -n "$EXPECT_SHA" ]; then
  case "$SHA" in
    "$EXPECT_SHA"*) ok "SHA matches --expect ($EXPECT_SHA)" ;;
    *) die "SHA mismatch: '$KIT_REF' resolved to $SHA but --expect was $EXPECT_SHA. Refusing (possible tag repoint / wrong ref)." ;;
  esac
fi
# (b) Tag-repoint guard: re-vendoring the SAME ref already pinned, but it now resolves to a
#     DIFFERENT commit -> the tag/branch MOVED. Refuse unless explicitly allowed.
if [ -f "$ROOT/$DEST_REL/.kit-version" ]; then
  prev_ref="$(awk '{print $1}' "$ROOT/$DEST_REL/.kit-version")"
  prev_sha="$(awk '{print $2}' "$ROOT/$DEST_REL/.kit-version")"
  if [ "$prev_ref" = "$KIT_REF" ] && [ -n "$prev_sha" ] && [ "$prev_sha" != "$SHA" ]; then
    [ "$ALLOW_REF_CHANGE" = "1" ] \
      && warn "ref '$KIT_REF' moved ${prev_sha:0:12} -> ${SHA:0:12} (allowed via --allow-ref-change)" \
      || die "ref '$KIT_REF' now resolves to ${SHA:0:12} but the pinned .kit-version has ${prev_sha:0:12} — the tag/branch MOVED (possible repoint). Review it, then re-run with --expect=$SHA or --allow-ref-change."
  fi
fi

# Vendor: copy the clone contents into DEST (excluding .git). Idempotent: overwrites.
rm -rf "$TMP/.git"
mkdir -p "$ROOT/$DEST_REL"
if have rsync; then
  rsync -a --delete --exclude '.security-audit.conf' "$TMP"/ "$ROOT/$DEST_REL"/
else
  cp -R "$TMP"/. "$ROOT/$DEST_REL"/
fi
ok "vendored: $DEST_REL/ (pin $KIT_REF @ ${SHA:0:12})"

# Evidence trail: which version was vendored (can be committed).
printf '%s %s\n' "$KIT_REF" "$SHA" > "$ROOT/$DEST_REL/.kit-version"
ok ".kit-version written (commit it -> team-shared pinned version)"

echo "== delegating to install.sh =="
bash "$ROOT/$DEST_REL/install.sh"

if [ "$RUN_SCAN" = "1" ]; then
  echo "== first scan (--scan) =="
  bash "$ROOT/$DEST_REL/scan.sh" all || true   # findings may surface; triage with /sec-triage
fi

cat <<EOF

== bootstrap complete ==
  vendor       : $DEST_REL/  (pin: $KIT_REF @ ${SHA:0:12})
  update?      : bash $DEST_REL/bootstrap.sh --check       (compare against latest remote tag)
  update       : bash $DEST_REL/bootstrap.sh <new-tag>     (idempotent, overwrites)
  ad-hoc scan  : bash $DEST_REL/scan.sh all
  triage       : /sec-triage in Claude
EOF
