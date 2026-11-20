#!/usr/bin/env bash
# security-audit-kit / lib/integrity.sh — is this kit directory exactly the files its manifest lists?
#
# Usage: integrity.sh <kit_dir> [<anchor>]
#   <anchor>  sha256 of the CHECKSUMS file as it was when the kit was installed (recorded in the git
#             dir by install.sh). Given, a manifest regenerated after an edit no longer passes.
# Prints one line per problem and exits 1:
#   MISSING   <path>   listed in CHECKSUMS, not on disk
#   MODIFIED  <path>   on disk, content differs from CHECKSUMS
#   EXTRA     <path>   on disk (file or link, ANY directory), not in CHECKSUMS
#   ANCHOR    ...      CHECKSUMS itself is not the manifest recorded at install
# Exit 0 = clean (silent). Exit 2 = cannot check (no directory, no manifest, no sha256 tool).
#
# Self-contained on purpose (no scan.sh, no python, no file of the checked tree): install.sh copies it
# into the git dir and the hook wrappers run THAT copy, so a branch that edits the vendored kit cannot
# also edit the check that guards it (N1/C). bash 3.2 compatible.
set -u
kd="${1:-}"; anchor="${2:-}"
[ -n "$kd" ] && [ -d "$kd" ] || { echo "integrity: no kit directory: ${kd:-<none>}" >&2; exit 2; }
cd "$kd" || exit 2
[ -f CHECKSUMS ] || { echo "integrity: no CHECKSUMS manifest in $kd" >&2; exit 2; }
if command -v sha256sum >/dev/null 2>&1; then MODE=gnu
elif command -v shasum >/dev/null 2>&1; then MODE=bsd
elif command -v openssl >/dev/null 2>&1; then MODE=openssl
else echo "integrity: no sha256 tool (sha256sum, shasum or openssl)" >&2; exit 2; fi
hash1(){
  case "$MODE" in
    gnu) sha256sum "$1" | awk '{print $1}' ;;
    bsd) shasum -a 256 "$1" | awk '{print $1}' ;;
    *)   openssl dgst -sha256 "$1" | awk '{print $NF}' ;;
  esac
}
tmp="$(mktemp -d)" || exit 2
trap 'rm -rf "$tmp"' EXIT
export LC_ALL=C
out="$tmp/out"; : > "$out"

# The manifest: "<64 hex>  <path>" per line. A line of any other shape is itself a problem.
grep -vE '^[0-9a-f]{64}  .+$' CHECKSUMS | grep -v '^$' | sed 's/^/MODIFIED  CHECKSUMS (malformed line): /' >> "$out"
grep -E '^[0-9a-f]{64}  .+$' CHECKSUMS | sort -u > "$tmp/want"
sed 's/^[0-9a-f]\{64\}  //' "$tmp/want" | sort -u > "$tmp/listed"

# MISSING / MODIFIED: one hashing call for every present file, not one process per file.
: > "$tmp/present"
while IFS= read -r p; do
  if [ -f "$p" ]; then printf '%s\n' "$p" >> "$tmp/present"; else printf 'MISSING   %s\n' "$p" >> "$out"; fi
done < "$tmp/listed"
if [ -s "$tmp/present" ]; then
  case "$MODE" in
    gnu) tr '\n' '\0' < "$tmp/present" | xargs -0 sha256sum ;;
    bsd) tr '\n' '\0' < "$tmp/present" | xargs -0 shasum -a 256 ;;
    *)   while IFS= read -r p; do printf '%s  %s\n' "$(hash1 "$p")" "$p"; done < "$tmp/present" ;;
  esac | sort -u > "$tmp/got"
  # A computed line that is not in the manifest = that path's content changed.
  comm -13 "$tmp/want" "$tmp/got" | sed 's/^[0-9a-f]\{64\}  //' | sed 's/^/MODIFIED  /' >> "$out"
fi

# EXTRA: everything under the kit dir, in every directory, files AND links. Exact path match (the old
# check was a substring test on skills/ only: an extra hooks/post-checkout or lib/json.py passed).
# Not counted: the manifest, the pin file, python's own bytecode caches (a .pyc without its source is
# never imported). In the kit's own git repo (maintainer), ignored files are build/run noise.
top="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [ -n "$top" ] && [ "$(cd "$top" && pwd -P)" = "$(pwd -P)" ]; then
  git -c core.quotepath=off ls-files -co --exclude-standard
else
  find . \( -type f -o -type l \) -print | sed 's|^\./||'
fi | grep -vE '^(CHECKSUMS|\.kit-version)$|(^|/)__pycache__/' | sort -u > "$tmp/found"
comm -23 "$tmp/found" "$tmp/listed" | sed 's/^/EXTRA     /' >> "$out"

# ANCHOR: the manifest itself must be the one recorded at install (else edit + regenerate passes).
if [ -n "$anchor" ]; then
  got="$(hash1 CHECKSUMS)"
  [ "$got" = "$anchor" ] || printf 'ANCHOR    CHECKSUMS is not the manifest recorded at install (now %s, recorded %s)\n' \
    "$(printf '%s' "$got" | cut -c1-12)" "$(printf '%s' "$anchor" | cut -c1-12)" >> "$out"
fi

[ -s "$out" ] || exit 0
cat "$out"; exit 1
