#!/usr/bin/env bash
# tests/trust-gate.sh — "trust the gate" (1.22): a branch must not be able to run code through the kit
# or switch it off. One case per finding of the 2026-11-20 review (N1, A, C), each a reproduction
# that failed before the fix. Offline: needs git, bash, a sha256 tool; no docker, no uvx.
# Usage: bash tests/trust-gate.sh   (exit 0 = all passed)
set -uo pipefail
unset VIRTUAL_ENV SKIP_SECURITY
KIT_SRC="$(cd "$(dirname "$0")/.." && pwd)"
PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
no(){ FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; }
G=(-c user.email=t@t -c user.name=t -c init.defaultBranch=main)
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
M="$W/markers"; mkdir -p "$M"

# A consumer repo with the kit vendored the way bootstrap does (tracked files only) and installed.
vendor(){   # <repo>
  mkdir -p "$1/tools/security-audit-kit"
  ( cd "$KIT_SRC" && git -c core.quotepath=off ls-files -co --exclude-standard -z \
      | while IFS= read -r -d '' f; do [ -e "$f" ] || [ -L "$f" ] && printf '%s\0' "$f"; done | xargs -0 tar cf - ) \
    | ( cd "$1/tools/security-audit-kit" && tar xf - )
}
newrepo(){  # <dir> -> initialised, kit vendored + committed + installed
  mkdir -p "$1"; git -C "$1" "${G[@]}" init -q; vendor "$1"
  ( cd "$1" && git add -A && bash tools/security-audit-kit/scan.sh checksums >/dev/null 2>&1 || true )
  ( cd "$1" && git "${G[@]}" add -A && SKIP_SECURITY=1 git "${G[@]}" commit -qm kit \
      && bash tools/security-audit-kit/install.sh --no-skills >"$W/install.log" 2>&1 \
      && rm -f .security-exclusions.md .security-audit.conf )
}
K=tools/security-audit-kit
# The working tree's CHECKSUMS may lag the tree while developing: regenerate it inside the copy so
# each case starts from a kit that matches its manifest (what a release ships).
R="$W/r"; newrepo "$R"
( cd "$R" && bash $K/scan.sh verify >/dev/null 2>&1 ) && ok "baseline: a freshly vendored kit verifies" \
  || no "baseline: fresh kit fails verify: $(cd "$R" && bash $K/scan.sh verify 2>&1 | tail -5)"

echo "-- N1: hooks run from the git dir, never from the checked-out tree --"
hp="$(git -C "$R" config core.hooksPath)"
case "$hp" in */security-audit-hooks) ok "N1: core.hooksPath points into the git dir ($hp)" ;; *) no "N1: core.hooksPath is '$hp'" ;; esac
grep -q '^kit_anchor=[0-9a-f]\{64\}$' "$R/.git/security-audit-install.state" && ok "N1: the install recorded a kit anchor in .git" \
  || no "N1: no kit_anchor in the install record"
# A branch adds a post-checkout hook inside the vendored kit: a plain checkout must not run it.
( cd "$R" && git "${G[@]}" checkout -q -b evil \
  && printf '#!/bin/sh\ntouch "%s/n1-post-checkout"\n' "$M" > $K/hooks/post-checkout && chmod +x $K/hooks/post-checkout \
  && git "${G[@]}" add -A && SKIP_SECURITY=1 git "${G[@]}" commit -qm evil -n \
  && git "${G[@]}" checkout -q main && git "${G[@]}" checkout -q evil ) >/dev/null 2>&1
[ ! -e "$M/n1-post-checkout" ] && ok "N1: a hook file a branch adds to the kit's hooks/ does NOT run on checkout" \
  || no "N1: post-checkout from the branch RAN on checkout"
# ...and the commit hook refuses that tree (EXTRA) instead of running the kit from it.
out="$(cd "$R" && echo x > f1 && git add f1 && git "${G[@]}" commit -qm f1 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && grep -q 'EXTRA .*hooks/post-checkout' <<<"$out" && ok "N1: the commit is blocked and names the extra hook file" \
  || no "N1: commit on a tree with an extra kit hook (rc=$rc): $out"
( cd "$R" && git reset -q && rm -f f1 && git "${G[@]}" checkout -q main ) >/dev/null 2>&1

# A branch edits the kit's own pre-commit: the wrapper must not run the edited copy.
( cd "$R" && git "${G[@]}" checkout -q -b evil2 \
  && printf '#!/bin/sh\ntouch "%s/n1-edited-hook"\nexit 0\n' "$M" > $K/hooks/pre-commit \
  && git "${G[@]}" add -A && SKIP_SECURITY=1 git "${G[@]}" commit -qm evil2 -n ) >/dev/null 2>&1
out="$(cd "$R" && echo y > f2 && git add f2 && git "${G[@]}" commit -qm f2 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && [ ! -e "$M/n1-edited-hook" ] && grep -q 'MODIFIED .*hooks/pre-commit' <<<"$out" \
  && ok "N1: an edited kit hook is NOT run; the commit is blocked (MODIFIED)" || no "N1: edited kit hook (rc=$rc, ran=$([ -e "$M/n1-edited-hook" ] && echo yes || echo no)): $out"
( cd "$R" && git reset -q && rm -f f2 && git "${G[@]}" checkout -q -f main ) >/dev/null 2>&1

# The same edit WITH a regenerated CHECKSUMS (self-consistent tree): the anchor in .git catches it.
( cd "$R" && git "${G[@]}" checkout -q -b evil3 \
  && printf '#!/bin/sh\ntouch "%s/n1-regen"\nexit 0\n' "$M" > $K/hooks/pre-commit \
  && bash $K/scan.sh checksums >/dev/null 2>&1 \
  && git "${G[@]}" add -A && SKIP_SECURITY=1 git "${G[@]}" commit -qm evil3 -n ) >/dev/null 2>&1
( cd "$R" && bash $K/scan.sh verify >/dev/null 2>&1 ) && ok "C: (setup) the regenerated tree is self-consistent, so scan.sh verify alone passes it" \
  || no "C: (setup) regenerated tree did not self-verify"
out="$(cd "$R" && echo z > f3 && git add f3 && git "${G[@]}" commit -qm f3 2>&1)"; rc=$?
[ "$rc" -ne 0 ] && [ ! -e "$M/n1-regen" ] && grep -q 'ANCHOR' <<<"$out" \
  && ok "N1/C: edit + regenerated CHECKSUMS is NOT run; blocked by the anchor recorded at install" || no "N1/C: regenerated manifest (rc=$rc): $out"
# Accepting a reviewed kit change = re-running install: the anchor moves, the commit goes through.
( cd "$R" && bash $K/install.sh --no-skills >/dev/null 2>&1 )
out="$(cd "$R" && git "${G[@]}" commit -qm f3 2>&1)"; rc=$?
[ "$rc" -eq 0 ] && ok "N1: re-running install.sh accepts the reviewed kit (new anchor), commits work again" \
  || no "N1: after re-install the commit failed (rc=$rc): $out"
( cd "$R" && git "${G[@]}" checkout -q -f main && bash $K/install.sh --no-skills >/dev/null 2>&1 ) ; rm -f "$M"/*
# Emergency bypass still works and runs no kit code.
( cd "$R" && echo b > fb && git add fb && SKIP_SECURITY=1 git "${G[@]}" commit -qm fb ) >/dev/null 2>&1 \
  && ok "N1: SKIP_SECURITY=1 still bypasses the hooks" || no "N1: SKIP_SECURITY bypass broken"

echo "-- A: .security-audit.conf is data, never code --"
C="$R/.security-audit.conf"
scan(){ (cd "$R" && env "$@" bash $K/scan.sh "${CMD:-doctor}" 2>&1); }
# SKIP_SECURITY from a committed file must not switch the checks off.
printf 'SKIP_SECURITY=1\n' > "$C"
out="$(CMD=deps scan)"
! grep -q 'all scans skipped' <<<"$out" && ok "A: SKIP_SECURITY=1 in the config does NOT skip the scans" || no "A: config SKIP_SECURITY skipped the scans"
grep -q 'SKIP_SECURITY is never read from the config' <<<"$(CMD=doctor scan)" && ok "A: doctor names the ignored SKIP_SECURITY line" \
  || no "A: doctor silent on SKIP_SECURITY in the config"
grep -q 'all scans skipped' <<<"$(CMD=deps scan SKIP_SECURITY=1)" && ok "A: SKIP_SECURITY=1 from the environment still skips" \
  || no "A: env SKIP_SECURITY no longer skips"
# `exit 0` in the config must not defeat verify on a tampered kit.
printf 'exit 0\n' > "$C"; printf '\n# tampered\n' >> "$R/$K/scan.sh"
out="$(CMD=verify scan)"; rc=$?
[ "$rc" -ne 0 ] && grep -q 'MODIFIED .*scan.sh' <<<"$out" && ok "A: 'exit 0' in the config does not defeat verify (tamper still found)" \
  || no "A: verify with 'exit 0' config (rc=$rc): $out"
( cd "$R" && git checkout -q -- $K/scan.sh )
# Lines that would RUN something: none runs, each is named with its line.
# shellcheck disable=SC2016  # literal config lines
printf '%s\n' "touch $M/a1" "SARIF=0 touch $M/a2" "BASE_REF=main && touch $M/a3" "REPORT= eval 'touch $M/a4'" \
  "TF_DIR=\$(touch $M/a5)" "SAST_PATHS=\`touch $M/a6\`" ': "${JS_DIRS:=$(touch '"$M"'/a7)}"' "PATH=/tmp/evil" > "$C"
out="$(CMD=doctor scan)"
n="$(ls "$M" | wc -l | tr -d ' ')"
[ "$n" = 0 ] && ok "A: no command in the config ran (8 attempts: plain, behind an assignment, &&, eval, \$(), backquote, :=\$(), PATH)" \
  || no "A: $n config command(s) ran: $(ls "$M" | tr '\n' ' ')"
miss=""; for i in 1 2 3 4 5 6 7 8; do grep -q "line $i[: ].*not applied" <<<"$out" || miss="$miss $i"; done
[ -z "$miss" ] && ok "A: doctor names every rejected line, with its number" || no "A: lines not reported:$miss — $out"
grep -q 'settings only, all known' <<<"$out" && no "A: doctor still says 'settings only, all known'" || ok "A: no false all-clear"
# Plain settings still apply, and env still wins.
# shellcheck disable=SC2016
printf '%s\n' '# comment' ': "${SAST_PATHS:=src lib}"' "TF_DIR='infra/main'" 'export JS_DIRS="web"  # trailing comment' 'SCAN_OFFLINE=1' > "$C"
probe='printf "%s|%s|%s|%s\n" "$SAST_PATHS" "$TF_DIR" "$JS_DIRS" "$SCAN_OFFLINE"'
got="$(cd "$R" && sed -n '/^conf_load(){/,/^conf_load$/p;/^CONF=/p;/^CONFIG_ENV_/p;/^CONF_LOAD_WARNINGS=/p;/^conf_warn/,/^}/p' $K/scan.sh > "$W/cl.sh" \
  && ROOT="$R" KIT_DIR="$R/$K" bash -c '. "$1"; '"$probe" _ "$W/cl.sh")"
[ "$got" = "src lib|infra/main|web|1" ] && ok "A: plain settings in every accepted form are applied" || no "A: applied values: '$got'"
got="$(cd "$R" && SAST_PATHS=env ROOT="$R" KIT_DIR="$R/$K" bash -c '. "$1"; printf %s "$SAST_PATHS"' _ "$W/cl.sh")"
[ "$got" = env ] && ok "A: env > conf (the environment value wins)" || no "A: env did not win: '$got'"
# The shipped example raises nothing.
cp "$R/$K/security-audit.conf.example" "$C"
grep -q 'settings only, all known' <<<"$(CMD=doctor scan)" && ok "A: the shipped example config is clean" || no "A: example config warns: $(CMD=doctor scan | grep -A9 config)"
rm -f "$C"

echo "-- C: verify sees an extra file in ANY directory of the kit --"
for f in lib/json.py hooks/post-merge extra-at-root.sh scan.s skills/sec-triage/extra.md; do
  mkdir -p "$(dirname "$R/$K/$f")"; echo 'print(1)' > "$R/$K/$f"
  out="$(CMD=verify scan)"; rc=$?
  [ "$rc" -ne 0 ] && grep -qx "EXTRA     $f" <<<"$out" && ok "C: EXTRA $f" || no "C: $f not reported (rc=$rc)"
  rm -f "$R/$K/$f"
done
ln -s ../scan.sh "$R/$K/skills/link"; out="$(CMD=verify scan)"
grep -qx 'EXTRA     skills/link' <<<"$out" && ok "C: EXTRA for a symlink" || no "C: symlink not reported"; rm -f "$R/$K/skills/link"
mkdir -p "$R/$K/lib/__pycache__" && echo x > "$R/$K/lib/__pycache__/evidence.cpython-312.pyc"
( cd "$R" && bash $K/scan.sh verify >/dev/null 2>&1 ) && ok "C: python's own bytecode cache is not an extra" || no "C: __pycache__ flagged"
( cd "$R" && bash $K/scan.sh verify >/dev/null 2>&1 ) && ok "C: clean kit verifies again" || no "C: clean kit fails verify"

echo
printf 'trust-gate: %d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
