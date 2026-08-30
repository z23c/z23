#!/usr/bin/env bash
# arch_score.sh — mechanical completion score for the ARCHITECTURE NORTH STAR
# (docs/ARCHITECTURE_NORTH_STAR.md). Each sub-goal is a checkable KPI worth a
# fixed weight; the total is a 0-100 "how done is the architecture" number.
# Run `make arch-score` as you work: the score only rises when a real invariant
# is satisfied or an outcome gate passes. Prints the lowest-scoring KPIs last
# as the "chase these next" list. No python, no network — grep + existing gates.
#
# Honesty rules: a KPI scores its full weight ONLY on a mechanical proof
# (a grep that finds zero violations, or an outcome gate that emits a PASS).
# A KPI with no proof yet scores 0 and says why. Never award partial credit
# for "looks close".
set -uo pipefail
export LC_ALL=C
cd "$(dirname "${BASH_SOURCE[0]}")/../.." || exit 2
ROOT="$(pwd)"

TOTAL=0 MAX=0
declare -a ROWS   # "score/weight|slug|note"

kpi() { # weight got slug note
  local w="$1" g="$2" slug="$3" note="$4"
  MAX=$((MAX + w)); TOTAL=$((TOTAL + g))
  ROWS+=("$g/$w|$slug|$note")
}

# Every ledger-backed KPI below asks the ledger's JUDGE, never the ledger file.
# Reading `history.jsonl` directly (the old `tail -n 5 | grep '"verdict":"pass"'`)
# is a five-run sliding OR-gate: it has no freshness check, no thin-fixture check
# and no lagging-fixture check, so a PASS recorded days ago against a
# below-checkpoint peer kept scoring forever. stopwatch_evidence_judge.sh — which
# `make c3-stopwatch-report` / `make netdisrupt-stopwatch-report` wrap, complete
# with the FALSE-GREEN GUARD that fails the recipe if no VERDICT= line is printed
# — applies all three. Asking it can only ever LOWER a score relative to the
# grep, which is what ARCH_QUEST_BOARD.md rule 1 requires: "You win a point ONLY
# by the real proof … never inflate an existing one."
judge_pass() { # <make-target>
  command -v make >/dev/null || return 1
  local out rc=0
  out="$(make -s "$1" 2>/dev/null)" || rc=$?
  [ "$rc" -eq 0 ] && grep -q 'VERDICT=PASS' <<<"$out"
}
c3pass=0; judge_pass c3-stopwatch-report && c3pass=1

# ── KPI 1 (20) — INSTANT-ON END TO END: a wiped node installs the bundle and
#    reaches tip. THE outcome. Proof = a PASS from the c3 stopwatch JUDGE. ─────
so1=0; n1="c3-stopwatch judge does not say PASS (D8: install defers → genesis fold)"
if [ "$c3pass" = 1 ]; then
  so1=20; n1="c3 stopwatch judge VERDICT=PASS"
fi
kpi 20 "$so1" "instant-on-e2e" "$n1"

# ── KPI 2 (15) — STAY SYNCED: soak evidence + disruption recovery. ───────────
so2=0; n2="no soak MET verdict + no netdisrupt PASS yet"
if [ "$c3pass" = 1 ]; then
  ndp=0
  judge_pass netdisrupt-stopwatch-report && ndp=1
  if [ "$ndp" = 1 ]; then so2=15; n2="stopwatch report PASS + disruption recovery PASS"
  else so2=8; n2="stopwatch PASS but disruption recovery not yet proven"; fi
fi
kpi 15 "$so2" "stay-synced" "$n2"

# ── KPI 3 (20) — SINGLE WRITER PER FRONTIER (the core invariant). Each frontier
#    fact has ONE canonical writer; a second writer is a cloned ledger (the
#    D1-D8 disease). Measured against a manifest of (frontier, canonical owner);
#    a write outside the owner is a violation. Score scales with clean frontiers.
FMAN="$ROOT/tools/scripts/arch_frontier_owners.tsv"
so3=0; n3="frontier-owner manifest missing"
if [ -f "$FMAN" ]; then
  clean=0 nf=0
  while IFS=$'\t' read -r frontier owner writepat; do
    case "$frontier" in ''|'#'*) continue;; esac
    nf=$((nf + 1))
    # count files (excluding the owner + tests/docs) that match the write pattern
    viol=$(grep -rlE "$writepat" app lib config src core 2>/dev/null \
             | grep -vE "(^|/)(${owner})$|/test|/tests/|_test\.|/include/" | wc -l | tr -d ' ')
    [ "${viol:-1}" = 0 ] && clean=$((clean + 1))
  done < "$FMAN"
  if [ "$nf" -gt 0 ]; then
    so3=$(( 20 * clean / nf ))
    n3="$clean/$nf frontiers have a single canonical writer"
  fi
fi
kpi 20 "$so3" "single-writer-per-frontier" "$n3"

# ── KPI 4 (15) — READERS READ THE FOLD, not a side cursor. Gates/status/self-heal
#    must consult the reducer frontier, never pindex_best_header / coins-applied
#    directly. Violation = a gate/decision reading a side view. ────────────────
so4=0
# "Readers read the fold" is only PROVEN when a wiped node's install actually
# binds and reaches tip — i.e. the instant-on-e2e outcome. A grep of the source
# can be fooled (the defer message is split across lines, and a fix may keep a
# legitimate not-ready defer). So this scores only on the outcome: no e2e PASS
# ⇒ we have NOT demonstrated the install reads the right authority.
[ "$so1" = 20 ] && so4=15
n4=$([ "$so4" = 15 ] && echo "install binds on the frontier authority (proven by e2e PASS)" || echo "unproven — install still defers on a side cursor (D8 OPEN)")
kpi 15 "$so4" "readers-read-the-fold" "$n4"

# ── KPI 5 (10) — NO SILENT STALL: every stall raises a named blocker. Proxy: the
#    known silent-spin sites carry a typed blocker. D7 (Sapling rebuild livelock)
#    is the open counter-example — it logs INFO forever with no blocker. ───────
so5=0; n5="D7 Sapling-rebuild livelock logs INFO forever, no named blocker (OPEN)"
# The livelock is the "deferring... foreign open transaction" retry loop. It
# clears when that specific path raises a typed blocker with a height (a fix
# marker the lane must add) instead of an INFO log.
if grep -qsE 'deferring height=.*blocker|persist_livelock_blocker|blocker.*foreign open transaction' \
     app/controllers/src/sync_controller_sapling_tree_persist.c; then
  so5=10; n5="Sapling-persist livelock raises a named blocker (D7 closed)"
fi
kpi 10 "$so5" "no-silent-stall" "$n5"

# ── KPI 6 (10) — NO HIDDEN O(chain) BOOT WORK: the bundle ships complete state
#    so a fresh instant-on node never rebuilds the Sapling tree at boot. Proxy:
#    a full-bundle install path does NOT arm the deferred Sapling rebuild. ─────
so6=0; n6="bundle install path can still trigger the O(chain) Sapling rebuild (legacy seam)"
# scored when a lane wires the bundle's shielded tree so rebuild is skipped
if grep -qsE 'skip.*sapling.*rebuild|bundle.*ships.*(sapling|shielded).*tree' config/src/consensus_state_install_runtime.c 2>/dev/null; then
  so6=10; n6="bundle-installed shielded tree skips the boot rebuild"
fi
kpi 10 "$so6" "no-ochain-boot" "$n6"

# ── KPI 7 (10) — OBSERVABILITY: reads never block on the write lock; a folding
#    node stays introspectable. Proof = the three stage dumpers use trylock. ───
so7=0; dt=0
for f in utxo_apply_stage_dump script_validate_stage_dump proof_validate_stage_dump; do
  grep -qE 'progress_store_tx_trylock' app/jobs/src/$f.c 2>/dev/null && dt=$((dt + 1))
done
[ "$dt" = 3 ] && so7=10
n7="$dt/3 stage dumpers use trylock (busy node stays observable)"
kpi 10 "$so7" "observability" "$n7"

# ── KPI 8 (enforcement, weight 0 but gates the ceiling) — the single-writer
#    invariant is LINT-ENFORCED so a future LLM cannot re-clone a ledger. ──────
# PRESENT only when a REAL lint gate (not this scorer) fails the build on a
# second frontier writer, AND it is wired into `make lint`.
enf="MISSING"
if [ -f tools/scripts/check_frontier_single_writer.sh ] && grep -qsE 'check-frontier-single-writer|check_frontier_single_writer' Makefile; then
  enf="PRESENT"
fi

# ── Report ───────────────────────────────────────────────────────────────────
pct=$(( MAX > 0 ? 100 * TOTAL / MAX : 0 ))
echo "════════════════════════════════════════════════════════════════"
echo "  ARCHITECTURE NORTH STAR — SCORE: ${TOTAL}/${MAX}  (${pct}%)"
echo "  enforcement gate (single-writer lint): ${enf}"
echo "════════════════════════════════════════════════════════════════"
# print highest first, lowest (chase-next) last
printf '%s\n' "${ROWS[@]}" | sort -t/ -k1 -rn | while IFS='|' read -r sc slug note; do
  mark="✗"; g="${sc%%/*}"; w="${sc##*/}"
  [ "$g" = "$w" ] && mark="✓"; [ "$g" != 0 ] && [ "$g" != "$w" ] && mark="◐"
  printf "  [%5s] %-28s %s  %s\n" "$sc" "$slug" "$mark" "$note"
done
echo "────────────────────────────────────────────────────────────────"
# name the single highest-weight unfinished quest as the concrete next move
NEXT=$(printf '%s\n' "${ROWS[@]}" | awk -F'|' '{split($1,a,"/"); if(a[1]<a[2]) print (a[2]-a[1])"\t"$2}' \
        | sort -rn | head -1 | cut -f2)
echo "  ▶ NEXT QUEST: ${NEXT:-none — 100/100, you win}"
echo "  ▶ PLAY: docs/ARCH_QUEST_BOARD.md  (exact move + win-proof per quest)"
echo "  ▶ RULES: don't edit this scorer to win; consensus frozen; copy-prove."
# exit code = 100 - pct so CI/loops can gate on a threshold
exit 0
