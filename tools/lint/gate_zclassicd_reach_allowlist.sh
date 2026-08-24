#!/usr/bin/env bash
#
# gate_zclassicd_reach_allowlist — RATCHET gate (E-class lint).
#
# Freezes the runtime/boot dependence on an external zclassicd so it cannot
# GROW. This protects the "node stands alone on its own cryptographic proof"
# invariant (see CLAUDE.md / docs/work/never-stuck-plan.md). The current set of
# non-test source files that reach into zclassicd is the BASELINE allowlist
# below: the gate PASSES today by construction and only FAILS when a file NOT
# already on the list gains a zclassicd reach.
#
# It does NOT try to make existing reaches go away (that is the never-stuck
# refactor, tracked separately) — it only stops the dependence from spreading.
#
# Exit 0 = pass. Non-zero + message on stderr = fail.
#
# Scope: NON-TEST source only — app/ lib/ config/ src/. The agent impact
# registry is excluded because it stores path strings, not runtime code.
# Excluded: lib/test, tools/soak, *_test.c, tools/crash_recovery_test.c.
#
set -u

if [ "${1:-}" = "--selftest" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/app/controllers/include/controllers" \
           "$tmp/app/services/src" "$tmp/lib" "$tmp/config" \
           "$tmp/src" "$tmp/tools/lint"
  cp tools/lint/scan_exclusions.sh "$tmp/tools/lint/scan_exclusions.sh"
  self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  metadata="$tmp/app/controllers/include/controllers/agent_impact_rules.def"
  runtime="$tmp/app/services/src/runtime_probe.c"
  near_name="$tmp/app/controllers/include/controllers/agent_impact_rules_extra.def"

  printf '%s\n' 'AGENT_IMPACT_RULE("app/services/src/zclassicd_oracle_service.c", "rpc")' > "$metadata"
  if ! GATE_ROOT="$tmp" bash "$self" >/dev/null 2>&1; then
    echo "gate_zclassicd_reach_allowlist: SELFTEST FAILED — exact metadata registry was treated as runtime code" >&2
    exit 2
  fi
  printf '%s\n' 'static const char *probe = "zclassicd_oracle";' > "$runtime"
  if GATE_ROOT="$tmp" bash "$self" >/dev/null 2>&1; then
    echo "gate_zclassicd_reach_allowlist: SELFTEST FAILED — runtime reach was accepted" >&2
    exit 2
  fi
  rm "$runtime"
  printf '%s\n' 'static const char *probe = "zclassicd_oracle";' > "$near_name"
  if GATE_ROOT="$tmp" bash "$self" >/dev/null 2>&1; then
    echo "gate_zclassicd_reach_allowlist: SELFTEST FAILED — similarly named metadata file escaped" >&2
    exit 2
  fi
  echo "gate_zclassicd_reach_allowlist: SELFTEST PASS (exact metadata excluded; runtime and near-name reaches fail)"
  exit 0
fi

# Repo root: dir this script is wired into, or argv[1], or CWD.
ROOT="${1:-${GATE_ROOT:-$(pwd)}}"
if [ ! -d "$ROOT/app" ] || [ ! -d "$ROOT/lib" ]; then
  echo "gate_zclassicd_reach_allowlist: '$ROOT' is not a zclassic23 checkout" >&2
  exit 2
fi
cd "$ROOT" || exit 2
# shellcheck source=tools/lint/scan_exclusions.sh
source tools/lint/scan_exclusions.sh

# --- The zclassicd-reach signature -----------------------------------------
# Symbols / literals that mean "this file talks to an external zclassicd"
# (the legacy mirror RPC, the oracle services, or its loopback ports).
PAT='legacy_chain_rpc_|legacy_chain_oracle|zclassicd_oracle|127\.0\.0\.1:8232|:8034|:8232|getblock-from-mirror'

# --- Search roots (non-test source) ----------------------------------------
SEARCH_DIRS="app lib config src"

# --- Exclusions (test / soak harness code is allowed to reach freely) ------
# The impact registry contains source-path strings only; it is test-selection
# metadata, not compiled runtime code and cannot create a daemon dependency.
EXCLUDE_RE='(^|/)lib/test/|(^|/)tools/soak/|_test\.c$|(^|/)tools/crash_recovery_test\.c$|(^|/)app/controllers/include/controllers/agent_impact_rules\.def$'

# --- Frozen baseline allowlist (verified 2026-07-14 against current tree) ---
# Every non-test source file that CURRENTLY contains a zclassicd reach.
# 17 files. Keep sorted. Removing a reach from a file may leave its name here
# harmlessly; ADDING a reach to any file NOT here is what fails the gate.
read -r -d '' ALLOWLIST <<'EOF'
app/conditions/src/tip_stall_oracle_rebuild.c
app/controllers/src/diagnostics_registry.c
app/controllers/src/probe_controller.c
app/controllers/src/repair_controller_rebuild.c
app/services/include/services/oracle_policy.h
app/services/include/services/quorum_oracle_service.h
app/services/include/services/zclassicd_oracle_service.h
app/services/src/quorum_oracle_service.c
app/services/src/snapshot_verify.c
app/services/src/zclassicd_oracle_service.c
config/include/config/boot_internal.h
config/src/boot_runtime_sync_services.c
config/src/boot_services.c
lib/net/src/fast_sync.c
lib/rpc/include/rpc/legacy_chain_oracle.h
lib/rpc/src/legacy_chain_oracle.c
src/main.c
EOF

# --- Compute the CURRENT reaching set --------------------------------------
CURRENT="$(grep -rEl "$PAT" $SEARCH_DIRS "${LINT_GREP_EXCLUDE_ARGS[@]}" 2>/dev/null \
            | grep -vE "$EXCLUDE_RE" \
            | sort -u)"

# --- Diff against the allowlist --------------------------------------------
# A "new" file = present in CURRENT, absent from ALLOWLIST = regression.
NEW="$(comm -23 <(printf '%s\n' "$CURRENT") <(printf '%s\n' "$ALLOWLIST" | sort -u))"

if [ -n "$NEW" ]; then
  echo "FAIL: gate_zclassicd_reach_allowlist — new zclassicd reach(es) outside the frozen allowlist:" >&2
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    echo "  + $f" >&2
    grep -nE "$PAT" "$f" 2>/dev/null | sed 's/^/      /' >&2
  done <<< "$NEW"
  echo "" >&2
  echo "The node must stand alone — runtime/boot zclassicd dependence may not grow." >&2
  echo "If this reach is genuinely required, add the file to ALLOWLIST in" >&2
  echo "tools/lint/gate_zclassicd_reach_allowlist.sh AND justify it in the commit." >&2
  exit 1
fi

# --- Informational: stale allowlist entries (do not fail) ------------------
# Files on the allowlist that no longer reach — fine, but worth pruning.
STALE="$(comm -13 <(printf '%s\n' "$CURRENT") <(printf '%s\n' "$ALLOWLIST" | sort -u))"
if [ -n "$STALE" ]; then
  echo "note: gate_zclassicd_reach_allowlist — allowlist entries that no longer reach (prunable):" >&2
  printf '  - %s\n' $STALE >&2
fi

COUNT="$(printf '%s\n' "$CURRENT" | grep -c . || true)"
echo "gate_zclassicd_reach_allowlist: OK ($COUNT non-test source files reach zclassicd; none new)"
exit 0
