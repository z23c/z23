#!/usr/bin/env bash
# Gate: sandbox wired (HARD).
#
# The os_sandbox node steady-state profile is only a defense if boot actually
# ENTERS it. This gate asserts that engine/composition/src/boot.c both (a) registers a
# SYSINIT boundary record named "sandbox" and (b) calls os_sandbox_enter(),
# so the confinement wiring cannot silently regress to zero-sandbox while the
# -sandbox=steady flag still advertises confinement.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

SRC="engine/composition/src/boot.c"
[[ -f "$SRC" ]] || { echo "check_sandbox_wired: FATAL — missing $SRC" >&2; exit 2; }

SANDBOX_SRC="platform/modules/platform/src/os_sandbox_linux.c"
[[ -f "$SANDBOX_SRC" ]] || { echo "check_sandbox_wired: FATAL — missing $SANDBOX_SRC" >&2; exit 2; }

fail=0

if ! grep -Eq '\.name[[:space:]]*=[[:space:]]*"sandbox"' "$SRC"; then
    echo "check_sandbox_wired: FAIL — no SYSINIT record named \"sandbox\" in $SRC" >&2
    fail=1
fi

if ! grep -Eq '\.stage[[:space:]]*=[[:space:]]*BOOT_STAGE_SERVICES_RUNNING.*"sandbox"|"sandbox".*BOOT_STAGE_SERVICES_RUNNING' "$SRC"; then
    echo "check_sandbox_wired: FAIL — the sandbox record is not on the SERVICES_RUNNING boundary in $SRC" >&2
    fail=1
fi

if ! grep -Eq '\bos_sandbox_enter[[:space:]]*\(' "$SRC"; then
    echo "check_sandbox_wired: FAIL — boot never calls os_sandbox_enter() in $SRC" >&2
    fail=1
fi

# The seccomp filter must be installed with SECCOMP_FILTER_FLAG_TSYNC via the
# seccomp(2) syscall so it lands on EVERY thread of the process atomically —
# not just the boot thread + descendants (prctl-only would silently leave the
# already-running P2P/RPC/service threads unconfined). Assert the TSYNC flag
# and the SYS_seccomp install call both appear in the sandbox install path so
# a refactor cannot regress total seccomp coverage back to per-thread.
if ! grep -Eq 'SECCOMP_FILTER_FLAG_TSYNC' "$SANDBOX_SRC"; then
    echo "check_sandbox_wired: FAIL — $SANDBOX_SRC does not use SECCOMP_FILTER_FLAG_TSYNC (seccomp would confine only the boot thread)" >&2
    fail=1
fi

if ! grep -Eq 'syscall[[:space:]]*\([[:space:]]*__NR_seccomp' "$SANDBOX_SRC"; then
    echo "check_sandbox_wired: FAIL — $SANDBOX_SRC never installs via the seccomp(2) syscall (__NR_seccomp) for the TSYNC path" >&2
    fail=1
fi

# ── Visibility: confinement that cannot be observed is confinement nobody
# can operate. Three invariants, all greppable:
#
#  (1) boot must NOTE the request before attempting it. Every degrade path in
#      sr_confine_enter returns ZCL_OK and runs the node UNCONFINED; without
#      the note, `active == false` cannot be told apart from "nobody asked".
#  (2) a `confinement` dumpstate row must exist, so the verdict is reachable
#      through `ops state` and not only from a log line at boot.
#  (3) the witness must NEVER re-probe Landlock. os_sandbox_landlock_abi()
#      issues landlock_create_ruleset(2), which is absent from both -confine
#      seccomp allow-sets — a probe from inside a confined process is
#      SECCOMP_RET_KILL_PROCESS. The witness reads the cached ABI instead.
WITNESS_SRC="platform/modules/platform/src/os_sandbox_witness.c"
# The descriptor rows live in per-domain files under a pure aggregator, so the
# row is searched for across the whole resolved set — see tools/lint/dumper_defs.sh
# for why this is not a hardcoded single path.
# shellcheck source=tools/lint/dumper_defs.sh
. tools/lint/dumper_defs.sh

if ! grep -Eq '\bos_sandbox_note_requested[[:space:]]*\(' "$SRC"; then
    echo "check_sandbox_wired: FAIL — boot never calls os_sandbox_note_requested() in $SRC (a failed apply would be indistinguishable from 'never requested')" >&2
    fail=1
fi

if [[ ! -f "$WITNESS_SRC" ]]; then
    echo "check_sandbox_wired: FAIL — missing $WITNESS_SRC (the confinement witness)" >&2
    fail=1
elif grep -Eq '\bos_sandbox_landlock_abi[[:space:]]*\(' "$WITNESS_SRC"; then
    echo "check_sandbox_wired: FAIL — $WITNESS_SRC live-probes Landlock; use os_sandbox_landlock_abi_cached() (a probe from a confined process is KILL_PROCESS)" >&2
    fail=1
fi

if ! dumper_def_files dumper_defs; then
    echo "check_sandbox_wired: FAIL — could not resolve the dumpstate descriptor set" >&2
    fail=1
elif ! grep -Eq '"confinement"[[:space:]]*,[[:space:]]*confinement_dump_state_json' \
        "${dumper_defs[@]}"; then
    echo "check_sandbox_wired: FAIL — no \"confinement\" dumpstate row in ${DUMPER_DEF_AGGREGATOR} or the $(( ${#dumper_defs[@]} - 1 )) per-domain files it includes (the UNCONFINED verdict would be unreachable via ops state)" >&2
    fail=1
fi

if (( fail )); then
    echo "check_sandbox_wired: the -sandbox=steady confinement wiring is missing or moved." >&2
    exit 1
fi

echo "[check_sandbox_wired] OK — boot registers the sandbox record, enters os_sandbox, notes the request, exposes the \`confinement\` witness (no live Landlock re-probe), and the seccomp filter installs with TSYNC (all-thread coverage)"
exit 0
