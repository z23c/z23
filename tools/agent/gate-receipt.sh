#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# gate-receipt.sh — run a gate and leave behind evidence that it ran.
#
# ── WHY THIS EXISTS ────────────────────────────────────────────────────────
# A lane agent reports "make lint passed". The orchestrator cannot tell that
# apart from a confident guess without re-running lint, and has been burned
# twice by exactly this class: a test that was green only because it read the
# live node's datadir, and a lint gate that reported CLEAN because a
# `printf | grep -q` under pipefail inverted its verdict. Re-running every
# claimed gate costs more than the lane did.
#
# So: wrap the gate. The receipt is a BYPRODUCT of running it — the wrapper
# holds the child's combined output, times it, and commits to it with a
# SHA3-256 — and it is transparent (same stdout, same exit status), so the
# honest path is `tools/agent/gate-receipt.sh --gate lint -- make lint`
# instead of `make lint`, and nothing else changes.
#
# ── WHAT THIS DEFENDS AGAINST, AND WHAT IT DOES NOT ────────────────────────
# DEFENDS (the common case): an agent that did not run the gate and reports
# success from memory. To forge a passing receipt it must produce the gate's
# entire literal output — 128 banner lines for lint, 866 group lines for the
# suite — with a matching SHA3, a matching HEAD and working-tree digest, a
# plausible wall time and child CPU time, and a valid link into the receipt
# chain. That is strictly more work than running the gate.
# DEFENDS: a STALE receipt replayed after the tree moved (head_sha and the
#   working-tree digests are recorded and re-derived by check-claims.sh).
# DEFENDS: a receipt produced in another worktree, on another host, or before
#   a reboot (worktree_path, hostname, kernel_boot_id).
# DEFENDS: exit-status laundering — the verdict is derived from the wrapper's
#   observed status AND independently re-derived by check-claims.sh from the
#   stored log's success/failure tokens, so "PASS" with a log containing
#   `SOME TESTS FAILED` is caught.
# DOES NOT DEFEND: a lane agent writing a receipt file (and a matching log)
#   directly. Nothing here is signed by a key the agent lacks; every field is
#   computable by anything with a shell in this checkout. This is EVIDENCE,
#   not proof. Do not describe it as tamper-proof.
# DOES NOT DEFEND: a gate run in a doctored environment (patched gate script,
#   fixture stub). The receipt records what ran, not that what ran was honest.
# The upgrade that would close the first gap is an out-of-band signature
# (ssh-keygen -Y sign, as platform/deploy/promotion-receipts.jsonl already does) with a
# key the lane cannot read. On this host the lane and the orchestrator share a
# user, so that buys nothing today; it buys everything once lanes run as
# separate users or on separate machines.
#
# ── USAGE ──────────────────────────────────────────────────────────────────
#   tools/agent/gate-receipt.sh --gate lint -- make lint
#   tools/agent/gate-receipt.sh --gate t-fast -- make t-fast ONLY=boot_phase
#   tools/agent/gate-receipt.sh --gate custom --expect 'MY OK TOKEN' -- ./thing
#   make gate-receipt GATE=lint CMD='make lint'
#
#   --gate <slug>      names the claim. Repeated runs of the same slug are all
#                      kept; check-claims.sh judges the NEWEST per slug and
#                      counts the rest as iterations.
#   --dir <path>       receipt directory (default .cache/agent-receipts, or
#                      $ZCL_RECEIPT_DIR). Gitignored; hand the path back to
#                      the orchestrator.
#   --expect <token>   literal that MUST appear in the output for PASS.
#   --forbid <token>   literal that must NOT appear. Both may repeat.
#   --label <text>     free-text note carried into the receipt.
#   --quiet            do not mirror the child's output to this terminal.
#   --selftest-helper  compile the helper into a fresh temporary directory,
#                      verify SHA3-256("abc"), then exit without running a gate.
#
# Known slugs carry default tokens (see TOKEN DEFAULTS below) so that
# `--gate lint` already means "and the literal all-checks-passed banner was
# printed", not merely "exit 0". A zero exit alone is not green in this repo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tools/scripts/sh_str.sh
. "$REPO/tools/scripts/sh_str.sh"

GATE=""
DIR="${ZCL_RECEIPT_DIR:-$REPO/.cache/agent-receipts}"
LABEL=""
QUIET=0
EXPECT=()
FORBID=()
CMD=()
SELFTEST_HELPER=0

die() { echo "gate-receipt: $*" >&2; exit 2; }

# The receipt helper uses only the scalar streaming SHA3 surface. Keep this
# build path small: keccak_x4.c is the independent four-message accelerator,
# is never called by agent_sha3, and pulls in platform SIMD dispatch providers
# that a fresh standalone link otherwise has to mirror forever.
build_sha3_helper() {
    local out="$1"
    mkdir -p "$(dirname "$out")"
    "${CC:-cc}" -std=c23 -O2 -Wall -Wextra -Werror \
        -I"$REPO/platform/modules/sha3/include" -I"$REPO/core/modules/crypto/include" \
        -I"$REPO/platform/modules/support/include" -I"$REPO/platform/modules/base/include" \
        -o "$out" \
        "$REPO/tools/agent/agent_sha3.c" \
        "$REPO/platform/modules/sha3/src/sha3.c"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --gate)   [ "$#" -ge 2 ] || die "--gate needs a value";   GATE="$2"; shift 2 ;;
        --dir)    [ "$#" -ge 2 ] || die "--dir needs a value";    DIR="$2";  shift 2 ;;
        --label)  [ "$#" -ge 2 ] || die "--label needs a value";  LABEL="$2"; shift 2 ;;
        --expect) [ "$#" -ge 2 ] || die "--expect needs a value"; EXPECT+=("$2"); shift 2 ;;
        --forbid) [ "$#" -ge 2 ] || die "--forbid needs a value"; FORBID+=("$2"); shift 2 ;;
        --quiet)  QUIET=1; shift ;;
        --selftest-helper) SELFTEST_HELPER=1; shift ;;
        --)       shift; CMD=("$@"); break ;;
        -h|--help) sed -n '2,70p' "$0"; exit 0 ;;
        *)        die "unknown option '$1' (the command goes after --)" ;;
    esac
done

if [ "$SELFTEST_HELPER" = "1" ]; then
    selftest_tmp="$(mktemp -d "${TMPDIR:-/tmp}/zcl-gate-receipt-selftest.XXXXXX")" \
        || die "selftest mktemp failed"
    selftest_bin="$selftest_tmp/agent_sha3"
    selftest_cleanup() {
        rm -f "$selftest_bin"
        rmdir "$selftest_tmp" 2>/dev/null || true
    }
    trap selftest_cleanup EXIT
    trap 'exit 130' INT TERM
    build_sha3_helper "$selftest_bin" \
        || die "selftest could not build a fresh agent_sha3 helper"
    selftest_got="$(printf '%s' abc | "$selftest_bin" -)"
    selftest_want="3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    [ "$selftest_got" = "$selftest_want" ] \
        || die "selftest SHA3-256(abc) mismatch: got=$selftest_got want=$selftest_want"
    echo "gate-receipt: selftest PASS — fresh scalar helper links and hashes SHA3-256(abc)"
    exit 0
fi

[ -n "$GATE" ] || die "--gate <slug> is required; it is the name of the claim"
[ "${#CMD[@]}" -gt 0 ] || die "no command — put it after --, e.g. -- make lint"
case "$GATE" in
    ''|*[!A-Za-z0-9_.-]*) die "--gate '$GATE' must be [A-Za-z0-9_.-] only" ;;
esac

# ── TOKEN DEFAULTS ─────────────────────────────────────────────────────────
# House rule: green means the literal success token is PRESENT and the literal
# failure token is ABSENT. A zero exit alone is not green. Encoding that here
# means an agent cannot accidentally claim a hollow pass.
if [ "${#EXPECT[@]}" -eq 0 ] && [ "${#FORBID[@]}" -eq 0 ]; then
    case "$GATE" in
        lint|lint-cached|lint-cold-audit)
            EXPECT=("LINT: all checks passed") ;;
        test|test-parallel|t|t-fast|t-asan|t-tsan|ci)
            EXPECT=("ALL TESTS PASSED"); FORBID=("SOME TESTS FAILED") ;;
    esac
fi

mkdir -p "$DIR"
DIR="$(cd "$DIR" && pwd)"

SHA3_BIN="$REPO/build/bin/agent_sha3"
if [ ! -x "$SHA3_BIN" ]; then
    # One translation unit plus the scalar in-tree SHA3; under a second. Built here
    # rather than made a Makefile prerequisite so that a receipt never costs a
    # Makefile parse (~6 s on this host) it did not already owe.
    build_sha3_helper "$SHA3_BIN" >&2 \
        || die "cannot build $SHA3_BIN (see above)"
fi

sha3_of_file() { "$SHA3_BIN" "$1" | cut -d' ' -f1; }
sha3_of_stdin() { "$SHA3_BIN" -; }

cd "$REPO"

# ── pre-run snapshot ───────────────────────────────────────────────────────
head_sha="$(git rev-parse HEAD 2>/dev/null || echo UNKNOWN)"
branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo UNKNOWN)"
porcelain="$(git status --porcelain 2>/dev/null || true)"
dirty=0
dirty_files=0
if [ -n "$porcelain" ]; then
    dirty=1
    dirty_files="$(wc -l <<< "$porcelain" | tr -d ' ')"
fi
status_sha3="$(printf '%s' "$porcelain" | sha3_of_stdin)"
# The tracked-content digest. head_sha alone does not describe a dirty tree,
# and a lane is almost always dirty when it runs a gate.
diff_before="$(git diff HEAD 2>/dev/null | sha3_of_stdin)"

hostname_v="$(uname -n)"
boot_id="$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo UNKNOWN)"
user_v="${USER:-$(id -un 2>/dev/null || echo UNKNOWN)}"

# Receipt id: 16 bytes of kernel randomness. Not a secret — it just makes two
# receipts written in the same second distinguishable and un-guessable by
# something reconstructing a chain after the fact.
receipt_id="$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"

# Chain position: the newest existing receipt in this directory. A receipt
# inserted into the middle of the chain after the fact does not link.
chain_index=0
prev_sha3="GENESIS"
prev_name="NONE"
newest=""
# Ordered by the RECORDED index, not by mtime: several receipts can share a
# second, and mtime is the one field a filesystem copy silently rewrites.
best_idx=-1
for f in "$DIR"/*.receipt; do
    [ -e "$f" ] || continue
    idx="$(sed -n 's/^chain_index=//p' "$f" | head -n1)"
    case "$idx" in ''|*[!0-9]*) idx=0 ;; esac
    if [ "$idx" -gt "$best_idx" ]; then best_idx="$idx"; newest="$f"; fi
done
if [ -n "$newest" ]; then
    chain_index=$(( best_idx + 1 ))
    prev_sha3="$(sha3_of_file "$newest")"
    prev_name="$(basename "$newest")"
fi

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
base="$(printf '%06d-%s-%s' "$chain_index" "$GATE" "$stamp")"
receipt="$DIR/$base.receipt"
log="$DIR/$base.log"

started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_ns="$(date +%s%N)"

# Cumulative CHILD CPU around the run. A receipt claiming a passing `make lint`
# with ~0 s of child CPU is self-evidently fabricated; this is free to produce
# honestly and awkward to invent consistently.
#
# `times` MUST be captured by redirect, never by `$( times )`: a command
# substitution forks, and fork() zeroes the child process's RUSAGE_CHILDREN, so
# the subshell form reports 0m0.000s for everything. Measured on bash 5.2 here.
# Lines 1-2 of `times` are the shell's own user/sys; lines 3-4 are the
# children's — those are the two we want.
cpu_tmp="$(mktemp)"
trap 'rm -f "$cpu_tmp"' EXIT
times > "$cpu_tmp"
read -r _ _ cpu_before_u cpu_before_s <<< "$(tr '\n' ' ' < "$cpu_tmp")"

# ── run it ─────────────────────────────────────────────────────────────────
# tee never exits early, so this pipeline cannot SIGPIPE the child; the child's
# real status comes from PIPESTATUS, never from tee.
set +e
if [ "$QUIET" -eq 1 ]; then
    "${CMD[@]}" >"$log" 2>&1
    rc=$?
else
    "${CMD[@]}" 2>&1 | tee "$log"
    rc=${PIPESTATUS[0]}
fi
set -e

ended_ns="$(date +%s%N)"
ended_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
wall_ms=$(( (ended_ns - started_ns) / 1000000 ))
times > "$cpu_tmp"
read -r _ _ cpu_after_u cpu_after_s <<< "$(tr '\n' ' ' < "$cpu_tmp")"

# `times` prints <m>m<s>.<ms>s; convert to milliseconds without bc.
to_ms() {
    local t="${1:-0m0.000s}" m s ms
    m="${t%%m*}"; s="${t#*m}"; s="${s%s}"
    ms="${s#*.}"; s="${s%%.*}"
    case "$m"  in ''|*[!0-9]*) m=0  ;; esac
    case "$s"  in ''|*[!0-9]*) s=0  ;; esac
    case "$ms" in ''|*[!0-9]*) ms=0 ;; esac
    echo $(( (m * 60 + s) * 1000 + 10#$ms ))
}
child_cpu_ms=$(( $(to_ms "$cpu_after_u") + $(to_ms "$cpu_after_s")
                 - $(to_ms "$cpu_before_u") - $(to_ms "$cpu_before_s") ))
[ "$child_cpu_ms" -lt 0 ] && child_cpu_ms=0

diff_after="$(git diff HEAD 2>/dev/null | sha3_of_stdin)"
head_after="$(git rev-parse HEAD 2>/dev/null || echo UNKNOWN)"

out_bytes="$(wc -c < "$log" | tr -d ' ')"
out_lines="$(wc -l < "$log" | tr -d ' ')"
out_sha3="$(sha3_of_file "$log")"

# Token presence is decided by grepping the FILE. No printf|grep pipeline: a
# match must never be able to surface printf's SIGPIPE 141 as a miss.
token_hits() { grep -cF -- "$1" "$log" 2>/dev/null || true; }

expect_missing=0
forbid_present=0
for t in ${EXPECT[@]+"${EXPECT[@]}"}; do
    if [ "$(token_hits "$t")" -eq 0 ]; then
        expect_missing=$(( expect_missing + 1 ))
    fi
done
for t in ${FORBID[@]+"${FORBID[@]}"}; do
    if [ "$(token_hits "$t")" -gt 0 ]; then
        forbid_present=$(( forbid_present + 1 ))
    fi
done

verdict=PASS
[ "$rc" -eq 0 ] || verdict=FAIL
[ "$expect_missing" -eq 0 ] || verdict=FAIL
[ "$forbid_present" -eq 0 ] || verdict=FAIL

# The exact argv, two ways. `command_display` is for humans and is shell-quoted;
# `command_argv_sha3` is the authority — a digest over the NUL-joined argv, so
# it is exact regardless of how the display line quotes anything.
command_display="$(printf '%q ' "${CMD[@]}")"
command_display="${command_display% }"
command_argv_sha3="$(printf '%s\0' "${CMD[@]}" | sha3_of_stdin)"

body="$(
cat <<EOF
receipt_schema=zcl.gate_receipt.v1
receipt_id=$receipt_id
chain_index=$chain_index
prev_receipt=$prev_name
prev_receipt_sha3=$prev_sha3
gate=$GATE
label=$LABEL
command_display=$command_display
command_argv_sha3=$command_argv_sha3
command_argc=${#CMD[@]}
worktree_path=$REPO
branch=$branch
head_sha=$head_sha
head_sha_after=$head_after
tree_dirty=$dirty
tree_dirty_files=$dirty_files
tree_status_sha3=$status_sha3
tree_diff_sha3_before=$diff_before
tree_diff_sha3_after=$diff_after
hostname=$hostname_v
kernel_boot_id=$boot_id
run_user=$user_v
runner_pid=$$
started_at_utc=$started_utc
ended_at_utc=$ended_utc
wall_ms=$wall_ms
child_cpu_ms=$child_cpu_ms
exit_status=$rc
output_path=$(basename "$log")
output_bytes=$out_bytes
output_lines=$out_lines
output_sha3=$out_sha3
expect_tokens=${#EXPECT[@]}
forbid_tokens=${#FORBID[@]}
expect_missing=$expect_missing
forbid_present=$forbid_present
verdict=$verdict
EOF
for t in ${EXPECT[@]+"${EXPECT[@]}"}; do echo "expect_token=$t"; done
for t in ${FORBID[@]+"${FORBID[@]}"}; do echo "forbid_token=$t"; done
)"

{
    printf '%s\n' "$body"
    printf 'receipt_sha3=%s\n' "$(printf '%s\n' "$body" | sha3_of_stdin)"
} > "$receipt"

{
    echo "gate-receipt: $GATE $verdict (exit $rc, ${wall_ms}ms wall, ${child_cpu_ms}ms child CPU)"
    echo "gate-receipt: receipt $receipt"
    echo "gate-receipt: output  $log ($out_lines lines, $out_bytes bytes)"
} >&2

# Transparent wrapper: the caller sees the gate's own exit status.
exit "$rc"
