#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# ship.sh — build ONE production binary and put those exact bytes on every node
# in the fleet, verifying each one by the source identity it reports back.
# The two package-verify workers the daemon spawns at reproduce time
# (zclassic23-package-verify{,-dev}, resolved beside its executable) ship as
# part of the same frozen artifact set: a host with a fresh daemon beside a
# stale worker fails reproduces with a bare "rebuild worker exit 2".
#
# Why this exists. Before it, deployment was: `make deploy` for this host only,
# `deploy-dev` refusing outright, and no path at all to the second server —
# `remote_node_update.sh` is observation-only by construction. The result was
# both public nodes running a binary three days older than main, one of them
# blocked by a defect whose fix was already merged and just never shipped.
#
# The design rule is BUILD ONCE, SHIP MANY:
#   - The production binary is a single whole-program cc over every source file
#     (~200 s). Rebuilding it per host multiplies that by the fleet size and,
#     worse, produces DIFFERENT bytes per host, so "are they running the same
#     code" stops being answerable by comparison.
#   - Instead one candidate is frozen, its SHA-256 and baked source id recorded,
#     and those bytes are copied to every target. Fleet agreement is then a
#     string compare, not an inference.
#
# Every host is verified from the RUNNING process: its /proc executable must be
# the candidate's exact bytes, its process environment must contain the exact
# deploy identity, and those bytes must answer status. A host that does not
# qualify is rolled back to the binary and identity it was running before the
# next host is touched.
#
# Usage:
#   tools/ship.sh                     # gate, build, deploy local, deploy remote
#   tools/ship.sh --targets=local     # one host
#   tools/ship.sh --targets=remote
#   tools/ship.sh --dry-run           # print the plan, touch nothing
#   tools/ship.sh --skip-gate         # reuse a banked verdict for this source id
#
# Environment:
#   ZCL_SHIP_REMOTE   ssh destination of the second node (required; fleet
#                     endpoints are operator-local and not committed)
#   ZCL_SHIP_HOSTS    override the whole fleet list, space separated
#
# ── HEALTH VERDICTS ARE NOT STOPWATCHES ─────────────────────────────────────
# Four loops in this file used to gate a REMOTE, DESTRUCTIVE rollback on a
# duration: 300s for the candidate to qualify (twice — once on the remote leg
# with an env override, once here with the number written into the source and
# no override at all), 60s for a restore to qualify. All four demanded that
# `timeout 20 "/proc/$pid/exe" status` answer, and a box booting a ~22 GB
# datadir on a 7200rpm disk misses that routinely. Ship touches the whole
# fleet in one command, so one SSD-shaped budget rolled correctly-shipped
# binaries off every slow machine at once.
#
# tools/scripts/ship_progress_lib.sh replaces all four with observed-progress
# verdicts read from /proc/<pid>/{io,stat} — bytes, CPU ticks, and
# delayacct_blkio_ticks, which climbs precisely while the process is BLOCKED
# on the disk and is therefore the one signal that stays alive on a box
# burning no CPU. A WEDGE IS SILENCE, NOT SLOWNESS, so only proven stillness
# (or a process that will not stay up) can authorise a rollback.
#
# The absolute ceilings survive as REPORTING windows and nothing else. When
# one expires while the box is still demonstrably advancing, ship says so and
# exits 3 with the candidate LEFT INSTALLED. Exit codes:
#
#   0  every named target qualified
#   1  a real fault: a target's process was proven wedged or would not stay
#      up. That target was rolled back, with the evidence printed.
#   3  UNVERIFIED, STILL PROGRESSING — a reporting window expired on a box
#      that was working. NOT a failure, and NOTHING was rolled back.
#   4  UNKNOWN — the host could not be observed (ssh down, /proc unreadable).
#      An unreachable host is not a failed deploy. NOTHING was rolled back;
#      a human decides.
#
# Knobs, all optional. Raising one never changes what a verdict MEANS:
#   ZCL_SHIP_REMOTE_HEALTH_SECONDS     candidate reporting window (900)
#   ZCL_SHIP_REMOTE_SILENCE_SECONDS    stillness that convicts a candidate (300)
#   ZCL_SHIP_ROLLBACK_HEALTH_SECONDS   restore reporting window (600)
#   ZCL_SHIP_ROLLBACK_SILENCE_SECONDS  stillness that convicts a restore (180)
#   ZCL_SHIP_CRASH_SAMPLES             consecutive absent/churning samples (3)
#   ZCL_SHIP_UNKNOWN_SAMPLES           consecutive unobservable samples (5)
#   ZCL_SHIP_RPC_BUDGETS               escalating `status` timeouts (5 20 60)
#   ZCL_SHIP_REMOTE_EXEC               test seam: stands in for ssh entirely
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=tools/scripts/source_identity_lib.sh
. "$REPO_ROOT/tools/scripts/source_identity_lib.sh"  # zcl_is_sha256, zcl_json_first_sha256

# Observed-progress health verdicts. The SAME file is sourced here and shipped
# over the wire ahead of both remote scripts, because the target box has no
# checkout: one implementation reaches the same verdict on both machines.
SHIP_LIB_PATH="$REPO_ROOT/tools/scripts/ship_progress_lib.sh"
# shellcheck source=tools/scripts/ship_progress_lib.sh
. "$SHIP_LIB_PATH"  # ship_await, ship_verdict, ship_remote_sh, ship_observe
SHIP_LIB_TEXT="$(cat "$SHIP_LIB_PATH")"

if [ -z "${ZCL_SHIP_REMOTE:-}" ]; then
    echo "set ZCL_SHIP_REMOTE=<host> locally; fleet endpoints are operator-local and not committed" >&2
    exit 2
fi
REMOTE_HOST="$ZCL_SHIP_REMOTE"
# One source of truth for the ssh options: the library is POSIX sh and cannot
# hold an array, so the string is canonical and the array is derived from it.
# Every option is a single word, so the word-splitting inside the library is
# exact rather than approximate.
SHIP_SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15"
SHIP_REMOTE_HOST="$REMOTE_HOST"
read -r -a SSH_OPTS <<< "$SHIP_SSH_OPTS"

# Health-verdict knobs, resolved once so the local leg and the two remote
# scripts are configured identically. See the HEALTH VERDICTS block above.
SHIP_REMOTE_WINDOW="${ZCL_SHIP_REMOTE_HEALTH_SECONDS:-900}"
SHIP_REMOTE_SILENCE="${ZCL_SHIP_REMOTE_SILENCE_SECONDS:-300}"
SHIP_ROLLBACK_WINDOW="${ZCL_SHIP_ROLLBACK_HEALTH_SECONDS:-600}"
SHIP_ROLLBACK_SILENCE="${ZCL_SHIP_ROLLBACK_SILENCE_SECONDS:-180}"
SHIP_CRASH_SAMPLES="${ZCL_SHIP_CRASH_SAMPLES:-3}"
SHIP_UNKNOWN_SAMPLES="${ZCL_SHIP_UNKNOWN_SAMPLES:-5}"
SHIP_RPC_BUDGETS="${ZCL_SHIP_RPC_BUDGETS:-5 20 60}"
# Spawnable companions of the daemon, resolved BESIDE its executable at
# reproduce time (pkgl_worker_path). Both ship with every candidate; the
# index order here is the order the remote swap stages them.
WORKER_NAMES=(zclassic23-package-verify zclassic23-package-verify-dev)
TARGETS="local remote"
TARGETS_EXPLICIT=0
DRY_RUN=0
SKIP_GATE=0
GATE_CACHE_DIR="${HOME}/.cache/zcl-ship"

for arg in "$@"; do
    case "$arg" in
        --targets=*) TARGETS="${arg#*=}"; TARGETS="${TARGETS//,/ }"; TARGETS_EXPLICIT=1 ;;
        --dry-run)   DRY_RUN=1 ;;
        --skip-gate) SKIP_GATE=1 ;;
        -h|--help)   sed -n '2,35p' "$0"; exit 0 ;;
        *) printf 'ship: unknown argument %s\n' "$arg" >&2; exit 2 ;;
    esac
done

say()  { printf '\033[1mship:\033[0m %s\n' "$*"; }
step() { printf '\n\033[1m── %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31mship: REFUSE:\033[0m %s\n' "$*" >&2; exit 1; }

# ── 0. The proof server is not a deploy target ──────────────────────────────
# $REMOTE_HOST holds one immutable tagged release candidate and records the
# evidence that the candidate stayed up. Restarting it destroys the very thing
# it exists to measure: an uptime and zero-intervention record is only worth
# something if nothing quietly resets it.
#
# Until 2026-07-29 this script did exactly that. `remote` was in the DEFAULT
# target list and the deploy step ran an unconditional `systemctl --user restart
# zclassic23` on it, so a bare `tools/ship.sh` — the documented everyday
# invocation — restarted the box that must not be restarted. The tooling and
# the operating rule were in direct opposition and nothing said so.
#
# Two different refusals on purpose, because the two mistakes are different:
#   - Bare `ship.sh`: the operator asked to ship, not to touch the proof
#     server. Drop `remote`, say so loudly, ship local. Refusing the whole run
#     would punish the common case for a target the operator never named.
#   - Explicit `--targets=...remote`: the operator DID name it. Silently
#     dropping it there would be worse than failing — they would believe the
#     proof server had been updated. Refuse outright, non-zero.
#
# Promotion is a deliberate act: ZCL_SHIP_ALLOW_PROOF_SERVER=1. A successful
# promotion records itself twice in step 4 below, right after the running
# daemon proves it took the candidate: a signed, hash-chained line in the
# TRACKED ledger deploy/promotion-receipts.jsonl (the authority — it replicates
# to origin and cannot be rewritten undetected), plus a local
# proof-server/<timestamp> tag as a convenience index.
# `tools/scripts/promotion_receipt.sh verify` checks the chain offline;
# `tools/scripts/proof_server_pin.sh check` dials the box to see whether it
# still runs what was pinned.
case " $TARGETS " in *" remote "*)
    if [ "${ZCL_SHIP_ALLOW_PROOF_SERVER:-0}" != "1" ]; then
        if [ "$TARGETS_EXPLICIT" -eq 1 ]; then
            die "--targets names 'remote', but $REMOTE_HOST is the immutable proof
       server: it runs one tagged candidate and records the evidence that the
       candidate held. Deploying restarts it and resets that record.
       Promoting a new candidate is deliberate:
           ZCL_SHIP_ALLOW_PROOF_SERVER=1 tools/ship.sh --targets=remote
       A successful promotion appends a signed receipt to the tracked ledger
       deploy/promotion-receipts.jsonl automatically (verify it any time with
       'tools/scripts/promotion_receipt.sh verify', then COMMIT it so it
       replicates); run 'tools/scripts/proof_server_pin.sh check' afterwards to
       confirm the box still runs what was pinned."
        fi
        TARGETS="${TARGETS//remote/}"
        TARGETS="$(printf '%s' "$TARGETS" | tr -s ' ' | sed 's/^ *//; s/ *$//')"
        say "skipping 'remote' — $REMOTE_HOST is the immutable proof server."
        say "  to promote a candidate there: ZCL_SHIP_ALLOW_PROOF_SERVER=1 tools/ship.sh --targets=remote"
        [ -n "$TARGETS" ] || die "no targets left to ship to"
    else
        say "ZCL_SHIP_ALLOW_PROOF_SERVER=1 — the proof server WILL be restarted and its evidence window reset"
    fi
;; esac

# ── 1. Preflight ────────────────────────────────────────────────────────────
# Everything that can refuse cheaply refuses BEFORE the 200-second build, so a
# misconfigured run costs seconds rather than minutes.
step "Preflight"

[ -z "$(git status --porcelain)" ] || \
    die "working tree is dirty — ship what is committed, not what is lying around"

HEAD_SHA="$(git rev-parse HEAD)"
git fetch -q origin main 2>/dev/null || say "warning: could not fetch origin (offline?)"
if git rev-parse --verify -q origin/main >/dev/null; then
    behind="$(git rev-list --count "$HEAD_SHA"..origin/main)"
    [ "$behind" -eq 0 ] || \
        die "HEAD is $behind commit(s) behind origin/main — rebase before shipping"
    ahead="$(git rev-list --count origin/main.."$HEAD_SHA")"
    if [ "$ahead" -gt 0 ]; then
        say "HEAD is $ahead commit(s) ahead of origin/main — pushing first"
        [ "$DRY_RUN" -eq 1 ] || git push --no-verify origin main
    fi
fi
say "source     $(git rev-parse --short HEAD)  $(git log -1 --format=%s | cut -c1-58)"

# A remote host that cannot run these bytes must be found now, not after the
# binary is already installed and the service restarted. The production build
# targets -march=x86-64-v3, so AVX2/FMA/BMI2 are load-bearing: shipping to a
# host without them yields SIGILL on a public node.
for target in $TARGETS; do
    case "$target" in
        local) continue ;;
        remote) ;;
        *) die "unknown target '$target' (want: local, remote)" ;;
    esac
    ssh "${SSH_OPTS[@]}" "$REMOTE_HOST" true 2>/dev/null || \
        die "remote $REMOTE_HOST is unreachable over ssh"
    # libc version via awk, NOT `... | head -1 | grep ...`. head closes the pipe
    # after one line, ldd takes SIGPIPE, and `set -o pipefail` turns that into a
    # 141 exit that kills this script before a single host is touched. It is a
    # RACE — it survives only when ldd's whole output lands in one write, which
    # is why ship worked on 2026-07-27 and died here on 2026-07-28. awk consumes
    # the stream to EOF, so there is no early close and no signal.
    remote_facts="$(ssh "${SSH_OPTS[@]}" "$REMOTE_HOST" \
        'printf "%s|%s|%s\n" "$(uname -m)" \
             "$(grep -c -m1 avx2 /proc/cpuinfo)" \
             "$(ldd --version 2>/dev/null | awk "NR==1 && match(\$0, /[0-9]+\.[0-9]+\$/) { print substr(\$0, RSTART, RLENGTH) }")"')"
    r_arch="${remote_facts%%|*}"; rest="${remote_facts#*|}"
    r_avx2="${rest%%|*}"; r_libc="${rest##*|}"
    l_arch="$(uname -m)"
    l_libc="$(ldd --version 2>/dev/null |
        awk 'NR==1 && match($0, /[0-9]+\.[0-9]+$/) { print substr($0, RSTART, RLENGTH) }')"
    [ "$r_arch" = "$l_arch" ] || \
        die "remote arch $r_arch != local $l_arch — cannot ship one binary to both"
    [ "$r_avx2" -ge 1 ] || \
        die "remote lacks AVX2 but the build targets x86-64-v3 — it would SIGILL"
    [ "$r_libc" = "$l_libc" ] || \
        die "remote glibc $r_libc != local $l_libc — build on the older host instead"
    say "remote     $REMOTE_HOST  $r_arch  glibc $r_libc  avx2 ok"
done

# ── 2. Gate ─────────────────────────────────────────────────────────────────
# Keyed on the source identity, so re-shipping an already-proven tree is free
# but a single changed byte re-gates. The token, never the exit code, decides.
step "Gate"

SOURCE_ID="$(tools/dev/source-identity.sh capture 2>/dev/null || true)"
zcl_is_sha256 "$SOURCE_ID" || SOURCE_ID=""
gate_stamp="${GATE_CACHE_DIR}/${SOURCE_ID:-unknown}.passed"

if [ "$SKIP_GATE" -eq 1 ] && [ -n "$SOURCE_ID" ] && [ -f "$gate_stamp" ]; then
    say "gate       banked for this exact source id ($(cat "$gate_stamp"))"
elif [ "$DRY_RUN" -eq 1 ]; then
    say "gate       (dry run — would run lint + full suite)"
else
    say "gate       make lint"
    make lint >/dev/null || die "make lint failed"
    say "gate       make test-parallel"
    suite_log="$(mktemp)"
    make test-parallel >"$suite_log" 2>&1 || true
    if grep -q 'ALL TESTS PASSED' "$suite_log" && \
       ! grep -q 'SOME TESTS FAILED' "$suite_log"; then
        say "gate       $(grep -m1 'ALL TESTS PASSED' "$suite_log")"
        mkdir -p "$GATE_CACHE_DIR"
        [ -n "$SOURCE_ID" ] && date -u +%Y-%m-%dT%H:%M:%SZ > "$gate_stamp"
    else
        grep -E 'SUITE VERDICT|repro:' "$suite_log" | head -5 >&2
        rm -f "$suite_log"
        die "full suite did not pass — nothing ships"
    fi
    rm -f "$suite_log"
fi

# ── 3. Build one candidate ──────────────────────────────────────────────────
# The production rule is a whole-program cc with no depfile tracking, so a
# header-only edit leaves every .c mtime unchanged and plain `make` would relink
# nothing and ship stale bytes. Removing the target forces the rebuild. This is
# the same reasoning the `deploy` target documents; it is the single most
# expensive step and the reason the result is shared across the fleet.
step "Build"

if [ "$DRY_RUN" -eq 1 ]; then
    say "build      (dry run — would rebuild and freeze one candidate + both workers)"
    CANDIDATE=""; ARTIFACT_SHA=""; CAND_SOURCE_ID="$SOURCE_ID"
else
    rm -f build/bin/zclassic23 build/bin/zclassic23-package-verify build/bin/zclassic23-package-verify-dev
    make -j"$(nproc)" zclassic23 zclassic23-package-verify dev-package-verifier >/dev/null || \
        die "production build failed"
    CANDIDATE="$(mktemp "${TMPDIR:-/tmp}/zclassic23.ship.XXXXXX")"
    WORKER_FILES=(); WORKER_SHAS=()
    trap 'rm -f "$CANDIDATE" "${WORKER_FILES[@]}"' EXIT HUP INT TERM
    install -m 755 build/bin/zclassic23 "$CANDIDATE"
    ARTIFACT_SHA="$(sha256sum < "$CANDIDATE" | awk '{print $1}')"
    zcl_is_sha256 "$ARTIFACT_SHA" || die "could not hash the frozen candidate"

    # Ask the candidate itself what source it was built from. A binary that
    # cannot answer is not shippable, because nothing downstream could then
    # prove which code a node is running.
    agentbuild="$(timeout 30 "$CANDIDATE" agentbuild 2>&1)" || \
        die "frozen candidate failed its agentbuild preflight"
    CAND_SOURCE_ID="$(zcl_agentbuild_v2_top_source_id "$agentbuild")"
    zcl_is_sha256 "$CAND_SOURCE_ID" || \
        die "frozen candidate reports no valid source_id_sha256"
    [ "$CAND_SOURCE_ID" = "$SOURCE_ID" ] || \
        die "frozen candidate source id differs from the gated checkout"
    CAND_BUILD_COMMIT="$(zcl_agentbuild_v2_top_build_commit "$agentbuild")"
    case "$CAND_BUILD_COMMIT" in
        ''|*[!A-Za-z0-9._-]*)
            die "frozen candidate reports an invalid display build_commit" ;;
    esac
    say "candidate  source_id ${CAND_SOURCE_ID:0:16}…  commit $CAND_BUILD_COMMIT  sha256 ${ARTIFACT_SHA:0:16}…  $(du -h "$CANDIDATE" | cut -f1)"

    # The package-verify workers are spawned by the daemon at reproduce time
    # and resolved BESIDE the running executable (pkgl_worker_path). A ship
    # that moves only the daemon leaves every host spawning whatever stale
    # worker bytes happen to sit in that directory — the exact trap that
    # broke a fleet warm rebuild on 2026-08-25: the fresh CLI passed
    # --allow-testless-standard, the day-old worker exited 2 on usage, and
    # zcl_spawn_capture swallowed the stderr, so reproduce failed with a bare
    # "rebuild worker exit 2". Freeze the workers from the SAME gated checkout
    # so all three spawnables travel as one artifact set.
    for w in zclassic23-package-verify zclassic23-package-verify-dev; do
        [ -x "build/bin/$w" ] || die "gated build did not produce worker $w"
        f="$(mktemp "${TMPDIR:-/tmp}/zclassic23.ship.XXXXXX")"
        install -m 755 "build/bin/$w" "$f"
        WORKER_FILES+=("$f")
        s="$(sha256sum < "$f" | awk '{print $1}')"
        zcl_is_sha256 "$s" || die "could not hash frozen worker $w"
        WORKER_SHAS+=("$s")
    done
    say "workers    zclassic23-package-verify ${WORKER_SHAS[0]:0:16}…  zclassic23-package-verify-dev ${WORKER_SHAS[1]:0:16}…  $(du -ch "${WORKER_FILES[@]}" | tail -1 | cut -f1)"
fi

# ── 4. Deploy, host by host ─────────────────────────────────────────────────
# Sequential on purpose. Two nodes restarting at once is how a fleet goes dark
# on one bad build; this way the first failure stops the rollout with every
# later host still serving.
# Install the frozen worker candidates beside a service executable,
# byte-verified against the gated build. Local counterpart of the remote
# worker swap. Workers go in BEFORE the daemon: a newer worker is
# backward-compatible with the older CLI (flags are only ever added), while
# the reverse mix — a new daemon spawning a stale worker — is the outage
# class this ship exists to close. `make deploy` owns the daemon binary's
# own build/swap/rollback transaction; worker bytes here come from the same
# gated checkout it builds from.
install_local_workers() {
    local dir="$1" i got
    for i in "${!WORKER_NAMES[@]}"; do
        install -m 755 "${WORKER_FILES[$i]}" "$dir/${WORKER_NAMES[$i]}"
        got="$(sha256sum < "$dir/${WORKER_NAMES[$i]}" | awk '{print $1}')"
        [ "$got" = "${WORKER_SHAS[$i]}" ] || \
            die "local worker install bytes differ for ${WORKER_NAMES[$i]}"
    done
    say "workers    installed beside $dir/"
}

deploy_local() {
    step "Deploy → local"
    if [ "$DRY_RUN" -eq 1 ]; then say "would install workers + run make deploy"; return 0; fi
    local pid svc_dir
    pid="$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)"
    case "$pid" in
        ""|*[!0-9]*|0) die "local canonical service must be running before ship" ;;
    esac
    svc_dir="$(dirname "$(readlink -f "/proc/$pid/exe")")"
    install_local_workers "$svc_dir"
    ZCL_DEPLOY_ALLOW_CANONICAL=1 make deploy 2>&1 | tail -6
    return "${PIPESTATUS[0]}"
}

deploy_remote() {
    step "Deploy → $REMOTE_HOST"
    local svc_bin prev_sha
    svc_bin="$(ssh "${SSH_OPTS[@]}" "$REMOTE_HOST" \
        'set -eu
         pid="$(systemctl --user show zclassic23 -p MainPID --value)"
         case "$pid" in ""|*[!0-9]*|0) exit 1 ;; esac
         readlink -f "/proc/$pid/exe"')"
    case "$svc_bin" in
        /*) ;;
        *) die "remote running executable path is missing or not absolute: '$svc_bin'" ;;
    esac
    say "remote bin $svc_bin"
    if [ "$DRY_RUN" -eq 1 ]; then say "would install candidate + workers + restart + verify"; return 0; fi

    prev_sha="$(ssh "${SSH_OPTS[@]}" "$REMOTE_HOST" "sha256sum < '$svc_bin' | awk '{print \$1}'" 2>/dev/null || echo none)"
    say "remote now sha256 ${prev_sha:0:16}…"

    # Stage beside the target, keep the outgoing binary as the rollback copy,
    # then swap. The running process holds its inode open, so replacing the
    # path never disturbs the daemon still serving from the old bytes.
    scp -q "${SSH_OPTS[@]}" "$CANDIDATE" "$REMOTE_HOST:${svc_bin}.incoming" || \
        die "could not copy the candidate to $REMOTE_HOST"

    # Stage the workers beside the same executable: pkgl_worker_path resolves
    # them there, so that directory is the only location where worker bytes
    # matter at reproduce time.
    local wi
    for wi in "${!WORKER_NAMES[@]}"; do
        scp -q "${SSH_OPTS[@]}" "${WORKER_FILES[$wi]}" \
            "$REMOTE_HOST:${svc_bin%/*}/${WORKER_NAMES[$wi]}.incoming" || \
            die "could not copy ${WORKER_NAMES[$wi]} to $REMOTE_HOST"
    done

    # The health library goes over the wire ahead of the activation script:
    # the target box has no checkout, so the only way both machines can reach
    # the same verdict is for the code that reaches it to travel with the
    # question. Everything after this printf is the activation transaction,
    # unchanged in shape — tools/lint/check_ship_remote_transaction.sh extracts
    # it verbatim and runs it against a fake service.
    local activate_rc=0
    { printf '%s\n' "$SHIP_LIB_TEXT"; cat <<'REMOTE_SCRIPT'
set -euo pipefail
svc_bin="$1"; want_sha="$2"; want_src="$3"; want_commit="$4"
want_worker_v="$5"; want_worker_d="$6"
# Health-verdict configuration, passed positionally because ssh forwards no
# environment. tools/scripts/ship_progress_lib.sh has already been prepended
# to this script on stdin — the target box has no checkout to source it from.
remote_window="$7"; remote_silence="$8"
rollback_window="$9"; rollback_silence="${10}"
crash_samples="${11}"; unknown_samples="${12}"; rpc_budgets="${13}"

# The two subjects this script judges, each wrapped to ship_await's
# one-argument observer seam. Same observables, same classifier, same words.
observe_candidate() { ship_observe zclassic23 "$want_sha" "$want_src" "$want_commit" "$1"; }
observe_restore()   { ship_observe zclassic23 "$prior_sha" "" "" "$1"; }

worker_dir="$(dirname "$svc_bin")"
worker_v="$worker_dir/zclassic23-package-verify"
worker_d="$worker_dir/zclassic23-package-verify-dev"
dropin_dir="$HOME/.config/systemd/user/zclassic23.service.d"
dropin="$dropin_dir/90-build-identity.conf"
rollback_bin="${svc_bin}.rollback"
rollback_dropin="${dropin}.ship.rollback"
dropin_absent="${dropin}.ship.absent"
dropin_tmp=""
prior_sha=""
rollback_armed=0

# Workers stage beside the service binary. Each swap verifies the exact
# transferred bytes against the gated build, snapshots the outgoing file the
# same way the daemon's rollback_bin does, and uses the same
# present/absent marker pair as the dropin so restore_prior can undo a
# worker that did not exist before the ship.
stage_worker() {
    w_dst="$1"; w_sha="$2"
    w_got="$(sha256sum < "${w_dst}.incoming" | awk '{print $1}')"
    [ "$w_got" = "$w_sha" ] || \
        { echo "remote: transferred worker bytes differ from candidate: $w_dst" >&2; exit 1; }
    chmod 755 "${w_dst}.incoming"
    if [ -f "$w_dst" ]; then
        install -m 755 "$w_dst" "${w_dst}.ship.rollback"
        rm -f "${w_dst}.ship.absent"
    else
        : > "${w_dst}.ship.absent"
        rm -f "${w_dst}.ship.rollback"
    fi
    mv -f "${w_dst}.incoming" "$w_dst"
}

restore_worker() {
    r_dst="$1"
    if [ -f "${r_dst}.ship.rollback" ]; then
        install -m 755 "${r_dst}.ship.rollback" "$r_dst" || return 1
    elif [ -f "${r_dst}.ship.absent" ]; then
        rm -f "$r_dst" || return 1
    fi
}

restore_prior() {
    restore_worker "$worker_v" && restore_worker "$worker_d" || return 1
    install -m 755 "$rollback_bin" "$svc_bin" || return 1
    if [ -f "$rollback_dropin" ]; then
        install -m 644 "$rollback_dropin" "$dropin" || return 1
    elif [ -f "$dropin_absent" ]; then
        rm -f "$dropin" || return 1
    fi
    systemctl --user daemon-reload || return 1
    systemctl --user restart zclassic23 || return 1

    # The restored binary is judged by the same rule as the candidate: is this
    # process MOVING? A restore is the worst possible moment to mistake slow
    # for broken — the box has just been handed back its previous, known-good
    # executable, and calling that restore "failed" because a cold datadir
    # takes longer than a stopwatch would send an operator hunting a fault
    # that does not exist while a healthy node boots underneath them.
    #
    # There is no deploy identity to demand here: the restored binary predates
    # the identity drop-in this ship installed, so want_src is deliberately
    # empty and ship_observe reports ident=yes.
    SHIP_AWAIT_WINDOW="$rollback_window"
    SHIP_AWAIT_SILENCE="$rollback_silence"
    SHIP_AWAIT_POLL=2
    SHIP_AWAIT_CRASH_SAMPLES="$crash_samples"
    SHIP_AWAIT_UNKNOWN_SAMPLES="$unknown_samples"
    SHIP_AWAIT_RPC_BUDGETS="$rpc_budgets"
    restore_rc=0
    ship_await "remote restore" observe_restore "$prior_sha" || restore_rc=$?
    return "$restore_rc"
}

restore_on_failure() {
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "$rollback_armed" -eq 1 ]; then
        echo "remote: activation failed; restoring prior executable and identity" >&2
        if restore_prior; then
            echo "remote: rollback process-qualified"
        else
            restore_rc=$?
            case "$restore_rc" in
                3)
                    # The window expired on a restored process that is still
                    # advancing. The prior bytes and identity ARE back in
                    # place and the process is working; naming this CRITICAL
                    # would be the same collapse of slow into broken that
                    # this whole file just stopped making.
                    echo "remote: rollback restored and demonstrably booting — the reporting" \
                         "window expired while the restored process was still advancing." \
                         "This is a slow disk, NOT a failed rollback." >&2
                    ;;
                4)
                    echo "remote: CRITICAL — rollback bytes are in place but the process" \
                         "could not be OBSERVED at all (no /proc evidence). Unverified," \
                         "not proven failed — look at this host." >&2
                    rc=71
                    ;;
                *)
                    echo "remote: CRITICAL — rollback could not be process-qualified" >&2
                    rc=70
                    ;;
            esac
        fi
    fi
    [ -z "$dropin_tmp" ] || rm -f "$dropin_tmp"
    exit "$rc"
}
trap restore_on_failure EXIT HUP INT TERM

got="$(sha256sum < "${svc_bin}.incoming" | awk '{print $1}')"
[ "$got" = "$want_sha" ] || { echo "remote: transferred bytes differ from candidate" >&2; exit 1; }
chmod 755 "${svc_bin}.incoming"

# Workers swap BEFORE the daemon. If a worker stage fails, the host still has
# its old daemon and old workers — a consistent pair. Once the daemon swap
# begins, restore_prior (armed below) undoes workers and binary together. The
# brief old-daemon-spawns-new-worker window is the safe direction: worker
# flags are only ever added, so the newer worker accepts the older CLI.
stage_worker "$worker_v" "$want_worker_v"
stage_worker "$worker_d" "$want_worker_d"

# The transferred SHA-256 is the source binding. The local preflight already
# asked these exact bytes for their baked source id; re-parsing the same large
# JSON through a remote grep|head pipeline added no authority and could fail
# with SIGPIPE after extracting the right value.
pid="$(systemctl --user show zclassic23 -p MainPID --value)"
case "$pid" in ""|*[!0-9]*|0) echo "remote: no running MainPID" >&2; exit 1 ;; esac
install -m 755 "/proc/$pid/exe" "$rollback_bin"
prior_sha="$(sha256sum < "$rollback_bin" | awk '{print $1}')"
install -d "$dropin_dir"
rm -f "$rollback_dropin" "$dropin_absent"
if [ -f "$dropin" ]; then
    install -m 644 "$dropin" "$rollback_dropin"
else
    : > "$dropin_absent"
fi
# Every dependency needed for restoration now exists. Arm rollback before the
# first mutation, including the identity install and daemon-reload; otherwise
# a failure in that small window could leave intent describing bytes that were
# never activated.
rollback_armed=1
dropin_tmp="$(mktemp "${dropin}.tmp.XXXXXX")"
{
    printf '[Service]\n'
    printf 'Environment="ZCL_AGENT_EXPECT_SOURCE_ID=%s"\n' "$want_src"
    printf 'Environment="ZCL_AGENT_EXPECT_BUILD_COMMIT=%s"\n' "$want_commit"
    printf 'Environment="ZCL_AGENT_EXPECT_BUILD_SOURCE=ship"\n'
} > "$dropin_tmp"
install -m 644 "$dropin_tmp" "$dropin"
rm -f "$dropin_tmp"; dropin_tmp=""
systemctl --user daemon-reload
mv -f "${svc_bin}.incoming" "$svc_bin"
systemctl --user restart zclassic23

# Keep the rollback transaction armed until the new process proves both exact
# bytes and useful RPC behavior. A successful `systemctl restart` only proves
# that systemd accepted a request; it does not prove the daemon stayed alive.
#
# What DISARMS the transaction is a verdict, not a clock. `healthy=0` after a
# 300s countdown used to mean "roll this box back", and on a 7200rpm box with
# a cold ~22 GB datadir that countdown expires while the node is doing exactly
# what it should. Now only CRASHED (the process will not stay up) or WEDGED
# (nothing about it moved for the whole silence limit) reaches the rollback,
# and both print the observation that justified them.
SHIP_AWAIT_WINDOW="$remote_window"
SHIP_AWAIT_SILENCE="$remote_silence"
SHIP_AWAIT_POLL=2
SHIP_AWAIT_CRASH_SAMPLES="$crash_samples"
SHIP_AWAIT_UNKNOWN_SAMPLES="$unknown_samples"
SHIP_AWAIT_RPC_BUDGETS="$rpc_budgets"
qual_rc=0
ship_await "remote candidate" observe_candidate "$want_sha" || qual_rc=$?
case "$qual_rc" in
    0) ;;
    3)
        # Still advancing when the reporting window closed. The candidate is
        # installed and working; rolling it back here is precisely the defect.
        # Disarm the transaction BEFORE exiting or the EXIT trap undoes a good
        # deploy on the way out.
        rollback_armed=0
        trap - EXIT HUP INT TERM
        echo "remote: UNVERIFIED (still progressing) — the ${remote_window}s reporting" \
             "window expired while this node was demonstrably still advancing." \
             "The candidate is INSTALLED and nothing was rolled back. Re-run" \
             "ship with --targets to re-check, or raise" \
             "ZCL_SHIP_REMOTE_HEALTH_SECONDS for this box." >&2
        exit 3
        ;;
    4)
        rollback_armed=0
        trap - EXIT HUP INT TERM
        echo "remote: UNKNOWN — the candidate is installed but could not be" \
             "OBSERVED (no /proc evidence for $unknown_samples consecutive" \
             "samples). An unobservable host is not a failed deploy; nothing" \
             "was rolled back. Look at this host." >&2
        exit 4
        ;;
    *)
        echo "remote: candidate PROVEN faulty — see the verdict and last" \
             "observation above. Rolling back." >&2
        exit 1
        ;;
esac
rollback_armed=0
trap - EXIT HUP INT TERM
echo "remote: installed, restarted, and process-qualified"
REMOTE_SCRIPT
    } | ship_remote_script \
        "$svc_bin" "$ARTIFACT_SHA" "$CAND_SOURCE_ID" "$CAND_BUILD_COMMIT" \
        "${WORKER_SHAS[0]}" "${WORKER_SHAS[1]}" \
        "$SHIP_REMOTE_WINDOW" "$SHIP_REMOTE_SILENCE" \
        "$SHIP_ROLLBACK_WINDOW" "$SHIP_ROLLBACK_SILENCE" \
        "$SHIP_CRASH_SAMPLES" "$SHIP_UNKNOWN_SAMPLES" "$SHIP_RPC_BUDGETS" \
        || activate_rc=$?
    case "$activate_rc" in
        0) ;;
        3)
            say "$REMOTE_HOST is STILL PROGRESSING — the candidate is installed and working,"
            say "  but it had not finished coming up when the reporting window closed."
            say "  NOTHING was rolled back. Re-run ship --targets=remote to re-check."
            return 3
            ;;
        4)
            say "$REMOTE_HOST is UNKNOWN — the candidate is installed but the host could not"
            say "  be observed. An unobservable host is not a failed deploy; NOTHING was"
            say "  rolled back and no receipt was recorded. Go look at it."
            return 4
            ;;
        *)
            die "remote activation reported a proven fault (rc=$activate_rc); the remote
       transaction has already restored the prior executable and identity on
       $REMOTE_HOST. Its verdict and last observation are printed above."
            ;;
    esac

    # Verify the executable inode held by the RUNNING MainPID, not only the
    # pathname on disk. Exact process bytes bind the already-proven candidate
    # source id without another fallible JSON parser.
    #
    # This is the SECOND leg of the same question, asked from here so a remote
    # script that lied (or a box that changed its mind after the ssh closed)
    # is still caught. It used to be a hard-coded 300s countdown with NO
    # environment override at all, and `running_sha != ARTIFACT_SHA` after it —
    # including every case where ssh simply did not answer — meant ROLL BACK.
    # That single `|| true` turned a flaky network path into a fleet-wide
    # rollback of a good binary. Now the loop, the observables and the five
    # verdicts are the same ones the remote leg used; only the transport
    # differs, and a transport failure is UNKNOWN by construction.
    local qual_rc=0 running_sha rollback_rc
    SHIP_OBS_UNIT=zclassic23
    SHIP_OBS_SHA="$ARTIFACT_SHA"
    SHIP_OBS_SRC="$CAND_SOURCE_ID"
    SHIP_OBS_COMMIT="$CAND_BUILD_COMMIT"
    SHIP_AWAIT_WINDOW="$SHIP_REMOTE_WINDOW"
    SHIP_AWAIT_SILENCE="$SHIP_REMOTE_SILENCE"
    SHIP_AWAIT_POLL="${ZCL_SHIP_LOCAL_POLL_SECONDS:-10}"
    SHIP_AWAIT_CRASH_SAMPLES="$SHIP_CRASH_SAMPLES"
    SHIP_AWAIT_UNKNOWN_SAMPLES="$SHIP_UNKNOWN_SAMPLES"
    SHIP_AWAIT_RPC_BUDGETS="$SHIP_RPC_BUDGETS"
    ship_await "$REMOTE_HOST" ship_remote_observe "$ARTIFACT_SHA" || qual_rc=$?
    running_sha="$(ship_field "$SHIP_AWAIT_LAST_LINE" sha)"

    case "$qual_rc" in
        3)
            say "$REMOTE_HOST is STILL PROGRESSING — $SHIP_AWAIT_LAST_ADVANCES observed advances,"
            say "  last change ${SHIP_AWAIT_LAST_SILENT}s ago. The candidate stays installed and"
            say "  NOTHING was rolled back: a slow disk is not a failed deploy. No promotion"
            say "  receipt was appended — the binding is only recorded once a host qualifies."
            return 3
            ;;
        4)
            say "$REMOTE_HOST is UNKNOWN — no evidence could be gathered for"
            say "  $SHIP_UNKNOWN_SAMPLES consecutive attempts (host unreachable, or /proc unreadable)."
            say "  An unreachable host is not a failed deploy. NOTHING was rolled back."
            return 4
            ;;
    esac

    if [ "$qual_rc" -ne 0 ]; then
        say "$REMOTE_HOST is $SHIP_AWAIT_LAST_VERDICT — ROLLING BACK. Evidence:"
        say "  $SHIP_AWAIT_LAST_LINE"
        say "  ${SHIP_AWAIT_LAST_ADVANCES} observed advances in ${SHIP_AWAIT_LAST_ATTEMPTS} observations;"
        say "  nothing moved for the last ${SHIP_AWAIT_LAST_SILENT}s (limit ${SHIP_REMOTE_SILENCE}s)."
        rollback_rc=0
        { printf '%s\n' "$SHIP_LIB_TEXT"; cat <<'ROLLBACK_SCRIPT'
set -eu
svc_bin="$1"
rollback_window="$2"; rollback_silence="$3"
crash_samples="$4"; unknown_samples="$5"; rpc_budgets="$6"
dropin="$HOME/.config/systemd/user/zclassic23.service.d/90-build-identity.conf"
if [ -f "${svc_bin}.rollback" ]; then
    prior_sha="$(sha256sum < "${svc_bin}.rollback" | awk '{print $1}')"
    install -m 755 "${svc_bin}.rollback" "$svc_bin"
    rb_dir="$(dirname "$svc_bin")"
    for rb_w in "$rb_dir/zclassic23-package-verify" "$rb_dir/zclassic23-package-verify-dev"; do
        if [ -f "${rb_w}.ship.rollback" ]; then
            install -m 755 "${rb_w}.ship.rollback" "$rb_w"
        elif [ -f "${rb_w}.ship.absent" ]; then
            rm -f "$rb_w"
        fi
    done
    if [ -f "${dropin}.ship.rollback" ]; then
        install -m 644 "${dropin}.ship.rollback" "$dropin"
    elif [ -f "${dropin}.ship.absent" ]; then
        rm -f "$dropin"
    fi
    if ! systemctl --user daemon-reload; then
        echo "remote: CRITICAL — rollback daemon-reload failed" >&2
        exit 1
    fi
    if ! systemctl --user restart zclassic23; then
        echo "remote: CRITICAL — rollback restart request failed" >&2
        exit 1
    fi
    # Same rule as everywhere else in this file: the restored process is
    # judged by whether it is MOVING. The old 60s countdown printed
    # "CRITICAL — rollback restart did not qualify the old process" for a box
    # that was booting normally, which sends an operator looking for a fault
    # that is not there at the worst possible moment.
    #
    # There is no deploy identity to demand: the restored binary predates the
    # drop-in this ship installed, so the identity argument is empty.
    observe_restore() { ship_observe zclassic23 "$prior_sha" "" "" "$1"; }
    SHIP_AWAIT_WINDOW="$rollback_window"
    SHIP_AWAIT_SILENCE="$rollback_silence"
    SHIP_AWAIT_POLL=2
    SHIP_AWAIT_CRASH_SAMPLES="$crash_samples"
    SHIP_AWAIT_UNKNOWN_SAMPLES="$unknown_samples"
    SHIP_AWAIT_RPC_BUDGETS="$rpc_budgets"
    restore_rc=0
    ship_await "remote restore" observe_restore "$prior_sha" || restore_rc=$?
    case "$restore_rc" in
        0)
            echo "remote: rollback executable and identity restored; old process qualified"
            exit 0
            ;;
        3)
            echo "remote: rollback executable and identity restored; the restored process" \
                 "is demonstrably advancing but had not finished coming up when the" \
                 "${rollback_window}s reporting window closed. Slow, not failed."
            exit 3
            ;;
        4)
            echo "remote: CRITICAL — rollback bytes are in place but the restored process" \
                 "could not be OBSERVED at all. Unverified, not proven failed." >&2
            exit 4
            ;;
        *)
            echo "remote: CRITICAL — rollback restart did not qualify the old process;" \
                 "see the verdict and last observation above" >&2
            exit 1
            ;;
    esac
fi
echo "remote: CRITICAL — rollback executable is missing" >&2
exit 1
ROLLBACK_SCRIPT
        } | ship_remote_script "$svc_bin" \
                "$SHIP_ROLLBACK_WINDOW" "$SHIP_ROLLBACK_SILENCE" \
                "$SHIP_CRASH_SAMPLES" "$SHIP_UNKNOWN_SAMPLES" "$SHIP_RPC_BUDGETS" \
            || rollback_rc=$?
        case "$rollback_rc" in
            0) die "remote deploy failed; rollback process-qualified" ;;
            3) die "remote deploy failed; rollback restored and demonstrably booting — the
       restore's reporting window expired while the prior process was still
       advancing. The prior bytes and identity ARE back in place; this is a
       slow disk, not an unverified rollback." ;;
            *) die "remote deploy failed; CRITICAL: rollback is unverified (rc=$rollback_rc)" ;;
        esac
    fi
    say "remote ok  running sha256 ${running_sha:0:16}… (source_id ${CAND_SOURCE_ID:0:16}…) and answering status"

    # Record the pin at the one moment this script provably holds the
    # binding: the running process just proved exact candidate bytes, deploy
    # identity, and status. A failure here must not undo or fail a successful
    # deploy — report it loudly and move on.
    tools/scripts/proof_server_pin.sh record "$HEAD_SHA" "$CAND_SOURCE_ID" "$ARTIFACT_SHA" "$REMOTE_HOST" || \
        say "WARNING: could not record the proof-server pin for $HEAD_SHA / ${CAND_SOURCE_ID:0:16}… on $REMOTE_HOST — the deploy itself succeeded; re-run by hand: tools/scripts/proof_server_pin.sh record $HEAD_SHA $CAND_SOURCE_ID $ARTIFACT_SHA $REMOTE_HOST"

    # The tag above is a local convenience index. THIS is the record that
    # matters: a signed, hash-chained line appended to a TRACKED ledger, so it
    # replicates to origin on the next push of main and cannot be rewritten
    # afterwards without breaking the chain. Same failure policy as the pin —
    # a recording failure must never undo an already-successful deploy.
    #
    # It needs ZCL_RECEIPT_KEY in the environment (a key whose only job is
    # signing promotion evidence — never a login/push key) and refuses loudly
    # without one rather than reaching for a default. See "Owner setup" in
    # docs/PROMOTION_RECEIPTS.md; the chain must also have been started with
    # `promotion_receipt.sh init` before the first append can land.
    if tools/scripts/promotion_receipt.sh append "$HEAD_SHA" "$CAND_SOURCE_ID" "$ARTIFACT_SHA" "$REMOTE_HOST"; then
        say "commit deploy/promotion-receipts.jsonl — until it is committed the receipt exists on this disk only, and ship's clean-tree preflight will refuse the next run"
    else
        say "WARNING: could not append the promotion receipt for $HEAD_SHA / ${CAND_SOURCE_ID:0:16}… on $REMOTE_HOST — the deploy itself succeeded; re-run by hand: tools/scripts/promotion_receipt.sh append $HEAD_SHA $CAND_SOURCE_ID $ARTIFACT_SHA $REMOTE_HOST"
    fi
}

# The worst outcome across the fleet, carried to ship's own exit status. 3
# (still progressing) and 4 (unobservable) are NOT failures and must not stop
# the remaining targets or suppress the fleet report — a slow box is exactly
# the box whose height an operator wants to see. Only `die` stops the run.
SHIP_WORST_RC=0
note_target_rc() {
    local rc="$1"
    if [ "$rc" -gt "$SHIP_WORST_RC" ]; then SHIP_WORST_RC="$rc"; fi
    return 0
}

for target in $TARGETS; do
    case "$target" in
        local)
            local_rc=0
            deploy_local || local_rc=$?
            case "$local_rc" in
                0) ;;
                # make deploy adopted the same contract: 3 means the candidate
                # is installed and the node is still coming up. Rolling it back
                # here would undo a deploy that worked.
                3) say "local is STILL PROGRESSING — candidate installed, nothing rolled back"
                   note_target_rc 3 ;;
                *) die "local deploy failed" ;;
            esac
            ;;
        remote)
            remote_rc=0
            deploy_remote || remote_rc=$?
            note_target_rc "$remote_rc"
            ;;
    esac
done

# ── 5. Fleet report ─────────────────────────────────────────────────────────
step "Fleet"
printf '%-22s %-18s %-12s %s\n' HOST SOURCE_ID HEIGHT STATE
for target in $TARGETS; do
    case "$target" in
        local)
            s="$(timeout 20 build/bin/z23 status 2>/dev/null || true)"
            printf '%-22s %-18s %-12s %s\n' "local" "${CAND_SOURCE_ID:0:16}…" \
                "$(printf '%s' "$s" | grep -oE 'hstar=[0-9]+' | cut -d= -f2)" \
                "$(printf '%s' "$s" | grep -oE 'sync=[a-z_]+' | cut -d= -f2)" ;;
        remote)
            s="$(ssh "${SSH_OPTS[@]}" "$REMOTE_HOST" 'timeout 20 ~/bin/z23 status 2>/dev/null' || true)"
            printf '%-22s %-18s %-12s %s\n' "$REMOTE_HOST" "${CAND_SOURCE_ID:0:16}…" \
                "$(printf '%s' "$s" | grep -oE 'hstar=[0-9]+' | cut -d= -f2)" \
                "$(printf '%s' "$s" | grep -oE 'sync=[a-z_]+' | cut -d= -f2)" ;;
    esac
done
echo
if [ "$DRY_RUN" -eq 1 ]; then
    say "DRY RUN — nothing was built, installed, restarted, or pushed."
    say "plan was: $(git rev-parse --short HEAD) -> $TARGETS"
    exit 0
fi
say "shipped $(git rev-parse --short HEAD) to: $TARGETS"
case "$SHIP_WORST_RC" in
    0) ;;
    3) say "exit 3 — at least one target was STILL PROGRESSING when its reporting"
       say "  window closed. The candidate bytes are installed everywhere they were"
       say "  copied and NOTHING was rolled back. Re-run ship to re-check." ;;
    4) say "exit 4 — at least one target could not be OBSERVED. Its candidate is"
       say "  installed and nothing was rolled back; a human has to look at it." ;;
esac
exit "$SHIP_WORST_RC"
