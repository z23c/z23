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
#   tools/ship.sh                     # gate, build, deploy local + named hosts
#   tools/ship.sh --targets=local     # one host
#   tools/ship.sh --targets=remote
#   tools/ship.sh --dry-run           # print the plan, touch nothing
#   tools/ship.sh --skip-gate         # reuse a banked verdict for this source id
#
# Environment:
#   ZCL_SHIP_HOSTS    SSH destinations, space separated (operator-local)
#   ZCL_SHIP_REMOTE   compatibility fallback for one remote host
#   ZCL_SHIP_PROOF_SERVER
#                     optional immutable host; never inferred from remoteness
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=tools/scripts/source_identity_lib.sh
. "$REPO_ROOT/tools/scripts/source_identity_lib.sh"  # zcl_is_sha256, zcl_json_first_sha256

REMOTE_HOSTS_RAW="${ZCL_SHIP_HOSTS:-${ZCL_SHIP_REMOTE:-}}"
PROOF_SERVER="${ZCL_SHIP_PROOF_SERVER:-}"
REMOTE_HOSTS=()
DEPLOY_HOSTS=()
PROOF_SELECTED=0
declare -A HOST_GLIBC=()
SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15)
# Spawnable companions of the daemon, resolved BESIDE its executable at
# reproduce time (pkgl_worker_path). Both ship with every candidate; the
# index order here is the order the remote swap stages them.
WORKER_NAMES=(zclassic23-package-verify zclassic23-package-verify-dev)
TARGETS="local remote"
TARGETS_EXPLICIT=0
DRY_RUN=0
SKIP_GATE=0
GATE_CACHE_DIR="${HOME}/.cache/zcl-ship"

ship_valid_host() {
    case "$1" in ''|-*|*[!A-Za-z0-9._@-]*) return 1 ;; *) return 0 ;; esac
}

ship_glibc_satisfies() {
    local required="$1" available="$2"
    case "$required" in [0-9]*.[0-9]*) ;; *) return 1 ;; esac
    case "$available" in [0-9]*.[0-9]*) ;; *) return 1 ;; esac
    case "$required$available" in *[!0-9.]*) return 1 ;; esac
    [ "$(printf '%s\n%s\n' "$required" "$available" | sort -V | tail -1)" = "$available" ]
}

ship_is_proof_host() {
    [ -n "$PROOF_SERVER" ] && [ "$1" = "$PROOF_SERVER" ]
}

if [ "${1:-}" = "--selftest" ]; then
    test_fleet=(node1 node2 node3 node4)
    test_order=""
    for test_host in "${test_fleet[@]}"; do
        test_order="${test_order}${test_order:+ }$test_host"
    done
    [ "$test_order" = "node1 node2 node3 node4" ]
    ship_valid_host node1 && ship_valid_host user@node-4.example
    ! ship_valid_host '-host'
    ! ship_valid_host '-oProxyCommand=x' && ! ship_valid_host 'node;command'
    ship_glibc_satisfies 2.31 2.31
    ship_glibc_satisfies 2.31 2.35
    ship_glibc_satisfies 2.31 2.36
    ship_glibc_satisfies 2.31 2.39
    ! ship_glibc_satisfies 2.40 2.39
    PROOF_SERVER=node3
    ! ship_is_proof_host node1 && ship_is_proof_host node3
    printf 'ship: selftest PASS (four-host order; validation; GLIBC inequality; explicit proof host)\n'
    exit 0
fi

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
# ZCL_SHIP_PROOF_SERVER may identify one immutable tagged candidate and record
# evidence that the candidate stayed up. Restarting it destroys the very thing
# it exists to measure: an uptime and zero-intervention record is only worth
# something if nothing quietly resets it.
#
# Until 2026-07-29 a bare invocation could restart the host whose uninterrupted
# uptime was the evidence being measured. The proof identity is now explicit;
# ordinary remote nodes remain normal sequential rollout targets.
#
# Two different refusals on purpose, because the two mistakes are different:
#   - Bare `ship.sh`: skip only the explicitly identified proof host while
#     continuing through ordinary serving peers.
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
for target in $TARGETS; do
    case "$target" in local|remote) ;; *) die "unknown target '$target' (want: local, remote)" ;; esac
done
if [[ " $TARGETS " == *" remote "* ]]; then
    [ -n "$REMOTE_HOSTS_RAW" ] || die "remote target needs ZCL_SHIP_HOSTS='host1 host2'"
    read -r -a REMOTE_HOSTS <<< "$REMOTE_HOSTS_RAW"
    for host in "${REMOTE_HOSTS[@]}"; do
        ship_valid_host "$host" || die "invalid SSH host '$host'"
        for seen in "${DEPLOY_HOSTS[@]}"; do
            [ "$seen" != "$host" ] || die "duplicate SSH host '$host'"
        done
        if ship_is_proof_host "$host" && \
           [ "${ZCL_SHIP_ALLOW_PROOF_SERVER:-0}" != "1" ]; then
            if [ "$TARGETS_EXPLICIT" -eq 1 ]; then
                die "$host is the immutable proof server; promote deliberately with ZCL_SHIP_ALLOW_PROOF_SERVER=1"
            fi
            say "skipping $host — it is the explicitly named immutable proof server"
            continue
        fi
        DEPLOY_HOSTS+=("$host")
        ship_is_proof_host "$host" && PROOF_SELECTED=1
    done
    if [ "$PROOF_SELECTED" -eq 1 ] && [ "${ZCL_SHIP_ALLOW_PROOF_SERVER:-0}" = "1" ]; then
        say "ZCL_SHIP_ALLOW_PROOF_SERVER=1 — $PROOF_SERVER may be restarted"
    fi
fi

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
for host in "${DEPLOY_HOSTS[@]}"; do
    ssh "${SSH_OPTS[@]}" "$host" true 2>/dev/null || \
        die "remote $host is unreachable over ssh"
    # libc version via awk, NOT `... | head -1 | grep ...`. head closes the pipe
    # after one line, ldd takes SIGPIPE, and `set -o pipefail` turns that into a
    # 141 exit that kills this script before a single host is touched. It is a
    # RACE — it survives only when ldd's whole output lands in one write, which
    # is why ship worked on 2026-07-27 and died here on 2026-07-28. awk consumes
    # the stream to EOF, so there is no early close and no signal.
    remote_facts="$(ssh "${SSH_OPTS[@]}" "$host" '
        flags="$(awk -F: '\''/^flags[[:space:]]*:/ { print " " $2 " "; exit }'\'' /proc/cpuinfo)"
        missing=""
        for flag in cx16 lahf_lm popcnt pni ssse3 sse4_1 sse4_2 \
                    avx avx2 bmi1 bmi2 f16c fma abm movbe xsave; do
            case "$flags" in *" $flag "*) ;; *) missing="${missing}${missing:+,}$flag" ;; esac
        done
        printf "%s|%s|%s\n" "$(uname -m)" "$missing" \
             "$(ldd --version 2>/dev/null | awk "NR==1 && match(\$0, /[0-9]+\.[0-9]+\$/) { print substr(\$0, RSTART, RLENGTH) }")"')"
    r_arch="${remote_facts%%|*}"; rest="${remote_facts#*|}"
    r_missing="${rest%%|*}"; r_libc="${rest##*|}"
    l_arch="$(uname -m)"
    [ "$r_arch" = "$l_arch" ] || \
        die "remote arch $r_arch != local $l_arch — cannot ship one binary to both"
    [ -z "$r_missing" ] || \
        die "$host lacks x86-64-v3 CPU flags: $r_missing"
    case "$r_libc" in [0-9]*.[0-9]*) ;; *) die "$host returned no parseable glibc version" ;; esac
    HOST_GLIBC["$host"]="$r_libc"
    say "remote     $host  $r_arch  glibc $r_libc  x86-64-v3 ok"
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

    CAND_MAX_GLIBC="$(objdump -T "$CANDIDATE" 2>/dev/null |
        grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sort -V | tail -1 || true)"
    case "$CAND_MAX_GLIBC" in GLIBC_[0-9]*.[0-9]*) ;; *) die "candidate has no parseable GLIBC requirement" ;; esac
    cand_glibc="${CAND_MAX_GLIBC#GLIBC_}"
    # Qualify the complete fleet before the first restart. Runtime libc may be
    # newer than the candidate's maximum required symbol; exact host/build
    # version equality is neither necessary nor a portability proof.
    for host in "${DEPLOY_HOSTS[@]}"; do
        host_glibc="${HOST_GLIBC[$host]}"
        ship_glibc_satisfies "$cand_glibc" "$host_glibc" || \
            die "$host glibc $host_glibc cannot satisfy candidate $CAND_MAX_GLIBC"
        say "abi        $host glibc $host_glibc >= required $cand_glibc"
    done
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
    if [ "$DRY_RUN" -eq 1 ]; then say "would install the frozen candidate + workers transactionally"; return 0; fi
    local pid svc_dir worker_backup i rc=0
    pid="$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)"
    case "$pid" in
        ""|*[!0-9]*|0) die "local canonical service must be running before ship" ;;
    esac
    svc_dir="$(dirname "$(readlink -f "/proc/$pid/exe")")"
    worker_backup="$(mktemp -d "${TMPDIR:-/tmp}/z23-ship-local-workers.XXXXXX")"
    for i in "${!WORKER_NAMES[@]}"; do
        if [ -f "$svc_dir/${WORKER_NAMES[$i]}" ]; then
            install -m 755 "$svc_dir/${WORKER_NAMES[$i]}" "$worker_backup/$i"
        else
            : > "$worker_backup/$i.absent"
        fi
    done
    install_local_workers "$svc_dir"
    ZCL_DEPLOY_ALLOW_CANONICAL=1 \
    ZCL_DEPLOY_FROZEN_CANDIDATE="$CANDIDATE" \
        make deploy 2>&1 | tail -6 || rc="${PIPESTATUS[0]}"
    if [ "$rc" -ne 0 ]; then
        for i in "${!WORKER_NAMES[@]}"; do
            if [ -f "$worker_backup/$i" ]; then
                install -m 755 "$worker_backup/$i" "$svc_dir/${WORKER_NAMES[$i]}"
            else
                rm -f "$svc_dir/${WORKER_NAMES[$i]}"
            fi
        done
    fi
    find "$worker_backup" -depth -delete
    return "$rc"
}

deploy_remote() {
    local host="$1" svc_bin prev_sha run_id node_incoming
    step "Deploy → $host"
    svc_bin="$(ssh "${SSH_OPTS[@]}" "$host" \
        'set -eu
         pid="$(systemctl --user show zclassic23 -p MainPID --value)"
         case "$pid" in ""|*[!0-9]*|0) exit 1 ;; esac
         readlink -f "/proc/$pid/exe"')"
    case "$svc_bin" in
        /*) ;;
        *) die "remote running executable path is missing or not absolute: '$svc_bin'" ;;
    esac
    case "$svc_bin" in /*[!A-Za-z0-9_./-]*|*..*) die "$host returned unsafe executable path: '$svc_bin'" ;; esac
    say "remote bin $svc_bin"
    if [ "$DRY_RUN" -eq 1 ]; then say "would install candidate + workers + restart + verify"; return 0; fi

    prev_sha="$(ssh "${SSH_OPTS[@]}" "$host" bash -s -- "$svc_bin" <<'REMOTE_HASH'
set -eu
sha256sum < "$1" | awk '{print $1}'
REMOTE_HASH
    )" || prev_sha=none
    say "remote now sha256 ${prev_sha:0:16}…"

    run_id="${ARTIFACT_SHA:0:16}.$$"
    node_incoming="${svc_bin}.incoming.$run_id"

    # Stage beside the target, keep the outgoing binary as the rollback copy,
    # then swap. The running process holds its inode open, so replacing the
    # path never disturbs the daemon still serving from the old bytes.
    scp -q "${SSH_OPTS[@]}" "$CANDIDATE" "$host:$node_incoming" || \
        die "could not copy the candidate to $host"

    # Stage the workers beside the same executable: pkgl_worker_path resolves
    # them there, so that directory is the only location where worker bytes
    # matter at reproduce time.
    local wi
    for wi in "${!WORKER_NAMES[@]}"; do
        scp -q "${SSH_OPTS[@]}" "${WORKER_FILES[$wi]}" \
            "$host:${svc_bin%/*}/${WORKER_NAMES[$wi]}.incoming.$run_id" || \
            die "could not copy ${WORKER_NAMES[$wi]} to $host"
    done

    ssh "${SSH_OPTS[@]}" "$host" bash -s -- \
        "$svc_bin" "$ARTIFACT_SHA" "$CAND_SOURCE_ID" "$CAND_BUILD_COMMIT" \
        "${WORKER_SHAS[0]}" "${WORKER_SHAS[1]}" "$run_id" <<'REMOTE_SCRIPT'
set -euo pipefail
svc_bin="$1"; want_sha="$2"; want_src="$3"; want_commit="$4"
want_worker_v="$5"; want_worker_d="$6"
run_id="$7"
worker_dir="$(dirname "$svc_bin")"
worker_v="$worker_dir/zclassic23-package-verify"
worker_d="$worker_dir/zclassic23-package-verify-dev"
dropin_dir="$HOME/.config/systemd/user/zclassic23.service.d"
dropin="$dropin_dir/90-build-identity.conf"
rollback_bin="${svc_bin}.rollback.${run_id}"
rollback_dropin="${dropin}.ship.rollback.${run_id}"
dropin_absent="${dropin}.ship.absent.${run_id}"
node_incoming="${svc_bin}.incoming.${run_id}"
lock_dir="$HOME/.cache/z23/ship-activation.lock"
dropin_tmp=""
prior_sha=""
rollback_armed=0
lock_held=0

# Workers stage beside the service binary. Both outgoing files are snapshotted
# before either swap, using the same present/absent marker convention as the
# drop-in, so a second-worker failure restores the complete prior set.
stage_worker() {
    w_dst="$1"; w_sha="$2"
    w_incoming="${w_dst}.incoming.${run_id}"
    w_got="$(sha256sum < "$w_incoming" | awk '{print $1}')"
    [ "$w_got" = "$w_sha" ] || \
        { echo "remote: transferred worker bytes differ from candidate: $w_dst" >&2; exit 1; }
    chmod 755 "$w_incoming"
    mv -f "$w_incoming" "$w_dst"
}

snapshot_worker() {
    w_dst="$1"
    if [ -f "$w_dst" ]; then
        install -m 755 "$w_dst" "${w_dst}.ship.rollback.${run_id}"
        rm -f "${w_dst}.ship.absent.${run_id}"
    else
        : > "${w_dst}.ship.absent.${run_id}"
        rm -f "${w_dst}.ship.rollback.${run_id}"
    fi
}

restore_worker() {
    r_dst="$1"
    if [ -f "${r_dst}.ship.rollback.${run_id}" ]; then
        install -m 755 "${r_dst}.ship.rollback.${run_id}" "$r_dst" || return 1
    elif [ -f "${r_dst}.ship.absent.${run_id}" ]; then
        rm -f "$r_dst" || return 1
    fi
}

cleanup_backups() {
    rm -f "$rollback_bin" "$rollback_dropin" "$dropin_absent" \
        "${worker_v}.ship.rollback.${run_id}" "${worker_v}.ship.absent.${run_id}" \
        "${worker_d}.ship.rollback.${run_id}" "${worker_d}.ship.absent.${run_id}"
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

    restore_deadline=$(( $(date +%s) + ${ZCL_SHIP_ROLLBACK_HEALTH_SECONDS:-60} ))
    while [ "$(date +%s)" -lt "$restore_deadline" ]; do
        restore_pid="$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)"
        case "$restore_pid" in
            ""|*[!0-9]*|0) ;;
            *)
                restore_sha="$(sha256sum < "/proc/$restore_pid/exe" 2>/dev/null | awk '{print $1}' || true)"
                if [ "$restore_sha" = "$prior_sha" ] && \
                   timeout 20 "/proc/$restore_pid/exe" status >/dev/null 2>&1; then
                    return 0
                fi
                ;;
        esac
        sleep 2
    done
    return 1
}

restore_on_failure() {
    rc=$?
    trap - EXIT HUP INT TERM
    if [ "$rollback_armed" -eq 1 ]; then
        echo "remote: activation failed; restoring prior executable and identity" >&2
        if restore_prior; then
            cleanup_backups
            echo "remote: rollback process-qualified"
        else
            echo "remote: CRITICAL — rollback could not be process-qualified" >&2
            rc=70
        fi
    fi
    [ -z "$dropin_tmp" ] || rm -f "$dropin_tmp"
    rm -f "$node_incoming" "${worker_v}.incoming.${run_id}" "${worker_d}.incoming.${run_id}"
    [ "$lock_held" -eq 0 ] || rmdir "$lock_dir" 2>/dev/null || true
    exit "$rc"
}
trap restore_on_failure EXIT HUP INT TERM

mkdir -p "$HOME/.cache/z23"
mkdir "$lock_dir" || { echo "remote: another ship activation holds $lock_dir" >&2; exit 1; }
lock_held=1

got="$(sha256sum < "$node_incoming" | awk '{print $1}')"
[ "$got" = "$want_sha" ] || { echo "remote: transferred bytes differ from candidate" >&2; exit 1; }
chmod 755 "$node_incoming"

# Workers swap BEFORE the daemon. If a worker stage fails, the host still has
# its old daemon and old workers — a consistent pair. Once the daemon swap
# begins, restore_prior (armed below) undoes workers and binary together. The
# brief old-daemon-spawns-new-worker window is the safe direction: worker
# flags are only ever added, so the newer worker accepts the older CLI.
# The transferred SHA-256 is the source binding. The local preflight already
# asked these exact bytes for their baked source id; re-parsing the same large
# JSON through a remote grep|head pipeline added no authority and could fail
# with SIGPIPE after extracting the right value.
pid="$(systemctl --user show zclassic23 -p MainPID --value)"
case "$pid" in ""|*[!0-9]*|0) echo "remote: no running MainPID" >&2; exit 1 ;; esac
install -m 755 "/proc/$pid/exe" "$rollback_bin"
prior_sha="$(sha256sum < "$rollback_bin" | awk '{print $1}')"
snapshot_worker "$worker_v"
snapshot_worker "$worker_d"
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
stage_worker "$worker_v" "$want_worker_v"
stage_worker "$worker_d" "$want_worker_d"
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
mv -f "$node_incoming" "$svc_bin"
systemctl --user restart zclassic23

# Keep the rollback transaction armed until the new process proves both exact
# bytes and useful RPC behavior. A successful `systemctl restart` only proves
# that systemd accepted a request; it does not prove the daemon stayed alive.
deadline=$(( $(date +%s) + ${ZCL_SHIP_REMOTE_HEALTH_SECONDS:-300} ))
healthy=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    new_pid="$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)"
    case "$new_pid" in
        ""|*[!0-9]*|0) ;;
        *)
            running_sha="$(sha256sum < "/proc/$new_pid/exe" 2>/dev/null | awk '{print $1}' || true)"
            identity_ok="$(tr '\000' '\n' < "/proc/$new_pid/environ" 2>/dev/null |
                awk -v src="ZCL_AGENT_EXPECT_SOURCE_ID=$want_src" \
                    -v commit="ZCL_AGENT_EXPECT_BUILD_COMMIT=$want_commit" \
                    -v origin="ZCL_AGENT_EXPECT_BUILD_SOURCE=ship" '
                        $0 == src { have_src=1 }
                        $0 == commit { have_commit=1 }
                        $0 == origin { have_origin=1 }
                        END { if (have_src && have_commit && have_origin) print "yes" }
                    ' || true)"
            if [ "$running_sha" = "$want_sha" ] && \
               [ "$identity_ok" = yes ] && \
               timeout 20 "/proc/$new_pid/exe" status >/dev/null 2>&1; then
                healthy=1
                break
            fi
            ;;
    esac
    sleep 2
done
[ "$healthy" -eq 1 ] || { echo "remote: candidate failed process-byte/identity/RPC qualification" >&2; exit 1; }
rollback_armed=0
trap - EXIT HUP INT TERM
rmdir "$lock_dir"
lock_held=0
echo "remote: installed, restarted, and process-qualified"
REMOTE_SCRIPT

    # Verify the executable inode held by the RUNNING MainPID, not only the
    # pathname on disk. Exact process bytes bind the already-proven candidate
    # source id without another fallible JSON parser.
    local deadline running_sha rollback_rc ok=0
    deadline=$(( $(date +%s) + 300 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        running_sha="$(ssh "${SSH_OPTS[@]}" "$host" \
            'set -eu
             pid="$(systemctl --user show zclassic23 -p MainPID --value)"
             case "$pid" in ""|*[!0-9]*|0) exit 1 ;; esac
             timeout 20 "/proc/$pid/exe" status >/dev/null 2>&1
             sha256sum < "/proc/$pid/exe" | awk '\''{print $1}'\''' \
            2>/dev/null || true)"
        if [ "$running_sha" = "$ARTIFACT_SHA" ]; then
            ok=1; break
        fi
        sleep 10
    done

    if [ "$ok" -ne 1 ]; then
        say "remote did not come back healthy — ROLLING BACK"
        rollback_rc=0
        ssh "${SSH_OPTS[@]}" "$host" bash -s -- "$svc_bin" "$run_id" <<'ROLLBACK_SCRIPT' || rollback_rc=$?
set -eu
svc_bin="$1"
run_id="$2"
dropin="$HOME/.config/systemd/user/zclassic23.service.d/90-build-identity.conf"
if [ -f "${svc_bin}.rollback.${run_id}" ]; then
    prior_sha="$(sha256sum < "${svc_bin}.rollback.${run_id}" | awk '{print $1}')"
    install -m 755 "${svc_bin}.rollback.${run_id}" "$svc_bin"
    rb_dir="$(dirname "$svc_bin")"
    for rb_w in "$rb_dir/zclassic23-package-verify" "$rb_dir/zclassic23-package-verify-dev"; do
        if [ -f "${rb_w}.ship.rollback.${run_id}" ]; then
            install -m 755 "${rb_w}.ship.rollback.${run_id}" "$rb_w"
        elif [ -f "${rb_w}.ship.absent.${run_id}" ]; then
            rm -f "$rb_w"
        fi
    done
    if [ -f "${dropin}.ship.rollback.${run_id}" ]; then
        install -m 644 "${dropin}.ship.rollback.${run_id}" "$dropin"
    elif [ -f "${dropin}.ship.absent.${run_id}" ]; then
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
    deadline=$(( $(date +%s) + ${ZCL_SHIP_ROLLBACK_HEALTH_SECONDS:-60} ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        pid="$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)"
        case "$pid" in
            ""|*[!0-9]*|0) ;;
            *)
                running_sha="$(sha256sum < "/proc/$pid/exe" 2>/dev/null | awk '{print $1}' || true)"
                if [ "$running_sha" = "$prior_sha" ] && \
                   timeout 20 "/proc/$pid/exe" status >/dev/null 2>&1; then
                    echo "remote: rollback executable and identity restored; old process qualified"
                    exit 0
                fi
                ;;
        esac
        sleep 2
    done
    echo "remote: CRITICAL — rollback restart did not qualify the old process" >&2
    exit 1
fi
echo "remote: CRITICAL — rollback executable is missing" >&2
exit 1
ROLLBACK_SCRIPT
        if [ "$rollback_rc" -eq 0 ]; then
            die "remote deploy failed; rollback process-qualified"
        fi
        die "remote deploy failed; CRITICAL: rollback is unverified (ssh rc=$rollback_rc)"
    fi
    say "remote ok  running sha256 ${running_sha:0:16}… (source_id ${CAND_SOURCE_ID:0:16}…) and answering status"

    # Record the pin at the one moment this script provably holds the
    # binding: the running process just proved exact candidate bytes, deploy
    # identity, and status. A failure here must not undo or fail a successful
    # deploy — report it loudly and move on.
    if ship_is_proof_host "$host"; then
        tools/scripts/proof_server_pin.sh record "$HEAD_SHA" "$CAND_SOURCE_ID" "$ARTIFACT_SHA" "$host" || \
            say "WARNING: could not record the proof-server pin for $host"

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
        if tools/scripts/promotion_receipt.sh append "$HEAD_SHA" "$CAND_SOURCE_ID" "$ARTIFACT_SHA" "$host"; then
            say "commit deploy/promotion-receipts.jsonl — until committed the receipt is local only"
        else
            say "WARNING: could not append the promotion receipt for $host"
        fi
    fi

    # Qualification and any proof recording are complete; the run-addressed
    # rollback set is no longer an authority and must not accumulate forever.
    ssh "${SSH_OPTS[@]}" "$host" bash -s -- "$svc_bin" "$run_id" <<'REMOTE_CLEANUP' || \
        say "WARNING: $host retained the qualified run's rollback files"
set -eu
svc_bin="$1"; run_id="$2"
case "$run_id" in ''|*[!A-Za-z0-9.-]*) exit 2 ;; esac
dropin="$HOME/.config/systemd/user/zclassic23.service.d/90-build-identity.conf"
dir="$(dirname "$svc_bin")"
rm -f "${svc_bin}.rollback.${run_id}" \
    "$dir/zclassic23-package-verify.ship.rollback.${run_id}" \
    "$dir/zclassic23-package-verify.ship.absent.${run_id}" \
    "$dir/zclassic23-package-verify-dev.ship.rollback.${run_id}" \
    "$dir/zclassic23-package-verify-dev.ship.absent.${run_id}" \
    "${dropin}.ship.rollback.${run_id}" "${dropin}.ship.absent.${run_id}"
REMOTE_CLEANUP
}

for target in $TARGETS; do
    case "$target" in
        local)  deploy_local  || die "local deploy failed" ;;
        remote)
            for host in "${DEPLOY_HOSTS[@]}"; do
                deploy_remote "$host"
            done
            ;;
    esac
done

# ── 5. Fleet report ─────────────────────────────────────────────────────────
step "Fleet"
printf '%-22s %-18s %-12s %s\n' HOST SOURCE_ID HEIGHT STATE
for target in $TARGETS; do
    case "$target" in
        local)
            pid="$(systemctl --user show zclassic23 -p MainPID --value 2>/dev/null || true)"
            s="$(timeout 20 "/proc/$pid/exe" status 2>/dev/null || true)"
            printf '%-22s %-18s %-12s %s\n' "local" "${CAND_SOURCE_ID:0:16}…" \
                "$(printf '%s' "$s" | grep -oE 'hstar=[0-9]+' | cut -d= -f2)" \
                "$(printf '%s' "$s" | grep -oE 'sync=[a-z_]+' | cut -d= -f2)" ;;
        remote)
            for host in "${DEPLOY_HOSTS[@]}"; do
                s="$(ssh "${SSH_OPTS[@]}" "$host" '
                    pid="$(systemctl --user show zclassic23 -p MainPID --value)"
                    case "$pid" in ""|*[!0-9]*|0) exit 1 ;; esac
                    timeout 20 "/proc/$pid/exe" status 2>/dev/null' || true)"
                printf '%-22s %-18s %-12s %s\n' "$host" "${CAND_SOURCE_ID:0:16}…" \
                    "$(printf '%s' "$s" | grep -oE 'hstar=[0-9]+' | cut -d= -f2)" \
                    "$(printf '%s' "$s" | grep -oE 'sync=[a-z_]+' | cut -d= -f2)"
            done ;;
    esac
done
echo
if [ "$DRY_RUN" -eq 1 ]; then
    say "DRY RUN — nothing was built, installed, restarted, or pushed."
    say "plan was: $(git rev-parse --short HEAD) -> targets=$TARGETS hosts=${DEPLOY_HOSTS[*]:-none}"
else
    say "shipped $(git rev-parse --short HEAD) to targets=$TARGETS hosts=${DEPLOY_HOSTS[*]:-none}"
fi
