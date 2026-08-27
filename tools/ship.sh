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
# One source of truth for the ssh options. The library is POSIX sh and cannot
# hold an array, so the STRING is canonical and the array is derived from it.
# Every option is a single word, so the library's word-splitting is exact.
SHIP_SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15"
read -r -a SSH_OPTS <<< "$SHIP_SSH_OPTS"

# ── HEALTH VERDICTS ARE NOT STOPWATCHES ─────────────────────────────────────
# Four loops in this file gated a REMOTE, DESTRUCTIVE rollback on a duration:
# 300s for a candidate to qualify, 60s for a restore. All of them demanded that
# `timeout 20 "/proc/$pid/exe" status` answer, and a box booting a large datadir
# on a 7200rpm disk misses that routinely. Ship touches a whole fleet in one
# command, so one SSD-shaped budget rolled correctly-shipped binaries off every
# slow machine at once.
#
# ship_progress_lib.sh replaces them with observed-progress verdicts read from
# /proc/<pid>/{io,stat}: bytes, CPU ticks, and delayacct_blkio_ticks — which
# climbs precisely while the process is BLOCKED on the disk and is therefore
# the one signal still alive on a box burning no CPU. A WEDGE IS SILENCE, NOT
# SLOWNESS: only proven stillness, or a process that will not stay up, may
# authorise a rollback.
#
# The absolute ceilings survive as REPORTING windows only. Exit codes:
#   0  every named target qualified
#   1  a real fault — proven wedged or would not stay up. Rolled back.
#   3  UNVERIFIED, STILL PROGRESSING — window expired on a working box.
#      NOT a failure. NOTHING was rolled back.
#   4  UNKNOWN — host unobservable (ssh down, /proc unreadable). A human
#      decides. NOTHING was rolled back.
#
# The SAME file is sourced here and shipped over the wire ahead of the remote
# scripts, because the target box has no checkout: one implementation reaches
# the same verdict on both machines.
SHIP_LIB_PATH="$REPO_ROOT/tools/scripts/ship_progress_lib.sh"
# shellcheck source=tools/scripts/ship_progress_lib.sh
. "$SHIP_LIB_PATH"  # ship_await, ship_verdict, ship_remote_sh, ship_observe
SHIP_LIB_TEXT="$(cat "$SHIP_LIB_PATH")"

# Resolved once so the local leg and both remote scripts are configured
# identically. Raising one never changes what a verdict MEANS.
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

# A release candidate may claim onion support only when the candidate itself
# reports the production Tor implementation through the native command tree.
# Keep this check ahead of every deployment function: no byte crosses a host
# boundary and no service restarts before this exact value is observed.
ship_candidate_has_real_tor() {
    local candidate="$1" out tor_build
    out="$(timeout 30 "$candidate" ops telemetry network tor 2>/dev/null)" || return 1
    [ -x "$REPO_ROOT/build/bin/jsonq" ] || return 1
    tor_build="$(printf '%s\n' "$out" |
        "$REPO_ROOT/build/bin/jsonq" get data.values.tor.tor_build 2>/dev/null)" || return 1
    [ "$tor_build" = real_tor ]
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
    test_tmp="$(mktemp -d "${TMPDIR:-/tmp}/z23-ship-selftest.XXXXXX")"
    trap 'find "$test_tmp" -depth -delete' EXIT HUP INT TERM
    printf '#!/bin/sh\nprintf '\''%%s\\n'\'' '\''{"data":{"values":{"tor":{"tor_build":"real_tor"}}}}'\''\n' > "$test_tmp/real"
    printf '#!/bin/sh\nprintf '\''%%s\\n'\'' '\''{"data":{"values":{"tor":{"tor_build":"stub_tor"}}}}'\''\n' > "$test_tmp/stub"
    chmod 755 "$test_tmp/real" "$test_tmp/stub"
    ship_candidate_has_real_tor "$test_tmp/real"
    ! ship_candidate_has_real_tor "$test_tmp/stub"
    find "$test_tmp" -depth -delete; trap - EXIT HUP INT TERM
    printf 'ship: selftest PASS (four-host order; validation; GLIBC inequality; explicit proof host; real-Tor gate)\n'
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
    if grep -Eq 'hotswap_module=|HOTSWAP MODULE' "$suite_log"; then
        grep -E 'SUITE VERDICT|HOTSWAP MODULE' "$suite_log" | head -5 >&2
        rm -f "$suite_log"
        die "full suite used a hot-swap module — linked candidate remains unproven"
    elif grep -q 'ALL TESTS PASSED' "$suite_log" && \
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
    # The source preflight above requires a clean committed checkout and the
    # build happens only after HEAD was integrated/pushed.  The binary's
    # display field may intentionally say "external" for an out-of-tree link,
    # but deployment and rollback need a resolvable full commit identity.
    DEPLOY_COMMIT="$HEAD_SHA"
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

    ship_candidate_has_real_tor "$CANDIDATE" ||
        die "candidate did not report exact tor_build=real_tor; nothing was transferred or restarted"
    say "tor        candidate reports exact real_tor"

    RELEASE_MANIFEST="$(mktemp "${TMPDIR:-/tmp}/zclassic23.ship.manifest.XXXXXX")"
    trap 'rm -f "$CANDIDATE" "$RELEASE_MANIFEST" "${WORKER_FILES[@]}"' EXIT HUP INT TERM
    {
        printf '%s  z23\n' "$ARTIFACT_SHA"
        printf '%s  %s\n' "${WORKER_SHAS[0]}" "${WORKER_NAMES[0]}"
        printf '%s  %s\n' "${WORKER_SHAS[1]}" "${WORKER_NAMES[1]}"
    } > "$RELEASE_MANIFEST"
    RELEASE_ID="$(sha256sum < "$RELEASE_MANIFEST" | awk '{print $1}')"
    zcl_is_sha256 "$RELEASE_ID" || die "could not hash the release manifest"
    say "release    manifest ${RELEASE_ID:0:16}…"

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
    local host="$1" svc_bin prev_sha prior_commit run_id release_root node_incoming release_state
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

    run_id="${RELEASE_ID:0:16}.$$"
    # A process rollback after a forward schema migration is not recovery.
    # Prove that the persistent-schema implementation is byte-equivalent
    # between the running release and this candidate before any transfer.
    prior_commit="$(ssh "${SSH_OPTS[@]}" "$host" '
        pid="$(systemctl --user show zclassic23 -p MainPID --value)" || exit 1
        tr "\0" "\n" < "/proc/$pid/environ" |
            sed -n "s/^ZCL_AGENT_EXPECT_BUILD_COMMIT=//p"' | tail -1)"
    case "$prior_commit" in
        ''|*[!0-9a-f]*) die "$host has no exact rollback build commit; refusing a schema-unsafe restart" ;;
    esac
    git cat-file -e "$prior_commit^{commit}" 2>/dev/null ||
        die "$host rollback commit $prior_commit is unavailable locally"
    if ! git diff --quiet "$prior_commit" "$HEAD_SHA" -- \
        'app/models/src/database_*.c' 'app/models/src/schema_migration.c' \
        'app/models/include/models/schema_migration.h'; then
        die "$host candidate changes persistent-schema code; automatic binary rollback is not safe"
    fi
    say "rollback   $host persistent-schema code unchanged from ${prior_commit:0:12}"

    release_root="$(ssh "${SSH_OPTS[@]}" "$host" 'printf "%s\n" "$HOME/.local/lib/z23/releases"')/$RELEASE_ID"
    node_incoming="${release_root}.incoming.$run_id"

    # Existing immutable identities are reusable only when every byte still
    # matches the locally frozen manifest. A collision or partial directory is
    # corruption, never permission to overwrite an allegedly immutable root.
    release_state="$(ssh "${SSH_OPTS[@]}" "$host" bash -s -- \
        "$release_root" "$RELEASE_ID" "$ARTIFACT_SHA" \
        "${WORKER_SHAS[0]}" "${WORKER_SHAS[1]}" <<'REMOTE_RELEASE_CHECK'
set -eu
root="$1"; manifest_sha="$2"; daemon_sha="$3"; worker_v_sha="$4"; worker_d_sha="$5"
[ -e "$root" ] || { echo missing; exit 0; }
[ -d "$root" ] || { echo "remote: immutable release root is not a directory: $root" >&2; exit 1; }
[ "$(sha256sum < "$root/MANIFEST.sha256" | awk '{print $1}')" = "$manifest_sha" ] &&
[ "$(sha256sum < "$root/z23" | awk '{print $1}')" = "$daemon_sha" ] &&
[ "$(sha256sum < "$root/zclassic23-package-verify" | awk '{print $1}')" = "$worker_v_sha" ] &&
[ "$(sha256sum < "$root/zclassic23-package-verify-dev" | awk '{print $1}')" = "$worker_d_sha" ] || {
    echo "remote: immutable release root content mismatch: $root" >&2
    exit 1
}
echo exact
REMOTE_RELEASE_CHECK
    )" || die "$host refused an existing immutable release root"

    if [ "$release_state" = missing ]; then
        ssh "${SSH_OPTS[@]}" "$host" bash -s -- "$node_incoming" <<'REMOTE_RELEASE_MKDIR'
set -eu
incoming="$1"
[ ! -e "$incoming" ] || { echo "remote: incoming release already exists: $incoming" >&2; exit 1; }
install -d -m 700 "$incoming"
REMOTE_RELEASE_MKDIR
        scp -q "${SSH_OPTS[@]}" "$CANDIDATE" "$host:$node_incoming/z23" ||
            die "could not copy the candidate to $host"
        local wi
        for wi in "${!WORKER_NAMES[@]}"; do
            scp -q "${SSH_OPTS[@]}" "${WORKER_FILES[$wi]}" \
                "$host:$node_incoming/${WORKER_NAMES[$wi]}" ||
                die "could not copy ${WORKER_NAMES[$wi]} to $host"
        done
        scp -q "${SSH_OPTS[@]}" "$RELEASE_MANIFEST" "$host:$node_incoming/MANIFEST.sha256" ||
            die "could not copy the release manifest to $host"
    else
        [ "$release_state" = exact ] || die "$host returned invalid release state '$release_state'"
        say "remote     immutable release already present and exact"
    fi

    local activate_rc=0
    { printf '%s\n' "$SHIP_LIB_TEXT"; cat <<'REMOTE_SCRIPT'
set -euo pipefail
svc_bin="$1"; release_root="$2"; manifest_sha="$3"; want_sha="$4"; want_src="$5"; want_commit="$6"
want_worker_v="$7"; want_worker_d="$8"
run_id="$9"
# Health-verdict configuration, positional because ssh forwards no environment.
# tools/scripts/ship_progress_lib.sh is prepended to this script on stdin: the
# target box has no checkout, so the code that reaches the verdict has to
# travel with the question.
remote_window="${10}"; remote_silence="${11}"
rollback_window="${12}"; rollback_silence="${13}"
crash_samples="${14}"; unknown_samples="${15}"; rpc_budgets="${16}"
# The two subjects this script judges, each wrapped to ship_await's
# one-argument observer seam. Same observables, same classifier, same words as
# the local side uses.
observe_candidate() { ship_observe zclassic23 "$want_sha" "$want_src" "$want_commit" "$1"; }
observe_restore()   { ship_observe zclassic23 "$prior_sha" "" "" "$1"; }
worker_v="$release_root/zclassic23-package-verify"
worker_d="$release_root/zclassic23-package-verify-dev"
dropin_dir="$HOME/.config/systemd/user/zclassic23.service.d"
dropin="$dropin_dir/zzzzz-z23-ship-release.conf"
rollback_dropin="${dropin}.ship.rollback.${run_id}"
dropin_absent="${dropin}.ship.absent.${run_id}"
node_incoming="${release_root}.incoming.${run_id}"
lock_dir="$HOME/.cache/z23/ship-activation.lock"
dropin_tmp=""
prior_sha=""
rollback_armed=0
lock_held=0

cleanup_backups() {
    rm -f "$rollback_dropin" "$dropin_absent"
}

restore_prior() {
    if [ -f "$rollback_dropin" ]; then
        install -m 644 "$rollback_dropin" "$dropin" || return 1
    elif [ -f "$dropin_absent" ]; then
        rm -f "$dropin" || return 1
    fi
    systemctl --user daemon-reload || return 1
    # Do not wait for Type=notify startup here: ship_await below is the
    # progress-aware authority. A synchronous restart can block for tens of
    # minutes on a spinning-disk datadir before that observer even starts.
    systemctl --user restart --no-block zclassic23 || return 1

    SHIP_AWAIT_WINDOW="$rollback_window"
    SHIP_AWAIT_SILENCE="$rollback_silence"
    SHIP_AWAIT_POLL=2
    SHIP_AWAIT_CRASH_SAMPLES="$crash_samples"
    SHIP_AWAIT_UNKNOWN_SAMPLES="$unknown_samples"
    SHIP_AWAIT_RPC_BUDGETS="$rpc_budgets"
    restore_rc=0
    ship_await "remote restore" observe_restore "$prior_sha" || restore_rc=$?
    [ "$restore_rc" -eq 0 ] || return 1
    return 0
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
    case "$node_incoming" in
        "$HOME/.local/lib/z23/releases/"*.incoming.*)
            find "$node_incoming" -depth -delete 2>/dev/null || true ;;
        *) echo "remote: refusing unsafe incoming cleanup path" >&2 ;;
    esac
    [ "$lock_held" -eq 0 ] || rmdir "$lock_dir" 2>/dev/null || true
    exit "$rc"
}
trap restore_on_failure EXIT HUP INT TERM

mkdir -p "$HOME/.cache/z23"
mkdir "$lock_dir" || { echo "remote: another ship activation holds $lock_dir" >&2; exit 1; }
lock_held=1

# Finalize a new immutable directory, or re-verify a pre-existing one. No
# installed release byte is ever overwritten, including during rollback.
if [ -d "$node_incoming" ]; then
    [ "$(sha256sum < "$node_incoming/MANIFEST.sha256" | awk '{print $1}')" = "$manifest_sha" ] &&
    [ "$(sha256sum < "$node_incoming/z23" | awk '{print $1}')" = "$want_sha" ] &&
    [ "$(sha256sum < "$node_incoming/zclassic23-package-verify" | awk '{print $1}')" = "$want_worker_v" ] &&
    [ "$(sha256sum < "$node_incoming/zclassic23-package-verify-dev" | awk '{print $1}')" = "$want_worker_d" ] || {
        echo "remote: transferred release bytes differ from manifest" >&2; exit 1;
    }
    chmod 555 "$node_incoming/z23" "$node_incoming/zclassic23-package-verify" \
        "$node_incoming/zclassic23-package-verify-dev"
    chmod 444 "$node_incoming/MANIFEST.sha256"
    chmod 555 "$node_incoming"
    mv "$node_incoming" "$release_root"
fi
[ "$(sha256sum < "$release_root/MANIFEST.sha256" | awk '{print $1}')" = "$manifest_sha" ] &&
[ "$(sha256sum < "$release_root/z23" | awk '{print $1}')" = "$want_sha" ] &&
[ "$(sha256sum < "$worker_v" | awk '{print $1}')" = "$want_worker_v" ] &&
[ "$(sha256sum < "$worker_d" | awk '{print $1}')" = "$want_worker_d" ] || {
    echo "remote: immutable release verification failed" >&2; exit 1;
}

pid="$(systemctl --user show zclassic23 -p MainPID --value)"
case "$pid" in ""|*[!0-9]*|0) echo "remote: no running MainPID" >&2; exit 1 ;; esac
prior_sha="$(sha256sum < "/proc/$pid/exe" | awk '{print $1}')"
mapfile -d '' -t prior_argv < "/proc/$pid/cmdline"
[ "${#prior_argv[@]}" -gt 0 ] || { echo "remote: running argv is unavailable" >&2; exit 1; }
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
    printf 'ExecStart=\n'
    printf 'ExecStart="%s"' "$release_root/z23"
    for ((arg_i=1; arg_i<${#prior_argv[@]}; arg_i++)); do
        arg="${prior_argv[$arg_i]}"
        case "$arg" in *$'\n'*|*$'\r'*) echo "remote: node argv contains a control line" >&2; exit 1 ;; esac
        arg="${arg//\\/\\\\}"; arg="${arg//\"/\\\"}"
        arg="${arg//%/%%}"; arg="${arg//\$/\$\$}"
        printf ' "%s"' "$arg"
    done
    printf '\n'
    printf 'Environment="ZCL_AGENT_EXPECT_SOURCE_ID=%s"\n' "$want_src"
    printf 'Environment="ZCL_AGENT_EXPECT_BUILD_COMMIT=%s"\n' "$want_commit"
    printf 'Environment="ZCL_AGENT_EXPECT_BUILD_SOURCE=ship"\n'
} > "$dropin_tmp"
install -m 644 "$dropin_tmp" "$dropin"
rm -f "$dropin_tmp"; dropin_tmp=""
systemctl --user daemon-reload
# Queue the restart and immediately enter the progress-aware observer below.
# Waiting synchronously defeats the slow-box verdict because Type=notify does
# not return until the whole cold datadir startup has completed.
systemctl --user restart --no-block zclassic23

# The rollback stays armed until the candidate proves exact bytes, the expected
# identity, and answering RPC. A successful `systemctl restart` only proves
# systemd accepted a request. But the judgement is on the SUBJECT's progress,
# never on the observer's patience: a 300s countdown convicted honest boxes
# whose disks were still replaying, and rolling those back is how a network
# quietly stops accepting slow hardware.
SHIP_AWAIT_WINDOW="$remote_window"
SHIP_AWAIT_SILENCE="$remote_silence"
SHIP_AWAIT_POLL=2
SHIP_AWAIT_CRASH_SAMPLES="$crash_samples"
SHIP_AWAIT_UNKNOWN_SAMPLES="$unknown_samples"
SHIP_AWAIT_RPC_BUDGETS="$rpc_budgets"
cand_rc=0
ship_await "remote candidate" observe_candidate "$want_sha" || cand_rc=$?
case "$cand_rc" in
    0) ;;
    3|4)
        # Not qualified, and not proven faulty either. Disarm the rollback and
        # hand the word up: only the two fault verdicts may destroy anything.
        rollback_armed=0
        trap - EXIT HUP INT TERM
        rmdir "$lock_dir"
        lock_held=0
        echo "remote: candidate is $SHIP_AWAIT_LAST_VERDICT — $SHIP_AWAIT_LAST_LINE" >&2
        exit "$cand_rc"
        ;;
    *)
        echo "remote: candidate is $SHIP_AWAIT_LAST_VERDICT — $SHIP_AWAIT_LAST_LINE" >&2
        exit 1
        ;;
esac
rollback_armed=0
trap - EXIT HUP INT TERM
rmdir "$lock_dir"
lock_held=0
echo "remote: installed, restarted, and process-qualified"
REMOTE_SCRIPT
    } | ssh "${SSH_OPTS[@]}" "$host" bash -s -- \
        "$svc_bin" "$release_root" "$RELEASE_ID" "$ARTIFACT_SHA" \
        "$CAND_SOURCE_ID" "$DEPLOY_COMMIT" \
        "${WORKER_SHAS[0]}" "${WORKER_SHAS[1]}" "$run_id" \
        "$SHIP_REMOTE_WINDOW" "$SHIP_REMOTE_SILENCE" \
        "$SHIP_ROLLBACK_WINDOW" "$SHIP_ROLLBACK_SILENCE" \
        "$SHIP_CRASH_SAMPLES" "$SHIP_UNKNOWN_SAMPLES" "$SHIP_RPC_BUDGETS" \
        || activate_rc=$?

    # The remote reached a verdict with the same classifier the local side is
    # about to use. Honour the two non-destructive words here rather than
    # re-observing: a second opinion on a box that already said "still coming
    # up" cannot turn that into a fault, and re-running the local await would
    # only spend another window before saying the same thing.
    case "$activate_rc" in
        0) ;;
        3)
            say "$host is STILL PROGRESSING — the candidate is installed and working,"
            say "  but had not finished coming up when the remote window closed."
            say "  NOTHING was rolled back. Re-run ship to re-check."
            return 3
            ;;
        4)
            say "$host is UNKNOWN — the candidate is installed but the host could not"
            say "  produce evidence. NOTHING was rolled back; a human decides."
            return 4
            ;;
        *)
            # The remote proved a fault and its own armed transaction already
            # restored the prior executable before exiting.
            die "$host: candidate failed remote qualification (rc=$activate_rc); remote rolled back"
            ;;
    esac

    # Verify the executable inode held by the RUNNING MainPID, not only the
    # pathname on disk. Exact process bytes bind the already-proven candidate
    # source id without another fallible JSON parser.
    # The verdict, not a countdown, decides whether the rollback fires. Only a
    # process proven still (WEDGED) or one that will not stay up (CRASHED) may
    # authorise it; a box that is visibly working keeps its candidate.
    local running_sha rollback_rc qual_rc=0
    SHIP_OBS_UNIT=zclassic23
    SHIP_OBS_SHA="$ARTIFACT_SHA"
    SHIP_OBS_SRC="${CAND_SOURCE_ID:-}"
    SHIP_OBS_COMMIT="${DEPLOY_COMMIT:-}"
    SHIP_REMOTE_HOST="$host"
    SHIP_AWAIT_WINDOW="$SHIP_REMOTE_WINDOW"
    SHIP_AWAIT_SILENCE="$SHIP_REMOTE_SILENCE"
    SHIP_AWAIT_POLL="${ZCL_SHIP_LOCAL_POLL_SECONDS:-10}"
    SHIP_AWAIT_CRASH_SAMPLES="$SHIP_CRASH_SAMPLES"
    SHIP_AWAIT_UNKNOWN_SAMPLES="$SHIP_UNKNOWN_SAMPLES"
    SHIP_AWAIT_RPC_BUDGETS="$SHIP_RPC_BUDGETS"
    ship_await "$host" ship_remote_observe "$ARTIFACT_SHA" || qual_rc=$?
    running_sha="$(ship_field "$SHIP_AWAIT_LAST_LINE" sha)"

    case "$qual_rc" in
        3)
            say "$host is STILL PROGRESSING — $SHIP_AWAIT_LAST_ADVANCES observed advances,"
            say "  last change ${SHIP_AWAIT_LAST_SILENT}s ago. The candidate stays installed"
            say "  and NOTHING was rolled back: a slow disk is not a failed deploy."
            return 3
            ;;
        4)
            say "$host is UNKNOWN — no evidence could be gathered for"
            say "  $SHIP_UNKNOWN_SAMPLES consecutive attempts (host unreachable, or /proc"
            say "  unreadable). An unreachable host is not a failed deploy. NOTHING was"
            say "  rolled back; a human decides."
            return 4
            ;;
    esac

    if [ "$qual_rc" -ne 0 ]; then
        say "$host is $SHIP_AWAIT_LAST_VERDICT — ROLLING BACK. Evidence:"
        say "  $SHIP_AWAIT_LAST_LINE"
        rollback_rc=0
        { printf '%s\n' "$SHIP_LIB_TEXT"; cat <<'ROLLBACK_SCRIPT'
set -eu
svc_bin="$1"
run_id="$2"
prior_sha="$3"
# Health-verdict configuration, positional because ssh forwards no environment.
# tools/scripts/ship_progress_lib.sh is prepended to this script on stdin: the
# target box has no checkout, so the code that reaches the verdict has to
# travel with the question.
rollback_window="$4"; rollback_silence="$5"
crash_samples="$6"; unknown_samples="$7"; rpc_budgets="$8"
# Wrapped to ship_await's one-argument observer seam. prior_sha is assigned
# below, before the only call.
observe_restore() { ship_observe zclassic23 "$prior_sha" "" "" "$1"; }
dropin="$HOME/.config/systemd/user/zclassic23.service.d/zzzzz-z23-ship-release.conf"
if [ -f "${dropin}.ship.rollback.${run_id}" ] || [ -f "${dropin}.ship.absent.${run_id}" ]; then
    if [ -f "${dropin}.ship.rollback.${run_id}" ]; then
        install -m 644 "${dropin}.ship.rollback.${run_id}" "$dropin"
    elif [ -f "${dropin}.ship.absent.${run_id}" ]; then
        rm -f "$dropin"
    fi
    if ! systemctl --user daemon-reload; then
        echo "remote: CRITICAL — rollback daemon-reload failed" >&2
        exit 1
    fi
    if ! systemctl --user restart --no-block zclassic23; then
        echo "remote: CRITICAL — rollback restart request failed" >&2
        exit 1
    fi
    # Same rule as everywhere else in this file: the restored process is judged
    # by whether it is MOVING, not by a countdown. The old 60s clock printed
    # "rollback is unverified" — the most alarming words this tool can say —
    # for a healthy node whose disk simply had not finished replaying yet.
    SHIP_AWAIT_WINDOW="$rollback_window"
    SHIP_AWAIT_SILENCE="$rollback_silence"
    SHIP_AWAIT_POLL=2
    SHIP_AWAIT_CRASH_SAMPLES="$crash_samples"
    SHIP_AWAIT_UNKNOWN_SAMPLES="$unknown_samples"
    SHIP_AWAIT_RPC_BUDGETS="$rpc_budgets"
    restore_rc=0
    ship_await "remote restore" observe_restore "$prior_sha" || restore_rc=$?
    if [ "$restore_rc" -eq 0 ]; then
        echo "remote: rollback executable and identity restored; old process qualified"
        exit 0
    fi
    echo "remote: rollback restart is $SHIP_AWAIT_LAST_VERDICT — $SHIP_AWAIT_LAST_LINE" >&2
    exit "$restore_rc"
fi
echo "remote: CRITICAL — rollback path selection is missing" >&2
exit 1
ROLLBACK_SCRIPT
        } | ssh "${SSH_OPTS[@]}" "$host" bash -s -- "$svc_bin" "$run_id" "$prev_sha" \
            "$SHIP_ROLLBACK_WINDOW" "$SHIP_ROLLBACK_SILENCE" \
            "$SHIP_CRASH_SAMPLES" "$SHIP_UNKNOWN_SAMPLES" "$SHIP_RPC_BUDGETS" \
            || rollback_rc=$?
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
    ssh "${SSH_OPTS[@]}" "$host" bash -s -- "$run_id" <<'REMOTE_CLEANUP' || \
        say "WARNING: $host retained the qualified run's rollback files"
set -eu
run_id="$1"
case "$run_id" in ''|*[!A-Za-z0-9.-]*) exit 2 ;; esac
dropin="$HOME/.config/systemd/user/zclassic23.service.d/zzzzz-z23-ship-release.conf"
rm -f \
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
