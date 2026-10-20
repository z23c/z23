#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Executable regression for tools/dev/commons_journey_acceptance.sh ordering.
#
# A peer-dependent wait must never run before the peers it depends on have
# been started and their connections attempted. A node with no peer cannot
# leave finding_peers and its build worker cannot admit work, so asking
# before then is waiting on work the harness itself has not done yet: the
# wait burns its whole budget and dies, every run, for a reason that has
# nothing to do with the product.
#
# This is a STATIC check of the script's control flow. It starts no nodes and
# proves no runtime behaviour: a fixture may test harness ordering, it cannot
# substitute for real acceptance.
set -euo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JOURNEY="$SELF_DIR/commons_journey_acceptance.sh"
FAIL=0

fail() { printf 'commons-journey-ordering: FAIL: %s\n' "$*" >&2; FAIL=1; }
pass() { printf 'commons-journey-ordering: ok: %s\n' "$*"; }

[ -r "$JOURNEY" ] || { fail "cannot read $JOURNEY"; exit 2; }

# The function body under test, from `cj_overlay() {` to its closing brace.
overlay="$(awk '/^cj_overlay\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
[ -n "$overlay" ] || { fail "cj_overlay() not found"; exit 2; }

# Guard the guard: a body that no longer contains the steps this reasons
# about means the check has stopped checking, not that ordering is fine.
for needle in 'dht_spawn DHT_PGID_B' 'dht_spawn DHT_PGID_A' \
              'cj_connect_authenticated'; do
    grep -qF -- "$needle" <<<"$overlay" ||
        { fail "cj_overlay no longer contains '$needle'; this selftest is blind"; exit 2; }
done

line_of() { printf '%s\n' "$overlay" | grep -nF -- "$1" | head -1 | cut -d: -f1; }

spawn_b="$(line_of 'dht_spawn DHT_PGID_B')"
spawn_a="$(line_of 'dht_spawn DHT_PGID_A')"
connect="$(line_of 'cj_connect_authenticated')"

# Every wait that can only be satisfied by a peer.
peer_dependent_waits='cj_wait_worker_admits dht_wait_sync_live dht_wait_connected'

for w in $peer_dependent_waits; do
    at="$(printf '%s\n' "$overlay" | grep -nF -- "$w" | head -1 | cut -d: -f1 || true)"
    [ -n "$at" ] || continue
    if [ "$at" -lt "$spawn_b" ] || [ "$at" -lt "$spawn_a" ]; then
        fail "$w at body line $at runs before a node is started (B=$spawn_b A=$spawn_a)"
    elif [ "$at" -lt "$connect" ]; then
        fail "$w at body line $at runs before cj_connect_authenticated ($connect)"
    else
        pass "$w waits only after both nodes are up and connected"
    fi
done

# The readiness assertion must still exist and still fail closed. Deleting it
# would "fix" the ordering by removing the check.
grep -qF 'cj_wait_worker_admits' <<<"$overlay" ||
    fail "the build-worker readiness assertion was removed, not reordered"
grep -qF 'cj_die' <<<"$overlay" ||
    fail "cj_overlay no longer fails closed on a readiness timeout"

# The shared catch-up helper must not be retargeted at node B: its other
# callers deliberately accept blocks_download for the dialing node.
if grep -q 'dht_wait_sync_live[^|]*DHT_DD_B' <<<"$overlay"; then
    fail "dht_wait_sync_live was pointed at node B; it accepts catch-up states"
fi
pass "shared catch-up helper not repurposed for the build-worker node"
for mapping in 'peer_a="$CJ_PEER_ADDR_B:$B_PORT"' \
               'peer_b="$CJ_PEER_ADDR_A:$A_PORT"' \
               '"$A_HTTPS" "$peer_a"' '"$B_HTTPS" "$peer_b"'; do
    grep -qF "$mapping" <<<"$overlay" ||
        fail "two-host overlay lost a valid static launch target: $mapping"
done
pass "two-host overlay declares both static peer targets"

# Two-host latecomer C shares the requester's IP. Preserve the native
# same-IP rule by making the bootstrap peer and later route switch explicit.
# These are control-flow assertions only; the actual two-host run must still
# prove synchronization, publisher exit, and exact survivor-only delivery.
boot_c="$(awk '/^cj_boot_c\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
survival="$(awk '/^cj_journey_publisher_disappears\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
stop_a="$(awk '/^cj_stop_publisher\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
grep -qF 'bootstrap="127.0.0.1:$A_PORT"' <<<"$boot_c" ||
    fail "two-host latecomer lost its explicit requester bootstrap"
grep -qF '"$C_HTTPS" "$bootstrap"' <<<"$boot_c" ||
    fail "latecomer spawn ignores its declared bootstrap route"
grep -qF 'intervention=latecomer-bootstrap-via-requester' <<<"$boot_c" ||
    fail "latecomer bootstrap intervention is no longer recorded"
grep -qF 'node A still answers RPC after its disappearance' <<<"$stop_a" ||
    fail "publisher exit lost its RPC-down assertion"

survival_line() { printf '%s\n' "$survival" | grep -nF -- "$1" | head -1 | cut -d: -f1; }
delegate_c="$(survival_line 'del_c="$(cj_c zcode network delegate' || true)"
empty_c="$(survival_line '    cj_require_latecomer_empty' || true)"
stop_publisher="$(survival_line '        cj_stop_publisher' || true)"
restart_c="$(survival_line 'dht_spawn DHT_PGID_C' || true)"
if [ -z "$delegate_c" ] || [ -z "$empty_c" ] || [ -z "$stop_publisher" ] || [ -z "$restart_c" ]; then
    fail "latecomer phase ordering check lost a required operation"
elif [ "$delegate_c" -ge "$empty_c" ] || [ "$empty_c" -ge "$stop_publisher" ] || [ "$stop_publisher" -ge "$restart_c" ]; then
    fail "two-host publisher must exit after delegation and before survivor redial"
else
    pass "two-host latecomer changes peer only after anchored delegation and publisher exit"
fi
grep -qF 'intervention=latecomer-restart-toward-survivor-after-requester-exit' <<<"$survival" ||
    fail "latecomer route-switch intervention is no longer recorded"
grep -qF '[ "$CJ_TWOHOST" = 1 ] || cj_stop_publisher' <<<"$survival" ||
    fail "other topologies lost their publisher-stop operation"

# A Linux executable cannot run on an arm64 Mac. The physical-host journey
# must reject that topology before allocating remote scratch or copying bytes.
setup="$(awk '/^cj_multihost_setup\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
compat="$(awk '/^cj_require_compatible_binary_host\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
[ -n "$setup" ] && [ -n "$compat" ] ||
    { fail "multi-host binary compatibility preflight missing"; exit 2; }
compat_at="$(printf '%s\n' "$setup" | grep -nF 'cj_require_compatible_binary_host "$host"' | head -1 | cut -d: -f1 || true)"
scratch_at="$(printf '%s\n' "$setup" | grep -nF 'mktemp -d /tmp/z23-mh-' | head -1 | cut -d: -f1 || true)"
ship_at="$(printf '%s\n' "$setup" | grep -nF '"$DHT_SCP"' | head -1 | cut -d: -f1 || true)"
if [ -z "$compat_at" ] || [ -z "$scratch_at" ] || [ -z "$ship_at" ] ||
   [ "$compat_at" -ge "$scratch_at" ] || [ "$compat_at" -ge "$ship_at" ]; then
    fail "binary compatibility must be checked before remote scratch and SCP"
else
    pass "binary compatibility precedes remote scratch and SCP"
fi

# Run only the extracted preflight with a fake remote uname. No SSH connection,
# remote scratch, transfer or daemon is involved in this fixture.
eval "$compat"
DHT_SSH=ssh
ssh() {
    case "$*" in
        *'uname -s') printf '%s\n' "$CJ_FIXTURE_REMOTE_OS" ;;
        *'uname -m') printf '%s\n' "$CJ_FIXTURE_REMOTE_ARCH" ;;
        *) fail "unexpected preflight command: $*"; return 1 ;;
    esac
}
cj_die() { printf '%s\n' "$*" >&2; return 1; }
host_os="$(uname -s)"; host_arch="$(uname -m)"
if [ "$host_os:$host_arch" = Darwin:arm64 ]; then
    CJ_FIXTURE_REMOTE_OS=Linux CJ_FIXTURE_REMOTE_ARCH=x86_64
else
    CJ_FIXTURE_REMOTE_OS=Darwin CJ_FIXTURE_REMOTE_ARCH=arm64
fi
if incompatible="$(cj_require_compatible_binary_host fixture-host 2>&1)"; then
    fail "incompatible host accepted this host's binary"
elif ! grep -qF 'HOST_BINARY_INCOMPATIBLE' <<<"$incompatible"; then
    fail "incompatible host lacked a named refusal: $incompatible"
else
    pass "incompatible remote binary refuses by name"
fi
CJ_FIXTURE_REMOTE_OS="$host_os" CJ_FIXTURE_REMOTE_ARCH="$host_arch"
if ! cj_require_compatible_binary_host fixture-host; then
    fail "matching host OS and architecture was refused"
else
    pass "matching remote platform passes preflight"
fi

# Fixture only: boot-session equality rejects aliases, not shared hardware.
identity_fn="$(awk '/^cj_boot_identity\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
distinct_fn="$(awk '/^cj_require_distinct_boots\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
[ -n "$identity_fn" ] && [ -n "$distinct_fn" ] || exit 2
eval "$identity_fn"
ssh() { printf '%s\n' "$identity_fixture"; return "$identity_status"; }
identity_fixture=ABCDEF01-2345-6789-ABCD-EF0123456789
identity_status=0
upper="$(cj_boot_identity alias Linux)"
identity_fixture=abcdef01-2345-6789-abcd-ef0123456789
[ "$upper" = "$(cj_boot_identity alias Darwin)" ] || fail "boot UUID case normalization differs"
for identity_fixture in '' invalid 00000000-0000-0000-0000-000000000000; do
    if cj_boot_identity alias Linux >/dev/null 2>&1; then fail "invalid boot UUID accepted"; fi
done
identity_fixture=abcdef01-2345-6789-abcd-ef0123456789
identity_status=1
if cj_boot_identity alias Darwin >/dev/null 2>&1; then fail "failed identity producer accepted plausible stdout"; fi
if cj_boot_identity alias Unknown >/dev/null 2>&1; then fail "unknown identity platform accepted"; fi
# Substitute only observations to exercise every equality pair with no SSH.
eval "$distinct_fn"
cj_boot_identity() {
    case "$1" in '') printf '%s' "$fixture_a";; b) printf '%s' "$fixture_b";; c) printf '%s' "$fixture_c";; esac
}
CJ_TWOHOST=0 CJ_MULTIHOST=1 CJ_HOST_B=b CJ_HOST_C=c DHT_SSH=ssh
fixture_a=a fixture_b=b fixture_c=c
DHT_WORK="$(mktemp -d "${TMPDIR:-/tmp}/commons-host-identity.XXXXXX")"
if ! cj_require_distinct_boots; then fail "distinct boot sessions refused"; fi
for collision in ab ac bc; do
    fixture_a=a fixture_b=b fixture_c=c
    case "$collision" in ab) fixture_b=a;; ac) fixture_c=a;; bc) fixture_c=b;; esac
    if cj_require_distinct_boots >/dev/null 2>&1; then fail "equal boot pair $collision accepted"; fi
done
# Append to proposed identity regression before its temporary-directory cleanup.
CJ_BOOT_A=inherited CJ_BOOT_B=inherited CJ_BOOT_C=inherited DHT_SSH=fixture-shim
if ! cj_require_distinct_boots; then fail "local shim refused plumbing preflight"; fi
[ -z "$CJ_BOOT_A$CJ_BOOT_B$CJ_BOOT_C" ] || fail "shim preserved inherited boot identities"
[ "$CJ_TOPOLOGY_BASIS" = plumbing_only_host_topology_unvalidated ] || fail "shim topology not downgraded"
# These assertions bind both output owners to the same preflight qualifier.
facts_fn="$(awk '/^cj_write_facts\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
grep -qF 'topology_basis        = %s' <<<"$facts_fn" || fail "facts omit topology qualifier"
grep -qF 'custom SSH plumbing only; host topology unvalidated' <<<"$facts_fn" || fail "facts omit shim limitation"
grep -qF '\"topology_basis\":\"$CJ_TOPOLOGY_BASIS\"' "$JOURNEY" || fail "JSON omits topology qualifier"
rm -r "$DHT_WORK"
identity_at="$(printf '%s\n' "$setup" | grep -nF 'cj_require_distinct_boots || return 1' | head -1 | cut -d: -f1 || true)"
if [ -z "$identity_at" ] || [ "$identity_at" -ge "$scratch_at" ] || [ "$identity_at" -ge "$ship_at" ]; then
    fail "boot identity check must precede remote scratch and shipment"
fi

# The carried-cache rebuild on host C is judged by the toolchain capsule each
# node reports, never by the cc banner. A physical three-host run had host B
# and host C print the same `cc --version` and `as --version` banners while
# their assembler bytes differed by one distribution patch, so their capsule
# roots differed; the product correctly missed every carried object and the
# old assertion demanded zero compilers anyway.
verdict_fn="$(awk '/^cj_carrier_rebuild_verdict\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$JOURNEY")"
if [ -z "$verdict_fn" ]; then
    fail "cj_carrier_rebuild_verdict() not found: the carrier rebuild has no toolchain-capsule verdict"
else
    grep -qF 'cj_carrier_rebuild_verdict "$cap_b" "$cap_c"' <<<"$survival" ||
        fail "the survival step no longer judges the carrier rebuild by toolchain capsule"
    grep -qF 'cap_b="$(cj_toolchain_capsule b)"' <<<"$survival" &&
    grep -qF 'cap_c="$(cj_toolchain_capsule c)"' <<<"$survival" ||
        fail "the survival step no longer reads each node's own toolchain capsule"
    if grep -qF 'cc --version' <<<"$survival"; then
        fail "the survival step judges toolchain identity by the cc banner"
    fi
    eval "$verdict_fn"
    cap_1=5c82d3bc9d023caaf15a93b0db74f97aa0430f0c6458ae87b5d20aea6b3fcc8a
    cap_2=b0a1234afb88c1cbfb507b3d41c0f4b4422a428de33637b272818d33ce67d732
    rc_b=0e3af17f6df1afc80000000000000000000000000000000000000000000000b0
    rc_c=7691f79bdbcc05bcd5289bac4d07bb78fdcb5bf5a95d1baf72ad56abb5f61135
    carrier_ok() {
        local want="$1" label="$2" got; shift 2
        if got="$( (cj_carrier_rebuild_verdict "$@") 2>&1)" && [ "$got" = "$want" ]; then
            pass "carrier verdict $want: $label"
        else
            fail "carrier verdict should be $want for $label, got: $got"
        fi
    }
    carrier_refused() {
        local want="$1" label="$2" got; shift 2
        if got="$( (cj_carrier_rebuild_verdict "$@") 2>&1)"; then
            fail "carrier verdict accepted $label: $got"
        elif ! grep -qF -- "$want" <<<"$got"; then
            fail "carrier verdict refused $label but not by '$want': $got"
        else
            pass "carrier verdict refuses $label by '$want'"
        fi
    }
    #            capsule_b capsule_c entries hits misses reproduced warm_id ref_id
    carrier_ok same_capsule "one capsule, every object reused, B's receipt" \
        "$cap_1" "$cap_1" 2 2 0 True "$rc_b" "$rc_b"
    carrier_ok different_capsule "the recorded physical run: no object reused" \
        "$cap_1" "$cap_2" 2 0 2 True "$rc_c" "$rc_b"
    carrier_refused "spawned compilers" "one capsule with compiler spawns" \
        "$cap_1" "$cap_1" 2 0 2 True "$rc_c" "$rc_b"
    carrier_refused "caches disagree" "one capsule with a partial hit set" \
        "$cap_1" "$cap_1" 2 1 0 True "$rc_b" "$rc_b"
    carrier_refused "different receipts" "one capsule with a different receipt" \
        "$cap_1" "$cap_1" 2 2 0 True "$rc_c" "$rc_b"
    carrier_refused CROSS_TOOLCHAIN_OBJECT_REUSED "two capsules sharing objects" \
        "$cap_1" "$cap_2" 2 2 0 True "$rc_c" "$rc_b"
    carrier_refused CROSS_TOOLCHAIN_OBJECT_REUSED "two capsules sharing one object" \
        "$cap_1" "$cap_2" 2 1 1 True "$rc_c" "$rc_b"
    carrier_refused "compiled 1 of 2" "two capsules with a unit left uncompiled" \
        "$cap_1" "$cap_2" 2 0 1 True "$rc_c" "$rc_b"
    carrier_refused RECEIPT_CAPSULE_UNBOUND "two capsules filing one receipt" \
        "$cap_1" "$cap_2" 2 0 2 True "$rc_b" "$rc_b"
    carrier_refused "did not match" "a rebuild that did not reproduce" \
        "$cap_1" "$cap_2" 2 0 2 False "$rc_c" "$rc_b"
    carrier_refused TOOLCHAIN_CAPSULE_UNREADABLE "an unread capsule" \
        "$cap_1" "" 2 0 2 True "$rc_c" "$rc_b"
    carrier_refused CARRIER_RECEIPT_UNREADABLE "an unread receipt" \
        "$cap_1" "$cap_2" 2 0 2 True "" "$rc_b"
    carrier_refused CARRIER_COUNTS_UNREADABLE "unread cache counters" \
        "$cap_1" "$cap_2" 2 -1 -1 True "$rc_c" "$rc_b"
    carrier_refused CARRIER_COUNTS_UNREADABLE "an empty carrier" \
        "$cap_1" "$cap_1" 0 0 0 True "$rc_b" "$rc_b"
fi


# ── dht_kill_group stop discipline (runtime, scaled down) ────────────────
# A graceful stop must wait out the node's shutdown budget instead of
# SIGKILLing a node that is still exiting normally; a process that ignores
# TERM is killed only after the grace, and says so loudly. Real process
# groups, no node: this proves the driver's escalation, nothing else.
LIFECYCLE="$SELF_DIR/node_lifecycle.sh"
[ -r "$LIFECYCLE" ] || { fail "cannot read $LIFECYCLE"; exit 2; }

REPO_ROOT_SELFTEST="$(cd "$SELF_DIR/../.." && pwd)"
# Lint builds these helpers before gates run; never race sibling gates by
# launching a nested build from this fixture.
for ORPH_NEED in process-group-exec arena_product_journey_c23; do
    [ -x "$REPO_ROOT_SELFTEST/build/bin/$ORPH_NEED" ] ||
        { fail "missing build/bin/$ORPH_NEED (LINT_BUILT_PREREQS did not build it); the runtime scenarios cannot run"; exit 2; }
done

# stop_case NAME CHILD_SCRIPT SIG GRACE -> sets STOP_OUT and STOP_SECS.
# CHILD_SCRIPT creates the file named by its first argument once its traps are
# installed. A signal sent earlier is lost if the process group does not exist
# yet, or takes the default action if the trap is not installed yet. STOP_SECS
# counts from readiness, so a slow start is not charged to the stop.
stop_case() {
    local name="$1" child="$2" sig="$3" grace="$4" dir
    dir="$(mktemp -d "${TMPDIR:-/tmp}/z23-stop-case.XXXXXX")"
    STOP_OUT="$(
        set +e
        # shellcheck source=/dev/null
        source "$LIFECYCLE"
        DHT_STOP_GRACE_S="$grace"; DHT_STOP_POLL_S=0.1
        "$REPO_ROOT_SELFTEST/build/bin/process-group-exec" bash -c "$child" stop-case "$dir/ready" >/dev/null 2>&1 &
        pgid=$!
        DHT_OWNED_PGIDS[$pgid]=1
        for ((i = 0; i < 300; i++)); do
            [ -e "$dir/ready" ] && break
            sleep 0.1
        done
        t1="$SECONDS"
        if [ -e "$dir/ready" ]; then
            dht_kill_group "$pgid" $sig 2>&1
        else
            # No group may exist yet, and the stop helper would then wait on
            # the child forever.
            echo "NOT-READY"
            kill -KILL "-$pgid" "$pgid" 2>/dev/null || true
        fi
        if kill -0 "-$pgid" 2>/dev/null; then
            echo "STILL-ALIVE"
            kill -KILL "-$pgid" 2>/dev/null || true
        fi
        echo "unclean-count=$DHT_UNCLEAN_STOPS"
        echo "stop-secs=$((SECONDS - t1))"
    )" || true
    STOP_SECS="$(sed -n 's/^stop-secs=//p' <<<"$STOP_OUT")"
    STOP_SECS="${STOP_SECS:-0}"
    rm -rf "$dir"
    if grep -q NOT-READY <<<"$STOP_OUT"; then
        fail "stop case $name: the child did not start within 30 s"
    fi
}

# 1: exits 2 s after TERM (inside a 6 s grace): not killed, not unclean.
stop_case slow-clean \
    'trap "sleep 2; exit 0" TERM; : > "$1"; while :; do sleep 0.1; done' "" 6
if grep -q 'unclean stop' <<<"$STOP_OUT" || grep -q STILL-ALIVE <<<"$STOP_OUT" ||
   ! grep -q 'unclean-count=0' <<<"$STOP_OUT"; then
    fail "a group that exits within the grace was reported unclean: $STOP_OUT"
elif [ "$STOP_SECS" -ge 6 ]; then
    fail "a clean exit did not return promptly (${STOP_SECS}s)"
else
    pass "a group exiting 2s after TERM is not killed"
fi

# 2: ignores TERM: killed only after the grace, with the unclean line.
stop_case ignores-term \
    'trap "" TERM; : > "$1"; while :; do sleep 0.1; done' "" 3
if ! grep -q 'unclean stop: killed after [3-9]s' <<<"$STOP_OUT" ||
   grep -q STILL-ALIVE <<<"$STOP_OUT" ||
   ! grep -q 'unclean-count=1' <<<"$STOP_OUT"; then
    fail "a TERM-ignoring group was not killed loudly after the grace: $STOP_OUT"
elif [ "$STOP_SECS" -lt 3 ]; then
    fail "the TERM-ignoring group was killed before the grace (${STOP_SECS}s)"
else
    pass "a TERM-ignoring group is killed after the grace with an unclean line"
fi

# 3: deliberate KILL is immediate, labelled, and not counted unclean.
stop_case hard-kill \
    'trap "" TERM; : > "$1"; while :; do sleep 0.1; done' KILL 60
if ! grep -q 'hard kill (deliberate)' <<<"$STOP_OUT" ||
   grep -q 'unclean stop' <<<"$STOP_OUT" ||
   grep -q STILL-ALIVE <<<"$STOP_OUT" || [ "$STOP_SECS" -ge 10 ]; then
    fail "a deliberate hard kill was not immediate and labelled: $STOP_OUT"
else
    pass "a deliberate hard kill is immediate and labelled"
fi

# ── remote orphan fixture supervision (runtime, scaled) ──────────────────
# The remote journey legs must survive the ssh session that spawned them,
# yet never outlive a dead driver. A driver killed mid-run strands its
# remote daemon holding the shared test-safe ports, and every later journey
# on that host fails at bring-up with no holder to name. A supervision lease
# bounds exactly that: the driver refreshes a lease file on the daemon's own
# host, and a launcher whose lease went stale terminates the one group it
# spawned — no PPID heuristic, no port-squatting reap, no PID-reuse window.
# This drives the real dht_spawn incantation over a local ssh shim; the
# stand-in daemon is the shipped listen-report helper holding a real
# ephemeral port. It proves harness supervision, not node behaviour.
SPAWN_FN="$(awk '/^dht_spawn\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$LIFECYCLE")"
[ -n "$SPAWN_FN" ] || { fail "dht_spawn() not found in $LIFECYCLE"; exit 2; }
grep -qF -- '--die-with-lease' <<<"$SPAWN_FN" ||
    fail "remote dht_spawn no longer arms lease supervision; this check is blind"
grep -qF 'dht_ensure_remote_lease' <<<"$SPAWN_FN" ||
    fail "remote dht_spawn lost its lease-refresher setup"
lease_at="$(grep -nF 'dht_ensure_remote_lease' <<<"$SPAWN_FN" | head -1 | cut -d: -f1 || true)"
spawn_at="$(grep -nF 'bin/process-group-exec' <<<"$SPAWN_FN" | head -1 | cut -d: -f1 || true)"
if [ -z "$lease_at" ] || [ -z "$spawn_at" ]; then
    fail "lease guard cannot locate the spawn incantation in dht_spawn"
elif [ "$lease_at" -ge "$spawn_at" ]; then
    fail "the lease refresher must start before the first supervised spawn"
else
    pass "remote spawn arms lease supervision before the daemon starts"
fi
ASSERT_FN="$(awk '/^dht_assert_port\(\) \{/{f=1} f{print} f&&/^\}/{exit}' "$LIFECYCLE")"
grep -qF 'holder unknown' <<<"$ASSERT_FN" ||
    fail "a failed remote port probe no longer reports holder uncertainty"

ORPH="$(mktemp -d /tmp/z23-orphan-selftest-XXXXXXXX)"
mkdir -p "$ORPH/bin" "$ORPH/dd" "$ORPH/work"
cp "$REPO_ROOT_SELFTEST/build/bin/process-group-exec" "$ORPH/bin/"
cp "$REPO_ROOT_SELFTEST/build/bin/arena_product_journey_c23" "$ORPH/bin/"
# Stand-in daemon: the shipped helper's listen-report mode binds a real
# ephemeral port, publishes pid+port, and holds the listener forever.
printf '#!/bin/sh\nexec "%s/arena_product_journey_c23" listen-report "%s/dd/listen.out"\n' \
    "$ORPH/bin" "$ORPH" >"$ORPH/bin/zclassic23"
chmod +x "$ORPH/bin/zclassic23"
# Local ssh shim: node_lifecycle sends every remote command as one string
# after `--`; run it on this kernel, which is exactly the remote leg's
# process shape minus the network.
cat >"$ORPH/ssh-shim" <<'SHIM'
#!/bin/sh
while [ "$#" -gt 0 ]; do
    [ "$1" = "--" ] && { shift; break; }
    shift
done
[ "$#" -eq 1 ] || { echo "ssh-shim: expected one command after --" >&2; exit 1; }
exec bash -c "$1"
SHIM
chmod +x "$ORPH/ssh-shim"
cat >"$ORPH/driver.sh" <<EOF
#!/bin/bash
set -euo pipefail
DHT_SSH='$ORPH/ssh-shim'
DHT_LEASE_STALE_S=3
DHT_LEASE_REFRESH_S=1
DHT_WORK_PARENT='$ORPH/work'
. '$LIFECYCLE'
dht_make_work orphan-selftest
dht_register_remote_node 29999 shimhost '$ORPH'
dht_spawn ORPH_PGID '$ORPH/dd' 0 29999 0 0
for ((i = 0; i < 100; i++)); do [ -s '$ORPH/dd/listen.out' ] && break; sleep 0.1; done
[ -s '$ORPH/dd/listen.out' ] || { echo 'stand-in daemon never reported' >&2; exit 3; }
echo READY
while :; do sleep 5; done
EOF

bash "$ORPH/driver.sh" >"$ORPH/driver.out" 2>"$ORPH/driver.err" &
ORPH_DRIVER=$!
ORPH_READY=0
for ((i = 0; i < 150; i++)); do
    grep -q READY "$ORPH/driver.out" 2>/dev/null && { ORPH_READY=1; break; }
    kill -0 "$ORPH_DRIVER" 2>/dev/null || break
    sleep 0.1
done
if [ "$ORPH_READY" != 1 ]; then
    fail "orphan-scenario driver never became ready: $(tail -3 "$ORPH/driver.err" 2>/dev/null | tr '\n' ' ')"
else
    read -r ORPH_FPID ORPH_PORT <"$ORPH/dd/listen.out"
    kill -0 "$ORPH_FPID" 2>/dev/null ||
        fail "stand-in daemon exited before the scenario started"
    # While the driver lives, its fixture legitimately holds the port: the
    # next run's probe must fail. This is the obstruction later runs see.
    if DHT_SSH="$ORPH/ssh-shim" bash -c "
            . '$LIFECYCLE'
            dht_register_remote_node 29999 shimhost '$ORPH'
            dht_assert_port '$ORPH_PORT' 29999" 2>/dev/null; then
        fail "a live remote fixture's held port passed the rebind probe"
    else
        pass "a live remote fixture obstructs the port probe"
    fi
    # Kill the driver exactly as a crashed harness dies: SIGKILL, no trap.
    kill -9 "$ORPH_DRIVER" 2>/dev/null
    # wait reaps the SIGKILLed job and RETURNS 137; under set -e that would
    # end the whole selftest right here — the opposite of the reap check.
    wait "$ORPH_DRIVER" 2>/dev/null || true
    ORPH_T0=$SECONDS
    while kill -0 "$ORPH_FPID" 2>/dev/null && [ $((SECONDS - ORPH_T0)) -lt 8 ]; do
        sleep 0.2
    done
    if kill -0 "$ORPH_FPID" 2>/dev/null; then
        fail "the remote fixture outlived its dead driver (no bounded reap)"
        ORPH_PGID="$(ps -o pgid= -p "$ORPH_FPID" 2>/dev/null | tr -d '[:space:]')"
        case "$ORPH_PGID" in ''|*[!0-9]*) kill "$ORPH_FPID" 2>/dev/null || true ;;
            *) kill -TERM -- "-$ORPH_PGID" 2>/dev/null || true ;;
        esac
    else
        pass "a dead driver's remote fixture is reaped within the stale window"
        if DHT_SSH="$ORPH/ssh-shim" bash -c "
                . '$LIFECYCLE'
                dht_register_remote_node 29999 shimhost '$ORPH'
                dht_assert_port '$ORPH_PORT' 29999" 2>/dev/null; then
            pass "the reaped fixture's port rebinds for the next run"
        else
            fail "the port stayed obstructed after the fixture was reaped"
        fi
    fi
fi
rm -rf "$ORPH"

# Exercise the scheduled-start transport boundary without starting a node.
# Admission can outlast readiness; the admitted node keeps its original budget.
if (
    . "$LIFECYCLE"
    DHT_WAIT=1
    DHT_REMOTE_ADMISSION_WAIT=5
    dht_node_exec() {
        [ "$7" -ge 2 ] || return 75
        [ "$7" -eq 5 ] || return 1
        sleep 2
        printf '12345\n'
    }
    [ "$(dht_remote_scheduled_pid 29999 /unused true)" = 12345 ] &&
    [ "$DHT_WAIT" -eq 1 ]
); then
    pass "scheduler admission can exceed the unchanged readiness budget"
else
    fail "scheduler admission consumed the node readiness budget"
fi
for admission_budget in 08 09; do
    if (
        . "$LIFECYCLE"
        DHT_REMOTE_ADMISSION_WAIT="$admission_budget"
        dht_node_exec() {
            [ "$7" = "${admission_budget#0}" ] || return 1
            printf '12345\n'
        }
        [ "$(dht_remote_scheduled_pid 29999 /unused true)" = 12345 ]
    ); then
        pass "scheduler admission normalizes decimal budget $admission_budget"
    else
        fail "scheduler admission retained an octal budget $admission_budget"
    fi
done
for invalid_admission in 0 3601 invalid; do
    admission_rc=0
    (
        . "$LIFECYCLE"
        DHT_REMOTE_ADMISSION_WAIT="$invalid_admission"
        dht_node_exec() { exit 99; }
        dht_remote_scheduled_pid 29999 /unused true
    ) >/dev/null 2>&1 || admission_rc=$?
    [ "$admission_rc" -eq 2 ] ||
        fail "invalid admission budget $invalid_admission reached transport or lacked refusal"
done

# Capture the actual transport command construction; start no scheduler or node.
# The source functions remain the authority for argv and lease/PID phases.
SCHEDULING="$(mktemp -d "${TMPDIR:-/tmp}/z23-journey-scheduling.XXXXXX")"
for function_name in cj_remote_admission cj_node_rpc cj_node_dir \
                     cj_pause_remote_for_local_build cj_resume_remote_after_local_build \
                     cj_local_build_native cj_scheduled_on; do
    awk -v name="$function_name" '$0 == name "() {" {f=1} f {print} f && /^}/ {exit}' \
        "$JOURNEY" >>"$SCHEDULING/functions.sh"
done
if (
    . "$LIFECYCLE" || exit 1
    . "$SCHEDULING/functions.sh" || exit 1
    dht_node_exec() {
        printf '%s\n' "$4" >"$SCHEDULING/command"
        shift 5
        printf '%s\n' "$@" >"$SCHEDULING/arguments"
        printf '12345\n'
    }
    DHT_REMOTE_ADMISSION_WAIT=5
    dht_remote_scheduled_pid 29999 '/fixture path' fixture-command 'literal argument' >/dev/null || exit 1
    ! grep -Eq -- '--exclusive|systemd-run|CPUQuota|MemoryMax|taskset' "$SCHEDULING/command" || exit 1
    grep -qF -- '"$HOME/.local/bin/devbuild" --wait --project z23' "$SCHEDULING/command" || exit 1
    printf '%s\n' '/fixture path' 5 fixture-command 'literal argument' >"$SCHEDULING/expected"
    cmp "$SCHEDULING/expected" "$SCHEDULING/arguments" || exit 1
    CJ_TWOHOST=1 CJ_MULTIHOST=0 CJ_REMOTE_BUILD_PAUSED=1 B_RPC=29999 C_RPC=29998
    CJ_RDIR_B='/fixture path' DHT_DD_B='/fixture datadir'
    CJ_RDIR_C='/fixture C path' DHT_DD_C='/fixture C datadir'
    for topology_node in two:b multi:b multi:c; do
      CJ_TWOHOST=0 CJ_MULTIHOST=1
      [ "$topology_node" != two:b ] || { CJ_TWOHOST=1; CJ_MULTIHOST=0; }
      node="${topology_node#*:}"
      CJ_REMOTE_BUILD_NODE="$node"
      dir="$(cj_node_dir "$node")"; rpc="$(cj_node_rpc "$node")"
      case "$node" in b) dd="$DHT_DD_B" ;; c) dd="$DHT_DD_C" ;; esac
      for route in cj_local_build_native cj_scheduled_on; do
        "$route" "$node" fixture-command 'literal argument' >/dev/null || exit 1
        ! grep -Eq -- '--exclusive|systemd-run|CPUQuota|MemoryMax|taskset' "$SCHEDULING/command" || exit 1
        grep -qF -- '"$HOME/.local/bin/devbuild" --wait --project z23 "$@"' "$SCHEDULING/command" || exit 1
        if [ "$route" = cj_local_build_native ]; then
            printf '%s\n' "$dir" "$dir/bin/zclassic23" \
                "-datadir=$dd" "-rpcport=$rpc" -regtest \
                fixture-command 'literal argument' >"$SCHEDULING/expected"
        else
            printf '%s\n' "$dir" fixture-command 'literal argument' \
                >"$SCHEDULING/expected"
        fi
        cmp "$SCHEDULING/expected" "$SCHEDULING/arguments" || exit 1
      done
    done
); then
    pass "actual node, package and test commands reuse ordinary host admission"
else
    fail "journey command construction reserves exclusive or nested resources"
fi

# Exercise phase state and restart routes with mocks, never a node or scheduler.
if (
    . "$SCHEDULING/functions.sh"
    CJ_TWOHOST=0 CJ_MULTIHOST=1 CJ_REMOTE_BUILD_PAUSED=0
    DHT_WORK="$SCHEDULING" DHT_PGID_A=101 DHT_PGID_B=102 DHT_PGID_C=103
    CJ_PEER_ADDR_A=a CJ_PEER_ADDR_B=b CJ_PEER_ADDR_C=c
    A_PORT=1 B_PORT=2 C_PORT=3 B_RPC=4 C_RPC=5 B_FS=6 C_FS=7 B_HTTPS=8 C_HTTPS=9
    DHT_DD_B=/b DHT_DD_C=/c
    cj_die() { printf '%s\n' "$*" >&2; return 1; }
    b_rpc() { return 1; }; c_rpc() { return 1; }
    dht_kill_group() { printf '%s\n' "$1" >"$SCHEDULING/stopped"; }
    dht_spawn() { printf -v "$1" '%s' 201; printf '%s\n' "${@:2}" >"$SCHEDULING/restart"; }
    cj_wait_rpc_or_die() { :; }; dht_wait_connected() { :; }
    cj_pause_remote_for_local_build b || exit 1
    [ -z "$DHT_PGID_B" ] && [ "$CJ_REMOTE_BUILD_NODE" = b ] || exit 1
    cj_resume_remote_after_local_build || exit 1
    [ "$(tail -1 "$SCHEDULING/restart")" = a:1 ] || exit 1
    DHT_PGID_A=""
    cj_pause_remote_for_local_build c || exit 1
    [ -z "$DHT_PGID_C" ] && [ "$CJ_REMOTE_BUILD_NODE" = c ] || exit 1
    cj_resume_remote_after_local_build || exit 1
    [ "$(tail -1 "$SCHEDULING/restart")" = b:2 ] || exit 1
    cj_pause_remote_for_local_build b || exit 1
    cj_resume_remote_after_local_build || exit 1
    [ "$(tail -1 "$SCHEDULING/restart")" = c:3 ] || exit 1
    dht_node_exec() { return 75; }
    cj_pause_remote_for_local_build c || exit 1
    if cj_scheduled_on b true; then exit 1; fi
    if cj_scheduled_on c true; then exit 1; fi
    if cj_local_build_native c true; then exit 1; fi
    if cj_pause_remote_for_local_build b; then exit 1; fi
    CJ_REMOTE_BUILD_PAUSED=0
    dht_kill_group() { return 1; }
    if cj_pause_remote_for_local_build b; then exit 1; fi
    [ -n "$DHT_PGID_B" ] && [ "$CJ_REMOTE_BUILD_PAUSED" = 0 ] || exit 1
    dht_kill_group() { printf '%s\n' "$1" >"$SCHEDULING/stopped"; }
    c_rpc() { printf 'observed\n' >"$SCHEDULING/rpc-observed"; return 0; }
    DHT_PGID_C=103
    if cj_pause_remote_for_local_build c 2>"$SCHEDULING/live-rpc-refusal"; then exit 1; fi
    grep -qxF 'remote worker still answers during offline build phase' "$SCHEDULING/live-rpc-refusal" || exit 1
    [ -f "$SCHEDULING/rpc-observed" ] && [ "$(cat "$SCHEDULING/stopped")" = 103 ] || exit 1
    [ -z "$DHT_PGID_C" ] && [ "$CJ_REMOTE_BUILD_PAUSED" = 0 ] || exit 1
    dht_node_exec() { printf 'unexpected\n' >"$SCHEDULING/unpaused-transport"; return 75; }
    for route in cj_local_build_native cj_scheduled_on; do
        if "$route" b true 2>"$SCHEDULING/unpaused-refusal"; then exit 1; fi
        grep -qF 'was not phased for this node' "$SCHEDULING/unpaused-refusal" || exit 1
        [ ! -e "$SCHEDULING/unpaused-transport" ] || exit 1
    done
    c_rpc() { return 1; }; DHT_PGID_C=103
    cj_pause_remote_for_local_build c || exit 1
    DHT_PGID_B=""
    if cj_resume_remote_after_local_build; then exit 1; fi
    CJ_REMOTE_BUILD_PAUSED=0 CJ_TWOHOST=0 CJ_MULTIHOST=0
    cj_pause_remote_for_local_build a || exit 1
    [ "$CJ_REMOTE_BUILD_PAUSED" = 0 ] || exit 1
    cj_a() { printf 'local\n'; }
    [ "$(cj_local_build_native a true)" = local ] || exit 1
); then
    pass "both remote nodes phase admission and restart toward live peers; refusals propagate"
else
    fail "remote receiver admission phase or failure handling regressed"
fi
grep -qF 'if [ "$CJ_MULTIHOST" = 1 ]; then DHT_REMOTE_DEVBUILD=1; fi' "$JOURNEY" ||
    fail "three-host nodes bypass receiving-host scheduler admission"
grep -qF 'remote scheduler mapped-image qualification requires Linux' <<<"$setup" ||
    fail "real non-Linux topology lacks an early named refusal"
rm -rf "$SCHEDULING"

[ "$FAIL" -eq 0 ] || exit 1
printf 'commons-journey-ordering: OK\n'
