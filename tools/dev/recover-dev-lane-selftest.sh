#!/usr/bin/env bash
# Hermetic contract test for recover-dev-lane.sh. No real service or operator
# datadir is reachable: HOME and every service action live below one tmpdir.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
RECOVER="$SCRIPT_DIR/recover-dev-lane.sh"
SOURCE_ID="fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
SANDBOX="$(mktemp -d /tmp/zcl-dev-recovery-selftest.XXXXXX)"
chmod 700 "$SANDBOX"
CAPABILITY_FILE="$SANDBOX/.recover-dev-lane-selftest-capability"
CAPABILITY_TOKEN="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
[[ "$CAPABILITY_TOKEN" =~ ^[0-9a-f]{64}$ ]] || {
    printf '[dev-recovery-selftest] FAIL: could not mint fixture capability\n' >&2
    exit 1
}
printf '%s\n' "$CAPABILITY_TOKEN" > "$CAPABILITY_FILE"
chmod 600 "$CAPABILITY_FILE"

cleanup()
{
    rm -rf "$SANDBOX"
}
trap cleanup EXIT

fail()
{
    printf '[dev-recovery-selftest] FAIL: %s\n' "$*" >&2
    exit 1
}

make_generation()
{
    local home="$1" generation="$2" root="$home/.local/lib/zclassic23-dev"
    mkdir -p "$root/$generation" "$root/rejected"
    printf '#!/usr/bin/env bash\nexit 0\n' > "$root/$generation/zclassic23-dev"
    chmod 0555 "$root/$generation/zclassic23-dev"
    printf '{"schema":"zcl.dev_binary_generation.v1","generation":"%s",' \
        "$generation" > "$root/$generation/manifest.json"
    printf '"source_id_sha256":"%s","build_commit":"selftest"}\n' \
        "$SOURCE_ID" >> "$root/$generation/manifest.json"
    ln -sfn "$generation" "$root/current"
}

make_wedged_lane()
{
    local home="$1" generation="$2" dd="$home/.zclassic-c23-dev"
    mkdir -p "$dd" "$home/.config/systemd/user/zcl23-dev.service.d"
    printf '3175499 1\n' > "$dd/auto_reindex_request"
    printf 'old-derived-state\n' > "$dd/old-state.txt"
    # Minimal v2 ZCLUTXO header. The real loader owns body/frontier validation;
    # this hermetic test exercises recovery's pre-mutation version/height gate.
    dd if=/dev/zero of="$dd/utxo-seed-42.snapshot" bs=104 count=1 status=none
    printf '\x5a\x43\x4c\x55\x54\x58\x4f\x00\x02\x00\x00\x00' |
        dd of="$dd/utxo-seed-42.snapshot" conv=notrunc status=none
    printf '\x2a\x00\x00\x00\x00\x00\x00\x00' |
        dd of="$dd/utxo-seed-42.snapshot" bs=1 seek=16 conv=notrunc status=none
    # One legacy flat-file entry (8-byte header + 172-byte record), height 42.
    # This exercises recovery's pre-mutation snapshot/header span gate.
    dd if=/dev/zero of="$dd/block_index.bin" bs=180 count=1 status=none
    printf '\x49\x4c\x43\x5a\x01\x00\x00\x00' |
        dd of="$dd/block_index.bin" conv=notrunc status=none
    printf '\x2a\x00\x00\x00' |
        dd of="$dd/block_index.bin" bs=1 seek=72 conv=notrunc status=none
    printf '[Service]\nEnvironment="OLD_DROPIN=1"\n' > \
        "$home/.config/systemd/user/zcl23-dev.service.d/80-snapshot-loader.conf"
    printf '{"schema":"zcl.dev_rejected_generation.v1","generation":"%s","reason":"environmental timeout"}\n' \
        "$generation" > "$home/.local/lib/zclassic23-dev/rejected/$generation.json"
}

run_recovery()
{
    local home="$1" txn="$2" verify="$3" service_log="$4" generation="${5:-}"
    local active="$home/service-active" cli="$home/fake-cli" fixture_sha runner=(env)
    local args=(--apply)
    local stop_command="${RECOVERY_SELFTEST_STOP_OVERRIDE:-rm -f '$active'; printf 'stop\\n' >> '$service_log'}"
    [ -z "$generation" ] || args+=(--generation "$generation")
    printf '%s\n' "$verify" > "$home/proof-mode"
    fixture_sha="$(sha256sum "$home/.zclassic-c23-dev/utxo-seed-42.snapshot" | awk '{print $1}')"
    cat > "$cli" <<EOF
#!/usr/bin/env bash
if [ "\${1:-}" != '-datadir=$home/.zclassic-c23-dev' ] || [ "\${2:-}" != '-rpcport=18252' ]; then exit 1; fi
shift 2
case "\$#:\$*" in
  "2:dumpstate boot")
    [ "\$(cat '$home/proof-mode')" != signal ] || { touch '$home/verify-started'; sleep 2; }
    digest="$(printf '0%.0s' {1..64})" mode="\$(cat '$home/proof-mode')"
    [ "\$mode" != typed-bad ] || digest="$(printf 'f%.0s' {1..64})"
    printf '{"state":{"assisted_snapshot_load":{"complete":true,"seed_height":42,"snapshot_path":"%s/.zclassic-c23-dev/utxo-seed-42.snapshot","record_count":0,"payload_sha3":"%s","anchor_block_hash":"%s","artifact_sha256":"%s"}}}\n' "$home" "\$digest" "$(printf '0%.0s' {1..64})" "$fixture_sha" ;;
  "2:dumpstate reducer_frontier")
    [ "\$(cat '$home/proof-mode')" = hstar-stuck ] && hstar=42 || hstar=43; printf '{"state":{"hstar":%s}}\n' "\$hstar" ;;
  "1:getblockcount") printf '43\n' ;;
  "1:agent") printf '{"schema":"zcl.public_status.v3","source_id_sha256":"%s"}\n' "$SOURCE_ID" ;;
  *) exit 1 ;;
esac
EOF
    chmod 0555 "$cli"
    [ "$verify" != signal ] || runner=(exec env)
    "${runner[@]}" HOME="$home" \
    ZCL_DEV_RECOVERY_TXN_ID="$txn" \
    ZCL_DEV_RECOVERY_BUNDLE_DIR="$home/.zclassic-c23-dev" \
    ZCL_DEV_RECOVERY_MIN_PAYLOAD_BYTES=1 \
    ZCL_DEV_RECOVERY_TIMEOUT=1 \
    ZCL_DEV_RECOVERY_STOP_COMMAND="$stop_command" \
    ZCL_DEV_RECOVERY_START_COMMAND="touch '$active'; printf 'start\\n' >> '$service_log'" \
    ZCL_DEV_RECOVERY_DAEMON_RELOAD_COMMAND="printf 'reload\\n' >> '$service_log'" \
    ZCL_DEV_RECOVERY_RESET_FAILED_COMMAND="printf 'reset\\n' >> '$service_log'" \
    ZCL_DEV_RECOVERY_ACTIVE_COMMAND="test -f '$active'" \
    ZCL_DEV_RECOVERY_PID_COMMAND="printf '4242\\n'" \
    ZCL_DEV_RECOVERY_RUNNING_EXE_COMMAND="printf '%s\\n' '$home/.local/lib/zclassic23-dev/$generation/zclassic23-dev'" \
    ZCL_DEV_RECOVERY_CLI="$cli" \
    ZCL_DEV_RECOVERY_JSONQ="$REPO/build/bin/jsonq" \
    "$RECOVER" --internal-self-test "$SANDBOX" 8 "${args[@]}" \
        8< "$CAPABILITY_FILE"
}

test_public_environment_cannot_authorize_apply()
{
    local home="$SANDBOX/public-home"
    local generation="gen-2222222222222222222222222222222222222222222222222222222222222222"
    local root service_log output rc
    root="$home/.local/lib/zclassic23-dev"
    service_log="$home/service.log"
    output="$home/public-apply.out"
    make_generation "$home" "$generation"
    make_wedged_lane "$home" "$generation"
    set +e
    HOME="$home" \
    ZCL_DEV_RECOVERY_TEST_MODE=1 \
    ZCL_DEV_RECOVERY_STOP_COMMAND="touch '$service_log'" \
    "$RECOVER" --apply --generation "$generation" > "$output" 2>&1
    rc=$?
    set -e
    [ "$rc" -eq 3 ] || fail "public test-mode environment returned $rc, expected 3"
    grep -q 'dev recovery apply is contained' "$output" ||
        fail "public apply refusal omitted containment reason"
    [ ! -e "$service_log" ] || fail "public environment reached a service command"
    [ "$(readlink "$root/current")" = "$generation" ] ||
        fail "public environment changed current generation"
    [ -f "$home/.zclassic-c23-dev/auto_reindex_request" ] ||
        fail "public environment mutated the dev datadir"
}

test_internal_capability_is_fixture_bound()
{
    local home="$SANDBOX/capability-home"
    local generation="gen-3333333333333333333333333333333333333333333333333333333333333333"
    local output="$home/capability.out" rc
    make_generation "$home" "$generation"
    make_wedged_lane "$home" "$generation"
    set +e
    HOME="$home" "$RECOVER" --internal-self-test "$SANDBOX" 8 \
        --apply --generation "$generation" > "$output" 2>&1
    rc=$?
    set -e
    [ "$rc" -eq 3 ] || fail "closed recovery capability fd returned $rc"
    grep -q 'fd is not bound to sentinel' "$output" ||
        fail "closed recovery capability refusal missing"

    set +e
    HOME="$SANDBOX/not-the-fixture-home" "$RECOVER" \
        --internal-self-test "$SANDBOX" 8 --apply --generation "$generation" \
        8< "$CAPABILITY_FILE" > "$output" 2>&1
    rc=$?
    set -e
    [ "$rc" -eq 3 ] || fail "recovery capability accepted a different HOME"
    grep -q 'invalid internal self-test capability' "$output" ||
        fail "wrong-HOME recovery refusal missing"
}

test_internal_capability_rejects_command_injection()
{
    local home="$SANDBOX/injection-home"
    local generation="gen-4444444444444444444444444444444444444444444444444444444444444444"
    local service_log="$home/service.log" signal="$home/injection-reached"
    local output="$home/injection.out" rc
    make_generation "$home" "$generation"
    make_wedged_lane "$home" "$generation"
    set +e
    RECOVERY_SELFTEST_STOP_OVERRIDE="touch '$signal'" \
        run_recovery "$home" success true "$service_log" "$generation" \
        > "$output" 2>&1
    rc=$?
    set -e
    [ "$rc" -eq 3 ] || fail "recovery command injection returned $rc"
    grep -q 'ZCL_DEV_RECOVERY_STOP_COMMAND' "$output" ||
        fail "recovery command-injection refusal missing"
    [ ! -e "$signal" ] || fail "recovery capability executed injected command"
    [ "$(readlink "$home/.local/lib/zclassic23-dev/current")" = "$generation" ] ||
        fail "recovery command injection changed current generation"
}

test_success_archives_and_commits()
{
    local home="$SANDBOX/success-home" generation="gen-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    local previous="gen-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" txn="success"
    local dd archive root service_log
    dd="$home/.zclassic-c23-dev"
    archive="${dd}.recovery-archive-${txn}"
    root="$home/.local/lib/zclassic23-dev"
    service_log="$home/service.log"
    mkdir -p "$home/.zclassic-c23" "$home/.zclassic-c23-soak"
    printf 'live-untouched\n' > "$home/.zclassic-c23/sentinel"
    printf 'soak-untouched\n' > "$home/.zclassic-c23-soak/sentinel"
    make_generation "$home" "$previous"
    make_generation "$home" "$generation"
    ln -sfn "$previous" "$root/current"
    make_wedged_lane "$home" "$generation"

    run_recovery "$home" "$txn" typed-pass "$service_log" "$generation" >/dev/null ||
        fail "successful recovery transaction was rejected"

    [ -f "$archive/auto_reindex_request" ] || fail "old auto-reindex marker was not archived"
    grep -qx '3175499 1' "$archive/auto_reindex_request" || fail "archived auto-reindex marker changed"
    [ -f "$archive/old-state.txt" ] || fail "old datadir was not retained"
    [ ! -e "$dd/auto_reindex_request" ] || fail "fresh datadir inherited the auto-reindex marker"
    cmp -s "$archive/utxo-seed-42.snapshot" "$dd/utxo-seed-42.snapshot" || fail "snapshot payload changed during recovery"
    cmp -s "$archive/block_index.bin" "$dd/block_index.bin" || fail "header-index payload changed during recovery"
    [ ! -e "$dd/node.log" ] || fail "typed recovery proof unexpectedly depended on node.log"
    [ "$(readlink "$root/last-good")" = "$generation" ] || fail "proven generation was not promoted to last-good"
    [ "$(readlink "$root/current")" = "$generation" ] || fail "requested generation was not selected atomically"
    [ ! -e "$root/rejected/$generation.json" ] || fail "superseded environmental rejection remained active"
    find "$root/rejected-history" -type f -name "$generation.*.json" |
        grep -q . || fail "superseded rejection was deleted instead of archived"
    grep -q '"activation_status": "recovery_ready"' "$dd/agent-deploy.json" || fail "coherent post-recovery deploy state missing"
    grep -q "\"source_id_sha256\": \"$SOURCE_ID\"" \
        "$dd/agent-deploy.json" ||
        fail "coherent deploy state omitted source identity"
    grep -q "ZCL_AGENT_EXPECT_SOURCE_ID=$SOURCE_ID" \
        "$home/.config/systemd/user/zcl23-dev.service.d/90-build-identity.conf" ||
        fail "recovery drop-in omitted source identity"
    grep -q -- '-nolegacyimport -load-snapshot-at-own-height=' "$home/.config/systemd/user/zcl23-dev.service.d/80-snapshot-loader.conf" || fail "recovered lane can still merge legacy block coordinates"
    grep -q '"status":"committed"' "$home/.local/state/zclassic23-dev/recovery-latest.json" || fail "committed recovery verdict missing"
    grep -qx 'live-untouched' "$home/.zclassic-c23/sentinel" ||
        fail "canonical sentinel changed"
    grep -qx 'soak-untouched' "$home/.zclassic-c23-soak/sentinel" ||
        fail "soak sentinel changed"
    [ "$(tr '\n' ' ' < "$service_log")" = "stop reload reset start " ] || fail "success service actions escaped the bounded order"
}

test_failed_proof_restores_old_lane()
{
    local mode="$1" label="$2" home="$SANDBOX/fail-$2-home"
    local generation="gen-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    local previous="gen-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" txn="failure-$label"
    local dd failed root service_log
    dd="$home/.zclassic-c23-dev"
    failed="${dd}.recovery-failed-${txn}"
    root="$home/.local/lib/zclassic23-dev"
    service_log="$home/service.log"
    make_generation "$home" "$previous"
    make_generation "$home" "$generation"
    ln -sfn "$previous" "$root/current"
    make_wedged_lane "$home" "$generation"

    if run_recovery "$home" "$txn" "$mode" "$service_log" "$generation" >/dev/null 2>&1; then
        fail "failed loader/RPC proof unexpectedly committed"
    fi
    [ -f "$dd/auto_reindex_request" ] || fail "rollback did not restore old auto-reindex marker"
    [ -f "$dd/old-state.txt" ] || fail "rollback did not restore old datadir"
    [ -d "$failed" ] || fail "failed fresh datadir was deleted"
    [ -f "$failed/utxo-seed-42.snapshot" ] || fail "failed fresh evidence was not retained"
    [ -f "$root/rejected/$generation.json" ] || fail "failed proof improperly rescinded rejection"
    [ "$(readlink "$root/current")" = "$previous" ] || fail "failed proof did not restore the previous current generation"
    grep -q '"status":"rolled_back"' \
        "$home/.local/state/zclassic23-dev/recovery-latest.json" ||
        fail "rollback verdict missing"
    grep -q 'OLD_DROPIN=1' \
        "$home/.config/systemd/user/zcl23-dev.service.d/80-snapshot-loader.conf" ||
        fail "rollback did not restore original loader drop-in"
    [ "$(tr '\n' ' ' < "$service_log")" = "stop reload reset start stop reload " ] ||
        fail "failure service actions escaped the bounded order"
}

test_plan_is_read_only_and_canonical_refused()
{
    local home="$SANDBOX/plan-home" generation="gen-cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" dd archive_count
    dd="$home/.zclassic-c23-dev"
    make_generation "$home" "$generation"
    make_wedged_lane "$home" "$generation"
    HOME="$home" \
        ZCL_DEV_RECOVERY_BUNDLE_DIR="$home/.zclassic-c23-dev" \
        ZCL_DEV_RECOVERY_MIN_PAYLOAD_BYTES=1 \
        ZCL_DEV_RECOVERY_TXN_ID=plan "$RECOVER" --plan >/dev/null ||
        fail "read-only recovery plan failed"
    archive_count="$(find "$home" -maxdepth 1 -name '.zclassic-c23-dev.recovery-*' | wc -l)"
    [ "$archive_count" -eq 0 ] || fail "plan mode mutated the datadir"

    # A Git trace alone is never generation identity authority.
    printf '{"build_commit":"deadbeef"}\n' > \
        "$home/.local/lib/zclassic23-dev/$generation/manifest.json"
    if HOME="$home" \
       ZCL_DEV_RECOVERY_BUNDLE_DIR="$home/.zclassic-c23-dev" \
       ZCL_DEV_RECOVERY_MIN_PAYLOAD_BYTES=1 \
       ZCL_DEV_RECOVERY_TXN_ID=plan-no-source \
       "$RECOVER" --plan >/dev/null 2>&1; then
        fail "commit-only generation was accepted as recovery authority"
    fi
    printf '{"source_id_sha256":"%s","build_commit":"selftest"}\n' \
        "$SOURCE_ID" > \
        "$home/.local/lib/zclassic23-dev/$generation/manifest.json"

    if HOME="$home" \
       ZCL_DEV_RECOVERY_BUNDLE_DIR="$home/.zclassic-c23-dev" \
       ZCL_DEV_RECOVERY_DATADIR="$home/.zclassic-c23" \
       ZCL_DEV_RECOVERY_MIN_PAYLOAD_BYTES=1 \
       "$RECOVER" --plan >/dev/null 2>&1; then
        fail "canonical datadir override was not structurally refused"
    fi
    [ -f "$dd/auto_reindex_request" ] || fail "negative confinement test mutated dev"
}

test_signal_rolls_back_transaction()
{
    local home="$SANDBOX/signal-home"
    local generation="gen-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    local previous="gen-1111111111111111111111111111111111111111111111111111111111111111"
    local txn="signal" dd failed root service_log started pid rc=0
    dd="$home/.zclassic-c23-dev"
    failed="${dd}.recovery-failed-${txn}"
    root="$home/.local/lib/zclassic23-dev"
    service_log="$home/service.log"
    started="$home/verify-started"
    make_generation "$home" "$previous"
    make_generation "$home" "$generation"
    ln -sfn "$previous" "$root/current"
    make_wedged_lane "$home" "$generation"

    run_recovery "$home" "$txn" signal "$service_log" "$generation" >/dev/null 2>&1 &
    pid=$!
    for _ in $(seq 1 100); do
        [ -f "$started" ] && break
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.02
    done
    [ -f "$started" ] || fail "signal test never entered post-swap verification"
    kill -TERM "$pid"
    wait "$pid" || rc=$?
    [ "$rc" -eq 143 ] || fail "signal recovery exit was $rc, expected 143"
    [ -f "$dd/auto_reindex_request" ] ||
        fail "signal rollback did not restore the old datadir"
    [ -d "$failed" ] || fail "signal rollback discarded failed-fresh evidence"
    [ "$(readlink "$root/current")" = "$previous" ] ||
        fail "signal rollback did not restore the prior generation"
    grep -q '"status":"rolled_back"' \
        "$home/.local/state/zclassic23-dev/recovery-latest.json" ||
        fail "signal rollback verdict missing"
}

test_public_environment_cannot_authorize_apply
test_internal_capability_is_fixture_bound
test_internal_capability_rejects_command_injection
test_success_archives_and_commits
test_failed_proof_restores_old_lane typed-bad digest
test_failed_proof_restores_old_lane hstar-stuck hstar
test_plan_is_read_only_and_canonical_refused
test_signal_rolls_back_transaction
printf '[dev-recovery-selftest] PASS: public apply containment, fd-bound fixture authority, archive/seed/commit, proof+signal rollback, and plan purity\n'
