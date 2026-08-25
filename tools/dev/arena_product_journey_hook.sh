#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: One identity-preserving accepted zdogace change through Commons/Arena.

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
    echo "arena-product-journey: run make arena-product-journey" >&2
    exit 2
fi

apj_die() { dht_die "arena-product-journey: $*"; }
apj_note() { dht_note "arena-product-journey: $*"; }
apj_jget() {
    "$DHT_ACCEPTANCE_C23" json-get "$@"
}
apj_ok() {
    local label="$1" document="$2"
    [ "$(printf '%s' "$document" | apj_jget ok False 2>/dev/null || true)" = True ] ||
        apj_die "$label failed: $document"
}
apj_native() {
    local role="$1"; shift
    dht_native "${DDS[$role]}" "${RPCS[$role]}" -regtest "$@"
}
apj_assert_installed_node() {
    local role="$1" exe cwd installed
    exe="$(readlink -f "/proc/${PIDS[$role]}/exe" 2>/dev/null || true)"
    cwd="$(readlink -f "/proc/${PIDS[$role]}/cwd" 2>/dev/null || true)"
    # Resolved on BOTH sides. The installed product ships `z23` as the real
    # file with `zclassic23` beside it as a compatibility symlink, so
    # /proc/<pid>/exe resolves to .../bin/z23 whichever name started the
    # node. Comparing that against the unresolved symlink path failed on a
    # correctly installed product — the wrong answer to the question this
    # asks, which is whether the process IS the installed binary, not which
    # of its two names was typed.
    installed="$(readlink -f "$C23_BETA_INSTALL_BIN/zclassic23" 2>/dev/null || true)"
    [ -n "$installed" ] && [ "$exe" = "$installed" ] ||
        apj_die "role $role is not running the installed node: $exe (want $installed)"
    case "$cwd" in
        "$C23_BETA_FIXTURE_SOURCE"|"$C23_BETA_FIXTURE_SOURCE"/*)
            apj_die "role $role inherited the repository working directory" ;;
    esac
}
apj_restart() {
    local role="$1" connect_role="${2:-}" pos=-1 i
    local connects=()
    for i in 0 1 2 3 4 5 6; do
        [ "${ORDER[$i]}" = "$role" ] && pos="$i"
    done
    [ "$pos" -ge 0 ] || apj_die "role $role is absent from sparse order"
    dht_kill_group "${PIDS[$role]:-}"; PIDS[$role]=""
    if [ -n "$connect_role" ]; then
        connects=("127.0.0.1:${PORTS[$connect_role]}")
    elif [ "$pos" -eq 0 ]; then
        connects=("127.0.0.1:${PORTS[${ORDER[1]}]}")
    else
        connects=("127.0.0.1:${PORTS[${ORDER[$((pos - 1))]}]}")
    fi
    dht_spawn "PIDS[$role]" "${DDS[$role]}" "${PORTS[$role]}" \
        "${RPCS[$role]}" "${FSPORTS[$role]}" \
        "${HTTPSPORTS[$role]}" "${connects[@]}"
    dht_wait_rpc "${DDS[$role]}" "${RPCS[$role]}" "${PIDS[$role]}" ||
        apj_die "role $role did not restart"
    dht_wait_auth "${DDS[$role]}" "${RPCS[$role]}" 1 ||
        apj_die "role $role did not reauthenticate"
    apj_assert_installed_node "$role"
}
apj_allow_policy() {
    local role="$1" namespace="$2" common plan token commit code message
    common='"operation":"add","source":"local","effect":"allow","scope":"service_type","action_mask":63,"value":"'"$namespace"'"'
    plan="$(apj_native "$role" zcode network policy mutate \
        --input="{\"mode\":\"plan\",$common}" || true)"
    apj_ok "role $role policy plan $namespace" "$plan"
    token="$(printf '%s' "$plan" | apj_jget data.plan_token)"
    commit="$(apj_native "$role" zcode network policy mutate \
        --input="{\"mode\":\"commit\",$common,\"plan_token\":\"$token\"}" || true)"
    if [ "$(printf '%s' "$commit" | apj_jget ok False 2>/dev/null || true)" != True ]; then
        code="$(printf '%s' "$commit" | apj_jget error.code '' 2>/dev/null || true)"
        message="$(printf '%s' "$commit" | apj_jget error.message '' 2>/dev/null || true)"
        [ "$code" = POLICY_REFUSED ] && [ "$message" = duplicate ] ||
            apj_die "role $role policy commit $namespace failed: $commit"
    fi
}

APJ_NAMESPACE=zclassic23.package
APJ_ZPRNG_ROOT=91e9406a1016bcc224bb5e229377b1841e21c8ede1e0a00bc0d45d1989c41563
APJ_FIGHT_ROOT=3ea608b29cdee1df15d560a930455faa264b3ac9ded8b557efc28e3e720ef40a
APJ_DRONE_ROOT=10568ebc2876a6e3ecded390b012b0b8983613f3717949db1c9144ede2d78cf8
APJ_SEED=7
APJ_PLANES=3
APJ_A="$ORIGIN"; APJ_B="$NEXT"; APJ_C="$TARGET"; APJ_D=""
for apj_role in 0 1 2 3 4 5 6; do
    if [ "$apj_role" != "$APJ_A" ] && [ "$apj_role" != "$APJ_B" ] &&
       [ "$apj_role" != "$APJ_C" ]; then APJ_D="$apj_role"; break; fi
done
[ -n "$APJ_D" ] || apj_die "four independent roles are unavailable"
[ -x "$C23_BETA_INSTALL_BIN/zclassic23" ] &&
[ -x "$C23_BETA_INSTALL_BIN/arena_runner" ] &&
[ -x "$C23_BETA_DEV_BIN" ] ||
    apj_die "installed node, dev publisher, or Arena runner is unavailable"
for apj_role in "$APJ_A" "$APJ_B" "$APJ_C" "$APJ_D"; do
    apj_assert_installed_node "$apj_role"
    apj_allow_policy "$apj_role" "$APJ_NAMESPACE"
done
for apj_role in "$APJ_A" "$APJ_B" "$APJ_C" "$APJ_D"; do
    apj_restart "$apj_role"
done

APJ_AUTHOR="$DHT_WORK/zdogace-author"
APJ_DEPENDENCY_AUTHOR="$DHT_WORK/arena-dependencies-author"
mkdir -p "$APJ_AUTHOR" "$APJ_DEPENDENCY_AUTHOR"
git -C "$C23_BETA_FIXTURE_SOURCE" archive 2b00c4c2b^ packages/zdogace |
    tar -x -C "$APJ_AUTHOR" --strip-components=2
git -C "$C23_BETA_FIXTURE_SOURCE" archive 2b00c4c2b^ \
        packages/zprng packages/zdogfight packages/zdogdrone |
    tar -x -C "$APJ_DEPENDENCY_AUTHOR" --strip-components=1
[ -f "$APJ_AUTHOR/src/zdogace.c" ] || apj_die "old zdogace source was not materialized"

APJ_KEY="$DHT_WORK/arena-author.key"
APJ_PUB="$($C23_BETA_INSTALL_BIN/zclassic23-package-sign --generate "$APJ_KEY")"
[ "$(stat -c %a "$APJ_KEY")" = 600 ] && [ "${#APJ_PUB}" -eq 66 ] ||
    apj_die "offline package author identity is invalid"

apj_sign_digest() {
    local digest="$1" signature
    exec 7<"$APJ_KEY"
    signature="$($C23_BETA_INSTALL_BIN/zclassic23-package-sign \
        --sign-digest "$digest" --key-fd 7)" ||
        apj_die "offline package signature failed"
    exec 7<&-
    [ "${#signature}" -eq 128 ] || apj_die "offline signature is not compact"
    printf '%s' "$signature"
}
apj_create_dir() {
    local label="$1" dir="$2" sequence="$3" day="$4" expected="$5"
    local prep digest signature seal plan commit
    prep="$($NODE_BIN -regtest zcode package dev prepare \
        --input="{\"dir\":\"$dir\",\"publisher_pubkey\":\"$APJ_PUB\",\"publisher_sequence\":$sequence,\"chain_id\":\"zclassic-regtest\"}" \
        2>/dev/null | tail -1 || true)"
    apj_ok "$label prepare" "$prep"
    digest="$(printf '%s' "$prep" | apj_jget data.release_signing_digest)"
    signature="$(apj_sign_digest "$digest")"
    seal="$($NODE_BIN zcode package dev seal \
        --input="{\"release_body_hex\":\"$(printf '%s' "$prep" | apj_jget data.release_body_hex)\",\"signature_hex\":\"$signature\"}" \
        2>/dev/null | tail -1 || true)"
    apj_ok "$label seal" "$seal"
    APJ_CREATE_RELEASE="$(printf '%s' "$seal" | apj_jget data.release_hex)"
    APJ_CREATE_RELEASE_ID="$(printf '%s' "$seal" | apj_jget data.release_id)"
    local input
    input="\"release_hex\":\"$APJ_CREATE_RELEASE\",\"manifest_hex\":\"$(printf '%s' "$prep" | apj_jget data.manifest_hex)\",\"recipe_hex\":\"$(printf '%s' "$prep" | apj_jget data.recipe_hex)\",\"dir\":\"$dir\",\"day\":$day"
    plan="$(apj_native "$APJ_A" zcode create --input="{\"mode\":\"plan\",$input}" || true)"
    apj_ok "$label create plan" "$plan"
    commit="$(apj_native "$APJ_A" zcode create --input="{\"mode\":\"commit\",$input}" || true)"
    apj_ok "$label create commit" "$commit"
    APJ_CREATE_ROOT="$(printf '%s' "$commit" | apj_jget data.package_root)"
    APJ_CREATE_TRANSPORT="$(printf '%s' "$commit" | apj_jget data.transport_root)"
    [ "$APJ_CREATE_ROOT" = "$expected" ] ||
        apj_die "$label root drifted: $APJ_CREATE_ROOT expected $expected"
}

# The three unchanged dependencies are publisher inputs only. Every other
# role receives them through the authenticated provider route below.
apj_note "publisher derives the three unchanged Arena dependencies"
apj_create_dir zprng "$APJ_DEPENDENCY_AUTHOR/zprng" 1 1 "$APJ_ZPRNG_ROOT"
APJ_ZPRNG_TRANSPORT="$APJ_CREATE_TRANSPORT"
apj_create_dir zdogfight "$APJ_DEPENDENCY_AUTHOR/zdogfight" 2 8 "$APJ_FIGHT_ROOT"
APJ_FIGHT_TRANSPORT="$APJ_CREATE_TRANSPORT"
apj_create_dir zdogdrone "$APJ_DEPENDENCY_AUTHOR/zdogdrone" 3 15 "$APJ_DRONE_ROOT"
APJ_DRONE_TRANSPORT="$APJ_CREATE_TRANSPORT"

apj_use() {
    local role="$1" root="$2" plan plan_id commit now
    now="$(date +%s)"
    plan="$(apj_native "$role" zcode use \
        --input="{\"name_or_root\":\"$root\",\"now_unix\":$now}")"
    apj_ok "role $role use plan $root" "$plan"
    plan_id="$(printf '%s' "$plan" | apj_jget data.plan_id)"
    commit="$(apj_native "$role" zcode use \
        --input="{\"plan_id\":\"$plan_id\",\"now_unix\":$((now + 1))}")"
    apj_ok "role $role use commit $root" "$commit"
    APJ_USE_RECEIPT="$(printf '%s' "$commit" | "$DHT_ACCEPTANCE_C23" \
        array-match-get data.steps root "$root" build_receipt_id unused)"
}

# The pointer publication gate refuses REPRODUCTION_NOT_EVIDENCED unless the
# publishing node's own store holds two distinct byte-identical build
# receipts for the exact (package root, recipe root) pair. The install
# (`zcode use`) files the first; this deterministic rebuild files the
# distinct second, before the pointer plan exists.
apj_reproduce() {
    local role="$1" root="$2" reproduced
    reproduced="$(apj_native "$role" zcode package reproduce \
        --input="{\"name_or_root\":\"$root\"}" || true)"
    apj_ok "role $role reproduce $root" "$reproduced"
    [ "$(printf '%s' "$reproduced" | apj_jget data.reproduced False)" = True ] ||
        apj_die "role $role did not file a distinct rebuild receipt for $root"
}

apj_publish_record() {
    local role="$1" kind="$2" semantic="$3" transport="$4" sequence="$5"
    local now expiry common plan token commit
    now="$(date +%s)"; expiry=$((now + 3600))
    common='"kind":"'"$kind"'","namespace":"'"$APJ_NAMESPACE"'","transport_root":"'"$transport"'","sequence":'"$sequence"',"not_before":'"$((now - 5))"',"expiry":'"$expiry"
    [ "$kind" != pointer ] || common="$common,\"semantic_root\":\"$semantic\""
    plan="$(apj_native "$role" zcode network publish \
        --input="{\"mode\":\"plan\",$common}" || true)"
    apj_ok "$kind plan $semantic" "$plan"
    token="$(printf '%s' "$plan" | apj_jget data.plan_token)"
    commit="$(apj_native "$role" zcode network publish \
        --input="{\"mode\":\"commit\",$common,\"plan_token\":\"$token\"}" || true)"
    apj_ok "$kind commit $semantic" "$commit"
}
apj_publish_package() {
    apj_publish_record "$1" pointer "$2" "$3" 1
    apj_publish_record "$1" provider "$2" "$3" 1
}
apj_restart "$APJ_A" "$APJ_C"
# A is about to publish the three dependency pointers, and the gate requires
# the evidence in A's own store first: install the exact DAG (receipt one
# per root), then file the distinct rebuild receipt per published root.
apj_use "$APJ_A" "$APJ_DRONE_ROOT"
apj_reproduce "$APJ_A" "$APJ_ZPRNG_ROOT"
apj_reproduce "$APJ_A" "$APJ_FIGHT_ROOT"
apj_reproduce "$APJ_A" "$APJ_DRONE_ROOT"
apj_publish_package "$APJ_A" "$APJ_ZPRNG_ROOT" "$APJ_ZPRNG_TRANSPORT"
apj_publish_package "$APJ_A" "$APJ_FIGHT_ROOT" "$APJ_FIGHT_TRANSPORT"
apj_publish_package "$APJ_A" "$APJ_DRONE_ROOT" "$APJ_DRONE_TRANSPORT"

apj_pin() {
    local role="$1" root="$2" plan token commit
    plan="$(apj_native "$role" zcode package pin \
        --input="{\"root\":\"$root\",\"mode\":\"plan\"}")"
    apj_ok "role $role pin plan $root" "$plan"
    token="$(printf '%s' "$plan" | apj_jget data.plan_token)"
    commit="$(apj_native "$role" zcode package pin \
        --input="{\"root\":\"$root\",\"mode\":\"commit\",\"plan_token\":\"$token\"}")"
    apj_ok "role $role pin commit $root" "$commit"
}
apj_fetch() {
    local role="$1" semantic="$2" transport="$3" out deadline complete=False
    out="$(apj_native "$role" zcode package fetch \
        --input="{\"root\":\"$transport\",\"namespace\":\"$APJ_NAMESPACE\",\"maximum_bytes\":268435456}" || true)"
    apj_ok "role $role fetch $transport" "$out"
    deadline=$(( $(date +%s) + 180 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        out="$(apj_native "$role" zcode package pin \
            --input="{\"root\":\"$transport\",\"mode\":\"plan\"}" || true)"
        complete="$(printf '%s' "$out" | apj_jget data.package.complete False 2>/dev/null || true)"
        [ "$complete" = True ] && break
        sleep 1
    done
    [ "$complete" = True ] || apj_die "role $role did not complete $transport"
    out="$(apj_native "$role" zcode package fetch \
        --input="{\"root\":\"$transport\",\"namespace\":\"$APJ_NAMESPACE\",\"maximum_bytes\":268435456}" || true)"
    apj_ok "role $role import $transport" "$out"
    [ "$(printf '%s' "$out" | apj_jget data.package_root)" = "$semantic" ] ||
        apj_die "role $role imported the wrong semantic root"
    apj_pin "$role" "$transport"; apj_pin "$role" "$semantic"
}

# Reuse the production async proof helpers, but supply this exact project.
ZAP_HELPERS_ONLY=1
# shellcheck source=/dev/null
. "$SCRIPT_DIR/zcode_async_proof_acceptance_hook.sh"
unset ZAP_HELPERS_ONLY
ZAP_PROJECT="$APJ_AUTHOR"
for apj_role in "$APJ_A" "$APJ_B"; do zap_allow_context_policy "$apj_role"; done

# C and D need the dependency DAG before they can independently reproduce the
# candidate. B deliberately remains an inert, package-empty consumer.
for apj_role in "$APJ_C" "$APJ_D"; do
    apj_fetch "$apj_role" "$APJ_ZPRNG_ROOT" "$APJ_ZPRNG_TRANSPORT"
    apj_fetch "$apj_role" "$APJ_FIGHT_ROOT" "$APJ_FIGHT_TRANSPORT"
    apj_fetch "$apj_role" "$APJ_DRONE_ROOT" "$APJ_DRONE_TRANSPORT"
    apj_use "$apj_role" "$APJ_DRONE_ROOT"
done
apj_pin "$APJ_A" "$APJ_ZPRNG_TRANSPORT"; apj_pin "$APJ_A" "$APJ_ZPRNG_ROOT"
apj_pin "$APJ_A" "$APJ_FIGHT_TRANSPORT"; apj_pin "$APJ_A" "$APJ_FIGHT_ROOT"
apj_pin "$APJ_A" "$APJ_DRONE_TRANSPORT"; apj_pin "$APJ_A" "$APJ_DRONE_ROOT"
apj_use "$APJ_A" "$APJ_DRONE_ROOT"

for apj_role in 0 1 2 3 4 5 6; do
    dht_kill_group "${PIDS[$apj_role]:-}"; PIDS[$apj_role]=""
done
DHT_PGID_A=""; DHT_PGID_B=""
SAVED_BUILDWORKERS="$DHT_BUILDWORKERS"
DHT_BUILDWORKERS=0; zap_start_node "$APJ_B"
DHT_BUILDWORKERS="$SAVED_BUILDWORKERS"
zap_start_node "$APJ_C"; zap_start_node "$APJ_D"
zap_start_node "$APJ_A" "$APJ_C"
zap_connect "$APJ_A" "$APJ_D"; zap_connect "$APJ_A" "$APJ_B"

apj_note "native intent: Red Ace should turn toward its target rather than away"
APJ_START="$(apj_native "$APJ_A" zcode work start \
    --input="{\"workspace\":\"$APJ_AUTHOR\",\"goal\":\"Red Ace should turn toward its target rather than away from it\",\"profile\":\"standard\",\"max_cpu_seconds\":600}" || true)"
apj_ok "work start" "$APJ_START"
APJ_WORK="$(printf '%s' "$APJ_START" | apj_jget data.work_id)"
APJ_HANDOFF="$(apj_native "$APJ_A" zcode work run \
    --input="{\"workspace\":\"$APJ_AUTHOR\",\"work\":\"$APJ_WORK\",\"adapter\":\"manual\"}" || true)"
apj_ok "manual candidate handoff" "$APJ_HANDOFF"
APJ_CANDIDATE_WORKSPACE="$(printf '%s' "$APJ_HANDOFF" | apj_jget data.candidate_workspace)"
[ -d "$APJ_CANDIDATE_WORKSPACE/src" ] || apj_die "candidate workspace is absent"

"$DHT_ACCEPTANCE_C23" zdogace-correct "$APJ_CANDIDATE_WORKSPACE" ||
    apj_die "native C23 sign correction could not be applied exactly"

apj_build_red_direct() {
    local source="$1" out="$2" dd="${DDS[$APJ_A]}"
    cc -std=c23 -O1 -static -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L \
        -I"$source/include" -I"$dd/zcode/installed/$APJ_FIGHT_ROOT/include" \
        -I"$dd/zcode/installed/$APJ_ZPRNG_ROOT/include" \
        "$source/app/main.c" "$source/src/zdogace.c" \
        "$dd/zcode/installed/$APJ_FIGHT_ROOT/lib/libzdogfight.a" \
        "$dd/zcode/installed/$APJ_ZPRNG_ROOT/lib/libzprng.a" -o "$out"
}
apj_build_installed_pilot() {
    local role="$1" root="$2" name="$3" destination="$4" out="$5"
    local dd="${DDS[$role]}" reply
    mkdir -p "$(dirname "$destination")"
    reply="$(apj_native "$role" zcode package checkout \
        --input="{\"root\":\"$root\",\"destination\":\"$destination\"}")"
    apj_ok "role $role checkout $name" "$reply"
    cc -std=c23 -O1 -static -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L \
        -I"$dd/zcode/installed/$root/include" \
        -I"$dd/zcode/installed/$APJ_FIGHT_ROOT/include" \
        -I"$dd/zcode/installed/$APJ_ZPRNG_ROOT/include" \
        "$destination/app/main.c" "$dd/zcode/installed/$root/lib/lib$name.a" \
        "$dd/zcode/installed/$APJ_FIGHT_ROOT/lib/libzdogfight.a" \
        "$dd/zcode/installed/$APJ_ZPRNG_ROOT/lib/libzprng.a" -o "$out"
}
apj_build_accepted_pilot() {
    local role="$1" root="$2" destination="$3" out="$4"
    local dd="${DDS[$role]}" cas="${destination}-cas" reply
    mkdir -p "$destination" "$cas"
    reply="$(apj_native "$role" zcode workspace source package checkout \
        --input="{\"datadir\":\"$dd\",\"package_root\":\"$root\",\"source_root\":\"$APJ_SOURCE_ROOT\",\"accepted_work_root\":\"$APJ_ACCEPTED_ROOT\",\"workspace\":\"$cas\",\"destination\":\"$destination\"}")"
    apj_ok "role $role accepted source checkout" "$reply"
    cc -std=c23 -O1 -static -fno-omit-frame-pointer \
        -D_POSIX_C_SOURCE=200809L \
        -I"$destination/include" \
        -I"$dd/zcode/installed/$APJ_FIGHT_ROOT/include" \
        -I"$dd/zcode/installed/$APJ_ZPRNG_ROOT/include" \
        "$destination/app/main.c" "$destination/src/zdogace.c" \
        "$dd/zcode/installed/$APJ_FIGHT_ROOT/lib/libzdogfight.a" \
        "$dd/zcode/installed/$APJ_ZPRNG_ROOT/lib/libzprng.a" -o "$out"
}
apj_run_match() {
    local red="$1" blue="$2" replay="$3" output="$4" rc
    set +e
    "$C23_BETA_INSTALL_BIN/arena_runner" --seed "$APJ_SEED" \
        --planes-per-team "$APJ_PLANES" --pilot-red "$red" \
        --pilot-blue "$blue" --replay-out "$replay" >"$output" 2>&1
    rc="$?"
    set -e
    if [ "$rc" -eq 3 ]; then
        "$C23_BETA_INSTALL_BIN/arena_runner" --no-sandbox --seed "$APJ_SEED" \
            --planes-per-team "$APJ_PLANES" --pilot-red "$red" \
            --pilot-blue "$blue" --replay-out "$replay" >"$output" 2>&1
    elif [ "$rc" -ne 0 ]; then
        apj_die "Arena match failed: $(<"$output")"
    fi
}
apj_match_field() {
    tr ' ' '\n' <"$1" | awk -v k="$2" \
        'index($0,k "=")==1 {print substr($0,length(k)+2); exit}'
}

APJ_BLUE_CHECKOUT="$DHT_WORK/author-blue-checkout"
apj_build_installed_pilot "$APJ_A" "$APJ_DRONE_ROOT" zdogdrone \
    "$APJ_BLUE_CHECKOUT" "$DHT_WORK/author-blue"
apj_build_red_direct "$APJ_AUTHOR" "$DHT_WORK/red-before"
apj_build_red_direct "$APJ_CANDIDATE_WORKSPACE" "$DHT_WORK/red-candidate"
apj_run_match "$DHT_WORK/red-before" "$DHT_WORK/author-blue" \
    "$DHT_WORK/before.replay" "$DHT_WORK/before.out"
apj_run_match "$DHT_WORK/red-candidate" "$DHT_WORK/author-blue" \
    "$DHT_WORK/candidate.replay" "$DHT_WORK/candidate.out"
APJ_BEFORE_REPLAY="$(apj_match_field "$DHT_WORK/before.out" replay_root)"
APJ_CANDIDATE_REPLAY="$(apj_match_field "$DHT_WORK/candidate.out" replay_root)"
[ "$APJ_BEFORE_REPLAY" != "$APJ_CANDIDATE_REPLAY" ] ||
    apj_die "sign correction had no native Arena consequence"
apj_note "BASELINE $(tr '\n' ' ' <"$DHT_WORK/before.out")"
apj_note "CANDIDATE $(tr '\n' ' ' <"$DHT_WORK/candidate.out")"

APJ_RUN="$(apj_native "$APJ_A" zcode work run \
    --input="{\"workspace\":\"$APJ_AUTHOR\",\"work\":\"$APJ_WORK\",\"adapter\":\"manual\",\"datadir\":\"${DDS[$APJ_A]}\",\"details\":true}" || true)"
apj_ok "candidate async admission" "$APJ_RUN"
APJ_ACTION="$(printf '%s' "$APJ_RUN" | apj_jget data.expert.action_id)"
APJ_REPRO_ACTION="$(printf '%s' "$APJ_RUN" | apj_jget data.reproduction_action_id)"
APJ_CANDIDATE_ROOT="$(printf '%s' "$APJ_RUN" | apj_jget data.expert.candidate_root)"
APJ_SOURCE_ROOT="$(printf '%s' "$APJ_RUN" | apj_jget data.expert.candidate_source_root)"
APJ_TASK_ROOT="$(printf '%s' "$APJ_RUN" | apj_jget data.expert.task_root)"
[ "${#APJ_ACTION}" -eq 64 ] && [ "${#APJ_REPRO_ACTION}" -eq 64 ] ||
    apj_die "standard action pair is absent"
APJ_CONTEXT="$(zap_wait_context_root "$APJ_A" "$APJ_ACTION")" ||
    apj_die "candidate action never bound its carrier"
zap_publish_context_provider "$APJ_A" "$APJ_CONTEXT"
zap_fetch_inert_context "$APJ_B" "$APJ_CONTEXT" "$APJ_ACTION" "$APJ_REPRO_ACTION"
zap_wait_reproduction_ready "$APJ_A" "$APJ_ACTION" "$APJ_REPRO_ACTION" ||
    apj_die "two independent signers did not satisfy the candidate proof policy"
APJ_C_ACTION="$(zap_sql_value "$APJ_C" "SELECT action_id FROM build_actions WHERE action_id IN ('$APJ_ACTION','$APJ_REPRO_ACTION') AND state IN ('ACCEPTED','CACHE_HIT')")"
APJ_D_ACTION="$(zap_sql_value "$APJ_D" "SELECT action_id FROM build_actions WHERE action_id IN ('$APJ_ACTION','$APJ_REPRO_ACTION') AND state IN ('ACCEPTED','CACHE_HIT')")"
APJ_C_SIGNER="$(zap_sql_value "$APJ_C" "SELECT w.signer_pubkey FROM build_actions a JOIN build_workers w ON w.worker_id=a.worker_id WHERE a.action_id='$APJ_C_ACTION'")"
APJ_D_SIGNER="$(zap_sql_value "$APJ_D" "SELECT w.signer_pubkey FROM build_actions a JOIN build_workers w ON w.worker_id=a.worker_id WHERE a.action_id='$APJ_D_ACTION'")"
APJ_C_OUTPUT="$(zap_evidence_output "$APJ_C" "$APJ_C_ACTION")"
APJ_D_OUTPUT="$(zap_evidence_output "$APJ_D" "$APJ_D_ACTION")"
[ "${#APJ_C_SIGNER}" -eq 64 ] && [ "${#APJ_D_SIGNER}" -eq 64 ] &&
[ "$APJ_C_SIGNER" != "$APJ_D_SIGNER" ] && [ "$APJ_C_OUTPUT" = "$APJ_D_OUTPUT" ] ||
    apj_die "matching evidence did not retain two distinct signer identities"

APJ_STATUS="$(apj_native "$APJ_A" zcode work status \
    --input="{\"workspace\":\"$APJ_AUTHOR\",\"work\":\"$APJ_WORK\",\"datadir\":\"${DDS[$APJ_A]}\",\"details\":true}" || true)"
apj_ok "proof-complete work status" "$APJ_STATUS"
APJ_CONFIRMATION="$(printf '%s' "$APJ_STATUS" | apj_jget data.confirmation_identity)"
[ "$(printf '%s' "$APJ_STATUS" | apj_jget data.proof.approved_distinct_signers)" -eq 2 ] ||
    apj_die "human status appeared before two approved signers"
APJ_CONFIRM_VIEW="$(apj_native "$APJ_A" app presentation release-confirm \
    --input="{\"workspace\":\"$APJ_AUTHOR\",\"work\":\"$APJ_WORK\",\"datadir\":\"${DDS[$APJ_A]}\",\"output\":\"text\"}" || true)"
apj_ok "native release confirmation" "$APJ_CONFIRM_VIEW"
[ "$(printf '%s' "$APJ_CONFIRM_VIEW" | apj_jget data.confirmation_identity)" = "$APJ_CONFIRMATION" ] ||
    apj_die "native confirmation lost the proof-complete identity"

APJ_STALE="${APJ_CONFIRMATION}"
[ "${APJ_STALE:0:1}" = 0 ] && APJ_STALE="1${APJ_STALE:1}" || APJ_STALE="0${APJ_STALE:1}"
APJ_STALE_REPLY="$(apj_native "$APJ_A" zcode work accept \
    --input="{\"workspace\":\"$APJ_AUTHOR\",\"work\":\"$APJ_WORK\",\"datadir\":\"${DDS[$APJ_A]}\",\"confirmation_identity\":\"$APJ_STALE\"}" || true)"
[ "$(printf '%s' "$APJ_STALE_REPLY" | apj_jget error.code 2>/dev/null || true)" = CONFIRMATION_IDENTITY_STALE ] ||
    apj_die "stale confirmation was not refused by name: $APJ_STALE_REPLY"
APJ_ACCEPT="$(apj_native "$APJ_A" zcode work accept \
    --input="{\"workspace\":\"$APJ_AUTHOR\",\"work\":\"$APJ_WORK\",\"datadir\":\"${DDS[$APJ_A]}\",\"confirmation_identity\":\"$APJ_CONFIRMATION\",\"details\":true}" || true)"
apj_ok "exact human acceptance" "$APJ_ACCEPT"
APJ_ACCEPTED_ROOT="$(printf '%s' "$APJ_ACCEPT" | apj_jget data.expert.lane_receipt_root)"
APJ_JOB="$(printf '%s' "$APJ_ACCEPT" | apj_jget data.publication_job_root)"
[ "$(printf '%s' "$APJ_ACCEPT" | apj_jget data.publication_status)" = ACCEPTED_LANE_BOUND ] ||
    apj_die "accepted source did not enter dev.publication"

# Retained-source tamper: PROVEN stays immutable, but a rebind must refuse the
# changed candidate workspace by the command's named boundary.
"$DHT_ACCEPTANCE_C23" zdogace-tamper "$APJ_CANDIDATE_WORKSPACE/src/zdogace.c" ||
    apj_die "native source tamper fixture drifted"
APJ_SOURCE_TAMPER="$(apj_native "$APJ_A" zcode work accept \
    --input="{\"workspace\":\"$APJ_AUTHOR\",\"work\":\"$APJ_WORK\",\"datadir\":\"${DDS[$APJ_A]}\",\"confirmation_identity\":\"$APJ_CONFIRMATION\"}" || true)"
[ "$(printf '%s' "$APJ_SOURCE_TAMPER" | apj_jget error.code 2>/dev/null || true)" = ACCEPTED_PUBLICATION_BIND_FAILED ] ||
    apj_die "source tamper was not refused by name: $APJ_SOURCE_TAMPER"
"$DHT_ACCEPTANCE_C23" zdogace-tamper "$APJ_CANDIDATE_WORKSPACE/src/zdogace.c" ||
    apj_die "native source restore fixture drifted"

APJ_ADVANCE="$(ZCL_DEV_SOURCE_ROOT="$APJ_AUTHOR" "$C23_BETA_DEV_BIN" \
    -datadir="${DDS[$APJ_A]}" -rpcport="${RPCS[$APJ_A]}" -regtest \
    dev publication advance \
    --input="{\"job_root\":\"$APJ_JOB\",\"datadir\":\"${DDS[$APJ_A]}\",\"details\":true}" \
    2>/dev/null | tail -1 || true)"
apj_ok "dev.publication exact mapping" "$APJ_ADVANCE"
[ "$(printf '%s' "$APJ_ADVANCE" | apj_jget data.status)" = PACKAGE_MAPPING_READY ] ||
    apj_die "dev.publication did not reach its exact package mapping"
APJ_MAPPING="$(printf '%s' "$APJ_ADVANCE" | apj_jget data.package_mapping_root)"

APJ_PUBLISH_PLAN="$(apj_native "$APJ_A" zcode publish plan \
    --input="{\"workspace\":\"$APJ_AUTHOR\",\"datadir\":\"${DDS[$APJ_A]}\",\"acceptance_datadir\":\"${DDS[$APJ_A]}\",\"source_root\":\"$APJ_SOURCE_ROOT\",\"publisher_pubkey\":\"$APJ_PUB\",\"task_root\":\"$APJ_TASK_ROOT\",\"lane_receipt_root\":\"$APJ_ACCEPTED_ROOT\",\"package_mapping_root\":\"$APJ_MAPPING\",\"publication_job_root\":\"$APJ_JOB\"}" || true)"
apj_ok "accepted source publish plan" "$APJ_PUBLISH_PLAN"
APJ_PACKAGE_NAME="$(apj_jget name <"$APJ_AUTHOR/zcode-package.json")"
APJ_PACKAGE_VERSION="$(apj_jget semver <"$APJ_AUTHOR/zcode-package.json")"
APJ_PACKAGE_LICENSE="$(apj_jget license <"$APJ_AUTHOR/zcode-package.json")"
[ "$(printf '%s' "$APJ_PUBLISH_PLAN" | apj_jget data.package_name)" = "$APJ_PACKAGE_NAME" ] &&
    [ "$(printf '%s' "$APJ_PUBLISH_PLAN" | apj_jget data.package_version)" = "$APJ_PACKAGE_VERSION" ] &&
    [ "$(printf '%s' "$APJ_PUBLISH_PLAN" | apj_jget data.package_license)" = "$APJ_PACKAGE_LICENSE" ] &&
    [ "$(printf '%s' "$APJ_PUBLISH_PLAN" | apj_jget data.package_facts)" = exact_accepted_source ] ||
    apj_die "accepted source package facts were not reused exactly"
APJ_PACKAGE_ROOT="$(printf '%s' "$APJ_PUBLISH_PLAN" | apj_jget data.package_root)"
APJ_RELEASE_SIGNATURE="$(apj_sign_digest "$(printf '%s' "$APJ_PUBLISH_PLAN" | apj_jget data.release_signing_digest)")"
APJ_SEAL="$("$NODE_BIN" zcode package dev seal \
    --input="{\"release_body_hex\":\"$(printf '%s' "$APJ_PUBLISH_PLAN" | apj_jget data.release_body_hex)\",\"signature_hex\":\"$APJ_RELEASE_SIGNATURE\"}" \
    2>/dev/null | tail -1)"
apj_ok "accepted source release seal" "$APJ_SEAL"
APJ_RELEASE_HEX="$(printf '%s' "$APJ_SEAL" | apj_jget data.release_hex)"
APJ_RELEASE_ROOT="$(printf '%s' "$APJ_SEAL" | apj_jget data.release_id)"
APJ_BAD_RELEASE="${APJ_RELEASE_HEX%?}"
[ "${APJ_RELEASE_HEX: -1}" = 0 ] && APJ_BAD_RELEASE="${APJ_BAD_RELEASE}1" || APJ_BAD_RELEASE="${APJ_BAD_RELEASE}0"
apj_publish_commit() {
    apj_native "$APJ_A" zcode publish \
        --input="{\"workspace\":\"$APJ_AUTHOR\",\"datadir\":\"${DDS[$APJ_A]}\",\"acceptance_datadir\":\"${DDS[$APJ_A]}\",\"source_root\":\"$APJ_SOURCE_ROOT\",\"release_hex\":\"$1\",\"task_root\":\"$APJ_TASK_ROOT\",\"lane_receipt_root\":\"$APJ_ACCEPTED_ROOT\",\"day\":22,\"package_mapping_root\":\"$APJ_MAPPING\",\"publication_job_root\":\"$APJ_JOB\"}"
}
APJ_RELEASE_TAMPER="$(apj_publish_commit "$APJ_BAD_RELEASE" || true)"
[ "$(printf '%s' "$APJ_RELEASE_TAMPER" | apj_jget error.code 2>/dev/null || true)" = SIGNED_RELEASE_INVALID ] ||
    apj_die "release tamper was not refused by name: $APJ_RELEASE_TAMPER"
APJ_PUBLISH="$(apj_publish_commit "$APJ_RELEASE_HEX" || true)"
apj_ok "accepted source publish commit" "$APJ_PUBLISH"
APJ_TRANSPORT_ROOT="$(printf '%s' "$APJ_PUBLISH" | apj_jget data.transport_root)"
[ "$(printf '%s' "$APJ_PUBLISH" | apj_jget data.publication_status)" = RELEASE_PUBLISHED ] ||
    apj_die "publication job did not bind the signed release"

apj_restart "$APJ_A" "$APJ_C"
# A owns the accepted release bytes.  It advertises only that exact carrier;
# C fetches it through the real provider route and becomes the discovery
# relay.  This keeps the service's fixed operation cap intact after the three
# dependency publications and gives the fresh consumer no metadata handoff.
apj_publish_record "$APJ_A" provider "$APJ_PACKAGE_ROOT" \
    "$APJ_TRANSPORT_ROOT" 1
apj_restart "$APJ_A" "$APJ_C"
apj_fetch "$APJ_C" "$APJ_PACKAGE_ROOT" "$APJ_TRANSPORT_ROOT"
apj_restart "$APJ_C" "$APJ_A"
# C is about to publish this package's pointer: the gate requires C's own
# install receipt plus the distinct rebuild receipt in C's store first.
apj_use "$APJ_C" "$APJ_PACKAGE_ROOT"
apj_reproduce "$APJ_C" "$APJ_PACKAGE_ROOT"
apj_publish_record "$APJ_C" pointer "$APJ_PACKAGE_ROOT" \
    "$APJ_TRANSPORT_ROOT" 1
apj_restart "$APJ_C" "$APJ_A"
apj_publish_record "$APJ_C" provider "$APJ_PACKAGE_ROOT" \
    "$APJ_TRANSPORT_ROOT" 1
apj_pin "$APJ_A" "$APJ_TRANSPORT_ROOT"
apj_pin "$APJ_A" "$APJ_PACKAGE_ROOT"

apj_note "fresh consumer discovers and fetches four exact packages; bytes remain inert"
apj_fetch "$APJ_B" "$APJ_ZPRNG_ROOT" "$APJ_ZPRNG_TRANSPORT"
apj_fetch "$APJ_B" "$APJ_FIGHT_ROOT" "$APJ_FIGHT_TRANSPORT"
apj_fetch "$APJ_B" "$APJ_DRONE_ROOT" "$APJ_DRONE_TRANSPORT"
apj_fetch "$APJ_B" "$APJ_PACKAGE_ROOT" "$APJ_TRANSPORT_ROOT"
[ ! -e "${DDS[$APJ_B]}/zcode/installed/$APJ_PACKAGE_ROOT" ] ||
    apj_die "fetched C executed or installed before explicit local admission"

apj_use "$APJ_A" "$APJ_PACKAGE_ROOT"; APJ_A_BUILD_RECEIPT="$APJ_USE_RECEIPT"
apj_use "$APJ_B" "$APJ_PACKAGE_ROOT"; APJ_B_BUILD_RECEIPT="$APJ_USE_RECEIPT"
apj_use "$APJ_B" "$APJ_DRONE_ROOT"

apj_build_accepted_pilot "$APJ_A" "$APJ_PACKAGE_ROOT" \
    "$DHT_WORK/checkout-A-red" "$DHT_WORK/final-A-red"
apj_build_installed_pilot "$APJ_A" "$APJ_DRONE_ROOT" zdogdrone \
    "$DHT_WORK/checkout-A-blue" "$DHT_WORK/final-A-blue"
apj_build_accepted_pilot "$APJ_B" "$APJ_PACKAGE_ROOT" \
    "$DHT_WORK/checkout-B-red" "$DHT_WORK/final-B-red"
apj_build_installed_pilot "$APJ_B" "$APJ_DRONE_ROOT" zdogdrone \
    "$DHT_WORK/checkout-B-blue" "$DHT_WORK/final-B-blue"
cmp "$DHT_WORK/final-A-red" "$DHT_WORK/final-B-red" ||
    apj_die "fresh consumer pilot artifact differs"
APJ_A_ARTIFACT="$(openssl dgst -sha3-256 \
    "$DHT_WORK/final-A-red" | awk '{print $NF}')"
APJ_B_ARTIFACT="$(openssl dgst -sha3-256 \
    "$DHT_WORK/final-B-red" | awk '{print $NF}')"
[ "$APJ_A_ARTIFACT" = "$APJ_B_ARTIFACT" ] ||
    apj_die "fresh consumer installed artifact root differs"
apj_run_match "$DHT_WORK/final-A-red" "$DHT_WORK/final-A-blue" \
    "$DHT_WORK/final-A.replay" "$DHT_WORK/final-A.out"
apj_run_match "$DHT_WORK/final-B-red" "$DHT_WORK/final-B-blue" \
    "$DHT_WORK/final-B.replay" "$DHT_WORK/final-B.out"
cmp "$DHT_WORK/final-A.replay" "$DHT_WORK/final-B.replay" ||
    apj_die "fresh-node Arena replay differs"
APJ_FINAL_REPLAY="$(apj_match_field "$DHT_WORK/final-B.out" replay_root)"
APJ_FINAL_STATE="$(apj_match_field "$DHT_WORK/final-B.out" final_state_root)"
APJ_FINAL_CHAIN="$(apj_match_field "$DHT_WORK/final-B.out" state_root_chain)"
[ "$APJ_FINAL_REPLAY" = "$APJ_CANDIDATE_REPLAY" ] ||
    apj_die "installed-package replay lost the candidate consequence"

APJ_MANIFEST="${DDS[$APJ_B]}/zcode/manifests/$APJ_TRANSPORT_ROOT"
[ -f "$APJ_MANIFEST" ] || apj_die "fresh consumer carrier manifest is absent"
"$DHT_ACCEPTANCE_C23" flip-byte "$APJ_MANIFEST" last
APJ_OBJECT_TAMPER="$(apj_native "$APJ_B" zcode package verify \
    --input="{\"root\":\"$APJ_TRANSPORT_ROOT\"}" || true)"
APJ_OBJECT_TAMPER_CODE="$(printf '%s' "$APJ_OBJECT_TAMPER" | apj_jget error.code '' 2>/dev/null || true)"
[ -n "$APJ_OBJECT_TAMPER_CODE" ] ||
    apj_die "object tamper was not refused by name: $APJ_OBJECT_TAMPER"
"$DHT_ACCEPTANCE_C23" flip-byte "$APJ_MANIFEST" last

"$DHT_ACCEPTANCE_C23" flip-byte "$DHT_WORK/final-B.replay" 115
APJ_REPLAY_TAMPER_RC=0
APJ_REPLAY_TAMPER="$($C23_BETA_INSTALL_BIN/arena_runner \
    --verify-replay "$DHT_WORK/final-B.replay" \
    --expect-replay-root "$APJ_FINAL_REPLAY" 2>&1)" ||
    APJ_REPLAY_TAMPER_RC="$?"
[ "$APJ_REPLAY_TAMPER_RC" -eq 1 ] &&
case "$APJ_REPLAY_TAMPER" in *"verify=MISMATCH "*) true;; *) false;; esac ||
    apj_die "replay tamper was not refused by name: $APJ_REPLAY_TAMPER"
"$DHT_ACCEPTANCE_C23" flip-byte "$DHT_WORK/final-B.replay" 115
APJ_VERIFY="$($C23_BETA_INSTALL_BIN/arena_runner \
    --verify-replay "$DHT_WORK/final-B.replay" \
    --expect-replay-root "$APJ_FINAL_REPLAY" 2>&1)" ||
    apj_die "restored replay did not verify: $APJ_VERIFY"

printf '%s\n' \
    "IDENTITY task_root=$APJ_TASK_ROOT" \
    "IDENTITY candidate_root=$APJ_CANDIDATE_ROOT" \
    "IDENTITY source_root=$APJ_SOURCE_ROOT" \
    "IDENTITY actions=$APJ_ACTION,$APJ_REPRO_ACTION" \
    "IDENTITY signer_receipts=$APJ_C_SIGNER:$APJ_C_ACTION,$APJ_D_SIGNER:$APJ_D_ACTION" \
    "IDENTITY matching_output_root=$APJ_C_OUTPUT" \
    "IDENTITY confirmation_identity=$APJ_CONFIRMATION" \
    "IDENTITY accepted_work_root=$APJ_ACCEPTED_ROOT" \
    "IDENTITY publication_job_root=$APJ_JOB" \
    "IDENTITY package_mapping_root=$APJ_MAPPING" \
    "IDENTITY package_root=$APJ_PACKAGE_ROOT" \
    "IDENTITY release_root=$APJ_RELEASE_ROOT" \
    "IDENTITY transport_root=$APJ_TRANSPORT_ROOT" \
    "IDENTITY build_receipts=$APJ_A_BUILD_RECEIPT,$APJ_B_BUILD_RECEIPT" \
    "IDENTITY artifact_root=$APJ_A_ARTIFACT" \
    "IDENTITY replay_root=$APJ_FINAL_REPLAY" \
    "IDENTITY final_state_root=$APJ_FINAL_STATE" \
    "IDENTITY state_root_chain=$APJ_FINAL_CHAIN" \
    "REFUSAL source=ACCEPTED_PUBLICATION_BIND_FAILED" \
    "REFUSAL release=SIGNED_RELEASE_INVALID" \
    "REFUSAL object=$APJ_OBJECT_TAMPER_CODE" \
    "REFUSAL replay=$(printf '%s' "$APJ_REPLAY_TAMPER" | sed -n 's/.*verify=MISMATCH \([^ ]*\).*/\1/p')" \
    "CONSUMER repository_source=false copied_release_metadata=false fetched_inert=true" \
    "VERDICT=PASS"
