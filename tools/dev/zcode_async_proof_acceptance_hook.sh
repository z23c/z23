#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Three-full-node composition hook for zcode_dht_acceptance.sh. Sourced only
# after its seven isolated identities and authenticated sparse topology pass.

[ "${DHT_BUILDWORKERS:-0}" = 1 ] ||
    dht_die "async proof hook requires DHT_BUILDWORKERS=1"
[ "${DHT_PACKAGEHOST:-0}" = 1 ] ||
    dht_die "async proof hook requires DHT_PACKAGEHOST=1"
trap 'dht_die "async proof hook command failed at line $LINENO"' ERR

# Keep the package action observable long enough to stop a real executor after
# started_at is durable. Candidate changes still differ by only one source file
# and remain well below the task's fixed 16 MiB patch ceiling.
zap_write_source() {
    local path="$1" value="$2" functions="${3:-1800}"
    local pressure="${4:-0}" i prev
    {
        printf 'int x(void) { return %s; }\n' "$value"
        i=0
        while [ "$i" -lt "$functions" ]; do
            # External linkage keeps the deliberately large kill/retry
            # fixture warning-clean under the standard profile's -Werror.
            # Static unused functions would correctly make the independently
            # reproduced build fail before the lease scenarios can run.
            printf 'int zap_%05d(int v) { return v + %d; }\n' "$i" "$i"
            i=$((i + 1))
        done
        if [ "$pressure" = 1 ]; then
            # Balanced expansion makes compiler work observable without
            # inflating the source/context carrier past the task's bound.
            # Unsigned arithmetic is warning-clean in both declared compilers.
            printf '#define ZAP_PRESSURE_0(v) ((((unsigned)(v)) * 1664525u) ^ 1013904223u)\n'
            i=1
            while [ "$i" -le 11 ]; do
                prev=$((i - 1))
                printf '#define ZAP_PRESSURE_%d(v) (ZAP_PRESSURE_%d(v) ^ ZAP_PRESSURE_%d(((unsigned)(v)) + %du))\n' \
                    "$i" "$prev" "$prev" "$i"
                i=$((i + 1))
            done
            i=0
            while [ "$i" -lt 64 ]; do
                printf 'unsigned zap_pressure_%02d(unsigned v) { return ZAP_PRESSURE_11(v + %du); }\n' \
                    "$i" "$i"
                i=$((i + 1))
            done
        fi
    } >"$path"
}
zap_field() {
    "$DHT_ACCEPTANCE_C23" json-get "$@"
}

zap_submit() {
    local node="$1" value="$2" goal="$3" max_cpu="${4:-600}"
    local profile="${5:-quick}" functions="${6:-1800}"
    local pressure="${7:-0}"
    local start handoff candidate result started_ms finished_ms elapsed_ms
    local ok action reproduction submit_us feedback_us event request work
    start="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" zcode work start \
        --input="{\"workspace\":\"$ZAP_PROJECT\",\"goal\":\"$goal\",\"profile\":\"$profile\",\"max_cpu_seconds\":$max_cpu}" || true)"
    ok="$(printf '%s' "$start" | zap_field ok False 2>/dev/null || true)"
    [ "$ok" = True ] || dht_die "node $node could not start async work: $start"
    work="$(printf '%s' "$start" | zap_field data.work_id)"
    handoff="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" zcode work run \
        --input="{\"workspace\":\"$ZAP_PROJECT\",\"work\":\"$work\",\"adapter\":\"manual\"}" || true)"
    candidate="$(printf '%s' "$handoff" | zap_field data.candidate_workspace 2>/dev/null || true)"
    [ -d "$candidate/src" ] || dht_die "node $node did not materialize its candidate: $handoff"
    zap_write_source "$candidate/src/x.c" "$value" "$functions" "$pressure"
    started_ms="$(date +%s%3N)"
    result="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" zcode work run \
        --input="{\"workspace\":\"$ZAP_PROJECT\",\"work\":\"$work\",\"adapter\":\"manual\",\"datadir\":\"${DDS[$node]}\",\"details\":true}" || true)"
    printf '%s\n' "$start" >"$DHT_WORK/async-submit-${node}-${work}-start.json"
    printf '%s\n' "$handoff" >"$DHT_WORK/async-submit-${node}-${work}-handoff.json"
    printf '%s\n' "$result" >"$DHT_WORK/async-submit-${node}-${work}-result.json"
    finished_ms="$(date +%s%3N)"; elapsed_ms=$((finished_ms - started_ms))
    ok="$(printf '%s' "$result" | zap_field ok False 2>/dev/null || true)"
    [ "$ok" = True ] || dht_die "node $node foreground admission failed: $result"
    action="$(printf '%s' "$result" | zap_field data.expert.action_id)"
    reproduction="$(printf '%s' "$result" | zap_field data.reproduction_action_id '')"
    event="$(printf '%s' "$result" | zap_field data.async_proof_event_root)"
    request="$(printf '%s' "$result" | zap_field data.remote_request_id)"
    submit_us="$(printf '%s' "$result" | zap_field data.local_submit_us)"
    feedback_us="$(printf '%s' "$result" | zap_field data.local_first_feedback_us)"
    [ "${#action}" -eq 64 ] && [ "${#event}" -eq 64 ] &&
        [ "$request" -gt 0 ] && [ "$submit_us" -ge 0 ] &&
        [ "$feedback_us" -ge "$submit_us" ] ||
        dht_die "node $node response omitted root-bound async identity: $result"
    [ "$elapsed_ms" -lt 30000 ] ||
        dht_die "node $node foreground crossed 30s latency firewall: ${elapsed_ms}ms"
    [ "$(zap_sql_count "$node" "SELECT count(*) FROM build_actions WHERE action_id='$action'")" -eq 1 ] &&
    [ "$(zap_sql_count "$node" "SELECT count(*) FROM build_proof_events WHERE action_id='$action' AND state='REQUESTED'")" -eq 1 ] ||
        dht_die "node $node returned action $action for $work without owning its exact action/proof rows"
    if [ "$profile" = standard ]; then
        [ "${#reproduction}" -eq 64 ] && [ "$reproduction" != "$action" ] &&
        [ "$(zap_sql_count "$node" "SELECT count(*) FROM build_actions WHERE action_id='$reproduction'")" -eq 1 ] &&
        [ "$(zap_sql_count "$node" "SELECT count(*) FROM build_proof_events WHERE action_id='$reproduction' AND state='REQUESTED'")" -eq 1 ] ||
            dht_die "node $node did not own the standard reproduction action: $result"
    fi
    ZAP_ACTION="$action"; ZAP_WORK="$work"; ZAP_FOREGROUND_MS="$elapsed_ms"
    ZAP_REPRO_ACTION="$reproduction"
    ZAP_SUBMIT_US="$submit_us"; ZAP_FEEDBACK_US="$feedback_us"
}

zap_submit_capture() {
    local node="$1" value="$2" goal="$3" capture="$4"
    local functions="${5:-1800}" pressure="${6:-0}"
    (
        zap_submit "$node" "$value" "$goal" 600 quick "$functions" "$pressure"
        printf '%s\n%s\n%s\n%s\n' "$ZAP_ACTION" "$ZAP_WORK" \
            "$ZAP_FOREGROUND_MS" "$(date +%s%3N)" >"$capture"
    )
}

zap_wait_executor_running() {
    local node="$1" action="$2" deadline state
    ZAP_WAIT_ACTION_STATE=missing
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(zap_sql_value "$node" "SELECT state FROM build_actions WHERE action_id='$action'")"
        [ -n "$state" ] && ZAP_WAIT_ACTION_STATE="$state"
        [ "$state" = RUNNING ] && return 0
        case "$state" in
            FAILED|ACCEPTED|CACHE_HIT|STALE_REFUSED) return 1 ;;
        esac
        sleep 0.1
    done
    return 1
}

zap_wait_named_busy() {
    local node="$1" action="$2" deadline log
    log="${DDS[$node]}/node.log"
    deadline=$(( $(date +%s) + 30 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        grep -aF "action=$action stage=worker_admission" "$log" 2>/dev/null |
            grep -q 'disposition=BUSY .*reroute=1' && return 0
        sleep 0.1
    done
    return 1
}

zap_wait_context_root() {
    local node="$1" action="$2" deadline root
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        root="$(zap_sql_value "$node" "SELECT context_root_sha3 FROM build_actions WHERE action_id='$action'")"
        [ "${#root}" -eq 64 ] && { printf '%s' "$root"; return 0; }
        sleep 1
    done
    return 1
}

zap_publish_context_provider() {
    local node="$1" root="$2" now expiry common plan token commit
    now="$(date +%s)"; expiry=$((now + 600))
    common="\"kind\":\"provider\",\"namespace\":\"zclassic23.work\",\"transport_root\":\"$root\",\"sequence\":1,\"not_before\":$((now - 5)),\"expiry\":$expiry"
    plan="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
        zcode network publish --input="{\"mode\":\"plan\",$common}" || true)"
    printf '%s\n' "$plan" >"$DHT_WORK/async-context-provider-plan.json"
    [ "$(printf '%s' "$plan" | zap_field ok False 2>/dev/null || true)" = True ] ||
        dht_die "node $node could not plan the work-context provider record: $plan"
    token="$(printf '%s' "$plan" | zap_field data.plan_token)"
    commit="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
        zcode network publish --input="{\"mode\":\"commit\",$common,\"plan_token\":\"$token\"}" || true)"
    printf '%s\n' "$commit" >"$DHT_WORK/async-context-provider-commit.json"
    [ "$(printf '%s' "$commit" | zap_field ok False 2>/dev/null || true)" = True ] ||
        dht_die "node $node could not publish the work-context provider record: $commit"
}

zap_allow_context_policy() {
    local node="$1" common plan token commit ok code message
    common='"operation":"add","source":"local","effect":"allow","scope":"service_type","action_mask":63,"value":"zclassic23.work"'
    plan="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
        zcode network policy mutate --input="{\"mode\":\"plan\",$common}" || true)"
    [ "$(printf '%s' "$plan" | zap_field ok False 2>/dev/null || true)" = True ] ||
        dht_die "node $node could not plan work-context policy: $plan"
    token="$(printf '%s' "$plan" | zap_field data.plan_token)"
    commit="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
        zcode network policy mutate --input="{\"mode\":\"commit\",$common,\"plan_token\":\"$token\"}" || true)"
    ok="$(printf '%s' "$commit" | zap_field ok False 2>/dev/null || true)"
    code="$(printf '%s' "$commit" | zap_field error.code '' 2>/dev/null || true)"
    message="$(printf '%s' "$commit" | zap_field error.message '' 2>/dev/null || true)"
    [ "$ok" = True ] || { [ "$code" = POLICY_REFUSED ] && [ "$message" = duplicate ]; } ||
        dht_die "node $node could not commit work-context policy: $commit"
}

zap_fetch_inert_context() {
    local node="$1" root="$2" action_a="$3" action_b="$4"
    local result deadline complete next_resume
    [ "$(zap_sql_count "$node" "SELECT count(*) FROM build_actions WHERE action_id IN ('$action_a','$action_b')")" -eq 0 ] ||
        dht_die "inert importer $node already owned an execution action"
    result="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" zcode package fetch \
        --input="{\"root\":\"$root\",\"namespace\":\"zclassic23.work\",\"maximum_bytes\":67108864}" || true)"
    [ "$(printf '%s' "$result" | zap_field ok False 2>/dev/null || true)" = True ] ||
        dht_die "node $node could not fetch the inert work package: $result"
    deadline=$(( $(date +%s) + 120 ))
    next_resume=$(( $(date +%s) + 5 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        result="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" zcode package pin \
            --input="{\"root\":\"$root\",\"mode\":\"plan\"}" || true)"
        complete="$(printf '%s' "$result" | zap_field data.package.complete False 2>/dev/null || true)"
        [ "$complete" = True ] && break
        # A bounded provider/session I/O failure is a durable FAILED download
        # record, not completion. Re-admitting the same exact root is the
        # existing resumable-fetch operation: it reuses the failed slot and
        # immutable package identity without copying bytes or executing them.
        if [ "$(date +%s)" -ge "$next_resume" ]; then
            result="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
                zcode package fetch \
                --input="{\"root\":\"$root\",\"namespace\":\"zclassic23.work\",\"maximum_bytes\":67108864}" || true)"
            [ "$(printf '%s' "$result" | zap_field ok False 2>/dev/null || true)" = True ] ||
                dht_die "node $node could not resume the exact inert work package: $result"
            next_resume=$(( $(date +%s) + 5 ))
        fi
        sleep 1
    done
    [ "$complete" = True ] ||
        dht_die "node $node did not complete the inert work-package fetch"
    [ "$(zap_sql_count "$node" "SELECT count(*) FROM build_actions WHERE action_id IN ('$action_a','$action_b')")" -eq 0 ] &&
    [ "$(zap_sql_count "$node" "SELECT count(*) FROM build_receipts WHERE action_id IN ('$action_a','$action_b')")" -eq 0 ] ||
        dht_die "fetch/import alone executed code or projected evidence on node $node"
}

zap_wait_reproduction_ready() {
    local node="$1" action_a="$2" action_b="$3" deadline state_a state_b
    deadline=$(( $(date +%s) + 300 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        zap_approve_action_receipt "$node" "$action_a" || true
        zap_approve_action_receipt "$node" "$action_b" || true
        state_a="$(zap_latest_state "$node" "$action_a")"
        state_b="$(zap_latest_state "$node" "$action_b")"
        if [ "$state_a" = READY_FOR_ACCEPTANCE ] ||
           [ "$state_b" = READY_FOR_ACCEPTANCE ]; then
            [ "$(zap_sql_count "$node" "SELECT count(*) FROM build_receipts WHERE action_id IN ('$action_a','$action_b') AND trust_state IN ('REMOTE_OBSERVED','QUORUM_MATCHED')")" -eq 2 ] ||
                dht_die "standard readiness did not retain both reproduction receipts"
            return 0
        fi
        zap_assert_responsive "$node" "pending-reproduction-$action_a"
        sleep 1
    done
    return 1
}

zap_evidence_output() {
    local node="$1" action="$2" evidence
    evidence="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" zcode evidence \
        --input="{\"workspace\":\"$ZAP_PROJECT\",\"datadir\":\"${DDS[$node]}\",\"action_id\":\"$action\"}" || true)"
    [ "$(printf '%s' "$evidence" | zap_field ok False 2>/dev/null || true)" = True ] ||
        dht_die "node $node could not evaluate reproduction output: $evidence"
    printf '%s' "$evidence" | zap_field data.output_root
}

zap_sql_count() {
    local node="$1" sql="$2" out
    out="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
        core storage query --sql="$sql" 2>/dev/null || true)"
    printf '%s' "$out" | zap_field data.rows.0.0 2>/dev/null || printf '%s' -1
}

zap_sql_value() {
    local node="$1" sql="$2" out
    out="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
        core storage query --sql="$sql" 2>/dev/null || true)"
    printf '%s' "$out" | zap_field data.rows.0.0 2>/dev/null || true
}

zap_approve_action_receipt() {
    local requester="$1" action="$2" identity worker pubkey response ok changed
    identity="$(zap_sql_value "$requester" "SELECT r.worker_id||':'||w.signer_pubkey FROM build_receipts r JOIN build_workers w ON w.worker_id=r.worker_id WHERE r.action_id='$action' AND r.trust_state='REMOTE_OBSERVED' AND w.approved=0 AND w.revoked=0 LIMIT 1")"
    [ -n "$identity" ] || return 1
    worker="${identity%%:*}"; pubkey="${identity#*:}"
    [ "${#worker}" -eq 64 ] && [ "${#pubkey}" -eq 64 ] ||
        dht_die "action $action did not project its exact remote signer"
    response="$(dht_native "${DDS[$requester]}" "${RPCS[$requester]}" \
        metaverse build worker approve \
        --input="{\"worker_id\":\"$worker\",\"signer_pubkey\":\"$pubkey\",\"capabilities\":\"p2p-approved,c23.package.recipe.v1\",\"datadir\":\"${DDS[$requester]}\"}" || true)"
    ok="$(printf '%s' "$response" | zap_field ok False 2>/dev/null || true)"
    [ "$ok" = True ] || dht_die "requester $requester refused action $action signer approval: $response"
    changed="$(printf '%s:%s:%s' \
        "$(printf '%s' "$response" | zap_field data.worker_id)" \
        "$(printf '%s' "$response" | zap_field data.signer_pubkey)" \
        "$(printf '%s' "$response" | zap_field data.approved)")"
    [ "$changed" = "$worker:$pubkey:True" ] ||
        dht_die "approval response did not name the exact worker owning action $action: $response"
}

zap_assert_requester_did_not_execute() {
    local requester="$1" action="$2"
    [ "$(zap_sql_count "$requester" "SELECT count(*) FROM build_actions WHERE action_id='$action' AND state='SNAPSHOTTED' AND attempt_count=0 AND started_at=0 AND length(worker_id)=0")" -eq 1 ] ||
        dht_die "requester $requester raced peer execution for $action"
}

zap_assert_responsive() {
    local node="$1" phase="$2" started_ms response elapsed_ms
    started_ms="$(date +%s%3N)"
    response="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" status || true)"
    elapsed_ms=$(( $(date +%s%3N) - started_ms ))
    [ -n "$response" ] && [ "$elapsed_ms" -lt 5000 ] ||
        dht_die "requester $node stopped responding during $phase (${elapsed_ms}ms): $response"
    if [ -n "${ZAP_A_DB_IDENTITIES:-}" ] && [ "$node" = "${ZAP_A:-}" ]; then
        [ -n "${A_ORIGINAL_PID:-}" ] &&
        [ "${PIDS[$node]:-}" = "$A_ORIGINAL_PID" ] &&
        kill -0 "$A_ORIGINAL_PID" 2>/dev/null ||
            dht_die "requester $node process identity changed during $phase: expected_pid=${A_ORIGINAL_PID:-missing} actual_pid=${PIDS[$node]:-missing}"
        zap_assert_db_identity "$node" "$phase"
    fi
    printf '%s,%s\n' "$phase" "$elapsed_ms" >>"$DHT_WORK/async-requester-responsiveness.csv"
}

zap_db_identity() {
    local node="$1" dd
    dd="${DDS[$node]}"
    stat -Lc '%d:%i' "$dd/node.db" "$dd/node.db-wal" "$dd/node.db-shm" \
        2>/dev/null | paste -sd, -
}

zap_assert_db_identity() {
    local node="$1" phase="$2" current
    current="$(zap_db_identity "$node" || true)"
    [ -n "$current" ] && [ "$current" = "$ZAP_A_DB_IDENTITIES" ] ||
        dht_die "requester $node database/WAL identity changed during $phase: expected=$ZAP_A_DB_IDENTITIES actual=$current"
    ! ls -l "/proc/${PIDS[$node]}/fd" 2>/dev/null |
        grep -Eq 'node\.db(-wal|-shm)? \(deleted\)' ||
        dht_die "requester $node retained a deleted live database descriptor during $phase"
}

zap_assert_db_lifetime_clean() {
    local node="$1" phase="$2" log
    log="${DDS[$node]}/node.log"
    zap_assert_db_identity "$node" "$phase"
    [ "$(zap_sql_count "$node" 'SELECT 1')" -eq 1 ] ||
        dht_die "requester $node could not read its live database after $phase"
    ! grep -aEq 'unauthorized=1|DATABASE_OWNERSHIP_CONFLICT|disk I/O error' \
        "$log" ||
        dht_die "requester $node recorded an unauthorized database lifecycle event during $phase"
}

zap_latest_state() {
    local node="$1" action="$2" sql out
    sql="SELECT state FROM build_proof_events WHERE action_id='$action' ORDER BY rowid DESC LIMIT 1"
    out="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
        core storage query --sql="$sql" 2>/dev/null || true)"
    printf '%s' "$out" | zap_field data.rows.0.0 2>/dev/null || true
}

zap_wait_ready() {
    local node="$1" action="$2" deadline state bound
    deadline=$(( $(date +%s) + 180 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        state="$(zap_latest_state "$node" "$action")"
        if [ "$state" = READY_FOR_ACCEPTANCE ]; then
            bound="$(zap_sql_count "$node" "SELECT count(*) FROM build_receipts r JOIN build_workers w ON w.worker_id=r.worker_id WHERE r.action_id='$action' AND r.trust_state IN ('REMOTE_OBSERVED','QUORUM_MATCHED') AND w.approved=1 AND w.revoked=0 AND r.worker_id=w.worker_id")"
            [ "$bound" -eq 1 ] ||
                dht_die "readiness was not owned by the exact approved receipt worker for $action"
            return 0
        fi
        # Approval is selected from the canonical action receipt on every
        # observation. Once that exact worker is approved, the query returns
        # no row and this is a no-op; there is no harness-side lifecycle bit.
        zap_approve_action_receipt "$node" "$action" || true
        zap_assert_responsive "$node" "pending-$action"
        sleep 1
    done
    return 1
}

zap_wait_executor_started() {
    local node="$1" action="$2" deadline count accepted
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        count="$(zap_sql_count "$node" "SELECT count(*) FROM build_actions WHERE action_id='$action' AND started_at>0 AND state IN ('RUNNING','VERIFYING')")"
        [ "$count" -eq 1 ] 2>/dev/null && return 0
        accepted="$(zap_sql_count "$node" "SELECT count(*) FROM build_actions WHERE action_id='$action' AND state IN ('ACCEPTED','CACHE_HIT','FAILED')")"
        [ "$accepted" -eq 0 ] 2>/dev/null || return 2
        sleep 0.1
    done
    return 1
}

zap_stop_executor_mid_action() {
    local node="$1" deadline child
    deadline=$(( $(date +%s) + 90 ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        child="$(pgrep -P "${PIDS[$node]}" | head -1 || true)"
        if [ -n "$child" ]; then
            kill -STOP "-${PIDS[$node]}" ||
                dht_die "could not stop executor $node with live action child $child"
            return 0
        fi
        sleep 0.01
    done
    return 1
}

zap_assert_evidence() {
    local node="$1" action="$2" evidence
    evidence="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" zcode evidence \
        --input="{\"workspace\":\"$ZAP_PROJECT\",\"datadir\":\"${DDS[$node]}\",\"action_id\":\"$action\"}")"
    printf '%s\n' "$evidence" >"$DHT_WORK/async-evidence-$action.json"
    "$DHT_ACCEPTANCE_C23" evidence-check "$evidence" ||
        dht_die "async timing/evidence report was incomplete: $evidence"
    local bound mismatched
    bound="$(zap_sql_count "$node" "SELECT count(*) FROM build_proof_events e JOIN build_actions a ON a.action_id=e.action_id JOIN build_jobs j ON j.job_id=a.job_id WHERE e.action_id='$action' AND length(e.source_root_sha3)=64 AND e.source_root_sha3=j.source_cas_sha3")"
    mismatched="$(zap_sql_count "$node" "SELECT count(*) FROM build_proof_events e JOIN build_actions a ON a.action_id=e.action_id JOIN build_jobs j ON j.job_id=a.job_id WHERE e.action_id='$action' AND e.source_root_sha3<>j.source_cas_sha3")"
    [ "$bound" -ge 8 ] && [ "$mismatched" -eq 0 ] ||
        dht_die "async events lost direct source-root binding for $action"
}

zap_assert_same_action_identity() {
    local requester="$1" executor="$2" action="$3" sql requester_id executor_id
    sql="SELECT a.task_root_sha3||':'||a.candidate_root_sha3||':'||j.source_cas_sha3||':'||a.input_root_sha3||':'||j.toolchain_sha3 FROM build_actions a JOIN build_jobs j ON j.job_id=a.job_id WHERE a.action_id='$action'"
    requester_id="$(zap_sql_value "$requester" "$sql")"
    executor_id="$(zap_sql_value "$executor" "$sql")"
    [ -n "$requester_id" ] && [ "$requester_id" = "$executor_id" ] ||
        dht_die "executor $executor did not receive the exact immutable identity for $action"
}

zap_assert_receipt_bindings() {
    local requester="$1" executor="$2" action="$3" bad total lease_bound
    total="$(zap_sql_count "$requester" "SELECT count(*) FROM build_receipts WHERE action_id='$action'")"
    bad="$(zap_sql_count "$requester" "SELECT count(*) FROM build_receipts r JOIN build_actions a ON a.action_id=r.action_id JOIN build_jobs j ON j.job_id=a.job_id JOIN build_workers w ON w.worker_id=r.worker_id WHERE r.action_id='$action' AND (r.job_id<>a.job_id OR r.action_sha3<>a.action_id OR length(a.task_root_sha3)<>64 OR length(a.candidate_root_sha3)<>64 OR length(j.source_cas_sha3)<>64 OR length(a.input_root_sha3)<>64 OR length(a.proof_policy_root_sha3)<>64 OR length(j.toolchain_sha3)<>64 OR length(r.worker_id)<>64 OR length(w.signer_pubkey)<>64 OR length(r.lease_id)<>64 OR length(r.output_sha3)<>64 OR length(r.work_receipt_sha3)<>64 OR length(r.signature)<>128 OR length(r.confinement)=0)")"
    [ "$total" -ge 1 ] && [ "$bad" -eq 0 ] ||
        dht_die "requester receipt projection lost an exact authority binding for $action"
    lease_bound="$(zap_sql_count "$executor" "SELECT count(*) FROM build_receipts r JOIN build_actions a ON a.action_id=r.action_id JOIN build_jobs j ON j.job_id=a.job_id JOIN build_workers w ON w.worker_id=r.worker_id WHERE r.action_id='$action' AND r.job_id=a.job_id AND r.action_sha3=a.action_id AND r.lease_id=a.lease_id AND r.output_sha3=a.output_root_sha3 AND length(a.task_root_sha3)=64 AND length(a.candidate_root_sha3)=64 AND length(j.source_cas_sha3)=64 AND length(a.input_root_sha3)=64 AND length(a.proof_policy_root_sha3)=64 AND length(j.toolchain_sha3)=64 AND length(w.signer_pubkey)=64 AND length(r.signature)=128")"
    [ "$lease_bound" -ge 1 ] ||
        dht_die "executor receipt did not bind its exact action lease/output for $action"
}

zap_assert_exact_reuse() {
    local requester="$1" executor="$2" action="$3" work="$4"
    local before_attempts before_actions before_requests before_receipts result ok state
    before_attempts="$(zap_sql_count "$executor" "SELECT attempt_count FROM build_actions WHERE action_id='$action'")"
    before_actions="$(zap_sql_count "$requester" "SELECT count(*) FROM build_actions WHERE action_id='$action'")"
    before_requests="$(zap_sql_count "$requester" "SELECT count(*) FROM build_proof_events WHERE action_id='$action' AND state='REQUESTED'")"
    before_receipts="$(zap_sql_count "$requester" "SELECT count(*) FROM build_receipts WHERE action_id='$action'")"
    result="$(dht_native "${DDS[$requester]}" "${RPCS[$requester]}" zcode work run \
        --input="{\"workspace\":\"$ZAP_PROJECT\",\"work\":\"$work\",\"adapter\":\"manual\",\"datadir\":\"${DDS[$requester]}\"}" || true)"
    ok="$(printf '%s' "$result" | zap_field ok False 2>/dev/null || true)"
    state="$(printf '%s' "$result" | zap_field data.state 2>/dev/null || true)"
    [ "$ok" = True ] && [ "$state" = EVIDENCE_READY ] ||
        dht_die "exact reuse did not resolve through the canonical task projection: $result"
    [ "$(zap_sql_count "$executor" "SELECT attempt_count FROM build_actions WHERE action_id='$action'")" -eq "$before_attempts" ] &&
    [ "$(zap_sql_count "$requester" "SELECT count(*) FROM build_actions WHERE action_id='$action'")" -eq "$before_actions" ] &&
    [ "$(zap_sql_count "$requester" "SELECT count(*) FROM build_proof_events WHERE action_id='$action' AND state='REQUESTED'")" -eq "$before_requests" ] &&
    [ "$(zap_sql_count "$requester" "SELECT count(*) FROM build_receipts WHERE action_id='$action'")" -eq "$before_receipts" ] ||
        dht_die "exact action reuse scheduled duplicate computation for $action"
    printf '%s\n' 1 >>"$DHT_WORK/async-exact-reuse-eliminated.txt"
}

zap_dump_failure() {
    local node="$1" action="$2" sql
    sql="SELECT state,peer_id,deadline_at,elapsed_us,event_root FROM build_proof_events WHERE action_id='$action' ORDER BY rowid"
    dht_note "async proof lifecycle: $(dht_native "${DDS[$node]}" \
        "${RPCS[$node]}" core storage query --sql="$sql" 2>/dev/null || true)"
    dht_note "async proof log tail follows"
    tail -80 "${DDS[$node]}/node.log" >&2 || true
}

zap_start_node() {
    local node="$1" connect="${2:-}"
    if [ -n "$connect" ]; then
        dht_spawn "PIDS[$node]" "${DDS[$node]}" "${PORTS[$node]}" \
            "${RPCS[$node]}" "${FSPORTS[$node]}" "${HTTPSPORTS[$node]}" \
            "127.0.0.1:${PORTS[$connect]}"
    else
        dht_spawn "PIDS[$node]" "${DDS[$node]}" "${PORTS[$node]}" \
            "${RPCS[$node]}" "${FSPORTS[$node]}" "${HTTPSPORTS[$node]}" \
            "127.0.0.1:$DEAD_SINK"
    fi
    dht_wait_rpc "${DDS[$node]}" "${RPCS[$node]}" "${PIDS[$node]}" ||
        dht_die "async proof node $node failed to start"
}

zap_cancel_find_capability() {
    local node="$1" lookup_id="$2" owner_token="$3" result ok code
    [ "${#lookup_id}" -eq 32 ] && [ "${#owner_token}" -eq 32 ] ||
        dht_die "async proof lookup cleanup received an invalid capability"
    result="$(dht_native "${DDS[$node]}" "${RPCS[$node]}" \
        zcode network find cancel \
        --input="{\"lookup_id\":\"$lookup_id\",\"owner_token\":\"$owner_token\"}" || true)"
    ok="$(printf '%s' "$result" | dht_jget ok False 2>/dev/null || true)"
    code="$(printf '%s' "$result" | dht_jget error.code '' 2>/dev/null || true)"
    # Expiry cleanup cancels the service lookup before reporting the public
    # capability unknown. Both outcomes prove this client retains no slot.
    [ "$ok" = True ] || [ "$code" = LOOKUP_UNKNOWN ] ||
        dht_die "async proof lookup cleanup failed: $result"
}

zap_connect() {
    local from="$1" to="$2" deadline status_from status_to
    local enabled_from enabled_to find_result find_ok
    local auth_from auth_to accepted_from accepted_to started rearmed
    local lookup_id owner_token cleanup_index
    local -a cleanup_nodes=() cleanup_ids=() cleanup_owners=()
    case "${ZAP_CONNECT_SKIP_ONETRY:-0}" in
        0)
            dht_rpc "${DDS[$from]}" "${RPCS[$from]}" addnode \
                "\"127.0.0.1:${PORTS[$to]}\"" '"onetry"' >/dev/null || true
            ;;
        1) ;;
        *) dht_die "invalid ZAP_CONNECT_SKIP_ONETRY value" ;;
    esac
    case "${ZAP_CONNECT_DIRECTED_REARM:-0}" in
        0|1) ;;
        *) dht_die "invalid ZAP_CONNECT_DIRECTED_REARM value" ;;
    esac

    # P2P addnode establishes the transport path, but contacts.v2 is
    # authenticated HISTORY rather than current DHT reachability.  Admit an
    # actual lookup so a freshly restarted composition root resolves the
    # peer's accepted ZENDP record and performs a new Noise/delegation
    # exchange.  Without demand, this helper merely waited for unrelated
    # background package work to happen to open the overlay connection.
    # RPC readiness precedes composition-root startup.  Wait for the DHT to
    # be enabled so the lookup cannot be honestly refused as unavailable and
    # then leave the authentication wait with no admitted demand to service.
    enabled_from=False
    enabled_to=False
    deadline=$(( $(date +%s) + DHT_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        status_from="$(dht_status "${DDS[$from]}" "${RPCS[$from]}" 2>/dev/null || true)"
        status_to="$(dht_status "${DDS[$to]}" "${RPCS[$to]}" 2>/dev/null || true)"
        enabled_from="$(printf '%s' "$status_from" | dht_jget data.enabled False 2>/dev/null || true)"
        enabled_to="$(printf '%s' "$status_to" | dht_jget data.enabled False 2>/dev/null || true)"
        [ "$enabled_from" = True ] && [ "$enabled_to" = True ] && break
        sleep 0.5
    done
    [ "$enabled_from" = True ] ||
        dht_die "async proof node $from DHT did not enable"
    [ "$enabled_to" = True ] ||
        dht_die "async proof node $to DHT did not enable"
    find_result="$(dht_native "${DDS[$from]}" "${RPCS[$from]}" \
        zcode network find begin \
        --input="{\"node_id\":\"${NODES[$to]}\"}" || true)"
    find_ok="$(printf '%s' "$find_result" | dht_jget ok False 2>/dev/null || true)"
    [ "$find_ok" = True ] ||
        dht_die "async proof lookup $from/$to was not admitted: $find_result"
    lookup_id="$(printf '%s' "$find_result" | dht_jget data.lookup_id '')"
    owner_token="$(printf '%s' "$find_result" | dht_jget data.owner_token '')"
    cleanup_nodes+=("$from")
    cleanup_ids+=("$lookup_id")
    cleanup_owners+=("$owner_token")

    # Capability learning deliberately tears down the first plaintext P2P
    # connection and replaces it with Noise. A lookup admitted in that small
    # interval is correctly bounded, but its reachability request belonged to
    # the retired transport and is not replayed automatically. Observe both
    # peers jointly and re-arm one fresh lookup after the transport transition
    # has had time to settle. The verdict remains fail-closed on an actual
    # authenticated session plus an accepted frame at both ends.
    started="$(date +%s)"
    deadline=$((started + DHT_WAIT))
    rearmed=0
    while [ "$(date +%s)" -lt "$deadline" ]; do
        status_from="$(dht_status "${DDS[$from]}" "${RPCS[$from]}" 2>/dev/null || true)"
        status_to="$(dht_status "${DDS[$to]}" "${RPCS[$to]}" 2>/dev/null || true)"
        auth_from="$(printf '%s' "$status_from" | dht_jget data.connected_authenticated 0 2>/dev/null || true)"
        auth_to="$(printf '%s' "$status_to" | dht_jget data.connected_authenticated 0 2>/dev/null || true)"
        accepted_from="$(printf '%s' "$status_from" | dht_jget data.frames_accepted 0 2>/dev/null || true)"
        accepted_to="$(printf '%s' "$status_to" | dht_jget data.frames_accepted 0 2>/dev/null || true)"
        if [ "${auth_from:-0}" -ge 1 ] && [ "${auth_to:-0}" -ge 1 ] &&
           [ "${accepted_from:-0}" -ge 1 ] && [ "${accepted_to:-0}" -ge 1 ]; then
            for cleanup_index in "${!cleanup_ids[@]}"; do
                zap_cancel_find_capability \
                    "${cleanup_nodes[$cleanup_index]}" \
                    "${cleanup_ids[$cleanup_index]}" \
                    "${cleanup_owners[$cleanup_index]}"
            done
            return 0
        fi
        if [ "$rearmed" -eq 0 ] &&
           [ $(( $(date +%s) - started )) -ge 3 ]; then
            find_result="$(dht_native "${DDS[$from]}" "${RPCS[$from]}" \
                zcode network find begin \
                --input="{\"node_id\":\"${NODES[$to]}\"}" 2>/dev/null || true)"
            find_ok="$(printf '%s' "$find_result" | dht_jget ok False 2>/dev/null || true)"
            if [ "$find_ok" = True ]; then
                lookup_id="$(printf '%s' "$find_result" | dht_jget data.lookup_id '')"
                owner_token="$(printf '%s' "$find_result" | dht_jget data.owner_token '')"
                cleanup_nodes+=("$from")
                cleanup_ids+=("$lookup_id")
                cleanup_owners+=("$owner_token")
            fi
            if [ "${ZAP_CONNECT_DIRECTED_REARM:-0}" = 0 ]; then
                find_result="$(dht_native "${DDS[$to]}" "${RPCS[$to]}" \
                    zcode network find begin \
                    --input="{\"node_id\":\"${NODES[$from]}\"}" 2>/dev/null || true)"
                find_ok="$(printf '%s' "$find_result" | dht_jget ok False 2>/dev/null || true)"
                if [ "$find_ok" = True ]; then
                    lookup_id="$(printf '%s' "$find_result" | dht_jget data.lookup_id '')"
                    owner_token="$(printf '%s' "$find_result" | dht_jget data.owner_token '')"
                    cleanup_nodes+=("$to")
                    cleanup_ids+=("$lookup_id")
                    cleanup_owners+=("$owner_token")
                fi
            fi
            rearmed=1
        fi
        sleep 0.5
    done
    for cleanup_index in "${!cleanup_ids[@]}"; do
        zap_cancel_find_capability "${cleanup_nodes[$cleanup_index]}" \
            "${cleanup_ids[$cleanup_index]}" \
            "${cleanup_owners[$cleanup_index]}"
    done
    dht_die "async proof nodes $from/$to did not authenticate "\
"(from auth=${auth_from:-0} accepted=${accepted_from:-0}; "\
"to auth=${auth_to:-0} accepted=${accepted_to:-0})"
}

# The scaling campaign sources these canonical helpers after the same seven-
# identity bootstrap.  Returning here keeps one implementation of action,
# receipt, responsiveness, and database-lifetime assertions without making
# either harness a source of proof lifecycle truth.
if [ "${ZAP_HELPERS_ONLY:-0}" = 1 ]; then
    return 0
fi

ZAP_PROJECT="$DHT_WORK/async-proof-project"
mkdir -p "$ZAP_PROJECT/src" "$ZAP_PROJECT/include" "$ZAP_PROJECT/tests"
printf '%s\n' 'MIT' >"$ZAP_PROJECT/LICENSE"
printf '%s\n' 'int x(void);' >"$ZAP_PROJECT/include/x.h"
printf '%s\n' 'int main(void) { return 0; }' >"$ZAP_PROJECT/tests/test.c"
printf '%s\n' '{"schema":1,"name":"acceptance/async-proof","semver":"0.1.0","language":"c23","license":"MIT","include_dir":"include","source_dir":"src","dependencies":[]}' >"$ZAP_PROJECT/zcode-package.json"
zap_write_source "$ZAP_PROJECT/src/x.c" 1

# Keep the central SQLite/VFS ownership ledger enabled for every node started
# by this composed phase. A clean run must contain no unauthorized lifecycle
# owner; a failure retains exact open/close/delete callers in the artifact.
export ZCL_DB_LIFETIME_TRACE=1

# Collapse the prior discovery fixture to four full-node processes. B first
# exercises package import with execution disabled by local policy; A, C and D
# keep the same binary and C/D advertise the existing confined worker.
ZAP_A="$ORIGIN"; ZAP_B="$NEXT"; ZAP_C="$TARGET"
ZAP_D=""
for i in 0 1 2 3 4 5 6; do
    if [ "$i" != "$ZAP_A" ] && [ "$i" != "$ZAP_B" ] &&
       [ "$i" != "$ZAP_C" ]; then
        ZAP_D="$i"
        break
    fi
done
[ -n "$ZAP_D" ] || dht_die "async proof could not allocate a fourth identity"
zap_allow_context_policy "$ZAP_A"
zap_allow_context_policy "$ZAP_B"
for i in 0 1 2 3 4 5 6; do
    dht_kill_group "${PIDS[$i]:-}"; PIDS[$i]=""
done
DHT_PGID_A=""; DHT_PGID_B=""

SAVED_BUILDWORKERS="$DHT_BUILDWORKERS"
DHT_BUILDWORKERS=0
zap_start_node "$ZAP_B"
DHT_BUILDWORKERS="$SAVED_BUILDWORKERS"
zap_start_node "$ZAP_C"
zap_start_node "$ZAP_D"
zap_start_node "$ZAP_A" "$ZAP_C"
zap_connect "$ZAP_A" "$ZAP_D"
zap_connect "$ZAP_A" "$ZAP_B"
A_ORIGINAL_PID="${PIDS[$ZAP_A]}"
ZAP_A_DB_IDENTITIES="$(zap_db_identity "$ZAP_A" || true)"
[ -n "$ZAP_A_DB_IDENTITIES" ] ||
    dht_die "A did not expose stable node.db/WAL/SHM identities after boot"
zap_assert_responsive "$ZAP_A" "before-standard-reproduction"

dht_note "async proof: B imports inert bytes while C and D reproduce one standard candidate"
zap_submit "$ZAP_A" 6 "Change x to six for independent reproduction" 600 standard
STANDARD_ACTION="$ZAP_ACTION"; STANDARD_REPRO_ACTION="$ZAP_REPRO_ACTION"
STANDARD_MS="$ZAP_FOREGROUND_MS"
if [ -n "${ZAP_PROGRESS_OBSERVER:-}" ]; then
    declare -F "$ZAP_PROGRESS_OBSERVER" >/dev/null ||
        dht_die "configured standard progress observer is unavailable"
    "$ZAP_PROGRESS_OBSERVER" "$ZAP_A" "$STANDARD_ACTION" submitted
fi
STANDARD_CONTEXT="$(zap_wait_context_root "$ZAP_A" "$STANDARD_ACTION")" ||
    dht_die "standard action never bound its content carrier"
zap_publish_context_provider "$ZAP_A" "$STANDARD_CONTEXT"
zap_fetch_inert_context "$ZAP_B" "$STANDARD_CONTEXT" \
    "$STANDARD_ACTION" "$STANDARD_REPRO_ACTION"
zap_wait_reproduction_ready "$ZAP_A" "$STANDARD_ACTION" \
    "$STANDARD_REPRO_ACTION" || {
        zap_dump_failure "$ZAP_A" "$STANDARD_ACTION"
        zap_dump_failure "$ZAP_A" "$STANDARD_REPRO_ACTION"
        dht_die "C and D did not satisfy the standard reproduction policy"
    }
if [ -n "${ZAP_PROGRESS_OBSERVER:-}" ]; then
    "$ZAP_PROGRESS_OBSERVER" "$ZAP_A" "$STANDARD_ACTION" ready
fi

C_STANDARD_ACTION="$(zap_sql_value "$ZAP_C" "SELECT action_id FROM build_actions WHERE action_id IN ('$STANDARD_ACTION','$STANDARD_REPRO_ACTION') AND state IN ('ACCEPTED','CACHE_HIT')")"
D_STANDARD_ACTION="$(zap_sql_value "$ZAP_D" "SELECT action_id FROM build_actions WHERE action_id IN ('$STANDARD_ACTION','$STANDARD_REPRO_ACTION') AND state IN ('ACCEPTED','CACHE_HIT')")"
[ "${#C_STANDARD_ACTION}" -eq 64 ] && [ "${#D_STANDARD_ACTION}" -eq 64 ] &&
[ "$C_STANDARD_ACTION" != "$D_STANDARD_ACTION" ] ||
    dht_die "standard reproduction did not execute once each on C and D"
[ "$(zap_sql_count "$ZAP_C" "SELECT count(*) FROM build_actions WHERE action_id IN ('$STANDARD_ACTION','$STANDARD_REPRO_ACTION') AND attempt_count=1")" -eq 1 ] &&
[ "$(zap_sql_count "$ZAP_D" "SELECT count(*) FROM build_actions WHERE action_id IN ('$STANDARD_ACTION','$STANDARD_REPRO_ACTION') AND attempt_count=1")" -eq 1 ] ||
    dht_die "C or D executed more than its one independent reproduction action"
C_OUTPUT="$(zap_evidence_output "$ZAP_C" "$C_STANDARD_ACTION")"
D_OUTPUT="$(zap_evidence_output "$ZAP_D" "$D_STANDARD_ACTION")"
[ "${#C_OUTPUT}" -eq 64 ] && [ "$C_OUTPUT" = "$D_OUTPUT" ] ||
    dht_die "C/D standard artifact roots disagree: C=$C_OUTPUT D=$D_OUTPUT"
[ "$(zap_sql_count "$ZAP_A" "SELECT count(DISTINCT r.worker_id) FROM build_receipts r WHERE r.action_id IN ('$STANDARD_ACTION','$STANDARD_REPRO_ACTION')")" -eq 2 ] &&
[ "$(zap_sql_count "$ZAP_A" "SELECT count(DISTINCT w.signer_pubkey) FROM build_receipts r JOIN build_workers w ON w.worker_id=r.worker_id WHERE r.action_id IN ('$STANDARD_ACTION','$STANDARD_REPRO_ACTION')")" -eq 2 ] ||
    dht_die "standard reproduction evidence did not retain two independent signers"
[ "$(zap_sql_count "$ZAP_B" "SELECT count(*) FROM build_actions WHERE action_id IN ('$STANDARD_ACTION','$STANDARD_REPRO_ACTION')")" -eq 0 ] &&
[ "$(zap_sql_count "$ZAP_B" "SELECT count(*) FROM build_receipts WHERE action_id IN ('$STANDARD_ACTION','$STANDARD_REPRO_ACTION')")" -eq 0 ] ||
    dht_die "B's inert package import acquired execution or evidence authority"
cmp -s "${DDS[$ZAP_C]}/zcode/build-worker.ed25519" \
       "${DDS[$ZAP_D]}/zcode/build-worker.ed25519" &&
    dht_die "C and D unexpectedly shared a worker signing secret"
for non_signer in "$ZAP_A" "$ZAP_B"; do
    ! cmp -s "${DDS[$non_signer]}/zcode/build-worker.ed25519" \
        "${DDS[$ZAP_C]}/zcode/build-worker.ed25519" &&
    ! cmp -s "${DDS[$non_signer]}/zcode/build-worker.ed25519" \
        "${DDS[$ZAP_D]}/zcode/build-worker.ed25519" ||
        dht_die "A/B held a C/D reproduction signing secret"
done
zap_assert_same_action_identity "$ZAP_A" "$ZAP_C" "$C_STANDARD_ACTION"
zap_assert_same_action_identity "$ZAP_A" "$ZAP_D" "$D_STANDARD_ACTION"
zap_assert_receipt_bindings "$ZAP_A" "$ZAP_C" "$C_STANDARD_ACTION"
zap_assert_receipt_bindings "$ZAP_A" "$ZAP_D" "$D_STANDARD_ACTION"
zap_assert_requester_did_not_execute "$ZAP_A" "$STANDARD_ACTION"
zap_assert_requester_did_not_execute "$ZAP_A" "$STANDARD_REPRO_ACTION"
zap_assert_db_lifetime_clean "$ZAP_A" "four-node package reproduction"

# Exercise worker-owned one-slot admission with two independent requesters.
# Both initially see B's signed headroom hint. B atomically grants one action,
# names the other BUSY, and the existing requester-local projection reroutes
# the loser to D without waiting for the original lease deadline.
for node in "$ZAP_A" "$ZAP_B" "$ZAP_C" "$ZAP_D"; do
    dht_kill_group "${PIDS[$node]:-}"; PIDS[$node]=""
done
# Retained discovery is deliberately isolated for all four cleanly stopped
# nodes. `-connect` does not disable the C23 reachability dialer, so leaving
# even one node's old projection in place creates an undeclared edge and makes
# worker choice depend on fixture history. Identity, worker key, package CAS,
# chain, node database, and canonical listener addresses remain untouched.
# Runtime projections are moved aside before the originals are restored; this
# makes fixture cleanup copy-preserving and prevents a recreated empty file
# from overwriting pre-race state.
zap_quarantine_discovery() {
    local node="$1" q="$2" rel key path
    mkdir -p "$q"
    for rel in peers.dat peers.dat.sha3 contacts_projection.db \
               zcode/dht/contacts.v2 zcode/endpoints; do
        key="${rel//\//__}"
        path="${DDS[$node]}/$rel"
        [ ! -e "$path" ] || mv "$path" "$q/original-$key"
    done
}

zap_restore_discovery() {
    local node="$1" q="$2" rel key path
    for rel in peers.dat peers.dat.sha3 contacts_projection.db \
               zcode/dht/contacts.v2 zcode/endpoints; do
        key="${rel//\//__}"
        path="${DDS[$node]}/$rel"
        [ ! -e "$path" ] || mv "$path" "$q/runtime-$key"
        [ ! -e "$q/original-$key" ] || mv "$q/original-$key" "$path"
    done
}

RACE_DISCOVERY_QUARANTINE="$DHT_WORK/async-admission-discovery"
for node in "$ZAP_A" "$ZAP_B" "$ZAP_C" "$ZAP_D"; do
    zap_quarantine_discovery "$node" "$RACE_DISCOVERY_QUARANTINE/$node"
done
zap_start_node "$ZAP_B"
zap_start_node "$ZAP_D"
SAVED_BUILDWORKERS="$DHT_BUILDWORKERS"
DHT_BUILDWORKERS=0
zap_start_node "$ZAP_A"
zap_start_node "$ZAP_C"
DHT_BUILDWORKERS="$SAVED_BUILDWORKERS"
# This is an explicit clean phase transition, so the new resident process and
# its new SQLite sidecar generation become the race phase's ownership
# baseline.  Keeping the prior phase's inode/PID would falsely report the
# deliberate restart as a mid-action lifecycle violation.
A_ORIGINAL_PID="${PIDS[$ZAP_A]}"
ZAP_A_DB_IDENTITIES="$(zap_db_identity "$ZAP_A" || true)"
[ -n "$ZAP_A_DB_IDENTITIES" ] ||
    dht_die "A did not expose stable database identities for one-slot race"
RACE_A="$DHT_WORK/async-admission-race-a.txt"
RACE_C="$DHT_WORK/async-admission-race-c.txt"
# Candidate/action creation is requester-local factory work.  Keep it outside
# concurrent processes: two processes deriving the same checkout's mutable
# code-index/VCS projections would test shared-workspace tooling, not atomic
# worker admission. C authenticates while idle; its action is created only
# after B durably reports A as RUNNING, so connection setup cannot consume the
# occupied-slot window and correctness still follows from state, not a delay.
zap_connect "$ZAP_C" "$ZAP_B"
zap_submit_capture "$ZAP_A" 21 "One-slot race from requester A" "$RACE_A" 1800 1
RACE_A_ACTION="$(sed -n '1p' "$RACE_A")"
[ "${#RACE_A_ACTION}" -eq 64 ] ||
    dht_die "one-slot race did not create A's immutable action"
RACE_STARTED_MS="$(date +%s%3N)"
# Make B's first immutable action observably RUNNING before the second
# requester offers its distinct action.  This is state-driven contention, not
# a sleep: C remains independently live with an outstanding immutable action
# while A owns B's sole slot.
zap_connect "$ZAP_A" "$ZAP_B"
zap_wait_executor_running "$ZAP_B" "$RACE_A_ACTION" ||
    dht_die "B never durably entered RUNNING for its granted slot (last_state=$ZAP_WAIT_ACTION_STATE)"
zap_submit_capture "$ZAP_C" 22 "One-slot race from requester C" "$RACE_C" 1800 1
RACE_C_ACTION="$(sed -n '1p' "$RACE_C")"
[ "${#RACE_C_ACTION}" -eq 64 ] && [ "$RACE_A_ACTION" != "$RACE_C_ACTION" ] ||
    dht_die "one-slot race did not create C's distinct immutable action"
printf 'A=%s B=%s C=%s D=%s\nA_action=%s\nC_action=%s\n' \
    "$ZAP_A" "$ZAP_B" "$ZAP_C" "$ZAP_D" \
    "$RACE_A_ACTION" "$RACE_C_ACTION" \
    >"$DHT_WORK/async-admission-race-identities.txt"
zap_wait_named_busy "$ZAP_C" "$RACE_C_ACTION" ||
    dht_die "B did not issue C a named BUSY refusal while A held its slot"
# D becomes eligible only after the BUSY fact is requester-locally projected.
# This explicit authenticated edge is the first race-local fact that exposes
# it; authentication uses D's canonical address and identity.
zap_connect "$ZAP_C" "$ZAP_D"
zap_wait_ready "$ZAP_A" "$RACE_A_ACTION" ||
    dht_die "requester A's one-slot race action did not become ready"
zap_wait_ready "$ZAP_C" "$RACE_C_ACTION" ||
    dht_die "requester C's one-slot race action did not become ready"
B_RACE_ACTIONS="$(zap_sql_count "$ZAP_B" "SELECT count(*) FROM build_actions WHERE action_id IN ('$RACE_A_ACTION','$RACE_C_ACTION') AND state IN ('ACCEPTED','CACHE_HIT')")"
D_RACE_ACTIONS="$(zap_sql_count "$ZAP_D" "SELECT count(*) FROM build_actions WHERE action_id IN ('$RACE_A_ACTION','$RACE_C_ACTION') AND state IN ('ACCEPTED','CACHE_HIT')")"
[ "$B_RACE_ACTIONS" -eq 1 ] && [ "$D_RACE_ACTIONS" -eq 1 ] ||
    dht_die "one-slot race did not execute exactly once on B and once on D"
BUSY_COUNT="$(grep -hE 'disposition=BUSY .*reroute=1' \
    "${DDS[$ZAP_A]}/node.log" "${DDS[$ZAP_C]}/node.log" 2>/dev/null | \
    wc -l)"
[ "$BUSY_COUNT" -eq 1 ] ||
    dht_die "one-slot race did not produce exactly one named BUSY reroute"
RACE_REROUTE_SECONDS="$(
    for requester_action in "$ZAP_A:$RACE_A_ACTION" "$ZAP_C:$RACE_C_ACTION"; do
        requester="${requester_action%%:*}"
        action="${requester_action#*:}"
        zap_sql_value "$requester" "SELECT max(created_at)-min(created_at) FROM build_proof_events WHERE action_id='$action' AND state='PEER_DISCOVERED'"
    done | sort -nr | head -1
)"
[ -n "$RACE_REROUTE_SECONDS" ] && [ "$RACE_REROUTE_SECONDS" -le 5 ] ||
    dht_die "BUSY loser waited for lease expiry before reroute: ${RACE_REROUTE_SECONDS}s"
printf 'race_started_ms=%s\nadmission_reroute_max_ms=%s\nB_executions=%s\nD_executions=%s\n' \
    "$RACE_STARTED_MS" "$((RACE_REROUTE_SECONDS * 1000))" \
    "$B_RACE_ACTIONS" "$D_RACE_ACTIONS" \
    >"$DHT_WORK/async-admission-race-metrics.txt"
zap_assert_responsive "$ZAP_A" "one-slot-race-complete"
zap_assert_responsive "$ZAP_C" "one-slot-race-complete"

# Restart the original quick-profile sequence with every executor enabled.
for node in "$ZAP_A" "$ZAP_B" "$ZAP_C" "$ZAP_D"; do
    dht_kill_group "${PIDS[$node]:-}"; PIDS[$node]=""
done
for node in "$ZAP_A" "$ZAP_B" "$ZAP_C" "$ZAP_D"; do
    zap_restore_discovery "$node" "$RACE_DISCOVERY_QUARANTINE/$node"
done
zap_start_node "$ZAP_B"
zap_start_node "$ZAP_A" "$ZAP_B"
zap_connect "$ZAP_A" "$ZAP_B"
A_ORIGINAL_PID="${PIDS[$ZAP_A]}"
ZAP_A_DB_IDENTITIES="$(zap_db_identity "$ZAP_A" || true)"
[ -n "$ZAP_A_DB_IDENTITIES" ] ||
    dht_die "A did not expose stable database identities after reproduction"
zap_assert_responsive "$ZAP_A" "before-first-admission"

dht_note "async proof: A stays live while B executes the first fixed action"
zap_submit "$ZAP_A" 2 "Change x to two"
FIRST_ACTION="$ZAP_ACTION"; FIRST_WORK="$ZAP_WORK"; FIRST_MS="$ZAP_FOREGROUND_MS"
zap_assert_responsive "$ZAP_A" "after-first-admission"
zap_wait_ready "$ZAP_A" "$FIRST_ACTION" ||
    { zap_dump_failure "$ZAP_A" "$FIRST_ACTION";
      dht_die "A did not reach READY_FOR_ACCEPTANCE from B evidence"; }
[ "$(zap_sql_count "$ZAP_B" "SELECT count(*) FROM build_actions WHERE action_id='$FIRST_ACTION' AND state IN ('ACCEPTED','CACHE_HIT')")" -eq 1 ] ||
    dht_die "B did not independently execute A's first fixed action"
[ "$(zap_sql_count "$ZAP_B" "SELECT count(*) FROM build_actions WHERE action_id='$FIRST_ACTION' AND attempt_count=1")" -eq 1 ] &&
[ "$(zap_sql_count "$ZAP_A" "SELECT count(*) FROM build_proof_events WHERE action_id='$FIRST_ACTION' AND state='REQUESTED'")" -eq 1 ] ||
    dht_die "exact first request did not deduplicate to one execution/request"
zap_assert_requester_did_not_execute "$ZAP_A" "$FIRST_ACTION"
zap_assert_same_action_identity "$ZAP_A" "$ZAP_B" "$FIRST_ACTION"
zap_assert_evidence "$ZAP_A" "$FIRST_ACTION"
zap_assert_receipt_bindings "$ZAP_A" "$ZAP_B" "$FIRST_ACTION"
zap_assert_exact_reuse "$ZAP_A" "$ZAP_B" "$FIRST_ACTION" "$FIRST_WORK"

dht_note "async proof: A remains the same process while C executes another action"
dht_kill_group "${PIDS[$ZAP_B]}"; PIDS[$ZAP_B]=""
sleep 2
zap_start_node "$ZAP_C"
zap_connect "$ZAP_A" "$ZAP_C"
[ "${PIDS[$ZAP_A]}" = "$A_ORIGINAL_PID" ] &&
    kill -0 "-$A_ORIGINAL_PID" 2>/dev/null ||
    dht_die "A did not continue operating while executor roles changed"
[ "$(zap_sql_count "$ZAP_C" "SELECT count(*) FROM build_actions WHERE action_id='$FIRST_ACTION'")" -eq 0 ] ||
    dht_die "C falsely inherited B's first action"
zap_submit "$ZAP_A" 3 "Change x to three"
SECOND_ACTION="$ZAP_ACTION"; SECOND_WORK="$ZAP_WORK"; SECOND_MS="$ZAP_FOREGROUND_MS"
[ "$SECOND_ACTION" != "$FIRST_ACTION" ] || dht_die "distinct candidates aliased"
[ "$SECOND_WORK" != "$FIRST_WORK" ] || dht_die "distinct tasks aliased"
[ "$(zap_sql_count "$ZAP_A" "SELECT count(DISTINCT task_root_sha3) FROM build_actions WHERE action_id IN ('$FIRST_ACTION','$SECOND_ACTION')")" -eq 2 ] &&
[ "$(zap_sql_count "$ZAP_A" "SELECT count(DISTINCT candidate_root_sha3) FROM build_actions WHERE action_id IN ('$FIRST_ACTION','$SECOND_ACTION')")" -eq 2 ] ||
    dht_die "exact-action dedup conflated different task/candidate authority"
zap_wait_ready "$ZAP_A" "$SECOND_ACTION" ||
    { zap_dump_failure "$ZAP_A" "$SECOND_ACTION";
      dht_die "A did not reach READY_FOR_ACCEPTANCE from C evidence"; }
[ "$(zap_sql_count "$ZAP_C" "SELECT count(*) FROM build_actions WHERE action_id='$SECOND_ACTION' AND state IN ('ACCEPTED','CACHE_HIT')")" -eq 1 ] ||
    dht_die "C did not independently execute A's second fixed action"
zap_assert_requester_did_not_execute "$ZAP_A" "$SECOND_ACTION"
zap_assert_same_action_identity "$ZAP_A" "$ZAP_C" "$SECOND_ACTION"
zap_assert_evidence "$ZAP_A" "$SECOND_ACTION"
zap_assert_receipt_bindings "$ZAP_A" "$ZAP_C" "$SECOND_ACTION"
zap_assert_db_lifetime_clean "$ZAP_A" "B-to-C executor replacement"

dht_note "async proof: B dies after started_at; lease retry moves exact work to C"
dht_kill_group "${PIDS[$ZAP_C]}"; PIDS[$ZAP_C]=""
sleep 2
zap_start_node "$ZAP_B"
zap_connect "$ZAP_A" "$ZAP_B"
# Lease recovery is the boundary under test.  Thirty aggregate CPU-seconds
# keeps the measured ~12-second cold candidate clear of the former 10-second
# compilation cliff while retaining a real lease expiry inside the hook's
# bounded observation window.
zap_submit "$ZAP_A" 4 "Change x to four with lease recovery" 30
RETRY_ACTION="$ZAP_ACTION"; RETRY_MS="$ZAP_FOREGROUND_MS"
STALE_B_WORKER="$(zap_sql_value "$ZAP_B" "SELECT worker_id FROM build_workers WHERE approved=1 AND revoked=0 AND capabilities LIKE '%c23.package.recipe.v1%' ORDER BY last_seen_at DESC LIMIT 1")"
[ "${#STALE_B_WORKER}" -eq 64 ] || dht_die "B's stale worker identity was not durable"
zap_stop_executor_mid_action "$ZAP_B" ||
    dht_die "B did not spawn the fixed package action before the death probe"
zap_assert_responsive "$ZAP_A" "B-hard-stopped-mid-action"
zap_start_node "$ZAP_C"
zap_connect "$ZAP_A" "$ZAP_C"
zap_wait_ready "$ZAP_A" "$RETRY_ACTION" || {
    kill -CONT "-${PIDS[$ZAP_B]}" 2>/dev/null || true
    zap_dump_failure "$ZAP_A" "$RETRY_ACTION"
    dht_die "B lease loss did not retry the exact action on C"
}
[ "$(zap_sql_count "$ZAP_C" "SELECT count(*) FROM build_actions WHERE action_id='$RETRY_ACTION' AND state IN ('ACCEPTED','CACHE_HIT')")" -eq 1 ] ||
    dht_die "C did not execute the retried exact action"
zap_assert_requester_did_not_execute "$ZAP_A" "$RETRY_ACTION"
WINNING_C_WORKER="$(zap_sql_value "$ZAP_C" "SELECT worker_id FROM build_actions WHERE action_id='$RETRY_ACTION'")"
[ "${#WINNING_C_WORKER}" -eq 64 ] && [ "$WINNING_C_WORKER" != "$STALE_B_WORKER" ] ||
    dht_die "retry did not move the exact action to C's distinct worker"
zap_assert_same_action_identity "$ZAP_A" "$ZAP_C" "$RETRY_ACTION"
[ "$(zap_sql_count "$ZAP_A" "SELECT count(DISTINCT peer_id) FROM build_proof_events WHERE action_id='$RETRY_ACTION' AND peer_id<>0")" -ge 2 ] &&
[ "$(zap_sql_count "$ZAP_A" "SELECT count(*) FROM build_proof_events WHERE action_id='$RETRY_ACTION' AND state='PEER_DISCOVERED'")" -ge 2 ] ||
    dht_die "retry evidence did not preserve both peer leases"
STALE_EVENT_COUNT="$(zap_sql_count "$ZAP_A" "SELECT count(*) FROM build_proof_events WHERE action_id='$RETRY_ACTION'")"
kill -CONT "-${PIDS[$ZAP_B]}" || dht_die "could not resume stale B"
STALE_DEADLINE=$(( $(date +%s) + 90 ))
STALE_REFUSAL=0
while [ "$(date +%s)" -lt "$STALE_DEADLINE" ]; do
    [ "$(zap_sql_count "$ZAP_A" "SELECT count(*) FROM build_receipts WHERE action_id='$RETRY_ACTION' AND worker_id='$STALE_B_WORKER'")" -eq 0 ] ||
        dht_die "stale B entered A's receipt set while its late result was pending"
    if [ "$(zap_sql_count "$ZAP_B" "SELECT count(*) FROM build_actions WHERE action_id='$RETRY_ACTION' AND state IN ('ACCEPTED','CACHE_HIT','FAILED','LOCAL_FALLBACK')")" -eq 1 ] &&
       grep -Eq "result [0-9]+: work-lease-expired" \
           "${DDS[$ZAP_B]}/node.log"; then
        STALE_REFUSAL=1
        break
    fi
    zap_assert_responsive "$ZAP_A" "stale-B-finishing"
    sleep 1
done
[ "$STALE_REFUSAL" -eq 1 ] ||
    dht_die "stale B did not finish and produce a named late-result refusal"
[ "$(zap_sql_count "$ZAP_B" "SELECT count(*) FROM build_actions WHERE action_id='$RETRY_ACTION' AND worker_id='$STALE_B_WORKER' AND started_at>0 AND attempt_count=1")" -eq 1 ] ||
    dht_die "B was not durably stopped inside the exact leased action"
[ "$(zap_latest_state "$ZAP_A" "$RETRY_ACTION")" = READY_FOR_ACCEPTANCE ] &&
[ "$(zap_sql_count "$ZAP_A" "SELECT count(*) FROM build_proof_events WHERE action_id='$RETRY_ACTION'")" -eq "$STALE_EVENT_COUNT" ] ||
    dht_die "stale B advanced A's proof projection after losing its lease"
[ "$(zap_sql_count "$ZAP_A" "SELECT count(*) FROM build_receipts WHERE action_id='$RETRY_ACTION' AND worker_id='$WINNING_C_WORKER'")" -eq 1 ] &&
[ "$(zap_sql_count "$ZAP_A" "SELECT count(*) FROM build_receipts WHERE action_id='$RETRY_ACTION' AND worker_id='$STALE_B_WORKER'")" -eq 0 ] ||
    dht_die "stale B result entered A's receipt set or C's winning receipt was lost"
if ! grep -Eq "result [0-9]+: work-lease-expired" \
        "${DDS[$ZAP_B]}/node.log"; then
    dht_die "stale B did not produce the named work-lease-expired refusal"
fi
zap_assert_evidence "$ZAP_A" "$RETRY_ACTION"
zap_assert_receipt_bindings "$ZAP_A" "$ZAP_C" "$RETRY_ACTION"
zap_assert_db_lifetime_clean "$ZAP_A" "lease loss, C takeover, and stale-B refusal"

# A is only a task role. Kill it, then use the unchanged full-node code on B
# to originate and C to execute one final request.
dht_note "async proof: kill A; B originates through the same full-node path"
zap_assert_db_lifetime_clean "$ZAP_A" "complete A requester lifecycle"
dht_kill_group "${PIDS[$ZAP_A]}"; PIDS[$ZAP_A]=""
sleep 2
zap_connect "$ZAP_B" "$ZAP_C"
zap_submit "$ZAP_B" 5 "Change x to five after A disappears"
FINAL_ACTION="$ZAP_ACTION"; FINAL_MS="$ZAP_FOREGROUND_MS"
zap_wait_ready "$ZAP_B" "$FINAL_ACTION" ||
    { zap_dump_failure "$ZAP_B" "$FINAL_ACTION";
      dht_die "B did not originate successfully after A disappeared"; }
[ "$(zap_sql_count "$ZAP_C" "SELECT count(*) FROM build_actions WHERE action_id='$FINAL_ACTION' AND state IN ('ACCEPTED','CACHE_HIT')")" -eq 1 ] ||
    dht_die "C did not execute B's post-A action"
zap_assert_requester_did_not_execute "$ZAP_B" "$FINAL_ACTION"
zap_assert_same_action_identity "$ZAP_B" "$ZAP_C" "$FINAL_ACTION"
zap_assert_evidence "$ZAP_B" "$FINAL_ACTION"
zap_assert_receipt_bindings "$ZAP_B" "$ZAP_C" "$FINAL_ACTION"

"$SCRIPT_DIR/zcode_async_proof_perf_report.sh" "$DHT_WORK" \
    >"$DHT_WORK/async-proof-performance-report.txt" ||
    dht_die "async proof performance report was incomplete"
PERF_CANDIDATES="$(printf '%s\n' "$STANDARD_ACTION" \
    "$RACE_A_ACTION" "$RACE_C_ACTION" "$FIRST_ACTION" "$SECOND_ACTION" \
    "$RETRY_ACTION" "$FINAL_ACTION" | sort -u | wc -l)"
[ "$PERF_CANDIDATES" -eq 7 ] ||
    dht_die "performance campaign did not retain seven distinct immutable candidates"
grep -q "^background_total_precise_us n=$PERF_CANDIDATES " \
    "$DHT_WORK/async-proof-performance-report.txt" ||
    dht_die "performance report did not cover all seven accepted candidates"

dht_note "async proof PASS: standard_actions=$STANDARD_ACTION,$STANDARD_REPRO_ACTION quick_actions=$FIRST_ACTION,$SECOND_ACTION,$RETRY_ACTION,$FINAL_ACTION foreground_ms=$STANDARD_MS,$FIRST_MS,$SECOND_MS,$RETRY_MS,$FINAL_MS inert_fetch_node=$ZAP_B independent_reproducers=$ZAP_C,$ZAP_D github_contacted=false equal_full_nodes=true"
