#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Derive performance observations from immutable action-correlated node logs.
# This report is telemetry only: it never mutates proof or acceptance state.
set -euo pipefail

usage() {
    printf 'usage: %s <zcode-dht-acceptance-artifact>\n' "$0" >&2
    exit 2
}

[ "$#" -eq 1 ] || usage
root="$1"
[ -d "$root" ] || { printf 'artifact directory not found: %s\n' "$root" >&2; exit 2; }

shopt -s nullglob
logs=("$root"/*/node.log)
results=("$root"/async-submit-*-result.json)
[ "${#logs[@]}" -gt 0 ] || { printf 'no node logs under %s\n' "$root" >&2; exit 1; }
[ "${#results[@]}" -gt 0 ] || { printf 'no async result records under %s\n' "$root" >&2; exit 1; }

scratch="$(mktemp -d "${TMPDIR:-/tmp}/zcl-proof-perf.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT INT TERM

quantile() {
    local name="$1" file="$2" unit="$3"
    [ -f "$file" ] || : >"$file"
    sort -n "$file" | awk -v name="$name" -v unit="$unit" '
        { expected++ }
        /^$/ { missing++; next }
        !/^[0-9]+$/ || $0+0 > 9007199254740991 { invalid++; next }
        { values[++n]=$1; sum+=$1 }
        END {
            p50=int((n*50+99)/100); p95=int((n*95+99)/100)
            if (n) printf "%s n=%d p50_%s=%.0f p95_%s=%.0f mean_%s=%.0f max_%s=%.0f",
                   name,n,unit,values[p50],unit,values[p95],unit,sum/n,
                   unit,values[n]
            else printf "%s n=0 p50_%s=null p95_%s=null mean_%s=null max_%s=null",
                   name,unit,unit,unit,unit
            printf " expected=%d missing=%d invalid=%d complete=%s\n",
                   expected,missing,invalid,
                   (n > 0 && !missing && !invalid) ? "true" : "false"
            if (!n || invalid) exit 1
        }'
}

# API-local foreground spans do not depend on synchronized host clocks.
for file in "${results[@]}"; do
    for key in foreground_request_creation_us durable_action_lookup_dedup_us \
               local_submit_us local_first_feedback_us live_rpc_admission_us \
               live_rpc_request_bytes live_rpc_response_bytes; do
        value="$(sed -n "s/.*\"$key\":[[:space:]]*\([^,}[:space:]]*\).*/\1/p" "$file")"
        printf '%s\n' "$value" >>"$scratch/$key"
    done
done

# Every lifecycle log carries action=<immutable root>, stage=<projection>, and
# at_unix_us=<observation>. Cross-host deltas are valid when the campaign's
# clocks are synchronized; local durations remain valid independently.
awk -v out="$scratch" '
function field(name,    i,prefix) {
    prefix=name "="
    for (i=1;i<=NF;i++) if (index($i,prefix)==1) return substr($i,length(prefix)+1)
    return ""
}
function first(key,value) { if (!(key in at) || value < at[key]) at[key]=value }
function emit(name,value) {
    if (value == "") print "" >> (out "/" name)
    else if (value !~ /^[0-9]+$/ || value+0 > 9007199254740991)
        print "invalid" >> (out "/" name)
    else printf "%.0f\n",value >> (out "/" name)
}
function delta(name,from,to) {
    if (!from || !to) emit(name,"")
    else if (to < from) emit(name,"invalid")
    else emit(name,sprintf("%.0f",to-from))
}
index($0,"[zcode.proof_perf]") {
    lifecycle_records++
    action=field("action"); stage=field("stage"); timestamp=field("at_unix_us")
    if (length(action)!=64 || action !~ /^[0-9a-f]+$/ || stage=="" ||
        timestamp !~ /^[0-9]+$/ || timestamp+0<=0 ||
        timestamp+0>9007199254740991) { invalid_records++; next }
    timestamp+=0
    key=action SUBSEP stage
    if (stage=="requester_dispatch") {
        emit("context_prepare_us",field("context_prepare_us"))
        emit("peer_selection_us",field("peer_selection_us"))
        emit("request_submit_us",field("request_submit_us"))
        emit("context_prepared_bytes",field("context_bytes"))
        request_bytes[action]+=field("request_wire_bytes")+0
        dispatches[action]++
        if (field("context_cache_hit")=="1") context_cache_hits++
        else if (field("context_cache_hit")!="0") context_cache_unmeasured++
        context_cache_samples++
        if (field("retry")=="1") retries++
    }
    if (stage=="requester_dispatch" && field("retry")=="1") next
    first(key,timestamp)
    if (stage=="worker_execute") {
        emit("remote_execution_us",field("total_us"))
        emit("remote_cpu_us",field("child_cpu_us"))
        emit("sandbox_prepare_us",field("sandbox_prepare_us"))
        emit("execution_us",field("execution_us"))
        emit("output_cas_us",field("output_cas_us"))
        emit("receipt_sign_us",field("receipt_sign_us"))
        emit("worker_action_lookup_us",field("lookup_us"))
        emit("input_reconstruction_us",field("input_reconstruction_us"))
        emit("output_verify_us",field("output_verify_us"))
        emit("worker_revalidation_us",field("revalidation_us"))
        emit("worker_projection_us",field("projection_us"))
        emit("worker_input_bytes",field("input_bytes"))
        emit("worker_output_bytes",field("output_bytes"))
        emit("worker_processes",field("processes"))
        emit("compiler_processes",field("compiler_processes"))
        emit("test_processes",field("test_processes"))
        output_bytes[action]+=field("output_bytes")+0
        if (field("cache_hit")=="1") worker_cache_hits++
        else if (field("cache_hit")!="0") worker_cache_unmeasured++
        worker_cache_samples++
    } else if (stage=="remote_admission") {
        emit("remote_admission_us",field("admission_us"))
        emit("context_transferred_bytes",field("transferred_bytes"))
        context_transfer[action]=field("transferred_bytes")+0
    } else if (stage=="worker_lease") {
        emit("worker_claim_us",field("claim_us"))
        emit("remote_queue_us",field("queue_us"))
    } else if (stage=="requester_result") {
        emit("receipt_verification_us",field("receipt_verification_us"))
        emit("requester_result_projection_us",field("projection_us"))
        result_bytes[action]+=field("result_wire_bytes")+0
    } else if (stage=="acceptance_ready") {
        emit("acceptance_local_verification_us",field("local_verification_us"))
        emit("acceptance_projection_us",field("projection_us"))
    } else if (stage=="worker_progress_publish") {
        progress_bytes[action]+=field("progress_wire_bytes")+0
    }
}
END {
    for (key in at) {
        split(key,p,SUBSEP); actions[p[1]]=1
    }
    for (action in actions) {
        foreground=at[action SUBSEP "foreground_return"]
        dispatch=at[action SUBSEP "requester_dispatch"]
        admission=at[action SUBSEP "remote_admission"]
        lease=at[action SUBSEP "worker_lease"]
        publish=at[action SUBSEP "worker_result_publish"]
        result=at[action SUBSEP "requester_result"]
        ready=at[action SUBSEP "acceptance_ready"]
        delta("foreground_to_dispatch_us",foreground,dispatch)
        delta("dispatch_to_admission_us",dispatch,admission)
        delta("admission_to_lease_us",admission,lease)
        delta("result_transport_precise_us",publish,result)
        delta("result_to_acceptance_us",result,ready)
        delta("background_total_precise_us",foreground,ready)
        payload=context_transfer[action]+request_bytes[action]+progress_bytes[action]+result_bytes[action]+output_bytes[action]
        if (payload > 0) emit("network_payload_lower_bound_bytes",payload)
    }
    print retries+0 > (out "/retry_dispatches_total")
    print context_cache_hits+0 > (out "/context_cache_hits_total")
    print context_cache_samples+0 > (out "/context_cache_samples_total")
    print worker_cache_hits+0 > (out "/worker_cache_hits_total")
    print worker_cache_samples+0 > (out "/worker_cache_samples_total")
    print worker_cache_unmeasured+0 > (out "/worker_cache_unmeasured_total")
    print context_cache_unmeasured+0 > (out "/context_cache_unmeasured_total")
    print lifecycle_records+0 > (out "/lifecycle_records_total")
    print invalid_records+0 > (out "/invalid_lifecycle_records_total")
}' "${logs[@]}"

printf 'schema=zcl.async_proof_perf_report.v1\n'
printf 'artifact=%s\n' "$root"
printf 'clock_note=cross-host deltas require synchronized realtime clocks; local spans do not\n'
printf 'sample_note=missing and invalid observations are counted, never zero-filled; incomplete metrics are telemetry, not acceptance\n'
printf 'lifecycle_records=%s invalid_lifecycle_records=%s\n' \
    "$(cat "$scratch/lifecycle_records_total")" \
    "$(cat "$scratch/invalid_lifecycle_records_total")"
incomplete=0
[ "$(cat "$scratch/invalid_lifecycle_records_total")" -eq 0 ] || incomplete=1
for metric in foreground_request_creation_us durable_action_lookup_dedup_us \
              local_submit_us local_first_feedback_us live_rpc_admission_us \
              foreground_to_dispatch_us context_prepare_us peer_selection_us \
              request_submit_us dispatch_to_admission_us \
              remote_admission_us admission_to_lease_us remote_queue_us \
              worker_claim_us worker_action_lookup_us input_reconstruction_us \
              sandbox_prepare_us execution_us remote_execution_us remote_cpu_us \
              output_verify_us output_cas_us worker_revalidation_us \
              receipt_sign_us worker_projection_us result_transport_precise_us \
              receipt_verification_us requester_result_projection_us \
              result_to_acceptance_us acceptance_local_verification_us \
              acceptance_projection_us \
              background_total_precise_us; do
    if ! quantile "$metric" "$scratch/$metric" us; then incomplete=1; fi
done
for metric in live_rpc_request_bytes live_rpc_response_bytes \
              context_prepared_bytes context_transferred_bytes \
              worker_input_bytes worker_output_bytes \
              network_payload_lower_bound_bytes worker_processes \
              compiler_processes test_processes; do
    if ! quantile "$metric" "$scratch/$metric" count; then incomplete=1; fi
done

dedup=0
[ -f "$root/async-exact-reuse-eliminated.txt" ] &&
    dedup="$(awk '{sum+=$1} END{print sum+0}' "$root/async-exact-reuse-eliminated.txt")"
printf 'duplicate_executions_avoided=%s\n' "$dedup"
printf 'retry_dispatches=%s\n' "$(cat "$scratch/retry_dispatches_total")"
printf 'context_cache_hits=%s/%s\n' \
    "$(cat "$scratch/context_cache_hits_total")" \
    "$(cat "$scratch/context_cache_samples_total")"
printf 'worker_cache_hits=%s/%s\n' \
    "$(cat "$scratch/worker_cache_hits_total")" \
    "$(cat "$scratch/worker_cache_samples_total")"
printf 'context_cache_unmeasured=%s worker_cache_unmeasured=%s\n' \
    "$(cat "$scratch/context_cache_unmeasured_total")" \
    "$(cat "$scratch/worker_cache_unmeasured_total")"
exit "$incomplete"
