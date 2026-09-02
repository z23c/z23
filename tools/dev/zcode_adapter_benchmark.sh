#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Purpose: measure the fixed ZCode adapter against the frozen development tasks.

set -euo pipefail

arm=${1:-}
case "$arm" in
    control|preflight|packet-analysis|ephemeral-full|ephemeral-index|ephemeral-hybrid|ephemeral-hybrid-stable|appserver-hybrid-stable) ;;
    *)
    echo "usage: $0 {control|preflight|packet-analysis|ephemeral-full|ephemeral-index|ephemeral-hybrid|ephemeral-hybrid-stable|appserver-hybrid-stable}" >&2
    exit 64
    ;;
esac

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
z23_bin="$repo_root/build/bin/z23"
app_server_benchmark="$repo_root/build/bin/zclassic23-zcode-app-server-benchmark"
case_source="$repo_root/tests/harness/src/test_zcode_package_dev.c"
if [[ ! -x $z23_bin ]]; then
    echo "benchmark: build/bin/z23 is unavailable" >&2
    exit 69
fi
if [[ $arm == appserver-* && ! -x $app_server_benchmark ]]; then
    echo "benchmark: run make zcode-app-server-benchmark first" >&2
    exit 69
fi

bench_root=$(mktemp -d "${TMPDIR:-/tmp}/z23-adapter-benchmark.XXXXXX")
candidate_paths=()
cleanup() {
    if [[ ${Z23_ADAPTER_BENCHMARK_KEEP:-0} == 1 ]]; then
        printf 'benchmark_artifacts=%s\n' "$bench_root" >&2
        return
    fi
    local candidate
    for candidate in "${candidate_paths[@]}"; do
        case "$candidate" in
            /tmp/zclassic23-zcode-workspaces/"$(id -u)"/*/attempt-*)
                rm -rf -- "$candidate" ;;
            *) echo "benchmark: refusing unsafe candidate cleanup target" >&2 ;;
        esac
    done
    case "$bench_root" in
        "${TMPDIR:-/tmp}"/z23-adapter-benchmark.*) rm -rf -- "$bench_root" ;;
        *) echo "benchmark: refusing unsafe cleanup target" >&2 ;;
    esac
}
trap cleanup EXIT

make_project() {
    local root=$1 name=$2 value=$3
    mkdir -p "$root/include" "$root/src" "$root/tests"
    printf 'MIT\n' >"$root/LICENSE"
    printf 'int x(void);\n' >"$root/include/x.h"
    printf 'int x(void) { return %s; }\n' "$value" >"$root/src/x.c"
    printf 'int main(void) { return 0; }\n' >"$root/tests/test.c"
    printf '{"schema":1,"name":"fixture/%s","semver":"0.1.0","language":"c23","license":"MIT","include_dir":"include","source_dir":"src","dependencies":[]}\n' \
        "$name" >"$root/zcode-package.json"
}

for project in 0 1 2; do
    make_project "$bench_root/project-$project" "benchmark-$project" \
        "$((project + 1))"
done

# Read the frozen cases from their acceptance owner instead of maintaining a
# second mutable task list. The deliberately narrow grammar fails closed if
# the catalog's C representation changes.
mapfile -t cases < <(
    sed -n '/static const struct zpd_benchmark_case cases\[\] = {/,/^    };/p' \
        "$case_source" |
    sed -n 's/^[[:space:]]*{"[^"]*", "\([^"]*\)", \([0-2]\), \(false\|true\)},$/\2\t\3\t\1/p'
)
if [[ ${#cases[@]} -ne 12 ]]; then
    echo "benchmark: frozen task catalog did not resolve to 12 cases" >&2
    exit 65
fi

started_ns=$(date +%s%N)
native_calls=0
model_calls=0
retries=0
tool_output_bytes=0
packet_bytes=0
scope_errors=0
verified_success=0
unavailable=0
input_tokens=0
cached_input_tokens=0
output_tokens=0
model_tool_output_bytes=0
model_tool_calls=0
first_pass_success=0
exact_reproduction=0
model_failures=0
sandbox_failures=0
preflight_verified=0
full_packet_bytes=0
index_packet_bytes=0
hybrid_packet_bytes=0
stable_packet_bytes=0
hybrid_packets=()
stable_packets=()
task_limit=${Z23_ADAPTER_BENCHMARK_LIMIT:-12}
if [[ ! $task_limit =~ ^[0-9]+$ ]] || ((task_limit < 1 || task_limit > 12)); then
    echo "benchmark: Z23_ADAPTER_BENCHMARK_LIMIT must be in [1,12]" >&2
    exit 64
fi
benchmark_model=${Z23_ADAPTER_BENCHMARK_MODEL:-}
if [[ $arm == ephemeral-* || $arm == appserver-* ]] &&
   [[ -z $benchmark_model || $benchmark_model == *[[:space:]]* ]]; then
    echo "benchmark: executing arms require Z23_ADAPTER_BENCHMARK_MODEL" >&2
    exit 64
fi

snapshot_project() {
    local candidate=$1 output=$2 path
    : >"$output"
    for path in LICENSE include/x.h src/x.c tests/test.c zcode-package.json; do
        if [[ -f $candidate/$path ]]; then
            sha256sum "$candidate/$path" |
                sed "s#  $candidate/#  #" >>"$output"
        else
            printf 'MISSING  %s\n' "$path" >>"$output"
        fi
    done
}

source_index() {
    local candidate=$1 include_content=$2 path bytes digest
    for path in LICENSE include/x.h src/x.c tests/test.c zcode-package.json; do
        bytes=$(wc -c <"$candidate/$path")
        digest=$(sha256sum "$candidate/$path" | cut -d' ' -f1)
        if [[ $include_content == true ]]; then
            jq -cn --arg path "$path" --argjson bytes "$bytes" \
                --arg sha256 "$digest" --rawfile content "$candidate/$path" \
                '{path:$path,bytes:$bytes,sha256:$sha256,content:$content}'
        else
            jq -cn --arg path "$path" --argjson bytes "$bytes" \
                --arg sha256 "$digest" \
                '{path:$path,bytes:$bytes,sha256:$sha256}'
        fi
    done | jq -cs '.'
}

packet_for_arm() {
    local packet=$1 candidate=$2 output=$3 mode index stable
    case "$arm" in
        ephemeral-full) mode=full; stable=false ;;
        ephemeral-index) mode=index_only; stable=false ;;
        ephemeral-hybrid) mode=hybrid; stable=false ;;
        ephemeral-hybrid-stable|appserver-hybrid-stable)
            mode=hybrid; stable=true ;;
        *) return 64 ;;
    esac
    if [[ $mode == full ]]; then
        index=$(source_index "$candidate" true)
        jq -c --arg mode "$mode" --argjson index "$index" \
            '.context_mode=$mode | .source_files=$index | del(.selected_excerpts)' \
            "$packet" >"$output"
    else
        index=$(source_index "$candidate" false)
        jq -c --arg mode "$mode" --argjson index "$index" \
            '.context_mode=$mode | .source_index=$index |
             if $mode == "index_only" then del(.selected_excerpts) else . end' \
            "$packet" >"$output"
    fi
    if [[ $stable == true ]]; then
        jq -c '{instruction,limits,allowed_write_scopes,locked_dependencies,
                selected_dependency_context,dependency_lock_root,context_mode,
                source_index,selected_excerpts,context_query,goal}' \
            "$output" >"$output.stable"
        mv "$output.stable" "$output"
    fi
    jq -c '.instruction += " Do not use the network."' "$output" \
        >"$output.instructed"
    mv "$output.instructed" "$output"
}

common_prefix() {
    local first=$1 other prefix first_size other_size mismatch
    first_size=$(wc -c <"$first")
    prefix=$first_size
    shift
    for other in "$@"; do
        other_size=$(wc -c <"$other")
        mismatch=$(cmp -l "$first" "$other" 2>/dev/null |
            awk 'NR == 1 { print $1; exit }' || true)
        if [[ -n $mismatch ]]; then
            ((mismatch -= 1))
        elif ((other_size < first_size)); then
            mismatch=$other_size
        else
            mismatch=$first_size
        fi
        ((mismatch < prefix)) && prefix=$mismatch
    done
    printf '%s\n' "$prefix"
}

run_ephemeral_model() {
    local candidate=$1 packet=$2 events=$3 rc external_tool_key
    external_tool_key=$(printf '%s%s' m cp_servers)
    mkdir -p "$candidate/.zcode-adapter-tmp"
    set +e
    codex exec --json --model "$benchmark_model" \
        --sandbox workspace-write -C "$candidate" \
        --skip-git-repo-check --ephemeral --ignore-user-config --ignore-rules \
        --color never \
        -c "${external_tool_key}={}" -c 'plugins={}' \
        -c 'shell_environment_policy.inherit="none"' \
        -c 'shell_environment_policy.set.PATH="/usr/bin:/bin"' \
        -c 'shell_environment_policy.set.HOME="."' \
        -c 'shell_environment_policy.set.TMPDIR=".zcode-adapter-tmp"' \
        --disable apps --disable plugins --disable hooks \
        --disable multi_agent --disable browser_use \
        --disable browser_use_external --disable computer_use \
        --disable image_generation --disable in_app_browser \
        --disable skill_search --disable goals --disable guardian_approval \
        --disable tool_suggest - <"$packet" >"$events" 2>"$events.stderr"
    rc=$?
    set -e
    return "$rc"
}

verify_scope() {
    local before=$1 after=$2 scopes_json=$3 changed_file=$4 line path ok
    : >"$changed_file"
    while IFS= read -r line; do
        path=${line#*  }
        printf '%s\n' "$path" >>"$changed_file"
    done < <(diff --old-group-format='%<' --new-group-format='%>' \
                    --changed-group-format='%>' --unchanged-group-format='' \
                    "$before" "$after" || true)
    ok=true
    while IFS= read -r path; do
        [[ -z $path ]] && continue
        if ! jq -e --arg path "$path" \
            'any(.[]; $path == . or ($path | startswith(. + "/")))' \
            >/dev/null <<<"$scopes_json"; then
            ok=false
        fi
    done <"$changed_file"
    [[ $ok == true ]]
}

case_index=0
for row in "${cases[@]}"; do
    ((case_index += 1))
    ((case_index > task_limit)) && break
    IFS=$'\t' read -r project refused goal <<<"$row"
    # Each frozen request owns one exact workspace.  Reusing the three source
    # templates directly made later cases collide with the still-active task
    # admitted by the first case for that template.  The product is right to
    # refuse overlapping active work; the adapter harness must isolate its
    # independent requests instead of weakening that coordination rail.
    workspace="$bench_root/project-$project-case-$case_index"
    cp -a "$bench_root/project-$project" "$workspace"
    start_input=$(jq -cn --arg workspace "$workspace" --arg goal "$goal" \
        '{workspace:$workspace,goal:$goal,profile:"quick"}')
    start_output=$(
        "$z23_bin" zcode work start --input="$start_input"
    )
    native_calls=$((native_calls + 1))
    tool_output_bytes=$((tool_output_bytes + ${#start_output}))
    if ! jq -e '.ok == true and (.data.work_id | type == "string")' \
        >/dev/null <<<"$start_output"; then
        echo "benchmark: frozen task start failed" >&2
        exit 1
    fi
    work_id=$(jq -r '.data.work_id' <<<"$start_output")
    if [[ $arm == preflight ]]; then
        preflight_input=$(jq -cn --arg workspace "$workspace" \
            --arg work "$work_id" '{workspace:$workspace,work:$work}')
        preflight_output=$("$z23_bin" zcode work preflight \
            --input="$preflight_input")
        native_calls=$((native_calls + 1))
        tool_output_bytes=$((tool_output_bytes + ${#preflight_output}))
        if jq -e '
            .ok == true and
            .data.model_request_attempted == false and
            (.data.checks.executable_binding.runner_bound | type == "boolean") and
            (.data.checks.executable_binding.codex_bound | type == "boolean") and
            (.data.checks.credential_capability.ready | type == "boolean") and
            .data.checks.credential_capability.value_exposed == false and
            .data.checks.filesystem_sandbox.ready == true and
            .data.checks.filesystem_sandbox.model_request_attempted == false and
            .data.checks.packet.ready == true and
            .data.checks.packet.bytes > 0 and
            .data.blocker == .data.error_code and
            (.data.next_action | length > 0)' \
            >/dev/null <<<"$preflight_output"; then
            preflight_verified=$((preflight_verified + 1))
        else
            echo "benchmark: native adapter preflight contract failed" >&2
            exit 1
        fi
        continue
    fi
    if [[ $arm == control ]]; then
        run_input=$(jq -cn --arg workspace "$workspace" --arg work "$work_id" \
            '{workspace:$workspace,work:$work,adapter:"codex"}')
        set +e
        run_output=$("$z23_bin" zcode work run --input="$run_input")
        run_rc=$?
        set -e
        native_calls=$((native_calls + 1))
        tool_output_bytes=$((tool_output_bytes + ${#run_output}))
        if [[ $run_rc -ne 0 ]] &&
           jq -e '.ok == false and .error.code == "ADAPTER_UNAVAILABLE" and .error.mutated == false' \
              >/dev/null <<<"$run_output"; then
            unavailable=$((unavailable + 1))
        elif [[ $run_rc -eq 0 ]] && jq -e '.ok == true' >/dev/null <<<"$run_output"; then
            verified_success=$((verified_success + 1))
        else
            echo "benchmark: unexpected adapter result" >&2
            exit 1
        fi
        if find "$bench_root" -name '.zcode-adapter-packet.json' -print -quit |
           grep -q .; then
            scope_errors=$((scope_errors + 1))
        fi
        continue
    fi

    handoff_input=$(jq -cn --arg workspace "$workspace" --arg work "$work_id" \
        '{workspace:$workspace,work:$work,adapter:"manual"}')
    handoff_output=$("$z23_bin" zcode work run --input="$handoff_input")
    native_calls=$((native_calls + 1))
    tool_output_bytes=$((tool_output_bytes + ${#handoff_output}))
    if ! jq -e '.ok == true and .data.state == "AWAITING_CANDIDATE"' \
        >/dev/null <<<"$handoff_output"; then
        echo "benchmark: manual packet handoff failed" >&2
        exit 1
    fi
    candidate=$(jq -r '.data.candidate_workspace' <<<"$handoff_output")
    candidate_paths+=("$candidate")
    packet=$(jq -r '.data.adapter_packet_path' <<<"$handoff_output")
    if [[ $arm == packet-analysis ]]; then
        original_arm=$arm
        arm=ephemeral-full
        packet_for_arm "$packet" "$candidate" "$bench_root/full-$case_index"
        full_packet_bytes=$((full_packet_bytes + $(wc -c <"$bench_root/full-$case_index")))
        arm=ephemeral-index
        packet_for_arm "$packet" "$candidate" "$bench_root/index-$case_index"
        index_packet_bytes=$((index_packet_bytes + $(wc -c <"$bench_root/index-$case_index")))
        arm=ephemeral-hybrid
        packet_for_arm "$packet" "$candidate" "$bench_root/hybrid-$case_index"
        hybrid_packet_bytes=$((hybrid_packet_bytes + $(wc -c <"$bench_root/hybrid-$case_index")))
        hybrid_packets+=("$bench_root/hybrid-$case_index")
        arm=ephemeral-hybrid-stable
        packet_for_arm "$packet" "$candidate" "$bench_root/stable-$case_index"
        stable_packet_bytes=$((stable_packet_bytes + $(wc -c <"$bench_root/stable-$case_index")))
        stable_packets+=("$bench_root/stable-$case_index")
        arm=$original_arm
        continue
    fi
    scopes_json=$(jq -c '.allowed_write_scopes' "$packet")
    before="$bench_root/before-$case_index"
    after="$bench_root/after-$case_index"
    changed="$bench_root/changed-$case_index"
    prompt="$bench_root/prompt-$case_index.json"
    events="$bench_root/events-$case_index.jsonl"
    snapshot_project "$candidate" "$before"
    packet_for_arm "$packet" "$candidate" "$prompt"
    packet_bytes=$((packet_bytes + $(wc -c <"$prompt")))
    model_calls=$((model_calls + 1))
    if [[ $arm == appserver-hybrid-stable ]]; then
        app_packet="$candidate/.zcode-adapter-packet.json"
        cp "$prompt" "$app_packet"
        chmod 0600 "$app_packet"
        set +e
        app_output=$("$app_server_benchmark" \
            "$candidate" "$app_packet" "$benchmark_model")
        app_rc=$?
        set -e
        if [[ $app_rc -eq 0 ]] &&
           jq -e '.completed == true and .turn_status == "completed" and
                  .server_requests_denied == 0 and .forbidden_tool_calls == 0' \
              >/dev/null <<<"$app_output"; then
            model_ok=true
        else
            model_ok=false
            model_failures=$((model_failures + 1))
        fi
        input_tokens=$((input_tokens + $(jq -r '.tokens.input // 0' <<<"$app_output")))
        cached_input_tokens=$((cached_input_tokens + $(jq -r '.tokens.cached_input // 0' <<<"$app_output")))
        output_tokens=$((output_tokens + $(jq -r '.tokens.output // 0' <<<"$app_output")))
        model_tool_calls=$((model_tool_calls + $(jq -r '.tool_calls // 0' <<<"$app_output")))
        model_tool_output_bytes=$((model_tool_output_bytes + $(jq -r '.tool_output_bytes // 0' <<<"$app_output")))
        if jq -e '.diagnostic.bwrap_loopback_failure == true' >/dev/null \
                <<<"$app_output"; then
            sandbox_failures=$((sandbox_failures + 1))
        fi
    elif run_ephemeral_model "$candidate" "$prompt" "$events"; then
        model_ok=true
    else
        model_ok=false
        model_failures=$((model_failures + 1))
    fi
    if [[ $arm != appserver-hybrid-stable ]]; then
        input_tokens=$((input_tokens + $(jq -s '[.[] | select(.type == "turn.completed") | .usage.input_tokens // 0] | add // 0' "$events")))
        cached_input_tokens=$((cached_input_tokens + $(jq -s '[.[] | select(.type == "turn.completed") | .usage.cached_input_tokens // 0] | add // 0' "$events")))
        output_tokens=$((output_tokens + $(jq -s '[.[] | select(.type == "turn.completed") | .usage.output_tokens // 0] | add // 0' "$events")))
        model_tool_calls=$((model_tool_calls + $(jq -s '[.[] | select(.type == "item.completed" and .item.type == "command_execution")] | length' "$events")))
        model_tool_output_bytes=$((model_tool_output_bytes + $(jq -s '[.[] | select(.type == "item.completed" and .item.type == "command_execution") | (.item.aggregated_output // "" | utf8bytelength)] | add // 0' "$events")))
        retries=$((retries + $(jq -s '[.[] | select((.type // "") | test("retry"; "i"))] | length' "$events")))
        if grep -q 'Failed RTM_NEWADDR' "$events.stderr"; then
            sandbox_failures=$((sandbox_failures + 1))
        fi
    fi
    snapshot_project "$candidate" "$after"
    if ! verify_scope "$before" "$after" "$scopes_json" "$changed"; then
        scope_errors=$((scope_errors + 1))
    fi
    changed_count=$(wc -l <"$changed")

    if [[ $refused == true ]]; then
        if [[ $model_ok == true && $changed_count -eq 0 ]]; then
            verified_success=$((verified_success + 1))
            first_pass_success=$((first_pass_success + 1))
            exact_reproduction=$((exact_reproduction + 1))
        fi
        continue
    fi
    if [[ $model_ok != true || $changed_count -eq 0 ]]; then
        continue
    fi
    set +e
    admit_output=$("$z23_bin" zcode work run --input="$handoff_input")
    admit_rc=$?
    set -e
    native_calls=$((native_calls + 1))
    tool_output_bytes=$((tool_output_bytes + ${#admit_output}))
    if [[ $admit_rc -ne 0 ]] ||
       ! jq -e '.ok == true and .data.state == "EVIDENCE_READY" and .data.build_result == "passed"' \
           >/dev/null <<<"$admit_output"; then
        continue
    fi
    first_pass_success=$((first_pass_success + 1))
    accept_input=$(jq -cn --arg workspace "$workspace" --arg work "$work_id" \
        '{workspace:$workspace,work:$work}')
    accept_output=$("$z23_bin" zcode work accept --input="$accept_input")
    native_calls=$((native_calls + 1))
    tool_output_bytes=$((tool_output_bytes + ${#accept_output}))
    status_output=$("$z23_bin" zcode work status --input="$accept_input")
    native_calls=$((native_calls + 1))
    tool_output_bytes=$((tool_output_bytes + ${#status_output}))
    if jq -e '.ok == true and .data.state == "PROVEN"' >/dev/null \
            <<<"$accept_output" &&
       jq -e '.ok == true and .data.state == "PROVEN"' >/dev/null \
            <<<"$status_output"; then
        verified_success=$((verified_success + 1))
        exact_reproduction=$((exact_reproduction + 1))
    fi
    : "$refused"
done

elapsed_us=$((($(date +%s%N) - started_ns) / 1000))
if [[ $arm == preflight ]]; then
    jq -cn \
        --arg schema zcl.zcode_adapter_preflight_acceptance.v1 \
        --argjson tasks "$task_limit" \
        --argjson verified "$preflight_verified" \
        --argjson calls "$native_calls" \
        --argjson output_bytes "$tool_output_bytes" \
        --argjson elapsed_us "$elapsed_us" \
        '{schema:$schema,tasks:$tasks,preflight_verified:$verified,model_requests:0,native_tool_calls:$calls,native_tool_output_bytes:$output_bytes,elapsed_us:$elapsed_us}'
    exit 0
fi
if [[ $arm == packet-analysis ]]; then
    hybrid_prefix=$(common_prefix "${hybrid_packets[@]}")
    stable_prefix=$(common_prefix "${stable_packets[@]}")
    jq -cn --arg schema zcl.zcode_packet_benchmark.v1 \
        --argjson tasks "$task_limit" \
        --argjson full "$full_packet_bytes" \
        --argjson index "$index_packet_bytes" \
        --argjson hybrid "$hybrid_packet_bytes" \
        --argjson stable "$stable_packet_bytes" \
        --argjson hybrid_prefix "$hybrid_prefix" \
        --argjson stable_prefix "$stable_prefix" \
        --argjson native_calls "$native_calls" \
        --argjson tool_output_bytes "$tool_output_bytes" \
        --argjson elapsed_us "$elapsed_us" \
        '{schema:$schema,tasks:$tasks,packet_bytes:{full:$full,index_only:$index,hybrid:$hybrid,hybrid_stable:$stable},global_common_prefix_bytes:{hybrid_current:$hybrid_prefix,hybrid_stable:$stable_prefix},native_tool_calls:$native_calls,native_tool_output_bytes:$tool_output_bytes,elapsed_us:$elapsed_us}'
    exit 0
fi
if [[ $arm == control ]]; then
    token_state=unavailable_no_model_request
    input_json=null
    cached_json=null
    output_json=null
else
    token_state=measured
    input_json=$input_tokens
    cached_json=$cached_input_tokens
    output_json=$output_tokens
fi
jq -cn \
    --arg schema zcl.zcode_adapter_benchmark.v1 \
    --arg arm "$arm" \
    --arg token_state "$token_state" \
    --argjson tasks "$task_limit" \
    --argjson input_tokens "$input_json" \
    --argjson cached_input_tokens "$cached_json" \
    --argjson output_tokens "$output_json" \
    --argjson packet_bytes "$packet_bytes" \
    --argjson tool_output_bytes "$tool_output_bytes" \
    --argjson native_tool_calls "$native_calls" \
    --argjson model_calls "$model_calls" \
    --argjson retries "$retries" \
    --argjson elapsed_us "$elapsed_us" \
    --argjson scope_errors "$scope_errors" \
    --argjson verified_success "$verified_success" \
    --argjson adapter_unavailable "$unavailable" \
    --argjson model_tool_output_bytes "$model_tool_output_bytes" \
    --argjson model_tool_calls "$model_tool_calls" \
    --argjson first_pass_success "$first_pass_success" \
    --argjson exact_reproduction "$exact_reproduction" \
    --argjson model_failures "$model_failures" \
    --argjson sandbox_failures "$sandbox_failures" \
    '{schema:$schema,arm:$arm,tasks:$tasks,tokens:{state:$token_state,input:$input_tokens,cached_input:$cached_input_tokens,output:$output_tokens},packet_bytes:$packet_bytes,tool_output_bytes:{native:$tool_output_bytes,model:$model_tool_output_bytes},calls:{native:$native_tool_calls,model_requests:$model_calls,model_tools:$model_tool_calls},retries:$retries,elapsed_us:$elapsed_us,scope_errors:$scope_errors,sandbox_failures:$sandbox_failures,first_pass_success:$first_pass_success,verified_success:$verified_success,exact_reproduction:$exact_reproduction,model_failures:$model_failures,adapter_unavailable:$adapter_unavailable}'
