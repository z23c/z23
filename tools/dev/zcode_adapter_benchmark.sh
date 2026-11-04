#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Purpose: measure the fixed ZCode adapter against the frozen development tasks.

set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
jsonq_bin="$repo_root/build/bin/jsonq"
usage_sum=(0 0 0)
usage_reported=(0 0 0)
usage_unreported=(0 0 0)
usage_names=(input cached_input output)

usage_fail() {
    printf 'benchmark usage: %s\n' "$*" >&2
    return 65
}

# jsonq preserves the number's source lexeme. Neither jq's floating-point
# representation nor unchecked shell arithmetic qualifies integer counters.
usage_add() {
    local field=$1 value=$2 maximum=9223372036854775807
    local LC_ALL=C
    if [[ $value == null ]]; then
        usage_unreported[field]=$((usage_unreported[field] + 1))
        return
    fi
    if [[ ! $value =~ ^(0|[1-9][0-9]*)$ ]] ||
       ((${#value} > ${#maximum})) ||
       [[ ${#value} -eq ${#maximum} && $value > $maximum ]]; then
        usage_fail "invalid or overflowing ${usage_names[field]} counter"
        return 65
    fi
    if ((usage_sum[field] > maximum - value)); then
        usage_fail "${usage_names[field]} total exceeds INT64_MAX"
        return 65
    fi
    usage_sum[field]=$((usage_sum[field] + value))
    usage_reported[field]=$((usage_reported[field] + 1))
}

usage_value() {
    local document=$1 path=$2 value rc
    if value=$("$jsonq_bin" raw "$path" <<<"$document"); then
        printf '%s\n' "$value"
    else
        rc=$?
        if [[ $rc == 1 ]]; then printf 'null\n'; else return "$rc"; fi
    fi
}

usage_unique_fields() {
    local document=$1 path=$2 field matches
    shift 2
    for field in "$@"; do
        if ! matches=$("$jsonq_bin" key-count "$path" "$field" <<<"$document"); then
            usage_fail "cannot count ${field} members in ${path:-root} object"
            return 65
        fi
        if [[ ! $matches =~ ^[0-9]+$ ]]; then
            usage_fail "invalid ${field} member count in ${path:-root} object"
            return 65
        fi
        if ((matches > 1)); then
            usage_fail "duplicate ${field} member in ${path:-root} object"
            return 65
        fi
    done
}

usage_check_unique_if_object() {
    local document=$1 path=$2 type rc
    shift 2
    if type=$("$jsonq_bin" type "$path" <<<"$document"); then
        [[ $type != object ]] || usage_unique_fields "$document" "$path" "$@"
        return $?
    else
        rc=$?
        [[ $rc == 1 ]] && return 0
        return 65
    fi
}

usage_file_valid() {
    local file=$1
    # Bash read discards NUL bytes; reject them before reading any JSONL row.
    cmp -s "$file" <(LC_ALL=C tr -d '\000' <"$file") || {
        usage_fail 'unreadable or NUL-containing event stream'; return 65;
    }
}

usage_exec_file() {
    local file=$1 line root_type eq_status terminal=0
    [[ -x $jsonq_bin ]] || { usage_fail 'build/bin/jsonq is unavailable'; return 69; }
    usage_file_valid "$file" || return 65
    while IFS= read -r line || [[ -n $line ]]; do
        root_type=$("$jsonq_bin" type '' <<<"$line") || return 65
        [[ $root_type == object ]] || { usage_fail 'event is not an object'; return 65; }
        usage_unique_fields "$line" '' type usage || return 65
        # Compare decoded strings inside C23: shell text loses embedded NULs
        # and trailing newlines, while raw JSON spellings may contain escapes.
        if "$jsonq_bin" eq type turn.completed <<<"$line"; then
            terminal=$((terminal + 1))
            [[ $terminal == 1 ]] || {
                usage_fail 'multiple terminal usage events have no deduplication identity'; return 65;
            }
            usage_check_unique_if_object "$line" usage \
                input_tokens cached_input_tokens output_tokens || return 65
            # Exec wire names differ from the benchmark's existing output keys.
            local field value paths=(input_tokens cached_input_tokens output_tokens)
            for field in 0 1 2; do
                value=$(usage_value "$line" "usage.${paths[field]}") || return 65
                usage_add "$field" "$value" || return 65
            done
        else
            eq_status=$?
            [[ $eq_status == 1 ]] || return 65
        fi
    done <"$file"
    if [[ $terminal == 0 ]]; then
        usage_add 0 null; usage_add 1 null; usage_add 2 null
    fi
}

usage_app_document() {
    local document=$1 field value
    [[ -x $jsonq_bin ]] || { usage_fail 'build/bin/jsonq is unavailable'; return 69; }
    local root_type
    root_type=$("$jsonq_bin" type '' <<<"$document") || return 65
    [[ $root_type == object ]] || { usage_fail 'app-server response is not an object'; return 65; }
    usage_unique_fields "$document" '' tokens || return 65
    usage_check_unique_if_object "$document" tokens input cached_input output || return 65
    # The v1 helper always emits initialized zero counters even when the
    # notification is absent. Validate its numbers, but do not qualify coverage.
    for field in 0 1 2; do
        value=$(usage_value "$document" "tokens.${usage_names[field]}") || return 65
        local saved_sum=${usage_sum[field]} saved_reported=${usage_reported[field]}
        usage_add "$field" "$value" || return 65
        usage_sum[field]=$saved_sum
        usage_reported[field]=$saved_reported
        [[ $value == null ]] || usage_unreported[field]=$((usage_unreported[field] + 1))
    done
}

usage_summary() {
    local state=measured any_reported=0 any_unreported=0 field
    local values=() reported=() unreported=() sums=()
    for field in 0 1 2; do
        ((usage_reported[field] == 0)) || any_reported=1
        ((usage_unreported[field] == 0)) || any_unreported=1
        values[field]=${usage_sum[field]}
        if ((usage_unreported[field] > 0 || usage_reported[field] == 0)); then
            values[field]=null
        fi
        reported[field]="\"${usage_names[field]}\":${usage_reported[field]}"
        unreported[field]="\"${usage_names[field]}\":${usage_unreported[field]}"
        sums[field]="\"${usage_names[field]}\":${usage_sum[field]}"
    done
    if [[ $any_reported == 0 ]]; then state=unavailable;
    elif [[ $any_unreported == 1 ]]; then state=partial; fi
    printf '{"state":"%s","input":%s,"cached_input":%s,"output":%s,' \
        "$state" "${values[0]}" "${values[1]}" "${values[2]}"
    printf '"reported_sum":{%s,%s,%s},"coverage":{"reported":{%s,%s,%s},"unreported":{%s,%s,%s}}}\n' \
        "${sums[@]}" "${reported[@]}" "${unreported[@]}"
}

snapshot_project() {
    local candidate=$1 output=$2 path relative kind digest mode listing
    : >"$output"
    find "$candidate" -mindepth 1 -print0 >"$output.paths"
    LC_ALL=C sort -z "$output.paths" -o "$output.paths"
    while IFS= read -r -d '' path; do
        relative=${path#"$candidate/"}
        listing=$(LC_ALL=C ls -ld "$path") || {
            echo 'benchmark: cannot read workspace entry mode' >&2
            return 65
        }
        mode=${listing:0:10}
        [[ ${#mode} == 10 ]] || {
            echo 'benchmark: invalid workspace entry mode' >&2
            return 65
        }
        digest=''
        if [[ -L $path ]]; then
            kind=symlink
            digest=$(readlink -z -- "$path" | sha256sum | cut -d' ' -f1)
        elif [[ -f $path ]]; then
            kind=file
            digest=$(sha256sum <"$path" | cut -d' ' -f1)
        elif [[ -d $path ]]; then
            kind=directory
        else
            echo 'benchmark: unsupported workspace entry type' >&2
            return 65
        fi
        jq -cn --arg path "$relative" --arg kind "$kind" --arg digest "$digest" \
            --arg mode "$mode" '{path:$path,kind:$kind,digest:$digest,mode:$mode}' >>"$output"
    done <"$output.paths"
    rm -- "$output.paths"
}

verify_scope() {
    local before=$1 after=$2 scopes_json=$3 changed_file=$4
    jq -cs 'group_by(.path)[] | select(length == 1 or .[0] != .[1]) | .[0].path' \
        "$before" "$after" >"$changed_file"
    jq -se --argjson scopes "$scopes_json" \
        'all(.[]; . as $path | any($scopes[]; . as $scope | $path == $scope or ($path | startswith($scope + "/"))))' \
        "$changed_file" >/dev/null
}

emit_preflight_report() {
    jq -cn \
        --arg schema zcl.zcode_adapter_preflight_acceptance.v2 \
        --argjson tasks "$task_limit" \
        --argjson verified "$preflight_verified" \
        --argjson calls "$native_calls" \
        --argjson output_bytes "$tool_output_bytes" \
        --argjson elapsed_us "$elapsed_us" \
        '{schema:$schema,tasks:$tasks,preflight_verified:$verified,adapter_invocations:0,provider_requests:0,native_tool_calls:$calls,native_tool_output_bytes:$output_bytes,elapsed_us:$elapsed_us}'
}

emit_benchmark_report() {
if [[ $arm == control ]]; then
    token_summary='{"state":"unavailable_no_model_request","input":null,"cached_input":null,"output":null}'
else
    token_summary=$(usage_summary)
fi
benchmark_output=$(jq -cn \
    --arg schema zcl.zcode_adapter_benchmark.v2 \
    --arg arm "$arm" \
    --argjson tasks "$task_limit" \
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
    --argjson expected_refusal_success "$expected_refusal_success" \
    --argjson model_failures "$model_failures" \
    --argjson sandbox_failures "$sandbox_failures" \
    '{schema:$schema,arm:$arm,tasks:$tasks,tokens:"Z23_TOKEN_SUMMARY",packet_bytes:$packet_bytes,tool_output_bytes:{native:$tool_output_bytes,model:$model_tool_output_bytes},calls:{native:$native_tool_calls,adapter_invocations:$model_calls,provider_requests:null,model_tools:$model_tool_calls},retries:$retries,elapsed_us:$elapsed_us,scope_errors:$scope_errors,sandbox_failures:$sandbox_failures,first_pass_success:$first_pass_success,verified_success:$verified_success,exact_reproduction:$exact_reproduction,expected_refusal_success:$expected_refusal_success,model_failures:$model_failures,adapter_unavailable:$adapter_unavailable}')
# Keep integer totals exact; passing them back through jq can round INT64 values.
printf '%s\n' "${benchmark_output/\"Z23_TOKEN_SUMMARY\"/$token_summary}"
}

# Deterministic acceptance exercises the same extraction caller without any
# node operation, credential access, or model request.
if [[ ${1:-} == --report-fixture ]]; then
    [[ $# == 2 && ($2 == benchmark || $2 == preflight) ]] || exit 64
    # Synthetic observations exercise the production builders, not a model.
    arm=fixture task_limit=2 preflight_verified=2 native_calls=0
    tool_output_bytes=0 elapsed_us=0 packet_bytes=0 model_calls=2 retries=0
    scope_errors=0 verified_success=1 unavailable=0 model_tool_output_bytes=0
    model_tool_calls=0 first_pass_success=1 exact_reproduction=0
    expected_refusal_success=1 model_failures=0 sandbox_failures=0
    if [[ $2 == preflight ]]; then emit_preflight_report; else emit_benchmark_report; fi
    exit 0
fi
if [[ ${1:-} == --scope-fixture ]]; then
    [[ $# == 6 ]] || exit 64
    snapshot_project "$2" "$4"
    snapshot_project "$3" "$5"
    verify_scope "$4" "$5" "$6" "$5.changed"
    exit $?
fi
if [[ ${1:-} == --usage-fixture ]]; then
    [[ $# -ge 3 ]] || { usage_fail 'fixture needs format and input file'; exit 64; }
    format=${2:-}
    shift 2
    [[ $# -gt 0 ]] || { usage_fail 'fixture needs an input file'; exit 64; }
    for fixture in "$@"; do
        case "$format" in
            exec) usage_exec_file "$fixture" ;;
            appserver)
                usage_file_valid "$fixture"
                usage_app_document "$(cat "$fixture")" ;;
            *) usage_fail 'fixture format must be exec or appserver'; exit 64 ;;
        esac
    done
    usage_summary
    exit 0
fi

arm=${1:-}
case "$arm" in
    control|preflight|packet-analysis|ephemeral-full|ephemeral-index|ephemeral-hybrid|ephemeral-hybrid-stable|appserver-hybrid-stable) ;;
    *)
    echo "usage: $0 {control|preflight|packet-analysis|ephemeral-full|ephemeral-index|ephemeral-hybrid|ephemeral-hybrid-stable|appserver-hybrid-stable}" >&2
    exit 64
    ;;
esac

z23_bin="$repo_root/build/bin/z23"
app_server_benchmark="$repo_root/build/bin/z23-zcode-app-server-benchmark"
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
model_tool_output_bytes=0
model_tool_calls=0
first_pass_success=0
exact_reproduction=0
expected_refusal_success=0
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
    packet_for_arm "$packet" "$candidate" "$prompt"
    # Create harness-owned entries before observing any adapter writes.
    mkdir -p "$candidate/.zcode-adapter-tmp"
    if [[ $arm == appserver-hybrid-stable ]]; then
        app_packet="$candidate/.zcode-adapter-packet.json"
        cp "$prompt" "$app_packet"
        chmod 0600 "$app_packet"
    fi
    snapshot_project "$candidate" "$before"
    packet_bytes=$((packet_bytes + $(wc -c <"$prompt")))
    model_calls=$((model_calls + 1))
    if [[ $arm == appserver-hybrid-stable ]]; then
        set +e
        "$app_server_benchmark" \
            "$candidate" "$app_packet" "$benchmark_model" >"$events"
        app_rc=$?
        set -e
        usage_file_valid "$events"
        app_output=$(cat "$events")
        if [[ $app_rc -eq 0 ]] &&
           jq -e '.completed == true and .turn_status == "completed" and
                  .server_requests_denied == 0 and .forbidden_tool_calls == 0' \
              >/dev/null <<<"$app_output"; then
            model_ok=true
        else
            model_ok=false
            model_failures=$((model_failures + 1))
        fi
        usage_app_document "$app_output"
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
        usage_exec_file "$events"
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
        continue
    fi
    changed_count=$(wc -l <"$changed")

    if [[ $refused == true ]]; then
        if [[ $model_ok == true && $changed_count -eq 0 ]]; then
            verified_success=$((verified_success + 1))
            first_pass_success=$((first_pass_success + 1))
            expected_refusal_success=$((expected_refusal_success + 1))
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
    emit_preflight_report
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
emit_benchmark_report
