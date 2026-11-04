#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Purpose: deterministic token-coverage acceptance through the benchmark caller.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
reader="$repo_root/tools/dev/zcode_adapter_benchmark.sh"
jsonq="$repo_root/build/bin/jsonq"
[[ -x $jsonq ]] || { echo 'usage selftest: build/bin/jsonq is required' >&2; exit 69; }
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/z23-adapter-usage.XXXXXX")
trap 'rm -rf -- "$fixture_root"' EXIT
checks=0

check_value() {
    local path=$1 expected=$2 actual
    actual=$("$jsonq" raw "$path" <<<"$result")
    [[ $actual == "$expected" ]] || {
        printf 'usage selftest: %s expected %s, got %s\n' "$path" "$expected" "$actual" >&2
        exit 1
    }
    checks=$((checks + 1))
}

exec_fixture() {
    printf '{"type":"turn.completed","usage":%s}\n' "$2" >"$fixture_root/$1"
}

refused() {
    local format=$1 file=$2 rc
    if bash "$reader" --usage-fixture "$format" "$file" \
        >"$fixture_root/refusal.stdout" 2>"$fixture_root/refusal.stderr"; then
        echo 'usage selftest: invalid input was accepted' >&2
        exit 1
    else
        rc=$?
    fi
    [[ $rc == 65 && ! -s $fixture_root/refusal.stdout ]] || {
        echo 'usage selftest: refusal must exit 65 without partial totals' >&2
        exit 1
    }
    checks=$((checks + 1))
}

exec_fixture zero '{"input_tokens":0,"cached_input_tokens":0,"output_tokens":0}'
result=$(bash "$reader" --usage-fixture exec "$fixture_root/zero")
check_value state '"measured"'
check_value input 0
check_value cached_input 0
check_value output 0
check_value coverage.reported.input 1
check_value coverage.unreported.input 0

exec_fixture partial '{"input_tokens":5,"output_tokens":2}'
result=$(bash "$reader" --usage-fixture exec "$fixture_root/partial")
check_value state '"partial"'
check_value input 5
check_value cached_input null
check_value coverage.unreported.cached_input 1

exec_fixture complete '{"input_tokens":10,"cached_input_tokens":8,"output_tokens":3}'
result=$(bash "$reader" --usage-fixture exec "$fixture_root/complete" "$fixture_root/partial")
check_value state '"partial"'
check_value input 15
check_value output 5
check_value cached_input null
check_value reported_sum.cached_input 8
check_value coverage.reported.cached_input 1
check_value coverage.unreported.cached_input 1

printf '{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":0,"note\\ninput_tokens":"metadata"},"meta\\nusage":"metadata"}\n' \
    >"$fixture_root/escaped-newline-metadata"
result=$(bash "$reader" --usage-fixture exec "$fixture_root/escaped-newline-metadata")
check_value state '"measured"'
check_value input 1

printf '{"type":"turn.failed","error":{"message":"fixture failure"}}\n' >"$fixture_root/absent"
result=$(bash "$reader" --usage-fixture exec "$fixture_root/absent")
check_value state '"unavailable"'
check_value input null
check_value coverage.unreported.input 1

# Event type is a decoded JSON string, not its spelling in the JSON source.
printf '%s\n' '{"type":"turn.\u0063ompleted","usage":{"input_tokens":7,"cached_input_tokens":2,"output_tokens":3}}' \
    >"$fixture_root/escaped-terminal"
result=$(bash "$reader" --usage-fixture exec "$fixture_root/escaped-terminal")
check_value state '"measured"'
check_value input 7
check_value cached_input 2
check_value output 3
cat "$fixture_root/complete" "$fixture_root/escaped-terminal" >"$fixture_root/escaped-duplicate"
refused exec "$fixture_root/escaped-duplicate"
for suffix in '\u0000suffix' '\u0000' '\n'; do
    printf '{"type":"turn.completed%s","usage":{"input_tokens":7}}\n' "$suffix" \
        >"$fixture_root/not-terminal"
    result=$(bash "$reader" --usage-fixture exec "$fixture_root/not-terminal")
    check_value state '"unavailable"'
done

for value in -1 1.5 1e3 '"10"' true 9223372036854775808; do
    exec_fixture invalid "{\"input_tokens\":$value,\"cached_input_tokens\":0,\"output_tokens\":0}"
    refused exec "$fixture_root/invalid"
done

exec_fixture maximum '{"input_tokens":9223372036854775807,"cached_input_tokens":0,"output_tokens":0}'
result=$(bash "$reader" --usage-fixture exec "$fixture_root/maximum")
check_value state '"measured"'
check_value input 9223372036854775807
exec_fixture one '{"input_tokens":1,"cached_input_tokens":0,"output_tokens":0}'
if bash "$reader" --usage-fixture exec "$fixture_root/maximum" "$fixture_root/one" \
    >"$fixture_root/refusal.stdout" 2>"$fixture_root/refusal.stderr"; then
    echo 'usage selftest: aggregate overflow accepted' >&2
    exit 1
else
    rc=$?
fi
[[ $rc == 65 && ! -s $fixture_root/refusal.stdout ]]
checks=$((checks + 1))

cat "$fixture_root/complete" "$fixture_root/complete" >"$fixture_root/duplicate"
refused exec "$fixture_root/duplicate"
printf '{"type":"turn.completed","type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":0}}\n' \
    >"$fixture_root/duplicate-type-key"
refused exec "$fixture_root/duplicate-type-key"
cat >"$fixture_root/duplicate-escaped-type-key" <<'EOF'
{"type":"turn.completed","\u0074ype":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":0}}
EOF
refused exec "$fixture_root/duplicate-escaped-type-key"
printf '{"type":"turn.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":0},"usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":0}}\n' \
    >"$fixture_root/duplicate-usage-key"
refused exec "$fixture_root/duplicate-usage-key"
printf '{"type":"turn.completed","usage":{"input_tokens":1,"input_tokens":2,"cached_input_tokens":0,"output_tokens":0}}\n' \
    >"$fixture_root/duplicate-counter-key"
refused exec "$fixture_root/duplicate-counter-key"
cat >"$fixture_root/duplicate-escaped-counter-key" <<'EOF'
{"type":"turn.completed","usage":{"input_tokens":1,"input\u005ftokens":2,"cached_input_tokens":0,"output_tokens":0}}
EOF
refused exec "$fixture_root/duplicate-escaped-counter-key"
printf '{"type":"turn.completed","usage":{"input_tokens":1}} junk\n' >"$fixture_root/malformed"
refused exec "$fixture_root/malformed"
printf '[]\n' >"$fixture_root/array"
refused exec "$fixture_root/array"
printf '{"type":"turn.completed","usage":{"input_tokens":1}}\0\n' >"$fixture_root/nul"
refused exec "$fixture_root/nul"

printf '{"schema":"zcl.zcode_app_server_benchmark.v1","tokens":{"input":0,"cached_input":0,"output":0}}\n' \
    >"$fixture_root/appserver"
result=$(bash "$reader" --usage-fixture appserver "$fixture_root/appserver")
check_value state '"unavailable"'
check_value input null
check_value cached_input null
check_value coverage.reported.input 0
check_value coverage.unreported.input 1
printf '{"tokens":{"input":-1}}\n' >"$fixture_root/appserver-invalid"
refused appserver "$fixture_root/appserver-invalid"
refused appserver "$fixture_root/nul"
printf '{"tokens":{"input":1,"cached_input":0,"output":0},"tokens":{"input":2,"cached_input":0,"output":0}}\n' \
    >"$fixture_root/appserver-duplicate-tokens-key"
refused appserver "$fixture_root/appserver-duplicate-tokens-key"
printf '{"tokens":{"input":1,"input":2,"cached_input":0,"output":0}}\n' \
    >"$fixture_root/appserver-duplicate-counter-key"
refused appserver "$fixture_root/appserver-duplicate-counter-key"

scope_case() {
    local expected=$1 scopes=$2 rc=0
    bash "$reader" --scope-fixture "$fixture_root/before" "$fixture_root/after" \
        "$fixture_root/before.jsonl" "$fixture_root/after.jsonl" "$scopes" || rc=$?
    [[ $rc == "$expected" ]] || {
        printf 'scope selftest: expected status %s, got %s\n' "$expected" "$rc" >&2
        exit 1
    }
    checks=$((checks + 1))
}

mkdir -p "$fixture_root/before/src" "$fixture_root/after/src"
printf 'original\n' >"$fixture_root/before/src/x.c"
cp "$fixture_root/before/src/x.c" "$fixture_root/after/src/x.c"
chmod 0644 "$fixture_root/before/src/x.c" "$fixture_root/after/src/x.c"
scope_case 0 '[]'
printf 'extra\n' >"$fixture_root/after/untracked.c"
scope_case 1 '["src"]'
rm "$fixture_root/after/untracked.c"
printf 'extra\n' >"$fixture_root/after/src/new.c"
scope_case 0 '["src"]'
scope_case 1 '["src/x.c"]'
rm "$fixture_root/after/src/new.c"
rm "$fixture_root/after/src/x.c"
scope_case 1 '[]'
scope_case 0 '["src"]'
ln -s outside "$fixture_root/after/src/x.c"
scope_case 1 '[]'
rm "$fixture_root/after/src/x.c"
cp "$fixture_root/before/src/x.c" "$fixture_root/after/src/x.c"
chmod 04750 "$fixture_root/after/src/x.c"
scope_case 1 '[]'
chmod 0644 "$fixture_root/after/src/x.c"
scope_case 0 '[]'
mkdir "$fixture_root/after/untracked-dir"
scope_case 1 '["src"]'
rmdir "$fixture_root/after/untracked-dir"
printf 'extra\n' >"$fixture_root/after/odd"$'\n'"name"
scope_case 1 '["src"]'
rm "$fixture_root/after/odd"$'\n'"name"
ln -s target-one "$fixture_root/before/link"
ln -s target-two "$fixture_root/after/link"
scope_case 1 '["src"]'
scope_case 0 '["src","link"]'
rm "$fixture_root/before/link" "$fixture_root/after/link"
mkfifo "$fixture_root/after/fifo"
scope_case 65 '[]'

result=$(bash "$reader" --report-fixture benchmark)
check_value schema '"zcl.zcode_adapter_benchmark.v2"'
check_value calls.adapter_invocations 2
check_value calls.provider_requests null
check_value expected_refusal_success 1
check_value exact_reproduction 0
if "$jsonq" raw calls.model_requests <<<"$result" >/dev/null; then
    echo 'report selftest: obsolete model_requests key remains' >&2
    exit 1
fi
checks=$((checks + 1))
result=$(bash "$reader" --report-fixture preflight)
check_value schema '"zcl.zcode_adapter_preflight_acceptance.v2"'
check_value adapter_invocations 0
check_value provider_requests 0

printf 'adapter usage/scope selftest: %s checks passed; no model requests\n' "$checks"
