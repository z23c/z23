#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Hermetic end-to-end proof for exact deterministic compiler-failure
# coalescing. Uses a fake checkout, private HOME, and the real dev binary.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${ZCL_DEV_FAILURE_TEST_BIN:-$ROOT/build/bin/zclassic23-dev}"
[[ -x "$BIN" ]] || {
    echo "native-dev-failure-selftest: missing dev binary: $BIN" >&2
    exit 2
}

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/zcl-native-dev-failure.XXXXXX")"
REPO="$SANDBOX/repo"
WATCHER_ID=""

stop_watcher()
{
    if [[ -n "$WATCHER_ID" ]]; then
        HOME="$SANDBOX" ZCL_DEV_SOURCE_ROOT="$REPO" \
            "$BIN" dev loop stop "$WATCHER_ID" >/dev/null 2>&1 || true
    fi
}

cleanup()
{
    stop_watcher
    rm -rf -- "$SANDBOX"
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$REPO/.git" "$REPO/tools/dev"
printf '%064d 1 %064d\n' 0 1 >"$REPO/source.record"
printf '%064d\n' 2 >"$REPO/execution.id"
printf '0\n' >"$REPO/ff.count"
printf 'compile\n' >"$REPO/failure.mode"
printf 'int fixture;\n' >"$REPO/fixture.c"

cat >"$REPO/tools/dev/source-identity.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
bump_if_present()
{
    local path="$1" count
    [ -f "$path" ] || return 0
    count="$(cat "$path")"
    printf '%s\n' "$((count + 1))" > "$path"
}
case "${1:-}" in
    capture-record)
        bump_if_present capture.count
        cat source.record
        ;;
    verify-record)
        actual="$(cat source.record)"
        expected="$2 $3 $4"
        [[ "$actual" == "$expected" ]]
        printf '%s\n' "$actual"
        ;;
    verify-mutation)
        bump_if_present verify.count
        read -r _source _complete mutation < source.record
        [[ "$mutation" == "${2:-}" ]]
        printf '%s\n' "$mutation"
        ;;
    *)
        exit 2
        ;;
esac
SCRIPT
chmod 0700 "$REPO/tools/dev/source-identity.sh"

cat >"$REPO/tools/agent_fast_ci.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
[[ "${1:-}" == failure-execution-id ]]
cat execution.id
SCRIPT
chmod 0700 "$REPO/tools/agent_fast_ci.sh"

cat >"$REPO/Makefile" <<'MAKE'
.PHONY: dev-failure-execution-id ff

dev-failure-execution-id:
	@cat execution.id

ff:
	@count="$$(cat ff.count)"; count="$$((count + 1))"; \
	  printf '%s\n' "$$count" >ff.count; \
	  mode="$$(cat failure.mode)"; \
	  if [ "$$mode" = compile ]; then \
	    printf '%s\n' '[agent-fast-ci] FIRST-ERROR[compile]: fixture.c:1:1: error: synthetic compiler failure'; \
	  else \
	    printf '%s\n' '[agent-fast-ci] FIRST-ERROR[source-wide-tests]: synthetic test failure'; \
	  fi; \
	  exit 2
MAKE

fail()
{
    local watcher_log="$SANDBOX/.local/state/zclassic23-dev/native-watch.log"
    echo "native-dev-failure-selftest: FAIL: $*" >&2
    if [[ -f "$watcher_log" ]]; then
        echo "native-dev-failure-selftest: watcher log follows" >&2
        sed -n '1,240p' "$watcher_log" >&2
    fi
    exit 1
}

native()
{
    HOME="$SANDBOX" ZCL_DEV_SOURCE_ROOT="$REPO" "$BIN" "$@"
}

ENSURE="$(native dev loop ensure \
    --input="{\"root\":\"$REPO\",\"mode\":\"verify\"}")"
WATCHER_ID="$(sed -n 's/.*"watcher_id":\([0-9][0-9]*\).*/\1/p' <<<"$ENSURE")"
[[ -n "$WATCHER_ID" ]] || fail "watcher id missing"

wait_after()
{
    local after="$1" result status epoch
    # The native stream deliberately exposes EDIT_SEEN/IMPACT_READY. A fast
    # Linux reactor often reaches the terminal verdict before this client is
    # exec'd, while kqueue can truthfully expose those earlier stages. Consume
    # them by epoch instead of making the self-test depend on scheduler speed.
    for _ in 1 2 3 4 5 6 7 8; do
        result="$(native dev loop wait \
            --input="{\"after_epoch\":$after,\"timeout_ms\":10000}" \
            --view=summary)"
        status="$(sed -n 's/.*\"status\":\"\([^\"]*\)\".*/\1/p' \
            <<<"$result")"
        case "$status" in
            edit_seen|impact_ready|proof_pending|superseded)
                epoch="$(sed -n 's/.*\"epoch\":\([0-9][0-9]*\).*/\1/p' \
                    <<<"$result")"
                [[ -n "$epoch" ]] || fail "transient cycle epoch missing"
                after="$epoch"
                ;;
            *)
                printf '%s\n' "$result"
                return 0
                ;;
        esac
    done
    fail "cycle did not reach a terminal verdict"
}

touch "$REPO/fixture.c"
FIRST="$(wait_after 0)"
[[ "$FIRST" == *'"status":"rejected"'* &&
   "$FIRST" == *'"failure_id":'* ]] ||
    fail "first compiler red did not produce a durable failure"
[[ "$(cat "$REPO/ff.count")" == 1 ]] ||
    fail "first compiler red did not execute exactly once"
EPOCH1="$(sed -n 's/.*"epoch":\([0-9][0-9]*\).*/\1/p' <<<"$FIRST")"
[[ -n "$EPOCH1" ]] || fail "first epoch missing"

touch "$REPO/fixture.c"
SECOND="$(wait_after "$EPOCH1")"
[[ "$SECOND" == *'"status":"unchanged_failure"'* &&
   "$SECOND" == *'"coalesced":true'* ]] ||
    fail "identical compiler red was not coalesced"
[[ "$(cat "$REPO/ff.count")" == 1 ]] ||
    fail "coalesced red executed make ff"
EPOCH2="$(sed -n 's/.*"epoch":\([0-9][0-9]*\).*/\1/p' <<<"$SECOND")"
[[ -n "$EPOCH2" ]] || fail "second epoch missing"

# Compiler/toolchain execution changes invalidate the negative receipt even
# when source bytes and the normalized diagnostic are unchanged.
printf '%064d\n' 5 >"$REPO/execution.id"
touch "$REPO/fixture.c"
TOOLCHAIN="$(wait_after "$EPOCH2")"
[[ "$TOOLCHAIN" == *'"status":"rejected"'* &&
   "$(cat "$REPO/ff.count")" == 2 ]] ||
    fail "execution epoch change did not rerun make ff"
EPOCH_TOOLCHAIN="$(sed -n 's/.*"epoch":\([0-9][0-9]*\).*/\1/p' \
    <<<"$TOOLCHAIN")"
[[ -n "$EPOCH_TOOLCHAIN" ]] || fail "toolchain epoch missing"

# ABA mutation change: same source digest/failure, different mutation token.
printf '%064d 1 %064d\n' 0 3 >"$REPO/source.record"
touch "$REPO/fixture.c"
THIRD="$(wait_after "$EPOCH_TOOLCHAIN")"
[[ "$THIRD" == *'"status":"rejected"'* ]] ||
    fail "mutation change did not execute a new cycle"
[[ "$(cat "$REPO/ff.count")" == 3 ]] ||
    fail "mutation change did not rerun make ff"
EPOCH3="$(sed -n 's/.*"epoch":\([0-9][0-9]*\).*/\1/p' <<<"$THIRD")"
[[ -n "$EPOCH3" ]] || fail "third epoch missing"

# Test/lint/infrastructure-shaped reds are never negative-cached.
printf '%064d\n' 4 >"$REPO/execution.id"
printf 'test\n' >"$REPO/failure.mode"
touch "$REPO/fixture.c"
FOURTH="$(wait_after "$EPOCH3")"
EPOCH4="$(sed -n 's/.*"epoch":\([0-9][0-9]*\).*/\1/p' <<<"$FOURTH")"
[[ "$(cat "$REPO/ff.count")" == 4 && -n "$EPOCH4" ]] ||
    fail "first non-compiler red did not execute"
touch "$REPO/fixture.c"
FIFTH="$(wait_after "$EPOCH4")"
[[ "$FIFTH" != *'"coalesced":true'* &&
   "$(cat "$REPO/ff.count")" == 5 ]] ||
    fail "non-compiler red was coalesced"

# dev.ff is the explicit unchanged retry and always executes the ladder.
printf 'compile\n' >"$REPO/failure.mode"
set +e
RETRY="$(native dev ff 2>&1)"
RETRY_RC=$?
set -e
[[ "$RETRY_RC" -eq 1 && "$RETRY" == *'"code":"FF_LADDER_FAILED"'* &&
   "$(cat "$REPO/ff.count")" == 6 ]] ||
    fail "explicit dev.ff did not execute"

LATEST="$(native dev diagnose latest)"
FAILURE_ID="$(sed -n 's/.*"failure_id":"\([0-9a-f]\{64\}\)".*/\1/p' \
    <<<"$LATEST")"
[[ -n "$FAILURE_ID" && "$LATEST" == *'"found":true'* ]] ||
    fail "latest failure summary missing"
SHOW="$(native dev diagnose show "$FAILURE_ID" --view=full)"
[[ "$SHOW" == *'"data_schema":"zcl.dev_failure_show.v1"'* &&
   "$SHOW" == *'"retry_command":"dev.ff"'* &&
   "$SHOW" == *'"command":"dev.ff"'* ]] ||
    fail "show projection or typed retry drifted"

stop_watcher
WATCHER_ID=""

# Focused-test admission has two safe paths. The common unchanged path binds
# the runner's build-time mutation receipt without rehashing every source byte;
# edit/revert or copied checkouts fall back to exact byte capture instead of
# forcing an unnecessary rebuild. A stale byte identity still refuses before
# the runner executes.
mkdir -p "$REPO/build/bin"
cat >"$REPO/build/bin/test_parallel_fast" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
    --source-record)
        cat runner.record
        ;;
    --source-id)
        read -r source _complete _mutation < runner.record
        printf '%s\n' "$source"
        ;;
    --exact=test_api)
        count="$(cat runner.count)"
        printf '%s\n' "$((count + 1))" > runner.count
        ;;
    *) exit 2 ;;
esac
SCRIPT
chmod 0700 "$REPO/build/bin/test_parallel_fast"
printf '0\n' >"$REPO/runner.count"

if [[ "$(uname -s 2>/dev/null)" == Darwin ]]; then
    set +e
    DARWIN_ADMIT="$(native dev test run api 2>&1)"
    DARWIN_RC=$?
    set -e
    [[ "$DARWIN_RC" -ne 0 &&
       "$DARWIN_ADMIT" == *'"code":"SOURCE_IDENTITY_UNAVAILABLE"'* &&
       "$(cat "$REPO/runner.count")" == 0 ]] ||
        fail "Darwin focused runner executed an unattested script fixture"
    echo "native-dev-failure-selftest: PASS"
    exit 0
fi

printf '0\n' >"$REPO/capture.count"
printf '0\n' >"$REPO/verify.count"
printf '%064d 1 %064d\n' 6 7 >"$REPO/runner.record"
printf '%064d 1 %064d\n' 6 7 >"$REPO/source.record"

FAST_ADMIT="$(native dev test run api)"
[[ "$FAST_ADMIT" == *'"status":"passed"'* &&
   "$FAST_ADMIT" == *'"source_admission":"build_mutation_receipt"'* &&
   "$(cat "$REPO/capture.count")" == 0 &&
   "$(cat "$REPO/verify.count")" == 2 &&
   "$(cat "$REPO/runner.count")" == 1 ]] ||
    fail "unchanged focused runner did not use the receipt-only admission"

printf '0\n' >"$REPO/capture.count"
printf '0\n' >"$REPO/verify.count"
printf '0\n' >"$REPO/runner.count"
printf '%064d 1 %064d\n' 6 8 >"$REPO/source.record"
FALLBACK_ADMIT="$(native dev test run api)"
[[ "$FALLBACK_ADMIT" == *'"status":"passed"'* &&
   "$FALLBACK_ADMIT" == *'"source_admission":"full_byte_fallback"'* &&
   "$FALLBACK_ADMIT" == *'"source_mutation_sha256":"0000000000000000000000000000000000000000000000000000000000000008"'* &&
   "$(cat "$REPO/capture.count")" == 1 &&
   "$(cat "$REPO/verify.count")" == 2 &&
   "$(cat "$REPO/runner.count")" == 1 ]] ||
    fail "edit/revert focused runner did not use the exact-byte fallback"

printf '0\n' >"$REPO/capture.count"
printf '0\n' >"$REPO/verify.count"
printf '0\n' >"$REPO/runner.count"
printf '%064d 1 %064d\n' 9 8 >"$REPO/source.record"
set +e
STALE_ADMIT="$(native dev test run api 2>&1)"
STALE_RC=$?
set -e
[[ "$STALE_RC" -ne 0 && "$STALE_ADMIT" == *'"code":"TEST_RUNNER_STALE"'* &&
   "$(cat "$REPO/capture.count")" == 1 &&
   "$(cat "$REPO/verify.count")" == 1 &&
   "$(cat "$REPO/runner.count")" == 0 ]] ||
    fail "stale focused runner was not refused before execution"

printf '0\n' >"$REPO/capture.count"
printf '0\n' >"$REPO/verify.count"
printf '0\n' >"$REPO/runner.count"
printf 'malformed\n' >"$REPO/runner.record"
set +e
MALFORMED_ADMIT="$(native dev test run api 2>&1)"
MALFORMED_RC=$?
set -e
[[ "$MALFORMED_RC" -ne 0 &&
   "$MALFORMED_ADMIT" == *'"code":"TEST_RUNNER_STALE"'* &&
   "$(cat "$REPO/capture.count")" == 0 &&
   "$(cat "$REPO/verify.count")" == 0 &&
   "$(cat "$REPO/runner.count")" == 0 ]] ||
    fail "malformed focused-runner receipt was not refused fail-closed"

printf '0\n' >"$REPO/capture.count"
printf '0\n' >"$REPO/verify.count"
printf '0\n' >"$REPO/runner.count"
printf '%064d 1 %064d\n' 6 7 >"$REPO/source.record"
printf '%064d 1 %064d' 6 7 >"$REPO/runner.record"
printf '\0trailing-garbage\n' >>"$REPO/runner.record"
set +e
NUL_ADMIT="$(native dev test run api 2>&1)"
NUL_RC=$?
set -e
[[ "$NUL_RC" -ne 0 &&
   "$NUL_ADMIT" == *'"code":"TEST_RUNNER_STALE"'* &&
   "$(cat "$REPO/capture.count")" == 0 &&
   "$(cat "$REPO/verify.count")" == 0 &&
   "$(cat "$REPO/runner.count")" == 0 ]] ||
    fail "NUL-tailed focused-runner receipt was not refused fail-closed"

echo "native-dev-failure-selftest: PASS"
