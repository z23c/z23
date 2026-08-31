#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Hold the hosted test job to one non-vacuous cold-suite verdict. A substring
# grep is insufficient: "ALL TESTS PASSED (CACHED)" deliberately contains the
# old pass token, and can describe a run that executed zero groups.

set -uo pipefail
export LC_ALL=C
HOSTED_SUITE_FIXTURE_DIR=""

cleanup_fixture()
{
    [ -z "$HOSTED_SUITE_FIXTURE_DIR" ] ||
        rm -rf -- "$HOSTED_SUITE_FIXTURE_DIR"
}

fail()
{
    printf 'hosted-suite-verdict: FAIL: %s\n' "$*" >&2
}

check_log()
{
    local log="$1" verdict_count verdict first second token key datum
    local bad=0 total_n ran_n cached_n gated_n failed_n skips_n unobserved_n
    declare -A value=()

    if [ ! -r "$log" ]; then
        fail "suite log is not readable: $log"
        return 1
    fi

    verdict_count="$(grep -c '^SUITE VERDICT ' "$log" || true)"
    if [ "$verdict_count" -ne 1 ]; then
        fail "expected exactly one SUITE VERDICT line, found $verdict_count"
        bad=1
    else
        verdict="$(grep '^SUITE VERDICT ' "$log")"
        read -r first second token <<< "$verdict"
        if [ "$first" != SUITE ] || [ "$second" != VERDICT ]; then
            fail 'suite verdict prefix is malformed'
            bad=1
        fi
        for token in ${verdict#SUITE VERDICT }; do
            case "$token" in
                *=*) key="${token%%=*}"; datum="${token#*=}" ;;
                *)
                    fail "suite verdict token is not key=value: $token"
                    bad=1
                    continue
                    ;;
            esac
            case "$key" in
                mode|groups_total|groups_ran|groups_cached|groups_gated|groups_failed|self_skips|env_unobserved|toolkey) ;;
                *)
                    fail "unknown suite verdict field: $key"
                    bad=1
                    continue
                    ;;
            esac
            if [ -n "${value[$key]+x}" ]; then
                fail "duplicate suite verdict field: $key"
                bad=1
                continue
            fi
            value["$key"]="$datum"
        done
    fi

    for key in mode groups_total groups_ran groups_cached groups_gated \
               groups_failed self_skips env_unobserved toolkey; do
        if [ -z "${value[$key]+x}" ]; then
            fail "suite verdict is missing field: $key"
            bad=1
        fi
    done

    if [ "${value[mode]-}" != cold ]; then
        fail "suite mode is '${value[mode]-missing}', expected cold"
        bad=1
    fi
    for key in groups_total groups_ran groups_cached groups_gated \
               groups_failed self_skips env_unobserved; do
        if ! [[ "${value[$key]-}" =~ ^[0-9]+$ ]]; then
            fail "suite field $key is not a non-negative integer: ${value[$key]-missing}"
            bad=1
        fi
    done
    if ! [[ "${value[toolkey]-}" =~ ^[0-9a-f]{12}$ ]]; then
        fail "suite toolkey is not 12 lowercase hex characters: ${value[toolkey]-missing}"
        bad=1
    fi

    if [ "$bad" -eq 0 ]; then
        total_n=$((10#${value[groups_total]}))
        ran_n=$((10#${value[groups_ran]}))
        cached_n=$((10#${value[groups_cached]}))
        gated_n=$((10#${value[groups_gated]}))
        failed_n=$((10#${value[groups_failed]}))
        skips_n=$((10#${value[self_skips]}))
        unobserved_n=$((10#${value[env_unobserved]}))
        if [ "$total_n" -eq 0 ] || [ "$ran_n" -eq 0 ]; then
            fail "suite executed no groups (total=$total_n ran=$ran_n)"
            bad=1
        fi
        if [ "$cached_n" -ne 0 ]; then
            fail "suite reused $cached_n cached group(s); hosted proof must be cold"
            bad=1
        fi
        if [ "$failed_n" -ne 0 ]; then
            fail "suite reports $failed_n failed group(s)"
            bad=1
        fi
        if [ "$unobserved_n" -ne 0 ]; then
            fail "suite reports $unobserved_n environment-unobserved group(s)"
            bad=1
        fi
        if [ $((ran_n + gated_n)) -ne "$total_n" ]; then
            fail "suite accounting is incomplete: ran=$ran_n gated=$gated_n total=$total_n"
            bad=1
        fi
        if [ "$skips_n" -gt "$ran_n" ]; then
            fail "suite self-skips exceed executed groups: skips=$skips_n ran=$ran_n"
            bad=1
        fi
    fi

    if [ "$(grep -c '^ALL TESTS PASSED — ' "$log" || true)" -ne 1 ]; then
        fail 'expected exactly one cold ALL TESTS PASSED headline'
        bad=1
    fi
    if grep -q '^ALL TESTS PASSED (CACHED)' "$log"; then
        fail 'cached pass headline is not hosted cold-suite evidence'
        bad=1
    fi
    if grep -q '^SOME TESTS FAILED' "$log"; then
        fail 'failure headline is present'
        bad=1
    fi

    [ "$bad" -eq 0 ] || return 1
    printf 'hosted-suite-verdict: PASS: cold groups_total=%s groups_ran=%s groups_gated=%s self_skips=%s\n' \
        "${value[groups_total]}" "${value[groups_ran]}" \
        "${value[groups_gated]}" "${value[self_skips]}"
}

self_test()
{
    local fixture_dir good cached zero_run duplicate unobserved
    fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/zcl-hosted-suite-verdict.XXXXXX")" ||
        return 1
    HOSTED_SUITE_FIXTURE_DIR="$fixture_dir"
    trap cleanup_fixture EXIT
    good="$fixture_dir/good.log"
    cached="$fixture_dir/cached.log"
    zero_run="$fixture_dir/zero-run.log"
    duplicate="$fixture_dir/duplicate.log"
    unobserved="$fixture_dir/unobserved.log"

    printf '%s\n' \
        'SUITE VERDICT mode=cold groups_total=1050 groups_ran=1041 groups_cached=0 groups_gated=9 groups_failed=0 self_skips=20 env_unobserved=0 toolkey=34e55dd75397' \
        'ALL TESTS PASSED — 0/1041 groups failed, 20 skipped' > "$good"
    check_log "$good" >/dev/null || {
        fail 'self-test rejected the valid cold fixture'
        return 1
    }

    printf '%s\n' \
        'SUITE VERDICT mode=cached groups_total=1050 groups_ran=0 groups_cached=1041 groups_gated=9 groups_failed=0 self_skips=0 env_unobserved=0 toolkey=34e55dd75397' \
        'ALL TESTS PASSED (CACHED) — 0/1041 groups failed, 0 skipped' > "$cached"
    if check_log "$cached" >/dev/null 2>&1; then
        fail 'self-test mutation survived: cached zero-run log was admitted'
        return 1
    fi

    printf '%s\n' \
        'SUITE VERDICT mode=cold groups_total=9 groups_ran=0 groups_cached=0 groups_gated=9 groups_failed=0 self_skips=0 env_unobserved=0 toolkey=34e55dd75397' \
        'ALL TESTS PASSED — 0/0 groups failed, 0 skipped' > "$zero_run"
    if check_log "$zero_run" >/dev/null 2>&1; then
        fail 'self-test mutation survived: cold zero-run log was admitted'
        return 1
    fi

    printf '%s\n' \
        'SUITE VERDICT mode=cold groups_total=1050 groups_ran=1041 groups_cached=0 groups_gated=9 groups_failed=0 groups_failed=0 self_skips=20 env_unobserved=0 toolkey=34e55dd75397' \
        'ALL TESTS PASSED — 0/1041 groups failed, 20 skipped' > "$duplicate"
    if check_log "$duplicate" >/dev/null 2>&1; then
        fail 'self-test mutation survived: duplicate verdict field was admitted'
        return 1
    fi

    printf '%s\n' \
        'SUITE VERDICT mode=cold groups_total=1050 groups_ran=1041 groups_cached=0 groups_gated=9 groups_failed=0 self_skips=20 env_unobserved=1 toolkey=34e55dd75397' \
        'ALL TESTS PASSED — 0/1041 groups failed, 20 skipped' > "$unobserved"
    if check_log "$unobserved" >/dev/null 2>&1; then
        fail 'self-test mutation survived: environment-unobserved run was admitted'
        return 1
    fi

    cleanup_fixture
    HOSTED_SUITE_FIXTURE_DIR=""
    trap - EXIT
    printf '%s\n' 'hosted-suite-verdict self-test: PASS (valid cold + 4 rejecting mutations)'
}

case "${1:-}" in
    --self-test)
        [ "$#" -eq 1 ] || { fail 'usage: check_hosted_suite_verdict.sh --self-test | LOG'; exit 2; }
        self_test
        ;;
    '')
        fail 'usage: check_hosted_suite_verdict.sh --self-test | LOG'
        exit 2
        ;;
    *)
        [ "$#" -eq 1 ] || { fail 'usage: check_hosted_suite_verdict.sh --self-test | LOG'; exit 2; }
        check_log "$1"
        ;;
esac
