#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Cache-aware fast lane for agent/operator edit loops.
# This is deliberately not the release gate; pre-push/full CI remains authority.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SCHEMA="zcl.agent_fast_ci.v1"
PLAN_SCHEMA="zcl.agent_fast_plan.v1"
CACHE_SCHEMA="zcl.agent_fast_ci.cache.v4"
FAST_CC="${ZCL_FAST_CC:-}"
FAST_COMPILE="${ZCL_FAST_COMPILE:-changed}"
CACHE_ROOT="${ZCL_FAST_CACHE_DIR:-$ROOT/.cache/zcl-agent-fast-ci}"
CACHE_KEY=""
CACHE_RECORD=""
CACHE_AVAILABLE=0
CACHE_SOURCE_ID=""
CACHE_SOURCE_MUTATION=""
CACHE_TOOL="none"
PROOF_SCOPE="full_source_inventory"
VERIFY_ARTIFACT=""
TEST_GROUPS=""
UNMAPPED_CODE_CHANGES=""
COMPILE_PLAN_KIND=""
COMPILE_PLAN_TARGET=""
COMPILE_PLAN_DETAIL=""
COMPILE_PLAN_FALLBACK_REASON=""
NODE_BIN="${ZCL_FAST_NODE_BIN:-build/bin/z23}"
DEV_NODE_BIN="${ZCL_FAST_DEV_NODE_BIN:-build/bin/z23-dev}"
FAST_JOBS="${ZCL_FAST_JOBS:-}"
IMPACT_RULES_FILE="${ZCL_FAST_IMPACT_RULES_FILE:-app/controllers/include/controllers/agent_impact_rules.def}"
FROZEN_SOURCE_RECORD="${ZCL_FAST_BUILD_SOURCE_RECORD:-}"
FOCUSED_RECEIPT_RAN=0
FOCUSED_RECEIPT_REUSED=0
FOCUSED_RECEIPT_TOOLKEY=""

log() {
    printf '[agent-fast-ci] %s\n' "$*"
}

fail() {
    log "FAIL: $*"
    exit 1
}

json_escape() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_array_words() {
    local sep="" item
    printf '['
    for item in "$@"; do
        [ -n "$item" ] || continue
        printf '%s"%s"' "$sep" "$(json_escape "$item")"
        sep=","
    done
    printf ']'
}

json_array_stdin() {
    local sep="" item
    printf '['
    while IFS= read -r item; do
        [ -n "$item" ] || continue
        printf '%s"%s"' "$sep" "$(json_escape "$item")"
        sep=","
    done
    printf ']'
}

select_compiler() {
    if [ -n "$FAST_CC" ]; then
        case "$FAST_CC" in
            *sccache*) CACHE_TOOL="sccache" ;;
            *ccache*) CACHE_TOOL="ccache" ;;
            *) CACHE_TOOL="custom" ;;
        esac
        return
    fi

    if command -v sccache >/dev/null 2>&1; then
        FAST_CC="sccache cc"
        CACHE_TOOL="sccache"
    elif command -v ccache >/dev/null 2>&1; then
        FAST_CC="ccache cc"
        CACHE_TOOL="ccache"
    else
        FAST_CC="cc"
        CACHE_TOOL="none"
    fi
}

resolve_fast_jobs() {
    if [ -z "$FAST_JOBS" ]; then
        FAST_JOBS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 8)"
        case "$FAST_JOBS" in
            ''|*[!0-9]*) FAST_JOBS=8 ;;
        esac
        if [ "$FAST_JOBS" -gt 16 ] 2>/dev/null; then
            FAST_JOBS=16
        fi
    fi
    case "$FAST_JOBS" in
        ''|*[!0-9]*|0)
            fail "ZCL_FAST_JOBS must be a positive integer (got ${FAST_JOBS:-empty})"
            ;;
    esac
}

show_cache_stats() {
    case "$CACHE_TOOL" in
        sccache)
            command -v sccache >/dev/null 2>&1 && sccache --show-stats || true
            ;;
        ccache)
            command -v ccache >/dev/null 2>&1 && ccache -s || true
            ;;
        *)
            ;;
    esac
}

make_fast() {
    resolve_fast_jobs
    [ -n "$FROZEN_SOURCE_RECORD" ] ||
        fail "internal source record was not prepared before nested Make"
    make -j"$FAST_JOBS" CC="$FAST_CC" \
        BUILD_SOURCE_RECORD="$FROZEN_SOURCE_RECORD" "$@"
}

fast_changed_files_only() {
    case "${ZCL_FAST_CHANGED_FILES_ONLY:-0}" in
        1|true|yes|only) return 0 ;;
        0|false|no|"") return 1 ;;
        *) fail "unknown ZCL_FAST_CHANGED_FILES_ONLY=${ZCL_FAST_CHANGED_FILES_ONLY}" ;;
    esac
}

validate_changed_files_only() {
    if fast_changed_files_only &&
       [ -z "${ZCL_FAST_CHANGED_FILES_FILE:-}" ] &&
       [ -z "${ZCL_FAST_CHANGED_FILES:-}" ]; then
        fail "ZCL_FAST_CHANGED_FILES_ONLY requires explicit changed-file hints"
    fi
}

# These paths are classification/UX hints only. Git history and caller-supplied
# lists cannot prove a complete source delta and therefore never reduce the
# compile or test proof below PROOF_SCOPE=full_source_inventory.
changed_file_hints() {
    if [ -n "${ZCL_FAST_CHANGED_FILES_FILE:-}" ]; then
        [ -f "$ZCL_FAST_CHANGED_FILES_FILE" ] ||
            fail "ZCL_FAST_CHANGED_FILES_FILE does not exist: $ZCL_FAST_CHANGED_FILES_FILE"
        cat "$ZCL_FAST_CHANGED_FILES_FILE"
    fi
    if [ -n "${ZCL_FAST_CHANGED_FILES:-}" ]; then
        printf '%s\n' "$ZCL_FAST_CHANGED_FILES" | tr ' ,' '\n'
    fi
    if fast_changed_files_only; then
        return
    fi
    if [ -n "${ZCL_FAST_BASE:-}" ]; then
        git diff --name-only "$ZCL_FAST_BASE"...HEAD -- || true
    fi
    git diff --name-only HEAD --
    git diff --cached --name-only --
    git ls-files --others --exclude-standard
}

add_group() {
    local group="$1"
    case " $TEST_GROUPS " in
        *" $group "*) ;;
        *) TEST_GROUPS="${TEST_GROUPS:+$TEST_GROUPS }$group" ;;
    esac
}

add_unmapped_code_change() {
    local file="$1"
    case " $UNMAPPED_CODE_CHANGES " in
        *" $file "*) ;;
        *) UNMAPPED_CODE_CHANGES="${UNMAPPED_CODE_CHANGES:+$UNMAPPED_CODE_CHANGES }$file" ;;
    esac
}

# Transient lint/shape-gate fixture naming contract: test_make_lint_gates.c
# plants `_*fixture*.c` files under app/, lib/, domain/, etc. to exercise
# the gate scripts (E1-E13, raw-malloc, observability, ...), then deletes
# them before the test returns. A changed-file scan that samples the tree
# mid-test (this script's own `-changed`/`compile-changed` gates, or a
# concurrently running `dev-watch`/`pre-push-ci`) can observe one of these as
# a transient changed-path hint and pollute the mapping diagnostic even though
# the actual push is clean. Treat it as never a real source change everywhere
# the changed-file set feeds a classification decision. Kept in sync with
# zcl_devloop_path_is_relevant() in tools/dev/devloop_plan.c (real, tracked
# fixture sources live under lib/test/fixtures/ and have no leading '_').
is_transient_lint_fixture() {
    case "$1" in
        */_*fixture*.c|_*fixture*.c)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_code_like_change() {
    local file="$1"
    is_transient_lint_fixture "$file" && return 1
    case "$file" in
        *.c|*.h|Makefile|*.mk|tools/*.sh|tools/githooks/*)
            return 0
            ;;
        app/*|application/*|adapters/*|config/*|domain/*|lib/*|ports/*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_graph_wide_compile_change() {
    local file="$1"
    case "$file" in
        *.h|Makefile|*.mk|app/views/templates/*|app/views/css/*|tools/gen_templates.c|vendor/include/*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

is_node_c_source() {
    local file="$1"
    is_transient_lint_fixture "$file" && return 1
    case "$file" in
        src/main.c|app/*/src/*.c|config/src/*.c|\
        lib/*/src/*.c|domain/*/src/*.c|application/*/src/*.c|\
        adapters/outbound/persistence/src/*.c)
            case "$file" in
                lib/test/*|tools/sim/*)
                    return 1
                    ;;
                *)
                    return 0
                    ;;
            esac
            ;;
        *)
            return 1
            ;;
    esac
}

match_shared_impact_rules() {
    local file="$1" line patterns groups pattern group matched rule_re
    [ -f "$IMPACT_RULES_FILE" ] ||
        fail "agent impact rule file missing: $IMPACT_RULES_FILE"

    matched=1
    rule_re='^[[:space:]]*AGENT_IMPACT_RULE\("([^"]*)",[[:space:]]*"([^"]*)"\)'
    while IFS= read -r line; do
        [[ "$line" =~ $rule_re ]] || continue
        patterns="${BASH_REMATCH[1]}"
        groups="${BASH_REMATCH[2]}"
        IFS='|' read -r -a rule_patterns <<< "$patterns"
        for pattern in "${rule_patterns[@]}"; do
            case "$file" in
                $pattern)
                    for group in $groups; do
                        add_group "$group"
                    done
                    matched=0
                    break
                    ;;
            esac
        done
    done < "$IMPACT_RULES_FILE"
    return "$matched"
}

select_test_groups() {
    local file matched
    TEST_GROUPS=""
    UNMAPPED_CODE_CHANGES=""
    if [ -n "${ZCL_FAST_TESTS:-}" ]; then
        for file in $(printf '%s\n' "$ZCL_FAST_TESTS" | tr ',:' '  '); do
            [ -n "$file" ] && add_group "$file"
        done
        return
    fi

    while IFS= read -r file; do
        [ -n "$file" ] || continue
        matched=0
        if match_shared_impact_rules "$file"; then
            matched=1
        fi
        if [ "$matched" -eq 0 ] && is_code_like_change "$file"; then
            add_unmapped_code_change "$file"
        fi
    done <<EOF
$(changed_file_hints | sort -u)
EOF
}

note_unmapped_code_changes() {
    if [ -n "$UNMAPPED_CODE_CHANGES" ]; then
        log "classification hints without focused mappings: $UNMAPPED_CODE_CHANGES (source-wide proof scope is unchanged)"
    fi
}

fast_cache_enabled() {
    case "${ZCL_FAST_CACHE:-1}" in
        1|true|yes|on|"") return 0 ;;
        0|false|no|off|skip) return 1 ;;
        *) fail "unknown ZCL_FAST_CACHE=${ZCL_FAST_CACHE}" ;;
    esac
}

maybe_reset_fast_cache() {
    case "${ZCL_FAST_CACHE_RESET:-0}" in
        1|true|yes|reset)
            rm -rf "$CACHE_ROOT"
            log "fast result cache reset at $CACHE_ROOT"
            ;;
        0|false|no|"") ;;
        *) fail "unknown ZCL_FAST_CACHE_RESET=${ZCL_FAST_CACHE_RESET}" ;;
    esac
}

hash_file() {
    sha256sum "$1" | awk '{print $1}'
}

is_sha256_hex() {
    [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}

capture_source_identity_record() {
    local tool="$ROOT/tools/dev/source-identity.sh"
    local record source_id clean mutation extra
    [ -x "$tool" ] || return 2
    record="$(cd "$ROOT" && "$tool" capture-record 2>/dev/null)" || return 2
    read -r source_id clean mutation extra <<< "$record"
    is_sha256_hex "$source_id" && [ "$clean" = "1" ] &&
        is_sha256_hex "$mutation" && [ -z "${extra:-}" ] || return 2
    printf '%s %s %s\n' "$source_id" "$clean" "$mutation"
}

prepare_frozen_source_record() {
    local source_id clean mutation extra

    if [ -z "$FROZEN_SOURCE_RECORD" ]; then
        FROZEN_SOURCE_RECORD="$(capture_source_identity_record)" ||
            fail "exact source record capture failed"
    fi
    read -r source_id clean mutation extra <<< "$FROZEN_SOURCE_RECORD"
    if ! is_sha256_hex "$source_id" || [ "$clean" != "1" ] ||
       ! is_sha256_hex "$mutation" || [ -n "${extra:-}" ]; then
        fail "ZCL_FAST_BUILD_SOURCE_RECORD must be '<sha256> 1 <sha256>'"
    fi
    # Normalize whitespace before this value becomes one command-line Make
    # assignment.  Build-session acquire/final verification still compare it
    # with the exact current source inventory.
    FROZEN_SOURCE_RECORD="$source_id $clean $mutation"
}

cycle_source_identity_record() {
    [ -n "$FROZEN_SOURCE_RECORD" ] || return 2
    printf '%s\n' "$FROZEN_SOURCE_RECORD"
}

verify_frozen_source_record() {
    local source_id clean mutation extra
    read -r source_id clean mutation extra <<< "$FROZEN_SOURCE_RECORD"
    [ -z "${extra:-}" ] || return 1
    "$ROOT/tools/dev/source-identity.sh" verify-record \
        "$source_id" "$clean" "$mutation" >/dev/null 2>&1
}

cache_manifest_file() {
    local label="$1" path="$2"
    if [ -f "$path" ]; then
        printf 'file\t%s\t%s\t%s\n' "$label" "$path" "$(hash_file "$path")"
    elif [ -e "$path" ]; then
        printf 'file\t%s\t%s\tpresent-nonregular\n' "$label" "$path"
    else
        printf 'file\t%s\t%s\tabsent\n' "$label" "$path"
    fi
}

cache_manifest() {
    local file node_stat cc_version source_record clean
    source_record="$(cycle_source_identity_record)" || return 2
    read -r CACHE_SOURCE_ID clean CACHE_SOURCE_MUTATION <<< "$source_record"
    printf 'cache_schema\t%s\n' "$CACHE_SCHEMA"
    printf 'fast_schema\t%s\n' "$SCHEMA"
    printf 'proof_scope\t%s\n' "$PROOF_SCOPE"
    printf 'source_identity_schema\tzcl.dev_source_identity.v2\n'
    printf 'source_id_sha256\t%s\n' "$CACHE_SOURCE_ID"
    printf 'source_mutation_token\t%s\n' "$CACHE_SOURCE_MUTATION"
    printf 'fast_base\t%s\n' "${ZCL_FAST_BASE:-}"
    printf 'fast_cc\t%s\n' "$FAST_CC"
    printf 'cache_tool\t%s\n' "$CACHE_TOOL"
    printf 'fast_jobs\t%s\n' "$FAST_JOBS"
    printf 'fast_compile\t%s\n' "$FAST_COMPILE"
    printf 'fast_tests_env\t%s\n' "${ZCL_FAST_TESTS:-}"
    printf 'fast_strict_tests\t%s\n' "${ZCL_FAST_STRICT_TESTS:-0}"
    printf 'fast_live\t%s\n' "${ZCL_FAST_LIVE:-auto}"
    printf 'node_bin\t%s\n' "$NODE_BIN"
    printf 'impact_rules_file\t%s\n' "$IMPACT_RULES_FILE"
    printf 'make_version\t%s\n' "$(make --version 2>/dev/null | sed -n '1p' || echo unknown)"
    cc_version="$($FAST_CC --version 2>/dev/null | sed -n '1p' || true)"
    printf 'cc_version\t%s\n' "${cc_version:-unknown}"

    if [ -e "$NODE_BIN" ]; then
        node_stat="$(stat -c '%s:%Y' "$NODE_BIN" 2>/dev/null || echo unknown)"
    else
        node_stat="absent"
    fi
    printf 'node_bin_stat\t%s\n' "$node_stat"

    for file in Makefile "$IMPACT_RULES_FILE" tools/agent_fast_ci.sh \
        tools/githooks/pre-push tools/deploy_guard.sh tools/deploy_verify.sh \
        tools/dev/deploy-dev-lane.sh tools/dev/agent-dev-status.sh \
        tools/dev/agent-doctor.sh \
        tools/dev/reflex-hotfork-transport-acceptance.sh \
        tools/dev/reflex-hotfork-source-bundle-acceptance.sh \
        tools/scripts/remote_node_update.sh \
        tools/scripts/lane_recover.sh \
        tools/scripts/check_stable_publish_containment.sh \
        tools/scripts/build_vendor.sh \
        tools/scripts/background_quality_lane.sh \
        tools/scripts/check_agentdeployguard_cli_exit.sh \
        deploy/examples/zclassic23-remote-test-node.service \
        deploy/examples/zclassic23-remote-test.env.example \
        deploy/examples/zclassic23-self-update.service \
        deploy/examples/zclassic23-self-update.timer \
        deploy/zclassic23-fuzz.service deploy/zclassic23-fuzz.timer \
        deploy/zclassic23-coverage.service deploy/zclassic23-coverage.timer \
        deploy/zclassic23-test-suite.service deploy/zclassic23-test-suite.timer \
        lib/test/src/test_make_lint_gates.c docs/work/fast-path.md \
        docs/AGENT_API.md app/controllers/src/agent_controller.c \
        app/controllers/src/agent_lane_runtime.c \
        app/controllers/src/agent_runtime_controller.c; do
        cache_manifest_file "$file" "$file"
    done

    # Changed paths and mapped groups are routing diagnostics only. The
    # cached default lane compiles the full source inventory and runs the
    # source-wide test proof, so hints must not fragment identical evidence.
}

cache_authority_selftest() {
    local original_root="$ROOT" sandbox first second hinted dirty committed third
    local first_source third_source first_mutation third_mutation backup
    sandbox="$(mktemp -d "${TMPDIR:-/tmp}/zcl-fast-cache-selftest.XXXXXX")" ||
        return 1
    ROOT="$sandbox/repo"
    backup="$sandbox/source.backup"
    mkdir -p "$ROOT/tools/dev"
    cp "$original_root/tools/dev/source-identity.sh" \
        "$ROOT/tools/dev/source-identity.sh"
    chmod 755 "$ROOT/tools/dev/source-identity.sh"
    printf 'baseline\n' > "$ROOT/source.txt"
    git -C "$ROOT" init -q
    git -C "$ROOT" config user.name zcl-fast-cache-selftest
    git -C "$ROOT" config user.email fast-cache-selftest@invalid
    git -C "$ROOT" add source.txt tools/dev/source-identity.sh
    git -C "$ROOT" commit -qm baseline
    cd "$ROOT"
    CACHE_ROOT="$ROOT/.cache/zcl-agent-fast-ci"
    NODE_BIN="build/bin/z23"
    IMPACT_RULES_FILE="app/controllers/include/controllers/agent_impact_rules.def"
    FAST_CC=cc
    CACHE_TOOL=none
    FAST_JOBS=1

    FROZEN_SOURCE_RECORD="$(capture_source_identity_record)" || {
        rm -rf "$sandbox"
        return 1
    }
    first="$(cache_manifest)" || {
        rm -rf "$sandbox"
        return 1
    }
    git commit --allow-empty -qm history-only
    second="$(cache_manifest)" || {
        rm -rf "$sandbox"
        return 1
    }
    if [ "$first" != "$second" ]; then
        printf '%s\n' '[agent-fast-ci-selftest] FAIL: Git history changed cache authority' >&2
        rm -rf "$sandbox"
        return 1
    fi

    ZCL_FAST_CHANGED_FILES="source.txt"
    TEST_GROUPS="routing_hint_only"
    hinted="$(cache_manifest)" || {
        rm -rf "$sandbox"
        return 1
    }
    unset ZCL_FAST_CHANGED_FILES
    TEST_GROUPS=""
    if [ "$first" != "$hinted" ]; then
        printf '%s\n' '[agent-fast-ci-selftest] FAIL: routing hints fragmented source-wide proof reuse' >&2
        rm -rf "$sandbox"
        return 1
    fi

    printf 'accepted edit\n' >> source.txt
    FROZEN_SOURCE_RECORD="$(capture_source_identity_record)" || {
        rm -rf "$sandbox"
        return 1
    }
    dirty="$(cache_manifest)" || {
        rm -rf "$sandbox"
        return 1
    }
    git add source.txt
    git commit -qm accepted-edit
    FROZEN_SOURCE_RECORD="$(capture_source_identity_record)" || {
        rm -rf "$sandbox"
        return 1
    }
    committed="$(cache_manifest)" || {
        rm -rf "$sandbox"
        return 1
    }
    if [ "$dirty" != "$committed" ]; then
        printf '%s\n' '[agent-fast-ci-selftest] FAIL: committing identical authoritative source fragmented proof reuse' >&2
        rm -rf "$sandbox"
        return 1
    fi
    first="$committed"

    cp source.txt "$backup"
    printf 'transient edit\n' >> source.txt
    cp "$backup" source.txt
    chmod 600 source.txt
    chmod 644 source.txt
    FROZEN_SOURCE_RECORD="$(capture_source_identity_record)" || {
        rm -rf "$sandbox"
        return 1
    }
    third="$(cache_manifest)" || {
        rm -rf "$sandbox"
        return 1
    }
    first_source="$(printf '%s\n' "$first" | sed -n 's/^source_id_sha256[[:space:]]*//p')"
    third_source="$(printf '%s\n' "$third" | sed -n 's/^source_id_sha256[[:space:]]*//p')"
    first_mutation="$(printf '%s\n' "$first" | sed -n 's/^source_mutation_token[[:space:]]*//p')"
    third_mutation="$(printf '%s\n' "$third" | sed -n 's/^source_mutation_token[[:space:]]*//p')"
    if [ "$first_source" != "$third_source" ] ||
       [ "$first_mutation" = "$third_mutation" ] ||
       [ "$first" = "$third" ]; then
        printf '%s\n' '[agent-fast-ci-selftest] FAIL: edit/revert ABA did not supersede cache authority' >&2
        rm -rf "$sandbox"
        return 1
    fi
    compute_changed_compile_plan
    if [ "$COMPILE_PLAN_KIND" != full_source_inventory ] ||
       [ "$COMPILE_PLAN_TARGET" != fast-compile ]; then
        printf '%s\n' '[agent-fast-ci-selftest] FAIL: path hints reduced compile proof scope' >&2
        rm -rf "$sandbox"
        return 1
    fi
    rm -rf "$sandbox"
    printf '%s\n' '[agent-fast-ci-selftest] PASS: exact cache authority is history/commit-transition independent and ABA-safe; routing hints neither reduce nor fragment source-wide proof scope'
}

compute_cache_key() {
    local manifest key
    CACHE_AVAILABLE=0
    CACHE_KEY=""
    CACHE_RECORD=""
    CACHE_SOURCE_ID=""
    CACHE_SOURCE_MUTATION=""

    if ! fast_cache_enabled; then
        log "fast result cache disabled by ZCL_FAST_CACHE=${ZCL_FAST_CACHE:-0}"
        return 1
    fi
    if ! command -v sha256sum >/dev/null 2>&1; then
        log "fast result cache unavailable: sha256sum not found"
        return 1
    fi
    mkdir -p "$CACHE_ROOT"
    manifest="$(mktemp "$CACHE_ROOT/manifest.XXXXXX")" || return 1
    if ! cache_manifest >"$manifest"; then
        rm -f "$manifest"
        log "fast result cache unavailable: could not write manifest"
        return 1
    fi
    key="$(sha256sum "$manifest" | awk '{print $1}')"
    rm -f "$manifest"
    [ -n "$key" ] || return 1
    CACHE_KEY="$key"
    CACHE_RECORD="$CACHE_ROOT/$CACHE_KEY.ok"
    CACHE_AVAILABLE=1
    return 0
}

maybe_fast_cache_hit() {
    compute_cache_key || return 1
    [ -f "$CACHE_RECORD" ] || return 1
    if ! grep -q "^schema=$CACHE_SCHEMA$" "$CACHE_RECORD"; then
        rm -f "$CACHE_RECORD"
        return 1
    fi
    if ! verify_frozen_source_record; then
        log "fast result cache input was superseded during lookup"
        return 1
    fi
    log "fast result cache hit key=$CACHE_KEY; skipping previously proven source-wide lint/compile/test scope"
    return 0
}

record_fast_cache_pass() {
    local old_key tmp
    [ "$CACHE_AVAILABLE" = "1" ] || return 0
    old_key="$CACHE_KEY"
    if ! verify_frozen_source_record; then
        log "fast result cache not stored; exact source record was superseded"
        return 0
    fi
    compute_cache_key || return 0
    if [ "$CACHE_KEY" != "$old_key" ]; then
        log "fast result cache not stored; inputs changed during run"
        return 0
    fi

    tmp="$(mktemp "$CACHE_ROOT/pass.XXXXXX")" || return 0
    {
        printf 'schema=%s\n' "$CACHE_SCHEMA"
        printf 'key=%s\n' "$CACHE_KEY"
        printf 'stored_at=%s\n' "$(date -u +%FT%TZ)"
        printf 'groups=%s\n' "$TEST_GROUPS"
        printf 'node_bin=%s\n' "$NODE_BIN"
    } >"$tmp"
    mv "$tmp" "$CACHE_RECORD"
    log "fast result cache stored key=$CACHE_KEY"
}

PLAN_CACHE_ENABLED="true"
PLAN_CACHE_AVAILABLE="false"
PLAN_CACHE_HIT="false"
PLAN_CACHE_REASON=""

compute_plan_cache_status() {
    local manifest key record
    PLAN_CACHE_ENABLED="true"
    PLAN_CACHE_AVAILABLE="false"
    PLAN_CACHE_HIT="false"
    PLAN_CACHE_REASON=""
    CACHE_KEY=""
    CACHE_RECORD=""
    CACHE_SOURCE_ID=""
    CACHE_SOURCE_MUTATION=""

    case "${ZCL_FAST_CACHE:-1}" in
        1|true|yes|on|"") ;;
        0|false|no|off|skip)
            PLAN_CACHE_ENABLED="false"
            PLAN_CACHE_REASON="disabled_by_ZCL_FAST_CACHE"
            return
            ;;
        *)
            PLAN_CACHE_REASON="invalid_ZCL_FAST_CACHE"
            return
            ;;
    esac

    if ! command -v sha256sum >/dev/null 2>&1; then
        PLAN_CACHE_REASON="sha256sum_not_found"
        return
    fi
    if ! mkdir -p "$CACHE_ROOT" 2>/dev/null; then
        PLAN_CACHE_REASON="cache_root_unwritable"
        return
    fi
    manifest="$(mktemp "$CACHE_ROOT/manifest.XXXXXX" 2>/dev/null || true)"
    if [ -z "$manifest" ]; then
        PLAN_CACHE_REASON="manifest_create_failed"
        return
    fi
    if ! cache_manifest >"$manifest"; then
        rm -f "$manifest"
        PLAN_CACHE_REASON="manifest_write_failed"
        return
    fi
    key="$(sha256sum "$manifest" | awk '{print $1}')"
    rm -f "$manifest"
    if [ -z "$key" ]; then
        PLAN_CACHE_REASON="cache_key_empty"
        return
    fi

    record="$CACHE_ROOT/$key.ok"
    CACHE_KEY="$key"
    CACHE_RECORD="$record"
    PLAN_CACHE_AVAILABLE="true"
    if [ -f "$record" ] && grep -q "^schema=$CACHE_SCHEMA$" "$record"; then
        PLAN_CACHE_HIT="true"
        PLAN_CACHE_REASON="green_input_cache_hit"
    else
        PLAN_CACHE_REASON="cache_miss"
    fi
}

changed_file_count() {
    changed_file_hints | sort -u | sed '/^$/d' | wc -l | tr -d ' '
}

recommended_plan_command() {
    local changed_count="$1"
    if [ -n "$UNMAPPED_CODE_CHANGES" ]; then
        printf 'set ZCL_FAST_TESTS=<group[,group]> or extend %s' "$IMPACT_RULES_FILE"
    elif [ "$changed_count" = "0" ]; then
        printf 'make agent-dev-status'
    elif [ "$PLAN_CACHE_HIT" = "true" ]; then
        printf 'make fast-ci'
    else
        printf 'make agent-loop'
    fi
}

emit_plan_json() {
    local changed_count command

    select_compiler
    resolve_fast_jobs
    validate_changed_files_only
    select_test_groups
    compute_changed_compile_plan
    compute_plan_cache_status

    changed_count="$(changed_file_count)"
    command="$(recommended_plan_command "$changed_count")"

    printf '{\n'
    printf '  "schema": "%s",\n' "$PLAN_SCHEMA"
    printf '  "status": "ok",\n'
    printf '  "proof_scope": "%s",\n' "$PROOF_SCOPE"
    printf '  "changed_files_semantics": "hint_only_non_authoritative",\n'
    printf '  "compiler": "%s",\n' "$(json_escape "$FAST_CC")"
    printf '  "cache_tool": "%s",\n' "$(json_escape "$CACHE_TOOL")"
    printf '  "jobs": "%s",\n' "$(json_escape "$FAST_JOBS")"
    printf '  "fast_compile_mode": "%s",\n' "$(json_escape "$FAST_COMPILE")"
    printf '  "changed_file_count": %s,\n' "$changed_count"
    printf '  "changed_files": '
    changed_file_hints | sort -u | json_array_stdin
    printf ',\n'
    printf '  "test_groups": '
    json_array_words $TEST_GROUPS
    printf ',\n'
    printf '  "unmapped_code_changes": '
    json_array_words $UNMAPPED_CODE_CHANGES
    printf ',\n'
    printf '  "compile_plan": {\n'
    printf '    "schema": "zcl.agent_changed_compile_plan.v2",\n'
    printf '    "kind": "%s",\n' "$(json_escape "$COMPILE_PLAN_KIND")"
    printf '    "target": "%s",\n' "$(json_escape "$COMPILE_PLAN_TARGET")"
    printf '    "detail": "%s",\n' "$(json_escape "$COMPILE_PLAN_DETAIL")"
    printf '    "fallback_reason": "%s",\n' "$(json_escape "$COMPILE_PLAN_FALLBACK_REASON")"
    printf '    "proof_scope": "%s",\n' "$PROOF_SCOPE"
    printf '    "path_hint_role": "classification_only"\n'
    printf '  },\n'
    printf '  "green_input_cache": {\n'
    printf '    "schema": "%s",\n' "$CACHE_SCHEMA"
    printf '    "authority": "source_id_sha256_plus_mutation_token",\n'
    printf '    "source_id_sha256": "%s",\n' \
        "$(json_escape "$CACHE_SOURCE_ID")"
    printf '    "source_mutation_token": "%s",\n' \
        "$(json_escape "$CACHE_SOURCE_MUTATION")"
    printf '    "enabled": %s,\n' "$PLAN_CACHE_ENABLED"
    printf '    "available": %s,\n' "$PLAN_CACHE_AVAILABLE"
    printf '    "hit": %s,\n' "$PLAN_CACHE_HIT"
    printf '    "key": "%s",\n' "$(json_escape "$CACHE_KEY")"
    printf '    "record": "%s",\n' "$(json_escape "$CACHE_RECORD")"
    printf '    "reason": "%s",\n' "$(json_escape "$PLAN_CACHE_REASON")"
    printf '    "root": "%s"\n' "$(json_escape "$CACHE_ROOT")"
    printf '  },\n'
    printf '  "native_shortcuts": {\n'
    printf '    "fresh_source_tree": "z23 <leaf> [--input=json]",\n'
    printf '    "dev_linger_lane": "z23-dev <leaf> [--input=json]",\n'
    printf '    "discover": "z23 discover help | z23 discover search <q>",\n'
    printf '    "dev_hotswap_probe": "contained_before_dlopen_use_build_test_sim"\n'
    printf '  },\n'
    printf '  "dev_lane": {\n'
    printf '    "runtime_publication": false,\n'
    printf '    "publication_blocker": "immutable epoch/proof/resident-CAS/rollback transaction incomplete",\n'
    printf '    "status": "make agent-dev-status",\n'
    printf '    "stage_without_restart": "make agent-stage-dev",\n'
    printf '    "hot_swap_restart": "make agent-deploy-fast",\n'
    printf '    "loop_stage": "ZCL_AGENT_LOOP_DEPLOY=stage make agent-loop",\n'
    printf '    "loop_deploy": "ZCL_AGENT_LOOP_DEPLOY=dev make agent-loop"\n'
    printf '  },\n'
    printf '  "live_probe_mode": "%s",\n' "$(json_escape "${ZCL_FAST_LIVE:-auto}")"
    printf '  "recommended_command": "%s"\n' "$(json_escape "$command")"
    printf '}\n'
}

run_shell_checks() {
    local script
    log "shell checks"
    git diff --check
    # These source-wide authority gates are part of the cached proof.  They
    # run before a v3 receipt can be written; an exact-source cache hit may
    # therefore reattach without paying their cost on every warm interaction.
    make_fast watcher-safety-gates
    tools/agent_fast_ci.sh receipt-selftest
    for script in tools/agent_fast_ci.sh tools/githooks/pre-push \
        tools/deploy_guard.sh tools/deploy_verify.sh \
        tools/dev/deploy-dev-lane.sh tools/dev/agent-dev-status.sh \
        tools/dev/agent-doctor.sh \
        tools/scripts/remote_node_update.sh \
        tools/scripts/lane_recover.sh \
        tools/scripts/check_stable_publish_containment.sh \
        tools/scripts/build_vendor.sh \
        tools/scripts/background_quality_lane.sh \
        tools/scripts/check_agentdeployguard_cli_exit.sh; do
        bash -n "$script"
    done
}

focused_receipt_uint() {
    local verdict="$1" key="$2"
    printf '%s\n' "$verdict" |
        sed -n "s/.* ${key}=\([0-9][0-9]*\).*/\1/p" | head -1
}

# A cached runner exit of zero is not, by itself, push authority. Require the
# runner's machine verdict to account for every selected exact group, reject
# failures, and reject runtime SKIP markers. The test cache stores only
# skip-free PASS, so a reused group is exactly as strong as the fresh PASS that
# minted its content-addressed receipt.
validate_focused_receipt() {
    local output="$1" expected="$2" verdict ran reused failed skips toolkey
    verdict="$(printf '%s\n' "$output" |
        sed -n '/^SUITE VERDICT /p' | tail -1)"
    if [ -z "$verdict" ]; then
        log "focused receipt invalid reason=missing_suite_verdict"
        return 1
    fi
    ran="$(focused_receipt_uint "$verdict" groups_ran)"
    reused="$(focused_receipt_uint "$verdict" groups_cached)"
    failed="$(focused_receipt_uint "$verdict" groups_failed)"
    skips="$(focused_receipt_uint "$verdict" self_skips)"
    toolkey="$(printf '%s\n' "$verdict" |
        sed -n 's/.* toolkey=\([^[:space:]]*\).*/\1/p' | head -1)"
    case "$ran:$reused:$failed:$skips:$expected" in
        *[!0-9:]*|:*|*::*)
            log "focused receipt invalid reason=malformed_counts"
            return 1
            ;;
    esac
    if [ "$failed" -ne 0 ]; then
        log "focused receipt invalid reason=failed_groups count=$failed"
        return 1
    fi
    if [ "$skips" -ne 0 ]; then
        log "focused receipt invalid reason=self_skips count=$skips"
        return 1
    fi
    if [ $((ran + reused)) -ne "$expected" ]; then
        log "focused receipt invalid reason=accounting expected=$expected ran=$ran reused=$reused"
        return 1
    fi
    if [ -z "$toolkey" ]; then
        log "focused receipt invalid reason=missing_toolkey"
        return 1
    fi
    if [ "${#toolkey}" -ne 12 ]; then
        log "focused receipt invalid reason=malformed_toolkey"
        return 1
    fi
    case "$toolkey" in
        *[!0-9a-f]*)
            log "focused receipt invalid reason=malformed_toolkey"
            return 1
            ;;
    esac
    FOCUSED_RECEIPT_RAN="$ran"
    FOCUSED_RECEIPT_REUSED="$reused"
    FOCUSED_RECEIPT_TOOLKEY="$toolkey"
    return 0
}

focused_receipt_selftest() {
    local good prefix
    prefix="SUITE VERDICT mode=cached groups_total=946"
    good="$prefix groups_ran=2 groups_cached=3 groups_gated=941 groups_failed=0 self_skips=0 toolkey=0123456789ab"
    validate_focused_receipt "$good" 5 ||
        fail "focused receipt selftest rejected a complete PASS"
    if validate_focused_receipt "${good/self_skips=0/self_skips=1}" 5 >/dev/null; then
        fail "focused receipt selftest accepted a runtime SKIP"
    fi
    if validate_focused_receipt "${good/groups_failed=0/groups_failed=1}" 5 >/dev/null; then
        fail "focused receipt selftest accepted a failed group"
    fi
    if validate_focused_receipt "$good" 6 >/dev/null; then
        fail "focused receipt selftest accepted incomplete accounting"
    fi
    if validate_focused_receipt "ALL TESTS PASSED (CACHED)" 5 >/dev/null; then
        fail "focused receipt selftest accepted a missing machine verdict"
    fi
    log "PASS: focused receipt authority selftest"
}

run_test_proof() {
    local target
    target="test-parallel-fast-active"
    case "${ZCL_FAST_STRICT_TESTS:-0}" in
        1|true|yes|strict)
            target="test-parallel-active"
            ;;
        0|false|no|"") ;;
        *) fail "unknown ZCL_FAST_STRICT_TESTS=${ZCL_FAST_STRICT_TESTS}" ;;
    esac
    log "source-wide test proof target=$target jobs=${FAST_JOBS:-auto} classification_hints=${TEST_GROUPS:-none}"
    make_fast "$target"
}

compute_changed_compile_plan() {
    COMPILE_PLAN_KIND="full_source_inventory"
    COMPILE_PLAN_TARGET="fast-compile"
    COMPILE_PLAN_DETAIL="compile every current dev source input"
    COMPILE_PLAN_FALLBACK_REASON="changed-file lists are hint-only and cannot reduce proof scope"
}

compile_changed_gate() {
    compute_changed_compile_plan
    log "fast-changed-compile: source-wide fast-compile (path lists are classification hints only)"
    make_fast fast-compile
}

run_compile_gate() {
    local target
    case "$FAST_COMPILE" in
        changed|changed-dev|auto)
            compile_changed_gate
            return
            ;;
        dev|fast|quick|"")
            target="fast-compile"
            ;;
        strict|release|build-only)
            target="build-only"
            ;;
        *)
            fail "unknown ZCL_FAST_COMPILE=${FAST_COMPILE}"
            ;;
    esac
    log "$target"
    make_fast "$target"
}

run_dev_rebuild() {
    local start end size

    start="$(date +%s)"
    compile_changed_gate
    log "dev-bin link target=$DEV_NODE_BIN"
    make_fast "$DEV_NODE_BIN"
    [ -x "$DEV_NODE_BIN" ] ||
        fail "dev rebuild did not produce executable $DEV_NODE_BIN"

    end="$(date +%s)"
    size="$(stat -c '%s' "$DEV_NODE_BIN" 2>/dev/null || echo unknown)"
    log "PASS: dev rebuild complete bin=$DEV_NODE_BIN size=$size elapsed_s=$((end - start))"
    log "Use $DEV_NODE_BIN for local iteration; run make zclassic23 or make deploy for release/live."
}

live_service_detected() {
    if command -v systemctl >/dev/null 2>&1 &&
       systemctl --user is-active --quiet zclassic23; then
        return 0
    fi
    [ -f "$HOME/.zclassic-c23/.cookie" ]
}

validate_agent_json() {
    local json="$1"
    if command -v jq >/dev/null 2>&1; then
        if ! printf '%s\n' "$json" |
            jq -e '(.schema == "zcl.public_status.v3" or
                    .schema == "zcl.public_status.v2") and
                   .status == "healthy" and
                   .healthy == true and
                   .serving == true and
                   (.operator_needed == false)' >/dev/null; then
            log "agent probe summary: $(printf '%s\n' "$json" |
                jq -c '{schema,status,healthy,serving,operator_needed,gap,primary_blocker,next}' 2>/dev/null ||
                printf '%s' "$json")"
            fail "agent live probe did not report healthy serving status"
        fi
    else
        printf '%s\n' "$json" |
            grep -qE '"schema"[[:space:]]*:[[:space:]]*"zcl\.public_status\.v[23]"'
        printf '%s\n' "$json" |
            grep -q '"status"[[:space:]]*:[[:space:]]*"healthy"'
        printf '%s\n' "$json" |
            grep -q '"healthy"[[:space:]]*:[[:space:]]*true'
        printf '%s\n' "$json" |
            grep -q '"serving"[[:space:]]*:[[:space:]]*true'
        printf '%s\n' "$json" |
            grep -q '"operator_needed"[[:space:]]*:[[:space:]]*false'
    fi
}

validate_health_json() {
    local json="$1"
    if command -v jq >/dev/null 2>&1; then
        if ! printf '%s\n' "$json" |
            jq -e '.healthy == true and
                   .serving == true and
                   .checks.has_peers == true and
                   .checks.peer_count > 0 and
                   ((.checks.blocking_reason // "") == "")' >/dev/null; then
            log "health probe summary: $(printf '%s\n' "$json" |
                jq -c '{healthy,serving,peer_count:.checks.peer_count,blocking_reason:.checks.blocking_reason,warning:.checks.warning,warning_reasons:.checks.warning_reasons}' 2>/dev/null ||
                printf '%s' "$json")"
            fail "health live probe did not report healthy serving status"
        fi
    else
        printf '%s\n' "$json" |
            grep -q '"healthy"[[:space:]]*:[[:space:]]*true'
        printf '%s\n' "$json" |
            grep -q '"serving"[[:space:]]*:[[:space:]]*true'
        printf '%s\n' "$json" |
            grep -q '"has_peers"[[:space:]]*:[[:space:]]*true'
        printf '%s\n' "$json" |
            grep -q '"peer_count"[[:space:]]*:[[:space:]]*[1-9][0-9]*'
    fi
}

run_native_service_probe() {
    local agent health
    log "live service probe via $NODE_BIN agent"
    agent="$("$NODE_BIN" agent)"
    validate_agent_json "$agent"

    log "live service probe via $NODE_BIN healthcheck"
    health="$("$NODE_BIN" healthcheck)"
    validate_health_json "$health"
}

run_live_probe() {
    [ -x "$NODE_BIN" ] ||
        fail "native service binary $NODE_BIN unavailable; run make build-only or set ZCL_FAST_LIVE=0"
    run_native_service_probe
}

maybe_live_probe() {
    case "${ZCL_FAST_LIVE:-auto}" in
        0|false|no|skip)
            log "live topology probe skipped by ZCL_FAST_LIVE=${ZCL_FAST_LIVE}"
            ;;
        1|true|yes|require)
            run_live_probe
            ;;
        auto|"")
            if live_service_detected; then
                run_live_probe
            else
                log "live topology probe skipped; zclassic23 service was not detected"
            fi
            ;;
        *)
            fail "unknown ZCL_FAST_LIVE=${ZCL_FAST_LIVE}"
            ;;
    esac
}

# Dense one-line failure diagnosis for a rung. Priority:
#  (1) first compiler error   file:line:col: error:
#  (2) else, if a "Failed groups:" block is present, the first log=<path>
#      token's first failing assertion line (inline it — the harness only
#      prints the path, so the reader would otherwise have to open the file)
#  (3) else the first line matching error|FAIL
# Always prints exactly one line, prefixed FIRST-ERROR[<label>]: .
first_error_line() {
    local label="$1" output="$2" line log_path
    line="$(printf '%s\n' "$output" | grep -m1 -E ':[0-9]+:[0-9]+: error:' || true)"
    if [ -n "$line" ]; then
        log "FIRST-ERROR[$label]: $line"
        return
    fi
    line="$(printf '%s\n' "$output" |
        grep -m1 -E 'source build superseded|make(\[[0-9]+\])?: \*\*\*' || true)"
    if [ -n "$line" ]; then
        log "FIRST-ERROR[$label]: $line"
        return
    fi
    if printf '%s\n' "$output" | grep -q 'Failed groups:'; then
        log_path="$(printf '%s\n' "$output" |
            grep -m1 -oE 'log=[^[:space:]]+' | sed 's/^log=//' || true)"
        if [ -n "$log_path" ] && [ -f "$log_path" ]; then
            line="$(grep -m1 -E 'FAIL|Assertion|assert|EXPECT' "$log_path" || true)"
            if [ -n "$line" ]; then
                log "FIRST-ERROR[$label]: $line"
                return
            fi
        fi
    fi
    line="$(printf '%s\n' "$output" |
        grep -viE '(^|\.\.\.) OK$' | grep -m1 -iE 'error|FAIL' || true)"
    log "FIRST-ERROR[$label]: ${line:-<no matching error line>}"
}

# Run one ladder rung, capturing combined output. Always prints the output;
# on non-zero exit prints a dense FIRST-ERROR line then fails (short-circuits
# the ladder). set +e/-e brackets the capture so pipefail does not abort us
# before we can diagnose.
run_rung() {
    local label="$1"
    shift
    local output rc
    set +e
    output="$("$@" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$output"
    if [ "$rc" -ne 0 ]; then
        first_error_line "$label" "$output"
        fail "rung $label failed (exit $rc)"
    fi
}

# Compact rung used by verify-change. Complete stdout/stderr stays in one
# retained artifact; the terminal sees only PASS lines or one FIRST-ERROR.
run_rung_quiet() {
    local label="$1"
    shift
    local rc started elapsed output
    started="$(date +%s)"
    set +e
    ( set -e; "$@" ) >>"$VERIFY_ARTIFACT" 2>&1
    rc=$?
    set -e
    elapsed="$(( $(date +%s) - started ))"
    if [ "$rc" -ne 0 ]; then
        output="$(tail -n 240 "$VERIFY_ARTIFACT")"
        first_error_line "$label" "$output"
        log "artifact=$VERIFY_ARTIFACT"
        fail "verify-change rung $label failed (exit $rc)"
    fi
    log "PASS[$label] elapsed_s=$elapsed"
}

ensure_fresh_compdb() {
    local status
    status="$(bash tools/dev/generate-compdb.sh --status 2>/dev/null || true)"
    if printf '%s' "$status" | grep -q '"fresh":true'; then
        log "compile database fresh"
        return 0
    fi
    log "refresh compile_commands.json from real dev recipes"
    make_fast agent-index
    FROZEN_SOURCE_RECORD="$(capture_source_identity_record)" ||
        fail "source identity recapture failed after compdb refresh"
    log "source identity recaptured after compilation-database publication"
}

compdb_command_for_source() {
    local source="$1"
    jq -r --arg source "$source" \
        '[.[] | select(.file == $source)][0].command // empty' \
        compile_commands.json
}

compile_affected_gate() {
    local changed source command output fallback=0 count=0
    changed="$(mktemp "${TMPDIR:-/tmp}/zcl-verify-changed.XXXXXX")"
    changed_file_hints | sort -u | sed '/^$/d' >"$changed"
    while IFS= read -r source; do
        case "$source" in
            *.c) ;;
            *.md|docs/*|*.txt) ;;
            *) fallback=1 ;;
        esac
    done <"$changed"
    if [ "$fallback" -eq 1 ]; then
        rm -f "$changed"
        log "compile scope=full_source_inventory reason=header_or_build_graph_change"
        make_fast fast-compile
        return
    fi
    ensure_fresh_compdb
    while IFS= read -r source; do
        case "$source" in *.c) ;; *) continue ;; esac
        command="$(compdb_command_for_source "$source")"
        if [ -z "$command" ]; then
            rm -f "$changed"
            log "compile scope=full_source_inventory reason=source_missing_from_compdb file=$source"
            make_fast fast-compile
            return
        fi
        output="$(jq -r --arg source "$source" \
            '[.[] | select(.file == $source)][0].output // empty' \
            compile_commands.json)"
        [ -n "$output" ] && mkdir -p "$(dirname "$output")"
        log "compile affected source=$source recipe=compile_commands.json"
        bash -c "$command"
        count=$((count + 1))
    done <"$changed"
    rm -f "$changed"
    log "compile scope=affected_translation_units count=$count"
}

run_mapped_focused_tests() {
    local exact_groups exact_csv count=0 output rc
    [ -z "$UNMAPPED_CODE_CHANGES" ] ||
        fail "unmapped code changes require an impact rule: $UNMAPPED_CODE_CHANGES"
    if [ -z "$TEST_GROUPS" ]; then
        log "focused test scope=mapped_groups count=0"
        return
    fi
    exact_groups="$(tools/dev/test-group-list.sh --resolve-proof $TEST_GROUPS)" ||
        fail "focused proof plan contains a non-exact registered group: $TEST_GROUPS"
    count="$(printf '%s\n' "$exact_groups" | sed '/^$/d' | wc -l | tr -d ' ')"
    exact_csv="$(printf '%s\n' "$exact_groups" | sed '/^$/d' | paste -sd, -)"
    log "focused test exact_groups=$exact_csv count=$count"
    set +e
    output="$(make_fast t-fast-exact "ONLY=$exact_csv" \
        "T_FAST_EXACT_ARGS=--cache --activate-proof-contracts" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "$output"
    if [ "$rc" -ne 0 ]; then
        first_error_line focused-tests "$output"
        fail "focused proof set failed (exit $rc)"
    fi
    validate_focused_receipt "$output" "$count" ||
        fail "focused proof set did not produce complete skip-free authority"
    FROZEN_SOURCE_RECORD="$(capture_source_identity_record)" ||
        fail "source identity recapture failed after focused proof set"
    log "focused receipt schema=zcl.push_focused_receipt.v1 selected=$count ran=$FOCUSED_RECEIPT_RAN reused=$FOCUSED_RECEIPT_REUSED toolkey=$FOCUSED_RECEIPT_TOOLKEY"
    log "focused test scope=mapped_groups count=$count"
}

# Loud but NEVER fatal: compile_commands.json drifts stale silently — nothing
# on the edit path regenerates it, and IDE/index consumers then read a DB
# from the wrong source epoch. The probe is ~30 ms (mtime + content hash of
# the recorded status, no Make parse); regeneration is ~15 s, so the hot loop
# warns and names the fix instead of paying it. The DB is an index input
# only, never a build input, so staleness is advisory.
compdb_freshness_notice() {
    local status freshness
    [ -f tools/dev/generate-compdb.sh ] || return 0
    status="$(bash tools/dev/generate-compdb.sh --status 2>/dev/null)" || {
        log "compdb: freshness probe failed — run \`make agent-index\` to rebuild compile_commands.json"
        return 0
    }
    freshness="$(printf '%s' "$status" |
        sed -n 's/.*"freshness":"\([^"]*\)".*/\1/p' | head -1)"
    if [ "$freshness" != "fresh" ]; then
        log "compdb: compile_commands.json is ${freshness:-unknown} — run \`make agent-index\` (index consumers only; never a build input)"
    fi
}

main() {
    local mode="${1:-run}"
    case "$mode" in
        cache-selftest|--cache-selftest)
            cache_authority_selftest
            return
            ;;
        receipt-selftest|--receipt-selftest)
            focused_receipt_selftest
            return
            ;;
    esac

    # One exact capture per direct cycle.  A parent Make/watcher can supply its
    # already-captured record; nested Makes receive it on their command line so
    # parsing does not rescan the tree.  Artifact sessions independently verify
    # it before compilation and before publication.
    prepare_frozen_source_record

    case "$mode" in
        plan|plan-json|doctor-json)
            emit_plan_json
            return
            ;;
    esac

    select_compiler
    if [ "$mode" = failure-execution-id ]; then
        make_fast dev-failure-execution-id
        return
    fi
    log "schema=$SCHEMA"
    resolve_fast_jobs
    log "compiler=$FAST_CC cache=$CACHE_TOOL jobs=$FAST_JOBS compile=$FAST_COMPILE"
    validate_changed_files_only

    case "$mode" in
        run|"") ;;
        compile-changed|changed-compile|fast-changed-compile)
            compile_changed_gate
            log "PASS: source-wide compile gate complete"
            return
            ;;
        test-changed|t-changed|focused-tests)
            # Path mappings are useful diagnostics, but cannot prove a complete
            # delta. Always run the source-wide fast harness.
            select_test_groups
            note_unmapped_code_changes
            run_test_proof
            log "PASS: source-wide test proof (classification hints: ${TEST_GROUPS:-none})"
            return
            ;;
        ff)
            # Fail-fast ladder for the edit loop: cost-ordered, short-circuiting,
            # no live probe, no full/LTO build. Order is load-bearing — compile is
            # the cheapest rung and a broken compile poisons test + lint output, so
            # it runs first; the source-wide test proof before lint keeps runtime
            # failures at the front.
            log "ff ladder: compile -> source-wide-tests -> lint-fast (fail-fast; not release CI)"

            # rung 1: compile the complete current source inventory.
            run_rung compile compile_changed_gate

            # rung 2: run the source-wide fast harness. Mapped paths are hints.
            select_test_groups
            note_unmapped_code_changes
            run_rung source-wide-tests run_test_proof

            # rung 3: fast lint gates.
            run_rung lint-fast make_fast lint-fast

            # Non-fatal index-freshness probe (see compdb_freshness_notice).
            compdb_freshness_notice

            log "PASS: ff ladder green (compile -> source-wide-tests -> lint-fast); not release CI"
            return
            ;;
        verify-change)
            select_test_groups
            note_unmapped_code_changes
            mkdir -p "$ROOT/build/verify-change"
            local_source_id="${FROZEN_SOURCE_RECORD%% *}"
            VERIFY_ARTIFACT="$ROOT/build/verify-change/${local_source_id}.log"
            : >"$VERIFY_ARTIFACT"
            log "verify-change schema=zcl.dev_verify_change.v1"
            log "changed_files=$(changed_file_count) focused_groups=${TEST_GROUPS:-none}"
            run_rung_quiet compile compile_affected_gate
            run_rung_quiet focused-tests run_mapped_focused_tests
            run_rung_quiet lint-fast make_fast lint-fast
            log "PASS: verify-change green artifact=$VERIFY_ARTIFACT"
            return
            ;;
        pre-push)
            # Push gate: strict compile + lint-fast + mapped focused tests.
            # A missing impact rule must not expand to the 941-group suite.
            select_test_groups
            log "pre-push focused groups=${TEST_GROUPS:-none} unmapped=${UNMAPPED_CODE_CHANGES:-none}"
            run_shell_checks
            run_compile_gate
            log "lint-fast"
            make_fast lint-fast
            run_mapped_focused_tests
            maybe_live_probe
            log "PASS: pre-push focused gate complete; full-suite/fuzz/coverage via make install-quality-linger"
            return
            ;;
        rebuild-dev|dev-rebuild|fast-rebuild|hot-rebuild)
            run_dev_rebuild
            return
            ;;
        *)
            fail "unknown mode: $mode"
            ;;
    esac

    maybe_reset_fast_cache
    select_test_groups
    note_unmapped_code_changes

    if maybe_fast_cache_hit; then
        maybe_live_probe
        log "PASS: fast lane cache hit; not full release CI"
        log "Before pushing main, keep the strict gate: make lint && make build-only && relevant tests; default pre-push runs make pre-push-ci. Full-suite/fuzz/coverage run through make install-quality-linger."
        return
    fi

    verify_frozen_source_record ||
        fail "exact source record was superseded before uncached proof"

    show_cache_stats

    run_shell_checks
    # Compile before lint: a broken compile must surface the compiler error
    # first, not be buried under lint noise. Both still run on green.
    run_compile_gate
    log "lint-fast"
    make_fast lint-fast
    run_test_proof
    maybe_live_probe

    record_fast_cache_pass
    log "PASS: fast lane complete; not full release CI"
    log "Before pushing main, keep the strict gate: make lint && make build-only && relevant tests; default pre-push runs make pre-push-ci. Full-suite/fuzz/coverage run through make install-quality-linger."
}

main "$@"
