#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# HARD gate: ZVCS and producer-source authority may not inherit Git/SHA-1.
# ZVCS and content.v2 use SHA3-256; the dev supersession identity uses a
# SHA-256 digest of current source bytes. Git object ids may remain external
# GitHub trace/publish metadata, never an input to these authority digests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ROOT="${ZCL_VCS_SHA1_ROOT:-$DEFAULT_ROOT}"

fatal()
{
    printf 'check_vcs_no_sha1: FATAL — %s\n' "$*" >&2
    exit 2
}

grep_checked()
{
    local pattern="$1" path="$2" output rc
    if output="$(grep -rnEi --include='*.c' --include='*.h' --include='*.sh' \
            --include='Makefile' -- "$pattern" "$path" 2>&1)"; then
        rc=0
    else
        rc=$?
    fi
    if [ "$rc" -ge 2 ]; then
        printf '%s\n' "$output" >&2
        fatal "grep failed with rc=$rc scanning $path"
    fi
    [ "$rc" -eq 0 ] && printf '%s\n' "$output"
    return 0
}

source_git_commands_allowed()
{
    local source_identity="$1" calls line code bad=0
    calls="$(sed 's/[[:space:]]*#.*$//' "$source_identity" |
        grep -nE '(^|[^[:alnum:]_.-])git[[:space:]]' || true)"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        code="${line#*:}"
        # Git is only a path/index enumerator here. Object/revision-producing
        # commands are never authority inputs. Keep this an allowlist so a new
        # spelling fails closed instead of evading a blacklist.
        case "$code" in
            *'git rev-parse --show-toplevel'*|\
            *'git rev-parse --git-path index'*|\
            *'git -C "$prefix" rev-parse --show-toplevel'*|\
            *'git -C "$prefix" rev-parse --git-path index'*|\
            *'git -C "$repo" config --null --list'*|\
            *'git -C "$repo" rev-parse --git-path info/exclude'*|\
            *'git -C "$repo" config --path --null --get core.excludesFile'*|\
            *'git ls-files -v -z'*|\
            *'git ls-files --others --exclude-standard -z --'*|\
            *'git ls-files --others --ignored --exclude-standard --directory -z --'*|\
            *'git diff --name-only --no-renames -z HEAD --'*|\
            *'git -C "$prefix" ls-files -v -z'*|\
            *'git -C "$prefix" ls-files --others --exclude-standard -z --'*|\
            *'git -C "$prefix" diff --name-only --no-renames -z HEAD --'*|\
            *'git -C "$prefix" ls-files --stage -z --'*|\
            *'git ls-files --stage -z --'*) ;;
            *) printf 'FAIL: non-allowlisted Git command in source identity: %s\n' \
                       "$line"; bad=1 ;;
        esac
        # One allowed invocation cannot be used as camouflage for a second.
        case "${code#*git }" in
            *'git '*)
                printf 'FAIL: multiple Git invocations on source-identity line: %s\n' \
                       "$line"
                bad=1
                ;;
        esac
    done <<< "$calls"
    [ "$bad" -eq 0 ]
}

identity_publications_verified()
{
    local makefile="$1" publish_tool="$2" session_tool="$3"
    # Dynamically inspect every Make rule that mentions baked source identity
    # and publishes an output. Each such rule must verify the exact record (or
    # delegate to the epoch verifier/publisher) in that same rule. This catches
    # newly-added link aliases instead of blessing one textual verify-record.
    if ! awk '
        function flush() {
            if (identity && publish &&
                (!verified || (!delegated && verify_line >= publish_line))) {
                print "FAIL: identity-bearing publication lacks in-rule verification: " header
                bad = 1
            }
            identity = publish = verified = delegated = 0
            verify_line = publish_line = 0
        }
        /^[^[:space:]#][^:]*:/ {
            if ($0 !~ /^[^:]*:[[:space:]]*=/) {
                flush()
                header = $0
            }
        }
        /BUILD_SOURCE_ID|ZCL_BUILD_SOURCE_ID|BUILD_IDENTITY_STAMP/ {
            identity = 1
        }
        /source-identity\.sh[[:space:]]+verify-record|BUILD_EPOCH_SESSION_TOOL\)[[:space:]]+verify|BUILD_EPOCH_PUBLISH_TOOL\)/ {
            verified = 1
            verify_line = NR
            if ($0 ~ /BUILD_EPOCH_PUBLISH_TOOL\)/)
                delegated = 1
        }
        /publish_exact|BUILD_EPOCH_PUBLISH_TOOL\)|(^|[[:space:]])@?(mv|cp|install|ln)[[:space:]].*\$+@|-o[[:space:]]+[^[:space:]]*\$+@/ {
            publish = 1
            publish_line = NR
        }
        END { flush(); exit bad }
    ' "$makefile"; then
        return 1
    fi

    # The delegated alias publisher must itself revalidate immediately before
    # its atomic rename, and that verifier must re-check current source bytes.
    local verify_line publish_line source_verify_line
    verify_line="$(grep -nF '"$SESSION_TOOL" verify' "$publish_tool" |
        tail -1 | cut -d: -f1)"
    publish_line="$(grep -nF 'mv -f -- "$TMP" "$ALIAS"' "$publish_tool" |
        tail -1 | cut -d: -f1)"
    source_verify_line="$(grep -nF '"$VERIFY_TOOL" verify-record' \
        "$session_tool" | tail -1 | cut -d: -f1)"
    [[ "$verify_line" =~ ^[0-9]+$ ]] &&
        [[ "$publish_line" =~ ^[0-9]+$ ]] &&
        [ "$verify_line" -lt "$publish_line" ] &&
        [[ "$source_verify_line" =~ ^[0-9]+$ ]] || {
            printf '%s\n' 'FAIL: delegated build-alias publication is not source-reverified before rename'
            return 1
        }
}

mutation_receipt_confined()
{
    local makefile="$1" refs line code seen=0 bad=0
    refs="$(grep -nE 'ZCL_BUILD_SOURCE_MUTATION|DEV_SOURCE_RECEIPT_CPPFLAGS' \
        "$makefile" || true)"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        code="${line#*:}"
        case "$code" in
            'DEV_SOURCE_RECEIPT_CPPFLAGS = -DZCL_BUILD_SOURCE_MUTATION=\"$(BUILD_MUTATION)\"')
                seen=$((seen + 1))
                ;;
            *'$(eval $(call BUILD_NODE_TOOL,test_zcl,'*'$(DEV_SOURCE_RECEIPT_CPPFLAGS))'*|\
            *'$(eval $(call BUILD_NODE_TOOL,test_parallel_wpo,'*'$(DEV_SOURCE_RECEIPT_CPPFLAGS))'*|\
            '$(TEST_FAST_OBJ_DIR)/lib/util/src/clientversion.o: TEST_FAST_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)'|\
            '$(TEST_REL_OBJ_DIR)/lib/util/src/clientversion.o: TEST_REL_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)'|\
            '$(TEST_ASAN_OBJ_DIR)/lib/util/src/clientversion.o: TEST_ASAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)'|\
            '$(DEV_ASAN_OBJ_DIR)/lib/util/src/clientversion.o: DEV_ASAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)'|\
            '$(TEST_TSAN_OBJ_DIR)/lib/util/src/clientversion.o: TEST_TSAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)'|\
            '$(DEV_TSAN_OBJ_DIR)/lib/util/src/clientversion.o: DEV_TSAN_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)'|\
            '$(COV_BUILD_DIR)/lib/util/src/clientversion.o: COV_OBJECT_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)'|\
            '$(DEV_OBJ_DIR)/lib/util/src/clientversion.o: DEV_COMPILE_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)')
                ;;
            *)
                printf 'FAIL: host-local mutation receipt escaped dev/test identity TU: %s\n' "$line"
                bad=1
                ;;
        esac
    done <<< "$refs"
    [ "$seen" -eq 1 ] || {
        printf '%s\n' 'FAIL: dev/test mutation receipt definition missing or duplicated'
        bad=1
    }
    [ "$bad" -eq 0 ]
}

scan_tree()
{
    local root="$1" hits record_line source_line clean_line mutation_line path
    local vcs="$root/lib/vcs"
    local source_identity="$root/tools/dev/source-identity.sh"
    local receipt="$root/config/src/consensus_state_producer_receipt.c"
    local makefile="$root/Makefile"
    local publish_tool="$root/tools/dev/publish-build-alias.sh"
    local session_tool="$root/tools/dev/build-epoch-session.sh"
    [ -d "$vcs" ] || fatal "missing authority surface: $vcs"
    [ -f "$source_identity" ] || fatal "missing authority surface: $source_identity"
    [ -f "$receipt" ] || fatal "missing authority surface: $receipt"
    [ -f "$makefile" ] || fatal "missing authority surface: $makefile"
    [ -f "$publish_tool" ] || fatal "missing authority surface: $publish_tool"
    [ -f "$session_tool" ] || fatal "missing authority surface: $session_tool"

    # Internal VCS/package code may not even name or call a SHA-1 primitive.
    # Consensus OP_SHA1 and RFC6455 live outside lib/vcs and are intentionally
    # not part of this source-authority gate.
    # Match the token anywhere in an identifier: prefixed APIs such as
    # EVP_sha1(), mbedtls_sha1_init(), and git_sha1_entry() are still SHA-1.
    hits="$(grep_checked 'sha[-_]?1' "$vcs")" || return $?
    if [ -n "$hits" ]; then
        printf '%s\n' "$hits"
        printf '%s\n' 'FAIL: lib/vcs must use SHA3-256/SHA-256, never SHA-1'
        return 1
    fi

    # The supersession CAS may use a small allowlist of Git path/index
    # enumeration commands, but never revision/object-producing commands.
    source_git_commands_allowed "$source_identity" || return 1
    hits="$(grep_checked 'sha1(sum)?|sha-1|zcl\.dev_source_identity\.v1' "$source_identity")" || return $?
    [ -z "$hits" ] || {
        printf '%s\n' "$hits"
        printf '%s\n' 'FAIL: source identity names legacy SHA-1/v1 authority'
        return 1
    }

    # Scan every consensus/source authority implementation, not only the
    # receipt writer. Display-only controller fields live outside this list.
    local authority_paths=(
        "$vcs"
        "$root/config/src/consensus_state_bundle_validate.c"
        "$root/config/src/consensus_state_producer_receipt.c"
        "$root/config/src/consensus_state_producer_status.c"
        "$root/config/src/consensus_state_snapshot_candidate.c"
        "$root/config/src/consensus_state_snapshot_candidate_validate.c"
        "$root/config/src/consensus_state_snapshot_export.c"
        "$root/config/src/consensus_state_snapshot_export_proof.c"
        "$root/config/src/consensus_state_snapshot_export_write.c"
        "$root/config/src/consensus_state_snapshot_install.c"
        "$root/config/src/consensus_state_snapshot_install_activate.c"
        "$root/app/services/src/consensus_state_publication_cas.c"
        "$publish_tool"
        "$session_tool"
        "$root/tools/dev/build-epoch-key.sh"
        "$root/tools/dev/compile-epoch-object.sh"
    )
    for path in "${authority_paths[@]}"; do
        [ -e "$path" ] || fatal "missing authority surface: $path"
        hits="$(grep_checked '([[:alnum:]_]*sha1[[:alnum:]_]*[[:space:]]*\(|sha1sum|SHA1[[:space:]]*\()' "$path")" || return $?
        if [ -n "$hits" ]; then
            printf '%s\n' "$hits"
            printf 'FAIL: SHA-1 primitive in authority surface: %s\n' "$path"
            return 1
        fi
    done

    local authority_c=(
        "$root/config/src/consensus_state_bundle_validate.c"
        "$root/config/src/consensus_state_producer_receipt.c"
        "$root/config/src/consensus_state_producer_status.c"
        "$root/config/src/consensus_state_snapshot_candidate.c"
        "$root/config/src/consensus_state_snapshot_candidate_validate.c"
        "$root/config/src/consensus_state_snapshot_export.c"
        "$root/config/src/consensus_state_snapshot_export_proof.c"
        "$root/config/src/consensus_state_snapshot_export_write.c"
        "$root/config/src/consensus_state_snapshot_install.c"
        "$root/config/src/consensus_state_snapshot_install_activate.c"
        "$root/app/services/src/consensus_state_publication_cas.c"
    )
    for path in "${authority_c[@]}"; do
        hits="$(grep_checked 'zcl_build_commit(_full)?[[:space:]]*\(' "$path")" || return $?
        if [ -n "$hits" ]; then
            printf '%s\n' "$hits"
            printf 'FAIL: display-only Git commit entered authority surface: %s\n' "$path"
            return 1
        fi
    done

    # New receipt sessions must use the baked SHA-256 source identity. The v1
    # codec may still dual-read a protected producer artifact, but the writer
    # may not call the Git-commit getter.
    hits="$(grep_checked 'zcl_build_commit_full[[:space:]]*\(' "$receipt")" || return $?
    if [ -n "$hits" ]; then
        printf '%s\n' "$hits"
        printf '%s\n' 'FAIL: producer receipt writer still derives authority from Git SHA-1'
        return 1
    fi
    if ! grep -q 'zcl_build_source_id_sha256[[:space:]]*(' "$receipt"; then
        printf '%s\n' 'FAIL: producer receipt writer has no SHA-256 source identity input'
        return 1
    fi

    record_line="$(grep -E '^BUILD_SOURCE_RECORD[[:space:]]*:=' "$makefile" || true)"
    source_line="$(grep -E '^BUILD_SOURCE_ID[[:space:]]*:=' "$makefile" || true)"
    clean_line="$(grep -E '^BUILD_CLEAN[[:space:]]*:=' "$makefile" || true)"
    mutation_line="$(grep -E '^BUILD_MUTATION[[:space:]]*:=' "$makefile" || true)"
    if [ -z "$record_line" ] ||
       [[ "$record_line" != *"tools/dev/source-identity.sh capture-record"* ]] ||
       [[ "$record_line" == *"git "* ]] ||
       [[ "$source_line" != *'$(word 1,$(BUILD_SOURCE_RECORD))'* ]] ||
       [[ "$clean_line" != *'$(word 2,$(BUILD_SOURCE_RECORD))'* ]] ||
       [[ "$mutation_line" != *'$(word 3,$(BUILD_SOURCE_RECORD))'* ]]; then
        printf 'FAIL: build identity/clean/mutation state is not one source-identity.v2 record: %s | %s | %s | %s\n' \
            "${record_line:-missing}" "${source_line:-missing}" \
            "${clean_line:-missing}" "${mutation_line:-missing}"
        return 1
    fi
    identity_publications_verified "$makefile" "$publish_tool" \
        "$session_tool" || return 1
    mutation_receipt_confined "$makefile" || return 1
    if ! grep -q 'tools/dev/source-identity-selftest.sh' "$makefile"; then
        printf '%s\n' 'FAIL: source identity regression suite is not wired into lint'
        return 1
    fi
    if grep -q -- '-DZCL_BUILD_COMMIT\(_FULL\)\?=' "$makefile"; then
        printf '%s\n' 'FAIL: Git commit text is baked into exact executable/receipt authority'
        return 1
    fi

    return 0
}

self_test()
{
    local sandbox="$DEFAULT_ROOT/test-tmp/_vcs_sha1_policy_fixture"
    rm -rf "$sandbox"
    mkdir -p "$sandbox/lib/vcs/src" "$sandbox/tools/dev" \
        "$sandbox/config/src" "$sandbox/app/services/src"
    printf '%s\n' 'void sha3_only(void);' > "$sandbox/lib/vcs/src/object.c"
    printf '%s\n' '#!/bin/sh' 'git ls-files --stage -z --' 'sha256sum' \
        > "$sandbox/tools/dev/source-identity.sh"
    printf '%s\n' 'const char *zcl_build_source_id_sha256(void);' \
        'void receipt(void) { (void)zcl_build_source_id_sha256(); }' \
        > "$sandbox/config/src/consensus_state_producer_receipt.c"
    local authority_fixture
    for authority_fixture in \
        consensus_state_bundle_validate.c \
        consensus_state_producer_status.c \
        consensus_state_snapshot_candidate.c \
        consensus_state_snapshot_candidate_validate.c \
        consensus_state_snapshot_export.c \
        consensus_state_snapshot_export_proof.c \
        consensus_state_snapshot_export_write.c \
        consensus_state_snapshot_install.c \
        consensus_state_snapshot_install_activate.c; do
        printf '%s\n' 'void authority_sha256_only(void);' \
            > "$sandbox/config/src/$authority_fixture"
    done
    printf '%s\n' 'void publication_sha256_only(void);' \
        > "$sandbox/app/services/src/consensus_state_publication_cas.c"
    printf '%s\n' '#!/bin/sh' '"$SESSION_TOOL" verify' \
        'mv -f -- "$TMP" "$ALIAS"' \
        > "$sandbox/tools/dev/publish-build-alias.sh"
    printf '%s\n' '#!/bin/sh' '"$VERIFY_TOOL" verify-record' \
        > "$sandbox/tools/dev/build-epoch-session.sh"
    printf '%s\n' '#!/bin/sh' 'sha256sum' \
        > "$sandbox/tools/dev/build-epoch-key.sh"
    printf '%s\n' '#!/bin/sh' 'sha256sum' \
        > "$sandbox/tools/dev/compile-epoch-object.sh"
    printf '%s\n' \
        'BUILD_SOURCE_RECORD := $(shell tools/dev/source-identity.sh capture-record)' \
        'BUILD_SOURCE_ID := $(word 1,$(BUILD_SOURCE_RECORD))' \
        'BUILD_CLEAN := $(word 2,$(BUILD_SOURCE_RECORD))' \
        'BUILD_MUTATION := $(word 3,$(BUILD_SOURCE_RECORD))' \
        'DEV_SOURCE_RECEIPT_CPPFLAGS = -DZCL_BUILD_SOURCE_MUTATION=\"$(BUILD_MUTATION)\"' \
        '$(DEV_OBJ_DIR)/lib/util/src/clientversion.o: DEV_COMPILE_CFLAGS += $(BUILD_IDENTITY_CPPFLAGS) $(DEV_SOURCE_RECEIPT_CPPFLAGS)' \
        'artifact: $(BUILD_IDENTITY_STAMP)' \
        '	@set -eu; \
	tmp="$@.tmp"; \
	cc -DZCL_BUILD_SOURCE_ID -o "$$tmp" source.c; \
	tools/dev/source-identity.sh verify-record "$(BUILD_SOURCE_ID)" "$(BUILD_CLEAN)" "$(BUILD_MUTATION)"; \
	mv -f -- "$$tmp" "$@"' \
        'lint: ; @tools/dev/source-identity-selftest.sh' \
        > "$sandbox/Makefile"

    scan_tree "$sandbox" >/dev/null || fatal 'known-good fixture failed'
    printf '%s\n' 'BUILD_IDENTITY_CPPFLAGS += $(DEV_SOURCE_RECEIPT_CPPFLAGS)' \
        >> "$sandbox/Makefile"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'host-local mutation receipt escaped into release identity flags'
    fi
    # Rewrite, not GNU `sed -i`: BSD sed would take '$d' as an in-place
    # backup suffix and the Makefile path as the script, mutating nothing.
    sed '$d' "$sandbox/Makefile" > "$sandbox/Makefile.nolid" \
        && mv "$sandbox/Makefile.nolid" "$sandbox/Makefile"
    mkdir -p "$sandbox/fail-bin"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 2' \
        > "$sandbox/fail-bin/grep"
    chmod +x "$sandbox/fail-bin/grep"
    if PATH="$sandbox/fail-bin:$PATH" scan_tree "$sandbox" \
            >/dev/null 2>&1; then
        fatal 'grep/discovery failure false-greened the hard gate'
    fi
    printf '%s\n' 'void bad(void) { sha1_init(0); }' \
        >> "$sandbox/lib/vcs/src/object.c"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'lib/vcs SHA-1 fixture passed'
    fi
    printf '%s\n' \
        'void prefixed(void) { EVP_sha1(); mbedtls_sha1_init();' \
        ' git_sha1_entry(); }' > "$sandbox/lib/vcs/src/object.c"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'prefixed lib/vcs SHA-1 API fixtures passed'
    fi
    printf '%s\n' 'void sha3_only(void);' > "$sandbox/lib/vcs/src/object.c"
    printf '%s\n' 'git rev-parse HEAD' >> "$sandbox/tools/dev/source-identity.sh"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'Git HEAD source-identity fixture passed'
    fi
    printf '%s\n' '#!/bin/sh' 'git ls-files --stage -z --' 'sha256sum' \
        > "$sandbox/tools/dev/source-identity.sh"
    printf '%s\n' 'git -C . rev-parse HEAD' \
        >> "$sandbox/tools/dev/source-identity.sh"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'Git -C HEAD source-identity fixture passed'
    fi
    printf '%s\n' '#!/bin/sh' 'git ls-files --stage -z --' 'sha256sum' \
        > "$sandbox/tools/dev/source-identity.sh"
    printf '%s\n' 'git rev-parse main' >> "$sandbox/tools/dev/source-identity.sh"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'alternate Git revision source-identity fixture passed'
    fi
    printf '%s\n' '#!/bin/sh' 'git ls-files --stage -z --' 'sha256sum' \
        > "$sandbox/tools/dev/source-identity.sh"
    printf '%s\n' 'git log -1 --format=%H' >> "$sandbox/tools/dev/source-identity.sh"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'Git log object-id source-identity fixture passed'
    fi
    printf '%s\n' '#!/bin/sh' 'git ls-files --stage -z --' 'sha256sum' \
        > "$sandbox/tools/dev/source-identity.sh"
    printf '%s\n' 'git ls-tree HEAD' >> "$sandbox/tools/dev/source-identity.sh"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'Git ls-tree object-id source-identity fixture passed'
    fi
    printf '%s\n' '#!/bin/sh' 'git ls-files --stage -z --' 'sha256sum' \
        > "$sandbox/tools/dev/source-identity.sh"
    printf '%s\n' 'const char *zcl_build_source_id_sha256(void);' \
        'const char *zcl_build_commit_full(void);' \
        'void receipt(void) { (void)zcl_build_source_id_sha256();' \
        ' (void)zcl_build_commit_full(); }' \
        > "$sandbox/config/src/consensus_state_producer_receipt.c"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'Git commit receipt-authority fixture passed'
    fi
    printf '%s\n' 'const char *zcl_build_source_id_sha256(void);' \
        'void receipt(void) { (void)zcl_build_source_id_sha256(); }' \
        > "$sandbox/config/src/consensus_state_producer_receipt.c"
    printf '%s\n' 'CFLAGS += -DZCL_BUILD_COMMIT_FULL="deadbeef"' \
        >> "$sandbox/Makefile"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'baked Git commit executable-authority fixture passed'
    fi
    # Same rewrite rule as above: no GNU `sed -i` on a BSD host.
    sed '/CFLAGS += -DZCL_BUILD_COMMIT/d' "$sandbox/Makefile" \
        > "$sandbox/Makefile.nocommit" && mv "$sandbox/Makefile.nocommit" "$sandbox/Makefile"
    printf '%s\n' \
        'unverified: $(BUILD_IDENTITY_STAMP)' \
        '	@cp source.c "$@"' >> "$sandbox/Makefile"
    if scan_tree "$sandbox" >/dev/null 2>&1; then
        fatal 'unverified identity-bearing publication fixture passed'
    fi
    rm -rf "$sandbox"
}

case "${1:-}" in
    --self-test) self_test; printf '%s\n' 'check_vcs_no_sha1: self-test PASS'; exit 0 ;;
    --scan|'') ;;
    *) fatal "unknown argument: $1" ;;
esac

cd "$ROOT" || fatal "cannot enter $ROOT"
self_test
if ! scan_tree "$ROOT"; then
    exit 1
fi
printf '%s\n' 'check_vcs_no_sha1: clean — ZVCS/producer-source authority is SHA-1-free'
