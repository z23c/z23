#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Prove both release-reproduction entry points force their child builds
# offline, even when a caller attempts to export the permissive value.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/zcl-repro-network-selftest.XXXXXX")"
trap 'rm -rf "$SANDBOX"' EXIT HUP INT TERM

fail()
{
    printf 'repro_network_policy_selftest: FAIL: %s\n' "$*" >&2
    exit 1
}

mkdir -p "$SANDBOX/source"
contact_log="$SANDBOX/build-policy.log"
: > "$contact_log"

# Exported shell functions survive the child Bash entry point while the code
# under test resets PATH to its exact production value.  This proves the PATH
# pin itself instead of adding a test-only escape hatch to production code.
make()
{
    local arg build_dir=build binary=zclassic23
    if [[ " $* " == *' __zcl_repro_capture '* ]]; then
        case "${ZCL_REPRO_CAPTURE_NAME:-}" in
            CFLAGS)
                printf '%s\n' '-std=c23 -O2 -march=native -Iexpanded/include' \
                    >"$ZCL_REPRO_CAPTURE_PATH"
                ;;
            LDFLAGS)
                printf '%s\n' '-pthread -Wl,-z,now' >"$ZCL_REPRO_CAPTURE_PATH"
                ;;
            *) return 2 ;;
        esac
        return 0
    fi
    printf 'offline=%s ccache=%s locale=%s timezone=%s path=%s home=%s\n' \
        "${ZCL_VENDOR_OFFLINE:-unset}" "${ZCL_USE_CCACHE:-unset}" \
        "${LC_ALL:-unset}" "${TZ:-unset}" "${PATH:-unset}" \
        "${HOME:-unset}" \
        >>"$REPRO_POLICY_LOG"
    for arg in "$@"; do
        case "$arg" in
            BUILD_DIR=*) build_dir="${arg#BUILD_DIR=}" ;;
            zclassic23|zclassic-cli) binary="$arg" ;;
        esac
    done
    # The real node build emits build/bin/z23 with zclassic23 as its migration
    # alias. The CLI remains a regular zclassic-cli artifact.
    mkdir -p "$build_dir/bin"
    if [ "$binary" = zclassic23 ]; then
        printf 'repro-network-policy-fixture\n' >"$build_dir/bin/z23"
        ln -s z23 "$build_dir/bin/zclassic23"
    else
        printf 'repro-network-policy-fixture\n' >"$build_dir/bin/$binary"
    fi
}

git()
{
    if [[ " $* " == *' rev-parse --show-toplevel '* ]]; then
        printf '%s\n' "$REPRO_FAKE_SOURCE"
    elif [[ " $* " == *' log -1 '* ]]; then
        printf '%s\n' '1700000000'
    fi
    return 0
}

rsync()
{
    local argc=$# src dst
    local args=("$@")
    (( argc >= 2 )) || return 2
    src="${args[argc - 2]}"
    dst="${args[argc - 1]}"
    mkdir -p "$dst"
    if [[ -d "${src%/./}" ]]; then
        cp -a "${src%/./}/." "$dst/"
    fi
}

export -f make git rsync
export REPRO_POLICY_LOG="$contact_log"

# Exercise the exact policy block from the production Makefile and prove it
# overrides a permissive caller before any included-input rule could run.
policy_make="$SANDBOX/network-policy.mk"
sed -n '/^ZCL_NETWORK_DENIED_BUILD_GOALS :=/,/^endif$/p' \
    "$ROOT/Makefile" > "$policy_make"
cat >> "$policy_make" <<'EOF'
.PHONY: ci-reproducible
ci-reproducible:
	@printf '%s %s\n' "$(ZCL_VENDOR_OFFLINE)" "$(ZCL_USE_CCACHE)"
EOF
policy_value="$(/usr/bin/make -s -f "$policy_make" \
    ZCL_VENDOR_OFFLINE=0 ZCL_USE_CCACHE=1 ci-reproducible)"
[[ "$policy_value" == "1 0" ]] ||
    fail "Make parse barrier did not force offline/no-cache policy: $policy_value"
policy_line="$(grep -n '^ZCL_NETWORK_DENIED_BUILD_GOALS :=' \
    "$ROOT/Makefile" | cut -d: -f1)"
cache_select_line="$(grep -n '^ZCL_USE_CCACHE ?=' "$ROOT/Makefile" | head -1 | cut -d: -f1)"
barrier_line="$(grep -n '^VENDOR_BOOTSTRAP_MK :=' "$ROOT/Makefile" | cut -d: -f1)"
(( policy_line < cache_select_line )) ||
    fail 'Make hermetic policy is defined after compiler-cache selection'
(( policy_line < barrier_line )) ||
    fail 'Make offline policy is defined after the vendor parse barrier'

# The same-directory release profile also consults make while deriving flags.
# Preserve the real tools needed for hashing/comparison after the fake prefix.
if ! check_output="$(cd "$ROOT" && \
        ZCL_VENDOR_OFFLINE=0 PATH=/usr/bin:/bin JOBS=1 BINARY=zclassic23 \
        bash tools/scripts/check_reproducible_build.sh 2>&1)"; then
    fail 'check_reproducible_build fixture failed'
fi
[[ "$check_output" == *'-march=x86-64-v3 -Iexpanded/include'* ]] ||
    fail 'release profile did not report the compiler-expanded CFLAGS'
[[ "$check_output" != *'$('* ]] ||
    fail 'release profile retained an unresolved Make expression'

# The different-path gate snapshots a tiny synthetic source and lets the same
# fake make produce its two equal artifacts.
if ! (cd "$SANDBOX/source" && \
        REPRO_FAKE_SOURCE="$SANDBOX/source" ZCL_VENDOR_OFFLINE=0 PATH=/usr/bin:/bin \
        ZCL_REPRO_JOBS=1 bash "$ROOT/tools/scripts/repro-verify.sh") \
        >/dev/null 2>&1; then
    fail 'repro-verify fixture failed'
fi

line_count="$(wc -l < "$contact_log")"
[[ "$line_count" == "4" ]] ||
    fail "expected four observed child builds, got $line_count"
if grep -v '^offline=1 ccache=0 locale=C timezone=UTC path=/usr/bin:/bin home=/nonexistent$' \
        "$contact_log" >/dev/null; then
    fail 'a child build inherited non-hermetic execution policy'
fi

printf '%s\n' \
    'repro_network_policy_selftest: PASS builds=4 make_parse_offline=true make_parse_cache=false host_cache=false'
