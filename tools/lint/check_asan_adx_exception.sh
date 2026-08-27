#!/usr/bin/env bash
# Keep the ASan frame-pointer exception closed over the two Montgomery ADX
# translation units that cannot compile while GCC reserves a frame pointer.
# The exception changes register allocation only: ASan+UBSan stay inherited
# from the common profile, every other TU keeps -fno-omit-frame-pointer, and
# both compile epochs name the exceptional sources and flag explicitly.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

MAKEFILE_PATH="${ZCL_ASAN_ADX_MAKEFILE:-Makefile}"
GATE=check_asan_adx_exception

fail() {
    echo "$GATE: FAIL — $*" >&2
    exit 1
}

# Print one continued make variable assignment as normalized whitespace.
read_make_var() {
    local name="$1"
    awk -v want="$name" '
        function trim(s) {
            sub(/^[[:space:]]+/, "", s)
            sub(/[[:space:]]+$/, "", s)
            return s
        }
        BEGIN { active = 0; value = "" }
        {
            line = $0
            if (!active) {
                prefix = "^override[[:space:]]+" want "[[:space:]]*:="
                if (line !~ prefix) next
                sub(prefix, "", line)
                active = 1
            }
            continued = (line ~ /\\[[:space:]]*$/)
            sub(/\\[[:space:]]*$/, "", line)
            line = trim(line)
            if (line != "") value = value (value == "" ? "" : " ") line
            if (!continued) {
                print value
                exit
            }
        }
    ' "$MAKEFILE_PATH"
}

require_fixed() {
    local needle="$1"
    awk -v needle="$needle" 'index($0, needle) { found = 1 } END { exit !found }' \
        "$MAKEFILE_PATH" || fail "missing required Makefile wiring: $needle"
}

check_contract() {
    [ -f "$MAKEFILE_PATH" ] || fail "cannot read $MAKEFILE_PATH"

    local sources flags common epoch_count override_count
    sources="$(read_make_var ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS)"
    flags="$(read_make_var ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)"
    common="$(read_make_var ASAN_COMMON_SAN_FLAGS)"

    [ "$sources" = "lib/sapling/src/bn254_accel.c lib/sapling/src/fr_avx512.c" ] ||
        fail "exception source allowlist changed: '$sources'"
    [ "$flags" = "-fomit-frame-pointer" ] ||
        fail "exception flags changed: '$flags'"
    [ "$common" = "-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize=alignment" ] ||
        fail "general ASan/UBSan flags changed: '$common'"

    require_fixed 'TEST_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS := $(addprefix $(TEST_ASAN_OBJ_DIR)/,$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS:.c=.o))'
    require_fixed '$(TEST_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS): TEST_ASAN_OBJECT_CFLAGS += $(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)'
    require_fixed 'DEV_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS := $(addprefix $(DEV_ASAN_OBJ_DIR)/,$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS:.c=.o))'
    require_fixed '$(DEV_ASAN_ADX_FRAME_POINTER_EXCEPTION_OBJS): DEV_ASAN_OBJECT_CFLAGS += $(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)'

    epoch_count="$(awk 'index($0, "adx-exception=$(ASAN_ADX_FRAME_POINTER_EXCEPTION_SRCS):$(ASAN_ADX_FRAME_POINTER_EXCEPTION_FLAGS)") { n++ } END { print n + 0 }' "$MAKEFILE_PATH")"
    [ "$epoch_count" -eq 2 ] ||
        fail "expected the test and dev ASan compile epochs to bind the exception; found $epoch_count binding(s)"

    override_count="$(awk '/ASAN_COMMON_SAN_FLAGS[[:space:]]*=/ { n++ } END { print n + 0 }' "$MAKEFILE_PATH")"
    [ "$override_count" -eq 0 ] ||
        fail "found $override_count recipe/caller override(s) of ASAN_COMMON_SAN_FLAGS"

    require_fixed 'TEST_ASAN_CFLAGS = $(filter-out -O3 $(ZCL_LTO_FLAG) -Werror,$(CACHED_CFLAGS)) -O1 -g -DZCL_TESTING \'
    require_fixed 'DEV_ASAN_CFLAGS = $(filter-out -O3 $(ZCL_LTO_FLAG) -Werror,$(CACHED_CFLAGS)) $(ZCL_DEV_OPT) -g3 -DZCL_DEV_BUILD \'
}

if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    cp "$MAKEFILE_PATH" "$tmp/Makefile"

    ZCL_ASAN_ADX_MAKEFILE="$tmp/Makefile" \
        "$0" >/dev/null

    sed -i '0,/lib\/sapling\/src\/bn254_accel\.c/{s//lib\/sapling\/src\/bn254_accel.c lib\/sapling\/src\/unaudited_accel.c/}' \
        "$tmp/Makefile"
    if ZCL_ASAN_ADX_MAKEFILE="$tmp/Makefile" \
            "$0" >"$tmp/out" 2>&1; then
        fail "selftest expanded the exception allowlist but the gate passed"
    fi
    if ! awk 'index($0, "exception source allowlist changed") { found = 1 } END { exit !found }' "$tmp/out"; then
        fail "selftest failed for the wrong reason"
    fi

    echo "$GATE: selftest PASS — an allowlist expansion is rejected"
    exit 0
fi

check_contract
echo "$GATE: clean — exactly two ASan ADX TUs omit frame pointers; sanitizer coverage and epoch bindings remain intact"
