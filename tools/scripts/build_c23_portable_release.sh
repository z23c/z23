#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Build the ordinary C23 node at the project's supported Linux ABI floor.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tools/scripts/source_identity_lib.sh
. "$SCRIPT_DIR/source_identity_lib.sh"

verify_source_epoch() {
    local before="$1" after="$2" baked="$3"
    zcl_is_sha256 "$before" || {
        echo "c23-portable-release: invalid initial source identity" >&2
        return 1
    }
    zcl_is_sha256 "$after" || {
        echo "c23-portable-release: invalid final source identity" >&2
        return 1
    }
    zcl_is_sha256 "$baked" || {
        echo "c23-portable-release: node omitted its baked source identity" >&2
        return 1
    }
    [ "$before" = "$after" ] || {
        echo "c23-portable-release: source epoch changed during build: before=$before after=$after" >&2
        return 1
    }
    [ "$baked" = "$after" ] || {
        echo "c23-portable-release: node baked source $baked but final source is $after" >&2
        return 1
    }
}

if [ "${1:-}" = --selftest ]; then
    # `! cmd` is EXEMPT from set -e — bash does not exit for a command "whose
    # return value is being inverted with !", and the ERR trap is exempt for
    # the same reason. Both negative controls below used to be written that
    # way, so neither could fail this selftest whatever verify_source_epoch
    # returned: a source-epoch mismatch would have printed PASS. refute()
    # exits for itself and names the assertion.
    refute() {
        if "$@"; then
            printf 'c23-portable-release: selftest FAILED — expected non-zero from: %s\n' \
                "$*" >&2
            exit 1
        fi
    }
    a="$(printf epoch-a | sha256sum | awk '{print $1}')"
    b="$(printf epoch-b | sha256sum | awk '{print $1}')"
    verify_source_epoch "$a" "$a" "$a"
    refute verify_source_epoch "$a" "$b" "$a" >/dev/null 2>&1
    refute verify_source_epoch "$a" "$a" "$b" >/dev/null 2>&1
    echo "c23-portable-release: selftest PASS"
    exit 0
fi

CC_WRAPPER="$($SCRIPT_DIR/c23_portable_sysroot.sh prepare)"
SYSROOT="$($SCRIPT_DIR/c23_portable_sysroot.sh root-path)"
PORTABLE_CC_DIR="$(dirname "$CC_WRAPPER")"

echo "c23-portable-release: rebuilding linked archives through $CC_WRAPPER" >&2
# Put the exact wrapper first but pass its stable command name to third-party
# build systems. OpenSSL records the literal CC command in libcrypto; giving it
# the absolute wrapper path would leak this checkout's /home/<user> into the
# supposedly portable final binary even though all generated code is correct.
PATH="$PORTABLE_CC_DIR:$PATH" VENDOR_CC=cc "$SCRIPT_DIR/build_vendor.sh" \
    libtor_stub.a libsqlite3.a libz.a libcrypto.a libssl.a \
    libevent.a libevent_openssl.a libevent_pthreads.a

# Vendor archives and generated headers are source-identity inputs. Capture
# only after the pinned archive rebuild has settled, then close the epoch after
# every product is linked. This prevents a late source edit from leaving an
# earlier node beside later helper products while the aggregate prints PASS.
SOURCE_BEFORE="$($REPO_ROOT/tools/dev/source-identity.sh capture)"
zcl_is_sha256 "$SOURCE_BEFORE" || {
    echo "c23-portable-release: could not capture settled source identity" >&2
    exit 1
}

# The portable baseline is the ordinary offline-friendly node. A checkout
# containing an optional host-built full-Tor archive must not silently import
# that host ABI into this artifact; the stub leaves Tor explicitly disabled.
products=(zclassic23 zcl-rpc zcl-nodectl zclassic23-package-sign zclassic23-package-verify)
# The two tiny stable-name helpers are FORCE-built by their canonical rules;
# changing this compiler also changes vendor provenance, which invalidates the
# two whole-program products without making every source prerequisite phony.
PATH="$PORTABLE_CC_DIR:$PATH" make -C "$REPO_ROOT" CC=cc VENDOR_CC=cc \
    ZCL_C23_PORTABLE_RELEASE=1 TOR_FULL= "${products[@]}"
for product in "${products[@]}"; do
    ZCL_C23_MAX_GLIBC=GLIBC_2.31 \
        "$SCRIPT_DIR/check_c23_node_binary.sh" \
        "$REPO_ROOT/build/bin/$product" >/dev/null
done

SOURCE_AFTER="$($REPO_ROOT/tools/dev/source-identity.sh capture)"
agentbuild="$("$REPO_ROOT/build/bin/zclassic23" agentbuild)"
BAKED_SOURCE="$(zcl_agentbuild_v2_top_source_id "$agentbuild")"
verify_source_epoch "$SOURCE_BEFORE" "$SOURCE_AFTER" "$BAKED_SOURCE"

# Symbol inspection is necessary but execution under the actual old loader is
# the smallest exact compatibility proof. This command is read-only and exits
# before node boot, networking, wallet, or datadir access.
"$SYSROOT/lib64/ld-linux-x86-64.so.2" \
    --library-path "$SYSROOT/lib/x86_64-linux-gnu:$SYSROOT/usr/lib/x86_64-linux-gnu" \
    "$REPO_ROOT/build/bin/zclassic23" discover search package >/dev/null
cpu_runtime_proof="compiler-baseline"
if command -v qemu-x86_64 >/dev/null 2>&1; then
    qemu-x86_64 -cpu qemu64 \
        "$SYSROOT/lib64/ld-linux-x86-64.so.2" \
        --library-path "$SYSROOT/lib/x86_64-linux-gnu:$SYSROOT/usr/lib/x86_64-linux-gnu" \
        "$REPO_ROOT/build/bin/zclassic23" discover search package >/dev/null
    cpu_runtime_proof="qemu64"
fi

max="$(objdump -T "$REPO_ROOT/build/bin/zclassic23" 2>/dev/null |
    grep -oE 'GLIBC_[0-9]+(\.[0-9]+)+' | sort -V | tail -1)"
sha="$(sha256sum "$REPO_ROOT/build/bin/zclassic23" | awk '{print $1}')"
echo "c23-portable-release: PASS products=${#products[@]} cpu=x86-64 cpu_runtime_proof=$cpu_runtime_proof glibc_floor=2.31 source_id=$SOURCE_AFTER node=build/bin/zclassic23 sha256=$sha max_abi=$max" >&2
