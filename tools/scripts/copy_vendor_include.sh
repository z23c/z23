#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Copy gitignored headers produced by `make vendor` into another checkout.
# Keeping this operation in one helper prevents worktree-prime and the older
# worktree initializer from disagreeing about which generated headers a fresh
# lane needs before its first compile.

set -euo pipefail

copy_vendor_include()
{
    local source_root="$1"
    local destination_root="$2"

    if [ ! -d "$source_root/vendor/include" ]; then
        echo "vendor/include: source $source_root/vendor/include is missing" \
            "-- openssl/zlib gates will fail until you run make vendor there" >&2
        return 1
    fi

    mkdir -p "$destination_root/vendor/include"
    cp -a "$source_root/vendor/include/." \
        "$destination_root/vendor/include/"
}

selftest()
{
    local source destination
    SELFTEST_FIXTURE="$(mktemp -d \
        "${TMPDIR:-/tmp}/z23-vendor-include.XXXXXX")"
    trap 'rm -rf "$SELFTEST_FIXTURE"' EXIT HUP INT TERM
    source="$SELFTEST_FIXTURE/source"
    destination="$SELFTEST_FIXTURE/destination"

    mkdir -p "$source/vendor/include/openssl" \
        "$destination/vendor/include/leveldb"
    printf 'evp-v1\n' > "$source/vendor/include/openssl/evp.h"
    printf 'zlib-v1\n' > "$source/vendor/include/zlib.h"
    printf 'zconf-v1\n' > "$source/vendor/include/zconf.h"
    printf 'tracked\n' > "$destination/vendor/include/leveldb/db.h"

    copy_vendor_include "$source" "$destination"
    cmp "$source/vendor/include/openssl/evp.h" \
        "$destination/vendor/include/openssl/evp.h"
    cmp "$source/vendor/include/zlib.h" \
        "$destination/vendor/include/zlib.h"
    cmp "$source/vendor/include/zconf.h" \
        "$destination/vendor/include/zconf.h"
    [ "$(cat "$destination/vendor/include/leveldb/db.h")" = tracked ]

    printf 'evp-v2\n' > "$source/vendor/include/openssl/evp.h"
    copy_vendor_include "$source" "$destination"
    cmp "$source/vendor/include/openssl/evp.h" \
        "$destination/vendor/include/openssl/evp.h"

    echo "copy-vendor-include --selftest: PASS"
}

case "${1:-}" in
    --selftest)
        [ "$#" -eq 1 ] || {
            echo "usage: $0 --selftest | SOURCE_ROOT DESTINATION_ROOT" >&2
            exit 2
        }
        selftest
        ;;
    *)
        [ "$#" -eq 2 ] || {
            echo "usage: $0 --selftest | SOURCE_ROOT DESTINATION_ROOT" >&2
            exit 2
        }
        copy_vendor_include "$1" "$2"
        ;;
esac
