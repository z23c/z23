#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
# A service descriptor with an initializer must never reach its first byte.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd -P)"
cli="${Z23_SHADOW_PROBE_BIN:-$root/build/bin/z23-dev}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/z23-shadow-image-XXXXXXXX")"
trap 'rm -rf -- "$tmp"' EXIT HUP INT TERM

cat > "$tmp/early.c" <<'C23'
#include "hotswap/hotswap_service.h"
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

static const int table = 42;
const struct zcl_hotswap_service_candidate zcl_hotswap_service = {
    .service_id = "test.shadow.early.v1",
    .source_tu = "test.shadow.early.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(table),
    .abi_fingerprint = "test.abi",
    .schema_fingerprint = "test.schema",
    .wire_fingerprint = "test.wire",
    .kat_fingerprint = "test.kat",
    .vtable = &table,
};

__attribute__((constructor)) static void early(void)
{
    const char *path = getenv("Z23_SHADOW_EARLY_MARKER");
    if (!path) return;
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        (void)write(fd, "ran\n", 4);
        (void)close(fd);
    }
}
C23

"${CC:-cc}" -std=c23 -shared -fPIC -nostartfiles -Wl,-z,now \
    -I"$root/engine/modules/hotswap/include" \
    -o "$tmp/early.so" "$tmp/early.c"

set +e
output="$(Z23_SHADOW_EARLY_MARKER="$tmp/ran" \
    "$cli" dev hotswap probe \
    --so_path="$tmp/early.so" 2>&1)"
rc=$?
set -e
if [[ -e "$tmp/ran" ]]; then
    printf '%s\n' 'FAIL: service initializer executed before admission' >&2
    exit 1
fi
if [[ $rc -eq 0 ]] || ! grep -Eq \
    'pre-map callbacks|pre-load executable code' <<<"$output"; then
    printf '%s\n' "$output" >&2
    printf '%s\n' 'FAIL: service image was not refused at pre-map admission' >&2
    exit 1
fi
printf '%s\n' 'PASS: service initializer was refused before execution'

"${CC:-cc}" -std=c23 -shared -fPIC -nostartfiles -Wl,-z,now \
    -Wl,-Bsymbolic -DZCL_HOTSWAP_SERVICE_GEN \
    '-DZCL_HOTSWAP_SERVICE_SOURCE_TU="cognition/services/src/dev_reflex_policy_service.c"' \
    -I"$root/cognition/services/include" \
    -I"$root/engine/modules/hotswap/include" \
    -I"$root/platform/modules/json/include" \
    -o "$tmp/service.so" \
    "$root/cognition/services/src/dev_reflex_policy_service.c"
expected="$(sha256sum "$tmp/service.so")"
expected="${expected%% *}"
output="$("$cli" dev hotswap probe --so_path="$tmp/service.so" 2>&1)" || {
    printf '%s\n' "$output" >&2
    printf '%s\n' 'FAIL: valid service image did not pass frozen host probe' >&2
    exit 1
}
if ! grep -Fq "\"loaded_image_sha256\":\"$expected\"" \
    <<<"$output"; then
    printf '%s\n' "$output" >&2
    printf '%s\n' 'FAIL: reported loaded image differs from compiled service bytes' >&2
    exit 1
fi
printf '%s\n' 'PASS: frozen probe loaded the exact sealed service image'
