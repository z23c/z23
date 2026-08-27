#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Purpose: verify package roots and exact-once monolith source ownership.
set -euo pipefail

checker="build/bin/zcode-package-registry-check"
if [[ ! -x "$checker" ]]; then
    echo "check-zcode-package-registry: FAIL — missing $checker" >&2
    exit 1
fi

"$checker"

mapfile -t package_dirs < <(
    sed -n 's/^ZCODE_PACKAGE("[^"]*", "\([^"]*\)".*/\1/p' \
        config/zcode_package_registry.def \
        config/zcode_c23_commons_app.def | LC_ALL=C sort -u
)
package_patterns=()
for package_dir in "${package_dirs[@]}"; do
    package_patterns+=("$package_dir/src/*.c")
done
mapfile -t package_sources < <(
    git ls-files -- "${package_patterns[@]}" | LC_ALL=C sort -u
)
mapfile -t monolith_sources < <(
    make -s --no-print-directory print-zcode-monolith-lib-sources |
        sed -n '/^lib\/.*\/src\/.*\.c$/p'
)
platform_alternatives=(
    lib/platform/src/os_sandbox_linux.c
    lib/platform/src/os_sandbox_stub.c
)

if (( ${#package_sources[@]} == 0 || ${#monolith_sources[@]} == 0 )); then
    echo "check-zcode-package-registry: FAIL — empty package or monolith source projection" >&2
    exit 1
fi

for source in "${package_sources[@]}"; do
    for alternative in "${platform_alternatives[@]}"; do
        [[ "$source" == "$alternative" ]] && continue 2
    done
    count=0
    for compiled in "${monolith_sources[@]}"; do
        [[ "$compiled" == "$source" ]] && ((count += 1))
    done
    if (( count != 1 )); then
        echo "check-zcode-package-registry: FAIL — $source appears $count times in LIB_SRCS" >&2
        exit 1
    fi
done

platform_count=0
for alternative in "${platform_alternatives[@]}"; do
    for compiled in "${monolith_sources[@]}"; do
        [[ "$compiled" == "$alternative" ]] && ((platform_count += 1))
    done
done
if (( platform_count != 1 )); then
    echo "check-zcode-package-registry: FAIL — platform sandbox alternatives appear $platform_count times in LIB_SRCS" >&2
    exit 1
fi

codec_consumers=(
    lib/vcs/src/package_release.c
    lib/vcs/src/package_recipe.c
    lib/vcs/src/package_deps.c
)
for source in "${codec_consumers[@]}"; do
    if ! git grep -q '#include "codec/cursor.h"' -- "$source"; then
        echo "check-zcode-package-registry: FAIL — $source does not use the bounded codec cursor" >&2
        exit 1
    fi
done
if git grep -n -E 'vcs_(wr|rd)_u(16|32|64)le|#include "vcs_priv.h"' -- \
        "${codec_consumers[@]}"; then
    echo "check-zcode-package-registry: FAIL — package release/recipe/lock restored a private codec" >&2
    exit 1
fi

echo "zcode package registry: ${#package_sources[@]} authoritative package sources occur exactly once in monolith LIB_SRCS"
echo "zcode package registry: exactly one host sandbox implementation is selected"
echo "zcode package registry: release, recipe and lock wires use codec/cursor.h exclusively"
