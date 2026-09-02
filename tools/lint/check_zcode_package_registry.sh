#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# Purpose: verify package roots and exact-once monolith source ownership.
set -euo pipefail

checker="build/bin/zcode-package-registry-check"
# The registry .def files are pulled into this checker at COMPILE time by an
# X-macro (tools/zcode_package_registry_check.c), so the binary carries a
# snapshot of them. Grading with whatever binary happens to sit in build/bin
# therefore says nothing about the .def on disk: a registry file overwritten
# with all-zero roots still passed here. Build it first, so the verdict is
# about the tree being gated. tools/scripts/zcode_registry_rederive.sh has
# always done this; only the lint side was missing it. Do not swap this for
# an mtime comparison -- the binary also embeds engine/composition/zcode_c23_commons_app.def
# and contexts/commons/modules/vcs/src/package_*.c, so only make knows the real prerequisite set.
if ! make -s --no-print-directory "$checker" >/dev/null 2>&1; then
    echo "check-zcode-package-registry: FAIL — could not build $checker" >&2
    exit 1
fi
if [[ ! -x "$checker" ]]; then
    echo "check-zcode-package-registry: FAIL — missing $checker" >&2
    exit 1
fi
"$checker"

mapfile -t package_dirs < <(
    sed -n 's/^ZCODE_PACKAGE("[^"]*", "\([^"]*\)".*/\1/p' \
        engine/composition/zcode_package_registry.def \
        engine/composition/zcode_c23_commons_app.def | LC_ALL=C sort -u
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
        sed -nE '/^(core|engine|contexts|cognition|platform)\/.*\/src\/.*\.c$/p'
)
platform_alternative_groups=(
    "platform/modules/platform/src/os_sandbox_linux.c platform/modules/platform/src/os_sandbox_stub.c"
    "contexts/commons/modules/vcs/src/vcs_devloop.c contexts/commons/modules/vcs/src/vcs_devloop_windows.c"
)
# The devloop pair used to live here, because the Windows implementation was
# compiled on EVERY host: only the POSIX one was host-optional, so "expected 1
# on Linux, 0 on MSYS" described the build exactly. That was the defect, not
# the description — a Windows devloop has no business being compiled into a
# Linux binary, and once the Makefile stopped doing it the pair became a
# straightforward platform alternative like the sandbox pair above.
#
# The package and terminal-worker sandbox extensions are genuinely Linux-only
# in addition to the linux-or-stub base sandbox alternative.  They therefore
# belong in the host-optional set: exactly once in the Linux monolith and
# absent from native Windows/macOS builds, whose implementations either use
# Seatbelt in the stub translation unit or refuse before sandbox entry.
host_optional_sources=(
    platform/modules/platform/src/os_sandbox_package_linux.c
    platform/modules/platform/src/os_sandbox_terminal_worker.c
)

if (( ${#package_sources[@]} == 0 || ${#monolith_sources[@]} == 0 )); then
    echo "check-zcode-package-registry: FAIL — empty package or monolith source projection" >&2
    exit 1
fi

for source in "${package_sources[@]}"; do
    for group in "${platform_alternative_groups[@]}"; do
        for alternative in $group; do
            [[ "$source" == "$alternative" ]] && continue 3
        done
    done
    for optional in "${host_optional_sources[@]}"; do
        [[ "$source" == "$optional" ]] && continue 2
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

host_name="$(uname -s 2>/dev/null || true)"
for optional in "${host_optional_sources[@]}"; do
    count=0
    for compiled in "${monolith_sources[@]}"; do
        [[ "$compiled" == "$optional" ]] && ((count += 1))
    done
    expected=0
    case "$host_name" in
        Linux*) expected=1 ;;
    esac
    if (( count != expected )); then
        echo "check-zcode-package-registry: FAIL — host-optional $optional appears $count times in LIB_SRCS (expected $expected on $host_name)" >&2
        exit 1
    fi
    echo "zcode package registry: host-optional source count is exact: $optional=$count"
done

for group in "${platform_alternative_groups[@]}"; do
    platform_count=0
    chosen=""
    for alternative in $group; do
        for compiled in "${monolith_sources[@]}"; do
            if [[ "$compiled" == "$alternative" ]]; then
                ((platform_count += 1))
                chosen="$alternative"
            fi
        done
    done
    if (( platform_count != 1 )); then
        echo "check-zcode-package-registry: FAIL — platform alternative group appears $platform_count times in LIB_SRCS ($group)" >&2
        exit 1
    fi
    echo "zcode package registry: exactly one host alternative selected: $chosen"
done

codec_consumers=(
    contexts/commons/modules/vcs/src/package_release.c
    contexts/commons/modules/vcs/src/package_recipe.c
    contexts/commons/modules/vcs/src/package_deps.c
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
