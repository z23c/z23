#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: HARD gate — every registry package compiles from its OWN declared
#          dependencies and nothing else.
#
# WHY THIS EXISTS. A C23 Commons package ships to a node that never met its
# author: the build worker unpacks the package plus the packages its manifest
# names, and compiles. Any include reaching outside that set makes the package
# unbuildable there, however well it builds inside this monolith, where every
# -I is on the command line and the reach is invisible.
#
# That is not hypothetical. lib/base is the dependency-free ROOT of the
# registry, and a portability change gave lib/base/src/log_level.c an
# `#include "platform/time_compat.h"`. The monolith built fine. The package
# did not, and because base is the root, every one of the ten packages failed
# with it. The only signal was test_zcode_package_registry reporting
# `verdict build-fail (test exit 0)` — a verdict with no cause attached, from
# a group that takes half a minute to reach the failure. This gate names the
# file and prints the compiler's own error in about two seconds.
#
# WHAT IT CHECKS. For each ZCODE_PACKAGE in config/zcode_package_registry.def:
# compile every source the package ships with -I<pkg>/include plus the include
# dir of each package its manifest lists under "dependencies", using the
# recipe's own quick profile from config/include/config/c23_commons_build_profile.h.
# A manifest that declares "files" is honoured exactly — an unlisted source is
# not shipped, so it is not compiled here either.
#
# This gate is about include CLOSURE. It does not link, does not run tests and
# does not judge roots; check-zcode-package-registry owns the digests and
# test_zcode_package_registry owns the real sandboxed build.
#
# Exit: 0 clean, 1 violations, 2 hollow scan set / broken selftest.
set -uo pipefail

cd "$(dirname "$0")/../.." || { echo "FAIL: cannot reach repo root" >&2; exit 2; }

# Both .def files, exactly as test_zcode_package_registry.c includes them: the
# sample application is package ten and rides the same row shape.
REGISTRY_DEFS=(config/zcode_package_registry.def config/zcode_c23_commons_app.def)
PROFILE="config/include/config/c23_commons_build_profile.h"
# Default to `cc`, NOT `gcc`. make's own built-in default for CC is `cc`, and
# make does not export makefile-set variables, so this script receives CC only
# when the environment already had it — which is to say, usually not. Falling
# back to bare `gcc` therefore graded packages with a DIFFERENT compiler than
# the one the project builds with. On a host where `cc` is gcc 14 and `gcc` is
# still gcc 13, that reported every package unbuildable for want of C23 support
# the real build has, and read as "this machine cannot build the project" when
# the machine builds it fine.
CC_BIN="${CC:-cc}"

# The recipe's own compile contract, read from the header the worker reads, so
# this gate cannot drift from the profile it claims to mirror. The trailing
# -c is already part of the macro.
#
# The concrete flags are now platform-specific (supplied by lib/platform at
# runtime), so this script mirrors that choice for the standalone compile gate.
read_quick_flags() {
    case "$(uname -s)" in
        Darwin)
            case "$(uname -m)" in
                arm64|aarch64)
                    echo "-std=c23 -O1 -march=armv8-a -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -ffile-prefix-map=SOURCE=. -c"
                    ;;
                x86_64|amd64)
                    echo "-std=c23 -O1 -march=x86-64 -fno-omit-frame-pointer -D_POSIX_C_SOURCE=200809L -D_DARWIN_C_SOURCE -ffile-prefix-map=SOURCE=. -c"
                    ;;
                *)
                    echo "FAIL: unsupported Darwin machine $(uname -m)" >&2
                    exit 2
                    ;;
            esac
            ;;
        Linux)
            awk '
                /#define ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2/ { collecting = 1; next }
                collecting {
                    line = $0
                    cont = (line ~ /\\$/)
                    gsub(/\\$/, "", line)
                    while (match(line, /"[^"]*"/)) {
                        s = substr(line, RSTART + 1, RLENGTH - 2)
                        printf "%s", s
                        line = substr(line, RSTART + RLENGTH)
                    }
                    if (!cont) { print ""; exit }
                }
            ' "$PROFILE"
            ;;
        *)
            echo "FAIL: unsupported host $(uname -s) for standalone package gate" >&2
            exit 2
            ;;
    esac
}

# name<TAB>dir for every package in the registry, so a package added later is
# covered without editing this gate.
read_registry() {
    awk '
        /^ZCODE_PACKAGE\(/ {
            if (match($0, /"[^"]*"[^"]*"[^"]*"/)) {
                s = substr($0, RSTART, RLENGTH)
                n = split(s, parts, "\"")
                print parts[2] "\t" parts[4]
            }
        }
    ' "${REGISTRY_DEFS[@]}"
}

# The include dir of every package named under "dependencies" in a manifest.
dep_includes() {
    local manifest="$1" dep dir
    while read -r dep; do
        [[ -n "$dep" ]] || continue
        dir="${PKG_DIR[$dep]:-}"
        if [[ -z "$dir" ]]; then
            echo "MISSINGDEP:$dep"
            continue
        fi
        echo "-I$dir/include"
    done < <(awk '
        /"dependencies"/ { in_deps = 1 }
        in_deps && /\]/   { in_deps = 0 }
        in_deps && /"name"[[:space:]]*:/ {
            if (match($0, /"zclassic23\/[^"]*"/)) {
                s = substr($0, RSTART + 1, RLENGTH - 2)
                print s
            }
        }
    ' "$manifest")
}

# Sources a package actually ships: everything under src/ (and tests/, which
# the recipe compiles too), narrowed to files[] when the manifest declares one.
pkg_sources() {
    local dir="$1" manifest="$1/zcode-package.json" f rel
    local -i subset=0
    if grep -q '"files"' "$manifest"; then subset=1; fi
    for f in "$dir"/src/*.c "$dir"/tests/*.c; do
        [[ -e "$f" ]] || continue
        if (( subset )); then
            rel="${f#"$dir"/}"
            grep -q "\"$rel\"" "$manifest" || continue
        fi
        echo "$f"
    done
}

QUICK_FLAGS="$(read_quick_flags)"
if [[ -z "$QUICK_FLAGS" ]]; then
    echo "FAIL: cannot read ZCL_C23_COMMONS_BUILD_FLAGS_QUICK_V2 from $PROFILE" >&2
    exit 2
fi
# -ffile-prefix-map=SOURCE=. names a path only the worker's sandbox has.
QUICK_FLAGS="${QUICK_FLAGS//-ffile-prefix-map=SOURCE=./}"

declare -A PKG_DIR=()
pkg_names=()
while IFS=$'\t' read -r name dir; do
    [[ -n "$name" && -n "$dir" ]] || continue
    PKG_DIR["$name"]="$dir"
    pkg_names+=("$name")
done < <(read_registry)

if (( ${#pkg_names[@]} == 0 )); then
    echo "FAIL: no packages parsed from ${REGISTRY_DEFS[*]} — hollow scan" >&2
    exit 2
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

violations=0
compiled=0

compile_package() {
    local name="$1" dir="$2"
    local manifest="$dir/zcode-package.json"
    if [[ ! -f "$manifest" ]]; then
        echo "  $name: no manifest at $manifest"
        return 1
    fi
    local incs=(-I"$dir/include")
    local line missing=0
    while read -r line; do
        [[ -n "$line" ]] || continue
        if [[ "$line" == MISSINGDEP:* ]]; then
            echo "  $name: declares dependency ${line#MISSINGDEP:}, which is not in ${REGISTRY_DEFS[*]}"
            missing=1
            continue
        fi
        incs+=("$line")
    done < <(dep_includes "$manifest")
    (( missing )) && return 1

    local rc=0 src
    while read -r src; do
        [[ -n "$src" ]] || continue
        compiled=$((compiled + 1))
        # shellcheck disable=SC2086 -- QUICK_FLAGS is a flag string by design.
        if ! $CC_BIN $QUICK_FLAGS "${incs[@]}" "$src" \
                -o "$work/obj.o" 2>"$work/err.txt"; then
            echo "  $name: $src does not compile from its declared dependencies"
            awk '/error:/ { print "      " $0; n++ } n >= 3 { exit }' "$work/err.txt"
            rc=1
        fi
    done < <(pkg_sources "$dir")
    return $rc
}

for name in "${pkg_names[@]}"; do
    compile_package "$name" "${PKG_DIR[$name]}" || violations=$((violations + 1))
done

if (( compiled == 0 )); then
    echo "FAIL: parsed ${#pkg_names[@]} package(s) but compiled nothing — hollow scan" >&2
    exit 2
fi

if (( violations > 0 )); then
    echo "[check_zcode_package_standalone] $violations package(s) cannot build from their declared dependencies"
    echo "[check_zcode_package_standalone] a package ships to a node that has only the packages its manifest names; move the shared code down or declare the edge"
    exit 1
fi

echo "[check_zcode_package_standalone] ${#pkg_names[@]} package(s), $compiled source(s): all build from their declared dependencies"
exit 0
