#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: HARD gate — packages/ format discipline (docs/spec/c23-package-format.md §2).
#
# WHY THIS EXISTS. The Commons packages are the reusable C23 parts the
# whole product is built from, and their anatomy IS the format: one package
# is one component, the public header is its exact interface, and anything
# the format forbids (function-like macros, hidden extra sources, undeclared
# files, executable build logic) makes a package unreadable, unrebuildable,
# or unverifiable by a node that never met its author. Today every package
# conforms; this gate keeps it that way mechanically instead of by memory.
#
# RULES (per packages/<pkg>/, rooted at the spec):
#   R1  zcode-package.json, LICENSE, README.md, include/, src/, tests/ exist.
#   R2  manifest: schema 1, language c23, name "<pkg>/<pkg>", license on the
#       frozen v1 SPDX allowlist (mirrors vcs_package_release_license_allowed).
#   R3  the manifest's files[] array is exact: every file under the package
#       directory is listed, and every listed file exists.
#   R4  exactly one public header, at include/<pkg>/<pkg>.h, guarded by
#       #ifndef/<PKG>_H … #define … #endif.
#   R5  zero function-like macros in the public header (#define NAME( ).
#       Constants are enum/constexpr, polymorphism is _Generic/typeof.
#   R6  no function bodies in the public header (no static/extern inline):
#       the installed artifact is the static archive.
#   R7  src/<pkg>.c is the primary translation unit; any extra src/*.c or
#       src/*.h is internal, must be listed in files[], and must not be a
#       second public surface. A component wanting two public TUs is two
#       packages joined by a dependency edge.
#   R8  tests/ holds at least one .c.
#   R9  no executable build logic: no Makefile, configure, CMakeLists.txt,
#       or *.sh anywhere under a package. The recipe is declarative.
#
# Exit: 0 clean, 1 violations, 2 hollow scan set / broken selftest.
set -uo pipefail

cd "$(dirname "$0")/../.." || { echo "FAIL: cannot reach repo root" >&2; exit 2; }
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

ALLOWED_LICENSES=" 0BSD MIT Apache-2.0 BSD-2-Clause BSD-3-Clause ISC Zlib "

failures=()
packages_scanned=0
fail() { failures+=("$1"); }

# Emit only the canonical rows inside the single files[] array.  This is
# intentionally stricter than substring search: a path mentioned in a note,
# dependency, or other field is not a declaration that the package ships it.
manifest_files_list() {
    local manifest="$1"
    awk '
        BEGIN { seen = 0; inside = 0; closed = 0; bad = 0; count = 0 }
        /^[[:space:]]*"files"[[:space:]]*:[[:space:]]*\[/ {
            if (seen) bad = 1
            seen = 1
            inside = 1
            next
        }
        inside && /^[[:space:]]*\][[:space:]]*,?[[:space:]]*$/ {
            inside = 0
            closed = 1
            next
        }
        inside {
            if ($0 !~ /^[[:space:]]*"[^"]+"[[:space:]]*,?[[:space:]]*$/) {
                bad = 1
                next
            }
            line = $0
            comma = (line ~ /,[[:space:]]*$/)
            sub(/^[[:space:]]*"/, "", line)
            sub(/"[[:space:]]*,?[[:space:]]*$/, "", line)
            count++
            values[count] = line
            commas[count] = comma
            next
        }
        END {
            if (!seen || inside || !closed || bad || count == 0) exit 2
            for (i = 1; i < count; i++) {
                if (!commas[i]) exit 2
            }
            if (commas[count]) exit 2
            for (i = 1; i <= count; i++) print values[i]
        }
    ' "$manifest"
}

check_package() {
    local d="$1" pkg m hdr guard
    pkg="$(basename "$d")"

    # R1 — required entries.
    local req
    for req in zcode-package.json LICENSE README.md; do
        [ -f "$d/$req" ] || fail "$pkg: missing $req"
    done
    for req in include src tests; do
        [ -d "$d/$req" ] || fail "$pkg: missing $req/ directory"
    done
    m="$d/zcode-package.json"
    [ -f "$m" ] || return

    # R2 — manifest shape (flat-field extraction; the byte-exact parse is
    # lib/vcs/src/package_prepare.c's job, this gate checks the contract).
    grep -q '"schema": 1' "$m" || fail "$pkg: manifest schema is not 1"
    grep -q "\"name\": \"$pkg/$pkg\"" "$m" \
        || fail "$pkg: manifest name is not \"$pkg/$pkg\""
    grep -q '"language": "c23"' "$m" \
        || fail "$pkg: manifest language is not \"c23\""
    local lic
    lic="$(sed -n 's/.*"license": "\([^"]*\)".*/\1/p' "$m" | head -1)"
    case "$ALLOWED_LICENSES" in
        *" $lic "*) ;;
        *) fail "$pkg: license '$lic' is not on the frozen v1 SPDX allowlist" ;;
    esac

    # R3 — files[] is exact in both directions.  Parse that array once; text
    # elsewhere in the manifest cannot satisfy membership.
    local f rel manifest_files_text
    local -A declared_files=()
    if ! manifest_files_text="$(manifest_files_list "$m")"; then
        fail "$pkg: manifest files[] is missing, duplicated, or malformed"
    else
        while IFS= read -r rel; do
            [ -n "$rel" ] || continue
            if [ -n "${declared_files[$rel]+present}" ]; then
                fail "$pkg: manifest files[] lists $rel more than once"
            else
                declared_files["$rel"]=1
            fi
        done <<< "$manifest_files_text"
        while IFS= read -r f; do
            rel="${f#"$d"/}"
            [ -n "${declared_files[$rel]+present}" ] \
                || fail "$pkg: $rel exists but is not listed in manifest files[]"
        done < <(find "$d" -type f | sort)
        for rel in "${!declared_files[@]}"; do
            [ -f "$d/$rel" ] \
                || fail "$pkg: manifest files[] lists $rel but it does not exist"
        done
    fi

    # R4 — exactly one public header, namespaced, with the <PKG>_H guard.
    local -a hdrs=()
    while IFS= read -r f; do hdrs+=("$f"); done \
        < <(find "$d/include" -name '*.h' -type f 2>/dev/null | sort)
    if [ "${#hdrs[@]}" -ne 1 ]; then
        fail "$pkg: expected exactly 1 public header, found ${#hdrs[@]}"
    elif [ "${hdrs[0]}" != "$d/include/$pkg/$pkg.h" ]; then
        fail "$pkg: public header is ${hdrs[0]#"$d"/}, want include/$pkg/$pkg.h"
    else
        hdr="${hdrs[0]}"
        guard="$(printf '%s' "$pkg" | tr 'a-z' 'A-Z')_H"
        grep -qE "^#ifndef ${guard}\$" "$hdr" \
            || fail "$pkg: public header missing #ifndef $guard"
        grep -qE "^#define ${guard}\$" "$hdr" \
            || fail "$pkg: public header missing #define $guard"
        grep -qE '^#endif' "$hdr" \
            || fail "$pkg: public header missing #endif guard close"

        # R5/R6 inspect code, not prose.  Use the shared line-preserving C
        # scanner so comments and literals cannot create false facts, while
        # split tokens such as `static /* reason */ inline` remain visible.
        local hit grep_status stripped_header
        if [ ! -f tools/lint/strip_c_comments.awk ]; then
            echo "check_package_anatomy: FATAL — missing shared C comment scanner" >&2
            exit 2
        fi
        if ! stripped_header="$(awk -v strings=1 -f tools/lint/strip_c_comments.awk "$hdr")"; then
            echo "check_package_anatomy: FATAL — cannot strip comments from $hdr" >&2
            exit 2
        fi

        # R5 — zero function-like macros (#define NAME( with no space).
        if hit="$(printf '%s\n' "$stripped_header" | grep -nE -m 1 '^[[:space:]]*#[[:space:]]*define[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\(')"; then
            fail "$pkg: function-like macro in public header: $hit (use enum/constexpr/_Generic)"
        else
            grep_status=$?
            if [ "$grep_status" -ne 1 ]; then
                echo "check_package_anatomy: FATAL — cannot scan $hdr for function-like macros" >&2
                exit 2
            fi
        fi

        # R6 — no function bodies in the public header.
        if hit="$(printf '%s\n' "$stripped_header" | grep -nE -m 1 '(^|[^[:alnum:]_])(__inline|inline)([^[:alnum:]_]|$)')"; then
            fail "$pkg: inline function in public header: $hit (the archive owns definitions)"
        else
            grep_status=$?
            if [ "$grep_status" -ne 1 ]; then
                echo "check_package_anatomy: FATAL — cannot scan $hdr for inline definitions" >&2
                exit 2
            fi
        fi
    fi

    # R7 — primary TU is src/<pkg>.c; extras are internal and declared.
    [ -f "$d/src/$pkg.c" ] || fail "$pkg: missing primary translation unit src/$pkg.c"
    while IFS= read -r f; do
        rel="${f#"$d"/}"
        case "$rel" in
            "src/$pkg.c") continue ;;
        esac
        case "$rel" in
            src/*.h) ;;  # internal header: allowed when declared (R3 did)
            src/*.c) ;;  # internal helper TU: allowed when declared (R3 did)
            *) fail "$pkg: unexpected file under src/: $rel" ;;
        esac
    done < <(find "$d/src" -type f | sort)

    # R8 — tests exist.
    if [ -z "$(find "$d/tests" -name '*.c' -type f 2>/dev/null)" ]; then
        fail "$pkg: tests/ holds no .c file"
    fi

    # R9 — no executable build logic.
    local b
    b="$(find "$d" -type f \( -iname 'Makefile*' -o -iname 'configure*' \
         -o -iname 'CMakeLists*' -o -name '*.sh' \) | head -1)"
    [ -z "$b" ] || fail "$pkg: executable build logic $b — the recipe is declarative"
}

scan_packages() {
    local root="$1" d
    local -a dirs=()
    while IFS= read -r d; do dirs+=("$d"); done \
        < <(find "$root" -mindepth 1 -maxdepth 1 -type d | sort)
    packages_scanned="${#dirs[@]}"
    for d in "${dirs[@]}"; do check_package "$d"; done
}

# These three package tests were added with the anatomy repair.  Running them
# from this registered lint entrypoint makes their manifest test rows real
# proof rather than decorative source files.  The app/window TUs are excluded:
# these KATs exercise the deterministic reusable painter component only.
run_required_package_kats() {
    local work rc=0 pkg bin status runner=build/bin/z23_bounded_run
    local kat_timeout_ms=10000
    local -a cc_argv=()
    read -r -a cc_argv <<< "${CC:-cc}"
    if [ "${#cc_argv[@]}" -eq 0 ]; then
        echo "check_package_anatomy: FATAL — CC resolved to an empty command" >&2
        return 2
    fi
    if ! command -v "${cc_argv[0]}" >/dev/null 2>&1; then
        echo "check_package_anatomy: FATAL — compiler '${cc_argv[0]}' is unavailable" >&2
        return 2
    fi
    if ! "${cc_argv[@]}" --version >/dev/null 2>&1; then
        echo "check_package_anatomy: FATAL — compiler '${cc_argv[*]}' cannot execute" >&2
        return 2
    fi
    if [ ! -x "$runner" ]; then
        echo "check_package_anatomy: FATAL — bounded KAT runner $runner is unavailable" >&2
        return 2
    fi
    if ! "$runner" --selftest; then
        echo "check_package_anatomy: FATAL — bounded KAT runner selftest failed" >&2
        return 2
    fi
    work="$(mktemp -d)" || {
        echo "check_package_anatomy: FATAL — cannot create KAT work directory" >&2
        return 2
    }
    for pkg in ball zdemo zhello; do
        bin="$work/test_$pkg"
        if ! "${cc_argv[@]}" -std=c23 -O2 -Wall -Wextra -Werror -pedantic \
                -I"packages/$pkg/include" "packages/$pkg/src/$pkg.c" \
                "packages/$pkg/tests/test_$pkg.c" -o "$bin"; then
            echo "check_package_anatomy: $pkg declared KAT does not compile" >&2
            rc=1
            continue
        fi
        "$runner" "$kat_timeout_ms" "$bin"
        status=$?
        case "$status" in
            0) ;;
            124)
                echo "check_package_anatomy: $pkg declared KAT exceeded ${kat_timeout_ms}ms" >&2
                rc=1
                ;;
            125|126|127)
                echo "check_package_anatomy: FATAL — bounded runner could not supervise $pkg KAT" >&2
                rm -rf "$work"
                return 2
                ;;
            *)
                echo "check_package_anatomy: $pkg declared KAT failed (exit $status)" >&2
                rc=1
                ;;
        esac
    done
    rm -rf "$work"
    return "$rc"
}

write_selftest_package() {
    local root="$1" pkg="$2" invalid="$3" d guard extra_header=""
    d="$root/$pkg"
    guard="$(printf '%s' "$pkg" | tr 'a-z' 'A-Z')_H"
    case "$invalid" in
        macro) extra_header="#define ${guard}_MAX(a,b) ((a)>(b)?(a):(b))" ;;
        inline) extra_header="static/**/inline int ${pkg}_inline(void) { return 0; }" ;;
        clean|manifest_substring|duplicate_file|missing_comma|trailing_comma) ;;
        *) echo "FAIL: unknown package-anatomy selftest mode $invalid" >&2; return 2 ;;
    esac
    mkdir -p "$d/include/$pkg" "$d/src" "$d/tests"
    printf '#ifndef %s\n#define %s\n/* inline and #define COMMENT_FN(x) are prose, not code. */\n#define COMMENT_SPLIT/**/(x) (x)\n%s\nint %s(void);\n#endif\n' \
        "$guard" "$guard" "$extra_header" "$pkg" > "$d/include/$pkg/$pkg.h"
    printf 'int %s(void) { return 0; }\n' "$pkg" > "$d/src/$pkg.c"
    printf 'int main(void) { return 0; }\n' > "$d/tests/test_$pkg.c"
    printf 'x\n' > "$d/LICENSE"
    printf 'x\n' > "$d/README.md"
    printf '{\n  "schema": 1,\n  "name": "%s/%s",\n' "$pkg" "$pkg" \
        > "$d/zcode-package.json"
    printf '  "language": "c23",\n  "license": "MIT",\n' \
        >> "$d/zcode-package.json"
    if [ "$invalid" = manifest_substring ]; then
        printf '  "note": "README.md",\n' >> "$d/zcode-package.json"
    fi
    if [ "$invalid" = missing_comma ]; then
        printf '  "files": [\n    "LICENSE"\n' >> "$d/zcode-package.json"
    else
        printf '  "files": [\n    "LICENSE",\n' >> "$d/zcode-package.json"
    fi
    if [ "$invalid" = duplicate_file ]; then
        printf '    "LICENSE",\n' >> "$d/zcode-package.json"
    fi
    if [ "$invalid" != manifest_substring ]; then
        printf '    "README.md",\n' >> "$d/zcode-package.json"
    fi
    printf '    "include/%s/%s.h",\n' "$pkg" "$pkg" \
        >> "$d/zcode-package.json"
    printf '    "src/%s.c",\n    "tests/test_%s.c",\n' "$pkg" "$pkg" \
        >> "$d/zcode-package.json"
    if [ "$invalid" = trailing_comma ]; then
        printf '    "zcode-package.json",\n  ]\n}\n' >> "$d/zcode-package.json"
    else
        printf '    "zcode-package.json"\n  ]\n}\n' >> "$d/zcode-package.json"
    fi
}

selftest() {
    local tmp rc=0 script_path out status i pkg
    tmp="$(mktemp -d)" || { echo "FAIL: mktemp failed" >&2; exit 2; }
    script_path="$(pwd -P)/tools/lint/check_package_anatomy.sh"

    # Exercise the same 70-package floor and production entrypoint as the gate.
    for ((i = 0; i < 70; i++)); do
        pkg="$(printf 'zfixture%02d' "$i")"
        write_selftest_package "$tmp/good" "$pkg" clean
        case "$i" in
            0) write_selftest_package "$tmp/bad" "$pkg" macro ;;
            1) write_selftest_package "$tmp/bad" "$pkg" inline ;;
            2) write_selftest_package "$tmp/bad" "$pkg" manifest_substring ;;
            3) write_selftest_package "$tmp/bad" "$pkg" duplicate_file ;;
            4) write_selftest_package "$tmp/bad" "$pkg" missing_comma ;;
            5) write_selftest_package "$tmp/bad" "$pkg" trailing_comma ;;
            *) write_selftest_package "$tmp/bad" "$pkg" clean ;;
        esac
        if [ "$i" -lt 69 ]; then
            write_selftest_package "$tmp/hollow" "$pkg" clean
        fi
    done

    if ! out="$("$script_path" --root "$tmp/good" 2>&1)"; then
        echo "FAIL: selftest production entrypoint rejected conforming fixture:" >&2
        printf '  %s\n' "$out" >&2
        rc=2
    fi
    if out="$("$script_path" --root "$tmp/bad" 2>&1)"; then
        echo "FAIL: selftest production entrypoint accepted invalid macro fixture:" >&2
        printf '  %s\n' "$out" >&2
        rc=2
    else
        status=$?
        case "$out" in
            *"6 package-anatomy violation(s)"*"function-like macro"*"inline function"*"exists but is not listed"*"more than once"*"files[] is missing, duplicated, or malformed"*) ;;
            *) status=2 ;;
        esac
        if [ "$status" -ne 1 ]; then
            echo "FAIL: selftest invalid fixture refusal was not the production gate verdict:" >&2
            printf '  exit=%s output=%s\n' "$status" "$out" >&2
            rc=2
        fi
    fi
    if out="$("$script_path" --root "$tmp/hollow" 2>&1)"; then
        echo "FAIL: selftest production entrypoint accepted below-floor fixture:" >&2
        printf '  %s\n' "$out" >&2
        rc=2
    else
        status=$?
        case "$out" in
            *"FATAL"*"scan set is '69' (< floor 70)"*) ;;
            *) status=2 ;;
        esac
        if [ "$status" -ne 2 ]; then
            echo "FAIL: selftest below-floor fixture was not a hollow-scan refusal:" >&2
            printf '  exit=%s output=%s\n' "$status" "$out" >&2
            rc=2
        fi
    fi
    rm -rf "$tmp"
    [ "$rc" -eq 0 ] \
        && echo "check_package_anatomy: selftest PASS — production entrypoint accepts commented clean code, rejects macro/inline/exact JSON files[], and refuses hollow scans"
    return "$rc"
}

root=packages
case "${1:-}" in
    --selftest) selftest; exit $? ;;
    --root)
        [ "$#" -eq 2 ] || {
            echo "check_package_anatomy: --root requires exactly one directory" >&2
            exit 2
        }
        root="$2"
        ;;
    --help|-h)  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    .)          shift ;;
    '')         ;;
    *) echo "check_package_anatomy: unknown argument '$1'" >&2; exit 2 ;;
esac

scan_packages "$root"
n="$packages_scanned"
gate_require_scanned "$n" 70 check_package_anatomy \
    "$root held almost no package directories; run from a real checkout."

if [ "${#failures[@]}" -ne 0 ]; then
    echo "" >&2
    echo "FAIL: ${#failures[@]} package-anatomy violation(s):" >&2
    printf '  %s\n' "${failures[@]}" >&2
    echo "" >&2
    echo "Rules: docs/spec/c23-package-format.md §2 (package anatomy discipline)." >&2
    exit 1
fi
if [ "$root" = packages ]; then
    run_required_package_kats || exit $?
fi
echo "check_package_anatomy: clean — $n packages conform (R1-R9)"
exit 0
