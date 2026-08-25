#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: HARD gate — packages/ format discipline (docs/spec/c23-package-format.md §2).
#
# WHY THIS EXISTS. The 76 Commons packages are the reusable C23 parts the
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
fail() { failures+=("$1"); }

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

    # R3 — files[] is exact in both directions.
    local f rel
    while IFS= read -r f; do
        rel="${f#"$d"/}"
        grep -qF "\"$rel\"" "$m" \
            || fail "$pkg: $rel exists but is not listed in manifest files[]"
    done < <(find "$d" -type f | sort)
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        [ -f "$d/$rel" ] \
            || fail "$pkg: manifest files[] lists $rel but it does not exist"
    done < <(awk '/"files": *\[/{infiles=1; next}
                  infiles && /\]/{infiles=0}
                  infiles { gsub(/[", ]/, ""); if (length) print }' "$m")

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

        # R5 — zero function-like macros (#define NAME( with no space).
        local hit
        hit="$(grep -nE '^[[:space:]]*#[[:space:]]*define[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\(' "$hdr" | head -1)"
        [ -z "$hit" ] \
            || fail "$pkg: function-like macro in public header: $hit (use enum/constexpr/_Generic)"

        # R6 — no function bodies in the public header.
        hit="$(grep -nE '\b(static|extern)[[:space:]]+inline\b|__inline' "$hdr" | head -1)"
        [ -z "$hit" ] \
            || fail "$pkg: inline function in public header: $hit (the archive owns definitions)"
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
    if ! find "$d/tests" -name '*.c' -type f 2>/dev/null | grep -q .; then
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
    for d in "${dirs[@]}"; do check_package "$d"; done
    printf '%s\n' "${#dirs[@]}"
}

selftest() {
    local tmp rc=0
    tmp="$(mktemp -d)" || { echo "FAIL: mktemp failed" >&2; exit 2; }

    # A conforming package must pass.
    local g="$tmp/good/zdemo"
    mkdir -p "$g/include/zdemo" "$g/src" "$g/tests"
    printf '/* demo */\n#ifndef ZDEMO_H\n#define ZDEMO_H\nint zdemo(void);\n#endif\n' \
        > "$g/include/zdemo/zdemo.h"
    printf 'int zdemo(void) { return 0; }\n' > "$g/src/zdemo.c"
    printf 'int main(void) { return 0; }\n' > "$g/tests/test_zdemo.c"
    printf 'x\n' > "$g/LICENSE"; printf 'x\n' > "$g/README.md"
    cat > "$g/zcode-package.json" <<'EOF'
{
  "schema": 1,
  "name": "zdemo/zdemo",
  "language": "c23",
  "license": "MIT",
  "files": [
    "LICENSE",
    "README.md",
    "include/zdemo/zdemo.h",
    "src/zdemo.c",
    "tests/test_zdemo.c",
    "zcode-package.json"
  ]
}
EOF

    # A package violating R5 (function-like macro) must be caught.
    local b="$tmp/bad/zevil"
    mkdir -p "$b/include/zevil" "$b/src" "$b/tests"
    printf '#ifndef ZEVIL_H\n#define ZEVIL_H\n#define ZEVIL_MAX(a,b) ((a)>(b)?(a):(b))\n#endif\n' \
        > "$b/include/zevil/zevil.h"
    printf 'int zevil(void) { return 0; }\n' > "$b/src/zevil.c"
    printf 'int main(void) { return 0; }\n' > "$b/tests/test_zevil.c"
    printf 'x\n' > "$b/LICENSE"; printf 'x\n' > "$b/README.md"
    cat > "$b/zcode-package.json" <<'EOF'
{
  "schema": 1,
  "name": "zevil/zevil",
  "language": "c23",
  "license": "MIT",
  "files": [
    "LICENSE",
    "README.md",
    "include/zevil/zevil.h",
    "src/zevil.c",
    "tests/test_zevil.c",
    "zcode-package.json"
  ]
}
EOF

    failures=()
    scan_packages "$tmp/good" > /dev/null
    if [ "${#failures[@]}" -ne 0 ]; then
        echo "FAIL: selftest conforming fixture rejected:" >&2
        printf '  %s\n' "${failures[@]}" >&2
        rc=2
    fi
    failures=()
    scan_packages "$tmp/bad" > /dev/null
    if [ "${#failures[@]}" -ne 1 ]; then
        echo "FAIL: selftest expected exactly 1 violation for the macro fixture," >&2
        echo "      got ${#failures[@]}:" >&2
        printf '  %s\n' "${failures[@]}" >&2
        rc=2
    fi
    failures=()
    rm -rf "$tmp"
    [ "$rc" -eq 0 ] \
        && echo "check_package_anatomy: selftest PASS — clean fixture accepted, macro fixture rejected"
    return "$rc"
}

case "${1:-}" in
    --selftest) selftest; exit $? ;;
    --help|-h)  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    .)          shift ;;
    '')         ;;
    *) echo "check_package_anatomy: unknown argument '$1'" >&2; exit 2 ;;
esac

n="$(scan_packages packages)"
gate_require_scanned "$n" 70 check_package_anatomy \
    "packages/ held almost no package directories; run from a real checkout."

if [ "${#failures[@]}" -ne 0 ]; then
    echo "" >&2
    echo "FAIL: ${#failures[@]} package-anatomy violation(s):" >&2
    printf '  %s\n' "${failures[@]}" >&2
    echo "" >&2
    echo "Rules: docs/spec/c23-package-format.md §2 (package anatomy discipline)." >&2
    exit 1
fi
echo "check_package_anatomy: clean — $n packages conform (R1-R9)"
exit 0
