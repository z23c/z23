#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: HARD gate — every C23 Commons package's manifest states the union
#          of capability classes its SHIPPED files can reach, exactly: not a
#          superset, not a subset.
#
# WHY THIS EXISTS. A C23 Commons package ships to a node that never met its
# author (the sentence tools/lint/check_zcode_package_standalone.sh opens
# with, for the same reason). That node can already verify what a package
# DEPENDS ON — the manifest names each dependency by content root, and
# check-zcode-package-registry re-derives every one of those roots from
# bytes. It had no way at all to know what the package can DO. "It only needs
# zclassic23/base" and "it cannot open a socket" are different sentences, and
# only the first one was written down.
#
# config/capability_classes.def already answers the second question for a
# single translation unit, and it answers it decidably: a class names a kind
# of REACH the linker can see, never a kind of intent. What was missing was
# the rollup — the same fact stated about a package, in the package's own
# manifest, where a stranger reads it. This gate is what makes that stated
# fact true.
#
# THE VALUE IS IN THE EMPTY ARRAY. "capabilities": [] means this package
# reaches NOTHING: no socket, no spawn, no dlopen, no file, no key, no
# entropy, no clock, no privilege change. Two of the nine registry packages
# (zclassic23/sha3 and zclassic23/codec) are inert in exactly that sense, and
# a stranger can confirm it in seconds. That is why an ABSENT "capabilities"
# field is a VIOLATION here and never "assume empty": the whole worth of the
# empty array is that somebody derived it and a gate keeps it true, and a
# reader who cannot tell "reaches nothing" from "nobody wrote it down" has
# been handed the second while believing the first.
#
# WHAT IT CHECKS, per ZCODE_PACKAGE row in config/zcode_package_registry.def
# and config/zcode_c23_commons_app.def:
#
#   1. PRESENCE.   The manifest has a "capabilities" key. Absent FAILS.
#   2. VOCABULARY. Every entry names a class declared in
#                  config/capability_classes.def. CAP_NONE is not a class and
#                  has no row there; it is spelled [].
#   3. CANONICAL.  The array is strictly ascending and duplicate-free, so the
#                  declaration has ONE encoding. A manifest is content-
#                  addressed — its bytes are hashed into the package root —
#                  so two spellings of one set would be two roots for one
#                  package.
#   4. SYMMETRY.   The declared set EQUALS the union of the classes
#                  config/module_capabilities.def grants to this package's
#                  SHIPPED sources. Both directions fail:
#                    - a class a shipped file reaches but the manifest omits
#                      (the core property: the manifest must not understate
#                      what the code can do), and
#                    - a class the manifest names that no shipped file
#                      reaches (the same discipline check-capability-closure
#                      applies per file: a declaration must not rot upward as
#                      the code that justified it shrinks — an overstated
#                      NETWORK is a package a node refuses for no reason, and
#                      worse, it is a claim nobody re-derived).
#   5. HOLLOWNESS. Zero packages parsed, zero capability classes read, zero
#                  module rows read, or ANY package with zero shipped sources
#                  prints UNPROVEN and exits 2 — never 0. Same discipline as
#                  check_zcode_package_standalone.sh, which exits 2 on a
#                  hollow scan set rather than reporting ten clean packages
#                  it never opened.
#
# WHICH FILES A PACKAGE SHIPS is not re-derived here: it comes from
# zcode_pkg_sources() in tools/lint/zcode_pkg_sources.sh, the same function
# check-zcode-package-standalone compiles. If the two gates disagreed about
# the shipped set, one of them would be grading a set the receiving node will
# never see.
#
# WHAT THIS DOES NOT PROVE, stated here so nobody has to discover it later.
# The derivation is exactly as strong as config/module_capabilities.def, and
# that table is a snapshot of what an OBJECT TREE showed:
# check-capability-closure proves a file with no row reaches nothing only for
# files it found a compiled object for. Every shipped src/*.c in the registry
# does have one today. The shipped tests/*.c and lib/commons_demo/app/main.c
# do NOT — they are compiled by the package recipe and the test harness, not
# into build/dev-obj. Their empty contribution here is therefore UNOBSERVED
# rather than measured, in the precise sense check_capability_closure.sh's
# own symmetry check uses that word. Closing that is a change to which
# objects the epoch holds, not a change to this gate.
#
# Exit: 0 clean, 1 violations, 2 hollow scan / broken selftest.
#
# Usage:
#   tools/lint/check_package_capabilities.sh             # the gate
#   tools/lint/check_package_capabilities.sh --selftest  # prove it fires
set -uo pipefail
# The canonical-order check below compares class names with the shell's own
# `<` operator and the reports sort with `sort`; both must use ONE collation or
# a name pair could be "ascending" to one and not the other.
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tools/lint/zcode_pkg_sources.sh
source "$SCRIPT_DIR/zcode_pkg_sources.sh"

# The registry is spread over more than one .def — the library packages and
# the sample application, which rides the same row shape. Same registry pair
# check_zcode_package_standalone.sh reads.
REGISTRY_DEF_NAMES=(config/zcode_package_registry.def config/zcode_c23_commons_app.def)
CLASSES_DEF_NAME=config/capability_classes.def
MODULES_DEF_NAMES=(config/module_capabilities.def
                   config/module_capabilities_linux.def
                   config/module_capabilities_windows.def)

# ── config/capability_classes.def ───────────────────────────────────────────
# ZCL_CAPABILITY_CLASS(NETWORK, ...) -> CAP_NETWORK, one per line.
pkgcap_classes() {
    awk '
        match($0, /ZCL_CAPABILITY_CLASS\([[:space:]]*[A-Z][A-Z0-9_]*/) {
            s = substr($0, RSTART, RLENGTH)
            sub(/^ZCL_CAPABILITY_CLASS\([[:space:]]*/, "", s)
            print "CAP_" s
        }
    ' "$1"
}

# ── config/module_capabilities.def ──────────────────────────────────────────
# "<source path>\t<CAP_A|CAP_B>" per row. Tolerant of a row wrapped across
# lines by a long `why` string, the same way
# check_capability_closure.sh's reader is: the path and the class union are
# always on the opening line, but the parse must not be thrown by what
# follows.
pkgcap_module_tsv() {
    awk '
        /ZCL_MODULE_CAPABILITY\(/ {
            if (match($0, /"([^"\\]|\\.)*"[[:space:]]*,[[:space:]]*CAP_[A-Z_|]*/)) {
                s = substr($0, RSTART, RLENGTH)
                if (match(s, /"([^"\\]|\\.)*"/))
                    path = substr(s, RSTART + 1, RLENGTH - 2)
                else
                    path = ""
                cls = s
                sub(/^[^,]*,[[:space:]]*/, "", cls)
                if (path != "" && cls != "") print path "\t" cls
            }
        }
    ' "$@"
}

# ── config/*.def registry rows ──────────────────────────────────────────────
# "<package name>\t<package dir>" per ZCODE_PACKAGE row. Same extractor
# check_zcode_package_standalone.sh uses, so a package added later is covered
# by both gates without editing either.
pkgcap_registry_tsv() {
    awk '
        /^ZCODE_PACKAGE\(/ {
            if (match($0, /"[^"]*"[^"]*"[^"]*"/)) {
                s = substr($0, RSTART, RLENGTH)
                n = split(s, parts, "\"")
                print parts[2] "\t" parts[4]
            }
        }
    ' "$@"
}

# ── the check ───────────────────────────────────────────────────────────────
# Runs entirely against $1, so --selftest can aim it at a fixture root.
# Returns 0 clean, 1 violations, 2 hollow / unreadable input.
check_root() {
    local root="${1%/}"
    local violations=0

    local classes_file="$root/$CLASSES_DEF_NAME"
    local -a modules_files=()
    local module_name
    for module_name in "${MODULES_DEF_NAMES[@]}"; do
        [ -f "$root/$module_name" ] && modules_files+=("$root/$module_name")
    done

    # ── vocabulary ──────────────────────────────────────────────────────────
    if [ ! -f "$classes_file" ]; then
        echo "check_package_capabilities: UNPROVEN — cannot read $classes_file"
        echo "  That file is the closed list of class names a manifest may use."
        echo "  Without it every declared name would have to be believed."
        return 2
    fi
    local -A KNOWN_CLASS=()
    local cls n_class=0
    while IFS= read -r cls; do
        [ -n "$cls" ] || continue
        KNOWN_CLASS["$cls"]=1
        n_class=$((n_class + 1))
    done < <(pkgcap_classes "$classes_file")
    if [ "$n_class" -lt 1 ]; then
        echo "check_package_capabilities: UNPROVEN — parsed 0 classes from"
        echo "  $classes_file. Either it is empty or this script's reader no"
        echo "  longer matches its ZCL_CAPABILITY_CLASS(...) shape. Refusing to"
        echo "  grade declarations against a vocabulary that saw nothing."
        return 2
    fi

    # ── per-file declarations ───────────────────────────────────────────────
    if [ "${#modules_files[@]}" -eq 0 ]; then
        echo "check_package_capabilities: UNPROVEN — cannot read ${MODULES_DEF_NAMES[0]}"
        echo "  That file is what every package capability set is DERIVED from."
        echo "  Its absence is a broken precondition, not zero violations."
        return 2
    fi
    local -A MOD_RAW=()
    local path raw old tok n_mod=0
    while IFS=$'\t' read -r path raw; do
        [ -n "$path" ] || continue
        old="${MOD_RAW[$path]:-}"
        IFS='|' read -ra toks <<< "$raw"
        for tok in "${toks[@]}"; do
            [ -n "$tok" ] && [ "$tok" != "CAP_NONE" ] || continue
            case "|$old|" in
                *"|$tok|"*) ;;
                *) [ -n "$old" ] && old="$old|$tok" || old="$tok" ;;
            esac
        done
        MOD_RAW["$path"]="$old"
        n_mod=$((n_mod + 1))
    done < <(pkgcap_module_tsv "${modules_files[@]}")
    if [ "$n_mod" -lt 1 ]; then
        echo "check_package_capabilities: UNPROVEN — parsed 0 rows from"
        echo "  ${modules_files[*]}. Every package would derive the empty set and"
        echo "  every genuinely inert package would 'pass' off a scan that saw"
        echo "  nothing. That is not a proof of inertness."
        return 2
    fi

    # ── the registry ────────────────────────────────────────────────────────
    local -a defs=() name dir
    local d
    for d in "${REGISTRY_DEF_NAMES[@]}"; do
        [ -f "$root/$d" ] && defs+=("$root/$d")
    done
    local -a pkg_names=() pkg_dirs=()
    if [ "${#defs[@]}" -gt 0 ]; then
        while IFS=$'\t' read -r name dir; do
            [ -n "$name" ] && [ -n "$dir" ] || continue
            pkg_names+=("$name")
            pkg_dirs+=("$dir")
        done < <(pkgcap_registry_tsv "${defs[@]}")
    fi
    if [ "${#pkg_names[@]}" -eq 0 ]; then
        echo "check_package_capabilities: UNPROVEN — no ZCODE_PACKAGE rows parsed"
        echo "  from ${REGISTRY_DEF_NAMES[*]} under $root. Zero packages graded is"
        echo "  a scan that did not happen, never a clean tree."
        return 2
    fi

    # ── grade each package ──────────────────────────────────────────────────
    local i manifest src rel tok
    local n_src_total=0
    for i in "${!pkg_names[@]}"; do
        name="${pkg_names[$i]}"
        dir="${pkg_dirs[$i]}"
        manifest="$root/$dir/zcode-package.json"

        if [ ! -f "$manifest" ]; then
            echo "check_package_capabilities: VIOLATION — $name has no manifest at"
            echo "  $dir/zcode-package.json, so it can declare nothing at all."
            violations=$((violations + 1))
            continue
        fi

        # what it ships (the ONE definition — see zcode_pkg_sources.sh)
        local -a sources=()
        while IFS= read -r src; do
            [ -n "$src" ] || continue
            rel="${src#"$root"/}"
            sources+=("$rel")
        done < <(zcode_pkg_sources "$root/$dir")
        if [ "${#sources[@]}" -eq 0 ]; then
            echo "check_package_capabilities: UNPROVEN — $name ($dir) ships zero C"
            echo "  sources. Deriving the empty capability set from an empty file"
            echo "  list would 'prove' the package inert without reading one line"
            echo "  of it. A package this gate cannot see is not a package it can"
            echo "  clear."
            return 2
        fi
        n_src_total=$((n_src_total + ${#sources[@]}))

        # derived set: the union over the shipped sources
        local -A derived=()
        for rel in "${sources[@]}"; do
            raw="${MOD_RAW[$rel]:-}"
            [ -n "$raw" ] || continue
            local -a toks=()
            IFS='|' read -ra toks <<< "$raw"
            for tok in "${toks[@]}"; do
                [ -n "$tok" ] || continue
                derived["$tok"]=1
            done
        done

        # declared set, straight from the manifest
        local -a declared_list=()
        local declared_out declared_rc
        declared_out="$(zcode_pkg_json_array "$manifest" capabilities)"
        declared_rc=$?
        if [ "$declared_rc" -ne 0 ]; then
            echo "check_package_capabilities: VIOLATION — $name ($dir) has NO"
            echo "  \"capabilities\" field in its manifest."
            echo "  Absent is not empty. A node reading this package cannot tell"
            echo "  'reaches nothing' from 'nobody wrote it down', and only the"
            echo "  first of those is worth anything. Add the derived value:"
            echo "      \"capabilities\": [$(pkgcap_render_json "${!derived[@]}")]"
            violations=$((violations + 1))
            continue
        fi
        while IFS= read -r tok; do
            [ -n "$tok" ] || continue
            declared_list+=("$tok")
        done <<< "$declared_out"

        # 2. vocabulary + 3. canonical order, before comparing sets: an
        #    unknown or misordered name makes the comparison meaningless.
        local prev="" bad=0
        for tok in "${declared_list[@]}"; do
            if [ -z "${KNOWN_CLASS[$tok]+x}" ]; then
                echo "check_package_capabilities: VIOLATION — $name declares '$tok',"
                echo "  which is not a class in $CLASSES_DEF_NAME."
                echo "  CAP_NONE is not a class and has no row there; the empty set"
                echo "  is spelled []."
                bad=1
            fi
            if [ -n "$prev" ] && ! [[ "$prev" < "$tok" ]]; then
                echo "check_package_capabilities: VIOLATION — $name declares '$tok'"
                echo "  after '$prev'. capabilities[] must be strictly ascending and"
                echo "  duplicate-free: a manifest is content-addressed, so two"
                echo "  spellings of one set are two roots for one package."
                bad=1
            fi
            prev="$tok"
        done
        if [ "$bad" -ne 0 ]; then
            violations=$((violations + 1))
            continue
        fi

        # 4. symmetry, both directions, both reported in one pass.
        local -A declared_set=()
        for tok in "${declared_list[@]}"; do declared_set["$tok"]=1; done

        local -a missing=() extra=()
        for tok in $(pkgcap_sorted "${!derived[@]}"); do
            [ -n "${declared_set[$tok]+x}" ] || missing+=("$tok")
        done
        for tok in "${declared_list[@]}"; do
            [ -n "${derived[$tok]+x}" ] || extra+=("$tok")
        done

        if [ "${#missing[@]}" -gt 0 ]; then
            echo "check_package_capabilities: VIOLATION — $name UNDERSTATES its reach."
            echo "  Shipped files declare ${missing[*]}, the manifest does not."
            for tok in "${missing[@]}"; do
                for rel in "${sources[@]}"; do
                    raw="${MOD_RAW[$rel]:-}"
                    case "|$raw|" in *"|$tok|"*) echo "    $tok <- $rel" ;; esac
                done
            done
            violations=$((violations + 1))
        fi
        if [ "${#extra[@]}" -gt 0 ]; then
            echo "check_package_capabilities: VIOLATION — $name OVERSTATES its reach."
            echo "  Manifest declares ${extra[*]}, no shipped file reaches it."
            echo "  Shrink the declaration; a claim nobody re-derived is not a"
            echo "  safety margin, it is rot in the other direction."
            violations=$((violations + 1))
        fi

        if [ "${#missing[@]}" -eq 0 ] && [ "${#extra[@]}" -eq 0 ]; then
            printf '  %-28s %s\n' "$name" \
                "capabilities: [$(pkgcap_render_plain "${!derived[@]}")]"
        else
            echo "  Derived value for $name:"
            echo "      \"capabilities\": [$(pkgcap_render_json "${!derived[@]}")]"
        fi

    done

    echo "check_package_capabilities: ${#pkg_names[@]} package(s), $n_src_total shipped"
    echo "  source(s), $n_mod module row(s), $n_class capability class(es)."
    if [ "$violations" -gt 0 ]; then
        echo "check_package_capabilities: FAIL — $violations violation(s)"
        return 1
    fi
    echo "check_package_capabilities: OK — every manifest states exactly what its"
    echo "  shipped files can reach"
    return 0
}

# Sorted, deduplicated class list on one line (may legitimately be empty).
pkgcap_sorted() {
    [ "$#" -gt 0 ] || return 0
    printf '%s\n' "$@" | LC_ALL=C sort -u
}
# `"CAP_A", "CAP_B"` — the manifest spelling.
pkgcap_render_json() {
    local out="" t
    for t in $(pkgcap_sorted "$@"); do
        [ -n "$out" ] && out="$out, "
        out="$out\"$t\""
    done
    printf '%s' "$out"
}
# `CAP_A CAP_B` — the report spelling.
pkgcap_render_plain() {
    local out="" t
    for t in $(pkgcap_sorted "$@"); do
        [ -n "$out" ] && out="$out "
        out="$out$t"
    done
    printf '%s' "$out"
}

# ── selftest ────────────────────────────────────────────────────────────────
# Every case below is a fixture tree with its own config/ and lib/, graded by
# the same check_root the gate runs, so nothing about the production tree can
# make a case pass or fail by accident.
FIXTURE_ROOT=""
selftest_cleanup() { [ -n "$FIXTURE_ROOT" ] && rm -rf "$FIXTURE_ROOT"; }

# fixture_base <dir> — config/capability_classes.def (three real classes) and
# an empty config/module_capabilities.def placeholder.
fixture_base() {
    local d="$1"
    mkdir -p "$d/config"
    cat > "$d/config/capability_classes.def" <<'EOF'
ZCL_CAPABILITY_CLASS(NETWORK, "", "")
ZCL_CAPABILITY_CLASS(FS_READ, "", "")
ZCL_CAPABILITY_CLASS(FS_WRITE, "", "")
EOF
    : > "$d/config/module_capabilities.def"
}

# fixture_rows <dir> <"path CAP_A|CAP_B">... — module_capabilities.def rows.
fixture_rows() {
    local d="$1"; shift
    : > "$d/config/module_capabilities.def"
    local row p c
    for row in "$@"; do
        p="${row%% *}"; c="${row#* }"
        printf 'ZCL_MODULE_CAPABILITY("%s", %s, "")\n' "$p" "$c" \
            >> "$d/config/module_capabilities.def"
    done
}

# fixture_pkg <dir> <name> <pkgdir> <capabilities-json-or-ABSENT> <src>...
# Writes the registry row, the manifest (files[] listing exactly <src>...)
# and an empty file for each source.
fixture_pkg() {
    local d="$1" name="$2" pkgdir="$3" caps="$4"; shift 4
    mkdir -p "$d/$pkgdir/src" "$d/config"
    printf 'ZCODE_PACKAGE("%s", "%s", 1,\n    "aa")\n' "$name" "$pkgdir" \
        >> "$d/config/zcode_package_registry.def"
    {
        printf '{\n  "schema": 1,\n  "name": "%s",\n  "dependencies": [],\n' "$name"
        if [ "$caps" != "ABSENT" ]; then
            printf '  "capabilities": [%s],\n' "$caps"
        fi
        printf '  "files": [\n'
        local s first=1
        for s in "$@"; do
            [ "$first" -eq 1 ] || printf ',\n'
            first=0
            printf '    "%s"' "$s"
            mkdir -p "$d/$pkgdir/$(dirname "$s")"
            : > "$d/$pkgdir/$s"
        done
        printf '\n  ]\n}\n'
    } > "$d/$pkgdir/zcode-package.json"
}

expect_rc() {
    local label="$1" want="$2" needle="$3" d="$4" out rc
    out="$(check_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -ne "$want" ]; then
        echo "SELFTEST FAIL: $label — expected exit $want, got $rc."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    if [ -n "$needle" ] && ! grep -qF -- "$needle" <<< "$out"; then
        echo "SELFTEST FAIL: $label — exit $rc was right, but the report never said"
        echo "  '$needle'. A gate that fails for an unstated reason is not a gate."
        printf '%s\n' "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label (rc=$rc)"
    return 0
}

run_selftest() {
    FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/pkg-caps-selftest.XXXXXX")" || {
        echo "check_package_capabilities --selftest: FATAL — mktemp failed"
        return 2
    }
    trap selftest_cleanup EXIT
    local rc=0 d n=0

    echo "== check_package_capabilities selftest =="

    # A. THE CORE PROPERTY. A shipped file reaches NETWORK; the manifest does
    #    not say so. Understated reach must fail.
    d="$FIXTURE_ROOT/a"; fixture_base "$d"
    fixture_pkg "$d" "fx/dialer" "lib/dialer" '' src/dialer.c
    fixture_rows "$d" "lib/dialer/src/dialer.c CAP_NETWORK"
    expect_rc "A: shipped file uses NETWORK, manifest omits it" 1 "UNDERSTATES" "$d" || rc=1
    n=$((n + 1))

    # B. THE OTHER DIRECTION. A manifest names a class no shipped file
    #    reaches. A declaration must not rot upward as code shrinks.
    d="$FIXTURE_ROOT/b"; fixture_base "$d"
    fixture_pkg "$d" "fx/quiet" "lib/quiet" '"CAP_NETWORK"' src/quiet.c
    fixture_rows "$d" "lib/other/src/other.c CAP_FS_READ"
    expect_rc "B: manifest declares a class no shipped file uses" 1 "OVERSTATES" "$d" || rc=1
    n=$((n + 1))

    # C. POSITIVE CONTROL. A genuinely inert package — no rows, empty array —
    #    must PASS. Without this case every other one could be satisfied by a
    #    gate that simply always fails.
    d="$FIXTURE_ROOT/c"; fixture_base "$d"
    fixture_pkg "$d" "fx/inert" "lib/inert" '' src/inert.c
    fixture_rows "$d" "lib/elsewhere/src/elsewhere.c CAP_NETWORK"
    expect_rc "C: a genuinely inert package with [] passes (positive control)" 0 "OK — every manifest" "$d" || rc=1
    n=$((n + 1))

    # C2. POSITIVE CONTROL, non-empty. A correct multi-class declaration must
    #     also pass, so "always fail unless the set is empty" cannot satisfy
    #     this suite either.
    d="$FIXTURE_ROOT/c2"; fixture_base "$d"
    fixture_pkg "$d" "fx/busy" "lib/busy" '"CAP_FS_READ", "CAP_FS_WRITE", "CAP_NETWORK"' \
        src/a.c src/b.c
    fixture_rows "$d" "lib/busy/src/a.c CAP_FS_READ|CAP_NETWORK" \
                      "lib/busy/src/b.c CAP_FS_WRITE"
    expect_rc "C2: a correct three-class declaration passes (positive control)" 0 "OK — every manifest" "$d" || rc=1
    n=$((n + 1))

    # C3. Platform-exact rows replace portable rows for object symmetry, but
    # a package crosses platforms and must declare their UNION. Pin the
    # duplicate-path merge so an associative-array overwrite cannot silently
    # discard either target's reach.
    d="$FIXTURE_ROOT/c3"; fixture_base "$d"
    fixture_pkg "$d" "fx/cross-target" "lib/cross-target" \
        '"CAP_FS_READ", "CAP_NETWORK"' src/portable.c
    fixture_rows "$d" "lib/cross-target/src/portable.c CAP_FS_READ"
    cat > "$d/config/module_capabilities_windows.def" <<'EOF'
ZCL_MODULE_CAPABILITY("lib/cross-target/src/portable.c", CAP_NETWORK, "Windows exact arm")
EOF
    expect_rc "C3: package claims union portable and Windows exact reach" \
        0 "OK — every manifest" "$d" || rc=1
    n=$((n + 1))

    # D. ABSENT IS NOT EMPTY. No "capabilities" key at all must FAIL, and must
    #    not be quietly read as the empty set.
    d="$FIXTURE_ROOT/d"; fixture_base "$d"
    fixture_pkg "$d" "fx/silent" "lib/silent" ABSENT src/silent.c
    fixture_rows "$d" "lib/other/src/other.c CAP_FS_READ"
    expect_rc "D: a manifest with no capabilities field fails, never 'assume empty'" \
        1 "Absent is not empty" "$d" || rc=1
    n=$((n + 1))

    # E. HOLLOW SCAN: zero packages parsed. Exit 2 UNPROVEN, never 0.
    d="$FIXTURE_ROOT/e"; fixture_base "$d"
    fixture_rows "$d" "lib/x/src/x.c CAP_NETWORK"
    : > "$d/config/zcode_package_registry.def"
    expect_rc "E: zero packages parsed is UNPROVEN (exit 2), never a clean tree" \
        2 "UNPROVEN" "$d" || rc=1
    n=$((n + 1))

    # E2. HOLLOW SCAN, the other shape: a package that ships zero C sources.
    #     The object-count floor's blind spot — the scan set is non-empty, so
    #     only a per-package floor can see it.
    d="$FIXTURE_ROOT/e2"; fixture_base "$d"
    fixture_pkg "$d" "fx/empty" "lib/empty" '' README.md
    fixture_rows "$d" "lib/x/src/x.c CAP_NETWORK"
    expect_rc "E2: a package shipping zero C sources is UNPROVEN (exit 2)" \
        2 "ships zero C" "$d" || rc=1
    n=$((n + 1))

    # E3. HOLLOW SCAN, third shape: module_capabilities.def parsed to zero
    #     rows. Every package would derive [] and every empty declaration
    #     would 'pass' off a table this script could not read.
    d="$FIXTURE_ROOT/e3"; fixture_base "$d"
    fixture_pkg "$d" "fx/inert" "lib/inert" '' src/inert.c
    : > "$d/config/module_capabilities.def"
    expect_rc "E3: zero module rows is UNPROVEN (exit 2), not a tree of inert packages" \
        2 "parsed 0 rows" "$d" || rc=1
    n=$((n + 1))

    # F. LIST-END PINNING, declared array. A bash `read` loop over a payload
    #    with no trailing newline silently DROPS THE LAST FIELD, and a
    #    validator that cannot see the last element of a list fails open for
    #    its entire life. Pin BOTH ends: the offending entry LAST, then the
    #    same defect NON-LAST.
    d="$FIXTURE_ROOT/f1"; fixture_base "$d"
    fixture_pkg "$d" "fx/tail" "lib/tail" '"CAP_FS_READ", "CAP_NETWORK"' src/tail.c
    fixture_rows "$d" "lib/tail/src/tail.c CAP_FS_READ"
    expect_rc "F1: a bogus class in the LAST array position is seen" 1 "CAP_NETWORK" "$d" || rc=1
    n=$((n + 1))

    d="$FIXTURE_ROOT/f2"; fixture_base "$d"
    fixture_pkg "$d" "fx/head" "lib/head" '"CAP_FS_READ", "CAP_NETWORK"' src/head.c
    fixture_rows "$d" "lib/head/src/head.c CAP_NETWORK"
    expect_rc "F2: the same defect in a NON-LAST array position is seen" 1 "CAP_FS_READ" "$d" || rc=1
    n=$((n + 1))

    # G. LIST-END PINNING, shipped files[]. Same hazard on the other list: the
    #    reach must be found whether it comes from the LAST shipped source or
    #    an earlier one.
    d="$FIXTURE_ROOT/g1"; fixture_base "$d"
    fixture_pkg "$d" "fx/lastfile" "lib/lastfile" '' src/one.c src/two.c src/three.c
    fixture_rows "$d" "lib/lastfile/src/three.c CAP_NETWORK"
    expect_rc "G1: reach from the LAST shipped source is seen" 1 "src/three.c" "$d" || rc=1
    n=$((n + 1))

    d="$FIXTURE_ROOT/g2"; fixture_base "$d"
    fixture_pkg "$d" "fx/firstfile" "lib/firstfile" '' src/one.c src/two.c src/three.c
    fixture_rows "$d" "lib/firstfile/src/one.c CAP_NETWORK"
    expect_rc "G2: reach from a NON-LAST shipped source is seen" 1 "src/one.c" "$d" || rc=1
    n=$((n + 1))

    # H. VOCABULARY. A name that is not a class in capability_classes.def.
    d="$FIXTURE_ROOT/h"; fixture_base "$d"
    fixture_pkg "$d" "fx/bogus" "lib/bogus" '"CAP_TELEPATHY"' src/bogus.c
    fixture_rows "$d" "lib/bogus/src/bogus.c CAP_NETWORK"
    expect_rc "H: a class name absent from capability_classes.def fails" \
        1 "not a class in" "$d" || rc=1
    n=$((n + 1))

    # I. CANONICAL ORDER. One set, one encoding — the manifest is hashed.
    d="$FIXTURE_ROOT/i"; fixture_base "$d"
    fixture_pkg "$d" "fx/unsorted" "lib/unsorted" '"CAP_NETWORK", "CAP_FS_READ"' src/u.c
    fixture_rows "$d" "lib/unsorted/src/u.c CAP_FS_READ|CAP_NETWORK"
    expect_rc "I: an out-of-order capabilities array fails" 1 "strictly ascending" "$d" || rc=1
    n=$((n + 1))

    # J. UNSHIPPED FILES DO NOT COUNT. A file that lives in the package
    #    directory but is NOT in files[] never reaches the receiving node, so
    #    it must not push a capability into the manifest. This is the case
    #    that makes six of the nine real packages inert, and the one an
    #    implementation that globbed the directory would get wrong.
    d="$FIXTURE_ROOT/j"; fixture_base "$d"
    fixture_pkg "$d" "fx/narrow" "lib/narrow" '' src/shipped.c
    : > "$d/lib/narrow/src/unshipped.c"
    fixture_rows "$d" "lib/narrow/src/unshipped.c CAP_NETWORK"
    expect_rc "J: a file in the directory but not in files[] contributes nothing" \
        0 "OK — every manifest" "$d" || rc=1
    n=$((n + 1))

    if [ "$rc" -eq 0 ]; then
        echo "== selftest: PASS ($n/$n) =="
    else
        echo "== selftest: FAIL =="
    fi
    return "$rc"
}

main() {
    case "${1:-}" in
        --selftest) run_selftest; exit $? ;;
        "") ;;
        *) echo "usage: $0 [--selftest]" >&2; exit 2 ;;
    esac
    check_root "$REPO_ROOT"
    exit $?
}

main "$@"
