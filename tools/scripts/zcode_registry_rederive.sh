#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Drive the C23 Commons package registry back to a fixpoint after source moved.
#
# WHY THIS EXISTS
# ---------------
# A package's roots are derived from its file content. Any edit under a
# registered package directory moves that package's content root, which
# invalidates two independent places the old value was written down:
#
#   1. its row in engine/composition/zcode_package_registry.def, and
#   2. the `dependencies[].root` pin in every OTHER package's
#      zcode-package.json that depends on it.
#
# Both must move together, and (2) is itself package content -- so updating a
# dependent's pin moves that dependent's own root, which invalidates ITS
# dependents. The drift therefore cascades along the dependency DAG and cannot
# be fixed in one pass; it has to be iterated to a fixpoint.
#
# There was no tool for this. zcode-package-registry-check reports exactly one
# mismatch and its --derive prints values without writing anything, so the only
# available procedure was: read a hash, hand-edit a row, rebuild the checker
# (the .def is compiled in through an X-macro, so a stale binary keeps
# reporting the drift you just fixed), run again, repeat -- once per package,
# in dependency order. That is why a `zclassic23/base` drift reached origin/main
# unfixed and took three test groups down with it.
#
# CONTRACT
# --------
#  * Discovers every contexts/commons/packages/*/zcode-package.json, whether
#    or not that package has a registry .def row. A tracked manifest omitted
#    from the scan is a coverage failure, never a clean result.
#  * Derives from actual on-disk content. It cannot manufacture a pass: every
#    root written here is one the C23 checker independently recomputes.
#  * Converges or FAILS LOUD. A non-converging registry exits non-zero and says
#    which package would not settle. It never reports success on a dirty check.
#  * --check makes no edits and exits 1 on drift, for use as a gate.
#
# Usage: tools/scripts/zcode_registry_rederive.sh [--check|--selftest]
set -Eeuo pipefail

cd "$(dirname "$0")/../.."

BIN=build/bin/zcode-package-registry-check
CHECK_ONLY=0
SELFTEST=0
case "${1:-}" in
    "") ;;
    --check) CHECK_ONLY=1 ;;
    --selftest) SELFTEST=1 ;;
    *) echo "usage: $0 [--check|--selftest]" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { echo "usage: $0 [--check|--selftest]" >&2; exit 2; }

CORPUS_MANIFEST_ROOT=contexts/commons/packages
PACKAGE_MANIFESTS=()
EDGE_MANIFESTS=()
EDGE_NAMES=()
EDGE_ROOTS=()
MISMATCH_MANIFESTS=()
MISMATCH_NAMES=()
MISMATCH_PINNED=()
MISMATCH_EXPECTED=()
declare -A ROOT_BY_NAME MANIFEST_BY_NAME

# The filesystem glob is the working-tree discovery. Git's tracked list is an
# independent coverage oracle: if discovery ever skips a checked-in manifest,
# the script refuses before it can print CLEAN. Untracked package manifests are
# included too, because re-derivation is about the actual on-disk tree.
require_manifest_coverage() { # $1 = repository root, remaining = discovered
    local root="$1"; shift
    local tracked candidate found
    mapfile -t tracked < <(
        git -C "$root" ls-files -- "$CORPUS_MANIFEST_ROOT/*/zcode-package.json" |
            LC_ALL=C sort
    )
    [ "${#tracked[@]}" -gt 0 ] || {
        echo "FAIL: no tracked package manifests under $CORPUS_MANIFEST_ROOT" >&2
        return 2
    }
    for candidate in "${tracked[@]}"; do
        found=0
        local discovered
        for discovered in "$@"; do
            [ "$candidate" = "$discovered" ] && { found=1; break; }
        done
        [ "$found" -eq 1 ] || {
            echo "FAIL: package manifest discovery missed $candidate" >&2
            echo "      refusing to report CLEAN with incomplete coverage" >&2
            return 2
        }
    done
}

discover_package_manifests() { # $1 = repository root
    local root="$1" path
    local found=("$root"/$CORPUS_MANIFEST_ROOT/*/zcode-package.json)
    PACKAGE_MANIFESTS=()
    for path in "${found[@]}"; do
        [ -f "$path" ] || continue
        PACKAGE_MANIFESTS+=("${path#"$root"/}")
    done
    mapfile -t PACKAGE_MANIFESTS < <(
        printf '%s\n' "${PACKAGE_MANIFESTS[@]}" | LC_ALL=C sort -u
    )
    [ "${#PACKAGE_MANIFESTS[@]}" -gt 0 ] || {
        echo "FAIL: no package manifests discovered under $CORPUS_MANIFEST_ROOT" >&2
        return 2
    }
    require_manifest_coverage "$root" "${PACKAGE_MANIFESTS[@]}"
}

# Derive every package root and every named direct dependency from the C23
# helper. Nothing here trusts registry membership: the manifest census is the
# authority over what must be scanned.
scan_corpus() { # $1 = repository root, $2 = checker command/function
    local root="$1" deriver="$2" manifest dir out header name content line
    local dep_name dep_root expected i
    ROOT_BY_NAME=()
    MANIFEST_BY_NAME=()
    EDGE_MANIFESTS=()
    EDGE_NAMES=()
    EDGE_ROOTS=()
    MISMATCH_MANIFESTS=()
    MISMATCH_NAMES=()
    MISMATCH_PINNED=()
    MISMATCH_EXPECTED=()

    for manifest in "${PACKAGE_MANIFESTS[@]}"; do
        dir="$root/${manifest%/zcode-package.json}"
        if ! out=$("$deriver" --derive-dir "$dir" 2>&1); then
            echo "FAIL: could not derive $manifest:" >&2
            printf '%s\n' "$out" >&2
            return 2
        fi
        header=$(printf '%s\n' "$out" | head -1)
        name=${header%% *}
        content=$(printf '%s\n' "$header" |
            LC_ALL=C sed -n 's/.* content=\([0-9a-f]*\).*/\1/p')
        if [[ ! "$name" =~ ^[a-z0-9][a-z0-9._+-]*/[a-z0-9][a-z0-9._+-]*$ ]] ||
           [[ ! "$content" =~ ^[0-9a-f]{64}$ ]]; then
            echo "FAIL: malformed derivation header for $manifest: $header" >&2
            return 2
        fi
        if [ -n "${ROOT_BY_NAME[$name]+present}" ]; then
            echo "FAIL: duplicate package name $name in $manifest and ${MANIFEST_BY_NAME[$name]}" >&2
            return 2
        fi
        ROOT_BY_NAME[$name]=$content
        MANIFEST_BY_NAME[$name]=$manifest

        while IFS= read -r line; do
            [[ "$line" == dependency\ name=*\ root=* ]] || continue
            dep_name=${line#dependency name=}
            dep_name=${dep_name%% root=*}
            dep_root=${line##* root=}
            if [ -z "$dep_name" ] || [[ ! "$dep_root" =~ ^[0-9a-f]{64}$ ]]; then
                echo "FAIL: malformed dependency derivation for $manifest: $line" >&2
                return 2
            fi
            EDGE_MANIFESTS+=("$manifest")
            EDGE_NAMES+=("$dep_name")
            EDGE_ROOTS+=("$dep_root")
        done <<< "$out"
    done

    for i in "${!EDGE_NAMES[@]}"; do
        name=${EDGE_NAMES[$i]}
        expected=${ROOT_BY_NAME[$name]:-}
        if [ -z "$expected" ]; then
            echo "FAIL: ${EDGE_MANIFESTS[$i]} names undiscovered dependency $name" >&2
            return 2
        fi
        if [ "${EDGE_ROOTS[$i]}" != "$expected" ]; then
            MISMATCH_MANIFESTS+=("${EDGE_MANIFESTS[$i]}")
            MISMATCH_NAMES+=("$name")
            MISMATCH_PINNED+=("${EDGE_ROOTS[$i]}")
            MISMATCH_EXPECTED+=("$expected")
        fi
    done
}

# Replace the root in exactly one named dependency object. Buffering each JSON
# object makes member order irrelevant (`root` precedes `name` in some checked
# manifests). Zero or duplicate matches are hard failures.
rewrite_dependency_pin() { # $1 = manifest, $2 = name, $3 = root
    local manifest="$1" name="$2" root="$3" tmp="$1.tmp.$$"
    if ! awk -v wanted="$name" -v replacement="$root" '
        function emit_object(    i) {
            if (object_name == wanted) {
                matches++
                if (root_count != 1) bad = 1
                else sub(/"root"[ \t]*:[ \t]*"[^"]*"/,
                         "\"root\": \"" replacement "\"", lines[root_line])
            }
            for (i = 1; i <= line_count; i++) print lines[i]
            delete lines
            line_count = root_count = root_line = 0
            object_name = ""
            in_object = 0
        }
        {
            if (!in_dependencies) {
                print
                if ($0 ~ /"dependencies"[ \t]*:[ \t]*\[/)
                    in_dependencies = 1
                next
            }
            if (!in_object && $0 ~ /^[ \t]*\]/) {
                in_dependencies = 0
                print
                next
            }
            if (!in_object && $0 ~ /^[ \t]*\{/) in_object = 1
            if (in_object) {
                lines[++line_count] = $0
                if ($0 ~ /"name"[ \t]*:/) {
                    object_name = $0
                    sub(/^.*"name"[ \t]*:[ \t]*"/, "", object_name)
                    sub(/".*$/, "", object_name)
                }
                if ($0 ~ /"root"[ \t]*:/) {
                    root_count++
                    root_line = line_count
                }
                if ($0 ~ /^[ \t]*\}/) emit_object()
                next
            }
            print
        }
        END {
            if (in_object || bad || matches != 1) exit 1
        }
    ' "$manifest" > "$tmp"; then
        rm -f "$tmp"
        echo "FAIL: $manifest does not contain exactly one dependency named $name" >&2
        return 2
    fi
    mv "$tmp" "$manifest"
}

fixture_derive() { # selftest-only deterministic stand-in for --derive-dir
    local dir="$2" package=${2##*/} pinned root
    pinned=$(LC_ALL=C sed -n 's/.*"root"[ \t]*:[ \t]*"\([0-9a-f]*\)".*/\1/p' \
        "$dir/zcode-package.json" | head -1)
    case "$package" in
        zprng) printf 'zprng/zprng content=%064d\n' 0 | tr '0' '1' ;;
        consumer)
            [ "$pinned" = "$(printf '%064d' 0 | tr '0' '1')" ] &&
                root=$(printf '%064d' 0 | tr '0' '2') ||
                root=$(printf '%064d' 0 | tr '0' 'b')
            printf 'fixture/consumer content=%s\n' "$root"
            printf 'dependency name=zprng/zprng root=%s\n' "$pinned"
            ;;
        top)
            [ "$pinned" = "$(printf '%064d' 0 | tr '0' '2')" ] &&
                root=$(printf '%064d' 0 | tr '0' '3') ||
                root=$(printf '%064d' 0 | tr '0' 'c')
            printf 'fixture/top content=%s\n' "$root"
            printf 'dependency name=fixture/consumer root=%s\n' "$pinned"
            ;;
        *) return 2 ;;
    esac
}

run_selftest() {
    local tmp rounds i old_leaf old_consumer new_leaf new_consumer
    tmp=$(mktemp -d)
    trap "rm -rf '$tmp'" EXIT
    old_leaf=$(printf '%064d' 0 | tr '0' 'a')
    old_consumer=$(printf '%064d' 0 | tr '0' 'b')
    new_leaf=$(printf '%064d' 0 | tr '0' '1')
    new_consumer=$(printf '%064d' 0 | tr '0' '2')
    mkdir -p "$tmp/$CORPUS_MANIFEST_ROOT"/{zprng,consumer,top}
    printf '{\n  "schema": 1,\n  "name": "zprng/zprng",\n  "dependencies": []\n}\n' \
        > "$tmp/$CORPUS_MANIFEST_ROOT/zprng/zcode-package.json"
    printf '{\n  "schema": 1,\n  "name": "fixture/consumer",\n  "dependencies": [\n    {\n      "name": "zprng/zprng",\n      "root": "%s"\n    }\n  ]\n}\n' \
        "$old_leaf" > "$tmp/$CORPUS_MANIFEST_ROOT/consumer/zcode-package.json"
    printf '{\n  "schema": 1,\n  "name": "fixture/top",\n  "dependencies": [\n    {\n      "root": "%s",\n      "name": "fixture/consumer"\n    }\n  ]\n}\n' \
        "$old_consumer" > "$tmp/$CORPUS_MANIFEST_ROOT/top/zcode-package.json"
    git -C "$tmp" init -q
    git -C "$tmp" add "$CORPUS_MANIFEST_ROOT"

    discover_package_manifests "$tmp"
    [ "${#PACKAGE_MANIFESTS[@]}" -eq 3 ] || return 1
    local incomplete=()
    for i in "${PACKAGE_MANIFESTS[@]}"; do
        [[ "$i" == */zprng/zcode-package.json ]] || incomplete+=("$i")
    done
    if require_manifest_coverage "$tmp" "${incomplete[@]}" >/dev/null 2>&1; then
        echo "SELFTEST FAILED: omitted zprng manifest reported complete coverage" >&2
        return 1
    fi
    echo "  selftest ok: an omitted non-registry zprng manifest fails coverage"

    rounds=0
    while :; do
        scan_corpus "$tmp" fixture_derive
        [ "${#MISMATCH_NAMES[@]}" -gt 0 ] || break
        for i in "${!MISMATCH_NAMES[@]}"; do
            rewrite_dependency_pin "$tmp/${MISMATCH_MANIFESTS[$i]}" \
                "${MISMATCH_NAMES[$i]}" "${MISMATCH_EXPECTED[$i]}"
        done
        rounds=$((rounds + 1))
        [ "$rounds" -le 3 ] || return 1
    done
    [ "$rounds" -eq 2 ] || {
        echo "SELFTEST FAILED: leaf-to-top propagation took $rounds rounds" >&2
        return 1
    }
    grep -q "$new_leaf" "$tmp/$CORPUS_MANIFEST_ROOT/consumer/zcode-package.json"
    grep -q "$new_consumer" "$tmp/$CORPUS_MANIFEST_ROOT/top/zcode-package.json"
    if grep -qr -e "$old_leaf" -e "$old_consumer" "$tmp/$CORPUS_MANIFEST_ROOT"; then
        echo "SELFTEST FAILED: an old dependency root survived the fixpoint" >&2
        return 1
    fi
    echo "  selftest ok: non-registry leaf root repins its dependent and transitive consumer"
    echo "[zcode_registry_rederive] SELFTEST PASS (omitted manifests fail; non-registry roots reach a terminal fixpoint)"
}

if [ "$SELFTEST" -eq 1 ]; then
    run_selftest
    exit 0
fi

# The registry is spread over MORE THAN ONE .def -- engine/composition/
# zcode_package_registry.def holds the library packages and
# engine/composition/zcode_c23_commons_app.def holds the commons app. A tool that
# assumes a single file silently fails to rewrite the rows it cannot
# find, and then loops forever re-deriving a row it never changed.
# Discover them instead of naming one.
mapfile -t DEFS < <(LC_ALL=C grep -rl '^ZCODE_PACKAGE(' --include='*.def' engine/composition/ | sort)
[ "${#DEFS[@]}" -gt 0 ] || { echo "FAIL: no registry .def found under engine/composition/" >&2; exit 2; }

# Which .def owns a given package row.
def_for() {
    local n="$1" f
    for f in "${DEFS[@]}"; do
        if LC_ALL=C grep -q "^ZCODE_PACKAGE(\"$n\"," "$f"; then printf '%s' "$f"; return 0; fi
    done
    return 1
}

# One round per package is the theoretical worst case (a single dependency
# chain, fixed one link at a time); double it so an honest non-convergence is
# reported as such instead of being mistaken for the iteration cap.
discover_package_manifests "$PWD"
PKG_COUNT=$(LC_ALL=C grep -ch '^ZCODE_PACKAGE(' "${DEFS[@]}" | awk '{s += $1} END {print s + 0}')
MAX_ROUNDS=$(((PKG_COUNT + ${#PACKAGE_MANIFESTS[@]}) * 2 + 2))

rebuild() {
    if ! make -j"$(nproc 2>/dev/null || echo 4)" "$BIN" >/tmp/zcode_rederive_build.$$ 2>&1; then
        echo "FAIL: could not rebuild $BIN -- registry state NOT verified." >&2
        tail -20 /tmp/zcode_rederive_build.$$ >&2
        rm -f /tmp/zcode_rederive_build.$$
        exit 2
    fi
    rm -f /tmp/zcode_rederive_build.$$
}

# Field N (1-based) of a package's stored row: content release recipe lock
# capsule publisher signature, in the order of the ZCODE_PACKAGE macro.
stored_field() {
    local d; d=$(def_for "$1") || return 1
    awk -v n="$1" -v k="$2" '
        index($0, "ZCODE_PACKAGE(\"" n "\",") == 1 { found = 1; i = 0; next }
        found { i++; if (i == k) { gsub(/[^0-9a-f]/, ""); print; exit } }
    ' "$d"
}

changed_any=0
registry_changed=0
prev_name=""
for round in $(seq 1 "$MAX_ROUNDS"); do
    rebuild
    scan_corpus "$PWD" "$BIN" || exit 2
    if [ "${#MISMATCH_NAMES[@]}" -gt 0 ]; then
        if [ "$CHECK_ONLY" = 1 ]; then
            echo "registry: DRIFT on ${MISMATCH_MANIFESTS[0]} dependency ${MISMATCH_NAMES[0]}"
            echo "  pinned:   ${MISMATCH_PINNED[0]}"
            echo "  derived:  ${MISMATCH_EXPECTED[0]}"
            echo "  fix: tools/scripts/zcode_registry_rederive.sh"
            exit 1
        fi
        for i in "${!MISMATCH_NAMES[@]}"; do
            rewrite_dependency_pin "$PWD/${MISMATCH_MANIFESTS[$i]}" \
                "${MISMATCH_NAMES[$i]}" "${MISMATCH_EXPECTED[$i]}"
            echo "  [$round] repinned ${MISMATCH_MANIFESTS[$i]} -> ${MISMATCH_NAMES[$i]} (${MISMATCH_PINNED[$i]:0:12}… -> ${MISMATCH_EXPECTED[$i]:0:12}…)"
        done
        changed_any=1
        continue
    fi
    if out=$("$BIN" 2>&1); then
        if [ "$changed_any" = 1 ]; then
            echo "registry: CLEAN after $((round - 1)) fixpoint round(s); ${#PACKAGE_MANIFESTS[@]} package manifests covered"
            # This script rebuilds ONLY $BIN. Three test sources include the
            # same engine/composition/zcode_package_registry.def and compile the row into
            # build/bin/test_parallel, so until that is relinked the suite is
            # still asserting the OLD root and will report a mismatch that no
            # longer exists. That exact stale-binary reading has already been
            # mistaken for a real regression once. Say so, every time a row
            # actually moved.
            if [ "$registry_changed" = 1 ]; then
                echo "registry: a row MOVED -- rebuild before trusting the suite:" >&2
                echo "           make -j\"\$(getconf _NPROCESSORS_ONLN)\" test_parallel" >&2
                echo "         build/bin/test_parallel still embeds the old root" >&2
                echo "         until it is relinked (test_zcode_package_registry," >&2
                echo "         test_zcode_swarm_net, test_zcode_score_receipt)." >&2
            fi
        else
            echo "registry: CLEAN -- no drift, nothing to do; ${#PACKAGE_MANIFESTS[@]} package manifests covered"
        fi
        exit 0
    fi

    name=$(printf '%s\n' "$out" | LC_ALL=C sed -n 's/^zcode registry mismatch: \([^ ]*\).*/\1/p' | head -1)
    if [ -z "$name" ]; then
        echo "FAIL: $BIN failed but printed no mismatch line:" >&2
        printf '%s\n' "$out" >&2
        exit 2
    fi

    if [ "$CHECK_ONLY" = 1 ]; then
        echo "registry: DRIFT on $name (and possibly more behind it)."
        echo "  fix: tools/scripts/zcode_registry_rederive.sh"
        exit 1
    fi

    d=$("$BIN" --derive "$name" 2>&1 | head -1)
    field() { printf '%s\n' "$d" | LC_ALL=C sed -n "s/.* $1=\([0-9a-f]*\).*/\1/p"; }
    content=$(field content); release=$(field release); recipe=$(field recipe)
    lock=$(field lock); capsule=$(field capsule)
    publisher=$(field publisher); signature=$(field signature)
    if [ -z "$signature" ] || [ -z "$content" ]; then
        echo "FAIL: could not parse --derive output for $name:" >&2
        printf '%s\n' "$d" >&2
        exit 2
    fi

    old_content=$(stored_field "$name" 1)

    # Non-progress, caught on the round it happens rather than after
    # MAX_ROUNDS. Rewriting a row with the values it already holds cannot
    # move the checker, so the same name coming back with old == new means
    # the mismatch is NOT this row's digests. In practice it is a dependent
    # whose zcode-package.json pins a root that is neither this package's
    # old value nor its new one -- the cascade below rewrites pins by
    # substituting the OLD string, so a third value is invisible to it and
    # updates 0 pins forever. Spinning to MAX_ROUNDS and blaming a
    # "dependency cycle" sends the reader to the wrong place entirely.
    if [ "$name" = "$prev_name" ] && [ "$old_content" = "$content" ]; then
        echo "FAIL: $name re-derived to the root it already records" >&2
        echo "      ($content)." >&2
        echo "      Its digests are correct, so the mismatch is elsewhere:" >&2
        echo "      look for a dependencies[].root in a zcode-package.json" >&2
        echo "      that names none of the current registry roots." >&2
        echo "      Compare: grep -rn '\"root\"' --include=zcode-package.json ." >&2
        echo "      against the content column of engine/composition/*.def." >&2
        exit 2
    fi
    prev_name=$name

    # 1. the registry row, in whichever .def actually declares it. A row
    #    we cannot locate is a hard failure, never a skipped edit: a
    #    silent no-op here is precisely what makes the loop spin.
    def=$(def_for "$name") || {
        echo "FAIL: $name is not declared in any registry .def under engine/composition/." >&2
        echo "      The checker knows a package the registry files do not." >&2
        exit 2
    }
    awk -v n="$name" -v a="$content" -v b="$release" -v c="$recipe" -v e="$lock" \
        -v f="$capsule" -v g="$publisher" -v h="$signature" '
        index($0, "ZCODE_PACKAGE(\"" n "\",") == 1 {
            print; k = 1; split(a " " b " " c " " e " " f " " g " " h, V, " "); next
        }
        k >= 1 && k <= 7 { printf "    \"%s\"%s\n", V[k], (k == 7 ? ")" : ","); k++; next }
        { print }
    ' "$def" > "$def.tmp.$$" && mv "$def.tmp.$$" "$def"

    # 2. every dependent's pinned copy of the root that just moved
    pinned=0
    if [ -n "$old_content" ] && [ "$old_content" != "$content" ]; then
        while IFS= read -r j; do
            awk -v o="$old_content" -v w="$content" '
                /"root"/ { gsub(o, w) } { print }
            ' "$j" > "$j.tmp.$$" && mv "$j.tmp.$$" "$j"
            pinned=$((pinned + 1))
        done < <(LC_ALL=C grep -rl "\"$old_content\"" --include=zcode-package.json . || true)
    fi

    echo "  [$round] re-derived $name (${old_content:0:12}… -> ${content:0:12}…), ${pinned} dependent pin(s) updated"
    changed_any=1
    registry_changed=1
done

echo "FAIL: registry did not converge in $MAX_ROUNDS round(s)." >&2
echo "      This is a real problem -- a dependency cycle or a root that is not" >&2
echo "      a pure function of content. NOT a pass; do not ignore." >&2
exit 2
