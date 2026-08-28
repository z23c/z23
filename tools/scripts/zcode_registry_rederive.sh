#!/usr/bin/env bash
# Drive the C23 Commons package registry back to a fixpoint after source moved.
#
# WHY THIS EXISTS
# ---------------
# A package's roots are derived from its file content. Any edit under a
# registered package directory moves that package's content root, which
# invalidates two independent places the old value was written down:
#
#   1. its row in config/zcode_package_registry.def, and
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
#  * Derives from actual on-disk content. It cannot manufacture a pass: every
#    value written here is one the checker independently recomputes.
#  * Converges or FAILS LOUD. A non-converging registry exits non-zero and says
#    which package would not settle. It never reports success on a dirty check.
#  * --check makes no edits and exits 1 on drift, for use as a gate.
#
# Usage: tools/scripts/zcode_registry_rederive.sh [--check]
set -Eeuo pipefail

cd "$(dirname "$0")/../.."

# The registry is spread over MORE THAN ONE .def -- config/
# zcode_package_registry.def holds the library packages and
# config/zcode_c23_commons_app.def holds the commons app. A tool that
# assumes a single file silently fails to rewrite the rows it cannot
# find, and then loops forever re-deriving a row it never changed.
# Discover them instead of naming one.
mapfile -t DEFS < <(LC_ALL=C grep -rl '^ZCODE_PACKAGE(' --include='*.def' config/ | sort)
[ "${#DEFS[@]}" -gt 0 ] || { echo "FAIL: no registry .def found under config/" >&2; exit 2; }

# Which .def owns a given package row.
def_for() {
    local n="$1" f
    for f in "${DEFS[@]}"; do
        if LC_ALL=C grep -q "^ZCODE_PACKAGE(\"$n\"," "$f"; then printf '%s' "$f"; return 0; fi
    done
    return 1
}
BIN=build/bin/zcode-package-registry-check
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1


# One round per package is the theoretical worst case (a single dependency
# chain, fixed one link at a time); double it so an honest non-convergence is
# reported as such instead of being mistaken for the iteration cap.
PKG_COUNT=$(LC_ALL=C grep -ch '^ZCODE_PACKAGE(' "${DEFS[@]}" | awk '{s += $1} END {print s + 0}')
MAX_ROUNDS=$((PKG_COUNT * 2 + 2))

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
for round in $(seq 1 "$MAX_ROUNDS"); do
    rebuild
    if out=$("$BIN" 2>&1); then
        if [ "$changed_any" = 1 ]; then
            echo "registry: CLEAN after $((round - 1)) re-derivation(s)"
        else
            echo "registry: CLEAN -- no drift, nothing to do"
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

    # 1. the registry row, in whichever .def actually declares it. A row
    #    we cannot locate is a hard failure, never a skipped edit: a
    #    silent no-op here is precisely what makes the loop spin.
    def=$(def_for "$name") || {
        echo "FAIL: $name is not declared in any registry .def under config/." >&2
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
done

echo "FAIL: registry did not converge in $MAX_ROUNDS round(s)." >&2
echo "      This is a real problem -- a dependency cycle or a root that is not" >&2
echo "      a pure function of content. NOT a pass; do not ignore." >&2
exit 2
