#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
# Enforce the physical five-authority architecture and its product rooms.
set -euo pipefail
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/repo_shape.sh
source "$SCRIPT_DIR/repo_shape.sh"

fail=0
tracked="$(mktemp "${TMPDIR:-/tmp}/z23-architecture-tracked.XXXXXX")"
actual="$(mktemp "${TMPDIR:-/tmp}/z23-architecture-actual.XXXXXX")"
expected="$(mktemp "${TMPDIR:-/tmp}/z23-architecture-expected.XXXXXX")"
trap 'rm -f "$tracked" "$actual" "$expected"' EXIT
git ls-files > "$tracked"

# The root is the public table of contents, not an overflow namespace.  The
# current tree needs 24 entries for the five product authorities, developer
# and distribution surfaces, tool-discovery files, and legal/build metadata.
# Any 25th entry must first be placed under an existing owner or deliberately
# replace something here; merely tracking it must not make the root grow.
root_entries="$(awk -F/ '{ seen[$1] = 1 } END { print length(seen) }' "$tracked")"
if (( root_entries > 24 )); then
    echo "check-architecture-tree: root-entry budget exceeded: $root_entries > 24" >&2
    echo "check-architecture-tree: place the new entry under its owning authority" >&2
    fail=1
fi

obsolete=(app lib config adapters ports domain application packages src examples)
for old in "${obsolete[@]}"; do
    if grep -q "^$old/" "$tracked"; then
        echo "check-architecture-tree: obsolete root still tracked: $old/" >&2
        fail=1
    fi
done

# Product contexts are a closed set declared once in the Makefile.
awk -F/ '$1=="contexts" && NF>1 {print $2}' "$tracked" | sort -u > "$actual"
printf '%s\n' "${ZCL_PRODUCT_CONTEXTS[@]}" | sort -u > "$expected"
if ! cmp -s "$actual" "$expected"; then
    echo "check-architecture-tree: contexts/ differs from PRODUCT_CONTEXTS" >&2
    diff -u "$expected" "$actual" >&2 || true
    fail=1
fi

# Every declared module has one and only one physical owner.
awk -F/ '
    $1=="contexts" && $3=="modules" && NF>3 {print $4}
    ($1=="core" || $1=="engine" || $1=="cognition" || $1=="platform") &&
        $2=="modules" && NF>2 {print $3}
' "$tracked" | sort -u > "$actual"
printf '%s\n' "${ZCL_LIB_MODULES[@]}" | sort -u > "$expected"
if ! cmp -s "$actual" "$expected"; then
    echo "check-architecture-tree: physical modules differ from the module declaration" >&2
    diff -u "$expected" "$actual" >&2 || true
    fail=1
fi
duplicates="$(awk -F/ '
    $1=="contexts" && $3=="modules" && NF>3 {print $1 "/" $2 "/" $3 "\t" $4}
    ($1=="core" || $1=="engine" || $1=="cognition" || $1=="platform") &&
        $2=="modules" && NF>2 {print $1 "/" $2 "\t" $3}
' "$tracked" | sort -u | awk -F'\t' '{print $2}' | sort | uniq -d)"
if [[ -n "$duplicates" ]]; then
    echo "check-architecture-tree: module has more than one physical owner:" >&2
    printf '%s\n' "$duplicates" >&2
    fail=1
fi

check_rooms() {
    local prefix="$1" allowed="$2" room
    awk -F/ -v prefix="$prefix" '
        index($0, prefix "/") == 1 {
            rest=substr($0, length(prefix)+2); split(rest, part, "/")
            if (index(rest, "/") > 0 && part[1] != "") print part[1]
        }
    ' "$tracked" | sort -u > "$actual"
    : > "$expected"
    for room in $allowed; do printf '%s\n' "$room"; done | sort -u > "$expected"
    while IFS= read -r room; do
        [[ -z "$room" ]] && continue
        if ! grep -qxF "$room" "$expected"; then
            echo "check-architecture-tree: $prefix/$room has no declared room shape" >&2
            fail=1
        fi
    done < "$actual"
}

check_rooms core "chainparams consensus math modules params"
check_rooms engine "application composition conditions controllers entry jobs models modules reducer services supervisors"
check_rooms cognition "controllers models modules services"
check_rooms platform "adapters deploy domain modules packaging ports"
for context in "${ZCL_PRODUCT_CONTEXTS[@]}"; do
    check_rooms "contexts/$context" \
        "apps conditions controllers corpus domain jobs models modules packages services supervisors views"
done

# Reducer support shapes are nested beneath the one-writer room. A reducer
# source appearing in a generic engine shape would create an ambiguous home.
if awk -F/ '
    $1=="engine" && $2!="reducer" && ($0 ~ /(^|\/)reducer([^/]*)(\/|\.)/) {
        print; bad=1
    }
    END {exit bad ? 0 : 1}
' "$tracked" > "$actual"; then
    echo "check-architecture-tree: reducer-owned path escaped engine/reducer/:" >&2
    cat "$actual" >&2
    fail=1
fi

if (( fail != 0 )); then exit 1; fi
echo "check-architecture-tree: PASS — five authorities, ${#ZCL_PRODUCT_CONTEXTS[@]} contexts, ${#ZCL_LIB_MODULES[@]} single-owner modules"
