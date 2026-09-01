# shellcheck shell=bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: the ONE answer to "what does this C23 Commons package actually
#          ship?", shared by every gate that has to grade a package on its
#          own shipped contents.
#
# WHY THIS IS A SHARED FILE. A C23 Commons package ships to a node that never
# met its author: the receiving worker unpacks exactly the paths the manifest
# lists and nothing else. Two gates now grade a package against that set —
# check-zcode-package-standalone (does every shipped source COMPILE from the
# declared dependencies?) and check-package-capabilities (does the manifest
# name everything the shipped sources can REACH?). If those two disagreed
# about which files are shipped, one of them would be grading a set the node
# will never see. One function, two readers, no drift.
#
# THE RULE, in the order the manifest states it:
#   * a manifest declaring "files" is honoured EXACTLY — the array is the
#     shipped set, wherever in the tree its entries live. That is why this
#     enumerates files[] rather than globbing and filtering: contexts/commons/modules/commons_demo
#     ships app/main.c, which no src/ + tests/ glob can see, and a gate that
#     cannot see it cannot grade it.
#   * a manifest with no "files" ships its whole tree; the compilable part of
#     that is src/*.c plus tests/*.c, which is what the recipe compiles.
#
# A listed-but-absent path is PRINTED, not skipped. Skipping it would make a
# manifest that names a file it does not carry look like a smaller, cleaner
# package to every caller; letting it through makes the caller fail on it,
# which is the honest outcome. (contexts/commons/modules/vcs/src/package_prepare.c refuses such a
# manifest outright when it prepares the package for real.)
#
# HISTORY: this began as pkg_sources() private to
# tools/lint/check_zcode_package_standalone.sh, which globbed src/ + tests/
# and then narrowed to files[] by substring grep. Lifting it here widened it
# to honour files[] entries OUTSIDE src/ and tests/ — the only such entry in
# the registry today is contexts/commons/modules/commons_demo/app/main.c, which was verified to
# compile from its declared dependencies before the widening landed.

# zcode_pkg_json_array <manifest> <key>
#   Prints every string element of the top-level JSON array <key>, one per
#   line, in manifest order. Returns 0 if the key is PRESENT (even when the
#   array is empty and nothing is printed) and 1 if it is ABSENT.
#
#   "present but empty" and "absent" must not collapse: an empty
#   "capabilities" array is the most valuable value in the whole package
#   format — it says this package reaches NOTHING — and a reader that cannot
#   tell it from a missing field would treat "nobody wrote it down" as a
#   proof of inertness. The exit status is the only channel that can carry
#   that distinction when the output is legitimately empty.
zcode_pkg_json_array() {
    awk -v key="$2" '
        function emit(s,   line) {
            line = s
            while (match(line, /"[^"]*"/)) {
                print substr(line, RSTART + 1, RLENGTH - 2)
                line = substr(line, RSTART + RLENGTH)
            }
        }
        inarr {
            emit($0)
            if (index($0, "]")) inarr = 0
            next
        }
        index($0, "\"" key "\"") && match($0, /"[^"]*"[[:space:]]*:/) {
            found = 1
            rest = substr($0, RSTART + RLENGTH)
            b = index(rest, "[")
            if (b == 0) { inarr = 1; next }
            rest = substr(rest, b + 1)
            emit(rest)
            if (index(rest, "]") == 0) inarr = 1
            next
        }
        END { exit(found ? 0 : 1) }
    ' "$1"
}

# zcode_pkg_has_key <manifest> <key>  — true (0) iff <key> is a top-level key.
zcode_pkg_has_key() {
    LC_ALL=C grep -qE "^[[:space:]]*\"$2\"[[:space:]]*:" "$1"
}

# zcode_pkg_sources <pkg_dir>
#   Prints every C source the package SHIPS, one path per line, prefixed with
#   <pkg_dir> exactly as given (so a repo-relative dir yields repo-relative
#   paths). Returns 1 with no output if the manifest is missing.
zcode_pkg_sources() {
    local dir="$1" manifest="$1/zcode-package.json" f rel
    [ -f "$manifest" ] || return 1
    if zcode_pkg_has_key "$manifest" files; then
        while IFS= read -r rel; do
            case "$rel" in
                *.c) printf '%s\n' "$dir/$rel" ;;
            esac
        done < <(zcode_pkg_json_array "$manifest" files)
    else
        for f in "$dir"/src/*.c "$dir"/tests/*.c; do
            [ -e "$f" ] || continue
            printf '%s\n' "$f"
        done
    fi
    return 0
}
