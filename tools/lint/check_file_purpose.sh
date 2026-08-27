#!/usr/bin/env bash
# Gate P1 (docs/work/palace-design.md §3) — check-file-purpose: every indexed
# .c/.h under the codeindex roots yields a non-empty DERIVABLE one-line purpose,
# so `code file`/`code map` can describe a file without opening it.
#
# "Derivable" is the shell mirror of ci_file_purpose()
# (lib/codeindex/src/codeindex_scan.c:194-268): a block comment must precede the
# first code token; within it, Copyright/license lines and blank `*` fill are
# skipped; a file PASSES if a substantive comment line exists OR an explicit
# `purpose:` override line exists. We check DERIVABILITY only — the extractor's
# stem-prefix-stripping cosmetics are irrelevant to whether a purpose exists.
#
# Mode: WARN | RATCHET | FAIL (controlled by ZCL_LINT_MODE; default WARN),
# modeled on tools/lint/check_group_purpose.sh + framework_shape_check.sh:
#   WARN    — report violations, always exit 0 (measurement).
#   RATCHET — fail only on violations NOT in file_purpose_baseline.txt.
#   FAIL    — fail on ANY violation, baseline ignored.
# Rollout is WARN→RATCHET→HARD with a shrink-only baseline (see palace-design
# §3, Gate P1), identical to framework_shape_allowlist.txt semantics.
set -euo pipefail
# ASCII source scans: pin the locale so BSD awk never trips on high bytes.
export LC_ALL=C

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source "$SCRIPT_DIR/gate_lib.sh"
# shellcheck source=tools/lint/repo_shape.sh
source "$SCRIPT_DIR/repo_shape.sh"

MODE="${ZCL_LINT_MODE:-WARN}"
# ZCL_FILE_PURPOSE_ROOT overrides the base directory whose codeindex roots are
# enumerated — test isolation only (test_make_lint_gates points this at a tiny
# fixture tree so the self-test never scans the real codebase). Unset in
# production. Mirrors ZCL_GROUP_PURPOSE_SRC in check_group_purpose.sh.
SCAN_ROOT="${ZCL_FILE_PURPOSE_ROOT:-.}"
BASELINE="$SCRIPT_DIR/file_purpose_baseline.txt"

[[ -d "$SCAN_ROOT" ]] || { echo "check_file_purpose: FATAL — missing scan root $SCAN_ROOT" >&2; exit 2; }

# ── the enumerated roots — a MIRROR of ci_enumerate_sources()
# (lib/codeindex/src/codeindex_build.c:111). Keep this list in lockstep with
# that function: lib/<mod>/{src,include} for each k_lib_modules[] module,
# app/<shape>/{src,include} for each k_app_shapes[] shape, then core,
# config/{src,include}, tools, domain, adapters (all recursive). Note: ports/
# is NOT enumerated there, so it is NOT scanned here either.

# Parse a (possibly line-continued) Makefile variable into a space list. The
# Both lists are DERIVED from the Makefile by repo_shape.sh — the build
# depends on LIB_MODULES and APP_DIRS, so they cannot rot without the build
# breaking. (Event is an eighth framework shape with no app/ folder of its
# own; see FRAMEWORK.md §3 row 7.)
lib_modules=("${ZCL_LIB_MODULES[@]}")
app_shapes=("${ZCL_APP_SHAPES[@]}")

gate_require_scanned "${#lib_modules[@]}" 1 check-file-purpose \
    "LIB_MODULES parse came back empty — Makefile layout changed?"

# Build the directory list, then find .c/.h under it.
scan_dirs=()
for m in "${lib_modules[@]}"; do
    scan_dirs+=("$SCAN_ROOT/lib/$m/src" "$SCAN_ROOT/lib/$m/include")
done
for s in "${app_shapes[@]}"; do
    scan_dirs+=("$SCAN_ROOT/app/$s/src" "$SCAN_ROOT/app/$s/include")
done
scan_dirs+=("$SCAN_ROOT/core" "$SCAN_ROOT/config/src" "$SCAN_ROOT/config/include" \
            "$SCAN_ROOT/tools" "$SCAN_ROOT/domain" "$SCAN_ROOT/adapters")

existing_dirs=()
for d in "${scan_dirs[@]}"; do
    [[ -d "$d" ]] && existing_dirs+=("$d")
done
gate_require_scanned "${#existing_dirs[@]}" 1 check-file-purpose \
    "none of the codeindex root dirs exist under $SCAN_ROOT — layout changed?"

# Collect files, stripping the "$SCAN_ROOT/" prefix so baseline keys are
# root-relative (e.g. lib/bloom/src/bloom.c).
prefix="$SCAN_ROOT/"
mapfile -t files < <(
    find "${existing_dirs[@]}" -type f \( -name '*.c' -o -name '*.h' \) \
        -not -path '*/build/*' 2>/dev/null | sort -u |
    while IFS= read -r f; do printf '%s\n' "${f#"$prefix"}"; done
)

# Floor: the real tree carries ~1900 indexed sources; refuse to report clean off
# a hollow scan. Under test isolation (override set) a tiny fixture tree is
# expected, so relax the floor to 1.
if [[ -n "${ZCL_FILE_PURPOSE_ROOT:-}" ]]; then FLOOR=1; else FLOOR=1500; fi
gate_require_scanned "${#files[@]}" "$FLOOR" check-file-purpose \
    "the codeindex-root .c/.h scan came back too small — a scanned dir moved?"

# Is a file's leading comment substantive (a derivable purpose)? Mirror of
# ci_file_purpose(): block/line comment must precede the first code token; skip
# Copyright + blank `*` fill; `purpose:` override or any other non-empty line
# is substantive. Exit 0 = derivable (PASS), 1 = not derivable (violation).
file_is_derivable() {
    awk '
        function consider(b,  t) {
            t=b; gsub(/\r/,"",t)
            sub(/^[ \t*]+/,"",t); sub(/[ \t*]+$/,"",t)
            if (t=="") return 0                               # blank fill
            if (tolower(substr(t,1,8))=="purpose:") return 1  # explicit override
            if (tolower(substr(t,1,9))=="copyright") return 0 # skip license line
            return 1                                          # substantive
        }
        BEGIN { started=0; verdict=0 }
        {
            line=$0; sub(/^[ \t]+/,"",line); sub(/\r$/,"",line)
            if (!started) {
                if (line=="") next
                if (substr(line,1,2)=="/*") {
                    started=1; block=1; incomment=1; rest=substr(line,3)
                    if (index(rest,"*/")>0) { sub(/\*\/.*$/,"",rest); incomment=0 }
                    if (consider(rest)==1) { verdict=1; exit }
                    next
                }
                if (substr(line,1,2)=="//") {
                    started=1; block=0; rest=substr(line,3)
                    if (consider(rest)==1) { verdict=1; exit }
                    next
                }
                verdict=0; exit                               # code before comment
            }
            if (block==1) {
                if (incomment==0) exit                        # block closed, nothing found
                rest=line; hadclose=(index(rest,"*/")>0)
                if (hadclose) sub(/\*\/.*$/,"",rest)
                if (consider(rest)==1) { verdict=1; exit }
                if (hadclose) incomment=0
                next
            } else {
                if (substr(line,1,2)=="//") {
                    rest=substr(line,3)
                    if (consider(rest)==1) { verdict=1; exit }
                    next
                }
                exit                                          # end of // run
            }
        }
        END { if (verdict==1) exit 0; exit 1 }
    ' "$1"
}

declare -A ALLOWED=()
gate_load_list_file "$BASELINE" ALLOWED

scanned=0
violations=0
allowlisted=0
for f in "${files[@]}"; do
    scanned=$((scanned + 1))
    if file_is_derivable "$SCAN_ROOT/$f"; then
        continue
    fi
    if [[ "$MODE" != "FAIL" && -n "${ALLOWED[$f]:-}" ]]; then
        allowlisted=$((allowlisted + 1))
        continue
    fi
    violations=$((violations + 1))
    echo "$f: no derivable file purpose — add a top-of-file comment line (or a '/* purpose: ... */' override)" >&2
done

gate_require_scanned "$scanned" "${#files[@]}" check-file-purpose \
    "the per-file scan loop ran fewer iterations than the file list"

echo "[check_file_purpose] scanned $scanned source file(s) under $SCAN_ROOT"
echo "[check_file_purpose] $violations violation(s) found (mode: $MODE)"
if (( allowlisted > 0 )); then
    echo "[check_file_purpose] $allowlisted allowlisted violation(s) ignored"
fi
if (( violations > 0 )); then
    echo "[check_file_purpose] add the one-line purpose, or (shrink-only) write to tools/lint/file_purpose_baseline.txt"
fi

fail=0
if (( violations > 0 )) && [[ "$MODE" == "FAIL" || "$MODE" == "RATCHET" ]]; then
    fail=1
fi
exit "$fail"
