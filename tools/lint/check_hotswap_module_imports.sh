#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_hotswap_module_imports.sh — a hot-swap module may import only what
# config/hotswap_module_imports.def allows.
#
# ── THE INVARIANT ──────────────────────────────────────────────────────────
# A Tier-2 hot-swap module is a .so compiled from ONE shape-leaf TU and
# dlopen'd into the LIVE node's address space. Every body it does not define
# itself is resolved out of the resident image at load time. So the module's
# UNDEFINED dynamic-symbol set IS its complete interface to the node — a
# device-driver contract, mechanically derivable from the artifact, and until
# this gate existed, enforced nowhere.
#
# That absence was reachable. None of the existing hot-swap gates looks at
# what a module LINKS AGAINST: check-hotswap-swappable-shape checks the TU's
# PATH and its leaves' READY/read-only spec, check-hotswap-static-state checks
# mutable file-scope statics, check-core-seal-root-mirror checks the sealed
# consensus pin, check-hotswap-package-receipt-is-not-authority checks that
# admission re-derives its facts. A controller edit that added one `#include`
# and one call would acquire a door into the reducer, the coins view, the
# wallet spend path or chain state, pass all of them, and mount — with no diff
# a reviewer could read as a reach change, because the change is an #include.
#
# ── WHAT IS ASSERTED ───────────────────────────────────────────────────────
# Leg 1 (CONTRACT — always runs, needs no build artifacts, fail-closed):
#   * config/hotswap_module_imports.def exists and parses to >= IMPORT_FLOOR
#     rows. A gutted or unparseable allowlist is exit 2, never a pass: an
#     empty allowlist would make every module's import set "not allowed" and
#     an empty PARSE would make it "all allowed" depending on which way the
#     bug fell, and neither is something to guess at.
#   * No duplicate symbol rows.
#   * Every row's group is in the closed set declared in the .def header. A
#     row with an invented group is a row nobody classified.
#
# Leg 1b (CONTRACT — always runs, needs no build artifacts, fail-closed):
#   the allowlist above says a module may import a symbol; it never says
#   what that symbol can DO. `HOTSWAP_MODULE_IMPORT("socket", "LIBC")` would
#   pass leg 1 outright — the row is well-formed, the group is valid, and no
#   module has to import it yet for the row to sit there as a door. This leg
#   crosses every allowlisted symbol against config/capability_symbols.def
#   and FAILS the build if any of them carries CAP_NETWORK, CAP_PROCESS,
#   CAP_DYNLOAD, CAP_PRIVILEGE, or CAP_WALLET — reach a hot-swap module has
#   no business holding regardless of whether anything currently calls it.
#   Because "found nothing forbidden" and "the parser matched nothing" look
#   identical from outside, this leg also asserts a coverage floor
#   (CAPABILITY_CROSS_FLOOR): fewer than that many allowlisted symbols
#   resolving to a class in capability_symbols.def is exit 2 FATAL, not a
#   clean crossing. There is no waiver/exception path here on purpose — the
#   measured crossing is zero forbidden today, so none is needed, and an
#   unused waiver is a hole waiting to be used.
#
#
# Leg 1c (CONTRACT — always runs, needs no build artifacts, fail-closed):
#   leg 1b names five forbidden classes. config/capability_classes.def
#   declares nine. A hardcoded forbidden list over an open vocabulary is
#   default-PERMIT: add a tenth class to the class table and leg 1b lets it
#   onto the allowlist, because it is absent from a list of five and absence
#   reads as harmless. This leg reads the class table and requires every
#   class it declares to appear in FORBIDDEN_CAP_CLASSES or
#   PERMITTED_CAP_CLASSES, refusing (exit 2) when one appears in neither, so
#   adding a class forces a decision in THIS file instead of inheriting one
#   by omission. Same symmetry config/remote_command_classes.def uses. It
#   carries its own floor (CLASS_VOCAB_FLOOR) for the same reason leg 1b
#   does: a vocabulary that failed to parse must not read as one where every
#   class happened to be classified.
# Leg 2 (ARTIFACTS): every `*.so` under build/hotswap is read with
#   `nm -D --undefined-only`, the `@GLIBC_x.y.z` version suffix is stripped
#   (a glibc bump is a toolchain fact, not a widening of reach), and any name
#   absent from the allowlist FAILS, naming the module and the symbol.
#
# ── ZERO MODULES IS NOT A PASS — the deliberate choice, and why ────────────
# build/hotswap is a BUILD OUTPUT directory and is not tracked. Making a
# missing directory FATAL would make `make lint` red on every fresh clone and
# on every CI job that lints without building modules — a gate that cries wolf
# gets deleted, and then the invariant is enforced nowhere again. Making it a
# silent exit 0 is the failure mode this whole file exists to prevent.
#
# So the two cases are split on a sharp line:
#
#   build/hotswap DOES NOT EXIST  -> UNOBSERVED. Exit 0, but the word OK is
#       never printed for the artifact leg and the output says in full what
#       was and was not proven. Nothing was built, so there is nothing to
#       judge. This is honest, not vacuous: leg 1 still ran and still proved
#       the contract file itself is well-formed and non-empty, so the gate
#       never reports success without having checked something real.
#   build/hotswap EXISTS BUT HOLDS NO *.so  -> FATAL, exit 2. The producer
#       ran and emptied, or the artifact naming changed under us. That is
#       exactly the hollow-scan shape (see tools/lint/gate_lib.sh) and it must
#       be loud.
#
# In sandbox (--selftest) mode there is no UNOBSERVED path at all: the
# selftest always plants at least one clean module of its own, so an empty
# sandbox is FATAL and the trip/recover proof can never be vacuous.
#
# ── SHELL DISCIPLINE ───────────────────────────────────────────────────────
# `set -uo pipefail`, no `set -e`. A status-carrying `cmd | grep -q` INVERTS
# under pipefail in this tree (grep -q exits at the first match, the producer
# takes SIGPIPE, pipefail reports 141) — for a lint gate that means a FOUND
# VIOLATION reads as CLEAN. See tools/scripts/sh_str.sh. Every decision below
# either greps a FILE directly or captures output with `$(...)` and tests the
# captured STRING. `nm` is invoked un-piped so its own exit status is real.
# LC_ALL=C on every grep/sort.
#
# Usage:
#   tools/lint/check_hotswap_module_imports.sh
#   tools/lint/check_hotswap_module_imports.sh --selftest
#
# Env (selftest only; refused otherwise):
#   ZCL_HOTSWAP_IMPORTS_SELFTEST         marker naming this gate
#   ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR      module directory to scan instead of
#                                        build/hotswap; must live under $SCRATCH
#   ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE     allowlist file to read instead of
#                                        config/hotswap_module_imports.def;
#                                        must live under $SCRATCH
#   ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE capability table to read instead of
#                                        config/capability_symbols.def; must
#                                        live under $SCRATCH
#
# Exit: 0 clean (or UNOBSERVED artifact leg), 1 on a forbidden import or a
# malformed allowlist row, 2 when the gate could not look.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2
SELF="$SCRIPT_DIR/$(basename "${BASH_SOURCE[0]}")"

GATE="check_hotswap_module_imports"
DEF="config/hotswap_module_imports.def"
CAPFILE="config/capability_symbols.def"
SO_DIR="build/hotswap"
SCRATCH="$HOME/.local/state/zclassic23/scratch/lane-imports"

# The closed set of rationale groups. A row outside it is a row nobody
# classified, which is the same as an unreviewed widening.
VALID_GROUPS=" TOOLCHAIN LIBC JSON LOG NODE_COMMAND NODE_STATUS NODE_DB NODE_UTIL NODE_HOTSWAP NODE_APP "

# A floor, not a count. The allowlist was derived from 93 real artifacts and
# holds 282 rows; shrinking it is always legitimate (it is a ceiling), but a
# drop below this means the file was gutted or the parser stopped matching,
# and neither may be reported as clean.
IMPORT_FLOOR=100

# Capability classes a hot-swap module's allowlist may never contain, under
# any group and whether or not anything currently imports the symbol: the
# allowlist itself is the widening, not just what a module takes from it.
#
# ⛔ THESE TWO LISTS MUST BETWEEN THEM COVER EVERY CLASS config/
# capability_classes.def DECLARES. A hardcoded FORBIDDEN list alone is
# default-PERMIT on an open vocabulary: add a tenth class to the class table
# and it is silently allowed here, because it is absent from a list of five.
# check_class_vocabulary() below refuses when a declared class appears in
# neither list, so adding a class forces a decision in THIS file rather than
# inheriting one by omission. That is the same symmetry
# config/remote_command_classes.def uses for command leaves.
FORBIDDEN_CAP_CLASSES=" CAP_NETWORK CAP_PROCESS CAP_DYNLOAD CAP_PRIVILEGE CAP_WALLET "

# The other half of the vocabulary: classes a module may hold. CAP_HARMLESS is
# not a row in the class table (it is the sentinel for "reaches nothing worth
# classing"), so it is named here explicitly rather than derived.
PERMITTED_CAP_CLASSES=" CAP_HARMLESS CAP_FS_READ CAP_FS_WRITE CAP_CLOCK CAP_RANDOM "

# The class table itself, read so the vocabulary check has something to check
# AGAINST. A gate that derived the vocabulary from the symbol file alone could
# only ever see classes already in use.
CLASSFILE="config/capability_classes.def"

# Hollowness guard for the class table: it declares nine classes today and a
# parse that returns fewer than this did not read the table.
CLASS_VOCAB_FLOOR=5

# A hollowness guard, not a target. "Zero forbidden symbols" and "the parser
# matched nothing" print identically unless something asserts a floor on how
# many allowlisted symbols actually resolved to a class. Measured on this
# tree: 289 allowlisted, 45+ resolve. This floor is set well below that so
# legitimate ceiling-trimming never trips it, while a parser that stopped
# matching (or a capability table that stopped resolving) still does.
CAPABILITY_CROSS_FLOOR=30

SANDBOX=0
if [ -n "${ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR:-}" ]; then
    # Honored ONLY for a re-invocation from run_selftest, which sets the
    # marker. Without this check a stray environment variable would redirect a
    # REAL `make lint` scan at a directory of the setter's choosing — the
    # "green gate that checked nothing" shape this file exists to prevent.
    if [ "${ZCL_HOTSWAP_IMPORTS_SELFTEST:-}" != "$GATE" ]; then
        echo "$GATE: FATAL — ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR is set outside --selftest; refusing to scan anywhere but $SO_DIR" >&2
        exit 2
    fi
    case "$ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR" in
        "$SCRATCH"/*) ;;
        *)
            echo "$GATE: FATAL — sandbox dir must live under $SCRATCH, got: $ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR" >&2
            exit 2
            ;;
    esac
    SO_DIR="$ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR"
    SANDBOX=1
    echo "$GATE: SANDBOX module dir (selftest only): $SO_DIR"
fi

if [ -n "${ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE:-}" ]; then
    # Same guard, same reason: without the selftest marker a stray env var
    # would let a real `make lint` scan judge modules against an allowlist
    # nobody reviewed.
    if [ "${ZCL_HOTSWAP_IMPORTS_SELFTEST:-}" != "$GATE" ]; then
        echo "$GATE: FATAL — ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE is set outside --selftest; refusing to read anywhere but $DEF" >&2
        exit 2
    fi
    case "$ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE" in
        "$SCRATCH"/*) ;;
        *)
            echo "$GATE: FATAL — allowlist override must live under $SCRATCH, got: $ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE" >&2
            exit 2
            ;;
    esac
    DEF="$ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE"
    echo "$GATE: SANDBOX allowlist file (selftest only): $DEF"
fi

if [ -n "${ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE:-}" ]; then
    if [ "${ZCL_HOTSWAP_IMPORTS_SELFTEST:-}" != "$GATE" ]; then
        echo "$GATE: FATAL — ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE is set outside --selftest; refusing to read anywhere but $CAPFILE" >&2
        exit 2
    fi
    case "$ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE" in
        "$SCRATCH"/*) ;;
        *)
            echo "$GATE: FATAL — capability table override must live under $SCRATCH, got: $ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE" >&2
            exit 2
            ;;
    esac
    CAPFILE="$ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE"
    echo "$GATE: SANDBOX capability table (selftest only): $CAPFILE"
fi

fail=0
bad() { printf '%s: FAIL — %s\n' "$GATE" "$1" >&2; fail=1; }
note() { printf '  %s\n' "$1"; }

# ── leg 1: the contract file itself ────────────────────────────────────────
declare -A ALLOWED=()
declare -A GROUP_OF=()
ALLOWED_N=0

# ── leg 1b: what the contract's symbols REACH ──────────────────────────────
declare -A CAP_CLASS_OF=()

load_allowlist() {
    if [ ! -f "$DEF" ]; then
        echo "$GATE: FATAL — allowlist $DEF does not exist. The import contract cannot be checked against a file that is not there; refusing to report clean." >&2
        exit 2
    fi

    # grep a FILE directly (no pipe carrying a decision), capture the STRING.
    local rows rc
    rows="$(LC_ALL=C grep -oE '^[[:space:]]*HOTSWAP_MODULE_IMPORT\("[^"]+"[[:space:]]*,[[:space:]]*"[^"]+"\)' "$DEF" 2>/dev/null)"
    rc=$?
    if [ "$rc" -ge 2 ]; then
        echo "$GATE: FATAL — grep failed (exit $rc) reading $DEF; refusing to report clean off a broken scan." >&2
        exit 2
    fi
    if [ -z "${rows//[[:space:]]/}" ]; then
        echo "$GATE: FATAL — $DEF parsed to ZERO HOTSWAP_MODULE_IMPORT rows." >&2
        echo "  Either the file was gutted or its row shape changed and this" >&2
        echo "  parser no longer matches it. An empty parse is not an empty" >&2
        echo "  contract; it is an unreadable one." >&2
        exit 2
    fi

    local line sym grp rest dupes=""
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        rest="${line#*\"}"          # sym", "GRP")
        sym="${rest%%\"*}"
        rest="${line#*,}"           #  , "GRP")
        rest="${rest#*\"}"
        grp="${rest%%\"*}"
        if [ -z "$sym" ] || [ -z "$grp" ]; then
            bad "unparseable allowlist row in $DEF: $line"
            continue
        fi
        case "$VALID_GROUPS" in
            *" $grp "*) ;;
            *)
                bad "allowlist row for '$sym' carries group '$grp', which is not one of the declared groups ($VALID_GROUPS). A row nobody classified is an unreviewed widening."
                continue
                ;;
        esac
        if [ -n "${ALLOWED[$sym]:-}" ]; then
            dupes="$dupes $sym"
            continue
        fi
        ALLOWED["$sym"]=1
        GROUP_OF["$sym"]="$grp"
        ALLOWED_N=$((ALLOWED_N + 1))
    done <<< "$rows"

    if [ -n "${dupes// /}" ]; then
        bad "duplicate symbol row(s) in $DEF:$dupes"
    fi

    if [ "$ALLOWED_N" -lt "$IMPORT_FLOOR" ]; then
        echo "$GATE: FATAL — allowlist holds $ALLOWED_N row(s), below the floor of $IMPORT_FLOOR." >&2
        echo "  $DEF was derived from the real undefined-symbol union of every" >&2
        echo "  built module; a drop this far means it was gutted or the parser" >&2
        echo "  stopped matching. Refusing to judge modules against it." >&2
        exit 2
    fi

    [ "$fail" -eq 0 ] || return 1
    note "contract  : OK — $ALLOWED_N allowlisted import(s) in $DEF, all classified, no duplicates"
    return 0
}

# Parses $CAPFILE into CAP_CLASS_OF[symbol]=CAP_xxx. Handles the row shape
# where the class sits on the SAME physical line as the symbol (the common
# case) and the shape where a long symbol name pushes the class onto a
# CONTINUATION line (measured: 7 of 547 rows in this tree today, e.g.
# secp256k1_ecdsa_recoverable_signature_parse_compact). A naive single-line
# grep silently drops the continuation rows; this walks forward from a row
# that opens ZCL_CAPABILITY_SYMBOL( until it finds a CAP_ token, stopping (and
# refusing) if it runs into the NEXT row's opener or EOF first. A row that
# cannot be assigned a class is a row this gate cannot judge, so that is
# exit 2 FATAL, never a silent skip.
load_capability_classes() {
    CAP_CLASS_OF=()

    if [ ! -f "$CAPFILE" ]; then
        echo "$GATE: FATAL — capability table $CAPFILE does not exist. The allowlist cannot be crossed against reach classes for a file that is not there; refusing to report clean." >&2
        exit 2
    fi

    local expect_n rc
    expect_n="$(LC_ALL=C grep -c -E '^[[:space:]]*ZCL_CAPABILITY_SYMBOL\(' "$CAPFILE" 2>/dev/null)"
    rc=$?
    if [ "$rc" -ge 2 ]; then
        echo "$GATE: FATAL — grep failed (exit $rc) reading $CAPFILE; refusing to cross off a broken scan." >&2
        exit 2
    fi
    expect_n="${expect_n:-0}"
    if [ "$expect_n" -eq 0 ]; then
        echo "$GATE: FATAL — $CAPFILE parsed to ZERO ZCL_CAPABILITY_SYMBOL rows." >&2
        echo "  Either the file was gutted or its row shape changed and this" >&2
        echo "  parser no longer matches it. Refusing to cross the import" >&2
        echo "  allowlist against a capability table that read as empty." >&2
        exit 2
    fi

    local lines=()
    mapfile -t lines < "$CAPFILE"
    local total=${#lines[@]}
    local i=0 j look line sym cls parsed=0 unparsed=""
    while [ "$i" -lt "$total" ]; do
        line="${lines[$i]}"
        if [[ "$line" =~ ^[[:space:]]*ZCL_CAPABILITY_SYMBOL\( ]]; then
            sym=""
            if [[ "$line" =~ \"([^\"]+)\" ]]; then
                sym="${BASH_REMATCH[1]}"
            fi
            cls=""
            if [[ "$line" =~ (CAP_[A-Z_]+) ]]; then
                cls="${BASH_REMATCH[1]}"
            else
                j=$((i + 1))
                while [ "$j" -lt "$total" ]; do
                    look="${lines[$j]}"
                    if [[ "$look" =~ ^[[:space:]]*ZCL_CAPABILITY_SYMBOL\( ]]; then
                        break
                    fi
                    if [[ "$look" =~ (CAP_[A-Z_]+) ]]; then
                        cls="${BASH_REMATCH[1]}"
                        break
                    fi
                    j=$((j + 1))
                done
            fi
            if [ -z "$sym" ] || [ -z "$cls" ]; then
                unparsed="$unparsed
    line $((i + 1)): $line"
            else
                CAP_CLASS_OF["$sym"]="$cls"
                parsed=$((parsed + 1))
            fi
        fi
        i=$((i + 1))
    done

    if [ -n "${unparsed//[[:space:]]/}" ]; then
        echo "$GATE: FATAL — $CAPFILE holds ZCL_CAPABILITY_SYMBOL row(s) this gate could not assign a class to:$unparsed" >&2
        echo "  A row it cannot parse is a row it cannot judge; refusing to cross the" >&2
        echo "  import allowlist against an incompletely-read capability table." >&2
        exit 2
    fi

    if [ "$parsed" -ne "$expect_n" ]; then
        echo "$GATE: FATAL — parsed $parsed ZCL_CAPABILITY_SYMBOL row(s) but $CAPFILE holds $expect_n; refusing to report a crossing off a partial parse." >&2
        exit 2
    fi
}

# ── leg 1b: cross the allowlist against capability_symbols.def ────────────
# Crosses every symbol in ALLOWED (populated by load_allowlist, which runs
# first) against CAP_CLASS_OF. No exception/waiver mechanism exists here on
# purpose: the crossing is zero forbidden today, so none is needed, and an
# unused waiver is a hole nobody would notice opening. If a future symbol
# legitimately needs one, whoever adds that row writes the mechanism then.
# ── the vocabulary check: no class may be permitted by omission ────────────
# Reads every class config/capability_classes.def declares and requires each
# to appear in FORBIDDEN_CAP_CLASSES or PERMITTED_CAP_CLASSES. A class in
# neither is refused: the alternative is that a class added to the table after
# this gate was written is treated as harmless here, which is the
# default-permit shape the whole capability system exists to avoid.
#
# Honoured overrides are selftest-only and guarded exactly like the others.
check_class_vocabulary() {
    local classfile="$CLASSFILE"
    if [ -n "${ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE:-}" ]; then
        if [ "${ZCL_HOTSWAP_IMPORTS_SELFTEST:-}" != "$GATE" ]; then
            echo "$GATE: FATAL — ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE is set outside --selftest" >&2
            exit 2
        fi
        case "$ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE" in
            "$SCRATCH"/*) ;;
            *)
                echo "$GATE: FATAL — ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE must live under $SCRATCH" >&2
                exit 2
                ;;
        esac
        classfile="$ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE"
    fi

    if [ ! -f "$classfile" ]; then
        echo "$GATE: FATAL — $classfile is missing; the class vocabulary cannot be checked." >&2
        exit 2
    fi

    # Anchored: the macro is also named inside this file's own doc comment,
    # and an unanchored match counts that comment as a row.
    local classes
    classes="$(LC_ALL=C grep -oE '^[[:space:]]*ZCL_CAPABILITY_CLASS\([[:space:]]*[A-Z_]+' "$classfile" \
        | LC_ALL=C sed 's/.*(\s*//' | LC_ALL=C sort -u)"

    local n=0 c
    # printf '%s\n' — a bare '%s' leaves the final line unterminated and `read`
    # silently drops it, which here would mean the LAST class is never checked.
    while IFS= read -r c; do
        [ -n "$c" ] || continue
        n=$((n + 1))
        local tok="CAP_$c"
        case "$FORBIDDEN_CAP_CLASSES$PERMITTED_CAP_CLASSES" in
            *" $tok "*) ;;
            *)
                echo "$GATE: FATAL — $classfile declares $tok, which this gate classifies neither way." >&2
                echo "  A hot-swap module's import allowlist is checked against a CLOSED vocabulary." >&2
                echo "  A class this file does not name is a class permitted by omission." >&2
                echo "  Decide, in tools/lint/check_hotswap_module_imports.sh:" >&2
                echo "    - can a hot-swapped module hold $tok?  add it to PERMITTED_CAP_CLASSES" >&2
                echo "    - can it not?                          add it to FORBIDDEN_CAP_CLASSES" >&2
                exit 2
                ;;
        esac
    done < <(printf '%s\n' "$classes")

    if [ "$n" -lt "$CLASS_VOCAB_FLOOR" ]; then
        echo "$GATE: FATAL — parsed only $n class(es) from $classfile (floor $CLASS_VOCAB_FLOOR)." >&2
        echo "  Refusing to judge the allowlist against a vocabulary that did not load." >&2
        exit 2
    fi
    CLASS_VOCAB_N="$n"
    return 0
}

check_capability_crossing() {
    load_capability_classes

    local sym cls resolved=0 forbidden_rows=""
    local -A class_count=()
    for sym in "${!ALLOWED[@]}"; do
        cls="${CAP_CLASS_OF[$sym]:-}"
        [ -n "$cls" ] || continue
        resolved=$((resolved + 1))
        class_count["$cls"]=$(( ${class_count["$cls"]:-0} + 1 ))
        case "$FORBIDDEN_CAP_CLASSES" in
            *" $cls "*)
                forbidden_rows="$forbidden_rows
    $sym  carries $cls"
                ;;
        esac
    done

    if [ "$resolved" -lt "$CAPABILITY_CROSS_FLOOR" ]; then
        echo "$GATE: FATAL — only $resolved of $ALLOWED_N allowlisted import(s) resolved to a class in $CAPFILE, below the coverage floor of $CAPABILITY_CROSS_FLOOR." >&2
        echo "  A crossing that resolves almost nothing prints the same result as a" >&2
        echo "  crossing whose parser matched nothing. Refusing to report either the" >&2
        echo "  presence or the absence of a forbidden capability off a scan this thin" >&2
        echo "  — the crossing could not be meaningfully performed." >&2
        exit 2
    fi

    if [ -n "${forbidden_rows//[[:space:]]/}" ]; then
        bad "allowlisted import(s) in $DEF carry a FORBIDDEN capability class:$forbidden_rows"
        {
            echo ""
            echo "  $DEF is the closed set of what a hot-swap module may import from the"
            echo "  resident node. A symbol that reaches the network, spawns a process,"
            echo "  loads code, changes privilege, or touches the wallet does not belong"
            echo "  in a module's interface at all — the allowlist row itself is the"
            echo "  widening, whether or not any module currently imports it."
            echo ""
            echo "  Remove the row from $DEF. The call belongs in the resident node behind"
            echo "  an existing NODE_COMMAND door, not imported into the module; if the"
            echo "  honest answer is that the module needs it, that door is designed and"
            echo "  reviewed then, not pre-opened here."
        } >&2
        return 1
    fi

    note "crossing  : OK — $resolved/$ALLOWED_N allowlisted import(s) resolved to a capability class in $CAPFILE (harmless=${class_count[CAP_HARMLESS]:-0} fs_read=${class_count[CAP_FS_READ]:-0} fs_write=${class_count[CAP_FS_WRITE]:-0} clock=${class_count[CAP_CLOCK]:-0} random=${class_count[CAP_RANDOM]:-0}) over a ${CLASS_VOCAB_N}-class closed vocabulary; zero forbidden (network/process/dynload/privilege/wallet)"
    return 0
}

# ── leg 2: the artifacts ───────────────────────────────────────────────────
# Returns 0 clean, 1 violation, 3 UNOBSERVED (nothing built). Exits 2 itself
# on a hollow scan.
SCANNED_SO=0
declare -A SEEN_IMPORT=()

canonical_import_symbol() {
    local raw="$1"
    local host_os="$2"
    CANONICAL_IMPORT_SYMBOL="$raw"
    if [ "$host_os" = "Darwin" ]; then
        # Mach-O adds exactly one underscore to the C linkage name. Removing
        # more would turn a distinct private/runtime symbol into an allowed
        # import. The dyld binder is loader plumbing rather than module reach.
        CANONICAL_IMPORT_SYMBOL="${raw#_}"
        if [ "$CANONICAL_IMPORT_SYMBOL" = "dyld_stub_binder" ]; then
            CANONICAL_IMPORT_SYMBOL=""
        fi
    fi
}

scan_modules() {
    if [ ! -d "$SO_DIR" ]; then
        if [ "$SANDBOX" -eq 1 ]; then
            echo "$GATE: FATAL — sandbox module dir $SO_DIR does not exist" >&2
            exit 2
        fi
        return 3
    fi

    local sos=()
    local f
    for f in "$SO_DIR"/*.so; do
        [ -f "$f" ] || continue
        sos+=("$f")
    done

    if [ "${#sos[@]}" -eq 0 ]; then
        # The directory EXISTS and holds no module. The producer ran and
        # emptied, or the artifact naming changed. Hollow scan: loud, never a
        # quiet pass. (A never-built tree has no directory at all and takes
        # the UNOBSERVED path above.)
        echo "$GATE: FATAL — $SO_DIR exists but contains no *.so module." >&2
        echo "  A module directory that is present and empty is a producer that" >&2
        echo "  ran and emitted nothing, or an artifact name this gate no longer" >&2
        echo "  matches. Either way the import contract would be 'proven' against" >&2
        echo "  zero artifacts. Refusing." >&2
        exit 2
    fi

    local nm_out nm_rc line sym mod bad_rows=""
    if ! command -v nm >/dev/null 2>&1; then
        echo "$GATE: FATAL — nm(1) is not on PATH; the undefined-symbol set cannot be read" >&2
        exit 2
    fi

    for f in "${sos[@]}"; do
        mod="$(basename "$f")"
        # nm is NOT in a pipeline: its exit status is a real decision here.
        # `nm -u` (undefined-only) works on both GNU binutils and BSD nm;
        # `-D` (dynamic symbols) is GNU-only, so try the exact contract read
        # first and fall back to the portable undefined-only read.
        nm_out="$(nm -D --undefined-only "$f" 2>/dev/null)" && nm_rc=0 || nm_rc=$?
        if [ "$nm_rc" -ne 0 ]; then
            nm_out="$(nm -u "$f" 2>&1)"
            nm_rc=$?
        fi
        if [ "$nm_rc" -ne 0 ]; then
            bad "cannot read dynamic symbols of $mod (nm exit $nm_rc): $nm_out"
            continue
        fi
        SCANNED_SO=$((SCANNED_SO + 1))
        while IFS= read -r line; do
            [ -n "${line//[[:space:]]/}" ] || continue
            sym="${line##* }"      # trailing field is the symbol name
            sym="${sym%%@*}"       # drop the @GLIBC_x.y.z version half
            [ -n "$sym" ] || continue
            canonical_import_symbol "$sym" "$(uname -s)"
            probe_sym="$CANONICAL_IMPORT_SYMBOL"
            SEEN_IMPORT["$sym"]=1
            if [ -n "$probe_sym" ]; then
                SEEN_IMPORT["$probe_sym"]=1
            fi
            if [ -n "$probe_sym" ] && [ -z "${ALLOWED[$sym]:-}" ] &&
               [ -z "${ALLOWED[$probe_sym]:-}" ]; then
                bad_rows="$bad_rows
    $mod  imports  $sym"
            fi
        done <<< "$nm_out"
    done

    if [ "$SCANNED_SO" -eq 0 ]; then
        echo "$GATE: FATAL — found ${#sos[@]} module file(s) but read the symbols of none of them" >&2
        exit 2
    fi

    if [ -n "${bad_rows//[[:space:]]/}" ]; then
        bad "module(s) import symbol(s) that are NOT on the declared contract:$bad_rows"
        {
            echo ""
            echo "  A hot-swap module runs inside the live node. Its UNDEFINED symbol set"
            echo "  is its whole reach into the resident image, so an import that nobody"
            echo "  declared is reach that nobody reviewed."
            echo ""
            echo "  If the new call is legitimate: add a row to $DEF under the group that"
            echo "  explains WHY it is allowed, and say in the commit message which door"
            echo "  you opened and why the leaf behind it still cannot misreport or mutate"
            echo "  anything a reader trusts."
            echo "  If the honest answer is that it can: do not import it. Move the call"
            echo "  into the resident and reach it through an existing NODE_COMMAND door."
        } >&2
        return 1
    fi
    return 0
}

# Informational only. A declared-but-unimported row is dead widening, not a
# violation — it grants reach nothing currently takes. Worth surfacing so the
# ceiling can be trimmed; never worth failing on, because a legitimate module
# rebuild routinely drops symbols.
report_unused() {
    local unused=0 sym
    for sym in "${!ALLOWED[@]}"; do
        [ -n "${SEEN_IMPORT[$sym]:-}" ] || unused=$((unused + 1))
    done
    if [ "$unused" -gt 0 ]; then
        note "unused    : $unused allowlisted import(s) are not taken by any built module (dead ceiling; safe to trim, not a violation)"
    fi
}

run_checks() {
    fail=0
    load_allowlist
    check_class_vocabulary
    check_capability_crossing
    local contract_fail="$fail"

    local art_rc=0
    scan_modules || art_rc=$?

    if [ "$contract_fail" -ne 0 ]; then
        echo "$GATE: the import contract file is malformed; module imports were not judged against it." >&2
        return 1
    fi

    if [ "$art_rc" -eq 3 ]; then
        echo "$GATE: UNOBSERVED (artifact leg) — $SO_DIR does not exist, so no module .so was examined."
        note "This is NOT a clean bill of health for any module. Nothing was built,"
        note "so nothing was judged. The contract leg above DID run and did prove"
        note "$DEF is well-formed and holds $ALLOWED_N classified rows."
        note "Build modules (make hotswap ...) and re-run to exercise the artifact leg."
        echo "$GATE: contract OK, artifacts UNOBSERVED"
        return 0
    fi

    if [ "$art_rc" -ne 0 ] || [ "$fail" -ne 0 ]; then
        return 1
    fi

    report_unused
    note "artifacts : OK — $SCANNED_SO module .so in $SO_DIR, every undefined symbol declared"
    echo "$GATE: OK — $SCANNED_SO module(s) checked against $ALLOWED_N declared imports in $DEF; no undeclared reach into the node"
    return 0
}

# ── self-test: prove the gate trips, then recovers ────────────────────────
# Nothing is written into the repository. `make lint` runs ~156 gates
# concurrently under -j24 and several of them glob the tree; a fixture that
# exists in build/hotswap for the length of two scans races them, and a
# concurrent build would try to consume it. So the selftest builds its OWN
# module directory in scratch and points the gate at the COPY.
run_selftest() {
    canonical_import_symbol "_memcpy" "Darwin"
    [ "$CANONICAL_IMPORT_SYMBOL" = "memcpy" ] || {
        echo "$GATE: selftest FATAL — Mach-O C-name normalization failed" >&2
        exit 2
    }
    canonical_import_symbol "___memcpy_chk" "Darwin"
    [ "$CANONICAL_IMPORT_SYMBOL" = "__memcpy_chk" ] || {
        echo "$GATE: selftest FATAL — Mach-O normalization widened a private symbol" >&2
        exit 2
    }
    canonical_import_symbol "_dyld_stub_binder" "Darwin"
    [ -z "$CANONICAL_IMPORT_SYMBOL" ] || {
        echo "$GATE: selftest FATAL — dyld loader plumbing was not isolated" >&2
        exit 2
    }

    mkdir -p "$SCRATCH" || {
        echo "$GATE: selftest FATAL — cannot create scratch dir $SCRATCH" >&2
        exit 2
    }
    # Unique per run: a fixed path plus rm -rf means two concurrent --selftest
    # runs (two lanes, or two worktrees sharing $HOME) delete each other's
    # sandbox mid-scan.
    local sandbox
    sandbox="$(mktemp -d "$SCRATCH/sandbox.XXXXXX")" || {
        echo "$GATE: selftest FATAL — cannot create sandbox under $SCRATCH" >&2
        exit 2
    }

    if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
        echo "$GATE: selftest FATAL — no C compiler on PATH; cannot build the fixture modules" >&2
        rm -rf "$sandbox"
        exit 2
    fi
    local CC; CC="$(command -v cc || command -v gcc)"

    # A CLEAN module of our own, so the sandbox is never empty regardless of
    # whether this checkout has ever built a real one. Its imports are all
    # allowlisted (LIBC + JSON), so a clean baseline is meaningful.
    cat > "$sandbox/clean_fixture.c" <<'CLEANEOF'
/* Built ONLY by check_hotswap_module_imports.sh --selftest, into a scratch
 * sandbox — never into build/hotswap and never into the repo. Its imports are
 * deliberately all on the declared contract so the sandbox baseline is clean. */
#include <stdlib.h>
#include <string.h>
extern void *json_init(void);
void *zcl_selftest_clean_leaf(const char *s);
void *zcl_selftest_clean_leaf(const char *s) {
    if (s == NULL || strlen(s) == 0u) { return NULL; }
    char *copy = (char *)malloc(strlen(s) + 1u);
    if (copy == NULL) { return NULL; }
    memcpy(copy, s, strlen(s) + 1u);
    free(copy);
    return json_init();
}
CLEANEOF
    # A module that reaches somewhere nobody declared.
    cat > "$sandbox/violating_fixture.c" <<'BADEOF'
/* Built ONLY by check_hotswap_module_imports.sh --selftest, into a scratch
 * sandbox. It imports an undeclared node entry point on purpose and is
 * deleted before this script returns. It must never survive a run. */
extern int zcl_selftest_undeclared_node_reach(int height);
int zcl_selftest_violating_leaf(void);
int zcl_selftest_violating_leaf(void) { return zcl_selftest_undeclared_node_reach(1); }
BADEOF

    local clean_so="$sandbox/zcl_selftest_clean.so"
    local bad_so="$sandbox/zcl_selftest_violating.so"
    local cc_out
    # The fixtures deliberately import symbols that only the resident image
    # provides. GNU ld allows unresolved symbols in -shared by default; ld64
    # requires -undefined dynamic_lookup for the same semantic.
    local undef_flags=""
    [[ "$(uname -s)" == "Darwin" ]] && undef_flags="-undefined dynamic_lookup"
    cc_out="$("$CC" -shared -fPIC -O0 $undef_flags -o "$clean_so" "$sandbox/clean_fixture.c" 2>&1)"
    if [ ! -f "$clean_so" ]; then
        echo "$GATE: selftest FATAL — could not build the clean fixture module: $cc_out" >&2
        rm -rf "$sandbox"
        exit 2
    fi
    cc_out="$("$CC" -shared -fPIC -O0 $undef_flags -o "$bad_so" "$sandbox/violating_fixture.c" 2>&1)"
    if [ ! -f "$bad_so" ]; then
        echo "$GATE: selftest FATAL — could not build the violating fixture module: $cc_out" >&2
        rm -rf "$sandbox"
        exit 2
    fi
    mv "$bad_so" "$sandbox/violating.so.parked"

    # Mirror the real modules in too when this checkout has them, so the
    # sandbox exercises the same shapes the real scan does.
    local mirrored=0 f
    if [ -d "build/hotswap" ]; then
        for f in build/hotswap/*.so; do
            [ -f "$f" ] || continue
            cp "$f" "$sandbox/" 2>/dev/null && mirrored=$((mirrored + 1))
        done
    fi

    local present=0
    for f in "$sandbox"/*.so; do
        [ -f "$f" ] || continue
        present=$((present + 1))
    done
    if [ "$present" -lt 1 ]; then
        # An empty sandbox would make the baseline vacuously clean and the
        # "planted fixture trips the gate" proof meaningless.
        echo "$GATE: selftest FATAL — sandbox holds no module .so; refusing to prove anything against an empty scan set" >&2
        rm -rf "$sandbox"
        exit 2
    fi

    local baseline_out="$sandbox/baseline.out"
    local tripped_out="$sandbox/tripped.out"
    local recovered_out="$sandbox/recovered.out"

    cleanup() { rm -rf "$sandbox"; }
    trap cleanup EXIT

    ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$sandbox" \
        "$SELF" >"$baseline_out" 2>&1
    local baseline_rc=$?
    if [ "$baseline_rc" -ne 0 ]; then
        echo "$GATE: selftest FATAL — sandbox baseline is not clean (rc=$baseline_rc); the trip/recover comparison would prove nothing" >&2
        cat "$baseline_out" >&2
        exit 2
    fi
    if LC_ALL=C grep -q 'zcl_selftest_undeclared_node_reach' "$baseline_out"; then
        echo "$GATE: selftest FATAL — baseline already names the forbidden symbol before the fixture was planted" >&2
        cat "$baseline_out" >&2
        exit 2
    fi

    mv "$sandbox/violating.so.parked" "$bad_so"
    ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$sandbox" \
        "$SELF" >"$tripped_out" 2>&1
    local tripped_rc=$?

    rm -f "$bad_so"
    ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$sandbox" \
        "$SELF" >"$recovered_out" 2>&1
    local recovered_rc=$?

    # Two more legs that need no artifacts: the override is refused without
    # the marker, and refused for a path outside scratch.
    local stray_out stray_rc
    stray_out="$(ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$sandbox" "$SELF" 2>&1)"
    stray_rc=$?
    local outside_out outside_rc
    outside_out="$(ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="/etc" "$SELF" 2>&1)"
    outside_rc=$?

    # ── capability-crossing selftest (leg 1b) ──────────────────────────────
    # A module dir the crossing scenarios can point the artifact leg at
    # without depending on whatever build/hotswap happens to hold right now.
    local cap_so_dir="$sandbox/capcross_so"
    mkdir -p "$cap_so_dir" || {
        echo "$GATE: selftest FATAL — cannot create $cap_so_dir" >&2
        exit 2
    }
    cp "$clean_so" "$cap_so_dir/" || {
        echo "$GATE: selftest FATAL — cannot stage a clean module for the capability-crossing selftest" >&2
        exit 2
    }

    # Scenario 1: a known-forbidden symbol on the allowlist must REFUSE. Built
    # by copying the REAL allowlist — already >= IMPORT_FLOOR and already
    # covers everything clean_so imports, per the baseline proof above — and
    # appending one row for a symbol capability_symbols.def classes CAP_NETWORK.
    local forbidden_def="$sandbox/capcross_forbidden.def"
    cp "$DEF" "$forbidden_def" || {
        echo "$GATE: selftest FATAL — cannot copy $DEF for the capability-crossing selftest" >&2
        exit 2
    }
    printf 'HOTSWAP_MODULE_IMPORT("socket", "LIBC")\n' >> "$forbidden_def"

    local forbidden_out forbidden_rc
    forbidden_out="$(ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" \
        ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE="$forbidden_def" \
        ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$cap_so_dir" \
        "$SELF" 2>&1)"
    forbidden_rc=$?

    # Scenario 2: a capability_symbols.def row whose class sits on a
    # CONTINUATION line must still be classified — proving the 8-row trap
    # (a long symbol name pushes CAP_ onto the next physical line) is
    # handled, not silently dropped by a single-line grep. Again built on
    # top of the real allowlist so the artifact leg stays clean.
    local cont_capfile="$sandbox/capcross_continuation_cap.def"
    local cont_def="$sandbox/capcross_continuation_imports.def"
    : > "$cont_capfile"
    cp "$DEF" "$cont_def" || {
        echo "$GATE: selftest FATAL — cannot copy $DEF for the continuation-line selftest" >&2
        exit 2
    }
    local k
    for k in $(seq 1 35); do
        printf 'ZCL_CAPABILITY_SYMBOL("zcl_selftest_pad_sym_%s", CAP_HARMLESS, "selftest pad row")\n' "$k" >> "$cont_capfile"
        printf 'HOTSWAP_MODULE_IMPORT("zcl_selftest_pad_sym_%s", "LIBC")\n' "$k" >> "$cont_def"
    done
    {
        printf 'ZCL_CAPABILITY_SYMBOL("zcl_selftest_continuation_symbol",\n'
        printf '    CAP_RANDOM, "selftest continuation-line row")\n'
    } >> "$cont_capfile"
    printf 'HOTSWAP_MODULE_IMPORT("zcl_selftest_continuation_symbol", "LIBC")\n' >> "$cont_def"

    local cont_out cont_rc
    cont_out="$(ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" \
        ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE="$cont_def" \
        ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE="$cont_capfile" \
        ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$cap_so_dir" \
        "$SELF" 2>&1)"
    cont_rc=$?

    # Scenario 3: the coverage floor trips when almost nothing on the
    # allowlist resolves to a capability class — a crossing this thin must
    # FATAL rather than silently report "clean".
    local floor_def="$sandbox/capcross_floor.def"
    : > "$floor_def"
    printf 'HOTSWAP_MODULE_IMPORT("malloc", "LIBC")\n' >> "$floor_def"
    printf 'HOTSWAP_MODULE_IMPORT("free", "LIBC")\n' >> "$floor_def"
    printf 'HOTSWAP_MODULE_IMPORT("strlen", "LIBC")\n' >> "$floor_def"
    printf 'HOTSWAP_MODULE_IMPORT("memcpy", "LIBC")\n' >> "$floor_def"
    printf 'HOTSWAP_MODULE_IMPORT("open", "LIBC")\n' >> "$floor_def"
    for k in $(seq 1 100); do
        printf 'HOTSWAP_MODULE_IMPORT("zcl_selftest_floor_pad_%s", "LIBC")\n' "$k" >> "$floor_def"
    done

    local floor_out floor_rc
    floor_out="$(ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" \
        ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE="$floor_def" \
        "$SELF" 2>&1)"
    floor_rc=$?

    # The two new overrides get the same stray/outside refusal proof as the
    # existing module-dir override: refused without the marker, refused for
    # a path outside $SCRATCH.
    local defov_stray_out defov_stray_rc
    defov_stray_out="$(ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE="$forbidden_def" "$SELF" 2>&1)"
    defov_stray_rc=$?
    local defov_outside_out defov_outside_rc
    defov_outside_out="$(ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE="/etc" "$SELF" 2>&1)"
    defov_outside_rc=$?
    local capov_stray_out capov_stray_rc
    capov_stray_out="$(ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE="$cont_capfile" "$SELF" 2>&1)"
    capov_stray_rc=$?
    local capov_outside_out capov_outside_rc
    capov_outside_out="$(ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE="/etc" "$SELF" 2>&1)"
    capov_outside_rc=$?

    local ok=1
    if [ "$tripped_rc" -eq 0 ]; then
        echo "$GATE: selftest FAIL — the module importing an undeclared symbol did not trip the gate (rc=0)" >&2
        cat "$tripped_out" >&2
        ok=0
    fi
    if ! LC_ALL=C grep -q 'zcl_selftest_undeclared_node_reach' "$tripped_out"; then
        echo "$GATE: selftest FAIL — gate did not name the forbidden symbol; it may have failed for an unrelated reason" >&2
        cat "$tripped_out" >&2
        ok=0
    fi
    if ! LC_ALL=C grep -q 'zcl_selftest_violating.so' "$tripped_out"; then
        echo "$GATE: selftest FAIL — gate did not name the offending module file" >&2
        cat "$tripped_out" >&2
        ok=0
    fi
    if [ -e "$bad_so" ]; then
        echo "$GATE: selftest FAIL — violating fixture was not removed" >&2
        ok=0
    fi
    if LC_ALL=C grep -q 'zcl_selftest_undeclared_node_reach' "$recovered_out"; then
        echo "$GATE: selftest FAIL — gate still names the forbidden symbol after cleanup" >&2
        cat "$recovered_out" >&2
        ok=0
    fi
    if [ "$recovered_rc" -ne "$baseline_rc" ]; then
        echo "$GATE: selftest FAIL — gate did not return to its baseline exit code (baseline=$baseline_rc recovered=$recovered_rc)" >&2
        ok=0
    fi
    if [ "$stray_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — sandbox override without the selftest marker was accepted (rc=$stray_rc); a stray env var could redirect a real lint scan" >&2
        printf '%s\n' "$stray_out" >&2
        ok=0
    fi
    if [ "$outside_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — sandbox override pointing outside $SCRATCH was accepted (rc=$outside_rc)" >&2
        printf '%s\n' "$outside_out" >&2
        ok=0
    fi
    if [ "$forbidden_rc" -eq 0 ]; then
        echo "$GATE: selftest FAIL — an allowlist row for a forbidden-capability symbol (socket / CAP_NETWORK) did not trip the crossing leg (rc=0)" >&2
        printf '%s\n' "$forbidden_out" >&2
        ok=0
    fi
    if ! LC_ALL=C grep -q 'socket' <<<"$forbidden_out" || ! LC_ALL=C grep -q 'CAP_NETWORK' <<<"$forbidden_out"; then
        echo "$GATE: selftest FAIL — crossing leg did not name both the forbidden symbol and its capability class" >&2
        printf '%s\n' "$forbidden_out" >&2
        ok=0
    fi
    if [ "$cont_rc" -ne 0 ]; then
        echo "$GATE: selftest FAIL — a capability_symbols.def row with its class on a CONTINUATION line was not classified (rc=$cont_rc); the 8-row trap is not handled" >&2
        printf '%s\n' "$cont_out" >&2
        ok=0
    fi
    if ! LC_ALL=C grep -q 'random=1' <<<"$cont_out"; then
        echo "$GATE: selftest FAIL — the continuation-line row (CAP_RANDOM) was not counted in the crossing; it may have been silently dropped" >&2
        printf '%s\n' "$cont_out" >&2
        ok=0
    fi
    if [ "$floor_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — a crossing that resolves far fewer than CAPABILITY_CROSS_FLOOR symbols did not FATAL (rc=$floor_rc)" >&2
        printf '%s\n' "$floor_out" >&2
        ok=0
    fi
    if ! LC_ALL=C grep -q 'coverage floor' <<<"$floor_out"; then
        echo "$GATE: selftest FAIL — the coverage-floor FATAL did not name the floor" >&2
        printf '%s\n' "$floor_out" >&2
        ok=0
    fi
    if [ "$defov_stray_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — allowlist override without the selftest marker was accepted (rc=$defov_stray_rc)" >&2
        printf '%s\n' "$defov_stray_out" >&2
        ok=0
    fi
    if [ "$defov_outside_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — allowlist override pointing outside $SCRATCH was accepted (rc=$defov_outside_rc)" >&2
        printf '%s\n' "$defov_outside_out" >&2
        ok=0
    fi
    if [ "$capov_stray_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — capability table override without the selftest marker was accepted (rc=$capov_stray_rc)" >&2
        printf '%s\n' "$capov_stray_out" >&2
        ok=0
    fi
    if [ "$capov_outside_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — capability table override pointing outside $SCRATCH was accepted (rc=$capov_outside_rc)" >&2
        printf '%s\n' "$capov_outside_out" >&2
        ok=0
    fi

    # Scenario 4: a class table that declares a class this gate classifies
    # neither way must FATAL. Without this the gate is default-PERMIT on an
    # open vocabulary: a class added to config/capability_classes.def after
    # this file was written would be silently allowed on the allowlist.
    local vocab_classfile="$sandbox/capcross_vocab_classes.def"
    cp "$CLASSFILE" "$vocab_classfile" || {
        echo "$GATE: selftest FATAL — cannot copy $CLASSFILE for the vocabulary selftest" >&2
        exit 2
    }
    printf 'ZCL_CAPABILITY_CLASS(ZCL_SELFTEST_UNVERDICTED, "selftest", "a class added after this gate was written")\n' >> "$vocab_classfile"

    local vocab_out vocab_rc
    vocab_out="$(ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" \
        ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE="$vocab_classfile" \
        ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR="$cap_so_dir" \
        "$SELF" 2>&1)"
    vocab_rc=$?
    if [ "$vocab_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — a class with no verdict in either list did not FATAL (rc=$vocab_rc)" >&2
        printf '%s\n' "$vocab_out" >&2
        ok=0
    elif ! LC_ALL=C grep -q 'CAP_ZCL_SELFTEST_UNVERDICTED' <<<"$vocab_out"; then
        echo "$GATE: selftest FAIL — the vocabulary refusal did not name the offending class" >&2
        printf '%s\n' "$vocab_out" >&2
        ok=0
    fi

    # And the same override must be refused without the marker, and refused
    # when it points outside $SCRATCH.
    local vocabov_stray_rc vocabov_outside_rc
    ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE="$vocab_classfile" "$SELF" >/dev/null 2>&1
    vocabov_stray_rc=$?
    ZCL_HOTSWAP_IMPORTS_SELFTEST="$GATE" \
        ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE="/etc/hosts" "$SELF" >/dev/null 2>&1
    vocabov_outside_rc=$?
    if [ "$vocabov_stray_rc" -ne 2 ] || [ "$vocabov_outside_rc" -ne 2 ]; then
        echo "$GATE: selftest FAIL — class-table override accepted without the marker (rc=$vocabov_stray_rc) or outside $SCRATCH (rc=$vocabov_outside_rc)" >&2
        ok=0
    fi

    trap - EXIT
    rm -rf "$sandbox"

    if [ "$ok" -ne 1 ]; then
        echo "$GATE: selftest FAILED" >&2
        exit 1
    fi
    echo "$GATE: selftest PASS — a sandbox module importing an undeclared node symbol tripped the gate (rc=$tripped_rc; module and symbol both named); removing it restored the baseline verdict (rc=$baseline_rc) over $present sandbox module(s) ($mirrored mirrored from build/hotswap); the sandbox override is refused without the marker and refused outside $SCRATCH; a forbidden-capability allowlist row (socket/CAP_NETWORK) tripped the crossing leg (rc=$forbidden_rc); a continuation-line capability row was classified (CAP_RANDOM counted); a thin crossing hit the coverage floor (rc=$floor_rc); a class with no verdict in either list FATALed (rc=$vocab_rc) and was named; both new overrides are refused without the marker and refused outside $SCRATCH"
    exit 0
}

if [ "${1:-}" = "--selftest" ]; then
    run_selftest
fi

run_checks
exit $?
