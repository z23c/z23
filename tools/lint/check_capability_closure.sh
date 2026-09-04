#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
# purpose: HARD gate — every external entry point this tree's compiled
#          objects reach is classified, and every file that reaches a
#          classified capability has said so, and only what it uses.
#
# WHY THIS EXISTS. engine/composition/capability_classes.def names nine kinds of reach a
# translation unit can have (network, process spawn, dynamic load, filesystem
# read/write, wallet-key reach, randomness, clock, privilege). Two files make
# that design real:
#
#   engine/composition/capability_symbols.def   — every external symbol this tree calls,
#                                      and which class it belongs to (or
#                                      CAP_HARMLESS, meaning none).
#   engine/composition/module_capabilities.def  — cross-target source declarations.
#   engine/composition/module_capabilities_linux.def / _windows.def — exact overrides for
#                                      paths whose selected host arm differs.
#
# Neither file enforces anything by existing. This script is the enforcement:
# it reads what the compiler already proved (every undefined symbol in every
# compiled object, via `nm`) and checks it against both tables. A file with
# no row in module_capabilities.def declares nothing, and nothing is enforced
# positively — reaching a classified symbol without a row is a build failure.
#
# WHAT THIS CHECKS, all six, all run every time (no short-circuit — one pass
# reports every violation — except item 6, which by its nature must abort the
# rest of the pass; see below):
#
#   1. CLOSURE.      Every undefined symbol the object tree carries appears
#                     in config/capability_symbols.def. An unclassified
#                     symbol is a build failure, not an assumed-harmless one.
#   2. DECLARATION.   Every object referencing a symbol classified to a real
#                     capability (anything but CAP_HARMLESS) maps to a source
#                     file whose module_capabilities.def row grants that
#                     class. Undeclared reach fails.
#   3. SYMMETRY.      A row granting a class the file's object does not
#                     actually use fails (declarations cannot rot upward as
#                     code shrinks). A row naming a source file that no
#                     longer exists fails.
#   4. HOLLOWNESS.    Fewer than CAP_CLOSURE_MIN_OBJECTS_SCANNED objects
#                     scanned prints UNPROVEN and exits 2 — never 0. Modeled
#                     on CJ_MIN_OBJECTS_SCANNED in
#                     tests/harness/src/test_cold_join_sovereign.c.
#   5. RAW SYSCALL BAN. A hand-rolled syscall reaches the kernel with no
#                     symbol for `nm` to see, which defeats checks 1-3
#                     entirely. Every tracked .c file with no CAP_PRIVILEGE
#                     row is grepped for a direct `syscall(` call and for
#                     inline-asm trap instructions (`int $0x80`, `svc #`, a
#                     bare `syscall` mnemonic inside an asm block). Files
#                     that declare CAP_PRIVILEGE are exempt — they have
#                     already told a reviewer to look.
#   6. COVERAGE FLOOR. Every row in engine/composition/module_capabilities.def names a
#                     source file that was compiled into an epoch when the
#                     table was written — the table is a coverage
#                     expectation. Runs immediately after the epoch's object
#                     list is gathered, BEFORE items 1-3 and 5 are graded off
#                     it. More than CAP_CLOSURE_COVERAGE_BASELINE declared
#                     rows with no compiled object anywhere in this scan
#                     prints UNPROVEN and exits 2 — a partial epoch (e.g. a
#                     `make z23-dev`-only rebuild) can hold thousands of
#                     objects, well past the HOLLOWNESS floor, while still
#                     silently missing files the hollowness floor cannot see
#                     it missing. See CAP_CLOSURE_COVERAGE_BASELINE below for
#                     the measured baseline and how it was produced. FEWER
#                     unobserved rows than the baseline fails too (as a
#                     VIOLATION, not UNPROVEN) — the baseline is a shrink-only
#                     ratchet and coverage improving without lowering it is
#                     exactly how a ratchet rusts shut at a stale number.
#
# WEAK-UNDEFINED SYMBOLS. `nm -u` reports both STRONG undefined (type `U`)
# and WEAK undefined (type `w`, occasionally `v` for a weak object) symbols.
# A strip that keeps only `U` silently drops every weak-undefined reference —
# measured on this tree: 18 occurrences, including
# ed25519_secret_key_from_seed (CAP_WALLET) and five dynhost_*/tor_*/hs_*
# CAP_NETWORK entry points reached through Tor's weak-symbol linkage. A gate
# that stops seeing a whole symbol class while still reporting clean is worse
# than no gate. This script treats `U`, `w` and `v` alike as undefined
# everywhere it reads `nm` output, and --selftest carries a case that
# regresses on it (case C below).
#
# THE OBJECT TREE THIS SCRIPT MEASURES: build/dev-obj/epochs/<hash>, the
# newest-mtime subdirectory when more than one epoch is present (a stale
# epoch can sit alongside a fresh one; this is the same "several epochs can
# coexist" accommodation test_cold_join_sovereign.c makes). Populate a
# COMPLETE one (the COVERAGE FLOOR above will refuse a `make z23-dev`-only
# rebuild) with:
#
#     tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \
#       make -j16 build/bin/z23-dev build/bin/zclassic23-package-verify-dev
#
# A cold build/dev-obj/ prints UNPROVEN and exits 2 rather than reporting a
# false clean — see HOLLOWNESS above. A newer-but-partial epoch (present but
# missing declared files) also prints UNPROVEN and exits 2 — see COVERAGE
# FLOOR above.
#
# Exit: 0 clean, 1 violations (including a stale, too-high coverage
# baseline), 2 hollow/partial scan, broken selftest, or cannot read
# engine/composition/capability_symbols.def (that file is owned by a different lane; its
# absence is a broken precondition, not zero violations).
#
# Usage:
#   tools/lint/check_capability_closure.sh              # the gate
#   tools/lint/check_capability_closure.sh --selftest    # prove it fires
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
# shellcheck source=tools/scripts/sh_str.sh
source "$REPO_ROOT/tools/scripts/sh_str.sh"

# Anti-hollow floor. Named after CJ_MIN_OBJECTS_SCANNED in
# tests/harness/src/test_cold_join_sovereign.c, same discipline: a tree below the
# floor is refused, never reported clean.
CAP_CLOSURE_MIN_OBJECTS_SCANNED=500

# Coverage floor, shrink-only ratchet (same discipline as RATCHET_CEILING in
# check_no_wallclock_assertion.sh — read that script's header for the
# convention this mirrors). Every row in engine/composition/module_capabilities.def names
# a source file that WAS compiled into an epoch when the table was written;
# the table is itself a coverage expectation. A partial rebuild (e.g.
# `make z23-dev` alone) produces a newer-but-incomplete epoch that silently
# drops objects like tools/package_verify.o while still holding thousands of
# objects — comfortably above CAP_CLOSURE_MIN_OBJECTS_SCANNED, so the
# hollowness floor above cannot see it. Measured live: exactly that rebuild
# made this gate report "OK — closed" while three genuinely unclassified
# symbols reachable only from tools/package_verify.c stayed invisible to it.
# The count of module_capabilities.def rows with NO compiled object anywhere
# in the scanned epoch ("declared but unobserved") is the signal a targeted,
# partial scan leaves that a blanket object-count floor cannot.
#
# Overridable (ZCL_CAP_CLOSURE_COVERAGE_BASELINE) so --selftest can aim it at
# synthetic fixtures far too small to ever carry the production count.
#
# Baseline measured 2026-08-30 against a freshly built COMPLETE Linux epoch:
#   tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \
#     make -j16 build/bin/z23-dev build/bin/zclassic23-package-verify-dev
# (2060 objects, epoch 2617150eb95064fbce18c5cd445173e9dc2e80d3787aa96ad604d8c14f9b26f7).
# Of the host-selected module declaration set, exactly 2 have no compiled
# object anywhere in that epoch, both genuine standalone binaries neither
# target links:
#   tests/harness/src/test_thread_qos.c   — built only by the test harness
#   tools/rebuild_recent.c           — its own BUILD_NODE_TOOL binary
# Neither belongs in z23-dev or the package verifier; this is the honest
# floor for THIS pair of targets, not padding. Host alternatives that Makefile
# does not select are excluded by exact source identity below: Linux drops the
# sandbox stub; Darwin drops the Linux sandbox and native self-backtrace arms;
# Windows drops the Linux sandbox and VCS arms plus the explicitly refused
# Linux-confinement package verifier. They are not baseline headroom. If a
# dependency shape changes, the baseline may only move DOWN without review —
# a rise means either a legitimate new standalone exemption (document it
# above) or the partial-scan regression this floor exists to catch.
CAP_CLOSURE_HOST_BASELINE=2
CAP_CLOSURE_COVERAGE_BASELINE="${ZCL_CAP_CLOSURE_COVERAGE_BASELINE:-$CAP_CLOSURE_HOST_BASELINE}"

CAP_CLOSURE_HOST_OS="$(uname -s 2>/dev/null || true)"
case "$CAP_CLOSURE_HOST_OS" in
    Linux|Darwin) ;;
    MINGW*|MSYS*|CYGWIN*) CAP_CLOSURE_HOST_OS=Windows ;;
    *) CAP_CLOSURE_HOST_OS=Other ;;
esac

# Linux produced the portable declaration snapshot and remains the
# shrink-only symmetry authority. Darwin still enforces closure and every
# undeclared reach, but cannot call Linux-only compiler lowering stale.
CAP_CLOSURE_HOST_SYMMETRY=1
[ "$CAP_CLOSURE_HOST_OS" = "Darwin" ] &&
    CAP_CLOSURE_HOST_SYMMETRY=0
CAP_CLOSURE_ENFORCE_SYMMETRY="${ZCL_CAP_CLOSURE_ENFORCE_SYMMETRY:-$CAP_CLOSURE_HOST_SYMMETRY}"

CAP_CLOSURE_HOST_WINDOWS=false
[ "$CAP_CLOSURE_HOST_OS" = "Windows" ] && CAP_CLOSURE_HOST_WINDOWS=true

# Return success when a declared source belongs to the complete epoch shape
# for this host. These exclusions mirror Makefile's selected platform arms
# plus Windows' named package-verifier refusal; do not turn this into a broad
# directory or pattern exemption.
cap_closure_coverage_applicable() {
    local path="$1"
    case "$CAP_CLOSURE_HOST_OS:$path" in
        Linux:platform/modules/platform/src/os_sandbox_stub.c|\
        Darwin:platform/modules/platform/src/os_sandbox_linux.c|\
        Darwin:platform/modules/platform/src/os_sandbox_package_linux.c|\
        Darwin:platform/modules/util/src/self_backtrace.c|\
        Windows:platform/modules/platform/src/os_sandbox_linux.c|\
        Windows:platform/modules/platform/src/os_sandbox_package_linux.c|\
        Windows:contexts/commons/modules/vcs/src/vcs_devloop.c|\
        Windows:tools/package_verify.c)
            return 1
            ;;
    esac
    return 0
}

# ── nm output parsing ───────────────────────────────────────────────────────
# One line of `nm --print-file-name` looks like:
#   <path>:<16-hex-or-blank> <TYPE> <name>          (defined: has an address)
#   <path>:                  <type> <name>          (undefined: no address)
# Split on the first colon AFTER an optional Windows drive prefix, then take
# the last two whitespace tokens as (type, name) regardless of whether the
# address field is present.  Native MinGW nm rewrites an MSYS /c/... input to
# C:/... in its output; treating the drive colon as the record delimiter maps
# every such object to the fake source name "C" and hollows the scan.
# Prints "<path>\t<type>\t<name>" per input line; unparsable lines are
# dropped silently (nm's own banner/error lines, if any leak through).
cap_closure_parse_nm() {
    local strip_linker_prefix=0
    [ "$(uname -s 2>/dev/null || true)" = "Darwin" ] &&
        strip_linker_prefix=1
    awk -v strip_linker_prefix="$strip_linker_prefix" '
        {
            line = $0
            colon = index(line, ":")
            if (colon == 2 && substr(line, 1, 1) ~ /[A-Za-z]/ &&
                (substr(line, 3, 1) == "/" || substr(line, 3, 1) == "\\")) {
                tail_colon = index(substr(line, 3), ":")
                if (tail_colon == 0) next
                colon = tail_colon + 2
            }
            if (colon == 0) next
            path = substr(line, 1, colon - 1)
            rest = substr(line, colon + 1)
            n = split(rest, a, /[ \t]+/)
            m = 0
            for (i = 1; i <= n; i++) if (a[i] != "") { m++; b[m] = a[i] }
            if (m == 2) { type = b[1]; name = b[2] }
            else if (m == 3) { type = b[2]; name = b[3] }
            else next
            # Mach-O prefixes every external C symbol with one underscore.
            # Normalize that ABI decoration so the shared capability table
            # continues to name source-level symbols (connect, open, ...).
            if (strip_linker_prefix && substr(name, 1, 1) == "_")
                name = substr(name, 2)
            # Darwin decorates some POSIX entry points with ABI variants
            # such as open$UNIX2003 and fopen$DARWIN_EXTSN. They are the
            # same source-level authority as open/fopen and must match the
            # shared capability declaration rather than inventing a second
            # platform-only spelling.
            if (strip_linker_prefix)
                sub(/\$[A-Z0-9_]+$/, "", name)
            print path "\t" type "\t" name
        }
    '
}

# ── find the object tree ────────────────────────────────────────────────────
# Prints the chosen epoch directory on stdout, or nothing if none found.
cap_closure_find_epoch() {
    local root="$1" base="$root/build/dev-obj/epochs" newest="" newest_mtime=0
    [ -d "$base" ] || return 0
    local d mtime
    for d in "$base"/*/; do
        [ -d "$d" ] || continue
        d="${d%/}"
        mtime="$(stat -c '%Y' "$d" 2>/dev/null || stat -f '%m' "$d" 2>/dev/null || echo 0)"
        if [ -z "$newest" ] || [ "$mtime" -gt "$newest_mtime" ]; then
            newest="$d"
            newest_mtime="$mtime"
        fi
    done
    [ -n "$newest" ] && printf '%s\n' "$newest"
}

# ── engine/composition/capability_symbols.def ───────────────────────────────────────────
# cap_closure_symbols_tsv prints "symbol\tCAP_XXX" pairs, tolerant of a
# ZCL_CAPABILITY_SYMBOL(...) call wrapped across multiple lines (a long
# symbol name pushes the class onto the next line). It is a pure function —
# safe to call inside command substitution.
#
# cap_closure_load_symbols populates the global assoc array CAP_SYM and sets
# CAP_SYM_COUNT. It must be called DIRECTLY, never inside $(...): a command
# substitution forks a subshell, and an associative array populated inside
# that subshell vanishes when the subshell exits, leaving the caller's array
# empty while the subshell's own stdout (e.g. a row count) still comes back
# looking correct — measured live in this script's own first --selftest run,
# which reported "1 classified symbols" while CAP_SYM stayed empty and every
# lookup missed.
cap_closure_symbols_tsv() {
    awk '
        function flush() {
            if (buf == "") return
            gsub(/\n/, " ", buf)
            if (match(buf, /ZCL_CAPABILITY_SYMBOL\([[:space:]]*"([^"\\]|\\.)*"[[:space:]]*,[[:space:]]*CAP_[A-Z_]+/)) {
                s = substr(buf, RSTART, RLENGTH)
                if (match(s, /"([^"\\]|\\.)*"/)) sym = substr(s, RSTART + 1, RLENGTH - 2)
                else sym = ""
                rest = s
                sub(/^[^,]*,[[:space:]]*/, "", rest)
                cls = rest
                gsub(/[[:space:]]+$/, "", cls)
                if (sym != "" && cls != "") print sym "\t" cls
            }
            buf = ""
        }
        /ZCL_CAPABILITY_SYMBOL\(/ { flush(); buf = $0; next }
        buf != "" { buf = buf "\n" $0 }
        END { flush() }
    ' "$1"
}
declare -A CAP_SYM=()
CAP_SYM_COUNT=0
cap_closure_load_symbols() {
    local file="$1" out sym cls n=0
    CAP_SYM=()
    [ -f "$file" ] || return 1
    out="$(cap_closure_symbols_tsv "$file")" || return 1
    while IFS=$'\t' read -r sym cls; do
        [ -n "$sym" ] || continue
        CAP_SYM["$sym"]="$cls"
        n=$((n + 1))
    done <<< "$out"
    if [ "$CAP_CLOSURE_HOST_WINDOWS" = true ]; then
        # MinGW COFF names an imported function pointer __imp_<symbol> while
        # ELF/Mach-O report the callable symbol itself. This is ABI decoration,
        # not a second capability judgement: give every reviewed table row its
        # exact import-pointer alias without inflating the configured-row count.
        while IFS=$'\t' read -r sym cls; do
            [ -n "$sym" ] || continue
            CAP_SYM["__imp_$sym"]="$cls"
            CAP_SYM["__imp__$sym"]="$cls"
            CAP_SYM["__mingw_$sym"]="$cls"
        done <<< "$out"
    fi
    CAP_SYM_COUNT=$n
    return 0
}

# ── engine/composition/module_capabilities.def ──────────────────────────────────────────
# Same subshell discipline as the symbols loader above: cap_closure_module_tsv
# is the pure, $()-safe half; cap_closure_load_module_rows must be called
# directly so it can actually populate CAP_MOD_RAW in the caller's shell.
cap_closure_module_tsv() {
    awk '
        function flush() {
            if (buf == "") return
            gsub(/\n/, " ", buf)
            if (match(buf, /ZCL_MODULE_CAPABILITY\([[:space:]]*"([^"\\]|\\.)*"[[:space:]]*,[[:space:]]*[A-Z_|]+[[:space:]]*,/)) {
                s = substr(buf, RSTART, RLENGTH)
                if (match(s, /"([^"\\]|\\.)*"/)) path = substr(s, RSTART + 1, RLENGTH - 2)
                else path = ""
                rest = s
                sub(/^[^,]*,[[:space:]]*/, "", rest)
                sub(/[[:space:]]*,[[:space:]]*$/, "", rest)
                cls = rest
                if (path != "" && cls != "") print path "\t" cls
            }
            buf = ""
        }
        /ZCL_MODULE_CAPABILITY\(/ { flush(); buf = $0; next }
        buf != "" { buf = buf "\n" $0 }
        END { flush() }
    ' "$1"
}
declare -A CAP_MOD_RAW=()
declare -A CAP_MOD_UNION_RAW=()
CAP_MOD_COUNT=0
CAP_MOD_PLATFORM_COUNT=0

# Add the tokens in $2 to the set encoded by $1. CAP_NONE is the explicit
# empty-set spelling used only by a platform override that must replace a
# non-empty portable row.
cap_closure_union_caps() {
    local out="$1" add="$2" tok
    IFS='|' read -ra toks <<< "$add"
    for tok in "${toks[@]}"; do
        [ -n "$tok" ] && [ "$tok" != "CAP_NONE" ] || continue
        if ! cap_closure_grants "$out" "$tok"; then
            [ -n "$out" ] && out="$out|$tok" || out="$tok"
        fi
    done
    printf '%s' "$out"
}

cap_closure_load_module_rows() {
    local file="$1" platform_file="${2:-}" out path cls pn=0
    CAP_MOD_RAW=()
    CAP_MOD_UNION_RAW=()
    [ -f "$file" ] || return 1
    out="$(cap_closure_module_tsv "$file")" || return 1
    while IFS=$'\t' read -r path cls; do
        [ -n "$path" ] || continue
        CAP_MOD_RAW["$path"]="$cls"
        CAP_MOD_UNION_RAW["$path"]="$(cap_closure_union_caps "${CAP_MOD_UNION_RAW[$path]:-}" "$cls")"
    done <<< "$out"
    if [ -n "$platform_file" ] && [ -f "$platform_file" ]; then
        out="$(cap_closure_module_tsv "$platform_file")" || return 1
        while IFS=$'\t' read -r path cls; do
            [ -n "$path" ] || continue
            # Exact active-target replacement for object-level symmetry.
            # The source/package union is retained separately below.
            CAP_MOD_RAW["$path"]="$cls"
            CAP_MOD_UNION_RAW["$path"]="$(cap_closure_union_caps "${CAP_MOD_UNION_RAW[$path]:-}" "$cls")"
            pn=$((pn + 1))
        done <<< "$out"
    fi
    CAP_MOD_COUNT="${#CAP_MOD_RAW[@]}"
    CAP_MOD_PLATFORM_COUNT=$pn
    return 0
}

# True (0) iff the "CAP_A|CAP_B|..." string in $1 contains class $2 as a
# whole token (not a substring match against a longer class name).
cap_closure_grants() {
    local raw="$1" want="$2" tok
    IFS='|' read -ra toks <<< "$raw"
    for tok in "${toks[@]}"; do
        [ "$tok" = "$want" ] && return 0
    done
    return 1
}

# ── compiled-out detection ──────────────────────────────────────────────────
# A declared-but-unused capability (item 3a, symmetry) can mean two very
# different things: the file really does not need what it declares (a
# genuine VIOLATION), or the code that would use it never compiled on THIS
# host because a feature macro guarding it is off here (contexts/wallet's
# GTK/WebKit GUI is the standing example: no fleet box has the toolkit dev
# packages, so wallet_gui.c/.c_bot compile only their `#else` stub). The
# second case proves nothing either way — treat it as UNOBSERVED, never as a
# pass and never as a violation, and name exactly which macro(s) are absent.
#
# CAP_CLOSURE_DEFINED_MACRO holds every -D<NAME> macro this build's actual
# compile line defines, in order, with a later -U<NAME> removing it again —
# read from the same CFLAGS the Makefile hands the compiler (see
# `make print-CFLAGS`), never guessed from file names or HAVE_* conventions.
declare -A CAP_CLOSURE_DEFINED_MACRO=()
CAP_CLOSURE_DEFINED_MACRO_LOADED=0

cap_closure_load_defined_macros() {
    local root="$1" text tok name
    CAP_CLOSURE_DEFINED_MACRO=()
    if [ -n "${CAP_CLOSURE_CFLAGS_OVERRIDE+x}" ]; then
        text="$CAP_CLOSURE_CFLAGS_OVERRIDE"
    else
        text="$(cd "$root" && make -s print-CFLAGS 2>/dev/null)" || text=""
    fi
    for tok in $text; do
        case "$tok" in
            -D*)
                name="${tok#-D}"
                name="${name%%=*}"
                [ -n "$name" ] && CAP_CLOSURE_DEFINED_MACRO[$name]=1
                ;;
            -U*)
                name="${tok#-U}"
                [ -n "$name" ] && unset -v 'CAP_CLOSURE_DEFINED_MACRO[$name]'
                ;;
        esac
    done
    CAP_CLOSURE_DEFINED_MACRO_LOADED=1
}

# Prints the identifiers guarding the FIRST non-blank, non-comment line of
# $1, iff that line is `#if ...` / `#ifdef ...` — the only shape this trusts
# as "the whole file's primary arm depends on this macro", because it is
# textually the first thing the preprocessor sees. A guard appearing deeper
# in the file (after real code already ran) proves nothing about the file as
# a whole and is deliberately never matched here.
cap_closure_first_guard_macros() {
    local file="$1" line
    line="$(awk '
        BEGIN { in_comment = 0 }
        {
            l = $0
            if (in_comment) {
                if (l ~ /\*\//) { in_comment = 0 }
                next
            }
            gsub(/^[ \t]+/, "", l)
            if (l == "") next
            if (l ~ /^\/\*/) {
                if (l !~ /\*\//) { in_comment = 1 }
                next
            }
            if (l ~ /^\/\//) next
            print l
            exit
        }
    ' "$file" 2>/dev/null)"
    case "$line" in
        '#if'*|'#ifdef'*)
            printf '%s\n' "$line" \
                | grep -oE '[A-Za-z_][A-Za-z0-9_]*' \
                | grep -v -E '^(if|ifdef|defined)$'
            ;;
    esac
}

# Iff $1 ($2 = repo root) opens with a preprocessor guard AND every macro
# named in that guard is undefined in this build's real CFLAGS, prints the
# macro list (comma-joined) and returns 0. A guard where even one named
# macro IS defined proves nothing — this build might still take that arm
# via `&&`/`||` combinations this deliberately does not evaluate — so that
# case (and "no guard at all") returns 1 and callers must treat it as an
# ordinary, ungoverned violation, never a free pass.
cap_closure_compiled_out_macros() {
    local path="$1" root="$2" macros="" macro defined_any=0 joined
    [ "$CAP_CLOSURE_DEFINED_MACRO_LOADED" -eq 1 ] || cap_closure_load_defined_macros "$root"
    macros="$(cap_closure_first_guard_macros "$root/$path")"
    [ -n "$macros" ] || return 1
    while IFS= read -r macro; do
        [ -n "$macro" ] || continue
        if [ -n "${CAP_CLOSURE_DEFINED_MACRO[$macro]:-}" ]; then
            defined_any=1
        fi
    done <<< "$macros"
    [ "$defined_any" -eq 0 ] || return 1
    joined="$(printf '%s\n' "$macros" | paste -sd, -)"
    [ -n "$joined" ] || return 1
    printf '%s' "$joined"
    return 0
}

# ── the check ────────────────────────────────────────────────────────────────
# Runs entirely against $root, so --selftest can aim it at a fixture. Prints
# a report to stdout/stderr and returns 0 (clean), 1 (violations) or 2
# (hollow / cannot read required input).
check_root() {
    local root="$1"
    # Each check_root call grades one specific $root/CAP_CLOSURE_CFLAGS_OVERRIDE
    # pairing (production runs this once; --selftest runs it once per
    # fixture with a different override each time) — never carry a prior
    # call's cached defined-macro set into this one.
    CAP_CLOSURE_DEFINED_MACRO_LOADED=0
    local symbols_file="$root/engine/composition/capability_symbols.def"
    local module_file="$root/engine/composition/module_capabilities.def"
    local platform_module_file=""
    case "$CAP_CLOSURE_HOST_OS" in
        Linux)
            platform_module_file="$root/engine/composition/module_capabilities_linux.def"
            ;;
        Windows)
            platform_module_file="$root/engine/composition/module_capabilities_windows.def"
            ;;
    esac
    local violations=0

    if ! cap_closure_load_symbols "$symbols_file"; then
        echo "check_capability_closure: FATAL — cannot read $symbols_file"
        echo "  This file is the symbol->class table; without it, closure and"
        echo "  declaration cannot be checked at all. Refusing to report clean"
        echo "  off input this script cannot see."
        return 2
    fi
    local n_sym="$CAP_SYM_COUNT"
    if [ "$n_sym" -lt 1 ]; then
        echo "check_capability_closure: FATAL — parsed 0 rows from $symbols_file"
        echo "  Either the file is empty or this script's parser no longer"
        echo "  matches its ZCL_CAPABILITY_SYMBOL(...) shape. Refusing to"
        echo "  report clean off a scan that saw nothing."
        return 2
    fi

    if ! cap_closure_load_module_rows "$module_file" "$platform_module_file"; then
        echo "check_capability_closure: FATAL — cannot read $module_file"
        return 2
    fi
    local n_mod="$CAP_MOD_COUNT"

    # ── item 4: hollowness, checked before anything is reported clean ──────
    local epoch epoch_nm
    epoch="$(cap_closure_find_epoch "$root")"
    if [ -z "$epoch" ]; then
        echo "check_capability_closure: UNPROVEN — no build/dev-obj/epochs/* found."
        echo "  Populate it with the normal dev build (e.g. 'make z23-dev') and"
        echo "  re-run. Never treat an absent object tree as zero violations."
        return 2
    fi
    epoch_nm="$epoch"
    if command -v cygpath >/dev/null 2>&1; then
        epoch_nm="$(cygpath -m "$epoch")" || return 2
    fi
    # ── gather nm data over the whole epoch, once ───────────────────────────
    local work
    work="$(mktemp -d "${TMPDIR:-/tmp}/cap-closure.XXXXXX")" || {
        echo "check_capability_closure: FATAL — mktemp failed"
        return 2
    }
    trap 'rm -rf "$work"' RETURN

    # Freeze the object list ONCE and reuse it for both nm passes, so a
    # build actively adding/removing objects underneath this scan (this repo
    # normally runs several agent lanes against one checkout) cannot hand the
    # undefined-symbol pass and the defined-symbol pass two different sets.
    # restart-base.o is a generated relocatable aggregate of the exact object
    # list already scanned below. Treating it as an ordinary TU both doubles
    # every undefined edge and invents a nonexistent restart-base.c owner.
    find "$epoch" -name '*.o' ! -name 'restart-base.o' -print0 > "$work/objs.z"
    local n_obj
    n_obj="$(tr -cd '\0' < "$work/objs.z" | wc -c | tr -d ' ')"
    if [ -z "$n_obj" ] || [ "$n_obj" -lt "$CAP_CLOSURE_MIN_OBJECTS_SCANNED" ]; then
        echo "check_capability_closure: UNPROVEN — $epoch holds only ${n_obj:-0}"
        echo "  production objects (floor $CAP_CLOSURE_MIN_OBJECTS_SCANNED)."
        echo "  A stale or partial build epoch, not a clean scan."
        return 2
    fi

    # A build actively rewriting an object file underneath nm truncates or
    # transiently corrupts it; GNU nm reports that on stderr and a nonzero
    # exit for the whole invocation while still printing the OBJECTS THAT DID
    # read cleanly to stdout — a scan that looks complete but silently is not.
    # Measured live on this host: a concurrent lane's rebuild raced this
    # exact scan and produced 9,421 false "unclassified symbol" reports for
    # ordinary in-tree names (GetArg, FormatMoney, ...) because their
    # defining object read as empty mid-write. Discarding nm's stderr with
    # `2>/dev/null` is exactly what let that reach the report as violations
    # instead of failing loud. Treat either signal as UNPROVEN, never as a
    # trustworthy partial result.
    # Do not use `nm -u` here: Apple nm removes the U/w/v type column in
    # undefined-only mode, making strong and weak references
    # indistinguishable and unparsable. The full symbol listing retains the
    # type on GNU and Darwin; undef_uw.tsv below performs the exact filter.
    xargs -0 nm --print-file-name < "$work/objs.z" 2>"$work/nm_u.err" \
        | cap_closure_parse_nm > "$work/undef.tsv"
    local nm_u_rc="${PIPESTATUS[0]}"
    xargs -0 nm -U --print-file-name < "$work/objs.z" 2>"$work/nm_U.err" \
        | cap_closure_parse_nm > "$work/defined.tsv"
    local nm_U_rc="${PIPESTATUS[0]}"
    if [ "$nm_u_rc" -ne 0 ] || [ "$nm_U_rc" -ne 0 ] \
       || [ -s "$work/nm_u.err" ] || [ -s "$work/nm_U.err" ]; then
        echo "check_capability_closure: UNPROVEN — nm reported an error scanning"
        echo "  $epoch (rc=$nm_u_rc/$nm_U_rc). Likely a concurrent build rewriting"
        echo "  an object underneath this scan. Refusing to trust a partial read:"
        cat "$work/nm_u.err" "$work/nm_U.err" 2>/dev/null | sed 's/^/    /'
        return 2
    fi

    # Every source file that actually has an object IN THIS SCAN (regardless
    # of whether the object has any symbols) — the evidence set for symmetry
    # (item 3, below) and for the coverage floor immediately after. Derive
    # this from the frozen object list, not nm output: an inactive platform
    # arm can compile to a valid symbol-free object that nm prints no row for.
    # A source with no object here is either a standalone tool/test binary
    # this epoch legitimately never links, or a file a PARTIAL rebuild
    # silently dropped — the coverage floor below is what tells those apart.
    while IFS= read -r -d '' obj; do
        src="${obj#"$epoch"/}"
        printf '%s\n' "${src%.o}.c"
    done < "$work/objs.z" | LC_ALL=C sort -u > "$work/compiled_sources.txt"

    # ── coverage floor ───────────────────────────────────────────────────
    # Refuse to grade a scan whose coverage it cannot vouch for. See
    # CAP_CLOSURE_COVERAGE_BASELINE above for the reasoning and the measured
    # baseline. A row whose source file no longer exists at all is item 3b's
    # concern, not this one, and is excluded here.
    local unobserved=0 platform_excluded=0 cov_path
    : > "$work/declared_unobserved.txt"
    for cov_path in "${!CAP_MOD_RAW[@]}"; do
        [ -f "$root/$cov_path" ] || continue
        if ! cap_closure_coverage_applicable "$cov_path"; then
            platform_excluded=$((platform_excluded + 1))
            continue
        fi
        grep -qxF "$cov_path" "$work/compiled_sources.txt" && continue
        printf '%s\n' "$cov_path" >> "$work/declared_unobserved.txt"
        unobserved=$((unobserved + 1))
    done
    LC_ALL=C sort -o "$work/declared_unobserved.txt" "$work/declared_unobserved.txt"

    if [ "$unobserved" -gt "$CAP_CLOSURE_COVERAGE_BASELINE" ]; then
        echo "check_capability_closure: UNPROVEN — $unobserved module_capabilities.def"
        echo "  row(s) have no compiled object anywhere in $epoch — above the"
        echo "  shrink-only coverage baseline of $CAP_CLOSURE_COVERAGE_BASELINE."
        echo "  This looks like a PARTIAL epoch (e.g. a 'make z23-dev'-only"
        echo "  rebuild), not a scan complete enough to grade. 'I scanned an"
        echo "  incomplete epoch' is not a pass and it is not a violation; it is"
        echo "  a scan that did not happen. Missing (first 20 of $unobserved):"
        sed -n '1,20p' "$work/declared_unobserved.txt" | sed 's/^/    /'
        if [ "$unobserved" -gt 20 ]; then
            echo "    ... and $((unobserved - 20)) more"
        fi
        echo "  Build a COMPLETE epoch and re-run:"
        echo "    tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \\"
        if [ "$CAP_CLOSURE_HOST_WINDOWS" = true ]; then
            echo "      make -j16 z23-dev"
        else
            echo "      make -j16 build/bin/z23-dev build/bin/zclassic23-package-verify-dev"
        fi
        return 2
    fi

    # names defined ANYWHERE in the tree: an in-tree cross-TU call, out of
    # scope for engine/composition/capability_symbols.def (see that file's SCOPE note).
    cut -f3 "$work/defined.tsv" | LC_ALL=C sort -u > "$work/defined_names.txt"
    # every undefined reference, U/w/v alike (see header note on weak symbols)
    awk -F'\t' '$2 == "U" || $2 == "w" || $2 == "v"' "$work/undef.tsv" > "$work/undef_uw.tsv"
    cut -f3 "$work/undef_uw.tsv" | LC_ALL=C sort -u > "$work/undef_names.txt"
    # externally-undefined: undefined somewhere, defined nowhere in this tree
    # `comm` verifies each input is sorted in ITS OWN idea of order before
    # diffing, and that idea comes from the ambient locale unless told
    # otherwise. Both files above were sorted with `LC_ALL=C sort -u`; a bare
    # `comm` here judges them against a locale collation that disagrees with
    # C on case and punctuation ordering, prints "not in sorted order" on
    # stderr, and silently falls back to a comparison that misclassifies
    # thousands of ordinary in-tree names as "externally undefined" — caught
    # live on this tree (9,421 false "unclassified symbol" reports for names
    # like GetArg/FormatMoney that are plainly defined in-tree). LC_ALL=C
    # here makes comm agree with the sort that produced its inputs.
    if ! LC_ALL=C comm -23 "$work/undef_names.txt" "$work/defined_names.txt" \
            > "$work/external_names.txt" 2>"$work/comm.err"; then
        :
    fi
    if [ -s "$work/comm.err" ]; then
        echo "check_capability_closure: UNPROVEN — comm reported a sort-order problem:"
        sed 's/^/    /' "$work/comm.err"
        return 2
    fi

    # ── item 1: closure ─────────────────────────────────────────────────────
    local unclassified=0 sym
    while IFS= read -r sym; do
        [ -n "$sym" ] || continue
        if [ -z "${CAP_SYM[$sym]+x}" ]; then
            echo "check_capability_closure: VIOLATION — unclassified external symbol '$sym'"
            echo "  Reached by this tree, absent from config/capability_symbols.def."
            echo "  Add a row: ZCL_CAPABILITY_SYMBOL(\"$sym\", CAP_..., \"why\")"
            unclassified=$((unclassified + 1))
        fi
    done < "$work/external_names.txt"
    violations=$((violations + unclassified))

    # ── per-object -> per-source-file capability USE (excludes CAP_HARMLESS) ─
    # obj path relative to the epoch root, .o -> .c, matching the convention
    # this whole design uses.
    : > "$work/file_uses.tsv"
    awk -F'\t' -v epoch="$epoch_nm/" '
        NR == FNR { cls[$1] = $2; next }
        {
            obj = $1; name = $3
            if (!(name in cls)) next
            c = cls[name]
            if (c == "CAP_HARMLESS") next
            src = obj
            sub("^" epoch, "", src)
            sub(/\.o$/, ".c", src)
            key = src SUBSEP c
            if (!(key in seen)) { seen[key] = 1; print src "\t" c }
        }
    ' <(for k in "${!CAP_SYM[@]}"; do printf '%s\t%s\n' "$k" "${CAP_SYM[$k]}"; done) \
      "$work/undef_uw.tsv" > "$work/file_uses.tsv"

    # compiled_sources.txt and the coverage floor already ran above, right
    # after the nm passes — this is where symmetry (item 3, below) reads
    # "no object here" as UNOBSERVED (a standalone tool/test binary this
    # epoch legitimately never links), not "confirmed unused"; conflating
    # the two would make declaring a real capability for such a file
    # impossible to do without tripping a false "overdeclared".

    # ── item 2: declaration — every used class must be granted ─────────────
    local undeclared=0 src cls granted
    while IFS=$'\t' read -r src cls; do
        [ -n "$src" ] || continue
        granted="${CAP_MOD_RAW[$src]:-}"
        if [ -z "$granted" ] || ! cap_closure_grants "$granted" "$cls"; then
            echo "check_capability_closure: VIOLATION — undeclared reach: $src uses $cls"
            if [ -z "$granted" ]; then
                echo "  with no module_capabilities.def row at all (declares CAP_NONE)."
            else
                echo "  but its row only grants: $granted"
            fi
            echo "  Add/extend: ZCL_MODULE_CAPABILITY(\"$src\", ...|$cls, \"why\")"
            undeclared=$((undeclared + 1))
        fi
    done < "$work/file_uses.tsv"
    violations=$((violations + undeclared))

    # ── item 3a: symmetry — a granted class must actually be used ──────────
    # item 3b: a row's source file must still exist.
    local overdeclared=0 platform_unobserved=0 missing_src=0 compiled_out=0 path raw tok
    : > "$work/compiled_out.txt"
    for path in "${!CAP_MOD_RAW[@]}"; do
        raw="${CAP_MOD_RAW[$path]}"
        if [ ! -f "$root/$path" ]; then
            echo "check_capability_closure: VIOLATION — module_capabilities.def row"
            echo "  names '$path', which does not exist in this tree."
            missing_src=$((missing_src + 1))
            continue
        fi
        if ! grep -qxF "$path" "$work/compiled_sources.txt"; then
            # No object for this source exists anywhere in this scan (a
            # standalone tool or test binary this epoch never links). There
            # is no evidence either way, so a declared capability here is
            # UNOBSERVED rather than "confirmed unused" — do not flag it.
            continue
        fi
        IFS='|' read -ra toks <<< "$raw"
        for tok in "${toks[@]}"; do
            [ -n "$tok" ] && [ "$tok" != "CAP_NONE" ] || continue
            if ! grep -qF "$(printf '%s\t%s' "$path" "$tok")" "$work/file_uses.tsv"; then
                if [ "$CAP_CLOSURE_ENFORCE_SYMMETRY" != "1" ]; then
                    platform_unobserved=$((platform_unobserved + 1))
                    continue
                fi
                local co_macros
                if co_macros="$(cap_closure_compiled_out_macros "$path" "$root")"; then
                    echo "check_capability_closure: UNOBSERVED (compiled out: $co_macros) —"
                    echo "  $path declares $tok but its primary implementation never"
                    echo "  compiled here: the guard macro(s) $co_macros are not defined in"
                    echo "  this build's CFLAGS. Not a violation and not a pass — the code"
                    echo "  that would prove or disprove $tok did not run through this host's"
                    echo "  compiler. Validate on a host that defines $co_macros."
                    printf '%s\t%s\t%s\n' "$path" "$tok" "$co_macros" >> "$work/compiled_out.txt"
                    compiled_out=$((compiled_out + 1))
                    continue
                fi
                echo "check_capability_closure: VIOLATION — $path declares $tok but its"
                echo "  compiled object does not reference any symbol classified $tok."
                echo "  Shrink the row: ZCL_MODULE_CAPABILITY(\"$path\", <without $tok>, why)"
                overdeclared=$((overdeclared + 1))
            fi
        done
    done
    violations=$((violations + overdeclared + missing_src))

    # ── coverage floor, other half: the baseline must shrink, not just hold ─
    # $unobserved was computed once, above, right after compiled_sources.txt.
    # Fewer unobserved rows than the recorded baseline is good news, but a
    # baseline that is allowed to sit above the true count is a ratchet that
    # can only rust: it stops meaning "what we measured" and starts meaning
    # "whatever nobody bothered to lower". Fail this too, same as every other
    # shrink-only baseline in tools/lint/ (see check_no_wallclock_assertion.sh).
    if [ "$unobserved" -lt "$CAP_CLOSURE_COVERAGE_BASELINE" ]; then
        echo "check_capability_closure: VIOLATION — coverage baseline is stale:"
        echo "  only $unobserved module_capabilities.def row(s) are unobserved in"
        echo "  $epoch, below CAP_CLOSURE_COVERAGE_BASELINE=$CAP_CLOSURE_COVERAGE_BASELINE"
        echo "  recorded in tools/lint/check_capability_closure.sh. Coverage"
        echo "  improved without lowering the baseline — that is what keeps this a"
        echo "  shrink-only ratchet instead of a number that only ever grows."
        echo "  Lower CAP_CLOSURE_COVERAGE_BASELINE to $unobserved (with the reason)"
        echo "  in the same commit."
        violations=$((violations + 1))
    fi

    # ── item 5: raw syscall ban ─────────────────────────────────────────────
    local syscall_violations=0
    local src_list
    src_list="$(cd "$root" && git ls-files '*.c' -- ':!:vendor/*' 2>/dev/null)"
    if [ -z "$src_list" ]; then
        src_list="$(cd "$root" && find . -name '*.c' -not -path './build/*' -not -path './vendor/*' -not -path './.git/*' 2>/dev/null | sed 's#^\./##')"
    fi
    # word-bounded syscall( call (no space before the paren — every real call
    # site in this tree writes it that way; a space there is prose, e.g. a
    # comment reading "a forbidden syscall (socket) kills the process"), x86
    # int $0x80 trap, ARM svc # trap, and a bare "syscall" mnemonic (no
    # paren) inside a quoted asm string.
    local pat='(^|[^A-Za-z0-9_])syscall\(|int[[:space:]]+\$0x80|svc[[:space:]]+#|"[[:space:]]*syscall[[:space:]\\]'
    local f granted5 hit
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        granted5="${CAP_MOD_UNION_RAW[$f]:-}"
        [ -n "$granted5" ] && cap_closure_grants "$granted5" "CAP_PRIVILEGE" && continue
        hit="$(grep -nE "$pat" "$root/$f" 2>/dev/null || true)"
        if [ -n "$hit" ]; then
            echo "check_capability_closure: VIOLATION — $f reaches the kernel through a"
            echo "  raw syscall or inline-asm trap with no CAP_PRIVILEGE declaration:"
            printf '%s\n' "$hit" | sed 's/^/    /'
            syscall_violations=$((syscall_violations + 1))
        fi
    done <<< "$src_list"
    violations=$((violations + syscall_violations))

    echo "check_capability_closure: scanned $n_obj objects under $epoch,"
    echo "  $n_sym classified symbols, $n_mod module rows."
    echo "  unclassified=$unclassified undeclared=$undeclared overdeclared=$overdeclared"
    echo "  platform-unobserved=$platform_unobserved symmetry-enforced=$CAP_CLOSURE_ENFORCE_SYMMETRY"
    echo "  missing-source-rows=$missing_src raw-syscall=$syscall_violations"
    echo "  declared-but-unobserved=$unobserved (coverage baseline=$CAP_CLOSURE_COVERAGE_BASELINE)"
    echo "  platform-target-excluded=$platform_excluded"
    echo "  platform-exact-overrides=$CAP_MOD_PLATFORM_COUNT"
    echo "  compiled-out-unobserved=$compiled_out (never a violation, never a pass — see UNOBSERVED lines above)"
    if [ "$compiled_out" -gt 0 ]; then
        echo "  compiled-out rows:"
        while IFS=$'\t' read -r co_path co_tok co_macros; do
            [ -n "$co_path" ] || continue
            echo "    $co_path declares $co_tok, undefined macro(s): $co_macros"
        done < "$work/compiled_out.txt"
    fi

    if [ "$violations" -gt 0 ]; then
        echo "check_capability_closure: FAIL — $violations violation(s)"
        return 1
    fi
    echo "check_capability_closure: OK — closed"
    return 0
}

# ── selftest ─────────────────────────────────────────────────────────────────
# Synthesizes a fixture object tree and requires the gate to refuse:
#   A. a strong-undefined reference to a classified symbol with no row
#      (the core property: undeclared reach fails).
#   B. a row granting a capability the object never uses (symmetry).
#   C. a WEAK-undefined reference to a classified symbol with no row — the
#      regression case for the U-only extraction bug: if this script ever
#      goes back to filtering strictly on type=="U", this case stops firing
#      while everything else stays green, which is exactly the silent
#      failure mode a gate must not have.
#   E. an epoch below CAP_CLOSURE_MIN_OBJECTS_SCANNED — HOLLOWNESS.
#   F. a declared row with no compiled object anywhere in an otherwise
#      well-populated epoch, above CAP_CLOSURE_COVERAGE_BASELINE — the
#      regression case for the real package_verify.o omission bug: a
#      `make z23-dev`-only rebuild that HOLLOWNESS alone cannot see because
#      the epoch still holds thousands of other objects.
#   G. a coverage baseline held above the true (improved) unobserved count —
#      the ratchet must not be allowed to rust shut at a stale number.
# And a positive control:
#   D. a correctly declared, fully-used fixture passes.
# Windows/COFF regressions are pinned separately:
#   H. a native drive-letter nm record keeps the whole object path;
#   I. MinGW import-pointer decorations inherit the reviewed base symbol;
#   J. a Windows exact override replaces (rather than unions with) the
#      portable row, including CAP_NONE and exact platform coverage skips;
#   K. a Linux exact override has the same replacement semantics;
#   L. coverage follows the exact host-source selection, not a cross-target
#      union, while the two real standalone rows stay applicable everywhere;
#   M. a symbol-free compiled object is still present coverage evidence, not
#      "no object here";
#   N. compiled-out honesty: a declaration behind a guard macro this build's
#      real CFLAGS never define is UNOBSERVED, not a VIOLATION and not a
#      pass (N1) — but an identically-shaped guard the CFLAGS DO define is
#      not "compiled out", and a genuine overdeclaration behind it still
#      VIOLATIONs (N2), so the softening cannot launder an ordinary defect.
FIXTURE_ROOT=""
selftest_cleanup() { [ -n "$FIXTURE_ROOT" ] && rm -rf "$FIXTURE_ROOT"; }

# make_epoch <dir> — populate <dir>/build/dev-obj/epochs/fx0/ with
# CAP_CLOSURE_MIN_OBJECTS_SCANNED harmless filler objects (zero undefined
# symbols each, so they cannot affect closure/declaration/symmetry) plus
# whatever real synthetic objects the caller compiles in afterward.
make_epoch() {
    local d="$1" epoch="$1/build/dev-obj/epochs/fx0"
    mkdir -p "$epoch"
    local src="$d/.filler.c" obj="$d/.filler.o"
    cat > "$src" <<'EOF'
static int filler_fn(int x) { return x + 1; }
int filler_export(int x) { return filler_fn(x) + 1; }
EOF
    cc -std=c23 -c "$src" -o "$obj" 2>/dev/null || cc -c "$src" -o "$obj"
    local i
    for i in $(seq 1 "$CAP_CLOSURE_MIN_OBJECTS_SCANNED"); do
        cp "$obj" "$epoch/filler_$i.o"
    done
}

# fixture_symbols <dir> — a minimal, real capability_symbols.def: just
# "connect" -> CAP_NETWORK, which is all the synthetic objects reference.
fixture_symbols() {
    local d="$1"
    mkdir -p "$d/engine/composition"
    cat > "$d/engine/composition/capability_symbols.def" <<'EOF'
ZCL_CAPABILITY_SYMBOL("connect", CAP_NETWORK, "")
EOF
}

# fixture_module_rows <dir> <row>... — engine/composition/module_capabilities.def with
# exactly the given rows (each a pre-formatted ZCL_MODULE_CAPABILITY line).
fixture_module_rows() {
    local d="$1"; shift
    mkdir -p "$d/engine/composition"
    : > "$d/engine/composition/module_capabilities.def"
    local row
    for row in "$@"; do
        printf '%s\n' "$row" >> "$d/engine/composition/module_capabilities.def"
    done
}

expect_reject() {
    local label="$1" needle="$2" d="$3" out rc
    out="$(check_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ]; then
        echo "SELFTEST FAIL: $label — expected rejection, got a PASS."
        echo "$out" | sed 's/^/    /'
        return 1
    fi
    if str_lacks "$out" "$needle"; then
        echo "SELFTEST FAIL: $label — rejected, but never named '$needle'."
        echo "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label (rc=$rc)"
    return 0
}

expect_accept() {
    local label="$1" d="$2" out rc
    out="$(check_root "$d" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "SELFTEST FAIL: $label — expected a PASS, got rejection (rc=$rc)."
        echo "$out" | sed 's/^/    /'
        return 1
    fi
    echo "  selftest ok: $label"
    return 0
}

run_selftest() {
    command -v cc >/dev/null 2>&1 || {
        echo "check_capability_closure --selftest: FATAL — no cc on PATH, cannot synthesize fixture objects"
        return 2
    }
    FIXTURE_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/cap-closure-selftest.XXXXXX")"
    trap selftest_cleanup EXIT
    local rc=0 d
    local host_os_saved="$CAP_CLOSURE_HOST_OS"
    local host_windows_saved="$CAP_CLOSURE_HOST_WINDOWS"

    # Cases A-E below declare either zero rows or one row that IS compiled,
    # so their true "declared but unobserved" count is always 0 — nothing
    # about the production coverage baseline (calibrated against the real
    # rows) is meaningful for a 0-or-1-row fixture. Pin it to 0 so those
    # cases exercise exactly what they intend to and nothing else; cases F
    # and G below set it explicitly for what they are testing.
    CAP_CLOSURE_COVERAGE_BASELINE=0
    CAP_CLOSURE_ENFORCE_SYMMETRY=1

    echo "== check_capability_closure selftest =="

    # A. strong-undefined reference to a classified symbol, no declaration.
    d="$FIXTURE_ROOT/a"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    fixture_module_rows "$d"   # no rows at all
    cat > "$d/fixture_src/undeclared_user.c" <<'EOF'
extern int connect(int, int, int);
int use_it(void) { return connect(1, 2, 3); }
EOF
    cc -std=c23 -c "$d/fixture_src/undeclared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src_undeclared_user.o" 2>/dev/null \
      || cc -c "$d/fixture_src/undeclared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src_undeclared_user.o"
    # object path must map (epoch-relative, .o->.c) to fixture_src/undeclared_user.c
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    mv "$d/build/dev-obj/epochs/fx0/fixture_src_undeclared_user.o" \
       "$d/build/dev-obj/epochs/fx0/fixture_src/undeclared_user.o"
    expect_reject "A: undeclared strong-undefined reach to a classified symbol" \
                  "undeclared reach" "$d" || rc=1

    # B. a declared capability the object never uses.
    d="$FIXTURE_ROOT/b"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    cat > "$d/fixture_src/overdeclared_user.c" <<'EOF'
static int nothing_dangerous(int x) { return x * 2; }
int overdeclared_export(int x) { return nothing_dangerous(x); }
EOF
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    cc -std=c23 -c "$d/fixture_src/overdeclared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/overdeclared_user.o" 2>/dev/null \
      || cc -c "$d/fixture_src/overdeclared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/overdeclared_user.o"
    fixture_module_rows "$d" \
        'ZCL_MODULE_CAPABILITY("fixture_src/overdeclared_user.c", CAP_NETWORK, "test: declared but unused")'
    expect_reject "B: declared CAP_NETWORK never used by the object" \
                  "overdeclared" "$d" || rc=1

    # C. WEAK-undefined reference to a classified symbol, no declaration —
    # the regression case for the U-only extraction bug.
    d="$FIXTURE_ROOT/c"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    fixture_module_rows "$d"   # no rows at all
    cat > "$d/fixture_src/weak_undeclared_user.c" <<'EOF'
extern __attribute__((weak)) int connect(int, int, int);
int use_weak(void) { return connect(1, 2, 3); }
EOF
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    cc -std=c23 -c "$d/fixture_src/weak_undeclared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/weak_undeclared_user.o" 2>/dev/null \
      || cc -c "$d/fixture_src/weak_undeclared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/weak_undeclared_user.o"
    expect_reject "C: undeclared WEAK-undefined reach to a classified symbol (regression)" \
                  "undeclared reach" "$d" || rc=1

    # D. positive control — a correctly declared, fully-used fixture passes.
    d="$FIXTURE_ROOT/d"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    cat > "$d/fixture_src/declared_user.c" <<'EOF'
extern int connect(int, int, int);
int use_it_declared(void) { return connect(1, 2, 3); }
EOF
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    cc -std=c23 -c "$d/fixture_src/declared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/declared_user.o" 2>/dev/null \
      || cc -c "$d/fixture_src/declared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/declared_user.o"
    fixture_module_rows "$d" \
        'ZCL_MODULE_CAPABILITY("fixture_src/declared_user.c", CAP_NETWORK, "test: correctly declared")'
    # A generated relocatable aggregate repeats the same TU edges and maps to
    # no real source owner. Give it an unclassified edge: the positive control
    # stays green only while restart-base.o is excluded from every nm pass.
    cat > "$d/.restart-base.c" <<'EOF'
extern int aggregate_only_unknown(void);
int aggregate_edge(void) { return aggregate_only_unknown(); }
EOF
    cc -std=c23 -c "$d/.restart-base.c" \
        -o "$d/build/dev-obj/epochs/fx0/restart-base.o" 2>/dev/null \
      || cc -c "$d/.restart-base.c" \
        -o "$d/build/dev-obj/epochs/fx0/restart-base.o"
    expect_accept "D: a correctly declared, fully-used fixture passes (positive control)" "$d" || rc=1

    # E. hollowness — an epoch below the floor must UNPROVEN (exit 2), never
    # a clean pass.
    d="$FIXTURE_ROOT/e"; mkdir -p "$d/build/dev-obj/epochs/fx0" "$d/fixture_src"
    fixture_symbols "$d"
    fixture_module_rows "$d"
    out="$(check_root "$d" 2>&1)"; erc=$?
    if [ "$erc" -ne 2 ]; then
        echo "SELFTEST FAIL: E: a hollow (empty) epoch must exit 2, got $erc"
        echo "$out" | sed 's/^/    /'
        rc=1
    elif str_lacks "$out" "UNPROVEN"; then
        echo "SELFTEST FAIL: E: hollow epoch rejected but never said UNPROVEN"
        rc=1
    else
        echo "  selftest ok: E: an epoch below the object floor is UNPROVEN, exit 2, never 0"
    fi

    # F. coverage floor — a declared row with no compiled object anywhere in
    # the epoch, above the baseline, must UNPROVEN (exit 2), never a clean
    # pass and never a plain FAIL(1). This is the regression case for the
    # real bug: a `make z23-dev`-only rebuild silently drops an object like
    # tools/package_verify.o while the epoch still holds thousands of other
    # objects — comfortably past the HOLLOWNESS floor (case E), which is
    # exactly why hollowness alone cannot catch it.
    d="$FIXTURE_ROOT/f"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    # phantom_tool.c is declared and EXISTS on disk (so item 3b, "row names a
    # file that does not exist", cannot be what fires here) but is never
    # compiled into fx0 — modeling the exact package_verify.o omission.
    cat > "$d/fixture_src/phantom_tool.c" <<'EOF'
static int nothing_dangerous(int x) { return x + 1; }
int phantom_export(int x) { return nothing_dangerous(x); }
EOF
    fixture_module_rows "$d" \
        'ZCL_MODULE_CAPABILITY("fixture_src/phantom_tool.c", CAP_NETWORK, "test: a standalone tool this partial epoch never compiled")'
    CAP_CLOSURE_COVERAGE_BASELINE=0
    out="$(check_root "$d" 2>&1)"; frc=$?
    if [ "$frc" -ne 2 ]; then
        echo "SELFTEST FAIL: F: a declared row with no compiled object anywhere in the epoch (above baseline) must exit 2, got $frc"
        echo "$out" | sed 's/^/    /'
        rc=1
    elif str_lacks "$out" "UNPROVEN"; then
        echo "SELFTEST FAIL: F: rejected but never said UNPROVEN"
        rc=1
    elif str_lacks "$out" "phantom_tool.c"; then
        echo "SELFTEST FAIL: F: rejected but never NAMED the specific missing file"
        rc=1
    else
        echo "  selftest ok: F: a partial epoch missing a declared file (above the coverage baseline) is UNPROVEN, exit 2, never 0 or 1"
    fi

    # G. coverage floor, other half — a baseline set ABOVE the true
    # unobserved count must fail too (a VIOLATION, exit 1 — not UNPROVEN),
    # so the ratchet cannot rust shut at a stale, too-generous number.
    d="$FIXTURE_ROOT/g"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    cat > "$d/fixture_src/declared_user_g.c" <<'EOF'
extern int connect(int, int, int);
int use_it_declared_g(void) { return connect(1, 2, 3); }
EOF
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    cc -std=c23 -c "$d/fixture_src/declared_user_g.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/declared_user_g.o" 2>/dev/null \
      || cc -c "$d/fixture_src/declared_user_g.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/declared_user_g.o"
    fixture_module_rows "$d" \
        'ZCL_MODULE_CAPABILITY("fixture_src/declared_user_g.c", CAP_NETWORK, "test: correctly declared and compiled — 0 unobserved")'
    CAP_CLOSURE_COVERAGE_BASELINE=1   # true unobserved count is 0 — stale on purpose
    out="$(check_root "$d" 2>&1)"; grc=$?
    if [ "$grc" -ne 1 ]; then
        echo "SELFTEST FAIL: G: a coverage baseline set above the true unobserved count must exit 1 (violation), got $grc"
        echo "$out" | sed 's/^/    /'
        rc=1
    elif str_lacks "$out" "coverage baseline is stale"; then
        echo "SELFTEST FAIL: G: rejected but never said the baseline is stale"
        rc=1
    else
        echo "  selftest ok: G: a coverage baseline held above the true (improved) unobserved count is a VIOLATION, exit 1, not silently tolerated"
    fi
    CAP_CLOSURE_COVERAGE_BASELINE=0

    # H. MinGW nm rewrites /c/... to C:/... and therefore emits two colons.
    # The drive colon is not the record delimiter.
    local parsed expected
    parsed="$(printf '%s\n' 'C:/work/epoch/core/modules/net/dialer.o:         U connect' | cap_closure_parse_nm)"
    expected="$(printf 'C:/work/epoch/core/modules/net/dialer.o\tU\tconnect')"
    if [ "$parsed" != "$expected" ]; then
        echo "SELFTEST FAIL: H: Windows drive-letter nm path was parsed as '$parsed'"
        rc=1
    else
        echo "  selftest ok: H: Windows drive-letter nm records preserve the full object path"
    fi

    # I. COFF import pointers and MinGW stdio wrappers are ABI spellings of a
    # reviewed base entry, not new unclassified capabilities.
    d="$FIXTURE_ROOT/i"; fixture_symbols "$d"
    CAP_CLOSURE_HOST_OS=Windows
    CAP_CLOSURE_HOST_WINDOWS=true
    if ! cap_closure_load_symbols "$d/engine/composition/capability_symbols.def" ||
       [ "${CAP_SYM[__imp_connect]:-}" != "CAP_NETWORK" ] ||
       [ "${CAP_SYM[__imp__connect]:-}" != "CAP_NETWORK" ] ||
       [ "${CAP_SYM[__mingw_connect]:-}" != "CAP_NETWORK" ]; then
        echo "SELFTEST FAIL: I: MinGW ABI aliases did not inherit CAP_NETWORK"
        rc=1
    else
        echo "  selftest ok: I: MinGW import and wrapper decorations inherit the base symbol class"
    fi

    # J. The portable row is a cross-target/package claim; Windows symmetry
    # must grade the exact replacement. CAP_NONE is deliberately explicit so
    # a harmless refusal/native arm can replace a non-empty portable row.
    d="$FIXTURE_ROOT/j"; mkdir -p "$d/fixture_src" "$d/platform/modules/platform/src"
    make_epoch "$d"
    fixture_symbols "$d"
    cat > "$d/fixture_src/platform_user.c" <<'EOF'
static int local_only(int x) { return x + 1; }
int platform_export(int x) { return local_only(x); }
EOF
    cat > "$d/platform/modules/platform/src/os_sandbox_linux.c" <<'EOF'
int linux_only_fixture(void) { return 1; }
EOF
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    cc -std=c23 -c "$d/fixture_src/platform_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/platform_user.o" 2>/dev/null \
      || cc -c "$d/fixture_src/platform_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/platform_user.o"
    fixture_module_rows "$d" \
        'ZCL_MODULE_CAPABILITY("fixture_src/platform_user.c", CAP_NETWORK, "portable arm")' \
        'ZCL_MODULE_CAPABILITY("platform/modules/platform/src/os_sandbox_linux.c", CAP_NETWORK, "Linux-only arm")'
    cat > "$d/engine/composition/module_capabilities_windows.def" <<'EOF'
ZCL_MODULE_CAPABILITY("fixture_src/platform_user.c", CAP_NONE, "Windows exact empty arm")
EOF
    expect_accept "J: Windows exact CAP_NONE override replaces portable reach and skips only the named Linux arm" "$d" || rc=1

    # K. Linux exact overrides have the same replacement semantics as the
    # Windows supplement. The portable cross-target union remains intact,
    # while symmetry grades only the selected Linux arm.
    d="$FIXTURE_ROOT/k"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    cat > "$d/fixture_src/platform_user.c" <<'EOF'
static int local_only(int x) { return x + 1; }
int platform_export(int x) { return local_only(x); }
EOF
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    cc -std=c23 -c "$d/fixture_src/platform_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/platform_user.o" 2>/dev/null \
      || cc -c "$d/fixture_src/platform_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/platform_user.o"
    fixture_module_rows "$d" \
        'ZCL_MODULE_CAPABILITY("fixture_src/platform_user.c", CAP_NETWORK, "portable arm")'
    cat > "$d/engine/composition/module_capabilities_linux.def" <<'EOF'
ZCL_MODULE_CAPABILITY("fixture_src/platform_user.c", CAP_NONE, "Linux exact empty arm")
EOF
    CAP_CLOSURE_HOST_OS=Linux
    CAP_CLOSURE_HOST_WINDOWS=false
    expect_accept "K: Linux exact CAP_NONE override replaces portable cross-target reach" "$d" || rc=1

    # L. Coverage grades the exact host-selected graph, while the two real
    # standalone rows remain applicable on every host. An unselected platform
    # arm is not an honest addition to the unobserved-row baseline.
    CAP_CLOSURE_HOST_OS=Linux
    if cap_closure_coverage_applicable \
           "platform/modules/platform/src/os_sandbox_stub.c" ||
       ! cap_closure_coverage_applicable \
           "tests/harness/src/test_thread_qos.c" ||
       ! cap_closure_coverage_applicable "tools/rebuild_recent.c"; then
        echo "SELFTEST FAIL: L: Linux host-source selection or standalone rows drifted"
        rc=1
    else
        CAP_CLOSURE_HOST_OS=Darwin
        if cap_closure_coverage_applicable \
               "platform/modules/platform/src/os_sandbox_linux.c" ||
           cap_closure_coverage_applicable \
               "platform/modules/platform/src/os_sandbox_package_linux.c" ||
           cap_closure_coverage_applicable \
               "platform/modules/util/src/self_backtrace.c"; then
            echo "SELFTEST FAIL: L: Darwin host-source selection drifted"
            rc=1
        else
            CAP_CLOSURE_HOST_OS=Windows
            if cap_closure_coverage_applicable \
                   "platform/modules/platform/src/os_sandbox_linux.c" ||
               cap_closure_coverage_applicable \
                   "platform/modules/platform/src/os_sandbox_package_linux.c" ||
               cap_closure_coverage_applicable \
                   "contexts/commons/modules/vcs/src/vcs_devloop.c" ||
               cap_closure_coverage_applicable "tools/package_verify.c"; then
                echo "SELFTEST FAIL: L: Windows host-source selection drifted"
                rc=1
            else
                echo "  selftest ok: L: coverage follows exact host-source selection and retains the two standalone rows"
            fi
        fi
    fi
    CAP_CLOSURE_HOST_OS="$host_os_saved"
    CAP_CLOSURE_HOST_WINDOWS="$host_windows_saved"

    # M. A valid object with no symbols is still compiled evidence. Platform
    # guards routinely leave an inactive host arm in exactly this shape; nm
    # emits no row for it, so coverage must use the frozen object list itself.
    d="$FIXTURE_ROOT/m"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    cat > "$d/fixture_src/empty_user.c" <<'EOF'
typedef int empty_user_not_on_this_platform;
EOF
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    cc -std=c23 -c "$d/fixture_src/empty_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/empty_user.o" 2>/dev/null \
      || cc -c "$d/fixture_src/empty_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/empty_user.o"
    fixture_module_rows "$d" \
        'ZCL_MODULE_CAPABILITY("fixture_src/empty_user.c", CAP_NONE, "inactive platform arm")'
    CAP_CLOSURE_HOST_OS=Linux
    CAP_CLOSURE_HOST_WINDOWS=false
    expect_accept "M: a symbol-free object is present coverage evidence" "$d" || rc=1
    CAP_CLOSURE_HOST_OS="$host_os_saved"
    CAP_CLOSURE_HOST_WINDOWS="$host_windows_saved"

    # N. compiled-out honesty, both directions. N1: a file guarded by a
    # macro this build's real CFLAGS never define compiles only its `#else`
    # arm — the declared capability is UNOBSERVED, not a VIOLATION, and the
    # gate still exits clean. N2: an identically-shaped guard whose macro
    # THIS build's CFLAGS do define is not "compiled out" at all — a genuine
    # overdeclaration behind such a guard must still VIOLATION, proving the
    # softening above cannot be used to launder an ordinary defect.
    d="$FIXTURE_ROOT/n"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    cat > "$d/fixture_src/compiled_out_user.c" <<'EOF'
#if defined(FIXTURE_N_MISSING_MACRO)
extern int connect(int, int, int);
int use_compiled_out(void) { return connect(1, 2, 3); }
#else
typedef int compiled_out_user_unused;
#endif
EOF
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    cc -std=c23 -c "$d/fixture_src/compiled_out_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/compiled_out_user.o" 2>/dev/null \
      || cc -c "$d/fixture_src/compiled_out_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/compiled_out_user.o"
    fixture_module_rows "$d" \
        'ZCL_MODULE_CAPABILITY("fixture_src/compiled_out_user.c", CAP_NETWORK, "test: only real under FIXTURE_N_MISSING_MACRO")'
    CAP_CLOSURE_CFLAGS_OVERRIDE=""
    out="$(check_root "$d" 2>&1)"; nrc=$?
    unset CAP_CLOSURE_CFLAGS_OVERRIDE
    if [ "$nrc" -ne 0 ]; then
        echo "SELFTEST FAIL: N1: a compiled-out declaration (guard macro undefined in this build) must exit 0, got $nrc"
        echo "$out" | sed 's/^/    /'
        rc=1
    elif str_lacks "$out" "UNOBSERVED (compiled out: FIXTURE_N_MISSING_MACRO)"; then
        echo "SELFTEST FAIL: N1: never reported UNOBSERVED (compiled out: ...) naming the macro"
        echo "$out" | sed 's/^/    /'
        rc=1
    elif ! str_lacks "$out" "check_capability_closure: VIOLATION"; then
        echo "SELFTEST FAIL: N1: a compiled-out declaration must never also read as a VIOLATION"
        echo "$out" | sed 's/^/    /'
        rc=1
    else
        echo "  selftest ok: N1: a declaration behind a guard this build never defines is UNOBSERVED, exit 0, never a VIOLATION"
    fi

    d="$FIXTURE_ROOT/n2"; mkdir -p "$d/fixture_src"
    make_epoch "$d"
    fixture_symbols "$d"
    cat > "$d/fixture_src/still_overdeclared_user.c" <<'EOF'
#if defined(FIXTURE_N_PRESENT_MACRO)
static int nothing_dangerous(int x) { return x + 1; }
int still_overdeclared_export(int x) { return nothing_dangerous(x); }
#else
typedef int still_overdeclared_user_unused;
#endif
EOF
    mkdir -p "$d/build/dev-obj/epochs/fx0/fixture_src"
    cc -std=c23 -DFIXTURE_N_PRESENT_MACRO -c "$d/fixture_src/still_overdeclared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/still_overdeclared_user.o" 2>/dev/null \
      || cc -DFIXTURE_N_PRESENT_MACRO -c "$d/fixture_src/still_overdeclared_user.c" \
        -o "$d/build/dev-obj/epochs/fx0/fixture_src/still_overdeclared_user.o"
    fixture_module_rows "$d" \
        'ZCL_MODULE_CAPABILITY("fixture_src/still_overdeclared_user.c", CAP_NETWORK, "test: guard is on in this build, declaration is simply wrong")'
    CAP_CLOSURE_CFLAGS_OVERRIDE="-DFIXTURE_N_PRESENT_MACRO"
    expect_reject "N2: a guard this build DOES define is not compiled-out — genuine overdeclaration still VIOLATIONs" \
                  "still_overdeclared_user.c declares CAP_NETWORK" "$d" || rc=1
    unset CAP_CLOSURE_CFLAGS_OVERRIDE

    if [ "$rc" -eq 0 ]; then
        echo "== selftest: PASS (15/15) =="
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
