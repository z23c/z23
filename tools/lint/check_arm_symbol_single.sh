#!/usr/bin/env bash
# Gate — a non-static function is defined ONCE per translation unit
# (ratchet, shrink-only <path>\t<function> baseline).
#
# THE BUG CLASS THIS CLOSES (found live, 2026-08-29).
# lib/net/src/file_service.c splits into a `#if defined(_WIN32)` arm and a
# POSIX `#else` arm. Three PURE request parsers — fs_parse_rom_request,
# fs_parse_rom_manifest_request, fs_parse_rom_list_request — had a full body
# in BOTH arms, and the bodies had drifted apart on two axes: Windows
# required an exact payload length and refused a NULL output pointer; POSIX
# accepted any payload at least the minimum length (silently ignoring
# trailing bytes) and treated the output pointers as optional, returning
# true having written nothing. A Windows node and a Linux node could
# therefore disagree about whether identical bytes on the wire are a valid
# request — a network-splitting bug, for functions that touch no platform
# API at all and had no reason to be inside the split in the first place.
#
# WHAT THIS GATE CHECKS. The C standard already forbids two unconditional
# definitions of one external symbol in a TU — the only way a file compiles
# with a name defined twice is if the two definitions sit in mutually
# exclusive preprocessor branches. So the general defect class is not
# "duplicated inside `#if defined(_WIN32)`" specifically — it is: a
# non-static function is DEFINED (has a body) more than once, anywhere, in
# one .c file. Whatever macro (`_WIN32`, `__linux__`, `ZCL_TESTING`, a CPU
# feature flag, ...) separates the copies, every one of them is a place two
# bodies can silently drift apart under one name.
#
# WHAT THIS DOES NOT PROVE. A duplicate is not automatically a bug: a real
# OS-abstraction "platform seam" (lib/platform/src is the intentional home
# for exactly this shape — one function, N OS-specific bodies) or a real
# SIMD/feature dispatch pair can legitimately share a name across arms. This
# gate cannot tell "genuinely platform-dependent, correctly split" apart
# from "pure function, accidentally split, actively drifting" — that needs
# a human reading the two bodies. What it CAN do, and what it is for, is
# make every such pair visible so a human decides, instead of the bodies
# drifting in the dark the way the ROM parsers did. The baseline below is
# that visible list: every row is a reviewed, accepted duplicate (mostly
# genuine platform/feature/test arms); a row is removed only by fixing the
# file, never by widening the gate.
#
# WHAT IT CANNOT CHECK. It is a line-order scanner over C text, not a
# compiler (same limitation class as check_outparam_init_before_return.sh
# and check_byte_order_codec_single.sh):
#   - It does not expand macros, so a body produced entirely by a
#     function-defining macro (e.g. FS_WINDOWS_TRANSPORT_REFUSAL(name, args)
#     in file_service.c) is invisible — a real drift risk if the two arms'
#     macro expansions differ, but out of reach for a text scanner.
#   - `static` is detected by a token match on the signature's own line (or
#     the line immediately above it); a return type wrapped onto its own
#     separate line above THAT can hide a leading `static` and produce a
#     false "non-static" — the failure mode is over-reporting, not a missed
#     violation, and it has not been observed in this tree.
#   - `__attribute__((...))` and `__declspec(...)` prefixes are recognized
#     and skipped so they cannot be mistaken for the function name; a
#     C23 `[[...]]` attribute list is fine too (it has no parenthesis to
#     confuse the scanner) as long as it sits on the same physical line as
#     the signature it decorates.
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
#
# A baseline row that no longer matches (function fixed, or file deleted)
# must be DELETED, or the ratchet rusts shut at a stale list. That is
# reported as a failure too.
#
# --selftest plants: (1) two non-static bodies for the same name inside
# `#ifdef`/`#else` — must FAIL; (2) the same shape but both bodies `static`
# — must PASS (internal linkage, not this gate's class); (3) a
# `#define`-based function-generator macro invoked twice under different
# names — must PASS (no false hit from the macro's own `{`/`}`); (4) an
# `__attribute__((...))`-prefixed function on its own line above the
# signature — must PASS (the attribute must not be read as the function
# name); (5) one clean, singly-defined function — must PASS. A gate that
# cannot fail on (1) is worse than no gate; a gate that fires on (2)-(5) is
# noise that gets ignored.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE=check_arm_symbol_single
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_ARM_SYMBOL_BASELINE:-tools/lint/arm_symbol_single_baseline.txt}"
ANALYZER_NAME="arm_symbol_scan.awk"

SCAN_ROOTS_DEFAULT="app config lib src tools"
read -r -a SCAN_ROOTS <<< "${ZCL_ARM_SYMBOL_SCAN_ROOTS:-$SCAN_ROOTS_DEFAULT}"

# ── the analyzer, emitted here so --selftest and the real run share one text ──
# Reads N .c files (as awk ARGV), tracking brace depth (bdepth, are we
# inside a function body) and paren depth (pdepth, are we still inside an
# in-progress parameter list) per file — reset at FNR==1 so state never
# leaks across files in one invocation. Prints one line per non-static
# top-level function DEFINITION seen: "<file>\t<name>\t<line>\t<is_static>".
write_analyzer() {
    cat > "$1" <<'AWK_EOF'
function process_candidate(   sigfull, name, is_static) {
    sigfull = sig
    gsub(/[ \t\n]+/, " ", sigfull)
    sub(/^ +/, "", sigfull)
    if (sigfull ~ /^(typedef|struct |union |enum )/) return
    if (candidate_name == "") return
    name = candidate_name
    if (name ~ /^(if|for|while|switch|do|else|return|sizeof|defined|static_assert|_Static_assert)$/) return
    is_static = (static_hint ~ /(^|[^A-Za-z0-9_])static([^A-Za-z0-9_]|$)/) ? 1 : 0
    printf "%s\t%s\t%d\t%d\n", FILENAME, name, start_line, is_static
}

function reset_state() {
    bdepth = 0; state = "idle"; pdepth = 0; sig = ""; incomment = 0
    indefine = 0; prev_idle = ""; candidate_name = ""; static_hint = ""
}

BEGIN { reset_state() }
FNR == 1 { reset_state() }
{
    line = $0
    gsub(/"([^"\\]|\\.)*"/, "\"\"", line)
    gsub(/'"'"'([^'"'"'\\]|\\.)*'"'"'/, "CH", line)
    sub(/\/\/.*$/, "", line)
    if (incomment) {
        if (line ~ /\*\//) { sub(/^.*\*\//, "", line); incomment = 0 }
        else next
    }
    while (match(line, /\/\*/)) {
        pre = substr(line, 1, RSTART - 1)
        rest = substr(line, RSTART)
        if (match(rest, /\*\//)) { line = pre substr(rest, RSTART + 2) }
        else { line = pre; incomment = 1; break }
    }

    trimmed = line
    gsub(/^[ \t]+/, "", trimmed)
    gsub(/[ \t]+$/, "", trimmed)

    if (indefine) {
        if (trimmed !~ /\\[ \t]*$/) indefine = 0
        next
    }
    if (trimmed ~ /^#/) {
        if (trimmed ~ /\\[ \t]*$/) indefine = 1
        next
    }

    nb = gsub(/\{/, "{", line)
    ne = gsub(/\}/, "}", line)
    op = gsub(/\(/, "(", line)
    cl = gsub(/\)/, ")", line)

    # Inside a function body (or any brace-nested construct entered from
    # the "idle" state below): just track the way back out.
    if (bdepth > 0) {
        bdepth += nb - ne
        if (bdepth < 0) bdepth = 0
        next
    }

    if (state == "idle") {
        if (op == 0) {
            # A brace with no paren on the same line at depth 0 (a bare
            # struct/enum/array-literal opener) still has to be tracked or
            # bdepth desyncs from the file's real nesting.
            if (nb > 0 || ne > 0) {
                bdepth += nb - ne
                if (bdepth < 0) bdepth = 0
            }
            if (trimmed != "") prev_idle = trimmed
            next
        }
        # A "(" appeared: figure out what precedes it before deciding this
        # is a real function signature.
        p = index(line, "(")
        head = substr(line, 1, p - 1)
        if (match(head, /[A-Za-z_][A-Za-z0-9_]*[ \t]*$/)) {
            ident = substr(head, RSTART, RLENGTH)
            gsub(/[ \t]/, "", ident)
        } else ident = ""
        # SCREAMING_SNAKE_CASE immediately before "(" is this tree's own
        # convention for a macro, not a function (see FS_WINDOWS_TRANSPORT_
        # REFUSAL(name, args) in file_service.c); __attribute__/__declspec
        # are the two non-uppercase spellings of the same "not a function
        # name" case.
        is_macro = (ident != "" && (ident ~ /^[A-Z_][A-Z0-9_]*$/ || \
                    ident == "__attribute__" || ident == "__declspec")) ? 1 : 0
        pdepth = op - cl
        if (is_macro || ident == "") {
            state = "skipping"
            if (pdepth <= 0) { state = "idle"; pdepth = 0 }
            prev_idle = ""
            next
        }
        sig = line
        candidate_name = ident
        static_hint = prev_idle " " head
        start_line = FNR
        prev_idle = ""
        if (pdepth <= 0) {
            if (nb >= 1) {
                # Single-line signature + body, e.g. `bool f(x) { return x; }`.
                process_candidate()
                bdepth = nb - ne
                if (bdepth < 0) bdepth = 0
                state = "idle"; sig = ""; pdepth = 0; candidate_name = ""
            } else if (line ~ /;[ \t]*$/) {
                # A complete statement/prototype ending in ";": not a
                # definition.
                state = "idle"; sig = ""; pdepth = 0; candidate_name = ""
            } else {
                # Parens already balanced, no brace yet: K&R-style, the
                # brace is expected on a following line.
                state = "collecting"; pdepth = 0
            }
        } else {
            state = "collecting"
        }
        next
    }

    if (state == "skipping") {
        pdepth += op - cl
        if (pdepth <= 0) { state = "idle"; pdepth = 0 }
        next
    }

    if (state == "collecting") {
        sig = sig " " line
        pdepth += op - cl
        if (pdepth <= 0) {
            if (nb >= 1) {
                process_candidate()
                bdepth = nb - ne
                if (bdepth < 0) bdepth = 0
                state = "idle"; sig = ""; pdepth = 0; candidate_name = ""
            } else if (line ~ /;[ \t]*$/) {
                state = "idle"; sig = ""; pdepth = 0; candidate_name = ""
            }
            # else: parens closed but no brace and no ";" yet — stay
            # collecting, waiting for the brace on a later line.
        }
        next
    }
}
AWK_EOF
}

# ── --selftest ─────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    analyzer="$tmp/$ANALYZER_NAME"
    write_analyzer "$analyzer"

    run_dup_names() { # $1 = file; prints non-static names that appear >=2 times
        awk -f "$analyzer" -- "$1" | \
            awk -F'\t' '$4==0{c[$2]++} END{for (n in c) if (c[n]>1) print n}'
    }

    expect_dup() { # $1=msg $2=file $3=body
        printf '%s\n' "$3" > "$2"
        local hits
        hits="$(run_dup_names "$2")"
        if [ -z "$hits" ]; then
            echo "$GATE: SELFTEST FAILED — $1 (expected a duplicate, found none)" >&2
            exit 2
        fi
    }
    expect_clean() { # $1=msg $2=file $3=body
        printf '%s\n' "$3" > "$2"
        local hits
        hits="$(run_dup_names "$2")"
        if [ -n "$hits" ]; then
            echo "$GATE: SELFTEST FAILED — $1 (unexpected duplicate: $hits)" >&2
            exit 2
        fi
    }

    # (1) negative control: two non-static bodies, same name, disjoint arms.
    expect_dup "two non-static bodies of the same name in #ifdef/#else arms did not trip" \
        "$tmp/dup.c" \
'#ifdef _WIN32
bool fs_parse_thing(const uint8_t *p, uint32_t n)
{
    return n != 4;
}
#else
bool fs_parse_thing(const uint8_t *p, uint32_t n)
{
    return n < 4;
}
#endif'

    # (2) positive control: same shape, but both bodies static — not this
    # gate's class (internal linkage, no cross-arm wire-parity risk).
    expect_clean "a static duplicate across arms was flagged (should be out of scope)" \
        "$tmp/static_dup.c" \
'#ifdef _WIN32
static bool fs_parse_thing(const uint8_t *p, uint32_t n)
{
    return n != 4;
}
#else
static bool fs_parse_thing(const uint8_t *p, uint32_t n)
{
    return n < 4;
}
#endif'

    # (3) positive control: a function-generator macro invoked twice under
    # different names must not be misread as one name defined twice.
    expect_clean "a function-defining macro invoked under two different names was flagged" \
        "$tmp/macro.c" \
'#define FS_WINDOWS_TRANSPORT_REFUSAL(name_, args_) \
    bool name_ args_ { errno = ENOTSUP; return false; }

FS_WINDOWS_TRANSPORT_REFUSAL(fs_send_frame,
    (struct fs_session *s, uint32_t n))
FS_WINDOWS_TRANSPORT_REFUSAL(fs_recv_frame,
    (struct fs_session *s, uint32_t n))

void fs_server_start(const char *datadir, uint16_t port)
{ (void)datadir; (void)port; }'

    # (4) positive control: an __attribute__ line above the signature must
    # not be read as the function name (and must not swallow the real one).
    expect_clean "an __attribute__-prefixed function was flagged / misnamed" \
        "$tmp/attr.c" \
'__attribute__((target("sha,sse4.1")))
static void sha256_transform_shani(uint32_t *state, const unsigned char *data)
{
    (void)state; (void)data;
}

void sha256_transform_generic(uint32_t *state, const unsigned char *data)
{
    (void)state; (void)data;
}'

    # (5) positive control: one clean, singly-defined function.
    expect_clean "a singly-defined function was flagged" \
        "$tmp/clean.c" \
'bool fs_parse_once(const uint8_t *p, uint32_t n)
{
    return p && n > 0;
}'

    echo "[$GATE] SELFTEST PASS (cross-arm non-static dup fails; static dup," \
         "macro-generated pair, __attribute__-prefixed fn and a clean" \
         "singleton all pass)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
collect_files() {
    local root
    for root in "${SCAN_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        find "$root" -name '*.c' -type f 2>/dev/null
    done
}

mapfile -t scan_files < <(collect_files | sort)
gate_require_scanned "${#scan_files[@]}" "${ZCL_ARM_SYMBOL_FILE_FLOOR:-2500}" "$GATE" \
    "no production .c under: ${SCAN_ROOTS[*]}"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/zcl-arm-symbol.XXXXXX")" || {
    echo "$GATE: FATAL — mktemp failed." >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT
ANALYZER="$WORK/$ANALYZER_NAME"
write_analyzer "$ANALYZER"

RAW="$WORK/raw.tsv"
awk -f "$ANALYZER" -- "${scan_files[@]}" > "$RAW"

# ── Detect: a non-static name appearing >=2 times in the same file ───────
mapfile -t FOUND < <(
    awk -F'\t' '$4==0 { key=$1"\t"$2; c[key]++ } END { for (k in c) if (c[k] > 1) print k }' "$RAW" | sort
)

declare -A BASELINED=()
gate_load_list_file "$BASELINE" BASELINED baseline_count

declare -A HIT=()
violations=()
for pair in "${FOUND[@]}"; do
    if [ -n "${BASELINED[$pair]+x}" ]; then
        HIT["$pair"]=1
    else
        violations+=("$pair")
    fi
done

stale=()
for pair in "${!BASELINED[@]}"; do
    [ -z "${HIT[$pair]+x}" ] && stale+=("$pair")
done

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# $GATE baseline — <path>\\t<function> pairs where a non-static"
        echo "# function is DEFINED more than once in one translation unit"
        echo "# (necessarily in disjoint preprocessor arms — see the header"
        echo "# comment in tools/lint/$GATE.sh for the defect class and its"
        echo "# limits). One pair per line, tab-separated. THE LIST MAY ONLY"
        echo "# SHRINK."
        echo "#"
        echo "# Fix a row by either (a) hoisting the function ABOVE the"
        echo "# preprocessor split as ONE definition, with the strictest"
        echo "# semantics of the arms it replaces, when the two bodies exist"
        echo "# only because it was copy-pasted into a platform split it"
        echo "# never needed (the file_service.c ROM-parser fix is the"
        echo "# reference case), or (b) marking both bodies 'static' when a"
        echo "# real per-arm implementation is intentional and has no"
        echo "# external caller relying on a single symbol. Adding a row is"
        echo "# not a fix."
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        printf '%s\n' "${FOUND[@]}" | sort
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED: $BASELINE"
    exit 0
fi

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} new non-static duplicate definition(s)" \
         "(not in $BASELINE):"
    printf '  %s\n' "${violations[@]}" | sed 's/\t/  ->  /' | sort
    echo ""
    echo "  Either hoist the function above the platform/feature split as ONE"
    echo "  definition (strictest semantics of the arms it replaces), or mark"
    echo "  both bodies 'static' if a real per-arm implementation is"
    echo "  intentional. Adding a row to $BASELINE is NOT a fix."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — no longer duplicated." \
         "Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sed 's/\t/  ->  /' | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} files scanned, ${#FOUND[@]} duplicate" \
     "pair(s), all $baseline_count baselined)"
