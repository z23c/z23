#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# hotswap-candidates.sh — "is this file hot-swappable, and if not, why?"
#
# ── WHY THIS EXISTS ────────────────────────────────────────────────────────
# Editing a REGISTERED swappable TU and rebuilding it as a module .so is a
# ~9 second loop (tools/dev/hotswap-module-fast.sh). Editing anything else and
# rebuilding the node is ~4m45s (whole-program LTO). That is a 31x difference,
# and an agent about to open a file had no way to ask which side of the line it
# is on — so the fast loop went unused and everyone paid the slow one.
#
# This tool answers that question for ONE file, or prints the whole ledger. It
# derives EVERYTHING from the .def manifests and the same rules the lint gates
# enforce; there is no hardcoded list of files or leaves anywhere below. Add a
# row to a .def tomorrow and this tool reflects it with no edit here.
#
# ── THE THREE VERDICTS ─────────────────────────────────────────────────────
#   SWAPPABLE  registered today (a config/hotswap_swappable.def row, or a
#              config/hotswap_islands.def member of one). The 9-second loop is
#              available right now and the exact command is printed.
#   ELIGIBLE   passes every MECHANICAL rule but is not registered. The exact
#              .def rows to add are printed — together with the standing rule
#              that a lint pass is NOT an approval (see below).
#   BLOCKED    names the specific leaf and the specific rule that fails.
#
# ── A LINT PASS IS NOT AN APPROVAL ─────────────────────────────────────────
# Read the comment above HOTSWAP_SWAPPABLE("app/controllers/src/
# chain_native_handlers.c", ...) in config/hotswap_swappable.def:
# core.chain.block.get and core.chain.transaction.get are ZCL_COMMAND_READY_READ
# and pass every mechanical gate, and are STILL withheld, because they render
# block and transaction bytes. The standing rule is that anything one cannot
# argue is off the consensus path is not eligible. ELIGIBLE below therefore
# means "no mechanical rule objects", never "approved".
#
# ── USAGE ──────────────────────────────────────────────────────────────────
#   tools/dev/hotswap-candidates.sh <file.c>      verdict for ONE translation unit
#   tools/dev/hotswap-candidates.sh --all         the full ledger + coverage summary
#   tools/dev/hotswap-candidates.sh --leaf <leaf> verdict for the TU owning a leaf
#   tools/dev/hotswap-candidates.sh --summary     the coverage summary line only
#
# Exit: 0 SWAPPABLE (or a clean --all/--summary), 1 ELIGIBLE, 2 BLOCKED or
# misuse. Read-only: touches no datadir, starts nothing, activates nothing.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2

SWAPPABLE_DEF="${ZCL_HOTSWAP_SWAPPABLE_MANIFEST:-config/hotswap_swappable.def}"
ELIGIBLE_DEF="${ZCL_HOTSWAP_MANIFEST:-config/hotswap_eligible.def}"
ISLANDS_DEF="${ZCL_HOTSWAP_ISLAND_MANIFEST:-config/hotswap_islands.def}"
DENIED_DEF="${ZCL_HOTSWAP_DENIED_LEAVES:-config/hotswap_denied_leaves.def}"
PROBE_DEF="${ZCL_HOTSWAP_PROBE_CASES:-config/hotswap_probe_cases.def}"
SERVICES_DEF="${ZCL_HOTSWAP_SERVICES:-config/hotswap_services.def}"
CMD_DEF_DIR="${ZCL_HOTSWAP_COMMAND_DEF_DIR:-config/commands}"
BRIDGE_TU="${ZCL_HOTSWAP_BRIDGE_TU:-tools/command/native_command.c}"

# The shape roots, copied verbatim from the two gates that enforce them:
#   tools/lint/check_hotswap_swappable_shape.sh  (ALLOWED / FORBIDDEN)
#   tools/lint/check_hotswap_eligible_scope.sh   (FORBIDDEN)
SHAPE_ALLOWED='^(app/controllers|app/views|app/conditions)/'
SHAPE_FORBIDDEN='^(core|lib/consensus|lib/validation|lib/storage|lib/net|lib/coins|lib/chain|lib/mining|app/jobs|lib/kernel|lib/supervisor|app/supervisors|domain/consensus)/'

die() { echo "hotswap-candidates: $*" >&2; exit 2; }

for f in "$SWAPPABLE_DEF" "$ELIGIBLE_DEF" "$ISLANDS_DEF" "$DENIED_DEF" \
         "$PROBE_DEF" "$BRIDGE_TU"; do
    [ -r "$f" ] || die "FATAL — required manifest '$f' missing/unreadable (refusing to answer off a hollow parse)"
done
[ -d "$CMD_DEF_DIR" ] || die "FATAL — command catalog dir '$CMD_DEF_DIR' missing"

# ── Build-free macro walker ────────────────────────────────────────────────
# Same COLUMN-1, paren-depth, string-literal-aware walk the lint gates use, so
# the prose in a .def header comment (which spells the macro signature out) is
# never mistaken for a row.
MACRO_AWK='
{ buf = buf $0 "\n" }
END {
    n = length(buf); L = length(TOK)
    i = 1
    while (i <= n) {
        if (substr(buf, i, L) != TOK || (i > 1 && substr(buf, i - 1, 1) != "\n")) {
            i++; continue
        }
        j = i + L; depth = 1; in_str = 0; esc = 0; spec = ""
        while (j <= n && depth > 0) {
            c = substr(buf, j, 1)
            if (in_str) {
                if (esc) { esc = 0 }
                else if (c == "\\") { esc = 1 }
                else if (c == "\"") { in_str = 0 }
            } else {
                if (c == "\"") { in_str = 1 }
                else if (c == "(") { depth++ }
                else if (c == ")") { depth-- }
            }
            if (depth > 0) spec = spec c
            j++
        }
        out = ""; rest = spec
        for (k = 0; k < ARGN; k++) {
            v = ""
            if (k == ARGN - 1 && JOIN_LAST) {
                # C adjacent-string-literal concatenation: the LAST requested
                # argument absorbs every remaining literal, joined. Without
                # this a multi-line reason/description is silently truncated
                # to its first fragment.
                while (match(rest, /"[^"]*"/)) {
                    v = v substr(rest, RSTART + 1, RLENGTH - 2)
                    rest = substr(rest, RSTART + RLENGTH)
                }
            } else if (match(rest, /"[^"]*"/)) {
                v = substr(rest, RSTART + 1, RLENGTH - 2)
                rest = substr(rest, RSTART + RLENGTH)
            }
            out = out (k ? "\t" : "") v
        }
        print out
        i = j
    }
}'

macro_rows() {  # TOK ARGN FILE... ; ZCL_JOIN_LAST=1 to concatenate trailing literals
    local tok="$1" argn="$2"; shift 2
    LC_ALL=C awk -v TOK="$tok" -v ARGN="$argn" -v JOIN_LAST="${ZCL_JOIN_LAST:-0}" \
        "$MACRO_AWK" "$@"
}

# ── The command catalog: every ZCL_COMMAND_* leaf, its macro form, its
#    documented CLI example, and its bound handler symbol. ────────────────
# Emits: macro <TAB> leaf <TAB> example <TAB> handler_symbol
CATALOG_AWK='
{ buf = buf $0 "\n" }
END {
    n = length(buf)
    i = 1
    while (i <= n) {
        if (substr(buf, i, 12) != "ZCL_COMMAND_" || (i > 1 && substr(buf, i - 1, 1) != "\n")) {
            i++; continue
        }
        j = i; name = ""
        while (j <= n && substr(buf, j, 1) ~ /[A-Za-z0-9_]/) { name = name substr(buf, j, 1); j++ }
        if (substr(buf, j, 1) != "(") { i = j; continue }
        j++; depth = 1; in_str = 0; esc = 0; spec = ""
        while (j <= n && depth > 0) {
            c = substr(buf, j, 1)
            if (in_str) {
                if (esc) { esc = 0 }
                else if (c == "\\") { esc = 1 }
                else if (c == "\"") { in_str = 0 }
            } else {
                if (c == "\"") { in_str = 1 }
                else if (c == "(") { depth++ }
                else if (c == ")") { depth-- }
            }
            if (depth > 0) spec = spec c
            j++
        }
        leaf = ""; ex = ""; first = 1; rest = spec
        while (match(rest, /"([^"\\]|\\.)*"/)) {
            v = substr(rest, RSTART + 1, RLENGTH - 2)
            rest = substr(rest, RSTART + RLENGTH)
            if (first) { leaf = v; first = 0 }
            # The catalog example field is the CLI invocation and always begins
            # "z23 ". Take the LAST such literal: a description literal may also
            # quote a command, and the example field comes after the description.
            if (substr(v, 1, 4) == "z23 ") ex = v
        }
        h = ""
        if (match(spec, /[A-Za-z_][A-Za-z0-9_]*[ \t\n]*$/)) {
            h = substr(spec, RSTART, RLENGTH); gsub(/[ \t\n]/, "", h)
        }
        if (leaf != "") print name "\t" leaf "\t" ex "\t" h
        i = j
    }
}'

declare -A LEAF_MACRO=() LEAF_EXAMPLE=() LEAF_HANDLER=() READY_READ=()
ready_read_total=0
catalog_rows=0
while IFS=$'\t' read -r macro leaf example handler; do
    [ -n "$leaf" ] || continue
    catalog_rows=$((catalog_rows + 1))
    LEAF_MACRO["$leaf"]="$macro"
    LEAF_EXAMPLE["$leaf"]="$example"
    LEAF_HANDLER["$leaf"]="$handler"
    if [ "$macro" = "ZCL_COMMAND_READY_READ" ]; then
        READY_READ["$leaf"]=1
        ready_read_total=$((ready_read_total + 1))
    fi
done < <(LC_ALL=C awk "$CATALOG_AWK" "$CMD_DEF_DIR"/*.def)

[ "$catalog_rows" -ge 1 ] || die "FATAL — parsed zero command rows from $CMD_DEF_DIR/*.def"
[ "$ready_read_total" -ge 1 ] || die "FATAL — parsed zero ZCL_COMMAND_READY_READ leaves from $CMD_DEF_DIR/*.def"

# ── Manifests ──────────────────────────────────────────────────────────────
declare -A SWAP_LEAVES=() ELIGIBLE_PROBE=() ISLAND_MEMBERS=() MEMBER_OWNER=()
declare -A DENIED_REASON=() PROBE_CASE_INPUT=() PROBE_CASE_ID=()
swap_tu_order=()
swap_leaf_total=0

while IFS=$'\t' read -r tu leaves; do
    [ -n "$tu" ] || continue
    SWAP_LEAVES["$tu"]="$leaves"
    swap_tu_order+=("$tu")
    for l in $leaves; do swap_leaf_total=$((swap_leaf_total + 1)); done
done < <(macro_rows 'HOTSWAP_SWAPPABLE(' 2 "$SWAPPABLE_DEF")
[ "${#swap_tu_order[@]}" -ge 1 ] || die "FATAL — parsed zero HOTSWAP_SWAPPABLE rows from $SWAPPABLE_DEF"
[ "$swap_leaf_total" -ge 1 ] || die "FATAL — parsed zero swappable leaves from $SWAPPABLE_DEF"

while IFS=$'\t' read -r tu probe; do
    [ -n "$tu" ] || continue
    ELIGIBLE_PROBE["$tu"]="$probe"
done < <(macro_rows 'HOTSWAP_ELIGIBLE(' 1 "$ELIGIBLE_DEF" | while IFS= read -r p; do
    [ -n "$p" ] || continue
    pr="$(LC_ALL=C sed -n "s|^[[:space:]]*HOTSWAP_ELIGIBLE(\"$(printf '%s' "$p" | LC_ALL=C sed 's/[][\.*^$/]/\\&/g')\")[[:space:]]*HOTSWAP_PROBE(\"\([^\"]*\)\").*|\1|p" "$ELIGIBLE_DEF" | head -1)"
    printf '%s\t%s\n' "$p" "$pr"
done)
[ "${#ELIGIBLE_PROBE[@]}" -ge 1 ] || die "FATAL — parsed zero HOTSWAP_ELIGIBLE rows from $ELIGIBLE_DEF"

island_member_total=0
while IFS=$'\t' read -r owner members; do
    [ -n "$owner" ] || continue
    ISLAND_MEMBERS["$owner"]="$members"
    for m in $members; do
        MEMBER_OWNER["$m"]="$owner"
        island_member_total=$((island_member_total + 1))
    done
done < <(macro_rows 'HOTSWAP_ISLAND(' 2 "$ISLANDS_DEF")
[ "$island_member_total" -ge 1 ] || die "FATAL — parsed zero HOTSWAP_ISLAND members from $ISLANDS_DEF"

while IFS=$'\t' read -r leaf reason; do
    [ -n "$leaf" ] || continue
    DENIED_REASON["$leaf"]="$reason"
done < <(ZCL_JOIN_LAST=1 macro_rows 'HOTSWAP_DENIED_LEAF(' 2 "$DENIED_DEF")
[ "${#DENIED_REASON[@]}" -ge 1 ] || die "FATAL — parsed zero HOTSWAP_DENIED_LEAF rows from $DENIED_DEF (the denylist fails CLOSED)"

declare -A SERVICE_ID=()
while IFS=$'\t' read -r sid stu; do
    [ -n "$stu" ] || continue
    SERVICE_ID["$stu"]="$sid"
done < <(macro_rows 'HOTSWAP_SERVICE(' 2 "$SERVICES_DEF")

while IFS=$'\t' read -r case_id kind op input _rest; do
    [ -n "$op" ] || continue
    PROBE_CASE_INPUT["$op"]="$input"
    PROBE_CASE_ID["$op"]="$case_id"
done < <(macro_rows 'HOTSWAP_PROBE_CASE(' 5 "$PROBE_DEF")
[ "${#PROBE_CASE_INPUT[@]}" -ge 1 ] || die "FATAL — parsed zero HOTSWAP_PROBE_CASE rows from $PROBE_DEF"

# ── Leaf -> body symbol, for leaves bound to the generic native bridge ─────
# tools/command/native_command.c holds the ONLY leaf->body binding table. A
# READY_READ leaf whose catalog handler is the generic bridge resolves through
# it; a leaf in g_bridge_rpc_direct[] has no controller body at all (the bridge
# forwards it to a JSON-RPC method itself).
declare -A BRIDGE_BODY=() BRIDGE_DIRECT=()
BRIDGE_TABLE_AWK='
BEGIN { in_body = 0; in_direct = 0 }
/g_bridge_native_body\[\][ \t]*=[ \t]*\{/ { in_body = 1; next }
/g_bridge_rpc_direct\[\][ \t]*=[ \t]*\{/ { in_direct = 1; next }
in_body || in_direct {
    if ($0 ~ /^\};/) { in_body = 0; in_direct = 0; next }
    line = $0
    if (in_body) {
        if (match(line, /\{[ \t]*"[^"]+"[ \t]*,[ \t]*[A-Za-z_][A-Za-z0-9_]*/)) {
            seg = substr(line, RSTART, RLENGTH)
            if (match(seg, /"[^"]+"/)) {
                leaf = substr(seg, RSTART + 1, RLENGTH - 2)
                tail = substr(seg, RSTART + RLENGTH)
                if (match(tail, /[A-Za-z_][A-Za-z0-9_]*/))
                    print "body\t" leaf "\t" substr(tail, RSTART, RLENGTH)
            }
            pending = ""
        } else if (match(line, /\{[ \t]*"[^"]+"[ \t]*,[ \t]*$/)) {
            # binding wrapped across two lines
            seg = substr(line, RSTART, RLENGTH)
            match(seg, /"[^"]+"/)
            pending = substr(seg, RSTART + 1, RLENGTH - 2)
        } else if (pending != "" && match(line, /[A-Za-z_][A-Za-z0-9_]*/)) {
            print "body\t" pending "\t" substr(line, RSTART, RLENGTH)
            pending = ""
        }
    } else if (in_direct) {
        if (match(line, /\{[ \t]*"[^"]+"[ \t]*,/)) {
            seg = substr(line, RSTART, RLENGTH)
            match(seg, /"[^"]+"/)
            print "direct\t" substr(seg, RSTART + 1, RLENGTH - 2) "\t-"
        }
    }
}'
while IFS=$'\t' read -r kind leaf sym; do
    case "$kind" in
        body) BRIDGE_BODY["$leaf"]="$sym" ;;
        direct) BRIDGE_DIRECT["$leaf"]=1 ;;
    esac
done < <(LC_ALL=C awk "$BRIDGE_TABLE_AWK" "$BRIDGE_TU")
[ "${#BRIDGE_BODY[@]}" -ge 1 ] || die "FATAL — parsed zero g_bridge_native_body[] bindings from $BRIDGE_TU"

# ── Symbol -> defining .c file, and leaf -> owning translation unit ───────
# Built LAZILY. The scan below is the only expensive thing this tool does
# (~1.2 s: one awk pass over every app/, tools/ and lib/ .c). The paths that
# do not need it — `--leaf <denied>`, `--leaf <not-READY_READ>` — answer from
# the manifests alone and must stay instant, and the lint gate that drives
# this tool several times per run pays the cost once per invocation instead
# of unconditionally.
declare -A SYM_FILE=() LEAF_BODY_TU=() LEAF_OWNER=() LEAF_BLOCK=()
declare -A TU_LEAVES=() NAT_LEAVES=()
OWNERSHIP_RESOLVED=0
resolve_ownership() {
    [ "$OWNERSHIP_RESOLVED" = 1 ] && return 0
    OWNERSHIP_RESOLVED=1
    local sym file leaf handler body_tu owner other cur tu
    local sym_defs=0

while IFS=$'\t' read -r sym file; do
    [ -n "$sym" ] || continue
    [ -n "${SYM_FILE[$sym]:-}" ] && continue
    SYM_FILE["$sym"]="$file"
    sym_defs=$((sym_defs + 1))
done < <(LC_ALL=C find app tools lib -name '*.c' -type f -print0 2>/dev/null \
    | LC_ALL=C xargs -0 awk '
        /^[A-Za-z_]/ {
            line = $0
            p = index(line, "(")
            if (p < 2) next
            head = substr(line, 1, p - 1)
            if (match(head, /[A-Za-z_][A-Za-z0-9_]*[ \t]*$/)) {
                s = substr(head, RSTART, RLENGTH); gsub(/[ \t]/, "", s)
                if (s != "" && head != s) print s "\t" FILENAME
            }
        }')
[ "$sym_defs" -ge 1 ] || die "FATAL — symbol index is empty (the definition scan found nothing)"

for leaf in "${!READY_READ[@]}"; do
    handler="${LEAF_HANDLER[$leaf]:-}"
    body_tu=""
    if [ -n "${BRIDGE_DIRECT[$leaf]:-}" ]; then
        LEAF_BLOCK["$leaf"]="pure JSON-RPC pass-through (g_bridge_rpc_direct[] in $BRIDGE_TU): no controller body exists to recompile"
        continue
    fi
    sym="$handler"
    if [ "$handler" = "zcl_native_bridge_command" ]; then
        sym="${BRIDGE_BODY[$leaf]:-}"
        if [ -z "$sym" ]; then
            LEAF_BLOCK["$leaf"]="bound to the generic bridge but absent from g_bridge_native_body[] in $BRIDGE_TU: no body symbol to re-point"
            continue
        fi
    fi
    if [ -z "$sym" ]; then
        LEAF_BLOCK["$leaf"]="catalog row declares no handler symbol"
        continue
    fi
    body_tu="${SYM_FILE[$sym]:-}"
    if [ -z "$body_tu" ]; then
        LEAF_BLOCK["$leaf"]="handler symbol '$sym' has no definition site in app/, tools/ or lib/"
        continue
    fi
    LEAF_BODY_TU["$leaf"]="$body_tu"
    owner="${MEMBER_OWNER[$body_tu]:-$body_tu}"
    LEAF_OWNER["$leaf"]="$owner"
    TU_LEAVES["$owner"]="${TU_LEAVES[$owner]:-}${TU_LEAVES[$owner]:+ }$leaf"
    # NAT_LEAVES is the ownership the CODE implies, before any manifest row
    # overrides it. The difference between the two is what a registered row
    # leaves on the table.
    NAT_LEAVES["$owner"]="${NAT_LEAVES[$owner]:-}${NAT_LEAVES[$owner]:+ }$leaf"
done

# A registered row is authoritative about ownership even when the leaf's body
# resolves elsewhere (or not at all) — the row IS the contract.
for tu in "${swap_tu_order[@]}"; do
    for leaf in ${SWAP_LEAVES[$tu]}; do
        cur="${LEAF_OWNER[$leaf]:-}"
        [ "$cur" = "$tu" ] && continue
        if [ -n "$cur" ]; then
            TU_LEAVES["$cur"]="$(printf '%s\n' ${TU_LEAVES[$cur]:-} | LC_ALL=C grep -vxF "$leaf" | tr '\n' ' ')"
            TU_LEAVES["$cur"]="${TU_LEAVES[$cur]% }"
        fi
        LEAF_OWNER["$leaf"]="$tu"
        case " ${TU_LEAVES[$tu]:-} " in
            *" $leaf "*) ;;
            *) TU_LEAVES["$tu"]="${TU_LEAVES[$tu]:-}${TU_LEAVES[$tu]:+ }$leaf" ;;
        esac
    done
done

}

# ── Helpers ────────────────────────────────────────────────────────────────

# Mutable file-scope statics: the exact heuristic of
# tools/lint/check_hotswap_static_state.sh, so a verdict here and that gate
# cannot disagree.
detect_statics() {
    [ -f "$1" ] || return 0
    LC_ALL=C awk '
        /hotswap-static-ok:/ { next }
        /^static[ \t]/ {
            line = $0
            if (line ~ /\<const\>/)   next
            if (line ~ /\(/)          next
            if (line ~ /=/ || line ~ /\[/ || line ~ /\{[ \t]*$/)
                printf "%s:%d: %s\n", FILENAME, FNR, line
        }
    ' "$1"
}

# A non-zero exit here is a VERDICT, not a failure. Say so once, where an
# agent will see it, because `make hotswap FILE=...` surfaces it as
# "make: *** Error 1" and that reads like the tool broke.
exit_note() {
    echo
    echo "  (exit 0 = SWAPPABLE, 1 = ELIGIBLE, 2 = BLOCKED. This verdict exits $1,"
    echo "   which \`make hotswap FILE=...\` reports as \"Error $1\" — that is the"
    echo "   verdict, not a tool failure.)"
}

has_module_table() {
    [ -f "$1" ] || return 1
    LC_ALL=C grep -q 'ZCL_HOTSWAP_MODULE_LEAVES[[:space:]]*(' -- "$1"
}

# The ARGS string for `make hotswap-try`. Preference order:
#   1. the catalog's own documented CLI example, when it is a bare route (no
#      flags, no <placeholder>, no quoting) — that is a route the CLI declares
#      it accepts;
#   2. the canonical dotted leaf path with dots as spaces.
# Neither ever carries a datadir: hotswap-try supplies the dev lane itself.
probe_args_for_leaf() {
    local leaf="$1" ex="${LEAF_EXAMPLE[$1]:-}"
    if [ -n "$ex" ]; then
        local route="${ex#z23 }"
        case "$route" in
            *"<"*|*"'"*|*'"'*|*"="*|*"\\"*|*"--"*|"$ex") ;;
            *) printf '%s\n' "$route"; return 0 ;;
        esac
    fi
    printf '%s\n' "${leaf//./ }"
}

# The leaf a TU's probe should use: its declared HOTSWAP_PROBE when registered,
# else the first of its leaves that has a `{}` canonical probe case, else its
# first leaf.
probe_leaf_for_tu() {
    local tu="$1" declared="${ELIGIBLE_PROBE[$tu]:-}" leaves="$2" l
    if [ -n "$declared" ]; then printf '%s\n' "$declared"; return 0; fi
    for l in $leaves; do
        [ "${PROBE_CASE_INPUT[$l]:-}" = "{}" ] && { printf '%s\n' "$l"; return 0; }
    done
    for l in $leaves; do printf '%s\n' "$l"; return 0; done
    printf '\n'
}

swappable_command_for() {  # tu
    local tu="$1" leaves="${SWAP_LEAVES[$1]}" pl args
    pl="$(probe_leaf_for_tu "$tu" "$leaves")"
    args="$(probe_args_for_leaf "$pl")"
    printf 'make hotswap-try FILE=%s ARGS="%s"\n' "$tu" "$args"
}

# ── Verdict for one translation unit ───────────────────────────────────────
# Prints a full report. Returns 0 SWAPPABLE, 1 ELIGIBLE, 2 BLOCKED.
verdict_tu() {
    resolve_ownership
    local tu="$1" verbose="${2:-1}"
    local leaves="${TU_LEAVES[$tu]:-}"
    local owner statics l reason bad

    # 1. Already registered.
    if [ -n "${SWAP_LEAVES[$tu]:-}" ]; then
        [ "$verbose" = 1 ] && {
            echo "VERDICT: SWAPPABLE — registered in $SWAPPABLE_DEF"
            echo "  file:   $tu"
            echo "  leaves: ${SWAP_LEAVES[$tu]}"
            echo "  probe:  ${ELIGIBLE_PROBE[$tu]:-(none declared)}"
            [ -n "${ISLAND_MEMBERS[$tu]:-}" ] && \
              echo "  island: ${ISLAND_MEMBERS[$tu]}"
            echo
            echo "  Edit it and see the change in ~9 seconds:"
            echo "    $(swappable_command_for "$tu")"
            echo "  Build the module only (no run):"
            echo "    tools/dev/hotswap-module-fast.sh FILE=$tu"
            echo "  Prove the row is loadable (no node, no datadir):"
            echo "    make hotswap-verify FILE=$tu"
            local pl pin
            pl="$(probe_leaf_for_tu "$tu" "${SWAP_LEAVES[$tu]}")"
            pin="${PROBE_CASE_INPUT[$pl]:-}"
            if [ -n "$pin" ] && [ "$pin" != "{}" ]; then
                echo "  Note: the resident probe case for '$pl' is not empty input;"
                echo "        probe-before-publish uses ${PROBE_CASE_ID[$pl]} with input $pin"
            fi
            local withheld_denied="" withheld_open="" l
            for l in ${NAT_LEAVES[$tu]:-}; do
                case " ${SWAP_LEAVES[$tu]} " in *" $l "*) continue ;; esac
                if [ -n "${DENIED_REASON[$l]:-}" ]; then
                    withheld_denied="${withheld_denied}${withheld_denied:+$'\n'}    $l — ${DENIED_REASON[$l]}"
                else
                    withheld_open="${withheld_open}${withheld_open:+$'\n'}    $l"
                fi
            done
            if [ -n "$withheld_denied" ]; then
                echo
                echo "  This TU also owns leaves DENIED by $DENIED_DEF."
                echo "  A module built from it must never re-point them:"
                printf '%s\n' "$withheld_denied"
            fi
            if [ -n "$withheld_open" ]; then
                echo
                echo "  This TU also owns READY_READ leaves that its row does NOT list, and"
                echo "  that no denylist row explains. A swap re-points only listed leaves, so"
                echo "  these keep dispatching into the RESIDENT build — an edit to their body"
                echo "  will NOT show up through hotswap-try. Either add them to the row (with"
                echo "  an argument) or record why they are withheld:"
                printf '%s\n' "$withheld_open"
            fi
        }
        return 0
    fi

    # 2. An island member of a registered row — editing it IS the fast loop.
    owner="${MEMBER_OWNER[$tu]:-}"
    if [ -n "$owner" ] && [ -n "${SWAP_LEAVES[$owner]:-}" ]; then
        [ "$verbose" = 1 ] && {
            echo "VERDICT: SWAPPABLE — island member of $owner"
            echo "  file:   $tu"
            echo "  This TU is compiled INTO that module (config/hotswap_islands.def),"
            echo "  so editing it gets the same ~9 second loop through its owner:"
            echo "    $(swappable_command_for "$owner")"
        }
        return 0
    fi

    # 3. Mechanical rules.
    bad=""
    LAST_BLOCK_CLASS="other"
    case "$tu" in
        *.c) ;;
        *) bad="not a .c translation unit"; LAST_BLOCK_CLASS="shape" ;;
    esac
    [ -z "$bad" ] && [ ! -f "$tu" ] && { bad="file does not exist"; LAST_BLOCK_CLASS="missing"; }
    [ -z "$bad" ] && [[ "$tu" =~ $SHAPE_FORBIDDEN ]] && \
        { bad="under a forbidden consensus/state/supervisor root — check_hotswap_swappable_shape.sh FORBIDDEN='$SHAPE_FORBIDDEN'. Consensus, validation, storage, net, coins, chain, mining, reducer stages, the kernel and supervisors are NEVER hot-swappable, not even in dev."
          LAST_BLOCK_CLASS="forbidden-root"; }
    [ -z "$bad" ] && [[ ! "$tu" =~ $SHAPE_ALLOWED ]] && \
        { bad="not under an allowed shape-leaf folder (app/controllers/, app/views/, app/conditions/) — a swappable TU must be a controller/view/condition LEAF. check_hotswap_swappable_shape.sh ALLOWED='$SHAPE_ALLOWED'."
          LAST_BLOCK_CLASS="not-a-shape-leaf"; }
    if [ -z "$bad" ] && [ -z "$leaves" ]; then
        bad="owns no ZCL_COMMAND_READY_READ command leaf, so a module built from it would re-point nothing"
        LAST_BLOCK_CLASS="no-leaf"
    fi
    if [ -n "$bad" ]; then
        [ "$verbose" = 1 ] && {
            echo "VERDICT: BLOCKED"
            echo "  file: $tu"
            echo "  rule: $bad"
            if [ -n "$leaves" ]; then
                echo "  leaves this TU owns: $leaves"
            fi
            if [ -n "${SERVICE_ID[$tu]:-}" ]; then
                echo "  note: this TU IS registered in $SERVICES_DEF as pure service"
                echo "        island '${SERVICE_ID[$tu]}'. That is the HOT_SHADOW"
                echo "        proposal surface — compiled as a candidate, KAT-run in a"
                echo "        disposable fork, never loaded or activated. It does NOT"
                echo "        give the ~9 second hotswap-try loop."
            fi
            exit_note 2
        }
        return 2
    fi

    # Per-leaf rules: the denylist, then READY_READ, then unique ownership.
    local denied_hits="" nonready_hits="" claimed_hits="" ok_leaves=""
    for l in $leaves; do
        if [ -n "${DENIED_REASON[$l]:-}" ]; then
            denied_hits="${denied_hits}${denied_hits:+$'\n'}  $l -> $DENIED_DEF: ${DENIED_REASON[$l]}"
            continue
        fi
        if [ -z "${READY_READ[$l]:-}" ]; then
            nonready_hits="${nonready_hits}${nonready_hits:+$'\n'}  $l -> declared ${LEAF_MACRO[$l]:-<unknown>}, not ZCL_COMMAND_READY_READ"
            continue
        fi
        local claimer=""
        for other in "${swap_tu_order[@]}"; do
            case " ${SWAP_LEAVES[$other]} " in *" $l "*) claimer="$other" ;; esac
        done
        if [ -n "$claimer" ]; then
            claimed_hits="${claimed_hits}${claimed_hits:+$'\n'}  $l -> already claimed by $claimer (a leaf belongs to exactly one file)"
            continue
        fi
        ok_leaves="${ok_leaves}${ok_leaves:+ }$l"
    done

    statics="$(detect_statics "$tu")"

    if [ -z "$ok_leaves" ] || [ -n "$statics" ]; then
        if [ -n "$statics" ]; then LAST_BLOCK_CLASS="mutable-static"
        elif [ -n "$denied_hits" ]; then LAST_BLOCK_CLASS="denied-leaf"
        elif [ -n "$claimed_hits" ]; then LAST_BLOCK_CLASS="leaf-already-owned"
        elif [ -n "$nonready_hits" ]; then LAST_BLOCK_CLASS="not-ready-read"
        else LAST_BLOCK_CLASS="no-leaf"; fi
        [ "$verbose" = 1 ] && {
            echo "VERDICT: BLOCKED"
            echo "  file: $tu"
            if [ -n "$statics" ]; then
                echo "  rule: defines a mutable file-scope static — a module .so gets its own"
                echo "        zero-initialized copy and the live process state is silently lost"
                echo "        (tools/lint/check_hotswap_static_state.sh):"
                printf '%s\n' "$statics" | LC_ALL=C sed 's/^/          /'
                echo "        Move it to a sibling NON-swappable resident TU, or annotate the"
                echo "        declaration line  hotswap-static-ok: <reason>  if provably swap-safe."
            fi
            if [ -n "$denied_hits" ]; then
                echo "  rule: leaf is on the hot-swap DENYLIST (an owner decision, not a lint preference):"
                printf '%s\n' "$denied_hits"
            fi
            [ -n "$nonready_hits" ] && {
                echo "  rule: leaf is not READY + read-only:"
                printf '%s\n' "$nonready_hits"; }
            [ -n "$claimed_hits" ] && {
                echo "  rule: leaf is already owned:"
                printf '%s\n' "$claimed_hits"; }
            [ -z "$statics$denied_hits$nonready_hits$claimed_hits" ] && \
                echo "  rule: no swappable leaf remains after the per-leaf rules"
            exit_note 2
        }
        return 2
    fi

    # 4. ELIGIBLE — mechanical only.
    if [ "$verbose" = 1 ]; then
        local pl args pin
        pl="$(probe_leaf_for_tu "$tu" "$ok_leaves")"
        args="$(probe_args_for_leaf "$pl")"
        pin="${PROBE_CASE_INPUT[$pl]:-}"
        echo "VERDICT: ELIGIBLE — passes every MECHANICAL rule, NOT registered"
        echo "  file:   $tu"
        echo "  leaves: $ok_leaves"
        [ -n "$denied_hits$nonready_hits$claimed_hits" ] && {
            echo "  excluded from the row above:"
            [ -n "$denied_hits" ] && printf '%s\n' "$denied_hits"
            [ -n "$nonready_hits" ] && printf '%s\n' "$nonready_hits"
            [ -n "$claimed_hits" ] && printf '%s\n' "$claimed_hits"; }
        echo
        echo "  ── THIS IS NOT AN APPROVAL ─────────────────────────────────────────"
        echo "  ELIGIBLE means no mechanical rule objects. It does NOT mean the file"
        echo "  may be registered. The standing rule is that anything one cannot"
        echo "  argue is off the CONSENSUS PATH is not eligible, and a lint pass"
        echo "  cannot make that argument. core.chain.block.get and"
        echo "  core.chain.transaction.get are ZCL_COMMAND_READY_READ, pass every"
        echo "  gate, and are deliberately withheld for exactly this reason (see the"
        echo "  comment above the chain_native_handlers.c row in $SWAPPABLE_DEF)."
        echo "  A human has to make and record that argument before these rows land."
        echo
        echo "  ── ROWS TO ADD, once that argument is made ─────────────────────────"
        echo "  $ELIGIBLE_DEF:"
        echo "    HOTSWAP_ELIGIBLE(\"$tu\") HOTSWAP_PROBE(\"$pl\")"
        echo
        echo "  $SWAPPABLE_DEF:"
        echo "    /* <one line saying what these leaves project, and why that is off"
        echo "       the consensus path> */"
        echo "    HOTSWAP_SWAPPABLE(\"$tu\","
        echo "                      \"$ok_leaves\")"
        if [ -z "$pin" ]; then
            echo
            echo "  $PROBE_DEF (the probe has no resident case yet;"
            echo "  check_hotswap_eligible_scope.sh requires EXACTLY one):"
            echo "    HOTSWAP_PROBE_CASE(\"command.<id>.v1\", \"command\","
            echo "        \"$pl\", \"{}\", \"<zcl.output_schema.vN>\", 4096)"
        fi
        if ! has_module_table "$tu"; then
            echo
            echo "  $tu still needs its module leaf table — without it the .so exports"
            echo "  no zcl_hotswap_module and the loader refuses it at the manifest stage:"
            echo "    #ifdef ZCL_HOTSWAP_MODULE_GEN"
            echo "    ZCL_HOTSWAP_TRAMPOLINE(module_tramp_<name>, <body_fn>)"
            echo "    static const struct zcl_hotswap_leaf k_module_leaves[] = { ... };"
            echo "    ZCL_HOTSWAP_MODULE_LEAVES(k_module_leaves, module_selftest_<name>)"
            echo "    #endif"
        fi
        # Bodies that live outside this TU and outside its island would be
        # imported from the resident node at dlopen: the leaf would be
        # re-pointed into the OLD code and the swap would silently do nothing.
        local outside=""
        for l in $ok_leaves; do
            local btu="${LEAF_BODY_TU[$l]:-}"
            [ -z "$btu" ] && continue
            [ "$btu" = "$tu" ] && continue
            [ "${MEMBER_OWNER[$btu]:-}" = "$tu" ] && continue
            outside="${outside}${outside:+$'\n'}    $l body is $btu"
        done
        if [ -n "$outside" ]; then
            echo
            echo "  $ISLANDS_DEF — these leaf bodies live OUTSIDE $tu. A body outside the"
            echo "  module is imported from the resident node at dlopen, so the leaf would"
            echo "  dispatch into the OLD code and the swap would silently do nothing:"
            printf '%s\n' "$outside"
            echo "    HOTSWAP_ISLAND(\"$tu\", \"<those .c files>\")"
        fi
        echo
        echo "  Then: make lint && make hotswap-verify FILE=$tu"
        echo "  Then the loop becomes: make hotswap-try FILE=$tu ARGS=\"$args\""
        exit_note 1
    fi
    return 1
}

# ── Ledger ─────────────────────────────────────────────────────────────────
print_summary() {
    local pct_leaf pct_tu ctl_total
    ctl_total="$(LC_ALL=C find app/controllers -name '*.c' -type f 2>/dev/null | LC_ALL=C wc -l)"
    [ "$ctl_total" -ge 1 ] 2>/dev/null || ctl_total=0
    pct_leaf="$(LC_ALL=C awk -v a="$swap_leaf_total" -v b="$ready_read_total" 'BEGIN{ if (b) printf "%.1f", 100*a/b; else printf "0.0" }')"
    pct_tu="$(LC_ALL=C awk -v a="${#swap_tu_order[@]}" -v b="$ctl_total" 'BEGIN{ if (b) printf "%.1f", 100*a/b; else printf "0.0" }')"
    echo "SUMMARY: leaves ${swap_leaf_total}/${ready_read_total} READY_READ covered (${pct_leaf}%) | TUs ${#swap_tu_order[@]}/${ctl_total} app/controllers TUs registered (${pct_tu}%) + ${island_member_total} island member(s) | eligible-not-registered ${ELIGIBLE_COUNT:-0} TU(s)/${ELIGIBLE_LEAF_COUNT:-0} leaf/leaves | blocked ${BLOCKED_COUNT:-0} TU(s) | ${WITHHELD_COUNT:-0} leaf/leaves owned by a registered TU but unlisted and unexplained"
}

ledger() {
    resolve_ownership
    local tu rc
    local -a elig=() blocked=()
    declare -A BLOCK_CLASS=()
    ELIGIBLE_COUNT=0; ELIGIBLE_LEAF_COUNT=0; BLOCKED_COUNT=0; WITHHELD_COUNT=0

    echo "══ HOT-SWAP CANDIDATE LEDGER ══"
    echo "derived from $SWAPPABLE_DEF, $ELIGIBLE_DEF, $ISLANDS_DEF,"
    echo "$DENIED_DEF, $PROBE_DEF, $CMD_DEF_DIR/*.def and $BRIDGE_TU."
    echo "Nothing below is hardcoded: add a .def row and this ledger moves."
    echo
    echo "── SWAPPABLE (registered; the ~9s loop works TODAY) ─────────────────"
    for tu in "${swap_tu_order[@]}"; do
        printf '  %s\n' "$tu"
        printf '      leaves: %s\n' "${SWAP_LEAVES[$tu]}"
        printf '      %s\n' "$(swappable_command_for "$tu")"
        if [ -n "${ISLAND_MEMBERS[$tu]:-}" ]; then
            local m
            for m in ${ISLAND_MEMBERS[$tu]}; do
                printf '      island member (same loop): %s\n' "$m"
            done
        fi
        local l wd=""
        for l in ${NAT_LEAVES[$tu]:-}; do
            case " ${SWAP_LEAVES[$tu]} " in *" $l "*) continue ;; esac
            if [ -n "${DENIED_REASON[$l]:-}" ]; then
                wd="${wd}${wd:+ }$l(denied)"
            else
                wd="${wd}${wd:+ }$l"
                WITHHELD_COUNT=$((WITHHELD_COUNT + 1))
            fi
        done
        [ -n "$wd" ] && printf '      owned but NOT in the row: %s\n' "$wd"
    done

    # Candidate universe: every TU that owns at least one READY_READ leaf.
    for tu in "${!TU_LEAVES[@]}"; do
        [ -n "${SWAP_LEAVES[$tu]:-}" ] && continue
        [ -n "${MEMBER_OWNER[$tu]:-}" ] && [ -n "${SWAP_LEAVES[${MEMBER_OWNER[$tu]}]:-}" ] && continue
        verdict_tu "$tu" 0
        rc=$?
        case "$rc" in
            1) elig+=("$tu") ;;
            2) blocked+=("$tu"); BLOCK_CLASS["$tu"]="$LAST_BLOCK_CLASS" ;;
        esac
    done

    echo
    echo "── ELIGIBLE (every mechanical rule passes; NOT registered) ──────────"
    echo "   Mechanical only. A human still has to argue each one is off the"
    echo "   consensus path before it may be registered — see any single-file"
    echo "   report for the exact rows and the standing rule."
    if [ "${#elig[@]}" -eq 0 ]; then
        echo "  (none)"
    else
        local sorted
        while IFS= read -r tu; do
            [ -n "$tu" ] || continue
            ELIGIBLE_COUNT=$((ELIGIBLE_COUNT + 1))
            local n=0 l
            for l in ${TU_LEAVES[$tu]}; do
                [ -n "${DENIED_REASON[$l]:-}" ] && continue
                n=$((n + 1)); ELIGIBLE_LEAF_COUNT=$((ELIGIBLE_LEAF_COUNT + 1))
            done
            printf '  %s\n      %d leaf/leaves: %s\n' "$tu" "$n" "${TU_LEAVES[$tu]}"
            printf '      tools/dev/hotswap-candidates.sh %s   (exact rows to add)\n' "$tu"
        done < <(printf '%s\n' "${elig[@]}" | LC_ALL=C sort)
    fi

    echo
    echo "── BLOCKED (owns a command leaf, but a rule refuses) ────────────────"
    if [ "${#blocked[@]}" -eq 0 ]; then
        echo "  (none)"
    else
        BLOCKED_COUNT="${#blocked[@]}"
        # Grouped by the rule that refuses, so 50-odd TUs refused by ONE rule
        # read as one fact instead of fifty repetitions of the same paragraph.
        local cls seen_cls="" n
        for cls in not-a-shape-leaf forbidden-root mutable-static denied-leaf \
                   leaf-already-owned not-ready-read no-leaf missing other; do
            n=0
            for tu in "${blocked[@]}"; do
                [ "${BLOCK_CLASS[$tu]}" = "$cls" ] && n=$((n + 1))
            done
            [ "$n" -eq 0 ] && continue
            seen_cls="${seen_cls} $cls"
            case "$cls" in
              not-a-shape-leaf)
                echo "  RULE: not under an allowed shape-leaf folder (app/controllers/,"
                echo "        app/views/, app/conditions/). A swappable TU must be a"
                echo "        controller/view/condition LEAF — check_hotswap_swappable_shape.sh"
                echo "        ALLOWED='$SHAPE_ALLOWED'"
                echo "        $n TU(s):" ;;
              forbidden-root)
                echo "  RULE: under a forbidden consensus/state/supervisor root —"
                echo "        check_hotswap_swappable_shape.sh"
                echo "        FORBIDDEN='$SHAPE_FORBIDDEN'"
                echo "        $n TU(s):" ;;
              mutable-static)
                echo "  RULE: defines a mutable file-scope static (a module .so gets its own"
                echo "        zero copy; live process state is silently lost) —"
                echo "        tools/lint/check_hotswap_static_state.sh"
                echo "        $n TU(s):" ;;
              denied-leaf)
                echo "  RULE: every leaf it owns is on $DENIED_DEF"
                echo "        $n TU(s):" ;;
              leaf-already-owned)
                echo "  RULE: every leaf it owns is already claimed by another swappable row"
                echo "        $n TU(s):" ;;
              not-ready-read)
                echo "  RULE: no leaf it owns is ZCL_COMMAND_READY_READ (READY + read-only)"
                echo "        $n TU(s):" ;;
              no-leaf)
                echo "  RULE: owns no re-pointable READY_READ leaf"
                echo "        $n TU(s):" ;;
              missing)
                echo "  RULE: file does not exist"
                echo "        $n TU(s):" ;;
              *)
                echo "  RULE: (see the per-file report)"
                echo "        $n TU(s):" ;;
            esac
            while IFS= read -r tu; do
                [ -n "$tu" ] || continue
                [ "${BLOCK_CLASS[$tu]}" = "$cls" ] || continue
                printf '          %s  [%s]\n' "$tu" "${TU_LEAVES[$tu]:-no leaf}"
            done < <(printf '%s\n' "${blocked[@]}" | LC_ALL=C sort)
        done
        echo "  (tools/dev/hotswap-candidates.sh <file> for the full per-file rule text)"
    fi

    # Leaves with no swappable owner at all — the honest remainder.
    local orphan=0 l
    for l in "${!LEAF_BLOCK[@]}"; do orphan=$((orphan + 1)); done
    echo
    echo "── READY_READ leaves with no re-pointable controller body: $orphan ──"
    echo "   (pure JSON-RPC pass-throughs and unbound rows; nothing to recompile)"

    echo
    print_summary
}

# ── Entry ──────────────────────────────────────────────────────────────────
case "${1:-}" in
    ""|-h|--help)
        LC_ALL=C sed -n '3,50p' "$0" | LC_ALL=C sed 's/^# \{0,1\}//'
        exit 0 ;;
    --all)
        ledger
        exit 0 ;;
    --summary)
        ledger >/dev/null
        print_summary
        exit 0 ;;
    --leaf)
        leaf="${2:-}"
        [ -n "$leaf" ] || die "usage: $0 --leaf <canonical.leaf.path>"
        [ -n "${LEAF_MACRO[$leaf]:-}" ] || die "'$leaf' is not a leaf in $CMD_DEF_DIR/*.def"
        if [ -n "${DENIED_REASON[$leaf]:-}" ]; then
            echo "VERDICT: BLOCKED"
            echo "  leaf: $leaf"
            echo "  rule: on the hot-swap DENYLIST ($DENIED_DEF)"
            echo "        ${DENIED_REASON[$leaf]}"
            exit_note 2
            exit 2
        fi
        if [ -z "${READY_READ[$leaf]:-}" ]; then
            echo "VERDICT: BLOCKED"
            echo "  leaf: $leaf"
            echo "  rule: declared ${LEAF_MACRO[$leaf]}, not ZCL_COMMAND_READY_READ"
            echo "        (a swappable leaf must be READY and read-only)"
            exit_note 2
            exit 2
        fi
        resolve_ownership
        owner="${LEAF_OWNER[$leaf]:-}"
        if [ -z "$owner" ]; then
            echo "VERDICT: BLOCKED"
            echo "  leaf: $leaf"
            echo "  rule: ${LEAF_BLOCK[$leaf]:-no owning translation unit could be resolved}"
            exit_note 2
            exit 2
        fi
        echo "leaf $leaf is owned by $owner"
        echo
        verdict_tu "$owner" 1
        exit $? ;;
    -*)
        die "unknown option '$1' (try --help)" ;;
    *)
        target="$1"
        target="${target#./}"
        case "$target" in
            /*) target="${target#$ROOT/}" ;;
        esac
        verdict_tu "$target" 1
        exit $? ;;
esac
