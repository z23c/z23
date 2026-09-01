#!/usr/bin/env bash
# Lint gate — blocker remedy totality (docs/work/tenacity-roadmap.md "Hold-class doctrine").
#
# Goal: every named typed blocker (platform/modules/util/blocker.h) a production call
# site can raise has a declared remedy — a condition-engine healer name
# checked to exist in condition_registry.def, or the honest token OWNER —
# in the checked-in ratchet table
# engine/conditions/include/conditions/blocker_remedy_bindings.def. The class
# this closes: a PERMANENT blocker with an empty escape_action and NO
# auto-remedy condition anywhere in the tree looks exactly like every
# other typed blocker (registry-visible, well-formed) but can pin H*
# forever with nothing ever attempting a cure — that is
# `utxo_apply.nullifier_backfill_gap` (hold-class-audit defect D3), which
# wedged the canonical node for weeks. This gate makes "add a new
# permanent-no-cure blocker and never declare that fact anywhere" fail the
# build.
#
# Two extraction passes, unioned into ALL_IDS, each entry of which must be
# an EXACT key in the binding table:
#
#   1. LITERAL / MACRO call-site ids — the id argument to blocker_init()
#      (position 2) or one of three wrapper functions the codebase uses
#      for the same purpose (chain_linkage_hold_raise position 2;
#      sentinel_raise_blocker / name_dependency_blocker position 1) is
#      either a quoted string literal, or a bare identifier that resolves
#      via a `#define <NAME>_BLOCKER_ID "literal"` in scope. Both resolve
#      to an exact id.
#
#   2. PATTERN markers — a call site whose id argument is a bare variable
#      (built at runtime via snprintf, e.g. "coin_backfill.%d") cannot be
#      resolved by string matching alone. Its construction site must carry
#      a `/* blocker-id: <pattern> */` marker comment (conversion
#      specifiers collapsed to a single `*`, e.g. "coin_backfill.*") — see
#      engine/jobs/src/stage_repair_coin_backfill_util.c for worked examples.
#      Any FILE containing a call site whose id argument resolves to
#      neither (1) nor a known baseline exemption is a hard failure
#      independent of the table: the marker is how a dynamic id declares
#      itself at all, table membership is the separate remedy declaration.
#
# Scope mirrors check_blocker_escape_registered.sh: core engine contexts cognition platform,
# excluding lib/test (production + sim/fuzz harness code; test fixtures
# intentionally use synthetic ids never meant to be enumerated) and the
# blocker primitive's own file (defines the functions, doesn't call them).
set -euo pipefail

cd "$(dirname "$0")/../.."

TABLE=engine/conditions/include/conditions/blocker_remedy_bindings.def
REGISTRY_ROOTS=(core engine contexts cognition platform)

[ -f "$TABLE" ] || { echo "check_blocker_remedy: missing $TABLE" >&2; exit 1; }

collect_files() {
    for root in "${REGISTRY_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        find "$root" -type f \( -name '*.c' -o -name '*.h' -o -name '*.def' \) \
            ! -path 'tests/harness/include/test/*' \
            ! -path 'platform/modules/util/src/blocker.c' \
            ! -path 'platform/modules/util/include/util/blocker.h' \
            2>/dev/null
    done
}

if [ -n "${ZCL_BLOCKER_REMEDY_SCAN_FILES:-}" ]; then
    mapfile -t scan_files <<< "${ZCL_BLOCKER_REMEDY_SCAN_FILES}"
else
    mapfile -t scan_files < <(collect_files)
fi

if [ "${#scan_files[@]}" -eq 0 ]; then
    echo "check_blocker_remedy: no files to scan" >&2
    exit 1
fi

# ── Pass 0: macro table — every `#define <NAME>_BLOCKER_ID "literal"`,
# joining a trailing-backslash continuation onto the next line first. ──
extract_macros() {
    awk '
        {
            line = $0
            while (line ~ /\\[ \t]*$/) {
                sub(/\\[ \t]*$/, "", line)
                if ((getline nextline) <= 0) break
                line = line " " nextline
            }
            if (match(line, /#define[ \t]+[A-Za-z_][A-Za-z0-9_]*_BLOCKER_ID[ \t]+"([^"\\]|\\.)*"/)) {
                s = substr(line, RSTART, RLENGTH)
                name = s
                sub(/^#define[ \t]+/, "", name)
                sub(/_BLOCKER_ID.*/, "_BLOCKER_ID", name)
                if (match(s, /"([^"\\]|\\.)*"/)) {
                    val = substr(s, RSTART + 1, RLENGTH - 2)
                    printf "%s\t%s\n", name, val
                }
            }
        }
    ' "$@"
}

declare -A MACRO
while IFS=$'\t' read -r name val; do
    [ -n "$name" ] && MACRO["$name"]="$val"
done < <(extract_macros "${scan_files[@]}")

# ── Pass 1: call-site id arguments (literal / macro / dynamic-bare-var). ──
# Emits: file<TAB>line<TAB>kind<TAB>value
#   kind=lit   value = resolved exact id (literal or macro-resolved)
#   kind=dyn   value = the bare-identifier argument text (unresolved)
extract_call_sites() {
    awk '
        function trim(s) {
            gsub(/^[ \t\n]+/, "", s)
            gsub(/[ \t\n]+$/, "", s)
            return s
        }
        # Quote-aware search for the ")" matching the "(" that ends the
        # call name at buf-position `name_end` (buf[name_end] == "("):
        # returns its 1-based position, or -1 if buf ends first (caller
        # must pull in more lines and retry — a naive index(buf, ";")
        # scan is WRONG here, a reason string can itself contain a ";",
        # e.g. "resident usage at/above CRITICAL threshold; forcing
        # shrink-sink pass" in memory_pressure_high.c). Comments are not
        # stripped, but none of the four scanned call forms are ever
        # invoked from inside a comment in production scope.
        function find_close(buf, start,    depth, instr, esc, i, c, n) {
            n = length(buf)
            depth = 1
            instr = 0
            esc = 0
            for (i = start; i <= n; i++) {
                c = substr(buf, i, 1)
                if (instr) {
                    if (esc) esc = 0
                    else if (c == "\\") esc = 1
                    else if (c == "\"") instr = 0
                } else {
                    if (c == "\"") instr = 1
                    else if (c == "(") depth++
                    else if (c == ")") { depth--; if (depth == 0) return i }
                }
            }
            return -1
        }
        function split_top(s, arr,    n, i, c, depth, instr, esc, cur, cnt) {
            n = length(s); depth = 0; instr = 0; esc = 0; cur = ""; cnt = 0
            for (i = 1; i <= n; i++) {
                c = substr(s, i, 1)
                if (instr) {
                    cur = cur c
                    if (esc) esc = 0
                    else if (c == "\\") esc = 1
                    else if (c == "\"") instr = 0
                    continue
                }
                if (c == "\"") { instr = 1; cur = cur c; continue }
                if (c == "(") { depth++; cur = cur c; continue }
                if (c == ")") { depth--; cur = cur c; continue }
                if (c == "," && depth == 0) { cnt++; arr[cnt] = cur; cur = ""; continue }
                cur = cur c
            }
            cnt++; arr[cnt] = cur
            return cnt
        }
        BEGIN {
            fn[1] = "blocker_init";              idx[1] = 2
            fn[2] = "chain_linkage_hold_raise";   idx[2] = 2
            fn[3] = "sentinel_raise_blocker";     idx[3] = 1
            fn[4] = "name_dependency_blocker";    idx[4] = 1
            nfn = 4
        }
        {
            for (k = 1; k <= nfn; k++) {
                name = fn[k]
                pat = name "\\("
                if (!match($0, pat)) continue
                startline = FNR
                buf = $0
                callpos = index(buf, name "(")
                if (callpos == 0) continue
                name_end = callpos + length(name)   # position of "(" char
                closepos = find_close(buf, name_end + 1)
                joins = 0
                while (closepos < 0 && joins < 60) {
                    if ((getline nextline) <= 0) break
                    buf = buf "\n" nextline
                    joins++
                    closepos = find_close(buf, name_end + 1)
                }
                if (closepos < 0) continue   # truncated/malformed — give up
                args = substr(buf, name_end + 1, closepos - (name_end + 1))
                if (args ~ /const[ \t]+char[ \t]*\*/) continue   # decl/proto, not a call
                m = split_top(args, av)
                want = idx[k]
                if (want > m) continue
                a = trim(av[want])
                if (a == "") continue
                if (a ~ /^"/) {
                    # quoted literal
                    v = a
                    sub(/^"/, "", v)
                    sub(/"[ \t]*$/, "", v)
                    printf "%s\t%d\t%s\t%s\t%s\n", FILENAME, startline, name, "lit", v
                } else if (a ~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
                    printf "%s\t%d\t%s\t%s\t%s\n", FILENAME, startline, name, "id", a
                } else {
                    printf "%s\t%d\t%s\t%s\t%s\n", FILENAME, startline, name, "expr", a
                }
            }
        }
    ' "$@"
}

# ── Pass 2: `/* blocker-id: <pattern> */` markers, one per file that owns
# a dynamic (bare-variable) call-site id. ──
extract_markers() {
    grep -rnoE '/\*[ \t]*blocker-id:[ \t]*[A-Za-z0-9_.*-]+[ \t]*\*/' "$@" 2>/dev/null |
    # [[:space:]], not [ \t]: inside a bracket expression Apple/BSD sed reads
    # "\t" as literal backslash-or-"t" (GNU reads TAB), so a pattern id whose
    # first letter is "t" lost that letter here and the gate invented a
    # phantom missing binding.
    sed -E 's#^([^:]+):([0-9]+):.*blocker-id:[[:space:]]*([A-Za-z0-9_.*-]+).*#\1\t\2\t\3#'
}

declare -A FILE_HAS_MARKER
declare -A ALL_IDS   # discovered id/pattern -> 1
while IFS=$'\t' read -r file line pattern; do
    [ -z "$file" ] && continue
    FILE_HAS_MARKER["$file"]=1
    ALL_IDS["$pattern"]=1
done < <(extract_markers "${scan_files[@]}")

# Buffer call-site rows so we can do two passes: (1) learn which files carry
# at least one LITERAL wrapper-function call (chain_linkage_hold_raise /
# sentinel_raise_blocker / name_dependency_blocker) — a same-file internal
# blocker_init(..., <the wrapper's own forwarded parameter>, ...) is not an
# undeclared dynamic id, its literal values are already captured at the
# wrapper's OWN call sites, which may appear later in the file than the
# wrapper body itself; (2) evaluate dynamic-site violations with that
# knowledge in hand.
mapfile -t CALL_ROWS < <(extract_call_sites "${scan_files[@]}")

declare -A FILE_HAS_LITERAL_WRAPPER_CALL
for row in "${CALL_ROWS[@]}"; do
    IFS=$'\t' read -r file line fn kind val <<< "$row"
    [ -z "$file" ] && continue
    if [ "$kind" = "lit" ] && [ "$fn" != "blocker_init" ]; then
        FILE_HAS_LITERAL_WRAPPER_CALL["$file"]=1
    fi
done

fail=0
dyn_violations=()

for row in "${CALL_ROWS[@]}"; do
    IFS=$'\t' read -r file line fn kind val <<< "$row"
    [ -z "$file" ] && continue
    case "$kind" in
        lit)
            ALL_IDS["$val"]=1
            ;;
        id|expr)
            if [ "$kind" = "id" ] && [ -n "${MACRO[$val]+x}" ]; then
                ALL_IDS["${MACRO[$val]}"]=1
                continue
            fi
            # Dynamic: bare variable / non-literal expression feeding the id
            # slot, not a resolvable macro. Satisfied if this exact FILE
            # either carries a /* blocker-id: <pattern> */ marker, or (for
            # blocker_init specifically) already has a literal wrapper-
            # function call elsewhere in the file whose forwarded parameter
            # this internal call is re-using.
            if [ -n "${FILE_HAS_MARKER[$file]+x}" ]; then
                continue
            fi
            if [ "$fn" = "blocker_init" ] && [ -n "${FILE_HAS_LITERAL_WRAPPER_CALL[$file]+x}" ]; then
                continue
            fi
            dyn_violations+=("$file:$line: $fn(...) id argument \"$val\" is a bare variable/expression with no #define macro, no /* blocker-id: <pattern> */ marker, and no same-file literal wrapper call to forward from")
            fail=1
            ;;
    esac
done

# ── Table load: ZCL_BLOCKER_REMEDY(id_or_pattern, remedy) rows. ──
declare -A TABLE_REMEDY
declare -a TABLE_ORDER
while IFS=$'\t' read -r idpat remedy; do
    [ -z "$idpat" ] && continue
    TABLE_REMEDY["$idpat"]="$remedy"
    TABLE_ORDER+=("$idpat")
done < <(awk '
    match($0, /^ZCL_BLOCKER_REMEDY\(/) {
        s = $0
        sub(/^ZCL_BLOCKER_REMEDY\(/, "", s)
        sub(/\)[ \t]*(\/\*.*\*\/)?[ \t]*$/, "", s)
        n = split(s, parts, ",")
        if (n < 2) next
        id = parts[1]
        remedy = parts[2]
        for (i = 3; i <= n; i++) remedy = remedy "," parts[i]
        gsub(/^[ \t]+|[ \t]+$/, "", id)
        gsub(/^[ \t]+|[ \t]+$/, "", remedy)
        gsub(/[ \t]+$/, "", remedy)
        sub(/[ \t]*\/\*.*/, "", remedy)
        gsub(/[ \t]+$/, "", remedy)
        if (id != "" && remedy != "") printf "%s\t%s\n", id, remedy
    }
' "$TABLE")

if [ "${#TABLE_ORDER[@]}" -eq 0 ]; then
    echo "check_blocker_remedy: parsed zero rows from $TABLE — parser or table is broken" >&2
    exit 1
fi

# ── Coverage check: every discovered id/pattern must be an exact table key. ──
missing=()
for id in "${!ALL_IDS[@]}"; do
    if [ -z "${TABLE_REMEDY[$id]+x}" ]; then
        missing+=("$id")
    fi
done

# ── Remedy validity: every non-OWNER remedy must name a real condition. ──
collect_registry_files() { collect_files; }
extract_condition_names() {
    awk '
        {
            if (match($0, /ZCL_CONDITION\([A-Za-z0-9_]+\)/)) {
                s = substr($0, RSTART, RLENGTH)
                sub(/^ZCL_CONDITION\(/, "", s)
                sub(/\)$/, "", s)
                print s
            }
            if (match($0, /#define[ \t]+[A-Za-z0-9_]+_COND_NAME[ \t]+"([^"\\]|\\.)*"/)) {
                line = substr($0, RSTART, RLENGTH)
                if (match(line, /"([^"\\]|\\.)*"/)) {
                    print substr(line, RSTART + 1, RLENGTH - 2)
                }
            }
        }
    ' "$@"
}
declare -A CONDITIONS
while IFS= read -r name; do
    [ -n "$name" ] && CONDITIONS["$name"]=1
done < <(extract_condition_names "${scan_files[@]}")

# ── ESCAPE(<action>) remedies — a row may instead name a blocker escape
# action registered via blocker_register_escape("<action>", fn): the
# supervisor sweep's own edge-triggered escape ladder IS the auto-remedy
# (see engine/services/src/chain_activation_service.c:211). Only literal
# quoted action-name registrations are recognized (a macro-built action
# name can't be resolved by string matching, same limitation as the id
# extraction above). ──
extract_registered_escapes() {
    grep -rhoE 'blocker_register_escape\([ \t]*"[^"]+"' "$@" 2>/dev/null |
    # Same [[:space:]] rule as extract_markers above (BSD sed bracket \t).
    sed -E 's/^blocker_register_escape\([[:space:]]*"//; s/"$//'
}
declare -A ESCAPES
while IFS= read -r name; do
    [ -n "$name" ] && ESCAPES["$name"]=1
done < <(extract_registered_escapes "${scan_files[@]}")

bad_remedy=()
escape_count=0
for id in "${TABLE_ORDER[@]}"; do
    remedy="${TABLE_REMEDY[$id]}"
    [ "$remedy" = "OWNER" ] && continue
    if [[ "$remedy" =~ ^ESCAPE\((.+)\)$ ]]; then
        action="${BASH_REMATCH[1]}"
        if [ -z "${ESCAPES[$action]+x}" ]; then
            bad_remedy+=("$id -> \"$remedy\" (no blocker_register_escape(\"$action\", ...) call site found anywhere in scope)")
            fail=1
        else
            escape_count=$((escape_count + 1))
        fi
        continue
    fi
    if [ -z "${CONDITIONS[$remedy]+x}" ]; then
        bad_remedy+=("$id -> \"$remedy\" (no ZCL_CONDITION($remedy) / *_COND_NAME \"$remedy\" found anywhere in scope)")
        fail=1
    fi
done

if [ "${#missing[@]}" -gt 0 ]; then
    fail=1
fi

if [ "$fail" = "0" ]; then
    owner_count=0
    cond_count=0
    for id in "${TABLE_ORDER[@]}"; do
        if [ "${TABLE_REMEDY[$id]}" = "OWNER" ]; then
            owner_count=$((owner_count + 1))
        elif [[ "${TABLE_REMEDY[$id]}" =~ ^ESCAPE\( ]]; then
            :  # already counted in escape_count
        else
            cond_count=$((cond_count + 1))
        fi
    done
    echo "check_blocker_remedy: clean — ${#TABLE_ORDER[@]} bound blocker id(s)/pattern(s) (${cond_count} condition-remedied, ${escape_count} escape-remedied, ${owner_count} OWNER), ${#ALL_IDS[@]} discovered in source, all covered"
    exit 0
fi

echo ""
echo "check_blocker_remedy: FAILED"
echo ""
if [ "${#dyn_violations[@]}" -gt 0 ]; then
    echo "${#dyn_violations[@]} dynamic blocker-id call site(s) with no /* blocker-id: <pattern> */ marker:"
    for v in "${dyn_violations[@]}"; do
        echo "  $v"
    done
    echo ""
fi
if [ "${#missing[@]}" -gt 0 ]; then
    echo "${#missing[@]} blocker id/pattern(s) discovered in source but MISSING from $TABLE:"
    for id in "${missing[@]}"; do
        echo "  $id"
    done
    echo ""
fi
if [ "${#bad_remedy[@]}" -gt 0 ]; then
    echo "${#bad_remedy[@]} table row(s) with a remedy that names no real condition:"
    for v in "${bad_remedy[@]}"; do
        echo "  $v"
    done
    echo ""
fi
echo "Fix options:"
echo "  1. New blocker id/pattern: add"
echo "     'ZCL_BLOCKER_REMEDY(<id_or_pattern>, <condition_name_or_OWNER>)' to"
echo "     $TABLE. Use a real condition name ONLY if you have verified in"
echo "     code that it detects/clears this exact blocker (directly or by"
echo "     driving the state its raiser self-clears on) — otherwise OWNER."
echo "  2. New dynamic (snprintf-built) blocker id: add a"
echo "     '/* blocker-id: <pattern-with-*> */' marker comment at the"
echo "     construction site (collapse each conversion specifier to a"
echo "     single '*'), matching an existing example in"
echo "     engine/jobs/src/stage_repair_coin_backfill_util.c."
echo "  3. Remedy names no condition: fix the typo, or add a"
echo "     ZCL_CONDITION(<name>) entry to condition_registry.def if the"
echo "     condition genuinely exists but isn't registered yet."
exit 1
