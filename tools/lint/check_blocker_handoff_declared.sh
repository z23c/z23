#!/usr/bin/env bash
# Gate — blocker HAND-OFF declaration (ratchet, shrink-only baseline).
#
# What it enforces
# ----------------
# This codebase's defining property is that a stall is always a NAMED
# blocker, never a silent stop. Naming is only half of it. A blocker that a
# production call site can raise with an EMPTY `escape_action` — nothing for
# blocker_supervisor_sweep to dispatch — must therefore carry one of:
#
#   (a) an AUTOMATIC remedy declared in
#       app/conditions/include/conditions/blocker_remedy_bindings.def: a
#       condition-engine healer name, or ESCAPE(<action>). The condition
#       engine drives (detect, remedy, witness) off its own poll loop, so an
#       empty escape_action is fine — something in the tree attempts a cure.
#
#   (b) an explicit HUMAN-decision marker: the id is bound to the honest
#       token OWNER in that table AND a matching row exists in
#       app/conditions/include/conditions/blocker_operator_decisions.def
#       stating the decision the person owns and the tradeoff.
#
# Neither = a stuck horn. Measured on the canonical node 2026-07-27:
# address_index.below_snapshot_seed fired 11,666 times with escape_action ""
# and retry_budget 0 — eleven thousand announcements of a problem with
# nothing to do about it. An alarm like that trains an operator to ignore
# alarms, which destroys the value of the honest-failure design the rest of
# this codebase is built on.
#
# check-blocker-remedy (tools/scripts/check_blocker_remedy.sh) already
# enforces that every raisable id has SOME row (condition | ESCAPE | OWNER).
# It stops there: OWNER with no decision text passes it. This gate is the
# next notch — OWNER is an answer to "does anything auto-heal this?", not an
# answer to "what am I supposed to do?".
#
# Ratchet, not a world-breaker
# ----------------------------
# blocker_handoff_baseline.txt lists ids that are OWNER-bound with no
# decision written yet. They are tolerated; the file may only SHRINK. A NEW
# empty-escape blocker id that is neither auto-remedied nor decision-declared
# fails the build. A baseline entry that no longer violates must be deleted
# (stale entries fail too, so the ratchet cannot rust).
#
# Recognised raise forms (every typed blocker in the tree goes through one):
#   blocker_init(&rec, <id>, ...)      escape = a later `rec.escape_action`
#                                      assignment inside the same function
#   blocker_name_dependency(<id>, ...) static inline, blocker.h — never sets
#                                      an escape action
#   chain_linkage_hold_raise(_, <id>, ...)
#   sentinel_raise_blocker(<id>, ...)
#   name_dependency_blocker(<id>, ...)
# The last three are thin wrappers whose bodies never touch escape_action;
# the gate re-verifies that assumption from source and aborts LOUD if a
# wrapper ever starts setting one (WRAPPER_FILES below).
#
# Modes (ZCL_LINT_MODE): FAIL (default, ratchet) | WARN | UPDATE.
#   UPDATE rewrites the baseline — manual only, never from `make lint`.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

GATE=check_blocker_handoff_declared
MODE="${ZCL_LINT_MODE:-FAIL}"

REMEDY_TABLE="${ZCL_BLOCKER_HANDOFF_REMEDY_TABLE:-app/conditions/include/conditions/blocker_remedy_bindings.def}"
DECISION_TABLE="${ZCL_BLOCKER_HANDOFF_DECISION_TABLE:-app/conditions/include/conditions/blocker_operator_decisions.def}"
BASELINE="${ZCL_BLOCKER_HANDOFF_BASELINE:-tools/lint/blocker_handoff_baseline.txt}"

for f in "$REMEDY_TABLE" "$DECISION_TABLE"; do
    [ -f "$f" ] || { echo "$GATE: FATAL — missing $f" >&2; exit 2; }
done

# ── Scan set ─────────────────────────────────────────────────────────────
# Same scope as check_blocker_remedy.sh: production source only. lib/test is
# excluded (fixtures raise synthetic ids on purpose) and so is the blocker
# primitive itself (it DEFINES the raise functions, it does not call them).
SCAN_ROOTS_DEFAULT="app config lib src"
read -r -a SCAN_ROOTS <<< "${ZCL_BLOCKER_HANDOFF_SCAN_ROOTS:-$SCAN_ROOTS_DEFAULT}"

collect_files() {
    local root
    for root in "${SCAN_ROOTS[@]}"; do
        [ -d "$root" ] || continue
        find "$root" -type f \( -name '*.c' -o -name '*.h' \) \
            ! -path 'lib/test/*' \
            ! -path 'lib/util/src/blocker.c' \
            ! -path 'lib/util/include/util/blocker.h' \
            2>/dev/null
    done
}

mapfile -t scan_files < <(collect_files)
gate_require_scanned "${#scan_files[@]}" "${ZCL_BLOCKER_HANDOFF_FILE_FLOOR:-200}" "$GATE" \
    "no production .c/.h under: ${SCAN_ROOTS[*]}"

# ── Wrapper assumption re-check ──────────────────────────────────────────
# The three wrapper raise helpers are treated as "never sets escape_action".
# That is a fact about their bodies, so read the bodies rather than trusting
# a comment: if one of these files grows an escape_action assignment the
# hardcoded table below is stale and the gate must stop, not guess.
WRAPPER_FILES=(
    app/services/src/invariant_sentinel.c
    lib/validation/src/chain_linkage_check.c
    app/services/src/sticky_escalator.c
)
for wf in "${WRAPPER_FILES[@]}"; do
    [ -f "$wf" ] || continue
    if grep -qE '\.escape_action|->escape_action' "$wf"; then
        echo "$GATE: FATAL — $wf now assigns escape_action; the wrapper" >&2
        echo "  table in this gate assumes it never does. Re-derive it." >&2
        exit 2
    fi
done

# ── Pass 0: `#define <NAME>_BLOCKER_ID "literal"` macro table ────────────
declare -A MACRO=()
while IFS=$'\t' read -r name val; do
    [ -n "$name" ] && MACRO["$name"]="$val"
done < <(awk '
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
            if (match(s, /"([^"\\]|\\.)*"/))
                printf "%s\t%s\n", name, substr(s, RSTART + 1, RLENGTH - 2)
        }
    }
' "${scan_files[@]}")

# ── Pass 1: raise sites ──────────────────────────────────────────────────
# Emits: file<TAB>line<TAB>fn<TAB>kind(lit|id|expr)<TAB>value<TAB>has_escape
# `has_escape` is 1 only for blocker_init sites whose record variable is
# later assigned an escape_action inside the same function body.
extract_raise_sites() {
    awk '
        function trim(s) { gsub(/^[ \t\n]+|[ \t\n]+$/, "", s); return s }
        function find_close(buf, start,   depth, instr, esc, i, c, n) {
            n = length(buf); depth = 1; instr = 0; esc = 0
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
        function split_top(s, arr,   n, i, c, depth, instr, esc, cur, cnt) {
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
        # Does `var` get a NON-EMPTY escape_action between line `from` and the
        # end of the enclosing function (a `}` in column 1), bounded?
        #
        # `rec.escape_action[0] = 0;` / `= ""` is an EXPLICIT empty escape, not
        # an arming — app/jobs/src/tip_finalize_post_step.c:87 and
        # app/jobs/src/utxo_root_ladder_tripwire.c:95 both write one on purpose.
        # Counting those as armed is the one mistake that would let this gate
        # pass a stuck horn, so an explicit-empty anywhere in the same raise
        # window WINS over an arming line: a function that arms on one branch
        # and blanks on another CAN raise the blocker with an empty escape.
        function escape_set_after(var, from,   i, lim, pat1, pat2, armed, line) {
            pat1 = var ".escape_action"
            pat2 = var "->escape_action"
            armed = 0
            lim = (from + 200 < NLINES) ? from + 200 : NLINES
            for (i = from; i <= lim; i++) {
                if (i > from && L[i] ~ /^\}/) break
                line = L[i]
                if (index(line, pat1) == 0 && index(line, pat2) == 0) continue
                if (line ~ /escape_action(\[[^]]*\])?[ \t]*=[ \t]*(0|.\\0.|"")[ \t]*;/)
                    return 0          # explicit empty — never armed
                armed = 1
            }
            return armed
        }
        BEGIN {
            fn[1] = "blocker_init";               idx[1] = 2; rec[1] = 1
            fn[2] = "blocker_name_dependency";    idx[2] = 1; rec[2] = 0
            fn[3] = "chain_linkage_hold_raise";   idx[3] = 2; rec[3] = 0
            fn[4] = "sentinel_raise_blocker";     idx[4] = 1; rec[4] = 0
            fn[5] = "name_dependency_blocker";    idx[5] = 1; rec[5] = 0
            nfn = 5
        }
        FNR == 1 && NR > 1 { flush() }
        { L[FNR] = $0; NLINES = FNR; FNAME = FILENAME }
        END { flush() }
        function flush(   ln, k, name, callpos, name_end, closepos, buf, args,
                          m, av, a, v, recvar, has_esc, joins, i) {
            for (ln = 1; ln <= NLINES; ln++) {
                for (k = 1; k <= nfn; k++) {
                    name = fn[k]
                    callpos = index(L[ln], name "(")
                    if (callpos == 0) continue
                    # crude word-boundary: char before must not be ident-ish
                    if (callpos > 1) {
                        c0 = substr(L[ln], callpos - 1, 1)
                        if (c0 ~ /[A-Za-z0-9_]/) continue
                    }
                    buf = L[ln]
                    name_end = callpos + length(name)
                    closepos = find_close(buf, name_end + 1)
                    joins = 0
                    i = ln
                    while (closepos < 0 && joins < 60 && i < NLINES) {
                        i++; joins++
                        buf = buf "\n" L[i]
                        closepos = find_close(buf, name_end + 1)
                    }
                    if (closepos < 0) continue
                    args = substr(buf, name_end + 1, closepos - (name_end + 1))
                    if (args ~ /const[ \t]+char[ \t]*\*/) continue  # prototype
                    m = split_top(args, av)
                    if (idx[k] > m) continue
                    a = trim(av[idx[k]])
                    if (a == "") continue
                    has_esc = 0
                    if (rec[k]) {
                        recvar = trim(av[1])
                        sub(/^&/, "", recvar)
                        if (recvar ~ /^[A-Za-z_][A-Za-z0-9_]*$/)
                            has_esc = escape_set_after(recvar, ln)
                    }
                    if (a ~ /^"/) {
                        v = a; sub(/^"/, "", v); sub(/"[ \t]*$/, "", v)
                        printf "%s\t%d\t%s\tlit\t%s\t%d\n", FNAME, ln, name, v, has_esc
                    } else if (a ~ /^[A-Za-z_][A-Za-z0-9_]*$/) {
                        printf "%s\t%d\t%s\tid\t%s\t%d\n", FNAME, ln, name, a, has_esc
                    } else {
                        printf "%s\t%d\t%s\texpr\t%s\t%d\n", FNAME, ln, name, a, has_esc
                    }
                }
            }
            delete L; NLINES = 0
        }
    ' "$@"
}

mapfile -t RAISE_ROWS < <(extract_raise_sites "${scan_files[@]}")
gate_require_scanned "${#RAISE_ROWS[@]}" "${ZCL_BLOCKER_HANDOFF_SITE_FLOOR:-100}" "$GATE" \
    "raise-site extraction collapsed — the awk pass matched almost nothing"

# ── Pass 2: /* blocker-id: <pattern> */ markers (dynamic ids) ────────────
# A dynamic id (snprintf-built) declares itself with this marker; the
# construction site is what the marker annotates, so the pattern inherits the
# escape disposition of the raise site in that same file.
declare -A FILE_MARKER=()
while IFS=$'\t' read -r file line pattern; do
    [ -z "$file" ] && continue
    FILE_MARKER["$file"]="${FILE_MARKER[$file]:-}${FILE_MARKER[$file]:+ }$pattern"
done < <(grep -rnoE '/\*[ \t]*blocker-id:[ \t]*[A-Za-z0-9_.*-]+[ \t]*\*/' "${scan_files[@]}" 2>/dev/null |
         # [[:space:]], not [ \t]: BSD sed reads "\t" in a bracket expression as
         # literal backslash-or-"t", so a marker id starting with "t" lost that
         # letter here (check_blocker_remedy.sh carries the same fix).
         sed -E 's#^([^:]+):([0-9]+):.*blocker-id:[[:space:]]*([A-Za-z0-9_.*-]+).*#\1\t\2\t\3#' || true)

# ── Fold raise sites into: id -> can be raised with an empty escape? ─────
# The question is "CAN this id be raised with an empty escape action", so a
# single empty-escape raise site puts the id in scope even when another site
# arms one. No "some other raise site armed it" suppression.
declare -A EMPTY_ESCAPE=()   # id -> "file:line" of the first empty-escape raise
scanned_sites=0
for row in "${RAISE_ROWS[@]}"; do
    IFS=$'\t' read -r file line fname kind val has_esc <<< "$row"
    [ -z "$file" ] && continue
    scanned_sites=$((scanned_sites + 1))
    ids=()
    case "$kind" in
        lit) ids=("$val") ;;
        id)
            if [ -n "${MACRO[$val]+x}" ]; then
                ids=("${MACRO[$val]}")
            elif [ -n "${FILE_MARKER[$file]+x}" ]; then
                read -r -a ids <<< "${FILE_MARKER[$file]}"
            else
                continue   # check_blocker_remedy owns the undeclared-dynamic failure
            fi
            ;;
        expr)
            if [ -n "${FILE_MARKER[$file]+x}" ]; then
                read -r -a ids <<< "${FILE_MARKER[$file]}"
            else
                continue
            fi
            ;;
    esac
    for id in "${ids[@]}"; do
        [ -z "$id" ] && continue
        if [ "$has_esc" != "1" ] && [ -z "${EMPTY_ESCAPE[$id]+x}" ]; then
            EMPTY_ESCAPE["$id"]="$file:$line"
        fi
    done
done

# ── Table loads ──────────────────────────────────────────────────────────
parse_def_ids() {  # $1 = macro name, $2 = file — prints "id<TAB>second-arg-head"
    # Trailing `/* ... */` first (a row comment may itself contain commas and
    # a `)`), then the closing paren, then the first top-level comma.
    awk -v macro="$1" '
        BEGIN { pat = "^" macro "\\(" }
        $0 ~ pat {
            s = $0
            sub(pat, "", s)
            sub(/[ \t]*\/\*.*$/, "", s)
            sub(/[ \t]*\)[ \t]*$/, "", s)
            c = index(s, ",")
            if (c > 0) { id = substr(s, 1, c - 1); rest = substr(s, c + 1) }
            else       { id = s; rest = "" }
            gsub(/^[ \t]+|[ \t]+$/, "", id)
            gsub(/^[ \t]+|[ \t]+$/, "", rest)
            if (id != "") printf "%s\t%s\n", id, rest
        }
    ' "$2"
}

declare -A REMEDY=()
declare -a REMEDY_ORDER=()
while IFS=$'\t' read -r idpat remedy; do
    [ -z "$idpat" ] && continue
    REMEDY["$idpat"]="$remedy"
    REMEDY_ORDER+=("$idpat")
done < <(parse_def_ids ZCL_BLOCKER_REMEDY "$REMEDY_TABLE")
gate_require_scanned "${#REMEDY_ORDER[@]}" "${ZCL_BLOCKER_HANDOFF_REMEDY_FLOOR:-80}" "$GATE" \
    "parsed too few ZCL_BLOCKER_REMEDY rows from $REMEDY_TABLE"

declare -a DECISION_PATTERNS=()
while IFS=$'\t' read -r idpat _rest; do
    [ -z "$idpat" ] && continue
    DECISION_PATTERNS+=("$idpat")
done < <(parse_def_ids ZCL_BLOCKER_DECISION "$DECISION_TABLE")
gate_require_scanned "${#DECISION_PATTERNS[@]}" "${ZCL_BLOCKER_HANDOFF_DECISION_FLOOR:-1}" "$GATE" \
    "parsed zero ZCL_BLOCKER_DECISION rows from $DECISION_TABLE"

# Longest-match-wins glob lookup — the same rule the runtime resolver uses
# (app/conditions/src/blocker_handoff_registry.c best_match): an exact id
# beats every pattern; among patterns the longest wins.
best_pattern() {  # $1 = id; remaining args = patterns. echoes the winner or ""
    local id="$1"; shift
    local p best="" bestlen=0
    for p in "$@"; do
        [ -z "$p" ] && continue
        if [ "$p" = "$id" ]; then echo "$p"; return 0; fi
        case "$p" in *'*'*) ;; *) continue ;; esac
        # shellcheck disable=SC2254  # deliberate glob match
        case "$id" in
            $p) if [ "${#p}" -gt "$bestlen" ]; then best="$p"; bestlen="${#p}"; fi ;;
        esac
    done
    echo "$best"
}

# ── Classification ───────────────────────────────────────────────────────
declare -A BASELINED=()
baseline_count=0
gate_load_list_file "$BASELINE" BASELINED baseline_count

violations=()          # new, unbaselined
tolerated=()           # matched a baseline entry
declare -A HIT=()      # baseline entries actually used
auto_ok=0
declared_ok=0

for id in "${!EMPTY_ESCAPE[@]}"; do
    rp="$(best_pattern "$id" "${REMEDY_ORDER[@]}")"
    if [ -n "$rp" ] && [ "${REMEDY[$rp]}" != "OWNER" ]; then
        auto_ok=$((auto_ok + 1))
        continue
    fi
    dp="$(best_pattern "$id" "${DECISION_PATTERNS[@]}")"
    if [ -n "$dp" ]; then
        declared_ok=$((declared_ok + 1))
        continue
    fi
    if [ -n "${BASELINED[$id]+x}" ]; then
        HIT["$id"]=1
        tolerated+=("$id")
        continue
    fi
    if [ -z "$rp" ]; then
        violations+=("$id  (${EMPTY_ESCAPE[$id]}) — empty escape_action, NO row in $REMEDY_TABLE")
    else
        violations+=("$id  (${EMPTY_ESCAPE[$id]}) — empty escape_action, bound OWNER, no ZCL_BLOCKER_DECISION row")
    fi
done

# Stale baseline entries: a ratchet that keeps rows for ids that no longer
# violate rusts shut. Removing the row is part of fixing the blocker.
stale=()
for id in "${!BASELINED[@]}"; do
    [ -z "${HIT[$id]+x}" ] && stale+=("$id")
done

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# $GATE baseline — ids raisable with an EMPTY escape_action that are"
        echo "# bound OWNER with no ZCL_BLOCKER_DECISION row yet. SHRINK ONLY."
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        for id in $(printf '%s\n' "${tolerated[@]}" "${violations[@]%% *}" | sed '/^$/d' | sort -u); do
            echo "$id"
        done
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED: $BASELINE"
    exit 0
fi

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} blocker id(s) can be raised with an empty escape action"
    echo "        and carry neither an automatic remedy nor a human-decision marker:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  Fix ONE of:"
    echo "   1. Bind it to a real auto-remedy in $REMEDY_TABLE"
    echo "      (a condition-engine healer name, or ESCAPE(<registered action>))."
    echo "   2. Keep it OWNER and add a ZCL_BLOCKER_DECISION row to"
    echo "      $DECISION_TABLE stating the"
    echo "      decision the operator owns and the tradeoff between the options."
    echo "      An honest 'a person must choose between X and Y' is a CORRECT"
    echo "      outcome — do not invent a risky automatic repair, especially for"
    echo "      anything that would mutate consensus state."
    echo "   3. Arm a real escape_action at the raise site (must resolve to a"
    echo "      blocker_register_escape(...) registration — check-blocker-escape-"
    echo "      registered enforces that)."
    echo "  Adding a line to $BASELINE is NOT a fix; that file may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline entry(ies) — no longer raisable with an"
    echo "        empty, undeclared hand-off. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} files, $scanned_sites raise site(s), ${#EMPTY_ESCAPE[@]} id(s) raisable with an empty escape action: $auto_ok auto-remedied, $declared_ok decision-declared, ${#tolerated[@]} baselined of $baseline_count)"
