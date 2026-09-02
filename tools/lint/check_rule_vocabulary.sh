#!/usr/bin/env bash
# Gate: the rule vocabulary is CLOSED and resolves in both directions (HARD).
#
# engine/composition/rule_vocab.def is the only place a rule an executor may be
# shown is named. Everything the harness does with a rule — count its trials,
# score it, retire it, propose promoting it — is keyed on that id, so an id
# that names nothing is a score attached to no rule, and a rule with no id is
# guidance nobody is measuring.
#
# BOTH DIRECTIONS OR NEITHER. Checking only that rows resolve lets a new
# persona arrive unscored and never noticed. Checking only that sources are
# covered lets a row outlive the heading it claims to quote. A hardcoded list
# checked one way is default-permit, which is the failure this project has
# already paid for once.
#
# Sources:
#   .grok/rules/*.md                                     -> "grok:<slug>"
#   engine/modules/engine/include/engine/personas.def     -> "persona:<territory>"
#
# The slug is the heading text lowercased, every run of non-alphanumerics
# turned into one '-', trimmed at both ends. That transform lives in exactly
# one awk function here and in nothing else; the .def stores the result.
#
# Per repo law 10 it FAILS LOUD on an empty scan set: a .def that stopped
# parsing must never read as "clean". There is no baseline — a row that stopped
# resolving is not a debt, it is a false statement.
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 2

GATE="check_rule_vocabulary"
DEF="${ZCL_RULE_VOCAB_DEF:-engine/composition/rule_vocab.def}"
PERSONA_DEF="${ZCL_RULE_PERSONA_DEF:-engine/modules/engine/include/engine/personas.def}"
GROK_DIR="${ZCL_RULE_GROK_DIR:-.grok/rules}"
ROW_FLOOR="${ZCL_RULE_ROW_FLOOR:-7}"
TEXT_MIN=30
TEXT_MAX=300

# ── the one slug transform ───────────────────────────────────────────────
# Emits "grok:<slug>" for every ATX heading in every .md under $1.
grok_ids() { # $1 = directory
    find "$1" -type f -name '*.md' -print0 2>/dev/null \
    | sort -z \
    | xargs -0 -r awk '
        function slug(s,   t) {
            t = tolower(s)
            gsub(/[^a-z0-9]+/, "-", t)
            sub(/^-+/, "", t); sub(/-+$/, "", t)
            return t
        }
        /^#+[ \t]+/ {
            line = $0
            sub(/^#+[ \t]+/, "", line)
            sub(/[ \t]+$/, "", line)
            if (line != "") printf "grok:%s\n", slug(line)
        }'
}

# Emits "persona:<territory>" for every PERSONA row in $1.
persona_ids() { # $1 = personas.def
    awk '
    /^PERSONA\(/ {
        rest = $0
        if (match(rest, /"([^"\\]|\\.)*"/)) {
            printf "persona:%s\n", substr(rest, RSTART + 1, RLENGTH - 2)
        }
    }' "$1"
}

# Emits one tab-separated record per ZCL_RULE row:
#   id, source, state, floor, min_trials, text
# A row that does not carry six fields is emitted as MALFORMED so the scan
# reports it rather than skipping it silently.
rule_rows() { # $1 = rule_vocab.def
    awk '
    /^ZCL_RULE\(/ {
        rest = $0
        n = 0
        while (match(rest, /"([^"\\]|\\.)*"/)) {
            lit[++n] = substr(rest, RSTART + 1, RLENGTH - 2)
            rest = substr(rest, RSTART + RLENGTH)
        }
        # the two string literals are id and text; the middle fields are bare
        body = $0
        sub(/^ZCL_RULE\(/, "", body)
        sub(/\)[ \t]*$/, "", body)
        if (n != 2) { printf "MALFORMED\t%s\t\t\t\t%s\n", $0, ""; next }
        # bare fields: split the row on commas that are outside quotes
        src = ""; st = ""; fl = ""; mt = ""
        tail = body
        # strip the leading quoted id
        if (match(tail, /^[ \t]*"([^"\\]|\\.)*"[ \t]*,/)) {
            tail = substr(tail, RSTART + RLENGTH)
        } else { printf "MALFORMED\t%s\t\t\t\t\n", $0; next }
        if (split(tail, f, ",") < 5) { printf "MALFORMED\t%s\t\t\t\t\n", $0; next }
        src = f[1]; st = f[2]; fl = f[3]; mt = f[4]
        gsub(/^[ \t]+|[ \t]+$/, "", src)
        gsub(/^[ \t]+|[ \t]+$/, "", st)
        gsub(/^[ \t]+|[ \t]+$/, "", fl)
        gsub(/^[ \t]+|[ \t]+$/, "", mt)
        printf "%s\t%s\t%s\t%s\t%s\t%s\n", lit[1], src, st, fl, mt, lit[2]
    }' "$1"
}

# Prints one fault per line; prints nothing when the vocabulary is closed.
# Sets nothing: it is always called in a command substitution, so a count
# assigned here would be assigned in a subshell and lost.
scan() { # $1 = rule_vocab.def  $2 = personas.def  $3 = grok dir
    local def="$1" pdef="$2" gdir="$3"
    local -A seen=() have=()
    local id src st fl mt text

    while IFS= read -r line; do
        [ -n "$line" ] || continue
        have["$line"]=1
    done < <(grok_ids "$gdir"; persona_ids "$pdef")

    while IFS=$'\t' read -r id src st fl mt text; do
        [ -n "$id" ] || continue
        if [ "$id" = "MALFORMED" ]; then
            echo "  a ZCL_RULE row does not carry (id, source, state, floor, min_trials, text)"
            continue
        fi
        if [ -n "${seen[$id]+x}" ]; then
            echo "  $id: a second row for an id that already has one"
        fi
        seen["$id"]=1

        case "$id" in
            grok:*)    [ "$src" = "ZCL_RULE_SRC_GROK" ] \
                         || echo "  $id: a grok: id must declare ZCL_RULE_SRC_GROK, not '$src'" ;;
            persona:*) [ "$src" = "ZCL_RULE_SRC_PERSONA" ] \
                         || echo "  $id: a persona: id must declare ZCL_RULE_SRC_PERSONA, not '$src'" ;;
            *)         echo "  $id: an id must begin grok: or persona:" ;;
        esac

        [ -n "${have[$id]+x}" ] \
            || echo "  $id: names no heading in $gdir and no PERSONA row in $pdef"

        case "$st" in
            ZCL_RULE_SHADOW|ZCL_RULE_OBEYED|ZCL_RULE_RETIRED) ;;
            *) echo "  $id: state '$st' is not shadow, obeyed or retired" ;;
        esac

        case "$fl" in
            ''|*[!0-9]*) echo "  $id: floor '$fl' is not a per-mille integer" ;;
            *) [ "$fl" -le 1000 ] \
                 || echo "  $id: floor $fl is above 1000 per-mille, which no rule can clear" ;;
        esac

        case "$mt" in
            ''|*[!0-9]*) echo "  $id: min_trials '$mt' is not an integer" ;;
            *) [ "$mt" -ge 1 ] \
                 || echo "  $id: min_trials $mt would let a rule be judged on nothing" ;;
        esac

        local len=${#text}
        if [ "$len" -lt "$TEXT_MIN" ]; then
            echo "  $id: text is $len characters; a rule a reader can act on is longer"
        elif [ "$len" -gt "$TEXT_MAX" ]; then
            echo "  $id: text is $len characters; that is a section, not a rule"
        fi
    done < <(rule_rows "$def")

    # The other direction: every source must have a row.
    local sid
    while IFS= read -r sid; do
        [ -n "$sid" ] || continue
        [ -n "${seen[$sid]+x}" ] \
            || echo "  $sid: exists in its source but has no row; it would be shown and never scored"
    done < <(grok_ids "$gdir"; persona_ids "$pdef")
}

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    fails=0

    mkdir -p "$tmp/grok"
    printf '# Only Rule\n' > "$tmp/grok/r.md"
    printf '%s\n' 'PERSONA("platform/modules/base",
    "LOG_FAIL, LOG_ERR and LOG_NULL RETURN; they are not print statements.",
    "platform/modules/base/include/base/log_macros.h")' > "$tmp/personas.def"

    good_grok='ZCL_RULE("grok:only-rule", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, 30, "New program code is C23 and there is no Python fallback.")'
    good_per='ZCL_RULE("persona:platform/modules/base", ZCL_RULE_SRC_PERSONA, ZCL_RULE_OBEYED, 500, 30, "LOG_FAIL and LOG_ERR return; discarding the value changes control flow.")'

    expect() { # $1 = clean|dirty  $2 = label ; reads $tmp/def
        local want="$1" label="$2" out
        out="$(scan "$tmp/def" "$tmp/personas.def" "$tmp/grok")"
        if [ "$want" = clean ] && [ -n "$out" ]; then
            echo "$GATE: SELFTEST FAILED — $label produced faults:" >&2
            echo "$out" >&2
            fails=$((fails + 1))
        elif [ "$want" = dirty ] && [ -z "$out" ]; then
            echo "$GATE: SELFTEST FAILED — $label produced no fault" >&2
            fails=$((fails + 1))
        else
            echo "  selftest ok: $label"
        fi
    }

    # Both ends of the file are pinned: the FIRST row and the LAST row each
    # carry a fault in their own case, because a `while read` that drops an
    # unterminated last line validates the tail of a file not at all, and this
    # tree has already shipped a validator that failed exactly that way.
    printf '%s\n%s\n' "$good_grok" "$good_per" > "$tmp/def"
    expect clean "a vocabulary that covers both sources exactly"

    printf '%s\n%s\n%s\n' "$good_grok" "$good_per" \
        'ZCL_RULE("grok:no-such-heading", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, 30, "A rule quoting a heading that nobody ever wrote down.")' > "$tmp/def"
    expect dirty "a LAST row whose id names no heading"

    printf '%s\n%s\n%s\n' \
        'ZCL_RULE("grok:no-such-heading", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, 30, "A rule quoting a heading that nobody ever wrote down.")' \
        "$good_grok" "$good_per" > "$tmp/def"
    expect dirty "a FIRST row whose id names no heading"

    printf '%s\n' "$good_grok" > "$tmp/def"
    expect dirty "a persona with no row — it would be shown and never scored"

    printf '%s\n%s\n%s\n' "$good_grok" "$good_per" "$good_per" > "$tmp/def"
    expect dirty "two rows for one id"

    printf '%s\n%s\n' "$good_grok" \
        'ZCL_RULE("persona:platform/modules/base", ZCL_RULE_SRC_GROK, ZCL_RULE_OBEYED, 500, 30, "LOG_FAIL and LOG_ERR return; discarding the value changes control flow.")' > "$tmp/def"
    expect dirty "a persona id declaring the grok source"

    printf '%s\n%s\n' "$good_grok" \
        'ZCL_RULE("persona:platform/modules/base", ZCL_RULE_SRC_PERSONA, ZCL_RULE_MAYBE, 500, 30, "LOG_FAIL and LOG_ERR return; discarding the value changes control flow.")' > "$tmp/def"
    expect dirty "a state that is not shadow, obeyed or retired"

    printf '%s\n%s\n' "$good_grok" \
        'ZCL_RULE("persona:platform/modules/base", ZCL_RULE_SRC_PERSONA, ZCL_RULE_OBEYED, 1400, 30, "LOG_FAIL and LOG_ERR return; discarding the value changes control flow.")' > "$tmp/def"
    expect dirty "a floor above 1000 per-mille that no rule could ever clear"

    printf '%s\n%s\n' "$good_grok" \
        'ZCL_RULE("persona:platform/modules/base", ZCL_RULE_SRC_PERSONA, ZCL_RULE_OBEYED, 500, 0, "LOG_FAIL and LOG_ERR return; discarding the value changes control flow.")' > "$tmp/def"
    expect dirty "min_trials of zero, which judges a rule on nothing"

    printf '%s\n%s\n' "$good_grok" \
        'ZCL_RULE("persona:platform/modules/base", ZCL_RULE_SRC_PERSONA, ZCL_RULE_OBEYED, 500, 30, "be careful")' > "$tmp/def"
    expect dirty "text too short to act on"

    # A hollow scan must be LOUD, never a quiet pass.
    : > "$tmp/empty.def"
    rc=0
    ZCL_RULE_VOCAB_DEF="$tmp/empty.def" bash "$PWD/tools/lint/$GATE.sh" \
        >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — a .def with no rows did not exit 2" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a .def with no rows fails LOUD (exit 2), never clean"
    fi

    [ "$fails" -eq 0 ] || exit 1
    echo "[$GATE] SELFTEST PASS (unresolvable id at either end of the file, uncovered source, duplicate id, wrong source tag, bad state, impossible floor, zero min_trials and unusably short text all fail; a closed vocabulary passes; an empty .def exits 2)"
    exit 0
fi

# ── the real scan ────────────────────────────────────────────────────────
[ -f "$DEF" ] || {
    echo "[$GATE] FATAL — $DEF is missing; refusing to report a clean scan" >&2
    exit 2
}
[ -f "$PERSONA_DEF" ] || {
    echo "[$GATE] FATAL — $PERSONA_DEF is missing; refusing to report a clean scan" >&2
    exit 2
}
[ -d "$GROK_DIR" ] || {
    echo "[$GATE] FATAL — $GROK_DIR is missing; refusing to report a clean scan" >&2
    exit 2
}

# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

ROWS="$(rule_rows "$DEF" | grep -c . || true)"
faults="$(scan "$DEF" "$PERSONA_DEF" "$GROK_DIR")"
gate_require_scanned "$ROWS" "$ROW_FLOOR" "$GATE" \
    "rule_vocab.def parsed $ROWS row(s); the ZCL_RULE( parser or the file changed shape"

if [ -n "$faults" ]; then
    echo "[$GATE] FAIL — the rule vocabulary is not closed:" >&2
    echo "$faults" >&2
    echo "" >&2
    echo "  Every id must resolve to a heading in $GROK_DIR or a PERSONA row in" >&2
    echo "  $PERSONA_DEF, and every heading and persona must have a row." >&2
    echo "  Add or correct the row in $DEF." >&2
    exit 1
fi

SOURCES="$( { grok_ids "$GROK_DIR"; persona_ids "$PERSONA_DEF"; } | grep -c . || true)"
echo "[$GATE] PASS — $ROWS rule(s) closed over $SOURCES source(s); every id resolves and every source has a row"
