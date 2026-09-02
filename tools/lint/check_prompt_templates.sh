#!/usr/bin/env bash
# Gate: every prompt template names a real section, and every kind can be
# selected (HARD).
#
# engine/composition/prompt_templates.def supplies the BODIES for the sections
# engine/modules/engine/include/engine/prompt_sections.def declares. Two files,
# one vocabulary, and a vocabulary with only one enforced direction is a
# default-permit: a denylist of forbidden section names would let the next
# section anyone invents through by omission.
#
# So this gate is a MEMBERSHIP rule, checked both ways:
#
#   1. every `section` named in prompt_templates.def is declared in
#      prompt_sections.def. A template naming a section nobody emits is a
#      body that is silently never delivered — and the prompt still passes
#      engine_prompt_audit_text(), because the marker it checks is emitted by
#      the composer, not by the template. Nothing at run time can catch this.
#
#   2. every `kind` in prompt_templates.def supplies a body for every section
#      prompt_sections.def marks ENGINE_PROMPT_NEED_ALWAYS. A kind missing one
#      is a kind engine_prompt_kind_is_complete() refuses at dispatch, so it
#      would sit in the table reading as an available option that is not one:
#      a kind nobody can select.
#
# Both faults are invisible to the compiler and to the run-time audit, which
# is the whole reason a gate exists for them.
#
# Per repo law 10 it FAILS LOUD on an empty scan set: a .def that stopped
# parsing must never read as "clean". There is no baseline — a row that names
# a section the tree does not declare is a false statement, not a debt.
set -euo pipefail
cd "$(dirname "$0")/../.." || exit 2

GATE="check_prompt_templates"
TEMPLATES="${ZCL_PROMPT_TEMPLATES_DEF:-engine/composition/prompt_templates.def}"
SECTIONS="${ZCL_PROMPT_SECTIONS_DEF:-engine/modules/engine/include/engine/prompt_sections.def}"
ROW_FLOOR="${ZCL_PROMPT_TEMPLATE_ROW_FLOOR:-8}"

# Every declared section id, one per line.
parse_sections() {
    awk '/^ENGINE_PROMPT_SECTION\(/ {
        line = $0
        sub(/^ENGINE_PROMPT_SECTION\(/, "", line)
        split(line, f, ",")
        gsub(/[ \t]/, "", f[1])
        if (f[1] != "") print f[1]
    }' "$1"
}

# The section ids that must be present in EVERY prompt, one per line.
parse_always_sections() {
    awk '/^ENGINE_PROMPT_SECTION\(/ {
        line = $0
        sub(/^ENGINE_PROMPT_SECTION\(/, "", line)
        split(line, f, ",")
        gsub(/[ \t]/, "", f[1])
        gsub(/[ \t]/, "", f[2])
        if (f[1] != "" && f[2] == "ENGINE_PROMPT_NEED_ALWAYS") print f[1]
    }' "$1"
}

# Every template row as "kind<TAB>section". Prose inside a non-empty string
# is not parsed — a parser that reached into the sentences would break on
# the first apostrophe or embedded comma — but an empty third argument is
# treated as missing: ENGINE_PROMPT_TEMPLATE(kind, section, "") would
# otherwise count as filling the section, and the composed prompt would be
# a bare header the shape audit cannot tell from a filled one.
parse_templates() {
    awk '/^ENGINE_PROMPT_TEMPLATE\(/ {
        line = $0
        sub(/^ENGINE_PROMPT_TEMPLATE\(/, "", line)
        comma1 = index(line, ",")
        if (comma1 == 0) next
        kind = substr(line, 1, comma1 - 1)
        rest = substr(line, comma1 + 1)
        comma2 = index(rest, ",")
        if (comma2 == 0) next
        section = substr(rest, 1, comma2 - 1)
        body = substr(rest, comma2 + 1)
        gsub(/[ \t]/, "", kind)
        gsub(/[ \t]/, "", section)
        gsub(/[ \t]/, "", body)
        if (body == "\"\")") next
        if (kind != "" && section != "") printf "%s\t%s\n", kind, section
    }' "$1"
}

# Prints one fault per line and nothing when the two files agree. Called in a
# command substitution, so it deliberately assigns nothing that a caller
# needs: a count set in here would be set in a subshell and lost, which is
# how a hollow scan reads as clean.
scan() { # $1 = templates def, $2 = sections def
    local tdef="$1" sdef="$2"
    local declared always rows
    declared="$(parse_sections "$sdef")"
    always="$(parse_always_sections "$sdef")"
    rows="$(parse_templates "$tdef")"

    local kind section
    # Direction 1: a template section that no prompt section declares.
    while IFS=$'\t' read -r kind section; do
        [ -n "$kind" ] || continue
        if ! grep -qx -- "$section" <<<"$declared"; then
            echo "  $kind: names the section '$section', which prompt_sections.def does not declare"
        fi
    done <<< "$rows"

    # Direction 2: a kind that cannot be selected because a required section
    # has no body.
    local kinds k need
    kinds="$(printf '%s\n' "$rows" | cut -f1 | sort -u)"
    while IFS= read -r k; do
        [ -n "$k" ] || continue
        while IFS= read -r need; do
            [ -n "$need" ] || continue
            if ! grep -qx -- "$k	$need" <<<"$rows"; then
                echo "  $k: supplies no body for the always-required '$need' section, so nobody can select this kind"
            fi
        done <<< "$always"
    done <<< "$kinds"
}

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    fails=0

    cat > "$tmp/sections.def" <<'SECTIONS'
ENGINE_PROMPT_SECTION(rules, ENGINE_PROMPT_NEED_NO_SYSTEM_CHANNEL, "R")
ENGINE_PROMPT_SECTION(task, ENGINE_PROMPT_NEED_ALWAYS, "T")
ENGINE_PROMPT_SECTION(protocol, ENGINE_PROMPT_NEED_ALWAYS, "P")
SECTIONS

    expect() { # $1 = clean|dirty, $2 = label
        local want="$1" label="$2" out
        out="$(scan "$tmp/templates.def" "$tmp/sections.def")"
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

    cat > "$tmp/templates.def" <<'GOOD'
ENGINE_PROMPT_TEMPLATE(fix-gate, task, "do the thing")
ENGINE_PROMPT_TEMPLATE(fix-gate, protocol, "write files")
GOOD
    expect clean "a kind that fills every always-required section"

    cat > "$tmp/templates.def" <<'UNKNOWN'
ENGINE_PROMPT_TEMPLATE(fix-gate, task, "do the thing")
ENGINE_PROMPT_TEMPLATE(fix-gate, protocol, "write files")
ENGINE_PROMPT_TEMPLATE(fix-gate, epilogue, "and finally")
UNKNOWN
    expect dirty "a template naming a section prompt_sections.def does not declare"

    cat > "$tmp/templates.def" <<'PARTIAL'
ENGINE_PROMPT_TEMPLATE(fix-gate, task, "do the thing")
ENGINE_PROMPT_TEMPLATE(fix-gate, protocol, "write files")
ENGINE_PROMPT_TEMPLATE(half-done, task, "only half")
PARTIAL
    expect dirty "a kind missing an always-required section"

    cat > "$tmp/templates.def" <<'EMPTYBODY'
ENGINE_PROMPT_TEMPLATE(fix-gate, task, "")
ENGINE_PROMPT_TEMPLATE(fix-gate, protocol, "write files")
EMPTYBODY
    expect dirty "a kind whose required body is an empty string"

    # A hollow scan must be LOUD, never a quiet pass.
    : > "$tmp/empty.def"
    rc=0
    ZCL_PROMPT_TEMPLATES_DEF="$tmp/empty.def" \
        bash "$PWD/tools/lint/$GATE.sh" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — a .def with no rows did not exit 2" >&2
        fails=$((fails + 1))
    else
        echo "  selftest ok: a .def with no rows fails LOUD (exit 2), never clean"
    fi

    [ "$fails" -eq 0 ] || exit 1
    echo "[$GATE] SELFTEST PASS (an undeclared section, a kind missing a required body, and an empty-string body all fail; a complete kind passes; an empty .def exits 2)"
    exit 0
fi

# ── the real scan ────────────────────────────────────────────────────────
for f in "$TEMPLATES" "$SECTIONS"; do
    [ -f "$f" ] || {
        echo "[$GATE] FATAL — $f is missing; refusing to report a clean scan" >&2
        exit 2
    }
done

# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

ROWS="$(parse_templates "$TEMPLATES" | grep -c . || true)"
SECTION_ROWS="$(parse_sections "$SECTIONS" | grep -c . || true)"
faults="$(scan "$TEMPLATES" "$SECTIONS")"

gate_require_scanned "$ROWS" "$ROW_FLOOR" "$GATE" \
    "prompt_templates.def parsed $ROWS row(s); the ENGINE_PROMPT_TEMPLATE( parser or the file changed shape"
gate_require_scanned "$SECTION_ROWS" 3 "$GATE" \
    "prompt_sections.def parsed $SECTION_ROWS row(s); the ENGINE_PROMPT_SECTION( parser or the file changed shape"

if [ -n "$faults" ]; then
    echo ""
    echo "[$GATE] a prompt template and the declared prompt shape disagree:"
    echo "$faults"
    echo ""
    echo "  A body under a section nobody emits is never delivered, and a"
    echo "  kind missing a required body is an option nobody can choose."
    echo "  Neither shows up at run time. Fix the row or the section."
    exit 1
fi

KINDS="$(parse_templates "$TEMPLATES" | cut -f1 | sort -u | grep -c . || true)"
echo "[$GATE] PASS ($ROWS row(s), $KINDS kind(s); every section is declared and every kind fills each always-required section)"
