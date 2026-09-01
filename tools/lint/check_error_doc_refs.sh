#!/usr/bin/env bash
# check-error-doc-refs — a document named in an operator-facing message must
# exist.
#
# Why this gate exists
# --------------------
# Three boot refusals in engine/composition/src/boot.c told the operator
# "To recover: see WALLET_PERSISTENCE_RECOVERY.md". No such file has ever
# existed in this repository. The refusals were on the wallet path — the node
# stops there precisely because private keys are on disk and it will not write
# over them — so the one moment an operator most needs the instructions, the
# instructions were a dead pointer.
#
# A wrong next step is worse than no next step: it costs a round trip and it
# teaches the reader to stop trusting the error surface. `check-markdown-links`
# already covers links between .md files; nothing covered a doc path baked into
# a C string literal, which is exactly where operator remedies live.
#
# What it checks
# --------------
# Every string literal in a tracked .c/.h file that contains a token ending in
# `.md`, resolved against the repo root. Comments are ignored (only literals
# reach an operator). A token resolves if the file exists, or if it exists
# under docs/ or docs/work/ by basename — the messages carry a repo-relative
# path, but older text sometimes carried a bare filename.
#
# Deliberately NOT checked: paths built at runtime (a literal that contains a
# printf conversion is skipped — the gate cannot know what it expands to), and
# any literal carrying a shell/SQL glob.
#
# Mode: HARD. The repo is at zero violations, so there is no baseline to
# ratchet — a new dead pointer fails immediately.
#
# Per-line override: `// error-doc-ref-ok:<reason>` on the same line, for a
# path that is genuinely created at runtime.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || exit 2

violations=0

while IFS= read -r file; do
    [ -f "$file" ] || continue
    lineno=0
    while IFS= read -r line; do
        lineno=$((lineno + 1))
        case "$line" in
            *'.md'*) ;;
            *) continue ;;
        esac
        case "$line" in
            *'// error-doc-ref-ok:'*) continue ;;
        esac
        # Only string literals. Pull each quoted run out of the line, then look
        # for doc-shaped tokens inside it.
        literals=$(printf '%s\n' "$line" | grep -o '"[^"]*"' 2>/dev/null) || continue
        [ -n "$literals" ] || continue
        while IFS= read -r lit; do
            case "$lit" in
                *'.md'*) ;;
                *) continue ;;
            esac
            # A literal with a printf conversion is assembled at runtime.
            case "$lit" in
                *%s*|*%d*|*%l*|*%z*|*'*'*) continue ;;
            esac
            for tok in $(printf '%s\n' "$lit" | tr -c 'A-Za-z0-9_./-' ' '); do
                case "$tok" in
                    .md|*/.md) continue ;;   # a bare suffix constant
                    *.md) ;;
                    *) continue ;;
                esac
                # Skip bare "CLAUDE.md"-style references to files at the root
                # that do exist, and anything that resolves directly.
                [ -e "$tok" ] && continue
                base="${tok##*/}"
                [ -e "docs/$base" ] && continue
                [ -e "docs/work/$base" ] && continue
                printf '  %s:%d names a document that does not exist: %s\n' \
                    "$file" "$lineno" "$tok"
                violations=$((violations + 1))
            done
        done <<< "$literals"
    done < "$file"
done < <(git ls-files '*.c' '*.h' | grep -v '^tests/harness/')
# tests/harness/ is excluded: its literals are fixture paths the test itself
# creates and removes (docs/notes.md, .claude/commands/kept.md, test-tmp/*.md).
# Those never reach an operator, and asserting they exist at lint time would be
# asserting the opposite of what the tests are for.

if [ "$violations" -gt 0 ]; then
    echo
    echo "check_error_doc_refs: FAIL — $violations operator-facing reference(s) to a missing document"
    echo
    echo "An error message that names a document the reader cannot open is worse"
    echo "than one that names nothing: it spends a round trip and it costs the"
    echo "error surface its credibility. Either write the document, or replace the"
    echo "reference with a command you have actually run."
    echo
    echo "If the path is genuinely produced at runtime, append"
    echo "  // error-doc-ref-ok:<reason>"
    echo "to the line."
    exit 1
fi

echo "check_error_doc_refs: clean — every document named in a C string literal exists"
exit 0
