#!/usr/bin/env bash
# check_doc_inline_paths — backticked source paths in Markdown must resolve.
#
# check_markdown_links.sh gates Markdown LINK targets and explicitly excludes
# "fenced/inline-code examples". Every dead path an agent actually burns budget
# on is inline code: a doc says `domain/consensus/src/tx_structural.c:121`,
# the agent trusts the precision, and the directory moved two refactors ago.
# This gate closes that hole.
#
# Two prongs, one baseline, one override marker.
#
# (1) FILE tokens. A token is checked when it is backticked, contains a '/',
#     and ends in a source/doc extension (optionally with a `:LINE` or
#     `:LINE-LINE` suffix). It resolves if it is a tracked path, a
#     "/"-anchored suffix of one (so include-style `util/log_macros.h` finds
#     lib/util/include/util/log_macros.h), or resolves relative to the doc's
#     own directory.
#
# (2) MODULE-DIRECTORY tokens. Prong (1) only sees paths that end in a file
#     extension, so a whole module that MOVES stays invisible: `lib/consensus`
#     and `domain/consensus` both survived the core/ split in six docs with
#     lint green, and a directory is the single most expensive dead reference
#     there is — an agent greps it, finds nothing, and concludes the feature
#     was deleted. For any backticked token rooted at a top-level source
#     directory, this prong resolves the FIRST TWO components (`lib/consensus`,
#     `app/events`) against the set of tracked directories. Two components
#     only: deeper module shorthand (`lib/storage/chain_segment`) names a file
#     stem, not a directory, and is not this gate's business.
#
# Deliberately out of scope: absolute paths (/etc/..., URL paths), globs and
# brace expansions (they cannot be resolved to one file), generated artifacts
# under build/, .cache/, test-tmp/, and `vendor/` (submodule content that is
# legitimately absent until `make setup` fetches it).
#
# RATCHET: tools/lint/doc_inline_paths_baseline.txt is shrink-only. A NEW
# unresolvable path fails HARD. An entry that starts resolving must be removed
# from the baseline (the gate says so). Per-line escape hatch for a path that
# is deliberately not in the tree (a deleted file cited for `git log` recovery,
# an upstream project's file in an attribution): put `doc-path-ok` in an HTML
# comment on the same line.
set -euo pipefail

cd "$(dirname "$0")/../.."
# shellcheck source=tools/lint/gate_lib.sh
. tools/lint/gate_lib.sh

BASELINE="${ZCL_DOC_INLINE_PATHS_BASELINE:-tools/lint/doc_inline_paths_baseline.txt}"
DOC_GLOB="${ZCL_DOC_INLINE_PATHS_GLOB:-*.md}"

# Top-level source roots whose two-component children prong (2) resolves.
# Superset of KNOWN_TOPS in tools/lint/check_no_orphan_placement.sh and of
# ci_group_for_path() in lib/codeindex/src/codeindex_group.c (their eight, plus
# application/, apps/, docs/, src/). Those three lists are hand-kept mirrors of
# each other — adding or removing a top-level directory means editing all of
# them; see docs/AGENT_TRAPS.md §4. `vendor/` is deliberately absent: submodule
# content is legitimately missing until `make setup` fetches it.
MODULE_TOPS='adapters|app|application|apps|config|core|docs|domain|lib|ports|src|tools'

TMP="$(mktemp -d "${TMPDIR:-/tmp}/zcl-doc-inline-paths.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

git ls-files > "$TMP/tracked"
tracked_count=$(wc -l < "$TMP/tracked")
gate_require_scanned "$tracked_count" 100 check_doc_inline_paths \
    "git ls-files returned almost nothing — not a repo checkout?"

mapfile -t DOCS < <(git ls-files -- "$DOC_GLOB")
gate_require_scanned "${#DOCS[@]}" 1 check_doc_inline_paths \
    "no tracked files matched: $DOC_GLOB"

# Resolution sets: exact tracked paths, plus every "/"-anchored suffix, plus
# every two-component tracked directory prefix (prong 2).
declare -A IS_TRACKED=()
declare -A HAS_SUFFIX=()
declare -A IS_MODULE_DIR=()
while IFS= read -r p; do
    IS_TRACKED["$p"]=1
    rest="$p"
    while [ "${rest#*/}" != "$rest" ]; do
        rest="${rest#*/}"
        HAS_SUFFIX["$rest"]=1
    done
    case "$p" in
        */*/*)
            p_top="${p%%/*}"
            p_rest="${p#*/}"
            IS_MODULE_DIR["$p_top/${p_rest%%/*}"]=1
            ;;
    esac
done < "$TMP/tracked"
gate_require_scanned "${#IS_MODULE_DIR[@]}" 20 check_doc_inline_paths \
    "no two-component tracked directories — the module-directory prong would pass on anything"

# Collapse "a/b/../c" -> "a/c" and strip a leading "./".
# The label/branch is spelled with separate -e expressions on purpose: a
# one-string `sed -E 's#^\./##; :a; ...; ta'` misparses on Apple's sed
# ("unused label"), which left every "../" path unresolved and failed the
# gate on phantom drift.
norm() {
    printf '%s' "$1" | sed -E -e 's#^\./##' -e ':a' -e 's#(^|/)[^/]+/\.\./#\1#' -e 'ta'
}

resolves() {
    local tok="$1" docdir="$2"
    [ -n "${IS_TRACKED[$tok]:-}" ] && return 0
    [ -n "${HAS_SUFFIX[$tok]:-}" ] && return 0
    local rel; rel="$(norm "$docdir/$tok")"
    [ -n "${IS_TRACKED[$rel]:-}" ] && return 0
    return 1
}

# One awk pass over the whole corpus emits "<kind>TAB<file>TAB<line>TAB<token>"
# records: kind F for a file path (prong 1), kind D for a module directory
# (prong 2). Shelling out to grep/sed per line made this the slowest gate in
# the umbrella. External-URL link text is stripped first: it names another
# project's file.
git grep -n '`' -- "$DOC_GLOB" \
  | awk -F: -v tops="$MODULE_TOPS" '
      { file=$1; lineno=$2;
        text=substr($0, length(file)+length(lineno)+3);
        if (text ~ /doc-path-ok/) next;
        gsub(/\[`[^`]*`\]\((https?|mailto):[^)]*\)/, "", text);
        rest = text;
        while (match(text, /`[A-Za-z0-9_.\/-]+\.(c|h|cc|def|inc|sh|md|txt|tsv|py|json)(:[0-9]+(-[0-9]+)?)?`/)) {
            tok = substr(text, RSTART+1, RLENGTH-2);
            text = substr(text, RSTART+RLENGTH);
            sub(/:[0-9]+(-[0-9]+)?$/, "", tok);
            if (tok ~ /\//) print "F\t" file "\t" lineno "\t" tok;
        }
        while (match(rest, /`[A-Za-z0-9_.\/-]+\/?`/)) {
            tok = substr(rest, RSTART+1, RLENGTH-2);
            rest = substr(rest, RSTART+RLENGTH);
            sub(/\/+$/, "", tok);
            if (tok !~ ("^(" tops ")/")) continue;
            n = split(tok, seg, "/");
            if (n < 2 || seg[2] ~ /\./) continue;
            print "D\t" file "\t" lineno "\t" seg[1] "/" seg[2];
        }
      }' > "$TMP/records"

grep -c $'^F\t' "$TMP/records" > "$TMP/fcount" || true
grep -c $'^D\t' "$TMP/records" > "$TMP/dcount" || true
gate_require_scanned "$(cat "$TMP/fcount")" 200 check_doc_inline_paths \
    "the tokenizer found almost no backticked source paths — regex or corpus broke"
gate_require_scanned "$(cat "$TMP/dcount")" 100 check_doc_inline_paths \
    "the tokenizer found almost no backticked module directories — regex or corpus broke"

: > "$TMP/found"
: > "$TMP/found_lines"
# The baseline key deliberately omits the line number: a doc edit that shifts a
# line must not churn the baseline into a double failure.
while IFS=$'\t' read -r kind f ln raw; do
    if [ "$kind" = "D" ]; then
        [ -n "${IS_MODULE_DIR[$raw]:-}" ] && continue
        printf '%s -> %s/\n' "$f" "$raw" >> "$TMP/found"
        printf '%s:%s -> %s/\n' "$f" "$ln" "$raw" >> "$TMP/found_lines"
        continue
    fi
    tok=$(norm "$raw")
    case "$tok" in
        /*|build/*|.cache/*|test-tmp/*) continue ;;
        */*) ;;
        *) continue ;;
    esac
    resolves "$tok" "$(dirname "$f")" || {
        printf '%s -> %s\n' "$f" "$tok" >> "$TMP/found"
        printf '%s:%s -> %s\n' "$f" "$ln" "$tok" >> "$TMP/found_lines"
    }
done < "$TMP/records"
sort -u "$TMP/found" > "$TMP/current"

declare -A BASE=()
base_count=0
gate_load_list_file "$BASELINE" BASE base_count

: > "$TMP/new"
: > "$TMP/still"
while IFS= read -r v; do
    [ -n "$v" ] || continue
    if [ -n "${BASE[$v]:-}" ]; then echo "$v" >> "$TMP/still"; else echo "$v" >> "$TMP/new"; fi
done < "$TMP/current"

: > "$TMP/fixed"
for k in "${!BASE[@]}"; do
    grep -qxF -- "$k" "$TMP/current" || echo "$k" >> "$TMP/fixed"
done

new_count=$(wc -l < "$TMP/new")
fixed_count=$(wc -l < "$TMP/fixed")
rc=0

if [ "$new_count" -gt 0 ]; then
    echo "check_doc_inline_paths: FAIL — $new_count backticked path(s)/director(y|ies) in Markdown do not exist:" >&2
    while IFS= read -r v; do
        grep -F -- " -> ${v#* -> }" "$TMP/found_lines" | grep -F "${v%% -> *}:" | sed 's/^/  /' >&2
    done < "$TMP/new"
    echo "" >&2
    echo "  Fix the DOC to match the tree (never move code to match a doc)." >&2
    echo "  Find the real path:  z23 code sym --input='{\"name\":\"<symbol>\"}'" >&2
    echo "                       git ls-files | grep '<basename>'" >&2
    echo "  If the path is deliberately absent (a deleted file cited for git" >&2
    echo "  recovery, an upstream project's file in an attribution), add" >&2
    echo "  '<!-- doc-path-ok: <reason> -->' on that line." >&2
    rc=1
fi

if [ "$fixed_count" -gt 0 ]; then
    echo "check_doc_inline_paths: FAIL — $fixed_count baseline entr(y|ies) now resolve." >&2
    echo "  This baseline is shrink-only. Delete these lines from $BASELINE:" >&2
    sed 's/^/  /' "$TMP/fixed" >&2
    rc=1
fi

[ "$rc" -eq 0 ] || exit 1

still=$(wc -l < "$TMP/still")
echo "check_doc_inline_paths: PASS (${#DOCS[@]} docs scanned, $still baselined, 0 new)"
