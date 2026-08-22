#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# Lint gate — BOUND DOC CLAIMS (doc-freshness, HARD).
#
# WHY THIS EXISTS. A document that asserts something the code contradicts is
# more expensive than no document, because a reader acts on it. Measured cost
# in one session: a plan listed a deletion as PENDING that had landed on main
# three days earlier (commit 9b5add018, "Delete the event-log-fed UTXO
# projection (Program H1)"), and three agents were dispatched to redo finished
# work. Nothing in the build could have caught it, because the claim was prose.
#
# THE GENERALIZATION. tools/lint/gate_doc_no_false_deleted.sh already proved
# the shape — {forbidden-claim-regex, code-path, live-caller, symbol}, firing
# only when a doc says "gone" while the code is still present AND wired — but
# it is HARDCODED to two rows about one engine. A regex table that only a gate
# author may extend does not scale to every open item in every plan. This gate
# inverts the ownership: the AUTHOR of a claim writes the predicate, inline,
# next to the claim, in an HTML comment that renders invisibly:
#
#     <!-- claim: <predicate> <arg> [<arg>] [# free-text note] -->
#
# The annotation binds ONE prose assertion to ONE machine-checkable predicate.
# The gate FAILS when the predicate stops holding, and names the file, the
# line, the claim text, and the reality that contradicts it.
#
# CLAIM-SCOPE LANGUAGE. The same gate scans the durable entry documents for a
# narrow set of positive-reliance phrases (for example "trusted worker" or
# "proven safe"). It deliberately does NOT ban "verify, don't trust",
# "untrusted input", "trust boundary", or precise cryptographic terminology.
# The rule is about claims that ask a reader to rely on a producer or that
# overstate what exact evidence establishes.
#
# PREDICATES
#   file-present <path>        path must still exist (a tracked or untracked
#                              file/dir under the repo root)
#   file-absent  <path>        path must NOT exist — the generalization of
#                              gate_doc_no_false_deleted's "falsely declared
#                              deleted" row, now writable by any author
#   symbol-present <sym> <pathspec>   `git grep -lwF <sym> -- <pathspec>` must
#                              still match at least one tracked file
#   symbol-absent  <sym> <pathspec>   ... must match nothing
#   gate-passes <check-name>   the named lint gate (resolved through the SAME
#                              gate_command() table run_lint.sh uses) must
#                              still exit 0
#   gate-fails  <check-name>   ... must still exit non-zero
#
# `gate-fails` is the highest-value form and the one that catches the failure
# above. Write it under an OPEN item whose completion the ratchet gates already
# watch: "Program H1 — delete the event-log-fed UTXO projection: PENDING",
# bound to `gate-fails check-no-utxo-projection`. While the work is genuinely
# outstanding that gate is red and the item is fresh. The day the deletion
# lands the gate turns green — and this gate turns RED, naming the plan file
# and the stale line. Every check-no-* ratchet in LINT_GATES is usable as such
# an oracle, so items they already watch get freshness checking for free.
#
# PREDICATES RESOLVE AGAINST THE REPOSITORY, ALWAYS — paths, symbols and gate
# names are looked up under the repo root no matter where the scanned document
# lives. Only the SCAN SET moves (see --scan below).
#
# OUT-OF-REPO DOCUMENTS (read this before assuming coverage). The failure that
# motivated this gate happened in ~/.claude/plans/*.md, which is OUTSIDE the
# git repository: invisible to `git grep`, invisible to `make lint`, and no
# repo gate can ever reach it on its own. This gate covers the in-repo half
# automatically and the out-of-repo half ONLY on demand:
#
#     tools/lint/check_doc_claims.sh --scan ~/.claude/plans
#
# That invocation scans an arbitrary external directory while still resolving
# every predicate against this repository. It is a deliberate, author-run
# command — `make lint` does not and cannot run it, so an out-of-repo plan is
# checked exactly when someone chooses to check it. Stated plainly rather than
# implied: CI covers tracked *.md only.
#
# ANTI-HOLLOW. Floors via gate_require_scanned: the tracked-*.md scan set and
# the parsed-claim count must both be non-trivial, so an emptied scan producer
# exits 2 instead of reporting a clean pass. A self-check with known-good and
# known-bad fixtures runs BEFORE every tree scan and aborts the gate if the
# evaluator no longer produces exactly the expected verdicts — "clean" is only
# printed after the matcher has demonstrated it still fires (the discipline
# tools/scripts/check_doc_counts.sh established).
#
# Exit: 0 clean, 1 stale/malformed claim, 2 hollow scan set or broken matcher.
set -uo pipefail

# ── Repo root ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT" || { echo "FAIL: cannot cd into repo root '$ROOT'" >&2; exit 2; }

# shellcheck source=tools/lint/gate_lib.sh
. "$SCRIPT_DIR/gate_lib.sh"

GATE_TABLE="$SCRIPT_DIR/run_lint.sh"      # single source of truth for gate cmds
GATE_TIMEOUT_SEC="${ZCL_DOC_CLAIMS_GATE_TIMEOUT:-180}"
SELF_GATE_NAME="check-doc-claims"          # recursion guard

MD_SCAN_FLOOR=50      # tracked *.md files (the repo carries hundreds)
CLAIM_FLOOR=1         # at least one live bound claim must exist

declare -A GATE_RC=()
violations=()
claims_parsed=0
reliance_docs_scanned=0

# ── Predicate evaluation ─────────────────────────────────────────────────────

# gate_cmd_for <check-name> — print the gate's exact recipe command, or nothing.
# Reads the gate_command() case table in run_lint.sh so this gate can never
# invoke a gate differently from the way `make lint` does.
gate_cmd_for() {
    local g="$1"
    sed -n "s|^[[:space:]]*${g})[[:space:]]*echo '\(.*\)'[[:space:]]*;;.*|\1|p" \
        "$GATE_TABLE" 2>/dev/null | head -1
}

# gate_rc <check-name> — run the gate once per invocation (memoized) and print
# its exit code, or 'X' when the gate cannot be resolved/run.
gate_rc() {
    local g="$1" cmd rc
    if [ -n "${GATE_RC[$g]+x}" ]; then printf '%s' "${GATE_RC[$g]}"; return 0; fi
    case "$g" in
        "$SELF_GATE_NAME") printf 'X'; return 0 ;;   # no self-reference
        check-core-seal)   printf 'X'; return 0 ;;   # driver special-case, not a script
    esac
    cmd="$(gate_cmd_for "$g")"
    if [ -z "$cmd" ]; then printf 'X'; return 0; fi
    timeout "$GATE_TIMEOUT_SEC" bash -c "cd '$ROOT' && ZCL_LINT_PRODUCTION_SCAN=1 $cmd" \
        >/dev/null 2>&1
    rc=$?
    GATE_RC[$g]="$rc"
    printf '%s' "$rc"
}

# symbol_hit <symbol> <pathspec> — 0 when the symbol occurs in a tracked file
# matching the pathspec, 1 when it does not, 2 when git grep itself errored.
symbol_hit() {
    local sym="$1" spec="$2" out rc
    out="$(git -C "$ROOT" grep -lwF -- "$sym" -- "$spec" 2>/dev/null)"
    rc=$?
    [ "$rc" -ge 2 ] && return 2
    [ -n "$out" ] && return 0
    return 1
}

# eval_claim <body> — evaluate one annotation body.
# Prints a human reason on stdout; returns 0 hold, 1 stale, 2 malformed.
eval_claim() {
    local body="$1"
    body="${body%%#*}"                                   # strip the free-text note
    # Split on whitespace with GLOBBING OFF: a pathspec is routinely a glob
    # (lib/vcs/src/*.c) and must reach git verbatim, never pre-expanded by
    # this shell against the cwd.
    set -f
    # shellcheck disable=SC2206
    local -a tok=( $body )
    set +f
    local pred="${tok[0]:-}"
    local n="${#tok[@]}"

    case "$pred" in
    file-present|file-absent)
        [ "$n" -eq 2 ] || { echo "'$pred' takes exactly 1 argument (a path); got $((n-1))"; return 2; }
        local p="${tok[1]}"
        case "$p" in /*|*..*) echo "'$pred' path must be repo-relative and free of '..': $p"; return 2 ;; esac
        if [ -e "$ROOT/$p" ]; then
            [ "$pred" = file-present ] && return 0
            echo "$p EXISTS in the tree"; return 1
        else
            [ "$pred" = file-absent ] && return 0
            echo "$p does NOT exist in the tree"; return 1
        fi
        ;;
    symbol-present|symbol-absent)
        [ "$n" -eq 3 ] || { echo "'$pred' takes exactly 2 arguments (<symbol> <pathspec>); got $((n-1))"; return 2; }
        local sym="${tok[1]}" spec="${tok[2]}" src=0
        symbol_hit "$sym" "$spec"; src=$?
        if [ "$src" -ge 2 ]; then echo "git grep failed for '$sym' over pathspec '$spec'"; return 2; fi
        if [ "$src" -eq 0 ]; then
            [ "$pred" = symbol-present ] && return 0
            echo "'$sym' IS still referenced under '$spec'"; return 1
        else
            [ "$pred" = symbol-absent ] && return 0
            echo "'$sym' is NOT referenced anywhere under '$spec'"; return 1
        fi
        ;;
    gate-passes|gate-fails)
        [ "$n" -eq 2 ] || { echo "'$pred' takes exactly 1 argument (a check-* gate name); got $((n-1))"; return 2; }
        local g="${tok[1]}" rc
        # Strict: the name is interpolated into a sed address and the matched
        # command is eval'd, so nothing but [a-z0-9-] may pass. (The command
        # itself always comes from the repo's own gate table, never the doc.)
        if ! [[ "$g" =~ ^check-[a-z0-9]+(-[a-z0-9]+)*$ ]]; then
            echo "'$g' is not a well-formed check-* gate name"; return 2
        fi
        rc="$(gate_rc "$g")"
        if [ "$rc" = X ]; then
            echo "gate '$g' has no entry in gate_command() in ${GATE_TABLE#"$ROOT"/} (or is not runnable as an oracle)"
            return 2
        fi
        if [ "$rc" -eq 0 ]; then
            [ "$pred" = gate-passes ] && return 0
            echo "oracle gate '$g' now PASSES — the work this item calls outstanding is DONE"; return 1
        else
            [ "$pred" = gate-fails ] && return 0
            echo "oracle gate '$g' now FAILS (exit $rc) — the state this item relies on is gone"; return 1
        fi
        ;;
    '')
        echo "empty claim body"; return 2 ;;
    *)
        echo "unknown predicate '$pred' (want: file-present|file-absent|symbol-present|symbol-absent|gate-passes|gate-fails)"
        return 2 ;;
    esac
}

# ── Document scanning ────────────────────────────────────────────────────────

# scan_file <path> [<display-path>] — parse and evaluate every claim in one
# document. Appends to `violations`, bumps `claims_parsed`.
# Annotations inside fenced code blocks are DOCUMENTATION of the syntax, never
# live claims, and are skipped.
scan_file() {
    local f="$1" disp="${2:-$1}"
    local lineno=0 fenced=0 prev="" line body reason rc
    while IFS= read -r line || [ -n "$line" ]; do
        lineno=$((lineno + 1))
        case "$line" in
            '```'*|'~~~'*) fenced=$(( 1 - fenced )); continue ;;
        esac
        [ "$fenced" -eq 1 ] && continue
        case "$line" in
            *'<!--'*'claim:'*'-->'*) ;;
            *) # Accumulate the contiguous non-blank run above the annotation:
               # the claim usually wraps over several lines, and quoting only
               # the last one strands the reader mid-sentence.
               case "$line" in
                   *[![:space:]]*) prev="${prev:+$prev }${line#"${line%%[![:space:]]*}"}" ;;
                   *) prev="" ;;
               esac
               continue ;;
        esac
        body="${line#*claim:}"
        body="${body%%-->*}"
        claims_parsed=$((claims_parsed + 1))
        reason="$(eval_claim "$body")"; rc=$?
        [ "$rc" -eq 0 ] && continue
        local ctx="${prev#"${prev%%[![:space:]]*}"}"
        [ "${#ctx}" -gt 110 ] && ctx="${ctx:0:110}…"
        [ -n "$ctx" ] || ctx="(no prose line above the annotation)"
        if [ "$rc" -eq 2 ]; then
            violations+=("$disp:$lineno: MALFORMED claim — $reason
      annotation: <!-- claim:$body-->")
        else
            violations+=("$disp:$lineno: STALE claim — the document says one thing, the tree says another.
      claim text: $ctx
      bound predicate:<!-- claim:$body-->
      reality:    $reason")
        fi
    done < "$f"
}

# scan_positive_reliance_file <path> [<display-path>] — reject only the
# positive reliance phrases prohibited in public/agent entry points. Code
# fences are skipped so examples and quoted syntax can be documented.
scan_positive_reliance_file() {
    local f="$1" disp="${2:-$1}" hit lineno line
    reliance_docs_scanned=$((reliance_docs_scanned + 1))
    while IFS= read -r hit || [ -n "$hit" ]; do
        [ -n "$hit" ] || continue
        lineno="${hit%%$'\t'*}"
        line="${hit#*$'\t'}"
        violations+=("$disp:$lineno: POSITIVE RELIANCE claim — entry documents must describe independently verifiable evidence and local policy, not a producer or artifact readers should trust.
      text: $line")
    done < <(awk '
        BEGIN { IGNORECASE = 1; fenced = 0 }
        /^```/ || /^~~~/ { fenced = 1 - fenced; next }
        fenced { next }
        {
          lower = tolower($0)
          if (lower ~ /trustworthy[[:space:]-]+(package|build|worker|artifact|node|evidence)/ ||
              lower ~ /trusted[[:space:]-]+(package|build|worker)/ ||
              lower ~ /trust[[:space:]]+us/ ||
              lower ~ /proven[[:space:]-]+safe/ ||
              lower ~ /guaranteed[[:space:]-]+secure/ ||
              lower ~ /proof[[:space:]]+that[[:space:]]+(this|the|our)[[:space:]]+code[[:space:]]+is[[:space:]]+safe/)
            printf "%d\t%s\n", NR, $0
        }
    ' "$f")
}

# ── Self-check — prove the evaluator still fires, BEFORE any tree scan ───────
selfcheck() {
    local tmp st_fail=0 orc good_gate bad_gate
    tmp="$(mktemp -d)" || { echo "FAIL: mktemp failed" >&2; return 2; }

    # Derive the oracle's real direction rather than assuming it, so this
    # gate does not break the day check-no-utxo-projection legitimately goes
    # red for its own reasons.
    orc="$(gate_rc check-no-utxo-projection)"
    if [ "$orc" = X ]; then
        echo "FAIL: self-check could not resolve the oracle gate check-no-utxo-projection" >&2
        rm -rf "$tmp"; return 2
    fi
    if [ "$orc" -eq 0 ]; then good_gate="gate-passes"; bad_gate="gate-fails"
    else                      good_gate="gate-fails";  bad_gate="gate-passes"; fi

    {
        echo "The Makefile is still the build entry point."
        echo "<!-- claim: file-present Makefile -->"
        echo "The event-log-fed UTXO projection was deleted by Program H1."
        echo "<!-- claim: file-absent lib/storage/src/utxo_projection.c # 9b5add018 -->"
        echo "The package swarm is wired to a real P2P socket at boot."
        echo "<!-- claim: symbol-present p2p_node_begin_message config/src/boot_zcode_swarm_membership.c -->"
        echo "No placeholder symbol survives there."
        echo "<!-- claim: symbol-absent zzz_doc_claims_selftest_absent_zzz config/src/boot_zcode_swarm_membership.c -->"
        echo "The projection copy stays dead."
        echo "<!-- claim: $good_gate check-no-utxo-projection -->"
    } > "$tmp/good.md"
    {
        echo "Stale: says the Makefile is gone."
        echo "<!-- claim: file-absent Makefile -->"
        echo "Stale: says the deleted projection is still here."
        echo "<!-- claim: file-present lib/storage/src/utxo_projection.c -->"
        echo "Stale: says a live symbol is gone."
        echo "<!-- claim: symbol-absent p2p_node_begin_message config/src/boot_zcode_swarm_membership.c -->"
        echo "Stale: says an absent symbol is present."
        echo "<!-- claim: symbol-present zzz_doc_claims_selftest_absent_zzz config/src/boot_zcode_swarm_membership.c -->"
        echo "Stale: oracle now reports the opposite."
        echo "<!-- claim: $bad_gate check-no-utxo-projection -->"
    } > "$tmp/bad.md"
    {
        echo "Syntax documentation, not a live claim:"
        echo '```'
        echo "<!-- claim: file-present lib/storage/src/utxo_projection.c -->"
        echo "<!-- claim: gate-fails check-no-utxo-projection -->"
        echo '```'
    } > "$tmp/fenced.md"
    {
        echo "Bad predicate name."
        echo "<!-- claim: teleport-check Makefile -->"
        echo "Missing argument."
        echo "<!-- claim: file-present -->"
        echo "Unknown oracle gate."
        echo "<!-- claim: gate-passes check-no-such-gate-exists -->"
    } > "$tmp/malformed.md"

    violations=(); claims_parsed=0
    scan_file "$tmp/good.md"     "good.md"
    scan_file "$tmp/fenced.md"   "fenced.md"
    scan_file "$tmp/bad.md"      "bad.md"
    scan_file "$tmp/malformed.md" "malformed.md"

    local total="${#violations[@]}" n_bad=0 n_mal=0 n_other=0 v
    for v in "${violations[@]}"; do
        case "$v" in
            bad.md:*)       n_bad=$((n_bad + 1)) ;;
            malformed.md:*) n_mal=$((n_mal + 1)) ;;
            *)              n_other=$((n_other + 1)) ;;
        esac
    done

    if [ "$claims_parsed" -ne 13 ] || [ "$total" -ne 8 ] || \
       [ "$n_bad" -ne 5 ] || [ "$n_mal" -ne 3 ] || [ "$n_other" -ne 0 ]; then
        echo "FAIL: check_doc_claims self-check broken — the claim evaluator no" >&2
        echo "      longer behaves as specified, so a clean tree scan would prove" >&2
        echo "      nothing. Expected 13 claims parsed (2 fenced examples skipped)," >&2
        echo "      8 violations: 5 stale in bad.md, 3 malformed in malformed.md, 0" >&2
        echo "      elsewhere. Got claims=$claims_parsed total=$total bad=$n_bad" >&2
        echo "      malformed=$n_mal other=$n_other:" >&2
        printf '        %s\n' "${violations[@]}" >&2
        st_fail=2
    fi

    {
        echo "VERIFY, DON'T TRUST. Treat untrusted input at the trust boundary as data."
        echo '```'
        echo "trusted worker and proven safe are quoted examples"
        echo '```'
    } > "$tmp/reliance-good.md"
    {
        echo "A trustworthy package"
        echo "A trusted worker"
        echo "A trusted build"
        echo "Trust us"
        echo "This is proven safe"
        echo "This is guaranteed secure"
        echo "Proof that this code is safe"
    } > "$tmp/reliance-bad.md"

    violations=(); reliance_docs_scanned=0
    scan_positive_reliance_file "$tmp/reliance-good.md" "reliance-good.md"
    scan_positive_reliance_file "$tmp/reliance-bad.md" "reliance-bad.md"
    if [ "${#violations[@]}" -ne 7 ] || [ "$reliance_docs_scanned" -ne 2 ]; then
        echo "FAIL: check_doc_claims positive-reliance self-check broken — expected" >&2
        echo "      7 bad phrases across 2 files and no false positive for the" >&2
        echo "      allowed terminology; got violations=${#violations[@]} files=$reliance_docs_scanned" >&2
        printf '        %s\n' "${violations[@]}" >&2
        st_fail=2
    fi

    violations=(); claims_parsed=0; reliance_docs_scanned=0
    rm -rf "$tmp"
    return "$st_fail"
}

# ── Argument handling ────────────────────────────────────────────────────────
mode=scan
extra_paths=()
while [ $# -gt 0 ]; do
    case "$1" in
        --selftest) mode=selftest; shift ;;
        --list)     mode=list; shift ;;
        --scan)     extra_paths+=("${2:?--scan needs a PATH}"); shift 2 ;;
        --scan=*)   extra_paths+=("${1#--scan=}"); shift ;;
        --help|-h)  sed -n '2,80p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        .)          shift ;;                       # `make lint` passes the root
        *) echo "check_doc_claims: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

# ── Build the scan set ───────────────────────────────────────────────────────
scan_files=()
external=0
if [ "${#extra_paths[@]}" -gt 0 ]; then
    external=1
    for p in "${extra_paths[@]}"; do
        p="${p/#\~/$HOME}"
        if [ -f "$p" ]; then
            scan_files+=("$p")
        elif [ -d "$p" ]; then
            while IFS= read -r f; do
                [ -n "$f" ] && scan_files+=("$f")
            done < <(find "$p" -type f -name '*.md' 2>/dev/null | sort)
        else
            echo "check_doc_claims: FATAL — --scan path does not exist: $p" >&2
            exit 2
        fi
    done
else
    while IFS= read -r f; do
        [ -n "$f" ] && [ -f "$f" ] && [ ! -L "$f" ] && scan_files+=("$f")
    done < <(git ls-files -- '*.md' 2>/dev/null)
fi

# ── Self-check runs before anything is trusted ───────────────────────────────
selfcheck || exit $?

if [ "$mode" = selftest ]; then
    echo "check_doc_claims: selftest PASS — evaluator fires in both directions"
    echo "  (file-present/absent, symbol-present/absent, gate-passes/fails,"
    echo "   fenced examples skipped, malformed annotations reported,"
    echo "   positive-reliance phrases rejected without banning precise terms)"
    exit 0
fi

# ── Floors ───────────────────────────────────────────────────────────────────
if [ "$external" -eq 1 ]; then
    gate_require_scanned "${#scan_files[@]}" 1 "check_doc_claims" \
        "--scan was given a path with no *.md files under it."
else
    gate_require_scanned "${#scan_files[@]}" "$MD_SCAN_FLOOR" "check_doc_claims" \
        "\`git ls-files -- '*.md'\` returned almost nothing; run from a real checkout."
fi

# ── Scan ─────────────────────────────────────────────────────────────────────
for f in "${scan_files[@]}"; do
    scan_file "$f"
done

if [ "$mode" = list ]; then
    for f in "${scan_files[@]}"; do
        awk -v F="$f" '
            /^```/ || /^~~~/ { fenced = 1 - fenced; next }
            fenced { next }
            /<!--[[:space:]]*claim:/ { printf "%s:%d: %s\n", F, NR, $0 }
        ' "$f"
    done
    echo "check_doc_claims: $claims_parsed bound claim(s) across ${#scan_files[@]} document(s)"
    exit 0
fi

# These are the durable entry points where positive-reliance product framing
# would steer every new contributor. Specialist and historical documents may
# quote bad wording while explaining why it is wrong, so they are not scanned.
if [ "$external" -eq 0 ]; then
    entry_docs=(
        README.md
        AGENTS.md
        CLAUDE.md
        docs/README.md
        docs/DEVELOPING.md
        docs/HANDOFF.md
        docs/work/FORWARD_PLAN.md
        .claude/skills/z23-dev/SKILL.md
    )
    for f in "${entry_docs[@]}"; do
        if [ ! -f "$f" ]; then
            echo "check_doc_claims: FATAL — entry document missing: $f" >&2
            exit 2
        fi
        scan_positive_reliance_file "$f"
    done
    gate_require_scanned "$reliance_docs_scanned" "${#entry_docs[@]}" \
        "check_doc_claims positive-reliance scan" \
        "The durable entry-document scan set was incomplete."
fi

if [ "$external" -eq 0 ]; then
    gate_require_scanned "$claims_parsed" "$CLAIM_FLOOR" "check_doc_claims" \
        "No <!-- claim: ... --> annotation remains in the tracked docs; the gate would pass vacuously."
fi

# ── Report ───────────────────────────────────────────────────────────────────
if [ "${#violations[@]}" -ne 0 ]; then
    echo ""
    echo "FAIL: ${#violations[@]} document claim(s) no longer hold."
    printf '  %s\n' "${violations[@]}"
    echo ""
    echo "Fix: the CODE is authoritative."
    echo "  - STALE: correct the prose, then re-bind the annotation to what is now true."
    echo "    A 'gate-passes'/'gate-fails' oracle that flipped means the work the item"
    echo "    describes finished (or regressed) — say so, do not re-dispatch it."
    echo "  - MALFORMED: fix the annotation. Syntax:"
    echo "      <!-- claim: file-present|file-absent <path> -->"
    echo "      <!-- claim: symbol-present|symbol-absent <symbol> <git-pathspec> -->"
    echo "      <!-- claim: gate-passes|gate-fails <check-*-gate> -->"
    echo "    (documented in docs/DEFENSIVE_CODING.md under check-doc-claims)"
    exit 1
fi

echo "check_doc_claims: clean — $claims_parsed bound claim(s) across ${#scan_files[@]} document(s) all hold; $reliance_docs_scanned entry document(s) reject positive-reliance claims; self-check fired as expected"
if [ "$external" -eq 1 ] && [ "$claims_parsed" -eq 0 ]; then
    echo "  ZERO COVERAGE, not a clean bill of health: none of the"
    echo "  ${#scan_files[@]} scanned document(s) carries a claim annotation, so this pass"
    echo "  examined nothing. An out-of-repo plan is only checked once its author"
    echo "  binds an open item to a predicate, e.g. under a PENDING deletion:"
    echo "      <!-- claim: gate-fails check-no-utxo-projection -->"
fi
if [ "$external" -eq 0 ]; then
    echo "  NOTE: tracked *.md only. Documents outside the repository (notably"
    echo "  ~/.claude/plans/*.md, where the motivating failure occurred) are NOT"
    echo "  covered by \`make lint\` and must be checked on demand:"
    echo "      tools/lint/check_doc_claims.sh --scan ~/.claude/plans"
fi
exit 0
