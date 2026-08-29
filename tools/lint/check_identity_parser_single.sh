#!/usr/bin/env bash
# check_identity_parser_single.sh — stop a tenth copy of the source-identity
# JSON parser from growing back. Mode: shrink-only ratchet (ZCL_LINT_MODE:
# FAIL default | WARN | UPDATE — same shape as check_supervisor_progress_declared.sh).
#
# WHY THIS EXISTS: "source_id_sha256" was parsed inline in ~9 shell files,
# with `is_sha256`/`is_hex64`/`json_first_string_field` each redefined
# several times over — and the copies had DIVERGED: a greedy `sed
# 's/.*"key":"\(...\)".*/\1/'` returns the LAST occurrence of a repeated
# JSON key, not the first, and `agentbuild` emits `source_id_sha256`
# SEVERAL times on one line (8 on one build measured 2026-07-30; the exact
# count is build- and lane-state-dependent — once baked, the rest in
# nested runtime blocks). That produced a false "the live daemon and the
# dev build have identical identities" on 2026-07-28.
# tools/scripts/source_identity_lib.sh is now the one canonical reader
# (anchored on the FIRST occurrence); this gate is the anti-rot check
# that keeps a new copy from being pasted back in.
#
# Two things counted, per scanned *.sh file:
#   A. A local re-definition of the 64-lowercase-hex validator, caught
#      TWO ways so a rename cannot dodge it:
#        A1. exact name: json_first_string_field (the JSON-field-extractor
#            helper — no rename exploit has been demonstrated against this
#            one, so it stays name-matched).
#        A2. STRUCTURAL, name-independent: any short function (at most
#            BODY_LIMIT substantive body lines) whose body performs a
#            64-lowercase-hex validity check — `=~ ^[0-9a-f]{64}$`, a quiet
#            (`-q`) grep on that pattern, or the `*[!0-9a-f]*` case-pattern
#            rejection idiom. This is what closes the exploit the verifier
#            proved on 2026-07-30: a file containing only
#            `is_sha256_hex() { ... }` (a name that matches none of the
#            fixed A1-style list) passed this gate silently. Matching the
#            SHAPE of the validator rather than a name list means a rename
#            cannot dodge it. The body-line cap keeps this from over-firing
#            on unrelated multi-purpose functions that happen to touch a
#            64-hex value for a different reason entirely (a UTXO
#            commitment reader, a compiler-id cache key, a generation
#            manifest reader that also does its own JSON extraction) —
#            see scan_counts() for the exact gating and why grep -oE
#            (extraction) is deliberately NOT treated as the same shape as
#            grep -Eq / `=~` (a boolean test).
#   B. an inline grep/sed extraction of the "source_id_sha256" JSON key —
#      the copy-pasted one-liner the library replaces. Plain JSON
#      construction (`printf '"source_id_sha256":"%s"'`) does NOT count:
#      only a line that also invokes grep or sed is a parser copy.
#
# Shrink-only ratchet: tools/lint/identity_parser_baseline.txt names the
# files with a deliberately-not-yet-migrated copy and how many occurrences
# each carries (a visible to-do, not just a number). A file with no
# baseline row may carry ZERO. A baselined file may carry AT MOST its
# recorded count; once it reaches zero the row is STALE and must be
# deleted, or the ratchet rusts shut at a number nobody is paying down.
#
# RATCHET_CEILING below is the total measured across the baseline —
# 16, across 11 files (see the baseline header). It moved from 15 to 16
# once (2026-07-30, same day this gate was introduced): broadening Class-A
# detection from an exact name list to also catch the validator SHAPE
# (see the file header) surfaced two real, previously-invisible copies —
# tools/agent_fast_ci.sh and tools/repro_on_copy.sh's own is_sha256_hex()
# — that the exact-name list had never seen. That is a detection fix
# surfacing pre-existing debt, not new debt being introduced; the ceiling
# still may only go DOWN from here as rows are migrated and deleted.
# Summing the baseline and refusing to exceed this ceiling is what stops
# someone from quietly bumping a baseline number up to cover new debt while
# leaving the total unchanged elsewhere — raising the ceiling itself is a
# one-line diff in code review, not a silent runtime edit.
#
# tools/ship.sh once carried two remote inline parsers as permanent
# exemptions. The fleet publisher now binds the running /proc executable
# SHA-256 to the locally source-proven candidate instead, so the production
# marker budget ratcheted to zero. It is back at ONE, for
# tools/scripts/install_z23.sh only — see MARKER_CEILING below for why that
# one file cannot be migrated. The marker machinery is bounded in two
# directions and its selftest proves a future exemption cannot be added
# silently, in either detection class.
#
# --selftest plants a fresh inline copy of both classes in a sandboxed
# tools/ tree, proves the gate FAILS on it, then removes it and proves
# PASS — a ratchet that cannot be shown to fail is worse than no gate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

GATE=check_identity_parser_single
RATCHET_CEILING=16
# See the file header. Bounds the `zcl-identity-parser-allow:` exemption
# mechanism itself: without a ceiling, any new copy anywhere under
# $SCAN_ROOT could dodge the ratchet forever just by pasting the same
# comment near it — an unbounded bypass in a gate whose entire job is
# catching the tenth copy. MARKER_ALLOWED_FILES is the second half: WHICH
# files may carry the marker at all, so a marker planted in a file that
# was never named here fails regardless of the count.
# tools/scripts/install_z23.sh carries the ONE marker in the budget below.
# Its attest_is_sha256() is a genuine 64-hex validator and a genuine Class-A
# shape — but this gate's normal remedy ("source
# tools/scripts/source_identity_lib.sh instead") provably cannot apply to it:
# install_z23.sh is a SHIPPED RELEASE ARTIFACT that the front door
# (packaging/install/install.sh) fetches ALONE into a mktemp directory and
# runs there, with no repository and no sibling library beside it. Shipping a
# second file to source would also break the two-digest
# z23-pin-v1:<manifest>:<installer> pin published in three independent
# places. The validator itself is load-bearing: it checks the two 64-hex
# halves of that pin, and the installer must judge that evidence
# independently of the front door, or a captive portal's junk answer counts
# as an agreeing pin. So the grant is exactly what the mechanism was built
# for: ONE marker, in ONE named file. Both bounds stay — the ceiling caps how
# many exemptions exist at all, the allowlist caps WHERE one may be written.
MARKER_CEILING=1
MARKER_ALLOWED_FILES=(tools/scripts/install_z23.sh)

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/tools/scripts"

    plant() { # $1 = extra line to append to the sandbox file (may be empty)
        cat > "$tmp/tools/scripts/selftest_copy.sh" <<EOF
#!/usr/bin/env bash
# a fixture consumer, not a real tool
echo hello
$1
EOF
    }

    # A second, DIFFERENT file in the sandbox tree, used only by the
    # marker-allowlist tests below: it is never named in
    # ZCL_IDENTITY_PARSER_MARKER_ALLOWED, so a marker planted here proves
    # the "wrong file" half of the marker bound (blocker: a marker must
    # name its file, not just stay under a count).
    plant_other() { # $1 = extra line to append (may be empty)
        cat > "$tmp/tools/scripts/other_copy.sh" <<EOF
#!/usr/bin/env bash
# a second fixture consumer, not a real tool
echo hello2
$1
EOF
    }
    rm -f "$tmp/tools/scripts/other_copy.sh"

    self="$PWD/tools/lint/$GATE.sh"
    : > "$tmp/empty_baseline.txt"

    run_sandbox() {
        ZCL_IDENTITY_PARSER_SCAN_ROOT="$tmp/tools" \
        ZCL_IDENTITY_PARSER_BASELINE="$tmp/empty_baseline.txt" \
        ZCL_IDENTITY_PARSER_CEILING=0 \
        ZCL_IDENTITY_PARSER_FILE_FLOOR=1 \
        ZCL_IDENTITY_PARSER_MARKER_CEILING="${SANDBOX_MARKER_CEILING:-1}" \
        ZCL_IDENTITY_PARSER_MARKER_ALLOWED="$tmp/tools/scripts/selftest_copy.sh" \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >/dev/null 2>&1
    }

    expect() { # $1 = expected rc class (fail|pass), $2 = message, $3 = extra line
        local want="$1" msg="$2" extra="${3:-}" rc=0
        plant "$extra"
        run_sandbox || rc=$?
        if [ "$want" = "fail" ] && [ "$rc" -eq 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
        if [ "$want" = "pass" ] && [ "$rc" -ne 0 ]; then
            echo "$GATE: SELFTEST FAILED — $msg" >&2; exit 2
        fi
    }

    class_a_copy="$(cat <<'FIXTURE'
is_sha256() { [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]; }
FIXTURE
)"
    class_a_renamed_copy="$(cat <<'FIXTURE'
totally_unrelated_name_not_on_any_list() {
    [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}
FIXTURE
)"
    class_b_copy="$(cat <<'FIXTURE'
x=$(printf %s "$1" | grep -oE '"source_id_sha256"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')
FIXTURE
)"
    class_b_marked="$(cat <<'FIXTURE'
# zcl-identity-parser-allow: fixture, cannot source the lib here
x=$(printf %s "$1" | grep -oE '"source_id_sha256"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1)
FIXTURE
)"
    # Class A, both shapes, with the marker directly above the function
    # HEADER — which is where a reviewer writes it, and (for a multi-line
    # body) NOT within 8 lines of the closing brace the count fires on.
    class_a_marked="$(cat <<'FIXTURE'
# zcl-identity-parser-allow: fixture, cannot source the lib here
is_sha256() { [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]; }
FIXTURE
)"
    class_a_marked_multiline="$(cat <<'FIXTURE'
# zcl-identity-parser-allow: fixture, cannot source the lib here
totally_unrelated_name_not_on_any_list() {
    [[ "${1:-}" =~ ^[0-9a-f]{64}$ ]]
}
FIXTURE
)"

    expect pass "a clean consumer with no copy was reported as a violation" ""
    expect fail "an inline is_sha256() definition (class A, named) did not fail the gate" \
        "$class_a_copy"
    expect pass "reverting the class-A copy did not clear the violation" ""
    expect fail "a RENAMED validator (class A, structural — no name on any list) did not fail the gate; the name-list dodge is not closed" \
        "$class_a_renamed_copy"
    expect pass "reverting the renamed structural copy did not clear the violation" ""
    expect fail "an inline grep/sed source_id_sha256 extraction (class B) did not fail the gate" \
        "$class_b_copy"
    expect pass "reverting the class-B copy did not clear the violation" ""
    # A marked (allowlisted) copy in the NAMED file must NOT count as debt.
    expect pass "a zcl-identity-parser-allow-marked copy in the allowed file was still counted as debt" \
        "$class_b_marked"
    expect pass "reverting left a stray marker violation" ""

    # The SAME three proofs for CLASS A. Before fn_start/fn_allow existed,
    # last_allow was read at exactly one place — the class-B branch — so the
    # gate's own documented exemption could not be applied to a class-A copy
    # at all, no matter where the marker was written.
    expect pass "a zcl-identity-parser-allow-marked class-A copy (single-line) in the allowed file was still counted as debt" \
        "$class_a_marked"
    expect pass "reverting the marked single-line class-A copy left a violation" ""
    expect pass "a zcl-identity-parser-allow-marked class-A copy (multi-line body) in the allowed file was still counted as debt; the marker above the HEADER must survive the body" \
        "$class_a_marked_multiline"
    expect pass "reverting the marked multi-line class-A copy left a violation" ""
    # And the marker must exempt only what it marks: an UNMARKED class-A copy
    # in the very same allowlisted file must still fail. Without this, wiring
    # last_allow into class A could exempt everything and nobody would see it.
    expect fail "an UNMARKED class-A copy in the allowlisted file stopped failing — the class-A marker wiring exempts too much" \
        "$class_a_copy"
    expect pass "reverting the unmarked class-A copy did not clear the violation" ""
    expect fail "an UNMARKED renamed structural class-A copy in the allowlisted file stopped failing" \
        "$class_a_renamed_copy"
    expect pass "reverting the unmarked renamed class-A copy did not clear the violation" ""

    # The marker bound, second half: the SAME marked copy, but planted in a
    # file that is NOT in ZCL_IDENTITY_PARSER_MARKER_ALLOWED, must fail —
    # a marker cannot exempt a copy in a file nobody named.
    plant_other "$class_b_marked"
    rc=0; run_sandbox || rc=$?
    plant_other ""
    if [ "$rc" -eq 0 ]; then
        echo "$GATE: SELFTEST FAILED — a zcl-identity-parser-allow marker in an unauthorized file was not caught" >&2
        exit 2
    fi
    rc=0; run_sandbox || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "$GATE: SELFTEST FAILED — reverting the unauthorized marker did not clear the violation" >&2
        exit 2
    fi

    # Same bound, class A: a marked class-A copy in a file nobody named must
    # still fail. A validator that cannot source the library has to be argued
    # for by NAME in MARKER_ALLOWED_FILES, not by writing a comment.
    plant_other "$class_a_marked"
    rc=0; run_sandbox || rc=$?
    plant_other ""
    if [ "$rc" -eq 0 ]; then
        echo "$GATE: SELFTEST FAILED — a zcl-identity-parser-allow-marked class-A copy in an unauthorized file was not caught" >&2
        exit 2
    fi
    rc=0; run_sandbox || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "$GATE: SELFTEST FAILED — reverting the unauthorized class-A marker did not clear the violation" >&2
        exit 2
    fi

    # The marker bound, count half: two markers in the ALLOWED file, with
    # MARKER_CEILING pinned to 1, must fail even though the file itself is
    # on the allowlist.
    two_markers="$(cat <<'FIXTURE'
# zcl-identity-parser-allow: fixture A
a=1
# zcl-identity-parser-allow: fixture B
b=2
FIXTURE
)"
    SANDBOX_MARKER_CEILING=1
    plant "$two_markers"
    rc=0; run_sandbox || rc=$?
    plant ""
    if [ "$rc" -eq 0 ]; then
        echo "$GATE: SELFTEST FAILED — exceeding MARKER_CEILING in the allowed file was not caught" >&2
        exit 2
    fi

    echo "[$GATE] SELFTEST PASS (clean passes; named and renamed class-A copies fail; class-B copies fail; reverted copies pass; an allowlisted+in-budget marker does not count, in class A — single-line AND multi-line body — as well as class B; an UNMARKED class-A copy in that same file still fails; a marker in an unauthorized file, or over MARKER_CEILING, fails in either class)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_IDENTITY_PARSER_BASELINE:-tools/lint/identity_parser_baseline.txt}"
SCAN_ROOT="${ZCL_IDENTITY_PARSER_SCAN_ROOT:-tools}"
CEILING="${ZCL_IDENTITY_PARSER_CEILING:-$RATCHET_CEILING}"
MARKER_CEIL="${ZCL_IDENTITY_PARSER_MARKER_CEILING:-$MARKER_CEILING}"
if [ -n "${ZCL_IDENTITY_PARSER_MARKER_ALLOWED:-}" ]; then
    IFS=' ' read -r -a MARKER_ALLOWED <<< "$ZCL_IDENTITY_PARSER_MARKER_ALLOWED"
else
    MARKER_ALLOWED=("${MARKER_ALLOWED_FILES[@]}")
fi

# The canonical library and this gate itself are excluded: they are the
# thing every other file is compared against (and this file's own header
# comment, and the library's, necessarily quote the exact patterns they
# forbid elsewhere — matching those would be a self-inflicted false
# positive, not a real duplicate).
EXCLUDE_RE='(^|/)source_identity_lib\.sh$|(^|/)check_identity_parser_single\.sh$'

mapfile -t scan_files < <(find "$SCAN_ROOT" -type f -name '*.sh' 2>/dev/null | grep -Ev "$EXCLUDE_RE" || true)
gate_require_scanned "${#scan_files[@]}" "${ZCL_IDENTITY_PARSER_FILE_FLOOR:-5}" "$GATE" \
    "no *.sh files found under $SCAN_ROOT — the scan root moved"

# ── Per-file counts ──────────────────────────────────────────────────────
# Emits: path<TAB>count
#
# Class A1 (name): a local definition (start-of-line, ignoring indent) of
# json_first_string_field — the one duplicated-helper name left on an
# exact list (see the file header for why the validator names moved to A2).
#
# Class A2 (structural, name-independent): a short function — at most
# BODY_LIMIT substantive body lines, one-liner bodies included — whose body
# performs a 64-lowercase-hex validity check. This is what stops a rename
# from dodging Class A entirely (proven exploitable 2026-07-30: a fresh
# file containing only `is_sha256_hex() { ... }` passed this gate). See
# has_sig() below for exactly what counts as the check, and why a plain
# `grep -oE` extraction of a 64-hex value (a different job — reading a
# UTXO commitment root, say — done by unrelated scripts elsewhere in this
# tree) does NOT count: only a boolean test does.
#
# Class B: a line containing the literal JSON-key pattern
# "source_id_sha256"[:space:]*: (plain or backslash-escaped quotes, so a
# copy embedded in a heredoc/ssh command string is still counted) AND
# invoking grep or sed on the same line — plain JSON construction
# (printf '"source_id_sha256":"%s"') is excluded on purpose.
# A `zcl-identity-parser-allow` marker within the previous 8 lines exempts
# a match in EITHER class — bounded separately below by MARKER_CEIL and
# MARKER_ALLOWED, since an unbounded marker is its own hole in the ratchet
# (any future copy anywhere could be exempted forever by pasting the same
# comment near it). It once covered class B only, which meant the gate's
# own documented exemption could not be applied to the case that actually
# needed it: a short 64-hex validator in a file that cannot source the
# library because it ships standalone. For class A the marker sits above
# the function HEADER, so the window is measured from the header line, not
# from the closing brace (see fn_start/fn_allow below).
scan_counts() {
    # The class-B needle is built from sprintf("%c") rather than typed as a
    # quoted/backslashed literal: the data being searched is shell SOURCE
    # TEXT that itself contains a literal backslash and literal quote
    # characters (e.g. \"source_id_sha256\" inside a double-quoted ssh
    # command string), and typing that as an awk string literal is exactly
    # the kind of double-escaping that is easy to get subtly wrong. Building
    # it one character at a time removes any ambiguity about how many
    # backslashes awk's own lexer consumes.
    awk '
        BEGIN {
            bs = sprintf("%c", 92); q = sprintf("%c", 34)
            plain_needle = q "source_id_sha256" q "[[:space:]]*:"
            esc_needle   = bs q "source_id_sha256" bs q "[[:space:]]*:"
            hex_a = "[0-9a-f]{64}"
            hex_b = "[!0-9a-f]"
            BODY_LIMIT = 5
        }
        function has_sig(l) {
            # hex_b (a negated-hex-class case-pattern, e.g. *[!0-9a-f]*) is
            # inherently a boolean branch — it cannot print/extract a
            # value — so it needs no further gating.
            if (index(l, hex_b) > 0) return 1
            # hex_a ("[0-9a-f]{64}") alone is ambiguous: `grep -oE
            # '"'"'[0-9a-f]{64}'"'"'` EXTRACTS a value (e.g. a UTXO
            # commitment reader elsewhere in this tree) and is not a
            # validator copy. Require it appear in an actual boolean test:
            # bash'"'"'s =~ operator, or a quiet (-q) grep.
            if (index(l, hex_a) > 0) {
                if (index(l, "=~") > 0) return 1
                if (l ~ /grep[ \t]+-[A-Za-z]*q/) return 1
            }
            return 0
        }
        FNR == 1 {
            if (NR > 1) emit()
            path = FILENAME; count = 0; last_allow = -1000
            infunc = 0; pending_open = 0; brace_depth = 0
            body_lines = 0; body_has_sig = 0; too_long = 0
            fn_start = 0; fn_allow = -1000
        }
        {
            line = $0
            trimmed = line
            gsub(/^[ \t]+/, "", trimmed); gsub(/[ \t]+$/, "", trimmed)

            if (line ~ /^[ \t]*json_first_string_field[ \t]*\(\)/) {
                count++
            }

            if (line ~ /zcl-identity-parser-allow/) last_allow = FNR

            has_needle = (index(line, plain_needle) > 0 || index(line, esc_needle) > 0)
            has_tool = (index(line, "grep") > 0 || index(line, "sed") > 0)
            if (has_needle && has_tool) {
                if (FNR - last_allow > 8) count++
            }

            # ---- Class A2: structural, name-independent (see has_sig) ----
            if (!infunc && !pending_open) {
                if (trimmed ~ /^[A-Za-z_][A-Za-z0-9_]*\(\)[ \t]*\{.*$/) {
                    # A function BEGINS here (single-line or multi-line body).
                    # The allow-marker sits above the HEADER, so the marker
                    # state is captured at the header and carried to the close
                    # — reading last_allow at the closing brace instead would
                    # push the marker out of the 8-line window for any body
                    # longer than that, and silently un-exempt it.
                    fn_start = FNR; fn_allow = last_allow
                    body_text = trimmed
                    sub(/^[A-Za-z_][A-Za-z0-9_]*\(\)[ \t]*\{/, "", body_text)
                    if (body_text ~ /\}[ \t]*;?[ \t]*$/) {
                        one = body_text
                        sub(/\}[ \t]*;?[ \t]*$/, "", one)
                        if (has_sig(one) && FNR - last_allow > 8) count++
                    } else {
                        infunc = 1; brace_depth = 1
                        body_lines = 0; body_has_sig = 0; too_long = 0
                        if (has_sig(body_text)) body_has_sig = 1
                        if (body_text ~ /[^ \t]/) body_lines++
                    }
                } else if (trimmed ~ /^[A-Za-z_][A-Za-z0-9_]*\(\)[ \t]*$/) {
                    pending_open = 1
                }
            } else if (pending_open) {
                if (trimmed == "{") {
                    # Second entry point for a function body (the `name()`
                    # line and its `{` on separate lines). Same capture: the
                    # marker is above the `name()` header, two lines up.
                    fn_start = FNR; fn_allow = last_allow
                    infunc = 1; pending_open = 0; brace_depth = 1
                    body_lines = 0; body_has_sig = 0; too_long = 0
                } else {
                    pending_open = 0
                }
            } else if (infunc) {
                tmp = line; opens = gsub(/\{/, "{", tmp)
                tmp2 = line; closes = gsub(/\}/, "}", tmp2)
                newdepth = brace_depth + opens - closes
                if (newdepth <= 0) {
                    if (!too_long && body_lines <= BODY_LIMIT && body_has_sig &&
                        fn_start - fn_allow > 8) count++
                    infunc = 0; brace_depth = 0
                } else {
                    if (trimmed ~ /[^ \t]/) body_lines++
                    if (has_sig(line)) body_has_sig = 1
                    if (body_lines > BODY_LIMIT) too_long = 1
                    brace_depth = newdepth
                }
            }
        }
        END { emit() }
        function emit() {
            if (path != "" && count > 0) printf "%s\t%d\n", path, count
        }
    ' "${scan_files[@]}"
}

mapfile -t COUNT_ROWS < <(scan_counts)

declare -A BASELINED=()
gate_load_kv_file "$BASELINE" BASELINED
baseline_count="${#BASELINED[@]}"
baseline_sum=0
for path in "${!BASELINED[@]}"; do
    baseline_sum=$(( baseline_sum + ${BASELINED[$path]} ))
done

declare -A HIT=()
violations=()
tolerated=()
total_copies=0

for row in "${COUNT_ROWS[@]}"; do
    IFS=$'\t' read -r path debt <<< "$row"
    total_copies=$(( total_copies + debt ))
    allowed="${BASELINED[$path]:-}"
    if [ -n "$allowed" ]; then
        HIT["$path"]=1
        if [ "$debt" -le "$allowed" ]; then
            tolerated+=("$path ($debt/$allowed)")
            continue
        fi
        violations+=("$path — $debt copy/copies found, baseline allows $allowed")
    else
        violations+=("$path — $debt copy/copies found, not in the baseline (new file may carry ZERO)")
    fi
done

# A baseline row whose file is now clean (or gone) must be deleted, or the
# ratchet rusts shut at a stale number.
stale=()
for path in "${!BASELINED[@]}"; do
    [ -z "${HIT[$path]+x}" ] && stale+=("$path (baseline says ${BASELINED[$path]}, actual 0)")
done

# The ceiling check: the baseline FILE's own recorded SUM may never exceed
# the ceiling this gate was introduced with. This does NOT prevent one row
# rising while another falls within the same sum — that is a judgment call
# for code review to catch by reading the diff, same as any other data-file
# edit in this repo, not something a single integer comparison can settle.
# What it DOES prevent is the sum itself creeping upward silently: the only
# way to raise the CEILING (and so legitimately allow the total to grow) is
# a change to the constant in this script, which is a visible source diff,
# not a data-file edit.
if [ "$baseline_sum" -gt "$CEILING" ]; then
    echo ""
    echo "[$GATE] baseline sum ($baseline_sum) exceeds the ratchet ceiling ($CEILING)"
    echo "        in $BASELINE — the baseline was edited upward. Lower it back,"
    echo "        or lower RATCHET_CEILING in this script if debt has genuinely"
    echo "        and legitimately grown (a change that belongs in code review,"
    echo "        not a quiet data-file edit)."
    violations+=("$BASELINE — baseline sum $baseline_sum exceeds ceiling $CEILING")
fi

# ── Marker bound ─────────────────────────────────────────────────────────
# The `zcl-identity-parser-allow:` marker (see scan_counts()) fully exempts
# a Class-A or Class-B match from debt. Left unbounded, ANY future copy under
# $SCAN_ROOT could dodge the ratchet forever just by pasting that comment
# near it — a hole in a gate whose entire job is catching the next copy.
# Bound it two ways, same shrink-only shape as the baseline sum:
#   1. the total marker count may not exceed MARKER_CEIL.
#   2. a marker may only appear in a file named in MARKER_ALLOWED. A marker
#      in any other file is a violation regardless of the count, because it
#      exempts a copy this gate was never told about.
declare -A marker_file_count=()
marker_total=0
for f in "${scan_files[@]}"; do
    n=$(grep -c 'zcl-identity-parser-allow' "$f" 2>/dev/null || true)
    n="${n:-0}"
    [ "$n" -gt 0 ] || continue
    marker_file_count["$f"]=$n
    marker_total=$(( marker_total + n ))
done

is_marker_allowed_file() {
    local f="$1" a
    for a in "${MARKER_ALLOWED[@]}"; do
        [ "$f" = "$a" ] && return 0
    done
    return 1
}

for f in "${!marker_file_count[@]}"; do
    if ! is_marker_allowed_file "$f"; then
        violations+=("$f — carries a zcl-identity-parser-allow marker but is not on MARKER_ALLOWED_FILES (only ${MARKER_ALLOWED[*]} may exempt a copy this way)")
    fi
done

if [ "$marker_total" -gt "$MARKER_CEIL" ]; then
    echo ""
    echo "[$GATE] zcl-identity-parser-allow marker count ($marker_total) exceeds"
    echo "        MARKER_CEILING ($MARKER_CEIL) — a new marker exempts a copy from"
    echo "        the ratchet invisibly; raising MARKER_CEILING is a visible"
    echo "        source diff in this script, not a comment nobody reviews."
    violations+=("marker count $marker_total exceeds MARKER_CEILING $MARKER_CEIL")
fi

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# check_identity_parser_single baseline — files still carrying an inline"
        echo "# copy of the source-identity JSON parser (a local is_sha256/is_hex64/"
        echo "# json_first_string_field/is_source_id_sha256 definition, or an inline"
        echo "# grep/sed extraction of the \"source_id_sha256\" JSON key) instead of"
        echo "# sourcing tools/scripts/source_identity_lib.sh."
        echo "#"
        echo "# Format: <path> <count>.  COUNTS MAY ONLY SHRINK."
        echo "#"
        echo "# Regenerate: ZCL_LINT_MODE=UPDATE tools/lint/$GATE.sh"
        for row in "${COUNT_ROWS[@]}"; do
            IFS=$'\t' read -r path debt <<< "$row"
            echo "$path $debt"
        done | sort
    } > "$BASELINE"
    echo "[$GATE] baseline UPDATED: $BASELINE"
    exit 0
fi

fail=0
if [ "${#violations[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#violations[@]} violation(s) — a new or grown inline copy of the"
    echo "        source-identity JSON parser:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  Source tools/scripts/source_identity_lib.sh instead:"
    echo "    zcl_is_sha256 / zcl_json_first_string / zcl_json_first_sha256 /"
    echo "    zcl_binary_source_id"
    echo "  Raising a number in $BASELINE is NOT a fix; counts may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — the file no longer carries"
    echo "        any inline copy. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} *.sh files scanned, ${#COUNT_ROWS[@]} carrying a copy, $total_copies total, $baseline_count baselined file(s) summing to $baseline_sum/$CEILING, ${#tolerated[@]} tolerated, $marker_total/$MARKER_CEIL allow-marker(s))"
