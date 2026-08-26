#!/usr/bin/env bash
# check_source_identity_authority.sh — the JSON key "source_id_sha256"
# answers two different questions in this tree, and a script that spells
# both the same way, or reads one positionally instead of through the
# schema-anchored reader that exists for it, is how the two get confused.
# Mode: shrink-only ratchet (ZCL_LINT_MODE: FAIL default | WARN | UPDATE —
# same shape as check_identity_parser_single.sh).
#
# WHY THIS EXISTS: tools/scripts/source_identity_lib.sh's header states the
# distinction in full — Q1 "what source tree was this BINARY built from?"
# (constant, baked in at compile time, read via `zcl_build_source_id_sha256()`
# / `<bin> agentbuild`'s top-level `source_id_sha256`) vs Q2 "what source
# tree is in THIS DIRECTORY right now?" (varies by directory, computed by
# tools/dev/source-identity.sh). A freshness check ("is the running daemon
# the build I expect?") must read Q1: a directory-derived answer can pass a
# stale daemon whose own checkout happens to look current, or fail a fresh
# one checked out elsewhere. `tools/agent_fast_ci.sh`'s `green_input_cache`
# once published the Q2 (working-tree) value under the bare Q1-shaped key
# `source_id_sha256` — fixed by renaming it to
# `working_tree_source_id_sha256`. This gate is the anti-rot check that
# stops that naming collision, and the positional (not schema-anchored)
# reads it enables, from growing back.
#
# Two things counted, per scanned *.sh file (plus the top-level Makefile,
# whose deploy recipe carried two of the four sites this ratchet was
# introduced to close):
#
#   R. A POSITIONAL read of an `agentbuild` response's `source_id_sha256`,
#      instead of the schema-anchored `zcl_agentbuild_v2_top_source_id`
#      (which binds schema, api_version, status, field position, AND the
#      exact top-level value — see source_identity_lib.sh). Two shapes:
#        R1. a call to `zcl_json_first_string`, `zcl_json_first_sha256`, or
#            `json_first_string_field` (the tools/dev/ dev-loop scripts'
#            still-unmigrated equivalent — see
#            tools/lint/identity_parser_baseline.txt) with `source_id_sha256`
#            as the key argument.
#        R2. an inline grep/sed extraction of the `"source_id_sha256"` JSON
#            key (the same needle check_identity_parser_single.sh's Class B
#            uses).
#      Neither shape is debt by itself — `zcl_json_first_string` reading a
#      DIFFERENT schema (e.g. the `agent` RPC's zcl.public_status.v2/v3, or
#      a promotion-receipt record) has no agentbuild-shaped strict reader to
#      use instead, and is not counted. What makes a match this gate's
#      business is R1/R2 landing within WINDOW lines of the literal
#      substring `agentbuild` — every real site this ratchet was written
#      against names its own source variable `agentbuild`,
#      `candidate_agentbuild`, `rollback_agentbuild`, or pipes an inline
#      `<bin> agentbuild` invocation directly into the extraction, so this
#      is a precise, low-noise signal for "this is reading an agentbuild
#      response" without having to trace shell variable flow in full.
#
#   P. A PRODUCER emitting the bare key `source_id_sha256` (JSON
#      `"source_id_sha256":` form, plain construction — a printf/echo with
#      no grep/sed on the same line, the mirror image of R2's needle) in a
#      file that also invokes `tools/dev/source-identity.sh capture-record`
#      — the one subcommand whose entire job is "what is in THIS DIRECTORY
#      right now" (Q2). This is exactly agent_fast_ci.sh's fixed defect:
#      capture a Q2 reading, then publish it under the Q1-shaped bare key.
#      Scoped to `capture-record` specifically (not `verify`/`verify-record`,
#      which compare an already-bound identity rather than mint a fresh Q2
#      answer to report under a key) to keep this precise.
#
# Shrink-only ratchet: tools/lint/source_identity_authority_baseline.txt
# names the files with a deliberately-reviewed exception and how many
# occurrences each carries. A file with no baseline row may carry ZERO of
# either class. Fix a row by converting the site to
# zcl_agentbuild_v2_top_source_id (class R) or by renaming the producer's
# key to name the tree, e.g. `working_tree_source_id_sha256` (class P), then
# lower or delete the row — never by raising the number.
#
# --selftest plants a fresh violating copy of both classes in a sandboxed
# tools/ tree, proves the gate FAILS on each, then removes it and proves
# PASS — a ratchet that cannot be shown to fail is worse than no gate. It
# also proves the gate does not mask a real grep failure as "no match"
# under `set -o pipefail` (see tools/scripts/sh_str.sh's own header for why
# that inversion is a standing hazard in this tree).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"
# shellcheck source=tools/lint/gate_lib.sh
source tools/lint/gate_lib.sh

GATE=check_source_identity_authority
# See tools/lint/source_identity_authority_baseline.txt for what these 5
# rows are and why each is a reviewed exception, not new debt.
RATCHET_CEILING=5
WINDOW=6

# ── --selftest ───────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/tools/scripts" "$tmp/tools/lint"
    : > "$tmp/empty_baseline.txt"
    self="$PWD/tools/lint/$GATE.sh"

    plant_clean() {
        cat > "$tmp/tools/scripts/selftest_clean.sh" <<'FIXTURE'
#!/usr/bin/env bash
# a clean consumer: reads a DIFFERENT schema (agent RPC public_status), and
# the schema-anchored reader for a real agentbuild response.
. tools/scripts/source_identity_lib.sh
status_id="$(zcl_json_first_string "$agent_status" "source_id_sha256")"
agentbuild="$("$bin" agentbuild 2>&1)"
observed="$(zcl_agentbuild_v2_top_source_id "$agentbuild")"
FIXTURE
    }

    plant_class_r() {
        cat > "$tmp/tools/scripts/selftest_class_r.sh" <<'FIXTURE'
#!/usr/bin/env bash
. tools/scripts/source_identity_lib.sh
candidate_agentbuild="$(timeout 30 "$candidate" agentbuild 2>&1)"
candidate_source_id="$(zcl_json_first_sha256 "$candidate_agentbuild" source_id_sha256)"
FIXTURE
    }

    plant_class_p() {
        cat > "$tmp/tools/scripts/selftest_class_p.sh" <<'FIXTURE'
#!/usr/bin/env bash
record="$("$tool" capture-record 2>/dev/null)"
read -r source_id clean mutation <<< "$record"
printf '"source_id_sha256":"%s"' "$source_id"
FIXTURE
    }

    rm -f "$tmp/tools/scripts/selftest_class_r.sh" "$tmp/tools/scripts/selftest_class_p.sh"

    run_sandbox() {
        ZCL_SOURCE_AUTHORITY_SCAN_ROOT="$tmp/tools" \
        ZCL_SOURCE_AUTHORITY_MAKEFILE="$tmp/no-such-makefile" \
        ZCL_SOURCE_AUTHORITY_BASELINE="$tmp/empty_baseline.txt" \
        ZCL_SOURCE_AUTHORITY_CEILING=0 \
        ZCL_SOURCE_AUTHORITY_FILE_FLOOR=1 \
        ZCL_LINT_MODE=FAIL \
        bash "$self" >"$tmp/out.log" 2>&1
    }

    plant_clean
    rc=0; run_sandbox || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "$GATE: SELFTEST FAILED — a clean consumer (different schema, plus a properly schema-anchored agentbuild read) was reported as a violation" >&2
        sed 's/^/  /' "$tmp/out.log" >&2
        exit 2
    fi

    plant_class_r
    rc=0; run_sandbox || rc=$?
    plant_class_r_output_saved="$(cat "$tmp/out.log")"
    rm -f "$tmp/tools/scripts/selftest_class_r.sh"
    if [ "$rc" -eq 0 ]; then
        echo "$GATE: SELFTEST FAILED — a positional agentbuild source_id_sha256 read (class R) did not fail the gate" >&2
        exit 2
    fi
    case "$plant_class_r_output_saved" in
        *class_r*) ;;
        *)
            echo "$GATE: SELFTEST FAILED — class-R violation did not name the offending file" >&2
            exit 2
            ;;
    esac
    rc=0; run_sandbox || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "$GATE: SELFTEST FAILED — reverting the class-R copy did not clear the violation" >&2
        exit 2
    fi

    plant_class_p
    rc=0; run_sandbox || rc=$?
    plant_class_p_output_saved="$(cat "$tmp/out.log")"
    rm -f "$tmp/tools/scripts/selftest_class_p.sh"
    if [ "$rc" -eq 0 ]; then
        echo "$GATE: SELFTEST FAILED — a working-tree identity published under the bare source_id_sha256 key (class P) did not fail the gate" >&2
        exit 2
    fi
    case "$plant_class_p_output_saved" in
        *class_p*) ;;
        *)
            echo "$GATE: SELFTEST FAILED — class-P violation did not name the offending file" >&2
            exit 2
            ;;
    esac
    rc=0; run_sandbox || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "$GATE: SELFTEST FAILED — reverting the class-P copy did not clear the violation" >&2
        exit 2
    fi

    # A gate whose scan pipeline masks a real grep/awk failure as "no match"
    # under set -o pipefail is worse than no gate (see tools/scripts/sh_str.sh's
    # header). Prove the scan-set floor actually fires when the scan root is
    # hollow, rather than quietly reporting a clean pass off zero files.
    rc=0
    ZCL_SOURCE_AUTHORITY_SCAN_ROOT="$tmp/no-such-dir" \
    ZCL_SOURCE_AUTHORITY_MAKEFILE="$tmp/no-such-makefile" \
    ZCL_SOURCE_AUTHORITY_BASELINE="$tmp/empty_baseline.txt" \
    ZCL_SOURCE_AUTHORITY_CEILING=0 \
    ZCL_SOURCE_AUTHORITY_FILE_FLOOR=1 \
    ZCL_LINT_MODE=FAIL \
        bash "$self" >"$tmp/hollow.log" 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
        echo "$GATE: SELFTEST FAILED — an empty/moved scan root did not hit the gate_require_scanned floor (got rc=$rc, wanted 2)" >&2
        sed 's/^/  /' "$tmp/hollow.log" >&2
        exit 2
    fi

    echo "[$GATE] SELFTEST PASS (clean multi-schema/strict-reader consumer passes; a positional agentbuild read (class R) and a bare-key working-tree producer (class P) each fail; reverting either clears the violation; a hollow scan root hits the floor instead of reporting clean)"
    exit 0
fi

# ── Scan set ─────────────────────────────────────────────────────────────
MODE="${ZCL_LINT_MODE:-FAIL}"
BASELINE="${ZCL_SOURCE_AUTHORITY_BASELINE:-tools/lint/source_identity_authority_baseline.txt}"
SCAN_ROOT="${ZCL_SOURCE_AUTHORITY_SCAN_ROOT:-tools}"
MAKEFILE="${ZCL_SOURCE_AUTHORITY_MAKEFILE:-Makefile}"
CEILING="${ZCL_SOURCE_AUTHORITY_CEILING:-$RATCHET_CEILING}"

# Same self-exclusion rationale as check_identity_parser_single.sh: the
# canonical library and this gate's own selftest fixtures necessarily quote
# the exact patterns being forbidden elsewhere.
EXCLUDE_RE='(^|/)source_identity_lib\.sh$|(^|/)check_source_identity_authority\.sh$|(^|/)check_identity_parser_single\.sh$'

mapfile -t scan_files < <(find "$SCAN_ROOT" -type f -name '*.sh' 2>/dev/null | grep -Ev "$EXCLUDE_RE" || true)
if [ -f "$MAKEFILE" ]; then
    scan_files+=("$MAKEFILE")
fi
gate_require_scanned "${#scan_files[@]}" "${ZCL_SOURCE_AUTHORITY_FILE_FLOOR:-5}" "$GATE" \
    "no *.sh files found under $SCAN_ROOT (plus $MAKEFILE) — the scan root moved"

# ── Per-file counts ──────────────────────────────────────────────────────
# Emits: path<TAB>count
scan_counts() {
    awk -v window="$WINDOW" '
        BEGIN {
            q = sprintf("%c", 34)
            bs = sprintf("%c", 92)
            # R2 needle: the literal SOURCE TEXT of an inline grep/sed regex
            # extracting the key (so it necessarily contains the regex
            # spacing token "[[:space:]]*:" right after the quoted key,
            # exactly as check_identity_parser_single.sh'"'"'s Class B needle
            # does) — this is NOT itself a regex, index() is a plain
            # substring search.
            regex_needle_plain = q "source_id_sha256" q "[[:space:]]*:"
            regex_needle_esc   = bs q "source_id_sha256" bs q "[[:space:]]*:"
            # P needle: a plain JSON producer'"'"'s key token, no regex
            # spacing junk — printf '"'"'"source_id_sha256":"%s"'"'"' contains
            # exactly this substring and nothing more elaborate.
            plain_key_needle = q "source_id_sha256" q ":"
        }
        FNR == 1 {
            if (NR > 1) emit()
            path = FILENAME; count = 0; p_count = 0; has_capture = 0
            for (i = 0; i < window; i++) recent[i] = ""
            ri = 0
        }
        {
            line = $0
            trimmed = line
            gsub(/^[ \t]+/, "", trimmed)
            # A pure comment line does not count toward "agentbuild nearby"
            # — otherwise an explanatory comment naming agentbuild (exactly
            # what this gate'"'"'s own rationale comments do, right next to a
            # call this gate must NOT flag) would self-trigger.
            if (trimmed ~ /^#/) {
                recent[ri % window] = ""
            } else {
                recent[ri % window] = line
            }
            ri++

            has_regex_needle = (index(line, regex_needle_plain) > 0 || index(line, regex_needle_esc) > 0)
            has_tool = (index(line, "grep") > 0 || index(line, "sed") > 0)
            # Shell function CALLS have no parens ("zcl_json_first_sha256
            # \"$x\" key", not "zcl_json_first_sha256(x, key)") — match the
            # name followed by whitespace, not preceded by an identifier
            # character (so this does not also match a longer name that
            # happens to end the same way).
            is_reader_call = (line ~ /(^|[^A-Za-z0-9_])zcl_json_first_string[ \t]/ ||
                               line ~ /(^|[^A-Za-z0-9_])zcl_json_first_sha256[ \t]/ ||
                               line ~ /(^|[^A-Za-z0-9_])json_first_string_field[ \t]/) &&
                              (index(line, "source_id_sha256") > 0)

            # ---- Class R: positional read of an agentbuild body ----
            if ((has_regex_needle && has_tool) || is_reader_call) {
                near = 0
                for (i = 0; i < window; i++) {
                    if (recent[i] != "" && index(recent[i], "agentbuild") > 0) near = 1
                }
                if (near) count++
            }

            # ---- Class P: bare-key producer of a captured working tree ----
            # Whole-FILE scoped, not windowed: a file typically captures a
            # Q2 reading in one helper (e.g. bind_quality_tree()) and
            # publishes it many lines later in another (e.g. write_status())
            # — the two are never within a few lines of each other, unlike
            # class R'"'"'s single-call-site read.
            if (index(line, "capture-record") > 0) has_capture = 1
            has_plain_key = (index(line, plain_key_needle) > 0)
            if (has_plain_key && !has_tool) p_count++
        }
        END { emit() }
        function emit() {
            total = count + (has_capture ? p_count : 0)
            if (path != "" && total > 0) printf "%s\t%d\n", path, total
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
        violations+=("$path — $debt occurrence(s) found, baseline allows $allowed")
    else
        violations+=("$path — $debt occurrence(s) found, not in the baseline (new file may carry ZERO)")
    fi
done

stale=()
for path in "${!BASELINED[@]}"; do
    [ -z "${HIT[$path]+x}" ] && stale+=("$path (baseline says ${BASELINED[$path]}, actual 0)")
done

if [ "$baseline_sum" -gt "$CEILING" ]; then
    echo ""
    echo "[$GATE] baseline sum ($baseline_sum) exceeds the ratchet ceiling ($CEILING)"
    echo "        in $BASELINE — the baseline was edited upward. Lower it back,"
    echo "        or lower RATCHET_CEILING in this script if debt has genuinely"
    echo "        and legitimately grown (a change that belongs in code review,"
    echo "        not a quiet data-file edit)."
    violations+=("$BASELINE — baseline sum $baseline_sum exceeds ceiling $CEILING")
fi

if [ "$MODE" = "UPDATE" ]; then
    {
        echo "# check_source_identity_authority baseline — reviewed exceptions to the"
        echo "# Q1 (baked build)/Q2 (working tree) source_id_sha256 naming and reader"
        echo "# ratchet. See tools/lint/check_source_identity_authority.sh's header for"
        echo "# class R (positional agentbuild read) and class P (bare-key working-tree"
        echo "# producer)."
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
    echo "[$GATE] ${#violations[@]} violation(s) — a new or grown positional"
    echo "        agentbuild source_id_sha256 read, or a working-tree identity"
    echo "        published under the bare source_id_sha256 key:"
    printf '  %s\n' "${violations[@]}" | sort
    echo ""
    echo "  Class R: use zcl_agentbuild_v2_top_source_id (tools/scripts/source_identity_lib.sh)."
    echo "  Class P: rename the producer's key to name the tree, e.g."
    echo "           working_tree_source_id_sha256."
    echo "  Raising a number in $BASELINE is NOT a fix; counts may only shrink."
    fail=1
fi

if [ "${#stale[@]}" -gt 0 ]; then
    echo ""
    echo "[$GATE] ${#stale[@]} STALE baseline row(s) — the file no longer carries"
    echo "        any counted occurrence. Delete them from $BASELINE:"
    printf '  %s\n' "${stale[@]}" | sort
    fail=1
fi

if [ "$fail" != "0" ] && [ "$MODE" = "FAIL" ]; then
    exit 1
fi

echo "[$GATE] PASS (${#scan_files[@]} files scanned, ${#COUNT_ROWS[@]} carrying an occurrence, $total_copies total, $baseline_count baselined file(s) summing to $baseline_sum/$CEILING, ${#tolerated[@]} tolerated)"
