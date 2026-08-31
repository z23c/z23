#!/usr/bin/env bash
# Copyright 2026 Rhett Creighton - Apache License 2.0
#
# check_verification_coverage.sh — hosted CI's green must not overstate what it
# checked.
#
# THE DEFECT THIS EXISTS FOR. Hosted checks once omitted the test suite while a
# reader reasonably read a row of green checks as "this commit is verified".
# The suite is hosted now, so the same rail must also hold what that green means:
# one cold, non-vacuous complete verdict, not a cached zero-run headline that
# happens to contain the old ALL TESTS PASSED substring.
#
# So the declared coverage lives in .github/verification-coverage.txt and this
# gate holds it to the workflow, both directions:
#
#   1. SHAPE. Every line parses into exactly five fields; `hosted` is exactly
#      yes or no; hosted=yes carries a real job_key and `-` for attested_by;
#      hosted=no carries `-` for job_key and a NON-EMPTY attested_by. An item
#      that is not hosted and names nobody who vouches for it is an unverified
#      claim wearing a declaration's clothes.
#   2. THE REQUIRED ITEMS ARE HARD-CODED HERE, in a different file from the
#      manifest. The gap cannot be closed by deleting the `tests` row. This is
#      the discipline check_promotion_receipt_chain.sh prong 6 documents, and it
#      is there because a mutation once reworded a message while a same-file
#      self-test still passed.
#   3. CLAIMED -> REAL. Every hosted=yes job_key must exist as a key under
#      `jobs:` in build.yml. A renamed or deleted job stops satisfying the item
#      it used to satisfy, instead of silently continuing to.
#   4. REAL -> CLAIMED. Every job key in build.yml must be claimed by some
#      hosted=yes row. A job added without declaring what it verifies fails,
#      so the manifest cannot quietly fall behind the workflow.
#   5. ANTI-ORPHAN. build.yml must point at this manifest by path, grepped and
#      never inferred, so a reader of the workflow is sent to the coverage
#      statement instead of counting jobs and guessing.
#   6. TEST NON-VACUITY. The hosted test job must force --no-cache and delegate
#      its full log to the semantic verdict checker. That checker mutation-tests
#      the cached-zero-run case here, outside the workflow file it holds.
#   7. THE STANDING FACT. Whatever the manifest says, this gate names the
#      not-hosted items in its own output, so a maintainer reading a gate log
#      sees the gap spelled out rather than inferring it.
#      SCOPE OF THAT CLAIM, stated precisely because overstating it would be the
#      very defect this gate exists to catch: tools/lint/run_lint.sh captures
#      each gate's stdout AND stderr into .cache/lint-gates/<gate>.log and prints
#      it only on failure, and a passing gate with unchanged inputs is
#      cache-SKIPPED and does not run at all. So this text is NOT on a
#      maintainer's terminal on every `make lint`. The surface that actually
#      reaches the audience who needs it — someone reading the commit on GitHub —
#      is .github/workflows/build.yml itself, which prong 5 forces to point here
#      and which states its exact hosted test contract. This prong is the
#      maintainer-facing half; the workflow comment is the reader-facing half.
#
# Field splitting uses `|` because a display name contains spaces, so the
# `<key> <value>` helpers in gate_lib.sh cannot carry these rows. Validation uses
# `case` globs, never `printf | grep -Eq '^…$'`: grep is LINE-based, so a value
# that somehow carried a newline would pass an anchored regex on the strength of
# one matching line. `case` matches the whole string or nothing.

set -uo pipefail
export LC_ALL=C

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 1
# shellcheck source=tools/lint/gate_lib.sh
source "$ROOT/tools/lint/gate_lib.sh"

MANIFEST=.github/verification-coverage.txt
WORKFLOW=.github/workflows/build.yml
HOSTED_SUITE_VERIFIER=tools/lint/check_hosted_suite_verdict.sh

# The owner's five named verification items. HARD-CODED HERE ON PURPOSE — see
# prong 2 in the header. Adding an item to this list is how a new verification
# axis becomes mandatory; removing one is how it stops being. Neither is
# something the manifest can do to itself.
REQUIRED_ITEMS=(gcc clang lint tests fuzz-replay)

fail=0

# ── the two inputs must exist ────────────────────────────────────────────
if [ ! -r "$MANIFEST" ]; then
    echo "FAIL: $MANIFEST is missing."
    echo "      Hosted CI publishes five green checks per commit and the test suite is"
    echo "      not among them. Without a declared coverage manifest, a reader on GitHub"
    echo "      cannot tell which of gcc/clang/lint/tests/fuzz-replay a green commit"
    echo "      actually passed, and the workflow's prose is free to rot unchecked."
    exit 1
fi
if [ ! -r "$WORKFLOW" ]; then
    echo "FAIL: $WORKFLOW is missing — there is nothing to hold the manifest to."
    exit 1
fi

# ── job keys really present in the workflow ──────────────────────────────
# `jobs:` at column 0, then each job key at exactly two spaces of indent. Steps,
# `with:`, `env:` and friends are deeper, and `on:`/`permissions:`/`concurrency:`
# are at column 0, so this indent is the job level and nothing else.
workflow_jobs="$(awk '
    /^jobs:[[:space:]]*$/ { injobs = 1; next }
    injobs && /^[^[:space:]#]/ { injobs = 0 }
    injobs && /^  [a-z][A-Za-z0-9_-]*:[[:space:]]*$/ {
        k = $1; sub(/:$/, "", k); print k
    }
' "$WORKFLOW")"
workflow_job_count="$(printf '%s' "$workflow_jobs" | grep -c . || true)"

# ANTI-HOLLOW FLOOR. If the extractor returns nothing, this gate would "pass"
# prong 4 vacuously and report clean off a broken scan. The workflow is
# documented to carry five jobs; anything under two means the awk above stopped
# matching (an indent change, a `jobs:` rename) and the verdict is worthless.
gate_require_scanned "$workflow_job_count" 2 check-verification-coverage \
    "no job keys parsed out of $WORKFLOW — the awk job-level indent match broke"

# ── parse the manifest ───────────────────────────────────────────────────
declare -A ITEM_HOSTED=() ITEM_JOB=() ITEM_ATTEST=()
declare -A CLAIMED_JOB=()
rows=0
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    # Comments and blanks. Note: only a FULL-LINE comment is stripped. A `#`
    # inside attested_by is legitimate prose and must survive.
    case "$line" in
        ''|'#'*) continue ;;
    esac

    # Exactly five fields. Count separators rather than trusting a read -d.
    seps="${line//[!|]/}"
    if [ "${#seps}" -ne 4 ]; then
        echo "FAIL: $MANIFEST line $lineno has ${#seps} '|' separator(s), needs exactly 4"
        echo "      expected: item|hosted|job_key|display_name|attested_by"
        echo "      got:      $line"
        fail=1
        continue
    fi

    item="${line%%|*}"; rest="${line#*|}"
    hosted="${rest%%|*}"; rest="${rest#*|}"
    job="${rest%%|*}"; rest="${rest#*|}"
    display="${rest%%|*}"
    attest="${rest#*|}"

    # `case` not grep — whole-string matching. See the header.
    case "$item" in
        ''|*[!a-z0-9-]*)
            echo "FAIL: $MANIFEST line $lineno item '$item' must be non-empty lowercase [a-z0-9-]"
            fail=1; continue ;;
    esac
    if [ -n "${ITEM_HOSTED[$item]+x}" ]; then
        echo "FAIL: $MANIFEST line $lineno declares item '$item' twice — one row per item"
        fail=1; continue
    fi
    case "$hosted" in
        yes|no) ;;
        *)
            echo "FAIL: $MANIFEST line $lineno hosted='$hosted' — must be exactly 'yes' or 'no'"
            fail=1; continue ;;
    esac
    case "$display" in
        '')
            echo "FAIL: $MANIFEST line $lineno display_name is empty"
            fail=1; continue ;;
    esac

    if [ "$hosted" = yes ]; then
        case "$job" in
            ''|-|*[!A-Za-z0-9_-]*)
                echo "FAIL: $MANIFEST line $lineno item '$item' is hosted=yes so job_key must be a real"
                echo "      workflow job key, got '$job'"
                fail=1; continue ;;
        esac
        if [ "$attest" != "-" ]; then
            echo "FAIL: $MANIFEST line $lineno item '$item' is hosted=yes so attested_by must be '-'"
            echo "      (the hosted job IS the attestation), got '$attest'"
            fail=1; continue
        fi
        CLAIMED_JOB["$job"]=1
    else
        if [ "$job" != "-" ]; then
            echo "FAIL: $MANIFEST line $lineno item '$item' is hosted=no so job_key must be '-', got '$job'"
            fail=1; continue
        fi
        # THE PRONG THAT MATTERS. A not-hosted item with no attestor is an
        # unverified claim. `-` is not an answer here, and neither is blank.
        # Whitespace-only is blank. Strip both ends and test the remainder, so a
        # row of spaces cannot pass as an attestor. (No extglob: this gate must
        # run under a plain `bash` with no shopt set for it.)
        attest_trim="${attest#"${attest%%[![:space:]]*}"}"
        attest_trim="${attest_trim%"${attest_trim##*[![:space:]]}"}"
        case "$attest_trim" in
            ''|-)
                echo "FAIL: $MANIFEST line $lineno item '$item' is hosted=no and names no attestor."
                echo "      An item that hosted CI does not check must say where its verdict comes"
                echo "      from. Leaving it blank turns an admitted gap into a silent one."
                fail=1; continue ;;
        esac
    fi

    ITEM_HOSTED["$item"]="$hosted"
    ITEM_JOB["$item"]="$job"
    ITEM_ATTEST["$item"]="$attest"
    rows=$((rows + 1))
done < "$MANIFEST"

# Anti-hollow floor on the manifest scan itself: the required list alone is five
# items, so fewer than that many parsed rows means the parse broke or the file
# was gutted, and prongs 2-4 below would pass vacuously on an empty set.
gate_require_scanned "$rows" "${#REQUIRED_ITEMS[@]}" check-verification-coverage \
    "only $rows row(s) parsed from $MANIFEST — the parse broke or the file was emptied"

# ── prong 2: every required item is declared ─────────────────────────────
for want in "${REQUIRED_ITEMS[@]}"; do
    if [ -z "${ITEM_HOSTED[$want]+x}" ]; then
        echo "FAIL: $MANIFEST does not declare required verification item '$want'."
        echo "      The required list lives in this gate, not in the manifest, so a coverage"
        echo "      gap cannot be closed by deleting its row. Declare '$want' — as hosted=no"
        echo "      with an attestor if nothing hosted checks it."
        fail=1
    fi
done

# ── prong 3: claimed -> real ──────────────────────────────────────────────
for item in "${!ITEM_HOSTED[@]}"; do
    [ "${ITEM_HOSTED[$item]}" = yes ] || continue
    job="${ITEM_JOB[$item]}"
    found=0
    while IFS= read -r k; do
        [ -n "$k" ] || continue
        [ "$k" = "$job" ] && { found=1; break; }
    done <<< "$workflow_jobs"
    if [ "$found" != 1 ]; then
        echo "FAIL: $MANIFEST claims item '$item' is verified by workflow job '$job',"
        echo "      but $WORKFLOW has no such job. It was renamed or removed, and the"
        echo "      item it used to cover is now unverified while still claiming to be"
        echo "      hosted. Jobs present: $(printf '%s ' $workflow_jobs)"
        fail=1
    fi
done

# ── prong 4: real -> claimed ──────────────────────────────────────────────
while IFS= read -r k; do
    [ -n "$k" ] || continue
    if [ -z "${CLAIMED_JOB[$k]+x}" ]; then
        echo "FAIL: $WORKFLOW defines job '$k' that no item in $MANIFEST claims."
        echo "      Every hosted job must declare which verification item it provides, or"
        echo "      the manifest stops being a statement about what green means."
        fail=1
    fi
done <<< "$workflow_jobs"

# ── prong 5: anti-orphan — the workflow points at the manifest ───────────
if ! gate_grep -q "verification-coverage\.txt" "$WORKFLOW"; then
    echo "FAIL: $WORKFLOW does not mention $MANIFEST."
    echo "      A reader of the workflow must be sent to the coverage statement rather"
    echo "      than counting jobs and guessing what green covers. Reference it in a"
    echo "      comment next to the job list."
    fail=1
fi

# ── prong 6: hosted tests are cold and semantically non-vacuous ───────────
if [ ! -x "$HOSTED_SUITE_VERIFIER" ]; then
    echo "FAIL: hosted suite verifier is missing or not executable: $HOSTED_SUITE_VERIFIER"
    fail=1
else
    if ! "$HOSTED_SUITE_VERIFIER" --self-test; then
        echo "FAIL: hosted suite verifier did not reject its adversarial fixtures"
        fail=1
    fi
fi
if ! gate_grep -q 'TEST_PARALLEL_ARGS=--no-cache' "$WORKFLOW"; then
    echo "FAIL: hosted tests do not force TEST_PARALLEL_ARGS=--no-cache"
    fail=1
fi
if ! gate_grep -q 'check_hosted_suite_verdict[.]sh /tmp/suite[.]log' "$WORKFLOW"; then
    echo "FAIL: hosted tests do not semantically verify the full captured suite log"
    fail=1
fi

# ── prong 7: print the standing fact, every run ──────────────────────────
not_hosted=()
for item in "${REQUIRED_ITEMS[@]}"; do
    [ -n "${ITEM_HOSTED[$item]+x}" ] || continue
    [ "${ITEM_HOSTED[$item]}" = no ] && not_hosted+=("$item")
done

if [ "$fail" != 0 ]; then
    exit 1
fi

# Job KEYS, not check-runs: `compile-check` is one key that a 2-way matrix
# expands into two check names (gcc, clang), which is why two items can claim
# the same key and why this count is legitimately smaller than the five checks
# a reader sees on GitHub.
echo "  ok: $rows declared item(s); $workflow_job_count workflow job key(s), all claimed"
if [ "${#not_hosted[@]}" -eq 0 ]; then
    echo "  ok: every required verification item is covered by a hosted job"
else
    echo "  NOT HOSTED — hosted CI does NOT check: ${not_hosted[*]}"
    for item in "${not_hosted[@]}"; do
        echo "      $item: ${ITEM_ATTEST[$item]}"
    done
    echo "      A green commit on GitHub therefore does NOT mean the above passed on"
    echo "      that source. Do not read the hosted checks as covering them."
fi
echo "check_verification_coverage: clean — declared coverage matches $WORKFLOW"
