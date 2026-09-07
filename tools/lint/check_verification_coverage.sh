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
exec "$(dirname "$0")/../../build/bin/z23-lint" check-verification-coverage "$@"
