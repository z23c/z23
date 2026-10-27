<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Incomplete R1CS reference diagnostics

Date: 2026-10-26.
Source parent: f9b721f5aaa6bf098402ca2642021f95aa17f1b2.

The optional reference reader reports a truncated row as a test failure. Before
this repair, a valid header followed by no rows still produced 21 section hashes
under the reference-golden heading and a reference transcript hash. The allocated
reference-hash buffer remained non-null after the reader closed the truncated
file, so the diagnostic printer consumed an incomplete buffer.

The row comparison now reports whether all 76,893 reference-prefix rows were
decoded. The caller frees and clears an incomplete reference-hash buffer before
the golden printer. The original truncation message, failure count and failing
test outcome remain. The complete-prefix output path is retained by source
inspection; the normal group without an external reference does not exercise it.

<!-- claim: symbol-present r1cs_hash_and_compare_rows tests/harness/src/test_groth16_r1cs_oracle.c -->
<!-- claim: symbol-present r1cs_print_reference_hashes tests/harness/src/test_groth16_r1cs_oracle.c -->

## Portable reproduction

Run from the repository root. The fixture has the valid eight-byte magic,
little-endian row/input/auxiliary counts of 76,893/7/98,638, and no row payload.
It contains 20 bytes.

~~~sh
mkdir -p build/r1cs-reference-repro
printf 'ZR1CS\000\000\001\135\054\001\000\007\000\000\000\116\201\001\000' \
    > build/r1cs-reference-repro/header-only.bin
make t-fast ONLY=groth16_r1cs_oracle || exit 1
if ZCL_R1CS_REF="$PWD/build/r1cs-reference-repro/header-only.bin" \
    make t-fast ONLY=groth16_r1cs_oracle \
    > build/r1cs-reference-repro/truncated.log 2>&1; then
    printf 'expected the truncated reference to fail\n' >&2
    exit 1
fi
grep -F 'FAIL: reference dump truncated at row 0' \
    build/r1cs-reference-repro/truncated.log || exit 1
if grep -E 'REFERENCE section hashes|REFERENCE transcript SHA3-256' \
    build/r1cs-reference-repro/truncated.log; then
    printf 'incomplete reference hashes were printed\n' >&2
    exit 1
fi
~~~

On maintainer hosts, prefix each make invocation with devbuild --wait.
The normal group must pass. The malformed-reference invocation must retain its
test failure and emit neither reference-golden heading nor reference transcript.
No proving parameters or live chain are needed for this fixture.

## Recorded failure

The parent source passed its normal focused group. One invocation with the
20-byte fixture parsed the header, passed the row/input-count checks, failed at
row 0, then printed 21 purported reference section hashes and a transcript hash.
The registered group reported one failure, zero skips and zero flaky results;
the make invocation exited 2. This is evidence of the diagnostic defect,
separate from the normal group qualification.

## Reorder fixture bounds

A separate review found that the reorder injection searched for a row differing
from row zero, then indexed the result even when no such row existed. Zero-row,
one-row, or all-equal input could therefore reach an out-of-bounds swap. The
in-place swap helper now refuses those inputs without modifying a row and returns
false when no distinct pair exists. The normal injection still swaps row zero
with the first differing row and retains both original caught/located assertions.
A degenerate corpus remains a failing injection; it is not silently accepted.

The registered group directly exercises the actual swap helper with zero rows,
one row, three equal rows, and three distinct rows. Refusal cases must leave the
whole supplied buffer unchanged. The distinct case checks the exact resulting
buffer, including the untouched third row.

### Reorder follow-up evidence

Source parent: f5ef7770c8359d05d4fc8d12a6da490a60e68bb6.
The focused `groth16_r1cs_oracle` group passed on 2026-10-27: one cold group,
zero failures, skips, unobserved environment checks or load-flaky results.
All four direct swap-helper edge checks passed. The original five injected
coefficient, matrix, reorder and variable-kind disagreement checks retained
their failing-input assertions and passed, including both reorder caught/located
checks. Reported group wall time was 0.8 seconds; this is not a performance claim.

The unchanged 20-byte header-only reference fixture still produced make exit 2
and the original row-0 truncation failure. One registered group failed with zero
skips, unobserved environment checks or load-flaky results, including its native
isolated retry. Neither reference section-golden output nor the reference
transcript hash appeared. The expected-negative assertion wrapper returned 0.
A full external reference was not fabricated or newly tested.

Evidence SHA256:

- Normal focused log:
  `4ffdc09eff3b6610c8edc426f0dabd9dee955bc2d5f29b739f29f2de64230d49`.
- Expected-negative log:
  `317e755562df226650a8411d4e74eec5cb9d9e56918376ce55a497e5e4422674`.
- Retained header-only reference fixture:
  `9e50b47001df41c716c2806e75bfe919205b7238db68af90bd21222b0d1b2bb2`.
