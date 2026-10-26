<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Optional Groth16 reference-byte guard

Date: 2026-10-26.
Source parent: e6caee0a1135fb237d4c4ad3a4bf72200a33f58b.

The spend parity oracle declares an uninitialized `nk_ref` buffer and asks the
optional external reference to fill it. A missing reference returns false.
The compressed-representation loop previously read that buffer before the
later availability guard suppressed the external-reference verdict.

The expected reference-bit expression now short-circuits on `have_nk_ref`.
When the reference is absent, it reads no `nk_ref` bytes. The buffer is not
initialized with substitute data. The existing availability guard still
suppresses the reference verdict and prints the same absence diagnostic.
The `ak` work, native wire checks and valid-reference read order remain intact.

<!-- claim: symbol-present parity_check_compressed_key_representation tests/harness/src/groth16_spend_parity.c -->

## Evidence and limits

The finding is established by source-path inspection. GCC analyzer output was
NOTDETECTED: it did not report this read. No wrong runtime verdict was
demonstrated. This change does not claim a demonstrated cryptographic mismatch
or a production-crypto repair; it guards an optional test-reference read.

The existing `groth16_selfverify` registered group calls the spend parity
oracle, whose corpus contains six witnesses. It is the focused regression
check for this change and exercises the actual caller. No mirror test or new
instrumentation is added. A passing group does not turn the analyzer result
into detection evidence.

<!-- claim: symbol-present groth16_spend_parity_oracle tests/harness/src/test_groth16_selfverify.c -->
<!-- claim: symbol-present CORPUS_N tests/harness/src/groth16_spend_parity.c -->

## Reproduce the existing caller check

Run from the repository root:

~~~sh
make t-fast ONLY=groth16_selfverify || exit 1
~~~

On maintainer hosts, prefix the make invocation with `devbuild --wait`.
This requires no live node, spending authority or production wallet state.
