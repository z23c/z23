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
oracle, whose corpus contains six witnesses. The representation helper now
receives a null reference pointer whenever the reference is unavailable;
available references retain their original pointer. The actual caller must
complete those cases without accessing the absent reference.

The guarded caller passed the registered group on 2026-10-27 with all six
witnesses: one cold group, zero failures, skips, unobserved environment checks
or load-flaky results. The reported test body took 44.748 seconds; this is not
a performance comparison.

A temporary mutant removed only `have_nk_ref &&` from the expected reference-bit
expression. The same registered group then failed with SIGSEGV at address zero
in `groth16_spend_parity_oracle`, after corpus[1] reported its reference absent.
Make exited 2; one group failed with zero skips or load-flaky results. The
guarded source was restored and its exact blob verified after the experiment.

This demonstrates guard-removal detection with the null-reference caller on
the tested build. It does not establish a wrong cryptographic verdict or
change the earlier analyzer NOTDETECTED result.

Source parent for this follow-up:
`2aaad2e234cdfcef77269d4c581876d6b7614f50`.
Guarded source blob: `4fcced4009d8e8b89694dd27c0e657ae9c60af08`.

Evidence SHA256:

- Guarded group log:
  `a340016c8fe8f776f0136cc12875962cc90bbc0a821dc9734f7b4aa5b000e1c8`.
- Guard-removal group log:
  `7c9b39d6e308e0edb4c48d65f676ad0a871120eff237167550123d7504399722`.

<!-- claim: symbol-present groth16_spend_parity_oracle tests/harness/src/test_groth16_selfverify.c -->
<!-- claim: symbol-present CORPUS_N tests/harness/src/groth16_spend_parity.c -->

## Reproduce the existing caller check

Run from the repository root:

~~~sh
make t-fast ONLY=groth16_selfverify || exit 1
~~~

On maintainer hosts, prefix the make invocation with `devbuild --wait`.
This requires no live node, spending authority or production wallet state.
