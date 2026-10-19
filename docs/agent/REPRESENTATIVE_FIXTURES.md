<!-- Copyright 2026 Z23 contributors. Licensed under Apache-2.0. -->

# Representative regression fixtures

Build a regression from the smallest public shape that still reaches the
production failure. Representative means behaviorally faithful, not copied
with secrets or unrelated bulk.

## Preserve the failure shape

- Start from an observed production path and identify the caller-visible
  postcondition that failed.
- Copy structural facts needed to reproduce it: ordering, boundary sizes,
  file kinds, return codes, and state transitions. Replace identifiers and
  payload bytes that are not part of the invariant.
- Put files under the repository's test scratch helpers. Do not write a bare
  global temporary path or mutate the source tree during proof generation.
- Register the test in the owning group. Use `z23 code tests <path>` to find
  every group routed by the changed path.

Prove RED with one intentional mutation that removes or inverts the proposed
fix. Record the exact mutation and expected failure. Restore the source and
prove GREEN with the same fixture. A zero-test run is not a pass, and one
injected directory error does not prove every possible directory error.

## Report only what ran

Name the exact base, candidate, command, fixture, exit status, and retained
receipt. Use these verdicts literally:

- **PASS**: the named command tested the named inputs and met its assertion.
- **FAIL**: the command ran and did not meet it; preserve the diagnostic.
- **NOT RUN**: no applicable execution evidence exists.

An ordinary self-test witness covers its fixture and execution environment.
It is not a whole-tree gate or full lint. Fixtures and receipts are public only after a sensitive-material review.
Never embed wallet seeds, private keys, credentials, private endpoints,
personal data, machine paths, or host load and capacity figures.
