<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Wallet recovery fixture validation

Observed 2026-11-07. The payment and destruction-drill fixtures initialize
ordinary wallets as ready. The destruction drill writes the computed transaction
hash into its single-transaction block's Merkle root. The missing-body refusal
and custody assertions remain in place.

<!-- claim: symbol-present wallet_readiness_initialize tests/harness/src/test_shielded_payment_gate.c # ordinary wallet fixture lifecycle -->
<!-- claim: symbol-present wallet_readiness_initialize tests/harness/src/test_wallet_destruction_drill.c # restored wallet fixture lifecycle -->
<!-- claim: symbol-present hashMerkleRoot tests/harness/src/test_wallet_destruction_drill.c # authenticated synthetic block body -->

The first run passed three selected groups with one skipped payment stress
section. The second run exercised that section and passed without skips.

```sh
make t-fast-exact ONLY=shielded_payment_gate,simnet_shielded_wallet_e2e,wallet_destruction_drill ZCL_PARAMS_TESTS=1 ZCL_TEST_WERROR=1
make t-fast-exact ONLY=shielded_payment_gate ZCL_PARAMS_TESTS=1 ZCL_STRESS_TESTS=1 ZCL_TEST_WERROR=1
```

Evidence SHA-256:

- First run: `d9fbebc09b49a2ed4629ac034ca9fd151d3bb6be23d56fb42856c737bbe10cd5`.
- Stress run: `d5eeed3c9d0514791252a05beaab5a3db3e0be80645453c100ac322070d32527`.

These fixture results do not establish live phone migration or server snapshot
acceptance.
