<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# Signed request-ID replay binding

Date: 2026-09-24T21:35:07-04:00 (2026-09-25T01:35:07Z).
Base commit: `4d0b1e25abaedce0a4d6aeb1a36d1a25079953f7`.
Host: AMD Ryzen 7 PRO 8840U. Compiler: GCC 16.1.1 20260430, C23.

A worker retains an inbound track by authenticated peer and request ID. The
previous repeat branch selected that track and signed an admission for the
newly received request without comparing its signed bytes. A peer could send
a second valid signature under the same request ID with a different action
root. The worker would answer with the old slot's disposition and generation
bound to the new action root, although it had not admitted that new action.

The worker now returns `VCS_ZCODE_WORK_NODE_REPLAY` when a repeated request
does not match the original signature. An exact repeat still returns the
existing signed admission after reconnect. The executable regression changes
only the action root, signs the new request with the original requester key,
and verifies replay refusal without adding another physical request.
The handler's redundant confinement check was removed; its mandatory mask
remains inside `work_capability_matches` through `work_capability_allows`.

```bash
make CC=gcc -j4 t-fast ONLY=zcode_dev_objects
make CC=gcc docs-capability-inventory
make CC=gcc check-capability-inventory-generated
```

The registered `zcode_dev_objects` group passed 1/1 in 11.3 s after the
modified source and test objects were rebuilt. Its captured log SHA-256 is
`d2ace5fdc4aefb0003aa06a616fa890f19b19a0726024d029011e8fb51d91a4c`.
The generated inventory check passed 1503 capabilities and 1151 resolved
registered roots. The inventory SHA-256 is
`efdfc26fa4166722e24fc08019462505bc8a2b388e4a81b09def0c69be6bb43a`;
its captured generation/check log SHA-256 is
`11a264e3373f1c61a3481a8ec95f202772951042fbacd026ce1a5d7a59129c02`.

The focused test proves the in-process signed replay boundary. It does not
claim six-peer delivery, cross-task component reuse, a remote proof receipt,
or release acceptance.

## Successor on current main

At 2026-09-25T02:24:01Z, native land seq 47 had ended in a terminal rebase
conflict over the generated inventory and test source. The successor was
applied in an isolated worktree at base
`f6d1fc7679ef96dc16f7211c8870aa3600bca420`. The replay source and
regression applied cleanly; the inventory was regenerated from that exact
tree. The registered group passed 1/1 with zero skipped groups; its log
SHA-256 is `057ebbfc11eefc632985bcb90fe8e84fd4fa491abb457d7ff01e68315dcaa3fb`.
The generated inventory check and lint-fast passed with log SHA-256 values
`8854b342b12f5eeae4617ced02e9b36af026e7a89f807a0e1079f8985977e3fc`
and `7a52c5827055c9b90f96625413412d94b51b8d39911dafb9e7c1e893e238e404`.
The source, test, and inventory SHA-256 values are respectively
`7c0bc5c40cecdb60dd4d35e2fa96b9d9bc20f4d5363731a841062e78488a0757`,
`2dbcd3579744427904a7434a0730fcf26a545ca72ff55acd8daf07b5855e761a`,
and `cdbaf94f4a90c0954c7b714c3ddb28dd190247fc35d7e351dadf638041f09c8b`.
This section establishes local focused acceptance on the successor source;
native landing proof and independent remote receipt remain separate gates.

Before successor submission, `origin/main` advanced to
`613962f32` and changed the generated inventory. A non-destructive merge
integrated that tip; the inventory was regenerated from the merged source.
The merged inventory SHA-256 is
`0f0b2580647ce355d0453110139f11351cdf9f23c03cf2e22c55b7074abfbf11`.
The generated check passed again. The registered group remained 1/1 PASS
with no skipped groups (log SHA-256
`53b56a5df9333b26e8c2dae56a4cb1e977e4051d2640024e2c1319af810382e7`),
and lint-fast passed (log SHA-256
`0e3dbe66ef22b4d2d6dab1b3a8091f209bf405a9a7449eeac5002cc9e5bf399e`).
