<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->
# Pixel shielded transaction API

Date: 2026-10-28. Device: Pixel 3, Android API 35, AArch64.

## Contract

`core mining regtest-mine` plans a bounded payment of block rewards to a
transparent address. Input is `address`, integer `blocks` in 1..101, and
optional boolean `confirm`. Planning does not contact or mutate a node.
Committing requires `confirm:true`, checks that the target reports regtest,
and calls the existing `generatetoaddress` handler once. That handler retains
its network, sovereignty, and active-network address checks.

The result contains `stage`, `address`, `blocks`, and, after success,
`block_hashes`. An interrupted or malformed commit response reports
`MINING_OUTCOME_UNKNOWN`: inspect the chain before any retry. This command
does not provide durable deduplication.

## Isolated demonstration

Use a fresh test datadir and wallet, explicit distinct RPC/P2P ports,
`-regtest -regtestshielded -operator-lane=dev`, and verified public proving
parameters. Confirm `getblockchaininfo.chain` is `regtest` before mutations.
Pass the explicit test datadir and RPC port on every client invocation.
`wallet_scope=dev` does not select the network or isolate the wallet.

1. Create a transparent address and two Sapling addresses with
   `core wallet address new` and `core wallet shielded address`.
2. Mine 101 blocks to the transparent address so a coinbase is mature.
3. Plan and commit `core wallet shielded send` from the transparent address
   to the first Sapling address, using an exact decimal amount and a memo.
4. Mine one block. Read `core wallet transaction get`,
   `core wallet shielded notes`, and `core chain block get`; require a
   confirmation, the expected note amount/memo, and actual block inclusion.
5. Repeat from the first Sapling address to the second. Require block
   inclusion and the recipient note before reporting success.

A committed transaction ID alone is not confirmation. Use only valueless
regtest coins; no mainnet wallet is needed for this demonstration.

## Evidence

The host `simnet_sapling_shielded_send` group passed its real output/spend
proof and consensus-verifier legs: one group, zero failures, zero skips,
42.2 seconds. `native_api_contract,generatetoaddress` passed two groups with
zero failures or skips. The new command received independent source review.

On the Pixel, all four public parameter files matched pinned SHA-256 hashes.
The installed binary passed its native Spend/Output/binding prover self-test.
The existing shielded API created a 1.00000000 regtest coin payment in
11.062 seconds. Its recipient note and memo were observed with one
confirmation at height 102, and the transaction was present in that block.

These device observations exercise the previously installed binary; the new
mining API has not yet been installed or qualified on the Pixel. Full release
gates have not been completed.

The subsequent shielded-to-shielded device transaction committed in
101.124 seconds and was confirmed at height 103. The recipient note was
0.25000000, its memo matched, and the change note was 0.74999900 after a
0.00000100 fee. The transaction ID appeared in the independently queried
block transaction list. These timings include proving and API processing
while the mainnet node also ran; they are observations, not standalone
prover benchmarks. The temporary regtest node shut down cleanly after the
demonstration; its test wallet and evidence were retained.

## Reverse transaction mapping regression

On 2026-10-29 UTC, the release proof rejected the new mining command because
its semantic transaction mapping was missing. The coinbase reward catalog now
includes the bounded regtest mining command as a component. The regression
assertion requires that exact role and rejects a nonchain exemption; the
general reverse-coverage assertion and catalog counts remain unchanged.
<!-- claim: symbol-present tx_type_regtest_mining_maps_coinbase tests/harness/src/test_api_transaction_types.c # regtest mining requires a real coinbase component mapping -->

The focused `api`, `native_api_contract`, and `command_registry_catalog`
groups passed: three groups ran, zero failed, zero skipped, 43.8 seconds wall
time. This repairs catalog classification without changing mining, consensus
or custody behavior. Reproduce through the canonical runner:

```sh
make -j4 t-fast-exact ONLY=api,native_api_contract,command_registry_catalog
```
