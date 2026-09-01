# Simulator

This document describes the current deterministic simulator surface and the
application action coverage tested through it.

Source anchors for this matrix are code, not project prose:

- `engine/modules/sim/include/sim/simnet.h`
- `engine/modules/sim/src/simnet.c`
- `tests/harness/src/test_simnet.c`
- `tests/harness/src/test_simnet_doublespend.c`
- `tests/harness/src/test_simnet_chained_tx.c`
- `tests/harness/src/test_simnet_block_sigops.c`
- `tests/harness/src/test_simnet_duplicate_input.c`
- `tests/harness/src/test_simnet_value_inflation.c`
- `tests/harness/src/test_simnet_fee_range.c`
- `tests/harness/src/test_simnet_empty_vin_vout.c`
- `tests/harness/src/test_simnet_input_value_range.c`
- `tests/harness/src/test_simnet_sapling_activation.c`
- `tests/harness/src/test_simnet_sapling_shielded_send.c`
- `engine/modules/sim/include/sim/simnet_sapling.h`
- `engine/modules/sim/src/simnet_sapling.c`
- `engine/modules/sim/include/sim/simnet_cluster.h`
- `engine/modules/sim/src/simnet_cluster.c`
- `tests/harness/src/test_simnet_cluster.c`
- `tests/harness/src/test_simnet_fuzz.c`
- `contexts/market/modules/zslp/include/zslp/slp.h`
- `contexts/market/modules/zslp/src/slp.c`
- `contexts/naming/modules/znam/include/znam/znam.h`
- `contexts/naming/modules/znam/src/znam.c`
- `contexts/explorer/models/src/explorer_index.c`
- `contexts/market/models/src/explorer_index_zslp.c`
- `engine/modules/storage/src/znam_projection.c`
- `engine/controllers/src/api_controller_app_protocols.c`
- `core/modules/net/src/msgprocessor.c`
- `core/modules/net/include/net/zmsg.h`
- `core/modules/net/include/net/p2p_game.h`
- `core/modules/net/include/net/file_market.h`
- `core/modules/net/include/net/file_service.h`
- `core/modules/script/include/script/htlc.h`
- `core/modules/script/src/htlc.c`
- `engine/controllers/src/swap_controller.c`

## Model

`simnet` is a deterministic, RAM-only, single-node chain harness. It builds
blocks and sends them through the real `connect_block()` path with
`expensive_checks=false`, then inspects the in-memory `coins_view_cache` and
any explicit projection database the test opens.

The harness does not change consensus predicates. It installs a synthetic
covering checkpoint and mints at heights covered by that checkpoint, which is
the same mechanism used by connect-block tests to skip expensive PoW and
script verification without changing the validator code under test.

The live chain state is:

- `view`: RAM `coins_view_cache`; this is the simulator UTXO set.
- `tip`: current `block_index`; the next block links to `tip.hashBlock`.
- `params`: copied chain params plus the synthetic checkpoint entry.
- projection DBs: optional in-memory `node_db` instances opened by tests for
  explorer, ZSLP, and ZNAM assertions.

The simulator is deterministic. It uses caller-assembled transactions, fixed
heights, fixed keys/seeds in tests, and no wall-clock or entropy source. The
`tools/sim` seed-tape path is the wider deterministic replay mechanism: a
64-bit seed can drive generated events, and the replayed event sequence is the
unit under comparison.

## Public API

| Function | Purpose |
|----------|---------|
| `simnet_init` | Initialize a fresh RAM-only chain harness with a synthetic base tip and checkpoint-covered params. |
| `simnet_free` | Release the harness in-memory coins view; idempotent. |
| `simnet_mint_coinbase` | Mint one block containing only the harness coinbase and advance through `connect_block()`. |
| `simnet_mint_txs` | Mint one block containing the harness coinbase plus caller-built transparent transactions. |
| `simnet_spend` | Mint a mature-coinbase spend through `connect_block()` and return the spend txid. |
| `simnet_tip_height` | Return the current simulator tip height. |
| `simnet_tip_hash` | Copy the current simulator tip hash. |
| `simnet_coin_exists` | Return whether a txid has any live output in the RAM UTXO set. |
| `simnet_coin_value` | Return the value of a live `txid:n` coin from the RAM UTXO set. |

## Action Classes

Class A: on-chain transparent or OP_RETURN action testable through simnet
today. These actions can be placed in a real block, accepted by
`connect_block()`, and asserted against the RAM coins view or an in-memory
projection.

Class B: on-chain or script action not yet simulable. The action has protocol
or script code, but current simnet lacks a required component such as Sapling
post-activation state, a mempool/timelock flow, a builder/parser/projector, or
an end-to-end settlement path.

Class C: P2P-only, controller-only, or direct-service action. These actions do
not fold through `connect_block()` and are out of simnet scope.

## Action Coverage Matrix

| Action | Class | Current coverage or gap |
|--------|-------|-------------------------|
| Transparent P2PKH spend | A | `make t ONLY=simnet`: `spend the matured coinbase through connect_block`, `spend output carries the chosen value`. |
| Transparent double-spend rejection (same-block and cross-block) | A | `make t ONLY=simnet_doublespend`: `test_simnet_doublespend` mints two distinct transparent txs spending one matured-coinbase outpoint in the same block, and separately spends an outpoint in block N then attempts a second spend of it in block N+1; both are rejected by `connect_block()` with `bad-txns-inputs-missingorspent` and the tip does not advance. A positive-control single valid spend and a post-rejection honest mint prove the negatives are not vacuous. |
| Intra-block chained/dependent-tx ordering (topological order) | A | `make t ONLY=simnet_chained_tx`: `test_simnet_chained_tx` mints tx A (spends a matured coinbase) followed by tx B (spends A's output) in the SAME block; `connect_block()` applies vtx[] in order, so A-before-B is accepted and B's output lands in the view. A second simnet, built from BYTE-IDENTICAL tx content (same txids, proven via `uint256_eq`) but with B placed BEFORE A, is rejected with `bad-txns-inputs-missingorspent` because A's output does not exist yet when B is checked — proving order alone (not tx content) determines the outcome. A 3-tx chain (A→B→C, in order) is a positive control that the mechanism generalizes past one hop. |
| Block sigop-limit rejection (`bad-blk-sigops`) | A | `make t ONLY=simnet_block_sigops`: `test_simnet_block_sigops` mints a block whose spend outputs carry two 10000-byte OP_CHECKSIG scriptPubKeys plus a one-byte one (20001 legacy sigops, one over `MAX_BLOCK_SIGOPS=20000`); `connect_block()`/`check_block()` rejects it with `bad-blk-sigops` and the tip does not advance. A positive control at exactly 20000 sigops is accepted (tip advances) and a post-rejection honest mint proves the negative is not vacuous. |
| Transparent duplicate-input rejection (one tx, same outpoint twice) | A | `make t ONLY=simnet_duplicate_input`: `test_simnet_duplicate_input` mints one tx whose vin list contains the same matured-coinbase outpoint twice; `connect_block()` rejects it structurally (`check_block` -> `check_transaction`) with `bad-txns-inputs-duplicate` and the tip does not advance. A positive-control two-input tx over two DISTINCT coinbase outpoints is accepted, consumes both coins, and advances the tip — distinct from the double-spend (`missingorspent`) row above. |
| Output value inflation rejection | A | `make t ONLY=simnet_value_inflation`: `test_simnet_value_inflation` spends a matured coinbase (1_000_000 zatoshi) to a single output of 2_000_000 — every individual output is in `MoneyRange`, so the only defect is that the output sum exceeds the input sum; `connect_block()` rejects with `bad-txns-in-belowout` and the tip does not advance. A positive control (900_000-out, 100_000-fee spend accepted) and an equal-value boundary (zero-fee `value_in == value_out` accepted) prove the negative is neither vacuous nor off-by-one. Distinct from the coinbase over-claim (`bad-cb-amount`) and single-output value-range (`bad-txns-vout-*`) classes. |
| Negative-fee / money-creation rejection (outputs exceed inputs) | A | `make t ONLY=simnet_fee_range`: `test_simnet_fee_range` spends a matured coinbase to an output LARGER than the input (implied negative fee), which `connect_block()` rejects with `bad-txns-in-belowout` (the `value_in < value_out` check at connect_block.c:527 fires before the shadowed `bad-txns-fee-negative` check) and the tip does not advance. A positive control spending to a smaller output (a +100k-zatoshi in-range fee) is accepted and advances the tip. Note: `bad-txns-fee-negative` is arithmetically unreachable (shadowed by belowout) and `bad-txns-fee-outofrange` needs a per-block fee sum > MAX_MONEY, not constructible under subsidy-bounded simnet funding. |
| Empty transaction inputs / outputs rejection | A | `make t ONLY=simnet_empty_vin_vout`: `test_simnet_empty_vin_vout` mints a non-coinbase tx with zero inputs (rejected `bad-txns-vin-empty`) and, separately, a tx with zero outputs (rejected `bad-txns-vout-empty`) through the real `connect_block()` (`check_block` → `check_transaction_in_block` → `domain_consensus_check_transaction_structural`, tx_structural.c:92-105); both rejects leave the tip unadvanced. A positive-control valid ≥1-in/≥1-out spend and a post-rejection honest mint prove the negatives are not vacuous. |
| Input value out of range rejection | A | `make t ONLY=simnet_input_value_range`: `test_simnet_input_value_range` spends a matured coinbase with a Sapling `value_balance` that pushes the tx's contextual input total (transparent prevout + `value_balance`) one atoshi past `MAX_MONEY`; `connect_block()` rejects with `bad-txns-inputvalues-outofrange` and the tip does not advance. A boundary positive control at exactly `MAX_MONEY` and an ordinary in-range spend are accepted, so the negative is a true off-by-one (the context-free structural gate bounds `value_balance` alone but cannot see the transparent prevout). |
| Transparent multi-input spend | A | `make t ONLY=simnet`: `mint multi-input/multi-output/P2SH tx through simnet`, `multi-input tx consumes both inputs`. |
| Transparent multi-output spend | A | `make t ONLY=simnet`: `explorer indexes multi-input/multi-output/P2SH tx`, `explorer records two transparent inputs`. |
| OP_RETURN data output | A | `make t ONLY=simnet`: `simnet_mint_txs accepts transparent+OP_RETURN block`, plus malformed protocol OP_RETURN negatives below. |
| P2SH funding output | A | `make t ONLY=simnet`: `P2SH output remains in coins view`, `explorer records one P2SH output`. |
| P2SH redeem | A | `make t ONLY=simnet`: `test_simnet_txkit` covers HTLC P2SH funding, redeem settlement (claim with secret), and refund settlement (reclaim after locktime). |
| ZSLP `GENESIS` | A | `make t ONLY=simnet`: `mint SLP GENESIS through simnet`, `ZSLP projection sees token`. |
| ZSLP `SEND` | A | `make t ONLY=simnet`: `mint SLP SEND through simnet`, `ZSLP projection sees genesis/send transfer balances`. |
| ZSLP `MINT` | A | `make t ONLY=simnet`: `mint SLP MINT through simnet`, `ZSLP projection sees mint transfer`. |
| ZSLP malformed lokad | A | Negative case: `malformed SLP OP_RETURN is indexed as non-SLP`, `malformed SLP does not add token transfers`. |
| ZSLP `BURN` | B | `SLP_TX_BURN` exists as an implicit enum/comment, but there is no `slp_build_burn`, parser branch, or burn projection row. Current ZSLP projection records decoded token transfers; it is not a token-validity ledger and does not enforce spend balance. |
| ZNAM `REGISTER` | A | `make t ONLY=simnet`: `mint ZNAM REGISTER through simnet`, `ZNAM projection resolves registered name`. |
| ZNAM `UPDATE` | A | `make t ONLY=simnet`: owner positive `ZNAM owner UPDATE changes primary target`; non-owner negative `ZNAM non-owner UPDATE is ignored by projection`. |
| ZNAM `TRANSFER` | A | `make t ONLY=simnet`: `mint ZNAM TRANSFER through simnet`, `ZNAM TRANSFER changes owner`. |
| ZNAM `RENEW` | A | `make t ONLY=simnet`: `mint ZNAM RENEW through simnet`, `ZNAM RENEW is a node.db projection no-op today`. The event-log projection has expiry/renew concepts, but the node.db explorer projection has no expiry column. |
| ZNAM `SET_RECORD` | A | `make t ONLY=simnet`: owner positive `ZNAM SET_RECORD writes BTC address record`; non-owner negative `ZNAM non-owner SET_RECORD is ignored by projection`. Owner-auth enforced (same mechanism as `UPDATE`, `contexts/explorer/models/src/explorer_index.c` `apply_znam`); unit-level coverage also in `test_explorer_index`. |
| ZNAM `SET_TEXT` | A | `make t ONLY=simnet`: owner positive `ZNAM SET_TEXT writes text record`; non-owner negative `ZNAM non-owner SET_TEXT is ignored by projection`. Owner-auth enforced (same mechanism as `UPDATE`, `contexts/explorer/models/src/explorer_index.c` `apply_znam`); unit-level coverage also in `test_explorer_index`. |
| ZNAM malformed lokad | A | Negative case: `malformed ZNAM OP_RETURN is indexed generically`, `malformed ZNAM lokad does not mutate name projection`. |
| ZMSG P2P send (`zmsg`) | C | P2P message, not a chain action. Serialization, overflow rejection, deterministic id, and in-memory store are covered by `test_protocols`; network framing is covered by `test_net`. |
| ZMSG P2P ack (`zmsgack`) | C | P2P acknowledgement dispatch, not a chain action. Dispatch table coverage is in `test_net`; ZMSG message primitives are in `test_protocols`. |
| ZMSG Sapling memo channel | A | On-chain channel implemented. The v1 memo wire format (magic `ZM` + version + flags + reply-to + UTF-8 payload, ≤474 bytes; `docs/ZMSG_ONCHAIN.md`) has an encoder/decoder in `core/modules/net/src/zmsg.c` with unit + negative tests in `test_protocols` (fast pool). `msg_send channel=onchain` composes `z_sendmany` (memo carried via a new binary-safe `memo_hex` recipient key), failing closed when the prover isn't READY. The note-decrypt path (`tip_finalize_post_step.c` → `zmsg_ingest_onchain_note`) lands inbound ZMSGs in the store (dedup by `msg_id = SHA3(txid‖memo)`). End-to-end proof: `make t ONLY=simnet_zmsg_onchain` (params-gated) mints a real `t→z` memo tx in-sim, decrypts, parses, ingests, and surfaces it in the store. |
| Sapling sim-local activation | A | `make t ONLY=simnet_sapling_activation`: `test_simnet_sapling_activation` lowers Overwinter/Sapling activation on the sim's params value-copy only (`simnet_activate_sapling_at`), proves no mainnet leak (`chain_params_get()` unchanged), and a post-activation transparent block passes the real `hashFinalSaplingRoot` check via the empty-tree-root stamp. |
| Sapling shielded send (t→z, z→z) | A | Params-gated (`ZCL_PARAMS_TESTS=1` or `--only=simnet_sapling_shielded_send`; real Groth16 proving is seconds+RAM-heavy, so it is out of the default fast pool): `test_simnet_sapling_shielded_send` drives the full in-sim shielded pipeline — depth-32 note-commitment tree + anchor/witness (`engine/modules/sim/src/simnet_sapling.c`), t→z and z→z built with the real prover and verified by the real consensus verifier, memo/rcm decrypt round-trip, durable nullifier set with shielded double-spend rejection, and seeded txid determinism via the `ZCL_TESTING` RNG hooks. |
| Market offer gossip (`zfilelist`) | C | P2P gossip action, out of simnet scope. Serialization/cache behavior is covered by `test_file_market` and dispatch/cache coverage in `test_net`. |
| Market challenge (`zfilechal`) | C | P2P proof-of-possession challenge, out of simnet scope. Covered at serialization/model level by `test_file_market`. |
| Market proof (`zfileproof`) | C | P2P challenge response, out of simnet scope. Covered at serialization/model level by `test_file_market`. |
| Market payment notification (`zfilepay`) | C | P2P notification carrying a payment txid, out of simnet scope. End-to-end shielded payment settlement is not a simnet action today. |
| File address announcement (`zfileaddr`) | C | P2P/file discovery action handled by the message processor, not a chain action. Dispatch table coverage is in `test_net`. |
| File service `HELLO` | C | Direct TCP file-service frame, not a chain action. `test_file_controller` covers service start/stop and manifest state; no focused frame roundtrip is in simnet. |
| File service `MANIFEST` | C | Direct TCP file-service frame, not a chain action. Manifest building/status are covered by `test_file_controller`; direct frame transfer is not in simnet. |
| File service `REQUEST` | C | Direct TCP file-service frame, not a chain action. No focused simnet coverage; belongs in file-service frame tests. |
| File service `DATA` | C | Direct TCP file-service frame, not a chain action. No focused simnet coverage; belongs in file-service frame tests. |
| File service `DONE` | C | Direct TCP file-service frame, not a chain action. No focused simnet coverage; belongs in file-service frame tests. |
| File service `PADDING` | C | Direct TCP keepalive/traffic-analysis padding frame, not a chain action. No focused simnet coverage; belongs in file-service frame tests. |
| Market RPC/local `zmarket_offer` | C | Controller/service action that creates local offer state and gossip payloads. Lower-level offer serialization/cache/DB behavior is covered by `test_file_market`; no end-to-end simnet coverage. |
| Market RPC/local `zmarket_list` | C | Local read/controller action. Lower-level offer list/find behavior is covered by `test_file_market`; no end-to-end simnet coverage. |
| Market RPC/local `zmarket_buy` | C | Local download workflow action. The chunk/payment glue is not an on-chain simnet action today; no end-to-end simnet coverage. |
| Market RPC/local `zmarket_status` | C | Local read/controller action. File manifest/status pieces are covered by `test_file_controller`; no end-to-end simnet coverage. |
| HTLC script build | A | `make t ONLY=simnet`: `test_simnet_txkit` builds and tests the 97-byte HTLC contract through settlement (lines 321-322). |
| HTLC P2SH address derivation | A | `make t ONLY=simnet`: `test_simnet_txkit` derives P2SH address from HTLC script and funds P2SH output; redeem/refund settlement paths are tested end-to-end. |
| HTLC redeem scriptSig build | A | `make t ONLY=simnet`: `test_simnet_txkit` (lines 334-345) builds redeem scriptSig, enqueues to mempool, and verifies settlement through connect_block. |
| HTLC refund scriptSig build | A | `make t ONLY=simnet`: `test_simnet_txkit` (lines 362-381) builds refund scriptSig, tests nonfinal rejection before lock height, advances to lock height, then enqueues and verifies settlement. |
| HTLC secret extraction | A | `make t ONLY=simnet`: `test_simnet_txkit` uses extracted secret in redeem scriptSig (line 195) and verifies it through mempool/settlement. |
| Swap chain selection (`ZCL`, `BTC`, `LTC`, `DOGE`) | C | Controller/model selection action, not a chain action. Covered by swap/HTLC protocol tests. |
| Swap initiate | C | Controller/model action that builds local swap state. On-chain funding/settlement remains Class B. |
| Swap participate | C | Controller/model action that builds local swap state. On-chain funding/settlement remains Class B. |
| Swap list | C | Local read action, not a chain action. |
| Swap funded/redeemed/refunded/expired state transitions | B | States exist in code, but complete on-chain detection and settlement are not driven through simnet today. |
| Game ping type | C | P2P latency game, not a chain action. Covered by `test_game`. |
| Game tic-tac-toe type | C | P2P game, not a chain action. Covered by `test_game`. |
| Game `INVITE` | C | P2P game action. Covered by `test_game`. |
| Game `ACCEPT` | C | P2P game action. Covered by `test_game`. |
| Game `MOVE` | C | P2P game action. Covered by `test_game`. |
| Game `STATE` | C | P2P game action. Covered by `test_game`. |
| Game `RESIGN` | C | P2P game action. Covered by `test_game`. |
| Game `RESULT` | C | P2P game action. Covered by `test_game`. |

## Running

Current simnet action coverage is in the `simnet` test group:

```bash
make t ONLY=simnet
```

This branch does not split a separate `simnet_actions` group. If a future
branch moves the matrix to `test_simnet_actions.c`, run:

```bash
make t ONLY=simnet_actions
```

### Multi-node cluster fuzz (`simnet_fuzz`)

`test_simnet_fuzz` is a deterministic seed-fuzzer over the REAL multi-node
simulator (`simnet_cluster` + `simnet_chain`: real `connect_block()` /
`disconnect_block()` and real chainwork fork-choice). Per seed it derives a
scenario — node count (2–4), rounds of random-length branch mints, a
send-side partition (a random subset relays while the rest withhold a private
branch), then a final heal — drives the cluster to quiescence, and asserts:
all nodes converge to one tip hash, `simnet_cluster_coins_digest` is identical
across every node, replay of the same seed is bit-identical (tip + coins
digest + delivery fingerprint), and — via the `simnet_byzantine` builders in
the same loop — every rejected block was rejected with a NAMED reason. On any
failure it prints the failing 64-bit seed and writes a replay capsule
(postmortem/seed-tape API).

```bash
make t ONLY=simnet_fuzz
# deeper nightly sweep + pinned replay:
ZCL_SIMNET_FUZZ_SEEDS=2000 make t ONLY=simnet_fuzz
ZCL_SIMNET_FUZZ_SEED=0x51c0ffee5eed0001 make t ONLY=simnet_fuzz
```

Run the normal compile and lint gates before shipping simulator edits:

```bash
make -j8 build-only
make -j8 t ONLY=simnet
make lint
make check-doc-accuracy
```

### Algorithmic-cost measurement (`simnet_perf`)

Everything above measures CORRECTNESS. `engine/modules/sim/src/simnet_perf.c` +
`tools/sim/simperf.c` (`make sim-perf`) measure COST: they replay a fixed
mint/spend workload through the same real `connect_block()` fold at 1x/2x/4x
size and gate on how much per-transaction CPU cost GROWS across that span, which
catches an algorithmic-complexity regression on the UTXO path. The gated metric
is a dimensionless ratio, so it holds on any machine; absolute nanoseconds are
reported for humans only. It is explicitly NOT a wall-clock sync measurement —
there is no disk, network, real PoW, or real script/proof verification on this
path. The detector ships with a proven-failing direction
(`make sim-perf-teeth`, `make t ONLY=simnet_perf`). Full contract:
[`SIMNET_PERF.md`](./SIMNET_PERF.md).

## Reproducing a failure

`tools/sim/wire_sweep.c` (`make wire-sweep SEEDS=N`) sweeps `simnet_wire`
seeds and, on any monitor failure, prints `FAIL seed=0x...` and saves that
seed's replay capsule as `<artifact-dir>/seed_0x<HEX>.tape`. Two make
targets turn that failing seed (or a saved capsule) back into a live
repro, reusing `wire_sweep` itself — no separate harness or binary:

```bash
# Replay one exact seed deterministically (rebuilds wire_sweep if needed):
make simnet-repro SEED=0x2a

# Replay every seed_0x*.tape capsule saved under a directory (or a
# single .tape file) from a prior failing sweep:
make simnet-replay CAP=build/wire-sweep-output
```

`simnet-repro` is `wire_sweep --start=SEED --count=1 --verbose` — the
single-seed slice of the same sweep loop `make wire-sweep` runs.
`simnet-replay` (`tools/scripts/simnet_replay_capsule.sh`) recovers the
seed from each capsule's filename and calls `wire_sweep` the same way;
it does not need to parse the `.tape` file's contents because
`wire_sweep_run_one(seed)` is a pure function of the scalar seed (the
"bugs become 64-bit seeds" property, `docs/work/sim-phase2-plan.md`) —
the same seed always rebuilds the identical adversary archetype,
sub-case, and event stream. Both targets exit non-zero if the replayed
seed still reports a monitor failure.

## Phase 2

The phase-2 roadmap is `docs/work/sim-phase2-plan.md` on the follow-up branch.
The expected simulator extensions are:

- Sapling post-activation state for shielded memo and Sapling transaction tests.
- Mempool and timelock support for HTLC redeem/refund settlement.
- Token-validity projection for ZSLP balance, baton, and burn semantics.
- Event-log integration for ZNAM expiry and renew semantics.
