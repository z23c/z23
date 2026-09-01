# 07 — Multi-node cluster convergence (reorg)

## What it demonstrates

`docs/examples/07_cluster_reorg.c` runs two independent simulated nodes in one
process via `simnet_cluster` (`engine/modules/sim/include/sim/simnet_cluster.h`). Each
node mints its own branch in isolation (a simulated network partition) —
node 0 a 3-block branch, node 1 a 6-block branch — then both branches are
broadcast and delivered into the cluster. Delivery drives the real
`disconnect_block()` / `connect_block()` reorg path: node 0 unwinds its
3-block branch and adopts node 1's longer branch. The example asserts both
nodes end on the identical tip hash AND an identical UTXO-set digest
(`struct utxo_commitment`, an XOR accumulator over every live coin) —
proof the reorg re-derived the same coin set the winning chain would have
produced built alone, not just moved a tip pointer.

## Build and run

```bash
make -C examples && ./examples/bin/07_cluster_reorg
```

Deterministic: seeded with a fixed `uint64_t` (`CLUSTER_SEED =
0xC10A00000000A007ULL`) passed to `simnet_cluster_init`, so output is
byte-identical run to run.

## Expected output sketch

```
=== 07_cluster_reorg: 2-node partition + convergence ===

[1/5] initializing 2-node simnet_cluster (seed=0xC10A00000000A007)...
[2/5] partitioned mining: node 0 mints a 3-block losing branch, node 1 mints a 6-block winning branch...
    node0 losing tip:  <64-hex-char hash>
    node1 winning tip: <64-hex-char hash>
[3/5] broadcasting both branches into the cluster...
[4/5] delivering pending blocks (this drives disconnect_block on node 0's losing branch + connect_block for node 1's winning branch)...
[5/5] verifying both nodes converged to the same tip + coins...
    node0 final tip:   <hash, equal to node1 winning tip>
    node1 final tip:   <hash, equal to node0 final tip>
    node0 utxo count:  N
    node1 utxo count:  N

=== SUCCESS: node 0 reorged off its 3-block branch onto node 1's 6-block branch via
disconnect_block/connect_block; both nodes now share tip hash + identical
UTXO digest ===
```

Exit code 0 on success; nonzero with a `FAIL:` message on stderr if any
step or the final convergence check fails.

## Key APIs used

| File | Symbol |
|------|--------|
| `engine/modules/sim/include/sim/simnet_cluster.h` | `simnet_cluster_init`, `simnet_cluster_free` |
| `engine/modules/sim/include/sim/simnet_cluster.h` | `simnet_cluster_mint_on` |
| `engine/modules/sim/include/sim/simnet_cluster.h` | `simnet_cluster_broadcast` |
| `engine/modules/sim/include/sim/simnet_cluster.h` | `simnet_cluster_deliver_pending` |
| `engine/modules/sim/include/sim/simnet_cluster.h` | `simnet_cluster_tip_hash`, `simnet_cluster_coins_digest` |
| `core/modules/coins/include/coins/utxo_commitment.h` | `struct utxo_commitment`, `utxo_commitment_equal` |
| `core/math/include/core/uint256.h` | `struct uint256`, `uint256_eq`, `uint256_get_hex` |

Underneath `simnet_cluster_deliver_pending`, the reorg replay itself lives in
`engine/modules/sim/src/simnet_chain.c`: it calls `disconnect_block()` in reverse order
to unwind the losing branch, then `connect_block()` forward to apply the
winning branch — the same pair a live node calls. **Both live in
`core/modules/validation/src/connect_block.c`**; there is no `disconnect_block.c` under
any prefix.

## Production counterpart

The equivalent live-node machinery:

- `find_most_work_chain()` — `core/modules/validation/src/process_block_core.c` — picks
  the best-work tip across all known block-index entries. It is a thin wrapper
  over `select_most_work_eligible()` in `core/modules/validation/src/chainstate.c`,
  which holds the actual selection rule (including the refuse-below-tip guard).
  There is **no** `activate_best_chain()` in this tree — the disconnect/connect
  walk is driven by the reducer stage below, not by a Bitcoin-Core-named
  activation function.
- `connect_block()` / `disconnect_block()` — both in
  `core/modules/validation/src/connect_block.c`.
- `engine/jobs/src/utxo_apply_delta_reorg.c` — the reducer-side job that applies
  a block-index reorg to the on-disk `coins_kv` authority table (the
  persistent-storage analogue of this example's in-RAM UTXO digest).
- `z23 ops timeline` — inspect recent reorg events a live node has
  actually processed.

See also: `docs/SIMULATOR.md` (simulator model), `tests/harness/src/test_simnet_cluster.c`
(the ground-truth test this example's API usage is derived from).
