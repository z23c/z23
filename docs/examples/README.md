# z23 teaching examples

Eleven small, standalone C23 programs that each exercise a real slice of the
node — the same `engine/modules/sim`, `core/modules/validation`, `contexts/wallet/modules/wallet`, `core/modules/script`,
`contexts/naming/modules/znam`, `contexts/market/modules/zslp`, `core/modules/net` code a live node runs, driven through the
deterministic simulator (`engine/modules/sim/include/sim/simnet.h` and friends) instead
of a live chain. No disk, no real proof-of-work, no live funds, no wall
clock, no network — but genuine consensus validation (`connect_block()`), a
real projection layer, and a real P2P message processor.

## 30-second quickstart

```bash
make -C examples run
```

One command. Zero setup, zero parameters, no environment variables, no
config files. It builds all 11 programs and runs them in order, each
printing a one-line banner, numbered `[step/N]` progress lines in plain
task language, and a closing `=== SUCCESS: ... ===` line — then stops
immediately (naming the offender) if anything goes red. A clean run ends
with:

```
All 11 examples ran successfully.
```

Want just one? `make -C examples run-04_zslp_token` (any name from the
table below works as `run-<name>`). Want the friendly map of what's here
without running anything long? Bare `make -C examples` builds everything
and prints a one-screen index.

Each example is paired with a walkthrough doc under
[`docs/cookbook/`](../cookbook/) that explains the mental model, shows
expected output, and maps every function called back to its production
counterpart.

## Build and run

```bash
make -C examples                    # build every example into examples/bin/,
                                     # then print a one-screen usage table
make -C examples run                # build, then run every one in order;
                                     # stops at the first failure, naming it
make -C examples run-<name>         # build (if needed) and run just one,
                                     # e.g. run-04_zslp_token
make -C examples clean              # remove examples/bin/ and examples/obj/
```

The examples Makefile is standalone (see [`Makefile`](./Makefile) for how it
reuses the root build's object tree and compile/link flags without
duplicating or drifting from them) — it does not modify the root
`../Makefile`. Building it will, on first run, build (or reuse) the root's
`test_parallel_fast` object tree via `make -C .. test_parallel_fast`.

## The examples

| # | Program | What it teaches | Run it |
|---|---------|------------------|--------|
| 01 | [`01_mint_and_spend.c`](./01_mint_and_spend.c) | The simulator "hello world": mint a coinbase to a deterministic wallet, mine past `COINBASE_MATURITY` (100 blocks), spend it, and verify the UTXO-set fold. | `make -C examples run-01_mint_and_spend` |
| 02 | [`02_multi_io_p2sh.c`](./02_multi_io_p2sh.c) | Two transaction shapes a wallet must build: a multi-input/multi-output transparent send, and a P2SH HTLC fund + reveal-the-secret redeem. | `make -C examples run-02_multi_io_p2sh` |
| 03 | [`03_op_return_overlay.c`](./03_op_return_overlay.c) | `OP_RETURN` as a provably-unspendable data carrier — permanent in the block, pruned from the live UTXO set — and the Lokad-ID-tagged-payload pattern every overlay protocol (ZNAM, ZSLP) builds on. | `make -C examples run-03_op_return_overlay` |
| 04 | [`04_zslp_token.c`](./04_zslp_token.c) | The ZSLP (SLP Type 1) token overlay end to end: GENESIS -> SEND -> MINT, folded into the `zslp_tokens`/`zslp_transfers` projection and re-parsed independently from the wire bytes. Also shows a real projection gap (MINT doesn't update `total_minted`). | `make -C examples run-04_zslp_token` |
| 05 | [`05_znam_names.c`](./05_znam_names.c) | The ZNAM on-chain name registry: REGISTER -> owner UPDATE -> SET_TEXT, then a non-owner forged UPDATE that parses as valid wire data but is discarded by the projection's owner-address check. | `make -C examples run-05_znam_names` |
| 06 | [`06_htlc_swap.c`](./06_htlc_swap.c) | The HTLC (Hash Time-Locked Contract) atomic-swap primitive: both settlement paths — redeem (secret-holder claims) and refund (funder reclaims after CLTV timeout), including the pre-timeout rejection. | `make -C examples run-06_htlc_swap` |
| 07 | [`07_cluster_reorg.c`](./07_cluster_reorg.c) | Multi-node convergence: two independent simulated chains disagree, then a real `disconnect_block`/`connect_block` reorg brings both nodes to the same tip hash and UTXO digest. | `make -C examples run-07_cluster_reorg` |
| 08 | [`08_byzantine_blocks.c`](./08_byzantine_blocks.c) | Four ways a block/header can be adversarially malformed (bad merkle root, over-subsidy coinbase, negative output, invalid PoW) — each rejected with a named reason, tip unchanged, chain still live afterward. | `make -C examples run-08_byzantine_blocks` |
| 09 | [`09_seed_replay.c`](./09_seed_replay.c) | Determinism as a debugging tool: a `seed_tape_t` records RNG draws, clock advances, and injected events; both a plain `.bin` snapshot and a postmortem crash capsule replay the exact same continuation. | `make -C examples run-09_seed_replay` |
| 10 | [`10_wire_adversaries.c`](./10_wire_adversaries.c) | The in-memory P2P wire harness under attack: an honest peer plus a flooding adversary, a partition of the honest link with no silent halt, then heal and recover. | `make -C examples run-10_wire_adversaries` |
| 11 | [`11_collectible_market.c`](./11_collectible_market.c) | The full digital-collectible marketplace lifecycle: mint a one-of-one ZSLP deed hash-bound to real artwork bytes, claim a permanent ZNAM storefront, sell one deed by direct payment and two more through a trustless HTLC escrow (one redeemed, one refunded after timeout). | `make -C examples run-11_collectible_market` |

Every example prints a one-line banner, numbered `[step/N]` progress lines,
and a closing `=== SUCCESS: ... ===` line, and exits 0 on success (the same
convention `make -C examples run` checks). Two examples are intentionally
*not* byte-for-byte reproducible across runs, and say so in their own header
comments and console output:

- **06** and **11** — the HTLC secret(s) come from the real OS CSPRNG
  (`GetRandBytes`), not the seed tape's mockable RNG hook, because genuine
  cryptographic secret material must never be routed through a replayable
  test hook, even in a demo. The surrounding chain mechanics (heights, fees,
  tx sizes, addresses) are still deterministic.
- **09** — its own point is snapshot/replay of a seed tape, so it creates a
  fresh `mkdtemp()` scratch directory (and a PID-suffixed capsule filename)
  every run; the actual RNG continuation and event replay it demonstrates
  are still verified bit-for-bit inside the run itself.

## Zero setup, by design

Every example runs standalone with no external dependencies: no live
datadir, no network connection, no environment variables, no config or
params files. All ten deterministic examples produce byte-identical console
output (address, txids, heights, fees) on every run because they seed the
simulator's RNG and virtual clock from a single fixed 64-bit constant —
"every bug is a 64-bit seed." `make -C examples clean && make -C examples
run` from a fresh checkout is the whole recipe.

## Where to go next

- [`docs/cookbook/`](../cookbook/) — one walkthrough doc per example,
  with expected console output and a "Production counterpart" section
  mapping every simulator call back to the real node code path (or naming
  the gap, where one exists).
- [`docs/SIMULATOR.md`](../SIMULATOR.md) / [`docs/SIMULATOR_TXNS.md`](../SIMULATOR_TXNS.md) —
  the simulator's own design docs and transaction-shape coverage table.
- `tests/harness/src/test_simnet*.c` — the ground-truth test suite these
  examples are built from; when in doubt about an API's contract, that's
  the authoritative source.
- [`docs/CODEBASE_MAP.md`](../CODEBASE_MAP.md) — where things live in
  the wider node codebase.
