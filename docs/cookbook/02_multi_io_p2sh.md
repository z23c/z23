# Cookbook 02 — Multi-input/multi-output tx + P2SH spend

**File:** `docs/examples/02_multi_io_p2sh.c`

## What it demonstrates

Builds two transaction shapes through the deterministic `simnet` harness
(`engine/modules/sim/`), which drives real transactions through the actual consensus
function `connect_block()` in RAM (no disk, no real PoW, no real funds):

1. A **multi-input, multi-output transparent transaction** — two separate
   matured coinbases are consolidated as inputs and split across two
   recipient outputs (plus a change output) in a single transaction.
2. A **P2SH spend** — fund a hash-time-locked contract (HTLC) script (the
   same 97-byte contract shape ZSWP atomic swaps use), then redeem it with
   the real "reveal secret + sign" scriptSig builder from `core/modules/script/src/htlc.c`.

Everything is deterministic (one fixed seed tape drives both the wallet
keys and the virtual block clock), so the printed txids/fees/sizes are
byte-identical on every run.

## Build / run

```bash
make -C examples && ./examples/bin/02_multi_io_p2sh
```

(The integrator's `docs/examples/Makefile` compiles with `-DZCL_TESTING` and the
project's standard `-I` include set — see the root `Makefile`'s
`APP_INCLUDES`/`LIB_INCLUDES`/etc. This file uses only public headers under
`lib/*/include`, so it needs no test-only symbols.)

## Expected output sketch

```
=== 02_multi_io_p2sh: multi-input/multi-output send + a P2SH HTLC fund/redeem ===
[1/4] minting two coinbases to alice (200 maturity blocks total)...
[2/4] building multi-input/multi-output transparent tx (2 inputs -> 2 recipients + change)...
    multi-input/multi-output    txid=<64 hex chars> fee=<n> zats size=<n> bytes
[3/4] funding a P2SH HTLC output (real 97-byte contract)...
    P2SH HTLC fund               txid=<64 hex chars> fee=<n> zats size=<n> bytes
[4/4] redeeming the P2SH HTLC (reveal secret)...
    P2SH HTLC redeem              txid=<64 hex chars> fee=<n> zats size=<n> bytes

tip height = <n>
=== SUCCESS: built, minted, and verified a multi-input/multi-output transparent send and a P2SH HTLC fund+redeem, all through connect_block() ===
```

Exact fee/size numbers are deterministic given the fixed seed and the
simnet catalog fee rate (`SIMNET_WALLET_DEFAULT_FEE_PER_K`, 10,000 zats/kB)
— see `docs/SIMULATOR_TXNS.md`'s transaction catalog table
for the shape-by-shape reference values measured by
`test_simnet_txkit.c` (multi-input consolidation: 164 bytes / 1640 zats;
P2SH HTLC fund: 162 bytes / 1620 zats; HTLC redeem: 325 bytes / 3250 zats
— this example's exact numbers may differ slightly because it uses a
2-recipient fan-out rather than the test's single-recipient consolidation).

## Key APIs used

| API | File | Purpose |
|---|---|---|
| `seed_tape_open` / `seed_tape_install` | `engine/modules/sim/include/sim/seed_tape.h` | deterministic RNG + virtual clock |
| `simnet_init` / `simnet_use_seed_tape` | `engine/modules/sim/include/sim/simnet.h` | RAM-only chain harness bound to the seed tape |
| `simnet_wallet_create` / `simnet_wallet_fund` | `engine/modules/sim/include/sim/simnet_wallet.h` | deterministic P2PKH wallet; mint + mature a coinbase |
| `simnet_wallet_send_many` | `engine/modules/sim/include/sim/simnet_wallet.h` | build/fee/enqueue a multi-recipient fan-out (multi-input when funded UTXOs don't cover one input) |
| `simnet_wallet_send` | `engine/modules/sim/include/sim/simnet_wallet.h` | build/fee/enqueue a spend to an arbitrary script (used to fund the P2SH output) |
| `simnet_mempool_add` / `simnet_mempool_mint` | `engine/modules/sim/include/sim/simnet_mempool.h` | admit a manually-built tx (the HTLC redeem) and mint the held FIFO set through `connect_block()` |
| `htlc_build_script` / `htlc_build_redeem_scriptsig` | `core/modules/script/include/script/htlc.h` | build the 97-byte HTLC contract and its redeem scriptSig (production code — this example calls the exact functions the node calls) |
| `script_id_from_script` / `script_for_p2sh` | `core/modules/script/include/script/standard.h` | wrap the HTLC contract as a P2SH scriptPubKey |
| `transaction_alloc` / `transaction_compute_hash` / `transaction_serialize_size` | `core/modules/primitives/include/primitives/transaction.h` | manual tx assembly for the redeem spend (no `simnet_wallet_*` wrapper exists for P2SH redemption — it's protocol-specific, not a generic wallet op) |

## Production counterpart

- Multi-input/multi-output send: `wallet_create_transaction_selected()` in
  `contexts/wallet/modules/wallet/include/wallet/wallet.h`, reached through the typed
  `vault intent plan` → `vault intent commit` lifecycle in
  `contexts/wallet/controllers/src/vault_intent_controller.c`. That path binds exact
  outputs, inputs, fee, wallet identity, genesis, tip, custody snapshot and
  expiry before broadcast. The legacy `sendmany` RPC remains a guarded
  compatibility surface, not the recommended developer API.
- P2SH HTLC fund + redeem: `core/modules/script/include/script/htlc.h`'s builders are already
  production code (this example calls the same functions the node calls).
  Swap state lives in `engine/controllers/src/swap_controller.c`
  (`swap_initiate`, `swap_participate`); on-chain broadcast/settlement of
  the redeem/refund path is still in flight — see the ZSWP rows of
  `docs/SIMULATOR.md`'s action-coverage matrix.

## Notes for the integrator

- No test-only (`#ifdef ZCL_TESTING`) symbols are used — every function
  called here is a public header under `lib/*/include`. `-DZCL_TESTING`
  is harmless to pass but not required for this file specifically.
- The example intentionally does not exercise the HTLC **refund** path
  (timelock-gated reclaim) or the mempool's same-batch chained-spend
  rejection — those negative/edge cases are covered in
  `tests/harness/src/test_simnet_txkit.c` and documented in
  `docs/SIMULATOR_TXNS.md`.
