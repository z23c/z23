# 04 — ZSLP token lifecycle in the simulator

Demonstrates the full ZSLP (SLP Type 1) token life cycle — GENESIS, SEND,
MINT — entirely inside the deterministic RAM-only simulator. Each step
encodes an OP_RETURN payload with the real `slp_build_*` encoders, carries it
on an ordinary transparent transaction through a real block via
`connect_block()`, folds the result into the `zslp_tokens` /
`zslp_transfers` projection with `explorer_index_apply_slp`, and finally
parses every OP_RETURN back with `slp_parse` to show the wire bytes alone
carry the whole story.

## Build and run

```bash
make -C examples && ./examples/bin/04_zslp_token
```

The example is a standalone C23 program (`docs/examples/04_zslp_token.c`) built
with `-DZCL_TESTING` against the same `-I` include set as the main binary
(see the root `Makefile`'s `APP_INCLUDES`/`LIB_INCLUDES`/etc.). It is fully
deterministic — fixed seeds/values everywhere, no wall clock, no network —
so every run produces byte-identical output.

## Expected output sketch

```
=== 04_zslp_token: GENESIS -> SEND -> MINT, built and parsed ===

[1/5] init simnet + fund a transparent input to spend GENESIS from...
      tip height 200, funding coin ready (900000 zats)

[2/5] GENESIS: create token "SIM" with 1000 initial units...
      block accepted at height 201; token_id = genesis txid
      projection: ticker=SIM name="Simnet Token" total_minted=1000

[3/5] SEND: split the 1000 units into 250 + 750...
      block accepted at height 202; projection now has 3 transfer row(s)

[4/5] MINT: baton issues 125 additional units...
      block accepted at height 203; total_minted (GENESIS-only field) still reads 1000; MINT recorded as a transfer row of 125 units

[5/5] parse every OP_RETURN back independently of the projection...
    parsed GENESIS  type=GENESIS ticker=SIM name="Simnet Token" initial_qty=1000
    parsed SEND     type=SEND outputs=2 qty[vout1]=250 qty[vout2]=750
    parsed MINT     type=MINT additional_qty=125

=== SUCCESS: GENESIS(1000) -> SEND(250+750) -> MINT(+125 recorded as
a transfer row, total_minted stays a GENESIS-only 1000), verified via both
the chain projection and independent parse ===
```

Exact heights depend on `simnet`'s coinbase-maturity mechanics (each
`simnet_spend` mints at the height satisfying `COINBASE_MATURITY`); the
token math and the projection/parse content are the invariant part.

**Projection gap, shown on purpose:** `explorer_index_apply_slp()`
(`contexts/market/models/src/explorer_index_zslp.c`) records a MINT as a
`zslp_transfers` row (same shape as a SEND), but does **not** add the
minted quantity back into the token's stored `total_minted` column — that
field is written once, at GENESIS, and never updated again. So
`db_zslp_token_find()->total_minted` reads 1000 both before and after the
MINT step; the `+125` is only visible as a `SLP_TX_MINT` transfer row. The
example asserts the real behavior (the transfer row), not the total a
learner might otherwise expect.

## Key APIs used

| File | Function |
|------|----------|
| `engine/modules/sim/include/sim/simnet.h` | `simnet_init`, `simnet_mint_coinbase`, `simnet_spend`, `simnet_mint_txs`, `simnet_tip_height`, `simnet_free` |
| `contexts/market/modules/zslp/include/zslp/slp.h` | `slp_build_genesis`, `slp_build_mint`, `slp_build_send`, `slp_parse`, `struct slp_message` |
| `contexts/explorer/models/include/models/explorer_index.h` | `explorer_index_apply_slp` — folds one parsed SLP message into the `zslp_tokens`/`zslp_transfers` projection given the carrying transaction and block height |
| `contexts/market/models/include/models/zslp.h` | `db_zslp_token_find`, `db_zslp_transfer_list_by_token`, `struct db_zslp_token_info`, `struct db_zslp_transfer_info` |
| `engine/models/include/models/database.h` | `node_db_open`, `node_db_close` (in-memory `:memory:` projection DB) |
| `core/modules/primitives/include/primitives/transaction.h` | `transaction_init`, `transaction_alloc`, `transaction_compute_hash`, `transaction_free` |

The token OP_RETURN builder/carrier-tx pattern and the wire-order byte
reversal for `token_id` (big-endian on the wire, little-endian in
`struct uint256`) mirror `tests/harness/src/test_simnet.c` section 6 (search for
`slp_build_genesis` there) — that file is the ground-truth reference this
example was built from.

## Production counterpart

There is no dedicated `wallet_slp_send` — a real ZSLP transaction is built
the same way (an OP_RETURN vout[0] from `slp_build_genesis`/`mint`/`send`,
plus ordinary transparent value outputs) and submitted through the normal
transparent send path in `contexts/wallet/controllers/src/wallet_controller.c`. The read
side in this example — `slp_parse` + `explorer_index_apply_slp` — is the
literal production path: a live node's forward-sync indexer calls the same
two functions from `index_op_return`
(`contexts/explorer/models/src/explorer_index.c`, `contexts/market/models/src/explorer_index_zslp.c`)
for every OP_RETURN in every synced block, and
`contexts/market/controllers/src/zslp_controller.c` (plus `z23 app tokens list`)
read the resulting `zslp_tokens`/`zslp_transfers` rows back for callers.
