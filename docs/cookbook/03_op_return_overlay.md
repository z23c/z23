# 03_op_return_overlay

What it demonstrates: an `OP_RETURN` output is a scriptPubKey whose first
byte is `OP_RETURN`, which consensus treats as provably unspendable — it is
never added to the live UTXO set, but the bytes pushed after it are
permanent inside the mined block. That one primitive (push bytes, pay a
normal fee, mine it) is the substrate every z23 overlay protocol
(ZNAM name registry, ZSLP tokens) builds on: they are just agreed-upon byte
layouts inside an OP_RETURN payload, tagged with a 4-byte "Lokad ID"
(`"ZNAM"` / `"SLP\0"`) so an indexer knows which protocol parsed the rest.

This example builds a pure data-carrier OP_RETURN transaction, reads the
payload back out of the actual queued transaction bytes *before* it is
mined, mines it, then proves the OP_RETURN vout is pruned from the UTXO set
while a sibling change output stays spendable. It finishes by pairing a
ZNAM-shaped payload with a real value transfer in one transaction — the
same shape a "register a name and pay a fee" transaction uses.

## Build / run

```bash
make -C examples && ./examples/bin/03_op_return_overlay
```

(If `examples/` has no `Makefile` yet in your checkout, compile directly:
`cc -std=c23 -O2 <the -I flags from the root Makefile's CFLAGS> \
docs/examples/03_op_return_overlay.c -o /tmp/03_op_return_overlay <link objects>`.)

## Expected output sketch

```
=== 03_op_return_overlay: OP_RETURN as a provably-unspendable data carrier ===
[1/4] minting a coinbase to alice, mining 100 blocks to maturity...
[2/4] building an OP_RETURN data carrier, reading the payload back BEFORE mining...
    recovered payload (12 bytes): "hello, chain"
    OP_RETURN data carrier      txid=<64 hex chars> fee=1030 zats size=103 bytes
[3/4] mining the carrier; confirming the OP_RETURN vout is pruned from the UTXO set while change is spendable...
    vout 0 (OP_RETURN) spendable=false; vout 1 (change) spendable=true value=<n> zats
[4/4] building a Lokad-tagged overlay payload ('ZNAM' + fields) alongside a real value transfer to bob...
    OP_RETURN + value (ZNAM-shaped) txid=<64 hex chars> fee=<n> zats size=<n> bytes

tip height = 102
=== SUCCESS: built OP_RETURN data carriers, read them back pre-mine, and verified them through connect_block() ===
```

Exact txids/fees/sizes are byte-identical run to run (fixed seed tape), and
match the measured `OP_RETURN data carrier` row (103 bytes, fee 1030 zats)
in `docs/SIMULATOR_TXNS.md`'s cost table.

## Key APIs used

- `engine/modules/sim/include/sim/seed_tape.h` — `seed_tape_open` / `seed_tape_install` / `seed_tape_close`: deterministic RNG + virtual clock so every run is byte-identical.
- `engine/modules/sim/include/sim/simnet.h` — `simnet_init`, `simnet_use_seed_tape`, `simnet_tip_height`, `simnet_coin_value`: the RAM-only harness that drives blocks through the real `connect_block()`.
- `engine/modules/sim/include/sim/simnet_wallet.h` — `simnet_wallet_create`, `simnet_wallet_fund`, `simnet_wallet_op_return`: wallet-level helpers that build, fee, and enqueue an OP_RETURN carrier (with an optional paired value output).
- `engine/modules/sim/include/sim/simnet_mempool.h` — `simnet_mempool_mint`: mints the FIFO-held queued transaction(s) into the next block.
- `engine/modules/sim/src/simnet_mempool.c` (behavior documented in the header) — `simnet_mempool_add` deep-copies an accepted tx into `struct simnet.mempool_txs`; this example reads `sim.mempool_txs[sim.mempool_count - 1]` directly to inspect the exact queued transaction before it is mined.
- `core/modules/script/include/script/script.h` — `script_get_op`: the generic script-walker used to parse the `OP_RETURN` opcode and its length-prefixed data push back out of a `scriptPubKey`; also `script_is_unspendable` (consensus definition of "provably unspendable").
- `core/modules/coins/include/coins/coins.h` — `coins_from_transaction` (doc comment): the function that actually skips OP_RETURN/unspendable outputs when building the UTXO record connect_block persists — this is *why* vout 0 disappears from `simnet_coin_value` after mining.

## Production counterpart

- Generic OP_RETURN + value transaction assembly: `wallet_create_transaction()` / `wallet_create_transaction_multi()` in `contexts/wallet/modules/wallet/include/wallet/wallet.h`.
- ZNAM (on-chain name registry) OP_RETURN encoding + commit: `rpc_name_register()` in `engine/controllers/src/name_controller.c`, using the field layout in `contexts/naming/modules/znam/include/znam/znam.h` (`ZNAM_LOKAD_BYTES = "ZNAM"`, `ZNAM_CMD_*` command bytes).
- ZSLP (token protocol) OP_RETURN encoding + commit: `zslp_command_commit_with_op_return()` in `contexts/market/services/include/services/zslp_command_service.h`, using the field layout in `contexts/market/modules/zslp/include/zslp/slp.h` (`SLP_LOKAD_BYTES = "SLP\0"`).

Both real protocols are read back the same way this example does: parse the
scriptPubKey with `script_get_op()`, check the Lokad ID, then decode the
protocol-specific fields.
