# 05 — ZNAM name registry lifecycle in the simulator

Demonstrates the ZCL Names (ZNAM) on-chain registry — REGISTER, owner UPDATE,
and SET_TEXT — entirely inside the deterministic RAM-only simulator, then a
negative case: a wallet that never owned the name posts a well-formed
UPDATE funded by its own coin, and the projection's owner-address check
silently discards it (the name's target does not change). Each step encodes
an OP_RETURN payload with the real `znam_build_*` encoders, carries it on an
ordinary transparent transaction through a real block via `connect_block()`,
and folds the result into the `znam_names`/`znam_text_records` projection
with `explorer_index_block`.

## Build and run

```bash
make -C examples && ./examples/bin/05_znam_names
```

The example is a standalone C23 program (`docs/examples/05_znam_names.c`) built
with `-DZCL_TESTING` against the same `-I` include set as the main binary
(see the root `Makefile`'s `APP_INCLUDES`/`LIB_INCLUDES`/etc.). It is fully
deterministic — fixed seeds/values/names everywhere, no wall clock, no
network — so every run produces byte-identical output.

## Expected output sketch

```
=== 05_znam_names: REGISTER -> UPDATE -> SET_TEXT, then a non-owner UPDATE that the projection discards ===

[1/4] minting a coinbase and 100 blocks to reach coinbase maturity, then funding alice + mallory from it...
      block accepted at height 201; alice vout=0 (400000 zats), mallory vout=1 (400000 zats)

[2/4] REGISTER "alice-home" -> t1exampletarget, owned by whoever funds the tx (alice)...
      block accepted at height 202; owner=t1... target=t1exampletarget

[3/4] owner UPDATE (alice) repoints the name, then SET_TEXT attaches an email record...
      block accepted at height 203; target now t1updatedtarget (owner unchanged)
      block accepted at height 204; text[email]=alice@example.test

[4/4] NEGATIVE: mallory (never the owner) posts a well-formed UPDATE for "alice-home", funded by HER OWN coin...
      block accepted at height 205; znam_parse decodes it as a valid UPDATE("alice-home" -> t1stolentarget) — the wire format has no owner field
      projection after fold: target=t1updatedtarget owner=t1... — the forged block parsed but was NOT applied (owner-address mismatch at the authorization layer)

=== SUCCESS: REGISTER -> UPDATE -> SET_TEXT applied by the true
owner; a non-owner UPDATE parsed as valid ZNAM wire data but was rejected by
the projection's owner-address check ===
```

Exact heights depend on `simnet`'s coinbase-maturity mechanics
(`simnet_mint_to_height` walks to height 200 before the funding tx mints);
the owner address string and the accept/reject outcome are the invariant
part.

## Key APIs used

| File | Function |
|------|----------|
| `engine/modules/sim/include/sim/simnet.h` | `simnet_init`, `simnet_mint_coinbase`, `simnet_mint_to_height`, `simnet_mint_txs`, `simnet_tip_height`, `simnet_free` |
| `contexts/naming/modules/znam/include/znam/znam.h` | `znam_build_register`, `znam_build_update`, `znam_build_set_text`, `znam_parse`, `struct znam_message` |
| `contexts/explorer/models/include/models/explorer_index.h` | `explorer_index_block` — the per-block hook that dispatches every OP_RETURN through `znam_parse` + `apply_znam` (`contexts/explorer/models/src/explorer_index.c`) |
| `contexts/naming/models/include/models/znam.h` | `db_znam_find`, `db_znam_text_get`, `struct znam_entry` |
| `engine/models/include/models/database.h` | `node_db_open`, `node_db_close` (in-memory `:memory:` projection DB) |
| `core/modules/primitives/include/primitives/transaction.h` | `transaction_init`, `transaction_alloc`, `transaction_compute_hash`, `transaction_free` |

The funding/OP_RETURN transaction-builder pattern, and the owner-authorized
UPDATE vs. non-owner UPDATE contrast, mirror `tests/harness/src/test_simnet.c`
section 7 (search for `znam_build_register` there) — that file is the
ground-truth reference this example was built from. The owner-authorization
mechanism itself is real, not simulated: `apply_znam` derives the
authorizing address from `tx->vin[0].prevout` (`znam_owner_address` in
`contexts/explorer/models/src/explorer_index.c`) and compares it against the name's stored
`owner_address` — it is not a field carried inside the OP_RETURN message, so
`znam_parse` alone cannot tell a legitimate UPDATE from a forged one; only
the projection's address check can.

## Production counterpart

There is no dedicated `wallet_name_register` entry point — a real ZNAM
transaction is built the same way this example does it (an OP_RETURN
vout[0] from `znam_build_register`/`update`/`transfer`/`renew`/
`set_record`/`set_text`, plus an ordinary transparent change output) and
submitted through the normal transparent send path in
`contexts/wallet/controllers/src/wallet_controller.c`. The RPC-facing entry point is
`name_register` and its sibling handlers in
`engine/controllers/src/name_controller.c` (also reachable via the
`z23 rpc name_register`). The read side in this example —
`explorer_index_block` → `apply_znam` — is the literal production path: a
live node's forward-sync indexer calls it for every block, and the
resulting `znam_names`/`znam_text_records`/`znam_addr_records` rows are
exactly what `name_resolve` (`name_controller.c`) and the
`z23 app names resolve` and `z23 app names list` — reads back for callers.
