# 08 — Byzantine blocks: adversarial input rejected by real consensus

## What this demonstrates

A node accepts bytes from untrusted peers, so every block or header a peer
sends must pass through the same validator an honest block passes through —
there is no separate "attack detector." This example drives four distinct
malformed inputs (bad merkle root, over-subsidy coinbase, negative output
value, invalid PoW solution) through the real `connect_block()` / header
admission gates via the `simnet_byzantine` fixture library, and checks three
things per case: the block/header is rejected with a specific named reason,
the chain tip does not move, and an ordinary honest block minted immediately
afterward still connects — proving the rejection didn't corrupt or wedge
anything.

## Build and run

```bash
make -C examples && ./examples/bin/08_byzantine_blocks
```

(If your `examples/` build harness is not yet wired for this file, it
compiles standalone with the library's public headers; see "Key APIs" below
for the include list an ad hoc build needs.)

## Expected output sketch

```
=== 08_byzantine_blocks: four ways a block/header can be adversarially malformed, each rejected by real consensus ===

[1/4] bad merkle root (bad_merkle)... OK
        reject_reason="bad-txnmrklroot" (expected "bad-txnmrklroot")
        blocker=simnet_byz.bad_merkle class=PERMANENT
        tip: 0 -> 0 (unchanged), honest block after: accepted

[2/4] over-subsidy coinbase (bad_cb_amount)... OK
        reject_reason="bad-cb-amount" (expected "bad-cb-amount")
        blocker=simnet_byz.bad_cb_amount class=PERMANENT
        tip: 0 -> 0 (unchanged), honest block after: accepted

[3/4] negative output value (negative_output)... OK
        reject_reason="bad-txns-vout-negative" (expected "bad-txns-vout-negative")
        blocker=simnet_byz.negative_output class=PERMANENT
        tip: 0 -> 0 (unchanged), honest block after: accepted

[4/4] invalid PoW solution (invalid_pow)... OK
        reject_reason="invalid-solution" (expected "invalid-solution")
        blocker=simnet_byz.invalid_pow class=PERMANENT
        tip: 0 -> 0 (unchanged), honest block after: accepted

=== SUCCESS: all 4 byzantine classes were rejected with the correct named reason, left
the tip unchanged, and did not stop an honest block from connecting right
after ===
```

Exit code 0 on success; nonzero with a `FAILED:` line on stderr if any case
did not reject, rejected with the wrong reason, moved the tip, or blocked
the following honest mint.

## Key APIs used

| File | Function | Role |
|------|----------|------|
| `engine/modules/sim/include/sim/simnet_byzantine.h` | `simnet_byzantine_run_connect_case` | Tier-1 case: builds one malformed block for a class and drives it through `connect_block()` on a fresh in-RAM chain. |
| `engine/modules/sim/include/sim/simnet_byzantine.h` | `simnet_byzantine_run_header_case` | Tier-2 case: builds one malformed header and drives it through `check_block_header()` / `contextual_check_block_header()` (before any body is fetched). |
| `engine/modules/sim/include/sim/simnet_byzantine.h` | `simnet_byzantine_class_tier`, `simnet_byzantine_class_name`, `simnet_byzantine_expected_reason` | Metadata per `enum simnet_byzantine_class` — which gate applies and what reason string a correct rejection must carry. |
| `engine/modules/sim/src/simnet_byzantine.c` | `simnet_byzantine_observation_ok` | The invariant this example re-derives independently: rejected, non-empty reason, tip unchanged, and the follow-up honest mint succeeded. |
| `platform/modules/util/include/util/blocker.h` | `blocker_module_init`, `blocker_reset_for_testing`, `blocker_class_name` | Every rejection in this example becomes a typed `BLOCKER_PERMANENT` record, the same primitive a live node exposes via `z23 ops state --subsystem=blocker` and `z23 core sync blockers`. |

Reference test (ground truth for expected reason strings and blocker
classes per class): `tests/harness/src/test_simnet_byzantine.c`.

## Byzantine classes covered here

| Class | Tier | Gate | Reject reason |
|-------|------|------|----------------|
| `SIMNET_BYZ_BAD_MERKLE` | 1 | `connect_block()` | `bad-txnmrklroot` |
| `SIMNET_BYZ_BAD_CB_AMOUNT` | 1 | `connect_block()` | `bad-cb-amount` |
| `SIMNET_BYZ_NEGATIVE_OUTPUT` | 1 | `connect_block()` | `bad-txns-vout-negative` |
| `SIMNET_BYZ_INVALID_POW` | 2 | `check_block_header()` | `invalid-solution` |

`simnet_byzantine.h` defines seven more classes (BIP30 duplicate txid,
missing spend, immature coinbase spend, overflow output, oversize vtx, bad
diffbits, bad timestamp) not exercised in this example — see the header's
`enum simnet_byzantine_class` and `docs/SIMULATOR.md` for the full matrix.

## Production counterpart

The same functions this example calls directly are reached from real P2P
messages in production:

- `core/modules/validation/include/validation/connect_block.h` (`connect_block()`) —
  called from `engine/controllers/src/sync_controller_blocks.c` while advancing
  the chain over the real, disk-backed `coins_view`.
- `core/modules/validation/include/validation/check_block.h`
  (`check_block_header()` / `contextual_check_block_header()`) — called from
  `core/modules/validation/src/accept_block_header.c` and
  `core/modules/validation/src/process_block_contextual_header.c` the moment a
  `headers` P2P message arrives, before the block body is even requested.
- `platform/modules/util/include/util/blocker.h` (`blocker_set()`) — turns a production
  reject into a durable, typed, observable record instead of a log line that
  scrolls away.
