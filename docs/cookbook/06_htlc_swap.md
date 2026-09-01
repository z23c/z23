# 06 — HTLC atomic-swap contract lifecycle

## What it demonstrates

Builds an HTLC (Hash Time-Locked Contract) — the cross-chain atomic-swap
primitive shared with ZCL/BTC/LTC/DOGE (same 97-byte contract shape as
dcrdex) — entirely inside the deterministic `simnet` harness. It funds a
P2SH HTLC output and proves both settlement paths through the real
`connect_block()` path: the redeem path (secret-holder claims, then a
counterparty extracts the secret from the settled scriptSig) and the
refund path (original funder reclaims after an absolute-height timeout,
with a correct rejection before the timeout).

## Build / run

```bash
make -C examples && ./examples/bin/06_htlc_swap
```

(The example source lives at `docs/examples/06_htlc_swap.c`; the harness
compiles it against the library sources it calls into — sim, script,
core, crypto — the same as any other example in this directory.)

## Expected output sketch

```
=== 06_htlc_swap: HTLC atomic-swap contract lifecycle ===

[1/4] funding alice + maturing coinbase (100 blocks)...
      alice balance = 400000 zatoshi at height 200

[2/4] leg A: fund an HTLC redeemable by bob, then redeem it...
      secret   = a1b2c3d4...(32 bytes, from htlc_generate_secret; real CSPRNG, so this DIFFERS on every run — see file header)
      HTLC funded: txid:0 holds 180000 zatoshi behind the P2SH contract
      redeem accepted+mined at height 202 — bob now holds the coin
      htlc_extract_secret recovered the exact secret from the on-chain scriptSig

[3/4] leg B: fund an HTLC, let the timeout pass, refund it...
      refund before height 205 correctly rejected (nonfinal)
      refund accepted+mined at height 206 — alice reclaimed the coin

[4/4] both HTLC settlement paths proved through real connect_block()
      redeem path : secret-holder claims any time before or after timeout
      refund path : original funder reclaims only after the CLTV height

=== SUCCESS: HTLC atomic-swap lifecycle settled both ways — fund/redeem (secret-holder claims) and fund/refund (funder reclaims after CLTV timeout) ===
```

Heights are deterministic given the fixed seed (`0x06874C5350`) and
`simnet_init`'s fixed base tip — but the exact 32 HTLC secret bytes are
**not**: `htlc_generate_secret()` (`core/modules/script/src/htlc.c`) draws from the
real OS CSPRNG (`GetRandBytes`), not the seed tape's mockable `rng_u64()`
hook, by design — genuine cryptographic secret material must never go
through a replayable test hook, even in a demo. So the secret differs on
every run while everything else (heights, fees, tx sizes, wallet
addresses) stays byte-identical. The example only asserts success/failure
of each step, never the secret's exact bytes.

## Key APIs used

| API | File |
|---|---|
| `htlc_generate_secret`, `htlc_build_script`, `htlc_p2sh_address` (via `script_id_from_script`/`script_for_p2sh`), `htlc_extract_secret`, `htlc_build_redeem_scriptsig`, `htlc_build_refund_scriptsig` | `core/modules/script/include/script/htlc.h`, `core/modules/script/src/htlc.c` |
| `seed_tape_open` / `seed_tape_install` / `seed_tape_uninstall` / `seed_tape_close` | `engine/modules/sim/include/sim/seed_tape.h` |
| `simnet_init`, `simnet_use_seed_tape`, `simnet_tip_height`, `simnet_mint_to_height`, `simnet_coin_value`, `simnet_free` | `engine/modules/sim/include/sim/simnet.h` |
| `simnet_wallet_create`, `simnet_wallet_fund`, `simnet_wallet_send`, `simnet_wallet_balance`, `simnet_wallet_script`, `simnet_wallet_default_fee_rate` | `engine/modules/sim/include/sim/simnet_wallet.h` |
| `simnet_mempool_add`, `simnet_mempool_mint`, `simnet_mempool_reject_name`, `SIMNET_MEMPOOL_REJECT_NONFINAL` | `engine/modules/sim/include/sim/simnet_mempool.h` |
| `transaction_init`, `transaction_alloc`, `transaction_compute_hash`, `transaction_serialize_size`, `transaction_free`, `fee_rate_get_fee` | `core/modules/primitives/include/primitives/transaction.h`, `core/modules/core/include/core/amount.h` |

Ground-truth reference for this exact flow: `tests/harness/src/test_simnet_txkit.c`
(`txk_htlc_scripts` / `txk_build_htlc_spend`), `tests/harness/src/test_htlc.c`
(unit coverage of each `htlc_*` builder), and
`docs/SIMULATOR_TXNS.md` ("test a timelocked contract").

## Production counterpart

The script-level functions (`htlc_build_script`, `htlc_p2sh_address`,
`htlc_generate_secret`, `htlc_extract_secret`,
`htlc_build_redeem_scriptsig`, `htlc_build_refund_scriptsig` in
`core/modules/script/src/htlc.c`) are the exact same functions a live node calls —
nothing in this example is simulator-only.

The RPC/controller glue is `rpc_swap_initiate` / `rpc_swap_participate` in
`engine/controllers/src/swap_controller.c` (also exposed as the
`z23 rpc swap_initiate` / `z23 rpc swap_participate`), which build the
HTLC params, P2SH script, and local swap-state record from an
initiate/participate RPC call.

**Gap versus this example:** as of this writing there is no node-broadcast
redeem/refund/settlement RPC path — an operator funds/redeems/refunds the
resulting P2SH address by hand (e.g. raw-transaction RPCs via `z23 rpc`),
the same way this example builds the redeem/refund transactions directly.
See `docs/SIMULATOR.md`'s HTLC/swap rows (Class B/C) for the current
coverage boundary.
