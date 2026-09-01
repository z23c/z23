# Cookbook 01 — Mint and Spend

**What it demonstrates.** The deterministic simulator's hello world: initialize
an in-RAM chain harness (`struct simnet`), mint a coinbase to a deterministic
P2PKH wallet, mine 100 filler blocks to clear the real `COINBASE_MATURITY`
predicate, spend the matured coinbase to a new output, and assert the old
UTXO is gone and the new one is present. Every mint is driven through the
REAL consensus validator (`connect_block()`) — the only things skipped are
proof-of-work and expensive script checks, via the same synthetic-checkpoint
mechanism the test suite uses. Nothing here touches disk, a live datadir, or
real funds.

## Build and run

```bash
make -C examples && ./examples/bin/01_mint_and_spend
```

(The example source lives at `docs/examples/01_mint_and_spend.c`. It compiles with
`-DZCL_TESTING` and the standard `lib/*/include` module include paths — see
the root `Makefile`'s `LIB_INCLUDES`/`LIB_MODULES` for the exact flag set the
integrator's `docs/examples/Makefile` should reuse.)

## Expected output (sketch)

```
=== 01_mint_and_spend: the simnet hello world ===
[1/4] initializing simnet (in-RAM chain, no disk, no real PoW)...
      base tip height = 99
      deterministic wallet address: <fixed P2PKH address for seed 0xC0FFEE1234>
[2/4] minting a coinbase that pays the wallet's script...
      tip advanced to height 100; coinbase txid recorded
[3/4] mining 100 filler blocks to clear COINBASE_MATURITY (=100)...
      tip is now height 200 (coinbase matured at 100 confirmations)
[4/4] spending the matured coinbase to a new output...
      spent coinbase consumed:  yes
      new UTXO present in view:  yes
      new UTXO value:            900000 zats

=== SUCCESS: minted a coinbase, matured it past COINBASE_MATURITY, spent it, and verified the UTXO-set fold — all through the real validator ===
```

Because a fixed `seed_tape` seeds both the wallet's keypair RNG and the
virtual block clock, every field above (address, txids not shown, heights)
is byte-identical on every run — that's the "every bug is a 64-bit seed"
property the whole simulator is built around.

## Key APIs used

| File | Function | Role |
|---|---|---|
| `engine/modules/sim/include/sim/seed_tape.h` | `seed_tape_open`, `seed_tape_install`, `seed_tape_uninstall`, `seed_tape_close` | Deterministic RNG + virtual clock the wallet keypair and block timestamps are drawn from |
| `engine/modules/sim/include/sim/simnet.h` | `simnet_init`, `simnet_free`, `simnet_use_seed_tape`, `simnet_tip_height` | Own/tear down the in-RAM chain harness; bind the deterministic clock |
| `engine/modules/sim/include/sim/simnet.h` | `simnet_mint_coinbase_to` | Mint a coinbase block paying an explicit script through `connect_block()` |
| `engine/modules/sim/include/sim/simnet.h` | `simnet_mint_to_height` | Mine empty filler blocks up to a target height (used here to clear coinbase maturity) |
| `engine/modules/sim/include/sim/simnet.h` | `simnet_spend` | Spend a coin at `txid:vout` to a new output, at a height that satisfies `COINBASE_MATURITY` |
| `engine/modules/sim/include/sim/simnet.h` | `simnet_coin_exists`, `simnet_coin_value` | Query the live in-RAM UTXO view — the same fold `coins_view_cache` performs on a real node |
| `engine/modules/sim/include/sim/simnet_wallet.h` | `simnet_wallet_create`, `simnet_wallet_address`, `simnet_wallet_script`, `simnet_wallet_free` | Deterministic P2PKH wallet toolkit for the sim |
| `core/params/include/consensus/consensus.h` | `COINBASE_MATURITY` (=100) | The real consensus constant driving step 3 |

## Production counterpart

The example's steps map onto real node code as:

- **Mint a coinbase** → the miner's block-template assembly (`engine/jobs/`) followed by the same `connect_block()` in `core/modules/validation`, driven live by the `utxo_apply` reducer stage (`engine/jobs/src/utxo_apply_stage.c`).
- **Coinbase maturity** → `core/params/include/consensus/consensus.h` (`COINBASE_MATURITY`), enforced inside `connect_block()` for every real block, not just the sim.
- **Spend the coin** → `wallet_create_transaction()` / `wallet_create_transaction_multi()` (`contexts/wallet/modules/wallet/include/wallet/wallet.h`) followed by `wallet_commit_transaction()`, surfaced through `z23 rpc sendtoaddress` on a live node.
- **UTXO existence/value query** → `coins_view_cache_have_coins()` and friends in `core/modules/coins/include/coins/coins_view.h` over the real on-disk `coins_kv` table, or `z23 core wallet utxo list` / `z23 core chain transaction get` at the command layer.

## See also

- `docs/SIMULATOR.md` — the simulator model overview.
- `docs/SIMULATOR_TXNS.md` — the transaction toolkit (wallets, fees, mempool, HTLCs) built on top of the primitives used here.
- `tests/harness/src/test_simnet.c` (sections 1-2) — the ground-truth test this example is adapted from.
