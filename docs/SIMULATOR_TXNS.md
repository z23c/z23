# Simulator Transaction Toolkit

`engine/modules/sim` now has a small transparent-transaction toolkit for deterministic
simnet tests. The harness still mints through the real `connect_block(...)`
path with `expensive_checks=false`, so transaction structure, values,
outpoints, scripts, finality, and coinbase maturity matter; PoW and script
execution do not.

Run the focused coverage:

```bash
make t ONLY=simnet_txkit
```

## API

- `simnet_use_seed_tape(s, tape)` binds an installed seed tape so block `nTime`, `GetAdjustedTime()`, and locktime finality advance together.
- `simnet_mint_coinbase_to(s, script, value, out_cb_txid)` mints one coinbase output to an explicit script and amount.
- `simnet_mint_to_height(s, h)` mints empty coinbase blocks until the tip reaches `h`.
- `simnet_mempool_add(s, tx, out)` validates a tx against the current sim chain view and appends it to the FIFO held set.
- `simnet_mempool_mint(s)` mints all held mempool txs in FIFO order via `simnet_mint_txs`.
- `simnet_mempool_size(s)` returns the number of held transactions.
- `simnet_mempool_last_reject(s)` returns the last typed reject reason.
- `simnet_mempool_last_reject_detail(s)` returns the last reject detail string.
- `simnet_mempool_reject_name(reason)` maps a reject enum to a stable string.
- `simnet_wallet_create(s)` creates a deterministic P2PKH wallet from the seed-tape RNG.
- `simnet_wallet_free(w)` releases wallet-owned UTXO tracking.
- `simnet_wallet_address(w)` returns the wallet's deterministic display address.
- `simnet_wallet_script(w)` returns the wallet's P2PKH script.
- `simnet_wallet_balance(w)` returns mature, still-unspent wallet-tracked value.
- `simnet_wallet_default_fee_per_k()` returns the simnet catalog fee rate (`SIMNET_WALLET_DEFAULT_FEE_PER_K`, 10,000 zats per kB).
- `simnet_wallet_default_fee_rate()` returns that catalog rate as a `struct fee_rate`.
- `simnet_wallet_fund(w, amount, out)` mints a coinbase to the wallet and mines it through `COINBASE_MATURITY`.
- `simnet_wallet_send(from, to_script, amount, out)` builds, fees, and enqueues a one-recipient spend to an arbitrary script.
- `simnet_wallet_send_to_wallet(from, to, amount, out)` builds, fees, and enqueues a P2PKH wallet-to-wallet spend.
- `simnet_wallet_send_many(from, recips, nrecips, out)` builds, fees, and enqueues a multi-output fan-out.
- `simnet_wallet_op_return(from, payload, payload_len, value_out, out)` builds, fees, and enqueues an OP_RETURN carrier, optionally with one value output.

`struct simnet_tx_result` reports the `txid`, serialized `tx_size`, `fee`,
input total, output total, change value, and change vout. Simnet fees are
size-proportional at `SIMNET_WALLET_DEFAULT_FEE_PER_K` (10,000 zats/kB,
`0.00010000 ZCL/kB`). That catalog rate is independent of the live wallet's
flat `WALLET_DEFAULT_FEE_ZAT` min-relay floor (100 zat per transaction).

## Time And Locktime

When a seed tape is bound with `simnet_use_seed_tape`, the next minted block
uses the tape wall clock as its `nTime`. Every successful mint advances both
the next block `nTime` and the seed-tape wall clock by the ZClassic target
spacing: 150 seconds, or 2.5 virtual minutes.

Absolute locktime uses the chain's real strict finality rule. A height lock
`N` is not final for block `N`; it is final for the next block only after the
candidate block height is greater than `N`. A time lock `T` is the same shape:
the candidate block time must be greater than `T`, not equal to it.
`simnet_mint_to_height(s, h)` is the usual way to advance height locks; each
empty block it mints also advances virtual time by 150 seconds.

Coinbase outputs mature under the real `COINBASE_MATURITY` predicate. The
wallet funding helper mines 100 maturity blocks after the funding coinbase, so
funded wallet value is usable after 100 blocks, or 250.0 virtual minutes.

## Transaction Catalog

Measured by `test_simnet_txkit` at the default fee rate:

| tx kind | size_bytes | fee_zcl | usable_blocks | virtual_minutes |
|---|---:|---:|---:|---:|
| P2PKH single-in/single-out | 121 | 0.00001210 | 1 | 2.5 |
| multi-input consolidation | 164 | 0.00001640 | 1 | 2.5 |
| multi-output fan-out | 189 | 0.00001890 | 1 | 2.5 |
| OP_RETURN data carrier | 103 | 0.00001030 | 1 | 2.5 |
| OP_RETURN plus value output | 137 | 0.00001370 | 1 | 2.5 |
| P2SH HTLC fund | 162 | 0.00001620 | 1 | 2.5 |
| HTLC redeem path | 325 | 0.00003250 | 1 | 2.5 |
| HTLC refund path | 292 | 0.00002920 | 3 | 7.5 |
| chained spend after mint | 87 | 0.00000870 | 2 | 5.0 |

The HTLC rows use the real builders in `core/modules/script/src/htlc.c` for the contract,
redeem scriptSig, and refund scriptSig. The refund row uses a lock height three
blocks past the funding setup in the test, so it is only accepted after
`simnet_mint_to_height` advances past the lock boundary.

The simulator mempool does not permit intra-batch chained spends. Admission
validates against the current chain view only; it does not topologically sort
or recursively evaluate outputs created by earlier held txs. A child spending
an output from another mempool tx is rejected as
`SIMNET_MEMPOOL_REJECT_MISSING_INPUT`. Mine the parent first, then enqueue the
child.

## Worked Examples

### add a new overlay tx test in ~10 lines

```c
seed_tape_t *t = seed_tape_open(0xA11CE, 1700000000);
seed_tape_install(t);
struct simnet s;
TXK_CHECK("simnet", simnet_init(&s));
simnet_use_seed_tape(&s, t);
struct simnet_wallet *w = simnet_wallet_create(&s);
struct simnet_tx_result fund, tx;
TXK_CHECK("fund", simnet_wallet_fund(w, 100000, &fund));
const uint8_t payload[] = { 'o', 'v', 'e', 'r', 'l', 'a', 'y' };
TXK_CHECK("opreturn", simnet_wallet_op_return(w, payload, sizeof(payload), NULL, &tx));
TXK_CHECK("mine", simnet_mempool_mint(&s));
```

### test a timelocked contract

```c
uint32_t lock_height = (uint32_t)(simnet_tip_height(&s) + 3);
struct script htlc_p2sh;
uint8_t contract[HTLC_CONTRACT_SIZE], secret[32];
TXK_CHECK("htlc script", txk_htlc_scripts(lock_height, &htlc_p2sh, contract, secret));
TXK_CHECK("fund htlc", simnet_wallet_send(alice, &htlc_p2sh, 160000, &fund_tx));
TXK_CHECK("mine fund", simnet_mempool_mint(&s));
TXK_CHECK("refund before lock rejected",
          !simnet_mempool_add(&s, &refund_tx, &reject) &&
          reject.reason == SIMNET_MEMPOOL_REJECT_NONFINAL);
TXK_CHECK("advance", simnet_mint_to_height(&s, (int)lock_height));
TXK_CHECK("refund accepted", simnet_mempool_add(&s, &refund_tx, NULL));
```

### fund → send → assert balances

```c
struct simnet_wallet *alice = simnet_wallet_create(&s);
struct simnet_wallet *bob = simnet_wallet_create(&s);
struct simnet_tx_result fund, send;
TXK_CHECK("fund alice", simnet_wallet_fund(alice, 500000, &fund));
TXK_CHECK("send", simnet_wallet_send_to_wallet(alice, bob, 50000, &send));
TXK_CHECK("mine", simnet_mempool_mint(&s));
TXK_CHECK("bob got paid", simnet_wallet_balance(bob) == 50000);
TXK_CHECK("fee was default", send.fee == 1210);
```
