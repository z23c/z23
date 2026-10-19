# Transaction laboratory notebook

This notebook answers two different questions without blending them:

1. Can the current code build, sign, prove, validate, and settle each supported
   transaction family in an isolated deterministic environment?
2. Has that transaction family actually confirmed on mainnet under the bounded
   dev custody grant?

The first answer can be green while the second remains zero. Run
`make transaction-lab-status` for both progress bars and cumulative value/fee
statistics. Run `make transaction-lab-proof` to reproduce the isolated proof
matrix; it uses production transaction builders, ECDSA signing, Sapling proving
and verification, the consensus script interpreter, and the isolated settlement
projections named in `tools/dev/transaction_lab_catalog.def`.

For the complete machine-readable inventory—including receive-only, contained,
planned, ZID/ZDIR/ZANC, and ZCODE shapes—start with
`z23 app transaction-types list`; field meanings and the AI workflow are
documented in the [transaction API guide](../TRANSACTION_API.md).
The checked mainnet classification, prerequisites, and owner-reviewed
shield/private/unshield sequence are in the
[live transaction demonstration runbook](./LIVE_TRANSACTION_DEMONSTRATIONS.md).

## Safety boundary

- Mainnet uses only the explicitly bound `dev` wallet scope.
- Total recipient value plus fees may not exceed `0.05000000 ZCL`; the
  `0.25000000 ZCL` development reserve remains untouched.
- A live transaction requires a current identity-bound money snapshot and the
  owner-visible vault plan/commit path. Raw observed balance is not authority.
- Two fresh isolated recipient wallets are required before live funding.
- No automatic transfer or rebalance is permitted.
- The notebook never stores addresses, endpoints, datadir paths, grant tokens,
  private keys, recovery words, memos, or swap secrets. A mainnet txid is public
  and may be recorded after broadcast.
- `docs/HANDOFF.md` is the current operational authority. Do not start while
  it says to stop the mainnet transaction lab; when it clears the
  infrastructure stop, the live identity-bound custody checks and the exact
  per-transaction owner approval are still required.

## Evidence vocabulary

| Proof | Meaning |
|---|---|
| `builder_verified` | Production builder emitted the expected signed or unsigned transaction shape. |
| `interpreter_verified` | The consensus script interpreter accepted the intended spend branch and rejected invalid branches. |
| `projection_verified` | An isolated confirmed-payment fixture was reconciled by the application projection. |
| `consensus_verified` | The production consensus transaction verifier accepted the complete transaction. |
| `simnet_confirmed` | The transaction was admitted or mined on the deterministic simulated chain. |
| `live_confirmed` | A public mainnet txid reached the required confirmation state. |
| `not_demonstrated` | No end-to-end transaction path exists; the case must remain `BLOCKED`, never PASS. |

Only `live_confirmed` increments the live-mainnet bar or cumulative live value
and fee totals.

## Append-only event ledger

The repository ledger `docs/quality/transaction-lab-events.jsonl` is the public,
reproducible isolated-test baseline only. Real public-chain receipts go to a
mode-0600 private working ledger under
`~/.local/state/zclassic23-transaction-lab/`; they must never be committed or
pushed. The first `record` privately copies the baseline, and `status`
automatically reads that private copy when it exists.

Existing `zcl.transaction_lab_event.v1` lines remain valid. New public-chain
receipts use `zcl.transaction_lab_event.v2`, which adds confirmation height and
block hash. Existing lines are append-only evidence; corrections are later
events for the same `case_id`. Statistics use the latest event per case.

Validate before and after recording:

```bash
make transaction-lab-check # validates the reproducible repository baseline
tools/dev/transaction-lab.sh record \
  --case=transparent_t_to_t --network=mainnet --proof=live_confirmed \
  --result=PASS --source=owner_visible_receipt --txid=<64-lowercase-hex> \
  --recipient-zat=<integer> --fee-zat=<integer> \
  --block-height=<confirmed-height> --block-hash=<64-lowercase-hex>
make transaction-lab-status
```

`transaction-lab-status` validates and summarizes the private working ledger
after a record. It prints aggregate counts only and never prints its path.

The recorder accepts no address, path, endpoint, memo, token, or secret field.
Recording is bookkeeping only; it cannot build, sign, broadcast, or authorize a
transaction. It also refuses any output ledger path inside the repository and
requires an operator-owned mode-0600 ledger.
`make check-no-live-lab-history` mechanically rejects a committed live receipt,
micro-lab event, recipient-wallet manifest, or duplicate notebook.


## Current status

`make transaction-lab-status` prints the live counts; `make transaction-lab-proof`
reproduces them. Isolated proof covers every catalogued family (39 rows: 38
`simnet_confirmed`, one process-only Sprout row pinned to two canonical mainnet
transactions). Live-mainnet confirmations are recorded only through the
operator-owned ledger above and are zero in the repository.
