# Live transaction demonstration runbook

This runbook answers one narrow question: which cataloged transaction shapes
can be demonstrated on ZClassic mainnet, and what must be true before an owner
permits each broadcast?

The current source catalog contains **39** semantic transaction types:

```text
mainnet broadcast-capable  [#################---] 35/39
public-chain reference     [#-------------------]  2/39
contained                  [#-------------------]  1/39
isolated-network-only      [#-------------------]  1/39
```

The honest completion target is therefore **35 newly broadcast mainnet
transactions plus four non-broadcast demonstrations**, not 39 new mainnet
transactions. Coinbase is created only by mining and Sprout construction is
retired; both use pinned public-chain transactions. Shielded store payment is
deliberately simnet-only, and Blog anchoring remains contained until its
event-signing broker is available. Relabeling any of those four as a wallet
broadcast would be false evidence.

`mainnet broadcast-capable` does not mean “safe to send now.” It means the
source exposes a mainnet path after the global gates below and the row-specific
prerequisite both pass. The machine-readable authority for this classification
is `tools/dev/transaction_live_catalog.def`; `make transaction-lab-check`
requires it to contain exactly the same IDs and availability posture as the
semantic catalog.

## AI operator experience

The owner is not expected to translate a request into CLI flags or JSON. A
normal interaction is:

```text
Owner:  Demonstrate a real Z-to-Z transaction using the dev lab allowance.
Agent:  Current custody is CURRENT. Here is the redacted exact plan:
        wallet=dev, recipient_value=..., maximum_fee=..., reserve_after=...,
        snapshot=..., expiry=.... Approve this exact plan?
Owner:  Approve.
Agent:  Committed once. Confirmation: txid=..., height=..., block=....
```

The agent maps natural language to the semantic catalog (`Z-to-Z` to
`sapling_z_to_z`, `multisig` to `transparent_p2sh_multisig_spend`), calls
`app transaction-types guide` to discover the current typed workflow, and uses
the identity-bound money and vault intent commands itself. The commands shown
below are the auditable transport and developer recovery path; they are not a
human-operating requirement.

Every money request remains a two-message ceremony: the first turn may inspect
and create a non-broadcasting reservation, while a later explicit approval may
commit that exact plan once. “Do every transaction” is permission to prepare a
campaign, not blanket approval for 35 future commits. The agent reports
`UNKNOWN`, `STALE`, or `CONFLICTED` instead of inventing a balance and never
puts keys, addresses, grants, endpoints, paths, memos, or secrets in chat.

## Non-negotiable go/no-go gate

Do not create a plan, reserve funds, or broadcast while any item is false:

1. `docs/HANDOFF.md` no longer says to stop the mainnet transaction lab, and
   every acceptance fact listed there is closed with current evidence.
2. The installed dev binary identifies the source being reviewed; the node's
   typed `status` and `dumpstate reducer_frontier` reads are current.
3. `make custody-status ARGS='--broker-dir=<owner-private-absolute-dir>
   --wallet-scope=dev'` reports `status=ready scope=dev`.
4. `metaverse agent money` reports the explicitly targeted dev wallet as
   `CURRENT` with a current snapshot root. The independent portfolio may remain
   partial when production is unavailable; that never turns production into
   zero and never authorizes a production spend.
5. The explicit source scope is `dev`. The production wallet and legacy
   `zclassicd` wallet are never funding sources for this campaign.
6. Two fresh isolated lab recipient wallets exist. Their addresses, keys,
   paths, endpoints, and grants stay out of Git, logs, receipts, and this
   notebook.
7. The sum of every live recipient value and maximum fee is at most
   `0.05000000 ZCL`, and every proposed commit leaves at least
   `0.25000000 ZCL` confirmed and spendable in development custody.

Run the read-only checks first:

```bash
z23 status
z23 dumpstate reducer_frontier
make custody-status ARGS='--broker-dir=<owner-private-absolute-dir> --wallet-scope=dev'
z23 metaverse agent money --dir=<owner-private-absolute-dir>
make transaction-lab-status
```

On a new operator host, create only the development binding once with
`make custody-bind ARGS='--wallet-scope=dev'` before those reads. The command
does not probe or require production. It keeps identifiers, endpoints and paths
in the owner-private broker directory and never moves funds. This replaces
hand-authored grant JSON and is safe to rerun when the assigned wallet endpoint
changes: unchanged bindings are idempotent, while a changed binding is minted
in a fresh private generation and atomically promoted without forking an older
receipt chain. Omit `--wallet-scope` only when the complete two-wallet portfolio
is intentionally being bound.

Never substitute a remembered `0.30000000 ZCL` development observation for a
current identity-bound snapshot. Never infer the wallet scope from default CLI
flags. No script in this runbook automatically commits, transfers, rebalances,
or retries a transaction.

## First live campaign: shield, private transfer, unshield

This is the smallest useful public-history campaign. It exercises the three
Sapling directions and then the mixed-recipient form, using only the explicit
`dev` scope. Proposed recipient values are:

| Order | Catalog case | Route | Recipient value |
|---:|---|---|---:|
| 1 | `sapling_t_to_z` | `shield` | `0.01000000 ZCL` |
| 2 | `sapling_z_to_z` | `private` | `0.00500000 ZCL` |
| 3 | `sapling_z_to_t` | `unshield` | `0.00300000 ZCL` |
| 4 | `sapling_mixed_recipient` | `mixed` | `0.00100000 ZCL` total |

The proposed recipient total is `0.01900000 ZCL`. Before the first plan, set a
campaign maximum-fee envelope no larger than `0.00100000 ZCL` across all four
transactions. If the four exact plans require more, stop and revise the values
or the campaign; do not raise the lifetime `0.05000000 ZCL` lab cap. Recipient
value is counted even when it moves between owner-controlled lab wallets.

For each row, obtain current schemas instead of copying remembered keys:

```bash
z23 app transaction-types guide --type=sapling_t_to_z
z23 discover schema vault.intent.plan
z23 discover schema vault.intent.commit
z23 discover schema vault.intent.status
```

Pass the source and recipient addresses through the private local stdin path.
The shielding plan has this shape:

```bash
printf '%s' '{
  "wallet_scope":"dev",
  "route":"shield",
  "from":"<private-local-transparent-source>",
  "idempotency_key":"mainnet-lab-shield-001",
  "effects":[
    {"asset":"ZCL","to":"<private-local-sapling-recipient>","amount":"0.01000000"}
  ]
}' | z23 vault intent plan --input=-
```

Planning is intentionally non-broadcasting, but it creates a durable
reservation. The owner reviews its exact output value, maximum fee, wallet
scope/instance, genesis, tip, snapshot root, expiry, and privacy warning. Only
then may the owner commit the returned plan once:

```bash
z23 vault intent commit --input='{
  "wallet_scope":"dev",
  "plan_id":"<64hex-from-reviewed-plan>",
  "confirm":true
}'
z23 vault intent status --input='{"plan_id":"<64hex>"}'
```

Repeating the identical plan request is the supported timeout-recovery path. It
returns the same plan ID and the same complete `digest`, `fee`,
`confirmation_policy`, `from`, `route`, `privacy`, and `effects` document with
`idempotent_plan:true`. Never fill in an omitted review field from memory. The
commit/status `txid` and `confirmed_block_hash` are canonical display-order
chain identifiers and may be copied directly into the explorer or the private
lab recorder.

For a Sapling source, group confirmed unspent notes by exact address and sum
their decimal amounts; select an address whose total covers recipient value
plus maximum fee. Do not select the address attached to the oldest note merely
because it has the most confirmations—one confirmed note may still be too
small. If planning returns `WITNESS_RESCAN_REQUIRED`, run the typed
`core wallet rescan-witnesses` command. It rebuilds and header-verifies the
witnesses without moving funds. Because that updates wallet state, take a new
stdin-password encrypted backup before creating a fresh plan and idempotency
key. `SHIELDED_HISTORY_INCOMPLETE` or `SHIELDED_AUTHORITY_UNAVAILABLE` remains
a stop condition.

Wait for confirmation and a refreshed `CURRENT` money snapshot before planning
the next row. Repeat with route `private` and a Sapling source for Z-to-Z, route
`unshield` and a Sapling source for Z-to-T, and route `mixed` with one
transparent and one Sapling effect totaling `0.00100000 ZCL`. Never reuse an
idempotency key. A timeout after commit is not permission to send again: query
the same plan until it reconciles.

After each confirmation, record only its public txid and exact accounting:

```bash
tools/dev/transaction-lab.sh record \
  --case=sapling_t_to_z --network=mainnet --proof=live_confirmed \
  --result=PASS --source=owner_visible_receipt \
  --txid=<64-lowercase-hex> --recipient-zat=1000000 --fee-zat=<integer> \
  --block-height=<confirmed-height> --block-hash=<64-lowercase-hex>
make transaction-lab-check
make transaction-lab-status
```

The recorder writes mode-0600 private local state by default. Never copy its
live receipts into the repository ledger or push experiment history to `main`.

The txid, confirmation height, and block hash form the stable public-chain
historical reference. A reorg requires a later correcting event; never edit an
old receipt. Do not add an address, memo, endpoint, path, grant, secret, or key
to the event ledger.

## Complete 39-type mainnet posture

The prerequisite names below are concise checklists, not grants. For every
`mainnet_ready` row, start with
`z23 app transaction-types guide --type=<case_id>`, inspect every
builder/component/commit schema it names, produce a non-broadcasting plan where
available, and obtain owner approval for that exact plan. Stateful rows should
be executed in dependency order within their campaign.

| Transaction type | Mainnet posture | Required setup before its own plan |
|---|---|---|
| `coinbase_reward` | process reference | Reference and validate a newly mined public block; agents do not mint coinbase. |
| `transparent_t_to_t` | mainnet ready | Fresh transparent recipient. |
| `transparent_multi_recipient` | mainnet ready | Two fresh isolated recipients. |
| `sapling_mixed_recipient` | mainnet ready | Prover plus transparent and Sapling recipients. |
| `raw_custom_transaction` | mainnet ready | Standard script/output and explicit owner review of signed bytes. |
| `transparent_p2sh_multisig_spend` | mainnet ready | Threshold keys already resident; fund, then spend the P2SH output. |
| `sapling_t_to_z` | mainnet ready | Prover and fresh Sapling recipient. |
| `sapling_z_to_z` | mainnet ready | Confirmed Sapling note, witness, prover, and recipient. |
| `sapling_z_to_t` | mainnet ready | Confirmed Sapling note, witness, prover, and fresh transparent recipient. |
| `sprout_joinsplit` | process reference | Verify the pinned canonical mainnet PHGR13/Groth16 transactions; no deprecated constructor exists. |
| `zslp_genesis` | mainnet ready | Fresh token definition and initial allocation. |
| `zslp_mint` | mainnet ready | Confirmed GENESIS and owned mint baton. |
| `zslp_send` | mainnet ready | Confirmed owned token output. |
| `zslp_burn` | mainnet ready | Confirmed owned token output selected for explicit burn. |
| `znam_register` | mainnet ready | Unclaimed name and owner. |
| `znam_update` | mainnet ready | Confirmed owned name. |
| `znam_transfer` | mainnet ready | Confirmed owned name and new owner. |
| `znam_renew` | mainnet ready | Confirmed owned name. |
| `znam_set_record` | mainnet ready | Confirmed owned name and public record. |
| `znam_set_text` | mainnet ready | Confirmed owned name and public text. |
| `sapling_onchain_memo` | mainnet ready | Prover and message recipient; memo stays private. |
| `zpay_memo_envelope` | mainnet ready | Composed network-bound ZPAY envelope, prover, and recipient. |
| `zid_anchor` | mainnet ready | Fresh identity public key. |
| `zid_rotate` | mainnet ready | Confirmed active owned identity. |
| `zid_revoke` | mainnet ready | Confirmed active owned identity. |
| `zdir_register` | mainnet ready | Owned Tor v3 onion identity and intended public record. |
| `zdir_deregister` | mainnet ready | Confirmed active directory record owned by the same identity. |
| `zanc_digest_anchor` | mainnet ready | Public digest/label and owner-reviewed funding transaction. |
| `zanc_epoch_anchor` | mainnet ready | Current verified epoch catalog. |
| `zcode_release_anchor` | mainnet ready | Signed, proved, verified release documents. |
| `blog_anchor` | contained | Event-signing broker is still contained; do not invent or bypass it. |
| `htlc_initiate` | mainnet ready | Two-party ceremony and explicit ZCL-leg funding. |
| `htlc_participate` | mainnet ready | Matching secret hash, counterparty terms, and explicit ZCL-leg funding. |
| `htlc_redeem` | mainnet ready | Confirmed funded HTLC and correct secret. |
| `htlc_refund` | mainnet ready | Confirmed funded HTLC and matured CLTV lock height. |
| `store_transparent_payment` | mainnet ready | Fresh order and its one-time payment binding. |
| `store_shielded_payment` | isolated only | Mainnet is deliberately refused; demonstrate on simnet only. |
| `yardsale_atomic_purchase` | mainnet ready | Two-party ceremony, order, and token inventory. |
| `market_purchase` | mainnet ready | Authenticated offer, reachable delivery peer, destination, and exact range. |

The stateful campaign order is: base and Sapling funding; ZSLP lifecycle; ZNAM
lifecycle; ZID lifecycle; ZDIR register/deregister; ZANC/ZCODE anchors;
messaging/ZPAY; HTLC ceremony; commerce. Confirm and reconcile each dependency
before its successor. Recalculate the cumulative recipient-plus-fee total
before every plan. If all 35 ready rows cannot fit the remaining lifetime lab
allocation, stop with a documented budget blocker; do not make values dust,
weaken fee bounds, reuse existing user recipients, or exceed the cap merely to
fill the progress bar.

## 100-transaction exact-value campaign

For the separately requested series of 100 newly mined transactions at exactly
`0.00001000 ZCL` primary recipient value each, use
[`TRANSACTION_MICRO_LAB.md`](./TRANSACTION_MICRO_LAB.md). Its checked manifest
allocates 100 stable slots across 14 amount-bearing shapes, bounds recipient
value plus current supported wallet fees at `0.01100000 ZCL`, and gives all
setup transactions a separate envelope so prerequisites cannot disappear from
the lifetime lab accounting. It does not pretend that metadata-only or
process-only transactions have a 1,000-zatoshi payment amount.

## Reproducible evidence commands

These commands never contact or mutate a live wallet:

```bash
make transaction-lab-check
make transaction-lab-status
make transaction-lab-proof
```

The isolated proof bar and the mainnet confirmation bar answer different
questions and must remain separate. A public historical transaction can be
recorded as `live_confirmed` only after its txid, confirmation height, block
hash, and actual fee are known. Failed, conflicted, expired, or reorged plans
remain reservations until the existing intent reconciler reaches a terminal
state.
