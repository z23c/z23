# 100-transaction micro lab

> Owner-gated live-funds demonstration runbook, not ordinary development work
> or a current-work queue. Use only after an explicit owner request and the
> custody checks below. Current development ordering lives only in
> [`FORWARD_PLAN.md`](./FORWARD_PLAN.md).

This is the owner-visible plan for demonstrating **100 newly mined ZClassic
transactions**, each with a primary recipient value of **0.00001000 ZCL**
(1,000 zatoshi), while collecting enough evidence to make future AI-operated
transactions predictable.

The human interface is conversational. The agent uses the typed native
commands, checks custody, presents each exact redacted plan for approval,
waits for confirmation, and records the public result. The owner is not
expected to translate this runbook into CLI input.

The fast native planning surface is compiled into the binary:

```bash
z23 app transaction-types micro-lab
z23 app transaction-types micro-lab --slot=91
```

The first call returns the bounded 100-slot/14-type campaign, money envelopes,
fee policy, and custody gate. The slot call returns one exact profile, its full
semantic transaction contract, and the typed `guide` input for the next step.
It is node-free and deterministic, so an AI can navigate the campaign without
opening this Markdown file or parsing the shell notebook. It still cannot
create a wallet plan, reserve, sign, rebalance, or broadcast.

```text
100 confirmed transactions  [--------------------]   0/100
14 exact-value shapes        [--------------------]   0/14
execution gate               [--------------------]   EXTERNAL CHECK REQUIRED
```

No transaction in this campaign has been broadcast according to its ledger.
This page intentionally carries no live lane or balance claim: re-read
`docs/HANDOFF.md`, current typed status, and `make custody-status` before every
session. A remembered 0.30000000 ZCL observation is not spend authority.

## What “smallest possible fee” means

The current node has one supported money fee:

- Local minimum relay policy is 100 zatoshi per transaction
  (`DEFAULT_MIN_RELAY_TX_FEE` / `WALLET_DEFAULT_FEE_ZAT`).
- Wallet, shielded, vault-intent, swap, market, overlay, and yardsale builders
  use that same flat default.

There is no connected live fee estimator. The smallest fee the typed custody
workflow constructs and binds is therefore **100 zatoshi (0.00000100 ZCL)**.
Every plan still exposes its exact fee before `confirm:true`. Simnet catalog
fees remain a separate size-proportional 10,000 zat/kB rate; they do not set
live `paytxfee`.

A running node keeps the fee it booted with until that binary is restarted. Do
not treat a remembered 10,000-zat campaign as current once this default is
live.

## Exact budget

```text
100 recipients x 1,000 zat       100,000 zat   0.00100000 ZCL
100 fees x <=100 zat              10,000 zat   0.00010000 ZCL
bounded setup envelope           900,000 zat   0.00900000 ZCL
campaign maximum               2,000,000 zat   0.02000000 ZCL
```

The 0.02000000 ZCL maximum is below the lifetime 0.05000000 ZCL transaction-lab
allocation. If development custody is freshly proven as 0.30000000 ZCL and no
other lab allocation has been consumed, the maximum would leave 0.28000000 ZCL,
above the 0.25000000 ZCL reserve. Those are conditional calculations; the
identity-bound live snapshot and existing reservations remain authoritative.

The setup envelope covers owner-visible, separately approved prerequisites:

- one Sapling seed note up to 600,000 zatoshi plus its fee;
- confirmed P2SH multisig funding outputs;
- four confirmed HTLC funding outputs for two claim and two timeout spends;
- the minimum ZSLP inventory and two-party commerce fixtures;
- their fees and protocol-defined dust outputs.

Create the two unfunded recipient wallets with
`make transaction-micro-lab-wallets-setup`. The harness uses isolated
loopback ports, persists private mode-0600 address manifests outside the
repository, stops both nodes after derivation, and prints only a redacted
readiness count. Re-running it resumes instead of replacing either wallet.
`make transaction-micro-lab-wallets-status` is read-only. Neither command
funds, reserves, signs, broadcasts, or exports a key.

Setup transactions are not secretly counted among the 100. They are separately
identified public transactions, included in the same lifetime cap, and never
created automatically. The original four-transaction shield/unshield proposal
in `LIVE_TRANSACTION_DEMONSTRATIONS.md` is superseded by this campaign's setup
when this campaign is selected; do not fund both.

The two recipient wallets persist the isolated `test` operator lane. After an
explicit dev setup transaction funds one, chained Z-to-Z and Z-to-T work must
target that wallet's own endpoint with `wallet_scope=test`. The wallet-local
money snapshot still requires matching identity, genesis, current tip, complete
money readers, and exact reservations. Its liquid confirmed balance is its
entire transaction envelope: `test` is not a third broker portfolio domain and
cannot spend or aggregate the dev, prod, legacy, or sibling lab wallet.

## The 100 numbered slots

The stable machine-readable allocation is
[`transaction_micro_lab_profiles.def`](../../app/controllers/include/controllers/transaction_micro_lab_profiles.def).
The shell notebook's developer catalog is mechanically checked against that
compiled C23 authority. It covers 14 transaction shapes:

| Slots | Count | Shape | What varies |
|---:|---:|---|---|
| 001–016 | 16 | transparent T-to-T | ordinary standard payments |
| 017–026 | 10 | raw custom | separated create/sign/broadcast path |
| 027–028 | 2 | P2SH multisig spend | threshold-signed spends |
| 029–043 | 15 | Sapling T-to-Z | shielding micro-payments |
| 044–058 | 15 | Sapling Z-to-Z | private micro-payments |
| 059–073 | 15 | Sapling Z-to-T | unshielding micro-payments |
| 074–078 | 5 | mixed Sapling | transparent plus shielded recipients totaling 1,000 zat |
| 079–086 | 8 | on-chain memo | encrypted Sapling memo payments |
| 087–090 | 4 | ZPAY | typed payment-envelope memo payments |
| 091–092 | 2 | HTLC redeem | secret-claim settlements |
| 093–094 | 2 | HTLC refund | matured timeout settlements |
| 095–096 | 2 | store payment | one-time transparent order payments |
| 097–098 | 2 | yardsale purchase | atomic ZCL-for-token purchases |
| 099–100 | 2 | market purchase | paid, verified file delivery |

“Primary recipient value” excludes ordinary change, OP_RETURN metadata, and a
protocol-required token dust output. Those are still included in exact plan
review and fee/accounting receipts. The catalog deliberately excludes the 25
other semantic types from the 1,000-zatoshi claim: coinbase and Sprout are
process references; metadata-only operations do not have a payment amount;
some lifecycle operations require more than a 1,000-zatoshi spendable output;
Blog is contained; and shielded store payment is isolated-only. The separate
39-type runbook still demonstrates those honestly instead of disguising them
as micro-payments.

## Safe execution order

The campaign is serial by default:

1. Re-run the global gate in `LIVE_TRANSACTION_DEMONSTRATIONS.md`. Continue only
   at scoped custody 5/5 with the dev wallet `CURRENT`, a current tip and money
   snapshot, no conflicting reservations, and explicit `dev` scope. A partial
   production reader remains visible but does not authorize or block dev.
2. Create and confirm the separately approved setup transactions. Refresh the
   identity-bound snapshot after each one.
3. For the next numbered slot, ask
   `app transaction-types guide --type=<case_id>` for current schemas. Create a
   non-broadcasting exact plan with a unique idempotency key.
4. Show the owner the redacted wallet identity, route, exact outputs, recipient
   total, maximum fee, reserve after, tip, snapshot root, and expiry. Generic
   approval of this campaign does not approve unknown outputs or a changed fee.
5. Commit the exact approved plan once. A timeout is not permission to resend.
   Record `broadcast`, then query and reconcile the same plan until mined,
   conflicted, expired, or reorged.
6. Record confirmation, refresh custody, and only then advance to the next slot.

Small bounded parallel batches may be considered later only if independent
notes/UTXOs and atomic reservations are proven. The first live run remains
one-at-a-time so the confirmation latency and fee evidence are interpretable
and the campaign cannot become a burst of low-value traffic.

## Notebook and statistics

The redacted append-only working ledger is private local state under
`~/.local/state/zclassic23-transaction-lab/`; it is never a Git input and must
not be committed or pushed. The repository's
`docs/work/transaction-micro-lab-events.jsonl` is an empty campaign-header
template only. The first `record` copies that header into a mode-0600 private
ledger; `status` automatically reads the private ledger when it exists. It
permits only public txids, block identity, amounts, fees, and Unix times.
Addresses, endpoints, paths, grant tokens, plan IDs, memos, secrets, keys, and
recovery words are rejected.

Immediately after a successful broadcast, the agent records:

```bash
tools/dev/transaction-micro-lab.sh record \
  --slot=1 --state=broadcast --txid=<64-lowercase-hex> \
  --fee-zat=<actual-fee> --broadcast-unix=<unix-seconds>
```

After it is mined:

```bash
tools/dev/transaction-micro-lab.sh record \
  --slot=1 --state=confirmed --txid=<same-64-lowercase-hex> \
  --fee-zat=<same-actual-fee> --broadcast-unix=<same-unix-seconds> \
  --confirmed-unix=<unix-seconds> --block-height=<height> \
  --block-hash=<64-lowercase-hex>
```

`conflicted`, `expired`, and `reorged` are private append-only corrective states.
A later canonical block-body proof may append `confirmed` after a local
`conflicted` or `expired` observation for the same txid.  This is a correction
of incomplete local indexing, not a second broadcast: the earlier observation
remains in the ledger, the exact txid/fee must match, and the confirming event
must carry canonical height, block hash, and time.  Future agents must prefer
that stronger chain evidence and must never edit the older event.
A recorder override still cannot point inside the repository or weaken the
operator-owned mode-0600 file requirement, and
`make check-no-live-lab-history` rejects tracked campaign events or recipient
wallet manifests before push. A reconfirmed transaction appends a new
`confirmed` event with the same txid and
new block identity. The checker rejects slot/case drift, changed accounting,
duplicate broadcasts, txid reuse, impossible transitions, missing block
identity, over-ceiling fees, and sensitive field names.

Developer/operator summary:

```bash
make transaction-micro-lab-check
make transaction-micro-lab-status
```

The status reports confirmed transaction and type coverage, in-flight and
terminal counts, recipient/fee totals, minimum/maximum/average fee, and average
broadcast-to-confirmation time. It is evidence-only: neither command reads a
private wallet, signs, authorizes, or broadcasts.
