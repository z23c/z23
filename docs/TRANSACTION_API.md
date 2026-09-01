# Z23 transaction API

This is the map from a human intention (pay, shield, register a name, anchor a
release, settle a swap) to the exact typed command that can create the
corresponding ZClassic transaction. The machine-readable catalog is the source
of truth; this page explains how to use it safely.

## Table of contents

1. [Big picture](#big-picture)
2. [First call for an agent](#first-call-for-an-agent)
3. [One-call AI guide](#one-call-ai-guide)
4. [Reverse command lookup](#reverse-command-lookup)
5. [Catalog fields](#catalog-fields)
6. [Consensus wire and script catalog](#consensus-wire-and-script-catalog)
7. [Transaction families](#transaction-families)
8. [Safe plan/commit workflow](#safe-plancommit-workflow)
9. [Immediate asynchronous submission](#immediate-asynchronous-submission)
10. [Parallel transaction readiness](#parallel-transaction-readiness)
11. [What is not a chain transaction](#what-is-not-a-chain-transaction)
12. [Proof and statistics](#proof-and-statistics)
13. [Adding a transaction type](#adding-a-transaction-type)

## Big picture

There are three layers, and none changes legacy ZClassic consensus:

```text
human intent
    |
    v
typed native command ---------> plan / explicit commit
    |                                  |
    v                                  v
ZCL transaction bytes --------> mempool -> block -> confirmation
    |
    +-- ordinary scripts (transparent, P2SH HTLC)
    +-- Sapling spends/outputs and encrypted memos
    +-- OP_RETURN application records (ZSLP, ZNAM, ZID, ZDIR, ZANC/ZCODE)
```

The catalog describes semantic transaction shapes, not aliases. For example,
all `t→z`, `z→z`, and `z→t` payments use one command but appear as three types
because their privacy and chain behavior differ. Conversely, an atomic-swap
funding flow uses two commands—create the HTLC contract, then pay its returned
P2SH address—but appears as one composite type.

Discovery never grants authority. Reading this resource cannot unlock a wallet,
create a vault session, approve a plan, or broadcast a transaction.

## First call for an agent

Use the native interface when operating the node:

```bash
z23 yardsale guide
z23 app transaction-types list
z23 app transaction-types wire
z23 app transaction-types show --type=znam_register
z23 app transaction-types guide --type=znam_register
z23 app transaction-types command core.wallet.transaction.send
z23 discover describe app.names.register
z23 discover schema app.names.register
```

`z23 yardsale guide` is the one-call map for paying ZCL at the min-relay fee
and selling a 1/1 collectible through yardsale, the package swarm, or an onion
shop. It grants no authority. See [`SELL.md`](./SELL.md).

Public read-only clients may use the REST mirror:

```text
GET /api/v1/transaction-types
GET /api/v1/transaction-types/znam_register
```

The collection schema is `zcl.transaction_types.index.v2` and deliberately
contains compact discovery rows that fit the native response budget; a member
is the full `zcl.transaction_type.v2` contract. The collection also reports
`demonstrated_count`, `blocked_count`, `chain_confirmed_count`,
`process_only_consensus_verified_count`, `chain_or_process_verified_count`,
`mainnet_live_proven_count`, `proof_test_group_count`,
`fully_demonstrated`, and `fully_chain_or_process_verified`, so an agent can
assess proof coverage without parsing all catalog rows. It also names the
reverse lookup command and counts the explicitly audited alternate routes and
non-chain dispositions. The current catalog has 6 alternate route bindings and
18 explicit negative classifications.
`core.wallet.transaction.list` is different: it is
wallet history, not the type catalog. `app.protocols` describes broader
application protocols, not an exhaustive transaction inventory.

A full member keeps its primary `test_group` and also exposes
`supplemental_test_groups`. Supplemental groups are required when one claim
depends on independent evidence—for example, the HTLC rows retain their public
workflow or direct-interpreter group while adding `test_simnet_contract` for
the mined chain lifecycle. `make transaction-lab-proof` derives and
deduplicates both sources, so a future proof cannot silently replace one axis
with another.

An AI should select by `id`, reject `planned`, respect `network_policy`, then
inspect the named command's current input schema. It must not synthesize flags
or infer a wallet scope from examples.

## One-call AI guide

`app transaction-types guide --type=<id>` joins a catalog member to the live
command registry in one bounded read. It returns role-labeled builder, commit,
component, and inspection contracts with each command's exact schemas, allowed
input keys, example, effect, risk, authority, and confirmation mode. It also
returns a fail-closed `agent_decision`, whether a current custody snapshot and
owner authorization are required, the focused proof group, and a short safety
checklist.

When a transaction type supports durable background execution, the guide also
returns `preferred_submission_mode: immediate_ack_async`, names
`vault.intent.submit` as `preferred_submission_command`, and states that the
initial reply boundary is `durable_queue`. Its `operation_id_source` is the
existing `plan_id`, its `status_command` is `vault.intent.status`, and its
finite `lifecycle_states` array tells an AI exactly which later states it may
report. Types without that route say `foreground_commit`; an agent must not
invent asynchronous completion for them.

The guide grants no authority and executes nothing. A `ready` member may say
`can_execute:true` when every referenced command is currently ready; a
`process_only`, `contained`, or `planned` member still returns its useful
contract but tells the caller to receive only or refuse. For example,
`blog_anchor` is `contained`: `app blog anchor` can plan/commit the on-chain
anchor for an already stored, signed event, but the separate operation that
creates that signed event remains behind the unfinished runtime App grant
broker. An AI must not reinterpret anchor readiness as event-signing authority.

## Reverse command lookup

Sometimes an agent starts with a command instead of an intention. Use the
reverse lookup before invoking an unfamiliar mutation:

```bash
z23 app transaction-types command core.wallet.transaction.send
z23 app transaction-types command vault.send-shielded
z23 app transaction-types command core.wallet.address.new
```

The `zcl.transaction_command.v1` response joins the exact live command leaf to
every semantic transaction type it serves. Each mapping says whether the
command is a `builder`, `plan`, `commit`, alternate `route`, workflow
`component`, or `inspect` step, and includes the exact `guide_input` for the
next `app transaction-types guide` call. A shared primitive can map to several
types: `core.wallet.transaction.send` is the direct transparent payment command
and also funds HTLC and storefront workflows.

The result has three deliberately different states:

| `catalog_status` | Meaning | Agent action |
|---|---|---|
| `mapped` | One or more transaction workflows name this command. | Select the intended type, call its guide, then follow plan/commit policy. |
| `explicitly_non_chain` | A reviewed negative row explains why this mutating command cannot create, sign, submit, or confirm a chain transaction. | Treat it according to its own command contract, not as a transaction. |
| `unclassified` | Neither positive nor negative evidence exists. | Stop. Never infer that an omitted command is off-chain. |

Vault pass-through commands are alternate routes, not independent transaction
implementations. Their declarations live in
`engine/controllers/include/controllers/transaction_type_command_aliases.def`.
Reviewed negative assertions live separately in
`transaction_type_nonchain_commands.def`; absence from that file proves
nothing. `test_api` scans every ready mutating wallet-risk command and every
ready mutation whose registry text names a chain signal. A new ambiguous leaf
fails until it receives a positive semantic mapping or a reviewed negative
explanation.

## Catalog fields

| Field | Meaning |
|---|---|
| `availability` | `ready`, `process_only`, `contained`, or `planned`. |
| `transaction_role` | A direct chain transaction, overlay transaction, or multi-command composite. |
| `chain_encoding` | The actual chain shape: standard script, Sapling, OP_RETURN, P2SH HTLC, and so on. |
| `lifecycle` | Whether the operation is plan/commit, build/sign/broadcast, receive-only processing, or a two-party ceremony. |
| `builder_command` | First typed command. Empty means no supported builder exists. |
| `commit_command` | The value-moving/broadcast step. It may be the same command with `confirm:true`. |
| `component_commands` | Every additional command required by a composite flow. |
| `network_policy` | Where the path may run. Values such as `isolated_non_mainnet_only`, `no_broadcast_path`, and `no_public_constructor_or_broadcast_path` are hard boundaries, not suggestions. |
| `proof_level` / `test_group` | Strongest checked-in isolated proof and the exact focused test that reproduces it. |
| `lab_case_id` | Matching append-only notebook case, when one exists. |
| `evidence_status` | `demonstrated` when checked-in evidence exists; otherwise explicit `blocked`. |
| `mainnet_live_proven` | Derived from `proof_level == live_confirmed`; currently false for every type. Monetary mainnet statistics come only from the notebook ledger. |

`process_only` is not zero support: the node can parse, validate, connect, index,
and display the transaction, but agents cannot create a new one. `contained`
means code exists but policy deliberately refuses the named network. `planned`
means no end-to-end broadcast path exists and must never be presented as done.

## Consensus wire and script catalog

The transaction inventory has two independent axes:

```text
semantic intent                         consensus structure
--------------                         -------------------
pay, shield, ZNAM, ZCODE, ZSLP, ...    version + serialized fields + scripts
app transaction-types list/show/guide  app transaction-types wire
```

The semantic side is a finite list of applications currently recognized by
this binary. The structural side is what prevents that list from becoming a
false claim that every future application is enumerable. Run:

```bash
z23 app transaction-types wire
```

The `zcl.transaction_wire_catalog.v1` response derives four wire families from
the transaction serializer and consensus version constants. It also says
whether each family is current, historical-only, or impossible on mainnet;
nullable height bounds, a public example txid when one exists, the evidence
level, and exact reproducing test groups prevent a format row from being
mistaken for a live-mainnet claim.

| Wire family | Version/group | Mainnet status | Additional shielded structure |
|---|---|---|---|
| `legacy_v1` | v1, no group id | Historical-only, heights 0–476968; exact height-1 fixture. | Transparent inputs and outputs only. |
| `legacy_v2` | v2, no group id | Historical-only, heights 0–476968; exact height-241 fixture. | Optional Sprout JoinSplits with PHGR13 proofs. |
| `overwinter_v3` | v3 / `0x03c48270` | Never active on mainnet. Overwinter and Sapling both activate at 476969, leaving no v3-only height. | Expiry height plus optional PHGR13 Sprout JoinSplits; serializer/test-network support only. |
| `sapling_v4` | v4 / `0x892f2085` | Current from height 476969; exact height-476970 Groth16 fixture plus Sapling simnet proofs. | Sapling spends/outputs/value balance/binding signature and optional Groth16 Sprout JoinSplits. |

It also reports all six output-script classifier buckets: `nonstandard`,
`pubkey`, `pubkeyhash`, `scripthash`, `multisig`, and `nulldata`. Classification
is not consensus validity. A nonstandard script may still be consensus-valid,
and its spendability and destination shape are script-dependent; the API says
that explicitly instead of forcing an unsafe boolean answer. `nulldata` is
provably unspendable, while the ordinary and P2SH/multisig classes are
spendable subject to their scripts and signatures.

Five classifier rows carry exact canonical-mainnet examples whose complete
wire bytes, txid, contextual acceptance, byte-identical reserialization, and
solver result are pinned by `test_transaction_wire_evidence`: `pubkey`,
`pubkeyhash`, `scripthash`, `nulldata`, and `nonstandard`. Bare `multisig` is
honestly marked `mainnet_example_status=not_pinned`; its positive builder,
solver, signature-count, and P2SH wrapping vectors remain covered by
`test_multisig` and `test_domain_consensus_script_standard`. “Not pinned” is
not “impossible” or “unsupported”—it means the checked-in evidence is a
deterministic solver vector rather than a claimed historical mainnet example.

Application meaning is intentionally open-ended. Consensus permits arbitrary
scripts, unknown or future OP_RETURN tags, and opaque 512-byte Sapling memos.
The node processes a consensus-valid transaction without inventing application
semantics. Unknown OP_RETURN data is indexed by tag and payload digest; an
opaque memo is decoded only when an explicit codec recognizes it. The wire
catalog lists recognized codecs and marks coverage honestly. ZPAY now names its
typed compose and inspect commands plus the existing owner-authorized Sapling
send step; optional ZID signing remains unavailable through agent input so an
identity seed never enters command context.

## Transaction families

The native catalog carries every individual entry. This grouped map is the
human index:

| Family | Semantic type ids | Current posture |
|---|---|---|
| Base ZCL | `coinbase_reward`, `transparent_t_to_t`, `transparent_multi_recipient`, `sapling_mixed_recipient`, `raw_custom_transaction`, `transparent_p2sh_multisig_spend`, `sapling_t_to_z`, `sapling_z_to_z`, `sapling_z_to_t`, `sprout_joinsplit` | Identity-bound transparent, Sapling, and mixed-pool payments use one durable vault-intent lifecycle, whether they have one recipient or fifty. P2SH multisig is ready; composition accepts public keys only and its signer uses resident owner-wallet keys. Coinbase and Sprout are process-only; Sprout evidence pins complete canonical mainnet transactions before and after Sapling activation plus contextual JoinSplit signature and PHGR13/Groth16 proof verification, without exposing a deprecated constructor. |
| ZSLP tokens | `zslp_genesis`, `zslp_mint`, `zslp_send`, `zslp_burn` | Identity-bound durable plan/commit. Planning prepares exact signed bytes and atomically claims the token/baton and fee inputs; commit names only custody scope plus plan ID. |
| ZNAM names | `znam_register`, `znam_update`, `znam_transfer`, `znam_renew`, `znam_set_record`, `znam_set_text` | Identity-bound durable plan/commit. Planning prepares exact signed OP_RETURN bytes, atomically claims every funding input plus the maximum fee, and preserves owner checks; commit names only custody scope plus plan ID. |
| Messaging | `sapling_onchain_memo` | On-chain ZMSG uses an encrypted Sapling memo; P2P messaging is off-chain. |
| Payments | `zpay_memo_envelope` | `app payments zpay compose` creates an exact anonymous invoice/payment/receipt memo; `core wallet shielded send` owns the value-moving plan/commit, and `app payments zpay inspect` strictly decodes, authenticates, and checks network/time policy. |
| Identity/directory | `zid_anchor`, `zid_rotate`, `zid_revoke`, `zdir_register`, `zdir_deregister` | Explicit custody-bound plan/commit paths with exact-input + maximum-fee reservation; all five production codec shapes have isolated owner-funded mined-and-projected proofs. Public receipts omit identity, hostname, owner, address, endpoint, and raw-transaction fields. |
| Anchors/ZCODE | `zanc_digest_anchor`, `zanc_epoch_anchor`, `zcode_release_anchor` | Generic ZANC commits an explicit SHA2/SHA3 digest through a typed compose → raw owner plan/commit workflow; epoch-ZANC commits the declared catalog range and ZCODE folds signed releases. Every exact command-produced OP_RETURN shape has isolated mined proof. |
| Blog | `blog_anchor` | `app blog anchor` durably plans/commits the strict ZBLG v1 transaction for an existing verified event. The plan requires explicit custody scope and idempotency; new event signing remains broker-contained. |
| Atomic swaps | `htlc_initiate`, `htlc_participate`, `htlc_redeem`, `htlc_refund` | Contract preparation plus explicit funding; redeem/refund settle the ZCL leg. |
| Commerce | `store_transparent_payment`, `store_shielded_payment`, `yardsale_atomic_purchase`, `market_purchase` | Exact transparent and shielded store payments are isolated-mined and reconciled against their bound one-time order identity; the shielded command remains isolated-only. The exact jointly signed Yardsale controller broadcast is isolated-mined with exact settlement and fee accounting. File-market plan/commit/retrieve mines its exact memo payment before proving authenticated delivery, verified assembly, and atomic publication. |

## Safe plan/commit workflow

For any value-moving operation, an agent follows this sequence:

```text
catalog -> exact command schema -> current bound custody snapshot
        -> confirm:false plan -> owner-authorized confirm:true commit
        -> txid/operation reconciliation -> notebook evidence
```

1. Read the catalog member and stop unless its availability and network policy
   permit the requested environment.
2. Run `discover describe` and `discover schema` for `builder_command` and
   `commit_command`; the catalog is navigation, while the command registry owns
   exact input keys.
3. Read `metaverse agent money --dir=<broker-dir>`. A missing, stale,
   conflicted, incomplete, or wrong-wallet snapshot is a refusal, never a zero
   balance. The wallet scope must be explicit. The broker portfolio recognizes
   only `dev` and `prod`; a separately targeted, pre-funded isolated wallet may
   use `wallet_scope=test` for a wallet-local vault intent. That scope must
   match its persisted `test` operator lane, is never aggregated into the
   dev/prod portfolio, and cannot draw from either portfolio wallet.
4. Create the typed plan and preserve its wallet identity, outputs, maximum
   fee, expiry, snapshot root, and idempotency identity exactly. Some plans are
   pure previews; durable vault and market-purchase plans intentionally mutate
   only reservation state so concurrent commitments cannot oversubscribe the
   wallet. Planning never broadcasts value.
5. Commit only after explicit authorization. A changed tip-bound plan, output,
   fee, wallet, network, reservation, or custody snapshot fails closed.
6. Inspect the returned txid or async operation through the member's
   `inspect_command`, wait for the required confirmation state, then record only
   redacted evidence in the transaction notebook.

ZSLP and ZNAM use the same developer-facing shape: the first typed call requires
`wallet_scope` plus `idempotency_key`, returns a durable `plan_id` and complete
`commit_input`, and reserves exact inputs without broadcasting. The second call
uses only that commit input. Their public plan/commit receipts intentionally
omit token/name values, destination or owner addresses, raw transaction bytes,
wallet paths, node endpoints, and keys; those semantics remain encrypted in the
durable intent and the public chain reveals only what its protocol requires
after an authorized broadcast.

## Immediate asynchronous submission

Interactive agents should acknowledge a long-running Sapling proof as soon as
the exact authorized plan is durably queued, rather than holding the user
connection open until broadcast or mining. The queue boundary is not a claim
that the transaction reached the mempool:

```text
owner-authorized plan
        |
        v
vault.intent.submit ---- immediate reply: operation_status=queued
        |
        +--> proving --> mempool_accepted --> confirmed --> finalized
                 |              |                |
                 +-------- vault.intent.status --+
```

Use the exact plan ID returned by `vault.intent.plan`:

```bash
z23 vault intent submit --input='{
  "wallet_scope":"dev",
  "plan_id":"<64hex>",
  "confirm":true
}'

z23 vault intent status --input='{"plan_id":"<64hex>"}'
```

`vault.intent.submit` returns the same plan ID as `operation_id`, persists the
`ASYNC_QUEUED` marker before starting proof work, and deduplicates repeated
submissions. A restart requeues the durable plan. Before first signing, the
worker still performs the normal synchronous commit checks: wallet identity,
current money snapshot, exact effects, fee, reservation, and tip-bound state
are never weakened by the asynchronous boundary.
An expired plan cannot start new proof or signing work. If exact signed bytes
were already durably prepared before expiry, the worker may finish publishing
only those same bytes; this is restart recovery, not renewed spend authority.
Transient shielded-note reservation lag stays queued and retries the same raw
transaction instead of creating a replacement. That prepared-byte retry still
requires current money readers and the same wallet identity, but it does not
pretend the old tip snapshot is current; present-chain mempool validation is
the authority for admitting the exact already-signed transaction.
After restart, a durable `mempool_accepted` intent is also reconciled against
the new process's mempool. If absent, the node loads the encrypted exact bytes,
verifies their txid, runs full current mempool validation, and relays them
again. It never selects inputs, changes outputs, or signs replacement bytes;
a transient re-admission failure leaves the accepted intent durable for an
idempotent retry.
Once the next-block height is beyond those exact bytes' consensus expiry, the
status reconciler marks `TX_EXPIRED_UNCONFIRMED`, removes the stale wallet
transaction, and releases only that txid's note reservations. A later payment
must use a fresh plan and receives a new transaction ID.
For a fully shielded transaction, wallet history and txindex are not sufficient
confirmation authorities: either projection may lag or omit a transaction with
no transparent inputs or outputs. Before applying expiry, the reconciler looks
up the exact durable transaction's Sapling nullifiers in the canonical
nullifier set, reads the active block at the revealed height, and requires the
exact txid in that block body. Exact body evidence corrects an earlier local
`expired` or `conflicted` observation to `confirmed`/`finalized` and atomically
restores the wallet notes to canonically spent. A matching nullifier without
the exact transaction body is `SHIELDED_NULLIFIER_CONFLICT`; the losing local
transaction is rolled back before its reservation is released. Unavailable,
non-canonical, or incomplete evidence leaves the prior state and reservation
fail-closed—it is never interpreted as zero, expiry, or confirmation.
Shielded coin selection runs the same authority check before choosing notes:
every locally unspent Sapling note is checked against the complete canonical
nullifier ledger, and a canonical match must resolve to the exact active block
body and spending transaction before the note is atomically marked spent. If
the nullifier history, active body, or wallet write lane is unavailable, plan
execution stops before proof construction or relay. This keeps stale wallet
projections from producing a transaction that peers will immediately reject.
The private-plan preflight also checks the prepared transaction's exact anchor
against the current coins view before creating a reservation. A missing anchor
returns `WITNESS_RESCAN_REQUIRED`; run `core wallet rescan-witnesses`, refresh
the encrypted backup after that wallet-state write, and create a fresh plan.
`SHIELDED_HISTORY_INCOMPLETE` and `SHIELDED_AUTHORITY_UNAVAILABLE` are
authority failures, not retry or zero-balance signals. Commit repeats the same
check before persisting its exact signed bytes.
Before retrying, a read-only reservation probe must identify every shielded
nullifier as an available wallet note or an idempotent reservation by that same
transaction. A missing nullifier becomes `PREPARED_NOTE_MISMATCH`; a note owned
by another transaction becomes `PREPARED_NOTE_CONFLICT`. Both are terminal and
require a fresh plan—neither may loop forever or generate replacement bytes.
Mempool refusal is also typed durably. In particular,
`SHIELDED_REQUIREMENTS_MISSING` is the defensive commit/mempool fallback when
an already prepared transaction's anchor or nullifier is no longer present in
the node's current shielded view. Other stable codes distinguish invalid
proof/script data, transparent missing inputs, conflicts, insufficient relay
fee, non-final locktime, near expiry, and internal admission failure. Agents
must branch on `error_code`, never parse log prose or resubmit a terminal plan.
Every failure from plan, commit, submit, fanout, and exact-byte publication has
the same recovery envelope: `error_code`, `current_state`, `retryable`,
`human_action_required`, and `next_action`. The legacy `code` field remains an
alias of `error_code`. `retryable: true` means only the stated same
`idempotency_key` or same `plan_id` operation is safe; it never authorizes a
new payment. `RECOVERY_REQUIRED` and `STATUS_REQUIRED` explicitly require an
intent-status lookup before any new plan, so a persistence or RPC-response
failure cannot turn into a duplicate send.

Report states literally. `proving` means background construction or retry is
active; `mempool_accepted` means the node admitted the transaction;
`confirmed` and `finalized` are chain states. `reorged`, `conflicted`,
`expired`, and `failed` must never be rendered as zero or success. Cancellation
is safe only while an intent remains unclaimed and planned; once proof work or
signed bytes may exist, `vault.intent.cancel` refuses.

This route is the preferred conversational API for transparent and Sapling
vault intents, especially `t->z`, `z->z`, `z->t`, and mixed-recipient proofs.
Application-specific foreground commands remain foreground until their typed
guide explicitly advertises an asynchronous route.

## Parallel transaction readiness

One large UTXO can contain enough value for many payments while still allowing
only one of them to reserve that input at a time. Ask the broker whether an
explicitly scoped wallet already has enough independent, reservation-eligible
transparent UTXOs for the intended concurrency:

```bash
z23 metaverse agent liquidity --input='{
  "dir":"/private/broker",
  "wallet_scope":"dev",
  "recipient_value_zat":1000,
  "maximum_fee_zat":10000,
  "concurrency":10
}'
```

The response is advisory and aggregate-only. `READY_NOW` means the requested
payments can reserve disjoint inputs now. `NEEDS_FANOUT` means the wallet has
enough permitted transparent value but needs one owner-approved preparation
transaction. `INSUFFICIENT_POLICY_BUDGET`, `NEEDS_TRANSPARENT_LIQUIDITY`, and
`FANOUT_FEE_EXCEEDS_BUDGET` distinguish allowance, pool-liquidity, and fee
shortfalls. An unavailable or non-current custody reader instead reports an
unknown/stale/conflicted status with `amounts_known:false`; it never invents a
zero balance or plan.

When fan-out is useful, the response gives only output count, value per output,
total value, maximum fee, and the private-address
`vault.intent.fanout-plan` -> `vault.intent.commit` route. It does not return an
address or outpoint, create the outputs, or rebalance automatically. The owner
can prepare the private destinations and exact reservation in one call:

```bash
z23 vault intent fanout-plan --input='{
  "wallet_scope":"dev",
  "recipient_value_zat":1000,
  "maximum_fee_zat":10000,
  "concurrency":10,
  "idempotency_key":"parallel-lab-001"
}'
```

The generated wallet-owned addresses stay inside the encrypted plan. The owner
reviews its aggregate values and plan digest, then separately authorizes
`vault.intent.commit`; preparation never signs or broadcasts. Each later
transaction still takes a fresh money snapshot and reserves recipient value
plus maximum fee atomically; the advisory plan is never spend authority.

Ordinary fee-coin selection minimizes input count deterministically. That makes
ZSLP operations cheaper to prepare without treating token or mint-baton outputs
as ordinary ZCL: those outputs remain excluded from the available-coin set.
Every `app tokens create|send|mint|burn` plan requires an explicit
`wallet_scope` and `idempotency_key`. Its receipt omits the recipient address;
the exact operation remains encrypted beside the restart-safe raw transaction.
Commit accepts only `wallet_scope`, the returned `plan_id`, and `confirm:true`,
so changed outputs or units cannot be substituted during approval. Exact
outpoints are unique across active intents, preventing two concurrent token
plans from racing the same token output, mint baton, or fee coin.

Overlay transaction builders that start from a transparent wallet base must
separate preparation from publication. Use
`zslp_command_prepare_with_op_return()` during the plan leg to insert the
canonical OP_RETURN, sign all inputs, and compute the exact txid without
touching the mempool. Persist those bytes and atomically claim their exact
inputs before returning the plan. The older
`zslp_command_commit_with_op_return()` remains a compatibility wrapper for
operator RPCs that still broadcast immediately; new typed agent mutations must
not use it as their plan leg.
For more than 50 simultaneous effects, use reviewed batches of at most 50 so
the normal intent limits, fee caps, reserve floor, and idempotency checks remain
in force.

### P2SH multisig without private-key arguments

A multisig policy is a two-transaction workflow: first fund the composed P2SH
address, then spend that output with the threshold signatures. Start with the
AI-ready contract rather than memorizing these steps:

```bash
z23 app transaction-types guide --type=transparent_p2sh_multisig_spend
```

Resolve each freshly created wallet address to its resident public key without
exporting a private key, then compose a 2-of-3 policy from those public keys:

```bash
z23 core wallet address public-key --address=<wallet-owned-address>

z23 core wallet transaction multisig compose --input='{
  "required_signatures":2,
  "public_keys":["02...","03...","02..."]
}'
```

The public-key lookup fails closed for invalid, external, watch-only, and script
addresses and returns no address or private material. The composition result
returns `address`, `redeem_script_hex`, and the exact fund, create-spend, sign,
and broadcast command paths. Fund `address` using the ordinary identity-bound
transparent payment workflow. To spend the resulting outpoint, use
`core wallet transaction raw create`, then pass its exact `scriptPubKey`,
amount, and returned `redeem_script_hex` as `redeemScript` in the `prevtxs`
array for `core wallet transaction raw sign`. Preview and commit the exact
signed bytes with `core wallet transaction raw broadcast`.

The resident owner wallet must already contain at least the threshold number
of private keys. The typed API deliberately accepts no private keys and does
not merge partial signatures produced by separate wallets. If the threshold
is unavailable, signing returns incomplete/fails closed; an agent must not
export keys or substitute a weaker policy.

Private keys, recovery words, addresses, endpoints, datadir paths, grant tokens,
swap secrets, and private memos never belong in catalog output, agent receipts,
logs, or the notebook. A public mainnet txid may be recorded after broadcast.

## What is not a chain transaction

- `app.messaging.send` with `channel=p2p` writes to a peer socket; only
  `channel=onchain` creates the Sapling-memo transaction in this catalog.
- `app.swap.initiate` and `app.swap.participate` create and persist HTLC
  contracts but broadcast nothing. The composite catalog rows explicitly name
  the later transparent funding command.
- `yardsale.seller.arm` configures the seller. The completed two-party ceremony
  is what produces the atomic ZCL/ZSLP transaction.
- ZCODE reward and badge assets are simulated local objects today. ZCODE
  science, package, DHT, and fetch operations are also off-chain. Only
  `zcode_release_anchor` in this catalog commits a ZCODE-derived root on-chain.
- File-market offers, challenges, proofs, and signed payment claims are P2P or
  local workflow objects. The real Sapling payment leg is exposed as
  `app market purchase plan|commit|status`: it binds the authenticated offer,
  exact range and amount, wallet identity, network, tip, custody snapshot,
  maximum fee, expiry, and idempotency key. Planning atomically reserves value
  plus fee; commit broadcasts at most once and persists the txid and encrypted
  buyer credential across restart.
  `app market purchase retrieve` then requires a confirmed full-file payment,
  targets only the endpoint authenticated by that signed offer, resumes only
  after rehashing durable staged chunks, verifies the full manifest root, and
  atomically publishes without overwriting an existing destination. A payment
  is never presented as a completed download before that final state.
  Paid offer ingress and exact confirmed Sapling-payment reconciliation are
  network-bound, expiry-checked, durable, and reorg-aware. The session-bound
  `zfileget.v3` delivery request verifies the buyer, refuses stamps outside
  its signed 900-second freshness window, and authorizes before invoking the
  owner-private content reader; paid payload bytes use a separate
  authenticated-encryption channel rather than the public-data chunk path.
  `app market content register` binds a signed offer to exact local bytes;
  restart reconstructs that binding and file mutation revokes delivery. See
  [`FILE_MARKET_PROTOCOL.md`](./FILE_MARKET_PROTOCOL.md) for the exact contract
  and developer workflow.
- Legacy `zclassicd` wallet funds are operator-owned and outside agent custody.

## Proof and statistics

The catalog's `proof_level` is isolated technical evidence, not a claim that
money moved on mainnet. Reproduce the bounded matrix and print the two separate
bars with:

```bash
make transaction-lab-proof
make transaction-lab-status
make transaction-lab-check
```

The collection names this split in machine-readable fields:
`checked_in_proof_source` points to the reproducible isolated baseline,
`live_proof_source` is `private_local_notebook`, and
`funded_experiment_history_policy` is `private_local_only_never_git`.
The reproducible isolated-event baseline is
[`work/transaction-lab-events.jsonl`](./work/transaction-lab-events.jsonl); live
receipts default to private local state and are never committed. The
procedure and safety cap are in
[`work/TRANSACTION_LAB.md`](./work/TRANSACTION_LAB.md). Only a `live_confirmed`
mainnet event with a public txid increments live counts, recipient value, or
fees. Simnet confirmation never increments live money statistics.
The exact 39-row mainnet posture and the owner-reviewed Sapling campaign are in
[`work/LIVE_TRANSACTION_DEMONSTRATIONS.md`](./work/LIVE_TRANSACTION_DEMONSTRATIONS.md).

The current complete inventory is **39/39 isolated cases passing**, with **38
simulated-chain confirmations** plus **1 process-only consensus-verified**
legacy Sprout case, **0 live-mainnet confirmations**, and **0 ZCL** live
recipient value or fees. Sprout's canonical mainnet fixtures pin full
transactions and proof verification, but no deprecated constructor is exposed;
therefore the 38/39 simulated-chain bar is a policy boundary, not missing send
support. The earlier 33/33 result was complete for the catalog as then declared;
the later audit found ZBLG, made the gap explicit, then added its typed
plan/commit and mined proof rather than hiding it.

For one transparent payment with multiple recipients, use the same canonical
custody engine application workflows use. Amounts are decimal strings and the
sensitive effects document goes through stdin:

```bash
printf '%s' '{"wallet_scope":"dev","route":"transparent","idempotency_key":"payment-001","effects":[{"asset":"ZCL","to":"t1...","amount":"0.00100000"},{"asset":"ZCL","to":"t1...","amount":"0.00200000"}]}' |
  z23 vault intent plan --input=-

z23 vault intent commit --input='{"wallet_scope":"dev","plan_id":"<64hex-from-plan>","confirm":true}'
z23 vault intent status --plan_id=<64hex-from-plan>
```

The required idempotency key makes a retry return the same plan; reusing that
key for different effects fails closed. The plan reserves recipient value plus the maximum fee and binds the exact
outputs, selected inputs, wallet instance, genesis, tip, current money snapshot
and expiry. Commit revalidates those bindings and is idempotent. This is the
developer-facing multi-recipient API; the legacy `sendmany` RPC is compatibility
surface, not the custody workflow agents should build against.

Every successful first plan and same-request idempotent retry returns the same
complete review fields: `digest`, `fee`, `confirmation_policy`, `route`,
`privacy`, and `effects` (plus `from` for shielded routes). An agent may safely
retry a timed-out plan request and present that response for owner review; it
must not reconstruct missing outputs from memory. Receipt `txid` and
`confirmed_block_hash` values use canonical blockchain display order, so they
can be passed directly to transaction lookup and explorer surfaces.

The same API handles every pool shape without guessing from defaults. Supply
an explicit source address and a route matching the effects: `shield` for
transparent-to-Sapling, `private` for Sapling-to-Sapling, `unshield` for
Sapling-to-transparent, or `mixed` when one transaction has recipients in both
pools. Sapling effects may include `memo` or `memo_hex`; `memo_hex` wins when
both are present. For example:

```bash
printf '%s' '{"wallet_scope":"dev","route":"mixed","from":"t1...","idempotency_key":"lab-payment-1","effects":[{"asset":"ZCL","to":"zs1...","amount":"0.00030000","memo":"private note"},{"asset":"ZCL","to":"t1...","amount":"0.00010000"}]}' |
  z23 vault intent plan --input=-
```

Planning performs a non-broadcast prover/source preflight and persists the
encrypted normalized request plus its reservation. Commit reconstructs and
stores the exact signed bytes before relay. A retry publishes those same bytes;
a different transaction cannot steal a Sapling-note reservation. The current
bounded-agent policy still default-denies this multi-effect owner workflow;
developers must not bypass that denial with a weaker single-amount grant.

The opt-in isolated end-to-end regression uses real Sapling proving parameters,
replays the exact plan, commits it to an isolated mempool, rejects a tampered
proof, decrypts the wallet-owned note, and mines the transaction in simnet:

```bash
ZCL_STRESS_TESTS=1 make -j"$(nproc)" t-fast ONLY=shielded_payment_gate
```

The ZPAY sequence deliberately keeps composition separate from custody:

```bash
# Exact field widths: nonce/request_id are 32 hex characters;
# invoice_digest/amount_commitment are 64. Times are explicit Unix seconds.
z23 app payments zpay compose --input='{
  "network":"regtest",
  "message_type":"payment",
  "created_at":1700000000,
  "expires_at":1700000600,
  "nonce":"<32-hex>",
  "request_id":"<32-hex>",
  "invoice_digest":"<64-hex>",
  "asset":"ZCL",
  "amount_commitment":"<64-hex>"
}'

# Copy the returned memo_hex into the existing owner-only command after
# discovering its current schema. That command alone plans/commits value.
z23 discover schema core.wallet.shielded.send

# A recipient checks exact bytes against an explicit network and clock.
z23 app payments zpay inspect --input='{
  "memo_hex":"<1024-hex>",
  "network":"regtest",
  "now_unix":1700000100
}'
```

Generic ZANC anchors use the same separation. The deterministic command takes
only public material and returns an exact fragment for the existing raw owner
workflow:

```bash
# 1. Compose and inspect exact public chain bytes; neither call reads a wallet.
z23 core anchor compose --input='{
  "digest":"<64-hex-sha2-or-sha3>",
  "hash_type":"sha3",
  "label":"release@1"
}'
z23 core anchor inspect '<returned-op_return_hex>'

# 2. Discover the owner-only funding/signing/plan-commit contracts. The
# composer output's next_input_fragment supplies op_return_hex verbatim.
z23 discover schema core.wallet.transaction.raw.create
z23 discover schema core.wallet.transaction.raw.sign
z23 discover schema core.wallet.transaction.raw.broadcast

# 3. Create with explicit inputs/change plus op_return_hex, sign, then call
# raw.broadcast first without confirm. Only the owner-authorized second call
# with the identical raw_hex and confirm:true may submit it.
```

This path never hashes a local file implicitly and never selects a funding
coin. The caller computes or verifies the digest outside wallet context, and
the raw workflow makes every input, change output, signature, and final byte
explicit.

The 32-byte `amount_commitment` is an application commitment supplied by the
calling invoice protocol; the composer does not reinterpret it as the Sapling
output amount. The owner must keep that external commitment and the actual
`core.wallet.shielded.send` amount consistent. A decoded memo is not itself
proof that the transaction paid the expected value or confirmed on-chain.

The safe ZBLG sequence is:

```bash
# Inspect the exact keys before constructing a request.
z23 discover schema app.blog.anchor

# Create a durable plan for an event already stored and ZNAM-owner-verified.
# This prepares exact signed bytes and reserves only the maximum fee; it does
# not broadcast. Keep the returned plan_id.
z23 app blog anchor --input='{"wallet_scope":"dev","name":"alice","event_id":"<64-hex>","idempotency_key":"alice-post-1"}'

# Owner-authorized commit uses only the explicit scope and durable plan ID.
# The event-signing operation is a separate contained capability.
z23 app blog anchor --input='{"wallet_scope":"dev","plan_id":"<64-hex>","confirm":true}'
```

The returned `commit_input` is the exact second-call document. Never rebuild it
from a default wallet flag. The plan is bound to wallet instance ID, network
genesis, operator lane, tip hash, custody snapshot root, exact prepared
transaction bytes, actual and maximum fee, expiry, event ID, current ZNAM
owner, and idempotency key. Planning atomically reserves the maximum fee; a
changed money snapshot or event owner conflicts the plan instead of silently
replanning. A restart reloads the same prepared bytes, so retry can only relay
the same transaction ID.

## Adding a transaction type

Future developers make one coherent feature slice:

1. Add one semantic row to
   `engine/controllers/include/controllers/transaction_types.def`. Reuse a type id
   only if the on-chain meaning is unchanged; aliases are component commands,
   not new semantic types.
2. Add or update the typed native builder/reader in `engine/composition/commands/*.def`.
   Every non-empty command named by the catalog is test-checked against the
   live command registry and exposed through `app transaction-types guide`.
3. Query the new leaf with `app transaction-types command <path>`. A canonical
   builder/commit/component is mapped automatically from the semantic row. If
   the leaf is only another typed route to an existing owner, add a narrowly
   explained row to `transaction_type_command_aliases.def`. If a chain-shaped
   mutation is genuinely not a transaction, add a reviewed negative row to
   `transaction_type_nonchain_commands.def`. Never silence the gate by calling
   an unknown leaf off-chain without evidence.
4. Add the isolated proof to `tools/dev/transaction_lab_catalog.def` and its
   append-only evidence event. Never label builder-only evidence as a chain
   confirmation.
5. If the change adds a recognized OP_RETURN or Sapling-memo codec, update the
   recognized-codec rows returned by `app transaction-types wire`. Add a wire
   family or script class only when the authoritative consensus/version or
   script-classification source changes; application aliases never create a
   new wire family.
6. Update this grouped index only when a family or safety posture changes; do
   not duplicate the detailed machine catalog here.
7. Run `make t-fast ONLY=test_api`, the referenced transaction test group,
   `make transaction-lab-check`, `make lint`, and the normal build/test gates.

<!-- claim: symbol-present app.transaction-types.list engine/composition/commands/apps.def -->
<!-- claim: symbol-present app.transaction-types.show engine/composition/commands/apps.def -->
<!-- claim: symbol-present app.transaction-types.guide engine/composition/commands/apps.def -->
<!-- claim: symbol-present app.transaction-types.command engine/composition/commands/apps.def -->
<!-- claim: symbol-present app.transaction-types.wire engine/composition/commands/apps.def -->
<!-- claim: file-present engine/controllers/include/controllers/transaction_types.def -->
<!-- claim: file-present engine/controllers/include/controllers/transaction_type_command_aliases.def -->
<!-- claim: file-present engine/controllers/include/controllers/transaction_type_nonchain_commands.def -->
<!-- claim: file-present tools/dev/transaction_lab_catalog.def -->
