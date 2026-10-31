# Wallet private relay (2026-10-31)

Copyright 2026 Rhett Creighton - Apache License 2.0

## Question

Can a Z23 wallet send reach the network without any observer tying the
payment to this node's IP address?

## Mechanism

- The wallet validates its own transaction with the full `accept_to_mempool`
  gate into a private `tx_mempool` that no P2P handler reads. The main mempool
  never holds it, so `mempool`, `getdata`, trickle, Dandelion fluff and block
  templates cannot reveal it.
- After a uniformly random 2 to 20 s delay (CSPRNG) the transaction is pushed
  once, as an unsolicited `tx` message, to ONE randomly chosen peer that is
  outbound, handshaked, connected, relays transactions and is reached over
  Tor.
- With no such peer the transaction is held (`waiting_for_route`). There is no
  clearnet fallback.
- Not seen back within `WPR_RESEND_AFTER_S` (180 s), it goes to a different
  onion peer after a fresh delay. The receiving peer stems for at most one
  30 s Dandelion embargo per hop, so 180 s covers several hops and still
  allows about seven distinct peers before a 20-block expiry.
- Seen back through `wallet_tx_accepted`, or included in a block: pending state
  clears and the private pool entry is removed.
- Expiry: the existing `wallet_rollback_persisted_commit` returns the notes.
- Restart: the pending set (`wallet_private_relay.pending`) survives; each
  transaction is revalidated into the private pool and resumed with a fresh
  delay. Nothing is announced or placed in the main mempool.
- Mode: `-walletbroadcast=auto|private|public`. Auto is private when Tor runs.
- Status: `z23 core wallet broadcast status` (read-only): mode, pending
  count, eligible onion peers, and per txid state, attempts and seconds since
  the last attempt. No amounts or addresses.

## Scope

Only the wallet's own sends: `sendtoaddress`, `sendmany`, `z_sendmany`
(transparent and shielded legs). Vault, ZSLP, ZDIR, ZNAM, ZID, blog, swap,
multisig and raw transaction paths keep public relay.

## Measured

Test group `wallet_private_relay` (injected clock and RNG, fake peers):

- the old relay puts the transaction in the main mempool and announces it to a
  clearnet peer (witness for the difference);
- a private send leaves the main mempool empty; `mempool` and `getdata` through
  a real message processor serve nothing to a clearnet or onion peer;
- 400 CSPRNG draws fall within 2 to 20 s, with the extremes exercised;
- exactly one eligible onion peer receives each attempt among onion, clearnet,
  inbound, disconnecting and no-relay peers; the resend goes to a different
  peer, never clearnet;
- with no onion peer the transaction is held with the right status;
- the acceptance hook and block inclusion clear the pending state;
- expiry returns the input notes;
- restart resumes and announces nothing;
- a second send cannot reselect reserved coins and a conflicting spend is
  refused by the private pool.

The shielded leg runs under `simnet_sapling_shielded_send` (parameter-gated):
a real prove and verify transaction is admitted into a private pool and is
accepted by a second node after the delayed push.

## Not measured, not solved

- Timing correlation: an observer of both this node's Tor circuits and the
  network can still correlate the push with the first appearance.
- A malicious first onion peer learns that this node originated the
  transaction.
- Acceptance of an unsolicited `tx` by `zclassicd` peers is from protocol
  knowledge; it is not verified in this repository.
- No live network run was made.
- Chained spends of unconfirmed change are unsupported in public and private
  modes alike: the wallet selects confirmed coins only.

## Mutants

Each was applied alone to the sources and run against the group; each turns
the group red (`groups_failed=1`):

- clearnet filter removed from `wpr_peer_eligible`: the clearnet-silence,
  resend, no-route and restart reports fail;
- public relay called when no onion peer exists: the no-route silence, resend
  and chained-send reports fail;
- `wallet_send_view` keeps the main pool: the main-mempool, `mempool`/`getdata`
  and delay reports fail.

## Run record

Host r1, 2026-10-31. `agent-verify` over `wallet_private_relay`,
`simnet_sapling_shielded_send`, `shielded_payment_gate`,
`wallet_funds_safety`, `mempool`, `accept_to_mempool`: groups_failed=0.
One earlier run reported groups_failed=1 for an unidentified group among the
six; the isolated rerun of `wallet_private_relay` and
`simnet_sapling_shielded_send` passed, and the next full run passed.
