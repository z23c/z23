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
- Expiry: only when the wallet's scanned height is more than
  `WPR_EXPIRY_MARGIN_BLOCKS` (20) past the transaction expiry height and the
  wallet shows no confirmation. Then `wallet_rollback_persisted_commit`
  returns the coins and notes, the database projection releases the input
  (`db_wallet_utxo_release_spent_by`, note reservation) and a terminal
  `expired` record stays seven days. A send's record never vanishes while it
  could still be on chain.
- Restart: the pending set (`wallet_private_relay.pending`) survives; each
  transaction is revalidated into the private pool and resumed with a fresh
  delay. Nothing is announced or placed in the main mempool.
- Mode: `-walletbroadcast=private|public`; default public. Private is
  explicit and boot refuses it without `-onlynet=onion` or with
  `-externalip` (see Leaks closed).
- Status: `z23 core wallet broadcast status` (read-only): mode, pending
  count, eligible onion peers, and per txid state, attempts and seconds since
  the last attempt. No amounts or addresses.

## Leaks closed after custody review

- `sendmany` used the public mempool; it now uses the private-pool view and is
  tested through the real RPC handlers.
- `-externalip` was announced to every peer in `version`; boot refuses it in
  private mode.
- An echoed unsolicited transaction could be fluffed to a clearnet peer,
  letting that peer's spy see this node announce first; with `-onlynet=onion`
  there is no clearnet peer to fluff to.
- The phone: `apps/z23android/operations.c` launches
  `-operator-lane=canonical -tor -onion-persist` with no `-onlynet=onion`, no
  `-externalip` and no `-walletbroadcast`. It is not onion-only today, so the
  app must also pass `-onlynet=onion` and `-walletbroadcast=private` before
  private mode boots there.

## Scope

Only the wallet's own sends: `sendtoaddress`, `sendmany`, `z_sendmany`
(transparent and shielded legs). Vault intents, ZSLP, ZDIR, ZNAM, ZID, blog,
swap, yardsale and `sendrawtransaction` are refused in private mode with the
typed error `PRIVATE_BROADCAST_UNSUPPORTED`; none reaches a peer. Both
`vault.send-shielded` and `vault.intent.*` publish through
`vault_intent_publish_prepared`, which is refused. Behaviorally tested:
`sendrawtransaction`; the other sites are guarded by the same helper and not
individually exercised.

## Measured

Test group `wallet_private_relay` (injected clock and RNG, fake peers, a real
node database and wallet database where noted). Sends go through the real RPC
handlers `sendtoaddress` and `sendmany`:

- the old relay puts the transaction in the main mempool and announces it to a
  clearnet peer (witness for the difference);
- a private `sendtoaddress` and a private `sendmany` leave the main mempool
  empty; `mempool` and `getdata` through a real message processor serve
  nothing to a clearnet or onion peer;
- 400 CSPRNG draws fall within 2 to 20 s, with the extremes exercised;
- exactly one eligible onion peer receives each attempt among onion, clearnet,
  inbound, disconnecting and no-relay peers; the resend goes to a different
  peer, never clearnet; the resend check covers the worst case of two maximum
  delays around the 180 s interval;
- with no onion peer the transaction is held and the status read says it is
  safe to wait;
- the acceptance hook and block inclusion clear the pending state;
- expiry: one block past expiry at the chain lookahead, and the full margin,
  do not expire a send; one block past the margin does; a send the wallet
  shows confirmed is never rolled back, even when the expiry path runs for it;
- with a real node and wallet database, expiry releases the funding coin
  (`spent_txid`), drops the send's output rows and wallet row, `listunspent`
  sees every coin again, and the status read reports `expired` with the next
  step and no amount or address;
- restart in private mode resumes with a fresh delay and announces nothing;
  restart in public mode with an onion peer connected resumes, pushes nothing,
  and the ticker expires the send after the margin;
- boot: private mode without `-onlynet=onion` and with `-externalip` is
  refused, onion-only starts, and the default is public;
- a second send cannot reselect reserved coins and a conflicting spend is
  refused by the private pool.

The shielded leg runs two ways. Under `shielded_payment_gate` (sets
`ZCL_STRESS_TESTS=1`, needs the Sapling parameters) the real wallet RPC
`z_sendmany` from a funded transparent address to a shielded address runs in
private mode with the real prover: the main mempool is unchanged, the private
pool holds the transaction, nothing is announced before the delay, exactly the
onion peer then receives it with no clearnet byte, and a second node's message
processor accepts it. The simnet test `simnet_sapling_shielded_send` keeps a
probe that pushes a built and verified transaction; that probe does not call
`z_sendmany`. The shielded-spend branch (`z_sendmany_shielded`, notes and
witnesses) is not driven by either test; its relay call at
`wallet_shielded_send_shielded.c` shares `wallet_send_relay` with the covered
paths.


## Not measured, not solved

- Timing correlation: an observer of both this node's Tor circuits and the
  network can still correlate the push with the first appearance.
- A malicious first onion peer learns that this node originated the
  transaction.
- A resend goes to a different onion peer after 180 s; the two peers can
  compare notes and learn the origin sent both.
- Acceptance of an unsolicited `tx` by `zclassicd` peers is from protocol
  knowledge. A `zclassicd` binary exists on host r1 but only as the live
  oracle and production nodes; this repository has no regtest `zclassicd`
  harness, none was built, and no live node was touched.
- No live network run was made.
- Chained spends of unconfirmed change are unsupported in public and private
  modes alike: the wallet selects confirmed coins only.

## Mutants

Each was applied alone, with the matching group run, and every one turned the
group red (`groups_failed=1`), failing the report named:

- `sendmany` on the public context: the private-send, `mempool`/`getdata`,
  delay and chained-send reports;
- `-externalip` refusal removed: the externalip boot report;
- `-onlynet=onion` refusal removed: the onlynet boot report;
- expiry margin 0: the lookahead and full-margin reports;
- confirmation recheck removed from the expiry path: the mined-send and
  record-survival reports;
- `db_wallet_utxo_release_spent_by` removed: the database release report;
- `wallet_private_broadcast_start` returns before resume in public mode: the
  public-restart and default-mode reports;
- terminal expired record replaced by forgetting it: the expiry, status and
  public-restart reports;
- `z_sendmany` on the public context: the five real-send reports of
  `shielded_payment_gate`.

Earlier, on the first version: clearnet filter removed from
`wpr_peer_eligible`, public relay when no onion peer exists, and
`wallet_send_view` keeping the main pool each turned the group red.

## Run record

See the commit message for the head hash and gate lines. One earlier
`agent-verify` run reported groups_failed=1 without naming the group. The logs
do not identify it. The follow-up work found one flaky report in
`wallet_private_relay`: the resend check ran 210 s of simulated time, which is
shorter than the worst case of 220 s, so about one run in seven failed it
under any load. The run window is now 225 s. This may be what failed; it is
not proved.

## Second delta review (2026-10-31)

Closed with a test each: every wallet commit and re-admission is gated to the
private pool in private mode; a send handed to a peer never reads "nothing was
sent", also after a restart (the fact is persisted); a refused peer queue is
not an attempt and success is worded as handed to the peer; a failed queue
write with a failed rollback answers "outcome unknown"; a resume reserves the
notes of a recorded shielded send again; held sends are reported as held by the
send callers; a seen-back send keeps a status until mined; `walletbroadcast`
in `z23.conf` is honored and an unknown value stops the boot; private mode
runs no onion service directory or request handler and refuses
`-onion-persist` and `-onion-rotate`. Embedded Tor starts with the network
disabled, the dynhost service slot is claimed and verified, and only then is
the network enabled; a lost claim keeps the network off and refuses sends
(`test_tor`: claim, gate order, bootstrap line).

Not covered by a test: the refusal guards on the vault, ZSLP, ZDIR, ZNAM, ZID,
blog, swap and yardsale call sites are exercised only through the wallet
commit gate where they reach it; `wpb_nullifiers_unseen` is covered only for
the history-incomplete branch (hold); `wallet_view_send` and the messaging
reply are not driven by a test; no live Tor run was done for these items.

Live embedded Tor, 2026-10-31T19:27Z, isolated regtest datadir, built
binary, `-tor -onlynet=onion -walletbroadcast=private`: torrc carried
`DisableNetwork 1`; the log recorded `claim verified at 1793474853618 ms,
network enabled at 1793474853631 ms` (claim 13 ms before the network);
Tor bootstrapped to 100% over the real network; dynhost's first activation
check found its slot occupied (`attempted=0`, non-null service) and no line
`Activating dynhost ephemeral service` appeared in `tor.log` or
`tor-rend.log`; `tor_data/onion_service` stayed empty; the only listeners
were the loopback SOCKS, RPC and P2P ports. The run did not exercise a lost
claim: that path is covered by `test_tor` with a stand-in slot.
The reservation test builds a transaction whose proofs are not valid, so it
shows the reservation, not an accepted spend.
