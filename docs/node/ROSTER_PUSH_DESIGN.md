<!-- Copyright 2026 Rhett Creighton - Apache License 2.0 -->

# Roster push: fast fleet delivery without a pairing

Design only. This note installs nothing, changes no consensus, custody or
datadir rule, and edits no sealed `core/` file. The implementation is a later
change and needs one non-author review, because it touches who may deliver a
post to whom.

## Problem

A fleet post reaches another box in one of two ways.

- **Paired peers** are pushed to. The post rides one `board` stream OPEN and
  the receiver answers with a receipt (`boot_fleet_board_push.c`). A pairing
  needs a held ZID delegation (anchoring one costs coins; the lane reads held
  delegations from the DHT routing table, so a peer that left the table reads
  as `no_delegation`).
- **Roster-only peers** (a machine on the armed fleet roster with no pairing
  row) are **never pushed to**. They pull over `board.roster` every
  `FLEET_BOARD_FLEET_PULL_INTERVAL_S` (15 s). The sender already works out
  which connected roster peers it would serve and only counts them
  (`push_fanout_roster_unpushed`, `fanout_roster_serves` in
  `boot_fleet_board_push_fanout.c`).

So the free path is the slow path: delivery latency is up to one pull interval,
with no receipt. On 2026-11-25 the lab node's one pairing could not move a
message and nothing in the board said a roster peer was waiting.

## Proposal

A second push service, `board.roster.push`, for connected roster-only peers.
It reuses the push frame, the inbox, the commit tick and the receipt; it
changes only how the pusher is proved and who may be pushed to.

### Sender

- Eligibility is the predicate the code already has: `fanout_roster_serves`
  (the session proved a board key, that key stands on an armed roster, the
  read role holds). Use it to select targets instead of only counting them.
- Open `board.roster.push` over the existing session, with the OPEN payload
  `push head + roster proof + records`. The proof is the 96-byte asking proof
  `fleet_board_roster_proof_make` already produces, with a new side value
  `PUSH` so an ask proof cannot be replayed as a push proof. It binds the
  network genesis, this Noise session's transcript hash and connection
  generation, so it proves nothing on another session and needs no clock.
- Only posts this box's own board key signed are pushed (as today). Same
  bounds: `FLEET_BOARD_PUSH_POSTS_MAX` records, `FLEET_BOARD_PUSH_MAX` bytes,
  one open push per peer, `net_send_over_budget` respected.
- A peer that answers `stream_malformed` or an unknown service is marked
  unsupported for that session and not pushed to again (older nodes), exactly
  as the paired push does.

### Receiver

- Admission mirrors `board_roster_open`: `fleet_board_roster_admit` (no
  working pairing row, the key is a member of the roster in force, the proof
  verifies against this session) and `board_push_may_read` for the key.
  A peer with a working pairing row stays on the paired push, unchanged.
- Each record must be decoded, id re-derived, FLEET scope, and **signed by the
  board key the proof named**. A record by any other key is refused and the
  whole OPEN answers `push_author_mismatch`. This keeps the existing rule that
  a push can never reveal what the receiver holds that another box wrote.
- Records go through the same store path a pulled post meets, including the
  roster screen (`boot_fleet_roster_screen_post`): a non-member author is
  refused there regardless.
- At commit the standing is asked again (`fleet_board_roster_standing`, as
  `board_serve_authorized` does). A revoked or removed member answers
  `push_revoked`. Revocation travels as a sealed head row and wins on the next
  commit.
- Same bounded inbox (`FLEET_BOARD_PUSH_INBOX_MAX`), one slot per pushing peer,
  `push_busy` and `push_inbox_full` as today. The inbox is shared with paired
  pushes; a roster pusher cannot take more than one slot.
- Receipt: the existing `FLEET_BOARD_FLEET_MSG_PUSH_RECEIPT`, so a sender learns
  `stored`, `held`, `deferred` or `refused` per post. Record it in
  `fleet_board_deliveries` keyed by the receiving box (verify the table's key
  accepts a roster peer that has no pairing id before relying on it).

### What does not change

The pull stays the carrier of last resort and every pushed post still arrives
by pull if the push is refused, lost or unanswered. A pairing keeps its path.
Nothing is relayed: a box pushes only posts its own key signed. No coins, no
new key, no new trust root: the roster seal is the only authority.

## Risks to review

1. **Admission edge.** The pairing-row rule exists so a revoked pairing cannot
   be bypassed. The `pairing_row_held` check (including the inert-row rule in
   `boot_fleet_board_roster.c`) must be the one gate for both halves.
2. **Proof replay.** The new `PUSH` side must be mixed into the proof message
   so an ask proof never verifies as a push proof.
3. **Resource use.** At most one slot per pushing peer; a large roster could
   fill `FLEET_BOARD_PUSH_INBOX_MAX` (8). Decide whether roster pushes get
   their own smaller cap so they cannot starve paired pushes.
4. **Compatibility.** An older receiver refuses the service; the sender must
   fall back to the pull without logging a refusal per post.
5. **Kill switch.** An operator flag to turn roster push off, defaulting on
   only after the two-node test below passes.

## Test plan

Extend the two-node fixture in `tests/harness/src/test_fleet_board.c` (the
roster fixtures `fbr_*`, `fbc_*` and the push cases `k_fbp_cases`):

- a roster member with no pairing row is pushed one post and stores it, and
  the sender sees a `stored` receipt;
- a non-member, a revoked member and a peer with a working pairing row are
  not pushed to over this service;
- an ask proof replayed as a push proof is refused;
- a record signed by a key other than the proving one answers
  `push_author_mismatch`;
- revocation between OPEN and commit answers `push_revoked`;
- an old receiver (service absent) leaves the post to the pull and counts one
  `unsupported` skip, not one per post.

Measure: a live two-node run records post-to-receipt time against the 15 s
pull baseline. Until that run exists, no latency claim stands.

## Cheap steps that do not need this design

- After a roster peer answers a pull, pull again in about 3 s while it keeps
  answering, falling back to 15 s when idle.
- Count a fleet post that found no live session at all, so an operator can tell
  "waiting for a peer" from "stuck".
