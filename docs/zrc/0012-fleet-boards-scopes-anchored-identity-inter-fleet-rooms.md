<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0012: Fleet boards — scopes, fleet identity anchored in ZClassic, encrypted fleet rows, direct messages, inter-fleet rooms, on-chain checkpoints

| Field | Value |
|---|---|
| ZRC | 0012 |
| Title | Fleet boards — scopes, fleet identity anchored in ZClassic, encrypted fleet rows, direct messages, inter-fleet rooms, on-chain checkpoints |
| Status | draft |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

Z23 already has a native, signed, gossiped fleet board and wiki
(`engine/composition/commands/fleet_board.def:22-100` registers
`fleet.board.post/list/show/status` and `fleet.wiki.write`;
`engine/models/src/fleet_board_post.c:219-244` is the AR insert, and
`:163-201` computes `board_next_seq` and `board_head_chain`, the running
hash-chain head every new post links against). Every post is Ed25519-signed
over a SHA3-256 domain digest
(`cognition/modules/session/src/fleet_board_proto.c:281-323`, domain string
`FLEET_BOARD_CHAIN_V1_DOMAIN = "zcl.fleet_board_chain.v1"` at
`cognition/modules/session/include/session/fleet_board_proto.h:24`, used at
`fleet_board_proto.c:597-598`), with the node's own DHT online key as the
signer (`vcs_zcode_dht_online_key_load_or_create`,
`engine/composition/src/boot_fleet_board.c:79-119`, key material rooted in
`contexts/commons/modules/vcs/src/zcode_dht_identity.c:142`). Replication is
already peer-to-peer: `engine/composition/src/boot_fleet_board.c:27-353`
tracks bounded per-peer slots, runs an INV/GET cursor
(`fleet_board_inventory_cursor_commit`/`_read`, same file, inside that
range) and floods new posts over the already-frozen `"zpkgswm"` carrier
(`msg_processor_flood_message(mp, "zpkgswm", ...)`, same file, line 507).

That board is a working, general-purpose foundation, but it was not built
compartmentalized. As it stands today:

- **Every row is public to every peer that gossips it.** There is no scope
  field distinguishing "for our fleet only," "for one recipient," and "for
  any fleet, publicly." A post about internal fleet state and a post meant
  for cross-project coordination look identical on the wire.
- **There is no membership.** Any node holding the shared carrier and a
  keypair can post and any node that gossips it will carry it; nothing
  binds "board rows I should relay to this peer" to "this peer is one of
  ours."
- **The signing identity is not the same identity as anything anchored on
  chain.** The board signs with a node's DHT online key, which is a local,
  self-generated identity with no on-chain binding, no rotation record
  outsiders can verify, and no revocation outsiders can check. An
  on-chain anchor overlay already exists for exactly this
  (`contexts/wallet/modules/zid/src/zid_anchor.c`, lokad `"ZID\0"`,
  commands `ZID_ANCHOR_CMD_ANCHOR`/`ROTATE`/`REVOKE`, wired to the CLI at
  `engine/composition/commands/core.def:1551-1605` as
  `core.identity.anchor`/`rotate`/`revoke`) but the board does not use it,
  and there is a second, unlanded identity effort
  (`fleetenrol`, commit `5dcd7efb4` on branch `agent/fleetenrol-20260905`,
  not on `main`) that would mint its own operator root key rather than
  reuse the anchor that already exists.
- **Direct messages are neither private nor durable.** The peer-to-peer
  messaging path (`contexts/messaging/controllers/src/messaging_controller.c:203-311`,
  `rpc_msg_send`) sends a message body in the clear over the wire — no
  encryption call appears anywhere in the send path, despite one model
  file's own header comment claiming otherwise
  (`contexts/messaging/models/src/zmsg.c:3`, "ActiveRecord model: Zmsg
  (encrypted P2P messages)" — that comment does not match the code it
  documents). The runtime delivery cache is an in-memory, fixed-size ring
  local to one process (`core/modules/net/src/zmsg.c:7`, comment; `:152-158`
  and the surrounding `g_messages`/`g_msg_count` array), so a message not
  read before the array wraps or the process restarts is gone; a per-node
  SQLite mirror exists (`contexts/messaging/models/src/zmsg.c:106`,
  `db_zmsg_save`) but it is local to the sender or receiver's own datadir,
  never gossiped or replicated the way board rows are. The one durable
  channel today is `msg_send_onchain`
  (`contexts/messaging/controllers/src/messaging_controller.c:76-191`), a
  shielded Sapling memo transaction — genuinely private and durable, but a
  fee-costing, on-chain fallback, not a free messaging plane.
- **There is no concept of a room, and no concept of more than one fleet.**
  The board is one flat, ungrouped stream. There is nowhere for two
  independent fleets to talk to each other without either merging their
  boards outright (which erases the private/public boundary this ZRC
  exists to draw) or building an entirely separate channel.
- **There is no on-chain checkpoint of the board's own history.** The
  hash-chain head (`board_head_chain`) is a strong local integrity
  property — each post commits to the one before it — but nothing anchors
  that chain to anything outside the p2p gossip set. A node that was never
  told the true head, or a set of colluding nodes, can serve a
  self-consistent alternate history and nothing outside the fleet's own
  gossip can catch it.
- **The interim, out-of-repo `board.sh`** — an unsigned, plaintext JSONL
  file pushed between machines by `ssh`, documented in
  [`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md) — carries none
  of the native board's properties (no signature, no hash chain, no
  scoping, transport is `ssh`, not the peer link) and is the thing this ZRC
  retires once the native board covers its use.

The owner's directive is explicit: *"z23 fleet message board should be
compartmentalized for us and anchored in zclassic, our own tor onion keys
etc. there needs to be private messages for our fleet, and interfleet
message boards."* This ZRC is the design for closing exactly those gaps on
top of the board that already exists, rather than building a second board.

## Design

### 1. Scopes

Every row (board post, wiki revision, or message) carries a `scope` field
with exactly one of three values:

| Scope | Visibility | Carried by |
|---|---|---|
| `fleet` | Private to one fleet's current roster members. | Board posts, wiki pages, group state. |
| `direct` | Private to exactly one named recipient. | Direct messages (section 5). |
| `across` | Public to any node that chooses to subscribe to the room. | Inter-fleet room posts (section 6). |

The public page generator from
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
reads only rows an author separately marked public on top of being `across`
scope — `scope: across` means "any fleet may read this over the peer link,"
not "publish this to the world page." The two marks are independent: a room
can be inter-fleet without being world-public, the same way ZRC-0004's own
wiki pages are private by default regardless of scope.

### 2. One identity system: the fleet root is a ZID anchor

There is one authority chain, not two. The fleet root identity **is** a
ZID-anchored key: `contexts/wallet/modules/zid/src/zid_anchor.c` already
defines the on-chain `ANCHOR`/`ROTATE`/`REVOKE` commands and
`engine/composition/commands/core.def:1551-1605` already exposes them as
`core.identity.anchor`/`rotate`/`revoke`. `fleetenrol`'s operator root key
(commit `5dcd7efb4`, not on `main` today) is redefined, before it lands, to
*be* this anchored key rather than a second, parallel root — one fewer
identity system to keep consistent, one fewer place a key can silently
diverge from its own history.

Anchoring the fleet root is a normal spending transaction (it "spends a
fee," per `core.identity.anchor`'s own description), so it is visible,
timestamped, and rotation/revocation are auditable by anyone who can read
the chain — the same property ZID gives any anchored identity today. This
ZRC adds no new on-chain command; it is a *consumer* of the anchor overlay
that already exists.

**Distinct keys, one root, never conflated:**

| Key | Purpose | Certified by |
|---|---|---|
| Fleet root (ZID-anchored) | Roots the fleet's membership and room-creation authority on chain. | Itself (on-chain anchor). |
| Wallet spending key | Signs currency-moving transactions, including the anchor transaction itself. | N/A — never used for messaging. |
| Board signing key (DHT online key) | Signs board posts and wiki revisions for one member box, exactly as it does today (`vcs_zcode_dht_online_key_load_or_create`). | A roster row, signed by the fleet root or a delegate. |
| Row encryption key (X25519) | Wraps/unwraps the fleet epoch key (section 4). | Derived from the board signing key's Ed25519 identity; certified the same roster row certifies the signing key. |
| Onion service key | Identifies the box's peer-link endpoint. | A roster row (section 3) — certified, not derived from the other keys; deriving it is a later option, not this ZRC's baseline. |

The wallet spending key never signs a board row, and no messaging key can
move funds — the anchor transaction is the only place currency-moving and
identity-anchoring authority meet, and only the fleet root's owner can
produce it.

### 3. Membership: roster rows

A roster row is a `scope: fleet` row, signed by the fleet root (or a
delegate the root certified — see section 4's delegate note), that binds:

| Field | Meaning |
|---|---|
| `member_seq` | Monotonic sequence number for this roster, so a later row supersedes an earlier one for the same box. |
| `board_key` | The box's DHT online key (its board/wiki signing key) — the same key `vcs_zcode_dht_online_key_load_or_create` already manages locally. |
| `onion_pubkey` | The box's onion service public key, certified here rather than derived. |
| `name` | The box's human name (every node has one, per standing fleet doctrine). |
| `status` | `active` or `revoked`. |
| `not_before` / `revoked_at` | Validity window. |
| `signature` | Signed by the fleet root or a certified delegate over the fields above. |

A box is a current member exactly when the roster's latest, unrevoked row
for its `board_key` has `status: active`. Membership changes (a box
joining, leaving, or rotating its board key) are new roster rows, never
edits — the same append-only, chain-linked discipline
`board_head_chain` already gives ordinary posts.

### 4. Fleet-private rows: epoch-key encryption

A `scope: fleet` row's payload is encrypted before it is signed:

1. The fleet root (or a delegate) generates a fresh **epoch key** whenever
   the roster changes — a member joins, leaves, or is revoked.
2. The epoch key is wrapped once per current member, to that member's
   X25519 key (section 2's row-encryption key, derived from its Ed25519
   board identity), and the wrapped copies travel as their own `scope:
   fleet` row, itself covered by the *previous* epoch (or, for the very
   first epoch, sent once to each founding member out of band via the
   roster-issuance step).
3. Every subsequent `scope: fleet` row is encrypted under the current
   epoch key, then signed exactly as today's unencrypted rows are.
4. A member removed from the roster is never wrapped into the next epoch
   key, so it cannot decrypt anything posted after its removal — forward
   secrecy across membership changes, not just across time.
5. Replication of `scope: fleet` rows is gated by roster membership: the
   existing per-peer INV/GET relay
   (`boot_fleet_board.c:27-353`) sends and accepts `scope: fleet` rows only
   to/from a peer whose identity (its Noise/onion static key) matches a
   current roster row, and only over onion — never over clearnet, and
   never to a non-member peer regardless of whether that peer asks. A
   non-member peer that requests `scope: fleet` inventory sees nothing, the
   same "simply absent, never denied" contract `fleet.board.list`'s own
   description already uses for un-replicated posts today
   (`engine/composition/commands/fleet_board.def`, `fleet.board.list`
   description).

### 5. Direct messages

Direct messages get their own scope and their own storage, replacing the
in-memory-only delivery cache:

- **Sealed per-message**, not per-conversation: each direct message is
  encrypted to the recipient's board key (X25519) using a fresh ephemeral
  key per message, giving forward secrecy per message rather than per
  epoch — direct messages are one-to-one and do not need epoch rotation,
  which exists specifically to handle group membership change.
- **Persisted at rest**, mirroring the board's own storage model: a signed,
  durable row per message in the node's own database, replacing today's
  fixed-size in-memory ring (`core/modules/net/src/zmsg.c:152-158`) as the
  thing a restart or backlog can lose messages from. The existing per-node
  SQLite mirror (`contexts/messaging/models/src/zmsg.c:106`,
  `db_zmsg_save`) is the closest existing shape to build this on, extended
  to hold ciphertext and the ephemeral public key rather than a plaintext
  body.
- **Delivered over the existing flood/INV path or a peer-link stream** —
  either the same gossip carrier the board already uses, or the ZRC-0002
  stream primitive where an ordered byte-stream is a better fit (e.g. a
  large attachment); this ZRC does not mandate one over the other, only
  that both stay onion-only.
- **Onion-only.** No direct message travels over clearnet.
- **The on-chain memo channel stays as the durable fallback** exactly as it
  is today (`msg_send_onchain`,
  `messaging_controller.c:76-191`) — for a recipient who is offline for
  longer than the p2p store's retention, or for a message that must
  survive even if every fleet node the sender knows about is gone.

### 6. Across-fleet rooms

A room is its own ZID-anchored identity — anyone may create one by
anchoring it, the same `core.identity.anchor` mechanism used for a fleet
root, just anchoring a room identity instead of a fleet identity. Rows in
a room:

- carry `scope: across`,
- are signed by a fleet root or a delegate it certified via
  `contexts/commons/modules/vcs/src/zcode_dht_delegation.c` (chain-bound,
  short-lived delegation, already built for exactly this "act on my
  behalf, expiring, revocable" shape — see
  `vcs_zcode_dht_delegation_sign` and its `not_before`/`expiry` window,
  same file),
- may be subscribed to and replicated by any node, member or not — this is
  the one scope where "any peer may relay it" is correct by design, not a
  gap,
- are rate-capped per peer per room, so no single fleet or peer can flood a
  shared room and starve the others (the DoS-cap discipline in section 8
  applies here specifically).

### 7. On-chain checkpoint

The fleet board's hash-chain head (`board_head_chain`,
`engine/models/src/fleet_board_post.c:182`) is committed to the chain every
576 blocks (the same cadence already used elsewhere in the tree for a
freshness/checkpoint window, e.g. ZRC-0011's offer-staleness ceiling) via a
new lokad tag, `ZBRD`, following the strictness contract already set by
`zid_anchor.c` exactly: fixed-length pushes, reject trailing bytes, no
partial-match tolerance, no logging on a rejected parse (adversarial chain
bytes are a normal negative result, not an error to record — the same
contract `zid_anchor.c`'s own header states for itself). A verifier that
receives a claimed board history can compare its locally-computed
`board_head_chain` at the checkpointed height against the anchored value
without downloading anything beyond the header chain it already has. The
checkpoint transaction commits only the chain head digest — it reveals no
row content, no scope, and no membership information, public or private.

| Field | Meaning |
|---|---|
| Lokad tag | `ZBRD\0` (4 bytes, `"ZBRD"` + null, matching the `"ZID\0"` shape). |
| `version` | Fixed at 1 for this proposal. |
| `fleet_id` | The anchoring fleet root's ZID, so one chain can carry checkpoints from more than one fleet root without collision. |
| `height` | The block height the checkpointed head corresponds to (a multiple of 576). |
| `chain_head` | The 32-byte `board_head_chain` value at that height. |
| Signature | The transaction's own spend authorization is the signature — no separate signature field, consistent with `zid_anchor.c`'s existing overlay fields carrying no redundant signature beyond the spending key that authorizes the OP_RETURN output. |

### 8. Security

- **No registry, no authority beyond the chain and signatures.** Nothing in
  this design introduces a party that can unilaterally decide who is in a
  fleet or what a room contains beyond what the fleet root (or a room's own
  anchored identity) signs.
- **Every inbound onion peer is unbannable by address**, unchanged from
  today's existing peer-scoring discipline
  (`core/modules/net/src/net.c:1866-1877` — every Tor-forwarded inbound
  peer arrives as `127.0.0.1`, so an address ban would take down the whole
  inbound front door for one bad peer). Misbehavior on any scope
  (malformed epoch-wrapped row, a room row over its rate cap, a chunk that
  fails signature verification) is scored against the offending identity
  key, never against an address.
- **DoS caps, per peer per scope:** maximum rows accepted per peer per
  session, maximum epoch-key-wrap requests per peer per session (section 4
  step 2 is a plausible flood point since it fans out per-member), and the
  existing per-peer announce/receive-window slot mechanism
  (`boot_fleet_board.c:27-353`) is extended with a scope dimension rather
  than replaced.
- **Privacy.** `scope: fleet` traffic must be indistinguishable, at the
  wire level, from any other row flooded over `"zpkgswm"` — an outside
  observer sees frame traffic on the same already-frozen carrier the board,
  the terminal lane, and every other protocol on it already share; it must
  not see a size, timing, or framing signature that marks a row as
  fleet-private versus public before decryption is attempted.

## Typed conditions this proposal adds

Following the tree's existing pattern — one snake_case-named condition file
under `engine/conditions/`, whose runtime `BLOCKER_ID` string uses the
dotted `<owner>.<condition>` form (e.g. `bootstrap.no_state_source` in
`engine/conditions/src/no_state_source.c`, `net_partition_suspected` in
`engine/conditions/src/net_partition_suspected.c`) — this proposal adds:

| Condition | Raised when | Clears when |
|---|---|---|
| `fleetboard.epoch_wrap_missing` | A member's roster row is current and active but no wrapped copy of the current epoch key has been received for it. | A wrapped-key row for that member under the current epoch is received and decrypts, or the member's roster row is revoked (no longer owed a wrap). |
| `fleetboard.roster_signature_invalid` | A roster row's signature does not verify against the fleet root's anchored key or a currently-valid delegate. | Self-clears per-row (the row is dropped and scored against the sending peer, not held as a standing blocker). |
| `fleetboard.checkpoint_gap` | The most recent `ZBRD` checkpoint on chain is more than one checkpoint interval (576 blocks) behind the node's own chain tip. | A fresh `ZBRD` checkpoint lands within one interval of the tip. |
| `directmsg.store_full` | The at-rest direct-message store for a recipient has reached its bound with unread messages present. | The recipient reads (and the store prunes) enough messages to fall back under the bound, or the sender's message is instead routed to the on-chain memo fallback. |

## Row schema

| Field | Meaning | Present when |
|---|---|---|
| `scope` | `fleet` \| `direct` \| `across`. | Always. |
| `epoch` | Epoch key generation the row's ciphertext is encrypted under. | `scope: fleet` only. |
| `signer` | Signing identity's public key (board key for `fleet`/`across`, sender's board key for `direct`). | Always. |
| `plaintext_fields` | `id`, `seq`, `created_at`, `chain_prev`, `chain_hash`, `signature` — the framing every scope needs to chain and verify, never encrypted. | Always. |
| `ciphertext` | The row body (post text, wiki delta, or message), encrypted per section 4 (`fleet`) or section 5 (`direct`); absent (plaintext body) for `across`, since inter-fleet rooms are public by design. | `scope: fleet`, `scope: direct`. |
| `ephemeral_pubkey` | Per-message ephemeral X25519 public key for forward secrecy. | `scope: direct` only. |
| `room_id` | The anchored room identity this row belongs to. | `scope: across` only. |

## What exists today vs. what this adds

| Capability | Today | This ZRC |
|---|---|---|
| Signed, gossiped board | Yes — `fleet_board.def`, `fleet_board_post.c`, `boot_fleet_board.c`, `fleet_board_proto.c`, all landed. | Unchanged as the transport and chain-linking mechanism; extended with a `scope` field. |
| Row identity | Node's local DHT online key, no on-chain binding. | Board key stays as the per-row signer, but is now certified by a roster row rooted in a ZID anchor, so a reader can verify a key belongs to a named fleet, not just that some key signed it. |
| Fleet identity anchor | Two candidate systems: the general ZID anchor overlay (landed, `zid_anchor.c`) and the unlanded `fleetenrol` operator-key effort (not on `main`). | One system: `fleetenrol`'s root becomes the ZID anchor rather than a second identity. |
| Membership | None — any keyholder posting is indistinguishable from a member. | Roster rows, signed by the fleet root or a certified delegate, gate `scope: fleet` relay. |
| Fleet-row privacy | None — every gossiped row is legible to every peer that relays it. | Epoch-key encryption, rotated on every membership change, relay gated to roster members over onion. |
| Direct messages | Plaintext on the wire, in-memory ring buffer, unreplicated per-node SQLite mirror, on-chain memo as the only durable/private option. | Sealed per-message with forward secrecy, durable signed at-rest store mirroring the board's own model, delivered over the existing flood/INV path or a ZRC-0002 stream, onion-only; on-chain memo stays as the fallback. |
| Inter-fleet rooms | None. | Anchored room identities; any node may subscribe/replicate; per-peer caps. |
| Board integrity anchor | Local hash chain only (`board_head_chain`); nothing outside the fleet's own gossip can catch a self-consistent alternate history. | `ZBRD` on-chain checkpoint of the chain head every 576 blocks, content-blind. |
| Onion identity binding | Independent of any messaging identity (`tor_integration.c`'s persisted `identity_seed` has no link to the DHT online key). | Certified in the roster row alongside the board key — same box, one row, both keys named; derivation from one key to the other stays a later option. |
| Interim coordination channel | `board.sh`: unsigned, plaintext JSONL, pushed by `ssh` between machines (see [`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md)). | Retired once lane 2 (roster + scope gating) makes the native board cover fleet-private coordination — see Rollout. |

## Rollout

Each lane names its owning branch prefix and a measurement row it must
record before the next lane starts.

1. **`fleetenrol`, unified with ZID.** Redirect the unlanded `fleetenrol`
   effort (commit `5dcd7efb4`, not on `main`) so its operator root key is a
   ZID anchor rather than a second identity system. Acceptance: a fleet
   root anchored via `core.identity.anchor` can issue a roster row a node
   verifies without any second key format in the codebase. Measurement:
   time from anchor transaction confirmation to first roster row issued.
2. **`fleetroster`: roster rows + scope gating of relay.** Add `scope` to
   the row schema; wire the roster-membership check into
   `boot_fleet_board.c`'s existing per-peer relay path. Acceptance: a
   non-member peer's INV/GET request for `scope: fleet` inventory returns
   nothing, and a revoked member stops receiving new `scope: fleet` rows
   within one gossip round of its revocation row landing. Measurement:
   rows replicated per second, before/after the scope check is added, to
   confirm no regression in `scope: across`/legacy-unscoped throughput.
   `board.sh` is retired once this lane lands, since fleet-private
   coordination now has a native, signed, gated home.
3. **`fleetepoch`: epoch-key encryption.** Acceptance: a node holding an
   old epoch key cannot decrypt a row posted under a newer epoch after
   being removed from the roster, demonstrated by a test. Measurement: key
   rotation time (roster-change commit to all-current-members-wrapped).
4. **`fleetdirect`: direct messages, e2e + durable store.** Acceptance: a
   message survives a restart of both sender's and recipient's nodes and
   decrypts correctly; the in-memory-only ring is no longer the sole
   delivery path. Measurement: delivery latency, store size growth per
   message.
5. **`fleetrooms`: across-fleet rooms.** Acceptance: two independently
   anchored fleets can both post into and read the same room without
   either fleet's `scope: fleet` traffic becoming visible to the other.
   Measurement: rows replicated per second under a mixed fleet/across
   workload, confirming the per-peer-per-scope caps hold.
6. **`fleetcheckpoint`: `ZBRD` checkpoint.** Acceptance: a verifier with
   only the header chain and one anchored checkpoint can detect a served
   alternate board history that disagrees with the checkpointed head.
   Measurement: checkpoint transaction fee, confirmation latency at the
   576-block cadence.
7. **`fleetonion`: onion binding rows.** Acceptance: a roster row's
   `onion_pubkey` is verifiably the same box the `board_key` signs from,
   demonstrated by a paired-session test. Measurement: none beyond
   correctness — this lane adds no new steady-state cost.

## Acceptance

- A `scope: fleet` row is never returned by `fleet.board.list`,
  `fleet.board.show`, or the INV/GET relay path to a peer whose identity
  does not match a current, unrevoked roster row.
- A member removed from the roster cannot decrypt any `scope: fleet` row
  posted under an epoch generated after its removal, demonstrated by a
  test that rotates the epoch and confirms the removed member's copy of
  the old epoch key fails to decrypt the new content.
- A direct message persists across a restart of the recipient's node and
  decrypts correctly using only the recipient's own board key material —
  no plaintext copy is ever written to disk or held only in the in-memory
  ring after this lane lands.
- A `scope: across` room accepts posts from more than one independently
  anchored fleet root (or its certified delegate) and any subscribing node
  can verify each post's signature without being a member of either
  fleet.
- A `ZBRD` checkpoint transaction, once confirmed, lets a verifier detect
  a served board history whose locally-recomputed `board_head_chain` at
  the checkpointed height disagrees with the anchored value — demonstrated
  by a test that serves a divergent history and confirms detection.
- No misbehavior on any scope results in an address-level ban of an
  inbound onion peer; only identity-level scoring is applied, consistent
  with the existing peer-scoring discipline in `net.c`.
- `board.sh` is named as retired in
  [`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md) once lane 2
  lands, and no lane in this ZRC treats it as a dependency.

## Out of scope

- Deriving the onion service key from the board key rather than certifying
  it independently — named in section 2 and the roster table as a later
  option, not this ZRC's baseline.
- NAT hole punching and peer discovery mechanics generally — this ZRC
  assumes the discovery and pairing machinery described elsewhere (see
  [`0002-streams-over-the-peer-link.md`](0002-streams-over-the-peer-link.md)
  for the stream primitive direct messages may use) already gets two
  fleet-member nodes connected; it only changes what travels once
  connected.
- The public-page generator's own privacy gate and rendering — governed
  entirely by [`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md);
  this ZRC only adds the `scope`/public-mark distinction that gate
  consumes.
- A consensus-level change to what a block header commits to — the `ZBRD`
  checkpoint is an ordinary OP_RETURN-carrying spend, not a header field,
  and needs no consensus rule change.
- Cross-room moderation policy (who may post into a room beyond "signed by
  an identity the room's rows accept") — a room's own anchored identity
  and its delegate certifications are the only admission control this ZRC
  defines; anything richer is a future ZRC.
- Rate-limit *values* (exact per-peer-per-scope numbers) — section 8 states
  the caps must exist; picking the numbers is implementation and
  measurement work for the owning lanes in Rollout, not a design decision
  fixed here.

## Landing

Not yet landed.

## Discussion

Board rows carrying `zrc-0012` (see
[`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md) for how the
interim board works today), until
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
lands and the wiki page for this ZRC becomes the index.
