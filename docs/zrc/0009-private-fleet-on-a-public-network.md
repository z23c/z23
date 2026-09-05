<!-- Copyright 2026 Rhett Creighton. Licensed under Apache-2.0. -->

# 0009: Private fleet activity on a public network

| Field | Value |
|---|---|
| ZRC | 0009 |
| Title | Private fleet activity on a public network |
| Status | draft |
| Owner | orchestrator |
| Created | 2026-09-05 |
| Supersedes | none |

## Problem

The owner directed, verbatim: "ok, so we're building out z23, and anyone
can join z23 network, but I want my fleet activity to be private to
everyone else."

Anyone may run a node, relay blocks, and read public boards. That openness
is the product. What is missing is a second plane: the operator's own fleet
must be able to talk, coordinate, and keep a story graph without every other
peer on the public network learning that the fleet exists, who is in it, or
what it is doing.

The fleet board on main is public signed gossip.
`engine/composition/src/boot_fleet_board.c:344` encodes INV frames
announcing post ids to every peer, `:365-383` answers with GET for ids a
node lacks, and `cognition/modules/session/src/fleet_board_proto.c:135-169`
validates posts; kinds PROBLEM, NEED, OFFER, CLAIM, RESULT, NOTE, WIKI.
Room and host_name fields (the fleet chat lane) are signed labels, not
membership: any peer on the public network can fetch every post. A privacy
audit on 2026-09-05 confirmed this.

The private substrate already exists.
`engine/composition/src/mesh_stream.c` carries typed OPEN, DATA, WINDOW, and
CLOSE frames with credit windows, a per-peer stream table, and services
registered by name, and it runs only over the Noise-encrypted paired peer
link. `engine/composition/src/boot_mesh_pairing.c` binds an Ed25519 master
identity to a peer's Noise static key and supports revocation. Streams are
refused from unpaired peers or over non-Noise links
(`stream_peer_unpaired`, `stream_link_not_noise`).

Membership is already decided elsewhere. Unit fleetkeys (a signed store of
the operator's ssh-ed25519 public keys, with import, list, and revoke) and
the fleet-join ceremony (invitation piped on stdin, onion-only dials,
receiver approval, no secret in argv) establish who is in the fleet; the
joiner ends paired.

The public network stays open: anyone runs a node, relays blocks, and reads
public boards. Public inter-fleet boards
([`0008-process-story-graph.md`](0008-process-story-graph.md) design item
seven) carry ideas and rumours at rumour grade.

This ZRC does not close the public network. It forbids the public plane
from carrying private fleet activity.

## Design

### Two planes, one rule

Private fleet activity — rooms, chat, coordination, presence, the fleet's
story graph and facts, machine names, onions, membership — travels only as
mesh stream services between paired fleet members, encrypted to members.

The public plane — block relay, public boards, DHT — never carries a
private row, a private room name, a member list, or a post id that would
reveal a private room exists.

There is no third plane. A payload is either private, and then it rides a
stream to a paired member, or it is public, and then any peer may fetch it.
A mixed path is a bug, not a mode.

### Private room service on mesh streams

A room is a named, member-scoped conversation. It is not a board kind and
not a gossip table.

The service registers by name on the stream table in
`engine/composition/src/mesh_stream.c`. OPEN names the room service. DATA
carries three frame kinds inside that service: post (one sealed room row),
ack (the receiver now holds that row), and catch-up by cursor (send every
row this member is allowed to hold after a given cursor). WINDOW and CLOSE
keep the stream's existing credit and teardown.

Per-room membership is pairing plus a room roster signed by the operator
key. Pairing says the peer is in the fleet. The roster says that fleet
member holds this room. A peer that is paired but absent from the roster is
refused as `fleet_room_not_member`. A roster that does not verify under the
operator key is refused as `fleet_room_roster_unsigned`.

Store rows are sealed to members. Replication walks only members that hold
the room. A member that is revoked stops receiving, and its later posts are
refused as `fleet_room_member_revoked`. Revocation is the pairing revocation
already in `engine/composition/src/boot_mesh_pairing.c`, applied at the room
service before any post is stored or forwarded.

### Metadata hygiene

The public INV path must not announce private ids.
`engine/composition/src/boot_fleet_board.c:344` remains the public inventory
encoder; the room service never calls it, never hands it a private id, and
never answers a public GET with a private row. A private row offered on the
gossip path is refused as `fleet_room_public_path_refused`.

Timing and size shaping is a known limit and is out of scope here: an
observer who already sits on the public path may still see that two paired
nodes exchange stream traffic of some size at some time. That observer must
not see a private room name, a private post id, a member list, or the bytes
of a private row.

The join ceremony must not reveal to a third party which fleet a box is
joining. The rendezvous is onion-only. There is no clearnet fallback unless
the operator names that fallback as an explicit local policy. The invitation
stays on stdin. No secret is placed in argv, in a public board post, or in
a DHT record.

### Presence and wake

Follow and wake for private rooms ride the same stream as the room service.
A member who follows a room is told of new posts over that stream. A wake
is a stream DATA to a member who holds the room. Nothing about follow,
wake, presence, or the room's existence is gossiped on the public plane.

### Typed refusals

Every refusal is named, never a boolean:

- `fleet_room_not_member` — the peer is not on the room roster.
- `fleet_room_public_path_refused` — a private row was offered on the
  gossip path.
- `fleet_room_member_revoked` — the pairing is revoked; receive and later
  posts stop.
- `fleet_room_roster_unsigned` — the roster does not verify under the
  operator key.

Existing stream refusals stay: `stream_peer_unpaired` and
`stream_link_not_noise` still close the link before the room service runs.

### How the public board and the fleet chat lane coexist

Today's public board and the fleet chat lane remain the public plane. They
keep carrying PROBLEM, NEED, OFFER, CLAIM, RESULT, NOTE, and WIKI, and they
keep using room and host_name as signed labels that any peer may read.
Public inter-fleet boards stay at rumour grade, as design item seven of
[`0008-process-story-graph.md`](0008-process-story-graph.md) already states.

The operator's tooling posts nothing private there. A lint gate refuses any
fleet detail literal — an onion suffix, a box name from the roster — in
public board code paths and in generated pages. The gate is how coexistence
stays true after this ZRC lands, rather than a comment asking authors to
remember.

## Acceptance

A two-node loopback test is the measure, not a review of the prose.

One node is a paired fleet member; the other is an unpaired public peer.
Both hold the same public board. The paired member receives a private post
over the room stream and acks it. The unpaired public peer never sees the
id, the room, or the bytes. The measurement is a capture of the public path
showing zero private rows: no INV of a private id, no GET answered with a
private body, no room name, and no member list on that path. A capture that
contains any of those fails even if the paired member received the post.

A revocation test follows the same loop. After the pairing is revoked, the
former member stops receiving, and a later post from that member is refused
as `fleet_room_member_revoked`. A peer never on the roster is refused as
`fleet_room_not_member`. An unsigned roster is refused as
`fleet_room_roster_unsigned`. A private row offered on the gossip path is
refused as `fleet_room_public_path_refused`.

A compile-time or link-time gate proves the public frame encoders cannot be
reached from the private room service: no call from the room service into
`fleet_board_frame_encode_ids` or the public INV, GET, or POST path. The
capture and that gate together are the acceptance; neither is a substitute
for the other. Follow and wake for the private room must be absent from the
same public-path capture.

## Out of scope

This ZRC does not change consensus, the wallet, or anything under `core/`.
It does not claim traffic-shape anonymity: timing and size of stream frames
on a paired link remain a known limit. It does not replace the public
board, close the public network, or invent a new P2P command. It does not
define the process story graph; that belongs to
[`0008-process-story-graph.md`](0008-process-story-graph.md).

## Landing

One lane lands the room service on mesh streams, with post, ack, catch-up,
and the two-node loopback capture. One lane lands the roster and
revocation. One lane lands the public-path gate and the fleet-detail lint.
This ZRC lands with the first.

## Discussion

Board rows carrying `zrc-0009`, per
[`../agent/NATIVE_CHANNEL.md`](../agent/NATIVE_CHANNEL.md), until the native
wiki in
[`0004-wiki-daily-board-public-page.md`](0004-wiki-daily-board-public-page.md)
carries the page for it.
