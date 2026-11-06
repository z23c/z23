<!-- Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 -->

# Verified state transfer over existing peers

## Problem and observed behavior

An Android preview node reported millions of blocks remaining. Its state-offer
status reported zero offers and fallback after the 120-second discovery window.
This observation establishes that the device did not activate offered state;
it does not identify which remote provider caused the failure.

Source inspection found two independent obstacles:

- The endpoint store rejected onion peers whose connection supplied no IP
  address. The separate file-service port is not necessarily reachable through
  an existing onion P2P service.
- Registered bundles use relative paths such as `bundles/state.sqlite`, while
  signed offers require safe basenames. Copying the registered path into the
  offer prevented signing. Artifact opening must retain the full registered
  path, while the advertised destination name uses only the basename.

## Implementation contract

The engine multiplexes bounded `ZBND` frames over the existing `zpkgswm`
connection. Service bit 27 (`NODE_STATE_OFFER_LINK`) advertises this extension;
legacy package hosts receive no discovery frames they would interpret as
malformed package messages. This bit describes in-band protocol support, not a
file-service endpoint or an assurance that a particular bundle is available.

Discovery returns the existing signed state-offer batch. Transfer serves only
registered consensus bundles. One object request streams frames no larger than
64 KiB, avoiding a network round trip per fragment. Sender disk work and receiver
file work run outside the message loop. Admission, response storage, peer queues
and per-tick work remain bounded.

The receiver verifies the manifest against the signed chunk root, each chunk
against that manifest, and the complete file against the signed content digest.
It rechecks journaled chunks before resuming. Durable data precedes journal
progress; atomic publication precedes installation. The existing checkpoint and
Sapling state verification remain the activation authority. A valid signature
alone never authorizes installation.

Independent peer sources for the same content remain available when one sender
fails. Transfer corruption rejects the serving peer rather than globally
rejecting the shared digest. Temporary failures preserve verified partial data
and allow retry. Disconnects cancel the waiting reader and release the sender
slot.

## Acceptance still required

Registered tests cover wire bounds, signed discovery, legacy compatibility,
chunk verification, retry, source isolation, disconnects and durable resume.
Results must be recorded after a stable-source run. Device startup latency,
end-to-end activation and network throughput remain unmeasured for this change.
No claim of instant wallet readiness follows from transport tests alone.

The peer receiver currently has an explicit unavailable result on Windows;
the existing IP transport remains available there. macOS compilation and runtime
qualification are pending. Android and Linux are the initial receiver targets.

## Development evidence

On 2026-11-05, the stable seven-group run passed `state_offer_link`,
`state_offer_link_receive`, `state_offer_store`, `state_offer`,
`stale_offers_only`, and `boot_phase`. The peer adapter test exposed a sender
cancellation race: a worker captured its generation after cancellation.
Capturing the immutable request generation at admission repaired that failure;
the subsequent affected run passed both `state_offer_link` and
`state_offer_peer`, with no skips.

Review then found a separate negotiation defect: `msg_version_build` constructs
its services field independently of the manager field. Setting bit 27 in the
manager alone did not put it on the wire. The approved networking change now
propagates that explicit capability through the version builder. Its regression
inspects the emitted version message. After the owner-approved unseal/reseal,
the `state_offer_peer`, `state_offer`, `net`, and `peer_lifecycle` groups passed
on base `b3b3fb99b123328c90e3bab4ee55c606fb8ca067`, with no skips. Subsequent
integration onto `f9e2fe4c5ad8fde472de49708b84f4fc39880418` requires final
candidate gates. Live activation and phone readiness remain unproven.

The existing producer refresh still opens bundle manifests on the message
thread. Registry-count changes now invalidate an empty cached snapshot promptly;
same-count replacement retains the existing cache lifetime. This is not a claim
that producer refresh performs no blocking I/O.

The emitted-version regression was run against the unchanged sealed builder and
failed as expected: the serialized services field omitted
`NODE_STATE_OFFER_LINK`. The isolated repeat reproduced the same assertion.
This is an observed negotiation failure, not merely a predicted source defect.

After integration and lint repairs, a cold focused run passed all seven groups:
`state_offer_link`, `state_offer_link_receive`, `state_offer_store`,
`state_offer_peer`, `state_offer`, `stale_offers_only`, and `boot_phase`.
There were no skipped or unobserved groups. Capability closure passed after
rebuilding stale objects. The producer now reuses `zcl_path_leaf` for its
basename, avoiding a duplicate helper. The offer store retains at most four
peer-link sources per digest and rotates an idle source to admit a later peer;
it never evicts a source being fetched. This bounds the space used by one
digest in the store without establishing resistance to distinct-digest or continuous churn.

Full candidate lint and the complete test suite remain required. These results
do not establish device activation, current bundle availability, or startup
latency.

The repaired source was integrated onto
`17ffb95f6de9bdd56a656b63177d91c2e6f1bc0e` after review of the landed core
changes. The approved version-handshake edits were resealed with core root
`7228bde66f7a581578c012163c952fa080b08be13a90eb4effa360316624b92f`.
The integrated candidate still requires full lint, the complete test suite,
and device activation evidence.

The candidate based on `17ffb95f6de9bdd56a656b63177d91c2e6f1bc0e` passed
full lint. Its full suite ran 1,480 groups with one long-path fixture failure
and 19 self-skips; the affected file operations passed separately with a short
isolated test root. Consensus parity passed separately. Two FreeBSD legs were
unobserved. The candidate was integrated onto
`63cadb227946ade1d7b37012eb1d9cd2a238153e` after a seal metadata conflict;
the unchanged approved handshake edits were resealed with core root
`01cbeec8a6d0b1c3d459bbc7341cf7f11d5121486292e3b1a2dac046b985e30c`.
Integrated candidate gates and device activation remain pending.

## Onion FlySync run of 2026-11-06

A fresh `-onlynet=onion -flysync` client without `-packagehost`, connected
to two capable onion peers on release `3be2ba86`, fell back after 120 seconds
with `peers_offering=2 offers_seen=20`. The fallback counters contradict the
first reading of zero link offers. Legacy handshake offers are never retained
from an all-zero onion address, so the two retained offers came from link
discovery. The fallback came within five seconds after both serving peers were
disconnected by the stale-header rules. Header sync is held during FlySync,
so no peer could deliver a useful header. One connection had sent the client
29.6 MB with no headers accepted, which indicates a bundle transfer was in
progress. The single `engine not running` warning came from an ordinary
package frame. Every `ZBND` frame is handled before that check.

The `state_offer_onion_link` group reproduces this case in one process. Two
connections at the zero address are cross-wired through the production frame
and tick entries. The client has the package engine off and a header-sync
hold. The fixture shows the following:

- the legacy offer is dropped as `dropped-endpoint`;
- link discovery records the signed rung offer;
- the fetch starts and lands the verified bundle;
- the client sends only link frames.

On unchanged source the group failed because the stale-header predicate
still dropped the serving peer at 121 seconds under the hold. Both
stale-header predicates now return false while this node holds header sync.
Both return true again once the hold ends. Each fetch now logs one line when
it starts and one when it ends, naming its height, peer, transport and
result. Device activation and transfer time over Tor remain unmeasured.
