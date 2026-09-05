/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Signed state-offer rows carried on the existing "zfileaddr" message.
 *
 * ZRC-0011 phase 1a. The tree ALREADY advertises a file-service endpoint over
 * the peer link: after a ZCL23 handshake a node pushes "zfileaddr" carrying its
 * own file-service PORT (core/modules/net/src/msg_version.c), the receiver
 * pairs that port with the peer's IP from the live connection
 * (handle_zfileaddr, core/modules/net/src/msgprocessor.c) and stores the pair
 * in the node_db `file_services` table, and boot arms up to 8 CACHED endpoints
 * from that table as bundle-fetch seeds
 * (engine/composition/src/boot_bundle_fetch_peer_seeds.c:107-187).
 *
 * WHAT WAS MISSING is not the advertisement and not the transfer — the ROM
 * manifest (RMF) path already binds per-chunk SHA3 digests to a root, verifies
 * every chunk BEFORE it is written, journals for resume, and fails a chunk over
 * to the next peer (core/modules/net/include/net/rom_fetch.h:261-308). What was
 * missing is that "zfileaddr" says only "I have a file service on port N". It
 * carries no height, no digest and no producer identity, so a consumer cannot
 * judge whether a peer is worth dialling — and the cached-only arming means a
 * node's FIRST boot, with an empty file_services table, has nobody to ask.
 *
 * This header adds the missing row: an optional, signed offer batch APPENDED to
 * the same "zfileaddr" message after its 2-byte port. The append is backward
 * compatible in both directions — an older node reads its 2 bytes and ignores
 * the rest, and a newer node reading an older 2-byte message simply records a
 * port with no offers.
 *
 * WHAT AN OFFER IS. A claim, not an authority. The strongest thing a consumer
 * learns is "a durable identity signed for these bytes at this height". It then
 * fetches through the unchanged RMF path (per-chunk verified, resumable) and
 * installs through the unchanged install path (whole-file SHA3, checkpoint
 * re-derivation, Sapling-root re-derivation). No check anywhere is relaxed by
 * anything here. A peer that lies buys one bounded, content-verified fetch that
 * fails, and a score against its own signing identity.
 *
 * WHERE THE FETCH ADDRESS COMES FROM. The connection, never the offer. The
 * offer names no host and no port: the host is the peer's own connection
 * address and the port is the same 2-byte field "zfileaddr" already carries.
 * A row that could name a third-party endpoint would be a redirection lever
 * this protocol has no reason to hand anyone.
 *
 * SIGNATURE SCOPE, stated plainly. "zfileaddr" rides the plain P2P link; Noise
 * is opt-in (-noisetransport), so an offer cannot require a live Noise session
 * without excluding most peers. The signature therefore binds the offer to the
 * offering node's DURABLE Ed25519 online identity
 * (vcs_zcode_dht_online_key_load) and not to a session transcript. That makes a
 * bad offerer attributable for identity-level scoring — the mechanism ZRC-0011
 * section 6 asks for, because address banning an onion peer would take the
 * whole inbound front door down (core/modules/net/src/net.c:1866-1877). It does
 * NOT make the offer unreplayable, and it is not asked to: replaying an offer
 * costs the consumer one bounded fetch whose digest check decides the outcome.
 * Session binding arrives in phase 1b, when the transfer moves onto the
 * ZRC-0002 peer-link stream, which is Noise-established by construction. */

#ifndef ZCL_NET_STATE_OFFER_H
#define ZCL_NET_STATE_OFFER_H

#include "net/rom_seed.h" /* ROM_SEED_* bounds, enum rom_artifact_kind */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STATE_OFFER_VERSION 1u
#define STATE_OFFER_FLAGS_NONE 0u

/* ZRC-0011 section 4: an offer more than this many blocks behind the OFFERING
 * peer's own reported tip is not offered at all, and is refused on parse. A
 * stale offer is worse than no offer because it teaches a consumer the wrong
 * newest height. */
#define STATE_OFFER_FRESHNESS_BLOCKS 576

/* ZRC-0011 section 6 DoS cap: offers accepted from one peer in one message.
 * Four, not ROM_SEED_MAX_ARTIFACTS (8): a peer has at most a consensus bundle
 * and a header seed worth offering, and the cap bounds what one unauthenticated
 * handshake can make a consumer parse and store. */
#define STATE_OFFER_MAX_PER_PEER 4u

/* Chunking is the RMF path's, not a new one. */
#define STATE_OFFER_CHUNK_SIZE_BYTES ROM_SEED_CHUNK_SIZE

#define STATE_OFFER_NAME_MAX ROM_SEED_NAME_MAX

#define STATE_OFFER_V1_UNSIGNED_BYTES 368u
#define STATE_OFFER_V1_WIRE_BYTES (STATE_OFFER_V1_UNSIGNED_BYTES + 64u)

#define STATE_OFFER_BATCH_V1_HEADER_BYTES 20u
#define STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES              \
    (STATE_OFFER_BATCH_V1_HEADER_BYTES +                 \
     (size_t)STATE_OFFER_MAX_PER_PEER * STATE_OFFER_V1_WIRE_BYTES)

/* Every refusal arrives BY NAME. A caller that scores a peer must be able to
 * say which rule the peer broke, and a test must be able to assert the exact
 * rule rather than "some failure". */
enum state_offer_error {
    STATE_OFFER_OK = 0,
    STATE_OFFER_NULL,
    STATE_OFFER_SIZE,
    STATE_OFFER_MAGIC,
    STATE_OFFER_VERSION_INVALID,
    STATE_OFFER_FLAGS,
    STATE_OFFER_FIELD,    /* a required 32-byte commitment is all zero */
    STATE_OFFER_HEIGHT,   /* nonpositive, or above the offerer's own tip */
    STATE_OFFER_STALE,    /* beyond STATE_OFFER_FRESHNESS_BLOCKS */
    STATE_OFFER_CHUNKING, /* chunk size / count disagrees with the length */
    STATE_OFFER_CONTENT,  /* content length outside the RMF artifact bounds */
    STATE_OFFER_NAME,     /* filename is not a sane bare basename */
    STATE_OFFER_KIND,     /* artifact kind is not one this consumer fetches */
    STATE_OFFER_TIME,
    STATE_OFFER_COUNT,    /* batch names more than the per-peer cap */
    STATE_OFFER_SIGNATURE,
};

/* One signed state offer. Field order here is the wire order. Every field the
 * ZRC-0011 offer table names is present; `chunk_tree_root` is the RMF
 * `chunk_root` this tree already computes and serves against, not a new tree. */
struct state_offer_v1 {
    uint16_t version;
    uint16_t flags;
    int32_t bundle_height;      /* height the bundle's state is asserted at */
    int32_t offerer_tip_height; /* the OFFERING peer's own reported tip */
    uint32_t chunk_size;        /* must be ROM_SEED_CHUNK_SIZE */
    uint32_t num_chunks;        /* must be ceil(content_bytes / chunk_size) */
    uint16_t kind;              /* enum rom_artifact_kind */
    uint16_t filename_len;      /* used bytes of filename */
    uint8_t header_hash[32];         /* block hash at bundle_height */
    uint8_t content_digest[32];      /* whole-file SHA3 — the install check */
    uint8_t chunk_tree_root[32];     /* RMF chunk_root — the serve-request key */
    /* The offerer's MMB peaks digest at offerer_tip_height — the accumulator a
     * phase-2 sampling proof samples from. ZRC-0011 section 1 writes this "at
     * bundle_height"; this tree can produce an MMB root for the state it
     * currently holds and has no accessor for a historical one, and a work
     * proof wants the tip anchor in any case. The offer carries
     * offerer_tip_height beside it so the anchor is never ambiguous, and the
     * freshness rule already bounds the two heights within 576 of each other. */
    uint8_t mmb_peaks_digest[32];
    uint8_t producer_receipt_id[32]; /* mint identity, for dedup + freshness */
    uint8_t offerer_online_pubkey[32]; /* durable Ed25519 key that signed this */
    uint64_t content_bytes;
    uint64_t issued_unix;
    uint8_t filename[STATE_OFFER_NAME_MAX]; /* bare basename, NUL-padded */
    uint8_t signature[64];
};

struct state_offer_batch_v1 {
    uint16_t version;
    uint16_t flags;
    uint32_t count;
    int32_t offerer_tip_height; /* echoed once; every row must agree */
    struct state_offer_v1 offers[STATE_OFFER_MAX_PER_PEER];
};

const char *state_offer_error_string(enum state_offer_error error);

/* True when bundle_height is within STATE_OFFER_FRESHNESS_BLOCKS of tip_height
 * and does not exceed it. THE single place the 576-block rule is decided: the
 * producer's eligibility filter, the parser's refusal and the consumer's choice
 * all call this, so the three can never drift apart. */
bool state_offer_height_is_fresh(int32_t bundle_height, int32_t tip_height);

/* Shape + freshness + RMF-consistency rules; the signature is not consulted. */
enum state_offer_error state_offer_v1_validate(
    const struct state_offer_v1 *offer);

/* Domain-separated digest the signature covers. */
enum state_offer_error state_offer_v1_root(const struct state_offer_v1 *offer,
                                           uint8_t out[32]);

/* Sign with the node's durable Ed25519 online seed — the same identity
 * mesh_status_receipt_v1_sign uses, loaded by vcs_zcode_dht_online_key_load.
 * Fills offerer_online_pubkey FROM the seed, so a row can never advertise a key
 * it was not signed by. */
enum state_offer_error state_offer_v1_sign(struct state_offer_v1 *offer,
                                           const uint8_t online_seed[32]);

/* Verify against the row's own offerer_online_pubkey. This says the row is
 * attributable to that identity; it says nothing about whether the identity is
 * one to trust, and it is not the content anchor — the digests are. */
enum state_offer_error state_offer_v1_verify(
    const struct state_offer_v1 *offer);

/* NUL-terminated copy of the offered filename. False when the row's name field
 * is unusable, so a caller can never open a half-formed path. */
bool state_offer_v1_filename(const struct state_offer_v1 *offer, char *out,
                             size_t out_capacity);

enum state_offer_error state_offer_v1_encode(
    const struct state_offer_v1 *offer, uint8_t out[STATE_OFFER_V1_WIRE_BYTES]);
enum state_offer_error state_offer_v1_decode(struct state_offer_v1 *out,
                                             const uint8_t *wire,
                                             size_t wire_len);

size_t state_offer_batch_v1_wire_size(const struct state_offer_batch_v1 *batch);
enum state_offer_error state_offer_batch_v1_validate(
    const struct state_offer_batch_v1 *batch);
enum state_offer_error state_offer_batch_v1_encode(
    const struct state_offer_batch_v1 *batch, uint8_t *out, size_t out_capacity,
    size_t *out_len);
/* Refuses a batch naming more than STATE_OFFER_MAX_PER_PEER WHOLE, and refuses
 * any row failing state_offer_v1_validate. Signatures are NOT checked here, so
 * a malformed batch and a forged signature stay separately nameable by a caller
 * that scores the peer differently for each. */
enum state_offer_error state_offer_batch_v1_decode(
    struct state_offer_batch_v1 *out, const uint8_t *wire, size_t wire_len);

/* ── Offer production seam ───────────────────────────────────────────
 *
 * The net layer knows WHEN to advertise (the "zfileaddr" send site, once per
 * ZCL23 handshake) but cannot know WHAT: a complete offer needs the bundle's
 * own SQLite manifest (block hash, producer receipt) and the node's durable
 * signing identity, neither of which net owns. Composition registers a provider
 * that fills a batch; net asks. A node that registers nothing simply advertises
 * its port as before, which is the pre-offer behaviour unchanged. */
typedef uint32_t (*state_offer_provider_fn)(struct state_offer_batch_v1 *out,
                                            void *ctx);
void state_offer_set_provider(state_offer_provider_fn provider, void *ctx);

/* Ask the registered provider for this node's current offers and encode them.
 * Returns the encoded length, or 0 when there is nothing to say — including
 * when the provider produced a batch that does not validate. Refusing to send
 * our OWN malformed batch is the same fail-closed rule the receive side uses;
 * a bug on the producing side must not become a refusal every peer has to
 * score us for. */
size_t state_offer_collect_wire(uint8_t *out, size_t out_capacity);

#endif /* ZCL_NET_STATE_OFFER_H */
