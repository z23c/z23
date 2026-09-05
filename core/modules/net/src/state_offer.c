/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Strict allocation-free state-offer codec and offer signature.
 *
 * Nothing here trusts an offer. The strongest verdict this file can reach is
 * "a durable identity signed a well-formed, fresh claim"; the digests it
 * carries are checked by the unchanged RMF fetch and the unchanged installer.
 * See net/state_offer.h for the trust boundary in full. */

#include "net/state_offer.h"

#include "base/bytes.h"
#include "base/cleanse.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

static const uint8_t offer_magic[8] = {'Z', 'S', 'O', 'F', '1', 0, 0, 0};
static const uint8_t batch_magic[8] = {'Z', 'S', 'O', 'B', '1', 0, 0, 0};
static const char offer_signature_domain[] = "zcl.state.offer.signature.v1";

/* A row claiming to predate the project is a malformed row, not a clock to
 * reason about. */
#define STATE_OFFER_MIN_ISSUED_UNIX UINT64_C(1700000000)

_Static_assert(STATE_OFFER_MAX_PER_PEER <= ROM_SEED_MAX_ARTIFACTS,
               "a peer cannot offer more artifacts than it can hold");

const char *state_offer_error_string(enum state_offer_error error)
{
    switch (error) {
    case STATE_OFFER_OK: return "ok";
    case STATE_OFFER_NULL: return "null";
    case STATE_OFFER_SIZE: return "size";
    case STATE_OFFER_MAGIC: return "magic";
    case STATE_OFFER_VERSION_INVALID: return "version";
    case STATE_OFFER_FLAGS: return "flags";
    case STATE_OFFER_FIELD: return "field";
    case STATE_OFFER_HEIGHT: return "height";
    case STATE_OFFER_STALE: return "stale";
    case STATE_OFFER_CHUNKING: return "chunking";
    case STATE_OFFER_CONTENT: return "content";
    case STATE_OFFER_NAME: return "name";
    case STATE_OFFER_KIND: return "kind";
    case STATE_OFFER_TIME: return "time";
    case STATE_OFFER_COUNT: return "count";
    case STATE_OFFER_SIGNATURE: return "signature";
    }
    return "unknown";
}

bool state_offer_height_is_fresh(int32_t bundle_height, int32_t tip_height)
{
    if (bundle_height <= 0 || tip_height <= 0)
        return false;
    if (bundle_height > tip_height)
        return false;
    /* Both positive with bundle_height <= tip_height, so this subtraction can
     * neither overflow nor go negative. */
    return tip_height - bundle_height <= STATE_OFFER_FRESHNESS_BLOCKS;
}

/* A bare basename: no separator, no traversal, no control bytes, exactly
 * filename_len long and zero past it. A row whose padding carries bytes is a
 * row whose signed digest and opened path could disagree. */
static enum state_offer_error name_shape(const struct state_offer_v1 *offer)
{
    if (offer->filename_len == 0 || offer->filename_len >= STATE_OFFER_NAME_MAX)
        return STATE_OFFER_NAME;
    for (size_t i = 0; i < offer->filename_len; i++) {
        uint8_t c = offer->filename[i];
        if (c <= 0x20u || c >= 0x7fu)
            return STATE_OFFER_NAME;
        if (c == '/' || c == '\\')
            return STATE_OFFER_NAME;
    }
    for (size_t i = offer->filename_len; i < STATE_OFFER_NAME_MAX; i++)
        if (offer->filename[i] != 0)
            return STATE_OFFER_NAME;
    if (offer->filename[0] == '.')
        return STATE_OFFER_NAME; /* ".", "..", and dotfiles alike */
    return STATE_OFFER_OK;
}

/* The offer must describe an artifact the RMF path would accept, or a consumer
 * would build a manifest rom_fetch_manifest_sane refuses and learn that only
 * after dialling. */
static enum state_offer_error chunking_shape(const struct state_offer_v1 *offer)
{
    if (offer->chunk_size != STATE_OFFER_CHUNK_SIZE_BYTES)
        return STATE_OFFER_CHUNKING;
    if (offer->content_bytes < ROM_SEED_MIN_ARTIFACT_BYTES ||
        offer->content_bytes > ROM_SEED_MAX_ARTIFACT_BYTES)
        return STATE_OFFER_CONTENT;
    if (offer->num_chunks == 0 || offer->num_chunks > ROM_SEED_MAX_CHUNKS)
        return STATE_OFFER_CHUNKING;
    uint64_t expect = (offer->content_bytes + offer->chunk_size - 1u) /
                      offer->chunk_size;
    if ((uint64_t)offer->num_chunks != expect)
        return STATE_OFFER_CHUNKING;
    return STATE_OFFER_OK;
}

static enum state_offer_error offer_shape(const struct state_offer_v1 *offer,
                                          bool require_signature)
{
    if (!offer)
        return STATE_OFFER_NULL;
    if (offer->version != STATE_OFFER_VERSION)
        return STATE_OFFER_VERSION_INVALID;
    if (offer->flags != STATE_OFFER_FLAGS_NONE)
        return STATE_OFFER_FLAGS;

    /* Every commitment an all-zero value would silently disable. chunk_tree_root
     * is in this list on purpose: it is the RMF serve-request key, so a zero
     * root is not "chunking not used yet", it is an unfetchable offer. */
    const uint8_t *critical[] = {
        offer->header_hash, offer->content_digest, offer->chunk_tree_root,
        offer->mmb_peaks_digest, offer->producer_receipt_id,
        offer->offerer_online_pubkey,
    };
    for (size_t i = 0; i < sizeof(critical) / sizeof(critical[0]); i++)
        if (!zcl_bytes_any_set(critical[i], 32))
            return STATE_OFFER_FIELD;

    if (offer->kind != (uint16_t)ROM_ARTIFACT_CONSENSUS_BUNDLE &&
        offer->kind != (uint16_t)ROM_ARTIFACT_HEADER_SEED)
        return STATE_OFFER_KIND;

    if (offer->bundle_height <= 0 || offer->offerer_tip_height <= 0 ||
        offer->bundle_height > offer->offerer_tip_height)
        return STATE_OFFER_HEIGHT;
    if (!state_offer_height_is_fresh(offer->bundle_height,
                                     offer->offerer_tip_height))
        return STATE_OFFER_STALE;

    enum state_offer_error error = chunking_shape(offer);
    if (error != STATE_OFFER_OK)
        return error;
    error = name_shape(offer);
    if (error != STATE_OFFER_OK)
        return error;

    if (offer->issued_unix < STATE_OFFER_MIN_ISSUED_UNIX)
        return STATE_OFFER_TIME;
    if (require_signature && !zcl_bytes_any_set(offer->signature, 64))
        return STATE_OFFER_SIGNATURE;
    return STATE_OFFER_OK;
}

enum state_offer_error state_offer_v1_validate(
    const struct state_offer_v1 *offer)
{
    return offer_shape(offer, false);
}

static size_t offer_write_unsigned(const struct state_offer_v1 *offer,
                                   uint8_t out[STATE_OFFER_V1_UNSIGNED_BYTES])
{
    size_t off = 0;
    memcpy(out + off, offer_magic, sizeof(offer_magic)); off += 8;
    zcl_write_u16_le(out + off, offer->version); off += 2;
    zcl_write_u16_le(out + off, offer->flags); off += 2;
    zcl_write_i32_le(out + off, offer->bundle_height); off += 4;
    zcl_write_i32_le(out + off, offer->offerer_tip_height); off += 4;
    zcl_write_u32_le(out + off, offer->chunk_size); off += 4;
    zcl_write_u32_le(out + off, offer->num_chunks); off += 4;
    zcl_write_u16_le(out + off, offer->kind); off += 2;
    zcl_write_u16_le(out + off, offer->filename_len); off += 2;
    memcpy(out + off, offer->header_hash, 32); off += 32;
    memcpy(out + off, offer->content_digest, 32); off += 32;
    memcpy(out + off, offer->chunk_tree_root, 32); off += 32;
    memcpy(out + off, offer->mmb_peaks_digest, 32); off += 32;
    memcpy(out + off, offer->producer_receipt_id, 32); off += 32;
    memcpy(out + off, offer->offerer_online_pubkey, 32); off += 32;
    zcl_write_u64_le(out + off, offer->content_bytes); off += 8;
    zcl_write_u64_le(out + off, offer->issued_unix); off += 8;
    memcpy(out + off, offer->filename, STATE_OFFER_NAME_MAX);
    off += STATE_OFFER_NAME_MAX;
    return off;
}

static enum state_offer_error offer_signing_root(
    const struct state_offer_v1 *offer, uint8_t out[32])
{
    enum state_offer_error error = offer_shape(offer, false);
    if (error != STATE_OFFER_OK)
        return error;
    uint8_t fixed[STATE_OFFER_V1_UNSIGNED_BYTES];
    if (offer_write_unsigned(offer, fixed) != sizeof(fixed)) {
        memory_cleanse(fixed, sizeof(fixed));
        return STATE_OFFER_SIZE;
    }
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)offer_signature_domain,
                   sizeof(offer_signature_domain) - 1u);
    sha3_256_write(&sha, fixed, sizeof(fixed));
    sha3_256_finalize(&sha, out);
    memory_cleanse(fixed, sizeof(fixed));
    return STATE_OFFER_OK;
}

enum state_offer_error state_offer_v1_root(const struct state_offer_v1 *offer,
                                           uint8_t out[32])
{
    if (!out)
        return STATE_OFFER_NULL;
    return offer_signing_root(offer, out);
}

enum state_offer_error state_offer_v1_sign(struct state_offer_v1 *offer,
                                           const uint8_t online_seed[32])
{
    if (!offer || !online_seed)
        return STATE_OFFER_NULL;
    uint8_t public_key[32];
    uint8_t secret[64];
    ed25519_keypair(public_key, secret, online_seed);
    /* Derived from the seed, never accepted from the caller: a row cannot name
     * a key it was not signed by. */
    memcpy(offer->offerer_online_pubkey, public_key, 32);

    uint8_t root[32];
    enum state_offer_error error = offer_signing_root(offer, root);
    if (error == STATE_OFFER_OK)
        ed25519_sign(offer->signature, root, sizeof(root), secret, public_key);
    memory_cleanse(secret, sizeof(secret));
    memory_cleanse(root, sizeof(root));
    return error;
}

enum state_offer_error state_offer_v1_verify(const struct state_offer_v1 *offer)
{
    enum state_offer_error error = offer_shape(offer, true);
    if (error != STATE_OFFER_OK)
        return error;
    uint8_t root[32];
    error = offer_signing_root(offer, root);
    if (error != STATE_OFFER_OK)
        return error;
    bool ok = ed25519_verify(offer->signature, root, sizeof(root),
                             offer->offerer_online_pubkey);
    memory_cleanse(root, sizeof(root));
    return ok ? STATE_OFFER_OK : STATE_OFFER_SIGNATURE;
}

bool state_offer_v1_filename(const struct state_offer_v1 *offer, char *out,
                             size_t out_capacity)
{
    if (!offer || !out || out_capacity == 0)
        return false;
    if (name_shape(offer) != STATE_OFFER_OK)
        return false;
    if ((size_t)offer->filename_len + 1u > out_capacity)
        return false;
    memcpy(out, offer->filename, offer->filename_len);
    out[offer->filename_len] = '\0';
    return true;
}

enum state_offer_error state_offer_v1_encode(
    const struct state_offer_v1 *offer, uint8_t out[STATE_OFFER_V1_WIRE_BYTES])
{
    if (!out)
        return STATE_OFFER_NULL;
    enum state_offer_error error = offer_shape(offer, true);
    if (error != STATE_OFFER_OK)
        return error;
    if (offer_write_unsigned(offer, out) != STATE_OFFER_V1_UNSIGNED_BYTES)
        return STATE_OFFER_SIZE;
    memcpy(out + STATE_OFFER_V1_UNSIGNED_BYTES, offer->signature, 64);
    return STATE_OFFER_OK;
}

enum state_offer_error state_offer_v1_decode(struct state_offer_v1 *out,
                                             const uint8_t *wire,
                                             size_t wire_len)
{
    if (!out || !wire)
        return STATE_OFFER_NULL;
    if (wire_len != STATE_OFFER_V1_WIRE_BYTES)
        return STATE_OFFER_SIZE;
    if (memcmp(wire, offer_magic, sizeof(offer_magic)) != 0)
        return STATE_OFFER_MAGIC;

    struct state_offer_v1 offer;
    memset(&offer, 0, sizeof(offer));
    size_t off = 8;
    offer.version = zcl_read_u16_le(wire + off); off += 2;
    offer.flags = zcl_read_u16_le(wire + off); off += 2;
    offer.bundle_height = zcl_read_i32_le(wire + off); off += 4;
    offer.offerer_tip_height = zcl_read_i32_le(wire + off); off += 4;
    offer.chunk_size = zcl_read_u32_le(wire + off); off += 4;
    offer.num_chunks = zcl_read_u32_le(wire + off); off += 4;
    offer.kind = zcl_read_u16_le(wire + off); off += 2;
    offer.filename_len = zcl_read_u16_le(wire + off); off += 2;
    memcpy(offer.header_hash, wire + off, 32); off += 32;
    memcpy(offer.content_digest, wire + off, 32); off += 32;
    memcpy(offer.chunk_tree_root, wire + off, 32); off += 32;
    memcpy(offer.mmb_peaks_digest, wire + off, 32); off += 32;
    memcpy(offer.producer_receipt_id, wire + off, 32); off += 32;
    memcpy(offer.offerer_online_pubkey, wire + off, 32); off += 32;
    offer.content_bytes = zcl_read_u64_le(wire + off); off += 8;
    offer.issued_unix = zcl_read_u64_le(wire + off); off += 8;
    memcpy(offer.filename, wire + off, STATE_OFFER_NAME_MAX);
    off += STATE_OFFER_NAME_MAX;
    memcpy(offer.signature, wire + off, 64); off += 64;
    if (off != STATE_OFFER_V1_WIRE_BYTES)
        return STATE_OFFER_SIZE;

    enum state_offer_error error = offer_shape(&offer, true);
    if (error != STATE_OFFER_OK)
        return error;
    *out = offer;
    return STATE_OFFER_OK;
}

size_t state_offer_batch_v1_wire_size(const struct state_offer_batch_v1 *batch)
{
    if (!batch || batch->count > STATE_OFFER_MAX_PER_PEER)
        return 0;
    return STATE_OFFER_BATCH_V1_HEADER_BYTES +
           (size_t)batch->count * STATE_OFFER_V1_WIRE_BYTES;
}

enum state_offer_error state_offer_batch_v1_validate(
    const struct state_offer_batch_v1 *batch)
{
    if (!batch)
        return STATE_OFFER_NULL;
    if (batch->version != STATE_OFFER_VERSION)
        return STATE_OFFER_VERSION_INVALID;
    if (batch->flags != STATE_OFFER_FLAGS_NONE)
        return STATE_OFFER_FLAGS;
    /* Fail closed on the DoS cap: refuse the whole batch, never truncate to the
     * cap. Truncating would let a sender choose which offers survive by
     * ordering, and would hide that the cap was reached at all. */
    if (batch->count > STATE_OFFER_MAX_PER_PEER)
        return STATE_OFFER_COUNT;
    if (batch->offerer_tip_height <= 0)
        return STATE_OFFER_HEIGHT;
    for (uint32_t i = 0; i < batch->count; i++) {
        /* One peer, one tip: a row disagreeing with the batch's declared tip
         * could claim a generous tip of its own and buy freshness it has not
         * earned. */
        if (batch->offers[i].offerer_tip_height != batch->offerer_tip_height)
            return STATE_OFFER_HEIGHT;
        enum state_offer_error error = offer_shape(&batch->offers[i], true);
        if (error != STATE_OFFER_OK)
            return error;
    }
    return STATE_OFFER_OK;
}

enum state_offer_error state_offer_batch_v1_encode(
    const struct state_offer_batch_v1 *batch, uint8_t *out, size_t out_capacity,
    size_t *out_len)
{
    if (!batch || !out || !out_len)
        return STATE_OFFER_NULL;
    enum state_offer_error error = state_offer_batch_v1_validate(batch);
    if (error != STATE_OFFER_OK)
        return error;
    size_t need = state_offer_batch_v1_wire_size(batch);
    if (need == 0 || need > out_capacity)
        return STATE_OFFER_SIZE;

    size_t off = 0;
    memcpy(out + off, batch_magic, sizeof(batch_magic)); off += 8;
    zcl_write_u16_le(out + off, batch->version); off += 2;
    zcl_write_u16_le(out + off, batch->flags); off += 2;
    zcl_write_u32_le(out + off, batch->count); off += 4;
    zcl_write_i32_le(out + off, batch->offerer_tip_height); off += 4;
    if (off != STATE_OFFER_BATCH_V1_HEADER_BYTES)
        return STATE_OFFER_SIZE;
    for (uint32_t i = 0; i < batch->count; i++) {
        error = state_offer_v1_encode(&batch->offers[i], out + off);
        if (error != STATE_OFFER_OK)
            return error;
        off += STATE_OFFER_V1_WIRE_BYTES;
    }
    *out_len = off;
    return STATE_OFFER_OK;
}

enum state_offer_error state_offer_batch_v1_decode(
    struct state_offer_batch_v1 *out, const uint8_t *wire, size_t wire_len)
{
    if (!out || !wire)
        return STATE_OFFER_NULL;
    if (wire_len < STATE_OFFER_BATCH_V1_HEADER_BYTES ||
        wire_len > STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES)
        return STATE_OFFER_SIZE;
    if (memcmp(wire, batch_magic, sizeof(batch_magic)) != 0)
        return STATE_OFFER_MAGIC;

    struct state_offer_batch_v1 batch;
    memset(&batch, 0, sizeof(batch));
    size_t off = 8;
    batch.version = zcl_read_u16_le(wire + off); off += 2;
    batch.flags = zcl_read_u16_le(wire + off); off += 2;
    batch.count = zcl_read_u32_le(wire + off); off += 4;
    batch.offerer_tip_height = zcl_read_i32_le(wire + off); off += 4;

    if (batch.version != STATE_OFFER_VERSION)
        return STATE_OFFER_VERSION_INVALID;
    if (batch.flags != STATE_OFFER_FLAGS_NONE)
        return STATE_OFFER_FLAGS;
    /* The DECLARED count is capped before any arithmetic uses it, so an
     * oversized count can neither index past the fixed array nor be silently
     * truncated, and the refusal names the cap rather than a size mismatch. */
    if (batch.count > STATE_OFFER_MAX_PER_PEER)
        return STATE_OFFER_COUNT;
    if (wire_len != STATE_OFFER_BATCH_V1_HEADER_BYTES +
                        (size_t)batch.count * STATE_OFFER_V1_WIRE_BYTES)
        return STATE_OFFER_SIZE;

    for (uint32_t i = 0; i < batch.count; i++) {
        enum state_offer_error error = state_offer_v1_decode(
            &batch.offers[i], wire + off, STATE_OFFER_V1_WIRE_BYTES);
        if (error != STATE_OFFER_OK)
            return error;
        off += STATE_OFFER_V1_WIRE_BYTES;
    }
    enum state_offer_error error = state_offer_batch_v1_validate(&batch);
    if (error != STATE_OFFER_OK)
        return error;
    *out = batch;
    return STATE_OFFER_OK;
}
