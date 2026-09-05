/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Adversarial acceptance for the signed state-offer wire (ZRC-0011).
 *
 * Every refusal below must arrive BY NAME. A test that only asserted "decode
 * failed" would pass just as happily if the parser collapsed the freshness rule
 * and the digest rule into one vague error — exactly the collapse a peer-facing
 * parser must never be allowed to make, because a caller scores a stale offerer
 * and a forging offerer differently. */

#include "test/test_core.h"

#include "base/bytes.h"
#include "crypto/ed25519.h"
#include "net/state_offer.h"

#include <string.h>

/* Wire offsets the tamper cases below poke directly. Named here so a layout
 * change breaks the static assertion instead of silently making a tamper test
 * hit the wrong field and still "pass". */
#define OFF_BUNDLE_HEIGHT 12u
#define OFF_BATCH_COUNT 12u

_Static_assert(STATE_OFFER_V1_WIRE_BYTES == 432u,
               "state offer v1 wire size is frozen; a change is a wire change");
_Static_assert(STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES == 20u + 4u * 432u,
               "state offer batch ceiling is frozen");

static void fill_bytes(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(first + i);
}

static void seed_bytes(uint8_t seed[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++)
        seed[i] = (uint8_t)(first ^ (uint8_t)(i * 7u + 3u));
}

static void set_name(struct state_offer_v1 *offer, const char *name)
{
    size_t len = strlen(name);
    memset(offer->filename, 0, sizeof(offer->filename));
    memcpy(offer->filename, name, len);
    offer->filename_len = (uint16_t)len;
}

/* A well-formed, in-window, SIGNED offer at the given height — the shape a
 * consumer actually receives. It is signed here because a decoded row must name
 * the identity that signed it, so an offer with an all-zero pubkey is malformed
 * by construction and would make every shape assertion below read as a field
 * refusal rather than the rule it is meant to prove. When the requested height
 * is out of window the sign call refuses (that IS the rule under test) and the
 * row is returned unsigned, still carrying the advertised key. */
static void make_offer(struct state_offer_v1 *offer, int32_t bundle_height,
                       int32_t tip_height)
{
    memset(offer, 0, sizeof(*offer));
    offer->version = STATE_OFFER_VERSION;
    offer->flags = STATE_OFFER_FLAGS_NONE;
    offer->bundle_height = bundle_height;
    offer->offerer_tip_height = tip_height;
    offer->chunk_size = STATE_OFFER_CHUNK_SIZE_BYTES;
    offer->content_bytes = (uint64_t)STATE_OFFER_CHUNK_SIZE_BYTES * 64u + 17u;
    offer->num_chunks = 65u; /* ceil(64 chunks + 17 bytes) */
    offer->kind = (uint16_t)ROM_ARTIFACT_CONSENSUS_BUNDLE;
    fill_bytes(offer->header_hash, 0x11);
    fill_bytes(offer->content_digest, 0x31);
    fill_bytes(offer->chunk_tree_root, 0x51);
    fill_bytes(offer->mmb_peaks_digest, 0x71);
    fill_bytes(offer->producer_receipt_id, 0x91);
    offer->issued_unix = UINT64_C(1800000000);
    set_name(offer, "consensus-state-bundle-1000000.sqlite");

    uint8_t seed[32];
    seed_bytes(seed, 0x0d);
    (void)state_offer_v1_sign(offer, seed);
}

static int offer_roundtrip(void)
{
    int failures = 0;
    TEST_CASE("state offer v1 round-trips through the wire unchanged") {
        struct state_offer_v1 offer;
        uint8_t seed[32];
        make_offer(&offer, 1000000, 1000000);
        seed_bytes(seed, 0x5a);
        ASSERT_EQ(state_offer_v1_sign(&offer, seed), STATE_OFFER_OK);
        ASSERT_EQ(state_offer_v1_verify(&offer), STATE_OFFER_OK);

        /* The advertised key is DERIVED from the signing seed, never taken from
         * the caller — a row cannot name a key it was not signed by. */
        uint8_t pk[32], sk[64];
        ed25519_keypair(pk, sk, seed);
        ASSERT(memcmp(offer.offerer_online_pubkey, pk, 32) == 0);

        uint8_t wire[STATE_OFFER_V1_WIRE_BYTES];
        ASSERT_EQ(state_offer_v1_encode(&offer, wire), STATE_OFFER_OK);
        struct state_offer_v1 back;
        ASSERT_EQ(state_offer_v1_decode(&back, wire, sizeof(wire)),
                  STATE_OFFER_OK);
        ASSERT(memcmp(&back, &offer, sizeof(offer)) == 0);
        ASSERT_EQ(state_offer_v1_verify(&back), STATE_OFFER_OK);

        char name[STATE_OFFER_NAME_MAX];
        ASSERT(state_offer_v1_filename(&back, name, sizeof(name)));
        ASSERT(strlen(name) == back.filename_len);
        /* A buffer one byte short of the NUL refuses rather than truncating. */
        char tight[8];
        ASSERT(!state_offer_v1_filename(&back, tight, sizeof(tight)));

        /* Two independent roots over the same row agree; a different row does
         * not share a root. */
        uint8_t root_a[32], root_b[32];
        ASSERT_EQ(state_offer_v1_root(&offer, root_a), STATE_OFFER_OK);
        ASSERT_EQ(state_offer_v1_root(&back, root_b), STATE_OFFER_OK);
        ASSERT(memcmp(root_a, root_b, 32) == 0);
        struct state_offer_v1 other = offer;
        other.bundle_height -= 1;
        ASSERT_EQ(state_offer_v1_root(&other, root_b), STATE_OFFER_OK);
        ASSERT(memcmp(root_a, root_b, 32) != 0);
    } TEST_END
    return failures;
}

static int offer_freshness_refusal(void)
{
    int failures = 0;
    TEST_CASE("the 576-block freshness rule refuses a stale offer by name") {
        /* The BOUNDARY is the whole rule. Exactly 576 behind is the last
         * acceptable offer; 577 behind is the first refusal. A mutation that
         * turns <= into <, or 576 into 575 or 577, must fail HERE. */
        ASSERT(state_offer_height_is_fresh(1000000 - 576, 1000000));
        ASSERT(!state_offer_height_is_fresh(1000000 - 577, 1000000));
        ASSERT(state_offer_height_is_fresh(1000000 - 575, 1000000));
        ASSERT(state_offer_height_is_fresh(1000000, 1000000));
        ASSERT(!state_offer_height_is_fresh(1000001, 1000000));
        ASSERT(!state_offer_height_is_fresh(0, 1000000));
        ASSERT(!state_offer_height_is_fresh(-1, 1000000));
        ASSERT(!state_offer_height_is_fresh(1000, 0));
        ASSERT(!state_offer_height_is_fresh(1000, -1));
        /* Extremes must not wrap into "fresh". */
        ASSERT(!state_offer_height_is_fresh(1, INT32_MAX));
        ASSERT(!state_offer_height_is_fresh(INT32_MIN, INT32_MAX));
        ASSERT(state_offer_height_is_fresh(INT32_MAX, INT32_MAX));

        struct state_offer_v1 offer;
        uint8_t seed[32];
        seed_bytes(seed, 0x11);

        make_offer(&offer, 1000000 - 576, 1000000);
        ASSERT_EQ(state_offer_v1_validate(&offer), STATE_OFFER_OK);
        ASSERT_EQ(state_offer_v1_sign(&offer, seed), STATE_OFFER_OK);
        uint8_t fresh_wire[STATE_OFFER_V1_WIRE_BYTES];
        ASSERT_EQ(state_offer_v1_encode(&offer, fresh_wire), STATE_OFFER_OK);
        struct state_offer_v1 back;
        ASSERT_EQ(state_offer_v1_decode(&back, fresh_wire, sizeof(fresh_wire)),
                  STATE_OFFER_OK);

        /* One block staler: refused, and refused by the STALE name — not by a
         * generic size or field error a caller could not act on. */
        struct state_offer_v1 stale;
        make_offer(&stale, 1000000 - 577, 1000000);
        ASSERT_EQ(state_offer_v1_validate(&stale), STATE_OFFER_STALE);
        /* Signing refuses a stale row too, so a node cannot mint a stale offer
         * and leave the consumer to be the only thing that catches it. */
        ASSERT_EQ(state_offer_v1_sign(&stale, seed), STATE_OFFER_STALE);
        uint8_t unused[STATE_OFFER_V1_WIRE_BYTES];
        ASSERT_EQ(state_offer_v1_encode(&stale, unused), STATE_OFFER_STALE);

        /* A row signed while fresh and then rewritten staler must not decode.
         * The parse refuses BEFORE any signature question, so a rewritten row
         * cannot slip past a caller that only checks signatures. */
        uint8_t tampered[STATE_OFFER_V1_WIRE_BYTES];
        memcpy(tampered, fresh_wire, sizeof(tampered));
        int32_t staler = 1000000 - 5000;
        tampered[OFF_BUNDLE_HEIGHT + 0] = (uint8_t)(staler & 0xff);
        tampered[OFF_BUNDLE_HEIGHT + 1] = (uint8_t)((staler >> 8) & 0xff);
        tampered[OFF_BUNDLE_HEIGHT + 2] = (uint8_t)((staler >> 16) & 0xff);
        tampered[OFF_BUNDLE_HEIGHT + 3] = (uint8_t)((staler >> 24) & 0xff);
        ASSERT_EQ(state_offer_v1_decode(&back, tampered, sizeof(tampered)),
                  STATE_OFFER_STALE);

        /* Above the offerer's own tip is a HEIGHT refusal, not a STALE one. */
        struct state_offer_v1 above;
        make_offer(&above, 1000001, 1000000);
        ASSERT_EQ(state_offer_v1_validate(&above), STATE_OFFER_HEIGHT);
        make_offer(&above, 0, 1000000);
        ASSERT_EQ(state_offer_v1_validate(&above), STATE_OFFER_HEIGHT);
    } TEST_END
    return failures;
}

static int offer_field_refusals(void)
{
    int failures = 0;
    TEST_CASE("state offer refuses each malformed field by its own name") {
        struct state_offer_v1 base;
        struct state_offer_v1 trial;
        make_offer(&base, 900000, 900000);
        ASSERT_EQ(state_offer_v1_validate(&base), STATE_OFFER_OK);

        trial = base;
        trial.version = STATE_OFFER_VERSION + 1u;
        ASSERT_EQ(state_offer_v1_validate(&trial),
                  STATE_OFFER_VERSION_INVALID);

        trial = base;
        trial.flags = 1u;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_FLAGS);

        /* An all-zero content digest is not a digest. This is the refusal that
         * stops a peer from offering "some bytes, trust me". */
        trial = base;
        memset(trial.content_digest, 0, sizeof(trial.content_digest));
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_FIELD);

        /* An all-zero chunk root is an UNFETCHABLE offer, not "chunking unused":
         * the root is the RMF serve-request key. */
        trial = base;
        memset(trial.chunk_tree_root, 0, sizeof(trial.chunk_tree_root));
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_FIELD);

        trial = base;
        memset(trial.header_hash, 0, sizeof(trial.header_hash));
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_FIELD);

        trial = base;
        memset(trial.producer_receipt_id, 0, sizeof(trial.producer_receipt_id));
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_FIELD);

        trial = base;
        memset(trial.mmb_peaks_digest, 0, sizeof(trial.mmb_peaks_digest));
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_FIELD);

        trial = base;
        trial.kind = (uint16_t)ROM_ARTIFACT_UNKNOWN;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_KIND);
        trial.kind = (uint16_t)ROM_ARTIFACT_SOURCE_BUNDLE;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_KIND);
        trial.kind = (uint16_t)ROM_ARTIFACT_HEADER_SEED;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_OK);

        /* Chunking must agree with the RMF path's own arithmetic, or a consumer
         * would build a manifest rom_fetch_manifest_sane refuses and learn that
         * only after dialling. */
        trial = base;
        trial.chunk_size = STATE_OFFER_CHUNK_SIZE_BYTES / 2u;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_CHUNKING);

        trial = base;
        trial.num_chunks = base.num_chunks + 1u;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_CHUNKING);
        trial.num_chunks = 0;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_CHUNKING);

        trial = base;
        trial.content_bytes = ROM_SEED_MIN_ARTIFACT_BYTES - 1u;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_CONTENT);
        trial.content_bytes = ROM_SEED_MAX_ARTIFACT_BYTES + 1u;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_CONTENT);
        trial.content_bytes = 0;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_CONTENT);

        /* A path separator or a traversal in the offered name would let a peer
         * choose where a consumer writes. Refused by name. */
        trial = base;
        set_name(&trial, "../escape.sqlite");
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_NAME);
        trial = base;
        set_name(&trial, "sub/dir.sqlite");
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_NAME);
        trial = base;
        set_name(&trial, "sub\\dir.sqlite");
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_NAME);
        trial = base;
        set_name(&trial, ".hidden");
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_NAME);
        trial = base;
        trial.filename_len = 0;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_NAME);
        trial = base;
        trial.filename_len = STATE_OFFER_NAME_MAX;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_NAME);
        /* Bytes past the declared length must be zero, or the signed digest and
         * the opened path could disagree. */
        trial = base;
        trial.filename[STATE_OFFER_NAME_MAX - 1u] = 'x';
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_NAME);
        trial = base;
        trial.filename[1] = 0;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_NAME);
        trial = base;
        trial.filename[1] = ' ';
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_NAME);

        trial = base;
        trial.issued_unix = 1;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_TIME);
        trial.issued_unix = 0;
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_TIME);
    } TEST_END
    return failures;
}

static int offer_signature(void)
{
    int failures = 0;
    TEST_CASE("a tampered offer fails the signature, not the shape check") {
        struct state_offer_v1 offer;
        uint8_t seed[32];
        make_offer(&offer, 700000, 700100);
        seed_bytes(seed, 0x2c);
        ASSERT_EQ(state_offer_v1_sign(&offer, seed), STATE_OFFER_OK);

        struct state_offer_v1 trial = offer;
        /* Same shape, different committed digest: the row still PARSES, so the
         * only thing between a consumer and a lie is the signature. */
        fill_bytes(trial.content_digest, 0xa5);
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_OK);
        ASSERT_EQ(state_offer_v1_verify(&trial), STATE_OFFER_SIGNATURE);

        trial = offer;
        fill_bytes(trial.chunk_tree_root, 0xb6);
        ASSERT_EQ(state_offer_v1_validate(&trial), STATE_OFFER_OK);
        ASSERT_EQ(state_offer_v1_verify(&trial), STATE_OFFER_SIGNATURE);

        trial = offer;
        trial.bundle_height = 700100;
        ASSERT_EQ(state_offer_v1_verify(&trial), STATE_OFFER_SIGNATURE);

        trial = offer;
        set_name(&trial, "consensus-state-bundle-700100.sqlite");
        ASSERT_EQ(state_offer_v1_verify(&trial), STATE_OFFER_SIGNATURE);

        trial = offer;
        memset(trial.signature, 0, sizeof(trial.signature));
        ASSERT_EQ(state_offer_v1_verify(&trial), STATE_OFFER_SIGNATURE);

        trial = offer;
        trial.signature[0] ^= 0x01u;
        ASSERT_EQ(state_offer_v1_verify(&trial), STATE_OFFER_SIGNATURE);

        /* Swapping in another node's key does not rescue the signature. */
        trial = offer;
        uint8_t other_seed[32], other_pk[32], other_sk[64];
        seed_bytes(other_seed, 0x77);
        ed25519_keypair(other_pk, other_sk, other_seed);
        memcpy(trial.offerer_online_pubkey, other_pk, 32);
        ASSERT_EQ(state_offer_v1_verify(&trial), STATE_OFFER_SIGNATURE);

        /* And re-signing under the other identity re-advertises THAT key —
         * the row stays attributable to whoever actually signed it. */
        ASSERT_EQ(state_offer_v1_sign(&trial, other_seed), STATE_OFFER_OK);
        ASSERT_EQ(state_offer_v1_verify(&trial), STATE_OFFER_OK);
        ASSERT(memcmp(trial.offerer_online_pubkey, other_pk, 32) == 0);
    } TEST_END
    return failures;
}

static int batch_cap_and_bounds(void)
{
    int failures = 0;
    TEST_CASE("a batch at the per-peer cap round-trips; one over is refused") {
        struct state_offer_batch_v1 batch;
        uint8_t seed[32];
        seed_bytes(seed, 0x3e);
        memset(&batch, 0, sizeof(batch));
        batch.version = STATE_OFFER_VERSION;
        batch.flags = STATE_OFFER_FLAGS_NONE;
        batch.count = STATE_OFFER_MAX_PER_PEER;
        batch.offerer_tip_height = 800000;
        for (uint32_t i = 0; i < batch.count; i++) {
            make_offer(&batch.offers[i], 800000 - (int32_t)(i * 100u), 800000);
            fill_bytes(batch.offers[i].content_digest, (uint8_t)(0x40u + i));
            ASSERT_EQ(state_offer_v1_sign(&batch.offers[i], seed),
                      STATE_OFFER_OK);
        }
        ASSERT_EQ(state_offer_batch_v1_validate(&batch), STATE_OFFER_OK);

        uint8_t wire[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(state_offer_batch_v1_encode(&batch, wire, sizeof(wire),
                                              &wire_len),
                  STATE_OFFER_OK);
        ASSERT(wire_len == state_offer_batch_v1_wire_size(&batch));
        ASSERT(wire_len == sizeof(wire));

        struct state_offer_batch_v1 back;
        ASSERT_EQ(state_offer_batch_v1_decode(&back, wire, wire_len),
                  STATE_OFFER_OK);
        ASSERT(back.count == batch.count);
        for (uint32_t i = 0; i < batch.count; i++)
            ASSERT(memcmp(&back.offers[i], &batch.offers[i],
                               sizeof(back.offers[i])) == 0);

        /* One over the cap: the DECLARED count is refused BY NAME before any
         * arithmetic uses it, so an oversized count can neither index past the
         * fixed array nor be silently truncated to the cap. */
        uint8_t over[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
        memcpy(over, wire, sizeof(over));
        over[OFF_BATCH_COUNT] = (uint8_t)(STATE_OFFER_MAX_PER_PEER + 1u);
        ASSERT_EQ(state_offer_batch_v1_decode(&back, over, sizeof(over)),
                  STATE_OFFER_COUNT);
        /* A wildly oversized count is the SAME named refusal, never a crash. */
        over[OFF_BATCH_COUNT + 0] = 0xffu; over[OFF_BATCH_COUNT + 1] = 0xffu;
        over[OFF_BATCH_COUNT + 2] = 0xffu; over[OFF_BATCH_COUNT + 3] = 0xffu;
        ASSERT_EQ(state_offer_batch_v1_decode(&back, over, sizeof(over)),
                  STATE_OFFER_COUNT);

        struct state_offer_batch_v1 too_many = batch;
        too_many.count = STATE_OFFER_MAX_PER_PEER + 1u;
        ASSERT_EQ(state_offer_batch_v1_validate(&too_many), STATE_OFFER_COUNT);
        ASSERT(state_offer_batch_v1_wire_size(&too_many) == 0);
        size_t len = 0;
        ASSERT_EQ(state_offer_batch_v1_encode(&too_many, wire, sizeof(wire),
                                              &len),
                  STATE_OFFER_COUNT);

        /* An EMPTY batch is legal — a peer with a file service and no eligible
         * bundle still advertises its port and says "nothing fresh". */
        struct state_offer_batch_v1 empty;
        memset(&empty, 0, sizeof(empty));
        empty.version = STATE_OFFER_VERSION;
        empty.count = 0;
        empty.offerer_tip_height = 800000;
        ASSERT_EQ(state_offer_batch_v1_validate(&empty), STATE_OFFER_OK);
        ASSERT_EQ(state_offer_batch_v1_encode(&empty, wire, sizeof(wire), &len),
                  STATE_OFFER_OK);
        ASSERT(len == STATE_OFFER_BATCH_V1_HEADER_BYTES);
        ASSERT_EQ(state_offer_batch_v1_decode(&back, wire, len),
                  STATE_OFFER_OK);
        ASSERT(back.count == 0);
    } TEST_END
    return failures;
}

static int batch_bounds(void)
{
    int failures = 0;
    TEST_CASE("batch decode refuses truncation, bad magic and tip disagreement") {
        struct state_offer_batch_v1 batch;
        uint8_t seed[32];
        seed_bytes(seed, 0x62);
        memset(&batch, 0, sizeof(batch));
        batch.version = STATE_OFFER_VERSION;
        batch.count = 2;
        batch.offerer_tip_height = 810000;
        for (uint32_t i = 0; i < batch.count; i++) {
            make_offer(&batch.offers[i], 810000 - (int32_t)(i * 10u), 810000);
            ASSERT_EQ(state_offer_v1_sign(&batch.offers[i], seed),
                      STATE_OFFER_OK);
        }
        uint8_t wire[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
        size_t wire_len = 0;
        ASSERT_EQ(state_offer_batch_v1_encode(&batch, wire, sizeof(wire),
                                              &wire_len),
                  STATE_OFFER_OK);

        struct state_offer_batch_v1 back;
        /* Every truncation length is a named refusal, never a partial parse. */
        for (size_t cut = 1; cut < wire_len; cut += 29) {
            enum state_offer_error e =
                state_offer_batch_v1_decode(&back, wire, cut);
            ASSERT(e == STATE_OFFER_SIZE || e == STATE_OFFER_MAGIC);
        }
        ASSERT_EQ(state_offer_batch_v1_decode(&back, wire, wire_len + 1u),
                  STATE_OFFER_SIZE);
        ASSERT_EQ(state_offer_batch_v1_decode(
                      &back, wire, STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES + 1u),
                  STATE_OFFER_SIZE);

        uint8_t bad_magic[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
        memcpy(bad_magic, wire, wire_len);
        bad_magic[0] ^= 0xffu;
        ASSERT_EQ(state_offer_batch_v1_decode(&back, bad_magic, wire_len),
                  STATE_OFFER_MAGIC);

        /* One peer, one tip: a row claiming a more generous tip than the batch
         * declared would buy itself freshness it has not earned. */
        struct state_offer_batch_v1 mixed = batch;
        mixed.offers[1].offerer_tip_height = 810000 + 5000;
        ASSERT_EQ(state_offer_batch_v1_validate(&mixed), STATE_OFFER_HEIGHT);

        /* A batch carrying ONE stale row is refused WHOLE — a consumer never
         * sees a half-accepted batch. */
        struct state_offer_batch_v1 one_stale = batch;
        one_stale.offers[1].bundle_height =
            batch.offerer_tip_height - (STATE_OFFER_FRESHNESS_BLOCKS + 1);
        ASSERT_EQ(state_offer_batch_v1_validate(&one_stale), STATE_OFFER_STALE);

        /* Likewise one unsigned row. */
        struct state_offer_batch_v1 one_unsigned = batch;
        memset(one_unsigned.offers[0].signature, 0, 64);
        ASSERT_EQ(state_offer_batch_v1_validate(&one_unsigned),
                  STATE_OFFER_SIGNATURE);
    } TEST_END
    return failures;
}

static int null_and_empty_inputs(void)
{
    int failures = 0;
    TEST_CASE("null and zero-length inputs are refused, never dereferenced") {
        struct state_offer_v1 offer;
        struct state_offer_batch_v1 batch;
        uint8_t wire[STATE_OFFER_V1_WIRE_BYTES];
        char namebuf[STATE_OFFER_NAME_MAX];
        size_t len = 0;
        memset(wire, 0, sizeof(wire));
        ASSERT_EQ(state_offer_v1_validate(NULL), STATE_OFFER_NULL);
        ASSERT_EQ(state_offer_v1_decode(NULL, wire, sizeof(wire)),
                  STATE_OFFER_NULL);
        ASSERT_EQ(state_offer_v1_decode(&offer, NULL, sizeof(wire)),
                  STATE_OFFER_NULL);
        ASSERT_EQ(state_offer_v1_decode(&offer, wire, 0), STATE_OFFER_SIZE);
        /* An all-zero buffer of the right length is a MAGIC refusal. */
        ASSERT_EQ(state_offer_v1_decode(&offer, wire, sizeof(wire)),
                  STATE_OFFER_MAGIC);
        ASSERT_EQ(state_offer_v1_sign(NULL, NULL), STATE_OFFER_NULL);
        ASSERT_EQ(state_offer_v1_verify(NULL), STATE_OFFER_NULL);
        ASSERT_EQ(state_offer_v1_root(NULL, NULL), STATE_OFFER_NULL);
        ASSERT_EQ(state_offer_batch_v1_validate(NULL), STATE_OFFER_NULL);
        ASSERT_EQ(state_offer_batch_v1_decode(NULL, wire, sizeof(wire)),
                  STATE_OFFER_NULL);
        ASSERT_EQ(state_offer_batch_v1_encode(NULL, wire, sizeof(wire), &len),
                  STATE_OFFER_NULL);
        ASSERT(state_offer_batch_v1_wire_size(NULL) == 0);
        ASSERT(!state_offer_v1_filename(NULL, namebuf, sizeof(namebuf)));
        memset(&batch, 0, sizeof(batch));
        ASSERT_EQ(state_offer_batch_v1_validate(&batch),
                  STATE_OFFER_VERSION_INVALID);
        /* Every named error has a name; none falls through to "unknown". */
        for (int e = STATE_OFFER_OK; e <= STATE_OFFER_SIGNATURE; e++)
            ASSERT(strcmp(state_offer_error_string(
                                   (enum state_offer_error)e),
                               "unknown") != 0);
    } TEST_END
    return failures;
}

int test_state_offer(void)
{
    int failures = 0;

    failures += offer_roundtrip();
    failures += offer_freshness_refusal();
    failures += offer_field_refusals();
    failures += offer_signature();
    failures += batch_cap_and_bounds();
    failures += batch_bounds();
    failures += null_and_empty_inputs();
    return failures;
}
