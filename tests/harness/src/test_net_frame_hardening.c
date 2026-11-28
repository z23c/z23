/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * net_frame_hardening — decode-path refusal proofs for inbound P2P wire
 * parsing. A hostile peer fully controls every byte of a message body, so
 * every deserializer that the dispatch table feeds peer bytes to must REFUSE
 * a malformed frame with its existing typed failure (a false return through
 * the bounded stream reader / LOG_FAIL) instead of over-reading, trusting a
 * declared size, or leaving partially-applied state.
 *
 * This group pins those refusals so the hardening cannot silently regress.
 * Each audited site family is fed three hostile shapes:
 *
 *   1. TRUNCATED      — the frame ends mid-field.
 *   2. OVERSIZED      — a declared count/length exceeds its protocol cap
 *                       (MAX_INV_SZ / MAX_SOLUTION_SIZE / MAX_TX_INPUTS /
 *                       MAX_COMPACT_BLOCK_TXNS / ZMSG_MAX_* ...).
 *   3. OVER-REMAINING — the declared count/length is within its cap but
 *                       exceeds the bytes actually present (the
 *                       "claim 10M items, send 3 bytes" pre-allocation
 *                       shape).
 *
 * plus a VALID control per family so a refusal is never vacuous, and —
 * where the refusal comes from a failed read — an assertion that the
 * stream's error is latched (the cursor is frozen: nothing further can be
 * consumed from a refused frame, which is the decode-level "never
 * partially applied" proof). Every object that survives a refusal is
 * released through its normal _free() to prove teardown stays clean.
 *
 * Level map: net_framing_dos (test_net_msg_dos.c) pins the 24-byte framing
 * layer and handler-level DoS scoring; this group pins the deserializers
 * one level down. */

#include "test/test_core.h"

#include "base/hex.h"
#include "core/serialize.h"
#include "crypto/sha256.h"
#include "bloom/merkle.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "net/p2p_message.h"
#include "net/protocol.h"
#include "net/compact_blocks.h"
#include "net/zmsg.h"
#include "net/file_market.h"
#include "transaction_v6_ironwood_fixture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NETH_CHECK(name, expr) do { \
    printf("net_frame_hardening: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Feed the first `len` bytes of a written payload to a deserializer as a
 * read-only stream. Mirrors stream_init_from_data's const-borrow contract:
 * the reader never owns or frees w->data. */
static void neth_reader(struct byte_stream *r, const struct byte_stream *w,
                        size_t len)
{
    if (len > w->size)
        len = w->size;
    stream_init_from_data(r, w->data, len);
}

/* ── 1. version_message_deserialize (p2p_message.c:35) ────────
 * Fixed-prefix fields, then a compact-size subver length into
 * sub_version[256]. Guard: subver_len >= MAX_SUBVER_LENGTH refused
 * before the read; a short body fails through the bounded reader. */
static int neth_case_version_message(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct version_message v;
    struct version_message good;

    /* Valid control. */
    version_message_init(&good);
    good.protocol_version = 170100;
    good.services = 0x1;
    good.timestamp = 1700000000;
    good.nonce = 0x4242424242424242ULL;
    snprintf(good.sub_version, sizeof(good.sub_version), "/neth:0.1/");
    good.start_height = 42;
    good.relay = true;
    stream_init(&w, 256);
    NETH_CHECK("version: valid control serializes",
               version_message_serialize(&good, &w));
    neth_reader(&r, &w, w.size);
    version_message_init(&v);
    NETH_CHECK("version: valid control deserializes",
               version_message_deserialize(&v, &r));
    NETH_CHECK("version: control payload fully consumed",
               r.error == false && r.read_pos == r.size);
    stream_free(&r);

    /* Truncated mid addr_recv (the prefix is 4+8+8+26+26+8+subver). */
    neth_reader(&r, &w, 30);
    version_message_init(&v);
    NETH_CHECK("version: truncated frame refused",
               version_message_deserialize(&v, &r) == false);
    NETH_CHECK("version: truncated frame latched stream error",
               r.error == true);
    stream_free(&r);
    stream_free(&w);

    /* Handcraft the fixed prefix up to (and including) the nonce so
     * the next field on the wire is exactly the subver length. */
    stream_init(&w, 128);
    NETH_CHECK("version: handcrafted prefix serializes",
               stream_write_i32_le(&w, good.protocol_version) &&
               stream_write_u64_le(&w, good.services) &&
               stream_write_i64_le(&w, good.timestamp) &&
               net_address_serialize(&good.addr_recv, &w, false) &&
               net_address_serialize(&good.addr_from, &w, false) &&
               stream_write_u64_le(&w, good.nonce));

    /* Oversized subver length: 300 >= MAX_SUBVER_LENGTH (256) must be
     * refused BEFORE the fixed buffer is touched. */
    stream_write_compact_size(&w, 300);
    neth_reader(&r, &w, w.size);
    version_message_init(&v);
    NETH_CHECK("version: subver_len 300 >= MAX_SUBVER_LENGTH refused",
               version_message_deserialize(&v, &r) == false);
    stream_free(&r);

    /* Over-remaining: declared subver_len 100, zero bytes behind it. */
    w.size = 80; /* rewind the stream: keep the prefix, drop the count */
    stream_write_compact_size(&w, 100);
    neth_reader(&r, &w, w.size);
    version_message_init(&v);
    NETH_CHECK("version: subver_len 100 with no bytes refused",
               version_message_deserialize(&v, &r) == false);
    NETH_CHECK("version: over-remaining refusal latched error",
               r.error == true);
    stream_free(&r);
    stream_free(&w);

    return failures;
}

/* ── 2. net_address / inv_item (protocol.c:150, protocol.c:170) ── */
static int neth_case_netaddr_inv(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct net_address a;
    struct inv_item inv;

    /* Valid control (with timestamp: 4+8+16+2 = 30 bytes). */
    stream_init(&w, 64);
    stream_write_u32_le(&w, 1700000000u);
    stream_write_u64_le(&w, 1);
    unsigned char ip[16] = {0};
    ip[10] = 0xff; ip[11] = 0xff; ip[12] = 203; ip[13] = 0;
    ip[14] = 113; ip[15] = 91;
    stream_write_bytes(&w, ip, sizeof(ip));
    unsigned char port[2] = {0x1f, 0x5b};
    stream_write_bytes(&w, port, sizeof(port));
    neth_reader(&r, &w, w.size);
    net_address_init(&a);
    NETH_CHECK("netaddr: valid control deserializes",
               net_address_deserialize(&a, &r, true));
    stream_free(&r);

    /* Truncated mid-ip. */
    neth_reader(&r, &w, 16);
    net_address_init(&a);
    NETH_CHECK("netaddr: truncated frame refused",
               net_address_deserialize(&a, &r, true) == false);
    NETH_CHECK("netaddr: refusal latched stream error", r.error == true);
    stream_free(&r);
    stream_free(&w);

    /* inv_item: type present, hash truncated. */
    stream_init(&w, 40);
    stream_write_u32_le(&w, 1);
    unsigned char short_hash[10] = {0};
    stream_write_bytes(&w, short_hash, sizeof(short_hash));
    neth_reader(&r, &w, w.size);
    NETH_CHECK("inv: truncated hash refused",
               inv_item_deserialize(&inv, &r) == false);
    NETH_CHECK("inv: refusal latched stream error", r.error == true);
    stream_free(&r);
    stream_free(&w);

    return failures;
}

/* ── 3. block_locator_deserialize (block.c:149) ───────────────
 * vhave is clamped to MAX_LOCATOR_HASHES (64); excess entries are
 * read-and-discarded; any short read refuses. */
static int neth_case_block_locator(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct block_locator loc;
    unsigned char hash[32] = {0};

    /* Valid control: 2 hashes. */
    stream_init(&w, 256);
    stream_write_i32_le(&w, 170011);
    stream_write_compact_size(&w, 2);
    hash[0] = 1;
    stream_write_bytes(&w, hash, sizeof(hash));
    hash[0] = 2;
    stream_write_bytes(&w, hash, sizeof(hash));
    neth_reader(&r, &w, w.size);
    block_locator_init(&loc);
    NETH_CHECK("locator: valid control deserializes",
               block_locator_deserialize(&loc, &r));
    NETH_CHECK("locator: control keeps 2 hashes", loc.num_hashes == 2);
    block_locator_free(&loc);
    stream_free(&r);

    /* Truncated: ends inside the locator nVersion field. */
    neth_reader(&r, &w, 3);
    block_locator_init(&loc);
    NETH_CHECK("locator: truncated frame refused",
               block_locator_deserialize(&loc, &r) == false);
    NETH_CHECK("locator: refusal latched stream error", r.error == true);
    block_locator_free(&loc);
    stream_free(&r);

    /* Oversized: count 1000 > MAX_LOCATOR_HASHES with no hashes —
     * clamped to 64, then the first 32-byte read refuses. */
    stream_free(&w);
    stream_init(&w, 16);
    stream_write_i32_le(&w, 170011);
    stream_write_compact_size(&w, 1000);
    neth_reader(&r, &w, w.size);
    block_locator_init(&loc);
    NETH_CHECK("locator: oversized count refused",
               block_locator_deserialize(&loc, &r) == false);
    NETH_CHECK("locator: oversized count alloc clamped to 64",
               loc.num_hashes == MAX_LOCATOR_HASHES);
    block_locator_free(&loc);
    stream_free(&r);

    /* Over-remaining: count 64, only 10 hashes' bytes supplied. */
    stream_free(&w);
    stream_init(&w, 512);
    stream_write_i32_le(&w, 170011);
    stream_write_compact_size(&w, MAX_LOCATOR_HASHES);
    for (int i = 0; i < 10; i++) {
        hash[0] = (unsigned char)i;
        stream_write_bytes(&w, hash, sizeof(hash));
    }
    neth_reader(&r, &w, w.size);
    block_locator_init(&loc);
    NETH_CHECK("locator: count 64 with 10 hashes refused",
               block_locator_deserialize(&loc, &r) == false);
    block_locator_free(&loc);
    stream_free(&r);
    stream_free(&w);

    return failures;
}

/* ── 4. block_header_deserialize (block.c:40) ─────────────────
 * Fixed 140-byte prefix, then compact-size solution length into the
 * fixed nSolution[1344]. */
static int neth_case_block_header(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct block_header h;
    unsigned char zeros[140] = {0};

    /* Valid control: zero-size solution. */
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 0);
    neth_reader(&r, &w, w.size);
    block_header_init(&h);
    NETH_CHECK("header: valid control deserializes",
               block_header_deserialize(&h, &r));
    stream_free(&r);

    /* Truncated mid-nNonce. */
    neth_reader(&r, &w, 100);
    block_header_init(&h);
    NETH_CHECK("header: truncated frame refused",
               block_header_deserialize(&h, &r) == false);
    NETH_CHECK("header: refusal latched stream error", r.error == true);
    stream_free(&r);

    /* Oversized: solution length MAX_SOLUTION_SIZE + 1. */
    stream_free(&w);
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, (uint64_t)MAX_SOLUTION_SIZE + 1);
    neth_reader(&r, &w, w.size);
    block_header_init(&h);
    NETH_CHECK("header: sol size 1345 > MAX_SOLUTION_SIZE refused",
               block_header_deserialize(&h, &r) == false);
    stream_free(&r);

    /* Over-remaining: sol size 100 (under cap), 10 bytes supplied. */
    stream_free(&w);
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 100);
    stream_write_bytes(&w, zeros, 10);
    neth_reader(&r, &w, w.size);
    block_header_init(&h);
    NETH_CHECK("header: sol size 100 with 10 bytes refused",
               block_header_deserialize(&h, &r) == false);
    NETH_CHECK("header: over-remaining refusal latched error",
               r.error == true);
    stream_free(&r);
    stream_free(&w);

    return failures;
}

/* ── 5. block_deserialize (block.c:71) ────────────────────────
 * Header + compact-size tx count, capped at MAX_BLOCK_TRANSACTIONS,
 * with a count*10 > remaining pre-allocation guard. */
static int neth_case_block(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct block b;
    unsigned char zeros[140] = {0};

    /* Valid control: header + zero txs. */
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 0);
    stream_write_compact_size(&w, 0);
    neth_reader(&r, &w, w.size);
    block_init(&b);
    NETH_CHECK("block: valid control deserializes",
               block_deserialize(&b, &r));
    NETH_CHECK("block: control has 0 txs", b.num_vtx == 0);
    block_free(&b);
    stream_free(&r);

    /* Oversized: tx count MAX_BLOCK_TRANSACTIONS + 1. */
    stream_free(&w);
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 0);
    stream_write_compact_size(&w, (uint64_t)MAX_BLOCK_TRANSACTIONS + 1);
    neth_reader(&r, &w, w.size);
    block_init(&b);
    NETH_CHECK("block: tx count 50001 > cap refused",
               block_deserialize(&b, &r) == false);
    block_free(&b);
    stream_free(&r);

    /* Over-remaining: tx count 100 (under cap), zero tx bytes — the
     * count*10 > remaining guard must refuse before the calloc. */
    stream_free(&w);
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 0);
    stream_write_compact_size(&w, 100);
    neth_reader(&r, &w, w.size);
    block_init(&b);
    NETH_CHECK("block: tx count 100 with no bytes refused",
               block_deserialize(&b, &r) == false);
    block_free(&b);
    stream_free(&r);

    /* Truncated tx list: count 1 declared, tx body cut short. */
    stream_free(&w);
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 0);
    stream_write_compact_size(&w, 1);
    stream_write_u32_le(&w, 2);   /* tx version, then frame ends */
    neth_reader(&r, &w, w.size);
    block_init(&b);
    NETH_CHECK("block: truncated tx refused",
               block_deserialize(&b, &r) == false);
    block_free(&b); /* refused mid-loop: teardown must stay clean */
    stream_free(&r);
    stream_free(&w);

    return failures;
}

static void neth_v6_block_start(struct byte_stream *w, uint64_t count)
{
    unsigned char zeros[BLOCK_HEADER_SIZE] = {0};
    stream_init(w, 256);
    stream_write_bytes(w, zeros, sizeof(zeros));
    stream_write_compact_size(w, 0);
    stream_write_compact_size(w, count);
}

static int neth_v6_valid_frames(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct block b;

    struct uint256 expected_txid;
    uint256_set_hex(&expected_txid, "6657f1febe7ff9a032381517ce4720db94b18a3dea11a17ce075ec3f9928bfc3");
    neth_v6_block_start(&w, 2);
    stream_write_bytes(&w, ironwood_anchor_a, sizeof(ironwood_anchor_a));
    stream_write_bytes(&w, ironwood_anchor_a, sizeof(ironwood_anchor_a));
    neth_reader(&r, &w, w.size);
    block_init(&b);
    NETH_CHECK("block v6: consecutive checked frames deserialize",
               block_deserialize(&b, &r) && r.read_pos == r.size);
    NETH_CHECK("block v6: opaque bytes retained and digest txids assigned",
               b.num_vtx == 2 &&
               b.vtx[0].v6_wire.size == sizeof(ironwood_anchor_a) &&
               b.vtx[1].v6_wire.size == sizeof(ironwood_anchor_a) &&
               memcmp(b.vtx[0].v6_wire.data, ironwood_anchor_a,
                      sizeof(ironwood_anchor_a)) == 0 &&
               memcmp(b.vtx[1].v6_wire.data, ironwood_anchor_a,
                      sizeof(ironwood_anchor_a)) == 0 &&
               b.vtx[0].v6_wire.data != b.vtx[1].v6_wire.data &&
               b.vtx[0].overwintered && b.vtx[0].version == IRONWOOD_TX_VERSION &&
               b.vtx[0].version_group_id == IRONWOOD_VERSION_GROUP_ID &&
               uint256_eq(&b.vtx[0].hash, &expected_txid) &&
               uint256_eq(&b.vtx[1].hash, &expected_txid));
    block_free(&b);
    stream_free(&r);

    stream_write_u8(&w, 0);
    neth_reader(&r, &w, w.size);
    block_init(&b);
    NETH_CHECK("block v6: trailing bytes refused",
               block_deserialize(&b, &r) == false);
    block_free(&b);
    stream_free(&r);
    stream_free(&w);
    return failures;
}

static int neth_v6_invalid_frames(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct block b;

    neth_v6_block_start(&w, 1);
    stream_write_bytes(&w, ironwood_anchor_a, sizeof(ironwood_anchor_a) - 1);
    neth_reader(&r, &w, w.size);
    block_init(&b);
    NETH_CHECK("block v6: truncated frame refused",
               block_deserialize(&b, &r) == false && b.vtx[0].v6_wire.data == NULL);
    block_free(&b);
    stream_free(&r);
    stream_free(&w);

    neth_v6_block_start(&w, 1);
    stream_write_bytes(&w, ironwood_anchor_a, 20);
    stream_write_u8(&w, 253);
    stream_write_u16_le(&w, 0);
    stream_write_bytes(&w, ironwood_anchor_a + 20,
                       sizeof(ironwood_anchor_a) - 20);
    neth_reader(&r, &w, w.size);
    block_init(&b);
    NETH_CHECK("block v6: non-canonical count refused",
               block_deserialize(&b, &r) == false && b.vtx[0].v6_wire.data == NULL);
    block_free(&b);
    stream_free(&r);
    stream_free(&w);
    return failures;
}

static int neth_v6_legacy_frame(int32_t version)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct block b;
    struct transaction legacy;
    transaction_init(&legacy);
    legacy.overwintered = true;
    legacy.version = version;
    legacy.version_group_id = version == OVERWINTER_TX_VERSION ?
                              OVERWINTER_VERSION_GROUP_ID : SAPLING_VERSION_GROUP_ID;
    struct byte_stream txwire;
    stream_init(&txwire, 128);
    NETH_CHECK("block legacy: control serializes",
               transaction_serialize(&legacy, &txwire));
    transaction_free(&legacy);

    neth_v6_block_start(&w, 1);
    stream_write_bytes(&w, txwire.data, txwire.size);
    stream_write_u8(&w, 0);
    neth_reader(&r, &w, w.size);
    block_init(&b);
    char label[96];
    snprintf(label, sizeof(label),
             "block v%d: legacy decode and trailing behavior unchanged", version);
    NETH_CHECK(label,
               block_deserialize(&b, &r) && b.num_vtx == 1 &&
               b.vtx[0].version == version && stream_remaining(&r) == 1 &&
               r.read_pos == w.size - 1);
    struct byte_stream encoded;
    stream_init(&encoded, 128);
    NETH_CHECK("block legacy: reserialized bytes unchanged",
               transaction_serialize(&b.vtx[0], &encoded) &&
               encoded.size == txwire.size &&
               memcmp(encoded.data, txwire.data, txwire.size) == 0);
    stream_free(&encoded);
    block_free(&b);
    stream_free(&r);
    stream_free(&txwire);
    stream_free(&w);
    return failures;
}

static int neth_case_block_v6(void)
{
    int failures = neth_v6_valid_frames();
    failures += neth_v6_invalid_frames();
    for (int32_t version = OVERWINTER_TX_VERSION;
         version <= SAPLING_TX_VERSION; ++version)
        failures += neth_v6_legacy_frame(version);
    return failures;
}

static bool neth_digest_is(const unsigned char digest[32], const char *expected)
{
    char hex[65];
    zcl_hex_encode(digest, 32, hex);
    return strcmp(hex, expected) == 0;
}

static bool neth_sha256_is(const unsigned char *data, size_t size,
                           const char *expected)
{
    struct sha256_ctx sha;
    unsigned char digest[32];
    sha256_init(&sha);
    sha256_write(&sha, data, size);
    sha256_finalize(&sha, digest);
    return neth_digest_is(digest, expected);
}

static int neth_v6_candidate_block_identity(const unsigned char *data, size_t size)
{
    int failures = 0;
    NETH_CHECK("block v6: strict H127 candidate is exactly 9882 bytes",
               size == 9882);
    bool block_identity = size == 9882 && neth_sha256_is(data, size,
        "c55c4ccad3b636da48c32c7cc3ac13e96bd3e151e82af16a940ed99d0f2b0d55");
    NETH_CHECK("block v6: strict H127 whole-block SHA-256 identity",
               block_identity);
    if (!block_identity) {
        free((void *)data);
        return failures;
    }
    return failures;
}

static int neth_v6_candidate_load(const char *path, unsigned char **out_data,
                                  size_t *out_size)
{
    int failures = 0;
    FILE *file = fopen(path, "rb");
    NETH_CHECK("block v6: external candidate opens", file != NULL);
    if (!file) return failures;
    long length = -1;
    bool sized = fseek(file, 0, SEEK_END) == 0 &&
                 (length = ftell(file)) > 0 && length <= MAX_BLOCK_SIZE &&
                 fseek(file, 0, SEEK_SET) == 0;
    NETH_CHECK("block v6: external candidate has bounded size", sized);
    if (!sized) {
        fclose(file);
        return failures;
    }

    size_t size = (size_t)length;
    unsigned char *data = malloc(size);
    NETH_CHECK("block v6: external candidate buffer allocates", data != NULL);
    if (!data) {
        fclose(file);
        return failures;
    }
    bool read = fread(data, 1, size, file) == size;
    if (fclose(file) != 0) read = false;
    NETH_CHECK("block v6: external candidate reads completely", read);
    if (!read) {
        free(data);
        return failures;
    }

    failures += neth_v6_candidate_block_identity(data, size);
    if (failures) return failures;
    *out_data = data;
    *out_size = size;
    return failures;
}

static int neth_v6_candidate_header_identity(const struct block *b)
{
    int failures = 0;
    struct uint256 parent, merkle, sapling, block_id;
    uint256_set_hex(&parent,
        "0538be8be2416c63df63c6319726d805db66e3189df6f8bdbbc4c04caf5cd473");
    uint256_set_hex(&merkle,
        "a685e1643c76ab4ee8d8f50a0cf250a72fc9db77da585a5e7ddff11d4a27ce80");
    uint256_set_hex(&sapling,
        "6eb10fd1464824132d26de60046cbed6bc1676527cf3965451d1d9f8e278e699");
    block_get_hash(b, &block_id);
    NETH_CHECK("block v6: independent H127 header identity",
               b->header.nSolutionSize == 36 && b->header.nBits == 0x200f0f0f &&
               uint256_eq(&b->header.hashPrevBlock, &parent) &&
               uint256_eq(&b->header.hashMerkleRoot, &merkle) &&
               uint256_eq(&b->header.hashFinalSaplingRoot, &sapling) &&
               neth_digest_is(block_id.data,
                   "5c60569e89416a317adf01fb9f1bc90954a2fd25cdfe61975eebe57304ea9d04"));
    return failures;
}

static int neth_v6_candidate_transaction_identity(const struct block *b,
                                                  const unsigned char *data)
{
    int failures = 0;
    struct byte_stream coinbase;
    struct uint256 v6_txid;
    uint256_set_hex(&v6_txid, "35458f2ec6ae7de6e1b8b5b106d60b61fbafe8141e6c411c4541591892694790");
    stream_init(&coinbase, 128);
    bool coinbase_encoded = transaction_serialize(&b->vtx[0], &coinbase);
    NETH_CHECK("block v6: independent H127 transaction identities and bytes",
               b->vtx[0].version == SAPLING_TX_VERSION &&
               transaction_is_coinbase(&b->vtx[0]) && coinbase_encoded &&
               coinbase.size == 82 && memcmp(coinbase.data, data + 178, 82) == 0 &&
               neth_digest_is(b->vtx[0].hash.data,
                   "e8fe2b19757b591262f16b445638b26047072db3395e60a02b0656f63c15c7f7") &&
               b->vtx[1].v6_wire.size == 9622 &&
               b->vtx[1].v6_wire.data != data + 260 &&
               memcmp(b->vtx[1].v6_wire.data, data + 260, 9622) == 0 &&
               neth_sha256_is(b->vtx[1].v6_wire.data, b->vtx[1].v6_wire.size,
                   "684900bd4595fa07474506a5b6d04b524ff2954877b259a6de6c7da5f4ee2111") &&
               uint256_eq(&b->vtx[1].hash, &v6_txid));
    stream_free(&coinbase);
    return failures;
}

static int neth_v6_candidate_decode(const unsigned char *data, size_t size)
{
    int failures = 0;
    struct byte_stream r;
    stream_init_from_data(&r, data, size);
    struct block b;
    block_init(&b);
    bool decoded = block_deserialize(&b, &r);
    bool shape = decoded && r.read_pos == r.size && b.num_vtx == 2 &&
                 b.vtx[1].v6_wire.size != 0;
    NETH_CHECK("block v6: external strict funded candidate decodes exactly",
               shape);
    if (!shape) {
        block_free(&b);
        stream_free(&r);
        return failures;
    }

    failures += neth_v6_candidate_header_identity(&b);
    failures += neth_v6_candidate_transaction_identity(&b, data);
    struct uint256 txids[2] = {b.vtx[0].hash, b.vtx[1].hash};
    struct uint256 root = compute_merkle_root(txids, 2);
    NETH_CHECK("block v6: coinbase and v6 txids reproduce H127 merkle root",
               uint256_eq(&root, &b.header.hashMerkleRoot));
    txids[1].data[0] ^= 1;
    root = compute_merkle_root(txids, 2);
    NETH_CHECK("block v6: merkle root uses the decoded v6 txid",
               !uint256_eq(&root, &b.header.hashMerkleRoot));
    block_free(&b);
    stream_free(&r);
    return failures;
}

static int neth_case_external_v6_block(void)
{
    int failures = 0;
    const char *required_env = getenv("Z23_V6_BLOCK_REQUIRED");
    bool required = required_env && strcmp(required_env, "1") == 0;
    if (required_env && !required && strcmp(required_env, "0") != 0)
        NETH_CHECK("block v6: required mode is 0 or 1", false);

    const char *path = getenv("Z23_V6_BLOCK_CANDIDATE");
    if (!path || !*path) {
        if (required)
            NETH_CHECK("block v6: required candidate path is present", false);
        return failures;
    }

    unsigned char *data = NULL;
    size_t size = 0;
    int load_failures = neth_v6_candidate_load(path, &data, &size);
    if (load_failures) return failures + load_failures;
    failures += neth_v6_candidate_decode(data, size);
    free(data);
    return failures;
}

/* ── 6. transaction_deserialize (transaction.c:528) ───────────
 * Section caps (vin/vout/shielded/joinsplit) plus per-section
 * count*N > remaining pre-allocation guards. */
static int neth_case_transaction(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct transaction tx;

    /* Valid control: v1 tx, no vin, no vout, locktime. */
    stream_init(&w, 64);
    stream_write_u32_le(&w, 1);
    stream_write_compact_size(&w, 0);
    stream_write_compact_size(&w, 0);
    stream_write_u32_le(&w, 0);
    neth_reader(&r, &w, w.size);
    transaction_init(&tx);
    NETH_CHECK("tx: valid control deserializes",
               transaction_deserialize(&tx, &r));
    transaction_free(&tx);
    stream_free(&r);

    /* Truncated: header only. */
    neth_reader(&r, &w, 4);
    transaction_init(&tx);
    NETH_CHECK("tx: truncated frame refused",
               transaction_deserialize(&tx, &r) == false);
    NETH_CHECK("tx: refusal latched stream error", r.error == true);
    transaction_free(&tx);
    stream_free(&r);

    /* Oversized vin count: MAX_TX_INPUTS + 1. */
    stream_free(&w);
    stream_init(&w, 64);
    stream_write_u32_le(&w, 1);
    stream_write_compact_size(&w, (uint64_t)MAX_TX_INPUTS + 1);
    neth_reader(&r, &w, w.size);
    transaction_init(&tx);
    NETH_CHECK("tx: vin count 65537 > cap refused",
               transaction_deserialize(&tx, &r) == false);
    transaction_free(&tx);
    stream_free(&r);

    /* Over-remaining vin: count 100 (under cap), no entries — the
     * count*41 > remaining guard refuses before the calloc. */
    stream_free(&w);
    stream_init(&w, 64);
    stream_write_u32_le(&w, 1);
    stream_write_compact_size(&w, 100);
    neth_reader(&r, &w, w.size);
    transaction_init(&tx);
    NETH_CHECK("tx: vin count 100 with no bytes refused",
               transaction_deserialize(&tx, &r) == false);
    transaction_free(&tx);
    stream_free(&r);

    /* Over-remaining vout: count 100, no entries. */
    stream_free(&w);
    stream_init(&w, 64);
    stream_write_u32_le(&w, 1);
    stream_write_compact_size(&w, 0);
    stream_write_compact_size(&w, 100);
    neth_reader(&r, &w, w.size);
    transaction_init(&tx);
    NETH_CHECK("tx: vout count 100 with no bytes refused",
               transaction_deserialize(&tx, &r) == false);
    transaction_free(&tx);
    stream_free(&r);

    /* Joinsplit section (version >= 2): oversized count refused;
     * under-cap count with no payload hits the count*1634 guard. */
    stream_free(&w);
    stream_init(&w, 64);
    stream_write_u32_le(&w, 2);   /* version 2, not overwintered */
    stream_write_compact_size(&w, 0);
    stream_write_compact_size(&w, 0);
    stream_write_u32_le(&w, 0);   /* lock_time */
    stream_write_compact_size(&w, (uint64_t)MAX_JOINSPLITS + 1);
    neth_reader(&r, &w, w.size);
    transaction_init(&tx);
    NETH_CHECK("tx: joinsplit count 4097 > cap refused",
               transaction_deserialize(&tx, &r) == false);
    transaction_free(&tx);
    stream_free(&r);

    stream_free(&w);
    stream_init(&w, 64);
    stream_write_u32_le(&w, 2);
    stream_write_compact_size(&w, 0);
    stream_write_compact_size(&w, 0);
    stream_write_u32_le(&w, 0);
    stream_write_compact_size(&w, 10);
    neth_reader(&r, &w, w.size);
    transaction_init(&tx);
    NETH_CHECK("tx: joinsplit count 10 with no bytes refused",
               transaction_deserialize(&tx, &r) == false);
    transaction_free(&tx);
    stream_free(&r);
    stream_free(&w);

    return failures;
}

/* ── 7. compact_block_msg_deserialize (compact_blocks.c:503) ──
 * Header + nonce + short-txid count + prefilled count, each capped
 * at MAX_COMPACT_BLOCK_TXNS. */
static int neth_case_compact_block(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct compact_block_msg cb;
    unsigned char zeros[140] = {0};

    /* Valid control: no short ids, no prefilled. */
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 0); /* solution size */
    stream_write_u64_le(&w, 0);       /* nonce */
    stream_write_compact_size(&w, 0); /* short txids */
    stream_write_compact_size(&w, 0); /* prefilled */
    neth_reader(&r, &w, w.size);
    compact_block_msg_init(&cb);
    NETH_CHECK("cmpct: valid control deserializes",
               compact_block_msg_deserialize(&cb, &r));
    compact_block_msg_free(&cb);
    stream_free(&r);

    /* Truncated mid header. */
    neth_reader(&r, &w, 70);
    compact_block_msg_init(&cb);
    NETH_CHECK("cmpct: truncated frame refused",
               compact_block_msg_deserialize(&cb, &r) == false);
    NETH_CHECK("cmpct: refusal latched stream error", r.error == true);
    compact_block_msg_free(&cb);
    stream_free(&r);

    /* Oversized short-txid count. */
    stream_free(&w);
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 0);
    stream_write_u64_le(&w, 0);
    stream_write_compact_size(&w, (uint64_t)MAX_COMPACT_BLOCK_TXNS + 1);
    neth_reader(&r, &w, w.size);
    compact_block_msg_init(&cb);
    NETH_CHECK("cmpct: short-txid count 50001 > cap refused",
               compact_block_msg_deserialize(&cb, &r) == false);
    compact_block_msg_free(&cb);
    stream_free(&r);

    /* Over-remaining: 4 short ids declared (24 bytes), 1 supplied. */
    stream_free(&w);
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 0);
    stream_write_u64_le(&w, 0);
    stream_write_compact_size(&w, 4);
    stream_write_bytes(&w, zeros, SHORT_TXID_LEN);
    neth_reader(&r, &w, w.size);
    compact_block_msg_init(&cb);
    NETH_CHECK("cmpct: 4 short ids with 1 supplied refused",
               compact_block_msg_deserialize(&cb, &r) == false);
    compact_block_msg_free(&cb); /* refusal frees internally; idempotent */
    stream_free(&r);

    /* Oversized prefilled count (short ids already parsed). */
    stream_free(&w);
    stream_init(&w, 256);
    stream_write_bytes(&w, zeros, sizeof(zeros));
    stream_write_compact_size(&w, 0);
    stream_write_u64_le(&w, 0);
    stream_write_compact_size(&w, 0);
    stream_write_compact_size(&w, (uint64_t)MAX_COMPACT_BLOCK_TXNS + 1);
    neth_reader(&r, &w, w.size);
    compact_block_msg_init(&cb);
    NETH_CHECK("cmpct: prefilled count 50001 > cap refused",
               compact_block_msg_deserialize(&cb, &r) == false);
    compact_block_msg_free(&cb);
    stream_free(&r);
    stream_free(&w);

    return failures;
}

/* ── 8. block_txn_request_deserialize (compact_blocks.c:600) ── */
static int neth_case_block_txn_request(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct block_txn_request req;
    unsigned char hash[32] = {0};
    hash[0] = 9;

    /* Valid control: 1 differential index. */
    stream_init(&w, 64);
    stream_write_bytes(&w, hash, sizeof(hash));
    stream_write_compact_size(&w, 1);
    stream_write_compact_size(&w, 3);
    neth_reader(&r, &w, w.size);
    block_txn_request_init(&req);
    NETH_CHECK("getblocktxn: valid control deserializes",
               block_txn_request_deserialize(&req, &r));
    NETH_CHECK("getblocktxn: control index decoded", req.num_indices == 1);
    block_txn_request_free(&req);
    stream_free(&r);

    /* Truncated hash. */
    neth_reader(&r, &w, 20);
    block_txn_request_init(&req);
    NETH_CHECK("getblocktxn: truncated hash refused",
               block_txn_request_deserialize(&req, &r) == false);
    NETH_CHECK("getblocktxn: refusal latched stream error",
               r.error == true);
    block_txn_request_free(&req);
    stream_free(&r);

    /* Oversized index count. */
    stream_free(&w);
    stream_init(&w, 64);
    stream_write_bytes(&w, hash, sizeof(hash));
    stream_write_compact_size(&w, (uint64_t)MAX_GETBLOCKTXN_INDICES + 1);
    neth_reader(&r, &w, w.size);
    block_txn_request_init(&req);
    NETH_CHECK("getblocktxn: index count 50001 > cap refused",
               block_txn_request_deserialize(&req, &r) == false);
    block_txn_request_free(&req);
    stream_free(&r);

    /* Over-remaining: 3 indices declared, 0 diffs supplied. */
    stream_free(&w);
    stream_init(&w, 64);
    stream_write_bytes(&w, hash, sizeof(hash));
    stream_write_compact_size(&w, 3);
    neth_reader(&r, &w, w.size);
    block_txn_request_init(&req);
    NETH_CHECK("getblocktxn: 3 indices with no diffs refused",
               block_txn_request_deserialize(&req, &r) == false);
    block_txn_request_free(&req);
    stream_free(&r);
    stream_free(&w);

    return failures;
}

/* ── 9. block_txn_response_deserialize (compact_blocks.c:652) ─ */
static int neth_case_block_txn_response(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct block_txn_response resp;
    unsigned char hash[32] = {0};
    hash[0] = 7;

    /* Valid control: zero txs. */
    stream_init(&w, 64);
    stream_write_bytes(&w, hash, sizeof(hash));
    stream_write_compact_size(&w, 0);
    neth_reader(&r, &w, w.size);
    block_txn_response_init(&resp);
    NETH_CHECK("blocktxn: valid control deserializes",
               block_txn_response_deserialize(&resp, &r));
    block_txn_response_free(&resp);
    stream_free(&r);

    /* Truncated hash. */
    neth_reader(&r, &w, 10);
    block_txn_response_init(&resp);
    NETH_CHECK("blocktxn: truncated hash refused",
               block_txn_response_deserialize(&resp, &r) == false);
    NETH_CHECK("blocktxn: refusal latched stream error", r.error == true);
    block_txn_response_free(&resp);
    stream_free(&r);

    /* Oversized tx count. */
    stream_free(&w);
    stream_init(&w, 64);
    stream_write_bytes(&w, hash, sizeof(hash));
    stream_write_compact_size(&w, (uint64_t)MAX_COMPACT_BLOCK_TXNS + 1);
    neth_reader(&r, &w, w.size);
    block_txn_response_init(&resp);
    NETH_CHECK("blocktxn: tx count 50001 > cap refused",
               block_txn_response_deserialize(&resp, &r) == false);
    block_txn_response_free(&resp);
    stream_free(&r);

    /* Over-remaining: 1 tx declared, cut mid-tx. */
    stream_free(&w);
    stream_init(&w, 64);
    stream_write_bytes(&w, hash, sizeof(hash));
    stream_write_compact_size(&w, 1);
    stream_write_u32_le(&w, 1); /* tx version, then frame ends */
    neth_reader(&r, &w, w.size);
    block_txn_response_init(&resp);
    NETH_CHECK("blocktxn: 1 tx with truncated body refused",
               block_txn_response_deserialize(&resp, &r) == false);
    block_txn_response_free(&resp); /* refusal frees internally */
    stream_free(&r);
    stream_free(&w);

    return failures;
}

/* ── 10. zmsg_deserialize (zmsg.c:39) ─────────────────────────
 * Length-prefixed sender/recipient/body into fixed buffers; a
 * length at or over its cap must refuse WITHOUT writing the field. */
static int neth_case_zmsg(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct zmsg_message m;
    struct zmsg_message good;

    /* Valid control via the serializer. */
    memset(&good, 0, sizeof(good));
    for (int i = 0; i < 32; i++)
        good.msg_id[i] = (uint8_t)i;
    good.timestamp = 1700000000;
    snprintf(good.sender, sizeof(good.sender), "sender@example");
    snprintf(good.recipient, sizeof(good.recipient), "rcpt@example");
    snprintf(good.body, sizeof(good.body), "hello hardening");
    stream_init(&w, 256);
    NETH_CHECK("zmsg: valid control serializes", zmsg_serialize(&good, &w));
    neth_reader(&r, &w, w.size);
    memset(&m, 0, sizeof(m));
    NETH_CHECK("zmsg: valid control deserializes",
               zmsg_deserialize(&m, &r));
    NETH_CHECK("zmsg: control body round-trips",
               strcmp(m.body, good.body) == 0);
    stream_free(&r);

    /* Truncated: ends inside msg_id. */
    neth_reader(&r, &w, 10);
    memset(&m, 0, sizeof(m));
    NETH_CHECK("zmsg: truncated frame refused",
               zmsg_deserialize(&m, &r) == false);
    NETH_CHECK("zmsg: refusal latched stream error", r.error == true);
    stream_free(&r);

    /* Oversized sender length: 200 >= ZMSG_MAX_ADDR (128) refused
     * before the fixed field is written (no partial state). */
    stream_free(&w);
    stream_init(&w, 128);
    stream_write(&w, good.msg_id, 32);
    stream_write_i64_le(&w, good.timestamp);
    stream_write_u8(&w, 200);
    neth_reader(&r, &w, w.size);
    memset(&m, 0, sizeof(m));
    NETH_CHECK("zmsg: sender length 200 >= ZMSG_MAX_ADDR refused",
               zmsg_deserialize(&m, &r) == false);
    NETH_CHECK("zmsg: refusal left sender untouched",
               m.sender[0] == '\0');
    stream_free(&r);

    /* Oversized body length: ZMSG_MAX_BODY itself is refused. */
    stream_free(&w);
    stream_init(&w, 128);
    stream_write(&w, good.msg_id, 32);
    stream_write_i64_le(&w, good.timestamp);
    stream_write_u8(&w, 0); /* sender len 0 */
    stream_write_u8(&w, 0); /* recipient len 0 */
    stream_write_u16_le(&w, (uint16_t)ZMSG_MAX_BODY);
    neth_reader(&r, &w, w.size);
    memset(&m, 0, sizeof(m));
    NETH_CHECK("zmsg: body length 4096 >= ZMSG_MAX_BODY refused",
               zmsg_deserialize(&m, &r) == false);
    stream_free(&r);

    /* Over-remaining: body length 10 declared, nothing behind it. */
    stream_free(&w);
    stream_init(&w, 128);
    stream_write(&w, good.msg_id, 32);
    stream_write_i64_le(&w, good.timestamp);
    stream_write_u8(&w, 0);
    stream_write_u8(&w, 0);
    stream_write_u16_le(&w, 10);
    neth_reader(&r, &w, w.size);
    memset(&m, 0, sizeof(m));
    NETH_CHECK("zmsg: body length 10 with no bytes refused",
               zmsg_deserialize(&m, &r) == false);
    NETH_CHECK("zmsg: over-remaining refusal latched error",
               r.error == true);
    stream_free(&r);
    stream_free(&w);

    return failures;
}

/* ── 11. file_offer_deserialize (file_market.c:85) ────────────
 * u8 name length into filename[256]; every field through the
 * bounded reader. */
static int neth_case_file_offer(void)
{
    int failures = 0;
    struct byte_stream w;
    struct byte_stream r;
    struct file_offer offer;
    unsigned char root[32] = {0};
    root[0] = 5;

    /* Valid control. */
    stream_init(&w, 256);
    stream_write(&w, root, sizeof(root));
    stream_write_u8(&w, 5);
    stream_write(&w, (const unsigned char *)"hello", 5);
    stream_write_u64_le(&w, 1024 * 1024);
    stream_write_u32_le(&w, 1);
    stream_write_i64_le(&w, 0); /* price 0 */
    unsigned char zaddr[43] = {0};
    stream_write(&w, zaddr, sizeof(zaddr));
    unsigned char ip[16] = {0};
    stream_write(&w, ip, sizeof(ip));
    stream_write_u16_le(&w, 8033);
    stream_write_u8(&w, 3); /* ttl */
    neth_reader(&r, &w, w.size);
    NETH_CHECK("offer: valid control deserializes",
               file_offer_deserialize(&offer, &r));
    NETH_CHECK("offer: control name round-trips",
               strcmp(offer.filename, "hello") == 0);
    stream_free(&r);

    /* Truncated mid z_addr. */
    neth_reader(&r, &w, 60);
    NETH_CHECK("offer: truncated frame refused",
               file_offer_deserialize(&offer, &r) == false);
    NETH_CHECK("offer: refusal latched stream error", r.error == true);
    stream_free(&r);

    /* Over-remaining: namelen 100 declared, nothing behind it. */
    stream_free(&w);
    stream_init(&w, 64);
    stream_write(&w, root, sizeof(root));
    stream_write_u8(&w, 100);
    neth_reader(&r, &w, w.size);
    NETH_CHECK("offer: namelen 100 with no bytes refused",
               file_offer_deserialize(&offer, &r) == false);
    NETH_CHECK("offer: over-remaining refusal latched error",
               r.error == true);
    stream_free(&r);
    stream_free(&w);

    return failures;
}

int test_net_frame_hardening(void);
int test_net_frame_hardening(void)
{
    int failures = 0;
    printf("\n=== net_frame_hardening decode-path refusal tests ===\n");

    failures += neth_case_version_message();
    failures += neth_case_netaddr_inv();
    failures += neth_case_block_locator();
    failures += neth_case_block_header();
    failures += neth_case_block();
    failures += neth_case_block_v6();
    failures += neth_case_external_v6_block();
    failures += neth_case_transaction();
    failures += neth_case_compact_block();
    failures += neth_case_block_txn_request();
    failures += neth_case_block_txn_response();
    failures += neth_case_zmsg();
    failures += neth_case_file_offer();

    printf("net_frame_hardening decode-path refusal tests: %s\n",
           failures == 0 ? "ALL PASSED" : "FAILURES PRESENT");
    return failures;
}
