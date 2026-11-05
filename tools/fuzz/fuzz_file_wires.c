/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Exercise the peer-reachable file-market and file-service wire
 * decoders (signed file offer, state-offer batch, ROM/serve request parsers,
 * raw and private chunk receivers) under sanitizers and hold each to its
 * contract: re-encode to identical bytes, leave the output as documented on a
 * refusal, keep every decoded count inside its array, and stay clear of the
 * guard bytes around the output.
 *
 * The first input byte picks the decoder, the rest is its input. Arms that
 * need a valid signed row start from a valid wire built once at init and apply
 * fuzz-chosen (position, xor) patches to it, so the fuzzer reaches past the
 * magic and signature checks without having to forge a point or a signature.
 * The chunk receivers run over a local socketpair: bytes are written before
 * the call and the writer is closed, so nothing waits and no thread runs.
 *
 * Not reached from here: fs_stream_range and the client manifest reader
 * (fs_sync_read_chunks) are static and need a datadir, a running server flag
 * or a live socket; the zfileaddr tail handler needs a p2p_node and a
 * net_manager, so its decoder state_offer_batch_v1_decode is called directly.
 * Raw abort throughout: no handlers, nothing that could mask a crash. */

#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "base/log_level.h"
#include "base/serialize_le.h"
#include "net/file_market.h"
#include "net/file_service.h"
#include "net/state_offer.h"
#include "sapling/sapling.h"
#include "sapling/fr.h"
#include "util/safe_alloc.h"

#include "fuzz_checks.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

volatile sig_atomic_t g_shutdown_requested = 0;

#define FUZZ_FILE_ARMS 9u
#define FUZZ_FILE_MAX_INPUT (1u << 16)
#define FUZZ_FILE_GUARD 64u
#define FUZZ_FILE_CANARY 0xA5u
#define FUZZ_FILE_PATCH_MAX 31u
#define FUZZ_FILE_CHUNK_MAX 32768u
/* The receivers refuse a claimed size above 60 MiB; below that they allocate
 * what the header claims before reading a byte. The harness keeps a claimed
 * size under 1 MiB so one input does not cost a large allocation. */
#define FUZZ_FILE_PEER_CHUNK_MAX (60u * 1024u * 1024u)
#define FUZZ_FILE_CLAIM_CAP (1u << 20)
#define FUZZ_FILE_GENESIS_BYTE 0x42u
#define FUZZ_FILE_NOW 1100
#define FUZZ_STATE_TIP 1000
#define FUZZ_STATE_ISSUED UINT64_C(1700000001)

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint8_t g_file_base[2][FILE_MARKET_OFFER_WIRE_BYTES_MAX];
static size_t g_file_base_len[2];
static uint8_t g_state_base[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
static size_t g_state_base_len;
static struct fs_session g_rx;
static struct fs_session g_tx;

/* ── guard around an output struct ─────────────────────────────────── */

struct guarded_file_offer {
    uint8_t pre[FUZZ_FILE_GUARD];
    struct file_offer out;
    uint8_t post[FUZZ_FILE_GUARD];
};

struct guarded_state_batch {
    uint8_t pre[FUZZ_FILE_GUARD];
    struct state_offer_batch_v1 out;
    uint8_t post[FUZZ_FILE_GUARD];
};

static void require_filled(const uint8_t *p, size_t len)
{
    for (size_t i = 0; i < len; i++)
        if (p[i] != FUZZ_FILE_CANARY)
            abort();
}

static uint8_t *exact_copy(const uint8_t *src, size_t len)
{
    uint8_t *copy = zcl_malloc(len ? len : 1, "fuzz_file_wires_copy");
    if (!copy)
        abort();
    if (len)
        memcpy(copy, src, len);
    return copy;
}

/* Triples of (position u16 LE, xor u8). Positions wrap over the wire. */
static void apply_patches(uint8_t *wire, size_t wire_len,
                          const uint8_t *patch, size_t patch_len)
{
    if (wire_len == 0)
        return;
    for (size_t i = 0; i + 3 <= patch_len; i += 3) {
        size_t pos = (size_t)zcl_read_u16_le(patch + i) %
                     wire_len;
        wire[pos] ^= patch[i + 2];
    }
}

/* Splits "[n][n*3 patch bytes][tail]"; the patch part is clamped to the
 * input, the tail is whatever is left. */
static void split_patches(const uint8_t *in, size_t len,
                          const uint8_t **patch, size_t *patch_len,
                          const uint8_t **tail, size_t *tail_len)
{
    size_t want = len ? (size_t)(in[0] % FUZZ_FILE_PATCH_MAX) * 3u : 0;
    size_t have = len ? len - 1u : 0;
    if (want > have)
        want = have;
    *patch = len ? in + 1 : in;
    *patch_len = want;
    *tail = *patch + want;
    *tail_len = have - want;
}

/* ── init: valid bases ─────────────────────────────────────────────── */

static bool build_file_base(uint16_t version, uint8_t *out, size_t *out_len)
{
    struct file_offer offer;
    struct jub_point payment_key;
    uint8_t seed[32], secret[32];
    memset(&offer, 0, sizeof(offer));
    memset(seed, 0x5a, sizeof(seed));
    memset(offer.root_hash, 0x11, sizeof(offer.root_hash));
    memset(offer.network_genesis, FUZZ_FILE_GENESIS_BYTE,
           sizeof(offer.network_genesis));
    ed25519_keypair(offer.seller_pubkey, secret, seed);
    snprintf(offer.filename, sizeof(offer.filename), "fuzz-base.dat");
    offer.size_bytes = FILE_MARKET_CHUNK_SIZE + 1u;
    offer.num_chunks = 2;
    offer.price_per_mb = 1200;
    for (uint8_t d = 1;; d++) {
        memset(offer.z_addr, 0, sizeof(offer.z_addr));
        offer.z_addr[0] = d;
        if (sapling_diversifier_to_gd(&payment_key, offer.z_addr))
            break;
        if (d == UINT8_MAX)
            return false;
    }
    jub_to_bytes(offer.z_addr + 11, &payment_key);
    offer.auth_version = version;
    if (version == FILE_MARKET_OFFER_VERSION) {
        offer.peer_ip[15] = 7;
        offer.peer_port = 18034;
    } else {
        offer.endpoint_type = FILE_MARKET_ENDPOINT_ONION;
        memset(offer.onion_pubkey, 0x33, sizeof(offer.onion_pubkey));
    }
    offer.nonce = 1;
    offer.issued_unix = FUZZ_FILE_NOW - 10;
    offer.expires_unix = FUZZ_FILE_NOW + 600;
    return file_offer_auth_seal(&offer, seed) == FILE_OFFER_AUTH_OK &&
           file_offer_auth_encode_into(&offer, out,
                                       FILE_MARKET_OFFER_WIRE_BYTES_MAX,
                                       out_len) == FILE_OFFER_AUTH_OK;
}

static bool build_state_base(void)
{
    struct state_offer_batch_v1 batch;
    uint8_t seed[32];
    memset(&batch, 0, sizeof(batch));
    memset(seed, 0x6b, sizeof(seed));
    batch.version = STATE_OFFER_VERSION;
    batch.count = STATE_OFFER_MAX_PER_PEER;
    batch.offerer_tip_height = FUZZ_STATE_TIP;
    for (uint32_t i = 0; i < batch.count; i++) {
        struct state_offer_v1 *offer = &batch.offers[i];
        offer->version = STATE_OFFER_VERSION;
        offer->bundle_height = FUZZ_STATE_TIP - (int32_t)i;
        offer->offerer_tip_height = FUZZ_STATE_TIP;
        offer->chunk_size = STATE_OFFER_CHUNK_SIZE_BYTES;
        offer->num_chunks = 3;
        offer->kind = (uint16_t)(i % 2 ? ROM_ARTIFACT_HEADER_SEED
                                       : ROM_ARTIFACT_CONSENSUS_BUNDLE);
        offer->filename_len = 12;
        memset(offer->header_hash, 0x01 + (int)i, 32);
        memset(offer->content_digest, 0x21, 32);
        memset(offer->chunk_tree_root, 0x31, 32);
        memset(offer->mmb_peaks_digest, 0x41, 32);
        memset(offer->producer_receipt_id, 0x51, 32);
        offer->content_bytes = 2ull * STATE_OFFER_CHUNK_SIZE_BYTES + 5u;
        offer->issued_unix = FUZZ_STATE_ISSUED;
        memcpy(offer->filename, "bundle-0.dat", 12);
        offer->filename[7] = (uint8_t)('0' + i);
        if (state_offer_v1_sign(offer, seed) != STATE_OFFER_OK)
            return false;
    }
    return state_offer_batch_v1_encode(&batch, g_state_base,
                                       sizeof(g_state_base),
                                       &g_state_base_len) == STATE_OFFER_OK;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    /* Refusals log at ERROR; with the level off the run spends its time on
     * the decoders, not on stderr. Nothing else is silenced. */
    zcl_log_level_set(ZCL_LOG_OFF);
    if (!build_file_base(FILE_MARKET_OFFER_VERSION, g_file_base[0],
                         &g_file_base_len[0]) ||
        !build_file_base(FILE_MARKET_OFFER_VERSION_V2, g_file_base[1],
                         &g_file_base_len[1]) ||
        !build_state_base())
        abort();
    return 0;
}

/* ── file offer (file_market_offer.c) ──────────────────────────────── */

/* The v1 body is 471 bytes: u8 name_len at 215, then the 255-byte name field
 * that ends the v1 body. The decoder checks neither that the field's padding
 * is zero nor that name_len equals the length up to the first NUL, so the one
 * signed meaning has several wire encodings (reported as a finding, see the
 * lane notes). The signature covers the canonical re-encode, so the harness
 * holds every byte outside this field to the strict round trip and holds a
 * non-canonical name field to idempotence: the canonical wire must decode to
 * the very same offer, offer_id included. */
#define FUZZ_OFFER_NAME_LEN_OFF 215u
#define FUZZ_OFFER_NAME_END (FUZZ_OFFER_NAME_LEN_OFF + 1u + 255u)

static void require_canonical_or_name_only(const struct file_offer *o,
                                           const uint8_t *wire,
                                           const uint8_t *canonical,
                                           size_t wire_len)
{
    if (memcmp(wire, canonical, wire_len) == 0)
        return;
    if (memcmp(wire, canonical, FUZZ_OFFER_NAME_LEN_OFF) != 0 ||
        memcmp(wire + FUZZ_OFFER_NAME_END, canonical + FUZZ_OFFER_NAME_END,
               wire_len - FUZZ_OFFER_NAME_END) != 0)
        abort();
    /* Bytes after an embedded NUL stay in the struct's filename buffer on the
     * first decode and not on the second; the string is the same. */
    struct file_offer same = *o;
    size_t shown = strnlen(same.filename, sizeof(same.filename));
    memset(same.filename + shown, 0, sizeof(same.filename) - shown);
    struct file_offer again;
    if (file_offer_auth_decode(canonical, wire_len, &again) !=
            FILE_OFFER_AUTH_OK ||
        memcmp(&again, &same, sizeof(again)) != 0)
        abort();
}

static void check_file_offer_ok(const struct file_offer *o,
                                const uint8_t *wire, size_t wire_len)
{
    if (!file_offer_auth_version_supported(o->auth_version) ||
        o->endpoint_type > FILE_MARKET_ENDPOINT_ONION ||
        strnlen(o->filename, sizeof(o->filename)) >= sizeof(o->filename) ||
        o->filename[0] == '\0' || o->num_chunks == 0)
        abort();
    uint8_t canonical[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
    size_t canonical_len = 0;
    if (file_offer_auth_encode_into(o, canonical, sizeof(canonical),
                                    &canonical_len) != FILE_OFFER_AUTH_OK ||
        canonical_len != wire_len)
        abort();
    require_canonical_or_name_only(o, wire, canonical, wire_len);
    uint8_t genesis[32];
    memset(genesis, FUZZ_FILE_GENESIS_BYTE, sizeof(genesis));
    (void)file_offer_auth_verify_at(o, genesis, FUZZ_FILE_NOW);
}

static void fuzz_file_offer(const uint8_t *wire, size_t wire_len)
{
    struct guarded_file_offer g;
    memset(g.pre, FUZZ_FILE_CANARY, sizeof(g.pre));
    memset(g.post, FUZZ_FILE_CANARY, sizeof(g.post));
    memset(&g.out, FUZZ_FILE_CANARY, sizeof(g.out));
    uint8_t *copy = exact_copy(wire, wire_len);
    enum file_offer_auth_error error =
        file_offer_auth_decode(copy, wire_len, &g.out);
    if (error != FILE_OFFER_AUTH_OK)
        require_zeroed(&g.out, sizeof(g.out));
    else
        check_file_offer_ok(&g.out, copy, wire_len);
    require_filled(g.pre, sizeof(g.pre));
    require_filled(g.post, sizeof(g.post));
    free(copy);
}

static void fuzz_file_offer_patched(const uint8_t *in, size_t len)
{
    if (len == 0)
        return;
    unsigned which = in[0] & 1u;
    const uint8_t *patch, *tail;
    size_t patch_len, tail_len;
    split_patches(in + 1, len - 1, &patch, &patch_len, &tail, &tail_len);
    uint8_t wire[FILE_MARKET_OFFER_WIRE_BYTES_MAX];
    size_t wire_len = g_file_base_len[which];
    memcpy(wire, g_file_base[which], wire_len);
    apply_patches(wire, wire_len, patch, patch_len);
    /* A tail byte shortens or lengthens the wire so the size check is hit. */
    if (tail_len && tail[0] % 8 == 0)
        wire_len -= (size_t)(tail[0] / 8) % wire_len;
    fuzz_file_offer(wire, wire_len);
}

/* ── state offer batch (state_offer.c, the zfileaddr tail's decoder) ── */

static void check_state_batch_ok(const struct state_offer_batch_v1 *b,
                                 const uint8_t *wire, size_t wire_len)
{
    if (b->count > STATE_OFFER_MAX_PER_PEER)
        abort();
    char name[STATE_OFFER_NAME_MAX + 1];
    for (uint32_t i = 0; i < b->count; i++) {
        const struct state_offer_v1 *o = &b->offers[i];
        if (o->filename_len == 0 || o->filename_len >= STATE_OFFER_NAME_MAX ||
            o->filename[STATE_OFFER_NAME_MAX - 1] != 0 ||
            o->offerer_tip_height != b->offerer_tip_height)
            abort();
        if (!state_offer_v1_filename(o, name, sizeof(name)) ||
            strlen(name) != o->filename_len)
            abort();
        if (state_offer_v1_filename(o, name, o->filename_len))
            abort(); /* no room for the NUL: must refuse */
        (void)state_offer_v1_verify(o);
    }
    uint8_t canonical[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
    size_t canonical_len = 0;
    if (state_offer_batch_v1_encode(b, canonical, sizeof(canonical),
                                    &canonical_len) != STATE_OFFER_OK ||
        canonical_len != wire_len || memcmp(canonical, wire, wire_len) != 0)
        abort();
}

static void fuzz_state_batch(const uint8_t *wire, size_t wire_len)
{
    struct guarded_state_batch g;
    memset(g.pre, FUZZ_FILE_CANARY, sizeof(g.pre));
    memset(g.post, FUZZ_FILE_CANARY, sizeof(g.post));
    memset(&g.out, FUZZ_FILE_CANARY, sizeof(g.out));
    uint8_t *copy = exact_copy(wire, wire_len);
    enum state_offer_error error =
        state_offer_batch_v1_decode(&g.out, copy, wire_len);
    if (error != STATE_OFFER_OK) {
        /* The decoder stages into a local and copies out only on success. */
        require_filled((const uint8_t *)&g.out, sizeof(g.out));
    } else {
        check_state_batch_ok(&g.out, copy, wire_len);
    }
    require_filled(g.pre, sizeof(g.pre));
    require_filled(g.post, sizeof(g.post));
    free(copy);
}

static void fuzz_state_batch_patched(const uint8_t *in, size_t len)
{
    if (len == 0)
        return;
    uint32_t count = in[0] % (STATE_OFFER_MAX_PER_PEER + 1u);
    const uint8_t *patch, *tail;
    size_t patch_len, tail_len;
    split_patches(in + 1, len - 1, &patch, &patch_len, &tail, &tail_len);
    uint8_t wire[STATE_OFFER_BATCH_V1_MAX_WIRE_BYTES];
    memcpy(wire, g_state_base, g_state_base_len);
    /* Header count at byte 12: keep it consistent with the kept length. */
    wire[12] = (uint8_t)count;
    size_t wire_len = STATE_OFFER_BATCH_V1_HEADER_BYTES +
                      (size_t)count * STATE_OFFER_V1_WIRE_BYTES;
    apply_patches(wire, wire_len, patch, patch_len);
    if (tail_len && tail[0] % 8 == 0)
        wire_len -= (size_t)(tail[0] / 8) % wire_len;
    fuzz_state_batch(wire, wire_len);
}

/* ── file_service request parsers (pure) ───────────────────────────── */

static void fuzz_rom_requests(const uint8_t *wire, size_t wire_len)
{
    uint8_t *p = exact_copy(wire, wire_len);
    uint8_t root[32];
    uint32_t idx = 0xdeadbeefu;
    memset(root, FUZZ_FILE_CANARY, sizeof(root));
    bool ok = fs_parse_rom_request(p, (uint32_t)wire_len, root, &idx);
    if (ok) {
        if (wire_len != FS_ROM_REQUEST_SIZE || memcmp(p, "ROM", 3) != 0 ||
            memcmp(root, p + 3, 32) != 0 ||
            idx != zcl_read_u32_le(p + 35))
            abort();
    } else if (idx != 0xdeadbeefu) {
        abort();
    }
    memset(root, FUZZ_FILE_CANARY, sizeof(root));
    ok = fs_parse_rom_manifest_request(p, (uint32_t)wire_len, root);
    if (ok && (wire_len != FS_ROM_MANIFEST_REQUEST_SIZE ||
               memcmp(p, "RMF", 3) != 0 || memcmp(root, p + 3, 32) != 0))
        abort();
    if (!ok)
        require_filled(root, sizeof(root));
    if (fs_parse_rom_list_request(p, (uint32_t)wire_len) !=
        (wire_len == FS_ROM_LIST_REQUEST_SIZE && memcmp(p, "RLS", 3) == 0))
        abort();
    free(p);
}

static void check_serve_rng(const uint8_t *body, uint32_t blen,
                            uint16_t start, uint16_t end)
{
    if (blen < 8 || memcmp(body, "RNG", 3) != 0 ||
        start != zcl_read_u16_le(body + 3) ||
        end != zcl_read_u16_le(body + 5))
        abort();
}

static void check_serve_ok(const uint8_t *p, uint32_t plen, bool all,
                           bool rng, const uint8_t *puzzle, uint16_t start,
                           uint16_t end)
{
    if (all == rng)
        abort(); /* exactly one kind */
    if (puzzle && (puzzle != p || plen < FS_POW_SOLUTION_SIZE + 3u))
        abort();
    const uint8_t *body = puzzle ? p + FS_POW_SOLUTION_SIZE : p;
    uint32_t blen = puzzle ? plen - FS_POW_SOLUTION_SIZE : plen;
    if (all && (blen != 3 || memcmp(body, "ALL", 3) != 0 || start || end))
        abort();
    if (rng)
        check_serve_rng(body, blen, start, end);
}

static void fuzz_serve_request(const uint8_t *wire, size_t wire_len)
{
    uint8_t *p = exact_copy(wire, wire_len);
    bool all = true, rng = true;
    const uint8_t *puzzle = p;
    uint16_t start = 0xffffu, end = 0xffffu;
    bool ok = fs_parse_serve_request(p, (uint32_t)wire_len, &all, &rng,
                                     &puzzle, &start, &end);
    if (ok)
        check_serve_ok(p, (uint32_t)wire_len, all, rng, puzzle, start, end);
    else if (all || rng || puzzle || start || end)
        abort(); /* a refusal reports nothing */
    (void)fs_parse_serve_request(p, (uint32_t)wire_len, NULL, NULL, NULL,
                                 NULL, NULL);
    free(p);
}

/* ── chunk receivers over a local socketpair ───────────────────────── */

static void session_setup(struct fs_session *s, int fd, bool initiator)
{
    fs_session_init(s, fd);
    memset(s->key, 0x77, sizeof(s->key));
    s->key_established = true;
    memset(s->our_nonce, initiator ? 0xA1 : 0xB2, sizeof(s->our_nonce));
    memset(s->peer_nonce, initiator ? 0xB2 : 0xA1, sizeof(s->peer_nonce));
}

static void write_all(int fd, const uint8_t *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0)
            abort(); /* the socket buffer holds an input; never blocks */
        buf += n;
        len -= (size_t)n;
    }
}

/* Feed `bytes` to a fresh receiving session, then close the writer. */
static int feed_receiver(const uint8_t *bytes, size_t len)
{
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        abort();
    write_all(fds[1], bytes, len);
    close(fds[1]);
    session_setup(&g_rx, fds[0], false);
    return fds[0];
}

/* A claimed chunk size over the harness cap but inside the receiver's own
 * ceiling is folded under the cap; zero and over-ceiling stay as sent. */
static void cap_claim(uint8_t *header)
{
    uint32_t claim = zcl_read_u32_le(header);
    if (claim > FUZZ_FILE_CLAIM_CAP && claim <= FUZZ_FILE_PEER_CHUNK_MAX) {
        claim = (claim & (FUZZ_FILE_CLAIM_CAP - 1u)) | 1u;
        zcl_write_u32_le(header, claim);
    }
}

static void require_no_chunk(uint8_t *out, uint32_t out_size)
{
    if (out != NULL || out_size != 0)
        abort();
}

static void fuzz_fast_raw(const uint8_t *in, size_t len)
{
    if (len < 32)
        return;
    uint8_t digest[32];
    memcpy(digest, in, 32);
    uint8_t *stream = exact_copy(in + 32, len - 32);
    if (len - 32 >= 4)
        cap_claim(stream);
    int fd = feed_receiver(stream, len - 32);
    uint8_t *out = (uint8_t *)(uintptr_t)1;
    uint32_t out_size = 7;
    if (fs_recv_chunk_fast(&g_rx, &out, &out_size, digest)) {
        /* Not forgeable without the key; if it ever succeeds it must own a
         * buffer of the size it reports, which the free() below checks. */
        if (!out || out_size == 0 || out_size > FUZZ_FILE_CLAIM_CAP)
            abort();
        free(out);
    } else {
        require_no_chunk(out, out_size);
    }
    close(fd);
    free(stream);
}

static void fuzz_private_raw(const uint8_t *in, size_t len)
{
    if (len < 34)
        return;
    uint32_t expected = (uint32_t)zcl_read_u16_le(in) + 1u;
    uint8_t digest[32];
    memcpy(digest, in + 2, 32);
    uint8_t *stream = exact_copy(in + 34, len - 34);
    if (len - 34 >= 4)
        cap_claim(stream);
    int fd = feed_receiver(stream, len - 34);
    uint8_t *out = (uint8_t *)(uintptr_t)1;
    uint32_t out_size = 7;
    if (fs_recv_chunk_private(&g_rx, &out, &out_size, expected, digest)) {
        if (!out || out_size != expected)
            abort();
        free(out);
    } else {
        require_no_chunk(out, out_size);
    }
    close(fd);
    free(stream);
}

/* Send one chunk through a real sender session and capture the wire. */
static size_t capture_frame(bool priv, const uint8_t *chunk, uint32_t size,
                            const uint8_t digest[32], uint8_t *frame,
                            size_t frame_cap)
{
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        abort();
    session_setup(&g_tx, fds[1], true);
    bool sent = priv ? fs_send_chunk_private(&g_tx, chunk, size, digest)
                     : fs_send_chunk_fast(&g_tx, chunk, size, digest);
    if (!sent)
        abort();
    close(fds[1]);
    size_t got = 0;
    for (;;) {
        ssize_t n = read(fds[0], frame + got, frame_cap - got);
        if (n < 0)
            abort();
        if (n == 0)
            break;
        got += (size_t)n;
    }
    close(fds[0]);
    return got;
}

/* Patch positions skip header bytes 2 and 3 so a claim stays small. */
static void patch_frame(uint8_t *frame, size_t frame_len,
                        const uint8_t *patch, size_t patch_len)
{
    for (size_t i = 0; i + 3 <= patch_len; i += 3) {
        size_t slot = (size_t)zcl_read_u16_le(patch + i) %
                      (frame_len - 2u);
        frame[slot < 2 ? slot : slot + 2u] ^= patch[i + 2];
    }
}

static void fuzz_sealed(bool priv, const uint8_t *in, size_t len)
{
    const uint8_t *patch, *chunk;
    size_t patch_len, chunk_len;
    split_patches(in, len, &patch, &patch_len, &chunk, &chunk_len);
    if (chunk_len == 0)
        return;
    if (chunk_len > FUZZ_FILE_CHUNK_MAX)
        chunk_len = FUZZ_FILE_CHUNK_MAX;
    uint8_t digest[32];
    sha3_256(chunk, chunk_len, digest);
    uint8_t frame[FUZZ_FILE_CHUNK_MAX + 128u], original[sizeof(frame)];
    size_t frame_len = capture_frame(priv, chunk, (uint32_t)chunk_len, digest,
                                     frame, sizeof(frame));
    if (frame_len < chunk_len + 4u)
        abort();
    memcpy(original, frame, frame_len);
    patch_frame(frame, frame_len, patch, patch_len);
    bool intact = memcmp(frame, original, frame_len) == 0;
    int fd = feed_receiver(frame, frame_len);
    uint8_t *out = NULL;
    uint32_t out_size = 0;
    bool ok = priv ? fs_recv_chunk_private(&g_rx, &out, &out_size,
                                           (uint32_t)chunk_len, digest)
                   : fs_recv_chunk_fast(&g_rx, &out, &out_size, digest);
    if (ok != intact)
        abort(); /* intact frames verify; any changed byte is refused */
    if (ok) {
        if (out_size != chunk_len || memcmp(out, chunk, chunk_len) != 0 ||
            g_rx.recv_counter != 1)
            abort();
        free(out);
    } else {
        require_no_chunk(out, out_size);
    }
    close(fd);
}

/* The first byte picks the decoder; the rest is its input. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0 || size > FUZZ_FILE_MAX_INPUT)
        return 0;

    const uint8_t *in = data + 1;
    size_t len = size - 1;
    switch (data[0] % FUZZ_FILE_ARMS) {
    case 0: fuzz_file_offer(in, len); break;
    case 1: fuzz_file_offer_patched(in, len); break;
    case 2: fuzz_state_batch(in, len); break;
    case 3: fuzz_state_batch_patched(in, len); break;
    case 4:
        fuzz_rom_requests(in, len);
        fuzz_serve_request(in, len);
        break;
    case 5: fuzz_fast_raw(in, len); break;
    case 6: fuzz_sealed(false, in, len); break;
    case 7: fuzz_private_raw(in, len); break;
    default: fuzz_sealed(true, in, len); break;
    }
    return 0;
}
