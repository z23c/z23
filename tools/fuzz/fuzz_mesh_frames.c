/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Exercise the peer-reachable mesh frame decoders (terminal, capability,
 * private object, stream, game, fleet board, agent broker) and the Noise
 * record-layer bounds under sanitizers. The first input byte picks the
 * decoder; the rest is its input. Every accepted frame must re-encode to the
 * bytes it came from, every refusal must leave its output as the header
 * documents, and every decoded length or count must sit inside the array it
 * describes. A guard struct around each output catches a write past the
 * struct that ASan cannot see. */

#include "base/serialize_le.h"
#include "config/boot_mesh_game.h"
#include "config/mesh_stream.h"
#include "crypto/ed25519.h"
#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"
#include "noise/session_transport.h"
#include "session/agent_broker_proto.h"
#include "session/fleet_board_proto.h"
#include "session/mesh_capability_proto.h"
#include "session/mesh_private_object_frame.h"
#include "session/mesh_terminal_proto.h"
#include "util/sync.h"

#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

volatile sig_atomic_t g_shutdown_requested = 0;

#define FUZZ_MESH_MAX_INPUT 20480u
#define GUARD_BYTES 64u
#define GUARD_FILL 0xA5u
#define OUT_FILL 0x5Au

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* ── helpers ─────────────────────────────────────────────────────────── */

static void require(bool ok)
{
    if (!ok)
        abort();
}

static void require_fill(const uint8_t *p, size_t len, uint8_t fill)
{
    for (size_t i = 0; i < len; i++)
        if (p[i] != fill)
            abort();
}

static void require_zeroed(const void *p, size_t len)
{
    require_fill(p, len, 0);
}

/* A heap block of exactly `len` bytes, so ASan sees any write or read past
 * the capacity the callee was told about. */
static uint8_t *exact_alloc(size_t len)
{
    uint8_t *p = malloc(len);
    require(p != NULL || len == 0);
    return p;
}

#define GUARDED(T) \
    struct { uint8_t pre[GUARD_BYTES]; T v; uint8_t post[GUARD_BYTES]; }
#define GUARD_ARM(g) \
    do { \
        memset((g).pre, GUARD_FILL, sizeof((g).pre)); \
        memset(&(g).v, OUT_FILL, sizeof((g).v)); \
        memset((g).post, GUARD_FILL, sizeof((g).post)); \
    } while (0)
#define GUARD_CHECK(g) \
    do { \
        require_fill((g).pre, sizeof((g).pre), GUARD_FILL); \
        require_fill((g).post, sizeof((g).post), GUARD_FILL); \
    } while (0)

/* Reads bytes off the fuzz input; past the end it yields zeros. */
struct rd {
    const uint8_t *p;
    size_t n, i;
};

static uint8_t rd8(struct rd *r)
{
    return r->i < r->n ? r->p[r->i++] : 0;
}

static uint16_t rd16(struct rd *r)
{
    uint16_t lo = rd8(r);
    return (uint16_t)(lo | (uint16_t)(rd8(r) << 8));
}

static uint64_t rd64(struct rd *r)
{
    uint64_t v = 0;
    for (unsigned s = 0; s < 64; s += 8)
        v |= (uint64_t)rd8(r) << s;
    return v;
}

static void rd_bytes(struct rd *r, uint8_t *dst, size_t len)
{
    for (size_t i = 0; i < len; i++)
        dst[i] = rd8(r);
}

/* 32 bytes, never all zero. */
static void rd_id(struct rd *r, uint8_t dst[32])
{
    rd_bytes(r, dst, 32);
    dst[0] |= 1u;
}

/* A fixed Ed25519 identity for the paths that must carry a real signature. */
static uint8_t g_seed[32];
static uint8_t g_pk[32];
static uint8_t g_sk[32];
static bool g_keys_ready;

static void keys_init(void)
{
    if (g_keys_ready)
        return;
    for (size_t i = 0; i < sizeof(g_seed); i++)
        g_seed[i] = (uint8_t)(0x40u + i);
    ed25519_keypair(g_pk, g_sk, g_seed);
    g_keys_ready = true;
}

/* ── mesh_terminal_proto ─────────────────────────────────────────────── */

static void term_open(const uint8_t *w, size_t n)
{
    GUARDED(struct mesh_terminal_open_v1) g;
    GUARD_ARM(g);
    enum mesh_terminal_proto_error e =
        mesh_terminal_open_v1_decode(&g.v, w, n);
    GUARD_CHECK(g);
    if (e != MESH_TERMINAL_PROTO_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    require(g.v.cols >= 1 && g.v.cols <= MESH_TERMINAL_MAX_COLS);
    require(g.v.rows >= 1 && g.v.rows <= MESH_TERMINAL_MAX_ROWS);
    uint8_t canon[MESH_TERMINAL_OPEN_V1_WIRE_BYTES];
    require(mesh_terminal_open_v1_encode(&g.v, canon) ==
            MESH_TERMINAL_PROTO_OK);
    require(n == sizeof(canon) && memcmp(w, canon, n) == 0);
    uint8_t root[32];
    require(mesh_terminal_open_v1_root(&g.v, root) == MESH_TERMINAL_PROTO_OK);
}

static void term_receipt_try(const uint8_t *w, size_t n)
{
    GUARDED(struct mesh_terminal_receipt_v1) g;
    GUARD_ARM(g);
    enum mesh_terminal_proto_error e =
        mesh_terminal_receipt_v1_decode(&g.v, w, n);
    GUARD_CHECK(g);
    if (e != MESH_TERMINAL_PROTO_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    size_t len = g.v.capsule_len;
    require(len <= MESH_TERMINAL_CAPSULE_MAX);
    require_zeroed(g.v.capsule + len, MESH_TERMINAL_CAPSULE_MAX - len);
    require(mesh_terminal_receipt_v1_wire_size(&g.v) == n);
    uint8_t *out = exact_alloc(n);
    size_t out_len = 0;
    require(mesh_terminal_receipt_v1_encode(&g.v, out, n, &out_len) ==
            MESH_TERMINAL_PROTO_OK);
    require(out_len == n && memcmp(w, out, n) == 0);
    free(out);
    uint8_t root[32];
    require(mesh_terminal_receipt_v1_root(&g.v, root) ==
            MESH_TERMINAL_PROTO_OK);
}

/* Wire offsets inside a receipt: capsule_len, capsule_root, capsule. */
#define TERM_RECEIPT_LEN_OFF 14u
#define TERM_RECEIPT_ROOT_OFF 304u
#define TERM_RECEIPT_CAPSULE_OFF 336u

/* The capsule root is a hash, which mutation cannot produce: recompute it in
 * a copy so the decoder's deeper checks (timing, signature presence) run. */
static void term_receipt(const uint8_t *w, size_t n)
{
    term_receipt_try(w, n);
    if (n < MESH_TERMINAL_RECEIPT_V1_FIXED_BYTES ||
        n > MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES)
        return;
    uint8_t buf[MESH_TERMINAL_RECEIPT_V1_MAX_WIRE_BYTES];
    memcpy(buf, w, n);
    size_t cl = zcl_read_u16_le(buf + TERM_RECEIPT_LEN_OFF);
    if (cl > MESH_TERMINAL_CAPSULE_MAX ||
        n != MESH_TERMINAL_RECEIPT_V1_FIXED_BYTES + cl)
        return;
    require(mesh_terminal_capsule_v1_root(buf + TERM_RECEIPT_CAPSULE_OFF, cl,
                                          buf + TERM_RECEIPT_ROOT_OFF) ==
            MESH_TERMINAL_PROTO_OK);
    term_receipt_try(buf, n);
}

static void term_data(const uint8_t *w, size_t n)
{
    GUARDED(struct mesh_terminal_data_v1) g;
    GUARD_ARM(g);
    enum mesh_terminal_proto_error e =
        mesh_terminal_data_v1_decode(&g.v, w, n);
    GUARD_CHECK(g);
    if (e != MESH_TERMINAL_PROTO_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    size_t len = g.v.payload_len;
    require(len <= MESH_TERMINAL_DATA_PAYLOAD_MAX);
    require_zeroed(g.v.payload + len, MESH_TERMINAL_DATA_PAYLOAD_MAX - len);
    uint8_t *out = exact_alloc(n);
    size_t out_len = 0;
    require(mesh_terminal_data_v1_encode(&g.v, out, n, &out_len) ==
            MESH_TERMINAL_PROTO_OK);
    require(out_len == n && memcmp(w, out, n) == 0);
    free(out);
}

static void term_resize(const uint8_t *w, size_t n)
{
    GUARDED(struct mesh_terminal_resize_v1) g;
    GUARD_ARM(g);
    enum mesh_terminal_proto_error e =
        mesh_terminal_resize_v1_decode(&g.v, w, n);
    GUARD_CHECK(g);
    if (e != MESH_TERMINAL_PROTO_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    require(g.v.cols >= 1 && g.v.cols <= MESH_TERMINAL_MAX_COLS);
    require(g.v.rows >= 1 && g.v.rows <= MESH_TERMINAL_MAX_ROWS);
    uint8_t canon[MESH_TERMINAL_RESIZE_V1_WIRE_BYTES];
    require(mesh_terminal_resize_v1_encode(&g.v, canon) ==
            MESH_TERMINAL_PROTO_OK);
    require(n == sizeof(canon) && memcmp(w, canon, n) == 0);
}

static void term_close(const uint8_t *w, size_t n)
{
    GUARDED(struct mesh_terminal_close_v1) g;
    GUARD_ARM(g);
    enum mesh_terminal_proto_error e =
        mesh_terminal_close_v1_decode(&g.v, w, n);
    GUARD_CHECK(g);
    if (e != MESH_TERMINAL_PROTO_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    require(g.v.reason <= MESH_TERMINAL_CLOSE_SHUTDOWN);
    uint8_t canon[MESH_TERMINAL_CLOSE_V1_WIRE_BYTES];
    require(mesh_terminal_close_v1_encode(&g.v, canon) ==
            MESH_TERMINAL_PROTO_OK);
    require(n == sizeof(canon) && memcmp(w, canon, n) == 0);
}

/* ── mesh_capability_proto ───────────────────────────────────────────── */

typedef struct mesh_capability_frame_view_v1 cap_view;

static size_t cap_wire_size(enum mesh_capability_frame_kind kind)
{
    switch (kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        return MESH_CAPABILITY_PROPOSAL_V1_WIRE_BYTES;
    case MESH_CAPABILITY_FRAME_COMMIT:
        return MESH_CAPABILITY_COMMIT_V1_WIRE_BYTES;
    case MESH_CAPABILITY_FRAME_GRANT:
        return MESH_CAPABILITY_GRANT_V1_WIRE_BYTES;
    case MESH_CAPABILITY_FRAME_REFUSAL:
        return MESH_CAPABILITY_REFUSAL_V1_WIRE_BYTES;
    case MESH_CAPABILITY_FRAME_RENEW:
        return MESH_CAPABILITY_RENEW_V1_WIRE_BYTES;
    case MESH_CAPABILITY_FRAME_CANCEL:
        return MESH_CAPABILITY_CANCEL_V1_WIRE_BYTES;
    case MESH_CAPABILITY_FRAME_ACK:
        return MESH_CAPABILITY_ACK_V1_WIRE_BYTES;
    }
    return 0;
}

static enum mesh_capability_proto_error cap_encode(
    const cap_view *f, uint8_t *out, size_t cap, size_t *len)
{
    switch (f->kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        return mesh_capability_proposal_v1_encode(&f->body.proposal, out, cap,
                                                  len);
    case MESH_CAPABILITY_FRAME_COMMIT:
        return mesh_capability_commit_v1_encode(&f->body.commit, out, cap,
                                                len);
    case MESH_CAPABILITY_FRAME_GRANT:
        return mesh_capability_grant_v1_encode(&f->body.grant, out, cap, len);
    case MESH_CAPABILITY_FRAME_REFUSAL:
        return mesh_capability_refusal_v1_encode(&f->body.refusal, out, cap,
                                                 len);
    case MESH_CAPABILITY_FRAME_RENEW:
        return mesh_capability_renew_v1_encode(&f->body.renew, out, cap, len);
    case MESH_CAPABILITY_FRAME_CANCEL:
        return mesh_capability_cancel_v1_encode(&f->body.cancel, out, cap,
                                                len);
    case MESH_CAPABILITY_FRAME_ACK:
        return mesh_capability_ack_v1_encode(&f->body.ack, out, cap, len);
    }
    return MESH_CAPABILITY_PROTO_KIND_INVALID;
}

/* A frame that decoded must validate and re-encode to its own bytes. */
static void cap_require_canonical(const cap_view *f, const uint8_t *w,
                                  size_t n)
{
    require(cap_wire_size(f->kind) == n);
    require(mesh_capability_frame_v1_validate(f) == MESH_CAPABILITY_PROTO_OK);
    uint8_t *out = exact_alloc(n);
    size_t out_len = 0;
    require(cap_encode(f, out, n, &out_len) == MESH_CAPABILITY_PROTO_OK);
    require(out_len == n && memcmp(w, out, n) == 0);
    free(out);
    uint8_t root[32];
    require(mesh_capability_frame_v1_root(f, root) == MESH_CAPABILITY_PROTO_OK);
}

static bool cap_decode_check(const uint8_t *w, size_t n)
{
    GUARDED(cap_view) g;
    GUARD_ARM(g);
    enum mesh_capability_proto_error e =
        mesh_capability_frame_v1_decode(&g.v, w, n);
    GUARD_CHECK(g);
    if (e != MESH_CAPABILITY_PROTO_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return false;
    }
    cap_require_canonical(&g.v, w, n);
    return true;
}

static void cap_build_proposal(struct mesh_capability_proposal_v1 *p,
                               struct rd *r)
{
    rd_id(r, p->network_genesis); rd_id(r, p->proposal_id);
    rd_id(r, p->target_master_pubkey); rd_id(r, p->subject_master_pubkey);
    rd_id(r, p->subject_noise_static); rd_id(r, p->input_root);
    rd_id(r, p->nonce); rd_id(r, p->idempotency_key);
    p->capability = UINT64_C(1) << (rd8(r) % 6u);
    p->result_mask = 1u + rd8(r) % 3u;
    p->max_bytes = 1u + rd64(r) % MESH_CAPABILITY_MAX_BYTES;
    p->max_cpu_milliseconds = 1u + rd64(r) % MESH_CAPABILITY_MAX_CPU_MILLISECONDS;
    p->max_memory_bytes = 1u + rd64(r) % MESH_CAPABILITY_MAX_MEMORY_BYTES;
    p->max_processes = 1u + rd8(r) % MESH_CAPABILITY_MAX_PROCESSES;
    p->max_concurrency = 1u + rd8(r) % MESH_CAPABILITY_MAX_CONCURRENCY;
    p->max_wall_milliseconds = 1u + rd64(r) % MESH_CAPABILITY_MAX_WALL_MILLISECONDS;
    p->not_before_unix = 1u + rd64(r) % UINT64_C(4000000000);
    p->expires_unix = p->not_before_unix + 1u +
                      rd64(r) % MESH_CAPABILITY_MAX_LIFETIME_SECONDS;
    p->deny_mask = MESH_CAPABILITY_POLICY_DENY_REQUIRED;
}

static void cap_build_commit(struct mesh_capability_commit_v1 *c, struct rd *r)
{
    rd_id(r, c->proposal_id); rd_id(r, c->proposal_root);
    rd_id(r, c->commit_id); rd_id(r, c->target_master_pubkey);
    rd_id(r, c->subject_master_pubkey); rd_id(r, c->transcript_hash);
    c->connection_generation = 1u + rd64(r) % UINT64_C(1000000);
    c->plan_generation = rd64(r);
    c->committed_unix = 1u + rd64(r) % UINT64_C(4000000000);
}

static void cap_build_grant(struct mesh_capability_grant_v1 *g, struct rd *r)
{
    rd_id(r, g->proposal_id); rd_id(r, g->proposal_root);
    rd_id(r, g->commit_id); rd_id(r, g->grant_id); rd_id(r, g->grant_nonce);
    rd_id(r, g->target_master_pubkey); rd_id(r, g->subject_master_pubkey);
    g->issued_unix = 1u + rd64(r) % UINT64_C(1000000000);
    g->not_before_unix = g->issued_unix + rd64(r) % UINT64_C(1000);
    g->expires_unix = g->not_before_unix + 1u +
                      rd64(r) % MESH_CAPABILITY_MAX_LIFETIME_SECONDS;
    g->revocation_generation = rd64(r);
}

static void cap_build_small(cap_view *f, struct rd *r)
{
    switch (f->kind) {
    case MESH_CAPABILITY_FRAME_REFUSAL: {
        struct mesh_capability_refusal_v1 *x = &f->body.refusal;
        rd_id(r, x->request_id); rd_id(r, x->request_root);
        rd_id(r, x->target_master_pubkey);
        x->reason = (enum mesh_capability_refusal_reason)(1u + rd8(r) % 9u);
        x->observed_unix = 1u + rd64(r) % UINT64_C(4000000000);
        x->authority_generation = rd64(r);
        break;
    }
    case MESH_CAPABILITY_FRAME_RENEW: {
        struct mesh_capability_renew_v1 *x = &f->body.renew;
        rd_id(r, x->request_id); rd_id(r, x->prior_grant_id);
        rd_id(r, x->replacement_proposal_id);
        rd_id(r, x->replacement_proposal_root);
        rd_id(r, x->target_master_pubkey); rd_id(r, x->subject_master_pubkey);
        x->requested_not_before_unix = 1u + rd64(r) % UINT64_C(1000000000);
        x->requested_expires_unix = x->requested_not_before_unix + 1u +
            rd64(r) % MESH_CAPABILITY_MAX_LIFETIME_SECONDS;
        x->revocation_generation = rd64(r);
        break;
    }
    case MESH_CAPABILITY_FRAME_CANCEL: {
        struct mesh_capability_cancel_v1 *x = &f->body.cancel;
        rd_id(r, x->cancel_id); rd_id(r, x->grant_id);
        rd_id(r, x->operation_id); rd_id(r, x->target_master_pubkey);
        rd_id(r, x->subject_master_pubkey);
        x->requested_unix = 1u + rd64(r) % UINT64_C(4000000000);
        break;
    }
    default: {
        struct mesh_capability_ack_v1 *x = &f->body.ack;
        rd_id(r, x->ack_id); rd_id(r, x->request_id);
        rd_id(r, x->request_root); rd_id(r, x->target_master_pubkey);
        rd_id(r, x->subject_master_pubkey);
        x->acknowledged_kind =
            (enum mesh_capability_frame_kind)(1u + rd8(r) % 6u);
        x->status = (enum mesh_capability_ack_status)(1u + rd8(r) % 2u);
        x->observed_unix = 1u + rd64(r) % UINT64_C(4000000000);
        x->authority_generation = rd64(r);
        break;
    }
    }
}

/* Every kind ends with signer_online_pubkey[32] and signature[64]. */
static uint8_t *cap_signer_key(cap_view *f)
{
    switch (f->kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        return f->body.proposal.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_COMMIT:
        return f->body.commit.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_GRANT:
        return f->body.grant.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_REFUSAL:
        return f->body.refusal.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_RENEW:
        return f->body.renew.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_CANCEL:
        return f->body.cancel.signer_online_pubkey;
    case MESH_CAPABILITY_FRAME_ACK:
        return f->body.ack.signer_online_pubkey;
    }
    return NULL;
}

static void cap_build(cap_view *f, struct rd *r)
{
    memset(f, 0, sizeof(*f));
    f->kind = (enum mesh_capability_frame_kind)(1u + rd8(r) % 7u);
    switch (f->kind) {
    case MESH_CAPABILITY_FRAME_PROPOSAL:
        cap_build_proposal(&f->body.proposal, r); break;
    case MESH_CAPABILITY_FRAME_COMMIT:
        cap_build_commit(&f->body.commit, r); break;
    case MESH_CAPABILITY_FRAME_GRANT:
        cap_build_grant(&f->body.grant, r); break;
    default:
        cap_build_small(f, r); break;
    }
    memcpy(cap_signer_key(f), g_pk, 32);
}

/* Build a legal signed frame from the input, encode it, decode it, and hold
 * the decode to the same bytes; then flip one bit and hold the decoder to
 * either a refusal or the same canonical rule. */
static void cap_signed(const uint8_t *w, size_t n)
{
    struct rd r = {w, n, 0};
    cap_view f;
    cap_build(&f, &r);
    if (mesh_capability_frame_v1_sign(&f, g_seed) != MESH_CAPABILITY_PROTO_OK)
        return;
    size_t size = cap_wire_size(f.kind);
    uint8_t *wire = exact_alloc(size);
    size_t wire_len = 0;
    require(cap_encode(&f, wire, size, &wire_len) == MESH_CAPABILITY_PROTO_OK);
    require(wire_len == size);
    require(cap_decode_check(wire, size));
    size_t pos = rd16(&r) % size;
    wire[pos] ^= (uint8_t)(1u << (rd8(&r) % 8u));
    (void)cap_decode_check(wire, size);
    free(wire);
}

static void fuzz_capability(const uint8_t *w, size_t n)
{
    if (n && (w[0] & 1u))
        (void)cap_decode_check(w + 1, n - 1);
    else
        cap_signed(w, n);
}

/* ── mesh_private_object_frame ───────────────────────────────────────── */

static enum mesh_private_object_frame_error pof_encode(
    const struct mesh_private_object_frame_view_v1 *f, uint8_t *out,
    size_t cap, size_t *len)
{
    switch (f->kind) {
    case MESH_PRIVATE_OBJECT_FRAME_OFFER:
        return mesh_private_object_frame_offer_v1_encode(&f->body.offer, out,
                                                         cap, len);
    case MESH_PRIVATE_OBJECT_FRAME_REQUEST:
        return mesh_private_object_frame_request_v1_encode(&f->body.request,
                                                           out, cap, len);
    case MESH_PRIVATE_OBJECT_FRAME_CHUNK:
        return mesh_private_object_frame_chunk_v1_encode(&f->body.chunk, out,
                                                         cap, len);
    case MESH_PRIVATE_OBJECT_FRAME_CANCEL:
        return mesh_private_object_frame_cancel_v1_encode(&f->body.cancel, out,
                                                          cap, len);
    }
    return MESH_PRIVATE_OBJECT_FRAME_KIND_INVALID;
}

static void pof_check(const uint8_t *w, size_t n)
{
    GUARDED(struct mesh_private_object_frame_view_v1) g;
    GUARD_ARM(g);
    enum mesh_private_object_frame_error e =
        mesh_private_object_frame_v1_decode(&g.v, w, n);
    GUARD_CHECK(g);
    if (e != MESH_PRIVATE_OBJECT_FRAME_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return;
    }
    if (g.v.kind == MESH_PRIVATE_OBJECT_FRAME_CHUNK) {
        const struct mesh_private_object_chunk_v1 *c = &g.v.body.chunk;
        require(c->sealed_len > MESH_PRIVATE_OBJECT_TAG_BYTES);
        require(c->sealed_len <= MESH_PRIVATE_OBJECT_CHUNK_BYTES);
        require(c->sealed == w + MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES);
        require(n == MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES +
                         (size_t)c->sealed_len);
    }
    uint8_t *out = exact_alloc(n);
    size_t out_len = 0;
    require(pof_encode(&g.v, out, n, &out_len) == MESH_PRIVATE_OBJECT_FRAME_OK);
    require(out_len == n && memcmp(w, out, n) == 0);
    free(out);
}

/* A chunk frame near the 64 KiB seal bound: the fuzz input is capped far
 * below it, so the body is synthesised and the declared length is the
 * fuzzed part. */
static void pof_big_chunk(const uint8_t *w, size_t n)
{
    struct rd r = {w, n, 0};
    uint32_t sealed_len = MESH_PRIVATE_OBJECT_CHUNK_BYTES - 2u + rd8(&r) % 5u;
    size_t body = MESH_PRIVATE_OBJECT_FRAME_CHUNK_FIXED_BYTES + sealed_len;
    size_t actual = body - 1u + rd8(&r) % 3u;
    uint8_t *frame = exact_alloc(actual);
    memset(frame, 0, actual);
    memcpy(frame, "ZMPO", 4);
    frame[4] = MESH_PRIVATE_OBJECT_FRAME_VERSION;
    frame[6] = MESH_PRIVATE_OBJECT_FRAME_CHUNK;
    memset(frame + 8, 1, 64);
    frame[72] = 1;
    zcl_write_u32_le(frame + 84, sealed_len);
    pof_check(frame, actual);
    free(frame);
}

static void fuzz_pof(const uint8_t *w, size_t n)
{
    if (n && (w[0] & 1u))
        pof_check(w + 1, n - 1);
    else
        pof_big_chunk(w, n);
}

/* ── mesh_game ───────────────────────────────────────────────────────── */

/* The roster decoder reads `reachable` as `byte != 0` and the composer
 * writes 1, so a canonical wire carries 0 or 1 there. Normalise the copy we
 * compare against; the leniency itself is reported, not asserted. */
static void game_normalise_roster(uint8_t *wire, size_t n)
{
    if (n < 35u || wire[0] != MESH_GAME_KIND_ROSTER)
        return;
    size_t stride = 33u + wire[33];
    for (size_t i = 0; i < wire[34]; i++) {
        size_t at = 35u + i * stride + 32u;
        if (at < n)
            wire[at] = wire[at] ? 1u : 0u;
    }
}

static void game_check_bounds(const struct mesh_game_frame *f)
{
    switch (f->kind) {
    case MESH_GAME_KIND_ROSTER:
        require(f->body.roster.row_count <= MESH_GAME_ROSTER_ROWS_MAX);
        require(f->body.roster.asset_count <= MESH_GAME_ASSET_MAX);
        break;
    case MESH_GAME_KIND_MATCH_OPEN:
        require(f->body.match_open.airships <= MESH_GAME_AIRSHIPS_MAX);
        break;
    case MESH_GAME_KIND_MATCH_STATE:
        require(f->body.match_state.airships <= MESH_GAME_AIRSHIPS_MAX);
        break;
    case MESH_GAME_KIND_MATCH_CLOSE:
        require(f->body.match_close.reason_len <= MESH_GAME_REASON_MAX);
        require(f->body.match_close.reason[f->body.match_close.reason_len] ==
                '\0');
        break;
    case MESH_GAME_KIND_HELLO:
        break;
    }
}

static void game_parse_check(const uint8_t *w, size_t n)
{
    GUARDED(struct mesh_game_frame) g;
    GUARD_ARM(g);
    enum mesh_game_refusal e = mesh_game_parse(w, n, &g.v);
    GUARD_CHECK(g);
    if (e != MESH_GAME_OK)
        return;
    game_check_bounds(&g.v);
    uint8_t *out = exact_alloc(n);
    size_t got = mesh_game_compose(&g.v, out, n);
    uint8_t *want = exact_alloc(n);
    memcpy(want, w, n);
    game_normalise_roster(want, n);
    require(got == n && memcmp(out, want, n) == 0);
    free(want);
    free(out);
}

static void game_fill_roster(struct mesh_game_roster *x, struct rd *r)
{
    rd_bytes(r, x->zid, 32);
    x->asset_count = rd8(r) % 6u;
    x->row_count = rd8(r) % 40u;
    for (size_t i = 0; i < MESH_GAME_ROSTER_ROWS_MAX; i++) {
        rd_bytes(r, x->rows[i].noise_fingerprint, 32);
        x->rows[i].reachable = (rd8(r) & 1u) != 0;
        rd_bytes(r, x->rows[i].assets, MESH_GAME_ASSET_MAX);
    }
}

static void game_fill(struct mesh_game_frame *f, struct rd *r)
{
    memset(f, 0, sizeof(*f));
    f->kind = (enum mesh_game_kind)(rd8(r) % 7u);
    switch (f->kind) {
    case MESH_GAME_KIND_HELLO:
        rd_bytes(r, f->body.hello.zid, 32);
        rd_bytes(r, f->body.hello.roster_digest, 32);
        break;
    case MESH_GAME_KIND_ROSTER:
        game_fill_roster(&f->body.roster, r);
        break;
    case MESH_GAME_KIND_MATCH_OPEN:
        f->body.match_open.seed = rd64(r);
        f->body.match_open.airships = rd8(r) % 40u;
        break;
    case MESH_GAME_KIND_MATCH_STATE:
        f->body.match_state.tick = (uint32_t)rd64(r);
        f->body.match_state.airships = rd8(r) % 40u;
        for (size_t i = 0; i < MESH_GAME_AIRSHIPS_MAX; i++)
            rd_bytes(r, f->body.match_state.poses[i], MESH_GAME_POSE_BYTES);
        break;
    default:
        f->body.match_close.reason_len = rd8(r) % 40u;
        rd_bytes(r, (uint8_t *)f->body.match_close.reason,
                 MESH_GAME_REASON_MAX);
        break;
    }
}

/* Compose from a fuzzed frame into a buffer of exactly the capacity named:
 * the composer must never write past it, and what it writes must parse. */
static void game_compose_check(const uint8_t *w, size_t n)
{
    struct rd r = {w, n, 0};
    struct mesh_game_frame f;
    game_fill(&f, &r);
    size_t cap = rd16(&r) % (MESH_GAME_FRAME_MAX + 8u);
    uint8_t *out = exact_alloc(cap);
    size_t got = mesh_game_compose(&f, out, cap);
    require(got <= cap);
    if (got) {
        struct mesh_game_frame back;
        require(mesh_game_parse(out, got, &back) == MESH_GAME_OK);
        uint8_t *again = exact_alloc(got);
        require(mesh_game_compose(&back, again, got) == got);
        require(memcmp(out, again, got) == 0);
        free(again);
    }
    free(out);
}

static void fuzz_game(const uint8_t *w, size_t n)
{
    if (n && (w[0] & 1u))
        game_parse_check(w + 1, n - 1);
    else
        game_compose_check(w, n);
}

/* ── fleet_board_proto ───────────────────────────────────────────────── */

static void board_check_post(const struct fleet_board_post *p)
{
    require(p->kind < FLEET_BOARD_KIND__COUNT);
    require(p->scope < FLEET_BOARD_SCOPE__COUNT);
    require(strnlen(p->room, sizeof(p->room)) <= FLEET_BOARD_ROOM_MAX);
    require(strnlen(p->agent, sizeof(p->agent)) <= FLEET_BOARD_AGENT_MAX);
    require(strnlen(p->slug, sizeof(p->slug)) <= FLEET_BOARD_SLUG_MAX);
    require(strnlen(p->title, sizeof(p->title)) <= FLEET_BOARD_TITLE_MAX);
    require(strnlen(p->receipt, sizeof(p->receipt)) <= FLEET_BOARD_RECEIPT_MAX);
    require(p->text_len <= FLEET_BOARD_WIKI_TEXT_MAX);
    require(p->text[p->text_len] == '\0');
    require_zeroed(p->text + p->text_len + 1u,
                   sizeof(p->text) - p->text_len - 1u);
}

/* Accepted post bytes must be reproduced exactly, and the decoder must be
 * total: a refusal leaves a zeroed post. */
static bool board_decode_check(const uint8_t *w, size_t n)
{
    GUARDED(struct fleet_board_post) g;
    GUARD_ARM(g);
    enum fleet_board_result e = fleet_board_post_decode(w, n, &g.v);
    GUARD_CHECK(g);
    if (e != FLEET_BOARD_OK) {
        require_zeroed(&g.v, sizeof(g.v));
        return false;
    }
    board_check_post(&g.v);
    uint8_t *out = exact_alloc(n);
    size_t out_len = 0;
    require(fleet_board_post_encode(&g.v, out, n, &out_len) == FLEET_BOARD_OK);
    require(out_len == n && memcmp(w, out, n) == 0);
    free(out);
    return true;
}

static void board_fill_str(struct rd *r, char *dst, size_t cap, size_t min,
                           bool slug)
{
    static const char alpha[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    size_t len = min + rd8(r) % (cap - min + 1u);
    for (size_t i = 0; i < len; i++) {
        uint8_t b = rd8(r);
        dst[i] = slug ? alpha[b % (sizeof(alpha) - 1u)]
                      : (char)(0x20u + b % 95u);
    }
    dst[len] = '\0';
}

static void board_build(struct fleet_board_post *p, struct rd *r)
{
    memset(p, 0, sizeof(*p));
    p->kind = (uint8_t)(1u + rd8(r) % 8u);
    p->scope = rd8(r) % FLEET_BOARD_SCOPE__COUNT;
    p->created_at = 1u + rd64(r) % UINT64_C(4000000000);
    p->ttl = 1u + (uint32_t)(rd64(r) % FLEET_BOARD_TTL_MAX);
    rd_id(r, p->ref);
    if (p->scope == FLEET_BOARD_SCOPE_PUBLIC)
        board_fill_str(r, p->room, FLEET_BOARD_ROOM_MAX, 1, true);
    board_fill_str(r, p->agent, FLEET_BOARD_AGENT_MAX, 1, false);
    if (p->kind == FLEET_BOARD_KIND_WIKI) {
        board_fill_str(r, p->slug, FLEET_BOARD_SLUG_MAX, 1, true);
        board_fill_str(r, p->title, FLEET_BOARD_TITLE_MAX, 1, false);
        rd_id(r, p->supersedes);
    }
    if (p->kind == FLEET_BOARD_KIND_CLAIM || p->kind == FLEET_BOARD_KIND_RESULT)
        board_fill_str(r, p->receipt, FLEET_BOARD_RECEIPT_MAX, 1, false);
    uint32_t max = fleet_board_text_max(p->kind);
    p->text_len = max ? 1u + (uint32_t)(rd64(r) % max) : 0u;
    for (uint32_t i = 0; i < p->text_len; i++)
        p->text[i] = (char)(0x20u + rd8(r) % 95u);
}

static void board_signed(const uint8_t *w, size_t n)
{
    struct rd r = {w, n, 0};
    struct fleet_board_post p;
    board_build(&p, &r);
    if (fleet_board_post_sign(&p, g_seed, g_pk) != FLEET_BOARD_OK)
        return;
    size_t cap = FLEET_BOARD_BODY_MAX + 512u;
    uint8_t *wire = exact_alloc(cap);
    size_t wire_len = 0;
    if (fleet_board_post_encode(&p, wire, cap, &wire_len) != FLEET_BOARD_OK) {
        free(wire);
        return;
    }
    require(board_decode_check(wire, wire_len));
    size_t frame_cap = wire_len + 8u;
    uint8_t *frame = exact_alloc(frame_cap);
    size_t frame_len = 0;
    require(fleet_board_frame_encode_post(&p, frame, frame_cap, &frame_len) ==
            FLEET_BOARD_OK);
    struct fleet_board_post back;
    require(fleet_board_frame_decode_post(frame, frame_len, &back) ==
            FLEET_BOARD_OK);
    board_check_post(&back);
    free(frame);
    size_t pos = rd16(&r) % wire_len;
    wire[pos] ^= (uint8_t)(1u << (rd8(&r) % 8u));
    (void)board_decode_check(wire, wire_len);
    free(wire);
}

static void fuzz_board_post(const uint8_t *w, size_t n)
{
    if (n && (w[0] & 1u))
        (void)board_decode_check(w + 1, n - 1);
    else
        board_signed(w, n);
}

static void fuzz_board_frame(const uint8_t *w, size_t n)
{
    struct fleet_board_post post;
    if (fleet_board_frame_decode_post(w, n, &post) != FLEET_BOARD_OK)
        require_zeroed(&post, sizeof(post));
    (void)fleet_board_frame_type(w, n);
    (void)fleet_board_frame_is_board(w, n);
    size_t ids_cap = n ? w[0] % (FLEET_BOARD_FRAME_IDS_MAX + 2u) : 0u;
    uint8_t (*ids)[32] = ids_cap ? (uint8_t (*)[32])exact_alloc(ids_cap * 32u)
                                 : NULL;
    uint8_t type = 0;
    size_t count = 0;
    enum fleet_board_result e = fleet_board_frame_decode_ids(
        w, n, &type, ids, ids_cap, &count);
    if (e == FLEET_BOARD_OK) {
        require(count <= ids_cap && count <= FLEET_BOARD_FRAME_IDS_MAX);
        require(type == FLEET_BOARD_FRAME_INV || type == FLEET_BOARD_FRAME_GET);
        if (ids || count == 0) {
            uint8_t *out = exact_alloc(n);
            size_t out_len = 0;
            require(fleet_board_frame_encode_ids(type, (const uint8_t (*)[32])ids,
                                                 count, out, n, &out_len) ==
                    FLEET_BOARD_OK);
            require(out_len == n && memcmp(out, w, n) == 0);
            free(out);
        }
    } else {
        require(count == 0);
    }
    free(ids);
}

/* ── agent_broker_proto ──────────────────────────────────────────────── */

static void mvap_require_same_request(const struct mvap_request *a,
                                      const struct mvap_request *b)
{
    require(a->verb == b->verb && a->request_id == b->request_id);
    require(a->value_zats == b->value_zats && a->kind == b->kind);
    require(a->version == b->version);
    require(memcmp(a->property_id, b->property_id, sizeof(a->property_id)) == 0);
    require(strcmp(a->param, b->param) == 0);
}

/* On a refusal `out` is untouched (the header: fills `out` only when every
 * check passes). A decoded param is a C string that stops at its first NUL,
 * so a record carrying bytes after a NUL is accepted and re-encodes
 * shorter; hold it to idempotence there and to the exact bytes otherwise. */
static void fuzz_mvap_request(const uint8_t *w, size_t n)
{
    GUARDED(struct mvap_request) g;
    GUARD_ARM(g);
    struct mvap_request before;
    memcpy(&before, &g.v, sizeof(before));
    bool ok = mvap_request_decode(w, n, &g.v);
    GUARD_CHECK(g);
    if (!ok) {
        require(memcmp(&before, &g.v, sizeof(before)) == 0);
        return;
    }
    require(g.v.verb > MVAP_VERB_NONE && g.v.verb < MVAP_VERB__COUNT);
    require(g.v.kind < MVAP_KIND__COUNT);
    require(strnlen(g.v.param, sizeof(g.v.param)) <= MVAP_PARAM_MAX);
    require(mvap_param_is_safe(g.v.param));
    uint8_t buf[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
    size_t m = mvap_request_encode(&g.v, buf, sizeof(buf));
    require(m > MVAP_FRAME_PREFIX);
    require(mvap_frame_length(buf, m) == m - MVAP_FRAME_PREFIX);
    struct mvap_request again;
    require(mvap_request_decode(buf + MVAP_FRAME_PREFIX, m - MVAP_FRAME_PREFIX,
                                &again));
    mvap_require_same_request(&g.v, &again);
    if (n == MVAP_REQ_FIXED + strlen(g.v.param))
        require(m - MVAP_FRAME_PREFIX == n &&
                memcmp(buf + MVAP_FRAME_PREFIX, w, n) == 0);
}

static void fuzz_mvap_response(const uint8_t *w, size_t n)
{
    GUARDED(struct mvap_response) g;
    GUARD_ARM(g);
    struct mvap_response before;
    memcpy(&before, &g.v, sizeof(before));
    bool ok = mvap_response_decode(w, n, &g.v);
    GUARD_CHECK(g);
    if (!ok) {
        require(memcmp(&before, &g.v, sizeof(before)) == 0);
        return;
    }
    require(strnlen(g.v.body, sizeof(g.v.body)) <= MVAP_BODY_MAX);
    uint8_t buf[MVAP_FRAME_PREFIX + MVAP_MAX_FRAME];
    size_t m = mvap_response_encode(&g.v, buf, sizeof(buf));
    require(m > MVAP_FRAME_PREFIX);
    require(mvap_frame_length(buf, m) == m - MVAP_FRAME_PREFIX);
    struct mvap_response again;
    require(mvap_response_decode(buf + MVAP_FRAME_PREFIX,
                                 m - MVAP_FRAME_PREFIX, &again));
    require(again.verb == g.v.verb && again.status == g.v.status);
    require(again.request_id == g.v.request_id && again.version == g.v.version);
    require(strcmp(again.body, g.v.body) == 0);
    if (n == MVAP_RESP_FIXED + strlen(g.v.body))
        require(m - MVAP_FRAME_PREFIX == n &&
                memcmp(buf + MVAP_FRAME_PREFIX, w, n) == 0);
}

static void fuzz_mvap_prefix(const uint8_t *w, size_t n)
{
    uint32_t len = mvap_frame_length(w, n);
    require(len <= MVAP_MAX_FRAME);
    if (n < MVAP_FRAME_PREFIX)
        require(len == 0);
}

/* ── mesh_stream ─────────────────────────────────────────────────────── */

/* The stream handlers are static; they are reached through the one public
 * ingress, mesh_stream_frame, against a hand-built established session and a
 * registered service. Nothing is sent: the composition context the sends go
 * through is never wired, so every send refuses before the wire. The table
 * and OPEN cadence are cleared each run through the existing test seam. */

struct fz_stream_ctx {
    uint64_t data_bytes;
    uint64_t releases;
};

static struct fz_stream_ctx g_stream_ctx;
static struct p2p_node *g_node;
static struct msg_processor *g_mp;
static bool g_stream_ready;

#define STREAM_PEER_BYTE 0x11u
#define STREAM_TRANSCRIPT_BYTE 0x22u
#define STREAM_GENERATION 7u

static void touch(const uint8_t *p, size_t len)
{
    volatile uint8_t sink = 0;
    for (size_t i = 0; i < len; i++)
        sink ^= p[i];
    (void)sink;
}

static enum mesh_stream_refusal fz_on_open(
    struct mesh_stream *st, const uint8_t *payload, size_t len,
    uint8_t *reply, size_t reply_cap, size_t *reply_len, void *ctx)
{
    (void)ctx;
    require(st->used && len <= MESH_STREAM_PAYLOAD_MAX);
    require(reply_cap == MESH_STREAM_SERVICE_REPLY_MAX);
    touch(payload, len);
    *reply_len = 0;
    if (len && (payload[0] & 1u))
        return MESH_STREAM_REFUSED_UNAVAILABLE;
    if (len > 1 && (payload[0] & 2u)) {
        *reply_len = len < 64 ? len : 64;
        memcpy(reply, payload, *reply_len);
    }
    if (len && (payload[0] & 4u))
        *reply_len = reply_cap + 1u; /* the primitive must drop it */
    return MESH_STREAM_OK;
}

static void fz_on_data(struct mesh_stream *st, const uint8_t *payload,
                       size_t len, void *ctx)
{
    struct fz_stream_ctx *c = ctx;
    require(st->used && !st->ended && len <= MESH_STREAM_PAYLOAD_MAX);
    require(len <= MESH_STREAM_INITIAL_WINDOW);
    touch(payload, len);
    c->data_bytes += len;
}

static void fz_on_close(struct mesh_stream *st, enum mesh_stream_refusal why,
                        const uint8_t *payload, size_t len, void *ctx)
{
    (void)ctx;
    require(st->used && st->ended && len <= MESH_STREAM_PAYLOAD_MAX);
    require(why <= MESH_STREAM_CLOSED_BY_SERVICE);
    touch(payload, len);
}

static void fz_on_release(struct mesh_stream *st, void *ctx)
{
    struct fz_stream_ctx *c = ctx;
    (void)st;
    c->releases++;
}

static void stream_setup(void)
{
    if (g_stream_ready)
        return;
    struct noise_transport *t = calloc(1, sizeof(*t));
    require(t != NULL);
    zcl_mutex_init(&t->lock);
    t->state = NOISE_ESTABLISHED;
    memset(t->peer_static, STREAM_PEER_BYTE, sizeof(t->peer_static));
    memset(t->transcript_hash, STREAM_TRANSCRIPT_BYTE,
           sizeof(t->transcript_hash));
    t->have_peer_static = true;
    t->have_transcript_hash = true;
    t->connection_generation = STREAM_GENERATION;
    t->connection_serial = 1;
    g_node = calloc(1, sizeof(*g_node));
    g_mp = calloc(1, sizeof(*g_mp));
    require(g_node != NULL && g_mp != NULL);
    zcl_mutex_init(&g_node->cs_recv);
    g_node->transport = t;
    g_node->inbound = false;
    struct mesh_stream_service svc = {
        .name = "fz", .required_pairing_capability = 0,
        .on_open = fz_on_open, .on_data = fz_on_data,
        .on_close = fz_on_close, .on_release = fz_on_release,
        .ctx = &g_stream_ctx,
    };
    require(mesh_stream_service_register(&svc));
    g_stream_ready = true;
}

static bool stream_visit_check(struct mesh_stream *st, void *ctx)
{
    (void)ctx;
    require(st->send_credit <= MESH_STREAM_INITIAL_WINDOW);
    require(st->recv_credit <= MESH_STREAM_INITIAL_WINDOW);
    require(st->bytes_received <= MESH_STREAM_INITIAL_WINDOW);
    if (st->ended)
        require(st->send_credit == 0 && st->recv_credit == 0);
    return true;
}

static void stream_feed_one(struct rd *r)
{
    uint8_t kind = rd8(r);
    uint8_t idsel = rd8(r);
    size_t room = r->n - r->i;
    size_t body = rd16(r) % (room + 1u);
    bool large = (idsel & 0x80u) != 0;
    if (large)
        body = MESH_STREAM_PAYLOAD_MAX + rd8(r) % 5u;
    size_t head = MESH_STREAM_FRAME_PREFIX_LEN + 1u + 8u;
    bool raw = kind == 0xFFu;
    size_t total = raw ? body : head + body;
    uint8_t *frame = exact_alloc(total);
    uint8_t *dst = frame;
    if (!raw) {
        memcpy(frame, MESH_STREAM_FRAME_PREFIX, MESH_STREAM_FRAME_PREFIX_LEN);
        frame[MESH_STREAM_FRAME_PREFIX_LEN] = kind;
        zcl_write_u64_le(frame + MESH_STREAM_FRAME_PREFIX_LEN + 1u,
                         idsel & 0x07u);
        dst = frame + head;
    }
    memset(dst, 0, body);
    for (size_t i = 0; i < body && r->i < r->n; i++)
        dst[i] = rd8(r);
    if (large && !raw && body >= 3u) {
        if (kind == MESH_STREAM_KIND_DATA)
            zcl_write_u16_le(dst, (uint16_t)(body - 2u));
        else if (kind == MESH_STREAM_KIND_CLOSE)
            zcl_write_u16_le(dst + 1, (uint16_t)(body - 3u));
    }
    (void)mesh_stream_frame(g_mp, g_node, frame, total, NULL);
    free(frame);
}

static void fuzz_stream(const uint8_t *w, size_t n)
{
    stream_setup();
    struct rd r = {w, n, 0};
    mesh_stream_test_reset();
    uint8_t peer[32], transcript[32];
    memset(peer, STREAM_PEER_BYTE, sizeof(peer));
    memset(transcript, STREAM_TRANSCRIPT_BYTE, sizeof(transcript));
    for (uint64_t id = 1; id <= 2; id++) {
        uint32_t window = rd8(&r) ? 1u + rd16(&r) % 4096u
                                  : MESH_STREAM_INITIAL_WINDOW;
        (void)mesh_stream_test_inject("fz", peer, transcript,
                                      STREAM_GENERATION, id == 2, id, window,
                                      NULL);
    }
    for (unsigned frames = 0; frames < 16 && r.i < r.n; frames++)
        stream_feed_one(&r);
    mesh_stream_visit("fz", stream_visit_check, NULL);
    mesh_stream_test_reset();
}

/* ── noise record layer ──────────────────────────────────────────────── */

static const uint8_t g_key_a[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
                                    14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                                    24, 25, 26, 27, 28, 29, 30, 31, 32};
static const uint8_t g_key_b[32] = {33, 34, 35, 36, 37, 38, 39, 40, 41, 42,
                                    43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
                                    53, 54, 55, 56, 57, 58, 59, 60, 61, 62,
                                    63, 64};

static void session_raw(const uint8_t *w, size_t n)
{
    struct session_transport rx;
    session_transport_init(&rx, g_key_b, g_key_a);
    uint8_t *out = exact_alloc(SESSION_MAX_PAYLOAD);
    size_t out_len = 0;
    enum session_channel ch = SESSION_CH_DATA;
    if (session_transport_decrypt(&rx, &ch, w, n, out, &out_len))
        require(out_len <= SESSION_MAX_PAYLOAD && (unsigned)ch <= 3u);
    free(out);
}

static void session_round(const uint8_t *w, size_t n, bool tamper)
{
    struct rd r = {w, n, 0};
    struct session_transport tx, rx;
    session_transport_init(&tx, g_key_a, g_key_b);
    session_transport_init(&rx, g_key_b, g_key_a);
    size_t len = rd16(&r) % (SESSION_FRAME_MAX_PLAINTEXT + 64u);
    enum session_channel ch = (enum session_channel)(rd8(&r) % 4u);
    uint8_t *plain = exact_alloc(len);
    rd_bytes(&r, plain, len);
    uint8_t *wire = exact_alloc(SESSION_FRAME_MAX_WIRE);
    size_t wire_len = 0;
    bool sealed = session_transport_encrypt(&tx, ch, plain, len, wire, &wire_len);
    require(sealed == (len <= SESSION_MAX_PAYLOAD));
    if (sealed) {
        require(wire_len == SESSION_FRAME_LEN_BYTES + 1u + len + SESSION_TAG_LEN);
        require(wire_len <= SESSION_FRAME_MAX_WIRE);
        if (tamper)
            wire[rd16(&r) % wire_len] ^= (uint8_t)(1u << (rd8(&r) % 8u));
        uint8_t *back = exact_alloc(SESSION_MAX_PAYLOAD);
        size_t back_len = 0;
        enum session_channel got = SESSION_CH_DATA;
        bool opened = session_transport_decrypt(&rx, &got, wire, wire_len, back,
                                                &back_len);
        require(opened == !tamper);
        if (opened)
            require(got == ch && back_len == len &&
                    memcmp(back, plain, len) == 0);
        free(back);
    }
    free(wire);
    free(plain);
}

/* An established pair, built once with a real handshake, then copied for
 * each run (the keys and counters are plain data). */
static struct noise_transport *g_ini;
static struct noise_transport *g_resp;

static void noise_free_out(uint8_t *a, uint8_t *b)
{
    free(a);
    free(b);
}

static void noise_feed_pair(struct noise_transport *t, const uint8_t *in,
                            size_t len, uint8_t **next, size_t *next_len)
{
    uint8_t *wire = NULL, *plain = NULL;
    size_t wire_len = 0, plain_len = 0;
    *next = NULL;
    *next_len = 0;
    require(noise_transport_feed(t, in, len, &wire, &wire_len, &plain,
                                 &plain_len));
    *next = wire;
    *next_len = wire_len;
    free(plain);
}

static void noise_setup(void)
{
    if (g_ini)
        return;
    uint8_t priv_a[32], priv_b[32];
    memset(priv_a, 0x31, sizeof(priv_a));
    memset(priv_b, 0x62, sizeof(priv_b));
    const unsigned char magic[4] = {0xd9, 0xb4, 0xbe, 0xf9};
    uint8_t *msg = NULL, *unused = NULL;
    size_t msg_len = 0, unused_len = 0;
    g_ini = noise_transport_begin(true, priv_a, magic, &msg, &msg_len);
    g_resp = noise_transport_begin(false, priv_b, magic, &unused, &unused_len);
    require(g_ini != NULL && g_resp != NULL);
    free(unused);
    bool to_resp = true;
    for (int round = 0; round < 8; round++) {
        struct noise_transport *t = to_resp ? g_resp : g_ini;
        uint8_t *next = NULL;
        size_t next_len = 0;
        noise_feed_pair(t, msg, msg_len, &next, &next_len);
        free(msg);
        msg = next;
        msg_len = next_len;
        to_resp = !to_resp;
        if (g_ini->state == NOISE_ESTABLISHED &&
            g_resp->state == NOISE_ESTABLISHED && msg_len == 0)
            break;
    }
    free(msg);
    require(g_ini->state == NOISE_ESTABLISHED &&
            g_resp->state == NOISE_ESTABLISHED);
    require(g_ini->pending == NULL && g_resp->pending == NULL);
}

static struct noise_transport *noise_clone(const struct noise_transport *src)
{
    struct noise_transport *t = malloc(sizeof(*t));
    require(t != NULL);
    memcpy(t, src, sizeof(*t));
    zcl_mutex_init(&t->lock);
    return t;
}

static void noise_drop(struct noise_transport *t)
{
    zcl_mutex_destroy(&t->lock);
    free(t);
}

/* Feed `in` to `t` in chunks of fuzzer-chosen size; the plaintext handed
 * back is appended to `plain`. Returns false once the transport refuses. */
static bool noise_feed_chunks(struct noise_transport *t, struct rd *r,
                              const uint8_t *in, size_t len, uint8_t *plain,
                              size_t plain_cap, size_t *plain_len)
{
    size_t at = 0;
    while (at < len) {
        size_t chunk = 1u + rd16(r) % 2048u;
        if (chunk > len - at)
            chunk = len - at;
        uint8_t *wire = NULL, *out = NULL;
        size_t wire_len = 0, out_len = 0;
        if (!noise_transport_feed(t, in + at, chunk, &wire, &wire_len, &out,
                                  &out_len))
            return false;
        require(wire_len == 0);
        require(*plain_len + out_len <= plain_cap);
        if (out_len)
            memcpy(plain + *plain_len, out, out_len);
        *plain_len += out_len;
        noise_free_out(wire, out);
        at += chunk;
    }
    return true;
}

static void noise_raw(const uint8_t *w, size_t n)
{
    struct rd r = {w, n, 0};
    struct noise_transport *t = noise_clone(g_resp);
    uint8_t *plain = exact_alloc(n + 1u);
    size_t plain_len = 0;
    (void)noise_feed_chunks(t, &r, w + r.i, n - r.i, plain, n + 1u, &plain_len);
    free(plain);
    noise_drop(t);
}

static void noise_round(const uint8_t *w, size_t n, bool tamper)
{
    struct rd r = {w, n, 0};
    size_t len = 1u + rd16(&r) % 4000u;
    uint8_t *msg = exact_alloc(len);
    rd_bytes(&r, msg, len);
    struct noise_transport *ini = noise_clone(g_ini);
    struct noise_transport *resp = noise_clone(g_resp);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    require(noise_transport_write(ini, msg, len, &wire, &wire_len));
    size_t records = (len + SESSION_MAX_PAYLOAD - 1u) / SESSION_MAX_PAYLOAD;
    require(wire != NULL && wire_len ==
            len + records * (SESSION_FRAME_LEN_BYTES + 1u + SESSION_TAG_LEN));
    if (tamper)
        wire[rd16(&r) % wire_len] ^= (uint8_t)(1u << (rd8(&r) % 8u));
    uint8_t *plain = exact_alloc(len);
    size_t plain_len = 0;
    bool ok = noise_feed_chunks(resp, &r, wire, wire_len, plain, len,
                                &plain_len);
    if (!tamper)
        require(ok && plain_len == len && memcmp(plain, msg, len) == 0);
    else if (ok)
        require(plain_len < len);
    free(plain);
    free(wire);
    free(msg);
    noise_drop(ini);
    noise_drop(resp);
}

static void fuzz_noise(const uint8_t *w, size_t n)
{
    noise_setup();
    unsigned sel = n ? w[0] % 6u : 0u;
    const uint8_t *rest = n ? w + 1 : w;
    size_t rn = n ? n - 1u : 0u;
    switch (sel) {
    case 0: session_raw(rest, rn); break;
    case 1: session_round(rest, rn, false); break;
    case 2: session_round(rest, rn, true); break;
    case 3: noise_raw(rest, rn); break;
    case 4: noise_round(rest, rn, false); break;
    default: noise_round(rest, rn, true); break;
    }
}

/* ── dispatch ────────────────────────────────────────────────────────── */

typedef void (*fuzz_arm_fn)(const uint8_t *wire, size_t len);


static const fuzz_arm_fn k_arms[] = {
    term_open,          term_receipt,      term_data,
    term_resize,        term_close,        fuzz_capability,
    fuzz_pof,           fuzz_stream,       fuzz_game,
    fuzz_board_post,    fuzz_board_frame,  fuzz_mvap_request,
    fuzz_mvap_response, fuzz_mvap_prefix,  fuzz_noise,
};

/* The first byte picks the decoder; the rest is its input. */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size == 0 || size > FUZZ_MESH_MAX_INPUT)
        return 0;
    keys_init();
    k_arms[data[0] % (sizeof(k_arms) / sizeof(k_arms[0]))](data + 1, size - 1);
    return 0;
}
