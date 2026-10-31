/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Clips record envelope: encode, strict decode, record id, Ed25519 sign and verify, chain, fork and time checks. */

#include "clips_internal.h"

#include "base/cleanse.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"

#include <string.h>

static const uint8_t k_record_magic[4] = { 0x5a, 0x43, 0x4c, 0x52 };
static const char k_record_id_domain[] = "z23.clips.record.id.v1";
static const uint8_t k_record_version = 1;
static const uint8_t k_record_alg_ed25519 = 1;

static bool clips_kind_lane(uint8_t kind, uint8_t *lane)
{
    switch (kind) {
    case CLIPS_KIND_POST:
    case CLIPS_KIND_PROFILE:
    case CLIPS_KIND_TOMBSTONE:
    case CLIPS_KIND_LIST:
        *lane = CLIPS_LANE_CONTENT;
        return true;
    case CLIPS_KIND_RATING:
        *lane = CLIPS_LANE_RATING;
        return true;
    case CLIPS_KIND_REACTION:
    case CLIPS_KIND_COMMENT:
    case CLIPS_KIND_FOLLOW:
    case CLIPS_KIND_BLOCK:
    case CLIPS_KIND_REPORT:
        *lane = CLIPS_LANE_SOCIAL;
        return true;
    default:
        return false;
    }
}

static enum clips_error clips_record_check_kind(const struct clips_record *rec)
{
    uint8_t lane = 0;

    if (!clips_kind_lane(rec->kind, &lane))
        return CLIPS_ERR_KIND;
    return rec->lane == lane ? CLIPS_OK : CLIPS_ERR_LANE;
}

static enum clips_error clips_record_read_front(struct zcl_codec_reader *r,
                                                struct clips_record *out)
{
    uint8_t magic[4];
    uint8_t version = 0;
    uint8_t alg = 0;

    if (!zcl_codec_read_bytes(r, magic, sizeof(magic)))
        return CLIPS_ERR_TRUNCATED;
    if (memcmp(magic, k_record_magic, sizeof(magic)) != 0)
        return CLIPS_ERR_MAGIC;
    if (!zcl_codec_read_u8(r, &version))
        return CLIPS_ERR_TRUNCATED;
    if (version != k_record_version)
        return CLIPS_ERR_VERSION;
    if (!zcl_codec_read_u8(r, &out->kind) || !zcl_codec_read_u8(r, &out->lane) ||
        !zcl_codec_read_u8(r, &alg))
        return CLIPS_ERR_TRUNCATED;
    if (alg != k_record_alg_ed25519)
        return CLIPS_ERR_ALG;
    return clips_record_check_kind(out);
}

static enum clips_error clips_record_read_tail(struct zcl_codec_reader *r,
                                               struct clips_record *out)
{
    if (!zcl_codec_read_bytes(r, out->author, sizeof(out->author)) ||
        !zcl_codec_read_u64le(r, &out->seq) ||
        !zcl_codec_read_bytes(r, out->prev, sizeof(out->prev)) ||
        !zcl_codec_read_i64le(r, &out->created_at) ||
        !zcl_codec_read_u64le(r, &out->stamp) ||
        !zcl_codec_read_u16le(r, &out->body_len))
        return CLIPS_ERR_TRUNCATED;
    return CLIPS_OK;
}

enum clips_error clips_record_decode(const uint8_t *in, size_t len,
                                     struct clips_record *out)
{
    struct zcl_codec_reader r;
    enum clips_error e;
    size_t need = 0;

    if (!in || !out)
        return CLIPS_ERR_ARGUMENT;
    if (len < CLIPS_RECORD_HEADER_LEN)
        return CLIPS_ERR_TRUNCATED;
    zcl_codec_reader_init(&r, in, len);
    e = clips_record_read_front(&r, out);
    if (e != CLIPS_OK)
        return e;
    e = clips_record_read_tail(&r, out);
    if (e != CLIPS_OK)
        return e;
    if (out->body_len > CLIPS_RECORD_BODY_MAX)
        return CLIPS_ERR_BODY_LEN;
    need = (size_t)CLIPS_RECORD_HEADER_LEN + out->body_len + CLIPS_RECORD_SIG_LEN;
    if (len < need)
        return CLIPS_ERR_TRUNCATED;
    if (len > need)
        return CLIPS_ERR_TRAILING;
    if (!zcl_codec_read_bytes(&r, out->body, out->body_len) ||
        !zcl_codec_read_bytes(&r, out->signature, sizeof(out->signature)))
        return CLIPS_ERR_TRUNCATED;
    return CLIPS_OK;
}

static bool clips_record_write_front(struct zcl_codec_writer *w,
                                     const struct clips_record *rec)
{
    return zcl_codec_write_bytes(w, k_record_magic, sizeof(k_record_magic)) &&
           zcl_codec_write_u8(w, k_record_version) &&
           zcl_codec_write_u8(w, rec->kind) && zcl_codec_write_u8(w, rec->lane) &&
           zcl_codec_write_u8(w, k_record_alg_ed25519) &&
           zcl_codec_write_bytes(w, rec->author, sizeof(rec->author)) &&
           zcl_codec_write_u64le(w, rec->seq) &&
           zcl_codec_write_bytes(w, rec->prev, sizeof(rec->prev));
}

static bool clips_record_write_tail(struct zcl_codec_writer *w,
                                    const struct clips_record *rec)
{
    return zcl_codec_write_i64le(w, rec->created_at) &&
           zcl_codec_write_u64le(w, rec->stamp) &&
           zcl_codec_write_u16le(w, rec->body_len) &&
           zcl_codec_write_bytes(w, rec->body, rec->body_len) &&
           zcl_codec_write_bytes(w, rec->signature, sizeof(rec->signature));
}

enum clips_error clips_record_encode(const struct clips_record *rec, uint8_t *out,
                                     size_t cap, size_t *written)
{
    struct zcl_codec_writer w;
    enum clips_error e;
    size_t need = 0;

    if (!rec || !out || !written)
        return CLIPS_ERR_ARGUMENT;
    e = clips_record_check_kind(rec);
    if (e != CLIPS_OK)
        return e;
    if (rec->body_len > CLIPS_RECORD_BODY_MAX)
        return CLIPS_ERR_BODY_LEN;
    need = (size_t)CLIPS_RECORD_HEADER_LEN + rec->body_len + CLIPS_RECORD_SIG_LEN;
    if (cap < need)
        return CLIPS_ERR_ARGUMENT;
    zcl_codec_writer_init(&w, out, cap);
    if (!clips_record_write_front(&w, rec) || !clips_record_write_tail(&w, rec))
        return CLIPS_ERR_ARGUMENT;
    if (!zcl_codec_writer_finish(&w, written))
        return CLIPS_ERR_ARGUMENT;
    return CLIPS_OK;
}

enum clips_error clips_record_id(const struct clips_record *rec, uint8_t id[CLIPS_HASH_LEN])
{
    uint8_t wire[CLIPS_RECORD_MAX_LEN];
    struct sha3_512_ctx ctx;
    const uint8_t sep = 0;
    size_t n = 0;
    enum clips_error e;

    if (!rec || !id)
        return CLIPS_ERR_ARGUMENT;
    e = clips_record_encode(rec, wire, sizeof(wire), &n);
    if (e != CLIPS_OK)
        return e;
    sha3_512_init(&ctx);
    sha3_512_write(&ctx, (const uint8_t *)k_record_id_domain, sizeof(k_record_id_domain) - 1);
    sha3_512_write(&ctx, &sep, 1);
    sha3_512_write(&ctx, wire, n - CLIPS_RECORD_SIG_LEN);
    sha3_512_finalize(&ctx, id);
    return CLIPS_OK;
}

enum clips_error clips_record_sign(struct clips_record *rec, const uint8_t seed[32])
{
    uint8_t pk[32];
    uint8_t sk[32];
    uint8_t id[CLIPS_HASH_LEN];
    enum clips_error e;

    if (!rec || !seed)
        return CLIPS_ERR_ARGUMENT;
    ed25519_keypair(pk, sk, seed);
    memory_cleanse(sk, sizeof(sk));
    if (memcmp(pk, rec->author, sizeof(pk)) != 0)
        return CLIPS_ERR_SIGNATURE;
    e = clips_record_id(rec, id);
    if (e != CLIPS_OK)
        return e;
    ed25519_sign(rec->signature, id, sizeof(id), seed, pk);
    return CLIPS_OK;
}

enum clips_error clips_record_verify(const struct clips_record *rec)
{
    uint8_t id[CLIPS_HASH_LEN];
    enum clips_error e;

    if (!rec)
        return CLIPS_ERR_ARGUMENT;
    e = clips_record_id(rec, id);
    if (e != CLIPS_OK)
        return e;
    if (!ed25519_verify(rec->signature, id, sizeof(id), rec->author))
        return CLIPS_ERR_SIGNATURE;
    return CLIPS_OK;
}

enum clips_error clips_record_check_body(const struct clips_record *rec)
{
    struct clips_body body;

    if (!rec)
        return CLIPS_ERR_ARGUMENT;
    return clips_body_decode(rec->kind, rec->body, rec->body_len, &body);
}

enum clips_error clips_record_time_check(const struct clips_record *rec, int64_t now)
{
    int64_t limit = 0;

    if (!rec)
        return CLIPS_ERR_ARGUMENT;
    limit = now > INT64_MAX - CLIPS_RECORD_MAX_FUTURE_SECS
                ? INT64_MAX
                : now + CLIPS_RECORD_MAX_FUTURE_SECS;
    return rec->created_at > limit ? CLIPS_ERR_TIME : CLIPS_OK;
}

enum clips_error clips_record_fork_check(const struct clips_record *a,
                                         const struct clips_record *b, bool *forked)
{
    uint8_t ia[CLIPS_HASH_LEN];
    uint8_t ib[CLIPS_HASH_LEN];
    enum clips_error e;

    if (!a || !b || !forked)
        return CLIPS_ERR_ARGUMENT;
    *forked = false;
    if (memcmp(a->author, b->author, sizeof(a->author)) != 0 || a->lane != b->lane ||
        a->seq != b->seq)
        return CLIPS_OK;
    e = clips_record_id(a, ia);
    if (e != CLIPS_OK)
        return e;
    e = clips_record_id(b, ib);
    if (e != CLIPS_OK)
        return e;
    *forked = memcmp(ia, ib, sizeof(ia)) != 0;
    return CLIPS_OK;
}

enum clips_error clips_chain_check(const struct clips_record *rec,
                                   const struct clips_chain_tip *tip)
{
    static const uint8_t zero[CLIPS_HASH_LEN];

    if (!rec)
        return CLIPS_ERR_ARGUMENT;
    if (!tip || !tip->present) {
        if (rec->seq != 1)
            return CLIPS_ERR_CHAIN_SEQ;
        return memcmp(rec->prev, zero, sizeof(zero)) == 0 ? CLIPS_OK : CLIPS_ERR_CHAIN_PREV;
    }
    if (memcmp(rec->author, tip->author, sizeof(tip->author)) != 0 || rec->lane != tip->lane)
        return CLIPS_ERR_ARGUMENT;
    if (tip->seq == UINT64_MAX || rec->seq != tip->seq + 1)
        return CLIPS_ERR_CHAIN_SEQ;
    return memcmp(rec->prev, tip->id, sizeof(tip->id)) == 0 ? CLIPS_OK : CLIPS_ERR_CHAIN_PREV;
}
