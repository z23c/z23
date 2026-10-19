/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZID hybrid release doc: encode/decode, sign and the both-signatures verify
 * (see zid/zid_hybrid.h and docs/work/PQ_HYBRID_RELEASE_SIGNATURE.md). */

#include "zid/zid_hybrid.h"
#include "base/log_macros.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "support/cleanse.h"
#include <assert.h>
#include <string.h>

/* The container layout, the v2 maximum and the SLH-DSA module sizes are one
 * fact; a drift in any of them must fail the build. */
static_assert(ZRS1_PQ_PK_SIZE == ZCL_SLHDSA_SHAKE_128S_PUBLIC_KEY_SIZE,
              "ZRS1 pk size follows the SHAKE-128s public key");
static_assert(ZRS1_PQ_SIG_SIZE == ZCL_SLHDSA_SHAKE_128S_SIGNATURE_SIZE,
              "ZRS1 sig size follows the SHAKE-128s signature");
static_assert(ZRS1_PQ_SEED_SIZE == ZCL_SLHDSA_SHAKE_128S_KEYGEN_SEED_SIZE,
              "ZRS1 seed size follows the SHAKE-128s keygen seed");
static_assert(ZRS1_CONTAINER_SIZE ==
                  4 + 1 + 64 + ZCL_SLHDSA_SHAKE_128S_PUBLIC_KEY_SIZE +
                      ZCL_SLHDSA_SHAKE_128S_SIGNATURE_SIZE,
              "container = magic + param + ed25519 sig + pk + slhdsa sig");
static_assert(ZID_DOC_V2_MAX == 9067 &&
                  ZID_DOC_V2_MAX == ZID_V2_PREFIX_FIXED + ZID_BODY_MAX +
                                        ZID_V2_PQ_BIND_LEN + 2 +
                                        ZRS1_CONTAINER_SIZE,
              "v2 maximum is computed exactly from the 128s container");
static_assert(ZID_DOC_V2_MAX > ZID_DOC_MAX, "v2 docs exceed the v1 maximum");
static_assert(ZRS1_CONTAINER_SIZE <= UINT16_MAX, "trailer_len is a u16");

#define HY_ED_SIG_OFF 5
#define HY_PK_OFF (HY_ED_SIG_OFF + 64)
#define HY_SIG_OFF (HY_PK_OFF + ZRS1_PQ_PK_SIZE)

const char *zid_hybrid_status_code(enum zid_hybrid_status st)
{
    switch (st) {
    case ZID_HYBRID_OK: return "OK";
    case ZID_HYBRID_ERR_ARGUMENT: return "BAD_ARGUMENT";
    case ZID_HYBRID_NOT_V2: return "NOT_V2_DOC";
    case ZID_HYBRID_DOC_MALFORMED: return "DOC_DECODE_FAILED";
    case ZID_HYBRID_PQ_CONTAINER_MALFORMED: return "PQ_CONTAINER_MALFORMED";
    case ZID_HYBRID_DOC_EXPIRED: return "DOC_EXPIRED";
    case ZID_HYBRID_BAD_SIGNATURE: return "BAD_SIGNATURE";
    case ZID_HYBRID_PQ_KEY_MISMATCH: return "PQ_KEY_MISMATCH";
    case ZID_HYBRID_BAD_PQ_SIGNATURE: return "BAD_PQ_SIGNATURE";
    case ZID_HYBRID_NOT_A_RELEASE_BODY: return "NOT_A_RELEASE_BODY";
    }
    return "UNKNOWN"; /* raw-return-ok: closed enum, unreachable */
}

/* Signed prefix: out[0 .. 51 + body_len + 33). Caller guarantees
 * body_len <= ZID_BODY_MAX and a large-enough buffer. */
static size_t hy_encode_prefix(uint8_t *out, const struct zid_doc_v2 *doc)
{
    size_t n = 0;
    out[n++] = ZID_DOC_VERSION_V2;
    memcpy(out + n, doc->master_pubkey, 32);
    n += 32;
    zcl_write_u64_le(out + n, doc->seq);
    n += 8;
    zcl_write_u64_le(out + n, doc->expiry);
    n += 8;
    out[n++] = (uint8_t)(doc->body_len & 0xff);
    out[n++] = (uint8_t)(doc->body_len >> 8);
    memcpy(out + n, doc->body, doc->body_len);
    n += doc->body_len;
    out[n++] = doc->pq_param;
    memcpy(out + n, doc->pq_pk_digest, 32);
    n += 32;
    return n;
}

size_t zid_hybrid_encode(uint8_t *out, size_t out_len,
                         const struct zid_doc_v2 *doc)
{
    if (!out || !doc)
        LOG_RETURN(0, "zid", "hybrid encode: NULL argument");
    if (doc->body_len > ZID_BODY_MAX)
        LOG_RETURN(0, "zid", "hybrid encode: body_len %u exceeds %d",
                   doc->body_len, ZID_BODY_MAX);
    if (doc->pq_param != ZRS1_PARAM_SHAKE_128S)
        LOG_RETURN(0, "zid", "hybrid encode: unsupported pq param %u",
                   doc->pq_param);
    size_t total = ZID_V2_PREFIX_FIXED + (size_t)doc->body_len +
                   ZID_V2_PQ_BIND_LEN + 2 + ZRS1_CONTAINER_SIZE;
    if (out_len < total)
        LOG_RETURN(0, "zid", "hybrid encode: out_len %zu too small (need %zu)",
                   out_len, total);
    size_t n = hy_encode_prefix(out, doc);
    out[n++] = (uint8_t)(ZRS1_CONTAINER_SIZE & 0xff);
    out[n++] = (uint8_t)(ZRS1_CONTAINER_SIZE >> 8);
    memcpy(out + n, ZRS1_MAGIC, 4);
    out[n + 4] = doc->pq_param;
    memcpy(out + n + HY_ED_SIG_OFF, doc->ed_signature, 64);
    memcpy(out + n + HY_PK_OFF, doc->pq_pk, ZRS1_PQ_PK_SIZE);
    memcpy(out + n + HY_SIG_OFF, doc->pq_signature, ZRS1_PQ_SIG_SIZE);
    return n + ZRS1_CONTAINER_SIZE;
}

/* Container lengths come from the param byte alone. 0 = unknown param. */
static size_t hy_container_size(uint8_t param)
{
    if (param != ZRS1_PARAM_SHAKE_128S)
        return 0; /* raw-return-ok: size lookup, 0 means unknown param */
    return 4 + 1 + 64 + zcl_slhdsa_public_key_size(ZCL_SLHDSA_SHAKE_128S) +
           zcl_slhdsa_signature_size(ZCL_SLHDSA_SHAKE_128S);
}

enum zid_hybrid_status zid_hybrid_decode(struct zid_doc_v2 *doc,
                                         const uint8_t *buf, size_t len)
{
    if (!doc || !buf)
        LOG_RETURN(ZID_HYBRID_ERR_ARGUMENT, "zid",
                   "hybrid decode: NULL argument");
    if (len < ZID_V2_PREFIX_FIXED)
        LOG_RETURN(ZID_HYBRID_DOC_MALFORMED, "zid",
                   "hybrid decode: len %zu below fixed prefix", len);
    if (buf[0] != ZID_DOC_VERSION_V2)
        LOG_RETURN(ZID_HYBRID_NOT_V2, "zid",
                   "hybrid decode: version %u is not %d", buf[0],
                   ZID_DOC_VERSION_V2);
    if (len > ZID_DOC_V2_MAX)
        LOG_RETURN(ZID_HYBRID_DOC_MALFORMED, "zid",
                   "hybrid decode: len %zu exceeds ZID_DOC_V2_MAX %d", len,
                   ZID_DOC_V2_MAX);
    size_t body_len = (size_t)buf[49] | ((size_t)buf[50] << 8);
    if (body_len > ZID_BODY_MAX)
        LOG_RETURN(ZID_HYBRID_DOC_MALFORMED, "zid",
                   "hybrid decode: body_len %zu exceeds %d", body_len,
                   ZID_BODY_MAX);
    size_t bind_off = ZID_V2_PREFIX_FIXED + body_len;
    if (len < bind_off + ZID_V2_PQ_BIND_LEN + 2)
        LOG_RETURN(ZID_HYBRID_DOC_MALFORMED, "zid",
                   "hybrid decode: len %zu too short for body_len %zu", len,
                   body_len);
    size_t trailer_len_off = bind_off + ZID_V2_PQ_BIND_LEN;
    size_t trailer_len = (size_t)buf[trailer_len_off] |
                         ((size_t)buf[trailer_len_off + 1] << 8);
    const uint8_t *trailer = buf + trailer_len_off + 2;
    size_t have = len - (trailer_len_off + 2);

    /* Container: magic and param first, then every length from the param. */
    if (have < 5 || memcmp(trailer, ZRS1_MAGIC, 4) != 0)
        LOG_RETURN(ZID_HYBRID_PQ_CONTAINER_MALFORMED, "zid",
                   "hybrid decode: bad ZRS1 magic or truncated header");
    uint8_t param = trailer[4];
    size_t want = hy_container_size(param);
    if (want == 0)
        LOG_RETURN(ZID_HYBRID_PQ_CONTAINER_MALFORMED, "zid",
                   "hybrid decode: unsupported ZRS1 param %u", param);
    if (buf[bind_off] != param)
        LOG_RETURN(ZID_HYBRID_PQ_CONTAINER_MALFORMED, "zid",
                   "hybrid decode: signed pq_param %u differs from container "
                   "param %u", buf[bind_off], param);
    if (trailer_len != want)
        LOG_RETURN(ZID_HYBRID_PQ_CONTAINER_MALFORMED, "zid",
                   "hybrid decode: trailer_len %zu != %zu for param %u",
                   trailer_len, want, param);
    if (have != want)
        LOG_RETURN(ZID_HYBRID_PQ_CONTAINER_MALFORMED, "zid",
                   "hybrid decode: %zu trailer bytes present, want exactly %zu",
                   have, want);

    memset(doc, 0, sizeof(*doc));
    memcpy(doc->master_pubkey, buf + 1, 32);
    doc->seq = zcl_read_u64_le(buf + 33);
    doc->expiry = zcl_read_u64_le(buf + 41);
    doc->body_len = (uint16_t)body_len;
    memcpy(doc->body, buf + ZID_V2_PREFIX_FIXED, body_len);
    doc->pq_param = param;
    memcpy(doc->pq_pk_digest, buf + bind_off + 1, 32);
    memcpy(doc->ed_signature, trailer + HY_ED_SIG_OFF, 64);
    memcpy(doc->pq_pk, trailer + HY_PK_OFF, ZRS1_PQ_PK_SIZE);
    memcpy(doc->pq_signature, trailer + HY_SIG_OFF, ZRS1_PQ_SIG_SIZE);
    return ZID_HYBRID_OK;
}

enum zid_hybrid_status zid_hybrid_verify(const struct zid_doc_v2 *doc,
                                         const uint8_t *pinned_pq_pk,
                                         uint64_t now_unix)
{
    if (!doc)
        LOG_RETURN(ZID_HYBRID_ERR_ARGUMENT, "zid", "hybrid verify: NULL doc");
    if (doc->body_len > ZID_BODY_MAX || doc->pq_param != ZRS1_PARAM_SHAKE_128S)
        LOG_RETURN(ZID_HYBRID_PQ_CONTAINER_MALFORMED, "zid",
                   "hybrid verify: body_len %u or pq param %u out of range",
                   doc->body_len, doc->pq_param);
    if (now_unix >= doc->expiry)
        return ZID_HYBRID_DOC_EXPIRED; /* raw-return-ok: expiry is a verdict, callers name it */

    uint8_t prefix[ZID_V2_PREFIX_FIXED + ZID_BODY_MAX + ZID_V2_PQ_BIND_LEN];
    size_t prefix_len = hy_encode_prefix(prefix, doc);
    if (!ed25519_verify(doc->ed_signature, prefix, prefix_len,
                        doc->master_pubkey))
        LOG_RETURN(ZID_HYBRID_BAD_SIGNATURE, "zid",
                   "hybrid verify: ed25519 signature check failed");

    uint8_t digest[32];
    sha3_256(doc->pq_pk, ZRS1_PQ_PK_SIZE, digest);
    if (memcmp(digest, doc->pq_pk_digest, 32) != 0)
        LOG_RETURN(ZID_HYBRID_PQ_KEY_MISMATCH, "zid",
                   "hybrid verify: container pk does not match the signed "
                   "pk digest");

    enum zcl_slhdsa_status st = zcl_slhdsa_verify(
        ZCL_SLHDSA_SHAKE_128S, doc->pq_pk, ZRS1_PQ_PK_SIZE, prefix, prefix_len,
        (const uint8_t *)ZRS1_CONTEXT, sizeof(ZRS1_CONTEXT) - 1,
        doc->pq_signature, ZRS1_PQ_SIG_SIZE);
    if (st != ZCL_SLHDSA_OK)
        LOG_RETURN(ZID_HYBRID_BAD_PQ_SIGNATURE, "zid",
                   "hybrid verify: slh-dsa signature check failed (%d)",
                   (int)st);

    if (pinned_pq_pk && memcmp(pinned_pq_pk, doc->pq_pk, ZRS1_PQ_PK_SIZE) != 0)
        LOG_RETURN(ZID_HYBRID_PQ_KEY_MISMATCH, "zid",
                   "hybrid verify: container pk differs from the pinned key");
    return ZID_HYBRID_OK;
}

enum zid_hybrid_status zid_hybrid_release_verify(
    const struct zid_doc_v2 *doc, const uint8_t *pinned_pq_pk,
    struct zid_release *rel_out, uint64_t now_unix)
{
    enum zid_hybrid_status st = zid_hybrid_verify(doc, pinned_pq_pk, now_unix);
    if (st != ZID_HYBRID_OK)
        return st; /* raw-return-ok: verify already logged the named refusal */
    struct zid_release rel;
    if (!zid_release_decode_body(&rel, doc->body, doc->body_len))
        LOG_RETURN(ZID_HYBRID_NOT_A_RELEASE_BODY, "zid",
                   "hybrid release_verify: body is not a release record");
    if (rel_out)
        *rel_out = rel;
    return ZID_HYBRID_OK;
}

/* ── signing ─────────────────────────────────────────────────────── */

/* keygen draws its 3n seed bytes through a callback; hand it the caller's
 * seed exactly once. */
struct hy_seed_source {
    const uint8_t *seed;
    size_t used;
};

static bool hy_seed_draw(void *context, uint8_t *out, size_t len)
{
    struct hy_seed_source *src = context;
    if (len > ZRS1_PQ_SEED_SIZE - src->used)
        return false;
    memcpy(out, src->seed + src->used, len);
    src->used += len;
    return true;
}

static enum zcl_slhdsa_status hy_pq_keygen(
    uint8_t pk[ZRS1_PQ_PK_SIZE],
    uint8_t sk[ZCL_SLHDSA_SHAKE_128S_SECRET_KEY_SIZE],
    const uint8_t pq_seed[ZRS1_PQ_SEED_SIZE])
{
    struct hy_seed_source src = {.seed = pq_seed, .used = 0};
    return zcl_slhdsa_keygen(ZCL_SLHDSA_SHAKE_128S, hy_seed_draw, &src, pk,
                             ZRS1_PQ_PK_SIZE, sk,
                             ZCL_SLHDSA_SHAKE_128S_SECRET_KEY_SIZE);
}

bool zid_hybrid_pq_pubkey(uint8_t pk[ZRS1_PQ_PK_SIZE],
                          const uint8_t pq_seed[ZRS1_PQ_SEED_SIZE])
{
    if (!pk || !pq_seed)
        LOG_FAIL("zid", "hybrid pq_pubkey: NULL argument");
    uint8_t sk[ZCL_SLHDSA_SHAKE_128S_SECRET_KEY_SIZE];
    enum zcl_slhdsa_status st = hy_pq_keygen(pk, sk, pq_seed);
    memory_cleanse(sk, sizeof(sk));
    if (st != ZCL_SLHDSA_OK)
        LOG_FAIL("zid", "hybrid pq_pubkey: keygen failed (%d)", (int)st);
    return true;
}

bool zid_hybrid_release_sign(struct zid_doc_v2 *doc,
                             const struct zid_release *rel, uint64_t seq,
                             uint64_t expiry, const uint8_t ed_seed[32],
                             const uint8_t pq_seed[ZRS1_PQ_SEED_SIZE])
{
    if (!doc || !rel || !ed_seed || !pq_seed)
        LOG_FAIL("zid", "hybrid sign: NULL argument");
    uint8_t body[ZID_RELEASE_BODY_MAX];
    size_t body_len = zid_release_encode_body(body, sizeof(body), rel);
    if (body_len == 0)
        LOG_FAIL("zid", "hybrid sign: release body encode failed");

    memset(doc, 0, sizeof(*doc));
    doc->seq = seq;
    doc->expiry = expiry;
    doc->body_len = (uint16_t)body_len;
    memcpy(doc->body, body, body_len);
    doc->pq_param = ZRS1_PARAM_SHAKE_128S;

    /* Both secret keys exist only inside this block. Each is wiped right
     * after its last use, and on every path (no early return while a secret
     * is live). */
    uint8_t ed_sk[32];
    uint8_t pq_sk[ZCL_SLHDSA_SHAKE_128S_SECRET_KEY_SIZE];
    ed25519_keypair(doc->master_pubkey, ed_sk, ed_seed);
    enum zcl_slhdsa_status kst = hy_pq_keygen(doc->pq_pk, pq_sk, pq_seed);

    uint8_t prefix[ZID_V2_PREFIX_FIXED + ZID_BODY_MAX + ZID_V2_PQ_BIND_LEN];
    size_t prefix_len = 0;
    if (kst == ZCL_SLHDSA_OK) {
        sha3_256(doc->pq_pk, ZRS1_PQ_PK_SIZE, doc->pq_pk_digest);
        prefix_len = hy_encode_prefix(prefix, doc);
        ed25519_sign(doc->ed_signature, prefix, prefix_len, ed_sk,
                     doc->master_pubkey);
    }
    memory_cleanse(ed_sk, sizeof(ed_sk));

    enum zcl_slhdsa_status sst = ZCL_SLHDSA_ERR_ARGUMENT;
    if (kst == ZCL_SLHDSA_OK)
        sst = zcl_slhdsa_sign_deterministic(
            ZCL_SLHDSA_SHAKE_128S, pq_sk, sizeof(pq_sk), prefix, prefix_len,
            (const uint8_t *)ZRS1_CONTEXT, sizeof(ZRS1_CONTEXT) - 1,
            doc->pq_signature, ZRS1_PQ_SIG_SIZE);
    memory_cleanse(pq_sk, sizeof(pq_sk));

    if (kst != ZCL_SLHDSA_OK || sst != ZCL_SLHDSA_OK) {
        memset(doc, 0, sizeof(*doc));
        LOG_FAIL("zid", "hybrid sign: slh-dsa keygen=%d sign=%d", (int)kst,
                 (int)sst);
    }
    return true;
}
