/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZID hybrid release doc (doc version 2, "ZRS1" trailer): one Ed25519
 * signature and one SLH-DSA-SHAKE-128s signature over the SAME signed
 * prefix, and verification requires BOTH. Design and resolutions:
 * docs/work/PQ_HYBRID_RELEASE_SIGNATURE.md.
 *
 * Version-1 docs (struct zid_doc, zid.h) are untouched; this header adds a
 * separate type so no v1 caller changes shape. A v2 doc is refused by the v1
 * decoder with a version mismatch.
 *
 * Wire (version 2):
 *   version:1 (=2) | master_pubkey:32 | seq:8 LE | expiry:8 LE |
 *   body_len:2 LE | body | pq_param:1 | pq_pk_sha3_256:32 |
 *   trailer_len:2 LE | trailer (a ZRS1 container)
 * The signed prefix is everything up to and including pq_pk_sha3_256, so the
 * SLH-DSA key is authenticated by the Ed25519 signature even unpinned.
 * ZRS1 container (param 0, SHAKE-128s):
 *   "ZRS1" | param:1 | ed25519_sig:64 | slhdsa_pk:32 | slhdsa_sig:7856
 * Ed25519 signs the prefix directly; SLH-DSA signs it under the FIPS 205
 * context string ZRS1_CONTEXT. Every container length is derived from the
 * checked param byte; the container carries no length to trust. */

#ifndef ZCL_ZID_HYBRID_H
#define ZCL_ZID_HYBRID_H

#include "zid/zid.h"
#include "slhdsa/slhdsa.h"

#include <stddef.h>
#include <stdint.h>

#define ZID_DOC_VERSION_V2 2
#define ZRS1_PARAM_SHAKE_128S 0 /* the only accepted param; 1 (192s) refused */
#define ZRS1_CONTEXT "z23.zrs1.release.v1"
#define ZRS1_MAGIC "ZRS1"
#define ZRS1_PQ_PK_SIZE 32
#define ZRS1_PQ_SIG_SIZE 7856
#define ZRS1_PQ_SEED_SIZE 48 /* SK.seed || SK.prf || PK.seed */
/* 4 magic + 1 param + 64 ed25519 + 32 pk + 7856 sig */
#define ZRS1_CONTAINER_SIZE 7957
/* Signed prefix: 51 fixed + body + pq_param:1 + pq_pk_sha3_256:32. */
#define ZID_V2_PREFIX_FIXED 51
#define ZID_V2_PQ_BIND_LEN 33
/* Largest v2 doc with the 128s container (9067). The v1 ZID_DOC_MAX is
 * unchanged and still bounds v1 docs. */
#define ZID_DOC_V2_MAX \
    (ZID_V2_PREFIX_FIXED + ZID_BODY_MAX + ZID_V2_PQ_BIND_LEN + 2 + \
     ZRS1_CONTAINER_SIZE)

struct zid_doc_v2 {
    uint8_t master_pubkey[32];
    uint64_t seq;
    uint64_t expiry;
    uint16_t body_len;
    uint8_t body[ZID_BODY_MAX];
    uint8_t pq_param;
    uint8_t pq_pk_digest[32]; /* SHA3-256 of pq_pk, inside the signed prefix */
    uint8_t ed_signature[64];
    uint8_t pq_pk[ZRS1_PQ_PK_SIZE];
    uint8_t pq_signature[ZRS1_PQ_SIG_SIZE];
};

/* Distinct outcomes. Never folded into one code: each maps to its own
 * refusal string (zid_hybrid_status_code). */
enum zid_hybrid_status {
    ZID_HYBRID_OK = 0,
    ZID_HYBRID_ERR_ARGUMENT,
    ZID_HYBRID_NOT_V2,              /* version byte is not 2 */
    ZID_HYBRID_DOC_MALFORMED,       /* outer layout wrong, before the trailer */
    ZID_HYBRID_PQ_CONTAINER_MALFORMED, /* trailer length/magic/param wrong */
    ZID_HYBRID_DOC_EXPIRED,
    ZID_HYBRID_BAD_SIGNATURE,       /* the Ed25519 half */
    ZID_HYBRID_PQ_KEY_MISMATCH,     /* container pk differs from digest or pin */
    ZID_HYBRID_BAD_PQ_SIGNATURE,    /* the SLH-DSA half */
    ZID_HYBRID_NOT_A_RELEASE_BODY
};

/* Refusal code string for a status ("BAD_PQ_SIGNATURE", ...), or "OK". */
const char *zid_hybrid_status_code(enum zid_hybrid_status st);

/* Returns the encoded size, or 0 on error (NULL, body too long, param not 0,
 * undersized buffer). Does not sign or verify. */
size_t zid_hybrid_encode(uint8_t *out, size_t out_len,
                         const struct zid_doc_v2 *doc);

/* Bounds-strict decode. Does NOT verify signatures. */
enum zid_hybrid_status zid_hybrid_decode(struct zid_doc_v2 *doc,
                                         const uint8_t *buf, size_t len);

/* Both signatures, in order: expiry, Ed25519, pk digest, SLH-DSA, then the
 * optional pin (pinned_pq_pk, 32 bytes, may be NULL). No body decode. */
enum zid_hybrid_status zid_hybrid_verify(const struct zid_doc_v2 *doc,
                                         const uint8_t *pinned_pq_pk,
                                         uint64_t now_unix);

/* zid_hybrid_verify, then decode the "ZIDR" release body into rel_out
 * (may be NULL). */
enum zid_hybrid_status zid_hybrid_release_verify(
    const struct zid_doc_v2 *doc, const uint8_t *pinned_pq_pk,
    struct zid_release *rel_out, uint64_t now_unix);

/* Derive the SLH-DSA-SHAKE-128s public key from a 48-byte seed. The
 * secret key is wiped before return. */
bool zid_hybrid_pq_pubkey(uint8_t pk[ZRS1_PQ_PK_SIZE],
                          const uint8_t pq_seed[ZRS1_PQ_SEED_SIZE]);

/* Sign a release as a v2 doc: Ed25519 key from ed_seed, SLH-DSA key from
 * pq_seed (deterministic signing). Both secret keys are wiped on every path;
 * the caller wipes its seed buffers. */
bool zid_hybrid_release_sign(struct zid_doc_v2 *doc,
                             const struct zid_release *rel, uint64_t seq,
                             uint64_t expiry, const uint8_t ed_seed[32],
                             const uint8_t pq_seed[ZRS1_PQ_SEED_SIZE]);

#endif /* ZCL_ZID_HYBRID_H */
