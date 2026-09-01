/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZID — sovereign identity document codec: blinded keys, encode/decode,
 * sign/verify, and the monotonic-seq supersede rule (no allocation).
 * Plus the anchor-domain tree: an append-only MMR over record digests so
 * one on-chain ZANC anchor commits an unbounded batch. */

#include "zid/zid.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "base/log_macros.h"
#include "support/cleanse.h"
#include <string.h>

/* Fixed wire prefix length: version:1 ‖ pubkey:32 ‖ seq:8 ‖ expiry:8 ‖
 * body_len:2. The signature (64 bytes) follows the body. */
#define ZID_PREFIX_LEN 51

void zid_blinded_key(uint8_t out[32], const uint8_t master_pubkey[32],
                     uint64_t period)
{
    /* "ZIDB" ‖ master_pubkey ‖ period_le64 — 4 + 32 + 8 bytes. */
    uint8_t buf[4 + 32 + 8];
    memcpy(buf, "ZIDB", 4);
    memcpy(buf + 4, master_pubkey, 32);
    zcl_write_u64_le(buf + 4 + 32, period);
    sha3_256(buf, sizeof(buf), out);
}

/* Encode the signature-covered prefix (everything before the signature)
 * into out[0..ZID_PREFIX_LEN + doc->body_len). Caller guarantees
 * body_len <= ZID_BODY_MAX and a large-enough buffer. */
static size_t zid_encode_prefix(uint8_t *out, const struct zid_doc *doc)
{
    size_t n = 0;
    out[n++] = ZID_DOC_VERSION;
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
    return n;
}

size_t zid_doc_encode(uint8_t *out, size_t out_len, const struct zid_doc *doc)
{
    if (!out || !doc)
        LOG_RETURN(0, "zid", "encode: NULL argument (out=%p doc=%p)",
                   (void *)out, (const void *)doc);
    if (doc->body_len > ZID_BODY_MAX)
        LOG_RETURN(0, "zid", "encode: body_len %u exceeds ZID_BODY_MAX %d",
                   doc->body_len, ZID_BODY_MAX);
    size_t total = ZID_PREFIX_LEN + (size_t)doc->body_len + 64;
    if (out_len < total)
        LOG_RETURN(0, "zid",
                   "encode: out_len %zu too small (need %zu for body_len %u)",
                   out_len, total, doc->body_len);
    size_t n = zid_encode_prefix(out, doc);
    memcpy(out + n, doc->signature, 64);
    return n + 64;
}

bool zid_doc_decode(struct zid_doc *doc, const uint8_t *buf, size_t len)
{
    if (!doc || !buf)
        LOG_FAIL("zid", "decode: NULL argument (doc=%p buf=%p)",
                 (void *)doc, (const void *)buf);
    if (len < ZID_PREFIX_LEN + 64)
        LOG_FAIL("zid", "decode: len %zu below minimum %d",
                 len, ZID_PREFIX_LEN + 64);
    if (len > ZID_DOC_MAX)
        LOG_FAIL("zid", "decode: len %zu exceeds ZID_DOC_MAX %d",
                 len, ZID_DOC_MAX);
    if (buf[0] != ZID_DOC_VERSION)
        LOG_FAIL("zid", "decode: unsupported version %u (want %d)",
                 buf[0], ZID_DOC_VERSION);

    uint16_t body_len = (uint16_t)buf[49] | ((uint16_t)buf[50] << 8);
    if (len != ZID_PREFIX_LEN + (size_t)body_len + 64)
        LOG_FAIL("zid",
                 "decode: len %zu does not match body_len %u (want exactly %zu)",
                 len, body_len, ZID_PREFIX_LEN + (size_t)body_len + 64);

    memcpy(doc->master_pubkey, buf + 1, 32);
    doc->seq = zcl_read_u64_le(buf + 33);
    doc->expiry = zcl_read_u64_le(buf + 41);
    doc->body_len = body_len;
    memcpy(doc->body, buf + ZID_PREFIX_LEN, body_len);
    memcpy(doc->signature, buf + ZID_PREFIX_LEN + body_len, 64);
    return true;
}

bool zid_doc_verify(const struct zid_doc *doc, uint64_t now_unix)
{
    if (!doc)
        LOG_FAIL("zid", "verify: NULL doc");
    if (doc->body_len > ZID_BODY_MAX)
        LOG_FAIL("zid", "verify: body_len %u exceeds ZID_BODY_MAX %d",
                 doc->body_len, ZID_BODY_MAX);
    if (now_unix >= doc->expiry)
        LOG_FAIL("zid", "verify: doc expired (expiry=%llu now=%llu)",
                 (unsigned long long)doc->expiry,
                 (unsigned long long)now_unix);

    uint8_t prefix[ZID_PREFIX_LEN + ZID_BODY_MAX];
    size_t prefix_len = zid_encode_prefix(prefix, doc);
    if (!ed25519_verify(doc->signature, prefix, prefix_len,
                        doc->master_pubkey))
        LOG_FAIL("zid", "verify: ed25519 signature check failed");
    return true;
}

bool zid_doc_sign(struct zid_doc *doc, const uint8_t *body, uint16_t body_len,
                  uint64_t seq, uint64_t expiry, const uint8_t seed[32])
{
    if (!doc || !seed)
        LOG_FAIL("zid", "sign: NULL argument (doc=%p seed=%p)",
                 (void *)doc, (const void *)seed);
    if (body_len > ZID_BODY_MAX)
        LOG_FAIL("zid", "sign: body_len %u exceeds ZID_BODY_MAX %d",
                 body_len, ZID_BODY_MAX);
    if (body_len > 0 && !body)
        LOG_FAIL("zid", "sign: NULL body with body_len %u", body_len);

    memset(doc, 0, sizeof(*doc));
    uint8_t sk[32];
    ed25519_keypair(doc->master_pubkey, sk, seed);
    doc->seq = seq;
    doc->expiry = expiry;
    doc->body_len = body_len;
    if (body_len > 0)
        memcpy(doc->body, body, body_len);

    uint8_t prefix[ZID_PREFIX_LEN + ZID_BODY_MAX];
    size_t prefix_len = zid_encode_prefix(prefix, doc);
    ed25519_sign(doc->signature, prefix, prefix_len, sk, doc->master_pubkey);
    memory_cleanse(sk, sizeof(sk)); /* seed copy — do not leave on stack */
    return true;
}

bool zid_doc_supersedes(const struct zid_doc *candidate,
                        const struct zid_doc *current)
{
    if (!candidate || !current)
        LOG_FAIL("zid", "supersedes: NULL argument (candidate=%p current=%p)",
                 (const void *)candidate, (const void *)current);
    if (memcmp(candidate->master_pubkey, current->master_pubkey, 32) != 0)
        return false; /* raw-return-ok: different identity, a predicate answer not an error */
    return candidate->seq > current->seq;
}

/* ── Anchor-domain tree (MMR over record digests) ──────────────────
 *
 * Same peak-merge geometry as core/modules/chain/src/mmr.c (self-contained here —
 * contexts/wallet/modules/zid must not depend on core/modules/chain), with one deliberate difference:
 * the leaf hash carries a "ZIDL" domain tag so a zid inclusion proof can
 * never be replayed against the chain MMR or any other 0x00‖digest tree.
 *
 * MMR geometry: leaves are numbered 0..n-1; the peaks are the powers of
 * two in n's binary decomposition, stored largest-first. Leaf `index`
 * maps arithmetically to (peak, position within peak) with no stored
 * metadata, so the verifier needs only (index, num_leaves, proof). */

#define ZID_TREE_TAG_LEAF     0x00
#define ZID_TREE_TAG_INTERNAL 0x01
#define ZID_TREE_TAG_ROOT     0x02

static void zid_tree_hash_leaf(const uint8_t record_digest[32], uint8_t out[32])
{
    uint8_t buf[1 + 4 + 32];
    buf[0] = ZID_TREE_TAG_LEAF;
    memcpy(buf + 1, "ZIDL", 4);
    memcpy(buf + 5, record_digest, 32);
    sha3_256(buf, sizeof(buf), out);
}

static void zid_tree_hash_internal(const uint8_t left[32],
                                   const uint8_t right[32], uint8_t out[32])
{
    uint8_t buf[1 + 32 + 32];
    buf[0] = ZID_TREE_TAG_INTERNAL;
    memcpy(buf + 1, left, 32);
    memcpy(buf + 33, right, 32);
    sha3_256(buf, sizeof(buf), out);
}

/* Bag peaks: SHA3-256(0x02 ‖ peak_0 ‖ … ‖ peak_k). Caller handles the
 * 0- and 1-peak edge cases (mirrors mmr.c: empty → zeros, one → itself). */
static void zid_tree_bag_peaks(const uint8_t (*peaks)[32], uint32_t n,
                               uint8_t out[32])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    uint8_t tag = ZID_TREE_TAG_ROOT;
    sha3_256_write(&ctx, &tag, 1);
    for (uint32_t i = 0; i < n; i++)
        sha3_256_write(&ctx, peaks[i], 32);
    sha3_256_finalize(&ctx, out);
}

static void zid_tree_root_from_peaks(const uint8_t (*peaks)[32], uint32_t n,
                                     uint8_t out[32])
{
    if (n == 0) {
        memset(out, 0, 32);
        return;
    }
    if (n == 1) {
        memcpy(out, peaks[0], 32);
        return;
    }
    zid_tree_bag_peaks(peaks, n, out);
}

/* Peak sizes in leaves (powers of two in n's binary decomposition),
 * largest first. Returns the count (= popcount(n)). */
static uint32_t zid_tree_peak_sizes(uint64_t num_leaves,
                                    uint64_t sizes[ZID_TREE_MAX_PEAKS])
{
    uint32_t k = 0;
    uint64_t remaining = num_leaves;
    for (int b = 63; b >= 0 && remaining != 0; b--) {
        uint64_t s = 1ULL << b;
        if (remaining & s) {
            sizes[k++] = s;
            remaining -= s;
        }
    }
    return k;
}

/* Hash of the perfect subtree covering `count` (a power of two) record
 * digests starting at leaves[0]. Recursion depth ≤ 64; no allocation. */
static void zid_tree_subtree_hash(const uint8_t leaves[][32], uint64_t count,
                                  uint8_t out[32])
{
    if (count == 1) {
        zid_tree_hash_leaf(leaves[0], out);
        return;
    }
    uint8_t left[32], right[32];
    zid_tree_subtree_hash(leaves, count / 2, left);
    zid_tree_subtree_hash(leaves + count / 2, count / 2, right);
    zid_tree_hash_internal(left, right, out);
}

/* Locate the peak containing leaf `index`: fills *pi (peak position in
 * bagging order), *peak_offset (first leaf of that peak), *peak_size.
 * Caller guarantees 0 <= index < num_leaves. */
static void zid_tree_locate(uint64_t num_leaves, uint64_t index,
                            uint64_t sizes[ZID_TREE_MAX_PEAKS], uint32_t *k_out,
                            uint32_t *pi, uint64_t *peak_offset,
                            uint64_t *peak_size)
{
    uint32_t k = zid_tree_peak_sizes(num_leaves, sizes);
    uint64_t offset = 0;
    for (uint32_t j = 0; j < k; j++) {
        if (index < offset + sizes[j]) {
            *k_out = k;
            *pi = j;
            *peak_offset = offset;
            *peak_size = sizes[j];
            return;
        }
        offset += sizes[j];
    }
    /* Unreachable: index < num_leaves means some peak contains it. */
    *k_out = k;
    *pi = k;
    *peak_offset = offset;
    *peak_size = 0;
}

void zid_tree_init(struct zid_tree *t)
{
    memset(t, 0, sizeof(*t));
}

bool zid_tree_append(struct zid_tree *t, const uint8_t record_digest[32])
{
    if (!t || !record_digest)
        LOG_FAIL("zid", "tree_append: NULL argument (t=%p digest=%p)",
                 (void *)t, (const void *)record_digest);

    uint8_t h[32];
    zid_tree_hash_leaf(record_digest, h);

    /* Merge with existing peaks while the new leaf completes a pair:
     * count trailing 1-bits in (num_leaves + 1). */
    uint64_t n = t->num_leaves + 1;
    while (n % 2 == 0 && t->num_peaks > 0) {
        uint8_t parent[32];
        zid_tree_hash_internal(t->peaks[t->num_peaks - 1], h, parent);
        memcpy(h, parent, 32);
        t->num_peaks--;
        n /= 2;
    }

    if (t->num_peaks >= ZID_TREE_MAX_PEAKS)
        LOG_FAIL("zid", "tree_append: peak capacity %d exhausted",
                 ZID_TREE_MAX_PEAKS);
    memcpy(t->peaks[t->num_peaks], h, 32);
    t->num_peaks++;
    t->num_leaves++;
    return true;
}

void zid_tree_root(const struct zid_tree *t, uint8_t out[32])
{
    zid_tree_root_from_peaks(t->peaks, t->num_peaks, out);
}

bool zid_tree_prove_from_leaves(const uint8_t leaves[][32],
                                uint64_t num_leaves, uint64_t index,
                                uint8_t proof_siblings[][32],
                                uint32_t *proof_len, uint8_t root_out[32])
{
    if (!leaves || !proof_siblings || !proof_len || !root_out)
        LOG_FAIL("zid", "tree_prove: NULL argument");
    if (num_leaves == 0 || index >= num_leaves)
        LOG_FAIL("zid", "tree_prove: index %llu out of range (num_leaves %llu)",
                 (unsigned long long)index, (unsigned long long)num_leaves);

    uint64_t sizes[ZID_TREE_MAX_PEAKS];
    uint32_t k, pi;
    uint64_t peak_offset, peak_size;
    zid_tree_locate(num_leaves, index, sizes, &k, &pi,
                    &peak_offset, &peak_size);

    uint32_t n = 0;

    /* Sibling path inside the peak, bottom-up. At level `width` the node
     * covers `width` leaves; its sibling subtree starts at
     * peak_offset + (pos ^ 1) * width. */
    uint64_t pos = index - peak_offset;
    for (uint64_t width = 1; width < peak_size; width *= 2) {
        if (n >= ZID_TREE_MAX_PEAKS)
            LOG_FAIL("zid", "tree_prove: proof exceeds %d-hash capacity",
                     ZID_TREE_MAX_PEAKS);
        uint64_t sib_pos = pos ^ 1;
        zid_tree_subtree_hash(leaves + peak_offset + sib_pos * width, width,
                              proof_siblings[n++]);
        pos >>= 1;
    }

    /* The OTHER peaks, in bagging order. The verifier knows pi from
     * (index, num_leaves) and re-inserts the computed peak there. */
    uint64_t offset = 0;
    for (uint32_t j = 0; j < k; j++) {
        if (j != pi) {
            if (n >= ZID_TREE_MAX_PEAKS)
                LOG_FAIL("zid", "tree_prove: proof exceeds %d-hash capacity",
                         ZID_TREE_MAX_PEAKS);
            zid_tree_subtree_hash(leaves + offset, sizes[j],
                                  proof_siblings[n++]);
        }
        offset += sizes[j];
    }
    *proof_len = n;

    /* Bagged root over all peaks (recomputed from the same leaf list, so
     * it matches the incremental zid_tree_append + zid_tree_root root). */
    uint8_t peaks[ZID_TREE_MAX_PEAKS][32];
    offset = 0;
    for (uint32_t j = 0; j < k; j++) {
        zid_tree_subtree_hash(leaves + offset, sizes[j], peaks[j]);
        offset += sizes[j];
    }
    zid_tree_root_from_peaks(peaks, k, root_out);
    return true;
}

bool zid_tree_verify(const uint8_t root[32], const uint8_t record_digest[32],
                     uint64_t index, uint64_t num_leaves,
                     const uint8_t proof_siblings[][32], uint32_t proof_len)
{
    if (!root || !record_digest || (!proof_siblings && proof_len > 0))
        LOG_FAIL("zid", "tree_verify: NULL argument");
    if (num_leaves == 0 || index >= num_leaves)
        LOG_FAIL("zid", "tree_verify: index %llu out of range (num_leaves %llu)",
                 (unsigned long long)index, (unsigned long long)num_leaves);

    uint64_t sizes[ZID_TREE_MAX_PEAKS];
    uint32_t k, pi;
    uint64_t peak_offset, peak_size;
    zid_tree_locate(num_leaves, index, sizes, &k, &pi,
                    &peak_offset, &peak_size);

    uint32_t path_len = 0;
    for (uint64_t width = 1; width < peak_size; width *= 2)
        path_len++;
    if (proof_len != path_len + (k - 1))
        LOG_FAIL("zid",
                 "tree_verify: proof_len %u wrong (want %u path + %u peaks)",
                 proof_len, path_len, k - 1);

    /* Fold the sibling path to the peak, bottom-up. */
    uint8_t h[32];
    zid_tree_hash_leaf(record_digest, h);
    uint64_t pos = index - peak_offset;
    for (uint32_t i = 0; i < path_len; i++) {
        uint8_t parent[32];
        if ((pos & 1) == 0)
            zid_tree_hash_internal(h, proof_siblings[i], parent);
        else
            zid_tree_hash_internal(proof_siblings[i], h, parent);
        memcpy(h, parent, 32);
        pos >>= 1;
    }

    /* Rebuild the full peak array: other peaks from the proof (bagging
     * order), the computed peak inserted at position pi. */
    uint8_t peaks[ZID_TREE_MAX_PEAKS][32];
    uint32_t p = path_len;
    for (uint32_t j = 0; j < k; j++) {
        if (j == pi)
            memcpy(peaks[j], h, 32);
        else
            memcpy(peaks[j], proof_siblings[p++], 32);
    }

    uint8_t computed[32];
    zid_tree_root_from_peaks(peaks, k, computed);

    int diff = 0;
    for (int i = 0; i < 32; i++)
        diff |= computed[i] ^ root[i];
    if (diff != 0)
        LOG_FAIL("zid", "tree_verify: root mismatch (index %llu num_leaves %llu)",
                 (unsigned long long)index, (unsigned long long)num_leaves);
    return true;
}

/* ── Canonical proof wire format ─────────────────────────────────── */

#define ZID_PROOF_HDR_LEN 19 /* version:1 ‖ index:8 ‖ num_leaves:8 ‖ proof_len:2 */

size_t zid_proof_encode(uint8_t *out, size_t out_len, uint64_t index,
                        uint64_t num_leaves,
                        const uint8_t proof_siblings[][32], uint32_t proof_len)
{
    if (!out || (!proof_siblings && proof_len > 0))
        LOG_RETURN(0, "zid", "proof_encode: NULL argument (out=%p siblings=%p len=%u)",
                   (void *)out, (const void *)proof_siblings, proof_len);
    if (proof_len > ZID_TREE_MAX_PEAKS)
        LOG_RETURN(0, "zid", "proof_encode: proof_len %u exceeds max %d",
                   proof_len, ZID_TREE_MAX_PEAKS);
    size_t total = ZID_PROOF_HDR_LEN + (size_t)proof_len * 32;
    if (out_len < total)
        LOG_RETURN(0, "zid",
                   "proof_encode: out_len %zu too small (need %zu for proof_len %u)",
                   out_len, total, proof_len);

    size_t n = 0;
    out[n++] = ZID_PROOF_VERSION;
    zcl_write_u64_le(out + n, index);
    n += 8;
    zcl_write_u64_le(out + n, num_leaves);
    n += 8;
    out[n++] = (uint8_t)(proof_len & 0xff);
    out[n++] = (uint8_t)(proof_len >> 8);
    for (uint32_t i = 0; i < proof_len; i++) {
        memcpy(out + n, proof_siblings[i], 32);
        n += 32;
    }
    return n;
}

bool zid_proof_decode(uint64_t *index, uint64_t *num_leaves,
                      uint8_t proof_siblings[][32], uint32_t *proof_len,
                      const uint8_t *buf, size_t len)
{
    if (!index || !num_leaves || !proof_siblings || !proof_len || !buf)
        LOG_FAIL("zid", "proof_decode: NULL argument");
    if (len < ZID_PROOF_HDR_LEN)
        LOG_FAIL("zid", "proof_decode: len %zu below header minimum %d",
                 len, ZID_PROOF_HDR_LEN);
    if (len > ZID_PROOF_WIRE_MAX)
        LOG_FAIL("zid", "proof_decode: len %zu exceeds ZID_PROOF_WIRE_MAX %d",
                 len, ZID_PROOF_WIRE_MAX);
    if (buf[0] != ZID_PROOF_VERSION)
        LOG_FAIL("zid", "proof_decode: unsupported version %u (want %d)",
                 buf[0], ZID_PROOF_VERSION);

    uint16_t plen = (uint16_t)buf[17] | ((uint16_t)buf[18] << 8);
    if (plen > ZID_TREE_MAX_PEAKS)
        LOG_FAIL("zid", "proof_decode: proof_len %u exceeds max %d",
                 plen, ZID_TREE_MAX_PEAKS);
    if (len != ZID_PROOF_HDR_LEN + (size_t)plen * 32)
        LOG_FAIL("zid",
                 "proof_decode: len %zu does not match proof_len %u (want exactly %zu)",
                 len, plen, ZID_PROOF_HDR_LEN + (size_t)plen * 32);

    *index = zcl_read_u64_le(buf + 1);
    *num_leaves = zcl_read_u64_le(buf + 9);
    *proof_len = plen;
    for (uint32_t i = 0; i < plen; i++)
        memcpy(proof_siblings[i], buf + ZID_PROOF_HDR_LEN + (size_t)i * 32, 32);
    return true;
}

/* ── Release record codec ────────────────────────────────────────── */

/* Printable ASCII 0x20..0x7E, no NUL games: len is a C-string bound and
 * every byte must be in range. */
static bool zid_release_str_valid(const char *s, size_t max_len, size_t *len_out)
{
    if (!s)
        return false;
    size_t len = strlen(s);
    if (len == 0 || len > max_len)
        return false;
    for (size_t i = 0; i < len; i++) {
        uint8_t c = (uint8_t)s[i];
        if (c < 0x20 || c > 0x7e)
            return false;
    }
    if (len_out)
        *len_out = len;
    return true;
}

size_t zid_release_encode_body(uint8_t *out, size_t out_len,
                               const struct zid_release *rel)
{
    if (!out || !rel)
        LOG_RETURN(0, "zid", "release_encode: NULL argument (out=%p rel=%p)",
                   (void *)out, (const void *)rel);
    size_t name_len, version_len;
    if (!zid_release_str_valid(rel->name, ZID_RELEASE_NAME_MAX, &name_len))
        LOG_RETURN(0, "zid",
                   "release_encode: name must be 1..%d printable ASCII bytes",
                   ZID_RELEASE_NAME_MAX);
    if (!zid_release_str_valid(rel->version, ZID_RELEASE_VERSION_MAX,
                               &version_len))
        LOG_RETURN(0, "zid",
                   "release_encode: version must be 1..%d printable ASCII bytes",
                   ZID_RELEASE_VERSION_MAX);

    size_t total = 4 + 1 + name_len + 1 + version_len + 32;
    if (out_len < total)
        LOG_RETURN(0, "zid",
                   "release_encode: out_len %zu too small (need %zu)",
                   out_len, total);

    size_t n = 0;
    memcpy(out + n, "ZIDR", 4);
    n += 4;
    out[n++] = (uint8_t)name_len;
    memcpy(out + n, rel->name, name_len);
    n += name_len;
    out[n++] = (uint8_t)version_len;
    memcpy(out + n, rel->version, version_len);
    n += version_len;
    memcpy(out + n, rel->manifest_root, 32);
    n += 32;
    return n;
}

bool zid_release_decode_body(struct zid_release *rel,
                             const uint8_t *body, uint16_t body_len)
{
    if (!rel || !body)
        LOG_FAIL("zid", "release_decode: NULL argument (rel=%p body=%p)",
                 (void *)rel, (const void *)body);
    if (body_len < 4 + 1 + 1 + 1 + 32)
        LOG_FAIL("zid", "release_decode: body_len %u below minimum %d",
                 body_len, 4 + 1 + 1 + 1 + 32);
    if (body_len > ZID_RELEASE_BODY_MAX)
        LOG_FAIL("zid", "release_decode: body_len %u exceeds max %d",
                 body_len, ZID_RELEASE_BODY_MAX);
    if (memcmp(body, "ZIDR", 4) != 0)
        LOG_FAIL("zid", "release_decode: bad tag (want ZIDR)");

    size_t name_len = body[4];
    if (name_len == 0 || name_len > ZID_RELEASE_NAME_MAX)
        LOG_FAIL("zid", "release_decode: name_len %zu out of range", name_len);
    if ((size_t)body_len < 4 + 1 + name_len + 1)
        LOG_FAIL("zid", "release_decode: truncated before version_len");
    size_t version_len = body[4 + 1 + name_len];
    if (version_len == 0 || version_len > ZID_RELEASE_VERSION_MAX)
        LOG_FAIL("zid", "release_decode: version_len %zu out of range",
                 version_len);
    size_t want = 4 + 1 + name_len + 1 + version_len + 32;
    if ((size_t)body_len != want)
        LOG_FAIL("zid",
                 "release_decode: body_len %u does not match fields (want exactly %zu)",
                 body_len, want);

    memset(rel, 0, sizeof(*rel));
    memcpy(rel->name, body + 5, name_len);
    memcpy(rel->version, body + 5 + name_len + 1, version_len);
    memcpy(rel->manifest_root, body + 5 + name_len + 1 + version_len, 32);
    /* Trailing NULs come from the memset; now prove the bytes are
     * printable (a name/version with a control byte is a reject, not a
     * silent sanitize). */
    if (!zid_release_str_valid(rel->name, ZID_RELEASE_NAME_MAX, NULL))
        LOG_FAIL("zid", "release_decode: name not printable ASCII");
    if (!zid_release_str_valid(rel->version, ZID_RELEASE_VERSION_MAX, NULL))
        LOG_FAIL("zid", "release_decode: version not printable ASCII");
    return true;
}

bool zid_release_sign(struct zid_doc *doc, const struct zid_release *rel,
                      uint64_t seq, uint64_t expiry, const uint8_t seed[32])
{
    if (!doc || !rel || !seed)
        LOG_FAIL("zid", "release_sign: NULL argument");
    uint8_t body[ZID_RELEASE_BODY_MAX];
    size_t body_len = zid_release_encode_body(body, sizeof(body), rel);
    if (body_len == 0)
        LOG_FAIL("zid", "release_sign: body encode failed");
    if (!zid_doc_sign(doc, body, (uint16_t)body_len, seq, expiry, seed))
        LOG_FAIL("zid", "release_sign: doc sign failed");
    return true;
}

bool zid_release_verify(const struct zid_doc *doc,
                        struct zid_release *rel_out, uint64_t now_unix)
{
    if (!doc)
        LOG_FAIL("zid", "release_verify: NULL doc");
    if (!zid_doc_verify(doc, now_unix))
        LOG_FAIL("zid", "release_verify: doc verify failed");
    struct zid_release rel;
    if (!zid_release_decode_body(&rel, doc->body, doc->body_len))
        LOG_FAIL("zid", "release_verify: body is not a valid release record");
    if (rel_out)
        *rel_out = rel;
    return true;
}

/* ── Domain batching ─────────────────────────────────────────────── */

void zid_record_digest(uint8_t out[32], const uint8_t *doc_wire,
                       size_t doc_wire_len)
{
    /* SHA3-256 of the canonical wire bytes, no tag — the "ZIDL" domain
     * separation lives in the tree's leaf hash, not in the record
     * digest itself. */
    sha3_256(doc_wire, doc_wire_len, out);
}

bool zid_tree_root_from_digests(const uint8_t digests[][32], uint64_t n,
                                uint8_t out[32])
{
    if (!out || (n > 0 && !digests))
        LOG_FAIL("zid", "tree_root_from_digests: NULL argument");
    struct zid_tree t;
    zid_tree_init(&t);
    for (uint64_t i = 0; i < n; i++)
        if (!zid_tree_append(&t, digests[i]))
            LOG_FAIL("zid",
                     "tree_root_from_digests: append failed at leaf %llu",
                     (unsigned long long)i);
    zid_tree_root(&t, out);
    return true;
}
