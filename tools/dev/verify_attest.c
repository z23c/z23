/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Signed compile attestations from a separate verifier account,
 *          the root-pinned key that admits them, and the admission
 *          decision. See verify_attest.h for the contract. */

#include "verify_attest.h"

#include "base/cleanse.h"
#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "codec/cursor.h"
#include "crypto/ed25519.h"
#include "sha3/sha3.h"
#include "verify/fixed_result_contract.h"

#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#define VA_LOG_DOMAIN "verify-attest"
/* Every v2 domain is length-framed, so no body can extend it. */
#define VA_SIGN_DOMAIN "z23verify.attest.signature.v2"
#define VA_STORE_DOMAIN "z23verify.attest.store_key.v2"
#define VA_V1_SCHEMA_LEN (sizeof(ZCL_VERIFY_ATTEST_SCHEMA_V1) - 1u)
#define VA_HASH ZCL_VERIFY_ATTEST_HASH_BYTES
#define VA_PUB ZCL_VERIFY_ATTEST_PUBKEY_BYTES
#define VA_SIG ZCL_VERIFY_ATTEST_SIGNATURE_BYTES
#define VA_V1_TRAILER (VA_PUB + VA_SIG)
#define VA_KEY_FILE_MAX 128u
#define VA_CHAIN_MAX 64u
#define VA_GROUP_OR_WORLD_WRITE 0022u
#define VA_STICKY 01000u

static void va_why(const char **why, const char *token)
{
    if (why) *why = token;
}

/* ── Canonical body (v2) ────────────────────────────────────────────────── */

#define VA_HASH_SPEC(label) {label, ZCL_FR_KIND_EXACT, VA_HASH}
static const struct zcl_fr_spec k_va_body_spec[] = {
    {"contract", ZCL_FR_KIND_BLOB, ZCL_VERIFY_ATTEST_CONTRACT_MAX},
    {"toolchain_id", ZCL_FR_KIND_BLOB, ZCL_VERIFY_ATTEST_TOOLCHAIN_MAX},
    {"argv_norm", ZCL_FR_KIND_BLOB, ZCL_VERIFY_ATTEST_ARGV_MAX},
    {"recorded_cwd", ZCL_FR_KIND_BLOB, ZCL_VERIFY_ATTEST_CWD_MAX},
    {"target", ZCL_FR_KIND_BLOB, ZCL_VERIFY_ATTEST_TARGET_MAX},
    VA_HASH_SPEC("pp_sha3"), VA_HASH_SPEC("closure_sha3"),
    VA_HASH_SPEC("profile_sha3"), VA_HASH_SPEC("receipt_sha3"),
    VA_HASH_SPEC("obj_sha3"), VA_HASH_SPEC("dep_sha3"),
    VA_HASH_SPEC("stderr_sha3"),
    {"exit_code", ZCL_FR_KIND_U64, 8u},
};
#define VA_BODY_FIELDS (sizeof(k_va_body_spec) / sizeof(k_va_body_spec[0]))

static const struct zcl_fr_spec k_va_trailer_spec[] = {
    {"signer_pubkey", ZCL_FR_KIND_EXACT, VA_PUB},
    {"signature", ZCL_FR_KIND_EXACT, VA_SIG},
};
#define VA_TRAILER_FIELDS 2u
/* The trailer's exact framed size: two labels, two values, four prefixes. */
#define VA_TRAILER (4u * 8u + sizeof("signer_pubkey") - 1u + \
                    sizeof("signature") - 1u + VA_PUB + VA_SIG)

static struct zcl_fr_value va_text_value(const struct zcl_verify_attest_text *t)
{
    return (struct zcl_fr_value){(const uint8_t *)t->bytes, t->len, 0u};
}

static struct zcl_fr_value va_hash_value(const uint8_t hash[VA_HASH])
{
    return (struct zcl_fr_value){hash, VA_HASH, 0u};
}

static void va_body_values(const struct zcl_verify_attest_record *r,
                           struct zcl_fr_value v[VA_BODY_FIELDS])
{
    v[0] = va_text_value(&r->binding.contract);
    v[1] = va_text_value(&r->toolchain_id);
    v[2] = va_text_value(&r->argv_norm);
    v[3] = va_text_value(&r->recorded_cwd);
    v[4] = va_text_value(&r->binding.target);
    v[5] = va_hash_value(r->pp_sha3);
    v[6] = va_hash_value(r->closure_sha3);
    v[7] = va_hash_value(r->binding.profile_sha3);
    v[8] = va_hash_value(r->binding.receipt_sha3);
    v[9] = va_hash_value(r->obj_sha3);
    v[10] = va_hash_value(r->dep_sha3);
    v[11] = va_hash_value(r->stderr_sha3);
    v[12] = (struct zcl_fr_value){NULL, 0u, (uint64_t)(int64_t)r->exit_code};
}

static bool va_record_ok(const struct zcl_verify_attest_record *r)
{
    const struct zcl_verify_attest_text *texts[] = {
        &r->binding.contract, &r->toolchain_id, &r->argv_norm,
        &r->recorded_cwd, &r->binding.target};
    for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
        if (texts[i]->len && !texts[i]->bytes) return false;
    return r->binding.contract.len > 0 && r->toolchain_id.len > 0 &&
           r->argv_norm.len > 0;
}

static const char *va_body_write(const struct zcl_verify_attest_record *r,
                                 struct zcl_fr_writer *w)
{
    struct zcl_fr_value v[VA_BODY_FIELDS];
    va_body_values(r, v);
    const char *why = zcl_fr_encode(w, ZCL_VERIFY_ATTEST_SCHEMA,
                                    k_va_body_spec, VA_BODY_FIELDS, v);
    if (why && strcmp(why, ZCL_FR_WHY_BUFFER) == 0)
        return ZCL_VERIFY_ATTEST_WHY_ARGUMENTS;
    return why ? ZCL_VERIFY_ATTEST_WHY_MALFORMED : NULL;
}

/* Allocate `extra` spare bytes after the body so seal can append its
 * trailer without a second copy. */
static bool va_body_alloc(const struct zcl_verify_attest_record *record,
                          size_t extra, uint8_t **out, size_t *body_len,
                          const char **why)
{
    va_why(why, NULL);
    if (!out || !body_len || !record) {
        va_why(why, ZCL_VERIFY_ATTEST_WHY_ARGUMENTS);
        return false;
    }
    *out = NULL;
    *body_len = 0;
    struct zcl_fr_writer w;
    zcl_fr_writer_buffer(&w, NULL, 0u);
    struct sha3_256_ctx sizing;
    sha3_256_init(&sizing);
    zcl_fr_writer_hash(&w, &sizing);
    const char *bad = va_record_ok(record) ? va_body_write(record, &w)
                                           : ZCL_VERIFY_ATTEST_WHY_MALFORMED;
    if (bad) {
        va_why(why, bad);
        return false;
    }
    uint8_t *buf = zcl_malloc(w.len + extra, "verify-attest-body");
    if (!buf) {
        va_why(why, ZCL_VERIFY_ATTEST_WHY_NO_MEMORY);
        return false;
    }
    zcl_fr_writer_buffer(&w, buf, w.len + extra);
    (void)va_body_write(record, &w);
    *out = buf;
    *body_len = w.len;
    return true;
}

bool zcl_verify_attest_body_encode(const struct zcl_verify_attest_record *record,
                                   uint8_t **out, size_t *out_len,
                                   const char **why)
{
    return va_body_alloc(record, 0u, out, out_len, why);
}

/* The signed message: F(sign domain), then the body. */
static uint8_t *va_sign_message(const uint8_t *body, size_t body_len,
                                size_t *msg_len)
{
    size_t prefix = 8u + sizeof(VA_SIGN_DOMAIN) - 1u;
    uint8_t *msg = zcl_malloc(prefix + body_len, "verify-attest-message");
    if (!msg)
        return NULL;
    struct zcl_fr_writer w;
    zcl_fr_writer_buffer(&w, msg, prefix + body_len);
    zcl_fr_put(&w, VA_SIGN_DOMAIN, sizeof(VA_SIGN_DOMAIN) - 1u);
    if (body_len)
        memcpy(msg + prefix, body, body_len);
    *msg_len = prefix + body_len;
    return msg;
}

static void va_put_trailer(uint8_t *at, const uint8_t pub[VA_PUB],
                           const uint8_t sig[VA_SIG])
{
    struct zcl_fr_writer w;
    zcl_fr_writer_buffer(&w, at, VA_TRAILER);
    zcl_fr_put(&w, "signer_pubkey", sizeof("signer_pubkey") - 1u);
    zcl_fr_put(&w, pub, VA_PUB);
    zcl_fr_put(&w, "signature", sizeof("signature") - 1u);
    zcl_fr_put(&w, sig, VA_SIG);
}

bool zcl_verify_attest_seal(const struct zcl_verify_attest_record *record,
                            const uint8_t seed[ZCL_VERIFY_ATTEST_SEED_BYTES],
                            uint8_t **out, size_t *out_len, const char **why)
{
    uint8_t *buf = NULL;
    size_t body_len = 0, msg_len = 0;
    uint8_t pub[VA_PUB], secret[ZCL_VERIFY_ATTEST_SEED_BYTES], sig[VA_SIG];
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!seed || !out || !out_len) {
        va_why(why, ZCL_VERIFY_ATTEST_WHY_ARGUMENTS);
        return false;
    }
    if (!va_body_alloc(record, VA_TRAILER, &buf, &body_len, why))
        return false;
    uint8_t *msg = va_sign_message(buf, body_len, &msg_len);
    if (!msg) {
        free(buf);
        va_why(why, ZCL_VERIFY_ATTEST_WHY_NO_MEMORY);
        return false;
    }
    ed25519_keypair(pub, secret, seed);
    memory_cleanse(secret, sizeof(secret));
    ed25519_sign(sig, msg, msg_len, seed, pub);
    free(msg);
    va_put_trailer(buf + body_len, pub, sig);
    *out = buf;
    *out_len = body_len + VA_TRAILER;
    return true;
}

/* ── Strict parse ───────────────────────────────────────────────────────── */

/* The retired v1 layout, parsed only so a well-formed v1 record is refused
 * by name instead of as noise. */
static void va_take_text(struct zcl_codec_reader *c,
                         struct zcl_verify_attest_text *out, size_t min,
                         size_t max)
{
    const uint8_t *len_bytes = zcl_codec_take(c, 4u);
    if (!len_bytes)
        return;
    size_t n = zcl_read_u32_le(len_bytes);
    if (n < min || n > max) {
        c->error = ZCL_CODEC_INVALID;
        return;
    }
    const uint8_t *text = zcl_codec_take(c, n);
    if (!text || (n && memchr(text, 0, n))) {
        c->error = ZCL_CODEC_INVALID;
        return;
    }
    out->bytes = (const char *)text;
    out->len = n;
}

static void va_take_hash(struct zcl_codec_reader *c, uint8_t out[VA_HASH])
{
    const uint8_t *hash = zcl_codec_take(c, VA_HASH);
    if (hash)
        memcpy(out, hash, VA_HASH);
}

static void va_take_v1_fields(struct zcl_codec_reader *c,
                              struct zcl_verify_attest_record *r)
{
    va_take_text(c, &r->toolchain_id, 1u, ZCL_VERIFY_ATTEST_TOOLCHAIN_MAX);
    va_take_text(c, &r->argv_norm, 1u, ZCL_VERIFY_ATTEST_ARGV_MAX);
    va_take_text(c, &r->recorded_cwd, 0u, ZCL_VERIFY_ATTEST_CWD_MAX);
    va_take_hash(c, r->pp_sha3);
    va_take_hash(c, r->closure_sha3);
    va_take_hash(c, r->obj_sha3);
    va_take_hash(c, r->dep_sha3);
    va_take_hash(c, r->stderr_sha3);
    const uint8_t *exit_bytes = zcl_codec_take(c, 4u);
    if (exit_bytes)
        r->exit_code = zcl_read_i32_le(exit_bytes);
}

static bool va_is_v1(const uint8_t *bytes, size_t len)
{
    return len >= 2u + VA_V1_SCHEMA_LEN &&
           zcl_read_u16_le(bytes) == VA_V1_SCHEMA_LEN &&
           memcmp(bytes + 2, ZCL_VERIFY_ATTEST_SCHEMA_V1, VA_V1_SCHEMA_LEN) == 0;
}

static const char *va_parse_v1(const uint8_t *bytes, size_t len,
                               struct zcl_verify_attest_signed *out)
{
    struct zcl_codec_reader c;
    zcl_codec_reader_init(&c, bytes, len);
    (void)zcl_codec_take(&c, 2u + VA_V1_SCHEMA_LEN);
    va_take_v1_fields(&c, &out->record);
    out->body_len = c.position;
    const uint8_t *trailer = zcl_codec_take(&c, VA_V1_TRAILER);
    if (c.error != ZCL_CODEC_OK || c.position != len)
        return ZCL_VERIFY_ATTEST_WHY_MALFORMED;
    memcpy(out->signer_pubkey, trailer, VA_PUB);
    memcpy(out->signature, trailer + VA_PUB, VA_SIG);
    out->record.schema_version = 1u;
    return NULL;
}

/* Contract framing refusals, renamed for the record: an unknown or
 * differently framed schema is attest_schema_unknown, every other framing
 * fault is attest_record_malformed. */
static const char *va_frame_refusal(const char *why)
{
    static const char *const schema[] = {
        ZCL_FR_WHY_VERSION_UNKNOWN, ZCL_FR_WHY_WRONG_ARTIFACT,
        ZCL_FR_WHY_DOMAIN_MALFORMED, ZCL_FR_WHY_V1_RETIRED,
    };
    for (size_t i = 0; i < sizeof(schema) / sizeof(schema[0]); i++)
        if (strcmp(why, schema[i]) == 0)
            return ZCL_VERIFY_ATTEST_WHY_SCHEMA_UNKNOWN;
    return ZCL_VERIFY_ATTEST_WHY_MALFORMED;
}

static void va_take_body(const struct zcl_fr_value *v,
                         struct zcl_verify_attest_record *r)
{
    struct zcl_verify_attest_text *texts[] = {
        &r->binding.contract, &r->toolchain_id, &r->argv_norm,
        &r->recorded_cwd, &r->binding.target};
    for (size_t i = 0; i < sizeof(texts) / sizeof(texts[0]); i++)
        *texts[i] = (struct zcl_verify_attest_text){
            (const char *)v[i].bytes, v[i].len};
    uint8_t *hashes[] = {
        r->pp_sha3, r->closure_sha3, r->binding.profile_sha3,
        r->binding.receipt_sha3, r->obj_sha3, r->dep_sha3, r->stderr_sha3};
    for (size_t i = 0; i < sizeof(hashes) / sizeof(hashes[0]); i++)
        memcpy(hashes[i], v[5u + i].bytes, VA_HASH);
    r->exit_code = (int32_t)(int64_t)v[12].u64;
    r->schema_version = 2u;
}

static const char *va_parse_v2(const uint8_t *bytes, size_t len,
                               struct zcl_verify_attest_signed *out)
{
    struct zcl_fr_value body[VA_BODY_FIELDS], trailer[VA_TRAILER_FIELDS];
    size_t used = 0;
    const char *why = zcl_fr_decode_prefix(bytes, len, ZCL_VERIFY_ATTEST_SCHEMA,
                                           k_va_body_spec, VA_BODY_FIELDS,
                                           body, &used);
    if (why)
        return va_frame_refusal(why);
    int64_t exit_code = (int64_t)body[12].u64;
    if (exit_code < INT32_MIN || exit_code > INT32_MAX ||
        body[0].len == 0 || body[1].len == 0 || body[2].len == 0)
        return ZCL_VERIFY_ATTEST_WHY_MALFORMED;
    out->body_len = used;
    va_take_body(body, &out->record);
    size_t trailer_used = 0;
    why = zcl_fr_decode_fields(bytes + used, len - used, k_va_trailer_spec,
                               VA_TRAILER_FIELDS, trailer, &trailer_used);
    if (why || used + trailer_used != len)
        return ZCL_VERIFY_ATTEST_WHY_MALFORMED;
    memcpy(out->signer_pubkey, trailer[0].bytes, VA_PUB);
    memcpy(out->signature, trailer[1].bytes, VA_SIG);
    return NULL;
}

bool zcl_verify_attest_parse(const uint8_t *bytes, size_t len,
                             struct zcl_verify_attest_signed *out,
                             const char **why)
{
    va_why(why, NULL);
    if (!out || (!bytes && len)) {
        va_why(why, ZCL_VERIFY_ATTEST_WHY_ARGUMENTS);
        return false;
    }
    memset(out, 0, sizeof(*out));
    const char *refusal = NULL;
    if (len < 8u)
        refusal = ZCL_VERIFY_ATTEST_WHY_MALFORMED;
    else if (va_is_v1(bytes, len))
        refusal = va_parse_v1(bytes, len, out);
    else
        refusal = va_parse_v2(bytes, len, out);
    if (refusal) {
        memset(out, 0, sizeof(*out));
        va_why(why, refusal);
        return false;
    }
    return true;
}

/* ── Store key ──────────────────────────────────────────────────────────── */

static void va_key_text(struct zcl_fr_writer *w, const char *label,
                        const struct zcl_verify_attest_text *t)
{
    size_t len = t && t->bytes ? t->len : 0u;
    zcl_fr_put(w, label, strlen(label));
    zcl_fr_put(w, len ? t->bytes : "", len);
}

void zcl_verify_attest_store_key(
    const struct zcl_verify_attest_text *toolchain_id,
    const struct zcl_verify_attest_text *argv_norm,
    const struct zcl_verify_attest_text *recorded_cwd,
    const uint8_t pp_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES],
    const uint8_t closure_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES],
    uint8_t out[ZCL_VERIFY_ATTEST_HASH_BYTES])
{
    static const uint8_t zero[VA_HASH] = {0};
    struct sha3_256_ctx ctx;
    struct zcl_fr_writer w;
    sha3_256_init(&ctx);
    zcl_fr_writer_hash(&w, &ctx);
    zcl_fr_put(&w, VA_STORE_DOMAIN, sizeof(VA_STORE_DOMAIN) - 1u);
    va_key_text(&w, "toolchain_id", toolchain_id);
    va_key_text(&w, "argv_norm", argv_norm);
    va_key_text(&w, "recorded_cwd", recorded_cwd);
    zcl_fr_put_hash(&w, "pp_sha3", pp_sha3 ? pp_sha3 : zero);
    zcl_fr_put_hash(&w, "closure_sha3", closure_sha3 ? closure_sha3 : zero);
    sha3_256_finalize(&ctx, out);
}

void zcl_verify_attest_store_key_hex(
    const struct zcl_verify_attest_text *toolchain_id,
    const struct zcl_verify_attest_text *argv_norm,
    const struct zcl_verify_attest_text *recorded_cwd,
    const uint8_t pp_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES],
    const uint8_t closure_sha3[ZCL_VERIFY_ATTEST_HASH_BYTES],
    char out[ZCL_VERIFY_ATTEST_STORE_KEY_HEX])
{
    uint8_t key[VA_HASH];
    zcl_verify_attest_store_key(toolchain_id, argv_norm, recorded_cwd,
                                pp_sha3, closure_sha3, key);
    zcl_hex_encode(key, sizeof(key), out);
}

/* ── Trust root: pure policy ────────────────────────────────────────────── */

static bool va_owner_ok(uint32_t uid,
                        const struct zcl_verify_attest_path_policy *policy)
{
    return uid == 0u || uid == policy->trusted_uid;
}

static const char *va_file_entry_check(
    const struct zcl_verify_attest_path_entry *e,
    const struct zcl_verify_attest_path_policy *policy)
{
    if (!e->is_regular)
        return ZCL_VERIFY_ATTEST_WHY_KEY_NOT_REGULAR;
    if (!va_owner_ok(e->uid, policy))
        return ZCL_VERIFY_ATTEST_WHY_KEY_NOT_ROOT_OWNED;
    if (e->mode & VA_GROUP_OR_WORLD_WRITE)
        return ZCL_VERIFY_ATTEST_WHY_KEY_WRITABLE;
    return NULL;
}

static const char *va_dir_entry_check(
    const struct zcl_verify_attest_path_entry *e,
    const struct zcl_verify_attest_path_policy *policy)
{
    if (!e->is_dir)
        return ZCL_VERIFY_ATTEST_WHY_DIR_NOT_DIRECTORY;
    if (!va_owner_ok(e->uid, policy))
        return ZCL_VERIFY_ATTEST_WHY_DIR_NOT_ROOT_OWNED;
    if ((e->mode & VA_GROUP_OR_WORLD_WRITE) == 0u)
        return NULL;
    bool sticky_root = policy->allow_sticky_root && e->uid == 0u &&
                       (e->mode & VA_STICKY) != 0u;
    return sticky_root ? NULL : ZCL_VERIFY_ATTEST_WHY_DIR_WRITABLE;
}

const char *zcl_verify_attest_path_check(
    const struct zcl_verify_attest_path_entry *entries, size_t count,
    const struct zcl_verify_attest_path_policy *policy)
{
    if (!entries || !policy || count == 0u)
        return ZCL_VERIFY_ATTEST_WHY_ARGUMENTS;
    const char *why = va_file_entry_check(&entries[0], policy);
    for (size_t i = 1; !why && i < count; i++)
        why = va_dir_entry_check(&entries[i], policy);
    return why;
}

/* Every encoding of a point in the order-1/2/4/8 torsion subgroup, with the
 * sign bit (bit 255) masked: y = 0 (order 4), y = 1 (identity), the two
 * order-8 y values, y = p - 1 (order 2), and the non-canonical y = p and
 * y = p + 1. No other 32-byte string decodes to a small-order point, so this
 * screen needs no point arithmetic; the pinned key file is not a consensus
 * input and the sealed ed25519 core exposes no point decoder. A key that is
 * not on the curve at all verifies nothing, since ed25519_verify rejects any
 * public key that fails to decompress. */
static const uint8_t k_va_small_order[7][32] = {
    {0x00},
    {0x01},
    {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4,
     0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6,
     0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
    {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b,
     0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39,
     0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
    {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
};

static bool va_small_order(const uint8_t key[VA_PUB])
{
    for (size_t i = 0; i < sizeof(k_va_small_order) / VA_PUB; i++) {
        const uint8_t *bad = k_va_small_order[i];
        if (memcmp(key, bad, VA_PUB - 1u) == 0 &&
            (key[VA_PUB - 1u] & 0x7fu) == bad[VA_PUB - 1u])
            return true;
    }
    return false;
}

bool zcl_verify_attest_pubkey_parse(
    const uint8_t *bytes, size_t len,
    uint8_t out[ZCL_VERIFY_ATTEST_PUBKEY_BYTES])
{
    char hex[2u * VA_PUB + 1u];
    memset(out, 0, VA_PUB);
    if (!bytes || (len != 2u * VA_PUB && len != 2u * VA_PUB + 1u))
        return false;
    if (len == 2u * VA_PUB + 1u && bytes[2u * VA_PUB] != '\n')
        return false;
    memcpy(hex, bytes, 2u * VA_PUB);
    hex[2u * VA_PUB] = 0;
    if (!zcl_hex_decode_lower(hex, out, VA_PUB))
        return false;
    if (va_small_order(out)) {
        memset(out, 0, VA_PUB);
        return false;
    }
    return true;
}

/* ── Trust root: loader ─────────────────────────────────────────────────── */

bool zcl_verify_attest_test_override_compiled(void)
{
#if defined(ZCL_TESTING) && !defined(_WIN32)
    return true;
#else
    return false;
#endif
}

/* One spelling per path: absolute, no empty, "." or ".." component, no
 * trailing slash. Every component is then lstat'ed exactly once. */
#if !defined(_WIN32)
static const char *va_path_shape(const char *path)
{
    size_t n = strlen(path);
    if (path[0] != '/')
        return ZCL_VERIFY_ATTEST_WHY_KEY_PATH_NOT_ABSOLUTE;
    if (n >= ZCL_VERIFY_ATTEST_PATH_MAX || path[n - 1u] == '/' ||
        strstr(path, "//") || strstr(path, "/./") || strstr(path, "/../"))
        return ZCL_VERIFY_ATTEST_WHY_KEY_PATH_NOT_CANONICAL;
    if ((n >= 2u && strcmp(path + n - 2u, "/.") == 0) ||
        (n >= 3u && strcmp(path + n - 3u, "/..") == 0))
        return ZCL_VERIFY_ATTEST_WHY_KEY_PATH_NOT_CANONICAL;
    return NULL;
}
#endif /* !defined(_WIN32) */

#if !defined(_WIN32)
static void va_entry_from_stat(const struct stat *st,
                               struct zcl_verify_attest_path_entry *e)
{
    e->uid = (uint32_t)st->st_uid;
    e->mode = (uint32_t)st->st_mode;
    e->is_regular = S_ISREG(st->st_mode);
    e->is_dir = S_ISDIR(st->st_mode);
}

/* The path the loader reads, and the owner it accepts. Production reads
 * the configured or default path and accepts root only. */
static const char *va_resolve(const char *configured,
                              struct zcl_verify_attest_path_policy *policy)
{
    policy->trusted_uid = 0u;
    policy->allow_sticky_root = false;
#if defined(ZCL_TESTING)
    const char *override = getenv("ZCL_TEST_VERIFY_ATTEST_PUBKEY");
    if (override && override[0]) {
        policy->trusted_uid = (uint32_t)geteuid();
        policy->allow_sticky_root = true;
        return override;
    }
#endif
    return configured ? configured : ZCL_VERIFY_ATTEST_DEFAULT_PUBKEY_PATH;
}

static const char *va_open_errno(int err)
{
    if (err == ENOENT)
        return ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY;
    if (err == ELOOP)
        return ZCL_VERIFY_ATTEST_WHY_KEY_NOT_REGULAR;
    return ZCL_VERIFY_ATTEST_WHY_KEY_UNREADABLE;
}

/* Open without following a final symlink, stat the open file, and read at
 * most VA_KEY_FILE_MAX bytes from it. */
static const char *va_read_key(const char *path,
                               struct zcl_verify_attest_path_entry *file,
                               uint8_t buf[VA_KEY_FILE_MAX], size_t *len)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return va_open_errno(errno);
    if (fstat(fd, &st) != 0) {
        (void)close(fd);
        return ZCL_VERIFY_ATTEST_WHY_KEY_UNREADABLE;
    }
    va_entry_from_stat(&st, file);
    if (!file->is_regular) {
        (void)close(fd);
        return ZCL_VERIFY_ATTEST_WHY_KEY_NOT_REGULAR;
    }
    ssize_t got = read(fd, buf, VA_KEY_FILE_MAX);
    (void)close(fd);
    if (got < 0)
        return ZCL_VERIFY_ATTEST_WHY_KEY_UNREADABLE;
    *len = (size_t)got;
    return NULL;
}

/* lstat every parent from the nearest to "/", so a symlinked component
 * shows up as a non-directory instead of being followed. */
static const char *va_stat_parents(const char *path,
                                   struct zcl_verify_attest_path_entry *chain,
                                   size_t *count)
{
    char dir[ZCL_VERIFY_ATTEST_PATH_MAX];
    struct stat st;
    size_t n = 1u;
    (void)snprintf(dir, sizeof(dir), "%s", path);
    for (char *slash = strrchr(dir, '/'); slash; slash = strrchr(dir, '/')) {
        if (n >= VA_CHAIN_MAX)
            return ZCL_VERIFY_ATTEST_WHY_KEY_PATH_NOT_CANONICAL;
        slash[slash == dir ? 1 : 0] = 0;
        if (lstat(dir, &st) != 0)
            return ZCL_VERIFY_ATTEST_WHY_KEY_UNREADABLE;
        va_entry_from_stat(&st, &chain[n++]);
        if (slash == dir)
            break;
    }
    *count = n;
    return NULL;
}

static const char *va_load_posix(const char *path,
                                 const struct zcl_verify_attest_path_policy *p,
                                 uint8_t pub[VA_PUB])
{
    struct zcl_verify_attest_path_entry chain[VA_CHAIN_MAX];
    uint8_t buf[VA_KEY_FILE_MAX];
    size_t len = 0, count = 0;
    memset(chain, 0, sizeof(chain));
    const char *why = va_path_shape(path);
    if (!why)
        why = va_read_key(path, &chain[0], buf, &len);
    if (!why)
        why = va_stat_parents(path, chain, &count);
    if (!why)
        why = zcl_verify_attest_path_check(chain, count, p);
    if (!why && !zcl_verify_attest_pubkey_parse(buf, len, pub))
        why = ZCL_VERIFY_ATTEST_WHY_KEY_MALFORMED;
    return why;
}
#endif

static bool va_load_refuse(struct zcl_verify_attest_trust_root *out,
                           const char *path, const char *token,
                           const char **why)
{
    memset(out, 0, sizeof(*out));
    va_why(why, token);
    if (strcmp(token, ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY) != 0)
        LOG_WARN(VA_LOG_DOMAIN, "verifier key refused: reason=%s path=%s",
                 token, path ? path : "(none)");
    return false;
}

bool zcl_verify_attest_trust_root_load(
    const char *configured_path, const struct zcl_verify_attest_box_key *box,
    struct zcl_verify_attest_trust_root *out, const char **why)
{
    va_why(why, NULL);
    if (!out) {
        va_why(why, ZCL_VERIFY_ATTEST_WHY_ARGUMENTS);
        return false;
    }
    memset(out, 0, sizeof(*out));
    if (!box || !box->known)
        return va_load_refuse(out, configured_path,
                              ZCL_VERIFY_ATTEST_WHY_BOX_KEY_UNKNOWN, why);
#if defined(_WIN32)
    return va_load_refuse(out, configured_path,
                          ZCL_VERIFY_ATTEST_WHY_PLATFORM, why);
#else
    struct zcl_verify_attest_path_policy policy;
    const char *path = va_resolve(configured_path, &policy);
    uint8_t pub[VA_PUB];
    const char *refusal = va_load_posix(path, &policy, pub);
    if (!refusal && box->present && memcmp(pub, box->pubkey, VA_PUB) == 0)
        refusal = ZCL_VERIFY_ATTEST_WHY_KEY_IS_BOX_SIGNER;
    if (refusal)
        return va_load_refuse(out, path, refusal, why);
    memcpy(out->verifier_pubkey, pub, VA_PUB);
    out->box = *box;
    out->loaded = true;
    return true;
#endif
}

/* ── Admission ──────────────────────────────────────────────────────────── */

static struct zcl_verify_attest_decision va_decide(const char *refusal)
{
    struct zcl_verify_attest_decision d = {
        refusal ? ZCL_VERIFY_ATTEST_REFUSE : ZCL_VERIFY_ATTEST_ADMIT,
        refusal};
    return d;
}

static struct zcl_verify_attest_decision va_signed_failure(void)
{
    struct zcl_verify_attest_decision d = {
        ZCL_VERIFY_ATTEST_FAIL, ZCL_VERIFY_ATTEST_WHY_EXIT_NONZERO};
    return d;
}

static struct zcl_verify_attest_decision va_signed_conflict(void)
{
    struct zcl_verify_attest_decision d = {
        ZCL_VERIFY_ATTEST_FAIL, ZCL_VERIFY_ATTEST_WHY_ELIGIBLE_CONFLICT};
    return d;
}

static const char *va_root_check(const struct zcl_verify_attest_trust_root *r)
{
    if (!r || !r->loaded)
        return ZCL_VERIFY_ATTEST_WHY_NO_VERIFIER_KEY;
    if (!r->box.known)
        return ZCL_VERIFY_ATTEST_WHY_BOX_KEY_UNKNOWN;
    if (r->box.present &&
        memcmp(r->verifier_pubkey, r->box.pubkey, VA_PUB) == 0)
        return ZCL_VERIFY_ATTEST_WHY_KEY_IS_BOX_SIGNER;
    return NULL;
}

static bool va_box_signed(const struct zcl_verify_attest_signed *s,
                          const uint8_t *msg, size_t msg_len,
                          const struct zcl_verify_attest_trust_root *root)
{
    return root->box.present &&
           ed25519_verify(s->signature, msg, msg_len, root->box.pubkey);
}

/* Name the box signer whenever its key made the signature, whichever key
 * the trailer claims; otherwise only the pinned verifier's key admits. */
static const char *va_signer_verdict(
    const struct zcl_verify_attest_signed *s, const uint8_t *msg,
    size_t msg_len, const struct zcl_verify_attest_trust_root *root)
{
    if (root->box.present &&
        memcmp(s->signer_pubkey, root->box.pubkey, VA_PUB) == 0)
        return ZCL_VERIFY_ATTEST_WHY_SIGNED_BY_BOX;
    bool claims_verifier =
        memcmp(s->signer_pubkey, root->verifier_pubkey, VA_PUB) == 0;
    if (claims_verifier &&
        ed25519_verify(s->signature, msg, msg_len, root->verifier_pubkey))
        return NULL;
    if (va_box_signed(s, msg, msg_len, root))
        return ZCL_VERIFY_ATTEST_WHY_SIGNED_BY_BOX;
    return claims_verifier ? ZCL_VERIFY_ATTEST_WHY_SIGNATURE_INVALID
                           : ZCL_VERIFY_ATTEST_WHY_SIGNER_NOT_VERIFIER;
}

static const char *va_signer_check(
    const uint8_t *record_bytes, const struct zcl_verify_attest_signed *s,
    const struct zcl_verify_attest_trust_root *root)
{
    size_t msg_len = 0;
    uint8_t *msg = va_sign_message(record_bytes, s->body_len, &msg_len);
    if (!msg)
        return ZCL_VERIFY_ATTEST_WHY_NO_MEMORY;
    const char *why = va_signer_verdict(s, msg, msg_len, root);
    free(msg);
    return why;
}

static bool va_text_eq(const struct zcl_verify_attest_text *a,
                       const struct zcl_verify_attest_text *b)
{
    return a->len == b->len &&
           (a->len == 0u || (a->bytes && b->bytes &&
                             memcmp(a->bytes, b->bytes, a->len) == 0));
}

static const char *va_input_check(
    const struct zcl_verify_attest_record *r,
    const struct zcl_verify_attest_expected *e)
{
    if (!va_text_eq(&r->toolchain_id, &e->toolchain_id))
        return ZCL_VERIFY_ATTEST_WHY_TOOLCHAIN_MISMATCH;
    if (!va_text_eq(&r->argv_norm, &e->argv_norm))
        return ZCL_VERIFY_ATTEST_WHY_ARGV_MISMATCH;
    if (r->recorded_cwd.len == 0u || e->recorded_cwd.len == 0u)
        return ZCL_VERIFY_ATTEST_WHY_CWD_MISSING;
    if (!va_text_eq(&r->recorded_cwd, &e->recorded_cwd))
        return ZCL_VERIFY_ATTEST_WHY_CWD_MISMATCH;
    if (memcmp(r->pp_sha3, e->pp_sha3, VA_HASH) != 0)
        return ZCL_VERIFY_ATTEST_WHY_PP_MISMATCH;
    static const uint8_t zero[VA_HASH] = {0};
    if (memcmp(r->closure_sha3, zero, VA_HASH) == 0 ||
        memcmp(e->closure_sha3, zero, VA_HASH) == 0)
        return ZCL_VERIFY_ATTEST_WHY_CLOSURE_MISSING;
    if (memcmp(r->closure_sha3, e->closure_sha3, VA_HASH) != 0)
        return ZCL_VERIFY_ATTEST_WHY_CLOSURE_MISMATCH;
    return NULL;
}

static const char *va_object_check(const struct zcl_verify_attest_record *r,
                                   const uint8_t *obj, size_t obj_len)
{
    uint8_t obj_hash[VA_HASH];
    if (obj_len == 0u)
        return ZCL_VERIFY_ATTEST_WHY_OBJ_EMPTY;
    zcl_sha3_256(obj, obj_len, obj_hash);
    if (memcmp(obj_hash, r->obj_sha3, VA_HASH) != 0)
        return ZCL_VERIFY_ATTEST_WHY_OBJ_MISMATCH;
    return NULL;
}

static const char *va_artifacts_check(const struct zcl_verify_attest_record *r,
                                      const uint8_t *obj, size_t obj_len,
                                      const uint8_t *dep, size_t dep_len,
                                      const uint8_t *stderr_bytes,
                                      size_t stderr_len)
{
    const char *why = NULL;
    uint8_t hash[VA_HASH];
    if ((!obj && obj_len) || (!dep && dep_len) ||
        (!stderr_bytes && stderr_len))
        return ZCL_VERIFY_ATTEST_WHY_ARGUMENTS;
    why = va_object_check(r, obj, obj_len);
    if (why)
        return why;
    if (dep_len == 0u)
        return ZCL_VERIFY_ATTEST_WHY_DEP_EMPTY;
    zcl_sha3_256(dep, dep_len, hash);
    if (memcmp(hash, r->dep_sha3, VA_HASH) != 0)
        return ZCL_VERIFY_ATTEST_WHY_DEP_MISMATCH;
    zcl_sha3_256(stderr_bytes, stderr_len, hash);
    if (memcmp(hash, r->stderr_sha3, VA_HASH) != 0)
        return ZCL_VERIFY_ATTEST_WHY_STDERR_MISMATCH;
    return NULL;
}

static bool va_zero_hash(const uint8_t h[VA_HASH])
{
    static const uint8_t zero[VA_HASH] = {0};
    return memcmp(h, zero, VA_HASH) == 0;
}

/* The record must repeat the receiver's own receipt expectation exactly;
 * an empty or zero expectation is never a wildcard. */
static const char *va_binding_check(const struct zcl_verify_attest_binding *have,
                                    const struct zcl_verify_attest_binding *want)
{
    if (!want)
        return ZCL_VERIFY_ATTEST_WHY_BINDING_MISSING;
    if (want->contract.len == 0 ||
        !va_text_eq(&have->contract, &want->contract))
        return ZCL_VERIFY_ATTEST_WHY_CONTRACT_MISMATCH;
    if (va_zero_hash(want->profile_sha3) ||
        memcmp(have->profile_sha3, want->profile_sha3, VA_HASH) != 0)
        return ZCL_VERIFY_ATTEST_WHY_PROFILE_MISMATCH;
    if (want->target.len == 0 || !va_text_eq(&have->target, &want->target))
        return ZCL_VERIFY_ATTEST_WHY_TARGET_MISMATCH;
    if (va_zero_hash(want->receipt_sha3) ||
        memcmp(have->receipt_sha3, want->receipt_sha3, VA_HASH) != 0)
        return ZCL_VERIFY_ATTEST_WHY_RECEIPT_MISMATCH;
    return NULL;
}

/* Everything a record must satisfy before its exit code means anything:
 * the current schema, the pinned verifier's signature, and the exact
 * expected inputs. */
static const char *va_signed_inputs(
    const uint8_t *record_bytes, const struct zcl_verify_attest_signed *s,
    const struct zcl_verify_attest_expected *expected,
    const struct zcl_verify_attest_trust_root *root)
{
    if (s->record.schema_version != 2u)
        return ZCL_VERIFY_ATTEST_WHY_RECORD_V1_UNBOUND;
    const char *why = va_signer_check(record_bytes, s, root);
    return why ? why : va_input_check(&s->record, expected);
}

struct zcl_verify_attest_decision zcl_verify_attest_admit(
    const uint8_t *record_bytes, size_t record_len,
    const uint8_t *obj_bytes, size_t obj_len,
    const uint8_t *dep_bytes, size_t dep_len,
    const uint8_t *stderr_bytes, size_t stderr_len,
    const struct zcl_verify_attest_binding *binding,
    const struct zcl_verify_attest_expected *expected,
    const struct zcl_verify_attest_trust_root *trust_root)
{
    struct zcl_verify_attest_signed parsed;
    const char *why = NULL;
    if (!expected || (!record_bytes && record_len))
        return va_decide(ZCL_VERIFY_ATTEST_WHY_ARGUMENTS);
    why = va_root_check(trust_root);
    if (why)
        return va_decide(why);
    if (!zcl_verify_attest_parse(record_bytes, record_len, &parsed, &why))
        return va_decide(why);
    why = va_signed_inputs(record_bytes, &parsed, expected, trust_root);
    if (!why && parsed.record.exit_code != 0)
        return va_signed_failure();
    if (!why)
        why = va_binding_check(&parsed.record.binding, binding);
    if (!why)
        why = va_artifacts_check(&parsed.record, obj_bytes, obj_len,
                                 dep_bytes, dep_len, stderr_bytes, stderr_len);
    return va_decide(why);
}

struct va_set_state {
    const char *first_refusal;
    size_t pass_index;
    uint8_t obj_sha3[VA_HASH];
    uint8_t dep_sha3[VA_HASH];
    uint8_t stderr_sha3[VA_HASH];
    bool saw_pass;
    bool saw_fail;
    bool pass_conflict;
    bool have_pass_hash;
};

static void va_set_refuse(struct va_set_state *s, const char *why)
{
    if (!s->first_refusal)
        s->first_refusal = why;
}

static void va_set_inspect(const struct zcl_verify_attest_observation *all,
                           size_t i,
                           const struct zcl_verify_attest_expected *expected,
                           const struct zcl_verify_attest_trust_root *root,
                           struct va_set_state *state)
{
    const struct zcl_verify_attest_observation *o = &all[i];
    struct zcl_verify_attest_signed parsed;
    const char *why = NULL;
    if (!zcl_verify_attest_parse(o->record_bytes, o->record_len,
                                 &parsed, &why)) {
        va_set_refuse(state, why);
        return;
    }
    why = va_signed_inputs(o->record_bytes, &parsed, expected, root);
    if (why) {
        va_set_refuse(state, why);
        return;
    }
    if (parsed.record.exit_code != 0) {
        state->saw_fail = true;
        return;
    }
    state->saw_pass = true;
    if (!state->have_pass_hash) {
        memcpy(state->obj_sha3, parsed.record.obj_sha3, VA_HASH);
        memcpy(state->dep_sha3, parsed.record.dep_sha3, VA_HASH);
        memcpy(state->stderr_sha3, parsed.record.stderr_sha3, VA_HASH);
        state->have_pass_hash = true;
    } else if (memcmp(state->obj_sha3, parsed.record.obj_sha3, VA_HASH) ||
               memcmp(state->dep_sha3, parsed.record.dep_sha3, VA_HASH) ||
               memcmp(state->stderr_sha3, parsed.record.stderr_sha3,
                      VA_HASH)) {
        state->pass_conflict = true;
    }
    struct zcl_verify_attest_decision d = zcl_verify_attest_admit(
        o->record_bytes, o->record_len, o->obj_bytes, o->obj_len,
        o->dep_bytes, o->dep_len, o->stderr_bytes, o->stderr_len,
        o->binding, expected, root);
    if (d.verdict != ZCL_VERIFY_ATTEST_ADMIT) {
        va_set_refuse(state, d.reason);
        return;
    }
    if (state->pass_index == SIZE_MAX)
        state->pass_index = i;
}

struct zcl_verify_attest_decision zcl_verify_attest_admit_set(
    const struct zcl_verify_attest_observation *observations, size_t count,
    const struct zcl_verify_attest_expected *expected,
    const struct zcl_verify_attest_trust_root *trust_root,
    size_t *selected_index)
{
    struct va_set_state state = {.pass_index = SIZE_MAX};
    if (selected_index)
        *selected_index = SIZE_MAX;
    if (!expected || (!observations && count != 0u))
        return va_decide(ZCL_VERIFY_ATTEST_WHY_ARGUMENTS);
    const char *root_why = va_root_check(trust_root);
    if (root_why)
        return va_decide(root_why);
    if (count == 0u)
        return va_decide(ZCL_VERIFY_ATTEST_WHY_NO_OBSERVATION);

    for (size_t i = 0; i < count; ++i)
        va_set_inspect(observations, i, expected, trust_root, &state);
    if ((state.saw_pass && state.saw_fail) || state.pass_conflict)
        return va_signed_conflict();
    if (state.saw_fail)
        return va_signed_failure();
    if (state.first_refusal)
        return va_decide(state.first_refusal);
    if (state.pass_index == SIZE_MAX)
        return va_decide(ZCL_VERIFY_ATTEST_WHY_NO_OBSERVATION);
    if (selected_index)
        *selected_index = state.pass_index;
    return va_decide(NULL);
}
