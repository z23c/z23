/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical zcl.component_proof_key.v1 preimages and signed
 *          zcl.proof_ticket.v1 observations, with their CAS placement. */

#include "vcs/proof_ticket.h"

#include "vcs/blob_store.h"

#include "base/log_macros.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <string.h>

#define PT_LOG "vcs.proof_ticket"

#define CPK_MAGIC "Z23CPK1\0"
#define CPK_VERSION 1u
#define CPK_KEY_DOMAIN "zcl.component_proof_key.v1"
#define CPK_FIELD_DOMAIN "zcl.component_proof_key.field.v1"
#define CPK_ENV_DOMAIN "zcl.component_proof_key.environment.v1"

#define PTK_MAGIC "Z23PTK1\0"
#define PTK_VERSION 1u
#define PTK_SIGN_DOMAIN "zcl.proof_ticket.v1"
#define PTK_ROOT_DOMAIN "zcl.proof_ticket_root.v1"
#define PTK_SIGN_MESSAGE_BYTES \
    ((sizeof(PTK_SIGN_DOMAIN) - 1u) + VCS_PROOF_TICKET_SIGNED_BYTES)

static const char *const cpk_field_names[VCS_CPK_FIELD_COUNT] = {
    "kind", "unit_id", "source_closure", "dependency_closure", "toolchain",
    "target", "flags", "environment", "abi_generation", "build_graph",
    "harness", "fixtures", "invariants", "integration_edges", "policy",
};

static bool pt_nonzero(const uint8_t *bytes, size_t len)
{
    uint8_t any = 0;
    for (size_t i = 0; i < len; i++) any |= bytes[i];
    return any != 0;
}

static void pt_sha3_domain(struct sha3_256_ctx *sha, const char *domain)
{
    sha3_256_init(sha);
    sha3_256_write(sha, (const uint8_t *)domain, strlen(domain));
}

static void pt_sha3_u16(struct sha3_256_ctx *sha, uint16_t v)
{
    uint8_t b[2];
    zcl_write_u16_le(b, v);
    sha3_256_write(sha, b, sizeof(b));
}

static void pt_sha3_u32(struct sha3_256_ctx *sha, uint32_t v)
{
    uint8_t b[4];
    zcl_write_u32_le(b, v);
    sha3_256_write(sha, b, sizeof(b));
}

static void pt_sha3_u64(struct sha3_256_ctx *sha, uint64_t v)
{
    uint8_t b[8];
    zcl_write_u64_le(b, v);
    sha3_256_write(sha, b, sizeof(b));
}

/* ── zcl.component_proof_key.v1 ─────────────────────────────────────── */

const char *vcs_component_proof_field_name(enum vcs_component_proof_field f)
{
    if ((unsigned)f >= VCS_CPK_FIELD_COUNT) return NULL;
    return cpk_field_names[f];
}

bool vcs_component_proof_field_root(enum vcs_component_proof_field field,
                                    const void *bytes, size_t len,
                                    uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    if (!out || (unsigned)field >= VCS_CPK_FIELD_COUNT || (!bytes && len))
        LOG_RETURN(false, PT_LOG, "field root arguments invalid (field=%u)",
                   (unsigned)field);
    struct sha3_256_ctx sha;
    pt_sha3_domain(&sha, CPK_FIELD_DOMAIN);
    pt_sha3_u16(&sha, (uint16_t)field);
    pt_sha3_u64(&sha, (uint64_t)len);
    if (len) sha3_256_write(&sha, (const uint8_t *)bytes, len);
    sha3_256_finalize(&sha, out);
    return true;
}

static bool cpk_env_name_valid(const char *name)
{
    if (!name || !name[0]) return false;
    for (const char *p = name; *p; p++) {
        bool ok = (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') ||
                  *p == '_';
        if (!ok) return false;
    }
    return true;
}

static bool cpk_env_canonical(const struct vcs_component_proof_env *env,
                              size_t count)
{
    for (size_t i = 0; i < count; i++) {
        if (!cpk_env_name_valid(env[i].name)) return false;
        if (i > 0 && strcmp(env[i - 1].name, env[i].name) >= 0) return false;
    }
    return true;
}

bool vcs_component_proof_environment_root(
    const struct vcs_component_proof_env *env, size_t count,
    uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    if (!out || (!env && count))
        LOG_RETURN(false, PT_LOG, "environment root arguments invalid");
    if (!cpk_env_canonical(env, count))
        LOG_RETURN(false, PT_LOG,
                   "environment allowlist not canonical (%zu names): names "
                   "must be [A-Z0-9_]+, strictly ascending, unique", count);
    struct sha3_256_ctx sha;
    pt_sha3_domain(&sha, CPK_ENV_DOMAIN);
    pt_sha3_u64(&sha, (uint64_t)count);
    for (size_t i = 0; i < count; i++) {
        size_t name_len = strlen(env[i].name);
        pt_sha3_u64(&sha, (uint64_t)name_len);
        sha3_256_write(&sha, (const uint8_t *)env[i].name, name_len);
        uint8_t present = env[i].value ? 1u : 0u;
        sha3_256_write(&sha, &present, 1);
        if (!present) continue;
        size_t value_len = strlen(env[i].value);
        pt_sha3_u64(&sha, (uint64_t)value_len);
        sha3_256_write(&sha, (const uint8_t *)env[i].value, value_len);
    }
    uint8_t digest[VCS_PROOF_ROOT_BYTES];
    sha3_256_finalize(&sha, digest);
    /* Bind the environment through the field-root domain like every other
     * field, so a raw environment digest never collides with a text root. */
    return vcs_component_proof_field_root(VCS_CPK_ENVIRONMENT, digest,
                                          sizeof(digest), out);
}

bool vcs_component_proof_key_valid(const struct vcs_component_proof_key_v1 *k)
{
    if (!k) return false;
    for (size_t f = 0; f < VCS_CPK_FIELD_COUNT; f++)
        if (!pt_nonzero(k->roots[f], VCS_PROOF_ROOT_BYTES)) return false;
    return true;
}

bool vcs_component_proof_key_encode(const struct vcs_component_proof_key_v1 *k,
                                    uint8_t out[VCS_CPK_WIRE_BYTES])
{
    if (!out || !vcs_component_proof_key_valid(k))
        LOG_RETURN(false, PT_LOG, "component proof key has a zero root");
    memcpy(out, CPK_MAGIC, 8);
    zcl_write_u32_le(out + 8, CPK_VERSION);
    zcl_write_u32_le(out + 12, VCS_CPK_FIELD_COUNT);
    for (size_t f = 0; f < VCS_CPK_FIELD_COUNT; f++)
        memcpy(out + 16 + f * VCS_PROOF_ROOT_BYTES, k->roots[f],
               VCS_PROOF_ROOT_BYTES);
    return true;
}

bool vcs_component_proof_key_decode(const uint8_t *wire, size_t len,
                                    struct vcs_component_proof_key_v1 *out)
{
    if (!out || !wire)
        LOG_RETURN(false, PT_LOG, "component proof key decode: null input");
    memset(out, 0, sizeof(*out));
    if (len != VCS_CPK_WIRE_BYTES)
        LOG_RETURN(false, PT_LOG, "component proof key: %zu bytes, want %u",
                   len, VCS_CPK_WIRE_BYTES);
    if (memcmp(wire, CPK_MAGIC, 8) != 0 ||
        zcl_read_u32_le(wire + 8) != CPK_VERSION ||
        zcl_read_u32_le(wire + 12) != VCS_CPK_FIELD_COUNT)
        LOG_RETURN(false, PT_LOG, "component proof key: unknown schema");
    struct vcs_component_proof_key_v1 parsed;
    for (size_t f = 0; f < VCS_CPK_FIELD_COUNT; f++)
        memcpy(parsed.roots[f], wire + 16 + f * VCS_PROOF_ROOT_BYTES,
               VCS_PROOF_ROOT_BYTES);
    if (!vcs_component_proof_key_valid(&parsed))
        LOG_RETURN(false, PT_LOG, "component proof key: zero root");
    *out = parsed;
    return true;
}

bool vcs_component_proof_key_derive(const struct vcs_component_proof_key_v1 *k,
                                    uint8_t input_key[VCS_PROOF_ROOT_BYTES])
{
    if (!input_key || !vcs_component_proof_key_valid(k))
        LOG_RETURN(false, PT_LOG, "cannot derive input key: invalid preimage");
    struct sha3_256_ctx sha;
    pt_sha3_domain(&sha, CPK_KEY_DOMAIN);
    for (size_t f = 0; f < VCS_CPK_FIELD_COUNT; f++) {
        pt_sha3_u16(&sha, (uint16_t)f);
        pt_sha3_u32(&sha, VCS_PROOF_ROOT_BYTES);
        sha3_256_write(&sha, k->roots[f], VCS_PROOF_ROOT_BYTES);
    }
    sha3_256_finalize(&sha, input_key);
    return true;
}

bool vcs_component_proof_key_preimage_root(
    const struct vcs_component_proof_key_v1 *k,
    uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    uint8_t wire[VCS_CPK_WIRE_BYTES];
    if (!out || !vcs_component_proof_key_encode(k, wire))
        LOG_RETURN(false, PT_LOG, "cannot root an invalid preimage");
    if (!vcs_blob_root(wire, sizeof(wire), out))
        LOG_RETURN(false, PT_LOG, "preimage blob root failed");
    return true;
}

uint32_t vcs_component_proof_key_diff(const struct vcs_component_proof_key_v1 *a,
                                      const struct vcs_component_proof_key_v1 *b)
{
    if (!a || !b) return (1u << VCS_CPK_FIELD_COUNT) - 1u;
    uint32_t mask = 0;
    for (size_t f = 0; f < VCS_CPK_FIELD_COUNT; f++)
        if (memcmp(a->roots[f], b->roots[f], VCS_PROOF_ROOT_BYTES) != 0)
            mask |= 1u << f;
    return mask;
}

/* ── zcl.proof_ticket.v1 ────────────────────────────────────────────── */

static bool ptk_counts_valid(const struct vcs_proof_ticket_v1 *t)
{
    if (t->checks_run == 0 || t->checks_passed > t->checks_run) return false;
    if (t->verdict == VCS_PROOF_VERDICT_PASS)
        return t->checks_passed == t->checks_run;
    return t->checks_passed < t->checks_run;
}

bool vcs_proof_ticket_body_valid(const struct vcs_proof_ticket_v1 *t)
{
    if (!t) return false;
    if (t->verdict != VCS_PROOF_VERDICT_PASS &&
        t->verdict != VCS_PROOF_VERDICT_FAIL)
        return false;
    return ptk_counts_valid(t) && t->created_unix != 0 &&
           pt_nonzero(t->input_key, VCS_PROOF_ROOT_BYTES) &&
           pt_nonzero(t->key_preimage_root, VCS_PROOF_ROOT_BYTES) &&
           pt_nonzero(t->evidence_root, VCS_PROOF_ROOT_BYTES) &&
           pt_nonzero(t->producer_pubkey, VCS_PROOF_PUBKEY_BYTES);
}

/* Bytes [0,192): everything the signature covers. */
static void ptk_put_signed(const struct vcs_proof_ticket_v1 *t, uint8_t *out)
{
    memcpy(out, PTK_MAGIC, 8);
    zcl_write_u32_le(out + 8, PTK_VERSION);
    out[12] = (uint8_t)t->verdict;
    out[13] = t->reproduced ? 1u : 0u;
    out[14] = 0;
    out[15] = 0;
    memcpy(out + 16, t->input_key, VCS_PROOF_ROOT_BYTES);
    memcpy(out + 48, t->key_preimage_root, VCS_PROOF_ROOT_BYTES);
    memcpy(out + 80, t->evidence_root, VCS_PROOF_ROOT_BYTES);
    zcl_write_u32_le(out + 112, t->checks_run);
    zcl_write_u32_le(out + 116, t->checks_passed);
    zcl_write_u64_le(out + 120, t->cpu_us);
    zcl_write_u64_le(out + 128, t->wall_us);
    zcl_write_u64_le(out + 136, t->bytes_in);
    zcl_write_u64_le(out + 144, t->bytes_out);
    zcl_write_u64_le(out + 152, t->created_unix);
    memcpy(out + 160, t->producer_pubkey, VCS_PROOF_PUBKEY_BYTES);
}

static void ptk_message(const struct vcs_proof_ticket_v1 *t,
                        uint8_t out[PTK_SIGN_MESSAGE_BYTES])
{
    memcpy(out, PTK_SIGN_DOMAIN, sizeof(PTK_SIGN_DOMAIN) - 1u);
    ptk_put_signed(t, out + sizeof(PTK_SIGN_DOMAIN) - 1u);
}

bool vcs_proof_ticket_sign(struct vcs_proof_ticket_v1 *t,
                           const uint8_t seed[32])
{
    if (!t || !seed || !pt_nonzero(seed, 32))
        LOG_RETURN(false, PT_LOG, "ticket sign: missing ticket or seed");
    uint8_t secret[32];
    ed25519_keypair(t->producer_pubkey, secret, seed);
    if (!vcs_proof_ticket_body_valid(t)) {
        memset(secret, 0, sizeof(secret));
        LOG_RETURN(false, PT_LOG, "ticket sign: body not canonical");
    }
    uint8_t message[PTK_SIGN_MESSAGE_BYTES];
    ptk_message(t, message);
    ed25519_sign(t->signature, message, sizeof(message), secret,
                 t->producer_pubkey);
    memset(secret, 0, sizeof(secret));
    return true;
}

bool vcs_proof_ticket_signature_valid(const struct vcs_proof_ticket_v1 *t)
{
    if (!vcs_proof_ticket_body_valid(t)) return false;
    uint8_t message[PTK_SIGN_MESSAGE_BYTES];
    ptk_message(t, message);
    return ed25519_verify(t->signature, message, sizeof(message),
                          t->producer_pubkey);
}

bool vcs_proof_ticket_encode(const struct vcs_proof_ticket_v1 *t,
                             uint8_t out[VCS_PROOF_TICKET_WIRE_BYTES])
{
    if (!out || !vcs_proof_ticket_body_valid(t))
        LOG_RETURN(false, PT_LOG, "ticket encode: body not canonical");
    if (!pt_nonzero(t->signature, VCS_PROOF_SIGNATURE_BYTES))
        LOG_RETURN(false, PT_LOG, "ticket encode: unsigned ticket refused");
    ptk_put_signed(t, out);
    memcpy(out + VCS_PROOF_TICKET_SIGNED_BYTES, t->signature,
           VCS_PROOF_SIGNATURE_BYTES);
    return true;
}

static void ptk_read(const uint8_t *wire, struct vcs_proof_ticket_v1 *t)
{
    t->verdict = (enum vcs_proof_verdict)wire[12];
    t->reproduced = wire[13] == 1u;
    memcpy(t->input_key, wire + 16, VCS_PROOF_ROOT_BYTES);
    memcpy(t->key_preimage_root, wire + 48, VCS_PROOF_ROOT_BYTES);
    memcpy(t->evidence_root, wire + 80, VCS_PROOF_ROOT_BYTES);
    t->checks_run = zcl_read_u32_le(wire + 112);
    t->checks_passed = zcl_read_u32_le(wire + 116);
    t->cpu_us = zcl_read_u64_le(wire + 120);
    t->wall_us = zcl_read_u64_le(wire + 128);
    t->bytes_in = zcl_read_u64_le(wire + 136);
    t->bytes_out = zcl_read_u64_le(wire + 144);
    t->created_unix = zcl_read_u64_le(wire + 152);
    memcpy(t->producer_pubkey, wire + 160, VCS_PROOF_PUBKEY_BYTES);
    memcpy(t->signature, wire + 192, VCS_PROOF_SIGNATURE_BYTES);
}

bool vcs_proof_ticket_decode(const uint8_t *wire, size_t len,
                             struct vcs_proof_ticket_v1 *out)
{
    if (!out || !wire)
        LOG_RETURN(false, PT_LOG, "ticket decode: null input");
    memset(out, 0, sizeof(*out));
    if (len != VCS_PROOF_TICKET_WIRE_BYTES)
        LOG_RETURN(false, PT_LOG, "ticket decode: %zu bytes, want %u", len,
                   VCS_PROOF_TICKET_WIRE_BYTES);
    if (memcmp(wire, PTK_MAGIC, 8) != 0 ||
        zcl_read_u32_le(wire + 8) != PTK_VERSION)
        LOG_RETURN(false, PT_LOG, "ticket decode: unknown schema");
    if (wire[13] > 1u || wire[14] != 0 || wire[15] != 0)
        LOG_RETURN(false, PT_LOG, "ticket decode: non-canonical flags");
    struct vcs_proof_ticket_v1 parsed;
    memset(&parsed, 0, sizeof(parsed));
    ptk_read(wire, &parsed);
    if (!vcs_proof_ticket_body_valid(&parsed) ||
        !pt_nonzero(parsed.signature, VCS_PROOF_SIGNATURE_BYTES))
        LOG_RETURN(false, PT_LOG, "ticket decode: non-canonical values");
    *out = parsed;
    return true;
}

bool vcs_proof_ticket_observation_root(const uint8_t *wire, size_t len,
                                       uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    if (!wire || !out || len == 0)
        LOG_RETURN(false, PT_LOG, "observation root: empty input");
    struct sha3_256_ctx sha;
    pt_sha3_domain(&sha, PTK_ROOT_DOMAIN);
    sha3_256_write(&sha, wire, len);
    sha3_256_finalize(&sha, out);
    return true;
}

/* ── CAS placement ──────────────────────────────────────────────────── */

bool vcs_proof_ticket_store_put(struct vcs_package_store *store,
                                const uint8_t *wire, size_t len,
                                uint8_t blob_root[VCS_PROOF_ROOT_BYTES])
{
    if (!store || !wire || !blob_root)
        LOG_RETURN(false, PT_LOG, "ticket store put: null argument");
    enum vcs_blob_result r = vcs_blob_put_to(store, wire, len, blob_root);
    if (r != VCS_BLOB_OK)
        LOG_RETURN(false, PT_LOG, "ticket store put (%zu bytes): %s", len,
                   vcs_blob_result_string(r));
    return true;
}

bool vcs_component_proof_key_load(struct vcs_package_store *store,
                                  const uint8_t preimage_root[32],
                                  struct vcs_component_proof_key_v1 *out)
{
    if (!store || !preimage_root || !out)
        LOG_RETURN(false, PT_LOG, "preimage load: null argument");
    uint8_t wire[VCS_CPK_WIRE_BYTES + 1u];
    size_t len = 0;
    enum vcs_blob_result r =
        vcs_blob_get_from(store, preimage_root, wire, sizeof(wire), &len);
    if (r != VCS_BLOB_OK)
        LOG_RETURN(false, PT_LOG, "preimage load: %s",
                   vcs_blob_result_string(r));
    if (!vcs_component_proof_key_decode(wire, len, out))
        LOG_RETURN(false, PT_LOG, "preimage load: blob is not a key preimage");
    uint8_t again[VCS_PROOF_ROOT_BYTES];
    if (!vcs_component_proof_key_preimage_root(out, again) ||
        memcmp(again, preimage_root, VCS_PROOF_ROOT_BYTES) != 0)
        LOG_RETURN(false, PT_LOG, "preimage load: root does not re-derive");
    return true;
}
