/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical zcl.component_proof_key.v1 preimages, interface
 *          contract roots and signed zcl.proof_ticket.v1 observations. */

#include "vcs/proof_ticket.h"

#include "vcs/blob_store.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"

#include <stdlib.h>
#include <string.h>

#define PT_LOG "vcs.proof_ticket"

#define CPK_MAGIC "Z23CPK1\0"
#define CPK_VERSION 1u
#define CPK_KEY_DOMAIN "zcl.component_proof_key.v1"
#define CPK_FIELD_DOMAIN "zcl.component_proof_key.field.v1"
#define CPK_LIST_DOMAIN "zcl.component_proof_key.list.v1"
#define CPK_ENV_DOMAIN "zcl.component_proof_key.environment.v1"
#define CPK_GEN_DOMAIN "zcl.component_proof_key.generated.v1"
#define CPK_EDGE_DOMAIN "zcl.component_proof_key.edges.v1"
#define CONTRACT_DOMAIN "zcl.component_contract.v1"

#define PTK_MAGIC "Z23PTK1\0"
#define PTK_VERSION 1u
#define PTK_SIGN_DOMAIN "zcl.proof_ticket.v1"
#define PTK_ROOT_DOMAIN "zcl.proof_ticket_root.v1"
#define PTK_SIGN_MESSAGE_BYTES \
    ((sizeof(PTK_SIGN_DOMAIN) - 1u) + VCS_PROOF_TICKET_SIGNED_BYTES)

static const char *const cpk_field_names[VCS_CPK_FIELD_COUNT] = {
    "kind", "unit_id", "source_closure", "dependency_closure",
    "negative_lookups", "generated_inputs", "toolchain", "linker", "sysroot",
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

static void pt_sha3_str(struct sha3_256_ctx *sha, const char *s)
{
    size_t len = strlen(s);
    pt_sha3_u64(sha, (uint64_t)len);
    sha3_256_write(sha, (const uint8_t *)s, len);
}

/* ── zcl.component_proof_key.v1 field roots ─────────────────────────── */

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

static bool pt_items_present(const char *const *items, size_t count)
{
    if (!items) return count == 0;
    for (size_t i = 0; i < count; i++)
        if (!items[i]) return false;
    return true;
}

bool vcs_component_proof_ordered_root(enum vcs_component_proof_field field,
                                      const char *const *items, size_t count,
                                      uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    if (!out || (unsigned)field >= VCS_CPK_FIELD_COUNT ||
        !pt_items_present(items, count))
        LOG_RETURN(false, PT_LOG, "ordered root arguments invalid (field=%u)",
                   (unsigned)field);
    struct sha3_256_ctx sha;
    pt_sha3_domain(&sha, CPK_LIST_DOMAIN);
    pt_sha3_u16(&sha, (uint16_t)field);
    pt_sha3_u64(&sha, (uint64_t)count);
    for (size_t i = 0; i < count; i++) pt_sha3_str(&sha, items[i]);
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
        pt_sha3_str(&sha, env[i].name);
        uint8_t present = env[i].value ? 1u : 0u;
        sha3_256_write(&sha, &present, 1);
        if (present) pt_sha3_str(&sha, env[i].value);
    }
    uint8_t digest[VCS_PROOF_ROOT_BYTES];
    sha3_256_finalize(&sha, digest);
    return vcs_component_proof_field_root(VCS_CPK_ENVIRONMENT, digest,
                                          sizeof(digest), out);
}

bool vcs_component_proof_generated_root(
    const struct vcs_component_proof_generated *inputs, size_t count,
    uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    if (!out || (!inputs && count))
        LOG_RETURN(false, PT_LOG, "generated inputs arguments invalid");
    struct sha3_256_ctx sha;
    pt_sha3_domain(&sha, CPK_GEN_DOMAIN);
    pt_sha3_u64(&sha, (uint64_t)count);
    for (size_t i = 0; i < count; i++) {
        const struct vcs_component_proof_generated *g = &inputs[i];
        if (!g->path || !g->path[0] ||
            (i > 0 && strcmp(inputs[i - 1].path, g->path) >= 0) ||
            !pt_nonzero(g->content_root, VCS_PROOF_ROOT_BYTES) ||
            !pt_nonzero(g->producer_key, VCS_PROOF_ROOT_BYTES))
            LOG_RETURN(false, PT_LOG,
                       "generated input %zu not canonical (paths ascending, "
                       "unique; roots nonzero)", i);
        pt_sha3_str(&sha, g->path);
        sha3_256_write(&sha, g->content_root, VCS_PROOF_ROOT_BYTES);
        sha3_256_write(&sha, g->producer_key, VCS_PROOF_ROOT_BYTES);
    }
    uint8_t digest[VCS_PROOF_ROOT_BYTES];
    sha3_256_finalize(&sha, digest);
    return vcs_component_proof_field_root(VCS_CPK_GENERATED_INPUTS, digest,
                                          sizeof(digest), out);
}

/* ── Interface contracts and integration edges ──────────────────────── */

static int pt_cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

/* Hash `items` as a SET: sorted copy, duplicates refused. */
static bool pt_sha3_set(struct sha3_256_ctx *sha, const char *const *items,
                        size_t count)
{
    if (!pt_items_present(items, count)) return false;
    pt_sha3_u64(sha, (uint64_t)count);
    if (count == 0) return true;
    const char **sorted = zcl_malloc(count * sizeof(*sorted), "contract_set");
    if (!sorted) LOG_RETURN(false, PT_LOG, "contract set: out of memory");
    memcpy(sorted, items, count * sizeof(*sorted));
    qsort(sorted, count, sizeof(*sorted), pt_cmp_str);
    bool ok = true;
    for (size_t i = 0; i < count && ok; i++) {
        ok = i == 0 || strcmp(sorted[i - 1], sorted[i]) != 0;
        if (ok) pt_sha3_str(sha, sorted[i]);
    }
    free(sorted);
    if (!ok) LOG_RETURN(false, PT_LOG, "contract set lists a member twice");
    return true;
}

bool vcs_component_contract_root(const struct vcs_component_contract *c,
                                 uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    if (!c || !out || !c->component_id || !c->component_id[0] ||
        !pt_items_present(c->header_tokens, c->header_token_count))
        LOG_RETURN(false, PT_LOG, "contract root arguments invalid");
    struct sha3_256_ctx sha;
    pt_sha3_domain(&sha, CONTRACT_DOMAIN);
    pt_sha3_str(&sha, c->component_id);
    pt_sha3_u64(&sha, (uint64_t)c->header_token_count);
    for (size_t i = 0; i < c->header_token_count; i++)
        pt_sha3_str(&sha, c->header_tokens[i]);
    if (!pt_sha3_set(&sha, c->symbols, c->symbol_count) ||
        !pt_sha3_set(&sha, c->premises, c->premise_count))
        LOG_RETURN(false, PT_LOG, "contract of %s: symbol/premise set invalid",
                   c->component_id);
    sha3_256_finalize(&sha, out);
    return true;
}

static int pt_cmp_edge(const void *a, const void *b)
{
    const struct vcs_component_edge *x = *(const struct vcs_component_edge *const *)a;
    const struct vcs_component_edge *y = *(const struct vcs_component_edge *const *)b;
    return strcmp(x->callee_id, y->callee_id);
}

static bool pt_edges_hash(const struct vcs_component_edge **sorted,
                          size_t count, uint8_t digest[VCS_PROOF_ROOT_BYTES])
{
    struct sha3_256_ctx sha;
    pt_sha3_domain(&sha, CPK_EDGE_DOMAIN);
    pt_sha3_u64(&sha, (uint64_t)count);
    for (size_t i = 0; i < count; i++) {
        if (i > 0 && strcmp(sorted[i - 1]->callee_id, sorted[i]->callee_id) == 0)
            LOG_RETURN(false, PT_LOG, "integration edge to %s listed twice",
                       sorted[i]->callee_id);
        if (!pt_nonzero(sorted[i]->contract_root, VCS_PROOF_ROOT_BYTES))
            LOG_RETURN(false, PT_LOG, "integration edge to %s: zero contract",
                       sorted[i]->callee_id);
        pt_sha3_str(&sha, sorted[i]->callee_id);
        sha3_256_write(&sha, sorted[i]->contract_root, VCS_PROOF_ROOT_BYTES);
    }
    sha3_256_finalize(&sha, digest);
    return true;
}

bool vcs_component_integration_edges_root(
    const struct vcs_component_edge *edges, size_t count,
    uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    if (!out || (!edges && count))
        LOG_RETURN(false, PT_LOG, "integration edges arguments invalid");
    for (size_t i = 0; i < count; i++)
        if (!edges[i].callee_id || !edges[i].callee_id[0])
            LOG_RETURN(false, PT_LOG, "integration edge %zu has no callee", i);
    const struct vcs_component_edge **sorted = NULL;
    if (count) {
        sorted = zcl_malloc(count * sizeof(*sorted), "integration_edges");
        if (!sorted) LOG_RETURN(false, PT_LOG, "edges: out of memory");
        for (size_t i = 0; i < count; i++) sorted[i] = &edges[i];
        qsort(sorted, count, sizeof(*sorted), pt_cmp_edge);
    }
    uint8_t digest[VCS_PROOF_ROOT_BYTES];
    bool ok = pt_edges_hash(sorted, count, digest);
    free(sorted);
    return ok && vcs_component_proof_field_root(VCS_CPK_INTEGRATION_EDGES,
                                                digest, sizeof(digest), out);
}

/* ── Preimage codec and key ─────────────────────────────────────────── */

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

bool vcs_proof_artifact_root(const uint8_t *bytes, size_t len,
                             uint8_t out[VCS_PROOF_ROOT_BYTES])
{
    if (!out || (!bytes && len))
        LOG_RETURN(false, PT_LOG, "artifact root arguments invalid");
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    if (len) sha3_256_write(&sha, bytes, len);
    sha3_256_finalize(&sha, out);
    return true;
}

static bool ptk_counts_valid(const struct vcs_proof_ticket_v1 *t)
{
    if (t->checks_run == 0 || t->checks_passed > t->checks_run) return false;
    if (t->verdict == VCS_PROOF_VERDICT_PASS)
        return t->checks_passed == t->checks_run;
    return t->checks_passed < t->checks_run;
}

static bool ptk_enums_valid(const struct vcs_proof_ticket_v1 *t)
{
    return (t->verdict == VCS_PROOF_VERDICT_PASS ||
            t->verdict == VCS_PROOF_VERDICT_FAIL) &&
           (t->basis == VCS_PROOF_BASIS_EXECUTED ||
            t->basis == VCS_PROOF_BASIS_REUSED) &&
           (t->action_class == VCS_PROOF_ACTION_BUILD ||
            t->action_class == VCS_PROOF_ACTION_CHECK);
}

/* Artifact only for a passing build; basis_ref only for a reuse. */
static bool ptk_links_valid(const struct vcs_proof_ticket_v1 *t)
{
    bool wants_artifact = t->action_class == VCS_PROOF_ACTION_BUILD &&
                          t->verdict == VCS_PROOF_VERDICT_PASS;
    bool wants_ref = t->basis == VCS_PROOF_BASIS_REUSED;
    return pt_nonzero(t->artifact_root, VCS_PROOF_ROOT_BYTES) ==
               wants_artifact &&
           pt_nonzero(t->basis_ref, VCS_PROOF_ROOT_BYTES) == wants_ref;
}

bool vcs_proof_ticket_body_valid(const struct vcs_proof_ticket_v1 *t)
{
    if (!t || !ptk_enums_valid(t) || !ptk_links_valid(t)) return false;
    return ptk_counts_valid(t) && t->created_unix != 0 &&
           pt_nonzero(t->input_key, VCS_PROOF_ROOT_BYTES) &&
           pt_nonzero(t->key_preimage_root, VCS_PROOF_ROOT_BYTES) &&
           pt_nonzero(t->source_root, VCS_PROOF_ROOT_BYTES) &&
           pt_nonzero(t->evidence_root, VCS_PROOF_ROOT_BYTES) &&
           pt_nonzero(t->producer_pubkey, VCS_PROOF_PUBKEY_BYTES);
}

/* Bytes [0,296): everything the signature covers. */
static void ptk_put_signed(const struct vcs_proof_ticket_v1 *t, uint8_t *out)
{
    memcpy(out, PTK_MAGIC, 8);
    zcl_write_u32_le(out + 8, PTK_VERSION);
    out[12] = (uint8_t)t->verdict;
    out[13] = (uint8_t)t->basis;
    out[14] = (uint8_t)t->action_class;
    out[15] = 0;
    memcpy(out + 16, t->input_key, VCS_PROOF_ROOT_BYTES);
    memcpy(out + 48, t->key_preimage_root, VCS_PROOF_ROOT_BYTES);
    memcpy(out + 80, t->source_root, VCS_PROOF_ROOT_BYTES);
    memcpy(out + 112, t->artifact_root, VCS_PROOF_ROOT_BYTES);
    memcpy(out + 144, t->evidence_root, VCS_PROOF_ROOT_BYTES);
    memcpy(out + 176, t->basis_ref, VCS_PROOF_ROOT_BYTES);
    zcl_write_u32_le(out + 208, t->checks_run);
    zcl_write_u32_le(out + 212, t->checks_passed);
    zcl_write_u64_le(out + 216, t->cpu_us);
    zcl_write_u64_le(out + 224, t->wall_us);
    zcl_write_u64_le(out + 232, t->bytes_in);
    zcl_write_u64_le(out + 240, t->bytes_out);
    zcl_write_u64_le(out + 248, t->created_unix);
    zcl_write_u64_le(out + 256, t->issuer_seq);
    memcpy(out + 264, t->producer_pubkey, VCS_PROOF_PUBKEY_BYTES);
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
    t->basis = (enum vcs_proof_basis)wire[13];
    t->action_class = (enum vcs_proof_action_class)wire[14];
    memcpy(t->input_key, wire + 16, VCS_PROOF_ROOT_BYTES);
    memcpy(t->key_preimage_root, wire + 48, VCS_PROOF_ROOT_BYTES);
    memcpy(t->source_root, wire + 80, VCS_PROOF_ROOT_BYTES);
    memcpy(t->artifact_root, wire + 112, VCS_PROOF_ROOT_BYTES);
    memcpy(t->evidence_root, wire + 144, VCS_PROOF_ROOT_BYTES);
    memcpy(t->basis_ref, wire + 176, VCS_PROOF_ROOT_BYTES);
    t->checks_run = zcl_read_u32_le(wire + 208);
    t->checks_passed = zcl_read_u32_le(wire + 212);
    t->cpu_us = zcl_read_u64_le(wire + 216);
    t->wall_us = zcl_read_u64_le(wire + 224);
    t->bytes_in = zcl_read_u64_le(wire + 232);
    t->bytes_out = zcl_read_u64_le(wire + 240);
    t->created_unix = zcl_read_u64_le(wire + 248);
    t->issuer_seq = zcl_read_u64_le(wire + 256);
    memcpy(t->producer_pubkey, wire + 264, VCS_PROOF_PUBKEY_BYTES);
    memcpy(t->signature, wire + 296, VCS_PROOF_SIGNATURE_BYTES);
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
    if (wire[15] != 0)
        LOG_RETURN(false, PT_LOG, "ticket decode: nonzero reserved byte");
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
