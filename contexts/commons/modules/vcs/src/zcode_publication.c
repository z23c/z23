/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical signed publication intents; no execution authority. */
#include "vcs/zcode_publication.h"
#include "vcs/signed_evidence.h"
#include "vcs/vcs_object.h"
#include <stdlib.h>
#include "base/bytes.h"
#include "base/log_macros.h"
#include "base/serialize_le.h"
#include <string.h>

bool vcs_zcode_publication_store_verified(
    const char *workspace, const struct vcs_zcode_publication_v1 *intent,
    const uint8_t expected_signer[32], uint8_t out_root[32])
{
    if (!out_root) LOG_FAIL("vcs.publication", "missing output root");
    memset(out_root, 0, 32);
    if (!workspace || !workspace[0] || !intent || !expected_signer)
        LOG_FAIL("vcs.publication", "missing store input");
    uint8_t root[32], wire[VCS_ZCODE_PUBLICATION_WIRE_BYTES];
    if (vcs_zcode_publication_verify(intent, expected_signer) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_publication_root(intent, root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_publication_serialize(intent, wire) != VCS_ZCODE_DEV_OK)
        LOG_FAIL("vcs.publication", "intent signature or canonical bytes refused");
    if (!vcs_object_store_initialized(workspace))
        LOG_FAIL("vcs.publication", "publication CAS is not initialized");
    /* Existence does not prove a prior initialization's barriers succeeded. */
    if (!vcs_object_store_init(workspace))
        LOG_FAIL("vcs.publication", "publication CAS parent barriers failed");
    struct vcs_zcode_publication_v1 checked;
    if (!vcs_object_put_addressed(workspace, root, wire, sizeof(wire)) ||
        !vcs_zcode_publication_load_verified(workspace, root, expected_signer, &checked))
        LOG_FAIL("vcs.publication", "stored intent did not verify");
    memcpy(out_root, root, 32);
    return true;
}

bool vcs_zcode_publication_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t expected_signer[32], struct vcs_zcode_publication_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!workspace || !workspace[0] || !root || !expected_signer) return false;
    uint8_t *wire = NULL, checked[32];
    size_t length = 0;
    struct vcs_zcode_publication_v1 intent;
    bool ok = vcs_object_load_raw_bounded(workspace, root,
            VCS_ZCODE_PUBLICATION_WIRE_BYTES, &wire, &length) == 0 &&
        vcs_zcode_publication_parse(wire, length, &intent) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_publication_root(&intent, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0 &&
        vcs_zcode_publication_verify(&intent, expected_signer) == VCS_ZCODE_DEV_OK;
    free(wire);
    if (ok) *out = intent;
    return ok;
}

static const uint8_t publication_magic[8] = {'Z','C','P','U','B','I','\r','\n'};
_Static_assert(VCS_ZCODE_PUBLICATION_BODY_BYTES == 376u, "publication body offsets");
_Static_assert(VCS_ZCODE_PUBLICATION_WIRE_BYTES == 440u, "publication wire offsets");

static bool publication_ref_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}

static bool publication_ref_component(const char *s, size_t n)
{
    if (!n || s[0] == '.' || s[n - 1] == '.') return false;
    if (n >= 5 && memcmp(s + n - 5, ".lock", 5) == 0) return false;
    for (size_t i = 0; i < n; i++) {
        if (!publication_ref_char((unsigned char)s[i])) return false;
        if (i && s[i] == '.' && s[i - 1] == '.') return false;
    }
    return true;
}

/* Deliberately bounded ASCII subset of Git refs; no revision expressions. */
static bool publication_ref_valid(const char ref[VCS_ZCODE_PUBLICATION_REF_BYTES])
{
    const char *end = memchr(ref, 0, VCS_ZCODE_PUBLICATION_REF_BYTES);
    if (!end) return false;
    size_t n = (size_t)(end - ref);
    if (n < 6 || memcmp(ref, "refs/", 5) != 0) return false;
    if (zcl_bytes_any_set((const uint8_t *)end,
                          VCS_ZCODE_PUBLICATION_REF_BYTES - n)) return false;
    size_t start = 5;
    for (size_t i = start; i <= n; i++) {
        if (i != n && ref[i] != '/') continue;
        if (!publication_ref_component(ref + start, i - start)) return false;
        start = i + 1;
    }
    return true;
}

static bool publication_oid_valid(const uint8_t oid[32], uint8_t format)
{
    if (format == VCS_ZCODE_PUBLICATION_GIT_OID_32)
        return zcl_bytes_any_set(oid, 32);
    return format == VCS_ZCODE_PUBLICATION_GIT_OID_20 &&
           zcl_bytes_any_set(oid, 20) && !zcl_bytes_any_set(oid + 20, 12);
}

static enum vcs_zcode_dev_error publication_fields(
    const struct vcs_zcode_publication_v1 *p, bool signature)
{
    if (!p) return VCS_ZCODE_DEV_ERR_NULL;
    if (p->schema_version != VCS_ZCODE_DEV_VERSION) return VCS_ZCODE_DEV_ERR_VERSION;
    const uint8_t *roots[] = {p->candidate_root, p->proof_set_root,
        p->target_identity_root, p->authority_root};
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32)) return VCS_ZCODE_DEV_ERR_ROOT_ZERO;
    if (!publication_oid_valid(p->expected_base, p->git_object_format) ||
        !publication_oid_valid(p->head_commit, p->git_object_format))
        return VCS_ZCODE_DEV_ERR_POLICY;
    if (!publication_ref_valid(p->target_ref)) return VCS_ZCODE_DEV_ERR_POLICY;
    if (p->created_unix <= 0) return VCS_ZCODE_DEV_ERR_TIME_ORDER;
    if (!zcl_bytes_any_set(p->author_pubkey, 32)) return VCS_ZCODE_DEV_ERR_PUBKEY_ZERO;
    if (signature && !zcl_bytes_any_set(p->signature, 64))
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_publication_validate(
    const struct vcs_zcode_publication_v1 *intent)
{
    return publication_fields(intent, true);
}

static enum vcs_zcode_dev_error publication_body(
    const struct vcs_zcode_publication_v1 *p, uint8_t out[376])
{
    enum vcs_zcode_dev_error error = publication_fields(p, false);
    if (error != VCS_ZCODE_DEV_OK) return error;
    memset(out, 0, VCS_ZCODE_PUBLICATION_BODY_BYTES);
    memcpy(out, publication_magic, 8);
    zcl_write_u16_le(out + 8, p->schema_version);
    out[10] = p->git_object_format;
    memcpy(out + 16, p->candidate_root, 32);
    memcpy(out + 48, p->proof_set_root, 32);
    memcpy(out + 80, p->target_identity_root, 32);
    memcpy(out + 112, p->authority_root, 32);
    memcpy(out + 144, p->target_ref, 128);
    memcpy(out + 272, p->expected_base, 32);
    memcpy(out + 304, p->head_commit, 32);
    zcl_write_i64_le(out + 336, p->created_unix);
    memcpy(out + 344, p->author_pubkey, 32);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_publication_serialize(
    const struct vcs_zcode_publication_v1 *p,
    uint8_t out[VCS_ZCODE_PUBLICATION_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error error = publication_fields(p, true);
    if (error != VCS_ZCODE_DEV_OK) return error;
    error = publication_body(p, out);
    if (error != VCS_ZCODE_DEV_OK) return error;
    memcpy(out + VCS_ZCODE_PUBLICATION_BODY_BYTES, p->signature, 64);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_publication_parse(
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_publication_v1 *out)
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire) return VCS_ZCODE_DEV_ERR_NULL;
    if (wire_len != VCS_ZCODE_PUBLICATION_WIRE_BYTES) return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    if (memcmp(wire, publication_magic, 8) != 0 || zcl_bytes_any_set(wire + 11, 5))
        return VCS_ZCODE_DEV_ERR_WIRE_MAGIC;
    struct vcs_zcode_publication_v1 p = {0};
    p.schema_version = zcl_read_u16_le(wire + 8);
    p.git_object_format = wire[10];
    memcpy(p.candidate_root, wire + 16, 32);
    memcpy(p.proof_set_root, wire + 48, 32);
    memcpy(p.target_identity_root, wire + 80, 32);
    memcpy(p.authority_root, wire + 112, 32);
    memcpy(p.target_ref, wire + 144, 128);
    memcpy(p.expected_base, wire + 272, 32);
    memcpy(p.head_commit, wire + 304, 32);
    p.created_unix = zcl_read_i64_le(wire + 336);
    memcpy(p.author_pubkey, wire + 344, 32);
    memcpy(p.signature, wire + 376, 64);
    enum vcs_zcode_dev_error error = publication_fields(&p, true);
    if (error == VCS_ZCODE_DEV_OK) *out = p;
    return error;
}

enum vcs_zcode_dev_error vcs_zcode_publication_root(
    const struct vcs_zcode_publication_v1 *p, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    uint8_t wire[VCS_ZCODE_PUBLICATION_WIRE_BYTES];
    enum vcs_zcode_dev_error error = vcs_zcode_publication_serialize(p, wire);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_PUBLICATION_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

static enum vcs_zcode_dev_error publication_signing_root(
    const struct vcs_zcode_publication_v1 *p, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_PUBLICATION_BODY_BYTES];
    enum vcs_zcode_dev_error error = publication_body(p, body);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_PUBLICATION_SIGNING_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

enum vcs_zcode_dev_error vcs_zcode_publication_seal(
    struct vcs_zcode_publication_v1 *p, const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!p || !secret || !pubkey) return VCS_ZCODE_DEV_ERR_NULL;
    memcpy(p->author_pubkey, pubkey, 32);
    uint8_t root[32];
    enum vcs_zcode_dev_error error = publication_signing_root(p, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_seal_root(root, secret, pubkey, p->signature)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

enum vcs_zcode_dev_error vcs_zcode_publication_verify(
    const struct vcs_zcode_publication_v1 *p, const uint8_t expected_signer[32])
{
    if (!expected_signer) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error error = publication_fields(p, true);
    if (error != VCS_ZCODE_DEV_OK) return error;
    uint8_t root[32];
    error = publication_signing_root(p, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_verify_root(root, p->signature, p->author_pubkey, expected_signer)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

static const uint8_t publication_attachment_magic[8] =
    {'Z','C','P','A','T','T','\r','\n'};
_Static_assert(VCS_ZCODE_PUBLICATION_ATTACHMENT_BODY_BYTES == 184u,
               "publication attachment body offsets");
_Static_assert(VCS_ZCODE_PUBLICATION_ATTACHMENT_WIRE_BYTES == 248u,
               "publication attachment wire offsets");

static enum vcs_zcode_dev_error publication_attachment_fields(
    const struct vcs_zcode_publication_attachment_v1 *a, bool signature)
{
    if (!a) return VCS_ZCODE_DEV_ERR_NULL;
    if (a->schema_version != VCS_ZCODE_DEV_VERSION)
        return VCS_ZCODE_DEV_ERR_VERSION;
    const uint8_t *roots[] = {a->publication_root, a->bundle_sha256,
                              a->expected_base, a->head_commit};
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_DEV_ERR_ROOT_ZERO;
    if (a->created_unix <= 0) return VCS_ZCODE_DEV_ERR_TIME_ORDER;
    if (!zcl_bytes_any_set(a->author_pubkey, 32))
        return VCS_ZCODE_DEV_ERR_PUBKEY_ZERO;
    if (signature && !zcl_bytes_any_set(a->signature, 64))
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_publication_attachment_validate(
    const struct vcs_zcode_publication_attachment_v1 *a)
{
    return publication_attachment_fields(a, true);
}

static enum vcs_zcode_dev_error publication_attachment_body(
    const struct vcs_zcode_publication_attachment_v1 *a,
    uint8_t out[VCS_ZCODE_PUBLICATION_ATTACHMENT_BODY_BYTES])
{
    enum vcs_zcode_dev_error error = publication_attachment_fields(a, false);
    if (error != VCS_ZCODE_DEV_OK) return error;
    memset(out, 0, VCS_ZCODE_PUBLICATION_ATTACHMENT_BODY_BYTES);
    memcpy(out, publication_attachment_magic, 8);
    zcl_write_u16_le(out + 8, a->schema_version);
    memcpy(out + 16, a->publication_root, 32);
    memcpy(out + 48, a->bundle_sha256, 32);
    memcpy(out + 80, a->expected_base, 32);
    memcpy(out + 112, a->head_commit, 32);
    zcl_write_i64_le(out + 144, a->created_unix);
    memcpy(out + 152, a->author_pubkey, 32);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_publication_attachment_serialize(
    const struct vcs_zcode_publication_attachment_v1 *a,
    uint8_t out[VCS_ZCODE_PUBLICATION_ATTACHMENT_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error error = publication_attachment_fields(a, true);
    if (error != VCS_ZCODE_DEV_OK) return error;
    error = publication_attachment_body(a, out);
    if (error != VCS_ZCODE_DEV_OK) return error;
    memcpy(out + VCS_ZCODE_PUBLICATION_ATTACHMENT_BODY_BYTES,
           a->signature, 64);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_publication_attachment_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_publication_attachment_v1 *out)
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire) return VCS_ZCODE_DEV_ERR_NULL;
    if (wire_len != VCS_ZCODE_PUBLICATION_ATTACHMENT_WIRE_BYTES)
        return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    if (memcmp(wire, publication_attachment_magic, 8) != 0 ||
        zcl_bytes_any_set(wire + 10, 6))
        return VCS_ZCODE_DEV_ERR_WIRE_MAGIC;
    struct vcs_zcode_publication_attachment_v1 a = {0};
    a.schema_version = zcl_read_u16_le(wire + 8);
    memcpy(a.publication_root, wire + 16, 32);
    memcpy(a.bundle_sha256, wire + 48, 32);
    memcpy(a.expected_base, wire + 80, 32);
    memcpy(a.head_commit, wire + 112, 32);
    a.created_unix = zcl_read_i64_le(wire + 144);
    memcpy(a.author_pubkey, wire + 152, 32);
    memcpy(a.signature, wire + 184, 64);
    enum vcs_zcode_dev_error error = publication_attachment_fields(&a, true);
    if (error == VCS_ZCODE_DEV_OK) *out = a;
    return error;
}

enum vcs_zcode_dev_error vcs_zcode_publication_attachment_root(
    const struct vcs_zcode_publication_attachment_v1 *a, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    uint8_t wire[VCS_ZCODE_PUBLICATION_ATTACHMENT_WIRE_BYTES];
    enum vcs_zcode_dev_error error = vcs_zcode_publication_attachment_serialize(a, wire);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_PUBLICATION_ATTACHMENT_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

static enum vcs_zcode_dev_error publication_attachment_signing_root(
    const struct vcs_zcode_publication_attachment_v1 *a, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_PUBLICATION_ATTACHMENT_BODY_BYTES];
    enum vcs_zcode_dev_error error = publication_attachment_body(a, body);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_PUBLICATION_ATTACHMENT_SIGNING_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

enum vcs_zcode_dev_error vcs_zcode_publication_attachment_seal(
    struct vcs_zcode_publication_attachment_v1 *a,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!a || !secret || !pubkey) return VCS_ZCODE_DEV_ERR_NULL;
    memcpy(a->author_pubkey, pubkey, 32);
    uint8_t root[32];
    enum vcs_zcode_dev_error error = publication_attachment_signing_root(a, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_seal_root(root, secret, pubkey, a->signature)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

enum vcs_zcode_dev_error vcs_zcode_publication_attachment_verify(
    const struct vcs_zcode_publication_attachment_v1 *a,
    const uint8_t expected_signer[32])
{
    if (!expected_signer) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error error = publication_attachment_fields(a, true);
    if (error != VCS_ZCODE_DEV_OK) return error;
    uint8_t root[32];
    error = publication_attachment_signing_root(a, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_verify_root(root, a->signature,
                a->author_pubkey, expected_signer)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

static bool publication_attachment_intent_matches(
    const char *workspace,
    const struct vcs_zcode_publication_attachment_v1 *a,
    const uint8_t expected_signer[32])
{
    struct vcs_zcode_publication_v1 intent;
    return vcs_zcode_publication_load_verified(workspace, a->publication_root,
            expected_signer, &intent) &&
        memcmp(a->expected_base, intent.expected_base, 32) == 0 &&
        memcmp(a->head_commit, intent.head_commit, 32) == 0 &&
        a->created_unix >= intent.created_unix;
}

bool vcs_zcode_publication_attachment_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t expected_signer[32],
    struct vcs_zcode_publication_attachment_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!workspace || !workspace[0] || !root || !expected_signer) return false;
    uint8_t *wire = NULL, checked[32];
    size_t length = 0;
    struct vcs_zcode_publication_attachment_v1 a;
    bool ok = vcs_object_load_raw_bounded(workspace, root,
            VCS_ZCODE_PUBLICATION_ATTACHMENT_WIRE_BYTES, &wire, &length) == 0 &&
        vcs_zcode_publication_attachment_parse(wire, length, &a) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_publication_attachment_root(&a, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0 &&
        vcs_zcode_publication_attachment_verify(&a, expected_signer) == VCS_ZCODE_DEV_OK;
    free(wire);
    if (ok) ok = publication_attachment_intent_matches(workspace, &a,
                                                         expected_signer);
    if (ok) *out = a;
    return ok;
}

bool vcs_zcode_publication_attachment_store_verified(
    const char *workspace,
    const struct vcs_zcode_publication_attachment_v1 *a,
    const uint8_t expected_signer[32], uint8_t out_root[32])
{
    if (!out_root) LOG_FAIL("vcs.publication_attachment", "missing output root");
    memset(out_root, 0, 32);
    if (!workspace || !workspace[0] || !a || !expected_signer)
        LOG_FAIL("vcs.publication_attachment", "missing store input");
    uint8_t root[32], wire[VCS_ZCODE_PUBLICATION_ATTACHMENT_WIRE_BYTES];
    if (vcs_zcode_publication_attachment_verify(a, expected_signer) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_publication_attachment_root(a, root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_publication_attachment_serialize(a, wire) != VCS_ZCODE_DEV_OK)
        LOG_FAIL("vcs.publication_attachment", "attachment signature or wire refused");
    if (!publication_attachment_intent_matches(workspace, a, expected_signer))
        LOG_FAIL("vcs.publication_attachment", "stored intent or exact pair mismatch");
    if (!vcs_object_store_initialized(workspace) ||
        !vcs_object_store_init(workspace))
        LOG_FAIL("vcs.publication_attachment", "publication CAS barriers failed");
    struct vcs_zcode_publication_attachment_v1 checked;
    if (!vcs_object_put_addressed_repair(workspace, root, wire, sizeof(wire), NULL) ||
        !vcs_zcode_publication_attachment_load_verified(workspace, root,
            expected_signer, &checked))
        LOG_FAIL("vcs.publication_attachment", "stored attachment did not verify");
    memcpy(out_root, root, 32);
    return true;
}

static const uint8_t publication_result_magic[8] = {'Z','C','P','R','E','S','\r','\n'};
_Static_assert(VCS_ZCODE_PUBLICATION_RESULT_BODY_BYTES == 184u,
               "publication result body offsets");
_Static_assert(VCS_ZCODE_PUBLICATION_RESULT_WIRE_BYTES == 248u,
               "publication result wire offsets");

static enum vcs_zcode_dev_error publication_result_fields(
    const struct vcs_zcode_publication_result_v1 *r, bool signature)
{
    if (!r) return VCS_ZCODE_DEV_ERR_NULL;
    if (r->schema_version != VCS_ZCODE_DEV_VERSION)
        return VCS_ZCODE_DEV_ERR_VERSION;
    if (r->outcome < VCS_ZCODE_PUBLICATION_ACCEPTED ||
        r->outcome > VCS_ZCODE_PUBLICATION_UNKNOWN)
        return VCS_ZCODE_DEV_ERR_POLICY;
    if (!zcl_bytes_any_set(r->publication_root, 32) ||
        !zcl_bytes_any_set(r->attempt_root, 32) ||
        !zcl_bytes_any_set(r->evidence_root, 32))
        return VCS_ZCODE_DEV_ERR_ROOT_ZERO;
    if (r->attempted_unix <= 0) return VCS_ZCODE_DEV_ERR_TIME_ORDER;
    if (!zcl_bytes_any_set(r->producer_pubkey, 32))
        return VCS_ZCODE_DEV_ERR_PUBKEY_ZERO;
    if (signature && !zcl_bytes_any_set(r->signature, 64))
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_publication_result_validate(
    const struct vcs_zcode_publication_result_v1 *result)
{
    return publication_result_fields(result, true);
}

static enum vcs_zcode_dev_error publication_result_body(
    const struct vcs_zcode_publication_result_v1 *r,
    uint8_t out[VCS_ZCODE_PUBLICATION_RESULT_BODY_BYTES])
{
    enum vcs_zcode_dev_error error = publication_result_fields(r, false);
    if (error != VCS_ZCODE_DEV_OK) return error;
    memset(out, 0, VCS_ZCODE_PUBLICATION_RESULT_BODY_BYTES);
    memcpy(out, publication_result_magic, 8);
    zcl_write_u16_le(out + 8, r->schema_version);
    out[10] = r->outcome;
    memcpy(out + 16, r->publication_root, 32);
    memcpy(out + 48, r->attempt_root, 32);
    memcpy(out + 80, r->diagnostics_root, 32);
    memcpy(out + 112, r->evidence_root, 32);
    zcl_write_i64_le(out + 144, r->attempted_unix);
    memcpy(out + 152, r->producer_pubkey, 32);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_publication_result_serialize(
    const struct vcs_zcode_publication_result_v1 *r,
    uint8_t out[VCS_ZCODE_PUBLICATION_RESULT_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error error = publication_result_body(r, out);
    if (error != VCS_ZCODE_DEV_OK) return error;
    if (!zcl_bytes_any_set(r->signature, 64))
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    memcpy(out + VCS_ZCODE_PUBLICATION_RESULT_BODY_BYTES, r->signature, 64);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_publication_result_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_publication_result_v1 *out)
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire) return VCS_ZCODE_DEV_ERR_NULL;
    if (wire_len != VCS_ZCODE_PUBLICATION_RESULT_WIRE_BYTES)
        return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    if (memcmp(wire, publication_result_magic, 8) != 0 ||
        zcl_bytes_any_set(wire + 11, 5))
        return VCS_ZCODE_DEV_ERR_WIRE_MAGIC;
    struct vcs_zcode_publication_result_v1 r = {0};
    r.schema_version = zcl_read_u16_le(wire + 8);
    r.outcome = wire[10];
    memcpy(r.publication_root, wire + 16, 32);
    memcpy(r.attempt_root, wire + 48, 32);
    memcpy(r.diagnostics_root, wire + 80, 32);
    memcpy(r.evidence_root, wire + 112, 32);
    r.attempted_unix = zcl_read_i64_le(wire + 144);
    memcpy(r.producer_pubkey, wire + 152, 32);
    memcpy(r.signature, wire + 184, 64);
    enum vcs_zcode_dev_error error = publication_result_fields(&r, true);
    if (error == VCS_ZCODE_DEV_OK) *out = r;
    return error;
}

enum vcs_zcode_dev_error vcs_zcode_publication_result_root(
    const struct vcs_zcode_publication_result_v1 *r, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    uint8_t wire[VCS_ZCODE_PUBLICATION_RESULT_WIRE_BYTES];
    enum vcs_zcode_dev_error error = vcs_zcode_publication_result_serialize(r, wire);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_PUBLICATION_RESULT_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

static enum vcs_zcode_dev_error publication_result_signing_root(
    const struct vcs_zcode_publication_result_v1 *r, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_PUBLICATION_RESULT_BODY_BYTES];
    enum vcs_zcode_dev_error error = publication_result_body(r, body);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_PUBLICATION_RESULT_SIGNING_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

enum vcs_zcode_dev_error vcs_zcode_publication_result_seal(
    struct vcs_zcode_publication_result_v1 *r,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!r || !secret || !pubkey) return VCS_ZCODE_DEV_ERR_NULL;
    memcpy(r->producer_pubkey, pubkey, 32);
    uint8_t root[32];
    enum vcs_zcode_dev_error error = publication_result_signing_root(r, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_seal_root(root, secret, pubkey, r->signature)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

enum vcs_zcode_dev_error vcs_zcode_publication_result_verify(
    const struct vcs_zcode_publication_result_v1 *r,
    const uint8_t expected_signer[32])
{
    if (!expected_signer) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error error = publication_result_fields(r, true);
    if (error != VCS_ZCODE_DEV_OK) return error;
    uint8_t root[32];
    error = publication_result_signing_root(r, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_verify_root(root, r->signature,
                r->producer_pubkey, expected_signer)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

bool vcs_zcode_publication_result_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t publisher_signer[32], const uint8_t producer_signer[32],
    struct vcs_zcode_publication_result_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!workspace || !workspace[0] || !root || !publisher_signer ||
        !producer_signer) return false;
    uint8_t *wire = NULL, checked[32];
    size_t length = 0;
    struct vcs_zcode_publication_result_v1 result;
    bool ok = vcs_object_load_raw_bounded(workspace, root,
            VCS_ZCODE_PUBLICATION_RESULT_WIRE_BYTES, &wire, &length) == 0 &&
        vcs_zcode_publication_result_parse(wire, length, &result) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_publication_result_root(&result, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0 &&
        vcs_zcode_publication_result_verify(&result, producer_signer) == VCS_ZCODE_DEV_OK;
    free(wire);
    struct vcs_zcode_publication_v1 intent;
    if (ok) ok = vcs_zcode_publication_load_verified(workspace,
            result.publication_root, publisher_signer, &intent);
    if (ok) *out = result;
    return ok;
}

bool vcs_zcode_publication_result_store_verified(
    const char *workspace, const struct vcs_zcode_publication_result_v1 *result,
    const uint8_t publisher_signer[32], const uint8_t producer_signer[32],
    uint8_t out_root[32])
{
    if (!out_root) LOG_FAIL("vcs.publication_result", "missing output root");
    memset(out_root, 0, 32);
    if (!workspace || !workspace[0] || !result || !publisher_signer ||
        !producer_signer)
        LOG_FAIL("vcs.publication_result", "missing store input");
    uint8_t root[32], wire[VCS_ZCODE_PUBLICATION_RESULT_WIRE_BYTES];
    if (vcs_zcode_publication_result_verify(result, producer_signer) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_publication_result_root(result, root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_publication_result_serialize(result, wire) != VCS_ZCODE_DEV_OK)
        LOG_FAIL("vcs.publication_result", "result signature or canonical bytes refused");
    if (!vcs_object_store_initialized(workspace))
        LOG_FAIL("vcs.publication_result", "publication CAS is not initialized");
    if (!vcs_object_store_init(workspace))
        LOG_FAIL("vcs.publication_result", "publication CAS parent barriers failed");
    struct vcs_zcode_publication_v1 intent;
    if (!vcs_zcode_publication_load_verified(workspace, result->publication_root,
            publisher_signer, &intent))
        LOG_FAIL("vcs.publication_result", "stored publication intent missing");
    struct vcs_zcode_publication_result_v1 checked;
    if (!vcs_object_put_addressed_repair(
            workspace, root, wire, sizeof(wire), NULL) ||
        !vcs_zcode_publication_result_load_verified(workspace, root,
            publisher_signer, producer_signer, &checked))
        LOG_FAIL("vcs.publication_result", "stored publication result did not verify");
    memcpy(out_root, root, 32);
    return true;
}

static const uint8_t remote_receipt_magic[8] = {'Z','C','R','R','C','P','\r','\n'};
_Static_assert(VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES == 376u,
               "remote receipt body offsets");
_Static_assert(VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES == 440u,
               "remote receipt wire offsets");

static enum vcs_zcode_dev_error remote_receipt_fields(
    const struct vcs_zcode_remote_receipt_v1 *r, bool signature)
{
    if (!r) return VCS_ZCODE_DEV_ERR_NULL;
    if (r->schema_version != VCS_ZCODE_DEV_VERSION)
        return VCS_ZCODE_DEV_ERR_VERSION;
    const uint8_t *roots[] = {r->publication_root, r->target_identity_root,
        r->fetched_main_source_root, r->verified_ancestry_root,
        r->evidence_root};
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!zcl_bytes_any_set(roots[i], 32))
            return VCS_ZCODE_DEV_ERR_ROOT_ZERO;
    if (!publication_oid_valid(r->fetched_main_tip, r->git_object_format) ||
        !publication_ref_valid(r->target_ref))
        return VCS_ZCODE_DEV_ERR_POLICY;
    if (r->observed_unix <= 0) return VCS_ZCODE_DEV_ERR_TIME_ORDER;
    if (!zcl_bytes_any_set(r->observer_pubkey, 32))
        return VCS_ZCODE_DEV_ERR_PUBKEY_ZERO;
    if (signature && !zcl_bytes_any_set(r->signature, 64))
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_validate(
    const struct vcs_zcode_remote_receipt_v1 *receipt)
{
    return remote_receipt_fields(receipt, true);
}

static enum vcs_zcode_dev_error remote_receipt_body(
    const struct vcs_zcode_remote_receipt_v1 *r,
    uint8_t out[VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES])
{
    enum vcs_zcode_dev_error error = remote_receipt_fields(r, false);
    if (error != VCS_ZCODE_DEV_OK) return error;
    memset(out, 0, VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES);
    memcpy(out, remote_receipt_magic, 8);
    zcl_write_u16_le(out + 8, r->schema_version);
    out[10] = r->git_object_format;
    memcpy(out + 16, r->publication_root, 32);
    memcpy(out + 48, r->target_identity_root, 32);
    memcpy(out + 80, r->target_ref, VCS_ZCODE_PUBLICATION_REF_BYTES);
    memcpy(out + 208, r->fetched_main_tip, 32);
    memcpy(out + 240, r->fetched_main_source_root, 32);
    memcpy(out + 272, r->verified_ancestry_root, 32);
    memcpy(out + 304, r->evidence_root, 32);
    zcl_write_i64_le(out + 336, r->observed_unix);
    memcpy(out + 344, r->observer_pubkey, 32);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_serialize(
    const struct vcs_zcode_remote_receipt_v1 *r,
    uint8_t out[VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error error = remote_receipt_body(r, out);
    if (error != VCS_ZCODE_DEV_OK) return error;
    if (!zcl_bytes_any_set(r->signature, 64))
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    memcpy(out + VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES, r->signature, 64);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_remote_receipt_v1 *out)
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire) return VCS_ZCODE_DEV_ERR_NULL;
    if (wire_len != VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES)
        return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    if (memcmp(wire, remote_receipt_magic, 8) != 0 ||
        zcl_bytes_any_set(wire + 11, 5))
        return VCS_ZCODE_DEV_ERR_WIRE_MAGIC;
    struct vcs_zcode_remote_receipt_v1 r = {0};
    r.schema_version = zcl_read_u16_le(wire + 8);
    r.git_object_format = wire[10];
    memcpy(r.publication_root, wire + 16, 32);
    memcpy(r.target_identity_root, wire + 48, 32);
    memcpy(r.target_ref, wire + 80, VCS_ZCODE_PUBLICATION_REF_BYTES);
    memcpy(r.fetched_main_tip, wire + 208, 32);
    memcpy(r.fetched_main_source_root, wire + 240, 32);
    memcpy(r.verified_ancestry_root, wire + 272, 32);
    memcpy(r.evidence_root, wire + 304, 32);
    r.observed_unix = zcl_read_i64_le(wire + 336);
    memcpy(r.observer_pubkey, wire + 344, 32);
    memcpy(r.signature, wire + 376, 64);
    enum vcs_zcode_dev_error error = remote_receipt_fields(&r, true);
    if (error == VCS_ZCODE_DEV_OK) *out = r;
    return error;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_root(
    const struct vcs_zcode_remote_receipt_v1 *r, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    uint8_t wire[VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES];
    enum vcs_zcode_dev_error error = vcs_zcode_remote_receipt_serialize(r, wire);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_REMOTE_RECEIPT_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

static enum vcs_zcode_dev_error remote_receipt_signing_root(
    const struct vcs_zcode_remote_receipt_v1 *r, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES];
    enum vcs_zcode_dev_error error = remote_receipt_body(r, body);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_REMOTE_RECEIPT_SIGNING_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_seal(
    struct vcs_zcode_remote_receipt_v1 *r,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!r || !secret || !pubkey) return VCS_ZCODE_DEV_ERR_NULL;
    memcpy(r->observer_pubkey, pubkey, 32);
    uint8_t root[32];
    enum vcs_zcode_dev_error error = remote_receipt_signing_root(r, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_seal_root(root, secret, pubkey, r->signature)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_verify(
    const struct vcs_zcode_remote_receipt_v1 *r,
    const uint8_t expected_signer[32])
{
    if (!expected_signer) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error error = remote_receipt_fields(r, true);
    if (error != VCS_ZCODE_DEV_OK) return error;
    uint8_t root[32];
    error = remote_receipt_signing_root(r, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_verify_root(root, r->signature,
                r->observer_pubkey, expected_signer)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

static bool remote_receipt_target_matches(
    const struct vcs_zcode_remote_receipt_v1 *r,
    const struct vcs_zcode_publication_v1 *intent)
{
    uint8_t root[32];
    return vcs_zcode_publication_root(intent, root) == VCS_ZCODE_DEV_OK &&
        memcmp(root, r->publication_root, 32) == 0 &&
        r->git_object_format == intent->git_object_format &&
        memcmp(r->target_identity_root, intent->target_identity_root, 32) == 0 &&
        memcmp(r->target_ref, intent->target_ref,
               VCS_ZCODE_PUBLICATION_REF_BYTES) == 0;
}

static bool remote_receipt_intent_matches(
    const struct vcs_zcode_remote_receipt_v1 *r,
    const struct vcs_zcode_publication_v1 *intent)
{
    return remote_receipt_target_matches(r, intent) &&
        memcmp(r->fetched_main_tip, intent->head_commit, 32) == 0;
}

bool vcs_zcode_remote_receipt_candidate_matches(
    const struct vcs_zcode_remote_receipt_v1 *receipt,
    const struct vcs_zcode_publication_v1 *intent,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t publisher_signer[32],
    const uint8_t observer_signer[32])
{
    if (!receipt || !intent || !candidate || !publisher_signer ||
        !observer_signer)
        LOG_FAIL("vcs.remote_receipt", "missing candidate binding input");
    uint8_t candidate_root[32];
    if (vcs_zcode_publication_verify(intent, publisher_signer) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_remote_receipt_verify(receipt, observer_signer) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, candidate_root) != VCS_ZCODE_DEV_OK)
        LOG_FAIL("vcs.remote_receipt", "candidate binding authenticity refused");
    if (!remote_receipt_intent_matches(receipt, intent) ||
        memcmp(intent->candidate_root, candidate_root, 32) != 0 ||
        memcmp(receipt->fetched_main_tip, intent->head_commit, 32) != 0 ||
        memcmp(receipt->fetched_main_source_root,
               candidate->candidate_source_root, 32) != 0)
        LOG_FAIL("vcs.remote_receipt", "candidate, intended head, or fetched source root mismatch");
    return true;
}

bool vcs_zcode_remote_receipt_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t publisher_signer[32], const uint8_t observer_signer[32],
    struct vcs_zcode_remote_receipt_v1 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!workspace || !workspace[0] || !root || !publisher_signer ||
        !observer_signer) return false;
    uint8_t *wire = NULL, checked[32];
    size_t length = 0;
    struct vcs_zcode_remote_receipt_v1 receipt;
    bool ok = vcs_object_load_raw_bounded(workspace, root,
            VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES, &wire, &length) == 0 &&
        vcs_zcode_remote_receipt_parse(wire, length, &receipt) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_remote_receipt_root(&receipt, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0 &&
        vcs_zcode_remote_receipt_verify(&receipt, observer_signer) == VCS_ZCODE_DEV_OK;
    free(wire);
    struct vcs_zcode_publication_v1 intent;
    if (ok) ok = vcs_zcode_publication_load_verified(workspace,
            receipt.publication_root, publisher_signer, &intent) &&
        remote_receipt_intent_matches(&receipt, &intent);
    if (ok) *out = receipt;
    return ok;
}

bool vcs_zcode_remote_receipt_load_candidate_bound(
    const char *workspace, const uint8_t receipt_root[32],
    const uint8_t publisher_signer[32],
    const uint8_t observer_signer[32],
    struct vcs_zcode_remote_receipt_v1 *out_receipt,
    struct vcs_zcode_candidate_v1 *out_candidate)
{
    if (!out_receipt || !out_candidate)
        LOG_FAIL("vcs.remote_receipt", "missing recovery output");
    memset(out_receipt, 0, sizeof(*out_receipt));
    memset(out_candidate, 0, sizeof(*out_candidate));
    if (!workspace || !workspace[0] || !receipt_root || !publisher_signer ||
        !observer_signer)
        LOG_FAIL("vcs.remote_receipt", "missing recovery input");
    struct vcs_zcode_remote_receipt_v1 receipt;
    struct vcs_zcode_publication_v1 intent;
    if (!vcs_zcode_remote_receipt_load_verified(workspace, receipt_root,
            publisher_signer, observer_signer, &receipt) ||
        !vcs_zcode_publication_load_verified(workspace,
            receipt.publication_root, publisher_signer, &intent))
        LOG_FAIL("vcs.remote_receipt", "receipt or intent recovery refused");
    uint8_t *wire = NULL, checked[32];
    size_t length = 0;
    struct vcs_zcode_candidate_v1 candidate;
    bool ok = vcs_object_load_raw_bounded(workspace, intent.candidate_root,
            VCS_ZCODE_CANDIDATE_WIRE_BYTES, &wire, &length) == 0 &&
        vcs_zcode_candidate_parse(wire, length, &candidate) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(&candidate, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(checked, intent.candidate_root, 32) == 0;
    free(wire);
    if (!ok || !vcs_zcode_remote_receipt_candidate_matches(&receipt, &intent,
            &candidate, publisher_signer, observer_signer))
        LOG_FAIL("vcs.remote_receipt", "candidate recovery or source binding refused");
    *out_receipt = receipt;
    *out_candidate = candidate;
    return true;
}

static bool remote_receipt_store_payload(
    const struct vcs_zcode_remote_receipt_v1 *receipt,
    const uint8_t observer_signer[32], uint8_t root[32],
    uint8_t wire[VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES])
{
    return vcs_zcode_remote_receipt_verify(receipt, observer_signer) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_remote_receipt_root(receipt, root) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_remote_receipt_serialize(receipt, wire) == VCS_ZCODE_DEV_OK;
}

bool vcs_zcode_remote_receipt_store_verified(
    const char *workspace, const struct vcs_zcode_remote_receipt_v1 *receipt,
    const uint8_t publisher_signer[32], const uint8_t observer_signer[32],
    uint8_t out_root[32])
{
    if (!out_root) LOG_FAIL("vcs.remote_receipt", "missing output root");
    memset(out_root, 0, 32);
    if (!workspace || !workspace[0] || !receipt || !publisher_signer ||
        !observer_signer)
        LOG_FAIL("vcs.remote_receipt", "missing store input");
    uint8_t root[32], wire[VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES];
    if (!remote_receipt_store_payload(receipt, observer_signer, root, wire))
        LOG_FAIL("vcs.remote_receipt", "receipt signature or canonical bytes refused");
    if (!vcs_object_store_initialized(workspace))
        LOG_FAIL("vcs.remote_receipt", "publication CAS is not initialized");
    if (!vcs_object_store_init(workspace))
        LOG_FAIL("vcs.remote_receipt", "publication CAS parent barriers failed");
    struct vcs_zcode_publication_v1 intent;
    if (!vcs_zcode_publication_load_verified(workspace, receipt->publication_root,
            publisher_signer, &intent) || !remote_receipt_intent_matches(receipt, &intent))
        LOG_FAIL("vcs.remote_receipt", "stored publication intent missing or mismatched");
    struct vcs_zcode_remote_receipt_v1 checked;
    if (!vcs_object_put_addressed_repair(
            workspace, root, wire, sizeof(wire), NULL) ||
        !vcs_zcode_remote_receipt_load_verified(workspace, root,
            publisher_signer, observer_signer, &checked))
        LOG_FAIL("vcs.remote_receipt", "stored remote receipt did not verify");
    memcpy(out_root, root, 32);
    return true;
}

static const uint8_t remote_receipt_v2_magic[8] =
    {'Z','C','R','R','C','2','\r','\n'};
_Static_assert(VCS_ZCODE_REMOTE_RECEIPT_V2_BODY_BYTES ==
    VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES + 32u, "remote receipt v2 body offsets");

static enum vcs_zcode_dev_error remote_receipt_v2_body(
    const struct vcs_zcode_remote_receipt_v2 *r,
    uint8_t out[VCS_ZCODE_REMOTE_RECEIPT_V2_BODY_BYTES])
{
    if (!r) return VCS_ZCODE_DEV_ERR_NULL;
    if (r->observation.schema_version != VCS_ZCODE_REMOTE_RECEIPT_V2_VERSION)
        return VCS_ZCODE_DEV_ERR_VERSION;
    if (!zcl_bytes_any_set(r->intended_head_source_root, 32))
        return VCS_ZCODE_DEV_ERR_ROOT_ZERO;
    struct vcs_zcode_remote_receipt_v1 prior = r->observation;
    prior.schema_version = VCS_ZCODE_DEV_VERSION;
    enum vcs_zcode_dev_error error = remote_receipt_body(&prior, out);
    if (error != VCS_ZCODE_DEV_OK) return error;
    memcpy(out, remote_receipt_v2_magic, sizeof(remote_receipt_v2_magic));
    zcl_write_u16_le(out + 8, VCS_ZCODE_REMOTE_RECEIPT_V2_VERSION);
    memcpy(out + VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES,
           r->intended_head_source_root, 32);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_serialize(
    const struct vcs_zcode_remote_receipt_v2 *r,
    uint8_t out[VCS_ZCODE_REMOTE_RECEIPT_V2_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    enum vcs_zcode_dev_error error = remote_receipt_v2_body(r, out);
    if (error != VCS_ZCODE_DEV_OK) return error;
    if (!zcl_bytes_any_set(r->observation.signature, 64))
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    memcpy(out + VCS_ZCODE_REMOTE_RECEIPT_V2_BODY_BYTES,
           r->observation.signature, 64);
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_parse(
    const uint8_t *wire, size_t wire_len,
    struct vcs_zcode_remote_receipt_v2 *out)
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire) return VCS_ZCODE_DEV_ERR_NULL;
    if (wire_len != VCS_ZCODE_REMOTE_RECEIPT_V2_WIRE_BYTES)
        return VCS_ZCODE_DEV_ERR_WIRE_SIZE;
    if (memcmp(wire, remote_receipt_v2_magic, 8) != 0)
        return VCS_ZCODE_DEV_ERR_WIRE_MAGIC;
    if (zcl_read_u16_le(wire + 8) != VCS_ZCODE_REMOTE_RECEIPT_V2_VERSION)
        return VCS_ZCODE_DEV_ERR_VERSION;
    uint8_t prior_wire[VCS_ZCODE_REMOTE_RECEIPT_WIRE_BYTES];
    memcpy(prior_wire, wire, VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES);
    memcpy(prior_wire, remote_receipt_magic, sizeof(remote_receipt_magic));
    zcl_write_u16_le(prior_wire + 8, VCS_ZCODE_DEV_VERSION);
    memcpy(prior_wire + VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES,
           wire + VCS_ZCODE_REMOTE_RECEIPT_V2_BODY_BYTES, 64);
    struct vcs_zcode_remote_receipt_v2 parsed = {0};
    enum vcs_zcode_dev_error error = vcs_zcode_remote_receipt_parse(
        prior_wire, sizeof(prior_wire), &parsed.observation);
    if (error != VCS_ZCODE_DEV_OK) return error;
    parsed.observation.schema_version = VCS_ZCODE_REMOTE_RECEIPT_V2_VERSION;
    memcpy(parsed.intended_head_source_root,
           wire + VCS_ZCODE_REMOTE_RECEIPT_BODY_BYTES, 32);
    if (!zcl_bytes_any_set(parsed.intended_head_source_root, 32))
        return VCS_ZCODE_DEV_ERR_ROOT_ZERO;
    *out = parsed;
    return VCS_ZCODE_DEV_OK;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_root(
    const struct vcs_zcode_remote_receipt_v2 *r, uint8_t out[32])
{
    if (!out) return VCS_ZCODE_DEV_ERR_NULL;
    uint8_t wire[VCS_ZCODE_REMOTE_RECEIPT_V2_WIRE_BYTES];
    enum vcs_zcode_dev_error error = vcs_zcode_remote_receipt_v2_serialize(r, wire);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_REMOTE_RECEIPT_V2_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, sizeof(wire), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

static enum vcs_zcode_dev_error remote_receipt_v2_signing_root(
    const struct vcs_zcode_remote_receipt_v2 *r, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_REMOTE_RECEIPT_V2_BODY_BYTES];
    enum vcs_zcode_dev_error error = remote_receipt_v2_body(r, body);
    if (error != VCS_ZCODE_DEV_OK) return error;
    static const char domain[] = VCS_ZCODE_REMOTE_RECEIPT_V2_SIGNING_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), body, sizeof(body), out)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_NULL;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_seal(
    struct vcs_zcode_remote_receipt_v2 *r,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!r || !secret || !pubkey) return VCS_ZCODE_DEV_ERR_NULL;
    memcpy(r->observation.observer_pubkey, pubkey, 32);
    uint8_t root[32];
    enum vcs_zcode_dev_error error = remote_receipt_v2_signing_root(r, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_seal_root(root, secret, pubkey,
                r->observation.signature)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

enum vcs_zcode_dev_error vcs_zcode_remote_receipt_v2_verify(
    const struct vcs_zcode_remote_receipt_v2 *r,
    const uint8_t expected_signer[32])
{
    if (!r || !expected_signer) return VCS_ZCODE_DEV_ERR_NULL;
    if (!zcl_bytes_any_set(r->observation.signature, 64))
        return VCS_ZCODE_DEV_ERR_SIGNATURE;
    uint8_t root[32];
    enum vcs_zcode_dev_error error = remote_receipt_v2_signing_root(r, root);
    if (error != VCS_ZCODE_DEV_OK) return error;
    return vcs_signed_evidence_verify_root(root, r->observation.signature,
                r->observation.observer_pubkey, expected_signer)
        ? VCS_ZCODE_DEV_OK : VCS_ZCODE_DEV_ERR_SIGNATURE;
}

bool vcs_zcode_remote_receipt_v2_candidate_matches(
    const struct vcs_zcode_remote_receipt_v2 *receipt,
    const struct vcs_zcode_publication_v1 *intent,
    const struct vcs_zcode_candidate_v1 *candidate,
    const uint8_t publisher_signer[32],
    const uint8_t observer_signer[32])
{
    if (!receipt || !intent || !candidate || !publisher_signer ||
        !observer_signer)
        LOG_FAIL("vcs.remote_receipt", "missing v2 candidate binding input");
    uint8_t candidate_root[32];
    if (vcs_zcode_publication_verify(intent, publisher_signer) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_remote_receipt_v2_verify(receipt, observer_signer) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_candidate_root(candidate, candidate_root) != VCS_ZCODE_DEV_OK)
        LOG_FAIL("vcs.remote_receipt", "v2 candidate authenticity refused");
    if (!remote_receipt_target_matches(&receipt->observation, intent) ||
        memcmp(intent->candidate_root, candidate_root, 32) != 0 ||
        memcmp(receipt->intended_head_source_root,
               candidate->candidate_source_root, 32) != 0)
        LOG_FAIL("vcs.remote_receipt", "v2 intended-head source binding refused");
    if (memcmp(receipt->observation.fetched_main_tip,
               intent->head_commit, 32) == 0 &&
        memcmp(receipt->observation.fetched_main_source_root,
               receipt->intended_head_source_root, 32) != 0)
        LOG_FAIL("vcs.remote_receipt", "v2 exact head has inconsistent source root");
    return true;
}

static bool remote_receipt_v2_load_candidate(
    const char *workspace, const uint8_t root[32],
    struct vcs_zcode_candidate_v1 *candidate)
{
    uint8_t *wire = NULL, checked[32];
    size_t length = 0;
    bool ok = vcs_object_load_raw_bounded(workspace, root,
            VCS_ZCODE_CANDIDATE_WIRE_BYTES, &wire, &length) == 0 &&
        vcs_zcode_candidate_parse(wire, length, candidate) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(candidate, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(checked, root, 32) == 0;
    free(wire);
    return ok;
}

bool vcs_zcode_remote_receipt_v2_load_verified(
    const char *workspace, const uint8_t root[32],
    const uint8_t publisher_signer[32], const uint8_t observer_signer[32],
    struct vcs_zcode_remote_receipt_v2 *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!workspace || !workspace[0] || !root || !publisher_signer ||
        !observer_signer) return false;
    uint8_t *wire = NULL, checked[32];
    size_t length = 0;
    struct vcs_zcode_remote_receipt_v2 receipt = {0};
    bool ok = vcs_object_load_raw_bounded(workspace, root,
            VCS_ZCODE_REMOTE_RECEIPT_V2_WIRE_BYTES, &wire, &length) == 0 &&
        vcs_zcode_remote_receipt_v2_parse(wire, length, &receipt) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_remote_receipt_v2_root(&receipt, checked) == VCS_ZCODE_DEV_OK &&
        memcmp(root, checked, 32) == 0;
    free(wire);
    struct vcs_zcode_publication_v1 intent;
    struct vcs_zcode_candidate_v1 candidate;
    if (ok) ok = vcs_zcode_publication_load_verified(workspace,
            receipt.observation.publication_root, publisher_signer, &intent) &&
        remote_receipt_v2_load_candidate(workspace, intent.candidate_root,
                                         &candidate) &&
        vcs_zcode_remote_receipt_v2_candidate_matches(&receipt, &intent,
            &candidate, publisher_signer, observer_signer);
    if (ok) *out = receipt;
    return ok;
}

static bool remote_receipt_v2_store_context(
    const char *workspace, const struct vcs_zcode_remote_receipt_v2 *receipt,
    const uint8_t publisher_signer[32], const uint8_t observer_signer[32])
{
    struct vcs_zcode_publication_v1 intent;
    struct vcs_zcode_candidate_v1 candidate;
    return vcs_zcode_publication_load_verified(workspace,
            receipt->observation.publication_root, publisher_signer, &intent) &&
        remote_receipt_v2_load_candidate(workspace, intent.candidate_root,
                                         &candidate) &&
        vcs_zcode_remote_receipt_v2_candidate_matches(receipt, &intent,
            &candidate, publisher_signer, observer_signer);
}

bool vcs_zcode_remote_receipt_v2_store_verified(
    const char *workspace, const struct vcs_zcode_remote_receipt_v2 *receipt,
    const uint8_t publisher_signer[32], const uint8_t observer_signer[32],
    uint8_t out_root[32])
{
    if (!out_root) LOG_FAIL("vcs.remote_receipt", "missing v2 output root");
    memset(out_root, 0, 32);
    if (!workspace || !workspace[0] || !receipt || !publisher_signer ||
        !observer_signer)
        LOG_FAIL("vcs.remote_receipt", "missing v2 store input");
    if (!vcs_object_store_initialized(workspace) ||
        !vcs_object_store_init(workspace))
        LOG_FAIL("vcs.remote_receipt", "v2 CAS unavailable");
    if (!remote_receipt_v2_store_context(workspace, receipt,
            publisher_signer, observer_signer))
        LOG_FAIL("vcs.remote_receipt", "v2 intent or candidate unavailable");
    uint8_t root[32], wire[VCS_ZCODE_REMOTE_RECEIPT_V2_WIRE_BYTES];
    if (vcs_zcode_remote_receipt_v2_root(receipt, root) != VCS_ZCODE_DEV_OK ||
        vcs_zcode_remote_receipt_v2_serialize(receipt, wire) != VCS_ZCODE_DEV_OK ||
        !vcs_object_put_addressed_repair(workspace, root, wire, sizeof(wire), NULL))
        LOG_FAIL("vcs.remote_receipt", "v2 CAS persistence refused");
    struct vcs_zcode_remote_receipt_v2 checked;
    if (!vcs_zcode_remote_receipt_v2_load_verified(workspace, root,
            publisher_signer, observer_signer, &checked))
        LOG_FAIL("vcs.remote_receipt", "v2 CAS reload refused");
    memcpy(out_root, root, 32);
    return true;
}
