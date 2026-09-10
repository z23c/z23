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
