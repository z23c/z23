/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Canonical bounded zcl.science_statement.v1 and relation-set wires. */

#include "vcs/zcode_science.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "vcs/signed_evidence.h"

#include <string.h>

static const uint8_t statement_magic[8] = {'Z','C','S','T','M','T','\r','\n'};
static const uint8_t relation_set_magic[8] =
    {'Z','C','S','R','E','L','\r','\n'};

static bool root_nonzero(const uint8_t root[32])
{
    return zcl_bytes_any_set(root, 32);
}

static void put_bytes(uint8_t *wire, size_t *off, const void *src, size_t len)
{
    memcpy(wire + *off, src, len);
    *off += len;
}

static void put_u16(uint8_t *wire, size_t *off, uint16_t value)
{
    zcl_write_u16_le(wire + *off, value);
    *off += 2;
}

static void put_u64(uint8_t *wire, size_t *off, uint64_t value)
{
    zcl_write_u64_le(wire + *off, value);
    *off += 8;
}

static void get_bytes(const uint8_t *wire, size_t *off, void *out, size_t len)
{
    memcpy(out, wire + *off, len);
    *off += len;
}

static uint16_t get_u16(const uint8_t *wire, size_t *off)
{
    uint16_t value = zcl_read_u16_le(wire + *off);
    *off += 2;
    return value;
}

static uint64_t get_u64(const uint8_t *wire, size_t *off)
{
    uint64_t value = zcl_read_u64_le(wire + *off);
    *off += 8;
    return value;
}

static uint8_t relation_set_types(
    const struct vcs_zcode_science_relation_set_v1 *relations);
static uint8_t relation_type_count(uint8_t types);
static enum vcs_zcode_science_error empty_relation_set_root(uint8_t out[32]);

static enum vcs_zcode_science_error statement_fields(
    const struct vcs_zcode_science_statement_v1 *s, bool require_signature)
{
    if (!s) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (s->schema_version != VCS_ZCODE_SCIENCE_STATEMENT_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    if (s->profile == 0 || s->profile >= VCS_ZCODE_SCIENCE_PROFILE_COUNT)
        return VCS_ZCODE_SCIENCE_ERR_PROFILE;
    if (s->access == 0 || s->access >= VCS_ZCODE_SCIENCE_ACCESS_COUNT ||
        s->privacy == 0 || s->privacy >= VCS_ZCODE_SCIENCE_PRIVACY_COUNT ||
        s->redistribution == 0 ||
        s->redistribution >= VCS_ZCODE_SCIENCE_REDISTRIBUTION_COUNT)
        return VCS_ZCODE_SCIENCE_ERR_RIGHTS;
    if (s->authorship == 0 ||
        s->authorship >= VCS_ZCODE_SCIENCE_AUTHORSHIP_COUNT)
        return VCS_ZCODE_SCIENCE_ERR_AUTHORSHIP;
    const uint8_t *roots[] = {
        s->subject_root, s->predicate_body_root, s->profile_schema_root,
        s->provenance_root, s->activity_root, s->input_root,
        s->authorship_assertion_root, s->license_root,
        s->access_policy_root, s->privacy_policy_root,
        s->external_identifiers_root, s->citations_root, s->relations_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    if (s->relation_count > VCS_ZCODE_SCIENCE_RELATION_MAX)
        return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    if ((s->relation_types & ~VCS_ZCODE_SCIENCE_RELATION_KNOWN_MASK) != 0)
        return VCS_ZCODE_SCIENCE_ERR_RELATION_TYPE;
    if (s->relation_count == 0) {
        uint8_t empty_root[32];
        if (s->relation_types != 0 ||
            empty_relation_set_root(empty_root) != VCS_ZCODE_SCIENCE_OK ||
            memcmp(s->relations_root, empty_root, sizeof(empty_root)) != 0)
            return VCS_ZCODE_SCIENCE_ERR_RELATION_MISMATCH;
    } else if (s->relation_types == 0 ||
               s->relation_count < relation_type_count(s->relation_types)) {
        return VCS_ZCODE_SCIENCE_ERR_RELATION_TYPE;
    }
    if (s->observed_unix <= 0) return VCS_ZCODE_SCIENCE_ERR_TIME_ORDER;
    if (s->embargo_until_unix != 0 &&
        s->embargo_until_unix < s->observed_unix)
        return VCS_ZCODE_SCIENCE_ERR_EMBARGO;
    bool has_pubkey = zcl_bytes_any_set(s->signer_pubkey, 32);
    bool has_signature = zcl_bytes_any_set(s->signature, 64);
    if ((s->authorship == VCS_ZCODE_SCIENCE_AUTHORSHIP_ASSERTED &&
         (has_pubkey || has_signature)) ||
        (s->authorship == VCS_ZCODE_SCIENCE_AUTHORSHIP_SIGNED &&
         (!has_pubkey || (require_signature && !has_signature))))
        return VCS_ZCODE_SCIENCE_ERR_AUTHORSHIP;
    return VCS_ZCODE_SCIENCE_OK;
}

static enum vcs_zcode_science_error statement_body(
    const struct vcs_zcode_science_statement_v1 *s,
    uint8_t out[VCS_ZCODE_SCIENCE_STATEMENT_BODY_BYTES],
    bool require_signature)
{
    if (!out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, VCS_ZCODE_SCIENCE_STATEMENT_BODY_BYTES);
    enum vcs_zcode_science_error error =
        statement_fields(s, require_signature);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    size_t off = 0;
    put_bytes(out, &off, statement_magic, sizeof(statement_magic));
    put_u16(out, &off, s->schema_version);
    out[off++] = s->profile;
    out[off++] = s->access;
    out[off++] = s->privacy;
    out[off++] = s->redistribution;
    out[off++] = s->authorship;
    out[off++] = s->relation_types;
    put_u16(out, &off, s->relation_count);
    const uint8_t *roots[] = {
        s->subject_root, s->predicate_body_root, s->profile_schema_root,
        s->provenance_root, s->activity_root, s->input_root,
        s->authorship_assertion_root, s->license_root,
        s->access_policy_root, s->privacy_policy_root,
        s->external_identifiers_root, s->citations_root, s->relations_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        put_bytes(out, &off, roots[i], 32);
    put_u64(out, &off, (uint64_t)s->observed_unix);
    put_u64(out, &off, (uint64_t)s->embargo_until_unix);
    put_bytes(out, &off, s->signer_pubkey, 32);
    return off == VCS_ZCODE_SCIENCE_STATEMENT_BODY_BYTES
               ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error vcs_zcode_science_relation_set_validate(
    const struct vcs_zcode_science_relation_set_v1 *relations)
{
    if (!relations) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (relations->schema_version != VCS_ZCODE_SCIENCE_RELATION_SET_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    if (relations->row_count > VCS_ZCODE_SCIENCE_RELATION_MAX)
        return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    for (size_t i = 0; i < relations->row_count; i++) {
        const struct vcs_zcode_science_relation_v1 *row = &relations->rows[i];
        if (row->type < VCS_ZCODE_SCIENCE_RELATION_SUPPORT ||
            row->type >= VCS_ZCODE_SCIENCE_RELATION_COUNT)
            return VCS_ZCODE_SCIENCE_ERR_RELATION_TYPE;
        if (!root_nonzero(row->statement_root))
            return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
        if (i > 0) {
            const struct vcs_zcode_science_relation_v1 *prev =
                &relations->rows[i - 1];
            int root_order = memcmp(prev->statement_root,
                                    row->statement_root, 32);
            if (prev->type > row->type ||
                (prev->type == row->type && root_order >= 0))
                return VCS_ZCODE_SCIENCE_ERR_RELATION_ORDER;
        }
    }
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_science_relation_set_serialize(
    const struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t out[VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES],
    size_t *out_len)
{
    if (out_len) *out_len = 0;
    if (!out || !out_len) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES);
    enum vcs_zcode_science_error error =
        vcs_zcode_science_relation_set_validate(relations);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    size_t off = 0;
    put_bytes(out, &off, relation_set_magic, sizeof(relation_set_magic));
    put_u16(out, &off, relations->schema_version);
    put_u16(out, &off, relations->row_count);
    for (size_t i = 0; i < relations->row_count; i++) {
        out[off++] = relations->rows[i].type;
        put_bytes(out, &off, relations->rows[i].statement_root, 32);
    }
    size_t expected = VCS_ZCODE_SCIENCE_RELATION_SET_HEADER_BYTES +
        (size_t)relations->row_count * VCS_ZCODE_SCIENCE_RELATION_ROW_BYTES;
    if (off != expected) return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    *out_len = off;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_science_relation_set_parse(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_science_relation_set_v1 *out)
{
    if (!out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (len < VCS_ZCODE_SCIENCE_RELATION_SET_HEADER_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, relation_set_magic, sizeof(relation_set_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(relation_set_magic);
    out->schema_version = get_u16(wire, &off);
    out->row_count = get_u16(wire, &off);
    if (out->row_count > VCS_ZCODE_SCIENCE_RELATION_MAX) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    }
    size_t expected = VCS_ZCODE_SCIENCE_RELATION_SET_HEADER_BYTES +
        (size_t)out->row_count * VCS_ZCODE_SCIENCE_RELATION_ROW_BYTES;
    if (len != expected) {
        memset(out, 0, sizeof(*out));
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    }
    for (size_t i = 0; i < out->row_count; i++) {
        out->rows[i].type = wire[off++];
        get_bytes(wire, &off, out->rows[i].statement_root, 32);
    }
    enum vcs_zcode_science_error error =
        vcs_zcode_science_relation_set_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_science_relation_set_root(
    const struct vcs_zcode_science_relation_set_v1 *relations,
    uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_SCIENCE_RELATION_SET_MAX_WIRE_BYTES];
    size_t wire_len = 0;
    if (out) memset(out, 0, 32);
    enum vcs_zcode_science_error error =
        vcs_zcode_science_relation_set_serialize(relations, wire, &wire_len);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_SCIENCE_RELATION_SET_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, wire_len, out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

static uint8_t relation_set_types(
    const struct vcs_zcode_science_relation_set_v1 *relations)
{
    uint8_t types = 0;
    for (size_t i = 0; i < relations->row_count; i++)
        types |= VCS_ZCODE_SCIENCE_RELATION_MASK(relations->rows[i].type);
    return types;
}

static uint8_t relation_type_count(uint8_t types)
{
    uint8_t count = 0;
    while (types != 0) {
        count = (uint8_t)(count + (types & 1u));
        types >>= 1;
    }
    return count;
}

static enum vcs_zcode_science_error empty_relation_set_root(uint8_t out[32])
{
    const struct vcs_zcode_science_relation_set_v1 empty = {
        .schema_version = VCS_ZCODE_SCIENCE_RELATION_SET_VERSION,
    };
    return vcs_zcode_science_relation_set_root(&empty, out);
}

enum vcs_zcode_science_error vcs_zcode_science_statement_validate(
    const struct vcs_zcode_science_statement_v1 *statement)
{
    return statement_fields(statement, true);
}

enum vcs_zcode_science_error vcs_zcode_science_statement_validate_relations(
    const struct vcs_zcode_science_statement_v1 *statement,
    const struct vcs_zcode_science_relation_set_v1 *relations)
{
    enum vcs_zcode_science_error error =
        vcs_zcode_science_statement_validate(statement);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_science_relation_set_validate(relations);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    uint8_t root[32];
    error = vcs_zcode_science_relation_set_root(relations, root);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (statement->relation_count != relations->row_count ||
        statement->relation_types != relation_set_types(relations) ||
        memcmp(statement->relations_root, root, sizeof(root)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_RELATION_MISMATCH;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_science_statement_serialize(
    const struct vcs_zcode_science_statement_v1 *statement,
    uint8_t out[VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES);
    enum vcs_zcode_science_error error =
        statement_body(statement, out, true);
    if (error == VCS_ZCODE_SCIENCE_OK)
        memcpy(out + VCS_ZCODE_SCIENCE_STATEMENT_BODY_BYTES,
               statement->signature, 64);
    return error;
}

enum vcs_zcode_science_error vcs_zcode_science_statement_parse(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_science_statement_v1 *out)
{
    if (!out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (len != VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, statement_magic, sizeof(statement_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(statement_magic);
    out->schema_version = get_u16(wire, &off);
    out->profile = wire[off++];
    out->access = wire[off++];
    out->privacy = wire[off++];
    out->redistribution = wire[off++];
    out->authorship = wire[off++];
    out->relation_types = wire[off++];
    out->relation_count = get_u16(wire, &off);
    uint8_t *roots[] = {
        out->subject_root, out->predicate_body_root,
        out->profile_schema_root, out->provenance_root, out->activity_root,
        out->input_root, out->authorship_assertion_root, out->license_root,
        out->access_policy_root, out->privacy_policy_root,
        out->external_identifiers_root, out->citations_root,
        out->relations_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        get_bytes(wire, &off, roots[i], 32);
    out->observed_unix = (int64_t)get_u64(wire, &off);
    out->embargo_until_unix = (int64_t)get_u64(wire, &off);
    get_bytes(wire, &off, out->signer_pubkey, 32);
    get_bytes(wire, &off, out->signature, 64);
    enum vcs_zcode_science_error error =
        vcs_zcode_science_statement_validate(out);
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

static enum vcs_zcode_science_error statement_signing_root(
    const struct vcs_zcode_science_statement_v1 *statement, uint8_t out[32])
{
    uint8_t body[VCS_ZCODE_SCIENCE_STATEMENT_BODY_BYTES];
    enum vcs_zcode_science_error error = statement_body(statement, body, false);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_SCIENCE_STATEMENT_SIGNING_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), body, sizeof(body),
                                    out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

enum vcs_zcode_science_error vcs_zcode_science_statement_root(
    const struct vcs_zcode_science_statement_v1 *statement, uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_SCIENCE_STATEMENT_WIRE_BYTES];
    if (out) memset(out, 0, 32);
    enum vcs_zcode_science_error error =
        vcs_zcode_science_statement_serialize(statement, wire);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] = VCS_ZCODE_SCIENCE_STATEMENT_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, sizeof(wire),
                                    out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

enum vcs_zcode_science_error vcs_zcode_science_statement_seal(
    struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t secret[32], const uint8_t pubkey[32])
{
    if (!statement || !secret || !pubkey) return VCS_ZCODE_SCIENCE_ERR_NULL;
    struct vcs_zcode_science_statement_v1 sealed = *statement;
    sealed.authorship = VCS_ZCODE_SCIENCE_AUTHORSHIP_SIGNED;
    memcpy(sealed.signer_pubkey, pubkey, 32);
    memset(sealed.signature, 0, sizeof(sealed.signature));
    uint8_t root[32];
    enum vcs_zcode_science_error error =
        statement_signing_root(&sealed, root);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (!vcs_signed_evidence_seal_root(
            root, secret, pubkey, sealed.signature))
        return VCS_ZCODE_SCIENCE_ERR_SIGNATURE;
    if (!vcs_signed_evidence_verify_root(
            root, sealed.signature, sealed.signer_pubkey, pubkey))
        return VCS_ZCODE_SCIENCE_ERR_SIGNATURE;
    *statement = sealed;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error vcs_zcode_science_statement_verify(
    const struct vcs_zcode_science_statement_v1 *statement,
    const uint8_t expected_signer[32])
{
    enum vcs_zcode_science_error error =
        vcs_zcode_science_statement_validate(statement);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (!expected_signer) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (statement->authorship != VCS_ZCODE_SCIENCE_AUTHORSHIP_SIGNED)
        return VCS_ZCODE_SCIENCE_ERR_AUTHORSHIP;
    uint8_t root[32];
    error = statement_signing_root(statement, root);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    return vcs_signed_evidence_verify_root(
               root, statement->signature, statement->signer_pubkey,
               expected_signer)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_SIGNATURE;
}
