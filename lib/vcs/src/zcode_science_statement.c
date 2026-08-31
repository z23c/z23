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
static const uint8_t vector_navigation_preregistration_magic[8] =
    {'Z','C','V','N','A','V','\r','\n'};

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

static void put_u32(uint8_t *wire, size_t *off, uint32_t value)
{
    zcl_write_u32_le(wire + *off, value);
    *off += 4;
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

static uint32_t get_u32(const uint8_t *wire, size_t *off)
{
    uint32_t value = zcl_read_u32_le(wire + *off);
    *off += 4;
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

enum vcs_zcode_science_error
vcs_zcode_vector_navigation_preregistration_validate(
    const struct vcs_zcode_vector_navigation_preregistration_v1 *prereg)
{
    if (!prereg) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (prereg->schema_version !=
        VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_VERSION)
        return VCS_ZCODE_SCIENCE_ERR_VERSION;
    if (prereg->arm_count != VCS_ZCODE_VECTOR_NAVIGATION_ARM_COUNT - 1u ||
        prereg->gate_count != VCS_ZCODE_VECTOR_NAVIGATION_GATE_COUNT - 1u ||
        prereg->development_queries !=
            VCS_ZCODE_VECTOR_NAVIGATION_DEVELOPMENT_QUERIES ||
        prereg->sealed_holdout_queries !=
            VCS_ZCODE_VECTOR_NAVIGATION_SEALED_HOLDOUT_QUERIES ||
        prereg->paired_bootstrap_samples !=
            VCS_ZCODE_VECTOR_NAVIGATION_BOOTSTRAP_SAMPLES ||
        prereg->bootstrap_seed == 0 ||
        prereg->bootstrap_confidence_bp !=
            VCS_ZCODE_VECTOR_NAVIGATION_BOOTSTRAP_CONFIDENCE_BP ||
        prereg->paraphrase_hit_at_10_gain_bp !=
            VCS_ZCODE_VECTOR_NAVIGATION_HIT_AT_10_GAIN_BP ||
        prereg->overall_ndcg_at_10_gain_ppm !=
            VCS_ZCODE_VECTOR_NAVIGATION_NDCG_AT_10_GAIN_PPM ||
        prereg->agent_noninferiority_bp !=
            VCS_ZCODE_VECTOR_NAVIGATION_AGENT_NONINFERIORITY_BP ||
        prereg->efficiency_gain_bp !=
            VCS_ZCODE_VECTOR_NAVIGATION_EFFICIENCY_GAIN_BP ||
        prereg->approximate_recall_at_20_bp !=
            VCS_ZCODE_VECTOR_NAVIGATION_APPROX_RECALL_AT_20_BP)
        return VCS_ZCODE_SCIENCE_ERR_LIMIT;
    if (prereg->evidence_kind !=
            VCS_ZCODE_VECTOR_NAVIGATION_EVIDENCE_MODEL_HINT ||
        prereg->reserved != 0 || prereg->reserved_tail != 0 ||
        prereg->prohibited_claims !=
            VCS_ZCODE_VECTOR_NAVIGATION_REQUIRED_PROHIBITIONS ||
        prereg->maximum_exact_identity_changes != 0 ||
        prereg->maximum_mandatory_proof_omissions != 0 ||
        prereg->maximum_vector_only_completeness_claims != 0)
        return VCS_ZCODE_SCIENCE_ERR_FLAGS;
    const uint8_t *roots[] = {
        prereg->study_spec_root, prereg->source_root, prereg->task_root,
        prereg->ontology_root, prereg->concept_card_root,
        prereg->model_root, prereg->embedding_profile_root,
        prereg->result_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    for (size_t i = 0; i < prereg->arm_count; i++)
        if (!root_nonzero(prereg->arm_roots[i]))
            return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    for (size_t i = 0; i < prereg->arm_count; i++)
        for (size_t j = i + 1; j < prereg->arm_count; j++)
            if (memcmp(prereg->arm_roots[i], prereg->arm_roots[j], 32) == 0)
                return VCS_ZCODE_SCIENCE_ERR_ROOT_REUSED;
    for (size_t i = 0; i < prereg->gate_count; i++)
        if (!root_nonzero(prereg->gate_roots[i]))
            return VCS_ZCODE_SCIENCE_ERR_ROOT_ZERO;
    for (size_t i = 0; i < prereg->gate_count; i++)
        for (size_t j = i + 1; j < prereg->gate_count; j++)
            if (memcmp(prereg->gate_roots[i], prereg->gate_roots[j], 32) == 0)
                return VCS_ZCODE_SCIENCE_ERR_ROOT_REUSED;
    return VCS_ZCODE_SCIENCE_OK;
}

enum vcs_zcode_science_error
vcs_zcode_vector_navigation_preregistration_serialize(
    const struct vcs_zcode_vector_navigation_preregistration_v1 *prereg,
    uint8_t out[VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_WIRE_BYTES])
{
    if (!out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_WIRE_BYTES);
    enum vcs_zcode_science_error error =
        vcs_zcode_vector_navigation_preregistration_validate(prereg);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    size_t off = 0;
    put_bytes(out, &off, vector_navigation_preregistration_magic,
              sizeof(vector_navigation_preregistration_magic));
    put_u16(out, &off, prereg->schema_version);
    out[off++] = prereg->arm_count;
    out[off++] = prereg->gate_count;
    out[off++] = prereg->evidence_kind;
    out[off++] = prereg->reserved;
    put_u16(out, &off, prereg->prohibited_claims);
    put_u16(out, &off, prereg->development_queries);
    put_u16(out, &off, prereg->sealed_holdout_queries);
    put_u32(out, &off, prereg->paired_bootstrap_samples);
    put_u64(out, &off, prereg->bootstrap_seed);
    put_u16(out, &off, prereg->bootstrap_confidence_bp);
    put_u16(out, &off, prereg->paraphrase_hit_at_10_gain_bp);
    put_u32(out, &off, prereg->overall_ndcg_at_10_gain_ppm);
    put_u16(out, &off, prereg->agent_noninferiority_bp);
    put_u16(out, &off, prereg->efficiency_gain_bp);
    put_u16(out, &off, prereg->approximate_recall_at_20_bp);
    put_u16(out, &off, prereg->maximum_exact_identity_changes);
    put_u16(out, &off, prereg->maximum_mandatory_proof_omissions);
    put_u16(out, &off, prereg->maximum_vector_only_completeness_claims);
    put_u32(out, &off, prereg->reserved_tail);
    const uint8_t *roots[] = {
        prereg->study_spec_root, prereg->source_root, prereg->task_root,
        prereg->ontology_root, prereg->concept_card_root,
        prereg->model_root, prereg->embedding_profile_root,
        prereg->result_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        put_bytes(out, &off, roots[i], 32);
    for (size_t i = 0; i < prereg->arm_count; i++)
        put_bytes(out, &off, prereg->arm_roots[i], 32);
    for (size_t i = 0; i < prereg->gate_count; i++)
        put_bytes(out, &off, prereg->gate_roots[i], 32);
    return off == VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_WIRE_BYTES
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
}

enum vcs_zcode_science_error
vcs_zcode_vector_navigation_preregistration_parse(
    const uint8_t *wire, size_t len,
    struct vcs_zcode_vector_navigation_preregistration_v1 *out)
{
    if (!out) return VCS_ZCODE_SCIENCE_ERR_NULL;
    memset(out, 0, sizeof(*out));
    if (!wire) return VCS_ZCODE_SCIENCE_ERR_NULL;
    if (len != VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_WIRE_BYTES)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (memcmp(wire, vector_navigation_preregistration_magic,
               sizeof(vector_navigation_preregistration_magic)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_WIRE_MAGIC;
    size_t off = sizeof(vector_navigation_preregistration_magic);
    out->schema_version = get_u16(wire, &off);
    out->arm_count = wire[off++];
    out->gate_count = wire[off++];
    out->evidence_kind = wire[off++];
    out->reserved = wire[off++];
    out->prohibited_claims = get_u16(wire, &off);
    out->development_queries = get_u16(wire, &off);
    out->sealed_holdout_queries = get_u16(wire, &off);
    out->paired_bootstrap_samples = get_u32(wire, &off);
    out->bootstrap_seed = get_u64(wire, &off);
    out->bootstrap_confidence_bp = get_u16(wire, &off);
    out->paraphrase_hit_at_10_gain_bp = get_u16(wire, &off);
    out->overall_ndcg_at_10_gain_ppm = get_u32(wire, &off);
    out->agent_noninferiority_bp = get_u16(wire, &off);
    out->efficiency_gain_bp = get_u16(wire, &off);
    out->approximate_recall_at_20_bp = get_u16(wire, &off);
    out->maximum_exact_identity_changes = get_u16(wire, &off);
    out->maximum_mandatory_proof_omissions = get_u16(wire, &off);
    out->maximum_vector_only_completeness_claims = get_u16(wire, &off);
    out->reserved_tail = get_u32(wire, &off);
    uint8_t *roots[] = {
        out->study_spec_root, out->source_root, out->task_root,
        out->ontology_root, out->concept_card_root, out->model_root,
        out->embedding_profile_root, out->result_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        get_bytes(wire, &off, roots[i], 32);
    for (size_t i = 0; i < out->arm_count &&
                       i < VCS_ZCODE_VECTOR_NAVIGATION_ARM_COUNT - 1u; i++)
        get_bytes(wire, &off, out->arm_roots[i], 32);
    for (size_t i = 0; i < out->gate_count &&
                       i < VCS_ZCODE_VECTOR_NAVIGATION_GATE_COUNT - 1u; i++)
        get_bytes(wire, &off, out->gate_roots[i], 32);
    enum vcs_zcode_science_error error =
        vcs_zcode_vector_navigation_preregistration_validate(out);
    if (off != len && error == VCS_ZCODE_SCIENCE_OK)
        error = VCS_ZCODE_SCIENCE_ERR_WIRE_SIZE;
    if (error != VCS_ZCODE_SCIENCE_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum vcs_zcode_science_error vcs_zcode_vector_navigation_preregistration_root(
    const struct vcs_zcode_vector_navigation_preregistration_v1 *prereg,
    uint8_t out[32])
{
    uint8_t wire[VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_WIRE_BYTES];
    if (out) memset(out, 0, 32);
    enum vcs_zcode_science_error error =
        vcs_zcode_vector_navigation_preregistration_serialize(prereg, wire);
    if (error != VCS_ZCODE_SCIENCE_OK || !out)
        return out ? error : VCS_ZCODE_SCIENCE_ERR_NULL;
    static const char domain[] =
        VCS_ZCODE_VECTOR_NAVIGATION_PREREGISTRATION_DOMAIN;
    return vcs_signed_evidence_root(domain, sizeof(domain), wire, sizeof(wire),
                                    out)
        ? VCS_ZCODE_SCIENCE_OK : VCS_ZCODE_SCIENCE_ERR_NULL;
}

enum vcs_zcode_science_error
vcs_zcode_vector_navigation_preregistration_validate_bindings(
    const struct vcs_zcode_vector_navigation_preregistration_v1 *prereg,
    const struct vcs_zcode_study_spec_v1 *study,
    const struct vcs_zcode_science_statement_v1 *statement)
{
    enum vcs_zcode_science_error error =
        vcs_zcode_vector_navigation_preregistration_validate(prereg);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_study_spec_validate(study);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_science_statement_validate(statement);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (statement->profile != VCS_ZCODE_SCIENCE_PROFILE_PREREGISTRATION)
        return VCS_ZCODE_SCIENCE_ERR_PROFILE;
    uint8_t study_root[32], prereg_root[32];
    error = vcs_zcode_study_spec_root(study, study_root);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    error = vcs_zcode_vector_navigation_preregistration_root(prereg,
                                                             prereg_root);
    if (error != VCS_ZCODE_SCIENCE_OK) return error;
    if (memcmp(prereg->study_spec_root, study_root, sizeof(study_root)) != 0 ||
        memcmp(prereg->source_root, study->source_root,
               sizeof(prereg->source_root)) != 0 ||
        memcmp(statement->predicate_body_root, prereg_root,
               sizeof(prereg_root)) != 0)
        return VCS_ZCODE_SCIENCE_ERR_STUDY_MISMATCH;
    return VCS_ZCODE_SCIENCE_OK;
}
