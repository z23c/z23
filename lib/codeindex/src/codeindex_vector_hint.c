/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical bounded codecs for exact concept cards and optional
 * MODEL_HINT-only signed-int8 code retrieval vectors. */

#include "codeindex/codeindex_vector_hint.h"

#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "ontology/ontology.h"

#include <limits.h>
#include <string.h>

static const uint8_t concept_magic[8] = {
    'Z', 'C', 'C', 'A', 'R', 'D', '1', 0,
};
static const uint8_t profile_magic[8] = {
    'Z', 'E', 'M', 'P', 'R', 'O', '1', 0,
};
static const uint8_t segment_magic[8] = {
    'Z', 'E', 'M', 'S', 'E', 'G', '1', 0,
};
static const char concept_domain[] = "zcl.code_concept_card.v1";
static const char profile_domain[] = "zcl.code_embedding_profile.v1";
static const char payload_domain[] = "zcl.code_embedding_payload.v1";
static const char segment_domain[] = "zcl.code_embedding_segment.v1";

_Static_assert(ZCL_CODE_CONCEPT_CARD_PACKAGE == 1 &&
                   ZCL_CODE_CONCEPT_CARD_COMPONENT == 2 &&
                   ZCL_CODE_CONCEPT_CARD_API == 3 &&
                   ZCL_CODE_CONCEPT_CARD_CONFIGURED_ENTITY == 4 &&
                   ZCL_CODE_CONCEPT_CARD_USAGE_NEIGHBORHOOD == 5 &&
                   ZCL_CODE_CONCEPT_CARD_INVARIANT == 6 &&
                   ZCL_CODE_CONCEPT_CARD_TEST == 7 &&
                   ZCL_CODE_CONCEPT_CARD_ACCEPTED_TELEMETRY == 8,
               "concept-card wire enums are append-only");
_Static_assert(ZCL_CODE_HINT_EVIDENCE_MODEL_HINT == 1 &&
                   ZCL_CODE_CONCEPT_EVIDENCE_EXACT_ROOTS == 1 &&
                   ZCL_CODE_EMBEDDING_METRIC_INTEGER_DOT == 1 &&
                   ZCL_CODE_EMBEDDING_QUANTIZER_SIGNED_INT8 == 1,
               "vector-hint wire enums are append-only");
_Static_assert(ZCL_CODE_CONCEPT_CARD_WIRE_BYTES == 8 + 8 + 8 * 32,
               "concept-card wire size drift");
_Static_assert(ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES == 8 + 8 + 8 + 10 * 32,
               "embedding-profile wire size drift");
_Static_assert(ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES ==
                   8 + 8 + 8 + 3 * 8 + 8 * 32,
               "embedding-segment header size drift");

static bool root_nonzero(const uint8_t root[32])
{
    if (!root) return false;
    uint8_t any = 0;
    for (size_t i = 0; i < 32; i++) any |= root[i];
    return any != 0;
}

static bool ranges_overlap(const void *a, size_t a_len,
                           const void *b, size_t b_len)
{
    if (!a || !b || a_len == 0 || b_len == 0) return false;
    uintptr_t a_start = (uintptr_t)a, b_start = (uintptr_t)b;
    if (a_len > UINTPTR_MAX - a_start || b_len > UINTPTR_MAX - b_start)
        return true;
    uintptr_t a_end = a_start + a_len, b_end = b_start + b_len;
    return a_start < b_end && b_start < a_end;
}

static bool card_kind_valid(uint8_t kind)
{
    return kind >= ZCL_CODE_CONCEPT_CARD_PACKAGE &&
           kind <= ZCL_CODE_CONCEPT_CARD_ACCEPTED_TELEMETRY;
}

static bool hint_fields_valid(uint8_t evidence_kind, uint8_t metric,
                              uint8_t quantizer)
{
    return evidence_kind == ZCL_CODE_HINT_EVIDENCE_MODEL_HINT &&
           metric == ZCL_CODE_EMBEDDING_METRIC_INTEGER_DOT &&
           quantizer == ZCL_CODE_EMBEDDING_QUANTIZER_SIGNED_INT8;
}

static void hash_wire(const char *domain, size_t domain_len,
                      const uint8_t *wire, size_t wire_len, uint8_t out[32])
{
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)domain, domain_len);
    sha3_256_write(&sha, wire, wire_len);
    sha3_256_finalize(&sha, out);
}

static size_t roots_copy_out(uint8_t *out, size_t off,
                             const uint8_t *const *roots, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        memcpy(out + off, roots[i], 32);
        off += 32;
    }
    return off;
}

static size_t roots_copy_in(const uint8_t *wire, size_t off,
                            uint8_t *const *roots, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        memcpy(roots[i], wire + off, 32);
        off += 32;
    }
    return off;
}

enum zcl_code_vector_hint_error zcl_code_concept_card_v1_validate(
    const struct zcl_code_concept_card_v1 *card)
{
    if (!card) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (card->schema_version != ZCL_CODE_CONCEPT_CARD_VERSION)
        return ZCL_CODE_VECTOR_HINT_ERR_VERSION;
    if (!card_kind_valid(card->kind) ||
        card->evidence_kind != ZCL_CODE_CONCEPT_EVIDENCE_EXACT_ROOTS)
        return ZCL_CODE_VECTOR_HINT_ERR_ENUM;
    if (card->flags != 0 || card->reserved != 0)
        return ZCL_CODE_VECTOR_HINT_ERR_FLAGS;
    const uint8_t *roots[] = {
        card->source_root, card->universe_root, card->ontology_root,
        card->context_root, card->subject_root, card->fact_manifest_root,
        card->coverage_root, card->extractor_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO;
    return ZCL_CODE_VECTOR_HINT_OK;
}

enum zcl_code_vector_hint_error zcl_code_concept_card_v1_encode(
    const struct zcl_code_concept_card_v1 *card,
    uint8_t out[ZCL_CODE_CONCEPT_CARD_WIRE_BYTES])
{
    if (!out) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (card && ranges_overlap(card, sizeof(*card), out,
                               ZCL_CODE_CONCEPT_CARD_WIRE_BYTES))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    enum zcl_code_vector_hint_error error =
        zcl_code_concept_card_v1_validate(card);
    if (error != ZCL_CODE_VECTOR_HINT_OK) {
        memset(out, 0, ZCL_CODE_CONCEPT_CARD_WIRE_BYTES);
        return error;
    }
    size_t off = 0;
    memcpy(out + off, concept_magic, sizeof(concept_magic));
    off += sizeof(concept_magic);
    zcl_write_u16_le(out + off, card->schema_version); off += 2;
    out[off++] = card->kind;
    out[off++] = card->evidence_kind;
    zcl_write_u16_le(out + off, card->flags); off += 2;
    zcl_write_u16_le(out + off, card->reserved); off += 2;
    const uint8_t *roots[] = {
        card->source_root, card->universe_root, card->ontology_root,
        card->context_root, card->subject_root, card->fact_manifest_root,
        card->coverage_root, card->extractor_root,
    };
    off = roots_copy_out(out, off, roots, sizeof(roots) / sizeof(roots[0]));
    return off == ZCL_CODE_CONCEPT_CARD_WIRE_BYTES
               ? ZCL_CODE_VECTOR_HINT_OK
               : ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
}

enum zcl_code_vector_hint_error zcl_code_concept_card_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_code_concept_card_v1 *out)
{
    if (!out) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (!wire) {
        memset(out, 0, sizeof(*out));
        return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    }
    if (ranges_overlap(wire, wire_len, out, sizeof(*out)))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    memset(out, 0, sizeof(*out));
    if (wire_len != ZCL_CODE_CONCEPT_CARD_WIRE_BYTES)
        return ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
    if (memcmp(wire, concept_magic, sizeof(concept_magic)) != 0)
        return ZCL_CODE_VECTOR_HINT_ERR_WIRE_MAGIC;
    size_t off = sizeof(concept_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->kind = wire[off++];
    out->evidence_kind = wire[off++];
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->reserved = zcl_read_u16_le(wire + off); off += 2;
    uint8_t *roots[] = {
        out->source_root, out->universe_root, out->ontology_root,
        out->context_root, out->subject_root, out->fact_manifest_root,
        out->coverage_root, out->extractor_root,
    };
    off = roots_copy_in(wire, off, roots, sizeof(roots) / sizeof(roots[0]));
    enum zcl_code_vector_hint_error error =
        off == wire_len ? zcl_code_concept_card_v1_validate(out)
                        : ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
    if (error != ZCL_CODE_VECTOR_HINT_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum zcl_code_vector_hint_error zcl_code_concept_card_v1_root(
    const struct zcl_code_concept_card_v1 *card, uint8_t out[32])
{
    if (!out) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (card && ranges_overlap(card, sizeof(*card), out, 32))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    memset(out, 0, 32);
    uint8_t wire[ZCL_CODE_CONCEPT_CARD_WIRE_BYTES];
    enum zcl_code_vector_hint_error error =
        zcl_code_concept_card_v1_encode(card, wire);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    hash_wire(concept_domain, sizeof(concept_domain), wire, sizeof(wire), out);
    return ZCL_CODE_VECTOR_HINT_OK;
}

enum zcl_code_vector_hint_error zcl_code_concept_card_v1_validate_ontology(
    const struct zcl_code_concept_card_v1 *card,
    const struct zcl_ontology_manifest_v1 *manifest,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_manifest_inputs_v1 *inputs)
{
    enum zcl_code_vector_hint_error error =
        zcl_code_concept_card_v1_validate(card);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    if (!manifest || !universe || !inputs)
        return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    uint8_t ontology_root[32];
    if (!zcl_ontology_manifest_v1_validate(manifest, universe, inputs) ||
        !zcl_ontology_manifest_v1_root(manifest, ontology_root) ||
        memcmp(card->source_root, manifest->source_root, 32) != 0 ||
        memcmp(card->universe_root, manifest->universe_root, 32) != 0 ||
        memcmp(card->ontology_root, ontology_root, 32) != 0 ||
        memcmp(card->fact_manifest_root,
               manifest->assertion_set_root, 32) != 0 ||
        memcmp(card->coverage_root, manifest->coverage_set_root, 32) != 0 ||
        memcmp(card->extractor_root, manifest->extractor_root, 32) != 0)
        return ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING;
    bool context_found = false, subject_found = false;
    for (size_t i = 0; i < inputs->context_count; i++) {
        uint8_t context_root[32];
        if (zcl_ontology_context_v1_root(
                &inputs->contexts[i], context_root) &&
            memcmp(card->context_root, context_root, 32) == 0)
            context_found = true;
    }
    for (size_t i = 0; i < inputs->term_count; i++)
        if (inputs->terms[i].kind == ZCL_ONTOLOGY_TERM_ENTITY &&
            memcmp(card->subject_root,
                   inputs->terms[i].identity_root, 32) == 0)
            subject_found = true;
    return context_found && subject_found
               ? ZCL_CODE_VECTOR_HINT_OK
               : ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING;
}

enum zcl_code_vector_hint_error zcl_code_embedding_profile_v1_validate(
    const struct zcl_code_embedding_profile_v1 *profile)
{
    if (!profile) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (profile->schema_version != ZCL_CODE_EMBEDDING_PROFILE_VERSION)
        return ZCL_CODE_VECTOR_HINT_ERR_VERSION;
    if (!hint_fields_valid(profile->evidence_kind, profile->metric,
                           profile->quantizer))
        return ZCL_CODE_VECTOR_HINT_ERR_ENUM;
    if (profile->flags != 0 || profile->reserved_byte != 0 ||
        profile->reserved != 0)
        return ZCL_CODE_VECTOR_HINT_ERR_FLAGS;
    if (profile->dimension == 0 ||
        profile->dimension > ZCL_CODE_EMBEDDING_DIMENSION_MAX)
        return ZCL_CODE_VECTOR_HINT_ERR_LIMIT;
    const uint8_t *roots[] = {
        profile->projection_root, profile->tokenizer_root,
        profile->preprocessing_root, profile->model_root,
        profile->weights_root, profile->license_root, profile->rights_root,
        profile->accepted_runner_root, profile->accepted_action_root,
        profile->reproducibility_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO;
    return ZCL_CODE_VECTOR_HINT_OK;
}

enum zcl_code_vector_hint_error zcl_code_embedding_profile_v1_encode(
    const struct zcl_code_embedding_profile_v1 *profile,
    uint8_t out[ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES])
{
    if (!out) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (profile && ranges_overlap(profile, sizeof(*profile), out,
                                  ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    enum zcl_code_vector_hint_error error =
        zcl_code_embedding_profile_v1_validate(profile);
    if (error != ZCL_CODE_VECTOR_HINT_OK) {
        memset(out, 0, ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES);
        return error;
    }
    size_t off = 0;
    memcpy(out + off, profile_magic, sizeof(profile_magic));
    off += sizeof(profile_magic);
    zcl_write_u16_le(out + off, profile->schema_version); off += 2;
    out[off++] = profile->evidence_kind;
    out[off++] = profile->metric;
    out[off++] = profile->quantizer;
    out[off++] = profile->reserved_byte;
    zcl_write_u16_le(out + off, profile->flags); off += 2;
    zcl_write_u32_le(out + off, profile->dimension); off += 4;
    zcl_write_u32_le(out + off, profile->reserved); off += 4;
    const uint8_t *roots[] = {
        profile->projection_root, profile->tokenizer_root,
        profile->preprocessing_root, profile->model_root,
        profile->weights_root, profile->license_root, profile->rights_root,
        profile->accepted_runner_root, profile->accepted_action_root,
        profile->reproducibility_root,
    };
    off = roots_copy_out(out, off, roots, sizeof(roots) / sizeof(roots[0]));
    return off == ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES
               ? ZCL_CODE_VECTOR_HINT_OK
               : ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
}

enum zcl_code_vector_hint_error zcl_code_embedding_profile_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_code_embedding_profile_v1 *out)
{
    if (!out) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (!wire) {
        memset(out, 0, sizeof(*out));
        return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    }
    if (ranges_overlap(wire, wire_len, out, sizeof(*out)))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    memset(out, 0, sizeof(*out));
    if (wire_len != ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES)
        return ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
    if (memcmp(wire, profile_magic, sizeof(profile_magic)) != 0)
        return ZCL_CODE_VECTOR_HINT_ERR_WIRE_MAGIC;
    size_t off = sizeof(profile_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->evidence_kind = wire[off++];
    out->metric = wire[off++];
    out->quantizer = wire[off++];
    out->reserved_byte = wire[off++];
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->dimension = zcl_read_u32_le(wire + off); off += 4;
    out->reserved = zcl_read_u32_le(wire + off); off += 4;
    uint8_t *roots[] = {
        out->projection_root, out->tokenizer_root, out->preprocessing_root,
        out->model_root, out->weights_root, out->license_root,
        out->rights_root, out->accepted_runner_root,
        out->accepted_action_root, out->reproducibility_root,
    };
    off = roots_copy_in(wire, off, roots, sizeof(roots) / sizeof(roots[0]));
    enum zcl_code_vector_hint_error error =
        off == wire_len ? zcl_code_embedding_profile_v1_validate(out)
                        : ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
    if (error != ZCL_CODE_VECTOR_HINT_OK) memset(out, 0, sizeof(*out));
    return error;
}

enum zcl_code_vector_hint_error zcl_code_embedding_profile_v1_root(
    const struct zcl_code_embedding_profile_v1 *profile, uint8_t out[32])
{
    if (!out) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (profile && ranges_overlap(profile, sizeof(*profile), out, 32))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    memset(out, 0, 32);
    uint8_t wire[ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES];
    enum zcl_code_vector_hint_error error =
        zcl_code_embedding_profile_v1_encode(profile, wire);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    hash_wire(profile_domain, sizeof(profile_domain), wire, sizeof(wire), out);
    return ZCL_CODE_VECTOR_HINT_OK;
}

static int vector_key_compare(const struct zcl_code_embedding_vector_v1 *a,
                              const struct zcl_code_embedding_vector_v1 *b)
{
    int cmp = memcmp(a->entity_root, b->entity_root, 32);
    if (cmp == 0) cmp = memcmp(a->concept_card_root, b->concept_card_root, 32);
    if (cmp == 0) cmp = memcmp(a->span_root, b->span_root, 32);
    return cmp;
}

static enum zcl_code_vector_hint_error vector_payload_shape(
    uint32_t dimension, uint64_t vector_count, uint64_t *row_bytes_out,
    uint64_t *payload_bytes_out)
{
    if (dimension == 0 || dimension > ZCL_CODE_EMBEDDING_DIMENSION_MAX ||
        vector_count == 0)
        return ZCL_CODE_VECTOR_HINT_ERR_LIMIT;
    uint64_t row_bytes = ZCL_CODE_EMBEDDING_ROW_ROOT_BYTES;
    if ((uint64_t)dimension > UINT64_MAX - row_bytes)
        return ZCL_CODE_VECTOR_HINT_ERR_OVERFLOW;
    row_bytes += dimension;
    if (vector_count > UINT64_MAX / row_bytes ||
        vector_count > (uint64_t)(SIZE_MAX /
                                  sizeof(struct zcl_code_embedding_vector_v1)))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERFLOW;
    uint64_t payload_bytes = vector_count * row_bytes;
    if (payload_bytes > ZCL_CODE_EMBEDDING_SEGMENT_WIRE_MAX -
                            ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES)
        return ZCL_CODE_VECTOR_HINT_ERR_LIMIT;
    if (row_bytes_out) *row_bytes_out = row_bytes;
    if (payload_bytes_out) *payload_bytes_out = payload_bytes;
    return ZCL_CODE_VECTOR_HINT_OK;
}

static enum zcl_code_vector_hint_error vector_rows_validate(
    uint32_t dimension, const struct zcl_code_embedding_vector_v1 *vectors,
    uint64_t vector_count)
{
    enum zcl_code_vector_hint_error error =
        vector_payload_shape(dimension, vector_count, NULL, NULL);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    if (!vectors) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    for (uint64_t i = 0; i < vector_count; i++) {
        const struct zcl_code_embedding_vector_v1 *vector = &vectors[i];
        if (!root_nonzero(vector->entity_root) ||
            !root_nonzero(vector->concept_card_root) ||
            !root_nonzero(vector->span_root))
            return ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO;
        if (!vector->values) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
        if (i != 0 && vector_key_compare(&vectors[i - 1], vector) >= 0)
            return ZCL_CODE_VECTOR_HINT_ERR_ORDER;
    }
    return ZCL_CODE_VECTOR_HINT_OK;
}

static void hash_vector_rows(struct sha3_256_ctx *sha, uint32_t dimension,
                             const struct zcl_code_embedding_vector_v1 *vectors,
                             uint64_t vector_count)
{
    for (uint64_t i = 0; i < vector_count; i++) {
        sha3_256_write(sha, vectors[i].entity_root, 32);
        sha3_256_write(sha, vectors[i].concept_card_root, 32);
        sha3_256_write(sha, vectors[i].span_root, 32);
        sha3_256_write(sha, (const uint8_t *)vectors[i].values, dimension);
    }
}

enum zcl_code_vector_hint_error zcl_code_embedding_payload_v1_root(
    uint32_t dimension,
    const struct zcl_code_embedding_vector_v1 *vectors,
    uint64_t vector_count, uint8_t out[32])
{
    if (!out) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    enum zcl_code_vector_hint_error error =
        vector_payload_shape(dimension, vector_count, NULL, NULL);
    if (error != ZCL_CODE_VECTOR_HINT_OK) {
        memset(out, 0, 32);
        return error;
    }
    if (vectors &&
        ranges_overlap(vectors, (size_t)vector_count * sizeof(*vectors),
                       out, 32))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    if (vectors)
        for (uint64_t i = 0; i < vector_count; i++)
            if (ranges_overlap(vectors[i].values, dimension, out, 32))
                return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    error = vector_rows_validate(dimension, vectors, vector_count);
    if (error != ZCL_CODE_VECTOR_HINT_OK) {
        memset(out, 0, 32);
        return error;
    }
    memset(out, 0, 32);
    struct sha3_256_ctx sha;
    uint8_t shape[12];
    zcl_write_u32_le(shape, dimension);
    zcl_write_u64_le(shape + 4, vector_count);
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)payload_domain,
                   sizeof(payload_domain));
    /* Bind the row grammar before its bytes. Without dimension and count,
     * different valid row partitions could name the same byte stream. */
    sha3_256_write(&sha, shape, sizeof(shape));
    hash_vector_rows(&sha, dimension, vectors, vector_count);
    sha3_256_finalize(&sha, out);
    return ZCL_CODE_VECTOR_HINT_OK;
}

static enum zcl_code_vector_hint_error segment_shape(
    const struct zcl_code_embedding_segment_v1 *segment, size_t *wire_size)
{
    if (!segment) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (segment->schema_version != ZCL_CODE_EMBEDDING_SEGMENT_VERSION)
        return ZCL_CODE_VECTOR_HINT_ERR_VERSION;
    if (!hint_fields_valid(segment->evidence_kind, segment->metric,
                           segment->quantizer))
        return ZCL_CODE_VECTOR_HINT_ERR_ENUM;
    if (segment->flags != 0 || segment->reserved_byte != 0 ||
        segment->reserved != 0)
        return ZCL_CODE_VECTOR_HINT_ERR_FLAGS;
    if (segment->dimension == 0 ||
        segment->dimension > ZCL_CODE_EMBEDDING_DIMENSION_MAX ||
        segment->vector_count == 0)
        return ZCL_CODE_VECTOR_HINT_ERR_LIMIT;
    uint64_t row_bytes = 0, payload_bytes = 0;
    enum zcl_code_vector_hint_error error = vector_payload_shape(
        segment->dimension, segment->vector_count, &row_bytes,
        &payload_bytes);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    if (segment->row_bytes != row_bytes ||
        segment->payload_bytes != payload_bytes)
        return ZCL_CODE_VECTOR_HINT_ERR_OVERFLOW;
    uint64_t total = ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES + payload_bytes;
    if (total > (uint64_t)SIZE_MAX)
        return ZCL_CODE_VECTOR_HINT_ERR_OVERFLOW;
    if (wire_size) *wire_size = (size_t)total;
    const uint8_t *roots[] = {
        segment->corpus_root, segment->source_root, segment->universe_root,
        segment->concept_card_set_root, segment->context_root,
        segment->coverage_root, segment->profile_root, segment->payload_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i])) return ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO;
    return vector_rows_validate(segment->dimension, segment->vectors,
                                segment->vector_count);
}

enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_validate(
    const struct zcl_code_embedding_segment_v1 *segment)
{
    enum zcl_code_vector_hint_error error = segment_shape(segment, NULL);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    uint8_t payload_root[32];
    error = zcl_code_embedding_payload_v1_root(
        segment->dimension, segment->vectors, segment->vector_count,
        payload_root);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    return memcmp(payload_root, segment->payload_root, 32) == 0
               ? ZCL_CODE_VECTOR_HINT_OK
               : ZCL_CODE_VECTOR_HINT_ERR_PAYLOAD_ROOT;
}

enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_validate_profile(
    const struct zcl_code_embedding_segment_v1 *segment,
    const struct zcl_code_embedding_profile_v1 *profile)
{
    enum zcl_code_vector_hint_error error =
        zcl_code_embedding_segment_v1_validate(segment);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    error = zcl_code_embedding_profile_v1_validate(profile);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    if (segment->dimension != profile->dimension ||
        segment->evidence_kind != profile->evidence_kind ||
        segment->metric != profile->metric ||
        segment->quantizer != profile->quantizer)
        return ZCL_CODE_VECTOR_HINT_ERR_ENUM;
    uint8_t profile_root[32];
    error = zcl_code_embedding_profile_v1_root(profile, profile_root);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    return memcmp(segment->profile_root, profile_root, 32) == 0
               ? ZCL_CODE_VECTOR_HINT_OK
               : ZCL_CODE_VECTOR_HINT_ERR_PROFILE_BINDING;
}

static void card_root_swap(uint8_t left[32], uint8_t right[32])
{
    uint8_t temporary[32];
    memcpy(temporary, left, 32);
    memcpy(left, right, 32);
    memcpy(right, temporary, 32);
}

static void card_root_sift_down(uint8_t (*roots)[32], size_t start,
                                size_t count)
{
    if (count < 2u) return;
    size_t parent = start;
    while (parent <= (count - 2u) / 2u) {
        size_t child = parent * 2u + 1u;
        if (child + 1u < count &&
            memcmp(roots[child], roots[child + 1u], 32) < 0)
            child++;
        if (memcmp(roots[parent], roots[child], 32) >= 0) return;
        card_root_swap(roots[parent], roots[child]);
        parent = child;
    }
}

static void card_roots_sort(uint8_t (*roots)[32], size_t count)
{
    if (count < 2u) return;
    for (size_t start = count / 2u; start != 0; start--)
        card_root_sift_down(roots, start - 1u, count);
    for (size_t end = count; end > 1u; end--) {
        card_root_swap(roots[0], roots[end - 1u]);
        card_root_sift_down(roots, 0, end - 1u);
    }
}

static const struct zcl_code_concept_card_v1 *card_find(
    const struct zcl_code_concept_card_v1 *cards,
    const uint8_t (*card_roots)[32], size_t count, const uint8_t wanted[32])
{
    size_t low = 0, high = count;
    while (low < high) {
        size_t middle = low + (high - low) / 2u;
        int order = memcmp(card_roots[middle], wanted, 32);
        if (order < 0) low = middle + 1u;
        else if (order > 0) high = middle;
        else return &cards[middle];
    }
    return NULL;
}

enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_validate_cards(
    const struct zcl_code_embedding_segment_v1 *segment,
    const struct zcl_code_embedding_profile_v1 *profile,
    const struct zcl_code_concept_card_v1 *cards, size_t card_count,
    uint8_t (*root_scratch)[32], size_t scratch_capacity)
{
    enum zcl_code_vector_hint_error error =
        zcl_code_embedding_segment_v1_validate_profile(segment, profile);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    if (!cards || !root_scratch) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (segment->vector_count != (uint64_t)card_count ||
        scratch_capacity < card_count || card_count == 0 ||
        card_count > SIZE_MAX / sizeof(*cards) ||
        card_count > SIZE_MAX / sizeof(*root_scratch))
        return ZCL_CODE_VECTOR_HINT_ERR_SCRATCH;
    size_t card_bytes = card_count * sizeof(*cards);
    size_t scratch_bytes = card_count * sizeof(*root_scratch);
    if (ranges_overlap(segment, sizeof(*segment), root_scratch,
                       scratch_bytes) ||
        ranges_overlap(profile, sizeof(*profile), root_scratch,
                       scratch_bytes) ||
        ranges_overlap(cards, card_bytes, root_scratch, scratch_bytes) ||
        ranges_overlap(segment->vectors,
                       card_count * sizeof(*segment->vectors),
                       root_scratch, scratch_bytes))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    for (size_t i = 0; i < card_count; i++)
        if (ranges_overlap(segment->vectors[i].values, segment->dimension,
                           root_scratch, scratch_bytes))
            return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    for (size_t i = 0; i < card_count; i++) {
        error = zcl_code_concept_card_v1_root(&cards[i], root_scratch[i]);
        if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
        if (i != 0 && memcmp(root_scratch[i - 1u], root_scratch[i], 32) >= 0)
            return ZCL_CODE_VECTOR_HINT_ERR_ORDER;
    }
    uint8_t set_root[32];
    if (!zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_CONCEPT_CARD,
            (const uint8_t (*)[32])root_scratch, card_count, set_root) ||
        memcmp(set_root, segment->concept_card_set_root, 32) != 0)
        return ZCL_CODE_VECTOR_HINT_ERR_CARD_SET_ROOT;
    for (size_t i = 0; i < card_count; i++) {
        const struct zcl_code_embedding_vector_v1 *vector =
            &segment->vectors[i];
        const struct zcl_code_concept_card_v1 *card = card_find(
            cards, (const uint8_t (*)[32])root_scratch, card_count,
            vector->concept_card_root);
        if (!card || memcmp(card->subject_root, vector->entity_root, 32) != 0 ||
            memcmp(card->source_root, segment->source_root, 32) != 0 ||
            memcmp(card->universe_root, segment->universe_root, 32) != 0 ||
            memcmp(card->context_root, segment->context_root, 32) != 0 ||
            memcmp(card->coverage_root, segment->coverage_root, 32) != 0)
            return ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING;
    }
    for (size_t i = 0; i < card_count; i++)
        memcpy(root_scratch[i], segment->vectors[i].concept_card_root, 32);
    card_roots_sort(root_scratch, card_count);
    for (size_t i = 0; i < card_count; i++) {
        uint8_t card_root[32];
        if ((i != 0 &&
             memcmp(root_scratch[i - 1u], root_scratch[i], 32) >= 0) ||
            zcl_code_concept_card_v1_root(&cards[i], card_root) !=
                ZCL_CODE_VECTOR_HINT_OK ||
            memcmp(root_scratch[i], card_root, 32) != 0)
            return ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING;
    }
    return ZCL_CODE_VECTOR_HINT_OK;
}

static bool segment_output_overlaps(
    const struct zcl_code_embedding_segment_v1 *segment,
    const void *out, size_t out_len);

enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_wire_size(
    const struct zcl_code_embedding_segment_v1 *segment, size_t *out)
{
    if (!out) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (segment_output_overlaps(segment, out, sizeof(*out)))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    *out = 0;
    enum zcl_code_vector_hint_error error =
        zcl_code_embedding_segment_v1_validate(segment);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    return segment_shape(segment, out);
}

static size_t segment_header_encode(
    const struct zcl_code_embedding_segment_v1 *segment, uint8_t *out)
{
    size_t off = 0;
    memcpy(out + off, segment_magic, sizeof(segment_magic));
    off += sizeof(segment_magic);
    zcl_write_u16_le(out + off, segment->schema_version); off += 2;
    out[off++] = segment->evidence_kind;
    out[off++] = segment->metric;
    out[off++] = segment->quantizer;
    out[off++] = segment->reserved_byte;
    zcl_write_u16_le(out + off, segment->flags); off += 2;
    zcl_write_u32_le(out + off, segment->dimension); off += 4;
    zcl_write_u32_le(out + off, segment->reserved); off += 4;
    zcl_write_u64_le(out + off, segment->vector_count); off += 8;
    zcl_write_u64_le(out + off, segment->row_bytes); off += 8;
    zcl_write_u64_le(out + off, segment->payload_bytes); off += 8;
    const uint8_t *roots[] = {
        segment->corpus_root, segment->source_root, segment->universe_root,
        segment->concept_card_set_root, segment->context_root,
        segment->coverage_root, segment->profile_root, segment->payload_root,
    };
    return roots_copy_out(out, off, roots, sizeof(roots) / sizeof(roots[0]));
}

static size_t segment_rows_encode(
    const struct zcl_code_embedding_segment_v1 *segment, uint8_t *out)
{
    size_t off = 0;
    for (uint64_t i = 0; i < segment->vector_count; i++) {
        const struct zcl_code_embedding_vector_v1 *vector =
            &segment->vectors[i];
        memcpy(out + off, vector->entity_root, 32); off += 32;
        memcpy(out + off, vector->concept_card_root, 32); off += 32;
        memcpy(out + off, vector->span_root, 32); off += 32;
        memcpy(out + off, vector->values, segment->dimension);
        off += segment->dimension;
    }
    return off;
}

static bool segment_output_overlaps(
    const struct zcl_code_embedding_segment_v1 *segment,
    const void *out, size_t out_len)
{
    if (!segment || !out) return false;
    if (ranges_overlap(segment, sizeof(*segment), out, out_len)) return true;
    if (segment->vectors &&
        ranges_overlap(segment->vectors, sizeof(*segment->vectors),
                       out, out_len))
        return true;
    if (segment->vectors &&
        segment->vector_count <= SIZE_MAX / sizeof(*segment->vectors) &&
        ranges_overlap(segment->vectors,
                       (size_t)segment->vector_count * sizeof(*segment->vectors),
                       out, out_len))
        return true;
    uint64_t maximum_vectors =
        (ZCL_CODE_EMBEDDING_SEGMENT_WIRE_MAX -
         ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES) /
        (ZCL_CODE_EMBEDDING_ROW_ROOT_BYTES + 1u);
    if (!segment->vectors || segment->vector_count > maximum_vectors ||
        segment->dimension == 0 ||
        segment->dimension > ZCL_CODE_EMBEDDING_DIMENSION_MAX)
        return false;
    for (uint64_t i = 0; i < segment->vector_count; i++)
        if (ranges_overlap(segment->vectors[i].values, segment->dimension,
                           out, out_len))
            return true;
    return false;
}

static enum zcl_code_vector_hint_error segment_wire_header_validate(
    const struct zcl_code_embedding_segment_v1 *segment)
{
    if (segment->schema_version != ZCL_CODE_EMBEDDING_SEGMENT_VERSION)
        return ZCL_CODE_VECTOR_HINT_ERR_VERSION;
    if (!hint_fields_valid(segment->evidence_kind, segment->metric,
                           segment->quantizer))
        return ZCL_CODE_VECTOR_HINT_ERR_ENUM;
    if (segment->flags != 0 || segment->reserved_byte != 0 ||
        segment->reserved != 0)
        return ZCL_CODE_VECTOR_HINT_ERR_FLAGS;
    const uint8_t *roots[] = {
        segment->corpus_root, segment->source_root, segment->universe_root,
        segment->concept_card_set_root, segment->context_root,
        segment->coverage_root, segment->profile_root, segment->payload_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!root_nonzero(roots[i]))
            return ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO;
    return ZCL_CODE_VECTOR_HINT_OK;
}

static enum zcl_code_vector_hint_error segment_wire_payload_validate(
    const uint8_t *payload,
    const struct zcl_code_embedding_segment_v1 *segment)
{
    size_t row_bytes = (size_t)segment->row_bytes;
    size_t count = (size_t)segment->vector_count;
    const uint8_t *previous = NULL;
    for (size_t i = 0; i < count; i++) {
        const uint8_t *row = payload + i * row_bytes;
        if (!root_nonzero(row) || !root_nonzero(row + 32) ||
            !root_nonzero(row + 64))
            return ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO;
        if (previous && memcmp(previous, row,
                               ZCL_CODE_EMBEDDING_ROW_ROOT_BYTES) >= 0)
            return ZCL_CODE_VECTOR_HINT_ERR_ORDER;
        previous = row;
    }
    uint8_t shape[12], actual_root[32];
    zcl_write_u32_le(shape, segment->dimension);
    zcl_write_u64_le(shape + 4, segment->vector_count);
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)payload_domain,
                   sizeof(payload_domain));
    sha3_256_write(&sha, shape, sizeof(shape));
    sha3_256_write(&sha, payload, (size_t)segment->payload_bytes);
    sha3_256_finalize(&sha, actual_root);
    return memcmp(actual_root, segment->payload_root, 32) == 0
               ? ZCL_CODE_VECTOR_HINT_OK
               : ZCL_CODE_VECTOR_HINT_ERR_PAYLOAD_ROOT;
}

enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_encode(
    const struct zcl_code_embedding_segment_v1 *segment,
    uint8_t *out, size_t out_cap, size_t *out_len)
{
    if (!out || !out_len) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (ranges_overlap(out, out_cap, out_len, sizeof(*out_len)) ||
        segment_output_overlaps(segment, out_len, sizeof(*out_len)))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    *out_len = 0;
    size_t needed = 0;
    enum zcl_code_vector_hint_error error =
        zcl_code_embedding_segment_v1_wire_size(segment, &needed);
    if (error != ZCL_CODE_VECTOR_HINT_OK) return error;
    if (segment_output_overlaps(segment, out, out_cap))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    if (out_cap < needed) return ZCL_CODE_VECTOR_HINT_ERR_CAPACITY;
    size_t off = segment_header_encode(segment, out);
    if (off != ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES)
        return ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
    off += segment_rows_encode(segment, out + off);
    if (off != needed) return ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
    *out_len = off;
    return ZCL_CODE_VECTOR_HINT_OK;
}

enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_parse(
    const uint8_t *wire, size_t wire_len,
    struct zcl_code_embedding_segment_v1 *out,
    struct zcl_code_embedding_vector_v1 *vector_storage,
    size_t vector_capacity, size_t *required_vectors)
{
    if (!out || !required_vectors) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (!wire) {
        memset(out, 0, sizeof(*out));
        *required_vectors = 0;
        return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    }
    if (ranges_overlap(wire, wire_len, out, sizeof(*out)))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    if (ranges_overlap(wire, wire_len, required_vectors,
                       sizeof(*required_vectors)) ||
        ranges_overlap(out, sizeof(*out), required_vectors,
                       sizeof(*required_vectors)))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    *required_vectors = 0;
    if (vector_capacity > SIZE_MAX / sizeof(*vector_storage)) {
        if (vector_storage &&
            ranges_overlap(out, sizeof(*out), vector_storage,
                           sizeof(*vector_storage)))
            return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
        memset(out, 0, sizeof(*out));
        return ZCL_CODE_VECTOR_HINT_ERR_CAPACITY;
    }
    size_t storage_bytes = vector_capacity * sizeof(*vector_storage);
    if (storage_bytes != 0 && !vector_storage) {
        memset(out, 0, sizeof(*out));
        return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    }
    if (ranges_overlap(wire, wire_len, vector_storage, storage_bytes) ||
        ranges_overlap(out, sizeof(*out), vector_storage, storage_bytes) ||
        ranges_overlap(vector_storage, storage_bytes, required_vectors,
                       sizeof(*required_vectors)))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    memset(out, 0, sizeof(*out));
    if (wire_len < ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES ||
        wire_len > ZCL_CODE_EMBEDDING_SEGMENT_WIRE_MAX)
        return ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
    if (memcmp(wire, segment_magic, sizeof(segment_magic)) != 0)
        return ZCL_CODE_VECTOR_HINT_ERR_WIRE_MAGIC;
    size_t off = sizeof(segment_magic);
    out->schema_version = zcl_read_u16_le(wire + off); off += 2;
    out->evidence_kind = wire[off++];
    out->metric = wire[off++];
    out->quantizer = wire[off++];
    out->reserved_byte = wire[off++];
    out->flags = zcl_read_u16_le(wire + off); off += 2;
    out->dimension = zcl_read_u32_le(wire + off); off += 4;
    out->reserved = zcl_read_u32_le(wire + off); off += 4;
    out->vector_count = zcl_read_u64_le(wire + off); off += 8;
    out->row_bytes = zcl_read_u64_le(wire + off); off += 8;
    out->payload_bytes = zcl_read_u64_le(wire + off); off += 8;
    uint8_t *roots[] = {
        out->corpus_root, out->source_root, out->universe_root,
        out->concept_card_set_root, out->context_root, out->coverage_root,
        out->profile_root, out->payload_root,
    };
    off = roots_copy_in(wire, off, roots, sizeof(roots) / sizeof(roots[0]));
    if (off != ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES) goto wire_fail;
    if (out->vector_count > (uint64_t)SIZE_MAX) goto shape_fail;
    if (out->dimension == 0 ||
        out->dimension > ZCL_CODE_EMBEDDING_DIMENSION_MAX ||
        out->vector_count == 0)
        goto limit_fail;
    uint64_t expected_row = ZCL_CODE_EMBEDDING_ROW_ROOT_BYTES +
                            (uint64_t)out->dimension;
    if (out->row_bytes != expected_row ||
        out->vector_count > UINT64_MAX / expected_row)
        goto shape_fail;
    uint64_t expected_payload = out->vector_count * expected_row;
    if (out->payload_bytes != expected_payload ||
        expected_payload > SIZE_MAX - off ||
        (size_t)expected_payload + off != wire_len)
        goto wire_fail;
    enum zcl_code_vector_hint_error wire_error =
        segment_wire_header_validate(out);
    if (wire_error == ZCL_CODE_VECTOR_HINT_OK)
        wire_error = segment_wire_payload_validate(wire + off, out);
    if (wire_error != ZCL_CODE_VECTOR_HINT_OK) {
        memset(out, 0, sizeof(*out));
        return wire_error;
    }
    *required_vectors = (size_t)out->vector_count;
    if (out->vector_count > (uint64_t)vector_capacity || !vector_storage) {
        memset(out, 0, sizeof(*out));
        return ZCL_CODE_VECTOR_HINT_ERR_CAPACITY;
    }
    for (uint64_t i = 0; i < out->vector_count; i++) {
        struct zcl_code_embedding_vector_v1 *vector = &vector_storage[i];
        memcpy(vector->entity_root, wire + off, 32); off += 32;
        memcpy(vector->concept_card_root, wire + off, 32); off += 32;
        memcpy(vector->span_root, wire + off, 32); off += 32;
        vector->values = (const int8_t *)(wire + off);
        off += out->dimension;
    }
    out->vectors = vector_storage;
    {
        enum zcl_code_vector_hint_error error =
            zcl_code_embedding_segment_v1_validate(out);
        if (error == ZCL_CODE_VECTOR_HINT_OK && off == wire_len) return error;
        memset(vector_storage, 0,
               (size_t)out->vector_count * sizeof(*vector_storage));
        memset(out, 0, sizeof(*out));
        return error == ZCL_CODE_VECTOR_HINT_OK
                   ? ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE : error;
    }

shape_fail:
    memset(out, 0, sizeof(*out));
    return ZCL_CODE_VECTOR_HINT_ERR_OVERFLOW;
limit_fail:
    memset(out, 0, sizeof(*out));
    return ZCL_CODE_VECTOR_HINT_ERR_LIMIT;
wire_fail:
    memset(out, 0, sizeof(*out));
    return ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
}

enum zcl_code_vector_hint_error zcl_code_embedding_segment_v1_root(
    const struct zcl_code_embedding_segment_v1 *segment, uint8_t out[32])
{
    if (!out) return ZCL_CODE_VECTOR_HINT_ERR_NULL;
    if (segment_output_overlaps(segment, out, 32))
        return ZCL_CODE_VECTOR_HINT_ERR_OVERLAP;
    enum zcl_code_vector_hint_error error =
        zcl_code_embedding_segment_v1_validate(segment);
    if (error != ZCL_CODE_VECTOR_HINT_OK) {
        memset(out, 0, 32);
        return error;
    }
    memset(out, 0, 32);
    uint8_t header[ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES];
    size_t header_len = segment_header_encode(segment, header);
    if (header_len != sizeof(header)) return ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const uint8_t *)segment_domain,
                   sizeof(segment_domain));
    sha3_256_write(&sha, header, sizeof(header));
    hash_vector_rows(&sha, segment->dimension, segment->vectors,
                     segment->vector_count);
    sha3_256_finalize(&sha, out);
    return ZCL_CODE_VECTOR_HINT_OK;
}

const char *zcl_code_vector_hint_error_string(
    enum zcl_code_vector_hint_error error)
{
    switch (error) {
    case ZCL_CODE_VECTOR_HINT_OK: return "ok";
    case ZCL_CODE_VECTOR_HINT_ERR_NULL: return "null";
    case ZCL_CODE_VECTOR_HINT_ERR_VERSION: return "version";
    case ZCL_CODE_VECTOR_HINT_ERR_ENUM: return "enum";
    case ZCL_CODE_VECTOR_HINT_ERR_FLAGS: return "flags";
    case ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO: return "root_zero";
    case ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE: return "wire_size";
    case ZCL_CODE_VECTOR_HINT_ERR_WIRE_MAGIC: return "wire_magic";
    case ZCL_CODE_VECTOR_HINT_ERR_LIMIT: return "limit";
    case ZCL_CODE_VECTOR_HINT_ERR_OVERFLOW: return "overflow";
    case ZCL_CODE_VECTOR_HINT_ERR_ORDER: return "order";
    case ZCL_CODE_VECTOR_HINT_ERR_PAYLOAD_ROOT: return "payload_root";
    case ZCL_CODE_VECTOR_HINT_ERR_CAPACITY: return "capacity";
    case ZCL_CODE_VECTOR_HINT_ERR_OVERLAP: return "overlap";
    case ZCL_CODE_VECTOR_HINT_ERR_PROFILE_BINDING:
        return "profile_binding";
    case ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING: return "card_binding";
    case ZCL_CODE_VECTOR_HINT_ERR_CARD_SET_ROOT: return "card_set_root";
    case ZCL_CODE_VECTOR_HINT_ERR_SCRATCH: return "scratch";
    }
    return "unknown";
}
