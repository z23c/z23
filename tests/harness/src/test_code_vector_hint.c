/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical and born-red MODEL_HINT code-vector codec acceptance. */

#include "test/test_core.h"

#include "codeindex/codeindex_vector_hint.h"
#include "ontology/ontology.h"

#include <string.h>

static void vh_root(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(first + i);
}

static void vh_hex(const uint8_t root[32], char out[65])
{
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        out[i * 2] = digits[root[i] >> 4];
        out[i * 2 + 1] = digits[root[i] & 15];
    }
    out[64] = '\0';
}

static void vh_card(struct zcl_code_concept_card_v1 *card)
{
    memset(card, 0, sizeof(*card));
    card->schema_version = ZCL_CODE_CONCEPT_CARD_VERSION;
    card->kind = ZCL_CODE_CONCEPT_CARD_CONFIGURED_ENTITY;
    card->evidence_kind = ZCL_CODE_CONCEPT_EVIDENCE_EXACT_ROOTS;
    vh_root(card->source_root, 0x01);
    vh_root(card->universe_root, 0x11);
    vh_root(card->ontology_root, 0x21);
    vh_root(card->context_root, 0x31);
    vh_root(card->subject_root, 0x41);
    vh_root(card->fact_manifest_root, 0x51);
    vh_root(card->coverage_root, 0x61);
    vh_root(card->extractor_root, 0x71);
}

static void vh_profile(struct zcl_code_embedding_profile_v1 *profile)
{
    memset(profile, 0, sizeof(*profile));
    profile->schema_version = ZCL_CODE_EMBEDDING_PROFILE_VERSION;
    profile->evidence_kind = ZCL_CODE_HINT_EVIDENCE_MODEL_HINT;
    profile->metric = ZCL_CODE_EMBEDDING_METRIC_INTEGER_DOT;
    profile->quantizer = ZCL_CODE_EMBEDDING_QUANTIZER_SIGNED_INT8;
    profile->dimension = 4;
    vh_root(profile->projection_root, 0x02);
    vh_root(profile->tokenizer_root, 0x12);
    vh_root(profile->preprocessing_root, 0x22);
    vh_root(profile->model_root, 0x32);
    vh_root(profile->weights_root, 0x42);
    vh_root(profile->license_root, 0x52);
    vh_root(profile->rights_root, 0x62);
    vh_root(profile->accepted_runner_root, 0x72);
    vh_root(profile->accepted_action_root, 0x82);
    vh_root(profile->reproducibility_root, 0x92);
}

static void vh_vectors(struct zcl_code_embedding_vector_v1 vectors[2],
                       int8_t values[2][4])
{
    memset(vectors, 0, 2 * sizeof(*vectors));
    static const int8_t fixed[2][4] = {
        { INT8_MIN, -1, 0, INT8_MAX },
        { 1, 2, 3, 4 },
    };
    memcpy(values, fixed, sizeof(fixed));
    vh_root(vectors[0].entity_root, 0x03);
    vh_root(vectors[0].concept_card_root, 0x23);
    vh_root(vectors[0].span_root, 0x43);
    vectors[0].values = values[0];
    vh_root(vectors[1].entity_root, 0x83);
    vh_root(vectors[1].concept_card_root, 0xa3);
    vh_root(vectors[1].span_root, 0xc3);
    vectors[1].values = values[1];
}

static bool vh_segment(struct zcl_code_embedding_segment_v1 *segment,
                       struct zcl_code_embedding_vector_v1 vectors[2],
                       int8_t values[2][4])
{
    memset(segment, 0, sizeof(*segment));
    vh_vectors(vectors, values);
    segment->schema_version = ZCL_CODE_EMBEDDING_SEGMENT_VERSION;
    segment->evidence_kind = ZCL_CODE_HINT_EVIDENCE_MODEL_HINT;
    segment->metric = ZCL_CODE_EMBEDDING_METRIC_INTEGER_DOT;
    segment->quantizer = ZCL_CODE_EMBEDDING_QUANTIZER_SIGNED_INT8;
    segment->dimension = 4;
    segment->vector_count = 2;
    segment->row_bytes = ZCL_CODE_EMBEDDING_ROW_ROOT_BYTES + 4;
    segment->payload_bytes = segment->row_bytes * segment->vector_count;
    vh_root(segment->corpus_root, 0x04);
    vh_root(segment->source_root, 0x14);
    vh_root(segment->universe_root, 0x24);
    vh_root(segment->concept_card_set_root, 0x34);
    vh_root(segment->context_root, 0x44);
    vh_root(segment->coverage_root, 0x54);
    vh_root(segment->profile_root, 0x64);
    segment->vectors = vectors;
    return zcl_code_embedding_payload_v1_root(
               segment->dimension, segment->vectors, segment->vector_count,
               segment->payload_root) == ZCL_CODE_VECTOR_HINT_OK;
}

static bool vh_bound_segment(
    struct zcl_code_embedding_segment_v1 *segment,
    struct zcl_code_embedding_vector_v1 vectors[2], int8_t values[2][4],
    struct zcl_code_embedding_profile_v1 *profile,
    struct zcl_code_concept_card_v1 cards[2])
{
    if (!vh_segment(segment, vectors, values)) return false;
    vh_profile(profile);
    if (zcl_code_embedding_profile_v1_root(
            profile, segment->profile_root) != ZCL_CODE_VECTOR_HINT_OK)
        return false;
    uint8_t roots[2][32];
    for (size_t i = 0; i < 2; i++) {
        vh_card(&cards[i]);
        cards[i].kind = i == 0 ? ZCL_CODE_CONCEPT_CARD_CONFIGURED_ENTITY
                               : ZCL_CODE_CONCEPT_CARD_USAGE_NEIGHBORHOOD;
        memcpy(cards[i].source_root, segment->source_root, 32);
        memcpy(cards[i].universe_root, segment->universe_root, 32);
        memcpy(cards[i].context_root, segment->context_root, 32);
        memcpy(cards[i].coverage_root, segment->coverage_root, 32);
        memcpy(cards[i].subject_root, vectors[i].entity_root, 32);
        vh_root(cards[i].ontology_root, (uint8_t)(0x35u + i * 0x20u));
        vh_root(cards[i].fact_manifest_root, (uint8_t)(0x45u + i * 0x20u));
        vh_root(cards[i].extractor_root, (uint8_t)(0x55u + i * 0x20u));
        if (zcl_code_concept_card_v1_root(&cards[i], roots[i]) !=
            ZCL_CODE_VECTOR_HINT_OK)
            return false;
    }
    if (memcmp(roots[0], roots[1], 32) > 0) {
        struct zcl_code_concept_card_v1 card = cards[0];
        uint8_t root[32];
        cards[0] = cards[1]; cards[1] = card;
        memcpy(root, roots[0], 32);
        memcpy(roots[0], roots[1], 32);
        memcpy(roots[1], root, 32);
    }
    for (size_t vector = 0; vector < 2; vector++) {
        bool found = false;
        for (size_t card = 0; card < 2; card++) {
            if (memcmp(cards[card].subject_root,
                       vectors[vector].entity_root, 32) != 0)
                continue;
            memcpy(vectors[vector].concept_card_root, roots[card], 32);
            found = true;
        }
        if (!found) return false;
    }
    if (!zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_CONCEPT_CARD,
            (const uint8_t (*)[32])roots, 2,
            segment->concept_card_set_root))
        return false;
    return zcl_code_embedding_payload_v1_root(
               segment->dimension, segment->vectors, segment->vector_count,
               segment->payload_root) == ZCL_CODE_VECTOR_HINT_OK;
}

struct vh_ontology_fixture {
    struct zcl_source_universe_v1 universe;
    struct zcl_ontology_term_v1 terms[3];
    struct zcl_ontology_context_v1 context;
    struct zcl_ontology_manifest_v1 manifest;
    struct zcl_ontology_manifest_inputs_v1 inputs;
    uint8_t subject_identity_root[32];
    uint8_t entity_type_identity_root[32];
};

static bool vh_sort_terms(struct zcl_ontology_term_v1 *terms, size_t count,
                          uint8_t (*roots)[32])
{
    for (size_t i = 0; i < count; i++)
        if (!zcl_ontology_term_v1_root(&terms[i], roots[i])) return false;
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1u; j < count; j++) {
            int order = memcmp(roots[i], roots[j], 32);
            if (order == 0) return false;
            if (order > 0) {
                struct zcl_ontology_term_v1 term = terms[i];
                uint8_t term_root[32];
                terms[i] = terms[j];
                terms[j] = term;
                memcpy(term_root, roots[i], 32);
                memcpy(roots[i], roots[j], 32);
                memcpy(roots[j], term_root, 32);
            }
        }
    }
    return true;
}

static bool vh_ontology_fixture_init(
    struct vh_ontology_fixture *fixture,
    struct zcl_code_concept_card_v1 *card)
{
    memset(fixture, 0, sizeof(*fixture));
    fixture->universe.schema_version = ZCL_SOURCE_UNIVERSE_VERSION;
    fixture->universe.coverage_mask = ZCL_SOURCE_COVER_ALL;
    fixture->universe.governed_path_count = 3;
    fixture->universe.total_bytes = 4096;
    vh_root(fixture->universe.source_manifest_root, 0x01);
    vh_root(fixture->universe.governed_paths_root, 0x21);
    vh_root(fixture->universe.generated_paths_root, 0x41);
    vh_root(fixture->universe.vendor_paths_root, 0x61);
    vh_root(fixture->universe.metadata_paths_root, 0x81);
    vh_root(fixture->universe.publishable_paths_root, 0xa1);
    vh_root(fixture->universe.consensus_seal_root, 0xc1);
    vh_root(fixture->universe.indexed_paths_root, 0xe1);
    uint8_t universe_root[32], imports_root[32], vocabulary_root[32];
    if (!zcl_source_universe_v1_root(&fixture->universe, universe_root) ||
        !zcl_ontology_import_manifest_v1_root(
            universe_root, NULL, 0, imports_root))
        return false;
    vh_root(vocabulary_root, 0x19);
    uint8_t meta_type[32];
    vh_root(meta_type, 0x39);
    vh_root(fixture->entity_type_identity_root, 0x59);
    vh_root(fixture->subject_identity_root, 0x79);
    for (size_t i = 0; i < 3; i++) {
        fixture->terms[i].schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
        memcpy(fixture->terms[i].vocabulary_root, vocabulary_root, 32);
        vh_root(fixture->terms[i].lexical_root,
                (uint8_t)(0x29u + i * 0x20u));
    }
    fixture->terms[0].kind = ZCL_ONTOLOGY_TERM_TYPE;
    memcpy(fixture->terms[0].type_root, meta_type, 32);
    memcpy(fixture->terms[0].identity_root, meta_type, 32);
    fixture->terms[1].kind = ZCL_ONTOLOGY_TERM_TYPE;
    memcpy(fixture->terms[1].type_root, meta_type, 32);
    memcpy(fixture->terms[1].identity_root,
           fixture->entity_type_identity_root, 32);
    fixture->terms[2].kind = ZCL_ONTOLOGY_TERM_ENTITY;
    memcpy(fixture->terms[2].type_root,
           fixture->entity_type_identity_root, 32);
    memcpy(fixture->terms[2].identity_root,
           fixture->subject_identity_root, 32);
    uint8_t term_roots[3][32];
    if (!vh_sort_terms(fixture->terms, 3, term_roots)) return false;

    fixture->context.schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    fixture->context.kind = ZCL_ONTOLOGY_CONTEXT_CORPUS;
    memcpy(fixture->context.universe_root, universe_root, 32);
    memcpy(fixture->context.import_manifest_root, imports_root, 32);
    vh_root(fixture->context.subject_root, 0x99);
    vh_root(fixture->context.policy_root, 0xb9);
    uint8_t context_root[1][32];
    if (!zcl_ontology_context_v1_root(
            &fixture->context, context_root[0]))
        return false;

    fixture->manifest.schema_version = ZCL_ONTOLOGY_OBJECT_VERSION;
    fixture->manifest.term_count = 3;
    fixture->manifest.context_count = 1;
    memcpy(fixture->manifest.source_root,
           fixture->universe.source_manifest_root, 32);
    memcpy(fixture->manifest.universe_root, universe_root, 32);
    memcpy(fixture->manifest.vocabulary_root, vocabulary_root, 32);
    vh_root(fixture->manifest.extractor_root, 0x31);
    vh_root(fixture->manifest.policy_root, 0x51);
    if (!zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_TERM,
            (const uint8_t (*)[32])term_roots, 3,
            fixture->manifest.term_set_root) ||
        !zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_CONTEXT,
            (const uint8_t (*)[32])context_root, 1,
            fixture->manifest.context_set_root))
        return false;
    uint8_t *empty_roots[] = {
        fixture->manifest.predicate_set_root,
        fixture->manifest.formula_set_root,
        fixture->manifest.rule_set_root,
        fixture->manifest.assertion_set_root,
        fixture->manifest.coverage_set_root,
        fixture->manifest.domain_set_root,
        fixture->manifest.gap_set_root,
    };
    const enum zcl_ontology_object_kind empty_kinds[] = {
        ZCL_ONTOLOGY_OBJECT_PREDICATE,
        ZCL_ONTOLOGY_OBJECT_FORMULA,
        ZCL_ONTOLOGY_OBJECT_RULE,
        ZCL_ONTOLOGY_OBJECT_ASSERTION,
        ZCL_ONTOLOGY_OBJECT_COVERAGE,
        ZCL_ONTOLOGY_OBJECT_DOMAIN,
        ZCL_ONTOLOGY_OBJECT_GAP,
    };
    for (size_t i = 0; i < sizeof(empty_roots) / sizeof(empty_roots[0]); i++)
        if (!zcl_ontology_object_set_v1_root(
                empty_kinds[i], NULL, 0, empty_roots[i]))
            return false;
    fixture->inputs.terms = fixture->terms;
    fixture->inputs.term_count = 3;
    fixture->inputs.contexts = &fixture->context;
    fixture->inputs.context_count = 1;
    if (!zcl_ontology_manifest_v1_validate(
            &fixture->manifest, &fixture->universe, &fixture->inputs))
        return false;
    vh_card(card);
    memcpy(card->source_root, fixture->manifest.source_root, 32);
    memcpy(card->universe_root, fixture->manifest.universe_root, 32);
    if (!zcl_ontology_manifest_v1_root(
            &fixture->manifest, card->ontology_root))
        return false;
    memcpy(card->context_root, context_root[0], 32);
    memcpy(card->subject_root, fixture->subject_identity_root, 32);
    memcpy(card->fact_manifest_root,
           fixture->manifest.assertion_set_root, 32);
    memcpy(card->coverage_root, fixture->manifest.coverage_set_root, 32);
    memcpy(card->extractor_root, fixture->manifest.extractor_root, 32);
    return true;
}

static int concept_card_codec(void)
{
    int failures = 0;
    TEST_CASE("code vector concept-card canonical codec") {
        struct zcl_code_concept_card_v1 card, parsed;
        uint8_t wire[ZCL_CODE_CONCEPT_CARD_WIRE_BYTES], root[32], root2[32];
        char hex[65];
        vh_card(&card);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_concept_card_v1_encode(&card, wire));
        ASSERT(memcmp(wire, "ZCCARD1", 7) == 0);
        ASSERT_EQ(1, wire[8]);
        ASSERT_EQ(ZCL_CODE_CONCEPT_CARD_CONFIGURED_ENTITY, wire[10]);
        ASSERT_EQ(ZCL_CODE_CONCEPT_EVIDENCE_EXACT_ROOTS, wire[11]);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_concept_card_v1_parse(wire, sizeof(wire), &parsed));
        ASSERT_EQ(card.kind, parsed.kind);
        ASSERT(memcmp(card.fact_manifest_root, parsed.fact_manifest_root, 32) == 0);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_concept_card_v1_root(&card, root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_concept_card_v1_root(&parsed, root2));
        ASSERT(memcmp(root, root2, 32) == 0);
        vh_hex(root, hex);
#if defined(CODE_VECTOR_HINT_CAPTURE_KATS)
        printf("concept_card_root=%s\n", hex);
#else
        ASSERT_STR_EQ("7f615143fcf6cf6c3f969c846fcd139afe2d5d24a1c1ec6c60239dcf8c76bf52",
                      hex);
#endif
    } TEST_END
    return failures;
}

static int concept_card_refusals(void)
{
    int failures = 0;
    TEST_CASE("code vector concept-card malformed objects refuse") {
        struct zcl_code_concept_card_v1 card, parsed;
        uint8_t wire[ZCL_CODE_CONCEPT_CARD_WIRE_BYTES];
        vh_card(&card);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_concept_card_v1_encode(&card, wire));
        card.kind = 0xff;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ENUM,
                  zcl_code_concept_card_v1_validate(&card));
        vh_card(&card);
        card.evidence_kind = 0xff;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ENUM,
                  zcl_code_concept_card_v1_validate(&card));
        vh_card(&card);
        memset(card.coverage_root, 0, 32);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO,
                  zcl_code_concept_card_v1_validate(&card));
        vh_card(&card);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_NULL,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, NULL, NULL, NULL));
        wire[0] ^= 1;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_WIRE_MAGIC,
                  zcl_code_concept_card_v1_parse(wire, sizeof(wire), &parsed));
        ASSERT_EQ(0, parsed.schema_version);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE,
                  zcl_code_concept_card_v1_parse(wire, sizeof(wire) - 1,
                                                 &parsed));
    } TEST_END
    return failures;
}

static int concept_card_ontology_bindings(void)
{
    int failures = 0;
    TEST_CASE("code vector concept cards bind accepted ontology evidence") {
        struct vh_ontology_fixture fixture;
        struct zcl_code_concept_card_v1 card;
        ASSERT(vh_ontology_fixture_init(&fixture, &card));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));

        card.source_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
        card.source_root[0] ^= 1u;
        card.universe_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
        card.universe_root[0] ^= 1u;
        card.ontology_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
        card.ontology_root[0] ^= 1u;
        card.fact_manifest_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
        card.fact_manifest_root[0] ^= 1u;
        card.coverage_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
        card.coverage_root[0] ^= 1u;
        card.extractor_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
        card.extractor_root[0] ^= 1u;
        card.context_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
        card.context_root[0] ^= 1u;
        card.subject_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
        memcpy(card.subject_root, fixture.entity_type_identity_root, 32);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
        memcpy(card.subject_root, fixture.subject_identity_root, 32);
        fixture.manifest.policy_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_concept_card_v1_validate_ontology(
                      &card, &fixture.manifest, &fixture.universe,
                      &fixture.inputs));
    } TEST_END
    return failures;
}

static int profile_codec_and_refusals(void)
{
    int failures = 0;
    TEST_CASE("code vector profile canonical MODEL_HINT codec") {
        struct zcl_code_embedding_profile_v1 profile, parsed;
        uint8_t wire[ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES], root[32], root2[32];
        char hex[65];
        vh_profile(&profile);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_profile_v1_encode(&profile, wire));
        ASSERT(memcmp(wire, "ZEMPRO1", 7) == 0);
        ASSERT_EQ(ZCL_CODE_HINT_EVIDENCE_MODEL_HINT, wire[10]);
        ASSERT_EQ(ZCL_CODE_EMBEDDING_METRIC_INTEGER_DOT, wire[11]);
        ASSERT_EQ(ZCL_CODE_EMBEDDING_QUANTIZER_SIGNED_INT8, wire[12]);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_profile_v1_parse(wire, sizeof(wire),
                                                      &parsed));
        ASSERT_EQ(4, parsed.dimension);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_profile_v1_root(&profile, root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_profile_v1_root(&parsed, root2));
        ASSERT(memcmp(root, root2, 32) == 0);
        vh_hex(root, hex);
#if defined(CODE_VECTOR_HINT_CAPTURE_KATS)
        printf("embedding_profile_root=%s\n", hex);
#else
        ASSERT_STR_EQ("5033f77723c3d839274c4d046fef7429cb6049141241879a3999b484b8c186b5",
                      hex);
#endif
        profile.evidence_kind = 2;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ENUM,
                  zcl_code_embedding_profile_v1_validate(&profile));
        vh_profile(&profile);
        profile.dimension = ZCL_CODE_EMBEDDING_DIMENSION_MAX + 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_LIMIT,
                  zcl_code_embedding_profile_v1_validate(&profile));
        vh_profile(&profile);
        memset(profile.rights_root, 0, sizeof(profile.rights_root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO,
                  zcl_code_embedding_profile_v1_validate(&profile));
    } TEST_END
    return failures;
}

static int segment_codec(void)
{
    int failures = 0;
    TEST_CASE("code vector segment canonical signed-int8 codec") {
        struct zcl_code_embedding_segment_v1 segment, parsed;
        struct zcl_code_embedding_vector_v1 vectors[2], parsed_vectors[2];
        int8_t values[2][4];
        uint8_t wire[504], root[32], root2[32];
        size_t wire_size = 0, written = 0, required = 0;
        char hex[65];
        ASSERT(vh_segment(&segment, vectors, values));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_wire_size(&segment,
                                                          &wire_size));
        ASSERT_EQ(sizeof(wire), wire_size);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire), &written));
        ASSERT_EQ(sizeof(wire), written);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, parsed_vectors, 2,
                      &required));
        ASSERT_EQ(2, required);
        ASSERT_EQ(2, parsed.vector_count);
        ASSERT_EQ(INT8_MIN, parsed.vectors[0].values[0]);
        ASSERT_EQ(INT8_MAX, parsed.vectors[0].values[3]);
        /* The same concatenated row bytes under a different row grammar must
         * not share a payload root. Collapse both 100-byte rows into one
         * 200-byte row with a 104-dimensional value tail. */
        int8_t collapsed_values[104];
        size_t collapsed_off = 0;
        memcpy(collapsed_values + collapsed_off, values[0], 4);
        collapsed_off += 4;
        memcpy(collapsed_values + collapsed_off, vectors[1].entity_root, 32);
        collapsed_off += 32;
        memcpy(collapsed_values + collapsed_off,
               vectors[1].concept_card_root, 32);
        collapsed_off += 32;
        memcpy(collapsed_values + collapsed_off, vectors[1].span_root, 32);
        collapsed_off += 32;
        memcpy(collapsed_values + collapsed_off, values[1], 4);
        collapsed_off += 4;
        ASSERT_EQ(sizeof(collapsed_values), collapsed_off);
        struct zcl_code_embedding_vector_v1 collapsed = vectors[0];
        collapsed.values = collapsed_values;
        uint8_t regular_payload[32], collapsed_payload[32];
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_payload_v1_root(
                      4, vectors, 2, regular_payload));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_payload_v1_root(
                      104, &collapsed, 1, collapsed_payload));
        ASSERT(memcmp(regular_payload, collapsed_payload, 32) != 0);
        uint64_t maximum_vectors =
            (ZCL_CODE_EMBEDDING_SEGMENT_WIRE_MAX -
             ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES) /
            (ZCL_CODE_EMBEDDING_ROW_ROOT_BYTES + 1u);
        memset(collapsed_payload, 0xa5, sizeof(collapsed_payload));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_LIMIT,
                  zcl_code_embedding_payload_v1_root(
                      1, vectors, maximum_vectors + 1u,
                      collapsed_payload));
        for (size_t i = 0; i < sizeof(collapsed_payload); i++)
            ASSERT_EQ(0, collapsed_payload[i]);
        memset(collapsed_payload, 0xa5, sizeof(collapsed_payload));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERFLOW,
                  zcl_code_embedding_payload_v1_root(
                      1, vectors, UINT64_MAX, collapsed_payload));
        for (size_t i = 0; i < sizeof(collapsed_payload); i++)
            ASSERT_EQ(0, collapsed_payload[i]);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_root(&segment, root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_root(&parsed, root2));
        ASSERT(memcmp(root, root2, 32) == 0);
        vh_hex(root, hex);
#if defined(CODE_VECTOR_HINT_CAPTURE_KATS)
        printf("embedding_segment_root=%s\n", hex);
#else
        ASSERT_STR_EQ("ebbbfa043cb3bef705c1cae04c2626cbd1b01836cbf2e7da216dda8bee4848af",
                      hex);
#endif
    } TEST_END
    return failures;
}

static int segment_refusals(void)
{
    int failures = 0;
    TEST_CASE("code vector segment malformed and noncanonical rows refuse") {
        struct zcl_code_embedding_segment_v1 segment, parsed;
        struct zcl_code_embedding_vector_v1 vectors[2], parsed_vectors[2];
        int8_t values[2][4];
        uint8_t wire[504];
        size_t written = 0, required = 0;
        ASSERT(vh_segment(&segment, vectors, values));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire), &written));
        struct zcl_code_embedding_vector_v1 swap = vectors[0];
        vectors[0] = vectors[1];
        vectors[1] = swap;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ORDER,
                  zcl_code_embedding_segment_v1_validate(&segment));
        ASSERT(vh_segment(&segment, vectors, values));
        segment.payload_root[0] ^= 1;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_PAYLOAD_ROOT,
                  zcl_code_embedding_segment_v1_validate(&segment));
        ASSERT(vh_segment(&segment, vectors, values));
        segment.row_bytes++;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERFLOW,
                  zcl_code_embedding_segment_v1_validate(&segment));
        ASSERT(vh_segment(&segment, vectors, values));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CAPACITY,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire) - 1, &written));
        ASSERT_EQ(0, written);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire), &written));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CAPACITY,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, NULL, 0, &required));
        ASSERT_EQ(2, required);
        ASSERT_EQ(0, parsed.schema_version);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CAPACITY,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, parsed_vectors, 1,
                      &required));
        ASSERT_EQ(2, required);
        wire[8] = 2;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_VERSION,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, NULL, 0, &required));
        ASSERT_EQ(0, required);
        ASSERT_EQ(0, parsed.schema_version);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire), &written));
        wire[10] = 2;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ENUM,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, NULL, 0, &required));
        ASSERT_EQ(0, required);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire), &written));
        memset(wire + 48, 0, 32);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ROOT_ZERO,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, NULL, 0, &required));
        ASSERT_EQ(0, required);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire), &written));
        wire[written - 1u] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_PAYLOAD_ROOT,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, NULL, 0, &required));
        ASSERT_EQ(0, required);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire), &written));
        memset(wire + 16, 0, 4);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_LIMIT,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, parsed_vectors, 2,
                      &required));
        ASSERT_EQ(0, required);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire), &written));
        memset(wire + 24, 0, 8);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_LIMIT,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, parsed_vectors, 2,
                      &required));
        ASSERT_EQ(0, required);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, wire, sizeof(wire), &written));
        wire[11] = 2;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ENUM,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written, &parsed, parsed_vectors, 2,
                      &required));
        ASSERT_EQ(0, parsed.schema_version);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_WIRE_SIZE,
                  zcl_code_embedding_segment_v1_parse(
                      wire, written - 1, &parsed, parsed_vectors, 2,
                      &required));
        struct zcl_code_embedding_profile_v1 profile;
        vh_profile(&profile);
        ASSERT(vh_segment(&segment, vectors, values));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_profile_v1_root(
                      &profile, segment.profile_root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_validate_profile(
                      &segment, &profile));
        profile.dimension++;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ENUM,
                  zcl_code_embedding_segment_v1_validate_profile(
                      &segment, &profile));
        vh_profile(&profile);
        segment.profile_root[0] ^= 1;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_PROFILE_BINDING,
                  zcl_code_embedding_segment_v1_validate_profile(
                      &segment, &profile));
    } TEST_END
    return failures;
}

static int segment_card_bindings(void)
{
    int failures = 0;
    TEST_CASE("code vector rows bind exact concept cards and header roots") {
        struct zcl_code_embedding_segment_v1 segment;
        struct zcl_code_embedding_vector_v1 vectors[2];
        struct zcl_code_embedding_profile_v1 profile;
        struct zcl_code_concept_card_v1 cards[2];
        int8_t values[2][4];
        uint8_t scratch[2][32];
        ASSERT(vh_bound_segment(
            &segment, vectors, values, &profile, cards));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &segment, &profile, cards, 2, scratch, 2));

        segment.source_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &segment, &profile, cards, 2, scratch, 2));
        segment.source_root[0] ^= 1u;
        segment.context_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &segment, &profile, cards, 2, scratch, 2));
        segment.context_root[0] ^= 1u;
        segment.coverage_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &segment, &profile, cards, 2, scratch, 2));
        segment.coverage_root[0] ^= 1u;

        segment.concept_card_set_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_SET_ROOT,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &segment, &profile, cards, 2, scratch, 2));
        segment.concept_card_set_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_SCRATCH,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &segment, &profile, cards, 2, scratch, 1));

        vectors[0].entity_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_payload_v1_root(
                      segment.dimension, vectors, 2, segment.payload_root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &segment, &profile, cards, 2, scratch, 2));
        vectors[0].entity_root[0] ^= 1u;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_payload_v1_root(
                      segment.dimension, vectors, 2, segment.payload_root));

        struct zcl_code_embedding_segment_v1 same_segment = segment;
        struct zcl_code_embedding_vector_v1 same_vectors[2] = {
            vectors[0], vectors[1],
        };
        struct zcl_code_concept_card_v1 same_cards[2] = {
            cards[0], cards[1],
        };
        uint8_t same_roots[2][32];
        for (size_t i = 0; i < 2; i++) {
            memcpy(same_cards[i].subject_root,
                   same_vectors[0].entity_root, 32);
            ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                      zcl_code_concept_card_v1_root(
                          &same_cards[i], same_roots[i]));
        }
        if (memcmp(same_roots[0], same_roots[1], 32) > 0) {
            struct zcl_code_concept_card_v1 card = same_cards[0];
            uint8_t card_root[32];
            same_cards[0] = same_cards[1];
            same_cards[1] = card;
            memcpy(card_root, same_roots[0], 32);
            memcpy(same_roots[0], same_roots[1], 32);
            memcpy(same_roots[1], card_root, 32);
        }
        memcpy(same_vectors[1].entity_root,
               same_vectors[0].entity_root, 32);
        memcpy(same_vectors[0].concept_card_root, same_roots[0], 32);
        memcpy(same_vectors[1].concept_card_root, same_roots[1], 32);
        same_segment.vectors = same_vectors;
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_CONCEPT_CARD,
            (const uint8_t (*)[32])same_roots, 2,
            same_segment.concept_card_set_root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_payload_v1_root(
                      same_segment.dimension, same_vectors, 2,
                      same_segment.payload_root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &same_segment, &profile, same_cards, 2, scratch, 2));
        memcpy(same_vectors[1].concept_card_root, same_roots[0], 32);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_payload_v1_root(
                      same_segment.dimension, same_vectors, 2,
                      same_segment.payload_root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &same_segment, &profile, same_cards, 2, scratch, 2));

        struct zcl_code_concept_card_v1 changed_cards[2] = {
            cards[0], cards[1],
        };
        changed_cards[0].fact_manifest_root[0] ^= 1u;
        uint8_t changed_roots[2][32];
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_concept_card_v1_root(
                      &changed_cards[0], changed_roots[0]));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_concept_card_v1_root(
                      &changed_cards[1], changed_roots[1]));
        if (memcmp(changed_roots[0], changed_roots[1], 32) > 0) {
            struct zcl_code_concept_card_v1 card = changed_cards[0];
            uint8_t changed_root[32];
            changed_cards[0] = changed_cards[1];
            changed_cards[1] = card;
            memcpy(changed_root, changed_roots[0], 32);
            memcpy(changed_roots[0], changed_roots[1], 32);
            memcpy(changed_roots[1], changed_root, 32);
        }
        ASSERT(zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_CONCEPT_CARD,
            (const uint8_t (*)[32])changed_roots, 2,
            segment.concept_card_set_root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_CARD_BINDING,
                  zcl_code_embedding_segment_v1_validate_cards(
                      &segment, &profile, changed_cards, 2, scratch, 2));
    } TEST_END
    return failures;
}

static int overlap_and_output_refusals(void)
{
    int failures = 0;
    TEST_CASE("code vector codecs reject overlapping ownership") {
        union {
            max_align_t align;
            uint8_t bytes[ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES];
        } fixed;
        struct zcl_code_concept_card_v1 *card = (void *)fixed.bytes;
        vh_card(card);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_concept_card_v1_encode(card, fixed.bytes));
        vh_card(card);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_concept_card_v1_root(card, card->subject_root));
        struct zcl_code_concept_card_v1 card_value;
        vh_card(&card_value);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_concept_card_v1_encode(&card_value, fixed.bytes));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_concept_card_v1_parse(
                      fixed.bytes, ZCL_CODE_CONCEPT_CARD_WIRE_BYTES,
                      (struct zcl_code_concept_card_v1 *)(void *)fixed.bytes));

        struct zcl_code_embedding_profile_v1 *profile = (void *)fixed.bytes;
        vh_profile(profile);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_profile_v1_encode(profile, fixed.bytes));
        vh_profile(profile);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_profile_v1_root(
                      profile, profile->rights_root));
        struct zcl_code_embedding_profile_v1 profile_value;
        vh_profile(&profile_value);
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_profile_v1_encode(
                      &profile_value, fixed.bytes));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_profile_v1_parse(
                      fixed.bytes, ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES,
                      (struct zcl_code_embedding_profile_v1 *)(void *)fixed.bytes));

        struct zcl_code_embedding_segment_v1 segment, parsed;
        struct zcl_code_embedding_vector_v1 vectors[2], parsed_vectors[2];
        int8_t values[2][4];
        union {
            max_align_t align;
            uint8_t bytes[520];
        } segment_wire;
        size_t written = 0, required = 0;
        ASSERT(vh_segment(&segment, vectors, values));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, segment_wire.bytes, 504, &written));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_segment_v1_parse(
                      segment_wire.bytes, written, &parsed,
                      (struct zcl_code_embedding_vector_v1 *)(void *)(
                          segment_wire.bytes +
                          ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES),
                      2, &required));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_segment_v1_parse(
                      segment_wire.bytes, written,
                      (struct zcl_code_embedding_segment_v1 *)(void *)
                          segment_wire.bytes,
                      parsed_vectors, 2, &required));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_segment_v1_root(
                      &segment, segment.payload_root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_segment_v1_wire_size(
                      &segment, (size_t *)(void *)&segment.row_bytes));
        struct zcl_code_embedding_segment_v1 wide_segment = segment;
        struct zcl_code_embedding_vector_v1 wide_vector = vectors[0];
        union {
            max_align_t align;
            int8_t bytes[sizeof(size_t)];
        } wide_values = {0};
        wide_vector.values = wide_values.bytes;
        wide_segment.dimension = sizeof(wide_values.bytes);
        wide_segment.vector_count = 1;
        wide_segment.row_bytes = ZCL_CODE_EMBEDDING_ROW_ROOT_BYTES +
                                 sizeof(wide_values.bytes);
        wide_segment.payload_bytes = wide_segment.row_bytes;
        wide_segment.vectors = &wide_vector;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_OK,
                  zcl_code_embedding_payload_v1_root(
                      wide_segment.dimension, wide_segment.vectors,
                      wide_segment.vector_count, wide_segment.payload_root));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_segment_v1_wire_size(
                      &wide_segment,
                      (size_t *)(void *)wide_values.bytes));
        struct zcl_code_embedding_vector_v1 malformed_vectors[2] = {
            vectors[1], vectors[0],
        };
        union {
            max_align_t align;
            int8_t bytes[32];
        } alias_values = {0};
        malformed_vectors[0].values = alias_values.bytes;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_payload_v1_root(
                      32, malformed_vectors, 2,
                      (uint8_t *)(void *)alias_values.bytes));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_OVERLAP,
                  zcl_code_embedding_segment_v1_encode(
                      &segment, segment_wire.bytes, 504,
                      (size_t *)(void *)&segment.payload_bytes));
    } TEST_END

    return failures;
}

static int error_output_refusals(void)
{
    int failures = 0;
    TEST_CASE("code vector root failures clear nonoverlapping outputs") {
        struct zcl_code_concept_card_v1 card;
        struct zcl_code_embedding_profile_v1 profile;
        struct zcl_code_embedding_segment_v1 segment;
        struct zcl_code_embedding_vector_v1 vectors[2];
        int8_t values[2][4];
        uint8_t root[32];
        struct zcl_code_concept_card_v1 parsed_card;
        struct zcl_code_embedding_profile_v1 parsed_profile;
        size_t required = SIZE_MAX;
        memset(root, 0xa5, sizeof(root));
        vh_card(&card);
        card.kind = 0xff;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ENUM,
                  zcl_code_concept_card_v1_root(&card, root));
        for (size_t i = 0; i < sizeof(root); i++) ASSERT_EQ(0, root[i]);
        memset(&parsed_card, 0xa5, sizeof(parsed_card));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_NULL,
                  zcl_code_concept_card_v1_parse(
                      NULL, ZCL_CODE_CONCEPT_CARD_WIRE_BYTES,
                      &parsed_card));
        ASSERT_EQ(0, parsed_card.schema_version);
        memset(&parsed_profile, 0xa5, sizeof(parsed_profile));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_NULL,
                  zcl_code_embedding_profile_v1_parse(
                      NULL, ZCL_CODE_EMBEDDING_PROFILE_WIRE_BYTES,
                      &parsed_profile));
        ASSERT_EQ(0, parsed_profile.schema_version);
        memset(&segment, 0xa5, sizeof(segment));
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_NULL,
                  zcl_code_embedding_segment_v1_parse(
                      NULL, ZCL_CODE_EMBEDDING_SEGMENT_HEADER_BYTES,
                      &segment, NULL, 0, &required));
        ASSERT_EQ(0, segment.schema_version);
        ASSERT_EQ(0, required);
        memset(root, 0xa5, sizeof(root));
        vh_profile(&profile);
        profile.quantizer = 0xff;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_ENUM,
                  zcl_code_embedding_profile_v1_root(&profile, root));
        for (size_t i = 0; i < sizeof(root); i++) ASSERT_EQ(0, root[i]);
        memset(root, 0xa5, sizeof(root));
        ASSERT(vh_segment(&segment, vectors, values));
        segment.payload_root[0] ^= 1;
        ASSERT_EQ(ZCL_CODE_VECTOR_HINT_ERR_PAYLOAD_ROOT,
                  zcl_code_embedding_segment_v1_root(&segment, root));
        for (size_t i = 0; i < sizeof(root); i++) ASSERT_EQ(0, root[i]);
    } TEST_END
    return failures;
}

int test_code_vector_hint(void)
{
    int failures = 0;
    failures += concept_card_codec();
    failures += concept_card_refusals();
    failures += concept_card_ontology_bindings();
    failures += profile_codec_and_refusals();
    failures += segment_codec();
    failures += segment_refusals();
    failures += segment_card_bindings();
    failures += overlap_and_output_refusals();
    failures += error_output_refusals();
    return failures;
}

#if defined(CODE_VECTOR_HINT_STANDALONE_TEST)
int main(void)
{
    return test_code_vector_hint() == 0 ? 0 : 1;
}
#endif
