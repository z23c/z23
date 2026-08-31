/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Born-red acceptance for bounded semantic-duplicate evidence. */

#include "test/test_core.h"

#include "codeindex/codeindex_semantic_candidate.h"

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int sc_failures;

#define SC_ASSERT(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "  code_semantic_candidate: FAIL %s:%d: %s\n", \
                __FILE__, __LINE__, #expr); \
        sc_failures++; \
    } \
} while (0)

static void sc_root(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(first + i);
}

static bool sc_zero(const void *bytes, size_t length)
{
    const uint8_t *p = bytes;
    uint8_t any = 0;
    for (size_t i = 0; i < length; i++) any |= p[i];
    return any == 0;
}

static struct zcl_code_semantic_candidate_v1 sc_fixture(void)
{
    struct zcl_code_semantic_candidate_v1 candidate;
    memset(&candidate, 0, sizeof(candidate));
    candidate.schema_version = ZCL_CODE_SEMANTIC_CANDIDATE_VERSION;
    candidate.verdict = ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE;
    candidate.syntax_shape = ZCL_CODE_SEMANTIC_EVIDENCE_MATCH;
    candidate.graph_depth1 = ZCL_CODE_SEMANTIC_EVIDENCE_MATCH;
    candidate.behavior_a = ZCL_CODE_SEMANTIC_EVIDENCE_MATCH;
    candidate.behavior_b = ZCL_CODE_SEMANTIC_EVIDENCE_MATCH;
    candidate.vector_hint = ZCL_CODE_SEMANTIC_VECTOR_MODEL_HINT;
    candidate.behavior_a_left_distinct = 7;
    candidate.behavior_a_right_distinct = 9;
    candidate.behavior_b_left_distinct = 11;
    candidate.behavior_b_right_distinct = 13;
    sc_root(candidate.source_root, 0x01);
    sc_root(candidate.universe_root, 0x11);
    sc_root(candidate.ontology_root, 0x21);
    sc_root(candidate.context_root, 0x31);
    sc_root(candidate.left_subject_root, 0x41);
    sc_root(candidate.right_subject_root, 0x81);
    sc_root(candidate.left_concept_card_root, 0x02);
    sc_root(candidate.right_concept_card_root, 0x12);
    sc_root(candidate.syntax_evidence_root, 0x22);
    sc_root(candidate.graph_evidence_root, 0x32);
    sc_root(candidate.behavior_a_evidence_root, 0x42);
    sc_root(candidate.behavior_b_evidence_root, 0x52);
    sc_root(candidate.extractor_profile_root, 0x62);
    sc_root(candidate.vector_hint_root, 0x72);
    sc_root(candidate.proof_needed_root, 0x82);
    return candidate;
}

static void sc_set_state(struct zcl_code_semantic_candidate_v1 *candidate,
                         size_t channel, uint8_t state)
{
    uint8_t *states[] = {
        &candidate->syntax_shape, &candidate->graph_depth1,
        &candidate->behavior_a, &candidate->behavior_b,
    };
    uint8_t *roots[] = {
        candidate->syntax_evidence_root, candidate->graph_evidence_root,
        candidate->behavior_a_evidence_root,
        candidate->behavior_b_evidence_root,
    };
    *states[channel] = state;
    if (state == ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED)
        memset(roots[channel], 0, 32);
    if (channel == 2 && state == ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED) {
        candidate->behavior_a_left_distinct = 0;
        candidate->behavior_a_right_distinct = 0;
    }
    if (channel == 3 && state == ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED) {
        candidate->behavior_b_left_distinct = 0;
        candidate->behavior_b_right_distinct = 0;
    }
    SC_ASSERT(zcl_code_semantic_candidate_v1_derive_verdict(
                  candidate, &candidate->verdict) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
}

static void sc_roundtrip(void)
{
    static const uint8_t frozen_root[32] = {
        0xef, 0x67, 0xad, 0x48, 0x4e, 0xcb, 0xdb, 0xcd,
        0x5a, 0xe0, 0x26, 0x98, 0x32, 0x06, 0x14, 0x8d,
        0xe2, 0x1d, 0x04, 0xf0, 0x60, 0x79, 0xaf, 0x70,
        0x27, 0x41, 0x2e, 0x45, 0x4c, 0x9f, 0x8c, 0x79,
    };
    struct zcl_code_semantic_candidate_v1 candidate = sc_fixture(), parsed;
    uint8_t wire[ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES], wire_again[sizeof(wire)];
    uint8_t root[32], root_again[32], root_without_hint[32];
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    SC_ASSERT(zcl_code_semantic_candidate_v1_encode(&candidate, wire) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    SC_ASSERT(memcmp(wire, "ZCSEMC1\0", 8) == 0);
    SC_ASSERT(zcl_code_semantic_candidate_v1_parse(
                  wire, sizeof(wire), &parsed) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    SC_ASSERT(zcl_code_semantic_candidate_v1_encode(&parsed, wire_again) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    SC_ASSERT(memcmp(wire, wire_again, sizeof(wire)) == 0);
    SC_ASSERT(zcl_code_semantic_candidate_v1_root(&candidate, root) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    SC_ASSERT(memcmp(root, frozen_root, sizeof(root)) == 0);
    SC_ASSERT(zcl_code_semantic_candidate_v1_root(&parsed, root_again) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    SC_ASSERT(memcmp(root, root_again, sizeof(root)) == 0);
    parsed.vector_hint = ZCL_CODE_SEMANTIC_VECTOR_ABSENT;
    memset(parsed.vector_hint_root, 0, sizeof(parsed.vector_hint_root));
    SC_ASSERT(zcl_code_semantic_candidate_v1_root(
                  &parsed, root_without_hint) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    SC_ASSERT(memcmp(root, root_without_hint, sizeof(root)) == 0);
}

static void sc_verdict_matrix(void)
{
    size_t verdict_counts[4] = {0};
    struct zcl_code_semantic_candidate_v1 candidate = sc_fixture();
    uint8_t verdict = 0;
    SC_ASSERT(zcl_code_semantic_candidate_v1_derive_verdict(
                  &candidate, &verdict) == ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    SC_ASSERT(verdict == ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE);

    for (size_t channel = 0; channel < 4; channel++) {
        candidate = sc_fixture();
        sc_set_state(&candidate, channel,
                     ZCL_CODE_SEMANTIC_EVIDENCE_MISMATCH);
        SC_ASSERT(candidate.verdict == ZCL_CODE_SEMANTIC_VERDICT_MISMATCH);
        SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
                  ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    }
    for (size_t channel = 0; channel < 4; channel++) {
        candidate = sc_fixture();
        sc_set_state(&candidate, channel,
                     ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED);
        SC_ASSERT(candidate.verdict == ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE);
        SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
                  ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    }
    for (size_t channel = 0; channel < 4; channel++) {
        candidate = sc_fixture();
        sc_set_state(&candidate, channel,
                     ZCL_CODE_SEMANTIC_EVIDENCE_INCOMPLETE);
        SC_ASSERT(candidate.verdict == ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE);
        SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
                  ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    }

    candidate = sc_fixture();
    candidate.vector_hint = ZCL_CODE_SEMANTIC_VECTOR_ABSENT;
    memset(candidate.vector_hint_root, 0, 32);
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    SC_ASSERT(candidate.verdict == ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE);
    candidate = sc_fixture();
    sc_set_state(&candidate, 2, ZCL_CODE_SEMANTIC_EVIDENCE_MISMATCH);
    SC_ASSERT(candidate.vector_hint == ZCL_CODE_SEMANTIC_VECTOR_MODEL_HINT);
    SC_ASSERT(candidate.verdict == ZCL_CODE_SEMANTIC_VERDICT_MISMATCH);
    candidate = sc_fixture();
    sc_set_state(&candidate, 1, ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED);
    SC_ASSERT(candidate.vector_hint == ZCL_CODE_SEMANTIC_VECTOR_MODEL_HINT);
    SC_ASSERT(candidate.verdict == ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE);

    candidate = sc_fixture();
    sc_set_state(&candidate, 0, ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED);
    sc_set_state(&candidate, 2, ZCL_CODE_SEMANTIC_EVIDENCE_MISMATCH);
    SC_ASSERT(candidate.verdict == ZCL_CODE_SEMANTIC_VERDICT_MISMATCH);

    candidate = sc_fixture();
    SC_ASSERT(zcl_code_semantic_candidate_v1_derive_verdict(
                  &candidate, &candidate.verdict) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    verdict_counts[candidate.verdict]++;
    candidate = sc_fixture();
    sc_set_state(&candidate, 0, ZCL_CODE_SEMANTIC_EVIDENCE_MISMATCH);
    verdict_counts[candidate.verdict]++;
    candidate = sc_fixture();
    sc_set_state(&candidate, 0, ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED);
    verdict_counts[candidate.verdict]++;
    SC_ASSERT(verdict_counts[ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE] == 1);
    SC_ASSERT(verdict_counts[ZCL_CODE_SEMANTIC_VERDICT_MISMATCH] == 1);
    SC_ASSERT(verdict_counts[ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE] == 1);
}

static void sc_validation_refusals(void)
{
    struct zcl_code_semantic_candidate_v1 candidate;
    uint8_t *mandatory[10];
    for (size_t mutation = 0; mutation < 10; mutation++) {
        candidate = sc_fixture();
        uint8_t *roots[] = {
            candidate.source_root, candidate.universe_root,
            candidate.ontology_root, candidate.context_root,
            candidate.left_subject_root, candidate.right_subject_root,
            candidate.left_concept_card_root,
            candidate.right_concept_card_root,
            candidate.extractor_profile_root, candidate.proof_needed_root,
        };
        memcpy(mandatory, roots, sizeof(roots));
        memset(mandatory[mutation], 0, 32);
        SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
                  ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_ZERO);
    }
    candidate = sc_fixture(); candidate.schema_version++;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_VERSION);
    candidate = sc_fixture(); candidate.syntax_shape = 4;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ENUM);
    candidate = sc_fixture(); candidate.vector_hint = 2;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ENUM);
    candidate = sc_fixture(); candidate.flags = 1;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_FLAGS);
    candidate = sc_fixture(); candidate.reserved = 1;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_FLAGS);
    candidate = sc_fixture(); candidate.reserved_word = 1;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_FLAGS);
    candidate = sc_fixture(); candidate.verdict = ZCL_CODE_SEMANTIC_VERDICT_MISMATCH;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_VERDICT);
    candidate = sc_fixture();
    memcpy(candidate.right_subject_root, candidate.left_subject_root, 32);
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ORDER);
    candidate = sc_fixture();
    memset(candidate.syntax_evidence_root, 0, 32);
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_PRESENCE);
    candidate = sc_fixture();
    candidate.syntax_shape = ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED;
    candidate.verdict = ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_PRESENCE);
    candidate = sc_fixture(); candidate.behavior_a_left_distinct = 2;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_SAMPLES);
    candidate = sc_fixture(); candidate.behavior_b_right_distinct = 2;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_SAMPLES);
    candidate = sc_fixture();
    memcpy(candidate.behavior_b_evidence_root,
           candidate.behavior_a_evidence_root, 32);
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_CHANNEL_ALIAS);
    candidate = sc_fixture();
    candidate.vector_hint = ZCL_CODE_SEMANTIC_VECTOR_ABSENT;
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_PRESENCE);
    candidate = sc_fixture(); memset(candidate.vector_hint_root, 0, 32);
    SC_ASSERT(zcl_code_semantic_candidate_v1_validate(&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ROOT_PRESENCE);
}

static void sc_codec_refusals(void)
{
    struct zcl_code_semantic_candidate_v1 candidate = sc_fixture(), parsed;
    uint8_t wire[ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES + 1], root[32];
    SC_ASSERT(zcl_code_semantic_candidate_v1_encode(&candidate, wire) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_OK);
    memset(&parsed, 0xa5, sizeof(parsed));
    SC_ASSERT(zcl_code_semantic_candidate_v1_parse(
                  wire, ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES - 1,
                  &parsed) == ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_SIZE);
    SC_ASSERT(sc_zero(&parsed, sizeof(parsed)));
    memset(&parsed, 0xa5, sizeof(parsed));
    SC_ASSERT(zcl_code_semantic_candidate_v1_parse(
                  wire, sizeof(wire), &parsed) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_SIZE);
    SC_ASSERT(sc_zero(&parsed, sizeof(parsed)));
    wire[0] ^= 1;
    memset(&parsed, 0xa5, sizeof(parsed));
    SC_ASSERT(zcl_code_semantic_candidate_v1_parse(
                  wire, ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES,
                  &parsed) == ZCL_CODE_SEMANTIC_CANDIDATE_ERR_WIRE_MAGIC);
    SC_ASSERT(sc_zero(&parsed, sizeof(parsed)));
    memset(wire, 0xa5, sizeof(wire));
    candidate.flags = 1;
    SC_ASSERT(zcl_code_semantic_candidate_v1_encode(&candidate, wire) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_FLAGS);
    SC_ASSERT(sc_zero(wire, ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES));
    memset(root, 0xa5, sizeof(root));
    SC_ASSERT(zcl_code_semantic_candidate_v1_root(&candidate, root) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_FLAGS);
    SC_ASSERT(sc_zero(root, sizeof(root)));
    candidate = sc_fixture();
    candidate.behavior_a_left_distinct = ZCL_CODE_SEMANTIC_MIN_DISTINCT - 1;
    uint8_t verdict = 0xa5;
    SC_ASSERT(zcl_code_semantic_candidate_v1_derive_verdict(
                  &candidate, &verdict) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_SAMPLES);
    SC_ASSERT(verdict == 0);
    candidate = sc_fixture(); candidate.syntax_shape = 99;
    verdict = 0xa5;
    SC_ASSERT(zcl_code_semantic_candidate_v1_derive_verdict(
                  &candidate, &verdict) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_ENUM);
    SC_ASSERT(verdict == 0);
    verdict = 0xa5;
    SC_ASSERT(zcl_code_semantic_candidate_v1_derive_verdict(
                  NULL, &verdict) == ZCL_CODE_SEMANTIC_CANDIDATE_ERR_NULL);
    SC_ASSERT(verdict == 0);
    candidate = sc_fixture();
    SC_ASSERT(zcl_code_semantic_candidate_v1_encode(
                  &candidate, (uint8_t *)(void *)&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_OVERLAP);
    SC_ASSERT(zcl_code_semantic_candidate_v1_parse(
                  (const uint8_t *)(const void *)&candidate,
                  ZCL_CODE_SEMANTIC_CANDIDATE_WIRE_BYTES, &candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_OVERLAP);
    SC_ASSERT(zcl_code_semantic_candidate_v1_root(
                  &candidate, (uint8_t *)(void *)&candidate) ==
              ZCL_CODE_SEMANTIC_CANDIDATE_ERR_OVERLAP);
    SC_ASSERT(strcmp(zcl_code_semantic_candidate_error_string(
                         ZCL_CODE_SEMANTIC_CANDIDATE_ERR_SAMPLES),
                     "samples") == 0);
    SC_ASSERT(strcmp(zcl_code_semantic_verdict_string(
                         ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE),
                     "CANDIDATE") == 0);
    SC_ASSERT(strcmp(zcl_code_semantic_verdict_string(0), "UNKNOWN") == 0);
}

int test_code_semantic_candidate(void)
{
    sc_failures = 0;
    sc_roundtrip();
    sc_verdict_matrix();
    sc_validation_refusals();
    sc_codec_refusals();
    return sc_failures;
}

#if defined(CODE_SEMANTIC_CANDIDATE_STANDALONE_TEST)
int main(void)
{
    return test_code_semantic_candidate() == 0 ? 0 : 1;
}
#endif
