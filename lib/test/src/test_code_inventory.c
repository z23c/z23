/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prove the capability census derives uses, tests, duplicates, gaps,
 * packages, and source identity from a bounded source fixture. */

#include "codeindex/codeindex_inventory.h"
#include "codeindex/codeindex_semantic_candidate.h"
#include "codeindex/codeindex_vector_hint.h"
#include "fingerprint/fingerprint.h"
#include "fingerprint/fp_runtime.h"
#include "test/code_inventory_semantic_fixture.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define CI_FIX "test-tmp/code-inventory-fixture"

_Static_assert(ZCL_CODE_SEMANTIC_MIN_DISTINCT == FP_REPORT_MIN_DISTINCT,
               "semantic candidate and fingerprint sample floors drifted");

static int ci_failures;

#define CI_ASSERT(expr) do { \
    if (!(expr)) { \
        fprintf(stderr, "  code_inventory: FAIL %s:%d: %s\n", \
                __FILE__, __LINE__, #expr); \
        ci_failures++; \
    } \
} while (0)

static bool ci_write(const char *path, const char *text)
{
    FILE *out = fopen(path, "wb");
    if (!out) return false;
    size_t len = strlen(text);
    bool ok = fwrite(text, 1, len, out) == len && fclose(out) == 0;
    return ok;
}

static bool ci_copy(const char *source_path, const char *destination_path)
{
    FILE *source = fopen(source_path, "rb");
    FILE *destination;
    unsigned char block[4096];
    size_t got;
    bool ok = source != NULL;
    if (!ok) return false;
    destination = fopen(destination_path, "wb");
    if (!destination) {
        fclose(source);
        return false;
    }
    while ((got = fread(block, 1, sizeof(block), source)) != 0)
        if (fwrite(block, 1, got, destination) != got) {
            ok = false;
            break;
        }
    if (ferror(source)) ok = false;
    if (fclose(source) != 0) ok = false;
    if (fclose(destination) != 0) ok = false;
    return ok;
}

static bool ci_fixture(void)
{
    if (system("rm -rf " CI_FIX " && mkdir -p "
               CI_FIX "/lib/demo/include/demo "
               CI_FIX "/lib/demo/include/test "
               CI_FIX "/lib/demo/src "
               CI_FIX "/lib/test/src "
               CI_FIX "/build/obj/epochs/"
                      "1111111111111111111111111111111111111111111111111111111111111111 "
               CI_FIX "/packages/zmini/include/zmini "
               CI_FIX "/packages/zmini/src "
               CI_FIX "/tools/dev "
               CI_FIX "/tools/lint") != 0) return false;
    bool ok = ci_write(CI_FIX "/lib/demo/include/demo/demo.h",
        "/* purpose: Validate demo values for the fixture. */\n"
        "#ifndef DEMO_H\n#define DEMO_H\n#include <stdbool.h>\n"
        "/** Must reject zero and return true only for valid even values. */\n"
        "bool demo_validate(int value);\n"
        "/** Must reject invalid values; this declaration is not proof. */\n"
        "bool demo_stub(int value);\n"
        "/** Must validate the selected platform implementation. */\n"
        "bool demo_platform(int value);\n"
        "static inline int local_pick(int value) { return value + 1; }\n"
        "int demo_use_local(int value);\n#endif\n") &&
        ci_write(CI_FIX "/lib/demo/include/demo/other.h",
        "/* purpose: Exercise a same-named, path-distinct inline. */\n"
        "#ifndef OTHER_H\n#define OTHER_H\n#include <stdbool.h>\n"
        "static inline int local_pick(int value) { return value - 1; }\n"
        "int other_use_local(int value);\n#endif\n") &&
        ci_write(CI_FIX "/lib/demo/src/demo.c",
        "#include \"demo/demo.h\"\n"
        "bool demo_validate(int value)\n{\n"
        "    if (value <= 0) return false;\n"
        "    if (value > 1000) return false;\n"
        "    return (value % 2) == 0;\n}\n"
        "bool demo_stub(int value)\n{\n"
        "    (void)value;\n    return true;\n}\n"
        "#if defined(_WIN32)\n"
        "bool demo_platform(int value) { (void)value; return true; }\n"
        "#else\n"
        "bool demo_platform(int value) { return value > 0; }\n"
        "#endif\n"
        "int demo_use_local(int value) { return local_pick(value); }\n"
        "static int alpha_one(int value)\n{\n"
        "    int result = first_call(value, 7);\n"
        "    if (result < 0) return result;\n"
        "    result = second_call(result, value);\n"
        "    if (result == 0) return first_call(value, 7);\n"
        "    if (result > value) result = second_call(result, 7);\n"
        "    return result + 7;\n}\n") &&
        ci_write(CI_FIX "/lib/demo/src/copy.c",
        "#include \"demo/other.h\"\n"
        "bool demo_validate_copy(int value)\n{\n"
        "    if (value <= 0) return false;\n"
        "    if (value > 1000) return false;\n"
        "    return (value % 2) == 0;\n}\n"
        "int other_use_local(int value) { return local_pick(value); }\n"
        "static int alpha_two(int item)\n{\n"
        "    int answer = other_call(item, 9);\n"
        "    if (answer < 0) return answer;\n"
        "    answer = final_call(answer, item);\n"
        "    if (answer == 0) return other_call(item, 9);\n"
        "    if (answer > item) answer = final_call(answer, 9);\n"
        "    return answer + 9;\n}\n") &&
        ci_write(CI_FIX "/lib/test/src/test_fixture.c",
        "#include \"demo/demo.h\"\n"
        "int test_code_inventory_fixture(void)\n{\n"
        "    return demo_validate(2) && demo_use_local(2) == 3 ? 0 : 1;\n}\n") &&
        ci_write(CI_FIX "/packages/zmini/include/zmini/zmini.h",
        "/* purpose: Tiny package fixture. */\n"
        "#ifndef ZMINI_H\n#define ZMINI_H\n"
        "int zmini_add(int a, int b);\n#endif\n") &&
        ci_write(CI_FIX "/packages/zmini/src/zmini.c",
        "#include \"zmini/zmini.h\"\n"
        "int zmini_add(int a, int b) { return a + b; }\n") &&
        ci_write(CI_FIX "/tools/dev/test_group_catalog.def",
        "/* Include with ZCL_TEST_GROUP(name) and ZCL_SPEC_GROUP(name). */\n"
        "ZCL_TEST_GROUP(code_inventory_fixture)\n"
        "ZCL_TEST_GROUP(generated_fixture)\n") &&
        ci_write(CI_FIX "/build/obj/.current-epoch",
        "1111111111111111111111111111111111111111111111111111111111111111\n") &&
        ci_write(CI_FIX "/build/obj/epochs/"
                        "1111111111111111111111111111111111111111111111111111111111111111/"
                        "code_inventory_semantic_fixture.d",
        "build/obj/code_inventory_semantic_fixture.o: "
        "lib/demo/src/code_inventory_semantic_fixture.c "
        "lib/demo/include/test/code_inventory_semantic_fixture.h\n") &&
        ci_write(CI_FIX "/tools/lint/arm_symbol_single_baseline.txt",
        "# z23-generated-artifact: zcl.generated_artifact.v1\n"
        "# artifact-id: zcl.arm_symbol_single_baseline.v1\n"
        "# asserts: multi_arm_definition(path,symbol)\n"
        "# generated-by: tools/lint/check_arm_symbol_single.sh\n"
        "# regenerate: ZCL_LINT_MODE=UPDATE tools/lint/check_arm_symbol_single.sh\n"
        "lib/demo/src/demo.c\tdemo_platform\n");
    if (!ok) return false;
    return ci_copy("lib/test/include/test/code_inventory_semantic_fixture.h",
                   CI_FIX "/lib/demo/include/test/"
                          "code_inventory_semantic_fixture.h") &&
           ci_copy("lib/test/src/code_inventory_semantic_fixture.c",
                   CI_FIX "/lib/demo/src/"
                          "code_inventory_semantic_fixture.c") &&
           ci_copy("lib/test/src/code_inventory_semantic_fixture.c",
                   CI_FIX "/lib/test/src/"
                          "code_inventory_semantic_fixture.c");
}

static const struct ci_inventory_capability *ci_cap(
    const struct ci_inventory_report *report, const char *header)
{
    for (int i = 0; i < report->capability_count; i++)
        if (strcmp(report->capabilities[i].header, header) == 0)
            return &report->capabilities[i];
    return NULL;
}

static const struct ci_inventory_symbol *ci_symbol(
    const struct ci_inventory_report *report,
    const struct ci_inventory_capability *cap, const char *name)
{
    if (!cap) return NULL;
    for (int i = 0; i < cap->symbol_count; i++) {
        const struct ci_inventory_symbol *symbol =
            &report->symbols[cap->symbol_offset + i];
        if (strcmp(symbol->name, name) == 0) return symbol;
    }
    return NULL;
}

enum ci_semantic_kat_evidence {
    CI_SEMANTIC_KAT_MISMATCH = 0,
    CI_SEMANTIC_KAT_MATCH = 1,
    CI_SEMANTIC_KAT_UNKNOWN = 2,
    CI_SEMANTIC_KAT_MODEL_HINT = 3,
};

struct ci_semantic_kat_runtime {
    uint64_t h1;
    uint64_t h2;
    uint32_t distinct;
};

struct ci_semantic_kat_graph {
    bool known;
    char fingerprint[1024];
};

struct ci_semantic_kat_row {
    const char *left;
    const char *right;
    enum ci_semantic_kat_evidence exact;
    enum ci_semantic_kat_evidence alpha;
    enum ci_semantic_kat_evidence shape;
    enum ci_semantic_kat_evidence graph;
    enum ci_semantic_kat_evidence runtime_a;
    enum ci_semantic_kat_evidence runtime_b;
    enum ci_semantic_kat_evidence vector;
    uint8_t candidate;
    uint32_t distinct_a_left;
    uint32_t distinct_a_right;
    uint32_t distinct_b_left;
    uint32_t distinct_b_right;
    const char *proof_needed;
    unsigned action_count;
    unsigned merge_authorizations;
    unsigned delete_authorizations;
};

static bool ci_pair_names(const char *a, const char *b,
                          const char *left, const char *right)
{
    return (strcmp(a, left) == 0 && strcmp(b, right) == 0) ||
           (strcmp(a, right) == 0 && strcmp(b, left) == 0);
}

static enum ci_semantic_kat_evidence ci_duplicate_evidence(
    const struct ci_inventory_report *report, const char *left,
    const char *right, enum ci_inventory_duplicate_kind kind)
{
    for (int i = 0; i < report->duplicate_count; i++) {
        const struct ci_inventory_duplicate *duplicate =
            &report->duplicates[i];
        if (duplicate->kind == kind &&
            ci_pair_names(duplicate->symbol_a, duplicate->symbol_b,
                          left, right))
            return CI_SEMANTIC_KAT_MATCH;
    }
    return CI_SEMANTIC_KAT_MISMATCH;
}

static const struct fp_candidate *ci_fp_candidate(
    const struct fp_candidate *candidates, long count, const char *name)
{
    for (long i = 0; i < count; i++)
        if (strcmp(candidates[i].name, name) == 0) return &candidates[i];
    return NULL;
}

static enum ci_semantic_kat_evidence ci_shape_evidence(
    const struct fp_candidate *left, const struct fp_candidate *right)
{
    if (!left || !right) return CI_SEMANTIC_KAT_UNKNOWN;
    return left->shape == right->shape &&
                   strcmp(left->shape_text, right->shape_text) == 0
               ? CI_SEMANTIC_KAT_MATCH
               : CI_SEMANTIC_KAT_MISMATCH;
}

static int ci_text_compare(const void *left, const void *right)
{
    return strcmp((const char *)left, (const char *)right);
}

static bool ci_graph_fingerprint(struct codeindex *index, const char *name,
                                 struct ci_semantic_kat_graph *out)
{
    struct ci_symbol symbol;
    struct ci_ref refs[16];
    char identities[16][512];
    bool found = false;
    int count;
    int identities_count = 0;
    size_t used = 0;
    memset(out, 0, sizeof(*out));
    if (!codeindex_symbol(index, name, &symbol, &found) || !found)
        return false;
    count = codeindex_callees_for_symbol(index, &symbol, refs, 16);
    if (count < 0) return false;
    if (count == 16) return true;
    for (int i = 0; i < count; i++) {
        struct ci_symbol callee;
        bool callee_found = false;
        if (!codeindex_symbol(index, refs[i].callee, &callee,
                              &callee_found))
            return false;
        if (!callee_found || codeindex_symbol_record_id(
                &callee, identities[identities_count],
                sizeof(identities[identities_count])) < 0)
            return true;
        identities_count++;
    }
    qsort(identities, (size_t)identities_count, sizeof(identities[0]),
          ci_text_compare);
    for (int i = 0; i < identities_count; i++) {
        int written;
        if (i != 0 && strcmp(identities[i - 1], identities[i]) == 0)
            continue;
        written = snprintf(out->fingerprint + used,
                           sizeof(out->fingerprint) - used, "%s%s",
                           used == 0 ? "" : ";", identities[i]);
        if (written < 0 || (size_t)written >=
                            sizeof(out->fingerprint) - used)
            return true;
        used += (size_t)written;
    }
    out->known = true;
    return true;
}

static enum ci_semantic_kat_evidence ci_graph_evidence(
    const struct ci_semantic_kat_graph *left,
    const struct ci_semantic_kat_graph *right)
{
    if (!left->known || !right->known) return CI_SEMANTIC_KAT_UNKNOWN;
    return strcmp(left->fingerprint, right->fingerprint) == 0
               ? CI_SEMANTIC_KAT_MATCH
               : CI_SEMANTIC_KAT_MISMATCH;
}

typedef uint64_t (*ci_semantic_kat_fn)(uint64_t);

static void ci_runtime_fingerprint(ci_semantic_kat_fn function,
                                   uint64_t shape, uint32_t iterations,
                                   uint64_t salt,
                                   struct ci_semantic_kat_runtime *out)
{
    struct fp_acc accumulator;
    uint64_t seen[128];
    uint32_t seen_count = 0;
    fp_acc_init(&accumulator, shape);
    for (uint32_t iteration = 0; iteration < iterations; iteration++) {
        struct fp_rng random;
        uint64_t input;
        uint32_t seen_at;
        fp_rng_seed(&random, shape, iteration, salt);
        input = fp_rng_scalar(&random, (unsigned)sizeof(input), iteration, 0u);
        accumulator.cur = UINT64_C(0x9E3779B97F4A7C15);
        fp_acc_u64(&accumulator, 0u, function(input));
        for (seen_at = 0; seen_at < seen_count; seen_at++)
            if (seen[seen_at] == accumulator.cur) break;
        if (seen_at == seen_count && seen_count < 128u)
            seen[seen_count++] = accumulator.cur;
    }
    out->h1 = accumulator.h1;
    out->h2 = accumulator.h2;
    out->distinct = seen_count;
}

static enum ci_semantic_kat_evidence ci_runtime_evidence(
    const struct ci_semantic_kat_runtime *left,
    const struct ci_semantic_kat_runtime *right)
{
    return left->h1 == right->h1 && left->h2 == right->h2
               ? CI_SEMANTIC_KAT_MATCH
               : CI_SEMANTIC_KAT_MISMATCH;
}

static void ci_semantic_root(uint8_t out[32], uint8_t first)
{
    for (size_t i = 0; i < 32; i++) out[i] = (uint8_t)(first + i);
}

static bool ci_semantic_model_hint(void)
{
    struct zcl_code_embedding_profile_v1 profile;
    struct zcl_code_embedding_vector_v1 vectors[2];
    struct zcl_code_embedding_segment_v1 segment;
    static const int8_t values[2][4] = {
        { -7, 3, 11, 29 },
        { -7, 3, 11, 29 },
    };
    memset(&profile, 0, sizeof(profile));
    profile.schema_version = ZCL_CODE_EMBEDDING_PROFILE_VERSION;
    profile.evidence_kind = ZCL_CODE_HINT_EVIDENCE_MODEL_HINT;
    profile.metric = ZCL_CODE_EMBEDDING_METRIC_INTEGER_DOT;
    profile.quantizer = ZCL_CODE_EMBEDDING_QUANTIZER_SIGNED_INT8;
    profile.dimension = 4;
    ci_semantic_root(profile.projection_root, 0x01);
    ci_semantic_root(profile.tokenizer_root, 0x11);
    ci_semantic_root(profile.preprocessing_root, 0x21);
    ci_semantic_root(profile.model_root, 0x31);
    ci_semantic_root(profile.weights_root, 0x41);
    ci_semantic_root(profile.license_root, 0x51);
    ci_semantic_root(profile.rights_root, 0x61);
    ci_semantic_root(profile.accepted_runner_root, 0x71);
    ci_semantic_root(profile.accepted_action_root, 0x81);
    ci_semantic_root(profile.reproducibility_root, 0x91);

    memset(vectors, 0, sizeof(vectors));
    ci_semantic_root(vectors[0].entity_root, 0x02);
    ci_semantic_root(vectors[0].concept_card_root, 0x22);
    ci_semantic_root(vectors[0].span_root, 0x42);
    vectors[0].values = values[0];
    ci_semantic_root(vectors[1].entity_root, 0x82);
    ci_semantic_root(vectors[1].concept_card_root, 0xa2);
    ci_semantic_root(vectors[1].span_root, 0xc2);
    vectors[1].values = values[1];

    memset(&segment, 0, sizeof(segment));
    segment.schema_version = ZCL_CODE_EMBEDDING_SEGMENT_VERSION;
    segment.evidence_kind = ZCL_CODE_HINT_EVIDENCE_MODEL_HINT;
    segment.metric = ZCL_CODE_EMBEDDING_METRIC_INTEGER_DOT;
    segment.quantizer = ZCL_CODE_EMBEDDING_QUANTIZER_SIGNED_INT8;
    segment.dimension = 4;
    segment.vector_count = 2;
    segment.row_bytes = ZCL_CODE_EMBEDDING_ROW_ROOT_BYTES + 4u;
    segment.payload_bytes = segment.row_bytes * segment.vector_count;
    ci_semantic_root(segment.corpus_root, 0x03);
    ci_semantic_root(segment.source_root, 0x13);
    ci_semantic_root(segment.universe_root, 0x23);
    ci_semantic_root(segment.concept_card_set_root, 0x33);
    ci_semantic_root(segment.context_root, 0x43);
    ci_semantic_root(segment.coverage_root, 0x53);
    segment.vectors = vectors;
    if (zcl_code_embedding_profile_v1_root(&profile, segment.profile_root) !=
            ZCL_CODE_VECTOR_HINT_OK ||
        zcl_code_embedding_payload_v1_root(
            segment.dimension, vectors, segment.vector_count,
            segment.payload_root) != ZCL_CODE_VECTOR_HINT_OK ||
        zcl_code_embedding_segment_v1_validate(&segment) !=
            ZCL_CODE_VECTOR_HINT_OK ||
        zcl_code_embedding_segment_v1_validate_profile(&segment, &profile) !=
            ZCL_CODE_VECTOR_HINT_OK)
        return false;
    return profile.evidence_kind == ZCL_CODE_HINT_EVIDENCE_MODEL_HINT &&
           segment.evidence_kind == ZCL_CODE_HINT_EVIDENCE_MODEL_HINT &&
           memcmp(values[0], values[1], sizeof(values[0])) == 0;
}

static uint8_t ci_semantic_state(enum ci_semantic_kat_evidence evidence)
{
    switch (evidence) {
    case CI_SEMANTIC_KAT_MATCH:
        return ZCL_CODE_SEMANTIC_EVIDENCE_MATCH;
    case CI_SEMANTIC_KAT_MISMATCH:
        return ZCL_CODE_SEMANTIC_EVIDENCE_MISMATCH;
    case CI_SEMANTIC_KAT_UNKNOWN:
    case CI_SEMANTIC_KAT_MODEL_HINT:
        return ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED;
    }
    return ZCL_CODE_SEMANTIC_EVIDENCE_UNOBSERVED;
}

static uint8_t ci_candidate_verdict(
    const struct ci_semantic_kat_row *row)
{
    /* Classifier bridge only. Full roots, codec validation, canonical bytes,
     * and vector-normalized identity are covered by code_semantic_candidate. */
    struct zcl_code_semantic_candidate_v1 candidate = {
        .syntax_shape = ci_semantic_state(row->shape),
        .graph_depth1 = ci_semantic_state(row->graph),
        .behavior_a = ci_semantic_state(row->runtime_a),
        .behavior_b = ci_semantic_state(row->runtime_b),
        .vector_hint = row->vector == CI_SEMANTIC_KAT_MODEL_HINT
                           ? ZCL_CODE_SEMANTIC_VECTOR_MODEL_HINT
                           : ZCL_CODE_SEMANTIC_VECTOR_ABSENT,
        .behavior_a_left_distinct =
            row->runtime_a == CI_SEMANTIC_KAT_UNKNOWN
                ? 0 : row->distinct_a_left,
        .behavior_a_right_distinct =
            row->runtime_a == CI_SEMANTIC_KAT_UNKNOWN
                ? 0 : row->distinct_a_right,
        .behavior_b_left_distinct =
            row->runtime_b == CI_SEMANTIC_KAT_UNKNOWN
                ? 0 : row->distinct_b_left,
        .behavior_b_right_distinct =
            row->runtime_b == CI_SEMANTIC_KAT_UNKNOWN
                ? 0 : row->distinct_b_right,
    };
    uint8_t verdict = 0;
    if (zcl_code_semantic_candidate_v1_derive_verdict(
            &candidate, &verdict) != ZCL_CODE_SEMANTIC_CANDIDATE_OK)
        return 0;
    return verdict;
}

static void ci_semantic_known_answers(
    const struct ci_inventory_report *report)
{
    static const char *const files[] = {
        "lib/demo/include/test/code_inventory_semantic_fixture.h",
        "lib/demo/src/code_inventory_semantic_fixture.c",
    };
    struct fp_candidate candidates[16];
    size_t tally[FP_V_COUNT];
    struct fp_index *fingerprint_index = fp_index_build(
        CI_FIX, files, sizeof(files) / sizeof(files[0]));
    long candidate_count = -1;
    memset(candidates, 0, sizeof(candidates));
    memset(tally, 0, sizeof(tally));
    CI_ASSERT(fingerprint_index != NULL);
    if (fingerprint_index)
        candidate_count = fp_index_select(
            fingerprint_index, candidates,
            sizeof(candidates) / sizeof(candidates[0]), tally);
    CI_ASSERT(candidate_count >= 0);

    const struct fp_candidate *loop = candidate_count >= 0
        ? ci_fp_candidate(candidates, candidate_count, "ci_semantic_loop")
        : NULL;
    const struct fp_candidate *formula = candidate_count >= 0
        ? ci_fp_candidate(candidates, candidate_count, "ci_semantic_formula")
        : NULL;
    const struct fp_candidate *changed = candidate_count >= 0
        ? ci_fp_candidate(candidates, candidate_count, "ci_semantic_changed")
        : NULL;
    const struct fp_candidate *indirect = candidate_count >= 0
        ? ci_fp_candidate(candidates, candidate_count, "ci_semantic_indirect")
        : NULL;
    CI_ASSERT(loop != NULL);
    CI_ASSERT(formula != NULL);
    CI_ASSERT(changed != NULL);
    CI_ASSERT(indirect == NULL);
    CI_ASSERT(tally[FP_V_FUNCTION_POINTER] >= 1u);

    struct codeindex *code_index = codeindex_open_source_view(CI_FIX);
    struct ci_semantic_kat_graph loop_graph, formula_graph, changed_graph;
    struct ci_semantic_kat_graph indirect_graph;
    memset(&loop_graph, 0, sizeof(loop_graph));
    memset(&formula_graph, 0, sizeof(formula_graph));
    memset(&changed_graph, 0, sizeof(changed_graph));
    memset(&indirect_graph, 0, sizeof(indirect_graph));
    CI_ASSERT(code_index != NULL);
    if (code_index) {
        CI_ASSERT(ci_graph_fingerprint(
            code_index, "ci_semantic_loop", &loop_graph));
        CI_ASSERT(ci_graph_fingerprint(
            code_index, "ci_semantic_formula", &formula_graph));
        CI_ASSERT(ci_graph_fingerprint(
            code_index, "ci_semantic_changed", &changed_graph));
        CI_ASSERT(ci_graph_fingerprint(
            code_index, "ci_semantic_indirect", &indirect_graph));
    }

    struct ci_semantic_kat_runtime loop_a = {0}, formula_a = {0};
    struct ci_semantic_kat_runtime changed_a = {0};
    struct ci_semantic_kat_runtime loop_b = {0}, formula_b = {0};
    struct ci_semantic_kat_runtime changed_b = {0};
    if (loop) {
        ci_runtime_fingerprint(ci_semantic_loop, loop->shape, FP_ITERATIONS,
                               0, &loop_a);
        ci_runtime_fingerprint(ci_semantic_loop, loop->shape,
                               FP_CONFIRM_ITERATIONS, FP_CONFIRM_SALT,
                               &loop_b);
    }
    if (formula) {
        ci_runtime_fingerprint(ci_semantic_formula, formula->shape,
                               FP_ITERATIONS, 0, &formula_a);
        ci_runtime_fingerprint(ci_semantic_formula, formula->shape,
                               FP_CONFIRM_ITERATIONS, FP_CONFIRM_SALT,
                               &formula_b);
    }
    if (changed) {
        ci_runtime_fingerprint(ci_semantic_changed, changed->shape,
                               FP_ITERATIONS, 0, &changed_a);
        ci_runtime_fingerprint(ci_semantic_changed, changed->shape,
                               FP_CONFIRM_ITERATIONS, FP_CONFIRM_SALT,
                               &changed_b);
    }

    bool model_hint_valid = ci_semantic_model_hint();
    CI_ASSERT(model_hint_valid);
    struct ci_semantic_kat_row rows[3] = {
        {
            .left = "ci_semantic_loop",
            .right = "ci_semantic_formula",
            .proof_needed =
                "reviewed equivalence over the full shared input domain and "
                "reviewed architecture boundaries before any source action",
        },
        {
            .left = "ci_semantic_formula",
            .right = "ci_semantic_changed",
            .proof_needed =
                "the disjoint runtime fingerprints must agree before this "
                "pair can become a duplicate candidate",
        },
        {
            .left = "ci_semantic_loop",
            .right = "ci_semantic_indirect",
            .proof_needed =
                "resolve the indirect callee and obtain selected-shape plus "
                "A and B runtime fingerprints",
        },
    };
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        rows[i].exact = ci_duplicate_evidence(
            report, rows[i].left, rows[i].right,
            CI_INVENTORY_DUPLICATE_EXACT_BODY);
        rows[i].alpha = ci_duplicate_evidence(
            report, rows[i].left, rows[i].right,
            CI_INVENTORY_DUPLICATE_ALPHA_SHAPE);
        rows[i].vector = model_hint_valid ? CI_SEMANTIC_KAT_MODEL_HINT
                                          : CI_SEMANTIC_KAT_UNKNOWN;
    }

    rows[0].shape = ci_shape_evidence(loop, formula);
    rows[0].graph = ci_graph_evidence(&loop_graph, &formula_graph);
    rows[0].runtime_a = loop && formula
        ? ci_runtime_evidence(&loop_a, &formula_a)
        : CI_SEMANTIC_KAT_UNKNOWN;
    rows[0].runtime_b = loop && formula
        ? ci_runtime_evidence(&loop_b, &formula_b)
        : CI_SEMANTIC_KAT_UNKNOWN;
    rows[0].distinct_a_left = loop_a.distinct;
    rows[0].distinct_a_right = formula_a.distinct;
    rows[0].distinct_b_left = loop_b.distinct;
    rows[0].distinct_b_right = formula_b.distinct;

    rows[1].shape = ci_shape_evidence(formula, changed);
    rows[1].graph = ci_graph_evidence(&formula_graph, &changed_graph);
    rows[1].runtime_a = formula && changed
        ? ci_runtime_evidence(&formula_a, &changed_a)
        : CI_SEMANTIC_KAT_UNKNOWN;
    rows[1].runtime_b = formula && changed
        ? ci_runtime_evidence(&formula_b, &changed_b)
        : CI_SEMANTIC_KAT_UNKNOWN;
    rows[1].distinct_a_left = formula_a.distinct;
    rows[1].distinct_a_right = changed_a.distinct;
    rows[1].distinct_b_left = formula_b.distinct;
    rows[1].distinct_b_right = changed_b.distinct;

    rows[2].shape = ci_shape_evidence(loop, indirect);
    rows[2].graph = ci_graph_evidence(&loop_graph, &indirect_graph);
    rows[2].runtime_a = CI_SEMANTIC_KAT_UNKNOWN;
    rows[2].runtime_b = CI_SEMANTIC_KAT_UNKNOWN;
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
        rows[i].candidate = ci_candidate_verdict(&rows[i]);

    struct ci_semantic_kat_row graph_mismatch = {
        .shape = CI_SEMANTIC_KAT_MATCH,
        .graph = CI_SEMANTIC_KAT_MISMATCH,
        .runtime_a = CI_SEMANTIC_KAT_MATCH,
        .runtime_b = CI_SEMANTIC_KAT_MATCH,
        .distinct_a_left = ZCL_CODE_SEMANTIC_MIN_DISTINCT,
        .distinct_a_right = ZCL_CODE_SEMANTIC_MIN_DISTINCT,
        .distinct_b_left = ZCL_CODE_SEMANTIC_MIN_DISTINCT,
        .distinct_b_right = ZCL_CODE_SEMANTIC_MIN_DISTINCT,
    };
    CI_ASSERT(ci_candidate_verdict(&graph_mismatch) ==
              ZCL_CODE_SEMANTIC_VERDICT_MISMATCH);

    CI_ASSERT(rows[0].exact == CI_SEMANTIC_KAT_MISMATCH);
    CI_ASSERT(rows[0].alpha == CI_SEMANTIC_KAT_MISMATCH);
    CI_ASSERT(rows[0].shape == CI_SEMANTIC_KAT_MATCH);
    CI_ASSERT(rows[0].graph == CI_SEMANTIC_KAT_MATCH);
    CI_ASSERT(rows[0].runtime_a == CI_SEMANTIC_KAT_MATCH);
    CI_ASSERT(rows[0].runtime_b == CI_SEMANTIC_KAT_MATCH);
    CI_ASSERT(rows[0].distinct_a_left >= FP_REPORT_MIN_DISTINCT);
    CI_ASSERT(rows[0].distinct_a_right >= FP_REPORT_MIN_DISTINCT);
    CI_ASSERT(rows[0].distinct_b_left >= FP_REPORT_MIN_DISTINCT);
    CI_ASSERT(rows[0].distinct_b_right >= FP_REPORT_MIN_DISTINCT);
    CI_ASSERT(rows[0].vector == CI_SEMANTIC_KAT_MODEL_HINT);
    CI_ASSERT(rows[0].candidate == ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE);

    CI_ASSERT(rows[1].exact == CI_SEMANTIC_KAT_MISMATCH);
    CI_ASSERT(rows[1].alpha == CI_SEMANTIC_KAT_MISMATCH);
    CI_ASSERT(rows[1].shape == CI_SEMANTIC_KAT_MATCH);
    CI_ASSERT(rows[1].graph == CI_SEMANTIC_KAT_MATCH);
    CI_ASSERT(rows[1].runtime_a == CI_SEMANTIC_KAT_MISMATCH);
    CI_ASSERT(rows[1].runtime_b == CI_SEMANTIC_KAT_MISMATCH);
    CI_ASSERT(rows[1].vector == CI_SEMANTIC_KAT_MODEL_HINT);
    CI_ASSERT(rows[1].candidate == ZCL_CODE_SEMANTIC_VERDICT_MISMATCH);

    CI_ASSERT(rows[2].exact == CI_SEMANTIC_KAT_MISMATCH);
    CI_ASSERT(rows[2].alpha == CI_SEMANTIC_KAT_MISMATCH);
    CI_ASSERT(rows[2].shape == CI_SEMANTIC_KAT_UNKNOWN);
    CI_ASSERT(!indirect_graph.known);
    CI_ASSERT(rows[2].graph == CI_SEMANTIC_KAT_UNKNOWN);
    CI_ASSERT(rows[2].runtime_a == CI_SEMANTIC_KAT_UNKNOWN);
    CI_ASSERT(rows[2].runtime_b == CI_SEMANTIC_KAT_UNKNOWN);
    CI_ASSERT(rows[2].vector == CI_SEMANTIC_KAT_MODEL_HINT);
    CI_ASSERT(rows[2].candidate == ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE);

    struct ci_semantic_kat_row mutation = rows[0];
    mutation.graph = CI_SEMANTIC_KAT_UNKNOWN;
    CI_ASSERT(ci_candidate_verdict(&mutation) ==
              ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE);
    mutation = rows[0];
    mutation.runtime_b = CI_SEMANTIC_KAT_UNKNOWN;
    CI_ASSERT(ci_candidate_verdict(&mutation) ==
              ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE);
    mutation = rows[0];
    mutation.vector = CI_SEMANTIC_KAT_UNKNOWN;
    CI_ASSERT(ci_candidate_verdict(&mutation) ==
              ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE);
    mutation = rows[0];
    mutation.distinct_b_right = ZCL_CODE_SEMANTIC_MIN_DISTINCT - 1;
    CI_ASSERT(ci_candidate_verdict(&mutation) == 0);
    mutation = rows[1];
    mutation.vector = CI_SEMANTIC_KAT_MODEL_HINT;
    CI_ASSERT(ci_candidate_verdict(&mutation) ==
              ZCL_CODE_SEMANTIC_VERDICT_MISMATCH);

    size_t verdict_counts[4] = {0};
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
        if (rows[i].candidate < sizeof(verdict_counts) /
                                sizeof(verdict_counts[0]))
            verdict_counts[rows[i].candidate]++;
    CI_ASSERT(verdict_counts[ZCL_CODE_SEMANTIC_VERDICT_CANDIDATE] == 1);
    CI_ASSERT(verdict_counts[ZCL_CODE_SEMANTIC_VERDICT_MISMATCH] == 1);
    CI_ASSERT(verdict_counts[ZCL_CODE_SEMANTIC_VERDICT_INCOMPLETE] == 1);

    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        CI_ASSERT(rows[i].proof_needed != NULL &&
                  rows[i].proof_needed[0] != '\0');
        CI_ASSERT(rows[i].action_count == 0);
        CI_ASSERT(rows[i].merge_authorizations == 0);
        CI_ASSERT(rows[i].delete_authorizations == 0);
    }
    codeindex_close(code_index);
    fp_index_free(fingerprint_index);
}

int test_code_inventory(void)
{
    ci_failures = 0;
    CI_ASSERT(ci_fixture());
    struct ci_inventory_report *first = codeindex_inventory_analyze(CI_FIX);
    CI_ASSERT(first != NULL);
    if (!first) return 1;
    CI_ASSERT(first->registered_test_groups == 2);
    CI_ASSERT(first->registered_test_roots_found == 1);
    CI_ASSERT(first->registered_test_roots_missing == 1);
    CI_ASSERT(first->ambiguous_registered_test_roots == 0);
    CI_ASSERT(first->test_root_gap_count == 1);
    CI_ASSERT(first->test_root_gap_count == 1 &&
              strcmp(first->test_root_gaps[0].group,
                     "generated_fixture") == 0);

    const struct ci_inventory_capability *demo = ci_cap(
        first, "lib/demo/include/demo/demo.h");
    const struct ci_inventory_capability *package = ci_cap(
        first, "packages/zmini/include/zmini/zmini.h");
    const struct ci_inventory_capability *other = ci_cap(
        first, "lib/demo/include/demo/other.h");
    CI_ASSERT(demo != NULL);
    CI_ASSERT(package != NULL);
    CI_ASSERT(other != NULL);
    CI_ASSERT(demo && strcmp(demo->include_token, "demo/demo.h") == 0);
    CI_ASSERT(demo && demo->production_use_files >= 1);
    CI_ASSERT(demo && demo->test_use_files >= 1);
    CI_ASSERT(demo && demo->purpose_unproven);

    const struct ci_inventory_symbol *validate = ci_symbol(
        first, demo, "demo_validate");
    const struct ci_inventory_symbol *stub = ci_symbol(first, demo, "demo_stub");
    const struct ci_inventory_symbol *demo_local = ci_symbol(
        first, demo, "local_pick");
    const struct ci_inventory_symbol *other_local = ci_symbol(
        first, other, "local_pick");
    const struct ci_inventory_symbol *platform = ci_symbol(
        first, demo, "demo_platform");
    CI_ASSERT(validate != NULL);
    CI_ASSERT(validate && validate->test_evidence ==
              CI_INVENTORY_TEST_REGISTERED_REACHABLE);
    CI_ASSERT(validate && strcmp(validate->registered_test_group,
                                 "code_inventory_fixture") == 0);
    CI_ASSERT(stub != NULL);
    if (stub && !stub->constant_return_body)
        fprintf(stderr, "  code_inventory: stub definition=%s:%d\n",
                stub->definition_path, stub->definition_line);
    CI_ASSERT(stub && stub->constant_return_body);
    CI_ASSERT(stub && strcmp(stub->constant_return_value, "true") == 0);
    CI_ASSERT(platform && platform->multi_arm_definition);
    CI_ASSERT(platform && platform->definition_arm_count == 2);
    CI_ASSERT(platform && !platform->constant_return_body);
    CI_ASSERT(platform && strcmp(platform->definition_evidence,
              "multiple_preprocessor_arms_UNPROVEN") == 0);
    CI_ASSERT(demo_local != NULL);
    CI_ASSERT(other_local != NULL);
    CI_ASSERT(demo_local && strcmp(demo_local->definition_path,
              "lib/demo/include/demo/demo.h") == 0);
    CI_ASSERT(other_local && strcmp(other_local->definition_path,
              "lib/demo/include/demo/other.h") == 0);
    CI_ASSERT(demo_local && strcmp(demo_local->definition_evidence,
              "declaration_is_definition") == 0);
    CI_ASSERT(demo_local && demo_local->production_use_files == 1);
    CI_ASSERT(other_local && other_local->production_use_files == 1);
    CI_ASSERT(demo_local && demo_local->test_evidence ==
              CI_INVENTORY_TEST_REGISTERED_REACHABLE);
    CI_ASSERT(other_local && other_local->test_evidence !=
              CI_INVENTORY_TEST_REGISTERED_REACHABLE);
    CI_ASSERT(first->unresolved_include_sites == 3);

    bool exact = false, shape = false, stub_gap = false, platform_gap = false;
    bool platform_constant_arm = false, platform_real_arm = false;
    for (int i = 0; i < first->duplicate_count; i++) {
        const struct ci_inventory_duplicate *d = &first->duplicates[i];
        if (d->kind == CI_INVENTORY_DUPLICATE_EXACT_BODY &&
            ((strcmp(d->symbol_a, "demo_validate") == 0 &&
              strcmp(d->symbol_b, "demo_validate_copy") == 0) ||
             (strcmp(d->symbol_b, "demo_validate") == 0 &&
              strcmp(d->symbol_a, "demo_validate_copy") == 0))) exact = true;
        if (d->kind == CI_INVENTORY_DUPLICATE_ALPHA_SHAPE &&
            ((strcmp(d->symbol_a, "alpha_one") == 0 &&
              strcmp(d->symbol_b, "alpha_two") == 0) ||
             (strcmp(d->symbol_b, "alpha_one") == 0 &&
              strcmp(d->symbol_a, "alpha_two") == 0))) {
            shape = true;
            CI_ASSERT(d->proof_needed[0] != '\0');
        }
    }
    for (int i = 0; i < first->invariant_count; i++)
        if (strcmp(first->invariants[i].symbol, "demo_stub") == 0 &&
            strcmp(first->invariants[i].verdict, "UNPROVEN") == 0)
            stub_gap = true;
        else if (strcmp(first->invariants[i].symbol, "demo_platform") == 0 &&
                 first->invariants[i].constant_return_body &&
                 strcmp(first->invariants[i].constant_return_value,
                        "true") == 0 &&
                 first->invariants[i].multi_arm_definition &&
                 strcmp(first->invariants[i].definition_scope,
                        "preprocessor_arm_UNPROVEN") == 0)
            platform_gap = true;
    for (int i = 0; i < first->definition_arm_count; i++) {
        const struct ci_inventory_definition_arm *arm =
            &first->definition_arms[i];
        if (strcmp(arm->symbol, "demo_platform") != 0) continue;
        if (arm->constant_return_body &&
            strcmp(arm->constant_return_value, "true") == 0 &&
            strcmp(arm->preprocessor_guard, "defined(_WIN32)") == 0)
            platform_constant_arm = true;
        if (!arm->constant_return_body &&
            strcmp(arm->preprocessor_guard,
                   "else:defined(_WIN32)") == 0)
            platform_real_arm = true;
    }
    CI_ASSERT(exact);
    CI_ASSERT(shape);
    CI_ASSERT(stub_gap);
    CI_ASSERT(platform_gap);
    CI_ASSERT(platform_constant_arm);
    CI_ASSERT(platform_real_arm);
    ci_semantic_known_answers(first);

    struct ci_inventory_report *same = codeindex_inventory_analyze(CI_FIX);
    CI_ASSERT(same != NULL);
    CI_ASSERT(same && memcmp(first->source_root_sha3,
                             same->source_root_sha3, 32) == 0);
    codeindex_inventory_free(same);
    CI_ASSERT(ci_write(CI_FIX "/packages/zmini/src/zmini.c",
        "#include \"zmini/zmini.h\"\n"
        "int zmini_add(int a, int b) { return a + b + 0; }\n"));
    struct ci_inventory_report *changed = codeindex_inventory_analyze(CI_FIX);
    CI_ASSERT(changed != NULL);
    CI_ASSERT(changed && memcmp(first->source_root_sha3,
                                changed->source_root_sha3, 32) != 0);
    codeindex_inventory_free(changed);
    codeindex_inventory_free(first);
    if (!ci_failures) (void)system("rm -rf " CI_FIX);
    printf("  code_inventory: %s\n", ci_failures ? "FAIL" : "PASS");
    return ci_failures ? 1 : 0;
}
