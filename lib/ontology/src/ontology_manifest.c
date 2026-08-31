/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical ontology set and universe-bound manifest codecs. */
#include "ontology/ontology.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <string.h>

static bool manifest_nonzero(const uint8_t root[32])
{
    return root && zcl_bytes_any_set(root, 32);
}

static bool manifest_ranges_overlap(const void *left, size_t left_size,
                                    const void *right, size_t right_size)
{
    if (!left || !right || left_size == 0 || right_size == 0) return false;
    uintptr_t left_begin = (uintptr_t)left;
    uintptr_t right_begin = (uintptr_t)right;
    if (left_size > UINTPTR_MAX - left_begin ||
        right_size > UINTPTR_MAX - right_begin)
        return true;
    return left_begin < right_begin + right_size &&
           right_begin < left_begin + left_size;
}

static void manifest_hash_start(struct sha3_256_ctx *sha, const char *domain)
{
    sha3_256_init(sha);
    sha3_256_write(sha, (const uint8_t *)domain, strlen(domain) + 1u);
}

static void manifest_hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t wire[8];
    zcl_write_u64_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

static bool manifest_kind_valid(enum zcl_ontology_object_kind kind)
{
    return kind >= ZCL_ONTOLOGY_OBJECT_TERM &&
           kind <= ZCL_ONTOLOGY_OBJECT_GAP;
}

bool zcl_ontology_object_set_v1_root(
    enum zcl_ontology_object_kind kind, const uint8_t (*roots)[32],
    size_t count, uint8_t out[32])
{
    if (!out || !manifest_kind_valid(kind) || (count != 0 && !roots) ||
        count > SIZE_MAX / 32u ||
        manifest_ranges_overlap(roots, count * 32u, out, 32))
        return false;
    memset(out, 0, 32);
    for (size_t i = 0; i < count; i++) {
        if (!manifest_nonzero(roots[i]) ||
            (i != 0 && memcmp(roots[i - 1u], roots[i], 32) >= 0))
            return false;
    }
    struct sha3_256_ctx sha;
    manifest_hash_start(&sha, "zcl.ontology_object_set.v1");
    uint8_t kind_wire = (uint8_t)kind;
    sha3_256_write(&sha, &kind_wire, 1);
    manifest_hash_u64(&sha, (uint64_t)count);
    for (size_t i = 0; i < count; i++)
        sha3_256_write(&sha, roots[i], 32);
    sha3_256_finalize(&sha, out);
    return true;
}

typedef bool (*manifest_member_root_fn)(const void *member, uint8_t out[32]);

static bool manifest_term_root(const void *member, uint8_t out[32])
{
    return zcl_ontology_term_v1_root(member, out);
}

static bool manifest_predicate_root(const void *member, uint8_t out[32])
{
    return zcl_ontology_predicate_v1_root(member, out);
}

static bool manifest_formula_root(const void *member, uint8_t out[32])
{
    return zcl_ontology_formula_v1_root(member, out);
}

static bool manifest_context_root(const void *member, uint8_t out[32])
{
    return zcl_ontology_context_v1_root(member, out);
}

static bool manifest_assertion_root(const void *member, uint8_t out[32])
{
    return zcl_ontology_assertion_v1_root(member, out);
}

static bool manifest_coverage_root(const void *member, uint8_t out[32])
{
    return zcl_ontology_coverage_v1_root(member, out);
}

static bool manifest_domain_root(const void *member, uint8_t out[32])
{
    return zcl_ontology_domain_v1_root(member, out);
}

static bool manifest_typed_set_root(
    enum zcl_ontology_object_kind kind, const void *members, size_t count,
    size_t member_size, manifest_member_root_fn member_root, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!out || !manifest_kind_valid(kind) || member_size == 0 ||
        !member_root || (count != 0 && !members) ||
        count > SIZE_MAX / member_size)
        return false;
    struct sha3_256_ctx sha;
    manifest_hash_start(&sha, "zcl.ontology_object_set.v1");
    uint8_t kind_wire = (uint8_t)kind;
    sha3_256_write(&sha, &kind_wire, 1);
    manifest_hash_u64(&sha, (uint64_t)count);
    uint8_t previous[32] = {0};
    const uint8_t *cursor = members;
    for (size_t i = 0; i < count; i++, cursor += member_size) {
        uint8_t current[32];
        if (!member_root(cursor, current) ||
            (i != 0 && memcmp(previous, current, 32) >= 0))
            return false;
        sha3_256_write(&sha, current, 32);
        memcpy(previous, current, 32);
    }
    sha3_256_finalize(&sha, out);
    return true;
}

static bool manifest_shape_valid(
    const struct zcl_ontology_manifest_v1 *manifest)
{
    if (!manifest ||
        manifest->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        manifest->flags != 0 || manifest->reserved != 0)
        return false;
    const uint8_t *roots[] = {
        manifest->source_root, manifest->universe_root,
        manifest->vocabulary_root, manifest->term_set_root,
        manifest->predicate_set_root, manifest->formula_set_root,
        manifest->rule_set_root, manifest->context_set_root,
        manifest->assertion_set_root, manifest->coverage_set_root,
        manifest->domain_set_root, manifest->extractor_root,
        manifest->policy_root, manifest->gap_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!manifest_nonzero(roots[i])) return false;
    return true;
}

static void manifest_put_u16(uint8_t *wire, size_t *offset, uint16_t value)
{
    zcl_write_u16_le(wire + *offset, value);
    *offset += 2;
}

static void manifest_put_u32(uint8_t *wire, size_t *offset, uint32_t value)
{
    zcl_write_u32_le(wire + *offset, value);
    *offset += 4;
}

static void manifest_put_u64(uint8_t *wire, size_t *offset, uint64_t value)
{
    zcl_write_u64_le(wire + *offset, value);
    *offset += 8;
}

static void manifest_put_root(uint8_t *wire, size_t *offset,
                              const uint8_t root[32])
{
    memcpy(wire + *offset, root, 32);
    *offset += 32;
}

bool zcl_ontology_manifest_v1_encode(
    const struct zcl_ontology_manifest_v1 *manifest, uint8_t *out,
    size_t out_size)
{
    if (!manifest || !out ||
        out_size != ZCL_ONTOLOGY_MANIFEST_WIRE_BYTES ||
        manifest_ranges_overlap(manifest, sizeof(*manifest), out, out_size))
        return false;
    memset(out, 0, out_size);
    if (!manifest_shape_valid(manifest)) return false;
    size_t offset = 0;
    manifest_put_u16(out, &offset, manifest->schema_version);
    manifest_put_u16(out, &offset, manifest->flags);
    manifest_put_u32(out, &offset, manifest->reserved);
    const uint64_t counts[] = {
        manifest->term_count, manifest->predicate_count,
        manifest->formula_count, manifest->rule_count,
        manifest->context_count, manifest->assertion_count,
        manifest->coverage_count, manifest->domain_count,
        manifest->gap_count,
    };
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++)
        manifest_put_u64(out, &offset, counts[i]);
    const uint8_t *roots[] = {
        manifest->source_root, manifest->universe_root,
        manifest->vocabulary_root, manifest->term_set_root,
        manifest->predicate_set_root, manifest->formula_set_root,
        manifest->rule_set_root, manifest->context_set_root,
        manifest->assertion_set_root, manifest->coverage_set_root,
        manifest->domain_set_root, manifest->extractor_root,
        manifest->policy_root, manifest->gap_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        manifest_put_root(out, &offset, roots[i]);
    return offset == out_size;
}

static uint16_t manifest_get_u16(const uint8_t *wire, size_t *offset)
{
    uint16_t value = zcl_read_u16_le(wire + *offset);
    *offset += 2;
    return value;
}

static uint32_t manifest_get_u32(const uint8_t *wire, size_t *offset)
{
    uint32_t value = zcl_read_u32_le(wire + *offset);
    *offset += 4;
    return value;
}

static uint64_t manifest_get_u64(const uint8_t *wire, size_t *offset)
{
    uint64_t value = zcl_read_u64_le(wire + *offset);
    *offset += 8;
    return value;
}

static void manifest_get_root(const uint8_t *wire, size_t *offset,
                              uint8_t root[32])
{
    memcpy(root, wire + *offset, 32);
    *offset += 32;
}

bool zcl_ontology_manifest_v1_decode(
    const uint8_t *wire, size_t wire_size,
    struct zcl_ontology_manifest_v1 *out)
{
    if (!out) return false;
    if (wire && manifest_ranges_overlap(wire, wire_size, out, sizeof(*out)))
        return false;
    memset(out, 0, sizeof(*out));
    if (!wire || wire_size != ZCL_ONTOLOGY_MANIFEST_WIRE_BYTES) return false;
    size_t offset = 0;
    out->schema_version = manifest_get_u16(wire, &offset);
    out->flags = manifest_get_u16(wire, &offset);
    out->reserved = manifest_get_u32(wire, &offset);
    uint64_t *counts[] = {
        &out->term_count, &out->predicate_count, &out->formula_count,
        &out->rule_count, &out->context_count, &out->assertion_count,
        &out->coverage_count, &out->domain_count, &out->gap_count,
    };
    for (size_t i = 0; i < sizeof(counts) / sizeof(counts[0]); i++)
        *counts[i] = manifest_get_u64(wire, &offset);
    uint8_t *roots[] = {
        out->source_root, out->universe_root, out->vocabulary_root,
        out->term_set_root, out->predicate_set_root, out->formula_set_root,
        out->rule_set_root, out->context_set_root, out->assertion_set_root,
        out->coverage_set_root, out->domain_set_root, out->extractor_root,
        out->policy_root, out->gap_set_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        manifest_get_root(wire, &offset, roots[i]);
    if (offset != wire_size || !manifest_shape_valid(out)) {
        memset(out, 0, sizeof(*out));
        return false;
    }
    return true;
}

bool zcl_ontology_manifest_v1_root(
    const struct zcl_ontology_manifest_v1 *manifest, uint8_t out[32])
{
    uint8_t wire[ZCL_ONTOLOGY_MANIFEST_WIRE_BYTES];
    if (!manifest || !out ||
        manifest_ranges_overlap(manifest, sizeof(*manifest), out, 32))
        return false;
    memset(out, 0, 32);
    if (!zcl_ontology_manifest_v1_encode(
                    manifest, wire, sizeof(wire)))
        return false;
    struct sha3_256_ctx sha;
    manifest_hash_start(&sha, "zcl.ontology_manifest.v1");
    sha3_256_write(&sha, wire, sizeof(wire));
    sha3_256_finalize(&sha, out);
    return true;
}

static bool manifest_typed_set_matches(
    enum zcl_ontology_object_kind kind, const void *members, size_t count,
    size_t member_size, manifest_member_root_fn member_root,
    uint64_t declared_count, const uint8_t expected_root[32])
{
    uint8_t actual_root[32];
    return declared_count == (uint64_t)count &&
           manifest_typed_set_root(kind, members, count, member_size,
                                   member_root, actual_root) &&
           memcmp(actual_root, expected_root, 32) == 0;
}

static bool manifest_term_present(
    const struct zcl_ontology_manifest_inputs_v1 *inputs,
    const uint8_t wanted[32], uint8_t required_kind)
{
    for (size_t i = 0; i < inputs->term_count; i++) {
        uint8_t actual[32];
        if (inputs->terms[i].kind == required_kind &&
            zcl_ontology_term_v1_root(&inputs->terms[i], actual) &&
            memcmp(actual, wanted, 32) == 0)
            return true;
    }
    return false;
}

static const struct zcl_ontology_predicate_v1 *manifest_predicate_find(
    const struct zcl_ontology_manifest_inputs_v1 *inputs,
    const uint8_t wanted[32])
{
    for (size_t i = 0; i < inputs->predicate_count; i++) {
        uint8_t actual[32];
        if (zcl_ontology_predicate_v1_root(&inputs->predicates[i], actual) &&
            memcmp(actual, wanted, 32) == 0)
            return &inputs->predicates[i];
    }
    return NULL;
}

static const struct zcl_ontology_term_v1 *manifest_term_identity_find(
    const struct zcl_ontology_manifest_inputs_v1 *inputs,
    const uint8_t identity_root[32])
{
    for (size_t i = 0; i < inputs->term_count; i++)
        if (memcmp(inputs->terms[i].identity_root, identity_root, 32) == 0)
            return &inputs->terms[i];
    return NULL;
}

static bool manifest_type_present(
    const struct zcl_ontology_manifest_inputs_v1 *inputs,
    const uint8_t type_root[32])
{
    const struct zcl_ontology_term_v1 *term =
        manifest_term_identity_find(inputs, type_root);
    return term && term->kind == ZCL_ONTOLOGY_TERM_TYPE;
}

static bool manifest_value_has_type(
    const struct zcl_ontology_manifest_inputs_v1 *inputs,
    const uint8_t value_root[32], const uint8_t type_root[32])
{
    const struct zcl_ontology_term_v1 *term =
        manifest_term_identity_find(inputs, value_root);
    return term && memcmp(term->type_root, type_root, 32) == 0;
}

static bool manifest_context_present(
    const struct zcl_ontology_manifest_inputs_v1 *inputs,
    const uint8_t wanted[32])
{
    for (size_t i = 0; i < inputs->context_count; i++) {
        uint8_t actual[32];
        if (zcl_ontology_context_v1_root(&inputs->contexts[i], actual) &&
            memcmp(actual, wanted, 32) == 0)
            return true;
    }
    return false;
}

static bool manifest_references_valid(
    const struct zcl_ontology_manifest_v1 *manifest,
    const struct zcl_ontology_manifest_inputs_v1 *inputs)
{
    for (size_t i = 0; i < inputs->term_count; i++) {
        if (memcmp(inputs->terms[i].vocabulary_root,
                   manifest->vocabulary_root, 32) != 0 ||
            !manifest_type_present(inputs, inputs->terms[i].type_root))
            return false;
        for (size_t j = i + 1u; j < inputs->term_count; j++)
            if (memcmp(inputs->terms[i].identity_root,
                       inputs->terms[j].identity_root, 32) == 0)
                return false;
    }
    for (size_t i = 0; i < inputs->predicate_count; i++) {
        if (!manifest_term_present(
                inputs, inputs->predicates[i].term_root,
                ZCL_ONTOLOGY_TERM_PREDICATE))
            return false;
        for (size_t argument = 0;
             argument < inputs->predicates[i].arity; argument++)
            if (!manifest_type_present(
                    inputs,
                    inputs->predicates[i].argument_type_roots[argument]))
                return false;
    }
    for (size_t i = 0; i < inputs->formula_count; i++) {
        const struct zcl_ontology_formula_v1 *formula = &inputs->formulas[i];
        for (uint32_t node_index = 0; node_index < formula->node_count;
             node_index++) {
            const struct zcl_ontology_formula_node_v1 *node =
                &formula->nodes[node_index];
            if ((node->op == ZCL_ONTOLOGY_FORMULA_FORALL ||
                 node->op == ZCL_ONTOLOGY_FORMULA_EXISTS) &&
                !manifest_type_present(inputs, node->quantified_type_root))
                return false;
            const struct zcl_ontology_predicate_v1 *predicate = NULL;
            if (node->op == ZCL_ONTOLOGY_FORMULA_ATOM) {
                predicate = manifest_predicate_find(
                    inputs, node->predicate_root);
                if (!predicate || predicate->arity != node->arity)
                    return false;
            }
            for (size_t argument = 0; argument < node->arity; argument++) {
                const struct zcl_ontology_formula_term_v1 *term =
                    &node->terms[argument];
                if (!manifest_type_present(inputs, term->type_root) ||
                    (predicate && memcmp(
                        predicate->argument_type_roots[argument],
                        term->type_root, 32) != 0) ||
                    (term->kind == ZCL_ONTOLOGY_FORMULA_CONSTANT &&
                     !manifest_value_has_type(
                         inputs, term->value_root, term->type_root)))
                    return false;
            }
        }
    }
    for (size_t i = 0; i < inputs->context_count; i++)
        if (memcmp(inputs->contexts[i].universe_root,
                   manifest->universe_root, 32) != 0)
            return false;
    for (size_t i = 0; i < inputs->assertion_count; i++) {
        const struct zcl_ontology_predicate_v1 *predicate =
            manifest_predicate_find(
                inputs, inputs->assertions[i].predicate_root);
        if (!manifest_context_present(inputs,
                                      inputs->assertions[i].context_root) ||
            !predicate || predicate->arity != inputs->assertions[i].arity)
            return false;
        for (size_t argument = 0; argument < predicate->arity; argument++)
            if (!manifest_value_has_type(
                    inputs, inputs->assertions[i].argument_roots[argument],
                    predicate->argument_type_roots[argument]))
                return false;
    }
    for (size_t i = 0; i < inputs->coverage_count; i++)
        if (memcmp(inputs->coverage[i].universe_root,
                   manifest->universe_root, 32) != 0 ||
            !manifest_context_present(inputs,
                                      inputs->coverage[i].context_root))
            return false;
    for (size_t i = 0; i < inputs->domain_count; i++) {
        if (memcmp(inputs->domains[i].universe_root,
                   manifest->universe_root, 32) != 0 ||
            !manifest_context_present(inputs,
                                      inputs->domains[i].context_root) ||
            !manifest_type_present(inputs, inputs->domains[i].type_root))
            return false;
        for (uint64_t value = 0; value < inputs->domains[i].value_count;
             value++)
            if (!manifest_value_has_type(
                    inputs, inputs->domains[i].value_roots[value],
                    inputs->domains[i].type_root))
                return false;
    }
    return true;
}

bool zcl_ontology_manifest_v1_validate(
    const struct zcl_ontology_manifest_v1 *manifest,
    const struct zcl_source_universe_v1 *universe,
    const struct zcl_ontology_manifest_inputs_v1 *inputs)
{
    uint8_t universe_root[32];
    if (!manifest_shape_valid(manifest) || !inputs ||
        !zcl_source_universe_v1_root(universe, universe_root) ||
        memcmp(manifest->source_root, universe->source_manifest_root, 32) != 0 ||
        memcmp(manifest->universe_root, universe_root, 32) != 0 ||
        manifest->rule_count != 0 || manifest->gap_count != 0)
        return false;
    uint8_t empty_rule_root[32], empty_gap_root[32];
    if (!zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_RULE, NULL, 0, empty_rule_root) ||
        !zcl_ontology_object_set_v1_root(
            ZCL_ONTOLOGY_OBJECT_GAP, NULL, 0, empty_gap_root) ||
        memcmp(manifest->rule_set_root, empty_rule_root, 32) != 0 ||
        memcmp(manifest->gap_set_root, empty_gap_root, 32) != 0)
        return false;
    return manifest_typed_set_matches(
               ZCL_ONTOLOGY_OBJECT_TERM, inputs->terms,
               inputs->term_count, sizeof(*inputs->terms), manifest_term_root,
               manifest->term_count,
               manifest->term_set_root) &&
           manifest_typed_set_matches(
               ZCL_ONTOLOGY_OBJECT_PREDICATE, inputs->predicates,
               inputs->predicate_count, sizeof(*inputs->predicates),
               manifest_predicate_root, manifest->predicate_count,
               manifest->predicate_set_root) &&
           manifest_typed_set_matches(
               ZCL_ONTOLOGY_OBJECT_FORMULA, inputs->formulas,
               inputs->formula_count, sizeof(*inputs->formulas),
               manifest_formula_root, manifest->formula_count,
               manifest->formula_set_root) &&
           manifest_typed_set_matches(
               ZCL_ONTOLOGY_OBJECT_CONTEXT, inputs->contexts,
               inputs->context_count, sizeof(*inputs->contexts),
               manifest_context_root, manifest->context_count,
               manifest->context_set_root) &&
           manifest_typed_set_matches(
               ZCL_ONTOLOGY_OBJECT_ASSERTION, inputs->assertions,
               inputs->assertion_count, sizeof(*inputs->assertions),
               manifest_assertion_root, manifest->assertion_count,
               manifest->assertion_set_root) &&
           manifest_typed_set_matches(
               ZCL_ONTOLOGY_OBJECT_COVERAGE, inputs->coverage,
               inputs->coverage_count, sizeof(*inputs->coverage),
               manifest_coverage_root, manifest->coverage_count,
               manifest->coverage_set_root) &&
           manifest_typed_set_matches(
               ZCL_ONTOLOGY_OBJECT_DOMAIN, inputs->domains,
               inputs->domain_count, sizeof(*inputs->domains),
               manifest_domain_root, manifest->domain_count,
               manifest->domain_set_root) &&
           manifest_references_valid(manifest, inputs);
}
