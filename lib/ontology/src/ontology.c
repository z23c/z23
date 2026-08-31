/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Canonical roots and bounded four-valued ontology evaluation. */
#include "ontology/ontology.h"

#include "base/bytes.h"
#include "base/serialize_le.h"
#include "sha3/sha3.h"

#include <string.h>

static bool nonzero(const uint8_t root[32])
{
    return root && zcl_bytes_any_set(root, 32);
}

static void hash_start(struct sha3_256_ctx *sha, const char *domain)
{
    sha3_256_init(sha);
    sha3_256_write(sha, (const uint8_t *)domain, strlen(domain) + 1u);
}

static void hash_u16(struct sha3_256_ctx *sha, uint16_t value)
{
    uint8_t wire[2]; zcl_write_u16_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

static void hash_u32(struct sha3_256_ctx *sha, uint32_t value)
{
    uint8_t wire[4]; zcl_write_u32_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

static void hash_u64(struct sha3_256_ctx *sha, uint64_t value)
{
    uint8_t wire[8]; zcl_write_u64_le(wire, value);
    sha3_256_write(sha, wire, sizeof(wire));
}

bool zcl_source_universe_v1_root(
    const struct zcl_source_universe_v1 *u, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!u || !out || u->schema_version != ZCL_SOURCE_UNIVERSE_VERSION ||
        u->reserved != 0 || u->coverage_mask != ZCL_SOURCE_COVER_ALL ||
        u->governed_path_count == 0 || u->total_bytes == 0)
        return false;
    const uint8_t *roots[] = {
        u->source_manifest_root, u->governed_paths_root,
        u->generated_paths_root, u->vendor_paths_root,
        u->metadata_paths_root, u->publishable_paths_root,
        u->consensus_seal_root, u->indexed_paths_root,
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!nonzero(roots[i])) return false;
    struct sha3_256_ctx sha;
    hash_start(&sha, "zcl.source_universe.v1");
    hash_u16(&sha, u->schema_version); hash_u16(&sha, u->reserved);
    hash_u32(&sha, u->coverage_mask);
    hash_u64(&sha, u->governed_path_count); hash_u64(&sha, u->total_bytes);
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        sha3_256_write(&sha, roots[i], 32);
    sha3_256_finalize(&sha, out);
    return true;
}

bool zcl_ontology_predicate_v1_root(
    const struct zcl_ontology_predicate_v1 *p, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!p || !out || p->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        p->arity > ZCL_ONTOLOGY_MAX_ARITY ||
        (p->world != ZCL_ONTOLOGY_OPEN_WORLD &&
         p->world != ZCL_ONTOLOGY_CLOSED_WORLD) ||
        p->execution_tier < ZCL_ONTOLOGY_TIER_EXACT ||
        p->execution_tier > ZCL_ONTOLOGY_TIER_GOAL ||
        p->explicit_negation != 1 || p->reserved != 0 ||
        (p->coverage_required & ~ZCL_SOURCE_COVER_ALL) != 0 ||
        (p->world == ZCL_ONTOLOGY_CLOSED_WORLD &&
         p->coverage_required == 0) ||
        !nonzero(p->term_root)) return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
        if ((i < p->arity) != nonzero(p->argument_type_roots[i])) return false;
    struct sha3_256_ctx sha; hash_start(&sha, "zcl.ontology_predicate.v1");
    hash_u16(&sha, p->schema_version);
    const uint8_t fields[] = {p->arity, p->world, p->execution_tier,
                              p->explicit_negation};
    sha3_256_write(&sha, fields, sizeof(fields));
    hash_u16(&sha, p->reserved); hash_u32(&sha, p->coverage_required);
    sha3_256_write(&sha, p->term_root, 32);
    sha3_256_write(&sha, &p->argument_type_roots[0][0],
                   sizeof(p->argument_type_roots));
    sha3_256_finalize(&sha, out); return true;
}

bool zcl_ontology_context_v1_root(
    const struct zcl_ontology_context_v1 *c, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!c || !out || c->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        c->kind < ZCL_ONTOLOGY_CONTEXT_CORPUS ||
        c->kind > ZCL_ONTOLOGY_CONTEXT_TASK || c->reserved != 0 ||
        !nonzero(c->universe_root) || !nonzero(c->subject_root) ||
        !nonzero(c->import_manifest_root) || !nonzero(c->policy_root))
        return false;
    struct sha3_256_ctx sha; hash_start(&sha, "zcl.ontology_context.v1");
    hash_u16(&sha, c->schema_version); sha3_256_write(&sha, &c->kind, 1);
    sha3_256_write(&sha, &c->reserved, 1);
    sha3_256_write(&sha, c->universe_root, 32);
    sha3_256_write(&sha, c->subject_root, 32);
    sha3_256_write(&sha, c->import_manifest_root, 32);
    sha3_256_write(&sha, c->policy_root, 32);
    sha3_256_finalize(&sha, out); return true;
}

bool zcl_ontology_assertion_v1_root(
    const struct zcl_ontology_assertion_v1 *a, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!a || !out || a->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        a->arity > ZCL_ONTOLOGY_MAX_ARITY ||
        (a->polarity != ZCL_ONTOLOGY_POSITIVE &&
         a->polarity != ZCL_ONTOLOGY_NEGATIVE) ||
        !nonzero(a->context_root) || !nonzero(a->predicate_root) ||
        !nonzero(a->evidence_root)) return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
        if ((i < a->arity) != nonzero(a->argument_roots[i])) return false;
    struct sha3_256_ctx sha; hash_start(&sha, "zcl.ontology_assertion.v1");
    hash_u16(&sha, a->schema_version); sha3_256_write(&sha, &a->arity, 1);
    sha3_256_write(&sha, &a->polarity, 1);
    sha3_256_write(&sha, a->context_root, 32);
    sha3_256_write(&sha, a->predicate_root, 32);
    sha3_256_write(&sha, &a->argument_roots[0][0], sizeof(a->argument_roots));
    sha3_256_write(&sha, a->evidence_root, 32);
    sha3_256_finalize(&sha, out); return true;
}

bool zcl_ontology_import_manifest_v1_root(
    const uint8_t universe_root[32], const uint8_t (*imports)[32],
    size_t import_count, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!out || !nonzero(universe_root) || import_count > ZCL_ONTOLOGY_MAX_IMPORTS ||
        (import_count && !imports)) return false;
    for (size_t i = 0; i < import_count; i++)
        if (!nonzero(imports[i]) || (i && memcmp(imports[i - 1], imports[i], 32) >= 0))
            return false;
    struct sha3_256_ctx sha; hash_start(&sha, "zcl.ontology_import_manifest.v1");
    sha3_256_write(&sha, universe_root, 32); hash_u64(&sha, import_count);
    for (size_t i = 0; i < import_count; i++) sha3_256_write(&sha, imports[i], 32);
    sha3_256_finalize(&sha, out); return true;
}

bool zcl_ontology_coverage_v1_root(
    const struct zcl_ontology_coverage_v1 *c, uint8_t out[32])
{
    if (out) memset(out, 0, 32);
    if (!c || !out || c->schema_version != ZCL_ONTOLOGY_OBJECT_VERSION ||
        c->reserved || c->complete_mask == 0 ||
        (c->complete_mask & ~ZCL_SOURCE_COVER_ALL) || !nonzero(c->universe_root) ||
        !nonzero(c->context_root) || !nonzero(c->evidence_root)) return false;
    struct sha3_256_ctx sha; hash_start(&sha, "zcl.ontology_coverage.v1");
    hash_u16(&sha, c->schema_version); hash_u16(&sha, c->reserved);
    hash_u32(&sha, c->complete_mask);
    sha3_256_write(&sha, c->universe_root, 32);
    sha3_256_write(&sha, c->context_root, 32);
    sha3_256_write(&sha, c->evidence_root, 32);
    sha3_256_finalize(&sha, out); return true;
}

static bool context_visible(const struct zcl_ontology_query_v1 *q,
                            const uint8_t root[32])
{
    if (memcmp(q->context_root, root, 32) == 0) return true;
    for (size_t i = 0; i < q->import_count; i++)
        if (memcmp(q->import_context_roots[i], root, 32) == 0) return true;
    return false;
}

static bool contexts_bound(const struct zcl_ontology_query_v1 *q,
                           const uint8_t universe_root[32])
{
    uint8_t imports_root[32];
    if (!q->contexts || q->context_count == 0 ||
        memcmp(q->universe_root, universe_root, 32) != 0 ||
        !zcl_ontology_import_manifest_v1_root(
            universe_root, q->import_context_roots, q->import_count,
            imports_root))
        return false;
    for (size_t wanted = 0; wanted <= q->import_count; wanted++) {
        const uint8_t *root = wanted == 0 ? q->context_root
            : q->import_context_roots[wanted - 1u];
        bool found = false;
        for (size_t i = 0; i < q->context_count; i++) {
            uint8_t actual[32];
            if (zcl_ontology_context_v1_root(&q->contexts[i], actual) &&
                memcmp(actual, root, 32) == 0 &&
                memcmp(q->contexts[i].universe_root, universe_root, 32) == 0) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    bool primary_found = false;
    for (size_t i = 0; i < q->context_count; i++) {
        uint8_t actual[32];
        if (zcl_ontology_context_v1_root(&q->contexts[i], actual) &&
            memcmp(actual, q->context_root, 32) == 0 &&
            memcmp(q->contexts[i].import_manifest_root, imports_root, 32) == 0)
            primary_found = true;
    }
    if (!primary_found) return false;
    return true;
}

static uint32_t missing_coverage(const struct zcl_ontology_query_v1 *q,
                                 uint32_t required)
{
    uint32_t missing = 0;
    for (size_t wanted = 0; wanted <= q->import_count; wanted++) {
        const uint8_t *context = wanted == 0 ? q->context_root
            : q->import_context_roots[wanted - 1u];
        uint32_t proved = 0;
        for (size_t i = 0; i < q->coverage_count; i++) {
            uint8_t ignored[32];
            if (zcl_ontology_coverage_v1_root(&q->coverage[i], ignored) &&
                memcmp(q->coverage[i].universe_root, q->universe_root, 32) == 0 &&
                memcmp(q->coverage[i].context_root, context, 32) == 0)
                proved |= q->coverage[i].complete_mask;
        }
        missing |= required & ~proved;
    }
    return missing;
}

bool zcl_ontology_evaluate_atom_v1(
    const struct zcl_source_universe_v1 *u,
    const struct zcl_ontology_predicate_v1 *p,
    const struct zcl_ontology_query_v1 *q,
    struct zcl_ontology_result_v1 *out)
{
    uint8_t universe_root[32], predicate_root[32];
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !q || !zcl_source_universe_v1_root(u, universe_root) ||
        !zcl_ontology_predicate_v1_root(p, predicate_root) ||
        q->arity != p->arity || memcmp(q->predicate_root, predicate_root, 32) ||
        !nonzero(q->context_root) || q->import_count > ZCL_ONTOLOGY_MAX_IMPORTS ||
        (q->import_count && !q->import_context_roots) ||
        q->context_count > ZCL_ONTOLOGY_MAX_CONTEXTS ||
        q->coverage_count > ZCL_ONTOLOGY_MAX_COVERAGE ||
        (q->coverage_count && !q->coverage) ||
        (q->assertion_count && !q->assertions) ||
        !contexts_bound(q, universe_root)) return false;
    for (size_t i = 0; i < ZCL_ONTOLOGY_MAX_ARITY; i++)
        if ((i < p->arity) != nonzero(q->argument_roots[i])) return false;
    if (p->execution_tier != ZCL_ONTOLOGY_TIER_EXACT) {
        out->status = ZCL_ONTOLOGY_INCOMPLETE; out->complete = false;
        out->truncation_reason = "predicate_tier_unsupported"; return true;
    }
    size_t limit = q->assertion_count;
    if (limit > q->fact_budget) limit = q->fact_budget;
    for (size_t i = 0; i < limit; i++) {
        const struct zcl_ontology_assertion_v1 *a = &q->assertions[i];
        uint8_t assertion_root[32];
        out->facts_examined++;
        if (!zcl_ontology_assertion_v1_root(a, assertion_root)) {
            out->status = ZCL_ONTOLOGY_INCOMPLETE; out->complete = false;
            out->truncation_reason = "invalid_assertion"; return true;
        }
        if (a->arity != q->arity || !context_visible(q, a->context_root) ||
            memcmp(a->predicate_root, q->predicate_root, 32) ||
            memcmp(a->argument_roots, q->argument_roots,
                   sizeof(q->argument_roots))) continue;
        if (a->polarity == ZCL_ONTOLOGY_POSITIVE) out->observed_positive = true;
        if (a->polarity == ZCL_ONTOLOGY_NEGATIVE) out->observed_negative = true;
    }
    if (q->assertion_count > limit) {
        out->status = ZCL_ONTOLOGY_INCOMPLETE; out->complete = false;
        out->truncation_reason = "fact_budget_exhausted"; return true;
    }
    if (out->observed_positive && out->observed_negative)
        out->status = ZCL_ONTOLOGY_BOTH;
    else if (out->observed_positive) out->status = ZCL_ONTOLOGY_PROVED;
    else if (out->observed_negative) out->status = ZCL_ONTOLOGY_DISPROVED;
    else if (p->world == ZCL_ONTOLOGY_OPEN_WORLD)
        out->status = ZCL_ONTOLOGY_UNKNOWN;
    else {
        out->missing_coverage_mask = missing_coverage(q, p->coverage_required);
        out->status = out->missing_coverage_mask
            ? ZCL_ONTOLOGY_INCOMPLETE : ZCL_ONTOLOGY_DISPROVED;
    }
    out->complete = out->status != ZCL_ONTOLOGY_INCOMPLETE;
    return true;
}
