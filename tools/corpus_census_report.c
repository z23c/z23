/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * corpus-census: the evidence bundle and KPI report JSON documents
 * (slice 1b). Builds `evidence-<seq>.json` (every signed wire, every
 * recipe, every scope's roots and dependencies — the full audit trail)
 * and `report-<seq>.json` (the human-facing KPI summary, growth-rate
 * delta, exclusion accounting, and disclosures) from the finished
 * census_ctx that main()'s staged pipeline assembles. Neither document's
 * content can fail to build except for a handful of allocation/overflow
 * checks; those return false so the caller can exit the way the
 * original inline LOG_ERR call once did.
 */

#define _GNU_SOURCE

#include "corpus_census_priv.h"

#include "base/checked.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "vcs/zcode_c23_corpus_census.h"
#include "vcs/zcode_family_admission.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *exclusion_name(uint32_t bit)
{
    switch (bit) {
    case VCS_ZCODE_C23_EXCLUDE_VENDOR: return "vendor";
    case VCS_ZCODE_C23_EXCLUDE_MECHANICAL: return "mechanical";
    case VCS_ZCODE_C23_EXCLUDE_UNASSIGNED: return "unassigned";
    case VCS_ZCODE_C23_EXCLUDE_LICENSE: return "license";
    case VCS_ZCODE_C23_EXCLUDE_UNSUPPORTED: return "unsupported";
    case VCS_ZCODE_C23_EXCLUDE_OVERSIZE: return "oversize";
    case VCS_ZCODE_C23_EXCLUDE_INCOMPLETE: return "incomplete";
    case VCS_ZCODE_C23_EXCLUDE_DUPLICATE: return "duplicate";
    case VCS_ZCODE_C23_EXCLUDE_CONFLICT: return "conflict";
    case VCS_ZCODE_C23_EXCLUDE_REVIEW_REQUIRED: return "review_required";
    case VCS_ZCODE_C23_EXCLUDE_STALE_ADMISSION: return "stale_admission";
    case VCS_ZCODE_C23_EXCLUDE_INCOMPLETE_POSSESSION:
        return "incomplete_possession";
    }
    return "unknown";
}

static const struct {
    uint64_t bit;
    const char *name;
} k_evidence_bits[] = {
    {VCS_ZCODE_C23_EVIDENCE_API, "api"},
    {VCS_ZCODE_C23_EVIDENCE_RECIPE, "recipe"},
    {VCS_ZCODE_C23_EVIDENCE_TESTS, "tests"},
    {VCS_ZCODE_C23_EVIDENCE_PERMISSIVE_LICENSE, "permissive_license"},
    {VCS_ZCODE_C23_EVIDENCE_QUALITY_PROFILE, "quality_profile"},
    {VCS_ZCODE_C23_EVIDENCE_SOURCE_ASSIGNMENT, "source_assignment"},
    {VCS_ZCODE_C23_EVIDENCE_REPRODUCIBLE, "reproducible"},
    {VCS_ZCODE_C23_EVIDENCE_FAMILY_QUORUM, "family_quorum"},
    {VCS_ZCODE_C23_EVIDENCE_COMPLETE_POSSESSION, "complete_possession"},
};

static const char *kind_name(uint16_t kind)
{
    switch (kind) {
    case VCS_ZCODE_SOURCE_HUMAN_AUTHORED: return "human";
    case VCS_ZCODE_SOURCE_AI_AUTHORED: return "ai";
    case VCS_ZCODE_SOURCE_CANONICAL_IMPORT: return "import";
    default: return "unknown";
    }
}

/* ── evidence bundle ───────────────────────────────────────────────── */

static void census_evidence_recipes_build(const struct census_ctx *ctx,
                                          struct json_value *evidence)
{
    struct json_value recipes;
    json_init(&recipes);
    json_set_object(&recipes);
    (void)json_push_kv_str(&recipes, "release_root",
        "vcs_signed_evidence_root(\"zcl.zcode.corpus.release.v1\" incl "
        "NUL, concat over sorted repo-relative paths of path || NUL || "
        "u64-LE size || sha3_256(content))");
    (void)json_push_kv_str(&recipes, "license_root",
        "same-style root over license-path || NUL || u64-LE size || "
        "sha3_256(content) for the license file actually used "
        "(scope-local LICENSE else repo-root LICENSE), domain "
        "zcl.zcode.corpus.license.v1");
    (void)json_push_kv_str(&recipes, "author_binding_root",
        "domain zcl.zcode.corpus.author_binding.v1 over the ASCII "
        "author string (\"ZClassic23 founding contributors\" for kind "
        "human, \"zclassic23-agent-fleet\" for kind ai)");
    (void)json_push_kv_str(&recipes, "assignment_evidence_root",
        "domain zcl.zcode.corpus.assignment_evidence.v1 over the exact "
        "scopes.def line bytes for the scope (no trailing newline)");
    (void)json_push_kv_str(&recipes, "dependency_closure_root",
        "domain zcl.zcode.corpus.dependency_closure.v1 over concat of "
        "name || NUL || root-hex-ascii || NUL || semver || NUL per "
        "zcode-package.json dependency (file order); empty wire for "
        "the declared empty set");
    (void)json_push_kv_str(&recipes, "moderation_set_root",
        "domain zcl.zcode.corpus.moderation_set.v1 over the EMPTY wire "
        "(founding empty moderation set; corpus-local construction, "
        "no canonical founding root exists in "
        "zcode_family_moderation.c)");
    (void)json_push_kv_str(&recipes, "panel_root",
        "domain zcl.zcode.corpus.panel.v1 over the ASCII literal "
        "\"founding-self-screen\"");
    (void)json_push_kv_str(&recipes, "admission_evidence_root",
        "domain zcl.zcode.corpus.admission_evidence.v1 over the "
        "scope's 32-byte source_assignment_root");
    (void)json_push_kv_str(&recipes, "passport_root",
        "domain zcl.zcode.corpus.passport.v1 over name || NUL || spdx "
        "|| NUL || release_root || license_root || api-presence byte "
        "|| recipe-presence byte");
    (void)json_push_kv_str(&recipes, "recipe_root",
        "domain zcl.zcode.corpus.recipe.v1 over recipe-path || NUL || "
        "u64-LE size || sha3_256(content); the recipe is the scope's "
        "zcode-package.json when present, else the repo Makefile "
        "(declared core-scope build recipe)");
    (void)json_push_kv_str(&recipes, "quality_root",
        "domain zcl.zcode.corpus.quality.v1 over sorted tools/lint/ "
        "path || NUL || sha3_256(content) pairs; computed only with "
        "--quality-attested 1");
    (void)json_push_kv_str(&recipes, "reproduction_root",
        "domain zcl.zcode.corpus.reproduction.v1 over release_root || "
        "method literal (\"dual-worktree\" or "
        "\"in-process-reenumeration\")");
    (void)json_push_kv_str(&recipes, "proof_root",
        "domain zcl.zcode.corpus.proof.v1 over release_root || "
        "source_assignment_root || admission_root || quality_root || "
        "reproduction_root (zero slots = unattested)");
    (void)json_push_kv_str(&recipes, "possession_root",
        "domain zcl.zcode.corpus.possession.v1 over the scope's sorted "
        ".zvcs CAS blob hashes; REPORT ONLY — entries keep "
        "possession_root zero and DURABLE clear");
    (void)json_push_kv_str(&recipes, "replication_evidence_root",
        "domain zcl.zcode.corpus.replication.v1 over concat(shard "
        "roots in checkpoint order) || \"single-host-founding-v1\"");
    if (ctx->any_package) {
        (void)json_push_kv_str(&recipes, "package_release_root",
            "the def's package root, verified against the re-derived "
            "manifest root of the store's committed manifest "
            "(manifests/<root-hex>) — the EXACT published bytes");
        (void)json_push_kv_str(&recipes, "package_recipe_root",
            "the release envelope's recipe_root with the recipe wire "
            "present under recipes/ and re-rooted (fail closed on "
            "mismatch)");
        (void)json_push_kv_str(&recipes, "package_reproduction_root",
            "domain zcl.zcode.corpus.reproduction.v1 over release_root "
            "|| \"receipts-dual-confined-build\" || concat(sorted "
            "matching receipt ids) — vcs_package_reproduce_scan over "
            "<store>/zcode/receipts: >= 2 DISTINCT build receipts "
            "committing byte-identical output sets");
        (void)json_push_kv_str(&recipes, "package_quality_root",
            "domain zcl.zcode.corpus.quality.v1 over release_root || "
            "\"confined-build-test-receipt-green\" || concat(sorted "
            "receipt ids); the package QUALITY mapping is the same "
            "receipts evidence as REPRODUCIBLE, set iff reproduced");
        (void)json_push_kv_str(&recipes, "package_author_binding_root",
            "domain zcl.zcode.corpus.author_binding.v1 over the release "
            "envelope's publisher pubkey as 66 lowercase hex ASCII");
        (void)json_push_kv_str(&recipes, "package_possession_root",
            "domain zcl.zcode.corpus.possession.v1 over the sorted "
            "unique manifest chunk hashes; every chunk was re-read "
            "from the CAS and hash-verified (read-only equivalent of "
            "vcs_package_store_verify_possession require_pinned=false); "
            "REPORT ONLY — possession_root zero and DURABLE clear in "
            "the entry");
    }
    (void)json_push_kv(evidence, "recipes", &recipes);
    json_free(&recipes);
}

static void census_evidence_founding_build(const struct census_ctx *ctx,
                                           struct json_value *evidence)
{
    struct json_value founding;
    json_init(&founding);
    json_set_object(&founding);
    json_push_root(&founding, "family_policy_root", ctx->family_policy_root);
    json_push_root(&founding, "moderation_set_root",
                   ctx->moderation_set_root);
    json_push_root(&founding, "quality_root", ctx->quality_root);
    json_push_root(&founding, "replication_evidence_root",
                   ctx->replication_root);
    (void)json_push_kv_str(&founding, "reproduction_method",
                           ctx->repro_method);
    (void)json_push_kv_str(&founding, "panel_literal", k_panel_literal);
    (void)json_push_kv_int(&founding, "admission_expiry_blocks",
        (int64_t)CORPUS_CENSUS_ADMISSION_EXPIRY_BLOCKS);
    (void)json_push_kv_int(&founding, "admission_expiry_mtp_seconds",
        (int64_t)CORPUS_CENSUS_ADMISSION_EXPIRY_MTP_SECONDS);
    (void)json_push_kv(evidence, "founding", &founding);
    json_free(&founding);
}

static void census_evidence_scope_roots_build(const struct scope_measure *m,
                                              const struct scope_run *run,
                                              struct json_value *roots)
{
    json_init(roots);
    json_set_object(roots);
    json_push_root(roots, "release_root", m->release_root);
    json_push_root(roots, "license_root", m->license_root);
    json_push_root(roots, "recipe_root", m->recipe_root);
    json_push_root(roots, "dependency_closure_root", m->dep_closure_root);
    json_push_root(roots, "possession_root", m->possession_root);
    json_push_root(roots, "source_assignment_root", run->assignment_root);
    json_push_root(roots, "admission_root", run->admission_root);
    json_push_root(roots, "passport_root", run->passport_root);
    json_push_root(roots, "proof_root", run->proof_root);
    json_push_root(roots, "quality_root", run->quality_root);
    json_push_root(roots, "reproduction_root", run->reproduction_root);
}

static void census_evidence_scope_package_build(const struct scope_def *def,
                                                const struct scope_run *run,
                                                struct json_value *pobj)
{
    const struct package_ctx *pk = &run->pkg;
    json_init(pobj);
    json_set_object(pobj);
    json_push_root(pobj, "package_root", def->package_root);
    json_push_root(pobj, "release_id", pk->release_id);
    json_push_root(pobj, "recipe_root", pk->release.recipe_root);
    /* The store LABEL, never the resolved directory: this record is
     * committed. */
    (void)json_push_kv_str(pobj, "store", def->store);
    (void)json_push_kv_str(pobj, "release_name", pk->release.name);
    (void)json_push_kv_str(pobj, "semver", pk->release.semver);
    (void)json_push_kv_str(pobj, "publisher_pubkey", pk->publisher_hex);
    (void)json_push_kv_str(pobj, "reproduction_method", k_repro_receipts);
    (void)json_push_kv_bool(pobj, "reproduced", run->reproduced);
    struct json_value ids;
    json_init(&ids);
    json_set_array(&ids);
    for (size_t i = 0; i < run->receipt_ids.n; i++)
        json_push_str(&ids, run->receipt_ids.v[i]);
    (void)json_push_kv(pobj, "receipt_ids", &ids);
    json_free(&ids);
}

static bool census_evidence_scope_build(const struct census_ctx *ctx,
                                        size_t s, struct json_value *obj)
{
    const struct scope_def *def = &ctx->defs[s];
    const struct scope_run *run = &ctx->runs[s];
    const struct scope_measure *m = &run->measure;
    json_init(obj);
    json_set_object(obj);
    (void)json_push_kv_str(obj, "kind", kind_name(def->kind));
    (void)json_push_kv_str(obj, "spdx", def->spdx);
    (void)json_push_kv_str(obj, "license_file",
                           m->license_path ? m->license_path : "");
    (void)json_push_kv_str(obj, "recipe_file",
                           m->recipe_path ? m->recipe_path : "");
    (void)json_push_kv_bool(obj, "recipe_is_zcode_package",
                            m->recipe_is_package);
    (void)json_push_kv_str(obj, "scopes_def_line", def->def_line);
    {
        struct json_value roots;
        census_evidence_scope_roots_build(m, run, &roots);
        (void)json_push_kv(obj, "roots", &roots);
        json_free(&roots);
    }
    if (m->deps)
        (void)json_push_kv(obj, "dependencies", m->deps);
    else {
        struct json_value empty;
        json_init(&empty);
        json_set_array(&empty);
        (void)json_push_kv(obj, "dependencies", &empty);
        json_free(&empty);
    }
    {
        size_t hex_len = VCS_ZCODE_COMMONS_ADMISSION_WIRE_BYTES * 2u;
        char *hex = zcl_malloc(hex_len + 1u, "corpus.ev.hex");
        if (!hex)
            LOG_FAIL(CENSUS_LOG, "evidence hex alloc");
        zcl_hex_encode(run->assignment_wire, run->assignment_wire_len, hex);
        (void)json_push_kv_str(obj, "assignment_wire", hex);
        zcl_hex_encode(run->admission_wire, run->admission_wire_len, hex);
        (void)json_push_kv_str(obj, "admission_wire", hex);
        free(hex);
    }
    if (def->is_package) {
        struct json_value pobj;
        census_evidence_scope_package_build(def, run, &pobj);
        (void)json_push_kv(obj, "package", &pobj);
        json_free(&pobj);
    }
    return true;
}

static bool census_evidence_scopes_build(const struct census_ctx *ctx,
                                         struct json_value *evidence)
{
    struct json_value scopes;
    json_init(&scopes);
    json_set_object(&scopes);
    for (size_t s = 0; s < ctx->scope_count; s++) {
        struct json_value obj;
        if (!census_evidence_scope_build(ctx, s, &obj)) return false;
        (void)json_push_kv(&scopes, ctx->defs[s].name, &obj);
        json_free(&obj);
    }
    (void)json_push_kv(evidence, "scopes", &scopes);
    json_free(&scopes);
    return true;
}

bool census_build_evidence_bundle(const struct census_ctx *ctx,
                                  struct json_value *evidence)
{
    json_init(evidence);
    json_set_object(evidence);
    (void)json_push_kv_str(evidence, "schema",
                           "zcl.c23_corpus_census.evidence.v1");
    (void)json_push_kv_bool(evidence, "simulation_only", true);
    (void)json_push_kv_bool(evidence, "not_owner_approved", true);
    (void)json_push_kv_int(evidence, "sequence", (int64_t)ctx->args.sequence);
    (void)json_push_kv_int(evidence, "cutoff_height",
                           (int64_t)ctx->args.cutoff_height);
    (void)json_push_kv_int(evidence, "cutoff_mtp",
                           (int64_t)ctx->args.cutoff_mtp);
    (void)json_push_kv_str(evidence, "signer_pubkey", ctx->pubkey_hex);
    {
        char hex[65];
        root_hex(ctx->def_sha3, hex);
        (void)json_push_kv_str(evidence, "scopes_def_sha3", hex);
    }
    census_evidence_recipes_build(ctx, evidence);
    census_evidence_founding_build(ctx, evidence);
    return census_evidence_scopes_build(ctx, evidence);
}

/* ── KPI report ────────────────────────────────────────────────────── */

static bool census_downstream_mark_one(const struct census_ctx *ctx,
                                       size_t t, const char *droot,
                                       bool *used, uint64_t *downstream)
{
    for (size_t s = 0; s < ctx->scope_count; s++) {
        if (s == t || used[s] || !ctx->defs[s].is_package ||
            !(ctx->runs[s].result.entry.flags &
              VCS_ZCODE_C23_ENTRY_COUNTED))
            continue;
        char hex[65];
        root_hex(ctx->defs[s].package_root, hex);
        if (strcmp(droot, hex) != 0) continue;
        used[s] = true;
        uint64_t loc = 0;
        if (!zcl_u64_add(ctx->runs[s].measure.prod_loc,
                         ctx->runs[s].measure.test_loc, &loc) ||
            !zcl_u64_add(*downstream, loc, downstream))
            LOG_FAIL(CENSUS_LOG, "downstream-used overflow");
    }
    return true;
}

static bool census_downstream_scan_deps(const struct census_ctx *ctx,
                                        size_t t, const struct json_value *deps,
                                        bool *used, uint64_t *downstream)
{
    for (size_t d = 0; d < deps->num_children; d++) {
        const char *droot =
            json_get_str(json_get(json_at(deps, d), "root"));
        if (!droot || strlen(droot) != 64) continue;
        if (!census_downstream_mark_one(ctx, t, droot, used, downstream))
            return false;
    }
    return true;
}

/* Downstream-used LOC: admitted package scopes whose exact package root is
 * pinned in another scope's dependency closure. Counted once per
 * depended-upon package. */
static bool census_downstream_used_compute(const struct census_ctx *ctx,
                                           uint64_t *downstream,
                                           uint64_t *dep_pinned_scopes,
                                           uint64_t *dep_empty_scopes)
{
    *downstream = 0;
    *dep_pinned_scopes = 0;
    *dep_empty_scopes = 0;
    bool *used = zcl_calloc(ctx->scope_count ? ctx->scope_count : 1,
                            sizeof(*used), "corpus.kpi.used");
    if (!used)
        LOG_FAIL(CENSUS_LOG, "downstream-used alloc");
    bool ok = true;
    for (size_t t = 0; ok && t < ctx->scope_count; t++) {
        const struct json_value *deps = ctx->runs[t].measure.deps;
        if (!deps || deps->type != JSON_ARR || deps->num_children == 0) {
            (*dep_empty_scopes)++;
            continue;
        }
        (*dep_pinned_scopes)++;
        ok = census_downstream_scan_deps(ctx, t, deps, used, downstream);
    }
    free(used);
    return ok;
}

static bool census_report_kpis_build(const struct census_ctx *ctx,
                                     struct json_value *report)
{
    uint64_t admitted = 0;
    (void)zcl_u64_add(ctx->assembly.production_loc, ctx->assembly.test_loc,
                      &admitted);
    uint64_t downstream = 0, dep_pinned_scopes = 0, dep_empty_scopes = 0;
    if (!census_downstream_used_compute(ctx, &downstream, &dep_pinned_scopes,
                                        &dep_empty_scopes))
        return false;
    struct json_value kpis;
    json_init(&kpis);
    json_set_object(&kpis);
    (void)json_push_kv_int(&kpis, "admitted_production_loc",
                           (int64_t)ctx->assembly.production_loc);
    (void)json_push_kv_int(&kpis, "admitted_test_loc",
                           (int64_t)ctx->assembly.test_loc);
    (void)json_push_kv_int(&kpis, "admitted_total_loc", (int64_t)admitted);
    (void)json_push_kv_int(&kpis, "durably_hosted_loc",
                           (int64_t)ctx->assembly.durable_loc);
    (void)json_push_kv_int(&kpis, "downstream_used_loc",
                           (int64_t)downstream);
    (void)json_push_kv_int(&kpis, "scopes_with_pinned_dependencies",
                           (int64_t)dep_pinned_scopes);
    (void)json_push_kv_int(&kpis, "scopes_without_pinned_dependencies",
                           (int64_t)dep_empty_scopes);
    (void)json_push_kv_int(&kpis, "physical_lines",
                           (int64_t)ctx->assembly.physical_lines);
    (void)json_push_kv_int(&kpis, "unique_semantic_units",
                           (int64_t)ctx->assembly.unique_semantic_units);
    (void)json_push_kv_int(&kpis, "packages_admitted",
        (int64_t)(ctx->census_count - ctx->assembly.excluded_entries));
    (void)json_push_kv_int(&kpis, "packages_excluded",
                           (int64_t)ctx->assembly.excluded_entries);
    (void)json_push_kv(report, "kpis", &kpis);
    json_free(&kpis);
    return true;
}

/* Growth-rate KPI: raw deltas against the previous sequence's report.
 * Per-day rates are floor integers emitted only when at least one full day
 * elapsed between the two cutoffs (never fake precision). */
static bool census_report_growth_delta(const struct census_ctx *ctx,
                                       struct json_value *report)
{
    uint8_t *prev_wire = NULL;
    size_t prev_len = 0;
    if (!store_file_read(ctx->args.previous_report, 4u * 1024u * 1024u,
                         &prev_wire, &prev_len) || !prev_wire) {
        LOG_ERROR(CENSUS_LOG, "previous report %s unreadable",
                  ctx->args.previous_report);
        return false;
    }
    struct json_value prev;
    json_init(&prev);
    bool ok = json_read(&prev, (const char *)prev_wire, prev_len);
    free(prev_wire);
    const struct json_value *pk = ok ? json_get(&prev, "kpis") : NULL;
    const struct json_value *pc = ok ? json_get(&prev, "cutoff") : NULL;
    int64_t prev_total =
        pk ? json_get_int(json_get(pk, "admitted_total_loc")) : -1;
    int64_t prev_pkgs =
        pk ? json_get_int(json_get(pk, "packages_admitted")) : -1;
    int64_t prev_mtp = pc ? json_get_int(json_get(pc, "mtp")) : -1;
    int64_t prev_seq = ok ? json_get_int(json_get(&prev, "sequence")) : -1;
    if (!ok || prev_total < 0 || prev_pkgs < 0 || prev_mtp <= 0 ||
        prev_seq < 0) {
        json_free(&prev);
        LOG_ERROR(CENSUS_LOG, "previous report %s lacks the KPI fields",
                  ctx->args.previous_report);
        return false;
    }
    uint64_t this_total_u = 0;
    if (!zcl_u64_add(ctx->assembly.production_loc, ctx->assembly.test_loc,
                     &this_total_u)) {
        json_free(&prev);
        LOG_ERROR(CENSUS_LOG, "delta total overflow");
        return false;
    }
    int64_t this_total = (int64_t)this_total_u;
    int64_t this_pkgs =
        (int64_t)(ctx->census_count - ctx->assembly.excluded_entries);
    int64_t days = (ctx->args.cutoff_mtp - prev_mtp) / 86400;
    struct json_value delta;
    json_init(&delta);
    json_set_object(&delta);
    (void)json_push_kv_int(&delta, "previous_sequence", prev_seq);
    (void)json_push_kv_int(&delta, "days_elapsed", days);
    (void)json_push_kv_int(&delta, "admitted_loc_added",
                           this_total - prev_total);
    (void)json_push_kv_int(&delta, "packages_added", this_pkgs - prev_pkgs);
    if (days > 0) {
        (void)json_push_kv_int(&delta, "admitted_loc_per_day",
            (this_total - prev_total) / days);
        (void)json_push_kv_int(&delta, "packages_per_day_x100",
            (this_pkgs - prev_pkgs) * 100 / days);
    }
    (void)json_push_kv(report, "delta_vs_previous", &delta);
    json_free(&delta);
    json_free(&prev);
    return true;
}

static bool census_report_file_excluded_loc(const struct census_ctx *ctx,
                                            struct json_value *file)
{
    for (size_t r = 0; r < VCS_ZCODE_CENSUS_FILE_REASON_COUNT; r++) {
        uint64_t sum = 0;
        for (size_t s = 0; s < ctx->scope_count; s++)
            if (!zcl_u64_add(sum, ctx->runs[s].result.file_excluded_loc[r],
                             &sum))
                LOG_FAIL(CENSUS_LOG, "file exclusion sum overflow");
        (void)json_push_kv_int(file,
            vcs_zcode_corpus_census_file_reason_string(
                (enum vcs_zcode_corpus_census_file_reason)r),
            (int64_t)sum);
    }
    return true;
}

/* entry-level: driver-side would-be LOC per primary reason. Accumulate in
 * a fixed table and emit each reason EXACTLY once: json_push_kv is
 * append-only and json_get returns the first match, so a former
 * read-modify-push loop emitted ambiguous duplicate keys carrying partial
 * sums. Slots 0..11 are the VCS_ZCODE_C23_EXCLUDE_* bits; slot 12 is
 * "unknown". */
static bool census_report_entry_would_be_loc(const struct census_ctx *ctx,
                                             struct json_value *entry)
{
    uint64_t sums[13] = {0};
    for (size_t s = 0; s < ctx->scope_count; s++) {
        uint32_t mask = ctx->runs[s].result.scope_exclusion_mask;
        if (!mask) continue;
        uint32_t bit = vcs_zcode_corpus_census_primary_exclusion(mask);
        size_t slot = 12;
        if (bit && !(bit & ~VCS_ZCODE_C23_EXCLUSION_MASK)) {
            slot = 0;
            while ((bit & 1u) == 0) {
                bit >>= 1;
                slot++;
            }
        }
        uint64_t would = 0;
        if (!zcl_u64_add(ctx->runs[s].measure.prod_loc,
                         ctx->runs[s].measure.test_loc, &would) ||
            !zcl_u64_add(sums[slot], would, &sums[slot]))
            LOG_FAIL(CENSUS_LOG, "would-be loc overflow");
    }
    for (size_t i = 0; i < 13; i++) {
        if (!sums[i]) continue;
        const char *name =
            i < 12 ? exclusion_name((uint32_t)(UINT64_C(1) << i))
                   : "unknown";
        (void)json_push_kv_int(entry, name, (int64_t)sums[i]);
    }
    return true;
}

static bool census_report_excluded_by_reason(const struct census_ctx *ctx,
                                             struct json_value *report)
{
    struct json_value excluded, file, entry;
    json_init(&excluded);
    json_set_object(&excluded);
    json_init(&file);
    json_set_object(&file);
    if (!census_report_file_excluded_loc(ctx, &file)) return false;
    json_init(&entry);
    json_set_object(&entry);
    if (!census_report_entry_would_be_loc(ctx, &entry)) return false;
    (void)json_push_kv(&excluded, "file_level_semantic_loc", &file);
    (void)json_push_kv(&excluded, "entry_level_would_be_loc", &entry);
    json_free(&file);
    json_free(&entry);
    (void)json_push_kv(report, "excluded_loc_by_reason", &excluded);
    json_free(&excluded);
    return true;
}

static void census_report_scope_package_build(const struct scope_def *def,
                                              const struct scope_run *run,
                                              struct json_value *pobj)
{
    json_init(pobj);
    json_set_object(pobj);
    /* The store LABEL, never the resolved directory: this record is
     * committed. */
    (void)json_push_kv_str(pobj, "store", def->store);
    json_push_root(pobj, "release_id", run->pkg.release_id);
    (void)json_push_kv_str(pobj, "publisher_pubkey", run->pkg.publisher_hex);
    (void)json_push_kv_str(pobj, "reproduction_method", k_repro_receipts);
    struct json_value ids;
    json_init(&ids);
    json_set_array(&ids);
    for (size_t i = 0; i < run->receipt_ids.n; i++)
        json_push_str(&ids, run->receipt_ids.v[i]);
    (void)json_push_kv(pobj, "receipt_ids", &ids);
    json_free(&ids);
}

static void census_report_scope_roots_build(const struct scope_run *run,
                                            struct json_value *roots)
{
    const struct scope_measure *m = &run->measure;
    json_init(roots);
    json_set_object(roots);
    json_push_root(roots, "semantic_lineage_root",
                   run->result.entry.semantic_lineage_root);
    json_push_root(roots, "release_root", m->release_root);
    json_push_root(roots, "passport_root", run->passport_root);
    json_push_root(roots, "proof_root", run->proof_root);
    json_push_root(roots, "source_assignment_root", run->assignment_root);
    json_push_root(roots, "admission_root", run->admission_root);
    json_push_root(roots, "possession_root_report_only", m->possession_root);
}

static void census_report_scope_missing_evidence(uint64_t evidence_mask,
                                                 struct json_value *missing)
{
    json_init(missing);
    json_set_array(missing);
    for (size_t b = 0; b < ARRAY_LEN(k_evidence_bits); b++) {
        if (!(evidence_mask & k_evidence_bits[b].bit))
            json_push_str(missing, k_evidence_bits[b].name);
    }
}

static void census_report_scope_build(const struct census_ctx *ctx,
                                      size_t s, struct json_value *obj)
{
    const struct scope_def *def = &ctx->defs[s];
    const struct scope_run *run = &ctx->runs[s];
    const struct scope_measure *m = &run->measure;
    json_init(obj);
    json_set_object(obj);
    (void)json_push_kv_str(obj, "name", def->name);
    (void)json_push_kv_str(obj, "kind", kind_name(def->kind));
    (void)json_push_kv_str(obj, "spdx", def->spdx);
    (void)json_push_kv_bool(obj, "in_census", run->in_census);
    (void)json_push_kv_bool(obj, "counted",
        (run->result.entry.flags & VCS_ZCODE_C23_ENTRY_COUNTED) != 0);
    (void)json_push_kv_int(obj, "production_loc_would_be",
                           (int64_t)m->prod_loc);
    (void)json_push_kv_int(obj, "test_loc_would_be", (int64_t)m->test_loc);
    (void)json_push_kv_int(obj, "physical_lines",
                           (int64_t)run->result.entry.physical_lines);
    (void)json_push_kv_int(obj, "unique_semantic_units",
                           (int64_t)run->result.entry.unique_semantic_units);
    (void)json_push_kv_int(obj, "units_total",
                           (int64_t)run->result.units_total);
    (void)json_push_kv_int(obj, "units_already_claimed",
                           (int64_t)run->result.units_already_claimed);
    (void)json_push_kv_int(obj, "files_claimed",
                           (int64_t)ctx->files[s].n);
    (void)json_push_kv_int(obj, "files_scanned",
                           (int64_t)run->result.scanned_files);
    (void)json_push_kv_int(obj, "files_excluded",
                           (int64_t)run->result.excluded_files);
    {
        char mask_hex[19];
        (void)snprintf(mask_hex, sizeof(mask_hex), "0x%016" PRIx64,
                       run->evidence_mask);
        (void)json_push_kv_str(obj, "evidence_mask", mask_hex);
    }
    {
        struct json_value missing;
        census_report_scope_missing_evidence(run->evidence_mask, &missing);
        (void)json_push_kv(obj, "missing_evidence", &missing);
        json_free(&missing);
    }
    (void)json_push_kv_int(obj, "exclusion_mask",
                           (int64_t)run->result.scope_exclusion_mask);
    (void)json_push_kv_str(obj, "primary_exclusion",
        exclusion_name(vcs_zcode_corpus_census_primary_exclusion(
            run->result.scope_exclusion_mask)));
    (void)json_push_kv_bool(obj, "possession_suppressed",
                            run->result.possession_suppressed);
    (void)json_push_kv_bool(obj, "reproduced", run->reproduced);
    if (def->is_package) {
        struct json_value pobj;
        census_report_scope_package_build(def, run, &pobj);
        (void)json_push_kv(obj, "package", &pobj);
        json_free(&pobj);
    }
    {
        struct json_value roots;
        census_report_scope_roots_build(run, &roots);
        (void)json_push_kv(obj, "roots", &roots);
        json_free(&roots);
    }
}

static void census_report_scopes_build(const struct census_ctx *ctx,
                                       struct json_value *report)
{
    struct json_value scopes;
    json_init(&scopes);
    json_set_array(&scopes);
    for (size_t s = 0; s < ctx->scope_count; s++) {
        struct json_value obj;
        census_report_scope_build(ctx, s, &obj);
        (void)json_push_back(&scopes, &obj);
        json_free(&obj);
    }
    (void)json_push_kv(report, "scopes", &scopes);
    json_free(&scopes);
}

static void census_report_shards_build(const struct census_ctx *ctx,
                                       struct json_value *report)
{
    struct json_value shards;
    json_init(&shards);
    json_set_array(&shards);
    for (size_t i = 0; i < ctx->shard_count; i++) {
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        (void)json_push_kv_int(&obj, "index", (int64_t)i);
        json_push_root(&obj, "shard_root", ctx->shard_roots[i]);
        json_push_root(&obj, "first_lineage_root",
                       ctx->bindings[i].first_lineage_root);
        json_push_root(&obj, "last_lineage_root",
                       ctx->bindings[i].last_lineage_root);
        (void)json_push_kv_int(&obj, "entry_count",
                               (int64_t)ctx->bindings[i].entry_count);
        (void)json_push_kv_int(&obj, "production_loc",
                               (int64_t)ctx->bindings[i].production_loc);
        (void)json_push_kv_int(&obj, "test_loc",
                               (int64_t)ctx->bindings[i].test_loc);
        (void)json_push_kv_int(&obj, "durable_loc",
                               (int64_t)ctx->bindings[i].durable_loc);
        (void)json_push_kv_int(&obj, "physical_lines",
                               (int64_t)ctx->bindings[i].physical_lines);
        (void)json_push_kv_int(&obj, "unique_semantic_units",
            (int64_t)ctx->bindings[i].unique_semantic_units);
        (void)json_push_kv_int(&obj, "wire_bytes",
                               (int64_t)ctx->shard_wire_lens[i]);
        (void)json_push_back(&shards, &obj);
        json_free(&obj);
    }
    (void)json_push_kv(report, "shards", &shards);
    json_free(&shards);
}

static void census_report_disclosures_build(const struct census_ctx *ctx,
                                            struct json_value *report)
{
    struct json_value disclosures;
    json_init(&disclosures);
    json_set_array(&disclosures);
    json_push_str(&disclosures,
        "founding self-screen admission: every scope's admission is a "
        "self-signed SELF_SCREENED commons_admission.v1 (tier 0); 0 "
        "independent operator groups participated");
    if (ctx->any_repo)
        json_push_str(&disclosures,
            "reproduction binding is dual-worktree source rederivation "
            "(git worktree at HEAD, byte-identical release roots), NOT "
            "independent build reproduction");
    json_push_str(&disclosures,
        "quality bit reflects the operator's --quality-attested flag "
        "(make lint pass state at census time), not an independent "
        "review");
    json_push_str(&disclosures,
        "durable hosting: none yet; possession_root is recorded in "
        "this report only — every entry carries possession_root=0 and "
        "no DURABLE flag (nothing is 5-ACK/3-operator-group durable)");
    json_push_str(&disclosures,
        "simulation-only, not owner-approved; no live ZC23 token "
        "economics");
    json_push_str(&disclosures,
        "source_kind is DECLARED provenance: no per-file authorship "
        "marker exists in-tree, so all scopes are declared human "
        "(pre-existing node code); an overstated kind would be "
        "detectable only by out-of-band review");
    json_push_str(&disclosures,
        "vendor/ and core/ are out of corpus by design (third-party "
        "material and the byte-sealed consensus core)");
    if (ctx->any_package) {
        json_push_str(&disclosures,
            "package scopes: reproduction is the STRONG binding (>= 2 "
            "distinct byte-identical confined build receipts), but the "
            "builds ran on ONE host — independent-operator reproduction "
            "is future work");
        json_push_str(&disclosures,
            "package scopes: the QUALITY bit maps to 'confined "
            "build+test receipt green' (the same receipts evidence as "
            "REPRODUCIBLE), not a human quality review");
        json_push_str(&disclosures,
            "package scopes: the census reads the package store "
            "read-only (no store open, recovery sweep, GC, or "
            "access-count mutation); complete possession is the "
            "chunk-hash-verified full read, DURABLE stays clear");
    }
    (void)json_push_kv(report, "disclosures", &disclosures);
    json_free(&disclosures);
}

bool census_build_kpi_report(const struct census_ctx *ctx,
                             struct json_value *report)
{
    json_init(report);
    json_set_object(report);
    (void)json_push_kv_str(report, "schema", "zcl.c23_corpus_census.report.v1");
    (void)json_push_kv_bool(report, "simulation_only", true);
    (void)json_push_kv_bool(report, "not_owner_approved", true);
    (void)json_push_kv_int(report, "sequence", (int64_t)ctx->args.sequence);
    (void)json_push_kv_str(report, "signer_pubkey", ctx->pubkey_hex);
    json_push_root(report, "checkpoint_root", ctx->checkpoint_root);
    json_push_root(report, "rules_root", ctx->assembly.rules_root);
    json_push_root(report, "family_policy_root", ctx->family_policy_root);
    json_push_root(report, "moderation_set_root", ctx->moderation_set_root);
    (void)json_push_kv_bool(report, "quality_attested",
                            ctx->args.quality_attested);
    (void)json_push_kv_str(report, "reproduction_method", ctx->repro_method);
    {
        struct json_value cutoff;
        json_init(&cutoff);
        json_set_object(&cutoff);
        (void)json_push_kv_int(&cutoff, "height",
                               (int64_t)ctx->args.cutoff_height);
        (void)json_push_kv_int(&cutoff, "mtp", (int64_t)ctx->args.cutoff_mtp);
        (void)json_push_kv(report, "cutoff", &cutoff);
        json_free(&cutoff);
    }
    {
        struct json_value repo;
        json_init(&repo);
        json_set_object(&repo);
        (void)json_push_kv_str(&repo, "head", ctx->head_hex);
        (void)json_push_kv_bool(&repo, "dirty", ctx->repo_dirty);
        (void)json_push_kv(report, "repo", &repo);
        json_free(&repo);
    }
    if (!census_report_kpis_build(ctx, report)) return false;
    if (ctx->args.previous_report &&
        !census_report_growth_delta(ctx, report))
        return false;
    if (!census_report_excluded_by_reason(ctx, report)) return false;
    census_report_scopes_build(ctx, report);
    census_report_shards_build(ctx, report);
    census_report_disclosures_build(ctx, report);
    return true;
}
