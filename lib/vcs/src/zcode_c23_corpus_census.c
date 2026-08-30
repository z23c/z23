/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: pure census core of the C23 corpus odometer (see header). */

#include "vcs/zcode_c23_corpus_census.h"

#include "base/bytes.h"
#include "base/checked.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "vcs/package_release.h"
#include "vcs/signed_evidence.h"

#include <stdlib.h>
#include <string.h>

#define CENSUS_LOG "vcs.census"

const char *vcs_zcode_corpus_census_file_reason_string(
    enum vcs_zcode_corpus_census_file_reason reason)
{
    switch (reason) {
    case VCS_ZCODE_CENSUS_FILE_UNSUPPORTED: return "unsupported";
    case VCS_ZCODE_CENSUS_FILE_VENDOR: return "vendor";
    case VCS_ZCODE_CENSUS_FILE_MECHANICAL: return "mechanical";
    case VCS_ZCODE_CENSUS_FILE_OVERSIZE: return "oversize";
    case VCS_ZCODE_CENSUS_FILE_REASON_COUNT: break;
    }
    return "unknown";
}

void vcs_zcode_corpus_census_init(struct vcs_zcode_corpus_census *census)
{
    if (!census) return;
    memset(census, 0, sizeof(*census));
    vcs_score_set_init(&census->claimed_units);
    vcs_score_set_finalize(&census->claimed_units);
}

void vcs_zcode_corpus_census_free(struct vcs_zcode_corpus_census *census)
{
    if (!census) return;
    vcs_score_set_free(&census->claimed_units);
    memset(census, 0, sizeof(*census));
}

/* Diagnostic line tally for a file the census refused to count. */
static void record_excluded_file(
    struct vcs_zcode_corpus_census_scope_result *out,
    enum vcs_zcode_corpus_census_file_reason reason,
    const struct vcs_zcode_corpus_census_file *file)
{
    out->excluded_files++;
    if (file->bytes && file->len > 0) {
        struct vcs_score_line_tally tally;
        memset(&tally, 0, sizeof(tally));
        vcs_score_classify_lines(file->bytes, file->len, &tally);
        uint64_t sum = 0;
        if (zcl_u64_add(out->file_excluded_loc[reason], tally.semantic,
                        &sum))
            out->file_excluded_loc[reason] = sum;
    }
}

/* Add one tally class sum into a running total (checked). */
static bool tally_add(uint64_t *dst, uint32_t value)
{
    return zcl_u64_add(*dst, value, dst);
}

/* Count a file's classified lines without unitizing it: physical lines
 * plus production/test semantic LOC, no units. Shared by the 1 MiB..64 MiB
 * band and by files the unitizer refuses (one unit over package_score's
 * 64 KiB cap — e.g. a .def DSL file with no statement terminators, which
 * unitizes as a single statement). Under-crediting units is the safe
 * direction; the corpus rules cap FILES, not units. */
static bool count_lines_without_units(
    const struct vcs_zcode_corpus_census_file *file,
    enum vcs_score_file_kind path_kind, const char *scope_name,
    uint64_t *production, uint64_t *tests, uint64_t *physical)
{
    struct vcs_score_line_tally tally;
    memset(&tally, 0, sizeof(tally));
    vcs_score_classify_lines(file->bytes, file->len, &tally);
    if (!(tally_add(physical, tally.semantic) &&
          tally_add(physical, tally.blank) &&
          tally_add(physical, tally.comment_only) &&
          tally_add(physical, tally.brace_only) &&
          tally_add(path_kind == VCS_SCORE_FILE_TEST ? tests : production,
                    tally.semantic)))
        LOG_FAIL(CENSUS_LOG, "scope %s tally overflow on %s", scope_name,
                 file->path);
    return true;
}

/* The canonical semantic lineage root: sha3(domain-with-NUL || wire) where
 * wire is the scope's finalized sorted units, each as u32-LE length ||
 * bytes. See the header for the frozen definition. */
static bool lineage_root(const struct vcs_score_set *scope_units,
                         const char *scope_name, uint8_t out[32])
{
    size_t wire_len = 0;
    for (size_t i = 0; i < scope_units->count; i++) {
        size_t unit_len = strlen(scope_units->items[i]);
        if (!zcl_size_add(wire_len, 4u, &wire_len) ||
            !zcl_size_add(wire_len, unit_len, &wire_len))
            LOG_FAIL(CENSUS_LOG, "scope %s lineage wire size overflow",
                     scope_name);
    }
    uint8_t *wire = NULL;
    if (wire_len > 0) {
        wire = zcl_malloc(wire_len, "census_lineage_wire");
        if (!wire)
            LOG_FAIL(CENSUS_LOG, "scope %s lineage wire alloc %zu",
                     scope_name, wire_len);
        size_t off = 0;
        for (size_t i = 0; i < scope_units->count; i++) {
            size_t unit_len = strlen(scope_units->items[i]);
            zcl_write_u32_le(wire + off, (uint32_t)unit_len);
            off += 4;
            memcpy(wire + off, scope_units->items[i], unit_len);
            off += unit_len;
        }
    }
    static const char domain[] = VCS_ZCODE_C23_CORPUS_LINEAGE_V1_DOMAIN;
    bool ok = vcs_signed_evidence_root(domain, sizeof(domain),
                                       wire, wire_len, out);
    free(wire);
    if (!ok)
        LOG_FAIL(CENSUS_LOG, "scope %s lineage root failed", scope_name);
    return true;
}

bool vcs_zcode_corpus_census_process_scope(
    struct vcs_zcode_corpus_census *census,
    const struct vcs_zcode_corpus_census_scope_input *input,
    struct vcs_zcode_corpus_census_scope_result *out)
{
    GUARD_NOT_NULL(census, CENSUS_LOG, "census");
    GUARD_NOT_NULL(input, CENSUS_LOG, "input");
    GUARD_NOT_NULL(out, CENSUS_LOG, "out");
    memset(out, 0, sizeof(*out));
    GUARD_NOT_NULL(input->name, CENSUS_LOG, "input->name");
    if (input->file_count > 0)
        GUARD_NOT_NULL(input->files, CENSUS_LOG, "input->files");
    if (!input->release_sequence)
        LOG_FAIL(CENSUS_LOG, "scope %s release_sequence is 0", input->name);
    if (!zcl_bytes_any_set(input->release_root, 32))
        LOG_FAIL(CENSUS_LOG, "scope %s release_root is all-zero",
                 input->name);

    uint64_t production = 0, tests = 0, physical = 0;
    bool oversize_seen = false;
    struct vcs_score_set scope_units;
    vcs_score_set_init(&scope_units);

    for (size_t i = 0; i < input->file_count; i++) {
        const struct vcs_zcode_corpus_census_file *file = &input->files[i];
        if (!file->path) {
            vcs_score_set_free(&scope_units);
            LOG_FAIL(CENSUS_LOG, "scope %s file %zu has no path",
                     input->name, i);
        }
        enum vcs_score_exclude_reason path_reason = VCS_SCORE_EXCLUDE_NONE;
        enum vcs_score_file_kind path_kind =
            vcs_score_classify_path(file->path, &path_reason);

        /* Content the census cannot trust or must refuse outright: over
         * the 64 MiB corpus cap, unavailable, or a manifest/length
         * mismatch. File-level oversize is ALSO an entry-level exclusion
         * (the scope violates the corpus rules). */
        if (!file->bytes ||
            file->declared_size > VCS_ZCODE_C23_MAX_FILE_BYTES ||
            (uint64_t)file->len != file->declared_size) {
            if (file->bytes && (uint64_t)file->len != file->declared_size)
                LOG_WARN(CENSUS_LOG,
                         "scope %s file %s len %zu != declared %llu; "
                         "failing closed",
                         input->name, file->path, file->len,
                         (unsigned long long)file->declared_size);
            oversize_seen = true;
            record_excluded_file(out, VCS_ZCODE_CENSUS_FILE_OVERSIZE, file);
            continue;
        }

        if (path_kind == VCS_SCORE_FILE_EXCLUDED) {
            enum vcs_zcode_corpus_census_file_reason reason =
                VCS_ZCODE_CENSUS_FILE_UNSUPPORTED;
            if (path_reason == VCS_SCORE_EXCLUDE_VENDORED)
                reason = VCS_ZCODE_CENSUS_FILE_VENDOR;
            else if (path_reason == VCS_SCORE_EXCLUDE_GENERATED_PATH)
                reason = VCS_ZCODE_CENSUS_FILE_MECHANICAL;
            record_excluded_file(out, reason, file);
            continue;
        }

        struct vcs_score_file_scan scan;
        if (!vcs_score_scan_file(file->path, file->bytes, file->len,
                                 &scan)) {
            /* The unitizer refused the content: one unit over
             * VCS_SCORE_MAX_UNIT_BYTES (64 KiB) — a .def DSL file with no
             * statement terminators unitizes as ONE statement. The corpus
             * rules cap files, not units, so this is NOT an exclusion:
             * count its classified lines and credit no units, exactly
             * like the 1 MiB..64 MiB band below. (A true allocation
             * failure also lands here; the allocator has already logged
             * it, and the no-units outcome stays the safe direction.) */
            if (!count_lines_without_units(file, path_kind, input->name,
                                           &production, &tests,
                                           &physical)) {
                vcs_score_set_free(&scope_units);
                return false;
            }
            out->scanned_files++;
            continue;
        }
        if (scan.kind == VCS_SCORE_FILE_EXCLUDED &&
            scan.reason == VCS_SCORE_EXCLUDE_OVERSIZE) {
            /* The 1 MiB..64 MiB band: package_score refuses the content,
             * the corpus rules do not. Count the physical lines via
             * classification; the unitizer never sees the file. */
            if (!count_lines_without_units(file, path_kind, input->name,
                                           &production, &tests,
                                           &physical)) {
                vcs_score_set_free(&scope_units);
                vcs_score_file_scan_free(&scan);
                return false;
            }
            out->scanned_files++;
            vcs_score_file_scan_free(&scan);
            continue;
        }
        if (scan.kind == VCS_SCORE_FILE_EXCLUDED) {
            /* scan-level exclusion: the generated marker. */
            record_excluded_file(out, VCS_ZCODE_CENSUS_FILE_MECHANICAL,
                                 file);
            vcs_score_file_scan_free(&scan);
            continue;
        }

        bool ok = tally_add(&physical, scan.lines.semantic) &&
                  tally_add(&physical, scan.lines.blank) &&
                  tally_add(&physical, scan.lines.comment_only) &&
                  tally_add(&physical, scan.lines.brace_only) &&
                  tally_add(scan.kind == VCS_SCORE_FILE_TEST
                                ? &tests : &production,
                            scan.lines.semantic);
        for (size_t u = 0; ok && u < scan.units.count; u++)
            ok = vcs_score_set_add(&scope_units, scan.units.items[u],
                                   strlen(scan.units.items[u]));
        out->scanned_files++;
        vcs_score_file_scan_free(&scan);
        if (!ok) {
            vcs_score_set_free(&scope_units);
            LOG_FAIL(CENSUS_LOG, "scope %s tally/unit failure on %s",
                     input->name, file->path);
        }
    }
    vcs_score_set_finalize(&scope_units);

    /* Cross-scope overlap against the global claimed set. */
    uint64_t total_units = scope_units.count;
    uint64_t already = 0;
    for (size_t i = 0; i < scope_units.count; i++) {
        if (vcs_score_set_contains(&census->claimed_units,
                                   scope_units.items[i],
                                   strlen(scope_units.items[i])) &&
            !zcl_u64_add(already, 1, &already)) {
            vcs_score_set_free(&scope_units);
            LOG_FAIL(CENSUS_LOG, "scope %s overlap count overflow",
                     input->name);
        }
    }
    bool overlap_duplicate = false;
    if (total_units > 0) {
        uint64_t lhs = 0, rhs = 0;
        if (!zcl_u64_mul(already, 10000u, &lhs) ||
            !zcl_u64_mul(total_units,
                         VCS_ZCODE_C23_OVERLAP_THRESHOLD_BPS, &rhs)) {
            vcs_score_set_free(&scope_units);
            LOG_FAIL(CENSUS_LOG, "scope %s overlap ratio overflow",
                     input->name);
        }
        overlap_duplicate = lhs >= rhs;
    }

    /* Entry-level exclusions (the header names the canonical order). */
    uint32_t mask = 0;
    if (!vcs_package_release_license_allowed(input->license_spdx) ||
        !zcl_bytes_any_set(input->license_root, 32))
        mask |= VCS_ZCODE_C23_EXCLUDE_LICENSE;
    if (!zcl_bytes_any_set(input->source_assignment_root, 32))
        mask |= VCS_ZCODE_C23_EXCLUDE_UNASSIGNED;
    if (tests == 0 ||
        !(input->evidence_mask & VCS_ZCODE_C23_EVIDENCE_RECIPE))
        mask |= VCS_ZCODE_C23_EXCLUDE_INCOMPLETE;
    if (input->evidence_mask != VCS_ZCODE_C23_EVIDENCE_REQUIRED_MASK ||
        !zcl_bytes_any_set(input->passport_root, 32) ||
        !zcl_bytes_any_set(input->proof_root, 32) ||
        !zcl_bytes_any_set(input->admission_root, 32))
        mask |= VCS_ZCODE_C23_EXCLUDE_REVIEW_REQUIRED;
    if (input->source_kind == VCS_ZCODE_SOURCE_MECHANICAL_GENERATION)
        mask |= VCS_ZCODE_C23_EXCLUDE_MECHANICAL;
    else if (input->source_kind == VCS_ZCODE_SOURCE_VENDOR_MATERIAL)
        mask |= VCS_ZCODE_C23_EXCLUDE_VENDOR;
    else if (!vcs_zcode_source_kind_counts_v1(input->source_kind))
        mask |= VCS_ZCODE_C23_EXCLUDE_REVIEW_REQUIRED;
    if (oversize_seen)
        mask |= VCS_ZCODE_C23_EXCLUDE_OVERSIZE;
    if (overlap_duplicate)
        mask |= VCS_ZCODE_C23_EXCLUDE_DUPLICATE;

    /* Fill the entry. */
    struct vcs_zcode_c23_corpus_entry_v1 *entry = &out->entry;
    memcpy(entry->release_root, input->release_root, 32);
    memcpy(entry->passport_root, input->passport_root, 32);
    memcpy(entry->proof_root, input->proof_root, 32);
    memcpy(entry->source_assignment_root, input->source_assignment_root,
           32);
    memcpy(entry->admission_root, input->admission_root, 32);
    entry->release_sequence = input->release_sequence;
    entry->physical_lines = physical;
    entry->unique_semantic_units = total_units - already;
    entry->evidence_mask = input->evidence_mask;
    entry->exclusion_mask = mask;
    if (mask == 0) {
        entry->production_loc = production;
        entry->test_loc = tests;
        entry->flags = VCS_ZCODE_C23_ENTRY_COUNTED;
        if (zcl_bytes_any_set(input->possession_root, 32)) {
            memcpy(entry->possession_root, input->possession_root, 32);
            entry->flags |= VCS_ZCODE_C23_ENTRY_DURABLE;
        }
        /* Counted scopes claim their units (duplicates dedup on
         * finalize); excluded scopes claim nothing. */
        bool ok = true;
        for (size_t i = 0; ok && i < scope_units.count; i++)
            ok = vcs_score_set_add(&census->claimed_units,
                                   scope_units.items[i],
                                   strlen(scope_units.items[i]));
        if (!ok) {
            vcs_score_set_free(&scope_units);
            LOG_FAIL(CENSUS_LOG, "scope %s failed to claim units",
                     input->name);
        }
        vcs_score_set_finalize(&census->claimed_units);
    } else if (zcl_bytes_any_set(input->possession_root, 32)) {
        out->possession_suppressed = true;
        LOG_WARN(CENSUS_LOG,
                 "scope %s excluded (mask 0x%x): suppressing possession "
                 "root and durability", input->name, mask);
    }

    bool ok = lineage_root(&scope_units, input->name,
                           entry->semantic_lineage_root);
    vcs_score_set_free(&scope_units);
    if (!ok)
        return false;

    out->units_total = total_units;
    out->units_already_claimed = already;
    out->scope_exclusion_mask = mask;
    out->overlap_duplicate = overlap_duplicate;
    if (!zcl_u64_add(census->scopes_processed, 1,
                     &census->scopes_processed))
        LOG_FAIL(CENSUS_LOG, "scopes_processed overflow");
    return true;
}

uint32_t vcs_zcode_corpus_census_primary_exclusion(uint32_t exclusion_mask)
{
    static const uint32_t priority[] = {
        VCS_ZCODE_C23_EXCLUDE_LICENSE,
        VCS_ZCODE_C23_EXCLUDE_UNASSIGNED,
        VCS_ZCODE_C23_EXCLUDE_INCOMPLETE,
        VCS_ZCODE_C23_EXCLUDE_REVIEW_REQUIRED,
        VCS_ZCODE_C23_EXCLUDE_MECHANICAL,
        VCS_ZCODE_C23_EXCLUDE_VENDOR,
        VCS_ZCODE_C23_EXCLUDE_OVERSIZE,
        VCS_ZCODE_C23_EXCLUDE_DUPLICATE,
    };
    for (size_t i = 0; i < sizeof(priority) / sizeof(priority[0]); i++)
        if (exclusion_mask & priority[i])
            return priority[i];
    return exclusion_mask & VCS_ZCODE_C23_EXCLUSION_MASK;
}

static int entry_lineage_cmp(const void *a, const void *b)
{
    const struct vcs_zcode_c23_corpus_entry_v1 *ea = a;
    const struct vcs_zcode_c23_corpus_entry_v1 *eb = b;
    return memcmp(ea->semantic_lineage_root, eb->semantic_lineage_root,
                  32);
}

enum vcs_zcode_c23_error vcs_zcode_corpus_census_assemble(
    const struct vcs_zcode_corpus_census_scope_result *results,
    size_t result_count,
    const uint8_t family_policy_root[32],
    const uint8_t moderation_set_root[32],
    struct vcs_zcode_corpus_census_assembly *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!results || !family_policy_root || !moderation_set_root || !out)
        LOG_RETURN(VCS_ZCODE_C23_NULL, CENSUS_LOG,
                   "null argument to census assemble");
    if (!result_count || result_count > VCS_ZCODE_C23_SHARD_ENTRY_MAX)
        LOG_RETURN(VCS_ZCODE_C23_SIZE, CENSUS_LOG,
                   "entry count %zu outside 1..%u", result_count,
                   VCS_ZCODE_C23_SHARD_ENTRY_MAX);
    if (!zcl_bytes_any_set(family_policy_root, 32) ||
        !zcl_bytes_any_set(moderation_set_root, 32))
        LOG_RETURN(VCS_ZCODE_C23_ROOT, CENSUS_LOG,
                   "family/moderation root all-zero");

    size_t bytes = 0;
    if (!zcl_size_mul(result_count,
                      sizeof(struct vcs_zcode_c23_corpus_entry_v1), &bytes))
        LOG_RETURN(VCS_ZCODE_C23_OVERFLOW, CENSUS_LOG,
                   "entry array size overflow");
    struct vcs_zcode_c23_corpus_entry_v1 *entries =
        zcl_malloc(bytes, "census_entries");
    if (!entries)
        LOG_RETURN(VCS_ZCODE_C23_OVERFLOW, CENSUS_LOG,
                   "entry array alloc %zu", bytes);
    for (size_t i = 0; i < result_count; i++)
        entries[i] = results[i].entry;
    qsort(entries, result_count, sizeof(*entries), entry_lineage_cmp);
    for (size_t i = 1; i < result_count; i++) {
        if (memcmp(entries[i - 1u].semantic_lineage_root,
                   entries[i].semantic_lineage_root, 32) == 0) {
            free(entries);
            LOG_RETURN(VCS_ZCODE_C23_ORDER, CENSUS_LOG,
                       "scopes %zu/%zu collide on semantic lineage root; "
                       "failing closed", i - 1u, i);
        }
    }

    uint64_t production = 0, tests = 0, durable = 0, physical = 0;
    uint64_t unique = 0, excluded = 0;
    for (size_t i = 0; i < result_count; i++) {
        const struct vcs_zcode_c23_corpus_entry_v1 *entry = &entries[i];
        uint64_t entry_loc = 0;
        bool ok = zcl_u64_add(entry->production_loc, entry->test_loc,
                              &entry_loc) &&
                  zcl_u64_add(production, entry->production_loc,
                              &production) &&
                  zcl_u64_add(tests, entry->test_loc, &tests) &&
                  zcl_u64_add(physical, entry->physical_lines, &physical) &&
                  zcl_u64_add(unique, entry->unique_semantic_units,
                              &unique);
        if (ok && (entry->flags & VCS_ZCODE_C23_ENTRY_DURABLE))
            ok = zcl_u64_add(durable, entry_loc, &durable);
        if (ok && entry->exclusion_mask != 0)
            ok = zcl_u64_add(excluded, 1, &excluded);
        if (!ok) {
            free(entries);
            LOG_RETURN(VCS_ZCODE_C23_OVERFLOW, CENSUS_LOG,
                       "aggregate total overflow at entry %zu", i);
        }
    }

    struct vcs_zcode_c23_corpus_rules_v1 rules;
    vcs_zcode_c23_corpus_rules_v1_default(&rules);
    enum vcs_zcode_c23_error error =
        vcs_zcode_c23_corpus_rules_v1_root(&rules, out->rules_root);
    if (error != VCS_ZCODE_C23_OK) {
        free(entries);
        LOG_RETURN(error, CENSUS_LOG, "default rules root failed: %s",
                   vcs_zcode_c23_error_string(error));
    }

    out->shard.schema_version = 1;
    out->shard.flags = VCS_ZCODE_C23_CORPUS_REQUIRED_FLAGS;
    memcpy(out->shard.rules_root, out->rules_root, 32);
    memcpy(out->shard.family_policy_root, family_policy_root, 32);
    memcpy(out->shard.moderation_set_root, moderation_set_root, 32);
    out->shard.entries = entries;
    out->shard.entry_count = result_count;
    out->entries = entries;
    out->entry_count = result_count;
    out->total_entries = result_count;
    out->excluded_entries = excluded;
    out->production_loc = production;
    out->test_loc = tests;
    out->durable_loc = durable;
    out->physical_lines = physical;
    out->unique_semantic_units = unique;

    error = vcs_zcode_c23_corpus_shard_v1_validate(&out->shard);
    if (error != VCS_ZCODE_C23_OK) {
        vcs_zcode_corpus_census_assembly_free(out);
        LOG_RETURN(error, CENSUS_LOG,
                   "assembled shard failed self-validation: %s",
                   vcs_zcode_c23_error_string(error));
    }
    return VCS_ZCODE_C23_OK;
}

void vcs_zcode_corpus_census_assembly_free(
    struct vcs_zcode_corpus_census_assembly *assembly)
{
    if (!assembly) return;
    free(assembly->entries);
    memset(assembly, 0, sizeof(*assembly));
}
