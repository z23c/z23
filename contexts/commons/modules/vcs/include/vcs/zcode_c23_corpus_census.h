/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_c23_corpus_census — the PURE census core of the C23 corpus
 * odometer. Given the per-scope source file lists of one deterministic
 * corpus snapshot, it turns each scope into a
 * vcs_zcode_c23_corpus_entry_v1 (vcs/zcode_c23_corpus.h) ready to assemble
 * into the signed shard/checkpoint objects, plus diagnostics explaining
 * every line the odometer refused to count.
 *
 * Same doctrine as package_score: this layer parses caller-supplied bytes
 * and computes. It has no filesystem, network, wallet, build, execution,
 * signature, or node-state authority. The caller owns all I/O (walking
 * trees, reading files, hashing manifests) and every trust decision; the
 * census only applies the frozen counting and exclusion rules. Checkpoint
 * signing stays OUT of this library — the driver signs.
 *
 * Counting model (v1):
 *   - FILES. Each file runs vcs_score_classify_path + vcs_score_scan_file
 *     (the same counting engine the reward surface uses — reward KATs pin
 *     its behavior, so it is reused unmodified). File-level exclusions map
 *     onto the census taxonomy:
 *       extension not .c/.h/.def      -> FILE_UNSUPPORTED  (diagnostic)
 *       vendored path segment          -> FILE_VENDOR       (diagnostic)
 *       generated path/marker          -> FILE_MECHANICAL   (diagnostic)
 *       over VCS_ZCODE_C23_MAX_FILE_BYTES (64 MiB) or content unavailable
 *                                      -> FILE_OVERSIZE     (diagnostic
 *                                         AND entry-level
 *                                         VCS_ZCODE_C23_EXCLUDE_OVERSIZE)
 *     File-level exclusions never exclude the entry by themselves (except
 *     oversize): a real scope legitimately carries vendored/generated
 *     material. Their semantic-line content is measured for the
 *     file_excluded_loc diagnostic only, never counted.
 *   - THE 1 MiB..64 MiB BAND. package_score refuses to scan content over
 *     its own 1 MiB cap. The corpus rules cap is 64 MiB, so a file in the
 *     band is NOT file-excluded here: its physical lines are classified
 *     with vcs_score_classify_lines and counted (production/test LOC and
 *     physical_lines), but it contributes NO semantic units (the unitizer
 *     never sees it — under-crediting units is the safe direction).
 *     The same lines-without-units treatment applies when the unitizer
 *     refuses a file outright because ONE unit exceeds
 *     VCS_SCORE_MAX_UNIT_BYTES (64 KiB) — e.g. a .def DSL file with no
 *     statement terminators, which unitizes as a single statement. The
 *     corpus rules cap files, not units; this is not an exclusion.
 *   - LOC. Counted LOC = semantic lines only; production vs test follows
 *     package_score's path classification. physical_lines = every physical
 *     line of every scanned (non-file-excluded) file.
 *   - UNITS. unique_semantic_units = units unique within the scope AND not
 *     already claimed by an earlier scope. The census keeps one global
 *     claimed-unit set; scopes are processed in the caller's deterministic
 *     order (the caller passes scopes sorted by name). A scope's units are
 *     claimed ONLY when the scope's entry is counted (exclusion_mask == 0):
 *     an excluded scope never credited anything, so it must not poison the
 *     units of a later honest scope. Cross-scope overlap: a scope with
 *     total_units > 0 and (already_claimed * 10000 / total_units) >= 8000
 *     bps is excluded whole with VCS_ZCODE_C23_EXCLUDE_DUPLICATE and its
 *     units are NOT claimed.
 *   - ENTRY-LEVEL EXCLUSIONS (bits combine; use
 *     vcs_zcode_corpus_census_primary_exclusion for the report ordering):
 *       license_spdx off the v1 SPDX allowlist (the
 *         vcs_package_release_license_allowed authority) or zero
 *         license_root                      -> EXCLUDE_LICENSE
 *       zero source_assignment_root         -> EXCLUDE_UNASSIGNED
 *       no test semantic lines, or the
 *         evidence mask lacks RECIPE        -> EXCLUDE_INCOMPLETE
 *       evidence_mask != 0x1ff, zero
 *         passport/proof/admission root, or
 *         an out-of-enum source_kind        -> EXCLUDE_REVIEW_REQUIRED
 *       source_kind mechanical / vendor     -> EXCLUDE_MECHANICAL /
 *                                              EXCLUDE_VENDOR
 *       a file over the 64 MiB census cap,
 *         unavailable content, or a
 *         declared_size/len mismatch        -> EXCLUDE_OVERSIZE
 *       >=80% cross-scope unit overlap      -> EXCLUDE_DUPLICATE
 *     An entry-level exclusion zeroes production_loc/test_loc, drops the
 *     COUNTED flag, and forces the entry non-durable: a passed-in
 *     possession_root is ZEROED in the emitted entry and the suppression
 *     is reported (result.possession_suppressed, plus a WARN log).
 *     physical_lines/unique_semantic_units stay populated as diagnostics,
 *     which the shard validation rules explicitly permit.
 *
 * CANONICAL SEMANTIC LINEAGE ROOT (frozen; this definition is the
 * authority). Let U be the scope's finalized sorted unique-unit list
 * (package_score set order: ascending strcmp of the normalized unit
 * strings). The lineage wire is the concatenation over U of, per unit,
 * its length as u32 little-endian followed by the unit bytes; the wire of
 * an empty U is empty. Then:
 *
 *   semantic_lineage_root = vcs_signed_evidence_root(
 *       "zcl.zcode.c23_corpus.lineage.v1", domain length INCLUDING the
 *       terminating NUL (strlen + 1), wire, wire_len, out)
 *
 * Two scopes whose scorable content unitizes identically collide on this
 * root; assembly fails closed (VCS_ZCODE_C23_ORDER) rather than emitting
 * an ambiguous shard. Distinct-content scopes never collide in practice.
 */

#ifndef ZCL_VCS_ZCODE_C23_CORPUS_CENSUS_H
#define ZCL_VCS_ZCODE_C23_CORPUS_CENSUS_H

#include "vcs/package_score.h"
#include "vcs/zcode_c23_corpus.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_C23_CORPUS_LINEAGE_V1_DOMAIN \
    "zcl.zcode.c23_corpus.lineage.v1"

/* Closed file-level exclusion taxonomy (diagnostic only; see the header
 * comment for the mapping). Indexes file_excluded_loc in the result. */
enum vcs_zcode_corpus_census_file_reason {
    VCS_ZCODE_CENSUS_FILE_UNSUPPORTED = 0, /* extension not .c/.h/.def */
    VCS_ZCODE_CENSUS_FILE_VENDOR,          /* vendored path segment */
    VCS_ZCODE_CENSUS_FILE_MECHANICAL,      /* generated path or marker */
    VCS_ZCODE_CENSUS_FILE_OVERSIZE,        /* >64 MiB / content unavailable */
    VCS_ZCODE_CENSUS_FILE_REASON_COUNT
};

const char *vcs_zcode_corpus_census_file_reason_string(
    enum vcs_zcode_corpus_census_file_reason reason);

struct vcs_zcode_corpus_census_file {   /* one input file */
    const char *path;            /* scope-relative canonical path */
    const uint8_t *bytes;        /* exact content; NULL only if over cap */
    size_t len;
    uint64_t declared_size;
};

struct vcs_zcode_corpus_census_scope_input {
    const char *name;                     /* e.g. "zclassic23/base" */
    uint16_t source_kind;                 /* enum vcs_zcode_source_kind_v1 */
    const char *license_spdx;             /* e.g. "Apache-2.0"; NULL/empty = unsupported */
    uint8_t license_root[32];             /* content root of license text (caller-computed; zero if none) */
    uint64_t evidence_mask;               /* evidence bits the caller can honestly bind */
    uint8_t release_root[32];             /* caller-computed content root of the scope's manifest */
    uint8_t passport_root[32];            /* zero if unavailable */
    uint8_t proof_root[32];               /* zero if unavailable */
    uint8_t source_assignment_root[32];   /* root of a signed vcs_zcode_source_assignment_v1 the caller created; zero = unassigned */
    uint8_t admission_root[32];           /* zero if unavailable */
    uint8_t possession_root[32];          /* nonzero only if complete CAS possession was verified */
    uint64_t release_sequence;            /* >= 1 */
    const struct vcs_zcode_corpus_census_file *files;
    size_t file_count;
};

struct vcs_zcode_corpus_census_scope_result {
    struct vcs_zcode_c23_corpus_entry_v1 entry;   /* filled, unsigned-object-level */
    /* diagnostics */
    /* semantic lines lost per file-level reason (best-effort: measured by
     * classifying the excluded file's lines when its bytes are available,
     * else 0 — the content was never owed to the corpus) */
    uint64_t file_excluded_loc[VCS_ZCODE_CENSUS_FILE_REASON_COUNT];
    uint64_t scanned_files, excluded_files;
    uint64_t units_total;            /* distinct units in the scope */
    uint64_t units_already_claimed;  /* of units_total, claimed by earlier scopes */
    uint32_t scope_exclusion_mask;   /* entry-level */
    bool overlap_duplicate;          /* >=80% of its units already claimed */
    bool possession_suppressed;      /* caller's possession_root was zeroed */
};

/* Census state: one global claimed-unit set across scopes. Transparent
 * (package_score convention); init/free only. Between process_scope calls
 * claimed_units is always finalized. */
struct vcs_zcode_corpus_census {
    struct vcs_score_set claimed_units;
    uint64_t scopes_processed;
};

void vcs_zcode_corpus_census_init(struct vcs_zcode_corpus_census *census);
void vcs_zcode_corpus_census_free(struct vcs_zcode_corpus_census *census);

/* Process one scope into a corpus entry. False only on a caller-contract
 * violation (NULLs, zero release_sequence, zero release_root) or an
 * allocation/overflow failure — every such return logs context. Every
 * content problem is an exclusion named in the result, never a hard
 * error. `out` is fully overwritten. */
bool vcs_zcode_corpus_census_process_scope(
    struct vcs_zcode_corpus_census *census,
    const struct vcs_zcode_corpus_census_scope_input *input,
    struct vcs_zcode_corpus_census_scope_result *out);

/* The first exclusion bit in the canonical reporting order (LICENSE,
 * UNASSIGNED, INCOMPLETE, REVIEW_REQUIRED, MECHANICAL, VENDOR, OVERSIZE,
 * DUPLICATE, then any remaining mask bit). 0 when mask is 0. */
uint32_t vcs_zcode_corpus_census_primary_exclusion(uint32_t exclusion_mask);

/* Assembly output: the sorted entries (owned), the filled shard struct
 * (borrowing them), the default rules root, and aggregate totals suitable
 * for filling a checkpoint binding. Totals sum the emitted entry fields
 * over ALL entries — excluded entries contribute zero production/test LOC
 * but do contribute their diagnostic physical_lines/unique_semantic_units,
 * so a verifier can recompute every total from the shard alone.
 * durable_loc sums production+test of DURABLE entries only. */
struct vcs_zcode_corpus_census_assembly {
    struct vcs_zcode_c23_corpus_shard_v1 shard;
    struct vcs_zcode_c23_corpus_entry_v1 *entries; /* owned sorted copy */
    size_t entry_count;
    uint8_t rules_root[32];
    uint64_t total_entries;
    uint64_t excluded_entries;
    uint64_t production_loc;
    uint64_t test_loc;
    uint64_t durable_loc;
    uint64_t physical_lines;
    uint64_t unique_semantic_units;
};

/* Sort the per-scope entries by semantic_lineage_root (strictly
 * ascending; identical roots fail closed with VCS_ZCODE_C23_ORDER) and
 * fill the shard with the default rules root plus the caller's
 * family/moderation roots (both must be nonzero). The assembled shard is
 * validated with vcs_zcode_c23_corpus_shard_v1_validate before returning
 * — a census that cannot emit a valid shard returns the validation error
 * instead. Every error return logs context. result_count must be
 * 1..VCS_ZCODE_C23_SHARD_ENTRY_MAX (the driver shards larger corpora). */
enum vcs_zcode_c23_error vcs_zcode_corpus_census_assemble(
    const struct vcs_zcode_corpus_census_scope_result *results,
    size_t result_count,
    const uint8_t family_policy_root[32],
    const uint8_t moderation_set_root[32],
    struct vcs_zcode_corpus_census_assembly *out);

void vcs_zcode_corpus_census_assembly_free(
    struct vcs_zcode_corpus_census_assembly *assembly);

#endif /* ZCL_VCS_ZCODE_C23_CORPUS_CENSUS_H */
