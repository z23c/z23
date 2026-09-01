/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_science_index — the local ZCODE scientific-study/evidence search
 * index. This is a REBUILDABLE PROJECTION over the workspace CAS
 * (<repo_root>/.zvcs/objects): the persisted study_spec.v1,
 * benchmark_result.v2, reproduction.v1, science_findings.v1,
 * curation_vote.v1, and review.v1 wires stay authoritative and this index
 * holds no truth of its own — like zcode_task_index, it is rebuilt from the
 * canonical objects on every build and may be discarded at any time.
 *
 * An entry projects one persisted wire whose parse, structural validation,
 * and rederived root all succeed and whose root equals its CAS address (the
 * object file name). Objects of any other size or magic are other CAS
 * citizens and are skipped unread; a file carrying a science magic that
 * fails parse/validation/root agreement is logged and skipped — a forged or
 * misplaced file cannot enter the projection. Entries are sorted by root
 * hex for deterministic output.
 *
 * Read-only: the index never writes to the CAS and never verifies vote
 * signatures against a network identity (the vote service owns those); it
 * re-runs structural validation only. Expiry NEVER erases history: expired
 * studies keep their evidence; expired votes are flagged, not dropped. */

#ifndef ZCL_VCS_ZCODE_SCIENCE_INDEX_H
#define ZCL_VCS_ZCODE_SCIENCE_INDEX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_SCIENCE_INDEX_MAX_STUDIES 1024u
#define VCS_ZCODE_SCIENCE_INDEX_MAX_RESULTS 4096u
#define VCS_ZCODE_SCIENCE_INDEX_MAX_REPRODUCTIONS 4096u
#define VCS_ZCODE_SCIENCE_INDEX_MAX_FINDINGS 4096u
#define VCS_ZCODE_SCIENCE_INDEX_MAX_VOTES 4096u
#define VCS_ZCODE_SCIENCE_INDEX_MAX_REVIEWS 4096u

struct vcs_zcode_science_index_study_entry {
    char study_root_hex[65];
    char hypothesis_root_hex[65];
    char null_hypothesis_root_hex[65];
    char source_root_hex[65];
    uint16_t required_reproductions;
    uint16_t required_reviews;
    uint64_t sequence;
    int64_t created_unix;
    int64_t expires_unix;
    bool expired;   /* at the build's now_unix */
    bool retracted; /* a retraction findings targets this study root */
    uint32_t result_count;
    uint32_t reproduction_count;
    uint32_t findings_count;
    uint32_t review_count;
};

struct vcs_zcode_science_index_result_entry {
    char result_root_hex[65];
    char study_root_hex[65];
    char task_root_hex[65];
    char candidate_root_hex[65];
    char action_root_hex[65];
    char method_root_hex[65];
    char hardware_profile_root_hex[65];
    uint8_t status; /* enum vcs_zcode_benchmark_status */
    bool retracted; /* a retraction findings targets this result root */
    uint64_t sequence;
    int64_t started_unix;
    int64_t finished_unix;
};

struct vcs_zcode_science_index_reproduction_entry {
    char reproduction_root_hex[65];
    char study_root_hex[65];
    char original_result_root_hex[65];
    char reproduced_result_root_hex[65];
    char reproducer_pubkey_hex[65];
    uint8_t verdict; /* enum vcs_zcode_reproduction_verdict */
    uint64_t sequence;
    int64_t created_unix;
};

struct vcs_zcode_science_index_findings_entry {
    char findings_root_hex[65];
    char study_root_hex[65];
    char result_root_hex[65];
    char retraction_target_root_hex[65];
    uint16_t flags; /* enum vcs_zcode_science_finding_flag bits */
    uint8_t severity;
    uint64_t sequence;
    int64_t created_unix;
};

struct vcs_zcode_science_index_vote_entry {
    char vote_id_hex[65];
    char voter_zid_root_hex[65];
    char property_root_hex[65];
    char signer_pubkey_hex[65];
    uint8_t signal; /* enum vcs_zcode_curation_signal */
    uint64_t sequence;
    int64_t expires_unix;
    bool expired; /* at the build's now_unix */
};

struct vcs_zcode_science_index_review_entry {
    char review_root_hex[65];
    char findings_root_hex[65];
    char reviewer_pubkey_hex[65];
    uint8_t verdict;
    uint64_t sequence;
    int64_t created_unix;
};

struct vcs_zcode_science_index; /* opaque */

/* Build the projection from repo_root's workspace CAS. A missing/empty
 * object store yields an empty index. NULL on hard allocation failure
 * (logged). now_unix drives the expired flags only. */
struct vcs_zcode_science_index *vcs_zcode_science_index_build(
    const char *repo_root, int64_t now_unix);
void vcs_zcode_science_index_free(struct vcs_zcode_science_index *index);

size_t vcs_zcode_science_index_study_count(
    const struct vcs_zcode_science_index *index);
const struct vcs_zcode_science_index_study_entry *
vcs_zcode_science_index_study_at(
    const struct vcs_zcode_science_index *index, size_t i);
/* Look up one study entry by study root (32 bytes). NULL when absent. */
const struct vcs_zcode_science_index_study_entry *
vcs_zcode_science_index_find_study(
    const struct vcs_zcode_science_index *index, const uint8_t study_root[32]);

size_t vcs_zcode_science_index_result_count(
    const struct vcs_zcode_science_index *index);
const struct vcs_zcode_science_index_result_entry *
vcs_zcode_science_index_result_at(
    const struct vcs_zcode_science_index *index, size_t i);
const struct vcs_zcode_science_index_result_entry *
vcs_zcode_science_index_find_result(
    const struct vcs_zcode_science_index *index,
    const uint8_t result_root[32]);

size_t vcs_zcode_science_index_reproduction_count(
    const struct vcs_zcode_science_index *index);
const struct vcs_zcode_science_index_reproduction_entry *
vcs_zcode_science_index_reproduction_at(
    const struct vcs_zcode_science_index *index, size_t i);

size_t vcs_zcode_science_index_findings_count(
    const struct vcs_zcode_science_index *index);
const struct vcs_zcode_science_index_findings_entry *
vcs_zcode_science_index_findings_at(
    const struct vcs_zcode_science_index *index, size_t i);
const struct vcs_zcode_science_index_findings_entry *
vcs_zcode_science_index_find_findings(
    const struct vcs_zcode_science_index *index,
    const uint8_t findings_root[32]);

size_t vcs_zcode_science_index_vote_count(
    const struct vcs_zcode_science_index *index);
const struct vcs_zcode_science_index_vote_entry *
vcs_zcode_science_index_vote_at(
    const struct vcs_zcode_science_index *index, size_t i);
/* Look up one vote entry by its canonical vote id (32 bytes). */
const struct vcs_zcode_science_index_vote_entry *
vcs_zcode_science_index_find_vote(
    const struct vcs_zcode_science_index *index, const uint8_t vote_id[32]);
/* True when a DIFFERENT vote id already carries this voter+sequence — the
 * replay shape the projection rejects at admission. */
bool vcs_zcode_science_index_vote_sequence_seen(
    const struct vcs_zcode_science_index *index,
    const char *voter_zid_root_hex, uint64_t sequence,
    const char *except_vote_id_hex);

size_t vcs_zcode_science_index_review_count(
    const struct vcs_zcode_science_index *index);
const struct vcs_zcode_science_index_review_entry *
vcs_zcode_science_index_review_at(
    const struct vcs_zcode_science_index *index, size_t i);
const struct vcs_zcode_science_index_review_entry *
vcs_zcode_science_index_find_review(
    const struct vcs_zcode_science_index *index,
    const uint8_t review_root[32]);

#endif /* ZCL_VCS_ZCODE_SCIENCE_INDEX_H */
