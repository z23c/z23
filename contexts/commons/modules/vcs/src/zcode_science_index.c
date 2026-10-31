/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_science_index — implementation of the rebuildable science
 * projection declared in vcs/zcode_science_index.h. Every build re-walks
 * the workspace CAS and re-verifies each projected wire against its
 * address; nothing is cached across builds. */

#include "vcs/zcode_science_index.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_science.h"
#include "util/path_util.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INDEX_LOG "vcs.science_index"

/* Wire magics from zcode_science.c / zcode_dev.c — the first 8 bytes decide
 * whether an object of the right size is even a candidate for projection. */
static const uint8_t study_magic[8] = {'Z','C','S','T','U','D','\r','\n'};
static const uint8_t result_v1_magic[8] = {'Z','C','B','E','N','C','\r','\n'};
static const uint8_t result_v2_magic[8] = {'Z','C','B','E','N','2','\r','\n'};
static const uint8_t reproduction_magic[8] =
    {'Z','C','R','E','P','R','\r','\n'};
static const uint8_t findings_magic[8] = {'Z','C','F','I','N','D','\r','\n'};
static const uint8_t vote_magic[8] = {'Z','C','V','O','T','E','\r','\n'};
static const uint8_t review_magic[8] = {'Z','C','R','E','V','W','\r','\n'};

struct vcs_zcode_science_index {
    struct vcs_zcode_science_index_study_entry *studies;
    size_t study_count;
    struct vcs_zcode_science_index_result_entry *results;
    size_t result_count;
    struct vcs_zcode_science_index_reproduction_entry *reproductions;
    size_t reproduction_count;
    struct vcs_zcode_science_index_findings_entry *findings;
    size_t findings_count;
    struct vcs_zcode_science_index_vote_entry *votes;
    size_t vote_count;
    struct vcs_zcode_science_index_review_entry *reviews;
    size_t review_count;
};

static bool index_root_agrees(const uint8_t rederived[32],
                              const uint8_t address[32])
{
    return memcmp(rederived, address, 32) == 0;
}

static void index_add_result(
    struct vcs_zcode_science_index *index, bool *cap_logged,
    const uint8_t address[32], const uint8_t study_root[32],
    const uint8_t task_root[32], const uint8_t candidate_root[32],
    const uint8_t action_root[32], const uint8_t *method_root,
    const uint8_t *hardware_profile_root, uint8_t status, uint64_t sequence,
    int64_t started_unix, int64_t finished_unix)
{
    if (index->result_count >= VCS_ZCODE_SCIENCE_INDEX_MAX_RESULTS) {
        if (!*cap_logged) {
            LOG_ERROR(INDEX_LOG, "result index cap %u reached",
                      VCS_ZCODE_SCIENCE_INDEX_MAX_RESULTS);
            *cap_logged = true;
        }
        return;
    }
    struct vcs_zcode_science_index_result_entry *entry =
        &index->results[index->result_count++];
    memset(entry, 0, sizeof(*entry));
    zcl_hex_encode(address, 32, entry->result_root_hex);
    zcl_hex_encode(study_root, 32, entry->study_root_hex);
    zcl_hex_encode(task_root, 32, entry->task_root_hex);
    zcl_hex_encode(candidate_root, 32, entry->candidate_root_hex);
    zcl_hex_encode(action_root, 32, entry->action_root_hex);
    if (method_root)
        zcl_hex_encode(method_root, 32, entry->method_root_hex);
    if (hardware_profile_root)
        zcl_hex_encode(hardware_profile_root, 32,
                       entry->hardware_profile_root_hex);
    entry->status = status;
    entry->sequence = sequence;
    entry->started_unix = started_unix;
    entry->finished_unix = finished_unix;
}

enum index_wire_kind {
    INDEX_WIRE_NONE,
    INDEX_WIRE_STUDY,
    INDEX_WIRE_RESULT_V1,
    INDEX_WIRE_RESULT_V2,
    INDEX_WIRE_REPRODUCTION,
    INDEX_WIRE_FINDINGS,
    INDEX_WIRE_VOTE,
    INDEX_WIRE_REVIEW,
};

enum index_add_status {
    INDEX_ADD_OK,
    INDEX_ADD_INVALID,
    INDEX_ADD_CAPPED,
};

#define INDEX_MAGIC_BYTES 8

/* One row per wire family, checked in the same order the magic chain ran. */
static const struct {
    size_t wire_bytes;
    const uint8_t *magic;
    enum index_wire_kind kind;
} index_wire_table[] = {
    {VCS_ZCODE_STUDY_SPEC_WIRE_BYTES, study_magic, INDEX_WIRE_STUDY},
    {VCS_ZCODE_BENCHMARK_RESULT_WIRE_BYTES, result_v1_magic,
     INDEX_WIRE_RESULT_V1},
    {VCS_ZCODE_BENCHMARK_RESULT_V2_WIRE_BYTES, result_v2_magic,
     INDEX_WIRE_RESULT_V2},
    {VCS_ZCODE_REPRODUCTION_WIRE_BYTES, reproduction_magic,
     INDEX_WIRE_REPRODUCTION},
    {VCS_ZCODE_SCIENCE_FINDINGS_WIRE_BYTES, findings_magic,
     INDEX_WIRE_FINDINGS},
    {VCS_ZCODE_CURATION_VOTE_WIRE_BYTES, vote_magic, INDEX_WIRE_VOTE},
    {VCS_ZCODE_REVIEW_WIRE_BYTES, review_magic, INDEX_WIRE_REVIEW},
};

static enum index_wire_kind index_wire_kind(const uint8_t *wire, size_t len)
{
    size_t rows = sizeof(index_wire_table) / sizeof(index_wire_table[0]);
    for (size_t i = 0; i < rows; i++)
        if (len == index_wire_table[i].wire_bytes &&
            memcmp(wire, index_wire_table[i].magic, INDEX_MAGIC_BYTES) == 0)
            return index_wire_table[i].kind;
    return INDEX_WIRE_NONE;
}

static enum index_add_status index_add_study(
    struct vcs_zcode_science_index *index, uint8_t *wire, size_t len,
    const uint8_t address[32])
{
    struct vcs_zcode_study_spec_v1 study;
    uint8_t root[32];
    bool ok = vcs_zcode_study_spec_parse(wire, len, &study) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_study_spec_validate(&study) == VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_study_spec_root(&study, root) == VCS_ZCODE_SCIENCE_OK &&
        index_root_agrees(root, address);
    if (!ok)
        return INDEX_ADD_INVALID;
    if (index->study_count >= VCS_ZCODE_SCIENCE_INDEX_MAX_STUDIES)
        return INDEX_ADD_CAPPED;
    struct vcs_zcode_science_index_study_entry *e =
        &index->studies[index->study_count++];
    memset(e, 0, sizeof(*e));
    zcl_hex_encode(address, 32, e->study_root_hex);
    zcl_hex_encode(study.hypothesis_root, 32, e->hypothesis_root_hex);
    zcl_hex_encode(study.null_hypothesis_root, 32,
                   e->null_hypothesis_root_hex);
    zcl_hex_encode(study.source_root, 32, e->source_root_hex);
    e->required_reproductions = study.required_reproductions;
    e->required_reviews = study.required_reviews;
    e->sequence = study.sequence;
    e->created_unix = study.created_unix;
    e->expires_unix = study.expires_unix;
    return INDEX_ADD_OK;
}

static enum index_add_status index_add_result_v1(
    struct vcs_zcode_science_index *index, bool *cap_logged,
    uint8_t *wire, size_t len, const uint8_t address[32])
{
    struct vcs_zcode_benchmark_result_v1 result;
    uint8_t root[32];
    bool ok = vcs_zcode_benchmark_result_parse(wire, len, &result) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_benchmark_result_validate(&result) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_benchmark_result_root(&result, root) ==
            VCS_ZCODE_SCIENCE_OK &&
        index_root_agrees(root, address);
    if (!ok)
        return INDEX_ADD_INVALID;
    index_add_result(
        index, cap_logged, address, result.study_root,
        result.task_root, result.candidate_root, result.action_root,
        NULL, NULL, result.status, result.sequence,
        result.started_unix, result.finished_unix);
    return INDEX_ADD_OK;
}

static enum index_add_status index_add_result_v2(
    struct vcs_zcode_science_index *index, bool *cap_logged,
    uint8_t *wire, size_t len, const uint8_t address[32])
{
    struct vcs_zcode_benchmark_result_v2 result;
    uint8_t root[32];
    bool ok = vcs_zcode_benchmark_result_v2_parse(wire, len, &result) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_benchmark_result_v2_validate(&result) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_benchmark_result_v2_root(&result, root) ==
            VCS_ZCODE_SCIENCE_OK &&
        index_root_agrees(root, address);
    if (!ok)
        return INDEX_ADD_INVALID;
    index_add_result(
        index, cap_logged, address, result.study_root,
        result.task_root, result.candidate_root, result.action_root,
        result.method_root, result.hardware_profile_root,
        result.status, result.sequence, result.started_unix,
        result.finished_unix);
    return INDEX_ADD_OK;
}

static enum index_add_status index_add_reproduction(
    struct vcs_zcode_science_index *index, uint8_t *wire, size_t len,
    const uint8_t address[32])
{
    struct vcs_zcode_reproduction_v1 reproduction;
    uint8_t root[32];
    bool ok = vcs_zcode_reproduction_parse(wire, len, &reproduction) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_reproduction_validate(&reproduction) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_reproduction_root(&reproduction, root) ==
            VCS_ZCODE_SCIENCE_OK &&
        index_root_agrees(root, address);
    if (!ok)
        return INDEX_ADD_INVALID;
    if (index->reproduction_count >=
        VCS_ZCODE_SCIENCE_INDEX_MAX_REPRODUCTIONS)
        return INDEX_ADD_CAPPED;
    struct vcs_zcode_science_index_reproduction_entry *e =
        &index->reproductions[index->reproduction_count++];
    memset(e, 0, sizeof(*e));
    zcl_hex_encode(address, 32, e->reproduction_root_hex);
    zcl_hex_encode(reproduction.study_root, 32, e->study_root_hex);
    zcl_hex_encode(reproduction.original_result_root, 32,
                   e->original_result_root_hex);
    zcl_hex_encode(reproduction.reproduced_result_root, 32,
                   e->reproduced_result_root_hex);
    zcl_hex_encode(reproduction.reproducer_pubkey, 32,
                   e->reproducer_pubkey_hex);
    e->verdict = reproduction.verdict;
    e->sequence = reproduction.sequence;
    e->created_unix = reproduction.created_unix;
    return INDEX_ADD_OK;
}

static enum index_add_status index_add_findings(
    struct vcs_zcode_science_index *index, uint8_t *wire, size_t len,
    const uint8_t address[32])
{
    struct vcs_zcode_science_findings_v1 findings;
    uint8_t root[32];
    bool ok = vcs_zcode_science_findings_parse(wire, len, &findings) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_findings_validate(&findings) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_science_findings_root(&findings, root) ==
            VCS_ZCODE_SCIENCE_OK &&
        index_root_agrees(root, address);
    if (!ok)
        return INDEX_ADD_INVALID;
    if (index->findings_count >= VCS_ZCODE_SCIENCE_INDEX_MAX_FINDINGS)
        return INDEX_ADD_CAPPED;
    struct vcs_zcode_science_index_findings_entry *e =
        &index->findings[index->findings_count++];
    memset(e, 0, sizeof(*e));
    zcl_hex_encode(address, 32, e->findings_root_hex);
    zcl_hex_encode(findings.study_root, 32, e->study_root_hex);
    zcl_hex_encode(findings.result_root, 32, e->result_root_hex);
    zcl_hex_encode(findings.retraction_target_root, 32,
                   e->retraction_target_root_hex);
    e->flags = findings.flags;
    e->severity = findings.severity;
    e->sequence = findings.sequence;
    e->created_unix = findings.created_unix;
    return INDEX_ADD_OK;
}

static enum index_add_status index_add_vote(
    struct vcs_zcode_science_index *index, uint8_t *wire, size_t len,
    const uint8_t address[32])
{
    struct vcs_zcode_curation_vote_v1 vote;
    uint8_t id[32];
    bool ok = vcs_zcode_curation_vote_parse(wire, len, &vote) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_curation_vote_validate(&vote) ==
            VCS_ZCODE_SCIENCE_OK &&
        vcs_zcode_curation_vote_id(&vote, id) == VCS_ZCODE_SCIENCE_OK &&
        index_root_agrees(id, address);
    if (!ok)
        return INDEX_ADD_INVALID;
    if (index->vote_count >= VCS_ZCODE_SCIENCE_INDEX_MAX_VOTES)
        return INDEX_ADD_CAPPED;
    struct vcs_zcode_science_index_vote_entry *e =
        &index->votes[index->vote_count++];
    memset(e, 0, sizeof(*e));
    zcl_hex_encode(address, 32, e->vote_id_hex);
    zcl_hex_encode(vote.voter_zid_root, 32, e->voter_zid_root_hex);
    zcl_hex_encode(vote.property_root, 32, e->property_root_hex);
    zcl_hex_encode(vote.signer_pubkey, 32, e->signer_pubkey_hex);
    e->signal = vote.signal;
    e->sequence = vote.sequence;
    e->expires_unix = vote.expires_unix;
    return INDEX_ADD_OK;
}

static enum index_add_status index_add_review(
    struct vcs_zcode_science_index *index, uint8_t *wire, size_t len,
    const uint8_t address[32])
{
    struct vcs_zcode_review_v1 review;
    uint8_t root[32];
    bool ok = vcs_zcode_review_parse(wire, len, &review) ==
            VCS_ZCODE_DEV_OK &&
        vcs_zcode_review_validate(&review) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_review_root(&review, root) == VCS_ZCODE_DEV_OK &&
        index_root_agrees(root, address);
    if (!ok)
        return INDEX_ADD_INVALID;
    if (index->review_count >= VCS_ZCODE_SCIENCE_INDEX_MAX_REVIEWS)
        return INDEX_ADD_CAPPED;
    struct vcs_zcode_science_index_review_entry *e =
        &index->reviews[index->review_count++];
    memset(e, 0, sizeof(*e));
    zcl_hex_encode(address, 32, e->review_root_hex);
    zcl_hex_encode(review.findings_root, 32, e->findings_root_hex);
    zcl_hex_encode(review.reviewer_pubkey, 32, e->reviewer_pubkey_hex);
    e->verdict = review.verdict;
    e->sequence = review.sequence;
    e->created_unix = review.created_unix;
    return INDEX_ADD_OK;
}

/* What index_consider_wire found. index_consider_object maps each code to
 * its log line. */
enum index_outcome {
    INDEX_OUT_NONE,
    INDEX_OUT_UNREADABLE,
    INDEX_OUT_STUDY_INVALID,
    INDEX_OUT_STUDY_CAPPED,
    INDEX_OUT_RESULT_V1_INVALID,
    INDEX_OUT_RESULT_V2_INVALID,
    INDEX_OUT_REPRODUCTION_INVALID,
    INDEX_OUT_REPRODUCTION_CAPPED,
    INDEX_OUT_FINDINGS_INVALID,
    INDEX_OUT_FINDINGS_CAPPED,
    INDEX_OUT_VOTE_INVALID,
    INDEX_OUT_VOTE_CAPPED,
    INDEX_OUT_REVIEW_INVALID,
    INDEX_OUT_REVIEW_CAPPED,
};

/* A cap is reported once per index build: the first capped object yields
 * its code; later ones yield none. The caller sets the flag after it logs. */
static enum index_outcome index_outcome_of(enum index_add_status st,
                                           enum index_outcome invalid,
                                           enum index_outcome capped,
                                           bool *cap_logged)
{
    if (st == INDEX_ADD_INVALID)
        return invalid;
    if (st == INDEX_ADD_CAPPED) {
        if (*cap_logged)
            return INDEX_OUT_NONE;
        return capped;
    }
    return INDEX_OUT_NONE;
}

static enum index_outcome index_add_wire(
    struct vcs_zcode_science_index *index, uint8_t *wire, size_t len,
    const uint8_t address[32], bool *cap_logged)
{
    switch (index_wire_kind(wire, len)) {
    case INDEX_WIRE_STUDY:
        return index_outcome_of(
            index_add_study(index, wire, len, address),
            INDEX_OUT_STUDY_INVALID, INDEX_OUT_STUDY_CAPPED, cap_logged);
    case INDEX_WIRE_RESULT_V1:
        return index_outcome_of(
            index_add_result_v1(index, cap_logged, wire, len, address),
            INDEX_OUT_RESULT_V1_INVALID, INDEX_OUT_NONE, cap_logged);
    case INDEX_WIRE_RESULT_V2:
        return index_outcome_of(
            index_add_result_v2(index, cap_logged, wire, len, address),
            INDEX_OUT_RESULT_V2_INVALID, INDEX_OUT_NONE, cap_logged);
    case INDEX_WIRE_REPRODUCTION:
        return index_outcome_of(
            index_add_reproduction(index, wire, len, address),
            INDEX_OUT_REPRODUCTION_INVALID, INDEX_OUT_REPRODUCTION_CAPPED,
            cap_logged);
    case INDEX_WIRE_FINDINGS:
        return index_outcome_of(
            index_add_findings(index, wire, len, address),
            INDEX_OUT_FINDINGS_INVALID, INDEX_OUT_FINDINGS_CAPPED, cap_logged);
    case INDEX_WIRE_VOTE:
        return index_outcome_of(
            index_add_vote(index, wire, len, address),
            INDEX_OUT_VOTE_INVALID, INDEX_OUT_VOTE_CAPPED, cap_logged);
    case INDEX_WIRE_REVIEW:
        return index_outcome_of(
            index_add_review(index, wire, len, address),
            INDEX_OUT_REVIEW_INVALID, INDEX_OUT_REVIEW_CAPPED, cap_logged);
    default:
        return INDEX_OUT_NONE;
    }
}

/* On a loaded object *wire_out and *len_out are set; the caller frees the
 * wire after it has logged. */
static enum index_outcome index_consider_wire(
    const char *repo_root, const char *hex64,
    struct vcs_zcode_science_index *index, bool *cap_logged,
    uint8_t **wire_out, size_t *len_out)
{
    uint8_t address[32];
    if (!zcl_hex_decode_lower(hex64, address, 32))
        return INDEX_OUT_NONE;
    uint8_t *wire = NULL;
    size_t len = 0;
    if (vcs_object_load_raw(repo_root, address, &wire, &len) != 0)
        return INDEX_OUT_UNREADABLE;
    *wire_out = wire;
    *len_out = len;
    return index_add_wire(index, wire, len, address, cap_logged);
}

/* Wrong size or wrong magic means the object is another CAS citizen and is
 * skipped silently; right magic with a failed parse/validation/root check
 * is corruption and is logged. */
static void index_consider_object(const char *repo_root, const char *hex64,
                                  struct vcs_zcode_science_index *index,
                                  bool *cap_logged)
{
    uint8_t *wire = NULL;
    size_t len = 0;
    switch (index_consider_wire(repo_root, hex64, index, cap_logged,
                                &wire, &len)) {
    case INDEX_OUT_UNREADABLE:
        LOG_ERROR(INDEX_LOG, "unreadable CAS object %.8s", hex64);
        break;
    case INDEX_OUT_STUDY_INVALID:
        LOG_ERROR(INDEX_LOG, "skipping study-magic object %.8s: "
                  "parse, validation, or root agreement failed", hex64);
        break;
    case INDEX_OUT_STUDY_CAPPED:
        LOG_ERROR(INDEX_LOG, "study index cap %u reached",
                  VCS_ZCODE_SCIENCE_INDEX_MAX_STUDIES);
        *cap_logged = true;
        break;
    case INDEX_OUT_RESULT_V1_INVALID:
        LOG_ERROR(INDEX_LOG, "skipping result-v1-magic object %.8s: "
                  "parse, validation, or root agreement failed", hex64);
        break;
    case INDEX_OUT_RESULT_V2_INVALID:
        LOG_ERROR(INDEX_LOG, "skipping result-v2-magic object %.8s: "
                  "parse, validation, or root agreement failed", hex64);
        break;
    case INDEX_OUT_REPRODUCTION_INVALID:
        LOG_ERROR(INDEX_LOG, "skipping reproduction-magic object %.8s: "
                  "parse, validation, or root agreement failed", hex64);
        break;
    case INDEX_OUT_REPRODUCTION_CAPPED:
        LOG_ERROR(INDEX_LOG, "reproduction index cap %u reached",
                  VCS_ZCODE_SCIENCE_INDEX_MAX_REPRODUCTIONS);
        *cap_logged = true;
        break;
    case INDEX_OUT_FINDINGS_INVALID:
        LOG_ERROR(INDEX_LOG, "skipping findings-magic object %.8s: "
                  "parse, validation, or root agreement failed", hex64);
        break;
    case INDEX_OUT_FINDINGS_CAPPED:
        LOG_ERROR(INDEX_LOG, "findings index cap %u reached",
                  VCS_ZCODE_SCIENCE_INDEX_MAX_FINDINGS);
        *cap_logged = true;
        break;
    case INDEX_OUT_VOTE_INVALID:
        LOG_ERROR(INDEX_LOG, "skipping vote-magic object %.8s: "
                  "parse, validation, or id agreement failed", hex64);
        break;
    case INDEX_OUT_VOTE_CAPPED:
        LOG_ERROR(INDEX_LOG, "vote index cap %u reached",
                  VCS_ZCODE_SCIENCE_INDEX_MAX_VOTES);
        *cap_logged = true;
        break;
    case INDEX_OUT_REVIEW_INVALID:
        LOG_ERROR(INDEX_LOG, "skipping review-magic object %.8s: "
                  "parse, validation, or root agreement failed", hex64);
        break;
    case INDEX_OUT_REVIEW_CAPPED:
        LOG_ERROR(INDEX_LOG, "review index cap %u reached",
                  VCS_ZCODE_SCIENCE_INDEX_MAX_REVIEWS);
        *cap_logged = true;
        break;
    default:
        break;
    }
    free(wire);
}

static void index_scan_shard(const char *repo_root, const char *shard_path,
                             const char *shard,
                             struct vcs_zcode_science_index *index,
                             bool *cap_logged)
{
    DIR *d = opendir(shard_path);
    if (!d) {
        LOG_ERROR(INDEX_LOG, "cannot open CAS shard %s", shard_path);
        return;
    }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!zcl_is_lower_hex(de->d_name, 62))
            continue;
        char hex64[65];
        int n = snprintf(hex64, sizeof(hex64), "%s%s", shard, de->d_name);
        if (n != 64)
            continue;
        index_consider_object(repo_root, hex64, index, cap_logged);
    }
    closedir(d);
}

static int index_study_cmp(const void *a, const void *b)
{
    return strcmp(
        ((const struct vcs_zcode_science_index_study_entry *)a)->study_root_hex,
        ((const struct vcs_zcode_science_index_study_entry *)b)->study_root_hex);
}
static int index_result_cmp(const void *a, const void *b)
{
    return strcmp(
        ((const struct vcs_zcode_science_index_result_entry *)a)->result_root_hex,
        ((const struct vcs_zcode_science_index_result_entry *)b)->result_root_hex);
}
static int index_reproduction_cmp(const void *a, const void *b)
{
    return strcmp(
        ((const struct vcs_zcode_science_index_reproduction_entry *)a)->reproduction_root_hex,
        ((const struct vcs_zcode_science_index_reproduction_entry *)b)->reproduction_root_hex);
}
static int index_findings_cmp(const void *a, const void *b)
{
    return strcmp(
        ((const struct vcs_zcode_science_index_findings_entry *)a)->findings_root_hex,
        ((const struct vcs_zcode_science_index_findings_entry *)b)->findings_root_hex);
}
static int index_vote_cmp(const void *a, const void *b)
{
    return strcmp(
        ((const struct vcs_zcode_science_index_vote_entry *)a)->vote_id_hex,
        ((const struct vcs_zcode_science_index_vote_entry *)b)->vote_id_hex);
}
static int index_review_cmp(const void *a, const void *b)
{
    return strcmp(
        ((const struct vcs_zcode_science_index_review_entry *)a)->review_root_hex,
        ((const struct vcs_zcode_science_index_review_entry *)b)->review_root_hex);
}

static bool index_hex64_zero(const char *hex)
{
    for (size_t i = 0; i < 64; i++)
        if (hex[i] != '0')
            return false;
    return true;
}

static void index_derive_vote_expiry(struct vcs_zcode_science_index *index,
                                     int64_t now_unix)
{
    for (size_t i = 0; i < index->vote_count; i++)
        index->votes[i].expired =
            now_unix > 0 && now_unix >= index->votes[i].expires_unix;
}

static void index_derive_study(struct vcs_zcode_science_index *index,
                               size_t i, int64_t now_unix)
{
    struct vcs_zcode_science_index_study_entry *s = &index->studies[i];
    s->expired = now_unix > 0 && now_unix >= s->expires_unix;
    for (size_t r = 0; r < index->result_count; r++)
        if (strcmp(index->results[r].study_root_hex,
                   s->study_root_hex) == 0)
            s->result_count++;
    for (size_t r = 0; r < index->reproduction_count; r++)
        if (strcmp(index->reproductions[r].study_root_hex,
                   s->study_root_hex) == 0)
            s->reproduction_count++;
    for (size_t f = 0; f < index->findings_count; f++)
        if (strcmp(index->findings[f].study_root_hex,
                   s->study_root_hex) == 0)
            s->findings_count++;
}

static void index_derive_retraction(
    struct vcs_zcode_science_index *index,
    const struct vcs_zcode_science_index_findings_entry *fe)
{
    if (!(fe->flags & VCS_ZCODE_FINDING_RETRACTION) ||
        index_hex64_zero(fe->retraction_target_root_hex))
        return;
    for (size_t i = 0; i < index->study_count; i++)
        if (strcmp(index->studies[i].study_root_hex,
                   fe->retraction_target_root_hex) == 0)
            index->studies[i].retracted = true;
    for (size_t r = 0; r < index->result_count; r++)
        if (strcmp(index->results[r].result_root_hex,
                   fe->retraction_target_root_hex) == 0)
            index->results[r].retracted = true;
}

static void index_count_review_for_study(
    struct vcs_zcode_science_index *index, const char *study_root_hex)
{
    for (size_t i = 0; i < index->study_count; i++)
        if (strcmp(index->studies[i].study_root_hex, study_root_hex) == 0)
            index->studies[i].review_count++;
}

static void index_derive_review(
    struct vcs_zcode_science_index *index,
    const struct vcs_zcode_science_index_review_entry *re)
{
    for (size_t f = 0; f < index->findings_count; f++) {
        if (strcmp(index->findings[f].findings_root_hex,
                   re->findings_root_hex) != 0)
            continue;
        index_count_review_for_study(index, index->findings[f].study_root_hex);
    }
}

/* Derive per-study evidence counts, expiry flags, and retraction marks.
 * Retraction is an observation: a findings object carrying the RETRACTION
 * flag marks its target (a study root or a result root); nothing is
 * erased. */
static void index_derive(struct vcs_zcode_science_index *index,
                         int64_t now_unix)
{
    index_derive_vote_expiry(index, now_unix);
    for (size_t i = 0; i < index->study_count; i++)
        index_derive_study(index, i, now_unix);
    for (size_t f = 0; f < index->findings_count; f++)
        index_derive_retraction(index, &index->findings[f]);
    /* Review counts attach to studies through their findings. */
    for (size_t v = 0; v < index->review_count; v++)
        index_derive_review(index, &index->reviews[v]);
}

static bool index_alloc_entries(struct vcs_zcode_science_index *index)
{
    index->studies = zcl_malloc(sizeof(*index->studies) *
        VCS_ZCODE_SCIENCE_INDEX_MAX_STUDIES, "science_index_studies");
    index->results = zcl_malloc(sizeof(*index->results) *
        VCS_ZCODE_SCIENCE_INDEX_MAX_RESULTS, "science_index_results");
    index->reproductions = zcl_malloc(sizeof(*index->reproductions) *
        VCS_ZCODE_SCIENCE_INDEX_MAX_REPRODUCTIONS, "science_index_repros");
    index->findings = zcl_malloc(sizeof(*index->findings) *
        VCS_ZCODE_SCIENCE_INDEX_MAX_FINDINGS, "science_index_findings");
    index->votes = zcl_malloc(sizeof(*index->votes) *
        VCS_ZCODE_SCIENCE_INDEX_MAX_VOTES, "science_index_votes");
    index->reviews = zcl_malloc(sizeof(*index->reviews) *
        VCS_ZCODE_SCIENCE_INDEX_MAX_REVIEWS, "science_index_reviews");
    return index->studies && index->results && index->reproductions &&
        index->findings && index->votes && index->reviews;
}

static void index_scan_entries(const char *repo_root, const char *objects,
                               DIR *d, struct vcs_zcode_science_index *index)
{
    bool cap_logged = false;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!zcl_is_lower_hex(de->d_name, 2))
            continue; /* skips "tmp" and any non-shard entry */
        char shard_path[4400];
        int n = snprintf(shard_path, sizeof(shard_path), "%s/%s", objects,
                         de->d_name);
        if (n <= 0 || (size_t)n >= sizeof(shard_path))
            continue;
        index_scan_shard(repo_root, shard_path, de->d_name, index,
                         &cap_logged);
    }
}

static void index_sort_entries(struct vcs_zcode_science_index *index)
{
    if (index->study_count > 1)
        qsort(index->studies, index->study_count, sizeof(*index->studies),
              index_study_cmp);
    if (index->result_count > 1)
        qsort(index->results, index->result_count, sizeof(*index->results),
              index_result_cmp);
    if (index->reproduction_count > 1)
        qsort(index->reproductions, index->reproduction_count,
              sizeof(*index->reproductions), index_reproduction_cmp);
    if (index->findings_count > 1)
        qsort(index->findings, index->findings_count,
              sizeof(*index->findings), index_findings_cmp);
    if (index->vote_count > 1)
        qsort(index->votes, index->vote_count, sizeof(*index->votes),
              index_vote_cmp);
    if (index->review_count > 1)
        qsort(index->reviews, index->review_count, sizeof(*index->reviews),
              index_review_cmp);
}

struct vcs_zcode_science_index *vcs_zcode_science_index_build(
    const char *repo_root, int64_t now_unix)
{
    if (!repo_root)
        LOG_RETURN(NULL, INDEX_LOG, "null repo_root");
    struct vcs_zcode_science_index *index =
        zcl_malloc(sizeof(*index), "vcs_zcode_science_index");
    if (!index)
        LOG_RETURN(NULL, INDEX_LOG, "index alloc");
    memset(index, 0, sizeof(*index));
    if (!index_alloc_entries(index)) {
        vcs_zcode_science_index_free(index);
        LOG_RETURN(NULL, INDEX_LOG, "entry arrays");
    }
    char objects[4400];
    int n = snprintf(objects, sizeof(objects), "%s/.zvcs/objects", repo_root);
    if (n <= 0 || (size_t)n >= sizeof(objects)) {
        vcs_zcode_science_index_free(index);
        LOG_RETURN(NULL, INDEX_LOG, "objects path too long");
    }
    DIR *d = opendir(objects);
    if (!d)
        return index; /* no object store yet: an empty projection */
    index_scan_entries(repo_root, objects, d, index);
    closedir(d);
    index_sort_entries(index);
    index_derive(index, now_unix);
    return index;
}

void vcs_zcode_science_index_free(struct vcs_zcode_science_index *index)
{
    if (!index)
        return;
    free(index->reviews);
    free(index->votes);
    free(index->findings);
    free(index->reproductions);
    free(index->results);
    free(index->studies);
    free(index);
}

size_t vcs_zcode_science_index_study_count(
    const struct vcs_zcode_science_index *index)
{
    return index ? index->study_count : 0;
}

const struct vcs_zcode_science_index_study_entry *
vcs_zcode_science_index_study_at(
    const struct vcs_zcode_science_index *index, size_t i)
{
    if (!index || i >= index->study_count)
        return NULL;
    return &index->studies[i];
}

const struct vcs_zcode_science_index_study_entry *
vcs_zcode_science_index_find_study(
    const struct vcs_zcode_science_index *index, const uint8_t study_root[32])
{
    if (!index || !study_root)
        return NULL;
    char root_hex[65];
    zcl_hex_encode(study_root, 32, root_hex);
    for (size_t i = 0; i < index->study_count; i++)
        if (strcmp(index->studies[i].study_root_hex, root_hex) == 0)
            return &index->studies[i];
    return NULL;
}

size_t vcs_zcode_science_index_result_count(
    const struct vcs_zcode_science_index *index)
{
    return index ? index->result_count : 0;
}

const struct vcs_zcode_science_index_result_entry *
vcs_zcode_science_index_result_at(
    const struct vcs_zcode_science_index *index, size_t i)
{
    if (!index || i >= index->result_count)
        return NULL;
    return &index->results[i];
}

const struct vcs_zcode_science_index_result_entry *
vcs_zcode_science_index_find_result(
    const struct vcs_zcode_science_index *index,
    const uint8_t result_root[32])
{
    if (!index || !result_root)
        return NULL;
    char root_hex[65];
    zcl_hex_encode(result_root, 32, root_hex);
    for (size_t i = 0; i < index->result_count; i++)
        if (strcmp(index->results[i].result_root_hex, root_hex) == 0)
            return &index->results[i];
    return NULL;
}

size_t vcs_zcode_science_index_reproduction_count(
    const struct vcs_zcode_science_index *index)
{
    return index ? index->reproduction_count : 0;
}

const struct vcs_zcode_science_index_reproduction_entry *
vcs_zcode_science_index_reproduction_at(
    const struct vcs_zcode_science_index *index, size_t i)
{
    if (!index || i >= index->reproduction_count)
        return NULL;
    return &index->reproductions[i];
}

size_t vcs_zcode_science_index_findings_count(
    const struct vcs_zcode_science_index *index)
{
    return index ? index->findings_count : 0;
}

const struct vcs_zcode_science_index_findings_entry *
vcs_zcode_science_index_findings_at(
    const struct vcs_zcode_science_index *index, size_t i)
{
    if (!index || i >= index->findings_count)
        return NULL;
    return &index->findings[i];
}

size_t vcs_zcode_science_index_vote_count(
    const struct vcs_zcode_science_index *index)
{
    return index ? index->vote_count : 0;
}

const struct vcs_zcode_science_index_vote_entry *
vcs_zcode_science_index_vote_at(
    const struct vcs_zcode_science_index *index, size_t i)
{
    if (!index || i >= index->vote_count)
        return NULL;
    return &index->votes[i];
}

bool vcs_zcode_science_index_vote_sequence_seen(
    const struct vcs_zcode_science_index *index,
    const char *voter_zid_root_hex, uint64_t sequence,
    const char *except_vote_id_hex)
{
    if (!index || !voter_zid_root_hex)
        return false;
    for (size_t i = 0; i < index->vote_count; i++) {
        const struct vcs_zcode_science_index_vote_entry *e =
            &index->votes[i];
        if (except_vote_id_hex &&
            strcmp(e->vote_id_hex, except_vote_id_hex) == 0)
            continue;
        if (strcmp(e->voter_zid_root_hex, voter_zid_root_hex) == 0 &&
            e->sequence == sequence)
            return true;
    }
    return false;
}

size_t vcs_zcode_science_index_review_count(
    const struct vcs_zcode_science_index *index)
{
    return index ? index->review_count : 0;
}

const struct vcs_zcode_science_index_review_entry *
vcs_zcode_science_index_review_at(
    const struct vcs_zcode_science_index *index, size_t i)
{
    if (!index || i >= index->review_count)
        return NULL;
    return &index->reviews[i];
}

