/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Rebuildable ActiveRecord projections for ZCODE science objects,
 *          plus the durable plan/commit idempotency ledger.
 *
 * The canonical CAS wires (study_spec.v1, benchmark_result.v2,
 * reproduction.v1, science_findings.v1, curation_vote.v1, review.v1) are
 * the only truth; every table here may be dropped and rebuilt from the
 * workspace CAS via vcs/zcode_science_index.h. */

#ifndef ZCL_MODELS_ZCODE_SCIENCE_H
#define ZCL_MODELS_ZCODE_SCIENCE_H

#include "models/activerecord.h"
#include "models/database.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Longest science wire is study_spec.v1 (422 bytes); hex doubles it. */
#define ZCODE_SCIENCE_PLAN_WIRE_HEX_MAX 1024

#define ZCODE_SCIENCE_PLAN_STATE_PLANNED "PLANNED"
#define ZCODE_SCIENCE_PLAN_STATE_COMMITTED "COMMITTED"

/* One exact, expiring write plan. request_hash is the durable idempotency
 * key: sha3-256 over the request domain, kind, and the exact wire bytes. */
struct db_zcode_science_plan {
    char plan_root[65];
    char kind[24]; /* "study" | "work" | "review" | "vote" */
    char request_hash[65];
    char wire_hex[ZCODE_SCIENCE_PLAN_WIRE_HEX_MAX];
    char result_root[65]; /* empty until committed */
    char state[16];       /* PLANNED | COMMITTED */
    int64_t expires_unix;
    int64_t created_at;
};

/* Generic projection row shared by the six rebuildable tables. Columns are
 * lookup keys only; the projected CAS wire stays the authority. */
struct db_zcode_science_entry {
    char root[65];       /* canonical object root (vote: canonical vote id) */
    char study_root[65]; /* owning study root, or "" */
    char link_root[65];  /* original_result / property / findings / retraction target */
    char aux_root[65];   /* reproduced_result / task / signer, or "" */
    char author[65];     /* reproducer / voter_zid / reviewer, or "" */
    int64_t code;        /* status / verdict / signal / severity */
    int64_t flags;       /* findings flags, else 0 */
    int64_t sequence;
    int64_t created_at;
    int64_t expires_at;  /* votes: expires_unix; else 0 */
};

struct ar_callbacks *db_zcode_science_plan_callbacks(void);
struct ar_callbacks *db_zcode_science_entry_callbacks(void);

bool db_zcode_science_plan_validate(
    const struct db_zcode_science_plan *row, struct ar_errors *errors);
bool db_zcode_science_entry_validate(
    const struct db_zcode_science_entry *row, struct ar_errors *errors);

bool db_zcode_science_plan_save(
    struct node_db *ndb, const struct db_zcode_science_plan *row);
bool db_zcode_science_plan_find_by_request(
    struct node_db *ndb, const char *request_hash,
    struct db_zcode_science_plan *out);
bool db_zcode_science_plan_find(
    struct node_db *ndb, const char *plan_root,
    struct db_zcode_science_plan *out);

#define ZCODE_SCIENCE_TABLE_DECL(NAME)                                        \
    bool db_zcode_science_##NAME##_save(                                      \
        struct node_db *ndb, const struct db_zcode_science_entry *row);       \
    bool db_zcode_science_##NAME##_find(                                      \
        struct node_db *ndb, const char *root,                                \
        struct db_zcode_science_entry *out);

ZCODE_SCIENCE_TABLE_DECL(study)
ZCODE_SCIENCE_TABLE_DECL(result)
ZCODE_SCIENCE_TABLE_DECL(reproduction)
ZCODE_SCIENCE_TABLE_DECL(findings)
ZCODE_SCIENCE_TABLE_DECL(vote)
ZCODE_SCIENCE_TABLE_DECL(review)

/* List studies (projection read for zcode.science.study.list). Returns the
 * row count written (<= max). */
int db_zcode_science_study_list(
    struct node_db *ndb, struct db_zcode_science_entry *out, int max);

/* S5 (additive): filtered study list for zcode.science.discover's
 * filter-first step. search_like is a caller-escaped LIKE pattern (or
 * NULL); category is NULL or one of active|expired|retracted, decided at
 * now_unix. Deterministic order: root ascending. */
int db_zcode_science_study_list_filtered(
    struct node_db *ndb, const char *search_like, const char *category,
    int64_t now_unix, struct db_zcode_science_entry *out, int max);

/* Vote replay probe: true when a DIFFERENT vote id already carries this
 * voter_zid + sequence (the replay shape admission rejects). */
bool db_zcode_science_vote_sequence_seen(
    struct node_db *ndb, const char *voter_zid_root, int64_t sequence,
    const char *except_vote_id);

/* Drop every projection row (rebuild from CAS follows). Plans persist —
 * they are the durable request/result identity ledger, not a projection. */
bool db_zcode_science_projection_clear(struct node_db *ndb);

#endif /* ZCL_MODELS_ZCODE_SCIENCE_H */
