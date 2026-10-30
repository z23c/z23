/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_reward_priv — private internals shared by the package_reward
 * implementation units (package_reward.c = ledger, queue, plan and commit
 * driver; package_reward_commit_validate.c = pass 1 of a commit, the
 * validation of every PLANNED row against the current ledger; and
 * package_reward_labels.c, which shares nothing with them). NOT a public
 * header: nothing outside contexts/commons/modules/vcs/src/ includes this. */

#ifndef ZCL_VCS_PACKAGE_REWARD_PRIV_H
#define ZCL_VCS_PACKAGE_REWARD_PRIV_H

#include "vcs/package_reward.h"

#include "vcs/package_score.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define REWARD_LOG "vcs.reward"

struct vcs_reward_fact {
    uint8_t entry_id[32];
    uint8_t release_root[32];
    uint8_t contributor[33];
    uint8_t kind;
    uint8_t category;
    uint32_t points; /* settled */
    int64_t day;
    uint8_t facts_hash[32];
    uint8_t plan_id[32];
};

struct vcs_reward_loaded_plan {
    uint8_t id[32];
    int64_t day;
    uint8_t (*refs)[32]; /* PLANNED row entry ids */
    size_t ref_count;
    bool committed;
};

struct vcs_reward_ledger {
    char root[4400]; /* <zcode_dir>/rewards */
    struct vcs_reward_entry *entries; /* ascending entry_id */
    size_t entry_count;
    size_t entry_cap;
    struct vcs_reward_fact *facts;
    size_t fact_count;
    size_t fact_cap;
    struct vcs_reward_loaded_plan *plans; /* ascending id */
    size_t plan_count;
    size_t plan_cap;
    uint8_t (*commits)[32]; /* committed plan ids */
    size_t commit_count;
    size_t commit_cap;
    uint32_t corrupt;
    bool truncated;
};

/* Shared state of one commit: the plan, its scratch flags and the batch
 * additions that pass 1 accumulates for the exact cap recomputation. */
struct reward_commit_ctx {
    struct vcs_reward_ledger *l;
    const struct vcs_reward_plan *plan;
    const uint8_t *plan_id;
    bool *rejected;
    bool *resumed;
    struct vcs_reward_commit_result *out;
    char *detail;
    size_t detail_size;
    size_t addition_count;
    struct vcs_score_period_entry additions[VCS_REWARD_MAX_BATCH_ENTRIES];
    char contributors[VCS_REWARD_MAX_BATCH_ENTRIES][33];
    uint8_t accepted_roots[VCS_REWARD_MAX_BATCH_ENTRIES][32];
    uint8_t accepted_cats[VCS_REWARD_MAX_BATCH_ENTRIES];
};

/* Ledger lookups owned by package_reward.c and read by the commit
 * validation pass. */
int reward_id_cmp(const uint8_t a[32], const uint8_t b[32]);
size_t reward_history_for(const struct vcs_reward_ledger *l,
                          const uint8_t contributor[33],
                          const uint8_t exclude_plan[32],
                          struct vcs_score_period_entry *out, size_t cap);
bool reward_fact_duplicate(const struct vcs_reward_ledger *l,
                           const uint8_t release_root[32],
                           const uint8_t contributor[33],
                           enum vcs_reward_category category,
                           const uint8_t exclude_plan[32]);
const struct vcs_reward_fact *reward_fact_find(
    const struct vcs_reward_ledger *l, const uint8_t entry_id[32]);

/* Pass 1 of a commit: validates every PLANNED row; writes nothing. */
enum vcs_reward_commit_error reward_commit_validate_planned(
    struct reward_commit_ctx *c);

#endif
