/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * package_reward_commit_validate — pass 1 of a ZCODE reward-ledger commit
 * declared in vcs/package_reward.h: the state and exact period-cap checks of
 * every PLANNED row against the current ledger. Split out of
 * package_reward.c to keep that file under its size ceiling; it only reads
 * the ledger (through package_reward_priv.h) and writes nothing. */

#include "package_reward_priv.h"

#include "base/hex.h"

#include <stdio.h>
#include <string.h>

/* Sets the "entry missing" detail for a PLANNED entry absent from the
 * ledger and returns STALE. */
static enum vcs_reward_commit_error reward_commit_missing(
    const struct reward_commit_ctx *c, const char *id_hex)
{
    if (c->detail && c->detail_size > 0)
        snprintf(c->detail, c->detail_size, "entry %s missing", id_hex);
    return VCS_REWARD_COMMIT_STALE;
}

/* Sets the "settled by another plan" detail for a PLANNED entry and
 * returns STALE. */
static enum vcs_reward_commit_error reward_commit_settled_elsewhere(
    const struct reward_commit_ctx *c, const char *id_hex)
{
    if (c->detail && c->detail_size > 0)
        snprintf(c->detail, c->detail_size,
                 "entry %s settled by another plan", id_hex);
    return VCS_REWARD_COMMIT_STALE;
}

/* True when an accepted row of this batch already claims the entry's
 * (release, contributor, category). */
static bool reward_commit_batch_dup(const struct reward_commit_ctx *c,
                                    const struct vcs_reward_entry *e)
{
    for (size_t a = 0; a < c->addition_count; a++)
        if (c->accepted_cats[a] == (uint8_t)e->category &&
            memcmp(c->accepted_roots[a], e->release_root, 32) == 0 &&
            memcmp(c->contributors[a], e->contributor, 33) == 0)
            return true;
    return false;
}

/* Pass 1 state check of one PLANNED row: a missing or rejected entry, or one
 * whose settlement belongs to another plan, is STALE; a durable fact marks
 * the row resumed. */
static enum vcs_reward_commit_error reward_commit_check_state(
    struct reward_commit_ctx *c, size_t i, const struct vcs_reward_plan_row *r,
    const struct vcs_reward_entry *e, const char *id_hex)
{
    if (!e)
        return reward_commit_missing(c, id_hex);
    if (e->state == VCS_REWARD_STATE_REJECTED) {
        if (c->detail && c->detail_size > 0)
            snprintf(c->detail, c->detail_size, "entry %s rejected (%s)",
                     id_hex, e->rejected_rule);
        return VCS_REWARD_COMMIT_STALE;
    }
    const struct vcs_reward_fact *fact = reward_fact_find(c->l, r->entry_id);
    if (e->state == VCS_REWARD_STATE_SETTLED) {
        if (reward_id_cmp(e->settled_by_plan, c->plan_id) != 0 || !fact)
            return reward_commit_settled_elsewhere(c, id_hex);
        c->resumed[i] = true; /* replay of an interrupted commit */
    } else if (fact && reward_id_cmp(fact->plan_id, c->plan_id) != 0) {
        return reward_commit_settled_elsewhere(c, id_hex);
    } else if (fact) {
        c->resumed[i] = true; /* fact durable, queue update crashed */
    }
    return VCS_REWARD_COMMIT_OK;
}

/* Pass 1 cap check of one PLANNED row: a duplicate is REJECTED without a cap
 * check; otherwise the cap is recomputed exactly and an accepted row is added
 * to the batch. */
static enum vcs_reward_commit_error reward_commit_check_caps(
    struct reward_commit_ctx *c, size_t i, const struct vcs_reward_plan_row *r,
    const struct vcs_reward_entry *e, const char *id_hex)
{
    /* A same-(release, contributor, category) fact from ANOTHER
     * plan appeared since the plan was made: this entry can never
     * settle — reject it with the named rule, settle the rest.
     * The within-batch walk below catches the same collision
     * between two rows of THIS plan (defense in depth: plan_build
     * already excludes it). */
    if (!c->resumed[i] &&
        (reward_fact_duplicate(c->l, e->release_root, e->contributor,
                               e->category, c->plan_id) ||
         reward_commit_batch_dup(c, e))) {
        c->rejected[i] = true;
        return VCS_REWARD_COMMIT_OK;
    }

    /* Exact cap recomputation against the current ledger. */
    struct vcs_score_period_entry
        history[VCS_REWARD_MAX_FACTS + VCS_REWARD_MAX_BATCH_ENTRIES];
    size_t hcount = reward_history_for(c->l, e->contributor, c->plan_id,
                                       history, VCS_REWARD_MAX_FACTS);
    for (size_t a = 0; a < c->addition_count; a++) {
        if (memcmp(c->contributors[a], e->contributor, 33) == 0 &&
            hcount < sizeof(history) / sizeof(history[0]))
            history[hcount++] = c->additions[a];
    }
    struct vcs_score_period_caps caps;
    vcs_score_apply_period_caps(history, hcount, c->plan->day,
                                r->points_requested, &caps);
    if (caps.allowed_score != r->points_settled ||
        caps.daily_release_cap_hit) {
        if (c->detail && c->detail_size > 0)
            snprintf(c->detail, c->detail_size,
                     "entry %s: allowed %u != planned %u", id_hex,
                     caps.allowed_score, r->points_settled);
        return VCS_REWARD_COMMIT_CAPS_CHANGED;
    }
    if (!c->rejected[i] &&
        c->addition_count < VCS_REWARD_MAX_BATCH_ENTRIES) {
        c->additions[c->addition_count].day = c->plan->day;
        c->additions[c->addition_count].score = r->points_settled;
        memcpy(c->contributors[c->addition_count], e->contributor, 33);
        memcpy(c->accepted_roots[c->addition_count], e->release_root, 32);
        c->accepted_cats[c->addition_count] = (uint8_t)e->category;
        c->addition_count++;
    }
    return VCS_REWARD_COMMIT_OK;
}

enum vcs_reward_commit_error reward_commit_validate_planned(
    struct reward_commit_ctx *c)
{
    /* PASS 1 — validate every PLANNED row against the CURRENT ledger.
     * Nothing is written in this pass. Batch additions for the cap
     * recomputation accumulate in entry-id order exactly as plan_build
     * did, with this plan's own settled facts excluded (they are the
     * result, not the input). */
    for (size_t i = 0; i < c->plan->row_count; i++) {
        const struct vcs_reward_plan_row *r = &c->plan->rows[i];
        if (r->disposition != VCS_REWARD_DISP_PLANNED)
            continue;
        const struct vcs_reward_entry *e =
            vcs_reward_ledger_find(c->l, r->entry_id);
        char id_hex[65];
        zcl_hex_encode(r->entry_id, 32, id_hex);
        enum vcs_reward_commit_error err =
            reward_commit_check_state(c, i, r, e, id_hex);
        if (err == VCS_REWARD_COMMIT_OK)
            err = reward_commit_check_caps(c, i, r, e, id_hex);
        if (err != VCS_REWARD_COMMIT_OK)
            return err;
    }
    return VCS_REWARD_COMMIT_OK;
}
