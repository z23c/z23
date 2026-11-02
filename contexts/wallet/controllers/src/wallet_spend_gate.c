/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Phone spend rule gate. See controllers/wallet_spend_gate.h. */

#include "controllers/wallet_spend_gate.h"

#include "chain/chain.h"
#include "chain/checkpoints.h"
#include "controllers/sovereignty_controller.h"
#include "controllers/wallet_helpers.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/wallet_tx.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>

static void gate_reason(char *reason, size_t cap, const char *token)
{
    if (reason && cap)
        snprintf(reason, cap, "%s", token);
}

static bool gate_bytes_set(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (p[i])
            return true;
    return false;
}

/* Walk pprev from `from` down to `height`; NULL when the header chain has a
 * gap or `height` is above `from`. */
static const struct block_index *gate_ancestor(const struct block_index *from,
                                               int64_t height)
{
    if (!from || height < 0 || height > from->nHeight)
        return NULL;
    while (from && from->nHeight > height)
        from = from->pprev;
    return (from && from->nHeight == height) ? from : NULL;
}

/* One baked checkpoint: hash on the tip's ancestry, and the header Sapling
 * root at the frontier height equals the baked frontier root. */
static const char *gate_check_one(const struct block_index *tip,
                                  const struct rom_state_checkpoint *cp)
{
    if (!gate_bytes_set(cp->block_hash, 32) ||
        !gate_bytes_set(cp->sapling_frontier_root, 32) ||
        cp->height <= 0 || cp->sapling_frontier_height <= 0 ||
        cp->sapling_frontier_height > cp->height)
        return "checkpoint_missing";
    const struct block_index *at = gate_ancestor(tip, cp->height);
    if (!at)
        return "checkpoint_missing";
    if (memcmp(at->hashBlock.data, cp->block_hash, 32) != 0)
        return "tip_not_descended";
    const struct block_index *fb =
        gate_ancestor(at, cp->sapling_frontier_height);
    if (!fb)
        return "checkpoint_missing";
    if (memcmp(fb->hashFinalSaplingRoot.data, cp->sapling_frontier_root,
               32) != 0)
        return "checkpoint_mismatch";
    return NULL;
}

static const char *gate_check_checkpoints(const struct block_index *tip,
                                          int32_t hstar)
{
    const struct rom_state_checkpoint *ks = get_rom_state_checkpoint();
    if (!ks || ks->height <= 0 || ks->height > hstar)
        return "checkpoint_missing";
    const char *bad = gate_check_one(tip, ks);
    if (bad)
        return bad;
    size_t n = get_rom_state_rung_count();
    for (size_t i = 0; i < n; i++) {
        const struct rom_state_rung *r = get_rom_state_rung_at(i);
        if (!r || r->cp.height > hstar)
            continue;
        bad = gate_check_one(tip, &r->cp);
        if (bad)
            return bad;
    }
    return NULL;
}

static const char *gate_floor(const struct rom_state_checkpoint *ks,
                              int32_t *floor_height)
{
    int64_t cursor = 0;
    if (!sovereignty_history_cursor(&cursor) || cursor < 0 ||
        cursor > INT32_MAX)
        return "floor_unknown";
    *floor_height = (int32_t)(cursor > ks->height ? cursor : ks->height);
    return NULL;
}

/* The validated tip block, and that it is not behind the best header. */
static const char *gate_tip(const struct main_state *ms, int32_t hstar,
                            const struct block_index **tip)
{
    if (!ms || hstar <= 0)
        return "tip_not_validated";
    *tip = active_chain_at(&ms->chain_active, hstar);
    if (!*tip || !gate_bytes_set((*tip)->hashFinalSaplingRoot.data, 32))
        return "tip_not_validated";
    if (ms->pindex_best_header &&
        ms->pindex_best_header->nHeight > hstar + WALLET_SPEND_TIP_SLACK)
        return "behind_tip";
    return NULL;
}

/* The header Sapling root at the tip must be a recorded anchor of the
 * reducer ledger. */
static const char *gate_ledger(const struct block_index *tip)
{
    int found = sovereignty_sapling_ledger_has_root(
        tip->hashFinalSaplingRoot.data);
    if (found < 0)
        return "floor_unknown";
    return found ? NULL : "anchor_root_mismatch";
}

bool wallet_spend_gate_evaluate(const struct main_state *ms, int32_t hstar,
                                int32_t *floor_height,
                                char *reason, size_t reason_cap)
{
    const struct block_index *tip = NULL;
    int32_t floor = WALLET_SPEND_NO_FLOOR;
    if (floor_height)
        *floor_height = WALLET_SPEND_NO_FLOOR;
    const char *bad = gate_tip(ms, hstar, &tip);
    if (!bad)
        bad = gate_check_checkpoints(tip, hstar);
    if (!bad)
        bad = gate_ledger(tip);
    if (!bad)
        bad = gate_floor(get_rom_state_checkpoint(), &floor);
    gate_reason(reason, reason_cap, bad ? bad : "");
    if (bad)
        return false;
    if (floor_height)
        *floor_height = floor;
    return true;
}

bool wallet_spend_gate_check(struct wallet_rpc_context *ctx,
                             int32_t *floor_height,
                             char *reason, size_t reason_cap)
{
    int32_t floor = WALLET_SPEND_NO_FLOOR;
    char why[96] = {0};
    char token[WALLET_SPEND_REASON_MAX] = {0};
    if (floor_height)
        *floor_height = WALLET_SPEND_NO_FLOOR;
    bool option = sovereignty_spend_after_checkpoint_enabled();
    /* The strict guard reads a failed authority lookup as "not borrowed". With
     * the option on, no floor is granted unless the durable self-folded marker
     * reads true; otherwise the rule and its floor apply. */
    if (sovereignty_guard_allow("wallet_spend", why, sizeof(why)) &&
        (!option || sovereignty_self_folded_marker())) {
        gate_reason(reason, reason_cap, "");
        sovereignty_spend_rule_note_verdict("strict_guard");
        return true;
    }
    if (!option) {
        gate_reason(reason, reason_cap, "option_off");
        sovereignty_spend_rule_note_verdict("option_off");
        return false;
    }
    bool ok = wallet_spend_gate_evaluate(
        ctx ? ctx->main_state : NULL, reducer_frontier_external_tip_height(),
        &floor, token, sizeof(token));
    gate_reason(reason, reason_cap, token);
    sovereignty_spend_rule_note_verdict(ok ? "allowed_after_floor" : token);
    if (!ok) {
        LOG_WARN("wallet_spend", "spend-after-checkpoint refused: %s", token);
        return false;
    }
    if (floor_height)
        *floor_height = floor;
    return true;
}

bool wallet_spend_gate_witness_root_ok(const struct main_state *ms,
                                       int witness_height,
                                       const uint8_t root[32])
{
    if (!ms || !root || witness_height <= 0)
        return false;
    const struct block_index *bi =
        active_chain_at(&ms->chain_active, witness_height);
    return bi && gate_bytes_set(bi->hashFinalSaplingRoot.data, 32) &&
           memcmp(bi->hashFinalSaplingRoot.data, root, 32) == 0;
}

bool wallet_spend_gate_height_ok(int32_t floor_height, int32_t height)
{
    return floor_height == WALLET_SPEND_NO_FLOOR || height > floor_height;
}

void wallet_spend_gate_shortfall_message(char *out, size_t cap, int64_t need,
                                         int64_t have)
{
    if (!out || !cap)
        return;
    snprintf(out, cap,
             "Error: spend refused — insufficient_post_checkpoint_funds "
             "(short by %lld zat; funds received at or before the floor are not "
             "usable yet)",
             (long long)(need > have ? need - have : 0));
}

bool wallet_spend_gate_for_send(struct wallet_rpc_context *ctx,
                                bool checkpoint_rule, int32_t *floor_height,
                                struct json_value *result)
{
    char why[96] = {0};
    bool allowed = checkpoint_rule
        ? wallet_spend_gate_check(ctx, floor_height, why, sizeof(why))
        : sovereignty_guard_allow("wallet_spend", why, sizeof(why));
    if (allowed)
        return true;
    if (checkpoint_rule && strcmp(why, "option_off") != 0) {
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "Error: spend refused — spend-after-checkpoint check "
                 "failed: %s", why);
        json_set_str(result, msg);
    } else {
        json_set_str(result, "Error: spend refused — tip is release_assisted "
                             "(borrowed shielded history, not self-folded)");
    }
    LOG_FAIL("wallet_shielded", "z_sendmany: refused — %s", why);
}

bool wallet_spend_gate_short_funds(struct json_value *result, int32_t floor,
                                   int64_t need, int64_t have,
                                   const char *tag, const char *plain_text)
{
    char msg[160];
    if (floor == WALLET_SPEND_NO_FLOOR) {
        json_set_str(result, plain_text);
        LOG_FAIL("wallet_shielded", "z_sendmany: insufficient %s funds",
                 tag);
    }
    wallet_spend_gate_shortfall_message(msg, sizeof(msg), need, have);
    json_set_str(result, msg);
    LOG_FAIL("wallet_shielded",
             "z_sendmany: refused — insufficient post-checkpoint %s funds",
             tag);
}

const char *wallet_spend_gate_no_notes_text(int32_t floor)
{
    return floor == WALLET_SPEND_NO_FLOOR
        ? "No unspent shielded notes for this address"
        : "Error: spend refused — insufficient_post_checkpoint_funds (funds "
          "received at or before the floor are not usable yet)";
}
