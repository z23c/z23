/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: reconcile authoritative wallet readers into custody snapshots. */
// one-result-type-ok:wallet-scope predicates are pure total classification

#include "services/wallet_money_service.h"

#include "base/hex.h"
#include "base/serialize_le.h"
#include "chain/chain.h"
#include "crypto/sha3.h"
#include "jobs/reducer_frontier.h"
#include "json/json.h"
#include "models/agent_session.h"
#include "models/database.h"
#include "models/vault_intent.h"
#include "platform/time_compat.h"
#include "services/sync_monitor.h"
#include "services/vault_read.h"
#include "sync/sync_state.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>

static void money_root(struct wallet_money_snapshot *s)
{
    static const char domain[] = "zcl.wallet_money.v2";
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    sha3_256_write(&c, (const uint8_t *)domain, strlen(domain));
    sha3_256_write(&c, (const uint8_t *)s->wallet_scope,
                   strlen(s->wallet_scope));
    sha3_256_write(&c, (const uint8_t *)s->status, strlen(s->status));
    sha3_256_write(&c, (const uint8_t *)s->identity.wallet_instance_id,
                   WALLET_INSTANCE_ID_HEX_LEN);
    sha3_256_write(&c, s->identity.network_genesis, 32);
    sha3_256_write(&c, s->tip_hash, 32);
    uint8_t nums[10][8];
    const int64_t values[10] = {
        s->confirmed_zat, s->transparent_spendable_zat,
        s->shielded_spendable_zat, s->pending_zat, s->encumbered_zat,
        s->intent_reserved_zat, s->lifetime_lab_spent_zat,
        s->agent_available_zat, s->tip_height, s->network_tip_height,
    };
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        zcl_write_i64_le(nums[i], values[i]);
    sha3_256_write(&c, (const uint8_t *)nums, sizeof(nums));
    uint8_t flags[2] = { s->complete ? 1 : 0,
                         strcmp(s->status, "CURRENT") == 0 ? 1 : 0 };
    sha3_256_write(&c, flags, sizeof(flags));
    sha3_256_finalize(&c, s->snapshot_root);
}

int64_t wallet_money_agent_available_for_floor(
    const struct wallet_money_snapshot *s, int64_t reserve_floor_zat)
{
    if (!s || reserve_floor_zat < 0)
        return 0;
    int64_t liquid = s->confirmed_zat - s->intent_reserved_zat;
    if (liquid < 0)
        liquid = 0;
    if (strcmp(s->wallet_scope, "dev") == 0) {
        int64_t above_reserve =
            liquid > reserve_floor_zat ? liquid - reserve_floor_zat : 0;
        int64_t allocated = s->lifetime_lab_spent_zat;
        if (allocated <= INT64_MAX - s->intent_reserved_zat)
            allocated += s->intent_reserved_zat;
        else
            allocated = INT64_MAX;
        int64_t lab_left = allocated < VAULT_INTENT_DEV_LIFETIME_CAP_ZAT
            ? VAULT_INTENT_DEV_LIFETIME_CAP_ZAT - allocated : 0;
        return above_reserve < lab_left ? above_reserve : lab_left;
    } else if (strcmp(s->wallet_scope, "prod") == 0) {
        /* Production is deliberately unfunded/unallocated in this rollout.
         * A later owner grant may define a non-zero production policy. */
        return 0;
    } else {
        /* Isolated test custody is bounded by its own liquid balance. */
        return liquid;
    }
}

static void money_agent_available(struct wallet_money_snapshot *s)
{
    s->agent_available_zat = wallet_money_agent_available_for_floor(
        s, VAULT_INTENT_DEV_RESERVE_FLOOR_ZAT);
}

bool wallet_money_snapshot_after_reservation(
    const struct wallet_money_snapshot *before, int64_t reservation_zat,
    struct wallet_money_snapshot *after)
{
    if (!before || !after || before == after || reservation_zat <= 0 ||
        !before->complete || strcmp(before->status, "CURRENT") != 0 ||
        !wallet_money_scope_valid(before->wallet_scope) ||
        before->intent_reserved_zat < 0 ||
        before->intent_reserved_zat > INT64_MAX - reservation_zat ||
        before->confirmed_zat <
            before->intent_reserved_zat + reservation_zat ||
        (strcmp(before->wallet_scope, "dev") == 0 &&
         reservation_zat > before->agent_available_zat))
        return false;

    *after = *before;
    after->intent_reserved_zat += reservation_zat;
    money_agent_available(after);
    (void)snprintf(after->reason, sizeof(after->reason),
                   "all money authorities read; reservation included");
    money_root(after);
    return true;
}

enum wallet_money_freshness wallet_money_freshness_classify(
    bool hstar_published, int32_t hstar, int32_t money_tip,
    int32_t network_tip, size_t peer_count, enum sync_state state)
{
    if (!hstar_published || hstar < 0 || money_tip < 0 || network_tip < 0 ||
        peer_count == 0)
        return WALLET_MONEY_FRESHNESS_UNKNOWN;
    const bool live_catchup_state =
        state == SYNC_BLOCKS_DOWNLOAD ||
        state == SYNC_CONNECTING_BLOCKS ||
        state == SYNC_AT_TIP;
    const int64_t fold_edge = (int64_t)money_tip - (int64_t)hstar;
    /* The sovereignty spend gate requires coins_applied_height == H* + 1,
     * which is exactly money_tip == H*.  Calling a one-block run-ahead money
     * view CURRENT advertises a spend-ready snapshot that every wallet
     * mutation must immediately refuse.  Keep that transient state STALE. */
    if (money_tip < network_tip || fold_edge != 0 ||
        !live_catchup_state)
        return WALLET_MONEY_FRESHNESS_STALE;
    return WALLET_MONEY_FRESHNESS_CURRENT;
}

bool wallet_money_scope_valid(const char *wallet_scope)
{
    return wallet_scope &&
        (strcmp(wallet_scope, "dev") == 0 ||
         strcmp(wallet_scope, "prod") == 0 ||
         strcmp(wallet_scope, "test") == 0);
}

const char *wallet_money_scope_expected_lane(const char *wallet_scope)
{
    if (!wallet_money_scope_valid(wallet_scope))
        return NULL;
    return strcmp(wallet_scope, "prod") == 0 ? "canonical" : wallet_scope;
}

const char *wallet_money_scope_for_lane(const char *operator_lane)
{
    if (!operator_lane)
        return NULL;
    if (strcmp(operator_lane, "canonical") == 0)
        return "prod";
    if (strcmp(operator_lane, "dev") == 0)
        return "dev";
    if (strcmp(operator_lane, "test") == 0)
        return "test";
    return NULL;
}

struct money_chain_view {
    int32_t target_height;
    size_t peer_count;
    enum sync_state sync_state;
    bool money_tip_matches_active;
};

static struct money_chain_view money_chain_view_capture(
    struct main_state *main_state, int32_t money_tip,
    const uint8_t money_tip_hash[32])
{
    struct money_chain_view view = {
        .target_height = -1,
        .sync_state = sync_get_state(),
    };
    int32_t active_height = -1;
    int32_t header_height = -1;
    zcl_mutex_lock(&main_state->cs_main);
    struct block_index *tip = active_chain_at(&main_state->chain_active,
                                              money_tip);
    active_height = active_chain_height(&main_state->chain_active);
    header_height = main_state->pindex_best_header
        ? main_state->pindex_best_header->nHeight : active_height;
    view.money_tip_matches_active = tip && tip->nHeight == money_tip &&
        memcmp(tip->hashBlock.data, money_tip_hash, 32) == 0;
    zcl_mutex_unlock(&main_state->cs_main);

    struct connman *cm = sync_monitor_connman();
    view.peer_count = cm ? connman_get_node_count(cm) : 0;
    int32_t peer_height = cm ? connman_max_peer_height(cm) : -1;
    view.target_height = active_height;
    if (header_height > view.target_height)
        view.target_height = header_height;
    if (peer_height > view.target_height)
        view.target_height = peer_height;
    return view;
}

static bool money_classes_complete(const struct vault_snapshot *v,
                                   char *reason, size_t reason_cap)
{
    for (int i = 0; i < VAULT_CLASS_COUNT; i++) {
        if (v->rows[i].is_money && !v->rows[i].determined) {
            (void)snprintf(reason, reason_cap, "%s: %s",
                           v->rows[i].class_name, v->rows[i].reason);
            return false;
        }
    }
    return true;
}

struct zcl_result wallet_money_snapshot_build(
    struct node_db *ndb, struct main_state *main_state,
    const char *wallet_scope, struct wallet_money_snapshot *out)
{
    if (!ndb || !ndb->open || !main_state || !out ||
        !wallet_money_scope_valid(wallet_scope))
        return ZCL_ERR(-1,
                       "open node_db, main_state, and dev|prod|test scope are required");
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->wallet_scope, sizeof(out->wallet_scope), "%s",
                   wallet_scope);
    (void)snprintf(out->status, sizeof(out->status), "UNKNOWN");
    out->tip_height = -1;
    out->network_tip_height = -1;
    out->observed_at = (int64_t)platform_time_wall_time_t();

    if (!wallet_identity_find(ndb, &out->identity)) {
        (void)snprintf(out->reason, sizeof(out->reason),
                       "wallet identity is not initialized");
        money_root(out);
        return ZCL_OK;
    }
    const char *expected_lane = wallet_money_scope_expected_lane(wallet_scope);
    if (strcmp(out->identity.operator_lane, expected_lane) != 0) {
        (void)snprintf(out->status, sizeof(out->status), "CONFLICTED");
        (void)snprintf(out->reason, sizeof(out->reason),
                       "wallet scope does not match persisted operator lane");
        money_root(out);
        return ZCL_OK;
    }

    bool hstar_published = reducer_frontier_provable_tip_is_published();
    int32_t hstar = reducer_frontier_provable_tip_cached();
    int32_t money_tip = -1;
    uint8_t money_tip_hash[32] = { 0 };
    bool money_tip_hash_found = false;
    if (!reducer_frontier_derive_coins_best_now(
            &money_tip, money_tip_hash, &money_tip_hash_found) ||
        !money_tip_hash_found) {
        (void)snprintf(out->reason, sizeof(out->reason),
                       "authoritative wallet coins tip is unavailable");
        money_root(out);
        return ZCL_OK;
    }
    struct money_chain_view before = money_chain_view_capture(
        main_state, money_tip, money_tip_hash);
    if (!before.money_tip_matches_active) {
        (void)snprintf(out->reason, sizeof(out->reason),
                       "wallet coins tip differs from the active chain");
        money_root(out);
        return ZCL_OK;
    }
    out->tip_height = money_tip;
    memcpy(out->tip_hash, money_tip_hash, sizeof(out->tip_hash));
    out->network_tip_height = before.target_height;
    enum wallet_money_freshness freshness = wallet_money_freshness_classify(
        hstar_published, hstar, money_tip, out->network_tip_height,
        before.peer_count, before.sync_state);
    if (freshness != WALLET_MONEY_FRESHNESS_CURRENT) {
        (void)snprintf(out->status, sizeof(out->status), "%s",
                       freshness == WALLET_MONEY_FRESHNESS_STALE
                           ? "STALE" : "UNKNOWN");
        if (freshness == WALLET_MONEY_FRESHNESS_STALE &&
            out->network_tip_height > money_tip)
            (void)snprintf(out->reason, sizeof(out->reason),
                           "wallet coins tip is %d blocks behind network tip",
                           out->network_tip_height - money_tip);
        else if (freshness == WALLET_MONEY_FRESHNESS_STALE &&
                 money_tip != hstar)
            (void)snprintf(out->reason, sizeof(out->reason),
                           money_tip == hstar + 1
                               ? "wallet coins tip is one block ahead of the proven fold edge"
                               : "wallet coins tip is outside the proven fold edge");
        else if (freshness == WALLET_MONEY_FRESHNESS_STALE)
            (void)snprintf(out->reason, sizeof(out->reason),
                           "node sync state is %s",
                           sync_state_name(before.sync_state));
        else
            (void)snprintf(out->reason, sizeof(out->reason),
                           "network tip freshness is unavailable");
        money_root(out);
        return ZCL_OK;
    }

    struct vault_snapshot vault;
    struct zcl_result vr = vault_read_snapshot(ndb, &vault);
    if (!vr.ok) {
        (void)snprintf(out->reason, sizeof(out->reason),
                       "vault snapshot failed: %.120s", vr.message);
        money_root(out);
        return ZCL_OK;
    }
    out->confirmed_zat = vault.zcl_spendable;
    out->transparent_spendable_zat =
        vault.rows[VAULT_CLASS_TRANSPARENT].spendable;
    out->shielded_spendable_zat =
        vault.rows[VAULT_CLASS_SHIELDED].spendable;
    out->pending_zat = vault.zcl_pending;
    out->encumbered_zat = vault.zcl_encumbered + vault.zcl_immature;
    out->intent_reserved_zat = vault_intent_reserved_total_at(
        ndb, wallet_scope, out->identity.wallet_instance_id,
        out->observed_at);
    int64_t direct_lifetime =
        agent_session_scope_lifetime_spent(ndb, wallet_scope);
    int64_t completed_intents = vault_intent_unbound_completed_total(
        ndb, wallet_scope, out->identity.wallet_instance_id);
    out->lifetime_lab_spent_zat =
        direct_lifetime >= 0 && completed_intents >= 0 &&
        direct_lifetime <= INT64_MAX - completed_intents
            ? direct_lifetime + completed_intents : -1;
    if (out->intent_reserved_zat < 0 ||
        out->lifetime_lab_spent_zat < 0) {
        (void)snprintf(out->reason, sizeof(out->reason),
                       "reservation or lifetime allocation reader failed");
        money_root(out);
        return ZCL_OK;
    }
    if (!money_classes_complete(&vault, out->reason, sizeof(out->reason))) {
        money_root(out);
        return ZCL_OK;
    }

    money_agent_available(out);

    /* The authoritative readers live in separate stores. Re-read both chain
     * witnesses after the vault/intent reads and publish numbers only when the
     * exact money tip, active/header/peer target, and freshness classification
     * stayed unchanged for the whole observation. */
    int32_t money_tip_after = -1;
    uint8_t money_tip_hash_after[32] = { 0 };
    bool money_tip_hash_after_found = false;
    bool money_after_ok = reducer_frontier_derive_coins_best_now(
        &money_tip_after, money_tip_hash_after,
        &money_tip_hash_after_found);
    struct money_chain_view after = {
        .target_height = -1,
        .sync_state = sync_get_state(),
    };
    if (money_after_ok && money_tip_hash_after_found)
        after = money_chain_view_capture(
            main_state, money_tip_after, money_tip_hash_after);
    bool hstar_after_published =
        reducer_frontier_provable_tip_is_published();
    int32_t hstar_after = reducer_frontier_provable_tip_cached();
    enum wallet_money_freshness freshness_after =
        wallet_money_freshness_classify(
            hstar_after_published, hstar_after, money_tip_after,
            after.target_height, after.peer_count, after.sync_state);
    if (!money_after_ok || !money_tip_hash_after_found ||
        !after.money_tip_matches_active || money_tip_after != money_tip ||
        memcmp(money_tip_hash_after, money_tip_hash,
               sizeof(money_tip_hash)) != 0 ||
        after.target_height != before.target_height ||
        freshness_after != WALLET_MONEY_FRESHNESS_CURRENT) {
        out->network_tip_height = after.target_height;
        (void)snprintf(out->status, sizeof(out->status), "STALE");
        (void)snprintf(out->reason, sizeof(out->reason),
                       "money authorities changed during observation");
        money_root(out);
        return ZCL_OK;
    }
    out->complete = true;
    (void)snprintf(out->status, sizeof(out->status), "CURRENT");
    (void)snprintf(out->reason, sizeof(out->reason), "all money authorities read");
    money_root(out);
    return ZCL_OK;
}

struct zcl_result wallet_money_snapshot_build_current(
    struct node_db *ndb, struct main_state *main_state,
    struct wallet_money_snapshot *out)
{
    if (!ndb || !ndb->open || !main_state || !out)
        return ZCL_ERR(-1, "open node_db, main_state, and output are required");

    struct wallet_identity_row identity;
    if (!wallet_identity_find(ndb, &identity))
        return ZCL_ERR(-2, "wallet identity is not initialized");

    const char *scope = wallet_money_scope_for_lane(identity.operator_lane);
    if (!scope)
        return ZCL_ERR(-3, "wallet operator lane has no custody scope");

    return wallet_money_snapshot_build(ndb, main_state, scope, out);
}

static void amount_text(int64_t zat, char out[32])
{
    (void)snprintf(out, 32, "%lld.%08lld",
                   (long long)(zat / 100000000LL),
                   (long long)(zat >= 0 ? zat % 100000000LL
                                        : -(zat % 100000000LL)));
}

struct zcl_result wallet_money_snapshot_to_json(
    const struct wallet_money_snapshot *s, struct json_value *out)
{
    if (!s || !out)
        return ZCL_ERR(-1, "snapshot and JSON output are required");
    json_set_object(out);
    char genesis[65], tip[65], root[65], amount[32];
    wallet_identity_genesis_hex(&s->identity, genesis);
    zcl_hex_encode(s->tip_hash, 32, tip);
    zcl_hex_encode(s->snapshot_root, 32, root);
    (void)json_push_kv_str(out, "wallet_scope", s->wallet_scope);
    (void)json_push_kv_str(out, "wallet_instance_id",
                           s->identity.wallet_instance_id);
    (void)json_push_kv_str(out, "network_genesis", genesis);
    (void)json_push_kv_str(out, "operator_lane", s->identity.operator_lane);
    (void)json_push_kv_str(out, "status", s->status);
    (void)json_push_kv_str(out, "freshness", s->status);
    (void)json_push_kv_bool(out, "complete", s->complete);
    (void)json_push_kv_str(out, "reason", s->reason);
    if (s->complete && strcmp(s->status, "CURRENT") == 0) {
#define PUSH_AMOUNT(key_, member_) do {                                      \
        amount_text((member_), amount);                                      \
        (void)json_push_kv_str(out, (key_), amount);                         \
} while (0)
        PUSH_AMOUNT("confirmed_zcl", s->confirmed_zat);
        PUSH_AMOUNT("transparent_spendable_zcl",
                    s->transparent_spendable_zat);
        PUSH_AMOUNT("shielded_spendable_zcl", s->shielded_spendable_zat);
        PUSH_AMOUNT("pending_zcl", s->pending_zat);
        PUSH_AMOUNT("encumbered_zcl", s->encumbered_zat);
        PUSH_AMOUNT("intent_reserved_zcl", s->intent_reserved_zat);
        PUSH_AMOUNT("agent_available_zcl", s->agent_available_zat);
#undef PUSH_AMOUNT
        (void)json_push_kv_int(out, "confirmed_zat", s->confirmed_zat);
        (void)json_push_kv_int(out, "transparent_spendable_zat",
                               s->transparent_spendable_zat);
        (void)json_push_kv_int(out, "shielded_spendable_zat",
                               s->shielded_spendable_zat);
        (void)json_push_kv_int(out, "pending_zat", s->pending_zat);
        (void)json_push_kv_int(out, "encumbered_zat", s->encumbered_zat);
        (void)json_push_kv_int(out, "intent_reserved_zat",
                               s->intent_reserved_zat);
        (void)json_push_kv_int(out, "agent_available_zat",
                               s->agent_available_zat);
    } else {
        (void)json_push_kv_str(out, "confirmed_zcl", "UNKNOWN");
        (void)json_push_kv_str(out, "transparent_spendable_zcl", "UNKNOWN");
        (void)json_push_kv_str(out, "shielded_spendable_zcl", "UNKNOWN");
        (void)json_push_kv_str(out, "pending_zcl", "UNKNOWN");
        (void)json_push_kv_str(out, "encumbered_zcl", "UNKNOWN");
        (void)json_push_kv_str(out, "intent_reserved_zcl", "UNKNOWN");
        (void)json_push_kv_str(out, "agent_available_zcl", "UNKNOWN");
    }
    (void)json_push_kv_int(out, "tip_height", s->tip_height);
    (void)json_push_kv_int(out, "network_tip_height",
                           s->network_tip_height);
    (void)json_push_kv_str(out, "tip_hash", tip);
    (void)json_push_kv_int(out, "observed_at", s->observed_at);
    (void)json_push_kv_str(out, "snapshot_root", root);
    return ZCL_OK;
}
