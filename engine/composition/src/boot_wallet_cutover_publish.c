/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: guarded publication of replayed wallet checkpoint state. */
#include "config/boot_wallet_cutover_publish.h"
#include "platform/time_compat.h"
#include "wallet/wallet_lock.h"
#include "util/log_macros.h"
#include "boot_wallet_cutover_empty_internal.h"
#include "config/boot_wallet_cutover_replay.h"
#include "config/boot_wallet_cutover_coins.h"
#include "controllers/wallet_helpers.h"
#include "controllers/wallet_private_broadcast.h"
#include "models/database.h"
#include "models/wallet_tx.h"
#include "services/wallet_private_relay.h"
#include "storage/coins_kv_read_snapshot.h"
#include "validation/main_state.h"
#include "wallet/wallet_sqlite.h"
#include "util/safe_alloc.h"
#include <limits.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#ifdef ZCL_TESTING
static void (*g_bcp_before_final)(void *);
static void *g_bcp_before_final_ctx;
void boot_cutover_publish_test_before_final(void (*hook)(void *), void *ctx)
{
    g_bcp_before_final = hook;
    g_bcp_before_final_ctx = ctx;
}
static void bcp_test_before_final(void)
{
    if (g_bcp_before_final) g_bcp_before_final(g_bcp_before_final_ctx);
}
#else
static void bcp_test_before_final(void) { }
#endif

static bool bcp_lock_archive_chains(struct boot_cutover_replay *r)
{
    if (!r->canonical_state) return true;
    struct main_state *archive = r->ctx->main_state;
    if (!archive || archive == r->canonical_state ||
        !zcl_mutex_trylock(&r->canonical_state->cs_main)) return false;
    if (!zcl_mutex_trylock(&archive->cs_main)) {
        zcl_mutex_unlock(&r->canonical_state->cs_main);
        return false;
    }
    return true;
}

static void bcp_unlock_archive_chains(struct boot_cutover_replay *r)
{
    if (!r->canonical_state) return;
    zcl_mutex_unlock(&r->ctx->main_state->cs_main);
    zcl_mutex_unlock(&r->canonical_state->cs_main);
}

struct bcp_height { struct uint256 hash; int height; };
struct bcp_context {
    struct boot_cutover_replay *replay;
    struct wpr_pending_guard *guard;
    struct boot_cutover_coins *coins;
    struct bcp_height *heights;
    size_t count;
};

static int bcp_compare(const void *a, const void *b)
{
    return memcmp(((const struct bcp_height *)a)->hash.data,
                  ((const struct bcp_height *)b)->hash.data, 32);
}

static bool bcp_resolve(void *opaque, const uint8_t hash[32], int *height)
{
    struct bcp_context *ctx = opaque;
    struct bcp_height key = {0}; memcpy(key.hash.data, hash, 32);
    const struct bcp_height *found = bsearch(&key, ctx->heights, ctx->count,
                                             sizeof(*ctx->heights), bcp_compare);
    if (!found || !height) return false;
    *height = found->height;
    return true;
}

static size_t bcp_mark_height(struct bcp_context *ctx, const struct block_index *p)
{
    struct bcp_height key = {.hash = *p->phashBlock};
    struct bcp_height *found = bsearch(&key, ctx->heights, ctx->count,
                                       sizeof(*ctx->heights), bcp_compare);
    if (!found) return 0;
    size_t index = (size_t)(found - ctx->heights), marked = 0;
    while (index > 0 && !bcp_compare(&ctx->heights[index - 1], &key)) index--;
    while (index < ctx->count && !bcp_compare(&ctx->heights[index], &key)) {
        if (ctx->heights[index].height < 0) {
            ctx->heights[index].height = p->nHeight; marked++;
        }
        index++;
    }
    return marked;
}

static bool bcp_walk_heights(struct bcp_context *ctx, struct block_index *p)
{
    size_t remaining = ctx->count;
    while (p && remaining) {
        if (!p->phashBlock || p->nHeight < 0 ||
            memcmp(p->phashBlock->data, p->hashBlock.data, 32)) return false;
        remaining -= bcp_mark_height(ctx, p);
        if (p->pprev && p->pprev->nHeight != p->nHeight - 1) return false;
        p = p->pprev;
    }
    return remaining == 0;
}

/* Called before the final wallet and database locks, with startup quiescence. */
static bool bcp_prepare_heights(struct bcp_context *ctx)
{
    struct boot_cutover_replay *r = ctx->replay;
    struct wallet *w = r->ctx->wallet;
    ctx->heights = zcl_calloc(MAX_WALLET_TX + 1, sizeof(*ctx->heights), "cutover height map");
    if (!ctx->heights || !zcl_mutex_trylock(&w->cs)) return false;
    const uint8_t zero[32] = {0};
    for (size_t i = 0; i < MAX_WALLET_TX; i++) {
        if (w->map_wallet[i].used && memcmp(w->map_wallet[i].hash_block.data, zero, 32))
            ctx->heights[ctx->count++].hash = w->map_wallet[i].hash_block;
    }
    zcl_mutex_unlock(&w->cs);
    ctx->heights[ctx->count++].hash = r->endpoint.hash;
    qsort(ctx->heights, ctx->count, sizeof(*ctx->heights), bcp_compare);
    for (size_t i = 0; i < ctx->count; i++) ctx->heights[i].height = -1;
    struct block_index *tip = active_chain_tip(&r->ctx->main_state->chain_active);
    return tip && tip->nHeight == r->endpoint.height && bcp_walk_heights(ctx, tip);
}

static bool bcp_endpoint(void *opaque, int height, const uint8_t hash[32])
{
    struct bcp_context *ctx = opaque;
    struct boot_cutover_replay *r = ctx->replay;
    if (r->canonical_state && !boot_cutover_replay_archive_chains_current(r)) return false;
    struct block_index *tip = active_chain_tip(&r->ctx->main_state->chain_active);
    return tip && tip->phashBlock && height == r->endpoint.height && tip->nHeight == height &&
        !memcmp(hash, r->endpoint.hash.data, 32) && !memcmp(tip->phashBlock->data, hash, 32) &&
        !memcmp(tip->hashFinalSaplingRoot.data, r->endpoint.root.data, 32);
}

static enum db_wallet_cutover_tx_class bcp_classify(void *opaque, const uint8_t txid[32])
{
    const struct bcp_context *ctx = opaque;
    for (size_t i = 0; i < ctx->guard->count; i++) {
        const struct wpr_pending_record *record = &ctx->guard->records[i];
        if (!record->expired && !memcmp(record->txid.data, txid, 32)) return DB_CUTOVER_TX_ACTIVE;
    }
    return DB_CUTOVER_TX_UNKNOWN;
}

static bool bcp_holds(void *opaque, struct wallet *wallet, sqlite3 *db)
{
    struct bcp_context *ctx = opaque;
    struct wallet_readiness current = wallet_readiness_get_locked(wallet);
    const struct wallet_readiness *expected = &ctx->replay->readiness;
    int64_t deadline = ctx->replay->auth_deadline_ms;
    int64_t now = deadline ? platform_time_monotonic_ms() : 0;
    if (deadline && (now <= 0 || now >= deadline || wallet_lock_is_locked())) return false;
    if (!wallet_sqlite_verify_startup_sapling_in_tx_locked_r(
            ctx->replay->ctx->wallet_db, wallet, db).ok) return false;
    return (!ctx->replay->shielded_empty || boot_wallet_cutover_shielded_empty_locked(
            ctx->replay->ctx->wallet_db, db, wallet, ctx->replay->sapling_load_ok)) &&
        current.state == WALLET_READINESS_PENDING && current.epoch != UINT64_MAX &&
        current.epoch == expected->epoch && current.generation_present == expected->generation_present &&
        current.generation == expected->generation &&
        boot_cutover_coins_matches(ctx->coins, ctx->replay->endpoint.height,
            ctx->replay->endpoint.hash.data, expected->generation, ctx->replay->identity) &&
        wallet_private_broadcast_validate_holds_locked(ctx->guard, wallet, db);
}

static void bcp_rollback(struct node_db *db)
{
    (void)node_db_rollback(db);
    if (!sqlite3_get_autocommit(db->db)) abort();
}

static bool bcp_context_valid(const struct boot_cutover_replay *r)
{
    return r && r->ctx && r->ctx->wallet && r->ctx->wallet_db && r->ctx->node_db &&
        r->ctx->main_state && r->ctx->node_db->open && r->ctx->node_db->db &&
        r->ctx->wallet_db->open && r->ctx->wallet_db->db == r->ctx->node_db->db;
}

static bool bcp_receipt_valid(const struct boot_cutover_replay *r,
                              const struct coins_kv_read_snapshot_info *info)
{
    return info && r->phase == BOOT_CUTOVER_DONE && r->endpoint.height >= 0 &&
        r->endpoint.height < INT_MAX && info->applied_height == r->endpoint.height + 1 &&
        r->readiness.generation_present && info->authority_generation == r->readiness.generation;
}

static bool bcp_arguments(struct boot_cutover_replay *r, struct wpr_pending_guard *guard,
    struct coins_kv_read_snapshot *snapshot, const struct coins_kv_read_snapshot_info *info,
    struct wallet_cutover_v2_plan *plan, struct db_wallet_utxo_cutover_delivery *delivery)
{
    return bcp_context_valid(r) && bcp_receipt_valid(r, info) &&
        guard && guard->relay && guard->count <= WPR_MAX_ENTRIES && snapshot && plan &&
        delivery && !delivery->armed && !delivery->committed && delivery->count == 0;
}

static bool bcp_pool_known(struct coins_kv_read_snapshot *snapshot, int height)
{
    int64_t sprout = 0, sapling = 0;
    bool found = false;
    return coins_kv_read_snapshot_shielded_pool(snapshot, height,
                                               &sprout, &sapling, &found) && found;
}

static bool bcp_preflight(struct boot_cutover_replay *r, struct wpr_pending_guard *guard,
    struct coins_kv_read_snapshot *snapshot, const struct coins_kv_read_snapshot_info *info,
    struct wallet_cutover_v2_plan *plan, struct db_wallet_utxo_cutover_delivery *delivery)
{
    if (!bcp_arguments(r, guard, snapshot, info, plan, delivery)) { LOG_WARN("wallet", "cutover publication refused: arguments"); return false; }
    if (!bcp_pool_known(snapshot, r->endpoint.height)) { LOG_WARN("wallet", "cutover publication refused: pool"); return false; }
    return true;
}

static bool bcp_commit(struct boot_cutover_replay *r, struct wpr_pending_guard *guard,
                       struct wallet_cutover_v2_request *request,
                       struct wallet_cutover_v2_plan *plan, const char **stage)
{
    bcp_test_before_final();
    struct node_db *db = r->ctx->node_db;
    *stage = "connection_lock";
    sqlite3_mutex *mu = sqlite3_db_mutex(db->db);
    if (!mu || sqlite3_mutex_try(mu) != SQLITE_OK) return false;
    bool ok = false;
    *stage = "transaction_begin";
    if (!sqlite3_get_autocommit(db->db) || !node_db_begin_immediate(db)) goto unlock;
    *stage = "reserve_holds";
    if (wallet_private_broadcast_reserve_in_open_tx(guard, db, r->ctx->wallet) != WALLET_HOLD_PROOF_OK) {
        bcp_rollback(db); goto unlock;
    }
    *stage = "completion";
    struct zcl_result result = wallet_sqlite_cutover_complete_v2_in_open_tx_r(
        r->ctx->wallet_db, db, r->ctx->wallet, request, plan);
    if (!result.ok && result.code == WSQL_TXN_BEGIN_FAIL) bcp_rollback(db);
    ok = result.ok;
    if (!result.ok) LOG_WARN("wallet", "cutover completion status=%d", result.code);
unlock:
    sqlite3_mutex_leave(mu);
    return ok;
}


bool boot_wallet_cutover_publish(struct boot_cutover_replay *r,
    struct wpr_pending_guard *guard, struct coins_kv_read_snapshot *snapshot,
    const struct coins_kv_read_snapshot_info *info, struct wallet_cutover_v2_plan *plan,
    struct db_wallet_utxo_cutover_delivery *delivery)
{
    if (!bcp_preflight(r, guard, snapshot, info, plan, delivery)) return false;
    bool auth_lease = r->auth_deadline_ms != 0;
    if (auth_lease && !wallet_lock_startup_publication_begin(r->auth_deadline_ms)) return false;
    if (!bcp_lock_archive_chains(r)) {
        if (auth_lease) wallet_lock_startup_publication_end();
        LOG_WARN("wallet", "cutover publication refused: chain_lock");
        return false;
    }
    struct bcp_context ctx = {.replay = r, .guard = guard};
    bool ok = false;
    const char *stage = "endpoint";
    if (!bcp_endpoint(&ctx, r->endpoint.height, r->endpoint.hash.data)) goto done;
    stage = "heights";
    if (!bcp_prepare_heights(&ctx)) goto done;
    stage = "coin_plan";
    enum boot_cutover_coins_status coin_status = boot_cutover_coins_prepare(r->ctx->wallet, snapshot, info, r->endpoint.height,
            r->endpoint.hash.data, r->readiness.generation, r->identity,
            bcp_resolve, &ctx, &ctx.coins);
    if (coin_status != BOOT_CUTOVER_COINS_OK) { LOG_WARN("wallet", "cutover coin plan status=%d", (int)coin_status); goto done; }
    struct db_wallet_utxo_cutover_projection projection = {.delivery = delivery,
        .classify_unconfirmed = bcp_classify, .classify_ctx = &ctx,
        .reference_coin = boot_cutover_coins_verdict, .reference_coin_ctx = ctx.coins};
    struct wallet_cutover_v2_request request = {.binding = &r->binding,
        .generation_present = r->readiness.generation_present, .generation = r->readiness.generation,
        .reference_height = r->endpoint.height, .resolve = bcp_resolve, .endpoint_current = bcp_endpoint,
        .chain_ctx = &ctx, .holds_valid = bcp_holds, .holds_ctx = &ctx,
        .project = db_wallet_utxo_cutover_project, .projection_ctx = &projection};
    memcpy(request.reference_hash, r->endpoint.hash.data, 32);
    memcpy(request.scan_identity, r->identity, 32);
    ok = bcp_commit(r, guard, &request, plan, &stage);
done:
    if (!ok) LOG_WARN("wallet", "cutover publication refused: %s", stage);
    boot_cutover_coins_free(ctx.coins);
    free(ctx.heights);
    bcp_unlock_archive_chains(r);
    if (auth_lease) wallet_lock_startup_publication_end();
    return ok;
}

bool boot_wallet_cutover_publish_guarded(struct boot_cutover_replay *replay,
    struct wpr *relay, struct db_wallet_utxo_cutover_delivery *delivery)
{
    if (!relay || !delivery || delivery->armed || delivery->committed || delivery->count) {
        LOG_WARN("wallet", "cutover publication refused: guard_arguments");
        return false;
    }
    struct coins_kv_read_snapshot_info info;
    struct coins_kv_read_snapshot *snapshot = coins_kv_read_snapshot_open(&info);
    if (!snapshot) { LOG_WARN("wallet", "cutover publication refused: snapshot"); return false; }
    struct wallet_cutover_v2_plan plan = {0};
    bool ok = false;
    if (wallet_cutover_v2_plan_init(&plan, MAX_WALLET_TX)) {
        struct wpr_pending_guard guard = {0};
        struct wpr_pending_record records[WPR_MAX_ENTRIES];
        size_t count = 0;
        enum wpr_pending_read_status status = wpr_pending_proof_begin(relay,
            &guard, records, WPR_MAX_ENTRIES, &count);
        if (status == WPR_PENDING_OK || status == WPR_PENDING_ABSENT)
            ok = boot_wallet_cutover_publish(replay, &guard, snapshot, &info, &plan, delivery);
        else LOG_WARN("wallet", "cutover relay proof status=%d", (int)status);
        wpr_pending_proof_end(&guard);
    } else LOG_WARN("wallet", "cutover publication refused: plan_allocation");
    wallet_cutover_v2_plan_free(&plan);
    coins_kv_read_snapshot_abort(snapshot);
    return ok;
}
