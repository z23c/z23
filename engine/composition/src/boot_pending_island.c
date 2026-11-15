/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: prove a staged rung header window for one pending wallet-cutover
 * boot and register it as an island in memory only.
 *
 * A legacy bundle install at a baked rung leaves a PENDING cutover whose next
 * boot rebuilds the block index from the projection only. On a node whose
 * header chain came from the solutionless header seed, that index holds no row
 * for the coins tip, so the unchanged pending restore refuses. The install-ready
 * condition staged the 28 full headers rung-27..rung in the existing
 * header_solution_repair table before it armed the install. This boot loads
 * them through the restore's own loader, proves them with the verifier every
 * persisted island window gets (hash links down from the compiled rung hash,
 * frozen PoW and Equihash, root work from the compiled rung chainwork), inserts
 * the rows into this boot's map without emitting events and registers the
 * island in memory. Nothing about the island is written anywhere durable. The
 * boot never starts services: once the existing replay completes the cutover it
 * hands off to one more boot, which loads the full flat index as before. */

#include "boot_cutover_startup_internal.h"

#include "chain/checkpoints.h"
#include "config/flysync_island.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "services/island_anchor.h"
#include "storage/node_db_runtime.h"
#include "storage/progress_store.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "wallet/wallet_sqlite.h"

#include <stdlib.h>
#include <string.h>

#define BPI_SUBSYS "wallet"

static bool g_bpi_active;
/* Set only by boot_pending_island_restart_due, which boot_pending_finish
 * reaches after the existing replay returned BOOT_PENDING_COMPLETE. */
static bool g_bpi_completed;
static struct wallet_cutover_binding g_bpi_completed_binding;

/* A compiled ladder rung strictly above the keystone, at this exact hash. */
static bool bpi_target_is_rung(int32_t height, const uint8_t hash[32])
{
    const struct rom_state_checkpoint *keystone = get_rom_state_checkpoint();
    if (!keystone || height <= keystone->height) return false;
    for (size_t i = 0; i < get_rom_state_rung_count(); i++) {
        const struct rom_state_rung *r = get_rom_state_rung_at(i);
        if (r && r->cp.height == height) return memcmp(r->cp.block_hash, hash, 32) == 0;
    }
    return false;
}

/* The measured state only: a legacy pending cutover from a fresh coins state
 * (old_height 0) to a rung, the coins tip at that rung and absent from this
 * boot's index, FlySync off, and no island of any kind. */
static bool bpi_applies(struct main_state *ms, const struct wallet_cutover_binding *b,
                        int32_t coins_height, const struct uint256 *coins_hash)
{
    return ms && b && coins_hash && !b->history_identity_present && b->old_height == 0 &&
        flysync_island_phase() == FLYSYNC_OFF && !flysync_island_requested() &&
        coins_height == b->target_height && memcmp(coins_hash->data, b->target_hash, 32) == 0 &&
        bpi_target_is_rung(b->target_height, b->target_hash) &&
        !block_map_find(&ms->map_block_index, coins_hash) && !island_anchor_registered() &&
        island_anchor_state_load(progress_store_db()) == ISLAND_ANCHOR_STATE_NONE;
}

/* Top first, each row by the exact (height, hash) its child names. */
static bool bpi_load_window(int32_t rung_h, const uint8_t rung_hash[32], struct block_header *w)
{
    struct uint256 expect;
    memcpy(expect.data, rung_hash, 32);
    for (int i = 0; i < ISLAND_ANCHOR_WINDOW; i++) {
        if (!node_db_runtime_load_header_by_hash_height(rung_h - i, expect.data, &w[i])) {
            LOG_ERROR(BPI_SUBSYS, "pending island: staged rung window header h=%d is not stored; "
                      "the pending restore refuses as before", (int)(rung_h - i));
            return false;
        }
        expect = w[i].hashPrevBlock;
    }
    return true;
}

static enum boot_pending_island_result bpi_register(struct main_state *ms, const struct block_header *w,
    int32_t rung_h, const struct uint256 *coins_hash)
{
    struct island_anchor anchor;
    char why[192];
    if (!flysync_island_verify_window(w, ISLAND_ANCHOR_WINDOW, rung_h, &anchor, why, sizeof(why))) {
        LOG_ERROR(BPI_SUBSYS, "pending island: staged rung window h=%d refused: %s", (int)rung_h, why);
        return BOOT_PENDING_ISLAND_REFUSED;
    }
    /* If insertion or registration fails below, rows already inserted stay in
     * this process's map unreferenced: no island is registered, so the
     * unchanged restore refuses their parentless root (bpr_ancestry,
     * boot_wallet_pending_restore.c:99-100) and the boot exits without serving.
     * Nothing durable is written either way. */
    struct block_index *top = flysync_island_prepare_terminal_window(ms, w, ISLAND_ANCHOR_WINDOW, rung_h);
    if (!top || top != block_map_find(&ms->map_block_index, coins_hash)) {
        LOG_ERROR(BPI_SUBSYS, "pending island: verified rung window h=%d could not enter this boot's index",
                  (int)rung_h);
        return BOOT_PENDING_ISLAND_REFUSED;
    }
    struct zcl_result reg = island_anchor_register(&anchor);
    if (!reg.ok) {
        LOG_ERROR(BPI_SUBSYS, "pending island: in-memory registration refused: %s", reg.message);
        return BOOT_PENDING_ISLAND_REFUSED;
    }
    g_bpi_active = true;
    LOG_WARN(BPI_SUBSYS, "pending island: rung window h=%d..%d verified and registered for this boot "
             "only (nothing persisted); this boot completes the wallet cutover and restarts without "
             "serving", (int)anchor.root_height, (int)rung_h);
    return BOOT_PENDING_ISLAND_REGISTERED;
}

enum boot_pending_island_result boot_pending_island_prepare(struct main_state *ms,
    const struct wallet_cutover_binding *binding, int32_t coins_height, const struct uint256 *coins_hash)
{
    if (!bpi_applies(ms, binding, coins_height, coins_hash)) return BOOT_PENDING_ISLAND_SKIPPED;
    struct block_header *w = zcl_calloc(ISLAND_ANCHOR_WINDOW, sizeof(*w), "pending island window");
    if (!w) {
        LOG_ERROR(BPI_SUBSYS, "pending island: window allocation failed; the pending restore refuses");
        return BOOT_PENDING_ISLAND_REFUSED;
    }
    enum boot_pending_island_result r = bpi_load_window(binding->target_height, binding->target_hash, w)
        ? bpi_register(ms, w, binding->target_height, coins_hash) : BOOT_PENDING_ISLAND_REFUSED;
    free(w);
    return r;
}

bool boot_pending_island_active(void) { return g_bpi_active; }

/* An in-memory island never serves: after the replay completes the cutover the
 * caller arms the restart handoff instead of starting services, and the next
 * boot loads the full flat index. */
bool boot_pending_island_restart_due(const struct wallet_cutover_binding *binding)
{
    if (!g_bpi_active || !binding) return false;
    g_bpi_completed = true;
    g_bpi_completed_binding = *binding;
    LOG_WARN(BPI_SUBSYS, "wallet cutover to h=%d completed on the in-memory rung window; restarting "
             "once so the node boots on its full block index", (int)binding->target_height);
    return true;
}

/* The restart handoff after completion. This process must itself have seen
 * the existing replay complete this exact binding, and the PENDING record must
 * be retired. A legacy completion writes no completion record (only a bound
 * binding gets one: wallet_sqlite_cutover.c wsql_cutover_record_completed,
 * wallet_sqlite_scan_state.c wss_authority_completed), and this route is
 * legacy only, so the observation must be ABSENT; anything else refuses. */
bool boot_pending_island_handoff_ready(struct boot_cutover_env *e,
                                       const struct wallet_cutover_binding *binding)
{
    if (!g_bpi_active || !g_bpi_completed || !e || !e->wallet_db || !binding) return false;
    if (!wallet_cutover_binding_equal(&g_bpi_completed_binding, binding)) {
        LOG_ERROR(BPI_SUBSYS, "pending island: restart refused: the binding differs from the one this "
                  "boot completed");
        return false;
    }
    struct wallet_cutover_binding record, completed;
    if (wallet_sqlite_cutover_read(e->wallet_db, &record) != WALLET_CUTOVER_ABSENT) {
        LOG_ERROR(BPI_SUBSYS, "pending island: restart refused: the wallet cutover record is not retired");
        return false;
    }
    if (wallet_sqlite_cutover_observe_completed(e->wallet_db, &completed) != WALLET_CUTOVER_OBS_ABSENT) {
        LOG_ERROR(BPI_SUBSYS, "pending island: restart refused: a legacy completion leaves no completion "
                  "record, but one is present or unreadable");
        return false;
    }
    return true;
}

#ifdef ZCL_TESTING
void boot_pending_island_test_reset(void)
{
    if (g_bpi_active) island_anchor_unregister();
    g_bpi_active = false;
    g_bpi_completed = false;
    memset(&g_bpi_completed_binding, 0, sizeof(g_bpi_completed_binding));
}
#endif
