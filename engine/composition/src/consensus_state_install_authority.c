/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Canonical wallet installation authority classification. */
#include "config/consensus_state_install_runtime.h"
#if defined(_WIN32)
enum boot_bound_completion_result boot_bound_completed_retire(struct wallet_sqlite *ws,
    struct node_db *node, struct wallet *wallet, struct main_state *main, const char *datadir, int fd,
    const struct wallet_cutover_binding *expected, const struct boot_bound_bundle_observation *expected_request)
{
    (void)ws; (void)node; (void)wallet; (void)main; (void)datadir; (void)fd; (void)expected; (void)expected_request;
    return BOOT_BOUND_COMPLETION_ERROR;
}
enum boot_bound_completion_result boot_bound_completed_prove(struct wallet_sqlite *ws,
    struct node_db *node, struct wallet *wallet, struct main_state *main, const char *datadir, int dir_fd,
    bool *generation_present, uint64_t *generation)
{
    (void)ws; (void)node; (void)wallet; (void)main; (void)datadir; (void)dir_fd;
    if (generation_present) *generation_present = false;
    if (generation) *generation = 0;
    return BOOT_BOUND_COMPLETION_ERROR;
}
#else
#include "consensus_state_install_authority_internal.h"
#include "boot_cutover_startup_internal.h"
#include "config/boot_wallet_pending_restore.h"
#include "config/boot_datadir_lock.h"
#include "config/boot_internal.h"
#include "consensus_state_proof_prefix.h"
#include "models/database.h"
#include "services/consensus_state_publication_cas.h"
#include "storage/progress_store.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/wallet.h"
#include "validation/main_state.h"
#include "chain/chain.h"
#include "util/sync.h"
#include "util/ar_step_readonly.h"
#include "util/log_macros.h"
#include <sqlite3.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#define ICB_SUBSYS "install_consensus_bundle"

static bool icb_wallet_prefix_matches(const struct consensus_state_proof_prefix *p,
    const struct wallet_cutover_binding *b, bool present, uint64_t gen)
{
    return b->old_generation != UINT64_MAX && present && gen == b->old_generation + 1 &&
        p->present && p->authority_generation_present && p->authority_generation == gen &&
        p->height == b->target_height && memcmp(p->block_hash, b->target_hash, 32) == 0 &&
        memcmp(p->artifact_digest, b->artifact_digest, 32) == 0;
}

enum wallet_install_reconcile icb_wallet_classify_locked(
    sqlite3 *db, const struct wallet_cutover_binding *b)
{
    bool present = false, advanced = false;
    uint64_t gen = 0; int32_t height = -1; uint8_t hash[32];
    struct consensus_state_proof_prefix prefix;
    if (!boot_wallet_authority_generation(db, &present, &gen) ||
        !consensus_state_publication_cas_capture_frontier_locked(db, &height, hash) ||
        !consensus_state_proof_prefix_load(db, &prefix)) return WALLET_INSTALL_UNKNOWN;
    if (present == b->old_generation_present && gen == b->old_generation &&
        height == b->old_height && memcmp(hash, b->old_hash, 32) == 0)
        return WALLET_INSTALL_OLD;
    if (!icb_wallet_prefix_matches(&prefix, b, present, gen) ||
        !icb_recovery_frontier(db, &prefix, &advanced)) return WALLET_INSTALL_UNKNOWN;
    return WALLET_INSTALL_COMMITTED;
}
static bool icb_completed_end_read(sqlite3 *db)
{
    if (sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK) return true;
    if (sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL) != SQLITE_OK)
        LOG_ERROR(ICB_SUBSYS, "completed authority read rollback failed: %s", sqlite3_errmsg(db));
    return false;
}
static bool icb_retire_datadir(const char *path, int held)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat a, b;
    bool ok = fstat(fd, &a) == 0 && fstat(held, &b) == 0 &&
        S_ISDIR(a.st_mode) && S_ISDIR(b.st_mode) && a.st_dev == b.st_dev && a.st_ino == b.st_ino;
    return close(fd) == 0 && ok;
}
static bool icb_retire_no_scan_marker(sqlite3 *db)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT EXISTS(SELECT 1 FROM node_state WHERE key=\x27wallet_scan_incomplete\x27)",
                           -1, &stmt, NULL) != SQLITE_OK || !stmt) return false;
    bool ok = ar_step_checked(stmt, "completed authority scan marker", NULL) == ZCL_STEP_ROW && sqlite3_column_int(stmt, 0) == 0 &&
        ar_step_checked(stmt, "completed authority scan marker completion", NULL) == ZCL_STEP_DONE;
    return sqlite3_finalize(stmt) == SQLITE_OK && ok;
}
static bool icb_retire_scan_height(struct wallet_sqlite *ws, int target, int *scan)
{
    int reference = -1;
    return wallet_sqlite_validate_scan_state(ws) == WALLET_SCAN_STATE_OK &&
        wallet_sqlite_read_scan_height(ws, scan) &&
        wallet_sqlite_height_encoding(ws, &reference) == WALLET_HEIGHT_V2 &&
        *scan == reference && *scan >= target && icb_retire_no_scan_marker(ws->db);
}
static bool icb_retire_scan_chain(struct wallet_sqlite *ws, struct main_state *main,
                                  const struct wallet_cutover_binding *binding)
{
    int scan = -1;
    if (!icb_retire_scan_height(ws, binding->target_height, &scan)) return false;
    struct block_index *tip = active_chain_tip(&main->chain_active);
    struct block_index *target = active_chain_at(&main->chain_active, binding->target_height);
    struct block_index *scanned = active_chain_at(&main->chain_active, scan);
    return tip && tip->phashBlock && target && target->phashBlock && scanned && scanned->phashBlock &&
        tip->nHeight >= scan && !memcmp(target->phashBlock->data, binding->target_hash, 32) &&
        block_index_get_ancestor(tip, scan) == scanned &&
        block_index_get_ancestor(scanned, binding->target_height) == target;
}
static enum boot_bound_completion_result icb_retire_observed(struct wallet_sqlite *ws, struct main_state *main,
    sqlite3 *progress, const struct boot_bound_bundle_observation *obs,
    const struct wallet_cutover_binding *expected)
{
    struct wallet_cutover_binding binding, checked;
    enum wallet_cutover_observation_status status = wallet_sqlite_cutover_observe_completed(ws, &binding);
    if (status == WALLET_CUTOVER_OBS_PENDING) return BOOT_BOUND_COMPLETION_PENDING;
    if (status == WALLET_CUTOVER_OBS_FOUND && wallet_cutover_binding_equal(&binding, expected) &&
        boot_bound_request_matches_completed(obs, &binding) &&
        wallet_sqlite_cutover_authority_read(ws, expected, &checked) == WALLET_CUTOVER_AUTH_COMPLETED &&
        icb_wallet_classify_locked(progress, &binding) == WALLET_INSTALL_COMMITTED &&
        icb_retire_scan_chain(ws, main, &binding)) return BOOT_BOUND_COMPLETION_PROVEN;
    return BOOT_BOUND_COMPLETION_ERROR;
}
struct icb_retire_proof_context {
    const struct boot_bound_bundle_observation *obs;
    const struct wallet_cutover_binding *expected;
};
typedef enum boot_bound_completion_result (*icb_snapshot_proof_fn)(
    struct wallet_sqlite *, struct main_state *, sqlite3 *, void *);

static enum boot_bound_completion_result icb_retire_proof_adapter(
    struct wallet_sqlite *ws, struct main_state *main, sqlite3 *progress, void *opaque)
{
    struct icb_retire_proof_context *ctx = opaque;
    return icb_retire_observed(ws, main, progress, ctx->obs, ctx->expected);
}

static enum boot_bound_completion_result icb_snapshot_read(struct wallet_sqlite *ws,
    struct main_state *main, sqlite3 *progress, icb_snapshot_proof_fn proof, void *context)
{
    sqlite3 *db = ws->db; bool same = db == progress;
    if (!sqlite3_get_autocommit(db) || sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK)
        return BOOT_BOUND_COMPLETION_ERROR;
    bool progress_open = same || (sqlite3_get_autocommit(progress) &&
        sqlite3_exec(progress, "BEGIN", NULL, NULL, NULL) == SQLITE_OK);
    enum boot_bound_completion_result result = BOOT_BOUND_COMPLETION_ERROR;
    if (progress_open) result = proof(ws, main, progress, context);
    if (progress_open && !same && !icb_completed_end_read(progress)) result = BOOT_BOUND_COMPLETION_ERROR;
    if (!icb_completed_end_read(db)) result = BOOT_BOUND_COMPLETION_ERROR;
    return result;
}

static bool icb_retire_handles_valid(struct wallet_sqlite *ws, struct node_db *node,
    struct wallet *wallet, struct main_state *main, const char *datadir,
    const struct wallet_cutover_binding *expected)
{
    return expected && ws && ws->open && ws->db && node && node->open && ws->db == node->db &&
        wallet && main && datadir && datadir[0];
}
static bool icb_retire_context_valid(struct wallet_sqlite *ws, struct node_db *node,
    struct wallet *wallet, struct main_state *main, const char *datadir, int dir_fd,
    const struct wallet_cutover_binding *expected)
{
    return icb_retire_handles_valid(ws, node, wallet, main, datadir, expected) &&
        boot_wallet_cutover_replay_context_matches(node, ws, wallet, main) &&
        boot_datadir_lock_matches_fd(dir_fd) && icb_retire_datadir(datadir, dir_fd) &&
        consensus_state_wallet_node_file_matches(ws->db, dir_fd) &&
        progress_store_directory_matches_fd(progress_store_db(), dir_fd);
}
static enum boot_bound_completion_result icb_retire_locked(struct wallet_sqlite *ws,
    struct wallet *wallet, struct main_state *main, const char *datadir,
    const struct boot_bound_bundle_observation *obs, const struct wallet_cutover_binding *expected)
{
    sqlite3_mutex *connection = sqlite3_db_mutex(ws->db);
    bool locked = connection && sqlite3_mutex_try(connection) == SQLITE_OK;
    bool wallet_locked = locked && zcl_mutex_trylock(&wallet->cs);
    enum boot_bound_completion_result result = BOOT_BOUND_COMPLETION_ERROR;
    if (wallet_locked) {
        { struct icb_retire_proof_context proof = {obs, expected};
          result = icb_snapshot_read(ws, main, progress_store_db(), icb_retire_proof_adapter, &proof); }
        if (result == BOOT_BOUND_COMPLETION_PROVEN) {
            enum boot_bound_retire_result retired = boot_install_bound_bundle_retire(datadir, obs);
            result = retired == BOOT_BOUND_RETIRE_DONE ? BOOT_BOUND_COMPLETION_RETIRED :
                retired == BOOT_BOUND_RETIRE_UNKNOWN ? BOOT_BOUND_COMPLETION_UNKNOWN : BOOT_BOUND_COMPLETION_ERROR;
        }
        zcl_mutex_unlock(&wallet->cs);
    }
    if (locked) sqlite3_mutex_leave(connection);
    return result;
}
enum boot_bound_completion_result boot_bound_completed_retire(struct wallet_sqlite *ws,
    struct node_db *node, struct wallet *wallet, struct main_state *main, const char *datadir, int dir_fd,
    const struct wallet_cutover_binding *expected, const struct boot_bound_bundle_observation *expected_request)
{
    if (!expected_request || !icb_retire_context_valid(ws, node, wallet, main, datadir, dir_fd, expected))
        return BOOT_BOUND_COMPLETION_ERROR;
    struct boot_bound_bundle_observation obs = {0};
    enum boot_bound_read_result read = boot_install_bound_bundle_read(datadir, &obs);
    if (read == BOOT_BOUND_READ_ABSENT) return BOOT_BOUND_COMPLETION_ABSENT;
    if ((read != BOOT_BOUND_READ_READY && read != BOOT_BOUND_READ_TERMINAL) ||
        !boot_bound_observation_equal(&obs, expected_request)) return BOOT_BOUND_COMPLETION_ERROR;
    if (!zcl_mutex_trylock(&main->cs_main)) return BOOT_BOUND_COMPLETION_ERROR;
    if (!progress_store_tx_trylock()) { zcl_mutex_unlock(&main->cs_main); return BOOT_BOUND_COMPLETION_ERROR; }
    enum boot_bound_completion_result result = icb_retire_locked(ws, wallet, main, datadir, expected_request, expected);
    progress_store_tx_unlock(); zcl_mutex_unlock(&main->cs_main);
    return result;
}
static enum boot_bound_completion_result icb_completed_proof_read(
    struct wallet_sqlite *ws, struct main_state *main, sqlite3 *progress,
    bool *present, uint64_t *generation)
{
    struct wallet_cutover_binding binding, checked;
    enum wallet_cutover_observation_status status = wallet_sqlite_cutover_observe_completed(ws, &binding);
    if (status == WALLET_CUTOVER_OBS_ABSENT) return BOOT_BOUND_COMPLETION_ABSENT;
    if (status == WALLET_CUTOVER_OBS_PENDING) return BOOT_BOUND_COMPLETION_PENDING;
    if (status == WALLET_CUTOVER_OBS_FOUND && binding.history_identity_present &&
        wallet_sqlite_cutover_authority_read(ws, &binding, &checked) == WALLET_CUTOVER_AUTH_COMPLETED &&
        wallet_cutover_binding_equal(&binding, &checked) &&
        icb_wallet_classify_locked(progress, &binding) == WALLET_INSTALL_COMMITTED &&
        icb_retire_scan_chain(ws, main, &binding) &&
        boot_wallet_authority_generation(progress, present, generation))
        return BOOT_BOUND_COMPLETION_PROVEN;
    return BOOT_BOUND_COMPLETION_ERROR;
}

struct icb_completed_proof_context { bool *present; uint64_t *generation; };
static enum boot_bound_completion_result icb_completed_proof_adapter(
    struct wallet_sqlite *ws, struct main_state *main, sqlite3 *progress, void *opaque)
{
    struct icb_completed_proof_context *ctx = opaque;
    return icb_completed_proof_read(ws, main, progress, ctx->present, ctx->generation);
}

enum boot_bound_completion_result boot_bound_completed_prove(struct wallet_sqlite *ws,
    struct node_db *node, struct wallet *wallet, struct main_state *main, const char *datadir, int dir_fd,
    bool *generation_present, uint64_t *generation)
{
    if (generation_present) *generation_present = false;
    if (generation) *generation = 0;
    struct wallet_cutover_binding placeholder = {0};
    if (!generation_present || !generation ||
        !icb_retire_context_valid(ws, node, wallet, main, datadir, dir_fd, &placeholder))
        return BOOT_BOUND_COMPLETION_ERROR;
    if (!zcl_mutex_trylock(&main->cs_main)) return BOOT_BOUND_COMPLETION_ERROR;
    if (!progress_store_tx_trylock()) { zcl_mutex_unlock(&main->cs_main); return BOOT_BOUND_COMPLETION_ERROR; }
    sqlite3_mutex *connection = sqlite3_db_mutex(ws->db);
    bool locked = connection && sqlite3_mutex_try(connection) == SQLITE_OK;
    bool wallet_locked = locked && zcl_mutex_trylock(&wallet->cs);
    bool present = false; uint64_t value = 0;
    enum boot_bound_completion_result result = BOOT_BOUND_COMPLETION_ERROR;
    if (wallet_locked) {
        { struct icb_completed_proof_context proof = {&present, &value};
          result = icb_snapshot_read(ws, main, progress_store_db(), icb_completed_proof_adapter, &proof); }
        zcl_mutex_unlock(&wallet->cs);
    }
    if (locked) sqlite3_mutex_leave(connection);
    progress_store_tx_unlock(); zcl_mutex_unlock(&main->cs_main);
    if (result == BOOT_BOUND_COMPLETION_PROVEN) { *generation_present = present; *generation = value; }
    return result;
}
#endif
