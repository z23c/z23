/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: persist a verified startup DISCOVER replay checkpoint. */
#include "boot_wallet_cutover_checkpoint_internal.h"
#include "config/boot_datadir_lock.h"
#include "config/boot_internal.h"
#include "config/consensus_state_install_runtime.h"
#include "config/boot_wallet_cutover_replay.h"
#include "controllers/wallet_helpers.h"
#include "models/ar_after_commit.h"
#include "models/database.h"
#include "storage/coins_kv.h"
#include "storage/event_log.h"
#include "storage/progress_store.h"
#include "storage/wallet_projection.h"
#include "base/serialize_le.h"
#include "util/safe_alloc.h"
#include "util/thread_registry.h"
#include "util/log_macros.h"
#include "platform/time_compat.h"
#include "wallet/wallet_lock.h"
#include "validation/main_state.h"
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif
#include <sqlite3.h>
#include <string.h>
#include <stdlib.h>

#if defined(ZCL_TESTING) && !defined(_WIN32)
static void (*wcp_test_before_commit)(void *);
static void *wcp_test_before_commit_ctx;
static void (*wcp_test_after_commit)(void *);
static void *wcp_test_after_commit_ctx;
static bool wcp_test_fail_open;
void boot_wallet_discover_checkpoint_test_fail_open(bool fail) { wcp_test_fail_open = fail; }
void boot_wallet_discover_checkpoint_test_after_commit(void (*fn)(void *), void *ctx)
{ wcp_test_after_commit = fn; wcp_test_after_commit_ctx = ctx; }
void boot_wallet_discover_checkpoint_test_before_commit(void (*fn)(void *), void *ctx)
{ wcp_test_before_commit = fn; wcp_test_before_commit_ctx = ctx; }
#endif
#ifndef _WIN32
static bool wcp_stop(void *context)
{
    const struct boot_cutover_replay *r = context;
    if (thread_registry_shutdown_requested()) return true;
    if (!r || !r->auth_deadline_ms) return false;
    int64_t now = platform_time_monotonic_ms();
    return now <= 0 || now >= r->auth_deadline_ms;
}

static bool wcp_event_digest(struct boot_cutover_replay *r, uint64_t *end, uint8_t digest[32], bool capture)
{
    event_log_t *log = wallet_projection_event_log();
    if (!log || wcp_stop(r)) return false;
    if (capture) {
        *end = event_log_size(log);
        if (!event_log_flush(log)) return false;
    }
    return wallet_projection_event_log() == log &&
        event_log_prefix_digest(log, *end, digest, wcp_stop, r) == 0 &&
        wallet_projection_event_log() == log;
}

enum wcp_result { WCP_OK, WCP_STALE, WCP_BUSY, WCP_RETRY };
static enum wcp_result wcp_generation(const struct wallet_readiness *ready)
{
    uint8_t bytes[8]; size_t len = 0; bool present = false;
    sqlite3 *db = progress_store_db();
    if (!db || !progress_meta_get_blob_exact(db, COINS_KV_AUTHORITY_GENERATION_KEY,
        bytes, sizeof(bytes), &len, &present) || (present && len != sizeof(bytes))) return WCP_RETRY;
    return present == ready->generation_present &&
        (!present || zcl_read_u64_le(bytes) == ready->generation) ? WCP_OK : WCP_STALE;
}
static bool wcp_matches(const struct boot_cutover_replay *r,
                        const struct wallet_discover_checkpoint *c)
{
    return wallet_cutover_binding_equal(&r->binding, &c->binding) &&
        c->generation_present == r->readiness.generation_present &&
        c->generation == r->readiness.generation && c->floor == r->floor &&
        c->next_height >= r->floor && c->next_height <= r->endpoint.height &&
        c->endpoint_height == r->endpoint.height &&
        !memcmp(c->endpoint_hash, r->endpoint.hash.data, 32) &&
        !memcmp(c->endpoint_root, r->endpoint.root.data, 32) &&
        !memcmp(c->scan_identity, r->identity, 32);
}
static bool wcp_same(const struct wallet_discover_checkpoint *a,
                     const struct wallet_discover_checkpoint *b)
{
    return wallet_cutover_binding_equal(&a->binding, &b->binding) &&
        a->generation_present == b->generation_present && a->generation == b->generation &&
        a->floor == b->floor && a->next_height == b->next_height && a->endpoint_height == b->endpoint_height &&
        !memcmp(a->endpoint_hash, b->endpoint_hash, 32) && !memcmp(a->endpoint_root, b->endpoint_root, 32) &&
        !memcmp(a->scan_identity, b->scan_identity, 32) && !memcmp(a->key_digest, b->key_digest, 32) &&
        a->event_end == b->event_end && !memcmp(a->event_digest, b->event_digest, 32);
}
static void wcp_fill(const struct boot_cutover_replay *r,
                     struct wallet_discover_checkpoint *c)
{
    memset(c, 0, sizeof(*c)); c->binding = r->binding;
    c->generation_present = r->readiness.generation_present;
    c->generation = r->readiness.generation; c->floor = r->floor;
    c->next_height = r->next; c->endpoint_height = r->endpoint.height;
    memcpy(c->endpoint_hash, r->endpoint.hash.data, 32);
    memcpy(c->endpoint_root, r->endpoint.root.data, 32);
    memcpy(c->scan_identity, r->identity, 32); memcpy(c->key_digest, r->key_digest, 32);
}

/* Caller holds the datadir lease; the private handle has its own timeout policy. */
static bool wcp_writer_open(struct boot_cutover_replay *r, int fd, struct node_db *writer)
{
    struct node_db *original = r->ctx->node_db;
    const char *path = original && original->db ? sqlite3_db_filename(original->db, "main") : NULL;
    if (!path || !boot_datadir_lock_matches_fd(fd) ||
        !consensus_state_wallet_node_file_matches(original->db, fd) ||
        !node_db_open_existing_runtime(writer, path, "wallet.discover_checkpoint")) return false;
#ifdef ZCL_TESTING
    if (wcp_test_fail_open) return false;
#endif
    return sqlite3_busy_timeout(writer->db, 0) == SQLITE_OK &&
        consensus_state_wallet_node_file_matches(writer->db, fd);
}

struct wcp_locks { bool canonical, archive, wallet, keys, sapling, progress; };
static bool wcp_lock(struct boot_cutover_replay *r, struct wcp_locks *l)
{
    struct main_state *archive = r->ctx->main_state;
    struct main_state *canonical = r->canonical_state ? r->canonical_state : archive;
    struct wallet *w = r->ctx->wallet;
    if (!(l->canonical = zcl_mutex_trylock(&canonical->cs_main))) return false;
    if (archive != canonical && !(l->archive = zcl_mutex_trylock(&archive->cs_main))) return false;
    if (!(l->wallet = zcl_mutex_trylock(&w->cs))) return false;
    if (!(l->keys = zcl_mutex_trylock(&w->keystore.cs))) return false;
    if (!(l->sapling = zcl_mutex_trylock(&w->sapling_keys.cs))) return false;
    return l->progress = progress_store_tx_trylock();
}
static void wcp_unlock(struct boot_cutover_replay *r, const struct wcp_locks *l)
{
    struct main_state *archive = r->ctx->main_state;
    struct main_state *canonical = r->canonical_state ? r->canonical_state : archive;
    struct wallet *w = r->ctx->wallet;
    if (l->progress) progress_store_tx_unlock();
    if (l->sapling) zcl_mutex_unlock(&w->sapling_keys.cs);
    if (l->keys) zcl_mutex_unlock(&w->keystore.cs);
    if (l->wallet) zcl_mutex_unlock(&w->cs);
    if (l->archive) zcl_mutex_unlock(&archive->cs_main);
    if (l->canonical) zcl_mutex_unlock(&canonical->cs_main);
}
static bool wcp_context(struct boot_cutover_replay *r)
{
    struct main_state *canonical = r->canonical_state ? r->canonical_state : r->ctx->main_state;
    return r->ctx->node_db && r->ctx->wallet_db && r->ctx->node_db->db &&
        r->ctx->wallet_db->db == r->ctx->node_db->db &&
        boot_wallet_cutover_replay_context_matches(r->ctx->node_db,
            r->ctx->wallet_db, r->ctx->wallet, canonical);
}

struct wcp_transaction_state {
    struct boot_cutover_replay *replay;
    struct wallet_discover_checkpoint *checkpoint;
    struct node_db *writer;
    sqlite3_mutex *original_mutex;
    struct wcp_locks held;
    int fd;
    bool save, auth_lease, began, committed, original_locked;
};
static enum wcp_result wcp_sqlite_failure(struct node_db *writer)
{
    int rc = sqlite3_errcode(writer->db) & 0xff;
    return (rc == SQLITE_BUSY || rc == SQLITE_LOCKED) ? WCP_BUSY : WCP_RETRY;
}
static enum wcp_result wcp_transaction_open(struct wcp_transaction_state *t)
{
    if (!t->writer || !t->original_mutex) return WCP_RETRY;
    if (sqlite3_mutex_try(t->original_mutex) != SQLITE_OK) return WCP_BUSY;
    t->original_locked = true;
    if (!wcp_writer_open(t->replay, t->fd, t->writer)) return WCP_RETRY;
    t->began = node_db_begin_immediate(t->writer);
    return t->began ? WCP_OK : wcp_sqlite_failure(t->writer);
}
static enum wcp_result wcp_transaction_binding(struct wcp_transaction_state *t,
                                                struct wallet_sqlite *ws)
{
    struct wallet_cutover_binding binding;
    enum wallet_cutover_status status = wallet_sqlite_cutover_read(ws, &binding);
    if (status == WALLET_CUTOVER_ABSENT ||
        (status == WALLET_CUTOVER_PENDING &&
         !wallet_cutover_binding_equal(&binding, &t->replay->binding))) return WCP_STALE;
    return status == WALLET_CUTOVER_PENDING ? WCP_OK : WCP_RETRY;
}
static enum wcp_result wcp_transaction_write(struct wcp_transaction_state *t,
                                              struct wallet_sqlite *ws)
{
    if (t->save) {
        if (!wallet_sqlite_discover_checkpoint_save(ws, t->checkpoint))
            return wcp_sqlite_failure(t->writer);
    } else {
        struct wallet_discover_checkpoint current;
        if (wallet_sqlite_discover_checkpoint_read(ws, &current) != WALLET_DISCOVER_FOUND ||
            !wcp_same(&current, t->checkpoint)) return WCP_RETRY;
    }
    return WCP_OK;
}
static enum wcp_result wcp_transaction_commit(struct wcp_transaction_state *t)
{
    struct boot_cutover_replay *r = t->replay;
    if (!boot_datadir_lock_matches_fd(t->fd) ||
        !consensus_state_wallet_node_file_matches(r->ctx->node_db->db, t->fd) ||
        !consensus_state_wallet_node_file_matches(t->writer->db, t->fd) ||
        ar_after_commit_pending() != 0 || wcp_stop(r)) return WCP_RETRY;
#ifdef ZCL_TESTING
    if (wcp_test_before_commit) wcp_test_before_commit(wcp_test_before_commit_ctx);
#endif
    t->committed = node_db_commit(t->writer);
#ifdef ZCL_TESTING
    if (t->committed && wcp_test_after_commit) wcp_test_after_commit(wcp_test_after_commit_ctx);
#endif
    return t->committed ? WCP_OK : wcp_sqlite_failure(t->writer);
}
static enum wcp_result wcp_transaction_apply(struct wcp_transaction_state *t)
{
    struct boot_cutover_replay *r = t->replay;
    if (!wcp_lock(r, &t->held)) return WCP_BUSY;
    if (wcp_stop(r)) return WCP_RETRY;
    enum wcp_result result = wcp_generation(&r->readiness);
    if (result != WCP_OK) return result;
    if (!boot_cutover_replay_current_locked(r)) return WCP_STALE;
    struct wallet_sqlite ws = {.db = t->writer->db, .open = true};
    result = wcp_transaction_binding(t, &ws);
    if (result != WCP_OK) return result;
    result = wcp_transaction_write(t, &ws);
    if (result != WCP_OK) return result;
    return wcp_transaction_commit(t);
}
static void wcp_transaction_close(struct wcp_transaction_state *t)
{
    if (t->began && !t->committed) (void)node_db_rollback(t->writer);
    wcp_unlock(t->replay, &t->held);
    if (t->original_locked) sqlite3_mutex_leave(t->original_mutex);
    if (t->writer && t->writer->open) node_db_close(t->writer);
    free(t->writer); close(t->fd);
    if (t->auth_lease) wallet_lock_startup_publication_end();
}
/* Validates the PENDING binding again in the private write transaction. */
static enum wcp_result wcp_transaction(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *checkpoint, bool save)
{
    if (!r || !r->ctx) return WCP_RETRY;
    if (!wcp_context(r)) {
        LOG_WARN("wallet", "DISCOVER checkpoint refused: replay context or stage");
        return WCP_RETRY;
    }
    if (wcp_stop(r) || ar_after_commit_depth() != 0 ||
        ar_after_commit_pending() != 0) return WCP_RETRY;
    bool auth_lease = r->auth_deadline_ms != 0;
    if (auth_lease && !wallet_lock_startup_publication_begin(r->auth_deadline_ms)) return WCP_RETRY;
    int fd = open(r->ctx->datadir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) { if (auth_lease) wallet_lock_startup_publication_end(); return WCP_RETRY; }
    struct wcp_transaction_state t = {.replay = r, .checkpoint = checkpoint, .fd = fd,
        .save = save, .auth_lease = auth_lease,
        .writer = zcl_calloc(1, sizeof(*t.writer), "discover checkpoint writer"),
        .original_mutex = sqlite3_db_mutex(r->ctx->node_db->db)};
    enum wcp_result result = wcp_transaction_open(&t);
    if (result == WCP_OK) result = wcp_transaction_apply(&t);
    wcp_transaction_close(&t);
    return result;
}

static bool wcp_prepare_platform(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *c)
{
    if (!r || !r->ctx || !c) return false;
    wcp_fill(r, c);
    return wcp_event_digest(r, &c->event_end, c->event_digest, true);
}
static enum boot_discover_save wcp_save_platform(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *c)
{
    if (!r || !c || !wcp_matches(r, c) || c->next_height != r->next ||
        memcmp(c->key_digest, r->key_digest, 32)) return BOOT_DISCOVER_SAVE_RETRY;
    enum wcp_result result = wcp_transaction(r, c, true);
    return result == WCP_OK ? BOOT_DISCOVER_SAVED :
        (result == WCP_BUSY ? BOOT_DISCOVER_SAVE_BUSY : BOOT_DISCOVER_SAVE_RETRY);
}

static enum boot_discover_resume wcp_resume_platform(struct boot_cutover_replay *r)
{
    struct wallet_discover_checkpoint c;
    sqlite3_mutex *mu = sqlite3_db_mutex(r->ctx->node_db->db);
    if (!mu) return BOOT_DISCOVER_RETRY;
    if (sqlite3_mutex_try(mu) != SQLITE_OK) return BOOT_DISCOVER_BUSY;
    enum wallet_discover_checkpoint_status status =
        wallet_sqlite_discover_checkpoint_read(r->ctx->wallet_db, &c);
    sqlite3_mutex_leave(mu);
    if (status == WALLET_DISCOVER_ABSENT) return BOOT_DISCOVER_FLOOR;
    if (status != WALLET_DISCOVER_FOUND) return BOOT_DISCOVER_RETRY;
    if (!wcp_matches(r, &c)) return BOOT_DISCOVER_FLOOR;
    uint8_t digest[32];
    if (!wcp_event_digest(r, &c.event_end, digest, false) ||
        memcmp(digest, c.event_digest, sizeof(digest))) return BOOT_DISCOVER_RETRY;
    enum wcp_result result = wcp_transaction(r, &c, false);
    if (result == WCP_STALE) return BOOT_DISCOVER_FLOOR;
    if (result == WCP_BUSY) return BOOT_DISCOVER_BUSY;
    if (result != WCP_OK) return BOOT_DISCOVER_RETRY;
    r->next = c.next_height; memcpy(r->key_digest, c.key_digest, 32);
    r->checkpoint_resume = true;
    return BOOT_DISCOVER_RESUMED;
}
#else
static bool wcp_prepare_platform(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *c) { (void)r; (void)c; return true; }
static enum boot_discover_save wcp_save_platform(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *c) { (void)r; (void)c; return BOOT_DISCOVER_SAVED; }
static enum boot_discover_resume wcp_resume_platform(struct boot_cutover_replay *r)
{ (void)r; return BOOT_DISCOVER_FLOOR; }
#endif

bool boot_wallet_discover_checkpoint_prepare(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *c) { return wcp_prepare_platform(r, c); }
enum boot_discover_save boot_wallet_discover_checkpoint_save(struct boot_cutover_replay *r,
    struct wallet_discover_checkpoint *c) { return wcp_save_platform(r, c); }
enum boot_discover_resume boot_wallet_discover_checkpoint_resume(struct boot_cutover_replay *r)
{ return wcp_resume_platform(r); }
