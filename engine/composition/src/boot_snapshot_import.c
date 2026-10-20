/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared snapshot import implementation for the pre-restore probe in boot.c
 * and the post-services receive path in boot_services.c. The function takes
 * `struct node_db *` directly (not boot_svc_ctx) so it can run before
 * services have been composed. See engine/composition/include/config/boot_snapshot_import.h.
 */

#include "config/boot_snapshot_import.h"
#include "boot_snapshot_import_internal.h"
#include "config/consensus_state_install_runtime.h"
#include "config/boot_consensus_bundle_marker.h"
#include "base/serialize_le.h"
#include "core/serialize.h"
#include "jobs/refold_progress.h"
#include "sapling/incremental_merkle_tree.h"
#include "storage/anchor_kv.h"
#include "storage/nullifier_kv.h"
#include "chain/checkpoints.h"
#include "coins/utxo_commitment.h"
#include "models/database.h"
#include "platform/directory_transaction.h"
#include "services/reindex_epilogue.h"
#include "services/chain_restore_boot_snapshot.h"
#include "services/nullifier_backfill_service.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "event/event.h"
#include "util/ar_step_readonly.h"
#include "util/boot_progress.h"
#include "util/log_macros.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#if defined(_WIN32)
#include <io.h>
#endif

#include <sqlite3.h>

struct snapshot_bootstrap_state {
    const char *preserve_reason;
    sqlite3 *db;
    struct node_db *ndb;
    bool have_meta;
};

static void snapshot_preserve(struct snapshot_bootstrap_state *state, const char *reason)
{
    if (!state->preserve_reason)
        state->preserve_reason = reason;
}

/* Absence is distinct from an unreadable schema or an unexpected view. */
bool snapshot_table_exists(sqlite3 *db, const char *name, bool *exists)
{
    *exists = false;
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(db,
        "SELECT type FROM sqlite_schema WHERE name=?", -1, &st, NULL) == SQLITE_OK;
    if (ok)
        ok = sqlite3_bind_text(st, 1, name, -1, SQLITE_STATIC) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_ERROR; // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_ROW) {
        const unsigned char *type = sqlite3_column_text(st, 0);
        ok = sqlite3_column_type(st, 0) == SQLITE_TEXT && type &&
             strcmp((const char *)type, "table") == 0;
        *exists = ok;
        rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    }
    sqlite3_finalize(st);
    return ok && rc == SQLITE_DONE;
}

static bool snapshot_coin_state(sqlite3 *db, struct node_db *ndb,
                                 struct snapshot_bootstrap_state *state)
{
    bool exists = false;
    if (!snapshot_table_exists(db, "coins", &exists))
        return false;
    int64_t count = exists ? coins_kv_count_sqlite(db) : 0;
    if (count < 0)
        return false;
    if (count > 0) {
        snapshot_preserve(state, "existing kernel coins");
        return true;
    }
    if (!snapshot_table_exists(ndb->db, "utxos", &exists) || !exists)
        return false;
    int64_t mirror = -1;
    if (!node_db_utxo_count_checked(ndb, &mirror) || mirror < 0)
        return false;
    if (mirror > 0)
        snapshot_preserve(state, "existing legacy coin mirror");
    return true;
}

static bool snapshot_meta_u64(sqlite3 *db, const char *key, uint64_t *value, bool *found)
{
    uint8_t bytes[8];
    size_t len = 0;
    *value = 0;
    if (!progress_meta_get_blob_exact(db, key, bytes, sizeof(bytes), &len, found))
        return false;
    if (!*found)
        return true;
    if (len != sizeof(bytes))
        return false;
    *value = zcl_read_u64_le(bytes);
    return true;
}

static bool snapshot_boolean_stamp(sqlite3 *db, const char *key,
                                    struct snapshot_bootstrap_state *state)
{
    uint8_t byte = 0;
    size_t len = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(db, key, &byte, 1, &len, &found))
        return false;
    if (!found)
        return true;
    if (len != 1 || byte != 1)
        return false;
    snapshot_preserve(state, "existing coin or refold provenance");
    return true;
}

static bool snapshot_coin_metadata(sqlite3 *db, struct snapshot_bootstrap_state *state)
{
    bool found = false;
    uint64_t value = 0;
    if (!snapshot_meta_u64(db, COINS_APPLIED_HEIGHT_KEY, &value, &found))
        return false;
    if (found) {
        if (value > INT32_MAX)
            return false;
        if (value != 1) {
            snapshot_preserve(state, "existing applied coin progress");
            return true;
        }
    }
    if (!snapshot_meta_u64(db, COINS_KV_AUTHORITY_GENERATION_KEY, &value, &found))
        return false;
    if (found && value > 0) {
        snapshot_preserve(state, "existing coin authority generation");
        return true;
    }
    static const char *const keys[] = {COINS_KV_MIGRATION_COMPLETE_KEY,
        COINS_KV_SELF_FOLDED_KEY, REFOLD_IN_PROGRESS_KEY, REFOLD_FROM_ANCHOR_KEY};
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (!snapshot_boolean_stamp(db, keys[i], state))
            return false;
        if (state->preserve_reason)
            return true;
    }
    return true;
}

static bool snapshot_integer_rows(sqlite3 *db, const char *sql, int64_t fresh_max,
                                   struct snapshot_bootstrap_state *state)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    bool ok = true;
    int rc;
    while ((rc = sqlite3_step(st)) == SQLITE_ROW) { // raw-sql-ok:read-only-introspection
        if (sqlite3_column_type(st, 0) != SQLITE_INTEGER || sqlite3_column_int64(st, 0) < 0) {
            ok = false;
            break;
        }
        if (sqlite3_column_int64(st, 0) > fresh_max) {
            snapshot_preserve(state, "existing reducer progress");
            sqlite3_finalize(st);
            return true;
        }
    }
    sqlite3_finalize(st);
    return ok && rc == SQLITE_DONE;
}

static bool snapshot_progress_rows(sqlite3 *db, struct snapshot_bootstrap_state *state)
{
    static const struct { const char *table, *sql; int64_t fresh_max; } probes[] = {
        {"utxo_apply_log", "SELECT height FROM utxo_apply_log WHERE "
            "typeof(height)!='integer' OR height!=0 LIMIT 1", 0},
        {"tip_finalize_log", "SELECT height FROM tip_finalize_log WHERE "
            "typeof(height)!='integer' OR height!=0 LIMIT 1", 0},
        {"stage_cursor", "SELECT cursor FROM stage_cursor WHERE name='utxo_apply' AND "
            "(typeof(cursor)!='integer' OR cursor<0 OR cursor>1) LIMIT 1", 1},
        {"stage_cursor", "SELECT cursor FROM stage_cursor WHERE name='tip_finalize' AND "
            "(typeof(cursor)!='integer' OR cursor!=0) LIMIT 1", 0},
    };
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        bool exists = false;
        if (!snapshot_table_exists(db, probes[i].table, &exists))
            return false;
        if (exists && !snapshot_integer_rows(db, probes[i].sql, probes[i].fresh_max, state))
            return false;
        if (state->preserve_reason)
            return true;
    }
    return true;
}

static bool snapshot_anchor_adoption(sqlite3 *db, struct snapshot_bootstrap_state *state)
{
    sqlite3_stmt *st = NULL;
    const char *sql = "SELECT pool,activation_cursor FROM anchor_state WHERE "
        "typeof(pool)!='integer' OR pool NOT IN(0,1) OR "
        "typeof(activation_cursor)!='integer' OR activation_cursor!=0 LIMIT 1";
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    bool ok = rc == SQLITE_DONE;
    if (rc == SQLITE_ROW) {
        int64_t pool = sqlite3_column_int64(st, 0);
        int64_t cursor = sqlite3_column_int64(st, 1);
        ok = sqlite3_column_type(st, 0) == SQLITE_INTEGER && pool >= 0 && pool <= 1 &&
            sqlite3_column_type(st, 1) == SQLITE_INTEGER && cursor >= 0;
        if (ok)
            snapshot_preserve(state, "existing shielded adoption");
    }
    sqlite3_finalize(st);
    return ok;
}

static bool snapshot_anchor_state(sqlite3 *db, struct snapshot_bootstrap_state *state)
{
    static const char *const tables[] = {"sprout_anchors", "sapling_anchors"};
    for (int pool = 0; pool < 2; pool++) {
        bool exists = false, empty = false;
        if (!snapshot_table_exists(db, tables[pool], &exists))
            return false;
        if (exists) {
            if (!anchor_kv_table_is_empty(db, pool, &empty))
                return false;
            if (!empty) {
                snapshot_preserve(state, "existing shielded anchors");
                return true;
            }
        }
    }
    bool exists = false;
    if (!snapshot_table_exists(db, "anchor_state", &exists))
        return false;
    return !exists || snapshot_anchor_adoption(db, state);
}

static bool snapshot_any_nullifiers(sqlite3 *db, bool *found)
{
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM nullifiers LIMIT 1", -1, &st, NULL) != SQLITE_OK)
        return false;
    int rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    *found = rc == SQLITE_ROW;
    sqlite3_finalize(st);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

static bool snapshot_nullifier_state(sqlite3 *db, bool have_meta,
                                      struct snapshot_bootstrap_state *state)
{
    bool exists = false;
    if (!snapshot_table_exists(db, "nullifiers", &exists))
        return false;
    if (exists) {
        bool any = false;
        if (!snapshot_any_nullifiers(db, &any))
            return false;
        if (any) {
            snapshot_preserve(state, "existing shielded nullifiers");
            return true;
        }
    }
    if (!have_meta)
        return true;
    uint8_t bytes[24];
    size_t len = 0;
    bool found = false;
    if (!progress_meta_get_blob_exact(db, "nullifier_kv.activation_cursor",
                                      bytes, sizeof(bytes), &len, &found))
        return false;
    int64_t cursor = -1;
    if (found && !nullifier_kv_activation_cursor(db, &cursor, &found))
        return false;
    if (found && cursor > 0)
        snapshot_preserve(state, "existing nullifier adoption");
    return true;
}

bool snapshot_node_blob(struct node_db *ndb, const char *key,
                                void *out, size_t cap, size_t *len, bool *found)
{
    *found = false;
    *len = 0;
    sqlite3_stmt *st = NULL;
    bool ok = sqlite3_prepare_v2(ndb->db,
        "SELECT value FROM node_state WHERE key=?", -1, &st, NULL) == SQLITE_OK;
    if (ok)
        ok = sqlite3_bind_text(st, 1, key, -1, SQLITE_STATIC) == SQLITE_OK;
    int rc = ok ? sqlite3_step(st) : SQLITE_ERROR; // raw-sql-ok:read-only-introspection
    if (rc == SQLITE_ROW) {
        int n = sqlite3_column_bytes(st, 0);
        const void *bytes = sqlite3_column_blob(st, 0);
        ok = sqlite3_column_type(st, 0) == SQLITE_BLOB && n > 0 &&
             (size_t)n <= cap && bytes;
        if (ok) {
            memcpy(out, bytes, (size_t)n);
            *len = (size_t)n;
            *found = true;
        }
        rc = sqlite3_step(st); // raw-sql-ok:read-only-introspection
    }
    sqlite3_finalize(st);
    return ok && rc == SQLITE_DONE;
}

static bool snapshot_cached_sapling(struct node_db *ndb,
                                     struct snapshot_bootstrap_state *state)
{
    uint8_t bytes[8192];
    size_t len = 0, height_len = 0;
    bool have_tree = false, have_height = false;
    int64_t height = -1;
    if (!snapshot_node_blob(ndb, "sapling_tree", bytes, sizeof(bytes), &len, &have_tree) ||
        !snapshot_node_blob(ndb, "sapling_tree_rebuild_height", &height, sizeof(height),
                            &height_len, &have_height) || have_tree != have_height)
        return false;
    if (!have_tree)
        return true;
    if (height_len != sizeof(height) || height < 0)
        return false;
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    struct byte_stream stream;
    stream_init_from_data(&stream, bytes, len);
    if (!incremental_tree_deserialize(&tree, &stream) || stream.error || stream.read_pos != stream.size)
        return false;
    if (height > 0 || incremental_tree_size(&tree) > 0)
        snapshot_preserve(state, "existing cached Sapling state");
    return true;
}

static bool snapshot_decimal_marker(const uint8_t *bytes, size_t len)
{
    if (len == 0 || len > 19 || (len > 1 && bytes[0] == '0'))
        return false;
    int64_t value = 0;
    for (size_t i = 0; i < len; i++) {
        if (bytes[i] < '0' || bytes[i] > '9')
            return false;
        int digit = bytes[i] - '0';
        if (value > (INT64_MAX - digit) / 10)
            return false;
        value = value * 10 + digit;
    }
    return true;
}

static bool snapshot_pending_encoding(const char *key, const uint8_t *bytes, size_t len)
{
    if (strcmp(key, REFOLD_FROM_ANCHOR_TARGET_KEY) == 0)
        return len == 4 && zcl_read_u32_le(bytes) <= INT32_MAX;
    if (strcmp(key, NULLIFIER_BACKFILL_CHAIN_KEY) == 0)
        return len == 32;
    return snapshot_decimal_marker(bytes, len);
}

static bool snapshot_pending_markers(sqlite3 *db, struct snapshot_bootstrap_state *state)
{
    static const char *const keys[] = {
        SHIELDED_REPLAY_TARGET_KEY, SHIELDED_REPLAY_NEXT_KEY,
        SHIELDED_REPLAY_SPROUT_STARTED_KEY, SHIELDED_REPLAY_SAPLING_STARTED_KEY,
        REFOLD_FROM_ANCHOR_TARGET_KEY, NULLIFIER_BACKFILL_RESUME_KEY,
        NULLIFIER_BACKFILL_CHAIN_KEY,
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        uint8_t bytes[32];
        size_t len = 0;
        bool found = false;
        if (!progress_meta_get_blob_exact(db, keys[i], bytes, sizeof(bytes), &len, &found))
            return false;
        if (found) {
            if (!snapshot_pending_encoding(keys[i], bytes, len))
                return false;
            snapshot_preserve(state, "interrupted shielded replay or refold");
            return true;
        }
    }
    return true;
}

static bool snapshot_probe_coins(struct snapshot_bootstrap_state *s)
{ return snapshot_coin_state(s->db, s->ndb, s); }
static bool snapshot_probe_metadata(struct snapshot_bootstrap_state *s)
{ return !s->have_meta || snapshot_coin_metadata(s->db, s); }
static bool snapshot_probe_progress(struct snapshot_bootstrap_state *s)
{ return snapshot_progress_rows(s->db, s); }
static bool snapshot_probe_anchors(struct snapshot_bootstrap_state *s)
{ return snapshot_anchor_state(s->db, s); }
static bool snapshot_probe_nullifiers(struct snapshot_bootstrap_state *s)
{ return snapshot_nullifier_state(s->db, s->have_meta, s); }
static bool snapshot_probe_cache(struct snapshot_bootstrap_state *s)
{ return snapshot_cached_sapling(s->ndb, s); }
static bool snapshot_probe_pending(struct snapshot_bootstrap_state *s)
{ return !s->have_meta || snapshot_pending_markers(s->db, s); }

bool snapshot_import_shielded_pristine(struct node_db *ndb)
{
    struct snapshot_bootstrap_state state = {.db = progress_store_db(), .ndb = ndb};
    return snapshot_table_exists(state.db, "progress_meta", &state.have_meta) &&
        snapshot_probe_anchors(&state) && snapshot_probe_nullifiers(&state) &&
        snapshot_probe_cache(&state) && snapshot_probe_pending(&state) &&
        (!state.have_meta ||
         (snapshot_boolean_stamp(state.db, REFOLD_IN_PROGRESS_KEY, &state) &&
          snapshot_boolean_stamp(state.db, REFOLD_FROM_ANCHOR_KEY, &state))) &&
        !state.preserve_reason;
}

static struct zcl_result snapshot_bootstrap_eligibility(struct node_db *ndb,
    struct snapshot_bootstrap_state *state)
{
    state->db = progress_store_db();
    state->ndb = ndb;
    if (!snapshot_table_exists(state->db, "progress_meta", &state->have_meta))
        return ZCL_ERR(-1, "snapshot-first: unreadable kernel metadata schema; preserve this datadir");
    static const struct {
        bool (*read)(struct snapshot_bootstrap_state *);
        const char *name;
    } probes[] = {
        {snapshot_probe_coins, "kernel or legacy coin count"},
        {snapshot_probe_metadata, "coin progress or provenance metadata"},
        {snapshot_probe_progress, "reducer progress"},
        {snapshot_probe_anchors, "shielded anchors or adoption"},
        {snapshot_probe_nullifiers, "shielded nullifiers or adoption"},
        {snapshot_probe_cache, "cached Sapling tree/height pair"},
        {snapshot_probe_pending, "interrupted replay metadata"},
    };
    for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        if (!probes[i].read(state))
            return ZCL_ERR(-1, "snapshot-first: unreadable %s; preserve this datadir "
                          "and diagnose a copy; automatic snapshot import refused", probes[i].name);
        if (state->preserve_reason)
            return ZCL_OK;
    }
    return ZCL_OK;
}

static enum boot_snapshot_first_outcome snapshot_first_import(
    struct node_db *ndb, const char *path)
{
    int64_t count = 0, height = 0;
    uint8_t best[32] = {0};
    bool ok = boot_import_snapshot_db(ndb, path, &count, &height, best);
    chain_restore_record_snapshot_import(ok, count, height);
    event_emitf(EV_BOOT_UTXO_IMPORT, 0,
                "phase=pre-restore ok=%d utxos=%lld height=%lld",
                ok ? 1 : 0, (long long)count, (long long)height);
    if (ok)
        printf("[boot] snapshot-first import OK: %lld UTXOs at h=%lld — "
               "chain restore will observe snapshot anchor\n",
               (long long)count, (long long)height);
    else
        fprintf(stderr,  // obs-ok:helper-context-logged
                "[boot] snapshot-first import failed for %s — %s\n", path,
                boot_snapshot_import_pending_or_error(ndb) ?
                    "committed or unreadable pending import; stopping boot for recovery" :
                    "no pending import; falling through to block-by-block IBD path");
    return ok ? BOOT_SNAPSHOT_FIRST_IMPORTED : BOOT_SNAPSHOT_FIRST_IMPORT_FAILED;
}

static struct zcl_result snapshot_first_select(struct node_db *ndb,
    const char *datadir, enum boot_snapshot_first_outcome *outcome)
{
    *outcome = BOOT_SNAPSHOT_FIRST_NO_SOURCE;
    if (!ndb->open)
        return ZCL_OK;
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/consensus_snapshot.db", datadir);
    struct stat st;
    if (n <= 0 || (size_t)n >= sizeof(path) || stat(path, &st) != 0 ||
        st.st_size <= (off_t)(10 * 1024 * 1024))
        return ZCL_OK;
    struct snapshot_bootstrap_state state = {0};
    struct zcl_result eligible = snapshot_bootstrap_eligibility(ndb, &state);
    if (!eligible.ok)
        return eligible;
    if (state.preserve_reason) {
        printf("[boot] snapshot-first: preserving %s; skipping automatic snapshot import\n",
               state.preserve_reason);
        *outcome = BOOT_SNAPSHOT_FIRST_STATE_PRESERVED;
        return ZCL_OK;
    }
    *outcome = snapshot_first_import(ndb, path);
    return ZCL_OK;
}

struct zcl_result boot_prepare_snapshot_first(struct node_db *ndb,
    const char *datadir, enum boot_snapshot_first_outcome *outcome)
{
    if (outcome)
        *outcome = BOOT_SNAPSHOT_FIRST_DEFERRED;
    if (!progress_store_db())
        return ZCL_OK;
    if (!ndb || !datadir)
        return ZCL_ERR(-1, "snapshot-first: node store or datadir missing");
    bool recovered = false;
    struct zcl_result resumed = snapshot_import_recover(ndb, datadir, &recovered);
    if (!resumed.ok)
        return resumed;
    if (recovered) {
        if (outcome)
            *outcome = BOOT_SNAPSHOT_FIRST_IMPORTED;
        return ZCL_OK;
    }
#if !defined(_WIN32)
    struct zcl_result installed_recovery =
        consensus_state_install_recover_committed(ndb, datadir, NULL);
    if (!installed_recovery.ok)
        return installed_recovery;
#endif
    if (boot_consensus_bundle_marker_exists(datadir)) {
        printf("[boot] snapshot-first: preserving installed bundle; skipping automatic snapshot import\n");
        if (outcome)
            *outcome = BOOT_SNAPSHOT_FIRST_INSTALLED_PRESERVED;
        return ZCL_OK;
    }
    enum boot_snapshot_first_outcome selected;
    struct zcl_result selection = snapshot_first_select(ndb, datadir, &selected);
    if (selection.ok && selected == BOOT_SNAPSHOT_FIRST_IMPORT_FAILED &&
        boot_snapshot_import_pending_or_error(ndb))
        return ZCL_ERR(-1, "committed snapshot import needs recovery; preserve this datadir and restart");
    if (outcome)
        *outcome = selected;
    return selection;
}

/* SQLite calls this only after executing more virtual-machine instructions.
 * Unlike a timer thread, it cannot claim progress while a disk operation is
 * hung. Returning zero preserves the statement; the callback records only a
 * cheap lock-free liveness timestamp. */
static int snapshot_import_progress(void *unused)
{
    (void)unused;
    boot_progress_tick("snapshot_import_bulk_insert");
    return 0;
}

/* Inspect the kernel belonging to this node, never an unrelated singleton.
 * The comparison uses the store's retained directory identity, not matching
 * path spellings. This does not authorize importing into an established set. */
bool snapshot_import_directory_bound(const char *directory)
{
    sqlite3 *db = progress_store_db();
    if (!db || !directory || !directory[0])
        return false;
#if defined(_WIN32)
    struct platform_directory_transaction parent;
    platform_directory_transaction_init(&parent);
    if (!platform_directory_transaction_open(&parent, directory))
        return false;
    int fd = platform_directory_child_duplicate_fd(parent.native, _O_RDONLY);
    platform_directory_transaction_close(&parent);
    bool bound = fd >= 0 && progress_store_directory_matches_fd(db, fd);
    if (fd >= 0)
        (void)_close(fd);
#else
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    bool bound = fd >= 0 && progress_store_directory_matches_fd(db, fd);
    if (fd >= 0)
        (void)close(fd);
#endif
    return bound;
}

bool snapshot_import_store_bound(struct node_db *ndb)
{
    const char *path = sqlite3_db_filename(ndb->db, "main");
    if (!path || !path[0])
        return false;
    const char *leaf = strrchr(path, '/');
#if defined(_WIN32)
    const char *back = strrchr(path, '\\');
    if (!leaf || (back && back > leaf))
        leaf = back;
#endif
    if (!leaf || (size_t)(leaf - path) >= PATH_MAX)
        return false;
    char directory[PATH_MAX];
    size_t len = leaf == path ? 1u : (size_t)(leaf - path);
#if defined(_WIN32)
    if (len == 2 && path[1] == ':')
        len++;
#endif
    memcpy(directory, path, len);
    directory[len] = '\0';
    return snapshot_import_directory_bound(directory);
}

static bool snapshot_import_target_eligible(struct node_db *ndb)
{
    if (!sqlite3_get_autocommit(ndb->db) || !progress_store_db() ||
        !sqlite3_get_autocommit(progress_store_db()))
        LOG_RETURN(false, "boot_snapshot_import", "snapshot import requires idle node and consensus stores");
    struct snapshot_import_pending pending;
    bool found = false;
    if (!snapshot_import_pending_load(ndb, &pending, &found) || found)
        LOG_RETURN(false, "boot_snapshot_import",
                   "pending or unreadable snapshot import; preserve this datadir and restart for recovery");
    if (!snapshot_import_store_bound(ndb) || !snapshot_import_no_installed_state(ndb))
        LOG_RETURN(false, "boot_snapshot_import",
                   "consensus store is closed or belongs to another datadir; "
                   "preserve this datadir and diagnose a copy; snapshot import refused");
    struct snapshot_bootstrap_state state = {0};
    struct zcl_result eligible = snapshot_bootstrap_eligibility(ndb, &state);
    if (!eligible.ok)
        LOG_RETURN(false, "boot_snapshot_import", "%s", eligible.message);
    if (state.preserve_reason)
        LOG_RETURN(false, "boot_snapshot_import",
                   "preserving %s; preserve this datadir and diagnose a copy; "
                   "snapshot import refused", state.preserve_reason);
    return true;
}

static bool snapshot_import_prepare_record(int64_t height, const uint8_t hash[32],
    struct snapshot_import_pending *pending)
{
    memset(pending, 0, sizeof(*pending));
    if (height >= INT32_MAX ||
        !coins_kv_get_authority_generation(progress_store_db(), &pending->generation) ||
        pending->generation != 0)
        LOG_RETURN(false, "boot_snapshot_import", "invalid snapshot height or authority generation");
    pending->height = (int32_t)height;
    memcpy(pending->hash, hash, sizeof(pending->hash));
    return true;
}

static bool snapshot_import_record_mirror(struct node_db *ndb,
    struct snapshot_import_pending *pending, int64_t expected_count)
{
    utxo_commitment_sha3_compute(ndb->db, pending->root, &pending->count);
    return pending->count == (uint64_t)expected_count && snapshot_import_pending_save(ndb, pending);
}

static bool snapshot_import_complete(struct node_db *ndb)
{
    bool completed = false;
    struct zcl_result completion = snapshot_import_recover(ndb, NULL, &completed);
    if (!completion.ok || !completed)
        LOG_RETURN(false, "boot_snapshot_import", "committed import needs recovery: %s", completion.message);
    return true;
}

bool boot_import_snapshot_db(struct node_db *ndb,
                              const char *snapshot_path,
                              int64_t *out_utxo_count,
                              int64_t *out_snap_height,
                              uint8_t out_best_hash[32])
{
    if (!ndb || !ndb->open || !ndb->db || !snapshot_path)
        LOG_FAIL("boot_snapshot_import", "null inputs");
    if (!snapshot_import_target_eligible(ndb))
        return false;

    struct stat st;
    if (stat(snapshot_path, &st) != 0)
        LOG_FAIL("boot_snapshot_import", "stat %s: %s",
                 snapshot_path, strerror(errno));
    if (st.st_size < (off_t)(10 * 1024 * 1024))
        LOG_FAIL("boot_snapshot_import",
                 "snapshot too small (%lld bytes) — likely truncated",
                 (long long)st.st_size);

    sqlite3 *src = NULL;
    if (sqlite3_open_v2(snapshot_path, &src,
                        SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        const char *m = src ? sqlite3_errmsg(src) : "n/a";
        if (src) sqlite3_close(src);
        LOG_FAIL("boot_snapshot_import", "open ro %s: %s",
                 snapshot_path, m);
    }

    bool integrity_ok = false;
    {
        sqlite3_stmt *ck = NULL;
        if (sqlite3_prepare_v2(src, "PRAGMA integrity_check",
                               -1, &ck, NULL) == SQLITE_OK && ck) {
            if (sqlite3_step(ck) == SQLITE_ROW) {  // raw-sql-ok:integrity-pragma
                const unsigned char *r = sqlite3_column_text(ck, 0);
                integrity_ok = r && strcmp((const char *)r, "ok") == 0;
            }
            sqlite3_finalize(ck);
        }
    }
    if (!integrity_ok) {
        sqlite3_close(src);
        LOG_FAIL("boot_snapshot_import",
                 "integrity_check failed for %s", snapshot_path);
    }

    int64_t snap_height = -1;
    {
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(src,
                "SELECT value FROM _snapshot_meta WHERE key='height'",
                -1, &q, NULL) == SQLITE_OK && q) {
            if (sqlite3_step(q) == SQLITE_ROW) {  // raw-sql-ok:read-only-snapshot
                const unsigned char *v = sqlite3_column_text(q, 0);
                if (v) snap_height = strtoll((const char *)v, NULL, 10);
            }
            sqlite3_finalize(q);
        }
    }
    if (snap_height < 1) {
        sqlite3_close(src);
        LOG_FAIL("boot_snapshot_import",
                 "missing/invalid _snapshot_meta.height");
    }

    /* PROVENANCE GATE (defense-in-depth for the peer-served path):
     * this importer installs a `consensus_snapshot.db` that arrived over the
     * unauthenticated file_service (file_index=254) — the per-chunk SHA3 only
     * proves the bytes match the SERVING PEER's manifest, not that the coin set
     * is the real consensus set. We only have an in-binary cryptographic ground
     * truth AT the single compiled checkpoint (the WRITE-TIME SHA3 reject
     * below). ABOVE the checkpoint there is no in-binary root and no anchor
     * binding here, so a forged snapshot at an arbitrary height would otherwise
     * be installed as ground truth (forged-money / consensus divergence).
     * REFUSE to promote an above-checkpoint peer snapshot — fall back to safe
     * P2P IBD. The assisted operator bundle path
     * (boot_load_snapshot_at_own_height_reset, which checks that the snapshot
     * anchor names a validated block_index location) is the supported way to
     * seed above the checkpoint; that location check does not authenticate
     * UTXO/shielded contents, and the path does NOT use this function. */
    {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        if (cp && snap_height > (int64_t)cp->height) {
            sqlite3_close(src);
            LOG_FAIL("boot_snapshot_import",
                     "REFUSING peer snapshot at h=%lld (above compiled "
                     "checkpoint h=%llu): no in-binary root to consensus-verify "
                     "it against — falling back to P2P IBD / operator bundle",
                     (long long)snap_height,
                     (unsigned long long)cp->height);
        }
    }

    uint8_t best_hash[32] = {0};
    bool best_found = false;
    {
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(src,
                "SELECT hash FROM blocks WHERE height=?",
                -1, &q, NULL) == SQLITE_OK && q) {
            sqlite3_bind_int64(q, 1, snap_height);
            if (sqlite3_step(q) == SQLITE_ROW) {  // raw-sql-ok:read-only-snapshot
                const void *b = sqlite3_column_blob(q, 0);
                int n = sqlite3_column_bytes(q, 0);
                if (b && n == 32) {
                    memcpy(best_hash, b, 32);
                    best_found = true;
                }
            }
            sqlite3_finalize(q);
        }
    }
    if (!best_found) {
        sqlite3_close(src);
        LOG_FAIL("boot_snapshot_import",
                 "no blocks row at h=%lld", (long long)snap_height);
    }

    int64_t snap_utxos = 0;
    {
        sqlite3_stmt *q = NULL;
        if (sqlite3_prepare_v2(src,
                "SELECT COUNT(*) FROM utxos",
                -1, &q, NULL) == SQLITE_OK && q) {
            if (sqlite3_step(q) == SQLITE_ROW)  // raw-sql-ok:read-only-snapshot
                snap_utxos = sqlite3_column_int64(q, 0);
            sqlite3_finalize(q);
        }
    }
    sqlite3_close(src);
    if (snap_utxos < 1000)
        LOG_FAIL("boot_snapshot_import",
                 "implausible utxo count %lld", (long long)snap_utxos);

    struct snapshot_import_pending pending;
    if (!snapshot_import_prepare_record(snap_height, best_hash, &pending))
        return false;

    char attach_sql[640];
    snprintf(attach_sql, sizeof(attach_sql),
             "ATTACH DATABASE '%s' AS snapsrc", snapshot_path);
    char *err = NULL;
    if (sqlite3_exec(ndb->db, attach_sql, NULL, NULL, &err) != SQLITE_OK) {
        char msg[256] = "?";
        if (err) { snprintf(msg, sizeof(msg), "%s", err); sqlite3_free(err); }
        LOG_FAIL("boot_snapshot_import", "ATTACH failed: %s", msg);
    }

    bool ok = true;
    if (sqlite3_exec(ndb->db, "BEGIN IMMEDIATE", NULL, NULL, &err)
        != SQLITE_OK) {
        char msg[256] = "?";
        if (err) { snprintf(msg, sizeof(msg), "%s", err); sqlite3_free(err); }
        sqlite3_exec(ndb->db, "DETACH DATABASE snapsrc", NULL, NULL, NULL);
        LOG_FAIL("boot_snapshot_import", "BEGIN failed: %s", msg);
    }
    /* Report only measured SQLite VM progress while the bulk copy and
     * commitment scan run. A timer-based pump falsely kept a genuinely hung
     * INSERT alive forever once watchdog progress exemptions became active. */
    sqlite3_progress_handler(ndb->db, 50000,
                             snapshot_import_progress, NULL);
    if (ok && ar_exec_write_sql(ndb->db, "DELETE FROM main.utxos")
                  != SQLITE_OK) {
        fprintf(stderr, "[boot_snapshot_import] clear utxos: %s\n",  // obs-ok:bulk-import-failure
                sqlite3_errmsg(ndb->db));
        ok = false;
    }
    if (ok && ar_exec_write_sql(ndb->db,
            "INSERT INTO main.utxos SELECT * FROM snapsrc.utxos")
                  != SQLITE_OK) {
        fprintf(stderr, "[boot_snapshot_import] copy utxos: %s\n",  // obs-ok:bulk-import-failure
                sqlite3_errmsg(ndb->db));
        ok = false;
    }
    /* WRITE-TIME VERIFICATION (mirrors utxo_recovery_restore.c):
     * before COMMIT, recompute the SHA3 over the just-installed set. At the
     * compiled checkpoint height there is a cryptographic ground truth, so
     * REJECT unless (root,count) byte-match it — a peer's per-chunk transport
     * SHA3 only proves the file matches the SERVING PEER's manifest, NOT that
     * the coin set is the real consensus set. Runs while the SQLite progress
     * handler remains active (the walk is O(set)). Above the checkpoint there
     * is no
     * compiled root to verify against; that non-checkpoint provenance gap (the
     * snapshot path writes no cold-import seed, so the boot torn-gate cannot
     * see it) is a documented follow-up — the checkpoint reject is the
     * load-bearing half and closes the fabricate-at-the-checkpoint hole. */
    if (ok) {
        const struct sha3_utxo_checkpoint *cp = get_sha3_utxo_checkpoint();
        if (cp && snap_height == (int64_t)cp->height) {
            uint8_t root[32]; uint64_t cnt = 0;
            utxo_commitment_sha3_compute(ndb->db, root, &cnt);
            if (cnt != cp->utxo_count || memcmp(root, cp->sha3_hash, 32) != 0) {
                LOG_WARN("boot_snapshot_import",
                         "checkpoint SHA3 MISMATCH at h=%lld (count=%llu "
                         "want=%llu) — snapshot REJECTED, not installed as "
                         "ground truth",
                         (long long)snap_height, (unsigned long long)cnt,
                         (unsigned long long)cp->utxo_count);
                ok = false;
            } else {
                printf("[boot_snapshot_import] checkpoint SHA3 verified at "
                       "h=%lld (%llu UTXOs)\n", (long long)snap_height,
                       (unsigned long long)cnt);
            }
        }
    }
    if (ok) {
        ok = snapshot_import_record_mirror(ndb, &pending, snap_utxos);
    }
    if (ok) {
        /* A failed COMMIT (SQLITE_FULL / IO error) leaves the bulk-copy txn
         * uncommitted — we must NOT then stamp coins_best_block at the
         * snapshot tip (that is the snapshot-path coin-tear class). Capture
         * the rc, roll back, and propagate failure so the caller falls back
         * to normal sync instead of trusting a half-installed set. */
        if (sqlite3_exec(ndb->db, "COMMIT", NULL, NULL, NULL) != SQLITE_OK) {
            LOG_WARN("boot_snapshot_import",
                     "COMMIT failed (%s) — rolling back snapshot install",
                     sqlite3_errmsg(ndb->db));
            sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL);
            ok = false;
        }
    } else {
        sqlite3_exec(ndb->db, "ROLLBACK", NULL, NULL, NULL);
    }
    sqlite3_exec(ndb->db, "DETACH DATABASE snapsrc", NULL, NULL, NULL);
    sqlite3_progress_handler(ndb->db, 0, NULL, NULL);

    if (!ok) {
        LOG_FAIL("boot_snapshot_import",
                 "snapshot install failed; node.db rolled back");
        return false;
    }

    if (!snapshot_import_complete(ndb))
        return false;

    if (out_utxo_count)  *out_utxo_count  = snap_utxos;
    if (out_snap_height) *out_snap_height = snap_height;
    if (out_best_hash)   memcpy(out_best_hash, best_hash, 32);
    return true;
}
