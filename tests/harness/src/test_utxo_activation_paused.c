/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "conditions/utxo_activation_paused.h"
#include "chain/mmb.h"
#include "chain/mmr.h"
#include "coins/utxo_commitment.h"
#include "event/event.h"
#include "sync/sync_state.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/stage_repair.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/clock.h"
#include "net/snapshot_sync_contract.h"
#include "services/sync_monitor.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/process_block.h"

#include <stdatomic.h>
#include <sqlite3.h>
#include <string.h>

#define UAP_CHECK(name, expr) do { \
    printf("utxo_activation_paused: %s... ", (name)); \
    if (expr) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

void register_block_failed_mask_at_tip(void);
void register_tip_wedged_resnapshot(void);
void block_failed_mask_at_tip_test_reset(void);
int block_failed_mask_at_tip_test_stall_type(void);
int block_failed_mask_at_tip_test_target_height(void);
int block_failed_mask_at_tip_test_validate_repair_owner_height(void);
int block_failed_mask_at_tip_test_reducer_owner_target(void);
int block_failed_mask_at_tip_test_reducer_owner_hstar(void);
int block_failed_mask_at_tip_test_reducer_owner_reason(void);
void block_failed_mask_at_tip_test_mark_exhausted(int target_height);
void block_failed_mask_at_tip_test_mark_no_advance_exhausted(
    int target_height,
    int tip_height);
bool block_failed_mask_at_tip_recovery_exhausted(int *target_height,
                                                 int *attempts_out);
void tip_wedged_resnapshot_test_reset(void);
void tip_wedged_resnapshot_test_set_runtime(
    struct node_db *ndb,
    struct snapshot_sync_service *svc);
int tip_wedged_resnapshot_test_remedy_calls(void);
int tip_wedged_resnapshot_test_recovery_accepted(void);
int tip_wedged_resnapshot_test_last_manifest_height(void);

struct fake_clock {
    _Atomic int64_t wall_ms;
};

static int64_t fake_now_mono(void *self)
{
    (void)self;
    return 1;
}

static int64_t fake_now_wall(void *self)
{
    struct fake_clock *c = (struct fake_clock *)self;
    return atomic_load(&c->wall_ms);
}

static void fake_clock_install(struct fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
    static clock_iface_t iface;
    iface.now_monotonic_ns = fake_now_mono;
    iface.now_wall_ms = fake_now_wall;
    iface.self = c;
    clock_set_default(&iface);
}

static void fake_clock_set(struct fake_clock *c, int64_t unix_s)
{
    atomic_store(&c->wall_ms, unix_s * 1000);
}

static void operator_observer(enum event_type type, uint32_t peer_id,
                              const void *payload, uint32_t payload_len,
                              void *ctx)
{
    (void)type;
    (void)peer_id;
    (void)payload;
    (void)payload_len;
    _Atomic int *count = (_Atomic int *)ctx;
    atomic_fetch_add(count, 1);
}

static void reset_conditions(void)
{
    event_log_init();
    condition_engine_reset_for_testing();
    event_clear_all_observers();
    process_block_test_set_utxo_activation_paused_height(-1);
    utxo_activation_paused_test_reset();
    block_failed_mask_at_tip_test_reset();
    tip_wedged_resnapshot_test_reset();
}

static struct block_index *insert_test_block(struct main_state *ms,
                                             struct uint256 *hashes,
                                             int height,
                                             unsigned status)
{
    memset(&hashes[height], 0, sizeof(hashes[height]));
    hashes[height].data[0] = (uint8_t)height;
    hashes[height].data[1] = 0xA5;
    struct block_index *bi = chainstate_insert_block_index(
        (struct chainstate *)ms, &hashes[height]);
    if (!bi) return NULL;
    bi->nHeight = height;
    bi->nStatus = status;
    bi->nTx = 1;
    bi->nChainTx = (uint32_t)(height + 1);
    if (height > 0)
        bi->pprev = block_map_find(&ms->map_block_index, &hashes[height - 1]);
    return bi;
}

static const struct json_value *uap_json_condition(
    const struct json_value *root,
    const char *name)
{
    const struct json_value *conditions = json_get(root, "conditions");
    if (!conditions || !name)
        return NULL;
    for (size_t i = 0; i < json_size(conditions); i++) {
        const struct json_value *cond = json_at(conditions, i);
        const struct json_value *n = json_get(cond, "name");
        if (n && strcmp(json_get_str(n), name) == 0)
            return cond;
    }
    return NULL;
}

static void persist_snapshot_roots(struct node_db *ndb,
                                   const uint8_t block_hash[32],
                                   const uint8_t chain_work[32])
{
    struct mmr mmr;
    struct mmb mmb;
    struct mmb_leaf leaf;
    uint8_t buf[MMB_SERIALIZED_MAX];
    size_t len;

    mmr_init(&mmr);
    mmr_append(&mmr, block_hash);
    len = mmr_serialize(&mmr, buf, sizeof(buf));
    node_db_state_set(ndb, "mmr_state", buf, len);

    mmb_init(&mmb);
    mmb_leaf_from_block(&leaf, block_hash, 101, 1234567890, 0x1d00ffff,
                        block_hash, chain_work, NULL);
    mmb_append(&mmb, &leaf);
    len = mmb_serialize(&mmb, buf, sizeof(buf));
    node_db_state_set(ndb, "mmb_state", buf, len);
}

static bool seed_snapshot_manifest_db(struct node_db *ndb,
                                      const uint8_t block_hash[32],
                                      const uint8_t chain_work[32])
{
    uint8_t prev_hash[32];
    uint8_t merkle_root[32];
    uint8_t nonce[32];
    uint8_t solution[1] = {0};
    sqlite3_stmt *st = NULL;

    memset(prev_hash, 0x40, sizeof(prev_hash));
    memset(merkle_root, 0x42, sizeof(merkle_root));
    memset(nonce, 0x43, sizeof(nonce));

    if (!node_db_state_set_int(ndb, "tip_height", 101) ||
        !node_db_state_set(ndb, "tip_hash", block_hash, 32))
        return false;
    if (sqlite3_prepare_v2(ndb->db,
            "INSERT INTO blocks "
            "(hash,height,prev_hash,version,merkle_root,time,bits,nonce,"
            "solution,chain_work,status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,3)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_blob(st, 1, block_hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 2, 101);
    sqlite3_bind_blob(st, 3, prev_hash, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 4, 4);
    sqlite3_bind_blob(st, 5, merkle_root, 32, SQLITE_STATIC);
    sqlite3_bind_int(st, 6, 1234567890);
    sqlite3_bind_int(st, 7, 0x1d00ffff);
    sqlite3_bind_blob(st, 8, nonce, 32, SQLITE_STATIC);
    sqlite3_bind_blob(st, 9, solution, sizeof(solution), SQLITE_STATIC);
    sqlite3_bind_blob(st, 10, chain_work, 32, SQLITE_STATIC);
    bool ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    if (!ok)
        return false;
    if (!node_db_exec(ndb,
            "INSERT INTO utxos "
            "(txid,vout,value,script,script_type,height,is_coinbase) "
            "VALUES (X'0102030405060708090A0B0C0D0E0F101112131415161718"
            "191A1B1C1D1E1F20',0,5000,X'51',0,101,0)"))
        return false;
    persist_snapshot_roots(ndb, block_hash, chain_work);
    return true;
}

static bool exec_progress_sql(sqlite3 *db, const char *sql)
{
    char *err = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
    if (rc != SQLITE_OK) {
        printf("utxo_activation_paused SQL failed: %s\n",
               err ? err : "(no message)");
        if (err)
            sqlite3_free(err);
        return false;
    }
    return true;
}

static bool seed_validate_repair_frontier(sqlite3 *db, int repair_height)
{
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "CREATE TABLE IF NOT EXISTS validate_headers_log ("
        "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
        "fail_reason TEXT, validated_at INTEGER NOT NULL);"
        "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) "
        "VALUES('tip_finalize',%d,1),('validate_headers',%d,1);"
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height,hash,ok,fail_reason,validated_at) "
        "VALUES(%d,zeroblob(32),0,'header-source-hash-mismatch',1);",
        repair_height - 1, repair_height + 1, repair_height);
    return exec_progress_sql(db, sql);
}

static bool seed_reducer_frontier_owner_schema(sqlite3 *db)
{
    return
        exec_progress_sql(db,
            "CREATE TABLE IF NOT EXISTS header_admit_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL,"
            "parent_hash BLOB, admitted_at INTEGER NOT NULL);") &&
        exec_progress_sql(db,
            "CREATE TABLE IF NOT EXISTS validate_headers_log ("
            "height INTEGER PRIMARY KEY, hash BLOB NOT NULL, ok INTEGER NOT NULL,"
            "fail_reason TEXT, validated_at INTEGER NOT NULL);") &&
        exec_progress_sql(db,
            "CREATE TABLE IF NOT EXISTS script_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "block_hash BLOB);") &&
        exec_progress_sql(db,
            "CREATE TABLE IF NOT EXISTS body_persist_log ("
            "height INTEGER PRIMARY KEY, source TEXT, ok INTEGER NOT NULL);") &&
        exec_progress_sql(db,
            "CREATE TABLE IF NOT EXISTS body_fetch_log ("
            "height INTEGER PRIMARY KEY, hash BLOB, source TEXT,"
            "bytes INTEGER, fetched_at INTEGER, ok INTEGER,"
            "fail_reason TEXT);") &&
        exec_progress_sql(db,
            "CREATE TABLE IF NOT EXISTS proof_validate_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "block_hash BLOB);") &&
        exec_progress_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL);") &&
        exec_progress_sql(db,
            "CREATE TABLE IF NOT EXISTS utxo_apply_delta ("
            "height INTEGER PRIMARY KEY, branch_hash BLOB NOT NULL,"
            "spent_blob BLOB NOT NULL, added_blob BLOB NOT NULL);") &&
        exec_progress_sql(db,
            "CREATE TABLE IF NOT EXISTS tip_finalize_log ("
            "height INTEGER PRIMARY KEY, status TEXT, ok INTEGER NOT NULL,"
            "tip_hash BLOB);");
}

static bool seed_reducer_frontier_owner_rows(
    sqlite3 *db, const struct uint256 *h1, const struct uint256 *h2,
    const struct uint256 *h3)
{
    int a = REDUCER_FRONTIER_TRUSTED_ANCHOR;
    char sql[1024];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO stage_cursor(name,cursor,updated_at) VALUES"
        "('validate_headers',%d,1),('body_fetch',%d,1),"
        "('body_persist',%d,1),('script_validate',%d,1),"
        "('proof_validate',%d,1),('utxo_apply',%d,1),"
        "('tip_finalize',%d,1);",
        a + 4, a + 4, a + 4, a + 4, a + 4, a + 4, a + 4);
    if (!exec_progress_sql(db, sql))
        return false;

    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO header_admit_log"
            "(height,hash,parent_hash,admitted_at) VALUES(?,?,?,1)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    const struct uint256 *hashes[] = {h1, h2, h3};
    bool ok = true;
    for (int i = 0; ok && i < 3; i++) {
        sqlite3_bind_int(st, 1, a + 1 + i);
        sqlite3_bind_blob(st, 2, hashes[i]->data, 32, SQLITE_STATIC);
        if (i == 0)
            sqlite3_bind_null(st, 3);
        else
            sqlite3_bind_blob(st, 3, hashes[i - 1]->data, 32, SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-seed
        sqlite3_reset(st);
        sqlite3_clear_bindings(st);
    }
    sqlite3_finalize(st);
    if (!ok)
        return false;

    static const char *const statements[] = {
        "INSERT OR REPLACE INTO validate_headers_log"
        "(height,hash,ok,fail_reason,validated_at) VALUES(?,?,1,NULL,1)",
        "INSERT OR REPLACE INTO script_validate_log"
        "(height,status,ok,block_hash) VALUES(?,'verified',1,?)",
        "INSERT OR REPLACE INTO proof_validate_log"
        "(height,status,ok,block_hash) VALUES(?,'verified',1,?)",
        "INSERT OR REPLACE INTO utxo_apply_delta"
        "(height,branch_hash,spent_blob,added_blob) VALUES(?,?,X'',X'')",
    };
    for (size_t i = 0; ok && i < sizeof(statements) / sizeof(statements[0]);
         i++) {
        if (sqlite3_prepare_v2(db, statements[i], -1, &st, NULL) !=
            SQLITE_OK) {
            printf("utxo_activation_paused prepare failed: %s\n",
                   sqlite3_errmsg(db));
            ok = false;
        } else {
            sqlite3_bind_int(st, 1, a + 1);
            sqlite3_bind_blob(st, 2, h1->data, 32, SQLITE_STATIC);
            ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-seed
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    static const char *const simple_statements[] = {
        "INSERT OR REPLACE INTO body_persist_log"
        "(height,source,ok) VALUES(?,'fixture',1)",
        "INSERT OR REPLACE INTO utxo_apply_log"
        "(height,status,ok) VALUES(?,'verified',1)",
    };
    for (size_t i = 0;
         ok && i < sizeof(simple_statements) / sizeof(simple_statements[0]);
         i++) {
        if (sqlite3_prepare_v2(db, simple_statements[i], -1, &st, NULL) !=
            SQLITE_OK) {
            printf("utxo_activation_paused prepare failed: %s\n",
                   sqlite3_errmsg(db));
            ok = false;
        } else {
            sqlite3_bind_int(st, 1, a + 1);
            ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-seed
        }
        sqlite3_finalize(st);
        st = NULL;
    }
    if (!ok)
        return false;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO tip_finalize_log"
            "(height,status,ok,tip_hash) VALUES(?,'finalized',1,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int(st, 1, a + 1);
    sqlite3_bind_blob(st, 2, h2->data, 32, SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE; // raw-sql-ok:test-seed
    sqlite3_finalize(st);
    if (!ok)
        return false;

    uint8_t blob[8];
    uint64_t coins = (uint64_t)(a + 2);
    for (int i = 0; i < 8; i++)
        blob[i] = (uint8_t)(coins >> (8 * i));
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_applied_height", -1, SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, blob, sizeof(blob), SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    static const uint8_t dummy_txid[32] = {0x75};
    if (!ok || !coins_kv_ensure_schema(db) ||
        !coins_kv_add(db, dummy_txid, 0, 0, a, false, NULL, 0))
        return false;
    uint8_t one = 1;
    st = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO progress_meta(key,value) VALUES(?,?)",
            -1, &st, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(st, 1, "coins_kv_migration_complete", -1,
                      SQLITE_STATIC);
    sqlite3_bind_blob(st, 2, &one, sizeof(one), SQLITE_STATIC);
    ok = sqlite3_step(st) == SQLITE_DONE;
    sqlite3_finalize(st);
    return ok;
}

static bool seed_pending_finalize_utxo(sqlite3 *db, int height)
{
    char sql[512];
    snprintf(sql, sizeof(sql),
        "INSERT OR REPLACE INTO utxo_apply_log(height,status,ok) "
        "VALUES(%d,'verified',1);",
        height);
    return exec_progress_sql(db, sql);
}

static struct block_index *insert_reducer_owner_block(
    struct main_state *ms,
    struct uint256 *hash,
    int height,
    struct block_index *prev,
    unsigned status)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(height & 0xff);
    hash->data[1] = (uint8_t)((height >> 8) & 0xff);
    hash->data[2] = (uint8_t)((height >> 16) & 0xff);
    hash->data[31] = 0x5a;
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->pprev = prev;
    bi->nStatus = status;
    bi->nTx = 1;
    bi->nChainTx = prev ? prev->nChainTx + 1 : 1;
    return bi;
}

int test_utxo_activation_paused(void)
{
    printf("\n=== utxo activation paused condition tests ===\n");
    int failures = 0;

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 1000);
        bool ok = true;

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hashes[2];
        struct block_index *tip = insert_test_block(
            &ms, hashes, 0, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        struct block_index *next = insert_test_block(
            &ms, hashes, 1, BLOCK_HAVE_DATA);
        ok = ok && tip && next && active_chain_move_window_tip(&ms.chain_active, tip);
        condition_engine_set_main_state(&ms);
        register_block_failed_mask_at_tip();

        condition_engine_tick();
        fake_clock_set(&clock, 1301);
        condition_engine_tick();
        ok = ok && condition_engine_get_active_count() == 1;
        ok = ok && block_failed_mask_at_tip_test_stall_type() == 2;
        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        ok = ok && condition_engine_dump_state_json(&dump, NULL);
        const struct json_value *cond =
            uap_json_condition(&dump, "block_failed_mask_at_tip");
        const struct json_value *detail = json_get(cond, "detail");
        ok = ok && detail != NULL;
        ok = ok &&
             json_get_int(json_get(detail, "block_target_height")) == 1;
        ok = ok &&
             json_get_int(json_get(detail, "tip_height_at_detect")) == 0;
        ok = ok &&
             strcmp(json_get_str(json_get(detail, "stall_type")),
                    "no_advance") == 0;
        ok = ok &&
             strcmp(json_get_str(json_get(detail, "delegated_owner")),
                    "none") == 0;
        ok = ok &&
             json_get_int(json_get(detail, "last_remedy_target_height")) == 1;
        ok = ok &&
             strcmp(json_get_str(json_get(detail, "last_remedy_result")),
                    "height_not_found") == 0;
        ok = ok &&
             json_get_bool(json_get(detail, "last_remedy_treated_ok"));
        ok = ok &&
             json_get_int(json_get(detail, "last_witness_tip_height")) == 0;
        ok = ok &&
             !json_get_bool(json_get(
                 detail, "last_witness_advanced_since_detect"));
        ok = ok &&
             !json_get_bool(json_get(
                 detail, "last_witness_target_failed_present"));
        ok = ok &&
             json_get_bool(json_get(
                 detail, "last_witness_target_have_data_present"));
        ok = ok && json_get(detail, "remedy_contract") != NULL;
        json_free(&dump);
        ok = ok && active_chain_move_window_tip(&ms.chain_active, next);
        fake_clock_set(&clock, 1302);
        condition_engine_tick();
        ok = ok && condition_engine_get_active_count() == 0;

        UAP_CHECK("block condition fires on stale tip with HAVE_DATA", ok);
        main_state_free(&ms);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 1400);
        bool ok = true;

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 active_h;
        struct uint256 fork_parent_h;
        struct uint256 fork_child_h;
        memset(&active_h, 0, sizeof(active_h));
        active_h.data[0] = 0xA0;
        memset(&fork_parent_h, 0, sizeof(fork_parent_h));
        fork_parent_h.data[0] = 0xF0;
        memset(&fork_child_h, 0, sizeof(fork_child_h));
        fork_child_h.data[0] = 0xF1;

        struct block_index *tip = chainstate_insert_block_index(
            (struct chainstate *)&ms, &active_h);
        struct block_index *fork_parent = chainstate_insert_block_index(
            (struct chainstate *)&ms, &fork_parent_h);
        struct block_index *fork_child = chainstate_insert_block_index(
            (struct chainstate *)&ms, &fork_child_h);
        if (tip) {
            tip->nHeight = 0;
            tip->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
            tip->nTx = 1;
            tip->nChainTx = 1;
        }
        if (fork_parent) {
            fork_parent->nHeight = 0;
            fork_parent->nStatus = BLOCK_VALID_TREE;
        }
        if (fork_child) {
            fork_child->nHeight = 1;
            fork_child->pprev = fork_parent;
            fork_child->nStatus = BLOCK_VALID_TREE | BLOCK_HAVE_DATA;
            fork_child->nTx = 1;
        }

        ok = ok && tip && fork_parent && fork_child &&
             active_chain_move_window_tip(&ms.chain_active, tip);
        condition_engine_set_main_state(&ms);
        register_block_failed_mask_at_tip();

        condition_engine_tick();
        fake_clock_set(&clock, 1701);
        condition_engine_tick();

        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && block_failed_mask_at_tip_test_target_height() == -1;

        UAP_CHECK("block condition ignores fork HAVE_DATA child", ok);
        condition_engine_set_main_state(NULL);
        main_state_free(&ms);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 6500);
        bool ok = true;
        struct main_state ms;
        struct block_index tip;
        struct block_index recovered_tip;
        struct block_index best_header;
        struct node_db ndb;
        struct snapshot_sync_service svc;
        uint8_t block_hash[32];
        uint8_t chain_work[32];
        struct watchdog_stats wd;

        memset(&tip, 0, sizeof(tip));
        memset(&recovered_tip, 0, sizeof(recovered_tip));
        memset(&best_header, 0, sizeof(best_header));
        memset(block_hash, 0x54, sizeof(block_hash));
        memset(chain_work, 0x58, sizeof(chain_work));
        main_state_init(&ms);
        tip.nHeight = 100;
        tip.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        recovered_tip.nHeight = 101;
        recovered_tip.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        recovered_tip.pprev = &tip;
        best_header.nHeight = 110;
        ms.pindex_best_header = &best_header;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);

        ok = ok && node_db_open(&ndb, ":memory:");
        ok = ok && seed_snapshot_manifest_db(&ndb, block_hash, chain_work);
        snapsync_init(&svc, &ndb);

        condition_engine_set_main_state(&ms);
        sync_monitor_init();
        sync_monitor_set_context(NULL, NULL, &ms);
        tip_wedged_resnapshot_test_set_runtime(&ndb, &svc);
        block_failed_mask_at_tip_test_mark_no_advance_exhausted(101, 100);
        register_tip_wedged_resnapshot();

        condition_engine_tick();
        bool observed = true;
        observed = observed && tip_wedged_resnapshot_test_remedy_calls() == 1;
        observed = observed && tip_wedged_resnapshot_test_recovery_accepted() == 1;
        observed = observed &&
                   tip_wedged_resnapshot_test_last_manifest_height() == 101;
        observed = observed && svc.state == SNAPSYNC_NEGOTIATING;
        observed = observed && condition_engine_get_active_count() == 1;
        sync_monitor_get_stats(&wd);
        observed = observed &&
                   wd.last_recovery == WATCHDOG_SNAPSHOT_RESNAPSHOT;
        observed = observed && wd.last_recovery_local_height == 100;
        observed = observed && wd.last_recovery_peer_height == 110;
        observed = observed && wd.last_recovery_target_height == 101;
        observed = observed && wd.last_recovery_manifest_height == 101;
        observed = observed &&
                   strcmp(wd.last_recovery_trigger,
                          "tip_no_advance_exhausted") == 0;

        ok = ok && active_chain_move_window_tip(&ms.chain_active, &recovered_tip);
        fake_clock_set(&clock, 6501);
        condition_engine_tick();
        observed = observed && condition_engine_get_active_count() == 0;
        ok = ok && observed;

        UAP_CHECK("tip_wedged_resnapshot labels exhausted no-advance recovery",
                  ok);
        snapsync_reset(&svc);
        node_db_close(&ndb);
        main_state_free(&ms);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 1500);
        bool ok = true;
        char dir[256];

        progress_store_close();
        test_make_tmpdir(dir, sizeof(dir), "block_failed_mask", "vh_owner");
        ok = ok && progress_store_open(dir);
        ok = ok && seed_validate_repair_frontier(progress_store_db(), 2);

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hashes[3];
        struct block_index *b0 = insert_test_block(
            &ms, hashes, 0, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        struct block_index *tip = insert_test_block(
            &ms, hashes, 1, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        struct block_index *next = insert_test_block(
            &ms, hashes, 2, BLOCK_HAVE_DATA);
        ok = ok && b0 && tip && next &&
             active_chain_move_window_tip(&ms.chain_active, tip);
        condition_engine_set_main_state(&ms);
        register_block_failed_mask_at_tip();

        condition_engine_tick();
        fake_clock_set(&clock, 1801);
        condition_engine_tick();

        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok &&
             block_failed_mask_at_tip_test_validate_repair_owner_height() == 2;
        ok = ok && block_failed_mask_at_tip_test_target_height() == -1;
        UAP_CHECK("repairable validate frontier owns generic no-advance stall",
                  ok);

        condition_engine_set_main_state(NULL);
        main_state_free(&ms);
        progress_store_close();
        test_cleanup_tmpdir(dir);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 2500);
        bool ok = true;
        char dir[256];
        int a = REDUCER_FRONTIER_TRUSTED_ANCHOR;

        progress_store_close();
        test_make_tmpdir(dir, sizeof(dir), "block_failed_mask",
                         "reducer_owner");
        ok = ok && progress_store_open(dir);
        ok = ok && seed_reducer_frontier_owner_schema(progress_store_db());

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 h1, h2, h3;
        struct block_index *b1 = insert_reducer_owner_block(
            &ms, &h1, a + 1, NULL, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        struct block_index *b2 = insert_reducer_owner_block(
            &ms, &h2, a + 2, b1, BLOCK_HAVE_DATA);
        struct block_index *b3 = insert_reducer_owner_block(
            &ms, &h3, a + 3, b2,
            BLOCK_VALID_TREE | BLOCK_HAVE_DATA | BLOCK_FAILED_VALID);
        ok = ok && seed_reducer_frontier_owner_rows(
            progress_store_db(), &h1, &h2, &h3);
        ok = ok && b1 && b2 && b3 &&
             active_chain_move_window_tip(&ms.chain_active, b1);

        condition_engine_set_main_state(&ms);
        register_block_failed_mask_at_tip();

        condition_engine_tick();
        fake_clock_set(&clock, 2801);
        condition_engine_tick();

        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok &&
             block_failed_mask_at_tip_test_reducer_owner_target() == a + 2;
        ok = ok && block_failed_mask_at_tip_test_reducer_owner_hstar() >= 0;
        ok = ok &&
             block_failed_mask_at_tip_test_reducer_owner_reason() != 0;
        ok = ok && block_failed_mask_at_tip_test_target_height() == -1;
        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        ok = ok && condition_engine_dump_state_json(&dump, NULL);
        const struct json_value *cond =
            uap_json_condition(&dump, "block_failed_mask_at_tip");
        const struct json_value *detail = json_get(cond, "detail");
        ok = ok && detail != NULL;
        ok = ok &&
             strcmp(json_get_str(json_get(detail, "delegated_owner")),
                    "reducer_frontier_reconcile_light") == 0;
        ok = ok &&
             json_get_int(json_get(detail, "reducer_frontier_owner_target")) ==
             a + 2;
        ok = ok &&
             strcmp(json_get_str(json_get(
                        detail, "reducer_frontier_owner_reason")),
                    "frontier_repair") == 0;
        json_free(&dump);
        UAP_CHECK("reducer frontier owns generic no-advance stall", ok);

        condition_engine_set_main_state(NULL);
        main_state_free(&ms);
        progress_store_close();
        test_cleanup_tmpdir(dir);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 3000);
        bool ok = true;
        char dir[256];

        progress_store_close();
        test_make_tmpdir(dir, sizeof(dir), "block_failed_mask",
                         "pending_finalize");
        ok = ok && progress_store_open(dir);
        ok = ok && seed_reducer_frontier_owner_schema(progress_store_db());
        ok = ok && seed_pending_finalize_utxo(progress_store_db(), 101);

        struct main_state ms;
        main_state_init(&ms);
        struct uint256 h100, h101;
        struct block_index *tip = insert_reducer_owner_block(
            &ms, &h100, 100, NULL, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        struct block_index *next = insert_reducer_owner_block(
            &ms, &h101, 101, tip, BLOCK_HAVE_DATA);
        ok = ok && tip && next &&
             active_chain_move_window_tip(&ms.chain_active, tip);

        condition_engine_set_main_state(&ms);
        register_block_failed_mask_at_tip();

        condition_engine_tick();
        fake_clock_set(&clock, 3301);
        condition_engine_tick();

        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && block_failed_mask_at_tip_test_reducer_owner_target() == 101;
        ok = ok && block_failed_mask_at_tip_test_target_height() == -1;

        struct json_value dump;
        json_init(&dump);
        json_set_object(&dump);
        ok = ok && condition_engine_dump_state_json(&dump, NULL);
        const struct json_value *cond =
            uap_json_condition(&dump, "block_failed_mask_at_tip");
        const struct json_value *detail = json_get(cond, "detail");
        ok = ok && detail != NULL;
        ok = ok &&
             strcmp(json_get_str(json_get(
                        detail, "reducer_frontier_owner_reason")),
                    "pending_finalize") == 0;
        json_free(&dump);

        int target = -1;
        int attempts = 0;
        block_failed_mask_at_tip_test_mark_no_advance_exhausted(101, 100);
        ok = ok &&
             !block_failed_mask_at_tip_recovery_exhausted(&target,
                                                          &attempts);
        ok = ok && target == 101;
        ok = ok && attempts == 5;

        UAP_CHECK("pending tip-finalize owns no-advance stall and exhaustion",
                  ok);

        condition_engine_set_main_state(NULL);
        main_state_free(&ms);
        progress_store_close();
        test_cleanup_tmpdir(dir);
        clock_reset_default();
    }

    {
        reset_conditions();
        bool ok = true;
        int target = -1;
        int attempts = 0;
        block_failed_mask_at_tip_test_mark_no_advance_exhausted(101, 100);
        ok = ok &&
             block_failed_mask_at_tip_recovery_exhausted(&target, &attempts);
        ok = ok && target == 101;
        ok = ok && attempts == 5;
        UAP_CHECK("unwitnessed no-advance exhaustion is recoverable", ok);
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 2000);
        bool ok = true;
        register_utxo_activation_paused();
        process_block_test_set_utxo_activation_paused_height(1500);

        condition_engine_tick();
        fake_clock_set(&clock, 2299);
        condition_engine_tick();
        ok = ok && condition_engine_get_active_count() == 0;
        ok = ok && process_block_test_get_utxo_activation_paused_height() == 1500;
        UAP_CHECK("detect does not fire before 300s", ok);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 3000);
        bool ok = true;
        /* Honest witness (Law 7) requires the chain tip to have ACTUALLY
         * advanced past the paused height — not just the pause flag cleared.
         * Stand up a real chain whose tip sits at the paused height so the
         * resumed activation observably reached it. */
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hashes[2];
        struct block_index *b0 = insert_test_block(
            &ms, hashes, 0, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        struct block_index *b1 = insert_test_block(
            &ms, hashes, 1, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        b1->nHeight = 1600;
        /* keep the parent label consistent (1599): a child relabel with a
         * stale parent label is the splice shape the validation-pack
         * linkage check now (correctly) refuses at the tip move. */
        if (b0) b0->nHeight = 1599;
        ok = ok && b0 && b1 &&
             active_chain_move_window_tip(&ms.chain_active, b1);
        condition_engine_set_main_state(&ms);
        register_utxo_activation_paused();
        process_block_test_set_utxo_activation_paused_height(1600);

        condition_engine_tick();
        fake_clock_set(&clock, 3301);
        condition_engine_tick();
        ok = ok && utxo_activation_paused_test_resume_calls() == 1;
        ok = ok && utxo_activation_paused_test_repair_calls() == 0;
        ok = ok && process_block_test_get_utxo_activation_paused_height() == -1;
        ok = ok && condition_engine_get_active_count() == 0;
        UAP_CHECK("resume remedy clears pause", ok);
        main_state_free(&ms);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 4000);
        bool ok = true;
        struct main_state ms;
        main_state_init(&ms);
        struct uint256 hashes[2];
        struct block_index *b0 = insert_test_block(
            &ms, hashes, 0, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        struct block_index *b1 = insert_test_block(
            &ms, hashes, 1, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA);
        b1->nHeight = 1700;
        if (b0) b0->nHeight = 1699; /* consistent parent label (see above) */
        ok = ok && b0 && b1 &&
             active_chain_move_window_tip(&ms.chain_active, b1);
        condition_engine_set_main_state(&ms);
        register_utxo_activation_paused();
        utxo_activation_paused_test_set_reason("utxo_audit_drift");
        process_block_test_set_utxo_activation_paused_height(1700);

        condition_engine_tick();
        fake_clock_set(&clock, 4301);
        condition_engine_tick();
        ok = ok && utxo_activation_paused_test_resume_calls() == 0;
        ok = ok && utxo_activation_paused_test_repair_calls() == 1;
        ok = ok && process_block_test_get_utxo_activation_paused_height() == -1;
        UAP_CHECK("drift reason takes repair path", ok);
        main_state_free(&ms);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 5000);
        _Atomic int operator_events;
        atomic_store(&operator_events, 0);
        bool ok = true;
        event_observe(EV_OPERATOR_NEEDED, operator_observer,
                      &operator_events);
        register_utxo_activation_paused();
        utxo_activation_paused_test_set_remedy_clear_enabled(false);
        process_block_test_set_utxo_activation_paused_height(1800);

        condition_engine_tick();
        fake_clock_set(&clock, 5301);
        condition_engine_tick();
        fake_clock_set(&clock, 5332);
        condition_engine_tick();
        ok = ok && condition_engine_get_unresolved_count() == 1;
        ok = ok && atomic_load(&operator_events) >= 1;
        UAP_CHECK("max attempts emits operator event", ok);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 6000);
        bool ok = true;
        struct main_state ms;
        struct block_index tip;
        struct block_index recovered_tip;
        struct block_index best_header;
        struct node_db ndb;
        struct snapshot_sync_service svc;
        uint8_t block_hash[32];
        uint8_t chain_work[32];
        struct json_value root;
        const struct json_value *conditions;
        const struct json_value *condition;
        const struct json_value *attempts;
        const struct json_value *last_outcome;
        struct watchdog_stats wd;

        memset(&tip, 0, sizeof(tip));
        memset(&recovered_tip, 0, sizeof(recovered_tip));
        memset(&best_header, 0, sizeof(best_header));
        memset(block_hash, 0x51, sizeof(block_hash));
        memset(chain_work, 0x55, sizeof(chain_work));
        main_state_init(&ms);
        tip.nHeight = 100;
        tip.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        recovered_tip.nHeight = 101;
        recovered_tip.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        recovered_tip.pprev = &tip;
        best_header.nHeight = 110;
        ms.pindex_best_header = &best_header;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);

        ok = ok && node_db_open(&ndb, ":memory:");
        ok = ok && seed_snapshot_manifest_db(&ndb, block_hash, chain_work);
        snapsync_init(&svc, &ndb);

        condition_engine_set_main_state(&ms);
        sync_monitor_init();
        sync_monitor_set_context(NULL, NULL, &ms);
        tip_wedged_resnapshot_test_set_runtime(&ndb, &svc);
        block_failed_mask_at_tip_test_mark_exhausted(101);
        register_tip_wedged_resnapshot();

        condition_engine_tick();
        bool observed = true;
        observed = observed && tip_wedged_resnapshot_test_remedy_calls() == 1;
        observed = observed && tip_wedged_resnapshot_test_recovery_accepted() == 1;
        observed = observed &&
                   tip_wedged_resnapshot_test_last_manifest_height() == 101;
        observed = observed && svc.state == SNAPSYNC_NEGOTIATING;
        observed = observed && condition_engine_get_active_count() == 1;
        sync_monitor_get_stats(&wd);
        observed = observed &&
                   wd.last_recovery == WATCHDOG_SNAPSHOT_RESNAPSHOT;
        observed = observed && wd.last_recovery_local_height == 100;
        observed = observed && wd.last_recovery_peer_height == 110;
        observed = observed && wd.last_recovery_target_height == 101;
        observed = observed && wd.last_recovery_manifest_height == 101;
        observed = observed &&
                   strcmp(wd.last_recovery_trigger,
                          "block_failed_mask_exhausted") == 0;

        json_init(&root);
        json_set_object(&root);
        bool dump_ok = condition_engine_dump_state_json(&root, NULL);
        observed = observed && dump_ok;
        conditions = json_get(&root, "conditions");
        condition = conditions ? json_at(conditions, 0) : NULL;
        attempts = condition ? json_get(condition, "attempts") : NULL;
        last_outcome = condition ? json_get(condition, "last_outcome") : NULL;
        const struct json_value *name =
            condition ? json_get(condition, "name") : NULL;
        observed = observed && condition != NULL;
        observed = observed && name &&
                   strcmp(json_get_str(name),
                          "tip_wedged_resnapshot") == 0;
        observed = observed && attempts && json_get_int(attempts) == 1;
        observed = observed && last_outcome &&
                   strcmp(json_get_str(last_outcome), "unwitnessed") == 0;
        const struct json_value *detail =
            condition ? json_get(condition, "detail") : NULL;
        observed = observed && detail != NULL;
        observed = observed &&
                   strcmp(json_get_str(json_get(detail, "trigger")),
                          "block_failed_mask_exhausted") == 0;
        observed = observed &&
                   json_get_int(json_get(
                       detail, "local_height_at_detect")) == 100;
        observed = observed &&
                   json_get_int(json_get(
                       detail, "best_header_at_detect")) == 110;
        observed = observed &&
                   json_get_int(json_get(
                       detail, "target_height_at_detect")) == 101;
        observed = observed &&
                   json_get_bool(json_get(detail, "recovery_attempted"));
        observed = observed &&
                   json_get_bool(json_get(detail, "recovery_accepted"));
        observed = observed &&
                   json_get_int(json_get(
                       detail, "last_manifest_height")) == 101;
        observed = observed &&
                   strcmp(json_get_str(json_get(
                              detail, "snapshot_sync_state")),
                          "negotiating") == 0;
        observed = observed &&
                   json_get_int(json_get(
                       detail, "last_witness_local_height")) == 100;
        observed = observed && json_get(detail, "remedy_contract") != NULL;

        ok = ok && active_chain_move_window_tip(&ms.chain_active, &recovered_tip);
        fake_clock_set(&clock, 6001);
        condition_engine_tick();
        observed = observed && condition_engine_get_active_count() == 0;
        ok = ok && observed;
        json_free(&root);

        UAP_CHECK("tip_wedged_resnapshot requests snapshot recovery", ok);
        snapsync_reset(&svc);
        node_db_close(&ndb);
        main_state_free(&ms);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 7000);
        bool ok = true;
        struct main_state ms;
        struct block_index tip;
        struct block_index best_header;
        struct node_db ndb;
        struct snapshot_sync_service svc;
        uint8_t block_hash[32];
        uint8_t chain_work[32];
        struct watchdog_stats wd;

        memset(&tip, 0, sizeof(tip));
        memset(&best_header, 0, sizeof(best_header));
        memset(block_hash, 0x52, sizeof(block_hash));
        memset(chain_work, 0x56, sizeof(chain_work));
        main_state_init(&ms);
        tip.nHeight = 100;
        tip.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        best_header.nHeight = 110;
        ms.pindex_best_header = &best_header;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);

        ok = ok && node_db_open(&ndb, ":memory:");
        ok = ok && seed_snapshot_manifest_db(&ndb, block_hash, chain_work);
        snapsync_init(&svc, &ndb);

        condition_engine_set_main_state(&ms);
        sync_monitor_init();
        sync_monitor_set_context(NULL, NULL, &ms);
        sync_monitor_test_set_local_recovery(true, true, 101, 3,
                                             "next-child-missing");
        tip_wedged_resnapshot_test_set_runtime(&ndb, &svc);
        register_tip_wedged_resnapshot();

        condition_engine_tick();
        ok = ok && tip_wedged_resnapshot_test_remedy_calls() == 1;
        ok = ok && tip_wedged_resnapshot_test_recovery_accepted() == 1;
        ok = ok && tip_wedged_resnapshot_test_last_manifest_height() == 101;
        ok = ok && svc.state == SNAPSYNC_NEGOTIATING;
        ok = ok && condition_engine_get_active_count() == 1;
        sync_monitor_get_stats(&wd);
        ok = ok && wd.last_recovery == WATCHDOG_SNAPSHOT_RESNAPSHOT;
        ok = ok && wd.last_recovery_target_height == 101;
        ok = ok && wd.last_recovery_manifest_height == 101;
        ok = ok && strcmp(wd.last_recovery_trigger,
                          "local_import_exhausted") == 0;

        UAP_CHECK("tip_wedged_resnapshot uses exhausted local import", ok);
        snapsync_reset(&svc);
        node_db_close(&ndb);
        main_state_free(&ms);
        clock_reset_default();
    }

    {
        /* Regression for the missing cooldown_secs/cooldown_max_rearms: a
         * requested snapshot recovery gets accepted (svc moves to
         * NEGOTIATING) but the negotiation never completes -- local height
         * never reaches target and svc never reaches SNAPSYNC_COMPLETE --
         * so the witness keeps failing and every backoff-spaced tick accrues
         * another attempt against the SAME persistent, external-dependency
         * fault (a peer that never finishes negotiating). Before this fix
         * cooldown_secs was 0 ("legacy"), so condition_cooldown_rearm()
         * refused to reset the attempt budget once attempts hit
         * max_attempts=3 and the engine latched EV_OPERATOR_NEEDED forever
         * without ever calling the remedy again. Drive the same persistent
         * local-import-exhausted stall past max_attempts and assert the
         * engine re-arms and calls the remedy again instead of latching. */
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 7500);
        bool ok = true;
        struct main_state ms;
        struct block_index tip;
        struct block_index best_header;
        struct node_db ndb;
        struct snapshot_sync_service svc;
        uint8_t block_hash[32];
        uint8_t chain_work[32];

        memset(&tip, 0, sizeof(tip));
        memset(&best_header, 0, sizeof(best_header));
        memset(block_hash, 0x54, sizeof(block_hash));
        memset(chain_work, 0x58, sizeof(chain_work));
        main_state_init(&ms);
        tip.nHeight = 100;
        tip.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        best_header.nHeight = 110;
        ms.pindex_best_header = &best_header;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);

        ok = ok && node_db_open(&ndb, ":memory:");
        ok = ok && seed_snapshot_manifest_db(&ndb, block_hash, chain_work);
        snapsync_init(&svc, &ndb);

        condition_engine_set_main_state(&ms);
        sync_monitor_init();
        sync_monitor_set_context(NULL, NULL, &ms);
        sync_monitor_test_set_local_recovery(true, true, 101, 3,
                                             "next-child-missing");
        tip_wedged_resnapshot_test_set_runtime(&ndb, &svc);
        register_tip_wedged_resnapshot();

        condition_engine_tick();  /* attempt 1/3 */
        ok = ok && tip_wedged_resnapshot_test_remedy_calls() == 1;
        ok = ok && condition_engine_get_active_count() == 1;

        fake_clock_set(&clock, 7801);  /* +301s: past backoff_secs (300) */
        condition_engine_tick();  /* attempt 2/3 */
        ok = ok && tip_wedged_resnapshot_test_remedy_calls() == 2;
        ok = ok && condition_engine_get_active_count() == 1;

        fake_clock_set(&clock, 8102);  /* +301s */
        condition_engine_tick();  /* attempt 3/3 -- hits max_attempts */
        ok = ok && tip_wedged_resnapshot_test_remedy_calls() == 3;
        ok = ok && condition_engine_get_active_count() == 1;

        struct condition_runtime_snapshot snap;
        memset(&snap, 0, sizeof(snap));
        ok = ok && condition_engine_get_registered_snapshot(
                       "tip_wedged_resnapshot", &snap);
        ok = ok && snap.max_attempts == 3;
        ok = ok && snap.attempts == 3;
        ok = ok && snap.operator_needed_emitted;
        ok = ok && snap.cooldown_secs == 600;
        ok = ok && snap.cooldown_max_rearms == 0;

        /* Past max_attempts, past backoff -- without cooldown_secs this
         * would stay latched at operator_needed forever and the remedy
         * would never run again. */
        fake_clock_set(&clock, 8403);  /* +301s */
        condition_engine_tick();
        ok = ok && tip_wedged_resnapshot_test_remedy_calls() == 4;
        ok = ok && condition_engine_get_active_count() == 1;

        memset(&snap, 0, sizeof(snap));
        ok = ok && condition_engine_get_registered_snapshot(
                       "tip_wedged_resnapshot", &snap);
        ok = ok && snap.attempts < snap.max_attempts;  /* re-armed, not latched */

        UAP_CHECK("tip_wedged_resnapshot re-arms on cooldown past "
                  "max_attempts instead of latching forever", ok);
        snapsync_reset(&svc);
        node_db_close(&ndb);
        main_state_free(&ms);
        clock_reset_default();
    }

    {
        reset_conditions();
        struct fake_clock clock;
        fake_clock_install(&clock, 8000);
        bool ok = true;
        struct main_state ms;
        struct block_index tip;
        struct block_index best_header;
        struct node_db ndb;
        struct snapshot_sync_service svc;
        uint8_t block_hash[32];
        uint8_t chain_work[32];

        memset(&tip, 0, sizeof(tip));
        memset(&best_header, 0, sizeof(best_header));
        memset(block_hash, 0x53, sizeof(block_hash));
        memset(chain_work, 0x57, sizeof(chain_work));
        main_state_init(&ms);
        tip.nHeight = 100;
        tip.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        best_header.nHeight = 110;
        ms.pindex_best_header = &best_header;
        ok = ok && active_chain_move_window_tip(&ms.chain_active, &tip);

        ok = ok && node_db_open(&ndb, ":memory:");
        ok = ok && seed_snapshot_manifest_db(&ndb, block_hash, chain_work);
        snapsync_init(&svc, &ndb);
        svc.state = SNAPSYNC_NEGOTIATING;

        condition_engine_set_main_state(&ms);
        sync_monitor_init();
        sync_monitor_set_context(NULL, NULL, &ms);
        tip_wedged_resnapshot_test_set_runtime(&ndb, &svc);
        block_failed_mask_at_tip_test_mark_exhausted(101);
        register_tip_wedged_resnapshot();

        condition_engine_tick();
        ok = ok && tip_wedged_resnapshot_test_remedy_calls() == 0;
        ok = ok && tip_wedged_resnapshot_test_recovery_accepted() == 0;
        ok = ok && svc.state == SNAPSYNC_NEGOTIATING;
        ok = ok && condition_engine_get_active_count() == 0;

        UAP_CHECK("tip_wedged_resnapshot waits for idle snapshot sync", ok);
        snapsync_reset(&svc);
        node_db_close(&ndb);
        main_state_free(&ms);
        clock_reset_default();
    }

    reset_conditions();
    clock_reset_default();
    return failures;
}
