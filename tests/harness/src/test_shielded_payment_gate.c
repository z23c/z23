/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * MVP criterion #4 CI gate: transparent -> mixed shielded/transparent payment.
 *
 * The gate exercises the shipped RPC/controller path end-to-end inside
 * `test_zcl`:
 *   1. create a wallet-owned transparent funding address
 *   2. persist one spendable wallet UTXO into node.db
 *   3. create a wallet-owned Sapling address via `z_getnewaddress`
 *   4. durably plan a mixed t->(z,t) transaction without mutating mempool
 *   5. commit the exact encrypted plan through `vault_intent_commit`
 *   6. assert the tx reached mempool, has both output classes, and can be
 *      confirmed through simnet and rescanned from its actual disk body into
 *      a fresh uncredited recipient wallet, yielding exactly 1 ZCL
 *
 * This is an opt-in stress gate because it depends on real Sapling proving
 * params and builds a real proof. Run with:
 *   devbuild --wait make -j2 test-shielded-payment
 * A successful target exit without the observed proof/rescan case is not PASS.
 */

#include "platform/time_compat.h"
#include "test/test_core.h"
#include "keys/key_io.h"
#include "coins/undo.h"
#include "validation/main_state.h"
#include "sapling/params_init.h"
#include "models/wallet_tx.h"
#include "models/block.h"
#include "models/wallet_identity.h"
#include "controllers/wallet_controller.h"
#include "controllers/wallet_shielded_controller.h"
#include "net/connman.h"
#include "services/sync_monitor.h"
#include "services/wallet_backup_service.h"
#include "sync/sync_state.h"
#include "wallet/keystore.h"
#include "wallet/wallet_canary.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "coins/coins.h"
#include "coins/coins_view.h"
#include "consensus/validation.h"
#include "sapling/sapling_prover.h"
#include "validation/accept_to_mempool.h"
#include "validation/contextual_check_tx.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "jobs/reducer_frontier.h"
#include "jobs/reducer_frontier_schema.h"
#include "sim/simnet.h"
#include "sim/simnet_sapling.h"
#include "storage/disk_block_io.h"

#include <errno.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdatomic.h>

#define P11_4_TIP_HEIGHT 500000

static bool p11_4_params_available(char *params_dir, size_t params_dir_size)
{
    const char *home = getenv("HOME");
    if (!home || !params_dir || params_dir_size == 0)
        return false;

    snprintf(params_dir, params_dir_size, "%s/.zcash-params", home);

    const char *files[] = {
        "sapling-spend.params",
        "sapling-output.params",
        "sprout-groth16.params",
        "sprout-verifying.key",
    };

    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
        char path[768];
        snprintf(path, sizeof(path), "%s/%s", params_dir, files[i]);
        if (access(path, R_OK) != 0)
            return false;
    }

    return true;
}

static bool p11_4_make_tmpdir(char *tmpdir, size_t tmpdir_size)
{
    if (!tmpdir || tmpdir_size < 32)
        return false;
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    /* Reject an oversized absolute name before test_mkdtemp's fatal formatter.
     * The 256-byte caller buffer also leaves room in all derived 320-byte paths. */
    int dir_n = snprintf(tmpdir, tmpdir_size, "%s/test-tmp/p11_4_XXXXXX", cwd);
    if (dir_n <= 0 || (size_t)dir_n >= tmpdir_size)
        return false;
    return test_mkdtemp(tmpdir, tmpdir_size, "p11_4") != NULL;
}

/* Only reached after successful exclusive leaf creation and fixture closes. */
static bool p11_4_cleanup_owned(const char *tmpdir)
{
    if (test_rm_rf_recursive(tmpdir) == 0)
        return true;
    printf("FAIL (owned fixture cleanup path=%s errno=%d)\n", tmpdir, errno);
    return false;
}

static bool p11_4_save_tip(struct node_db *ndb,
                           const struct block_index *tip)
{
    if (!ndb || !tip)
        return false;
    struct db_block block;
    memset(&block, 0, sizeof(block));
    memcpy(block.hash, tip->hashBlock.data, sizeof(block.hash));
    memset(block.prev_hash, 0x4f, sizeof(block.prev_hash));
    memset(block.merkle_root, 0x4d, sizeof(block.merkle_root));
    memset(block.chain_work, 0x4c, sizeof(block.chain_work));
    block.height = tip->nHeight;
    block.time = tip->nTime;
    block.bits = 0x1d00ffffU;
    block.status = 3;
    static uint8_t solution[] = {0x01, 0x02};
    block.solution = solution;
    block.solution_len = sizeof(solution);
    return db_block_save(ndb, &block);
}

enum {
    P11_4_TRUST_READY = 0,
    P11_4_TRUST_NO_STORE = 1,
    P11_4_TRUST_NO_DB = 2,
    P11_4_TRUST_NO_COINS = 3,
    P11_4_TRUST_NO_REDUCER = 4,
    P11_4_TRUST_NO_COIN = 5
};

struct p11_4_trust_txn {
    sqlite3 *db;
    sqlite3_stmt *st;
    char *err;
    uint8_t tip_hash[32];
    bool began;
    bool applied;
    bool stamped;
    bool ok;
    bool header_prepared;
    bool header_written;
    bool committed;
    bool self_folded;
};

static int p11_4_trust_prepare_coin(const char *dir, sqlite3 **db_out)
{
    if (!progress_store_open(dir))
        return P11_4_TRUST_NO_STORE;
    sqlite3 *db = progress_store_db();
    if (!db)
        return P11_4_TRUST_NO_DB;
    *db_out = db;
    if (!coins_kv_ensure_schema(db))
        return P11_4_TRUST_NO_COINS;
    if (!reducer_frontier_ensure_schema(db))
        return P11_4_TRUST_NO_REDUCER;
    reducer_frontier_provable_tip_set(P11_4_TIP_HEIGHT);
    struct uint256 txid;
    uint256_set_null(&txid);
    txid.data[0] = 0x51;
    txid.data[31] = 0x77;
    const unsigned char script[4] = {0xE0, 0xE0, 0xE0, 0xE0};
    if (!coins_kv_add(db, txid.data, 0, 1234, P11_4_TIP_HEIGHT, true,
                      script, sizeof(script)))
        return P11_4_TRUST_NO_COIN;
    return P11_4_TRUST_READY;
}

static void p11_4_trust_write_header(struct p11_4_trust_txn *txn)
{
    uint8_t migrated = 1;
    memset(txn->tip_hash, 0x50, sizeof(txn->tip_hash));
    txn->began = sqlite3_exec(txn->db, "BEGIN IMMEDIATE", NULL, NULL,
                              &txn->err) == SQLITE_OK;
    txn->applied = txn->began && coins_kv_set_applied_height_in_tx(
        txn->db, P11_4_TIP_HEIGHT + 1);
    txn->stamped = txn->applied && progress_meta_set_in_tx(
        txn->db, COINS_KV_MIGRATION_COMPLETE_KEY, &migrated, sizeof(migrated));
    txn->ok = txn->began && txn->applied && txn->stamped;
    if (txn->ok) {
        txn->ok = sqlite3_prepare_v2(txn->db,
            "INSERT OR REPLACE INTO validate_headers_log"
            "(height,hash,ok,validated_at) VALUES(?1,?2,1,0)",
            -1, &txn->st, NULL) == SQLITE_OK;
        txn->header_prepared = txn->ok;
    }
    if (txn->ok) {
        sqlite3_bind_int(txn->st, 1, P11_4_TIP_HEIGHT);
        sqlite3_bind_blob(txn->st, 2, txn->tip_hash, sizeof(txn->tip_hash),
                          SQLITE_STATIC);
        txn->ok = sqlite3_step(txn->st) == SQLITE_DONE;
        txn->header_written = txn->ok;
    }
}

static void p11_4_trust_finish_txn(struct p11_4_trust_txn *txn)
{
    if (txn->st)
        sqlite3_finalize(txn->st);
    if (txn->ok) {
        txn->ok = sqlite3_exec(txn->db, "COMMIT", NULL, NULL, &txn->err) ==
            SQLITE_OK;
        txn->committed = txn->ok;
    } else if (txn->began) {
        (void)sqlite3_exec(txn->db, "ROLLBACK", NULL, NULL, NULL);
    }
    if (txn->ok) {
        txn->ok = coins_kv_mark_self_folded(txn->db);
        txn->self_folded = txn->ok;
    }
    if (txn->err)
        sqlite3_free(txn->err);
}

/* The production wallet commit path is sovereignty-gated. Populate the same
 * minimal self-derived progress projection a running node has; otherwise this
 * wallet test exits before reaching Sapling transaction construction. */
static bool p11_4_open_trust_fixture(const char *dir)
{
    sqlite3 *db = NULL;
    int prep = p11_4_trust_prepare_coin(dir, &db);
    if (prep == P11_4_TRUST_NO_STORE) {
        printf("(trust fixture: progress_store_open) ");
        return false;
    }
    if (prep == P11_4_TRUST_NO_DB) {
        printf("(trust fixture: progress_store_db) ");
        return false;
    }
    if (prep == P11_4_TRUST_NO_COINS) {
        printf("(trust fixture: coins schema: %s) ", sqlite3_errmsg(db));
        return false;
    }
    if (prep == P11_4_TRUST_NO_REDUCER) {
        printf("(trust fixture: reducer schema: %s) ", sqlite3_errmsg(db));
        return false;
    }
    if (prep == P11_4_TRUST_NO_COIN) {
        printf("(trust fixture: authority coin: %s) ", sqlite3_errmsg(db));
        return false;
    }
    struct p11_4_trust_txn txn;
    memset(&txn, 0, sizeof(txn));
    txn.db = db;
    p11_4_trust_write_header(&txn);
    p11_4_trust_finish_txn(&txn);
    if (!txn.ok)
        printf("(trust fixture: begin=%d applied=%d stamped=%d "
               "header_prepared=%d header_written=%d committed=%d "
               "self_folded=%d sqlite=%s) ", txn.began, txn.applied,
               txn.stamped, txn.header_prepared, txn.header_written,
               txn.committed, txn.self_folded, sqlite3_errmsg(db));
    return txn.ok;
}

static bool p11_4_build_funding_utxo(struct node_db *ndb,
                                     struct coins_view_cache *coins_tip,
                                     const struct uint256 *txid,
                                     const struct key_id *kid,
                                     const struct script *script,
                                     int utxo_height)
{
    struct db_wallet_utxo utxo;
    memset(&utxo, 0, sizeof(utxo));
    if (!txid)
        return false;
    memcpy(utxo.txid, txid->data, sizeof(utxo.txid));
    utxo.vout = 0;
    utxo.value = 3 * COIN_VALUE;
    memcpy(utxo.address_hash, kid->id.data, 20);
    utxo.script = (uint8_t *)script->data;
    utxo.script_len = script->size;
    utxo.height = utxo_height;
    utxo.is_coinbase = true;
    if (!db_wallet_utxo_save(ndb, &utxo))
        return false;

    /* The wallet selector reads its owned UTXOs from node.db, while the
     * shared mempool-admission gate reads the consensus UTXO view. A real
     * node keeps those projections in sync; this fixture must populate both
     * so the RPC exercises the complete production acceptance context. */
    struct coins_cache_entry *entry =
        coins_view_cache_modify_new(coins_tip, txid);
    if (!entry)
        return false;
    coins_alloc(&entry->coins, 1);
    if (!entry->coins.vout)
        return false;
    entry->coins.vout[0].value = utxo.value;
    entry->coins.vout[0].script_pub_key = *script;
    entry->coins.height = utxo.height;
    entry->coins.version = 1;
    entry->coins.is_coinbase = true;
    return true;
}

static bool p11_4_rpc_z_getnewaddress(struct rpc_table *tbl,
                                      char *out, size_t out_size)
{
    struct json_value params;
    struct json_value result;
    json_init(&params);
    json_init(&result);
    json_set_array(&params);

    bool ok = rpc_table_execute(tbl, "z_getnewaddress", &params, &result);
    ok = ok && result.type == JSON_STR;
    ok = ok && json_get_str(&result) != NULL;
    if (ok) {
        snprintf(out, out_size, "%s", json_get_str(&result));
    }

    json_free(&params);
    json_free(&result);
    return ok;
}

struct p11_4_plan_view {
    const char *plan_id;
    const char *digest;
    const char *route;
    const char *from;
    const struct json_value *effects;
};

static void p11_4_plan_view_load(bool ok, const struct json_value *result,
                                 struct p11_4_plan_view *view)
{
    view->plan_id = ok && result->type == JSON_OBJ
        ? json_get_str(json_get(result, "plan_id")) : NULL;
    view->digest = ok && result->type == JSON_OBJ
        ? json_get_str(json_get(result, "digest")) : NULL;
    view->route = ok && result->type == JSON_OBJ
        ? json_get_str(json_get(result, "route")) : NULL;
    view->from = ok && result->type == JSON_OBJ
        ? json_get_str(json_get(result, "from")) : NULL;
    view->effects = ok && result->type == JSON_OBJ
        ? json_get(result, "effects") : NULL;
}

static bool p11_4_plan_route_effects(const struct p11_4_plan_view *view,
                                     const struct json_value *result,
                                     const char *from_addr)
{
    return view->route && strcmp(view->route, "mixed") == 0 && view->from &&
        strcmp(view->from, from_addr) == 0 &&
        json_get_int(json_get(result, "confirmation_policy")) == 6 &&
        view->effects && view->effects->type == JSON_ARR &&
        json_size(view->effects) == 2;
}

static bool p11_4_plan_fresh_ok(bool ok, const struct json_value *result,
                                const struct p11_4_plan_view *view,
                                const char *from_addr,
                                struct tx_mempool *mempool)
{
    return ok && json_get_bool(json_get(result, "ok")) &&
        view->plan_id && strlen(view->plan_id) == 64 &&
        view->digest && strlen(view->digest) == 64 &&
        p11_4_plan_route_effects(view, result, from_addr) &&
        json_get(result, "idempotent_plan") != NULL &&
        !json_get_bool(json_get(result, "idempotent_plan")) &&
        tx_mempool_size(mempool) == 0;
}

static bool p11_4_plan_retry_ok(bool ok, const struct json_value *result,
                                const struct p11_4_plan_view *view,
                                const char *from_addr,
                                const char *plan_id_copy,
                                const char *digest_copy,
                                struct tx_mempool *mempool)
{
    return ok && json_get_bool(json_get(result, "ok")) &&
        json_get_bool(json_get(result, "idempotent_plan")) &&
        view->plan_id && strcmp(view->plan_id, plan_id_copy) == 0 &&
        view->digest && strcmp(view->digest, digest_copy) == 0 &&
        p11_4_plan_route_effects(view, result, from_addr) &&
        tx_mempool_size(mempool) == 0;
}

static const char *p11_4_commit_txid(bool ok, const struct json_value *result)
{
    return ok && result->type == JSON_OBJ
        ? json_get_str(json_get(result, "txid")) : NULL;
}

static bool p11_4_commit_accepted(bool ok, const struct json_value *result,
                                  const char *txid)
{
    return ok && json_get_bool(json_get(result, "ok")) && txid &&
        strlen(txid) == 64;
}

static const char *p11_4_json_str_or(const struct json_value *result,
                                     const char *key, const char *fallback)
{
    const char *value = json_get_str(json_get(result, key));
    return value ? value : fallback;
}

static void p11_4_copy_text(bool ok, const char *src, char *dst, size_t dst_size)
{
    if (ok)
        snprintf(dst, dst_size, "%s", src);
}

static bool p11_4_vault_mixed(struct rpc_table *tbl,
                              const char *from_addr,
                              const char *zaddr,
                              struct tx_mempool *mempool,
                              char *txid_hex, size_t txid_hex_size)
{
    struct json_value params, input, effects, effect, result;
    json_init(&params); json_set_array(&params);
    json_init(&input); json_set_object(&input);
    json_init(&effects); json_set_array(&effects);
    json_init(&effect); json_set_object(&effect);
    json_init(&result);

    /* This isolated wallet exercises a 1 ZCL payment. Development custody
     * retains its separate 0.05 ZCL lifetime cap. */
    json_push_kv_str(&input, "wallet_scope", "test");
    json_push_kv_str(&input, "route", "mixed");
    json_push_kv_str(&input, "from", from_addr);
    json_push_kv_str(&input, "idempotency_key", "shielded-payment-mixed-1");
    json_push_kv_str(&effect, "asset", "ZCL");
    json_push_kv_str(&effect, "to", zaddr);
    json_push_kv_str(&effect, "amount", "1.00000000");
    json_push_back(&effects, &effect);

    /* One transaction crossing both recipient pools is the production
     * mixed-recipient shape the durable vault route must preserve. */
    json_free(&effect); json_init(&effect); json_set_object(&effect);
    json_push_kv_str(&effect, "asset", "ZCL");
    json_push_kv_str(&effect, "to", from_addr);
    json_push_kv_str(&effect, "amount", "0.01000000");
    json_push_back(&effects, &effect);
    json_push_kv(&input, "effects", &effects);
    json_push_back(&params, &input);

    char plan_id_copy[65] = {0};
    char digest_copy[65] = {0};
    bool ok = rpc_table_execute(tbl, "vault_intent_plan", &params, &result);
    struct p11_4_plan_view view;
    p11_4_plan_view_load(ok, &result, &view);
    ok = p11_4_plan_fresh_ok(ok, &result, &view, from_addr, mempool);
    if (!ok)
        printf("(plan code=%s message=%s) ",
               p11_4_json_str_or(&result, "code", "RPC_FAILURE"),
               p11_4_json_str_or(&result, "message", "no message"));
    p11_4_copy_text(ok, view.plan_id, plan_id_copy, sizeof(plan_id_copy));
    p11_4_copy_text(ok, view.digest, digest_copy, sizeof(digest_copy));

    /* An agent reviewing an idempotent retry must receive the same complete
     * owner-visible plan, not merely a plan id and reservation row. */
    json_free(&result); json_init(&result);
    ok = ok && rpc_table_execute(tbl, "vault_intent_plan", &params, &result);
    p11_4_plan_view_load(ok, &result, &view);
    ok = p11_4_plan_retry_ok(ok, &result, &view, from_addr, plan_id_copy,
                             digest_copy, mempool);
    if (!ok)
        printf("(idempotent plan code=%s message=%s) ",
               p11_4_json_str_or(&result, "code", "RPC_FAILURE"),
               p11_4_json_str_or(&result, "message", "incomplete retry review"));

    json_free(&params); json_init(&params); json_set_array(&params);
    json_free(&input); json_init(&input); json_set_object(&input);
    json_push_kv_str(&input, "wallet_scope", "test");
    json_push_kv_str(&input, "plan_id", plan_id_copy);
    json_push_kv_bool(&input, "confirm", true);
    json_push_back(&params, &input);
    json_free(&result); json_init(&result);
    ok = ok && rpc_table_execute(tbl, "vault_intent_commit", &params, &result);
    const char *txid = p11_4_commit_txid(ok, &result);
    ok = p11_4_commit_accepted(ok, &result, txid);
    if (!ok)
        printf("(commit code=%s message=%s) ",
               p11_4_json_str_or(&result, "code", "RPC_FAILURE"),
               p11_4_json_str_or(&result, "message", "no message"));
    p11_4_copy_text(ok, txid, txid_hex, txid_hex_size);

    json_free(&params);
    json_free(&input);
    json_free(&effects);
    json_free(&effect);
    json_free(&result);
    return ok;
}

/* The recipient has only the exact receive key, never sender note state. */
static struct wallet *p11_4_recipient(const struct wallet *sender,
                                      const char *address)
{
    uint8_t diversifier[11], pk_d[32];
    if (!sapling_decode_payment_address(address, diversifier, pk_d)) {
        printf("(recipient address decode failed) ");
        return NULL;
    }
    const struct sapling_key_entry *key = sapling_keystore_find_by_address(
        &sender->sapling_keys, diversifier, pk_d);
    struct wallet *recipient = zcl_calloc(1, sizeof(*recipient),
                                          "p11_4_recipient");
    if (!recipient) {
        printf("(recipient allocation failed) ");
        return NULL;
    }
    wallet_init(recipient);
    if (!key || !sapling_keystore_import_xsk(&recipient->sapling_keys,
                                             &key->xsk)) {
        printf("(recipient key import failed) ");
        wallet_free(recipient);
        free(recipient);
        return NULL;
    }
    return recipient;
}

static bool p11_4_outputs(const struct transaction *tx,
                          const struct script *pay, const struct wallet *sender,
                          int64_t *sum)
{
    int64_t total = 0;
    size_t payments = 0;
    bool change = false;
    for (size_t i = 0; i < tx->num_vout; i++) {
        const struct tx_out *out = &tx->vout[i];
        if (out->value < 0 || out->value > 3 * COIN_VALUE - total) {
            printf("(transparent output value invalid) ");
            return false;
        }
        total += out->value;
        if (!wallet_is_mine(sender, out)) {
            printf("(unexpected transparent destination) ");
            return false;
        }
        bool same = out->script_pub_key.size == pay->size &&
            memcmp(out->script_pub_key.data, pay->data, pay->size) == 0;
        payments += same && out->value == 1000000;
        change |= out->value > 1000000 && wallet_is_mine(sender, out);
    }
    *sum = total;
    bool ok = payments == 1 && change;
    if (!ok)
        printf("(transparent payment/change missing) ");
    return ok;
}

static bool p11_4_conserves(const struct transaction *tx,
                            struct tx_mempool *pool,
                            const struct uint256 *funding,
                            const struct script *pay,
                            const struct wallet *sender)
{
    int64_t total = 0;
    struct tx_mempool_entry_view view;
    bool outputs = p11_4_outputs(tx, pay, sender, &total);
    size_t entries = tx_mempool_collect_views(pool, &view, 1);
    int64_t fee = entries == 1 ? view.fee : -1;
    bool ok = tx->num_vin == 1 && tx->vin[0].prevout.n == 0 &&
        uint256_cmp(&tx->vin[0].prevout.hash, funding) == 0 &&
        tx->value_balance == -COIN_VALUE && outputs && entries == 1 &&
        tx_mempool_size(pool) == 1 &&
        uint256_cmp(&view.hash, &tx->hash) == 0 &&
        fee >= 0 && fee <= 3 * COIN_VALUE &&
        total + COIN_VALUE + fee == 3 * COIN_VALUE;
    if (!ok)
        printf("(funding/output conservation total=%lld fee=%lld) ",
               (long long)total, (long long)fee);
    return ok;
}

static bool p11_4_full_coverage(const struct wallet_rescan_report *r)
{
    return r->coverage_ok && !r->blocker[0] &&
        r->blocks_in_range == 1 && r->blocks_indexed == 1 &&
        r->blocks_scanned == 1 && r->blocks_no_index == 0 &&
        r->blocks_missing_data == 0 && r->blocks_read_failed == 0 &&
        r->shielded_txs_unscanned == 0 && !r->shielded_scan_skipped &&
        r->sapling_key_count == 1;
}

static bool p11_4_scan_refusals(struct wallet *recipient,
                               struct active_chain *chain,
                               struct block_index *index, const char *dir)
{
    struct wallet_rescan_report r;
    index->nStatus &= ~BLOCK_HAVE_DATA;
    (void)wallet_rescan_report(recipient, chain, index->nHeight,
                               index->nHeight, dir, &r);
    bool missing = !r.coverage_ok && r.blocks_missing_data == 1 &&
        recipient->num_sapling_notes == 0;
    index->nStatus |= BLOCK_HAVE_DATA;
    index->hashBlock.data[0] ^= 1;
    (void)wallet_rescan_report(recipient, chain, index->nHeight,
                               index->nHeight, dir, &r);
    bool mismatch = !r.coverage_ok && r.blocks_read_failed == 1 &&
        recipient->num_sapling_notes == 0;
    index->hashBlock.data[0] ^= 1;
    unsigned int saved_pos = index->nDataPos;
    index->nDataPos = UINT_MAX;
    (void)wallet_rescan_report(recipient, chain, index->nHeight,
                               index->nHeight, dir, &r);
    bool unreadable = !r.coverage_ok && r.blocks_read_failed == 1 &&
        recipient->num_sapling_notes == 0;
    index->nDataPos = saved_pos;
    bool ok = missing && mismatch && unreadable &&
        wallet_get_sapling_balance(recipient) == 0;
    printf("(confirmed rescan missing=%d mismatch=%d unreadable=%d) ",
           missing, mismatch, unreadable);
    return ok;
}

static bool p11_4_scan_credit(struct wallet *recipient,
                              struct active_chain *chain,
                              const struct block_index *index,
                              const struct transaction *payment,
                              const char *dir)
{
    struct wallet_rescan_report r;
    int found = wallet_rescan_report(recipient, chain, index->nHeight,
                                      index->nHeight, dir, &r);
    bool first = found == 1 && p11_4_full_coverage(&r) &&
        r.shielded_notes_found == 1 && recipient->num_sapling_notes == 1 &&
        wallet_get_sapling_balance(recipient) == COIN_VALUE;
    if (!first) {
        printf("(confirmed first scan found=%d notes=%zu balance=%lld) ",
               found, recipient->num_sapling_notes,
               (long long)wallet_get_sapling_balance(recipient));
        return false;
    }
    struct sapling_received_note note = recipient->sapling_notes[0];
    bool identity = uint256_cmp(&note.txid, &payment->hash) == 0 &&
        note.output_index == 0 && note.value == COIN_VALUE;
    (void)wallet_rescan_report(recipient, chain, index->nHeight,
                               index->nHeight, dir, &r);
    bool repeated = p11_4_full_coverage(&r) && r.shielded_notes_found == 0 &&
        recipient->num_sapling_notes == 1 &&
        wallet_get_sapling_balance(recipient) == COIN_VALUE &&
        uint256_cmp(&recipient->sapling_notes[0].txid, &note.txid) == 0 &&
        recipient->sapling_notes[0].output_index == note.output_index;
    printf("(confirmed credit1ZCL=%d identity=%d repeat=%d) ",
           first, identity, repeated);
    return identity && repeated;
}

static bool p11_4_keyless_scan(const struct active_chain *chain,
                              int height, const char *dir)
{
    struct wallet *keyless = zcl_calloc(1, sizeof(*keyless),
                                        "p11_4_keyless");
    if (!keyless) {
        printf("(keyless recipient allocation failed) ");
        return false;
    }
    wallet_init(keyless);
    struct wallet_rescan_report r;
    int found = wallet_rescan_report(keyless, chain, height, height, dir, &r);
    bool ok = found == 0 && r.blocks_scanned == 1 &&
        r.shielded_scan_skipped && r.shielded_txs_unscanned == 1 &&
        keyless->num_sapling_notes == 0 &&
        wallet_get_sapling_balance(keyless) == 0;
    keyless->best_block = NULL;
    wallet_free(keyless);
    free(keyless);
    if (!ok)
        printf("(keyless scan found=%d skipped=%d unscanned=%lld) ",
               found, r.shielded_scan_skipped,
               (long long)r.shielded_txs_unscanned);
    return ok;
}

static bool p11_4_body_index(struct block *accepted, int height,
                             const struct transaction *payment,
                             const char *dir, struct block_index *index)
{
    char blocksdir[320];
    int n = snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", dir);
    if (n <= 0 || (size_t)n >= sizeof(blocksdir) ||
        (mkdir(blocksdir, 0700) != 0 && errno != EEXIST)) {
        printf("(confirmed blocks directory failed) ");
        return false;
    }
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    if (!write_block_to_disk(accepted, &pos, dir,
                             chain_params_get()->pchMessageStart)) {
        printf("(confirmed body write failed) ");
        return false;
    }
    block_index_init(index);
    block_get_hash(accepted, &index->hashBlock);
    index->phashBlock = &index->hashBlock;
    index->nHeight = height;
    index->nFile = pos.nFile;
    index->nDataPos = pos.nPos;
    index->nStatus = BLOCK_HAVE_DATA;
    struct block readback;
    block_init(&readback);
    bool read = read_block_from_disk_index(&readback, index, dir);
    if (read && readback.num_vtx == 2)
        transaction_compute_hash(&readback.vtx[1]);
    bool exact = read && readback.num_vtx == accepted->num_vtx &&
        readback.num_vtx == 2 &&
        uint256_cmp(&readback.vtx[1].hash, &payment->hash) == 0 &&
        readback.vtx[1].num_shielded_output == 1;
    block_free(&readback);
    if (!exact)
        printf("(confirmed body read=%d exact=%d) ", read, exact);
    return exact;
}

static bool p11_4_confirmed_rescan(struct wallet *recipient,
                                  struct block *accepted, int height,
                                  const struct transaction *payment,
                                  const char *dir)
{
    struct block_index index;
    bool exact = p11_4_body_index(accepted, height, payment, dir, &index);
    struct active_chain chain;
    active_chain_init(&chain);
    bool ready = exact && active_chain_install_tip_slot(&chain, &index);
    bool keyless = ready && p11_4_keyless_scan(&chain, height, dir);
    bool negative = keyless && p11_4_scan_refusals(recipient, &chain,
                                                &index, dir);
    bool credit = negative && p11_4_scan_credit(recipient, &chain, &index,
                                                payment, dir);
    /* recipient best_block references index; clear it before index expires. */
    recipient->best_block = NULL;
    active_chain_free(&chain);
    if (!credit)
        printf("(confirmed body exact=%d ready=%d negatives=%d) ",
               exact, ready, negative);
    return credit;
}

static bool p11_4_tip_confirmed(const struct simnet *sim,
                               const struct block *accepted,
                               int before, int height)
{
    struct uint256 body_hash, tip_hash;
    block_get_hash(accepted, &body_hash);
    bool tip_known = simnet_tip_hash(sim, &tip_hash);
    return simnet_tip_height(sim) == before + 1 && height == before + 1 &&
        tip_known && uint256_cmp(&body_hash, &tip_hash) == 0 &&
        accepted->num_vtx == 2 &&
        accepted->vtx[1].num_shielded_output == 1;
}

static bool p11_4_mint_payment(struct simnet *sim,
                              const struct transaction *payment,
                              const struct uint256 *funding,
                              struct block *accepted, int *height)
{
    struct transaction chain_tx;
    transaction_init(&chain_tx);
    bool copied = transaction_copy(&chain_tx, payment);
    struct output_description *chain_outputs = copied
        ? chain_tx.v_shielded_output : NULL;
    int before = simnet_tip_height(sim);
    bool mined = copied && simnet_mint_txs_capture(sim, &chain_tx, 1,
                                                    accepted, height);
    bool independent = mined && accepted->num_vtx == 2 &&
        accepted->vtx[1].v_shielded_output != chain_outputs;
    /* Original input arrays are borrowed, not the block_clone's copies. */
    free(chain_outputs);
    bool confirmed = mined && p11_4_tip_confirmed(sim, accepted, before,
                                                  *height) && independent &&
        !simnet_coin_value(sim, funding, 0, NULL) &&
        simnet_coin_exists(sim, &payment->hash) &&
        simnet_sapling_tree_size(sim) == 1;
    if (!copied)
        transaction_free(&chain_tx);
    if (!confirmed)
        printf("(mint copied=%d mined=%d independent=%d) ",
               copied, mined, independent);
    return confirmed;
}

static bool p11_4_payment_shape(bool found, const struct transaction *payment,
                                struct tx_mempool *pool,
                                const struct uint256 *funding,
                                const struct script *pay,
                                const struct wallet *sender)
{
    return found && payment->num_shielded_output == 1 &&
        payment->num_vout >= 2 && payment->value_balance == -COIN_VALUE &&
        p11_4_conserves(payment, pool, funding, pay, sender);
}

static bool p11_4_require_prover(const char *params_dir)
{
    if (!sapling_init_params(params_dir)) {
        printf("FAIL (sapling_init_params(%s) failed)\n", params_dir);
        return false;
    }
    if (!zclassic_sapling_prover_is_ready()) {
        printf("FAIL (Sapling prover backend=%s status=%s)\n",
               zclassic_sapling_prover_backend(),
               zclassic_sapling_prover_status());
        return false;
    }
    return true;
}

static bool p11_4_open_wallet_fixture(char *tmpdir, size_t tmpdir_size,
                                      char *dbpath, size_t dbpath_size,
                                      struct wallet **wallet_out)
{
    if (!p11_4_make_tmpdir(tmpdir, tmpdir_size)) {
        printf("FAIL (tmpdir)\n");
        return false;
    }
    if (!p11_4_open_trust_fixture(tmpdir)) {
        printf("FAIL (sovereignty trust fixture)\n");
        reducer_frontier_provable_tip_reset();
        progress_store_close();
        if (!p11_4_cleanup_owned(tmpdir))
            printf("FAIL (trust fixture cleanup)\n");
        return false;
    }
    snprintf(dbpath, dbpath_size, "%s/node.db", tmpdir);

    struct wallet *wallet = zcl_calloc(1, sizeof(*wallet), "p11_4_wallet");
    if (!wallet) {
        printf("FAIL (wallet alloc)\n");
        reducer_frontier_provable_tip_reset();
        progress_store_close();
        if (!p11_4_cleanup_owned(tmpdir))
            printf("FAIL (wallet allocation fixture cleanup)\n");
        return false;
    }
    wallet_init(wallet);
    if (!sapling_keystore_generate_seed(&wallet->sapling_keys)) {
        wallet_free(wallet);
        free(wallet);
        printf("FAIL (sapling seed)\n");
        reducer_frontier_provable_tip_reset();
        progress_store_close();
        if (!p11_4_cleanup_owned(tmpdir))
            printf("FAIL (seed fixture cleanup)\n");
        return false;
    }
    *wallet_out = wallet;
    return true;
}

static void p11_4_bind_tip_and_sync(struct wallet *wallet,
                                    struct main_state *ms,
                                    struct connman *cm,
                                    struct p2p_node *peer,
                                    struct p2p_node **peer_slots,
                                    struct block_index *tip,
                                    struct node_db *ndb,
                                    const char *dbpath,
                                    bool *ok,
                                    const char **fail_step)
{
    tip->nHeight = P11_4_TIP_HEIGHT;
    tip->nTime = (uint32_t)platform_time_wall_time_t();
    memset(tip->hashBlock.data, 0x50, sizeof(tip->hashBlock.data));
    active_chain_move_window_tip(&ms->chain_active, tip);
    wallet->best_block = tip;
    wallet->best_block_height = tip->nHeight;
    zcl_mutex_init(&cm->manager.cs_nodes);
    peer->id = 1;
    peer->starting_height = tip->nHeight;
    peer->state = PEER_ACTIVE;
    peer->services = NODE_NETWORK;
    peer_slots[0] = peer;
    cm->manager.nodes = peer_slots;
    cm->manager.num_nodes = 1;
    sync_monitor_set_context(cm, NULL, ms);
    (void)sync_set_state(SYNC_IDLE, "shielded payment fixture reset");
    *ok = sync_set_state(SYNC_FINDING_PEERS, "shielded payment fixture") &&
          sync_set_state(SYNC_HEADERS_DOWNLOAD, "shielded payment fixture") &&
          sync_set_state(SYNC_BLOCKS_DOWNLOAD, "shielded payment fixture") &&
          sync_set_state(SYNC_CONNECTING_BLOCKS, "shielded payment fixture") &&
          sync_set_state(SYNC_AT_TIP, "shielded payment fixture");

    *ok = *ok && node_db_open(ndb, dbpath);
    if (!*ok)
        printf("(node_db_open failed for %s)\n", dbpath);

    if (*ok) {
        *fail_step = "persisted_chain_tip";
        *ok = p11_4_save_tip(ndb, tip);
    }
}

static void p11_4_open_wallet_db(bool *ok, struct wallet_sqlite *wsql,
                                 struct node_db *ndb, bool *wsql_open)
{
    if (*ok) {
        /* z_getnewaddress fail-closes (wallet_shielded_controller.c) unless
         * ctx->wallet_db is a real, open wallet_sqlite — same as production
         * boot.c, which opens wallet_sqlite over the same node.db handle
         * right after node_db_open succeeds. A NULL wallet_db here would
         * trip that guard on the very first RPC call. */
        struct zcl_result wsql_r = wallet_sqlite_open_r(wsql, ndb->db);
        *ok = wsql_r.ok && wallet_sqlite_self_test(wsql).ok &&
            wallet_canary_run(ndb->db, NULL) == WALLET_CANARY_OK;
        if (*ok) {
            *wsql_open = true;
        } else {
            printf("(wallet_sqlite_open_r failed: code=%d message=%s)\n",
                   wsql_r.code, wsql_r.message);
        }
    }
}

static void p11_4_persist_funding_key(bool *ok, const char **fail_step,
                                      struct wallet *wallet,
                                      struct wallet_sqlite *wsql,
                                      struct privkey *funding_key,
                                      struct pubkey *funding_pubkey,
                                      struct key_id *funding_kid)
{
    if (*ok) {
        *fail_step = "wallet_unlock";
        wallet_lock_reset_for_test();
        wallet_lock_note_encrypted_at_rest();
        *ok = wallet_lock_unlock(NULL, NULL, "shielded-payment-gate").ok;
    }

    if (*ok) {
        privkey_make_new(funding_key, true);
        privkey_get_pubkey(funding_key, funding_pubkey);
        *funding_kid = pubkey_get_id(funding_pubkey);
        *ok = keystore_add_key(&wallet->keystore, funding_key) &&
              wallet_sqlite_write_key_r(
                  wsql, funding_pubkey, funding_key).ok;
    }

    if (*ok) {
        *fail_step = "persisted_keypool";
        *ok = wallet_top_up_key_pool(wallet, 2);
        int64_t generation = wallet_key_pool_generation_ceiling(wallet);
        *ok = *ok && wallet_sqlite_flush_r(wsql, wallet).ok;
        if (*ok)
            wallet_key_pool_mark_persisted_through(wallet, generation);
    }
}

static void p11_4_fund_on_simnet(bool *ok, const char **fail_step,
                                 struct tx_destination *funding_dest,
                                 const struct key_id *funding_kid,
                                 struct script *funding_script,
                                 char *funding_addr, size_t funding_addr_size,
                                 struct simnet *chain_sim,
                                 bool *chain_sim_open,
                                 int *chain_funding_height,
                                 struct uint256 *chain_funding_txid,
                                 struct node_db *ndb,
                                 struct coins_view_cache *coins_tip)
{
    if (*ok) {
        funding_dest->type = DEST_KEY_ID;
        funding_dest->id.key = *funding_kid;
        script_for_destination(funding_script, funding_dest);
        const struct chain_params *cp = chain_params_get();
        size_t pk_pfx_len = 0;
        size_t sc_pfx_len = 0;
        const unsigned char *pk_pfx =
            chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
        const unsigned char *sc_pfx =
            chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);
        *ok = encode_destination(funding_dest, pk_pfx, pk_pfx_len,
                                 sc_pfx, sc_pfx_len,
                                 funding_addr, funding_addr_size);
    }

    if (*ok) {
        *fail_step = "simnet_funding";
        *ok = simnet_init(chain_sim);
        if (*ok) {
            *chain_sim_open = true;
            int sapling_height = simnet_tip_height(chain_sim) + 1;
            simnet_activate_sapling_at(chain_sim, sapling_height);
            *ok = simnet_enable_sapling_tree(chain_sim);
            simnet_enable_contextual_check(chain_sim, true);
            *chain_funding_height = sapling_height;
        }
        *ok = *ok && simnet_mint_coinbase_to(
            chain_sim, funding_script, 3 * COIN_VALUE,
            chain_funding_txid);
        *ok = *ok && simnet_mint_to_height(
            chain_sim, *chain_funding_height + COINBASE_MATURITY);
    }

    if (*ok)
        *ok = p11_4_build_funding_utxo(
            ndb, coins_tip, chain_funding_txid, funding_kid,
            funding_script, *chain_funding_height);
}

static void p11_4_register_and_address(bool *ok, const char **fail_step,
                                       struct rpc_table *tbl,
                                       struct wallet *wallet,
                                       struct main_state *ms,
                                       const char *tmpdir,
                                       struct wallet_sqlite *wsql,
                                       struct tx_mempool *mempool,
                                       struct node_db *ndb,
                                       struct coins_view_cache *coins_tip,
                                       char *zaddr, size_t zaddr_size,
                                       struct wallet **recipient)
{
    if (*ok) {
        /* register_wallet_rpc_commands() already registers the shielded
         * sub-controller (wallet_controller.c calls
         * register_wallet_shielded_rpc_commands internally), so a second
         * explicit call here would re-register z_getnewaddress and trip the
         * rpc_table_must_append duplicate-name guard. One call registers the
         * full transparent + shielded surface the gate exercises. */
        register_wallet_rpc_commands(tbl);
        {
            char warmup_status[64];
            if (rpc_is_in_warmup(warmup_status, sizeof(warmup_status)))
                set_rpc_warmup_finished();
        }
        rpc_wallet_set_state(wallet, ms, tmpdir, wsql, mempool, NULL);
        rpc_wallet_set_node_db(ndb);
        rpc_wallet_set_coins_tip(coins_tip);
    }

    if (*ok) {
        *fail_step = "z_getnewaddress";
        *ok = p11_4_rpc_z_getnewaddress(tbl, zaddr, zaddr_size);
    }

    if (*ok) {
        *fail_step = "zaddr_prefix";
        *ok = strncmp(zaddr, "zs1", 3) == 0;
    }

    if (*ok) {
        *fail_step = "uncredited_recipient";
        *recipient = p11_4_recipient(wallet, zaddr);
        *ok = *recipient && (*recipient)->num_sapling_notes == 0 &&
            wallet_get_sapling_balance(*recipient) == 0;
    }

    if (*ok) {
        *fail_step = "custody_identity";
        struct wallet_identity_row identity;
        *ok = wallet_identity_ensure(ndb,
            chain_params_get()->consensus.hashGenesisBlock.data,
            "test", &identity);
    }
}

static void p11_4_backup_and_health(bool *ok, const char **fail_step,
                                    char *backup_dir, size_t backup_dir_size,
                                    const char *tmpdir, struct node_db *ndb,
                                    struct wallet_sqlite *wsql,
                                    struct wallet *wallet)
{
    if (*ok) {
        *fail_step = "encrypted_backup";
        snprintf(backup_dir, backup_dir_size, "%s/backups", tmpdir);
        struct wallet_backup_config backup;
        memset(&backup, 0, sizeof(backup));
        backup.backup_dir = backup_dir;
        backup.encrypt = true;
        backup.encrypt_password = "shielded-payment-backup";
        *ok = wallet_backup_start(&backup, ndb).ok &&
              wallet_backup_now().ok;
    }

    if (*ok) {
        struct wallet_sqlite_health health = wallet_sqlite_get_health(
            wsql, (int)wallet->keystore.num_keys);
        if (!health.open || !health.canary_ok || health.mismatch) {
            printf("(persistence open=%d canary=%d rows=%d keys=%d error=%s) ",
                   health.open, health.canary_ok, health.row_count,
                   health.keystore_count, health.last_error);
        }
    }
}

struct p11_4_send_probe {
    bool lookup_ok;
    bool shape_ok;
    bool admit_ok;
    bool copied;
    bool tamper_ok;
    bool uncredited;
    enum mempool_accept_result accepted;
    enum mempool_accept_result rejected;
};

static void p11_4_probe_admission(struct p11_4_send_probe *probe,
                                  struct tx_mempool *mempool,
                                  struct transaction *sent_tx,
                                  struct coins_view_cache *coins_tip,
                                  struct main_state *ms,
                                  const struct uint256 *chain_funding_txid,
                                  const struct script *funding_script,
                                  const struct wallet *wallet,
                                  const char *txid_hex)
{
    struct uint256 txid;
    memset(&txid, 0, sizeof(txid));
    uint256_set_hex(&txid, txid_hex);
    probe->lookup_ok = tx_mempool_lookup(mempool, &txid, sent_tx);
    probe->shape_ok = p11_4_payment_shape(probe->lookup_ok, sent_tx, mempool,
        chain_funding_txid, funding_script, wallet);

    /* A second, independent admission into an empty pool exercises the
     * complete consensus/mempool boundary: structure, Sapling output
     * proof + binding signature, transparent input/script, and fee. */
    struct tx_mempool proof_pool;
    tx_mempool_init(&proof_pool, 0);
    probe->accepted = accept_to_mempool(
        &proof_pool, coins_tip, ms, chain_params_get(), sent_tx);
    probe->admit_ok = probe->accepted == MEMPOOL_ACCEPT_OK &&
        tx_mempool_exists(&proof_pool, &sent_tx->hash);
    tx_mempool_free(&proof_pool);
}

static void p11_4_probe_tamper(struct p11_4_send_probe *probe,
                               const struct transaction *sent_tx,
                               struct coins_view_cache *coins_tip,
                               struct main_state *ms)
{
    /* Negative control: changing one proof byte must be rejected by the
     * same full admission boundary and must leave its pool empty. */
    struct transaction tampered_tx;
    transaction_init(&tampered_tx);
    probe->copied = transaction_copy(&tampered_tx, sent_tx);
    if (probe->copied && tampered_tx.num_shielded_output == 1) {
        tampered_tx.v_shielded_output[0].zkproof[0] ^= 0x01;
        transaction_compute_hash(&tampered_tx);
    }
    struct tx_mempool reject_pool;
    tx_mempool_init(&reject_pool, 0);
    probe->rejected = probe->copied
        ? accept_to_mempool(&reject_pool, coins_tip, ms,
                            chain_params_get(), &tampered_tx)
        : MEMPOOL_ACCEPT_INTERNAL_ERROR;
    probe->tamper_ok = probe->copied &&
        probe->rejected == MEMPOOL_ACCEPT_INVALID &&
        tx_mempool_size(&reject_pool) == 0;
    tx_mempool_free(&reject_pool);
    transaction_free(&tampered_tx);
}

static bool p11_4_post_send_checks(struct tx_mempool *mempool,
                                   struct transaction *sent_tx,
                                   struct coins_view_cache *coins_tip,
                                   struct main_state *ms,
                                   const struct uint256 *chain_funding_txid,
                                   const struct script *funding_script,
                                   const struct wallet *wallet,
                                   const char *txid_hex,
                                   struct wallet *recipient)
{
    struct p11_4_send_probe probe;
    memset(&probe, 0, sizeof(probe));
    p11_4_probe_admission(&probe, mempool, sent_tx, coins_tip, ms,
                          chain_funding_txid, funding_script, wallet,
                          txid_hex);
    p11_4_probe_tamper(&probe, sent_tx, coins_tip, ms);
    probe.uncredited = recipient && recipient->num_sapling_notes == 0 &&
        wallet_get_sapling_balance(recipient) == 0;
    bool passed = probe.lookup_ok && probe.shape_ok && probe.admit_ok &&
        probe.tamper_ok && probe.uncredited;
    if (!passed)
        printf("(lookup=%d zouts=%zu vouts=%zu value_balance=%lld "
               "accept=%d admitted=%d copied=%d reject=%d tamper=%d "
               "uncredited=%d) ",
               probe.lookup_ok, sent_tx->num_shielded_output,
               sent_tx->num_vout, (long long)sent_tx->value_balance,
               (int)probe.accepted, probe.admit_ok, probe.copied,
               (int)probe.rejected, probe.tamper_ok, probe.uncredited);
    return passed;
}

static void p11_4_exercise_payment(bool *ok, const char **fail_step,
                                   struct rpc_table *tbl,
                                   const char *funding_addr,
                                   const char *zaddr,
                                   struct tx_mempool *mempool,
                                   char *txid_hex, size_t txid_hex_size,
                                   struct transaction *sent_tx,
                                   struct coins_view_cache *coins_tip,
                                   struct main_state *ms,
                                   const struct uint256 *chain_funding_txid,
                                   const struct script *funding_script,
                                   struct wallet *wallet,
                                   struct wallet *recipient,
                                   struct simnet *chain_sim,
                                   struct block *accepted_block,
                                   int *accepted_height,
                                   bool *chain_confirmed,
                                   const char *tmpdir)
{
    if (*ok) {
        *fail_step = "vault_intent_mixed";
        *ok = p11_4_vault_mixed(tbl, funding_addr, zaddr, mempool,
                                txid_hex, txid_hex_size);
    }

    if (*ok) {
        *fail_step = "post_send_checks";
        *ok = p11_4_post_send_checks(mempool, sent_tx, coins_tip, ms,
                                     chain_funding_txid, funding_script,
                                     wallet, txid_hex, recipient);
    }

    if (*ok) {
        *fail_step = "simnet_confirm";
        *chain_confirmed = p11_4_mint_payment(chain_sim, sent_tx,
            chain_funding_txid, accepted_block, accepted_height);
        *ok = *chain_confirmed;
    }

    if (*ok) {
        *fail_step = "confirmed_body_rescan";
        *ok = p11_4_confirmed_rescan(recipient, accepted_block,
                                     *accepted_height, sent_tx, tmpdir);
    }
}

static int p11_4_finish_gate(bool ok, const char *fail_step,
                             int previous_defer_height, bool chain_confirmed,
                             struct wallet *recipient,
                             struct block *accepted_block,
                             struct transaction *sent_tx,
                             struct coins_view_cache *coins_tip,
                             struct tx_mempool *mempool,
                             struct wallet_sqlite *wsql, bool wsql_open,
                             struct node_db *ndb, struct main_state *ms,
                             struct wallet *wallet,
                             struct simnet *chain_sim, bool chain_sim_open,
                             const char *tmpdir)
{
    atomic_store_explicit(&g_deferred_proof_validation_below_height,
                          previous_defer_height, memory_order_relaxed);

    rpc_wallet_set_node_db(NULL);
    rpc_wallet_set_coins_tip(NULL);
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    sync_monitor_set_context(NULL, NULL, NULL);
    (void)sync_set_state(SYNC_IDLE, "shielded payment fixture cleanup");
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    wallet_backup_stop();
    wallet_lock_reset_for_test();

    block_free(accepted_block);
    if (recipient) {
        wallet_free(recipient);
        free(recipient);
    }
    transaction_free(sent_tx);
    coins_view_cache_free(coins_tip);
    tx_mempool_free(mempool);
    if (wsql_open)
        wallet_sqlite_close(wsql);
    node_db_close(ndb);
    main_state_free(ms);
    wallet_free(wallet);
    free(wallet);
    if (chain_sim_open)
        simnet_free(chain_sim);
    ok = p11_4_cleanup_owned(tmpdir) && ok;

    int failures = 0;
    if (ok) {
        printf("OK (durable t->(z,t) plan/commit, proof verified, fully "
               "admitted, tamper rejected, confirmed body rescanned to "
               "1.00000000 ZCL without precredit, "
               "simnet block confirmed=%d)\n", chain_confirmed);
    } else {
        printf("FAIL (%s)\n", fail_step);
        failures++;
    }
    return failures;
}

int test_shielded_payment_gate(void)
{
    printf("\n=== shielded payment (MVP #4) ===\n");
    printf("shielded_payment wallet shield + private send e2e... ");

    if (!getenv("ZCL_STRESS_TESTS")) {
        printf("SKIP (set ZCL_STRESS_TESTS=1 to run deterministic gate)\n");
        return 0;
    }

    char params_dir[512];
    if (!p11_4_params_available(params_dir, sizeof(params_dir))) {
        /* Activating the proof contract expresses intent to observe this
         * leg; it cannot manufacture the external ~770 MiB fixture.  Report
         * that environmental boundary explicitly so the runner records no
         * PASS receipt and no runtime SKIP, while a params-provisioned
         * acceptance host still has to execute the proof below. */
        printf("UNOBSERVED (ZCL_STRESS_TESTS=1 but Sapling params absent at "
               "%s/.zcash-params — provision the ~770MB fixture on this "
               "runner to observe the real prover leg)\n",
               getenv("HOME") ? getenv("HOME") : "$HOME");
        return 0;
    }

    if (!p11_4_require_prover(params_dir))
        return 1;

    char tmpdir[256];
    char dbpath[320];
    struct node_db ndb;
    struct wallet_sqlite wsql;
    bool wsql_open = false;
    struct wallet *wallet = NULL;
    struct wallet *recipient = NULL;
    struct block accepted_block;
    block_init(&accepted_block);
    int accepted_height = -1;
    struct main_state ms;
    struct tx_mempool mempool;
    struct connman cm;
    struct p2p_node peer;
    struct p2p_node *peer_slots[1];
    struct coins_view null_coins_view;
    struct coins_view_cache coins_tip;
    struct block_index tip;
    struct rpc_table tbl;
    struct transaction sent_tx;
    struct privkey funding_key;
    struct pubkey funding_pubkey;
    struct key_id funding_kid;
    struct tx_destination funding_dest;
    struct script funding_script;
    struct simnet chain_sim;
    struct uint256 chain_funding_txid;
    int chain_funding_height = 0;
    bool chain_sim_open = false;
    bool chain_confirmed = false;
    char funding_addr[128];
    char zaddr[128];
    char txid_hex[65];
    char backup_dir[320];
    const char *fail_step = "setup";
    bool ok = true;

    memset(&ndb, 0, sizeof(ndb));
    memset(&wsql, 0, sizeof(wsql));
    memset(&ms, 0, sizeof(ms));
    memset(&mempool, 0, sizeof(mempool));
    memset(&cm, 0, sizeof(cm));
    memset(&peer, 0, sizeof(peer));
    memset(peer_slots, 0, sizeof(peer_slots));
    memset(&null_coins_view, 0, sizeof(null_coins_view));
    memset(&coins_tip, 0, sizeof(coins_tip));
    memset(&tip, 0, sizeof(tip));
    memset(&tbl, 0, sizeof(tbl));
    memset(&sent_tx, 0, sizeof(sent_tx));
    memset(&funding_key, 0, sizeof(funding_key));
    memset(&funding_pubkey, 0, sizeof(funding_pubkey));
    memset(&funding_kid, 0, sizeof(funding_kid));
    memset(&funding_dest, 0, sizeof(funding_dest));
    memset(&funding_script, 0, sizeof(funding_script));
    memset(&chain_sim, 0, sizeof(chain_sim));
    memset(&chain_funding_txid, 0, sizeof(chain_funding_txid));
    memset(funding_addr, 0, sizeof(funding_addr));
    memset(zaddr, 0, sizeof(zaddr));
    memset(txid_hex, 0, sizeof(txid_hex));
    memset(backup_dir, 0, sizeof(backup_dir));

    if (!p11_4_open_wallet_fixture(tmpdir, sizeof(tmpdir), dbpath,
                                   sizeof(dbpath), &wallet))
        return 1;
    main_state_init(&ms);
    tx_mempool_init(&mempool, 0);
    coins_view_cache_init(&coins_tip, &null_coins_view);
    rpc_table_init(&tbl);
    block_index_init(&tip);
    transaction_init(&sent_tx);

    p11_4_bind_tip_and_sync(wallet, &ms, &cm, &peer, peer_slots, &tip, &ndb,
                            dbpath, &ok, &fail_step);
    p11_4_open_wallet_db(&ok, &wsql, &ndb, &wsql_open);
    p11_4_persist_funding_key(&ok, &fail_step, wallet, &wsql, &funding_key,
                              &funding_pubkey, &funding_kid);
    p11_4_fund_on_simnet(&ok, &fail_step, &funding_dest, &funding_kid,
                         &funding_script, funding_addr, sizeof(funding_addr),
                         &chain_sim, &chain_sim_open, &chain_funding_height,
                         &chain_funding_txid, &ndb, &coins_tip);
    p11_4_register_and_address(&ok, &fail_step, &tbl, wallet, &ms, tmpdir,
                               &wsql, &mempool, &ndb, &coins_tip, zaddr,
                               sizeof(zaddr), &recipient);
    p11_4_backup_and_health(&ok, &fail_step, backup_dir, sizeof(backup_dir),
                            tmpdir, &ndb, &wsql, wallet);

    /* Make the gate prove that Groth16 checks really ran even if another test
     * changed the process-wide historical-proof deferral policy. */
    int previous_defer_height = atomic_exchange_explicit(
        &g_deferred_proof_validation_below_height, -1,
        memory_order_relaxed);

    p11_4_exercise_payment(&ok, &fail_step, &tbl, funding_addr, zaddr,
                           &mempool, txid_hex, sizeof(txid_hex), &sent_tx,
                           &coins_tip, &ms, &chain_funding_txid,
                           &funding_script, wallet, recipient, &chain_sim,
                           &accepted_block, &accepted_height,
                           &chain_confirmed, tmpdir);

    return p11_4_finish_gate(ok, fail_step, previous_defer_height,
                             chain_confirmed, recipient, &accepted_block,
                             &sent_tx, &coins_tip, &mempool, &wsql, wsql_open,
                             &ndb, &ms, wallet, &chain_sim, chain_sim_open,
                             tmpdir);
}
