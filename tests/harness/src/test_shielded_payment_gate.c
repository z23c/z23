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
 *      decrypted back into the wallet's note set
 *
 * This is an opt-in stress gate because it depends on real Sapling proving
 * params and builds a real proof. Run with:
 *   ZCL_STRESS_TESTS=1 build/bin/test_zcl
 *   ZCL_STRESS_TESTS=1 ZCL_TEST_ONLY=shielded_payment build/bin/test_zcl
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
    char test_root[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd)))
        return false;
    int root_n = snprintf(test_root, sizeof(test_root), "%s/test-tmp", cwd);
    int dir_n = snprintf(tmpdir, tmpdir_size, "%s/p11_4_%d", test_root,
                         (int)getpid());
    if (root_n <= 0 || (size_t)root_n >= sizeof(test_root) ||
        dir_n <= 0 || (size_t)dir_n >= tmpdir_size)
        return false;
    mkdir(test_root, 0755);
    if (mkdir(tmpdir, 0700) != 0 && errno != EEXIST)
        return false;
    return true;
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

/* The production wallet commit path is sovereignty-gated. Populate the same
 * minimal self-derived progress projection a running node has; otherwise this
 * wallet test exits before reaching Sapling transaction construction. */
static bool p11_4_open_trust_fixture(const char *dir)
{
    if (!progress_store_open(dir)) {
        printf("(trust fixture: progress_store_open) ");
        return false;
    }
    sqlite3 *db = progress_store_db();
    if (!db) {
        printf("(trust fixture: progress_store_db) ");
        return false;
    }
    if (!coins_kv_ensure_schema(db)) {
        printf("(trust fixture: coins schema: %s) ", sqlite3_errmsg(db));
        return false;
    }
    if (!reducer_frontier_ensure_schema(db)) {
        printf("(trust fixture: reducer schema: %s) ", sqlite3_errmsg(db));
        return false;
    }
    reducer_frontier_provable_tip_set(P11_4_TIP_HEIGHT);
    struct uint256 txid;
    uint256_set_null(&txid);
    txid.data[0] = 0x51;
    txid.data[31] = 0x77;
    const unsigned char script[4] = {0xE0, 0xE0, 0xE0, 0xE0};
    if (!coins_kv_add(db, txid.data, 0, 1234, P11_4_TIP_HEIGHT, true,
                      script, sizeof(script))) {
        printf("(trust fixture: authority coin: %s) ", sqlite3_errmsg(db));
        return false;
    }
    uint8_t migrated = 1;
    uint8_t tip_hash[32];
    memset(tip_hash, 0x50, sizeof(tip_hash));
    char *err = NULL;
    bool began = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) ==
        SQLITE_OK;
    bool applied = began && coins_kv_set_applied_height_in_tx(
        db, P11_4_TIP_HEIGHT + 1);
    bool stamped = applied && progress_meta_set_in_tx(
        db, COINS_KV_MIGRATION_COMPLETE_KEY, &migrated, sizeof(migrated));
    bool ok = began && applied && stamped;
    sqlite3_stmt *st = NULL;
    bool header_prepared = false;
    bool header_written = false;
    bool committed = false;
    bool self_folded = false;
    if (ok) {
        ok = sqlite3_prepare_v2(db,
            "INSERT OR REPLACE INTO validate_headers_log"
            "(height,hash,ok,validated_at) VALUES(?1,?2,1,0)",
            -1, &st, NULL) == SQLITE_OK;
        header_prepared = ok;
    }
    if (ok) {
        sqlite3_bind_int(st, 1, P11_4_TIP_HEIGHT);
        sqlite3_bind_blob(st, 2, tip_hash, sizeof(tip_hash), SQLITE_STATIC);
        ok = sqlite3_step(st) == SQLITE_DONE;
        header_written = ok;
    }
    if (st)
        sqlite3_finalize(st);
    if (ok) {
        ok = sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
        committed = ok;
    } else if (began) {
        (void)sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
    }
    if (ok) {
        ok = coins_kv_mark_self_folded(db);
        self_folded = ok;
    }
    if (err)
        sqlite3_free(err);
    if (!ok)
        printf("(trust fixture: begin=%d applied=%d stamped=%d "
               "header_prepared=%d header_written=%d committed=%d "
               "self_folded=%d sqlite=%s) ", began, applied, stamped,
               header_prepared, header_written, committed, self_folded,
               sqlite3_errmsg(db));
    return ok;
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

    json_push_kv_str(&input, "wallet_scope", "dev");
    json_push_kv_str(&input, "route", "mixed");
    json_push_kv_str(&input, "from", from_addr);
    json_push_kv_str(&input, "idempotency_key", "shielded-payment-mixed-1");
    json_push_kv_str(&effect, "asset", "ZCL");
    json_push_kv_str(&effect, "to", zaddr);
    json_push_kv_str(&effect, "amount", "0.02000000");
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

    bool ok = rpc_table_execute(tbl, "vault_intent_plan", &params, &result);
    const char *plan_id = ok && result.type == JSON_OBJ
        ? json_get_str(json_get(&result, "plan_id")) : NULL;
    const char *digest = ok && result.type == JSON_OBJ
        ? json_get_str(json_get(&result, "digest")) : NULL;
    const char *route = ok && result.type == JSON_OBJ
        ? json_get_str(json_get(&result, "route")) : NULL;
    const char *from = ok && result.type == JSON_OBJ
        ? json_get_str(json_get(&result, "from")) : NULL;
    const struct json_value *plan_effects = ok && result.type == JSON_OBJ
        ? json_get(&result, "effects") : NULL;
    char plan_id_copy[65] = {0};
    char digest_copy[65] = {0};
    ok = ok && json_get_bool(json_get(&result, "ok")) &&
        plan_id && strlen(plan_id) == 64 && digest && strlen(digest) == 64 &&
        route && strcmp(route, "mixed") == 0 && from &&
        strcmp(from, from_addr) == 0 &&
        json_get_int(json_get(&result, "confirmation_policy")) == 6 &&
        plan_effects && plan_effects->type == JSON_ARR &&
        json_size(plan_effects) == 2 &&
        json_get(&result, "idempotent_plan") != NULL &&
        !json_get_bool(json_get(&result, "idempotent_plan")) &&
        tx_mempool_size(mempool) == 0;
    if (!ok) {
        const char *code = json_get_str(json_get(&result, "code"));
        const char *message = json_get_str(json_get(&result, "message"));
        printf("(plan code=%s message=%s) ", code ? code : "RPC_FAILURE",
               message ? message : "no message");
    }
    if (ok) {
        snprintf(plan_id_copy, sizeof(plan_id_copy), "%s", plan_id);
        snprintf(digest_copy, sizeof(digest_copy), "%s", digest);
    }

    /* An agent reviewing an idempotent retry must receive the same complete
     * owner-visible plan, not merely a plan id and reservation row. */
    json_free(&result); json_init(&result);
    ok = ok && rpc_table_execute(tbl, "vault_intent_plan", &params, &result);
    plan_id = ok && result.type == JSON_OBJ
        ? json_get_str(json_get(&result, "plan_id")) : NULL;
    digest = ok && result.type == JSON_OBJ
        ? json_get_str(json_get(&result, "digest")) : NULL;
    route = ok && result.type == JSON_OBJ
        ? json_get_str(json_get(&result, "route")) : NULL;
    from = ok && result.type == JSON_OBJ
        ? json_get_str(json_get(&result, "from")) : NULL;
    plan_effects = ok && result.type == JSON_OBJ
        ? json_get(&result, "effects") : NULL;
    ok = ok && json_get_bool(json_get(&result, "ok")) &&
        json_get_bool(json_get(&result, "idempotent_plan")) &&
        plan_id && strcmp(plan_id, plan_id_copy) == 0 && digest &&
        strcmp(digest, digest_copy) == 0 &&
        route && strcmp(route, "mixed") == 0 && from &&
        strcmp(from, from_addr) == 0 &&
        json_get_int(json_get(&result, "confirmation_policy")) == 6 &&
        plan_effects && plan_effects->type == JSON_ARR &&
        json_size(plan_effects) == 2 && tx_mempool_size(mempool) == 0;
    if (!ok) {
        const char *code = json_get_str(json_get(&result, "code"));
        const char *message = json_get_str(json_get(&result, "message"));
        printf("(idempotent plan code=%s message=%s) ",
               code ? code : "RPC_FAILURE",
               message ? message : "incomplete retry review");
    }

    json_free(&params); json_init(&params); json_set_array(&params);
    json_free(&input); json_init(&input); json_set_object(&input);
    json_push_kv_str(&input, "wallet_scope", "dev");
    json_push_kv_str(&input, "plan_id", plan_id_copy);
    json_push_kv_bool(&input, "confirm", true);
    json_push_back(&params, &input);
    json_free(&result); json_init(&result);
    ok = ok && rpc_table_execute(tbl, "vault_intent_commit", &params, &result);
    const char *txid = ok && result.type == JSON_OBJ
        ? json_get_str(json_get(&result, "txid")) : NULL;
    ok = ok && json_get_bool(json_get(&result, "ok")) && txid &&
        strlen(txid) == 64;
    if (!ok) {
        const char *code = json_get_str(json_get(&result, "code"));
        const char *message = json_get_str(json_get(&result, "message"));
        printf("(commit code=%s message=%s) ", code ? code : "RPC_FAILURE",
               message ? message : "no message");
    }
    if (ok)
        snprintf(txid_hex, txid_hex_size, "%s", txid);

    json_free(&params);
    json_free(&input);
    json_free(&effects);
    json_free(&effect);
    json_free(&result);
    return ok;
}

int test_shielded_payment_gate(void)
{
    int failures = 0;

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

    if (!sapling_init_params(params_dir)) {
        printf("FAIL (sapling_init_params(%s) failed)\n", params_dir);
        return 1;
    }
    if (!zclassic_sapling_prover_is_ready()) {
        printf("FAIL (Sapling prover backend=%s status=%s)\n",
               zclassic_sapling_prover_backend(),
               zclassic_sapling_prover_status());
        return 1;
    }

    char tmpdir[256];
    char dbpath[320];
    struct node_db ndb;
    struct wallet_sqlite wsql;
    bool wsql_open = false;
    struct wallet *wallet = NULL;
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

    if (!p11_4_make_tmpdir(tmpdir, sizeof(tmpdir))) {
        printf("FAIL (tmpdir)\n");
        return 1;
    }
    if (!p11_4_open_trust_fixture(tmpdir)) {
        printf("FAIL (sovereignty trust fixture)\n");
        test_cleanup_tmpdir(tmpdir);
        return 1;
    }
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", tmpdir);

    wallet = zcl_calloc(1, sizeof(*wallet), "p11_4_wallet");
    if (!wallet) {
        printf("FAIL (wallet alloc)\n");
        return 1;
    }
    wallet_init(wallet);
    if (!sapling_keystore_generate_seed(&wallet->sapling_keys)) {
        wallet_free(wallet);
        free(wallet);
        printf("FAIL (sapling seed)\n");
        return 1;
    }
    main_state_init(&ms);
    tx_mempool_init(&mempool, 0);
    coins_view_cache_init(&coins_tip, &null_coins_view);
    rpc_table_init(&tbl);
    block_index_init(&tip);
    transaction_init(&sent_tx);

    tip.nHeight = P11_4_TIP_HEIGHT;
    tip.nTime = (uint32_t)platform_time_wall_time_t();
    memset(tip.hashBlock.data, 0x50, sizeof(tip.hashBlock.data));
    active_chain_move_window_tip(&ms.chain_active, &tip);
    wallet->best_block = &tip;
    wallet->best_block_height = tip.nHeight;
    zcl_mutex_init(&cm.manager.cs_nodes);
    peer.id = 1;
    peer.starting_height = tip.nHeight;
    peer.state = PEER_ACTIVE;
    peer.services = NODE_NETWORK;
    peer_slots[0] = &peer;
    cm.manager.nodes = peer_slots;
    cm.manager.num_nodes = 1;
    sync_monitor_set_context(&cm, NULL, &ms);
    (void)sync_set_state(SYNC_IDLE, "shielded payment fixture reset");
    ok = sync_set_state(SYNC_FINDING_PEERS, "shielded payment fixture") &&
         sync_set_state(SYNC_HEADERS_DOWNLOAD, "shielded payment fixture") &&
         sync_set_state(SYNC_BLOCKS_DOWNLOAD, "shielded payment fixture") &&
         sync_set_state(SYNC_CONNECTING_BLOCKS, "shielded payment fixture") &&
         sync_set_state(SYNC_AT_TIP, "shielded payment fixture");

    ok = ok && node_db_open(&ndb, dbpath);
    if (!ok)
        printf("(node_db_open failed for %s)\n", dbpath);

    if (ok) {
        fail_step = "persisted_chain_tip";
        ok = p11_4_save_tip(&ndb, &tip);
    }

    if (ok) {
        /* z_getnewaddress fail-closes (wallet_shielded_controller.c) unless
         * ctx->wallet_db is a real, open wallet_sqlite — same as production
         * boot.c, which opens wallet_sqlite over the same node.db handle
         * right after node_db_open succeeds. A NULL wallet_db here would
         * trip that guard on the very first RPC call. */
        struct zcl_result wsql_r = wallet_sqlite_open_r(&wsql, ndb.db);
        ok = wsql_r.ok && wallet_sqlite_self_test(&wsql).ok &&
            wallet_canary_run(ndb.db, NULL) == WALLET_CANARY_OK;
        if (ok) {
            wsql_open = true;
        } else {
            printf("(wallet_sqlite_open_r failed: code=%d message=%s)\n",
                   wsql_r.code, wsql_r.message);
        }
    }

    if (ok) {
        fail_step = "wallet_unlock";
        wallet_lock_reset_for_test();
        wallet_lock_note_encrypted_at_rest();
        ok = wallet_lock_unlock(NULL, NULL, "shielded-payment-gate").ok;
    }

    if (ok) {
        privkey_make_new(&funding_key, true);
        privkey_get_pubkey(&funding_key, &funding_pubkey);
        funding_kid = pubkey_get_id(&funding_pubkey);
        ok = keystore_add_key(&wallet->keystore, &funding_key) &&
             wallet_sqlite_write_key_r(
                 &wsql, &funding_pubkey, &funding_key).ok;
    }

    if (ok) {
        fail_step = "persisted_keypool";
        ok = wallet_top_up_key_pool(wallet, 2);
        int64_t generation = wallet_key_pool_generation_ceiling(wallet);
        ok = ok && wallet_sqlite_flush_r(&wsql, wallet).ok;
        if (ok)
            wallet_key_pool_mark_persisted_through(wallet, generation);
    }

    if (ok) {
        funding_dest.type = DEST_KEY_ID;
        funding_dest.id.key = funding_kid;
        script_for_destination(&funding_script, &funding_dest);
        const struct chain_params *cp = chain_params_get();
        size_t pk_pfx_len = 0;
        size_t sc_pfx_len = 0;
        const unsigned char *pk_pfx =
            chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_pfx_len);
        const unsigned char *sc_pfx =
            chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_pfx_len);
        ok = encode_destination(&funding_dest, pk_pfx, pk_pfx_len,
                                sc_pfx, sc_pfx_len,
                                funding_addr, sizeof(funding_addr));
    }

    if (ok) {
        fail_step = "simnet_funding";
        ok = simnet_init(&chain_sim);
        if (ok) {
            chain_sim_open = true;
            int sapling_height = simnet_tip_height(&chain_sim) + 1;
            simnet_activate_sapling_at(&chain_sim, sapling_height);
            ok = simnet_enable_sapling_tree(&chain_sim);
            simnet_enable_contextual_check(&chain_sim, true);
            chain_funding_height = sapling_height;
        }
        ok = ok && simnet_mint_coinbase_to(
            &chain_sim, &funding_script, 3 * COIN_VALUE,
            &chain_funding_txid);
        ok = ok && simnet_mint_to_height(
            &chain_sim, chain_funding_height + COINBASE_MATURITY);
    }

    if (ok)
        ok = p11_4_build_funding_utxo(
            &ndb, &coins_tip, &chain_funding_txid, &funding_kid,
            &funding_script, chain_funding_height);

    if (ok) {
        /* register_wallet_rpc_commands() already registers the shielded
         * sub-controller (wallet_controller.c calls
         * register_wallet_shielded_rpc_commands internally), so a second
         * explicit call here would re-register z_getnewaddress and trip the
         * rpc_table_must_append duplicate-name guard. One call registers the
         * full transparent + shielded surface the gate exercises. */
        register_wallet_rpc_commands(&tbl);
        {
            char warmup_status[64];
            if (rpc_is_in_warmup(warmup_status, sizeof(warmup_status)))
                set_rpc_warmup_finished();
        }
        rpc_wallet_set_state(wallet, &ms, tmpdir, &wsql, &mempool, NULL);
        rpc_wallet_set_node_db(&ndb);
        rpc_wallet_set_coins_tip(&coins_tip);
    }

    if (ok) {
        fail_step = "z_getnewaddress";
        ok = p11_4_rpc_z_getnewaddress(&tbl, zaddr, sizeof(zaddr));
    }

    if (ok) {
        fail_step = "zaddr_prefix";
        ok = strncmp(zaddr, "zs1", 3) == 0;
    }

    if (ok) {
        fail_step = "custody_identity";
        struct wallet_identity_row identity;
        ok = wallet_identity_ensure(&ndb,
            chain_params_get()->consensus.hashGenesisBlock.data,
            "dev", &identity);
    }

    if (ok) {
        fail_step = "encrypted_backup";
        snprintf(backup_dir, sizeof(backup_dir), "%s/backups", tmpdir);
        struct wallet_backup_config backup;
        memset(&backup, 0, sizeof(backup));
        backup.backup_dir = backup_dir;
        backup.encrypt = true;
        backup.encrypt_password = "shielded-payment-backup";
        ok = wallet_backup_start(&backup, &ndb).ok &&
             wallet_backup_now().ok;
    }

    if (ok) {
        struct wallet_sqlite_health health = wallet_sqlite_get_health(
            &wsql, (int)wallet->keystore.num_keys);
        if (!health.open || !health.canary_ok || health.mismatch) {
            printf("(persistence open=%d canary=%d rows=%d keys=%d error=%s) ",
                   health.open, health.canary_ok, health.row_count,
                   health.keystore_count, health.last_error);
        }
    }

    /* Make the gate prove that Groth16 checks really ran even if another test
     * changed the process-wide historical-proof deferral policy. */
    int previous_defer_height = atomic_exchange_explicit(
        &g_deferred_proof_validation_below_height, -1,
        memory_order_relaxed);

    if (ok) {
        fail_step = "vault_intent_mixed";
        ok = p11_4_vault_mixed(&tbl, funding_addr, zaddr, &mempool,
                               txid_hex, sizeof(txid_hex));
    }

    if (ok) {
        fail_step = "post_send_checks";
        struct uint256 txid;
        memset(&txid, 0, sizeof(txid));
        uint256_set_hex(&txid, txid_hex);
        bool lookup_ok = tx_mempool_lookup(&mempool, &txid, &sent_tx);
        bool shape_ok = lookup_ok && sent_tx.num_shielded_output == 1 &&
            sent_tx.num_vout >= 2 && sent_tx.value_balance == -2000000LL;

        /* A second, independent admission into an empty pool exercises the
         * complete consensus/mempool boundary: structure, Sapling output
         * proof + binding signature, transparent input/script, and fee. */
        struct tx_mempool proof_pool;
        tx_mempool_init(&proof_pool, 0);
        enum mempool_accept_result accepted = accept_to_mempool(
            &proof_pool, &coins_tip, &ms, chain_params_get(), &sent_tx);
        bool admit_ok = accepted == MEMPOOL_ACCEPT_OK &&
            tx_mempool_exists(&proof_pool, &sent_tx.hash);
        tx_mempool_free(&proof_pool);

        /* Negative control: changing one proof byte must be rejected by the
         * same full admission boundary and must leave its pool empty. */
        struct transaction tampered_tx;
        transaction_init(&tampered_tx);
        bool copied = transaction_copy(&tampered_tx, &sent_tx);
        if (copied && tampered_tx.num_shielded_output == 1) {
            tampered_tx.v_shielded_output[0].zkproof[0] ^= 0x01;
            transaction_compute_hash(&tampered_tx);
        }
        struct tx_mempool reject_pool;
        tx_mempool_init(&reject_pool, 0);
        enum mempool_accept_result rejected = copied
            ? accept_to_mempool(&reject_pool, &coins_tip, &ms,
                                chain_params_get(), &tampered_tx)
            : MEMPOOL_ACCEPT_INTERNAL_ERROR;
        bool tamper_ok = copied && rejected == MEMPOOL_ACCEPT_INVALID &&
            tx_mempool_size(&reject_pool) == 0;
        tx_mempool_free(&reject_pool);
        transaction_free(&tampered_tx);

        int decrypted = wallet_try_sapling_decrypt(wallet, &sent_tx, &txid);
        int64_t shielded_balance = wallet_get_sapling_balance(wallet);
        bool decrypt_ok = decrypted == 1 && wallet->num_sapling_notes == 1 &&
            shielded_balance == 2000000LL;
        ok = lookup_ok && shape_ok && admit_ok && tamper_ok && decrypt_ok;
        if (!ok)
            printf("(lookup=%d zouts=%zu vouts=%zu value_balance=%lld "
                   "accept=%d admitted=%d copied=%d reject=%d tamper=%d "
                   "decrypted=%d notes=%zu shielded_balance=%lld) ",
                   lookup_ok, sent_tx.num_shielded_output,
                   sent_tx.num_vout, (long long)sent_tx.value_balance,
                   (int)accepted, admit_ok, copied, (int)rejected, tamper_ok,
                   decrypted, wallet->num_sapling_notes,
                   (long long)shielded_balance);
    }

    if (ok) {
        fail_step = "simnet_confirm";
        struct transaction chain_tx;
        transaction_init(&chain_tx);
        bool copied = transaction_copy(&chain_tx, &sent_tx);
        struct output_description *chain_outputs = copied
            ? chain_tx.v_shielded_output : NULL;
        int before_height = simnet_tip_height(&chain_sim);
        bool mined = copied && simnet_mint_txs(&chain_sim, &chain_tx, 1);
        free(chain_outputs);
        chain_confirmed = mined &&
            simnet_tip_height(&chain_sim) == before_height + 1 &&
            !simnet_coin_value(&chain_sim, &chain_funding_txid, 0, NULL) &&
            simnet_coin_exists(&chain_sim, &sent_tx.hash) &&
            simnet_sapling_tree_size(&chain_sim) == 1;
        ok = chain_confirmed;
        if (!copied)
            transaction_free(&chain_tx);
    }

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

    transaction_free(&sent_tx);
    coins_view_cache_free(&coins_tip);
    tx_mempool_free(&mempool);
    if (wsql_open)
        wallet_sqlite_close(&wsql);
    node_db_close(&ndb);
    main_state_free(&ms);
    wallet_free(wallet);
    free(wallet);
    if (chain_sim_open)
        simnet_free(&chain_sim);
    test_cleanup_tmpdir(tmpdir);

    if (ok) {
        printf("OK (durable t->(z,t) plan/commit, proof verified, fully "
               "admitted, tamper rejected, decrypted to 0.02000000 ZCL, "
               "simnet block confirmed=%d)\n", chain_confirmed);
    } else {
        printf("FAIL (%s)\n", fail_step);
        failures++;
    }

    return failures;
}
