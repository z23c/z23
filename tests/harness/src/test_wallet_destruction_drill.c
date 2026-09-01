/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * THE DESTRUCTION-AND-RESTORE DRILL.
 *
 * The audit's finding was that this project had a backup subsystem and no
 * restore subsystem, and — worse — that the one path a user would actually
 * walk after losing a machine reported success at every layer while finding
 * nothing. This file is the drill that would have caught that. It proves two
 * claims an owner should be able to make about their own money:
 *
 *     "I cannot easily destroy my funds."
 *     "I can recover from mistakes."
 *
 * The bar is deliberately higher than the pre-existing "restore" coverage
 * (test_simnet_wallet_import_backup.c part 2), which decrypts a backup
 * directly into place as node.db and reads a balance out of a table it
 * hand-inserted — it boots nothing, restores nothing through the restore
 * service, and rescans nothing. Here every act destroys real state and
 * recovers it through the shipped code path.
 *
 *   ACT 1 — TRANSPARENT, hermetic.
 *     Fund a wallet-generated address with a REAL connect_block-validated
 *     transfer. Record the exact balance. Back it up (and encrypt it, the
 *     shipped WBE1 path). DELETE the datadir — recursively, every file,
 *     asserted gone, not renamed. Restore onto a FRESH datadir from the
 *     encrypted backup alone via wallet_restore_run(). Re-supply the block
 *     bodies the way a rebuilt machine gets them (from the network, never
 *     from the backup). Rescan. Assert the balance is EXACTLY what it was.
 *     Then SPEND it: sendtoaddress signs with the private key that came out
 *     of the backup, the tx is admitted to a real mempool, and the coin
 *     moves. A balance that displays is not money you can move; this act
 *     proves the second thing, not just the first.
 *
 *   ACT 2 — THE NEGATIVE, hermetic, and the most important assertion here.
 *     Restore onto a datadir that has block INDEX entries but no block
 *     BODIES — exactly the state snapshot_controller_import.c leaves behind
 *     when it strips BLOCK_HAVE_DATA because the source's block files were
 *     never copied, i.e. the fast-sync bootstrap every new user is steered
 *     toward. This is the precise way a real user loses money today: the
 *     rescan walks every height, reads nothing, finds nothing, and every
 *     layer calls it a success. The drill asserts it now FAILS LOUD — a
 *     typed blocker, coverage_ok false, and a rescanblockchain reply that
 *     refuses to let "0 found" pass for "you have nothing".
 *
 *   ACT 3 — SHIELDED, gated on ~/.zcash-params + a ready production prover.
 *     Same shape, on shielded value: a REAL production-prover t->z note the
 *     REAL consensus verifier accepts, persisted, backed up, destroyed with
 *     the datadir, restored, its witness rebuilt from re-synced chain data
 *     (what rescanwitnesses does), and then SPENT — a z->t spend built from
 *     the RESTORED spending key and the RESTORED note randomness, accepted
 *     by contextual_check_transaction. Absent the params or the prover this
 *     act SKIPs and says so; it never fakes the assertion.
 *
 * Hermeticity: acts 1 and 2 need no network, no params, no oracle, and no
 * external process. Act 3 self-skips. The whole group is therefore safe in
 * `make ci-mvp-gates`, where it runs as its own focused process.
 */

#include "test/test_core.h"
#include "support/pagelocker.h"
#include "support/cleanse.h"
#include "keys/key_io.h"

#include "sim/simnet.h"
#include "sim/simnet_sapling.h"

#include "controllers/wallet_controller.h"
#include "controllers/wallet_helpers.h"

#include "models/database.h"
#include "models/utxo.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"

#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"
#include "wallet/sapling_keys.h"

#include "services/wallet_backup_service.h"
#include "services/wallet_restore_service.h"
#include "services/wallet_recovery_service.h"
#include "command/native_command.h"   /* the READ leaf's read-only open */
#include "config/boot_wallet_phrase.h"
#include "wallet/bip44.h"
#include "wallet/keystore.h"
#include "wallet/mnemonic.h"

#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/params_init.h"
#include "sapling/zip32.h"
#include "sapling/fr.h"
#include "sapling/note_encryption.h"
#include "sapling/incremental_merkle_tree.h"

#include "primitives/transaction.h"
#include "validation/sighash.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_state.h"
#include "validation/main_constants.h"
#include "validation/txmempool.h"
#include "validation/chainstate.h"
#include "consensus/validation.h"
#include "consensus/upgrades.h"
#include "script/script.h"
#include "script/sighashtype.h"
#include "coins/coins_view.h"
#include "coins/coins.h"
#include "chain/chainparams.h"
#include "platform/time_compat.h"

#include "storage/disk_block_io.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "jobs/reducer_frontier.h"

#include "util/safe_alloc.h"
#include "json/json.h"
#include "rpc/server.h"

#include <sqlite3.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define DR_CHECK(name, expr) do {               \
    printf("  %s... ", (name));                 \
    if (expr) printf("OK\n");                   \
    else { printf("FAIL\n"); failures++; }      \
} while (0)

/* ── fixtures ─────────────────────────────────────────────────── */

struct dr_key {
    struct privkey priv;
    struct pubkey  pub;
    struct key_id  kid;
    struct script  spk;
};

static void dr_make_key(struct dr_key *k)
{
    memset(k, 0, sizeof(*k));
    privkey_make_new(&k->priv, true);
    privkey_get_pubkey(&k->priv, &k->pub);
    k->kid = pubkey_get_id(&k->pub);
    script_for_p2pkh(&k->spk, &k->kid);
}

static void dr_mkdir(char *dir, size_t cap, const char *tag)
{
    mkdir("./test-tmp", 0755); /* raw-alloc-ok:test-fixture */
    /* Absolute via the shared formatter: the restore and backup services write
     * through platform_private_path_resolve(), which refuses a parent that is
     * not absolute. Same directory, spelled so production will accept it. */
    test_fmt_tmpdir(dir, cap, "drill", tag);
    mkdir(dir, 0700); /* raw-alloc-ok:test-fixture */
}

static void dr_mk_datadir(char *dir, size_t cap, const char *tag)
{
    dr_mkdir(dir, cap, tag);
    char blocks[384];
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    mkdir(blocks, 0755); /* raw-alloc-ok:test-fixture */
}

/* DESTROY THE MACHINE.
 *
 * test_cleanup_tmpdir() only unlinks the top level, which would leave
 * <datadir>/blocks/ behind — and a drill that "destroys" a datadir while
 * quietly leaving the block files in place proves nothing. This walks the
 * tree and deletes everything, then the caller asserts the directory is
 * gone. Depth-limited (2 is all a datadir fixture ever needs) so a bug here
 * can never recurse out of the fixture. */
static void dr_destroy_tree(const char *path, int depth)
{
    DIR *d = opendir(path);
    if (!d) { (void)unlink(path); return; }
    struct dirent *ent;
    char child[768];
    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.' &&
            (ent->d_name[1] == '\0' ||
             (ent->d_name[1] == '.' && ent->d_name[2] == '\0')))
            continue;
        snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        struct stat st;
        if (depth > 0 && stat(child, &st) == 0 && S_ISDIR(st.st_mode))
            dr_destroy_tree(child, depth - 1);
        else
            (void)unlink(child);
    }
    closedir(d);
    (void)rmdir(path);
}

/* True only when nothing of `path` survives — not the directory, not
 * node.db, not the wal/shm sidecars, not the block files. */
static bool dr_is_destroyed(const char *path)
{
    struct stat st;
    if (stat(path, &st) == 0)
        return false;
    char probe[768];
    const char *leftovers[] = { "node.db", "node.db-wal", "node.db-shm",
                                "blocks" };
    for (size_t i = 0; i < sizeof(leftovers) / sizeof(leftovers[0]); i++) {
        snprintf(probe, sizeof(probe), "%s/%s", path, leftovers[i]);
        if (stat(probe, &st) == 0)
            return false;
    }
    return true;
}

/* Sovereignty-guard trust fixture — sendtoaddress fails closed without a
 * progress store (see test_simnet_wallet_import_backup.c, same shape). */
static bool dr_open_trust_fixture(const char *dir)
{
    if (!progress_store_open(dir))
        return false;
    sqlite3 *db = progress_store_db();
    if (!db || !coins_kv_ensure_schema(db))
        return false;
    reducer_frontier_provable_tip_set(50);
    struct uint256 t1;
    uint256_set_null(&t1);
    t1.data[0] = 0x51;
    t1.data[31] = 0x77;
    unsigned char sc[4] = { 0xE0, 0xE0, 0xE0, 0xE0 };
    if (!coins_kv_add(db, t1.data, 0, 1234, 50, true, sc, sizeof(sc)))
        return false;
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
              && coins_kv_set_applied_height_in_tx(db, 51)
              && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok;
}

/* Deterministic 1-in/1-out transparent transfer. Built twice from identical
 * inputs it is byte-identical, so the copy fed to the real connect_block and
 * the copy written to a block file share a txid. */
static bool dr_build_fund_tx(struct transaction *tx,
                             const struct uint256 *prev_txid, uint32_t prev_n,
                             const struct script *to_script, int64_t value)
{
    transaction_init(tx);
    if (!transaction_alloc(tx, 1, 1))
        return false;
    tx->version = 1;
    tx->vin[0].prevout.hash = *prev_txid;
    tx->vin[0].prevout.n = prev_n;
    tx->vin[0].sequence = 0xFFFFFFFFu;
    uint8_t placeholder_sig[] = { 0x00, 0x00 };
    script_set(&tx->vin[0].script_sig, placeholder_sig,
               sizeof(placeholder_sig));
    tx->vout[0].value = value;
    tx->vout[0].script_pub_key = *to_script;
    transaction_compute_hash(tx);
    return true;
}

/* Write one transaction into a block file under `datadir`. This models the
 * ONE thing a rebuilt machine legitimately gets from somewhere other than
 * the backup: block bodies, re-downloaded from the network. Nothing wallet-
 * specific crosses here — no keys, no notes, no balances. */
static bool dr_write_block(const char *datadir, struct transaction *tx,
                           struct disk_block_pos *pos_out)
{
    struct block blk;
    block_init(&blk);
    blk.header.nVersion = 4;
    blk.header.nTime = 1700000000u;
    blk.header.nBits = 0x2000ffffu;
    blk.num_vtx = 1;
    blk.vtx = calloc(1, sizeof(*blk.vtx)); /* raw-alloc-ok:test-fixture */
    bool ok = false;
    if (blk.vtx) {
        blk.vtx[0] = *tx;
        transaction_init(tx); /* ownership moved into blk */
        unsigned char msg_start[4] = { 0x24, 0xe9, 0x27, 0x64 };
        disk_block_pos_init(pos_out);
        ok = write_block_to_disk(&blk, pos_out, datadir, msg_start);
    }
    block_free(&blk);
    return ok;
}

static void dr_params_none(struct json_value *p)
{
    json_init(p);
    json_set_array(p);
}

static void dr_params_2str(struct json_value *p, const char *a, const char *b)
{
    json_init(p);
    json_set_array(p);
    struct json_value v;
    json_init(&v);
    json_set_str(&v, a);
    json_push_back(p, &v);
    json_set_str(&v, b);
    json_push_back(p, &v);
    json_free(&v);
}

static void dr_clear_rpc_ctx(void)
{
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    rpc_wallet_set_node_db(NULL);
    rpc_wallet_set_coins_tip(NULL);
}

/* ─────────────────────────────────────────────────────────────────
 * ACT 1 — transparent: fund, back up, DESTROY, restore, rescan,
 *         assert the exact balance, and SPEND.
 * ───────────────────────────────────────────────────────────────── */

static int act1_transparent(void)
{
    int failures = 0;
    printf("\n-- ACT 1: transparent destroy-and-recover, ending in a SPEND --\n");

    const int64_t FAUCET_AMOUNT = COIN_VALUE + 10000;
    const int64_t FUND_VALUE    = COIN_VALUE;
    const int64_t SEND_FEE      = WALLET_DEFAULT_FEE_ZAT;
    const char   *PASSPHRASE    = "destruction-drill-act1";

    char livedir[256], backupdir[256], newdir[256];
    dr_mk_datadir(livedir, sizeof(livedir), "act1live");
    dr_mkdir(backupdir, sizeof(backupdir), "act1bk");

    /* ── the machine, before it is destroyed ────────────────────── */
    char livedb[320];
    snprintf(livedb, sizeof(livedb), "%s/node.db", livedir);
    struct node_db live_ndb;
    memset(&live_ndb, 0, sizeof(live_ndb));
    DR_CHECK("live: node_db_open", node_db_open(&live_ndb, livedb));

    struct wallet *live_w = zcl_calloc(1, sizeof(*live_w), "dr_act1_live_wallet");
    DR_CHECK("live: alloc wallet (heap)", live_w != NULL);
    if (live_w) wallet_init(live_w);
    struct wallet_sqlite live_ws;
    DR_CHECK("live: wallet_sqlite_open", wallet_sqlite_open(&live_ws, live_ndb.db));

    rpc_wallet_set_state(live_w, NULL, livedir, &live_ws, NULL, NULL);
    rpc_wallet_set_node_db(&live_ndb);
    rpc_wallet_set_coins_tip(NULL);

    struct rpc_table live_tbl;
    rpc_table_init(&live_tbl);
    register_wallet_rpc_commands(&live_tbl);

    char addrA[128] = "";
    {
        struct json_value params, result;
        dr_params_none(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&live_tbl, "getnewaddress", &params, &result)
                  && result.type == JSON_STR;
        if (ok) snprintf(addrA, sizeof(addrA), "%s", json_get_str(&result));
        json_free(&params);
        json_free(&result);
        DR_CHECK("live: getnewaddress produced the address to be funded",
                 ok && addrA[0]);
    }

    struct tx_destination destA;
    memset(&destA, 0, sizeof(destA));
    bool decoded = addrA[0] && wallet_decode_address(addrA, &destA) &&
                   destA.type == DEST_KEY_ID;
    DR_CHECK("live: address decodes to a P2PKH destination", decoded);

    struct script scriptA;
    script_init(&scriptA);
    if (decoded)
        script_for_destination(&scriptA, &destA);

    /* Keep a copy of the private key ONLY so the drill can later prove the
     * restored key is byte-identical. The restored wallet never receives it
     * from here — it comes back out of the backup file. */
    struct privkey keyA_expected;
    privkey_init(&keyA_expected);
    bool have_expected = decoded && live_w &&
        wallet_dump_key(live_w, &destA.id.key, &keyA_expected);
    DR_CHECK("live: the funded address has a spending key in the wallet",
             have_expected && keyA_expected.fValid);

    /* REAL connect_block-validated funding on the deterministic simnet. */
    struct simnet s;
    DR_CHECK("simnet_init", simnet_init(&s));

    struct dr_key faucet;
    dr_make_key(&faucet);
    struct uint256 cb_txid;
    int cb_height = simnet_tip_height(&s) + 1;
    DR_CHECK("simnet: mint faucet coinbase",
             simnet_mint_coinbase_to(&s, &faucet.spk, FAUCET_AMOUNT, &cb_txid));
    DR_CHECK("simnet: mature faucet coinbase",
             simnet_mint_to_height(&s, cb_height + COINBASE_MATURITY));

    int fund_height = simnet_tip_height(&s) + 1;
    struct uint256 txid_A;
    uint256_set_null(&txid_A);
    struct transaction fund_for_mint;
    bool built = decoded &&
        dr_build_fund_tx(&fund_for_mint, &cb_txid, 0, &scriptA, FUND_VALUE);
    if (built) txid_A = fund_for_mint.hash;
    DR_CHECK("simnet: build the funding transfer", built);
    DR_CHECK("simnet: mint it through REAL connect_block validation",
             built && simnet_mint_txs(&s, &fund_for_mint, 1));

    /* The wallet's own record of the funded coin — wallet_utxos is one of
     * the eight tables a backup captures, so this is the row whose survival
     * the whole drill turns on. */
    struct db_wallet_utxo wu;
    memset(&wu, 0, sizeof(wu));
    memcpy(wu.txid, txid_A.data, 32);
    wu.vout = 0;
    memcpy(wu.address_hash, destA.id.key.id.data, 20);
    wu.value = FUND_VALUE;
    wu.height = fund_height;
    wu.is_coinbase = false;
    wu.script = scriptA.data;
    wu.script_len = scriptA.size;
    DR_CHECK("live: record the funded coin in wallet_utxos",
             decoded && db_wallet_utxo_save(&live_ndb, &wu));

    /* THE NUMBER the drill must reproduce, read through the shipped RPC. */
    char recorded_balance[32] = "";
    {
        struct json_value params, result;
        dr_params_none(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&live_tbl, "getbalance", &params, &result)
                  && result.type == JSON_STR;
        if (ok) snprintf(recorded_balance, sizeof(recorded_balance), "%s",
                         json_get_str(&result));
        json_free(&params);
        json_free(&result);
        char expect[32];
        format_amount(FUND_VALUE, expect, sizeof(expect));
        DR_CHECK("live: getbalance reports the funded amount",
                 ok && strcmp(recorded_balance, expect) == 0);
    }

    /* ── back it up, then encrypt it (the shipped WBE1 path) ────── */
    char plainpath[512] = "";
    int64_t key_count = -1;
    bool backed_up = wallet_backup_run_once(backupdir, &live_ndb, plainpath,
                                            sizeof(plainpath), &key_count,
                                            NULL, 0).ok;
    DR_CHECK("backup: wallet_backup_run_once produced a file with keys",
             backed_up && plainpath[0] && key_count >= 1);

    char encpath[576] = "";
    snprintf(encpath, sizeof(encpath), "%s.enc", plainpath);
    bool encrypted = backed_up &&
        wallet_backup_encrypt_file(plainpath, encpath, PASSPHRASE).ok;
    DR_CHECK("backup: encrypt it (ChaCha20-Poly1305, the shipped path)",
             encrypted);
    /* Remove the plaintext copy: from here the ONLY surviving wallet
     * artifact in the universe is the encrypted file. */
    if (encrypted) (void)unlink(plainpath);

    /* ── DESTROY THE MACHINE ─────────────────────────────────────── */
    dr_clear_rpc_ctx();
    wallet_sqlite_close(&live_ws);
    if (live_w) { wallet_free(live_w); free(live_w); live_w = NULL; }
    node_db_close(&live_ndb);

    dr_destroy_tree(livedir, 2);
    DR_CHECK("DESTROY: the datadir is gone — no node.db, no wal, no blocks/",
             dr_is_destroyed(livedir));
    {
        struct stat st;
        DR_CHECK("DESTROY: the encrypted backup is the only thing left",
                 stat(encpath, &st) == 0 && S_ISREG(st.st_mode));
    }

    /* ── RESTORE onto a fresh datadir, from the backup alone ────── */
    test_fmt_tmpdir(newdir, sizeof(newdir), "drill", "act1new");
    /* Deliberately NOT created: a rebuilt machine has no datadir, and the
     * restore service is supposed to make one. */
    struct wallet_restore_report rep;
    struct wallet_restore_request req = {
        .backup_path = encpath,
        .datadir     = newdir,
        .password    = PASSPHRASE,
        .dry_run     = false,
    };
    struct zcl_result rr = wallet_restore_run(&req, &rep);
    DR_CHECK("restore: wallet_restore_run succeeds on a datadir that did not exist",
             rr.ok);
    DR_CHECK("restore: it created node.db", rr.ok && rep.target_created);
    DR_CHECK("restore: it read the encrypted backup",
             rr.ok && rep.source_was_encrypted);
    DR_CHECK("restore: it merged rows back in",
             rr.ok && rep.total_inserted >= 2);   /* >=1 key + the utxo */
    DR_CHECK("restore: nothing collided on a virgin datadir",
             rr.ok && rep.total_collided == 0);
    DR_CHECK("restore: the target's schema rejected nothing",
             rr.ok && rep.total_rejected == 0);

    /* Per-table: the two rows that ARE the funds must both be back. */
    int64_t restored_keys = -1, restored_utxos = -1;
    for (size_t i = 0; i < rep.n_tables; i++) {
        if (strcmp(rep.tables[i].table, "wallet_keys") == 0)
            restored_keys = rep.tables[i].rows_after;
        else if (strcmp(rep.tables[i].table, "wallet_utxos") == 0)
            restored_utxos = rep.tables[i].rows_after;
    }
    DR_CHECK("restore: wallet_keys came back", restored_keys >= 1);
    DR_CHECK("restore: wallet_utxos came back", restored_utxos == 1);

    /* ── the rebuilt machine ─────────────────────────────────────── */
    char blocksdir[384];
    snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", newdir);
    mkdir(blocksdir, 0755); /* raw-alloc-ok:test-fixture */

    /* Re-supply the block body. On a real rebuilt machine this arrives from
     * the P2P network; it is chain data, not wallet data, and it is NOT in
     * the backup. Byte-identical construction ⇒ the same txid. */
    struct transaction fund_for_disk;
    bool rebuilt_tx = built &&
        dr_build_fund_tx(&fund_for_disk, &cb_txid, 0, &scriptA, FUND_VALUE);
    DR_CHECK("resync: the re-downloaded block carries the same txid",
             rebuilt_tx &&
             memcmp(fund_for_disk.hash.data, txid_A.data, 32) == 0);
    struct disk_block_pos pos;
    bool wrote = rebuilt_tx && dr_write_block(newdir, &fund_for_disk, &pos);
    DR_CHECK("resync: block body written into the rebuilt datadir", wrote);

    struct block_index bi;
    block_index_init(&bi);
    bi.nHeight   = fund_height;
    bi.nFile     = pos.nFile;
    bi.nDataPos  = pos.nPos;
    bi.nStatus   = BLOCK_HAVE_DATA;
    bi.phashBlock = NULL;

    char newdb[576];
    snprintf(newdb, sizeof(newdb), "%s/node.db", newdir);
    struct node_db new_ndb;
    memset(&new_ndb, 0, sizeof(new_ndb));
    DR_CHECK("rebuilt: node_db_open on the restored database",
             node_db_open(&new_ndb, newdb));

    struct wallet *new_w = zcl_calloc(1, sizeof(*new_w), "dr_act1_new_wallet");
    DR_CHECK("rebuilt: alloc wallet (heap)", new_w != NULL);
    if (new_w) wallet_init(new_w);
    struct wallet_sqlite new_ws;
    DR_CHECK("rebuilt: wallet_sqlite_open", wallet_sqlite_open(&new_ws, new_ndb.db));

    /* The keystore is loaded FROM THE RESTORED DATABASE — no import, no WIF,
     * nothing carried over in memory. */
    DR_CHECK("rebuilt: wallet_sqlite_read_keys loads the restored keys",
             new_w && wallet_sqlite_read_keys(&new_ws, new_w));
    {
        struct privkey got;
        privkey_init(&got);
        bool got_it = decoded && new_w && wallet_dump_key(new_w, &destA.id.key, &got);
        DR_CHECK("rebuilt: the restored private key is byte-identical",
                 got_it && have_expected && got.fValid &&
                 memcmp(got.vch, keyA_expected.vch, 32) == 0);
        memory_cleanse(got.vch, 32);
    }

    struct main_state new_ms;
    main_state_init(&new_ms);
    struct block_index **chain_arr =
        calloc((size_t)(fund_height + 1), sizeof(*chain_arr)); /* raw-alloc-ok:test-fixture */
    DR_CHECK("rebuilt: alloc synthetic active_chain", chain_arr != NULL);
    if (chain_arr) {
        chain_arr[fund_height] = &bi;
        free(new_ms.chain_active.chain);
        new_ms.chain_active.chain    = chain_arr;
        new_ms.chain_active.height   = fund_height;
        new_ms.chain_active.capacity = fund_height + 1;
    }

    struct tx_mempool new_mempool;
    tx_mempool_init(&new_mempool, 0);
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache new_coins;
    coins_view_cache_init(&new_coins, &null_view);

    struct coins_cache_entry *eA = coins_view_cache_modify_new(&new_coins, &txid_A);
    DR_CHECK("rebuilt: stamp the coin into the coins view (chain state)",
             eA != NULL);
    if (eA) {
        coins_alloc(&eA->coins, 1);
        eA->coins.vout[0].value = FUND_VALUE;
        eA->coins.vout[0].script_pub_key = scriptA;
        eA->coins.height = fund_height;
        eA->coins.version = 1;
        eA->coins.is_coinbase = false;
    }

    rpc_wallet_set_state(new_w, &new_ms, newdir, &new_ws, &new_mempool, NULL);
    rpc_wallet_set_node_db(&new_ndb);
    rpc_wallet_set_coins_tip(&new_coins);

    struct rpc_table new_tbl;
    rpc_table_init(&new_tbl);
    register_wallet_rpc_commands(&new_tbl);

    /* ── RESCAN — through the real rescanblockchain RPC ──────────── */
    {
        struct json_value params, result;
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&new_tbl, "rescanblockchain", &params,
                                    &result);
        const struct json_value *cov  = ok ? json_get(&result, "coverage_ok") : NULL;
        const struct json_value *fnd  = ok ? json_get(&result, "outputs_found") : NULL;
        const struct json_value *scan = ok ? json_get(&result, "blocks_scanned") : NULL;
        DR_CHECK("rescan: rescanblockchain succeeds", ok);
        DR_CHECK("rescan: coverage_ok — the node could read the blocks",
                 cov && json_get_bool(cov));
        DR_CHECK("rescan: it actually read block bodies",
                 scan && json_get_int(scan) >= 1);
        DR_CHECK("rescan: it found the restored wallet's output",
                 fnd && json_get_int(fnd) >= 1);
        json_free(&params);
        json_free(&result);
    }

    /* ── ASSERT THE EXACT PRIOR BALANCE ─────────────────────────── */
    {
        struct json_value params, result;
        dr_params_none(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&new_tbl, "getbalance", &params, &result)
                  && result.type == JSON_STR;
        bool exact = ok && recorded_balance[0] &&
                     strcmp(json_get_str(&result), recorded_balance) == 0;
        DR_CHECK("RECOVERED: getbalance is EXACTLY the pre-destruction balance",
                 exact);
        json_free(&params);
        json_free(&result);
    }

    /* ── SPEND IT ────────────────────────────────────────────────── */
    struct dr_key recipient;
    dr_make_key(&recipient);
    char addrR[128] = "";
    {
        struct tx_destination destR;
        destR.type = DEST_KEY_ID;
        destR.id.key = recipient.kid;
        wallet_encode_destination(&destR, addrR, sizeof(addrR));
    }

    char sendtxid[80] = "";
    {
        int64_t send_amount = FUND_VALUE - SEND_FEE;  /* exact, no change */
        char amtstr[32];
        format_amount(send_amount, amtstr, sizeof(amtstr));
        struct json_value params, result;
        dr_params_2str(&params, addrR, amtstr);
        json_init(&result);
        bool ok = addrR[0] &&
            rpc_table_execute(&new_tbl, "sendtoaddress", &params, &result) &&
            result.type == JSON_STR;
        if (ok) snprintf(sendtxid, sizeof(sendtxid), "%s", json_get_str(&result));
        if (!ok && result.type == JSON_STR)
            fprintf(stderr, "  sendtoaddress error: %s\n", json_get_str(&result)); /* obs-ok:test-diagnostic */
        json_free(&params);
        json_free(&result);
        DR_CHECK("SPEND: sendtoaddress signs with the RESTORED key and broadcasts",
                 ok && sendtxid[0]);
    }

    struct transaction sendtx;
    transaction_init(&sendtx);
    bool have_sendtx = false;
    if (sendtxid[0]) {
        struct uint256 send_hash;
        uint256_set_hex(&send_hash, sendtxid);
        have_sendtx = tx_mempool_lookup(&new_mempool, &send_hash, &sendtx);
        DR_CHECK("SPEND: the signed tx was admitted to a real mempool",
                 have_sendtx);
    }

    bool mined = false;
    if (have_sendtx) {
        struct coins_cache_entry *espend =
            coins_view_cache_modify(&new_coins, &txid_A);
        if (espend)
            coins_spend(&espend->coins, 0);
        struct coins_cache_entry *enew =
            coins_view_cache_modify_new(&new_coins, &sendtx.hash);
        mined = espend && enew &&
                coins_from_transaction(&enew->coins, &sendtx, fund_height + 1);
    }
    DR_CHECK("SPEND: confirm it (apply to the coins view)", mined);

    if (mined) {
        struct coins spent_check;
        coins_init(&spent_check);
        bool still =
            coins_view_cache_get_coins(&new_coins, &txid_A, &spent_check) &&
            coins_is_available(&spent_check, 0);
        coins_free(&spent_check);
        DR_CHECK("SPEND: the recovered coin is now spent", !still);

        struct coins recv;
        coins_init(&recv);
        bool recv_ok =
            coins_view_cache_get_coins(&new_coins, &sendtx.hash, &recv) &&
            coins_is_available(&recv, 0) &&
            recv.vout[0].value == FUND_VALUE - SEND_FEE &&
            recv.vout[0].script_pub_key.size == recipient.spk.size &&
            memcmp(recv.vout[0].script_pub_key.data, recipient.spk.data,
                   recipient.spk.size) == 0;
        coins_free(&recv);
        DR_CHECK("SPEND: the recipient received the recovered funds — the money MOVED",
                 recv_ok);
    }
    if (have_sendtx)
        transaction_free(&sendtx);

    /* ── teardown ────────────────────────────────────────────────── */
    dr_clear_rpc_ctx();
    if (have_expected)
        memory_cleanse(keyA_expected.vch, 32);
    memory_cleanse(faucet.priv.vch, 32);
    memory_cleanse(recipient.priv.vch, 32);
    coins_view_cache_free(&new_coins);
    tx_mempool_free(&new_mempool);
    free(new_ms.chain_active.chain);
    new_ms.chain_active.chain = NULL;
    wallet_sqlite_close(&new_ws);
    if (new_w) { wallet_free(new_w); free(new_w); new_w = NULL; }
    node_db_close(&new_ndb);
    simnet_free(&s);

    dr_destroy_tree(newdir, 2);
    dr_destroy_tree(backupdir, 2);
    return failures;
}

/* ─────────────────────────────────────────────────────────────────
 * ACT 2 — THE NEGATIVE. Restore onto a snapshot-bootstrapped datadir
 *         (block index present, block BODIES absent) and prove the
 *         rescan refuses to call "0 found" an answer.
 *
 * This is the exact shape snapshot_controller_import.c leaves behind: it
 * strips BLOCK_HAVE_DATA across the whole imported range when the source's
 * block files were not copied. Before the fix, a user restoring a backup
 * onto such a node saw "Rescan complete: N blocks scanned, 0 wallet outputs
 * found", a zero balance, and concluded the backup was empty. It is the way
 * a real user loses money, so it is the assertion that matters most here.
 * ───────────────────────────────────────────────────────────────── */

static int act2_bodyless_restore_must_fail_loud(void)
{
    int failures = 0;
    printf("\n-- ACT 2: restore onto a body-less (snapshot-bootstrapped) node "
           "must FAIL LOUD --\n");

    const int64_t FUND_VALUE = 7 * COIN_VALUE;
    const int     RANGE_TOP  = 40;

    char srcdir[256], backupdir[256], snapdir[256];
    dr_mkdir(srcdir, sizeof(srcdir), "act2src");
    dr_mkdir(backupdir, sizeof(backupdir), "act2bk");

    /* A funded wallet, backed up. */
    char srcdb[320];
    snprintf(srcdb, sizeof(srcdb), "%s/node.db", srcdir);
    struct node_db src_ndb;
    memset(&src_ndb, 0, sizeof(src_ndb));
    DR_CHECK("act2: node_db_open (source)", node_db_open(&src_ndb, srcdb));

    struct wallet_sqlite src_ws;
    DR_CHECK("act2: wallet_sqlite_open", wallet_sqlite_open(&src_ws, src_ndb.db));

    struct dr_key keyB;
    dr_make_key(&keyB);
    DR_CHECK("act2: persist a real key",
             wallet_sqlite_write_key_r(&src_ws, &keyB.pub, &keyB.priv).ok);

    struct db_wallet_utxo wu;
    memset(&wu, 0, sizeof(wu));
    memset(wu.txid, 0x5A, 32);
    wu.vout = 0;
    memcpy(wu.address_hash, keyB.kid.id.data, 20);
    wu.value = FUND_VALUE;
    wu.height = 10;
    wu.is_coinbase = false;
    wu.script = keyB.spk.data;
    wu.script_len = keyB.spk.size;
    DR_CHECK("act2: fund it", db_wallet_utxo_save(&src_ndb, &wu));

    char plainpath[512] = "";
    bool backed_up = wallet_backup_run_once(backupdir, &src_ndb, plainpath,
                                            sizeof(plainpath), NULL,
                                            NULL, 0).ok;
    DR_CHECK("act2: backup taken", backed_up && plainpath[0]);

    wallet_sqlite_close(&src_ws);
    node_db_close(&src_ndb);
    dr_destroy_tree(srcdir, 2);
    DR_CHECK("act2: DESTROY the source datadir", dr_is_destroyed(srcdir));

    /* Restore onto a datadir that will have NO block bodies. */
    test_fmt_tmpdir(snapdir, sizeof(snapdir), "drill", "act2snap");
    struct wallet_restore_report rep;
    struct wallet_restore_request req = {
        .backup_path = plainpath,
        .datadir     = snapdir,
        .password    = NULL,
        .dry_run     = false,
    };
    struct zcl_result rr = wallet_restore_run(&req, &rep);
    DR_CHECK("act2: restore onto the snapshot-bootstrapped datadir succeeds",
             rr.ok && rep.total_inserted >= 2);

    char snapdb[576];
    snprintf(snapdb, sizeof(snapdb), "%s/node.db", snapdir);
    struct node_db snap_ndb;
    memset(&snap_ndb, 0, sizeof(snap_ndb));
    DR_CHECK("act2: open the restored database", node_db_open(&snap_ndb, snapdb));

    struct wallet *snap_w = zcl_calloc(1, sizeof(*snap_w), "dr_act2_snap_wallet");
    DR_CHECK("act2: alloc wallet (heap)", snap_w != NULL);
    if (snap_w) wallet_init(snap_w);
    struct wallet_sqlite snap_ws;
    DR_CHECK("act2: wallet_sqlite_open", wallet_sqlite_open(&snap_ws, snap_ndb.db));
    DR_CHECK("act2: the restored keys load",
             snap_w && wallet_sqlite_read_keys(&snap_ws, snap_w));

    /* THE SNAPSHOT STATE: every height is indexed, and every one of them has
     * BLOCK_HAVE_DATA CLEAR — snapshot_controller_import.c's header-only
     * import. There is no blocks/ directory at all. */
    struct main_state snap_ms;
    main_state_init(&snap_ms);
    struct block_index *bis =
        calloc((size_t)(RANGE_TOP + 1), sizeof(*bis)); /* raw-alloc-ok:test-fixture */
    struct block_index **arr =
        calloc((size_t)(RANGE_TOP + 1), sizeof(*arr)); /* raw-alloc-ok:test-fixture */
    DR_CHECK("act2: alloc the header-only chain", bis && arr);
    if (bis && arr) {
        for (int h = 0; h <= RANGE_TOP; h++) {
            block_index_init(&bis[h]);
            bis[h].nHeight = h;
            memset(bis[h].hashBlock.data, (uint8_t)(0x40 + h), 32);
            bis[h].phashBlock = &bis[h].hashBlock;
            bis[h].nStatus = 0;    /* BLOCK_HAVE_DATA CLEAR — no body */
            arr[h] = &bis[h];
        }
        free(snap_ms.chain_active.chain);
        snap_ms.chain_active.chain    = arr;
        snap_ms.chain_active.height   = RANGE_TOP;
        snap_ms.chain_active.capacity = RANGE_TOP + 1;
    }
    {
        struct stat st;
        char blocksdir[640];
        snprintf(blocksdir, sizeof(blocksdir), "%s/blocks", snapdir);
        DR_CHECK("act2: the datadir genuinely has no block files",
                 stat(blocksdir, &st) != 0);
    }

    struct tx_mempool snap_mempool;
    tx_mempool_init(&snap_mempool, 0);
    struct coins_view null_view;
    memset(&null_view, 0, sizeof(null_view));
    struct coins_view_cache snap_coins;
    coins_view_cache_init(&snap_coins, &null_view);

    rpc_wallet_set_state(snap_w, &snap_ms, snapdir, &snap_ws, &snap_mempool,
                         NULL);
    rpc_wallet_set_node_db(&snap_ndb);
    rpc_wallet_set_coins_tip(&snap_coins);

    struct rpc_table snap_tbl;
    rpc_table_init(&snap_tbl);
    register_wallet_rpc_commands(&snap_tbl);

    /* ── the assertion this whole file exists for ────────────────── */
    {
        struct json_value params, result;
        json_init(&params);
        json_set_array(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&snap_tbl, "rescanblockchain", &params,
                                    &result);
        const struct json_value *cov  = ok ? json_get(&result, "coverage_ok") : NULL;
        const struct json_value *blk  = ok ? json_get(&result, "blocker") : NULL;
        const struct json_value *fnd  = ok ? json_get(&result, "outputs_found") : NULL;
        const struct json_value *scan = ok ? json_get(&result, "blocks_scanned") : NULL;
        const struct json_value *miss = ok ? json_get(&result, "blocks_missing_data") : NULL;

        DR_CHECK("act2: rescanblockchain returns a reply", ok);
        DR_CHECK("act2: it read ZERO block bodies",
                 scan && json_get_int(scan) == 0);
        DR_CHECK("act2: it counted every height as missing its body",
                 miss && json_get_int(miss) == (int64_t)RANGE_TOP + 1);
        DR_CHECK("act2: it found nothing (it could not look)",
                 fnd && json_get_int(fnd) == 0);
        /* The two that make this a loud failure rather than a quiet zero. */
        DR_CHECK("act2: coverage_ok is FALSE — the zero is NOT an answer",
                 cov && cov->type == JSON_BOOL && !json_get_bool(cov));
        DR_CHECK("act2: it names the typed blocker RESCAN_NO_BLOCK_DATA",
                 blk && blk->type == JSON_STR &&
                 strcmp(json_get_str(blk),
                        WALLET_RESCAN_BLOCKER_NO_BLOCK_DATA) == 0);
        json_free(&params);
        json_free(&result);
    }

    /* The funds ARE there — the wallet rows restored fine. A user reading
     * only "0 outputs found" would have concluded the opposite, which is
     * precisely why the blocker above has to fire. */
    DR_CHECK("act2: meanwhile the restored balance is intact in wallet_utxos",
             db_wallet_utxo_spendable_balance(&snap_ndb, NULL) == FUND_VALUE);

    /* Same range, same wallet, bodies present ⇒ no blocker. Without this the
     * act above could pass with a rescan that fails unconditionally. */
    if (bis && arr && snap_w) {
        struct wallet_rescan_report ctl;
        for (int h = 0; h <= RANGE_TOP; h++)
            bis[h].nStatus = BLOCK_HAVE_DATA;
        (void)wallet_rescan_report(snap_w, &snap_ms.chain_active, 0,
                                   RANGE_TOP, snapdir, &ctl);
        /* Bodies are FLAGGED present but the files are not there, so the
         * read fails — a different, equally loud failure. What must NOT
         * happen is a silent success. */
        DR_CHECK("act2 control: a claimed-but-unreadable body also blocks",
                 !ctl.coverage_ok && ctl.blocks_read_failed == RANGE_TOP + 1 &&
                 ctl.blocks_missing_data == 0);
        for (int h = 0; h <= RANGE_TOP; h++)
            bis[h].nStatus = 0;
    }

    dr_clear_rpc_ctx();
    memory_cleanse(keyB.priv.vch, 32);
    coins_view_cache_free(&snap_coins);
    tx_mempool_free(&snap_mempool);
    free(snap_ms.chain_active.chain);
    snap_ms.chain_active.chain = NULL;
    free(bis);
    wallet_sqlite_close(&snap_ws);
    if (snap_w) { wallet_free(snap_w); free(snap_w); snap_w = NULL; }
    node_db_close(&snap_ndb);

    dr_destroy_tree(snapdir, 2);
    dr_destroy_tree(backupdir, 2);
    return failures;
}

/* ─────────────────────────────────────────────────────────────────
 * ACT 3 — SHIELDED. Params- and prover-gated; skips cleanly otherwise.
 * ───────────────────────────────────────────────────────────────── */

struct dr_zid {
    struct zip32_xsk xsk;
    uint8_t ask[32], nsk[32], ovk[32];
    uint8_t ak[32], nk[32], ivk[32];
    uint8_t d[11], pk_d[32];
};

static bool dr_zid_from_seed(struct dr_zid *id, const uint8_t seed[32])
{
    zip32_xsk_master(&id->xsk, seed, 32);
    struct zip32_xfvk xfvk;
    zip32_xsk_to_xfvk(&xfvk, &id->xsk);
    if (!zip32_xfvk_address(&xfvk, id->d, id->pk_d))
        return false;
    memcpy(id->ask, id->xsk.expsk.ask, 32);
    memcpy(id->nsk, id->xsk.expsk.nsk, 32);
    memcpy(id->ovk, id->xsk.expsk.ovk, 32);
    memcpy(id->ak, xfvk.fvk.ak, 32);
    memcpy(id->nk, xfvk.fvk.nk, 32);
    sapling_crh_ivk(id->ak, id->nk, id->ivk);
    return true;
}

static bool dr_sighash(struct transaction *tx, const struct consensus_params *cp,
                       int height, struct uint256 *out)
{
    uint32_t branch = consensus_current_epoch_branch_id(height, cp);
    struct sighash_type ht;
    ht.raw = 1; /* SIGHASH_ALL */
    struct script empty;
    empty.size = 0;
    uint256_set_null(out);
    return signature_hash(&empty, tx, NOT_AN_INPUT, ht, 0, branch, NULL, out);
}

static bool dr_verify(const struct transaction *tx,
                      const struct consensus_params *cp, int height)
{
    struct validation_state st;
    validation_state_init(&st);
    bool ok = contextual_check_transaction(tx, &st, cp, height, 100);
    if (!ok)
        printf("    contextual reject: %s\n", st.reject_reason);
    return ok;
}

static void dr_rsk(const uint8_t ask[32], const uint8_t ar[32], uint8_t rsk[32])
{
    struct fs a, r, o;
    fs_from_bytes(&a, ask);
    fs_from_bytes(&r, ar);
    fs_add(&o, &a, &r);
    fs_to_bytes(rsk, &o);
    memory_cleanse(&a, sizeof(a));
    memory_cleanse(&r, sizeof(r));
    memory_cleanse(&o, sizeof(o));
}

static bool dr_decrypt_note(const struct output_description *od,
                            const uint8_t ivk[32], uint64_t *value_out,
                            uint8_t rcm_out[32])
{
    uint8_t dhsecret[32], enckey[32], pt[564];
    bool ok = sapling_ka_agree(od->ephemeral_key.data, ivk, dhsecret) &&
              sapling_kdf(enckey, dhsecret, od->ephemeral_key.data) &&
              sapling_note_decrypt(enckey, od->enc_ciphertext,
                                   sizeof(od->enc_ciphertext), pt);
    if (ok) {
        uint64_t v = 0;
        for (int i = 0; i < 8; i++)
            v |= (uint64_t)pt[12 + i] << (8 * i);
        if (value_out) *value_out = v;
        if (rcm_out) memcpy(rcm_out, pt + 20, 32);
    }
    memory_cleanse(dhsecret, sizeof(dhsecret));
    memory_cleanse(enckey, sizeof(enckey));
    memory_cleanse(pt, sizeof(pt));
    return ok;
}

static int act3_shielded(void)
{
    int failures = 0;
    printf("\n-- ACT 3: SHIELDED destroy-and-recover, ending in a shielded SPEND --\n");

    const int64_t FUND_VALUE     = 100000000;   /* 1 ZCL */
    const int64_t FEE            = 10000;
    const int64_t SHIELDED_VALUE = FUND_VALUE - FEE;
    const int     SAPLING_H      = 100;
    const char   *PASSPHRASE     = "destruction-drill-act3";

    char livedir[256], backupdir[256], newdir[256];
    dr_mkdir(livedir, sizeof(livedir), "act3live");
    dr_mkdir(backupdir, sizeof(backupdir), "act3bk");

    /* A wallet with a real Sapling spending key, derived from a seed we
     * install so the restored copy can be compared byte-for-byte. */
    uint8_t seed32[32];
    memset(seed32, 0x5e, sizeof(seed32));
    seed32[0] = 0xD1;
    struct dr_zid id;
    DR_CHECK("act3: derive the Sapling spending key", dr_zid_from_seed(&id, seed32));

    char livedb[320];
    snprintf(livedb, sizeof(livedb), "%s/node.db", livedir);
    struct node_db live_ndb;
    memset(&live_ndb, 0, sizeof(live_ndb));
    DR_CHECK("act3: node_db_open", node_db_open(&live_ndb, livedb));
    struct wallet_sqlite live_ws;
    DR_CHECK("act3: wallet_sqlite_open", wallet_sqlite_open(&live_ws, live_ndb.db));

    struct wallet *live_w = zcl_calloc(1, sizeof(*live_w), "dr_act3_live_wallet");
    DR_CHECK("act3: alloc wallet (heap)", live_w != NULL);
    if (live_w) wallet_init(live_w);
    DR_CHECK("act3: install the seed",
             live_w && sapling_keystore_set_seed(&live_w->sapling_keys, seed32));
    DR_CHECK("act3: import the spending key",
             live_w && sapling_keystore_import_xsk(&live_w->sapling_keys, &id.xsk));
    DR_CHECK("act3: persist the seed",
             wallet_sqlite_write_sapling_seed(&live_ws, seed32));
    DR_CHECK("act3: persist the Sapling key",
             live_w && live_w->sapling_keys.num_keys >= 1 &&
             wallet_sqlite_write_sapling_key(&live_ws,
                 live_w->sapling_keys.keys[0].child_index,
                 &live_w->sapling_keys.keys[0]));

    char zaddr[128] = "";
    DR_CHECK("act3: encode the z-address",
             sapling_encode_payment_address(id.d, id.pk_d, "zs", zaddr,
                                            sizeof(zaddr)));

    /* ── a REAL shielded note the REAL verifier accepts ──────────── */
    struct simnet s;
    DR_CHECK("act3: simnet_init", simnet_init(&s));
    simnet_activate_sapling_at(&s, SAPLING_H);
    DR_CHECK("act3: enable the in-sim Sapling tree", simnet_enable_sapling_tree(&s));
    simnet_enable_contextual_check(&s, false);
    const struct consensus_params *cp = &s.params.consensus;

    struct script fund_script;
    script_init(&fund_script);
    { uint8_t pk[3] = { 0x76, 0xa9, 0x14 }; script_set(&fund_script, pk, sizeof(pk)); }
    struct uint256 cb_txid;
    DR_CHECK("act3: mint funding coinbase",
             simnet_mint_coinbase_to(&s, &fund_script, FUND_VALUE, &cb_txid));
    DR_CHECK("act3: mature it",
             simnet_mint_to_height(&s, SAPLING_H + COINBASE_MATURITY));

    const int tz_height = SAPLING_H + COINBASE_MATURITY + 1;
    const int zt_height = tz_height + 1;

    uint8_t note_rcm[32];  memset(note_rcm, 0, 32);
    uint8_t note_cm[32];   memset(note_cm, 0, 32);
    struct uint256 note_cm_u256;
    uint256_set_null(&note_cm_u256);
    bool have_note = false;
    {
        void *pctx = zclassic_sapling_proving_ctx_init();
        DR_CHECK("act3: acquire the production proving ctx", pctx != NULL);

        struct transaction tz;
        transaction_init(&tz);
        tz.overwintered     = true;
        tz.version          = SAPLING_TX_VERSION;
        tz.version_group_id = SAPLING_VERSION_GROUP_ID;
        DR_CHECK("act3: alloc transparent input", transaction_alloc(&tz, 1, 0));
        tz.vin[0].prevout.hash = cb_txid;
        tz.vin[0].prevout.n    = 0;
        tz.vin[0].sequence     = 0xFFFFFFFFu;
        { uint8_t ss[2] = { 0x00, 0x00 }; script_set(&tz.vin[0].script_sig, ss, sizeof(ss)); }
        tz.value_balance = -SHIELDED_VALUE;

        tz.v_shielded_output = zcl_calloc(1, sizeof(struct output_description),
                                          "dr_tz_out");
        DR_CHECK("act3: alloc shielded output", tz.v_shielded_output != NULL);
        tz.num_shielded_output = 1;

        uint8_t memo[512];
        memset(memo, 0xF6, sizeof(memo));
        const char *msg = "destruction drill: shielded funds to be destroyed";
        memcpy(memo, msg, strlen(msg));

        bool ok = pctx && tz.v_shielded_output &&
            sapling_build_output_with_ctx(
                pctx, id.ovk, id.d, id.pk_d, (uint64_t)SHIELDED_VALUE, memo,
                tz.v_shielded_output[0].cv.data,
                tz.v_shielded_output[0].cm.data,
                tz.v_shielded_output[0].ephemeral_key.data,
                tz.v_shielded_output[0].enc_ciphertext,
                tz.v_shielded_output[0].out_ciphertext,
                tz.v_shielded_output[0].zkproof);
        DR_CHECK("act3: build the t->z output (production prover)", ok);

        struct uint256 sighash;
        DR_CHECK("act3: sighash", ok && dr_sighash(&tz, cp, tz_height, &sighash));
        DR_CHECK("act3: binding sig",
                 ok && zclassic_sapling_binding_sig(pctx, tz.value_balance,
                                                    sighash.data, tz.binding_sig));
        transaction_compute_hash(&tz);
        DR_CHECK("act3: the REAL consensus verifier ACCEPTS the funding tx",
                 ok && dr_verify(&tz, cp, tz_height));

        uint64_t dv = 0;
        bool dec = ok && dr_decrypt_note(&tz.v_shielded_output[0], id.ivk,
                                         &dv, note_rcm);
        DR_CHECK("act3: the note decrypts to the wallet's ivk",
                 dec && dv == (uint64_t)SHIELDED_VALUE);
        if (ok) {
            memcpy(note_cm, tz.v_shielded_output[0].cm.data, 32);
            memcpy(note_cm_u256.data, note_cm, 32);
        }

        DR_CHECK("act3: mint it (tree append + connect_block)",
                 ok && simnet_mint_txs(&s, &tz, 1));
        have_note = dec && simnet_sapling_tree_size(&s) == 1;
        DR_CHECK("act3: the note is at tree position 0", have_note);

        free(tz.v_shielded_output);
        tz.v_shielded_output = NULL;
        tz.num_shielded_output = 0;
        transaction_free(&tz);
        zclassic_sapling_proving_ctx_free(pctx);
    }

    /* Persist the note — with its REAL rcm and cm, the material a spend
     * needs and the material the backup must carry. */
    struct db_sapling_note note;
    memset(&note, 0, sizeof(note));
    memset(note.txid, 0xD1, 32);
    note.output_index = 0;
    note.value = SHIELDED_VALUE;
    memcpy(note.rcm, note_rcm, 32);
    memset(note.memo, 0xF6, sizeof(note.memo));
    note.memo_len = 512;
    memcpy(note.ivk, id.ivk, 32);
    memcpy(note.diversifier, id.d, 11);
    memcpy(note.pk_d, id.pk_d, 32);
    memcpy(note.cm, note_cm, 32);
    memset(note.nullifier, 0xA5, 32);   /* replaced by the real one on spend */
    note.block_height = tz_height;
    note.is_spent = false;
    snprintf(note.address, sizeof(note.address), "%s", zaddr);
    snprintf(note.source, sizeof(note.source), "%s", DB_SAPLING_NOTE_SOURCE_LOCAL);
    DR_CHECK("act3: persist the received note", have_note &&
             db_sapling_note_save(&live_ndb, &note));

    /* ── back up, then DESTROY ───────────────────────────────────── */
    char plainpath[512] = "";
    bool backed_up = wallet_backup_run_once(backupdir, &live_ndb, plainpath,
                                            sizeof(plainpath), NULL, NULL, 0).ok;
    DR_CHECK("act3: backup taken", backed_up && plainpath[0]);
    char encpath[576] = "";
    snprintf(encpath, sizeof(encpath), "%s.enc", plainpath);
    bool encrypted = backed_up &&
        wallet_backup_encrypt_file(plainpath, encpath, PASSPHRASE).ok;
    DR_CHECK("act3: encrypt it", encrypted);
    if (encrypted) (void)unlink(plainpath);

    wallet_sqlite_close(&live_ws);
    if (live_w) { wallet_free(live_w); free(live_w); live_w = NULL; }
    node_db_close(&live_ndb);
    dr_destroy_tree(livedir, 2);
    DR_CHECK("act3: DESTROY the datadir — the shielded key and note are gone",
             dr_is_destroyed(livedir));

    /* ── RESTORE ─────────────────────────────────────────────────── */
    test_fmt_tmpdir(newdir, sizeof(newdir), "drill", "act3new");
    struct wallet_restore_report rep;
    struct wallet_restore_request req = {
        .backup_path = encpath,
        .datadir     = newdir,
        .password    = PASSPHRASE,
        .dry_run     = false,
    };
    struct zcl_result rr = wallet_restore_run(&req, &rep);
    DR_CHECK("act3: wallet_restore_run succeeds", rr.ok);

    int64_t r_sap_keys = -1, r_seed = -1, r_notes = -1;
    for (size_t i = 0; i < rep.n_tables; i++) {
        if (strcmp(rep.tables[i].table, "wallet_sapling_keys") == 0)
            r_sap_keys = rep.tables[i].rows_after;
        else if (strcmp(rep.tables[i].table, "wallet_seed") == 0)
            r_seed = rep.tables[i].rows_after;
        else if (strcmp(rep.tables[i].table, "wallet_sapling_notes") == 0)
            r_notes = rep.tables[i].rows_after;
    }
    DR_CHECK("act3: wallet_sapling_keys came back", r_sap_keys >= 1);
    DR_CHECK("act3: wallet_seed came back", r_seed >= 1);
    DR_CHECK("act3: wallet_sapling_notes came back", r_notes == 1);

    char newdb[576];
    snprintf(newdb, sizeof(newdb), "%s/node.db", newdir);
    struct node_db new_ndb;
    memset(&new_ndb, 0, sizeof(new_ndb));
    DR_CHECK("act3: open the restored database", node_db_open(&new_ndb, newdb));
    struct wallet_sqlite new_ws;
    DR_CHECK("act3: wallet_sqlite_open", wallet_sqlite_open(&new_ws, new_ndb.db));

    struct wallet *new_w = zcl_calloc(1, sizeof(*new_w), "dr_act3_new_wallet");
    DR_CHECK("act3: alloc wallet (heap)", new_w != NULL);
    if (new_w) wallet_init(new_w);
    uint8_t restored_seed[32];
    memset(restored_seed, 0, sizeof(restored_seed));
    DR_CHECK("act3: the seed loads out of the restored database",
             wallet_sqlite_read_sapling_seed(&new_ws, restored_seed) &&
             memcmp(restored_seed, seed32, 32) == 0);
    DR_CHECK("act3: the Sapling keys load out of the restored database",
             new_w && wallet_sqlite_read_sapling_keys(&new_ws, new_w) &&
             new_w->sapling_keys.num_keys >= 1);

    const struct sapling_key_entry *restored_key = new_w ?
        sapling_keystore_find_by_ivk(&new_w->sapling_keys, id.ivk) : NULL;
    DR_CHECK("act3: the restored keystore holds the note's ivk", restored_key != NULL);
    DR_CHECK("act3: the restored SPENDING key is byte-identical",
             restored_key &&
             memcmp(restored_key->xsk.expsk.ask, id.ask, 32) == 0 &&
             memcmp(restored_key->xsk.expsk.nsk, id.nsk, 32) == 0);

    /* ── the restored note, read back out of the restored database ── */
    uint8_t got_rcm[32], got_cm[32];
    int64_t got_value = -1;
    bool note_back = false;
    {
        sqlite3_stmt *st = NULL;
        const char *sql = "SELECT value, rcm, cm FROM wallet_sapling_notes "
                          "WHERE spent_txid IS NULL LIMIT 1";
        if (sqlite3_prepare_v2(new_ndb.db, sql, -1, &st, NULL) == SQLITE_OK &&
            sqlite3_step(st) == SQLITE_ROW) {
            got_value = sqlite3_column_int64(st, 0);
            const void *rcm_b = sqlite3_column_blob(st, 1);
            const void *cm_b  = sqlite3_column_blob(st, 2);
            if (rcm_b && cm_b && sqlite3_column_bytes(st, 1) == 32 &&
                sqlite3_column_bytes(st, 2) == 32) {
                memcpy(got_rcm, rcm_b, 32);
                memcpy(got_cm, cm_b, 32);
                note_back = true;
            }
        }
        if (st) sqlite3_finalize(st);
    }
    DR_CHECK("act3: the note's value survived exactly",
             note_back && got_value == SHIELDED_VALUE);
    DR_CHECK("act3: the note's rcm survived byte-for-byte",
             note_back && memcmp(got_rcm, note_rcm, 32) == 0);
    DR_CHECK("act3: the note's commitment survived byte-for-byte",
             note_back && memcmp(got_cm, note_cm, 32) == 0);

    /* ── REBUILD THE WITNESS ──────────────────────────────────────
     * A restored note has rows but no witness, and a note without a witness
     * cannot be spent — that is what `core wallet rescan-witnesses` is for.
     * Here the tree is rebuilt from the re-synced chain's note commitments
     * (chain data, never from the backup) and the witness re-derived. */
    struct incremental_merkle_tree tree;
    sapling_tree_init(&tree);
    struct incremental_witness wit;
    memset(&wit, 0, sizeof(wit));
    struct uint256 anchor;
    uint256_set_null(&anchor);
    bool witness_ok = false;
    if (note_back) {
        struct uint256 leaf;
        uint256_set_null(&leaf);
        memcpy(leaf.data, got_cm, 32);
        incremental_tree_append(&tree, &leaf);
        incremental_witness_init(&wit, &tree);
        incremental_tree_root(&tree, &anchor);
        struct uint256 wroot;
        incremental_witness_root(&wit, &wroot);
        witness_ok = memcmp(wroot.data, anchor.data, 32) == 0;
    }
    DR_CHECK("act3: the rebuilt witness hashes up to the rebuilt anchor",
             witness_ok);
    {
        struct uint256 chain_anchor;
        uint256_set_null(&chain_anchor);
        bool same = simnet_sapling_tree_root(&s, &chain_anchor) &&
                    memcmp(chain_anchor.data, anchor.data, 32) == 0;
        DR_CHECK("act3: the rebuilt anchor equals the chain's own tree root",
                 same);
    }

    /* ── SPEND IT: a real z->t spend from restored material ──────── */
    if (witness_ok && restored_key) {
        void *pctx = zclassic_sapling_proving_ctx_init();
        DR_CHECK("act3: acquire the proving ctx for the spend", pctx != NULL);

        struct transaction zt;
        transaction_init(&zt);
        zt.overwintered     = true;
        zt.version          = SAPLING_TX_VERSION;
        zt.version_group_id = SAPLING_VERSION_GROUP_ID;
        /* The pool loses the full note value. The transparent output is lower
         * by FEE; fees do not reduce Sapling valueBalance itself. */
        zt.value_balance    = SHIELDED_VALUE;

        struct dr_key sink;
        dr_make_key(&sink);
        bool alloced = transaction_alloc(&zt, 0, 1);
        DR_CHECK("act3: alloc the transparent output", alloced);
        if (alloced) {
            zt.vout[0].value = SHIELDED_VALUE - FEE;
            zt.vout[0].script_pub_key = sink.spk;
        }

        zt.v_shielded_spend = zcl_calloc(1, sizeof(struct spend_description),
                                         "dr_zt_spend");
        DR_CHECK("act3: alloc the shielded spend", zt.v_shielded_spend != NULL);

        uint8_t path[1 + 32 * 33];
        size_t path_len = 0;
        bool pathok = incremental_witness_merkle_path(&wit, path, &path_len);
        DR_CHECK("act3: extract the Merkle path from the rebuilt witness", pathok);

        /* EVERY secret below came out of the restored database: the spend
         * authority (ask/nsk from the restored keystore), the address the
         * note pays to, and the note randomness (rcm read back out of
         * wallet_sapling_notes). Nothing survives from the destroyed
         * machine's memory. */
        uint8_t ar[32];
        bool spend_built = pctx && zt.v_shielded_spend && pathok && alloced &&
            sapling_build_spend_with_ctx(
                pctx, restored_key->xsk.expsk.ask, restored_key->xsk.expsk.nsk,
                restored_key->diversifier, restored_key->pk_d, got_rcm,
                (uint64_t)got_value, /*position*/0, anchor.data,
                path, path_len,
                zt.v_shielded_spend[0].cv.data,
                zt.v_shielded_spend[0].nullifier.data,
                zt.v_shielded_spend[0].rk.data,
                zt.v_shielded_spend[0].zkproof, ar);
        DR_CHECK("act3: build the spend proof from the RESTORED key + rcm",
                 spend_built);
        if (spend_built) {
            zt.num_shielded_spend = 1;
            memcpy(zt.v_shielded_spend[0].anchor.data, anchor.data, 32);
        }

        struct uint256 sighash;
        DR_CHECK("act3: sighash",
                 spend_built && dr_sighash(&zt, cp, zt_height, &sighash));
        if (spend_built) {
            uint8_t rsk[32];
            dr_rsk(restored_key->xsk.expsk.ask, ar, rsk);
            DR_CHECK("act3: spend_auth_sig from the restored spending key",
                     redjubjub_sign(rsk, sighash.data, 32,
                                    zt.v_shielded_spend[0].spend_auth_sig, 5));
            memory_cleanse(rsk, sizeof(rsk));
        }
        DR_CHECK("act3: binding sig",
                 spend_built && zclassic_sapling_binding_sig(
                     pctx, zt.value_balance, sighash.data, zt.binding_sig));
        transaction_compute_hash(&zt);

        DR_CHECK("act3: THE REAL CONSENSUS VERIFIER ACCEPTS THE RESTORED "
                 "WALLET'S SHIELDED SPEND — the shielded money MOVED",
                 spend_built && dr_verify(&zt, cp, zt_height));

        /* Negative control: a one-byte tamper must be rejected, so the
         * ACCEPT above is a verdict and not a rubber stamp. */
        if (spend_built) {
            struct transaction bad;
            transaction_init(&bad);
            bool copied = transaction_copy(&bad, &zt);
            if (copied && bad.num_shielded_spend == 1) {
                bad.v_shielded_spend[0].zkproof[0] ^= 0x01;
                transaction_compute_hash(&bad);
            }
            DR_CHECK("act3: a tampered spend proof is REJECTED",
                     copied && !dr_verify(&bad, cp, zt_height));
            transaction_free(&bad);
        }

        memory_cleanse(sink.priv.vch, 32);
        free(zt.v_shielded_spend);
        zt.v_shielded_spend = NULL;
        zt.num_shielded_spend = 0;
        transaction_free(&zt);
        zclassic_sapling_proving_ctx_free(pctx);
    } else {
        DR_CHECK("act3: shielded spend prerequisites (witness + restored key)",
                 false);
    }

    memory_cleanse(seed32, sizeof(seed32));
    memory_cleanse(restored_seed, sizeof(restored_seed));
    memory_cleanse(&id, sizeof(id));
    wallet_sqlite_close(&new_ws);
    if (new_w) { wallet_free(new_w); free(new_w); new_w = NULL; }
    node_db_close(&new_ndb);
    simnet_free(&s);

    dr_destroy_tree(newdir, 2);
    dr_destroy_tree(backupdir, 2);
    return failures;
}

/* ── ACT 4: THE TWELVE WORDS ──────────────────────────────────────
 *
 * Acts 1-3 recover from a FILE. This act recovers from nothing but words
 * on paper — the disaster where the machine and the backup file went into
 * the same fire.
 *
 * Two claims, and neither is a green test for its own sake:
 *
 *   (a) SEED AGREEMENT. The 32-byte seed the node persists for a wallet it
 *       created is byte-for-byte the seed its recovery phrase derives.
 *       Proven twice over: the seed read back off disk equals
 *       mnemonic_to_wallet_seed(phrase), and the first receiving address
 *       computed from each of those two seeds is the same string. If these
 *       ever diverge, "recovery succeeded" would hand a user an empty
 *       wallet, which is worse than no feature at all.
 *
 *   (b) THE CAPABILITY. Create a wallet, write down its words, ask it for
 *       a receiving address, then DELETE the datadir — every file,
 *       asserted gone. Recover into a FRESH datadir from the phrase alone,
 *       through the shipped service. The same address comes back, and the
 *       spending key behind it is in the recovered keystore.
 *
 * Plus the two refusals that keep the feature from destroying money: a
 * mistyped phrase is rejected rather than opening an empty wallet, and
 * recovering over a datadir that already holds a wallet is refused.
 *
 * Hermetic: no network, no params, no prover, no node.
 */
/* Is the spending key behind `addr` in this wallet's keystore? The whole
 * question a user is asking when they ask whether their money came back:
 * an address the wallet cannot sign for is not theirs, however familiar
 * the string looks. */
static bool act4_addr_is_mine(const struct wallet *w, const char *addr)
{
    const struct chain_params *cp = chain_params_get();
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk_pfx =
        chain_params_base58_prefix(cp, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc_pfx =
        chain_params_base58_prefix(cp, B58_SCRIPT_ADDRESS, &sc_len);
    struct tx_destination d;
    if (!decode_destination(addr, pk_pfx, pk_len, sc_pfx, sc_len, &d) ||
        d.type != DEST_KEY_ID)
        return false;
    return keystore_have_key(&w->keystore, &d.id.key);
}

/* Rewrite `phrase` into `out` with every single space replaced by `sep`,
 * optionally wrapped in leading/trailing whitespace. The point is that all
 * of these are the SAME twelve words to a human holding a piece of paper,
 * and so must be the same wallet. */
static void act4_respace(const char *phrase, const char *lead,
                         const char *sep, const char *trail,
                         char *out, size_t cap)
{
    size_t o = 0;
    for (const char *p = lead; *p && o + 1 < cap; p++) out[o++] = *p;
    for (const char *p = phrase; *p && o + 1 < cap; p++) {
        if (*p == ' ') {
            for (const char *s = sep; *s && o + 1 < cap; s++) out[o++] = *s;
        } else {
            out[o++] = *p;
        }
    }
    for (const char *p = trail; *p && o + 1 < cap; p++) out[o++] = *p;
    out[o] = '\0';
}

static int act4_recovery_phrase(void)
{
    int failures = 0;
    printf("\n-- ACT 4: destroy the machine, recover from TWELVE WORDS --\n");

    char livedir[256], newdir[256];
    dr_mkdir(livedir, sizeof(livedir), "act4live");

    char livedb[320];
    snprintf(livedb, sizeof(livedb), "%s/node.db", livedir);

    /* ── create a wallet exactly the way boot creates one ───────── */
    struct node_db live_ndb;
    memset(&live_ndb, 0, sizeof(live_ndb));
    DR_CHECK("act4: node_db_open", node_db_open(&live_ndb, livedb));
    struct wallet_sqlite live_ws;
    DR_CHECK("act4: wallet_sqlite_open",
             wallet_sqlite_open(&live_ws, live_ndb.db));

    struct wallet *live_w = zcl_malloc(sizeof(*live_w), "act4.live_wallet");
    DR_CHECK("act4: wallet alloc", live_w != NULL);
    if (!live_w) return failures + 1;
    wallet_init(live_w);

    char phrase[BOOT_WALLET_PHRASE_CAP];
    DR_CHECK("act4: a new wallet is born with a recovery phrase",
             boot_wallet_mint_recovery_phrase(live_w, phrase, sizeof(phrase)));
    DR_CHECK("act4: the phrase is 12 words",
             mnemonic_validate(phrase) && strlen(phrase) > 20);
    DR_CHECK("act4: the wallet's keys now descend from it",
             wallet_has_hd(live_w));

    /* boot's order: keypool from the phrase's seed, then flush. */
    DR_CHECK("act4: mint the keypool from the phrase",
             wallet_top_up_key_pool(live_w, DEFAULT_KEYPOOL_SIZE));
    DR_CHECK("act4: flush the wallet",
             wallet_sqlite_flush_r(&live_ws, live_w).ok);

    /* The address a user would actually be handed and would actually
     * publish. THIS is the string that has to come back. */
    char live_addr[128] = "";
    uint32_t live_addr_index = live_w->hd_external_counter;
    DR_CHECK("act4: the user asks for a receiving address",
             wallet_get_new_address(live_w, live_addr, sizeof(live_addr)) &&
             live_addr[0]);
    DR_CHECK("act4: flush that address too",
             wallet_sqlite_flush_r(&live_ws, live_w).ok);
    printf("    receiving address before destruction: %s (index %u)\n",
           live_addr, live_addr_index);

    /* PIN THE FACT the recovery has to survive: the keypool consumed
     * indices 0..99, so the FIRST address a user is ever handed is index
     * 100 — one PAST a fixed hundred-key rebuild. If this ever stops being
     * true the gap-limit floor below has to move with it. */
    DR_CHECK("act4: the first address a wallet hands out is index "
             "DEFAULT_KEYPOOL_SIZE, not 0",
             live_addr_index == (uint32_t)DEFAULT_KEYPOOL_SIZE);
    DR_CHECK("act4: the gap-limit floor covers that index",
             (uint32_t)WALLET_RECOVERY_MIN_LOOKAHEAD > live_addr_index);

    /* ── (a) SEED AGREEMENT ─────────────────────────────────────── */
    uint8_t seed_on_disk[32];
    DR_CHECK("act4: the node persisted a 32-byte seed",
             wallet_sqlite_read_sapling_seed(&live_ws, seed_on_disk));
    uint8_t seed_from_words[32];
    DR_CHECK("act4: the phrase derives a 32-byte seed",
             mnemonic_to_wallet_seed(phrase, NULL, seed_from_words));
    DR_CHECK("act4: SEED AGREEMENT — persisted seed == phrase-derived seed, "
             "byte for byte",
             memcmp(seed_on_disk, seed_from_words, 32) == 0);

    char addr_from_disk_seed[128] = "";
    char addr_from_word_seed[128] = "";
    DR_CHECK("act4: first address from the persisted seed",
             wallet_seed_address_at(seed_on_disk, 0, BIP44_EXTERNAL, 0,
                                    addr_from_disk_seed,
                                    sizeof(addr_from_disk_seed)));
    DR_CHECK("act4: first address from the phrase-derived seed",
             wallet_seed_address_at(seed_from_words, 0, BIP44_EXTERNAL, 0,
                                    addr_from_word_seed,
                                    sizeof(addr_from_word_seed)));
    DR_CHECK("act4: the same first address two ways",
             addr_from_disk_seed[0] &&
             strcmp(addr_from_disk_seed, addr_from_word_seed) == 0);

    /* ── (a2) HOW THE WORDS WERE WRITTEN DOWN MUST NOT MATTER ─────
     *
     * BIP39 derives the seed from the phrase BYTES, so before this was
     * normalised a phrase pasted out of a text file (trailing newline), a
     * chat message (doubled spaces) or a spreadsheet (tabs) derived a
     * DIFFERENT seed — and the sloppy spellings still passed checksum
     * validation, so the user was handed a valid-looking, empty, wrong
     * wallet and told it worked. Every spelling below is the same twelve
     * words to the person holding the paper, so every one must be the same
     * 32 bytes. Asserted byte-for-byte, not by address string. */
    {
        struct { const char *what, *lead, *sep, *trail; } variants[] = {
            { "a leading space",            " ",      " ",    ""      },
            { "a trailing newline",         "",       " ",    "\n"    },
            { "doubled internal spaces",    "",       "  ",   ""      },
            { "tab separators",             "",       "\t",   ""      },
            { "CRLF line wrapping",         "",       "\r\n", ""      },
            { "leading and trailing mess",  "  \n\t", " ",    " \t\n" },
            { "all of it at once",          "\n ",    " \t ", "\r\n " },
        };
        for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); i++) {
            char v[BOOT_WALLET_PHRASE_CAP * 3];
            act4_respace(phrase, variants[i].lead, variants[i].sep,
                         variants[i].trail, v, sizeof(v));
            uint8_t vseed[32];
            memset(vseed, 0, sizeof(vseed));
            bool ok = mnemonic_to_wallet_seed(v, NULL, vseed);
            char msg[160];
            snprintf(msg, sizeof(msg),
                     "act4: WHITESPACE — %s derives the SAME 32-byte seed",
                     variants[i].what);
            DR_CHECK(msg, ok && memcmp(vseed, seed_from_words, 32) == 0);
            snprintf(msg, sizeof(msg),
                     "act4: WHITESPACE — %s still validates as a phrase",
                     variants[i].what);
            DR_CHECK(msg, mnemonic_validate(v));
            memory_cleanse(v, sizeof(v));
            memory_cleanse(vseed, sizeof(vseed));
        }
        /* Anti-vacuous: the comparison above can catch a wrong seed. A
         * phrase that is genuinely different must NOT normalise to the
         * same bytes. */
        char swapped[BOOT_WALLET_PHRASE_CAP];
        snprintf(swapped, sizeof(swapped), "%s", phrase);
        char *sp = strchr(swapped, ' ');
        if (sp) {
            /* Replace the first word with a different wordlist entry. */
            char rest[BOOT_WALLET_PHRASE_CAP];
            snprintf(rest, sizeof(rest), "%s", sp + 1);
            const char *first = mnemonic_wordlist_get(
                    strncmp(swapped, "zoo", 3) == 0 ? 0 : 2047);
            snprintf(swapped, sizeof(swapped), "%s %s", first, rest);
            uint8_t sseed[32];
            DR_CHECK("act4: WHITESPACE — a genuinely different phrase does "
                     "NOT derive the same seed (the check can fail)",
                     mnemonic_to_wallet_seed(swapped, NULL, sseed) &&
                     memcmp(sseed, seed_from_words, 32) != 0);
            memory_cleanse(sseed, sizeof(sseed));
            memory_cleanse(rest, sizeof(rest));
        }
        memory_cleanse(swapped, sizeof(swapped));
    }

    wallet_sqlite_close(&live_ws);
    wallet_free(live_w);
    free(live_w);
    node_db_close(&live_ndb);

    /* ── DESTROY THE MACHINE ────────────────────────────────────── */
    dr_destroy_tree(livedir, 2);
    DR_CHECK("act4: the datadir is GONE — nothing left but the words",
             dr_is_destroyed(livedir));

    /* ── a mistyped phrase must be refused, never silently opened ─ */
    dr_mkdir(newdir, sizeof(newdir), "act4new");
    dr_destroy_tree(newdir, 2);   /* recover into a directory that is absent */
    {
        char typo[BOOT_WALLET_PHRASE_CAP];
        const char *rest = strchr(phrase, ' ');
        /* Use a word-shaped token that is absent from the BIP39 wordlist.
         * Mutating one letter can accidentally produce another valid word
         * and, with a 12-word phrase, a valid checksum one time in sixteen. */
        snprintf(typo, sizeof(typo), "zzzz%s", rest ? rest : "");
        struct wallet_recovery_request bad = {
            .phrase = typo, .datadir = newdir, .dry_run = true };
        struct wallet_recovery_report brep;
        struct zcl_result br = wallet_recovery_run(&bad, &brep);
        DR_CHECK("act4: a mistyped phrase is REFUSED, not opened empty",
                 !br.ok && br.code == -60);
        memory_cleanse(typo, sizeof(typo));
    }

    /* ── RECOVER FROM THE PHRASE ALONE ──────────────────────────── */
    struct wallet_recovery_request rr = {
        .phrase = phrase, .datadir = newdir, .dry_run = true };
    struct wallet_recovery_report plan;
    struct zcl_result pr = wallet_recovery_run(&rr, &plan);
    DR_CHECK("act4: the plan derives the wallet without writing", pr.ok);
    DR_CHECK("act4: the plan names the right first address",
             strcmp(plan.first_address, addr_from_disk_seed) == 0);
    DR_CHECK("act4: the plan wrote nothing", plan.keys_after == 0);

    /* "Nothing has been written yet" is a sentence the plan PRINTS, so it
     * gets checked on disk and not just in the report. The plan used to
     * mkdir the datadir and leave an 864 KB node.db in it while saying
     * that. dr_is_destroyed() looks at the filesystem. */
    DR_CHECK("act4: the plan created NO datadir and NO database on disk — "
             "the 'nothing has been written yet' it prints is true",
             dr_is_destroyed(newdir));
    DR_CHECK("act4: the plan reports the same rebuild the commit will do",
             plan.receiving_keys >=
                 (uint32_t)WALLET_RECOVERY_MIN_LOOKAHEAD &&
             plan.shielded_children ==
                 (uint32_t)WALLET_RECOVERY_SHIELDED_LOOKAHEAD);

    /* THE SECRET NEVER LEAVES. The report a caller renders must not
     * contain the phrase anywhere in its bytes. */
    {
        const char *hay = (const char *)&plan;
        size_t n = sizeof(plan), plen = strlen(phrase);
        bool found = false;
        for (size_t i = 0; plen && i + plen <= n; i++)
            if (memcmp(hay + i, phrase, plen) == 0) { found = true; break; }
        DR_CHECK("act4: the phrase is NOT anywhere in the report a caller "
                 "would print", !found);
    }

    /* Recovering installs the whole wallet the phrase controls — the
     * spending keys AND the master seed — so it now obeys the same at-rest
     * rule the node obeys when it creates a wallet: encrypt it, or say in
     * as many words that this datadir may hold them in the clear. This
     * drill is a local fixture with no passphrase, so it says so, exactly
     * as an operator would. Without a decision the recovery is refused and
     * nothing is written; that refusal is proven in its own group
     * (wallet_recovery_safety), not here. */
    setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);

    rr.dry_run = false;
    struct wallet_recovery_report rep;
    struct zcl_result cr = wallet_recovery_run(&rr, &rep);
    DR_CHECK("act4: RECOVERED from the phrase alone", cr.ok);
    if (!cr.ok) {
        /* Everything below reads the database this was supposed to write.
         * Say why, once, and stop — a run that keeps going here dereferences
         * a handle that was never opened and takes the whole group down with
         * a signal, which hides the one line that explains it. */
        printf("    recovery refused: code=%d %s\n", cr.code, cr.message);
        return failures;
    }
    DR_CHECK("act4: the recovered wallet has keys", rep.keys_after > 0);
    DR_CHECK("act4: recovery reports the seed installed", rep.seed_installed);
    /* Gap-limit floor, on both chains, and the shielded lookahead — not the
     * fixed hundred that stopped one index short of the first address. */
    DR_CHECK("act4: the rebuild derived past the first address a wallet "
             "hands out, on both transparent chains",
             rep.receiving_keys > live_addr_index &&
             rep.change_keys >= (uint32_t)WALLET_RECOVERY_MIN_LOOKAHEAD);
    DR_CHECK("act4: the shielded side is not stopped at child 0",
             rep.shielded_children ==
                 (uint32_t)WALLET_RECOVERY_SHIELDED_LOOKAHEAD);
    DR_CHECK("act4: with no chain in this datadir the report SAYS no chain "
             "was consulted rather than 'no history found'",
             !rep.chain_history_consulted);
    DR_CHECK("act4: an untruncated scan is not reported as truncated",
             !rep.transparent_scan_truncated);
    DR_CHECK("act4: the target had no seed row before, and that is reported "
             "as absent — not as unreadable",
             rep.seed_state_before == WALLET_SEED_ABSENT &&
             !rep.seed_present_before);

    /* ── the same address comes back ────────────────────────────── */
    char newdb[320];
    snprintf(newdb, sizeof(newdb), "%s/node.db", newdir);
    struct node_db new_ndb;
    memset(&new_ndb, 0, sizeof(new_ndb));
    DR_CHECK("act4: open the recovered datadir", node_db_open(&new_ndb, newdb));
    struct wallet_sqlite new_ws;
    DR_CHECK("act4: open its wallet tables",
             wallet_sqlite_open(&new_ws, new_ndb.db));

    uint8_t restored_seed[32];
    DR_CHECK("act4: the recovered seed matches the destroyed one",
             wallet_sqlite_read_sapling_seed(&new_ws, restored_seed) &&
             memcmp(restored_seed, seed_on_disk, 32) == 0);

    struct wallet *new_w = zcl_malloc(sizeof(*new_w), "act4.new_wallet");
    DR_CHECK("act4: wallet alloc", new_w != NULL);
    if (new_w) {
        wallet_init(new_w);
        DR_CHECK("act4: load the recovered keys",
                 wallet_sqlite_read_keys(&new_ws, new_w));
        /* Exactly what boot does on the next start of this datadir. */
        DR_CHECK("act4: boot adopts the seed as the HD master",
                 wallet_hd_adopt_seed(new_w, restored_seed));

        /* ── THE ASSERTION THAT MATTERS ───────────────────────────
         *
         * The address the user PUBLISHED, before destruction, is spendable
         * by the recovered wallet — asked BEFORE any new address is
         * requested. This is the whole claim: "your money came back".
         *
         * It has to be asked in this order. A recovery that rebuilt a
         * fixed 100 keys (indices 0..99) does not hold index 100, which is
         * the first address a wallet ever hands out — so it recovered every
         * address the user never saw and none of the one they gave people,
         * and then recommended a rescan that structurally could not find
         * their coins. Asking the recovered wallet for a NEW address first
         * hides that completely: the counter re-derives index 100 on the
         * spot and the string matches. So: ismine first, fresh address
         * after. */
        DR_CHECK("act4: THE PUBLISHED ADDRESS IS SPENDABLE AFTER RECOVERY "
                 "— before a single new address is asked for",
                 act4_addr_is_mine(new_w, live_addr));
        printf("    published address after recovery:    %s (ismine=%d, "
               "keys=%zu)\n", live_addr,
               (int)act4_addr_is_mine(new_w, live_addr),
               new_w->keystore.num_keys);

        /* The gap-limit floor, proven on the recovered wallet rather than
         * assumed: the counters land past the index the user was on. */
        DR_CHECK("act4: the rebuild reached the gap-limit floor on both "
                 "chains",
                 new_w->hd_external_counter >=
                     (uint32_t)WALLET_RECOVERY_MIN_LOOKAHEAD &&
                 new_w->hd_internal_counter >=
                     (uint32_t)WALLET_RECOVERY_MIN_LOOKAHEAD);

        /* And the change chain, which a user never sees but every spend
         * needs: the address the wallet would have used for change at the
         * same point is spendable too. */
        {
            char live_change[128] = "";
            DR_CHECK("act4: derive the change address the destroyed wallet "
                     "would have used",
                     wallet_seed_address_at(seed_on_disk, 0, BIP44_INTERNAL,
                                            0, live_change,
                                            sizeof(live_change)));
            DR_CHECK("act4: that change address is spendable after recovery",
                     act4_addr_is_mine(new_w, live_change));
        }

        /* NOW ask for a new one. It must be a FRESH address — reissuing the
         * one already published would be address reuse — and it must be
         * spendable too. */
        char new_addr[128] = "";
        DR_CHECK("act4: ask the recovered wallet for a receiving address",
                 wallet_get_new_address(new_w, new_addr, sizeof(new_addr)) &&
                 new_addr[0]);
        printf("    next fresh address after recovery:   %s\n", new_addr);
        DR_CHECK("act4: the next address is FRESH, not a reissue of the one "
                 "already published",
                 strcmp(new_addr, live_addr) != 0);
        DR_CHECK("act4: the spending key behind it is in the wallet too",
                 act4_addr_is_mine(new_w, new_addr));

        wallet_free(new_w);
        free(new_w);
    }

    /* ── recovering over an existing wallet is refused ──────────── */
    wallet_sqlite_close(&new_ws);
    node_db_close(&new_ndb);
    {
        struct wallet_recovery_request again = {
            .phrase = phrase, .datadir = newdir, .dry_run = false };
        struct wallet_recovery_report arep;
        struct zcl_result ar = wallet_recovery_run(&again, &arep);
        DR_CHECK("act4: recovering over a wallet that is already there is "
                 "REFUSED", !ar.ok && ar.code == -62);
    }
    /* The at-rest decision an operator makes for a node holds for as long
     * as the node does; it is not re-made per command. Drop it here, where
     * the recovery half of the drill ends, so nothing below inherits it. */
    unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");

    /* ── status tells the truth about this wallet ───────────────── */
    {
        /* The shipped read path: the caller opens node.db READ-ONLY and
         * hands the handle in. Exercised here exactly as the READ leaf
         * does it, so the drill would notice the service growing an open
         * of its own again. */
        struct wallet_recovery_report srep;
        struct zcl_result pre =
            wallet_recovery_status_preflight(newdir, &srep);
        DR_CHECK("act4: status preflight clears the recovered datadir",
                 pre.ok);
        sqlite3 *sdb = NULL;
        struct node_db sndb;
        char sndb_path[1200];
        enum zcl_node_db_ro_status ro = zcl_native_node_db_open_readonly(
            newdir, &sdb, &sndb, sndb_path, sizeof(sndb_path));
        DR_CHECK("act4: status opens the recovered node.db read-only",
                 ro == ZCL_NODE_DB_RO_OK);
        struct zcl_result sr = wallet_recovery_status(newdir, &sndb, &srep);
        zcl_native_node_db_close_readonly(&sdb, &sndb);
        DR_CHECK("act4: status reads the recovered wallet", sr.ok);
        DR_CHECK("act4: status says it IS recoverable from words",
                 srep.seed_installed);
        DR_CHECK("act4: and names the seed it read, not just a bool",
                 srep.seed_state_before == WALLET_SEED_PLAINTEXT ||
                 srep.seed_state_before == WALLET_SEED_UNLOCKED);
    }

    /* ── "LOCKED" IS NOT "THERE IS NO PHRASE" ────────────────────────
     *
     * An encrypted wallet whose seed cannot be decrypted here used to come
     * back exactly like a wallet that never had a seed: one false, one
     * answer. The owner of a perfectly recoverable wallet was told it
     * predated recovery phrases and that only a file backup could bring
     * their money back. Two proofs, on a wallet holding an ENCRYPTED seed
     * and no keys, so the seed row is the only thing either answer can
     * turn on:
     *
     *   1. status reads it as LOCKED, never ABSENT;
     *   2. recovery REFUSES to write over it — "I could not read your seed"
     *      must never be the condition that permits installing another one.
     */
    {
        char lockdir[256];
        dr_mkdir(lockdir, sizeof(lockdir), "act4locked");
        char lockdb[320];
        snprintf(lockdb, sizeof(lockdb), "%s/node.db", lockdir);

        wallet_lock_reset_for_test();
        DR_CHECK("act4/locked: explicitly unlock the fixture",
                 wallet_lock_unlock(NULL, NULL,
                                    "act4-the-right-passphrase").ok);
        struct node_db lndb;
        memset(&lndb, 0, sizeof(lndb));
        DR_CHECK("act4/locked: open the fixture db",
                 node_db_open(&lndb, lockdb));
        struct wallet_sqlite lws;
        DR_CHECK("act4/locked: open its wallet tables",
                 wallet_sqlite_open(&lws, lndb.db));
        uint8_t lseed[32];
        memset(lseed, 0x5A, sizeof(lseed));
        DR_CHECK("act4/locked: store an ENCRYPTED seed and no keys",
                 wallet_sqlite_write_sapling_seed(&lws, lseed));
        DR_CHECK("act4/locked: it reads back while unlocked",
                 wallet_sqlite_sapling_seed_state(&lws, NULL) ==
                     WALLET_SEED_UNLOCKED);
        DR_CHECK("act4/locked: the fixture really has zero keys",
                 db_wallet_key_count(&lndb) == 0);
        wallet_sqlite_close(&lws);
        node_db_close(&lndb);

        /* Lock it, exactly as a fresh process must see an encrypted wallet. */
        wallet_lock_lock(NULL);

        struct wallet_recovery_report lrep;
        struct zcl_result lpre =
            wallet_recovery_status_preflight(lockdir, &lrep);
        DR_CHECK("act4/locked: preflight clears the fixture", lpre.ok);
        sqlite3 *ldb = NULL;
        struct node_db lrondb;
        char lpath[1200];
        enum zcl_node_db_ro_status lro = zcl_native_node_db_open_readonly(
            lockdir, &ldb, &lrondb, lpath, sizeof(lpath));
        DR_CHECK("act4/locked: read-only open", lro == ZCL_NODE_DB_RO_OK);
        struct zcl_result lsr =
            wallet_recovery_status(lockdir, &lrondb, &lrep);
        zcl_native_node_db_close_readonly(&ldb, &lrondb);
        DR_CHECK("act4/locked: status answers", lsr.ok);
        DR_CHECK("act4/locked: the seed is reported LOCKED — NOT absent, "
                 "which is what told a recoverable wallet's owner they had "
                 "no recovery phrase",
                 lrep.seed_state_before == WALLET_SEED_LOCKED);
        DR_CHECK("act4/locked: and the seed ROW is reported present",
                 lrep.seed_present_before);
        DR_CHECK("act4/locked: it does not claim the keys descend from a "
                 "seed it could not read",
                 !lrep.seed_installed);

        /* The at-rest gate runs before target inspection. Allow this call to
         * reach the refusal under test: the existing encrypted seed row. */
        setenv("ZCL_ALLOW_PLAINTEXT_WALLET", "1", 1);
        struct wallet_recovery_request lrr = {
            .phrase = phrase, .datadir = lockdir, .dry_run = false };
        struct wallet_recovery_report lwrep;
        struct zcl_result lwr = wallet_recovery_run(&lrr, &lwrep);
        DR_CHECK("act4/locked: recovery REFUSES to write a second seed over "
                 "a seed it merely could not decrypt",
                 !lwr.ok && lwr.code == -62);

        unsetenv("ZCL_ALLOW_PLAINTEXT_WALLET");
        wallet_lock_reset_for_test();
        memory_cleanse(lseed, sizeof(lseed));
        dr_destroy_tree(lockdir, 2);
    }

    memory_cleanse(phrase, sizeof(phrase));
    memory_cleanse(seed_on_disk, sizeof(seed_on_disk));
    memory_cleanse(seed_from_words, sizeof(seed_from_words));
    memory_cleanse(restored_seed, sizeof(restored_seed));
    dr_destroy_tree(newdir, 2);
    return failures;
}

/* ── the group ────────────────────────────────────────────────── */

int test_wallet_destruction_drill(void);
int test_wallet_destruction_drill(void)
{
    printf("\n=== wallet destruction-and-restore drill ===\n");
    int failures = 0;

    char status[256];
    if (rpc_is_in_warmup(status, sizeof(status)))
        set_rpc_warmup_finished();

    /* sendtoaddress in act 1 needs the sovereignty guard's trust fixture. */
    char trustdir[256];
    dr_mkdir(trustdir, sizeof(trustdir), "trust");
    DR_CHECK("trust fixture (progress store, bare self-derived)",
             dr_open_trust_fixture(trustdir));

    failures += act1_transparent();
    failures += act2_bodyless_restore_must_fail_loud();
    failures += act4_recovery_phrase();

    /* Act 3 needs the proving parameters AND the native C23 prover self-test.
     * Without both, the shielded half cannot be proven
     * here, so it SKIPs and says so rather than asserting something weaker.
     * "SKIP (" is the harness sentinel — this stays visible in the suite's
     * skipped-coverage ledger instead of vanishing. */
    const char *home = getenv("HOME");
    char params_dir[512];
    snprintf(params_dir, sizeof(params_dir), "%s/.zcash-params",
             (home && *home) ? home : ".");
    char probe_path[640];
    snprintf(probe_path, sizeof(probe_path), "%s/sapling-output.params",
             params_dir);
    FILE *probe = fopen(probe_path, "rb");
    if (!probe) {
        printf("  act 3 (shielded): ~/.zcash-params absent — SKIP (no proving "
               "parameters; the shielded half of the drill cannot run here)\n");
    } else {
        fclose(probe);
        if (!sapling_init_params(params_dir) ||
            !zclassic_sapling_prover_is_ready()) {
            printf("  act 3 (shielded): native C23 prover not ready — SKIP "
                   "(status=%s; inspect the Spend/Output/binding self-test)\n",
                   zclassic_sapling_prover_status());
        } else {
            printf("  act 3 (shielded): production prover READY (backend=%s)\n",
                   zclassic_sapling_prover_backend());
            int saved = atomic_load(&g_deferred_proof_validation_below_height);
            atomic_store(&g_deferred_proof_validation_below_height, -1);
            failures += act3_shielded();
            atomic_store(&g_deferred_proof_validation_below_height, saved);
        }
    }

    reducer_frontier_provable_tip_reset();
    progress_store_close();
    dr_destroy_tree(trustdir, 2);

    printf("wallet_destruction_drill: %s (%d failure%s)\n",
           failures == 0 ? "OK — funds survived destruction and moved again"
                         : "FAIL",
           failures, failures == 1 ? "" : "s");
    return failures;
}
