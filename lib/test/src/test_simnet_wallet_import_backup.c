/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Lane W1-b: key import/export + backup/restore E2E.
 *
 * Part 1 — dumpprivkey/importprivkey/rescan/spend round trip:
 *   1. On a deterministic simnet chain, mint a REAL connect_block-validated
 *      transfer to a transparent address A that wallet1 generated via the
 *      production `getnewaddress` RPC.
 *   2. dumpprivkey(A) on wallet1; assert the WIF round-trips
 *      (decode -> re-encode -> byte-identical string).
 *   3. Create a FRESH wallet2 (its own node.db, its own empty keystore).
 *      Bridge the exact same validated funding fact into wallet2's own
 *      node.db (the canonical `utxos` table) and a synthetic on-disk block
 *      file — the model-layer bridge this codebase's tests use everywhere
 *      a full production reducer pipeline is out of scope (see
 *      test_wallet_funds_safety.c, test_accept_to_mempool.c).
 *   4. importprivkey(WIF) into wallet2 (the production RPC — instant
 *      SQL balance index) then rescan via the REAL `wallet_rescan()`
 *      (the exact function `rescanblockchain` drives), which reads the
 *      synthetic block back off disk and folds it into wallet2's
 *      in-memory transaction map — the step that makes the coin
 *      SPENDABLE, not just visible in getbalance.
 *   5. Assert wallet2's getbalance sees A's funds, then build + broadcast
 *      (sendtoaddress, a real ECDSA signature from the imported key,
 *      real mempool admission) and mine (apply the confirmed tx to the
 *      coins view) a spend of the imported coin; assert the original
 *      coin is gone and the recipient received the funds.
 *
 * Part 2 — wallet_backup_service backup/restore:
 *   A funded wallet's plain SQLite backup, then a ChaCha20-Poly1305
 *   encrypted backup (`wallet_backup_encrypt_file`), decrypted and
 *   restored into a fresh datadir; keys + balance survive; a wrong
 *   passphrase fails closed and leaves no partial file.
 */

#include "test/test_core.h"
#include "base/safe_alloc.h"
#include "support/pagelocker.h"
#include "keys/key_io.h"

#include "sim/simnet.h"

#include "controllers/wallet_controller.h"
#include "controllers/wallet_helpers.h"

#include "models/database.h"
#include "models/utxo.h"
#include "models/wallet_tx.h"

#include "wallet/wallet.h"
#include "wallet/wallet_lock.h"
#include "wallet/wallet_sqlite.h"

#include "services/wallet_backup_service.h"
#include "services/wallet_restore_service.h"

#include "storage/disk_block_io.h"
#include "validation/main_state.h"
#include "validation/main_constants.h"
#include "validation/txmempool.h"
#include "coins/coins_view.h"
#include "coins/coins.h"

#include "json/json.h"
#include "rpc/server.h"
#include "jobs/reducer_frontier.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"

#include <sqlite3.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define IB_CHECK(name, expr) do {              \
    printf("  %s... ", (name));                \
    if (expr) printf("OK\n");                  \
    else { printf("FAIL\n"); failures++; }      \
} while (0)

/* ── Shared helpers ──────────────────────────────────────────────── */

struct ib_key {
    struct privkey priv;
    struct pubkey pub;
    struct key_id kid;
    struct script spk;
};

static void ib_make_key(struct ib_key *k)
{
    memset(k, 0, sizeof(*k));
    privkey_make_new(&k->priv, true);
    privkey_get_pubkey(&k->priv, &k->pub);
    k->kid = pubkey_get_id(&k->pub);
    script_for_p2pkh(&k->spk, &k->kid);
}

static bool ib_wif_encode(const struct privkey *k, char *out, size_t outlen)
{
    const struct chain_params *cp = chain_params_get();
    size_t pfxlen = 0;
    const unsigned char *pfx =
        chain_params_base58_prefix(cp, B58_SECRET_KEY, &pfxlen);
    return encode_secret(k, pfx, pfxlen, out, outlen);
}

static bool ib_wif_decode(const char *wif, struct privkey *out)
{
    const struct chain_params *cp = chain_params_get();
    size_t pfxlen = 0;
    const unsigned char *pfx =
        chain_params_base58_prefix(cp, B58_SECRET_KEY, &pfxlen);
    return decode_secret(wif, pfx, pfxlen, out);
}

static void ib_make_dir(char *dir, size_t dirlen, const char *tag)
{
    char rel[192];
    mkdir("./test-tmp", 0755);
    snprintf(rel, sizeof(rel), "./test-tmp/ibck_%d_%s", (int)getpid(), tag);
    /* wbs_ensure_backup_dir resolves its destination through the
     * absolute-only platform_private seam — hand every dir this fixture
     * mints to callers in absolute form. */
    test_abs_path(rel, dir, dirlen);
    /* platform_private_directory_ensure requires exactly 0700 on any dir
     * it is handed to validate (EACCES otherwise) — mint them private. */
    mkdir(dir, 0700);
    chmod(dir, 0700);
}

/* A datadir that also needs a blocks/ subdir for write_block_to_disk. */
static void ib_make_datadir(char *dir, size_t dirlen, const char *tag)
{
    ib_make_dir(dir, dirlen, tag);
    char blocks[384];
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    mkdir(blocks, 0755); /* raw-alloc-ok:test-fixture */
}

/* Trust fixture for the sendtoaddress sovereignty guard
 * (sovereignty_guard_allow fails closed when the progress store is
 * absent): give this test process the same bare/self-derived fixture as
 * test_sovereignty_guard.c — one coin at h=50, applied=51, H* pinned to
 * 50. Bare (no migration stamp) grants wallet_spend, which is the state
 * every pre-guard run of this test implicitly spent under. */
static bool ib_open_trust_fixture(const char *dir)
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
    unsigned char sc[4] = {0xE0, 0xE0, 0xE0, 0xE0};
    if (!coins_kv_add(db, t1.data, 0, 1234, 50, true, sc, sizeof(sc)))
        return false;
    char *err = NULL;
    bool ok = sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, &err) == SQLITE_OK
              && coins_kv_set_applied_height_in_tx(db, 51)
              && sqlite3_exec(db, "COMMIT", NULL, NULL, &err) == SQLITE_OK;
    if (err) sqlite3_free(err);
    return ok;
}

/* Build a deterministic 1-in/1-out transparent spend tx. Called twice with
 * identical inputs (once to feed simnet's real connect_block, once to write
 * to a synthetic on-disk block) produces byte-identical transactions —
 * same final txid both times, no randomness involved. Script-sig is a
 * placeholder (matches sim/simnet_wallet.c's own convention): the funding
 * input is spent from a throwaway faucet key, not address A, so nothing
 * this test asserts depends on that signature being real. */
static bool ib_build_fund_tx(struct transaction *tx,
                             const struct uint256 *prev_txid,
                             uint32_t prev_n,
                             const struct script *to_script,
                             int64_t value)
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

/* ── Minimal RPC param builders (mirrors test_rpc_safety.c's idiom) ── */

static void ib_params_none(struct json_value *p)
{
    json_init(p);
    json_set_array(p);
}

static void ib_params_1str(struct json_value *p, const char *s)
{
    json_init(p);
    json_set_array(p);
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s);
    json_push_back(p, &v);
    json_free(&v);
}

static void ib_params_str_str(struct json_value *p, const char *a,
                              const char *b)
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

/* ── Part 1 ──────────────────────────────────────────────────────── */

static void ib_ensure_rpc_warmup_finished(void)
{
    char status[256];
    if (rpc_is_in_warmup(status, sizeof(status)))
        set_rpc_warmup_finished();
}

static __attribute__((noinline)) int part1_import_rescan_spend(void)
{
    int failures = 0;
    printf("\n-- Part 1: dumpprivkey / importprivkey / rescan / spend --\n");
    ib_ensure_rpc_warmup_finished();

    const int64_t FAUCET_AMOUNT = COIN_VALUE + 10000;
    const int64_t FUND_VALUE    = COIN_VALUE;
    const int64_t SEND_FEE      = WALLET_DEFAULT_FEE_ZAT;

    /* ── wallet1: generate address A via the real getnewaddress RPC ── */
    char datadir1[256];
    ib_make_dir(datadir1, sizeof(datadir1), "w1");
    char dbpath1[320];
    snprintf(dbpath1, sizeof(dbpath1), "%s/node.db", datadir1);
    struct node_db ndb1;
    memset(&ndb1, 0, sizeof(ndb1));
    IB_CHECK("wallet1: node_db_open", node_db_open(&ndb1, dbpath1));

    struct wallet *w1 = zcl_malloc(sizeof(*w1), "wallet import source");
    struct wallet *w2 = zcl_malloc(sizeof(*w2), "wallet import target");
    IB_CHECK("wallet fixtures allocated", w1 != NULL && w2 != NULL);
    if (!w1 || !w2) {
        free(w1);
        free(w2);
        node_db_close(&ndb1);
        test_cleanup_tmpdir(datadir1);
        return failures;
    }
    wallet_init(w1);
    struct wallet_sqlite ws1;
    IB_CHECK("wallet1: wallet_sqlite_open", wallet_sqlite_open(&ws1, ndb1.db));

    rpc_wallet_set_state(w1, NULL, datadir1, &ws1, NULL, NULL);
    rpc_wallet_set_node_db(NULL);
    rpc_wallet_set_coins_tip(NULL);

    struct rpc_table wtbl1;
    rpc_table_init(&wtbl1);
    register_wallet_rpc_commands(&wtbl1);

    char addrA[128] = "";
    {
        struct json_value params, result;
        ib_params_none(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&wtbl1, "getnewaddress", &params, &result) &&
                  result.type == JSON_STR;
        if (ok) snprintf(addrA, sizeof(addrA), "%s", json_get_str(&result));
        json_free(&params);
        json_free(&result);
        IB_CHECK("wallet1: getnewaddress produced address A", ok && addrA[0]);
    }

    struct tx_destination destA;
    memset(&destA, 0, sizeof(destA));
    bool decoded_a = addrA[0] &&
        wallet_decode_address(addrA, &destA) && destA.type == DEST_KEY_ID;
    IB_CHECK("wallet1: address A decodes to a P2PKH destination", decoded_a);

    struct script scriptA;
    script_init(&scriptA);
    if (decoded_a)
        script_for_destination(&scriptA, &destA);

    char wifA[128] = "";
    {
        struct json_value params, result;
        ib_params_1str(&params, addrA);
        json_init(&result);
        bool ok = rpc_table_execute(&wtbl1, "dumpprivkey", &params, &result) &&
                  result.type == JSON_STR;
        if (ok) snprintf(wifA, sizeof(wifA), "%s", json_get_str(&result));
        json_free(&params);
        json_free(&result);
        IB_CHECK("wallet1: dumpprivkey(A) returns a WIF", ok && wifA[0]);
    }

    /* WIF round-trip: decode -> re-encode -> byte-identical string. */
    {
        struct privkey k2;
        bool dec_ok = wifA[0] && ib_wif_decode(wifA, &k2);
        char wif2[128] = "";
        bool enc_ok = dec_ok && ib_wif_encode(&k2, wif2, sizeof(wif2));
        IB_CHECK("wallet1: dumpprivkey WIF round-trips byte-for-byte",
                 dec_ok && enc_ok && strcmp(wifA, wif2) == 0);
        if (dec_ok)
            memory_cleanse(k2.vch, 32);
    }

    /* ── simnet: REAL connect_block-validated transfer to address A ── */
    /* The canonical runner executes groups on bounded worker stacks.  A
     * simnet owns large chain/coins fixtures and must not be an automatic
     * object (Darwin faults before the first test line otherwise). */
    struct simnet *s = zcl_malloc(sizeof(*s), "wallet import simnet");
    bool simnet_ready = s && simnet_init(s);
    IB_CHECK("simnet_init", simnet_ready);
    if (!simnet_ready) {
        free(s);
        wallet_free(w1);
        free(w1);
        free(w2);
        wallet_sqlite_close(&ws1);
        node_db_close(&ndb1);
        test_cleanup_tmpdir(datadir1);
        return failures;
    }

    struct ib_key faucet;
    ib_make_key(&faucet);

    struct uint256 cb_txid;
    int cb_height = simnet_tip_height(s) + 1;
    IB_CHECK("mint faucet coinbase",
             simnet_mint_coinbase_to(s, &faucet.spk, FAUCET_AMOUNT, &cb_txid));
    IB_CHECK("mature faucet coinbase",
             simnet_mint_to_height(s, cb_height + COINBASE_MATURITY));

    struct uint256 txid_A;
    uint256_set_null(&txid_A);
    int fund_height = simnet_tip_height(s) + 1;
    struct transaction fund_for_mint;
    bool built_mint = decoded_a &&
        ib_build_fund_tx(&fund_for_mint, &cb_txid, 0, &scriptA, FUND_VALUE);
    if (built_mint)
        txid_A = fund_for_mint.hash;
    IB_CHECK("build fund tx (A's transfer, for real mint)", built_mint);
    IB_CHECK("mint fund tx (REAL connect_block validation)",
             built_mint && simnet_mint_txs(s, &fund_for_mint, 1));

    /* A byte-identical second copy for the synthetic on-disk block below —
     * deterministic construction, same final txid both times. */
    struct transaction fund_for_disk;
    bool built_disk = built_mint &&
        ib_build_fund_tx(&fund_for_disk, &cb_txid, 0, &scriptA, FUND_VALUE);
    IB_CHECK("fund tx for disk is byte-identical (same txid)",
             built_disk && memcmp(fund_for_disk.hash.data, txid_A.data, 32) == 0);

    /* ── wallet2: a FRESH wallet, own node.db, empty keystore ── */
    char datadir2[256];
    ib_make_datadir(datadir2, sizeof(datadir2), "w2");
    char dbpath2[320];
    snprintf(dbpath2, sizeof(dbpath2), "%s/node.db", datadir2);
    struct node_db ndb2;
    memset(&ndb2, 0, sizeof(ndb2));
    IB_CHECK("wallet2: node_db_open (fresh datadir)",
             node_db_open(&ndb2, dbpath2));

    /* Bridge the validated fact into wallet2's own canonical utxos table —
     * the model-layer bridge this suite uses whenever the full reducer
     * pipeline (utxo_apply) is out of scope; see test_wallet_funds_safety.c. */
    struct db_utxo u;
    memset(&u, 0, sizeof(u));
    memcpy(u.txid, txid_A.data, 32);
    u.vout = 0;
    u.value = FUND_VALUE;
    u.script = scriptA.data;
    u.script_len = scriptA.size;
    u.script_type = SCRIPT_P2PKH;
    memcpy(u.address_hash, destA.id.key.id.data, 20);
    u.has_address = true;
    u.height = fund_height;
    u.is_coinbase = false;
    IB_CHECK("bridge A's UTXO into wallet2's node_db (utxos table)",
             decoded_a && db_utxo_save(&ndb2, &u));

    /* Write a synthetic on-disk block so the REAL wallet_rescan() (the
     * function rescanblockchain drives) can fold it in. phashBlock is left
     * NULL so read_block_from_disk_index_pread skips its optional hash
     * cross-check (see lib/storage/src/disk_block_io.c). */
    struct disk_block_pos pos;
    disk_block_pos_init(&pos);
    {
        struct block blk;
        block_init(&blk);
        blk.header.nVersion = 4;
        blk.header.nTime = 1700000000u;
        blk.header.nBits = 0x2000ffffu;
        blk.num_vtx = 1;
        blk.vtx = calloc(1, sizeof(*blk.vtx)); /* raw-alloc-ok:test-fixture */
        bool have_slot = blk.vtx != NULL;
        if (have_slot) {
            blk.vtx[0] = fund_for_disk;
            transaction_init(&fund_for_disk); /* ownership moved into blk */
        }
        unsigned char msg_start[4] = { 0x24, 0xe9, 0x27, 0x64 };
        bool wrote = built_disk && have_slot &&
            write_block_to_disk(&blk, &pos, datadir2, msg_start);
        block_free(&blk);
        IB_CHECK("write A's funding block to disk (wallet2 datadir)", wrote);
    }

    struct block_index bi;
    block_index_init(&bi);
    bi.nHeight = fund_height;
    bi.nFile = pos.nFile;
    bi.nDataPos = pos.nPos;
    bi.nStatus = BLOCK_HAVE_DATA;
    bi.phashBlock = NULL;

    wallet_init(w2);
    struct wallet_sqlite ws2;
    IB_CHECK("wallet2: wallet_sqlite_open", wallet_sqlite_open(&ws2, ndb2.db));

    struct main_state ms2;
    main_state_init(&ms2);
    struct block_index **chain_arr =
        calloc((size_t)(fund_height + 1), sizeof(*chain_arr)); /* raw-alloc-ok:test-fixture */
    IB_CHECK("alloc synthetic active_chain array", chain_arr != NULL);
    if (chain_arr) {
        chain_arr[fund_height] = &bi;
        free(ms2.chain_active.chain); /* active_chain_init leaves this NULL;
                                       * defensive in case that changes. */
        ms2.chain_active.chain = chain_arr;
        ms2.chain_active.height = fund_height;
        ms2.chain_active.capacity = fund_height + 1;
    }

    struct tx_mempool mempool2;
    tx_mempool_init(&mempool2, 0);

    struct coins_view null_view2;
    memset(&null_view2, 0, sizeof(null_view2));
    struct coins_view_cache coins2;
    coins_view_cache_init(&coins2, &null_view2);

    /* Stamp the same validated fact into a coins_view_cache so
     * accept_to_mempool's real input/script checks have something to
     * check against — the same construction test_accept_to_mempool.c uses. */
    struct coins_cache_entry *eA = coins_view_cache_modify_new(&coins2, &txid_A);
    IB_CHECK("stamp A's coin into wallet2's coins_view_cache", eA != NULL);
    if (eA) {
        coins_alloc(&eA->coins, 1);
        eA->coins.vout[0].value = FUND_VALUE;
        eA->coins.vout[0].script_pub_key = scriptA;
        eA->coins.height = fund_height;
        eA->coins.version = 1;
        eA->coins.is_coinbase = false;
    }

    rpc_wallet_set_state(w2, &ms2, datadir2, &ws2, &mempool2, NULL);
    rpc_wallet_set_node_db(&ndb2);
    rpc_wallet_set_coins_tip(&coins2);

    struct rpc_table wtbl2;
    rpc_table_init(&wtbl2);
    register_wallet_rpc_commands(&wtbl2);

    /* ── importprivkey: instant SQL balance visibility ── */
    {
        struct json_value params, result;
        ib_params_1str(&params, wifA);
        json_init(&result);
        bool ok = wifA[0] && rpc_table_execute(&wtbl2, "importprivkey",
                                               &params, &result);
        json_free(&params);
        json_free(&result);
        IB_CHECK("wallet2: importprivkey(WIF of A) succeeds", ok);
    }

    /* ── rescan: the REAL wallet_rescan() — folds the synthetic block
     * into wallet2's in-memory transaction map. Without this step the
     * coin is visible in getbalance but NOT selectable by
     * wallet_create_transaction (which reads only w->map_wallet). ── */
    int found = wallet_rescan(w2, &ms2.chain_active, fund_height,
                              fund_height, datadir2);
    IB_CHECK("wallet2: wallet_rescan finds A's funding output", found >= 1);

    /* ── getbalance sees A's funds ── */
    {
        struct json_value params, result;
        ib_params_none(&params);
        json_init(&result);
        bool ok = rpc_table_execute(&wtbl2, "getbalance", &params, &result) &&
                  result.type == JSON_STR;
        char bal[32]; format_amount(FUND_VALUE, bal, sizeof(bal));
        bool matches = ok && strcmp(json_get_str(&result), bal) == 0;
        json_free(&params);
        json_free(&result);
        IB_CHECK("wallet2: getbalance reports A's full balance", matches);
    }

    /* ── spend: build + broadcast (sendtoaddress, real ECDSA signature
     * from the imported key, real mempool admission) ── */
    struct ib_key recipient;
    ib_make_key(&recipient);
    char addrR[128] = "";
    {
        struct tx_destination destR;
        destR.type = DEST_KEY_ID;
        destR.id.key = recipient.kid;
        wallet_encode_destination(&destR, addrR, sizeof(addrR));
    }

    char sendtxid[80] = "";
    {
        int64_t send_amount = FUND_VALUE - SEND_FEE; /* exact spend, no change */
        char amtstr[32];
        format_amount(send_amount, amtstr, sizeof(amtstr));

        struct json_value params, result;
        ib_params_str_str(&params, addrR, amtstr);
        json_init(&result);
        bool ok = addrR[0] &&
            rpc_table_execute(&wtbl2, "sendtoaddress", &params, &result) &&
            result.type == JSON_STR;
        if (ok) snprintf(sendtxid, sizeof(sendtxid), "%s", json_get_str(&result));
        if (!ok && result.type == JSON_STR)
            fprintf(stderr, "sendtoaddress error: %s\n", json_get_str(&result));
        json_free(&params);
        json_free(&result);
        IB_CHECK("wallet2: sendtoaddress builds+signs+broadcasts the spend",
                 ok && sendtxid[0]);
    }

    /* ── mine: apply the confirmed spend to the coins view ── */
    bool mined = false;
    struct transaction sendtx;
    transaction_init(&sendtx);
    bool have_sendtx = false;
    if (sendtxid[0]) {
        struct uint256 send_hash;
        uint256_set_hex(&send_hash, sendtxid);
        have_sendtx = tx_mempool_lookup(&mempool2, &send_hash, &sendtx);
        IB_CHECK("wallet2: broadcast tx is present in the mempool", have_sendtx);
    }
    if (have_sendtx) {
        struct coins_cache_entry *espend =
            coins_view_cache_modify(&coins2, &txid_A);
        if (espend)
            coins_spend(&espend->coins, 0);
        struct coins_cache_entry *enew =
            coins_view_cache_modify_new(&coins2, &sendtx.hash);
        mined = espend != NULL && enew != NULL &&
                coins_from_transaction(&enew->coins, &sendtx, fund_height + 1);
    }
    IB_CHECK("mine: apply the confirmed spend to the coins view", mined);

    if (mined) {
        struct coins spent_check;
        coins_init(&spent_check);
        bool still_avail =
            coins_view_cache_get_coins(&coins2, &txid_A, &spent_check) &&
            coins_is_available(&spent_check, 0);
        coins_free(&spent_check);
        IB_CHECK("A's original coin is spent after mining", !still_avail);

        struct coins recv_check;
        coins_init(&recv_check);
        bool recv_ok =
            coins_view_cache_get_coins(&coins2, &sendtx.hash, &recv_check) &&
            coins_is_available(&recv_check, 0) &&
            recv_check.vout[0].value == FUND_VALUE - SEND_FEE &&
            recv_check.vout[0].script_pub_key.size == recipient.spk.size &&
            memcmp(recv_check.vout[0].script_pub_key.data,
                   recipient.spk.data, recipient.spk.size) == 0;
        coins_free(&recv_check);
        IB_CHECK("recipient received the spent funds", recv_ok);
    }
    if (have_sendtx)
        transaction_free(&sendtx);

    /* ── cleanup — null the shared RPC context before returning so a
     * later group in the same process (test_zcl monolith) never reads a
     * dangling pointer into this function's stack. ── */
    rpc_wallet_set_state(NULL, NULL, NULL, NULL, NULL, NULL);
    rpc_wallet_set_node_db(NULL);
    rpc_wallet_set_coins_tip(NULL);

    coins_view_cache_free(&coins2);
    tx_mempool_free(&mempool2);
    free(ms2.chain_active.chain);
    wallet_sqlite_close(&ws2);
    wallet_free(w2);
    free(w2);
    node_db_close(&ndb2);
    wallet_sqlite_close(&ws1);
    wallet_free(w1);
    free(w1);
    node_db_close(&ndb1);
    simnet_free(s);
    free(s);

    test_cleanup_tmpdir(datadir1);
    test_cleanup_tmpdir(datadir2);
    return failures;
}

/* ── Part 2 ──────────────────────────────────────────────────────── */

static __attribute__((noinline)) int part2_backup_restore(void)
{
    int failures = 0;
    printf("\n-- Part 2: wallet_backup_service backup / restore "
           "(plain + encrypted) --\n");

    char srcdir[256], backupdir[256], restoredir[256];
    ib_make_dir(srcdir, sizeof(srcdir), "bksrc");
    ib_make_dir(backupdir, sizeof(backupdir), "bkdst");
    ib_make_dir(restoredir, sizeof(restoredir), "bkrestore");

    char srcdb[320];
    snprintf(srcdb, sizeof(srcdb), "%s/node.db", srcdir);
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    IB_CHECK("part2: node_db_open (funded wallet source)",
             node_db_open(&ndb, srcdb));

    struct wallet_sqlite ws;
    IB_CHECK("part2: wallet_sqlite_open", wallet_sqlite_open(&ws, ndb.db));

    wallet_lock_reset_for_test();
    IB_CHECK("part2: unlock encrypted wallet fixture",
             wallet_lock_unlock(NULL, NULL,
                                "ib-wallet-row-passphrase").ok);

    struct ib_key keyB;
    ib_make_key(&keyB);
    struct zcl_result wr = wallet_sqlite_write_key_r(&ws, &keyB.pub, &keyB.priv);
    IB_CHECK("part2: write an encrypted real key into wallet_keys", wr.ok);

    const int64_t BALANCE = 42 * COIN_VALUE;
    struct db_wallet_utxo wu;
    memset(&wu, 0, sizeof(wu));
    memset(wu.txid, 0x77, 32);
    wu.vout = 0;
    memcpy(wu.address_hash, keyB.kid.id.data, 20);
    wu.value = BALANCE;
    wu.height = 10;
    wu.is_coinbase = false;
    wu.script = keyB.spk.data;
    wu.script_len = keyB.spk.size;
    IB_CHECK("part2: seed a funded UTXO (wallet_utxos)",
             db_wallet_utxo_save(&ndb, &wu));

    int64_t orig_balance = db_wallet_utxo_balance(&ndb);
    IB_CHECK("part2: source wallet balance is funded",
             orig_balance == BALANCE);

    /* Plain backup, then the ChaCha20-Poly1305 encrypted variant — both
     * the exact production primitives wallet_backup_service uses. */
    char plainpath[512] = "";
    int64_t key_count = -1;
    bool ran = wallet_backup_run_once(backupdir, &ndb, plainpath,
                                      sizeof(plainpath), &key_count,
                                      NULL, 0).ok;
    IB_CHECK("part2: plain backup produced with 1 key",
             ran && key_count == 1 && plainpath[0]);

    char encpath[576] = "";
    snprintf(encpath, sizeof(encpath), "%s.enc", plainpath);
    const char *passphrase = "ib-lane-w1b-passphrase";
    bool enc_ok = ran &&
        wallet_backup_encrypt_file(plainpath, encpath, passphrase).ok;
    IB_CHECK("part2: encrypt the backup", enc_ok);

    /* ── Restore into a FRESH datadir through the real merge lifecycle ──
     *
     * A wallet backup is deliberately a partial SQLite store: its CTAS
     * wallet tables are evidence to merge, not a complete node.db schema.
     * Installing the decrypted file directly as node.db used to rely on the
     * open ceremony mistaking missing node_state for fresh schema 0. The
     * fail-closed schema preflight correctly rejects that shape. Exercise the
     * production restore service, which inspects the partial artifact and
     * merges it into a freshly initialized target node.db. */
    char restored_db[576];
    snprintf(restored_db, sizeof(restored_db), "%s/node.db", restoredir);
    struct wallet_restore_request restore_req = {
        .backup_path = encpath,
        .datadir = restoredir,
        .password = passphrase,
        .dry_run = false,
    };
    struct wallet_restore_report restore_rep;
    struct zcl_result restore_r = enc_ok
        ? wallet_restore_run(&restore_req, &restore_rep)
        : ZCL_ERR(-1, "encrypted backup was not produced");
    bool restore_ok = restore_r.ok && restore_rep.source_was_encrypted &&
                      restore_rep.target_created;
    IB_CHECK("part2: explicit restore lifecycle decrypts and merges backup",
             restore_ok);

    struct node_db ndb_restored;
    memset(&ndb_restored, 0, sizeof(ndb_restored));
    bool opened_restored = restore_ok &&
                           node_db_open(&ndb_restored, restored_db);
    IB_CHECK("part2: restored node.db opens", opened_restored);

    if (opened_restored) {
        int64_t restored_balance = db_wallet_utxo_balance(&ndb_restored);
        IB_CHECK("part2: restored balance matches the original",
                 restored_balance == orig_balance);

        struct wallet_sqlite ws_restored;
        bool ws_ok = wallet_sqlite_open(&ws_restored, ndb_restored.db);
        struct privkey got;
        privkey_init(&got);
        struct zcl_result rr = ws_ok ?
            wallet_sqlite_read_single_key(&ws_restored, &keyB.pub, &got) :
            ZCL_ERR(-1, "wallet_sqlite_open failed");
        bool key_survives = rr.ok && got.fValid &&
                           memcmp(got.vch, keyB.priv.vch, 32) == 0;
        IB_CHECK("part2: restored encrypted key and wrapped DEK recover",
                 key_survives);
        memory_cleanse(got.vch, 32);
        if (ws_ok)
            wallet_sqlite_close(&ws_restored);
        node_db_close(&ndb_restored);
    }

    /* ── A wrong passphrase fails closed and leaves no partial file ── */
    char wrongpath[576];
    snprintf(wrongpath, sizeof(wrongpath), "%s/wrong.sqlite", restoredir);
    bool wrong_ok = enc_ok &&
        wallet_backup_decrypt_file(encpath, wrongpath,
                                   "definitely-the-wrong-passphrase").ok;
    IB_CHECK("part2: wrong passphrase is rejected (AEAD tag mismatch)",
             !wrong_ok);
    struct stat st;
    IB_CHECK("part2: wrong-passphrase decrypt leaves no partial file",
             stat(wrongpath, &st) != 0);

    memory_cleanse(keyB.priv.vch, 32);
    wallet_sqlite_close(&ws);
    node_db_close(&ndb);
    wallet_lock_reset_for_test();

    test_cleanup_tmpdir(srcdir);
    test_cleanup_tmpdir(backupdir);
    test_cleanup_tmpdir(restoredir);
    return failures;
}

/* ── Aggregator ──────────────────────────────────────────────────── */

int test_simnet_wallet_import_backup(void);
int test_simnet_wallet_import_backup(void)
{
    printf("\n=== simnet wallet import/export + backup/restore E2E "
           "(lane W1-b) ===\n");
    int failures = 0;
    /* Sovereignty-guard trust fixture (bare ⇒ wallet_spend allowed) for the
     * sendtoaddress spend in part 1 — see ib_open_trust_fixture. */
    char trustdir[256];
    ib_make_dir(trustdir, sizeof(trustdir), "trust");
    IB_CHECK("trust fixture (progress store, bare self-derived)",
             ib_open_trust_fixture(trustdir));
    failures += part1_import_rescan_spend();
    failures += part2_backup_restore();
    reducer_frontier_provable_tip_reset();
    progress_store_close();
    printf("simnet_wallet_import_backup: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    return failures;
}
