/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Focused wallet projection model tests. */

#include "test/test_core.h"
#include "models/block.h"
#include "models/tx_index.h"
#include "models/utxo.h"
#include "models/wallet_key.h"
#include "models/wallet_tx.h"
#include "keys/key.h"
#include "support/cleanse.h"
#include "wallet/wallet_sqlite.h"
#include "storage/wallet_projection.h"
#include <unistd.h>

/* Fixture cleanup without a shell: the path is absolute and may contain
 * spaces. A directory that is already gone counts as success, but only when
 * the directory itself is verified absent: the remover can also report
 * ENOENT for a nested entry while the root remains. */
static bool fixture_rm_ok(const char *dir)
{
    if (test_rm_rf_recursive(dir) == 0)
        return true;
    if (errno != ENOENT)
        return false;
    struct stat st;
    errno = 0;
    return lstat(dir, &st) != 0 && errno == ENOENT;
}

static bool wallet_projection_note_witness_roundtrip(struct node_db *ndb,
                                                     struct db_sapling_note *note,
                                                     bool ok)
{
    uint8_t witness_blob[] = {0x71, 0x72, 0x73};
    uint8_t exact_nf[32];
    memset(exact_nf, 0x7a, sizeof(exact_nf));
    ok = ok && db_sapling_note_save_witness_and_nullifier(
        ndb, note->txid, note->output_index, witness_blob,
        sizeof(witness_blob), 24, exact_nf);
    struct db_sapling_note *saved_notes = NULL;
    int saved_count = db_sapling_note_list_unspent_alloc(
        ndb, &saved_notes);
    ok = ok && saved_count == 1 && saved_notes &&
         memcmp(saved_notes[0].nullifier, exact_nf, 32) == 0;
    uint8_t *loaded_witness = NULL;
    size_t loaded_witness_len = 0;
    int loaded_witness_height = 0;
    ok = ok && db_sapling_note_load_witness(
        ndb, note->txid, note->output_index, &loaded_witness,
        &loaded_witness_len, &loaded_witness_height) &&
         loaded_witness_len == sizeof(witness_blob) &&
         memcmp(loaded_witness, witness_blob,
                sizeof(witness_blob)) == 0 &&
         loaded_witness_height == 24;
    free(loaded_witness);
    free(saved_notes);
    return ok;
}

static bool wallet_projection_summary_check(struct node_db *ndb, bool ok)
{
    struct db_wallet_projection_summary summary;
    memset(&summary, 0, sizeof(summary));
    ok = ok && db_wallet_projection_summary(ndb, &summary);
    ok = ok && (summary.chain_tip_height == 25);
    ok = ok && (summary.effective_tip_height == 30);
    ok = ok && (summary.utxo_count == 1);
    ok = ok && (summary.note_count == 1);
    ok = ok && (summary.transparent_balance == 5000);
    ok = ok && (summary.shielded_balance == 7000);
    ok = ok && (summary.speed_balance == 5000);
    return ok;
}

static bool wallet_projection_summary_case(void)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    bool ok;
    test_make_tmpdir(dbdir, sizeof(dbdir), "wallet", "projection");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));
    ok = node_db_open(&ndb, dbpath);

    if (ok) {
        struct db_block blk;
        struct db_wallet_utxo utxo;
        struct db_sapling_note note;

        memset(&blk, 0, sizeof(blk));
        memset(&utxo, 0, sizeof(utxo));
        memset(&note, 0, sizeof(note));

        memset(blk.hash, 0x01, 32);
        memset(blk.prev_hash, 0x0b, 32);
        memset(blk.merkle_root, 0x0c, 32);
        memset(blk.chain_work, 0x0d, 32);
        blk.height = 25;
        blk.time = 12345;
        blk.bits = 0x1d00ffffU;
        blk.status = 3;
        {
            static uint8_t blk_solution[] = {0x01, 0x02};
            blk.solution = blk_solution;
            blk.solution_len = sizeof(blk_solution);
        }
        ok = db_block_save(&ndb, &blk);

        memset(utxo.txid, 0x02, 32);
        memset(utxo.address_hash, 0x03, 20);
        utxo.value = 5000;
        utxo.height = 30;
        utxo.script = (uint8_t *)"\x76\xa9\x14\x00\x88\xac";
        utxo.script_len = 6;
        ok = ok && db_wallet_utxo_save(&ndb, &utxo);

        memset(note.txid, 0x04, 32);
        memset(note.rcm, 0x05, 32);
        memset(note.ivk, 0x06, 32);
        memset(note.diversifier, 0x07, 11);
        memset(note.pk_d, 0x08, 32);
        memset(note.cm, 0x09, 32);
        memset(note.nullifier, 0x0a, 32);
        note.value = 7000;
        note.block_height = 22;
        ok = ok && db_sapling_note_save(&ndb, &note);

        ok = wallet_projection_note_witness_roundtrip(&ndb, &note, ok);
        ok = wallet_projection_summary_check(&ndb, ok);
        node_db_close(&ndb);
    }

    ok &= fixture_rm_ok(dbdir);
    return ok;
}

static bool wallet_projection_raw_tx_case(void)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    bool ok;
    test_make_tmpdir(dbdir, sizeof(dbdir), "wallet", "raw_projection");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));
    ok = node_db_open(&ndb, dbpath);

    if (ok) {
        struct db_wallet_tx a;
        struct db_wallet_tx b;
        struct db_wallet_tx_raw_view rows[4];
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        memset(rows, 0, sizeof(rows));

        memset(a.txid, 0x11, 32);
        a.raw_tx = (uint8_t *)"\x01\x02\x03";
        a.raw_tx_len = 3;
        a.block_height = 10;
        a.has_block = true;
        memset(a.block_hash, 0x21, 32);
        a.time_received = 100;
        ok = db_wallet_tx_save(&ndb, &a);

        memset(b.txid, 0x12, 32);
        b.raw_tx = (uint8_t *)"\xaa\xbb\xcc\xdd";
        b.raw_tx_len = 4;
        b.block_height = 25;
        b.has_block = true;
        memset(b.block_hash, 0x22, 32);
        b.time_received = 200;
        ok = ok && db_wallet_tx_save(&ndb, &b);

        if (ok) {
            int count = db_wallet_tx_recent_raw(&ndb, rows, 4);
            ok = (count == 2);
            ok = ok && rows[0].raw_tx && rows[0].raw_tx_len == 4;
            ok = ok && rows[0].block_height == 25;
            ok = ok && rows[1].raw_tx && rows[1].raw_tx_len == 3;
            ok = ok && rows[1].block_height == 10;
        }

        for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++)
            db_wallet_tx_raw_view_free(&rows[i]);
        node_db_close(&ndb);
    }

    ok &= fixture_rm_ok(dbdir);
    return ok;
}

static bool wallet_projection_sapling_payment_case(void)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    bool ok;
    test_make_tmpdir(dbdir, sizeof(dbdir), "wallet",
                     "sapling_payment_projection");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));
    ok = node_db_open(&ndb, dbpath);

    if (ok) {
        struct db_sapling_note a;
        struct db_sapling_note b;
        struct db_sapling_note c;
        memset(&a, 0, sizeof(a));
        memset(&b, 0, sizeof(b));
        memset(&c, 0, sizeof(c));

        memset(a.txid, 0x31, 32);
        memset(a.rcm, 0x32, 32);
        memset(a.ivk, 0x33, 32);
        memset(a.diversifier, 0x34, 11);
        memset(a.pk_d, 0x35, 32);
        memset(a.cm, 0x36, 32);
        memset(a.nullifier, 0x37, 32);
        a.value = 5000;
        a.block_height = 11;
        snprintf(a.address, sizeof(a.address), "%s", "zs1alpha");
        ok = db_sapling_note_save(&ndb, &a);

        memset(b.txid, 0x41, 32);
        memset(b.rcm, 0x42, 32);
        memset(b.ivk, 0x43, 32);
        memset(b.diversifier, 0x44, 11);
        memset(b.pk_d, 0x45, 32);
        memset(b.cm, 0x46, 32);
        memset(b.nullifier, 0x47, 32);
        b.value = 5000;
        b.block_height = 12;
        snprintf(b.address, sizeof(b.address), "%s", "zs1alpha");
        ok = ok && db_sapling_note_save(&ndb, &b);

        memset(c.txid, 0x51, 32);
        memset(c.rcm, 0x52, 32);
        memset(c.ivk, 0x53, 32);
        memset(c.diversifier, 0x54, 11);
        memset(c.pk_d, 0x55, 32);
        memset(c.cm, 0x56, 32);
        memset(c.nullifier, 0x57, 32);
        c.value = 7000;
        c.block_height = 13;
        snprintf(c.address, sizeof(c.address), "%s", "zs1beta");
        ok = ok && db_sapling_note_save(&ndb, &c);

        ok = ok && (db_sapling_note_balance_for_address(&ndb, "zs1alpha") == 10000);
        ok = ok && (db_sapling_note_balance_for_address(&ndb, "zs1beta") == 7000);
        ok = ok && (db_sapling_note_balance_for_exact_value(&ndb, 5000) == 10000);
        ok = ok && (db_sapling_note_balance_for_exact_value(&ndb, 7000) == 7000);
        ok = ok && (db_sapling_note_balance_for_exact_value(&ndb, 1234) == 0);
        node_db_close(&ndb);
    }

    ok &= fixture_rm_ok(dbdir);
    return ok;
}

static bool wallet_projection_bulk_replace_case(void)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    bool ok;
    test_make_tmpdir(dbdir, sizeof(dbdir), "wallet", "projection_bulk");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));
    ok = node_db_open(&ndb, dbpath);

    if (ok) {
        struct db_wallet_utxo utxos[2];
        struct db_sapling_note notes[2];
        struct db_wallet_tx tx;
        struct db_wallet_txid_ref refs[4];
        memset(utxos, 0, sizeof(utxos));
        memset(notes, 0, sizeof(notes));
        memset(&tx, 0, sizeof(tx));
        memset(refs, 0, sizeof(refs));

        memset(utxos[0].txid, 0x61, 32);
        memset(utxos[0].address_hash, 0x62, 20);
        utxos[0].value = 1111;
        utxos[0].height = 9;
        utxos[0].script = (uint8_t *)"\x51";
        utxos[0].script_len = 1;

        memset(utxos[1].txid, 0x63, 32);
        memset(utxos[1].address_hash, 0x64, 20);
        utxos[1].value = 2222;
        utxos[1].height = 10;
        utxos[1].script = (uint8_t *)"\x52";
        utxos[1].script_len = 1;

        memset(notes[0].txid, 0x71, 32);
        memset(notes[0].rcm, 0x72, 32);
        memset(notes[0].ivk, 0x73, 32);
        memset(notes[0].diversifier, 0x74, 11);
        memset(notes[0].pk_d, 0x75, 32);
        memset(notes[0].cm, 0x76, 32);
        memset(notes[0].nullifier, 0x77, 32);
        notes[0].value = 3333;
        notes[0].block_height = 12;
        snprintf(notes[0].address, sizeof(notes[0].address), "%s", "zs1bulk");

        memset(notes[1].txid, 0x78, 32);
        memset(notes[1].rcm, 0x79, 32);
        memset(notes[1].ivk, 0x7a, 32);
        memset(notes[1].diversifier, 0x7b, 11);
        memset(notes[1].pk_d, 0x7c, 32);
        memset(notes[1].cm, 0x7d, 32);
        memset(notes[1].nullifier, 0x7e, 32);
        notes[1].value = 4444;
        notes[1].block_height = 13;
        snprintf(notes[1].address, sizeof(notes[1].address), "%s", "zs1bulk");

        ok = db_wallet_utxo_replace_all(&ndb, utxos, 2);
        ok = ok && db_sapling_note_replace_all(&ndb, notes, 2);
        ok = ok && (db_wallet_utxo_balance_with_count(&ndb, NULL) == 3333);
        ok = ok && (db_sapling_note_balance_for_address(&ndb, "zs1bulk") == 7777);

        memset(tx.txid, 0x81, 32);
        tx.raw_tx = (uint8_t *)"\xaa\xbb";
        tx.raw_tx_len = 2;
        tx.time_received = 123;
        ok = ok && db_wallet_tx_save(&ndb, &tx);
        if (ok) {
            struct db_wallet_tx unconfirmed;
            memset(&unconfirmed, 0, sizeof(unconfirmed));
            ok = sqlite3_exec(ndb.db,
                "UPDATE wallet_transactions SET block_height=0 "
                "WHERE txid=x'8181818181818181818181818181818181818181818181818181818181818181'",
                NULL, NULL, NULL) == SQLITE_OK;
            ok = ok && db_wallet_tx_find(&ndb, tx.txid, &unconfirmed) &&
                 !unconfirmed.has_block && unconfirmed.block_height == 0;
            db_wallet_tx_free(&unconfirmed);
            int count = db_wallet_tx_list_unconfirmed(&ndb, refs, 4);
            ok = (count == 1);
            ok = ok && memcmp(refs[0].txid, tx.txid, 32) == 0;
            ok = ok && db_wallet_tx_update_block_height(&ndb, tx.txid, 99);
            count = db_wallet_tx_list_unconfirmed(&ndb, refs, 4);
            ok = ok && (count == 0);
        }
        node_db_close(&ndb);
    }

    ok &= fixture_rm_ok(dbdir);
    return ok;
}

static bool wallet_projection_tx_index_bulk_case(void)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    bool ok;
    test_make_tmpdir(dbdir, sizeof(dbdir), "wallet_projection",
                     "tx_index_bulk");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));
    ok = node_db_open(&ndb, dbpath);

    if (ok) {
        struct db_tx_index tx;
        struct db_tx_index found;
        memset(&tx, 0, sizeof(tx));
        memset(&found, 0, sizeof(found));

        ok = db_tx_prepare_bulk_load(&ndb);
        memset(tx.txid, 0x91, 32);
        memset(tx.block_hash, 0x92, 32);
        tx.block_height = 21;
        tx.tx_index = 0;
        tx.file_num = 4;
        tx.file_pos = 100;
        tx.is_coinbase = true;
        ok = ok && db_tx_save(&ndb, &tx);
        ok = ok && db_tx_count(&ndb) == 1;
        ok = ok && db_tx_finalize_bulk_load(&ndb);
        ok = ok && db_tx_find(&ndb, tx.txid, &found);
        ok = ok && (found.block_height == 21);
        ok = ok && db_tx_delete_all(&ndb);
        ok = ok && (db_tx_count(&ndb) == 0);
        node_db_close(&ndb);
    }

    test_rm_rf_recursive(dbdir);
    return ok;
}

static bool wallet_projection_plant_wallet_key(struct node_db *ndb,
                                               uint8_t key_pkh[20], bool ok)
{
    /* Plant the wallet key through the single writer (the model
     * save is gone — wallet_sqlite owns the wallet_keys table). */
    {
        struct wallet_sqlite ws;
        ok = wallet_sqlite_open(&ws, ndb->db);
        struct privkey key;
        struct pubkey pk;
        privkey_init(&key);
        memset(key.vch, 0x43, 32);
        key.vch[1] = 0x34;
        key.fValid = true;
        key.fCompressed = true;
        ok = ok && privkey_get_pubkey(&key, &pk);
        ok = ok && wallet_sqlite_write_key(&ws, &pk, &key);
        if (ok) {
            struct key_id kid = pubkey_get_id(&pk);
            memcpy(key_pkh, kid.id.data, 20);
        }
        wallet_sqlite_close(&ws);
        memory_cleanse(key.vch, 32);
    }
    return ok;
}

static bool wallet_projection_address_cache_check(struct node_db *ndb, bool ok)
{
    sqlite3_stmt *s = NULL;
    int address_rows = 0;
    int64_t address_balance = 0;

    if (ok &&
        sqlite3_prepare_v2(ndb->db,
            "SELECT COUNT(*), COALESCE(SUM(balance),0) FROM addresses",
            -1, &s, NULL) == SQLITE_OK &&
        s &&
        sqlite3_step(s) == SQLITE_ROW) {
        address_rows = sqlite3_column_int(s, 0);
        address_balance = sqlite3_column_int64(s, 1);
    } else {
        ok = false;
    }
    if (s)
        sqlite3_finalize(s);
    ok = ok && address_rows == 2;
    ok = ok && address_balance == 3333;
    return ok;
}

static bool wallet_projection_utxo_cache_case(void)
{
    char dbdir[256];
    char dbpath[320];
    struct node_db ndb;
    bool ok;
    test_make_tmpdir(dbdir, sizeof(dbdir), "wallet", "utxo_cache_rebuild");
    snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
    memset(&ndb, 0, sizeof(ndb));
    ok = node_db_open(&ndb, dbpath);

    if (ok) {
        struct db_utxo wallet_utxo;
        struct db_utxo external_utxo;
        uint8_t wallet_script[] = {0x76, 0xa9, 0x14, 0x88, 0xac};
        uint8_t external_addr[20];

        memset(&wallet_utxo, 0, sizeof(wallet_utxo));
        memset(&external_utxo, 0, sizeof(external_utxo));
        memset(external_addr, 0x66, sizeof(external_addr));

        uint8_t key_pkh[20];
        memset(key_pkh, 0, sizeof(key_pkh));
        ok = wallet_projection_plant_wallet_key(&ndb, key_pkh, ok);

        memset(wallet_utxo.txid, 0x51, sizeof(wallet_utxo.txid));
        wallet_utxo.vout = 0;
        wallet_utxo.value = 1111;
        wallet_utxo.script = wallet_script;
        wallet_utxo.script_len = sizeof(wallet_script);
        wallet_utxo.script_type = SCRIPT_P2PKH;
        memcpy(wallet_utxo.address_hash, key_pkh,
               sizeof(wallet_utxo.address_hash));
        wallet_utxo.has_address = true;
        wallet_utxo.height = 10;
        ok = ok && db_utxo_save(&ndb, &wallet_utxo);

        memset(external_utxo.txid, 0x52, sizeof(external_utxo.txid));
        external_utxo.vout = 1;
        external_utxo.value = 2222;
        external_utxo.script = wallet_script;
        external_utxo.script_len = sizeof(wallet_script);
        external_utxo.script_type = SCRIPT_P2PKH;
        memcpy(external_utxo.address_hash, external_addr,
               sizeof(external_utxo.address_hash));
        external_utxo.has_address = true;
        external_utxo.height = 11;
        ok = ok && db_utxo_save(&ndb, &external_utxo);

        ok = ok && db_utxo_rebuild_wallet_and_address_caches(&ndb);
        ok = ok && db_wallet_utxo_balance(&ndb) == 1111;
        ok = ok && db_utxo_total_value(&ndb) == 3333;
        ok = wallet_projection_address_cache_check(&ndb, ok);
        node_db_close(&ndb);
    }

    ok &= fixture_rm_ok(dbdir);
    return ok;
}

static int projection_interrupt(void *unused)
{
    (void)unused;
    return 1;
}

static bool wallet_projection_unspent_errors(struct node_db *ndb)
{
    struct db_sapling_note *rows = NULL;
    sqlite3_progress_handler(ndb->db, 1, projection_interrupt, NULL);
    int interrupted = db_sapling_note_list_unspent_alloc(ndb, &rows);
    sqlite3_progress_handler(ndb->db, 0, NULL, NULL);
    bool ok = interrupted == -1 && !rows;
    if (sqlite3_exec(ndb->db, "DROP TABLE wallet_sapling_notes", NULL, NULL, NULL) != SQLITE_OK) return false;
    return db_sapling_note_list_unspent_alloc(ndb, &rows) == -1 && !rows && ok;
}

static bool wallet_projection_unspent_list_case(void)
{
    char dir[256], path[320];
    struct node_db ndb = {0};
    test_make_tmpdir(dir, sizeof(dir), "wallet", "unspent_list");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool ok = node_db_open(&ndb, path);
    if (!ok) { (void)fixture_rm_ok(dir); return false; }
    struct db_sapling_note *rows = NULL;
    if (ok) ok = db_sapling_note_list_unspent_alloc(&ndb, &rows) == 0 && !rows;
    struct db_sapling_note note = {0};
    memset(note.txid, 1, 32); memset(note.rcm, 2, 32); memset(note.ivk, 3, 32);
    memset(note.diversifier, 4, 11); memset(note.pk_d, 5, 32);
    memset(note.cm, 6, 32); memset(note.nullifier, 7, 32);
    note.value = 1; note.block_height = 2;
    if (ok) ok = db_sapling_note_save(&ndb, &note);
    note.txid[0] = 8; note.nullifier[0] = 9; note.value = 2;
    if (ok) ok = db_sapling_note_save(&ndb, &note);
    int n = ok ? db_sapling_note_list_unspent_alloc(&ndb, &rows) : -1;
    ok = ok && n == 2 && rows && rows[0].value == 2 && rows[1].value == 1;
    free(rows); rows = NULL;
    ok = wallet_projection_unspent_errors(&ndb) && ok;
    node_db_close(&ndb);
    return fixture_rm_ok(dir) && ok;
}

static bool replay_blob_is(sqlite3_stmt *s, int col, const void *data, size_t len)
{
    const void *p = sqlite3_column_blob(s, col);
    return p && sqlite3_column_bytes(s, col) == (int)len && memcmp(p, data, len) == 0;
}

static bool replay_note_preserved(struct node_db *db, const struct db_sapling_note *n,
                                  const uint8_t *nf, const uint8_t *spent,
                                  const uint8_t *witness, size_t witness_len)
{
    sqlite3_stmt *s = NULL;
    const char *sql = "SELECT nullifier,spent_txid,witness_data,witness_height,source "
                      "FROM wallet_sapling_notes WHERE txid=? AND output_index=?";
    if (sqlite3_prepare_v2(db->db, sql, -1, &s, NULL) != SQLITE_OK) return false;
    bool ok = sqlite3_bind_blob(s, 1, n->txid, 32, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(s, 2, n->output_index) == SQLITE_OK && sqlite3_step(s) == SQLITE_ROW;
    if (ok) ok = replay_blob_is(s, 0, nf, 32) && replay_blob_is(s, 1, spent, 32) &&
        replay_blob_is(s, 2, witness, witness_len) &&
        sqlite3_column_int(s, 3) == 42 && sqlite3_column_text(s, 4) &&
        strcmp((const char *)sqlite3_column_text(s, 4), DB_SAPLING_NOTE_SOURCE_LOCAL) == 0;
    if (sqlite3_finalize(s) != SQLITE_OK) ok = false;
    return ok;
}

static bool replay_note_query_failure(struct node_db *db, const struct db_sapling_note *n)
{
    struct sapling_replay_delivery delivery = {0};
    return node_db_begin_immediate(db) &&
        sqlite3_exec(db->db, "DROP TABLE wallet_sapling_notes", NULL, NULL, NULL) == SQLITE_OK &&
        db_sapling_note_merge_replayed(db, n, &delivery) == SAPLING_REPLAY_MERGE_ERROR && node_db_rollback(db);
}

static bool wallet_projection_replay_merge_case(void)
{
    char dir[256], path[320];
    struct node_db db = {0};
    test_make_tmpdir(dir, sizeof(dir), "wallet", "replay_merge");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    if (!node_db_open(&db, path)) return false;
    struct db_sapling_note n = {0};
    memset(n.txid, 1, 32); memset(n.rcm, 2, 32); memset(n.ivk, 3, 32);
    memset(n.diversifier, 4, 11); memset(n.pk_d, 5, 32);
    memset(n.cm, 6, 32); memset(n.nullifier, 7, 32);
    n.value = 12; n.block_height = 15; n.memo[0] = 9; n.memo_len = 1;
    uint8_t nf[32], spent[32], witness[] = {1,2,3,4};
    struct sapling_replay_delivery delivery = {0};
    memset(nf, 8, sizeof(nf)); memset(spent, 9, sizeof(spent));
    bool ok = db_sapling_note_merge_replayed(&db, &n, &delivery) == SAPLING_REPLAY_MERGE_ERROR &&
        node_db_begin_immediate(&db) &&
        db_sapling_note_merge_replayed(&db, &n, &delivery) == SAPLING_REPLAY_MERGE_INSERTED &&
        db_sapling_note_save_witness_and_nullifier(&db, n.txid, n.output_index,
                                                   witness, sizeof(witness), 42, nf) &&
        db_sapling_note_mark_spent(&db, nf, spent) == DB_MARK_SPENT_OK && node_db_commit(&db);
    if (ok) ok = node_db_begin_immediate(&db) &&
        db_sapling_note_merge_replayed(&db, &n, &delivery) == SAPLING_REPLAY_MERGE_EXISTING;
    n.cm[0] ^= 1;
    if (ok) ok = db_sapling_note_merge_replayed(&db, &n, &delivery) == SAPLING_REPLAY_MERGE_CONFLICT;
    n.cm[0] ^= 1; n.block_height++;
    if (ok) ok = db_sapling_note_merge_replayed(&db, &n, &delivery) == SAPLING_REPLAY_MERGE_CONFLICT;
    n.block_height--;
    if (ok) ok = replay_note_preserved(&db, &n, nf, spent, witness, sizeof(witness)) && node_db_commit(&db);
    if (ok) ok = replay_note_query_failure(&db, &n);
    db_sapling_replay_delivery_clear(&delivery);
    node_db_close(&db);
    return fixture_rm_ok(dir) && ok;
}

static int wallet_presence_deny_select(void *unused, int action, const char *a,
    const char *b, const char *c, const char *d)
{
    (void)unused; (void)a; (void)b; (void)c; (void)d;
    return action == SQLITE_SELECT ? SQLITE_DENY : SQLITE_OK;
}

static bool wallet_projection_tx_presence_case(void)
{
    char dir[256], path[320]; struct node_db db = {0};
    test_make_tmpdir(dir, sizeof(dir), "wallet", "presence");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    bool ok = node_db_open(&db, path);
    struct db_wallet_tx tx = {0};
    memset(tx.txid, 0x51, sizeof(tx.txid));
    tx.raw_tx = (uint8_t *)"\x01\x02"; tx.raw_tx_len = 2; tx.time_received = 100;
    if (ok) ok = db_wallet_tx_presence_checked(&db, tx.txid) == DB_WALLET_TX_ABSENT;
    if (ok) ok = db_wallet_tx_save(&db, &tx);
    if (ok) ok = db_wallet_tx_presence_checked(&db, tx.txid) == DB_WALLET_TX_PRESENT;
    if (ok) ok = sqlite3_set_authorizer(db.db, wallet_presence_deny_select, NULL) == SQLITE_OK;
    if (ok) ok = db_wallet_tx_presence_checked(&db, tx.txid) == DB_WALLET_TX_ERROR;
    if (db.open) { (void)sqlite3_set_authorizer(db.db, NULL, NULL); node_db_close(&db); }
    return fixture_rm_ok(dir) && ok;
}

static bool wallet_cutover_utxo_preserved(struct node_db *db, const struct db_wallet_utxo *u,
                                         const uint8_t spender[32], int height)
{
    struct db_wallet_utxo got = {0};
    bool ok = db_wallet_utxo_find(db, u->txid, u->vout, &got) && got.is_spent &&
        !memcmp(got.spent_txid, spender, 32) && got.spent_vin == 2 && got.height == height;
    db_wallet_utxo_free(&got); return ok;
}

static bool wallet_cutover_utxo_rollback_case(struct node_db *db, const struct db_wallet_utxo *u,
    struct db_wallet_utxo_cutover_delivery *delivery, event_log_t *log)
{
    return node_db_begin_immediate(db) &&
        db_wallet_utxo_cutover_merge(db, u, delivery) == DB_UTXO_CUTOVER_OK &&
        !db_wallet_utxo_cutover_delivery_flush(delivery) && event_log_size(log) == 0 &&
        node_db_rollback(db) && !db_wallet_utxo_cutover_delivery_flush(delivery) &&
        node_db_begin_immediate(db) && node_db_commit(db) &&
        !db_wallet_utxo_cutover_delivery_flush(delivery) && event_log_size(log) == 0;
}

static bool wallet_cutover_utxo_commit_case(struct node_db *db, const struct db_wallet_utxo *u,
    struct db_wallet_utxo_cutover_delivery *delivery, event_log_t *log, const uint8_t spender[32])
{
    bool ok = node_db_begin_immediate(db) &&
        db_wallet_utxo_cutover_merge(db, u, delivery) == DB_UTXO_CUTOVER_OK &&
        db_wallet_utxo_cutover_spend(db, u->txid, u->vout, spender, 2) == DB_UTXO_CUTOVER_OK &&
        event_log_size(log) == 0 && node_db_commit(db);
    if (ok) {
        wallet_projection_set_event_log(NULL);
        ok = !db_wallet_utxo_cutover_delivery_flush(delivery);
        wallet_projection_set_event_log(log);
    }
    return ok && db_wallet_utxo_cutover_delivery_flush(delivery) && event_log_size(log) > 0;
}

static bool wallet_cutover_utxo_conflict_case(struct node_db *db, struct db_wallet_utxo *u,
    struct db_wallet_utxo_cutover_delivery *delivery, const uint8_t spender[32], const uint8_t other[32])
{
    if (!node_db_begin_immediate(db)) return false;
    u->height = 11;
    bool ok = db_wallet_utxo_cutover_merge(db, u, delivery) == DB_UTXO_CUTOVER_OK &&
        db_wallet_utxo_cutover_spend(db, u->txid, u->vout, spender, 2) == DB_UTXO_CUTOVER_OK &&
        db_wallet_utxo_cutover_spend(db, u->txid, u->vout, other, 2) == DB_UTXO_CUTOVER_CONFLICT;
    u->value++;
    if (ok) ok = db_wallet_utxo_cutover_merge(db, u, delivery) == DB_UTXO_CUTOVER_CONFLICT;
    u->value--;
    return ok && wallet_cutover_utxo_preserved(db, u, spender, 11) && node_db_rollback(db) &&
        wallet_cutover_utxo_preserved(db, u, spender, 10);
}

static bool wallet_cutover_utxo_fixture(void)
{
    char dir[256], path[320], logpath[320];
    test_make_tmpdir(dir, sizeof(dir), "wallet", "cutover_utxo");
    snprintf(path, sizeof(path), "%s/node.db", dir);
    snprintf(logpath, sizeof(logpath), "%s/events.log", dir);
    struct node_db db = {0};
    event_log_t *log = event_log_open(logpath);
    bool ok = log && node_db_open(&db, path);
    if (log) wallet_projection_set_event_log(log);
    uint8_t script[1] = {0x51}, spender[32] = {9}, other[32] = {8};
    struct db_wallet_utxo u = {.vout = 1, .value = 12345, .height = 10,
        .script = script, .script_len = sizeof(script)};
    u.txid[0] = 1; u.address_hash[0] = 2;
    struct db_wallet_utxo_cutover_delivery delivery = {0};
    if (ok) ok = wallet_cutover_utxo_rollback_case(&db, &u, &delivery, log);
    db_wallet_utxo_cutover_delivery_clear(&delivery);
    if (ok) ok = wallet_cutover_utxo_commit_case(&db, &u, &delivery, log, spender);
    db_wallet_utxo_cutover_delivery_clear(&delivery);
    if (ok) ok = wallet_cutover_utxo_conflict_case(&db, &u, &delivery, spender, other);
    db_wallet_utxo_cutover_delivery_clear(&delivery);
    wallet_projection_set_event_log(NULL);
    if (db.open) node_db_close(&db);
    if (log) event_log_close(log);
    return fixture_rm_ok(dir) && ok;
}

int test_model_wallet_projection(void)
{
    int failures = 0;
    printf("Cutover UTXO merge preserves reservations and defers events... ");
    if (wallet_cutover_utxo_fixture()) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    printf("Wallet transaction presence distinguishes missing and I/O failure... ");
    if (wallet_projection_tx_presence_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    printf("Replay note merge preserves confirmed state... ");
    if (wallet_projection_replay_merge_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }
    printf("Unspent list reports complete rows and errors... ");
    if (wallet_projection_unspent_list_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("Wallet projection model summarizes balances and tips... ");
    if (wallet_projection_summary_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("Wallet raw tx projection lists recent serialized rows... ");
    if (wallet_projection_raw_tx_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("Sapling note payment projections summarize by address and amount... ");
    if (wallet_projection_sapling_payment_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("Wallet projection bulk replace and tx height backfill stay model-owned... ");
    if (wallet_projection_bulk_replace_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("Tx index bulk-load lifecycle stays model-owned... ");
    if (wallet_projection_tx_index_bulk_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    printf("UTXO model rebuilds wallet and address caches... ");
    if (wallet_projection_utxo_cache_case()) printf("OK\n");
    else { printf("FAIL\n"); failures++; }

    return failures;
}
