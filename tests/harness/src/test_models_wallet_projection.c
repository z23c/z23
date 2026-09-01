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
#include <unistd.h>

int test_model_wallet_projection(void)
{
    int failures = 0;

    printf("Wallet projection model summarizes balances and tips... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        snprintf(dbdir, sizeof(dbdir), ".zcl_test_wallet_projection_%d", (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);

        if (ok) {
            struct db_block blk;
            struct db_wallet_utxo utxo;
            struct db_sapling_note note;
            struct db_wallet_projection_summary summary;

            memset(&blk, 0, sizeof(blk));
            memset(&utxo, 0, sizeof(utxo));
            memset(&note, 0, sizeof(note));
            memset(&summary, 0, sizeof(summary));

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

            uint8_t witness_blob[] = {0x71, 0x72, 0x73};
            uint8_t exact_nf[32];
            memset(exact_nf, 0x7a, sizeof(exact_nf));
            ok = ok && db_sapling_note_save_witness_and_nullifier(
                &ndb, note.txid, note.output_index, witness_blob,
                sizeof(witness_blob), 24, exact_nf);
            struct db_sapling_note *saved_notes = NULL;
            int saved_count = db_sapling_note_list_unspent_alloc(
                &ndb, &saved_notes);
            ok = ok && saved_count == 1 && saved_notes &&
                 memcmp(saved_notes[0].nullifier, exact_nf, 32) == 0;
            uint8_t *loaded_witness = NULL;
            size_t loaded_witness_len = 0;
            int loaded_witness_height = 0;
            ok = ok && db_sapling_note_load_witness(
                &ndb, note.txid, note.output_index, &loaded_witness,
                &loaded_witness_len, &loaded_witness_height) &&
                 loaded_witness_len == sizeof(witness_blob) &&
                 memcmp(loaded_witness, witness_blob,
                        sizeof(witness_blob)) == 0 &&
                 loaded_witness_height == 24;
            free(loaded_witness);
            free(saved_notes);

            ok = ok && db_wallet_projection_summary(&ndb, &summary);
            ok = ok && (summary.chain_tip_height == 25);
            ok = ok && (summary.effective_tip_height == 30);
            ok = ok && (summary.utxo_count == 1);
            ok = ok && (summary.note_count == 1);
            ok = ok && (summary.transparent_balance == 5000);
            ok = ok && (summary.shielded_balance == 7000);
            ok = ok && (summary.speed_balance == 5000);
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Wallet raw tx projection lists recent serialized rows... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        snprintf(dbdir, sizeof(dbdir),
                 ".zcl_test_wallet_raw_projection_%d", (int)getpid());
        mkdir(dbdir, 0755);
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

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Sapling note payment projections summarize by address and amount... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        snprintf(dbdir, sizeof(dbdir),
                 ".zcl_test_sapling_payment_projection_%d", (int)getpid());
        mkdir(dbdir, 0755);
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

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Wallet projection bulk replace and tx height backfill stay model-owned... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        snprintf(dbdir, sizeof(dbdir),
                 ".zcl_test_wallet_projection_bulk_%d", (int)getpid());
        mkdir(dbdir, 0755);
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

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Tx index bulk-load lifecycle stays model-owned... ");
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
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("UTXO model rebuilds wallet and address caches... ");
    {
        char dbdir[256];
        char dbpath[320];
        struct node_db ndb;
        bool ok;
        snprintf(dbdir, sizeof(dbdir),
                 ".zcl_test_utxo_cache_rebuild_%d", (int)getpid());
        mkdir(dbdir, 0755);
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", dbdir);
        memset(&ndb, 0, sizeof(ndb));
        ok = node_db_open(&ndb, dbpath);

        if (ok) {
            struct db_utxo wallet_utxo;
            struct db_utxo external_utxo;
            uint8_t wallet_script[] = {0x76, 0xa9, 0x14, 0x88, 0xac};
            uint8_t external_addr[20];
            sqlite3_stmt *s = NULL;
            int address_rows = 0;
            int64_t address_balance = 0;

            memset(&wallet_utxo, 0, sizeof(wallet_utxo));
            memset(&external_utxo, 0, sizeof(external_utxo));
            memset(external_addr, 0x66, sizeof(external_addr));

            /* Plant the wallet key through the single writer (the model
             * save is gone — wallet_sqlite owns the wallet_keys table). */
            uint8_t key_pkh[20];
            memset(key_pkh, 0, sizeof(key_pkh));
            {
                struct wallet_sqlite ws;
                ok = wallet_sqlite_open(&ws, ndb.db);
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

            if (ok &&
                sqlite3_prepare_v2(ndb.db,
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
            node_db_close(&ndb);
        }

        char cmd[384];
        snprintf(cmd, sizeof(cmd), "rm -rf %s", dbdir);
        system(cmd);
        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
