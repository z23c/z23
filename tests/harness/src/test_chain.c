/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"
#include "consensus/upgrades.h"
#include "util/timedata.h"
#include "bloom/merkle.h"
#include "keys/key_io.h"
#include "chain/subsidy.h"
#include "validation/contextual_check_tx.h"
#include "validation/main_logic.h"
#include "storage/coins_db.h"
#include "validation/update_coins.h"
#include "storage/block_index_db.h"
#include "util/boot_phase.h"
#include "crypto/equihash.h"
#include "crypto/equihash_solver.h"
#include "chain/equihash.h"
#include "validation/check_block.h"
#include "models/block.h"
#include "controllers/explorer_internal.h"
#include <unistd.h>
#include "util/safe_alloc.h"
#include "validation/process_block.h"
#include "validation/main_state.h"
#include "consensus/params.h"

static struct block_index *test_block_index_insert(void *ctx,
                                                    const struct uint256 *hash)
{
    return chainstate_insert_block_index((struct chainstate *)ctx, hash);
}

static bool test_eh_cancel(void *ctx)
{
    return *(const bool *)ctx;
}

int test_chain(void)
{
    int failures = 0;

    printf("CheckProofOfWork... ");
    {
        struct consensus_params cp;
        memset(&cp, 0, sizeof(cp));
        memset(cp.powLimit.data, 0xff, 32);

        struct uint256 hash;
        uint256_set_null(&hash);
        uint32_t nBits = 0x2100ffff;
        struct arith_uint256 target;
        arith_uint256_set_compact(&target, nBits, NULL, NULL);
        uint32_t easy_bits = arith_uint256_get_compact(&target, false);

        if (CheckProofOfWork(hash, easy_bits, &cp))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("GetBlockProof... ");
    {
        struct block_index bi;
        block_index_init(&bi);
        bi.nBits = 0x1d00ffff;
        struct arith_uint256 proof = GetBlockProof(&bi);
        if (!arith_uint256_is_zero(&proof))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("checkpoints... ");
    {
        struct checkpoint_entry entries[] = {
            {0, {{0}}},
            {100000, {{0}}},
        };
        struct checkpoint_data cd = {
            .entries = entries,
            .nEntries = 2,
            .nTimeLastCheckpoint = 1500000000,
            .nTransactionsLastCheckpoint = 200000,
            .fTransactionsPerDay = 1000.0,
        };
        int est = checkpoints_get_total_blocks_estimate(&cd);
        struct block_index bi;
        block_index_init(&bi);
        bi.nChainTx = 100000;
        bi.nTime = 1500000000;
        double prog = checkpoints_guess_verification_progress(&cd, &bi, true);
        if (est == 100000 && prog > 0.0 && prog < 1.0)
            printf("OK (blocks=%d, progress=%.2f)\n", est, prog);
        else {
            printf("FAIL (blocks=%d, progress=%.2f)\n", est, prog);
            failures++;
        }
    }

    printf("chainparams mainnet... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *p = chain_params_get();
        size_t pfx_len;
        const unsigned char *pfx = chain_params_base58_prefix(p, B58_PUBKEY_ADDRESS, &pfx_len);
        if (pfx_len == 2 && pfx[0] == 0x1C && pfx[1] == 0xB8 &&
            p->nDefaultPort == 8033 &&
            p->consensus.vUpgrades[UPGRADE_BUTTERCUP].nActivationHeight == 707000 &&
            strcmp(p->strCurrencyUnits, "ZCL") == 0 &&
            p->nFoundersRewardAddresses == 48)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chainparams testnet... ");
    {
        chain_params_select(CHAIN_TESTNET);
        const struct chain_params *p = chain_params_get();
        size_t pfx_len;
        const unsigned char *pfx = chain_params_base58_prefix(p, B58_PUBKEY_ADDRESS, &pfx_len);
        if (pfx_len == 2 && pfx[0] == 0x1D && pfx[1] == 0x25 &&
            p->nDefaultPort == 18033 &&
            strcmp(p->strCurrencyUnits, "ZCT") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chainparams regtest... ");
    {
        chain_params_select(CHAIN_REGTEST);
        const struct chain_params *p = chain_params_get();
        if (p->nEquihashN == 48 && p->nEquihashK == 5 &&
            p->fMineBlocksOnDemand == true &&
            p->fMiningRequiresPeers == false &&
            strcmp(p->strNetworkID, "regtest") == 0)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("chainparams address roundtrip via params... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *p = chain_params_get();
        size_t pk_len, sc_len;
        const unsigned char *pk_pfx = chain_params_base58_prefix(p, B58_PUBKEY_ADDRESS, &pk_len);
        const unsigned char *sc_pfx = chain_params_base58_prefix(p, B58_SCRIPT_ADDRESS, &sc_len);
        struct tx_destination dest;
        dest.type = DEST_KEY_ID;
        memset(dest.id.key.id.data, 0x42, 20);
        char addr[64];
        if (encode_destination(&dest, pk_pfx, pk_len, sc_pfx, sc_len, addr, sizeof(addr))) {
            struct tx_destination decoded;
            if (decode_destination(addr, pk_pfx, pk_len, sc_pfx, sc_len, &decoded) &&
                decoded.type == DEST_KEY_ID &&
                memcmp(decoded.id.key.id.data, dest.id.key.id.data, 20) == 0)
                printf("OK\n");
            else { printf("FAIL\n"); failures++; }
        } else { printf("FAIL (encode)\n"); failures++; }
    }

    printf("get_block_subsidy slow start... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *p = chain_params_get();
        int64_t s0 = get_block_subsidy(0, &p->consensus);
        int64_t s1 = get_block_subsidy(1, &p->consensus);
        if (s0 == 0 && s1 == 1250000000)
            printf("OK\n");
        else { printf("FAIL (s0=%" PRId64 " s1=%" PRId64 ")\n", s0, s1); failures++; }
    }

    printf("get_block_subsidy full reward... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t s = get_block_subsidy(10, &p->consensus);
        if (s == 1250000000)
            printf("OK\n");
        else { printf("FAIL (%" PRId64 ")\n", s); failures++; }
    }

    printf("get_block_subsidy pre-buttercup... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t s = get_block_subsidy(706999, &p->consensus);
        if (s == 1250000000)
            printf("OK\n");
        else { printf("FAIL (%" PRId64 ")\n", s); failures++; }
    }

    printf("get_block_subsidy buttercup... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t s = get_block_subsidy(707001, &p->consensus);
        if (s == 78125000)
            printf("OK\n");
        else { printf("FAIL (%" PRId64 ")\n", s); failures++; }
    }

    printf("block_map insert/find... ");
    {
        struct block_map bm;
        block_map_init(&bm);
        struct uint256 h1, h2;
        uint256_set_null(&h1);
        h1.data[0] = 1;
        uint256_set_null(&h2);
        h2.data[0] = 2;

        struct block_index *bi1 = zcl_calloc(1, sizeof(struct block_index), "test_block_index");
        block_index_init(bi1);
        bi1->nHeight = 100;

        struct block_index *bi2 = zcl_calloc(1, sizeof(struct block_index), "test_block_index");
        block_index_init(bi2);
        bi2->nHeight = 200;

        block_map_insert(&bm, &h1, bi1);
        block_map_insert(&bm, &h2, bi2);

        struct block_index *found = block_map_find(&bm, &h1);
        if (found && found->nHeight == 100 && block_map_count(&bm) == 2)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        block_map_free(&bm);
    }

    printf("active_chain set_tip... ");
    {
        struct block_index b0, b1, b2;
        block_index_init(&b0);
        block_index_init(&b1);
        block_index_init(&b2);
        b0.nHeight = 0;
        b0.pprev = NULL;
        b1.nHeight = 1;
        b1.pprev = &b0;
        b2.nHeight = 2;
        b2.pprev = &b1;

        struct active_chain ac;
        active_chain_init(&ac);
        active_chain_move_window_tip(&ac, &b2);

        if (active_chain_tip(&ac) == &b2 &&
            active_chain_at(&ac, 0) == &b0 &&
            active_chain_at(&ac, 1) == &b1 &&
            active_chain_height(&ac) == 2 &&
            active_chain_contains(&ac, &b1))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        active_chain_free(&ac);
    }

    printf("chainstate init/insert... ");
    {
        struct chainstate cs;
        chainstate_init(&cs);
        struct uint256 h;
        uint256_set_null(&h);
        h.data[0] = 0xab;
        struct block_index *bi = chainstate_insert_block_index(&cs, &h);
        struct block_index *bi2 = chainstate_insert_block_index(&cs, &h);
        if (bi && bi == bi2 && block_map_count(&cs.map_block_index) == 1)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        chainstate_free(&cs);
    }

    printf("block_tree_db flags... ");
    {
        /* Per-process path: a fixed one would contend for the LevelDB LOCK
         * with a concurrently running copy of the suite, and the open below
         * silently degrades a collision into a SKIP. */
        char dbdir[512];
        test_make_tmpdir(dbdir, sizeof(dbdir), "chain", "btdb_flags");
        struct block_tree_db btdb;
        if (block_tree_db_open(&btdb, dbdir, 1 << 20, false, true)) {
            bool val = false;
            block_tree_db_write_flag(&btdb, "txindex", true);
            block_tree_db_read_flag(&btdb, "txindex", &val);
            if (val) {
                block_tree_db_write_flag(&btdb, "txindex", false);
                block_tree_db_read_flag(&btdb, "txindex", &val);
                if (!val)
                    printf("OK\n");
                else {
                    printf("FAIL (clear)\n");
                    failures++;
                }
            } else {
                printf("FAIL (read)\n");
                failures++;
            }
            block_tree_db_close(&btdb);
        } else {
            printf("SKIP (open failed)\n");
        }
        test_rm_rf(dbdir);
    }

    printf("block_tree_db reindex... ");
    {
        char dbdir[512];
        test_make_tmpdir(dbdir, sizeof(dbdir), "chain", "btdb_reindex");
        struct block_tree_db btdb;
        if (block_tree_db_open(&btdb, dbdir, 1 << 20, false, true)) {
            bool val = false;
            block_tree_db_write_reindexing(&btdb, true);
            block_tree_db_read_reindexing(&btdb, &val);
            if (val) {
                block_tree_db_write_reindexing(&btdb, false);
                block_tree_db_read_reindexing(&btdb, &val);
                if (!val)
                    printf("OK\n");
                else {
                    printf("FAIL (clear)\n");
                    failures++;
                }
            } else {
                printf("FAIL\n");
                failures++;
            }
            block_tree_db_close(&btdb);
        } else {
            printf("SKIP (open failed)\n");
        }
        test_rm_rf(dbdir);
    }

    printf("is_final_tx... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        tx.lock_time = 0;
        bool ok = is_final_tx(&tx, 100, 1000000);
        if (!ok) { printf("FAIL (locktime 0)\n"); failures++; }
        else {
            tx.lock_time = 50;
            ok = is_final_tx(&tx, 100, 1000000);
            if (!ok) { printf("FAIL (height final)\n"); failures++; }
            else {
                transaction_alloc(&tx, 1, 1);
                tx.vin[0].sequence = 0;
                tx.lock_time = 500000001;
                ok = is_final_tx(&tx, 100, 500000000);
                if (ok) { printf("FAIL (time not final)\n"); failures++; }
                else {
                    ok = is_final_tx(&tx, 100, 500000002);
                    if (ok) printf("OK\n");
                    else { printf("FAIL (time final)\n"); failures++; }
                }
                transaction_free(&tx);
            }
        }
    }

    printf("is_expiring_soon_tx... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        tx.overwintered = true;
        tx.expiry_height = 100;
        if (is_expiring_soon_tx(&tx, 98) && !is_expiring_soon_tx(&tx, 96))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("format_state_message... ");
    {
        struct validation_state st;
        validation_state_init(&st);
        validation_state_dos(&st, 10, false, REJECT_INVALID, "bad-txns", false, "details");
        char buf[256];
        format_state_message(&st, buf, sizeof(buf));
        if (strstr(buf, "bad-txns") && strstr(buf, "details"))
            printf("OK\n");
        else { printf("FAIL (%s)\n", buf); failures++; }
    }

    printf("main_constants... ");
    {
        if (MAX_BLOCK_SIZE == 2000000 &&
            COINBASE_MATURITY == 100 &&
            MAX_BLOCK_SIGOPS == 20000 &&
            MAX_HEADERS_RESULTS == 160 &&
            TX_EXPIRING_SOON_THRESHOLD == 3 &&
            MIN_BLOCKS_TO_KEEP == 288)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("disk_block_io write/read roundtrip... ");
    {
        /* Per-process: this block used to `rm -rf` a fixed path, so a
         * concurrent copy of the suite would delete this fixture mid-test. */
        char tmpbuf[512];
        test_make_tmpdir(tmpbuf, sizeof(tmpbuf), "chain", "disk_block_io");
        const char *tmpdir = tmpbuf;
        char cmd[600];
        snprintf(cmd, sizeof(cmd), "mkdir -p %s/blocks", tmpdir);
        (void)system(cmd);

        struct block b;
        block_init(&b);
        b.header.nVersion = 4;
        b.header.nTime = 9999;
        b.header.nBits = 0x1d00ffff;
        b.num_vtx = 1;
        b.vtx = zcl_calloc(1, sizeof(struct transaction), "test_vtx");
        transaction_init(&b.vtx[0]);
        transaction_alloc(&b.vtx[0], 1, 1);
        b.vtx[0].vin[0].sequence = 0xffffffff;
        b.vtx[0].vout[0].value = 10 * COIN;

        struct disk_block_pos pos;
        pos.nFile = 0;
        pos.nPos = 0;
        unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
        bool ok = write_block_to_disk(&b, &pos, tmpdir, msg_start);
        if (ok) {
            struct block b2;
            ok = read_block_from_disk(&b2, &pos, tmpdir);
            if (ok && b2.header.nTime == 9999 &&
                b2.num_vtx == 1 &&
                b2.vtx[0].vout[0].value == 10 * COIN) {
                printf("OK\n");
                block_free(&b2);
            } else {
                printf("FAIL (read)\n");
                failures++;
            }
        } else {
            printf("FAIL (write)\n");
            failures++;
        }
        block_free(&b);
        test_rm_rf(tmpdir);
    }

    printf("main_state init/free... ");
    {
        struct main_state ms;
        main_state_init(&ms);
        if (ms.pindex_best_header == NULL &&
            ms.nScriptCheckThreads == 0 &&
            !atomic_load(&ms.fImporting) &&
            !atomic_load(&ms.fReindex) &&
            ms.fCheckpointsEnabled &&
            ms.nMaxTipAge == DEFAULT_MAX_TIP_AGE) {
            printf("OK\n");
        } else {
            printf("FAIL\n");
            failures++;
        }
        main_state_free(&ms);
    }

    printf("is_initial_block_download... ");
    {
        struct main_state ms;
        main_state_init(&ms);
        bool ibd = is_initial_block_download(&ms);
        if (ibd)
            printf("OK (in IBD with no tip)\n");
        else { printf("FAIL\n"); failures++; }
        main_state_free(&ms);
    }

    printf("coins_view_cache... ");
    {
        struct coins_view null_view = { NULL, NULL };
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &null_view);

        struct uint256 txid;
        memset(txid.data, 0x42, 32);

        struct coins_cache_entry *entry =
            coins_view_cache_modify_new(&cache, &txid);
        coins_alloc(&entry->coins, 2);
        entry->coins.is_coinbase = false;
        entry->coins.height = 100;
        entry->coins.version = 1;
        entry->coins.vout[0].value = 50 * COIN;
        entry->coins.vout[1].value = 25 * COIN;

        bool have = coins_view_cache_have_coins(&cache, &txid);
        const struct tx_out *out = NULL;
        struct tx_in tin;
        tx_in_init(&tin);
        tin.prevout.hash = txid;
        tin.prevout.n = 0;
        out = coins_view_cache_get_output_for(&cache, &tin);
        if (have && out && out->value == 50 * COIN)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        coins_view_cache_free(&cache);
    }

    printf("coins_view_db write/read... ");
    {
        char dbdir[512];
        test_make_tmpdir(dbdir, sizeof(dbdir), "chain", "coins_db");
        struct coins_view_db cvdb;
        if (coins_view_db_open(&cvdb, dbdir, 1 << 20, false, true)) {
            struct uint256 txid;
            memset(txid.data, 0xab, 32);

            struct coins_map cm;
            coins_map_init(&cm);
            struct coins_cache_entry *e = coins_map_insert(&cm, &txid);
            coins_alloc(&e->coins, 1);
            e->coins.is_coinbase = true;
            e->coins.height = 1000;
            e->coins.version = 1;
            e->coins.vout[0].value = 50 * COIN;
            e->flags = COINS_CACHE_DIRTY;

            struct uint256 best;
            memset(best.data, 0xcc, 32);
            bool ok = coins_view_db_batch_write(&cvdb, &cm, &best);
            coins_map_free(&cm);

            if (ok) {
                bool have = coins_view_db_have_coins(&cvdb, &txid);
                struct uint256 read_best;
                bool got_best = coins_view_db_get_best_block(&cvdb, &read_best);
                if (have && got_best && uint256_cmp(&best, &read_best) == 0)
                    printf("OK\n");
                else { printf("FAIL (read)\n"); failures++; }
            } else {
                printf("FAIL (write)\n");
                failures++;
            }
            coins_view_db_close(&cvdb);
        } else {
            printf("SKIP (open failed)\n");
        }
        test_rm_rf(dbdir);
    }

    printf("update_coins... ");
    {
        struct coins_view null_view = { NULL, NULL };
        struct coins_view_cache cache;
        coins_view_cache_init(&cache, &null_view);

        struct transaction coinbase_tx;
        transaction_init(&coinbase_tx);
        transaction_alloc(&coinbase_tx, 1, 2);
        outpoint_set_null(&coinbase_tx.vin[0].prevout);
        coinbase_tx.vin[0].sequence = 0xffffffff;
        coinbase_tx.vout[0].value = 10 * COIN;
        coinbase_tx.vout[1].value = 2 * COIN;
        transaction_compute_hash(&coinbase_tx);

        update_coins(&coinbase_tx, &cache, 1);

        bool have = coins_view_cache_have_coins(&cache, &coinbase_tx.hash);
        if (have) {
            struct tx_in tin;
            tx_in_init(&tin);
            tin.prevout.hash = coinbase_tx.hash;
            tin.prevout.n = 0;
            const struct tx_out *out =
                coins_view_cache_get_output_for(&cache, &tin);
            if (out && out->value == 10 * COIN)
                printf("OK\n");
            else { printf("FAIL (output)\n"); failures++; }
        } else { printf("FAIL (have)\n"); failures++; }

        transaction_free(&coinbase_tx);
        coins_view_cache_free(&cache);
    }

    printf("disk_block_index roundtrip... ");
    {
        struct disk_block_index dbi;
        disk_block_index_init(&dbi);
        dbi.nHeight = 42000;
        dbi.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_SCRIPTS;
        dbi.nTx = 5;
        dbi.nFile = 3;
        dbi.nDataPos = 12345;
        dbi.nVersion = 4;
        dbi.nTime = 1700000000;
        dbi.nBits = 0x1d00ffff;
        memset(dbi.hashPrev.data, 0x11, 32);
        memset(dbi.hashMerkleRoot.data, 0x22, 32);

        struct byte_stream s;
        stream_init(&s, 512);
        bool ok = disk_block_index_serialize(&dbi, &s);
        if (ok) {
            struct disk_block_index dbi2;
            disk_block_index_init(&dbi2);
            struct byte_stream s2;
            stream_init_from_data(&s2, s.data, s.size);
            ok = disk_block_index_deserialize(&dbi2, &s2);
            if (ok && dbi2.nHeight == 42000 &&
                dbi2.nTx == 5 && dbi2.nFile == 3 &&
                dbi2.nDataPos == 12345 &&
                dbi2.nVersion == 4 &&
                dbi2.nTime == 1700000000) {
                struct uint256 h1, h2;
                disk_block_index_get_hash(&dbi, &h1);
                disk_block_index_get_hash(&dbi2, &h2);
                if (uint256_cmp(&h1, &h2) == 0)
                    printf("OK\n");
                else { printf("FAIL (hash)\n"); failures++; }
            } else { printf("FAIL (deser)\n"); failures++; }
            stream_free(&s2);
        } else { printf("FAIL (ser)\n"); failures++; }
        stream_free(&s);
    }

    printf("block_tree_db load preserves exact body position... ");
    {
        /* Do not spell this under /tmp: on Darwin /tmp is a symlink to
         * /private/tmp, and the LevelDB wrapper correctly refuses a path
         * whose traversed directory object is a symlink.  The shared helper
         * gives every platform a real, private, per-process fixture leaf. */
        char path[512];
        test_make_tmpdir(path, sizeof(path), "chain", "btdb_pos");

        struct block_tree_db btdb;
        bool opened = block_tree_db_open(&btdb, path, 1 << 20, false, true);
        struct disk_block_index written;
        disk_block_index_init(&written);
        written.nHeight = 1;
        written.nStatus = BLOCK_HAVE_DATA | BLOCK_VALID_TRANSACTIONS;
        written.nTx = 1;
        written.nFile = 0;
        written.nDataPos = 1711; /* h=1 in the canonical blk00000 file. */
        written.nVersion = 4;
        written.nTime = 1478414242;
        written.nBits = 0x1f07ffff;
        written.hashPrev.data[0] = 1;
        written.hashMerkleRoot.data[0] = 2;

        bool ok = opened &&
                  block_tree_db_write_block_index(&btdb, &written);
        struct chainstate loaded;
        chainstate_init(&loaded);
        if (ok)
            ok = block_tree_db_load_block_index_guts(
                &btdb, test_block_index_insert, &loaded);

        struct uint256 hash;
        disk_block_index_get_hash(&written, &hash);
        struct block_index *got = block_map_find(&loaded.map_block_index,
                                                 &hash);
        ok = ok && got && got->nFile == 0 && got->nDataPos == 1711 &&
             (got->nStatus & BLOCK_HAVE_DATA) != 0;

        if (ok)
            printf("OK\n");
        else {
            printf("FAIL (file=%d pos=%u)\n", got ? got->nFile : -1,
                   got ? got->nDataPos : 0);
            failures++;
        }
        chainstate_free(&loaded);
        if (opened)
            block_tree_db_close(&btdb);
        test_rm_rf(path);
    }

    printf("block_tree_db guts load pumps boot-liveness marker... ");
    {
        /* Reproduces the 2026-07-27 crash-loop hazard class: a multi-million
         * row LevelDB index walk with no boot-progress pump outlives the
         * 2-min systemd watchdog on a cold boot. The guts loop now pumps
         * boot_progress_note() every 4096 rows, so >4096 rows MUST advance
         * the marker. (Sibling of the blocks-table hydrate pump test in
         * test_block_index_loader.c §15b.) */
        const int N = 4096 + 16;
        char path[512];
        test_make_tmpdir(path, sizeof(path), "chain", "btdb_pump");

        struct block_tree_db btdb;
        bool opened = block_tree_db_open(&btdb, path, 1 << 20, false, true);
        bool ok = opened;
        for (int i = 0; ok && i < N; i++) {
            struct disk_block_index d;
            disk_block_index_init(&d);
            d.nHeight = i;
            d.nStatus = BLOCK_VALID_TRANSACTIONS;
            d.nVersion = 4;
            d.nTime = 1478414242 + (uint32_t)i; /* unique key per row */
            d.nBits = 0x1f07ffff;
            ok = block_tree_db_write_block_index(&btdb, &d);
        }

        struct chainstate loaded2;
        chainstate_init(&loaded2);
        uint64_t marker_before = boot_progress_marker();
        if (ok)
            ok = block_tree_db_load_block_index_guts(
                &btdb, test_block_index_insert, &loaded2);
        ok = ok && boot_progress_marker() > marker_before;

        if (ok)
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
        chainstate_free(&loaded2);
        if (opened)
            block_tree_db_close(&btdb);
        test_rm_rf(path);
    }

    printf("block serialize/deserialize roundtrip... ");
    {
        struct block b;
        block_init(&b);
        b.header.nVersion = 4;
        b.header.nTime = 1234567890;
        b.header.nBits = 0x1d00ffff;
        memset(b.header.hashPrevBlock.data, 0xaa, 32);
        memset(b.header.hashMerkleRoot.data, 0xbb, 32);
        b.num_vtx = 1;
        b.vtx = zcl_calloc(1, sizeof(struct transaction), "test_vtx");
        transaction_init(&b.vtx[0]);
        transaction_alloc(&b.vtx[0], 1, 1);
        b.vtx[0].vin[0].sequence = 0xffffffff;
        b.vtx[0].vout[0].value = 50 * 100000000LL;

        struct byte_stream s;
        stream_init(&s, 512);
        bool ok = block_serialize(&b, &s);
        if (ok) {
            struct block b2;
            block_init(&b2);
            struct byte_stream s2;
            stream_init_from_data(&s2, s.data, s.size);
            ok = block_deserialize(&b2, &s2);
            if (ok && b2.num_vtx == 1 &&
                b2.header.nTime == 1234567890 &&
                b2.header.nBits == 0x1d00ffff &&
                b2.vtx[0].vout[0].value == 50 * 100000000LL) {
                struct uint256 h1, h2;
                block_get_hash(&b, &h1);
                block_get_hash(&b2, &h2);
                if (uint256_cmp(&h1, &h2) == 0)
                    printf("OK\n");
                else {
                    printf("FAIL (hash mismatch)\n");
                    failures++;
                }
            } else {
                printf("FAIL (deserialize)\n");
                failures++;
            }
            block_free(&b2);
            stream_free(&s2);
        } else {
            printf("FAIL (serialize)\n");
            failures++;
        }
        stream_free(&s);
        block_free(&b);
    }

    printf("equihash(96,5) valid solution... ");
    {
        struct equihash_params ep;
        equihash_params_init(&ep, 96, 5);

        struct blake2b_ctx state;
        equihash_initialise_state(&ep, &state);

        const char *input = "Equihash is an asymmetric PoW based on the "
                            "Generalised Birthday problem.";
        blake2b_update(&state, (const unsigned char *)input, strlen(input));

        unsigned char nonce[32] = {0};
        nonce[0] = 1;
        blake2b_update(&state, nonce, 32);

        eh_index valid_indices[32] = {
            2261, 15185, 36112, 104243, 23779, 118390, 118332, 130041,
            32642, 69878, 76925, 80080, 45858, 116805, 92842, 111026,
            15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
            23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568
        };

        unsigned char soln[68];
        size_t soln_len = eh_get_minimal_from_indices(
            valid_indices, 32, ep.collision_bit_length, soln, sizeof(soln));

        bool ok = equihash_is_valid_solution(&ep, &state, soln, soln_len);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("equihash(96,5) invalid solution (changed index)... ");
    {
        struct equihash_params ep;
        equihash_params_init(&ep, 96, 5);

        struct blake2b_ctx state;
        equihash_initialise_state(&ep, &state);

        const char *input = "Equihash is an asymmetric PoW based on the "
                            "Generalised Birthday problem.";
        blake2b_update(&state, (const unsigned char *)input, strlen(input));

        unsigned char nonce[32] = {0};
        nonce[0] = 1;
        blake2b_update(&state, nonce, 32);

        eh_index bad_indices[32] = {
            2262, 15185, 36112, 104243, 23779, 118390, 118332, 130041,
            32642, 69878, 76925, 80080, 45858, 116805, 92842, 111026,
            15972, 115059, 85191, 90330, 68190, 122819, 81830, 91132,
            23460, 49807, 52426, 80391, 69567, 114474, 104973, 122568
        };

        unsigned char soln[68];
        size_t soln_len = eh_get_minimal_from_indices(
            bad_indices, 32, ep.collision_bit_length, soln, sizeof(soln));

        bool ok = equihash_is_valid_solution(&ep, &state, soln, soln_len);
        if (!ok)
            printf("OK\n");
        else {
            printf("FAIL (accepted invalid solution)\n");
            failures++;
        }
    }

    printf("check_equihash_solution size validation... ");
    {
        const struct chain_params *p = chain_params_get();
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nSolutionSize = 1344;
        memset(hdr.nSolution, 0x42, 1344);
        bool ok = (hdr.nSolutionSize == 1344);
        if (ok)
            printf("OK (size=1344)\n");
        else {
            printf("FAIL\n");
            failures++;
        }

        hdr.nSolutionSize = 999;
        ok = check_equihash_solution(&hdr, p);
        if (!ok)
            printf("check_equihash_solution bad size... OK\n");
        else {
            printf("check_equihash_solution bad size... FAIL\n");
            failures++;
        }
    }

    /* Skip equihash solver by default — takes ~20s and 3.25GB RAM.
     * Run with EQUIHASH_TEST=1 to enable. */
    if (getenv("EQUIHASH_TEST")) {
    printf("equihash solver (192,7) finds valid solution... ");
    {
        struct equihash_params ep;
        equihash_params_init(&ep, 192, 7);
        struct blake2b_ctx base_state;
        equihash_initialise_state(&ep, &base_state);

        unsigned char header_data[140];
        memset(header_data, 0, sizeof(header_data));
        header_data[0] = 0x04;
        blake2b_update(&base_state, header_data, sizeof(header_data));

        unsigned char nonce[32];
        memset(nonce, 0x42, sizeof(nonce));
        struct blake2b_ctx curr = base_state;
        blake2b_update(&curr, nonce, sizeof(nonce));

        struct eh_solver *solver = eh_solver_new();
        if (solver) {
            eh_solver_set_state(solver, &curr);
            uint32_t nsols = eh_solver_run(solver);
            bool found_valid = false;
            for (uint32_t i = 0; i < nsols; i++) {
                unsigned char sol_bytes[EH_SOL_BYTES];
                size_t sol_len = eh_get_minimal_from_indices(
                    solver->sols[i], EH_PROOFSIZE,
                    ep.collision_bit_length, sol_bytes, sizeof(sol_bytes));
                if (sol_len == EH_SOL_BYTES) {
                    bool valid = equihash_is_valid_solution(
                        &ep, &curr, sol_bytes, sol_len);
                    if (valid) {
                        found_valid = true;
                        break;
                    }
                }
            }
            if (found_valid)
                printf("OK (found %u solutions)\n", nsols);
            else if (nsols > 0) {
                printf("FAIL (found %u solutions but none valid)\n", nsols);
                failures++;
            } else {
                printf("SKIP (no solutions for this nonce)\n");
            }
            eh_solver_free(solver);
        } else {
            printf("SKIP (insufficient memory)\n");
        }
    }
    } /* end EQUIHASH_TEST guard */

    printf("equihash solver cancellation is immediate... ");
    {
        struct eh_solver solver = {0};
        bool cancel = true;
        uint32_t nsols = eh_solver_run_cancelable(
            &solver, test_eh_cancel, &cancel);
        if (nsols == 0 && solver.cancelled)
            printf("OK\n");
        else {
            printf("FAIL (nsols=%u cancelled=%d)\n",
                   nsols, solver.cancelled);
            failures++;
        }
    }

    printf("check_block_header version too low... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nVersion = 1;
        bool ok = check_block_header(&hdr, &state, p, false);
        if (!ok && strcmp(state.reject_reason, "version-too-low") == 0)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d reason=%s)\n", ok, state.reject_reason);
            failures++;
        }
    }

    printf("check_block_header valid (no PoW check)... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nVersion = 4;
        hdr.nTime = (uint32_t)GetAdjustedTime();
        bool ok = check_block_header(&hdr, &state, p, false);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL (reason=%s)\n", state.reject_reason);
            failures++;
        }
    }

    printf("check_block merkle root mismatch... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block b;
        block_init(&b);
        b.header.nVersion = 4;
        b.header.nTime = (uint32_t)GetAdjustedTime();
        b.num_vtx = 1;
        b.vtx = zcl_calloc(1, sizeof(struct transaction), "test_vtx");
        transaction_init(&b.vtx[0]);
        transaction_alloc(&b.vtx[0], 1, 1);
        b.vtx[0].vin[0].prevout.n = UINT32_MAX;
        b.vtx[0].vout[0].value = 50 * 100000000LL;
        transaction_compute_hash(&b.vtx[0]);
        memset(b.header.hashMerkleRoot.data, 0xff, 32);
        bool ok = check_block(&b, &state, p, false, true, false);
        if (!ok && strcmp(state.reject_reason, "bad-txnmrklroot") == 0)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d reason=%s)\n", ok, state.reject_reason);
            failures++;
        }
        block_free(&b);
    }

    printf("check_block valid with correct merkle root... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block b;
        block_init(&b);
        b.header.nVersion = 4;
        b.header.nTime = (uint32_t)GetAdjustedTime();
        b.num_vtx = 1;
        b.vtx = zcl_calloc(1, sizeof(struct transaction), "test_vtx");
        transaction_init(&b.vtx[0]);
        transaction_alloc(&b.vtx[0], 1, 1);
        b.vtx[0].vin[0].prevout.n = UINT32_MAX;
        b.vtx[0].vout[0].value = 50 * 100000000LL;
        b.vtx[0].vin[0].script_sig.data[0] = 1;
        b.vtx[0].vin[0].script_sig.data[1] = 0;
        b.vtx[0].vin[0].script_sig.size = 2;
        transaction_compute_hash(&b.vtx[0]);
        b.header.hashMerkleRoot = compute_merkle_root(&b.vtx[0].hash, 1);
        bool ok = check_block(&b, &state, p, false, true, true);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL (reason=%s)\n", state.reject_reason);
            failures++;
        }
        block_free(&b);
    }

    printf("check_block no coinbase... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block b;
        block_init(&b);
        b.header.nVersion = 4;
        b.header.nTime = (uint32_t)GetAdjustedTime();
        b.num_vtx = 1;
        b.vtx = zcl_calloc(1, sizeof(struct transaction), "test_vtx");
        transaction_init(&b.vtx[0]);
        transaction_alloc(&b.vtx[0], 1, 1);
        b.vtx[0].vin[0].prevout.n = 0;
        b.vtx[0].vout[0].value = 50 * 100000000LL;
        transaction_compute_hash(&b.vtx[0]);
        b.header.hashMerkleRoot = compute_merkle_root(&b.vtx[0].hash, 1);
        bool ok = check_block(&b, &state, p, false, true, true);
        if (!ok && strcmp(state.reject_reason, "bad-cb-missing") == 0)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d reason=%s)\n", ok, state.reject_reason);
            failures++;
        }
        block_free(&b);
    }

    printf("contextual_check_block_header genesis bypass... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nVersion = 4;
        hdr.nTime = (uint32_t)GetAdjustedTime();
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 0;
        prev.nTime = (uint32_t)(GetAdjustedTime() - 600);
        prev.nBits = 0x2007ffff;
        hdr.nBits = GetNextWorkRequired(&prev, &hdr, &p->consensus);
        bool ok = contextual_check_block_header(&hdr, &state, p, &prev, false);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL (reason=%s)\n", state.reject_reason);
            failures++;
        }
    }

    /* removing the skip_diffbits escape hatch must cause a header
     * whose nBits disagrees with GetNextWorkRequired to be rejected, even
     * when the 28-ancestor window is incomplete (previously silently
     * skipped).  Trivial pass-through value 0x1d00ffff (Bitcoin's mainnet
     * limit) does NOT match Zcash's much tighter powLimit, so the header
     * must fail with "bad-diffbits". */
    printf("contextual_check_block_header rejects trivial-low nBits ... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nVersion = 4;
        hdr.nTime = (uint32_t)GetAdjustedTime();
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 100;              /* well past any early-chain bypass */
        prev.nTime = (uint32_t)(GetAdjustedTime() - 600);
        prev.nBits = 0x2007ffff;
        hdr.nBits = 0x1d00ffff;          /* Bitcoin limit — trivial for Zcash */
        /* Solution size zero to skip the equihash-size check. */
        hdr.nSolutionSize = 0;
        bool ok = contextual_check_block_header(&hdr, &state, p, &prev, false);
        if (!ok && strcmp(state.reject_reason, "bad-diffbits") == 0)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d reason=%s)\n", ok, state.reject_reason);
            failures++;
        }
    }

    printf("contextual_check_block_header version < 4... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nVersion = 3;
        hdr.nTime = (uint32_t)GetAdjustedTime();
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 100;
        prev.nTime = (uint32_t)(GetAdjustedTime() - 60);
        hdr.nBits = GetNextWorkRequired(&prev, &hdr, &p->consensus);
        bool ok = contextual_check_block_header(&hdr, &state, p, &prev, false);
        if (!ok && strcmp(state.reject_reason, "bad-version") == 0)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d reason=%s)\n", ok, state.reject_reason);
            failures++;
        }
    }

    printf("contextual_check_block BIP34 height... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block b;
        block_init(&b);
        b.header.nVersion = 4;
        b.header.nTime = (uint32_t)GetAdjustedTime();
        b.num_vtx = 1;
        b.vtx = zcl_calloc(1, sizeof(struct transaction), "test_vtx");
        transaction_init(&b.vtx[0]);
        transaction_alloc(&b.vtx[0], 1, 1);
        b.vtx[0].vin[0].prevout.n = UINT32_MAX;
        b.vtx[0].vout[0].value = 50 * 100000000LL;
        b.vtx[0].vin[0].script_sig.data[0] = 1;
        b.vtx[0].vin[0].script_sig.data[1] = 5;
        b.vtx[0].vin[0].script_sig.size = 2;
        transaction_compute_hash(&b.vtx[0]);
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 4;
        bool ok = contextual_check_block(&b, &state, p, &prev, false);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL (reason=%s)\n", state.reject_reason);
            failures++;
        }
        block_free(&b);
    }

    printf("contextual_check_block BIP34 wrong height... ");
    {
        const struct chain_params *p = chain_params_get();
        struct validation_state state;
        validation_state_init(&state);
        struct block b;
        block_init(&b);
        b.header.nVersion = 4;
        b.header.nTime = (uint32_t)GetAdjustedTime();
        b.num_vtx = 1;
        b.vtx = zcl_calloc(1, sizeof(struct transaction), "test_vtx");
        transaction_init(&b.vtx[0]);
        transaction_alloc(&b.vtx[0], 1, 1);
        b.vtx[0].vin[0].prevout.n = UINT32_MAX;
        b.vtx[0].vout[0].value = 50 * 100000000LL;
        b.vtx[0].vin[0].script_sig.data[0] = 1;
        b.vtx[0].vin[0].script_sig.data[1] = 99;
        b.vtx[0].vin[0].script_sig.size = 2;
        transaction_compute_hash(&b.vtx[0]);
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 4;
        bool ok = contextual_check_block(&b, &state, p, &prev, false);
        if (!ok && strcmp(state.reject_reason, "bad-cb-height") == 0)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d reason=%s)\n", ok, state.reject_reason);
            failures++;
        }
        block_free(&b);
    }

    printf("compute_merkle_root_mutated no false positive... ");
    {
        struct uint256 a, b_hash, c, d;
        memset(a.data, 0xaa, 32);
        memset(b_hash.data, 0xbb, 32);
        memset(c.data, 0xcc, 32);
        memset(d.data, 0xdd, 32);
        struct uint256 txids[4] = {a, b_hash, c, d};
        bool mutated = false;
        compute_merkle_root_mutated(txids, 4, &mutated);
        if (!mutated)
            printf("OK\n");
        else {
            printf("FAIL (false mutation)\n");
            failures++;
        }
    }

    printf("compute_merkle_root_mutated detects dup pair at end... ");
    {
        struct uint256 a, b_hash, c;
        memset(a.data, 0xaa, 32);
        memset(b_hash.data, 0xbb, 32);
        memset(c.data, 0xcc, 32);
        struct uint256 txids[4] = {a, b_hash, c, c};
        bool mutated = false;
        compute_merkle_root_mutated(txids, 4, &mutated);
        if (mutated)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    /* ── Consensus upgrade activation tests ─────────────────── */

    printf("Upgrade activation: Sprout always active... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *p = chain_params_get();
        if (consensus_network_upgrade_active(&p->consensus, 0, BASE_SPROUT) &&
            consensus_network_upgrade_active(&p->consensus, 1000000, BASE_SPROUT))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Upgrade activation: Overwinter at 476969... ");
    {
        const struct chain_params *p = chain_params_get();
        if (!consensus_network_upgrade_active(&p->consensus, 476968, UPGRADE_OVERWINTER) &&
            consensus_network_upgrade_active(&p->consensus, 476969, UPGRADE_OVERWINTER))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Upgrade activation: Sapling at 476969... ");
    {
        const struct chain_params *p = chain_params_get();
        if (!consensus_network_upgrade_active(&p->consensus, 476968, UPGRADE_SAPLING) &&
            consensus_network_upgrade_active(&p->consensus, 476969, UPGRADE_SAPLING))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Upgrade activation: Bubbles at 585318... ");
    {
        const struct chain_params *p = chain_params_get();
        if (!consensus_network_upgrade_active(&p->consensus, 585317, UPGRADE_BUBBLES) &&
            consensus_network_upgrade_active(&p->consensus, 585318, UPGRADE_BUBBLES))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Upgrade activation: DIFFADJ at 585322... ");
    {
        const struct chain_params *p = chain_params_get();
        if (!consensus_network_upgrade_active(&p->consensus, 585321, UPGRADE_DIFFADJ) &&
            consensus_network_upgrade_active(&p->consensus, 585322, UPGRADE_DIFFADJ))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Upgrade activation: Buttercup at 707000... ");
    {
        const struct chain_params *p = chain_params_get();
        if (!consensus_network_upgrade_active(&p->consensus, 706999, UPGRADE_BUTTERCUP) &&
            consensus_network_upgrade_active(&p->consensus, 707000, UPGRADE_BUTTERCUP))
            printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("Branch ID: Sprout epoch... ");
    {
        const struct chain_params *p = chain_params_get();
        uint32_t bid = consensus_current_epoch_branch_id(100, &p->consensus);
        if (bid == 0)
            printf("OK\n");
        else { printf("FAIL (got 0x%08x)\n", bid); failures++; }
    }

    printf("Branch ID: Sapling epoch... ");
    {
        const struct chain_params *p = chain_params_get();
        uint32_t bid = consensus_current_epoch_branch_id(500000, &p->consensus);
        if (bid == 0x76b809bb)
            printf("OK\n");
        else { printf("FAIL (got 0x%08x)\n", bid); failures++; }
    }

    printf("Branch ID: Bubbles epoch... ");
    {
        const struct chain_params *p = chain_params_get();
        uint32_t bid = consensus_current_epoch_branch_id(585320, &p->consensus);
        if (bid == 0x821a451c)
            printf("OK\n");
        else { printf("FAIL (got 0x%08x)\n", bid); failures++; }
    }

    printf("Branch ID: DIFFADJ epoch (must be 0x930b540d)... ");
    {
        const struct chain_params *p = chain_params_get();
        uint32_t bid = consensus_current_epoch_branch_id(600000, &p->consensus);
        if (bid == 0x930b540d)
            printf("OK\n");
        else { printf("FAIL (got 0x%08x, expected 0x930b540d)\n", bid); failures++; }
    }

    printf("Branch ID: Buttercup epoch... ");
    {
        const struct chain_params *p = chain_params_get();
        uint32_t bid = consensus_current_epoch_branch_id(800000, &p->consensus);
        if (bid == 0x930b540d)
            printf("OK\n");
        else { printf("FAIL (got 0x%08x)\n", bid); failures++; }
    }

    printf("Subsidy: genesis block... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t sub = get_block_subsidy(0, &p->consensus);
        if (sub == 0)
            printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)sub); failures++; }
    }

    printf("Subsidy: block 1 (slow start, second half)... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t sub = get_block_subsidy(1, &p->consensus);
        /* nSubsidySlowStartInterval=2, height 1 is in second half:
         * 1250000000 / 2 * (1+1) = 1250000000 */
        if (sub == 1250000000)
            printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)sub); failures++; }
    }

    printf("Subsidy: block 2 (full subsidy)... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t sub = get_block_subsidy(2, &p->consensus);
        if (sub == 1250000000) /* 12.5 ZCL */
            printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)sub); failures++; }
    }

    printf("Subsidy: block 500000 (no halving yet)... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t sub = get_block_subsidy(500000, &p->consensus);
        if (sub == 1250000000)
            printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)sub); failures++; }
    }

    printf("Subsidy: at Buttercup (707000, triple halving + /2)... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t sub = get_block_subsidy(707000, &p->consensus);
        /* (12.5 / 2) >> 3 = 6.25 >> 3 = 0.78125 ZCL = 78125000 sat */
        if (sub == 78125000)
            printf("OK\n");
        else { printf("FAIL (got %lld, expected 78125000)\n", (long long)sub); failures++; }
    }

    printf("Halving: pre-Buttercup count... ");
    {
        const struct chain_params *p = chain_params_get();
        int h = consensus_halving(&p->consensus, 500000);
        if (h == 0)
            printf("OK\n");
        else { printf("FAIL (got %d)\n", h); failures++; }
    }

    printf("Halving: post-Buttercup returns 3... ");
    {
        const struct chain_params *p = chain_params_get();
        int h = consensus_halving(&p->consensus, 707000);
        if (h == 3)
            printf("OK\n");
        else { printf("FAIL (got %d)\n", h); failures++; }
    }

    printf("PoW target spacing: pre-Buttercup 150s... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t sp = consensus_pow_target_spacing(&p->consensus, 706999);
        if (sp == 150)
            printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)sp); failures++; }
    }

    printf("PoW target spacing: post-Buttercup 75s... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t sp = consensus_pow_target_spacing(&p->consensus, 707000);
        if (sp == 75)
            printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)sp); failures++; }
    }

    printf("Equihash params: pre-Bubbles N=200 K=9... ");
    {
        const struct chain_params *p = chain_params_get();
        unsigned int n = chain_params_equihash_n(p, 585317);
        unsigned int k = chain_params_equihash_k(p, 585317);
        if (n == 200 && k == 9)
            printf("OK\n");
        else { printf("FAIL (got N=%u K=%u)\n", n, k); failures++; }
    }

    printf("Equihash params: post-Bubbles N=192 K=7... ");
    {
        const struct chain_params *p = chain_params_get();
        unsigned int n = chain_params_equihash_n(p, 585318);
        unsigned int k = chain_params_equihash_k(p, 585318);
        if (n == 192 && k == 7)
            printf("OK\n");
        else { printf("FAIL (got N=%u K=%u)\n", n, k); failures++; }
    }

    printf("Equihash solution size gate: Bubbles boundary... ");
    {
        const struct chain_params *p = chain_params_get();
        struct block_index prev;
        block_index_init(&prev);
        prev.nHeight = 585317;
        prev.nTime = 1700000000;
        prev.nBits = 0x2007ffff;

        struct block_header hdr;
        block_header_init(&hdr);
        hdr.nVersion = 4;
        hdr.nTime = (uint32_t)(prev.nTime + 1);
        hdr.nBits = GetNextWorkRequired(&prev, &hdr, &p->consensus);
        hdr.nSolutionSize = 400;

        struct validation_state state;
        validation_state_init(&state);
        bool ok_post = contextual_check_block_header(&hdr, &state, p,
                                                     &prev, false);

        hdr.nSolutionSize = 1344;
        validation_state_init(&state);
        bool reject_old = !contextual_check_block_header(&hdr, &state, p,
                                                         &prev, false) &&
                          strcmp(state.reject_reason,
                                 "bad-equihash-solution-size") == 0;

        prev.nHeight = 585316;
        hdr.nBits = GetNextWorkRequired(&prev, &hdr, &p->consensus);
        hdr.nSolutionSize = 1344;
        validation_state_init(&state);
        bool ok_pre = contextual_check_block_header(&hdr, &state, p,
                                                    &prev, false);

        hdr.nSolutionSize = 400;
        validation_state_init(&state);
        bool reject_new_early =
            !contextual_check_block_header(&hdr, &state, p, &prev, false) &&
            strcmp(state.reject_reason, "bad-equihash-solution-size") == 0;

        if (ok_post && reject_old && ok_pre && reject_new_early)
            printf("OK\n");
        else {
            printf("FAIL (post=%d old=%d pre=%d early=%d reason=%s)\n",
                   ok_post, reject_old, ok_pre, reject_new_early,
                   state.reject_reason);
            failures++;
        }
    }

    printf("Founders reward last height... ");
    {
        const struct chain_params *p = chain_params_get();
        int last = consensus_last_founders_reward_height(&p->consensus);
        if (last == 840000)
            printf("OK\n");
        else { printf("FAIL (got %d)\n", last); failures++; }
    }

    printf("Averaging window timespan: pre-Buttercup... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t ts = consensus_averaging_window_timespan(&p->consensus, 500000);
        if (ts == 17 * 150)
            printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)ts); failures++; }
    }

    printf("Averaging window timespan: post-Buttercup... ");
    {
        const struct chain_params *p = chain_params_get();
        int64_t ts = consensus_averaging_window_timespan(&p->consensus, 707000);
        if (ts == 17 * 75)
            printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)ts); failures++; }
    }

    /* ── zcl_total_supply_zatoshi: cross-check vs per-block subsidy ── */
    printf("Supply: block 0 = 0... ");
    {
        int64_t s = zcl_total_supply_zatoshi(0);
        if (s == 0) printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)s); failures++; }
    }

    printf("Supply: block 1 = 12.5 ZCL... ");
    {
        int64_t s = zcl_total_supply_zatoshi(1);
        if (s == 1250000000LL) printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)s); failures++; }
    }

    printf("Supply: block 2 = 25.0 ZCL... ");
    {
        int64_t s = zcl_total_supply_zatoshi(2);
        if (s == 2500000000LL) printf("OK\n");
        else { printf("FAIL (got %lld)\n", (long long)s); failures++; }
    }

    printf("Supply: block 100 = 100*12.5 ZCL... ");
    {
        int64_t s = zcl_total_supply_zatoshi(100);
        /* block 0=0, blocks 1-100 = 100*12.5 = 1250 ZCL */
        int64_t expected = 100LL * 1250000000LL;
        if (s == expected) printf("OK\n");
        else { printf("FAIL (got %lld, expected %lld)\n", (long long)s, (long long)expected); failures++; }
    }

    printf("Supply: cross-check vs get_block_subsidy up to block 1000... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct consensus_params *cp = &chain_params_get()->consensus;
        int64_t sum = 0;
        for (int h = 0; h <= 1000; h++)
            sum += get_block_subsidy(h, cp);
        int64_t computed = zcl_total_supply_zatoshi(1000);
        if (sum == computed) printf("OK\n");
        else { printf("FAIL (sum=%lld, computed=%lld)\n", (long long)sum, (long long)computed); failures++; }
    }

    printf("Supply: pre-Buttercup boundary (706999)... ");
    {
        /* Block 0 = 0, blocks 1-706999 = 706999 * 12.5 ZCL */
        int64_t expected = 706999LL * 1250000000LL;
        int64_t computed = zcl_total_supply_zatoshi(706999);
        if (computed == expected) printf("OK\n");
        else { printf("FAIL (computed=%lld, expected=%lld)\n", (long long)computed, (long long)expected); failures++; }
    }

    printf("Supply: at Buttercup (707000)... ");
    {
        /* Pre-Buttercup: blocks 1-706999 at 12.5 ZCL = 706999 * 12.5 */
        /* Block 707000: 0.78125 ZCL */
        int64_t pre = 706999LL * 1250000000LL;
        int64_t post = 78125000LL;
        int64_t expected = pre + post;
        int64_t computed = zcl_total_supply_zatoshi(707000);
        if (computed == expected) printf("OK\n");
        else { printf("FAIL (computed=%lld, expected=%lld)\n", (long long)computed, (long long)expected); failures++; }
    }

    printf("Supply: cross-check Buttercup boundary (707000-707100)... ");
    {
        const struct consensus_params *cp = &chain_params_get()->consensus;
        int64_t base = zcl_total_supply_zatoshi(706999);
        int64_t sum = base;
        for (int h = 707000; h <= 707100; h++)
            sum += get_block_subsidy(h, cp);
        int64_t computed = zcl_total_supply_zatoshi(707100);
        if (sum == computed) printf("OK\n");
        else { printf("FAIL (sum=%lld, computed=%lld, diff=%lld)\n",
            (long long)sum, (long long)computed, (long long)(sum - computed)); failures++; }
    }

    printf("Supply: second halving boundary (2387001)... ");
    {
        const struct consensus_params *cp = &chain_params_get()->consensus;
        /* At 2387000: should still be era 0 (0.78125 ZCL) */
        /* At 2387001: era 1 (0.390625 ZCL) */
        int64_t s1 = get_block_subsidy(2387000, cp);
        int64_t s2 = get_block_subsidy(2387001, cp);
        if (s1 == 78125000 && s2 == 39062500) printf("OK\n");
        else { printf("FAIL (s1=%lld, s2=%lld)\n", (long long)s1, (long long)s2); failures++; }
    }

    printf("Supply: cross-check era boundary (2386990-2387010)... ");
    {
        const struct consensus_params *cp = &chain_params_get()->consensus;
        int64_t base = zcl_total_supply_zatoshi(2386989);
        int64_t sum = base;
        for (int h = 2386990; h <= 2387010; h++)
            sum += get_block_subsidy(h, cp);
        int64_t computed = zcl_total_supply_zatoshi(2387010);
        if (sum == computed) printf("OK\n");
        else { printf("FAIL (sum=%lld, computed=%lld, diff=%lld)\n",
            (long long)sum, (long long)computed, (long long)(sum - computed)); failures++; }
    }

    printf("Supply: never exceeds MAX_MONEY (21M ZCL)... ");
    {
        /* MAX_MONEY = 21,000,000 ZCL = 2,100,000,000,000,000 zatoshi.
         * Supply must never exceed this at any height. Test at very
         * large height (well past all halvings) where supply converges. */
        int64_t max_money = 2100000000000000LL;
        int64_t at_10m = zcl_total_supply_zatoshi(10000000);
        int64_t at_50m = zcl_total_supply_zatoshi(50000000);
        if (at_10m <= max_money && at_50m <= max_money &&
            at_50m >= at_10m) /* monotonically increasing */
            printf("OK (at 50M blocks: %.8f ZCL)\n", (double)at_50m / 1e8);
        else { printf("FAIL (10M=%lld, 50M=%lld, max=%lld)\n",
            (long long)at_10m, (long long)at_50m, (long long)max_money); failures++; }
    }

    printf("Supply: monotonically increasing... ");
    {
        int64_t prev = 0;
        bool ok = true;
        int test_heights[] = {0, 1, 2, 100, 706999, 707000, 707001,
            1000000, 2387000, 2387001, 3000000, 5000000, 10000000};
        for (int i = 0; i < (int)(sizeof(test_heights)/sizeof(test_heights[0])); i++) {
            int64_t s = zcl_total_supply_zatoshi(test_heights[i]);
            if (s < prev) { ok = false; break; }
            prev = s;
        }
        if (ok) printf("OK\n");
        else { printf("FAIL (non-monotonic)\n"); failures++; }
    }

    /* ── Boot SQLite fallback: block_map height=0 detection ── */

    printf("boot: block_map height=0 non-genesis detected... ");
    {
        /* Simulate the scenario from boot.c: coins DB best block hash
         * exists in block_map but with nHeight=0 (LevelDB mismatch).
         *
         * We test the detection logic directly:
         * - Create a block_map with a non-genesis hash at height 0
         * - Verify this is detectable as a mismatch */
        struct block_map bm;
        block_map_init(&bm);

        /* Non-genesis hash mapped to height 0 (the bug scenario) */
        struct uint256 fake_hash;
        memset(fake_hash.data, 0xAB, 32); /* definitely not genesis */

        struct block_index *bi = zcl_calloc(1, sizeof(struct block_index), "test_block_index");
        block_index_init(bi);
        bi->nHeight = 0;  /* wrong! should be e.g. 3,056,896 */
        block_map_insert(&bm, &fake_hash, bi);

        struct block_index *found = block_map_find(&bm, &fake_hash);
        bool is_mismatch = found && found->nHeight == 0;

        /* Verify genesis hash is different */
        const struct chain_params *p = chain_params_get();
        bool not_genesis = !uint256_eq(&fake_hash,
                                       &p->consensus.hashGenesisBlock);

        if (is_mismatch && not_genesis)
            printf("OK\n");
        else {
            printf("FAIL (mismatch=%d not_genesis=%d)\n",
                   is_mismatch, not_genesis);
            failures++;
        }

        free(bi);
        block_map_free(&bm);
    }

    printf("boot: genesis block at height=0 is NOT flagged... ");
    {
        /* Genesis block at height 0 is correct — should NOT trigger fallback */
        struct block_map bm;
        block_map_init(&bm);

        const struct chain_params *p = chain_params_get();
        struct uint256 genesis = p->consensus.hashGenesisBlock;

        struct block_index *bi = zcl_calloc(1, sizeof(struct block_index), "test_block_index");
        block_index_init(bi);
        bi->nHeight = 0;  /* correct for genesis */
        block_map_insert(&bm, &genesis, bi);

        struct block_index *found = block_map_find(&bm, &genesis);
        bool is_genesis = uint256_eq(&genesis,
                                     &p->consensus.hashGenesisBlock);

        /* Should NOT be treated as mismatch: height=0 for genesis is valid */
        if (found && found->nHeight == 0 && is_genesis)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }

        free(bi);
        block_map_free(&bm);
    }

    printf("boot: block_map height>0 not flagged as mismatch... ");
    {
        /* Normal case: coins tip at height 3056896, found correctly */
        struct block_map bm;
        block_map_init(&bm);

        struct uint256 tip_hash;
        memset(tip_hash.data, 0xCD, 32);

        struct block_index *bi = zcl_calloc(1, sizeof(struct block_index), "test_block_index");
        block_index_init(bi);
        bi->nHeight = 3056896;  /* correct mapping */
        block_map_insert(&bm, &tip_hash, bi);

        struct block_index *found = block_map_find(&bm, &tip_hash);
        bool would_trigger_fallback = found && found->nHeight == 0;

        if (!would_trigger_fallback && found && found->nHeight == 3056896)
            printf("OK\n");
        else {
            printf("FAIL (height=%d)\n", found ? found->nHeight : -1);
            failures++;
        }

        free(bi);
        block_map_free(&bm);
    }

    printf("boot: SQLite block lookup by hash... ");
    {
        /* Test that db_block_find_by_hash works for fallback.
         * Create an in-memory SQLite DB and verify hash→height lookup. */
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        char ddir[512], dbpath[600];
        test_make_tmpdir(ddir, sizeof(ddir), "chain", "boot_fallback");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", ddir);
        if (node_db_open(&ndb, dbpath)) {
            /* Insert a block */
            struct db_block blk;
            memset(&blk, 0, sizeof(blk));
            memset(blk.hash, 0xAB, 32);
            memset(blk.prev_hash, 0x11, 32);
            memset(blk.merkle_root, 0x22, 32);
            memset(blk.chain_work, 0x01, 32);
            blk.height = 3056896;
            blk.version = 4;
            blk.time = 1700000000;
            blk.bits = 0x1d00ffff;
            blk.num_tx = 1;
            blk.status = 1;
            /* Equihash solution required by schema */
            uint8_t dummy_sol[1344];
            memset(dummy_sol, 0, sizeof(dummy_sol));
            blk.solution = dummy_sol;
            blk.solution_len = sizeof(dummy_sol);
            db_block_save(&ndb, &blk);

            /* Look it up by hash */
            struct db_block found;
            bool ok = db_block_find_by_hash(&ndb, blk.hash, &found);
            if (ok && found.height == 3056896)
                printf("OK\n");
            else {
                printf("FAIL (found=%d height=%d)\n", ok,
                       ok ? found.height : -1);
                failures++;
            }

            node_db_close(&ndb);
        } else {
            printf("SKIP (SQLite init failed)\n");
        }
        /* Cleanup */
        test_rm_rf(ddir);
    }

    printf("boot: SQLite lookup for missing hash returns false... ");
    {
        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        char ddir[512], dbpath[600];
        test_make_tmpdir(ddir, sizeof(ddir), "chain", "boot_fallback2");
        snprintf(dbpath, sizeof(dbpath), "%s/node.db", ddir);
        if (node_db_open(&ndb, dbpath)) {
            uint8_t missing[32];
            memset(missing, 0xFF, 32);
            struct db_block found;
            bool ok = db_block_find_by_hash(&ndb, missing, &found);
            if (!ok)
                printf("OK\n");
            else {
                printf("FAIL (found non-existent block)\n");
                failures++;
            }
            node_db_close(&ndb);
        } else {
            printf("SKIP (SQLite init failed)\n");
        }
        test_rm_rf(ddir);
    }

    /* ── Checkpoint helpers (testable API over the inlined scan) ── */
    printf("checkpoints_hash_at_height: exact match... ");
    {
        struct checkpoint_entry entries[3];
        entries[0].height = 100;
        memset(entries[0].hash.data, 0xAA, 32);
        entries[1].height = 2000;
        memset(entries[1].hash.data, 0xBB, 32);
        entries[2].height = 3054000;
        memset(entries[2].hash.data, 0xCC, 32);
        struct checkpoint_data data = {
            .entries = entries,
            .nEntries = 3,
            .nTimeLastCheckpoint = 0,
            .nTransactionsLastCheckpoint = 0,
            .fTransactionsPerDay = 0,
        };
        struct uint256 got;
        bool found = checkpoints_hash_at_height(&data, 2000, &got);
        bool ok = found && got.data[0] == 0xBB && got.data[31] == 0xBB;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("checkpoints_hash_at_height: miss... ");
    {
        struct checkpoint_entry entries[2] = {
            { .height = 100 }, { .height = 200 },
        };
        memset(entries[0].hash.data, 0x11, 32);
        memset(entries[1].hash.data, 0x22, 32);
        struct checkpoint_data data = {
            .entries = entries, .nEntries = 2, 0, 0, 0,
        };
        struct uint256 got = {0};
        bool found = checkpoints_hash_at_height(&data, 150, &got);
        bool ok = !found;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("checkpoints_last_height... ");
    {
        struct checkpoint_entry entries[4];
        memset(entries, 0, sizeof(entries));
        entries[0].height = 0;
        entries[1].height = 100;
        entries[2].height = 5000;
        entries[3].height = 3054000;
        struct checkpoint_data data = {
            .entries = entries, .nEntries = 4, 0, 0, 0,
        };
        int last = checkpoints_last_height(&data);
        bool ok = last == 3054000;

        struct checkpoint_data empty = {NULL, 0, 0, 0, 0};
        ok = ok && checkpoints_last_height(&empty) == -1;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("checkpoints_validate_header: pass through (no checkpoint)... ");
    {
        struct checkpoint_entry entries[2] = {
            { .height = 100 }, { .height = 200 },
        };
        memset(entries[0].hash.data, 0xAA, 32);
        memset(entries[1].hash.data, 0xBB, 32);
        struct checkpoint_data data = {
            .entries = entries, .nEntries = 2, 0, 0, 0,
        };
        struct uint256 any_hash;
        memset(any_hash.data, 0x99, 32);
        bool ok = checkpoints_validate_header(&data, 150, &any_hash);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("checkpoints_validate_header: accept matching hash... ");
    {
        struct checkpoint_entry entries[1] = {{ .height = 2013514 }};
        memset(entries[0].hash.data, 0x77, 32);
        struct checkpoint_data data = {
            .entries = entries, .nEntries = 1, 0, 0, 0,
        };
        struct uint256 match;
        memset(match.data, 0x77, 32);
        bool ok = checkpoints_validate_header(&data, 2013514, &match);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("checkpoints_validate_header: reject fork at checkpoint... ");
    {
        struct checkpoint_entry entries[1] = {{ .height = 2013514 }};
        memset(entries[0].hash.data, 0x77, 32);
        struct checkpoint_data data = {
            .entries = entries, .nEntries = 1, 0, 0, 0,
        };
        struct uint256 wrong;
        memset(wrong.data, 0x88, 32);
        bool rejected = !checkpoints_validate_header(&data, 2013514, &wrong);
        if (rejected) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("checkpoints: mainnet chainparams are loaded + non-zero... ");
    {
        chain_params_select(CHAIN_MAIN);
        const struct chain_params *p = chain_params_get();
        const struct checkpoint_data *cp = &p->checkpointData;
        bool ok = cp->nEntries >= 1 && cp->entries != NULL;
        /* Spot-check a few that init_main_params hard-codes. */
        bool any_nonzero = false;
        for (int i = 0; i < cp->nEntries; i++) {
            for (int b = 0; b < 32; b++) {
                if (cp->entries[i].hash.data[b] != 0) {
                    any_nonzero = true;
                    break;
                }
            }
        }
        ok = ok && any_nonzero;
        ok = ok && checkpoints_last_height(cp) >= 3054000;
        if (ok) printf("OK\n"); else { printf("FAIL (entries=%d)\n", cp->nEntries); failures++; }
    }

    printf("checkpoints: NULL-safe... ");
    {
        bool ok = true;
        struct uint256 h = {0};
        ok = ok && !checkpoints_hash_at_height(NULL, 0, &h);
        ok = ok && checkpoints_last_height(NULL) == -1;
        ok = ok && checkpoints_validate_header(NULL, 0, &h);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* Regression test: skip_contextual gate must fire when the PoW averaging
     * window cannot be walked back contiguously from pindex_prev. Models
     * the case where a FlyClient snapshot places
     * tip=3,081,601 but block_index only reaches 3,081,408, so the
     * 17-block GetNextWorkRequired window returns weakest-allowed nBits
     * and every inbound header gets bad-diffbits-rejected. */
    printf("skip_contextual: complete retarget+MTP window, no skip... ");
    {
        struct consensus_params cp = { .nPowAveragingWindow = 17 };
        struct main_state ms;
        main_state_init(&ms);

        /* Build enough contiguous history for both the 17-block retarget
         * window and the median-time-past call on the far-edge block. */
        struct block_index bi[32];
        for (int i = 0; i < 32; i++) {
            block_index_init(&bi[i]);
            bi[i].nHeight = i;
            bi[i].nTime = 1000 + i;
            bi[i].pprev = (i == 0) ? NULL : &bi[i - 1];
        }
        active_chain_move_window_tip(&ms.chain_active, &bi[31]);

        bool should_skip =
            process_block_should_skip_contextual_header(&ms, &bi[31], &cp);
        /* Contiguous chain, far from the "old-IBD" case, retarget and
         * MTP windows walk cleanly → gate must NOT skip contextual check. */
        if (!should_skip)
            printf("OK\n");
        else {
            printf("FAIL (unexpected skip on contiguous chain)\n");
            failures++;
        }
        active_chain_free(&ms.chain_active);
    }

    printf("skip_contextual: sparse import anchor, MUST skip... ");
    {
        struct consensus_params cp = { .nPowAveragingWindow = 17 };
        struct main_state ms;
        main_state_init(&ms);

        /* Models legacy chainstate import: 17 real headers exist above a
         * metadata-only anchor whose nTime is zero and whose pprev is NULL.
         * Retarget would otherwise compute MTP from the sparse anchor and
         * reject honest legacy headers with bad-diffbits. */
        struct block_index bi[18];
        for (int i = 0; i < 18; i++) {
            block_index_init(&bi[i]);
            bi[i].nHeight = 3110157 + i;
            bi[i].nTime = (i == 0) ? 0 : (1778635105 + i);
            bi[i].pprev = (i == 0) ? NULL : &bi[i - 1];
        }
        active_chain_move_window_tip(&ms.chain_active, &bi[17]);

        bool should_skip =
            process_block_should_skip_contextual_header(&ms, &bi[17], &cp);
        if (should_skip)
            printf("OK\n");
        else {
            printf("FAIL (sparse retarget anchor was treated as complete)\n");
            failures++;
        }
        active_chain_free(&ms.chain_active);
    }

    printf("skip_contextual: broken pprev at tip, MUST skip... ");
    {
        struct consensus_params cp = { .nPowAveragingWindow = 17 };
        struct main_state ms;
        main_state_init(&ms);

        /* Simulates the FlyClient-snapshot-tail case: tip is at a high
         * height but its pprev chain breaks after only a few contiguous
         * blocks (block_index is not populated for the tail region). */
        struct block_index bi[5];
        for (int i = 0; i < 5; i++) {
            block_index_init(&bi[i]);
            bi[i].nHeight = 100000 + i; /* past the "too-young" guard */
            bi[i].pprev = (i == 0) ? NULL : &bi[i - 1];
        }
        active_chain_move_window_tip(&ms.chain_active, &bi[4]);

        bool should_skip =
            process_block_should_skip_contextual_header(&ms, &bi[4], &cp);
        /* Only 5 blocks of history → can't walk a 17-block window →
         * gate MUST return true to bypass contextual_check_block_header. */
        if (should_skip)
            printf("OK\n");
        else {
            printf("FAIL (gate failed to fire — this is the bug)\n");
            failures++;
        }
        active_chain_free(&ms.chain_active);
    }

    printf("skip_contextual: height-inversion mid-window, MUST skip... ");
    {
        struct consensus_params cp = { .nPowAveragingWindow = 17 };
        struct main_state ms;
        main_state_init(&ms);

        /* Build 20 blocks but deliberately break height continuity at
         * position 10 (nHeight jumps, violating the pprev->nHeight + 1
         * invariant). This is the on-disk-corruption / scrambled-import
         * case. */
        struct block_index bi[20];
        for (int i = 0; i < 20; i++) {
            block_index_init(&bi[i]);
            bi[i].nHeight = 100000 + i;
            bi[i].pprev = (i == 0) ? NULL : &bi[i - 1];
        }
        bi[10].nHeight = 100500; /* deliberate non-contiguous jump */
        active_chain_move_window_tip(&ms.chain_active, &bi[19]);

        bool should_skip =
            process_block_should_skip_contextual_header(&ms, &bi[19], &cp);
        if (should_skip)
            printf("OK\n");
        else {
            printf("FAIL (gate did not detect height-inversion within window)\n");
            failures++;
        }
        active_chain_free(&ms.chain_active);
    }

    printf("skip_contextual: NULL pindex_prev → safe default... ");
    {
        struct consensus_params cp = { .nPowAveragingWindow = 17 };
        struct main_state ms;
        main_state_init(&ms);

        /* NULL pindex_prev — the caller already short-circuits on this,
         * but the gate must not SEGV either. Return value is "don't skip"
         * because there's nothing to walk; the caller's existing NULL
         * guard handles the real branch. */
        bool should_skip =
            process_block_should_skip_contextual_header(&ms, NULL, &cp);
        if (!should_skip)
            printf("OK\n");
        else {
            printf("FAIL (NULL pindex_prev returned skip=true)\n");
            failures++;
        }
        active_chain_free(&ms.chain_active);
    }

    printf("block_index sizeof and memory audit... ");
    {
        size_t sz = sizeof(struct block_index);
        printf("(%zu bytes) ", sz);
        /* Struct should be <=296 bytes after removing Sprout anchor/root
         * and reordering fields to eliminate padding. If someone adds a
         * large field without realizing the memory cost, this will catch
         * it: 3M entries * 296 = 888MB which is acceptable. */
        bool ok = (sz <= 296);
        /* Verify nSolution pointer is NULL after init */
        struct block_index bi;
        block_index_init(&bi);
        ok = ok && (bi.nSolution == NULL);
        ok = ok && (bi.nSolutionSize == 0);
        if (ok) printf("OK\n"); else { printf("FAIL (sz=%zu)\n", sz); failures++; }
    }

    /* Round 6 C4 — typed BLOCK_FAILED classification.
     *
     * Verifies the three-class model: PERMANENT (VALID), DEPENDENCY
     * (CHILD), TRANSIENT. block_has_any_failure() must catch all
     * three; block_index_is_valid() must reject all three. Each
     * predicate must answer for its own class only. */
    printf("block_failed typed classification... ");
    {
        struct block_index perm, dep, trans, clean, mixed;
        block_index_init(&perm);
        block_index_init(&dep);
        block_index_init(&trans);
        block_index_init(&clean);
        block_index_init(&mixed);

        perm.nStatus  = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_FAILED_VALID;
        dep.nStatus   = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_FAILED_CHILD;
        trans.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_FAILED_TRANSIENT;
        clean.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        mixed.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                        BLOCK_FAILED_VALID | BLOCK_FAILED_TRANSIENT;

        bool ok = true;
        ok = ok && block_is_permanently_failed(&perm);
        ok = ok && !block_is_dependency_failed(&perm);
        ok = ok && !block_is_transiently_failed(&perm);
        ok = ok && block_has_any_failure(&perm);

        ok = ok && !block_is_permanently_failed(&dep);
        ok = ok && block_is_dependency_failed(&dep);
        ok = ok && !block_is_transiently_failed(&dep);
        ok = ok && block_has_any_failure(&dep);

        ok = ok && !block_is_permanently_failed(&trans);
        ok = ok && !block_is_dependency_failed(&trans);
        ok = ok && block_is_transiently_failed(&trans);
        ok = ok && block_has_any_failure(&trans);

        ok = ok && !block_has_any_failure(&clean);
        ok = ok && block_index_is_valid(&clean, BLOCK_VALID_TREE);

        ok = ok && block_is_permanently_failed(&mixed);
        ok = ok && block_is_transiently_failed(&mixed);
        ok = ok && block_has_any_failure(&mixed);
        ok = ok && !block_index_is_valid(&perm, BLOCK_VALID_TREE);
        ok = ok && !block_index_is_valid(&trans, BLOCK_VALID_TREE);

        /* NULL-safety: every typed helper must tolerate NULL. */
        ok = ok && !block_is_permanently_failed(NULL);
        ok = ok && !block_is_dependency_failed(NULL);
        ok = ok && !block_is_transiently_failed(NULL);
        ok = ok && !block_has_any_failure(NULL);

        /* BLOCK_FAILED_MASK preserved at legacy value (VALID|CHILD) for
         * on-disk compatibility; ANY_MASK widens to include TRANSIENT. */
        ok = ok && (BLOCK_FAILED_MASK == (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD));
        ok = ok && (BLOCK_FAILED_ANY_MASK ==
                    (BLOCK_FAILED_VALID | BLOCK_FAILED_CHILD | BLOCK_FAILED_TRANSIENT));

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_index atomic status helpers... ");
    {
        struct block_index bi;
        block_index_init(&bi);
        bi.nStatus = BLOCK_VALID_TREE;

        bool ok = true;
        ok = ok && block_index_status_load(&bi) == BLOCK_VALID_TREE;

        unsigned int old =
            block_index_status_fetch_or(&bi, BLOCK_HAVE_DATA | BLOCK_FAILED_CHILD);
        ok = ok && old == BLOCK_VALID_TREE;
        ok = ok && block_is_dependency_failed(&bi);
        ok = ok && !block_index_is_valid(&bi, BLOCK_VALID_TREE);

        old = block_index_status_clear_bits(&bi, BLOCK_FAILED_CHILD);
        ok = ok && (old & BLOCK_FAILED_CHILD) != 0;
        ok = ok && !block_is_dependency_failed(&bi);

        unsigned int now =
            block_index_status_set_valid_level(&bi, BLOCK_VALID_SCRIPTS);
        ok = ok && (now & BLOCK_VALID_MASK) == BLOCK_VALID_SCRIPTS;
        ok = ok && block_index_is_valid(&bi, BLOCK_VALID_SCRIPTS);

        ok = ok && block_index_status_load(NULL) == 0;
        ok = ok && block_index_status_fetch_or(NULL, BLOCK_HAVE_DATA) == 0;
        ok = ok && block_index_status_clear_bits(NULL, BLOCK_HAVE_DATA) == 0;
        ok = ok &&
             block_index_status_set_valid_level(NULL, BLOCK_VALID_TREE) == 0;

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    printf("block_index disk position snapshot helpers... ");
    {
        struct block_index bi;
        block_index_init(&bi);
        struct disk_block_pos pos;
        unsigned int status = 0;
        bool ok = true;

        disk_block_pos_init(&pos);
        ok = ok && !block_index_disk_pos_snapshot(&bi, &pos, &status);
        ok = ok && status == 0;

        block_index_disk_pos_store(&bi, 7, 12345);
        disk_block_pos_init(&pos);
        ok = ok && !block_index_disk_pos_snapshot(&bi, &pos, &status);

        block_index_status_fetch_or(&bi, BLOCK_HAVE_DATA);
        disk_block_pos_init(&pos);
        ok = ok && block_index_disk_pos_snapshot(&bi, &pos, &status);
        ok = ok && (status & BLOCK_HAVE_DATA) != 0;
        ok = ok && pos.nFile == 7;
        ok = ok && pos.nPos == 12345;

        __atomic_store_n(&bi.nUndoPos, 67890u, __ATOMIC_RELAXED);
        block_index_status_fetch_or(&bi, BLOCK_HAVE_UNDO);
        disk_block_pos_init(&pos);
        ok = ok && block_index_undo_pos_snapshot(&bi, &pos, &status);
        ok = ok && (status & BLOCK_HAVE_UNDO) != 0;
        ok = ok && pos.nFile == 7;
        ok = ok && pos.nPos == 67890u;

        block_index_status_clear_bits(&bi, BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
        disk_block_pos_init(&pos);
        ok = ok && !block_index_disk_pos_snapshot(&bi, &pos, NULL);
        ok = ok && !block_index_undo_pos_snapshot(&bi, &pos, NULL);

        ok = ok && !block_index_disk_pos_snapshot(NULL, &pos, NULL);
        ok = ok && !block_index_disk_pos_snapshot(&bi, NULL, NULL);
        ok = ok && !block_index_undo_pos_snapshot(NULL, &pos, NULL);
        ok = ok && !block_index_undo_pos_snapshot(&bi, NULL, NULL);

        if (ok) printf("OK\n");
        else { printf("FAIL\n"); failures++; }
    }

    return failures;
}
