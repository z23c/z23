/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for block_index_loader service — flat file save/load,
 * SQLite cache save/load, round-trip integrity, and edge cases.
 */

#include "test/test_core.h"
#include "services/block_index_loader.h"
#include "services/block_index_cache_envelope.h"
#include "services/block_index_integrity.h"
#include "services/chain_tip.h"
#include "storage/sha3_sidecar_io.h"
#include "storage/progress_store.h"
#include "storage/coins_kv.h"
#include "jobs/tip_finalize_stage.h"
#include "jobs/stage_repair.h"
#include "services/block_row_verify.h"
#include "util/blocker.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "chain/checkpoints.h"
#include "primitives/block.h"
#include "chain/chain.h"
#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "chain/pow.h"
#include "core/arith_uint256.h"
#include "models/block.h"
#include "util/blocker.h"
#include "util/boot_phase.h"
#include "support/log_throttle.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "test/setup_result.h"

#define BIL_CHECK(name, expr) do {          \
    printf("%s... ", (name));              \
    if ((expr)) printf("OK\n");            \
    else { printf("FAIL\n"); failures++; } \
} while (0)

/* Build a minimal block_index chain of `n` blocks in main_state. */
static void build_synthetic_chain(struct main_state *ms, int n)
{
    struct uint256 hashes[2048];
    int limit = n < 2048 ? n : 2048;

    for (int h = 0; h < limit; h++) {
        memset(&hashes[h], 0, sizeof(hashes[h]));
        hashes[h].data[0] = (uint8_t)(h & 0xFF);
        hashes[h].data[1] = (uint8_t)((h >> 8) & 0xFF);
        hashes[h].data[2] = (uint8_t)((h >> 16) & 0xFF);
        hashes[h].data[3] = 0xAA;

        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)ms, &hashes[h]);
        if (!pi) continue;

        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = 1000000 + (uint32_t)h * 150;
        pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        pi->nFile = h / 1000;
        pi->nDataPos = (uint32_t)(h * 2048);

        if (h > 0) {
            struct block_index *prev = block_map_find(
                &ms->map_block_index, &hashes[h - 1]);
            if (prev) {
                pi->pprev = prev;
                struct arith_uint256 proof = GetBlockProof(pi);
                arith_uint256_add(&pi->nChainWork,
                                  &prev->nChainWork, &proof);
                pi->nChainTx = prev->nChainTx + pi->nTx;
            }
        } else {
            pi->nChainWork = GetBlockProof(pi);
            pi->nChainTx = 1;
        }
    }
}

static struct uint256 make_test_hash(int h)
{
    struct uint256 hash;
    memset(&hash, 0, sizeof(hash));
    hash.data[0] = (uint8_t)(h & 0xFF);
    hash.data[1] = (uint8_t)((h >> 8) & 0xFF);
    hash.data[2] = (uint8_t)((h >> 16) & 0xFF);
    hash.data[3] = 0xAA;
    return hash;
}

/* Create the node.db `blocks` table (the real schema columns the hydrate
 * loader reads + the NOT NULL companions) in an in-memory db. */
static bool bih_create_blocks_table(sqlite3 *db)
{
    return sqlite3_exec(db,
        "CREATE TABLE blocks("
        "hash BLOB PRIMARY KEY,height INTEGER NOT NULL,"
        "prev_hash BLOB NOT NULL,version INTEGER NOT NULL,"
        "merkle_root BLOB NOT NULL,time INTEGER NOT NULL,"
        "bits INTEGER NOT NULL,nonce BLOB NOT NULL,"
        "solution BLOB NOT NULL,chain_work BLOB NOT NULL,"
        "status INTEGER NOT NULL DEFAULT 0,"
        "file_num INTEGER,data_pos INTEGER,undo_pos INTEGER,"
        "num_tx INTEGER NOT NULL DEFAULT 0,"
        "sapling_root BLOB,sprout_root BLOB,"
        "sapling_value INTEGER DEFAULT 0,"
        "sprout_value INTEGER DEFAULT 0)",
        NULL, NULL, NULL) == SQLITE_OK;
}

/* Build a deterministic header at height h linked to `prev`, insert a
 * header-only `blocks` row (status=SCRIPTS but NO HAVE_DATA, chain_work=0 —
 * exactly what --importblockindex writes), and return its real PoW hash so the
 * stored `hash` column hash-binds. Returns false on any DB error. */
static bool bih_insert_header_row(sqlite3 *db, int h,
                                  const struct uint256 *prev,
                                  struct uint256 *out_hash)
{
    struct block_header hdr;
    block_header_init(&hdr);
    hdr.nVersion = 4;
    hdr.hashPrevBlock = *prev;
    memset(hdr.hashMerkleRoot.data, 0, 32);
    hdr.hashMerkleRoot.data[0] = (uint8_t)(h & 0xFF);
    hdr.hashMerkleRoot.data[1] = (uint8_t)((h >> 8) & 0xFF);
    hdr.hashMerkleRoot.data[31] = 0x5A;
    memset(hdr.hashFinalSaplingRoot.data, 0, 32);
    hdr.hashFinalSaplingRoot.data[0] = (uint8_t)(h & 0xFF);
    hdr.hashFinalSaplingRoot.data[30] = 0x11;
    hdr.nTime = 1000000 + (uint32_t)h * 150;
    hdr.nBits = 0x1f07ffff;
    memset(hdr.nNonce.data, 0, 32);
    hdr.nNonce.data[0] = (uint8_t)(h & 0xFF);
    hdr.nNonce.data[1] = 0xC3;
    hdr.nSolutionSize = 32;
    for (int i = 0; i < 32; i++)
        hdr.nSolution[i] = (uint8_t)(i + h);

    /* Mine (bump nTime) until the real header hash meets the PoW target at
     * nBits — the hydrate loader's canonical per-row verify now runs hash-bind
     * + CheckProofOfWork on every row (POINT 1 admission parity), exactly as a
     * genuine imported header already satisfies its own network difficulty.
     * Cheap SHA256d search (no Equihash: these low heights sit below the
     * stride / ROM-checkpoint gate). Compares against the decoded target the
     * same way CheckProofOfWork does, but without its per-attempt log storm. */
    {
        bool neg = false, of = false;
        struct arith_uint256 target;
        arith_uint256_set_compact(&target, hdr.nBits, &neg, &of);
        if (neg || of || arith_uint256_is_zero(&target))
            return false;
        bool mined = false;
        for (uint32_t tries = 0; tries < 2000000u; tries++) {
            hdr.nTime = 1231006505u + tries;
            block_header_get_hash(&hdr, out_hash);
            struct arith_uint256 ha;
            uint256_to_arith(&ha, out_hash);
            if (arith_uint256_compare(&ha, &target) <= 0) {
                mined = true;
                break;
            }
        }
        if (!mined)
            return false;
    }

    uint8_t zero32[32] = {0};
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,"
            "time,bits,nonce,solution,chain_work,status,file_num,data_pos,"
            "undo_pos,num_tx,sapling_root,sprout_root,sapling_value,"
            "sprout_value) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    sqlite3_bind_blob(s, 1, out_hash->data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 2, h);
    sqlite3_bind_blob(s, 3, hdr.hashPrevBlock.data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 4, hdr.nVersion);
    sqlite3_bind_blob(s, 5, hdr.hashMerkleRoot.data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 6, hdr.nTime);
    sqlite3_bind_int64(s, 7, hdr.nBits);
    sqlite3_bind_blob(s, 8, hdr.nNonce.data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 9, hdr.nSolution, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 10, zero32, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 11, BLOCK_VALID_SCRIPTS);   /* no HAVE bits */
    sqlite3_bind_int(s, 12, 0);
    sqlite3_bind_int(s, 13, 0);
    sqlite3_bind_int(s, 14, 0);
    sqlite3_bind_int(s, 15, 1);
    sqlite3_bind_blob(s, 16, hdr.hashFinalSaplingRoot.data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 17, zero32, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 18, 0);
    sqlite3_bind_int64(s, 19, 0);
    bool ok = (sqlite3_step(s) == SQLITE_DONE);
    sqlite3_finalize(s);
    return ok;
}

int test_block_index_loader(void)
{
    printf("\n=== block index loader tests ===\n");
    int failures = 0;

    /* ── 1. Flat file round-trip ─────────────────────────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 100);

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_flat", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);

        save_block_index_flat(tmpdir, &ms);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);
        struct stat st;
        bool file_ok = (stat(path, &st) == 0 && st.st_size > 8);

        /* Embedded single-file format (task #32): the body itself starts
         * with the 48-byte "BIIE" integrity header, and NO separate
         * sidecar file is written. */
        bool embedded_header_ok = false;
        {
            FILE *bf = fopen(path, "rb");
            if (bf) {
                struct ssio_sidecar_header hdr;
                if (fread(&hdr, 1, sizeof(hdr), bf) == sizeof(hdr))
                    embedded_header_ok =
                        (memcmp(hdr.magic, BII_EMBEDDED_MAGIC, 4) == 0 &&
                         hdr.version == BII_EMBEDDED_VERSION);
                fclose(bf);
            }
        }
        char sidecar_path[512];
        snprintf(sidecar_path, sizeof(sidecar_path), "%s/block_index.bin.sha3",
                 tmpdir);
        bool no_sidecar = (stat(sidecar_path, &st) != 0);

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);

        bool loaded = file_ok && load_block_index_flat(tmpdir, &ms2).ok;
        bool count_ok = loaded && (ms2.map_block_index.size == ms.map_block_index.size);

        uint8_t point_hash[32], point_root[32], zero_root[32] = {0};
        struct uint256 expected_point_hash = make_test_hash(42);
        struct zcl_result point = block_index_flat_header_at(
            tmpdir, 42, point_hash, point_root);
        bool point_ok = point.ok &&
            memcmp(point_hash, expected_point_hash.data, 32) == 0 &&
            memcmp(point_root, zero_root, 32) == 0;

        bool heights_ok = count_ok;
        for (int h = 0; h < 100 && heights_ok; h++) {
            struct uint256 hash = make_test_hash(h);
            struct block_index *pi = block_map_find(&ms2.map_block_index, &hash);
            if (!pi || pi->nHeight != h) heights_ok = false;
        }

        BIL_CHECK("bil: flat save embeds integrity header, writes no sidecar",
                  file_ok && embedded_header_ok && no_sidecar);
        BIL_CHECK("bil: point read returns exact block hash + Sapling root",
                  point_ok);
        BIL_CHECK("bil: flat file round-trip preserves 100 entries", heights_ok);

        unlink(sidecar_path);
        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── 2. Flat file pprev linking ──────────────────────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 50);

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_pprev", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);

        save_block_index_flat(tmpdir, &ms);

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);
        ZCL_TEST_SETUP(load_block_index_flat(tmpdir, &ms2));

        struct uint256 tip_hash = make_test_hash(49);
        struct block_index *tip = block_map_find(&ms2.map_block_index, &tip_hash);
        bool ok = (tip != NULL && tip->nHeight == 49);

        int walk = 0;
        struct block_index *cur = tip;
        while (cur && walk < 100) { walk++; cur = cur->pprev; }
        ok = ok && (walk == 50);

        BIL_CHECK("bil: flat file pprev walk from h=49 to genesis (50 hops)", ok);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);
        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── 2b. Scrambled stored height loads WITHOUT a pprev lasso ─────────
     * Regression fixture for the live-cure wedge root cause: the flat loader's
     * old by-HEIGHT pprev fallback wired a WRONG parent whenever a stored
     * height label was scrambled, forming a pprev cycle the scoped ancestry
     * relink could only fail-closed (cycle=1) refuse. The loader now links
     * pprev HASH-ONLY: a prev_hash that misses resolves to NULL (honest), never
     * a height guess.
     *
     * Shape: node P has a prev_hash that is NOT in the file (its parent is not
     * loaded); node C is P's REAL child (C.prev_hash == P.hash, so it links by
     * hash) but C's stored height is scrambled to P.height-1. Under the deleted
     * fallback, P's missing prev_hash resolved to by_height[P.height-1] == C —
     * P.pprev = C while C.pprev = P is a 2-node lasso. Hash-only linking leaves
     * P.pprev == NULL, so the graph is acyclic. */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);

        /* Ghost parent: a hash P points at that we DO NOT insert, so it is not
         * saved and P's prev_hash misses on reload. */
        struct uint256 ghost_hash = make_test_hash(900);
        struct block_index ghost;
        block_index_init(&ghost);
        ghost.hashBlock = ghost_hash;
        ghost.phashBlock = &ghost.hashBlock;

        struct uint256 p_hash = make_test_hash(10);
        struct uint256 c_hash = make_test_hash(11);
        struct block_index *P = chainstate_insert_block_index(
            (struct chainstate *)&ms, &p_hash);
        struct block_index *C = chainstate_insert_block_index(
            (struct chainstate *)&ms, &c_hash);
        bool built = (P && C);
        if (built) {
            P->nHeight = 10;
            P->nBits = 0x1f07ffff;
            P->nTime = 1000000;
            P->nVersion = 4;
            P->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
            P->nTx = 1;
            P->pprev = &ghost;               /* saved prev_hash = ghost (misses) */

            C->nBits = 0x1f07ffff;
            C->nTime = 1000150;
            C->nVersion = 4;
            C->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
            C->nTx = 1;
            C->pprev = P;                    /* saved prev_hash = P.hash (links) */
            C->nHeight = 9;                  /* SCRAMBLE: == P.height - 1 */
        }

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_nolasso", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);
        if (built)
            save_block_index_flat(tmpdir, &ms);

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);
        bool loaded = built && load_block_index_flat(tmpdir, &ms2).ok;

        struct block_index *P2 = loaded
            ? block_map_find(&ms2.map_block_index, &p_hash) : NULL;
        struct block_index *C2 = loaded
            ? block_map_find(&ms2.map_block_index, &c_hash) : NULL;

        /* P's missing parent resolves to NULL — NEVER the height-guessed C. */
        BIL_CHECK("bil: scrambled height — missing parent is NULL, not "
                  "height-guessed",
                  P2 != NULL && P2->pprev == NULL);
        /* C's hash linkage to P survives (hash-only linking is not affected). */
        BIL_CHECK("bil: scrambled height — child still hash-links to its "
                  "real parent", C2 != NULL && C2->pprev == P2);

        /* The graph is acyclic: a bounded pprev walk from every node
         * terminates well within the node count (a lasso would spin to the
         * cap). */
        bool acyclic = (P2 && C2);
        if (acyclic) {
            int steps = 0;
            for (struct block_index *cur = C2; cur && steps < 8; steps++)
                cur = cur->pprev;
            acyclic = acyclic && (steps <= 2);   /* C2 -> P2 -> NULL */
        }
        BIL_CHECK("bil: scrambled height — pprev graph is acyclic (no lasso)",
                  acyclic);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);
        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── 3. Flat file bad magic rejected ─────────────────── */

    {
        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_badm", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);
        FILE *f = fopen(path, "wb");
        bool ok = (f != NULL);
        if (f) {
            uint32_t bad_magic = 0xDEADBEEF, count = 0;
            fwrite(&bad_magic, 4, 1, f);
            fwrite(&count, 4, 1, f);
            fclose(f);

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            block_map_init(&ms.map_block_index);
            active_chain_init(&ms.chain_active);
            ok = ok && !load_block_index_flat(tmpdir, &ms).ok;
            block_map_free(&ms.map_block_index);
        }

        BIL_CHECK("bil: flat file rejects bad magic", ok);

        unlink(path);
        rmdir(tmpdir);
    }

    /* ── 4. Flat file truncated rejected ─────────────────── */

    {
        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_trunc", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);
        FILE *f = fopen(path, "wb");
        bool ok = (f != NULL);
        if (f) {
            uint32_t magic = 0x5A434C49, count = 100;
            fwrite(&magic, 4, 1, f);
            fwrite(&count, 4, 1, f);
            fclose(f);

            struct main_state ms;
            memset(&ms, 0, sizeof(ms));
            block_map_init(&ms.map_block_index);
            active_chain_init(&ms.chain_active);
            ok = ok && !load_block_index_flat(tmpdir, &ms).ok;
            block_map_free(&ms.map_block_index);
        }

        BIL_CHECK("bil: flat file rejects truncated file", ok);

        unlink(path);
        rmdir(tmpdir);
    }

    /* ── 5. SQLite round-trip ────────────────────────────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 1500);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool ok = (sqlite3_open(":memory:", &ndb.db) == SQLITE_OK);
        ndb.open = ok;

        if (ok) {
            sqlite3_exec(ndb.db,
                "CREATE TABLE block_index_cache ("
                "hash BLOB PRIMARY KEY,"
                "prev_hash BLOB,"
                "height INTEGER,"
                "n_bits INTEGER,"
                "n_time INTEGER,"
                "n_version INTEGER,"
                "n_status INTEGER,"
                "n_file INTEGER,"
                "n_data_pos INTEGER,"
                "n_undo_pos INTEGER,"
                "n_tx INTEGER,"
                "chain_work BLOB,"
                "n_cached_branch_id INTEGER,"
                "n_chain_tx INTEGER"
                ")", NULL, NULL, NULL);

            save_block_index_recent(&ndb, &ms);

            sqlite3_stmt *cnt = NULL;
            sqlite3_prepare_v2(ndb.db,
                "SELECT COUNT(*) FROM block_index_cache", -1, &cnt, NULL);
            int64_t saved = 0;
            if (sqlite3_step(cnt) == SQLITE_ROW)
                saved = sqlite3_column_int64(cnt, 0);
            sqlite3_finalize(cnt);
            ok = ok && (saved >= 1500);

            struct main_state ms2;
            memset(&ms2, 0, sizeof(ms2));
            block_map_init(&ms2.map_block_index);
            active_chain_init(&ms2.chain_active);

            ok = ok && load_block_index_sqlite(&ndb, &ms2).ok;
            ok = ok && (ms2.map_block_index.size >= 1500);

            block_map_free(&ms2.map_block_index);
            sqlite3_close(ndb.db);
        }

        BIL_CHECK("bil: SQLite cache round-trip (1500 entries)", ok);

        block_map_free(&ms.map_block_index);
    }

    /* ── 6. SQLite rejects small cache ───────────────────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 500);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool ok = (sqlite3_open(":memory:", &ndb.db) == SQLITE_OK);
        ndb.open = ok;

        if (ok) {
            sqlite3_exec(ndb.db,
                "CREATE TABLE block_index_cache ("
                "hash BLOB PRIMARY KEY,"
                "prev_hash BLOB,"
                "height INTEGER,"
                "n_bits INTEGER,"
                "n_time INTEGER,"
                "n_version INTEGER,"
                "n_status INTEGER,"
                "n_file INTEGER,"
                "n_data_pos INTEGER,"
                "n_undo_pos INTEGER,"
                "n_tx INTEGER,"
                "chain_work BLOB,"
                "n_cached_branch_id INTEGER,"
                "n_chain_tx INTEGER"
                ")", NULL, NULL, NULL);

            save_block_index_recent(&ndb, &ms);

            struct main_state ms2;
            memset(&ms2, 0, sizeof(ms2));
            block_map_init(&ms2.map_block_index);
            active_chain_init(&ms2.chain_active);

            ok = ok && !load_block_index_sqlite(&ndb, &ms2).ok;

            block_map_free(&ms2.map_block_index);
            sqlite3_close(ndb.db);
        }

        BIL_CHECK("bil: SQLite load rejects cache with < 1000 entries", ok);

        block_map_free(&ms.map_block_index);
    }

    /* ── 6b. SQLite cache integrity envelope: tamper -> demote -> rebuild ──
     * Wave N hardening (docs/work/FORWARD_PLAN.md item 7.3): the SQLite
     * cache carries an XOR-combined SHA3 envelope (block_index_cache_
     * envelope) verified in the SAME O(rows) load pass. A tampered row
     * must be DETECTED (never silently trusted), DEMOTE the cache (discard
     * + typed blocker, never refuse boot — it is a pure re-derivable
     * cache), and a subsequent clean save+load must succeed and clear the
     * blocker — "boots without FATAL" is not the bar; H*-equivalent proof
     * here is the fresh rebuild actually loading every entry back. */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 1500);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool ok = (sqlite3_open(":memory:", &ndb.db) == SQLITE_OK);
        ndb.open = ok;

        if (ok) {
            sqlite3_exec(ndb.db,
                "CREATE TABLE block_index_cache ("
                "hash BLOB PRIMARY KEY,"
                "prev_hash BLOB,"
                "height INTEGER,"
                "n_bits INTEGER,"
                "n_time INTEGER,"
                "n_version INTEGER,"
                "n_status INTEGER,"
                "n_file INTEGER,"
                "n_data_pos INTEGER,"
                "n_undo_pos INTEGER,"
                "n_tx INTEGER,"
                "chain_work BLOB,"
                "n_cached_branch_id INTEGER,"
                "n_chain_tx INTEGER"
                ");"
                "CREATE TABLE block_index_cache_envelope ("
                "envelope_id INTEGER PRIMARY KEY,"
                "row_count INTEGER NOT NULL,"
                "content_sha3 BLOB NOT NULL,"
                "written_at INTEGER NOT NULL)",
                NULL, NULL, NULL);

            save_block_index_recent(&ndb, &ms);

            int64_t env_rows = 0;
            sqlite3_stmt *ec = NULL;
            sqlite3_prepare_v2(ndb.db,
                "SELECT COUNT(*) FROM block_index_cache_envelope", -1,
                &ec, NULL);
            if (sqlite3_step(ec) == SQLITE_ROW)
                env_rows = sqlite3_column_int64(ec, 0);
            sqlite3_finalize(ec);
            ok = ok && env_rows == 1;

            /* Tamper ONE cached row's n_bits — content changes, row_count
             * does not, so this exercises the digest mismatch path (not
             * the row-count mismatch path). */
            sqlite3_exec(ndb.db,
                "UPDATE block_index_cache SET n_bits=n_bits+1 "
                "WHERE height=750", NULL, NULL, NULL);

            uint64_t demotions_before =
                block_index_cache_envelope_demotions_for_testing();

            struct main_state ms2;
            memset(&ms2, 0, sizeof(ms2));
            block_map_init(&ms2.map_block_index);
            active_chain_init(&ms2.chain_active);

            struct zcl_result tampered = load_block_index_sqlite(&ndb, &ms2);
            ok = ok && !tampered.ok;
            ok = ok && block_index_cache_envelope_demotions_for_testing() ==
                           demotions_before + 1;
            ok = ok && ms2.map_block_index.size == 0;
            ok = ok && blocker_exists("block_index_cache.integrity_demoted");

            int64_t cache_rows_after_demote = -1;
            sqlite3_stmt *cc = NULL;
            sqlite3_prepare_v2(ndb.db,
                "SELECT COUNT(*) FROM block_index_cache", -1, &cc, NULL);
            if (sqlite3_step(cc) == SQLITE_ROW)
                cache_rows_after_demote = sqlite3_column_int64(cc, 0);
            sqlite3_finalize(cc);
            ok = ok && cache_rows_after_demote == 0;

            /* REBUILD: a fresh, clean save from the original (untampered)
             * `ms` re-derives the cache; the next load must succeed and the
             * blocker must self-clear. This is the "never refuses boot,
             * always re-derivable" proof — not just "no crash". */
            save_block_index_recent(&ndb, &ms);

            struct main_state ms3;
            memset(&ms3, 0, sizeof(ms3));
            block_map_init(&ms3.map_block_index);
            active_chain_init(&ms3.chain_active);

            struct zcl_result rebuilt = load_block_index_sqlite(&ndb, &ms3);
            ok = ok && rebuilt.ok;
            ok = ok && ms3.map_block_index.size >= 1500;
            ok = ok && !blocker_exists("block_index_cache.integrity_demoted");

            block_map_free(&ms3.map_block_index);
            block_map_free(&ms2.map_block_index);
            sqlite3_close(ndb.db);
        }

        BIL_CHECK("bil: SQLite cache envelope detects tamper, demotes, "
                 "rebuilds clean", ok);

        block_map_free(&ms.map_block_index);
    }

    /* ── 7. Flat file chain_work preserved ───────────────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 20);

        struct uint256 tip_hash = make_test_hash(19);
        struct block_index *orig_tip = block_map_find(&ms.map_block_index, &tip_hash);
        struct arith_uint256 orig_work = {0};
        bool ok = (orig_tip != NULL);
        if (ok) orig_work = orig_tip->nChainWork;

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_cw", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);

        if (ok) save_block_index_flat(tmpdir, &ms);

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);

        if (ok) ok = load_block_index_flat(tmpdir, &ms2).ok;
        if (ok) {
            struct block_index *loaded = block_map_find(&ms2.map_block_index, &tip_hash);
            ok = ok && loaded && (arith_uint256_compare(&loaded->nChainWork, &orig_work) == 0);
        }

        BIL_CHECK("bil: flat file preserves chain_work at height 19", ok);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);
        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── 8. Missing flat file returns false ───────────────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);

        bool ok = !load_block_index_flat("/nonexistent/path", &ms).ok;

        BIL_CHECK("bil: load_block_index_flat returns false for missing file", ok);

        block_map_free(&ms.map_block_index);
    }

    /* ── 9. Embedded format: corrupted payload byte rejected ── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 30);

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_corrupt", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);
        save_block_index_flat(tmpdir, &ms);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);

        /* Flip a byte deep in the payload (well past the 48-byte header). */
        FILE *bf = fopen(path, "r+b");
        bool wrote = false;
        if (bf) {
            if (fseek(bf, BII_EMBEDDED_HEADER_BYTES + 64, SEEK_SET) == 0) {
                int c = fgetc(bf);
                if (c != EOF &&
                    fseek(bf, BII_EMBEDDED_HEADER_BYTES + 64, SEEK_SET) == 0) {
                    fputc(c ^ 0xFF, bf);
                    wrote = true;
                }
            }
            fclose(bf);
        }

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);
        bool rejected = wrote && !load_block_index_flat(tmpdir, &ms2).ok;

        BIL_CHECK("bil: embedded format rejects corrupted payload", rejected);

        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── 10. Embedded format: truncated file rejected ───────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 30);

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_etrunc", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);
        save_block_index_flat(tmpdir, &ms);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);

        /* Truncate the file to half its size — payload no longer matches
         * the embedded body_size, so the hash/size check must reject it. */
        struct stat st;
        bool tok = (stat(path, &st) == 0 && st.st_size > 200);
        if (tok) tok = (truncate(path, st.st_size / 2) == 0);

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);
        bool rejected = tok && !load_block_index_flat(tmpdir, &ms2).ok;

        BIL_CHECK("bil: embedded format rejects truncated file", rejected);

        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── 11. Embedded format: header-only file rejected ─────── */

    {
        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_hdronly", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);

        /* A valid-magic embedded header that claims a non-zero payload,
         * with NO payload bytes following — the size check must reject. */
        struct ssio_sidecar_header hdr;
        memset(&hdr, 0, sizeof(hdr));
        memcpy(hdr.magic, BII_EMBEDDED_MAGIC, 4);
        hdr.version = BII_EMBEDDED_VERSION;
        hdr.body_size = 200;  /* claim payload we will not write */
        FILE *f = fopen(path, "wb");
        bool wrote = (f != NULL);
        if (f) { wrote = (fwrite(&hdr, sizeof(hdr), 1, f) == 1); fclose(f); }

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        bool rejected = wrote && !load_block_index_flat(tmpdir, &ms).ok;

        BIL_CHECK("bil: embedded format rejects header-only file", rejected);

        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
    }

    /* ── 12. Legacy two-file format still loads ─────────────── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 40);

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_legacy", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);

        /* Hand-write a LEGACY body: "ZCLI" magic + count + entries at
         * offset 0, no embedded header. Then stamp a matching sidecar
         * (the pre-task-#32 on-disk shape) so the first boot after deploy
         * loads cleanly. */
        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);

        /* Build the legacy body by saving the embedded format then
         * stripping the 48-byte header back off — gives a byte-identical
         * legacy payload + lets us stamp the legacy sidecar over it. */
        save_block_index_flat(tmpdir, &ms);
        bool legacy_ok = false;
        {
            FILE *src = fopen(path, "rb");
            if (src) {
                struct stat st;
                if (stat(path, &st) == 0 &&
                    (size_t)st.st_size > BII_EMBEDDED_HEADER_BYTES) {
                    size_t plen = (size_t)st.st_size - BII_EMBEDDED_HEADER_BYTES;
                    uint8_t *payload = malloc(plen);  // raw-alloc-ok:test-fixture
                    if (payload &&
                        fseek(src, BII_EMBEDDED_HEADER_BYTES, SEEK_SET) == 0 &&
                        fread(payload, 1, plen, src) == plen) {
                        fclose(src); src = NULL;
                        FILE *dst = fopen(path, "wb");
                        if (dst) {
                            legacy_ok = (fwrite(payload, 1, plen, dst) == plen);
                            fclose(dst);
                        }
                    }
                    free(payload);
                }
                if (src) fclose(src);
            }
        }
        /* Stamp the legacy sidecar over the legacy body. */
        if (legacy_ok)
            legacy_ok = bii_write_sidecar(tmpdir).ok;

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);
        bool loaded = legacy_ok && load_block_index_flat(tmpdir, &ms2).ok;
        bool count_ok = loaded &&
            (ms2.map_block_index.size == ms.map_block_index.size);
        struct block_index_flat_identity stale_identity;
        bool legacy_unbound = !block_index_flat_verified_identity(
            tmpdir, &stale_identity);

        /* The legacy body verifies through the sidecar path. */
        bool verify_ok = count_ok &&
            (bii_verify(tmpdir, NULL, NULL, NULL, 0) == BII_OK);

        BIL_CHECK("bil: legacy two-file format still loads + verifies",
                  count_ok && verify_ok && legacy_unbound);

        char sidecar_path[512];
        snprintf(sidecar_path, sizeof(sidecar_path),
                 "%s/block_index.bin.sha3", tmpdir);
        unlink(sidecar_path);
        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── 13. Legacy body, missing sidecar = SIDECAR_MISSING ── */

    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 40);

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_nosc", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);

        /* Legacy body (strip the embedded header) with NO sidecar. */
        save_block_index_flat(tmpdir, &ms);
        bool legacy_ok = false;
        {
            FILE *src = fopen(path, "rb");
            if (src) {
                struct stat st;
                if (stat(path, &st) == 0 &&
                    (size_t)st.st_size > BII_EMBEDDED_HEADER_BYTES) {
                    size_t plen = (size_t)st.st_size - BII_EMBEDDED_HEADER_BYTES;
                    uint8_t *payload = malloc(plen);  // raw-alloc-ok:test-fixture
                    if (payload &&
                        fseek(src, BII_EMBEDDED_HEADER_BYTES, SEEK_SET) == 0 &&
                        fread(payload, 1, plen, src) == plen) {
                        fclose(src); src = NULL;
                        FILE *dst = fopen(path, "wb");
                        if (dst) {
                            legacy_ok = (fwrite(payload, 1, plen, dst) == plen);
                            fclose(dst);
                        }
                    }
                    free(payload);
                }
                if (src) fclose(src);
            }
        }

        /* The body still loads (legacy magic), and bii_verify reports
         * SIDECAR_MISSING — exactly today's first-run-after-upgrade
         * behavior, which boot accepts. */
        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);
        bool loaded = legacy_ok && load_block_index_flat(tmpdir, &ms2).ok;
        bool missing_ok = loaded &&
            (bii_verify(tmpdir, NULL, NULL, NULL, 0) == BII_SIDECAR_MISSING);

        BIL_CHECK("bil: legacy body with no sidecar = SIDECAR_MISSING (accepted)",
                  missing_ok);

        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── 14. seed_tip_from_finalized: genesis-root install + REFUSE cases ──
     *
     * Regression guard for the kill-9-at-genesis recovery. A
     * fresh regtest node mined N blocks, was kill-9'd, and rebooted to a NULL
     * active tip while the durable tip_finalize cursor + coins were at N. The
     * genesis-root branch of block_index_loader_seed_tip_from_finalized must
     * INSTALL the tip at N (rooted at the canonical genesis) yet REFUSE every
     * unsafe variant: an oversized walk (mainnet floor cap), a link missing
     * HAVE_DATA/VALID_SCRIPTS, a non-canonical genesis terminus, and
     * coins_applied_height <= tip_height. It also must still cleanly extend an
     * existing live tip (cur_tip != NULL, the unchanged branch). */
    {
        chain_params_select(CHAIN_REGTEST);
        const struct chain_params *cp = chain_params_get();
        const struct uint256 gen = cp->consensus.hashGenesisBlock;

        char dir[256];
        mkdir("./test-tmp", 0755);
        test_fmt_tmpdir(dir, sizeof(dir), "bil_seedfin", "main");
        mkdir(dir, 0755);

        progress_store_close();
        bool store_ok = progress_store_open(dir);
        sqlite3 *db = store_ok ? progress_store_db() : NULL;
        BIL_CHECK("bil/seedfin: progress_store opens", store_ok && db);

        /* Build a synthetic regtest chain 0..N whose GENESIS hash is the real
         * params genesis (so the canonical-terminus check can pass), with the
         * rest of the chain HAVE_DATA + VALID_SCRIPTS + contiguous pprev. */
        const int N = 5;
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);

        struct uint256 hashes[16];
        for (int h = 0; h <= N; h++) {
            if (h == 0) {
                hashes[0] = gen;
            } else {
                memset(&hashes[h], 0, sizeof(hashes[h]));
                hashes[h].data[0] = (uint8_t)(h & 0xFF);
                hashes[h].data[31] = 0xC2; /* distinct from genesis */
            }
            struct block_index *pi = chainstate_insert_block_index(
                (struct chainstate *)&ms, &hashes[h]);
            if (pi) {
                pi->nHeight = h;
                pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
                pi->nTx = 1;
                pi->nBits = 0x200f0f0f;
                if (h > 0) {
                    struct block_index *prev = block_map_find(
                        &ms.map_block_index, &hashes[h - 1]);
                    pi->pprev = prev;
                    if (prev) {
                        struct arith_uint256 proof = GetBlockProof(pi);
                        arith_uint256_add(&pi->nChainWork, &prev->nChainWork,
                                          &proof);
                        pi->nChainTx = prev->nChainTx + pi->nTx;
                    }
                } else {
                    pi->nChainWork = GetBlockProof(pi);
                    pi->nChainTx = 1;
                }
            }
        }
        /* phashBlock must point at per-node storage (the canonical-terminus
         * memcmp reads node->phashBlock->data). */
        {
            size_t it = 0; struct block_index *pi; const struct uint256 *hp;
            while (block_map_next(&ms.map_block_index, &it, &hp, &pi)) {
                if (pi && hp) { pi->hashBlock = *hp; pi->phashBlock = &pi->hashBlock; }
            }
        }
        struct block_index *tipN = block_map_find(&ms.map_block_index, &hashes[N]);

        /* Register the tip_finalize stage so seed_anchor can stamp the
         * served-tip cursor (the value resolve_durable_tip reads). Without
         * tip_finalize_stage_handle() the cursor stamp is skipped and the
         * durable tip never resolves. */
        bool tf_init = tip_finalize_stage_init(&ms);
        BIL_CHECK("bil/seedfin: tip_finalize stage init", tf_init);

        /* Seed the durable finalized anchor at N (cursor -> N, own-hash). */
        bool anchor_ok = db && tf_init &&
            tip_finalize_stage_seed_anchor(N, hashes[N].data, true);
        BIL_CHECK("bil/seedfin: durable anchor seeded at N", anchor_ok);

        /* Helper: set coins_kv applied_height directly. The utxo_apply cursor
         * convention stores the NEXT height to apply, so tip N is coin-backed
         * only when coins_applied_height >= N+1. */
        #define BIL_SET_APPLIED(H) do {                                       \
            if (db) {                                                         \
                sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL);        \
                coins_kv_set_applied_height_in_tx(db, (H));                   \
                sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);                 \
            }                                                                 \
        } while (0)

        /* (iv-pre) coins_applied ABSENT → refuse (cur_tip NULL, no install). */
        int r_no_coins = db ? block_index_loader_seed_tip_from_finalized(
                                  &ms, cp, db) : 1;
        BIL_CHECK("bil/seedfin: REFUSE when coins_applied absent (<N)",
                  r_no_coins == 0 && active_chain_tip(&ms.chain_active) == NULL);

        /* (iv-a) coins_applied = N-1 (< N) → refuse (finalized>coins). */
        BIL_SET_APPLIED(N - 1);
        int r_low_coins = db ? block_index_loader_seed_tip_from_finalized(
                                   &ms, cp, db) : 1;
        BIL_CHECK("bil/seedfin: REFUSE when coins_applied < tip_height",
                  r_low_coins == 0 && active_chain_tip(&ms.chain_active) == NULL);

        /* (iv-b) coins_applied = N still means coins are applied through N-1,
         * so publishing tip N must refuse too. */
        BIL_SET_APPLIED(N);
        int r_equal_coins = db ? block_index_loader_seed_tip_from_finalized(
                                     &ms, cp, db) : 1;
        BIL_CHECK("bil/seedfin: REFUSE when coins_applied == tip_height",
                  r_equal_coins == 0 &&
                  active_chain_tip(&ms.chain_active) == NULL);

        /* Raise coins to N+1 for the install + remaining structural cases. */
        BIL_SET_APPLIED(N + 1);

        /* (ii) a mid-chain link missing HAVE_DATA → refuse. Clear it, test,
         * restore it. */
        struct block_index *mid = block_map_find(&ms.map_block_index, &hashes[3]);
        uint32_t saved_status = mid ? mid->nStatus : 0;
        if (mid) mid->nStatus &= ~(uint32_t)BLOCK_HAVE_DATA;
        int r_nodata = db ? block_index_loader_seed_tip_from_finalized(
                                &ms, cp, db) : 1;
        BIL_CHECK("bil/seedfin: REFUSE when a mid link lacks HAVE_DATA",
                  r_nodata == 0 && active_chain_tip(&ms.chain_active) == NULL);
        if (mid) mid->nStatus = saved_status;

        /* (iii) non-canonical genesis terminus → refuse. Re-point genesis's
         * stored hash to a NON-params value (height stays 0, HAVE_DATA set),
         * so the terminus memcmp fails. Restore after. */
        struct block_index *g0 = block_map_find(&ms.map_block_index, &hashes[0]);
        struct uint256 saved_g0 = g0 ? g0->hashBlock : gen;
        if (g0) {
            struct uint256 fake = gen; fake.data[0] ^= 0xFF;
            g0->hashBlock = fake;
            g0->phashBlock = &g0->hashBlock;
        }
        int r_nongen = db ? block_index_loader_seed_tip_from_finalized(
                                &ms, cp, db) : 1;
        BIL_CHECK("bil/seedfin: REFUSE when terminus is non-canonical genesis",
                  r_nongen == 0 && active_chain_tip(&ms.chain_active) == NULL);
        if (g0) { g0->hashBlock = saved_g0; g0->phashBlock = &g0->hashBlock; }

        /* (v) ALL preconditions hold → INSTALL h=N, cur_tip was NULL,
         * active_chain_tip() == tipN afterward. */
        int r_install = db ? block_index_loader_seed_tip_from_finalized(
                                 &ms, cp, db) : 0;
        BIL_CHECK("bil/seedfin: INSTALL genesis-root h=N (cur_tip NULL)",
                  r_install == 1 &&
                  active_chain_tip(&ms.chain_active) == tipN &&
                  active_chain_height(&ms.chain_active) == N);

        /* (vi) extend-live-chain branch (cur_tip != NULL) still returns 1 and
         * lands pointer-equal. Reset the active tip DOWN to a live tip at N-2
         * (a forward-only rewind is allowed for repair installs), then the
         * seed's walk N..N-1 must land on the N-2 tip and re-install N. The
         * durable cursor is still at N from the install above. */
        {
            struct block_index *live = block_map_find(&ms.map_block_index,
                                                      &hashes[N - 2]);
            (void)chain_set_active_tip(&ms, live, TIP_FROM_RESTORE,
                                       "bil_seedfin_extend_setup");
            BIL_SET_APPLIED(N + 1);
            int r_ext = (db && live)
                ? block_index_loader_seed_tip_from_finalized(&ms, cp, db) : 0;
            BIL_CHECK("bil/seedfin: extend-live-chain branch installs h=N",
                      r_ext == 1 &&
                      active_chain_tip(&ms.chain_active) == tipN &&
                      active_chain_height(&ms.chain_active) == N);
        }

        #undef BIL_SET_APPLIED

        /* Done with the shared cursor/stage; tear it down before the isolated
         * oversized-walk case opens its OWN progress store + stage so the
         * big_h anchor cannot clobber the cases above. */
        tip_finalize_stage_shutdown();
        progress_store_close();
        block_map_free(&ms.map_block_index);
        test_cleanup_tmpdir(dir);

        /* (i) oversized walk (tip_height - 0 > MAX_GAP) → refuse. Isolated
         * store + stage, fresh ms, cur_tip NULL, a single tip node at a height
         * beyond the cap with a durable anchor there. The MAX_GAP bound check
         * fires BEFORE the walk — the load-bearing mainnet refusal. */
        {
            char dir2[256];
            test_fmt_tmpdir(dir2, sizeof(dir2), "bil_seedfin_big", "main");
            mkdir(dir2, 0755);
            progress_store_close();
            bool s2 = progress_store_open(dir2);
            sqlite3 *db2 = s2 ? progress_store_db() : NULL;

            struct main_state ms2;
            memset(&ms2, 0, sizeof(ms2));
            block_map_init(&ms2.map_block_index);
            active_chain_init(&ms2.chain_active);
            bool tf2 = tip_finalize_stage_init(&ms2);

            int big_h = BLOCK_INDEX_LOADER_SEED_MAX_GAP + 10000; /* 60000 */
            struct uint256 bh;
            memset(&bh, 0, sizeof(bh));
            bh.data[0] = 0x77; bh.data[1] = 0xEE; bh.data[31] = 0xC2;
            struct block_index *bn = chainstate_insert_block_index(
                (struct chainstate *)&ms2, &bh);
            if (bn) {
                bn->nHeight = big_h;
                bn->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
                bn->hashBlock = bh; bn->phashBlock = &bn->hashBlock;
            }
            /* coins_applied = big_h+1 so ONLY the MAX_GAP cap can be the
             * refuser (the precondition would otherwise also refuse). */
            if (db2) {
                sqlite3_exec(db2, "BEGIN IMMEDIATE", NULL, NULL, NULL);
                coins_kv_set_applied_height_in_tx(db2, big_h + 1);
                sqlite3_exec(db2, "COMMIT", NULL, NULL, NULL);
            }
            bool anchor2 = db2 && tf2 &&
                tip_finalize_stage_seed_anchor(big_h, bh.data, true);
            int r_big = (db2 && anchor2)
                ? block_index_loader_seed_tip_from_finalized(&ms2, cp, db2) : 1;
            BIL_CHECK("bil/seedfin: REFUSE oversized walk (tip-0 > MAX_GAP)",
                      r_big == 0 && active_chain_tip(&ms2.chain_active) == NULL);

            tip_finalize_stage_shutdown();
            progress_store_close();
            block_map_free(&ms2.map_block_index);
            test_cleanup_tmpdir(dir2);
        }

        chain_params_select(CHAIN_MAIN);
    }

    /* ── 15. node.db `blocks` hydrate: hash-linked rows load + link ──────
     *
     * Reproduces the fresh-datadir header-hydration hole: --importblockindex
     * fills the `blocks` table with header-only rows but writes no flat file /
     * cache / LevelDB, so the map is genesis-only until this rung reads them
     * back. Build N hash-linked header rows, hydrate, and assert the map size,
     * tip linkage to genesis, and honest header-only validity clamping. */
    {
        const int N = 300;
        struct uint256 *hashes = malloc((size_t)N * sizeof(*hashes)); // raw-alloc-ok:test-fixture
        bool ok = (hashes != NULL);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ok = ok && (sqlite3_open(":memory:", &ndb.db) == SQLITE_OK);
        ndb.open = ok;
        ok = ok && bih_create_blocks_table(ndb.db);

        struct uint256 zero;
        memset(&zero, 0, sizeof(zero));
        for (int h = 0; ok && h < N; h++) {
            const struct uint256 *prev = (h == 0) ? &zero : &hashes[h - 1];
            ok = bih_insert_header_row(ndb.db, h, prev, &hashes[h]);
        }

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);

        ok = ok && load_block_index_from_blocks_table(&ndb, &ms).ok;
        bool size_ok = ok && (ms.map_block_index.size == (size_t)N);

        /* Tip present at height N-1 and pprev-walks N hops to the root. */
        bool tip_ok = false, valid_ok = false;
        if (size_ok) {
            struct block_index *tip = block_map_find(&ms.map_block_index,
                                                     &hashes[N - 1]);
            int walk = 0;
            struct block_index *cur = tip;
            while (cur && walk < N + 5) { walk++; cur = cur->pprev; }
            tip_ok = tip && tip->nHeight == N - 1 && walk == N;

            /* Honest validity: a mid entry is clamped to header-only TREE with
             * NO HAVE_DATA, even though the row stored SCRIPTS. */
            struct block_index *mid = block_map_find(&ms.map_block_index,
                                                     &hashes[N / 2]);
            valid_ok = mid &&
                ((mid->nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_TREE) &&
                !(mid->nStatus & BLOCK_HAVE_DATA) &&
                !(mid->nStatus & BLOCK_HAVE_UNDO);
        }

        BIL_CHECK("bil: blocks-table hydrate loads N hash-linked headers",
                  size_ok && tip_ok);
        BIL_CHECK("bil: blocks-table hydrate clamps to header-only "
                  "(BLOCK_VALID_TREE, no HAVE_DATA)", valid_ok);

        block_map_free(&ms.map_block_index);
        if (ndb.db) sqlite3_close(ndb.db);
        free(hashes);
    }

    /* ── 15b. blocks hydrate pumps the boot-liveness marker ──────────────
     *
     * Reproduces the 2026-07-27 canonical crash loop: a corrupt flat file
     * (`tip hash maps to wrong height (-1 vs SQLite …)`) forced the
     * multi-minute blocks-table hydrate on EVERY boot; it bumped no
     * boot-progress marker, systemd's 2-min WatchdogSec killed each boot
     * mid-load, and the shutdown-persisted heal never landed (8 SIGABRTs).
     * The hydrate now pumps boot_progress_note() every 4096 rows in its
     * validate/insert/link passes, so >4096 rows MUST advance the marker. */
    {
        const int N = 4096 + 64;
        struct uint256 *hashes = malloc((size_t)N * sizeof(*hashes)); // raw-alloc-ok:test-fixture
        bool ok = (hashes != NULL);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ok = ok && (sqlite3_open(":memory:", &ndb.db) == SQLITE_OK);
        ndb.open = ok;
        ok = ok && bih_create_blocks_table(ndb.db);

        struct uint256 zero;
        memset(&zero, 0, sizeof(zero));
        for (int h = 0; ok && h < N; h++) {
            const struct uint256 *prev = (h == 0) ? &zero : &hashes[h - 1];
            ok = bih_insert_header_row(ndb.db, h, prev, &hashes[h]);
        }

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);

        uint64_t marker_before = boot_progress_marker();
        ok = ok && load_block_index_from_blocks_table(&ndb, &ms).ok;
        BIL_CHECK("bil: blocks-table hydrate pumps boot-progress marker "
                  "(>4096 rows, watchdog liveness)",
                  ok && boot_progress_marker() > marker_before);

        block_map_free(&ms.map_block_index);
        if (ndb.db) sqlite3_close(ndb.db);
        free(hashes);
    }

    /* ── 16. node.db `blocks` hydrate (J5): a corrupted row is QUARANTINED
     *       per-row (purged + typed blocker + dumpstate counter) and the load
     *       CONTINUES with the remaining rows — it no longer refuses whole. ── */
    {
        const int N = 120;
        const int POISON_H = N / 2;
        struct uint256 *hashes = malloc((size_t)N * sizeof(*hashes)); // raw-alloc-ok:test-fixture
        bool ok = (hashes != NULL);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ok = ok && (sqlite3_open(":memory:", &ndb.db) == SQLITE_OK);
        ndb.open = ok;
        ok = ok && bih_create_blocks_table(ndb.db);

        struct uint256 zero;
        memset(&zero, 0, sizeof(zero));
        for (int h = 0; ok && h < N; h++) {
            const struct uint256 *prev = (h == 0) ? &zero : &hashes[h - 1];
            ok = bih_insert_header_row(ndb.db, h, prev, &hashes[h]);
        }

        /* Poison ONE row: rewrite its merkle_root so the stored hash no longer
         * hash-binds (the header re-serializes to a different PoW hash). The
         * `hash` column keeps its original value, so db_block_delete(that hash)
         * addresses exactly this row. */
        if (ok) {
            uint8_t bad[32];
            memset(bad, 0xEE, sizeof(bad));
            sqlite3_stmt *u = NULL;
            ok = (sqlite3_prepare_v2(ndb.db,
                    "UPDATE blocks SET merkle_root=? WHERE height=?",
                    -1, &u, NULL) == SQLITE_OK && u);
            if (ok) {
                sqlite3_bind_blob(u, 1, bad, 32, SQLITE_TRANSIENT);
                sqlite3_bind_int(u, 2, POISON_H);
                ok = (sqlite3_step(u) == SQLITE_DONE);
                sqlite3_finalize(u);
            }
        }

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);

        blocker_clear("block_index.blocks_hydrate_quarantine");
        int64_t q_before = block_index_blocks_hydrate_quarantined();

        /* The load must SUCCEED, quarantining exactly the one poisoned row. */
        bool loaded = ok && load_block_index_from_blocks_table(&ndb, &ms).ok;
        int64_t q_delta = block_index_blocks_hydrate_quarantined() - q_before;

        /* Exactly one row quarantined; the typed blocker is present. */
        bool counter_ok = loaded && (q_delta == 1);
        bool blocker_ok =
            blocker_exists("block_index.blocks_hydrate_quarantine");

        /* The poisoned height is absent from the map (never inserted) AND
         * purged from `blocks`; the remaining N-1 rows loaded. */
        bool poison_gone_map =
            (block_map_find(&ms.map_block_index, &hashes[POISON_H]) == NULL);
        bool remaining_ok = loaded && (ms.map_block_index.size == (size_t)(N - 1));

        bool poison_gone_db = false;
        if (ndb.db) {
            sqlite3_stmt *c = NULL;
            if (sqlite3_prepare_v2(ndb.db,
                    "SELECT COUNT(*) FROM blocks WHERE height=?",
                    -1, &c, NULL) == SQLITE_OK && c) {
                sqlite3_bind_int(c, 1, POISON_H);
                if (sqlite3_step(c) == SQLITE_ROW)
                    poison_gone_db = (sqlite3_column_int(c, 0) == 0);
                sqlite3_finalize(c);
            }
        }

        /* A sampled surviving neighbour on each side is intact + header-only
         * (no HAVE_DATA fabricated). */
        struct block_index *below =
            block_map_find(&ms.map_block_index, &hashes[POISON_H - 1]);
        struct block_index *above =
            block_map_find(&ms.map_block_index, &hashes[POISON_H + 1]);
        bool neighbours_ok = below && above &&
            below->nHeight == POISON_H - 1 && above->nHeight == POISON_H + 1 &&
            !(below->nStatus & BLOCK_HAVE_DATA) &&
            !(above->nStatus & BLOCK_HAVE_DATA);

        BIL_CHECK("bil: blocks-table hydrate QUARANTINES one poisoned row + "
                  "continues (counter=1, blocker set)",
                  counter_ok && blocker_ok);
        BIL_CHECK("bil: quarantined row purged from map + `blocks`, remaining "
                  "rows intact",
                  poison_gone_map && poison_gone_db && remaining_ok &&
                  neighbours_ok);

        blocker_clear("block_index.blocks_hydrate_quarantine");
        block_map_free(&ms.map_block_index);
        if (ndb.db) sqlite3_close(ndb.db);
        free(hashes);
    }

    /* ── 16b. node.db `blocks` hydrate (J5): an ALL-poisoned table quarantines
     *        every row and returns .ok=false (0 usable) — never a partial map. */
    {
        const int N = 8;
        struct uint256 *hashes = malloc((size_t)N * sizeof(*hashes)); // raw-alloc-ok:test-fixture
        bool ok = (hashes != NULL);

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ok = ok && (sqlite3_open(":memory:", &ndb.db) == SQLITE_OK);
        ndb.open = ok;
        ok = ok && bih_create_blocks_table(ndb.db);

        struct uint256 zero;
        memset(&zero, 0, sizeof(zero));
        for (int h = 0; ok && h < N; h++) {
            const struct uint256 *prev = (h == 0) ? &zero : &hashes[h - 1];
            ok = bih_insert_header_row(ndb.db, h, prev, &hashes[h]);
        }
        /* Poison EVERY row's merkle_root. */
        if (ok) {
            uint8_t bad[32];
            memset(bad, 0xEE, sizeof(bad));
            sqlite3_stmt *u = NULL;
            ok = (sqlite3_prepare_v2(ndb.db,
                    "UPDATE blocks SET merkle_root=?", -1, &u, NULL)
                    == SQLITE_OK && u);
            if (ok) {
                sqlite3_bind_blob(u, 1, bad, 32, SQLITE_TRANSIENT);
                ok = (sqlite3_step(u) == SQLITE_DONE);
                sqlite3_finalize(u);
            }
        }

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);

        int64_t q_before = block_index_blocks_hydrate_quarantined();
        bool refused = ok && !load_block_index_from_blocks_table(&ndb, &ms).ok;
        int64_t q_delta = block_index_blocks_hydrate_quarantined() - q_before;
        bool empty_map = (ms.map_block_index.size == 0);

        BIL_CHECK("bil: all-poisoned blocks-table quarantines all rows, "
                  "returns 0-usable, empty map",
                  refused && q_delta == N && empty_map);

        blocker_clear("block_index.blocks_hydrate_quarantine");
        block_map_free(&ms.map_block_index);
        if (ndb.db) sqlite3_close(ndb.db);
        free(hashes);
    }

    /* ── 16d. RUNTIME poisoned-blocks-row quarantine (Lane B3):
     *        stage_repair_quarantine_blocks_row purges a row that FAILS the
     *        frozen block_row_verify, clears its in-memory HAVE_DATA, bumps the
     *        process counter + typed blocker; REFUSES a clean row; and falls
     *        back to db_block_delete_by_height for a row whose stored `hash`
     *        column does not match the canonical hash. CHAIN_MAIN is already
     *        selected above (case 14), so chain_params_get() != NULL. ──────── */
    {
        const int N = 5;
        const int POISON_H = 2;
        struct uint256 hashes[5];

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        bool ok = (sqlite3_open(":memory:", &ndb.db) == SQLITE_OK);
        ndb.open = ok;
        ok = ok && bih_create_blocks_table(ndb.db);

        struct uint256 zero;
        memset(&zero, 0, sizeof(zero));
        for (int h = 0; ok && h < N; h++) {
            const struct uint256 *prev = (h == 0) ? &zero : &hashes[h - 1];
            ok = bih_insert_header_row(ndb.db, h, prev, &hashes[h]);
        }

        /* Active chain over the SAME hashes; HAVE_DATA set on the poison row so
         * the quarantine's in-memory clear is observable. */
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        struct block_index *bi_arr[5] = {0};
        for (int h = 0; ok && h < N; h++) {
            struct block_index *bi = chainstate_insert_block_index(
                (struct chainstate *)&ms, &hashes[h]);
            ok = ok && (bi != NULL);
            if (bi) {
                bi->nHeight = h;
                bi->nStatus = (unsigned)BLOCK_VALID_TREE |
                    (h == POISON_H ? (unsigned)BLOCK_HAVE_DATA : 0u);
                if (h > 0)
                    bi->pprev = bi_arr[h - 1];
                bi_arr[h] = bi;
            }
        }
        ok = ok && active_chain_move_window_tip(&ms.chain_active, bi_arr[N - 1]);

        /* Poison the durable row at POISON_H: rewrite merkle_root so the stored
         * header no longer hash-binds to its `hash` column (== canonical). */
        if (ok) {
            uint8_t bad[32];
            memset(bad, 0xEE, sizeof(bad));
            sqlite3_stmt *u = NULL;
            ok = (sqlite3_prepare_v2(ndb.db,
                    "UPDATE blocks SET merkle_root=? WHERE height=?",
                    -1, &u, NULL) == SQLITE_OK && u);
            if (ok) {
                sqlite3_bind_blob(u, 1, bad, 32, SQLITE_TRANSIENT);
                sqlite3_bind_int(u, 2, POISON_H);
                ok = (sqlite3_step(u) == SQLITE_DONE);
                sqlite3_finalize(u);
            }
        }

        blocker_clear("block_index.runtime_row_quarantine");
        int64_t q0 = stage_repair_runtime_row_quarantined();

        struct stage_repair_row_quarantine_result qr;
        memset(&qr, 0, sizeof(qr));
        bool purged = ok && stage_repair_quarantine_blocks_row(
            &ndb, &ms, POISON_H, &hashes[POISON_H], &qr);
        int64_t q_delta = stage_repair_runtime_row_quarantined() - q0;

        bool gone_db = false;
        if (ndb.db) {
            sqlite3_stmt *c = NULL;
            if (sqlite3_prepare_v2(ndb.db,
                    "SELECT COUNT(*) FROM blocks WHERE height=?",
                    -1, &c, NULL) == SQLITE_OK && c) {
                sqlite3_bind_int(c, 1, POISON_H);
                if (sqlite3_step(c) == SQLITE_ROW)
                    gone_db = (sqlite3_column_int(c, 0) == 0);
                sqlite3_finalize(c);
            }
        }
        bool have_data_cleared = bi_arr[POISON_H] &&
            !(block_index_status_load(bi_arr[POISON_H]) & BLOCK_HAVE_DATA);
        bool blocker_ok =
            blocker_exists("block_index.runtime_row_quarantine");

        BIL_CHECK("bil/B3: runtime quarantine purges poisoned row (counter+1, "
                  "blocker set, HAVE_DATA cleared, row gone)",
                  purged && qr.quarantined && q_delta == 1 && gone_db &&
                  have_data_cleared && blocker_ok);

        /* REFUSE a clean row: calling on a still-valid neighbour must NOT delete
         * it and must NOT bump the counter (verdict OK). */
        int64_t q1 = stage_repair_runtime_row_quarantined();
        struct stage_repair_row_quarantine_result qr2;
        memset(&qr2, 0, sizeof(qr2));
        bool purged2 = ok && stage_repair_quarantine_blocks_row(
            &ndb, &ms, 1, &hashes[1], &qr2);
        bool clean_present = false;
        if (ndb.db) {
            sqlite3_stmt *c = NULL;
            if (sqlite3_prepare_v2(ndb.db,
                    "SELECT COUNT(*) FROM blocks WHERE height=?",
                    -1, &c, NULL) == SQLITE_OK && c) {
                sqlite3_bind_int(c, 1, 1);
                if (sqlite3_step(c) == SQLITE_ROW)
                    clean_present = (sqlite3_column_int(c, 0) == 1);
                sqlite3_finalize(c);
            }
        }
        BIL_CHECK("bil/B3: runtime quarantine REFUSES a clean row (no delete, "
                  "verdict OK)",
                  !purged2 && qr2.refused_clean &&
                  qr2.verdict == (int)BLOCK_ROW_VERIFY_OK &&
                  (stage_repair_runtime_row_quarantined() - q1) == 0 &&
                  clean_present);

        /* by_height FALLBACK: a poisoned row at height 4 whose stored `hash`
         * column is REWRITTEN to a non-canonical value X. Read-by-canonical-hash
         * finds nothing → the helper reads by height, verifies the stored header
         * against the canonical hash (mismatch), and deletes by height. */
        int64_t q2 = stage_repair_runtime_row_quarantined();
        bool okh = ok;
        if (okh) {
            uint8_t xhash[32];
            memset(xhash, 0x77, sizeof(xhash));
            uint8_t bad[32];
            memset(bad, 0xAB, sizeof(bad));
            sqlite3_stmt *u = NULL;
            okh = (sqlite3_prepare_v2(ndb.db,
                    "UPDATE blocks SET hash=?, merkle_root=? WHERE height=?",
                    -1, &u, NULL) == SQLITE_OK && u);
            if (okh) {
                sqlite3_bind_blob(u, 1, xhash, 32, SQLITE_TRANSIENT);
                sqlite3_bind_blob(u, 2, bad, 32, SQLITE_TRANSIENT);
                sqlite3_bind_int(u, 3, 4);
                okh = (sqlite3_step(u) == SQLITE_DONE);
                sqlite3_finalize(u);
            }
        }
        struct stage_repair_row_quarantine_result qr3;
        memset(&qr3, 0, sizeof(qr3));
        bool purged3 = okh && stage_repair_quarantine_blocks_row(
            &ndb, &ms, 4, &hashes[4], &qr3);
        bool gone4 = false;
        if (ndb.db) {
            sqlite3_stmt *c = NULL;
            if (sqlite3_prepare_v2(ndb.db,
                    "SELECT COUNT(*) FROM blocks WHERE height=?",
                    -1, &c, NULL) == SQLITE_OK && c) {
                sqlite3_bind_int(c, 1, 4);
                if (sqlite3_step(c) == SQLITE_ROW)
                    gone4 = (sqlite3_column_int(c, 0) == 0);
                sqlite3_finalize(c);
            }
        }
        BIL_CHECK("bil/B3: runtime quarantine falls back to delete-by-height for "
                  "a non-canonical-hash poisoned row",
                  purged3 && qr3.quarantined && qr3.deleted_by_height &&
                  gone4 && (stage_repair_runtime_row_quarantined() - q2) == 1);

        blocker_clear("block_index.runtime_row_quarantine");
        block_map_free(&ms.map_block_index);
        if (ndb.db) sqlite3_close(ndb.db);
    }

    /* ── 16c. Repair-storm throttle: N rapid SAME-key failures collapse to a
     *        BOUNDED emission count (first-fire + one keepalive per window) —
     *        the de-storm contract the quarantine WARN and the
     *        stale_validate_headers_repair deferral WARN both rely on. Uses the
     *        caller-supplied clock so the assertion is deterministic. ─────── */
    {
        struct log_throttle t = LOG_THROTTLE_INIT;
        const int64_t keepalive = 60;
        const uint64_t key = 3179245;   /* a fixed "height" fingerprint */
        int64_t now = 1000000;

        int emits = 0;
        /* 500 rapid failures within the same wall-second: exactly ONE emit. */
        for (int i = 0; i < 500; i++)
            if (log_throttle_should_emit(&t, key, now, keepalive, NULL))
                emits++;
        bool first_window_ok = (emits == 1);

        /* Advance past the keepalive window: exactly one keepalive emit. */
        now += keepalive + 1;
        int emits2 = 0;
        for (int i = 0; i < 500; i++)
            if (log_throttle_should_emit(&t, key, now, keepalive, NULL))
                emits2++;
        bool keepalive_ok = (emits2 == 1);

        /* A DIFFERENT key emits immediately (distinct episode, not throttled). */
        bool diff_key_ok =
            log_throttle_should_emit(&t, key + 1, now, keepalive, NULL);

        BIL_CHECK("bil: repair-storm throttle bounds N rapid same-key failures "
                  "to 1 emit/window", first_window_ok && keepalive_ok);
        BIL_CHECK("bil: repair-storm throttle re-emits on a new-key episode",
                  diff_key_ok);
    }

    /* ── Fast-restart: forward pass ALWAYS re-derives stored work ────────
     * The trust-flat fast-restart skip was removed because a stale binding
     * (flat saved best tip <= the coins/fold tip) that skipped the forward pass
     * left pindex_best_header pinned at the coins tip and converged the reducer
     * drive with unfolded bodies — a live wedge. Guard the removal: a flat file
     * carrying STALE (here: zeroed) stored nChainWork must still load with the
     * correct work, because load_block_index_flat unconditionally re-derives it
     * from the pointer graph. If a skip ever reappeared, the loaded tip work
     * would read back as the zeroed stored value and this fails. */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 20);

        struct uint256 tip_hash = make_test_hash(19);
        struct block_index *tip = block_map_find(&ms.map_block_index, &tip_hash);
        struct arith_uint256 correct_work = {0};
        bool ok = (tip != NULL);
        if (ok) correct_work = tip->nChainWork;

        /* Poison every entry's stored derived work to zero BEFORE saving, so the
         * flat carries garbage the forward pass must overwrite on load. */
        for (int h = 0; h < 20; h++) {
            struct uint256 hh = make_test_hash(h);
            struct block_index *pi = block_map_find(&ms.map_block_index, &hh);
            if (pi) memset(&pi->nChainWork, 0, sizeof(pi->nChainWork));
        }

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_reder", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);
        if (ok) save_block_index_flat(tmpdir, &ms);

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);
        if (ok) ok = load_block_index_flat(tmpdir, &ms2).ok;

        struct arith_uint256 zero = {0};
        struct block_index *loaded =
            ok ? block_map_find(&ms2.map_block_index, &tip_hash) : NULL;
        bool rederived = loaded &&
            arith_uint256_compare(&loaded->nChainWork, &correct_work) == 0 &&
            arith_uint256_compare(&loaded->nChainWork, &zero) != 0;
        BIL_CHECK("bil: load re-derives stored work (no fast-restart skip)",
                  ok && rederived);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);
        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── Persisted-FAILED-bit trust policy (C2) ─────────────────────────
     * A stale persisted BLOCK_FAILED_VALID bit on the true best-chain tip must
     * NEVER wedge the node ("stale BLOCK_FAILED_VALID wedges tip" class). The
     * flat + SQLite loaders reconcile the bit against the baked ROM checkpoint:
     *   - below the checkpoint: STRIP it (re-derive, never trust);
     *   - above it:            DEMOTE it to a lazy revalidation candidate
     *                          (clear the FAILED bit, set BLOCK_REVALIDATE_PENDING).
     * Either way the demoted/stripped block is failure-free, so
     * select_most_work_eligible() promotes it again. Genuinely-failed behavior
     * is unchanged — the marker DEMANDS revalidation; the loader never blesses
     * the block (no HAVE bit added, validity level not raised). */

    /* ── T1: pure unit test of the policy helper (deterministic). ──────── */
    {
        /* Below checkpoint (h=100, ckpt=1000): STRIP, no marker. */
        struct block_index bi;
        block_index_init(&bi);
        bi.nHeight = 100;
        bi.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_FAILED_VALID;
        int64_t before_strip = block_index_failed_bits_stripped();
        enum block_index_failure_trust_action a1 =
            block_index_apply_persisted_failure_trust(&bi, 1000);
        bool strip_ok = (a1 == BLOCK_FAILURE_TRUST_STRIPPED) &&
                        !(bi.nStatus & BLOCK_FAILED_MASK) &&
                        !(bi.nStatus & BLOCK_REVALIDATE_PENDING) &&
                        /* validity level + HAVE bit preserved (no weakening) */
                        (bi.nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_SCRIPTS &&
                        (bi.nStatus & BLOCK_HAVE_DATA) &&
                        block_index_failed_bits_stripped() == before_strip + 1;
        BIL_CHECK("bil: policy strips FAILED below the ROM checkpoint", strip_ok);

        /* Above checkpoint (h=2000, ckpt=1000): DEMOTE to a candidate. */
        struct block_index bi2;
        block_index_init(&bi2);
        bi2.nHeight = 2000;
        bi2.nStatus = BLOCK_VALID_TREE | BLOCK_FAILED_CHILD;
        int64_t before_demote = block_index_failed_bits_demoted();
        enum block_index_failure_trust_action a2 =
            block_index_apply_persisted_failure_trust(&bi2, 1000);
        bool demote_ok = (a2 == BLOCK_FAILURE_TRUST_DEMOTED) &&
                         !(bi2.nStatus & BLOCK_FAILED_MASK) &&
                         (bi2.nStatus & BLOCK_REVALIDATE_PENDING) &&
                         !block_has_any_failure(&bi2) &&      /* selectable */
                         block_is_revalidation_pending(&bi2) &&
                         (bi2.nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_TREE &&
                         block_index_failed_bits_demoted() == before_demote + 1;
        BIL_CHECK("bil: policy demotes FAILED above the checkpoint to a "
                  "revalidation candidate", demote_ok);

        /* No persisted verdict + a stale round-tripped marker → NONE, marker
         * self-clears, no counter movement, other bits untouched. */
        struct block_index bi3;
        block_index_init(&bi3);
        bi3.nHeight = 2000;
        bi3.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                      BLOCK_REVALIDATE_PENDING;
        enum block_index_failure_trust_action a3 =
            block_index_apply_persisted_failure_trust(&bi3, 1000);
        bool none_ok = (a3 == BLOCK_FAILURE_TRUST_NONE) &&
                       !(bi3.nStatus & BLOCK_REVALIDATE_PENDING) &&
                       bi3.nStatus == (unsigned)(BLOCK_VALID_SCRIPTS |
                                                 BLOCK_HAVE_DATA);
        BIL_CHECK("bil: policy clears a stale round-tripped marker when no "
                  "FAILED bit is present", none_ok);
    }

    /* ── T2: end-to-end via the FLAT loader with a low override checkpoint,
     * proving the demote cures the wedge at the selection layer. A synthetic
     * chain h=0..49 with a FAILED_VALID stamped on the tip is saved and
     * reloaded; the override checkpoint at h=10 puts the tip ABOVE it, so the
     * reloaded tip must be demoted (FAILED cleared + marker set) and
     * select_most_work_eligible() must return it. */
    {
        struct rom_state_checkpoint ov;
        memset(&ov, 0, sizeof(ov));
        ov.height = 10;   /* tip h=49 sits ABOVE this */
        checkpoints_set_rom_state_override_for_test(&ov);

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 50);

        /* Stamp a STALE FAILED_VALID on the best-chain tip (h=49). */
        struct uint256 tip_hash = make_test_hash(49);
        struct block_index *tip = block_map_find(&ms.map_block_index, &tip_hash);
        bool ok = (tip != NULL);
        if (ok) tip->nStatus |= BLOCK_FAILED_VALID;

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_demote", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);
        if (ok) save_block_index_flat(tmpdir, &ms);

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);
        if (ok) ok = load_block_index_flat(tmpdir, &ms2).ok;

        struct block_index *loaded =
            ok ? block_map_find(&ms2.map_block_index, &tip_hash) : NULL;
        bool demoted = loaded &&
            !(loaded->nStatus & BLOCK_FAILED_MASK) &&
            block_is_revalidation_pending(loaded) &&
            !block_has_any_failure(loaded);

        /* The cured tip must now be the most-work selection (was excluded by
         * the stale FAILED bit before the reconcile). */
        struct block_index *sel =
            ok ? select_most_work_eligible(&ms2.chain_active,
                                           &ms2.map_block_index, NULL) : NULL;
        bool selected = (sel == loaded);

        BIL_CHECK("bil: flat loader demotes a stale FAILED tip above the "
                  "checkpoint and it becomes selectable", demoted && selected);

        checkpoints_reset_rom_state_override_for_test();
        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);
        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── T3: FLAT loader with the DEFAULT (high) checkpoint — the whole
     * synthetic chain is BELOW it, so a stale FAILED tip is STRIPPED (no
     * marker) and still becomes selectable. */
    {
        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 40);

        struct uint256 tip_hash = make_test_hash(39);
        struct block_index *tip = block_map_find(&ms.map_block_index, &tip_hash);
        bool ok = (tip != NULL);
        if (ok) tip->nStatus |= BLOCK_FAILED_VALID;

        char tmpdir[256];
        snprintf(tmpdir, sizeof(tmpdir), "./test-tmp/%d_bil_strip", getpid());
        mkdir("./test-tmp", 0755);
        mkdir(tmpdir, 0755);
        if (ok) save_block_index_flat(tmpdir, &ms);

        struct main_state ms2;
        memset(&ms2, 0, sizeof(ms2));
        block_map_init(&ms2.map_block_index);
        active_chain_init(&ms2.chain_active);
        if (ok) ok = load_block_index_flat(tmpdir, &ms2).ok;

        struct block_index *loaded =
            ok ? block_map_find(&ms2.map_block_index, &tip_hash) : NULL;
        bool stripped = loaded &&
            !(loaded->nStatus & BLOCK_FAILED_MASK) &&
            !block_is_revalidation_pending(loaded) &&   /* below ckpt = no marker */
            !block_has_any_failure(loaded);
        struct block_index *sel =
            ok ? select_most_work_eligible(&ms2.chain_active,
                                           &ms2.map_block_index, NULL) : NULL;
        bool selected = (sel == loaded);
        BIL_CHECK("bil: flat loader strips a stale FAILED tip below the default "
                  "checkpoint and it becomes selectable", stripped && selected);

        char path[512];
        snprintf(path, sizeof(path), "%s/block_index.bin", tmpdir);
        unlink(path);
        rmdir(tmpdir);
        block_map_free(&ms.map_block_index);
        block_map_free(&ms2.map_block_index);
    }

    /* ── T4: SQLite loader applies the SAME reconcile. A FAILED_VALID tip
     * above a low override checkpoint is demoted on load_block_index_sqlite. */
    {
        struct rom_state_checkpoint ov;
        memset(&ov, 0, sizeof(ov));
        ov.height = 10;
        checkpoints_set_rom_state_override_for_test(&ov);

        struct main_state ms;
        memset(&ms, 0, sizeof(ms));
        block_map_init(&ms.map_block_index);
        active_chain_init(&ms.chain_active);
        build_synthetic_chain(&ms, 1200);

        struct uint256 tip_hash = make_test_hash(1199);
        struct block_index *tip = block_map_find(&ms.map_block_index, &tip_hash);
        bool ok = (tip != NULL);
        if (ok) tip->nStatus |= BLOCK_FAILED_VALID;

        struct node_db ndb;
        memset(&ndb, 0, sizeof(ndb));
        ok = ok && (sqlite3_open(":memory:", &ndb.db) == SQLITE_OK);
        ndb.open = ok;
        if (ok) {
            sqlite3_exec(ndb.db,
                "CREATE TABLE block_index_cache ("
                "hash BLOB PRIMARY KEY,prev_hash BLOB,height INTEGER,"
                "n_bits INTEGER,n_time INTEGER,n_version INTEGER,"
                "n_status INTEGER,n_file INTEGER,n_data_pos INTEGER,"
                "n_undo_pos INTEGER,n_tx INTEGER,chain_work BLOB,"
                "n_cached_branch_id INTEGER,n_chain_tx INTEGER)",
                NULL, NULL, NULL);
            save_block_index_recent(&ndb, &ms);

            struct main_state ms2;
            memset(&ms2, 0, sizeof(ms2));
            block_map_init(&ms2.map_block_index);
            active_chain_init(&ms2.chain_active);
            ok = load_block_index_sqlite(&ndb, &ms2).ok;

            struct block_index *loaded =
                ok ? block_map_find(&ms2.map_block_index, &tip_hash) : NULL;
            bool demoted = loaded &&
                !(loaded->nStatus & BLOCK_FAILED_MASK) &&
                block_is_revalidation_pending(loaded) &&
                !block_has_any_failure(loaded);
            BIL_CHECK("bil: SQLite loader demotes a stale FAILED tip above the "
                      "checkpoint", ok && demoted);

            block_map_free(&ms2.map_block_index);
            sqlite3_close(ndb.db);
        }
        checkpoints_reset_rom_state_override_for_test();
        block_map_free(&ms.map_block_index);
    }

    printf("=== block index loader: %d failures ===\n", failures);
    return failures + ZCL_TEST_SETUP_FAILURES();
}
