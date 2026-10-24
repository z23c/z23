/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Whole-struct parity dump for the in-memory block index.
 *
 * The block index is the node's largest memory user and is being shrunk step
 * by step. Every step must keep every answer bit-identical, so this test pins
 * the whole struct: a deterministic dump walks block_map and digests, for
 * every entry, EVERY field of struct block_index as read through today's
 * public accessors and fields (hash, prev hash, skip height, nChainWork,
 * raw nCachedBranchId, the five shielded values, the three flags, nSequenceId,
 * Sapling root, the header extension bytes, nStatus, nFile, nDataPos,
 * nUndoPos, nTx, nChainTx, nVersion, nTime, nBits). The dump reads the live
 * in-memory entries, never a flat row, so fields the flat row does not carry
 * are covered too.
 *
 * Records are digested sorted by block hash, not in raw slot order, so a later
 * step that changes the map layout (capacity, bucket size) does not move the
 * goldens; only a change of an observable answer does.
 *
 * One fixture is loaded through each boot path the tests can drive (flat
 * load, node.db top-up, cold-import blocks hydrate, header accept) plus a
 * fork-and-reorg run on the header-accept path; a SHA3-256 golden is pinned
 * per path. A field-sensitivity check flips every dumped field of one entry
 * and requires the digest to move, so a field silently dropped from the dump
 * fails here.
 */

#include "test/test_core.h"
#include "test/setup_result.h"

#include "services/block_index_loader.h"
#include "models/database.h"
#include "models/block.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/main_state.h"
#include "validation/chainstate.h"
#include "validation/accept_block_header.h"
#include "primitives/block.h"
#include "chain/chain.h"
#include "chain/pow.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "sha3/sha3.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BIPD_CHECK(name, expr) do {                 \
    printf("bipd: %s... ", (name));                 \
    if ((expr)) printf("OK\n");                     \
    else { printf("FAIL\n"); failures++; }          \
} while (0)

/* ── The dump ─────────────────────────────────────────────────────────── */

static void bipd_bytes(struct sha3_256_ctx *c, const void *p, size_t n)
{
    sha3_256_write(c, (const unsigned char *)p, n);
}

static void bipd_u64(struct sha3_256_ctx *c, uint64_t v)
{
    unsigned char b[8];
    for (int i = 0; i < 8; i++)
        b[i] = (unsigned char)(v >> (8 * i));
    bipd_bytes(c, b, sizeof(b));
}

static void bipd_u32(struct sha3_256_ctx *c, uint32_t v)
{
    bipd_u64(c, v);
}

static void bipd_work(struct sha3_256_ctx *c, const struct arith_uint256 *w)
{
    for (size_t i = 0; i < ARITH_UINT256_WIDTH; i++)
        bipd_u32(c, w->pn[i]);
}

static void bipd_identity(struct sha3_256_ctx *c, const struct block_index *bi)
{
    struct uint256 zero;
    memset(&zero, 0, sizeof(zero));
    bipd_bytes(c, bi->hashBlock.data, 32);
    bipd_u32(c, bi->phashBlock == &bi->hashBlock);
    bipd_bytes(c, bi->pprev ? bi->pprev->hashBlock.data : zero.data, 32);
    bipd_u32(c, bi->pprev != NULL);
    bipd_u32(c, (uint32_t)(bi->pskip ? bi->pskip->nHeight : -1));
    bipd_u32(c, (uint32_t)bi->nHeight);
    bipd_work(c, &bi->nChainWork);
    bipd_bytes(c, bi->hashFinalSaplingRoot.data, 32);
}

static void bipd_shielded(struct sha3_256_ctx *c, const struct block_index *bi)
{
    bipd_u64(c, (uint64_t)bi->nCachedBranchId);
    bipd_u64(c, (uint64_t)bi->nSproutValue);
    bipd_u64(c, (uint64_t)bi->nChainSproutValue);
    bipd_u64(c, (uint64_t)bi->nSaplingValue);
    bipd_u64(c, (uint64_t)bi->nChainSaplingValue);
    bipd_u32(c, bi->has_sprout_value);
    bipd_u32(c, bi->has_chain_sprout_value);
    bipd_u32(c, bi->has_chain_sapling_value);
}

static void bipd_position(struct sha3_256_ctx *c, const struct block_index *bi)
{
    bipd_u32(c, bi->nStatus);
    bipd_u32(c, (uint32_t)bi->nFile);
    bipd_u32(c, bi->nDataPos);
    bipd_u32(c, bi->nUndoPos);
    bipd_u32(c, bi->nTx);
    bipd_u32(c, bi->nChainTx);
    bipd_u32(c, bi->nSequenceId);
}

static void bipd_header(struct sha3_256_ctx *c, const struct block_index *bi)
{
    struct uint256 merkle = block_index_merkle_root(bi);
    struct uint256 nonce = block_index_nonce(bi);
    size_t sol_len = 0;
    const unsigned char *sol = block_index_solution(bi, &sol_len);
    bipd_u32(c, (uint32_t)bi->nVersion);
    bipd_u32(c, bi->nTime);
    bipd_u32(c, bi->nBits);
    bipd_bytes(c, merkle.data, 32);
    bipd_bytes(c, nonce.data, 32);
    bipd_u64(c, sol_len);
    if (sol && sol_len)
        bipd_bytes(c, sol, sol_len);
}

static void bipd_entry(struct sha3_256_ctx *c, const struct block_index *bi)
{
    bipd_identity(c, bi);
    bipd_shielded(c, bi);
    bipd_position(c, bi);
    bipd_header(c, bi);
}

static int bipd_by_hash(const void *a, const void *b)
{
    const struct block_index *x = *(struct block_index *const *)a;
    const struct block_index *y = *(struct block_index *const *)b;
    return memcmp(x->hashBlock.data, y->hashBlock.data, 32);
}

/* Digest of the whole map, hex into out[65]. False on allocation failure. */
static bool bipd_digest(const struct block_map *m, char out[65])
{
    struct block_index **all = NULL;
    size_t n = 0;
    if (!block_map_snapshot_indices(m, &all, &n))
        return false;
    qsort(all, n, sizeof(*all), bipd_by_hash);
    struct sha3_256_ctx c;
    sha3_256_init(&c);
    bipd_u64(&c, n);
    for (size_t i = 0; i < n; i++)
        bipd_entry(&c, all[i]);
    unsigned char d[SHA3_256_OUTPUT_SIZE];
    sha3_256_finalize(&c, d);
    for (int i = 0; i < SHA3_256_OUTPUT_SIZE; i++)
        snprintf(out + 2 * i, 3, "%02x", d[i]);
    free(all);
    return true;
}

static bool bipd_golden(const char *path, const struct block_map *m,
                        const char *expect)
{
    char got[65];
    if (!bipd_digest(m, got)) {
        printf("bipd: %s: digest allocation failed\n", path);
        return false;
    }
    bool ok = strcmp(got, expect) == 0;
    printf("bipd: %s digest %s%s\n", path, got, ok ? "" : "  (MISMATCH)");
    return ok;
}

/* ── Goldens (SHA3-256 of the dump per load path) ─────────────────────── */

#define BIPD_GOLDEN_FLAT   "a855de8464cca4049680052ae022f5116ecb463617d2665e7b2043efbcbc4485"
#define BIPD_GOLDEN_TOPUP  "125346669d099f08fb972894ded87e2096c100e28785dafc80dc84db04cd619f"
#define BIPD_GOLDEN_COLD   "878f5d7b0d7a5e8619a5bfc0e2f7d767077452639fddeb3326077501484c64d2"
#define BIPD_GOLDEN_ACCEPT "556806c533ac848b43b4f0d2e125f10cd8ee6da18e3501e05db79770e74df58e"
#define BIPD_GOLDEN_REORG  "a24b9be7342b14045cb66ca1b6a5263a300d4cb13269fd68f5fe7fdf8ee727a1"

/* ── Shared fixture helpers ───────────────────────────────────────────── */

static struct uint256 bipd_hash(int tag, int h)
{
    struct uint256 x;
    memset(&x, 0, sizeof(x));
    x.data[0] = (uint8_t)(h & 0xFF);
    x.data[1] = (uint8_t)((h >> 8) & 0xFF);
    x.data[2] = (uint8_t)tag;
    x.data[3] = 0xAA;
    return x;
}

static void bipd_map_new(struct main_state *ms)
{
    memset(ms, 0, sizeof(*ms));
    block_map_init(&ms->map_block_index);
    active_chain_init(&ms->chain_active);
}

static void bipd_dir(char *dir, size_t cap, const char *tag)
{
    snprintf(dir, cap, "./test-tmp/%d_bipd_%s", (int)getpid(), tag);
    mkdir("./test-tmp", 0755);
    mkdir(dir, 0755);
}

/* ── Path 1: flat load ────────────────────────────────────────────────── */

/* A chain whose every field is set to a distinct, non-default value so the
 * dump can tell what the flat row carries from what it drops. */
static void bipd_populate(struct block_index *pi, int h)
{
    pi->nHeight = h;
    pi->nBits = 0x1f07ffff;
    pi->nTime = 1000000 + (uint32_t)h * 150;
    pi->nVersion = 4;
    pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA |
                  ((h % 3) ? BLOCK_HAVE_UNDO : 0);
    pi->nTx = 1 + (unsigned int)(h % 5);
    pi->nFile = h / 40;
    pi->nDataPos = (uint32_t)(h * 2048 + 7);
    pi->nUndoPos = (h % 3) ? (uint32_t)(h * 512 + 3) : 0;
    pi->nSequenceId = (uint32_t)h + 11;
    pi->nCachedBranchId = (h % 4) ? 0x76b809bb : 0x2bb40e60;
    pi->nSproutValue = h * 100 + 1;
    pi->nChainSproutValue = h * 1000 + 2;
    pi->nSaplingValue = h * 10 + 3;
    pi->nChainSaplingValue = h * 7000 + 4;
    pi->has_sprout_value = (h % 2) == 0;
    pi->has_chain_sprout_value = (h % 3) == 0;
    pi->has_chain_sapling_value = (h % 5) != 0;
    memset(pi->hashFinalSaplingRoot.data, 0, 32);
    pi->hashFinalSaplingRoot.data[0] = (uint8_t)(h / 8);   /* shared roots */
    pi->hashFinalSaplingRoot.data[31] = 0x42;
}

static bool bipd_build_flat_source(struct main_state *ms, int n)
{
    for (int h = 0; h < n; h++) {
        struct uint256 hash = bipd_hash(1, h);
        struct block_index *pi =
            chainstate_insert_block_index((struct chainstate *)ms, &hash);
        if (!pi)
            return false;
        bipd_populate(pi, h);
        if (h > 0) {
            struct uint256 ph = bipd_hash(1, h - 1);
            pi->pprev = block_map_find(&ms->map_block_index, &ph);
            if (!pi->pprev)
                return false;
            struct arith_uint256 proof = GetBlockProof(pi);
            arith_uint256_add(&pi->nChainWork, &pi->pprev->nChainWork, &proof);
            pi->nChainTx = pi->pprev->nChainTx + pi->nTx;
            block_index_build_skip(pi);
        } else {
            pi->nChainWork = GetBlockProof(pi);
            pi->nChainTx = pi->nTx;
        }
    }
    return true;
}

static int bipd_path_flat(void)
{
    int failures = 0;
    struct main_state src, dst;
    bipd_map_new(&src);
    bipd_map_new(&dst);
    char dir[256];
    bipd_dir(dir, sizeof(dir), "flat");

    bool built = bipd_build_flat_source(&src, 120);
    BIPD_CHECK("flat: source chain built", built);
    bool loaded = false;
    if (built) {
        save_block_index_flat(dir, &src);
        loaded = load_block_index_flat(dir, &dst).ok;
    }
    BIPD_CHECK("flat: saved and loaded", loaded);
    BIPD_CHECK("flat: golden",
               loaded && bipd_golden("flat", &dst.map_block_index,
                                     BIPD_GOLDEN_FLAT));

    char path[512];
    snprintf(path, sizeof(path), "%s/block_index.bin", dir);
    unlink(path);
    rmdir(dir);
    block_map_free(&src.map_block_index);
    block_map_free(&dst.map_block_index);
    return failures;
}

/* ── Path 2: node.db top-up ───────────────────────────────────────────── */

static void bipd_topup_hash(int h, struct uint256 *out)
{
    memset(out->data, 0, 32);
    out->data[0] = (uint8_t)(h & 0xFF);
    out->data[1] = (uint8_t)((h >> 8) & 0xFF);
    out->data[31] = 0xA5;
}

static bool bipd_topup_row(struct node_db *ndb, int h)
{
    static uint8_t sol[3] = {1, 2, 3};
    struct db_block b;
    memset(&b, 0, sizeof(b));
    struct uint256 hh, ph;
    bipd_topup_hash(h, &hh);
    bipd_topup_hash(h - 1, &ph);
    memcpy(b.hash, hh.data, 32);
    memcpy(b.prev_hash, ph.data, 32);
    b.height = h;
    b.version = 4;
    memset(b.merkle_root, 0x11 + (h & 7), 32);
    b.time = 1700000000u + (uint32_t)h;
    b.bits = 0x2000ffffu;
    memset(b.nonce, 0x22 + (h & 3), 32);
    b.solution = sol;
    b.solution_len = sizeof(sol);
    b.chain_work[0] = (uint8_t)h;
    b.status = 3 | BLOCK_HAVE_UNDO;
    b.file_num = 1;
    b.data_pos = 1000 + h;
    b.undo_pos = 2000 + h;
    b.num_tx = 2 + (h & 1);
    memset(b.sapling_root, 0x30 + (h & 1), 32);
    memset(b.sprout_root, 0, 32);
    return db_block_save(ndb, &b);
}

static bool bipd_topup_best(sqlite3 *db, int coins_best)
{
    if (!coins_kv_ensure_schema(db) || !progress_meta_table_ensure(db))
        return false;
    if (sqlite3_exec(db, "BEGIN IMMEDIATE", NULL, NULL, NULL) != SQLITE_OK)
        return false;
    bool ok = coins_kv_set_applied_height_in_tx(db, coins_best + 1);
    return sqlite3_exec(db, ok ? "COMMIT" : "ROLLBACK", NULL, NULL, NULL) ==
               SQLITE_OK && ok;
}

static struct block_index *bipd_topup_entry(struct main_state *ms, int h)
{
    struct uint256 hh;
    bipd_topup_hash(h, &hh);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &hh);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->nBits = 0x2000ffffu;
    bi->nTime = 1700000000u + (uint32_t)h;
    bi->nVersion = 4;
    bi->nStatus = BLOCK_VALID_TREE;
    bi->nFile = -1;
    return bi;
}

static bool bipd_topup_setup(struct node_db *ndb, sqlite3 **progress,
                             struct main_state *ms, const char *dir)
{
    char np[320], pp[320];
    snprintf(np, sizeof(np), "%s/node.db", dir);
    snprintf(pp, sizeof(pp), "%s/progress.db", dir);
    memset(ndb, 0, sizeof(*ndb));
    main_state_init(ms); /* before any failure return: the caller frees ms */
    if (!node_db_open(ndb, np) || sqlite3_open(pp, progress) != SQLITE_OK)
        return false;
    for (int h = 100; h <= 108; h++)
        if (!bipd_topup_row(ndb, h))
            return false;
    struct uint256 seed;
    bipd_topup_hash(102, &seed);
    if (!node_db_state_set_int(ndb, "cold_import_seed_anchor_height", 102) ||
        !node_db_state_set(ndb, "cold_import_seed_anchor_hash", seed.data, 32))
        return false;
    if (!bipd_topup_best(*progress, 107))
        return false;
    struct block_index *e101 = bipd_topup_entry(ms, 101);
    struct block_index *e102 = bipd_topup_entry(ms, 102);
    struct block_index *e103 = bipd_topup_entry(ms, 103);
    if (!e101 || !e102 || !e103)
        return false;
    e102->pprev = e101;
    /* 103 already carries a body: raise-only keeps it. */
    e103->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
    e103->nFile = 1;
    e103->nDataPos = 1103;
    e103->nTx = 5;
    return true;
}

static int bipd_path_topup(void)
{
    int failures = 0;
    char dir[256];
    bipd_dir(dir, sizeof(dir), "topup");
    struct node_db ndb;
    sqlite3 *progress = NULL;
    struct main_state ms;
    memset(&ms, 0, sizeof(ms));
    bool ready = bipd_topup_setup(&ndb, &progress, &ms, dir);
    BIPD_CHECK("topup: fixture built", ready);
    bool ran = ready && block_index_node_db_topup_with(&ms, &ndb, progress, dir);
    BIPD_CHECK("topup: ran", ran);
    BIPD_CHECK("topup: golden",
               ran && bipd_golden("topup", &ms.map_block_index,
                                  BIPD_GOLDEN_TOPUP));
    /* setup initialises ms before any failure return, so free it always */
    main_state_free(&ms);
    if (progress)
        sqlite3_close(progress);
    if (ndb.open)
        node_db_close(&ndb);
    return failures;
}

/* ── Path 3: cold import (node.db blocks hydrate) ─────────────────────── */

static bool bipd_blocks_table(sqlite3 *db)
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

static void bipd_cold_header(struct block_header *hdr, int h,
                             const struct uint256 *prev)
{
    block_header_init(hdr);
    hdr->nVersion = 4;
    hdr->hashPrevBlock = *prev;
    hdr->hashMerkleRoot.data[0] = (uint8_t)h;
    hdr->hashMerkleRoot.data[31] = 0x5A;
    hdr->hashFinalSaplingRoot.data[0] = (uint8_t)(h / 4);
    hdr->hashFinalSaplingRoot.data[30] = 0x11;
    hdr->nBits = 0x1f07ffff;
    hdr->nNonce.data[0] = (uint8_t)h;
    hdr->nNonce.data[1] = 0xC3;
    hdr->nSolutionSize = 32;
    for (int i = 0; i < 32; i++)
        hdr->nSolution[i] = (uint8_t)(i + h);
}

/* Bump nTime until the header meets its PoW target (the loader re-checks). */
static bool bipd_cold_mine(struct block_header *hdr, struct uint256 *out)
{
    bool neg = false, of = false;
    struct arith_uint256 target;
    arith_uint256_set_compact(&target, hdr->nBits, &neg, &of);
    if (neg || of || arith_uint256_is_zero(&target))
        return false;
    for (uint32_t t = 0; t < 2000000u; t++) {
        hdr->nTime = 1231006505u + t;
        block_header_get_hash(hdr, out);
        struct arith_uint256 ha;
        uint256_to_arith(&ha, out);
        if (arith_uint256_compare(&ha, &target) <= 0)
            return true;
    }
    return false;
}

static bool bipd_cold_insert(sqlite3 *db, const struct block_header *hdr,
                             int h, const struct uint256 *hash)
{
    uint8_t zero32[32] = {0};
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db,
            "INSERT INTO blocks(hash,height,prev_hash,version,merkle_root,"
            "time,bits,nonce,solution,chain_work,status,file_num,data_pos,"
            "undo_pos,num_tx,sapling_root,sprout_root,sapling_value,"
            "sprout_value) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            -1, &s, NULL) != SQLITE_OK || !s)
        return false;
    sqlite3_bind_blob(s, 1, hash->data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 2, h);
    sqlite3_bind_blob(s, 3, hdr->hashPrevBlock.data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 4, hdr->nVersion);
    sqlite3_bind_blob(s, 5, hdr->hashMerkleRoot.data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 6, hdr->nTime);
    sqlite3_bind_int64(s, 7, hdr->nBits);
    sqlite3_bind_blob(s, 8, hdr->nNonce.data, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 9, hdr->nSolution, 32, SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 10, zero32, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int(s, 11, BLOCK_VALID_SCRIPTS);
    sqlite3_bind_int(s, 12, 0);
    sqlite3_bind_int(s, 13, 0);
    sqlite3_bind_int(s, 14, 0);
    sqlite3_bind_int(s, 15, 1);
    sqlite3_bind_blob(s, 16, hdr->hashFinalSaplingRoot.data, 32,
                      SQLITE_TRANSIENT);
    sqlite3_bind_blob(s, 17, zero32, 32, SQLITE_TRANSIENT);
    sqlite3_bind_int64(s, 18, 0);
    sqlite3_bind_int64(s, 19, 0);
    bool ok = sqlite3_step(s) == SQLITE_DONE;
    sqlite3_finalize(s);
    return ok;
}

static bool bipd_cold_rows(sqlite3 *db, int n)
{
    struct uint256 prev;
    memset(&prev, 0, sizeof(prev));
    for (int h = 0; h < n; h++) {
        struct block_header hdr;
        struct uint256 hash;
        bipd_cold_header(&hdr, h, &prev);
        if (!bipd_cold_mine(&hdr, &hash) || !bipd_cold_insert(db, &hdr, h, &hash))
            return false;
        prev = hash;
    }
    return true;
}

static int bipd_path_cold(void)
{
    int failures = 0;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool ok = sqlite3_open(":memory:", &ndb.db) == SQLITE_OK;
    ndb.open = ok;
    ok = ok && bipd_blocks_table(ndb.db) && bipd_cold_rows(ndb.db, 40);
    BIPD_CHECK("cold: blocks table filled", ok);
    struct main_state ms;
    bipd_map_new(&ms);
    bool loaded = ok && load_block_index_from_blocks_table(&ndb, &ms).ok;
    BIPD_CHECK("cold: hydrated", loaded);
    BIPD_CHECK("cold: golden",
               loaded && bipd_golden("cold", &ms.map_block_index,
                                     BIPD_GOLDEN_COLD));
    block_map_free(&ms.map_block_index);
    if (ndb.db)
        sqlite3_close(ndb.db);
    return failures;
}

/* ── Path 4: header accept, and the reorg run on top of it ────────────── */

static void bipd_accept_header(struct block_header *hdr, int tag, int h,
                               const struct uint256 *prev)
{
    block_header_init(hdr);
    hdr->nVersion = 4;
    if (prev)
        hdr->hashPrevBlock = *prev;
    hdr->hashMerkleRoot.data[0] = (uint8_t)h;
    hdr->hashMerkleRoot.data[1] = (uint8_t)tag;
    hdr->hashFinalSaplingRoot.data[0] = (uint8_t)(tag * 16 + h / 2);
    hdr->hashFinalSaplingRoot.data[31] = 0x77;
    hdr->nTime = 1600000000u + (uint32_t)(h * 150 + tag);
    hdr->nBits = 0x1f07ffff;
    hdr->nNonce.data[0] = (uint8_t)(h + tag);
    hdr->nNonce.data[31] = 0x99;
    hdr->nSolutionSize = 40;
    for (int i = 0; i < 40; i++)
        hdr->nSolution[i] = (uint8_t)(i * 3 + h + tag);
}

/* Accept `len` headers of branch `tag` on top of `parent` (NULL = genesis). */
static bool bipd_accept_branch(struct main_state *ms, int tag, int first_h,
                               int len, struct uint256 *parent_hash,
                               struct block_index **out)
{
    for (int i = 0; i < len; i++) {
        struct block_header hdr;
        bipd_accept_header(&hdr, tag, first_h + i,
                           first_h == 0 && i == 0 ? NULL : parent_hash);
        struct block_index *bi = add_to_block_index(ms, &hdr);
        if (!bi)
            return false;
        block_header_get_hash(&hdr, parent_hash);
        if (out)
            out[i] = bi;
    }
    return true;
}

/* Mark a branch as connected, with every per-block value the connect path
 * would stamp. */
static void bipd_connect(struct block_index *bi, uint32_t seq)
{
    bi->nStatus |= BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO;
    bi->nTx = 2;
    bi->nChainTx = (bi->pprev ? bi->pprev->nChainTx : 0) + bi->nTx;
    bi->nFile = 0;
    bi->nDataPos = 8 + seq * 1000;
    bi->nUndoPos = 8 + seq * 100;
    bi->nSequenceId = seq;
    bi->nCachedBranchId = 0x76b809bb;
    bi->nSaplingValue = 1000 + seq;
    bi->nChainSaplingValue = (bi->pprev ? bi->pprev->nChainSaplingValue : 0) +
                             bi->nSaplingValue;
    bi->has_chain_sapling_value = true;
    bi->nSproutValue = -(int64_t)seq;
    bi->has_sprout_value = true;
}

struct bipd_fork {
    struct block_index *g;
    struct block_index *a[3];
    struct block_index *b[4];
};

static bool bipd_build_forks(struct main_state *ms, struct bipd_fork *f)
{
    struct uint256 ph;
    memset(&ph, 0, sizeof(ph));
    if (!bipd_accept_branch(ms, 0, 0, 1, &ph, &f->g))
        return false;
    struct uint256 fork_hash = ph;
    if (!bipd_accept_branch(ms, 1, 1, 3, &ph, f->a))
        return false;
    ph = fork_hash;
    return bipd_accept_branch(ms, 2, 1, 4, &ph, f->b);
}

static int bipd_path_accept(void)
{
    int failures = 0;
    struct main_state ms;
    bipd_map_new(&ms);
    struct bipd_fork f;
    memset(&f, 0, sizeof(f));
    bool built = bipd_build_forks(&ms, &f);
    BIPD_CHECK("accept: genesis + branches A(3) B(4) admitted",
               built && block_map_count(&ms.map_block_index) == 8);
    BIPD_CHECK("accept: golden (header-only entries)",
               built && bipd_golden("accept", &ms.map_block_index,
                                    BIPD_GOLDEN_ACCEPT));

    /* Reorg run: branch A connects first, then heavier B displaces it; A's
     * tip is left failed, its child flagged, the rest keeps its body. */
    bool reorg_ok = false;
    if (built) {
        f.g->nStatus |= BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        f.g->nTx = 1;
        f.g->nChainTx = 1;
        uint32_t seq = 1;
        for (int i = 0; i < 3; i++)
            bipd_connect(f.a[i], seq++);
        for (int i = 0; i < 4; i++)
            bipd_connect(f.b[i], seq++);
        f.a[1]->nStatus |= BLOCK_FAILED_VALID;
        f.a[2]->nStatus |= BLOCK_FAILED_CHILD;
        f.a[2]->nStatus &= ~(unsigned int)BLOCK_HAVE_UNDO;
        f.a[2]->nUndoPos = 0;
        reorg_ok = arith_uint256_compare(&f.b[3]->nChainWork,
                                         &f.a[2]->nChainWork) > 0;
    }
    BIPD_CHECK("reorg: B outweighs A", reorg_ok);
    BIPD_CHECK("reorg: golden (post-reorg entries)",
               reorg_ok && bipd_golden("reorg", &ms.map_block_index,
                                       BIPD_GOLDEN_REORG));
    block_map_free(&ms.map_block_index);
    return failures;
}

/* ── Field sensitivity: every dumped field moves the digest ───────────── */

#define BIPD_MUT(name, stmt) \
    static void bipd_mut_##name(struct block_index *bi) { stmt; }

BIPD_MUT(prev, bi->pprev = bi->pprev ? NULL : bi)
BIPD_MUT(skip, bi->pskip = bi->pskip ? NULL : bi)
BIPD_MUT(height, bi->nHeight += 1)
BIPD_MUT(work, bi->nChainWork.pn[3] ^= 1u)
BIPD_MUT(sroot, bi->hashFinalSaplingRoot.data[17] ^= 1)
BIPD_MUT(branch, bi->nCachedBranchId ^= 1)
BIPD_MUT(sprout, bi->nSproutValue ^= 1)
BIPD_MUT(csprout, bi->nChainSproutValue ^= 1)
BIPD_MUT(sapling, bi->nSaplingValue ^= 1)
BIPD_MUT(csapling, bi->nChainSaplingValue ^= 1)
BIPD_MUT(f1, bi->has_sprout_value = !bi->has_sprout_value)
BIPD_MUT(f2, bi->has_chain_sprout_value = !bi->has_chain_sprout_value)
BIPD_MUT(f3, bi->has_chain_sapling_value = !bi->has_chain_sapling_value)
BIPD_MUT(seq, bi->nSequenceId ^= 1)
BIPD_MUT(status, bi->nStatus ^= BLOCK_HAVE_UNDO)
BIPD_MUT(file, bi->nFile ^= 1)
BIPD_MUT(datapos, bi->nDataPos ^= 1)
BIPD_MUT(undopos, bi->nUndoPos ^= 1)
BIPD_MUT(tx, bi->nTx ^= 1)
BIPD_MUT(chaintx, bi->nChainTx ^= 1)
BIPD_MUT(version, bi->nVersion ^= 1)
BIPD_MUT(time, bi->nTime ^= 1)
BIPD_MUT(bits, bi->nBits ^= 1)
BIPD_MUT(hash, bi->hashBlock.data[9] ^= 1)
BIPD_MUT(merkle, bi->ext->hashMerkleRoot.data[5] ^= 1)
BIPD_MUT(nonce, bi->ext->nNonce.data[5] ^= 1)
BIPD_MUT(solbyte, bi->ext->nSolution[7] ^= 1)
BIPD_MUT(sollen, bi->ext->nSolutionSize -= 1)

struct bipd_mut {
    const char *name;
    void (*apply)(struct block_index *);
};

#define BIPD_ROW(n) { #n, bipd_mut_##n }

static const struct bipd_mut g_bipd_muts[] = {
    BIPD_ROW(prev), BIPD_ROW(skip), BIPD_ROW(height), BIPD_ROW(work),
    BIPD_ROW(sroot), BIPD_ROW(branch), BIPD_ROW(sprout), BIPD_ROW(csprout),
    BIPD_ROW(sapling), BIPD_ROW(csapling), BIPD_ROW(f1), BIPD_ROW(f2),
    BIPD_ROW(f3), BIPD_ROW(seq), BIPD_ROW(status), BIPD_ROW(file),
    BIPD_ROW(datapos), BIPD_ROW(undopos), BIPD_ROW(tx), BIPD_ROW(chaintx),
    BIPD_ROW(version), BIPD_ROW(time), BIPD_ROW(bits), BIPD_ROW(hash),
    BIPD_ROW(merkle), BIPD_ROW(nonce), BIPD_ROW(solbyte), BIPD_ROW(sollen),
};

/* Applying a mutator twice restores every XOR/toggle field; prev/skip/height
 * and the solution length need an explicit undo, so snapshot the entry. */
static int bipd_sensitivity(void)
{
    int failures = 0;
    struct main_state ms;
    bipd_map_new(&ms);
    struct bipd_fork f;
    memset(&f, 0, sizeof(f));
    bool built = bipd_build_forks(&ms, &f);
    BIPD_CHECK("sensitivity: fixture built", built);
    if (!built) {
        block_map_free(&ms.map_block_index);
        return failures;
    }
    bipd_connect(f.b[1], 9);
    struct block_index *victim = f.b[1];
    char base[65], moved[65], back[65];
    bool ok = bipd_digest(&ms.map_block_index, base);
    for (size_t i = 0; ok && i < sizeof(g_bipd_muts) / sizeof(g_bipd_muts[0]);
         i++) {
        struct block_index saved = *victim;
        struct block_index_hdrext saved_ext = *victim->ext;
        unsigned char saved_sol[40];
        memcpy(saved_sol, victim->ext->nSolution, sizeof(saved_sol));
        g_bipd_muts[i].apply(victim);
        bool d1 = bipd_digest(&ms.map_block_index, moved);
        *victim = saved;
        *victim->ext = saved_ext;
        memcpy(victim->ext->nSolution, saved_sol, sizeof(saved_sol));
        bool d2 = bipd_digest(&ms.map_block_index, back);
        char label[96];
        snprintf(label, sizeof(label), "sensitivity: field %s moves digest",
                 g_bipd_muts[i].name);
        BIPD_CHECK(label, d1 && d2 && strcmp(base, moved) != 0 &&
                          strcmp(base, back) == 0);
    }
    BIPD_CHECK("sensitivity: baseline digest computed", ok);
    block_map_free(&ms.map_block_index);
    return failures;
}

int test_block_index_parity_dump(void)
{
    printf("\n=== block index whole-struct parity dump ===\n");
    int failures = 0;
    failures += bipd_path_flat();
    failures += bipd_path_topup();
    failures += bipd_path_cold();
    failures += bipd_path_accept();
    failures += bipd_sensitivity();
    printf("=== block_index_parity_dump: %d failure(s) ===\n", failures);
    return failures;
}
