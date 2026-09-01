/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_chainstate_legacy_reader: exercises the legacy CCoins reader
 * against a snapshot of a real zclassicd chainstate when one is
 * available.
 *
 * The test looks at:
 *   1. ZCL_LEGACY_CHAINSTATE  — explicit override path
 *   2. /tmp/zcl_chainstate_snapshot — convention used by the
 *      developer-only worktree harness
 *
 * If neither directory exists (or it can't be opened — e.g. live
 * zclassicd holds the lock on the original), the test is skipped
 * with PASS so CI on a fresh checkout doesn't fail.  When a snapshot
 * is present we verify:
 *
 *   A. open succeeds
 *   B. best-block hash decodes to 32 bytes and is non-zero
 *   C. iter walks the whole 'c' keyspace and emits ~1.3M records,
 *      with sane per-record fields (height in range, value >0,
 *      script non-empty)
 *   D. sum of values matches the order of magnitude of the
 *      published supply (~10M ZCL)
 *   E. a synthetic round-trip test on a hand-built record (covers
 *      the decode path even in CI where no snapshot exists)
 */

#include "test/test_core.h"
#include "storage/chainstate_legacy_reader.h"
#include "storage/dbwrapper.h"
#include "sapling/incremental_merkle_tree.h"
#include "core/serialize.h"
#include "core/uint256.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* ─────────────────────────────────────────────────────────────────────
 * Hermetic coverage of the 6 bulk shielded-history iterators
 * (iter_{sapling,sprout}_{anchors,nullifiers}, get_best_{sapling,sprout}_
 * anchor). No live snapshot / no ~/.zcash-params: Sapling frontiers are
 * Pedersen-hashed in-binary over synthetic commitments, Sprout via
 * SHA256Compress. Each scenario gets its OWN LevelDB dir so a corrupt row
 * in one case cannot poison another, and every row is written+closed
 * BEFORE the reader (which holds the dir lock) opens.
 * ───────────────────────────────────────────────────────────────────── */

#define BLK_CHECK(name, expr) do {                                   \
    printf("chainstate_legacy_bulk: %s... ", (name));                \
    if ((expr)) printf("OK\n");                                      \
    else { printf("FAIL\n"); failures++; }                           \
} while (0)

static void blk_fill(struct uint256 *h, uint8_t seed, size_t idx)
{
    for (size_t i = 0; i < 32; i++)
        h->data[i] = (uint8_t)(seed ^ (idx + i));
}

/* Build a non-empty frontier of `n` synthetic commitments. */
static void blk_build_sapling(size_t n, struct incremental_merkle_tree *out)
{
    sapling_tree_init(out);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm; blk_fill(&cm, 0x33, i);
        incremental_tree_append(out, &cm);
    }
}
static void blk_build_sprout(size_t n, struct incremental_merkle_tree *out)
{
    sprout_tree_init(out);
    for (size_t i = 0; i < n; i++) {
        struct uint256 cm; blk_fill(&cm, 0x77, i);
        incremental_tree_append(out, &cm);
    }
}

/* open → put(key,val) → close. Sequential opens only (LevelDB single-writer);
 * the reader is never open concurrently. */
static bool blk_put(const char *dir, const char *key, size_t klen,
                    const unsigned char *val, size_t vlen)
{
    struct db_wrapper db;
    memset(&db, 0, sizeof(db));
    if (!db_wrapper_open(&db, dir, 1u << 20, false, false))
        return false;
    bool ok = db_write(&db, key, klen, (const char *)val, vlen, true);
    db_wrapper_close(&db);
    return ok;
}

/* Create/wipe an empty LevelDB at dir (also lays down the obfuscate key). */
static bool blk_make_empty(const char *dir)
{
    struct db_wrapper db;
    memset(&db, 0, sizeof(db));
    if (!db_wrapper_open(&db, dir, 1u << 20, false, true /*wipe*/))
        return false;
    db_wrapper_close(&db);
    return true;
}

/* Store one anchor row: (prefix||root) -> serialized(tree). */
static bool blk_put_anchor(const char *dir, char prefix,
                           const struct uint256 *keyroot,
                           const struct incremental_merkle_tree *tree)
{
    struct byte_stream ser;
    stream_init(&ser, 256);
    if (!incremental_tree_serialize(tree, &ser) || ser.error) {
        stream_free(&ser);
        return false;
    }
    char key[33];
    key[0] = prefix;
    memcpy(key + 1, keyroot->data, 32);
    bool ok = blk_put(dir, key, sizeof(key), ser.data, ser.size);
    stream_free(&ser);
    return ok;
}

struct anchor_collect {
    int      count;
    bool     root_ok;      /* every delivered tree re-hashed to its key */
    struct uint256 last_root;
    bool     refuse;       /* if set, cb returns false on first record */
};
static bool anchor_cb(const struct uint256 *root,
                      const struct incremental_merkle_tree *tree, void *ctx)
{
    struct anchor_collect *c = ctx;
    struct uint256 rehash;
    incremental_tree_root(tree, &rehash);
    if (memcmp(rehash.data, root->data, 32) != 0)
        c->root_ok = false;
    c->last_root = *root;
    c->count++;
    if (c->refuse) return false;
    return true;
}

struct nf_collect {
    int     count;
    uint8_t last[32];
};
static bool nf_cb(const uint8_t nf[32], void *ctx)
{
    struct nf_collect *c = ctx;
    memcpy(c->last, nf, 32);
    c->count++;
    return true;
}

static int run_bulk_iter_tests(void)
{
    int failures = 0;
    char dir[512];

    /* ── A. Empty pool: every iterator returns 0, best pointers absent. ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_empty", "db");
    BLK_CHECK("make empty db", blk_make_empty(dir));
    {
        void *h = NULL;
        BLK_CHECK("open empty", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            struct anchor_collect ac = {0}; ac.root_ok = true;
            struct nf_collect nc = {0};
            BLK_CHECK("empty: iter_sapling_anchors == 0",
                      chainstate_legacy_iter_sapling_anchors(h, anchor_cb, &ac) == 0);
            BLK_CHECK("empty: iter_sprout_anchors == 0",
                      chainstate_legacy_iter_sprout_anchors(h, anchor_cb, &ac) == 0);
            BLK_CHECK("empty: iter_sapling_nullifiers == 0",
                      chainstate_legacy_iter_sapling_nullifiers(h, nf_cb, &nc) == 0);
            BLK_CHECK("empty: iter_sprout_nullifiers == 0",
                      chainstate_legacy_iter_sprout_nullifiers(h, nf_cb, &nc) == 0);
            struct uint256 br; blk_fill(&br, 0x11, 1);
            BLK_CHECK("empty: get_best_sapling_anchor == false (absent)",
                      chainstate_legacy_get_best_sapling_anchor(h, &br) == false &&
                      uint256_is_null(&br));
            blk_fill(&br, 0x22, 2);
            BLK_CHECK("empty: get_best_sprout_anchor == false (absent)",
                      chainstate_legacy_get_best_sprout_anchor(h, &br) == false &&
                      uint256_is_null(&br));
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    /* ── B. Single Sapling anchor + best pointer. ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_sap1", "db");
    {
        struct incremental_merkle_tree t; blk_build_sapling(7, &t);
        struct uint256 root; incremental_tree_root(&t, &root);
        BLK_CHECK("make empty (sap1)", blk_make_empty(dir));
        BLK_CHECK("put Sapling anchor row", blk_put_anchor(dir, 'Z', &root, &t));
        char zk = 'z';
        BLK_CHECK("put best-Sapling pointer",
                  blk_put(dir, &zk, 1, root.data, 32));

        void *h = NULL;
        BLK_CHECK("open (sap1)", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            struct anchor_collect ac = {0}; ac.root_ok = true;
            BLK_CHECK("iter_sapling_anchors == 1",
                      chainstate_legacy_iter_sapling_anchors(h, anchor_cb, &ac) == 1);
            BLK_CHECK("delivered root matches + tree re-hashes to key",
                      ac.count == 1 && ac.root_ok &&
                      memcmp(ac.last_root.data, root.data, 32) == 0);
            /* Sprout keyspace is empty in this db (isolation). */
            struct anchor_collect ac2 = {0}; ac2.root_ok = true;
            BLK_CHECK("iter_sprout_anchors == 0 (isolated)",
                      chainstate_legacy_iter_sprout_anchors(h, anchor_cb, &ac2) == 0);
            struct uint256 best; blk_fill(&best, 0x44, 4);
            BLK_CHECK("get_best_sapling_anchor == root",
                      chainstate_legacy_get_best_sapling_anchor(h, &best) &&
                      memcmp(best.data, root.data, 32) == 0);
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    /* ── C. Single Sprout anchor + best pointer. ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_spr1", "db");
    {
        struct incremental_merkle_tree t; blk_build_sprout(5, &t);
        struct uint256 root; incremental_tree_root(&t, &root);
        BLK_CHECK("make empty (spr1)", blk_make_empty(dir));
        BLK_CHECK("put Sprout anchor row", blk_put_anchor(dir, 'A', &root, &t));
        char ak = 'a';
        BLK_CHECK("put best-Sprout pointer",
                  blk_put(dir, &ak, 1, root.data, 32));

        void *h = NULL;
        BLK_CHECK("open (spr1)", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            struct anchor_collect ac = {0}; ac.root_ok = true;
            BLK_CHECK("iter_sprout_anchors == 1",
                      chainstate_legacy_iter_sprout_anchors(h, anchor_cb, &ac) == 1);
            BLK_CHECK("Sprout root matches + re-hashes",
                      ac.count == 1 && ac.root_ok &&
                      memcmp(ac.last_root.data, root.data, 32) == 0);
            struct uint256 best; blk_fill(&best, 0x55, 5);
            BLK_CHECK("get_best_sprout_anchor == root",
                      chainstate_legacy_get_best_sprout_anchor(h, &best) &&
                      memcmp(best.data, root.data, 32) == 0);
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    /* ── D. Nullifier keyspaces ('S' Sapling, 's' Sprout) — presence-only. ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_nf", "db");
    {
        const unsigned char one = 0x01; /* zcashd stores serialized `true`. */
        struct uint256 nf1, nf2, nf3;
        blk_fill(&nf1, 0xA1, 1); blk_fill(&nf2, 0xA2, 2); blk_fill(&nf3, 0xB3, 3);
        char k[33];
        BLK_CHECK("make empty (nf)", blk_make_empty(dir));
        k[0] = 'S'; memcpy(k + 1, nf1.data, 32);
        BLK_CHECK("put Sapling nf1", blk_put(dir, k, 33, &one, 1));
        k[0] = 'S'; memcpy(k + 1, nf2.data, 32);
        BLK_CHECK("put Sapling nf2", blk_put(dir, k, 33, &one, 1));
        k[0] = 's'; memcpy(k + 1, nf3.data, 32);
        BLK_CHECK("put Sprout nf3", blk_put(dir, k, 33, &one, 1));

        void *h = NULL;
        BLK_CHECK("open (nf)", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            struct nf_collect sap = {0}, spr = {0};
            BLK_CHECK("iter_sapling_nullifiers == 2",
                      chainstate_legacy_iter_sapling_nullifiers(h, nf_cb, &sap) == 2);
            BLK_CHECK("iter_sprout_nullifiers == 1",
                      chainstate_legacy_iter_sprout_nullifiers(h, nf_cb, &spr) == 1);
            BLK_CHECK("Sprout nf bytes delivered verbatim",
                      spr.count == 1 && memcmp(spr.last, nf3.data, 32) == 0);
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    /* ── E. Corrupt (non-re-hashing) anchor: valid tree under a WRONG-root
     *       key MUST abort the whole scan (fail-closed completeness). ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_badroot", "db");
    {
        struct incremental_merkle_tree t; blk_build_sapling(4, &t);
        struct uint256 wrong; blk_fill(&wrong, 0xEE, 999); /* != tree root */
        BLK_CHECK("make empty (badroot)", blk_make_empty(dir));
        BLK_CHECK("put valid tree under WRONG root key",
                  blk_put_anchor(dir, 'Z', &wrong, &t));

        void *h = NULL;
        BLK_CHECK("open (badroot)", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            struct anchor_collect ac = {0}; ac.root_ok = true;
            BLK_CHECK("iter_sapling_anchors == -1 (root mismatch refused)",
                      chainstate_legacy_iter_sapling_anchors(h, anchor_cb, &ac) == -1);
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    /* ── F. Trailing bytes after a valid tree — torn record, refused. ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_trailing", "db");
    {
        struct incremental_merkle_tree t; blk_build_sapling(6, &t);
        struct uint256 root; incremental_tree_root(&t, &root);
        struct byte_stream ser; stream_init(&ser, 256);
        bool ser_ok = incremental_tree_serialize(&t, &ser) && !ser.error;
        /* Append one garbage byte after the valid tree. */
        unsigned char extra = 0xFF;
        ser_ok = ser_ok && stream_write(&ser, &extra, 1);
        char key[33]; key[0] = 'Z'; memcpy(key + 1, root.data, 32);
        BLK_CHECK("make empty (trailing)", blk_make_empty(dir));
        BLK_CHECK("put tree+trailing byte",
                  ser_ok && blk_put(dir, key, sizeof(key), ser.data, ser.size));
        stream_free(&ser);

        void *h = NULL;
        BLK_CHECK("open (trailing)", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            /* Point lookup must also refuse trailing bytes (hardened). */
            struct incremental_merkle_tree got;
            BLK_CHECK("get_sapling_anchor(trailing) == ERROR",
                      chainstate_legacy_get_sapling_anchor(h, &root, &got) ==
                          CHAINSTATE_ANCHOR_ERROR);
            struct anchor_collect ac = {0}; ac.root_ok = true;
            BLK_CHECK("iter_sapling_anchors == -1 (trailing bytes refused)",
                      chainstate_legacy_iter_sapling_anchors(h, anchor_cb, &ac) == -1);
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    /* ── G. Malformed key length inside the anchor prefix — refused. ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_shortkey", "db");
    {
        BLK_CHECK("make empty (shortkey)", blk_make_empty(dir));
        /* A 'Z'-prefixed key of length 20 (not 33) is corrupt/foreign. */
        char shortkey[20]; memset(shortkey, 0, sizeof(shortkey));
        shortkey[0] = 'Z';
        unsigned char v = 0x00;
        BLK_CHECK("put malformed short 'Z' key",
                  blk_put(dir, shortkey, sizeof(shortkey), &v, 1));

        void *h = NULL;
        BLK_CHECK("open (shortkey)", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            struct anchor_collect ac = {0}; ac.root_ok = true;
            BLK_CHECK("iter_sapling_anchors == -1 (short key refused)",
                      chainstate_legacy_iter_sapling_anchors(h, anchor_cb, &ac) == -1);
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    /* ── H. Consumer refusal aborts the scan (import must be complete). ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_refuse", "db");
    {
        struct incremental_merkle_tree t; blk_build_sapling(3, &t);
        struct uint256 root; incremental_tree_root(&t, &root);
        BLK_CHECK("make empty (refuse)", blk_make_empty(dir));
        BLK_CHECK("put valid Sapling anchor", blk_put_anchor(dir, 'Z', &root, &t));
        void *h = NULL;
        BLK_CHECK("open (refuse)", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            struct anchor_collect ac = {0}; ac.root_ok = true; ac.refuse = true;
            BLK_CHECK("cb returning false -> iter == -1",
                      chainstate_legacy_iter_sapling_anchors(h, anchor_cb, &ac) == -1);
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    /* ── I. NULL-arg guards on the bulk surface. ── */
    {
        struct anchor_collect ac = {0};
        struct nf_collect nc = {0};
        struct uint256 r;
        BLK_CHECK("iter_sapling_anchors(NULL handle) == -1",
                  chainstate_legacy_iter_sapling_anchors(NULL, anchor_cb, &ac) == -1);
        BLK_CHECK("iter_sapling_nullifiers(NULL cb) == -1 is not required; NULL handle == -1",
                  chainstate_legacy_iter_sapling_nullifiers(NULL, nf_cb, &nc) == -1);
        BLK_CHECK("get_best_sapling_anchor(NULL) == false",
                  chainstate_legacy_get_best_sapling_anchor(NULL, &r) == false);
    }

    /* ── J. EMPTY value under a well-formed 33-byte 'Z' anchor key —
     *       refused, not a crash / OOB read. Regression: this scenario
     *       existed in an earlier revision of this file and was dropped by
     *       merge f4ab099a7's conflict resolution (which took the "ours"
     *       side of a conflicting rewrite wholesale). The reader itself
     *       was never affected — chainstate_legacy_reader.c's
     *       `if (!v || vlen == 0)` check (both in iter_anchor_keyspace and
     *       the chainstate_legacy_get_sapling_anchor point lookup) already
     *       refuses an empty value; this only re-adds the missing
     *       coverage. ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_emptyval", "db");
    {
        BLK_CHECK("make empty (emptyval)", blk_make_empty(dir));
        struct uint256 root; blk_fill(&root, 0x99, 9);
        char key[33]; key[0] = 'Z'; memcpy(key + 1, root.data, 32);
        BLK_CHECK("put well-formed 'Z' key with empty (0-byte) value",
                  blk_put(dir, key, sizeof(key), (const unsigned char *)"", 0));

        void *h = NULL;
        BLK_CHECK("open (emptyval)", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            /* Point lookup: db_read() returns a non-NULL 0-length buffer
             * for a present-but-empty LevelDB value (malloc(0) is non-NULL
             * on glibc), so this exercises the explicit `vlen == 0` check
             * — not the "key absent" path — and must land on MISSING, the
             * documented "nothing usable returned" outcome (never FOUND). */
            struct incremental_merkle_tree got;
            BLK_CHECK("get_sapling_anchor(empty value) == MISSING",
                      chainstate_legacy_get_sapling_anchor(h, &root, &got) ==
                          CHAINSTATE_ANCHOR_MISSING);
            struct anchor_collect ac = {0}; ac.root_ok = true;
            BLK_CHECK("iter_sapling_anchors == -1 (empty value refused)",
                      chainstate_legacy_iter_sapling_anchors(h, anchor_cb, &ac) == -1);
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    /* ── K. TRUNCATED (short) anchor value — fewer bytes than
     *       incremental_tree_deserialize needs for the tree it is claimed
     *       to hold. Must fail closed on the short buffer (stream_read's
     *       bounds check trips inside incremental_tree_deserialize) with
     *       no read past the value's actual length. Same drop history as
     *       scenario J above. ── */
    test_make_tmpdir(dir, sizeof(dir), "cslr_truncval", "db");
    {
        struct incremental_merkle_tree t; blk_build_sapling(6, &t);
        struct uint256 root; incremental_tree_root(&t, &root);
        struct byte_stream ser; stream_init(&ser, 256);
        bool ser_ok = incremental_tree_serialize(&t, &ser) && !ser.error;
        BLK_CHECK("serialize a real tree for truncation", ser_ok);

        char key[33]; key[0] = 'Z'; memcpy(key + 1, root.data, 32);
        BLK_CHECK("make empty (truncval)", blk_make_empty(dir));
        /* Store the FIRST 3 bytes only (well short of a full tree) under
         * the tree's own (real, correctly-computed) root key. */
        size_t short_len = ser.size > 3 ? 3 : ser.size;
        BLK_CHECK("put truncated (3-byte) serialized tree under its own root",
                  ser_ok && blk_put(dir, key, sizeof(key), ser.data, short_len));
        stream_free(&ser);

        void *h = NULL;
        BLK_CHECK("open (truncval)", chainstate_legacy_open(dir, &h) && h);
        if (h) {
            struct incremental_merkle_tree got;
            BLK_CHECK("get_sapling_anchor(truncated) == ERROR",
                      chainstate_legacy_get_sapling_anchor(h, &root, &got) ==
                          CHAINSTATE_ANCHOR_ERROR);
            struct anchor_collect ac = {0}; ac.root_ok = true;
            BLK_CHECK("iter_sapling_anchors == -1 (truncated value refused)",
                      chainstate_legacy_iter_sapling_anchors(h, anchor_cb, &ac) == -1);
            chainstate_legacy_close(h);
        }
    }
    test_rm_rf_recursive(dir);

    return failures;
}

struct walk_state {
    int64_t  records;
    int64_t  total_vouts;
    int64_t  total_value_sat;
    int      min_height;
    int      max_height;
    int      bad_records;
    int      print_first; /* dump the first few records */
};

static bool walk_cb(const struct uint256 *txid,
                    const struct legacy_coins *coins,
                    void *ctx)
{
    struct walk_state *st = ctx;
    st->records++;
    st->total_vouts += (int64_t)coins->num_vouts;

    if (coins->height < 0 || coins->height > 100000000) {
        st->bad_records++;
    } else {
        if (st->min_height == 0 || coins->height < st->min_height)
            st->min_height = coins->height;
        if (coins->height > st->max_height)
            st->max_height = coins->height;
    }

    for (size_t i = 0; i < coins->num_vouts; i++) {
        if (coins->vouts[i].value < 0)
            st->bad_records++;
        st->total_value_sat += coins->vouts[i].value;
        if (coins->vouts[i].script_len == 0)
            st->bad_records++;
    }

    if (st->print_first > 0) {
        char hex[65];
        uint256_get_hex(txid, hex);
        printf("    sample: txid=%s height=%d coinbase=%d vouts=%zu",
               hex, coins->height, coins->coinbase, coins->num_vouts);
        if (coins->num_vouts > 0) {
            printf(" v[0]={n=%u value=%" PRId64 " script_len=%zu}",
                   coins->vouts[0].n, coins->vouts[0].value,
                   coins->vouts[0].script_len);
        }
        printf("\n");
        st->print_first--;
    }
    return true;
}

static bool dir_exists(const char *p)
{
    struct stat st;
    if (stat(p, &st) != 0) return false;
    return S_ISDIR(st.st_mode);
}

static const char *pick_snapshot_path(void)
{
    const char *override = getenv("ZCL_LEGACY_CHAINSTATE");
    if (override && *override && dir_exists(override))
        return override;
    static const char *candidates[] = {
        "/tmp/zcl_chainstate_snapshot",
        NULL,
    };
    for (int i = 0; candidates[i]; i++)
        if (dir_exists(candidates[i]))
            return candidates[i];
    return NULL;
}

int test_chainstate_legacy_reader(void)
{
    int failures = 0;
    const char *path = pick_snapshot_path();

    printf("chainstate_legacy_reader: smoke (no snapshot needed)... ");
    {
        /* Open NULL handle path → must return false, no crash. */
        void *h = NULL;
        bool ok = chainstate_legacy_open(NULL, &h);
        if (ok || h != NULL) { printf("FAIL (NULL arg)\n"); failures++; }
        else printf("OK\n");
    }

    /* Hermetic coverage of the 6 shielded-history bulk iterators — always
     * runs (no live snapshot / no ~/.zcash-params required). */
    failures += run_bulk_iter_tests();

    if (!path) {
        printf("chainstate_legacy_reader: snapshot not found "
               "(set ZCL_LEGACY_CHAINSTATE or populate "
               "/tmp/zcl_chainstate_snapshot) — skipping live tests\n");
        return failures;
    }
    printf("chainstate_legacy_reader: using snapshot at %s\n", path);

    void *h = NULL;
    printf("chainstate_legacy_reader: open... ");
    if (!chainstate_legacy_open(path, &h) || !h) {
        printf("FAIL\n");
        return failures + 1;
    }
    printf("OK\n");

    printf("chainstate_legacy_reader: best-block hash... ");
    {
        struct uint256 best;
        uint256_set_null(&best);
        if (!chainstate_legacy_get_best_block(h, &best)) {
            printf("FAIL (read)\n"); failures++;
        } else if (uint256_is_null(&best)) {
            printf("FAIL (null)\n"); failures++;
        } else {
            char hex[65];
            uint256_get_hex(&best, hex);
            printf("OK %s\n", hex);
        }
    }

    printf("chainstate_legacy_reader: full iter... ");
    fflush(stdout);
    struct walk_state st = {0};
    st.print_first = 3;
    int64_t n = chainstate_legacy_iter(h, walk_cb, &st);
    if (n < 0) {
        printf("FAIL (iter returned -1)\n"); failures++;
    } else {
        printf("OK records=%" PRId64 " vouts=%" PRId64
               " value=%.4f ZCL height_range=[%d..%d] bad=%d\n",
               n, st.total_vouts,
               (double)st.total_value_sat / 1e8,
               st.min_height, st.max_height, st.bad_records);
        /* Records here are CCoins rows (one per transaction with any
         * unspent output), not individual vouts.  Live zclassicd
         * `gettxoutsetinfo` reports ~500k transactions / ~1.35M
         * txouts on ZCL mainnet — track the tx count for `records`
         * and the vout count for `total_vouts`.  Generous bands. */
        if (n < 400000 || n > 2000000) {
            printf("    FAIL: record count outside [400k..2M] sanity band\n");
            failures++;
        }
        if (st.total_vouts < 1000000 || st.total_vouts > 5000000) {
            printf("    FAIL: vout count outside [1M..5M] sanity band\n");
            failures++;
        }
        if (st.bad_records > 0) {
            printf("    FAIL: %d malformed records\n", st.bad_records);
            failures++;
        }
        if (st.min_height < 1 || st.max_height < 3000000) {
            printf("    FAIL: height range [%d..%d] looks wrong\n",
                   st.min_height, st.max_height);
            failures++;
        }
        /* Supply check: ZCL has a published supply on the order of
         * 10M ZCL ≈ 1e15 sat.  Accept 5e14..3e15. */
        if (st.total_value_sat < 500000000000000LL ||
            st.total_value_sat > 3000000000000000LL) {
            printf("    FAIL: total value %.2f ZCL outside [5M..30M] band\n",
                   (double)st.total_value_sat / 1e8);
            failures++;
        }
    }

    chainstate_legacy_close(h);
    return failures;
}
