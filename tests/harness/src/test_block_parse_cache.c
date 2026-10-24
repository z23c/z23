/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for block_parse_cache (engine/modules/storage/src/block_parse_cache.c), the
 * BLOCK_PARSE_CACHE_CAPACITY-entry (height, block_hash) immutable body ring.
 * Converted stages pin and borrow the resident block; the compatibility get
 * API returns an independent byte-identical deep clone.
 *
 * A stale entry, key collision, shallow clone, or eviction error would hand a
 * wrong body to the fold and corrupt the UTXO set. These tests assert:
 *   (a) deep-clone equality + independence (miss then hit; mutate one, others
 *       and the cache entry unaffected),
 *   (b) no (height,hash) key collision (same height/diff hash, same hash/diff
 *       height both return their own bytes),
 *   (c) direct-ring replacement at the capacity boundary.
 *   (d) sealed segment source below the frontier (see test_segment_backed_read).
 *   (e) a MISS whose body does not hash to the requested key is never
 *       installed into the cache (verify-before-store).
 *   (f) block_parse_cache_evict(height,hash) removes exactly that one entry
 *       and leaves every other resident entry untouched.
 *
 * The cache is driven through its real public API (block_parse_cache_get /
 * block_parse_cache_clear). Misses are satisfied from synthetic blocks written
 * to a tmp datadir via write_block_to_disk (same fixture style as
 * test_disk_block_io.c), with a block_index whose phashBlock/nFile/nDataPos/
 * nStatus mirror what the production reader sees.
 */

#include "test/test_core.h"
#include "storage/block_parse_cache.h"
#include "storage/chain_segment.h"
#include "storage/disk_block_io.h"
#include "chain/chain.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "core/serialize.h"
#include "core/amount.h"
#include "core/uint256.h"
#include "util/reducer_stage_profile.h"
#include "json/json.h"
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

/* ── Fixture helpers ─────────────────────────────────────────── */

static void make_test_dir(char *buf, size_t len)
{
    snprintf(buf, len, "./test-tmp/%d_bpc", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(buf, 0755);
    char blocks[512];
    snprintf(blocks, sizeof(blocks), "%s/blocks", buf);
    mkdir(blocks, 0755);
}

static void cleanup_test_dir(const char *dir)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
     TEST_DISCARD(system(cmd));
}

/* Build a distinguishable synthetic block: `nout` outputs, output i carries
 * value (nseed + i) * COIN, and the header nTime = nseed. This makes both the
 * serialized bytes and the block hash a function of (nseed, nout), so two
 * fixtures with different (nseed, nout) are guaranteed distinct bodies. */
static void build_block(struct block *b, uint32_t nseed, int nout)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = nseed;
    b->header.nBits = 0x2000ffff;
    /* salt the header so nout-only differences yield a distinct hash */
    b->header.nNonce.data[0] = (uint8_t)(nseed & 0xff);
    b->header.nNonce.data[1] = (uint8_t)((nseed >> 8) & 0xff);
    b->num_vtx = 1;
    b->vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    transaction_init(&b->vtx[0]);
    transaction_alloc(&b->vtx[0], 1, nout);
    b->vtx[0].vin[0].sequence = 0xffffffff;
    for (int i = 0; i < nout; i++)
        b->vtx[0].vout[i].value = (CAmount)(nseed + (uint32_t)i) * COIN;
}

/* Serialize `b` into a freshly-malloc'd buffer; caller frees. */
static unsigned char *ser(const struct block *b, size_t *out_len)
{
    struct byte_stream s;
    stream_init(&s, 4096);
    if (!block_serialize(b, &s)) { stream_free(&s); return NULL; }
    unsigned char *buf = malloc(s.size ? s.size : 1); // raw-alloc-ok:test
    if (buf && s.size) memcpy(buf, s.data, s.size);
    *out_len = s.size;
    stream_free(&s);
    return buf;
}

/* A single fixture block on disk with its index entry primed. */
struct fixture {
    struct disk_block_pos pos;
    struct uint256        hash;        /* phashBlock storage */
    struct block_index    bi;
    unsigned char        *bytes;       /* canonical serialized body */
    size_t                len;
};

/* Write `src` to `datadir`, capture its canonical bytes + hash, and fill a
 * block_index that points read_block_from_disk_pread at it (BLOCK_HAVE_DATA,
 * nFile/nDataPos). `height` is the LRU key's height component. Returns true on
 * success. On failure, fx may be partially populated; caller frees fx->bytes. */
static bool make_fixture(struct fixture *fx, const char *datadir,
                         struct block *src, int height)
{
    memset(fx, 0, sizeof(*fx));
    fx->bytes = ser(src, &fx->len);
    if (!fx->bytes) return false;

    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    disk_block_pos_init(&fx->pos);
    if (!write_block_to_disk(src, &fx->pos, datadir, msg_start))
        return false;

    block_get_hash(src, &fx->hash);

    block_index_init(&fx->bi);
    fx->bi.nHeight = height;
    fx->bi.phashBlock = &fx->hash;
    fx->bi.nFile = fx->pos.nFile;
    fx->bi.nDataPos = fx->pos.nPos;
    fx->bi.nStatus |= BLOCK_HAVE_DATA;
    return true;
}

/* Serialize `b` and report whether it is byte-identical to the fixture's
 * canonical body. The serialized buffer is freed before returning. */
static bool bpc_body_is_fixture(const struct block *b, const struct fixture *fx)
{
    size_t len = 0;
    unsigned char *s = ser(b, &len);
    bool same = s && len == fx->len && memcmp(s, fx->bytes, len) == 0;
    free(s);
    return same;
}

/* Copy of `bi` with the disk pointer broken (HAVE_DATA off): a get under it
 * can only be satisfied by a cache HIT, never by a disk read. */
static struct block_index bpc_index_without_data(const struct block_index *bi)
{
    struct block_index broken = *bi;
    broken.nStatus &= ~(unsigned int)BLOCK_HAVE_DATA;
    return broken;
}

/* Get (height, fx->hash) through `bi` and report whether the returned body is
 * byte-identical to the fixture. The block is freed before returning. */
static bool bpc_get_matches_fixture(const struct fixture *fx,
                                    const struct block_index *bi,
                                    const char *datadir, int32_t height)
{
    struct block g; block_init(&g);
    bool got = block_parse_cache_get(height, fx->hash.data, bi, datadir, &g);
    bool same = got && bpc_body_is_fixture(&g, fx);
    block_free(&g);
    return same;
}

/* ── Test (a): deep-clone equality + independence ─────────────── */

static int test_deep_clone_equality(const char *datadir)
{
    int failures = 0;
    block_parse_cache_clear();

    TEST("bpc: miss then hit both byte-identical to source; clones independent") {
        struct block src;
        build_block(&src, 0xA1B2, 3);
        struct fixture fx;
        if (!make_fixture(&fx, datadir, &src, 100)) {
            printf("FAIL (fixture)\n"); failures++; block_free(&src);
            free(fx.bytes); goto done;
        }
        block_free(&src);

        /* MISS: first get reads from disk, populates the cache. */
        struct block b_miss; block_init(&b_miss);
        if (!block_parse_cache_get(100, fx.hash.data, &fx.bi, datadir, &b_miss)) {
            printf("FAIL (miss get)\n"); failures++;
            block_free(&b_miss); free(fx.bytes); goto done;
        }
        if (!bpc_body_is_fixture(&b_miss, &fx)) {
            printf("FAIL (miss body != source bytes)\n"); failures++;
            block_free(&b_miss); free(fx.bytes); goto done;
        }

        /* HIT: second get is served from cache; must equal source too. */
        struct block b_hit; block_init(&b_hit);
        if (!block_parse_cache_get(100, fx.hash.data, &fx.bi, datadir, &b_hit)) {
            printf("FAIL (hit get)\n"); failures++;
            block_free(&b_miss); block_free(&b_hit); free(fx.bytes); goto done;
        }
        if (!bpc_body_is_fixture(&b_hit, &fx)) {
            printf("FAIL (hit body != source bytes)\n"); failures++;
            block_free(&b_miss); block_free(&b_hit);
            free(fx.bytes); goto done;
        }

        /* INDEPENDENCE: mutate the miss clone, then free it; the hit clone
         * must be unchanged and a fresh hit must still equal the source. */
        b_miss.vtx[0].vout[0].value ^= 0xdeadbeef;
        block_free(&b_miss);

        if (b_hit.num_vtx != 1 ||
            b_hit.vtx[0].vout[0].value != (CAmount)(0xA1B2u) * COIN) {
            printf("FAIL (mutating/freeing miss clone disturbed hit clone)\n");
            failures++; block_free(&b_hit); free(fx.bytes); goto done;
        }
        block_free(&b_hit);

        struct block b_hit2; block_init(&b_hit2);
        if (!block_parse_cache_get(100, fx.hash.data, &fx.bi, datadir, &b_hit2)) {
            printf("FAIL (post-mutate hit get)\n"); failures++;
            block_free(&b_hit2); free(fx.bytes); goto done;
        }
        bool same = bpc_body_is_fixture(&b_hit2, &fx);
        block_free(&b_hit2);
        if (!same) {
            printf("FAIL (cache entry corrupted by consumer mutation/free)\n");
            failures++; free(fx.bytes); goto done;
        }

        free(fx.bytes);
        printf("OK\n");
    }
done:
    return failures;
}

/* ── Test (b): no (height, hash) key collision ────────────────── */

static int test_no_key_collision(const char *datadir)
{
    int failures = 0;
    block_parse_cache_clear();

    TEST("bpc: distinct keys never serve each other's bytes") {
        /* A: height 200, body S_A.  B: SAME height 200, DIFFERENT body/hash.
         * C: DIFFERENT height 201, but we force the SAME hash as A to prove
         *    the height component of the key is honored. */
        struct block ba, bb;
        build_block(&ba, 0x1111, 2);
        build_block(&bb, 0x2222, 5);   /* different bytes -> different hash */
        struct fixture fa, fb;
        if (!make_fixture(&fa, datadir, &ba, 200) ||
            !make_fixture(&fb, datadir, &bb, 200)) {
            printf("FAIL (fixtures)\n"); failures++;
            block_free(&ba); block_free(&bb);
            free(fa.bytes); free(fb.bytes); goto done;
        }
        block_free(&ba); block_free(&bb);

        if (memcmp(fa.hash.data, fb.hash.data, 32) == 0) {
            printf("FAIL (test setup: A and B hashes collided)\n");
            failures++; free(fa.bytes); free(fb.bytes); goto done;
        }

        /* Populate both (same height, different hash). */
        struct block ga, gb; block_init(&ga); block_init(&gb);
        bool oka = block_parse_cache_get(200, fa.hash.data, &fa.bi, datadir, &ga);
        bool okb = block_parse_cache_get(200, fb.hash.data, &fb.bi, datadir, &gb);
        if (!oka || !okb) {
            printf("FAIL (populate A/B)\n"); failures++;
            block_free(&ga); block_free(&gb);
            free(fa.bytes); free(fb.bytes); goto done;
        }
        block_free(&ga); block_free(&gb);

        /* Re-get each: must return ITS OWN bytes, not the sibling's. */
        bool a_ok = bpc_get_matches_fixture(&fa, &fa.bi, datadir, 200);
        bool b_ok = bpc_get_matches_fixture(&fb, &fb.bi, datadir, 200);
        if (!a_ok || !b_ok) {
            printf("FAIL (same-height/diff-hash collision: A_ok=%d B_ok=%d)\n",
                   a_ok, b_ok);
            failures++; free(fa.bytes); free(fb.bytes); goto done;
        }

        /* Same-hash / different-height: A's hash at height 201 is a MISS that
         * reads A's body via fa.bi; the bytes must be A's, and a re-get at 200
         * must still be A. */
        struct block rc; block_init(&rc);
        if (!block_parse_cache_get(201, fa.hash.data, &fa.bi, datadir, &rc)) {
            printf("FAIL (same-hash/diff-height get)\n"); failures++;
            block_free(&rc); free(fa.bytes); free(fb.bytes); goto done;
        }
        bool c_ok = bpc_body_is_fixture(&rc, &fa);
        block_free(&rc);

        bool a200_ok = bpc_get_matches_fixture(&fa, &fa.bi, datadir, 200);

        if (!c_ok || !a200_ok) {
            printf("FAIL (height component ignored: h201_ok=%d h200_still=%d)\n",
                   c_ok, a200_ok);
            failures++; free(fa.bytes); free(fb.bytes); goto done;
        }

        free(fa.bytes); free(fb.bytes);
        printf("OK\n");
    }
done:
    return failures;
}

/* ── Test (c): direct-ring replacement ───────────────────────── */

/* Derived from the production constant (block_parse_cache.h) so the test
 * tracks the real capacity boundary. */
#define BPC_CAP BLOCK_PARSE_CACHE_CAPACITY

/* Build the n ring fixtures (height 300+i) with deferred fdatasync. Returns
 * false if any setup fails; the caller frees every fxs[i].bytes. */
static bool bpc_ring_make_fixtures(struct fixture *fxs, int n, const char *datadir)
{
    /* Deferred fdatasync: one sync_pending() after the loop instead of N
     * inline barriers; the previous mode is restored afterwards. */
    bool prior_deferred = disk_block_io_deferred_sync_enabled();
    disk_block_io_set_deferred_sync(true);
    bool setup_ok = true;
    for (int i = 0; i < n; i++) {
        struct block src;
        build_block(&src, (uint32_t)(0x3000 + i), 1 + (i % 4));
        if (!make_fixture(&fxs[i], datadir, &src, 300 + i)) {
            setup_ok = false; block_free(&src); break;
        }
        block_free(&src);
        /* Heartbeat: keep the no-output watchdog quiet on a loaded box. */
        if (i > 0 && i % 512 == 0)
            printf("... fixtures %d/%d\n", i, n);
    }
    disk_block_io_sync_pending();
    disk_block_io_set_deferred_sync(prior_deferred);
    return setup_ok;
}

/* Insert all n fixtures as misses (n disk reads + cache stores). Returns
 * false after printing the failing index on the first get that fails. */
static bool bpc_ring_insert_all(const struct fixture *fxs, int n, const char *datadir)
{
    for (int i = 0; i < n; i++) {
        struct block g; block_init(&g);
        if (!block_parse_cache_get(300 + i, fxs[i].hash.data,
                                   &fxs[i].bi, datadir, &g)) {
            printf("FAIL (insert %d)\n", i);
            block_free(&g);
            return false;
        }
        block_free(&g);
    }
    return true;
}

/* Free every fixture body in the n-entry array, then the array itself. */
static void bpc_ring_fixtures_free(struct fixture *fxs, int n)
{
    for (int j = 0; j < n; j++) free(fxs[j].bytes);
    free(fxs);
}

static int test_ring_replacement(const char *datadir)
{
    int failures = 0;
    block_parse_cache_clear();

    TEST("bpc: ring collision replaces slot; other slots remain byte-identical") {
        /* CAP+1 distinct fixtures. Insert 0..CAP in order (each a miss). The
         * first and last heights map to the same direct-ring slot. */
        const int N = BPC_CAP + 1;
        struct fixture *fxs = calloc((size_t)N, sizeof(*fxs)); // raw-alloc-ok:test
        if (!fxs) { printf("FAIL (alloc)\n"); failures++; goto done; }

        if (!bpc_ring_make_fixtures(fxs, N, datadir)) {
            printf("FAIL (fixtures)\n"); failures++;
            bpc_ring_fixtures_free(fxs, N); goto done;
        }

        if (!bpc_ring_insert_all(fxs, N, datadir)) {
            failures++;
            bpc_ring_fixtures_free(fxs, N); goto done;
        }

        /* Every non-colliding key (1..CAP) must remain byte-correct. */
        bool recents_ok = true;
        for (int i = 1; i < N; i++)
            if (!bpc_get_matches_fixture(&fxs[i], &fxs[i].bi, datadir, 300 + i))
                recents_ok = false;
        if (!recents_ok) {
            printf("FAIL (a recent key was corrupted/lost)\n"); failures++;
            bpc_ring_fixtures_free(fxs, N); goto done;
        }

        /* idx 0 should have been replaced. Clear its block_index disk pointer
         * (HAVE_DATA off): a HIT ignores the index, an evicted entry takes the
         * MISS path and fails the HAVE_DATA guard, so get returns false. */
        struct block_index broken = bpc_index_without_data(&fxs[0].bi);
        struct block g0; block_init(&g0);
        bool still_cached = block_parse_cache_get(300 + 0, fxs[0].hash.data,
                                                  &broken, datadir, &g0);
        block_free(&g0);
        if (still_cached) {
            printf("FAIL (colliding key NOT replaced after %d inserts)\n", N);
            failures++;
            bpc_ring_fixtures_free(fxs, N); goto done;
        }

        /* And a normal re-get of idx 0 (intact index) re-reads from disk and
         * is still byte-correct. */
        if (!bpc_get_matches_fixture(&fxs[0], &fxs[0].bi, datadir, 300 + 0)) {
            printf("FAIL (re-read of evicted key not byte-correct)\n");
            failures++;
            bpc_ring_fixtures_free(fxs, N); goto done;
        }

        bpc_ring_fixtures_free(fxs, N);
        printf("OK\n");
    }
done:
    block_parse_cache_clear();
    return failures;
}

/* ── Test (e): verify-before-store — a MISS on wrong bytes never poisons
 * the requested key ───────────────────────────────────────────────
 * `fx_bad` is on disk but requested under `h_good`; a second fixture `fx_good`
 * whose bytes hash to `h_good` is then requested under the same key. A poisoned
 * (H,h_good) slot would return `fx_bad`'s bytes instead of `fx_good`'s. */

static int test_no_cache_on_hash_mismatch(const char *datadir)
{
    int failures = 0;
    block_parse_cache_clear();

    TEST("bpc: MISS body not matching the requested key is never cached") {
        const int H = 500;

        struct block bad_src;
        build_block(&bad_src, 0x5AD1, 2);
        struct fixture fx_bad;
        if (!make_fixture(&fx_bad, datadir, &bad_src, H)) {
            printf("FAIL (fx_bad fixture)\n"); failures++;
            block_free(&bad_src); free(fx_bad.bytes); goto done;
        }
        block_free(&bad_src);

        struct block good_src;
        build_block(&good_src, 0x6000D, 4);
        struct fixture fx_good;
        if (!make_fixture(&fx_good, datadir, &good_src, H)) {
            printf("FAIL (fx_good fixture)\n"); failures++;
            block_free(&good_src);
            free(fx_bad.bytes); free(fx_good.bytes); goto done;
        }
        block_free(&good_src);

        if (memcmp(fx_bad.hash.data, fx_good.hash.data, 32) == 0) {
            printf("FAIL (test setup: bad/good hashes collided)\n");
            failures++; free(fx_bad.bytes); free(fx_good.bytes); goto done;
        }

        /* "Bad read": fx_bad.bi genuinely points at fx_bad's on-disk bytes,
         * but we request the key under fx_good's hash (simulating a read
         * that came back wrong for the (height,hash) the caller wanted). */
        struct block out1; block_init(&out1);
        bool ok1 = block_parse_cache_get(H, fx_good.hash.data, &fx_bad.bi,
                                         datadir, &out1);
        if (!ok1) {
            printf("FAIL (bad-key get itself failed)\n"); failures++;
            block_free(&out1); free(fx_bad.bytes); free(fx_good.bytes);
            goto done;
        }
        /* The contract still hands back whatever was read (fx_bad's bytes); the
         * caller's gate decides. */
        bool out1_is_bad = bpc_body_is_fixture(&out1, &fx_bad);
        block_free(&out1);
        if (!out1_is_bad) {
            printf("FAIL (mismatched MISS did not return the actually-read bytes)\n");
            failures++; free(fx_bad.bytes); free(fx_good.bytes); goto done;
        }

        /* The (H, fx_good.hash) slot must not be poisoned: with an index
         * pointing at fx_good's bytes this is a genuine MISS returning
         * fx_good's bytes. */
        struct block out2; block_init(&out2);
        bool ok2 = block_parse_cache_get(H, fx_good.hash.data, &fx_good.bi,
                                         datadir, &out2);
        if (!ok2) {
            printf("FAIL (correct-key get failed)\n"); failures++;
            block_free(&out2); free(fx_bad.bytes); free(fx_good.bytes);
            goto done;
        }
        bool out2_is_good = bpc_body_is_fixture(&out2, &fx_good);
        bool out2_is_poisoned_bad = bpc_body_is_fixture(&out2, &fx_bad);
        block_free(&out2);
        if (!out2_is_good || out2_is_poisoned_bad) {
            printf("FAIL (poisoned slot served stale bytes: got_good=%d got_bad=%d)\n",
                   out2_is_good, out2_is_poisoned_bad);
            failures++; free(fx_bad.bytes); free(fx_good.bytes); goto done;
        }

        /* And it is now a real, correctly-keyed cache entry: a third get
         * under the same key hits it and still returns fx_good's bytes. */
        bool out3_ok = bpc_get_matches_fixture(&fx_good, &fx_good.bi, datadir, H);
        if (!out3_ok) {
            printf("FAIL (post-fix hit did not serve fx_good bytes)\n");
            failures++; free(fx_bad.bytes); free(fx_good.bytes); goto done;
        }

        free(fx_bad.bytes); free(fx_good.bytes);
        printf("OK\n");
    }
done:
    block_parse_cache_clear();
    return failures;
}

/* ── Test (f): block_parse_cache_evict removes exactly one key ────
 * Deterministic, single-threaded: populate three distinct keys, evict the
 * middle one, and prove (via the same broken-index trick as the LRU test)
 * that exactly the evicted key is forced back to a MISS while its siblings
 * remain resident cache HITs. */

static int test_evict_removes_one_key(const char *datadir)
{
    int failures = 0;
    block_parse_cache_clear();

    TEST("bpc: evict removes exactly the targeted key, siblings untouched") {
        struct block b1, b2, b3;
        build_block(&b1, 0x7001, 1);
        build_block(&b2, 0x7002, 2);
        build_block(&b3, 0x7003, 3);
        struct fixture f1, f2, f3;
        bool setup_ok = make_fixture(&f1, datadir, &b1, 600) &&
                        make_fixture(&f2, datadir, &b2, 601) &&
                        make_fixture(&f3, datadir, &b3, 602);
        block_free(&b1); block_free(&b2); block_free(&b3);
        if (!setup_ok) {
            printf("FAIL (fixtures)\n"); failures++;
            free(f1.bytes); free(f2.bytes); free(f3.bytes); goto done;
        }

        /* Populate all three (each a genuine MISS + cache install). */
        struct block g1, g2, g3;
        block_init(&g1); block_init(&g2); block_init(&g3);
        bool got = block_parse_cache_get(600, f1.hash.data, &f1.bi, datadir, &g1) &&
                   block_parse_cache_get(601, f2.hash.data, &f2.bi, datadir, &g2) &&
                   block_parse_cache_get(602, f3.hash.data, &f3.bi, datadir, &g3);
        block_free(&g1); block_free(&g2); block_free(&g3);
        if (!got) {
            printf("FAIL (populate)\n"); failures++;
            free(f1.bytes); free(f2.bytes); free(f3.bytes); goto done;
        }

        /* Evict only key 2. */
        block_parse_cache_evict(601, f2.hash.data);

        /* Key 2 must now be a MISS: break its index and confirm the get
         * fails (a HIT would ignore the broken index entirely). */
        struct block_index broken2 = bpc_index_without_data(&f2.bi);
        struct block e2; block_init(&e2);
        bool still2 = block_parse_cache_get(601, f2.hash.data, &broken2,
                                            datadir, &e2);
        block_free(&e2);
        if (still2) {
            printf("FAIL (evicted key still served from cache)\n");
            failures++; free(f1.bytes); free(f2.bytes); free(f3.bytes);
            goto done;
        }

        /* Keys 1 and 3 must still be resident HITs: break THEIR indexes too
         * and confirm the get still succeeds and returns the right bytes —
         * only possible if served from the (untouched) cache entry. */
        struct block_index broken1 = bpc_index_without_data(&f1.bi);
        struct block_index broken3 = bpc_index_without_data(&f3.bi);

        bool sib1_ok = bpc_get_matches_fixture(&f1, &broken1, datadir, 600);
        bool sib3_ok = bpc_get_matches_fixture(&f3, &broken3, datadir, 602);
        if (!sib1_ok || !sib3_ok) {
            printf("FAIL (evict disturbed a sibling key: sib1_ok=%d sib3_ok=%d)\n",
                   sib1_ok, sib3_ok);
            failures++; free(f1.bytes); free(f2.bytes); free(f3.bytes);
            goto done;
        }

        /* Evicting an absent key (or NULL hash) is a safe no-op. */
        block_parse_cache_evict(999999, f1.hash.data);
        block_parse_cache_evict(600, NULL);

        free(f1.bytes); free(f2.bytes); free(f3.bytes);
        printf("OK\n");
    }
done:
    block_parse_cache_clear();
    return failures;
}

/* ── Test (d): sealed-segment source below the frontier ───────────
 * The fold substrate: when a sealed segment covers a height, the miss path
 * serves the body from the mmap'd segment (byte-identical, hash-bound) instead
 * of blk*.dat. We prove it by breaking the disk pointer so ONLY the segment can
 * satisfy the read, and by confirming an UNCOVERED height with the same broken
 * disk pointer genuinely fails — so the segment is demonstrably the source. */

struct seg_body_src { uint32_t h; const unsigned char *bytes; size_t len; };
static bool seg_body_src_fn(void *u, uint32_t h, uint8_t **b, size_t *l)
{
    struct seg_body_src *s = u;
    if (h != s->h) return false;
    uint8_t *c = malloc(s->len ? s->len : 1); // raw-alloc-ok:test
    if (!c) return false;
    if (s->len) memcpy(c, s->bytes, s->len);
    *b = c; *l = s->len;
    return true;
}

static int test_segment_backed_read(const char *base)
{
    int failures = 0;
    char dir[300];    snprintf(dir, sizeof(dir), "%s/segrd", base);      mkdir(dir, 0755);
    char blocks[400]; snprintf(blocks, sizeof(blocks), "%s/blocks", dir);   mkdir(blocks, 0755);
    char segd[400];   snprintf(segd, sizeof(segd), "%s/segments", dir);     mkdir(segd, 0755);

    block_parse_cache_clear();

    TEST("bpc: sealed segment serves the fold body byte-identically (disk broken)") {
        const uint32_t H = 1000;
        struct block src;
        build_block(&src, 0xBEEF, 3);
        struct fixture fx;
        if (!make_fixture(&fx, dir, &src, (int)H)) {
            printf("FAIL (fixture)\n"); failures++; block_free(&src);
            free(fx.bytes); goto done;
        }
        block_free(&src);

        /* Seal the exact on-disk bytes for height H into <dir>/segments. */
        struct seg_body_src ss = { .h = H, .bytes = fx.bytes, .len = fx.len };
        char serr[256] = {0};
        enum cseg_status st = chain_segment_seal_range(segd, seg_body_src_fn, &ss,
                                                       H, 1, serr, sizeof(serr));
        if (st != CSEG_OK) {
            printf("FAIL (seal: %s)\n", serr); failures++;
            free(fx.bytes); goto done;
        }

        /* Break the disk pointer: only the sealed segment can now serve H. */
        fx.bi.nStatus &= ~(unsigned int)BLOCK_HAVE_DATA;
        fx.bi.nFile = -1;
        fx.bi.nDataPos = 0;
        block_parse_cache_clear();

        /* COVERED height -> served from the segment, byte-identical to disk.
         * Snapshot the fold read-source counters (block_parse_cache.h) around
         * the call: this is the exact per-call source-of-truth the
         * chain_segments dumper's fold_reads_from_segment counter is built
         * on, so proving it increments here proves the dumper is honest. */
        uint64_t seg_before = 0, blk_before = 0;
        block_parse_cache_segment_read_stats(&seg_before, &blk_before);
        struct block out; block_init(&out);
        bool ok = block_parse_cache_get((int32_t)H, fx.hash.data, &fx.bi, dir, &out);
        if (!ok) {
            printf("FAIL (segment get with broken disk)\n"); failures++;
            block_free(&out); free(fx.bytes); goto done;
        }
        uint64_t seg_after = 0, blk_after = 0;
        block_parse_cache_segment_read_stats(&seg_after, &blk_after);
        if (seg_after != seg_before + 1 || blk_after != blk_before) {
            printf("FAIL (segment-hit counter did not increment: seg %llu->%llu blk %llu->%llu)\n",
                   (unsigned long long)seg_before, (unsigned long long)seg_after,
                   (unsigned long long)blk_before, (unsigned long long)blk_after);
            failures++; block_free(&out); free(fx.bytes); goto done;
        }
        size_t l = 0; unsigned char *s = ser(&out, &l);
        bool ident = s && l == fx.len && memcmp(s, fx.bytes, l) == 0;
        free(s); block_free(&out);
        if (!ident) {
            printf("FAIL (segment body != on-disk bytes)\n"); failures++;
            free(fx.bytes); goto done;
        }

        /* UNCOVERED height, same broken disk -> must fail, proving the segment
         * (not some disk fallback) is what satisfied the covered read. This
         * is a blk*.dat-path attempt (segment source declined), so it must
         * bump the blk*.dat counter, not the segment counter. */
        struct block_index bi2 = fx.bi;
        bi2.nHeight = (int)H + 50;
        struct block out2; block_init(&out2);
        bool ok2 = block_parse_cache_get((int32_t)H + 50, fx.hash.data, &bi2,
                                         dir, &out2);
        block_free(&out2);
        if (ok2) {
            printf("FAIL (uncovered height served despite broken disk)\n");
            failures++; free(fx.bytes); goto done;
        }
        uint64_t seg_final = 0, blk_final = 0;
        block_parse_cache_segment_read_stats(&seg_final, &blk_final);
        if (seg_final != seg_after || blk_final != blk_after + 1) {
            printf("FAIL (blk*.dat-fallback counter did not increment on uncovered read)\n");
            failures++; free(fx.bytes); goto done;
        }

        free(fx.bytes);
        printf("OK\n");
    }
done:
    block_parse_cache_clear();
    return failures;
}

/* ── Test (g): a corrupt sealed segment fails CLOSED and falls back ───
 * A tampered segment is caught (whole-segment digest on open) so
 * bpc_segment_try logs + returns false. With blk*.dat intact the reader falls
 * back to disk; with the disk pointer also broken the read fails closed
 * rather than serve unverified bytes. */
static int test_segment_corruption_fails_closed(const char *base)
{
    int failures = 0;
    char dir[300];    snprintf(dir, sizeof(dir), "%s/segcorrupt", base);   mkdir(dir, 0755);
    char blocks[400]; snprintf(blocks, sizeof(blocks), "%s/blocks", dir);  mkdir(blocks, 0755);
    char segd[400];   snprintf(segd, sizeof(segd), "%s/segments", dir);    mkdir(segd, 0755);

    block_parse_cache_clear();

    TEST("bpc: corrupt sealed segment fails closed; falls back to blk*.dat when present") {
        const uint32_t H = 1200;
        struct block src;
        build_block(&src, 0xC0DE, 2);
        struct fixture fx;
        if (!make_fixture(&fx, dir, &src, (int)H)) {
            printf("FAIL (fixture)\n"); failures++; block_free(&src);
            free(fx.bytes); goto done;
        }
        block_free(&src);

        /* Seal the exact on-disk bytes for H into <dir>/segments. */
        struct seg_body_src ss = { .h = H, .bytes = fx.bytes, .len = fx.len };
        char serr[256] = {0};
        enum cseg_status st = chain_segment_seal_range(segd, seg_body_src_fn, &ss,
                                                       H, 1, serr, sizeof(serr));
        if (st != CSEG_OK) {
            printf("FAIL (seal: %s)\n", serr); failures++;
            free(fx.bytes); goto done;
        }

        /* Corrupt one data byte WITHOUT re-fixing the trailer, so the
         * whole-segment SHA3 fails when the store opens the segment on read. */
        char segfile[600];
        snprintf(segfile, sizeof(segfile), "%s/seg-%u-1.dat", segd, H);
        chmod(segfile, 0644);
        long tamper_off = 32 + 48 + 2;   /* header(32) + 1 index entry(48) + 2 */
        FILE *f = fopen(segfile, "r+b");
        bool tampered = false;
        if (f) {
            fseek(f, tamper_off, SEEK_SET);
            int c = fgetc(f);
            fseek(f, tamper_off, SEEK_SET);
            fputc(c ^ 0xff, f);
            fclose(f);
            tampered = true;
        }
        if (!tampered) {
            printf("FAIL (tamper write)\n"); failures++;
            free(fx.bytes); goto done;
        }

        /* Case 1 — FALLBACK: disk pointer intact. bpc_segment_try must reject
         * the corrupt segment and the reader must fall back to blk*.dat,
         * returning the correct bytes byte-identically. */
        block_parse_cache_clear();
        struct block out; block_init(&out);
        bool ok = block_parse_cache_get((int32_t)H, fx.hash.data, &fx.bi, dir, &out);
        size_t l = 0; unsigned char *s = ok ? ser(&out, &l) : NULL;
        bool fell_back_ok = ok && s && l == fx.len && memcmp(s, fx.bytes, l) == 0;
        free(s); block_free(&out);
        if (!fell_back_ok) {
            printf("FAIL (corrupt segment did not fall back to disk)\n");
            failures++; free(fx.bytes); goto done;
        }

        /* Case 2 — FAIL CLOSED: break the disk pointer too. With neither a
         * valid segment nor a valid blk*.dat body, the read must return false
         * rather than serve unverified bytes. */
        block_parse_cache_clear();
        struct block_index broken = fx.bi;
        broken.nStatus &= ~(unsigned int)BLOCK_HAVE_DATA;
        broken.nFile = -1;
        broken.nDataPos = 0;
        struct block out2; block_init(&out2);
        bool ok2 = block_parse_cache_get((int32_t)H, fx.hash.data, &broken, dir, &out2);
        block_free(&out2);
        if (ok2) {
            printf("FAIL (corrupt segment + broken disk served bytes; not fail-closed)\n");
            failures++; free(fx.bytes); goto done;
        }

        free(fx.bytes);
        printf("OK\n");
    }
done:
    block_parse_cache_clear();
    return failures;
}

struct borrowed_reader_ctx {
    const struct fixture *fx;
    const char *datadir;
    int failures;
};

static void *borrowed_reader(void *arg)
{
    struct borrowed_reader_ctx *ctx = arg;
    for (int i = 0; i < 100; i++) {
        struct block_parse_handle h;
        if (!block_parse_cache_acquire(1400, ctx->fx->hash.data, &ctx->fx->bi,
                                       ctx->datadir, &h)) {
            ctx->failures++;
            continue;
        }
        const struct block *b = block_parse_handle_block(&h);
        if (!b || b->num_vtx != 1 || b->vtx[0].num_vout != 3)
            ctx->failures++;
        block_parse_cache_release(&h);
    }
    return NULL;
}

/* Each borrowed-contract case is its own function so the fixture pair stays
 * shared while every TEST block keeps its own assertions. */
static int test_borrowed_pin_survives(struct fixture *fa, struct fixture *fb,
                                      const char *datadir)
{
    int failures = 0;
    TEST("bpc borrowed: pin survives collision and pressure clear") {
        block_parse_cache_clear();
        struct block_parse_handle a, collision;
        bool ok = block_parse_cache_acquire(1400, fa->hash.data, &fa->bi,
                                            datadir, &a) &&
                  block_parse_cache_acquire(
                      1400 + BLOCK_PARSE_CACHE_CAPACITY, fb->hash.data, &fb->bi,
                      datadir, &collision);
        const struct block *held = block_parse_handle_block(&a);
        block_parse_cache_clear();
        ok = ok && held && held->vtx[0].num_vout == 3;
        block_parse_cache_release(&collision);
        block_parse_cache_release(&a);
        struct block_index broken = bpc_index_without_data(&fa->bi);
        struct block after; block_init(&after);
        bool resident = block_parse_cache_get(1400, fa->hash.data, &broken,
                                              datadir, &after);
        block_free(&after);
        if (!ok || resident) { printf("FAIL (pin/clear)\n"); failures++; }
        else printf("OK\n");
    }
    return failures;
}

static int test_borrowed_stale_release(struct fixture *fa, struct fixture *fb,
                                       const char *datadir)
{
    int failures = 0;
    TEST("bpc borrowed: generation makes stale release harmless") {
        block_parse_cache_clear();
        struct block_parse_handle a, b;
        bool ok = block_parse_cache_acquire(1400, fa->hash.data, &fa->bi,
                                            datadir, &a);
        struct block_parse_handle stale = a;
        block_parse_cache_release(&a);
        ok = ok && block_parse_cache_acquire(
            1400 + BLOCK_PARSE_CACHE_CAPACITY, fb->hash.data, &fb->bi, datadir,
            &b);
        block_parse_cache_release(&stale);
        block_parse_cache_clear();
        const struct block *still_pinned = block_parse_handle_block(&b);
        ok = ok && still_pinned && still_pinned->vtx[0].num_vout == 4;
        block_parse_cache_release(&b);
        if (!ok) { printf("FAIL (stale generation)\n"); failures++; }
        else printf("OK\n");
    }
    return failures;
}

static int test_borrowed_concurrent_readers(const struct fixture *fa,
                                            const char *datadir)
{
    int failures = 0;
    TEST("bpc borrowed: concurrent readers remain immutable") {
        block_parse_cache_clear();
        enum { N = 8 };
        pthread_t threads[N];
        struct borrowed_reader_ctx ctx[N];
        bool spawned[N] = {0};
        for (int i = 0; i < N; i++) {
            ctx[i] = (struct borrowed_reader_ctx){ .fx = fa,
                                                   .datadir = datadir };
            spawned[i] = pthread_create(&threads[i], NULL, borrowed_reader,
                                        &ctx[i]) == 0;
        }
        bool ok = true;
        for (int i = 0; i < N; i++) {
            if (spawned[i]) pthread_join(threads[i], NULL);
            if (!spawned[i] || ctx[i].failures) ok = false;
        }
        if (!ok) { printf("FAIL (concurrent readers)\n"); failures++; }
        else printf("OK\n");
    }
    return failures;
}

static int test_borrowed_wire_identity(struct fixture *fa, const char *datadir)
{
    int failures = 0;
    TEST("bpc borrowed: borrowed and legacy bytes are identical") {
        block_parse_cache_clear();
        struct block_parse_handle h;
        struct block legacy; block_init(&legacy);
        bool ok = block_parse_cache_acquire(1400, fa->hash.data, &fa->bi,
                                            datadir, &h) &&
                  block_parse_cache_get(1400, fa->hash.data, &fa->bi, datadir,
                                        &legacy);
        size_t blen = 0, llen = 0;
        unsigned char *bb = ok ? ser(block_parse_handle_block(&h), &blen) : NULL;
        unsigned char *lb = ok ? ser(&legacy, &llen) : NULL;
        ok = ok && bb && lb && blen == llen && memcmp(bb, lb, blen) == 0;
        free(bb); free(lb); block_free(&legacy);
        block_parse_cache_release(&h);
        if (!ok) { printf("FAIL (wire identity)\n"); failures++; }
        else printf("OK\n");
    }
    return failures;
}

static int test_borrowed_contract(const char *datadir)
{
    int failures = 0;
    struct block a_src, b_src;
    build_block(&a_src, 0xB011, 3);
    build_block(&b_src, 0xB022, 4);
    struct fixture fa, fb;
    bool fixtures = make_fixture(&fa, datadir, &a_src, 1400) &&
                    make_fixture(&fb, datadir, &b_src,
                                 1400 + BLOCK_PARSE_CACHE_CAPACITY);
    block_free(&a_src);
    block_free(&b_src);
    if (!fixtures) {
        free(fa.bytes); free(fb.bytes);
        return 1;
    }

    failures += test_borrowed_pin_survives(&fa, &fb, datadir);
    failures += test_borrowed_stale_release(&fa, &fb, datadir);
    failures += test_borrowed_concurrent_readers(&fa, datadir);
    failures += test_borrowed_wire_identity(&fa, datadir);

    free(fa.bytes); free(fb.bytes);
    block_parse_cache_clear();
    return failures;
}

/* json_get(v, key) that yields NULL when the parent `v` is absent. */
static const struct json_value *bpc_json_child(const struct json_value *v,
                                               const char *key)
{
    return v ? json_get(v, key) : NULL;
}

static int test_profile_reset(void)
{
    int failures = 0;
    TEST("reducer profile: counters are resettable and unmeasured fields null") {
        reducer_stage_profile_reset();
        reducer_stage_profile_add(REDUCER_PROFILE_BODY_PERSIST, RPF_BLOCKS, 7);
        reducer_stage_profile_observe_us(REDUCER_PROFILE_BODY_PERSIST,
                                         RPF_TOTAL_US, 1);
        reducer_stage_profile_observe_us(REDUCER_PROFILE_BODY_PERSIST,
                                         RPF_TOTAL_US, 2);
        reducer_stage_profile_observe_us(REDUCER_PROFILE_BODY_PERSIST,
                                         RPF_TOTAL_US, 3);
        reducer_stage_profile_observe_us(REDUCER_PROFILE_BODY_PERSIST,
                                         RPF_TOTAL_US, 100);
        struct json_value root;
        json_init(&root);
        bool ok = reducer_stage_profile_dump_state_json(&root, NULL);
        const struct json_value *body = json_get(&root, "body_persist");
        const struct json_value *cumulative = bpc_json_child(body, "cumulative");
        const struct json_value *blocks = bpc_json_child(cumulative, "blocks");
        const struct json_value *ctx = bpc_json_child(cumulative,
                                                      "contextual_gate_us");
        const struct json_value *quantiles =
            bpc_json_child(cumulative, "latency_quantiles_us");
        const struct json_value *total_q = bpc_json_child(quantiles, "total_us");
        const struct json_value *samples = bpc_json_child(total_q, "samples");
        const struct json_value *p50 = bpc_json_child(total_q, "p50");
        const struct json_value *p95 = bpc_json_child(total_q, "p95");
        ok = ok && blocks && json_get_int(blocks) == 7 && ctx &&
             json_is_null(ctx) && samples && json_get_int(samples) == 4 &&
             p50 && json_get_int(p50) == 3 && p95 && json_get_int(p95) == 127;
        reducer_stage_profile_reset();
        json_free(&root);
        if (!ok) { printf("FAIL (profile reset/nullability)\n"); failures++; }
        else printf("OK\n");
    }
    return failures;
}

/* ── Entry point ─────────────────────────────────────────────── */

int test_block_parse_cache(void)
{
    printf("\n=== block_parse_cache (borrow / key / ring / segment) ===\n");
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    failures += test_deep_clone_equality(tmpdir);
    failures += test_no_key_collision(tmpdir);
    failures += test_ring_replacement(tmpdir);
    failures += test_no_cache_on_hash_mismatch(tmpdir);
    failures += test_evict_removes_one_key(tmpdir);
    failures += test_segment_backed_read(tmpdir);
    failures += test_segment_corruption_fails_closed(tmpdir);
    failures += test_borrowed_contract(tmpdir);
    failures += test_profile_reset();

    block_parse_cache_clear();
    cleanup_test_dir(tmpdir);
    return failures;
}
