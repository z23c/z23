/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for block_parse_cache (engine/modules/storage/src/block_parse_cache.c), the
 * BLOCK_PARSE_CACHE_CAPACITY-entry (height, block_hash) immutable body ring.
 * Converted stages pin and borrow the resident block; the compatibility get
 * API returns an independent byte-identical deep clone.
 *
 * A silent defect here (stale entry, key collision, shallow clone, eviction
 * error) would hand a WRONG body to body_persist/script_validate/proof_validate/
 * utxo_apply and corrupt the UTXO set. These tests assert the properties
 * that protect the fold:
 *   (a) deep-clone equality + independence (miss then hit; mutate one, others
 *       and the cache entry unaffected),
 *   (b) no (height,hash) key collision (same height/diff hash, same hash/diff
 *       height both return their own bytes),
 *   (c) direct-ring replacement at the capacity boundary.
 *   (d) sealed segment source below the frontier (see test_segment_backed_read).
 *   (e) a MISS whose body does NOT hash to the requested key is never
 *       installed into the cache (verify-before-store) — a bad disk read at
 *       height H must not poison the (H,hash) slot for a later, correct read.
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
    (void)system(cmd);
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
    /* salt the header so even nout-only differences yield a distinct hash */
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
        size_t l1 = 0; unsigned char *s1 = ser(&b_miss, &l1);
        if (!s1 || l1 != fx.len || memcmp(s1, fx.bytes, l1) != 0) {
            printf("FAIL (miss body != source bytes)\n"); failures++;
            free(s1); block_free(&b_miss); free(fx.bytes); goto done;
        }
        free(s1);

        /* HIT: second get is served from cache; must equal source too. */
        struct block b_hit; block_init(&b_hit);
        if (!block_parse_cache_get(100, fx.hash.data, &fx.bi, datadir, &b_hit)) {
            printf("FAIL (hit get)\n"); failures++;
            block_free(&b_miss); block_free(&b_hit); free(fx.bytes); goto done;
        }
        size_t l2 = 0; unsigned char *s2 = ser(&b_hit, &l2);
        if (!s2 || l2 != fx.len || memcmp(s2, fx.bytes, l2) != 0) {
            printf("FAIL (hit body != source bytes)\n"); failures++;
            free(s2); block_free(&b_miss); block_free(&b_hit);
            free(fx.bytes); goto done;
        }
        free(s2);

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
        size_t l3 = 0; unsigned char *s3 = ser(&b_hit2, &l3);
        bool same = s3 && l3 == fx.len && memcmp(s3, fx.bytes, l3) == 0;
        free(s3); block_free(&b_hit2);
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
        struct block ra, rb; block_init(&ra); block_init(&rb);
        block_parse_cache_get(200, fa.hash.data, &fa.bi, datadir, &ra);
        block_parse_cache_get(200, fb.hash.data, &fb.bi, datadir, &rb);
        size_t la = 0, lb = 0;
        unsigned char *sa = ser(&ra, &la), *sb = ser(&rb, &lb);
        bool a_ok = sa && la == fa.len && memcmp(sa, fa.bytes, la) == 0;
        bool b_ok = sb && lb == fb.len && memcmp(sb, fb.bytes, lb) == 0;
        free(sa); free(sb); block_free(&ra); block_free(&rb);
        if (!a_ok || !b_ok) {
            printf("FAIL (same-height/diff-hash collision: A_ok=%d B_ok=%d)\n",
                   a_ok, b_ok);
            failures++; free(fa.bytes); free(fb.bytes); goto done;
        }

        /* Same-hash / different-height: ask for A's hash at height 201. A's
         * disk fixture is at height 200; with a height-honoring key this is a
         * MISS that reads A's body from A's index (we hand fa.bi, which points
         * at A's disk bytes). The returned body must be A's bytes, and it must
         * NOT be served from the height-200 entry's slot in a way that
         * corrupts it. Then a re-get at 200 must still be A. */
        struct block rc; block_init(&rc);
        if (!block_parse_cache_get(201, fa.hash.data, &fa.bi, datadir, &rc)) {
            printf("FAIL (same-hash/diff-height get)\n"); failures++;
            block_free(&rc); free(fa.bytes); free(fb.bytes); goto done;
        }
        size_t lc = 0; unsigned char *sc = ser(&rc, &lc);
        bool c_ok = sc && lc == fa.len && memcmp(sc, fa.bytes, lc) == 0;
        free(sc); block_free(&rc);

        struct block ra2; block_init(&ra2);
        block_parse_cache_get(200, fa.hash.data, &fa.bi, datadir, &ra2);
        size_t la2 = 0; unsigned char *sa2 = ser(&ra2, &la2);
        bool a200_ok = sa2 && la2 == fa.len && memcmp(sa2, fa.bytes, la2) == 0;
        free(sa2); block_free(&ra2);

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

/* Derived from the production constant (block_parse_cache.h) rather than a
 * duplicated magic number, so this test always exercises the REAL capacity
 * boundary instead of silently drifting out of sync with it. */
#define BPC_CAP BLOCK_PARSE_CACHE_CAPACITY

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

        /* Deferred fdatasync: N inline fdatasync() barriers (one per fixture)
         * dominate wall time under load, since every write lands in the same
         * blk file and each barrier serializes behind the last — this test's
         * disk bytes are gone the moment the tmp datadir is removed below, so
         * durability mid-loop buys nothing. Batch to a single sync_pending()
         * after the loop; restore whatever mode was in effect before this
         * test ran so other tests in the group are unaffected. */
        bool prior_deferred = disk_block_io_deferred_sync_enabled();
        disk_block_io_set_deferred_sync(true);
        bool setup_ok = true;
        for (int i = 0; i < N; i++) {
            struct block src;
            build_block(&src, (uint32_t)(0x3000 + i), 1 + (i % 4));
            if (!make_fixture(&fxs[i], datadir, &src, 300 + i)) {
                setup_ok = false; block_free(&src); break;
            }
            block_free(&src);
            /* Heartbeat: keep the no-output watchdog quiet on a loaded box
             * even if per-fixture cost regresses again later. */
            if (i > 0 && i % 512 == 0)
                printf("... fixtures %d/%d\n", i, N);
        }
        disk_block_io_sync_pending();
        disk_block_io_set_deferred_sync(prior_deferred);
        if (!setup_ok) {
            printf("FAIL (fixtures)\n"); failures++;
            for (int i = 0; i < N; i++) free(fxs[i].bytes);
            free(fxs); goto done;
        }

        /* Insert all N as misses (this is N disk reads + cache stores). */
        for (int i = 0; i < N; i++) {
            struct block g; block_init(&g);
            if (!block_parse_cache_get(300 + i, fxs[i].hash.data,
                                       &fxs[i].bi, datadir, &g)) {
                printf("FAIL (insert %d)\n", i); failures++;
                block_free(&g);
                for (int j = 0; j < N; j++) free(fxs[j].bytes);
                free(fxs); goto done;
            }
            block_free(&g);
        }

        /* Every non-colliding key (1..CAP) must remain byte-correct.
         * We cannot observe hit-vs-miss directly through the API, but a
         * correct entry returns its own bytes regardless; the eviction
         * property is exercised by confirming idx 0 was replaced (below) while
         * every later key is intact. */
        bool recents_ok = true;
        for (int i = 1; i < N; i++) {
            struct block g; block_init(&g);
            block_parse_cache_get(300 + i, fxs[i].hash.data,
                                  &fxs[i].bi, datadir, &g);
            size_t l = 0; unsigned char *s = ser(&g, &l);
            if (!s || l != fxs[i].len || memcmp(s, fxs[i].bytes, l) != 0)
                recents_ok = false;
            free(s); block_free(&g);
        }
        if (!recents_ok) {
            printf("FAIL (a recent key was corrupted/lost)\n"); failures++;
            for (int j = 0; j < N; j++) free(fxs[j].bytes);
            free(fxs); goto done;
        }

        /* idx 0 should have been replaced. Prove replacement structurally: clear
         * its block_index disk pointer (HAVE_DATA off). A cache HIT would
         * ignore the index and still return bytes; an evicted entry forces the
         * MISS path, which now fails the HAVE_DATA guard -> get returns false.
         * That false is the observable proof the colliding slot was replaced. */
        struct block_index broken = fxs[0].bi;
        broken.nStatus &= ~(unsigned int)BLOCK_HAVE_DATA;
        struct block g0; block_init(&g0);
        bool still_cached = block_parse_cache_get(300 + 0, fxs[0].hash.data,
                                                  &broken, datadir, &g0);
        block_free(&g0);
        if (still_cached) {
            printf("FAIL (colliding key NOT replaced after %d inserts)\n", N);
            failures++;
            for (int j = 0; j < N; j++) free(fxs[j].bytes);
            free(fxs); goto done;
        }

        /* And a normal re-get of idx 0 (intact index) re-reads from disk and
         * is still byte-correct. */
        struct block g0b; block_init(&g0b);
        bool reread = block_parse_cache_get(300 + 0, fxs[0].hash.data,
                                            &fxs[0].bi, datadir, &g0b);
        size_t l0 = 0; unsigned char *s0 = reread ? ser(&g0b, &l0) : NULL;
        bool reread_ok = s0 && l0 == fxs[0].len &&
                         memcmp(s0, fxs[0].bytes, l0) == 0;
        free(s0); block_free(&g0b);
        if (!reread_ok) {
            printf("FAIL (re-read of evicted key not byte-correct)\n");
            failures++;
            for (int j = 0; j < N; j++) free(fxs[j].bytes);
            free(fxs); goto done;
        }

        for (int j = 0; j < N; j++) free(fxs[j].bytes);
        free(fxs);
        printf("OK\n");
    }
done:
    block_parse_cache_clear();
    return failures;
}

/* ── Test (e): verify-before-store — a MISS on wrong bytes never poisons
 * the requested key ───────────────────────────────────────────────
 * Reproduces the audit-confirmed defect: a MISS whose read body does NOT
 * hash to the requested key (a bad disk read / stale bytes at a recycled
 * position) used to be cached anyway under the requested (height,hash), so
 * every later refetch of that key kept being served the SAME wrong bytes
 * forever — a stuck-refetch liveness wedge. We drive this through the real
 * public API only: `fx_bad` is genuinely on disk, but we ask for it under
 * `h_good` (a different block's real hash) — a "bad read" from the cache's
 * point of view. Then a second, distinct fixture `fx_good` — whose real
 * on-disk bytes DO hash to `h_good` — is asked for under the same key. If
 * the first call had wrongly poisoned (H,h_good), this second call would
 * return `fx_bad`'s bytes (a cache HIT on the poisoned slot) instead of
 * `fx_good`'s bytes (a genuine MISS reading the correct body). */

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
        /* Sanity: the contract still hands back whatever was actually read
         * (fx_bad's bytes) — today's "caller's gate decides" behavior. */
        size_t l1 = 0; unsigned char *s1 = ser(&out1, &l1);
        bool out1_is_bad = s1 && l1 == fx_bad.len &&
                           memcmp(s1, fx_bad.bytes, l1) == 0;
        free(s1); block_free(&out1);
        if (!out1_is_bad) {
            printf("FAIL (mismatched MISS did not return the actually-read bytes)\n");
            failures++; free(fx_bad.bytes); free(fx_good.bytes); goto done;
        }

        /* The (H, fx_good.hash) slot must NOT have been poisoned with
         * fx_bad's bytes. Ask for the same key again, this time with an
         * index pointing at fx_good's real (correct) on-disk bytes. A fixed
         * cache treats this as a genuine MISS and returns fx_good's bytes; a
         * poisoned cache would HIT and return fx_bad's bytes instead. */
        struct block out2; block_init(&out2);
        bool ok2 = block_parse_cache_get(H, fx_good.hash.data, &fx_good.bi,
                                         datadir, &out2);
        if (!ok2) {
            printf("FAIL (correct-key get failed)\n"); failures++;
            block_free(&out2); free(fx_bad.bytes); free(fx_good.bytes);
            goto done;
        }
        size_t l2 = 0; unsigned char *s2 = ser(&out2, &l2);
        bool out2_is_good = s2 && l2 == fx_good.len &&
                            memcmp(s2, fx_good.bytes, l2) == 0;
        bool out2_is_poisoned_bad = s2 && l2 == fx_bad.len &&
                                    memcmp(s2, fx_bad.bytes, l2) == 0;
        free(s2); block_free(&out2);
        if (!out2_is_good || out2_is_poisoned_bad) {
            printf("FAIL (poisoned slot served stale bytes: got_good=%d got_bad=%d)\n",
                   out2_is_good, out2_is_poisoned_bad);
            failures++; free(fx_bad.bytes); free(fx_good.bytes); goto done;
        }

        /* And it is now a real, correctly-keyed cache entry: a third get
         * under the same key hits it and still returns fx_good's bytes. */
        struct block out3; block_init(&out3);
        bool ok3 = block_parse_cache_get(H, fx_good.hash.data, &fx_good.bi,
                                         datadir, &out3);
        size_t l3 = 0; unsigned char *s3 = ok3 ? ser(&out3, &l3) : NULL;
        bool out3_ok = s3 && l3 == fx_good.len &&
                       memcmp(s3, fx_good.bytes, l3) == 0;
        free(s3); block_free(&out3);
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
        struct block_index broken2 = f2.bi;
        broken2.nStatus &= ~(unsigned int)BLOCK_HAVE_DATA;
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
        struct block_index broken1 = f1.bi, broken3 = f3.bi;
        broken1.nStatus &= ~(unsigned int)BLOCK_HAVE_DATA;
        broken3.nStatus &= ~(unsigned int)BLOCK_HAVE_DATA;

        struct block h1, h3; block_init(&h1); block_init(&h3);
        bool ok1 = block_parse_cache_get(600, f1.hash.data, &broken1, datadir, &h1);
        bool ok3 = block_parse_cache_get(602, f3.hash.data, &broken3, datadir, &h3);
        size_t l1 = 0, l3 = 0;
        unsigned char *s1 = ok1 ? ser(&h1, &l1) : NULL;
        unsigned char *s3 = ok3 ? ser(&h3, &l3) : NULL;
        bool sib1_ok = s1 && l1 == f1.len && memcmp(s1, f1.bytes, l1) == 0;
        bool sib3_ok = s3 && l3 == f3.len && memcmp(s3, f3.bytes, l3) == 0;
        free(s1); free(s3); block_free(&h1); block_free(&h3);
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
 * The read-integrity guarantee the sealer exists to provide: below the sealed
 * frontier a body is served from the hash-verified segment store, and a
 * tampered segment is caught (whole-segment digest on open) so bpc_segment_try
 * logs + returns false. With blk*.dat intact the reader transparently falls
 * back to disk (same bytes); with the disk pointer ALSO broken the read fails
 * closed (returns false) rather than serving unverified bytes. This is exactly
 * the warm-restart fold-read integrity the wired sealer restores. */
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

    TEST("bpc borrowed: pin survives collision and pressure clear") {
        block_parse_cache_clear();
        struct block_parse_handle a, collision;
        bool ok = block_parse_cache_acquire(1400, fa.hash.data, &fa.bi,
                                            datadir, &a) &&
                  block_parse_cache_acquire(
                      1400 + BLOCK_PARSE_CACHE_CAPACITY, fb.hash.data, &fb.bi,
                      datadir, &collision);
        const struct block *held = block_parse_handle_block(&a);
        block_parse_cache_clear();
        ok = ok && held && held->vtx[0].num_vout == 3;
        block_parse_cache_release(&collision);
        block_parse_cache_release(&a);
        struct block_index broken = fa.bi;
        broken.nStatus &= ~(unsigned int)BLOCK_HAVE_DATA;
        struct block after; block_init(&after);
        bool resident = block_parse_cache_get(1400, fa.hash.data, &broken,
                                              datadir, &after);
        block_free(&after);
        if (!ok || resident) { printf("FAIL (pin/clear)\n"); failures++; }
        else printf("OK\n");
    }

    TEST("bpc borrowed: generation makes stale release harmless") {
        block_parse_cache_clear();
        struct block_parse_handle a, b;
        bool ok = block_parse_cache_acquire(1400, fa.hash.data, &fa.bi,
                                            datadir, &a);
        struct block_parse_handle stale = a;
        block_parse_cache_release(&a);
        ok = ok && block_parse_cache_acquire(
            1400 + BLOCK_PARSE_CACHE_CAPACITY, fb.hash.data, &fb.bi, datadir,
            &b);
        block_parse_cache_release(&stale);
        block_parse_cache_clear();
        const struct block *still_pinned = block_parse_handle_block(&b);
        ok = ok && still_pinned && still_pinned->vtx[0].num_vout == 4;
        block_parse_cache_release(&b);
        if (!ok) { printf("FAIL (stale generation)\n"); failures++; }
        else printf("OK\n");
    }

    TEST("bpc borrowed: concurrent readers remain immutable") {
        block_parse_cache_clear();
        enum { N = 8 };
        pthread_t threads[N];
        struct borrowed_reader_ctx ctx[N];
        bool spawned[N] = {0};
        for (int i = 0; i < N; i++) {
            ctx[i] = (struct borrowed_reader_ctx){ .fx = &fa,
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

    TEST("bpc borrowed: borrowed and legacy bytes are identical") {
        block_parse_cache_clear();
        struct block_parse_handle h;
        struct block legacy; block_init(&legacy);
        bool ok = block_parse_cache_acquire(1400, fa.hash.data, &fa.bi,
                                            datadir, &h) &&
                  block_parse_cache_get(1400, fa.hash.data, &fa.bi, datadir,
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

    free(fa.bytes); free(fb.bytes);
    block_parse_cache_clear();
    return failures;
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
        const struct json_value *cumulative = body ? json_get(body, "cumulative") : NULL;
        const struct json_value *blocks = cumulative ? json_get(cumulative, "blocks") : NULL;
        const struct json_value *ctx = cumulative ? json_get(cumulative,
                                                  "contextual_gate_us") : NULL;
        const struct json_value *quantiles = cumulative
            ? json_get(cumulative, "latency_quantiles_us") : NULL;
        const struct json_value *total_q = quantiles
            ? json_get(quantiles, "total_us") : NULL;
        const struct json_value *samples = total_q
            ? json_get(total_q, "samples") : NULL;
        const struct json_value *p50 = total_q ? json_get(total_q, "p50") : NULL;
        const struct json_value *p95 = total_q ? json_get(total_q, "p95") : NULL;
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
