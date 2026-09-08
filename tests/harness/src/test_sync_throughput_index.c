/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sync_throughput, part 2: S6 flat header point reads (single-shot and
 * batched cursor) and S7 forward-pass input ordering, plus the group's
 * entry point test_sync_throughput(). S1-S5 and the shared fixture/timing
 * helpers live in test_sync_throughput.c (test/test_sync_throughput_internal.h
 * is the seam between the two files); see that file's header comment for
 * the stage list and the overall teeth/budget contract.
 */

#include "test/test_core.h"
#include "test/test_sync_throughput_internal.h"

#include "core/uint256.h"
#include "chain/chain.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include "services/block_index_loader.h"
#include "util/safe_alloc.h"
#include "platform/time_compat.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Flat-index fixture: synthetic chain saved to a test-local tmpdir
 * (hermetic fixture directory, never a node datadir). */
struct st_flat_fixture {
    char dir[256];
    struct main_state ms;
    int live;
};

static void st_flat_build(struct st_flat_fixture *fx, int n, int *failures)
{
    memset(fx, 0, sizeof(*fx));
    memset(&fx->ms, 0, sizeof(fx->ms));
    block_map_init(&fx->ms.map_block_index);
    active_chain_init(&fx->ms.chain_active);
    struct uint256 prev;
    memset(&prev, 0, sizeof(prev));
    for (int h = 0; h < n; h++) {
        struct uint256 hh;
        memset(&hh, 0, sizeof(hh));
        hh.data[0] = (uint8_t)(h & 0xff);
        hh.data[1] = (uint8_t)((h >> 8) & 0xff);
        hh.data[2] = (uint8_t)((h >> 16) & 0xff);
        hh.data[3] = 0xBB;
        struct block_index *pi = chainstate_insert_block_index(
            (struct chainstate *)&fx->ms, &hh);
        if (!pi) {
            printf("  S6 fixture insert h=%d... FAIL\n", h);
            (*failures)++;
            return;
        }
        pi->nHeight = h;
        pi->nBits = 0x1f07ffff;
        pi->nTime = ST_FIXED_TIME + (uint32_t)h * 150u;
        pi->nVersion = 4;
        pi->nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA;
        pi->nTx = 1;
        if (h > 0) {
            struct block_index *pp = block_map_find(
                &fx->ms.map_block_index, &prev);
            if (pp)
                pi->pprev = pp;
        }
        for (int b = 0; b < 32; b++)
            pi->hashFinalSaplingRoot.data[b] =
                (uint8_t)((h * 37 + b * 11) & 0xff);
        prev = hh;
    }
    snprintf(fx->dir, sizeof(fx->dir), "./test-tmp/%d_st_flat", getpid());
    mkdir("./test-tmp", 0755);
    mkdir(fx->dir, 0755);
    save_block_index_flat(fx->dir, &fx->ms);
    fx->live = 1;
}

static void st_flat_teardown(struct st_flat_fixture *fx)
{
    if (!fx->live)
        return;
    char path[512];
    snprintf(path, sizeof(path), "%s/block_index.bin", fx->dir);
    unlink(path);
    rmdir(fx->dir);
    block_map_free(&fx->ms.map_block_index);
    fx->live = 0;
}

/* Expected deterministic bytes for row h (mirrors st_flat_build). */
static void st_flat_expect(int h, uint8_t hash[32], uint8_t root[32])
{
    memset(hash, 0, 32);
    hash[0] = (uint8_t)(h & 0xff);
    hash[1] = (uint8_t)((h >> 8) & 0xff);
    hash[2] = (uint8_t)((h >> 16) & 0xff);
    hash[3] = 0xBB;
    for (int b = 0; b < 32; b++)
        root[b] = (uint8_t)((h * 37 + b * 11) & 0xff);
}

/* S6: flat header point reads, one open+verify per height (the baseline
 * the batched cursor optimisation is measured against). */
/* S6 teeth: exact bytes at three heights; missing height refuses. Split
 * out of st_stage_flat_reads to keep each stage helper under the
 * complexity cap. */
static void st_stage_flat_reads_teeth(struct st_flat_fixture *fx,
                                      int *failures)
{
    int spots[] = { 0, 1042, ST_FLAT_ROWS - 1 };
    for (size_t s = 0; s < 3; s++) {
        uint8_t hash[32], root[32], eh[32], er[32];
        struct zcl_result r = block_index_flat_header_at(
            fx->dir, spots[s], hash, root);
        st_flat_expect(spots[s], eh, er);
        char name[96];
        snprintf(name, sizeof(name),
                 "S6 point read h=%d returns fixture bytes", spots[s]);
        ST_CHECK(name, r.ok && memcmp(hash, eh, 32) == 0 &&
                 memcmp(root, er, 32) == 0);
    }
    uint8_t hash[32], root[32];
    struct zcl_result miss = block_index_flat_header_at(
        fx->dir, ST_FLAT_ROWS + 500, hash, root);
    ST_CHECK("S6 missing height refuses", !miss.ok);
}

/* S6 single-shot timing: one open+verify+lookup per height (the baseline
 * the batched cursor is measured against). Returns heights/s, or a
 * negative value on a read failure (caller tears the fixture down then).
 * Split out of st_stage_flat_reads to keep each stage helper under the
 * complexity cap. */
static double st_stage_flat_reads_single(struct st_flat_fixture *fx,
                                         int *failures)
{
    int64_t t0 = platform_time_monotonic_us();
    for (int k = 0; k < ST_FLAT_READS; k++) {
        uint8_t hash[32], root[32];
        struct zcl_result r = block_index_flat_header_at(
            fx->dir, (k * 7919) % ST_FLAT_ROWS, hash, root);
        if (!r.ok) {
            printf("  S6 point read stayed ok... FAIL (%s)\n", r.message);
            (*failures)++;
            return -1.0;
        }
    }
    uint64_t elapsed = (uint64_t)(platform_time_monotonic_us() - t0);
    double rate = st_per_s(ST_FLAT_READS, elapsed);
    double us_each = (double)elapsed / (double)ST_FLAT_READS;
    printf("  S6 flat point reads: %d heights in %lluus = %.1f heights/s (%.1f us/height)\n",
           ST_FLAT_READS, (unsigned long long)elapsed, rate, us_each);
    /* Declared budget: reference box reads >= 40 heights/s single-shot.
     * (Each read re-opens, re-mmaps and re-hashes the whole file — the
     * cursor optimisation exists to move this number, not this floor.) */
    st_check_floor_per_s("S6 heights/s floor", rate, 40.0, failures);
    return rate;
}

/* S6b: the same heights through one batched cursor (OPT-1). The cursor
 * must return byte-identical rows and the identical refusal code for a
 * missing height; only the lifetime (and therefore the verify count)
 * differs. Split out of st_stage_flat_reads to keep each stage helper
 * under the complexity cap. */
static void st_stage_flat_reads_cursor(struct st_flat_fixture *fx,
                                       double single_rate, int *failures)
{
    struct block_index_flat_cursor *cur = NULL;
    struct zcl_result or_ = block_index_flat_cursor_open(fx->dir, &cur);
    ST_CHECK("S6b cursor opens", or_.ok && cur != NULL);
    if (!or_.ok || !cur)
        return;
    int64_t t1 = platform_time_monotonic_us();
    bool match = true;
    for (int k = 0; k < ST_FLAT_READS; k++) {
        int h = (k * 7919) % ST_FLAT_ROWS;
        uint8_t hash[32], root[32], eh[32], er[32];
        struct zcl_result r = block_index_flat_cursor_read(
            cur, h, hash, root);
        st_flat_expect(h, eh, er);
        if (!r.ok || memcmp(hash, eh, 32) != 0 ||
            memcmp(root, er, 32) != 0) {
            match = false;
            break;
        }
    }
    uint64_t celapsed = (uint64_t)(platform_time_monotonic_us() - t1);
    double crate = st_per_s(ST_FLAT_READS, celapsed);
    ST_CHECK("S6b cursor rows byte-identical to single-shot", match);
    uint8_t hash[32], root[32];
    struct zcl_result cmiss = block_index_flat_cursor_read(
        cur, ST_FLAT_ROWS + 500, hash, root);
    struct zcl_result smiss = block_index_flat_header_at(
        fx->dir, ST_FLAT_ROWS + 500, hash, root);
    ST_CHECK("S6b cursor refusal matches single-shot refusal",
             !cmiss.ok && !smiss.ok && cmiss.code == smiss.code);
    block_index_flat_cursor_close(cur);
    block_index_flat_cursor_close(NULL); /* NULL-safe */
    printf("  S6b flat cursor reads: %d heights in %lluus = %.1f heights/s (%.2fx vs single-shot)\n",
           ST_FLAT_READS, (unsigned long long)celapsed, crate,
           single_rate > 0.0 ? crate / single_rate : 0.0);
    /* Declared budget: the cursor must clear 20k heights/s on the
     * reference box — two orders above the single-shot floor, because
     * the per-read work is O(log rows), not O(file). */
    st_check_floor_per_s("S6b cursor heights/s floor",
                         crate, 20000.0, failures);
}

/* S6: flat header point reads, one open+verify per height (the baseline
 * the batched cursor optimisation is measured against), then S6b through
 * the batched cursor. Each leg lives in its own helper (see above) so no
 * single function carries the whole stage's branch count. */
double st_stage_flat_reads(int *failures)
{
    struct st_flat_fixture fx;
    st_flat_build(&fx, ST_FLAT_ROWS, failures);
    if (!fx.live)
        return 0.0;

    st_stage_flat_reads_teeth(&fx, failures);
    double rate = st_stage_flat_reads_single(&fx, failures);
    if (rate < 0.0) {
        st_flat_teardown(&fx);
        return 0.0;
    }
    st_stage_flat_reads_cursor(&fx, rate, failures);
    st_flat_teardown(&fx);
    return rate;
}

/* S7 collect: fill parr[h] with the real block_index pointer at height h
 * from the fixture's map, in ascending height order (the shape a genuine
 * flat file's writer leaves the loader). Returns false (already reported
 * and counted) on any alloc or lookup miss. Split out of
 * st_stage_forward_order to keep each stage helper under the complexity
 * cap. */
static bool st_forward_order_collect(struct st_flat_fixture *fx,
                                     struct block_index **parr,
                                     int *failures)
{
    for (int h = 0; h < ST_FLAT_ROWS; h++) {
        uint8_t key[32];
        uint8_t root[32];
        st_flat_expect(h, key, root);
        struct uint256 k;
        memcpy(k.data, key, 32);
        parr[h] = block_map_find(&fx->ms.map_block_index, &k);
        if (!parr[h] || parr[h]->nHeight != h) {
            printf("  S7 fixture order collect h=%d... FAIL\n", h);
            (*failures)++;
            return false;
        }
    }
    return true;
}

/* S7 tooth: two adjacent slots aliasing the same pointer give the
 * predicate an equal-height pair, the exact case block_index_ptr_cmp_height
 * reports as tied (returns 0). The predicate's strict `>` test must agree
 * that a tie is "already in comparator order" and keep reporting sorted.
 * Split out of st_forward_order_teeth to keep it under the complexity
 * cap. */
static void st_forward_order_tooth_equal(struct block_index **parr,
                                         struct block_index **qcopy, size_t n,
                                         int *failures)
{
    memcpy(qcopy, parr, n * sizeof(*qcopy));
    qcopy[n - 2] = qcopy[n - 1];
    ST_CHECK("S7 equal-height adjacent pair still counts as ordered",
             block_index_ptrs_height_sorted(qcopy, n));
}

/* S7 tooth: a sorted prefix with a single inversion at the tail must be
 * rejected by the predicate (it inspects every adjacent pair, not just
 * gross/full reversal), and the production qsort call the loader makes
 * when the predicate returns false must still restore full order. Split
 * out of st_forward_order_teeth to keep it under the complexity cap. */
static void st_forward_order_tooth_tail_inversion(struct block_index **parr,
                                                  struct block_index **qcopy,
                                                  size_t n, int *failures)
{
    memcpy(qcopy, parr, n * sizeof(*qcopy));
    struct block_index *t = qcopy[n - 1];
    qcopy[n - 1] = qcopy[n - 2];
    qcopy[n - 2] = t;
    ST_CHECK("S7 sorted prefix with tail inversion not called sorted",
             !block_index_ptrs_height_sorted(qcopy, n));
    qsort(qcopy, n, sizeof(*qcopy), block_index_ptr_cmp_height);
    ST_CHECK("S7 loader qsort restores order after a tail inversion",
             block_index_ptrs_height_sorted(qcopy, n));
}

/* S7 teeth: the height-sorted predicate recognises the ascending
 * collected array and refuses a reversed copy of it. Split out of
 * st_stage_forward_order to keep each stage helper under the complexity
 * cap. */
static void st_forward_order_teeth(struct block_index **parr,
                                   struct block_index **qcopy, size_t n,
                                   int *failures)
{
    ST_CHECK("S7 height-ordered array recognised",
             block_index_ptrs_height_sorted(parr, n));
    memcpy(qcopy, parr, n * sizeof(*qcopy));
    for (size_t i = 0; i < n / 2; i++) {
        struct block_index *t = qcopy[i];
        qcopy[i] = qcopy[n - 1 - i];
        qcopy[n - 1 - i] = t;
    }
    ST_CHECK("S7 reversed array not called sorted",
             !block_index_ptrs_height_sorted(qcopy, n));
    st_forward_order_tooth_equal(parr, qcopy, n, failures);
    st_forward_order_tooth_tail_inversion(parr, qcopy, n, failures);
}

/* S7 timing: before shape (full qsort over the already-ordered array,
 * pinned as an identity permutation) against after shape (the linear
 * already-sorted predicate, pinned as staying true). Split out of
 * st_stage_forward_order to keep each stage helper under the complexity
 * cap. Returns qsort_us / predicate_us. */
static double st_forward_order_timing(struct block_index **parr,
                                      struct block_index **qcopy, size_t n,
                                      int *failures)
{
    const uint64_t iters = 30u;
    int64_t t0 = platform_time_monotonic_us();
    for (uint64_t k = 0; k < iters; k++) {
        memcpy(qcopy, parr, n * sizeof(*qcopy));
        qsort(qcopy, n, sizeof(*qcopy), block_index_ptr_cmp_height);
    }
    uint64_t qelapsed = (uint64_t)(platform_time_monotonic_us() - t0);
    bool same_seq = true;
    for (size_t i = 0; i < n && same_seq; i++) {
        if (qcopy[i]->nHeight != parr[i]->nHeight)
            same_seq = false;
    }
    ST_CHECK("S7 qsort on ordered input is an identity permutation",
             same_seq);

    t0 = platform_time_monotonic_us();
    bool ok_all = true;
    for (uint64_t k = 0; k < iters; k++) {
        if (!block_index_ptrs_height_sorted(parr, n))
            ok_all = false;
    }
    uint64_t celapsed = (uint64_t)(platform_time_monotonic_us() - t0);
    ST_CHECK("S7 predicate stays true", ok_all);

    double qus = (double)qelapsed / (double)iters;
    double cus = (double)celapsed / (double)iters;
    printf("  S7 forward-pass ordering (%zu ptrs): qsort=%.1f us vs check=%.1f us (%.1fx)\n",
           n, qus, cus, cus > 0.0 ? qus / cus : 0.0);
    /* Declared budget: the check over 8k pointers must clear in <= 5ms
     * on the reference box (it is one integer compare per row). */
    st_check_ceiling_us("S7 sorted-check us ceiling",
                        (uint64_t)(cus + 0.5), 5000u, failures);
    return cus > 0.0 ? qus / cus : 0.0;
}

/* S7: forward-pass input ordering. Genuine flat files leave the writer
 * height-sorted, so the loader's collected pointer array is already the
 * forward-pass order and the qsort is an identity permutation at
 * O(n log n) cost. Times the production qsort on sorted input (the
 * before shape) against the linear already-sorted predicate (the after
 * shape) over REAL block_index entries, and pins that both agree the
 * array is ordered and produce the same height sequence. Each leg lives
 * in its own helper (see above) so no single function carries the whole
 * stage's branch count. */
double st_stage_forward_order(int *failures)
{
    struct st_flat_fixture fx;
    st_flat_build(&fx, ST_FLAT_ROWS, failures);
    if (!fx.live)
        return 0.0;

    const size_t n = (size_t)ST_FLAT_ROWS;
    struct block_index **parr = zcl_malloc(n * sizeof(*parr),
                                           "sync_throughput order");
    struct block_index **qcopy = zcl_malloc(n * sizeof(*qcopy),
                                            "sync_throughput order copy");
    if (!parr || !qcopy) {
        printf("  S7 order alloc... FAIL\n");
        (*failures)++;
        free(parr);
        free(qcopy);
        st_flat_teardown(&fx);
        return 0.0;
    }
    if (!st_forward_order_collect(&fx, parr, failures)) {
        free(parr);
        free(qcopy);
        st_flat_teardown(&fx);
        return 0.0;
    }

    st_forward_order_teeth(parr, qcopy, n, failures);
    double speedup = st_forward_order_timing(parr, qcopy, n, failures);

    free(parr);
    free(qcopy);
    st_flat_teardown(&fx);
    return speedup;
}

int test_sync_throughput(void)
{
    printf("\n=== sync_throughput (initial-sync benchmark, hermetic) ===\n");
    int failures = 0;

    if (!st_build_fixture()) {
        printf("fixture build... FAIL\n");
        return 1;
    }

    double s1 = st_stage_header_roundtrip(&failures);
    double s2 = st_stage_pow_verify(&failures);
    double s3 = st_stage_merkle(&failures);
    double s4 = st_stage_check_block(&failures);
    double s5 = st_stage_range_plan(&failures);
    double s6 = st_stage_flat_reads(&failures);
    double s7 = st_stage_forward_order(&failures);

    printf("sync_throughput summary: headers/s=%.1f pow_us=%.1f "
           "merkle8_roots/s=%.1f validation_us_per_block=%.1f "
           "plan_us=%.1f flat_heights/s=%.1f fwd_order_speedup=%.1fx\n",
           s1, s2, s3, s4, s5, s6, s7);
    printf("sync_throughput: %s (%d failures)\n",
           failures == 0 ? "OK" : "FAIL", failures);
    st_free_fixture();
    return failures;
}
