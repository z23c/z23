/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_block_prefetch — lifecycle, bounded memory, miss-path fail-safety, and a
 * page-cache warming micro-benchmark for the block-body read-ahead worker
 * (storage/block_prefetch.h).
 *
 * The worker is decoupled from chain state via cursor/pos callbacks, so these
 * tests drive it with a synthetic blk*.dat file and a fixed height->position
 * map — no main_state, no reducer.
 *
 * Freshly-written blocks are ALREADY resident in the page cache, so the worker
 * takes the RWF_NOWAIT "hit" path and never issues a warming read. To exercise
 * the cold warm+LRU path the tests first evict the file (posix_fadvise
 * DONTNEED). A tmpfs/ramdisk cannot evict, so cold-path assertions (a page
 * transitioning cold→resident, a non-empty LRU) are guarded on the environment
 * actually demonstrating a cold page; the lifecycle, "window processed", and
 * bounded-memory-invariant assertions are FS-agnostic and always run. */

#define _GNU_SOURCE
#include "test/test_core.h"

#include "storage/block_prefetch.h"
#include "storage/disk_block_io.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "json/json.h"
#include "platform/time_compat.h"
#include "platform/file_advice.h"

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/uio.h>
#include <unistd.h>
#endif

#define BPT_NBLOCKS 12

static void bpt_make_dir(char *buf, size_t len)
{
    snprintf(buf, len, "./test-tmp/%d_block_prefetch", (int)getpid());
    mkdir("./test-tmp", 0755);
    mkdir(buf, 0755);
    char blocks[512];
    snprintf(blocks, sizeof(blocks), "%s/blocks", buf);
    mkdir(blocks, 0755);
}

static void bpt_cleanup(const char *dir)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)system(cmd);
}

/* Write one small block; record its payload position. */
static bool bpt_write_block(const char *datadir, struct disk_block_pos *pos,
                            uint32_t ntime)
{
    struct block b;
    block_init(&b);
    b.header.nVersion = 4;
    b.header.nTime = ntime;
    b.header.nBits = 0x2000ffff;
    b.num_vtx = 1;
    b.vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    transaction_init(&b.vtx[0]);
    transaction_alloc(&b.vtx[0], 1, 1);
    b.vtx[0].vin[0].sequence = 0xffffffff;
    b.vtx[0].vout[0].value = 10 * COIN;
    unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
    bool ok = write_block_to_disk(&b, pos, datadir, msg_start);
    block_free(&b);
    return ok;
}

/* Evict the blk file holding `pos` from the page cache. Best-effort: a tmpfs
 * ignores DONTNEED. Returns true if the syscalls succeeded (not that pages were
 * actually dropped). */
static bool bpt_evict(const char *datadir, const struct disk_block_pos *pos)
{
    char path[512];
    get_block_pos_filename(path, sizeof(path), datadir, pos, "blk");
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    struct stat st;
    bool ok = (fstat(fd, &st) == 0) &&
              (platform_file_advise_dontneed(fd, st.st_size) == 0);
    close(fd);
    return ok;
}

/* ── Synthetic callback context ─────────────────────────────────────────── */
struct bpt_ctx {
    struct disk_block_pos pos[BPT_NBLOCKS];
    int  n;
    _Atomic int32_t cursor;    /* fold height the worker sees */
    int  gap_at;               /* height index pos_fn refuses (-1 = none) */
    int  bad_file_at;          /* height index resolved to a missing file (-1) */
};

static bool bpt_cursor(void *user, int32_t *out_height)
{
    struct bpt_ctx *c = user;
    *out_height = atomic_load(&c->cursor);
    return true;
}

/* Map height h (1..n) to recorded pos[h-1]. Height 0 or > n is a gap. */
static bool bpt_pos(void *user, int32_t height, struct disk_block_pos *out)
{
    struct bpt_ctx *c = user;
    int idx = height - 1;
    if (idx < 0 || idx >= c->n)
        return false;
    if (idx == c->gap_at)
        return false;
    *out = c->pos[idx];
    if (idx == c->bad_file_at)
        out->nFile = 4242;     /* blk04242.dat does not exist */
    return true;
}

/* Poll warmed+hits (the "window processed" signal) until >= want. */
static bool bpt_wait_processed(uint64_t want, int timeout_ms)
{
    int64_t deadline = platform_time_monotonic_us() + (int64_t)timeout_ms * 1000;
    for (;;) {
        uint64_t processed = block_prefetch_warmed() + block_prefetch_warm_hits();
        if (processed >= want)
            return true;
        if (platform_time_monotonic_us() >= deadline)
            return false;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 2 * 1000000L };
        nanosleep(&ts, NULL);
    }
}

/* preadv2(RWF_NOWAIT) residency probe of one block payload:
 *   1 = resident, 0 = not resident (EAGAIN), -1 = probe unusable here. */
static int bpt_probe_resident(const char *datadir,
                              const struct disk_block_pos *pos)
{
#if defined(__linux__) && defined(RWF_NOWAIT)
    char path[512];
    get_block_pos_filename(path, sizeof(path), datadir, pos, "blk");
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    uint8_t buf[64];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    ssize_t n = preadv2(fd, &iov, 1, (off_t)pos->nPos, RWF_NOWAIT);
    int rc;
    if (n > 0)                     /* first page served without blocking */
        rc = 1;
    else if (n < 0 && errno == EAGAIN)
        rc = 0;                    /* first page not resident */
    else
        rc = -1;                   /* n == 0 (EOF) or other — inconclusive */
    close(fd);
    return rc;
#else
    (void)datadir; (void)pos;
    return -1;
#endif
}

static struct block_prefetch_config bpt_cfg(size_t budget)
{
    struct block_prefetch_config cfg;
    block_prefetch_config_default(&cfg);
    cfg.enabled = true;
    cfg.lead = 1;                 /* warm starting at cursor+1 → heights 1..n */
    cfg.window = BPT_NBLOCKS;
    cfg.max_bytes = budget;
    return cfg;
}

/* ── Test: disabled config is a benign no-op ────────────────────────────── */
static int t_disabled_noop(void)
{
    int failures = 0;
    block_prefetch_stop();        /* defensive: clear any leaked worker */
    char dir[256];
    bpt_make_dir(dir, sizeof(dir));
    struct bpt_ctx ctx = {0};
    struct block_prefetch_config cfg;
    block_prefetch_config_default(&cfg);

    TEST_CASE("disabled config: start is a no-op, nothing runs") {
        ASSERT(cfg.enabled == false);           /* default OFF */
        bool ok = block_prefetch_start(dir, &cfg, bpt_cursor, &ctx,
                                       bpt_pos, &ctx);
        ASSERT(ok);                              /* benign success */
        ASSERT(block_prefetch_running() == false);
        block_prefetch_stop();                   /* safe without a start */
    } TEST_END

    bpt_cleanup(dir);
    return failures;
}

/* ── Test: lifecycle + supervised child + window processed ──────────────── */
static int t_lifecycle(void)
{
    int failures = 0;
    block_prefetch_stop();
    char dir[256];
    bpt_make_dir(dir, sizeof(dir));
    struct bpt_ctx ctx = {0};
    ctx.gap_at = -1;
    ctx.bad_file_at = -1;

    TEST_CASE("lifecycle: worker processes the window, dumper shows supervised") {
        for (int i = 0; i < BPT_NBLOCKS; i++)
            ASSERT(bpt_write_block(dir, &ctx.pos[i], 1000 + i));
        ctx.n = BPT_NBLOCKS;
        atomic_store(&ctx.cursor, 0);

        struct block_prefetch_config cfg = bpt_cfg(4u * 1024u * 1024u);
        ASSERT(block_prefetch_start(dir, &cfg, bpt_cursor, &ctx, bpt_pos, &ctx));
        ASSERT(block_prefetch_running());

        /* Every non-cursor height (1..n) is processed — either warmed (cold) or
         * a residency hit (already cached). Both count as "processed". */
        ASSERT(bpt_wait_processed((uint64_t)BPT_NBLOCKS, 2000));

        struct json_value v;
        json_init(&v);
        ASSERT(block_prefetch_dump_state_json(&v, NULL));
        const struct json_value *sup = json_get(&v, "supervised");
        const struct json_value *cid = json_get(&v, "supervisor_child_id");
        const struct json_value *run = json_get(&v, "running");
        const struct json_value *passes = json_get(&v, "passes");
        ASSERT(sup && json_get_bool(sup) == true);
        ASSERT(cid && json_get_int(cid) >= 0);
        ASSERT(run && json_get_bool(run) == true);
        ASSERT(passes && json_get_int(passes) >= 1);
        json_free(&v);

        block_prefetch_stop();
        ASSERT(block_prefetch_running() == false);
        block_prefetch_stop();                     /* second stop is safe */
        ASSERT(block_prefetch_lru_count() == 0);   /* LRU cleared on stop */
    } TEST_END

    bpt_cleanup(dir);
    return failures;
}

/* ── Test: bounded memory — LRU never exceeds the byte budget ────────────── */
static int t_bounded_memory(void)
{
    int failures = 0;
    block_prefetch_stop();
    char dir[256];
    bpt_make_dir(dir, sizeof(dir));
    struct bpt_ctx ctx = {0};
    ctx.gap_at = -1;
    ctx.bad_file_at = -1;

    TEST_CASE("bounded memory: LRU bytes stay within the configured budget") {
        for (int i = 0; i < BPT_NBLOCKS; i++)
            ASSERT(bpt_write_block(dir, &ctx.pos[i], 2000 + i));
        ctx.n = BPT_NBLOCKS;
        atomic_store(&ctx.cursor, 0);

        /* force_warm skips the residency probe and always warms + LRU-retains,
         * so the warm/LRU/bounded path is exercised deterministically without
         * depending on the page cache actually being cold (this sandbox's tiny
         * single-page file + kernel readahead makes eviction unreliable). */
        const size_t budget = 1024; /* tiny — forces eviction across n blocks */
        struct block_prefetch_config cfg = bpt_cfg(budget);
        cfg.force_warm = true;
        ASSERT(block_prefetch_start(dir, &cfg, bpt_cursor, &ctx, bpt_pos, &ctx));

        /* Every height is warmed (no probe short-circuit). */
        ASSERT(bpt_wait_processed((uint64_t)BPT_NBLOCKS, 2000));
        ASSERT(block_prefetch_warmed() >= (uint64_t)BPT_NBLOCKS);

        /* The bounded-byte invariant holds on every re-pass while the worker
         * keeps warming + evicting. */
        for (int i = 0; i < 30; i++) {
            ASSERT(block_prefetch_lru_bytes() <= budget);
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 1 * 1000000L };
            nanosleep(&ts, NULL);
        }
        ASSERT(block_prefetch_lru_count() >= 1); /* at least one body retained */
        ASSERT(block_prefetch_lru_bytes() <= budget);

        block_prefetch_stop();
    } TEST_END

    bpt_cleanup(dir);
    return failures;
}

/* ── Test: miss-path fail-safety — gaps and missing files never crash ────── */
static int t_misspath_failsafe(void)
{
    int failures = 0;
    block_prefetch_stop();
    char dir[256];
    bpt_make_dir(dir, sizeof(dir));
    struct bpt_ctx ctx = {0};

    TEST_CASE("miss path: a resolve gap + a missing file degrade to no-ops") {
        for (int i = 0; i < BPT_NBLOCKS; i++)
            ASSERT(bpt_write_block(dir, &ctx.pos[i], 3000 + i));
        ctx.n = BPT_NBLOCKS;
        ctx.gap_at = 5;               /* height 6 (idx 5) refuses resolution */
        ctx.bad_file_at = 2;          /* height 3 (idx 2) → missing file */
        atomic_store(&ctx.cursor, 0);

        struct block_prefetch_config cfg = bpt_cfg(4u * 1024u * 1024u);
        ASSERT(block_prefetch_start(dir, &cfg, bpt_cursor, &ctx, bpt_pos, &ctx));

        /* The worker resolves 1,2 (idx 0,1), hits the missing file at idx 2
         * (a read_fail no-op), continues to 3,4,5, then the resolve gap at
         * idx 5 stops the pass. No crash; the worker stays alive. */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 300 * 1000000L };
        nanosleep(&ts, NULL);
        ASSERT(block_prefetch_running());

        struct json_value v;
        json_init(&v);
        ASSERT(block_prefetch_dump_state_json(&v, NULL));
        const struct json_value *gaps = json_get(&v, "resolve_gaps");
        const struct json_value *rfails = json_get(&v, "read_fails");
        ASSERT(gaps && json_get_int(gaps) >= 1);
        ASSERT(rfails && json_get_int(rfails) >= 1);
        json_free(&v);

        block_prefetch_stop();
    } TEST_END

    bpt_cleanup(dir);
    return failures;
}

/* ── Test: page-cache warming micro-benchmark ───────────────────────────── */
static int t_warm_microbench(void)
{
    int failures = 0;
    block_prefetch_stop();
    char dir[256];
    bpt_make_dir(dir, sizeof(dir));
    struct bpt_ctx ctx = {0};
    ctx.gap_at = -1;
    ctx.bad_file_at = -1;

    TEST_CASE("microbench: worker makes a cold page resident (env-guarded)") {
        for (int i = 0; i < BPT_NBLOCKS; i++)
            ASSERT(bpt_write_block(dir, &ctx.pos[i], 4000 + i));
        ctx.n = BPT_NBLOCKS;

        bpt_evict(dir, &ctx.pos[0]);
        int cold = bpt_probe_resident(dir, &ctx.pos[BPT_NBLOCKS - 1]);
        if (cold != 0)
            printf("(env cannot evict: cold-probe=%d — residency assertion "
                   "skipped) ", cold);

        /* Informational cold direct-read latency (also re-warms this one). */
        int64_t t0 = platform_time_monotonic_us();
        struct block cb;
        block_init(&cb);
        (void)read_block_from_disk_pread(&cb, &ctx.pos[BPT_NBLOCKS - 1], dir);
        block_free(&cb);
        int64_t cold_us = platform_time_monotonic_us() - t0;

        /* Re-evict so the WORKER is what warms the measured block. */
        bpt_evict(dir, &ctx.pos[0]);
        int cold2 = bpt_probe_resident(dir, &ctx.pos[BPT_NBLOCKS - 1]);

        struct block_prefetch_config cfg = bpt_cfg(4u * 1024u * 1024u);
        atomic_store(&ctx.cursor, 0);
        ASSERT(block_prefetch_start(dir, &cfg, bpt_cursor, &ctx, bpt_pos, &ctx));
        ASSERT(bpt_wait_processed((uint64_t)BPT_NBLOCKS, 2000));

        if (cold2 == 0) {
            int hot = bpt_probe_resident(dir, &ctx.pos[BPT_NBLOCKS - 1]);
            ASSERT(hot == 1);   /* the causal precondition for the latency win */
        }

        int64_t t1 = platform_time_monotonic_us();
        struct block wb;
        block_init(&wb);
        (void)read_block_from_disk_pread(&wb, &ctx.pos[BPT_NBLOCKS - 1], dir);
        block_free(&wb);
        int64_t warm_us = platform_time_monotonic_us() - t1;

        printf("(cold_read=%lldus warm_read=%lldus warmed=%llu "
               "nowait_misses=%llu hits=%llu) ",
               (long long)cold_us, (long long)warm_us,
               (unsigned long long)block_prefetch_warmed(),
               (unsigned long long)block_prefetch_nowait_misses(),
               (unsigned long long)block_prefetch_warm_hits());

        block_prefetch_stop();
    } TEST_END

    bpt_cleanup(dir);
    return failures;
}

int test_block_prefetch(void);
int test_block_prefetch(void)
{
    printf("\n=== block_prefetch (read-ahead worker) ===\n");
    int failures = 0;
    failures += t_disabled_noop();
    failures += t_lifecycle();
    failures += t_bounded_memory();
    failures += t_misspath_failsafe();
    failures += t_warm_microbench();
    block_prefetch_stop();        /* leave no worker running for sibling groups */
    return failures;
}
