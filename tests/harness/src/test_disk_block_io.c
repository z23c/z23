/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for disk_block_io thread safety and pread correctness. */

#include "test/test_core.h"
#include "storage/disk_block_io.h"
#include "primitives/block.h"
#include "core/serialize.h"
#include "config/boot_internal.h"
#include "services/block_index_loader.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#if !defined(_WIN32)
#include <dlfcn.h>
/* Only this thread's exact fixture path can fail, and only its first rb+ open.
 * Other streams use libc unchanged; no host files or library are modified. */
static _Thread_local const char *dbio_fault_path;
static _Thread_local int dbio_open_error, dbio_open_hits;
FILE *fopen(const char *path, const char *mode)
{
    if (dbio_fault_path && strcmp(path, dbio_fault_path) == 0 &&
        strcmp(mode, "rb+") == 0 && dbio_open_error) {
        errno = dbio_open_error;
        dbio_open_error = 0;
        dbio_open_hits++;
        return NULL;
    }
    void *symbol = dlsym(RTLD_NEXT, "fopen");
    FILE *(*native_open)(const char *, const char *);
    static_assert(sizeof(native_open) == sizeof(symbol));
    if (!symbol) {
        fprintf(stderr, "disk block fixture: cannot resolve libc fopen\n");
        errno = ENOSYS;
        return NULL;
    }
    memcpy(&native_open, &symbol, sizeof(native_open));
    return native_open(path, mode);
}
#endif

#if defined(_WIN32)
#include <windows.h>
/* NTFS hard links via the Win32 API; errno set for the fixture message. */
static int dbio_link(const char *existing, const char *alias)
{
    if (CreateHardLinkA(alias, existing, NULL))
        return 0;
    errno = EIO;
    return -1;
}
#define link dbio_link
#endif

/* ── Helpers ──────────────────────────────────────────────── */

static void make_test_dir(char *buf, size_t len)
{
    snprintf(buf, len, "./test-tmp/%d_disk_io", (int)getpid());
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

static const unsigned char TEST_MSG_START[4] = {0x24, 0xe9, 0x27, 0x64};

/* Build a minimal block with a distinguishing nTime value (caller frees). */
static void build_test_block(struct block *b, uint32_t ntime)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = ntime;
    b->header.nBits = 0x2000ffff;
    b->num_vtx = 1;
    b->vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    transaction_init(&b->vtx[0]);
    transaction_alloc(&b->vtx[0], 1, 1);
    b->vtx[0].vin[0].sequence = 0xffffffff;
    b->vtx[0].vout[0].value = 10 * COIN;
}

/* Write a minimal block with a distinguishing nTime value. */
static bool write_test_block(const char *datadir, struct disk_block_pos *pos,
                             uint32_t ntime)
{
    struct block b;
    build_test_block(&b, ntime);
    bool ok = write_block_to_disk(&b, pos, datadir, TEST_MSG_START);
    block_free(&b);
    return ok;
}

/* ── Thread safety test context ──────────────────────────── */

struct reader_ctx {
    const char *datadir;
    struct disk_block_pos pos;
    uint32_t expected_ntime;
    int iterations;
    bool ok;
};

static void *reader_thread(void *arg)
{
    struct reader_ctx *ctx = arg;
    ctx->ok = true;

    for (int i = 0; i < ctx->iterations; i++) {
        struct block b;
        if (!read_block_from_disk(&b, &ctx->pos, ctx->datadir)) {
            ctx->ok = false;
            return NULL;
        }
        if (b.header.nTime != ctx->expected_ntime) {
            ctx->ok = false;
            block_free(&b);
            return NULL;
        }
        block_free(&b);
    }
    return NULL;
}

static void *pread_reader_thread(void *arg)
{
    struct reader_ctx *ctx = arg;
    ctx->ok = true;

    for (int i = 0; i < ctx->iterations; i++) {
        struct block b;
        if (!read_block_from_disk_pread(&b, &ctx->pos, ctx->datadir)) {
            ctx->ok = false;
            return NULL;
        }
        if (b.header.nTime != ctx->expected_ntime) {
            ctx->ok = false;
            block_free(&b);
            return NULL;
        }
        block_free(&b);
    }
    return NULL;
}

/* ── Tests ───────────────────────────────────────────────── */

static int test_pread_basic_read(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("pread: basic read matches written block") {
        struct disk_block_pos pos = { .nFile = 0, .nPos = 0 };
        if (!write_test_block(tmpdir, &pos, 12345)) {
            printf("FAIL (write)\n"); failures++; goto _test_next;
        }

        struct block b;
        if (!read_block_from_disk_pread(&b, &pos, tmpdir)) {
            printf("FAIL (pread read)\n"); failures++; goto _test_next;
        }
        if (b.header.nTime != 12345 || b.num_vtx != 1) {
            printf("FAIL (data mismatch: nTime=%u vtx=%zu)\n",
                   b.header.nTime, b.num_vtx);
            failures++;
            block_free(&b);
            goto _test_next;
        }
        block_free(&b);
        printf("OK\n");
    }
    _test_next:

    cleanup_test_dir(tmpdir);
    return failures;
}

static int test_pread_matches_fread(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("pread: result matches read_block_from_disk") {
        struct disk_block_pos pos = { .nFile = 0, .nPos = 0 };
        if (!write_test_block(tmpdir, &pos, 77777)) {
            printf("FAIL (write)\n"); failures++; goto _test_next;
        }

        /* read_block_from_disk now delegates to pread internally,
         * so both paths should produce identical results */
        struct block b1, b2;
        if (!read_block_from_disk(&b1, &pos, tmpdir)) {
            printf("FAIL (read)\n"); failures++; goto _test_next;
        }
        if (!read_block_from_disk_pread(&b2, &pos, tmpdir)) {
            printf("FAIL (pread)\n"); failures++;
            block_free(&b1);
            goto _test_next;
        }
        if (b1.header.nTime != b2.header.nTime ||
            b1.num_vtx != b2.num_vtx) {
            printf("FAIL (mismatch)\n"); failures++;
        } else {
            printf("OK\n");
        }
        block_free(&b1);
        block_free(&b2);
    }
    _test_next:

    cleanup_test_dir(tmpdir);
    return failures;
}

static int test_concurrent_reads(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("pread: 4 threads reading different blocks concurrently") {
        /* Write 4 blocks with different nTime values */
        struct disk_block_pos positions[4];
        uint32_t times[4] = {1000, 2000, 3000, 4000};

        for (int i = 0; i < 4; i++) {
            positions[i].nFile = i;
            positions[i].nPos = 0;
            if (!write_test_block(tmpdir, &positions[i], times[i])) {
                printf("FAIL (write block %d)\n", i);
                failures++;
                goto _test_next;
            }
        }

        /* Spawn 4 reader threads, each reading its own block 50 times */
        pthread_t threads[4];
        struct reader_ctx ctxs[4];
        for (int i = 0; i < 4; i++) {
            ctxs[i].datadir = tmpdir;
            ctxs[i].pos = positions[i];
            ctxs[i].expected_ntime = times[i];
            ctxs[i].iterations = 50;
            ctxs[i].ok = false;
            pthread_create(&threads[i], NULL, reader_thread, &ctxs[i]);
        }

        bool all_ok = true;
        for (int i = 0; i < 4; i++) {
            pthread_join(threads[i], NULL);
            if (!ctxs[i].ok) {
                printf("FAIL (thread %d)\n", i);
                all_ok = false;
            }
        }
        if (!all_ok) {
            failures++;
            goto _test_next;
        }
        printf("OK\n");
    }
    _test_next:

    cleanup_test_dir(tmpdir);
    return failures;
}

static int test_concurrent_pread_same_file(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("pread: 4 threads reading same file concurrently") {
        struct disk_block_pos pos = { .nFile = 0, .nPos = 0 };
        if (!write_test_block(tmpdir, &pos, 55555)) {
            printf("FAIL (write)\n"); failures++; goto _test_next;
        }

        pthread_t threads[4];
        struct reader_ctx ctxs[4];
        for (int i = 0; i < 4; i++) {
            ctxs[i].datadir = tmpdir;
            ctxs[i].pos = pos;
            ctxs[i].expected_ntime = 55555;
            ctxs[i].iterations = 100;
            ctxs[i].ok = false;
            pthread_create(&threads[i], NULL, pread_reader_thread, &ctxs[i]);
        }

        bool all_ok = true;
        for (int i = 0; i < 4; i++) {
            pthread_join(threads[i], NULL);
            if (!ctxs[i].ok) all_ok = false;
        }
        if (!all_ok) {
            printf("FAIL (concurrent pread)\n");
            failures++;
            goto _test_next;
        }
        printf("OK\n");
    }
    _test_next:

    cleanup_test_dir(tmpdir);
    return failures;
}

static int test_disk_block_pread_raw(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("disk_block_pread: raw byte read returns data") {
        struct disk_block_pos pos = { .nFile = 0, .nPos = 0 };
        if (!write_test_block(tmpdir, &pos, 99999)) {
            printf("FAIL (write)\n"); failures++; goto _test_next;
        }

        uint8_t buf[4096];
        ssize_t n = disk_block_pread(tmpdir, &pos, "blk", buf, sizeof(buf));
        if (n <= 0) {
            printf("FAIL (pread returned %zd)\n", n);
            failures++;
            goto _test_next;
        }
        printf("OK (%zd bytes)\n", n);
    }
    _test_next:

    cleanup_test_dir(tmpdir);
    return failures;
}

static int test_pread_accepts_frame_offset(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("pread: accepts frame offset as recoverable index shape") {
        struct disk_block_pos pos = { .nFile = 0, .nPos = 0 };
        if (!write_test_block(tmpdir, &pos, 424242)) {
            printf("FAIL (write)\n"); failures++; goto _test_next;
        }
        if (pos.nPos < 8) {
            printf("FAIL (unexpected payload pos %u)\n", pos.nPos);
            failures++;
            goto _test_next;
        }

        struct disk_block_pos frame_pos = pos;
        frame_pos.nPos -= 8;

        struct block b;
        if (!read_block_from_disk_pread(&b, &frame_pos, tmpdir)) {
            printf("FAIL (pread frame offset)\n");
            failures++;
            goto _test_next;
        }
        if (b.header.nTime != 424242 || b.num_vtx != 1) {
            printf("FAIL (data mismatch: nTime=%u vtx=%zu)\n",
                   b.header.nTime, b.num_vtx);
            failures++;
            block_free(&b);
            goto _test_next;
        }
        block_free(&b);
        printf("OK\n");
    }
    _test_next:

    cleanup_test_dir(tmpdir);
    return failures;
}

/* A position with no 8-byte magic+size frame at pos-8 or pos is refused,
 * even when a parseable block payload sits there and hashes to the entry's
 * hash; an unframed offset must not answer. The sibling mmap reader
 * (bmr_get_payload) refuses the same shape. */
static int test_pread_refuses_unframed_position(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("pread: refuses a position with no block frame") {
        struct block a;
        build_test_block(&a, 787878);
        struct byte_stream s;
        stream_init(&s, 4096);
        bool ok = block_serialize(&a, &s);
        struct uint256 hash_a;
        block_get_hash(&a, &hash_a);
        block_free(&a);
        if (!ok) {
            stream_free(&s);
            printf("FAIL (serialize)\n"); failures++; goto _test_next;
        }

        /* blk00000.dat: 16 filler bytes (0x5a5a5a5a is no accepted magic),
         * then the raw block payload with no magic+size frame. */
        char path[512];
        snprintf(path, sizeof(path), "%s/blocks/blk00000.dat", tmpdir);
        FILE *f = fopen(path, "wb");
        if (!f) {
            stream_free(&s);
            printf("FAIL (open blk00000.dat)\n"); failures++; goto _test_next;
        }
        unsigned char filler[16];
        memset(filler, 0x5a, sizeof(filler));
        ok = fwrite(filler, 1, sizeof(filler), f) == sizeof(filler) &&
             fwrite(s.data, 1, s.size, f) == s.size;
        fclose(f);
        stream_free(&s);
        if (!ok) {
            printf("FAIL (write blk00000.dat)\n"); failures++; goto _test_next;
        }

        /* The payload starts at 16, but neither 8..15 nor 16..23 is a frame
         * header, so the position is refused. */
        struct disk_block_pos pos = { .nFile = 0, .nPos = 16 };
        struct block r;
        if (read_block_from_disk_pread(&r, &pos, tmpdir)) {
            printf("FAIL (unframed position answered: nTime=%u)\n",
                   r.header.nTime);
            block_free(&r);
            failures++;
            goto _test_next;
        }

        /* Through the index-level reader: a HAVE_DATA entry at a frameless
         * offset reports unreadable. */
        struct block_index bi;
        block_index_init(&bi);
        bi.nHeight = 9;
        bi.hashBlock = hash_a;
        bi.phashBlock = &bi.hashBlock;
        block_index_disk_pos_store(&bi, 0, 16);
        block_index_status_fetch_or(&bi, BLOCK_HAVE_DATA);
        if (block_index_have_data_readable(&bi, tmpdir)) {
            printf("FAIL (index reader answered an unframed position)\n");
            failures++;
            goto _test_next;
        }
        printf("OK\n");
    }
_test_next:
    cleanup_test_dir(tmpdir);
    return failures;
}

static int test_set_have_data_verified(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("set_have_data_verified: marks only after read-back hash match") {
        struct disk_block_pos pos = { .nFile = 0, .nPos = 0 };
        if (!write_test_block(tmpdir, &pos, 515151)) {
            printf("FAIL (write)\n"); failures++; goto _test_next;
        }

        struct block b;
        if (!read_block_from_disk_pread(&b, &pos, tmpdir)) {
            printf("FAIL (readback)\n"); failures++; goto _test_next;
        }
        struct uint256 hash;
        block_get_hash(&b, &hash);
        block_free(&b);

        struct block_index bi;
        block_index_init(&bi);
        bi.nHeight = 51;
        bi.phashBlock = &hash;
        if (!block_index_set_have_data_verified(&bi, &pos, tmpdir)) {
            printf("FAIL (verify helper)\n");
            failures++;
            goto _test_next;
        }
        if (!(bi.nStatus & BLOCK_HAVE_DATA) ||
            bi.nFile != pos.nFile || bi.nDataPos != pos.nPos) {
            printf("FAIL (index not marked correctly)\n");
            failures++;
            goto _test_next;
        }
        if (!block_index_have_data_readable(&bi, tmpdir)) {
            printf("FAIL (readability helper rejected valid data)\n");
            failures++;
            goto _test_next;
        }
        struct uint256 wrong = hash;
        wrong.data[0] ^= 0xff;
        bi.phashBlock = &wrong;
        if (block_index_have_data_readable(&bi, tmpdir)) {
            printf("FAIL (readability helper accepted mismatched data)\n");
            failures++;
            goto _test_next;
        }
        printf("OK\n");
    }
    _test_next:

    cleanup_test_dir(tmpdir);
    return failures;
}

#if !defined(_WIN32)
/* Deterministic lifetime regression for the disk-completion hook. A callback
 * admitted before the shutdown registration clear can still be in flight
 * while consumer teardown runs; the quiesce boundary must drain it first.
 * All interleavings are condition-variable driven — no sleeps. */
struct hook_lifetime_fixture {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    bool entered;
    bool release;
    bool finished;
    bool quiesce_started;
    bool quiesce_done;
};

static void hook_lifetime_blocking_cb(void *v)
{
    struct hook_lifetime_fixture *f = v;
    pthread_mutex_lock(&f->mu);
    f->entered = true;
    pthread_cond_broadcast(&f->cv);
    while (!f->release)
        pthread_cond_wait(&f->cv, &f->mu);
    f->finished = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
}

static void *hook_lifetime_fire_worker(void *v)
{
    (void)v;
    disk_block_io_test_fire_have_data_hook();
    return NULL;
}

static void *hook_lifetime_quiesce_worker(void *v)
{
    struct hook_lifetime_fixture *f = v;
    pthread_mutex_lock(&f->mu);
    f->quiesce_started = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    disk_block_io_quiesce_have_data_hook();
    pthread_mutex_lock(&f->mu);
    f->quiesce_done = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    return NULL;
}

static void hook_lifetime_cleanup(struct hook_lifetime_fixture *f,
                                  pthread_t *fire_w, bool fire_started,
                                  pthread_t *quiesce_w, bool quiesce_started)
{
    pthread_mutex_lock(&f->mu);
    f->release = true;
    pthread_cond_broadcast(&f->cv);
    pthread_mutex_unlock(&f->mu);
    if (fire_started)
        pthread_join(*fire_w, NULL);
    if (quiesce_started)
        pthread_join(*quiesce_w, NULL);
}

static int test_have_data_hook_quiesce_drains_inflight(void)
{
    int failures = 0;
    struct hook_lifetime_fixture f = {0};
    pthread_mutex_init(&f.mu, NULL);
    pthread_cond_init(&f.cv, NULL);
    pthread_t fire_w, quiesce_w;
    bool fire_started = false, quiesce_started = false;

    TEST("have_data hook: quiesce drains an admitted callback before teardown") {
        disk_block_io_set_have_data_hook(hook_lifetime_blocking_cb, &f);
        if (pthread_create(&fire_w, NULL, hook_lifetime_fire_worker, NULL) != 0) {
            printf("FAIL (fire worker)\n"); failures++; goto _test_next;
        }
        fire_started = true;

        pthread_mutex_lock(&f.mu);
        while (!f.entered)
            pthread_cond_wait(&f.cv, &f.mu);
        pthread_mutex_unlock(&f.mu);

        /* The shutdown clear is cheap: it must not wait for in-flight calls. */
        disk_block_io_set_have_data_hook(NULL, NULL);

        if (pthread_create(&quiesce_w, NULL, hook_lifetime_quiesce_worker, &f) != 0) {
            printf("FAIL (quiesce worker)\n"); failures++; goto _test_next;
        }
        quiesce_started = true;

        pthread_mutex_lock(&f.mu);
        while (!f.quiesce_started)
            pthread_cond_wait(&f.cv, &f.mu);
        if (f.quiesce_done || f.finished) {
            pthread_mutex_unlock(&f.mu);
            printf("FAIL (teardown-side drain lost the in-flight race)\n");
            failures++; goto _test_next;
        }
        /* Simulated consumer destroy point: the callback is still blocked, so
         * reaching it now would be the lifetime violation under test. */
        f.release = true;
        pthread_cond_broadcast(&f.cv);
        while (!f.finished || !f.quiesce_done)
            pthread_cond_wait(&f.cv, &f.mu);
        pthread_mutex_unlock(&f.mu);

        pthread_join(fire_w, NULL); fire_started = false;
        pthread_join(quiesce_w, NULL); quiesce_started = false;
        if (!f.quiesce_done) {
            printf("FAIL (quiesce never completed)\n"); failures++; goto _test_next;
        }
        printf("OK\n");
    }
    _test_next:

    if (fire_started || quiesce_started)
        hook_lifetime_cleanup(&f, &fire_w, fire_started, &quiesce_w, quiesce_started);
    pthread_mutex_destroy(&f.mu);
    pthread_cond_destroy(&f.cv);
    return failures;
}
#endif

static int test_write_allocates_append_position(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("write_block_to_disk: file=-1 allocates append position") {
        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        if (!write_test_block(tmpdir, &pos, 616161)) {
            printf("FAIL (write)\n"); failures++; goto _test_next;
        }
        if (pos.nFile < 0 || pos.nPos == 0) {
            printf("FAIL (position not allocated file=%d pos=%u)\n",
                   pos.nFile, pos.nPos);
            failures++;
            goto _test_next;
        }
        struct block b;
        if (!read_block_from_disk_pread(&b, &pos, tmpdir)) {
            printf("FAIL (readback)\n"); failures++; goto _test_next;
        }
        bool ok = b.header.nTime == 616161;
        block_free(&b);
        if (!ok) {
            printf("FAIL (wrong block read back)\n");
            failures++;
            goto _test_next;
        }
        printf("OK\n");
    }
    _test_next:

    cleanup_test_dir(tmpdir);
    return failures;
}

/* Read an entire file into a malloc'd buffer. Returns bytes read, -1 on error.
 * Caller frees *out. */
static long slurp_file(const char *path, unsigned char **out)
{
    *out = NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    unsigned char *buf = malloc(sz > 0 ? (size_t)sz : 1); // raw-alloc-ok:test-fixture
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if ((long)n != sz) { free(buf); return -1; }
    *out = buf;
    return sz;
}

static int test_append_quarantines_hardlinked_tail(void)
{
    int failures = 0;
    bool deferred = false;
    char tmpdir[256], shared_path[512], alias_path[512];
    unsigned char *before = NULL, *after_shared = NULL, *after_alias = NULL;
    long before_len = -1, after_shared_len = -1, after_alias_len = -1;
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("write_block_to_disk: append rotates past hardlinked tail") {
        /* The IBD-only append hint: a hard link created after the hint was
         * recorded still invalidates it and rotates to a new blk file. */
        disk_block_io_set_deferred_sync(true);
        deferred = true;
        struct disk_block_pos first;
        disk_block_pos_init(&first);
        if (!write_test_block(tmpdir, &first, 717171)) {
            printf("FAIL (seed write)\n"); failures++; goto _test_next;
        }
        get_block_pos_filename(shared_path, sizeof(shared_path), tmpdir,
                               &first, "blk");
        snprintf(alias_path, sizeof(alias_path), "%s/shared-blk.dat", tmpdir);
        if (link(shared_path, alias_path) != 0) {
            printf("FAIL (hardlink fixture: %s)\n", strerror(errno));
            failures++; goto _test_next;
        }
        before_len = slurp_file(shared_path, &before);
        if (before_len <= 0) {
            printf("FAIL (seed read)\n"); failures++; goto _test_next;
        }

        struct disk_block_pos appended;
        disk_block_pos_init(&appended);
        bool wrote = write_test_block(tmpdir, &appended, 727272);
        after_shared_len = slurp_file(shared_path, &after_shared);
        after_alias_len = slurp_file(alias_path, &after_alias);
        bool shared_unchanged = after_shared_len == before_len &&
            after_alias_len == before_len &&
            memcmp(before, after_shared, (size_t)before_len) == 0 &&
            memcmp(before, after_alias, (size_t)before_len) == 0;
        struct block readback;
        block_init(&readback);
        bool read_ok = wrote && appended.nFile == first.nFile + 1 &&
            read_block_from_disk_pread(&readback, &appended, tmpdir) &&
            readback.header.nTime == 727272;
        block_free(&readback);
        if (!wrote || !shared_unchanged || !read_ok) {
            printf("FAIL (wrote=%d file=%d shared_unchanged=%d read=%d)\n",
                   wrote, appended.nFile, shared_unchanged, read_ok);
            failures++; goto _test_next;
        }
        printf("OK\n");
    }
_test_next:
    if (deferred) {
        (void)disk_block_io_sync_pending();
        disk_block_io_set_deferred_sync(false);
    }
    free(before);
    free(after_shared);
    free(after_alias);
    cleanup_test_dir(tmpdir);
    return failures;
}

static int test_explicit_write_refuses_hardlinked_file(void)
{
    int failures = 0;
    char tmpdir[256], shared_path[512], alias_path[512];
    unsigned char *before = NULL, *after_shared = NULL, *after_alias = NULL;
    long before_len = -1, after_shared_len = -1, after_alias_len = -1;
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("write_block_to_disk: explicit hardlinked position fails unchanged") {
        struct disk_block_pos first;
        disk_block_pos_init(&first);
        if (!write_test_block(tmpdir, &first, 737373)) {
            printf("FAIL (seed write)\n"); failures++; goto _test_next;
        }
        get_block_pos_filename(shared_path, sizeof(shared_path), tmpdir,
                               &first, "blk");
        snprintf(alias_path, sizeof(alias_path), "%s/shared-blk.dat", tmpdir);
        if (link(shared_path, alias_path) != 0) {
            printf("FAIL (hardlink fixture: %s)\n", strerror(errno));
            failures++; goto _test_next;
        }
        before_len = slurp_file(shared_path, &before);
        if (before_len <= 0) {
            printf("FAIL (seed read)\n"); failures++; goto _test_next;
        }

        struct disk_block_pos explicit_pos = {.nFile = first.nFile,
                                               .nPos = 0};
        bool wrote = write_test_block(tmpdir, &explicit_pos, 747474);
        after_shared_len = slurp_file(shared_path, &after_shared);
        after_alias_len = slurp_file(alias_path, &after_alias);
        bool unchanged = after_shared_len == before_len &&
            after_alias_len == before_len &&
            memcmp(before, after_shared, (size_t)before_len) == 0 &&
            memcmp(before, after_alias, (size_t)before_len) == 0;
        if (wrote || !unchanged) {
            printf("FAIL (wrote=%d unchanged=%d)\n", wrote, unchanged);
            failures++; goto _test_next;
        }
        printf("OK\n");
    }
_test_next:
    free(before);
    free(after_shared);
    free(after_alias);
    cleanup_test_dir(tmpdir);
    return failures;
}

/* Format and create the immediate and deferred test datadirs, each with a
 * blocks subdir. */
static void make_deferred_sync_dirs(char *dir_immediate, size_t imm_len,
                                    char *dir_deferred, size_t def_len)
{
    snprintf(dir_immediate, imm_len,
             "./test-tmp/%d_disk_io_imm", (int)getpid());
    snprintf(dir_deferred, def_len,
             "./test-tmp/%d_disk_io_def", (int)getpid());
    mkdir("./test-tmp", 0755);
    for (int i = 0; i < 2; i++) {
        const char *d = i == 0 ? dir_immediate : dir_deferred;
        char blocks[512];
        mkdir(d, 0755);
        snprintf(blocks, sizeof(blocks), "%s/blocks", d);
        mkdir(blocks, 0755);
    }
}

/* True when both slurps succeeded with equal lengths and identical bytes. */
static bool slurped_files_identical(long ni, long nd,
                                    const unsigned char *bi,
                                    const unsigned char *bd)
{
    return ni > 0 && ni == nd && bi && bd &&
           memcmp(bi, bd, (size_t)ni) == 0;
}

/* Deferred-sync mode writes a byte-identical block file to immediate mode,
 * records a pending file (no inline fdatasync), and reads back before and
 * after disk_block_io_sync_pending(). */
static int test_deferred_sync_byte_identical(void)
{
    int failures = 0;
    char dir_immediate[256], dir_deferred[256];
    make_deferred_sync_dirs(dir_immediate, sizeof(dir_immediate),
                            dir_deferred, sizeof(dir_deferred));

    TEST("deferred_sync: byte-identical file + pending set + readback") {
        /* Immediate mode (default). */
        if (disk_block_io_deferred_sync_enabled()) {
            printf("FAIL (deferred mode leaked on from a prior test)\n");
            failures++; goto _test_next;
        }
        struct disk_block_pos pos_imm;
        disk_block_pos_init(&pos_imm);
        if (!write_test_block(dir_immediate, &pos_imm, 424242)) {
            printf("FAIL (immediate write)\n"); failures++; goto _test_next;
        }

        /* Deferred mode: same block. Must NOT sync inline — record pending. */
        disk_block_io_set_deferred_sync(true);
        if (!disk_block_io_deferred_sync_enabled()) {
            printf("FAIL (deferred flag not set)\n"); failures++;
            disk_block_io_set_deferred_sync(false); goto _test_next;
        }
        struct disk_block_pos pos_def;
        disk_block_pos_init(&pos_def);
        if (!write_test_block(dir_deferred, &pos_def, 424242)) {
            printf("FAIL (deferred write)\n"); failures++;
            disk_block_io_set_deferred_sync(false); goto _test_next;
        }

        /* Body must be readable from the page cache BEFORE the deferred sync
         * (so body_persist's read-back does not spuriously requeue). */
        struct block pre;
        if (!read_block_from_disk_pread(&pre, &pos_def, dir_deferred)) {
            printf("FAIL (deferred readback before sync)\n"); failures++;
            disk_block_io_set_deferred_sync(false); goto _test_next;
        }
        bool pre_ok = pre.header.nTime == 424242;
        block_free(&pre);
        if (!pre_ok) {
            printf("FAIL (wrong block before sync)\n"); failures++;
            disk_block_io_set_deferred_sync(false); goto _test_next;
        }

        /* Flush the deferred sync, then leave deferred mode. */
        if (!disk_block_io_sync_pending()) {
            printf("FAIL (sync_pending returned false)\n"); failures++;
            disk_block_io_set_deferred_sync(false); goto _test_next;
        }
        disk_block_io_set_deferred_sync(false);

        /* The two block files must be byte-for-byte identical: deferral changes
         * only WHEN bytes are synced, never the bytes. */
        char path_imm[600], path_def[600];
        struct disk_block_pos f0 = { .nFile = 0, .nPos = 0 };
        get_block_pos_filename(path_imm, sizeof(path_imm), dir_immediate, &f0, "blk");
        get_block_pos_filename(path_def, sizeof(path_def), dir_deferred, &f0, "blk");
        unsigned char *bi = NULL, *bd = NULL;
        long ni = slurp_file(path_imm, &bi);
        long nd = slurp_file(path_def, &bd);
        bool identical = slurped_files_identical(ni, nd, bi, bd);
        free(bi); free(bd);
        if (!identical) {
            printf("FAIL (files differ imm=%ld def=%ld)\n", ni, nd);
            failures++; goto _test_next;
        }

        /* Readback after sync still succeeds. */
        struct block post;
        if (!read_block_from_disk_pread(&post, &pos_def, dir_deferred)) {
            printf("FAIL (deferred readback after sync)\n"); failures++;
            goto _test_next;
        }
        bool post_ok = post.header.nTime == 424242;
        block_free(&post);
        if (!post_ok) {
            printf("FAIL (wrong block after sync)\n"); failures++; goto _test_next;
        }

        /* A second sync with nothing pending is a benign no-op → true. */
        if (!disk_block_io_sync_pending()) {
            printf("FAIL (empty sync_pending should be true)\n"); failures++;
            goto _test_next;
        }
        printf("OK\n");
    }
    _test_next:
    /* Never leak deferred mode into sibling tests. */
    disk_block_io_set_deferred_sync(false);
    cleanup_test_dir(dir_immediate);
    cleanup_test_dir(dir_deferred);
    return failures;
}

/* Between enter() and exit() the reader reuses one fd across same-file
 * reads; interleaved blocks at different offsets return their own bytes;
 * after exit() the stateless path resumes. */
static int test_scoped_read_fd_cache(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("read fd cache: scoped reuse returns correct interleaved blocks") {
        struct disk_block_pos pa, pb;
        disk_block_pos_init(&pa);
        disk_block_pos_init(&pb);
        if (!write_test_block(tmpdir, &pa, 111111) ||
            !write_test_block(tmpdir, &pb, 222222)) {
            printf("FAIL (write)\n"); failures++; goto _test_next;
        }
        if (pa.nFile != pb.nFile) {
            printf("FAIL (blocks not colocated file a=%d b=%d)\n",
                   pa.nFile, pb.nFile);
            failures++; goto _test_next;
        }

        disk_block_io_read_fd_cache_enter();
        bool ok = true;
        for (int i = 0; i < 8 && ok; i++) {
            struct block a, b;
            block_init(&a);
            block_init(&b);
            if (!read_block_from_disk_pread(&a, &pa, tmpdir) ||
                !read_block_from_disk_pread(&b, &pb, tmpdir) ||
                a.header.nTime != 111111 || b.header.nTime != 222222)
                ok = false;
            block_free(&a);
            block_free(&b);
        }
        disk_block_io_read_fd_cache_exit();
        if (!ok) {
            printf("FAIL (interleaved cached reads returned wrong block)\n");
            failures++; goto _test_next;
        }

        /* After exit the cache is off and its fd closed: a normal read works. */
        struct block c;
        block_init(&c);
        if (!read_block_from_disk_pread(&c, &pa, tmpdir)) {
            printf("FAIL (post-exit read)\n");
            block_free(&c);
            failures++; goto _test_next;
        }
        bool post_ok = c.header.nTime == 111111;
        block_free(&c);
        if (!post_ok) {
            printf("FAIL (post-exit wrong block)\n"); failures++; goto _test_next;
        }
        printf("OK\n");
    }
    _test_next:
    disk_block_io_read_fd_cache_exit();  /* never leak enabled state */
    cleanup_test_dir(tmpdir);
    return failures;
}

/* ── Duplicate-scan policy + position self-heal ─────────────
 * blk*.dat files hardlinked into a foreign datadir can get their tail
 * rewritten, so the boot scan indexes the EARLIEST copy of a duplicated
 * block and a dangling position is repairable from the surviving local
 * copy. */

/* A blk file holding TWO verbatim copies of one block indexes the earliest;
 * after the tail copy is destroyed it still reads back and hash-matches. */
static int test_scan_duplicate_keeps_earliest_copy(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("blk scan duplicate policy: earliest copy wins") {
        struct block b, c;
        build_test_block(&b, 333333);
        build_test_block(&c, 444444);
        struct disk_block_pos pb1, pb2, pc;
        disk_block_pos_init(&pb1);
        disk_block_pos_init(&pb2);
        disk_block_pos_init(&pc);
        bool ok = write_block_to_disk(&b, &pb1, tmpdir, TEST_MSG_START) &&
                  write_block_to_disk(&b, &pb2, tmpdir, TEST_MSG_START) &&
                  write_block_to_disk(&c, &pc, tmpdir, TEST_MSG_START);
        struct uint256 hash_b, hash_c;
        block_get_hash(&b, &hash_b);
        block_get_hash(&c, &hash_c);
        block_free(&b);
        block_free(&c);
        ASSERT(ok);

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *bi_b = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hash_b);
        struct block_index *bi_c = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hash_c);
        ASSERT(bi_b != NULL && bi_c != NULL);

        ASSERT(scan_block_files_mark_data(&ms, tmpdir, NULL) > 0);
        ASSERT(bi_b->nStatus & BLOCK_HAVE_DATA);
        ASSERT(bi_b->nFile == pb1.nFile && bi_b->nDataPos == pb1.nPos);
        ASSERT(bi_c->nStatus & BLOCK_HAVE_DATA && bi_c->nDataPos == pc.nPos);

        /* Simulate the foreign writer: destroy the SECOND copy's record. */
        char blkpath[512];
        snprintf(blkpath, sizeof(blkpath), "%s/blocks/blk%05d.dat",
                 tmpdir, pb1.nFile);
        int fd = open(blkpath, O_WRONLY);
        ASSERT(fd >= 0);
        char junk[4096];
        memset(junk, 0xA5, sizeof(junk));
        size_t rec2_len = (size_t)(pc.nPos - pb2.nPos);
        ssize_t wr = pwrite(fd, junk,
                            rec2_len < sizeof(junk) ? rec2_len : sizeof(junk),
                            (off_t)(pb2.nPos - 8));
        close(fd);
        ASSERT(wr > 0);

        /* The indexed (first) copy must still read and hash-match. */
        struct block r;
        block_init(&r);
        ok = read_block_from_disk_index_pread(&r, bi_b, tmpdir) &&
             r.header.nTime == 333333;
        block_free(&r);
        ASSERT(ok);
        printf("OK\n");
    }
_test_next:
    cleanup_test_dir(tmpdir);
    return failures;
}

/* block_index_repair_pos_from_disk: a stale/torn (nFile,nDataPos) is healed
 * by a hash-targeted blk-file scan + verified re-store; a hash with no copy
 * on disk returns false and leaves the entry untouched. */
static int test_position_repair_from_local_copy(void)
{
    int failures = 0;
    char tmpdir[256];
    make_test_dir(tmpdir, sizeof(tmpdir));

    TEST("repair_pos_from_disk: stale position healed, no-copy arm falls through") {
        struct block a, b;
        build_test_block(&a, 555555);
        build_test_block(&b, 666666);
        struct disk_block_pos pa, pb;
        disk_block_pos_init(&pa);
        disk_block_pos_init(&pb);
        bool ok = write_block_to_disk(&a, &pa, tmpdir, TEST_MSG_START) &&
                  write_block_to_disk(&b, &pb, tmpdir, TEST_MSG_START);
        struct uint256 hash_a;
        block_get_hash(&a, &hash_a);
        block_free(&a);
        block_free(&b);
        ASSERT(ok);

        struct block_index bi;
        block_index_init(&bi);
        bi.nHeight = 42;
        bi.hashBlock = hash_a;
        bi.phashBlock = &bi.hashBlock;
        /* Bogus position: mid-record garbage inside block B's record, with
         * HAVE_DATA set (read paths fire only on flagged entries). */
        block_index_disk_pos_store(&bi, pb.nFile, pb.nPos + 20);
        block_index_status_fetch_or(&bi, BLOCK_HAVE_DATA);

        ASSERT(block_index_repair_pos_from_disk(&bi, tmpdir, true));
        struct disk_block_pos fixed;
        disk_block_pos_init(&fixed);
        ASSERT(block_index_disk_pos_snapshot(&bi, &fixed, NULL));
        ASSERT(fixed.nFile == pa.nFile && fixed.nPos == pa.nPos);
        ASSERT(block_index_status_load(&bi) & BLOCK_HAVE_DATA);

        struct block r;
        block_init(&r);
        ok = read_block_from_disk_index_pread(&r, &bi, tmpdir) &&
             r.header.nTime == 555555;
        block_free(&r);
        ASSERT(ok);

        /* Second arm: hash with no copy on disk — false, entry untouched
         * (and it must NOT steal the other block's valid position). */
        struct block_index bi2;
        block_index_init(&bi2);
        bi2.nHeight = 43;
        memset(bi2.hashBlock.data, 0x77, sizeof(bi2.hashBlock.data));
        bi2.phashBlock = &bi2.hashBlock;
        block_index_disk_pos_store(&bi2, pa.nFile, pa.nPos);
        unsigned int st_before = block_index_status_load(&bi2);
        ASSERT(!block_index_repair_pos_from_disk(&bi2, tmpdir, true));
        /* bi2 never gained HAVE_DATA, so the snapshot API refuses it by
         * design; assert the raw position fields directly instead. */
        ASSERT(block_index_file_load(&bi2) == pa.nFile &&
               block_index_data_pos_load(&bi2) == pa.nPos);
        ASSERT(block_index_status_load(&bi2) == st_before);
        printf("OK\n");
    }
_test_next:
    cleanup_test_dir(tmpdir);
    return failures;
}

/* Missing datadirs fail closed. Other bytes are not a lifetime signal:
 * POSIX permits control bytes in path components. */
static int test_block_pos_filename_datadir_contract(void)
{
    int failures = 0;
    char tmpdir[512];
    make_test_dir(tmpdir, sizeof(tmpdir));

    printf("  block path refuses missing datadir without restricting bytes... ");
    {
        struct disk_block_pos pos = { .nFile = 49, .nPos = 8 };
        char path[512];
        memset(path, 'x', sizeof(path));
        get_block_pos_filename(path, sizeof(path), NULL, &pos, "blk");
        if (path[0] != '\0') {
            printf("FAIL (NULL datadir produced a path: %s)\n", path);
            failures++;
            goto _test_next;
        }

        /* Empty is refused on the same ground. */
        memset(path, 'x', sizeof(path));
        get_block_pos_filename(path, sizeof(path), "", &pos, "blk");
        if (path[0] != '\0') {
            printf("FAIL (empty datadir produced a path: %s)\n", path);
            failures++;
            goto _test_next;
        }
        /* Real paths — including UTF-8 and legal control bytes — are built
         * exactly as supplied. */
        get_block_pos_filename(path, sizeof(path), tmpdir, &pos, "blk");
        char want[512];
        snprintf(want, sizeof(want), "%s/blocks/blk00049.dat", tmpdir);
        if (strcmp(path, want) != 0) {
            printf("FAIL (good datadir changed: %s != %s)\n", path, want);
            failures++;
            goto _test_next;
        }
        get_block_pos_filename(path, sizeof(path), "/tmp/zcl\xc3\xa9", &pos,
                               "blk");
        if (strcmp(path, "/tmp/zcl\xc3\xa9/blocks/blk00049.dat") != 0) {
            printf("FAIL (UTF-8 datadir refused: %s)\n", path);
            failures++;
            goto _test_next;
        }
        get_block_pos_filename(path, sizeof(path), "/tmp/zcl\tdata", &pos,
                               "blk");
        if (strcmp(path, "/tmp/zcl\tdata/blocks/blk00049.dat") != 0) {
            printf("FAIL (legal control byte changed: %s)\n", path);
            failures++;
            goto _test_next;
        }
        printf("OK\n");
    }
_test_next:
    cleanup_test_dir(tmpdir);
    return failures;
}

/* ── Boot scan flat-save gate ─────────────────────────────
 * Boot's post-scan save_block_index_flat runs only when boot mutated the
 * in-memory index (scan marked count or stale-HAVE_DATA cleared count): a
 * 0/0 boot must not rewrite block_index.bin, any nonzero count must save. */

/* Fill ms with n synthetic index entries (distinct hashes; none on disk). */
static bool seed_index_entries(struct main_state *ms, int n)
{
    for (int i = 0; i < n; i++) {
        struct uint256 h;
        memset(h.data, 0, sizeof(h.data));
        h.data[0] = (unsigned char)(i & 0xFF);
        h.data[1] = (unsigned char)((i >> 8) & 0xFF);
        h.data[2] = (unsigned char)((i >> 16) & 0xFF);
        h.data[31] = 0x9b;
        if (!chainstate_insert_block_index((struct chainstate *)ms, &h))
            return false;
    }
    return true;
}

static bool flat_save_exists(const char *datadir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/block_index.bin", datadir);
    struct stat st;
    return stat(path, &st) == 0;
}

static void make_gate_dir(char *buf, size_t len, int tag)
{
    snprintf(buf, len, "./test-tmp/%d_disk_io_gate%d", (int)getpid(), tag);
    mkdir("./test-tmp", 0755);
    mkdir(buf, 0755);
    char blocks[512];
    snprintf(blocks, sizeof(blocks), "%s/blocks", buf);
    mkdir(blocks, 0755);
}

static int test_flat_save_gate_skips_when_quiet(void)
{
    int failures = 0;
    char tmpdir[256];
    make_gate_dir(tmpdir, sizeof(tmpdir), 1);

    /* marked==0 && cleared==0 (nothing on disk to mark, nothing cleared):
     * the flat cache must NOT be rewritten. */
    TEST("boot scan flat-save gate: 0 marked + 0 cleared skips the save") {
        struct main_state ms;
        main_state_init(&ms);
        ASSERT(seed_index_entries(&ms, 1100));
        int marked = scan_block_files_mark_data(&ms, tmpdir, NULL);
        ASSERT(marked == 0);
        save_block_index_flat_if_mutated(tmpdir, &ms, marked, 0);
        ASSERT(!flat_save_exists(tmpdir));
        main_state_free(&ms);
        printf("OK\n");
    }
_test_next:
    cleanup_test_dir(tmpdir);
    return failures;
}

static int test_flat_save_gate_saves_on_cleared(void)
{
    int failures = 0;
    char tmpdir[256];
    make_gate_dir(tmpdir, sizeof(tmpdir), 2);

    /* cleared>0 (the stale-HAVE_DATA clear step ran): the mutation MUST be
     * persisted even when the scan itself marked nothing. */
    TEST("boot scan flat-save gate: cleared > 0 saves") {
        struct main_state ms;
        main_state_init(&ms);
        ASSERT(seed_index_entries(&ms, 1100));
        int marked = scan_block_files_mark_data(&ms, tmpdir, NULL);
        ASSERT(marked == 0);
        save_block_index_flat_if_mutated(tmpdir, &ms, marked, 3);
        ASSERT(flat_save_exists(tmpdir));
        main_state_free(&ms);
        printf("OK\n");
    }
_test_next:
    cleanup_test_dir(tmpdir);
    return failures;
}

static int test_flat_save_gate_saves_on_marked(void)
{
    int failures = 0;
    char tmpdir[256];
    make_gate_dir(tmpdir, sizeof(tmpdir), 3);

    /* marked>0 (a real on-disk block matched an index entry): MUST save. */
    TEST("boot scan flat-save gate: marked > 0 saves") {
        struct block b;
        build_test_block(&b, 777777);
        struct disk_block_pos pb;
        disk_block_pos_init(&pb);
        bool ok = write_block_to_disk(&b, &pb, tmpdir, TEST_MSG_START);
        struct uint256 hash_b;
        block_get_hash(&b, &hash_b);
        block_free(&b);
        ASSERT(ok);

        struct main_state ms;
        main_state_init(&ms);
        ASSERT(seed_index_entries(&ms, 1100));
        struct block_index *bi = chainstate_insert_block_index(
            (struct chainstate *)&ms, &hash_b);
        ASSERT(bi != NULL);
        int marked = scan_block_files_mark_data(&ms, tmpdir, NULL);
        ASSERT(marked > 0);
        save_block_index_flat_if_mutated(tmpdir, &ms, marked, 0);
        ASSERT(bi->nStatus & BLOCK_HAVE_DATA);
        ASSERT(flat_save_exists(tmpdir));
        main_state_free(&ms);
        printf("OK\n");
    }
_test_next:
    cleanup_test_dir(tmpdir);
    return failures;
}

/* ── Entry point ─────────────────────────────────────────── */

#if !defined(_WIN32)
static long dbio_fixture_bytes(const char *path, unsigned char *buf, size_t cap)
{
    FILE *file = fopen(path, "rb");
    if (!file) {
        fprintf(stderr, "disk block fixture: cannot read %s\n", path);
        return -1;
    }
    size_t n = fread(buf, 1, cap, file);
    bool ok = feof(file) && !ferror(file);
    if (fclose(file) != 0) ok = false;
    if (!ok) fprintf(stderr, "disk block fixture: incomplete read of %s\n", path);
    return ok ? (long)n : -1;
}

static int test_open_error_preserves_frames(int error)
{
    int failures = 0;
    char tmpdir[256], path[512];
    unsigned char before[8192], after[8192];
    make_test_dir(tmpdir, sizeof(tmpdir));
    struct disk_block_pos pos = {.nFile = 1, .nPos = 0};
    get_block_pos_filename(path, sizeof(path), tmpdir, &pos, "blk");
    TEST(error == EIO ? "block open: EIO preserves frames" :
                       "block open: EINTR preserves frames") {
        ASSERT(write_test_block(tmpdir, &pos, 100));
        long first = dbio_fixture_bytes(path, before, sizeof(before));
        ASSERT(first > 0);
        pos.nPos = (uint32_t)first;
        ASSERT(write_test_block(tmpdir, &pos, 200));
        long size = dbio_fixture_bytes(path, before, sizeof(before));
        ASSERT(size > first);
        pos.nPos = 0;
        dbio_fault_path = path;
        dbio_open_error = error;
        dbio_open_hits = 0;
        FILE *file = open_block_file(tmpdir, &pos, false);
        dbio_fault_path = NULL;
        dbio_open_error = 0;
        bool refused = file == NULL;
        if (file) fclose(file);
        ASSERT(dbio_open_hits == 1);
        ASSERT(refused);
        ASSERT(dbio_fixture_bytes(path, after, sizeof(after)) == size);
        ASSERT(memcmp(before, after, (size_t)size) == 0);
        printf("OK\n");
    }
_test_next:
    cleanup_test_dir(tmpdir);
    return failures;
}
#endif

static int test_open_missing_file(void)
{
    int failures = 0;
    char tmpdir[256], path[512];
    make_test_dir(tmpdir, sizeof(tmpdir));
    struct disk_block_pos pos = {.nFile = 1, .nPos = 0};
    get_block_pos_filename(path, sizeof(path), tmpdir, &pos, "blk");
    TEST("block open: absent file creates only for writing") {
        disk_block_io_close_cache();
        ASSERT(open_block_file(tmpdir, &pos, true) == NULL);
        ASSERT(access(path, F_OK) == -1 && errno == ENOENT);
        FILE *file = open_block_file(tmpdir, &pos, false);
        ASSERT(file != NULL);
        ASSERT(fclose(file) == 0);
        ASSERT(access(path, F_OK) == 0);
        printf("OK\n");
    }
_test_next:
    disk_block_io_close_cache();
    cleanup_test_dir(tmpdir);
    return failures;
}

int test_disk_block_io(void)
{
    printf("\n=== disk_block_io (pread thread safety) ===\n");
    int failures = 0;
    failures += test_open_missing_file();
#if !defined(_WIN32)
    failures += test_open_error_preserves_frames(EIO);
    failures += test_open_error_preserves_frames(EINTR);
#endif
    failures += test_pread_basic_read();
    failures += test_pread_matches_fread();
    failures += test_concurrent_reads();
    failures += test_concurrent_pread_same_file();
    failures += test_disk_block_pread_raw();
    failures += test_pread_accepts_frame_offset();
    failures += test_pread_refuses_unframed_position();
    failures += test_set_have_data_verified();
#if !defined(_WIN32)
    failures += test_have_data_hook_quiesce_drains_inflight();
#endif
    failures += test_write_allocates_append_position();
    failures += test_append_quarantines_hardlinked_tail();
    failures += test_explicit_write_refuses_hardlinked_file();
    failures += test_deferred_sync_byte_identical();
    failures += test_scoped_read_fd_cache();
    failures += test_scan_duplicate_keeps_earliest_copy();
    failures += test_position_repair_from_local_copy();
    failures += test_block_pos_filename_datadir_contract();
    failures += test_flat_save_gate_skips_when_quiet();
    failures += test_flat_save_gate_saves_on_cleared();
    failures += test_flat_save_gate_saves_on_marked();
    return failures;
}
