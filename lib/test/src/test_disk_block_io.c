/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Tests for disk_block_io thread safety and pread correctness. */

#include "test/test_core.h"
#include "storage/disk_block_io.h"
#include "primitives/block.h"
#include "core/serialize.h"
#include "config/boot_internal.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

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
    (void)system(cmd);
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

/* A position carrying NO 8-byte magic+size frame at either pos-8 or pos is
 * refused outright — even when a bare, perfectly-parseable block payload sits
 * exactly there and hashes to the entry's own hash.
 *
 * Before the fix disk_block_locate_payload() fell through to "payload=nPos,
 * size=2000000, return true": a fixed 2 MB read from a raw offset handed
 * straight to block_deserialize. That made an unframed offset *answer* — a
 * guess dressed as a read, with only the downstream hash check between it and
 * a wrong block. On a real datadir (node1 2026-08-23: blk00050.dat hardlinked
 * into a foreign live writer's datadir which overwrote the indexed region) the
 * guess parsed arbitrary bytes and produced ~52% of the node's log volume.
 * Every writer in the tree frames its records and the sibling mmap reader
 * (blocks_mmap_reader.c bmr_get_payload) already refuses this shape; the pread
 * reader now agrees. */
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

        /* Hand-write blk00000.dat: 16 filler bytes (0x5a5a5a5a is none of
         * the three accepted magics), then the RAW block payload with no
         * magic+size frame in front of it. */
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

        /* The payload starts at 16, so a naive raw-offset read WOULD parse
         * it. Neither 8..15 nor 16..23 is a frame header, so the position
         * names no record and must be refused. */
        struct disk_block_pos pos = { .nFile = 0, .nPos = 16 };
        struct block r;
        if (read_block_from_disk_pread(&r, &pos, tmpdir)) {
            printf("FAIL (unframed position answered: nTime=%u)\n",
                   r.header.nTime);
            block_free(&r);
            failures++;
            goto _test_next;
        }

        /* Same through the index-level reader: a HAVE_DATA entry pointing at
         * a frameless offset reports unreadable instead of feeding a guessed
         * parse into the hash check. */
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

/* Deferred-sync mode must produce a byte-identical block file to immediate
 * mode, must record a pending file (not fdatasync inline), and the file must
 * be readable back both before and after disk_block_io_sync_pending(). This is
 * the "batch does not change WHAT is written, only WHEN it is synced" contract
 * plus the at-tip degrade-to-identical guarantee. */
static int test_deferred_sync_byte_identical(void)
{
    int failures = 0;
    char dir_immediate[256], dir_deferred[256];
    snprintf(dir_immediate, sizeof(dir_immediate),
             "./test-tmp/%d_disk_io_imm", (int)getpid());
    snprintf(dir_deferred, sizeof(dir_deferred),
             "./test-tmp/%d_disk_io_def", (int)getpid());
    mkdir("./test-tmp", 0755);
    for (int i = 0; i < 2; i++) {
        const char *d = i == 0 ? dir_immediate : dir_deferred;
        char blocks[512];
        mkdir(d, 0755);
        snprintf(blocks, sizeof(blocks), "%s/blocks", d);
        mkdir(blocks, 0755);
    }

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
        bool identical = (ni > 0 && ni == nd && bi && bd &&
                          memcmp(bi, bd, (size_t)ni) == 0);
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

/* Between enter() and exit() the reader reuses one fd across same-file reads.
 * Interleaving two blocks in the SAME blk file at different offsets must still
 * return each block's own bytes (pread is positional); after exit() the fd is
 * closed and the stateless path resumes. */
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
 * Regression coverage for the 2026-08 producer-fold wedge: blk*.dat files
 * hardlinked into a live zclassicd datadir get their tail rewritten by the
 * foreign appender, so (1) the boot scan must index the EARLIEST copy of a
 * duplicated block (most durable offset), and (2) a position that dangles
 * anyway must be repairable from the surviving local copy. */

/* A blk file holding TWO verbatim copies of the same block must index the
 * earliest one; after the tail copy is destroyed, the indexed copy must
 * still read back and hash-match. */
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
 * by a hash-targeted blk-file scan + verified re-store; a hash with NO copy
 * on disk returns false and leaves the entry untouched, so the caller's
 * clear-and-hold fallback still applies. */
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
         * HAVE_DATA set (the real wedge shape — read paths only fire on
         * flagged entries, and the position snapshot requires the flag). */
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

/* ── Entry point ─────────────────────────────────────────── */

int test_disk_block_io(void)
{
    printf("\n=== disk_block_io (pread thread safety) ===\n");
    int failures = 0;
    failures += test_pread_basic_read();
    failures += test_pread_matches_fread();
    failures += test_concurrent_reads();
    failures += test_concurrent_pread_same_file();
    failures += test_disk_block_pread_raw();
    failures += test_pread_accepts_frame_offset();
    failures += test_pread_refuses_unframed_position();
    failures += test_set_have_data_verified();
    failures += test_write_allocates_append_position();
    failures += test_deferred_sync_byte_identical();
    failures += test_scoped_read_fd_cache();
    failures += test_scan_duplicate_keeps_earliest_copy();
    failures += test_position_repair_from_local_copy();
    return failures;
}
