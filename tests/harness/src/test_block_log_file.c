/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * Tests for the file-backed block_log_port implementation.
 *
 * The adapter is exercised entirely through its public port surface
 * after construction — the test never touches block_log_file fields
 * directly. Each case uses a fresh mkdtemp() directory so test runs
 * are independent.
 *
 * Crash-simulation strategy: since we can't actually power-cut a
 * process from inside a test, we approximate the crash classes that
 * the open()-time recovery must handle by:
 *   (a) Appending normally, then truncating blocks.idx to its prior
 *       length to simulate "log fsynced, index not yet" — open()
 *       must rebuild the missing index entry.
 *   (b) Appending a fresh fully-formed record, then padding
 *       blocks.log with garbage past its true tail to simulate a
 *       torn record write — open() must truncate cleanly.
 */

#include "test/test_core.h"

#include "adapters/outbound/persistence/block_log_file.h"
#include "ports/block_log_port.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "test/setup_result.h"

#define BLF_CHECK(name, expr) do {                          \
    printf("block_log_file: %s... ", (name));               \
    if ((expr)) { printf("OK\n"); }                         \
    else { printf("FAIL\n"); failures++; }                  \
} while (0)

static void make_tmpdir(char *buf, size_t cap)
{
    snprintf(buf, cap, "/tmp/zcl_blf_XXXXXX");
    if (!mkdtemp(buf)) {
        perror("mkdtemp");
        buf[0] = '\0';
    }
}

static void fill_hash(struct block_hash *h, uint8_t seed)
{
    memset(h->bytes, 0, 32);
    h->bytes[0] = seed;
}

/* Iter callback: collect heights visited, comma-separated, into a
 * fixed buffer. Stops after 16 entries to bound buffer growth. */
struct iter_collect_state {
    char buf[256];
    size_t count;
};

static bool iter_collect(uint32_t height,
                         const struct block_hash *hash,
                         const uint8_t *bytes,
                         size_t len,
                         void *user_data)
{
    (void)hash; (void)bytes; (void)len;
    struct iter_collect_state *s = user_data;
    char tail[32];
    snprintf(tail, sizeof tail, "%s%u",
             s->count == 0 ? "" : ",", height);
    if (strlen(s->buf) + strlen(tail) + 1 < sizeof s->buf)
        strcat(s->buf, tail);
    s->count++;
    return s->count < 16;
}

int test_block_log_file(void)
{
    int failures = 0;

    /* ── 1. Empty log: tip = UINT32_MAX, read miss returns NOT_FOUND. */
    {
        char dir[64];
        make_tmpdir(dir, sizeof dir);
        struct block_log_file *h = NULL;
        struct block_log_port p = {0};
        struct zcl_result r = block_log_file_open(dir, &h, &p);
        BLF_CHECK("open empty -> OK", r.ok);
        BLF_CHECK("empty tip -> UINT32_MAX", p.tip_height(p.self) == UINT32_MAX);

        struct block_hash hash;
        fill_hash(&hash, 0xaa);
        const uint8_t *out = NULL;
        size_t outlen = 0;
        r = p.read_by_hash(p.self, &hash, &out, &outlen);
        BLF_CHECK("empty read_by_hash -> NOT_FOUND",
                  !r.ok && r.code == BLOCK_LOG_ERR_NOT_FOUND);

        block_log_file_close(h);
        test_rm_rf(dir);
    }

    /* ── 2. Append + read back. */
    {
        char dir[64]; make_tmpdir(dir, sizeof dir);
        struct block_log_file *h = NULL;
        struct block_log_port p = {0};
        struct zcl_result r = block_log_file_open(dir, &h, &p);
        BLF_CHECK("open -> OK (case 2)", r.ok);

        struct block_hash hash_a; fill_hash(&hash_a, 0xaa);
        uint8_t bytes_a[64];
        for (int i = 0; i < 64; i++) bytes_a[i] = (uint8_t)(0x40 + i);
        r = p.append(p.self, 0, &hash_a, bytes_a, sizeof bytes_a);
        BLF_CHECK("append -> OK", r.ok);

        const uint8_t *out = NULL; size_t outlen = 0;
        r = p.read_by_hash(p.self, &hash_a, &out, &outlen);
        BLF_CHECK("read_by_hash -> OK",
                  r.ok && outlen == sizeof bytes_a &&
                  memcmp(out, bytes_a, sizeof bytes_a) == 0);

        r = p.read_at_height(p.self, 0, &out, &outlen);
        BLF_CHECK("read_at_height(0) -> OK",
                  r.ok && outlen == sizeof bytes_a &&
                  memcmp(out, bytes_a, sizeof bytes_a) == 0);
        BLF_CHECK("tip_height after one append -> 0",
                  p.tip_height(p.self) == 0);

        block_log_file_close(h);
        test_rm_rf(dir);
    }

    /* ── 3. Idempotent re-append: same hash + same bytes -> OK. */
    {
        char dir[64]; make_tmpdir(dir, sizeof dir);
        struct block_log_file *h = NULL;
        struct block_log_port p = {0};
        ZCL_TEST_SETUP(block_log_file_open(dir, &h, &p));

        struct block_hash hash_a; fill_hash(&hash_a, 0xaa);
        static const uint8_t bytes_a[] = "hello block log!";
        ZCL_TEST_SETUP(p.append(p.self, 5, &hash_a, bytes_a,
                                sizeof bytes_a - 1));
        struct zcl_result r = p.append(p.self, 5, &hash_a, bytes_a,
                                        sizeof bytes_a - 1);
        BLF_CHECK("re-append same hash+bytes -> OK", r.ok);

        /* Different bytes for same hash -> CORRUPT. */
        static const uint8_t bytes_b[] = "DIFFERENT bytes!";
        r = p.append(p.self, 5, &hash_a, bytes_b, sizeof bytes_b - 1);
        BLF_CHECK("re-append same hash diff bytes -> ERR_CORRUPT",
                  !r.ok && r.code == BLOCK_LOG_ERR_CORRUPT);

        block_log_file_close(h);
        test_rm_rf(dir);
    }

    /* ── 4. Iteration order. */
    {
        char dir[64]; make_tmpdir(dir, sizeof dir);
        struct block_log_file *h = NULL;
        struct block_log_port p = {0};
        ZCL_TEST_SETUP(block_log_file_open(dir, &h, &p));

        struct block_hash ha, hb, hc;
        fill_hash(&ha, 1); fill_hash(&hb, 2); fill_hash(&hc, 3);
        uint8_t one[1] = {'a'}, two[1] = {'b'}, three[1] = {'c'};
        ZCL_TEST_SETUP(p.append(p.self, 0, &ha, one, 1));
        ZCL_TEST_SETUP(p.append(p.self, 1, &hb, two, 1));
        ZCL_TEST_SETUP(p.append(p.self, 2, &hc, three, 1));

        struct iter_collect_state st = {0};
        struct zcl_result r = p.iter_from(p.self, 1, iter_collect, &st);
        BLF_CHECK("iter_from(1) -> OK", r.ok);
        BLF_CHECK("iter_from(1) -> {1,2}",
                  strcmp(st.buf, "1,2") == 0);

        block_log_file_close(h);
        test_rm_rf(dir);
    }

    /* ── 5. Persistence across close/reopen. */
    {
        char dir[64]; make_tmpdir(dir, sizeof dir);
        struct block_log_file *h = NULL;
        struct block_log_port p = {0};
        ZCL_TEST_SETUP(block_log_file_open(dir, &h, &p));

        struct block_hash ha; fill_hash(&ha, 0x55);
        uint8_t buf[8] = {1,2,3,4,5,6,7,8};
        ZCL_TEST_SETUP(p.append(p.self, 42, &ha, buf, sizeof buf));
        block_log_file_close(h);

        h = NULL; memset(&p, 0, sizeof p);
        struct zcl_result r = block_log_file_open(dir, &h, &p);
        BLF_CHECK("reopen -> OK", r.ok);
        BLF_CHECK("tip persists after reopen", p.tip_height(p.self) == 42);
        const uint8_t *out = NULL; size_t outlen = 0;
        r = p.read_by_hash(p.self, &ha, &out, &outlen);
        BLF_CHECK("read after reopen -> bytes match",
                  r.ok && outlen == sizeof buf &&
                  memcmp(out, buf, sizeof buf) == 0);

        block_log_file_close(h);
        test_rm_rf(dir);
    }

    /* ── 6. Crash class A: log fsynced, index never written.
     * Approximated by truncating blocks.idx to length 0 and reopening
     * — the recovery scan must rebuild the index by walking blocks.log. */
    {
        char dir[64]; make_tmpdir(dir, sizeof dir);
        struct block_log_file *h = NULL;
        struct block_log_port p = {0};
        ZCL_TEST_SETUP(block_log_file_open(dir, &h, &p));

        struct block_hash ha; fill_hash(&ha, 0x77);
        static const uint8_t payload[] = "crashA-data!";
        ZCL_TEST_SETUP(p.append(p.self, 100, &ha, payload,
                                sizeof payload - 1));
        block_log_file_close(h);

        /* Wipe blocks.idx — simulates a power-cut between log fsync
         * and index fsync. */
        char idxpath[512];
        snprintf(idxpath, sizeof idxpath, "%s/blocks.idx", dir);
        int fd = open(idxpath, O_RDWR);
        ftruncate(fd, 0); close(fd);

        h = NULL; memset(&p, 0, sizeof p);
        struct zcl_result r = block_log_file_open(dir, &h, &p);
        BLF_CHECK("reopen after idx wipe -> OK", r.ok);
        const uint8_t *out = NULL; size_t outlen = 0;
        r = p.read_by_hash(p.self, &ha, &out, &outlen);
        BLF_CHECK("crashA: read_by_hash recovers via scan",
                  r.ok && outlen == sizeof payload - 1 &&
                  memcmp(out, payload, sizeof payload - 1) == 0);

        block_log_file_close(h);
        test_rm_rf(dir);
    }

    /* ── 7. Crash class B: torn log payload — extra garbage bytes
     * appended past the last complete record. Recovery must truncate
     * back to the last good record. */
    {
        char dir[64]; make_tmpdir(dir, sizeof dir);
        struct block_log_file *h = NULL;
        struct block_log_port p = {0};
        ZCL_TEST_SETUP(block_log_file_open(dir, &h, &p));

        struct block_hash ha; fill_hash(&ha, 0x99);
        uint8_t payload[5] = {9,9,9,9,9};
        ZCL_TEST_SETUP(p.append(p.self, 7, &ha, payload, sizeof payload));
        block_log_file_close(h);

        /* Append 3 garbage bytes — less than a header, so the open()
         * recovery should see "torn header" and truncate cleanly. */
        char logpath[512];
        snprintf(logpath, sizeof logpath, "%s/blocks.log", dir);
        int fd = open(logpath, O_RDWR | O_APPEND);
        uint8_t junk[3] = {0xff, 0xff, 0xff};
        (void)!write(fd, junk, sizeof junk);
        close(fd);

        h = NULL; memset(&p, 0, sizeof p);
        struct zcl_result r = block_log_file_open(dir, &h, &p);
        BLF_CHECK("reopen after torn header -> OK", r.ok);
        BLF_CHECK("crashB: tip still 7", p.tip_height(p.self) == 7);
        /* The original good record must still be readable. */
        const uint8_t *out = NULL; size_t outlen = 0;
        r = p.read_by_hash(p.self, &ha, &out, &outlen);
        BLF_CHECK("crashB: read good record",
                  r.ok && outlen == sizeof payload &&
                  memcmp(out, payload, sizeof payload) == 0);

        block_log_file_close(h);
        test_rm_rf(dir);
    }

    /* ── 8. Tip selection across multi-block append. */
    {
        char dir[64]; make_tmpdir(dir, sizeof dir);
        struct block_log_file *h = NULL;
        struct block_log_port p = {0};
        ZCL_TEST_SETUP(block_log_file_open(dir, &h, &p));

        struct block_hash hs[4];
        for (int i = 0; i < 4; i++) fill_hash(&hs[i], (uint8_t)(0xa0 + i));
        uint8_t blob[2] = {0xde, 0xad};

        /* Append out-of-order heights: 0, 2, 1, 3. tip_height must be 3. */
        ZCL_TEST_SETUP(p.append(p.self, 0, &hs[0], blob, sizeof blob));
        ZCL_TEST_SETUP(p.append(p.self, 2, &hs[1], blob, sizeof blob));
        ZCL_TEST_SETUP(p.append(p.self, 1, &hs[2], blob, sizeof blob));
        ZCL_TEST_SETUP(p.append(p.self, 3, &hs[3], blob, sizeof blob));
        BLF_CHECK("tip = max(height) across out-of-order appends",
                  p.tip_height(p.self) == 3);

        block_log_file_close(h);
        test_rm_rf(dir);
    }

    return failures + ZCL_TEST_SETUP_FAILURES();
}
