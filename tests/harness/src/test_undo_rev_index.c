/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_undo_rev_index — the rev-file undo locator accepts a record only when
 * its checksum binds the block's PARENT hash and the undo deserializer takes
 * the whole payload. Synthetic rev files in a temp datadir:
 *   - a good record is found (also through a wrong hint and a cursor step);
 *   - a flipped checksum byte, a truncated tail and a checksum bound to a
 *     different parent are rejected;
 *   - a datadir with no rev file is reported as UNDO_REV_NO_FILE. */

#include "test/test_core.h"

#include "coins/undo.h"
#include "core/hash.h"
#include "core/serialize.h"
#include "services/undo_rev_index.h"
#include "util/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const unsigned char TEST_MAGIC[UNDO_REV_MAGIC_SIZE] = { 0x24, 0xe9, 0x27, 0x64 };

enum rev_flaw { FLAW_NONE, FLAW_FLIP_CHECKSUM, FLAW_TRUNCATE, FLAW_OTHER_PARENT };

static struct uint256 make_hash(unsigned char seed)
{
    struct uint256 h;
    memset(h.data, seed, sizeof(h.data));
    return h;
}

/* One-input undo whose prevout value is `value`. */
static bool make_payload(int64_t value, struct byte_stream *s)
{
    struct block_undo u;
    block_undo_init(&u);
    if (!block_undo_alloc(&u, 1) || !tx_undo_alloc(&u.vtxundo[0], 1)) {
        block_undo_free(&u);
        return false;
    }
    struct tx_in_undo *in = &u.vtxundo[0].vprevout[0];
    in->txout.value = value;
    in->txout.script_pub_key.size = 3;
    memcpy(in->txout.script_pub_key.data, "\x51\x52\x53", 3);
    u.old_sprout_tree_root = make_hash(0x5a);
    stream_init(s, 0);
    bool ok = block_undo_serialize(&u, s);
    block_undo_free(&u);
    return ok;
}

static void put_le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16); p[3] = (unsigned char)(v >> 24);
}

/* Append [magic][size][payload][checksum] to f; the checksum binds
 * `bind_parent`. Flaws are applied to the written bytes. */
static bool append_record(FILE *f, const struct uint256 *bind_parent,
                          int64_t value, enum rev_flaw flaw)
{
    struct byte_stream s;
    if (!make_payload(value, &s))
        return false;
    size_t n = s.size;
    unsigned char *hb = zcl_malloc(32 + n, "test undo hash buf");
    if (!hb) { stream_free(&s); return false; }
    memcpy(hb, bind_parent->data, 32);
    memcpy(hb + 32, s.data, n);
    unsigned char sum[SHA256_OUTPUT_SIZE];
    hash256(hb, 32 + n, sum);
    if (flaw == FLAW_FLIP_CHECKSUM)
        sum[7] ^= 0x01;
    unsigned char head[8];
    memcpy(head, TEST_MAGIC, 4);
    put_le32(head + 4, (uint32_t)n);
    size_t keep = flaw == FLAW_TRUNCATE ? sizeof(sum) - 10 : sizeof(sum);
    bool ok = fwrite(head, 1, 8, f) == 8 && fwrite(s.data, 1, n, f) == n &&
              fwrite(sum, 1, keep, f) == keep;
    free(hb);
    stream_free(&s);
    return ok;
}

static bool make_datadir(char *dir, size_t len)
{
    if (!test_mkdtemp(dir, len, "undo_rev"))
        return false;
    char blocks[600];
    snprintf(blocks, sizeof(blocks), "%s/blocks", dir);
    return mkdir(blocks, 0700) == 0;
}

static FILE *open_rev(const char *dir, int n)
{
    char path[600];
    snprintf(path, sizeof(path), "%s/blocks/rev%05d.dat", dir, n);
    return fopen(path, "wb");
}

static void remove_datadir(const char *dir)
{
    char path[600];
    for (int n = 0; n < 3; n++) {
        snprintf(path, sizeof(path), "%s/blocks/rev%05d.dat", dir, n);
        (void)unlink(path);
    }
    snprintf(path, sizeof(path), "%s/blocks", dir);
    (void)rmdir(path);
    (void)rmdir(dir);
}

/* Single-file datadir holding one record bound to `bind`, read for `want`. */
static enum undo_rev_status read_one(const struct uint256 *bind,
                                     const struct uint256 *want,
                                     enum rev_flaw flaw, int64_t *value)
{
    char dir[512];
    enum undo_rev_status st = UNDO_REV_ERROR;
    if (!make_datadir(dir, sizeof(dir)))
        return st;
    FILE *f = open_rev(dir, 0);
    bool wrote = f && append_record(f, bind, 4242, flaw);
    if (f)
        fclose(f);
    struct undo_rev_locator loc;
    struct block_undo u;
    if (wrote && undo_rev_locator_init(&loc, dir, TEST_MAGIC)) {
        st = undo_rev_locator_read(&loc, want, 0, &u);
        if (st == UNDO_REV_FOUND) {
            *value = u.vtxundo[0].vprevout[0].txout.value;
            block_undo_free(&u);
        }
        undo_rev_locator_free(&loc);
    }
    remove_datadir(dir);
    return st;
}

static int check(bool ok, const char *name)
{
    printf("undo_rev_index: %s... %s\n", name, ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

static int test_good_and_rejected(void)
{
    int failures = 0;
    struct uint256 pa = make_hash(0x11), px = make_hash(0x99);
    int64_t v = 0;
    failures += check(read_one(&pa, &pa, FLAW_NONE, &v) == UNDO_REV_FOUND &&
                      v == 4242, "good record is found");
    failures += check(read_one(&pa, &pa, FLAW_FLIP_CHECKSUM, &v) ==
                      UNDO_REV_NOT_FOUND, "flipped checksum byte is rejected");
    failures += check(read_one(&pa, &pa, FLAW_TRUNCATE, &v) ==
                      UNDO_REV_NOT_FOUND, "truncated tail is rejected");
    failures += check(read_one(&px, &pa, FLAW_NONE, &v) ==
                      UNDO_REV_NOT_FOUND,
                      "record bound to a different parent is rejected");
    return failures;
}

static int test_missing_file(void)
{
    char dir[512];
    if (!make_datadir(dir, sizeof(dir)))
        return check(false, "missing file: temp datadir");
    struct undo_rev_locator loc;
    struct block_undo u;
    struct uint256 pa = make_hash(0x11);
    bool init = undo_rev_locator_init(&loc, dir, TEST_MAGIC);
    enum undo_rev_status st = init
        ? undo_rev_locator_read(&loc, &pa, -1, &u) : UNDO_REV_ERROR;
    if (init)
        undo_rev_locator_free(&loc);
    remove_datadir(dir);
    return check(st == UNDO_REV_NO_FILE, "missing rev file is reported cleanly");
}

/* Records for p1,p2 in rev00000 and p3 in rev00001: a wrong hint still
 * finds p3, and p2 is then reached from the cursor without a rescan. */
static int test_hint_and_cursor(void)
{
    char dir[512];
    if (!make_datadir(dir, sizeof(dir)))
        return check(false, "hint: temp datadir");
    struct uint256 p1 = make_hash(1), p2 = make_hash(2), p3 = make_hash(3);
    FILE *f0 = open_rev(dir, 0);
    FILE *f1 = open_rev(dir, 1);
    bool wrote = f0 && f1 && append_record(f0, &p1, 1, FLAW_NONE) &&
                 append_record(f0, &p2, 2, FLAW_NONE) &&
                 append_record(f1, &p3, 3, FLAW_NONE);
    if (f0) fclose(f0);
    if (f1) fclose(f1);
    struct undo_rev_locator loc;
    struct block_undo u;
    bool ok = wrote && undo_rev_locator_init(&loc, dir, TEST_MAGIC);
    if (ok) {
        ok = undo_rev_locator_read(&loc, &p3, 0, &u) == UNDO_REV_FOUND &&
             u.vtxundo[0].vprevout[0].txout.value == 3;
        block_undo_free(&u);
        undo_rev_locator_free(&loc);
        ok = ok && undo_rev_locator_init(&loc, dir, TEST_MAGIC);
    }
    if (ok) {
        ok = undo_rev_locator_read(&loc, &p1, -1, &u) == UNDO_REV_FOUND;
        block_undo_free(&u);
        ok = ok && undo_rev_locator_read(&loc, &p2, -1, &u) == UNDO_REV_FOUND &&
             u.vtxundo[0].vprevout[0].txout.value == 2 && loc.cursor_slot == 2;
        block_undo_free(&u);
        undo_rev_locator_free(&loc);
    }
    remove_datadir(dir);
    return check(ok, "wrong hint and sequential cursor find records");
}

int test_undo_rev_index(void)
{
    printf("\n=== undo rev index ===\n");
    int failures = 0;
    failures += test_good_and_rejected();
    failures += test_missing_file();
    failures += test_hint_and_cursor();
    return failures;
}
