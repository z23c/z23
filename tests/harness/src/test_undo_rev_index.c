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

#include "base/serialize_le.h"
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
static bool make_payload(int64_t value, size_t nprev, struct byte_stream *s)
{
    struct block_undo u;
    block_undo_init(&u);
    if (!block_undo_alloc(&u, 1) || !tx_undo_alloc(&u.vtxundo[0], nprev)) {
        block_undo_free(&u);
        return false;
    }
    for (size_t i = 0; i < nprev; i++) {
        struct tx_in_undo *in = &u.vtxundo[0].vprevout[i];
        in->txout.value = value;
        in->txout.script_pub_key.size = 3;
        memcpy(in->txout.script_pub_key.data, "\x51\x52\x53", 3);
    }
    u.old_sprout_tree_root = make_hash(0x5a);
    stream_init(s, 0);
    bool ok = block_undo_serialize(&u, s);
    block_undo_free(&u);
    return ok;
}

/* Append [magic][size][payload][checksum] to f; the checksum binds
 * `bind_parent`. Flaws are applied to the written bytes. */
static bool append_record(FILE *f, const struct uint256 *bind_parent,
                          int64_t value, size_t nprev, enum rev_flaw flaw)
{
    struct byte_stream s;
    if (!make_payload(value, nprev, &s))
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
    zcl_write_u32_le(head + 4, (uint32_t)n);
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
    bool wrote = f && append_record(f, bind, 4242, 1, flaw);
    if (f)
        fclose(f);
    struct undo_rev_locator loc;
    struct block_undo u;
    if (wrote && undo_rev_locator_init(&loc, dir, TEST_MAGIC)) {
        st = undo_rev_locator_read(&loc, want, 0, NULL, NULL, &u);
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
        ? undo_rev_locator_read(&loc, &pa, -1, NULL, NULL, &u) : UNDO_REV_ERROR;
    if (init)
        undo_rev_locator_free(&loc);
    remove_datadir(dir);
    return check(st == UNDO_REV_NO_FILE, "missing rev file is reported cleanly");
}

/* Prevout value of the undo found for `p`, or -1 when nothing is found. */
static int64_t found_value(struct undo_rev_locator *loc,
                           const struct uint256 *p, int hint)
{
    struct block_undo u;
    if (undo_rev_locator_read(loc, p, hint, NULL, NULL, &u) != UNDO_REV_FOUND)
        return -1;
    int64_t v = u.vtxundo[0].vprevout[0].txout.value;
    block_undo_free(&u);
    return v;
}

/* p1,p2 in rev00000 and p3 in rev00001. */
static bool write_two_files(const char *dir, const struct uint256 *p1,
                            const struct uint256 *p2, const struct uint256 *p3)
{
    FILE *f0 = open_rev(dir, 0);
    FILE *f1 = open_rev(dir, 1);
    bool wrote = f0 && f1 && append_record(f0, p1, 1, 1, FLAW_NONE) &&
                 append_record(f0, p2, 2, 1, FLAW_NONE) &&
                 append_record(f1, p3, 3, 1, FLAW_NONE);
    if (f0)
        fclose(f0);
    if (f1)
        fclose(f1);
    return wrote;
}

/* A wrong hint still finds p3; on a fresh locator p2 is then reached from the
 * cursor after p1 (cursor_slot 2). */
static int test_hint_and_cursor(void)
{
    char dir[512];
    if (!make_datadir(dir, sizeof(dir)))
        return check(false, "hint: temp datadir");
    struct uint256 p1 = make_hash(1), p2 = make_hash(2), p3 = make_hash(3);
    struct undo_rev_locator loc;
    bool ok = write_two_files(dir, &p1, &p2, &p3) &&
              undo_rev_locator_init(&loc, dir, TEST_MAGIC);
    if (ok) {
        ok = found_value(&loc, &p3, 0) == 3;
        undo_rev_locator_free(&loc);
        ok = ok && undo_rev_locator_init(&loc, dir, TEST_MAGIC);
    }
    if (ok) {
        ok = found_value(&loc, &p1, -1) == 1 &&
             found_value(&loc, &p2, -1) == 2 && loc.cursor_slot == 2;
        undo_rev_locator_free(&loc);
    }
    remove_datadir(dir);
    return check(ok, "wrong hint and sequential cursor find records");
}

/* Shape check standing in for the verifier's: this "block" has one tx with
 * two inputs. */
static bool two_input_shape(const struct block_undo *u, void *ctx)
{
    (void)ctx;
    return u->num_txundo == 1 && u->vtxundo[0].num_prevout == 2;
}

/* Two records bind parent p: a one-input sibling and a two-input one, in the
 * given order (value 11 for the sibling, 22 for the right one). */
static enum undo_rev_status read_siblings(size_t first_nprev, size_t second_nprev,
                                          int64_t *value)
{
    char dir[512];
    enum undo_rev_status st = UNDO_REV_ERROR;
    if (!make_datadir(dir, sizeof(dir)))
        return st;
    struct uint256 p = make_hash(0x33);
    FILE *f = open_rev(dir, 0);
    bool wrote = f && append_record(f, &p, first_nprev == 1 ? 11 : 22,
                                    first_nprev, FLAW_NONE) &&
                 append_record(f, &p, second_nprev == 1 ? 11 : 22,
                               second_nprev, FLAW_NONE);
    if (f)
        fclose(f);
    struct undo_rev_locator loc;
    struct block_undo u;
    if (wrote && undo_rev_locator_init(&loc, dir, TEST_MAGIC)) {
        st = undo_rev_locator_read(&loc, &p, 0, two_input_shape, NULL, &u);
        if (st == UNDO_REV_FOUND) {
            *value = u.vtxundo[0].vprevout[0].txout.value;
            block_undo_free(&u);
        }
        undo_rev_locator_free(&loc);
    }
    remove_datadir(dir);
    return st;
}

static int test_fork_siblings(void)
{
    int failures = 0;
    int64_t v = 0;
    failures += check(read_siblings(1, 2, &v) == UNDO_REV_FOUND && v == 22,
                      "wrong-shape sibling first: the right-shape record wins");
    v = 0;
    failures += check(read_siblings(2, 1, &v) == UNDO_REV_FOUND && v == 22,
                      "wrong-shape sibling second: the right-shape record wins");
    failures += check(read_siblings(2, 2, &v) == UNDO_REV_AMBIGUOUS,
                      "two same-parent same-shape records: ambiguous, none used");
    return failures;
}

/* Three lookups for absent blocks must not switch the scan off. */
static int test_misses_do_not_disable(void)
{
    char dir[512];
    if (!make_datadir(dir, sizeof(dir)))
        return check(false, "misses: temp datadir");
    struct uint256 p = make_hash(0x44);
    FILE *f = open_rev(dir, 0);
    bool wrote = f && append_record(f, &p, 9, 1, FLAW_NONE);
    if (f)
        fclose(f);
    struct undo_rev_locator loc;
    bool ok = wrote && undo_rev_locator_init(&loc, dir, TEST_MAGIC);
    if (ok) {
        for (unsigned char i = 1; i <= 3; i++) {
            struct uint256 absent = make_hash((unsigned char)(0xa0 + i));
            ok = ok && found_value(&loc, &absent, -1) == -1;
        }
        ok = ok && found_value(&loc, &p, -1) == 9;
        undo_rev_locator_free(&loc);
    }
    remove_datadir(dir);
    return check(ok, "present block is found after three absent-block misses");
}

int test_undo_rev_index(void)
{
    printf("\n=== undo rev index ===\n");
    int failures = 0;
    failures += test_good_and_rejected();
    failures += test_missing_file();
    failures += test_hint_and_cursor();
    failures += test_fork_siblings();
    failures += test_misses_do_not_disable();
    return failures;
}
