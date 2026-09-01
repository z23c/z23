/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "chain/chain.h"
#include "config/boot.h"
#include "core/amount.h"
#include "core/uint256.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "storage/disk_block_io.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define BSD_CHECK(name, expr) do {                                      \
    printf("boot_snapshot_drop_bodiless: %s... ", (name));             \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static void bsd_hash_for(int h, struct uint256 *out)
{
    memset(out->data, 0, sizeof(out->data));
    out->data[0] = (uint8_t)(h & 0xff);
    out->data[1] = (uint8_t)((h >> 8) & 0xff);
    out->data[31] = 0x5d;
}

static struct block_index *bsd_insert(struct main_state *ms, int h,
                                      unsigned int status, int nfile,
                                      unsigned int npos, unsigned int ntx)
{
    struct uint256 hash;
    bsd_hash_for(h, &hash);
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, &hash);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->nStatus = status;
    bi->nFile = nfile;
    bi->nDataPos = npos;
    bi->nTx = ntx;
    return bi;
}

static struct block_index *bsd_insert_hash(struct main_state *ms, int h,
                                           const struct uint256 *hash,
                                           unsigned int status, int nfile,
                                           unsigned int npos, unsigned int ntx)
{
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = h;
    bi->nStatus = status;
    bi->nFile = nfile;
    bi->nDataPos = npos;
    bi->nTx = ntx;
    return bi;
}

static bool bsd_mkdir_blocks(const char *datadir)
{
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/blocks", datadir);
    return n > 0 && (size_t)n < sizeof(path) && mkdir(path, 0755) == 0;
}

static bool bsd_write_blk(const char *datadir, int nfile, bool nonempty)
{
    char path[512];
    int n = snprintf(path, sizeof(path), "%s/blocks/blk%05d.dat",
                     datadir, nfile);
    if (n <= 0 || (size_t)n >= sizeof(path))
        return false;
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    bool ok = true;
    if (nonempty) {
        const unsigned char byte = 0xaa;
        ok = fwrite(&byte, 1, 1, f) == 1;
    }
    ok = fclose(f) == 0 && ok;
    return ok;
}

static void bsd_build_block(struct block *b, uint32_t seed)
{
    block_init(b);
    b->header.nVersion = 4;
    b->header.nTime = seed;
    b->header.nBits = 0x2000ffff;
    b->header.nNonce.data[0] = (uint8_t)(seed & 0xff);
    b->header.nNonce.data[1] = (uint8_t)((seed >> 8) & 0xff);
    b->num_vtx = 1;
    b->vtx = calloc(1, sizeof(struct transaction)); // raw-alloc-ok:test-fixture
    if (!b->vtx)
        return;
    transaction_init(&b->vtx[0]);
    transaction_alloc(&b->vtx[0], 1, 1);
    b->vtx[0].vin[0].sequence = 0xffffffff;
    b->vtx[0].vout[0].value = (CAmount)seed * COIN;
}

static bool bsd_is_cleared(const struct block_index *bi)
{
    return bi &&
           !(bi->nStatus & BLOCK_HAVE_DATA) &&
           (bi->nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_TREE &&
           bi->nFile == -1 &&
           bi->nDataPos == 0 &&
           bi->nTx == 0;
}

int test_boot_snapshot_drop_bodiless(void)
{
    test_reset_shared_globals();
    int failures = 0;

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_drop", "missing");
        BSD_CHECK("missing: blocks dir created", bsd_mkdir_blocks(dir));

        struct main_state ms;
        main_state_init(&ms);
        const int seed_h = 10;
        struct block_index *below = bsd_insert(
            &ms, 9, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA, 1, 111, 3);
        struct block_index *seed = bsd_insert(
            &ms, 10, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA, 1, 222, 4);
        struct block_index *above = bsd_insert(
            &ms, 11, BLOCK_VALID_CHAIN | BLOCK_HAVE_DATA, 1, 333, 5);

        size_t cleared =
            boot_snapshot_drop_bodiless_have_data_above_seed_for_test(
                &ms, dir, seed_h, true);

        BSD_CHECK("missing: below+above bodiless entries cleared",
                  cleared == 2 && bsd_is_cleared(below) &&
                  bsd_is_cleared(above));
        BSD_CHECK("missing: seed block protected",
                  seed &&
                  (seed->nStatus & BLOCK_HAVE_DATA) &&
                  (seed->nStatus & BLOCK_VALID_MASK) == BLOCK_VALID_SCRIPTS &&
                  seed->nFile == 1 &&
                  seed->nDataPos == 222 &&
                  seed->nTx == 4);

        main_state_free(&ms);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_drop", "present");
        BSD_CHECK("present: blocks dir created", bsd_mkdir_blocks(dir));
        BSD_CHECK("present: non-empty blk file written",
                  bsd_write_blk(dir, 2, true));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *below = bsd_insert(
            &ms, 8, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA, 2, 444, 6);
        struct block_index *above = bsd_insert(
            &ms, 12, BLOCK_VALID_CHAIN | BLOCK_HAVE_DATA, 2, 555, 7);

        size_t cleared =
            boot_snapshot_drop_bodiless_have_data_above_seed_for_test(
                &ms, dir, 10, true);

        BSD_CHECK("present: real block bodies keep HAVE_DATA",
                  cleared == 0 &&
                  below && above &&
                  (below->nStatus & BLOCK_HAVE_DATA) &&
                  (above->nStatus & BLOCK_HAVE_DATA) &&
                  below->nFile == 2 && below->nDataPos == 444 &&
                  below->nTx == 6 &&
                  above->nFile == 2 && above->nDataPos == 555 &&
                  above->nTx == 7);

        main_state_free(&ms);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_drop", "absent");
        BSD_CHECK("absent: blocks dir created", bsd_mkdir_blocks(dir));
        BSD_CHECK("absent: zero-size blk file written",
                  bsd_write_blk(dir, 3, false));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *no_file_slot = bsd_insert(
            &ms, 7, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA, -1, 777, 8);
        struct block_index *zero_file = bsd_insert(
            &ms, 13, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA, 3, 888, 9);
        struct block_index *no_have_data = bsd_insert(
            &ms, 14, BLOCK_VALID_TREE, 3, 999, 10);

        size_t cleared =
            boot_snapshot_drop_bodiless_have_data_above_seed_for_test(
                &ms, dir, 10, true);

        BSD_CHECK("absent: nFile=-1 and empty blk file clear",
                  cleared == 2 &&
                  bsd_is_cleared(no_file_slot) &&
                  bsd_is_cleared(zero_file));
        BSD_CHECK("absent: header-only rows are ignored",
                  no_have_data &&
                  !(no_have_data->nStatus & BLOCK_HAVE_DATA) &&
                  (no_have_data->nStatus & BLOCK_VALID_MASK) ==
                      BLOCK_VALID_TREE &&
                  no_have_data->nFile == 3 &&
                  no_have_data->nDataPos == 999 &&
                  no_have_data->nTx == 10);

        main_state_free(&ms);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_drop", "untrusted");
        BSD_CHECK("untrusted: blocks dir created", bsd_mkdir_blocks(dir));
        BSD_CHECK("untrusted: bogus non-empty blk file written",
                  bsd_write_blk(dir, 4, true));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *bogus = bsd_insert(
            &ms, 12, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA, 4, 8, 1);

        size_t cleared =
            boot_snapshot_drop_bodiless_have_data_above_seed_for_test(
                &ms, dir, 10, false);

        BSD_CHECK("untrusted: non-empty but unreadable body clears",
                  cleared == 1 && bsd_is_cleared(bogus));

        main_state_free(&ms);
        test_rm_rf_recursive(dir);
    }

    {
        char dir[256];
        test_make_tmpdir(dir, sizeof(dir), "boot_snapshot_drop", "verified");
        BSD_CHECK("verified: blocks dir created", bsd_mkdir_blocks(dir));

        struct block blk;
        bsd_build_block(&blk, 0x23);
        struct uint256 hash;
        block_get_hash(&blk, &hash);
        unsigned char msg_start[4] = {0x24, 0xe9, 0x27, 0x64};
        struct disk_block_pos pos;
        disk_block_pos_init(&pos);
        BSD_CHECK("verified: real block body written",
                  write_block_to_disk(&blk, &pos, dir, msg_start));

        struct main_state ms;
        main_state_init(&ms);
        struct block_index *real = bsd_insert_hash(
            &ms, 12, &hash, BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA,
            pos.nFile, pos.nPos, 1);

        size_t cleared =
            boot_snapshot_drop_bodiless_have_data_above_seed_for_test(
                &ms, dir, 10, false);

        BSD_CHECK("verified: hash-readable body keeps HAVE_DATA",
                  cleared == 0 && real &&
                  (real->nStatus & BLOCK_HAVE_DATA) &&
                  real->nFile == pos.nFile &&
                  real->nDataPos == pos.nPos &&
                  real->nTx == 1);

        main_state_free(&ms);
        block_free(&blk);
        test_rm_rf_recursive(dir);
    }

    return failures;
}
