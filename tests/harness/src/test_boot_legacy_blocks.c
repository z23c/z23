/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "test/test_core.h"

#include "config/boot_legacy_blocks.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BLB_CHECK(name, expr) do {                                      \
    printf("boot_legacy_blocks: %s... ", (name));                     \
    if (expr) printf("OK\n");                                         \
    else { printf("FAIL\n"); failures++; }                            \
} while (0)

static bool blb_mkdir(const char *path)
{
    return mkdir(path, 0700) == 0 || errno == EEXIST;
}

static bool blb_write_file(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    if (text && fputs(text, f) < 0) {
        fclose(f);
        return false;
    }
    return fclose(f) == 0;
}

static bool blb_make_blocks_dirs(const char *root,
                                 char *legacy_blocks,
                                 size_t legacy_blocks_n,
                                 char *datadir,
                                 size_t datadir_n)
{
    char legacy_root[512];
    char dest_blocks[512];
    int n1 = snprintf(legacy_root, sizeof(legacy_root), "%s/legacy", root);
    int n2 = snprintf(legacy_blocks, legacy_blocks_n,
                      "%s/legacy/blocks", root);
    int n3 = snprintf(datadir, datadir_n, "%s/c23", root);
    int n4 = snprintf(dest_blocks, sizeof(dest_blocks), "%s/c23/blocks",
                      root);
    if (n1 < 0 || (size_t)n1 >= sizeof(legacy_root) ||
        n2 < 0 || (size_t)n2 >= legacy_blocks_n ||
        n3 < 0 || (size_t)n3 >= datadir_n ||
        n4 < 0 || (size_t)n4 >= sizeof(dest_blocks))
        return false;
    return blb_mkdir(legacy_root) &&
           blb_mkdir(legacy_blocks) &&
           blb_mkdir(datadir) &&
           blb_mkdir(dest_blocks);
}

static bool blb_path(char *out, size_t out_n, const char *dir,
                     const char *name)
{
    int n = snprintf(out, out_n, "%s/%s", dir, name);
    return n >= 0 && (size_t)n < out_n;
}

struct blb_stage {
    char root[256];
    char legacy_blocks[512];
    char datadir[512];
    char p[512];
    char dest_blk[512];
    char dest_rev[512];
};

static bool blb_stage_block_pair(struct blb_stage *s, const char *tag,
                                 const char *blk_text, bool seed_dest_blk)
{
    test_make_tmpdir(s->root, sizeof(s->root), "boot_legacy_blocks", tag);
    bool ok = blb_make_blocks_dirs(s->root, s->legacy_blocks,
                                   sizeof(s->legacy_blocks),
                                   s->datadir, sizeof(s->datadir));
    ok = ok && blb_path(s->p, sizeof(s->p), s->legacy_blocks,
                        "blk00000.dat") &&
         blb_write_file(s->p, blk_text);
    ok = ok && blb_path(s->p, sizeof(s->p), s->legacy_blocks,
                        "rev00000.dat") &&
         blb_write_file(s->p, "rev0");
    ok = ok && blb_path(s->dest_blk, sizeof(s->dest_blk), s->datadir,
                        "blocks/blk00000.dat");
    if (seed_dest_blk)
        ok = ok && blb_write_file(s->dest_blk, blk_text);
    ok = ok && blb_path(s->dest_rev, sizeof(s->dest_rev), s->datadir,
                        "blocks/rev00000.dat");
    return ok;
}

static bool blb_import_pair_reaches_dest(struct blb_stage *s)
{
    bool ok = blb_stage_block_pair(s, "import", "blk0", false);
    struct boot_legacy_block_file_import_result r =
        boot_legacy_import_block_files(s->legacy_blocks, s->datadir, 4);
    return ok && r.destination_ready && r.source_available &&
           !r.truncated_path && r.failures == 0 &&
           access(s->dest_blk, F_OK) == 0 &&
           access(s->dest_rev, F_OK) == 0;
}

static bool blb_import_pair_skips_existing_blk(struct blb_stage *s)
{
    bool ok = blb_stage_block_pair(s, "skip", "same", true);
    struct boot_legacy_block_file_import_result r =
        boot_legacy_import_block_files(s->legacy_blocks, s->datadir, 4);
    return ok && r.destination_ready && r.source_available &&
           r.failures == 0 && access(s->dest_blk, F_OK) == 0 &&
           access(s->dest_rev, F_OK) != 0;
}

static bool blb_link_pair_links_missing(struct blb_stage *s)
{
    bool ok = blb_stage_block_pair(s, "link", "blk0", false);
    struct boot_legacy_block_file_link_result r =
        boot_legacy_link_missing_block_files(s->legacy_blocks, s->datadir, 4);
    return ok && r.destination_ready && r.source_available &&
           !r.truncated_path && r.linked == 1 &&
           access(s->dest_blk, F_OK) == 0 &&
           access(s->dest_rev, F_OK) == 0;
}

int test_boot_legacy_blocks(void)
{
    int failures = 0;

    {
        struct blb_stage s;
        bool pass = blb_import_pair_reaches_dest(&s);
        BLB_CHECK("import links or copies blk and rev pair", pass);
        test_rm_rf_recursive(s.root);
    }

    {
        struct blb_stage s;
        bool pass = blb_import_pair_skips_existing_blk(&s);
        BLB_CHECK("existing same-size blk preserves legacy skip semantics",
                  pass);
        test_rm_rf_recursive(s.root);
    }

    {
        struct blb_stage s;
        bool pass = blb_link_pair_links_missing(&s);
        BLB_CHECK("warm helper links missing blk and rev files", pass);
        test_rm_rf_recursive(s.root);
    }

    {
        struct boot_legacy_block_file_import_result ir =
            boot_legacy_import_block_files("/tmp/legacy", NULL, 4);
        struct boot_legacy_block_file_link_result lr =
            boot_legacy_link_missing_block_files("/tmp/legacy", NULL, 4);
        BLB_CHECK("invalid datadir fails closed",
                  ir.truncated_path && !ir.destination_ready &&
                  lr.truncated_path && !lr.destination_ready);
    }

    return failures;
}
