/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "models/block_data.h"
#include "util/file_tree_ops.h"
#include "util/log_macros.h"
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* Glob-equivalent filter for the fd-based tree copy: selects only regular
 * files whose name matches `<prefix>*.dat` (i.e. "blk*.dat" / "rev*.dat"),
 * replacing the shell `cp -au 'src'/blk*.dat 'dst'/` glob without a shell.
 * ctx is a `const char *` prefix ("blk" or "rev"). */
static bool dat_glob_filter(const char *name, bool is_dir, void *ctx)
{
    if (is_dir || !name || !ctx)
        return false;
    const char *prefix = ctx;
    size_t pl = strlen(prefix);
    if (strncmp(name, prefix, pl) != 0)
        return false;
    size_t nl = strlen(name);
    return nl >= 4 && strcmp(name + nl - 4, ".dat") == 0;
}

static void count_dat_files(const char *dir, const char *prefix,
                            int *count, int64_t *bytes)
{
    *count = 0;
    *bytes = 0;
    DIR *d = opendir(dir);
    if (!d) return;

    size_t pfx_len = strlen(prefix);
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strncmp(ent->d_name, prefix, pfx_len) == 0 &&
            strstr(ent->d_name, ".dat")) {
            (*count)++;
            char path[1024];
            int written = snprintf(path, sizeof(path), "%s/%s",
                                   dir, ent->d_name);
            if (written < 0 || (size_t)written >= sizeof(path))
                continue;
            struct stat st;
            if (stat(path, &st) == 0)
                *bytes += st.st_size;
        }
    }
    closedir(d);
}

bool block_data_validate(struct block_data *bd, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    bd->num_blk_files = 0;
    bd->num_rev_files = 0;
    bd->blk_bytes = 0;
    bd->rev_bytes = 0;
    bd->copy_blk_ok = false;
    bd->copy_rev_ok = false;

    validates_string_present(errors, bd->src_dir, "src_dir");
    validates_string_present(errors, bd->dst_dir, "dst_dir");
    if (ar_errors_any(errors))
        return false;

    struct stat st;
    validates_custom(errors,
                     stat(bd->src_dir, &st) == 0 && S_ISDIR(st.st_mode),
                     "src_dir", "is not a directory");
    if (ar_errors_any(errors))
        return false;

    count_dat_files(bd->src_dir, "blk", &bd->num_blk_files, &bd->blk_bytes);
    count_dat_files(bd->src_dir, "rev", &bd->num_rev_files, &bd->rev_bytes);

    validates_positive(errors, bd, num_blk_files);

    return !ar_errors_any(errors);
}

bool block_data_save(struct block_data *bd)
{
    bd->copy_blk_ok = false;
    bd->copy_rev_ok = false;

    struct stat st;
    if (stat(bd->dst_dir, &st) != 0)
        mkdir(bd->dst_dir, 0700);

    /* `cp -au 'src'/blk*.dat 'dst'/` — copy newer-or-missing blk*.dat files,
     * preserving their timestamps (cp -a), via the single fd-based walker with
     * a glob-equivalent filter. No shell. */
    printf("block_data: copying %d blk files (%.1f GB)...\n",
           bd->num_blk_files,
           (double)bd->blk_bytes / (1024.0 * 1024.0 * 1024.0));
    fflush(stdout);
    struct zcl_result rb = zcl_tree_copy(
        bd->src_dir, bd->dst_dir,
        ZCL_COPY_UPDATE_ONLY | ZCL_COPY_PRESERVE_TIMES,
        dat_glob_filter, (void *)"blk");
    bd->copy_blk_ok = rb.ok;
    if (!rb.ok)
        LOG_WARN("block_data", "blk copy failed: %s", rb.message);

    if (bd->num_rev_files > 0) {
        printf("block_data: copying %d rev files...\n", bd->num_rev_files);
        fflush(stdout);
        struct zcl_result rr = zcl_tree_copy(
            bd->src_dir, bd->dst_dir,
            ZCL_COPY_UPDATE_ONLY | ZCL_COPY_PRESERVE_TIMES,
            dat_glob_filter, (void *)"rev");
        bd->copy_rev_ok = rr.ok;
        if (!rr.ok)
            LOG_WARN("block_data", "rev copy failed: %s", rr.message);
    } else {
        bd->copy_rev_ok = true;
    }

    return bd->copy_blk_ok;
}
