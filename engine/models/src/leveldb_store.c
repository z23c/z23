/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "models/leveldb_store.h"
#include "models/leveldb_util.h"
#include "util/file_tree_ops.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

bool leveldb_store_validate(struct leveldb_store *store,
                             struct ar_errors *errors)
{
    ar_errors_clear(errors);
    store->num_sst_files = 0;
    store->total_bytes = 0;
    store->has_manifest = false;
    store->has_current = false;
    store->copy_ok = false;

    validates_string_present(errors, store->src_dir, "src_dir");
    validates_string_present(errors, store->dst_dir, "dst_dir");
    if (ar_errors_any(errors))
        return false;

    struct stat st;
    validates_custom(errors,
                     stat(store->src_dir, &st) == 0 && S_ISDIR(st.st_mode),
                     "src_dir", "is not a directory");
    if (ar_errors_any(errors))
        return false;

    scan_leveldb_dir(store->src_dir, &store->num_sst_files,
                     &store->total_bytes, &store->has_manifest,
                     &store->has_current);

    validates_custom(errors, store->has_manifest,
                     "has_manifest", "MANIFEST file required");
    validates_custom(errors, store->has_current,
                     "has_current", "CURRENT file required");
    validates_custom(errors,
                     store->num_sst_files > 0 || store->total_bytes > 0,
                     "total_bytes", "must be positive");

    return !ar_errors_any(errors);
}

bool leveldb_store_save(struct leveldb_store *store)
{
    store->copy_ok = false;
    const char *lbl = store->label ? store->label : "leveldb_store";

    printf("%s: clean copy (%d SST files, %.1f MB)...\n",
           lbl, store->num_sst_files,
           (double)store->total_bytes / (1024.0 * 1024.0));
    fflush(stdout);

    /* `rm -rf dst && mkdir -p dst && cp -a src/. dst/` — a clean full copy
     * of the LevelDB directory, via the single fd-based walker. Removing dst
     * first, then copying src→dst fresh, is equivalent to the shell form
     * (dst did not exist, so cp -a src/. dst/ == cp -a src dst) and yields
     * real error returns instead of the old `2>/dev/null`-silenced code. */
    struct zcl_result rrm = zcl_tree_remove(store->dst_dir);
    if (!rrm.ok) {
        LOG_WARN(lbl, "clean copy: could not remove dst %s: %s",
                 store->dst_dir, rrm.message);
        store->copy_ok = false;
        return false;
    }
    struct zcl_result rcp = zcl_tree_copy(store->src_dir, store->dst_dir,
                                          ZCL_COPY_PRESERVE_TIMES, NULL, NULL);
    if (!rcp.ok)
        LOG_WARN(lbl, "clean copy failed: %s", rcp.message);
    store->copy_ok = rcp.ok;
    return store->copy_ok;
}

