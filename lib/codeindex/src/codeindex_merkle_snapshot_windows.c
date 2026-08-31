/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Retained-handle Windows publication for sealed Merkle cache bytes. */

#include "codeindex_priv.h"

#if defined(_WIN32)

#include "platform/private_directory.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>

static _Atomic uint64_t g_merkle_snapshot_sequence = 1;

static bool snapshot_directory_path(const char *root, char out[CI_PATH_MAX])
{
    int n = snprintf(out, CI_PATH_MAX, "%s/.codeindex", root);
    return n > 0 && n < CI_PATH_MAX;
}

bool ci_merkle_snapshot_image_load_windows(
    const char *root, const char *leaf, size_t maximum,
    unsigned char **image_out, size_t *length_out, bool *found)
{
    if (image_out) *image_out = NULL;
    if (length_out) *length_out = 0;
    if (found) *found = false;
    if (!root || !leaf || !image_out || !length_out || !found)
        LOG_FAIL("codeindex", "invalid Windows Merkle snapshot load input");

    char path[CI_PATH_MAX];
    struct platform_directory_transaction directory;
    platform_directory_transaction_init(&directory);
    if (!snapshot_directory_path(root, path) ||
        !platform_directory_transaction_open(&directory, path))
        return true;
    struct platform_directory_child child;
    platform_directory_child_init(&child);
    enum platform_directory_result opened =
        platform_directory_child_open_result(&directory, leaf, false, true,
                                             &child, NULL);
    if (opened != PLATFORM_DIRECTORY_OK) {
        platform_directory_transaction_close(&directory);
        return true;
    }
    struct platform_directory_child_info info;
    bool valid = platform_directory_child_info(&child, &info) &&
                 info.size > 32 && info.size <= maximum &&
                 info.size <= SIZE_MAX && info.link_count == 1 &&
                 info.current_user_only;
    unsigned char *image = valid
        ? zcl_malloc((size_t)info.size, "ci_merkle_snapshot") : NULL;
    bool read_ok = valid && image && platform_directory_child_read_exact(
        &child, image, (size_t)info.size, 0);
    platform_directory_child_close(&child);
    platform_directory_transaction_close(&directory);
    if (!read_ok) { free(image); return true; }
    *image_out = image;
    *length_out = (size_t)info.size;
    *found = true;
    return true;
}

bool ci_merkle_snapshot_image_save_windows(
    const char *root, const char *leaf, const unsigned char *image,
    size_t length)
{
    if (!root || !leaf || !image || !length)
        LOG_FAIL("codeindex", "invalid Windows Merkle snapshot save input");
    char path[CI_PATH_MAX];
    struct platform_directory_transaction directory;
    platform_directory_transaction_init(&directory);
    if (!snapshot_directory_path(root, path) ||
        !platform_private_directory_ensure(path) ||
        !platform_directory_transaction_open(&directory, path))
        return false;

    struct platform_directory_child stage;
    platform_directory_child_init(&stage);
    char stage_name[128] = "";
    bool created = false;
    for (unsigned int attempt = 0; attempt < 32 && !created; attempt++) {
        uint64_t sequence = atomic_fetch_add_explicit(
            &g_merkle_snapshot_sequence, 1, memory_order_relaxed);
        int n = snprintf(stage_name, sizeof(stage_name), "%s.tmp.%llu", leaf,
                         (unsigned long long)sequence);
        if (n <= 0 || (size_t)n >= sizeof(stage_name)) break;
        created = platform_directory_child_create(&directory, stage_name,
                                                  &stage);
    }
    bool stage_named = created;
    bool ok = created && platform_directory_child_write_exact(
        &stage, image, length, 0) &&
        platform_directory_child_truncate(&stage, length) &&
        platform_directory_child_flush(&stage);
    struct platform_directory_child_info info;
    ok = ok && platform_directory_child_info(&stage, &info) &&
         info.size == length && info.link_count == 1 &&
         info.current_user_only;
    enum platform_directory_result published = PLATFORM_DIRECTORY_IO;
    if (ok)
        published = platform_directory_child_move_between(
            &directory, &stage, &directory, leaf, false);
    if (published == PLATFORM_DIRECTORY_OK ||
        published == PLATFORM_DIRECTORY_OUTCOME_UNKNOWN)
        stage_named = false;
    platform_directory_child_close(&stage);
    if (stage_named)
        (void)platform_directory_child_unlink(&directory, stage_name, true);
    platform_directory_transaction_close(&directory);
    return published == PLATFORM_DIRECTORY_OK;
}

bool ci_merkle_snapshot_image_forget_windows(const char *root,
                                             const char *leaf)
{
    if (!root || !leaf)
        LOG_FAIL("codeindex", "invalid Windows Merkle snapshot forget input");
    char path[CI_PATH_MAX];
    struct platform_directory_transaction directory;
    platform_directory_transaction_init(&directory);
    if (!snapshot_directory_path(root, path) ||
        !platform_directory_transaction_open(&directory, path))
        return true;
    bool ok = platform_directory_child_unlink(&directory, leaf, true);
    platform_directory_transaction_close(&directory);
    return ok;
}

#else
typedef int codeindex_merkle_snapshot_windows_not_built;
#endif
