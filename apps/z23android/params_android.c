/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "params_android.h"
#include <android/log.h>
#include <fcntl.h>
#include <stdio.h>

#define TAG "z23"

/* An uncompressed asset is a byte range of the package, so a descriptor and its range replace a read. */
static struct zapp_params_fd open_asset(AAssetManager *assets, const char *name)
{
    struct zapp_params_fd out = {-1, 0, 0};
    char path[160];
    snprintf(path, sizeof(path), "%s/%s", ZAPP_PARAMS_DIR, name);
    AAsset *asset = AAssetManager_open(assets, path, AASSET_MODE_STREAMING);
    off64_t start = 0, size = 0;
    out.fd = asset ? AAsset_openFileDescriptor64(asset, &start, &size) : -1;
    if (asset) AAsset_close(asset);
    if (out.fd >= 0) fcntl(out.fd, F_SETFD, FD_CLOEXEC);   /* a node spawned during the copy must not inherit it */
    if (out.fd >= 0) { out.offset = (uint64_t)start; out.length = (uint64_t)size; }
    else __android_log_print(ANDROID_LOG_ERROR, TAG, "proving parameter %s is not in the package", name);
    return out;
}

bool zapp_params_prepare_async(AAssetManager *assets, const char *files)
{
    struct zapp_params_fd fds[ZAPP_PARAMS_COUNT];
    if (!assets || !files) return false;
    for (size_t i = 0; i < ZAPP_PARAMS_COUNT; i++) fds[i] = open_asset(assets, zapp_param_files[i].name);
    return zapp_params_job_start(fds, files);
}
