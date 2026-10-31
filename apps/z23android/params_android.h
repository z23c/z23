/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_PARAMS_ANDROID_H
#define ZAPP_PARAMS_ANDROID_H
#include "params_job.h"
#include <android/asset_manager.h>

/* Opens the packaged proving parameters on the calling thread, which must be one that may use the
 * asset manager, then verifies and copies them to <files>/params on a new thread (params_job.h). The
 * thread keeps only the opened descriptors: it never touches the asset manager, JNI or the caller's
 * memory, so the manager only needs to outlive this call. Returns false when a copy is already
 * running, the thread cannot start or the arguments are unusable. Poll zapp_params_job_state for the
 * outcome; no callback runs, and a send may start only on ZAPP_PARAMS_VERIFIED. */
bool zapp_params_prepare_async(AAssetManager *assets, const char *files);
#endif
