/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_PARAMS_JOB_H
#define ZAPP_PARAMS_JOB_H
#include "params.h"

/* One packaged file, already opened by the caller: the descriptor and the byte range holding the
 * file. fd is -1 when the file could not be opened. */
struct zapp_params_fd {
    int fd;
    uint64_t offset, length;
};

enum zapp_params_state {
    ZAPP_PARAMS_IDLE,     /* nothing has run in this process */
    ZAPP_PARAMS_COPYING,  /* the worker thread is verifying or copying */
    ZAPP_PARAMS_VERIFIED, /* every file under <files>/params matched its pinned SHA-256 */
    ZAPP_PARAMS_FAILED    /* why holds the reason; no pinned file remains under <files>/params */
};

/* Runs zapp_params_install on a detached thread over the given descriptors, so the UI thread never
 * waits for it. fds has one entry per file, in table order. The job owns the descriptors from this
 * call on and closes them, also when it returns false (a copy is already running or the thread
 * cannot start). A start that returns false changes neither the state nor <files>/params: the
 * earlier outcome and any files stand, and a running copy is not disturbed. The thread touches
 * no JNI, no asset manager and no caller memory. The outcome is read by polling
 * zapp_params_job_state from any thread; nothing is called back. */
bool zapp_params_job_start(const struct zapp_params_fd *fds, const char *files);
bool zapp_params_job_start_set(const struct zapp_param_file *set, size_t count, const struct zapp_params_fd *fds,
                               const char *files);

/* The current state. why, when given, receives the plain reason of a FAILED state (empty otherwise). */
enum zapp_params_state zapp_params_job_state(char *why, size_t cap);
#endif
