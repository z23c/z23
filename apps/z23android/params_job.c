/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include "params_job.h"
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FILES 8

struct job {
    struct zapp_param_file set[MAX_FILES];
    struct zapp_params_fd fds[MAX_FILES];
    size_t count;
    char files[1024];
};

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static enum zapp_params_state state = ZAPP_PARAMS_IDLE;
static char reason[160];

static void close_all(const struct zapp_params_fd *fds, size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (fds[i].fd >= 0) close(fds[i].fd);
}

/* Hands the install a duplicate of the descriptor of the named file, which the install closes. */
static int open_fd(void *ctx, const char *name, uint64_t *offset, uint64_t *length)
{
    const struct job *job = ctx;
    for (size_t i = 0; i < job->count; i++) {
        if (strcmp(job->set[i].name, name) != 0 || job->fds[i].fd < 0) continue;
        int fd = fcntl(job->fds[i].fd, F_DUPFD_CLOEXEC, 0);
        if (fd >= 0) { *offset = job->fds[i].offset; *length = job->fds[i].length; }
        return fd;
    }
    return -1;
}

static void *work(void *arg)
{
    struct job *job = arg;
    struct zapp_params_source source = {job, open_fd};
    char why[sizeof(reason)] = "";
    bool ok = zapp_params_install_set(job->set, job->count, &source, job->files, why, sizeof(why)) == ZAPP_PARAMS_OK;
    close_all(job->fds, job->count);
    free(job);
    pthread_mutex_lock(&lock);
    state = ok ? ZAPP_PARAMS_VERIFIED : ZAPP_PARAMS_FAILED;
    snprintf(reason, sizeof(reason), "%s", ok ? "" : why[0] ? why : "The proving parameters could not be prepared.");
    pthread_mutex_unlock(&lock);
    return NULL;
}

bool zapp_params_job_start_set(const struct zapp_param_file *set, size_t count, const struct zapp_params_fd *fds,
                               const char *files)
{
    struct job *job = count && count <= MAX_FILES && files && strlen(files) < sizeof(job->files) ? calloc(1, sizeof(*job)) : NULL;
    pthread_t thread;
    bool started = false;
    enum zapp_params_state before = ZAPP_PARAMS_IDLE;
    char before_reason[sizeof(reason)] = "";
    if (job) {
        memcpy(job->set, set, count * sizeof(*set));
        memcpy(job->fds, fds, count * sizeof(*fds));
        job->count = count;
        snprintf(job->files, sizeof(job->files), "%s", files);
        pthread_mutex_lock(&lock);
        if (state != ZAPP_PARAMS_COPYING) {
            before = state;
            memcpy(before_reason, reason, sizeof(reason));
            state = ZAPP_PARAMS_COPYING;
            reason[0] = 0;
            started = true;
        }
        pthread_mutex_unlock(&lock);
    }
    if (started && pthread_create(&thread, NULL, work, job) != 0) {
        pthread_mutex_lock(&lock);
        state = before;   /* nothing started: the earlier outcome and the files stand */
        memcpy(reason, before_reason, sizeof(reason));
        pthread_mutex_unlock(&lock);
        started = false;
    }
    if (started) { pthread_detach(thread); return true; }
    close_all(fds, count);
    free(job);
    return false;
}

bool zapp_params_job_start(const struct zapp_params_fd *fds, const char *files)
{
    return zapp_params_job_start_set(zapp_param_files, ZAPP_PARAMS_COUNT, fds, files);
}

enum zapp_params_state zapp_params_job_state(char *why, size_t cap)
{
    pthread_mutex_lock(&lock);
    enum zapp_params_state now = state;
    if (why && cap) snprintf(why, cap, "%s", reason);
    pthread_mutex_unlock(&lock);
    return now;
}
