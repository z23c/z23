/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_NODELOG_H
#define ZAPP_NODELOG_H
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* Forwards the lines of the node console log that explain boot progress to Android logcat under
 * the tag "z23node", so `adb logcat -s z23node` shows why a node is stuck without root. */
#define ZAPP_NODELOG_TAG "z23node"
#define ZAPP_NODELOG_LINE_MAX 300
#define ZAPP_NODELOG_PER_SECOND 20

/* level is 0 for information and 1 for a warning or error. */
typedef void (*zapp_nodelog_sink)(void *arg, int level, const char *text);

struct zapp_nodelog {
    zapp_nodelog_sink sink;
    void *sink_arg;
    atomic_int stage;
    int64_t window_start;
    int window_count;
    pthread_t thread;
    bool started;
    atomic_bool stop;
    char file[1100];
    off_t offset;
    pid_t pid;
};

/* A NULL sink writes to logcat on Android and discards on other systems. */
void zapp_nodelog_init(struct zapp_nodelog *l, zapp_nodelog_sink sink, void *arg);
/* Handles one console line: records a boot stage and forwards the line when it explains progress,
 * at most ZAPP_NODELOG_PER_SECOND lines in each second of now_ms. */
void zapp_nodelog_line(struct zapp_nodelog *l, const char *line, int64_t now_ms);
/* Tails file from offset on a thread until pid exits or zapp_nodelog_stop runs. */
bool zapp_nodelog_start(struct zapp_nodelog *l, const char *file, off_t offset, pid_t pid);
void zapp_nodelog_stop(struct zapp_nodelog *l);
/* What the node is doing after the latest boot stage it reported, as a short plain phrase. */
const char *zapp_nodelog_stage(struct zapp_nodelog *l);
#endif
