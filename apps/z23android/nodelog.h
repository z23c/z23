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
/* The node console log is kept at or under this many bytes. Spawn moves a larger one to <name>.1, and the
 * running reader truncates it to 0 once it grows past the cap. */
#define ZAPP_CONSOLE_CAP ((off_t)16 * 1024 * 1024)

/* level is 0 for information and 1 for a warning or error. */
typedef void (*zapp_nodelog_sink)(void *arg, int level, const char *text);

enum zapp_replay_phase { ZAPP_REPLAY_NONE, ZAPP_REPLAY_TRANSPARENT, ZAPP_REPLAY_DISCOVER,
    ZAPP_REPLAY_WITNESS, ZAPP_REPLAY_SPENDS, ZAPP_REPLAY_BLOCK_INDEX };
struct zapp_replay_progress { enum zapp_replay_phase phase; int64_t floor, next, reference; };

struct zapp_nodelog {
    zapp_nodelog_sink sink;
    void *sink_arg;
    atomic_int stage;
    atomic_uint replay_seq;
    atomic_int replay_phase;
    atomic_int_fast64_t replay_floor, replay_next, replay_reference;
    int64_t window_start;
    int window_count;
    pthread_t thread;
    bool started;
    atomic_bool stop;
    char file[1100];
    off_t offset;
    /* The size past which the running reader truncates the file; set by zapp_nodelog_start. */
    off_t cap;
    pid_t pid;
};

/* A NULL sink writes to logcat on Android and discards on other systems. */
void zapp_nodelog_init(struct zapp_nodelog *l, zapp_nodelog_sink sink, void *arg);
/* Copies line to out (cap bytes, always terminated), replacing every .onion name, IPv4 address and IPv6 address, each with
 * its optional port, by "<peer>". Everything else is copied unchanged. */
void zapp_nodelog_redact(const char *line, char *out, size_t cap);
/* Handles one console line: records a boot stage and forwards the line when it explains progress,
 * at most ZAPP_NODELOG_PER_SECOND lines in each second of now_ms. */
void zapp_nodelog_line(struct zapp_nodelog *l, const char *line, int64_t now_ms);
/* Tails file from offset on a thread until pid exits or zapp_nodelog_stop runs. Whenever the file is larger than cap, the
 * reader forwards the unread bytes, truncates the file to 0 and continues from 0. */
bool zapp_nodelog_start(struct zapp_nodelog *l, const char *file, off_t offset, pid_t pid, off_t cap);
/* Renames file to file.1, replacing any older file.1, when file is a regular file larger than cap, so that the next
 * open of file starts empty. Other files are left alone. False when the rename fails. */
bool zapp_console_rotate(const char *file, off_t cap);
void zapp_nodelog_stop(struct zapp_nodelog *l);
/* What the node is doing after the latest boot stage it reported, as a short plain phrase. */
const char *zapp_nodelog_stage(struct zapp_nodelog *l);
/* NULL unless the current observed stage is before readiness. */
const char *zapp_nodelog_startup_stage(struct zapp_nodelog *l);
/* Bounded coherent snapshot of the current child replay, if present. */
bool zapp_nodelog_replay(struct zapp_nodelog *l, struct zapp_replay_progress *out);
bool zapp_nodelog_replay_visible(bool responding, bool running, bool stopping, bool has_progress);
void zapp_nodelog_replay_text(const struct zapp_replay_progress *p, char *out, size_t cap);
#endif
