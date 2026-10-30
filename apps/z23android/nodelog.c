/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "nodelog.h"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <android/log.h>
#endif

/* Boot stages in node order, with what the node is doing once it reports that stage. */
static const struct { const char *name, *doing; } stages[] = {
    {"init", "locking the data folder"},
    {"datadir_locked", "preparing cryptography"},
    {"crypto_ready", "opening the database"},
    {"db_open", "loading the wallet"},
    {"wallet_loaded", "loading the block index"},
    {"block_index_loaded", "finding the chain tip"},
    {"chain_tip_resolved", "connecting to the network"},
    {"network_ready", "starting services"},
    {"services_running", "finishing startup"},
    {"ready", "running"},
    {"shutdown_requested", "saving data and stopping"},
    {"shutdown_complete", "stopped"},
};
#define STAGES (sizeof(stages) / sizeof(stages[0]))

/* Lines containing any of these are forwarded. */
static const char *const wanted[] = {"[boot-stage]", "[boot]", "WARN", "ERROR", "FAIL", "FATAL", "handshake"};
/* A line holding any of these is never forwarded, whatever else it says. The node should not log
 * secrets; this keeps key material out of logcat even if one ever does. */
static const char *const secret[] = {"priv", "seed", "mnemonic", "spending key"};

static bool has_any(const char *s, const char *const *words, size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (strcasestr(s, words[i])) return true;
    return false;
}
#define HAS_ANY(s, list) has_any(s, list, sizeof(list) / sizeof(list[0]))

static bool explains_progress(const char *s)
{
    return HAS_ANY(s, wanted) || (strcasestr(s, "tor") && strcasestr(s, "bootstrap"));
}

/* "[boot-stage] a -> b" names the stage b the node has just entered. */
static void note_stage(struct zapp_nodelog *l, const char *line)
{
    const char *mark = strstr(line, "[boot-stage] ");
    const char *to = mark && !strstr(line, "FATAL") ? strstr(mark, " -> ") : NULL;
    if (!to) return;
    to += 4;
    size_t n = strcspn(to, " \r\n");
    for (size_t i = 0; i < STAGES; i++)
        if (strlen(stages[i].name) == n && !strncmp(stages[i].name, to, n))
            atomic_store(&l->stage, (int)i + 1);
}

static bool take_slot(struct zapp_nodelog *l, int64_t now_ms)
{
    if (l->window_count == 0 || now_ms - l->window_start >= 1000 || now_ms < l->window_start) {
        l->window_start = now_ms;
        l->window_count = 0;
    }
    return l->window_count++ < ZAPP_NODELOG_PER_SECOND;
}

void zapp_nodelog_line(struct zapp_nodelog *l, const char *line, int64_t now_ms)
{
    note_stage(l, line);
    char text[ZAPP_NODELOG_LINE_MAX + 1];
    snprintf(text, sizeof(text), "%s", line);
    text[strcspn(text, "\r\n")] = 0;
    if (!text[0] || !explains_progress(text) || HAS_ANY(text, secret)) return;
    if (!take_slot(l, now_ms)) return;
    bool bad = strstr(text, "WARN") || strstr(text, "ERROR") || strstr(text, "FAIL") || strstr(text, "FATAL");
    l->sink(l->sink_arg, bad ? 1 : 0, text);
}

static void logcat_sink(void *arg, int level, const char *text)
{
    (void)arg;
#ifdef __ANDROID__
    __android_log_write(level ? ANDROID_LOG_WARN : ANDROID_LOG_INFO, ZAPP_NODELOG_TAG, text);
#else
    (void)level; (void)text;
#endif
}

void zapp_nodelog_init(struct zapp_nodelog *l, zapp_nodelog_sink sink, void *arg)
{
    memset(l, 0, sizeof(*l));
    l->sink = sink ? sink : logcat_sink;
    l->sink_arg = arg;
}

static int64_t now_ms(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return 0;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Splits bytes into lines of at most 1023 characters; the rest of a longer line is dropped. */
struct splitter { char line[1024]; size_t used; };
static void split(struct zapp_nodelog *l, struct splitter *s, const char *data, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (data[i] == '\n') {
            s->line[s->used] = 0;
            zapp_nodelog_line(l, s->line, now_ms());
            s->used = 0;
        } else if (s->used + 1 < sizeof(s->line)) s->line[s->used++] = data[i];
    }
}

static bool node_alive(pid_t pid)
{
    return kill(pid, 0) == 0;
}

static void *tail_main(void *arg)
{
    struct zapp_nodelog *l = arg;
    int fd = open(l->file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct splitter s = {0};
    char buf[2048];
    bool last = false;
    if (lseek(fd, l->offset, SEEK_SET) < 0) { close(fd); return NULL; }
    for (;;) {
        ssize_t got = read(fd, buf, sizeof(buf));
        if (got > 0) { split(l, &s, buf, (size_t)got); continue; }
        if (last) break;
        /* Once the node has exited or stop is requested, one more read collects its last lines. */
        last = atomic_load(&l->stop) || !node_alive(l->pid);
        if (!last) { struct timespec pause = {.tv_nsec = 250000000}; nanosleep(&pause, NULL); }
    }
    close(fd);
    return NULL;
}

void zapp_nodelog_stop(struct zapp_nodelog *l)
{
    if (!l->started) return;
    atomic_store(&l->stop, true);
    pthread_join(l->thread, NULL);
    l->started = false;
}

bool zapp_nodelog_start(struct zapp_nodelog *l, const char *file, off_t offset, pid_t pid)
{
    zapp_nodelog_stop(l);
    atomic_store(&l->stage, 0);
    atomic_store(&l->stop, false);
    l->window_count = 0;
    l->offset = offset;
    l->pid = pid;
    if (snprintf(l->file, sizeof(l->file), "%s", file) >= (int)sizeof(l->file)) return false;
    l->started = pthread_create(&l->thread, NULL, tail_main, l) == 0;
    return l->started;
}

const char *zapp_nodelog_stage(struct zapp_nodelog *l)
{
    int stage = atomic_load(&l->stage);
    return stage > 0 ? stages[stage - 1].doing : "starting the node";
}
