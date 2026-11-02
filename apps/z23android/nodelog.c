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

/* A line holding any of these is never forwarded, whatever else it says. The node should not log
 * secrets; this keeps key material out of logcat even if one ever does. */
static const char *const secret[] = {"priv", "seed", "mnemonic", "spending key"};
/* The levels a node line names in its header. The first four are warnings: they are forwarded as their level, their
 * [domain] and their function only, whatever the text says, because the text can carry an address, a transaction id or an
 * amount. */
static const char *const levels[] = {"WARN", "ERROR", "FAIL", "FATAL", "INFO", "DEBUG", "TRACE"};
#define WARNING_LEVELS 4

static bool has_any(const char *s, const char *const *words, size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (strcasestr(s, words[i])) return true;
    return false;
}
#define HAS_ANY(s, list) has_any(s, list, sizeof(list) / sizeof(list[0]))

/* What a node line's header names: "TIME LEVEL [domain] file:line function(): text". Every part after the level is optional. */
struct header { size_t level; char domain[48], function[64]; };

static bool word_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}
static const char *skip_blanks(const char *s)
{
    while (*s == ' ' || *s == '\t') ++s;
    return s;
}
/* Whether the whole word appears in s, with no letter, digit or underscore either side. */
static bool has_word(const char *s, const char *word)
{
    size_t n = strlen(word);
    for (const char *at = strstr(s, word); at; at = strstr(at + 1, word))
        if ((at == s || !word_char(at[-1])) && !word_char(at[n])) return true;
    return false;
}
/* The index in levels of the word that starts the token at p, or the count when none does. */
static size_t level_at(const char *p)
{
    size_t token = strcspn(p, " \t");
    for (size_t i = 0; i < sizeof(levels) / sizeof(levels[0]); i++)
        if (strlen(levels[i]) == token && !strncmp(p, levels[i], token)) return i;
    return sizeof(levels) / sizeof(levels[0]);
}
/* "[domain]" at p: copies the name and returns the text after it, or NULL. */
static const char *read_domain(const char *p, char *out, size_t cap)
{
    if (*p != '[') return NULL;
    size_t n = strspn(p + 1, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-");
    if (n == 0 || n >= cap || p[1 + n] != ']') return NULL;
    memcpy(out, p + 1, n);
    out[n] = 0;
    return p + 2 + n;
}
/* "file:line function():" at p: copies the function name, or leaves it empty. */
static void read_function(const char *p, char *out, size_t cap)
{
    size_t place = strcspn(p, " \t");
    if (place < 3 || p[place - 1] < '0' || p[place - 1] > '9' || !memchr(p, ':', place)) return;
    p = skip_blanks(p + place);
    size_t n = strspn(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_");
    if (n == 0 || n >= cap || strncmp(p + n, "():", 3) != 0) return;
    memcpy(out, p, n);
    out[n] = 0;
}
/* Reads the header at the start of line: an optional time token (it starts with a digit), then a level word. False when the
 * line does not begin that way. */
static bool read_header(const char *line, struct header *h)
{
    const char *p = skip_blanks(line);
    memset(h, 0, sizeof(*h));
    if (*p >= '0' && *p <= '9') p = skip_blanks(p + strcspn(p, " \t"));
    h->level = level_at(p);
    if (h->level == sizeof(levels) / sizeof(levels[0])) return false;
    p = skip_blanks(p + strlen(levels[h->level]));
    const char *after = read_domain(p, h->domain, sizeof(h->domain));
    if (after) read_function(skip_blanks(after), h->function, sizeof(h->function));
    return true;
}
/* Whether the line is a warning, and which: by its header when it has one, otherwise by the first warning word anywhere in
 * it. A header that says INFO makes the line information, whatever its text holds. */
static bool warning_level(const char *line, bool has_header, struct header *h)
{
    if (has_header) return h->level < WARNING_LEVELS;
    for (size_t i = 0; i < WARNING_LEVELS; i++)
        if (has_word(line, levels[i])) { h->level = i; return true; }
    return false;
}
static bool starts_with(const char *s, const char *prefix, bool any_case)
{
    size_t n = strlen(prefix);
    return any_case ? strncasecmp(s, prefix, n) == 0 : strncmp(s, prefix, n) == 0;
}
/* Whether a line that is not a warning explains boot progress: a boot stage or timing, Tor bootstrap, or a peer handshake from
 * the net domain or from the node's own headerless peer lines. A handshake word anywhere else is only text. */
static bool explains_progress(const char *line, bool has_header, const struct header *h)
{
    bool domain_boot = has_header && !strcmp(h->domain, "boot"), domain_tor = has_header && !strcmp(h->domain, "tor");
    if (starts_with(line, "[boot-stage] ", false) || starts_with(line, "[boot]", false) || domain_boot) return true;
    if ((domain_tor || starts_with(line, "Tor:", true)) && strcasestr(line, "bootstrap")) return true;
    bool net = (has_header && !strcmp(h->domain, "net")) || starts_with(line, "Peer ", false) || starts_with(line, "Addnode ", false);
    return net && has_word(line, "handshake");
}
/* "LEVEL [domain] function()": the parts of the header that were read, and nothing of the text. */
static void level_summary(const struct header *h, char *out, size_t cap)
{
    size_t used = (size_t)snprintf(out, cap, "%s", levels[h->level]);
    if (h->domain[0] && used < cap) used += (size_t)snprintf(out + used, cap - used, " [%s]", h->domain);
    if (h->domain[0] && h->function[0] && used < cap) snprintf(out + used, cap - used, " %s()", h->function);
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
    if (!text[0] || HAS_ANY(text, secret)) return;
    struct header header;
    bool has_header = read_header(text, &header), warning = warning_level(text, has_header, &header);
    bool progress = !warning && explains_progress(text, has_header, &header);
    if (!warning && !progress) return;
    if (!take_slot(l, now_ms)) return;
    char summary[ZAPP_NODELOG_LINE_MAX + 1];
    if (warning) level_summary(&header, summary, sizeof(summary));
    l->sink(l->sink_arg, warning ? 1 : 0, warning ? summary : text);
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
