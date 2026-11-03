/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#define _GNU_SOURCE
#include "nodelog.h"
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
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


/* Peer names: a ".onion" host, an IPv4 address or an IPv6 address, each with an optional port. */
static bool peer_char(char c)
{
    return word_char(c) || c == '.' || c == ':' || c == '-' || c == '[' || c == ']';
}
static bool all_digits(const char *s, size_t n)
{
    if (n == 0) return false;
    for (size_t i = 0; i < n; i++)
        if (s[i] < '0' || s[i] > '9') return false;
    return true;
}
/* ":port" or nothing for the whole of s. */
static bool port_or_end(const char *s, size_t n)
{
    return n == 0 || (s[0] == ':' && all_digits(s + 1, n - 1));
}
static bool onion_name(const char *t, size_t n)
{
    for (size_t i = 0; i + 6 <= n; i++)
        if (strncasecmp(t + i, ".onion", 6) == 0 && port_or_end(t + i + 6, n - i - 6)) return true;
    return false;
}
static bool ipv4_name(const char *t, size_t n)
{
    size_t at = 0;
    for (int group = 0; group < 4; group++) {
        size_t digits = strspn(t + at, "0123456789");
        if (digits == 0 || digits > 3 || at + digits > n) return false;
        at += digits;
        if (group < 3 && (at >= n || t[at++] != '.')) return false;
    }
    return port_or_end(t + at, n - at);
}
/* Bracketed, or holding "::", or a full eight groups; a clock time such as 10:00:01 is none of these. */
static bool ipv6_name(const char *t, size_t n)
{
    bool bracket = n > 0 && t[0] == '[';
    size_t at = bracket ? 1 : 0, body = strspn(t + at, "0123456789abcdefABCDEF:.");
    if (at + body > n) body = n - at;
    if (body == 0) return false;
    size_t colons = 0;
    for (size_t i = at; i < at + body; i++) colons += t[i] == ':';
    bool compressed = memmem(t + at, body, "::", 2) != NULL;
    if (colons < 2 || !(bracket || compressed || colons == 7)) return false;
    at += body;
    if (bracket && (at >= n || t[at++] != ']')) return false;
    return port_or_end(t + at, n - at);
}
static bool peer_name(const char *t, size_t n)
{
    return onion_name(t, n) || ipv4_name(t, n) || ipv6_name(t, n);
}
/* Offset of the first peer name in the token t, tried at its start and after each ':', '-' or '[' inside it so a prefix such as
 * "Addnode:" or "peer-" does not hide the address; n when the token holds none. */
static size_t peer_start(const char *t, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && t[i - 1] != ':' && t[i - 1] != '-' && t[i] != '[') continue;
        if (peer_name(t + i, n - i)) return i;
    }
    return n;
}
static size_t append(char *out, size_t used, size_t cap, const char *s, size_t n)
{
    for (size_t i = 0; i < n && used + 1 < cap; i++) out[used++] = s[i];
    return used;
}
void zapp_nodelog_redact(const char *line, char *out, size_t cap)
{
    static const char mark[] = "<peer>";
    size_t used = 0;
    if (cap == 0) return;
    while (*line && used + 1 < cap) {
        size_t run = 0;
        while (peer_char(line[run])) run++;
        if (run == 0) { out[used++] = *line++; continue; }
        size_t core = run;
        while (core > 0 && (line[core - 1] == '.' || line[core - 1] == ':' || line[core - 1] == '-')) core--;
        size_t at = peer_start(line, core);
        used = append(out, used, cap, line, at);
        if (at < core) used = append(out, used, cap, mark, sizeof(mark) - 1);
        used = append(out, used, cap, line + core, run - core);
        line += run;
    }
    out[used] = 0;
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
    char shown[ZAPP_NODELOG_LINE_MAX + 1];
    zapp_nodelog_redact(warning ? summary : text, shown, sizeof(shown));
    l->sink(l->sink_arg, warning ? 1 : 0, shown);
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

/* Keeps the console log at or under the cap. Past it, the bytes not yet forwarded are forwarded first, then the file is
 * truncated to 0 and the read offset goes back to 0. The node's descriptor is O_APPEND, so its next write lands at the new end
 * of the file and the line it completes is forwarded as usual. A write made after the last byte forwarded and before the
 * truncation is lost; that window is a few microseconds. */
static void keep_within_cap(struct zapp_nodelog *l, int fd, struct splitter *s, char *buf, size_t bufsize)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= l->cap) return;
    off_t pos = lseek(fd, 0, SEEK_CUR);
    while (pos >= 0 && pos < st.st_size) {
        size_t want = (size_t)(st.st_size - pos) < bufsize ? (size_t)(st.st_size - pos) : bufsize;
        ssize_t got = read(fd, buf, want);
        if (got <= 0) break;
        split(l, s, buf, (size_t)got);
        pos += got;
    }
    if (ftruncate(fd, 0) != 0) return;
    l->offset = 0;
    lseek(fd, 0, SEEK_SET);
}

static void *tail_main(void *arg)
{
    struct zapp_nodelog *l = arg;
    /* Read-write only so the reader can truncate through the same descriptor it reads. */
    int fd = open(l->file, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return NULL;
    struct splitter s = {0};
    char buf[2048];
    bool last = false;
    if (lseek(fd, l->offset, SEEK_SET) < 0) { close(fd); return NULL; }
    for (;;) {
        keep_within_cap(l, fd, &s, buf, sizeof(buf));
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

bool zapp_nodelog_start(struct zapp_nodelog *l, const char *file, off_t offset, pid_t pid, off_t cap)
{
    zapp_nodelog_stop(l);
    atomic_store(&l->stage, 0);
    atomic_store(&l->stop, false);
    l->window_count = 0;
    l->offset = offset;
    l->cap = cap;
    l->pid = pid;
    if (snprintf(l->file, sizeof(l->file), "%s", file) >= (int)sizeof(l->file)) return false;
    l->started = pthread_create(&l->thread, NULL, tail_main, l) == 0;
    return l->started;
}

/* A rotated file keeps its name with ".1" appended; the path buffer holds the 1099 bytes the callers allow plus the suffix. */
bool zapp_console_rotate(const char *file, off_t cap)
{
    struct stat st;
    char rotated[1104];
    if (lstat(file, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= cap) return true;
    if (snprintf(rotated, sizeof(rotated), "%s.1", file) >= (int)sizeof(rotated)) return false;
    return rename(file, rotated) == 0;
}

const char *zapp_nodelog_stage(struct zapp_nodelog *l)
{
    int stage = atomic_load(&l->stage);
    return stage > 0 ? stages[stage - 1].doing : "starting the node";
}
