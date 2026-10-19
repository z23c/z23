/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared plumbing for the node SLO monitors: ledger directory resolution,
 * locked appends, atomic state files, strict env parsing and the bounded
 * text sink every ledger line is built with. */
// one-result-type-ok:typed-report-struct — each entry point fills a report struct that names the failing condition; the bool only says whether the ledger I/O completed.

#include "services/slo_monitor.h"

#include "base/safe_alloc.h"

#include "services/evidence_ledger_row.h"
#include "util/file_tree_ops.h"
#include "util/log_json.h"
#include "util/write_all.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/file.h>
#endif
#include <time.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

enum { SLO_LOCK_TRIES = 300, SLO_LOCK_STEP_NS = 100 * 1000 * 1000 };

void slo_text_init(struct slo_text *t, char *buf, size_t cap)
{
    t->buf = buf;
    t->cap = cap;
    t->len = 0;
    t->overflow = false;
    if (cap)
        buf[0] = '\0';
}

void slo_text_addf(struct slo_text *t, const char *fmt, ...)
{
    if (t->overflow || t->cap == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(t->buf + t->len, t->cap - t->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= t->cap - t->len) {
        t->overflow = true;
        t->buf[t->len] = '\0';
        return;
    }
    t->len += (size_t)n;
}

int slo_stamp_cmp(const void *a, const void *b)
{
    const struct slo_stamp *x = a, *y = b;
    if (x->ts != y->ts)
        return x->ts < y->ts ? -1 : 1;
    return x->seq < y->seq ? -1 : (x->seq > y->seq);
}

void slo_note_addf(char (*notes)[SLO_NOTE_LEN], size_t *count,
                   const char *fmt, ...)
{
    if (*count >= SLO_NOTE_MAX)
        return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(notes[(*count)++], SLO_NOTE_LEN, fmt, ap);
    va_end(ap);
}

void slo_json_escape(struct slo_text *out, const char *in)
{
    char escaped[2048];
    (void)log_json_escape(escaped, sizeof(escaped), in);
    slo_text_addf(out, "\"%s\"", escaped);
}

bool slo_monitor_dir(char *out, size_t cap)
{
    const char *over = getenv("ZCL_SLO_LEDGER_DIR");
    if (over && over[0]) {
        size_t n = strlen(over);
        if (n >= cap) {
            if (cap)
                out[0] = '\0';
            return false;
        }
        memcpy(out, over, n + 1);
        return true;
    }
    return evidence_ledger_home_rel_dir(".local/state/zclassic23-slo", out,
                                        cap);
}

bool slo_monitor_file(const char *name, char *out, size_t cap)
{
    char dir[SLO_PATH_MAX];
    if (!name || !name[0] || strchr(name, '/') || !slo_monitor_dir(dir, sizeof(dir)))
        return false;
    int n = snprintf(out, cap, "%s/%s", dir, name);
    return n > 0 && (size_t)n < cap;
}

bool slo_monitor_mkdir_p(const char *dir)
{
    return zcl_mkdir_p(dir, 0755).ok;
}

bool slo_monitor_state_file(const char *subdir, const char *name, bool make,
                            char *out, size_t cap)
{
    char dir[SLO_PATH_MAX];
    if (!subdir || !name || !name[0] || strchr(name, '/') ||
        !slo_monitor_dir(dir, sizeof(dir)))
        return false;
    int n = snprintf(out, cap, "%s/%s", dir, subdir);
    if (n <= 0 || (size_t)n >= cap)
        return false;
    if (make && !slo_monitor_mkdir_p(out))
        return false;
    int m = snprintf(out + n, cap - (size_t)n, "/%s", name);
    return m > 0 && (size_t)m < cap - (size_t)n;
}

bool slo_monitor_read_line(const char *path, char *out, size_t cap)
{
    if (cap == 0)
        return false;
    out[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    bool ok = fgets(out, (int)(cap > 4096 ? 4096 : cap), f) != NULL;
    fclose(f);
    if (ok)
        out[strcspn(out, "\r\n")] = '\0';
    return ok;
}

static bool lock_wait(int fd)
{
#if defined(_WIN32)
    (void)fd;
    return true;
#else
    for (int i = 0; i < SLO_LOCK_TRIES; i++) {
        if (flock(fd, LOCK_EX | LOCK_NB) == 0)
            return true;
        if (errno != EWOULDBLOCK && errno != EINTR)
            return false;
        struct timespec step = { .tv_sec = 0, .tv_nsec = SLO_LOCK_STEP_NS };
        nanosleep(&step, NULL);
    }
    return false;
#endif
}

bool slo_monitor_append(const char *path, const char *line)
{
    size_t n = strlen(line);
    char *row = zcl_malloc(n + 2, "slo_append_row");
    if (!row)
        return false;
    memcpy(row, line, n);
    row[n] = '\n';
    row[n + 1] = '\0';
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    bool ok = fd >= 0 && lock_wait(fd) && zcl_write_all(fd, row, n + 1);
    if (fd >= 0)
        close(fd);
    free(row);
    return ok;
}

bool slo_monitor_write_atomic(const char *path, const char *text)
{
    char tmp[SLO_PATH_MAX];
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp))
        return false;
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return false;
    bool ok = zcl_write_all(fd, text, strlen(text));
    ok = (close(fd) == 0) && ok;
    if (ok && rename(tmp, path) != 0)
        ok = false;
    if (!ok)
        unlink(tmp);
    return ok;
}

int64_t slo_parse_i64(const char *text, int64_t fallback)
{
    if (!text || !text[0])
        return fallback;
    errno = 0;
    char *end = NULL;
    long long v = strtoll(text, &end, 10);
    return (errno == 0 && end && *end == '\0') ? (int64_t)v : fallback;
}

double slo_parse_double(const char *text, double fallback)
{
    if (!text || !text[0])
        return fallback;
    errno = 0;
    char *end = NULL;
    double v = strtod(text, &end);
    return (errno == 0 && end && *end == '\0') ? v : fallback;
}


void slo_json_opt(struct slo_text *out, struct slo_opt value)
{
    if (value.has)
        slo_text_addf(out, "%lld", (long long)value.v);
    else
        slo_text_addf(out, "null");
}
