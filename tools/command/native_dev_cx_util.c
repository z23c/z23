/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: small shared helpers of the dev.cx leaves; see native_dev_cx.h. */

#include "command/native_dev_cx.h"

#include "base/safe_alloc.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool cx_set_add(struct cx_set *s, const char *text, size_t len)
{
    char *copy;
    if (s->n == s->cap) {
        size_t cap = s->cap ? s->cap * 2 : 64;
        char **v = zcl_realloc(s->v, cap * sizeof(*v), "dev_cx.set");
        if (!v)
            return false;
        s->v = v;
        s->cap = cap;
    }
    copy = zcl_malloc(len + 1, "dev_cx.set.item");
    if (!copy)
        return false;
    memcpy(copy, text, len);
    copy[len] = '\0';
    s->v[s->n++] = copy;
    return true;
}

bool cx_set_has(const struct cx_set *s, const char *text)
{
    for (size_t i = 0; i < s->n; i++)
        if (strcmp(s->v[i], text) == 0)
            return true;
    return false;
}

void cx_set_free(struct cx_set *s)
{
    for (size_t i = 0; i < s->n; i++)
        free(s->v[i]);
    free(s->v);
    memset(s, 0, sizeof(*s));
}

bool cx_set_add_lines(struct cx_set *s, const char *text)
{
    for (const char *p = text; *p;) {
        size_t n = strcspn(p, "\n");
        size_t m = n;
        if (m > 0 && p[m - 1] == '\r')
            m--;
        if (m > 0 && !cx_set_add(s, p, m))
            return false;
        p += n + (p[n] == '\n' ? 1 : 0);
    }
    return true;
}

char *cx_read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    size_t cap = 65536, used = 0;
    char *buf = f ? zcl_malloc(cap, "dev_cx.read") : NULL;
    while (buf) {
        size_t got = fread(buf + used, 1, cap - used - 1, f);
        used += got;
        if (ferror(f))
            break;
        if (feof(f)) {
            buf[used] = '\0';
            (void)fclose(f);
            if (len)
                *len = used;
            return buf;
        }
        cap *= 2;
        char *bigger = zcl_realloc(buf, cap, "dev_cx.read.grow");
        if (!bigger)
            break;
        buf = bigger;
    }
    free(buf);
    if (f)
        (void)fclose(f);
    return NULL;
}

bool cx_write_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    bool ok;
    if (!f)
        return false;
    ok = fwrite(data, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

int cx_run(const char *dir, const char *const argv[], char *buf, size_t cap,
           int timeout_ms, bool merged)
{
    bool timed_out = false;
    int rc = merged
        ? zcl_spawn_capture_merged_in_dir_observed(argv, dir, buf, cap,
                                                   timeout_ms, &timed_out)
        : zcl_spawn_capture_in_dir_observed(argv, dir, buf, cap, timeout_ms,
                                            &timed_out);
    return timed_out ? -1 : rc;
}

static bool cx_row_split(const char *line, size_t len, const char **fn,
                         const char **score)
{
    const char *last = NULL, *prev = NULL;
    for (size_t i = 0; i < len; i++) {
        if (line[i] != ':')
            continue;
        prev = last;
        last = line + i;
    }
    if (!last || !prev || prev == line || last == prev + 1 ||
        last + 1 == line + len)
        return false;
    *fn = prev;
    *score = last;
    return true;
}

bool cx_row_parse(const char *line, size_t len, struct cx_row *out)
{
    const char *fn, *score;
    char num[16];
    char *end;
    size_t flen, nlen, slen;
    if (len == 0 || line[0] == '#' || !cx_row_split(line, len, &fn, &score))
        return false;
    flen = (size_t)(fn - line);
    nlen = (size_t)(score - fn) - 1;
    slen = len - (size_t)(score - line) - 1;
    if (flen >= sizeof(out->file) || nlen >= sizeof(out->fn) ||
        slen >= sizeof(num))
        return false;
    memcpy(num, score + 1, slen);
    num[slen] = '\0';
    out->score = (int)strtol(num, &end, 10);
    if (*end != '\0' || out->score < 1)
        return false;
    memcpy(out->file, line, flen);
    out->file[flen] = '\0';
    memcpy(out->fn, fn + 1, nlen);
    out->fn[nlen] = '\0';
    return true;
}
