/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.agent.outcomes usage_log — per-event model token usage read
 *          from Muse host session logs and Claude Code transcripts,
 *          deduplicated by event id, with each format's counter meaning kept.
 *
 * ── CONTRACT ──────────────────────────────────────────────────────────────
 *
 * WHY. A unit receipt records one token number per attempt, and that number
 * cannot say what it contains: the Muse wire has no cache field, so a
 * receipt's "billed" total silently includes cache reads, and a refused
 * attempt can record 0 while its model calls really ran. The model host's
 * own log records every call with its raw counters. This reader folds those
 * logs so usage is read from what the host observed, per event.
 *
 * INPUT. dev.agent.outcomes gains one optional key, usage_log: a path to one
 * JSONL file, or a directory walked for *.jsonl (depth <= DVU_MAX_DEPTH,
 * symlinks never followed). The outcomes model/since filters apply to usage
 * events too (since compares the event's UTC hour).
 *
 * FORMATS, recognized per line; any other line is ignored:
 *   muse    payload.event.kind == "model_completed". Event id = record id.
 *           Hour from recorded_at (microseconds). Counters from
 *           payload.event.usage: input_tokens (INCLUDES cache reads),
 *           output_tokens, cache_read_tokens, cache_write_tokens,
 *           reasoning_tokens.
 *   claude  type == "assistant" with message.usage. Event id = message.id;
 *           the transcript repeats one message on several lines, and the
 *           LAST line for an id wins (its counters replace, never add).
 *           Hour from timestamp. Counters: input_tokens (EXCLUDES cache
 *           reads), output_tokens, cache_read_input_tokens,
 *           cache_creation_input_tokens, output_tokens_details
 *           .thinking_tokens.
 *   uncached_input_tokens is derived per event so both formats compare:
 *   muse input - cache_read, claude input.
 *
 * COUNTERS. A missing, negative or non-numeric counter is UNREPORTED: it is
 * never summed as 0, and each output row carries unreported[field] = the
 * number of its events that did not report it. An event with no id is
 * counted in `unkeyed` and not summed, since it cannot be deduplicated.
 *
 * OUTPUT. reply data gains "usage": {usage_log, files, lines, usage_lines,
 * malformed (a line mentioning usage that is not one JSON object),
 * unreadable, unkeyed, events (distinct ids kept), duplicate_lines,
 * truncated, by_model:[{format, model, input_includes_cache_read, events,
 * <counters>, unreported:{...}}], hours_total, by_hour: newest
 * DVU_MAX_HOURS {hour, format, model, events, <counters>}}.
 *
 * FAILURE. usage_log present but not a nonempty string is BAD_INPUT; a path
 * that does not exist is USAGE_LOG_NOT_FOUND; one that is neither a file
 * nor a directory is BAD_INPUT. Unreadable files inside a directory are
 * counted, never fatal. The reader runs no process and writes nothing.
 *
 * Tests: tests/harness/src/test_devagent_outcomes.c, usage section.
 */

#include "command/native_devagent_usage_internal.h"

#include "base/safe_alloc.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#define DVU_MAX_DEPTH 8
#define DVU_MAX_FILES 50000
#define DVU_MAX_EVENTS 1000000u
#define DVU_MAX_HOURS 48u
#define DVU_HOUR_LEN 13u /* YYYY-MM-DDTHH */
#define DVU_PATH_MAX 4096u

enum dvu_field {
    DVU_IN,
    DVU_OUT,
    DVU_CREAD,
    DVU_CWRITE,
    DVU_REASON,
    DVU_UNCACHED, /* derived: comparable across formats */
    DVU_NF
};

static const char *const dvu_field_names[DVU_NF] = {
    "input_tokens",       "output_tokens",    "cache_read_tokens",
    "cache_write_tokens", "reasoning_tokens", "uncached_input_tokens",
};

enum dvu_format { DVU_MUSE, DVU_CLAUDE };

static const char *const dvu_format_names[] = {"muse", "claude"};

/* One parsed line: pointers into the parsed row, copied on keep. */
struct dvu_fields {
    enum dvu_format format;
    const char *id;
    const char *model;
    char hour[DVU_HOUR_LEN + 1];
    int64_t v[DVU_NF];
};

struct dvu_event {
    char *id;
    char *model;
    char hour[DVU_HOUR_LEN + 1];
    enum dvu_format format;
    size_t seq; /* input order: the latest line for an id wins */
    int64_t v[DVU_NF];
};

struct dvu_scan {
    struct dvu_event *ev;
    size_t n;
    size_t cap;
    size_t seq;
    int64_t files;
    int64_t lines;
    int64_t usage_lines;
    int64_t malformed;
    int64_t unreadable;
    int64_t unkeyed;
    bool truncated;
    bool alloc_failed;
    const char *model;
    const char *since;
};

struct dvu_sum {
    int64_t events;
    int64_t v[DVU_NF];
    int64_t unreported[DVU_NF];
};

static void dvu_fail(struct zcl_command_reply *reply, enum zcl_command_exit exit_code,
                     const char *code, const char *message)
{
    (void)fprintf(stderr, "dev.agent.outcomes: %s: %s\n", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           "usage", false, false, message,
                           "dev.agent.outcomes usage_log reader");
}

/* ── parsing ─────────────────────────────────────────────────────────── */

static const struct json_value *dvu_get(const struct json_value *obj,
                                        const char *key)
{
    return obj && obj->type == JSON_OBJ ? json_get(obj, key) : NULL;
}

static const char *dvu_str(const struct json_value *obj, const char *key)
{
    const struct json_value *v = dvu_get(obj, key);
    return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

/* A reported counter is a non-negative number; anything else is -1. */
static int64_t dvu_counter(const struct json_value *obj, const char *key)
{
    const struct json_value *v = dvu_get(obj, key);
    if (v && v->type == JSON_INT)
        return json_get_int(v) >= 0 ? json_get_int(v) : -1;
    if (v && v->type == JSON_REAL) {
        double d = json_get_real(v);
        return d >= 0.0 && d < 9.0e18 ? (int64_t)d : -1;
    }
    return -1;
}

static void dvu_hour_from_us(int64_t us, char out[DVU_HOUR_LEN + 1])
{
    time_t secs = (time_t)(us / 1000000);
    struct tm tm_utc;
#if defined(_WIN32)
    bool conv = gmtime_s(&tm_utc, &secs) == 0;
#else
    bool conv = gmtime_r(&secs, &tm_utc) != NULL;
#endif
    if (us <= 0 || !conv ||
        strftime(out, DVU_HOUR_LEN + 1, "%Y-%m-%dT%H", &tm_utc) !=
            DVU_HOUR_LEN)
        (void)snprintf(out, DVU_HOUR_LEN + 1, "unknown");
}

static void dvu_hour_from_iso(const char *ts, char out[DVU_HOUR_LEN + 1])
{
    if (ts && strlen(ts) >= DVU_HOUR_LEN && ts[4] == '-' && ts[10] == 'T')
        (void)snprintf(out, DVU_HOUR_LEN + 1, "%.13s", ts);
    else
        (void)snprintf(out, DVU_HOUR_LEN + 1, "unknown");
}

static bool dvu_parse_muse(const struct json_value *row, struct dvu_fields *f)
{
    const struct json_value *ev = dvu_get(dvu_get(row, "payload"), "event");
    const char *kind = dvu_str(ev, "kind");
    if (!kind || strcmp(kind, "model_completed") != 0)
        return false;
    const struct json_value *u = dvu_get(ev, "usage");
    const struct json_value *at = dvu_get(row, "recorded_at");
    f->format = DVU_MUSE;
    f->id = dvu_str(row, "id");
    f->model = dvu_str(ev, "model");
    dvu_hour_from_us(at && at->type == JSON_INT ? json_get_int(at) : 0, f->hour);
    f->v[DVU_IN] = dvu_counter(u, "input_tokens");
    f->v[DVU_OUT] = dvu_counter(u, "output_tokens");
    f->v[DVU_CREAD] = dvu_counter(u, "cache_read_tokens");
    f->v[DVU_CWRITE] = dvu_counter(u, "cache_write_tokens");
    f->v[DVU_REASON] = dvu_counter(u, "reasoning_tokens");
    f->v[DVU_UNCACHED] = f->v[DVU_IN] >= 0 && f->v[DVU_CREAD] >= 0 &&
                                 f->v[DVU_IN] >= f->v[DVU_CREAD]
                             ? f->v[DVU_IN] - f->v[DVU_CREAD]
                             : -1;
    return true;
}

static bool dvu_parse_claude(const struct json_value *row, struct dvu_fields *f)
{
    const char *type = dvu_str(row, "type");
    const struct json_value *msg = dvu_get(row, "message");
    const struct json_value *u = dvu_get(msg, "usage");
    if (!type || strcmp(type, "assistant") != 0 || !u || u->type != JSON_OBJ)
        return false;
    f->format = DVU_CLAUDE;
    f->id = dvu_str(msg, "id");
    f->model = dvu_str(msg, "model");
    dvu_hour_from_iso(dvu_str(row, "timestamp"), f->hour);
    f->v[DVU_IN] = dvu_counter(u, "input_tokens");
    f->v[DVU_OUT] = dvu_counter(u, "output_tokens");
    f->v[DVU_CREAD] = dvu_counter(u, "cache_read_input_tokens");
    f->v[DVU_CWRITE] = dvu_counter(u, "cache_creation_input_tokens");
    f->v[DVU_REASON] = dvu_counter(dvu_get(u, "output_tokens_details"),
                                   "thinking_tokens");
    f->v[DVU_UNCACHED] = f->v[DVU_IN];
    return true;
}

/* ── collection ──────────────────────────────────────────────────────── */

static bool dvu_filtered_out(const struct dvu_scan *s, const struct dvu_fields *f)
{
    if (s->model && (!f->model || strcmp(f->model, s->model) != 0))
        return true;
    return s->since && (strcmp(f->hour, "unknown") == 0 ||
                        strncmp(f->hour, s->since, DVU_HOUR_LEN) < 0);
}

static void dvu_keep(struct dvu_scan *s, const struct dvu_fields *f)
{
    if (!f->id || !f->id[0]) {
        s->unkeyed++;
        return;
    }
    if (dvu_filtered_out(s, f))
        return;
    if (s->n >= DVU_MAX_EVENTS) {
        s->truncated = true;
        return;
    }
    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2u : 256u;
        struct dvu_event *t = zcl_realloc(s->ev, ncap * sizeof(*t),
                                          "devagent_usage_events");
        if (!t) {
            s->alloc_failed = true;
            return;
        }
        s->ev = t;
        s->cap = ncap;
    }
    struct dvu_event *e = &s->ev[s->n];
    e->id = zcl_strdup(f->id, "devagent_usage_id");
    e->model = zcl_strdup(f->model ? f->model : "", "devagent_usage_model");
    if (!e->id || !e->model) {
        free(e->id);
        free(e->model);
        s->alloc_failed = true;
        return;
    }
    memcpy(e->hour, f->hour, sizeof(e->hour));
    memcpy(e->v, f->v, sizeof(e->v));
    e->format = f->format;
    e->seq = s->seq++;
    s->n++;
}

static void dvu_line(struct dvu_scan *s, const char *line, size_t len)
{
    s->lines++;
    if (!strstr(line, "\"usage\""))
        return;
    struct json_value row;
    json_init(&row);
    if (!json_read(&row, line, len) || row.type != JSON_OBJ) {
        s->malformed++;
        json_free(&row);
        return;
    }
    struct dvu_fields f;
    memset(&f, 0, sizeof(f));
    if (dvu_parse_muse(&row, &f) || dvu_parse_claude(&row, &f)) {
        s->usage_lines++;
        dvu_keep(s, &f);
    }
    json_free(&row);
}

/* Portable whole-line reader (not every target has getline): grows one
 * buffer until the line's newline or EOF. False at EOF or on OOM. */
struct dvu_linebuf {
    char *buf;
    size_t len;
    size_t cap;
};

static bool dvu_next_line(FILE *fp, struct dvu_linebuf *lb, bool *oom)
{
    lb->len = 0;
    for (;;) {
        if (lb->cap - lb->len < 4096u) {
            size_t ncap = lb->cap ? lb->cap * 2u : 65536u;
            char *t = zcl_realloc(lb->buf, ncap, "devagent_usage_line");
            if (!t) {
                *oom = true;
                return false;
            }
            lb->buf = t;
            lb->cap = ncap;
        }
        if (!fgets(lb->buf + lb->len, (int)(lb->cap - lb->len), fp))
            return lb->len > 0;
        lb->len += strlen(lb->buf + lb->len);
        if (lb->len > 0 && lb->buf[lb->len - 1] == '\n')
            return true;
    }
}

static void dvu_read_file(struct dvu_scan *s, const char *path)
{
    if (s->files >= DVU_MAX_FILES) {
        s->truncated = true;
        return;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        s->unreadable++;
        return;
    }
    s->files++;
    struct dvu_linebuf lb = {0};
    while (!s->alloc_failed && dvu_next_line(fp, &lb, &s->alloc_failed))
        dvu_line(s, lb.buf, lb.len);
    if (ferror(fp))
        s->unreadable++;
    free(lb.buf);
    (void)fclose(fp);
}

static bool dvu_is_jsonl(const char *name)
{
    size_t len = strlen(name);
    return len > 6u && strcmp(name + len - 6u, ".jsonl") == 0;
}

/* Never follow a symlink out of the walked tree; Windows has no lstat. */
static int dvu_lstat(const char *path, struct stat *st)
{
#if defined(_WIN32)
    return stat(path, st);
#else
    return lstat(path, st);
#endif
}

static void dvu_walk(struct dvu_scan *s, const char *dir, int depth)
{
    DIR *d = opendir(dir);
    if (!d) {
        s->unreadable++;
        return;
    }
    struct dirent *e;
    char path[DVU_PATH_MAX];
    while (!s->alloc_failed && (e = readdir(d)) != NULL) {
        if (e->d_name[0] == '.')
            continue;
        struct stat st;
        int n = snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        if (n < 0 || (size_t)n >= sizeof(path) || dvu_lstat(path, &st) != 0) {
            s->unreadable++;
        } else if (S_ISDIR(st.st_mode)) {
            if (depth < DVU_MAX_DEPTH)
                dvu_walk(s, path, depth + 1);
            else
                s->truncated = true;
        } else if (S_ISREG(st.st_mode) && dvu_is_jsonl(e->d_name)) {
            dvu_read_file(s, path);
        }
    }
    (void)closedir(d);
}

/* ── dedup and aggregation ───────────────────────────────────────────── */

static int dvu_cmp_id(const void *a, const void *b)
{
    const struct dvu_event *x = a, *y = b;
    int c = strcmp(x->id, y->id);
    if (c)
        return c;
    return (x->seq > y->seq) - (x->seq < y->seq);
}

/* Keep the latest line for each id; returns the number of dropped lines. */
static int64_t dvu_dedup(struct dvu_scan *s)
{
    if (s->n == 0)
        return 0;
    qsort(s->ev, s->n, sizeof(*s->ev), dvu_cmp_id);
    size_t out = 0;
    for (size_t i = 0; i < s->n; i++) {
        bool last = i + 1 == s->n || strcmp(s->ev[i].id, s->ev[i + 1].id) != 0;
        if (last) {
            s->ev[out++] = s->ev[i];
        } else {
            free(s->ev[i].id);
            free(s->ev[i].model);
        }
    }
    int64_t dropped = (int64_t)(s->n - out);
    s->n = out;
    return dropped;
}

static int dvu_cmp_model(const void *a, const void *b)
{
    const struct dvu_event *x = a, *y = b;
    if (x->format != y->format)
        return (int)x->format - (int)y->format;
    return strcmp(x->model, y->model);
}

/* Newest hour first, then format, then model. */
static int dvu_cmp_hour(const void *a, const void *b)
{
    const struct dvu_event *x = a, *y = b;
    int c = strcmp(y->hour, x->hour);
    return c ? c : dvu_cmp_model(a, b);
}

static void dvu_sum_add(struct dvu_sum *t, const struct dvu_event *e)
{
    t->events++;
    for (int f = 0; f < DVU_NF; f++) {
        if (e->v[f] < 0)
            t->unreported[f]++;
        else
            t->v[f] += e->v[f];
    }
}

static void dvu_push_sum(struct json_value *row, const struct dvu_sum *t,
                         bool with_unreported)
{
    (void)json_push_kv_int(row, "events", t->events);
    for (int f = 0; f < DVU_NF; f++)
        (void)json_push_kv_int(row, dvu_field_names[f], t->v[f]);
    if (!with_unreported)
        return;
    struct json_value un;
    json_init(&un);
    json_set_object(&un);
    for (int f = 0; f < DVU_NF; f++)
        (void)json_push_kv_int(&un, dvu_field_names[f], t->unreported[f]);
    (void)json_push_kv(row, "unreported", &un);
    json_free(&un);
}

static void dvu_push_group_head(struct json_value *row, const struct dvu_event *e)
{
    (void)json_push_kv_str(row, "format", dvu_format_names[e->format]);
    (void)json_push_kv_str(row, "model", e->model);
}

static void dvu_push_by_model(struct json_value *usage, struct dvu_scan *s)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    qsort(s->ev, s->n, sizeof(*s->ev), dvu_cmp_model);
    for (size_t i = 0; i < s->n;) {
        struct dvu_sum t;
        memset(&t, 0, sizeof(t));
        size_t j = i;
        while (j < s->n && dvu_cmp_model(&s->ev[i], &s->ev[j]) == 0)
            dvu_sum_add(&t, &s->ev[j++]);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        dvu_push_group_head(&row, &s->ev[i]);
        (void)json_push_kv_bool(&row, "input_includes_cache_read",
                                s->ev[i].format == DVU_MUSE);
        dvu_push_sum(&row, &t, true);
        (void)json_push_back(&arr, &row);
        json_free(&row);
        i = j;
    }
    (void)json_push_kv(usage, "by_model", &arr);
    json_free(&arr);
}

static void dvu_push_by_hour(struct json_value *usage, struct dvu_scan *s)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    qsort(s->ev, s->n, sizeof(*s->ev), dvu_cmp_hour);
    int64_t groups = 0;
    for (size_t i = 0; i < s->n;) {
        struct dvu_sum t;
        memset(&t, 0, sizeof(t));
        size_t j = i;
        while (j < s->n && dvu_cmp_hour(&s->ev[i], &s->ev[j]) == 0)
            dvu_sum_add(&t, &s->ev[j++]);
        if ((size_t)groups++ < DVU_MAX_HOURS) {
            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            (void)json_push_kv_str(&row, "hour", s->ev[i].hour);
            dvu_push_group_head(&row, &s->ev[i]);
            dvu_push_sum(&row, &t, false);
            (void)json_push_back(&arr, &row);
            json_free(&row);
        }
        i = j;
    }
    (void)json_push_kv_int(usage, "hours_total", groups);
    (void)json_push_kv(usage, "by_hour", &arr);
    json_free(&arr);
}

static void dvu_scan_free(struct dvu_scan *s)
{
    for (size_t i = 0; i < s->n; i++) {
        free(s->ev[i].id);
        free(s->ev[i].model);
    }
    free(s->ev);
}

static void dvu_push_counts(struct json_value *usage, const struct dvu_scan *s,
                            int64_t duplicates)
{
    (void)json_push_kv_int(usage, "files", s->files);
    (void)json_push_kv_int(usage, "lines", s->lines);
    (void)json_push_kv_int(usage, "usage_lines", s->usage_lines);
    (void)json_push_kv_int(usage, "malformed", s->malformed);
    (void)json_push_kv_int(usage, "unreadable", s->unreadable);
    (void)json_push_kv_int(usage, "unkeyed", s->unkeyed);
    (void)json_push_kv_int(usage, "events", (int64_t)s->n);
    (void)json_push_kv_int(usage, "duplicate_lines", duplicates);
    (void)json_push_kv_bool(usage, "truncated", s->truncated);
}

/* ── entry ───────────────────────────────────────────────────────────── */

/* The usage_log path; NULL when the key is absent (nothing to do) or after
 * failing the reply. */
static const char *dvu_path(const struct json_value *input,
                            struct zcl_command_reply *reply, struct stat *st)
{
    const struct json_value *v = dvu_get(input, "usage_log");
    if (!v)
        return NULL;
    const char *path = v->type == JSON_STR ? json_get_str(v) : NULL;
    if (!path || !path[0]) {
        dvu_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT",
                 "input key 'usage_log' must be a nonempty path");
        return NULL;
    }
    char msg[DVU_PATH_MAX + 96];
    if (stat(path, st) != 0) {
        (void)snprintf(msg, sizeof(msg), "usage_log '%s' cannot be read: %s",
                       path, strerror(errno));
        dvu_fail(reply, ZCL_COMMAND_EXIT_INVALID,
                 errno == ENOENT ? "USAGE_LOG_NOT_FOUND" : "USAGE_LOG_UNREADABLE",
                 msg);
        return NULL;
    }
    if (!S_ISDIR(st->st_mode) && !S_ISREG(st->st_mode)) {
        (void)snprintf(msg, sizeof(msg),
                       "usage_log '%s' is neither a file nor a directory", path);
        dvu_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT", msg);
        return NULL;
    }
    return path;
}

void dvu_push_usage(const struct json_value *input, const char *model,
                    const char *since, struct zcl_command_reply *reply)
{
    struct stat st;
    const char *path = reply ? dvu_path(input, reply, &st) : NULL;
    if (!path)
        return;
    struct dvu_scan s;
    memset(&s, 0, sizeof(s));
    s.model = model;
    s.since = since;
    if (S_ISDIR(st.st_mode))
        dvu_walk(&s, path, 0);
    else
        dvu_read_file(&s, path);
    if (s.alloc_failed) {
        dvu_scan_free(&s);
        dvu_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                 "out of memory while reading usage_log");
        return;
    }
    int64_t duplicates = dvu_dedup(&s);
    struct json_value usage;
    json_init(&usage);
    json_set_object(&usage);
    (void)json_push_kv_str(&usage, "usage_log", path);
    dvu_push_counts(&usage, &s, duplicates);
    dvu_push_by_model(&usage, &s);
    dvu_push_by_hour(&usage, &s);
    (void)json_push_kv(&reply->data, "usage", &usage);
    json_free(&usage);
    dvu_scan_free(&s);
}
