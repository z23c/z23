/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land.window: the two-lander LAND-WINDOW mail protocol.
 *
 * WINDOW ROW. The mail body, exactly:
 *   "LAND-WINDOW <host>, candidate <sha10> on base <sha10>, proving now,
 *    expected done HH:MMZ."
 * A window is closed by a LATER row from the same sender (same `from`, larger
 * seq) whose body starts "LANDED" or "RELEASED" and contains the candidate.
 *
& through the pull action of dev.agent.mail
 *          (all jsonl streams, paged by next_since), collects windows that a
 *          host other than --host announced, drops the closed and expired
 *          ones, and reports open_windows plus max_seconds_left (0 when
 *          none); an optional base (7-40 hex) keeps only windows proving on that base, so a lander can defer a proof start. The expected-done time lies on the row's UTC date, or on
 *          the next day when that would be earlier than the row's own ts.
 *          Rows the mail reader or this leaf cannot parse are counted in
 *          `skipped`, never fatal. `now` (epoch seconds) overrides the clock.
 * announce Posts the window row once (kind=note, to=*, ref=astra-board-runs)
 *          through the dev.agent.mail post action. The row carries no seq, so
 *          the once-per-announcement key is host + candidate + base: the
 *          outbox is searched for that exact prior row and, when found,
 *          nothing is posted and already_announced=true is reported (ok).
 *          `seq` is the lander's own announcement counter, echoed back.
 */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "platform/state_root.h"
#include "platform/time_compat.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LW_REF "astra-board-runs"
#define LW_SHA_SHOW 10u
#define LW_SHA_MIN 7u
#define LW_SHA_MAX 40u
#define LW_HOST_MAX 64u
#define LW_FROM_MAX 128u
#define LW_MAX_WINDOWS 128u
#define LW_MAX_CLOSERS 512u
#define LW_LINE_CAP 16384
#define LW_CLOSER_BODY 192u
#define LW_BODY_CAP 4200u

struct lw_window {
    char host[LW_HOST_MAX + 1];
    char cand[LW_SHA_SHOW + 1];
    char base[LW_SHA_SHOW + 1];
    char from[LW_FROM_MAX + 1];
    char ts[24];
    long long seq;
    int64_t row_epoch;
    int64_t done_epoch;
};

struct lw_closer {
    char from[LW_FROM_MAX + 1];
    char ts[24];
    char body[LW_CLOSER_BODY + 1];
    long long seq;
};

/* The mail leaf's handler is held as a pointer (as dev.agent.mail.wait does):
 * this leaf posts one fixed row and reads no pull keys of its own. */
static const zcl_command_handler_fn lw_mail_handler =
    zcl_native_handle_dev_agent_mail;

struct lw_row {
    char ts[24];
    char from[LW_FROM_MAX + 1];
    char body[LW_BODY_CAP];
    long long seq;
};

struct lw_scan {
    struct lw_window win[LW_MAX_WINDOWS];
    struct lw_closer cls[LW_MAX_CLOSERS];
    size_t nwin;
    size_t ncls;
    int64_t skipped;
    int64_t dropped;
};

static void lw_invalid(struct zcl_command_reply *reply, const char *msg,
                       const char *evidence)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                           ZCL_COMMAND_EXIT_INVALID, "INVALID_INPUT",
                           "normalize", false, false, msg, evidence);
}

/* ── strict token parsers ─────────────────────────────────────────────── */

static const char *lw_eat(const char *p, const char *lit)
{
    size_t n = strlen(lit);
    return p && strncmp(p, lit, n) == 0 ? p + n : NULL;
}

static bool lw_host_ok(const char *s)
{
    size_t n = s ? strlen(s) : 0;
    if (n == 0 || n > LW_HOST_MAX)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)s[i]) && s[i] != '.' && s[i] != '-' &&
            s[i] != '_')
            return false;
    return true;
}

/* sha of LW_SHA_MIN..LW_SHA_MAX hex digits ending at `stop` (or NUL). */
static bool lw_sha_ok(const char *s, size_t n)
{
    if (n < LW_SHA_MIN || n > LW_SHA_MAX)
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isxdigit((unsigned char)s[i]))
            return false;
    return true;
}

/* Copy the run up to `stop` into out (cap bytes, NUL-terminated); returns
 * the pointer at `stop`, or NULL when the run is empty, too long or has no
 * stop byte. */
static const char *lw_run(const char *p, char stop, char *out, size_t cap)
{
    const char *e = p ? strchr(p, stop) : NULL;
    size_t n;
    if (!e || e == p)
        return NULL;
    n = (size_t)(e - p);
    if (n >= cap)
        return NULL;
    memcpy(out, p, n);
    out[n] = '\0';
    return e;
}

/* Strict HH:MMZ -> minutes since midnight, -1 when malformed. */
static int lw_hhmm(const char *p)
{
    if (!p || !isdigit((unsigned char)p[0]) || !isdigit((unsigned char)p[1]) ||
        p[2] != ':' || !isdigit((unsigned char)p[3]) ||
        !isdigit((unsigned char)p[4]) || p[5] != 'Z')
        return -1;
    int h = (p[0] - '0') * 10 + (p[1] - '0');
    int m = (p[3] - '0') * 10 + (p[4] - '0');
    return h > 23 || m > 59 ? -1 : h * 60 + m;
}

static void lw_short(char *dst, const char *sha)
{
    size_t n = strlen(sha);
    if (n > LW_SHA_SHOW)
        n = LW_SHA_SHOW;
    memcpy(dst, sha, n);
    dst[n] = '\0';
}

/* Parse a window body. *minutes is the expected-done minute of the day. */
static bool lw_parse_body(const char *body, struct lw_window *w, int *minutes)
{
    char cand[LW_SHA_MAX + 2], base[LW_SHA_MAX + 2];
    const char *p = lw_eat(body, "LAND-WINDOW ");
    p = p ? lw_run(p, ',', w->host, sizeof(w->host)) : NULL;
    p = p ? lw_eat(p, ", candidate ") : NULL;
    p = p ? lw_run(p, ' ', cand, sizeof(cand)) : NULL;
    p = p ? lw_eat(p, " on base ") : NULL;
    p = p ? lw_run(p, ',', base, sizeof(base)) : NULL;
    p = p ? lw_eat(p, ", proving now, expected done ") : NULL;
    if (!p || !lw_host_ok(w->host) || !lw_sha_ok(cand, strlen(cand)) ||
        !lw_sha_ok(base, strlen(base)))
        return false;
    *minutes = lw_hhmm(p);
    if (*minutes < 0 || p[6] != '.' || p[7] != '\0')
        return false;
    lw_short(w->cand, cand);
    lw_short(w->base, base);
    return true;
}

/* Days since 1970-01-01 of a proleptic Gregorian civil date. */
static int64_t lw_days(int64_t y, unsigned m, unsigned d)
{
    int64_t era, yoe, doy, doe;
    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = y - era * 400;
    doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + doe - 719468;
}

static bool lw_digits(const char *p, int n, int *out)
{
    int v = 0;
    for (int i = 0; i < n; i++) {
        if (!isdigit((unsigned char)p[i]))
            return false;
        v = v * 10 + (p[i] - '0');
    }
    *out = v;
    return true;
}

/* "YYYY-MM-DDTHH:MM:SSZ" -> epoch seconds and the day's midnight epoch. */
static bool lw_ts_epoch(const char *ts, int64_t *epoch, int64_t *midnight)
{
    static const int at[6] = {0, 5, 8, 11, 14, 17};
    static const int width[6] = {4, 2, 2, 2, 2, 2};
    static const int lo[6] = {0, 1, 1, 0, 0, 0};
    static const int hi[6] = {9999, 12, 31, 23, 59, 60};
    static const char seps[] = "--T::";
    int f[6];
    if (strlen(ts) < 19)
        return false;
    for (int i = 0; i < 5; i++)
        if (ts[at[i + 1] - 1] != seps[i])
            return false;
    for (int i = 0; i < 6; i++)
        if (!lw_digits(ts + at[i], width[i], &f[i]) || f[i] < lo[i] ||
            f[i] > hi[i])
            return false;
    *midnight = lw_days(f[0], (unsigned)f[1], (unsigned)f[2]) * 86400;
    *epoch = *midnight + f[3] * 3600 + f[4] * 60 + f[5];
    return true;
}

/* ── mail scan ──────────────────────────────────────────────────────────
 * The mail reader pages 16 KiB at a time (hundreds of pages for a real
 * history), so this leaf reads each jsonl stream under the mail dir once,
 * line by line, and parses only the rows that can matter. Fields are cut
 * with the same key-pattern reader the mail leaf uses for its own rows. */

/* Copy the string value of "key":"..." out of a row line (\" and \\ are
 * decoded, other escapes keep their second byte). */
static bool lw_field_str(const char *line, const char *key, char *out,
                         size_t cap)
{
    char pat[32];
    const char *p;
    size_t used = 0;
    (void)snprintf(pat, sizeof(pat), "\"%s\":\"", key);
    p = strstr(line, pat);
    if (!p)
        return false;
    for (p += strlen(pat); *p && *p != '"'; p++) {
        if (*p == '\\' && p[1])
            p++;
        if (used + 1 >= cap)
            return false;
        out[used++] = *p;
    }
    out[used] = '\0';
    return *p == '"';
}

static bool lw_field_int(const char *line, const char *key, long long *out)
{
    char pat[32];
    const char *p;
    char *end = NULL;
    (void)snprintf(pat, sizeof(pat), "\"%s\":", key);
    p = strstr(line, pat);
    if (!p)
        return false;
    *out = strtoll(p + strlen(pat), &end, 10);
    return end && end != p + strlen(pat) && *out >= 0;
}

static void lw_collect_window(struct lw_scan *sc, const struct lw_row *r)
{
    struct lw_window *w;
    int minutes;
    int64_t midnight;
    if (sc->nwin >= LW_MAX_WINDOWS) {
        sc->dropped++;
        return;
    }
    w = &sc->win[sc->nwin];
    memset(w, 0, sizeof(*w));
    (void)snprintf(w->from, sizeof(w->from), "%s", r->from);
    (void)snprintf(w->ts, sizeof(w->ts), "%s", r->ts);
    w->seq = r->seq;
    if (!lw_parse_body(r->body, w, &minutes) ||
        !lw_ts_epoch(w->ts, &w->row_epoch, &midnight)) {
        sc->skipped++;
        return;
    }
    w->done_epoch = midnight + (int64_t)minutes * 60;
    if (w->done_epoch < w->row_epoch)
        w->done_epoch += 86400;
    sc->nwin++;
}

static void lw_collect_closer(struct lw_scan *sc, const struct lw_row *r)
{
    struct lw_closer *c;
    if (sc->ncls >= LW_MAX_CLOSERS) {
        sc->dropped++;
        return;
    }
    c = &sc->cls[sc->ncls++];
    (void)snprintf(c->from, sizeof(c->from), "%s", r->from);
    (void)snprintf(c->ts, sizeof(c->ts), "%s", r->ts);
    (void)snprintf(c->body, sizeof(c->body), "%s", r->body);
    c->seq = r->seq;
}

static bool lw_line_relevant(const char *line)
{
    return strstr(line, "\"body\":\"LAND-WINDOW ") ||
           strstr(line, "\"body\":\"LANDED") ||
           strstr(line, "\"body\":\"RELEASED");
}

static void lw_scan_line(struct lw_scan *sc, const char *line)
{
    struct lw_row r;
    long long seq = 0;
    if (line[0] == '\0' || line[0] == '\n')
        return;
    if (line[0] != '{') {
        sc->skipped++;
        return;
    }
    if (!lw_line_relevant(line))
        return;
    if (!lw_field_int(line, "seq", &seq) ||
        !lw_field_str(line, "ts", r.ts, sizeof(r.ts)) ||
        !lw_field_str(line, "from", r.from, sizeof(r.from)) ||
        !lw_field_str(line, "body", r.body, sizeof(r.body))) {
        sc->skipped++;
        return;
    }
    r.seq = seq;
    if (strncmp(r.body, "LAND-WINDOW ", 12) == 0)
        lw_collect_window(sc, &r);
    else
        lw_collect_closer(sc, &r);
}

static void lw_scan_file(struct lw_scan *sc, const char *path)
{
    static char line[LW_LINE_CAP];
    bool tail = false;
    FILE *f = fopen(path, "r");
    if (!f)
        return;
    while (fgets(line, sizeof(line), f)) {
        bool full = strchr(line, '\n') != NULL;
        if (!tail)
            lw_scan_line(sc, line);
        tail = !full;
    }
    (void)fclose(f);
}

static bool lw_is_stream(const char *name)
{
    size_t n = strlen(name);
    return n > 6 && n < 128 && strcmp(name + n - 6, ".jsonl") == 0;
}

static bool lw_scan_mail(struct lw_scan *sc, struct zcl_command_reply *reply)
{
    char state[4096], dir[4200], path[4400];
    struct dirent *ent;
    DIR *d;
    if (!platform_state_root_existing(state, sizeof(state)))
        return true;
    (void)snprintf(dir, sizeof(dir), "%s/mail", state);
    d = opendir(dir);
    if (!d) {
        if (errno == ENOENT)
            return true;
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "MAIL_READ_FAILED",
                               "scan", true, false,
                               "cannot read the mail dir", "mail");
        return false;
    }
    while ((ent = readdir(d)) != NULL)
        if (lw_is_stream(ent->d_name) &&
            snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name) <
                (int)sizeof(path))
            lw_scan_file(sc, path);
    (void)closedir(d);
    return true;
}

/* ── open ─────────────────────────────────────────────────────────────── */

static bool lw_closed(const struct lw_scan *sc, const struct lw_window *w)
{
    for (size_t i = 0; i < sc->ncls; i++) {
        const struct lw_closer *c = &sc->cls[i];
        if (strcmp(c->from, w->from) == 0 && c->seq > w->seq &&
            strcmp(c->ts, w->ts) >= 0 && strstr(c->body, w->cand))
            return true;
    }
    return false;
}

static void lw_push_window(struct json_value *arr, const struct lw_window *w,
                           int64_t left)
{
    struct json_value item;
    json_init(&item);
    json_set_object(&item);
    (void)json_push_kv_str(&item, "host", w->host);
    (void)json_push_kv_str(&item, "candidate", w->cand);
    (void)json_push_kv_str(&item, "base", w->base);
    (void)json_push_kv_int(&item, "expected_done_epoch", w->done_epoch);
    (void)json_push_kv_int(&item, "seconds_left", left);
    (void)json_push_kv_int(&item, "seq", w->seq);
    (void)json_push_back(arr, &item);
    json_free(&item);
}

static void lw_report_open(const struct lw_scan *sc, const char *host,
                           const char *base, int64_t now,
                           struct zcl_command_reply *reply)
{
    struct json_value arr;
    int64_t max_left = 0;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < sc->nwin; i++) {
        const struct lw_window *w = &sc->win[i];
        int64_t left = w->done_epoch - now;
        if (strcmp(w->host, host) == 0 || left <= 0 || lw_closed(sc, w) ||
            (base[0] && strcmp(w->base, base) != 0))
            continue;
        lw_push_window(&arr, w, left);
        if (left > max_left)
            max_left = left;
    }
    (void)json_push_kv_str(&reply->data, "leaf", "dev.land.window");
    (void)json_push_kv_str(&reply->data, "action", "open");
    (void)json_push_kv(&reply->data, "open_windows", &arr);
    json_free(&arr);
    (void)json_push_kv_int(&reply->data, "max_seconds_left", max_left);
    (void)json_push_kv_int(&reply->data, "skipped", sc->skipped);
    (void)json_push_kv_int(&reply->data, "dropped", sc->dropped);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static const char *lw_input_str(const struct zcl_command_request *req,
                                const char *key)
{
    const struct json_value *v =
        req && req->input ? json_get(req->input, key) : NULL;
    return v && v->type == JSON_STR && json_get_str(v) &&
                   json_get_str(v)[0]
               ? json_get_str(v)
               : NULL;
}

/* Integer input accepted as JSON int or decimal string; false when absent
 * or malformed. */
static bool lw_input_int(const struct zcl_command_request *req,
                         const char *key, int64_t *out)
{
    const struct json_value *v =
        req && req->input ? json_get(req->input, key) : NULL;
    char *end = NULL;
    long long n;
    if (v && v->type == JSON_INT) {
        *out = json_get_int(v);
        return *out >= 0;
    }
    if (!v || v->type != JSON_STR || !json_get_str(v) || !json_get_str(v)[0])
        return false;
    n = strtoll(json_get_str(v), &end, 10);
    if (!end || *end != '\0' || n < 0)
        return false;
    *out = n;
    return true;
}

static void lw_open(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply)
{
    const char *host = lw_input_str(request, "host");
    const struct json_value *nowv =
        request->input ? json_get(request->input, "now") : NULL;
    struct lw_scan *sc;
    int64_t now = platform_time_wall_unix();
    const char *base = lw_input_str(request, "base");
    char base10[LW_SHA_SHOW + 1] = "";
    if (!host || !lw_host_ok(host)) {
        lw_invalid(reply, "host is 1-64 of [A-Za-z0-9._-]", "input.host");
        return;
    }
    if (base && !lw_sha_ok(base, strlen(base))) {
        lw_invalid(reply, "base is 7-40 hex digits", "input.base");
        return;
    }
    if (base)
        lw_short(base10, base);
    if (nowv && nowv->type != JSON_NULL &&
        !lw_input_int(request, "now", &now)) {
        lw_invalid(reply, "now is a non-negative epoch in seconds",
                   "input.now");
        return;
    }
    sc = (struct lw_scan *)zcl_calloc(1, sizeof(*sc), "dev_land_window.scan");
    if (!sc) {
        lw_invalid(reply, "cannot allocate the scan", "oom");
        return;
    }
    if (lw_scan_mail(sc, reply))
        lw_report_open(sc, host, base10, now, reply);
    free(sc);
}

/* ── announce ─────────────────────────────────────────────────────────── */

struct lw_announce {
    const char *host;
    char cand[LW_SHA_SHOW + 1];
    char base[LW_SHA_SHOW + 1];
    const char *expected;
    int64_t seq;
};

static bool lw_announce_args(const struct zcl_command_request *req,
                             struct lw_announce *a,
                             struct zcl_command_reply *reply)
{
    const char *cand = lw_input_str(req, "candidate");
    const char *base = lw_input_str(req, "base");
    a->host = lw_input_str(req, "host");
    a->expected = lw_input_str(req, "expected_done");
    if (!a->host || !lw_host_ok(a->host)) {
        lw_invalid(reply, "host is 1-64 of [A-Za-z0-9._-]", "input.host");
    } else if (!lw_input_int(req, "seq", &a->seq) || a->seq < 1) {
        lw_invalid(reply, "seq is a positive integer", "input.seq");
    } else if (!cand || !lw_sha_ok(cand, strlen(cand))) {
        lw_invalid(reply, "candidate is 7-40 hex digits", "input.candidate");
    } else if (!base || !lw_sha_ok(base, strlen(base))) {
        lw_invalid(reply, "base is 7-40 hex digits", "input.base");
    } else if (!a->expected || strlen(a->expected) != 6 ||
               lw_hhmm(a->expected) < 0) {
        lw_invalid(reply, "expected_done is HH:MMZ", "input.expected_done");
    } else {
        lw_short(a->cand, cand);
        lw_short(a->base, base);
        return true;
    }
    return false;
}

static bool lw_outbox_path(char *out, size_t cap)
{
    char state[4096];
    int n;
    if (!platform_state_root_existing(state, sizeof(state)))
        return false;
    n = snprintf(out, cap, "%s/mail/outbox.jsonl", state);
    return n > 0 && (size_t)n < cap;
}

/* True when the private outbox already holds this exact window row. Lines
 * longer than the buffer are skipped whole. */
static bool lw_prior_row(const struct lw_announce *a)
{
    char path[4200], needle[256], line[LW_LINE_CAP];
    bool found = false, cont = false;
    FILE *f;
    (void)snprintf(needle, sizeof(needle),
                   "\"body\":\"LAND-WINDOW %s, candidate %s on base %s,",
                   a->host, a->cand, a->base);
    if (!lw_outbox_path(path, sizeof(path)) || !(f = fopen(path, "r")))
        return false;
    while (!found && fgets(line, sizeof(line), f)) {
        bool full = strchr(line, '\n') != NULL;
        found = !cont && strstr(line, needle) != NULL;
        cont = !full;
    }
    (void)fclose(f);
    return found;
}

static void lw_announce_fields(struct zcl_command_reply *reply,
                               const struct lw_announce *a, bool already)
{
    (void)json_push_kv_str(&reply->data, "leaf", "dev.land.window");
    (void)json_push_kv_str(&reply->data, "action", "announce");
    (void)json_push_kv_str(&reply->data, "host", a->host);
    (void)json_push_kv_int(&reply->data, "seq", a->seq);
    (void)json_push_kv_str(&reply->data, "candidate", a->cand);
    (void)json_push_kv_str(&reply->data, "base", a->base);
    (void)json_push_kv_str(&reply->data, "expected_done", a->expected);
    (void)json_push_kv_bool(&reply->data, "already_announced", already);
    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = 0;
}

static bool lw_post(const struct zcl_command_request *request,
                    const struct lw_announce *a,
                    struct zcl_command_reply *reply)
{
    struct zcl_command_request sub = *request;
    struct zcl_command_reply post;
    struct json_value pargs;
    char body[LW_BODY_CAP];
    (void)snprintf(body, sizeof(body),
                   "LAND-WINDOW %s, candidate %s on base %s, proving now, "
                   "expected done %s.",
                   a->host, a->cand, a->base, a->expected);
    json_init(&pargs);
    json_set_object(&pargs);
    (void)json_push_kv_str(&pargs, "action", "post");
    (void)json_push_kv_str(&pargs, "to", "*");
    (void)json_push_kv_str(&pargs, "kind", "note");
    (void)json_push_kv_str(&pargs, "ref", LW_REF);
    (void)json_push_kv_str(&pargs, "body", body);
    sub.input = &pargs;
    zcl_command_reply_init(&post, "zcl.agent_mail.v1");
    lw_mail_handler(&sub, &post);
    json_free(&pargs);
    if (post.status != ZCL_COMMAND_STATUS_PASSED) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_FAILED, "MAIL_POST_FAILED",
                               "post", true, false, "mail post refused",
                               post.error.code);
        zcl_command_reply_free(&post);
        return false;
    }
    (void)json_push_kv_int(&reply->data, "mail_seq",
                           json_get_int(json_get(&post.data, "seq")));
    (void)json_push_kv_str(&reply->data, "body", body);
    zcl_command_reply_free(&post);
    return true;
}

static void lw_announce(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply)
{
    struct lw_announce a;
    memset(&a, 0, sizeof(a));
    if (!lw_announce_args(request, &a, reply))
        return;
    if (lw_prior_row(&a)) {
        lw_announce_fields(reply, &a, true);
        return;
    }
    if (lw_post(request, &a, reply))
        lw_announce_fields(reply, &a, false);
}

void zcl_native_handle_dev_land_window(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *action;
    if (!reply)
        return;
    action = lw_input_str(request, "action");
    if (action && strcmp(action, "open") == 0)
        lw_open(request, reply);
    else if (action && strcmp(action, "announce") == 0)
        lw_announce(request, reply);
    else
        lw_invalid(reply, "action is open or announce", "input.action");
}
