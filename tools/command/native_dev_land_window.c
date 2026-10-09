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
 * open     Reads every jsonl stream under the mail dir, collects windows
 *          that a host other than --host announced, drops the closed ones
 *          and those past expected-done + grace_s (default 0), and reports
 *          open_windows (seconds_left is negative inside the grace) plus
 *          max_seconds_left (0 when none); an optional base (7-40 hex)
 *          keeps only windows proving on that base. The expected-done time
 *          lies on the row's UTC date, or on the next day when that would be
 *          earlier than the row's own ts. Rows this leaf cannot parse are
 *          counted in `skipped`, never fatal. `now` (epoch seconds)
 *          overrides the clock.
 * announce Posts the window row once (kind=note, to=*, ref=astra-board-runs)
 *          through the dev.agent.mail post action. The row carries no seq, so
 *          the once-per-announcement key is host + candidate + base: the
 *          outbox is searched for that exact prior row and, when found,
 *          nothing is posted and already_announced=true is reported (ok).
 *          `seq` is the lander's own announcement counter, echoed back.
 *
 * LANDER SIDE (native_dev_land_window.h). dev.land defers a proof start
 * while a foreign window on its base is open, announces its own window with
 * an estimate measured from this host's proof attempts, re-announces when
 * the proof outlives it, and closes it with LANDED or RELEASED. Its own
 * window lives in a sidecar file, so each (candidate, base) is announced
 * once and closed once.
 */

#include "command/native_command.h"
#include "command/native_dev_land_window.h"

#include "base/safe_alloc.h"
#include "config/command_catalog.h"
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
#include <sys/stat.h>

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

/* A later window row from the same sender for the same pair supersedes this
 * one: it is the re-announcement with a fresh expected-done. */
static bool lw_superseded(const struct lw_scan *sc, const struct lw_window *w)
{
    for (size_t i = 0; i < sc->nwin; i++) {
        const struct lw_window *o = &sc->win[i];
        if (o != w && o->seq > w->seq && strcmp(o->from, w->from) == 0 &&
            strcmp(o->host, w->host) == 0 && strcmp(o->cand, w->cand) == 0 &&
            strcmp(o->base, w->base) == 0)
            return true;
    }
    return false;
}

/* Another host's window, on `base10` when given, neither closed nor
 * superseded. Expiry is the caller's. */
static bool lw_counts(const struct lw_scan *sc, const struct lw_window *w,
                      const char *host, const char *base10)
{
    return strcmp(w->host, host) != 0 &&
           (!base10[0] || strcmp(w->base, base10) == 0) &&
           !lw_closed(sc, w) && !lw_superseded(sc, w);
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
                           const char *base, int64_t now, int64_t grace,
                           struct zcl_command_reply *reply)
{
    struct json_value arr;
    int64_t max_left = 0;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < sc->nwin; i++) {
        const struct lw_window *w = &sc->win[i];
        int64_t left = w->done_epoch - now;
        if (left <= -grace || !lw_counts(sc, w, host, base))
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

/* `now` (default the wall clock) and `grace_s` (default 0, at most a day). */
static bool lw_open_clock(const struct zcl_command_request *request,
                          int64_t *now, int64_t *grace,
                          struct zcl_command_reply *reply)
{
    const struct json_value *nowv =
        request->input ? json_get(request->input, "now") : NULL;
    const struct json_value *gv =
        request->input ? json_get(request->input, "grace_s") : NULL;
    *now = platform_time_wall_unix();
    *grace = 0;
    if (nowv && nowv->type != JSON_NULL &&
        !lw_input_int(request, "now", now)) {
        lw_invalid(reply, "now is a non-negative epoch in seconds",
                   "input.now");
        return false;
    }
    if (gv && gv->type != JSON_NULL &&
        (!lw_input_int(request, "grace_s", grace) || *grace > 86400)) {
        lw_invalid(reply, "grace_s is 0-86400 seconds", "input.grace_s");
        return false;
    }
    return true;
}

static void lw_open(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply)
{
    const char *host = lw_input_str(request, "host");
    struct lw_scan *sc;
    int64_t now = 0, grace = 0;
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
    if (!lw_open_clock(request, &now, &grace, reply))
        return;
    sc = (struct lw_scan *)zcl_calloc(1, sizeof(*sc), "dev_land_window.scan");
    if (!sc) {
        lw_invalid(reply, "cannot allocate the scan", "oom");
        return;
    }
    if (lw_scan_mail(sc, reply))
        lw_report_open(sc, host, base10, now, grace, reply);
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

/* ── lander side: measured estimate ───────────────────────────────────────
 * A proof attempt dir is named <local40>-<base40>.<suffix>. Its `request`
 * holds the request epoch on line 4; phases.txt is appended as each step
 * finishes, so its last write is the end of the proof. Only attempts whose
 * phases.txt records a `step=test` row ran the suite: refusals and
 * superseded starts never do and stay out of the sample. */

#define LW_ATTEMPT_CAP 4096u
#define LW_ATTEMPT_SCAN 400u
#define LW_ATTEMPT_NAME 128u
#define LW_WALL_MAX (24 * 3600)

struct lw_attempt {
    int64_t start;
    char name[LW_ATTEMPT_NAME];
};

static bool lw_attempt_name(const char *n)
{
    size_t len = strlen(n);
    return len > 82 && len < LW_ATTEMPT_NAME && n[40] == '-' && n[81] == '.' &&
           lw_sha_ok(n, 40) && lw_sha_ok(n + 41, 40);
}

static bool lw_attempts_dir(const char *root, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/.cache/zcl-dev-proof/attempts", root);
    return root && n > 0 && (size_t)n < cap;
}

/* Line 4 of <dir>/request as a positive epoch. */
static bool lw_request_start(const char *dir, int64_t *start)
{
    char path[4400], line[128];
    long long v = 0;
    char *end = NULL;
    int at = 0;
    FILE *f;
    if (snprintf(path, sizeof(path), "%s/request", dir) >= (int)sizeof(path) ||
        !(f = fopen(path, "r")))
        return false;
    while (at < 4 && fgets(line, sizeof(line), f))
        at++;
    (void)fclose(f);
    if (at != 4)
        return false;
    v = strtoll(line, &end, 10);
    if (!end || end == line || (*end != '\n' && *end != '\0') || v <= 0)
        return false;
    *start = v;
    return true;
}

static int lw_attempt_newer(const void *a, const void *b)
{
    const struct lw_attempt *x = a, *y = b;
    return x->start < y->start ? 1 : x->start > y->start ? -1 : 0;
}

/* Every well-named attempt with a readable start, newest first. `prefix`
 * (may be NULL) keeps only names starting with it. */
static size_t lw_attempts_list(const char *root, const char *prefix,
                               struct lw_attempt *out, size_t cap)
{
    char dir[4200], sub[4400];
    struct dirent *ent;
    size_t n = 0;
    DIR *d;
    if (!lw_attempts_dir(root, dir, sizeof(dir)) || !(d = opendir(dir)))
        return 0;
    while (n < cap && (ent = readdir(d)) != NULL) {
        if (!lw_attempt_name(ent->d_name) ||
            (prefix && strncmp(ent->d_name, prefix, strlen(prefix)) != 0) ||
            snprintf(sub, sizeof(sub), "%s/%s", dir, ent->d_name) >=
                (int)sizeof(sub) ||
            !lw_request_start(sub, &out[n].start))
            continue;
        (void)snprintf(out[n].name, sizeof(out[n].name), "%s", ent->d_name);
        n++;
    }
    (void)closedir(d);
    qsort(out, n, sizeof(*out), lw_attempt_newer);
    return n;
}

static bool lw_attempt_path(const char *root, const struct lw_attempt *a,
                            const char *leaf, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/.cache/zcl-dev-proof/attempts/%s%s%s",
                     root, a->name, leaf ? "/" : "", leaf ? leaf : "");
    return n > 0 && (size_t)n < cap;
}

/* The real proof's wall, or false for an attempt that never ran the suite. */
static bool lw_attempt_wall(const char *root, const struct lw_attempt *a,
                            int64_t *wall)
{
    char path[4600], line[512];
    bool real = false, cont = false;
    struct stat st;
    FILE *f;
    if (!lw_attempt_path(root, a, "phases.txt", path, sizeof(path)) ||
        !(f = fopen(path, "r")))
        return false;
    while (!real && fgets(line, sizeof(line), f)) {
        real = !cont && strncmp(line, "step=test ", 10) == 0 &&
               strstr(line, " elapsed_ms=") != NULL;
        cont = strchr(line, '\n') == NULL;
    }
    (void)fclose(f);
    if (!real || stat(path, &st) != 0)
        return false;
    *wall = (int64_t)st.st_mtime - a->start;
    return *wall > 0 && *wall <= LW_WALL_MAX;
}

/* "exact" or "universal" from logs/<name>.test-selection.log. */
static bool lw_attempt_selection(const char *root, const struct lw_attempt *a,
                                 char shape[12])
{
    char path[4600], line[256], want[LW_ATTEMPT_NAME + 32];
    size_t pair = strcspn(a->name, ".");
    FILE *f;
    (void)snprintf(want, sizeof(want), "logs/%.*s.test-selection.log",
                   (int)pair, a->name);
    if (!lw_attempt_path(root, a, want, path, sizeof(path)) ||
        !(f = fopen(path, "r")))
        return false;
    bool got = fgets(line, sizeof(line), f) != NULL;
    (void)fclose(f);
    if (!got || strncmp(line, "test_selection=", 15) != 0)
        return false;
    size_t n = strcspn(line + 15, " \n");
    if ((n != 5 || strncmp(line + 15, "exact", 5) != 0) &&
        (n != 9 || strncmp(line + 15, "universal", 9) != 0))
        return false;
    (void)snprintf(shape, 12, "%.*s", (int)n, line + 15);
    return true;
}

static int lw_wall_order(const void *a, const void *b)
{
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

/* Nearest-rank percentile of a sorted sample. */
static int64_t lw_rank(const int64_t *sorted, int n, int pct)
{
    int idx = (pct * n + 99) / 100 - 1;
    return sorted[idx < 0 ? 0 : idx];
}

static void lw_estimate_fill(int64_t *walls, int n, const char *shape,
                             struct zcl_land_window_estimate *out)
{
    out->samples = n;
    (void)snprintf(out->shape, sizeof(out->shape), "%s", shape);
    if (n < ZCL_LAND_WINDOW_MIN_SAMPLES)
        return;
    qsort(walls, (size_t)n, sizeof(*walls), lw_wall_order);
    out->measured = true;
    out->p75_s = lw_rank(walls, n, 75);
    out->p90_s = lw_rank(walls, n, 90);
    out->max_s = walls[n - 1];
    out->seconds = out->p75_s < ZCL_LAND_WINDOW_FLOOR_S ? ZCL_LAND_WINDOW_FLOOR_S
                   : out->p75_s > ZCL_LAND_WINDOW_CEIL_S ? ZCL_LAND_WINDOW_CEIL_S
                                                          : out->p75_s;
}

struct lw_sample {
    int64_t any[ZCL_LAND_WINDOW_SAMPLE];
    int64_t same[ZCL_LAND_WINDOW_SAMPLE];
    int nany;
    int nsame;
};

/* Newest real proofs: up to SAMPLE overall and SAMPLE of `shape`. */
static void lw_sample_collect(const char *root, const char *shape,
                              const struct lw_attempt *a, size_t n,
                              struct lw_sample *s)
{
    char got[12];
    int64_t wall;
    for (size_t i = 0; i < n && i < LW_ATTEMPT_SCAN; i++) {
        bool want_any = s->nany < ZCL_LAND_WINDOW_SAMPLE;
        bool want_same = shape && s->nsame < ZCL_LAND_WINDOW_SAMPLE;
        if (!want_any && !want_same)
            break;
        if (!lw_attempt_wall(root, &a[i], &wall))
            continue;
        if (want_any)
            s->any[s->nany++] = wall;
        if (want_same && lw_attempt_selection(root, &a[i], got) &&
            strcmp(got, shape) == 0)
            s->same[s->nsame++] = wall;
    }
}

void zcl_land_window_estimate(const char *proof_root, const char *shape,
                              struct zcl_land_window_estimate *out)
{
    struct lw_attempt *a;
    struct lw_sample s;
    size_t n;
    memset(out, 0, sizeof(*out));
    out->seconds = out->p75_s = out->p90_s = out->max_s =
        ZCL_LAND_WINDOW_FALLBACK_S;
    (void)snprintf(out->shape, sizeof(out->shape), "%s", "any");
    if (shape && strcmp(shape, "exact") != 0 && strcmp(shape, "universal") != 0)
        shape = NULL;
    a = proof_root ? (struct lw_attempt *)zcl_calloc(
                         LW_ATTEMPT_CAP, sizeof(*a), "dev_land_window.attempts")
                   : NULL;
    if (!a)
        return;
    memset(&s, 0, sizeof(s));
    n = lw_attempts_list(proof_root, NULL, a, LW_ATTEMPT_CAP);
    lw_sample_collect(proof_root, shape, a, n, &s);
    free(a);
    if (shape && s.nsame >= ZCL_LAND_WINDOW_MIN_SAMPLES)
        lw_estimate_fill(s.same, s.nsame, shape, out);
    else
        lw_estimate_fill(s.any, s.nany, "any", out);
}

bool zcl_land_window_attempt_shape(const char *proof_root, const char *local,
                                   const char *base, char shape[12])
{
    char prefix[96];
    struct lw_attempt *a;
    size_t n;
    bool got = false;
    shape[0] = '\0';
    if (!proof_root || !local || !base || strlen(local) != 40 ||
        strlen(base) != 40)
        return false;
    (void)snprintf(prefix, sizeof(prefix), "%s-%s.", local, base);
    a = (struct lw_attempt *)zcl_calloc(64, sizeof(*a),
                                        "dev_land_window.attempt_shape");
    if (!a)
        return false;
    n = lw_attempts_list(proof_root, prefix, a, 64);
    got = n > 0 && lw_attempt_selection(proof_root, &a[0], shape);
    free(a);
    return got;
}

/* ── lander side: foreign windows ─────────────────────────────────────── */

/* Fold one counting window into the hit: past the grace it is stale, else
 * the latest-ending open window names the hit. */
static void lw_hit_take(struct zcl_land_window_hit *hit,
                        const struct lw_window *w, int64_t left,
                        int64_t grace_s)
{
    if (left <= -grace_s) {
        hit->stale++;
        return;
    }
    if (!hit->open || left > hit->seconds_left) {
        (void)snprintf(hit->host, sizeof(hit->host), "%s", w->host);
        (void)snprintf(hit->candidate, sizeof(hit->candidate), "%s", w->cand);
        (void)snprintf(hit->base, sizeof(hit->base), "%s", w->base);
        hit->seconds_left = left;
    }
    hit->open = true;
    hit->open_count++;
}

/* `base` (NULL or empty: any) as its 10-digit display form. */
static bool lw_base_filter(const char *base, char base10[LW_SHA_SHOW + 1])
{
    base10[0] = '\0';
    if (!base || !base[0])
        return true;
    if (!lw_sha_ok(base, strlen(base)))
        return false;
    lw_short(base10, base);
    return true;
}

bool zcl_land_window_foreign(const char *host, const char *base, int64_t now,
                             int64_t grace_s, struct zcl_land_window_hit *hit)
{
    struct zcl_command_reply scratch;
    struct lw_scan *sc;
    char base10[LW_SHA_SHOW + 1];
    bool ok;
    memset(hit, 0, sizeof(*hit));
    if (!host || !lw_host_ok(host) || !lw_base_filter(base, base10))
        return false;
    sc = (struct lw_scan *)zcl_calloc(1, sizeof(*sc), "dev_land_window.scan");
    if (!sc)
        return false;
    zcl_command_reply_init(&scratch, "zcl.land_window.v1");
    ok = lw_scan_mail(sc, &scratch);
    zcl_command_reply_free(&scratch);
    for (size_t i = 0; ok && i < sc->nwin; i++)
        if (lw_counts(sc, &sc->win[i], host, base10))
            lw_hit_take(hit, &sc->win[i], sc->win[i].done_epoch - now,
                        grace_s);
    hit->skipped = sc->skipped;
    free(sc);
    return ok;
}

/* ── lander side: own window ──────────────────────────────────────────── */

#define LW_SELF_SCHEMA "zcl.land_window_self.v1"

struct lw_self_state {
    char cand[LW_SHA_MAX + 1];
    char base[LW_SHA_MAX + 1];
    long long start;
    long long expected;
    long long last;
};

static bool lw_self_read(const char *path, struct lw_self_state *s)
{
    char line[512];
    FILE *f = path ? fopen(path, "r") : NULL;
    bool got;
    if (!f)
        return false;
    got = fgets(line, sizeof(line), f) != NULL;
    (void)fclose(f);
    memset(s, 0, sizeof(*s));
    return got &&
           sscanf(line, LW_SELF_SCHEMA " %40s %40s %lld %lld %lld", s->cand,
                  s->base, &s->start, &s->expected, &s->last) == 5 &&
           lw_sha_ok(s->cand, strlen(s->cand)) &&
           lw_sha_ok(s->base, strlen(s->base));
}

static bool lw_self_write(const char *path, const struct lw_self_state *s)
{
    char tmp[4200];
    FILE *f;
    bool ok;
    if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp) ||
        !(f = fopen(tmp, "w")))
        return false;
    ok = fprintf(f, LW_SELF_SCHEMA " %s %s %lld %lld %lld\n", s->cand, s->base,
                 s->start, s->expected, s->last) > 0;
    ok = fclose(f) == 0 && ok;
    if (ok && rename(tmp, path) == 0)
        return true;
    (void)remove(tmp);
    return false;
}

static int64_t lw_minute_up(int64_t t)
{
    return (t + 59) / 60 * 60;
}

static bool lw_mail_dir_present(void)
{
    char state[4096], dir[4200];
    struct stat st;
    return platform_state_root_existing(state, sizeof(state)) &&
           snprintf(dir, sizeof(dir), "%s/mail", state) < (int)sizeof(dir) &&
           stat(dir, &st) == 0 && S_ISDIR(st.st_mode);
}

/* Post one row as `from`. No mail dir: nothing to coordinate, true. */
static bool lw_post_as(const char *from, const char *body)
{
    struct zcl_command_request sub;
    struct zcl_command_reply post;
    struct json_value args;
    bool ok;
    if (!lw_mail_dir_present())
        return true;
    memset(&sub, 0, sizeof(sub));
    sub.spec = zcl_command_registry_find(zcl_command_catalog(),
                                         "dev.agent.mail", NULL);
    if (!sub.spec)
        return false;
    sub.view = "normal";
    json_init(&args);
    json_set_object(&args);
    ok = json_push_kv_str(&args, "action", "post") &&
         json_push_kv_str(&args, "to", "*") &&
         json_push_kv_str(&args, "kind", "note") &&
         json_push_kv_str(&args, "ref", LW_REF) &&
         json_push_kv_str(&args, "body", body) &&
         json_push_kv_str(&args, "from", from);
    sub.input = &args;
    zcl_command_reply_init(&post, "zcl.agent_mail.v1");
    if (ok)
        lw_mail_handler(&sub, &post);
    ok = ok && post.status == ZCL_COMMAND_STATUS_PASSED;
    zcl_command_reply_free(&post);
    json_free(&args);
    return ok;
}

static bool lw_self_post_window(const struct zcl_land_window_self *self,
                                const struct lw_self_state *s)
{
    char body[512];
    int64_t m = s->expected / 60;
    (void)snprintf(body, sizeof(body),
                   "LAND-WINDOW %s, candidate %.10s on base %.10s, proving "
                   "now, expected done %02d:%02dZ.",
                   self->host, s->cand, s->base, (int)((m / 60) % 24),
                   (int)(m % 60));
    return lw_post_as(self->from, body);
}

static bool lw_self_post_close(const struct zcl_land_window_self *self,
                               const struct lw_self_state *s, bool landed)
{
    char body[512];
    (void)snprintf(body, sizeof(body), "%s %s, candidate %.10s on base %.10s.",
                   landed ? "LANDED" : "RELEASED", self->host, s->cand,
                   s->base);
    return lw_post_as(self->from, body);
}

static bool lw_self_ok(const struct zcl_land_window_self *self)
{
    return self && self->sidecar && self->sidecar[0] && self->from &&
           self->from[0] && lw_host_ok(self->host);
}

static void lw_note(char *note, size_t cap, const char *verb,
                    const struct lw_self_state *s, int64_t expected)
{
    int64_t m = expected / 60;
    if (expected > 0)
        (void)snprintf(note, cap, "%s %.10s on base %.10s, expected done "
                       "%02d:%02dZ", verb, s->cand, s->base,
                       (int)((m / 60) % 24), (int)(m % 60));
    else
        (void)snprintf(note, cap, "%s %.10s on base %.10s", verb, s->cand,
                       s->base);
}

enum zcl_land_window_act zcl_land_window_close(
    const struct zcl_land_window_self *self, const char *keep_candidate,
    const char *keep_base, const char *landed_candidate, char *note,
    size_t cap)
{
    struct lw_self_state s;
    bool landed;
    note[0] = '\0';
    if (!lw_self_ok(self) || !lw_self_read(self->sidecar, &s))
        return ZCL_LAND_WINDOW_NONE;
    if (keep_candidate && keep_base && strcmp(keep_candidate, s.cand) == 0 &&
        strcmp(keep_base, s.base) == 0)
        return ZCL_LAND_WINDOW_NONE;
    landed = landed_candidate && strcmp(landed_candidate, s.cand) == 0;
    if (!lw_self_post_close(self, &s, landed)) {
        lw_note(note, cap, "close post failed for", &s, 0);
        return ZCL_LAND_WINDOW_FAILED;
    }
    (void)remove(self->sidecar);
    lw_note(note, cap, landed ? "LANDED" : "RELEASED", &s, 0);
    return ZCL_LAND_WINDOW_CLOSED;
}

enum zcl_land_window_act zcl_land_window_begin(
    const struct zcl_land_window_self *self, const char *candidate,
    const char *base, int64_t now, const struct zcl_land_window_estimate *est,
    char *note, size_t cap)
{
    struct lw_self_state s;
    char closed[256];
    note[0] = '\0';
    if (!lw_self_ok(self) || !candidate || !base || !est ||
        !lw_sha_ok(candidate, strlen(candidate)) ||
        !lw_sha_ok(base, strlen(base)))
        return ZCL_LAND_WINDOW_FAILED;
    if (lw_self_read(self->sidecar, &s) && strcmp(s.cand, candidate) == 0 &&
        strcmp(s.base, base) == 0)
        return ZCL_LAND_WINDOW_NONE;
    (void)zcl_land_window_close(self, NULL, NULL, NULL, closed,
                                sizeof(closed));
    memset(&s, 0, sizeof(s));
    (void)snprintf(s.cand, sizeof(s.cand), "%s", candidate);
    (void)snprintf(s.base, sizeof(s.base), "%s", base);
    s.start = now;
    s.last = now;
    s.expected = lw_minute_up(now + est->seconds);
    if (!lw_self_post_window(self, &s)) {
        lw_note(note, cap, "announce post failed for", &s, 0);
        return ZCL_LAND_WINDOW_FAILED;
    }
    if (!lw_self_write(self->sidecar, &s)) {
        lw_note(note, cap, "announced, sidecar write failed for", &s,
                s.expected);
        return ZCL_LAND_WINDOW_FAILED;
    }
    lw_note(note, cap, "announced", &s, s.expected);
    return ZCL_LAND_WINDOW_ANNOUNCED;
}

/* Proof start + the first of p75, p90, max at least REANNOUNCE_S ahead of
 * now, else now + 2 * REANNOUNCE_S. */
static int64_t lw_fresh_done(const struct lw_self_state *s,
                             const struct zcl_land_window_estimate *e,
                             int64_t now)
{
    const int64_t q[3] = {e->p75_s, e->p90_s, e->max_s};
    for (int i = 0; i < 3; i++)
        if (s->start + q[i] >= now + ZCL_LAND_WINDOW_REANNOUNCE_S)
            return s->start + q[i];
    return now + 2 * ZCL_LAND_WINDOW_REANNOUNCE_S;
}

enum zcl_land_window_act zcl_land_window_tick(
    const struct zcl_land_window_self *self, const char *proof_root,
    int64_t now, char *note, size_t cap)
{
    struct zcl_land_window_estimate e;
    struct lw_self_state s;
    char shape[12];
    note[0] = '\0';
    if (!lw_self_ok(self) || !lw_self_read(self->sidecar, &s) ||
        now < s.expected || now - s.last < ZCL_LAND_WINDOW_REANNOUNCE_S)
        return ZCL_LAND_WINDOW_NONE;
    zcl_land_window_estimate(
        proof_root,
        zcl_land_window_attempt_shape(proof_root, s.cand, s.base, shape)
            ? shape
            : NULL,
        &e);
    s.expected = lw_minute_up(lw_fresh_done(&s, &e, now));
    s.last = now;
    if (!lw_self_post_window(self, &s)) {
        lw_note(note, cap, "re-announce post failed for", &s, 0);
        return ZCL_LAND_WINDOW_FAILED;
    }
    (void)lw_self_write(self->sidecar, &s);
    lw_note(note, cap, "re-announced overrun", &s, s.expected);
    return ZCL_LAND_WINDOW_REANNOUNCED;
}

bool zcl_land_window_host_ok(const char *host)
{
    return lw_host_ok(host);
}
