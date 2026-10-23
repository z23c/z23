/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.objectives.verdict` leaf - compares two
 *          zcl.objectives_snapshot.v1 rows of <state>/land/objectives.jsonl
 *          (the file dl_objectives_snapshot appends after each landing) and
 *          says, per objective, whether the value moved the right way, so an
 *          unattended runner can tell whether its landing moved its objective.
 *
 * ROWS. By default the second-newest and newest valid rows, in file order.
 * before_seq / after_seq pick a row by its `seq` instead (the last row with
 * that seq wins); a seq the file does not hold is refused by name. A side
 * left unset keeps its default, so after_seq alone compares the second-newest
 * row with the chosen one.
 *
 * VERDICT. improved: the value moved in the objective's direction (min: lower
 * is better, max: higher is better). regressed: it moved the other way.
 * unchanged: equal. unmeasured: either side has a null value, or the id is in
 * only one row (the reason is carried).
 *
 * ROBUSTNESS. The file is streamed once with a bounded line reader
 * (FVD_LINE_MAX). An overlong line, a malformed one, or one with another
 * schema is skipped and counted in `skipped`. Only the rows the verdict can
 * need are kept (the newest two, plus the two named by seq), so memory does
 * not grow with the file. The leaf writes nothing. */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "platform/state_root.h"
#include "util/log_macros.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FVD_SCHEMA_IN "zcl.objectives_snapshot.v1"
#define FVD_SCHEMA_OUT "zcl.fleet_objectives_verdict.v1"
#define FVD_LINE_MAX 65536u
#define FVD_PATH_MAX 4352u
#define FVD_SCREEN_MAX 8192u
#define FVD_LEAF "fleet.objectives.verdict"

struct fvd_row {
    bool have;
    int64_t seq;
    struct json_value v;
};

struct fvd_scan {
    bool has_before, has_after;
    int64_t want_before, want_after;
    struct fvd_row last, prev, before, after;
    size_t rows, skipped;
    bool oom;
};

struct fvd_side {
    bool measured;
    int64_t value;
};

struct fvd_counts {
    int64_t improved, regressed, unchanged, unmeasured;
};

/* ── rows ─────────────────────────────────────────────────────────────── */

static void fvd_row_free(struct fvd_row *r)
{
    json_free(&r->v);
    json_init(&r->v);
    r->have = false;
}

/* Moves *src into the slot; *src is left a fresh null. */
static void fvd_row_move(struct fvd_row *slot, struct json_value *src,
                         int64_t seq)
{
    fvd_row_free(slot);
    slot->v = *src;
    json_init(src);
    slot->have = true;
    slot->seq = seq;
}

static bool fvd_row_copy(struct fvd_row *slot, const struct json_value *src,
                         int64_t seq)
{
    fvd_row_free(slot);
    if (!json_copy_checked(&slot->v, src)) {
        json_init(&slot->v);
        return false;
    }
    slot->have = true;
    slot->seq = seq;
    return true;
}

/* True when the parsed line is a snapshot row; *seq is its seq. */
static bool fvd_row_valid(const struct json_value *v, int64_t *seq)
{
    const struct json_value *s = json_get(v, "seq");
    const struct json_value *ts = json_get(v, "ts");
    const struct json_value *tip = json_get(v, "tip");
    const struct json_value *objs = json_get(v, "objectives");
    const struct json_value *schema = json_get(v, "schema");
    if (v->type != JSON_OBJ || !schema || schema->type != JSON_STR ||
        strcmp(json_get_str(schema), FVD_SCHEMA_IN) != 0)
        return false;
    if (!s || s->type != JSON_INT || !ts || ts->type != JSON_INT || !tip ||
        tip->type != JSON_STR || !objs || objs->type != JSON_ARR)
        return false;
    *seq = json_get_int(s);
    return true;
}

/* Keeps the parsed row where the verdict can need it. */
static void fvd_offer(struct fvd_scan *sc, struct json_value *parsed,
                      int64_t seq)
{
    if (sc->has_before && seq == sc->want_before &&
        !fvd_row_copy(&sc->before, parsed, seq))
        sc->oom = true;
    if (sc->has_after && seq == sc->want_after &&
        !fvd_row_copy(&sc->after, parsed, seq))
        sc->oom = true;
    fvd_row_free(&sc->prev);
    sc->prev = sc->last;
    json_init(&sc->last.v);
    sc->last.have = false;
    fvd_row_move(&sc->last, parsed, seq);
    sc->rows++;
}

/* ── bounded line reader ──────────────────────────────────────────────── */

enum fvd_line { FVD_LINE_OK, FVD_LINE_LONG, FVD_LINE_EOF };

/* Reads one line into buf (cap bytes with room for the NUL). A line longer
 * than cap-1 bytes is consumed to its newline and reported as LONG. */
static enum fvd_line fvd_read_line(FILE *f, char *buf, size_t cap, size_t *len)
{
    size_t n = 0;
    bool too_long = false;
    int c;
    while ((c = fgetc(f)) != EOF && c != '\n') {
        if (n + 1 < cap)
            buf[n++] = (char)c;
        else
            too_long = true;
    }
    buf[n] = '\0';
    *len = n;
    if (too_long)
        return FVD_LINE_LONG;
    return (c == EOF && n == 0) ? FVD_LINE_EOF : FVD_LINE_OK;
}

static bool fvd_blank(const char *s)
{
    for (; *s; s++)
        if (*s != ' ' && *s != '\t' && *s != '\r')
            return false;
    return true;
}

static void fvd_line_take(struct fvd_scan *sc, const char *line, size_t len)
{
    struct json_value v;
    int64_t seq = 0;
    if (fvd_blank(line))
        return;
    json_init(&v);
    if (!json_read(&v, line, len) || !fvd_row_valid(&v, &seq)) {
        sc->skipped++;
        json_free(&v);
        return;
    }
    fvd_offer(sc, &v, seq);
    json_free(&v);
}

/* Streams the file. False on a read error (errno set). */
static bool fvd_scan_file(FILE *f, struct fvd_scan *sc)
{
    char *line = zcl_malloc(FVD_LINE_MAX + 1u, "verdict line");
    enum fvd_line st;
    size_t len;
    if (!line) {
        sc->oom = true;
        return false;
    }
    while (!sc->oom && (st = fvd_read_line(f, line, FVD_LINE_MAX, &len)) !=
                           FVD_LINE_EOF) {
        if (st == FVD_LINE_LONG)
            sc->skipped++;
        else
            fvd_line_take(sc, line, len);
    }
    free(line);
    return !ferror(f);
}

/* ── inputs ───────────────────────────────────────────────────────────── */

static void fvd_fail(struct zcl_command_reply *reply, int exit_code,
                     const char *code, const char *message, const char *hint)
{
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           "decide", false, false, message, hint);
}

/* A seq input, integer or digit string. *has is false when absent. False,
 * with the reply filled, when present but not a non-negative integer. */
static bool fvd_seq_input(const struct zcl_command_request *request,
                          const char *key, bool *has, int64_t *out,
                          struct zcl_command_reply *reply)
{
    const struct json_value *v =
        request->input ? json_get(request->input, key) : NULL;
    char message[160], *end = NULL;
    const char *s;
    *has = false;
    if (!v || v->type == JSON_NULL)
        return true;
    if (v->type == JSON_INT && json_get_int(v) >= 0) {
        *has = true;
        *out = json_get_int(v);
        return true;
    }
    s = v->type == JSON_STR ? json_get_str(v) : NULL;
    if (s && s[0]) {
        errno = 0;
        long long n = strtoll(s, &end, 10);
        if (errno == 0 && end && !*end && n >= 0) {
            *has = true;
            *out = n;
            return true;
        }
    }
    (void)snprintf(message, sizeof(message),
                   "%s must be a non-negative integer (a row seq)", key);
    fvd_fail(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_SEQ", message,
             "z23-dev fleet objectives verdict --before_seq=N --after_seq=M");
    return false;
}

/* The snapshot path: the input, else <state>/land/objectives.jsonl, the
 * file dl_objectives_snapshot appends to. */
static bool fvd_path(const struct zcl_command_request *request, char *out,
                     size_t cap, struct zcl_command_reply *reply)
{
    const char *given = request->input
                            ? json_get_str(json_get(request->input, "snapshot"))
                            : NULL;
    char root[512];
    if (given && given[0]) {
        if (snprintf(out, cap, "%s", given) < (int)cap)
            return true;
        fvd_fail(reply, ZCL_COMMAND_EXIT_INVALID, "PATH_TOO_LONG",
                 "the snapshot path is too long", "");
        return false;
    }
    if (platform_state_root_existing(root, sizeof(root)) &&
        snprintf(out, cap, "%s/land/objectives.jsonl", root) < (int)cap)
        return true;
    fvd_fail(reply, ZCL_COMMAND_EXIT_INVALID, "NO_STATE_ROOT",
             "no state directory exists, so there is no default objectives.jsonl",
             "pass snapshot=<path to objectives.jsonl>");
    return false;
}

/* ── comparison ───────────────────────────────────────────────────────── */

static const struct json_value *fvd_find(const struct json_value *objs,
                                         const char *id)
{
    for (size_t i = 0; i < json_size(objs); i++) {
        const struct json_value *e = json_at(objs, i);
        const char *eid = json_get_str(json_get(e, "id"));
        if (eid && strcmp(eid, id) == 0)
            return e;
    }
    return NULL;
}

static struct fvd_side fvd_side_of(const struct json_value *entry)
{
    struct fvd_side s = {false, 0};
    const struct json_value *v = entry ? json_get(entry, "value") : NULL;
    if (v && v->type == JSON_INT) {
        s.measured = true;
        s.value = json_get_int(v);
    }
    return s;
}

static bool fvd_push_null(struct json_value *obj, const char *key)
{
    struct json_value nul;
    bool ok;
    json_init(&nul);
    ok = json_push_kv(obj, key, &nul);
    json_free(&nul);
    return ok;
}

static bool fvd_push_side(struct json_value *obj, const char *key, bool has,
                          int64_t v)
{
    return has ? json_push_kv_int(obj, key, v) : fvd_push_null(obj, key);
}

/* met_before / met_after: the entry's bool, or null. */
static bool fvd_push_met(struct json_value *obj, const char *key,
                         const struct json_value *entry)
{
    const struct json_value *m = entry ? json_get(entry, "met") : NULL;
    if (m && m->type == JSON_BOOL)
        return json_push_kv_bool(obj, key, json_get_bool(m));
    return fvd_push_null(obj, key);
}

/* The reason a pair is unmeasured: a side's own reason, else which row
 * lacks the id. */
static void fvd_reason(const struct json_value *be,
                       const struct json_value *ae, char *out, size_t cap)
{
    const char *rb = be ? json_get_str(json_get(be, "reason")) : NULL;
    const char *ra = ae ? json_get_str(json_get(ae, "reason")) : NULL;
    if (!be)
        (void)snprintf(out, cap, "not in the before row");
    else if (!ae)
        (void)snprintf(out, cap, "not in the after row");
    else if (ra && ra[0])
        (void)snprintf(out, cap, "after: %.200s", ra);
    else if (rb && rb[0])
        (void)snprintf(out, cap, "before: %.200s", rb);
    else
        (void)snprintf(out, cap, "a value is not an integer");
}

/* improved | regressed | unchanged for two measured sides. */
static const char *fvd_judge(bool is_max, int64_t before, int64_t after)
{
    if (after == before)
        return "unchanged";
    return ((after > before) == is_max) ? "improved" : "regressed";
}

static void fvd_count(struct fvd_counts *c, const char *verdict)
{
    if (strcmp(verdict, "improved") == 0)
        c->improved++;
    else if (strcmp(verdict, "regressed") == 0)
        c->regressed++;
    else if (strcmp(verdict, "unchanged") == 0)
        c->unchanged++;
    else
        c->unmeasured++;
}

static bool fvd_entry_fields(struct json_value *o, const char *id,
                             const struct json_value *be,
                             const struct json_value *ae,
                             const struct fvd_side *b, const struct fvd_side *a,
                             const char *verdict)
{
    const struct json_value *ref = ae ? ae : be;
    const char *dir = json_get_str(json_get(ref, "direction"));
    const struct json_value *target = json_get(ref, "target");
    bool both = b->measured && a->measured;
    return json_push_kv_str(o, "id", id) &&
           fvd_push_side(o, "before", b->measured, b->value) &&
           fvd_push_side(o, "after", a->measured, a->value) &&
           fvd_push_side(o, "delta", both, a->value - b->value) &&
           json_push_kv_str(o, "direction", dir ? dir : "") &&
           fvd_push_side(o, "target",
                         target && target->type == JSON_INT,
                         json_get_int(target)) &&
           fvd_push_met(o, "met_before", be) &&
           fvd_push_met(o, "met_after", ae) &&
           json_push_kv_str(o, "verdict", verdict);
}

/* Builds one {id, before, after, ...} entry and counts its verdict. */
static bool fvd_entry(struct json_value *o, const char *id,
                      const struct json_value *be, const struct json_value *ae,
                      struct fvd_counts *counts)
{
    struct fvd_side b = fvd_side_of(be), a = fvd_side_of(ae);
    const struct json_value *ref = ae ? ae : be;
    const char *dir = json_get_str(json_get(ref, "direction"));
    bool dir_ok = dir && (strcmp(dir, "min") == 0 || strcmp(dir, "max") == 0);
    const char *verdict = "unmeasured";
    char reason[256];
    json_set_object(o);
    if (b.measured && a.measured && dir_ok)
        verdict = fvd_judge(strcmp(dir, "max") == 0, b.value, a.value);
    fvd_count(counts, verdict);
    if (!fvd_entry_fields(o, id, be, ae, &b, &a, verdict))
        return false;
    if (strcmp(verdict, "unmeasured") != 0)
        return true;
    if (b.measured && a.measured)
        (void)snprintf(reason, sizeof(reason), "unknown direction");
    else
        fvd_reason(be, ae, reason, sizeof(reason));
    return json_push_kv_str(o, "reason", reason);
}

static bool fvd_push_entry(struct json_value *arr, const char *id,
                           const struct json_value *be,
                           const struct json_value *ae,
                           struct fvd_counts *counts)
{
    struct json_value o;
    bool ok;
    json_init(&o);
    ok = fvd_entry(&o, id, be, ae, counts) && json_push_back(arr, &o);
    json_free(&o);
    return ok;
}

/* Every id of the after row, then the ids only the before row has; or just
 * `only`. */
static bool fvd_collect(const struct json_value *bobjs,
                        const struct json_value *aobjs, const char *only,
                        struct json_value *arr, struct fvd_counts *counts)
{
    for (size_t i = 0; i < json_size(aobjs); i++) {
        const struct json_value *ae = json_at(aobjs, i);
        const char *id = json_get_str(json_get(ae, "id"));
        if (!id || (only && strcmp(id, only) != 0))
            continue;
        if (!fvd_push_entry(arr, id, fvd_find(bobjs, id), ae, counts))
            return false;
    }
    for (size_t i = 0; i < json_size(bobjs); i++) {
        const struct json_value *be = json_at(bobjs, i);
        const char *id = json_get_str(json_get(be, "id"));
        if (!id || (only && strcmp(id, only) != 0) || fvd_find(aobjs, id))
            continue;
        if (!fvd_push_entry(arr, id, be, NULL, counts))
            return false;
    }
    return true;
}

/* ── screen ───────────────────────────────────────────────────────────── */

struct fvd_buf {
    char *out;
    size_t left;
};

static void fvd_put(struct fvd_buf *b, const char *fmt, ...)
{
    va_list ap;
    int n;
    if (b->left <= 1u)
        return;
    va_start(ap, fmt);
    n = vsnprintf(b->out, b->left, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    if ((size_t)n >= b->left)
        n = (int)(b->left - 1u);
    b->out += n;
    b->left -= (size_t)n;
}

/* Copies s keeping printable ASCII; anything else becomes '?'. */
static void fvd_ascii(const char *s, char *out, size_t cap)
{
    size_t n = 0;
    if (!s || cap == 0)
        s = "";
    while (s[n] && n + 1 < cap) {
        unsigned char ch = (unsigned char)s[n];
        out[n] = (ch >= 0x20 && ch < 0x7f) ? (char)ch : '?';
        n++;
    }
    if (cap > 0)
        out[n] = '\0';
}

static void fvd_num(const struct json_value *v, char *out, size_t cap)
{
    if (v && v->type == JSON_INT)
        (void)snprintf(out, cap, "%" PRId64, json_get_int(v));
    else
        (void)snprintf(out, cap, "-");
}

static void fvd_screen_line(struct fvd_buf *b, const struct json_value *e)
{
    char id[64], bs[32], as[32], verdict[24], reason[96];
    const char *v = json_get_str(json_get(e, "verdict"));
    const char *r = json_get_str(json_get(e, "reason"));
    fvd_ascii(json_get_str(json_get(e, "id")), id, sizeof(id));
    fvd_ascii(v, verdict, sizeof(verdict));
    fvd_num(json_get(e, "before"), bs, sizeof(bs));
    fvd_num(json_get(e, "after"), as, sizeof(as));
    fvd_ascii(r, reason, sizeof(reason));
    if (strcmp(verdict, "regressed") == 0)
        (void)snprintf(verdict, sizeof(verdict), "REGRESSED");
    fvd_put(b, "%-30s %8s -> %-8s %s%s%s\n", id, bs, as, verdict,
            reason[0] ? " - " : "", reason);
}

static void fvd_screen(char *out, size_t cap, const struct fvd_row *before,
                       const struct fvd_row *after,
                       const struct json_value *entries,
                       const struct fvd_counts *c)
{
    struct fvd_buf b = {out, cap};
    char t1[16], t2[16];
    fvd_ascii(json_get_str(json_get(&before->v, "tip")), t1, sizeof(t1));
    fvd_ascii(json_get_str(json_get(&after->v, "tip")), t2, sizeof(t2));
    out[0] = '\0';
    fvd_put(&b, "objectives verdict: seq %" PRId64 " (%s) -> seq %" PRId64
                " (%s)\n",
            before->seq, t1, after->seq, t2);
    for (size_t i = 0; i < json_size(entries); i++)
        fvd_screen_line(&b, json_at(entries, i));
    fvd_put(&b, "improved %" PRId64 ", regressed %" PRId64
                ", unchanged %" PRId64 ", unmeasured %" PRId64 "\n",
            c->improved, c->regressed, c->unchanged, c->unmeasured);
}

/* ── reply ────────────────────────────────────────────────────────────── */

static bool fvd_push_row(struct json_value *data, const char *key,
                         const struct fvd_row *r)
{
    struct json_value o;
    bool ok;
    json_init(&o);
    json_set_object(&o);
    ok = json_push_kv_int(&o, "seq", r->seq) &&
         json_push_kv_str(&o, "tip", json_get_str(json_get(&r->v, "tip"))) &&
         json_push_kv_int(&o, "ts", json_get_int(json_get(&r->v, "ts"))) &&
         json_push_kv(data, key, &o);
    json_free(&o);
    return ok;
}

static bool fvd_push_regressions(struct json_value *data,
                                 const struct json_value *entries)
{
    struct json_value arr;
    bool ok = true;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; ok && i < json_size(entries); i++) {
        const struct json_value *e = json_at(entries, i);
        struct json_value s;
        if (strcmp(json_get_str(json_get(e, "verdict")), "regressed") != 0)
            continue;
        json_init(&s);
        json_set_str(&s, json_get_str(json_get(e, "id")));
        ok = json_push_back(&arr, &s);
        json_free(&s);
    }
    ok = ok && json_push_kv(data, "regressions", &arr);
    json_free(&arr);
    return ok;
}

static bool fvd_push_all(struct json_value *data, const struct fvd_scan *sc,
                         const struct fvd_row *before,
                         const struct fvd_row *after, const char *path,
                         struct json_value *entries,
                         const struct fvd_counts *c, const char *screen)
{
    return json_push_kv_str(data, "schema", FVD_SCHEMA_OUT) &&
           json_push_kv_str(data, "snapshot", path) &&
           fvd_push_row(data, "before", before) &&
           fvd_push_row(data, "after", after) &&
           json_push_kv(data, "objectives", entries) &&
           json_push_kv_int(data, "improved", c->improved) &&
           json_push_kv_int(data, "regressed", c->regressed) &&
           json_push_kv_int(data, "unchanged", c->unchanged) &&
           json_push_kv_int(data, "unmeasured", c->unmeasured) &&
           fvd_push_regressions(data, entries) &&
           json_push_kv_int(data, "rows", (int64_t)sc->rows) &&
           json_push_kv_int(data, "skipped", (int64_t)sc->skipped) &&
           json_push_kv_str(data, "screen", screen);
}

static bool fvd_fill(struct json_value *data, const struct fvd_scan *sc,
                     const struct fvd_row *before, const struct fvd_row *after,
                     const char *only, const char *path)
{
    struct json_value entries;
    struct fvd_counts c = {0, 0, 0, 0};
    char *screen = zcl_malloc(FVD_SCREEN_MAX, "verdict screen");
    bool ok = screen != NULL;
    json_init(&entries);
    json_set_array(&entries);
    ok = ok && fvd_collect(json_get(&before->v, "objectives"),
                           json_get(&after->v, "objectives"), only, &entries,
                           &c);
    if (ok)
        fvd_screen(screen, FVD_SCREEN_MAX, before, after, &entries, &c);
    ok = ok && fvd_push_all(data, sc, before, after, path, &entries, &c,
                            screen);
    json_free(&entries);
    free(screen);
    return ok;
}

/* Picks the two rows to compare; false, with the reply filled, when the
 * file cannot answer. */
static bool fvd_pick(const struct fvd_scan *sc, const struct fvd_row **before,
                     const struct fvd_row **after,
                     struct zcl_command_reply *reply)
{
    char message[256];
    *before = sc->has_before ? &sc->before : &sc->prev;
    *after = sc->has_after ? &sc->after : &sc->last;
    if (sc->has_before && !sc->before.have)
        (void)snprintf(message, sizeof(message),
                       "before_seq %" PRId64 " is not in the snapshot file "
                       "(%zu valid rows, %zu skipped)",
                       sc->want_before, sc->rows, sc->skipped);
    else if (sc->has_after && !sc->after.have)
        (void)snprintf(message, sizeof(message),
                       "after_seq %" PRId64 " is not in the snapshot file "
                       "(%zu valid rows, %zu skipped)",
                       sc->want_after, sc->rows, sc->skipped);
    else if (!(*before)->have || !(*after)->have)
        (void)snprintf(message, sizeof(message),
                       "the snapshot file needs two valid rows to compare; it "
                       "has %zu (%zu lines skipped)", sc->rows, sc->skipped);
    else if ((*before)->seq == (*after)->seq)
        (void)snprintf(message, sizeof(message),
                       "before and after are the same row (seq %" PRId64 ")",
                       (*before)->seq);
    else
        return true;
    fvd_fail(reply, ZCL_COMMAND_EXIT_INVALID, "SNAPSHOT_ROWS", message,
             "the land queue appends one row per landing to objectives.jsonl");
    return false;
}

/* An id in neither row is refused by name. */
static bool fvd_check_id(const char *only, const struct fvd_row *before,
                         const struct fvd_row *after,
                         struct zcl_command_reply *reply)
{
    char message[192];
    if (!only ||
        fvd_find(json_get(&before->v, "objectives"), only) ||
        fvd_find(json_get(&after->v, "objectives"), only))
        return true;
    (void)snprintf(message, sizeof(message),
                   "unknown objective id '%.80s': in neither snapshot row",
                   only);
    fvd_fail(reply, ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_OBJECTIVE", message,
             "z23-dev fleet objectives lists every id");
    return false;
}

static void fvd_scan_free(struct fvd_scan *sc)
{
    fvd_row_free(&sc->last);
    fvd_row_free(&sc->prev);
    fvd_row_free(&sc->before);
    fvd_row_free(&sc->after);
}

/* Opens and streams the file into sc; false, with the reply filled. */
static bool fvd_load(const char *path, struct fvd_scan *sc,
                     struct zcl_command_reply *reply)
{
    char message[FVD_PATH_MAX + 128];
    FILE *f = fopen(path, "rb");
    bool ok;
    if (!f) {
        (void)snprintf(message, sizeof(message),
                       "cannot open the snapshot file %s: %s", path,
                       strerror(errno));
        fvd_fail(reply, ZCL_COMMAND_EXIT_INVALID, "SNAPSHOT_MISSING", message,
                 "the land queue writes it after each landing, or pass snapshot=<path>");
        return false;
    }
    ok = fvd_scan_file(f, sc);
    (void)fclose(f);
    if (sc->oom) {
        LOG_ERROR(FVD_LEAF, "out of memory reading %s", path);
        fvd_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "VERDICT_ALLOC",
                 "out of memory reading the snapshot file", "");
        return false;
    }
    if (!ok) {
        fvd_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "SNAPSHOT_READ",
                 "read error on the snapshot file", "");
        return false;
    }
    return true;
}

static bool fvd_inputs(const struct zcl_command_request *request,
                       struct fvd_scan *sc, struct zcl_command_reply *reply)
{
    return fvd_seq_input(request, "before_seq", &sc->has_before,
                         &sc->want_before, reply) &&
           fvd_seq_input(request, "after_seq", &sc->has_after,
                         &sc->want_after, reply);
}

void zcl_native_handle_fleet_objectives_verdict(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct fvd_scan sc;
    const struct fvd_row *before, *after;
    char path[FVD_PATH_MAX];
    const char *only;
    if (!reply)
        return;
    zcl_command_reply_init(reply, FVD_SCHEMA_OUT);
    memset(&sc, 0, sizeof(sc));
    json_init(&sc.last.v);
    json_init(&sc.prev.v);
    json_init(&sc.before.v);
    json_init(&sc.after.v);
    only = (request && request->input)
               ? json_get_str(json_get(request->input, "id"))
               : NULL;
    if (only && !only[0])
        only = NULL;
    if (request && fvd_inputs(request, &sc, reply) &&
        fvd_path(request, path, sizeof(path), reply) &&
        fvd_load(path, &sc, reply) && fvd_pick(&sc, &before, &after, reply) &&
        fvd_check_id(only, before, after, reply)) {
        if (fvd_fill(&reply->data, &sc, before, after, only, path)) {
            reply->status = ZCL_COMMAND_STATUS_PASSED;
            reply->exit_code = ZCL_COMMAND_EXIT_OK;
        } else {
            LOG_ERROR(FVD_LEAF, "cannot build the verdict: out of memory");
            fvd_fail(reply, ZCL_COMMAND_EXIT_INTERNAL, "VERDICT_ALLOC",
                     "cannot build the verdict: out of memory", "");
        }
    }
    fvd_scan_free(&sc);
}

/* ── seq listing, for the loop step ───────────────────────────────────── */

struct fvd_seqs {
    int64_t *v;
    size_t n, cap;
    size_t skipped;
    bool oom;
};

static void fvd_seqs_push(struct fvd_seqs *s, int64_t seq)
{
    if (s->n == s->cap) {
        size_t ncap = s->cap ? s->cap * 2u : 256u;
        int64_t *grow = zcl_realloc(s->v, ncap * sizeof(*grow), "snapshot seqs");
        if (!grow) {
            s->oom = true;
            return;
        }
        s->v = grow;
        s->cap = ncap;
    }
    s->v[s->n++] = seq;
}

static void fvd_seqs_line(struct fvd_seqs *s, const char *line, size_t len)
{
    struct json_value v;
    int64_t seq = 0;
    if (fvd_blank(line))
        return;
    json_init(&v);
    if (json_read(&v, line, len) && fvd_row_valid(&v, &seq))
        fvd_seqs_push(s, seq);
    else
        s->skipped++;
    json_free(&v);
}

bool zcl_objectives_snapshot_seqs(const char *path, int64_t **seqs, size_t *n,
                                  size_t *skipped)
{
    struct fvd_seqs s = {NULL, 0, 0, 0, false};
    char *line;
    FILE *f;
    enum fvd_line st;
    size_t len;
    bool ok;
    *seqs = NULL;
    *n = 0;
    if (skipped)
        *skipped = 0;
    f = fopen(path, "rb");
    line = f ? zcl_malloc(FVD_LINE_MAX + 1u, "snapshot seq line") : NULL;
    if (!line) {
        if (f)
            (void)fclose(f);
        return false;
    }
    while (!s.oom && (st = fvd_read_line(f, line, FVD_LINE_MAX, &len)) !=
                         FVD_LINE_EOF) {
        if (st == FVD_LINE_LONG)
            s.skipped++;
        else
            fvd_seqs_line(&s, line, len);
    }
    ok = !ferror(f) && !s.oom;
    (void)fclose(f);
    free(line);
    if (!ok) {
        free(s.v);
        return false;
    }
    *seqs = s.v;
    *n = s.n;
    if (skipped)
        *skipped = s.skipped;
    return true;
}

bool zcl_objectives_snapshot_path(const struct zcl_command_request *request,
                                  char *out, size_t cap,
                                  struct zcl_command_reply *reply)
{
    return fvd_path(request, out, cap, reply);
}
