/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.agent.reviewscore — score reviewer findings against a known-answer
 * review set (milestone D3, docs/work/DEVELOPMENT_MVP.md).
 *
 * INPUT (zcl.agent_reviewscore_input.v1), both required
 *   set      JSONL, one case per line:
 *            {"id","label":"sound"|"defect","locus":"code"|"claim","class",
 *             "defect":[{"file","line_lo","line_hi"}],"tolerance","base_id"}
 *            locus, class and defect are required for a defect case and
 *            ignored for a sound one; tolerance defaults to 2 (0..50).
 *            class may not be "(other)": that name is the fold row.
 *            base_id (optional string, bound as id) names the sound change
 *            a case was cut from; without it a case is its own base. Two
 *            defect cases equal in class, locus, ranges and base REFUSE the
 *            set (SET_DUPLICATE_DEFECT). The reply's `independence` object
 *            reports, without refusing, bases over 3 cases or classes over 8.
 *   reviews  JSONL, one review per line:
 *            {"case","reviewer","findings":[{"kind":"CHANGE"|"CLAIM",
 *             "file","line"}]}
 *            An empty findings array means reviewed, nothing found.
 *
 * The rule is engine/engine_review_score.h (pure, reusable). This file only
 * reads the two files, accumulates, and writes the reply. Output members are
 * integers; a rate is a {num, den} pair and a zero denominator is printed as
 * 0 with the pair, never as a rate of zero percent.
 *
 * Limits: a set beyond 4096 cases is REFUSED, not truncated; a duplicate case
 * id REFUSES the set (two labels for one id are not scoreable); a malformed
 * or oversized set line REFUSES the set, naming the first one's line
 * (SET_MALFORMED). A malformed reviews line, or one over 8192 bytes, is
 * counted and the rest scored. Blank and whitespace-only lines are skipped
 * silently in both files. Reviews are streamed.
 */

#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "engine/engine_review_score.h"
#include "json/json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DRS_LEAF "dev.agent.reviewscore"
#define DRS_LINE_MAX 8192u
#define DRS_CASES_MAX 4096u
#define DRS_UNREVIEWED_MAX 64u
#define DRS_CLASSES_MAX 32u
#define DRS_DEFECT_MIN 59
#define DRS_PER_BASE_LIMIT 3
#define DRS_PER_CLASS_LIMIT 8
#define DRS_OVER_MAX 32u
#define DRS_LINE_NUM_MAX 1000000000
#define DRS_FOLD_NAME "(other)"

enum drs_row { DRS_ROW_OK, DRS_ROW_BAD, DRS_ROW_STOP };
enum drs_parse { DRS_PARSE_OK, DRS_PARSE_BAD, DRS_PARSE_ALLOC };
typedef enum drs_row (*drs_row_fn)(void *ctx, const struct json_value *row);

struct drs_case {
    struct ers_case c;
    char base[ERS_ID_MAX]; /* the change this case came from; its id if none */
    struct ers_range *own;
    int64_t reviews;
};

struct drs_bad {
    size_t count; /* malformed lines seen */
    size_t first; /* 1-based line number of the first one, 0 if none */
};

struct drs_set {
    struct drs_case *items;
    size_t n;
    size_t cap;
    struct drs_bad bad;
    int64_t sound;
    int64_t defect;
    char dup_id[ERS_ID_MAX];
    char same_a[ERS_ID_MAX]; /* the two ids of a duplicate defect */
    char same_b[ERS_ID_MAX];
    bool same_defect;
    bool dup;
    bool too_big;
    bool alloc_failed;
};

struct drs_class {
    char name[ERS_CLASS_MAX];
    int64_t reviews;
    int64_t accepted;
};

struct drs_tally {
    int64_t sound_reviews, sound_rejected, rej_change, rej_claim;
    int64_t defect_reviews, defect_accepted, acc_code, acc_claim;
    int64_t findings_total, findings_discarded;
    int64_t unknown, malformed;
    struct drs_class classes[DRS_CLASSES_MAX];
    size_t nclasses;
    struct drs_class other;
    bool other_used;
};

struct drs_run {
    struct drs_set *set;
    struct drs_tally tally;
    bool alloc_failed;
};

static void drs_refuse(struct zcl_command_reply *reply,
                       enum zcl_command_exit exit_code, const char *code,
                       const char *phase, const char *message,
                       const char *evidence, const char *next_action)
{
    (void)fprintf(stderr, "%s: %s: %s\n", DRS_LEAF, code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, exit_code, code,
                           phase, false, false, message, evidence);
    if (next_action)
        (void)snprintf(reply->error.next_action,
                       sizeof(reply->error.next_action), "%s", next_action);
    reply->error.human_action_required = false;
}

/* ── JSON field helpers ─────────────────────────────────────────────── */

static const char *drs_str(const struct json_value *row, const char *key)
{
    const struct json_value *v = json_get(row, key);
    if (!v || v->type != JSON_STR)
        return NULL;
    return json_get_str(v);
}

static bool drs_int(const struct json_value *row, const char *key, int64_t *out)
{
    const struct json_value *v = json_get(row, key);
    if (!v || v->type != JSON_INT)
        return false;
    *out = json_get_int(v);
    return true;
}

static bool drs_copy_str(const struct json_value *row, const char *key,
                         char *dst, size_t cap)
{
    const char *s = drs_str(row, key);
    if (!s || !s[0] || strlen(s) >= cap)
        return false;
    memcpy(dst, s, strlen(s) + 1u);
    return true;
}

/* ── the set ────────────────────────────────────────────────────────── */

static bool drs_parse_range(const struct json_value *el, struct ers_range *r)
{
    if (el->type != JSON_OBJ || !drs_copy_str(el, "file", r->file, sizeof(r->file)))
        return false;
    if (!drs_int(el, "line_lo", &r->line_lo) ||
        !drs_int(el, "line_hi", &r->line_hi))
        return false;
    return r->line_lo >= 1 && r->line_hi >= r->line_lo &&
           r->line_hi <= DRS_LINE_NUM_MAX;
}

static enum drs_parse drs_parse_ranges(const struct json_value *arr,
                                       struct drs_case *cs)
{
    size_t n = arr && arr->type == JSON_ARR ? json_size(arr) : 0u;
    if (n == 0 || n > ERS_RANGES_MAX)
        return DRS_PARSE_BAD;
    cs->own = zcl_malloc(n * sizeof(*cs->own), "reviewscore_ranges");
    if (!cs->own)
        return DRS_PARSE_ALLOC;
    for (size_t i = 0; i < n; i++) {
        if (!drs_parse_range(json_at(arr, i), &cs->own[i])) {
            free(cs->own);
            cs->own = NULL;
            return DRS_PARSE_BAD;
        }
    }
    cs->c.ranges = cs->own;
    cs->c.nranges = n;
    return DRS_PARSE_OK;
}

static enum drs_parse drs_parse_defect(const struct json_value *row,
                                       struct drs_case *cs)
{
    const char *locus = drs_str(row, "locus");
    if (locus && strcmp(locus, "code") == 0)
        cs->c.locus = ERS_LOCUS_CODE;
    else if (locus && strcmp(locus, "claim") == 0)
        cs->c.locus = ERS_LOCUS_CLAIM;
    else
        return DRS_PARSE_BAD;
    if (!drs_copy_str(row, "class", cs->c.cls, sizeof(cs->c.cls)))
        return DRS_PARSE_BAD;
    if (strcmp(cs->c.cls, DRS_FOLD_NAME) == 0)
        return DRS_PARSE_BAD;
    return drs_parse_ranges(json_get(row, "defect"), cs);
}

static bool drs_parse_tolerance(const struct json_value *row, int *out)
{
    const struct json_value *v = json_get(row, "tolerance");
    *out = ERS_TOLERANCE_DEFAULT;
    if (!v)
        return true;
    if (v->type != JSON_INT)
        return false;
    int64_t t = json_get_int(v);
    if (t < 0 || t > ERS_TOLERANCE_MAX)
        return false;
    *out = (int)t;
    return true;
}

/* base_id is optional; without one a case is its own base. */
static bool drs_parse_base(const struct json_value *row, struct drs_case *cs)
{
    if (!json_get(row, "base_id")) {
        memcpy(cs->base, cs->c.id, strlen(cs->c.id) + 1u);
        return true;
    }
    return drs_copy_str(row, "base_id", cs->base, sizeof(cs->base));
}

static enum drs_parse drs_parse_case(const struct json_value *row,
                                     struct drs_case *cs)
{
    if (!drs_copy_str(row, "id", cs->c.id, sizeof(cs->c.id)) ||
        !drs_parse_base(row, cs) ||
        !drs_parse_tolerance(row, &cs->c.tolerance))
        return DRS_PARSE_BAD;
    const char *label = drs_str(row, "label");
    if (label && strcmp(label, "sound") == 0) {
        cs->c.label = ERS_LABEL_SOUND;
        return DRS_PARSE_OK;
    }
    if (!label || strcmp(label, "defect") != 0)
        return DRS_PARSE_BAD;
    cs->c.label = ERS_LABEL_DEFECT;
    return drs_parse_defect(row, cs);
}

static void drs_case_free(struct drs_case *cs)
{
    free(cs->own);
    cs->own = NULL;
}

static void drs_set_free(struct drs_set *s)
{
    for (size_t i = 0; i < s->n; i++)
        drs_case_free(&s->items[i]);
    free(s->items);
    memset(s, 0, sizeof(*s));
}

static struct drs_case *drs_find(struct drs_set *s, const char *id)
{
    for (size_t i = 0; i < s->n; i++) {
        if (strcmp(s->items[i].c.id, id) == 0)
            return &s->items[i];
    }
    return NULL;
}

static bool drs_set_grow(struct drs_set *s)
{
    if (s->n < s->cap)
        return true;
    size_t next = s->cap ? s->cap * 2u : 64u;
    struct drs_case *grown =
        zcl_realloc(s->items, next * sizeof(*grown), "reviewscore_cases");
    if (!grown)
        return false;
    s->items = grown;
    s->cap = next;
    return true;
}

/* Same defect: class, locus, every range in order, and base all equal. */
static bool drs_same_defect(const struct drs_case *a, const struct drs_case *b)
{
    if (a->c.locus != b->c.locus || a->c.nranges != b->c.nranges ||
        strcmp(a->c.cls, b->c.cls) != 0 || strcmp(a->base, b->base) != 0)
        return false;
    for (size_t i = 0; i < a->c.nranges; i++) {
        const struct ers_range *x = &a->c.ranges[i], *y = &b->c.ranges[i];
        if (x->line_lo != y->line_lo || x->line_hi != y->line_hi ||
            strcmp(x->file, y->file) != 0)
            return false;
    }
    return true;
}

/* True, with both ids recorded, when `cs` repeats an earlier defect case. */
static bool drs_note_same_defect(struct drs_set *s, const struct drs_case *cs)
{
    for (size_t i = 0; i < s->n; i++) {
        const struct drs_case *o = &s->items[i];
        if (o->c.label != ERS_LABEL_DEFECT || !drs_same_defect(o, cs))
            continue;
        s->same_defect = true;
        memcpy(s->same_a, o->c.id, sizeof(s->same_a));
        memcpy(s->same_b, cs->c.id, sizeof(s->same_b));
        return true;
    }
    return false;
}

static enum drs_row drs_set_add(struct drs_set *s, struct drs_case *cs)
{
    if (drs_find(s, cs->c.id)) {
        s->dup = true;
        memcpy(s->dup_id, cs->c.id, sizeof(s->dup_id));
    } else if (cs->c.label == ERS_LABEL_DEFECT && drs_note_same_defect(s, cs)) {
        /* refused: the same defect twice is not two independent defects */
    } else if (s->n >= DRS_CASES_MAX) {
        s->too_big = true;
    } else if (!drs_set_grow(s)) {
        s->alloc_failed = true;
    } else {
        s->items[s->n++] = *cs;
        if (cs->c.label == ERS_LABEL_SOUND)
            s->sound++;
        else
            s->defect++;
        return DRS_ROW_OK;
    }
    drs_case_free(cs);
    return DRS_ROW_STOP;
}

static enum drs_row drs_set_row(void *ctx, const struct json_value *row)
{
    struct drs_set *s = ctx;
    struct drs_case cs;
    memset(&cs, 0, sizeof(cs));
    enum drs_parse p = drs_parse_case(row, &cs);
    if (p == DRS_PARSE_ALLOC) {
        s->alloc_failed = true;
        return DRS_ROW_STOP;
    }
    if (p == DRS_PARSE_BAD)
        return DRS_ROW_BAD;
    return drs_set_add(s, &cs);
}

/* ── the JSONL reader ───────────────────────────────────────────────── */

static bool drs_blank(const char *line)
{
    for (; *line; line++) {
        if (*line != ' ' && *line != '\t' && *line != '\r' && *line != '\n')
            return false;
    }
    return true;
}

/* 1: a line is ready; 0: end of file; -1: oversized, drained. */
static int drs_next_line(FILE *fp, char *line, size_t cap)
{
    if (!fgets(line, (int)cap, fp))
        return 0;
    if (!strchr(line, '\n') && !feof(fp)) {
        int c;
        do {
            c = fgetc(fp);
        } while (c != '\n' && c != EOF);
        return -1;
    }
    return 1;
}

static enum drs_row drs_dispatch(const char *line, drs_row_fn fn, void *ctx)
{
    struct json_value row;
    json_init(&row);
    if (!json_read(&row, line, strlen(line)) || row.type != JSON_OBJ) {
        json_free(&row);
        return DRS_ROW_BAD;
    }
    enum drs_row r = fn(ctx, &row);
    json_free(&row);
    return r;
}

static void drs_note_bad(struct drs_bad *bad, size_t lineno)
{
    if (bad->count == 0)
        bad->first = lineno;
    bad->count++;
}

/* Returns false when the file failed while being read. Line numbers are
 * physical and 1-based: blank and oversized lines count as lines. */
static bool drs_scan(FILE *fp, drs_row_fn fn, void *ctx, struct drs_bad *bad)
{
    char line[DRS_LINE_MAX];
    size_t lineno = 0;
    int got;
    while ((got = drs_next_line(fp, line, sizeof(line))) != 0) {
        lineno++;
        if (got < 0) {
            drs_note_bad(bad, lineno);
            continue;
        }
        if (drs_blank(line))
            continue;
        enum drs_row r = drs_dispatch(line, fn, ctx);
        if (r == DRS_ROW_STOP)
            break;
        if (r == DRS_ROW_BAD)
            drs_note_bad(bad, lineno);
    }
    bool ok = !ferror(fp);
    if (fclose(fp) != 0)
        ok = false;
    return ok;
}

static FILE *drs_open(struct zcl_command_reply *reply, const char *path,
                      const char *what)
{
    FILE *fp = fopen(path, "r");
    if (fp)
        return fp;
    char msg[512];
    (void)snprintf(msg, sizeof(msg), "%s file '%s' cannot be opened", what,
                   path);
    drs_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "INPUT_UNREADABLE", "read", msg,
               "dev.agent.reviewscore reads the two named files",
               "check the path, then rerun");
    return NULL;
}

static bool drs_refuse_unreadable(struct zcl_command_reply *reply,
                                  const char *what, const char *path)
{
    char msg[512];
    (void)snprintf(msg, sizeof(msg), "%s file '%s' failed while being read",
                   what, path);
    drs_refuse(reply, ZCL_COMMAND_EXIT_FAILED, "INPUT_UNREADABLE", "read", msg,
               "dev.agent.reviewscore reads the two named files",
               "check the file, then rerun");
    return false;
}

static bool drs_refuse_set_state(struct zcl_command_reply *reply,
                                 const struct drs_set *s)
{
    char msg[512];
    if (s->dup) {
        (void)snprintf(msg, sizeof(msg),
                       "case id '%s' appears twice in the set; two labels for "
                       "one id are not scoreable", s->dup_id);
        drs_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "SET_DUPLICATE_ID",
                   "validate", msg, "known-answer set", "give every case a unique id");
        return false;
    }
    if (s->same_defect) {
        (void)snprintf(msg, sizeof(msg),
                       "cases '%s' and '%s' are the same defect (same class, "
                       "locus, ranges and base); one defect counted twice is "
                       "not two independent defects", s->same_a, s->same_b);
        drs_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "SET_DUPLICATE_DEFECT",
                   "validate", msg, "known-answer set",
                   "drop one, or give the cases different bases");
        return false;
    }
    if (s->too_big) {
        drs_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "SET_TOO_LARGE", "validate",
                   "the set holds more than 4096 cases",
                   "known-answer set", "split the set");
        return false;
    }
    if (s->alloc_failed) {
        drs_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "aggregate",
                   "out of memory while reading the set",
                   "dev.agent.reviewscore case table", "retry with a smaller set");
        return false;
    }
    if (s->bad.count > 0) {
        (void)snprintf(msg, sizeof(msg),
                       "%zu set line(s) malformed; the first is line %zu. A "
                       "malformed set line refuses the whole set",
                       s->bad.count, s->bad.first);
        drs_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "SET_MALFORMED", "validate",
                   msg, "known-answer set", "fix the named set line, then rerun");
        return false;
    }
    return true;
}

static bool drs_load_set(struct zcl_command_reply *reply, const char *path,
                         struct drs_set *s)
{
    FILE *fp = drs_open(reply, path, "set");
    if (!fp)
        return false;
    bool read_ok = drs_scan(fp, drs_set_row, s, &s->bad);
    if (!drs_refuse_set_state(reply, s))
        return false;
    if (!read_ok)
        return drs_refuse_unreadable(reply, "set", path);
    return true;
}

/* ── the reviews ────────────────────────────────────────────────────── */

static void drs_parse_finding(const struct json_value *el, struct ers_finding *f)
{
    const char *kind = drs_str(el, "kind");
    int64_t line = 0;
    f->kind = ERS_KIND_INVALID;
    if (kind && strcmp(kind, "CHANGE") == 0)
        f->kind = ERS_KIND_CHANGE;
    else if (kind && strcmp(kind, "CLAIM") == 0)
        f->kind = ERS_KIND_CLAIM;
    f->file = drs_str(el, "file");
    (void)drs_int(el, "line", &line);
    f->line = line;
}

static struct drs_class *drs_class_row(struct drs_tally *t, const char *name)
{
    for (size_t i = 0; i < t->nclasses; i++) {
        if (strcmp(t->classes[i].name, name) == 0)
            return &t->classes[i];
    }
    if (t->nclasses < DRS_CLASSES_MAX) {
        struct drs_class *row = &t->classes[t->nclasses++];
        memcpy(row->name, name, strlen(name) + 1u);
        return row;
    }
    t->other_used = true;
    return &t->other;
}

static void drs_tally_defect(struct drs_tally *t, const struct drs_case *cs,
                             const struct ers_result *r)
{
    struct drs_class *row = drs_class_row(t, cs->c.cls);
    t->defect_reviews++;
    row->reviews++;
    if (!r->accepted)
        return;
    t->defect_accepted++;
    row->accepted++;
    if (cs->c.locus == ERS_LOCUS_CODE)
        t->acc_code++;
    else
        t->acc_claim++;
}

static void drs_tally_review(struct drs_tally *t, const struct drs_case *cs,
                             const struct ers_result *r)
{
    t->findings_total += (int64_t)r->findings;
    t->findings_discarded += (int64_t)r->discarded;
    if (cs->c.label == ERS_LABEL_DEFECT) {
        drs_tally_defect(t, cs, r);
        return;
    }
    t->sound_reviews++;
    t->sound_rejected += r->rejected ? 1 : 0;
    t->rej_change += r->rejected_change ? 1 : 0;
    t->rej_claim += r->rejected_claim ? 1 : 0;
}

static enum drs_row drs_score_known(struct drs_run *run, struct drs_case *cs,
                                    const struct json_value *findings)
{
    size_t n = json_size(findings);
    struct ers_finding *f = NULL;
    if (n > 0) {
        f = zcl_malloc(n * sizeof(*f), "reviewscore_findings");
        if (!f) {
            run->alloc_failed = true;
            return DRS_ROW_STOP;
        }
    }
    for (size_t i = 0; i < n; i++)
        drs_parse_finding(json_at(findings, i), &f[i]);
    struct ers_result r;
    ers_score_review(&cs->c, f, n, &r);
    free(f);
    drs_tally_review(&run->tally, cs, &r);
    cs->reviews++;
    return DRS_ROW_OK;
}

static enum drs_row drs_review_row(void *ctx, const struct json_value *row)
{
    struct drs_run *run = ctx;
    const char *id = drs_str(row, "case");
    const struct json_value *findings = json_get(row, "findings");
    if (!id || !id[0] || !findings || findings->type != JSON_ARR)
        return DRS_ROW_BAD;
    struct drs_case *cs = drs_find(run->set, id);
    if (!cs) {
        run->tally.unknown++;
        return DRS_ROW_OK;
    }
    return drs_score_known(run, cs, findings);
}

static bool drs_load_reviews(struct zcl_command_reply *reply, const char *path,
                             struct drs_run *run)
{
    FILE *fp = drs_open(reply, path, "reviews");
    if (!fp)
        return false;
    struct drs_bad bad;
    memset(&bad, 0, sizeof(bad));
    bool read_ok = drs_scan(fp, drs_review_row, run, &bad);
    run->tally.malformed = (int64_t)bad.count;
    if (run->alloc_failed) {
        drs_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "aggregate",
                   "out of memory while scoring a review",
                   "dev.agent.reviewscore findings buffer",
                   "retry with a smaller reviews file");
        return false;
    }
    if (!read_ok)
        return drs_refuse_unreadable(reply, "reviews", path);
    return true;
}

/* ── the reply ──────────────────────────────────────────────────────── */

static bool drs_push_pair(struct json_value *data, const char *key,
                          int64_t num, int64_t den)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    bool ok = json_push_kv_int(&obj, "num", num) &&
              json_push_kv_int(&obj, "den", den) &&
              json_push_kv(data, key, &obj);
    json_free(&obj);
    return ok;
}

static bool drs_push_class_row(struct json_value *arr, const struct drs_class *c)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    bool ok = json_push_kv_str(&obj, "class", c->name) &&
              json_push_kv_int(&obj, "defect_reviews", c->reviews) &&
              json_push_kv_int(&obj, "defect_accepted", c->accepted) &&
              json_push_back(arr, &obj);
    json_free(&obj);
    return ok;
}

static bool drs_push_classes(struct json_value *data, const struct drs_tally *t)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    bool ok = true;
    for (size_t i = 0; ok && i < t->nclasses; i++)
        ok = drs_push_class_row(&arr, &t->classes[i]);
    if (ok && t->other_used) {
        struct drs_class other = t->other;
        memcpy(other.name, DRS_FOLD_NAME, sizeof(DRS_FOLD_NAME));
        ok = drs_push_class_row(&arr, &other);
    }
    ok = ok && json_push_kv(data, "by_class", &arr) &&
         json_push_kv_bool(data, "classes_truncated", t->other_used);
    json_free(&arr);
    return ok;
}

static bool drs_push_unreviewed(struct json_value *data, const struct drs_set *s)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    int64_t total = 0;
    bool ok = true;
    for (size_t i = 0; ok && i < s->n; i++) {
        if (s->items[i].reviews != 0)
            continue;
        if (total < (int64_t)DRS_UNREVIEWED_MAX) {
            struct json_value id;
            json_init(&id);
            json_set_str(&id, s->items[i].c.id);
            ok = json_push_back(&arr, &id);
            json_free(&id);
        }
        total++;
    }
    ok = ok && json_push_kv(data, "unreviewed", &arr) &&
         json_push_kv_int(data, "unreviewed_total", total) &&
         json_push_kv_bool(data, "unreviewed_truncated",
                           total > (int64_t)DRS_UNREVIEWED_MAX);
    json_free(&arr);
    return ok;
}

/* ── independence of the defect cases ───────────────────────────────── */

struct drs_cnt {
    const char *name;
    int64_t n;
};

struct drs_indep {
    struct drs_cnt *rows; /* bases first, then classes; one block */
    struct drs_cnt *bases;
    struct drs_cnt *classes;
    size_t nb, nc;
    int64_t max_base, max_class, over_base, over_class;
    bool ok;
};

/* Count `name` in out[0..*k); a linear scan, so the tally is O(defects x
 * distinct names): 4096 x 4096 string compares at the cap. */
static void drs_count_name(struct drs_cnt *out, size_t *k, const char *name)
{
    for (size_t i = 0; i < *k; i++) {
        if (strcmp(out[i].name, name) == 0) {
            out[i].n++;
            return;
        }
    }
    out[*k].name = name;
    out[*k].n = 1;
    (*k)++;
}

static void drs_measure(const struct drs_cnt *c, size_t k, int64_t limit,
                        int64_t *max, int64_t *over)
{
    *max = 0;
    *over = 0;
    for (size_t i = 0; i < k; i++) {
        if (c[i].n > *max)
            *max = c[i].n;
        if (c[i].n > limit)
            (*over)++;
    }
}

/* Only defect cases are tallied; a sound case belongs to no base or class. */
static bool drs_indep_build(struct drs_indep *in, const struct drs_set *s)
{
    memset(in, 0, sizeof(*in));
    in->rows = zcl_malloc((2u * (size_t)s->defect + 1u) * sizeof(*in->rows),
                          "reviewscore_indep");
    if (!in->rows)
        return false;
    in->bases = in->rows;
    in->classes = in->rows + s->defect;
    for (size_t i = 0; i < s->n; i++) {
        if (s->items[i].c.label != ERS_LABEL_DEFECT)
            continue;
        drs_count_name(in->bases, &in->nb, s->items[i].base);
        drs_count_name(in->classes, &in->nc, s->items[i].c.cls);
    }
    drs_measure(in->bases, in->nb, DRS_PER_BASE_LIMIT, &in->max_base,
                &in->over_base);
    drs_measure(in->classes, in->nc, DRS_PER_CLASS_LIMIT, &in->max_class,
                &in->over_class);
    in->ok = in->over_base == 0 && in->over_class == 0;
    return true;
}

static bool drs_push_over(struct json_value *obj, const char *key,
                          const char *total_key, const struct drs_cnt *c,
                          size_t k, int64_t limit, int64_t total)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    size_t pushed = 0;
    bool ok = true;
    for (size_t i = 0; ok && i < k && pushed < DRS_OVER_MAX; i++) {
        if (c[i].n <= limit)
            continue;
        struct json_value el;
        json_init(&el);
        json_set_str(&el, c[i].name);
        ok = json_push_back(&arr, &el);
        json_free(&el);
        pushed++;
    }
    ok = ok && json_push_kv(obj, key, &arr) &&
         json_push_kv_int(obj, total_key, total);
    json_free(&arr);
    return ok;
}

static bool drs_push_independence(struct json_value *data,
                                  const struct drs_indep *in)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    bool ok = json_push_kv_int(&obj, "bases", (int64_t)in->nb) &&
              json_push_kv_int(&obj, "per_base_limit", DRS_PER_BASE_LIMIT) &&
              json_push_kv_int(&obj, "per_class_limit", DRS_PER_CLASS_LIMIT) &&
              json_push_kv_int(&obj, "max_per_base", in->max_base) &&
              json_push_kv_int(&obj, "max_per_class", in->max_class) &&
              drs_push_over(&obj, "over_base", "over_base_total", in->bases,
                            in->nb, DRS_PER_BASE_LIMIT, in->over_base) &&
              drs_push_over(&obj, "over_class", "over_class_total",
                            in->classes, in->nc, DRS_PER_CLASS_LIMIT,
                            in->over_class) &&
              json_push_kv_bool(&obj, "ok", in->ok) &&
              json_push_kv(data, "independence", &obj);
    json_free(&obj);
    return ok;
}

static bool drs_push_set_counts(struct json_value *data, const struct drs_set *s,
                                const struct drs_indep *in)
{
    bool enough = s->defect >= DRS_DEFECT_MIN;
    return json_push_kv_int(data, "sound_cases", s->sound) &&
           json_push_kv_int(data, "defect_cases", s->defect) &&
           json_push_kv_int(data, "defect_cases_min", DRS_DEFECT_MIN) &&
           json_push_kv_bool(data, "defect_cases_enough", enough) &&
           json_push_kv_bool(data, "set_ready",
                             enough && in->ok && s->sound > 0) &&
           json_push_kv_int(data, "set_malformed_lines", (int64_t)s->bad.count);
}

static bool drs_push_review_counts(struct json_value *data,
                                   const struct drs_tally *t)
{
    return json_push_kv_int(data, "sound_reviews", t->sound_reviews) &&
           json_push_kv_int(data, "sound_rejected", t->sound_rejected) &&
           json_push_kv_int(data, "sound_rejected_change", t->rej_change) &&
           json_push_kv_int(data, "sound_rejected_claim", t->rej_claim) &&
           json_push_kv_int(data, "defect_reviews", t->defect_reviews) &&
           json_push_kv_int(data, "defect_accepted", t->defect_accepted) &&
           json_push_kv_int(data, "defect_accepted_code", t->acc_code) &&
           json_push_kv_int(data, "defect_accepted_claim", t->acc_claim) &&
           json_push_kv_int(data, "findings_total", t->findings_total) &&
           json_push_kv_int(data, "findings_discarded", t->findings_discarded) &&
           json_push_kv_int(data, "reviews_malformed_lines", t->malformed) &&
           json_push_kv_int(data, "unknown_case_reviews", t->unknown);
}

static bool drs_push_all(struct json_value *data, const struct drs_set *s,
                         const struct drs_tally *t)
{
    struct drs_indep in;
    if (!drs_indep_build(&in, s))
        return false;
    bool ok = drs_push_set_counts(data, s, &in) &&
              drs_push_review_counts(data, t) &&
              drs_push_pair(data, "sound_reject_rate", t->sound_rejected,
                            t->sound_reviews) &&
              drs_push_pair(data, "defect_accept_rate", t->defect_accepted,
                            t->defect_reviews) &&
              json_push_kv_bool(data, "measurable",
                                t->sound_reviews > 0 && t->defect_reviews > 0) &&
              drs_push_unreviewed(data, s) && drs_push_classes(data, t) &&
              drs_push_independence(data, &in);
    free(in.rows);
    return ok;
}

static const char *drs_path(struct zcl_command_reply *reply,
                            const struct json_value *input, const char *key)
{
    const char *path = drs_str(input, key);
    if (path && path[0])
        return path;
    char msg[128];
    (void)snprintf(msg, sizeof(msg), "missing required input key '%s'", key);
    drs_refuse(reply, ZCL_COMMAND_EXIT_INVALID, "BAD_INPUT", "validate", msg,
               "dev.agent.reviewscore reads one set file and one reviews file",
               "rerun with --set=<cases.jsonl> --reviews=<reviews.jsonl>");
    return NULL;
}

void zcl_native_handle_dev_agent_reviewscore(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!reply)
        return;
    (void)json_push_kv_str(&reply->data, "leaf", DRS_LEAF);
    const struct json_value *input = request ? request->input : NULL;
    const char *set_path = drs_path(reply, input, "set");
    if (!set_path)
        return;
    const char *reviews_path = drs_path(reply, input, "reviews");
    if (!reviews_path)
        return;

    struct drs_set set;
    memset(&set, 0, sizeof(set));
    struct drs_run *run = zcl_malloc(sizeof(*run), "reviewscore_run");
    if (!run) {
        drs_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "aggregate",
                   "out of memory", "dev.agent.reviewscore tally", NULL);
        return;
    }
    memset(run, 0, sizeof(*run));
    run->set = &set;
    if (drs_load_set(reply, set_path, &set) &&
        drs_load_reviews(reply, reviews_path, run)) {
        if (!drs_push_all(&reply->data, &set, &run->tally))
            drs_refuse(reply, ZCL_COMMAND_EXIT_INTERNAL, "ALLOC", "aggregate",
                       "out of memory while rendering the score",
                       "dev.agent.reviewscore reply", "retry");
    }
    free(run);
    drs_set_free(&set);
}
