/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Record the selector's prediction before any proof runs, read the
 * reference run back, and name every required obligation a prediction
 * missed. */

#include "dev_shadow_select.h"

#include "base/safe_alloc.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static const char *const shadow_layer_names[ZCL_SHADOW_LAYER__COUNT] = {
    "contract", "caller", "integration",
};

const char *zcl_shadow_layer_name(enum zcl_shadow_layer layer)
{
    if ((unsigned)layer >= ZCL_SHADOW_LAYER__COUNT) return "unknown";
    return shadow_layer_names[layer];
}

static void shadow_cmp_why(char *why, size_t why_len, const char *fmt, ...)
{
    if (!why || why_len == 0) return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(why, why_len, fmt, ap);
    va_end(ap);
}

static bool shadow_names_truncated(const char *names)
{
    size_t n = strlen(names);
    return n >= 3 && strcmp(names + n - 3, "...") == 0;
}

bool zcl_shadow_render_prediction(FILE *out, const struct zcl_shadow_result *r)
{
    if (!out || !r) return false;
    bool sel_all = r->selector_universal;
    bool rule_all = r->predict_mode == ZCL_SHADOW_PREDICT_ALL;
    if ((!sel_all && shadow_names_truncated(r->selected_names)) ||
        (!rule_all && shadow_names_truncated(r->predicted_names)))
        return false;
    const char *sel = sel_all || !r->selected_names[0] ? "-"
                                                       : r->selected_names;
    const char *rule = rule_all || !r->predicted_names[0] ? "-"
                                                          : r->predicted_names;
    return fprintf(out, "%s\t%s\t%s\t%s\t%s\n", r->id,
                   sel_all ? "all" : "exact", sel, rule_all ? "all" : "exact",
                   rule) > 0;
}

bool zcl_shadow_names_contain(const char *names, const char *group)
{
    if (!names || !group || !group[0]) return false;
    size_t g = strlen(group);
    for (const char *p = names; *p;) {
        const char *comma = strchr(p, ',');
        size_t n = comma ? (size_t)(comma - p) : strlen(p);
        if (n == g && strncmp(p, group, g) == 0) return true;
        if (!comma) break;
        p = comma + 1;
    }
    return false;
}

/* ── tab-separated rows ───────────────────────────────────────────────── */

#define SHADOW_CMP_FIELDS 5

struct shadow_row {
    const char *field[SHADOW_CMP_FIELDS];
    size_t len[SHADOW_CMP_FIELDS];
};

/* Splits one line into exactly SHADOW_CMP_FIELDS tab-separated fields. */
static bool shadow_split(const char *line, size_t len, struct shadow_row *row)
{
    size_t f = 0, start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i < len && line[i] != '\t') continue;
        if (f >= SHADOW_CMP_FIELDS) return false;
        row->field[f] = line + start;
        row->len[f] = i - start;
        if (row->len[f] == 0) return false;
        f++;
        start = i + 1;
    }
    return f == SHADOW_CMP_FIELDS;
}

static bool shadow_copy(char *dst, size_t cap, const char *src, size_t len)
{
    if (len >= cap) return false;
    memcpy(dst, src, len);
    dst[len] = '\0';
    return true;
}

typedef bool (*shadow_row_fn)(const struct shadow_row *row, void *ctx,
                              char *why, size_t why_len);

static size_t shadow_line_count(const char *text, size_t len)
{
    size_t n = 1;
    for (size_t i = 0; i < len; i++) n += text[i] == '\n';
    return n;
}

static bool shadow_rows_each(const char *text, size_t len, shadow_row_fn fn,
                             void *ctx, char *why, size_t why_len)
{
    size_t pos = 0, line_no = 0;
    while (pos < len) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t end = nl ? (size_t)(nl - text) : len;
        const char *line = text + pos;
        size_t n = end - pos;
        line_no++;
        pos = nl ? end + 1 : len;
        if (n == 0 || line[0] == '#') continue;
        struct shadow_row row;
        if (!shadow_split(line, n, &row)) {
            shadow_cmp_why(why, why_len, "line_%zu_needs_%d_fields", line_no,
                           SHADOW_CMP_FIELDS);
            return false;
        }
        if (!fn(&row, ctx, why, why_len)) return false;
    }
    return true;
}

/* ── predictions ──────────────────────────────────────────────────────── */

static bool shadow_mode_parse(const struct shadow_row *row, size_t f,
                              enum zcl_shadow_predict_mode *mode)
{
    if (row->len[f] == 3 && memcmp(row->field[f], "all", 3) == 0)
        *mode = ZCL_SHADOW_PREDICT_ALL;
    else if (row->len[f] == 5 && memcmp(row->field[f], "exact", 5) == 0)
        *mode = ZCL_SHADOW_PREDICT_EXACT;
    else
        return false;
    /* `all` carries no list: the reference itself is the set. */
    return *mode == ZCL_SHADOW_PREDICT_EXACT ||
           (row->len[f + 1] == 1 && row->field[f + 1][0] == '-');
}

static bool shadow_names_parse(const struct shadow_row *row, size_t f,
                               char *dst, size_t cap)
{
    if (row->len[f] == 1 && row->field[f][0] == '-') {
        dst[0] = '\0';
        return true;
    }
    return shadow_copy(dst, cap, row->field[f], row->len[f]) &&
           !shadow_names_truncated(dst);
}

static bool shadow_prediction_row(const struct shadow_row *row, void *ctx,
                                  char *why, size_t why_len)
{
    struct zcl_shadow_predictions *p = ctx;
    struct zcl_shadow_prediction *out = &p->rows[p->count];
    bool ok = shadow_copy(out->id, sizeof(out->id), row->field[0],
                          row->len[0]) &&
              shadow_mode_parse(row, 1, &out->selector_mode) &&
              shadow_names_parse(row, 2, out->selector_names,
                                 sizeof(out->selector_names)) &&
              shadow_mode_parse(row, 3, &out->rule_mode) &&
              shadow_names_parse(row, 4, out->rule_names,
                                 sizeof(out->rule_names));
    if (!ok) {
        shadow_cmp_why(why, why_len, "prediction_row_%zu_invalid",
                       p->count + 1);
        return false;
    }
    if (zcl_shadow_prediction_find(p, out->id)) {
        shadow_cmp_why(why, why_len, "prediction_duplicate_%s", out->id);
        return false;
    }
    p->count++;
    return true;
}

bool zcl_shadow_predictions_parse(const char *text, size_t len,
                                  struct zcl_shadow_predictions *out,
                                  char *why, size_t why_len)
{
    if (!text || !out) return false;
    memset(out, 0, sizeof(*out));
    size_t cap = shadow_line_count(text, len);
    out->rows = zcl_calloc(cap, sizeof(*out->rows), "shadow_predictions");
    if (!out->rows) return false;
    if (shadow_rows_each(text, len, shadow_prediction_row, out, why, why_len))
        return true;
    zcl_shadow_predictions_free(out);
    return false;
}

void zcl_shadow_predictions_free(struct zcl_shadow_predictions *p)
{
    if (!p) return;
    free(p->rows);
    p->rows = NULL;
    p->count = 0;
}

const struct zcl_shadow_prediction *
zcl_shadow_prediction_find(const struct zcl_shadow_predictions *p,
                           const char *id)
{
    if (!p || !id) return NULL;
    for (size_t i = 0; i < p->count; i++)
        if (strcmp(p->rows[i].id, id) == 0) return &p->rows[i];
    return NULL;
}

/* ── observations ─────────────────────────────────────────────────────── */

static bool shadow_verdict_parse(const struct shadow_row *row, size_t f,
                                 enum zcl_shadow_verdict *out)
{
    static const struct {
        const char *name;
        enum zcl_shadow_verdict verdict;
    } names[] = {
        {"pass", ZCL_SHADOW_VERDICT_PASS},
        {"fail", ZCL_SHADOW_VERDICT_FAIL},
        {"not-run", ZCL_SHADOW_VERDICT_NOT_RUN},
    };
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
        if (strlen(names[i].name) == row->len[f] &&
            memcmp(row->field[f], names[i].name, row->len[f]) == 0) {
            *out = names[i].verdict;
            return true;
        }
    return false;
}

static bool shadow_observation_row(const struct shadow_row *row, void *ctx,
                                   char *why, size_t why_len)
{
    struct zcl_shadow_observations *o = ctx;
    struct zcl_shadow_observation *out = &o->rows[o->count];
    bool ok = shadow_copy(out->id, sizeof(out->id), row->field[0],
                          row->len[0]) &&
              shadow_copy(out->group, sizeof(out->group), row->field[1],
                          row->len[1]) &&
              shadow_verdict_parse(row, 2, &out->base) &&
              shadow_verdict_parse(row, 3, &out->patched);
    if (!ok) {
        shadow_cmp_why(why, why_len, "observation_row_%zu_invalid",
                       o->count + 1);
        return false;
    }
    for (size_t i = 0; i < o->count; i++)
        if (strcmp(o->rows[i].id, out->id) == 0 &&
            strcmp(o->rows[i].group, out->group) == 0) {
            shadow_cmp_why(why, why_len, "observation_duplicate_%s_%s",
                           out->id, out->group);
            return false;
        }
    o->count++;
    return true;
}

bool zcl_shadow_observations_parse(const char *text, size_t len,
                                   struct zcl_shadow_observations *out,
                                   char *why, size_t why_len)
{
    if (!text || !out) return false;
    memset(out, 0, sizeof(*out));
    size_t cap = shadow_line_count(text, len);
    out->rows = zcl_calloc(cap, sizeof(*out->rows), "shadow_observations");
    if (!out->rows) return false;
    if (shadow_rows_each(text, len, shadow_observation_row, out, why,
                         why_len))
        return true;
    zcl_shadow_observations_free(out);
    return false;
}

void zcl_shadow_observations_free(struct zcl_shadow_observations *o)
{
    if (!o) return;
    free(o->rows);
    o->rows = NULL;
    o->count = 0;
}

/* ── comparison ───────────────────────────────────────────────────────── */

bool zcl_shadow_obligation_required(const struct zcl_shadow_observation *o)
{
    if (!o || o->patched == ZCL_SHADOW_VERDICT_NOT_RUN) return false;
    if (o->patched == ZCL_SHADOW_VERDICT_FAIL) return true;
    return o->base != ZCL_SHADOW_VERDICT_NOT_RUN && o->base != o->patched;
}

static bool shadow_covers(enum zcl_shadow_predict_mode mode,
                          const char *names, const char *group)
{
    return mode == ZCL_SHADOW_PREDICT_ALL ||
           zcl_shadow_names_contain(names, group);
}

static void shadow_red(uint32_t *count, char *first, const char *group)
{
    if ((*count)++ == 0)
        (void)snprintf(first, ZCL_SHADOW_NAME_MAX, "%s", group);
}

bool zcl_shadow_compare(const struct zcl_shadow_prediction *p,
                        const struct zcl_shadow_observations *obs,
                        struct zcl_shadow_comparison *out)
{
    if (!p || !obs || !out) return false;
    memset(out, 0, sizeof(*out));
    for (size_t i = 0; i < obs->count; i++) {
        const struct zcl_shadow_observation *o = &obs->rows[i];
        if (strcmp(o->id, p->id) != 0) continue;
        out->observed++;
        if (!zcl_shadow_obligation_required(o)) continue;
        out->required++;
        if (!shadow_covers(p->selector_mode, p->selector_names, o->group))
            shadow_red(&out->red_selector, out->first_red_selector, o->group);
        if (!shadow_covers(p->rule_mode, p->rule_names, o->group))
            shadow_red(&out->red_rule, out->first_red_rule, o->group);
    }
    return true;
}

bool zcl_shadow_render_comparison(FILE *out, const char *id,
                                  const struct zcl_shadow_comparison *c)
{
    if (!out || !id || !c) return false;
    return fprintf(out,
        "SHADOW-COMPARE id=%s observed=%u required=%u red_selector=%u "
        "red_rule=%u first_red_selector=%s first_red_rule=%s verdict=%s\n",
        id, c->observed, c->required, c->red_selector, c->red_rule,
        c->first_red_selector[0] ? c->first_red_selector : "-",
        c->first_red_rule[0] ? c->first_red_rule : "-",
        c->red_rule ? "RED" : c->observed ? "GREEN" : "UNOBSERVED") > 0;
}
