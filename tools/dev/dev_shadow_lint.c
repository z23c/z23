/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Price lint gates from recorded base-relative premise selection
 * rows, name the obligation classes of a shadow prediction, and tally fresh
 * seconds per obligation for the top-N table. Shadow report only. */

#include "dev_shadow_select.h"

#include "test_group_catalog.h"

#include "base/safe_alloc.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

static const char *const shadow_class_names[ZCL_SHADOW_CLASS__COUNT] = {
    "lint", "floor", "direct", "caller", "integration", "fallback",
};

const char *zcl_shadow_class_name(enum zcl_shadow_class c)
{
    if ((unsigned)c >= ZCL_SHADOW_CLASS__COUNT) return "unknown";
    return shadow_class_names[c];
}

static void shadow_lint_why(char *why, size_t why_len, const char *fmt, ...)
{
    if (!why || why_len == 0) return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(why, why_len, fmt, ap);
    va_end(ap);
}

/* ── premise rows ─────────────────────────────────────────────────────── */

#define SHADOW_LINT_FIELDS 7

static bool shadow_lint_u32(const char *s, size_t n, uint32_t *out)
{
    if (n == 0 || n > 10) return false;
    uint64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10u + (uint64_t)(s[i] - '0');
    }
    if (v > UINT32_MAX) return false;
    *out = (uint32_t)v;
    return true;
}

static bool shadow_lint_copy(char *dst, size_t cap, const char *s, size_t n)
{
    if (n == 0 || n >= cap) return false;
    memcpy(dst, s, n);
    dst[n] = '\0';
    return true;
}

static bool shadow_lint_split(const char *line, size_t len,
                              const char **field, size_t *flen)
{
    size_t f = 0, start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i < len && line[i] != '\t') continue;
        if (f >= SHADOW_LINT_FIELDS || i == start) return false;
        field[f] = line + start;
        flen[f] = i - start;
        f++;
        start = i + 1;
    }
    return f == SHADOW_LINT_FIELDS;
}

static bool shadow_lint_selection(const char *s, size_t n, bool *enabled)
{
    if (n == 7 && memcmp(s, "enabled", 7) == 0) *enabled = true;
    else if (n == 8 && memcmp(s, "disabled", 8) == 0) *enabled = false;
    else return false;
    return true;
}

/* A row is refused, never repaired: every field present, a known selection
 * word, at least one unit, no more fresh units than units, and one row per
 * entry and gate. */
static bool shadow_lint_row(const char *line, size_t n,
                            struct zcl_shadow_lint_premise *r)
{
    const char *f[SHADOW_LINT_FIELDS];
    size_t len[SHADOW_LINT_FIELDS];
    memset(r, 0, sizeof(*r));
    return shadow_lint_split(line, n, f, len) &&
           shadow_lint_copy(r->id, sizeof(r->id), f[0], len[0]) &&
           shadow_lint_copy(r->gate, sizeof(r->gate), f[1], len[1]) &&
           shadow_lint_u32(f[2], len[2], &r->units) &&
           shadow_lint_u32(f[3], len[3], &r->fresh) &&
           shadow_lint_selection(f[4], len[4], &r->enabled) &&
           shadow_lint_u32(f[5], len[5], &r->select_ms) &&
           shadow_lint_u32(f[6], len[6], &r->always_ms) && r->units > 0 &&
           r->fresh <= r->units;
}

const struct zcl_shadow_lint_premise *
zcl_shadow_lint_premise_find(const struct zcl_shadow_lint_premises *p,
                             const char *id, const char *gate)
{
    if (!p || !id || !gate) return NULL;
    for (size_t i = 0; i < p->count; i++)
        if (strcmp(p->rows[i].id, id) == 0 &&
            strcmp(p->rows[i].gate, gate) == 0)
            return &p->rows[i];
    return NULL;
}

static size_t shadow_lint_lines(const char *text, size_t len)
{
    size_t n = 1;
    for (size_t i = 0; i < len; i++) n += text[i] == '\n';
    return n;
}

static bool shadow_lint_add(struct zcl_shadow_lint_premises *out,
                            const char *line, size_t n, size_t line_no,
                            char *why, size_t why_len)
{
    struct zcl_shadow_lint_premise row;
    if (!shadow_lint_row(line, n, &row)) {
        shadow_lint_why(why, why_len, "lint_premise_line_%zu_refused",
                        line_no);
        return false;
    }
    if (zcl_shadow_lint_premise_find(out, row.id, row.gate)) {
        shadow_lint_why(why, why_len, "lint_premise_line_%zu_duplicate",
                        line_no);
        return false;
    }
    out->rows[out->count++] = row;
    return true;
}

bool zcl_shadow_lint_premises_parse(const char *text, size_t len,
                                    struct zcl_shadow_lint_premises *out,
                                    char *why, size_t why_len)
{
    if (!text || !out) return false;
    memset(out, 0, sizeof(*out));
    out->rows = zcl_calloc(shadow_lint_lines(text, len), sizeof(*out->rows),
                           "shadow_lint_premise");
    if (!out->rows) return false;
    size_t pos = 0, line_no = 0;
    bool ok = true;
    while (ok && pos < len) {
        const char *nl = memchr(text + pos, '\n', len - pos);
        size_t end = nl ? (size_t)(nl - text) : len;
        const char *line = text + pos;
        size_t n = end - pos;
        line_no++;
        pos = nl ? end + 1 : len;
        if (n == 0 || line[0] == '#') continue;
        ok = shadow_lint_add(out, line, n, line_no, why, why_len);
    }
    if (!ok) zcl_shadow_lint_premises_free(out);
    return ok;
}

void zcl_shadow_lint_premises_free(struct zcl_shadow_lint_premises *p)
{
    if (!p) return;
    free(p->rows);
    p->rows = NULL;
    p->count = 0;
}

uint64_t zcl_shadow_lint_gate_ms(const struct zcl_shadow_lint_premise *row,
                                 uint32_t gate_ms, bool *premise_priced)
{
    if (premise_priced) *premise_priced = false;
    if (!row || !row->enabled || row->units == 0 || row->fresh > row->units)
        return gate_ms;
    uint64_t always = row->always_ms < gate_ms ? row->always_ms : gate_ms;
    uint64_t rest = (uint64_t)gate_ms - always;
    uint64_t share = (rest + row->units - 1u) / row->units;
    if (share < ZCL_SHADOW_LINT_UNIT_FLOOR_MS)
        share = ZCL_SHADOW_LINT_UNIT_FLOOR_MS;
    if (premise_priced) *premise_priced = true;
    uint64_t units_ms = share * row->fresh;
    if (units_ms > rest) units_ms = rest;
    return (uint64_t)row->select_ms + always + units_ms;
}

/* ── tally ────────────────────────────────────────────────────────────── */

bool zcl_shadow_tally_init(struct zcl_shadow_tally *t,
                           const struct zcl_shadow_weights *weights)
{
    if (!t || !weights) return false;
    memset(t, 0, sizeof(*t));
    t->weights = weights;
    t->groups = zcl_test_group_catalog_count();
    size_t lints = weights->count ? weights->count : 1;
    t->group_ms = zcl_calloc(t->groups + 1, sizeof(uint64_t), "tally_gms");
    t->group_entries = zcl_calloc(t->groups + 1, sizeof(uint32_t),
                                  "tally_gn");
    t->lint_ms = zcl_calloc(lints, sizeof(uint64_t), "tally_lms");
    t->lint_premise_ms = zcl_calloc(lints, sizeof(uint64_t), "tally_lpms");
    t->lint_entries = zcl_calloc(lints, sizeof(uint32_t), "tally_ln");
    bool ok = t->group_ms && t->group_entries && t->lint_ms &&
              t->lint_premise_ms && t->lint_entries;
    if (!ok) zcl_shadow_tally_free(t);
    return ok;
}

void zcl_shadow_tally_free(struct zcl_shadow_tally *t)
{
    if (!t) return;
    free(t->group_ms);
    free(t->group_entries);
    free(t->lint_ms);
    free(t->lint_premise_ms);
    free(t->lint_entries);
    memset(t, 0, sizeof(*t));
}

struct shadow_top_pick {
    bool lint;
    size_t index;
    uint64_t ms;
};

static struct shadow_top_pick shadow_top_next(const struct zcl_shadow_tally *t,
                                              const bool *lint_done,
                                              const bool *group_done)
{
    struct shadow_top_pick best = {false, SIZE_MAX, 0};
    for (size_t i = 0; i < t->weights->count; i++)
        if (!lint_done[i] && t->lint_ms[i] > best.ms)
            best = (struct shadow_top_pick){true, i, t->lint_ms[i]};
    for (size_t i = 0; i < t->groups; i++)
        if (!group_done[i] && t->group_ms[i] > best.ms)
            best = (struct shadow_top_pick){false, i, t->group_ms[i]};
    return best;
}

static bool shadow_top_line(FILE *out, const struct zcl_shadow_tally *t,
                            size_t rank, struct shadow_top_pick pick)
{
    const char *name = pick.lint ? t->weights->rows[pick.index].name
                                 : zcl_test_group_catalog_at(pick.index);
    uint32_t entries = pick.lint ? t->lint_entries[pick.index]
                                 : t->group_entries[pick.index];
    uint64_t after = pick.lint ? t->lint_premise_ms[pick.index] : pick.ms;
    return fprintf(out,
                   "SHADOW-TOP rank=%zu kind=%s name=%s fresh_s=%.1f "
                   "entries=%u fresh_s_with_lint_premise=%.1f\n",
                   rank, pick.lint ? "lint_gate" : "test_group", name,
                   (double)pick.ms / 1000.0, entries,
                   (double)after / 1000.0) > 0;
}

bool zcl_shadow_render_top(FILE *out, const struct zcl_shadow_tally *t,
                           size_t k)
{
    if (!out || !t || !t->weights) return false;
    bool *lint_done = zcl_calloc(t->weights->count + 1, sizeof(bool),
                                 "tally_ld");
    bool *group_done = zcl_calloc(t->groups + 1, sizeof(bool), "tally_gd");
    bool ok = lint_done && group_done;
    for (size_t rank = 1; ok && rank <= k; rank++) {
        struct shadow_top_pick pick = shadow_top_next(t, lint_done,
                                                      group_done);
        if (pick.index == SIZE_MAX) break;
        (pick.lint ? lint_done : group_done)[pick.index] = true;
        ok = shadow_top_line(out, t, rank, pick);
    }
    free(lint_done);
    free(group_done);
    return ok;
}
