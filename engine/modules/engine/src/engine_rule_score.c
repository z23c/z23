/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * engine_rule_score — the scoring half of the auto-updating heuristic set.
 *
 * ── OFF IS SAFE. ON IS NOT. ──────────────────────────────────────────────
 *
 * This file applies retirements and only PROPOSES promotions, and the reason
 * is not caution for its own sake. Turning a rule off costs one thing: an
 * executor stops being told something that may have been true, while the gate
 * goes on deciding every landing exactly as before. Turning a rule on costs
 * something else entirely: every future executor is handed a sentence nobody
 * read, by a loop that measured a correlation and called it guidance. The
 * first mistake is visible in a diff and revertible in one line. The second
 * one propagates.
 *
 * So: RETIRE rewrites rule_vocab.def in place, with the killing unit_ids in
 * the row so the decision can be argued with. PROMOTE writes a patch to the
 * state directory and stops. Nothing in this file ever applies one.
 *
 * See engine/modules/engine/include/engine/engine_rule_score.h for the rest
 * of the contract, and engine.h for the law the whole module rests on: the
 * model proposes, the gate decides.
 */

#include "engine/engine_rule_score.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ── labels ──────────────────────────────────────────────────────────── */

const char *zcl_rule_state_label(enum zcl_rule_state s)
{
    switch (s) {
    case ZCL_RULE_SHADOW:  return "shadow";
    case ZCL_RULE_OBEYED:  return "obeyed";
    case ZCL_RULE_RETIRED: return "retired";
    }
    return "unknown";
}

const char *zcl_rule_state_token(enum zcl_rule_state s)
{
    switch (s) {
    case ZCL_RULE_SHADOW:  return "ZCL_RULE_SHADOW";
    case ZCL_RULE_OBEYED:  return "ZCL_RULE_OBEYED";
    case ZCL_RULE_RETIRED: return "ZCL_RULE_RETIRED";
    }
    return "ZCL_RULE_SHADOW";
}

const char *zcl_rule_source_label(enum zcl_rule_source s)
{
    return s == ZCL_RULE_SRC_PERSONA ? "persona" : "grok";
}

const char *zcl_rule_verdict_label(enum zcl_rule_verdict v)
{
    switch (v) {
    case ZCL_RULE_VERDICT_UNTRIED:         return "untried";
    case ZCL_RULE_VERDICT_INSUFFICIENT:    return "insufficient";
    case ZCL_RULE_VERDICT_HOLD:            return "hold";
    case ZCL_RULE_VERDICT_RETIRE:          return "retire";
    case ZCL_RULE_VERDICT_PROMOTABLE:      return "promotable";
    case ZCL_RULE_VERDICT_ALREADY_RETIRED: return "already_retired";
    }
    return "unknown";
}

const char *zcl_rule_chain_status_label(enum zcl_rule_chain_status s)
{
    switch (s) {
    case ZCL_RULE_CHAIN_OK:        return "ok";
    case ZCL_RULE_CHAIN_EMPTY:     return "empty";
    case ZCL_RULE_CHAIN_MALFORMED: return "malformed_record";
    case ZCL_RULE_CHAIN_BROKEN:    return "chain_break";
    case ZCL_RULE_CHAIN_OVERFLOW:  return "over_bounds";
    }
    return "unknown";
}

/* ── the compiled-in vocabulary ──────────────────────────────────────── */

/* Including the .def here makes a malformed row a BUILD failure. The parser
 * below reads the same file as text because the rewriter has to preserve
 * comments and spacing, which a compiled table has already thrown away. */
static const struct zcl_rule_row k_builtin_rows[] = {
#define ZCL_RULE(id_, src_, state_, floor_, trials_, text_) \
    { .id = id_, .text = text_, .source = src_, .state = state_,            \
      .floor_permille = (floor_), .min_trials = (trials_), .line = 0 },
#include "../../../composition/rule_vocab.def"
#undef ZCL_RULE
};

const struct zcl_rule_vocab *zcl_rule_vocab_builtin(void)
{
    static struct zcl_rule_vocab v;
    static bool built = false;
    if (!built) {
        size_t n = sizeof k_builtin_rows / sizeof k_builtin_rows[0];
        if (n > ZCL_RULE_VOCAB_MAX) n = ZCL_RULE_VOCAB_MAX;
        for (size_t i = 0; i < n; i++)
            v.row[i] = k_builtin_rows[i];
        v.count = (uint32_t)n;
        built = true;
    }
    return &v;
}

/* ── small bounded helpers ───────────────────────────────────────────── */

static void copy_bounded(char *dst, size_t cap, const char *src, size_t len)
{
    if (cap == 0) return;
    if (len >= cap) len = cap - 1;
    if (len && src) memcpy(dst, src, len);
    dst[len] = '\0';
}

/* The one quoted literal starting at *at, unescaped only for \" and \\ —
 * a rule text carries no other escape and inventing support for the rest
 * would be a second JSON parser nobody asked for. Returns false if there is
 * no complete literal. */
static bool take_quoted(const char *s, size_t len, size_t *at,
                        char *out, size_t cap)
{
    size_t i = *at;
    while (i < len && (s[i] == ' ' || s[i] == '\t')) i++;
    if (i >= len || s[i] != '"') return false;
    i++;
    size_t w = 0;
    while (i < len && s[i] != '"') {
        char c = s[i];
        if (c == '\\' && i + 1 < len) { i++; c = s[i]; }
        if (w + 1 < cap) out[w] = c;
        w++;
        i++;
    }
    if (i >= len || s[i] != '"') return false;
    if (cap) out[w < cap ? w : cap - 1] = '\0';
    *at = i + 1;
    return true;
}

/* The next comma-separated bare token. */
static bool take_bare(const char *s, size_t len, size_t *at,
                      char *out, size_t cap)
{
    size_t i = *at;
    while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == ',')) i++;
    size_t start = i;
    while (i < len && s[i] != ',' && s[i] != ')' && s[i] != ' ' && s[i] != '\t')
        i++;
    if (i == start) return false;
    copy_bounded(out, cap, s + start, i - start);
    *at = i;
    return true;
}

static bool parse_u32(const char *s, uint32_t *out)
{
    if (!s || !*s) return false;
    uint64_t v = 0;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
        v = v * 10u + (uint64_t)(*p - '0');
        if (v > 0xFFFFFFFFull) return false;
    }
    *out = (uint32_t)v;
    return true;
}

/* ── vocabulary text parser ──────────────────────────────────────────── */

bool zcl_rule_vocab_parse(const char *text, size_t len,
                          struct zcl_rule_vocab *out)
{
    if (!text || !out) return false;
    memset(out, 0, sizeof *out);

    uint32_t line_no = 0;
    size_t i = 0;
    while (i < len) {
        size_t eol = i;
        while (eol < len && text[eol] != '\n') eol++;
        line_no++;
        size_t llen = eol - i;
        const char *line = text + i;

        static const char kPrefix[] = "ZCL_RULE(";
        if (llen > sizeof kPrefix - 1 &&
            memcmp(line, kPrefix, sizeof kPrefix - 1) == 0) {
            if (out->count >= ZCL_RULE_VOCAB_MAX) return false;
            struct zcl_rule_row row;
            memset(&row, 0, sizeof row);
            row.line = line_no;

            size_t at = sizeof kPrefix - 1;
            char src[40], st[40], fl[24], mt[24];
            if (!take_quoted(line, llen, &at, row.id, sizeof row.id))
                return false;
            if (!take_bare(line, llen, &at, src, sizeof src)) return false;
            if (!take_bare(line, llen, &at, st, sizeof st)) return false;
            if (!take_bare(line, llen, &at, fl, sizeof fl)) return false;
            if (!take_bare(line, llen, &at, mt, sizeof mt)) return false;
            while (at < llen && (line[at] == ',' || line[at] == ' ')) at++;
            if (!take_quoted(line, llen, &at, row.text, sizeof row.text))
                return false;

            if (strcmp(src, "ZCL_RULE_SRC_GROK") == 0)
                row.source = ZCL_RULE_SRC_GROK;
            else if (strcmp(src, "ZCL_RULE_SRC_PERSONA") == 0)
                row.source = ZCL_RULE_SRC_PERSONA;
            else
                return false;

            if (strcmp(st, "ZCL_RULE_SHADOW") == 0)
                row.state = ZCL_RULE_SHADOW;
            else if (strcmp(st, "ZCL_RULE_OBEYED") == 0)
                row.state = ZCL_RULE_OBEYED;
            else if (strcmp(st, "ZCL_RULE_RETIRED") == 0)
                row.state = ZCL_RULE_RETIRED;
            else
                return false;

            if (!parse_u32(fl, &row.floor_permille)) return false;
            if (!parse_u32(mt, &row.min_trials)) return false;
            if (row.floor_permille > 1000u || row.min_trials == 0u)
                return false;
            /* A duplicate id would give one rule two scores and let the
             * rewriter edit whichever it saw first. */
            for (uint32_t k = 0; k < out->count; k++)
                if (strcmp(out->row[k].id, row.id) == 0) return false;

            out->row[out->count++] = row;
        }
        i = (eol < len) ? eol + 1 : eol;
    }
    /* A vocabulary with no rows is not "clean", it is a parser that stopped
     * understanding the file. */
    return out->count > 0;
}

const struct zcl_rule_row *zcl_rule_vocab_find(const struct zcl_rule_vocab *v,
                                               const char *id)
{
    if (!v || !id) return NULL;
    for (uint32_t i = 0; i < v->count; i++)
        if (strcmp(v->row[i].id, id) == 0) return &v->row[i];
    return NULL;
}

/* ── the chain ───────────────────────────────────────────────────────── */

void zcl_rule_chain_link(const char *line, size_t len,
                         char out[ZCL_RULE_HEX_MAX])
{
    static const char hexd[] = "0123456789abcdef";
    unsigned char d[32];
    zcl_sha3_256((const unsigned char *)line, len, d);
    for (int i = 0; i < 32; i++) {
        out[i * 2] = hexd[d[i] >> 4];
        out[i * 2 + 1] = hexd[d[i] & 0x0f];
    }
    out[64] = '\0';
}

static const char *jstr(const struct json_value *o, const char *k)
{
    const struct json_value *v = json_get(o, k);
    if (!v || v->type != JSON_STR) return NULL;
    return json_get_str(v);
}

static bool jint(const struct json_value *o, const char *k, int64_t *out)
{
    const struct json_value *v = json_get(o, k);
    if (!v || v->type != JSON_INT) return false;
    *out = json_get_int(v);
    return true;
}

/* Integers only, as the schema says. A boolean field is an integer 0/1 or a
 * JSON true/false; both are accepted and nothing else is. */
static bool jbool(const struct json_value *o, const char *k, bool *out)
{
    const struct json_value *v = json_get(o, k);
    if (!v) return false;
    if (v->type == JSON_BOOL) { *out = json_get_bool(v); return true; }
    if (v->type == JSON_INT)  { *out = json_get_int(v) != 0; return true; }
    return false;
}

static bool receipt_from_json(const struct json_value *o,
                              struct zcl_rule_receipt *r)
{
    const char *schema = jstr(o, "schema");
    if (!schema || strcmp(schema, "zcl.engine_unit_receipt.v1") != 0)
        return false;

    const char *s;
    if (!(s = jstr(o, "unit_id"))) return false;
    copy_bounded(r->unit_id, sizeof r->unit_id, s, strlen(s));
    if (!(s = jstr(o, "task_sha3"))) return false;
    copy_bounded(r->task_sha3, sizeof r->task_sha3, s, strlen(s));

    if ((s = jstr(o, "engine")))
        copy_bounded(r->engine, sizeof r->engine, s, strlen(s));
    if ((s = jstr(o, "model")))
        copy_bounded(r->model, sizeof r->model, s, strlen(s));
    if ((s = jstr(o, "kind")))
        copy_bounded(r->kind, sizeof r->kind, s, strlen(s));
    if ((s = jstr(o, "group")))
        copy_bounded(r->group, sizeof r->group, s, strlen(s));
    if ((s = jstr(o, "template_sha3")))
        copy_bounded(r->template_sha3, sizeof r->template_sha3, s, strlen(s));
    if ((s = jstr(o, "worktree_head")))
        copy_bounded(r->worktree_head, sizeof r->worktree_head, s, strlen(s));

    int64_t n = 0;
    if (jint(o, "ts", &n) && n >= 0) r->ts = (uint64_t)n;
    if (jint(o, "prompt_tokens", &n) && n >= 0) r->prompt_tokens = (uint64_t)n;
    if (jint(o, "completion_tokens", &n) && n >= 0)
        r->completion_tokens = (uint64_t)n;
    if (jint(o, "wall_ms", &n) && n >= 0) r->wall_ms = (uint64_t)n;
    if (jint(o, "http_status", &n)) r->http_status = n;

    const struct json_value *shown = json_get(o, "rules_shown");
    if (shown && shown->type == JSON_ARR) {
        size_t cnt = json_size(shown);
        for (size_t i = 0; i < cnt && r->rules_shown_count < ZCL_RULE_SHOWN_MAX;
             i++) {
            const struct json_value *e = json_at(shown, i);
            if (!e || e->type != JSON_STR) continue;
            const char *id = json_get_str(e);
            if (!id || !*id) continue;
            copy_bounded(r->rules_shown[r->rules_shown_count],
                         ZCL_RULE_ID_MAX, id, strlen(id));
            r->rules_shown_count++;
        }
    }

    /* The outcome is where the ONE signal lives. A receipt with no outcome
     * object is not a receipt about an outcome, so it is refused rather than
     * counted as a failure — those are different facts. */
    const struct json_value *out = json_get(o, "outcome");
    if (!out || out->type != JSON_OBJ) return false;
    if (!jbool(out, "gate_pass", &r->gate_pass)) return false;
    (void)jbool(out, "applied", &r->applied);
    if (jint(out, "groups_ran", &n) && n >= 0) r->groups_ran = (uint32_t)n;
    if (jint(out, "groups_failed", &n) && n >= 0)
        r->groups_failed = (uint32_t)n;
    if (jint(out, "retries", &n) && n >= 0) r->retries = (uint32_t)n;
    if (jint(out, "lines_changed", &n) && n >= 0)
        r->lines_changed = (uint32_t)n;
    if (jint(out, "lint_rc", &n)) r->lint_rc = n;
    return true;
}

enum zcl_rule_chain_status
zcl_rule_receipts_parse(const char *text, size_t len,
                        struct zcl_rule_receipt_log *out, uint32_t *bad_line)
{
    if (bad_line) *bad_line = 0;
    if (!text || !out) return ZCL_RULE_CHAIN_MALFORMED;
    memset(out, 0, sizeof *out);
    if (len > ZCL_RULE_LOG_MAX) return ZCL_RULE_CHAIN_OVERFLOW;

    static const char kGenesis[65] =
        "0000000000000000000000000000000000000000000000000000000000000000";
    char expect[ZCL_RULE_HEX_MAX];
    memcpy(expect, kGenesis, sizeof kGenesis);

    uint32_t line_no = 0;
    size_t i = 0;
    while (i < len) {
        size_t eol = i;
        while (eol < len && text[eol] != '\n') eol++;
        size_t llen = eol - i;
        const char *line = text + i;
        i = (eol < len) ? eol + 1 : eol;

        /* Blank lines are not records and are not errors: a file that ends
         * with a newline has one. */
        bool blank = true;
        for (size_t k = 0; k < llen; k++)
            if (line[k] != ' ' && line[k] != '\t' && line[k] != '\r')
                { blank = false; break; }
        if (blank) continue;

        line_no++;
        if (bad_line) *bad_line = line_no;
        if (llen > ZCL_RULE_LINE_MAX) return ZCL_RULE_CHAIN_OVERFLOW;
        if (out->count >= ZCL_RULE_RECEIPT_MAX) return ZCL_RULE_CHAIN_OVERFLOW;

        struct json_value v;
        json_init(&v);
        if (!json_read(&v, line, llen)) {
            json_free(&v);
            return ZCL_RULE_CHAIN_MALFORMED;
        }
        if (v.type != JSON_OBJ) { json_free(&v); return ZCL_RULE_CHAIN_MALFORMED; }

        const char *prev = jstr(&v, "prev_sha3");
        if (!prev || strlen(prev) != 64) {
            json_free(&v);
            return ZCL_RULE_CHAIN_MALFORMED;
        }
        /* THE WHOLE LOG, NOT THE HONEST PREFIX. A score computed from the
         * records before a break is a number that reads as evidence and is
         * not one, so a break refuses everything. */
        if (memcmp(prev, expect, 64) != 0) {
            json_free(&v);
            return ZCL_RULE_CHAIN_BROKEN;
        }

        struct zcl_rule_receipt r;
        memset(&r, 0, sizeof r);
        if (!receipt_from_json(&v, &r)) {
            json_free(&v);
            return ZCL_RULE_CHAIN_MALFORMED;
        }
        json_free(&v);
        r.seq = line_no;
        out->r[out->count++] = r;
        zcl_rule_chain_link(line, llen, expect);
    }

    if (bad_line) *bad_line = 0;
    if (out->count == 0) return ZCL_RULE_CHAIN_EMPTY;
    return ZCL_RULE_CHAIN_OK;
}

/* ── the Wilson lower bound, in integers ─────────────────────────────── */

static uint64_t isqrt64(uint64_t n)
{
    if (n == 0) return 0;
    uint64_t x = n, y = (x + 1) / 2;
    while (y < x) { x = y; y = (x + n / x) / 2; }
    return x;
}

uint32_t zcl_rule_wilson_lower_permille(uint32_t passes, uint32_t trials)
{
    /* Nobody measured is not the same fact as it failed. */
    if (trials == 0) return 0;
    if (passes > trials) passes = trials;

    const uint64_t n = trials, k = passes;
    /* z = 1.96, so z^2 = 3.8416, held scaled by 10000. */
    const uint64_t Z2 = 38416;

    /* T = z^2 + 4k(n-k)/n, scaled by 10000. */
    uint64_t T = Z2 + (40000ull * k * (n - k) + n / 2) / n;
    /* z*sqrt(T): isqrt(T*10000) is sqrt(T_scaled)*100, and 1.96 of that,
     * divided by 100, is the term scaled by 10000. */
    uint64_t R = (196ull * isqrt64(T * 10000ull)) / 100ull;

    uint64_t num_scaled = 2ull * k * 10000ull + Z2;
    if (R >= num_scaled) return 0;
    num_scaled -= R;
    uint64_t den_scaled = 20000ull * n + 2ull * Z2;

    uint64_t permille = (1000ull * num_scaled) / den_scaled;
    return permille > 1000u ? 1000u : (uint32_t)permille;
}

/* ── scoring ─────────────────────────────────────────────────────────── */

static uint32_t mean_milli(uint64_t total, uint32_t n)
{
    if (n == 0) return 0;
    return (uint32_t)((total * 1000ull + n / 2) / n);
}

static bool receipt_shows(const struct zcl_rule_receipt *r, const char *id)
{
    for (uint32_t i = 0; i < r->rules_shown_count; i++)
        if (strcmp(r->rules_shown[i], id) == 0) return true;
    return false;
}

void zcl_rule_score_all(const struct zcl_rule_vocab *v,
                        const struct zcl_rule_receipt_log *log,
                        struct zcl_rule_scoring *out)
{
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!v) return;
    out->receipts = log ? log->count : 0;

    for (uint32_t i = 0; i < v->count && i < ZCL_RULE_VOCAB_MAX; i++) {
        const struct zcl_rule_row *row = &v->row[i];
        struct zcl_rule_score *sc = &out->rule[out->rule_count++];
        memset(sc, 0, sizeof *sc);
        copy_bounded(sc->id, sizeof sc->id, row->id, strlen(row->id));
        sc->state = row->state;
        sc->floor_permille = row->floor_permille;
        sc->min_trials = row->min_trials;

        uint64_t retries = 0, lines = 0;
        for (uint32_t j = 0; log && j < log->count; j++) {
            const struct zcl_rule_receipt *r = &log->r[j];
            if (!receipt_shows(r, row->id)) continue;
            sc->trials++;
            retries += r->retries;
            lines += r->lines_changed;
            if (r->gate_pass) {
                sc->passes++;
            } else {
                sc->killer_total++;
                if (sc->killer_count < ZCL_RULE_KILLER_MAX) {
                    copy_bounded(sc->killer[sc->killer_count],
                                 ZCL_RULE_UNIT_ID_MAX, r->unit_id,
                                 strlen(r->unit_id));
                    sc->killer_count++;
                }
            }
        }
        sc->lower_permille = zcl_rule_wilson_lower_permille(sc->passes,
                                                            sc->trials);
        sc->rate_permille = sc->trials
            ? (uint32_t)((1000ull * sc->passes + sc->trials / 2) / sc->trials)
            : 0;
        sc->mean_retries_milli = mean_milli(retries, sc->trials);
        sc->mean_lines_milli = mean_milli(lines, sc->trials);
    }

    /* Per template kind, in first-seen order so the report is stable. */
    for (uint32_t j = 0; log && j < log->count; j++) {
        const struct zcl_rule_receipt *r = &log->r[j];
        const char *kind = r->kind[0] ? r->kind : "(none)";
        struct zcl_rule_kind_score *ks = NULL;
        for (uint32_t i = 0; i < out->kind_count; i++)
            if (strcmp(out->kind[i].kind, kind) == 0) { ks = &out->kind[i]; break; }
        if (!ks) {
            if (out->kind_count >= ZCL_RULE_KIND_ROWS_MAX) continue;
            ks = &out->kind[out->kind_count++];
            memset(ks, 0, sizeof *ks);
            copy_bounded(ks->kind, sizeof ks->kind, kind, strlen(kind));
        }
        ks->trials++;
        if (r->gate_pass) ks->passes++;
        /* Totals are accumulated in the milli fields and divided below; the
         * struct carries no second pair of counters to fall out of step. */
        ks->mean_retries_milli += r->retries;
        ks->mean_lines_milli += r->lines_changed;
    }
    for (uint32_t i = 0; i < out->kind_count; i++) {
        struct zcl_rule_kind_score *ks = &out->kind[i];
        ks->lower_permille = zcl_rule_wilson_lower_permille(ks->passes,
                                                            ks->trials);
        ks->rate_permille = ks->trials
            ? (uint32_t)((1000ull * ks->passes + ks->trials / 2) / ks->trials)
            : 0;
        uint32_t rt = ks->mean_retries_milli, ln = ks->mean_lines_milli;
        ks->mean_retries_milli = mean_milli(rt, ks->trials);
        ks->mean_lines_milli = mean_milli(ln, ks->trials);
    }

    /* The baseline a shadow rule must beat: the MEDIAN lower bound of the
     * obeyed rules that have actually been measured. Unmeasured obeyed rows
     * are excluded — including them would let a vocabulary full of untried
     * rules drag the bar to zero and promote anything. With no measured
     * obeyed rule there is no baseline and nothing is promotable, because
     * "better than nothing" is not a comparison. */
    uint32_t vals[ZCL_RULE_VOCAB_MAX];
    uint32_t nvals = 0;
    for (uint32_t i = 0; i < out->rule_count; i++) {
        const struct zcl_rule_score *sc = &out->rule[i];
        if (sc->state != ZCL_RULE_OBEYED) continue;
        if (sc->trials < sc->min_trials) continue;
        vals[nvals++] = sc->lower_permille;
    }
    if (nvals > 0) {
        for (uint32_t a = 1; a < nvals; a++) {
            uint32_t key = vals[a];
            uint32_t b = a;
            while (b > 0 && vals[b - 1] > key) { vals[b] = vals[b - 1]; b--; }
            vals[b] = key;
        }
        /* An even count takes the LOWER middle value rather than an average:
         * an average would invent a bound no rule ever scored, and this one
         * is a bar that a promotion has to clear. */
        out->obeyed_baseline_permille = vals[(nvals - 1) / 2];
        out->baseline_known = true;
    }

    for (uint32_t i = 0; i < out->rule_count; i++) {
        struct zcl_rule_score *sc = &out->rule[i];
        if (sc->state == ZCL_RULE_RETIRED) {
            sc->verdict = ZCL_RULE_VERDICT_ALREADY_RETIRED;
        } else if (sc->trials == 0) {
            sc->verdict = ZCL_RULE_VERDICT_UNTRIED;
        } else if (sc->trials < sc->min_trials) {
            sc->verdict = ZCL_RULE_VERDICT_INSUFFICIENT;
        } else if (sc->state == ZCL_RULE_OBEYED) {
            sc->verdict = (sc->lower_permille < sc->floor_permille)
                            ? ZCL_RULE_VERDICT_RETIRE
                            : ZCL_RULE_VERDICT_HOLD;
            if (sc->verdict == ZCL_RULE_VERDICT_RETIRE) out->retire_count++;
        } else { /* shadow, measured */
            if (out->baseline_known &&
                sc->lower_permille > out->obeyed_baseline_permille) {
                sc->verdict = ZCL_RULE_VERDICT_PROMOTABLE;
                out->promotable_count++;
            } else {
                sc->verdict = ZCL_RULE_VERDICT_HOLD;
            }
        }
    }
}

/* ── rendering ───────────────────────────────────────────────────────── */

/* Appends into buf; returns false once anything would be lost. A truncated
 * report that still returned success would be a determinism claim about bytes
 * the caller never saw. */
static bool app(char *buf, size_t cap, size_t *at, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static bool app(char *buf, size_t cap, size_t *at, const char *fmt, ...)
{
    if (*at >= cap) return false;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + *at, cap - *at, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *at) return false;
    *at += (size_t)n;
    return true;
}

size_t zcl_rule_report_render(const struct zcl_rule_scoring *s,
                              char *buf, size_t cap)
{
    if (!s || !buf || cap == 0) return 0;
    size_t at = 0;
    /* No time, no path, no pointer: everything below is a function of the
     * scoring, which is a function of the log. */
    if (!app(buf, cap, &at, "rule_scoring v1\nreceipts %u\n", s->receipts))
        return 0;
    if (s->baseline_known) {
        if (!app(buf, cap, &at, "obeyed_baseline %u\n",
                 s->obeyed_baseline_permille)) return 0;
    } else if (!app(buf, cap, &at, "obeyed_baseline unknown\n")) {
        return 0;
    }
    for (uint32_t i = 0; i < s->rule_count; i++) {
        const struct zcl_rule_score *r = &s->rule[i];
        if (!app(buf, cap, &at,
                 "rule %s state=%s trials=%u passes=%u lower=%u rate=%u "
                 "floor=%u min_trials=%u retries_milli=%u lines_milli=%u "
                 "verdict=%s\n",
                 r->id, zcl_rule_state_label(r->state), r->trials, r->passes,
                 r->lower_permille, r->rate_permille, r->floor_permille,
                 r->min_trials, r->mean_retries_milli, r->mean_lines_milli,
                 zcl_rule_verdict_label(r->verdict)))
            return 0;
        for (uint32_t k = 0; k < r->killer_count; k++)
            if (!app(buf, cap, &at, "  killed_by %s\n", r->killer[k]))
                return 0;
    }
    for (uint32_t i = 0; i < s->kind_count; i++) {
        const struct zcl_rule_kind_score *k = &s->kind[i];
        if (!app(buf, cap, &at,
                 "kind %s trials=%u passes=%u lower=%u rate=%u "
                 "retries_milli=%u lines_milli=%u\n",
                 k->kind, k->trials, k->passes, k->lower_permille,
                 k->rate_permille, k->mean_retries_milli, k->mean_lines_milli))
            return 0;
    }
    if (!app(buf, cap, &at, "retire %u\npromotable %u\n",
             s->retire_count, s->promotable_count))
        return 0;
    return at;
}

/* ── applying a retirement ───────────────────────────────────────────── */

/* Rewrite one ZCL_RULE line so its state token becomes RETIRED, leaving every
 * other byte of the line alone. A regenerated line would silently normalise
 * spacing and drop whatever a person had written there. */
static bool retire_line(const char *line, size_t llen, char *buf, size_t cap,
                        size_t *at)
{
    static const char kObeyed[] = "ZCL_RULE_OBEYED";
    static const char kShadow[] = "ZCL_RULE_SHADOW";
    const char *tok = NULL;
    size_t toklen = 0;
    const char *hit = NULL;

    for (size_t i = 0; i + sizeof kObeyed - 1 <= llen; i++) {
        if (memcmp(line + i, kObeyed, sizeof kObeyed - 1) == 0) {
            hit = line + i; tok = kObeyed; toklen = sizeof kObeyed - 1; break;
        }
        if (memcmp(line + i, kShadow, sizeof kShadow - 1) == 0) {
            hit = line + i; tok = kShadow; toklen = sizeof kShadow - 1; break;
        }
    }
    if (!hit || !tok) return false;

    size_t head = (size_t)(hit - line);
    const char *repl = "ZCL_RULE_RETIRED";
    size_t rlen = strlen(repl);
    size_t tail = llen - head - toklen;
    if (*at + head + rlen + tail + 1 > cap) return false;
    memcpy(buf + *at, line, head); *at += head;
    memcpy(buf + *at, repl, rlen); *at += rlen;
    memcpy(buf + *at, line + head + toklen, tail); *at += tail;
    buf[(*at)++] = '\n';
    return true;
}

size_t zcl_rule_vocab_apply_retirements(const char *def_text, size_t def_len,
                                        const struct zcl_rule_scoring *s,
                                        char *buf, size_t cap)
{
    if (!def_text || !s || !buf || cap == 0) return 0;
    size_t at = 0;
    uint32_t line_no = 0;
    size_t i = 0;

    while (i < def_len) {
        size_t eol = i;
        while (eol < def_len && def_text[eol] != '\n') eol++;
        size_t llen = eol - i;
        const char *line = def_text + i;
        line_no++;

        const struct zcl_rule_score *kill = NULL;
        static const char kPrefix[] = "ZCL_RULE(";
        if (llen > sizeof kPrefix - 1 &&
            memcmp(line, kPrefix, sizeof kPrefix - 1) == 0) {
            /* Match by id, never by line number alone: an edit elsewhere in
             * the file would otherwise retire the wrong row. */
            size_t at2 = sizeof kPrefix - 1;
            char id[ZCL_RULE_ID_MAX];
            if (take_quoted(line, llen, &at2, id, sizeof id)) {
                for (uint32_t k = 0; k < s->rule_count; k++)
                    if (s->rule[k].verdict == ZCL_RULE_VERDICT_RETIRE &&
                        strcmp(s->rule[k].id, id) == 0)
                        { kill = &s->rule[k]; break; }
            }
        }

        if (kill) {
            /* The audit comment carries the numbers AND the receipts, because
             * a retirement a person cannot argue with is a retirement nobody
             * can undo on evidence. */
            char note[1024];
            int n = snprintf(note, sizeof note,
                             "/* auto-retired: trials=%u passes=%u "
                             "lower=%u floor=%u; failing units:",
                             kill->trials, kill->passes, kill->lower_permille,
                             kill->floor_permille);
            if (n < 0 || (size_t)n >= sizeof note) return 0;
            size_t nl = (size_t)n;
            for (uint32_t k = 0; k < kill->killer_count; k++) {
                int m = snprintf(note + nl, sizeof note - nl, " %s",
                                 kill->killer[k]);
                if (m < 0 || (size_t)m >= sizeof note - nl) return 0;
                nl += (size_t)m;
            }
            if (kill->killer_total > kill->killer_count) {
                int m = snprintf(note + nl, sizeof note - nl,
                                 " (+%u more)",
                                 kill->killer_total - kill->killer_count);
                if (m < 0 || (size_t)m >= sizeof note - nl) return 0;
                nl += (size_t)m;
            }
            int m = snprintf(note + nl, sizeof note - nl,
                             ". Delete this comment and set the state back to "
                             "turn it on again. */\n");
            if (m < 0 || (size_t)m >= sizeof note - nl) return 0;
            nl += (size_t)m;

            if (at + nl > cap) return 0;
            memcpy(buf + at, note, nl); at += nl;
            if (!retire_line(line, llen, buf, cap, &at)) return 0;
        } else {
            if (at + llen + 1 > cap) return 0;
            memcpy(buf + at, line, llen); at += llen;
            /* A file that did not end in a newline does not gain one. */
            if (eol < def_len) buf[at++] = '\n';
        }
        i = (eol < def_len) ? eol + 1 : eol;
    }
    return at;
}

/* ── the promotion patch ─────────────────────────────────────────────── */

static size_t line_start_of(const char *t, size_t len, uint32_t want)
{
    uint32_t n = 1;
    size_t i = 0;
    while (i < len && n < want) { if (t[i] == '\n') n++; i++; }
    return i;
}

static size_t line_len_at(const char *t, size_t len, size_t start)
{
    size_t e = start;
    while (e < len && t[e] != '\n') e++;
    return e - start;
}

size_t zcl_rule_promotion_patch(const char *def_text, size_t def_len,
                               const char *def_path,
                               const struct zcl_rule_row *row,
                               const struct zcl_rule_score *score,
                               uint32_t obeyed_baseline_permille,
                               char *buf, size_t cap)
{
    if (!def_text || !def_path || !row || !score || !buf || cap == 0) return 0;
    if (row->line == 0) return 0;

    uint32_t total = 1;
    for (size_t i = 0; i < def_len; i++) if (def_text[i] == '\n') total++;
    if (row->line > total) return 0;

    uint32_t ctx = 3;
    uint32_t first = row->line > ctx ? row->line - ctx : 1;
    uint32_t last = row->line + ctx;
    if (last > total) last = total;
    uint32_t count = last - first + 1;

    size_t at = 0;
    /* A patch, not an edit. Nothing in this tree applies it; a person does,
     * having read what the numbers were when it was proposed. */
    if (!app(buf, cap, &at,
             "# proposed promotion of %s from shadow to obeyed\n"
             "# trials=%u passes=%u wilson_lower=%u obeyed_baseline=%u "
             "min_trials=%u\n"
             "# This patch is NOT applied automatically. Turning a rule ON "
             "tells every\n"
             "# future executor something nobody read; turning one OFF only "
             "stops telling\n"
             "# them. Read the rule, then apply it yourself.\n"
             "--- a/%s\n+++ b/%s\n@@ -%u,%u +%u,%u @@\n",
             row->id, score->trials, score->passes, score->lower_permille,
             obeyed_baseline_permille, score->min_trials, def_path, def_path,
             first, count, first, count))
        return 0;

    for (uint32_t ln = first; ln <= last; ln++) {
        size_t st = line_start_of(def_text, def_len, ln);
        size_t ll = line_len_at(def_text, def_len, st);
        if (ln != row->line) {
            if (!app(buf, cap, &at, " %.*s\n", (int)ll, def_text + st))
                return 0;
        } else {
            if (!app(buf, cap, &at, "-%.*s\n", (int)ll, def_text + st))
                return 0;
        }
    }
    for (uint32_t ln = first; ln <= last; ln++) {
        if (ln != row->line) continue;
        size_t st = line_start_of(def_text, def_len, ln);
        size_t ll = line_len_at(def_text, def_len, st);
        /* Rewrite only the state token, exactly as the retirement path does,
         * so a reviewer sees one word change and nothing else. */
        char newline[ZCL_RULE_LINE_MAX];
        size_t w = 0;
        static const char kShadow[] = "ZCL_RULE_SHADOW";
        const char *hit = NULL;
        for (size_t k = 0; k + sizeof kShadow - 1 <= ll; k++)
            if (memcmp(def_text + st + k, kShadow, sizeof kShadow - 1) == 0)
                { hit = def_text + st + k; break; }
        if (!hit) return 0;
        size_t head = (size_t)(hit - (def_text + st));
        size_t tail = ll - head - (sizeof kShadow - 1);
        if (head + strlen("ZCL_RULE_OBEYED") + tail >= sizeof newline) return 0;
        memcpy(newline, def_text + st, head); w = head;
        memcpy(newline + w, "ZCL_RULE_OBEYED", strlen("ZCL_RULE_OBEYED"));
        w += strlen("ZCL_RULE_OBEYED");
        memcpy(newline + w, def_text + st + head + sizeof kShadow - 1, tail);
        w += tail;
        newline[w] = '\0';
        if (!app(buf, cap, &at, "+%s\n", newline)) return 0;
    }
    return at;
}

/* ── the file seam ───────────────────────────────────────────────────── */
/* Everything above is a function of its arguments. Everything below touches
 * files and nothing else: no process, no socket, no clock. */

static char *read_whole(const char *path, size_t cap, size_t *out_len)
{
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    char *buf = zcl_calloc(1, cap + 1, "rule_score");
    if (!buf) { (void)fclose(f); return NULL; }
    size_t n = fread(buf, 1, cap, f);
    /* A file at exactly the cap may have more behind it, and a scoring over
     * a silently truncated log is the failure this whole design exists to
     * avoid. Refuse instead. */
    int over = (n == cap) && (fgetc(f) != EOF);
    (void)fclose(f);
    if (over) { free(buf); return NULL; }
    buf[n] = '\0';
    *out_len = n;
    return buf;
}

static bool write_whole(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    size_t n = fwrite(data, 1, len, f);
    if (fclose(f) != 0) return false;
    return n == len;
}

/* The one writer of the live def. Nothing here ever opens `path` for
 * writing: the new bytes go whole into `<path>.tmp` in the same directory,
 * are flushed and fsynced, and a single rename publishes them. A crash, an
 * ENOSPC or a kill before the rename leaves the original standing — the
 * failure this exists to prevent is a truncated rule_vocab.def, and a
 * truncate-in-place `fopen(path, "wb")` produces exactly that.
 *
 * The rewrite was DECIDED from `old_text`, the bytes the caller read. If
 * the live def is not still exactly those bytes, publishing would clobber
 * an edit nobody scored. So before the rename the live def is re-read under
 * an exclusive fcntl lock and its SHA3-256 compared against `old_text`'s;
 * a mismatch refuses the whole write as STALE and leaves the file alone.
 * The lock spans the compare AND the rename, so two writers following this
 * same protocol cannot slip between each other's check and publish. */
enum zcl_rule_rewrite_status
zcl_rule_def_rewrite(const char *path, const char *old_text, size_t old_len,
                     const char *new_text, size_t new_len)
{
    if (!path || !old_text || !new_text) return ZCL_RULE_REWRITE_ERR_ARGS;

    char tmp[1024];
    int tn = snprintf(tmp, sizeof tmp, "%s.tmp", path);
    if (tn < 0 || (size_t)tn >= sizeof tmp) return ZCL_RULE_REWRITE_ERR_ARGS;

    char *fresh = zcl_calloc(1, old_len + 1u, "rule_score");
    if (!fresh) return ZCL_RULE_REWRITE_ERR_IO;

    /* O_RDWR, never O_TRUNC: the fd is only a handle for the write LOCK
     * (an exclusive fcntl lock requires a write-mode descriptor). */
    int live = open(path, O_RDWR);
    if (live < 0) { free(fresh); return ZCL_RULE_REWRITE_ERR_IO; }

    struct flock fl = {
        .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 0
    };
    enum zcl_rule_rewrite_status st = ZCL_RULE_REWRITE_ERR_IO;
    if (fcntl(live, F_SETLKW, &fl) == 0) {
        /* Fresh read under the lock, bounded by what the caller read: a
         * file of a different length is already not the bytes the caller
         * read, whatever they are. */
        size_t got = 0;
        bool read_err = false;
        while (got < old_len) {
            ssize_t r = read(live, fresh + got, old_len - got);
            if (r < 0 && errno == EINTR) continue;
            if (r < 0) { read_err = true; break; }
            if (r == 0) break;
            got += (size_t)r;
        }
        bool same_len = false;
        if (!read_err && got == old_len) {
            ssize_t one = read(live, fresh + got, 1);
            if (one < 0 && errno == EINTR) one = read(live, fresh + got, 1);
            if (one < 0) read_err = true;
            else same_len = (one == 0);
        }

        if (read_err) {
            st = ZCL_RULE_REWRITE_ERR_IO;
        } else if (!same_len) {
            st = ZCL_RULE_REWRITE_ERR_STALE;
        } else {
            unsigned char want[32], have[32];
            zcl_sha3_256((const unsigned char *)old_text, old_len, want);
            zcl_sha3_256((const unsigned char *)fresh, old_len, have);
            if (memcmp(want, have, sizeof want) != 0) {
                st = ZCL_RULE_REWRITE_ERR_STALE;
            } else {
                FILE *f = fopen(tmp, "wb");
                bool ok = f != NULL;
                if (ok) {
                    ok = fwrite(new_text, 1, new_len, f) == new_len &&
                         fflush(f) == 0 && fsync(fileno(f)) == 0;
                    if (fclose(f) != 0) ok = false;
                }
                if (!ok || rename(tmp, path) != 0) {
                    (void)unlink(tmp);
                    st = ZCL_RULE_REWRITE_ERR_IO;
                } else {
                    st = ZCL_RULE_REWRITE_OK;
                }
            }
        }
        fl.l_type = F_UNLCK;
        (void)fcntl(live, F_SETLK, &fl);
    }
    (void)close(live);
    free(fresh);
    return st;
}

const char *zcl_rule_rewrite_status_label(enum zcl_rule_rewrite_status s)
{
    switch (s) {
    case ZCL_RULE_REWRITE_OK:         return "published";
    case ZCL_RULE_REWRITE_ERR_ARGS:   return "bad arguments";
    case ZCL_RULE_REWRITE_ERR_IO:     return "write failed";
    case ZCL_RULE_REWRITE_ERR_STALE:  return "stale read";
    }
    return "unknown";
}

/* One promotion patch file per promotable rule. The id carries '/' and ':',
 * neither of which may reach a path component. */
static void safe_basename(const char *id, char *out, size_t cap)
{
    size_t w = 0;
    for (const char *p = id; *p && w + 1 < cap; p++) {
        char c = *p;
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_';
        out[w++] = ok ? c : '_';
    }
    out[w] = '\0';
}

bool zcl_rule_score_run(const char *vocab_path, const char *chainlog_path,
                        const char *state_dir, bool apply,
                        struct zcl_rule_run *out)
{
    if (!out) return false;
    memset(out, 0, sizeof *out);
    if (!vocab_path || !chainlog_path) return false;

    size_t def_len = 0;
    char *def_text = read_whole(vocab_path, ZCL_RULE_DEF_MAX, &def_len);
    struct zcl_rule_vocab vocab;
    if (def_text && zcl_rule_vocab_parse(def_text, def_len, &vocab)) {
        out->vocab_ok = true;
    } else {
        /* A vocabulary that would not parse is NOT quietly replaced by the
         * compiled one: that would score a checkout against a table it does
         * not contain. Say so, use the builtin, and refuse to apply. */
        vocab = *zcl_rule_vocab_builtin();
        out->vocab_ok = false;
        (void)snprintf(out->note, sizeof out->note,
                       "%s did not parse; scoring the vocabulary compiled "
                       "into this binary and applying nothing", vocab_path);
    }

    size_t log_len = 0;
    char *log_text = read_whole(chainlog_path, ZCL_RULE_LOG_MAX, &log_len);
    struct zcl_rule_receipt_log *log = zcl_calloc(1, sizeof *log, "rule_score");
    if (!log) { free(def_text); free(log_text); return false; }

    if (!log_text) {
        out->chain = ZCL_RULE_CHAIN_EMPTY;
        if (!out->note[0])
            (void)snprintf(out->note, sizeof out->note,
                           "no receipts at %s; every rule is untried, which "
                           "is not the same fact as failing", chainlog_path);
    } else {
        out->chain = zcl_rule_receipts_parse(log_text, log_len, log,
                                             &out->bad_line);
        out->log_ok = (out->chain == ZCL_RULE_CHAIN_OK);
        if (!out->log_ok && !out->note[0])
            (void)snprintf(out->note, sizeof out->note,
                           "%s refused at line %u: %s", chainlog_path,
                           out->bad_line,
                           zcl_rule_chain_status_label(out->chain));
    }

    zcl_rule_score_all(&vocab, out->log_ok ? log : NULL, &out->scoring);

    /* NOTHING IS APPLIED OFF A REFUSED LOG. A retirement decided from a log
     * whose chain did not verify is a change to the tree justified by
     * evidence that failed its own check. */
    bool may_apply = apply && out->vocab_ok && out->log_ok && def_text;
    if (may_apply && out->scoring.retire_count > 0) {
        size_t cap = def_len + 1024u * (size_t)out->scoring.retire_count + 1024u;
        char *nbuf = zcl_calloc(1, cap, "rule_score");
        if (nbuf) {
            size_t n = zcl_rule_vocab_apply_retirements(def_text, def_len,
                                                        &out->scoring,
                                                        nbuf, cap);
            if (n > 0) {
                enum zcl_rule_rewrite_status rw = zcl_rule_def_rewrite(
                    vocab_path, def_text, def_len, nbuf, n);
                if (rw == ZCL_RULE_REWRITE_OK)
                    out->retired_written = out->scoring.retire_count;
                else if (!out->note[0])
                    (void)snprintf(out->note, sizeof out->note,
                                   rw == ZCL_RULE_REWRITE_ERR_STALE
                                       ? "refused to rewrite %s: the def "
                                         "changed on disk since it was read; "
                                         "the original stands"
                                       : "refused to rewrite %s: the temp "
                                         "write, the fsync or the rename "
                                         "failed; the original def is "
                                         "untouched",
                                   vocab_path);
            }
            free(nbuf);
        }
    }
    if (may_apply && state_dir && out->scoring.promotable_count > 0) {
        char pdir[1024];
        int dn = snprintf(pdir, sizeof pdir, "%s/%s", state_dir,
                          ZCL_RULE_PROMOTIONS_DIR);
        /* An existing directory is not an error; a missing one would silently
         * drop every proposal this run made. */
        if (dn > 0 && (size_t)dn < sizeof pdir) (void)mkdir(pdir, 0755);
        for (uint32_t i = 0; i < out->scoring.rule_count; i++) {
            const struct zcl_rule_score *sc = &out->scoring.rule[i];
            if (sc->verdict != ZCL_RULE_VERDICT_PROMOTABLE) continue;
            const struct zcl_rule_row *row = zcl_rule_vocab_find(&vocab, sc->id);
            if (!row) continue;
            char base[ZCL_RULE_ID_MAX + 8];
            safe_basename(sc->id, base, sizeof base);
            char path[1024];
            int pn = snprintf(path, sizeof path, "%s/%s/%s.patch", state_dir,
                              ZCL_RULE_PROMOTIONS_DIR, base);
            if (pn < 0 || (size_t)pn >= sizeof path) continue;
            char *pbuf = zcl_calloc(1, 16384, "rule_score");
            if (!pbuf) continue;
            size_t pl = zcl_rule_promotion_patch(def_text, def_len, vocab_path,
                                                 row, sc,
                                                 out->scoring.obeyed_baseline_permille,
                                                 pbuf, 16384);
            if (pl > 0 && write_whole(path, pbuf, pl))
                out->patches_written++;
            free(pbuf);
        }
    }

    free(log);
    free(def_text);
    free(log_text);
    return true;
}
