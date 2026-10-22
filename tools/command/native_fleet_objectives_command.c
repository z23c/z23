/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The `fleet.objectives` leaf — one command that prints every
 *          objective z23 optimizes, its current value, its target, and
 *          whether it is met, unmet, or unmeasured today.
 *
 * WHAT IT DECIDES. Only which unmet objective to work on next: a product
 * objective before any lab one, and inside a class the
 * measured row with the largest gap to its target (`next` in the reply and
 * the last line of the screen). It reports what the catalog in
 * engine/composition/objectives.def declares, against what the tree can
 * measure right now. No gate reads this leaf.
 */

#include "native_fleet_objectives.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static const char *obj_input_str(const struct zcl_command_request *request,
                                 const char *key)
{
    const char *v;
    if (!request || !request->input)
        return NULL;
    v = json_get_str(json_get(request->input, key));
    return (v && v[0]) ? v : NULL;
}

static void obj_row_json(const struct zcl_objective_row *row,
                         const struct zcl_objective_value *value,
                         struct json_value *out)
{
    char status[80];
    json_set_object(out);
    (void)json_push_kv_str(out, "id", row->id);
    (void)json_push_kv_str(out, "class", row->class_);
    (void)json_push_kv_str(out, "source", row->source);
    (void)json_push_kv_str(out, "direction", row->direction);
    (void)json_push_kv_int(out, "target", row->target);
    (void)json_push_kv_str(out, "unit", row->unit);
    (void)json_push_kv_str(out, "why", row->why);
    (void)json_push_kv_bool(out, "measured", value->measured);
    if (value->measured)
        (void)json_push_kv_int(out, "value", value->value);
    else
        (void)json_push_kv_str(out, "reason", value->reason);
    zcl_objectives_status(row, value, status, sizeof(status));
    (void)json_push_kv_str(out, "status", status);
}

/* Pushes `next` into the reply data: the pick object, or JSON null when no
 * measured objective is unmet. False, with the reason on stderr, only when
 * the object cannot be built. */
static bool obj_push_next(struct json_value *data, const struct json_value *rows)
{
    struct json_value next;
    bool ok;
    json_init(&next);
    ok = zcl_objectives_next(rows, &next) && json_push_kv(data, "next", &next);
    if (!ok)
        LOG_ERROR("fleet.objectives",
                  "cannot attach next to the reply (%zu rows)",
                  rows->num_children);
    json_free(&next);
    return ok;
}

void zcl_native_handle_fleet_objectives(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    struct zcl_objectives_options options;
    struct zcl_objectives_node_cache node_cache = {0};
    const struct zcl_objective_row *catalog;
    struct json_value rows;
    char text[ZCL_OBJECTIVES_TEXT_MAX];
    char screen[ZCL_OBJECTIVES_SCREEN_MAX];
    size_t n;

    if (!reply)
        return;
    zcl_command_reply_init(reply, ZCL_OBJECTIVES_SCHEMA);

    memset(&options, 0, sizeof(options));
    options.outcomes = obj_input_str(request, "outcomes");
    options.attempts_dir = obj_input_str(request, "attempts_dir");
    options.repo = obj_input_str(request, "repo");
    options.lintc_dir = obj_input_str(request, "lintc_dir");
    options.baseline = obj_input_str(request, "baseline");
    options.brief = obj_input_str(request, "brief");
    options.datadir = obj_input_str(request, "datadir");
    options.node_cache = &node_cache;

    n = zcl_objectives_catalog(&catalog);

    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < n; i++) {
        struct zcl_objective_value value =
            zcl_objectives_measure(&options, catalog[i].id);
        struct json_value row;
        json_init(&row);
        obj_row_json(&catalog[i], &value, &row);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }

    zcl_objectives_node_cache_free(&node_cache);
    (void)zcl_objectives_render_text(&rows, text, sizeof(text));
    (void)zcl_objectives_render_screen(&rows, screen, sizeof(screen));

    (void)json_push_kv_str(&reply->data, "schema", ZCL_OBJECTIVES_SCHEMA);
    (void)json_push_kv(&reply->data, "objectives", &rows);
    if (!obj_push_next(&reply->data, &rows)) {
        json_free(&rows);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NEXT_TARGET_ALLOC",
                               "decide", false, false,
                               "cannot build the next-target object", "");
        return;
    }
    (void)json_push_kv_str(&reply->data, "text", text);
    (void)json_push_kv_str(&reply->data, "screen", screen);
    json_free(&rows);

    reply->status = ZCL_COMMAND_STATUS_PASSED;
    reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

/* ── decide: the next target ──────────────────────────────────────────── */

/* How far a measured value sits from its target, as a share of the target:
 * (value - target) / max(|target|, 1) for "min", (target - value) / the same
 * for "max". Positive when unmet. Done in doubles so no int64 subtraction
 * can overflow. */
static double obj_gap(bool is_max, int64_t value, int64_t target)
{
    double t = (double)target, v = (double)value;
    double den = t < 0 ? -t : t;
    if (den < 1.0)
        den = 1.0;
    return (is_max ? t - v : v - t) / den;
}

/* Three decimals, for the reply. The pick itself compares the unrounded
 * gaps. Gaps this large are returned as they are, so the cast below stays
 * in range. */
static double obj_round_gap(double gap)
{
    if (gap >= 1e12)
        return gap;
    return (double)(int64_t)(gap * 1000.0 + 0.5) / 1000.0;
}

/* A finished row's class: "product" or "lab". A row with no class reads as
 * lab, so only a row the catalog marked product can outrank another. */
static const char *obj_class(const struct json_value *row)
{
    const char *c = json_get_str(json_get(row, "class"));
    return (c && c[0]) ? c : "lab";
}

/* The measured, unmet row to work on: a product row always outranks a lab
 * row, the largest gap wins inside a class, and the first one in catalog
 * order wins a tie. NULL when no measured row is unmet. The reply's `next`
 * and the screen's closing line both come through here. */
static const struct json_value *obj_pick_next(const struct json_value *rows,
                                              double *gap_out)
{
    const struct json_value *best = NULL;
    double best_gap = 0.0;
    bool best_product = false;
    for (size_t i = 0; i < rows->num_children; i++) {
        const struct json_value *row = &rows->children[i];
        bool is_max, product;
        double gap;
        if (!json_get_bool(json_get(row, "measured")) ||
            strcmp(json_get_str(json_get(row, "status")), "unmet") != 0)
            continue;
        is_max = strcmp(json_get_str(json_get(row, "direction")), "max") == 0;
        product = strcmp(obj_class(row), "product") == 0;
        gap = obj_gap(is_max, json_get_int(json_get(row, "value")),
                      json_get_int(json_get(row, "target")));
        if (!best || (product && !best_product) ||
            (product == best_product && gap > best_gap)) {
            best = row;
            best_gap = gap;
            best_product = product;
        }
    }
    *gap_out = best_gap;
    return best;
}

static bool obj_next_fill(struct json_value *out, const struct json_value *row,
                          double gap)
{
    return json_push_kv_str(out, "id", json_get_str(json_get(row, "id"))) &&
           json_push_kv_str(out, "class", obj_class(row)) &&
           json_push_kv_int(out, "value", json_get_int(json_get(row, "value"))) &&
           json_push_kv_int(out, "target",
                            json_get_int(json_get(row, "target"))) &&
           json_push_kv_str(out, "direction",
                            json_get_str(json_get(row, "direction"))) &&
           json_push_kv_str(out, "unit", json_get_str(json_get(row, "unit"))) &&
           json_push_kv_real(out, "gap", obj_round_gap(gap)) &&
           json_push_kv_str(out, "why", json_get_str(json_get(row, "why")));
}

bool zcl_objectives_next(const struct json_value *rows, struct json_value *out)
{
    const struct json_value *row;
    double gap = 0.0;
    if (!out)
        return false;
    json_set_null(out);
    row = rows ? obj_pick_next(rows, &gap) : NULL;
    if (!row)
        return true;
    json_set_object(out);
    if (obj_next_fill(out, row, gap))
        return true;
    LOG_ERROR("fleet.objectives",
              "cannot build the next target for %s: out of memory",
              json_get_str(json_get(row, "id")));
    json_set_null(out);
    return false;
}

/* ── plain-text render ────────────────────────────────────────────────── */

struct obj_render_buf {
    char *at;
    size_t left;
};

static void obj_put(struct obj_render_buf *b, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static void obj_put(struct obj_render_buf *b, const char *format, ...)
{
    va_list args;
    int written;
    if (b->left <= 1)
        return;
    va_start(args, format);
    written = vsnprintf(b->at, b->left, format, args);
    va_end(args);
    if (written < 0)
        return;
    if ((size_t)written >= b->left)
        written = (int)b->left - 1;
    b->at += written;
    b->left -= (size_t)written;
}

size_t zcl_objectives_render_text(const struct json_value *rows, char *out,
                                  size_t cap)
{
    struct obj_render_buf b = {out, cap};
    if (!rows || !out || cap == 0)
        return 0;
    out[0] = '\0';
    obj_put(&b, "%-32s %10s %10s %8s %s\n", "objective", "value", "target",
           "unit", "status");
    for (size_t i = 0; i < rows->num_children; i++) {
        const struct json_value *row = &rows->children[i];
        const char *id = json_get_str(json_get(row, "id"));
        const char *unit = json_get_str(json_get(row, "unit"));
        const char *status = json_get_str(json_get(row, "status"));
        int64_t target = json_get_int(json_get(row, "target"));
        bool measured = json_get_bool(json_get(row, "measured"));
        char value_str[32];
        if (measured)
            (void)snprintf(value_str, sizeof(value_str), "%lld",
                          (long long)json_get_int(json_get(row, "value")));
        else
            (void)snprintf(value_str, sizeof(value_str), "%s", "-");
        obj_put(&b, "%-32s %10s %10lld %8s %s\n", id ? id : "", value_str,
               (long long)target, unit ? unit : "", status ? status : "");
    }
    return cap - b.left;
}

/* ── report-card screen ───────────────────────────────────────────────── */

#define OBJ_BAR_WIDTH 20

/* Cells of the bar to fill toward the target: value/target for a "max"
 * objective, target/value for a "min" one (full at or under target). */
static int obj_bar_fill(bool is_max, int64_t value, int64_t target)
{
    int64_t num, den;
    if (value < 0)
        value = 0;
    if (is_max) {
        if (target <= 0 || value >= target)
            return OBJ_BAR_WIDTH;
        num = value;
        den = target;
    } else {
        if (value <= target)
            return OBJ_BAR_WIDTH;
        num = target;
        den = value;
    }
    return (int)(num * OBJ_BAR_WIDTH / den);
}

/* The status text, ASCII only: bytes outside 0x20..0x7e become '?'. */
static void obj_ascii(const char *s, char *out, size_t cap)
{
    size_t n = 0;
    for (; s && *s && n + 1 < cap; s++)
        out[n++] = (*s >= 0x20 && *s <= 0x7e) ? *s : '?';
    out[n] = '\0';
}

/* The closing line: the next target with its value, target and why, or the
 * plain reason there is none. ASCII, like the rest of the screen. */
static void obj_put_next_line(struct obj_render_buf *b,
                              const struct json_value *rows, int64_t measured)
{
    double gap;
    const struct json_value *row = obj_pick_next(rows, &gap);
    char id[80], unit[40], why[1024];
    if (!row) {
        obj_put(b, "next: none - %s\n",
                measured > 0 ? "every measured objective is met"
                             : "no objective is measured yet");
        return;
    }
    obj_ascii(json_get_str(json_get(row, "id")), id, sizeof(id));
    obj_ascii(json_get_str(json_get(row, "unit")), unit, sizeof(unit));
    obj_ascii(json_get_str(json_get(row, "why")), why, sizeof(why));
    obj_put(b, "next: %s  %lld vs %lld %s - %s\n", id,
            (long long)json_get_int(json_get(row, "value")),
            (long long)json_get_int(json_get(row, "target")), unit, why);
}

size_t zcl_objectives_render_screen(const struct json_value *rows, char *out,
                                    size_t cap)
{
    struct obj_render_buf b = {out, cap};
    int64_t met = 0, unmeasured = 0;
    if (!rows || !out || cap == 0)
        return 0;
    out[0] = '\0';
    for (size_t i = 0; i < rows->num_children; i++) {
        const struct json_value *row = &rows->children[i];
        const char *id = json_get_str(json_get(row, "id"));
        const char *status = json_get_str(json_get(row, "status"));
        bool is_max = strcmp(json_get_str(json_get(row, "direction")),
                             "max") == 0;
        int64_t target = json_get_int(json_get(row, "target"));
        char bar[OBJ_BAR_WIDTH + 1], value_str[32], verdict[ZCL_OBJECTIVES_REASON_MAX + 32];
        int fill = 0;

        if (json_get_bool(json_get(row, "measured"))) {
            int64_t value = json_get_int(json_get(row, "value"));
            fill = obj_bar_fill(is_max, value, target);
            (void)snprintf(value_str, sizeof(value_str), "%lld",
                           (long long)value);
            if (strcmp(status, "met") == 0) {
                met++;
                (void)snprintf(verdict, sizeof(verdict), "met");
            } else {
                (void)snprintf(verdict, sizeof(verdict), "UNMET");
            }
        } else {
            unmeasured++;
            (void)snprintf(value_str, sizeof(value_str), "-");
            obj_ascii(status, verdict, sizeof(verdict));
        }
        for (int c = 0; c < OBJ_BAR_WIDTH; c++)
            bar[c] = json_get_bool(json_get(row, "measured"))
                         ? (c < fill ? '#' : '-')
                         : '?';
        bar[OBJ_BAR_WIDTH] = '\0';
        obj_put(&b, "%-30s [%s] %s/%lld %s\n", id ? id : "", bar, value_str,
                (long long)target, verdict);
    }
    obj_put(&b, "lab: met %lld of %zu, unmeasured %lld\n", (long long)met,
            rows->num_children, (long long)unmeasured);
    obj_put_next_line(&b, rows, (int64_t)rows->num_children - unmeasured);
    return cap - b.left;
}
