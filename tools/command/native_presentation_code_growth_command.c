/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: native hoverable chart of exact maintained C23 Git growth. */
#include "command/native_command.h"

#include "base/safe_alloc.h"
#include "json/json.h"
#include "presentation/canvas.h"
#include "presentation/presentation.h"
#include "science/code_growth.h"
#include "util/log_macros.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NPG_LEAF "app.presentation.code-growth"
#define NPG_WIDTH 1000u
#define NPG_HEIGHT 620u
#define NPG_PLOT_LEFT 84u
#define NPG_PLOT_TOP 180u
#define NPG_PLOT_RIGHT 878u
#define NPG_PLOT_BOTTOM 520u

struct npg_visual {
    uint8_t *pixels;
    struct zcl_present_window_hover_item_v1 *hover_items;
    char (*hover_text)[ZCL_PRESENT_WINDOW_HOVER_TEXT_MAX + 1u];
};

static void npg_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message)
{
    LOG_ERROR("native.presentation.code_growth", "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, code, "observe", false, false, message,
        NPG_LEAF);
}

static const char *npg_source_root(
    const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *environment = getenv("ZCL_DEV_SOURCE_ROOT");
    return environment && environment[0] ? environment : ".";
}

static void npg_u64(char out[32], uint64_t value)
{
    char plain[32];
    (void)snprintf(plain, sizeof(plain), "%" PRIu64, value);
    size_t length = strlen(plain);
    size_t commas = length > 0 ? (length - 1u) / 3u : 0;
    size_t output = length + commas;
    out[output] = '\0';
    size_t source = length;
    while (source > 0) {
        out[--output] = plain[--source];
        if (source > 0 && (length - source) % 3u == 0)
            out[--output] = ',';
    }
}

static void npg_text(struct zcl_present_canvas *canvas, int32_t x, int32_t y,
                     const char *text, uint32_t size,
                     struct zcl_present_color color)
{
    zcl_present_canvas_text(canvas, x, y, text, strlen(text), size, color);
}

static void npg_text_strong(
    struct zcl_present_canvas *canvas, int32_t x, int32_t y,
    const char *text, uint32_t size, struct zcl_present_color color)
{
    zcl_present_canvas_text_strong(
        canvas, x, y, text, strlen(text), size, color);
}

static int32_t npg_y(uint64_t value, uint64_t maximum)
{
    uint64_t height = NPG_PLOT_BOTTOM - NPG_PLOT_TOP;
    uint64_t scaled = maximum ? value * height / maximum : 0;
    return (int32_t)(NPG_PLOT_BOTTOM - scaled);
}

static uint32_t npg_x(size_t index, size_t count)
{
    if (count < 2u) return NPG_PLOT_LEFT;
    return NPG_PLOT_LEFT + (uint32_t)(
        (uint64_t)index * (NPG_PLOT_RIGHT - NPG_PLOT_LEFT) /
        (count - 1u));
}

static void npg_series(
    struct zcl_present_canvas *canvas,
    const struct science_code_growth_history *history, bool tests,
    uint64_t maximum, struct zcl_present_color color)
{
    for (size_t i = 0; i < history->day_count; i++) {
        uint64_t value = tests ? history->days[i].test_lines
                               : history->days[i].non_test_lines;
        int32_t x = (int32_t)npg_x(i, history->day_count);
        int32_t y = npg_y(value, maximum);
        if (i > 0) {
            uint64_t prior = tests ? history->days[i - 1u].test_lines
                                   : history->days[i - 1u].non_test_lines;
            int32_t prior_x = (int32_t)npg_x(i - 1u, history->day_count);
            int32_t prior_y = npg_y(prior, maximum);
            zcl_present_canvas_line(canvas, prior_x, prior_y,
                                    x, y, color);
            zcl_present_canvas_line(canvas, prior_x, prior_y + 1,
                                    x, y + 1, color);
        }
        zcl_present_canvas_fill_rect(canvas, x - 1, y - 1, 3u, 3u, color);
    }
}

static bool npg_visual_build(
    const struct science_code_growth_history *history,
    struct npg_visual *visual)
{
    if (!history || !visual || history->day_count == 0) return false;
    memset(visual, 0, sizeof(*visual));
    size_t pixel_bytes = (size_t)NPG_WIDTH * NPG_HEIGHT * 3u;
    visual->pixels = zcl_malloc(pixel_bytes, "code_growth.pixels");
    visual->hover_items = zcl_calloc(
        history->day_count, sizeof(*visual->hover_items),
        "code_growth.hover_items");
    visual->hover_text = zcl_calloc(
        history->day_count, sizeof(*visual->hover_text),
        "code_growth.hover_text");
    if (!visual->pixels || !visual->hover_items || !visual->hover_text)
        return false;
    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(&canvas, visual->pixels, pixel_bytes,
                                 NPG_WIDTH, NPG_HEIGHT))
        return false;
    const struct zcl_present_color background = {8, 14, 26};
    const struct zcl_present_color panel = {14, 24, 40};
    const struct zcl_present_color grid = {35, 54, 76};
    const struct zcl_present_color primary = {241, 246, 255};
    const struct zcl_present_color secondary = {153, 174, 201};
    const struct zcl_present_color cyan = {68, 224, 202};
    const struct zcl_present_color violet = {174, 125, 255};
    zcl_present_canvas_clear(&canvas, background);
    zcl_present_canvas_fill_rect(&canvas, 28, 24, 944u, 124u, panel);
    npg_text_strong(&canvas, 52, 42, "Z23 C23 growth", 32u, primary);
    npg_text(&canvas, 52, 86,
             "Exact first-parent Git history by UTC day.", 16u, secondary);
    npg_text(&canvas, 52, 111,
             "Current .c + .h totals verified against the live tree.",
             16u, secondary);

    char non_test[32], tests[32], total[32], metric[96];
    npg_u64(non_test, history->non_test_lines);
    npg_u64(tests, history->test_lines);
    npg_u64(total, history->non_test_lines + history->test_lines);
    (void)snprintf(metric, sizeof(metric), "%s total C23 lines", total);
    npg_text_strong(&canvas, 650, 45, metric, 23u, primary);
    (void)snprintf(metric, sizeof(metric), "%s non-test", non_test);
    npg_text(&canvas, 650, 87, metric, 17u, cyan);
    (void)snprintf(metric, sizeof(metric), "%s tests", tests);
    npg_text(&canvas, 821, 87, metric, 17u, violet);

    uint64_t maximum = history->non_test_lines > history->test_lines
        ? history->non_test_lines : history->test_lines;
    maximum = zcl_present_canvas_chart_scale_maximum(maximum);
    for (uint32_t row = 0; row <= 4u; row++) {
        int32_t y = (int32_t)NPG_PLOT_TOP +
            (int32_t)((NPG_PLOT_BOTTOM - NPG_PLOT_TOP) * row / 4u);
        zcl_present_canvas_line(&canvas, NPG_PLOT_LEFT, y,
                                NPG_PLOT_RIGHT, y, grid);
        uint64_t value = maximum * (4u - row) / 4u;
        char label[32];
        npg_u64(label, value);
        uint32_t width = zcl_present_canvas_text_width(
            label, strlen(label), 15u);
        npg_text(&canvas, (int32_t)NPG_PLOT_LEFT - (int32_t)width - 12,
                 y - 8, label, 15u, secondary);
    }
    npg_series(&canvas, history, false, maximum, cyan);
    npg_series(&canvas, history, true, maximum, violet);
    int32_t non_test_y = npg_y(history->non_test_lines, maximum);
    int32_t test_y = npg_y(history->test_lines, maximum);
    zcl_present_canvas_line(&canvas, NPG_PLOT_RIGHT + 3u, non_test_y,
                            NPG_PLOT_RIGHT + 14u, non_test_y, cyan);
    zcl_present_canvas_line(&canvas, NPG_PLOT_RIGHT + 3u, test_y,
                            NPG_PLOT_RIGHT + 14u, test_y, violet);
    npg_text_strong(&canvas, NPG_PLOT_RIGHT + 20u, non_test_y - 9,
                    "non-test", 15u, cyan);
    npg_text_strong(&canvas, NPG_PLOT_RIGHT + 20u, test_y - 9,
                    "tests", 15u, violet);
    for (size_t i = 0; i < history->day_count; i++) {
        const struct science_code_growth_day *day = &history->days[i];
        visual->hover_items[i].x = npg_x(i, history->day_count);
        visual->hover_items[i].text = visual->hover_text[i];
        char day_non_test[32], day_non_added[32], day_non_deleted[32];
        char day_tests[32], day_test_added[32], day_test_deleted[32];
        npg_u64(day_non_test, day->non_test_lines);
        npg_u64(day_non_added, day->non_test_added);
        npg_u64(day_non_deleted, day->non_test_deleted);
        npg_u64(day_tests, day->test_lines);
        npg_u64(day_test_added, day->test_added);
        npg_u64(day_test_deleted, day->test_deleted);
        (void)snprintf(
            visual->hover_text[i], sizeof(visual->hover_text[i]),
            "%s UTC  |  commit %.10s\nnon-test %s (+%s -%s)  |  "
            "tests %s (+%s -%s)",
            day->date, day->head_commit, day_non_test, day_non_added,
            day_non_deleted, day_tests, day_test_added, day_test_deleted);
    }
    const size_t labels[] = {0u, history->day_count / 2u,
                             history->day_count - 1u};
    for (size_t i = 0; i < sizeof(labels) / sizeof(labels[0]); i++) {
        if (i > 0 && labels[i] == labels[i - 1u]) continue;
        size_t day = labels[i];
        uint32_t width = zcl_present_canvas_text_width(
            history->days[day].date, 10u, 15u);
        npg_text(&canvas, (int32_t)npg_x(day, history->day_count) -
                 (int32_t)(width / 2u), NPG_PLOT_BOTTOM + 18,
                 history->days[day].date, 15u, secondary);
    }
    npg_text(&canvas, 84, 576,
             "Hover any day for exact totals and additions/deletions",
             17u, secondary);
    return true;
}

static void npg_visual_free(struct npg_visual *visual)
{
    if (!visual) return;
    free(visual->pixels);
    free(visual->hover_items);
    free(visual->hover_text);
    memset(visual, 0, sizeof(*visual));
}

static bool npg_array_str(struct json_value *array, const char *text)
{
    struct json_value value;
    json_init(&value);
    json_set_str(&value, text);
    bool ok = json_push_back(array, &value);
    json_free(&value);
    return ok;
}

static bool npg_array_u64(struct json_value *array, uint64_t number)
{
    if (number > (uint64_t)INT64_MAX) return false;
    struct json_value value;
    json_init(&value);
    json_set_int(&value, (int64_t)number);
    bool ok = json_push_back(array, &value);
    json_free(&value);
    return ok;
}

static bool npg_reply_points(
    struct zcl_command_reply *reply,
    const struct science_code_growth_history *history)
{
    bool ok = json_push_kv_str(&reply->data, "scope",
            "current maintained roots; .c+.h; non-test and test separated") &&
        json_push_kv_str(&reply->data, "history",
            "first-parent; merge diff against first parent; UTC commit day") &&
        json_push_kv_bool(&reply->data, "fresh_tree_crosscheck", true) &&
        json_push_kv_int(&reply->data, "day_count",
                         (int64_t)history->day_count) &&
        json_push_kv_int(&reply->data, "non_test_lines",
                         (int64_t)history->non_test_lines) &&
        json_push_kv_int(&reply->data, "test_lines",
                         (int64_t)history->test_lines);
    static const char *const fields[] = {
        "date_utc", "head_commit", "commits",
        "non_test_lines", "non_test_added", "non_test_deleted",
        "test_lines", "test_added", "test_deleted",
    };
    struct json_value field_names;
    json_init(&field_names);
    json_set_array(&field_names);
    for (size_t i = 0; ok && i < sizeof(fields) / sizeof(fields[0]); i++)
        ok = npg_array_str(&field_names, fields[i]);
    if (ok) ok = json_push_kv(&reply->data, "plot_point_fields",
                               &field_names);
    json_free(&field_names);
    struct json_value points;
    json_init(&points);
    json_set_array(&points);
    for (size_t i = 0; ok && i < history->day_count; i++) {
        const struct science_code_growth_day *day = &history->days[i];
        struct json_value point;
        json_init(&point);
        json_set_array(&point);
        ok = npg_array_str(&point, day->date) &&
            npg_array_str(&point, day->head_commit) &&
            npg_array_u64(&point, day->commits) &&
            npg_array_u64(&point, day->non_test_lines) &&
            npg_array_u64(&point, day->non_test_added) &&
            npg_array_u64(&point, day->non_test_deleted) &&
            npg_array_u64(&point, day->test_lines) &&
            npg_array_u64(&point, day->test_added) &&
            npg_array_u64(&point, day->test_deleted) &&
            json_push_back(&points, &point);
        json_free(&point);
    }
    if (ok) ok = json_push_kv(&reply->data, "plot_points", &points);
    json_free(&points);
    return ok;
}

void zcl_native_handle_presentation_code_growth(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *output_value = json_get(request->input, "output");
    const char *output = json_get_str(output_value);
    if (output_value && (!output || (strcmp(output, "native") != 0 &&
                                    strcmp(output, "text") != 0))) {
        npg_fail(reply, "INVALID_OUTPUT",
                 "output must be exactly native or text");
        return;
    }
    struct science_code_growth_history history;
    char error[192];
    if (!science_code_growth_collect(
            npg_source_root(request), &history, error, sizeof(error))) {
        npg_fail(reply, "CODE_GROWTH_UNAVAILABLE", error);
        return;
    }
    if (!npg_reply_points(reply, &history)) {
        npg_fail(reply, "PLOT_POINTS_FAILED",
                 "exact plot-point JSON allocation or bounds failed");
        return;
    }
    if (output && strcmp(output, "text") == 0) {
        (void)json_push_kv_bool(&reply->data, "launched", false);
        return;
    }
    struct npg_visual visual;
    if (!npg_visual_build(&history, &visual)) {
        npg_visual_free(&visual);
        npg_fail(reply, "CHART_RENDER_FAILED",
                 "native chart allocation or rendering failed");
        return;
    }
    struct zcl_present_window_v1 window = {
        .struct_size = sizeof(window),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Z23 C23 Growth - hover for exact daily lines",
        .pixels = visual.pixels,
        .width = NPG_WIDTH,
        .height = NPG_HEIGHT,
        .pixel_format = ZCL_PRESENT_RGB8,
    };
    struct zcl_present_window_hover_v1 hover = {
        .struct_size = sizeof(hover),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .plot_left = NPG_PLOT_LEFT,
        .plot_top = NPG_PLOT_TOP,
        .plot_right = NPG_PLOT_RIGHT,
        .plot_bottom = NPG_PLOT_BOTTOM,
        .items = visual.hover_items,
        .item_count = (uint32_t)history.day_count,
    };
    bool shown = zcl_present_window_run_hover_v1(
        &window, &hover, error, sizeof(error));
    npg_visual_free(&visual);
    if (!shown) {
        npg_fail(reply, "NATIVE_CHART_FAILED", error);
        return;
    }
    (void)json_push_kv_bool(&reply->data, "launched", true);
    (void)json_push_kv_str(&reply->data, "backend",
                           zcl_present_backend_name());
    (void)json_push_kv_str(&reply->data, "platform",
                           zcl_present_platform_name());
    (void)json_push_kv_str(&reply->data, "authority", "display-only");
}
