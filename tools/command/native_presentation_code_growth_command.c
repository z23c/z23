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
#define NPG_WIDTH 1120u
#define NPG_HEIGHT 680u
#define NPG_TEXT_SCALES 3u
#define NPG_TEXT_SCALE_DEFAULT 1u
#define NPG_PLOT_LEFT 104u
#define NPG_PLOT_TOP 230u
#define NPG_PLOT_RIGHT 1048u
#define NPG_PLOT_BOTTOM 552u

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

static uint32_t npg_font(uint32_t base, uint32_t text_scale)
{
    return base + text_scale * 2u;
}

static int32_t npg_y(uint64_t value, uint64_t maximum)
{
    uint64_t height = NPG_PLOT_BOTTOM - NPG_PLOT_TOP;
    uint64_t scaled = maximum ? (uint64_t)(
        (long double)value * (long double)height / (long double)maximum) : 0;
    return (int32_t)(NPG_PLOT_BOTTOM - scaled);
}

static uint64_t npg_fraction(
    uint64_t value, uint32_t numerator, uint32_t denominator)
{
    return denominator == 0 ? 0 :
        value / denominator * numerator +
        value % denominator * numerator / denominator;
}

static uint32_t npg_x(size_t index, size_t count)
{
    if (count < 2u) return NPG_PLOT_LEFT;
    return NPG_PLOT_LEFT + (uint32_t)(
        (uint64_t)index * (NPG_PLOT_RIGHT - NPG_PLOT_LEFT) /
        (count - 1u));
}

enum npg_series_kind {
    NPG_SERIES_TOTAL,
    NPG_SERIES_NON_TEST,
    NPG_SERIES_TEST,
};

static uint64_t npg_value(
    const struct science_code_growth_day *day, enum npg_series_kind kind)
{
    if (kind == NPG_SERIES_NON_TEST) return day->non_test_lines;
    if (kind == NPG_SERIES_TEST) return day->test_lines;
    if (UINT64_MAX - day->non_test_lines < day->test_lines)
        return UINT64_MAX;
    return day->non_test_lines + day->test_lines;
}

static void npg_series(
    struct zcl_present_canvas *canvas,
    const struct science_code_growth_history *history,
    enum npg_series_kind kind, uint64_t maximum,
    struct zcl_present_color color, uint32_t thickness)
{
    for (size_t i = 0; i < history->day_count; i++) {
        uint64_t value = npg_value(&history->days[i], kind);
        int32_t x = (int32_t)npg_x(i, history->day_count);
        int32_t y = npg_y(value, maximum);
        if (i > 0) {
            uint64_t prior = npg_value(&history->days[i - 1u], kind);
            int32_t prior_x = (int32_t)npg_x(i - 1u, history->day_count);
            int32_t prior_y = npg_y(prior, maximum);
            for (uint32_t line = 0; line < thickness; line++)
                zcl_present_canvas_line(
                    canvas, prior_x, prior_y + (int32_t)line,
                    x, y + (int32_t)line, color);
        }
    }
}

static void npg_short_date(const char date[11], char out[6])
{
    memcpy(out, date + 5, 5u);
    out[5] = '\0';
}

static const char *npg_month_name(const char date[11])
{
    static const char *const months[] = {
        "JAN", "FEB", "MAR", "APR", "MAY", "JUN",
        "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
    };
    if (date[5] < '0' || date[5] > '9' || date[6] < '0' || date[6] > '9')
        return NULL;
    unsigned month = (unsigned)(date[5] - '0') * 10u +
                     (unsigned)(date[6] - '0');
    return month >= 1u && month <= 12u ? months[month - 1u] : NULL;
}

static void npg_draw_header(
    struct zcl_present_canvas *canvas,
    const struct science_code_growth_history *history, uint32_t text_scale)
{
    const struct zcl_present_color panel = {14, 24, 40};
    const struct zcl_present_color primary = {241, 246, 255};
    const struct zcl_present_color secondary = {153, 174, 201};
    const struct zcl_present_color cyan = {68, 224, 202};
    const struct zcl_present_color violet = {174, 125, 255};
    char non_test[32], tests[32], total[32], metric[96];
    npg_u64(non_test, history->non_test_lines);
    npg_u64(tests, history->test_lines);
    uint64_t combined = UINT64_MAX - history->non_test_lines <
        history->test_lines ? UINT64_MAX
                            : history->non_test_lines + history->test_lines;
    npg_u64(total, combined);
    zcl_present_canvas_fill_rect(canvas, 28, 24, 1064u, 182u, panel);
    npg_text_strong(canvas, 52, 38, "C23 growth by day",
                    npg_font(34u, text_scale), primary);
    npg_text(canvas, 52, 82,
             "Exact first-parent Git history | live tree verified",
             npg_font(18u, text_scale), secondary);
    (void)snprintf(metric, sizeof(metric), "%s to %s | %zu UTC days",
                   history->days[0].date,
                   history->days[history->day_count - 1u].date,
                   history->day_count);
    npg_text_strong(canvas, 52, 108, metric,
                    npg_font(17u, text_scale), secondary);
    npg_text_strong(canvas, 727, 37, "TOTAL C23",
                    npg_font(16u, text_scale), secondary);
    npg_text_strong(canvas, 727, 60, total,
                    npg_font(30u, text_scale), primary);
    (void)snprintf(metric, sizeof(metric), "%s non-test", non_test);
    npg_text_strong(canvas, 727, 103, metric,
                    npg_font(18u, text_scale), cyan);
    (void)snprintf(metric, sizeof(metric), "%s tests", tests);
    npg_text_strong(canvas, 913, 103, metric,
                    npg_font(18u, text_scale), violet);
}

static void npg_draw_grid(
    struct zcl_present_canvas *canvas,
    const struct science_code_growth_history *history, uint64_t maximum,
    uint32_t text_scale)
{
    const struct zcl_present_color plot = {10, 19, 32};
    const struct zcl_present_color band = {12, 22, 37};
    const struct zcl_present_color grid = {35, 54, 76};
    const struct zcl_present_color major = {57, 78, 103};
    const struct zcl_present_color secondary = {153, 174, 201};
    const struct zcl_present_color month_text = {208, 222, 238};
    zcl_present_canvas_fill_rect(
        canvas, NPG_PLOT_LEFT, NPG_PLOT_TOP,
        NPG_PLOT_RIGHT - NPG_PLOT_LEFT + 1u,
        NPG_PLOT_BOTTOM - NPG_PLOT_TOP + 1u, plot);
    for (uint32_t row = 0; row < 4u; row += 2u) {
        int32_t y = (int32_t)NPG_PLOT_TOP +
            (int32_t)((NPG_PLOT_BOTTOM - NPG_PLOT_TOP) * row / 4u);
        uint32_t height = (NPG_PLOT_BOTTOM - NPG_PLOT_TOP) / 4u;
        zcl_present_canvas_fill_rect(
            canvas, NPG_PLOT_LEFT, y,
            NPG_PLOT_RIGHT - NPG_PLOT_LEFT + 1u, height, band);
    }
    for (uint32_t row = 0; row <= 4u; row++) {
        int32_t y = (int32_t)NPG_PLOT_TOP +
            (int32_t)((NPG_PLOT_BOTTOM - NPG_PLOT_TOP) * row / 4u);
        zcl_present_canvas_line(
            canvas, NPG_PLOT_LEFT, y, NPG_PLOT_RIGHT, y, grid);
        char label[32];
        npg_u64(label, npg_fraction(maximum, 4u - row, 4u));
        uint32_t font = npg_font(16u, text_scale);
        uint32_t width = zcl_present_canvas_text_width_strong(
            label, strlen(label), font);
        npg_text_strong(
            canvas, (int32_t)NPG_PLOT_LEFT - (int32_t)width - 11,
            y - (int32_t)(font / 2u), label, font, secondary);
    }
    const uint32_t axis_font = npg_font(16u, text_scale);
    char probe[6];
    npg_short_date(history->days[history->day_count - 1u].date, probe);
    uint32_t stride = zcl_present_canvas_axis_label_stride_v1(
        (uint32_t)history->day_count, NPG_PLOT_RIGHT - NPG_PLOT_LEFT,
        zcl_present_canvas_text_width_strong(probe, 5u, axis_font), 12u);
    const size_t last = history->day_count - 1u;
    int32_t month_right = INT32_MIN;
    for (size_t i = 0; i < history->day_count; i++) {
        int32_t x = (int32_t)npg_x(i, history->day_count);
        bool month = i == 0 || strncmp(history->days[i - 1u].date,
                                       history->days[i].date, 7u) != 0;
        bool week = (last - i) % stride == 0;
        zcl_present_canvas_line(canvas, x, NPG_PLOT_BOTTOM,
                                x, NPG_PLOT_BOTTOM + 4, grid);
        if (month || week)
            zcl_present_canvas_line(canvas, x, NPG_PLOT_TOP,
                                    x, NPG_PLOT_BOTTOM,
                                    month ? major : grid);
        if (week) {
            char date[6];
            npg_short_date(history->days[i].date, date);
            uint32_t width = zcl_present_canvas_text_width_strong(
                date, 5u, axis_font);
            int32_t left = x - (int32_t)(width / 2u);
            if (left < (int32_t)NPG_PLOT_LEFT) left = NPG_PLOT_LEFT;
            if (left + (int32_t)width > (int32_t)NPG_PLOT_RIGHT)
                left = (int32_t)NPG_PLOT_RIGHT - (int32_t)width;
            npg_text_strong(canvas, left, NPG_PLOT_BOTTOM + 12,
                            date, axis_font, secondary);
        }
        if (month) {
            const char *name = npg_month_name(history->days[i].date);
            if (name) {
                char label[12];
                (void)snprintf(label, sizeof(label), "%.3s %.4s",
                               name, history->days[i].date);
                uint32_t font = npg_font(14u, text_scale);
                uint32_t width = zcl_present_canvas_text_width_strong(
                    label, strlen(label), font);
                int32_t left = x - (int32_t)(width / 2u);
                if (left < (int32_t)NPG_PLOT_LEFT) left = NPG_PLOT_LEFT;
                if (left + (int32_t)width > (int32_t)NPG_PLOT_RIGHT)
                    left = (int32_t)NPG_PLOT_RIGHT - (int32_t)width;
                if (left > month_right + 12) {
                    npg_text_strong(canvas, left, NPG_PLOT_BOTTOM + 36,
                                    label, font, month_text);
                    month_right = left + (int32_t)width;
                }
            }
        }
    }
}

static void npg_draw_series(
    struct zcl_present_canvas *canvas,
    const struct science_code_growth_history *history, uint64_t maximum,
    uint32_t text_scale)
{
    const struct zcl_present_color primary = {241, 246, 255};
    const struct zcl_present_color cyan = {68, 224, 202};
    const struct zcl_present_color violet = {174, 125, 255};
    npg_series(canvas, history, NPG_SERIES_NON_TEST,
               maximum, cyan, 2u);
    npg_series(canvas, history, NPG_SERIES_TEST,
               maximum, violet, 2u);
    npg_series(canvas, history, NPG_SERIES_TOTAL,
               maximum, primary, 3u);
    const struct science_code_growth_day *last =
        &history->days[history->day_count - 1u];
    npg_text_strong(canvas, NPG_PLOT_RIGHT + 9,
                    npg_y(npg_value(last, NPG_SERIES_TOTAL), maximum) - 8,
                    "total", npg_font(16u, text_scale), primary);
    npg_text_strong(canvas, NPG_PLOT_RIGHT + 9,
                    npg_y(last->non_test_lines, maximum) - 8,
                    "code", npg_font(16u, text_scale), cyan);
    npg_text_strong(canvas, NPG_PLOT_RIGHT + 9,
                    npg_y(last->test_lines, maximum) - 8,
                    "tests", npg_font(16u, text_scale), violet);
}

static void npg_prepare_hover(
    const struct science_code_growth_history *history,
    struct npg_visual *visual)
{
    for (size_t i = 0; i < history->day_count; i++) {
        const struct science_code_growth_day *day = &history->days[i];
        visual->hover_items[i].x = npg_x(i, history->day_count);
        visual->hover_items[i].text = visual->hover_text[i];
        char total[32], non_test[32], non_added[32], non_deleted[32];
        char tests[32], test_added[32], test_deleted[32];
        npg_u64(total, npg_value(day, NPG_SERIES_TOTAL));
        npg_u64(non_test, day->non_test_lines);
        npg_u64(non_added, day->non_test_added);
        npg_u64(non_deleted, day->non_test_deleted);
        npg_u64(tests, day->test_lines);
        npg_u64(test_added, day->test_added);
        npg_u64(test_deleted, day->test_deleted);
        (void)snprintf(
            visual->hover_text[i], sizeof(visual->hover_text[i]),
            "%s UTC | %u commits | %.10s\nTOTAL %s | CODE %s (+%s -%s) | "
            "TESTS %s (+%s -%s)",
            day->date, day->commits, day->head_commit, total,
            non_test, non_added, non_deleted,
            tests, test_added, test_deleted);
    }
}

static void npg_draw_controls(
    struct zcl_present_canvas *canvas, uint32_t text_scale)
{
    const struct zcl_present_color panel = {14, 24, 40};
    const struct zcl_present_color primary = {241, 246, 255};
    const struct zcl_present_color secondary = {153, 174, 201};
    zcl_present_canvas_fill_rect(canvas, 28, 610, 1064u, 46u, panel);
    static const char *const labels[NPG_TEXT_SCALES] = {
        "TEXT SMALL", "TEXT MEDIUM", "TEXT LARGE",
    };
    npg_text_strong(canvas, 48, 623, labels[text_scale],
                    npg_font(16u, text_scale), primary);
    npg_text_strong(canvas, 157, 623,
             "- / +: TEXT  |  HOVER  |  WHEEL / ARROWS: DAY  |  "
             "PGUP PGDN: WEEK  |  HOME END: RANGE",
             npg_font(16u, text_scale), secondary);
}

static bool npg_visual_build(
    const struct science_code_growth_history *history,
    struct npg_visual *visual, uint32_t text_scale)
{
    if (!history || !visual || history->day_count == 0 ||
        text_scale >= NPG_TEXT_SCALES)
        return false;
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
    zcl_present_canvas_clear(&canvas, background);
    npg_draw_header(&canvas, history, text_scale);
    uint64_t maximum = UINT64_MAX - history->non_test_lines <
        history->test_lines ? UINT64_MAX
                            : history->non_test_lines + history->test_lines;
    maximum = zcl_present_canvas_chart_scale_maximum(maximum);
    npg_draw_grid(&canvas, history, maximum, text_scale);
    npg_draw_series(&canvas, history, maximum, text_scale);
    npg_prepare_hover(history, visual);
    npg_draw_controls(&canvas, text_scale);
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

static void npg_visuals_free(
    struct npg_visual visuals[NPG_TEXT_SCALES])
{
    for (uint32_t i = 0; i < NPG_TEXT_SCALES; i++)
        npg_visual_free(&visuals[i]);
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
        json_push_kv_bool(&reply->data, "cache_hit", history->cache_hit) &&
        json_push_kv_bool(&reply->data, "fresh_tree_crosscheck",
                          !history->cache_hit) &&
        json_push_kv_bool(&reply->data, "sealed_tree_crosscheck",
                          history->cache_hit) &&
        json_push_kv_int(&reply->data, "day_count",
                         (int64_t)history->day_count) &&
        json_push_kv_int(&reply->data, "non_test_lines",
                         (int64_t)history->non_test_lines) &&
        json_push_kv_int(&reply->data, "test_lines",
                         (int64_t)history->test_lines) &&
        json_push_kv_str(&reply->data, "navigation",
            "hover; wheel/arrows day; page keys week; home/end range") &&
        json_push_kv_str(&reply->data, "text_size",
            "minus/plus; small, medium, large; default medium");
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
    struct npg_visual visuals[NPG_TEXT_SCALES] = {0};
    struct zcl_present_window_v1 windows[NPG_TEXT_SCALES];
    struct zcl_present_window_hover_v1 hovers[NPG_TEXT_SCALES];
    bool rendered = true;
    for (uint32_t i = 0; i < NPG_TEXT_SCALES; i++) {
        rendered = rendered && npg_visual_build(&history, &visuals[i], i);
        windows[i] = (struct zcl_present_window_v1){
            .struct_size = sizeof(windows[i]),
            .abi_version = ZCL_PRESENT_ABI_V1,
            .title = "Z23 C23 Growth - Minus/Plus adjusts text",
            .pixels = visuals[i].pixels,
            .width = NPG_WIDTH,
            .height = NPG_HEIGHT,
            .pixel_format = ZCL_PRESENT_RGB8,
        };
        hovers[i] = (struct zcl_present_window_hover_v1){
            .struct_size = sizeof(hovers[i]),
            .abi_version = ZCL_PRESENT_ABI_V1,
            .plot_left = NPG_PLOT_LEFT,
            .plot_top = NPG_PLOT_TOP,
            .plot_right = NPG_PLOT_RIGHT,
            .plot_bottom = NPG_PLOT_BOTTOM,
            .items = visuals[i].hover_items,
            .item_count = (uint32_t)history.day_count,
        };
    }
    if (!rendered) {
        npg_visuals_free(visuals);
        npg_fail(reply, "CHART_RENDER_FAILED",
                 "native chart allocation or rendering failed");
        return;
    }
    const struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = windows,
        .page_count = NPG_TEXT_SCALES,
    };
    bool shown = zcl_present_window_run_pages_hover_v1(
        &pages, hovers, NPG_TEXT_SCALE_DEFAULT, error, sizeof(error));
    npg_visuals_free(visuals);
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
