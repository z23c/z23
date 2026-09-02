/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: native display-only window for the exact Z23 C23 ecosystem. */

#include "command/native_command.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "codeindex/codeindex.h"
#include "json/json.h"
#include "presentation/canvas.h"
#include "presentation/presentation.h"
#include "science/ecosystem.h"
#include "util/log_macros.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NPE_LEAF "app.presentation.ecosystem"
#define NPE_WIDTH 1000u
#define NPE_HEIGHT 620u
#define NPE_PAGES 5u
#define NPE_PLOT_LEFT 84u
#define NPE_PLOT_TOP 352u
#define NPE_PLOT_RIGHT 878u
#define NPE_PLOT_BOTTOM 548u

struct npe_visual {
    uint8_t *pixels[NPE_PAGES];
    struct zcl_present_window_v1 pages[NPE_PAGES];
    struct zcl_present_window_hover_item_v1 *hover_items;
    char (*hover_text)[ZCL_PRESENT_WINDOW_HOVER_TEXT_MAX + 1u];
    char copy_text[SCIENCE_ECOSYSTEM_TEXT_MAX];
};

static void npe_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message)
{
    LOG_ERROR("native.presentation.ecosystem", "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, code, "observe", false, false, message,
        NPE_LEAF);
}

static const char *npe_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *environment = getenv("ZCL_DEV_SOURCE_ROOT");
    return environment && environment[0] ? environment : ".";
}

static void npe_commas(char out[32], uint64_t value)
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

static void npe_text(struct zcl_present_canvas *canvas, int32_t x, int32_t y,
                     const char *text, uint32_t size,
                     struct zcl_present_color color)
{
    zcl_present_canvas_text(canvas, x, y, text, strlen(text), size, color);
}

static void npe_text_strong(struct zcl_present_canvas *canvas, int32_t x,
                            int32_t y, const char *text, uint32_t size,
                            struct zcl_present_color color)
{
    zcl_present_canvas_text_strong(canvas, x, y, text, strlen(text), size,
                                   color);
}

static void npe_card(struct zcl_present_canvas *canvas, int32_t x, int32_t y,
                     const char *label, const char *value,
                     struct zcl_present_color panel,
                     struct zcl_present_color muted,
                     struct zcl_present_color ink)
{
    zcl_present_canvas_fill_rect(canvas, x, y, 214u, 72u, panel);
    npe_text(canvas, x + 14, y + 12, label, 13u, muted);
    npe_text_strong(canvas, x + 14, y + 34, value, 20u, ink);
}

static int32_t npe_y(uint64_t value, uint64_t maximum)
{
    uint64_t height = NPE_PLOT_BOTTOM - NPE_PLOT_TOP;
    uint64_t scaled = maximum ? value * height / maximum : 0;
    return (int32_t)(NPE_PLOT_BOTTOM - scaled);
}

static uint32_t npe_x(size_t index, size_t count)
{
    if (count < 2u)
        return NPE_PLOT_LEFT;
    return NPE_PLOT_LEFT + (uint32_t)(
        (uint64_t)index * (NPE_PLOT_RIGHT - NPE_PLOT_LEFT) / (count - 1u));
}

static bool npe_canvas(struct zcl_present_canvas *canvas, uint8_t *pixels)
{
    size_t bytes = (size_t)NPE_WIDTH * NPE_HEIGHT * 3u;
    return zcl_present_canvas_init(canvas, pixels, bytes, NPE_WIDTH,
                                   NPE_HEIGHT);
}

static void npe_page_chrome(struct zcl_present_canvas *canvas,
                            const char *title, const char *subtitle,
                            uint32_t page_index)
{
    const struct zcl_present_color background = {8, 14, 26};
    const struct zcl_present_color panel = {14, 24, 40};
    const struct zcl_present_color primary = {241, 246, 255};
    const struct zcl_present_color secondary = {153, 174, 201};
    zcl_present_canvas_clear(canvas, background);
    zcl_present_canvas_fill_rect(canvas, 28, 20, 944u, 86u, panel);
    npe_text_strong(canvas, 48, 34, title, 28u, primary);
    npe_text(canvas, 48, 72, subtitle, 15u, secondary);
    char pager[32];
    (void)snprintf(pager, sizeof(pager), "%" PRIu32 " / %" PRIu32,
                   page_index + 1u, NPE_PAGES);
    npe_text(canvas, 880, 38, pager, 15u, secondary);
}

static void npe_list_page(struct zcl_present_canvas *canvas,
                          const struct science_ecosystem_named_count *rows,
                          uint32_t listed, uint32_t total, bool truncated,
                          const char *empty)
{
    const struct zcl_present_color primary = {241, 246, 255};
    const struct zcl_present_color secondary = {153, 174, 201};
    const struct zcl_present_color cyan = {68, 224, 202};
    if (listed == 0) {
        npe_text(canvas, 48, 130, empty, 17u, secondary);
        return;
    }
    uint32_t show = listed;
    if (show > 18u)
        show = 18u;
    for (uint32_t i = 0; i < show; i++) {
        int32_t col = (int32_t)(i / 9u);
        int32_t row = (int32_t)(i % 9u);
        int32_t x = 48 + col * 470;
        int32_t y = 126 + row * 42;
        char line[160];
        if (rows[i].count > 1u)
            (void)snprintf(line, sizeof(line), "%s  (%" PRIu32 ")",
                           rows[i].name, rows[i].count);
        else if (rows[i].detail[0])
            (void)snprintf(line, sizeof(line), "%s  %s", rows[i].name,
                           rows[i].detail);
        else
            (void)snprintf(line, sizeof(line), "%s", rows[i].name);
        npe_text(canvas, x, y, line, 16u, primary);
    }
    char footer[96];
    (void)snprintf(footer, sizeof(footer),
                   truncated ? "showing %" PRIu32 " of %" PRIu32 " (truncated)"
                             : "showing %" PRIu32 " of %" PRIu32,
                   show, total);
    npe_text(canvas, 48, 572, footer, 15u, cyan);
}

static void npe_metric_or_unavail(char out[48], bool available, uint64_t value,
                                  const char *unavailable)
{
    if (!available) {
        (void)snprintf(out, 48, "%s", unavailable);
        return;
    }
    npe_commas(out, value);
}

static void npe_render_overview(
    uint8_t *pixels, const struct science_ecosystem_snapshot *snap)
{
    struct zcl_present_canvas canvas;
    if (!npe_canvas(&canvas, pixels))
        return;
    const struct zcl_present_color panel = {14, 24, 40};
    const struct zcl_present_color primary = {241, 246, 255};
    const struct zcl_present_color secondary = {153, 174, 201};
    const struct zcl_present_color cyan = {68, 224, 202};
    const struct zcl_present_color violet = {174, 125, 255};
    const struct zcl_present_color grid = {35, 54, 76};
    npe_page_chrome(&canvas, "Z23 C23 ecosystem", snap->source_root, 0u);

    char packages[48], production[48], tests[48], contexts[48];
    char capabilities[48], deps[48], duplicates[48], reached[48];
    npe_commas(packages, snap->package_count);
    npe_commas(production, snap->corpus.non_test_lines);
    npe_commas(tests, snap->corpus.test_lines);
    npe_commas(contexts, snap->context_count);
    npe_metric_or_unavail(capabilities, snap->corpus.inventory_present,
                          snap->corpus.capabilities, "unavailable");
    if (!snap->include_edges_available)
        (void)snprintf(deps, sizeof(deps), "%s", "unavailable");
    else if (snap->include_edge_count == 0)
        (void)snprintf(deps, sizeof(deps), "%s", "unanswered");
    else
        npe_commas(deps, (uint64_t)snap->include_edge_count);
    npe_metric_or_unavail(duplicates, snap->corpus.inventory_present,
                          snap->corpus.duplicates, "unavailable");
    npe_metric_or_unavail(reached, snap->corpus.inventory_present,
                          snap->corpus.symbols_test_reached, "unavailable");

    npe_card(&canvas, 36, 118, "packages", packages, panel, secondary, cyan);
    npe_card(&canvas, 266, 118, "production C23", production, panel,
             secondary, primary);
    npe_card(&canvas, 496, 118, "test C23", tests, panel, secondary, violet);
    npe_card(&canvas, 726, 118, "contexts", contexts, panel, secondary,
             primary);
    npe_card(&canvas, 36, 204, "capabilities", capabilities, panel, secondary,
             primary);
    npe_card(&canvas, 266, 204, "dependencies", deps, panel, secondary,
             primary);
    npe_card(&canvas, 496, 204, "duplicate bodies", duplicates, panel,
             secondary, primary);
    npe_card(&canvas, 726, 204, "symbols tested", reached, panel, secondary,
             cyan);

    if (!snap->growth_present) {
        npe_text(&canvas, 48, 300, "Current growth is unavailable.", 16u,
                 secondary);
        npe_text(&canvas, 48, 326,
                 snap->growth_error[0] ? snap->growth_error : "not collected",
                 15u, secondary);
    } else {
        const struct science_code_growth_history *g = &snap->growth;
        npe_text(&canvas, 48, 292, "Exact first-parent Git growth by UTC day.",
                 15u, secondary);
        uint64_t maximum = g->non_test_lines > g->test_lines
            ? g->non_test_lines : g->test_lines;
        maximum = zcl_present_canvas_chart_scale_maximum(maximum);
        for (uint32_t row = 0; row <= 4u; row++) {
            int32_t y = (int32_t)NPE_PLOT_TOP +
                (int32_t)((NPE_PLOT_BOTTOM - NPE_PLOT_TOP) * row / 4u);
            zcl_present_canvas_line(&canvas, NPE_PLOT_LEFT, y,
                                    NPE_PLOT_RIGHT, y, grid);
        }
        for (size_t i = 0; i < g->day_count; i++) {
            uint64_t non_test = g->days[i].non_test_lines;
            uint64_t test = g->days[i].test_lines;
            int32_t x = (int32_t)npe_x(i, g->day_count);
            int32_t y_non = npe_y(non_test, maximum);
            int32_t y_test = npe_y(test, maximum);
            if (i > 0) {
                int32_t px = (int32_t)npe_x(i - 1u, g->day_count);
                zcl_present_canvas_line(
                    &canvas, px, npe_y(g->days[i - 1u].non_test_lines, maximum),
                    x, y_non, cyan);
                zcl_present_canvas_line(
                    &canvas, px, npe_y(g->days[i - 1u].test_lines, maximum),
                    x, y_test, violet);
            }
            zcl_present_canvas_fill_rect(&canvas, x - 1, y_non - 1, 3u, 3u,
                                         cyan);
            zcl_present_canvas_fill_rect(&canvas, x - 1, y_test - 1, 3u, 3u,
                                         violet);
        }
        npe_text_strong(&canvas, NPE_PLOT_RIGHT + 16,
                        npe_y(g->non_test_lines, maximum) - 8, "non-test",
                        14u, cyan);
        npe_text_strong(&canvas, NPE_PLOT_RIGHT + 16,
                        npe_y(g->test_lines, maximum) - 8, "tests", 14u,
                        violet);
    }
    npe_text(&canvas, 48, 572,
             "Hover the chart. PgDn drills down. Display only.",
             15u, secondary);
}

static void npe_render_evidence(
    uint8_t *pixels, const struct science_ecosystem_snapshot *snap)
{
    struct zcl_present_canvas canvas;
    if (!npe_canvas(&canvas, pixels))
        return;
    const struct zcl_present_color primary = {241, 246, 255};
    const struct zcl_present_color secondary = {153, 174, 201};
    npe_page_chrome(&canvas, "Reuse and test evidence",
                    "Inventory and code-index facts. Missing evidence stays named.",
                    3u);
    char line[192];
    int32_t y = 128;
    if (snap->index_present) {
        (void)snprintf(line, sizeof(line),
                       "Indexed C23 files: %" PRIu32, snap->indexed_c23_files);
        npe_text(&canvas, 48, y, line, 17u, primary);
        y += 32;
        (void)snprintf(line, sizeof(line),
                       "Registry nodes: %" PRIu32, snap->indexed_registry_nodes);
        npe_text(&canvas, 48, y, line, 17u, primary);
        y += 32;
        if (!snap->include_edges_available)
            (void)snprintf(line, sizeof(line), "Include edges: unavailable");
        else if (snap->include_edge_count == 0)
            (void)snprintf(line, sizeof(line),
                           "Include edges: unanswered (depfile graph absent)");
        else
            (void)snprintf(line, sizeof(line),
                           "Include edges: %" PRId64, snap->include_edge_count);
        npe_text(&canvas, 48, y, line, 17u, primary);
        y += 40;
    } else {
        npe_text(&canvas, 48, y, "Code index: unavailable", 17u, secondary);
        y += 40;
    }
    if (snap->corpus.inventory_present) {
        (void)snprintf(line, sizeof(line),
                       "Capabilities: %" PRIu64, snap->corpus.capabilities);
        npe_text(&canvas, 48, y, line, 17u, primary);
        y += 32;
        (void)snprintf(line, sizeof(line),
                       "Symbols reached by registered tests: %" PRIu64
                       " / %" PRIu64,
                       snap->corpus.symbols_test_reached,
                       snap->corpus.symbols_exposed);
        npe_text(&canvas, 48, y, line, 17u, primary);
        y += 32;
        (void)snprintf(line, sizeof(line),
                       "Duplicate-body candidates: %" PRIu64,
                       snap->corpus.duplicates);
        npe_text(&canvas, 48, y, line, 17u, primary);
        y += 32;
        (void)snprintf(line, sizeof(line),
                       "Untested declared invariants: %" PRIu64,
                       snap->corpus.untested_invariants);
        npe_text(&canvas, 48, y, line, 17u, primary);
        y += 32;
        npe_text(&canvas, 48, y,
                 snap->corpus.scope_agrees
                     ? "Inventory scope agrees with the live tree."
                     : "STALE inventory: run make docs-capability-inventory.",
                 16u, secondary);
    } else {
        npe_text(&canvas, 48, y,
                 "Capability inventory absent: reuse/test counts are unavailable, not zero.",
                 16u, secondary);
    }
}

static void npe_render_growth(
    uint8_t *pixels, const struct science_ecosystem_snapshot *snap)
{
    struct zcl_present_canvas canvas;
    if (!npe_canvas(&canvas, pixels))
        return;
    const struct zcl_present_color primary = {241, 246, 255};
    const struct zcl_present_color secondary = {153, 174, 201};
    npe_page_chrome(&canvas, "Current growth",
                    "Latest UTC days from first-parent Git history.", 4u);
    if (!snap->growth_present) {
        npe_text(&canvas, 48, 140,
                 snap->growth_error[0] ? snap->growth_error
                                       : "growth was not collected",
                 17u, secondary);
        return;
    }
    const struct science_code_growth_history *g = &snap->growth;
    uint32_t start = 0;
    if (g->day_count > 10u)
        start = (uint32_t)(g->day_count - 10u);
    int32_t y = 126;
    for (uint32_t i = start; i < (uint32_t)g->day_count; i++) {
        const struct science_code_growth_day *day = &g->days[i];
        char line[192];
        (void)snprintf(line, sizeof(line),
                       "%s  %.10s  non-test %" PRIu64 " (+%" PRIu64 " -%"
                       PRIu64 ")  tests %" PRIu64 " (+%" PRIu64 " -%" PRIu64 ")",
                       day->date, day->head_commit, day->non_test_lines,
                       day->non_test_added, day->non_test_deleted,
                       day->test_lines, day->test_added, day->test_deleted);
        npe_text(&canvas, 48, y, line, 15u, primary);
        y += 36;
    }
}

static bool npe_visual_build(const struct science_ecosystem_snapshot *snap,
                             struct npe_visual *visual)
{
    if (!snap || !visual)
        return false;
    memset(visual, 0, sizeof(*visual));
    size_t pixel_bytes = (size_t)NPE_WIDTH * NPE_HEIGHT * 3u;
    for (uint32_t i = 0; i < NPE_PAGES; i++) {
        visual->pixels[i] = zcl_malloc(pixel_bytes, "ecosystem.pixels");
        if (!visual->pixels[i])
            return false;
    }
    size_t text_len = 0;
    if (!science_ecosystem_format_text(snap, visual->copy_text,
                                       sizeof(visual->copy_text), &text_len))
        return false;

    npe_render_overview(visual->pixels[0], snap);
    struct zcl_present_canvas packages;
    if (!npe_canvas(&packages, visual->pixels[1]))
        return false;
    npe_page_chrome(&packages, "Packages",
                    "Each row is one zcode-package.json manifest.", 1u);
    npe_list_page(&packages, snap->packages, snap->package_listed,
                  snap->package_count, snap->packages_truncated,
                  "No package manifests were found.");
    struct zcl_present_canvas contexts;
    if (!npe_canvas(&contexts, visual->pixels[2]))
        return false;
    npe_page_chrome(&contexts, "Architectural contexts",
                    "Feature rooms under contexts/ in this checkout.", 2u);
    npe_list_page(&contexts, snap->contexts, snap->context_listed,
                  snap->context_count, snap->contexts_truncated,
                  "No architectural contexts were found.");
    npe_render_evidence(visual->pixels[3], snap);
    npe_render_growth(visual->pixels[4], snap);

    static const char *titles[NPE_PAGES] = {
        "Z23 C23 ecosystem - hover the chart, PgDn for drill-down",
        "Z23 C23 ecosystem - packages",
        "Z23 C23 ecosystem - contexts",
        "Z23 C23 ecosystem - reuse and tests",
        "Z23 C23 ecosystem - growth",
    };
    for (uint32_t i = 0; i < NPE_PAGES; i++) {
        visual->pages[i] = (struct zcl_present_window_v1){
            .struct_size = sizeof(visual->pages[i]),
            .abi_version = ZCL_PRESENT_ABI_V1,
            .title = titles[i],
            .pixels = visual->pixels[i],
            .width = NPE_WIDTH,
            .height = NPE_HEIGHT,
            .pixel_format = ZCL_PRESENT_RGB8,
            .copy_text = visual->copy_text,
        };
    }

    if (!snap->growth_present || snap->growth.day_count == 0)
        return true;
    size_t days = snap->growth.day_count;
    visual->hover_items = zcl_calloc(days, sizeof(*visual->hover_items),
                                     "ecosystem.hover_items");
    visual->hover_text = zcl_calloc(days, sizeof(*visual->hover_text),
                                    "ecosystem.hover_text");
    if (!visual->hover_items || !visual->hover_text)
        return false;
    for (size_t i = 0; i < days; i++) {
        const struct science_code_growth_day *day = &snap->growth.days[i];
        visual->hover_items[i].x = npe_x(i, days);
        visual->hover_items[i].text = visual->hover_text[i];
        char non_test[32], added[32], deleted[32], tests[32], tadd[32],
            tdel[32];
        npe_commas(non_test, day->non_test_lines);
        npe_commas(added, day->non_test_added);
        npe_commas(deleted, day->non_test_deleted);
        npe_commas(tests, day->test_lines);
        npe_commas(tadd, day->test_added);
        npe_commas(tdel, day->test_deleted);
        (void)snprintf(visual->hover_text[i], sizeof(visual->hover_text[i]),
                       "%s UTC  |  commit %.10s\nnon-test %s (+%s -%s)  |  "
                       "tests %s (+%s -%s)",
                       day->date, day->head_commit, non_test, added, deleted,
                       tests, tadd, tdel);
    }
    return true;
}

static void npe_visual_free(struct npe_visual *visual)
{
    if (!visual)
        return;
    for (uint32_t i = 0; i < NPE_PAGES; i++)
        free(visual->pixels[i]);
    free(visual->hover_items);
    free(visual->hover_text);
    memset(visual, 0, sizeof(*visual));
}

static bool npe_push_named(struct json_value *array,
                           const struct science_ecosystem_named_count *row)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    bool ok = json_push_kv_str(&obj, "name", row->name) &&
        json_push_kv_str(&obj, "detail", row->detail) &&
        json_push_kv_int(&obj, "count", (int64_t)row->count) &&
        json_push_back(array, &obj);
    json_free(&obj);
    return ok;
}

static bool npe_push_list(struct json_value *data, const char *key,
                          const struct science_ecosystem_named_count *rows,
                          uint32_t listed)
{
    struct json_value array;
    json_init(&array);
    json_set_array(&array);
    bool ok = true;
    for (uint32_t i = 0; ok && i < listed; i++)
        ok = npe_push_named(&array, &rows[i]);
    if (ok)
        ok = json_push_kv(data, key, &array);
    json_free(&array);
    return ok;
}

static bool npe_reply_snapshot(struct zcl_command_reply *reply,
                               const struct science_ecosystem_snapshot *snap,
                               const char *plain_text, bool launched)
{
    char sha3_hex[65];
    sha3_hex[0] = '\0';
    if (snap->source_root_sha3_present)
        zcl_hex_encode(snap->source_root_sha3, 32u, sha3_hex);

    bool ok = json_push_kv_bool(&reply->data, "launched", launched) &&
        json_push_kv_str(&reply->data, "delivery",
                         launched ? "native" : "text") &&
        json_push_kv_str(&reply->data, "authority", "display-only") &&
        json_push_kv_bool(&reply->data, "privileged_action_performed",
                          false) &&
        json_push_kv_str(&reply->data, "source_root", snap->source_root) &&
        json_push_kv_str(&reply->data, "source_root_sha3",
                         snap->source_root_sha3_present ? sha3_hex
                                                        : "unavailable") &&
        json_push_kv_int(&reply->data, "packages",
                         (int64_t)snap->package_count) &&
        json_push_kv_str(&reply->data, "packages_authority",
                         "zcode-package.json manifests") &&
        json_push_kv_bool(&reply->data, "packages_truncated",
                          snap->packages_truncated) &&
        npe_push_list(&reply->data, "package_list", snap->packages,
                      snap->package_listed) &&
        json_push_kv_int(&reply->data, "production_c23_lines",
                         (int64_t)snap->corpus.non_test_lines) &&
        json_push_kv_int(&reply->data, "test_c23_lines",
                         (int64_t)snap->corpus.test_lines) &&
        json_push_kv_int(&reply->data, "files_walked",
                         (int64_t)snap->corpus.files_walked) &&
        json_push_kv_int(&reply->data, "architectural_contexts",
                         (int64_t)snap->context_count) &&
        json_push_kv_bool(&reply->data, "contexts_truncated",
                          snap->contexts_truncated) &&
        npe_push_list(&reply->data, "context_list", snap->contexts,
                      snap->context_listed) &&
        json_push_kv_bool(&reply->data, "index_present", snap->index_present) &&
        json_push_kv_bool(&reply->data, "inventory_present",
                          snap->corpus.inventory_present) &&
        json_push_kv_bool(&reply->data, "growth_present",
                          snap->growth_present);
    if (!ok)
        return false;

    if (snap->index_present) {
        ok = json_push_kv_int(&reply->data, "indexed_c23_files",
                              (int64_t)snap->indexed_c23_files) &&
            json_push_kv_int(&reply->data, "indexed_registry_nodes",
                             (int64_t)snap->indexed_registry_nodes) &&
            json_push_kv_int(&reply->data, "indexed_source_roots",
                             (int64_t)snap->indexed_root_count) &&
            npe_push_list(&reply->data, "indexed_root_list",
                          snap->indexed_roots, snap->indexed_root_listed);
        if (ok && snap->include_edges_available) {
            if (snap->include_edge_count == 0)
                ok = json_push_kv_str(&reply->data, "include_edges",
                                      "unanswered");
            else
                ok = json_push_kv_int(&reply->data, "include_edges",
                                      snap->include_edge_count);
        } else if (ok) {
            ok = json_push_kv_str(&reply->data, "include_edges",
                                  "unavailable");
        }
    } else {
        ok = json_push_kv_str(&reply->data, "indexed_c23_files",
                              "unavailable") &&
            json_push_kv_str(&reply->data, "indexed_registry_nodes",
                             "unavailable") &&
            json_push_kv_str(&reply->data, "indexed_source_roots",
                             "unavailable") &&
            json_push_kv_str(&reply->data, "indexed_root_list",
                             "unavailable") &&
            json_push_kv_str(&reply->data, "include_edges", "unavailable");
    }

    if (ok && snap->corpus.inventory_present) {
        ok = json_push_kv_int(&reply->data, "capabilities",
                              (int64_t)snap->corpus.capabilities) &&
            json_push_kv_int(&reply->data, "symbols_exposed",
                             (int64_t)snap->corpus.symbols_exposed) &&
            json_push_kv_int(&reply->data, "symbols_test_reached",
                             (int64_t)snap->corpus.symbols_test_reached) &&
            json_push_kv_int(&reply->data, "duplicates",
                             (int64_t)snap->corpus.duplicates) &&
            json_push_kv_int(&reply->data, "untested_invariants",
                             (int64_t)snap->corpus.untested_invariants) &&
            json_push_kv_bool(&reply->data, "scope_agrees",
                              snap->corpus.scope_agrees);
    } else if (ok) {
        ok = json_push_kv_str(&reply->data, "capabilities", "unavailable") &&
            json_push_kv_str(&reply->data, "symbols_exposed", "unavailable") &&
            json_push_kv_str(&reply->data, "symbols_test_reached",
                             "unavailable") &&
            json_push_kv_str(&reply->data, "duplicates", "unavailable") &&
            json_push_kv_str(&reply->data, "untested_invariants",
                             "unavailable") &&
            json_push_kv_str(&reply->data, "scope_agrees", "n/a");
    }

    if (ok && snap->growth_present) {
        const struct science_code_growth_history *g = &snap->growth;
        const struct science_code_growth_day *latest =
            g->day_count ? &g->days[g->day_count - 1u] : NULL;
        ok = json_push_kv_int(&reply->data, "growth_days",
                              (int64_t)g->day_count) &&
            json_push_kv_int(&reply->data, "growth_non_test_lines",
                             (int64_t)g->non_test_lines) &&
            json_push_kv_int(&reply->data, "growth_test_lines",
                             (int64_t)g->test_lines);
        if (ok && latest)
            ok = json_push_kv_str(&reply->data, "growth_latest_date",
                                  latest->date) &&
                json_push_kv_str(&reply->data, "growth_latest_commit",
                                 latest->head_commit);
    } else if (ok) {
        ok = json_push_kv_str(&reply->data, "growth", "unavailable") &&
            json_push_kv_str(&reply->data, "growth_error",
                             snap->growth_error);
    }

    if (!ok)
        return false;
    if (!launched) {
        ok = json_push_kv_bool(&reply->data, "text_export", true) &&
            json_push_kv_bool(&reply->data, "text_complete", true) &&
            json_push_kv_int(&reply->data, "text_page", 0) &&
            json_push_kv_int(&reply->data, "text_page_count", 1) &&
            json_push_kv_str(&reply->data, "plain_text", plain_text) &&
            json_push_kv_str(&reply->data, "backend",
                             "c23-deterministic-text");
    } else {
        ok = json_push_kv_bool(&reply->data, "text_export_available", true) &&
            json_push_kv_str(&reply->data, "backend",
                             zcl_present_backend_name()) &&
            json_push_kv_str(&reply->data, "platform",
                             zcl_present_platform_name());
    }
    return ok;
}

static bool npe_bind_codeindex(const char *root,
                               struct science_ecosystem_snapshot *snap)
{
    /* Display-only authority: read the store that already exists and never
     * rebuild or refresh it. A missing store leaves index facts unbound so
     * every form names them unavailable. */
    struct codeindex *ci = codeindex_open_existing(root);
    if (!ci)
        return true;

    uint8_t sha3[32];
    memset(sha3, 0, sizeof(sha3));
    (void)codeindex_source_root_sha3(ci, sha3);

    struct ci_source_file_counts counts;
    memset(&counts, 0, sizeof(counts));
    bool have_counts = codeindex_source_file_counts(ci, &counts);

    int64_t edges = codeindex_include_edge_count(ci);
    bool include_available = edges >= 0;

    static struct ci_group groups[512];
    int ng = codeindex_groups(ci, groups,
                              (int)(sizeof(groups) / sizeof(groups[0])));
    if (ng < 0)
        ng = 0;

    static const char *const source_roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
    };
    struct science_ecosystem_named_count roots[SCIENCE_ECOSYSTEM_ROOTS_MAX];
    memset(roots, 0, sizeof(roots));
    uint32_t nroot = 0;
    for (size_t i = 0;
         i < sizeof(source_roots) / sizeof(source_roots[0]) &&
         nroot < SCIENCE_ECOSYSTEM_ROOTS_MAX;
         i++) {
        int fc = codeindex_count_files_in_group(ci, source_roots[i], true);
        if (fc <= 0)
            continue;
        const char *purpose = "";
        for (int g = 0; g < ng; g++)
            if (strcmp(groups[g].path, source_roots[i]) == 0) {
                purpose = groups[g].purpose;
                break;
            }
        (void)snprintf(roots[nroot].name, sizeof(roots[nroot].name), "%s",
                       source_roots[i]);
        (void)snprintf(roots[nroot].detail, sizeof(roots[nroot].detail), "%s",
                       purpose);
        roots[nroot].count = (uint32_t)fc;
        nroot++;
    }

    science_ecosystem_bind_index(
        snap, have_counts, sha3,
        have_counts ? (uint32_t)counts.c23_files : 0,
        have_counts ? (uint32_t)counts.registry_nodes : 0,
        include_available, include_available ? edges : 0, roots, nroot);
    codeindex_close(ci);
    return true;
}

void zcl_native_handle_presentation_ecosystem(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const struct json_value *output_value =
        request->input ? json_get(request->input, "output") : NULL;
    const char *output = json_get_str(output_value);
    if (output_value && (!output || (strcmp(output, "native") != 0 &&
                                    strcmp(output, "text") != 0))) {
        npe_fail(reply, "INVALID_OUTPUT",
                 "output must be exactly native or text");
        return;
    }

    struct science_ecosystem_snapshot *snap =
        zcl_calloc(1, sizeof(*snap), "ecosystem.snapshot");
    if (!snap) {
        npe_fail(reply, "SNAPSHOT_ALLOC_FAILED",
                 "ecosystem snapshot allocation failed");
        return;
    }
    char error[192];
    struct science_ecosystem_collect_options options = {
        .collect_growth = true,
        .inventory_path = NULL,
    };
    const char *root = npe_source_root(request);
    if (!science_ecosystem_collect(root, &options, snap, error,
                                   sizeof(error))) {
        free(snap);
        npe_fail(reply, "ECOSYSTEM_UNAVAILABLE", error);
        return;
    }
    (void)npe_bind_codeindex(root, snap);

    char plain_text[SCIENCE_ECOSYSTEM_TEXT_MAX];
    size_t text_len = 0;
    if (!science_ecosystem_format_text(snap, plain_text, sizeof(plain_text),
                                       &text_len)) {
        free(snap);
        npe_fail(reply, "ECOSYSTEM_TEXT_FAILED",
                 "deterministic ecosystem text did not fit");
        return;
    }
    if (output && strcmp(output, "text") == 0) {
        bool ok = npe_reply_snapshot(reply, snap, plain_text, false);
        free(snap);
        if (!ok)
            npe_fail(reply, "ECOSYSTEM_REPLY_FAILED",
                     "ecosystem text JSON allocation failed");
        return;
    }

    struct npe_visual visual;
    if (!npe_visual_build(snap, &visual)) {
        npe_visual_free(&visual);
        free(snap);
        npe_fail(reply, "ECOSYSTEM_RENDER_FAILED",
                 "native ecosystem allocation or rendering failed");
        return;
    }
    struct zcl_present_window_pages_v1 pages = {
        .struct_size = sizeof(pages),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = visual.pages,
        .page_count = NPE_PAGES,
    };
    bool shown;
    if (snap->growth_present && visual.hover_items) {
        struct zcl_present_window_hover_v1 hover = {
            .struct_size = sizeof(hover),
            .abi_version = ZCL_PRESENT_ABI_V1,
            .plot_left = NPE_PLOT_LEFT,
            .plot_top = NPE_PLOT_TOP,
            .plot_right = NPE_PLOT_RIGHT,
            .plot_bottom = NPE_PLOT_BOTTOM,
            .items = visual.hover_items,
            .item_count = (uint32_t)snap->growth.day_count,
        };
        shown = zcl_present_window_run_pages_first_hover_v1(
            &pages, &hover, error, sizeof(error));
    } else {
        struct zcl_present_window_event_v1 event;
        shown = zcl_present_window_run_pages_actions_v1(
            &pages, 0, NULL, NULL, &event, error, sizeof(error));
    }
    bool ok = shown && npe_reply_snapshot(reply, snap, plain_text, true);
    npe_visual_free(&visual);
    free(snap);
    if (!shown)
        npe_fail(reply, "NATIVE_ECOSYSTEM_FAILED", error);
    else if (!ok)
        npe_fail(reply, "ECOSYSTEM_REPLY_FAILED",
                 "ecosystem window JSON allocation failed");
}
