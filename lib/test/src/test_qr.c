/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "encoding/qr.h"
#include "command/native_command.h"
#include "json/json.h"
#include "presentation/canvas.h"
#include "presentation/model.h"
#include "presentation/model_render.h"
#include "presentation/model_text.h"
#include "presentation/presentation.h"
#include "presentation/zclassic_brand.h"
#include "views/qr_popup.h"
#include "views/ui_present.h"
#include "views/ui_present_document.h"
#include "views/ui_present_host_transport.h"
#include "vcs/zcode_work_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int qr_failures;

#define QR_CHECK(name, condition) do {                                      \
    printf("  %-58s ", (name));                                             \
    if (condition) printf("PASS\n");                                       \
    else { printf("FAIL\n"); qr_failures++; }                              \
} while (0)

static void qr_reproduction_facts(struct json_value *facts,
                                  const char *action, const char *candidate,
                                  const char *event, const char *receipt,
                                  const char *state)
{
    json_init(facts); json_set_object(facts);
    json_push_kv_str(facts, "schema", "zcl.build_fabric_action_state.v1");
    json_push_kv_bool(facts, "found", true);
    json_push_kv_bool(facts, "event_root_rederived", true);
    json_push_kv_str(facts, "action_id", action);
    json_push_kv_str(facts, "candidate_root", candidate);
    json_push_kv_str(facts, "event_root", event);
    json_push_kv_str(facts, "receipt_root", receipt);
    json_push_kv_str(facts, "state", state);
}

static void qr_publication_records(struct json_value *projection,
                                   const char *kind,
                                   const char *package_root,
                                   const char *transport_root,
                                   const char *provider_node_id,
                                   bool include)
{
    json_init(projection); json_set_object(projection);
    json_push_kv_bool(projection, "local_projection", true);
    struct json_value records;
    json_init(&records); json_set_array(&records);
    if (include) {
        struct json_value row;
        json_init(&row); json_set_object(&row);
        json_push_kv_str(&row, "kind", kind);
        json_push_kv_str(&row, "record_root", package_root);
        json_push_kv_str(&row, "namespace", "zclassic23.package");
        json_push_kv_str(&row, "semantic_root", package_root);
        json_push_kv_str(&row, "transport_root", transport_root);
        json_push_kv_str(&row, "provider_node_id", provider_node_id);
        json_push_back(&records, &row);
        json_free(&row);
    }
    json_push_kv(projection, "records", &records);
    json_free(&records);
}

static void qr_publication_facts(struct json_value *facts,
                                 const char *package_root,
                                 const char *transport_root,
                                 const char *confirmation_identity,
                                 const char *local_node_id,
                                 const char *record_node_id,
                                 bool local_complete, bool pointer,
                                 bool provider, bool download_complete,
                                 int64_t fetched_bytes)
{
    json_init(facts); json_set_object(facts);
    json_push_kv_str(facts, "schema", "zcl.package_publication_facts.v1");
    json_push_kv_str(facts, "package_root", package_root);
    json_push_kv_str(facts, "transport_root", transport_root);
    json_push_kv_str(facts, "confirmation_identity", confirmation_identity);
    json_push_kv_str(facts, "local_node_id", local_node_id);
    json_push_kv_bool(facts, "local_package_committed", local_complete);
    struct json_value package, local, download;
    json_init(&package); json_set_object(&package);
    json_init(&local); json_set_object(&local);
    json_push_kv_bool(&local, "found", local_complete);
    json_push_kv_bool(&local, "complete", local_complete);
    json_push_kv(&package, "local_package", &local);
    json_free(&local);
    json_push_kv_bool(&package, "download_found", download_complete);
    if (download_complete) {
        json_init(&download); json_set_object(&download);
        json_push_kv_str(&download, "state", "complete");
        json_push_kv_int(&download, "present_chunks", 3);
        json_push_kv_int(&download, "total_chunks", 3);
        json_push_kv_int(&download, "present_bytes", 4096);
        json_push_kv_int(&download, "total_bytes", 4096);
        json_push_kv_int(&download, "fetched_bytes", fetched_bytes);
        json_push_kv(&package, "download", &download);
        json_free(&download);
    }
    json_push_kv(facts, "package", &package);
    json_free(&package);
    struct json_value pointers, providers;
    qr_publication_records(&pointers, "pointer", package_root,
                           transport_root, record_node_id, pointer);
    qr_publication_records(&providers, "provider", package_root,
                           transport_root, record_node_id, provider);
    json_push_kv(facts, "pointer_records", &pointers);
    json_push_kv(facts, "provider_records", &providers);
    json_free(&pointers);
    json_free(&providers);
}

static bool finder_matches(const struct qr_matrix *matrix, uint32_t ox,
                           uint32_t oy)
{
    for (uint32_t y = 0; y < 7; y++) {
        for (uint32_t x = 0; x < 7; x++) {
            bool expected = x == 0 || x == 6 || y == 0 || y == 6 ||
                            (x >= 2 && x <= 4 && y >= 2 && y <= 4);
            bool actual = (matrix->modules[(size_t)(oy + y) * matrix->width +
                                           ox + x] & 1u) != 0;
            if (actual != expected) return false;
        }
    }
    return true;
}

int test_qr(void)
{
    printf("\n=== qr ===\n");
    qr_failures = 0;
    QR_CHECK("native QR backend is compiled", qr_matrix_backend_available());
    if (!qr_matrix_backend_available()) return qr_failures;

    char why[128];
    struct qr_matrix first;
    struct qr_matrix second;
    bool encoded = qr_matrix_encode(
        "zclassic:t1QRNativeC23?amount=0.01000000", &first,
        why, sizeof(why));
    QR_CHECK("payment URI encodes", encoded);
    if (!encoded) return qr_failures;
    QR_CHECK("matrix has a standards-shaped version width",
             first.width >= 21u && first.width <= 177u &&
             (first.width - 21u) % 4u == 0u);
    QR_CHECK("top-left finder pattern is exact", finder_matches(&first, 0, 0));
    QR_CHECK("top-right finder pattern is exact",
             finder_matches(&first, first.width - 7u, 0));
    QR_CHECK("bottom-left finder pattern is exact",
             finder_matches(&first, 0, first.width - 7u));

    bool encoded_again = qr_matrix_encode(
        "zclassic:t1QRNativeC23?amount=0.01000000", &second,
        why, sizeof(why));
    QR_CHECK("same payload encodes deterministically",
             encoded_again && second.width == first.width &&
             memcmp(second.modules, first.modules,
                    (size_t)first.width * first.width) == 0);

    uint8_t *pixels = NULL;
    uint32_t side = 0;
    bool rendered = qr_matrix_render_rgb(&first, 3, ZCL_QR_QUIET_MODULES,
                                         &pixels, &side, why, sizeof(why));
    QR_CHECK("RGB renderer succeeds", rendered);
    QR_CHECK("RGB renderer uses exact integer dimensions",
             rendered && side == (first.width + 8u) * 3u);
    QR_CHECK("quiet-zone corner is white",
             rendered && pixels[0] == 0xff && pixels[1] == 0xff &&
             pixels[2] == 0xff);
    size_t dark = ((size_t)ZCL_QR_QUIET_MODULES * 3u * side +
                   ZCL_QR_QUIET_MODULES * 3u) * 3u;
    QR_CHECK("first finder module renders black",
             rendered && pixels[dark] == 0 && pixels[dark + 1] == 0 &&
             pixels[dark + 2] == 0);
    free(pixels);

    char oversized[ZCL_QR_MAX_PAYLOAD + 2u];
    memset(oversized, 'x', sizeof(oversized));
    oversized[sizeof(oversized) - 1u] = '\0';
    struct qr_matrix rejected;
    QR_CHECK("empty payload is rejected",
             !qr_matrix_encode("", &rejected, why, sizeof(why)));
    QR_CHECK("oversized payload is rejected",
             !qr_matrix_encode(oversized, &rejected, why, sizeof(why)));

    uint8_t icon[ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES];
    QR_CHECK("canonical ZClassic window icon expands",
             zcl_present_zclassic_icon_rgba(icon, sizeof(icon)));
    bool saw_orange = false;
    bool saw_transparent = false;
    for (size_t i = 0; i < sizeof(icon); i += 4u) {
        if (icon[i] == 0xc8 && icon[i + 1u] == 0x70 &&
            icon[i + 2u] == 0x35 && icon[i + 3u] == 0xff)
            saw_orange = true;
        if (icon[i + 3u] == 0) saw_transparent = true;
    }
    QR_CHECK("canonical icon preserves brand color and transparency",
             saw_orange && saw_transparent);

    uint8_t canvas_pixels[32u * 32u * 3u];
    struct zcl_present_canvas canvas;
    QR_CHECK("reusable RGB canvas initializes",
             zcl_present_canvas_init(&canvas, canvas_pixels,
                                     sizeof(canvas_pixels), 32u, 32u));
    const struct zcl_present_color canvas_white = {0xff, 0xff, 0xff};
    const struct zcl_present_color canvas_orange = {0xc8, 0x70, 0x35};
    zcl_present_canvas_clear(&canvas, canvas_white);
    zcl_present_canvas_fill_rect(&canvas, -4, -4, 8u, 8u, canvas_orange);
    QR_CHECK("canvas primitives clip safely at the upper-left edge",
             canvas_pixels[0] == 0xc8 && canvas_pixels[1] == 0x70 &&
             canvas_pixels[2] == 0x35 &&
             canvas_pixels[((size_t)5u * 32u + 5u) * 3u] == 0xff);
    zcl_present_canvas_text(&canvas, 8, 8, "Aa", 2u, 16u, canvas_orange);
    bool saw_antialias = false;
    for (size_t i = 0; i < sizeof(canvas_pixels); i++) {
        if (canvas_pixels[i] != 0xff && canvas_pixels[i] != 0xc8 &&
            canvas_pixels[i] != 0x70 && canvas_pixels[i] != 0x35) {
            saw_antialias = true;
            break;
        }
    }
    QR_CHECK("embedded Basic Latin text is antialiased", saw_antialias);
    uint32_t balance_width =
        zcl_present_canvas_text_width("balance", 7u, 16u);
    QR_CHECK("proportional canvas text metrics are deterministic",
             balance_width > 40u && balance_width < 80u &&
             balance_width ==
                 zcl_present_canvas_text_width("balance", 7u, 16u));

    struct zcl_present_model_v1 deposit_model;
    QR_CHECK("deposit payload becomes one bounded QR visual model",
             zcl_present_model_qr_from_payload_v1(
                 "zclassic:t1QRNativeC23?label=phone&amount=0.01000000",
                 "ignored fixture title", &deposit_model,
                 why, sizeof(why)));
    struct qr_popup_card deposit_card;
    QR_CHECK("ZCL URI composes as a branded deposit card",
             qr_popup_card_render(&deposit_model, &deposit_card,
                 why, sizeof(why)));
    QR_CHECK("deposit card identifies exact address and amount",
             deposit_card.is_deposit &&
             strcmp(deposit_card.address, "t1QRNativeC23") == 0 &&
             strcmp(deposit_card.amount, "0.01000000") == 0);
    QR_CHECK("deposit card has stable presentation dimensions",
             deposit_card.pixels &&
             deposit_card.width == ZCL_QR_POPUP_CARD_WIDTH &&
             deposit_card.height == ZCL_QR_POPUP_CARD_HEIGHT);
    bool card_has_orange = false;
    for (size_t i = 0; deposit_card.pixels &&
         i < ZCL_QR_POPUP_CARD_BYTES; i += 3u) {
        if (deposit_card.pixels[i] == 0xc8 &&
            deposit_card.pixels[i + 1u] == 0x70 &&
            deposit_card.pixels[i + 2u] == 0x35) {
            card_has_orange = true;
            break;
        }
    }
    QR_CHECK("deposit card carries ZClassic orange branding in pixels",
             card_has_orange);
    qr_popup_card_free(&deposit_card);

    struct zcl_present_model_v1 generic_model;
    QR_CHECK("generic payload becomes the same closed QR model shape",
             zcl_present_model_qr_from_payload_v1(
                 "generic metadata", "Metadata", &generic_model,
                 why, sizeof(why)));
    struct qr_popup_card generic_card;
    QR_CHECK("non-payment text stays explicitly generic",
             qr_popup_card_render(&generic_model, &generic_card,
                                  why, sizeof(why)) &&
             !generic_card.is_deposit &&
             strcmp(generic_card.address, "generic metadata") == 0);
    qr_popup_card_free(&generic_card);
    struct ui_present_document qr_document;
    QR_CHECK("one compositor owns QR title, pixels and copy payload",
             ui_present_document_from_model(
                 &generic_model, &qr_document, why, sizeof(why)) &&
             qr_document.is_qr && qr_document.page_count == 1u &&
             qr_document.action_count == 0u &&
             qr_document.windows[0].pixels == qr_document.qr_card.pixels &&
             strcmp(qr_document.windows[0].title,
                    "Z23 — Metadata — C copies, Esc closes") == 0 &&
             strcmp(qr_document.windows[0].copy_text,
                    "generic metadata") == 0);
    ui_present_document_free(&qr_document);

    static const uint8_t tiny_rgb[] = {
        0xff, 0xff, 0xff, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
    };
    struct zcl_present_window_v1 present = {
        .struct_size = sizeof(present),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "Presentation validation fixture",
        .pixels = tiny_rgb,
        .width = 2,
        .height = 2,
        .pixel_format = ZCL_PRESENT_RGB8,
        .icon_rgba = icon,
        .icon_width = ZCL_PRESENT_ZCLASSIC_ICON_WIDTH,
        .icon_height = ZCL_PRESENT_ZCLASSIC_ICON_HEIGHT,
        .copy_text = "fixture",
    };
    QR_CHECK("portable presentation request validates",
             zcl_present_window_validate_v1(&present, why, sizeof(why)));
    present.abi_version++;
    QR_CHECK("presentation ABI mismatch fails closed",
             !zcl_present_window_validate_v1(&present, why, sizeof(why)));
    present.abi_version = ZCL_PRESENT_ABI_V1;
    struct zcl_present_window_event_v1 bounded_event;
    QR_CHECK("native action keys remain bounded to four",
             !zcl_present_window_run_actions_v1(
                 &present, ZCL_PRESENT_WINDOW_ACTIONS_MAX + 1u,
                 NULL, NULL, &bounded_event, why, sizeof(why)));
    uint32_t clicked_action = UINT32_MAX;
    QR_CHECK("native confirmation click selects the first exact action",
             zcl_present_window_action_at_v1(
                 720, 720, 720, 720, 100, 670, 2, &clicked_action) &&
             clicked_action == 0);
    QR_CHECK("resized confirmation click selects the second exact action",
             zcl_present_window_action_at_v1(
                 720, 720, 1440, 1440, 1100, 1340, 2,
                 &clicked_action) && clicked_action == 1);
    QR_CHECK("action gap and letterbox clicks return no decision",
             !zcl_present_window_action_at_v1(
                 720, 720, 720, 720, 360, 670, 2,
                 &clicked_action) &&
             !zcl_present_window_action_at_v1(
                 720, 720, 1000, 720, 100, 670, 2,
                 &clicked_action));
    struct zcl_present_model_v1 rejected_qr;
    QR_CHECK("shared QR model rejects an empty payload",
             !zcl_present_model_qr_from_payload_v1(
                 "", "Empty", &rejected_qr, why, sizeof(why)));
    char oversized_qr[ZCL_QR_MAX_PAYLOAD + 2u];
    memset(oversized_qr, 'x', sizeof(oversized_qr) - 1u);
    oversized_qr[sizeof(oversized_qr) - 1u] = '\0';
    QR_CHECK("shared QR model rejects oversized bytes",
             !zcl_present_model_qr_from_payload_v1(
                 oversized_qr, "Oversized", &rejected_qr,
                 why, sizeof(why)));
    char max_qr[ZCL_QR_MAX_PAYLOAD + 1u];
    memset(max_qr, 'q', sizeof(max_qr) - 1u);
    max_qr[sizeof(max_qr) - 1u] = '\0';
    char recovered_qr[ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX + 1u];
    QR_CHECK("maximum QR bytes use all ordered model chunks",
             zcl_present_model_qr_from_payload_v1(
                 max_qr, "Maximum", &rejected_qr, why, sizeof(why)) &&
             rejected_qr.item_count == ZCL_PRESENT_MODEL_QR_CHUNKS_MAX &&
             zcl_present_model_qr_payload_v1(
                 &rejected_qr, recovered_qr, why, sizeof(why)) &&
             strcmp(recovered_qr, max_qr) == 0);
    char qr_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t qr_text_len = 0;
    uint32_t qr_text_pages = 0;
    QR_CHECK("QR text companion pages the exact model payload chunks",
             zcl_present_model_text_page_v1(
                 &rejected_qr, 0, qr_text, sizeof(qr_text), &qr_text_len,
                 &qr_text_pages, why, sizeof(why)) &&
             qr_text_pages == ZCL_PRESENT_MODEL_QR_CHUNKS_MAX &&
             qr_text_len < sizeof(qr_text) &&
             strstr(qr_text, "page: 1/8") != NULL &&
             strstr(qr_text, "payload-bytes: 1-256 of 2048") != NULL &&
             strstr(qr_text, rejected_qr.items[0].value) != NULL &&
             zcl_present_model_text_page_v1(
                 &rejected_qr, ZCL_PRESENT_MODEL_QR_CHUNKS_MAX - 1u,
                 qr_text, sizeof(qr_text), &qr_text_len, &qr_text_pages,
                 why, sizeof(why)) &&
             strstr(qr_text, "payload-bytes: 1793-2048 of 2048") != NULL &&
             !zcl_present_model_text_page_v1(
                 &rejected_qr, ZCL_PRESENT_MODEL_QR_CHUNKS_MAX,
                 qr_text, sizeof(qr_text), &qr_text_len, &qr_text_pages,
                 why, sizeof(why)));
    QR_CHECK("complete QR text export joins every exact payload chunk",
             zcl_present_model_text_all_v1(
                 &rejected_qr, qr_text, sizeof(qr_text), &qr_text_len,
                 why, sizeof(why)) &&
             strstr(qr_text, "page: 1/1") != NULL &&
             strstr(qr_text, "payload-bytes: 1-2048 of 2048") != NULL &&
             strstr(qr_text, max_qr) != NULL);
    rejected_qr.items[1].id[0] = 'x';
    QR_CHECK("reordered QR payload chunks fail closed",
             !zcl_present_model_validate_v1(
                 &rejected_qr, why, sizeof(why)));
    QR_CHECK("presentation backend is the pinned software backend",
             strcmp(zcl_present_backend_name(), "rgfw-1.8.1-software") == 0);
    QR_CHECK("presentation uses stable desktop application identity",
             strcmp(ZCL_PRESENT_APPLICATION_ID,
                    "org.zclassic.ZClassic23") == 0);

    struct zcl_present_model_v1 visual;
    zcl_present_model_init_v1(&visual, ZCL_PRESENT_MODEL_PROGRESS);
    (void)snprintf(visual.request_id, sizeof(visual.request_id),
                   "reproduce-42");
    (void)snprintf(visual.title, sizeof(visual.title),
                   "Independent reproduction");
    (void)snprintf(visual.summary, sizeof(visual.summary),
                   "Builder two is reproducing the exact candidate bytes.");
    visual.item_count = 1;
    visual.items[0].kind = ZCL_PRESENT_ITEM_PROGRESS;
    visual.items[0].status = ZCL_PRESENT_STATUS_INFO;
    visual.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    visual.items[0].numerator = 7;
    visual.items[0].denominator = 10;
    (void)snprintf(visual.items[0].id, sizeof(visual.items[0].id),
                   "builder-two");
    (void)snprintf(visual.items[0].label, sizeof(visual.items[0].label),
                   "Builder two");
    (void)snprintf(visual.items[0].value, sizeof(visual.items[0].value),
                   "Compiling");
    visual.action_count = 1;
    visual.actions[0].kind = ZCL_PRESENT_ACTION_CLOSE;
    (void)snprintf(visual.actions[0].id, sizeof(visual.actions[0].id),
                   "close");
    (void)snprintf(visual.actions[0].label,
                   sizeof(visual.actions[0].label), "Close");
    QR_CHECK("renderer-neutral progress model validates",
             zcl_present_model_validate_v1(&visual, why, sizeof(why)));
    char visual_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    char visual_text_again[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t visual_text_len = 0, visual_text_len_again = 0;
    uint32_t visual_text_pages = 0, visual_text_pages_again = 0;
    bool visual_text_ok = zcl_present_model_text_page_v1(
        &visual, 0, visual_text, sizeof(visual_text), &visual_text_len,
        &visual_text_pages, why, sizeof(why));
    bool visual_text_again_ok = zcl_present_model_text_page_v1(
        &visual, 0, visual_text_again, sizeof(visual_text_again),
        &visual_text_len_again, &visual_text_pages_again,
        why, sizeof(why));
    QR_CHECK("same model produces one deterministic text companion",
             visual_text_ok && visual_text_again_ok &&
             visual_text_pages == 1u && visual_text_pages_again == 1u &&
             visual_text_len == visual_text_len_again &&
             strcmp(visual_text, visual_text_again) == 0 &&
             strstr(visual_text, "kind: progress") != NULL &&
             strstr(visual_text, "progress: 7/10") != NULL &&
             strstr(visual_text, "action 1: close") != NULL &&
             strstr(visual_text, "authority: display-only") != NULL);

    struct zcl_present_model_v1 chart;
    zcl_present_model_init_v1(&chart, ZCL_PRESENT_MODEL_CHART);
    (void)snprintf(chart.request_id, sizeof(chart.request_id),
                   "coverage-chart");
    (void)snprintf(chart.title, sizeof(chart.title),
                   "Exact candidate coverage");
    chart.item_count = 2;
    for (uint32_t i = 0; i < chart.item_count; i++) {
        chart.items[i].kind = ZCL_PRESENT_ITEM_CHART_POINT;
        chart.items[i].status = i == 0 ? ZCL_PRESENT_STATUS_INFO
                                       : ZCL_PRESENT_STATUS_GREEN;
        chart.items[i].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        chart.items[i].numerator = i == 0 ? 47u : 81u;
        chart.items[i].denominator = 100u;
        (void)snprintf(chart.items[i].id, sizeof(chart.items[i].id),
                       "coverage-%u", i);
        (void)snprintf(chart.items[i].label, sizeof(chart.items[i].label),
                       "%s", i == 0 ? "Before" : "Candidate");
        (void)snprintf(chart.items[i].value, sizeof(chart.items[i].value),
                       "%u%%", chart.items[i].numerator);
    }
    QR_CHECK("chart points require exact bounded fractions",
             zcl_present_model_validate_v1(&chart, why, sizeof(why)));
    char chart_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t chart_text_len = 0;
    QR_CHECK("chart text companion preserves the exact plotted fractions",
             zcl_present_model_text_all_v1(
                 &chart, chart_text, sizeof(chart_text), &chart_text_len,
                 why, sizeof(why)) &&
             strstr(chart_text, "chart-point: 47/100") != NULL &&
             strstr(chart_text, "chart-point: 81/100") != NULL);
    struct zcl_present_model_bitmap_v1 chart_47 = {0};
    struct zcl_present_model_bitmap_v1 chart_48 = {0};
    bool chart_47_ok = zcl_present_model_render_v1(
        &chart, &chart_47, why, sizeof(why));
    chart.items[0].numerator = 48u;
    bool chart_48_ok = zcl_present_model_render_v1(
        &chart, &chart_48, why, sizeof(why));
    QR_CHECK("one-point chart change produces different native pixels",
             chart_47_ok && chart_48_ok &&
             memcmp(chart_47.pixels, chart_48.pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    zcl_present_model_bitmap_free_v1(&chart_47);
    zcl_present_model_bitmap_free_v1(&chart_48);
    chart.items[0].denominator = 0;
    QR_CHECK("zero-scale chart data fails closed",
             !zcl_present_model_validate_v1(&chart, why, sizeof(why)) &&
             strstr(why, "chart-point fraction") != NULL);

    struct zcl_present_model_v1 timeline;
    zcl_present_model_init_v1(&timeline, ZCL_PRESENT_MODEL_TIMELINE);
    (void)snprintf(timeline.request_id, sizeof(timeline.request_id),
                   "proof-timeline");
    (void)snprintf(timeline.title, sizeof(timeline.title),
                   "Exact proof sequence");
    timeline.item_count = 2;
    for (uint32_t i = 0; i < timeline.item_count; i++) {
        timeline.items[i].kind = ZCL_PRESENT_ITEM_TIMELINE_EVENT;
        timeline.items[i].status = i == 0 ? ZCL_PRESENT_STATUS_INFO
                                          : ZCL_PRESENT_STATUS_GREEN;
        timeline.items[i].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        (void)snprintf(timeline.items[i].id,
                       sizeof(timeline.items[i].id), "event-%u", i);
        (void)snprintf(timeline.items[i].label,
                       sizeof(timeline.items[i].label), "%s",
                       i == 0 ? "Candidate observed" : "Receipt verified");
        (void)snprintf(timeline.items[i].value,
                       sizeof(timeline.items[i].value), "%s",
                       i == 0 ? "source epoch exact" : "independent signer");
    }
    struct zcl_present_model_bitmap_v1 timeline_pixels = {0};
    struct zcl_present_model_bitmap_v1 row_pixels = {0};
    bool timeline_ok = zcl_present_model_render_v1(
        &timeline, &timeline_pixels, why, sizeof(why));
    struct zcl_present_model_v1 rows = timeline;
    rows.kind = ZCL_PRESENT_MODEL_STATUS_CARD;
    rows.items[0].kind = ZCL_PRESENT_ITEM_KEY_VALUE;
    rows.items[1].kind = ZCL_PRESENT_ITEM_KEY_VALUE;
    bool rows_ok = zcl_present_model_render_v1(
        &rows, &row_pixels, why, sizeof(why));
    QR_CHECK("timeline events render as a native sequence, not generic rows",
             timeline_ok && rows_ok &&
             memcmp(timeline_pixels.pixels, row_pixels.pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    zcl_present_model_bitmap_free_v1(&timeline_pixels);
    zcl_present_model_bitmap_free_v1(&row_pixels);

    struct zcl_present_model_v1 graph;
    zcl_present_model_init_v1(&graph, ZCL_PRESENT_MODEL_EVIDENCE_GRAPH);
    (void)snprintf(graph.request_id, sizeof(graph.request_id),
                   "evidence-graph");
    (void)snprintf(graph.title, sizeof(graph.title),
                   "Candidate evidence");
    graph.item_count = 3;
    for (uint32_t i = 0; i < graph.item_count; i++) {
        graph.items[i].kind = ZCL_PRESENT_ITEM_GRAPH_NODE;
        graph.items[i].status = i == 2 ? ZCL_PRESENT_STATUS_GREEN
                                       : ZCL_PRESENT_STATUS_INFO;
        graph.items[i].parent_index = i == 0
            ? ZCL_PRESENT_MODEL_PARENT_NONE : (uint16_t)(i - 1u);
        (void)snprintf(graph.items[i].id, sizeof(graph.items[i].id),
                       "evidence-%u", i);
        (void)snprintf(graph.items[i].label,
                       sizeof(graph.items[i].label), "%s",
                       i == 0 ? "Candidate root" :
                       i == 1 ? "Story observation" : "Verified receipt");
        (void)snprintf(graph.items[i].value,
                       sizeof(graph.items[i].value), "exact node %u", i + 1u);
    }
    struct zcl_present_model_bitmap_v1 graph_pixels = {0};
    struct zcl_present_model_bitmap_v1 graph_rows_pixels = {0};
    bool graph_ok = zcl_present_model_render_v1(
        &graph, &graph_pixels, why, sizeof(why));
    struct zcl_present_model_v1 graph_rows = graph;
    graph_rows.kind = ZCL_PRESENT_MODEL_STATUS_CARD;
    for (uint32_t i = 0; i < graph_rows.item_count; i++) {
        graph_rows.items[i].kind = ZCL_PRESENT_ITEM_KEY_VALUE;
        graph_rows.items[i].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    }
    bool graph_rows_ok = zcl_present_model_render_v1(
        &graph_rows, &graph_rows_pixels, why, sizeof(why));
    QR_CHECK("evidence graph renders parent connectors, not generic rows",
             graph_ok && graph_rows_ok &&
             memcmp(graph_pixels.pixels, graph_rows_pixels.pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    zcl_present_model_bitmap_free_v1(&graph_pixels);
    zcl_present_model_bitmap_free_v1(&graph_rows_pixels);
    char graph_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t graph_text_len = 0;
    QR_CHECK("evidence graph text preserves the exact parent chain",
             zcl_present_model_text_all_v1(
                 &graph, graph_text, sizeof(graph_text), &graph_text_len,
                 why, sizeof(why)) &&
             strstr(graph_text, "parent-item: 1") != NULL &&
             strstr(graph_text, "parent-item: 2") != NULL);
    graph.items[1].parent_index = 2u;
    QR_CHECK("forward evidence-graph parent fails closed",
             !zcl_present_model_validate_v1(&graph, why, sizeof(why)) &&
             strstr(why, "earlier graph node") != NULL);

    struct zcl_present_model_v1 choice;
    zcl_present_model_init_v1(&choice, ZCL_PRESENT_MODEL_CHOICE);
    (void)snprintf(choice.request_id, sizeof(choice.request_id),
                   "proof-choice");
    (void)snprintf(choice.title, sizeof(choice.title),
                   "Choose the next proof");
    choice.item_count = 2;
    choice.action_count = 2;
    for (uint32_t i = 0; i < choice.item_count; i++) {
        choice.items[i].kind = ZCL_PRESENT_ITEM_CHOICE;
        choice.items[i].status = ZCL_PRESENT_STATUS_INFO;
        choice.items[i].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        choice.items[i].flags = i == 0 ? ZCL_PRESENT_ITEM_SELECTED : 0;
        choice.actions[i].kind = ZCL_PRESENT_ACTION_SELECT;
        (void)snprintf(choice.items[i].id, sizeof(choice.items[i].id),
                       "proof-%u", i + 1u);
        (void)snprintf(choice.actions[i].id, sizeof(choice.actions[i].id),
                       "proof-%u", i + 1u);
        (void)snprintf(choice.items[i].label,
                       sizeof(choice.items[i].label), "%s",
                       i == 0 ? "Focused story" : "Broader suite");
        (void)snprintf(choice.items[i].value,
                       sizeof(choice.items[i].value), "%s",
                       i == 0 ? "fast exact evidence" : "slower coverage");
        (void)snprintf(choice.actions[i].label,
                       sizeof(choice.actions[i].label), "%s",
                       i == 0 ? "Focused story" : "Broader suite");
    }
    struct zcl_present_model_bitmap_v1 choice_pixels = {0};
    struct zcl_present_model_bitmap_v1 choice_rows_pixels = {0};
    bool choice_ok = zcl_present_model_render_v1(
        &choice, &choice_pixels, why, sizeof(why));
    struct zcl_present_model_v1 choice_rows = choice;
    choice_rows.kind = ZCL_PRESENT_MODEL_STATUS_CARD;
    choice_rows.action_count = 0;
    for (uint32_t i = 0; i < choice_rows.item_count; i++) {
        choice_rows.items[i].kind = ZCL_PRESENT_ITEM_KEY_VALUE;
        choice_rows.items[i].flags = 0;
    }
    bool choice_rows_ok = zcl_present_model_render_v1(
        &choice_rows, &choice_rows_pixels, why, sizeof(why));
    QR_CHECK("choice options render as numbered radios, not generic rows",
             choice_ok && choice_rows_ok &&
             memcmp(choice_pixels.pixels, choice_rows_pixels.pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    zcl_present_model_bitmap_free_v1(&choice_pixels);
    zcl_present_model_bitmap_free_v1(&choice_rows_pixels);
    char choice_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t choice_text_len = 0;
    QR_CHECK("choice text binds selected row and returned action IDs",
             zcl_present_model_text_all_v1(
                 &choice, choice_text, sizeof(choice_text), &choice_text_len,
                 why, sizeof(why)) &&
             strstr(choice_text, "flags: selected") != NULL &&
             strstr(choice_text, "id: proof-1") != NULL &&
             strstr(choice_text, "action 1: select") != NULL);
    choice.actions[1].id[6] = '9';
    QR_CHECK("choice/action ID drift fails closed",
             !zcl_present_model_validate_v1(&choice, why, sizeof(why)) &&
             strstr(why, "matching select actions") != NULL);

    struct zcl_present_model_v1 form_model;
    zcl_present_model_init_v1(&form_model, ZCL_PRESENT_MODEL_FORM);
    (void)snprintf(form_model.request_id, sizeof(form_model.request_id),
                   "release-form");
    (void)snprintf(form_model.title, sizeof(form_model.title),
                   "Describe exact release");
    memset(form_model.exact_root, 'f', ZCL_PRESENT_MODEL_ROOT_MAX);
    form_model.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    form_model.item_count = 2;
    form_model.items[0].kind = ZCL_PRESENT_ITEM_FORM_FIELD;
    form_model.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    form_model.items[0].flags = ZCL_PRESENT_ITEM_REQUIRED;
    (void)snprintf(form_model.items[0].id,
                   sizeof(form_model.items[0].id), "release-note");
    (void)snprintf(form_model.items[0].label,
                   sizeof(form_model.items[0].label), "Release note");
    form_model.items[1].kind = ZCL_PRESENT_ITEM_FORM_FIELD;
    form_model.items[1].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    form_model.items[1].flags = ZCL_PRESENT_ITEM_READ_ONLY;
    (void)snprintf(form_model.items[1].id,
                   sizeof(form_model.items[1].id), "candidate-root");
    (void)snprintf(form_model.items[1].label,
                   sizeof(form_model.items[1].label), "Candidate root");
    (void)snprintf(form_model.items[1].value,
                   sizeof(form_model.items[1].value), "immutable-root");
    form_model.action_count = 2;
    form_model.actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(form_model.actions[0].id,
                   sizeof(form_model.actions[0].id), "cancel");
    (void)snprintf(form_model.actions[0].label,
                   sizeof(form_model.actions[0].label), "Cancel");
    form_model.actions[1].kind = ZCL_PRESENT_ACTION_SUBMIT;
    (void)snprintf(form_model.actions[1].id,
                   sizeof(form_model.actions[1].id), "submit-release-note");
    (void)snprintf(form_model.actions[1].label,
                   sizeof(form_model.actions[1].label), "Submit");
    QR_CHECK("bounded form fixes fields and safe cancel/submit order",
             zcl_present_model_validate_v1(
                 &form_model, why, sizeof(why)));
    struct zcl_present_model_bitmap_v1 form_pixels = {0};
    struct zcl_present_model_bitmap_v1 form_rows_pixels = {0};
    bool form_pixels_ok = zcl_present_model_render_v1(
        &form_model, &form_pixels, why, sizeof(why));
    struct zcl_present_model_v1 form_rows = form_model;
    form_rows.kind = ZCL_PRESENT_MODEL_STATUS_CARD;
    form_rows.action_count = 0;
    form_rows.exact_root[0] = '\0';
    for (uint32_t i = 0; i < form_rows.item_count; i++) {
        form_rows.items[i].kind = ZCL_PRESENT_ITEM_KEY_VALUE;
        form_rows.items[i].flags = 0;
    }
    bool form_rows_ok = zcl_present_model_render_v1(
        &form_rows, &form_rows_pixels, why, sizeof(why));
    QR_CHECK("form fields render as input boxes, not generic rows",
             form_pixels_ok && form_rows_ok &&
             memcmp(form_pixels.pixels, form_rows_pixels.pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    zcl_present_model_bitmap_free_v1(&form_pixels);
    zcl_present_model_bitmap_free_v1(&form_rows_pixels);

    struct zcl_present_window_form_v1 form_state;
    uint32_t form_focus = UINT32_MAX;
    QR_CHECK("shared form bridge preserves exact values and field policy",
             zcl_present_window_form_from_model_v1(
                 &form_model, &form_state, why, sizeof(why)) &&
             form_state.field_count == 2 &&
             form_state.fields[0].flags ==
                 ZCL_PRESENT_WINDOW_FORM_REQUIRED &&
             form_state.fields[0].value[0] == '\0' &&
             form_state.fields[1].flags ==
                 ZCL_PRESENT_WINDOW_FORM_READ_ONLY &&
             strcmp(form_state.fields[1].value, "immutable-root") == 0);
    QR_CHECK("form typing and Backspace change one exact editable value",
             zcl_present_window_form_edit_v1(
                 &form_state, 0, (uint8_t)'A', false) &&
             strcmp(form_state.fields[0].value, "A") == 0 &&
             zcl_present_window_form_edit_v1(
                 &form_state, 0, 0, true) &&
             form_state.fields[0].value[0] == '\0' &&
             !zcl_present_window_form_edit_v1(
                 &form_state, 1, (uint8_t)'x', false));
    QR_CHECK("form focus skips read-only bytes then reaches both actions",
             zcl_present_window_form_focus_step_v1(
                 &form_state, 2, 0, 1, &form_focus) &&
             form_focus == form_state.field_count &&
             zcl_present_window_form_focus_step_v1(
                 &form_state, 2, form_focus, 1, &form_focus) &&
             form_focus == form_state.field_count + 1u &&
             zcl_present_window_form_focus_step_v1(
                 &form_state, 2, form_focus, 1, &form_focus) &&
             form_focus == 0);

    struct zcl_present_model_v1 submitted_form = form_model;
    (void)snprintf(submitted_form.items[0].value,
                   sizeof(submitted_form.items[0].value), "exact note");
    QR_CHECK("form submission may change only editable value bytes",
             zcl_present_model_form_submission_validate_v1(
                 &form_model, &submitted_form, why, sizeof(why)));
    submitted_form.items[0].label[0] = 'X';
    QR_CHECK("form submission immutable-label mutant fails closed",
             !zcl_present_model_form_submission_validate_v1(
                 &form_model, &submitted_form, why, sizeof(why)));
    submitted_form = form_model;
    (void)snprintf(submitted_form.items[1].value,
                   sizeof(submitted_form.items[1].value), "forged-root");
    QR_CHECK("form submission read-only mutant fails closed",
             !zcl_present_model_form_submission_validate_v1(
                 &form_model, &submitted_form, why, sizeof(why)));
    submitted_form = form_model;
    submitted_form.actions[0].kind = ZCL_PRESENT_ACTION_SUBMIT;
    QR_CHECK("form action-order mutant fails closed",
             !zcl_present_model_validate_v1(
                 &submitted_form, why, sizeof(why)));

    struct zcl_present_model_v1 canvas_model;
    zcl_present_model_init_v1(&canvas_model, ZCL_PRESENT_MODEL_CANVAS);
    (void)snprintf(canvas_model.request_id,
                   sizeof(canvas_model.request_id), "placement-canvas");
    (void)snprintf(canvas_model.title, sizeof(canvas_model.title),
                   "Place the exact label");
    memset(canvas_model.exact_root, 'e', ZCL_PRESENT_MODEL_ROOT_MAX);
    canvas_model.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    canvas_model.item_count = 2;
    canvas_model.items[0].kind = ZCL_PRESENT_ITEM_CANVAS_POINT;
    canvas_model.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    canvas_model.items[0].flags = ZCL_PRESENT_ITEM_SELECTED;
    canvas_model.items[0].numerator = 250;
    canvas_model.items[0].denominator = 300;
    (void)snprintf(canvas_model.items[0].id,
                   sizeof(canvas_model.items[0].id), "label-origin");
    (void)snprintf(canvas_model.items[0].label,
                   sizeof(canvas_model.items[0].label), "Label origin");
    canvas_model.items[1].kind = ZCL_PRESENT_ITEM_CANVAS_POINT;
    canvas_model.items[1].status = ZCL_PRESENT_STATUS_INFO;
    canvas_model.items[1].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    canvas_model.items[1].flags = ZCL_PRESENT_ITEM_READ_ONLY;
    canvas_model.items[1].numerator = 800;
    canvas_model.items[1].denominator = 700;
    (void)snprintf(canvas_model.items[1].id,
                   sizeof(canvas_model.items[1].id), "fixed-anchor");
    (void)snprintf(canvas_model.items[1].label,
                   sizeof(canvas_model.items[1].label), "Fixed anchor");
    canvas_model.action_count = 2;
    canvas_model.actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(canvas_model.actions[0].id,
                   sizeof(canvas_model.actions[0].id), "cancel");
    (void)snprintf(canvas_model.actions[0].label,
                   sizeof(canvas_model.actions[0].label), "Cancel");
    canvas_model.actions[1].kind = ZCL_PRESENT_ACTION_SUBMIT;
    (void)snprintf(canvas_model.actions[1].id,
                   sizeof(canvas_model.actions[1].id), "submit-placement");
    (void)snprintf(canvas_model.actions[1].label,
                   sizeof(canvas_model.actions[1].label), "Submit");
    QR_CHECK("bounded canvas fixes one editable point and safe actions",
             zcl_present_model_validate_v1(
                 &canvas_model, why, sizeof(why)));
    struct zcl_present_model_bitmap_v1 canvas_model_pixels = {0};
    QR_CHECK("bounded canvas renders a real normalized 2D instrument",
             zcl_present_model_render_v1(
                 &canvas_model, &canvas_model_pixels, why, sizeof(why)) &&
             canvas_model_pixels.pixels != NULL);
    zcl_present_model_bitmap_free_v1(&canvas_model_pixels);
    char canvas_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t canvas_text_len = 0;
    QR_CHECK("canvas text companion preserves exact normalized coordinates",
             zcl_present_model_text_all_v1(
                 &canvas_model, canvas_text, sizeof(canvas_text),
                 &canvas_text_len, why, sizeof(why)) &&
             strstr(canvas_text, "canvas-point-x-y: 250/300") != NULL &&
             strstr(canvas_text, "flags: selected") != NULL &&
             strstr(canvas_text, "flags: read-only") != NULL);

    struct zcl_present_window_canvas_v1 canvas_state = {
        .struct_size = sizeof(canvas_state),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .point_count = 2,
        .editable_index = 0,
        .points = {
            {.x = 250, .y = 300, .label = "Label origin"},
            {.flags = ZCL_PRESENT_WINDOW_CANVAS_POINT_READ_ONLY,
             .status = ZCL_PRESENT_STATUS_INFO,
             .x = 800, .y = 700, .label = "Fixed anchor"},
        },
    };
    QR_CHECK("canvas reducer accepts one editable and one reference point",
             zcl_present_window_canvas_validate_v1(
                 &canvas_state, why, sizeof(why)));
    QR_CHECK("canvas arrows move only the editable point and clamp exactly",
             zcl_present_window_canvas_step_v1(
                 &canvas_state, -300, 710) &&
             canvas_state.points[0].x == 0 &&
             canvas_state.points[0].y == 1000 &&
             canvas_state.points[1].x == 800 &&
             canvas_state.points[1].y == 700);
    uint32_t canvas_focus = UINT32_MAX;
    QR_CHECK("canvas focus traverses point, Cancel, Submit, then wraps",
             zcl_present_window_canvas_focus_step_v1(
                 2, 0, 1, &canvas_focus) && canvas_focus == 1 &&
             zcl_present_window_canvas_focus_step_v1(
                 2, canvas_focus, 1, &canvas_focus) && canvas_focus == 2 &&
             zcl_present_window_canvas_focus_step_v1(
                 2, canvas_focus, 1, &canvas_focus) && canvas_focus == 0);
    uint32_t canvas_x = UINT32_MAX, canvas_y = UINT32_MAX;
    QR_CHECK("canvas hit test maps native pixels to bounded coordinates",
             zcl_present_window_canvas_point_at_v1(
                 ZCL_PRESENT_MODEL_BITMAP_WIDTH,
                 ZCL_PRESENT_MODEL_BITMAP_HEIGHT,
                 (int32_t)ZCL_PRESENT_MODEL_BITMAP_WIDTH,
                 (int32_t)ZCL_PRESENT_MODEL_BITMAP_HEIGHT,
                 359, 383, &canvas_x, &canvas_y) &&
             canvas_x == 499 && canvas_y == 498);
    struct zcl_present_model_v1 submitted_canvas = canvas_model;
    submitted_canvas.items[0].numerator = 499;
    submitted_canvas.items[0].denominator = 498;
    QR_CHECK("canvas submission may change only editable coordinates",
             zcl_present_model_canvas_submission_validate_v1(
                 &canvas_model, &submitted_canvas, why, sizeof(why)));
    submitted_canvas.items[1].numerator++;
    QR_CHECK("canvas reference-point mutant fails closed",
             !zcl_present_model_canvas_submission_validate_v1(
                 &canvas_model, &submitted_canvas, why, sizeof(why)));
    submitted_canvas = canvas_model;
    submitted_canvas.items[0].label[0] = 'X';
    QR_CHECK("canvas immutable-label mutant fails closed",
             !zcl_present_model_canvas_submission_validate_v1(
                 &canvas_model, &submitted_canvas, why, sizeof(why)));
    submitted_canvas = canvas_model;
    submitted_canvas.items[1].flags |= ZCL_PRESENT_ITEM_SELECTED;
    QR_CHECK("canvas selected-reference mutant fails closed",
             !zcl_present_model_validate_v1(
                 &submitted_canvas, why, sizeof(why)));

    uint8_t host_nonce[UI_HOST_NONCE_BYTES];
    memset(host_nonce, 0x5a, sizeof(host_nonce));
    uint8_t host_reply[UI_HOST_REPLY_BYTES];
    uint32_t host_status = UINT32_MAX, host_value = UINT32_MAX;
    uint32_t host_payload_len = 0;
    uint64_t host_elapsed = 0;
    ui_host_transport_reply(
        host_reply, UI_HOST_PHASE_EVENT, UI_HOST_STATUS_OK, 1,
        777, 1234, host_nonce);
    QR_CHECK("form payload length is nonce-bound in the fixed host reply",
             ui_host_transport_parse_reply(
                 host_reply, UI_HOST_PHASE_EVENT, &host_status,
                 &host_value, &host_payload_len, &host_elapsed,
                 host_nonce) && host_status == UI_HOST_STATUS_OK &&
             host_value == 1 && host_payload_len == 777 &&
             host_elapsed == 1234);
    host_reply[20] = 1;
    QR_CHECK("host reply reserved-byte mutant fails closed",
             !ui_host_transport_parse_reply(
                 host_reply, UI_HOST_PHASE_EVENT, &host_status,
                 &host_value, &host_payload_len, &host_elapsed,
                 host_nonce));

    uint8_t model_wire[ZCL_PRESENT_MODEL_WIRE_MAX];
    size_t model_wire_len = 0;
    struct zcl_present_model_v1 decoded;
    QR_CHECK("visual model encodes without structure padding",
             zcl_present_model_encode_v1(
                 &visual, model_wire, sizeof(model_wire), &model_wire_len,
                 why, sizeof(why)) && model_wire_len > 0);
    QR_CHECK("visual model round-trips exactly",
             zcl_present_model_decode_v1(
                 model_wire, model_wire_len, &decoded, why, sizeof(why)) &&
             decoded.kind == visual.kind &&
             decoded.item_count == 1 &&
             decoded.items[0].numerator == 7 &&
             decoded.items[0].denominator == 10 &&
             strcmp(decoded.items[0].value, "Compiling") == 0);
    QR_CHECK("visual model rejects trailing wire bytes",
             model_wire_len + 1u < sizeof(model_wire) &&
             !zcl_present_model_decode_v1(
                 model_wire, model_wire_len + 1u, &decoded,
                 why, sizeof(why)));

    struct zcl_present_model_v1 confirmation;
    zcl_present_model_init_v1(&confirmation,
                              ZCL_PRESENT_MODEL_CONFIRMATION);
    (void)snprintf(confirmation.request_id,
                   sizeof(confirmation.request_id), "publish-7");
    (void)snprintf(confirmation.title, sizeof(confirmation.title),
                   "Publish exact candidate?");
    memset(confirmation.exact_root, 'a', ZCL_PRESENT_MODEL_ROOT_MAX);
    confirmation.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    confirmation.action_count = 2;
    confirmation.actions[0].kind = ZCL_PRESENT_ACTION_CANCEL;
    (void)snprintf(confirmation.actions[0].id,
                   sizeof(confirmation.actions[0].id), "cancel");
    (void)snprintf(confirmation.actions[0].label,
                   sizeof(confirmation.actions[0].label), "Cancel");
    confirmation.actions[1].kind = ZCL_PRESENT_ACTION_CONFIRM;
    (void)snprintf(confirmation.actions[1].id,
                   sizeof(confirmation.actions[1].id), "confirm");
    (void)snprintf(confirmation.actions[1].label,
                   sizeof(confirmation.actions[1].label), "Publish");
    QR_CHECK("exact confirmation binds a root and two explicit actions",
             zcl_present_model_validate_v1(
                 &confirmation, why, sizeof(why)));
    struct zcl_present_model_bitmap_v1 exact_root_a = {0};
    struct zcl_present_model_bitmap_v1 exact_root_b = {0};
    bool exact_root_a_ok = zcl_present_model_render_v1(
        &confirmation, &exact_root_a, why, sizeof(why));
    confirmation.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX - 1u] = 'b';
    bool exact_root_b_ok = zcl_present_model_render_v1(
        &confirmation, &exact_root_b, why, sizeof(why));
    QR_CHECK("root suffix changes remain visible in exact confirmation pixels",
             exact_root_a_ok && exact_root_b_ok &&
             memcmp(exact_root_a.pixels, exact_root_b.pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    zcl_present_model_bitmap_free_v1(&exact_root_a);
    zcl_present_model_bitmap_free_v1(&exact_root_b);
    confirmation.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX - 1u] = 'a';
    confirmation.exact_root[0] = '\0';
    QR_CHECK("rootless publication confirmation fails closed",
             !zcl_present_model_validate_v1(
                 &confirmation, why, sizeof(why)));
    memset(confirmation.exact_root, 'a', ZCL_PRESENT_MODEL_ROOT_MAX);
    confirmation.exact_root[ZCL_PRESENT_MODEL_ROOT_MAX] = '\0';
    struct ui_present_document action_document;
    QR_CHECK("one compositor preserves exact actions and copy root",
             ui_present_document_from_model(
                 &confirmation, &action_document, why, sizeof(why)) &&
             !action_document.is_qr &&
             action_document.page_count == 1u &&
             action_document.action_count == 2u &&
             strcmp(action_document.windows[0].copy_text,
                    confirmation.exact_root) == 0);
    ui_present_document_free(&action_document);

    struct json_value status_facts, health_facts, health_checks;
    struct json_value backup_facts, work_facts;
    json_init(&status_facts); json_set_object(&status_facts);
    json_push_kv_int(&status_facts, "provable_tip", 3216084);
    json_push_kv_bool(&status_facts, "provable_tip_published", true);
    json_push_kv_bool(&status_facts, "sync_gap_known", true);
    json_push_kv_int(&status_facts, "sync_gap", 0);
    json_push_kv_int(&status_facts, "peers", 6);
    json_init(&health_facts); json_set_object(&health_facts);
    json_init(&health_checks); json_set_object(&health_checks);
    json_push_kv_bool(&health_checks, "tor_enabled", true);
    json_push_kv_bool(&health_checks, "onion_service_ready", true);
    json_push_kv_str(&health_checks, "onion_address", "fixture.onion");
    json_push_kv(&health_facts, "checks", &health_checks);
    json_free(&health_checks);
    json_init(&backup_facts); json_set_object(&backup_facts);
    json_push_kv_int(&backup_facts, "total_runs", 3);
    json_push_kv_int(&backup_facts, "total_failures", 0);
    json_push_kv_int(&backup_facts, "last_run_unix", 1234);
    json_push_kv_str(&backup_facts, "last_error", "");
    json_init(&work_facts); json_set_object(&work_facts);
    json_push_kv_bool(&work_facts, "enabled", true);
    json_push_kv_int(&work_facts, "worker_capacity", 4);
    json_push_kv_int(&work_facts, "worker_active", 1);
    json_push_kv_int(&work_facts, "worker_available", 3);
    struct zcl_present_model_v1 status_model;
    QR_CHECK("canonical status facts build one closed native model",
             zcl_native_presentation_status_model_from_facts(
                 &status_facts, &health_facts, &backup_facts, &work_facts,
                 &status_model, why, sizeof(why)) &&
             status_model.kind == ZCL_PRESENT_MODEL_STATUS_CARD &&
             status_model.item_count == 6);
    QR_CHECK("status model labels fact authority and preserves capacity",
             strncmp(status_model.items[0].label, "NODE FACT - ", 12) == 0 &&
             strcmp(status_model.items[0].value, "3216084") == 0 &&
             strcmp(status_model.items[5].value,
                    "3 available / 4 total (1 active)") == 0);
    QR_CHECK("dark canonical sources stay unavailable, never false-disabled",
             zcl_native_presentation_status_model_from_facts(
                 &status_facts, NULL, &backup_facts, NULL,
                 &status_model, why, sizeof(why)) &&
             strcmp(status_model.items[3].value, "unavailable") == 0 &&
             strcmp(status_model.items[5].value, "unavailable") == 0);
    json_free(&work_facts);
    json_free(&backup_facts);
    json_free(&health_facts);
    json_free(&status_facts);

    struct json_value corpus_facts;
    json_init(&corpus_facts); json_set_object(&corpus_facts);
    json_push_kv_bool(&corpus_facts, "projection_ready", true);
    json_push_kv_str(&corpus_facts, "checkpoint_root",
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
    json_push_kv_int(&corpus_facts, "admitted_production_loc", 201600);
    json_push_kv_int(&corpus_facts, "admitted_test_loc", 390954);
    json_push_kv_int(&corpus_facts, "durably_hosted_loc", 0);
    json_push_kv_int(&corpus_facts, "unique_semantic_units", 434817);
    json_push_kv_int(&corpus_facts, "packages_admitted", 50);
    json_push_kv_int(&corpus_facts, "packages_excluded", 18);
    json_push_kv_str(&corpus_facts, "progress_stage", "below_50m");
    json_push_kv_str(&corpus_facts, "blocker",
                     "verified lower bound is 592554 LOC");
    struct zcl_present_model_v1 corpus_model;
    QR_CHECK("canonical corpus status builds one exact native instrument",
             zcl_native_presentation_corpus_model_from_facts(
                 &corpus_facts, &corpus_model, why, sizeof(why)) &&
             corpus_model.kind == ZCL_PRESENT_MODEL_STATUS_CARD &&
             strcmp(corpus_model.title, "10 Million Exact C23") == 0 &&
             strcmp(corpus_model.exact_root,
                "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
                == 0 &&
             corpus_model.item_count == 10);
    bool corpus_package_exact = false;
    bool corpus_used_honest = false;
    bool corpus_velocity_honest = false;
    for (uint32_t i = 0; i < corpus_model.item_count; i++) {
        const struct zcl_present_model_item_v1 *item =
            &corpus_model.items[i];
        corpus_package_exact |= strcmp(item->id, "packages") == 0 &&
                                strcmp(item->value, "50 packages") == 0;
        corpus_used_honest |= strcmp(item->id, "used-loc") == 0 &&
            strcmp(item->value, "unavailable (not checkpoint-bound)") == 0 &&
            item->status == ZCL_PRESENT_STATUS_YELLOW;
        corpus_velocity_honest |= strcmp(item->id, "velocity") == 0 &&
            strcmp(item->value,
                   "unavailable (previous checkpoint not bound)") == 0 &&
            item->status == ZCL_PRESENT_STATUS_YELLOW;
    }
    QR_CHECK("corpus instrument preserves exact package and exclusion facts",
             corpus_package_exact &&
             strcmp(corpus_model.items[6].value,
                    "18 entries; reason LOC unavailable") == 0);
    QR_CHECK("corpus instrument never fabricates used LOC or velocity",
             corpus_used_honest && corpus_velocity_honest);
    char corpus_all_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t corpus_all_text_len = 0;
    QR_CHECK("one bounded corpus text export contains every exact fact",
             zcl_present_model_text_all_v1(
                 &corpus_model, corpus_all_text, sizeof(corpus_all_text),
                 &corpus_all_text_len, why, sizeof(why)) &&
             corpus_all_text_len < sizeof(corpus_all_text) &&
             strstr(corpus_all_text, "page: 1/1") != NULL &&
             strstr(corpus_all_text, "CORPUS FACT - Admitted production") &&
             strstr(corpus_all_text, "CORPUS FACT - Packages admitted") &&
             strstr(corpus_all_text, "CORPUS FACT - Exclusions") &&
             strstr(corpus_all_text, "CORPUS FACT - Velocity"));
    json_free(&corpus_facts);

    struct json_value corpus_request_input;
    json_init(&corpus_request_input); json_set_object(&corpus_request_input);
    json_push_kv_str(&corpus_request_input, "output", "text");
    struct zcl_command_request corpus_request = {
        .input = &corpus_request_input,
    };
    struct zcl_command_reply corpus_reply;
    zcl_command_reply_init(&corpus_reply,
                           "zcl.app_presentation_corpus.v1");
    zcl_native_handle_presentation_corpus(&corpus_request, &corpus_reply);
    const char *corpus_text =
        json_get_str(json_get(&corpus_reply.data, "plain_text"));
    QR_CHECK("typed corpus instrument is headless and display-only end to end",
             corpus_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             !json_get_bool(json_get(&corpus_reply.data, "launched")) &&
             json_get_bool(json_get(&corpus_reply.data, "text_complete")) &&
             json_get_int(json_get(&corpus_reply.data,
                                   "text_page_count")) == 1 &&
             corpus_text && strstr(corpus_text, "10 Million Exact C23") &&
             strstr(corpus_text, "CORPUS FACT - Admitted production") &&
             strstr(corpus_text, "CORPUS FACT - Packages admitted") &&
             strstr(corpus_text, "CORPUS FACT - Exclusions") &&
             strstr(corpus_text, "CORPUS FACT - Velocity") &&
             strstr(corpus_text, "value: unavailable") &&
             strcmp(json_get_str(json_get(&corpus_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&corpus_reply);
    json_free(&corpus_request_input);

    static const uint8_t code_before[] =
        "#include \"presentation/model.h\"\n"
        "int exact_value(void) {\n"
        "    return 1;\n"
        "}\n";
    static const uint8_t code_after[] =
        "#include \"presentation/model.h\"\n"
        "int exact_value(void) {\n"
        "    return 2;\n"
        "}\n";
    char root_a[65], root_b[65], tree_root[65];
    memset(root_a, 'a', 64u); root_a[64] = '\0';
    memset(root_b, 'b', 64u); root_b[64] = '\0';
    memset(tree_root, 'c', 64u); tree_root[64] = '\0';
    struct zcl_present_model_v1 code_model;
    QR_CHECK("exact C facts build a provenance-labeled code-change model",
             zcl_native_presentation_code_change_model_from_facts(
                 code_before, sizeof(code_before) - 1u,
                 code_after, sizeof(code_after) - 1u,
                 "tools/command/native_qr_command.c", "return two",
                 "returned one", "returns two", root_a, root_b, tree_root,
                 &code_model, why, sizeof(why)) &&
             code_model.kind == ZCL_PRESENT_MODEL_CODE_DIFF &&
             strcmp(code_model.exact_root, tree_root) == 0 &&
             strncmp(code_model.items[0].label, "AGENT SUMMARY - ", 16) == 0 &&
             strncmp(code_model.items[3].label, "LOCAL OBSERVATION - ", 20) == 0);
    bool caught_remove = false, caught_add = false, caught_include = false;
    for (uint32_t i = 0; i < code_model.item_count; i++) {
        caught_remove |= code_model.items[i].kind ==
                         ZCL_PRESENT_ITEM_DIFF_REMOVE &&
                         strcmp(code_model.items[i].value, "    return 1;") == 0;
        caught_add |= code_model.items[i].kind == ZCL_PRESENT_ITEM_DIFF_ADD &&
                      strcmp(code_model.items[i].value, "    return 2;") == 0;
        caught_include |= strcmp(code_model.items[i].id, "dependencies") == 0 &&
                          strcmp(code_model.items[i].value,
                                 "presentation/model.h") == 0;
    }
    QR_CHECK("code-change diff catches the semantic mutant in exact bytes",
             caught_remove && caught_add);
    QR_CHECK("candidate dependency row comes from exact include bytes",
             caught_include);

    struct json_value development_facts;
    json_init(&development_facts); json_set_object(&development_facts);
    json_push_kv_str(&development_facts, "schema", "zcl.dev_cycle.v1");
    json_push_kv_str(&development_facts, "status", "story_red");
    json_push_kv_str(&development_facts, "phase", "STORY_RED");
    json_push_kv_str(&development_facts, "edit_epoch", root_a);
    json_push_kv_str(&development_facts, "candidate_object_root", root_b);
    json_push_kv_str(&development_facts, "affected_component",
                     "presentation.code_change");
    json_push_kv_str(&development_facts, "feedback_class",
                     "HOT_SHADOW_CORE");
    json_push_kv_str(&development_facts, "failure_capsule",
                     "expected refusal was not observed");
    json_push_kv_str(&development_facts, "agent_next_action",
                     "inspect the candidate decision core");
    json_push_kv_int(&development_facts, "changed_path_count", 1);
    json_push_kv_int(&development_facts, "elapsed_us", 87000);
    json_push_kv_int(&development_facts, "compiler_processes", 1);
    json_push_kv_int(&development_facts, "linker_processes", 1);
    struct zcl_present_model_v1 development_model;
    bool development_built =
        zcl_native_presentation_development_model_from_facts(
            &development_facts, &development_model, why, sizeof(why));
    bool development_red = false, development_unknown = false;
    bool development_next = false;
    for (uint32_t i = 0; development_built &&
                         i < development_model.item_count; i++) {
        const struct zcl_present_model_item_v1 *item =
            &development_model.items[i];
        development_red |= strcmp(item->id, "diagnostic") == 0 &&
            item->status == ZCL_PRESENT_STATUS_RED &&
            strstr(item->value, "expected refusal") != NULL;
        development_unknown |= strcmp(item->id, "unknown") == 0 &&
            strstr(item->value, "Separate signed proof") != NULL;
        development_next |= strcmp(item->id, "next") == 0 &&
            strstr(item->value, "inspect the candidate") != NULL;
    }
    QR_CHECK("canonical reflex RED becomes one exact native consequence",
             development_built &&
             development_model.kind == ZCL_PRESENT_MODEL_PROGRESS &&
             strcmp(development_model.exact_root, root_a) == 0 &&
             development_model.items[3].status == ZCL_PRESENT_STATUS_RED &&
             development_red && development_unknown && development_next);

    json_free(&development_facts);
    json_init(&development_facts); json_set_object(&development_facts);
    json_push_kv_str(&development_facts, "schema", "zcl.dev_cycle.v1");
    json_push_kv_str(&development_facts, "status", "proof_pending");
    json_push_kv_str(&development_facts, "phase", "PROOF_PENDING");
    json_push_kv_str(&development_facts, "edit_epoch", root_a);
    json_push_kv_int(&development_facts, "file_count", 1);
    json_push_kv_str(&development_facts, "agent_next_action",
                     "wait for clean proof");
    development_built =
        zcl_native_presentation_development_model_from_facts(
            &development_facts, &development_model, why, sizeof(why));
    bool pending_is_honest = development_built &&
        development_model.items[1].numerator == 0 &&
        development_model.items[2].numerator == 0 &&
        development_model.items[3].numerator == 0 &&
        development_model.items[4].numerator == 0 &&
        development_model.items[4].status == ZCL_PRESENT_STATUS_INFO &&
        strstr(development_model.items[7].value, "unknown us") != NULL &&
        strstr(development_model.items[7].value,
               "compiler unknown; linker unknown") != NULL;
    QR_CHECK("proof-pending event never invents prior or resource evidence",
             pending_is_honest);
    json_free(&development_facts);

    json_init(&development_facts); json_set_object(&development_facts);
    json_push_kv_str(&development_facts, "schema", "zcl.dev_cycle.v1");
    json_push_kv_str(&development_facts, "status", "passed");
    json_push_kv_str(&development_facts, "phase", "COMPILE_GREEN");
    json_push_kv_str(&development_facts, "edit_epoch", root_a);
    json_push_kv_str(&development_facts, "candidate_object_root", root_a);
    json_push_kv_str(&development_facts, "affected_component", "package");
    json_push_kv_str(&development_facts, "feedback_class",
                     "COMPILE_ONLY_PACKAGE_RECEIPT");
    json_push_kv_str(&development_facts, "receipt_id", root_b);
    json_push_kv_str(&development_facts, "toolchain", "cc 1; build-pass");
    json_push_kv_bool(&development_facts, "candidate_bytes_executed", false);
    json_push_kv_bool(&development_facts, "proof_complete", false);
    development_built =
        zcl_native_presentation_development_model_from_facts(
            &development_facts, &development_model, why, sizeof(why));
    bool compile_only_receipt = development_built &&
        development_model.items[2].status == ZCL_PRESENT_STATUS_GREEN &&
        development_model.items[3].numerator == 0 &&
        development_model.items[4].numerator == 0;
    QR_CHECK("compile-only package receipt never becomes behavioral proof",
             compile_only_receipt);
    json_free(&development_facts);

    QR_CHECK("unchanged candidate bytes cannot masquerade as a code change",
             !zcl_native_presentation_code_change_model_from_facts(
                 code_before, sizeof(code_before) - 1u,
                 code_before, sizeof(code_before) - 1u,
                 "tools/command/native_qr_command.c", "return two",
                 "returned one", "returns two", root_a, root_a, tree_root,
                 &code_model, why, sizeof(why)));

    struct json_value publication_plan, publication_release;
    struct json_value publication_package;
    json_init(&publication_plan); json_set_object(&publication_plan);
    json_push_kv_bool(&publication_plan, "valid", true);
    json_push_kv_bool(&publication_plan, "ready_to_commit", true);
    json_push_kv_str(&publication_plan, "plan_token", root_a);
    json_init(&publication_release); json_set_object(&publication_release);
    json_push_kv_str(&publication_release, "name", "stranger/hello-c23");
    json_push_kv_str(&publication_release, "semver", "1.0.0");
    json_push_kv_str(&publication_release, "license", "Apache-2.0");
    json_push_kv(&publication_plan, "release", &publication_release);
    json_free(&publication_release);
    json_init(&publication_package); json_set_object(&publication_package);
    json_push_kv_str(&publication_package, "package_root", root_b);
    json_push_kv_int(&publication_package, "files", 3);
    json_push_kv_int(&publication_package, "bytes", 4096);
    json_push_kv_int(&publication_package, "chunks", 3);
    json_push_kv_bool(&publication_package, "chunks_checked", true);
    json_push_kv(&publication_plan, "package", &publication_package);
    json_free(&publication_package);
    struct zcl_present_model_v1 publication_model;
    QR_CHECK("canonical package plan builds exact inert confirmation",
             zcl_native_presentation_publication_confirm_model_from_plan(
                 &publication_plan, &publication_model,
                 why, sizeof(why)) &&
             publication_model.kind == ZCL_PRESENT_MODEL_CONFIRMATION &&
             strcmp(publication_model.exact_root, root_a) == 0 &&
             publication_model.item_count == 13 &&
             publication_model.action_count == 2 &&
             publication_model.actions[0].kind ==
                 ZCL_PRESENT_ACTION_CANCEL &&
             publication_model.actions[1].kind ==
                 ZCL_PRESENT_ACTION_CONFIRM);
    QR_CHECK("canonical confirmation focuses the harmless decision first",
             strcmp(publication_model.actions[0].id, "cancel") == 0 &&
             strcmp(publication_model.actions[1].id, "confirm") == 0);
    QR_CHECK("confirmation chrome and effect text are Z23-authored",
             strcmp(publication_model.actions[0].label,
                    "Cancel - make no change") == 0 &&
             strcmp(publication_model.actions[1].label,
                    "Confirm exact local commit") == 0 &&
             strncmp(publication_model.items[0].label,
                     "LOCAL OBSERVATION - ", 20) == 0 &&
             strstr(publication_model.summary, "HUMAN DECISION - ") != NULL);
    QR_CHECK("confirmation names every later publication evidence boundary",
             strcmp(publication_model.items[7].value,
                    "Pending this exact decision") == 0 &&
             strcmp(publication_model.items[8].value,
                    "Not started - separate commit required") == 0 &&
             strcmp(publication_model.items[9].value, "Not observed") == 0 &&
             strcmp(publication_model.items[10].value, "Not observed") == 0 &&
             strcmp(publication_model.items[11].value, "Not observed") == 0 &&
             strcmp(publication_model.items[12].value, "Not observed") == 0);
    json_free(&publication_plan);
    json_init(&publication_plan); json_set_object(&publication_plan);
    QR_CHECK("agent facts alone cannot fabricate a ready confirmation",
             !zcl_native_presentation_publication_confirm_model_from_plan(
                 &publication_plan, &publication_model,
                 why, sizeof(why)));
    json_free(&publication_plan);

    struct json_value release_status, release_expert, release_evidence;
    json_init(&release_status); json_set_object(&release_status);
    json_push_kv_str(&release_status, "state", "EVIDENCE_READY");
    json_push_kv_str(&release_status, "goal",
                     "Reject an empty note before hashing");
    json_init(&release_expert); json_set_object(&release_expert);
    json_push_kv_str(&release_expert, "task_root", root_a);
    json_push_kv_str(&release_expert, "candidate_root", root_b);
    json_push_kv_str(&release_expert, "proof_policy_root", tree_root);
    json_push_kv_str(&release_status, "work_id", "work-aaaaaaaaaaaa");
    json_push_kv(&release_status, "expert", &release_expert);
    json_free(&release_expert);
    json_init(&release_evidence); json_set_object(&release_evidence);
    json_push_kv_str(&release_evidence, "proof_set_root", root_a);
    json_push_kv_str(&release_evidence, "authority",
                     "LOCAL_CLEAN_SHADOW");
    json_push_kv_int(&release_evidence, "compile_receipts", 2);
    json_push_kv_int(&release_evidence, "test_receipts", 2);
    json_push_kv_int(&release_evidence, "approved_distinct_signers", 2);
    json_push_kv_bool(&release_evidence, "local_reproduced", true);
    json_push_kv_bool(&release_evidence, "quorum_satisfied", true);
    json_push_kv_bool(&release_evidence, "compile_satisfied", true);
    json_push_kv_bool(&release_evidence, "test_satisfied", true);
    json_push_kv_bool(&release_evidence, "policy_satisfied", true);
    struct zcl_present_model_v1 release_model;
    char release_identity[65], changed_release_identity[65];
    QR_CHECK("proven candidate facts build one exact inert release decision",
             zcl_native_presentation_release_confirm_model_from_facts(
                 &release_status, &release_evidence, &release_model,
                 release_identity, why, sizeof(why)) &&
             release_model.kind == ZCL_PRESENT_MODEL_CONFIRMATION &&
             strcmp(release_model.exact_root, release_identity) == 0 &&
             release_model.action_count == 2 &&
             release_model.actions[0].kind == ZCL_PRESENT_ACTION_CANCEL &&
             release_model.actions[1].kind == ZCL_PRESENT_ACTION_CONFIRM &&
             strstr(release_model.items[0].value,
                    "source and network stay unchanged") != NULL);
    struct json_value *candidate_value = (struct json_value *)json_get(
        json_get(&release_status, "expert"), "candidate_root");
    json_set_str(candidate_value, tree_root);
    QR_CHECK("changed candidate bytes change the human decision identity",
             zcl_native_presentation_release_confirm_model_from_facts(
                 &release_status, &release_evidence, &release_model,
                 changed_release_identity, why, sizeof(why)) &&
             strcmp(release_identity, changed_release_identity) != 0);
    json_set_str(candidate_value, root_b);
    json_set_bool((struct json_value *)json_get(
                      &release_evidence, "policy_satisfied"), false);
    QR_CHECK("incomplete proof policy cannot fabricate release confirmation",
             !zcl_native_presentation_release_confirm_model_from_facts(
                 &release_status, &release_evidence, &release_model,
                 release_identity, why, sizeof(why)));
    json_free(&release_evidence);
    json_free(&release_status);

    struct json_value publication_facts;
    struct zcl_present_model_v1 publication_status;
    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_a, true, false, false, false, 0);
    QR_CHECK("local commit alone cannot fabricate network publication",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.item_count == 6 &&
             publication_status.items[0].numerator == 0 &&
             publication_status.items[1].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[2].status == ZCL_PRESENT_STATUS_NEUTRAL &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_NEUTRAL &&
             strcmp(publication_status.request_id,
                    "publish-aaaaaaaaaaaa") == 0);
    json_free(&publication_facts);

    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_a, true, true, false, false, 0);
    QR_CHECK("signed pointer advances only its exact evidence stage",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[2].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[3].status == ZCL_PRESENT_STATUS_NEUTRAL &&
             publication_status.items[4].status == ZCL_PRESENT_STATUS_NEUTRAL);
    json_free(&publication_facts);

    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_a, true, true, true, true, 4096);
    QR_CHECK("self-published records cannot masquerade as peer discovery",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[2].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[3].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[4].status == ZCL_PRESENT_STATUS_NEUTRAL &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_NEUTRAL);
    json_free(&publication_facts);

    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_b, true, true, true, false, 0);
    QR_CHECK("matching non-self signed records prove peer discovery only",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[4].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_NEUTRAL);
    json_free(&publication_facts);

    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_b, true, true, true, true, 4096);
    QR_CHECK("exact imported peer bytes complete only the final stage",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[5].numerator == 1 &&
             publication_status.items[0].numerator == 0);
    json_free(&publication_facts);

    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_b, true, true, true, true, 0);
    QR_CHECK("CAS completion without received peer bytes is not a peer fetch",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[4].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_NEUTRAL);
    json_free(&publication_facts);

    struct json_value reproduction_facts;
    qr_reproduction_facts(&reproduction_facts, root_a, tree_root, root_b,
                          "", "RUNNING");
    struct zcl_present_model_v1 reproduction_model;
    QR_CHECK("canonical running event builds six fixed progress stages",
             zcl_native_presentation_reproduction_model_from_facts(
                 &reproduction_facts, &reproduction_model,
                 why, sizeof(why)) &&
             reproduction_model.kind == ZCL_PRESENT_MODEL_PROGRESS &&
             reproduction_model.item_count == 6 &&
             reproduction_model.items[2].numerator == 1 &&
             reproduction_model.items[3].numerator == 0);
    char running_request_id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
    (void)snprintf(running_request_id, sizeof(running_request_id), "%s",
                   reproduction_model.request_id);
    json_free(&reproduction_facts);
    qr_reproduction_facts(&reproduction_facts, root_a, tree_root, root_b,
                          root_b, "REPRODUCED");
    QR_CHECK("matching evidence updates the same action-bound window",
             zcl_native_presentation_reproduction_model_from_facts(
                 &reproduction_facts, &reproduction_model,
                 why, sizeof(why)) &&
             strcmp(reproduction_model.request_id, running_request_id) == 0 &&
             reproduction_model.items[5].numerator == 1 &&
             reproduction_model.items[5].status == ZCL_PRESENT_STATUS_GREEN);
    json_free(&reproduction_facts);
    qr_reproduction_facts(&reproduction_facts, root_a, tree_root, root_b,
                          root_b, "REMOTE_RED");
    QR_CHECK("remote mismatch stays a named red output refusal",
             zcl_native_presentation_reproduction_model_from_facts(
                 &reproduction_facts, &reproduction_model,
                 why, sizeof(why)) &&
             reproduction_model.items[3].status == ZCL_PRESENT_STATUS_RED &&
             strstr(reproduction_model.summary, "named refusal") != NULL);
    json_free(&reproduction_facts);

    struct json_value work_dump;
    json_init(&work_dump);
    vcs_zcode_work_node_set_global(NULL);
    QR_CHECK("package-worker diagnostic reports exact disabled capacity",
             vcs_zcode_work_node_dump_state_json(&work_dump, NULL) &&
             !json_get_bool(json_get(&work_dump, "enabled")) &&
             json_get_int(json_get(&work_dump, "worker_capacity")) == 0 &&
             json_get_int(json_get(&work_dump, "worker_available")) == 0 &&
             json_get_int(json_get(&work_dump, "capable_peers")) == 0 &&
             strstr(json_get_str(json_get(&work_dump, "next_action")),
                    "z23 join") != NULL &&
             strstr(json_get_str(json_get(&work_dump, "next_action")),
                    "-buildworker=1") == NULL);
    json_free(&work_dump);

    struct zcl_present_model_bitmap_v1 visual_bitmap;
    QR_CHECK("renderer-neutral progress card becomes native RGB pixels",
             zcl_present_model_render_v1(
                 &visual, &visual_bitmap, why, sizeof(why)) &&
             visual_bitmap.pixels &&
             visual_bitmap.width == ZCL_PRESENT_MODEL_BITMAP_WIDTH &&
             visual_bitmap.height == ZCL_PRESENT_MODEL_BITMAP_HEIGHT);
    bool visual_has_orange = false;
    bool visual_has_info = false;
    for (size_t i = 0; visual_bitmap.pixels &&
         i < ZCL_PRESENT_MODEL_BITMAP_BYTES; i += 3u) {
        visual_has_orange |= visual_bitmap.pixels[i] == 0xc8 &&
            visual_bitmap.pixels[i + 1u] == 0x70 &&
            visual_bitmap.pixels[i + 2u] == 0x35;
        visual_has_info |= visual_bitmap.pixels[i] == 0x32 &&
            visual_bitmap.pixels[i + 1u] == 0x68 &&
            visual_bitmap.pixels[i + 2u] == 0x91;
    }
    QR_CHECK("native model pixels preserve brand and semantic status",
             visual_has_orange && visual_has_info);
    zcl_present_model_bitmap_free_v1(&visual_bitmap);

    struct zcl_present_model_v1 long_table;
    zcl_present_model_init_v1(&long_table, ZCL_PRESENT_MODEL_TABLE);
    (void)snprintf(long_table.request_id, sizeof(long_table.request_id),
                   "bounded-table-64");
    (void)snprintf(long_table.title, sizeof(long_table.title),
                   "Every bounded row is reachable");
    long_table.item_count = ZCL_PRESENT_MODEL_ITEMS_MAX;
    for (uint32_t i = 0; i < long_table.item_count; i++) {
        long_table.items[i].kind = ZCL_PRESENT_ITEM_TABLE_ROW;
        long_table.items[i].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        (void)snprintf(long_table.items[i].id,
                       sizeof(long_table.items[i].id), "row-%u", i + 1u);
        (void)snprintf(long_table.items[i].label,
                       sizeof(long_table.items[i].label), "Owner %u", i + 1u);
        (void)snprintf(long_table.items[i].value,
                       sizeof(long_table.items[i].value), "Exact value %u",
                       i + 1u);
    }
    uint32_t table_pages = 0;
    QR_CHECK("maximum bounded table partitions into eight exact pages",
             zcl_present_model_page_count_v1(
                 &long_table, &table_pages, why, sizeof(why)) &&
             table_pages == 8u);
    struct ui_present_document table_document;
    QR_CHECK("resident and cold hosts receive the same complete page set",
             ui_present_document_from_model(
                 &long_table, &table_document, why, sizeof(why)) &&
             table_document.page_count == table_pages &&
             table_document.windows[0].pixels ==
                 table_document.bitmaps[0].pixels &&
             table_document.windows[table_pages - 1u].pixels ==
                 table_document.bitmaps[table_pages - 1u].pixels &&
             memcmp(table_document.windows[0].pixels,
                    table_document.windows[table_pages - 1u].pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    ui_present_document_free(&table_document);
    char table_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t table_text_len = 0;
    uint32_t table_text_pages = 0;
    QR_CHECK("maximum table text export is bounded and fully paged",
             zcl_present_model_text_page_v1(
                 &long_table, 63u, table_text, sizeof(table_text),
                 &table_text_len, &table_text_pages, why, sizeof(why)) &&
             table_text_pages == 64u &&
             table_text_len < sizeof(table_text) &&
             strstr(table_text, "id: row-64") != NULL &&
             !zcl_present_model_text_page_v1(
                 &long_table, table_text_pages, table_text,
                 sizeof(table_text), &table_text_len, &table_text_pages,
                 why, sizeof(why)));
    QR_CHECK("oversized complete text export refuses instead of truncating",
             !zcl_present_model_text_all_v1(
                 &long_table, table_text, sizeof(table_text),
                 &table_text_len, why, sizeof(why)) &&
             strstr(why, "exceeds its byte bound") != NULL);
    struct zcl_present_model_bitmap_v1 first_page, last_page;
    bool first_page_ok = zcl_present_model_render_page_v1(
        &long_table, 0, &first_page, why, sizeof(why));
    bool last_page_ok = zcl_present_model_render_page_v1(
        &long_table, table_pages - 1u, &last_page, why, sizeof(why));
    QR_CHECK("first and last bounded table pages render distinct pixels",
             first_page_ok && last_page_ok &&
             memcmp(first_page.pixels, last_page.pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    QR_CHECK("page past the exact model bound fails closed",
             !zcl_present_model_render_page_v1(
                 &long_table, table_pages, &visual_bitmap,
                 why, sizeof(why)));
    zcl_present_model_bitmap_free_v1(&first_page);
    zcl_present_model_bitmap_free_v1(&last_page);
    uint32_t next_page = UINT32_MAX;
    QR_CHECK("keyboard page movement advances and clamps deterministically",
             zcl_present_window_page_step_v1(
                 0, table_pages, 1, &next_page) && next_page == 1u &&
             zcl_present_window_page_step_v1(
                 table_pages - 1u, table_pages, 1, &next_page) &&
             next_page == table_pages - 1u &&
             zcl_present_window_page_step_v1(
                 0, table_pages, -1, &next_page) && next_page == 0u);
    uint32_t next_action = UINT32_MAX;
    QR_CHECK("keyboard action focus wraps without selecting authority",
             zcl_present_window_action_focus_step_v1(
                 0, 2, 1, &next_action) && next_action == 1u &&
             zcl_present_window_action_focus_step_v1(
                 1, 2, 1, &next_action) && next_action == 0u &&
             zcl_present_window_action_focus_step_v1(
                 0, 2, -1, &next_action) && next_action == 1u &&
             !zcl_present_window_action_focus_step_v1(
                 0, 0, 1, &next_action));

    static const char model_json[] =
        "{\"kind\":\"code-diff\",\"request_id\":\"diff-1\","
        "\"title\":\"Exact candidate diff\","
        "\"summary\":\"One candidate-owned line changed.\","
        "\"items\":[{\"kind\":\"diff-remove\",\"value\":\"return 0;\"},"
        "{\"kind\":\"diff-add\",\"status\":\"green\","
        "\"value\":\"return verified;\"}]}";
    struct json_value visual_json;
    json_init(&visual_json);
    QR_CHECK("typed native visual JSON parses",
             json_read(&visual_json, model_json, sizeof(model_json) - 1u));
    struct zcl_present_model_v1 json_model;
    bool visual_json_ok = ui_present_model_from_json(
        &visual_json, &json_model, why, sizeof(why));
    if (!visual_json_ok) printf("  visual JSON diagnostic: %s\n", why);
    QR_CHECK("closed visual JSON becomes the renderer-neutral model",
             visual_json_ok &&
             json_model.kind == ZCL_PRESENT_MODEL_CODE_DIFF &&
             json_model.item_count == 2 &&
             json_model.items[1].kind == ZCL_PRESENT_ITEM_DIFF_ADD);
    json_free(&visual_json);

    static const char chart_json[] =
        "{\"kind\":\"chart\",\"request_id\":\"coverage-chart\","
        "\"title\":\"Exact candidate coverage\",\"output\":\"text\","
        "\"items\":[{\"kind\":\"chart-point\",\"status\":\"green\","
        "\"id\":\"candidate\",\"label\":\"Candidate\",\"value\":\"81%\","
        "\"numerator\":81,\"denominator\":100}]}";
    struct json_value chart_input;
    json_init(&chart_input);
    QR_CHECK("typed chart request parses as one bounded model",
             json_read(&chart_input, chart_json,
                       sizeof(chart_json) - 1u));
    struct zcl_command_request chart_request = {.input = &chart_input};
    struct zcl_command_reply chart_reply;
    zcl_command_reply_init(&chart_reply, "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&chart_request, &chart_reply);
    const char *typed_chart_text =
        json_get_str(json_get(&chart_reply.data, "plain_text"));
    QR_CHECK("agent chart command exports the exact plotted fraction",
             chart_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_chart_text &&
             strstr(typed_chart_text, "kind: chart") != NULL &&
             strstr(typed_chart_text, "chart-point: 81/100") != NULL &&
             strcmp(json_get_str(json_get(&chart_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&chart_reply);
    json_free(&chart_input);

    static const char timeline_json[] =
        "{\"kind\":\"timeline\",\"request_id\":\"proof-timeline\","
        "\"title\":\"Exact proof sequence\",\"output\":\"text\","
        "\"items\":[{\"kind\":\"timeline-event\",\"status\":\"green\","
        "\"id\":\"receipt\",\"label\":\"Receipt verified\","
        "\"value\":\"independent signer\"}]}";
    struct json_value timeline_input;
    json_init(&timeline_input);
    QR_CHECK("typed timeline request parses as one bounded model",
             json_read(&timeline_input, timeline_json,
                       sizeof(timeline_json) - 1u));
    struct zcl_command_request timeline_request = {.input = &timeline_input};
    struct zcl_command_reply timeline_reply;
    zcl_command_reply_init(&timeline_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&timeline_request, &timeline_reply);
    const char *typed_timeline_text =
        json_get_str(json_get(&timeline_reply.data, "plain_text"));
    QR_CHECK("agent timeline command preserves the exact event companion",
             timeline_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_timeline_text &&
             strstr(typed_timeline_text, "kind: timeline") != NULL &&
             strstr(typed_timeline_text, "timeline-event [green]") != NULL &&
             strstr(typed_timeline_text,
                    "value: independent signer") != NULL &&
             strcmp(json_get_str(json_get(&timeline_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&timeline_reply);
    json_free(&timeline_input);

    static const char graph_json[] =
        "{\"kind\":\"evidence-graph\",\"request_id\":\"evidence-graph\","
        "\"title\":\"Candidate evidence\",\"output\":\"text\","
        "\"items\":[{\"kind\":\"graph-node\",\"status\":\"info\","
        "\"id\":\"candidate\",\"label\":\"Candidate root\","
        "\"value\":\"exact source\"},{\"kind\":\"graph-node\","
        "\"status\":\"green\",\"id\":\"receipt\","
        "\"label\":\"Verified receipt\",\"value\":\"independent signer\","
        "\"parent_index\":0}]}";
    struct json_value graph_input;
    json_init(&graph_input);
    QR_CHECK("typed evidence graph parses as one bounded parent chain",
             json_read(&graph_input, graph_json,
                       sizeof(graph_json) - 1u));
    struct zcl_command_request graph_request = {.input = &graph_input};
    struct zcl_command_reply graph_reply;
    zcl_command_reply_init(&graph_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&graph_request, &graph_reply);
    const char *typed_graph_text =
        json_get_str(json_get(&graph_reply.data, "plain_text"));
    QR_CHECK("agent evidence graph exports the exact parent relationship",
             graph_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_graph_text &&
             strstr(typed_graph_text, "kind: evidence-graph") != NULL &&
             strstr(typed_graph_text, "parent-item: 1") != NULL &&
             strcmp(json_get_str(json_get(&graph_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&graph_reply);
    json_free(&graph_input);

    static const char choice_json[] =
        "{\"kind\":\"choice\",\"request_id\":\"proof-choice\","
        "\"title\":\"Choose the next proof\",\"output\":\"text\","
        "\"items\":[{\"kind\":\"choice\",\"status\":\"info\","
        "\"id\":\"focused\",\"label\":\"Focused story\","
        "\"value\":\"fast exact evidence\",\"selected\":true},"
        "{\"kind\":\"choice\",\"status\":\"neutral\","
        "\"id\":\"broad\",\"label\":\"Broader suite\","
        "\"value\":\"slower coverage\"}],\"actions\":["
        "{\"kind\":\"select\",\"id\":\"focused\","
        "\"label\":\"Focused story\"},{\"kind\":\"select\","
        "\"id\":\"broad\",\"label\":\"Broader suite\"}]}";
    struct json_value choice_input;
    json_init(&choice_input);
    QR_CHECK("typed choice parses only matching bounded action IDs",
             json_read(&choice_input, choice_json,
                       sizeof(choice_json) - 1u));
    struct zcl_command_request choice_request = {.input = &choice_input};
    struct zcl_command_reply choice_reply;
    zcl_command_reply_init(&choice_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&choice_request, &choice_reply);
    const char *typed_choice_text =
        json_get_str(json_get(&choice_reply.data, "plain_text"));
    QR_CHECK("agent choice exports the exact display/action mapping",
             choice_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_choice_text &&
             strstr(typed_choice_text, "kind: choice") != NULL &&
             strstr(typed_choice_text, "flags: selected") != NULL &&
             strstr(typed_choice_text, "action 2: select") != NULL &&
             strcmp(json_get_str(json_get(&choice_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&choice_reply);
    json_free(&choice_input);

    static const char form_json[] =
        "{\"kind\":\"form\",\"request_id\":\"release-form\","
        "\"title\":\"Describe exact release\",\"output\":\"text\","
        "\"exact_root\":"
        "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\","
        "\"items\":[{\"kind\":\"form-field\",\"id\":\"release-note\","
        "\"label\":\"Release note\",\"value\":\"\",\"required\":true},"
        "{\"kind\":\"form-field\",\"id\":\"candidate-root\","
        "\"label\":\"Candidate root\",\"value\":\"immutable-root\","
        "\"read_only\":true}],\"actions\":["
        "{\"kind\":\"cancel\",\"id\":\"cancel\",\"label\":\"Cancel\"},"
        "{\"kind\":\"submit\",\"id\":\"submit-release-note\","
        "\"label\":\"Submit\"}]}";
    struct json_value form_input;
    json_init(&form_input);
    QR_CHECK("typed form parses as one exact bounded edit contract",
             json_read(&form_input, form_json, sizeof(form_json) - 1u));
    struct zcl_command_request form_request = {.input = &form_input};
    struct zcl_command_reply form_reply;
    zcl_command_reply_init(&form_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&form_request, &form_reply);
    const char *typed_form_text =
        json_get_str(json_get(&form_reply.data, "plain_text"));
    QR_CHECK("agent form text exposes the same fields and safe actions",
             form_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_form_text &&
             strstr(typed_form_text, "kind: form") != NULL &&
             strstr(typed_form_text, "id: release-note") != NULL &&
             strstr(typed_form_text, "flags: required") != NULL &&
             strstr(typed_form_text, "flags: read-only") != NULL &&
             strstr(typed_form_text, "action 1: cancel") != NULL &&
             strstr(typed_form_text, "action 2: submit") != NULL &&
             strcmp(json_get_str(json_get(&form_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&form_reply);
    json_free(&form_input);

    static const char canvas_json[] =
        "{\"kind\":\"canvas\",\"request_id\":\"placement-canvas\","
        "\"title\":\"Place exact label\",\"output\":\"text\","
        "\"exact_root\":"
        "\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\","
        "\"items\":[{\"kind\":\"canvas-point\","
        "\"id\":\"label-origin\",\"label\":\"Label origin\","
        "\"numerator\":250,\"denominator\":300,\"selected\":true},"
        "{\"kind\":\"canvas-point\",\"status\":\"info\","
        "\"id\":\"fixed-anchor\",\"label\":\"Fixed anchor\","
        "\"numerator\":800,\"denominator\":700,"
        "\"read_only\":true}],\"actions\":["
        "{\"kind\":\"cancel\",\"id\":\"cancel\",\"label\":\"Cancel\"},"
        "{\"kind\":\"submit\",\"id\":\"submit-placement\","
        "\"label\":\"Submit\"}]}";
    struct json_value canvas_input;
    json_init(&canvas_input);
    QR_CHECK("typed canvas parses as one exact bounded point contract",
             json_read(&canvas_input, canvas_json,
                       sizeof(canvas_json) - 1u));
    struct zcl_command_request canvas_request = {.input = &canvas_input};
    struct zcl_command_reply canvas_reply;
    zcl_command_reply_init(&canvas_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&canvas_request, &canvas_reply);
    const char *typed_canvas_text =
        json_get_str(json_get(&canvas_reply.data, "plain_text"));
    QR_CHECK("agent canvas text preserves exact point and safe actions",
             canvas_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_canvas_text &&
             strstr(typed_canvas_text, "kind: canvas") != NULL &&
             strstr(typed_canvas_text,
                    "canvas-point-x-y: 250/300") != NULL &&
             strstr(typed_canvas_text, "flags: read-only") != NULL &&
             strstr(typed_canvas_text, "action 1: cancel") != NULL &&
             strstr(typed_canvas_text, "action 2: submit") != NULL &&
             strcmp(json_get_str(json_get(&canvas_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&canvas_reply);
    json_free(&canvas_input);

    struct json_value text_delivery;
    json_init(&text_delivery);
    json_set_object(&text_delivery);
    json_push_kv_str(&text_delivery, "output", "text");
    struct zcl_command_reply text_reply;
    zcl_command_reply_init(&text_reply, "zcl.app_presentation_show.v1");
    zcl_native_present_model(&json_model, "app.presentation.show",
                             &text_delivery, &text_reply);
    QR_CHECK("shared presentation response proves no privileged action",
             text_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&text_reply.data, "text_complete")) &&
             json_get_int(json_get(&text_reply.data,
                                   "text_page_count")) == 1 &&
             strstr(json_get_str(json_get(&text_reply.data, "plain_text")),
                    "value: return 0;") != NULL &&
             strstr(json_get_str(json_get(&text_reply.data, "plain_text")),
                    "value: return verified;") != NULL &&
             strcmp(json_get_str(json_get(&text_reply.data, "authority")),
                    "display-only") == 0 &&
             !json_get_bool(json_get(&text_reply.data,
                                     "privileged_action_performed")));
    zcl_command_reply_free(&text_reply);

    zcl_command_reply_init(&text_reply, "zcl.app_presentation_show.v1");
    zcl_native_present_model(&long_table, "app.presentation.show",
                             &text_delivery, &text_reply);
    QR_CHECK("oversized shared text response falls back to exact paging",
             text_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             !json_get_bool(json_get(&text_reply.data, "text_complete")) &&
             json_get_int(json_get(&text_reply.data,
                                   "text_page_count")) == 64 &&
             strstr(json_get_str(json_get(&text_reply.data, "plain_text")),
                    "id: row-1") != NULL &&
             strstr(json_get_str(json_get(&text_reply.data, "plain_text")),
                    "id: row-2") == NULL);
    zcl_command_reply_free(&text_reply);
    json_free(&text_delivery);

    static const char smuggled_json[] =
        "{\"kind\":\"status\",\"request_id\":\"bad-1\","
        "\"title\":\"Bad\",\"items\":[{\"kind\":\"text\","
        "\"value\":\"x\",\"command\":\"/bin/sh\"}]}";
    json_init(&visual_json);
    QR_CHECK("unknown visual item key fixture parses as JSON",
             json_read(&visual_json, smuggled_json,
                       sizeof(smuggled_json) - 1u));
    QR_CHECK("visual model rejects command smuggling",
             !ui_present_model_from_json(&visual_json, &json_model,
                                         why, sizeof(why)));
    json_free(&visual_json);

    qr_matrix_free(&second);
    qr_matrix_free(&first);
    printf("=== qr: %d failure(s) ===\n", qr_failures);
    return qr_failures;
}
