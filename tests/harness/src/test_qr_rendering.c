/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * qr scenario checks: canvas/chart primitives, QR chunking and text
 * companion pages, and the progress/chart/timeline/evidence/choice/form
 * presentation data models.
 *
 * Split out of test_qr.c (which keeps the includes and the group entry
 * point) so no family member crosses the 1,500-line ceiling. Every
 * scenario grades itself through QR_CHECK, shared via qr_failures_ptr()
 * — see test_qr_priv.h. */

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
#include "test/test_qr_priv.h"


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


static bool qr_clipboard_bmp_header_is_2x2_24bpp(const uint8_t *bmp)
{
    return bmp[0] == 'B' && bmp[1] == 'M' &&
           bmp[18] == 2u && bmp[22] == 2u && bmp[28] == 24u;
}

static bool qr_clipboard_bmp_bgr_row_order(const uint8_t *bmp)
{
    return bmp[54] == 0x00u && bmp[55] == 0x00u && bmp[56] == 0x00u &&
           bmp[57] == 0xffu && bmp[58] == 0xffu && bmp[59] == 0xffu &&
           bmp[62] == 0xffu && bmp[63] == 0xffu && bmp[64] == 0xffu &&
           bmp[65] == 0x00u && bmp[66] == 0x00u && bmp[67] == 0x00u;
}

bool qr_case_payment_uri_encode_and_finders(void)
{
    char why[128];
    struct qr_matrix first;
    struct qr_matrix second;
    bool encoded = qr_matrix_encode(
        "zclassic:t1QRNativeC23?amount=0.01000000", &first,
        why, sizeof(why));
    QR_CHECK("payment URI encodes", encoded);
    if (!encoded) return false;
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
    qr_matrix_free(&second);
    qr_matrix_free(&first);
    return true;
}

void qr_case_zclassic_window_icon(void)
{
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
}

void qr_case_canvas_primitives(void)
{
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
    const struct zcl_present_color canvas_black = {0, 0, 0};
    zcl_present_canvas_clear(&canvas, canvas_black);
    zcl_present_canvas_fill_rect_alpha(
        &canvas, 0, 0, 1u, 1u, canvas_white, 128u);
    QR_CHECK("canvas alpha blend is exact in every RGB channel",
             canvas_pixels[0] == 128u && canvas_pixels[1] == 128u &&
             canvas_pixels[2] == 128u);
    zcl_present_canvas_fill_vertical_gradient(
        &canvas, 2, 0, 2u, 3u, canvas_white, canvas_orange);
    size_t gradient_top = 2u * 3u;
    size_t gradient_bottom = ((size_t)2u * 32u + 2u) * 3u;
    QR_CHECK("canvas vertical gradient preserves exact endpoint colors",
             canvas_pixels[gradient_top] == 0xff &&
             canvas_pixels[gradient_top + 1u] == 0xff &&
             canvas_pixels[gradient_top + 2u] == 0xff &&
             canvas_pixels[gradient_bottom] == 0xc8 &&
             canvas_pixels[gradient_bottom + 1u] == 0x70 &&
             canvas_pixels[gradient_bottom + 2u] == 0x35);
    zcl_present_canvas_line_thick(
        &canvas, 4, 20, 12, 20, 3u, canvas_orange);
    zcl_present_canvas_fill_circle(&canvas, 20, 20, 3u, canvas_orange);
    QR_CHECK("canvas thick paths and circles stay exact and bounded",
             canvas_pixels[((size_t)19u * 32u + 8u) * 3u] == 0xc8 &&
             canvas_pixels[((size_t)20u * 32u + 20u) * 3u] == 0xc8 &&
             canvas_pixels[((size_t)16u * 32u + 20u) * 3u] == 0);
}

void qr_case_chart_scale_maximum(void)
{
    QR_CHECK("chart scale chooses readable overflow-safe decimal intervals",
             zcl_present_canvas_chart_scale_maximum(0u) == 1u &&
             zcl_present_canvas_chart_scale_maximum(1123394u) == 1200000u &&
             zcl_present_canvas_chart_scale_maximum(100u) == 120u &&
             zcl_present_canvas_chart_scale_maximum(UINT64_MAX) ==
                 UINT64_MAX);
}

void qr_case_canvas_text_metrics(void)
{
    uint8_t canvas_pixels[32u * 32u * 3u];
    struct zcl_present_canvas canvas;
    const struct zcl_present_color canvas_white = {0xff, 0xff, 0xff};
    const struct zcl_present_color canvas_orange = {0xc8, 0x70, 0x35};
    (void)zcl_present_canvas_init(&canvas, canvas_pixels,
                                  sizeof(canvas_pixels), 32u, 32u);
    zcl_present_canvas_clear(&canvas, canvas_white);
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
    uint32_t strong_width =
        zcl_present_canvas_text_width_strong("balance", 7u, 16u);
    QR_CHECK("embedded Inter SemiBold metrics are deterministic",
             strong_width > 40u && strong_width < 80u &&
             strong_width == zcl_present_canvas_text_width_strong(
                 "balance", 7u, 16u));
    uint8_t strong_pixels[32u * 32u * 3u];
    struct zcl_present_canvas strong_canvas;
    bool strong_canvas_ok = zcl_present_canvas_init(
        &strong_canvas, strong_pixels, sizeof(strong_pixels), 32u, 32u);
    if (strong_canvas_ok) {
        zcl_present_canvas_clear(&strong_canvas, canvas_white);
        zcl_present_canvas_text_strong(
            &strong_canvas, 8, 8, "Aa", 2u, 16u, canvas_orange);
    }
    QR_CHECK("Inter Medium and SemiBold render distinct exact pixels",
             strong_canvas_ok &&
             memcmp(canvas_pixels, strong_pixels,
                    sizeof(canvas_pixels)) != 0);
}

void qr_case_deposit_card(void)
{
    char why[128];
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
}

void qr_case_generic_qr_compositor(void)
{
    char why[128];
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
}

void qr_case_presentation_clipboard_bmp(void)
{
    char why[128];
    uint8_t icon[ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES];
    (void)zcl_present_zclassic_icon_rgba(icon, sizeof(icon));
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
    size_t bmp_size = 0;
    uint8_t bmp[70] = {0};
    QR_CHECK("native clipboard BMP size is exact without allocation",
             zcl_present_bitmap_encode_bmp_v1(
                 &present, NULL, 0u, &bmp_size) && bmp_size == sizeof(bmp));
    QR_CHECK("native clipboard BMP preserves dimensions and BGR row order",
             zcl_present_bitmap_encode_bmp_v1(
                 &present, bmp, sizeof(bmp), &bmp_size) &&
             qr_clipboard_bmp_header_is_2x2_24bpp(bmp) &&
             qr_clipboard_bmp_bgr_row_order(bmp));
    QR_CHECK("native clipboard BMP refuses a short destination",
             !zcl_present_bitmap_encode_bmp_v1(
                 &present, bmp, sizeof(bmp) - 1u, &bmp_size) &&
             bmp_size == sizeof(bmp));
    present.abi_version++;
    QR_CHECK("presentation ABI mismatch fails closed",
             !zcl_present_window_validate_v1(&present, why, sizeof(why)));
}

void qr_case_confirmation_action_clicks(void)
{
    char why[128];
    uint8_t icon[ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES];
    (void)zcl_present_zclassic_icon_rgba(icon, sizeof(icon));
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
}

void qr_case_chart_hover(void)
{
    static const struct zcl_present_window_hover_item_v1 hover_items[] = {
        {.x = 100u, .text = "2026-08-30\n100 lines"},
        {.x = 300u, .text = "2026-08-31\n200 lines"},
        {.x = 500u, .text = "2026-09-01\n300 lines"},
    };
    const struct zcl_present_window_hover_v1 hover = {
        .struct_size = sizeof(hover),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .plot_left = 80u,
        .plot_top = 100u,
        .plot_right = 520u,
        .plot_bottom = 600u,
        .items = hover_items,
        .item_count = 3u,
    };
    uint32_t hover_index = UINT32_MAX;
    QR_CHECK("native chart hover selects the nearest exact day",
             zcl_present_window_hover_at_v1(
                 &hover, 720, 720, 720, 720, 340, 300,
                 &hover_index) && hover_index == 1u);
    QR_CHECK("resized chart hover preserves aspect-fit selection",
             zcl_present_window_hover_at_v1(
                 &hover, 720, 720, 1440, 1440, 980, 600,
                 &hover_index) && hover_index == 2u);
    QR_CHECK("chart hover refuses plot-exterior and letterbox positions",
             !zcl_present_window_hover_at_v1(
                 &hover, 720, 720, 720, 720, 40, 300,
                 &hover_index) &&
             !zcl_present_window_hover_at_v1(
                 &hover, 720, 720, 1000, 720, 100, 300,
                 &hover_index));
}

void qr_case_image_copy_control(void)
{
    const struct zcl_present_window_copy_v1 copy = {
        .struct_size = sizeof(copy),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .left = 500u,
        .top = 620u,
        .right = 700u,
        .bottom = 680u,
    };
    QR_CHECK("native image-copy control preserves resized hit geometry",
             zcl_present_window_copy_at_v1(
                 &copy, 720, 720, 720, 720, 600, 650) &&
             zcl_present_window_copy_at_v1(
                 &copy, 720, 720, 1440, 1440, 1200, 1300));
    QR_CHECK("native image-copy control rejects edges and letterboxing",
             !zcl_present_window_copy_at_v1(
                 &copy, 720, 720, 720, 720, 700, 650) &&
             !zcl_present_window_copy_at_v1(
                 &copy, 720, 720, 1000, 720, 120, 650));
}

void qr_case_chart_keys(void)
{
    uint32_t hover_index = UINT32_MAX;
    QR_CHECK("chart keys step and clamp exact day selection",
             zcl_present_window_hover_step_v1(
                 1u, 3u, -7, &hover_index) && hover_index == 0u &&
             zcl_present_window_hover_step_v1(
                 hover_index, 3u, 7, &hover_index) && hover_index == 2u &&
             zcl_present_window_hover_step_v1(
                 hover_index, 3u, 1, &hover_index) && hover_index == 2u);
    int32_t render_delta = 0;
    QR_CHECK("chart text-size keys map to bounded rendering steps",
             zcl_present_window_hover_render_delta_v1(
                 '+', &render_delta) && render_delta == 1 &&
             zcl_present_window_hover_render_delta_v1(
                 '=', &render_delta) && render_delta == 1 &&
             zcl_present_window_hover_render_delta_v1(
                 '-', &render_delta) && render_delta == -1 &&
             !zcl_present_window_hover_render_delta_v1(
                 'x', &render_delta));
}

void qr_case_chart_axis_cadence(void)
{
    QR_CHECK("chart axis cadence prefers weekly labels when they fit",
             zcl_present_canvas_axis_label_stride_v1(
                 85u, 944u, 40u, 12u) == 7u &&
             zcl_present_canvas_axis_label_stride_v1(
                 1u, 944u, 40u, 12u) == 7u);
    QR_CHECK("chart axis cadence widens before weekly labels collide",
             zcl_present_canvas_axis_label_stride_v1(
                 200u, 944u, 40u, 12u) == 14u &&
             zcl_present_canvas_axis_label_stride_v1(
                 512u, 944u, 40u, 12u) == 30u);
    QR_CHECK("chart axis cadence falls back to a yearly bound",
             zcl_present_canvas_axis_label_stride_v1(
                 512u, 80u, 40u, 12u) == 365u);
    QR_CHECK("chart axis cadence lone column keeps weekly, only unfittable widens",
             zcl_present_canvas_axis_label_stride_v1(
                 0u, 944u, 40u, 12u) == 7u &&
             zcl_present_canvas_axis_label_stride_v1(
                 1u, 944u, 40u, 12u) == 7u &&
             zcl_present_canvas_axis_label_stride_v1(
                 512u, 40u, 40u, 12u) == 365u);
}

void qr_case_chart_rendering_page_bound(void)
{
    char why[128];
    uint8_t icon[ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES];
    (void)zcl_present_zclassic_icon_rgba(icon, sizeof(icon));
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
    static const struct zcl_present_window_hover_item_v1 hover_items[] = {
        {.x = 100u, .text = "2026-08-30\n100 lines"},
        {.x = 300u, .text = "2026-08-31\n200 lines"},
        {.x = 500u, .text = "2026-09-01\n300 lines"},
    };
    const struct zcl_present_window_hover_v1 hover = {
        .struct_size = sizeof(hover),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .plot_left = 80u,
        .plot_top = 100u,
        .plot_right = 520u,
        .plot_bottom = 600u,
        .items = hover_items,
        .item_count = 3u,
    };
    const struct zcl_present_window_pages_v1 hover_pages = {
        .struct_size = sizeof(hover_pages),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .pages = &present,
        .page_count = 1u,
    };
    QR_CHECK("chart rendering page starts inside its exact bound",
             !zcl_present_window_run_pages_hover_v1(
                 &hover_pages, &hover, 1u, why, sizeof(why)) &&
             strstr(why, "initial page") != NULL);
}

void qr_case_shared_qr_model_rejects(void)
{
    char why[128];
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
}

void qr_case_maximum_qr_chunks(void)
{
    char why[128];
    struct zcl_present_model_v1 rejected_qr;
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
}

void qr_case_qr_text_companion_pages(void)
{
    char why[128];
    char max_qr[ZCL_QR_MAX_PAYLOAD + 1u];
    memset(max_qr, 'q', sizeof(max_qr) - 1u);
    max_qr[sizeof(max_qr) - 1u] = '\0';
    struct zcl_present_model_v1 rejected_qr;
    (void)zcl_present_model_qr_from_payload_v1(
        max_qr, "Maximum", &rejected_qr, why, sizeof(why));
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
}

void qr_case_qr_text_export_and_backend(void)
{
    char why[128];
    char max_qr[ZCL_QR_MAX_PAYLOAD + 1u];
    memset(max_qr, 'q', sizeof(max_qr) - 1u);
    max_qr[sizeof(max_qr) - 1u] = '\0';
    struct zcl_present_model_v1 rejected_qr;
    (void)zcl_present_model_qr_from_payload_v1(
        max_qr, "Maximum", &rejected_qr, why, sizeof(why));
    char qr_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t qr_text_len = 0;
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
}

void qr_case_progress_model(void)
{
    char why[128];
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
}

void qr_case_chart_model(void)
{
    char why[128];
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
}

void qr_case_timeline_model(void)
{
    char why[128];
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
}

void qr_case_evidence_graph(void)
{
    char why[128];
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
}

void qr_case_choice_model(void)
{
    char why[128];
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
}

void qr_case_form_model_render(void)
{
    char why[128];
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
}

