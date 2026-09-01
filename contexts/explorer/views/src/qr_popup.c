/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: QR-specific renderer over the reusable native presentation ABI. */

#include "views/qr_popup.h"

#include "base/safe_alloc.h"
#include "encoding/qr.h"
#include "presentation/canvas.h"
#include "presentation/zclassic_brand.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct zcl_present_color COLOR_INK = {0x20, 0x20, 0x22};
static const struct zcl_present_color COLOR_MUTED = {0x69, 0x65, 0x60};
static const struct zcl_present_color COLOR_PAPER = {0xfb, 0xfa, 0xf8};
static const struct zcl_present_color COLOR_RULE = {0xdf, 0xd8, 0xcf};

static void popup_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0)
        (void)snprintf(error, cap, "%s", message ? message :
                       "QR deposit card could not be rendered");
}

static void copy_span(char *out, size_t cap, const char *begin,
                      const char *end)
{
    if (!out || cap == 0) return;
    size_t length = begin && end && end > begin ? (size_t)(end - begin) : 0;
    if (length >= cap) length = cap - 1u;
    if (length > 0) memcpy(out, begin, length);
    out[length] = '\0';
}

static void describe_payload(const char *payload, struct qr_popup_card *card)
{
    card->is_deposit = strncmp(payload, "zclassic:", 9u) == 0 && payload[9];
    if (!card->is_deposit) {
        copy_span(card->address, sizeof(card->address), payload,
                  payload + strlen(payload));
        return;
    }

    const char *address = payload + 9u;
    const char *query = strchr(address, '?');
    const char *address_end = query ? query : payload + strlen(payload);
    copy_span(card->address, sizeof(card->address), address, address_end);
    if (!query) return;

    for (const char *part = query + 1u; part && *part;) {
        const char *next = strchr(part, '&');
        const char *end = next ? next : payload + strlen(payload);
        if ((size_t)(end - part) >= 7u && memcmp(part, "amount=", 7u) == 0) {
            copy_span(card->amount, sizeof(card->amount), part + 7u, end);
            return;
        }
        part = next ? next + 1u : NULL;
    }
}

static void canvas_center_text(struct zcl_present_canvas *canvas, int32_t y,
                               const char *text, uint32_t pixel_height,
                               struct zcl_present_color color)
{
    size_t length = strlen(text);
    uint32_t width = zcl_present_canvas_text_width(text, length, pixel_height);
    int32_t x = width < canvas->width ? (int32_t)(canvas->width - width) / 2 : 0;
    zcl_present_canvas_text(canvas, x, y, text, length, pixel_height, color);
}

static uint32_t canvas_wrapped_text(struct zcl_present_canvas *canvas,
                                    int32_t x, int32_t y,
                                    const char *text, uint32_t pixel_height,
                                    uint32_t max_width, uint32_t max_lines,
                                    struct zcl_present_color color)
{
    size_t length = strlen(text);
    size_t offset = 0;
    uint32_t lines = 0;
    while (offset < length && lines < max_lines) {
        size_t count = 0;
        while (offset + count < length) {
            uint32_t candidate = zcl_present_canvas_text_width(
                text + offset, count + 1u, pixel_height);
            if (candidate > max_width) break;
            count++;
        }
        if (count == 0) break;
        bool truncated = lines + 1u == max_lines && offset + count < length;
        if (truncated) {
            uint32_t dots = zcl_present_canvas_text_width("...", 3u,
                                                          pixel_height);
            while (count > 0 && zcl_present_canvas_text_width(
                       text + offset, count, pixel_height) + dots > max_width)
                count--;
        }
        int32_t line_y = y + (int32_t)(lines * (pixel_height + 3u));
        zcl_present_canvas_text(canvas, x, line_y, text + offset, count,
                                pixel_height, color);
        if (truncated) {
            uint32_t used = zcl_present_canvas_text_width(
                text + offset, count, pixel_height);
            zcl_present_canvas_text(canvas, x + (int32_t)used, line_y,
                                    "...", 3u, pixel_height, color);
        }
        offset += count;
        lines++;
        if (truncated) break;
    }
    return lines * (pixel_height + 3u);
}

static void blit_qr(struct zcl_present_canvas *canvas, const uint8_t *qr,
                    uint32_t side)
{
    int32_t x0 = 35 + (int32_t)(370u - side) / 2;
    int32_t y0 = 150 + (int32_t)(370u - side) / 2;
    for (uint32_t y = 0; y < side; y++) {
        size_t src = (size_t)y * side * 3u;
        size_t dst = (size_t)(y0 + (int32_t)y) * canvas->stride +
                     (size_t)x0 * 3u;
        memcpy(canvas->pixels + dst, qr + src, (size_t)side * 3u);
    }
}

bool qr_popup_card_render(const struct zcl_present_model_v1 *model,
                          struct qr_popup_card *out,
                          char *error, size_t error_cap)
{
    if (!out) {
        popup_error(error, error_cap, "missing QR deposit card output");
        return false;
    }
    *out = (struct qr_popup_card){0};

    char payload[ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX + 1u];
    if (!zcl_present_model_qr_payload_v1(model, payload,
                                         error, error_cap))
        return false;

    struct qr_matrix matrix;
    if (!qr_matrix_encode(payload, &matrix, error, error_cap))
        return false; // raw-return-ok:encoder supplied bounded caller error
    uint32_t full_modules = matrix.width + 2u * ZCL_QR_QUIET_MODULES;
    uint32_t scale = 330u / full_modules;
    if (scale < 2u) scale = 2u;
    if (scale > 10u) scale = 10u;

    uint8_t *qr_pixels = NULL;
    uint32_t qr_side = 0;
    if (!qr_matrix_render_rgb(&matrix, scale, ZCL_QR_QUIET_MODULES,
                              &qr_pixels, &qr_side, error, error_cap)) {
        qr_matrix_free(&matrix);
        return false;
    }

    uint8_t *pixels = zcl_malloc(ZCL_QR_POPUP_CARD_BYTES,
                                 "qr.popup.deposit_card");
    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(&canvas, pixels, ZCL_QR_POPUP_CARD_BYTES,
                                 ZCL_QR_POPUP_CARD_WIDTH,
                                 ZCL_QR_POPUP_CARD_HEIGHT)) {
        free(pixels);
        free(qr_pixels);
        qr_matrix_free(&matrix);
        popup_error(error, error_cap, "deposit card canvas is invalid");
        return false;
    }

    out->pixels = pixels;
    out->width = ZCL_QR_POPUP_CARD_WIDTH;
    out->height = ZCL_QR_POPUP_CARD_HEIGHT;
    describe_payload(payload, out);

    zcl_present_canvas_clear(&canvas, COLOR_PAPER);
    uint8_t logo[ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES];
    if (zcl_present_zclassic_icon_rgba(logo, sizeof(logo)))
        zcl_present_canvas_blit_rgba(&canvas, 20, 12, logo,
                                     ZCL_PRESENT_ZCLASSIC_ICON_WIDTH,
                                     ZCL_PRESENT_ZCLASSIC_ICON_HEIGHT);
    zcl_present_canvas_text(&canvas, 104, 18, "ZCLASSIC23", 10u, 24u,
                            COLOR_INK);
    zcl_present_canvas_text(&canvas, 105, 49, "WALLET", 6u, 12u,
                            COLOR_MUTED);
    zcl_present_canvas_line(&canvas, 104, 69, 415, 69, COLOR_RULE);

    const char *heading = out->is_deposit ? "Deposit ZCL" : "QR code";
    zcl_present_canvas_text(&canvas, 24, 92, heading, strlen(heading), 28u,
                            COLOR_INK);
    const char *subtitle = out->is_deposit
        ? "Scan this code with your wallet"
        : "Scan or copy the payload";
    zcl_present_canvas_text(&canvas, 25, 127, subtitle, strlen(subtitle), 14u,
                            COLOR_MUTED);

    blit_qr(&canvas, qr_pixels, qr_side);

    zcl_present_canvas_line(&canvas, 24, 528, 415, 528, COLOR_RULE);
    const char *label = out->is_deposit ? "Address" : "Payload";
    zcl_present_canvas_text(&canvas, 24, 542, label, strlen(label), 12u,
                            COLOR_MUTED);
    uint32_t address_height = canvas_wrapped_text(
        &canvas, 24, 560, out->address, 15u, 392u, 3u, COLOR_INK);
    int32_t amount_y = 560 + (int32_t)address_height + 5;
    if (out->is_deposit) {
        zcl_present_canvas_text(&canvas, 24, amount_y, "Amount", 6u, 12u,
                                COLOR_MUTED);
        const char *amount = out->amount[0] ? out->amount : "Any amount";
        char amount_line[96];
        (void)snprintf(amount_line, sizeof(amount_line), "%s%s",
                       amount, out->amount[0] ? " ZCL" : "");
        zcl_present_canvas_text(&canvas, 24, amount_y + 16, amount_line,
                                strlen(amount_line), 17u, COLOR_INK);
    }

    const char *footer = out->is_deposit
        ? "C  Copy payment URI        Esc  Close"
        : "C  Copy payload        Esc  Close";
    canvas_center_text(&canvas, 642, footer, 11u, COLOR_MUTED);

    free(qr_pixels);
    qr_matrix_free(&matrix);
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

void qr_popup_card_free(struct qr_popup_card *card)
{
    if (!card) return;
    free(card->pixels);
    *card = (struct qr_popup_card){0};
}
