/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical bounded composition of one visual model into pages. */

#include "views/ui_present_document.h"

#include <stdio.h>
#include <string.h>

static_assert(ZCL_PRESENT_MODEL_PAGES_MAX <= ZCL_PRESENT_WINDOW_PAGES_MAX,
              "model pages must fit the native window page bound");

static bool document_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0)
        (void)snprintf(error, cap, "%s", message);
    return false;
}

void ui_present_document_free(struct ui_present_document *document)
{
    if (!document) return;
    qr_popup_card_free(&document->qr_card);
    for (uint32_t i = 0; i < ZCL_PRESENT_MODEL_PAGES_MAX; i++)
        zcl_present_model_bitmap_free_v1(&document->bitmaps[i]);
    *document = (struct ui_present_document){0};
}

static void document_window(
    struct ui_present_document *document, uint32_t page,
    const uint8_t *pixels, uint32_t width, uint32_t height,
    const char *copy_text)
{
    document->windows[page] = (struct zcl_present_window_v1){
        .struct_size = sizeof(document->windows[page]),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .title = document->title,
        .pixels = pixels,
        .width = width,
        .height = height,
        .pixel_format = ZCL_PRESENT_RGB8,
        .icon_rgba = document->icon,
        .icon_width = ZCL_PRESENT_ZCLASSIC_ICON_WIDTH,
        .icon_height = ZCL_PRESENT_ZCLASSIC_ICON_HEIGHT,
        .copy_text = copy_text,
    };
}

bool ui_present_document_from_model(
    const struct zcl_present_model_v1 *model,
    struct ui_present_document *out,
    char *error, size_t error_cap)
{
    if (!model || !out)
        return document_error(error, error_cap,
                              "presentation document input is missing");
    *out = (struct ui_present_document){0};
    char why[192];
    if (!zcl_present_model_validate_v1(model, why, sizeof(why)))
        return document_error(error, error_cap, why);
    out->model = *model;
    out->action_count = model->action_count;
    out->is_qr = model->kind == ZCL_PRESENT_MODEL_QR_CARD;
    if (!zcl_present_zclassic_icon_rgba(out->icon, sizeof(out->icon)))
        return document_error(error, error_cap,
                              "ZClassic presentation icon is unavailable");

    if (out->is_qr) {
        if (!qr_popup_card_render(&out->model, &out->qr_card,
                                  error, error_cap) ||
            !zcl_present_model_qr_payload_v1(
                &out->model, out->qr_payload, error, error_cap)) {
            ui_present_document_free(out);
            return false;
        }
        const char *kind = out->qr_card.is_deposit
            ? "Deposit ZCL" : out->model.title;
        (void)snprintf(out->title, sizeof(out->title),
                       "Z23 — %s — C copies, Esc closes", kind);
        out->page_count = 1;
        document_window(out, 0, out->qr_card.pixels,
                        out->qr_card.width, out->qr_card.height,
                        out->qr_payload);
        if (error && error_cap > 0) error[0] = '\0';
        return true;
    }

    if (!zcl_present_model_page_count_v1(
            &out->model, &out->page_count, error, error_cap)) {
        ui_present_document_free(out);
        return false;
    }
    (void)snprintf(out->title, sizeof(out->title),
                   "Z23 — %s", out->model.title);
    for (uint32_t i = 0; i < out->page_count; i++) {
        if (!zcl_present_model_render_page_v1(
                &out->model, i, &out->bitmaps[i], error, error_cap)) {
            ui_present_document_free(out);
            return false;
        }
        document_window(out, i, out->bitmaps[i].pixels,
                        out->bitmaps[i].width, out->bitmaps[i].height,
                        out->model.exact_root[0]
                            ? out->model.exact_root : NULL);
    }
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

bool ui_present_document_from_wire(
    const uint8_t *wire, size_t wire_len,
    struct ui_present_document *out,
    char *error, size_t error_cap)
{
    struct zcl_present_model_v1 model;
    if (!zcl_present_model_decode_v1(
            wire, wire_len, &model, error, error_cap))
        return false;
    return ui_present_document_from_model(
        &model, out, error, error_cap);
}
