/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: one bounded model-to-native-window composition for every host. */

#ifndef ZCL_VIEWS_UI_PRESENT_DOCUMENT_H
#define ZCL_VIEWS_UI_PRESENT_DOCUMENT_H

#include "presentation/model.h"
#include "presentation/model_render.h"
#include "presentation/presentation.h"
#include "presentation/zclassic_brand.h"
#include "views/qr_popup.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Owns every byte referenced by `windows` for one blocking native-window
 * call. The document is inert: it contains only a validated model, rendered
 * pixels, title/icon bytes, copy text, and a bounded action count. */
struct ui_present_document {
    struct zcl_present_model_v1 model;
    struct zcl_present_model_bitmap_v1
        bitmaps[ZCL_PRESENT_MODEL_PAGES_MAX];
    struct qr_popup_card qr_card;
    struct zcl_present_window_v1 windows[ZCL_PRESENT_MODEL_PAGES_MAX];
    uint8_t icon[ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES];
    char title[ZCL_PRESENT_TITLE_MAX + 1u];
    char qr_payload[ZCL_PRESENT_MODEL_QR_PAYLOAD_MAX + 1u];
    uint32_t page_count;
    uint32_t action_count;
    bool is_qr;
};

/* Decode and render one exact model wire through the canonical composition.
 * Resident and compatibility hosts consume this same owned document. */
bool ui_present_document_from_wire(
    const uint8_t *wire, size_t wire_len,
    struct ui_present_document *out,
    char *error, size_t error_cap);

/* Pure-model entry point used by exact tests and model-owning callers. */
bool ui_present_document_from_model(
    const struct zcl_present_model_v1 *model,
    struct ui_present_document *out,
    char *error, size_t error_cap);

void ui_present_document_free(struct ui_present_document *document);

#endif /* ZCL_VIEWS_UI_PRESENT_DOCUMENT_H */
