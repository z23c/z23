/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic software renderer for bounded visual documents. */

#ifndef ZCL_PRESENTATION_MODEL_RENDER_H
#define ZCL_PRESENTATION_MODEL_RENDER_H

#include "presentation/model.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_PRESENT_MODEL_BITMAP_WIDTH 720u
#define ZCL_PRESENT_MODEL_BITMAP_HEIGHT 720u
#define ZCL_PRESENT_MODEL_BITMAP_BYTES \
    (ZCL_PRESENT_MODEL_BITMAP_WIDTH * ZCL_PRESENT_MODEL_BITMAP_HEIGHT * 3u)
#define ZCL_PRESENT_MODEL_ACTION_X 42u
#define ZCL_PRESENT_MODEL_ACTION_Y 650u
#define ZCL_PRESENT_MODEL_ACTION_WIDTH 636u
#define ZCL_PRESENT_MODEL_ACTION_HEIGHT 42u
#define ZCL_PRESENT_MODEL_ACTION_GAP 12u
#define ZCL_PRESENT_MODEL_PAGES_MAX 16u
#define ZCL_PRESENT_MODEL_FORM_X 42u
#define ZCL_PRESENT_MODEL_FORM_Y 184u
#define ZCL_PRESENT_MODEL_FORM_WIDTH 636u
#define ZCL_PRESENT_MODEL_FORM_FIELD_HEIGHT 78u
#define ZCL_PRESENT_MODEL_FORM_INPUT_Y_OFFSET 24u
#define ZCL_PRESENT_MODEL_FORM_INPUT_HEIGHT 42u
#define ZCL_PRESENT_MODEL_CANVAS_X 72u
#define ZCL_PRESENT_MODEL_CANVAS_Y 204u
#define ZCL_PRESENT_MODEL_CANVAS_WIDTH 576u
#define ZCL_PRESENT_MODEL_CANVAS_HEIGHT 360u

struct zcl_present_model_bitmap_v1 {
    uint8_t *pixels;
    uint32_t width;
    uint32_t height;
};

/* Render only inert model data into an owned RGB bitmap. The renderer performs
 * no input, filesystem, process, node, wallet, package, or network operation. */
bool zcl_present_model_render_v1(const struct zcl_present_model_v1 *model,
                                 struct zcl_present_model_bitmap_v1 *bitmap,
                                 char *error, size_t error_cap);

/* A bounded model may need more than one fixed native viewport. Pagination is
 * derived only from item kinds and the fixed software layout, so every
 * renderer/backend sees the same page count and page pixels. Page zero is the
 * compatibility view returned by render_v1. */
bool zcl_present_model_page_count_v1(
    const struct zcl_present_model_v1 *model, uint32_t *page_count,
    char *error, size_t error_cap);
bool zcl_present_model_render_page_v1(
    const struct zcl_present_model_v1 *model, uint32_t page_index,
    struct zcl_present_model_bitmap_v1 *bitmap,
    char *error, size_t error_cap);
void zcl_present_model_bitmap_free_v1(
    struct zcl_present_model_bitmap_v1 *bitmap);

#endif /* ZCL_PRESENTATION_MODEL_RENDER_H */
