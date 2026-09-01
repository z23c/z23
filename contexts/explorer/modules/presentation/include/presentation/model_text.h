/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: deterministic bounded plain-text companion for presentation models. */

#ifndef ZCL_PRESENTATION_MODEL_TEXT_H
#define ZCL_PRESENTATION_MODEL_TEXT_H

#include "presentation/model.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_PRESENT_MODEL_TEXT_MAX 3072u
#define ZCL_PRESENT_MODEL_TEXT_ITEMS_PER_PAGE 1u

/* Renders the complete model when its deterministic text representation fits
 * the command-safe text bound.  This is the normal AI/accessibility path: a
 * small instrument should take one command, not one command per visual row.
 * Callers fall back to the page API below only when this returns false with
 * the exact "exceeds its byte bound" diagnostic. */
bool zcl_present_model_text_all_v1(
    const struct zcl_present_model_v1 *model,
    char *out, size_t out_cap, size_t *out_len,
    char *error, size_t error_cap);

/* Renders one deterministic accessibility/export page from the exact same
 * inert model used by the native compositor. Caller-owned output is always
 * NUL-terminated on success. Page indices are zero-based. */
bool zcl_present_model_text_page_v1(
    const struct zcl_present_model_v1 *model, uint32_t page_index,
    char *out, size_t out_cap, size_t *out_len, uint32_t *page_count,
    char *error, size_t error_cap);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_PRESENTATION_MODEL_TEXT_H */
