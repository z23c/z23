/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: canonical ZClassic icon adapter for native presentation clients. */

#ifndef ZCL_PRESENTATION_ZCLASSIC_BRAND_H
#define ZCL_PRESENTATION_ZCLASSIC_BRAND_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_PRESENT_ZCLASSIC_ICON_WIDTH 64u
#define ZCL_PRESENT_ZCLASSIC_ICON_HEIGHT 64u
#define ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES \
    (ZCL_PRESENT_ZCLASSIC_ICON_WIDTH * ZCL_PRESENT_ZCLASSIC_ICON_HEIGHT * 4u)

/* Expand the attributed one-bit ZClassic mark into transparent RGBA8 using
 * the canonical #C87035 brand color. The caller supplies all storage. */
bool zcl_present_zclassic_icon_rgba(uint8_t *out, size_t out_cap);

#endif /* ZCL_PRESENTATION_ZCLASSIC_BRAND_H */
