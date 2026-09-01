/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: compact canonical ZClassic logo expansion for native windows.
 *
 * Artwork: "ZClassic Logo" by @jojo from the ZClassic Slack/Rocket.Chat,
 * 2016-12-05, CC BY 4.0. Source SVG:
 * https://commons.wikimedia.org/wiki/File:ZClassic_Logo.svg
 * The included 64px one-bit mask is a size-only rasterization of the official
 * mark; its shape and #C87035 brand color are unchanged. */

#include "presentation/zclassic_brand.h"

#include <string.h>

#include "zclassic_icon_mask.inc"

bool zcl_present_zclassic_icon_rgba(uint8_t *out, size_t out_cap)
{
    if (!out || out_cap < ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES)
        return false; // raw-return-ok:caller-owned bounded icon buffer
    memset(out, 0, ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES);
    for (size_t i = 0;
         i < ZCL_PRESENT_ZCLASSIC_ICON_WIDTH * ZCL_PRESENT_ZCLASSIC_ICON_HEIGHT;
         i++) {
        if ((g_zclassic_icon_mask[i / 8u] & (uint8_t)(0x80u >> (i % 8u))) == 0)
            continue;
        out[i * 4u] = 0xc8;
        out[i * 4u + 1u] = 0x70;
        out[i * 4u + 2u] = 0x35;
        out[i * 4u + 3u] = 0xff;
    }
    return true;
}
