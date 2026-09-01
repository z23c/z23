/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Standalone libzclpresentation example and cross-platform link proof. */

#include "presentation/canvas.h"
#include "presentation/presentation.h"
#include "presentation/zclassic_brand.h"

#include <stdint.h>
#include <string.h>

int main(void)
{
    static uint8_t pixels[520u * 320u * 3u];
    struct zcl_present_canvas canvas;
    if (!zcl_present_canvas_init(&canvas, pixels, sizeof(pixels), 520u, 320u))
        return 3;
    const struct zcl_present_color orange = {0xc8, 0x70, 0x35};
    const struct zcl_present_color ink = {0x20, 0x20, 0x22};
    const struct zcl_present_color muted = {0x69, 0x65, 0x60};
    const struct zcl_present_color white = {0xff, 0xff, 0xff};
    const struct zcl_present_color paper = {0xf4, 0xf1, 0xec};
    zcl_present_canvas_clear(&canvas, paper);
    zcl_present_canvas_fill_rect(&canvas, 0, 0, 520u, 88u, orange);
    uint8_t icon[ZCL_PRESENT_ZCLASSIC_ICON_RGBA_BYTES];
    if (!zcl_present_zclassic_icon_rgba(icon, sizeof(icon))) return 2;
    zcl_present_canvas_fill_rect(&canvas, 16, 8, 72u, 72u, white);
    zcl_present_canvas_blit_rgba(&canvas, 20, 12, icon,
                                 ZCL_PRESENT_ZCLASSIC_ICON_WIDTH,
                                 ZCL_PRESENT_ZCLASSIC_ICON_HEIGHT);
    zcl_present_canvas_text(&canvas, 108, 12, "ZCLASSIC23", 10u, 28u, white);
    zcl_present_canvas_text(&canvas, 110, 54,
                            "NATIVE PRESENTATION LAB", 23u, 12u, white);
    zcl_present_canvas_text(&canvas, 24, 112, "AVAILABLE BALANCE", 17u, 12u,
                            orange);
    zcl_present_canvas_text(&canvas, 24, 136, "12.34567890 ZCL", 14u, 28u,
                            ink);
    zcl_present_canvas_text(&canvas, 24, 184, "30 DAY ACTIVITY", 15u, 12u,
                            muted);
    zcl_present_canvas_line(&canvas, 24, 276, 496, 276, muted);
    static const int32_t points[][2] = {
        {24, 258}, {92, 244}, {160, 252}, {228, 218},
        {296, 226}, {364, 194}, {432, 204}, {496, 174},
    };
    for (size_t i = 1; i < sizeof(points) / sizeof(points[0]); i++)
        zcl_present_canvas_line(&canvas, points[i - 1u][0], points[i - 1u][1],
                                points[i][0], points[i][1], orange);
    const char *footer = "Reusable for deposits / balances / metadata / charts";
    zcl_present_canvas_text(&canvas, 24, 296, footer, strlen(footer), 11u,
                            muted);
    struct zcl_present_window_v1 request = {
        .struct_size = sizeof(request),
        .abi_version = ZCL_PRESENT_ABI_V1,
        .title = "ZClassic23 — Native Presentation Lab — Esc closes",
        .pixels = pixels,
        .width = 520u,
        .height = 320u,
        .pixel_format = ZCL_PRESENT_RGB8,
        .icon_rgba = icon,
        .icon_width = ZCL_PRESENT_ZCLASSIC_ICON_WIDTH,
        .icon_height = ZCL_PRESENT_ZCLASSIC_ICON_HEIGHT,
        .copy_text = "ZClassic23 native presentation",
    };
    char error[192];
    return zcl_present_window_run_v1(&request, error, sizeof(error)) ? 0 : 1;
}
