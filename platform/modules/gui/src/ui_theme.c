/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the closed style-token table (dark palette) and WCAG contrast. */
#include "gui/ui.h"

#define RGB(r, g, b) (((uint32_t)(r) << 16) | ((uint32_t)(g) << 8) | (uint32_t)(b))

#define C_BG RGB(0x12, 0x14, 0x1a)
#define C_CARD RGB(0x1c, 0x1f, 0x27)
#define C_TEXT RGB(0xe8, 0xea, 0xf0)
#define C_MUTED RGB(0x9a, 0xa3, 0xb2)

static const struct gui_theme_entry k_theme[GS_COUNT] = {
    [GS_SCREEN] = { C_TEXT, C_BG, 0, 0, 14, GUI_FONT_TEXT },
    [GS_CARD] = { C_TEXT, C_CARD, RGB(0x2b, 0x30, 0x3b), 10, 14, GUI_FONT_TEXT },
    [GS_CARD_WARN] = { RGB(0xff, 0xe9, 0xc7), RGB(0x3a, 0x2a, 0x12), RGB(0x8a, 0x5a, 0x1c), 10, 14, GUI_FONT_TEXT },
    [GS_TITLE] = { C_TEXT, C_BG, 0, 0, 20, GUI_FONT_STRONG },
    [GS_BODY] = { C_TEXT, C_BG, 0, 0, 14, GUI_FONT_TEXT },
    [GS_MUTED] = { C_MUTED, C_BG, 0, 0, 13, GUI_FONT_TEXT },
    [GS_HERO] = { RGB(0xff, 0xff, 0xff), C_BG, 0, 0, 40, GUI_FONT_STRONG },
    [GS_AMOUNT] = { C_TEXT, C_BG, 0, 0, 18, GUI_FONT_STRONG },
    [GS_BADGE_PRIVATE] = { RGB(0x06, 0x1a, 0x0c), RGB(0x34, 0xc7, 0x59), 0, 9, 13, GUI_FONT_STRONG },
    [GS_BADGE_PUBLIC] = { RGB(0x1d, 0x10, 0x02), RGB(0xd9, 0x82, 0x2b), 0, 9, 13, GUI_FONT_STRONG },
    [GS_BADGE_DANGER] = { RGB(0xff, 0xff, 0xff), RGB(0xc0, 0x39, 0x2b), 0, 9, 13, GUI_FONT_STRONG },
    [GS_BUTTON] = { C_TEXT, RGB(0x2a, 0x2f, 0x3a), RGB(0x3a, 0x40, 0x4e), 8, 14, GUI_FONT_STRONG },
    [GS_BUTTON_PRIMARY] = { RGB(0xff, 0xff, 0xff), RGB(0x2f, 0x6f, 0xed), RGB(0x2f, 0x6f, 0xed), 8, 14, GUI_FONT_STRONG },
    [GS_BUTTON_DANGER] = { RGB(0xff, 0xff, 0xff), RGB(0xb3, 0x26, 0x1e), RGB(0xb3, 0x26, 0x1e), 8, 14, GUI_FONT_STRONG },
    [GS_INPUT] = { C_TEXT, RGB(0x0d, 0x0f, 0x14), RGB(0x3a, 0x40, 0x4e), 6, 14, GUI_FONT_TEXT },
    [GS_TABLE] = { C_TEXT, C_CARD, RGB(0x2b, 0x30, 0x3b), 6, 13, GUI_FONT_TEXT },
    [GS_NAV] = { C_TEXT, RGB(0x16, 0x18, 0x1f), 0, 8, 14, GUI_FONT_TEXT },
    [GS_NAV_ACTIVE] = { RGB(0xff, 0xff, 0xff), RGB(0x2a, 0x33, 0x50), 0, 8, 14, GUI_FONT_STRONG },
    [GS_STATUS] = { C_MUTED, RGB(0x0d, 0x0f, 0x14), 0, 0, 13, GUI_FONT_TEXT },
    [GS_TOAST] = { C_TEXT, RGB(0x2a, 0x2f, 0x3a), 0, 8, 13, GUI_FONT_TEXT },
    [GS_DIALOG] = { C_TEXT, RGB(0x20, 0x24, 0x2e), RGB(0x3a, 0x40, 0x4e), 12, 14, GUI_FONT_TEXT },
};

const struct gui_theme_entry *gui_theme(enum gui_style s)
{
    return &k_theme[s < GS_COUNT ? s : GS_BODY];
}

static int64_t lin(uint32_t c8)
{
    /* sRGB to linear (x1e6). Used by the contrast test only; b^2.4 is
     * b^2 * b^0.4 with b^0.4 from Newton iteration on y^5 = b^2. */
    double c = (double)c8 / 255.0;
    if (c <= 0.03928) return (int64_t)(c / 12.92 * 1000000.0);
    double b = (c + 0.055) / 1.055, y = 1.0;
    for (int i = 0; i < 40; i++)
        y = y - (y * y * y * y * y - b * b) / (5.0 * y * y * y * y);
    return (int64_t)(b * b * y * 1000000.0);
}

int32_t gui_contrast_x100(uint32_t a, uint32_t b)
{
    int64_t la = (lin((a >> 16) & 255u) * 2126 + lin((a >> 8) & 255u) * 7152 +
                  lin(a & 255u) * 722) / 10000;
    int64_t lb = (lin((b >> 16) & 255u) * 2126 + lin((b >> 8) & 255u) * 7152 +
                  lin(b & 255u) * 722) / 10000;
    if (la < lb) { int64_t t = la; la = lb; lb = t; }
    return (int32_t)(((la + 50000) * 100) / (lb + 50000));
}
