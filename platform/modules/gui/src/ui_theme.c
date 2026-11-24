/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the closed style-token table and WCAG contrast. The palette is
 * ZclWallet v2.1.2-beta13's dark.qss (visual_spec section 1); sizes are its
 * point sizes in logical px (section 2). Fixed privacy meanings: green is
 * private, amber is public, red is de-shield only; no blue except info. */
#include "gui/ui.h"

#define RGB(r, g, b) (((uint32_t)(r) << 16) | ((uint32_t)(g) << 8) | (uint32_t)(b))

#define C_APP RGB(0x0f, 0x11, 0x15)      /* window, menu bar, status bar, dialogs */
#define C_PAGE RGB(0x15, 0x17, 0x1c)     /* pages, group boxes, cards */
#define C_INSET RGB(0x1d, 0x20, 0x27)    /* inputs, tables, menus */
#define C_RAIL RGB(0x0c, 0x0e, 0x12)
#define C_LINE RGB(0x2a, 0x2d, 0x35)     /* hairlines */
#define C_CTRL RGB(0x34, 0x3a, 0x44)     /* control borders */
#define C_TEXT RGB(0xe6, 0xe6, 0xe6)
#define C_WHITE RGB(0xff, 0xff, 0xff)
#define C_DIM RGB(0x9a, 0xa0, 0xa6)
#define C_GREEN RGB(0x1f, 0x7a, 0x1f)    /* private: fills, accents */
#define C_HERO RGB(0x34, 0xc7, 0x59)     /* private: green text on dark */
#define C_AMBER RGB(0xd9, 0x82, 0x2b)    /* public */
#define C_AMBER_TEXT RGB(0xe6, 0xb0, 0x6a)
#define C_RED RGB(0xc0, 0x39, 0x2b)      /* de-shield only */
#define C_DANGER_TEXT RGB(0xe0, 0x6b, 0x5e)
#define C_BUTTON RGB(0x2a, 0x2e, 0x37)
#define C_NAV_ON RGB(0x0f, 0x22, 0x14)   /* rgba(31,122,31,.18) over the rail */
#define C_AMBER_TINT RGB(0x23, 0x1e, 0x1d) /* rgba(217,130,43,.07) over the page */
/* Pill fills: the badge colour at alpha 38/255 over the table body. */
#define C_PILL_GREEN RGB(0x20, 0x30, 0x28)
#define C_PILL_AMBER RGB(0x39, 0x2f, 0x28)
#define C_PILL_RED RGB(0x35, 0x24, 0x28)
#define C_DESHIELD_TEXT RGB(0xf0, 0x8a, 0x7e)

#define T GUI_FONT_TEXT
#define B GUI_FONT_STRONG

static const struct gui_theme_entry k_theme[GS_COUNT] = {
    [GS_SCREEN] = { C_TEXT, C_APP, 0, 0, 19, T },
    [GS_CARD] = { C_TEXT, C_PAGE, C_LINE, 12, 19, T },
    [GS_CARD_WARN] = { C_AMBER_TEXT, C_AMBER_TINT, C_AMBER, 12, 17, B },
    [GS_TITLE] = { C_TEXT, C_PAGE, 0, 0, 21, B },
    [GS_BODY] = { C_TEXT, C_PAGE, 0, 0, 19, T },
    [GS_MUTED] = { C_DIM, C_PAGE, 0, 0, 17, T },
    [GS_HERO] = { C_HERO, C_PAGE, 0, 0, 53, B },
    [GS_AMOUNT] = { C_TEXT, C_PAGE, 0, 0, 19, B },
    [GS_BADGE_PRIVATE] = { C_HERO, C_PILL_GREEN, C_GREEN, 10, 16, B },
    [GS_BADGE_PUBLIC] = { C_AMBER_TEXT, C_PILL_AMBER, C_AMBER, 10, 16, B },
    [GS_BADGE_DANGER] = { C_DESHIELD_TEXT, C_PILL_RED, C_RED, 10, 16, B },
    [GS_BUTTON] = { C_TEXT, C_BUTTON, C_CTRL, 8, 16, B },
    [GS_BUTTON_PRIMARY] = { C_WHITE, C_GREEN, C_GREEN, 8, 16, B },
    [GS_BUTTON_DANGER] = { C_WHITE, C_RED, C_RED, 8, 16, B },
    [GS_INPUT] = { C_TEXT, C_INSET, C_CTRL, 8, 19, T },
    [GS_TABLE] = { C_TEXT, C_INSET, C_LINE, 10, 19, T },
    [GS_NAV] = { C_DIM, C_RAIL, 0, 8, 17, B },
    [GS_NAV_ACTIVE] = { C_WHITE, C_NAV_ON, C_GREEN, 8, 17, B },
    [GS_STATUS] = { C_DIM, C_APP, 0, 0, 19, T },
    [GS_TOAST] = { C_TEXT, C_BUTTON, 0, 8, 17, T },
    [GS_DIALOG] = { C_TEXT, C_APP, C_LINE, 12, 17, T },
    [GS_RAIL] = { C_DIM, C_RAIL, C_LINE, 0, 17, T },
    [GS_NAV_ITEM] = { C_DIM, C_RAIL, 0, 8, 17, B },
    [GS_NAV_ITEM_ACTIVE] = { C_WHITE, C_NAV_ON, C_GREEN, 8, 17, B },
    [GS_NAV_ADV] = { C_DIM, C_RAIL, 0, 8, 15, T },
    [GS_NAV_ADV_ACTIVE] = { C_WHITE, C_NAV_ON, C_GREEN, 8, 15, T },
    [GS_PAGE] = { C_TEXT, C_PAGE, 0, 0, 19, T },
    [GS_GROUP] = { C_TEXT, C_PAGE, C_LINE, 12, 19, T },
    [GS_GROUP_TITLE] = { C_TEXT, C_PAGE, 0, 0, 19, B },
    [GS_HERO_CARD] = { C_TEXT, C_PAGE, C_LINE, 12, 19, T },
    [GS_HERO_CAPTION] = { C_DIM, C_PAGE, 0, 0, 16, B },
    [GS_HERO_AMOUNT_OK] = { C_HERO, C_PAGE, 0, 0, 53, B },
    [GS_HERO_AMOUNT_WARM] = { C_DIM, C_PAGE, 0, 0, 53, B },
    [GS_HERO_TOTAL] = { C_DIM, C_PAGE, 0, 0, 17, T },
    [GS_HERO_NOTE] = { C_DIM, C_PAGE, 0, 0, 15, T },
    [GS_BUTTON_SECONDARY] = { C_TEXT, C_BUTTON, C_CTRL, 8, 16, B },
    [GS_BUTTON_AMBER] = { C_PAGE, C_AMBER, C_AMBER, 8, 16, B },
    [GS_CARD_AMBER] = { C_AMBER_TEXT, C_AMBER_TINT, C_LINE, 12, 17, B },
    [GS_AMBER_TEXT] = { C_AMBER_TEXT, C_AMBER_TINT, 0, 0, 17, B },
    [GS_PILL_PRIVATE] = { C_HERO, C_PILL_GREEN, C_GREEN, 10, 16, B },
    [GS_PILL_PUBLIC] = { C_AMBER_TEXT, C_PILL_AMBER, C_AMBER, 10, 16, B },
    [GS_PILL_DESHIELD] = { C_DESHIELD_TEXT, C_PILL_RED, C_RED, 10, 16, B },
    [GS_AMOUNT_MONO] = { C_TEXT, C_INSET, 0, 0, 19, T },
    [GS_SYNC_PILL] = { C_DIM, C_PAGE, 0, 0, 17, B },
    [GS_BANNER_CONNECTING] = { C_WHITE, RGB(0x55, 0x55, 0x55), 0, 8, 17, B },
    /* beta13 puts white on #d9822b (2.8:1); Z23 uses the amber button's dark text. */
    [GS_BANNER_SYNCING] = { C_PAGE, C_AMBER, 0, 8, 17, B },
    [GS_BANNER_INFO] = { C_WHITE, RGB(0x2c, 0x5d, 0x8f), 0, 8, 17, B },
    [GS_BANNER_TEXT] = { C_WHITE, RGB(0x55, 0x55, 0x55), 0, 0, 17, B },
    [GS_MENUBAR] = { C_TEXT, C_APP, 0, 0, 19, T },
    [GS_MENUBAR_ITEM] = { C_TEXT, C_APP, 0, 6, 19, T },
    [GS_MENU_POPUP] = { C_TEXT, C_INSET, C_LINE, 8, 19, T },
    [GS_MENU_ITEM] = { C_TEXT, C_INSET, 0, 6, 19, T },
    [GS_STATUSBAR] = { C_TEXT, C_APP, C_LINE, 0, 19, T },
    [GS_STATUS_LABEL] = { C_TEXT, C_APP, 0, 0, 19, T },
    [GS_STATUS_MSG] = { C_DIM, C_APP, 0, 0, 19, T },
    /* Icons are vector shapes, not text: the shape colour is in .border. */
    [GS_ICON_OK] = { C_APP, C_APP, C_HERO, 0, 16, T },
    [GS_ICON_WARN] = { C_APP, C_APP, C_AMBER, 0, 16, T },
    [GS_ICON_CRIT] = { C_APP, C_APP, C_RED, 0, 16, T },
    [GS_WARN_TEXT] = { C_DANGER_TEXT, C_INSET, 0, 0, 19, T },
    [GS_INPUT_VALID] = { C_TEXT, C_INSET, C_HERO, 8, 19, T },
    [GS_INPUT_INVALID] = { C_TEXT, C_INSET, C_RED, 8, 19, T },
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
