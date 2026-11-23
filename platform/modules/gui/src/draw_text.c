/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: antialiased UTF-8 text with Inter (stb_truetype), a bounded glyph
 * coverage cache, measuring, fitting and caret hit-testing. Advances are
 * rounded to whole pixels so layout is exact and deterministic. */
#include <math.h>
#include <string.h>

#include "gui/draw.h"

/* GCC can fold stb_truetype's `(float)sqrt(double)` into sqrtf and pull a
 * newer libm ABI than the pinned release sysroot; route it through a double
 * sqrt the way the presentation canvas does. */
static double gui_sqrt_compat(double v)
{
    volatile double x = v;
    return sqrt(x);
}

#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdouble-promotion"
#pragma GCC diagnostic ignored "-Wundef"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#endif
#define STBTT_STATIC
#define STBTT_sqrt(x) gui_sqrt_compat(x)
#define STBTT_pow(x, y) pow((x), (y))
#define STB_TRUETYPE_IMPLEMENTATION
#include "../../../../vendor/typography/stb_truetype.h"
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
#include "../../../../vendor/typography/inter_medium_ascii.inc"
#include "../../../../vendor/typography/inter_semibold_ascii.inc"

#define SLOTS 2048u
#define ARENA_BYTES (1024u * 1024u)
#define MAX_PX 400

struct glyph {
    bool used;
    uint8_t font;
    uint16_t px;
    uint32_t cp;
    int16_t xoff, yoff;
    uint16_t w, h;
    int16_t advance;
    uint32_t off;
};

static struct glyph g_slots[SLOTS];
static uint8_t g_arena[ARENA_BYTES];
static uint32_t g_arena_used;
static size_t g_used_slots, g_resets;
static stbtt_fontinfo g_font[2];
static bool g_font_ready[2];

void gui_text_cache_reset(void)
{
    memset(g_slots, 0, sizeof(g_slots));
    g_arena_used = 0;
    g_used_slots = 0;
    g_resets++;
}
size_t gui_text_cache_resets(void) { return g_resets; }

static stbtt_fontinfo *font_info(enum gui_font f)
{
    int i = f == GUI_FONT_STRONG ? 1 : 0;
    if (!g_font_ready[i]) {
        const unsigned char *d = i ? g_zcl_inter_semibold_ascii : g_zcl_inter_medium_ascii;
        if (!stbtt_InitFont(&g_font[i], d, 0)) return NULL;
        g_font_ready[i] = true;
    }
    return &g_font[i];
}

static int32_t clamp_px(int32_t px)
{
    return px < 4 ? 4 : px > MAX_PX ? MAX_PX : px;
}

static uint32_t slot_hash(uint8_t font, uint16_t px, uint32_t cp)
{
    uint32_t h = cp * 2654435761u;
    h ^= ((uint32_t)px << 8 | font) * 40503u;
    return h % SLOTS;
}

/* Rasterise one glyph into slot g. Returns false when the cache must reset
 * first (slot table or arena is full) or the font is unusable. */
static bool glyph_render(struct glyph *g, enum gui_font f, uint8_t fi, int32_t px, uint32_t cp)
{
    stbtt_fontinfo *fi_ptr = font_info(f);
    if (!fi_ptr) return false;
    float sc = stbtt_ScaleForPixelHeight(fi_ptr, (float)px);
    int adv, lsb, x0, y0, x1, y1;
    stbtt_GetCodepointHMetrics(fi_ptr, (int)cp, &adv, &lsb);
    stbtt_GetCodepointBitmapBox(fi_ptr, (int)cp, sc, sc, &x0, &y0, &x1, &y1);
    uint32_t bw = (uint32_t)(x1 - x0), bh = (uint32_t)(y1 - y0);
    if (g_used_slots >= SLOTS * 3 / 4 || g_arena_used + bw * bh > ARENA_BYTES) return false;
    *g = (struct glyph){ .used = true, .font = fi, .px = (uint16_t)px,
        .cp = cp, .xoff = (int16_t)x0, .yoff = (int16_t)y0,
        .w = (uint16_t)bw, .h = (uint16_t)bh,
        .advance = (int16_t)lroundf((float)adv * sc), .off = g_arena_used };
    if (bw && bh)
        stbtt_MakeCodepointBitmap(fi_ptr, g_arena + g_arena_used, (int)bw, (int)bh, (int)bw, sc, sc, (int)cp);
    g_arena_used += bw * bh;
    g_used_slots++;
    return true;
}

/* Probe for the glyph; fill the first empty slot on a miss. NULL = reset needed. */
static struct glyph *glyph_probe(enum gui_font f, uint8_t fi, int32_t px, uint32_t cp)
{
    uint32_t h = slot_hash(fi, (uint16_t)px, cp);
    for (uint32_t n = 0; n < SLOTS; n++) {
        struct glyph *g = &g_slots[(h + n) % SLOTS];
        if (g->used && g->font == fi && g->px == px && g->cp == cp) return g;
        if (!g->used) return glyph_render(g, f, fi, px, cp) ? g : NULL;
    }
    return NULL;
}

static struct glyph *glyph_get(enum gui_font f, int32_t px, uint32_t cp)
{
    if (cp < 0x20u || cp > 0x7Eu) cp = '?';
    px = clamp_px(px);
    uint8_t fi = f == GUI_FONT_STRONG ? 1 : 0;
    for (int attempt = 0; attempt < 2; attempt++) {
        struct glyph *g = glyph_probe(f, fi, px, cp);
        if (g) return g;
        gui_text_cache_reset(); /* output stays identical: glyphs re-render */
    }
    return NULL;
}

void gui_font_metrics(enum gui_font f, int32_t px, int32_t *ascent,
                      int32_t *descent, int32_t *line_h)
{
    px = clamp_px(px);
    stbtt_fontinfo *fi = font_info(f);
    int a = 0, d = 0, gap = 0;
    float sc = 1.0f;
    if (fi) {
        stbtt_GetFontVMetrics(fi, &a, &d, &gap);
        sc = stbtt_ScaleForPixelHeight(fi, (float)px);
    }
    int32_t asc = (int32_t)lroundf((float)a * sc);
    int32_t des = (int32_t)lroundf((float)-d * sc);
    if (ascent) *ascent = asc;
    if (descent) *descent = des;
    if (line_h) *line_h = asc + des + (int32_t)lroundf((float)gap * sc);
}

int32_t gui_text_width(enum gui_font f, int32_t px, const char *utf8, size_t len)
{
    int32_t w = 0;
    size_t i = 0;
    while (i < len) {
        struct glyph *g = glyph_get(f, px, gui_utf8_next(utf8, len, &i));
        if (g) w += g->advance;
    }
    return w;
}

void gui_text_draw(struct gui_surface *s, enum gui_font f, int32_t px,
                   int32_t x, int32_t baseline_y, const char *utf8, size_t len,
                   uint32_t color)
{
    size_t i = 0;
    while (i < len) {
        struct glyph *g = glyph_get(f, px, gui_utf8_next(utf8, len, &i));
        if (!g) continue;
        for (int32_t gy = 0; gy < g->h; gy++) {
            int32_t y = baseline_y + g->yoff + gy;
            if (y < s->clip.y || y >= s->clip.y + s->clip.h) continue;
            const uint8_t *row = g_arena + g->off + (size_t)gy * g->w;
            for (int32_t gx = 0; gx < g->w; gx++) {
                uint32_t cov = row[gx];
                int32_t xx = x + g->xoff + gx;
                if (!cov || xx < s->clip.x || xx >= s->clip.x + s->clip.w) continue;
                uint32_t *p = &s->px[(size_t)y * (size_t)s->stride + (size_t)xx];
                uint32_t d = *p, ia = 255u - cov;
                uint32_t r = (((d >> 16) & 255u) * ia + ((color >> 16) & 255u) * cov + 127u) / 255u;
                uint32_t gg = (((d >> 8) & 255u) * ia + ((color >> 8) & 255u) * cov + 127u) / 255u;
                uint32_t b = ((d & 255u) * ia + (color & 255u) * cov + 127u) / 255u;
                *p = (r << 16) | (gg << 8) | b;
            }
        }
        x += g->advance;
    }
}

size_t gui_text_fit(enum gui_font f, int32_t px, const char *utf8, size_t len,
                    int32_t max_w)
{
    size_t i = 0, ok = 0;
    int32_t w = 0;
    while (i < len) {
        size_t before = i;
        struct glyph *g = glyph_get(f, px, gui_utf8_next(utf8, len, &i));
        int32_t adv = g ? g->advance : 0;
        if (w + adv > max_w) return before;
        w += adv;
        ok = i;
    }
    return ok;
}

size_t gui_text_index_at_x(enum gui_font f, int32_t px, const char *utf8,
                           size_t len, int32_t x)
{
    size_t i = 0;
    int32_t w = 0;
    while (i < len) {
        size_t before = i;
        struct glyph *g = glyph_get(f, px, gui_utf8_next(utf8, len, &i));
        int32_t adv = g ? g->advance : 0;
        if (x < w + adv / 2) return before;
        w += adv;
    }
    return len;
}
