/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: clipped XRGB8888 primitives. Antialiasing uses integer 4x4
 * subsampling so output is identical on every compiler and libm. */
#include "gui/draw.h"

#include <stdlib.h>

struct gui_surface gui_surface_from_frame(const struct gui_cpu_frame *f)
{
    struct gui_surface s = { .px = f->pixels, .w = f->width, .h = f->height,
                             .stride = f->stride_px };
    s.clip = (struct gui_rect){ 0, 0, f->width, f->height };
    return s;
}

bool gui_rect_intersect(struct gui_rect a, struct gui_rect b,
                        struct gui_rect *out)
{
    int64_t x0 = a.x > b.x ? a.x : b.x;
    int64_t y0 = a.y > b.y ? a.y : b.y;
    int64_t x1 = (int64_t)a.x + a.w < (int64_t)b.x + b.w ? (int64_t)a.x + a.w
                                                          : (int64_t)b.x + b.w;
    int64_t y1 = (int64_t)a.y + a.h < (int64_t)b.y + b.h ? (int64_t)a.y + a.h
                                                          : (int64_t)b.y + b.h;
    if (a.w <= 0 || a.h <= 0 || b.w <= 0 || b.h <= 0 || x1 <= x0 || y1 <= y0) {
        if (out) *out = (struct gui_rect){ 0, 0, 0, 0 };
        return false;
    }
    if (out) *out = (struct gui_rect){ (int32_t)x0, (int32_t)y0,
                                       (int32_t)(x1 - x0), (int32_t)(y1 - y0) };
    return true;
}

struct gui_rect gui_rect_union(struct gui_rect a, struct gui_rect b)
{
    if (a.w <= 0 || a.h <= 0) return b;
    if (b.w <= 0 || b.h <= 0) return a;
    int32_t x0 = a.x < b.x ? a.x : b.x, y0 = a.y < b.y ? a.y : b.y;
    int32_t x1 = a.x + a.w > b.x + b.w ? a.x + a.w : b.x + b.w;
    int32_t y1 = a.y + a.h > b.y + b.h ? a.y + a.h : b.y + b.h;
    return (struct gui_rect){ x0, y0, x1 - x0, y1 - y0 };
}

bool gui_rect_contains(struct gui_rect r, int32_t x, int32_t y)
{
    return x >= r.x && y >= r.y && x < r.x + r.w && y < r.y + r.h;
}

bool gui_clip_push(struct gui_surface *s, struct gui_rect r)
{
    if (s->depth >= GUI_CLIP_DEPTH) return false;
    s->stack[s->depth++] = s->clip;
    struct gui_rect out;
    if (!gui_rect_intersect(s->clip, r, &out)) out = (struct gui_rect){ 0, 0, 0, 0 };
    s->clip = out;
    return true;
}

void gui_clip_pop(struct gui_surface *s)
{
    if (s->depth > 0) s->clip = s->stack[--s->depth];
}

static uint32_t mix(uint32_t dst, uint32_t src, uint32_t a /* 0..255 */)
{
    uint32_t ia = 255u - a;
    uint32_t r = (((dst >> 16) & 255u) * ia + ((src >> 16) & 255u) * a + 127u) / 255u;
    uint32_t g = (((dst >> 8) & 255u) * ia + ((src >> 8) & 255u) * a + 127u) / 255u;
    uint32_t b = ((dst & 255u) * ia + (src & 255u) * a + 127u) / 255u;
    return (r << 16) | (g << 8) | b;
}

static void put_cov(struct gui_surface *s, int32_t x, int32_t y, uint32_t color,
                    uint32_t cov)
{
    if (!cov || !gui_rect_contains(s->clip, x, y)) return;
    uint32_t *p = &s->px[(size_t)y * (size_t)s->stride + (size_t)x];
    *p = cov >= 255u ? color : mix(*p, color, cov);
}

void gui_fill_rect(struct gui_surface *s, struct gui_rect r, uint32_t color)
{
    struct gui_rect c;
    if (!gui_rect_intersect(r, s->clip, &c)) return;
    for (int32_t y = c.y; y < c.y + c.h; y++) {
        uint32_t *row = s->px + (size_t)y * (size_t)s->stride;
        for (int32_t x = c.x; x < c.x + c.w; x++) row[x] = color;
    }
}

void gui_fill_rect_blend(struct gui_surface *s, struct gui_rect r,
                         uint32_t color, uint8_t alpha)
{
    struct gui_rect c;
    if (!gui_rect_intersect(r, s->clip, &c)) return;
    for (int32_t y = c.y; y < c.y + c.h; y++) {
        uint32_t *row = s->px + (size_t)y * (size_t)s->stride;
        for (int32_t x = c.x; x < c.x + c.w; x++)
            row[x] = mix(row[x], color, alpha);
    }
}

/* Coverage 0..255 of pixel (px,py) by a disc of radius r centred at (cx,cy)
 * given in quarter pixels. 16 subsamples, exact integer arithmetic. */
static uint32_t disc_cov(int32_t px, int32_t py, int32_t cx4, int32_t cy4,
                         int32_t r4)
{
    int32_t in = 0;
    for (int32_t sy = 0; sy < 4; sy++)
        for (int32_t sx = 0; sx < 4; sx++) {
            int64_t dx = (int64_t)(px * 4 + sx) * 2 + 1 - (int64_t)cx4 * 2;
            int64_t dy = (int64_t)(py * 4 + sy) * 2 + 1 - (int64_t)cy4 * 2;
            if (dx * dx + dy * dy <= (int64_t)r4 * r4 * 4) in++;
        }
    return (uint32_t)(in * 255 / 16);
}

void gui_fill_round_rect(struct gui_surface *s, struct gui_rect r,
                         int32_t radius, uint32_t color)
{
    if (r.w <= 0 || r.h <= 0) return;
    int32_t rad = radius;
    if (rad > r.w / 2) rad = r.w / 2;
    if (rad > r.h / 2) rad = r.h / 2;
    if (rad <= 0) { gui_fill_rect(s, r, color); return; }
    gui_fill_rect(s, (struct gui_rect){ r.x, r.y + rad, r.w, r.h - 2 * rad }, color);
    gui_fill_rect(s, (struct gui_rect){ r.x + rad, r.y, r.w - 2 * rad, rad }, color);
    gui_fill_rect(s, (struct gui_rect){ r.x + rad, r.y + r.h - rad, r.w - 2 * rad, rad }, color);
    for (int32_t cy = 0; cy < 2; cy++)
        for (int32_t cx = 0; cx < 2; cx++) {
            int32_t ox = cx ? r.x + r.w - rad : r.x;
            int32_t oy = cy ? r.y + r.h - rad : r.y;
            int32_t ccx = cx ? ox : ox + rad; /* corner centre */
            int32_t ccy = cy ? oy : oy + rad;
            for (int32_t y = oy; y < oy + rad; y++)
                for (int32_t x = ox; x < ox + rad; x++)
                    put_cov(s, x, y, color,
                            disc_cov(x, y, ccx * 4, ccy * 4, rad * 4));
        }
}

void gui_stroke_rect(struct gui_surface *s, struct gui_rect r, int32_t t,
                     uint32_t color)
{
    if (t <= 0 || r.w <= 0 || r.h <= 0) return;
    if (t * 2 >= r.w || t * 2 >= r.h) { gui_fill_rect(s, r, color); return; }
    gui_fill_rect(s, (struct gui_rect){ r.x, r.y, r.w, t }, color);
    gui_fill_rect(s, (struct gui_rect){ r.x, r.y + r.h - t, r.w, t }, color);
    gui_fill_rect(s, (struct gui_rect){ r.x, r.y + t, t, r.h - 2 * t }, color);
    gui_fill_rect(s, (struct gui_rect){ r.x + r.w - t, r.y + t, t, r.h - 2 * t }, color);
}

void gui_line(struct gui_surface *s, int32_t x0, int32_t y0, int32_t x1,
              int32_t y1, uint32_t color)
{
    int32_t dx = abs(x1 - x0), dy = -abs(y1 - y0);
    int32_t sx = x0 < x1 ? 1 : -1, sy = y0 < y1 ? 1 : -1;
    int32_t err = dx + dy;
    for (int guard = 0; guard < 1 << 20; guard++) {
        put_cov(s, x0, y0, color, 255u);
        if (x0 == x1 && y0 == y1) break;
        int32_t e2 = 2 * err;
        if (e2 >= dy) { err += dy; x0 += sx; }
        if (e2 <= dx) { err += dx; y0 += sy; }
    }
}

void gui_fill_circle(struct gui_surface *s, int32_t cx, int32_t cy,
                     int32_t radius, uint32_t color)
{
    if (radius <= 0) return;
    for (int32_t y = cy - radius; y <= cy + radius; y++)
        for (int32_t x = cx - radius; x <= cx + radius; x++)
            put_cov(s, x, y, color,
                    disc_cov(x, y, cx * 4 + 2, cy * 4 + 2, radius * 4));
}

void gui_blit_mask(struct gui_surface *s, struct gui_rect dst,
                   const uint8_t *mask, int32_t mw, int32_t mh, uint32_t color)
{
    if (!mask || mw <= 0 || mh <= 0 || dst.w <= 0 || dst.h <= 0) return;
    for (int32_t y = 0; y < dst.h; y++)
        for (int32_t x = 0; x < dst.w; x++) {
            int32_t mx = (int32_t)((int64_t)x * mw / dst.w);
            int32_t my = (int32_t)((int64_t)y * mh / dst.h);
            if (mask[(size_t)my * (size_t)mw + (size_t)mx])
                put_cov(s, dst.x + x, dst.y + y, color, 255u);
        }
}
