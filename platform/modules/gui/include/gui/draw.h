/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: software drawing on an XRGB8888 surface, UTF-8 helpers and
 * antialiased text (Inter through stb_truetype). All sizes are physical px. */
#ifndef ZCL_GUI_DRAW_H
#define ZCL_GUI_DRAW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "gui/window.h"

#define GUI_CLIP_DEPTH 16

struct gui_surface {
    uint32_t *px;
    int32_t w, h, stride;
    struct gui_rect clip;
    struct gui_rect stack[GUI_CLIP_DEPTH];
    int depth;
};

static inline uint32_t gui_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    return ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

/* UTF-8. Invalid, overlong and surrogate sequences decode as U+FFFD and
 * consume one byte. gui_utf8_next advances *i past one scalar. */
uint32_t gui_utf8_next(const char *s, size_t len, size_t *i);
size_t gui_utf8_encode(uint32_t cp, char out[4]);
/* Largest codepoint boundary strictly below i (0 when i == 0). */
size_t gui_utf8_prev(const char *s, size_t len, size_t i);
bool gui_utf8_valid(const char *s, size_t len);

struct gui_surface gui_surface_from_frame(const struct gui_cpu_frame *f);
bool gui_rect_intersect(struct gui_rect a, struct gui_rect b,
                        struct gui_rect *out);
struct gui_rect gui_rect_union(struct gui_rect a, struct gui_rect b);
bool gui_rect_contains(struct gui_rect r, int32_t x, int32_t y);

/* The new clip is the intersection with the current one. */
bool gui_clip_push(struct gui_surface *s, struct gui_rect r);
void gui_clip_pop(struct gui_surface *s);

void gui_fill_rect(struct gui_surface *s, struct gui_rect r, uint32_t color);
void gui_fill_rect_blend(struct gui_surface *s, struct gui_rect r,
                         uint32_t color, uint8_t alpha);
void gui_fill_round_rect(struct gui_surface *s, struct gui_rect r,
                         int32_t radius, uint32_t color);
void gui_stroke_rect(struct gui_surface *s, struct gui_rect r,
                     int32_t thickness, uint32_t color);
void gui_line(struct gui_surface *s, int32_t x0, int32_t y0, int32_t x1,
              int32_t y1, uint32_t color);
void gui_fill_circle(struct gui_surface *s, int32_t cx, int32_t cy,
                     int32_t radius, uint32_t color);
/* 1-bit modules (row-major, one byte per module, nonzero = dark). */
void gui_blit_mask(struct gui_surface *s, struct gui_rect dst,
                   const uint8_t *mask, int32_t mw, int32_t mh, uint32_t color);

enum gui_font { GUI_FONT_TEXT, GUI_FONT_STRONG };

void gui_font_metrics(enum gui_font f, int32_t px, int32_t *ascent,
                      int32_t *descent, int32_t *line_h);
int32_t gui_text_width(enum gui_font f, int32_t px, const char *utf8,
                       size_t len);
void gui_text_draw(struct gui_surface *s, enum gui_font f, int32_t px,
                   int32_t x, int32_t baseline_y, const char *utf8, size_t len,
                   uint32_t color);
/* Bytes of utf8 that fit in max_w (callers append "..." for ellipsis). */
size_t gui_text_fit(enum gui_font f, int32_t px, const char *utf8, size_t len,
                    int32_t max_w);
/* Codepoint boundary nearest to x (for caret hit-testing). */
size_t gui_text_index_at_x(enum gui_font f, int32_t px, const char *utf8,
                           size_t len, int32_t x);
/* Number of times the glyph cache was reset (test hook). */
size_t gui_text_cache_resets(void);
void gui_text_cache_reset(void);

#endif
