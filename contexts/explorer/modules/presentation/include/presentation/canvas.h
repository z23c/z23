/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded dependency-free software canvas for native presentations. */

#ifndef ZCL_PRESENTATION_CANVAS_H
#define ZCL_PRESENTATION_CANVAS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZCL_PRESENT_CANVAS_DIMENSION_MAX 4096u

struct zcl_present_color {
    uint8_t r;
    uint8_t g;
    uint8_t b;
};

struct zcl_present_canvas {
    uint8_t *pixels;
    uint32_t width;
    uint32_t height;
    size_t stride;
};

/* Canvas storage is caller-owned RGB8. Every drawing operation clips to the
 * canvas, so reviewed presentation clients can safely compose cards, balance
 * panels, metadata, and charts without a GUI toolkit. */
bool zcl_present_canvas_init(struct zcl_present_canvas *canvas,
                             uint8_t *pixels, size_t pixels_cap,
                             uint32_t width, uint32_t height);
void zcl_present_canvas_clear(struct zcl_present_canvas *canvas,
                              struct zcl_present_color color);
void zcl_present_canvas_fill_rect(struct zcl_present_canvas *canvas,
                                  int32_t x, int32_t y,
                                  uint32_t width, uint32_t height,
                                  struct zcl_present_color color);
void zcl_present_canvas_stroke_rect(struct zcl_present_canvas *canvas,
                                    int32_t x, int32_t y,
                                    uint32_t width, uint32_t height,
                                    uint32_t thickness,
                                    struct zcl_present_color color);
void zcl_present_canvas_line(struct zcl_present_canvas *canvas,
                             int32_t x0, int32_t y0,
                             int32_t x1, int32_t y1,
                             struct zcl_present_color color);
void zcl_present_canvas_blit_rgba(struct zcl_present_canvas *canvas,
                                  int32_t x, int32_t y,
                                  const uint8_t *rgba,
                                  uint32_t width, uint32_t height);

/* Basic Latin text uses the embedded Noto Sans subset and antialiased software
 * rasterization. pixel_height is an integer from 8 through 96. Unsupported
 * bytes render as '?'. */
uint32_t zcl_present_canvas_text_width(const char *text, size_t text_len,
                                       uint32_t pixel_height);
void zcl_present_canvas_text(struct zcl_present_canvas *canvas,
                             int32_t x, int32_t y,
                             const char *text, size_t text_len,
                             uint32_t pixel_height,
                             struct zcl_present_color color);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_PRESENTATION_CANVAS_H */
