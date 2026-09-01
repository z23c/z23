/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_PNG_WRITER_H
#define ZCL_PNG_WRITER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Write an RGB image as a PNG file. Pure C23, no external dependencies.
 * pixels: row-major RGB bytes (3 bytes per pixel, width*height*3 total).
 * Returns true on success. */
bool png_write_rgb(const char *path, const uint8_t *pixels,
                   uint32_t width, uint32_t height);

#endif
