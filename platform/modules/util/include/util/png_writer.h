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

/* Write row-major RGBA bytes without dropping or re-packing alpha. */
bool png_write_rgba(const char *path, const uint8_t *pixels,
                    uint32_t width, uint32_t height);

/* Encode a complete PNG into caller-owned memory. output=NULL reports the
 * exact required size through written without writing bytes. */
bool png_encode_rgb(const uint8_t *pixels, uint32_t width, uint32_t height,
                    uint8_t *output, size_t output_cap, size_t *written);
bool png_encode_rgba(const uint8_t *pixels, uint32_t width, uint32_t height,
                     uint8_t *output, size_t output_cap, size_t *written);

#endif
