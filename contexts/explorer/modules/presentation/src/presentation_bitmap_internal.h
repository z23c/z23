/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * Internal bitmap scaling and clipboard image encoding. */
#ifndef ZCL_PRESENTATION_BITMAP_INTERNAL_H
#define ZCL_PRESENTATION_BITMAP_INTERNAL_H
#include "presentation/presentation.h"
#if defined(_WIN32) || defined(__linux__)
bool present_bmp_encode(const struct zcl_present_window_v1 *page,
                        uint8_t **encoded, size_t *encoded_len);
#endif
bool present_png_encode(const struct zcl_present_window_v1 *page,
                        uint8_t **encoded, size_t *encoded_len);
bool present_scale_bitmap(const struct zcl_present_window_v1 *request,
                          int32_t width, int32_t height, uint8_t **out);
#endif
