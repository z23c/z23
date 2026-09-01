/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded QR matrix encoding and dependency-free RGB rendering. */

#include "encoding/qr.h"
#include "base/safe_alloc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../vendor/qrcodegen/qrcodegen.h"

static void qr_error(char *error, size_t cap, const char *message)
{
    if (error && cap > 0)
        snprintf(error, cap, "%s", message ? message : "QR operation failed");
}

bool qr_matrix_backend_available(void)
{
    return true;
}

bool qr_matrix_encode(const char *payload, struct qr_matrix *out,
                      char *error, size_t error_cap)
{
    if (!out) {
        qr_error(error, error_cap, "missing QR output matrix");
        return false;
    }
    out->modules = NULL;
    out->width = 0;
    if (!payload || !payload[0]) {
        qr_error(error, error_cap, "QR payload must not be empty");
        return false;
    }
    size_t payload_len = strnlen(payload, ZCL_QR_MAX_PAYLOAD + 1u);
    if (payload_len > ZCL_QR_MAX_PAYLOAD) {
        qr_error(error, error_cap, "QR payload exceeds 2048 bytes");
        return false;
    }

    uint8_t work[qrcodegen_BUFFER_LEN_MAX];
    uint8_t encoded[qrcodegen_BUFFER_LEN_MAX];
    memcpy(work, payload, payload_len);
    if (!qrcodegen_encodeBinary(work, payload_len, encoded,
                                qrcodegen_Ecc_MEDIUM,
                                qrcodegen_VERSION_MIN,
                                qrcodegen_VERSION_MAX,
                                qrcodegen_Mask_AUTO, false)) {
        qr_error(error, error_cap, "QR encoder rejected the payload");
        return false;
    }
    int encoded_width = qrcodegen_getSize(encoded);
    uint32_t width = encoded_width > 0 ? (uint32_t)encoded_width : 0;
    if (width > 177u || (size_t)width > SIZE_MAX / (size_t)width) {
        qr_error(error, error_cap, "QR encoder returned an invalid matrix");
        return false;
    }
    size_t count = (size_t)width * (size_t)width;
    uint8_t *modules = zcl_malloc(count, "qr.matrix.modules");
    for (uint32_t y = 0; y < width; y++) {
        for (uint32_t x = 0; x < width; x++) {
            modules[(size_t)y * width + x] =
                qrcodegen_getModule(encoded, (int)x, (int)y) ? 1u : 0u;
        }
    }
    out->modules = modules;
    out->width = width;
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}

void qr_matrix_free(struct qr_matrix *matrix)
{
    if (!matrix) return;
    free(matrix->modules);
    matrix->modules = NULL;
    matrix->width = 0;
}

bool qr_matrix_render_rgb(const struct qr_matrix *matrix, uint32_t scale,
                          uint32_t quiet_modules, uint8_t **pixels,
                          uint32_t *side, char *error, size_t error_cap)
{
    if (pixels) *pixels = NULL;
    if (side) *side = 0;
    if (!matrix || !matrix->modules || matrix->width == 0 || !pixels ||
        !side || scale == 0 || scale > 64u || quiet_modules > 32u) {
        qr_error(error, error_cap, "invalid QR render arguments");
        return false;
    }
    uint64_t module_side = (uint64_t)matrix->width + 2u * quiet_modules;
    uint64_t image_side = module_side * scale;
    uint64_t bytes = image_side * image_side * 3u;
    if (image_side == 0 || image_side > UINT32_MAX || bytes > SIZE_MAX) {
        qr_error(error, error_cap, "QR render dimensions overflow");
        return false;
    }
    uint8_t *rgb = zcl_malloc((size_t)bytes, "qr.render.rgb");
    memset(rgb, 0xff, (size_t)bytes);
    uint32_t out_side = (uint32_t)image_side;
    for (uint32_t my = 0; my < matrix->width; my++) {
        for (uint32_t mx = 0; mx < matrix->width; mx++) {
            if (!(matrix->modules[(size_t)my * matrix->width + mx] & 1u))
                continue;
            uint32_t y0 = (my + quiet_modules) * scale;
            uint32_t x0 = (mx + quiet_modules) * scale;
            for (uint32_t py = 0; py < scale; py++) {
                size_t offset = ((size_t)(y0 + py) * out_side + x0) * 3u;
                memset(rgb + offset, 0, (size_t)scale * 3u);
            }
        }
    }
    *pixels = rgb;
    *side = out_side;
    if (error && error_cap > 0) error[0] = '\0';
    return true;
}
