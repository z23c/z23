/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded QR matrix encoding and scanner-safe RGB rendering. */

#ifndef ZCL_ENCODING_QR_H
#define ZCL_ENCODING_QR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_QR_MAX_PAYLOAD 2048u
#define ZCL_QR_QUIET_MODULES 4u

struct qr_matrix {
    uint8_t *modules;
    uint32_t width;
};

/* Encode one UTF-8/text payload as a QR symbol at error-correction level M.
 * The returned matrix is row-major; bit 0 is one for a dark module. */
bool qr_matrix_encode(const char *payload, struct qr_matrix *out,
                      char *error, size_t error_cap);
void qr_matrix_free(struct qr_matrix *matrix);

/* Render a scanner-safe RGB image with integer module scaling. The caller
 * owns *pixels and releases it with free(). */
bool qr_matrix_render_rgb(const struct qr_matrix *matrix, uint32_t scale,
                          uint32_t quiet_modules, uint8_t **pixels,
                          uint32_t *side, char *error, size_t error_cap);

bool qr_matrix_backend_available(void);

#endif
