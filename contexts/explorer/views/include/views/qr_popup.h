/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: local native presentation of bounded QR payloads. */

#ifndef ZCL_VIEWS_QR_POPUP_H
#define ZCL_VIEWS_QR_POPUP_H

#include "presentation/model.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCL_QR_POPUP_CARD_WIDTH 440u
#define ZCL_QR_POPUP_CARD_HEIGHT 660u
#define ZCL_QR_POPUP_CARD_BYTES \
    (ZCL_QR_POPUP_CARD_WIDTH * ZCL_QR_POPUP_CARD_HEIGHT * 3u)

struct qr_popup_card {
    uint8_t *pixels;
    uint32_t width;
    uint32_t height;
    bool is_deposit;
    char address[192];
    char amount[64];
};

/* Compose the QR specialization of the shared bounded visual model. The
 * caller owns pixels and releases them with qr_popup_card_free(). */
bool qr_popup_card_render(const struct zcl_present_model_v1 *model,
                          struct qr_popup_card *out,
                          char *error, size_t error_cap);
void qr_popup_card_free(struct qr_popup_card *card);

#endif
