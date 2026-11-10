/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Decode the bounded local worker offer row. */
#ifndef ZCL_NATIVE_APP_NETWORK_ROW_H
#define ZCL_NATIVE_APP_NETWORK_ROW_H
#include "command/native_app_offer.h"
#include "json/json.h"
/* Strict type read retains empty strings; canonical check compares exact bytes. */
const char *app_network_json_string(const struct json_value *value, const char *key);
bool app_network_json_canonical(const struct json_value *value, const char *wire, size_t len);
/* Compare validated, terminated rows including every offer identity field. */
bool app_network_row_equal(const struct zcl_app_offer_row *a, const struct zcl_app_offer_row *b);
bool app_network_row_decode(const struct json_value *value, struct zcl_app_offer_row *row);
#endif
