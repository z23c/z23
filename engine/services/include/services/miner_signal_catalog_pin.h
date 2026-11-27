/* purpose: Load an owned, digest-bound miner ballot catalog. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_MINER_SIGNAL_CATALOG_PIN_H
#define ZCL_SERVICES_MINER_SIGNAL_CATALOG_PIN_H
#include "services/miner_signal_catalog.h"

/* Owned immutable pin: no pointer refers to input JSON or another object. */
struct miner_signal_catalog_pin {
    uint8_t network_id[32], genesis[32], digest[32];
    int32_t start, window;
    size_t count;
    struct miner_signal_catalog_entry entries[256];
};
struct json_value;
/* Parse the four typed manifest fields; output is untouched on failure. */
struct zcl_result miner_signal_catalog_pin_parse(
    const struct json_value *fork, const struct json_value *start,
    const struct json_value *window, const struct json_value *rules,
    const uint8_t genesis[32], struct miner_signal_catalog_pin *out);
/* Load <datadir>/ballots/<lowercase digest>.json, bound to genesis and digest. */
struct zcl_result miner_signal_catalog_pin_load(
    const char *datadir, const char *digest_hex, const uint8_t genesis[32],
    struct miner_signal_catalog_pin *out);
/* Derive one schedule from the owned pin; verifies the pin remains coherent. */
struct zcl_result miner_signal_catalog_pin_select(
    const struct miner_signal_catalog_pin *pin, size_t slot,
    struct miner_signal_schedule *out);
#endif
