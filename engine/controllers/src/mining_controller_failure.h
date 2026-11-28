/* purpose: Render a complete partial mining failure for RPC clients. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_MINING_CONTROLLER_FAILURE_H
#define ZCL_MINING_CONTROLLER_FAILURE_H
static char *mining_failure_message(const struct json_value *hashes, int height,
                                    const struct validation_state *state)
{
    char reason[MAX_REJECT_REASON + 64], prefix[MAX_REJECT_REASON + 160];
    format_state_message(state, reason, sizeof(reason));
    int written = snprintf(prefix, sizeof(prefix), "Mining failed at height %d: %s; accepted hashes: ",
                           height, reason[0] ? reason : "reducer rejected block");
    if (written < 0 || (size_t)written >= sizeof(prefix)) return NULL;
    size_t len = json_write(hashes, NULL, 0);
    if (len > SIZE_MAX - (size_t)written - 1) return NULL;
    char *message = zcl_malloc((size_t)written + len + 1, "mining failure message");
    if (!message) return NULL;
    memcpy(message, prefix, (size_t)written);
    if (json_write(hashes, message + written, len + 1) != len) {
        free(message);
        return NULL;
    }
    return message;
}
#endif
