/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_APP_H
#define Z23_ANDROID_APP_H
#include <stdbool.h>
#include <stddef.h>

#define ZAPP_TEXT_CAP 65536
#define ZAPP_ERROR_CAP 256

struct zapp_operation {
    const char *id;
    const char *label;
    const char *description;
    const char *category;
};
const struct zapp_operation *zapp_operations(size_t *count);

enum zapp_reply_state { ZAPP_REPLY_READY, ZAPP_REPLY_WAITING, ZAPP_REPLY_CANCELLING };

struct zapp_view {
    char notice[512];
    char output[ZAPP_TEXT_CAP];
    char transcript[ZAPP_TEXT_CAP];
    char hardware[1024];
    char connection[256];
    char sync_status[1024];
    char balance[512];
    bool balance_known;
    bool balance_stale;
    char fleet_token[8192];
    char fleet_preview[2048];
    char fleet_receipt[8192];
    char fleet_status[8192];
    bool busy;
    bool node_running;
    bool scanning;
    enum zapp_reply_state reply_state;
};
#endif
