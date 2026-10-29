/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_CONVERSATION_H
#define Z23_ANDROID_CONVERSATION_H
#include <stdbool.h>
#include <stddef.h>
#define ZAPP_CONVERSATION_CAP 16001
struct zapp_conversation_snapshot {
    char sync_status[1024];
    char balance[512];
    char history[4096]; /* Recent exchanges, oldest first; empty when none. */
    bool balance_known, balance_stale, node_running;
};
bool zapp_conversation_format(const struct zapp_conversation_snapshot *snapshot,
                              const char *question, char *out, size_t cap);
#endif
