/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_APP_H
#define Z23_ANDROID_APP_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZAPP_TEXT_CAP 65536
#define ZAPP_NOTICE_CAP 1024u
#define ZAPP_ERROR_CAP 256

enum zapp_reply_state { ZAPP_REPLY_READY, ZAPP_REPLY_WAITING, ZAPP_REPLY_CANCELLING };
enum zapp_voice_state { ZAPP_VOICE_READY, ZAPP_VOICE_RECORDING, ZAPP_VOICE_TRANSCRIBING,
    ZAPP_VOICE_OBSERVING, ZAPP_VOICE_SYNTHESIZING, ZAPP_VOICE_PLAYING, ZAPP_VOICE_CANCELLING };

struct zapp_view {
    char notice[ZAPP_NOTICE_CAP];
    char result[ZAPP_NOTICE_CAP];
    char transcript[ZAPP_TEXT_CAP];
    char connection[256];
    char sync_status[1024];
    char balance[512];
    bool balance_known;
    bool balance_stale;
    char fleet_token[8192];
    char fleet_preview[2048];
    char fleet_receipt[8192];
    char fleet_status[8192];
    bool fleet_stale;
    bool busy;
    bool node_running;
    bool node_process_running;
    bool node_wanted;
    bool scanning;
    enum zapp_reply_state reply_state;
    enum zapp_voice_state voice_state;
    char voice_status[256];
    char voice_proposal[32];
    char pair_offer[256]; /* Descriptor offered over USB, awaiting the owner's decision. */
    char pair_code[8];
    char node_line[96]; /* One-line phone node summary for the main screen. */
};
#endif
