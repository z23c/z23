/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_CONVERSATION_H
#define Z23_ANDROID_CONVERSATION_H
#include <stdbool.h>
#include <stddef.h>
#define ZAPP_CONVERSATION_CAP 16001
#define ZAPP_HISTORY_CAP 4096
#define ZAPP_HISTORY_TURNS 32
struct json_value;
/* Earlier exchanges, oldest first, stored as NUL-terminated question and answer strings. */
struct zapp_history {
    char text[ZAPP_HISTORY_CAP];
    size_t used, turns;
};
struct zapp_conversation_snapshot {
    char sync_status[1024];
    char balance[512];
    bool balance_known, balance_stale, node_running;
};
bool zapp_conversation_format(const struct zapp_conversation_snapshot *snapshot,
                              const char *question, char *out, size_t cap);
/* Appends one exchange; false if it cannot fit. A full history first drops its oldest exchanges
 * down to half its capacity, so the retained exchanges stay an unchanged prefix for many turns. */
bool zapp_history_append(struct zapp_history *h, const char *question, const char *answer);
/* Writes the history as a JSON array of [question, answer] pairs. */
bool zapp_history_json(const struct zapp_history *h, struct json_value *out);
/* Puts one exchange before the shown conversation, newest first. When it does not fit, whole
 * older exchanges are dropped from the end; an exchange larger than the buffer replaces it with
 * as much of the answer as fits. */
void zapp_transcript_prepend(char *text, size_t cap, const char *question, const char *answer);
/* Renders the stored transcript as HTML for android.text.Html: the newest question muted and its
 * answer plain, earlier exchanges small and muted. Older exchanges that do not fit are dropped;
 * false with an empty out when even the newest does not fit. */
bool zapp_transcript_html(const char *transcript, char *out, size_t cap);
#endif
