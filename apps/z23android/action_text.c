/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* The words of an owner tap: what each queued action is doing, and the plain reason for each refusal. */
#include "action_text.h"
#include <stdio.h>
#include <string.h>

/* own: the action's screen shows its progress itself. */
static const struct { const char *action, *doing; bool own; } actions[] = {
    {"node_start", "Starting your node…", false},
    {"node_stop", "Stopping your node…", false},
    {"fleet_join", "Joining the fleet…", false},
    {"fleet_hosts", "Checking the fleet…", false},
    {"fleet_preview", "Reading the invitation…", false},
    {"voice_pair", "Pairing with the laptop…", false},
    {"chat", "Answering your question…", true},
    {"voice_start", "Listening…", true},
    {"scan", "Reading a code…", true},
    {"ops_errors", "Asking the host…", true},
    {"ops_plugins", "Reading plugin inventory…", true},
    {"ops_restart", "Asking the host…", true},
    {"ops_confirm", "Asking the host…", true},
};
static int action_index(const char *action)
{
    for (size_t i = 0; action && i < sizeof(actions) / sizeof(actions[0]); ++i)
        if (!strcmp(action, actions[i].action)) return (int)i;
    return -1;
}
const char *zapp_action_doing(const char *action)
{
    int i = action_index(action);
    return i < 0 ? NULL : actions[i].doing;
}
bool zapp_action_shows_itself(const char *action)
{
    int i = action_index(action);
    return i >= 0 && actions[i].own;
}
static const char *const reasons[] = {
    [ZAPP_REFUSAL_NOT_READY] = "The app is still opening. Tap again in a moment.",
    [ZAPP_REFUSAL_UNKNOWN] = "This version of the app has no such action.",
    [ZAPP_REFUSAL_TOO_LONG] = "That is too long. Make it shorter and tap again.",
    [ZAPP_REFUSAL_NO_QUESTION] = "Type a question first.",
    [ZAPP_REFUSAL_NO_INVITATION] = "Scan a fleet invitation first.",
    [ZAPP_REFUSAL_NO_OFFER] = "No laptop is offering to pair. Restart the laptop host to offer pairing again.",
    [ZAPP_REFUSAL_BAD_OFFER] = "That pairing offer could not be read. Restart the laptop host to offer pairing again.",
    [ZAPP_REFUSAL_NO_PROPOSAL] = "Nothing is waiting to be confirmed.",
    [ZAPP_REFUSAL_NO_HOST] = "No fleet host is listed yet.",
    [ZAPP_REFUSAL_NO_PLAN] = "Ask for a restart plan first, then confirm it.",
};
void zapp_action_refusal(enum zapp_refusal why, const char *running, const char *asked, char *out, size_t cap)
{
    if (!out || !cap) return;
    const char *doing = zapp_action_doing(running);
    if (why == ZAPP_REFUSAL_BUSY && doing && asked && !strcmp(asked, running)) snprintf(out, cap, "%s", doing);
    else if (why == ZAPP_REFUSAL_BUSY) snprintf(out, cap, "%s Tap again when it is done.", doing ? doing : "Another action is running.");
    else if (why > ZAPP_REFUSAL_BUSY && why <= ZAPP_REFUSAL_NO_PLAN) snprintf(out, cap, "%s", reasons[why]);
    else out[0] = 0;
}
