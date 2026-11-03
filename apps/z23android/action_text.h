/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* What an owner tap shows at once: what a queued action is doing, and why a tap that was not queued was refused. */
#ifndef ZAPP_ACTION_TEXT_H
#define ZAPP_ACTION_TEXT_H
#include <stdbool.h>
#include <stddef.h>

/* Why the controller did not queue a tap. */
enum zapp_refusal {
    ZAPP_REFUSAL_NONE,
    ZAPP_REFUSAL_BUSY,          /* Another action is still running. */
    ZAPP_REFUSAL_NOT_READY,     /* The controller has not started. */
    ZAPP_REFUSAL_UNKNOWN,       /* No such action. */
    ZAPP_REFUSAL_TOO_LONG,      /* The text given with it is too long. */
    ZAPP_REFUSAL_NO_QUESTION,   /* A question with no text. */
    ZAPP_REFUSAL_NO_INVITATION, /* Join with no invitation reviewed. */
    ZAPP_REFUSAL_NO_OFFER,      /* Accept with no pairing offer waiting. */
    ZAPP_REFUSAL_BAD_OFFER,     /* A pairing offer that could not be read. */
    ZAPP_REFUSAL_NO_PROPOSAL,   /* Confirm with nothing proposed. */
    ZAPP_REFUSAL_NO_HOST,       /* A host control with no fleet host chosen. */
    ZAPP_REFUSAL_NO_PLAN        /* Confirm restart with no plan asked for. */
};
/* What a queued action is doing, such as "Starting your node…"; NULL for an action the app does not have. */
const char *zapp_action_doing(const char *action);
/* Whether the action's own screen already shows its progress (the camera, the question, the voice line, the host controls),
 * so no notice repeats it. */
bool zapp_action_shows_itself(const char *action);
/* The plain reason for a refused tap of asked. A busy refusal names what running is doing: alone when asked is the same
 * action, else with when to tap again. */
void zapp_action_refusal(enum zapp_refusal why, const char *running, const char *asked, char *out, size_t cap);
#endif
