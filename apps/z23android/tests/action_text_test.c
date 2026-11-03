/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
/* Host test of the words an owner tap shows: each queued action says what it does, and each refusal says why. */
#include "action_text.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char *const queued[] = {"node_start", "node_stop", "fleet_join", "fleet_hosts", "fleet_preview", "voice_pair",
                                     "chat", "voice_start", "scan", "ops_errors", "ops_restart", "ops_confirm"};

/* Every action the controller queues has a few words that end in an ellipsis. */
static void doing_tests(void)
{
    for (size_t i = 0; i < sizeof(queued) / sizeof(queued[0]); ++i) {
        const char *doing = zapp_action_doing(queued[i]);
        size_t n = doing ? strlen(doing) : 0;
        assert(n > 3 && n < 40 && !strcmp(doing + n - 3, "…"));
    }
    assert(!strcmp(zapp_action_doing("node_start"), "Starting your node…"));
    assert(!strcmp(zapp_action_doing("node_stop"), "Stopping your node…"));
    assert(!zapp_action_doing("pair_accept") && !zapp_action_doing("") && !zapp_action_doing(NULL));
    /* The camera, the question, the voice line and the host controls show their own progress; node and fleet taps do not. */
    assert(zapp_action_shows_itself("scan") && zapp_action_shows_itself("chat") && zapp_action_shows_itself("voice_start"));
    assert(zapp_action_shows_itself("ops_confirm") && !zapp_action_shows_itself("node_start"));
    assert(!zapp_action_shows_itself("fleet_join") && !zapp_action_shows_itself("unknown"));
}

/* A refusal is a plain sentence of its own, never the old bare refusal, and a busy one names what runs. */
static void refusal_tests(void)
{
    char text[160], other[160];
    zapp_action_refusal(ZAPP_REFUSAL_BUSY, "node_start", "node_start", text, sizeof(text));
    assert(!strcmp(text, "Starting your node…"));
    zapp_action_refusal(ZAPP_REFUSAL_BUSY, "fleet_hosts", "node_start", text, sizeof(text));
    assert(!strcmp(text, "Checking the fleet… Tap again when it is done."));
    zapp_action_refusal(ZAPP_REFUSAL_BUSY, "", "node_stop", text, sizeof(text));
    assert(!strcmp(text, "Another action is running. Tap again when it is done."));
    for (int a = ZAPP_REFUSAL_BUSY; a <= ZAPP_REFUSAL_NO_PLAN; ++a) {
        zapp_action_refusal((enum zapp_refusal)a, "chat", "node_start", text, sizeof(text));
        assert(text[0] && text[strlen(text) - 1] == '.' && strlen(text) < 160 && !strstr(text, "Unable to start"));
        for (int b = a + 1; b <= ZAPP_REFUSAL_NO_PLAN; ++b) {
            zapp_action_refusal((enum zapp_refusal)b, "chat", "node_start", other, sizeof(other));
            assert(strcmp(text, other));
        }
    }
    zapp_action_refusal(ZAPP_REFUSAL_NOT_READY, "", "node_start", text, sizeof(text));
    assert(strstr(text, "still opening"));
    zapp_action_refusal(ZAPP_REFUSAL_NONE, "", "node_start", text, sizeof(text));
    assert(!text[0]);
    zapp_action_refusal(ZAPP_REFUSAL_NO_QUESTION, "", "chat", text, 8);
    assert(strlen(text) == 7);
    zapp_action_refusal(ZAPP_REFUSAL_BUSY, "node_start", "node_start", NULL, 0);
}

int main(void)
{
    doing_tests();
    refusal_tests();
    puts("action_text_test: ok");
    return 0;
}
