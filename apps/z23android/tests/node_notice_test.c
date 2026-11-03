/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include "node_notice.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static const char paused[] = "Paused while the phone cools down. It picks up again by itself.";

/* A known line is posted at once, as it is. */
static void known_line_posts_at_once(void)
{
    struct zapp_node_notice n = {0};
    char text[ZAPP_NODE_NOTICE_CAP];
    assert(zapp_node_notice_due(&n, paused, 100, text, sizeof(text)));
    assert(!strcmp(text, paused));
}

/* An empty or missing line is not known yet: the neutral text is posted, and the same unknown state is not posted again. */
static void unknown_line_uses_neutral(void)
{
    struct zapp_node_notice n = {0};
    char text[ZAPP_NODE_NOTICE_CAP];
    assert(zapp_node_notice_due(&n, "", 100, text, sizeof(text)));
    assert(!strcmp(text, ZAPP_NOTICE_NEUTRAL));
    assert(!zapp_node_notice_due(&n, NULL, 200, text, sizeof(text)));
}

/* Unchanged text is never posted again, however long it has been. */
static void unchanged_text_never_posts(void)
{
    struct zapp_node_notice n = {0};
    char text[ZAPP_NODE_NOTICE_CAP];
    assert(zapp_node_notice_due(&n, "Up to date", 100, text, sizeof(text)));
    assert(!zapp_node_notice_due(&n, "Up to date", 5000, text, sizeof(text)));
}

/* Changed text waits for the interval since the last post, then posts the new text. */
static void changed_text_waits_for_interval(void)
{
    struct zapp_node_notice n = {0};
    char text[ZAPP_NODE_NOTICE_CAP];
    assert(zapp_node_notice_due(&n, "Catching up: 800 blocks to go", 100, text, sizeof(text)));
    assert(!zapp_node_notice_due(&n, "Catching up: 790 blocks to go", 129, text, sizeof(text)));
    assert(zapp_node_notice_due(&n, "Catching up: 790 blocks to go", 130, text, sizeof(text)));
    assert(!strcmp(text, "Catching up: 790 blocks to go"));
}

int main(void)
{
    known_line_posts_at_once();
    unknown_line_uses_neutral();
    unchanged_text_never_posts();
    changed_text_waits_for_interval();
    puts("node notice tests passed");
    return 0;
}
