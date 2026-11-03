/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_NODE_NOTICE_H
#define ZAPP_NODE_NOTICE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Shown when the node line is not known yet. It is true whatever the node is doing. */
#define ZAPP_NOTICE_NEUTRAL "Your node keeps running while the app is hidden."
#define ZAPP_NOTICE_INTERVAL_SECS 30
#define ZAPP_NODE_NOTICE_CAP 160

struct zapp_node_notice {
    char text[ZAPP_NODE_NOTICE_CAP]; /* The text last posted. */
    bool posted;
    int64_t posted_at;          /* Monotonic seconds of the last post. */
};

/* Decides whether the foreground notification is posted now. The text is the node line, or the neutral text
 * when the line is empty. The first call posts at once; later calls post only when the text differs from the
 * last posted text and ZAPP_NOTICE_INTERVAL_SECS have passed since that post. When it returns true, text (cap
 * bytes) holds the text to post. */
bool zapp_node_notice_due(struct zapp_node_notice *n, const char *line, int64_t now, char *text, size_t cap);

/* What the controller worker does on each wait. While hidden the notification is a screen, so the node is observed every
 * ZAPP_NOTICE_INTERVAL_SECS and the fleet is not observed; while shown it keeps visible_secs and observes the node and the fleet. */
struct zapp_worker_step {
    unsigned wait_secs;
    bool observe_fleet;
};
struct zapp_worker_step zapp_worker_step_for(bool hidden, unsigned visible_secs);
#endif
