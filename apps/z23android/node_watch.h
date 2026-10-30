/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef Z23_ANDROID_NODE_WATCH_H
#define Z23_ANDROID_NODE_WATCH_H
#include <stdbool.h>

struct node_watch_ops {
    bool (*alive)(void *context); /* True while the node runs. */
    bool (*gone)(void *context); /* Called on the watch thread when the node is gone; false retries on the next tick. */
    void *context;
    unsigned interval_ms;
};

/* Replaces any running watch with one that calls ops->alive every interval until the node is gone
 * and gone() has handled it, or the watch is stopped. A stop that arrives first suppresses gone(). */
bool zapp_node_watch_start(const struct node_watch_ops *ops);
/* Stops the watch and waits for its thread. A no-op without a watch. */
void zapp_node_watch_stop(void);
#endif
