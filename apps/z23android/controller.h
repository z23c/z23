/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_CONTROLLER_H
#define ZAPP_CONTROLLER_H
#include "app.h"
/* notify may finish concurrently with detach; it must guard its own UI handle. */
bool zapp_controller_start(const char *files, const char *libs, bool preview, void (*notify)(void));
void zapp_controller_snapshot(struct zapp_view *view);
bool zapp_controller_action(const char *action, const char *argument, const char *model);
void zapp_controller_detach(void);
/* Hidden, the app cancels voice and stops observing the node and fleet, which keep running on
 * their own; shown again, it observes at once. */
void zapp_controller_visible(bool visible);
/* True while the node process runs; safe from any thread, with or without an activity. */
bool zapp_controller_node_running(void);
#endif
