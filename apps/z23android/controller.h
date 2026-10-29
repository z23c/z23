/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_CONTROLLER_H
#define ZAPP_CONTROLLER_H
#include "app.h"
/* notify may finish concurrently with detach; it must guard its own UI handle. */
bool zapp_controller_start(const char *files, const char *libs, void (*notify)(void));
void zapp_controller_snapshot(struct zapp_view *view);
bool zapp_controller_action(const char *action, const char *argument, const char *model);
void zapp_controller_detach(void);
void zapp_controller_pause(void);
#endif
