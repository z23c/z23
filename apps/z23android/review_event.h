/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZAPP_REVIEW_EVENT_H
#define ZAPP_REVIEW_EVENT_H
#include <stdbool.h>
#include <stdint.h>
/* Check before reading an FD: removed looper callbacks can still be delivered. */
static bool zapp_review_event_matches(uintptr_t current, bool active, int expected,
                                      uintptr_t received, int fd)
{
    return current && active && current == received && expected == fd;
}
/* Taking a wake retires both registrations before either FD can be removed. */
static bool zapp_review_take_wake(uintptr_t current, int expected, uintptr_t received, int fd,
                                  bool *wake_active, bool *timer_active, bool *remove_timer)
{
    if (!zapp_review_event_matches(current, *wake_active, expected, received, fd)) return false;
    *wake_active = false;
    *remove_timer = *timer_active;
    *timer_active = false;
    return true;
}
#endif
