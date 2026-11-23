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
#endif
