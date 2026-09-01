/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: scope sticky recovery auto-arming to actual chain work. */
#ifndef SERVICES_STICKY_ESCALATOR_TRIGGER_H
#define SERVICES_STICKY_ESCALATOR_TRIGGER_H

#include <stdbool.h>
#include <stdint.h>

struct main_state;

/* The generic CRITICAL-backlog safety net may arm chain recovery only while
 * there is positively pending chain work above H*. Explicit named stall
 * signals retain their own authority and do not pass through this gate. */
bool sticky_trigger_auto_arm_allowed(struct main_state *ms, int64_t hstar,
                                     int unresolved_critical);

bool sticky_trigger_auto_arm_suppressed(void);
uint64_t sticky_trigger_auto_arm_suppressions(void);

#ifdef ZCL_TESTING
void sticky_trigger_test_reset(void);
void sticky_trigger_test_set_pending_work(int override_value);
#endif

#endif /* SERVICES_STICKY_ESCALATOR_TRIGGER_H */
