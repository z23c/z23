/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Self-verified resnapshot rung and its one-dispatch completion gate. */

#ifndef ZCL_SERVICES_STICKY_ESCALATOR_RESNAPSHOT_H
#define ZCL_SERVICES_STICKY_ESCALATOR_RESNAPSHOT_H

#include "services/sticky_escalator.h"

#include <stdbool.h>
#include <stdint.h>

struct main_state;

enum sticky_resnapshot_gate_decision {
    STICKY_RESNAPSHOT_INVOKE = 0,
    STICKY_RESNAPSHOT_HOLD,
    STICKY_RESNAPSHOT_COMPLETE,
};

/* A resnapshot rewinds a range and therefore runs once per rung entry.  A
 * second caller holds while the synchronous dispatch is running; after it
 * lands, callers hold until the fold regains the pre-rewind entry frontier. */
void sticky_resnapshot_gate_reset(void);
enum sticky_resnapshot_gate_decision sticky_resnapshot_gate_decide(
    int64_t entry_tip, int64_t observed_tip);
void sticky_resnapshot_gate_finish(bool progressing);
int sticky_resnapshot_gate_state(void);

/* Rewind from the nearest locally self-verified base, never borrowed state. */
enum sticky_rung_result sticky_escalator_resnapshot_run(
    struct main_state *ms, int observed_tip);

#endif
