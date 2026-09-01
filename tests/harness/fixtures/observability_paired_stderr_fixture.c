/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Positive controls for the observability lint gate.
 */

#include "event/event.h"

#include <stdio.h>
#include <stdlib.h>

int observability_event_paired_fixture(void)
{
    fprintf(stderr, "fixture emitted an event too\n");
    event_emitf(EV_NODE_READY, 0, "observability fixture");
    return -1;
}

int observability_obs_ok_fixture(void)
{
    fprintf(stderr, "fixture debug note\n"); // obs-ok:test-fixture
    return 0;
}

void observability_terminal_fixture(void)
{
    fprintf(stderr, "fixture aborts after diagnostic\n");
    abort();
}
