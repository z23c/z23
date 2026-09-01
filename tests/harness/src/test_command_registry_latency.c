/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Wall-clock command contracts run before the parallel worker pool so CPU
 * contention cannot turn scheduler latency into a command regression. The
 * structural catalog proof remains independently parallelizable.
 */

#include "test/test_core.h"

int command_registry_ready_read_latency_contract(void);
int command_registry_status_latency_contract(void);

int test_command_registry_latency(void)
{
    int failures = 0;
    failures += command_registry_ready_read_latency_contract();
    failures += command_registry_status_latency_contract();
    return failures;
}
