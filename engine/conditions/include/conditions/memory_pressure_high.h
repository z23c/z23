/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * SYMPTOM: platform/modules/util/mem_pressure's poll reports mem_pressure_current() >=
 *   MEM_HIGH — resident usage crossed the configured HIGH percentage of the
 *   best available denominator (cgroup memory.high/max, else system total
 *   RAM). Before this condition, node_health_service's "high_memory_usage"
 *   warning was observe-only.
 * REMEDY: force an immediate mem_pressure_poll_tick() (rather than waiting
 *   up to MEM_PRESSURE_POLL_SECS) so every registered shrink sink fires
 *   now; logs the RSS delta as a freed-bytes estimate. Raises a named
 *   BLOCKER_RESOURCE blocker at CRITICAL — mirrors disk_full_pause.c's
 *   shape for the same transient-resource class. AUTO-TERMINATING: long
 *   unbounded cooldown re-arm, never latches operator_needed.
 * WITNESSED: a fresh poll shows mem_pressure_current() < MEM_HIGH.
 * COND_CRITICAL; poll_secs=10. */

#ifndef ZCL_CONDITIONS_MEMORY_PRESSURE_HIGH_H
#define ZCL_CONDITIONS_MEMORY_PRESSURE_HIGH_H

void register_memory_pressure_high(void);

#ifdef ZCL_TESTING
void memory_pressure_high_test_reset(void);
int  memory_pressure_high_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_MEMORY_PRESSURE_HIGH_H */
