/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_TIP_STALL_ORACLE_REBUILD_H
#define ZCL_CONDITIONS_TIP_STALL_ORACLE_REBUILD_H

#include <stdbool.h>
#include <stdint.h>

/* Register the tip_stall_oracle_rebuild Condition with the engine. */
void register_tip_stall_oracle_rebuild(void);

#ifdef ZCL_TESTING
/* Test seams. The two real side effects — reading the local zclassicd's
 * height and rebuild_recent_repair() — reach external services, so route
 * them through overridable function pointers the test can stub. */
void tip_stall_oracle_rebuild_test_reset(void);
void tip_stall_oracle_rebuild_test_force_stall(int64_t tip_h, int64_t age_secs);
void tip_stall_oracle_rebuild_test_set_stubs(bool (*oracle_height)(int *),
                                             bool (*rebuild)(int));
int tip_stall_oracle_rebuild_test_rebuild_calls(void);
int tip_stall_oracle_rebuild_test_last_rebuild_from(void);
#endif

#endif /* ZCL_CONDITIONS_TIP_STALL_ORACLE_REBUILD_H */
