/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_REDUCER_FRONTIER_RECONCILE_LIGHT_H
#define ZCL_CONDITIONS_REDUCER_FRONTIER_RECONCILE_LIGHT_H

void register_reducer_frontier_reconcile_light(void);

#ifdef ZCL_TESTING
void reducer_frontier_reconcile_light_test_reset(void);
void reducer_frontier_reconcile_light_test_clear_backoff(void);
int reducer_frontier_reconcile_light_test_remedy_calls(void);
#endif

#endif /* ZCL_CONDITIONS_REDUCER_FRONTIER_RECONCILE_LIGHT_H */
