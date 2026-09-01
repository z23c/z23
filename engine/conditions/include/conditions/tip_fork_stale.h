/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_CONDITIONS_TIP_FORK_STALE_H
#define ZCL_CONDITIONS_TIP_FORK_STALE_H

void register_tip_fork_stale(void);

#ifdef ZCL_TESTING
#include <stdbool.h>
#include <stdint.h>

#include "validation/process_block_invalidate.h"

struct main_state;
struct uint256;
struct zcl_result;

void tip_fork_stale_test_reset(void);
/* Pin the no-advance stall timer so detect()'s sustained-window gate is
 * satisfied without waiting TIP_STALL_SECS in real time. */
void tip_fork_stale_test_force_stall(int64_t tip_h, int64_t age_secs);
/* Override the remedy's two real side effects (invalidate + rebuild) with
 * test stubs. Either may be NULL to leave the production default in place. */
void tip_fork_stale_test_set_remedy_stubs(
    enum invalidate_result (*inv)(struct main_state *,
                                  const struct uint256 *,
                                  struct uint256 *),
    bool (*reb)(int));
void tip_fork_stale_test_set_queue_body_stub(
    struct zcl_result (*queue_body)(int height, const char *reason));
/* Override the live apply-candidate-anomaly hold reader (a unit test cannot run
 * the real utxo_apply selection path). Return the height utxo_apply is held at,
 * or -1 for "no live hold". */
void tip_fork_stale_test_set_anomaly_hold_stub(int64_t (*hold)(void));
/* The no-advance window detect() last applied — TIP_STALL_SECS (300) on the
 * patient path, TIP_STALL_CORROBORATED_SECS (10) on the corroborated one. */
int64_t tip_fork_stale_test_stall_window_at_detect(void);
int tip_fork_stale_test_invalidate_calls(void);
int tip_fork_stale_test_rebuild_calls(void);
int tip_fork_stale_test_queue_body_calls(void);
int64_t tip_fork_stale_test_last_invalidate_height(void);
int tip_fork_stale_test_last_rebuild_from(void);
int tip_fork_stale_test_last_queue_body_height(void);
#endif

#endif /* ZCL_CONDITIONS_TIP_FORK_STALE_H */
