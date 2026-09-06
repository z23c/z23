/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Supervisor private state shared with the read-only introspection unit. */
#ifndef ZCL_UTIL_SUPERVISOR_INTERNAL_H
#define ZCL_UTIL_SUPERVISOR_INTERNAL_H

#include "util/supervisor.h"

#include <pthread.h>
#include <stdatomic.h>

#define SUPERVISOR_STALL_TOKEN_REASON_BITS 8
#define SUPERVISOR_STALL_TOKEN_REASON_MASK UINT64_C(0xff)
_Static_assert(SUPERVISOR_STALL_REPEATED_RESTART <=
                   SUPERVISOR_STALL_TOKEN_REASON_MASK,
               "stall reasons must fit the delivery token");

static inline enum supervisor_stall_reason
supervisor_stall_token_reason(uint64_t token)
{
    return (enum supervisor_stall_reason)
        (token & SUPERVISOR_STALL_TOKEN_REASON_MASK);
}

static inline uint64_t supervisor_stall_token_cleared(uint64_t token)
{
    return token & ~SUPERVISOR_STALL_TOKEN_REASON_MASK;
}

struct supervisor_domain {
    char label[SUPERVISOR_NAME_MAX];
};

extern pthread_mutex_t g_supervisor_lock;
extern struct liveness_contract *g_supervisor_contracts[SUPERVISOR_CAP];
extern supervisor_domain_t
    *g_supervisor_contract_domains[SUPERVISOR_CAP];
extern int g_supervisor_contract_count;
extern supervisor_domain_t g_supervisor_domains[SUPERVISOR_DOMAIN_CAP];
extern int g_supervisor_domain_count;

extern _Atomic bool g_supervisor_running;
extern _Atomic bool g_supervisor_thread_alive;
extern _Atomic int g_supervisor_tick_ms;
extern _Atomic uint64_t g_supervisor_sweep_heartbeat;
extern _Atomic int64_t g_supervisor_sweep_last_us;
extern _Atomic bool g_supervisor_runner_running;
extern struct liveness_contract g_supervisor_runner_contract;
extern _Atomic bool g_supervisor_stall_runner_running;
extern _Atomic int64_t g_supervisor_stall_runner_last_us;
extern _Atomic int g_supervisor_runner_blocker_action;
extern _Atomic uint32_t g_supervisor_runner_blocker_coalesced;
extern _Atomic uint32_t g_supervisor_runner_blocker_discarded;

enum supervisor_progress_policy
supervisor_effective_progress_policy(const struct liveness_contract *c);
int supervisor_live_count_locked(void);
const char *supervisor_stall_active_callback_name_internal(void);

#define g_lock g_supervisor_lock
#define g_contracts g_supervisor_contracts
#define g_contract_domains g_supervisor_contract_domains
#define g_contract_count g_supervisor_contract_count
#define g_domains g_supervisor_domains
#define g_domain_count g_supervisor_domain_count
#define g_running g_supervisor_running
#define g_thread_alive g_supervisor_thread_alive
#define g_tick_ms g_supervisor_tick_ms
#define g_sweep_heartbeat g_supervisor_sweep_heartbeat
#define g_sweep_last_us g_supervisor_sweep_last_us
#define g_runner_running g_supervisor_runner_running
#define g_runner_contract g_supervisor_runner_contract
#define g_stall_runner_running g_supervisor_stall_runner_running
#define g_stall_runner_last_us g_supervisor_stall_runner_last_us
#define g_runner_blocker_action g_supervisor_runner_blocker_action
#define g_runner_blocker_coalesced g_supervisor_runner_blocker_coalesced
#define g_runner_blocker_discarded g_supervisor_runner_blocker_discarded
#define effective_progress_policy supervisor_effective_progress_policy

#endif /* ZCL_UTIL_SUPERVISOR_INTERNAL_H */
