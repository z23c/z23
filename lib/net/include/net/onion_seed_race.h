/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: race onion-directory seed fetches so a dead door cannot delay
 * a live one. Validation of an answer stays with the caller. */

#ifndef ZCL_NET_ONION_SEED_RACE_H
#define ZCL_NET_ONION_SEED_RACE_H

#include "net/tor_integration.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>

/* Each in-flight onion fetch is a separate Tor circuit. Four is enough to
 * start the compiled-in doors plus a couple of operator/directory lines at
 * once; a cold node has not yet proven it needs more circuits than that.
 * Remaining hosts queue only if this wave produces no usable answer. */
#define ONION_SEED_RACE_MAX_INFLIGHT 4

/* Same contract as tor_integration_fetch_onion_blocking, plus a caller
 * context so tests can inject a fetch that never touches the network. */
typedef int (*onion_seed_fetch_fn)(const char *onion_address,
                                   const char *path,
                                   struct onion_fetch_result *result,
                                   int timeout_secs,
                                   void *ctx);

/* Optional caller-owned content predicate. Transport success alone does not
 * make a directory useful; production uses this to reject empty or malformed
 * HTTP 200 bodies before they can win the race. */
typedef bool (*onion_seed_usable_fn)(const uint8_t *body, size_t body_len,
                                     void *ctx);

/* Handle for the workers this race spawned, including the ones that lost
 * and are still finishing. The blocking Tor primitive cannot be cancelled,
 * so a loser is left to complete into a result nobody reads; the caller
 * MUST wait it out before freeing the handle so no worker outlives the
 * fetch path it is standing in. */
struct onion_seed_race_join;

/* Race up to ONION_SEED_RACE_MAX_INFLIGHT fetches at a time. Returns 0
 * and fills *winner / *winner_index as soon as one fetch has status 200, a
 * non-NULL body, and passes `usable` when that callback is non-NULL. Does not
 * wait for the remaining in-flight fetches. Any live
 * seed's usable answer is equally acceptable; the winner is whoever
 * finished first, not a preferred index.
 *
 * Out-params are assigned on every path, including errors.
 *
 * join_out is REQUIRED, not optional. Every worker is spawned JOINABLE
 * through thread_registry_spawn() with join ownership transferred to the
 * caller, and *join_out is the only handle to those threads: the caller
 * must reach onion_seed_race_join_wait() + onion_seed_race_join_free() on
 * every path where it is set non-NULL. A NULL join_out is refused (there
 * would be no way to reap the losers), and *join_out is left NULL when the
 * call fails before any worker was spawned. */
int onion_seed_race_first_usable(const char *const *hosts,
                                 size_t n,
                                 onion_seed_fetch_fn fetch,
                                 void *fetch_ctx,
                                 onion_seed_usable_fn usable,
                                 void *usable_ctx,
                                 int timeout_secs,
                                 const _Atomic bool *stop,
                                 struct onion_fetch_result *winner,
                                 size_t *winner_index,
                                 struct onion_seed_race_join **join_out);

/* Join every worker this race spawned. Blocks until each has returned —
 * for a loser that is its own fetch timeout, which is why the winner is
 * handed back BEFORE this is called. Idempotent; call from the thread that
 * ran the race. Safe on NULL. */
void onion_seed_race_join_wait(struct onion_seed_race_join *join);

/* Release the handle. Waits first (onion_seed_race_join_wait is
 * idempotent), so a caller that forgets to join still cannot free the
 * threads' state out from under them. Safe on NULL. */
void onion_seed_race_join_free(struct onion_seed_race_join *join);

/* Workers spawned but not yet returned. Observability, and the seam the
 * unit test uses to prove the race handed back the winner while the slow
 * door was still blocked — a relationship, never a wall-clock budget. */
int onion_seed_race_join_in_flight(const struct onion_seed_race_join *join);

#endif /* ZCL_NET_ONION_SEED_RACE_H */
