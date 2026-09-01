/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * status_frontdoor — the single-round-trip operator status composition
 * (Program O2). One node-side dumper that composes `z23 status` from
 * lock-free / trylock-guarded in-process snapshot sources: the provable-tip
 * cache and reducer floor (plain atomics), the peer snapshot (trylock+cached,
 * never blocks), and the in-memory blocker registry. Every composed member
 * carries its own staleness label and any member whose snapshot is
 * stale/busy/unavailable is named in a top-level `degraded[]` array — there is
 * no single ok:bool that can read green while a member is dark.
 *
 * The old front door made TWELVE sequential node_rpc_call()s, each re-entering
 * the 4-worker RPC pool and racing the fold with a 10s kill-timeout; this
 * composition takes ZERO progress_store_tx_lock and runs no COUNT(*), so it
 * completes under load instead of queueing behind the reducer. The native
 * `z23 status` handler reaches it in ONE dumpstate round-trip; the full
 * legacy 12-call document stays available behind `status --full`.
 *
 * Registered as the `status_frontdoor` dumpstate subsystem. Reentrant-safe;
 * never takes the writer's lock. */
#ifndef ZCL_CONTROLLERS_STATUS_FRONTDOOR_H
#define ZCL_CONTROLLERS_STATUS_FRONTDOOR_H

#include <stdbool.h>

struct json_value;

/* Compose the operator status body from non-blocking in-process snapshot
 * sources into `out` (the caller initializes it with json_set_object first, per
 * the dumpstate convention). `key` is unused. Always returns true — a dark
 * member is reported via its {stale,age_us,...} label and the degraded[] array,
 * never by failing the whole composition. */
bool status_frontdoor_dump_state_json(struct json_value *out, const char *key);

#endif /* ZCL_CONTROLLERS_STATUS_FRONTDOOR_H */
