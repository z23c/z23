/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * subsystem_snapshot — a reusable seqlock publish envelope for the diagnostic
 * snapshot plane (Program O0). It generalizes the proven per-field seqlock in
 * app/controllers/src/event_agent_peers.c: a writer already holding its
 * subsystem's own lock publishes a coherent multi-field snapshot; readers
 * (dumpstate / status / harnesses) take a short lock-FREE bracket, never the
 * writer's lock, and always emit a value labeled with its staleness rather
 * than blocking behind the fold or returning an empty body.
 *
 * The contract, once, in one place:
 *   - A frontier/counter is published by exactly one writer, under the lock it
 *     already holds. No dumper ever takes that lock blocking.
 *   - A reader either reads a coherent snapshot, or — after a bounded number of
 *     retries against a busy writer — serves the LAST published values labeled
 *     {stale:true}. It never spins unbounded and never returns nothing.
 *
 * Threading: writer side runs under the subsystem's existing writer lock (so
 * only one publish is in flight at a time). Reader side is lock-free and may
 * run concurrently on any thread. All fields are _Atomic; the seqlock makes a
 * multi-field snapshot coherent without a mutex.
 */
#ifndef ZCL_UTIL_SUBSYSTEM_SNAPSHOT_H
#define ZCL_UTIL_SUBSYSTEM_SNAPSHOT_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

struct json_value;

/* The publish envelope. Embed one per published snapshot alongside the
 * subsystem's own payload atomics (the payload lives next to the env and is
 * written between publish_begin and publish_end).
 *
 *   seq              even = stable, odd = a writer is mid-publish.
 *   generation       increments once per completed publish (0 = never
 *                    published — readers must treat the payload as unseeded).
 *   published_us     monotonic-us timestamp of the last completed publish.
 *   last_height      the subsystem's last published height (or -1 if N/A) —
 *                    the uniform "last_publish_height" label field.
 *   torn_reads_total accounting: how many reader brackets exhausted their
 *                    retries against a busy writer and fell back to last-known.
 */
struct zcl_snapshot_env {
    _Atomic uint64_t seq;
    _Atomic uint64_t generation;
    _Atomic int64_t  published_us;
    _Atomic int64_t  last_height;
    _Atomic uint64_t torn_reads_total;
};

/* Static/zero initializer. last_height starts at -1 (unknown). A zeroed
 * struct (calloc / static) is also valid but reports last_height 0; prefer
 * this for a clean "unknown height" until the first publish. */
#define ZCL_SNAPSHOT_ENV_INIT { 0, 0, 0, -1, 0 }

/* Reader retry ceiling — a busy writer that keeps a reader spinning past this
 * many attempts is served the last-known snapshot labeled stale. */
#define ZCL_SNAPSHOT_READ_MAX_RETRIES 8

/* ── Writer side (call under the subsystem's own writer lock) ─────────────── */

/* Open a publish window: marks the env busy (seq -> odd). The caller then
 * writes its payload atomics, then calls publish_end. */
void zcl_snapshot_publish_begin(struct zcl_snapshot_env *env);

/* Close a publish window: stamps published_us (now), records last_height,
 * bumps generation, and marks the env stable (seq -> even). */
void zcl_snapshot_publish_end(struct zcl_snapshot_env *env, int64_t last_height);

/* ── Reader side (lock-free bracket, <= ZCL_SNAPSHOT_READ_MAX_RETRIES) ─────── */

/* Begin a read attempt. Loads the current seq into *seq_out. Returns true when
 * the env is stable (seq even) so the caller may read the payload atomics;
 * false when a writer is mid-publish (seq odd) so the caller should retry. */
bool zcl_snapshot_read_try(const struct zcl_snapshot_env *env,
                           uint64_t *seq_out);

/* Validate a completed read: applies the bracket's trailing acquire fence and
 * returns true iff no writer intervened since the matching read_try (seq
 * unchanged and even). A false result means the payload just read may be torn
 * — retry, or fall back to last-known labeled stale. */
bool zcl_snapshot_read_ok(const struct zcl_snapshot_env *env,
                          uint64_t seq_before);

/* Record that a reader bracket exhausted its retries and fell back to the
 * last-known snapshot. Bumps torn_reads_total. Cheap; call once per fallback. */
void zcl_snapshot_note_torn(struct zcl_snapshot_env *env);

/* ── Uniform staleness label ─────────────────────────────────────────────── */

/* Emit the uniform staleness contract into `out` (a json object the caller has
 * already initialized with json_set_object): keys {stale, age_us,
 * last_publish_height, generation, warning_reason}. `torn` is what the reader
 * observed (true => the payload is the last-known fallback). `now_us` is the
 * caller's monotonic-us clock read (platform_time_monotonic_us()).
 *
 * Never emits an empty body: on a never-published env it labels the values
 * stale with warning_reason "never_published"; on a torn read it labels them
 * stale with warning_reason "snapshot_torn_read"; otherwise stale is false and
 * warning_reason is "ok". */
void zcl_snapshot_emit_label(struct json_value *out,
                             const struct zcl_snapshot_env *env,
                             bool torn, int64_t now_us);

#endif /* ZCL_UTIL_SUBSYSTEM_SNAPSHOT_H */
