/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * telemetry_watch_service — the SAMPLER behind `ops.telemetry.watch`.
 *
 * The ring (util/telemetry_watch.h) remembers change records; this service is
 * the only thing that puts them there. Once per tick it fills one typed
 * snapshot per SAMPLED domain, diffs it against the previous sample, and
 * publishes a record when — and only when — something the node owns actually
 * moved. A tick that finds nothing publishes nothing, which is what makes
 * "emits only changes" true rather than aspirational.
 *
 * WHICH DOMAINS ARE SAMPLED, and why the answer is not "all of them". A domain
 * can only be sampled if it has a real provider filling a typed snapshot.
 * Today exactly one does (`sync`, engine/services/src/sync_telemetry_fill.c). The
 * other seven are DECLARED unsampled with a reason each, and the reason is
 * published in the reply — an omission nobody can read is how a feed quietly
 * stops covering half the node.
 *
 * `metaverse` is declared separately from the other six because its reason is
 * different in kind and permanent rather than pending: metaverse data is
 * directory-scoped and node-free, so there is no ambient in-process state to
 * sample. Inventing a change feed for it would be inventing state.
 *
 * SUPERVISION. This is a supervised child of the ops domain with an ARMED
 * progress policy — see the register function. It is time-driven by the root
 * supervisor's tick runner (no thread of its own), and every read it performs
 * is the sync provider's own lock-free/trylock read, so it cannot block that
 * runner behind the reducer.
 *
 * Layering: an application service over the telemetry render layer and the
 * sync provider. Opens no database directly, contacts no node, allocates
 * nothing per tick.
 */
#ifndef ZCL_SERVICES_TELEMETRY_WATCH_SERVICE_H
#define ZCL_SERVICES_TELEMETRY_WATCH_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* How often the supervisor drives one sample. Chosen against the ring: 64
 * slots at this cadence covers a bit over five minutes of continuous change,
 * so an agent polling once a minute never sees a gap while a busy node folds
 * blocks. */
#define TELEMETRY_WATCH_PERIOD_SECS 5

/* Register the sampler as a supervised child and arm NO_PROGRESS detection.
 * Idempotent; call once from the boot service wiring. */
void telemetry_watch_service_register(void);

/* True when the supervised child is registered IN THIS PROCESS.
 *
 * This is the question a one-shot CLI has to ask. A native command runs in its
 * own short-lived process that never booted the node, so no sampler is ticking
 * there and the ring would answer every poll with an empty batch forever. The
 * `watch` handler therefore samples once itself when this returns false, and
 * says so in the reply. Inside the node this returns true and the handler
 * leaves sampling to the supervised child, so a poll never races it. */
bool telemetry_watch_service_is_armed(void);

/* Take one sample of every sampled domain and publish a record per domain that
 * changed. Returns the number of records published (0 is the normal quiet
 * answer). Safe to call from any thread; safe to call before boot. */
size_t telemetry_watch_service_sample_once(void);

/* Records this sampler has published since the process started. This is the
 * supervisor progress marker: it counts RESULTS (changes observed), never
 * ticks. */
uint64_t telemetry_watch_service_records_published(void);

/* ── coverage, for the reply ────────────────────────────────────────────
 * The declared source table, so `ops.telemetry.watch` can state what it does
 * and does not cover instead of leaving a reader to assume "everything".
 * `*skip_reason` is NULL for a sampled domain and a short static token for a
 * declared-unsampled one. Returns false when `index` is out of range. */
size_t telemetry_watch_service_source_count(void);
bool telemetry_watch_service_source_at(size_t index, const char **domain,
                                       const char **canonical_path,
                                       const char **skip_reason);

/* Drop every remembered previous sample so the next one is a fresh baseline.
 * Used by the tests around telemetry_watch_restart(); production never calls
 * it — a restart of the process does the same thing for free. */
void telemetry_watch_service_reset_baseline(void);

#endif /* ZCL_SERVICES_TELEMETRY_WATCH_SERVICE_H */
