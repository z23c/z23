/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * event_log_singleton — tiny process-wide accessor for the shared
 * event_log_t used by durable projection emitters.
 *
 * The event_log primitive itself (engine/modules/storage/src/event_log.c) is
 * a deliberately stateless library — it owns no global handle. Projections,
 * however, need a way to find the one-and-only log
 * instance opened at boot, without having to thread it through every
 * call site. This file is that lightweight bridge.
 *
 * Lifecycle:
 *   - boot opens the event log with event_log_open(...)
 *   - boot calls event_log_set_singleton(log)
 *   - projection emitters (block_index_db, future projections) call
 *     event_log_singleton() on the hot path. NULL means "not wired
 *     yet" — emitters MUST tolerate that and skip the emit, since
 *     early-boot projection emission is best-effort. */

#ifndef ZCL_STORAGE_EVENT_LOG_SINGLETON_H
#define ZCL_STORAGE_EVENT_LOG_SINGLETON_H

#include "storage/event_log.h"

event_log_t *event_log_singleton(void);
void event_log_set_singleton(event_log_t *log);

#endif /* ZCL_STORAGE_EVENT_LOG_SINGLETON_H */
