/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * event_log_singleton — see header. Atomic pointer; no locking. */

#include "storage/event_log_singleton.h"

#include <stdatomic.h>
#include <stddef.h>

static _Atomic(event_log_t *) g_log = NULL;

event_log_t *event_log_singleton(void)
{
    return atomic_load_explicit(&g_log, memory_order_acquire);
}

void event_log_set_singleton(event_log_t *log)
{
    atomic_store_explicit(&g_log, log, memory_order_release);
}
