/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: distinguish operator-requested Tor from a running Tor thread. */

#include "net/tor_integration.h"
#include "net/tor_request_state.h"

#include <stdatomic.h>

static _Atomic bool g_tor_requested;

void tor_integration_mark_requested(void)
{
    atomic_store(&g_tor_requested, true);
}

bool tor_integration_is_requested(void)
{
    return atomic_load(&g_tor_requested);
}

void tor_integration_clear_requested(void)
{
    atomic_store(&g_tor_requested, false);
}
