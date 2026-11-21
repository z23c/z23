/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: test seams of dev.agent.mail.probe
 *          (tools/command/native_devagent_mailprobe.c). The leaf itself is
 *          reached only through the command registry; nothing here widens it. */

#ifndef ZCL_NATIVE_DEVAGENT_MAILPROBE_H
#define ZCL_NATIVE_DEVAGENT_MAILPROBE_H

#ifdef ZCL_TESTING
#include <stdint.h>

/* Replace the wall clock behind every t1..t4 timestamp, in unix
 * milliseconds. NULL restores CLOCK_REALTIME. Deadlines and pacing never use
 * it: they stay on the monotonic clock. */
typedef int64_t (*zcl_devagent_mailprobe_clock_fn)(void *ctx);
void zcl_devagent_mailprobe_test_set_clock(zcl_devagent_mailprobe_clock_fn fn,
                                           void *ctx);

/* Called by the send role right after each successful probe post, standing in
 * for the transport and the peer between two isolated state roots. */
typedef void (*zcl_devagent_mailprobe_pump_fn)(void *ctx);
void zcl_devagent_mailprobe_test_set_pump(zcl_devagent_mailprobe_pump_fn fn,
                                          void *ctx);
#endif

#endif
