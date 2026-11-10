/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Bound the lifetime of one private outbound worker. */
#ifndef ZCL_NATIVE_APP_NETWORK_LIFELINE_H
#define ZCL_NATIVE_APP_NETWORK_LIFELINE_H
#if !defined(_WIN32)
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
struct app_network_lifeline { pthread_t thread; atomic_bool stop; uint64_t parent; int64_t deadline, last; };
bool app_network_lifeline_start(struct app_network_lifeline *guard, uint64_t parent, unsigned timeout_ms);
bool app_host_lifeline_start(struct app_network_lifeline *guard, uint64_t parent, unsigned timeout_ms);
bool app_network_lifeline_stop(struct app_network_lifeline *guard);
#endif
#endif
