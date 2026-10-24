/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Deferred HTTPS start owned by the engine. The engine holds the configured
 * HTTPS and HTTP ports, so the deferred start must replay those ports. */

#ifndef ZCL_SERVICES_HTTPS_DEFERRED_START_H
#define ZCL_SERVICES_HTTPS_DEFERRED_START_H

#include "base/result.h"

#include <stdbool.h>

typedef bool (*https_deferred_start_fn)(const char *cert_path,
                                        const char *key_path,
                                        const char *hostname,
                                        int https_port, int http_port);

/* Queue an HTTPS start for when the node is synced. Refuses (returns a
 * non-ok result with the reason, nothing queued) when a path is NULL or a
 * port is outside 1..65535. */
struct zcl_result https_deferred_start_set(const char *cert_path,
                                           const char *key_path,
                                           const char *hostname,
                                           int https_port, int http_port);

/* Start the queued server with the stored ports when it is pending and not
 * already running. Clears the pending flag before starting. */
void https_deferred_start_check(void);

/* Writes true to *pending while a deferred start is queued and has not yet
 * fired. Fails (non-ok, *pending untouched) only when pending is NULL. */
struct zcl_result https_deferred_start_pending(bool *pending);

#ifdef ZCL_TESTING
/* Replace the start call (tests record arguments without binding sockets).
 * NULL restores https_server_start_on_port. */
void https_deferred_start_set_starter_for_testing(https_deferred_start_fn fn);
#endif

#endif
