/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Read-only discovery of a node service pid and active state.
 *          Linux asks systemd; macOS asks launchd. Ambiguous launchd jobs
 *          are refused. */

#ifndef ZCL_SERVICE_ARGS_H
#define ZCL_SERVICE_ARGS_H

#include <stddef.h>

/* Writes the discovered value without a newline. 0 on success, 1 when the
 * service is absent, ambiguous, or the tools do not answer. */
int zcl_service_query_pid(const char *unit, const char *plist,
                          char *out, size_t cap);
int zcl_service_query_active(const char *unit, const char *plist,
                             char *out, size_t cap);

/* Runs the GUI, background, ambiguous, and absent launchd cases. 0 when
 * every case matches. */
int zcl_service_args_selftest(void);

#endif
