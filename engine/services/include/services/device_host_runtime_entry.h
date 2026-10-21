/* purpose: Define strict raw HOST entry parsing, signal custody and stdio restoration. */
/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#ifndef ZCL_SERVICES_DEVICE_HOST_RUNTIME_ENTRY_H
#define ZCL_SERVICES_DEVICE_HOST_RUNTIME_ENTRY_H
#include "base/result.h"
#include "json/json.h"
#include <stdbool.h>
#include <stddef.h>
enum device_host_runtime_entry_exit {
    DEVICE_HOST_ENTRY_OK = 0, DEVICE_HOST_ENTRY_FAILED = 1,
    DEVICE_HOST_ENTRY_INVALID = 2, DEVICE_HOST_ENTRY_UNSUPPORTED = 3
};
/* One exclusive foreground process owner; no concurrent calls or node boot.
 * Parse untrusted text through this bounded rail before run: exact object,
 * no duplicate/unknown keys, NUL escapes or trailing data; fresh JSON output.
 * Fixed role and all typed fields remain mandatory. No private data is read
 * during parse. Input contains public approval/route facts, never a secret.
 * Parse returns a contextual zcl_result with code zero only on success.
 * Run reuses owner-private read-only identity, current grants and existing IO;
 * raw stdio contains bytes only, diagnostics stderr. Saves/restores shared OFD
 * status flags and SIGINT/SIGTERM/SIGHUP rail. Client HUP requests bounded
 * ordinary EOF/FIN drain after establishment; preauth/receiver HUP cancels.
 * Caller maintains independent stderr,
 * trusted ancestors/profile binding and exclusive stdio/signal ownership.
 * Client runs on Linux/macOS; receiver runs on Linux and loopback-only on
 * macOS, where allow_external=true refuses by name before input validation.
 * Unsupported roles and platforms refuse before private profile/socket
 * effects. */
struct zcl_result device_host_runtime_entry_parse(struct json_value *out, const char *text,
    size_t length, bool receiver);
struct zcl_result device_host_runtime_entry_run(
    const struct json_value *input, bool receiver, enum device_host_runtime_entry_exit *status);
/* Run requires independent exit-status storage. Null or overlap with the JSON
 * root refuses unchanged before effects; disjointness from JSON-owned child,
 * key and string storage remains a caller precondition. The explicit exit
 * retains native process behavior; only ENTRY_OK has successful result code0. */
#endif
