/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Verify public app frames and carriers over a caller-owned transport. */
#ifndef ZCL_NATIVE_APP_NETWORK_H
#define ZCL_NATIVE_APP_NETWORK_H
#include "command/native_app_offer.h"
#include "vcs/package_store.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One synchronous fetch; the caller fills only the supplied buffer, reports
 * actual length/status, and must honor timeout_ms and cancellation. No reply
 * bytes are trusted merely because the callback succeeded. */
typedef bool (*app_network_fetch_fn)(void *context, const char *onion,
    const char *path, uint8_t *out, size_t cap, size_t *len, int *status,
    unsigned timeout_ms);
struct app_network_transport {
    app_network_fetch_fn fetch;
    bool (*cancelled)(void *context);
    void *context;
    unsigned timeout_ms; /* deadline, 1..120000; local I/O cannot be interrupted */
    bool parallel_safe; /* fetch callback and context support concurrent calls */
};
#if defined(ZCL_TESTING)
void zcl_test_app_network_thread_faults(int spawn_after, int join_after);
#endif
enum app_network_error {
    APP_NETWORK_OK, APP_NETWORK_CANCELLED, APP_NETWORK_TIMEOUT,
    APP_NETWORK_UNAVAILABLE, APP_NETWORK_INVALID_RESPONSE,
    APP_NETWORK_CHANGED_OFFER, APP_NETWORK_CONTENT_MISMATCH,
    APP_NETWORK_STORE_REFUSED
};
/* Uses an already-owned, dial-ready Tor instance; never starts, stops or
 * reconfigures it. A separate process owner must provide that lifetime. */
bool app_network_tor_fetch(void *context, const char *onion, const char *path,
    uint8_t *out, size_t cap, size_t *len, int *status, unsigned timeout_ms);
/* Catalog is a bounded newest sample, not a complete global index. */
bool app_network_catalog(const struct app_network_transport *transport,
    const char *onion, int64_t now, struct zcl_app_offer_row *rows, size_t cap,
    size_t *count, bool *incomplete, enum app_network_error *error);
bool app_network_exact(const struct app_network_transport *transport,
    const char *onion, const char *post_id, int64_t now,
    struct zcl_app_offer_row *row, enum app_network_error *error);
/* Rechecks the selected post then verifies manifest, all chunks, carrier
 * length and SHA256. The borrowed store is never evicted; *mutated is set
 * before attempting admission, even on refusal. Caller frees *bytes. */
bool app_network_carrier(const struct app_network_transport *transport,
    const char *catalog_onion, const char *carrier_onion,
    const struct zcl_app_offer_row *selected, int64_t now,
    struct vcs_package_store *store, uint8_t **bytes, size_t *len, bool *mutated,
    enum app_network_error *error);
#endif
