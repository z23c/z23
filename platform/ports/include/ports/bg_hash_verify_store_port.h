/* SPDX-License-Identifier: Apache-2.0
 * Copyright 2026 Rhett Creighton
 *
 * bg_hash_verify_store_port — storage interface for the resume cursor the
 * background block-hash verification service persists.
 *
 * bg_hash_verification is a read-ONLY, NON-CONSENSUS observer: it walks
 * the active chain recomputing each header's SHA256d and comparing it to
 * the stored hash. The only thing it persists is one crash-resume cursor
 * (the highest height verified so far), saved every 1000 blocks. Those
 * two cursor operations are exactly what this port captures:
 *
 *   load_progress(out)   read the "bg_hash_verification_height" state key;
 *                        sets *out and returns true if present, false
 *                        (out untouched) on a missing key / unavailable
 *                        store — the caller then restarts from genesis.
 *   save_progress(h)     persist the current verified height under the
 *                        same key; returns true on success.
 *
 * No sqlite type appears in this header. The adapter under
 * platform/adapters/outbound/persistence/ is the only thing that names the
 * sqlite-backed node DB for this subsystem. It wraps an already-open
 * connection opened by boot and never takes ownership.
 *
 * Threading: both methods run only on the dedicated verification thread
 * (load once at startup, save periodically). They go through the node-DB
 * state-kv path, whose own locking serializes them against other writers
 * — the same concurrency contract the inline code had before the seam.
 */

#ifndef ZCL_PORTS_BG_HASH_VERIFY_STORE_PORT_H
#define ZCL_PORTS_BG_HASH_VERIFY_STORE_PORT_H

#include <stdbool.h>

struct bg_hash_verify_store_port {
    void *self;

    /* Read the persisted resume height into *out. Returns true if the
     * cursor key exists (leaving *out set), false (out untouched) if the
     * store is unavailable or the key has never been written. */
    bool (*load_progress)(void *self, int *out);

    /* Persist `height` as the resume cursor. Returns true on success,
     * false on a NULL self / unavailable store. */
    bool (*save_progress)(void *self, int height);
};

#endif /* ZCL_PORTS_BG_HASH_VERIFY_STORE_PORT_H */
