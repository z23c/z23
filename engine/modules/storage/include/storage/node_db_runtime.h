/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 *
 * node_db_runtime — the seam through which lib/ reaches the process-wide
 * node.db handle.
 *
 * `struct node_db` is an app/models type and the handle itself is owned by
 * the composition root's db_service. Code under lib/ that needs the live
 * handle therefore cannot see the struct and must not name config/: config/
 * wires the process together and sits ABOVE lib/. Calling
 * app_runtime_node_db() from lib/ closed that cycle.
 *
 * lib/ names this port instead; config/ registers the implementations at
 * process start. The four operations are exactly the ones whose bodies need
 * the struct layout or the db_service write runner, so they cannot move
 * down into lib/.
 *
 * FAIL-CLOSED: with no port registered, node_db_runtime() is NULL and every
 * predicate is false. Callers already treat a NULL handle as "not wired
 * yet", which is the pre-existing behaviour before boot publishes it.
 */

#ifndef ZCL_STORAGE_NODE_DB_RUNTIME_H
#define ZCL_STORAGE_NODE_DB_RUNTIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct node_db;
struct block_header;

/* Implementations supplied by the composition root. Every member may be
 * NULL; each accessor below degrades to its fail-closed answer. */
struct node_db_runtime_port {
    /* Live node.db handle, or NULL before boot wires it. */
    struct node_db *(*handle)(void);
    /* True when `ndb` is non-NULL and its sqlite connection is open. */
    bool (*handle_open)(const struct node_db *ndb);
    /* Durable key/value write through the db_service write runner, so it
     * serialises against the reducer's batch. */
    bool (*state_set)(struct node_db *ndb, const char *key,
                      const void *value, size_t len);
    /* MAX(height) over the utxos table, 0 when unavailable. */
    int (*utxo_max_height)(struct node_db *ndb);
    /* The complete canonical header (fixed fields + Equihash solution) at
     * exactly (height, hash), hash-bound by the implementation: a true return
     * means the returned bytes recompute to `hash`. The composition root may
     * resolve this from node.db or another existing durable header authority
     * when a snapshot deliberately omitted old bodies. False when no usable
     * local source exists. Read-only and subordinate to consensus writes. */
    bool (*load_header_by_hash_height)(int height, const uint8_t hash[32],
                                       struct block_header *out);
};

/* Install the port. `port` is borrowed and must have static storage
 * duration; pass NULL to unregister (fail-closed). */
void node_db_runtime_port_set(const struct node_db_runtime_port *port);

struct node_db *node_db_runtime(void);
bool node_db_runtime_handle_open(const struct node_db *ndb);
bool node_db_runtime_state_set(struct node_db *ndb, const char *key,
                               const void *value, size_t len);
int node_db_runtime_utxo_max_height(struct node_db *ndb);
bool node_db_runtime_load_header_by_hash_height(
    int height, const uint8_t hash[32], struct block_header *out);

#endif
