/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the mesh-status lane's private cross-TU contract. The combined
 * file passed the 800-line shape ceiling, so the requester lane (begin:
 * pairing preflight, session lookup, pending admission, request send) lives
 * in boot_mesh_status_requester.c while boot_mesh_status.c keeps the shared
 * state, the pure helpers, the responder lane, receipt ingress, poll, and
 * lifecycle. Production code outside those two translation units must not
 * include this header; the focused wire test includes it to exercise the
 * exact bounded-table contract.
 */

#ifndef ZCL_CONFIG_BOOT_MESH_STATUS_INTERNAL_H
#define ZCL_CONFIG_BOOT_MESH_STATUS_INTERNAL_H

#include "models/mesh_pairing.h"
#include "plugin/plugin_store.h"
#include "session/mesh_status_proto.h"
#include "vcs/zcode_dht_delegation.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct mesh_status_request_v1;
struct msg_processor;
struct net_manager;
struct noise_transport_snapshot;
struct p2p_node;

/* Locked snapshot of the wired composition context and its generation.
 * Defined in boot_mesh_status.c. */
struct boot_svc_ctx *mesh_status_service(uint64_t *generation_out);

/* Pending-table primitives for the requester lane; each takes the lane lock
 * internally. admit evicts expired entries and refuses a still-full table;
 * it never destroys a live request. retract clears the entry only when it
 * still names this exact request and has not completed. */
bool mesh_status_request_id_free(const uint8_t request_id[32]);
bool mesh_status_pending_admit(const struct mesh_status_request_v1 *request,
                               const uint8_t expected_responder_master[32],
                               const uint8_t expected_responder_online[32],
                               uint64_t generation);
void mesh_status_pending_retract(const uint8_t request_id[32]);

/* Prefix+kind frame send on zpkgswm. Defined in boot_mesh_status.c. */
bool mesh_status_send(struct msg_processor *mp, struct p2p_node *node,
                      uint8_t kind, const uint8_t *wire, size_t wire_len);

/* Mesh-lane shared helpers, defined in boot_mesh_status.c. The responder's
 * own receipt identity (filed local delegation + ACTIVE ZID master + online
 * key, fail-closed on every mismatch), and the connected-peer lookup: a
 * referenced p2p_node whose established Noise session names `peer_noise`,
 * with its session snapshot out; caller releases the reference. Both are
 * used by the mesh terminal lane too — one implementation, so fail-closed
 * identity and session lookup can never drift between the two lanes. */
bool boot_mesh_local_identity(struct node_db *ndb, const char *datadir,
                              uint8_t master_out[32],
                              uint8_t online_pub_out[32],
                              uint8_t online_seed_out[32]);
struct p2p_node *boot_mesh_find_session_peer(
    struct net_manager *nm, const uint8_t peer_noise[32],
    struct noise_transport_snapshot *session_out);
/* The bound variant: only the ready node whose session carries exactly this
 * transcript hash and connection generation (see boot_mesh_status.c). Use it
 * wherever a later step must stay on the session an earlier one chose. */
struct p2p_node *boot_mesh_find_session_bound(
    struct net_manager *nm, const uint8_t peer_noise[32],
    const uint8_t transcript_hash[32], uint64_t connection_generation,
    struct noise_transport_snapshot *session_out);

/* Most ready nodes one observation captures. The net manager's default is
 * 125 connections and a configured maximum is clamped near 1000, so this
 * covers any real table; the array is 8 KiB of stack. */
#define BOOT_MESH_OBSERVE_MAX_READY 1024u

/* "Does this node hold an established session with `peer_noise`". Membership
 * is fixed once, when the node table lock is held to capture every ready
 * node. Each captured node's session is read afterwards, one at a time, under
 * that node's own transport lock while its reference is held. This is not an
 * atomic view of all sessions: each read reports its node at its own later
 * moment, so a session that ends or changes between the capture and that read
 * is reported as read. A node that joins the table or becomes ready after the
 * capture is not seen until the next call. LIVE: a captured node's locked read
 * is established and names this peer. ABSENT: every ready node in the captured
 * membership was read under its transport lock, and none held an established
 * session naming this peer when read. INCOMPLETE (the zero value): more ready
 * nodes than the capture bound, a captured node had lost its transport when
 * read, or an argument was NULL. No reference is held on return. */
enum boot_mesh_session_observation {
    BOOT_MESH_SESSION_INCOMPLETE = 0,
    BOOT_MESH_SESSION_LIVE,
    BOOT_MESH_SESSION_ABSENT,
};
enum boot_mesh_session_observation boot_mesh_observe_session_peer(
    struct net_manager *nm, const uint8_t peer_noise[32]);

/* The paired peer's greatest-seq held delegation for the exact identity the
 * pairing row binds; two different online keys at that sequence are
 * ambiguous and fail closed. Used by both requester lanes — an open or a
 * status request must pre-flight the same authority the responder will
 * re-verify. Defined in boot_mesh_status.c. */
bool boot_mesh_peer_delegation_unheld(const struct db_mesh_pairing *row);
bool boot_mesh_peer_delegation(const struct db_mesh_pairing *row,
                               struct vcs_zcode_dht_delegation *out);


/* ── Plugins block of the status capsule (boot_mesh_status_plugins.c) ────
 * Which signed plugins this machine has installed and which generation is
 * current, read-only from the HOME store. At most MAX_ITEMS rows; ids are cut
 * to PREFIX hex characters. */
#define MESH_STATUS_PLUGINS_MAX_ITEMS 8u
#define MESH_STATUS_PLUGIN_PREFIX 16u

struct mesh_status_plugin_row {
    char name[PLUGIN_NAME_MAX + 1];
    char current[MESH_STATUS_PLUGIN_PREFIX + 1];
    char last_good[MESH_STATUS_PLUGIN_PREFIX + 1];
};

struct mesh_status_plugins {
    bool available;
    const char *reason; /* when !available: home_unset|store_absent|store_unreadable */
    size_t count;       /* all installed plugins */
    size_t listed;      /* rows filled in items, <= MAX_ITEMS */
    struct mesh_status_plugin_row items[MESH_STATUS_PLUGINS_MAX_ITEMS];
};

/* Snapshot the store under `home` (NULL or relative: home_unset). Never fails:
 * every problem is reported as available=false with a reason. */
void mesh_status_plugins_read(const char *home,
                              struct mesh_status_plugins *out);

/* Append the plugins block to the rendered identity capsule `base` (a JSON
 * object, <= the cap). Rows are dropped from the end, truncated=true, until
 * the result fits; if not even zero rows fit, out is `base` byte for byte.
 * Returns false only when base is not a JSON object. */
bool mesh_status_capsule_with_plugins(const char *base, size_t base_len,
                                      const struct mesh_status_plugins *p,
                                      uint8_t out[MESH_STATUS_CAPSULE_MAX],
                                      size_t *out_len);


/* Opt-in lane, -meshstatusplugins (default off). Off: the capsule is exactly
 * the identity render; HOME and the store are never touched. On: the
 * responder copies a cached snapshot (a short mutex, no syscalls); the
 * supervised refresh tick re-reads the store at most once per
 * MESH_STATUS_PLUGINS_REFRESH_S. Before the first refresh the block says
 * available=false reason "not_yet_read". */
#define MESH_STATUS_PLUGINS_REFRESH_S 60

bool mesh_status_plugins_enabled(void);
void mesh_status_plugins_cache_snapshot(struct mesh_status_plugins *out);
void mesh_status_plugins_cache_set(const struct mesh_status_plugins *snapshot,
                                   int64_t now);
void mesh_status_plugins_cache_reset(void);
void mesh_status_plugins_cache_refresh(const char *home, int64_t now);

/* Final capsule bytes from the rendered identity `base`: unchanged when the
 * lane is off, otherwise base plus the cached plugins block. */
void mesh_status_capsule_finish(const char *base, size_t base_len,
                                uint8_t out[MESH_STATUS_CAPSULE_MAX],
                                size_t *out_len);

#endif /* ZCL_CONFIG_BOOT_MESH_STATUS_INTERNAL_H */
