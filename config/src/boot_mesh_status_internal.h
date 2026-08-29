/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the mesh-status lane's private cross-TU contract. The combined
 * file passed the 800-line shape ceiling, so the requester lane (begin:
 * pairing preflight, session lookup, pending admission, request send) lives
 * in boot_mesh_status_requester.c while boot_mesh_status.c keeps the shared
 * state, the pure helpers, the responder lane, receipt ingress, poll, and
 * lifecycle. These declarations are all that crosses that seam, so they
 * live here and nowhere else — nothing outside those two translation units
 * may include this header.
 */

#ifndef ZCL_CONFIG_BOOT_MESH_STATUS_INTERNAL_H
#define ZCL_CONFIG_BOOT_MESH_STATUS_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct mesh_status_request_v1;
struct msg_processor;
struct p2p_node;

/* Locked snapshot of the wired composition context and its generation.
 * Defined in boot_mesh_status.c. */
struct boot_svc_ctx *mesh_status_service(uint64_t *generation_out);

/* Pending-table primitives for the requester lane; each takes the lane lock
 * internally. admit evicts expired entries, then the oldest, and binds the
 * entry to the given service generation. retract clears the entry only when
 * it still names this exact request and has not completed. */
bool mesh_status_request_id_free(const uint8_t request_id[32]);
bool mesh_status_pending_admit(const struct mesh_status_request_v1 *request,
                               const uint8_t expected_responder_master[32],
                               uint64_t generation);
void mesh_status_pending_retract(const uint8_t request_id[32]);

/* Prefix+kind frame send on zpkgswm. Defined in boot_mesh_status.c. */
bool mesh_status_send(struct msg_processor *mp, struct p2p_node *node,
                      uint8_t kind, const uint8_t *wire, size_t wire_len);

#endif /* ZCL_CONFIG_BOOT_MESH_STATUS_INTERNAL_H */
