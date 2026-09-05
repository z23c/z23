/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the mesh terminal lane's private cross-TU contract. The
 * responder (open decisions, receipts, the confined workers, the stream
 * drain) lives in boot_mesh_terminal.c; the requester (client sessions,
 * message ingress, watchdogs) lives in boot_mesh_terminal_client.c; the
 * RPC adapter lives in boot_mesh_terminal_rpc.c. Production code outside
 * those translation units must not include this header.
 *
 * Both halves are ONE stream service: boot_mesh_terminal.c registers
 * "terminal" once and routes each callback to the half that owns the
 * stream, told apart by which side opened it. Everything declared here
 * therefore runs under the stream primitive's single lane lock.
 */

#ifndef ZCL_CONFIG_BOOT_MESH_TERMINAL_INTERNAL_H
#define ZCL_CONFIG_BOOT_MESH_TERMINAL_INTERNAL_H

#include "config/mesh_stream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct noise_transport_snapshot;

/* The lane's message envelope: one kind byte then the
 * mesh_terminal_proto wire, as a stream DATA or CLOSE payload carries it.
 * Returns 0 when the message does not fit. Defined in
 * boot_mesh_terminal.c. */
size_t boot_mesh_terminal_msg(uint8_t kind, const uint8_t *wire,
                              size_t wire_len, uint8_t *out, size_t out_cap);

/* The stream's peer binding in the shape the pure decision and the
 * receipt checks take. Defined in boot_mesh_terminal.c. */
void boot_mesh_terminal_stream_session(const struct mesh_stream *st,
                                       struct noise_transport_snapshot *out);

/* Registers the "terminal" stream service (no supervisor tick, no
 * composition context of its own). Defined in boot_mesh_terminal.c;
 * boot_mesh_terminal_wire calls it, and the lane test groups call it to
 * drive the exact production callbacks. */
bool boot_mesh_terminal_register_service(void);

/* Requester-lane lifecycle, driven by the responder's wire/shutdown so the
 * two halves of the lane always arm and disarm together. Defined in
 * boot_mesh_terminal_client.c. */
void boot_mesh_terminal_client_wire(struct boot_svc_ctx *svc);
void boot_mesh_terminal_client_shutdown(void);

/* Composition context for the requester lane (its own locked snapshot).
 * Defined in boot_mesh_terminal_client.c. */
struct boot_svc_ctx *boot_mesh_terminal_client_service(void);

/* Requester-lane callbacks, called by the service dispatch in
 * boot_mesh_terminal.c for every stream this node opened. Defined in
 * boot_mesh_terminal_client.c. */
void boot_mesh_terminal_client_message(struct mesh_stream *st,
                                       const uint8_t *payload, size_t len);
void boot_mesh_terminal_client_tick(struct mesh_stream *st,
                                    uint64_t now_unix);
void boot_mesh_terminal_client_ended(struct mesh_stream *st,
                                     enum mesh_stream_refusal reason,
                                     const uint8_t *payload, size_t len);
void boot_mesh_terminal_client_release(struct mesh_stream *st);

#endif /* ZCL_CONFIG_BOOT_MESH_TERMINAL_INTERNAL_H */
