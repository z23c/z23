/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: the mesh terminal lane's private cross-TU contract. The
 * responder (open decisions, receipts, the confined session table, the
 * supervised pump) lives in boot_mesh_terminal.c; the requester (client
 * sessions, receipt/data/close ingress, watchdogs) lives in
 * boot_mesh_terminal_client.c; the RPC adapter lives in
 * boot_mesh_terminal_rpc.c. Production code outside those translation
 * units must not include this header.
 */

#ifndef ZCL_CONFIG_BOOT_MESH_TERMINAL_INTERNAL_H
#define ZCL_CONFIG_BOOT_MESH_TERMINAL_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct msg_processor;
struct p2p_node;

/* Prefix+kind frame send on zpkgswm, the ZMTERM namespace. Defined in
 * boot_mesh_terminal.c. */
bool boot_mesh_terminal_send(struct msg_processor *mp, struct p2p_node *node,
                             uint8_t kind, const uint8_t *wire,
                             size_t wire_len);

/* Requester-lane lifecycle, driven by the responder's wire/shutdown so the
 * two halves of the lane always arm and disarm together. Defined in
 * boot_mesh_terminal_client.c. */
void boot_mesh_terminal_client_wire(struct boot_svc_ctx *svc);
void boot_mesh_terminal_client_shutdown(void);

/* Composition context for the requester lane (its own locked snapshot).
 * Defined in boot_mesh_terminal_client.c. */
struct boot_svc_ctx *boot_mesh_terminal_client_service(void);

/* Requester-lane frame ingress, called by the dispatch in
 * boot_mesh_terminal.c after the responder tables declined the frame. All
 * three take the lane lock internally and drop quietly when no client
 * session claims the frame. */
void boot_mesh_terminal_client_receipt(struct p2p_node *node,
                                       const uint8_t *wire, size_t wire_len);
void boot_mesh_terminal_client_data(struct p2p_node *node,
                                    const uint8_t *wire, size_t wire_len);
void boot_mesh_terminal_client_close_frame(struct p2p_node *node,
                                           const uint8_t *wire,
                                           size_t wire_len);

#endif /* ZCL_CONFIG_BOOT_MESH_TERMINAL_INTERNAL_H */
