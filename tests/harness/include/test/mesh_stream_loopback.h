/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The loopback wire every mesh stream group drives: two real p2p nodes in
 * one process, sealing to each other's Noise transport with the socket
 * elided and nothing else. Frames go through the PRODUCTION decoder, so a
 * group that uses this proves the protocol as it ships.
 *
 * It lives here because more than one group needs the same wire, and two
 * copies of it could disagree about what "a frame arrived" means. Nothing
 * in production includes this header.
 */

#ifndef ZCL_TEST_MESH_STREAM_LOOPBACK_H
#define ZCL_TEST_MESH_STREAM_LOOPBACK_H

#include "net/msgprocessor.h"
#include "net/net.h"
#include "net/noise_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* One frame's ceiling on this wire. A caller sizing its own buffer may use
 * it; the helpers below size theirs with it. */
#define MESH_LOOP_WIRE_MAX 16384u

/* A queue head that is never sent, so p2p_node_end_message never asks the
 * (invalid) socket to write. Real segments queue behind it. The caller owns
 * the returned sentinel and frees it after mesh_loop_free_queue. */
struct send_segment *mesh_loop_sentinel(struct p2p_node *node);

/* Take the next sealed segment queued on `from`, open it on the peer's
 * transport, and copy out the one zpkgswm payload it carries. `*more` is
 * true whenever a segment was taken, so a caller can tell an empty queue
 * from a frame it could not read. */
size_t mesh_loop_take(struct p2p_node *from, struct send_segment *sentinel,
                      struct noise_transport *to_transport, uint8_t *out,
                      size_t out_cap, bool *more);

/* Every queued frame, opened on the peer's transport and thrown away.
 * Noise records must be opened in the order they were sealed, so a test
 * that wants a clean queue still has to feed every record through. */
void mesh_loop_discard(struct p2p_node *from, struct send_segment *sentinel,
                       struct noise_transport *to_transport);

/* Every frame queued on `from`, through the production decoder on `to`.
 * Returns the number the decoder accepted. */
size_t mesh_loop_pump(struct p2p_node *from, struct send_segment *sentinel,
                      struct noise_transport *to_transport,
                      struct msg_processor *mp, struct p2p_node *to);

/* Teardown: free whatever is still queued without opening it, and unhook
 * the transport, which the fixture owns rather than the node. */
void mesh_loop_free_queue(struct p2p_node *node,
                          struct send_segment *sentinel);

#endif /* ZCL_TEST_MESH_STREAM_LOOPBACK_H */
