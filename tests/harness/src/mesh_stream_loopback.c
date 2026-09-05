/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The shared mesh stream loopback wire (see the header). One copy, because
 * two groups driving two copies of it could disagree about what arrived.
 */

#include "test/mesh_stream_loopback.h"

#include "config/mesh_stream.h"

#include "base/safe_alloc.h"
#include "net/protocol.h"

#include <stdlib.h>
#include <string.h>

struct send_segment *mesh_loop_sentinel(struct p2p_node *node)
{
    struct send_segment *sentinel =
        zcl_calloc(1, sizeof(*sentinel), "mesh_loop_sentinel");
    node->send_head = sentinel;
    node->send_tail = sentinel;
    node->send_offset = 0;
    return sentinel;
}

size_t mesh_loop_take(struct p2p_node *from, struct send_segment *sentinel,
                      struct noise_transport *to_transport, uint8_t *out,
                      size_t out_cap, bool *more)
{
    *more = false;
    struct send_segment *seg = sentinel->next;
    if (!seg)
        return 0;
    *more = true;
    sentinel->next = seg->next;
    if (from->send_tail == seg)
        from->send_tail = sentinel;
    if (from->send_size >= seg->size)
        from->send_size -= seg->size;
    else
        from->send_size = 0;
    from->send_offset = 0;

    uint8_t *wire = NULL, *plain = NULL;
    size_t wire_len = 0, plain_len = 0, moved = 0;
    if (noise_transport_feed(to_transport, seg->data, seg->size, &wire,
                             &wire_len, &plain, &plain_len) &&
        wire_len == 0 && plain_len > MSG_HEADER_SIZE &&
        memcmp(plain + MESSAGE_START_SIZE, "zpkgswm", 7) == 0) {
        size_t payload_len = plain_len - MSG_HEADER_SIZE;
        if (payload_len <= out_cap) {
            memcpy(out, plain + MSG_HEADER_SIZE, payload_len);
            moved = payload_len;
        }
    }
    free(wire);
    free(plain);
    send_segment_free(seg);
    return moved;
}

void mesh_loop_discard(struct p2p_node *from, struct send_segment *sentinel,
                       struct noise_transport *to_transport)
{
    for (;;) {
        uint8_t frame[MESH_LOOP_WIRE_MAX];
        bool more = false;
        (void)mesh_loop_take(from, sentinel, to_transport, frame,
                             sizeof(frame), &more);
        if (!more)
            break;
    }
}

size_t mesh_loop_pump(struct p2p_node *from, struct send_segment *sentinel,
                      struct noise_transport *to_transport,
                      struct msg_processor *mp, struct p2p_node *to)
{
    size_t frames = 0;
    for (;;) {
        uint8_t frame[MESH_LOOP_WIRE_MAX];
        bool more = false;
        size_t n = mesh_loop_take(from, sentinel, to_transport, frame,
                                  sizeof(frame), &more);
        if (!more)
            break;
        if (n && mesh_stream_frame(mp, to, frame, n, NULL))
            frames++;
    }
    return frames;
}

void mesh_loop_free_queue(struct p2p_node *node,
                          struct send_segment *sentinel)
{
    if (!node || !sentinel)
        return;
    while (sentinel->next) {
        struct send_segment *seg = sentinel->next;
        sentinel->next = seg->next;
        send_segment_free(seg);
    }
    node->send_head = NULL;
    node->send_tail = NULL;
    node->transport = NULL; /* owned by the fixture */
}
