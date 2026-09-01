/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * msgprocessor_zcode_swarm — the core/modules/net seam of the ZCODE package
 * swarm (slice 12). The swarm engine lives in contexts/commons/modules/vcs, ABOVE net in the
 * module order, so this file knows nothing about the wire contract: it
 * hands the raw frame payload to the registered hook and drops frames
 * when no hook is wired (hosting disabled, or a one-shot build). The
 * glue that implements the hook (peer offence mapping, reply sends,
 * tick driving) lives in engine/composition/src/boot_zcode_swarm.c. */

#include "net/msgprocessor.h"

#include "core/serialize.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>

/* One swarm frame carries at most one 1 MiB content.v2 chunk plus the
 * bounded object header; 2 MiB leaves generous slack and matches the
 * node-wide MAX_PROTOCOL_MESSAGE_LENGTH posture. */
#define ZCL_ZCODE_SWARM_MAX_FRAME (2u * 1024u * 1024u)

void msg_processor_set_zcode_swarm(
    struct msg_processor *mp,
    msg_zcode_swarm_frame_fn frame,
    msg_zcode_swarm_tick_fn tick,
    void *ctx)
{
    if (!mp)
        return;
    mp->zcode_swarm_frame = frame;
    mp->zcode_swarm_tick = tick;
    mp->zcode_swarm_ctx = ctx;
}

bool mp_handle_zcode_swarm(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s)
{
    if (!mp || !node || !s)
        LOG_FAIL("net.zcode_swarm", "null mp/node/stream");
    if (!mp->zcode_swarm_frame)
        return true; /* swarm not wired on this node: drop quietly */
    size_t len = stream_remaining(s);
    if (len == 0 || len > ZCL_ZCODE_SWARM_MAX_FRAME)
        return true; /* out-of-contract payload: drop, never score here */
    uint8_t *buf = zcl_malloc(len, "zcode_swarm_frame");
    if (!buf)
        LOG_FAIL("net.zcode_swarm", "alloc %zu frame bytes", len);
    bool read_ok = stream_read_bytes(s, buf, len);
    bool ok = read_ok && mp->zcode_swarm_frame(mp, node, buf, len,
                                               mp->zcode_swarm_ctx);
    free(buf);
    return ok;
}
