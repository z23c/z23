/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the core/modules/net seam for the zclassicd v2.1.2-beta6 fast bootstrap.
 *
 * A stock beta6 client only fast-syncs from a peer it reaches on the ORDINARY
 * P2P port, so the eight snapshot commands have to be answered on a normal
 * peer connection. The server itself is engine/services (beta6_bootstrap_*.c),
 * above net in the module order: this seam copies the bounded payload out of
 * the receive stream and hands (node, command, payload) to it. No hook
 * installed — the default, and every node that has not set
 * -beta6-bootstrap-source — means the message is ignored, exactly as before
 * this seam existed.
 *
 * The eight dispatch ROWS stay in msgprocessor.c's one table; only the
 * handlers they name and the installer live here, so the legacy dispatch file
 * carries none of this seam's body.
 */

#include "msgprocessor_internal.h"

#include "net/protocol.h"
#include "base/safe_alloc.h"

#include <stdlib.h>

void msg_processor_set_beta6_bootstrap(
    struct msg_processor *mp,
    msg_beta6_bootstrap_armed_fn armed,
    msg_beta6_bootstrap_message_fn message)
{
    if (!mp)
        return;
    mp->beta6_armed = armed;
    mp->beta6_message = message;
}

static bool mp_beta6_bootstrap(struct msg_processor *mp, struct p2p_node *node,
                               struct byte_stream *s, const char *command)
{
    if (!mp || !node || !s)
        return true;
    if (!mp->beta6_message)
        return true;   /* server not wired on this node: ignore, as before */
    size_t len = stream_remaining(s);
    /* The largest beta6 request is a chunk request (a few dozen bytes); the
     * frame layer already bounds this at MAX_PROTOCOL_MESSAGE_LENGTH. */
    if (len > MAX_PROTOCOL_MESSAGE_LENGTH)
        return true;
    unsigned char *buf = NULL;
    if (len > 0) {
        buf = zcl_malloc(len, "beta6_bootstrap_payload");
        if (!buf)
            return true;
        if (!stream_read_bytes(s, buf, len)) {
            free(buf);
            return true;
        }
    }
    bool ok = mp->beta6_message(mp, node, command, buf, len);
    free(buf);
    return ok;
}

/* One row handler per beta6 command, all routed to the seam above. Declared in
 * msgprocessor_internal.h and named by g_msg_dispatch in msgprocessor.c. */
#define ZCL_BETA6_ROW(fn, command)                                      \
    bool fn(struct msg_processor *mp, struct p2p_node *node,            \
            struct byte_stream *s)                                      \
    {                                                                   \
        return mp_beta6_bootstrap(mp, node, s, command);                \
    }
ZCL_BETA6_ROW(mp_beta6_getbsman, "getbsman")
ZCL_BETA6_ROW(mp_beta6_bsman, "bsman")
ZCL_BETA6_ROW(mp_beta6_getbschk, "getbschk")
ZCL_BETA6_ROW(mp_beta6_bschk, "bschk")
ZCL_BETA6_ROW(mp_beta6_getbspman, "getbspman")
ZCL_BETA6_ROW(mp_beta6_bspman, "bspman")
ZCL_BETA6_ROW(mp_beta6_getbspchk, "getbspchk")
ZCL_BETA6_ROW(mp_beta6_bspchk, "bspchk")
#undef ZCL_BETA6_ROW
