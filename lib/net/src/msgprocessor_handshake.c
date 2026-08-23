/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

/* P2P handshake dispatch wrappers: version, verack, sendheaders.
 * The actual handshake logic lives in msg_version.c — these are the
 * dispatch-table adapters. peer_lifecycle observability is preserved
 * exactly as it was before the split. */

#include "msgprocessor_internal.h"
#include "util/log_macros.h"

bool mp_handle_version(struct msg_processor *mp, struct p2p_node *node,
                       struct byte_stream *s)
{
    return process_version(mp, node, s);
}

bool mp_handle_verack(struct msg_processor *mp, struct p2p_node *node,
                      struct byte_stream *s)
{
    (void)s;
    return process_verack(mp, node);
}

bool process_sendheaders(struct msg_processor *mp, struct p2p_node *node)
{
    /* BIP 130 preference is idempotent. More importantly, this bounds the
     * verified tip proof below to once per connection even if a peer floods
     * duplicate sendheaders messages. */
    bool first = !node->prefer_headers;
    node->prefer_headers = true;
    if (!first || !mp || !mp->main_state)
        return true;

    /* Normal new-block relay excludes the source peer to avoid echo. When
     * that peer is our mesh observer, a quiet tip otherwise leaves it with no
     * accepted-header vote and it can only fall back to our stale version
     * handshake height. Reply once to its explicit header preference with the
     * current verified tip. This is an availability statement, never a new
     * consensus authority: the receiver still validates the header normally. */
    struct block_index *tip =
        active_chain_tip(&mp->main_state->chain_active);
    if (!tip || tip->nHeight <= 0)
        return true;
    if (!push_verified_header_announcement(mp, node, tip)) {
        LOG_WARN("headers",
                 "sendheaders: current tip unavailable for peer=%s h=%d",
                 node->addr_name, tip->nHeight);
        return true;
    }
    LOG_INFO("headers", "sendheaders: announced verified tip h=%d peer=%s",
             tip->nHeight, node->addr_name);
    return true;
}

bool mp_handle_sendheaders(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s)
{
    (void)s;
    return process_sendheaders(mp, node);
}
