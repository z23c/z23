/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot_zcode_swarm — the config-layer glue between core/modules/net (below, owns
 * sockets + the "zpkgswm" dispatch row) and the ZCODE package/work swarm
 * engines in contexts/commons/modules/vcs (above, pure schedulers + accounting). core/modules/net may
 * NOT include vcs headers (module rank net < vcs), so net speaks to the
 * swarm only through the msg_zcode_swarm_* hooks on struct msg_processor;
 * this unit implements those hooks.
 *
 * Responsibilities:
 *   - lazily create the node-global engine on the first swarm frame when
 *     -packagehost=1 and the package store is open (borrowed global store,
 *     owned service book + reward ledger loaded from <datadir>/zcode);
 *   - derive each peer's LOCAL session pseudo-key (0x02 ||
 *     SHA3-256("zcl.zcode_swarm_peer.v1" || host identity)) — a transport
 *     session scope for the service book, NOT a contributor identity;
 *   - multiplex signed `ZCWS` work frames and dual-signed `ZSR1` receipts
 *     (plus `ZSID` identity) without adding another P2P command or swarm type;
 *   - fetch each accepted work request's content.v2 context root through the
 *     existing package scheduler before any worker can consume it;
 *   - map engine penalties onto typed peer offences (peer_scoring_record);
 *   - sync engine peer membership from the live node set (handshake
 *     complete + NODE_ZCL23 + not disconnecting), announce tracked
 *     packages to every known peer (deduped per peer), drive the
 *     scheduler tick, and drain the engine's bounded outbound queue onto
 *     the node's send queue.
 *
 * The swarm is EVENT-WOKEN with a clock backstop: wire() registers a
 * supervisor child (net.zcode.swarm, 1 s period), while foreground proof
 * admission, authenticated swarm frames, and accepted DHT reachability
 * requests ask for an immediate supervised tick. Callers only set an atomic
 * hint; all SQLite/network work remains on the supervisor runner. The period
 * preserves reconciliation and lease expiry when a wake is lost or no
 * traffic arrives.
 *
 * The engine itself (contexts/commons/modules/vcs/src/package_swarm_node.c) carries the whole
 * contract; this file is transport + offence-mapping only. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_SWARM_H
#define ZCL_CONFIG_BOOT_ZCODE_SWARM_H

#include "net/msgprocessor.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;

/* msg_zcode_swarm_frame_fn: deliver one received "zpkgswm" payload. */
bool boot_zcode_swarm_frame(struct msg_processor *mp, struct p2p_node *node,
                            const uint8_t *payload, size_t payload_len,
                            void *ctx);

/* msg_zcode_swarm_tick_fn: called once per peer message cycle (node is
 * the peer being serviced). Send-latency fast path only — the swarm's
 * real clock is the net.zcode_swarm supervisor child armed by wire();
 * this hook exists because a peer with inbound traffic might as well
 * drain immediately rather than wait for the next 1 s timer. */
void boot_zcode_swarm_tick(struct msg_processor *mp, struct p2p_node *node,
                           void *ctx);

/* O(1) scheduling hint for newly durable proof work, authenticated swarm
 * input, or a queued DHT reachability request. Never performs DB/network work
 * on the caller. */
void boot_zcode_swarm_request_tick(void);

/* Wire the hooks onto svc->msg_processor and arm the supervisor child
 * that clock-drives the swarm. Cheap; safe before the store opens (the
 * engine is created lazily on first use). */
void boot_zcode_swarm_wire(struct boot_svc_ctx *svc);

/* Free the engine + book + ledger and clear the node-global engine.
 * Idempotent. MUST run before vcs_package_store_close_global() (the
 * engine borrows the global store). */
void boot_zcode_swarm_shutdown(void);

#endif /* ZCL_CONFIG_BOOT_ZCODE_SWARM_H */
