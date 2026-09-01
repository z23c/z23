/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * params_service.h — carry the Zcash zk PROVING parameters between peers.
 *
 * This is the transport half of the feature whose verifier is
 * sapling/params_fetch.h. It adds six ZCL23 P2P commands and nothing else:
 * no new socket, no new port, no name to resolve, no certificate. The bytes
 * ride the same connections the node already has, which on a Tor-configured
 * node means they ride the onion circuits the node already built.
 *
 *   zparaminfo  →   "which parameter files can you serve?"       (no payload)
 *   zparamhave  ←   "these, at these lengths and chunk counts"
 *   zparammreq  →   "manifest for file N"
 *   zparamman   ←   chunk_count × 32-byte leaf hashes
 *   zparamcreq  →   "chunk C of file N"
 *   zparamdata  ←   the chunk bytes
 *
 * The requester trusts none of it. `zparamhave` is a hint about who to ask;
 * the lengths in it are compared against the compiled-in pin and a peer that
 * disagrees is simply not asked. `zparamman` is accepted only if it folds to
 * the compiled-in Merkle root. `zparamdata` is accepted only if it hashes to
 * the manifest leaf for that index. See sapling/params_fetch.h for why that
 * chain is sufficient.
 *
 * SERVING IS OFF BY DEFAULT. A node answers zparammreq/zparamcreq only after
 * zcl_param_serve_prepare() has verified its own local copy of the files —
 * which a node with no parameters can never do — and every answer is rate
 * limited. Nothing here runs on the reducer or tick threads: the serve path
 * is a bounded pread into a stack-sized buffer on the message thread.
 */

#ifndef ZCL_NET_PARAMS_SERVICE_H
#define ZCL_NET_PARAMS_SERVICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct msg_processor;
struct p2p_node;
struct byte_stream;

/* ── Wire commands (≤12 bytes, as the dispatch table requires) ─────── */
#define MSG_PARAM_INFO_REQ  "zparaminfo"
#define MSG_PARAM_INFO      "zparamhave"
#define MSG_PARAM_MAN_REQ   "zparammreq"
#define MSG_PARAM_MANIFEST  "zparamman"
#define MSG_PARAM_CHUNK_REQ "zparamcreq"
#define MSG_PARAM_CHUNK     "zparamdata"

/* ── Wire bounds ────────────────────────────────────────────────────
 *
 * Chunk payloads are at most 1 MiB + a 9-byte header, comfortably inside
 * MAX_PROTOCOL_MESSAGE_LENGTH (2 MiB). The manifest for the largest file is
 * 692 × 32 = 22144 bytes. Nothing here can be inflated by a peer: every
 * length is checked against a value derived from the compiled-in pin table
 * before a single byte is copied.
 */
#define PARAM_SERVE_MAX_CHUNKS_PER_HOUR       2048u   /* per peer IP */
#define PARAM_SERVE_MAX_GLOBAL_CHUNKS_PER_HOUR 65536ull
#define PARAM_SERVE_MAX_MANIFESTS_PER_HOUR    64u

/* How much garbage one peer may cost us before we stop asking it anything.
 * A peer that sends a chunk failing its manifest hash has spent our
 * bandwidth to no effect; at 8 MiB of that it is written off for the
 * lifetime of the connection. */
#define PARAM_PEER_WASTE_BUDGET_BYTES (8ull * 1024ull * 1024ull)

/* Must cover the connection reactor's full admitted peer set. The production
 * translation unit asserts this against REACTOR_MAX_FDS. */
#define PARAM_PEER_ACCOUNTING_SLOTS 1024u

/* A chunk request that has gone unanswered this long is reissued, possibly
 * to a different peer. Generous because the transport may be Tor on a
 * 7200rpm box doing under 2 MB/s. */
#define PARAM_REQUEST_TIMEOUT_SECS 180

/* Requests in flight to one peer at a time. Keeping this small is what stops
 * a slow peer from parking the whole download behind its queue. */
#define PARAM_MAX_INFLIGHT_PER_PEER 4

/* ── Dispatch handlers ───────────────────────────────────────────────
 * Registered in g_msg_dispatch (core/modules/net/src/msgprocessor.c), all with
 * requires_handshake = true and zcl23_only = true. */
bool mp_handle_param_info_req(struct msg_processor *mp, struct p2p_node *node,
                              struct byte_stream *s);
bool mp_handle_param_info(struct msg_processor *mp, struct p2p_node *node,
                          struct byte_stream *s);
bool mp_handle_param_man_req(struct msg_processor *mp, struct p2p_node *node,
                             struct byte_stream *s);
bool mp_handle_param_manifest(struct msg_processor *mp, struct p2p_node *node,
                              struct byte_stream *s);
bool mp_handle_param_chunk_req(struct msg_processor *mp, struct p2p_node *node,
                               struct byte_stream *s);
bool mp_handle_param_chunk(struct msg_processor *mp, struct p2p_node *node,
                           struct byte_stream *s);

/* ── Serving ────────────────────────────────────────────────────────── */

/* Verify the local parameter set and arm serving. Streams every file, so it
 * must be called from a background thread, never from a message handler.
 * Returns the number of files armed. Until this succeeds the node answers
 * zparammreq / zparamcreq with nothing at all. */
int param_service_arm_serving(const char *params_dir);

bool param_service_is_serving(void);

/* ── Fetching ───────────────────────────────────────────────────────── */

/* Arm the requester against `params_dir`. Files already installed and
 * verified are skipped. Returns true if there is anything to fetch — false
 * means the node already has a complete, verified parameter set.
 *
 * This does NOT start any transfer by itself; it makes the node willing to
 * ask peers, and the asking happens when a peer becomes available
 * (param_service_offer_peer) or when the tick reissues a timed-out request. */
bool param_service_begin_fetch(const char *params_dir);

bool param_service_fetch_active(void);

/* Stop fetching and release the session. Any `.part` and `.zpart` files stay
 * on disk, so the next param_service_begin_fetch resumes rather than
 * restarts. */
void param_service_end_fetch(void);

/* Tell the requester about a peer that just completed its handshake. Sends
 * one zparaminfo. Cheap and idempotent; safe to call for every peer. */
void param_service_offer_peer(struct msg_processor *mp, struct p2p_node *node);

/* Expire requests whose deadline passed, returning those chunks to the
 * missing set so the next peer to answer a zparaminfo is asked for them.
 *
 * It does NOT dial or re-send by itself: this module deliberately holds no
 * peer list, so re-requesting is driven by param_service_offer_peer being
 * called for peers as they become available. A caller that wants steady
 * progress should call this tick and then offer it a peer or two on the same
 * schedule. Queues no messages and does no I/O. */
void param_service_tick(struct msg_processor *mp, int64_t now_secs);

/* Progress, for status reporting. `out_file` receives the pinned index of
 * the file currently being fetched, or -1. */
void param_service_progress(int *out_file, uint32_t *out_have,
                            uint32_t *out_total);

#ifdef ZCL_TESTING
/* Byte-shape, peer-identity, and pre-hash admission seams. */
void param_service_test_rate_key(const uint8_t ip[16], bool has_torv3,
                                 const uint8_t torv3[32], uint8_t out[16]);
void param_service_test_wire_entry(uint8_t idx, uint64_t bytes,
                                   uint32_t chunks, uint8_t out[13]);
void param_service_test_wire_chunk_request(uint8_t idx, uint32_t chunk,
                                           uint8_t out[5]);
void param_service_test_peer_guard_reset(void);
bool param_service_test_mark_requested(int32_t id, uint32_t chunk);
void param_service_test_charge_peer(int32_t id, uint64_t bytes);
bool param_service_test_chunk_admitted(int32_t id, uint32_t chunk);

/* Test seam: drive the requester's accept path without a socket. Returns the
 * same verdict the message handler would reach. */
int param_service_test_accept_chunk(uint32_t file_idx, uint32_t chunk_idx,
                                    const uint8_t *data, size_t len);
#endif

#endif /* ZCL_NET_PARAMS_SERVICE_H */
