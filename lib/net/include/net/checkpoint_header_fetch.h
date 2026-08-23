/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * checkpoint_header_fetch — the P2P half of the checkpoint-header-solution cure.
 *
 * A headers-first substrate (--importblockindex / a header artifact) bulk-loads
 * the block index WITHOUT the Equihash nSolution for the compiled checkpoint
 * header. Every local solution source (in-memory index, node.db blocks.solution,
 * on-disk bodies, the header_solution_repair side-table, the block_index.bin
 * artifact) is then empty at exactly that one height, so
 * validate_headers_stage_ensure_pass_record cannot mint the -4 header-bootstrap
 * anchor and the checkpoint-bundle install refuses (retriably) — the D8
 * instant-on last gate.
 *
 * This module fetches that ONE header, with its solution, from a connected full
 * peer. It is the NET-thread mechanism only: it (a) sends a single bounded
 * getheaders span (locator forks at the checkpoint's parent, hash_stop is the
 * checkpoint hash) so a peer returns exactly the checkpoint header on the wire,
 * and (b) captures that header when process_headers deserializes it, HASH-PINNED
 * to the armed checkpoint hash. The block hash commits to nSolution (the header
 * serialization the hash is taken over INCLUDES the solution), so a peer whose
 * header hashes to the compiled checkpoint hash necessarily supplies the real
 * solution — it can waste one header of bandwidth, never inject.
 *
 * The app-layer condition checkpoint_header_solution_repair drives it: it arms
 * the request, polls the captured header, and does the frozen-Equihash verify +
 * durable persist (header_solution_repair) + ensure_pass_record. No consensus
 * predicate lives here; capture is a hash comparison, never a validation. */

#ifndef ZCL_NET_CHECKPOINT_HEADER_FETCH_H
#define ZCL_NET_CHECKPOINT_HEADER_FETCH_H

#include <stdbool.h>
#include <stdint.h>

struct block_header;
struct uint256;
struct msg_processor;
struct p2p_node;

/* Arm a fetch for the checkpoint header at `height` whose block hash is `hash`.
 * Idempotent: re-arming for the same target is safe. NULL hash / negative
 * height is a no-op. Set by the app-layer repair condition AND by boot on a
 * mainnet node that still needs the checkpoint bundle, so process_headers can
 * capture nSolution as IBD headers fly past — arming only after the height is
 * already passed misses the one header a new node needs. */
void checkpoint_header_fetch_arm(int32_t height, const struct uint256 *hash);

/* Arm for the compiled SHA3 UTXO checkpoint. No-op when no compiled
 * checkpoint exists. Cheap; capturing one header is the whole point. */
void checkpoint_header_fetch_arm_compiled(void);

/* Disarm: stop sending span requests and drop any un-consumed capture. Called by
 * the condition once the solution is durably persisted (or on shutdown). */
void checkpoint_header_fetch_disarm(void);

/* True while a fetch is armed (a request is outstanding). */
bool checkpoint_header_fetch_is_armed(void);

/* True when a captured header is waiting to be consumed by take() — a
 * NON-consuming peek at the capture slot. The app-layer repair condition reads
 * this to make its remedy immediately due (bypass the backoff) so a captured
 * checkpoint header is verified + persisted on the next engine tick instead of
 * waiting out the full backoff window. Cheap (one relaxed atomic). */
bool checkpoint_header_fetch_has_capture(void);

/* Consume a captured header. Returns true and fills *out (and *out_height, if
 * non-NULL) exactly once per capture, then clears the captured slot. The caller
 * MUST independently re-verify the hash-pin + frozen Equihash before trusting or
 * persisting it — this only transports the wire bytes off the net thread. */
bool checkpoint_header_fetch_take(struct block_header *out, int32_t *out_height);

/* Offer a just-deserialized received header (with its already-computed hash) to
 * the capture. Cheap (one relaxed atomic) when disarmed. On a hash-pin match it
 * copies the header for the condition to take. Called from process_headers for
 * every received header. */
void checkpoint_header_fetch_offer(const struct block_header *hdr,
                                   const struct uint256 *hash);

/* On a per-peer send tick: when armed and not yet captured, send ONE bounded
 * getheaders span to this peer if it is a usable full-chain source that holds
 * the checkpoint. Globally throttled so at most one request goes out per
 * interval regardless of peer count. `now_seconds` is the send-loop clock. */
void checkpoint_header_fetch_maybe_send(struct msg_processor *mp,
                                        struct p2p_node *node,
                                        int64_t now_seconds);

#ifdef ZCL_TESTING
void checkpoint_header_fetch_test_reset(void);
#endif

#endif /* ZCL_NET_CHECKPOINT_HEADER_FETCH_H */
