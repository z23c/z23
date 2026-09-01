/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ROM-fetch peer scoring — records a bad-chunk offence against the seeder that
 * served a chunk whose per-chunk SHA3 digest or transport MAC failed.
 *
 * Routing: when the offending endpoint maps to
 * a connected `p2p_node`, the offence is charged through the shared
 * peer_scoring_record() ban logic; otherwise it lands in a small bounded
 * local deprioritize list (same shape as the snapsync blacklist[16] —
 * engine/services/src/snapshot_sync_service.c's snapsync_blacklist_peer /
 * snapsync_is_peer_blacklisted) so a misbehaving ROM-only seeder is skipped
 * on the next scheduling round without touching the P2P ban table.
 *
 * A bad chunk is never poisonous (the content proof rejects it before use);
 * this scoring only stops us from wasting bandwidth on a peer that keeps
 * serving garbage — a bounded-duration DEPRIORITIZE, not a ban. Entries
 * expire on their own (ROM_PEER_DEPRIORITIZE_SECS) so a peer that was
 * temporarily flaky is retried again later. */

#ifndef ZCL_NET_ROM_PEER_SCORING_H
#define ZCL_NET_ROM_PEER_SCORING_H

#include <stdbool.h>
#include <stdint.h>

struct net_manager;
struct p2p_node;

/* Bounded local deprioritize-list capacity — mirrors SNAPSYNC_MAX_BLACKLIST
 * (snapshot_sync_contract.h). */
#define ROM_PEER_MAX_DEPRIORITIZE 16

/* How long a bad-chunk endpoint stays deprioritized after its most recent
 * offence. Mirrors the shape of SNAPSYNC_BLACKLIST_SECS (600s) but shorter:
 * this is scheduling pressure on an untrusted transport peer, not a ban on a
 * negotiated snapshot source. */
#define ROM_PEER_DEPRIORITIZE_SECS 300

/* Record that `peer_addr:port` served a bad chunk (`idx`) for `reason`
 * (a short static string, e.g. "digest" / "mac" / "short"). Routes to the
 * bounded local deprioritize list (no connected p2p_node is known at this
 * call site). Returns true if the offence was recorded (list had room or the
 * endpoint already had an entry to refresh), false on a NULL/empty
 * `peer_addr` or if the bounded list is full of other, still-live entries.
 * A false return still means the reason was logged — the caller does not
 * need to check it to be safe. */
bool rom_peer_note_bad_chunk(const char *peer_addr, uint16_t port,
                             uint32_t idx, const char *reason);

/* Same as rom_peer_note_bad_chunk, but for call sites that DO hold a
 * connected `p2p_node` for the offending endpoint (e.g. a future ROM-over-P2P
 * transport, or a caller that has already resolved the address to a live
 * connection): routes the offence through peer_scoring_record() with
 * PEER_OFFENCE_INVALID_CHUNK instead of the local list. `nm`/`node` may be
 * NULL, in which case this is identical to rom_peer_note_bad_chunk. */
bool rom_peer_note_bad_chunk_ex(struct net_manager *nm, struct p2p_node *node,
                                const char *peer_addr, uint16_t port,
                                uint32_t idx, const char *reason);

/* Query helper for the fetch scheduler: true if `peer_addr:port` currently
 * has a live (non-expired) local deprioritize entry. Pure query — never
 * mutates state, never touches the p2p_node ban table (a p2p_node-routed
 * offence is scored/banned entirely by peer_scoring.h; this list only knows
 * about endpoints that went through the local path). A scheduler should
 * treat "deprioritized" as "try other peers first", not "never use this
 * peer" — expired entries stop counting automatically. */
bool rom_peer_is_deprioritized(const char *peer_addr, uint16_t port);

/* Test-only: clear the local deprioritize list. */
void rom_peer_scoring_test_reset(void);

#endif /* ZCL_NET_ROM_PEER_SCORING_H */
