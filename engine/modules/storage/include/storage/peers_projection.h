/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_STORAGE_PEERS_PROJECTION_H
#define ZCL_STORAGE_PEERS_PROJECTION_H

#include "storage/event_log.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct peers_projection peers_projection_t;

peers_projection_t *peers_projection_open(const char *projection_path,
                                          event_log_t *log);
void peers_projection_close(peers_projection_t *p);

uint64_t peers_projection_catch_up(peers_projection_t *p);

bool peers_projection_get(peers_projection_t *p,
                          const uint8_t ip[16], uint16_t port,
                          uint64_t *services_out,
                          int64_t *last_seen_out,
                          int32_t *height_hint_out);

uint64_t peers_projection_count(peers_projection_t *p);

/* Process-global projection wiring used by the peer model. NULL log
 * disables emission and keeps legacy writes authoritative.
 */
void peers_projection_set_event_log(event_log_t *log);
event_log_t *peers_projection_event_log(void);

bool peers_projection_emit_observed(const uint8_t ip[16], uint16_t port,
                                    uint64_t services, int64_t observed_unix,
                                    int32_t height_hint);
bool peers_projection_emit_dropped(const uint8_t ip[16], uint16_t port,
                                   uint8_t reason);

/* Bank a closed peer session: its final reputation + transfer totals. Folds
 * into the append-only peer_sessions ledger AND updates the durable
 * `addresses` reputation columns (bandwidth_score/avg_latency_us/
 * sessions_count/last_useful_time/headers_delivered/blocks_delivered).
 * NULL/absent event log → no-op returning false (fail-open). */
bool peers_projection_emit_session_closed(const uint8_t ip[16], uint16_t port,
                                          uint8_t reason,
                                          uint32_t duration_secs,
                                          uint64_t bytes_in, uint64_t bytes_out,
                                          uint64_t headers_delivered,
                                          uint64_t blocks_delivered,
                                          uint32_t bandwidth_score,
                                          int64_t avg_latency_us,
                                          int64_t last_useful_time);

/* Bank a network fork observation into the append-only fork_events ledger.
 * tip_hash_a/b are NUL-terminated hex (may be NULL/empty). */
bool peers_projection_emit_fork_observed(int64_t height, int64_t observed_unix,
                                         uint32_t num_clusters,
                                         uint32_t count_a, uint32_t count_b,
                                         const char *tip_hash_a,
                                         const char *tip_hash_b);

/* Bank a node-census observation from a completed (or failed) version
 * handshake — real peer (source=EV_CENSUS_SOURCE_PEER) OR crawler contact
 * (source=EV_CENSUS_SOURCE_CRAWLER). Folds into the durable node_census table
 * (keyed by ip/port; first_seen stays stable across re-observation) plus the
 * append-only, retention-capped census_observations time-series.
 *
 * PEDANTIC INPUT DISCIPLINE (fails closed, never corrupts a row):
 *  - user_agent is validated byte-by-byte: any non-printable byte (outside
 *    ASCII 0x20..0x7E) makes the observation MALFORMED — it is REJECTED
 *    (returns false, bumps the reject counter), never stored.
 *  - a UA longer than EV_CENSUS_UA_MAX is TRUNCATED to the cap WITH the
 *    ua_overflow flag set (partial-with-flag, never a silent truncation).
 *  - success=false records a failed dial: it only bumps dial_fail_count on an
 *    EXISTING census row and never inserts a new one nor appends a time-series
 *    row (a failed dial carries no identity).
 *
 * user_agent may be NULL/"" (treated as empty, valid). NULL/absent event log
 * → no-op returning false (fail-open). */
bool peers_projection_emit_census_observed(const uint8_t ip[16], uint16_t port,
                                           uint8_t source, bool success,
                                           const char *user_agent,
                                           int32_t protocol_version,
                                           uint64_t services,
                                           int64_t reported_height,
                                           int64_t observed_unix);

/* ── the UNMEASURED half of the census (peers_census_unprobed.c) ────────
 * Note an address we KNOW but did NOT measure — the crawler could not dial it
 * at all (no Tor circuit available for a .onion, the onion budget ran out, an
 * unrenderable address).
 *
 * This is deliberately NOT a census observation. A not-probed address must
 * never reach peers_projection_emit_census_observed(success=false), because
 * that bumps dial_fail_count — laundering "we never looked" into "this peer
 * failed" and feeding a false negative into peer reputation, which is strictly
 * worse than having no data. So the unprobed population is accounted as a
 * counter + last-reason only: no row is written, no ledger is appended, and no
 * parallel store is created. The crawler's network_census dumper reports both.
 *
 * ip/reason may be NULL (the counter still moves); reason is truncated. Always
 * returns true — this is bookkeeping, never a fallible write. */
#define PEERS_CENSUS_UNPROBED_REASON_MAX 64
bool peers_projection_note_census_unprobed(const uint8_t ip[16], uint16_t port,
                                           const char *reason);
uint64_t peers_projection_census_unprobed_total(void);
void peers_projection_census_unprobed_reason(char *out, size_t cap);

/* Durable per-peer reputation, folded from the session ledger. All fields are
 * 0 (bandwidth_score/latency) or the accumulated totals for a known address;
 * a missing/never-banked address reads all-zero via the `false` return. */
struct peer_reputation {
    uint32_t bandwidth_score;
    int64_t  avg_latency_us;
    int64_t  sessions_count;
    int64_t  last_useful_time;
    int64_t  headers_delivered;
    int64_t  blocks_delivered;
};

bool peers_projection_get_reputation(peers_projection_t *p,
                                     const uint8_t ip[16], uint16_t port,
                                     struct peer_reputation *out);

/* Process-global convenience (uses the singleton opened at boot) — the
 * connect/dial paths in net/config read reputation without threading a
 * handle. Returns false (all-zero) when no projection is open or no row. */
bool peers_projection_get_reputation_global(const uint8_t ip[16], uint16_t port,
                                            struct peer_reputation *out);

/* Iterate every address that has banked reputation (sessions_count>0), newest
 * first, bounded by `max`. Returns the number visited. Global-singleton form
 * for the boot addrman-seed step. cb must not re-enter the projection. */
typedef void (*peers_reputation_cb)(const uint8_t ip[16], uint16_t port,
                                    const struct peer_reputation *rep,
                                    void *ctx);
size_t peers_projection_for_each_reputation_global(size_t max,
                                                   peers_reputation_cb cb,
                                                   void *ctx);

struct json_value;
bool peers_projection_dump_state_json(struct json_value *out, const char *key);

/* Durable network census introspection: population, reachable-in-last-24h,
 * top-N user-agent distribution, protocol-version distribution, and a height
 * distribution summary. See CLAUDE.md "Adding state introspection". */
bool census_dump_state_json(struct json_value *out, const char *key);

/* Count node_census rows (the durable network population). */
uint64_t peers_projection_census_count(peers_projection_t *p);

#ifdef ZCL_TESTING
/* Lower the append-only ledger retention caps so the delete-oldest path is
 * provable without inserting 50,000 rows. */
void peers_projection_test_set_retention_caps(uint64_t sessions_cap,
                                              uint64_t forks_cap);
void peers_projection_test_reset_retention_caps(void);
/* Lower the census_observations time-series retention cap. */
void peers_projection_test_set_census_cap(uint64_t census_cap);
/* Row count of a ledger table ("peer_sessions" / "fork_events" /
 * "node_census" / "census_observations"), -1 on error. */
int64_t peers_projection_test_ledger_count(peers_projection_t *p,
                                           const char *table);

/* Read back one census row for assertions. Any out param may be NULL.
 * user_agent (if non-NULL) receives up to ua_cap bytes, NUL-terminated.
 * Returns false when no row exists for (ip,port). */
struct census_row_view {
    int32_t  protocol_version;
    uint64_t services;
    int64_t  last_reported_height;
    int64_t  first_seen;
    int64_t  last_seen;
    int64_t  last_success;
    int64_t  dial_success_count;
    int64_t  dial_fail_count;
    int32_t  source;
    int32_t  ua_overflow;
};
bool peers_projection_test_census_row(peers_projection_t *p,
                                      const uint8_t ip[16], uint16_t port,
                                      struct census_row_view *out,
                                      char *user_agent, size_t ua_cap);
#endif

#endif /* ZCL_STORAGE_PEERS_PROJECTION_H */
