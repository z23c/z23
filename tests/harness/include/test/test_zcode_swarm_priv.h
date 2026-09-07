/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Private facet shared by the zcode_swarm test scenario check files
 * (test_zcode_swarm.c and its test_zcode_swarm_*.c siblings). The
 * SW_CHECK macro, the shared fixture types, and the fixture helpers
 * below are defined once in test_zcode_swarm.c; every sibling uses
 * them through this header instead of declaring its own copy. No
 * sibling declares its own file-scope mutable state. */

#ifndef TEST_ZCODE_SWARM_PRIV_H
#define TEST_ZCODE_SWARM_PRIV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "keys/key.h"
#include "keys/pubkey.h"
#include "vcs/package_manifest.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_transport.h"
#include "vcs/service_receipt.h"

#define SW_CHECK(name, expr) do {                                       \
    if (expr) { printf("  zcode_swarm: %s... OK\n", (name)); }          \
    else { printf("  zcode_swarm: %s... FAIL\n", (name)); failures++; } \
} while (0)

#define SW_MAX_FILES 12u
#define SW_MAX_FILE 1200u
#define SW_DAY 20500
#define SW_CONTRIBUTOR_SCORE UINT64_C(100)
#define SWARM_PUMP_MAX_WANTS 40u

/* ── fixture package (single-chunk files) ─────────────────────────── */

struct sw_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    size_t count;
    uint8_t contents[SW_MAX_FILES][SW_MAX_FILE];
    size_t lens[SW_MAX_FILES];
};

/* ── fixture node: store + book + engine over one datadir ─────────── */

struct sw_node {
    char datadir[1024];
    char zcode_dir[1100];
    struct vcs_package_store *store;
    struct vcs_service_book *book;
    struct vcs_swarm_engine *engine;
};

enum sw_serve_mode {
    SW_SERVE_HONEST = 0,
    SW_SERVE_WRONG_HASH,
    SW_SERVE_WRONG_COORDS,
    SW_SERVE_SILENT, /* never answer (timeout driver) */
};

struct sw_pump_stats {
    uint32_t wants;
    uint32_t cancels;
    uint32_t announces;
    uint32_t replies;
    uint32_t max_inflight; /* per-peer bound witness */
    struct vcs_swarm_frame_result last;
};

/* Fixture helpers, defined in test_zcode_swarm.c and used by scenarios
 * across more than one sibling file. */
bool sw_make_package(struct sw_pkg *p, size_t count, uint8_t seed);
void sw_free_package(struct sw_pkg *p);
const uint8_t *sw_chunk_bytes(const struct sw_pkg *p, uint32_t file_index,
                              size_t *len);
bool sw_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk);
bool sw_reward_address(char *out, size_t out_size);
bool sw_publish_release(struct vcs_package_store *store,
                        const uint8_t root[32], uint8_t seed,
                        const char *name);
uint64_t sw_score_contributor(const uint8_t contributor[33], void *ctx);
void sw_make_tmpdir(char *buf, size_t n, const char *tag);
bool sw_node_open(struct sw_node *n, const char *tag,
                  vcs_swarm_score_fn score_fn);
void sw_node_close(struct sw_node *n);
void sw_key(uint8_t seed, uint8_t out[33]);
size_t sw_announce_frame(const struct sw_pkg *p, uint8_t *out);
void sw_announce(struct vcs_swarm_engine *e, uint64_t peer,
                 const struct sw_pkg *p);
void sw_pump(struct sw_node *n, uint64_t peer, const struct sw_pkg *p,
            enum sw_serve_mode mode, bool duplicate_last, uint64_t now,
            struct sw_pump_stats *st);
bool sw_drive_complete(struct sw_node *n, const uint64_t *peers,
                       size_t peer_count, const struct sw_pkg *p,
                       uint32_t *max_inflight);
size_t sw_drain_wants(struct sw_node *n, uint64_t peer,
                      struct vcs_package_swarm_object *wants, size_t max);
struct vcs_swarm_frame_result sw_answer(
    struct sw_node *n, uint64_t peer,
    const struct vcs_package_swarm_object *want, const uint8_t *bytes,
    size_t bytes_len, uint32_t file_index_override);

/* Scenario group runners — test_zcode_swarm.c's entry point calls
 * every one of these in order; each lives in the sibling file its
 * scenario names.
 *
 * test_zcode_swarm_adversarial.c — malicious/wrong-hash/wrong-coord
 * chunks, unsolicited data and replay, cancel/disconnect races,
 * announce policy (inventory bound, flood limit), and the C23 shelf
 * announce walk. */
int t_swarm_invalid_data(void);
int t_swarm_unsolicited_and_replay(void);
int t_swarm_cancel_race(void);
int t_swarm_drop_race(void);
int t_swarm_announce_policy(void);
int t_swarm_c23_shelf_announce(void);

/* test_zcode_swarm_transfer.c — scheduler shape (rarest-first,
 * per-peer bound, multi-peer spread), timeout/retry, disconnect
 * requeue, resume from restart, serving/allowance, the disconnect
 * offence threshold, and blob transfer. */
int t_swarm_scheduler_order(void);
int t_swarm_timeout_retry(void);
int t_swarm_disconnect_requeue(void);
int t_swarm_resume(void);
int t_swarm_serving_and_allowance(void);
int t_swarm_disconnect_threshold(void);
int t_swarm_blob_transfer(void);

/* test_zcode_swarm_provider_and_receipts.c — provider-directed
 * downloads, the bounded-provider/legacy-record/event-driven-schedule
 * paths, dual-signed receipt exchange and session, and peer_offer. */
int t_swarm_provider_restricted(void);
int t_swarm_bounded_provider(void);
int t_swarm_legacy_record(void);
int t_swarm_event_driven_schedule(void);
int t_swarm_receipt_exchange(void);
int t_swarm_receipt_session(void);
int t_swarm_peer_offer(void);

#endif
