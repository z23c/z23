/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: What the "board" stream lane (boot_fleet_board_fleet.c) and its
 * push half (boot_fleet_board_push.c) share: the state tag every board
 * stream state starts with, and the push half's callbacks and lane-tick
 * entry. The authority questions both ask are in
 * boot_fleet_board_authority_internal.h. */

#ifndef ZCL_BOOT_FLEET_BOARD_PUSH_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_PUSH_INTERNAL_H

#include "config/boot_fleet_board.h"
#include "config/mesh_stream.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct node_db;

/* What a stream's service_state is. Every state starts with its tag, and
 * every callback dispatches on that tag, never on which side opened the
 * stream: the "board" and "board.roster" services share one callback set,
 * so a state is only ever read as the struct its own tag names. A pull and
 * a push-out state live only on a stream this node opened, a serve and a
 * push-in state only on one the peer opened. */
enum board_state_tag {
    BOARD_STATE_NONE = 0, /* never stored: a state no callback may read */
    BOARD_STATE_PULL = 1,
    BOARD_STATE_SERVE = 2,
    BOARD_STATE_PUSH_OUT = 3,
    BOARD_STATE_PUSH_IN = 4,
};

/* ── from the pull lane (boot_fleet_board_fleet.c) ────────────────────── */

/* A store refusal that can clear (role not yet granted, clock, quota, a full
 * or busy store): the pull offers the post again. */
bool board_refusal_retryable(enum fleet_board_result r);

/* ── the push half (boot_fleet_board_push.c) ─────────────────────────── */

/* False only in a test standing in for a node from before the push. */
bool board_push_dispatch_enabled(void);
/* An inbound OPEN whose first byte is FLEET_BOARD_FLEET_MSG_PUSH, on the
 * frame path under the lane lock: framing checks and one copy into the push
 * inbox, nothing else. A refusal names itself in a receipt in `reply`. */
enum mesh_stream_refusal board_push_accept(struct mesh_stream *st,
                                           const uint8_t *payload, size_t len,
                                           uint8_t *reply, size_t reply_cap,
                                           size_t *reply_len);
/* The callbacks for a stream whose state is tagged PUSH_OUT or PUSH_IN. */
void board_push_data_refused(struct mesh_stream *st, enum board_state_tag tag);
void board_push_stream_tick(struct mesh_stream *st, enum board_state_tag tag,
                            int64_t now);
void board_push_stream_close(struct mesh_stream *st, enum board_state_tag tag,
                             enum mesh_stream_refusal reason,
                             const uint8_t *payload, size_t len);
/* Free one PUSH_OUT or PUSH_IN state by its own rule. */
void board_push_state_free(void *state);
/* One lane tick of push work at lane time `now` (Unix seconds): commit at
 * most one received push into `store`, the oldest, then open the pushes the
 * queue holds, then write the delivery notes pushes left. Three counter
 * reads and no lock when there is nothing to do;
 * one more counter read and one push lock pair when posts wait and nothing
 * changed since the last sending round, which then runs at most once a
 * second. */
void board_push_lane_tick(struct boot_svc_ctx *svc, struct node_db *store,
                          int64_t now);
struct board_push_receipt;
/* Count a decoded receipt only for the post IDs actually sent; false when
 * it names other posts and was not counted. */
bool board_push_receipt_seen(const uint8_t ids[][32], uint8_t n,
                             const struct board_push_receipt *receipt);
/* Fill the push fields of the lane's counters. */
void board_push_counts(struct boot_fleet_board_fleet_counts *out);
/* The token a skip reason and a push code are logged and reported as. */
const char *board_push_skip_name(unsigned why);
const char *board_push_code_name(unsigned code);
/* Drop the queue, the inbox and the per-session memory. */
void board_push_forget(void);

/* ── the delivery record (boot_fleet_board_delivery.c) ──────────────── */

/* Note what `peer` answered for the `n` posts of one push: from its receipt,
 * or, when none came, an unknown answer under `reason`. Copies into a
 * bounded ring only; safe under the stream lane lock. */
void board_delivery_note_receipt(const uint8_t peer[32], const uint8_t ids[][32],
                                 uint8_t n, const struct board_push_receipt *rc,
                                 int64_t at);
void board_delivery_note_unanswered(const uint8_t peer[32], const uint8_t ids[][32],
                                    uint8_t n, const char *reason, int64_t at);
/* Write the noted answers into the store (lane tick; never while another
 * transaction is open) and keep the table bounded. Returns rows saved. */
size_t board_delivery_flush(struct node_db *store);
/* Notes given up because the ring was full or a save failed. */
uint64_t board_delivery_dropped(void);
/* Drop every pending note. */
void board_delivery_forget(void);

#endif /* ZCL_BOOT_FLEET_BOARD_PUSH_INTERNAL_H */
