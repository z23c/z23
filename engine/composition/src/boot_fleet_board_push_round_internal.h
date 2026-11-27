/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The push's sending round as its two files share it: the queue
 * entry, the per-peer table a round builds and the steps that judge, batch
 * and hold a post, defined in boot_fleet_board_push.c, and the fan-out walk
 * over every connected peer, in boot_fleet_board_push_fanout.c. Nothing
 * outside the push half includes this. */

#ifndef ZCL_BOOT_FLEET_BOARD_PUSH_ROUND_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_PUSH_ROUND_INTERNAL_H

#include "config/boot_fleet_board.h"
#include "models/mesh_pairing.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct db_fleet_board_post;
struct node_db;
struct noise_transport_snapshot;

/* Results a sending step returns beyond the skip reasons. */
#define PUSH_OK ((int)FLEET_BOARD_PUSH_SKIPS)
#define PUSH_HOLD ((int)FLEET_BOARD_PUSH_SKIPS + 1)
#define PUSH_UNASKED ((int)FLEET_BOARD_PUSH_SKIPS + 2)

/* One post id waiting for the tick, with the post it answers or the box the
 * local caller's hint named (the hint lives here and nowhere else). */
struct push_queued {
    uint8_t id[32];
    uint8_t ref[32];
    uint8_t host[32];
    int64_t queued;
    bool has_to; /* `to` is the hinted addressee's board key; ref unused */
    uint8_t to[32];
    bool waiting; /* held once already: the peer it was meant for */
    uint8_t waiting_peer[32];
    bool fanout; /* also offered to every connected peer a pull would serve */
    bool fanned; /* held by the fan-out for one peer: counted when it rides */
};

/* One pairing row as this round sees it. The first (newest) row of each
 * Noise key leads it: the lead holds that peer's judgment and the push being
 * built for it, so one peer gets one push however many rows it has. */
struct push_peer {
    struct db_mesh_pairing row;
    uint8_t online[32];
    struct push_peer *lead; /* this row's Noise key's newest row */
    int ready;              /* lead only: PUSH_UNASKED until judged */
    uint8_t ready_to[32];   /* lead only: the board key it was judged for */
    int fan_ready;          /* lead only: the fan-out's judgment, once */
    uint8_t fan_to[32];     /* lead only: the board key the pull would serve */
    uint8_t n;
    size_t len;
    uint8_t ids[FLEET_BOARD_PUSH_POSTS_MAX][32];
    uint8_t *frame; /* FLEET_BOARD_PUSH_MAX bytes once it holds a record */
};

/* A round allocates its peer table and post buffers, and walks the pairing
 * rows, only when an entry needs resolving: a round whose every entry waits
 * for a push still open does neither. */
struct push_round {
    struct boot_svc_ctx *svc;
    struct node_db *store;
    int64_t now;
    bool ready;  /* the peer table and the buffers below are built */
    struct push_peer *peers;
    size_t n_peers;
    struct push_queued held[FLEET_BOARD_PUSH_QUEUE_MAX];
    size_t n_held;
    struct db_fleet_board_post *row;     /* the post being offered */
    struct db_fleet_board_post *ref_row; /* the post it answers */
    /* Connected roster-only peers the roster answer would serve, which the
     * fan-out cannot reach (they have no pairing row): counted once a round
     * for the author key in roster_host. */
    bool roster_counted;
    uint8_t roster_host[32];
    size_t roster_unpushed;
};

/* ── boot_fleet_board_push.c ─────────────────────────────────────────── */

/* Count `n` posts not pushed for `why`, logged rate limited. */
void board_push_skip(enum fleet_board_push_skip why, uint64_t n);
/* A push to this peer is still waiting for its receipt. */
bool board_push_out_live(const uint8_t peer_static[32]);
/* This session answered the push type as an older node does. */
bool board_push_session_unsupported(const uint8_t peer_static[32],
                                    const struct noise_transport_snapshot *snap);
/* Add the round's resolved post to `p`'s push: PUSH_OK, PUSH_HOLD when the
 * push is full, or the skip reason. */
int board_push_batch_add(struct push_round *r, struct push_peer *p,
                         const struct push_queued *q);
/* Keep `q` for the next round while `p`'s push is open, within
 * FLEET_BOARD_PUSH_WAIT_S of its queueing; else it is left to the pull. */
void board_push_hold(struct push_round *r, const struct push_queued *q,
                     const struct push_peer *p);

/* ── boot_fleet_board_push_fanout.c ──────────────────────────────────── */

/* Offer the round's resolved post `q` to every lead peer but `done` (the
 * addressed push's peer, or NULL): connected, served by the pull's own
 * disclosure decision, and not proving the post's author key. Connected
 * roster-only peers are offered one "board.rpush" OPEN of this post. A peer
 * that OPEN did not take is counted in push_fanout_roster_unpushed. A post
 * that finds no live session in either walk is push_fanout_no_session. */
void board_push_fanout(struct push_round *r, const struct push_queued *q,
                       const struct push_peer *done, const uint8_t *roster_done);
/* Resolve a roster-only addressee; PUSH_UNASKED means no roster match. */
int board_push_roster_addressed(struct push_round *r, const uint8_t to[32],
                                const uint8_t *paired, uint8_t selected[32],
                                bool *matched);
/* A post the fan-out held for one peer rode a push after its wait. */
void board_push_fanout_sent(void);
/* Fill the fan-out fields of the lane's counters. */
void board_push_fanout_counts(struct boot_fleet_board_fleet_counts *out);

#endif /* ZCL_BOOT_FLEET_BOARD_PUSH_ROUND_INTERNAL_H */
