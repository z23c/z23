/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: The fleet board's per-peer carriage state: for each paired peer
 * the lane decided about, when it last tried a pull, when it last drained
 * an answer, how many of each, and the one named reason the most recent
 * pull did not happen or did not land. Read by `fleet board status`
 * ("carriage.peers") and `fleet doctor`. Bookkeeping only: nothing here
 * decides who is pulled, when, or under which role.
 */
#ifndef ZCL_BOOT_FLEET_BOARD_CARRIAGE_PEERS_INTERNAL_H
#define ZCL_BOOT_FLEET_BOARD_CARRIAGE_PEERS_INTERNAL_H

#include "config/boot_fleet_board.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Why the last pull toward a peer did not happen or did not land. NONE: no
 * reason on record (the last answer drained, or nothing happened yet). */
enum board_carriage_reason {
    BOARD_CARRIAGE_NONE = 0,
    BOARD_CARRIAGE_PAIRING_WINDOW_CLOSED, /* mesh_pairing_allows false */
    BOARD_CARRIAGE_NO_DELEGATION,         /* no delegation resolves the peer */
    BOARD_CARRIAGE_DELEGATION_REFUSED,    /* the delegation is not current */
    BOARD_CARRIAGE_ROSTER_GATED,          /* the roster does not admit it */
    BOARD_CARRIAGE_PULL_IN_FLIGHT,        /* a pull is already under way */
    BOARD_CARRIAGE_PEER_NOT_CONNECTED,    /* no session to the peer */
    BOARD_CARRIAGE_STREAM_OPEN_FAILED,    /* detail: the stream refusal */
    BOARD_CARRIAGE_ANSWER_REFUSED,        /* detail: the refusal or fault */
    BOARD_CARRIAGE_NOT_DUE_YET,           /* between pulls; the normal wait */
    BOARD_CARRIAGE_REASONS
};

#define BOARD_CARRIAGE_DETAIL_MAX 32u

struct board_carriage_peer {
    uint8_t peer[32];             /* the peer's master key, as the lane names it */
    int64_t last_pull_attempt_at; /* 0: never */
    int64_t last_answer_at;       /* 0: never */
    enum board_carriage_reason reason;
    char detail[BOARD_CARRIAGE_DETAIL_MAX];
    uint64_t pulls;   /* pull streams the lane tried to open */
    uint64_t answers; /* answers drained */
    uint64_t stored;  /* posts those answers added */
    uint64_t refused; /* answers refused, or pulls closed without one */
};

/* The reason name: "pairing_window_closed" ... ("" for none). */
const char *board_carriage_reason_name(enum board_carriage_reason r);

/* Record that the lane decided not to pull `peer`, with an optional detail
 * (NULL: none). A change to a reason that needs attention logs one INFO
 * line, at most one per peer per BOOT_FLEET_ROSTER_LOG_WINDOW_S. */
void board_carriage_skip(const uint8_t peer[32],
                         enum board_carriage_reason reason,
                         const char *detail, int64_t now);
/* The gate's verdict for a peer, by its enum. */
void board_carriage_gate(const uint8_t peer[32],
                         enum boot_fleet_board_gate_reason gate, int64_t now);
/* The lane tried to open a pull stream toward `peer`. `opened` says it did;
 * otherwise `not_connected` names the silent refusal and `refusal` is the
 * stream primitive's refusal name. An open stream ends every earlier skip. */
void board_carriage_pull(const uint8_t peer[32], int64_t now, bool opened,
                         bool not_connected, const char *refusal);
/* An answer from `peer` was drained, adding `stored` posts. Clears the
 * reason. */
void board_carriage_answer(const uint8_t peer[32], size_t stored, int64_t now);
/* A pull toward `peer` ended without a usable answer, for `detail`. */
void board_carriage_refused(const uint8_t peer[32], const char *detail,
                            int64_t now);
/* A second passed with no pull due: peers with no reason on record wait. */
void board_carriage_not_due(int64_t now);

/* Copy up to `cap` peer records; returns how many there are in all. */
size_t board_carriage_snapshot(struct board_carriage_peer *out, size_t cap);

#ifdef ZCL_TESTING
void board_carriage_test_reset(void);
#endif

#endif /* ZCL_BOOT_FLEET_BOARD_CARRIAGE_PEERS_INTERNAL_H */
