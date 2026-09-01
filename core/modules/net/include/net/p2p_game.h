/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * P2P game protocol — low-latency direct connections between nodes.
 *
 * Demonstrates: sub-second P2P messaging, state sync, move validation,
 * and optional on-chain settlement via ZSLP tokens.
 *
 * Architecture:
 *   1. Players discover each other via .onion or direct P2P
 *   2. Game state is a compact struct exchanged per move
 *   3. Each move is signed with the player's private key
 *   4. Optional: stake ZSLP tokens, winner gets the pot
 *
 * Wire format (over existing P2P TCP connection):
 *   Command: "zgame" (12 bytes in msg header)
 *   Payload: [1 game_type] [1 action] [variable data]
 *
 * Game types:
 *   0x01 = Tic-tac-toe (latency test, simplest possible game)
 *   0x02 = Chess (future)
 *   0x03 = Custom (extensible) */

#ifndef ZCL_NET_P2P_GAME_H
#define ZCL_NET_P2P_GAME_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MSG_GAME "zgame"

/* Game types */
enum game_type {
    GAME_PING      = 0,  /* latency measurement (not a real game) */
    GAME_TICTACTOE = 1,
};

/* Actions */
enum game_action {
    GAME_INVITE    = 0,  /* invite peer to play */
    GAME_ACCEPT    = 1,  /* accept invitation */
    GAME_MOVE      = 2,  /* make a move */
    GAME_STATE     = 3,  /* full state sync */
    GAME_RESIGN    = 4,  /* resign */
    GAME_RESULT    = 5,  /* game over, report result */
};

/* Tic-tac-toe board: 9 cells, each 0=empty, 1=X, 2=O */
struct ttt_state {
    uint8_t board[9];    /* row-major: [0,1,2,3,4,5,6,7,8] */
    uint8_t turn;        /* whose turn: 1=X, 2=O */
    uint8_t winner;      /* 0=ongoing, 1=X wins, 2=O wins, 3=draw */
    uint32_t move_count;
    int64_t last_move_us; /* timestamp of last move (microseconds) */
    int64_t game_start_us;
};

/* Ping game state — measures P2P round-trip latency */
struct ping_state {
    uint32_t rounds_done;
    uint32_t rounds_total;    /* default 10 */
    int64_t min_us;
    int64_t max_us;
    int64_t sum_us;
    int64_t last_send_us;     /* timestamp of last outgoing ping */
};

/* Game session between two peers */
struct game_session {
    uint8_t game_type;
    uint8_t my_side;     /* 1=X, 2=O */
    bool active;
    bool my_turn;
    union {
        struct ttt_state ttt;
        struct ping_state ping;
    } state;
    uint8_t peer_pubkey[33]; /* peer's compressed pubkey */
    int64_t latency_us;      /* measured round-trip latency */
    int64_t total_latency_us; /* cumulative for average */
    uint32_t latency_samples;
};

/* ── Game Type Registry ──────────────────────────────────────────
 * Each game type implements this interface. Tic-tac-toe and ping are
 * built-in; new game types can be added by extending the table. */

struct game_type_def {
    uint8_t type_id;            /* wire ID: GAME_PING=0, GAME_TICTACTOE=1 */
    const char *name;           /* "ping", "tictactoe" */
    size_t state_size;
    void (*init)(void *state);
    bool (*is_finished)(const void *state);
    uint8_t (*get_winner)(const void *state);
    void (*render)(const void *state, char *out, size_t max);
};

/* Get the game type definition, or NULL if unknown. */
const struct game_type_def *game_type_lookup(uint8_t type_id);

/* Get all registered game types (NULL-terminated). */
const struct game_type_def *game_type_list(void);

/* Number of registered game types. */
int game_type_count(void);

/* Initialize a new ping game (default 10 rounds) */
void ping_init(struct ping_state *s);
void ping_init_rounds(struct ping_state *s, uint32_t rounds);

/* Record a ping round-trip. Returns true if game is complete. */
bool ping_record_rtt(struct ping_state *s, int64_t rtt_us);

/* Get average latency in microseconds. Returns -1 if no samples. */
int64_t ping_avg_latency(const struct ping_state *s);

/* Render ping results to string. */
void ping_render(const struct ping_state *s, char *out, size_t max);

/* Initialize a new tic-tac-toe game */
void ttt_init(struct ttt_state *s);

/* Make a move. Returns true if valid. */
bool ttt_move(struct ttt_state *s, uint8_t position, uint8_t player);

/* Check for winner. Updates s->winner. */
void ttt_check_winner(struct ttt_state *s);

/* Render board to string (for display). */
void ttt_render(const struct ttt_state *s, char *out, size_t max);

/* Serialize game message for P2P.
 * Returns bytes written. */
size_t game_serialize_invite(uint8_t *out, size_t max, enum game_type type);
size_t game_serialize_accept(uint8_t *out, size_t max, uint8_t side);
size_t game_serialize_move(uint8_t *out, size_t max, uint8_t position);
size_t game_serialize_state(uint8_t *out, size_t max,
                             const struct ttt_state *state);

/* Deserialize incoming game message.
 * Returns action type, fills relevant output fields. */
enum game_action game_deserialize(const uint8_t *data, size_t len,
                                   uint8_t *game_type_out,
                                   uint8_t *position_out,
                                   struct ttt_state *state_out);

#endif
