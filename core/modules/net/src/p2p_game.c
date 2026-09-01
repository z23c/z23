/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * P2P game engine — tic-tac-toe for latency testing. */

#include "net/p2p_game.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static int64_t now_us(void)
{
    return platform_time_realtime_us();
}

/* ── Tic-tac-toe logic ───────────────────────────────────── */

void ttt_init(struct ttt_state *s)
{
    memset(s, 0, sizeof(*s));
    s->turn = 1; /* X goes first */
    s->game_start_us = now_us();
}

bool ttt_move(struct ttt_state *s, uint8_t pos, uint8_t player)
{
    if (pos >= 9) return false;
    if (s->board[pos] != 0) return false;
    if (s->turn != player) return false;
    if (s->winner != 0) return false;

    s->board[pos] = player;
    s->turn = (player == 1) ? 2 : 1;
    s->move_count++;
    s->last_move_us = now_us();

    ttt_check_winner(s);
    return true;
}

void ttt_check_winner(struct ttt_state *s)
{
    /* Check rows, columns, diagonals */
    static const uint8_t wins[8][3] = {
        {0,1,2}, {3,4,5}, {6,7,8}, /* rows */
        {0,3,6}, {1,4,7}, {2,5,8}, /* cols */
        {0,4,8}, {2,4,6}           /* diags */
    };

    for (int i = 0; i < 8; i++) {
        uint8_t a = s->board[wins[i][0]];
        uint8_t b = s->board[wins[i][1]];
        uint8_t c = s->board[wins[i][2]];
        if (a != 0 && a == b && b == c) {
            s->winner = a;
            return;
        }
    }

    /* Check draw */
    bool full = true;
    for (int i = 0; i < 9; i++)
        if (s->board[i] == 0) { full = false; break; }
    if (full) s->winner = 3; /* draw */
}

void ttt_render(const struct ttt_state *s, char *out, size_t max)
{
    static const char sym[] = ".XO";
    /* Clamp board/turn values for safety against corrupt state */
    #define S(i) sym[(s->board[i] <= 2) ? s->board[i] : 0]
    uint8_t t = (s->turn <= 2) ? s->turn : 1;
    snprintf(out, max,
        " %c | %c | %c \n"
        "---+---+---\n"
        " %c | %c | %c \n"
        "---+---+---\n"
        " %c | %c | %c \n"
        "Turn: %c  Moves: %u  %s",
        S(0), S(1), S(2), S(3), S(4), S(5), S(6), S(7), S(8),
        sym[t], s->move_count,
        s->winner == 1 ? "X wins!" :
        s->winner == 2 ? "O wins!" :
        s->winner == 3 ? "Draw!" : "");
    #undef S
}

/* ── Wire format serialization ───────────────────────────── */

size_t game_serialize_invite(uint8_t *out, size_t max, enum game_type type)
{
    if (max < 2) return 0;
    out[0] = (uint8_t)type;
    out[1] = GAME_INVITE;
    return 2;
}

size_t game_serialize_accept(uint8_t *out, size_t max, uint8_t side)
{
    if (max < 3) return 0;
    out[0] = GAME_TICTACTOE;
    out[1] = GAME_ACCEPT;
    out[2] = side;
    return 3;
}

size_t game_serialize_move(uint8_t *out, size_t max, uint8_t position)
{
    if (max < 4) return 0;
    out[0] = GAME_TICTACTOE;
    out[1] = GAME_MOVE;
    out[2] = position;
    /* Timestamp for latency measurement */
    int64_t ts = now_us();
    if (max >= 11) {
        memcpy(out + 3, &ts, 8);
        return 11;
    }
    return 3;
}

size_t game_serialize_state(uint8_t *out, size_t max,
                             const struct ttt_state *state)
{
    if (max < 14) return 0;
    out[0] = GAME_TICTACTOE;
    out[1] = GAME_STATE;
    memcpy(out + 2, state->board, 9);
    out[11] = state->turn;
    out[12] = state->winner;
    out[13] = (uint8_t)state->move_count;
    return 14;
}

/* ── Ping game logic ────────────────────────────────────── */

void ping_init(struct ping_state *s)
{
    memset(s, 0, sizeof(*s));
    s->rounds_total = 10;
    s->min_us = INT64_MAX;
}

void ping_init_rounds(struct ping_state *s, uint32_t rounds)
{
    ping_init(s);
    if (rounds > 0 && rounds <= 1000)
        s->rounds_total = rounds;
}

bool ping_record_rtt(struct ping_state *s, int64_t rtt_us)
{
    if (rtt_us <= 0 || rtt_us > 60000000) /* reject >60s */
        return s->rounds_done >= s->rounds_total;

    s->sum_us += rtt_us;
    if (rtt_us < s->min_us) s->min_us = rtt_us;
    if (rtt_us > s->max_us) s->max_us = rtt_us;
    s->rounds_done++;
    return s->rounds_done >= s->rounds_total;
}

int64_t ping_avg_latency(const struct ping_state *s)
{
    if (s->rounds_done == 0) return -1;
    return s->sum_us / (int64_t)s->rounds_done;
}

void ping_render(const struct ping_state *s, char *out, size_t max)
{
    if (s->rounds_done == 0) {
        snprintf(out, max, "Ping: 0/%u rounds", s->rounds_total);
        return;
    }
    int64_t avg = ping_avg_latency(s);
    snprintf(out, max,
        "Ping: %u/%u rounds  min=%.1fms  avg=%.1fms  max=%.1fms",
        s->rounds_done, s->rounds_total,
        (double)s->min_us / 1000.0,
        (double)avg / 1000.0,
        (double)s->max_us / 1000.0);
}

/* ── Game Type Registry ─────────────────────────────────── */

static void ping_init_void(void *s) { ping_init(s); }
static bool ping_is_finished(const void *s)
{
    const struct ping_state *p = s;
    return p->rounds_done >= p->rounds_total;
}
static uint8_t ping_get_winner(const void *s) { (void)s; return 3; /* draw */ }
static void ping_render_void(const void *s, char *out, size_t max)
{
    ping_render(s, out, max);
}

static void ttt_init_void(void *s) { ttt_init(s); }
static bool ttt_is_finished(const void *s)
{
    const struct ttt_state *t = s;
    return t->winner != 0;
}
static uint8_t ttt_get_winner(const void *s)
{
    const struct ttt_state *t = s;
    return t->winner;
}
static void ttt_render_void(const void *s, char *out, size_t max)
{
    ttt_render(s, out, max);
}

static const struct game_type_def g_game_types[] = {
    {
        .type_id = GAME_PING,
        .name = "ping",
        .state_size = sizeof(struct ping_state),
        .init = ping_init_void,
        .is_finished = ping_is_finished,
        .get_winner = ping_get_winner,
        .render = ping_render_void,
    },
    {
        .type_id = GAME_TICTACTOE,
        .name = "tictactoe",
        .state_size = sizeof(struct ttt_state),
        .init = ttt_init_void,
        .is_finished = ttt_is_finished,
        .get_winner = ttt_get_winner,
        .render = ttt_render_void,
    },
    { .type_id = 0xFF, .name = NULL } /* sentinel */
};

const struct game_type_def *game_type_lookup(uint8_t type_id)
{
    for (const struct game_type_def *g = g_game_types; g->name; g++) {
        if (g->type_id == type_id)
            return g;
    }
    return NULL;
}

const struct game_type_def *game_type_list(void)
{
    return g_game_types;
}

int game_type_count(void)
{
    int n = 0;
    for (const struct game_type_def *g = g_game_types; g->name; g++)
        n++;
    return n;
}

/* ── Wire format serialization ───────────────────────────── */

enum game_action game_deserialize(const uint8_t *data, size_t len,
                                   uint8_t *game_type_out,
                                   uint8_t *position_out,
                                   struct ttt_state *state_out)
{
    if (!data || len < 2) return GAME_RESIGN;
    if (game_type_out) *game_type_out = data[0];

    enum game_action action = (enum game_action)data[1];

    switch (action) {
    case GAME_INVITE:
        return GAME_INVITE;

    case GAME_ACCEPT:
        return GAME_ACCEPT;

    case GAME_MOVE:
        if (len >= 3 && position_out) *position_out = (data[2] < 9) ? data[2] : 0;
        return GAME_MOVE;

    case GAME_STATE:
        if (len >= 14 && state_out) {
            memcpy(state_out->board, data + 2, 9);
            /* Validate board values (0=empty, 1=X, 2=O) */
            for (int vi = 0; vi < 9; vi++) {
                if (state_out->board[vi] > 2)
                    state_out->board[vi] = 0;
            }
            state_out->turn = (data[11] <= 2) ? data[11] : 1;
            state_out->winner = (data[12] <= 3) ? data[12] : 0;
            state_out->move_count = (data[13] <= 9) ? data[13] : 0;
        }
        return GAME_STATE;

    default:
        return action;
    }
}
