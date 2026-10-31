/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the best block of each connected fleet machine, refreshed in the
 *          background so a status call never waits on the network.
 *
 * Every machine serves its provable tip (height and block hash) at
 * GET /explorer/tip on its onion, and with GET /explorer/tip/<height> also
 * the hash of its active-chain block at that height. fleet_tip_poll_tick()
 * runs on the main thread once a second, does work every
 * FLEET_TIP_TICK_SECS, and asks at most one roster machine per tick: the due
 * machine asked longest ago, each machine at most once per
 * FLEET_TIP_REFRESH_SECS, whatever the wallet is doing. It does nothing
 * while the node is paused for thermal reasons or Tor is not ready.
 *
 * Each ask names this node's tip height, so a machine that is ahead of this
 * node still says which block it holds there. Ages are measured on a clock
 * that keeps counting while the machine is suspended (fleet_tip_now_secs).
 *
 * The tip is public chain data: the height is already in /status, and the
 * explorer serves any block hash by height. The route names no peer,
 * address, wallet or balance. */

#ifndef ZCL_CONTROLLERS_FLEET_TIP_H
#define ZCL_CONTROLLERS_FLEET_TIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct fleet_status;
struct fleet_status_local;
struct onion_fetch_result;

#define FLEET_TIP_PATH "/explorer/tip"
#define FLEET_TIP_REFRESH_SECS 60  /* per machine, between two asks */
#define FLEET_TIP_MAX_AGE_SECS 300 /* older than this is unknown */
#define FLEET_TIP_TICK_SECS 10     /* between two scheduling steps */
#define FLEET_TIP_FETCH_TIMEOUT_SECS 20
#define FLEET_TIP_BODY_MAX 384
#define FLEET_TIP_HASH_HEX 64

struct fleet_tip {
    int64_t height;
    char hash[FLEET_TIP_HASH_HEX + 1]; /* lowercase hex */
    bool has_at;                       /* the machine named a block at at_height */
    int64_t at_height;
    char at_hash[FLEET_TIP_HASH_HEX + 1];
    int64_t fetched_at; /* seconds on the fleet_tip_now_secs() clock */
    bool refusal;       /* cache only: a send is held back by this machine */
};

/* Seconds on a clock that counts time spent suspended. */
int64_t fleet_tip_now_secs(void);

/* The HTTP response for GET /explorer/tip[/<height>] over this node's chain:
 *   {"schema":"zcl.tip.v1","height":N,"hash":"<64 hex>"
 *    [,"at":{"height":M,"hash":"<64 hex>"}]}
 * `at` is present when `height_arg` is a decimal height M at or below the
 * tip that the chain holds. 0 when there is no tip, or `height_arg` is
 * present and is not a decimal number (the caller answers 404). */
size_t fleet_tip_respond(const struct fleet_status_local *chain,
                         const char *height_arg, uint8_t *response,
                         size_t response_max);

/* fleet_tip_respond() over the running node. `height_arg` is NULL for the
 * bare route. */
size_t fleet_tip_serve(uint8_t *response, size_t response_max);
size_t fleet_tip_serve_at(const char *height_arg, uint8_t *response,
                          size_t response_max);

/* Parse a tip reply: an object with an integer height >= 0 and a 64-digit
 * hex hash, and optionally an `at` object of the same shape whose height is
 * `ask_height`. Anything else is refused. Hashes are lowercased. */
bool fleet_tip_parse(const uint8_t *body, size_t len, int64_t ask_height,
                     struct fleet_tip *out);

/* The cache, keyed by fleet_status_onion_key(). A put keeps the machine's
 * refusal flag. */
void fleet_tip_cache_put(const char *key, const struct fleet_tip *tip);
bool fleet_tip_cache_get(const char *key, struct fleet_tip *out);
void fleet_tip_cache_set_refusal(const char *key, bool refusal);
/* Monotone time of the last ask of `key`, 0 when never asked. */
int64_t fleet_tip_cache_last_try(const char *key);
void fleet_tip_cache_note_try(const char *key, int64_t now);
void fleet_tip_cache_reset(void);

/* How a transport reaches a machine: the contract of
 * tor_integration_fetch_onion_blocking. NULL restores Tor. */
typedef int (*fleet_tip_transport_fn)(const char *onion, const char *path,
                                      struct onion_fetch_result *res,
                                      int timeout_secs);
void fleet_tip_set_transport(fleet_tip_transport_fn fn);

/* Ask one machine, naming `ask_height`. True with its tip; false on any
 * failure (no route, a status other than 200, a malformed reply). */
typedef bool (*fleet_tip_fetch_fn)(const char *onion, int64_t ask_height,
                                   struct fleet_tip *out);
bool fleet_tip_fetch(const char *onion, int64_t ask_height,
                     struct fleet_tip *out);

/* One scheduling step over a status whose connections are filled in: asks the
 * connected machine that is due and was asked longest ago (never asked
 * first, then roster order) and returns true, or returns false having asked
 * nobody (paused, not a member, none connected, none due). A failed ask
 * still counts as a try and changes nothing else. A successful ask is cached
 * at `now` and settles the machine's send refusal against `local`. */
bool fleet_tip_poll_step(const struct fleet_status *s,
                         const struct fleet_status_local *local, int64_t now,
                         bool paused, fleet_tip_fetch_fn fetch);

/* Main-loop hook; cheap between ticks. */
void fleet_tip_poll_tick(void);

#endif /* ZCL_CONTROLLERS_FLEET_TIP_H */
