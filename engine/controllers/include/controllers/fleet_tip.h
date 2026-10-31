/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the best block of each connected fleet machine, refreshed in the
 *          background so a status call never waits on the network.
 *
 * Every machine serves its provable tip (height and block hash) at
 * GET /explorer/tip on its onion. fleet_tip_poll_tick() runs on the main
 * thread once a second, does work every FLEET_TIP_TICK_SECS, and asks at most
 * one roster machine per tick, each machine at most once per
 * FLEET_TIP_REFRESH_SECS, whatever the wallet is doing. It does nothing while
 * the node is paused for thermal reasons or Tor is not ready.
 *
 * The tip is public chain data: the height is already in /status, and the
 * explorer dashboard lists recent block hashes on the same onion. The route
 * names no peer, address, wallet or balance. */

#ifndef ZCL_CONTROLLERS_FLEET_TIP_H
#define ZCL_CONTROLLERS_FLEET_TIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct fleet_status;

#define FLEET_TIP_PATH "/explorer/tip"
#define FLEET_TIP_REFRESH_SECS 60  /* per machine, between two asks */
#define FLEET_TIP_MAX_AGE_SECS 300 /* older than this is unknown */
#define FLEET_TIP_TICK_SECS 10     /* between two scheduling steps */
#define FLEET_TIP_FETCH_TIMEOUT_SECS 20
#define FLEET_TIP_BODY_MAX 256
#define FLEET_TIP_HASH_HEX 64

struct fleet_tip {
    int64_t height;
    char hash[FLEET_TIP_HASH_HEX + 1]; /* lowercase hex */
    int64_t fetched_at;                /* monotonic seconds */
};

/* The HTTP response for GET /explorer/tip: this node's provable tip as
 * {"schema":"zcl.tip.v1","height":N,"hash":"<64 hex>"}. 0 when there is none
 * (the caller answers 404). */
size_t fleet_tip_serve(uint8_t *response, size_t response_max);

/* The HTTP response for a tip; fleet_tip_serve() over the provable tip. */
size_t fleet_tip_render(int64_t height, const char *hash, uint8_t *response,
                        size_t response_max);

/* Parse a tip reply: an object with an integer height >= 0 and a 64-digit
 * hex hash; anything else is refused. The hash is lowercased into `hash`. */
bool fleet_tip_parse(const uint8_t *body, size_t len, int64_t *height,
                     char hash[FLEET_TIP_HASH_HEX + 1]);

/* The cache, keyed by fleet_status_onion_key(). */
void fleet_tip_cache_put(const char *key, int64_t height, const char *hash,
                         int64_t now);
bool fleet_tip_cache_get(const char *key, struct fleet_tip *out);
/* True when `key` was not asked within FLEET_TIP_REFRESH_SECS before `now`. */
bool fleet_tip_cache_due(const char *key, int64_t now);
void fleet_tip_cache_note_try(const char *key, int64_t now);
void fleet_tip_cache_reset(void);

/* Ask one machine. True with its tip; false on any failure. */
typedef bool (*fleet_tip_fetch_fn)(const char *onion, int64_t *height,
                                   char hash[FLEET_TIP_HASH_HEX + 1]);

/* One scheduling step over a status whose connections are filled in: asks the
 * first connected machine that is due and returns true, or returns false
 * having asked nobody (paused, not a member, none connected, none due). A
 * failed ask still counts as a try. */
bool fleet_tip_poll_step(const struct fleet_status *s, int64_t now,
                         bool paused, fleet_tip_fetch_fn fetch);

/* Main-loop hook; cheap between ticks. */
void fleet_tip_poll_tick(void);

#endif /* ZCL_CONTROLLERS_FLEET_TIP_H */
