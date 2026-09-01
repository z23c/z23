/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Block explorer controller — Tor-only HTML block explorer. */

#ifndef ZCL_CONTROLLERS_EXPLORER_H
#define ZCL_CONTROLLERS_EXPLORER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

struct main_state;
struct tx_mempool;
struct coins_view_cache;
struct node_db;

void explorer_set_state(struct main_state *ms, struct tx_mempool *mp,
                         struct coins_view_cache *coins_tip,
                         struct node_db *ndb, const char *datadir);

void explorer_set_rpc(const char *user, const char *pass, int port);

size_t explorer_handle_request(const char *method, const char *path,
                                const uint8_t *body, size_t body_len,
                                uint8_t *response, size_t response_max);

/* Return the canonical /explorer/... location for supported top-level
 * explorer shortcuts such as /factoids and /hodl, or NULL otherwise. */
const char *explorer_canonical_shortcut(const char *path);

#ifdef ZCL_TESTING
void explorer_test_set_datadir(const char *datadir);
void explorer_test_reset_factoids_cache(void);
bool explorer_test_compute_factoids_cache_now(void);
bool explorer_test_factoids_compute_active(void);
#endif

#endif
