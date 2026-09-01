/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * REST API controller — fast, indexed JSON API for the block explorer.
 * Serves /api routes on the HTTPS server.
 * Queries local node data (SQLite) with zclassicd RPC fallback + caching. */

#ifndef ZCL_CONTROLLERS_API_H
#define ZCL_CONTROLLERS_API_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

struct main_state;
struct tx_mempool;
struct coins_view_cache;
struct node_db;

void api_set_state(struct main_state *ms, struct tx_mempool *mp,
                    struct coins_view_cache *coins_tip,
                    struct node_db *ndb, const char *datadir);

/* Configure the legacy RPC backend for data we don't have locally */
void api_set_rpc_backend(const char *rpc_user, const char *rpc_pass,
                          int rpc_port);

/* Start the background API cache refresh thread.
 * Call after api_set_rpc_backend so caches warm immediately. */
void api_start_cache(void);
void api_stop_cache(void);

#ifdef ZCL_TESTING
/* Monolithic-test isolation: stop both detached API workers and wait until
 * neither can retain a borrowed database/repository binding. */
bool api_test_stop_background_workers(void);
#endif

/* Operator-private surface classifier. The answer comes from the REST route
 * registry's private_route metadata, with path-boundary matching for private
 * resource prefixes and explicit public subresource overrides such as
 * /api/v1/swaps/chains. Untrusted listeners (the clearnet TLS server) must
 * 403 these BEFORE dispatching into api_handle_request: the router never sees
 * headers or peer identity and cannot authenticate. */
bool api_route_is_operator_private(const char *path);

/* Handle an API request. Returns bytes written to response, or 0 if not handled.
 * Response includes HTTP headers + JSON body. NOTE: performs no
 * authentication — see api_route_is_operator_private above. */
size_t api_handle_request(const char *method, const char *path,
                           const uint8_t *body, size_t body_len,
                           uint8_t *response, size_t response_max);

#endif
