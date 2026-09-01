/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Explorer secondary-page views: tokens, token detail, HODL wave, event
 * log, names, market, swaps, messages, and the shared projection-status page.
 * Each renders an HTTP+HTML response into the caller's buffer. Controllers
 * parse the request, pass the datadir, and delegate page assembly here. */

#ifndef ZCL_VIEWS_EXPLORER_PAGES_VIEW_H
#define ZCL_VIEWS_EXPLORER_PAGES_VIEW_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/* Shared projection-status page served by stats/factoids while their cache
 * warms. `accent` is the heading color; `subtitle` is the one-line status.
 * Returns bytes written. */
size_t explorer_view_loading_placeholder(uint8_t *r, size_t max,
                                          const char *title,
                                          const char *accent,
                                          const char *subtitle);

/* Shared error-page emitter for HTTP errors (404, 500, 503, etc.).
 * Renders a styled error page with the given title and message.
 * Returns bytes written. */
size_t explorer_emit_error_page(uint8_t *out, size_t max,
                                 int http_status,
                                 const char *title,
                                 const char *message);

/* ZSLP tokens index page. Opens its own read-only node.db under datadir,
 * renders into r, returns bytes written (0 on error). */
size_t explorer_view_tokens(const char *datadir, uint8_t *r, size_t max);

/* ZSLP token detail page for the given 64-hex token id. */
size_t explorer_view_token_detail(const char *token_id_hex,
                                   const char *datadir,
                                   uint8_t *r, size_t max);

/* HODL wave page (UTXO age distribution + time series). */
size_t explorer_view_hodl(const char *datadir, uint8_t *r, size_t max);
#ifdef ZCL_TESTING
void explorer_test_reset_hodl_view_cache(void);
bool explorer_test_hodl_view_refresh_active(void);
#endif

/* Static client-rendered pages (data fetched via the JSON API by inline JS). */
size_t explorer_view_events(uint8_t *r, size_t max);
size_t explorer_view_names(uint8_t *r, size_t max);
/* Server-rendered /network page over the banked census + topology stores.
 * `datadir` locates <datadir>/peers_projection.db + topology.db; degrades to a
 * bounded "not populated" card when the indexer lane has not written it yet. */
size_t explorer_view_network(const char *datadir, uint8_t *r, size_t max);
size_t explorer_view_market(uint8_t *r, size_t max);
size_t explorer_view_swaps(uint8_t *r, size_t max);
size_t explorer_view_messages(uint8_t *r, size_t max);

#endif
