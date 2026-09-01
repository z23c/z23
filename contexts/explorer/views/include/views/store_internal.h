/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Store VIEW — shared internals for the presentation-layer split.
 *
 * The store page handlers and response/format helpers are pure presentation:
 * they gather already-fetched DB rows and emit HTML / HTTP responses. The
 * controller owns request dispatch, security checks, and state mutation.
 *
 * This header declares the moved emitters + format helpers so the
 * controller (which still routes to them with identical arguments) can
 * call them. It also carries the includes the view translation unit
 * needs. Project-internal linkage; included by store_controller*.c (via
 * controllers/store_controller_internal.h) and by store_view.c only —
 * not part of any public surface. */

#ifndef ZCL_VIEWS_STORE_INTERNAL_H
#define ZCL_VIEWS_STORE_INTERNAL_H

#include "controllers/store_controller.h"
#include "models/database.h"
#include "models/store.h"
#include "util/template.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sqlite3.h>

/* ── Order-form client puzzle (DERIVED in store_controller_pow.c) ──
 *
 * The controller owns the security machinery — the shared net/puzzle.h
 * gate, its policy, the seed rotation and the single-use ring. The view
 * only embeds the result in the order form, exactly as it does for the
 * CSRF token. The type lives here because serve_product_detail() needs it
 * by value and the view must not include a controller-internal header.
 *
 * The client solves SHA3-256(seed || token || ts || nonce) for `bits`
 * leading zero bits, where seed and token are the two 32-byte values
 * these hex strings decode to and ts is `server_time`. */
struct store_pow_challenge {
    char    seed_hex[65];   /* server-issued rotating challenge seed */
    char    token_hex[65];  /* product-bound peer token             */
    int     bits;           /* required leading zero bits, right now */
    int64_t server_time;    /* wall seconds; the client echoes this  */
};

void store_pow_challenge(int64_t product_id, struct store_pow_challenge *out);

/* ── Shared response/format helpers (defined in store_view.c) ── */

/* Onion address this node serves on, or NULL before Tor publishes one. */
const char *store_get_onion_address(void);

/* Format zatoshi as a ZCL price string, trimming trailing zeros but
 * keeping at least 2 decimal places. For product/order price display. */
void format_zcl_price(char *out, size_t out_len, int64_t zatoshi);

/* Write the opening HTML (doctype, head/style, nav header) for a store
 * page titled `title` into `buf`. Returns bytes written (snprintf len). */
int html_body_start(char *buf, size_t max, const char *title);

/* Write the closing HTML (</main> + site footer) for a store page.
 * Returns bytes written. */
int html_body_end(char *buf, size_t max);

/* Wrap `body` as a 200 OK HTML HTTP response (with Content-Length) into
 * `resp`. Returns the total response length written. */
size_t store_html_response(const char *body, size_t body_len,
                           uint8_t *resp, size_t max);

/* Wrap `body` as an HTML HTTP error response with the given status line
 * (e.g. "404 Not Found") into `resp`. Returns response length written. */
size_t store_error_response(const char *status_code,
                            const char *body, size_t body_len,
                            uint8_t *resp, size_t max);

/* Wrap arbitrary (possibly NUL-containing) bytes as a 200 OK response
 * with `content_type` and Content-Length. When `download_filename` is
 * non-NULL, adds Content-Disposition: attachment. Returns total bytes
 * written, or 0 if headers+body would not fit in `max` (caller must
 * treat 0 as failure). Used by serve_gated_content to stream file
 * payloads — never route binary bytes through the %s-based helpers. */
size_t store_binary_response(const uint8_t *body, size_t body_len,
                             const char *content_type,
                             const char *download_filename,
                             uint8_t *resp, size_t max);

/* Human-readable label for a STORE_ORDER_* status ("Unknown" if unknown). */
const char *store_order_status_text(int status);

/* CSS class name for a STORE_ORDER_* status (pending/failed/paid). */
const char *store_order_status_class(int status);

/* ── Read-only page renderers (defined in store_view.c) ──
 * These read already-opened DB handles and emit HTML; they perform no
 * state mutation. The order-creating action (serve_create_order) is a
 * controller-owned request handler, not a view. */
size_t serve_order_index(sqlite3 *db, uint8_t *resp, size_t max);
size_t serve_product_list(sqlite3 *db, uint8_t *resp, size_t max);
size_t serve_product_detail(sqlite3 *db, int64_t product_id,
                            uint8_t *resp, size_t max);
size_t serve_order_status(sqlite3 *db, int64_t order_id,
                          uint8_t *resp, size_t max);

/* Token-gated service page (defined in store_view.c). Checks the
 * customer's ZSLP balance via store_check_token_access (security hook
 * that stays in the controller), then emits a 403 or 200 page. */
size_t serve_gated_content(sqlite3 *db, const char *customer_addr,
                           const char *token_id, uint64_t required,
                           const char *datadir,
                           uint8_t *resp, size_t max);

#endif /* ZCL_VIEWS_STORE_INTERNAL_H */
