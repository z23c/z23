/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names onion-gateway views — the presentation half of the
 * fetch-and-serve surface (controllers/name_gateway_controller.h).
 *
 * THE RENDERING RULE. Everything this view is handed from the far side is
 * attacker-chosen. It is never emitted into this node's own page context.
 * The relayed document goes into an <iframe sandbox srcdoc="…"> — the
 * sandbox attribute with NO allow-* tokens gives it a unique opaque
 * origin with scripts, forms, popups, plugins, same-origin access, and
 * top-level navigation all off — and the bytes are HTML-entity-escaped
 * into the srcdoc attribute, so the parent parser can never leave the
 * attribute. The page's own Content-Security-Policy (default-src 'none')
 * is inherited by the srcdoc document, so it also cannot fetch anything.
 * The "this node does not vouch for this content" banner lives OUTSIDE
 * the iframe, where the relayed document has no ability to reach it.
 *
 * Pure rendering: fills a caller-owned response buffer with a complete
 * raw HTTP/1.1 response and returns the byte count (0 = would not fit). */

#ifndef ZCL_VIEWS_NAME_GATEWAY_VIEW_H
#define ZCL_VIEWS_NAME_GATEWAY_VIEW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* 200 page carrying the relayed document. `body`/`body_len` are the raw
 * bytes from the far side; `truncated` and `upstream_bytes` describe what
 * was dropped by the relay cap, and are stated on the page rather than
 * hidden. */
size_t name_gateway_view_page(const char *name, const char *host,
                              const uint8_t *body, size_t body_len,
                              int upstream_status, bool truncated,
                              size_t upstream_bytes,
                              uint8_t *resp, size_t max);

/* The gateway could not serve the target (off, bad host, Tor down, fetch
 * failed, empty). Still a useful page: it names the failure, and it hands
 * the visitor the direct .onion link so the name is not a dead end. */
size_t name_gateway_view_unavailable(const char *name, const char *target,
                                     const char *code, const char *message,
                                     const char *http_status,
                                     uint8_t *resp, size_t max);

#endif /* ZCL_VIEWS_NAME_GATEWAY_VIEW_H */
