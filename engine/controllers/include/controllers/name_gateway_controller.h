/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names onion gateway — fetch-and-serve for /n/<name>.
 *
 * WHY THIS EXISTS. A name is supposed to REPLACE the 56-character onion
 * address, not decorate it. A bare 302 puts that address straight back in
 * the visitor's URL bar and hands anyone without Tor Browser a dead link,
 * which defeats the point of naming. The gateway instead dials the target
 * over the node's embedded Tor and serves what came back.
 *
 * WHY IT IS OFF BY DEFAULT. This is a fetch-on-behalf-of-a-stranger
 * surface: an anonymous visitor chooses which third party this node's
 * circuits contact, and this node's address is what the far side sees. That
 * is an operator decision, not a default. Set ZCL_NAMES_ONION_GATEWAY=1 to
 * turn it on; with it unset /n/<name> keeps today's 302 behaviour exactly.
 * Same shape as ZCL_NAMES_PUBLIC_REGISTER in name_site_controller.c.
 *
 * WHAT BOUNDS IT (all hard, all here so they can be read in one place):
 *   - only a syntactically exact Tor v3 hostname is ever dialled
 *     (name_gateway_host_from_target → 56 base32 chars + ".onion"),
 *   - only port 80 and only the site root "/" — no visitor-supplied path,
 *     query, body, or method crosses to the far side,
 *   - NO headers are forwarded in either direction. The fetch primitive
 *     carries (address, port, path) outbound and (status, body) inbound,
 *     so no cookie, Authorization, Referer, or Set-Cookie can cross,
 *   - NAME_GATEWAY_MAX_BODY_BYTES is the hard cap on what is kept and
 *     served; anything past it is dropped and the overflow is stated on
 *     the page,
 *   - NAME_GATEWAY_TIMEOUT_SECS is the hard wall-clock cap on the dial,
 *   - /n/ carries its own EXPENSIVE onion_ratelimit route class
 *     ("name-gateway"), so a flood hits a tight budget and then a client
 *     puzzle.
 *
 * Every byte that comes back is hostile. This module hands them to the
 * caller as opaque bytes and never interprets them; rendering safety is
 * name_gateway_view.c's job (sandboxed, escaped, inert). */

#ifndef ZCL_CONTROLLERS_NAME_GATEWAY_H
#define ZCL_CONTROLLERS_NAME_GATEWAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Hard cap on relayed bytes. Deliberately small: the onion listener's
 * response buffer is 64 KiB total, and this is third-party content the
 * node does not vouch for — it is a preview surface, not a CDN. */
#define NAME_GATEWAY_MAX_BODY_BYTES (24u * 1024u)

/* Hard wall-clock cap on one dial. The fetch blocks the serving thread,
 * so this is also the worst case a single visitor can hold it for. */
#define NAME_GATEWAY_TIMEOUT_SECS 8

/* A Tor v3 hostname is 56 base32 chars + ".onion" = 62, + NUL. The buffer
 * is wider than that because extraction copies the whole authority —
 * including an explicit ":80" — before the port is stripped and the
 * hostname validated. */
#define NAME_GATEWAY_HOST_MAX 80

enum name_gateway_status {
    NAME_GATEWAY_OK = 0,
    /* Operator has not opted in — the default. */
    NAME_GATEWAY_DISABLED = 1,
    /* Target is not an exact Tor v3 onion host (or names a port we will
     * not dial, or a scheme we do not speak). Nothing was dialled. */
    NAME_GATEWAY_BAD_HOST = 2,
    /* Tor is not built in / not bootstrapped on this node. */
    NAME_GATEWAY_TOR_UNAVAILABLE = 3,
    /* Dialled, but the circuit failed or the deadline passed. */
    NAME_GATEWAY_FETCH_FAILED = 4,
    /* Far side answered with nothing to show. */
    NAME_GATEWAY_EMPTY = 5,
};

struct name_gateway_result {
    char     host[NAME_GATEWAY_HOST_MAX];
    int      http_status;      /* far side's status, 0 when never reached */
    size_t   upstream_bytes;   /* what the far side sent                  */
    size_t   body_len;         /* what we kept (<= the cap above)         */
    bool     truncated;        /* upstream_bytes > body_len               */
    uint8_t  body[NAME_GATEWAY_MAX_BODY_BYTES];
};

/* Operator opt-in state. False unless ZCL_NAMES_ONION_GATEWAY=1. */
bool name_gateway_enabled(void);

/* Exact Tor v3 hostname predicate — 56 chars of [a-z2-7] then ".onion".
 * Mirrors onion_hostname_valid() in core/modules/net/src/onion_service.c, which is
 * file-static there; see that file's comment for the rationale. SEAM: when
 * that predicate is promoted to net/onion_service.h, delete this twin. */
bool name_gateway_host_valid(const char *h);

/* Pull a dialable host out of a registered target value: strips an
 * http/https scheme, any path/query/fragment, and an explicit :80, then
 * lowercases and validates. Returns false (leaving `out` empty) for
 * anything that is not an exact Tor v3 onion host on port 80. */
bool name_gateway_host_from_target(const char *target, char *out, size_t cap);

/* Dial `target`'s onion root over embedded Tor and fill `out`. `out` is
 * zeroed first, so a failure verdict still leaves a readable struct.
 * Blocking, bounded by NAME_GATEWAY_TIMEOUT_SECS. */
enum name_gateway_status name_gateway_fetch(const char *target,
                                            struct name_gateway_result *out);

/* Stable machine code + one-sentence human explanation per verdict. */
const char *name_gateway_status_code(enum name_gateway_status s);
const char *name_gateway_status_message(enum name_gateway_status s);

#endif /* ZCL_CONTROLLERS_NAME_GATEWAY_H */
