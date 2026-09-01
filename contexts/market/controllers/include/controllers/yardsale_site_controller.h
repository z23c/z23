/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the Yardsale app's public web surface — the /yardsale mount
 * served over the node's onion service and the public HTTPS listener
 * (both dispatch chains call yardsale_site_handle_request, exactly like
 * /blog reaches blog_site_handle_request).
 *
 * Routes:
 *   GET  /yardsale            the yard: every live sign this node
 *                             remembers (the zswap_ads projection), best
 *                             unit price first — a browse page, never a
 *                             matching engine. Below the signs, a "Known
 *                             sellers" section: fresh peer_directory rows
 *                             advertising the yardsale App, linked by
 *                             their .onion (discovery hints only — with
 *                             none discovered, the ads still propagate by
 *                             gossip and the page says so).
 *   GET  /yardsale/ad/<root>  one sign in full, plus the buy form.
 *   POST /yardsale/buy        begin the ceremony: the buyer's accept data
 *                             (his inputs, receive/change addresses, fee,
 *                             one WIF per input) becomes a zswap_accept.v1
 *                             flooded to the seller. Operator-facing: the
 *                             form lives on the buyer's OWN node.
 *   POST /yardsale/accept     the seller endpoint: the request body is one
 *                             raw zswap_accept.v1 wire; the response body
 *                             is the zswap_partial.v1 answer (the same
 *                             handler the P2P zswapaccept ingress drives).
 *
 * No CSRF token and no session, deliberately — mirroring the threat model
 * of the ceremony itself: the accept carries no signatures, the seller
 * signs only a transaction verified to pay him the exact ad terms, and a
 * forged buy POST cannot produce a valid ceremony without the buyer's own
 * keys (which the attacker does not have). Either party walking away
 * leaves no transaction and no loss.
 */

#ifndef ZCL_CONTROLLERS_YARDSALE_SITE_CONTROLLER_H
#define ZCL_CONTROLLERS_YARDSALE_SITE_CONTROLLER_H

#include <stddef.h>
#include <stdint.h>

/* Same handler shape as blog_site_handle_request: returns the full HTTP
 * response length written to response, or 0 when the mount cannot answer
 * (the dispatcher then serves its own 503). */
size_t yardsale_site_handle_request(const char *method, const char *path,
                                    const uint8_t *body, size_t body_len,
                                    uint8_t *response, size_t response_max);

#endif /* ZCL_CONTROLLERS_YARDSALE_SITE_CONTROLLER_H */
