/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The /observation.json onion mount, plus the two dumpstate dumpers that
 * render the same data for an operator.
 *
 * ONION-ONLY BY CONSTRUCTION. The document is served to PEERS, and the
 * reader that fetches it is another node, never a browser. A torv3 address
 * IS its publisher's ed25519 public key
 * (onion_identity_address_from_seed, net/tor_integration.h), so the
 * transport authenticates the document for free and no signature key needs
 * to exist. That matters: a signing key would create an identity a reader
 * must TRUST, which is precisely the authority shape this surface exists to
 * remove. Instead, every load-bearing claim in the document is either
 * recomputable by the reader (anchors, chainwork) or cross-checkable
 * against the named third party's own record (edges, peer claims).
 *
 * Before the first sample lands, the handler returns 0 and the route's
 * FAILCLOSED contract turns that into a 503 with a named body — an
 * unsampled node says "I have nothing", never an empty-but-healthy
 * document.
 */

#ifndef ZCL_CONTROLLERS_OBSERVATION_SITE_CONTROLLER_H
#define ZCL_CONTROLLERS_OBSERVATION_SITE_CONTROLLER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct json_value;

/* Same handler shape as blog_site_handle_request: returns the full HTTP
 * response length written to `response`, or 0 when the mount cannot answer
 * (the dispatcher then serves the row's 503). */
size_t observation_site_handle_request(const char *method, const char *path,
                                       const uint8_t *body, size_t body_len,
                                       uint8_t *response, size_t response_max);

/* g_dumpers[] "mesh_observation": THIS node's own record, byte-identical to
 * what the onion mount serves (one emitter feeds both). */
bool mesh_observation_dump_state_json(struct json_value *out, const char *key);

/* g_dumpers[] "mesh_compose": what THIS reader DERIVES from the records it
 * collected. Coverage first, then independence, then chain agreement
 * recomputed against our own chain. Zero fresh records reports UNVERIFIED,
 * never healthy. */
bool mesh_observation_compose_dump_state_json(struct json_value *out,
                                              const char *key);

#endif /* ZCL_CONTROLLERS_OBSERVATION_SITE_CONTROLLER_H */
