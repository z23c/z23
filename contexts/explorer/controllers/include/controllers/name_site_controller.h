/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * ZCL Names HTML site controller — name→site resolution + registry served
 * over onion + HTTPS. See engine/controllers/src/name_site_controller.c. */

#ifndef ZCL_CONTROLLERS_NAME_SITE_H
#define ZCL_CONTROLLERS_NAME_SITE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Handle any /n/ or /names request. Writes a complete raw HTTP/1.1 response
 * into `response` and returns the byte count (0 on missing args). Wired into
 * both the onion and HTTPS dispatch chains. */
size_t name_site_handle_request(const char *method, const char *path,
                                const uint8_t *body, size_t body_len,
                                uint8_t *response, size_t response_max);

/* Live CSRF token for the register action. Used by the GET form handler and
 * exposed for tests (the token is a per-process HMAC, so tests must read the
 * live value rather than precompute it). */
void name_site_csrf_token(char out[33]);

/* Verify + single-use-claim a name-bound register PoW solution
 * (peer_id = SHA3-256("znam:register:pow:" || name)). The POST handler calls
 * this internally; exposed for direct test coverage of the gate. */
bool name_pow_verify_and_claim(const char *name, const char *pow_ts_str,
                               const char *pow_nonce_str);

#endif /* ZCL_CONTROLLERS_NAME_SITE_H */
