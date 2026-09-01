/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared cross-model validators
 * -----------------------------
 * Canonical validators reused by model `validate_*` functions (via the
 * `validates_*` macros in activerecord.h) and by controllers that need
 * to reject malformed inputs before constructing a model. Keep this
 * surface small — anything that's really a model concern belongs on the
 * model itself.
 */

#ifndef ZCL_MODELS_SHARED_VALIDATORS_H
#define ZCL_MODELS_SHARED_VALIDATORS_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* True iff `addr` is a syntactically and cryptographically valid ZCL
 * address: either a transparent address (t1/t3 with valid Base58Check
 * version prefix + checksum) or a Sapling shielded address (zs1 with
 * valid bech32 checksum and decodable diversifier + pk_d).
 *
 * NULL or empty input returns false. Performs an alphanumeric+underscore
 * charset gate before decoding to prevent XSS when an address echoes
 * back into HTML output. Does NOT accept arbitrary cross-chain alphanumeric
 * strings — for ZSLP token recipients that may target non-ZCL chains,
 * use zslp_service_validate_recipient_addr() in engine/services/. */
bool zcl_validate_zcl_address(const char *addr);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_MODELS_SHARED_VALIDATORS_H */
