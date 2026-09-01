/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_FRAMEWORK_APP_PLATFORM_H
#define ZCL_FRAMEWORK_APP_PLATFORM_H

#include "zclassic23/app.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Core-side fail-closed validator for an app generation. `why` is always
 * populated on failure and never contains app-controlled format strings. */
bool zcl_app_manifest_v1_validate(const struct zcl_app_manifest_v1 *manifest,
                                  uint64_t host_capabilities,
                                  const char *expected_build_identity,
                                  char *why,
                                  size_t why_sz);

const char *zcl_app_capability_name(uint64_t one_capability);

/* Host-owned live-generation transaction. The runtime copies the host table
 * and owns only routing metadata + the opaque state handle; module code never
 * owns Core state. The manifest/module mapping must outlive its active slot.
 * This surface deliberately has no loader, storage, wallet-key, socket,
 * consensus, or release-publication authority. */
struct zcl_app_runtime_v1;

struct zcl_app_activation_receipt_v1 {
    uint32_t struct_size;
    bool ok;
    bool rolled_back;
    bool migration_prepared;
    bool migration_committed;
    uint64_t generation;
    uint32_t from_schema;
    uint32_t to_schema;
    char phase[32];
    char error[ZCL_APP_ERROR_MAX + 1];
};

struct zcl_app_runtime_v1 *zcl_app_runtime_v1_create(
    const struct zcl_app_host_v1 *host, uint64_t allowed_capabilities,
    const char *build_identity, char *why, size_t why_sz);
void zcl_app_runtime_v1_destroy(struct zcl_app_runtime_v1 *runtime);

/* Validate -> candidate self-test -> migration prepare -> old-generation
 * quiesce -> migration commit -> atomic slot replacement. Any failure leaves
 * the exact prior manifest/generation authoritative and calls abort after a
 * successful prepare. Schema removal or rollback is refused. */
bool zcl_app_runtime_v1_activate(
    struct zcl_app_runtime_v1 *runtime,
    const struct zcl_app_manifest_v1 *candidate,
    struct zcl_app_activation_receipt_v1 *receipt);

const struct zcl_app_manifest_v1 *zcl_app_runtime_v1_active(
    struct zcl_app_runtime_v1 *runtime, uint64_t *generation_out,
    uint32_t *schema_out);

/* Core-owned, non-consensus signed event contract. The payload is borrowed;
 * callers keep it alive for hashing, signing, and verification. Private keys
 * never enter the public App ABI: only Core may call the signer below. */
#define ZCL_APP_SIGNED_EVENT_V1 1u
#define ZCL_APP_EVENT_CHAIN_ID_SIZE 32u
#define ZCL_APP_EVENT_KEY_ID_SIZE 20u
#define ZCL_APP_EVENT_PUBKEY_SIZE 33u
#define ZCL_APP_EVENT_SIGNATURE_MAX 72u
#define ZCL_APP_EVENT_PAYLOAD_MAX 65536u

struct wallet;
struct zcl_app_event_signing_binding_v1;

#define ZCL_APP_WALLET_OP_SIGN_EVENT_V1 1u

struct zcl_app_event_scope_v1 {
    uint32_t struct_size;
    char app_id[ZCL_APP_ID_MAX + 1];
    char topic[ZCL_APP_TOPIC_MAX + 1];
    uint8_t chain_id[ZCL_APP_EVENT_CHAIN_ID_SIZE];
    /* Total canonical signed-envelope bytes, not payload bytes. */
    uint32_t max_event_bytes;
};

struct zcl_app_event_intent_v1 {
    uint32_t struct_size;
    uint32_t kind;
    uint64_t sequence;
    uint64_t created_at; /* Unix seconds; informational but signed. */
    uint8_t previous_event_id[32];
    struct zcl_app_bytes payload;
};

struct zcl_app_signed_event_v1 {
    uint32_t struct_size;
    uint32_t version;
    char app_id[ZCL_APP_ID_MAX + 1];
    char topic[ZCL_APP_TOPIC_MAX + 1];
    uint32_t kind;
    uint64_t sequence;
    uint64_t created_at; /* Unix seconds; informational but signed. */
    /* Genesis hash in the same raw/wire byte order as uint256.data. */
    uint8_t chain_id[ZCL_APP_EVENT_CHAIN_ID_SIZE];
    uint8_t previous_event_id[32];
    uint8_t author_key_id[ZCL_APP_EVENT_KEY_ID_SIZE];
    uint8_t author_pubkey[ZCL_APP_EVENT_PUBKEY_SIZE];
    struct zcl_app_bytes payload;
    /* Strict DER, canonical low-S secp256k1 ECDSA over the separated digest. */
    uint8_t signature[ZCL_APP_EVENT_SIGNATURE_MAX];
    uint32_t signature_len;
    uint8_t event_id[32];
};

/* Canonical unsigned field order is version, chain, length-framed app/topic,
 * kind, author key-id/pubkey, sequence, time, previous id, and length-framed
 * payload. The author key is compressed secp256k1 and author_key_id is
 * HASH160(author_pubkey). Integers are little-endian. event_id is SHA3-256 of
 * the NUL-ended
 * "zcl.app.event.id.v1" domain plus those bytes. The ECDSA digest is SHA3-256
 * of the NUL-ended "zcl.app.event.sig.v1" domain plus event_id. event_id does
 * not include signature bytes, so alternate encodings cannot fork identity.
 * A canonical signed frame appends a little-endian u16 signature length and
 * the strict-DER low-S signature. A short output buffer fails and reports the
 * required size through out_len. */
bool zcl_app_signed_event_v1_canonical_unsigned(
    const struct zcl_app_signed_event_v1 *event,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len,
    char *why,
    size_t why_sz);

bool zcl_app_signed_event_v1_id(
    const struct zcl_app_signed_event_v1 *event,
    uint8_t out_event_id[32],
    char *why,
    size_t why_sz);

bool zcl_app_signed_event_v1_sign_wallet(
    const struct zcl_app_event_intent_v1 *intent,
    const struct zcl_app_event_signing_binding_v1 *binding,
    struct wallet *wallet,
    struct zcl_app_signed_event_v1 *out_event,
    char *why,
    size_t why_sz);

bool zcl_app_signed_event_v1_verify(
    const struct zcl_app_signed_event_v1 *event,
    const struct zcl_app_event_scope_v1 *scope,
    char *why,
    size_t why_sz);

#ifdef ZCL_TESTING
/* Test-only stand-in for the future Core wallet broker. Production has no
 * public binding constructor: an App cannot submit identity, chain, topic,
 * byte policy, capability bits, or a wallet key selector to the signer. */
struct zcl_app_event_binding_test_spec_v1 {
    uint32_t struct_size;
    uint32_t operation;
    uint64_t app_generation;
    uint64_t grant_revision;
    uint8_t grant_id[32];
    uint8_t manifest_digest[32];
    struct zcl_app_event_scope_v1 scope;
    uint8_t author_key_id[ZCL_APP_EVENT_KEY_ID_SIZE];
    bool grant_active;
};

bool zcl_app_event_signing_binding_v1_test_create(
    const struct zcl_app_event_binding_test_spec_v1 *spec,
    struct zcl_app_event_signing_binding_v1 **out_binding,
    char *why,
    size_t why_sz);

void zcl_app_event_signing_binding_v1_test_destroy(
    struct zcl_app_event_signing_binding_v1 *binding);
#endif

#ifdef __cplusplus
}
#endif

#endif /* ZCL_FRAMEWORK_APP_PLATFORM_H */
