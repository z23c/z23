/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Crypto scheme registry — singleton catalog for cryptographic verifier
 * implementations.
 *
 * One level of indirection between consensus-critical call sites and the
 * concrete crypto implementations they invoke. Consensus paths use this for
 * ECDSA public-key verification and Equihash proof verification; diagnostics
 * expose the registered scheme table for operator inspection.
 *
 * Scheme ids are PERMANENT — once allocated, never reused. New schemes
 * append to the end. Removal is also permanent (slot stays reserved
 * with status=RETIRED in the registry).
 *
 * Wrappers register themselves at process start via
 * __attribute__((constructor)), so the registry is fully populated by
 * the time main() runs. Lookup is lock-free (atomic loads).
 *
 * ── How a scheme is registered + dispatched ──────────────────────────
 * Registration: each core/modules/crypto_registry/src/scheme_<name>.c defines a
 * file-static `struct crypto_scheme` (id/kind/status/name/impl + the one
 * verify/hash fn pointer) and a `__attribute__((constructor))` that calls
 * crypto_registry_register(&scheme). The constructor also does any one-time
 * setup the impl needs (e.g. scheme_secp256k1_ecdsa.c builds a
 * SECP256K1_CONTEXT_VERIFY here). Registration is a single CAS into the
 * id-indexed slot array: first writer wins, duplicates are rejected (see
 * .c). No central list — adding a scheme means adding one .c file.
 *
 * Dispatch (the consensus pattern, as used by the two live callers
 * contexts/wallet/modules/keys/src/pubkey.c::pubkey_verify and
 * core/modules/validation/src/check_block.c::check_equihash_solution_via_registry):
 *   1. scheme = crypto_registry_lookup(<ID>);   // once, then atomic-cache
 *   2. reject if !scheme || !scheme->fn.<verb> || status RETIRED/UNREGISTERED
 *   3. return scheme->fn.<verb>(...);            // the actual crypto
 * The registry adds only the lookup indirection; the verify guarantee is
 * entirely the wrapped impl's (see each typedef below for what it proves).
 */

#ifndef ZCL_CRYPTO_REGISTRY_H
#define ZCL_CRYPTO_REGISTRY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum crypto_scheme_id {
    /* Hash functions */
    CRYPTO_HASH_SHA256              = 1,
    CRYPTO_HASH_SHA3_256            = 2,
    CRYPTO_HASH_BLAKE2B_256         = 3,

    /* Signature schemes */
    CRYPTO_SIG_ECDSA_SECP256K1      = 100,
    CRYPTO_SIG_ED25519              = 101,

    /* Zero-knowledge proofs */
    CRYPTO_ZK_GROTH16_BLS12_381     = 200,
    CRYPTO_PROOF_EQUIHASH_200_9     = 201,

    /* Sentinel — do not use as a real scheme id. Slot-array size. */
    CRYPTO_SCHEME_MAX               = 1000,
};

enum crypto_scheme_status {
    CRYPTO_STATUS_UNREGISTERED = 0,
    CRYPTO_STATUS_ACTIVE       = 1,
    CRYPTO_STATUS_DEPRECATED   = 2,   /* still works, warns on use */
    CRYPTO_STATUS_RETIRED      = 3,   /* refuses to operate */
};

enum crypto_scheme_kind {
    CRYPTO_KIND_HASH = 1,
    CRYPTO_KIND_SIG  = 2,
    CRYPTO_KIND_ZK   = 3,
};

/* Hash interface — variable-length input, fixed 32-byte output.
 * Returns 0 on success and writes 32 bytes to `out`; returns -1 only when
 * `out` is NULL (the registered sha256/blake2b-256 wrappers never fail for
 * any data/len, including data==NULL with len==0). The digest is the plain
 * one-shot of `data[0..len)` — no domain separation, no keying. */
typedef int (*crypto_hash_fn)(const void *data, size_t len, uint8_t out[32]);

/* Signature interface — verify only (signing lives in wallet layer).
 * Returns true IFF `sig` is a valid signature by `pubkey` over `msg`.
 * Contract of the registered ecdsa-secp256k1 wrapper: rejects (returns
 * false, never aborts) on any null arg, msg_len != 32, empty/oversized
 * pubkey, or empty sig; parses the pubkey and a DER signature, then
 * low-S-normalizes the signature before secp256k1_ecdsa_verify — so a
 * high-S (malleated) encoding of an otherwise-valid signature still
 * verifies true here. `msg` is the 32-byte sighash, not the message. */
typedef bool (*crypto_sig_verify_fn)(const uint8_t *pubkey, size_t pubkey_len,
                                     const uint8_t *msg, size_t msg_len,
                                     const uint8_t *sig, size_t sig_len);

/* ZK / proof-of-work interface — verify a proof against a verification key
 * + public inputs. Returns true IFF the proof is valid for those inputs.
 * Two kinds share this signature for registry uniformity:
 *   - groth16-bls12-381 (real ZK): `vk` is the serialized verifying key,
 *     `public_inputs` is n*32 BLS12-381 scalar field elements, `proof` is
 *     exactly 192 bytes. Returns false on a malformed vk/proof or pi_len
 *     not a multiple of 32.
 *   - equihash-200-9 (PoW, NOT zero-knowledge): has no verifying key, so
 *     `vk`/`vk_len` are IGNORED and callers pass (NULL, 0). `public_inputs`
 *     is the personalized block-header bytes; `proof` is the on-wire
 *     Equihash solution and (N,K) is inferred from `proof_len`. Returns
 *     true only when every Wagner collision check and the final zero-XOR
 *     hold (see core/modules/crypto/src/equihash.c). */
typedef bool (*crypto_zk_verify_fn)(const uint8_t *vk, size_t vk_len,
                                    const uint8_t *public_inputs, size_t pi_len,
                                    const uint8_t *proof, size_t proof_len);

struct crypto_scheme {
    enum crypto_scheme_id     id;
    enum crypto_scheme_kind   kind;
    enum crypto_scheme_status status;
    const char               *name;        /* "ecdsa-secp256k1", etc. */
    const char               *impl;        /* "libsecp256k1 v0.4.1", etc. */
    union {
        crypto_hash_fn       hash;
        crypto_sig_verify_fn sig_verify;
        crypto_zk_verify_fn  zk_verify;
    } fn;
};

/* Register a scheme. Returns false (and logs the reason) if the scheme is
 * malformed — id outside [1, CRYPTO_SCHEME_MAX), unknown kind, status not
 * one of ACTIVE/DEPRECATED/RETIRED, empty name, empty impl tag, or NULL fn
 * pointer — or if the id's slot is already occupied. The slot fill is a
 * single atomic compare-and-exchange, so registration is single-shot per id:
 * the first constructor to claim an id wins and every later attempt on the
 * same id returns false. The registry does NOT copy the struct; it stores
 * the pointer, so `scheme` must have static lifetime (it does — each wrapper
 * passes a file-static). Called from each scheme_<name>.c at static-init
 * time via __attribute__((constructor)); not meant for runtime use. */
bool crypto_registry_register(const struct crypto_scheme *scheme);

/* Lookup by id. Returns the registered scheme, or NULL if the id is out of
 * range or unregistered. Lock-free atomic load — safe to call concurrently
 * and from the hot consensus path; callers typically cache the result.
 * Note: a non-NULL result may be DEPRECATED or RETIRED — check ->status (or
 * use crypto_registry_is_usable) before relying on it. */
const struct crypto_scheme *crypto_registry_lookup(enum crypto_scheme_id id);

/* Policy gate: returns true only for ACTIVE or DEPRECATED schemes; false for
 * UNREGISTERED, RETIRED, or an out-of-range id. A RETIRED scheme still has a
 * live fn pointer (lookup returns it) but this returns false to signal "must
 * not operate" — callers gating on usability must consult this, not just the
 * non-NULL lookup. */
bool crypto_registry_is_usable(enum crypto_scheme_id id);

/* Counters / introspection. */
size_t crypto_registry_count(void);                       /* total registered */
size_t crypto_registry_count_by_kind(enum crypto_scheme_kind kind);

/* Diagnostics dumper — see CLAUDE.md "Adding state introspection".
 * Reentrant-safe; caller calls json_set_object(out) before invoking. */
struct json_value;
bool crypto_registry_dump_state_json(struct json_value *out, const char *key);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CRYPTO_REGISTRY_H */
