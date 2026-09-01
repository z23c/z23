/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef ZCL_WALLET_SAPLING_KEYS_H
#define ZCL_WALLET_SAPLING_KEYS_H

#include "sapling/zip32.h"
#include "util/sync.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_SAPLING_KEYS 256
#define ZC_DIVERSIFIER_SIZE 11
#define ZC_MEMO_SIZE 512

struct sapling_key_entry {
    struct zip32_xsk xsk;
    struct zip32_xfvk xfvk;
    uint8_t diversifier[ZC_DIVERSIFIER_SIZE];
    uint8_t pk_d[32];
    uint8_t ivk[32];
    uint32_t child_index;
    bool used;
};

struct sapling_keystore {
    zcl_mutex_t cs;
    uint8_t seed[32];
    bool has_seed;
    struct zip32_xsk master_xsk;
    uint32_t next_child_index;
    struct sapling_key_entry keys[MAX_SAPLING_KEYS];
    size_t num_keys;
};

struct sapling_address_undo {
    uint32_t child_index;
    bool generated_seed;
    bool valid;
};

void sapling_keystore_init(struct sapling_keystore *sks);
void sapling_keystore_free(struct sapling_keystore *sks);

/* Draw a fresh random 32-byte seed, mark the keystore as seeded, and
 * derive the master extended spending key from it; resets the child
 * derivation counter to 0. Holds `sks->cs` for the update. Always
 * returns true. */
bool sapling_keystore_generate_seed(struct sapling_keystore *sks);

/* Install a caller-supplied 32-byte `seed`, mark the keystore as
 * seeded, derive the master extended spending key, and reset the child
 * counter to 0. Holds `sks->cs`. Use for restoring a known wallet seed.
 * Always returns true. */
bool sapling_keystore_set_seed(struct sapling_keystore *sks,
                                const uint8_t seed[32]);

/* Derive the next sequential Sapling payment address (path
 * m/32'/147'/index') and append it to the keystore. If the keystore is
 * unseeded a random seed is generated first. Writes the new address's
 * diversifier (11 bytes) to `diversifier_out` and pk_d (32 bytes) to
 * `pk_d_out`. Holds `sks->cs`. Returns false if the keystore is full
 * (MAX_SAPLING_KEYS) or address derivation fails; on those paths
 * intermediate key material is cleansed before return. */
bool sapling_keystore_new_address(struct sapling_keystore *sks,
                                   uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE],
                                   uint8_t pk_d_out[32]);

/* Transactional sibling used by receive-address creation. `undo_out` names
 * the exact appended child and whether this call created the seed. A caller
 * whose durability step fails may remove that address with
 * sapling_keystore_rollback_address(); rollback refuses if another child was
 * appended meanwhile, so it never erases a concurrent successful address. */
bool sapling_keystore_new_address_transactional(
    struct sapling_keystore *sks,
    uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE],
    uint8_t pk_d_out[32],
    struct sapling_address_undo *undo_out);
bool sapling_keystore_rollback_address(
    struct sapling_keystore *sks,
    const struct sapling_address_undo *undo);

bool sapling_encode_payment_address(const uint8_t diversifier[ZC_DIVERSIFIER_SIZE],
                                     const uint8_t pk_d[32],
                                     const char *hrp,
                                     char *out, size_t out_size);

bool sapling_decode_payment_address(const char *str,
                                     uint8_t diversifier_out[ZC_DIVERSIFIER_SIZE],
                                     uint8_t pk_d_out[32]);

bool sapling_keystore_have_spending_key(const struct sapling_keystore *sks,
                                         const uint8_t ivk[32]);

const struct sapling_key_entry *sapling_keystore_find_by_ivk(
    const struct sapling_keystore *sks, const uint8_t ivk[32]);

const struct sapling_key_entry *sapling_keystore_find_by_address(
    const struct sapling_keystore *sks,
    const uint8_t diversifier[ZC_DIVERSIFIER_SIZE],
    const uint8_t pk_d[32]);

/* Import a fully-derived extended spending key into the keystore.
 * Returns false if the key is already present or keystore is full. */
bool sapling_keystore_import_xsk(struct sapling_keystore *sks,
                                  const struct zip32_xsk *xsk);

/* Encode/decode extended spending key as bech32 (secret-extended-key-main).
 * xsk_bytes is 169 bytes: depth(1) parentFVKTag(4,LE) childIndex(4,LE)
 * chaincode(32) ask(32) nsk(32) ovk(32) dk(32). */
#define ZIP32_XSK_SERIALIZED_SIZE 169

bool sapling_encode_extended_spending_key(const struct zip32_xsk *xsk,
                                           const char *hrp,
                                           char *out, size_t out_size);

bool sapling_decode_extended_spending_key(const char *str,
                                           struct zip32_xsk *xsk_out);

/* Encode/decode extended full viewing key as bech32 (zviews). */
#define ZIP32_XFVK_SERIALIZED_SIZE 169

bool sapling_encode_extended_full_viewing_key(const struct zip32_xfvk *xfvk,
                                               const char *hrp,
                                               char *out, size_t out_size);

bool sapling_decode_extended_full_viewing_key(const char *str,
                                               struct zip32_xfvk *xfvk_out);

#endif
