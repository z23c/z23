/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * BIP44 multi-account hierarchy: m/44'/coin'/account'/change/index
 * ZClassic coin type = 147 (registered in SLIP-0044).
 *
 * Provides typed derivation from a BIP32 master key to external/internal
 * address chains, with monotonic index tracking for wallet integration.
 */

#ifndef ZCL_WALLET_BIP44_H
#define ZCL_WALLET_BIP44_H

#include "wallet/hd_keychain.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include <stdbool.h>
#include <stdint.h>

/* BIP44 constants */
#define BIP44_PURPOSE   44
#define BIP44_ZCL_COIN  147

/* BIP44 chain indices (non-hardened) */
#define BIP44_EXTERNAL  0   /* receiving addresses */
#define BIP44_INTERNAL  1   /* change addresses */

/* Maximum account index (non-hardened limit) */
#define BIP44_MAX_ACCOUNT 0x7FFFFFFFu

/* Maximum address index */
#define BIP44_MAX_INDEX   0x7FFFFFFFu

/* ── Account-level derivation ──────────────────────────────────────── */

/* Derive the account-level extended key: m/44'/147'/account'
 * account is the account number (0-based, will be hardened automatically).
 * Returns false on derivation failure. */
bool bip44_derive_account(const struct ext_key *master,
                          struct ext_key *account_out,
                          uint32_t account);

/* ── Chain-level derivation ────────────────────────────────────────── */

/* Derive the chain-level extended key: m/44'/147'/account'/change
 * change must be BIP44_EXTERNAL (0) or BIP44_INTERNAL (1). */
bool bip44_derive_chain(const struct ext_key *master,
                        struct ext_key *chain_out,
                        uint32_t account, uint32_t change);

/* ── Address-level derivation ──────────────────────────────────────── */

/* Derive a single address key: m/44'/147'/account'/change/index
 * Extracts the private key and public key for the derived child. */
bool bip44_derive_key(const struct ext_key *master,
                      struct ext_key *key_out,
                      uint32_t account, uint32_t change, uint32_t index);

/* Convenience: derive and extract just the privkey + pubkey pair. */
bool bip44_derive_keypair(const struct ext_key *master,
                          struct privkey *priv_out,
                          struct pubkey *pub_out,
                          uint32_t account, uint32_t change, uint32_t index);

/* ── Path formatting ───────────────────────────────────────────────── */

/* Format a BIP44 path string into buf. Returns bytes written (excl NUL)
 * or -1 if buf is too small. */
int bip44_format_path(char *buf, size_t buf_size,
                      uint32_t account, uint32_t change, uint32_t index);

#endif /* ZCL_WALLET_BIP44_H */
