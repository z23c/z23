/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Tor v3 onion address codec — derive the 56-char hostname from a
 * 32-byte ed25519 pubkey and recover the pubkey from a hostname, with the
 * checksum and version byte verified both ways. Used by the file market to
 * put the seller's onion identity inside the signed offer wire (which has
 * no room for the text form) and by the buyer to dial that identity. */

#ifndef ZCL_NET_ONION_V3_ADDRESS_H
#define ZCL_NET_ONION_V3_ADDRESS_H

#include <stdbool.h>
#include <stdint.h>

/* 56 base32 chars + ".onion" (NUL not counted). */
#define ONION_V3_ADDRESS_LEN 62u

/* hostname = base32(pubkey || checksum || 0x03) + ".onion",
 * checksum = SHA3-256(".onion checksum" || pubkey || 0x03)[0..1]. out must
 * hold ONION_V3_ADDRESS_LEN + 1 bytes. False on NULL / zero pubkey. */
bool onion_v3_address_from_pubkey(const uint8_t pubkey[32],
                                  char out[ONION_V3_ADDRESS_LEN + 1]);

/* Inverse: accepts the 56-char form with or without the ".onion" suffix,
 * verifies the checksum and version byte, and returns the 32-byte pubkey.
 * out is zeroed on any rejection. */
bool onion_v3_pubkey_from_address(const char *address, uint8_t out[32]);

#endif /* ZCL_NET_ONION_V3_ADDRESS_H */
