/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_pointer — the ZCODE ZNAM pointer layer (slice 4). A ZNAM name may
 * carry a ZCODE pointer record set: a package pointer (e.g. "ringbuffer")
 * naming the latest release root plus metadata, or a publisher profile
 * (e.g. "rhett") naming the contributor's profile metadata. This layer
 * resolves those records out of the CANONICAL ZNAM model
 * (engine/models/znam.*, node.db) — it creates no parallel name registry.
 *
 * POINTERS, NEVER IDENTITY: a ZNAM record is a mutable claim. The signed
 * release envelope and the package root stay the only package identity;
 * moving a pointer never changes an existing release (slice 1+3 enforce
 * this at the codec and store layers; this layer enforces it at the
 * presentation layer by keeping pointer facts and identity facts in
 * separate output shapes).
 *
 * POINTER RECORDS (all optional except kind; carried by existing ZNAM
 * primitives — primary target + SET_TEXT records):
 *   primary target (ZNAM_TYPE_CONTENT)  64-hex package root (package kind)
 *   text "zcode:kind"        "package" | "publisher"   (REQUIRED — a name
 *                                                     without it is not a
 *                                                     ZCODE pointer)
 *   text "zcode:pubkey"      66-hex compressed publisher pubkey
 *   text "zcode:description" package description
 *   text "zcode:onion"       onion service
 *   text "zcode:protocol"    supported package protocol version
 *   text "zcode:display"     contributor display name (publisher kind)
 *   text "zcode:profile"     64-hex profile root (publisher kind)
 *   text "zcode:index"       64-hex package index root (publisher kind)
 *   text "zcode:reward"      contributor reward address (publisher kind)
 *
 * BINDING (who may set/move a pointer): on-chain ZNAM already
 * authenticates record writes to the name's owner key (first-input P2PKH
 * signature). A ZCODE pointer is BOUND exactly when the name's
 * owner_address equals the P2PKH address derived from the claimed
 * zcode:pubkey on the active chain — i.e. only the publisher key holder's
 * own name can point at their releases. An unbound pointer (a squatted or
 * stale claim) resolves as bound=false and the commands refuse to treat it
 * as a valid pointer. */

#ifndef ZCL_SERVICES_ZCODE_POINTER_H
#define ZCL_SERVICES_ZCODE_POINTER_H

#include "models/database.h"
#include "models/znam.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ZCODE_POINTER_KEY_KIND "zcode:kind"
#define ZCODE_POINTER_KEY_PUBKEY "zcode:pubkey"
#define ZCODE_POINTER_KEY_DESCRIPTION "zcode:description"
#define ZCODE_POINTER_KEY_ONION "zcode:onion"
#define ZCODE_POINTER_KEY_PROTOCOL "zcode:protocol"
#define ZCODE_POINTER_KEY_DISPLAY "zcode:display"
#define ZCODE_POINTER_KEY_PROFILE "zcode:profile"
#define ZCODE_POINTER_KEY_INDEX "zcode:index"
#define ZCODE_POINTER_KEY_REWARD "zcode:reward"

#define ZCODE_POINTER_KIND_PACKAGE "package"
#define ZCODE_POINTER_KIND_PUBLISHER "publisher"

enum zcode_pointer_kind {
    ZCODE_POINTER_NONE = 0,   /* not a ZCODE pointer (no zcode:kind) */
    ZCODE_POINTER_PACKAGE,
    ZCODE_POINTER_PUBLISHER,
};

struct zcode_pointer {
    enum zcode_pointer_kind kind;
    char name[ZNAM_NAME_MAX + 1];
    char owner_address[64];
    /* Claimed pointer facts (empty when unset): */
    char package_root_hex[65];  /* package: primary CONTENT target */
    char publisher_hex[67];     /* zcode:pubkey */
    char description[ZNAM_TEXT_VAL_MAX + 1];
    char onion[ZNAM_TEXT_VAL_MAX + 1];
    char protocol[ZNAM_TEXT_VAL_MAX + 1];
    char display[ZNAM_TEXT_VAL_MAX + 1];     /* publisher */
    char profile_root_hex[65];               /* publisher */
    char index_root_hex[65];                 /* publisher */
    char reward_address[ZNAM_TEXT_VAL_MAX + 1]; /* publisher */
    /* Binding proof: */
    bool pubkey_claimed;      /* zcode:pubkey present and on-curve */
    char expected_owner[64];  /* P2PKH derived from the claimed key */
    bool bound;               /* owner_address == expected_owner */
};

/* Derive the P2PKH address of the active chain for a 33-byte compressed
 * secp256k1 pubkey. False when the key is not an on-curve compressed point
 * or no chain params are selected. */
bool zcode_pointer_expected_owner(const uint8_t pubkey[33], char *out,
                                  size_t out_cap);

/* Resolve one ZNAM name as a ZCODE pointer. Returns true and fills *out
 * whenever the name is REGISTERED (out->kind is ZCODE_POINTER_NONE when it
 * carries no zcode:kind record — an ordinary name); false when the name is
 * not registered. Chain params must be selected for the binding check. */
bool zcode_pointer_resolve(struct node_db *ndb, const char *name,
                           struct zcode_pointer *out);

/* Scan the registry for publisher-profile pointers claiming
 * publisher_hex: fills *out with the first BOUND one (preferring bound
 * over unbound) and returns the total number of claimant names (0 = no
 * profile points at this key). Bounded scan. */
size_t zcode_pointer_find_publisher_profiles(struct node_db *ndb,
                                             const char *publisher_hex,
                                             struct zcode_pointer *out);

#endif /* ZCL_SERVICES_ZCODE_POINTER_H */
