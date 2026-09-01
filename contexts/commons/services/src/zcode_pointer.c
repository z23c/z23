/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zcode_pointer — implementation of the ZCODE ZNAM pointer layer declared
 * in services/zcode_pointer.h. Read-only over the canonical ZNAM model;
 * every write path stays where it already is (the on-chain fold and the
 * name RPCs). */

// one-result-type-ok:read-only-pointer-verdicts — every export here is a
// query whose false/0 IS the answer ("name not registered", "claimed key
// off-curve", "no claimant"), never a failure to propagate; the native
// handlers in tools/command/native_zcode_contributor_command.c name each
// rejection (UNKNOWN_NAME, POINTER_NOT_BOUND, ...) at the boundary.

#include "services/zcode_pointer.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "script/standard.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZP_LOG "zcode.pointer"

/* Registry scan bound for publisher-profile lookup (matches the package
 * store's tracked bound; a registry larger than this still resolves by
 * exact name, the profile scan is what is bounded). */
#define ZCODE_POINTER_SCAN_MAX 4096u

bool zcode_pointer_expected_owner(const uint8_t pubkey[33], char *out,
                                  size_t out_cap)
{
    if (!pubkey || !out)
        LOG_RETURN(false, ZP_LOG, "null expected_owner argument");
    const struct chain_params *params = chain_params_get();
    if (!params)
        LOG_RETURN(false, ZP_LOG, "no chain params selected");
    struct pubkey pk;
    pubkey_set(&pk, pubkey, 33);
    if (!pubkey_is_fully_valid(&pk))
        return false; /* raw-return-ok: off-curve claim = cannot derive, not an error */
    size_t pubkey_len = 0;
    size_t script_len = 0;
    const unsigned char *pubkey_prefix =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pubkey_len);
    const unsigned char *script_prefix =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &script_len);
    if (!pubkey_prefix || !script_prefix)
        LOG_RETURN(false, ZP_LOG, "chain base58 prefixes unavailable");
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    dest.id.key = pubkey_get_id(&pk);
    return encode_destination(&dest, pubkey_prefix, pubkey_len,
                              script_prefix, script_len, out, out_cap);
}

static bool zp_text(struct node_db *ndb, const char *name, const char *key,
                    char *out, size_t out_cap)
{
    if (out_cap == 0)
        return false;
    out[0] = '\0';
    return db_znam_text_get(ndb, name, key, out, out_cap) && out[0] != '\0';
}

/* Fill the record fields of *out from the name's ZNAM rows. */
static void zp_fill_records(struct node_db *ndb, struct zcode_pointer *out)
{
    zp_text(ndb, out->name, ZCODE_POINTER_KEY_PUBKEY, out->publisher_hex,
            sizeof(out->publisher_hex));
    zp_text(ndb, out->name, ZCODE_POINTER_KEY_DESCRIPTION, out->description,
            sizeof(out->description));
    zp_text(ndb, out->name, ZCODE_POINTER_KEY_ONION, out->onion,
            sizeof(out->onion));
    zp_text(ndb, out->name, ZCODE_POINTER_KEY_PROTOCOL, out->protocol,
            sizeof(out->protocol));
    zp_text(ndb, out->name, ZCODE_POINTER_KEY_DISPLAY, out->display,
            sizeof(out->display));
    zp_text(ndb, out->name, ZCODE_POINTER_KEY_PROFILE, out->profile_root_hex,
            sizeof(out->profile_root_hex));
    zp_text(ndb, out->name, ZCODE_POINTER_KEY_INDEX, out->index_root_hex,
            sizeof(out->index_root_hex));
    zp_text(ndb, out->name, ZCODE_POINTER_KEY_REWARD, out->reward_address,
            sizeof(out->reward_address));

    /* Binding proof: the claimed key must derive the owner address. */
    uint8_t pubkey[33];
    out->pubkey_claimed = zcl_hex_decode(out->publisher_hex, pubkey, 33);
    out->bound = false;
    out->expected_owner[0] = '\0';
    if (out->pubkey_claimed &&
        zcode_pointer_expected_owner(pubkey, out->expected_owner,
                                     sizeof(out->expected_owner))) {
        out->bound =
            strcmp(out->expected_owner, out->owner_address) == 0;
    } else {
        out->pubkey_claimed = false;
    }
}

bool zcode_pointer_resolve(struct node_db *ndb, const char *name,
                           struct zcode_pointer *out)
{
    if (!ndb || !name || !out)
        LOG_RETURN(false, ZP_LOG, "null resolve argument");
    memset(out, 0, sizeof(*out));
    struct znam_entry entry;
    if (!db_znam_find(ndb, name, &entry))
        return false; /* raw-return-ok: "name not registered" is the answer */
    snprintf(out->name, sizeof(out->name), "%s", entry.name);
    snprintf(out->owner_address, sizeof(out->owner_address), "%s",
             entry.owner_address);
    if (entry.target_type == ZNAM_TYPE_CONTENT) {
        uint8_t package_root[32];
        if (zcl_hex_decode(entry.target_value, package_root,
                           sizeof(package_root)))
            snprintf(out->package_root_hex, sizeof(out->package_root_hex),
                     "%.64s", entry.target_value);
    }

    char kind[ZNAM_TEXT_VAL_MAX + 1];
    if (!zp_text(ndb, name, ZCODE_POINTER_KEY_KIND, kind, sizeof(kind))) {
        out->kind = ZCODE_POINTER_NONE;
        return true;
    }
    if (strcmp(kind, ZCODE_POINTER_KIND_PACKAGE) == 0)
        out->kind = ZCODE_POINTER_PACKAGE;
    else if (strcmp(kind, ZCODE_POINTER_KIND_PUBLISHER) == 0)
        out->kind = ZCODE_POINTER_PUBLISHER;
    else
        out->kind = ZCODE_POINTER_NONE;
    zp_fill_records(ndb, out);
    return true;
}

size_t zcode_pointer_find_publisher_profiles(struct node_db *ndb,
                                             const char *publisher_hex,
                                             struct zcode_pointer *out)
{
    if (out)
        memset(out, 0, sizeof(*out));
    if (!ndb || !publisher_hex)
        return 0;
    struct znam_entry *names =
        zcl_malloc(sizeof(*names) * ZCODE_POINTER_SCAN_MAX,
                   "zcode_pointer_scan");
    if (!names) {
        LOG_ERROR(ZP_LOG, "scan alloc failed");
        return 0;
    }
    int n = db_znam_list(ndb, names, ZCODE_POINTER_SCAN_MAX);
    size_t claimants = 0;
    bool have_bound = false;
    for (int i = 0; i < n; i++) {
        char kind[ZNAM_TEXT_VAL_MAX + 1];
        if (!zp_text(ndb, names[i].name, ZCODE_POINTER_KEY_KIND, kind,
                     sizeof(kind)) ||
            strcmp(kind, ZCODE_POINTER_KIND_PUBLISHER) != 0)
            continue;
        char claimed[67];
        if (!zp_text(ndb, names[i].name, ZCODE_POINTER_KEY_PUBKEY, claimed,
                     sizeof(claimed)) ||
            strcmp(claimed, publisher_hex) != 0)
            continue;
        claimants++;
        if (!out || have_bound)
            continue;
        struct zcode_pointer candidate;
        if (!zcode_pointer_resolve(ndb, names[i].name, &candidate))
            continue;
        if (candidate.bound) {
            *out = candidate;
            have_bound = true;
        } else if (claimants == 1) {
            *out = candidate; /* first claimant, reported unbound */
        }
    }
    free(names);
    return claimants;
}
