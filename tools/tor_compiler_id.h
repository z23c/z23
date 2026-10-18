/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Compiler identity comparison for the Tor provenance manifest.
 *
 * Two compiler ids name the same compiler when their compiler binary hashes
 * ("sha256:<64 hex>") are equal. Ids without a hash (manifests recorded
 * before bytes-based identity) are equal when the version text after the
 * first word is equal and non-empty; the first word is the driver name
 * ("cc", "gcc") and varies with how the same binary was invoked. An id with
 * a hash never matches one without, and a malformed or empty id never
 * matches.
 */
#ifndef Z23_TOR_COMPILER_ID_H
#define Z23_TOR_COMPILER_ID_H

#include <stdbool.h>
#include <string.h>

#define TOR_CID_HASH_PREFIX "sha256:"
#define TOR_CID_HASH_HEX 64

/* True when id carries the hash prefix; *hash is the 64 hex digits that
 * follow it, or NULL when they are not exactly 64 lowercase hex digits
 * ending the token. */
static inline bool tor_cid_has_hash_prefix(const char *id, const char **hash)
{
    size_t plen = strlen(TOR_CID_HASH_PREFIX);
    *hash = NULL;
    if (strncmp(id, TOR_CID_HASH_PREFIX, plen) != 0)
        return false;
    const char *h = id + plen;
    size_t n = 0;
    while ((h[n] >= '0' && h[n] <= '9') || (h[n] >= 'a' && h[n] <= 'f'))
        n++;
    if (n == TOR_CID_HASH_HEX && (h[n] == '\0' || h[n] == ' '))
        *hash = h;
    return true;
}

/* The text after the first word and its following spaces. */
static inline const char *tor_cid_after_driver(const char *id)
{
    while (*id == ' ')
        id++;
    while (*id != '\0' && *id != ' ')
        id++;
    while (*id == ' ')
        id++;
    return id;
}

static inline bool tor_compiler_ids_match(const char *recorded,
                                          const char *actual)
{
    if (!recorded || !actual || recorded[0] == '\0' || actual[0] == '\0')
        return false;
    const char *rh, *ah;
    bool rp = tor_cid_has_hash_prefix(recorded, &rh);
    bool ap = tor_cid_has_hash_prefix(actual, &ah);
    if (rp || ap)
        return rp && ap && rh && ah &&
               memcmp(rh, ah, TOR_CID_HASH_HEX) == 0;
    const char *rr = tor_cid_after_driver(recorded);
    const char *ar = tor_cid_after_driver(actual);
    return rr[0] != '\0' && strcmp(rr, ar) == 0;
}

#endif
