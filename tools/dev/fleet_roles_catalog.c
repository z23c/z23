/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The closed role/grant vocabulary, pasted from its one declaration in
 * engine/composition/roles.def, and the fingerprint this whole feature
 * keys everything by. See tools/dev/fleet_roles.h for the contract.
 */

#include "fleet_roles.h"

#include "sha3/sha3.h"
#include "base/hex.h"

#include <string.h>

/* ── roles ───────────────────────────────────────────────────────────── */

struct role_row {
    uint8_t id;
    const char *name;
};

static const struct role_row k_roles[] = {
#define Z23_ROLE(role_, why_) { ZCL_ROLE_CAT2(ZCL_ROLE_, role_), #role_ },
#define ZCL_ROLE_CAT2(a_, b_) ZCL_ROLE_CAT(a_, b_)
#define ZCL_ROLE_CAT(a_, b_) a_##b_
#include "../../engine/composition/roles.def"
#undef Z23_ROLE
#undef ZCL_ROLE_CAT2
#undef ZCL_ROLE_CAT
};
#define K_ROLES_N (sizeof k_roles / sizeof k_roles[0])

const char *zcl_role_name(uint8_t role)
{
    if (role == ZCL_ROLE_OPERATOR)
        return "operator";
    for (size_t i = 0; i < K_ROLES_N; i++)
        if (k_roles[i].id == role)
            return k_roles[i].name;
    return NULL;
}

bool zcl_role_from_name(const char *name, uint8_t *role_out)
{
    if (!name || !role_out)
        return false;
    if (strcmp(name, "operator") == 0) {
        *role_out = ZCL_ROLE_OPERATOR;
        return true;
    }
    for (size_t i = 0; i < K_ROLES_N; i++) {
        if (strcmp(k_roles[i].name, name) == 0) {
            *role_out = k_roles[i].id;
            return true;
        }
    }
    return false;
}

size_t zcl_role_count(void)
{
    return K_ROLES_N;
}

const char *zcl_role_at(size_t index)
{
    return index < K_ROLES_N ? k_roles[index].name : NULL;
}

/* ── grants ──────────────────────────────────────────────────────────── */

struct grant_row {
    uint8_t role;
    const char *leaf_pattern;
    const char *kinds; /* comma-separated, or "*" */
};

static const struct grant_row k_grants[] = {
#define Z23_ROLE_GRANT(role_, leaf_pattern_, kinds_) \
    { ZCL_ROLE_CAT2(ZCL_ROLE_, role_), leaf_pattern_, kinds_ },
#define ZCL_ROLE_CAT2(a_, b_) ZCL_ROLE_CAT(a_, b_)
#define ZCL_ROLE_CAT(a_, b_) a_##b_
#include "../../engine/composition/roles.def"
#undef Z23_ROLE_GRANT
#undef ZCL_ROLE_CAT2
#undef ZCL_ROLE_CAT
};
#define K_GRANTS_N (sizeof k_grants / sizeof k_grants[0])

/* An exact match, or a "prefix*" pattern matching every leaf under that
 * prefix. No other wildcard shape exists, so there is nothing else to
 * parse: a pattern that is not exactly this shape cannot appear because
 * the .def rows above are the only source of one. */
static bool leaf_matches(const char *pattern, const char *leaf)
{
    size_t plen = strlen(pattern);
    if (plen > 0 && pattern[plen - 1] == '*')
        return strncmp(pattern, leaf, plen - 1) == 0;
    return strcmp(pattern, leaf) == 0;
}

/* "*" allows every kind; otherwise `kind` must appear as a whole
 * comma-separated token, never a substring match of a longer name. */
static bool kind_matches(const char *kinds, const char *kind)
{
    if (!kind || strcmp(kinds, "*") == 0)
        return true;
    size_t klen = strlen(kind);
    const char *p = kinds;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t seg_len = comma ? (size_t)(comma - p) : strlen(p);
        if (seg_len == klen && strncmp(p, kind, klen) == 0)
            return true;
        p += seg_len;
        if (*p == ',')
            p++;
    }
    return false;
}

bool zcl_role_leaf_allowed(uint8_t role, const char *leaf, const char *kind)
{
    if (!leaf || role == ZCL_ROLE_OPERATOR)
        return false;
    for (size_t i = 0; i < K_GRANTS_N; i++) {
        if (k_grants[i].role != role)
            continue;
        if (leaf_matches(k_grants[i].leaf_pattern, leaf) &&
            kind_matches(k_grants[i].kinds, kind))
            return true;
    }
    return false;
}

/* ── fingerprint ─────────────────────────────────────────────────────── */

#define ZCL_ROLE_FP_DOMAIN "zcl.fleet_role_fingerprint.v1"

void zcl_role_fingerprint(const uint8_t pubkey[32],
                          uint8_t out[ZCL_ROLE_FP_BYTES])
{
    struct sha3_256_ctx ctx;
    sha3_256_init(&ctx);
    sha3_256_write(&ctx, (const unsigned char *)ZCL_ROLE_FP_DOMAIN,
                   sizeof(ZCL_ROLE_FP_DOMAIN));
    sha3_256_write(&ctx, pubkey, 32);
    sha3_256_finalize(&ctx, out);
}

void zcl_role_fingerprint_short(const uint8_t fp[ZCL_ROLE_FP_BYTES],
                                char out[9])
{
    char hex[65];
    zcl_hex_encode(fp, ZCL_ROLE_FP_BYTES, hex);
    memcpy(out, hex, 8);
    out[8] = '\0';
}
