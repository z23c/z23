/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Principal: a multi-user-server identity. One row per public key that has
 * authenticated to this node. The address (base58check(hash160(pubkey))) is
 * the primary key; `role` is the single authorization input and
 * `granted_capabilities` is a DERIVED cache recomputed from `role` through the
 * authz policy table (models/authz_policy.h) in before_validate — a
 * caller can therefore NEVER persist a capability mask that exceeds its role.
 * App-layer overlay only: `sybil_proof_height` is bookkeeping and is never
 * consulted by consensus. */

#ifndef ZCL_DB_MODEL_PRINCIPAL_H
#define ZCL_DB_MODEL_PRINCIPAL_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

enum {
    PRINCIPAL_ADDRESS_MAX = 95,   /* transparent t-addr fits well under this */
    PRINCIPAL_PUBKEY_HEX_MAX = 130, /* 65-byte uncompressed pubkey = 130 hex */
    PRINCIPAL_ZNAM_MAX = 63,
    PRINCIPAL_ROLE_NAME_MAX = 15,
};

/* Key scheme of the principal's public key. */
enum principal_key_kind {
    PRINCIPAL_KEY_SECP256K1 = 0,   /* recoverable compact ECDSA */
    PRINCIPAL_KEY_ED25519 = 1,     /* client presents pubkey; verify-only */
};

/* Role — the ONLY authorization input. Ordered by privilege; the authz policy
 * table maps each to (capability mask, authority ceiling). Persisted as the
 * lowercase name (guest/member/operator/owner). */
enum principal_role {
    PRINCIPAL_ROLE_GUEST = 0,
    PRINCIPAL_ROLE_MEMBER = 1,
    PRINCIPAL_ROLE_OPERATOR = 2,
    PRINCIPAL_ROLE_OWNER = 3,
};

/* Account status. */
enum principal_status {
    PRINCIPAL_STATUS_ACTIVE = 0,
    PRINCIPAL_STATUS_SUSPENDED = 1,
};

struct db_principal {
    char address[PRINCIPAL_ADDRESS_MAX + 1];       /* PRIMARY KEY */
    char pubkey_hex[PRINCIPAL_PUBKEY_HEX_MAX + 1];
    enum principal_key_kind key_kind;
    char znam_name[PRINCIPAL_ZNAM_MAX + 1];        /* optional ("" = none) */
    enum principal_role role;
    uint64_t granted_capabilities;                 /* DERIVED cache */
    int64_t created_at;
    int64_t last_login;                            /* 0 = never */
    enum principal_status status;
    int64_t sybil_proof_height;                    /* bookkeeping; -1 = none */
};

/* Role <-> lowercase name. */
const char *principal_role_name(enum principal_role role);
bool principal_role_from_name(const char *name, enum principal_role *out);
const char *principal_status_name(enum principal_status status);
bool principal_status_from_name(const char *name, enum principal_status *out);

/* Lazily-initialized callback registry (before_validate recompute hook). */
struct ar_callbacks *db_principal_callbacks(void);

/* Populate errors with any validation failures. Returns true iff p is valid:
 * address present + within bounds + printable; pubkey_hex a valid hex string;
 * role/status/key_kind in range; and granted_capabilities EXACTLY equal to the
 * authz mask for `role` (the before_validate recompute guarantees this). */
bool db_principal_validate(const struct db_principal *p, struct ar_errors *errors);

/* Upsert p. before_validate recomputes granted_capabilities from role (so no
 * caller can persist an over-privileged mask), then validate + INSERT OR
 * REPLACE via the AR lifecycle. Returns false on bad args/veto/validation/DB. */
bool db_principal_save(struct node_db *ndb, const struct db_principal *p);

/* SELECT by primary-key address. Returns true and fills out on hit. */
bool db_principal_find(struct node_db *ndb, const char *address,
                       struct db_principal *out);

/* True iff a principal with this pubkey_hex exists. */
bool db_principal_exists_pubkey(struct node_db *ndb, const char *pubkey_hex);

/* Load up to max principals ordered by created_at ascending. Returns count. */
int db_principal_list(struct node_db *ndb, struct db_principal *out, size_t max);

/* Total principal count. */
int db_principal_count(struct node_db *ndb);

/* Bounded JSON dump for `dumpstate principals` (never leaks pubkey material
 * beyond the public address/role/status projection). */
struct json_value;
bool principal_dump_state_json(struct json_value *out, const char *key);

#endif
