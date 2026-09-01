/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Auth challenge: a single-use login nonce. The login service issues one row
 * (random nonce bound to an address with an expiry) and later consumes it. The
 * consume is an ATOMIC compare-and-consume — one UPDATE that transitions
 * consumed 0->1 only when the nonce matches, the address matches, it is
 * unexpired, and it was not already consumed — so a replayed verify can never
 * succeed twice even under concurrency. */

#ifndef ZCL_DB_MODEL_AUTH_CHALLENGE_H
#define ZCL_DB_MODEL_AUTH_CHALLENGE_H

#include "models/database.h"
#include "models/activerecord.h"
#include <stdbool.h>
#include <stdint.h>

enum {
    AUTH_CHALLENGE_NONCE_HEX_MAX = 64,   /* 32 random bytes = 64 hex */
    AUTH_CHALLENGE_ADDRESS_MAX = 95,
};

struct db_auth_challenge {
    char nonce_hex[AUTH_CHALLENGE_NONCE_HEX_MAX + 1];  /* PRIMARY KEY */
    char address[AUTH_CHALLENGE_ADDRESS_MAX + 1];
    int64_t issued_at;
    int64_t expires_at;
    bool consumed;
};

struct ar_callbacks *db_auth_challenge_callbacks(void);

bool db_auth_challenge_validate(const struct db_auth_challenge *c,
                                struct ar_errors *errors);

/* Insert a freshly issued (unconsumed) challenge. AR lifecycle. */
bool db_auth_challenge_save(struct node_db *ndb,
                            const struct db_auth_challenge *c);

/* SELECT by primary-key nonce_hex. Returns true and fills out on hit. Used by
 * verify to recover the issued_at/expires_at needed to rebuild the canonical
 * signed message. Reading is safe; single-use is still enforced by consume. */
bool db_auth_challenge_find(struct node_db *ndb, const char *nonce_hex,
                            struct db_auth_challenge *out);

/* Atomic compare-and-consume: transition consumed 0->1 for the row whose
 * nonce_hex AND address match, that is not yet consumed, and whose expiry is
 * strictly after `now`. Returns true iff EXACTLY one row transitioned (i.e.
 * the challenge was valid, unexpired, unconsumed, and bound to this address).
 * A second call for the same nonce returns false. */
bool db_auth_challenge_consume(struct node_db *ndb, const char *nonce_hex,
                               const char *address, int64_t now);

/* Best-effort reap of expired/consumed rows older than `cutoff` issued_at.
 * Housekeeping only; never affects correctness. Returns rows removed (>=0). */
int db_auth_challenge_reap(struct node_db *ndb, int64_t cutoff);

/* Count of currently-unconsumed challenge rows (for dumpstate). */
int db_auth_challenge_pending_count(struct node_db *ndb);

struct json_value;
bool auth_challenge_dump_state_json(struct json_value *out, const char *key);

#endif
