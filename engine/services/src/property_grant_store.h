/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * PRIVATE to property_grant_service.c + property_grant_commit.c. The two files
 * are one service split only to stay under the per-file line ceiling; they
 * share ONE lock and ONE set of bounded arrays, and no other translation unit
 * may include this header (the public contract is
 * services/property_grant_service.h).
 *
 * Locking: `lock` guards every array and the key material. Helpers declared
 * here that say "lock held" must be called with it held; the public entry
 * points in the two .c files are the only places it is taken or released. */

#ifndef ZCL_SERVICES_PROPERTY_GRANT_STORE_H
#define ZCL_SERVICES_PROPERTY_GRANT_STORE_H

#include "services/property_grant_service.h"

#include "crypto/ed25519.h"

#include <pthread.h>

struct property_grant_store {
    pthread_mutex_t lock;
    struct property_grant_env env;

    /* STORE-WIDE AUTHORITY GENERATION. Bumped under `lock` by every mutation
     * of the store: mint, delegate, revoke, a commit's budget/rate debit, and
     * reset. A per-grant revocation generation says "this grant changed"; this
     * says "SOMETHING an authority decision could depend on changed", which is
     * the only counter a reader can use to prove the state it decided over did
     * not move underneath it. Never decremented, never reset except by
     * property_grant_service_reset (which bumps it rather than zeroing it, so
     * a reader across a reset also sees a move). */
    uint64_t authority_generation;

    struct metaverse_grant grants[PROPERTY_GRANT_MAX_GRANTS];
    bool grant_used[PROPERTY_GRANT_MAX_GRANTS];

    struct property_grant_plan plans[PROPERTY_GRANT_MAX_PLANS];
    bool plan_used[PROPERTY_GRANT_MAX_PLANS];

    /* Append-only within a process: receipts are never moved or removed, so a
     * receipt's index is stable and the per-grant chain order is insertion
     * order. Only property_grant_service_reset() clears it. */
    struct metaverse_receipt receipts[PROPERTY_GRANT_MAX_RECEIPTS];
    size_t receipt_count;

    uint8_t sk[32];
    uint8_t pk[32];
    bool key_set;

#ifdef ZCL_TESTING
    /* TEST-ONLY. Armed by property_grant_service_test_set_seal_hook() and
     * called by COMMIT at the one instant between the grant record's effect and
     * the sealed receipt — the window in which the store has moved and no
     * evidence exists yet. Compiled out entirely outside a ZCL_TESTING build so
     * the shipped money path carries no hook. */
    property_grant_test_seal_hook_fn seal_hook;
    void *seal_hook_ctx;
#endif
};

extern struct property_grant_store g_pg_store;

/* Resolve the current time and height through the configured provider. Safe
 * with or without the lock held (it only reads two immutable-after-configure
 * function pointers). */
void pg_now(int64_t *now_unix, int64_t *height);

/* Lock held. NULL when absent. */
struct metaverse_grant *pg_find_grant(const char *grant_id);
struct property_grant_plan *pg_find_plan_locked(const char *plan_id);

/* Lock held. Fills `out` root-first from g->lineage. Returns false when ANY
 * ancestor is missing — callers must map that to ANCESTOR_REVOKED, never to
 * "nothing to check". */
bool pg_collect_ancestors(const struct metaverse_grant *g,
                          const struct metaverse_grant **out,
                          size_t *out_count);

/* Lock held. Establishes the receipt signing keypair if none exists yet.
 * Returns false (logged) only on a CSPRNG failure. */
bool pg_ensure_key(void);

/* Lock held. Record that the store changed. Call it on the LAST statement of
 * every successful mutation, so a reader that sees an unchanged generation
 * really did observe an unchanged store. */
void pg_bump_authority(void);

#endif /* ZCL_SERVICES_PROPERTY_GRANT_STORE_H */
