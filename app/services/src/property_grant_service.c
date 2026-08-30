/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Property grant service — the store, the environment seams, grant lifecycle
 * (mint / delegate / revoke / list), and PLAN. COMMIT, the receipt chain, and
 * chain verification live in property_grant_commit.c over the private store
 * API in property_grant_store.h; the two files share one lock and one set of
 * bounded arrays, and nothing outside them touches the arrays.
 *
 * The decision rules are all in lib/metaverse and are pure. Everything in this
 * file is store, clock, and refusal plumbing. See the public header for why
 * COMMIT re-checks rather than trusting its plan. */

// one-result-type-ok:grant-decision — this service has no bool/errno failure
// surface to converge: every fallible entry point already returns
// `enum property_grant_reason`, a closed taxonomy where the refusal IS the
// answer (GRANT_REVOKED, BUDGET_EXCEEDED, STALE_REVISION, …) and the tokens are
// contract asserted by test_metaverse_grant. Wrapping that in struct zcl_result
// would put the reason in a free-text string and lose the exhaustive
// verdict→reason map. The four remaining bool exports are not that surface:
// set_signing_seed / signer_pubkey are key-material predicates, and
// pg_collect_ancestors / pg_ensure_key are private store helpers shared with
// property_grant_commit.c through property_grant_store.h.

#include "services/property_grant_service.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "crypto/random_secret.h"
#include "platform/clock.h"
#include "property_grant_store.h"

#include <stdio.h>
#include <string.h>

#define PG_LOG "metaverse.grant_service"

/* ── The store ──────────────────────────────────────────────────────────── */

struct property_grant_store g_pg_store = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static const char *const k_reason_tokens[PROPERTY_GRANT_REASON_COUNT] = {
    "OK",
    "BAD_ARGS",
    "STORE_FULL",
    "GRANT_UNKNOWN",
    "GRANT_EXISTS",
    "GRANT_MALFORMED",
    "GRANT_REVOKED",
    "ANCESTOR_REVOKED",
    "GRANT_EXPIRED_HEIGHT",
    "GRANT_EXPIRED_TIME",
    "WRONG_HOLDER",
    "ACTION_NOT_GRANTED",
    "PROPERTY_OUT_OF_SCOPE",
    "KIND_OUT_OF_SCOPE",
    "COUNTERPARTY_NOT_ALLOWED",
    "VALUE_NEGATIVE",
    "VALUE_ON_FREE_ACTION",
    "BUDGET_EXCEEDED",
    "RATE_LIMITED",
    "DELEGATION_NOT_PERMITTED",
    "DELEGATION_DEPTH_EXCEEDED",
    "PLAN_UNKNOWN",
    "PLAN_EXPIRED",
    "PLAN_ALREADY_COMMITTED",
    "CATALOG_UNAVAILABLE",
    "PROPERTY_UNKNOWN",
    "OWNER_MISMATCH",
    "STALE_REVISION",
    "RECEIPT_SEAL_FAILED",
    "SIGNING_KEY_UNAVAILABLE",
    "IDEMPOTENCY_KEY_REUSED",
    "AUTHORITY_CHANGED",
};

const char *property_grant_reason_token(enum property_grant_reason r)
{
    if (r < 0 || r >= PROPERTY_GRANT_REASON_COUNT) return "UNKNOWN_REASON";
    return k_reason_tokens[r];
}

/* The static-scope block of the taxonomy is laid out to mirror
 * enum metaverse_grant_verdict one-for-one, and this table is the proof: a
 * verdict added to the rules without a matching reason here becomes a compile
 * error, not a silent "UNKNOWN_REASON" in an operator's error body. */
static const enum property_grant_reason
    k_verdict_map[METAVERSE_GRANT_VERDICT_COUNT] = {
    [METAVERSE_GRANT_OK] = PROPERTY_GRANT_OK,
    [METAVERSE_GRANT_BAD_ARGS] = PROPERTY_GRANT_BAD_ARGS,
    [METAVERSE_GRANT_MALFORMED] = PROPERTY_GRANT_GRANT_MALFORMED,
    [METAVERSE_GRANT_REVOKED] = PROPERTY_GRANT_GRANT_REVOKED,
    [METAVERSE_GRANT_ANCESTOR_REVOKED] = PROPERTY_GRANT_ANCESTOR_REVOKED,
    [METAVERSE_GRANT_EXPIRED_HEIGHT] = PROPERTY_GRANT_GRANT_EXPIRED_HEIGHT,
    [METAVERSE_GRANT_EXPIRED_TIME] = PROPERTY_GRANT_GRANT_EXPIRED_TIME,
    [METAVERSE_GRANT_WRONG_HOLDER] = PROPERTY_GRANT_WRONG_HOLDER,
    [METAVERSE_GRANT_ACTION_NOT_GRANTED] = PROPERTY_GRANT_ACTION_NOT_GRANTED,
    [METAVERSE_GRANT_PROPERTY_OUT_OF_SCOPE] =
        PROPERTY_GRANT_PROPERTY_OUT_OF_SCOPE,
    [METAVERSE_GRANT_KIND_OUT_OF_SCOPE] = PROPERTY_GRANT_KIND_OUT_OF_SCOPE,
    [METAVERSE_GRANT_COUNTERPARTY_NOT_ALLOWED] =
        PROPERTY_GRANT_COUNTERPARTY_NOT_ALLOWED,
    [METAVERSE_GRANT_VALUE_NEGATIVE] = PROPERTY_GRANT_VALUE_NEGATIVE,
    [METAVERSE_GRANT_VALUE_ON_FREE_ACTION] =
        PROPERTY_GRANT_VALUE_ON_FREE_ACTION,
    [METAVERSE_GRANT_BUDGET_EXCEEDED] = PROPERTY_GRANT_BUDGET_EXCEEDED,
    [METAVERSE_GRANT_RATE_LIMITED] = PROPERTY_GRANT_RATE_LIMITED,
    [METAVERSE_GRANT_DELEGATION_NOT_PERMITTED] =
        PROPERTY_GRANT_DELEGATION_NOT_PERMITTED,
    [METAVERSE_GRANT_DELEGATION_DEPTH_EXCEEDED] =
        PROPERTY_GRANT_DELEGATION_DEPTH_EXCEEDED,
};

enum property_grant_reason property_grant_reason_from_verdict(
    enum metaverse_grant_verdict v)
{
    if (v < 0 || v >= METAVERSE_GRANT_VERDICT_COUNT)
        return PROPERTY_GRANT_BAD_ARGS;
    return k_verdict_map[v];
}

/* ── Environment ────────────────────────────────────────────────────────── */

/* Wall clock in seconds; height 0 means "unknown", which cannot prove expiry.
 * clock_now_wall_ms is the platform boundary, so this file has no raw clock. */
static void default_clock(int64_t *now_unix, int64_t *height, void *ctx)
{
    (void)ctx;
    if (now_unix) *now_unix = clock_now_wall_ms() / 1000;
    if (height) *height = 0;
}

void property_grant_service_configure(const struct property_grant_env *env)
{
    pthread_mutex_lock(&g_pg_store.lock);
    if (env) {
        g_pg_store.env = *env;
    } else {
        memset(&g_pg_store.env, 0, sizeof(g_pg_store.env));
    }
    if (!g_pg_store.env.clock) g_pg_store.env.clock = default_clock;
    /* THE ENVIRONMENT IS A DECISION INPUT, so replacing it moves the store-wide
     * generation like any other mutation. A snapshot carries the instant it was
     * taken against (snap.now_unix/height) and the pure rules measure expiry
     * against that instant, so a decision already computed is not retroactively
     * changed by a clock swap — but a decision still IN FLIGHT would otherwise
     * be revalidated as coherent across a change of which clock, and which
     * catalog, is authoritative. This is documented as a boot-time seam ("call
     * before any plan/commit") and no production path calls it at all, so the
     * bump costs one increment and buys an unconditional guarantee instead of
     * one that holds only while nobody reconfigures a running node. */
    pg_bump_authority();
    pthread_mutex_unlock(&g_pg_store.lock);
}

void pg_now(int64_t *now_unix, int64_t *height)
{
    metaverse_clock_fn fn = g_pg_store.env.clock;
    if (!fn) fn = default_clock;
    int64_t t = 0, h = 0;
    fn(&t, &h, g_pg_store.env.clock_ctx);
    if (now_unix) *now_unix = t;
    if (height) *height = h;
}

void pg_bump_authority(void)
{
    g_pg_store.authority_generation++;
}

uint64_t property_grant_service_authority_generation(void)
{
    pthread_mutex_lock(&g_pg_store.lock);
    uint64_t g = g_pg_store.authority_generation;
    pthread_mutex_unlock(&g_pg_store.lock);
    return g;
}

bool property_grant_service_test_store_lock_busy(void)
{
#ifndef ZCL_TESTING
    return false;
#else
    /* trylock, never lock: called from a catalog callback that may be running
     * on the very thread that would hold it, where a blocking acquire would
     * deadlock instead of reporting. EBUSY from the owning thread is exactly
     * the answer the test is asking for. */
    if (pthread_mutex_trylock(&g_pg_store.lock) != 0)
        return true;
    pthread_mutex_unlock(&g_pg_store.lock);
    return false;
#endif
}

void property_grant_service_reset(void)
{
    pthread_mutex_lock(&g_pg_store.lock);
    memset(g_pg_store.grants, 0, sizeof(g_pg_store.grants));
    memset(g_pg_store.grant_used, 0, sizeof(g_pg_store.grant_used));
    memset(g_pg_store.plans, 0, sizeof(g_pg_store.plans));
    memset(g_pg_store.plan_used, 0, sizeof(g_pg_store.plan_used));
    memset(g_pg_store.receipts, 0, sizeof(g_pg_store.receipts));
    g_pg_store.receipt_count = 0;
    memset(g_pg_store.sk, 0, sizeof(g_pg_store.sk));
    memset(g_pg_store.pk, 0, sizeof(g_pg_store.pk));
    g_pg_store.key_set = false;
#ifdef ZCL_TESTING
    /* A hook left armed by one test would fire in the next one, which is the
     * shape of a test that passes for the wrong reason. Reset disarms it. */
    g_pg_store.seal_hook = NULL;
    g_pg_store.seal_hook_ctx = NULL;
#endif
    /* Bumped, never zeroed: a reader holding a snapshot from before the reset
     * must see the state move, and zeroing could hand it back its own value. */
    pg_bump_authority();
    pthread_mutex_unlock(&g_pg_store.lock);
}

/* ── Ids ────────────────────────────────────────────────────────────────── */

/* 128 bits rendered as 32 lowercase hex chars — the same shape and hygiene as
 * an agent session id. Fails closed if the CSPRNG fails: a predictable grant id
 * is a guessable handle onto someone else's authority. */
static bool draw_id(char *out, size_t out_cap)
{
    if (!out || out_cap < 33)
        LOG_FAIL(PG_LOG, "draw id: buffer %zu < 33", out_cap);
    uint8_t raw[16];
    if (!zcl_random_secret_bytes(raw, sizeof(raw), "metaverse_grant_id"))
        LOG_FAIL(PG_LOG, "draw id: CSPRNG failed");
    zcl_hex_encode(raw, sizeof(raw), out);  /* base/hex.h: the one hex codec */
    return true;
}

/* ── Store lookups (lock held by caller) ────────────────────────────────── */

struct metaverse_grant *pg_find_grant(const char *grant_id)
{
    if (!grant_id || grant_id[0] == '\0') return NULL;
    for (size_t i = 0; i < PROPERTY_GRANT_MAX_GRANTS; i++) {
        if (!g_pg_store.grant_used[i]) continue;
        if (strcmp(g_pg_store.grants[i].grant_id, grant_id) == 0)
            return &g_pg_store.grants[i];
    }
    return NULL;
}

/* Collect a grant's ancestors, root-first, from its recorded lineage. Returns
 * false when ANY ancestor is missing from the store — the caller must treat
 * that as ANCESTOR_REVOKED, never as "no ancestors to check". */
bool pg_collect_ancestors(const struct metaverse_grant *g,
                          const struct metaverse_grant **out, size_t *out_count)
{
    *out_count = 0;
    for (size_t i = 0; i < g->lineage_count; i++) {
        struct metaverse_grant *a = pg_find_grant(g->lineage[i].grant_id);
        if (!a) return false;
        out[i] = a;
    }
    *out_count = g->lineage_count;
    return true;
}

/* NO AUTHORITY BUMP, here or in set_signing_seed. The signing key is not a
 * decision input: no verdict in metaverse_grant_check, and nothing an authority
 * snapshot copies, depends on it. It decides whether a receipt VERIFIES, which
 * is evidence rather than permission, and bumping on it would make the first
 * commit after a restart invalidate every concurrent decision for no reason. */
bool pg_ensure_key(void)
{
    if (g_pg_store.key_set) return true;
    uint8_t seed[32];
    if (!zcl_random_secret_bytes(seed, sizeof(seed), "metaverse_receipt_key"))
        LOG_FAIL(PG_LOG, "receipt signing key: CSPRNG failed");
    uint8_t sk[32], pk[32];
    ed25519_keypair(pk, sk, seed);
    memcpy(g_pg_store.sk, sk, sizeof(sk));
    memcpy(g_pg_store.pk, pk, sizeof(pk));
    g_pg_store.key_set = true;
    memset(seed, 0, sizeof(seed));
    return true;
}

bool property_grant_service_set_signing_seed(const uint8_t seed[32])
{
    if (!seed)
        LOG_FAIL(PG_LOG, "set signing seed: NULL seed");
    pthread_mutex_lock(&g_pg_store.lock);
    uint8_t sk[32], pk[32];
    ed25519_keypair(pk, sk, seed);
    memcpy(g_pg_store.sk, sk, sizeof(sk));
    memcpy(g_pg_store.pk, pk, sizeof(pk));
    g_pg_store.key_set = true;
    pthread_mutex_unlock(&g_pg_store.lock);
    return true;
}

bool property_grant_service_signer_pubkey(uint8_t out[METAVERSE_PUBKEY_LEN])
{
    if (!out)
        LOG_FAIL(PG_LOG, "signer pubkey: NULL output");
    pthread_mutex_lock(&g_pg_store.lock);
    bool have = g_pg_store.key_set;
    if (have) memcpy(out, g_pg_store.pk, METAVERSE_PUBKEY_LEN);
    pthread_mutex_unlock(&g_pg_store.lock);
    if (!have)
        LOG_FAIL(PG_LOG, "signer pubkey: no receipt signing key established");
    return true;
}

/* ── Grant lifecycle ────────────────────────────────────────────────────── */

/* Insert a copy of `g`; caller holds the lock and has already validated. */
static enum property_grant_reason store_grant(const struct metaverse_grant *g)
{
    if (pg_find_grant(g->grant_id)) return PROPERTY_GRANT_GRANT_EXISTS;
    for (size_t i = 0; i < PROPERTY_GRANT_MAX_GRANTS; i++) {
        if (g_pg_store.grant_used[i]) continue;
        g_pg_store.grants[i] = *g;
        g_pg_store.grant_used[i] = true;
        pg_bump_authority();
        return PROPERTY_GRANT_OK;
    }
    return PROPERTY_GRANT_STORE_FULL;
}

enum property_grant_reason property_grant_service_mint(struct metaverse_grant *g)
{
    if (!g) {
        LOG_ERROR(PG_LOG, "mint: NULL grant");
        return PROPERTY_GRANT_BAD_ARGS;
    }
    if (g->depth != 0 || g->lineage_count != 0) {
        LOG_ERROR(PG_LOG, "mint: depth %u is not a root grant — use delegate",
                     g->depth);
        return PROPERTY_GRANT_BAD_ARGS;
    }

    if (g->grant_id[0] == '\0' && !draw_id(g->grant_id, sizeof(g->grant_id))) {
        LOG_ERROR(PG_LOG, "mint: could not draw a grant id");
        return PROPERTY_GRANT_BAD_ARGS;
    }

    int64_t now = 0, height = 0;
    pg_now(&now, &height);
    if (g->created_unix == 0) g->created_unix = now;
    if (g->created_height == 0) g->created_height = height;
    if (g->rate_limit > 0 && g->window_start_unix == 0)
        g->window_start_unix = now;

    if (!metaverse_grant_well_formed(g)) {
        LOG_WARN(PG_LOG, "mint: grant %s is malformed", g->grant_id);
        return PROPERTY_GRANT_GRANT_MALFORMED;
    }

    pthread_mutex_lock(&g_pg_store.lock);
    enum property_grant_reason r = store_grant(g);
    pthread_mutex_unlock(&g_pg_store.lock);
    if (r != PROPERTY_GRANT_OK)
        LOG_WARN(PG_LOG, "mint: grant %s refused (%s)", g->grant_id,
                     property_grant_reason_token(r));
    return r;
}

enum property_grant_reason property_grant_service_delegate(
    const char *parent_grant_id, struct metaverse_grant *child)
{
    if (!parent_grant_id || !child) {
        LOG_ERROR(PG_LOG, "delegate: NULL parent id or child");
        return PROPERTY_GRANT_BAD_ARGS;
    }

    int64_t now = 0, height = 0;
    pg_now(&now, &height);

    pthread_mutex_lock(&g_pg_store.lock);
    struct metaverse_grant *parent = pg_find_grant(parent_grant_id);
    if (!parent) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PG_LOG, "delegate: no grant %s", parent_grant_id);
        return PROPERTY_GRANT_GRANT_UNKNOWN;
    }

    /* Stamp lineage from the LIVE store: the parent chain plus the parent's
     * current generation. This capture is what makes a later revoke anywhere up
     * the chain invalidate this child without touching it. */
    child->depth = parent->depth + 1u;
    if (child->depth > METAVERSE_GRANT_MAX_DEPTH) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PG_LOG, "delegate: child depth %u over ceiling %d",
                     child->depth, METAVERSE_GRANT_MAX_DEPTH);
        return PROPERTY_GRANT_DELEGATION_DEPTH_EXCEEDED;
    }
    memset(child->lineage, 0, sizeof(child->lineage));
    for (size_t i = 0; i < parent->lineage_count; i++)
        child->lineage[i] = parent->lineage[i];
    snprintf(child->lineage[parent->lineage_count].grant_id,
             sizeof(child->lineage[0].grant_id), "%s", parent->grant_id);
    child->lineage[parent->lineage_count].revocation_generation =
        parent->revocation_generation;
    child->lineage_count = parent->lineage_count + 1u;
    child->revoked = false;
    child->revocation_generation = 0;
    if (child->created_unix == 0) child->created_unix = now;
    if (child->created_height == 0) child->created_height = height;
    if (child->rate_limit > 0 && child->window_start_unix == 0)
        child->window_start_unix = now;
    if (child->grant_id[0] == '\0' &&
        !draw_id(child->grant_id, sizeof(child->grant_id))) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_ERROR(PG_LOG, "delegate: could not draw a grant id");
        return PROPERTY_GRANT_BAD_ARGS;
    }

    const struct metaverse_grant *anc[METAVERSE_GRANT_MAX_DEPTH];
    size_t anc_count = 0;
    if (!pg_collect_ancestors(parent, anc, &anc_count)) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PG_LOG, "delegate: parent %s has a missing ancestor",
                     parent_grant_id);
        return PROPERTY_GRANT_ANCESTOR_REVOKED;
    }

    enum metaverse_grant_verdict v = metaverse_grant_check_delegation(
        parent, anc, anc_count, child, now, height);
    if (v != METAVERSE_GRANT_OK) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PG_LOG, "delegate: parent %s refused child (%s)",
                     parent_grant_id, metaverse_grant_verdict_token(v));
        return property_grant_reason_from_verdict(v);
    }

    enum property_grant_reason r = store_grant(child);
    pthread_mutex_unlock(&g_pg_store.lock);
    if (r != PROPERTY_GRANT_OK)
        LOG_ERROR(PG_LOG, "delegate: store refused child %s (%s)",
                     child->grant_id, property_grant_reason_token(r));
    return r;
}

enum property_grant_reason property_grant_service_get(
    const char *grant_id, struct metaverse_grant *out)
{
    if (!grant_id || !out) return PROPERTY_GRANT_BAD_ARGS;
    pthread_mutex_lock(&g_pg_store.lock);
    const struct metaverse_grant *g = pg_find_grant(grant_id);
    if (g) *out = *g;
    pthread_mutex_unlock(&g_pg_store.lock);
    return g ? PROPERTY_GRANT_OK : PROPERTY_GRANT_GRANT_UNKNOWN;
}

enum property_grant_reason property_grant_service_revoke(const char *grant_id)
{
    if (!grant_id) {
        LOG_ERROR(PG_LOG, "revoke: NULL grant id");
        return PROPERTY_GRANT_BAD_ARGS;
    }
    pthread_mutex_lock(&g_pg_store.lock);
    struct metaverse_grant *g = pg_find_grant(grant_id);
    if (g) {
        g->revocation_generation++;
        g->revoked = true;
        pg_bump_authority();
    }
    pthread_mutex_unlock(&g_pg_store.lock);
    if (!g) {
        LOG_WARN(PG_LOG, "revoke: no grant %s", grant_id);
        return PROPERTY_GRANT_GRANT_UNKNOWN;
    }
    return PROPERTY_GRANT_OK;
}

size_t property_grant_service_list(const char *holder,
                                   struct metaverse_grant *out, size_t max)
{
    if (!out || max == 0) return 0;
    bool all = (!holder || holder[0] == '\0');
    size_t n = 0;
    pthread_mutex_lock(&g_pg_store.lock);
    for (size_t i = 0; i < PROPERTY_GRANT_MAX_GRANTS && n < max; i++) {
        if (!g_pg_store.grant_used[i]) continue;
        if (!all && strcmp(g_pg_store.grants[i].holder, holder) != 0) continue;
        out[n++] = g_pg_store.grants[i];
    }
    pthread_mutex_unlock(&g_pg_store.lock);
    return n;
}

/* ── LIVE AUTHORITY: snapshot → (no lock) decide → recheck ──────────────────
 *
 * The lock discipline here is the whole point of the pair, so it is spelled
 * out rather than left to be inferred:
 *
 *   snapshot()  LOCK … copy … UNLOCK. Between those two statements there is
 *               no allocation, no I/O, no callback into app code and no call
 *               that could take a second lock. It is a bounded memcpy of at
 *               most 1 + METAVERSE_GRANT_MAX_DEPTH fixed-size records.
 *   recheck()   LOCK … compare three integers … UNLOCK. Same discipline.
 *
 * Everything expensive — the property catalog projection, which walks the
 * datadir — happens BETWEEN them, with nothing held. */

enum property_grant_reason property_grant_service_snapshot(
    const char *grant_id, struct property_grant_authority_snapshot *out)
{
    if (!grant_id || !out) {
        LOG_ERROR(PG_LOG, "snapshot: NULL grant id or output");
        return PROPERTY_GRANT_BAD_ARGS;
    }
    memset(out, 0, sizeof(*out));

    /* The clock provider is app-installed, so it is resolved BEFORE the lock,
     * never under it. */
    pg_now(&out->now_unix, &out->height);

    pthread_mutex_lock(&g_pg_store.lock);
    const struct metaverse_grant *g = pg_find_grant(grant_id);
    if (!g) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PG_LOG, "snapshot: no grant %s", grant_id);
        return PROPERTY_GRANT_GRANT_UNKNOWN;
    }
    out->grant = *g;
    out->grant_generation = g->revocation_generation;

    const struct metaverse_grant *anc[METAVERSE_GRANT_MAX_DEPTH];
    size_t anc_count = 0;
    if (g->lineage_count > 0 && !pg_collect_ancestors(g, anc, &anc_count)) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PG_LOG, "snapshot: grant %s has a missing ancestor", grant_id);
        return PROPERTY_GRANT_ANCESTOR_REVOKED;
    }
    for (size_t i = 0; i < anc_count; i++) {
        out->ancestors[i] = *anc[i];
        out->ancestor_generations[i] = anc[i]->revocation_generation;
    }
    out->ancestor_count = anc_count;
    out->authority_generation = g_pg_store.authority_generation;
    out->valid = true;
    pthread_mutex_unlock(&g_pg_store.lock);
    return PROPERTY_GRANT_OK;
}

enum property_grant_reason property_grant_service_recheck(
    const struct property_grant_authority_snapshot *snap)
{
    if (!snap || !snap->valid) {
        LOG_ERROR(PG_LOG, "recheck: NULL or unpopulated snapshot");
        return PROPERTY_GRANT_BAD_ARGS;
    }

    pthread_mutex_lock(&g_pg_store.lock);
    enum property_grant_reason r = PROPERTY_GRANT_OK;
    if (g_pg_store.authority_generation != snap->authority_generation) {
        r = PROPERTY_GRANT_AUTHORITY_CHANGED;
    } else {
        const struct metaverse_grant *g = pg_find_grant(snap->grant.grant_id);
        if (!g) {
            r = PROPERTY_GRANT_GRANT_UNKNOWN;
        } else if (g->revocation_generation != snap->grant_generation) {
            r = PROPERTY_GRANT_AUTHORITY_CHANGED;
        } else {
            /* The store-wide counter already covers this, but an ancestor
             * revoked through a path that forgot to bump it would still be
             * caught here: the child's own generation does not move when its
             * parent is revoked, so this is the check that makes lineage
             * revocation part of the coherence guarantee rather than a
             * separate hope. */
            for (size_t i = 0; i < snap->ancestor_count; i++) {
                const struct metaverse_grant *a =
                    pg_find_grant(snap->ancestors[i].grant_id);
                if (!a || a->revocation_generation !=
                              snap->ancestor_generations[i]) {
                    r = PROPERTY_GRANT_AUTHORITY_CHANGED;
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_pg_store.lock);
    if (r == PROPERTY_GRANT_AUTHORITY_CHANGED)
        LOG_WARN(PG_LOG,
                 "recheck: the store moved under a decision about grant %s "
                 "(authority generation %llu -> now different)",
                 snap->grant.grant_id,
                 (unsigned long long)snap->authority_generation);
    return r;
}

size_t property_grant_snapshot_ancestors(
    const struct property_grant_authority_snapshot *snap,
    const struct metaverse_grant **out)
{
    if (!snap || !out) return 0;
    for (size_t i = 0; i < snap->ancestor_count; i++)
        out[i] = &snap->ancestors[i];
    return snap->ancestor_count;
}

/* ── PLAN ───────────────────────────────────────────────────────────────── */

static struct property_grant_plan *find_plan(const char *plan_id)
{
    if (!plan_id || plan_id[0] == '\0') return NULL;
    for (size_t i = 0; i < PROPERTY_GRANT_MAX_PLANS; i++) {
        if (!g_pg_store.plan_used[i]) continue;
        if (strcmp(g_pg_store.plans[i].plan_id, plan_id) == 0)
            return &g_pg_store.plans[i];
    }
    return NULL;
}

/* Free an expired, uncommitted slot. Committed plans are kept as the audit
 * link between a plan id and its receipt, and are only dropped on reset. */
static struct property_grant_plan *claim_plan_slot(int64_t now)
{
    for (size_t i = 0; i < PROPERTY_GRANT_MAX_PLANS; i++) {
        if (!g_pg_store.plan_used[i]) return &g_pg_store.plans[i];
    }
    for (size_t i = 0; i < PROPERTY_GRANT_MAX_PLANS; i++) {
        struct property_grant_plan *p = &g_pg_store.plans[i];
        if (!p->committed && now >= p->expires_unix) return p;
    }
    return NULL;
}

/* One PLAN attempt over one snapshot. Returns AUTHORITY_CHANGED when the store
 * moved between the snapshot and the store of the plan; the caller retries
 * exactly once. */
static enum property_grant_reason plan_attempt(
    const char *grant_id, const struct metaverse_action_request *req,
    struct property_grant_plan *out)
{
    struct property_grant_authority_snapshot snap;
    enum property_grant_reason r = property_grant_service_snapshot(grant_id,
                                                                  &snap);
    if (r != PROPERTY_GRANT_OK) return r;

    /* The caller does not get to choose the clock an expiry is measured
     * against, so whatever it put in req->now_unix/height is discarded — it
     * comes from the same snapshot the recheck will validate. */
    struct metaverse_action_request rq = *req;
    rq.now_unix = snap.now_unix;
    rq.height = snap.height;

    const struct metaverse_grant *anc[METAVERSE_GRANT_MAX_DEPTH];
    size_t anc_count = property_grant_snapshot_ancestors(&snap, anc);

    /* FAIL FAST, and OUTSIDE the lock. Action not in the set, property out of
     * scope, counterparty not allowed, budget exceeded, revoked, expired — all
     * decided here, before any plan artifact exists and before any catalog
     * work is paid for. The rules are pure, so running them on the snapshot is
     * the same computation as running them under the lock; what the recheck
     * below adds is the proof that the inputs did not move. */
    enum metaverse_grant_verdict v = metaverse_grant_check(
        &snap.grant, anc_count ? anc : NULL, anc_count, &rq);
    if (v != METAVERSE_GRANT_OK) {
        LOG_WARN(PG_LOG, "plan: grant %s refused %s on %s (%s)", grant_id,
                     metaverse_action_token(rq.action),
                     metaverse_kind_name(rq.property.kind),
                     metaverse_grant_verdict_token(v));
        return property_grant_reason_from_verdict(v);
    }

    /* Read the catalog if one is installed. NO LOCK IS HELD: the real catalog
     * is a projection that rebuilds every view from datadir bytes, and holding
     * the store mutex across it would put a disk read in front of every other
     * grant decision in the process. A missing catalog is recorded, not fatal:
     * PLAN is a read-only quote, and COMMIT is where it becomes fatal. */
    struct property_grant_plan p;
    memset(&p, 0, sizeof(p));
    p.catalog_seen = false;
    p.property_revision = -1;
    metaverse_catalog_lookup_fn lookup = g_pg_store.env.catalog_lookup;
    void *lookup_ctx = g_pg_store.env.catalog_ctx;
    if (lookup) {
        struct metaverse_catalog_view view;
        memset(&view, 0, sizeof(view));
        if (lookup(&rq.property, &view, lookup_ctx)) {
            p.catalog_seen = true;
            p.property_revision = view.revision;
            snprintf(p.controller_at_plan, sizeof(p.controller_at_plan), "%s",
                     view.controller);
        }
    }

    if (!draw_id(p.plan_id, sizeof(p.plan_id))) {
        LOG_ERROR(PG_LOG, "plan: could not draw a plan id");
        return PROPERTY_GRANT_BAD_ARGS;
    }
    snprintf(p.grant_id, sizeof(p.grant_id), "%s", snap.grant.grant_id);
    p.request = rq;
    p.created_unix = rq.now_unix;
    p.expires_unix = rq.now_unix + PROPERTY_GRANT_PLAN_TTL_SECONDS;
    p.committed = false;
    p.receipt_seq = 0;

    /* RE-ACQUIRE AND CONFIRM, then record — in one critical section, so the
     * generation cannot move between the confirmation and the write. */
    pthread_mutex_lock(&g_pg_store.lock);
    if (g_pg_store.authority_generation != snap.authority_generation) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_WARN(PG_LOG,
                 "plan: the store moved while quoting grant %s — retrying",
                 grant_id);
        return PROPERTY_GRANT_AUTHORITY_CHANGED;
    }
    struct property_grant_plan *slot = claim_plan_slot(rq.now_unix);
    if (!slot) {
        pthread_mutex_unlock(&g_pg_store.lock);
        LOG_ERROR(PG_LOG, "plan: no free plan slot (cap %d)",
                     PROPERTY_GRANT_MAX_PLANS);
        return PROPERTY_GRANT_STORE_FULL;
    }
    /* NO AUTHORITY BUMP. A plan slot is not part of the authority anyone
     * decides over: nothing in metaverse_grant_check reads a plan, an authority
     * snapshot copies grants and generations and never a plan, and a plan
     * RESERVES nothing — it debits no budget and consumes no rate window, which
     * is why two plans can be quoted over the same remaining budget and the
     * second one loses at COMMIT's re-check rather than at PLAN. Evicting an
     * expired uncommitted slot only turns one refusal (PLAN_EXPIRED) into
     * another (PLAN_UNKNOWN); no authority widens either way. Bumping here
     * would be actively wrong: a read-only quote would invalidate every
     * unrelated decision in flight, and two concurrent plans would spend their
     * one retry on each other and then both refuse. */
    *slot = p;
    size_t idx = (size_t)(slot - g_pg_store.plans);
    g_pg_store.plan_used[idx] = true;
    pthread_mutex_unlock(&g_pg_store.lock);

    *out = p;
    return PROPERTY_GRANT_OK;
}

enum property_grant_reason property_grant_service_plan(
    const char *grant_id, const struct metaverse_action_request *req,
    struct property_grant_plan *out)
{
    if (!grant_id || !req || !out) {
        LOG_ERROR(PG_LOG, "plan: NULL grant id, request, or output");
        return PROPERTY_GRANT_BAD_ARGS;
    }
    enum property_grant_reason r = plan_attempt(grant_id, req, out);
    if (r == PROPERTY_GRANT_AUTHORITY_CHANGED)
        r = plan_attempt(grant_id, req, out);   /* exactly ONE retry */
    return r;
}

enum property_grant_reason property_grant_service_plan_get(
    const char *plan_id, struct property_grant_plan *out)
{
    if (!plan_id || !out) return PROPERTY_GRANT_BAD_ARGS;
    pthread_mutex_lock(&g_pg_store.lock);
    const struct property_grant_plan *p = find_plan(plan_id);
    if (p) *out = *p;
    pthread_mutex_unlock(&g_pg_store.lock);
    return p ? PROPERTY_GRANT_OK : PROPERTY_GRANT_PLAN_UNKNOWN;
}

struct property_grant_plan *pg_find_plan_locked(const char *plan_id)
{
    return find_plan(plan_id);
}
