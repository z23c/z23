/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Crypto scheme registry — singleton dispatch table.
 *
 * Storage is a fixed-size pointer array indexed by enum crypto_scheme_id.
 * Registration is single-shot per slot via CAS: the first constructor
 * to register an id wins; later constructors with the same id return
 * false. Lookup is lock-free atomic_load.
 *
 * Consensus and key-verification callers use this table for registered
 * verifier implementations, while diagnostics expose it through dumpstate.
 */

#include "crypto_registry/crypto_registry.h"

#include "json/json.h"
#include "util/log_macros.h"

#include <stdatomic.h>
#include <string.h>

/* One pointer slot per scheme id. NULL = unregistered. The slot array
 * is sized at CRYPTO_SCHEME_MAX; with ~6 schemes today and a hard cap
 * of 1000 the memory cost is ~8 KB — trivial. */
static _Atomic(const struct crypto_scheme *) g_schemes[CRYPTO_SCHEME_MAX];

/* Counters updated only on successful registration. */
static atomic_size_t g_count_total;
static atomic_size_t g_count_hash;
static atomic_size_t g_count_sig;
static atomic_size_t g_count_zk;

static atomic_size_t *counter_for_kind(enum crypto_scheme_kind kind)
{
    switch (kind) {
    case CRYPTO_KIND_HASH: return &g_count_hash;
    case CRYPTO_KIND_SIG:  return &g_count_sig;
    case CRYPTO_KIND_ZK:   return &g_count_zk;
    }
    return NULL;
}

static bool status_is_valid(enum crypto_scheme_status s)
{
    return s == CRYPTO_STATUS_ACTIVE ||
           s == CRYPTO_STATUS_DEPRECATED ||
           s == CRYPTO_STATUS_RETIRED;
}

bool crypto_registry_register(const struct crypto_scheme *scheme)
{
    if (!scheme) {
        LOG_FAIL("crypto_registry", "register: scheme is NULL");
        return false;
    }
    if ((int)scheme->id <= 0 || (int)scheme->id >= CRYPTO_SCHEME_MAX) {
        LOG_FAIL("crypto_registry",
                 "register: bad id=%d (must be in [1, %d))",
                 (int)scheme->id, CRYPTO_SCHEME_MAX);
        return false;
    }
    atomic_size_t *kind_counter = counter_for_kind(scheme->kind);
    if (!kind_counter) {
        LOG_FAIL("crypto_registry",
                 "register: id=%d (%s) bad kind=%d",
                 (int)scheme->id,
                 scheme->name ? scheme->name : "(null)",
                 (int)scheme->kind);
        return false;
    }
    if (!status_is_valid(scheme->status)) {
        LOG_FAIL("crypto_registry",
                 "register: id=%d (%s) bad status=%d",
                 (int)scheme->id,
                 scheme->name ? scheme->name : "(null)",
                 (int)scheme->status);
        return false;
    }
    if (!scheme->name || !scheme->name[0]) {
        LOG_FAIL("crypto_registry",
                 "register: id=%d missing name", (int)scheme->id);
        return false;
    }
    if (!scheme->impl || !scheme->impl[0]) {
        LOG_FAIL("crypto_registry",
                 "register: id=%d (%s) missing impl tag",
                 (int)scheme->id, scheme->name);
        return false;
    }
    /* All three function-pointer union members share storage, so reading
     * one as a generic pointer is a valid non-null check. */
    if (scheme->fn.hash == NULL) {
        LOG_FAIL("crypto_registry",
                 "register: id=%d (%s) fn pointer is NULL",
                 (int)scheme->id, scheme->name);
        return false;
    }

    const struct crypto_scheme *expected = NULL;
    if (!atomic_compare_exchange_strong(&g_schemes[scheme->id],
                                        &expected, scheme)) {
        LOG_FAIL("crypto_registry",
                 "register: id=%d (%s) slot already taken by '%s'",
                 (int)scheme->id, scheme->name,
                 expected && expected->name ? expected->name : "(unknown)");
        return false;
    }

    atomic_fetch_add(&g_count_total, 1);
    atomic_fetch_add(kind_counter, 1);
    return true;
}

const struct crypto_scheme *crypto_registry_lookup(enum crypto_scheme_id id)
{
    if ((int)id <= 0 || (int)id >= CRYPTO_SCHEME_MAX) return NULL;
    return atomic_load(&g_schemes[id]);
}

bool crypto_registry_is_usable(enum crypto_scheme_id id)
{
    const struct crypto_scheme *s = crypto_registry_lookup(id);
    if (!s) return false;
    return s->status == CRYPTO_STATUS_ACTIVE ||
           s->status == CRYPTO_STATUS_DEPRECATED;
}

size_t crypto_registry_count(void)
{
    return atomic_load(&g_count_total);
}

size_t crypto_registry_count_by_kind(enum crypto_scheme_kind kind)
{
    atomic_size_t *c = counter_for_kind(kind);
    return c ? atomic_load(c) : 0;
}

/* ── Diagnostics ─────────────────────────────────────────────────── */

static const char *kind_name(enum crypto_scheme_kind k)
{
    switch (k) {
    case CRYPTO_KIND_HASH: return "hash";
    case CRYPTO_KIND_SIG:  return "sig";
    case CRYPTO_KIND_ZK:   return "zk";
    }
    return "unknown";
}

static const char *status_name(enum crypto_scheme_status s)
{
    switch (s) {
    case CRYPTO_STATUS_UNREGISTERED: return "unregistered";
    case CRYPTO_STATUS_ACTIVE:       return "active";
    case CRYPTO_STATUS_DEPRECATED:   return "deprecated";
    case CRYPTO_STATUS_RETIRED:      return "retired";
    }
    return "unknown";
}

bool crypto_registry_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;

    /* Caller follows the g_dumpers convention of calling json_set_object
     * on `out` before invoking us. We re-assert it to be safe (the call
     * is idempotent). */
    json_set_object(out);

    json_push_kv_int(out, "total_registered",
                     (int64_t)atomic_load(&g_count_total));

    struct json_value by_kind;
    json_init(&by_kind);
    json_set_object(&by_kind);
    json_push_kv_int(&by_kind, "hash",
                     (int64_t)atomic_load(&g_count_hash));
    json_push_kv_int(&by_kind, "sig",
                     (int64_t)atomic_load(&g_count_sig));
    json_push_kv_int(&by_kind, "zk",
                     (int64_t)atomic_load(&g_count_zk));
    json_push_kv(out, "by_kind", &by_kind);
    json_free(&by_kind);

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (int i = 1; i < CRYPTO_SCHEME_MAX; i++) {
        const struct crypto_scheme *s = atomic_load(&g_schemes[i]);
        if (!s) continue;

        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        json_push_kv_int(&obj, "id",     (int64_t)s->id);
        json_push_kv_str(&obj, "name",   s->name ? s->name : "");
        json_push_kv_str(&obj, "impl",   s->impl ? s->impl : "");
        json_push_kv_str(&obj, "kind",   kind_name(s->kind));
        json_push_kv_str(&obj, "status", status_name(s->status));
        json_push_back(&arr, &obj);
        json_free(&obj);
    }
    json_push_kv(out, "schemes", &arr);
    json_free(&arr);

    return true;
}
