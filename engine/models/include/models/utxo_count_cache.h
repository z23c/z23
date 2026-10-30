/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: time-bounded cache for the UTXO row count read by periodic gauges,
 * so an idle node does not scan the whole utxos table on every poll. */

#ifndef ZCL_MODELS_UTXO_COUNT_CACHE_H
#define ZCL_MODELS_UTXO_COUNT_CACHE_H

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* Gauge refresh period. `SELECT count(*) FROM utxos` visits every row (about
 * three million at the tip), takes seconds on a phone and, on the shared
 * node.db handle, makes WAL checkpoints answer SQLITE_LOCKED while it runs.
 * Consensus and audit callers do not use this cache. */
#define UTXO_COUNT_GAUGE_MAX_AGE_SECS 60

struct utxo_count_cache {
    _Atomic int64_t value;
    _Atomic int64_t at_secs; /* 0 = empty */
};

/* True and *out set when a count younger than max_age_secs is held at now. */
static inline bool utxo_count_cache_get(struct utxo_count_cache *c,
                                        int64_t now_secs, int64_t max_age_secs,
                                        int64_t *out)
{
    int64_t at = atomic_load(&c->at_secs);
    if (at == 0 || now_secs < at || now_secs - at >= max_age_secs)
        return false;
    *out = atomic_load(&c->value);
    return true;
}

static inline void utxo_count_cache_put(struct utxo_count_cache *c,
                                        int64_t now_secs, int64_t value)
{
    atomic_store(&c->value, value);
    atomic_store(&c->at_secs, now_secs > 0 ? now_secs : 1);
}

/* Fold one refresh into the cache. A successful read is stored and returned.
 * A failed read is never stored: the last good value is returned (0 if there
 * has never been one) so an unreadable table cannot show as an empty set. */
static inline int64_t utxo_count_cache_refresh(struct utxo_count_cache *c,
                                               int64_t now_secs, bool read_ok,
                                               int64_t value)
{
    if (read_ok) {
        utxo_count_cache_put(c, now_secs, value);
        return value;
    }
    return atomic_load(&c->at_secs) != 0 ? atomic_load(&c->value) : 0;
}

/* Keepalive for the "refresh failed" WARN: one line per this many seconds. */
#define UTXO_COUNT_REFRESH_WARN_SECS 600

#endif /* ZCL_MODELS_UTXO_COUNT_CACHE_H */
