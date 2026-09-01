/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Sorted, generation-bound DHT delegation chain cache. */

#include "config/boot_zcode_dht_chain.h"

#include "config/boot_internal.h"
#include "models/zid_identity.h"
#include "services/chain_state_service.h"
#include "util/sync.h"
#include "validation/chainstate.h"
#include "validation/main_constants.h"
#include "vcs/zcode_dht_service.h"
#include "json/json.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

struct chain_cache_entry {
  uint8_t master_pubkey[32];
  uint8_t beacon_hash[32];
  uint32_t beacon_height;
};

struct chain_cache_state {
  struct chain_cache_entry
      entries[VCS_ZCODE_DHT_SERVICE_MAX_CHAIN_DELEGATIONS];
  size_t count;
  uint64_t identity_generation, header_generation, cache_generation;
  uint64_t external_checks, cache_hits, cache_misses, invalidations;
  uint64_t ancestry_lookups, ancestry_max_height_span;
};

static zcl_mutex_t g_chain_lock;
static _Atomic int g_chain_lock_state;
static struct chain_cache_state g_chain;

static void chain_lock(void) {
  if (atomic_load_explicit(&g_chain_lock_state, memory_order_acquire) != 2) {
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &g_chain_lock_state, &expected, 1, memory_order_acq_rel,
            memory_order_acquire)) {
      zcl_mutex_init(&g_chain_lock);
      atomic_store_explicit(&g_chain_lock_state, 2, memory_order_release);
    } else {
      while (atomic_load_explicit(&g_chain_lock_state,
                                  memory_order_acquire) != 2)
        ;
    }
  }
  zcl_mutex_lock(&g_chain_lock);
}

static int entry_key_compare(const struct chain_cache_entry *entry,
                             const struct vcs_zcode_dht_delegation *d) {
  int comparison = memcmp(entry->master_pubkey, d->doc.master_pubkey, 32);
  if (comparison)
    return comparison;
  if (entry->beacon_height < d->beacon_height)
    return -1;
  if (entry->beacon_height > d->beacon_height)
    return 1;
  return memcmp(entry->beacon_hash, d->beacon_hash, 32);
}

static int entry_index_locked(const struct vcs_zcode_dht_delegation *d,
                              size_t *insert_at) {
  size_t lo = 0, hi = g_chain.count;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int comparison = entry_key_compare(&g_chain.entries[mid], d);
    if (!comparison) {
      if (insert_at)
        *insert_at = mid;
      return (int)mid;
    }
    if (comparison < 0)
      lo = mid + 1;
    else
      hi = mid;
  }
  if (insert_at)
    *insert_at = lo;
  return -1;
}

static bool epoch_current(uint64_t identity_generation,
                          uint64_t header_generation) {
  return identity_generation == zid_identity_status_generation() &&
         header_generation == csr_header_generation(csr_instance());
}

bool boot_zcode_dht_chain_cached(
    void *ctx, const struct vcs_zcode_dht_delegation *delegation) {
  (void)ctx;
  if (!delegation)
    return false;
  uint64_t identity_generation = zid_identity_status_generation();
  uint64_t header_generation = csr_header_generation(csr_instance());
  chain_lock();
  bool current = g_chain.identity_generation == identity_generation &&
                 g_chain.header_generation == header_generation;
  bool found = current && entry_index_locked(delegation, NULL) >= 0;
  if (found)
    g_chain.cache_hits++;
  else
    g_chain.cache_misses++;
  zcl_mutex_unlock(&g_chain_lock);
  return found;
}

bool boot_zcode_dht_chain_epoch_current(void) {
  uint64_t identity_generation = zid_identity_status_generation();
  uint64_t header_generation = csr_header_generation(csr_instance());
  chain_lock();
  bool current = g_chain.cache_generation != 0 &&
                 g_chain.identity_generation == identity_generation &&
                 g_chain.header_generation == header_generation;
  zcl_mutex_unlock(&g_chain_lock);
  return current;
}

bool boot_zcode_dht_chain_authorize(
    struct boot_svc_ctx *svc,
    const struct vcs_zcode_dht_delegation *delegation) {
  if (!svc || !svc->state || !svc->node_db || !delegation)
    return false;
  if (boot_zcode_dht_chain_cached(NULL, delegation))
    return true;
  uint64_t identity_generation = zid_identity_status_generation();
  uint64_t header_generation = csr_header_generation(csr_instance());
  struct zid_identity identity;
  bool ok = db_zid_identity_find(svc->node_db,
                                 delegation->doc.master_pubkey, &identity) &&
            strcmp(identity.status, ZID_IDENTITY_STATUS_ACTIVE) == 0 &&
            identity.anchor_height >= 0 &&
            identity.anchor_height <= INT32_MAX - ZCL_FINALITY_DEPTH &&
            delegation->beacon_height ==
                (uint32_t)(identity.anchor_height + ZCL_FINALITY_DEPTH);
  const struct block_index *tip =
      ok ? csr_header_tip_snapshot(csr_instance()) : NULL;
  uint64_t span = 0;
  if (!tip || tip->nHeight <
                  (int)delegation->beacon_height + ZCL_FINALITY_DEPTH)
    ok = false;
  struct block_index *beacon =
      ok ? block_index_get_ancestor((struct block_index *)tip,
                                    (int)delegation->beacon_height)
         : NULL;
  if (ok) {
    span = (uint64_t)tip->nHeight - delegation->beacon_height;
    ok = beacon && beacon->phashBlock &&
         memcmp(beacon->phashBlock->data, delegation->beacon_hash, 32) == 0;
  }
  bool current = epoch_current(identity_generation, header_generation);
  chain_lock();
  g_chain.external_checks++;
  if (beacon)
    g_chain.ancestry_lookups++;
  if (span > g_chain.ancestry_max_height_span)
    g_chain.ancestry_max_height_span = span;
  if (!current) {
    g_chain.invalidations++;
    g_chain.count = 0;
    g_chain.identity_generation = zid_identity_status_generation();
    g_chain.header_generation = csr_header_generation(csr_instance());
    g_chain.cache_generation++;
    zcl_mutex_unlock(&g_chain_lock);
    return false;
  }
  if (g_chain.identity_generation != identity_generation ||
      g_chain.header_generation != header_generation) {
    g_chain.count = 0;
    g_chain.identity_generation = identity_generation;
    g_chain.header_generation = header_generation;
    g_chain.invalidations++;
    g_chain.cache_generation++;
  }
  size_t at = 0;
  if (ok && entry_index_locked(delegation, &at) < 0 &&
      g_chain.count < VCS_ZCODE_DHT_SERVICE_MAX_CHAIN_DELEGATIONS) {
    memmove(&g_chain.entries[at + 1], &g_chain.entries[at],
            (g_chain.count - at) * sizeof(g_chain.entries[0]));
    struct chain_cache_entry *entry = &g_chain.entries[at];
    memcpy(entry->master_pubkey, delegation->doc.master_pubkey, 32);
    memcpy(entry->beacon_hash, delegation->beacon_hash, 32);
    entry->beacon_height = delegation->beacon_height;
    g_chain.count++;
  }
  zcl_mutex_unlock(&g_chain_lock);
  return ok;
}

void boot_zcode_dht_chain_dump_json(struct json_value *out) {
  if (!out)
    return;
  chain_lock();
  json_set_object(out);
  json_push_kv_int(out, "entries", (int64_t)g_chain.count);
  json_push_kv_int(out, "cache_generation",
                   (int64_t)g_chain.cache_generation);
  json_push_kv_int(out, "identity_generation",
                   (int64_t)g_chain.identity_generation);
  json_push_kv_int(out, "header_generation",
                   (int64_t)g_chain.header_generation);
  json_push_kv_int(out, "external_checks",
                   (int64_t)g_chain.external_checks);
  json_push_kv_int(out, "cache_hits", (int64_t)g_chain.cache_hits);
  json_push_kv_int(out, "cache_misses", (int64_t)g_chain.cache_misses);
  json_push_kv_int(out, "invalidations", (int64_t)g_chain.invalidations);
  json_push_kv_int(out, "ancestry_lookups",
                   (int64_t)g_chain.ancestry_lookups);
  json_push_kv_int(out, "ancestry_max_height_span",
                   (int64_t)g_chain.ancestry_max_height_span);
  zcl_mutex_unlock(&g_chain_lock);
}

void boot_zcode_dht_chain_reset(void) {
  chain_lock();
  memset(&g_chain, 0, sizeof(g_chain));
  zcl_mutex_unlock(&g_chain_lock);
}
