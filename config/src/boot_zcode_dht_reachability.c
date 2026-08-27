/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Fixed-size ZENDP node-ID index and bounded cold-contact dial queue. */

#include "config/boot_zcode_dht_reachability.h"

#include "base/serialize_le.h"
#include "config/boot_internal.h"
#include "config/boot_zcode_swarm.h"
#include "crypto/sha3.h"
#include "models/zid_identity.h"
#include "net/connman.h"
#include "net/netaddr.h"
#include "services/chain_state_service.h"
#include "util/sync.h"
#include "validation/main_constants.h"
#include "vcs/zendp_swarm.h"
#include "zid/zendp.h"
#include "json/json.h"

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#define DHT_REACH_REQUEST_MAX 64u
#define DHT_REACH_BACKOFF_BASE_S 5u
#define DHT_REACH_BACKOFF_MAX_S 300u

struct reachability_entry {
  uint8_t node_id[32];
  struct net_address address;
};

struct reachability_backoff {
  bool used;
  bool was_authenticated;
  uint8_t node_id[32];
  uint64_t next_mono;
  uint8_t attempts;
};

struct reachability_state {
  struct reachability_entry entries[ZENDP_DIR_MAX];
  size_t entry_count;
  uint8_t requests[DHT_REACH_REQUEST_MAX][32];
  size_t request_count;
  struct reachability_backoff backoff[ZENDP_DIR_MAX];
  uint8_t endpoint_fingerprint[32];
  uint8_t chain_hash[32];
  int chain_height;
  uint64_t identity_generation;
  uint64_t endpoint_generation;
  uint64_t index_generation;
  uint64_t cache_hits, rebuilds, lookups, misses;
  uint64_t requests_enqueued, request_deduplicated, request_overflow;
  uint64_t backoff_skips, backoff_full, dials_queued, dial_rejected;
};

static zcl_mutex_t g_reach_lock;
static _Atomic int g_reach_lock_state;
static struct reachability_state g_reach;

static void prune_backoff_locked(void);

static void reach_lock(void) {
  if (atomic_load_explicit(&g_reach_lock_state, memory_order_acquire) != 2) {
    int expected = 0;
    if (atomic_compare_exchange_strong_explicit(
            &g_reach_lock_state, &expected, 1, memory_order_acq_rel,
            memory_order_acquire)) {
      zcl_mutex_init(&g_reach_lock);
      atomic_store_explicit(&g_reach_lock_state, 2, memory_order_release);
    } else {
      while (atomic_load_explicit(&g_reach_lock_state, memory_order_acquire) !=
             2)
        ;
    }
  }
  zcl_mutex_lock(&g_reach_lock);
}

static int entry_compare(const void *a, const void *b) {
  const struct reachability_entry *left = a;
  const struct reachability_entry *right = b;
  return memcmp(left->node_id, right->node_id, 32);
}

static int entry_index_locked(const uint8_t node_id[32]) {
  size_t lo = 0, hi = g_reach.entry_count;
  while (lo < hi) {
    size_t mid = lo + (hi - lo) / 2;
    int comparison = memcmp(node_id, g_reach.entries[mid].node_id, 32);
    if (comparison == 0)
      return (int)mid;
    if (comparison < 0)
      hi = mid;
    else
      lo = mid + 1;
  }
  return -1;
}

static void endpoint_fingerprint(const struct zendp_record_view *views,
                                 size_t count, uint8_t out[32]) {
  struct sha3_256_ctx hash;
  sha3_256_init(&hash);
  uint8_t encoded[ZENDP_BODY_MAX], numeric[8];
  zcl_write_u64_le(numeric, count);
  sha3_256_write(&hash, numeric, sizeof(numeric));
  for (size_t i = 0; i < count; i++) {
    sha3_256_write(&hash, views[i].master_pubkey, 32);
    zcl_write_u64_le(numeric, views[i].seq);
    sha3_256_write(&hash, numeric, sizeof(numeric));
    zcl_write_u64_le(numeric, views[i].expiry);
    sha3_256_write(&hash, numeric, sizeof(numeric));
    zcl_write_u64_le(numeric, (uint64_t)(uint32_t)views[i].anchor_height);
    sha3_256_write(&hash, numeric, sizeof(numeric));
    size_t encoded_len = zendp_encode_body(encoded, sizeof(encoded),
                                           &views[i].ep);
    zcl_write_u64_le(numeric, encoded_len);
    sha3_256_write(&hash, numeric, sizeof(numeric));
    if (encoded_len)
      sha3_256_write(&hash, encoded, encoded_len);
  }
  sha3_256_finalize(&hash, out);
}

static bool address_from_view(struct net_address *address,
                              const struct zendp_record_view *view,
                              uint64_t wall_unix) {
  net_address_init(address);
  address->nServices = view->ep.services;
  address->nTime = (uint32_t)wall_unix;
  if (view->ep.flags & ZENDP_HAS_IPV4) {
    net_addr_set_ipv4(&address->svc.addr, view->ep.ipv4);
    address->svc.port = view->ep.ipv4_port;
    return true;
  }
  if (view->ep.flags & ZENDP_HAS_IPV6) {
    memcpy(address->svc.addr.ip, view->ep.ipv6, 16);
    address->svc.port = view->ep.ipv6_port;
    return true;
  }
  return false;
}

bool boot_zcode_dht_reachability_refresh(
    const uint8_t genesis[32], struct vcs_zcode_dht_time now) {
  if (!genesis)
    return false;
  struct zendp_record_view views[ZENDP_DIR_MAX];
  size_t count = zendp_global_records(now.wall_unix, views, ZENDP_DIR_MAX);
  uint8_t fingerprint[32];
  endpoint_fingerprint(views, count, fingerprint);
  uint64_t identity_generation = zid_identity_status_generation();
  const struct block_index *tip = csr_header_tip_snapshot(csr_instance());
  int chain_height = tip ? tip->nHeight : -1;
  uint8_t chain_hash[32] = {0};
  if (tip && tip->phashBlock)
    memcpy(chain_hash, tip->phashBlock->data, 32);

  reach_lock();
  bool unchanged = g_reach.index_generation != 0 &&
                   g_reach.identity_generation == identity_generation &&
                   g_reach.chain_height == chain_height &&
                   memcmp(g_reach.chain_hash, chain_hash, 32) == 0 &&
                   memcmp(g_reach.endpoint_fingerprint, fingerprint, 32) == 0;
  if (unchanged) {
    g_reach.cache_hits++;
    zcl_mutex_unlock(&g_reach_lock);
    return true;
  }
  zcl_mutex_unlock(&g_reach_lock);

  struct reachability_entry rebuilt[ZENDP_DIR_MAX];
  size_t rebuilt_count = 0;
  for (size_t i = 0; tip && i < count; i++) {
    if (views[i].anchor_height < 0 ||
        views[i].anchor_height > INT32_MAX - ZCL_FINALITY_DEPTH)
      continue;
    uint32_t beacon_height =
        (uint32_t)(views[i].anchor_height + ZCL_FINALITY_DEPTH);
    struct block_index *beacon = block_index_get_ancestor(
        (struct block_index *)tip, (int)beacon_height);
    struct reachability_entry *entry = &rebuilt[rebuilt_count];
    if (!beacon || !beacon->phashBlock ||
        !vcs_zcode_dht_node_id(entry->node_id, genesis,
                               views[i].master_pubkey,
                               beacon->phashBlock->data) ||
        !address_from_view(&entry->address, &views[i], now.wall_unix))
      continue;
    rebuilt_count++;
  }
  qsort(rebuilt, rebuilt_count, sizeof(rebuilt[0]), entry_compare);

  reach_lock();
  if (memcmp(g_reach.endpoint_fingerprint, fingerprint, 32) != 0)
    g_reach.endpoint_generation++;
  memcpy(g_reach.entries, rebuilt, rebuilt_count * sizeof(rebuilt[0]));
  if (rebuilt_count < ZENDP_DIR_MAX)
    memset(&g_reach.entries[rebuilt_count], 0,
           (ZENDP_DIR_MAX - rebuilt_count) * sizeof(rebuilt[0]));
  g_reach.entry_count = rebuilt_count;
  prune_backoff_locked();
  memcpy(g_reach.endpoint_fingerprint, fingerprint, 32);
  memcpy(g_reach.chain_hash, chain_hash, 32);
  g_reach.chain_height = chain_height;
  g_reach.identity_generation = identity_generation;
  g_reach.index_generation++;
  g_reach.rebuilds++;
  zcl_mutex_unlock(&g_reach_lock);
  return true;
}

bool boot_zcode_dht_reachability_request(void *ctx,
                                         const uint8_t node_id[32],
                                         uint64_t wall_unix) {
  (void)wall_unix;
  struct boot_svc_ctx *svc = ctx;
  if (!svc || !svc->connman || !node_id)
    return false;
  reach_lock();
  g_reach.lookups++;
  if (entry_index_locked(node_id) < 0) {
    g_reach.misses++;
    zcl_mutex_unlock(&g_reach_lock);
    return false;
  }
  for (size_t i = 0; i < g_reach.request_count; i++)
    if (memcmp(g_reach.requests[i], node_id, 32) == 0) {
      g_reach.request_deduplicated++;
      zcl_mutex_unlock(&g_reach_lock);
      return true;
    }
  if (g_reach.request_count == DHT_REACH_REQUEST_MAX) {
    g_reach.request_overflow++;
    zcl_mutex_unlock(&g_reach_lock);
    return false;
  }
  memcpy(g_reach.requests[g_reach.request_count++], node_id, 32);
  g_reach.requests_enqueued++;
  zcl_mutex_unlock(&g_reach_lock);

  /* The request queue is consumed by boot_zcode_dht_periodic(), which runs
   * at the front of the net.zcode.swarm supervisor turn.  A lookup can
   * discover several address-free hops in sequence; leaving each accepted
   * request to the periodic clock makes that clock latency cumulative and a
   * valid sparse route can reach the lookup ceiling before its final Noise
   * session is authenticated.  Wake the existing owner immediately.  The
   * callback still performs no dial, socket, database, or DHT lifecycle work;
   * all of that remains on the supervised consumer after this function has
   * released the reachability lock (and after its caller releases the DHT
   * lock). */
  boot_zcode_swarm_request_tick();
  return true;
}

static struct reachability_backoff *backoff_for_locked(
    const uint8_t node_id[32]) {
  struct reachability_backoff *free_slot = NULL;
  for (size_t i = 0; i < ZENDP_DIR_MAX; i++) {
    if (g_reach.backoff[i].used &&
        memcmp(g_reach.backoff[i].node_id, node_id, 32) == 0)
      return &g_reach.backoff[i];
    if (!g_reach.backoff[i].used && !free_slot)
      free_slot = &g_reach.backoff[i];
  }
  if (free_slot) {
    free_slot->used = true;
    memcpy(free_slot->node_id, node_id, 32);
  }
  return free_slot;
}

static void prune_backoff_locked(void) {
  for (size_t i = 0; i < ZENDP_DIR_MAX; i++)
    if (g_reach.backoff[i].used &&
        entry_index_locked(g_reach.backoff[i].node_id) < 0)
      memset(&g_reach.backoff[i], 0, sizeof(g_reach.backoff[i]));
}

void boot_zcode_dht_reachability_drive(
    struct boot_svc_ctx *svc, const struct vcs_zcode_dht_peer_view *peers,
    size_t peer_count, struct vcs_zcode_dht_time now) {
  if (!svc || !svc->connman)
    return;

  /* A FRESH authenticated session earns exactly one clean probe budget:
   * clearing the ladder on every steady-state tick would let any peer
   * that merely stays connected pin its dial delay at the base forever
   * (and nuke its own table slot identity with it). Sessions gone from
   * this tick's view lose the credit below, so a genuine reconnect
   * clears once while flapping pays each time. */
  for (size_t i = 0; peers && i < peer_count; i++) {
    if (!peers[i].authenticated)
      continue;
    reach_lock();
    /* Ladder credit only exists to hand a re-dialable directory member
     * one clean probe on reconnect; every dial below refuses ids outside
     * the projection, so a ladder for a non-member is dead state that
     * lets transient authenticated sessions consume the fixed pool a
     * member's next disconnect-reconnect depends on. */
    struct reachability_backoff *backoff =
        entry_index_locked(peers[i].node_id) >= 0
            ? backoff_for_locked(peers[i].node_id)
            : NULL;
    if (backoff && !backoff->was_authenticated) {
      backoff->attempts = 0;
      backoff->next_mono = 0;
      backoff->was_authenticated = true;
    }
    zcl_mutex_unlock(&g_reach_lock);
  }
  reach_lock();
  for (size_t i = 0; i < ZENDP_DIR_MAX; i++) {
    if (!g_reach.backoff[i].used)
      continue;
    bool seen = false;
    for (size_t p = 0; peers && !seen && p < peer_count; p++)
      seen = peers[p].authenticated &&
             memcmp(g_reach.backoff[i].node_id, peers[p].node_id,
                    32) == 0;
    if (!seen)
      g_reach.backoff[i].was_authenticated = false;
  }
  zcl_mutex_unlock(&g_reach_lock);

  uint8_t requests[DHT_REACH_REQUEST_MAX][32];
  size_t request_count = 0;
  reach_lock();
  request_count = g_reach.request_count;
  memcpy(requests, g_reach.requests,
         request_count * sizeof(g_reach.requests[0]));
  memset(g_reach.requests, 0, sizeof(g_reach.requests));
  g_reach.request_count = 0;
  zcl_mutex_unlock(&g_reach_lock);

  for (size_t i = 0; i < request_count; i++) {
    struct net_address address;
    bool dial = false;
    reach_lock();
    int at = entry_index_locked(requests[i]);
    struct reachability_backoff *backoff =
        at >= 0 ? backoff_for_locked(requests[i]) : NULL;
    if (at >= 0 && backoff && now.monotonic_s >= backoff->next_mono) {
      address = g_reach.entries[at].address;
      uint8_t exponent = backoff->attempts < 6 ? backoff->attempts : 6;
      uint64_t delay = DHT_REACH_BACKOFF_BASE_S << exponent;
      if (delay > DHT_REACH_BACKOFF_MAX_S)
        delay = DHT_REACH_BACKOFF_MAX_S;
      if (backoff->attempts != UINT8_MAX)
        backoff->attempts++;
      backoff->next_mono = now.monotonic_s + delay;
      dial = true;
    } else if (at >= 0 && backoff) {
      g_reach.backoff_skips++;
    } else if (at >= 0) {
      /* A member that cannot get a pool slot is a starved dial, not a
       * backed-off one; count it so exhaustion is observable instead of
       * indistinguishable from quiet. */
      g_reach.backoff_full++;
    }
    zcl_mutex_unlock(&g_reach_lock);
    if (!dial)
      continue;
    bool queued = connman_queue_dht_hint(svc->connman, &address);
    reach_lock();
    if (queued)
      g_reach.dials_queued++;
    else
      g_reach.dial_rejected++;
    zcl_mutex_unlock(&g_reach_lock);
  }
}

void boot_zcode_dht_reachability_dump_json(struct json_value *out) {
  if (!out)
    return;
  reach_lock();
  json_set_object(out);
  json_push_kv_int(out, "entries", (int64_t)g_reach.entry_count);
  json_push_kv_int(out, "index_generation",
                   (int64_t)g_reach.index_generation);
  json_push_kv_int(out, "endpoint_generation",
                   (int64_t)g_reach.endpoint_generation);
  json_push_kv_int(out, "identity_generation",
                   (int64_t)g_reach.identity_generation);
  json_push_kv_int(out, "chain_height", g_reach.chain_height);
  json_push_kv_int(out, "cache_hits", (int64_t)g_reach.cache_hits);
  json_push_kv_int(out, "rebuilds", (int64_t)g_reach.rebuilds);
  json_push_kv_int(out, "lookups", (int64_t)g_reach.lookups);
  json_push_kv_int(out, "misses", (int64_t)g_reach.misses);
  json_push_kv_int(out, "requests_enqueued",
                   (int64_t)g_reach.requests_enqueued);
  json_push_kv_int(out, "request_deduplicated",
                   (int64_t)g_reach.request_deduplicated);
  json_push_kv_int(out, "request_overflow",
                   (int64_t)g_reach.request_overflow);
  json_push_kv_int(out, "backoff_skips", (int64_t)g_reach.backoff_skips);
  json_push_kv_int(out, "backoff_full", (int64_t)g_reach.backoff_full);
  json_push_kv_int(out, "dials_queued", (int64_t)g_reach.dials_queued);
  json_push_kv_int(out, "dial_rejected", (int64_t)g_reach.dial_rejected);
  zcl_mutex_unlock(&g_reach_lock);
}

void boot_zcode_dht_reachability_reset(void) {
  reach_lock();
  memset(&g_reach, 0, sizeof(g_reach));
  zcl_mutex_unlock(&g_reach_lock);
}
