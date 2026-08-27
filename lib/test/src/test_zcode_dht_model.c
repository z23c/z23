/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Deterministic 32-node/10k-transition bounded DHT state model. */

#include "test/test_core.h"
#include "platform/barrier.h"

#include "config/boot_zcode_dht_reachability.h"
#include "../../vcs/src/zcode_dht_service_internal.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MODEL_NODES 32u
#define MODEL_TRANSITIONS 12000u

struct model_node {
  struct vcs_zcode_dht_service *service;
  uint64_t wall, monotonic;
  bool links[MODEL_NODES];
};

static uint64_t model_random(uint64_t *state) {
  uint64_t x = *state;
  x ^= x << 13;
  x ^= x >> 7;
  x ^= x << 17;
  *state = x;
  return x;
}

static void model_id(uint8_t out[32], uint32_t node, uint32_t serial) {
  memset(out, 0, 32);
  out[0] = (uint8_t)(0x80u | (node & 0x1fu));
  out[24] = (uint8_t)(node >> 8);
  out[25] = (uint8_t)node;
  out[28] = (uint8_t)(serial >> 24);
  out[29] = (uint8_t)(serial >> 16);
  out[30] = (uint8_t)(serial >> 8);
  out[31] = (uint8_t)serial;
}

static void model_contact(struct vcs_zcode_dht_contact *contact,
                          const uint8_t id[32], uint8_t identity,
                          uint64_t sequence) {
  memset(contact, 0, sizeof(*contact));
  memcpy(contact->node_id, id, 32);
  memset(contact->master_pubkey, identity, 32);
  memset(contact->online_pubkey, (uint8_t)(identity + 1), 32);
  memset(contact->noise_static_pubkey, (uint8_t)(identity + 2), 32);
  memset(contact->beacon_hash, (uint8_t)(identity + 3), 32);
  contact->beacon_height = 120;
  contact->delegation_sequence = sequence;
  contact->delegation_not_before = 1;
  contact->delegation_expiry = UINT64_MAX - 1;
  contact->last_success_unix = 1;
}

static bool model_caps_hold(const struct model_node nodes[MODEL_NODES]) {
  for (size_t n = 0; n < MODEL_NODES; n++) {
    const struct vcs_zcode_dht_service *s = nodes[n].service;
    if (!s || !s->table ||
        s->table->contact_count > VCS_ZCODE_DHT_MAX_CONTACTS ||
        s->table->pending_count > VCS_ZCODE_DHT_MAX_PENDING ||
        s->outbound_count > VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND)
      return false;
    size_t peers = 0, lookups = 0, queries = 0;
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
      peers += s->peers[i].used;
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++) {
      lookups += s->lookups[i].used;
      if (s->lookups[i].candidate_count >
          VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES)
        return false;
    }
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
      queries += s->queries[i].used;
    if (peers > VCS_ZCODE_DHT_SERVICE_MAX_PEERS ||
        lookups > VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS ||
        queries > VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES)
      return false;
    for (size_t p = 0; p < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; p++) {
      const struct service_peer *peer = &s->peers[p];
      if (!peer->used)
        continue;
      for (size_t q = p + 1; q < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; q++)
        if (s->peers[q].used && peer->authenticated &&
            s->peers[q].authenticated &&
            memcmp(peer->node_id, s->peers[q].node_id, 32) == 0)
          return false;
    }
  }
  return true;
}

static bool model_seed_lookup(struct vcs_zcode_dht_service *s,
                              struct service_lookup *lookup,
                              uint32_t node, uint32_t lookup_index,
                              uint32_t epoch) {
  memset(lookup, 0, sizeof(*lookup));
  lookup->used = true;
  lookup->id = (uint64_t)epoch * 1000 + lookup_index + 1;
  lookup->started_mono = epoch;
  lookup->deadline_mono = epoch + VCS_ZCODE_DHT_LOOKUP_CEILING_S;
  model_id(lookup->target, node, 0x70000000u + lookup_index);
  for (uint32_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES; i++) {
    uint8_t id[32];
    if (i < 4)
      memcpy(id, s->peers[i].node_id, 32);
    else
      model_id(id, (node + i + 1) % MODEL_NODES,
               epoch * VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES + i + 1);
    enum vcs_zcode_dht_candidate_state state =
        i < 4 ? VCS_ZCODE_DHT_CANDIDATE_AUTHENTICATED
              : VCS_ZCODE_DHT_CANDIDATE_UNVERIFIED;
    if (!vcs_zcode_dht_lookup_insert(lookup, id, state,
                                     i < 4 ? i + 1 : 0))
      return false;
  }
  return lookup->candidate_count == VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES &&
         vcs_zcode_dht_lookup_frontier_count(lookup) == VCS_ZCODE_DHT_K;
}

static struct vcs_zcode_dht_service *model_service(uint32_t node) {
  struct vcs_zcode_dht_service *s = calloc(1, sizeof(*s));
  struct vcs_zcode_dht_table *table = calloc(1, sizeof(*table));
  if (!s || !table) {
    free(s);
    free(table);
    return NULL;
  }
  model_id(s->self_id, node, 0);
  if (!vcs_zcode_dht_table_init(table, s->self_id)) {
    free(table);
    free(s);
    return NULL;
  }
  s->table = table;
  s->enabled = true;
  s->next_lookup_id = 1;
  for (uint32_t i = 0; i < VCS_ZCODE_DHT_K; i++) {
    uint8_t id[32];
    model_id(id, (node + 1) % MODEL_NODES, i + 1);
    struct vcs_zcode_dht_contact contact;
    model_contact(&contact, id, (uint8_t)(node + 1), 1);
    if (vcs_zcode_dht_table_add_contact(table, &contact, 1) !=
        VCS_ZCODE_DHT_ADD_ADDED) {
      free(table);
      free(s);
      return NULL;
    }
  }
  for (uint32_t i = 0; i < 4; i++) {
    s->peers[i].used = s->peers[i].connected =
        s->peers[i].authenticated = true;
    s->peers[i].peer_id = i + 1;
    s->peers[i].session.established = true;
    s->peers[i].session.generation = i + 1;
    s->peers[i].session.connection_serial = i + 1;
    model_id(s->peers[i].node_id, (node + i + 1) % MODEL_NODES, i + 1);
  }
  for (uint32_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++)
    if (!model_seed_lookup(s, &s->lookups[i], node, i, 1)) {
      free(table);
      free(s);
      return NULL;
    }
  for (uint32_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++) {
    s->queries[i].used = true;
    s->queries[i].kind = QUERY_LOOKUP;
    s->queries[i].lookup_id = s->lookups[i].id;
    s->queries[i].deadline_mono = UINT64_MAX;
    s->lookups[i].queries_pending++;
  }
  return s;
}

static bool model_persistence_corruption(uint32_t node) {
  uint8_t genesis[32] = {1}, self[32], wire[VCS_ZCODE_DHT_CONTACTS_HEADER_BYTES];
  model_id(self, node, 0);
  size_t len = 0;
  if (vcs_zcode_dht_contacts_serialize(NULL, 0, genesis, self, wire,
                                       sizeof(wire), &len) !=
      VCS_ZCODE_DHT_OK)
    return false;
  uint32_t count = 1;
  if (vcs_zcode_dht_contacts_parse(wire, len, genesis, self, 1, NULL, NULL,
                                   NULL, 0, &count) != VCS_ZCODE_DHT_OK ||
      count != 0)
    return false;
  wire[0] ^= 1;
  return vcs_zcode_dht_contacts_parse(wire, len, genesis, self, 1, NULL,
                                      NULL, NULL, 0, &count) ==
         VCS_ZCODE_DHT_ERR_WIRE_MAGIC;
}

static bool run_model(void) {
  struct model_node nodes[MODEL_NODES];
  uint32_t failed_step = UINT32_MAX;
  uint32_t failed_op = UINT32_MAX;
  memset(nodes, 0, sizeof(nodes));
  for (uint32_t n = 0; n < MODEL_NODES; n++) {
    nodes[n].service = model_service(n);
    if (!nodes[n].service)
      goto fail;
    nodes[n].wall = nodes[n].monotonic = 1000;
    nodes[n].links[(n + 1) % MODEL_NODES] = true;
    nodes[n].links[(n + 7) % MODEL_NODES] = true;
  }
  uint64_t random = UINT64_C(0x6a09e667f3bcc909);
  for (uint32_t step = 0; step < MODEL_TRANSITIONS; step++) {
    uint64_t draw = model_random(&random);
    uint32_t n = (uint32_t)(draw % MODEL_NODES);
    struct model_node *node = &nodes[n];
    struct vcs_zcode_dht_service *s = node->service;
    uint32_t lookup_index = (uint32_t)((draw >> 8) %
                                       VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS);
    struct service_lookup *lookup = &s->lookups[lookup_index];
    failed_step = step;
    failed_op = (uint32_t)((draw >> 16) % 10);
    switch (failed_op) {
    case 0: {
      uint8_t id[32];
      model_id(id, n, 0xf0000000u + step);
      (void)vcs_zcode_dht_lookup_insert(
          lookup, id, VCS_ZCODE_DHT_CANDIDATE_UNVERIFIED, 0);
      break;
    }
    case 1: {
      uint32_t at = (uint32_t)((draw >> 24) % lookup->candidate_count);
      if (lookup->candidates[at].state ==
          VCS_ZCODE_DHT_CANDIDATE_UNVERIFIED)
        lookup->candidates[at].state = VCS_ZCODE_DHT_CANDIDATE_UNREACHABLE;
      break;
    }
    case 2: {
      uint32_t peer = (uint32_t)((draw >> 24) % 4);
      s->peers[peer].connected = !s->peers[peer].connected;
      node->links[(n + peer + 1) % MODEL_NODES] = s->peers[peer].connected;
      break;
    }
    case 3: {
      (void)vcs_zcode_dht_service_lookup_cancel(s, lookup->id);
      if (!model_seed_lookup(s, lookup, n, lookup_index, step + 2))
        goto fail;
      break;
    }
    case 4: {
      /* Duplicate identity and key-rotation churn: the higher local serial
       * survives, independent of transcript generation ordering. */
      struct service_peer *old = &s->peers[0], *fresh = &s->peers[4];
      old->connected = true;
      old->authenticated = true;
      *fresh = *old;
      fresh->peer_id = 1000 + step;
      fresh->session.connection_serial = old->session.connection_serial + 1;
      fresh->session.generation ^= UINT64_C(0xfedcba9876543210);
      if (!vcs_zcode_dht_service_retain_unique_node_session(
              s, fresh,
              (struct vcs_zcode_dht_time){node->wall, node->monotonic}) ||
          old->used || !fresh->used)
        goto fail;
      *old = *fresh;
      old->peer_id = 1;
      memset(fresh, 0, sizeof(*fresh));
      break;
    }
    case 5: {
      /* A request-ID collision never enters the response namespace. */
      struct service_peer *peer = &s->peers[0];
      memset(peer->request_replay[0].id, (int)(step & 0xff), 16);
      peer->request_replay[0].used = true;
      peer->request_replay[0].seen_mono = node->monotonic;
      if (peer->response_replay[0].used &&
          memcmp(peer->request_replay[0].id,
                 peer->response_replay[0].id, 16) == 0)
        memset(&peer->response_replay[0], 0,
               sizeof(peer->response_replay[0]));
      break;
    }
    case 6: {
      uint8_t candidate_id[32];
      model_id(candidate_id, (n + 1) % MODEL_NODES, 0xe0000000u + step);
      struct vcs_zcode_dht_contact candidate;
      model_contact(&candidate, candidate_id, (uint8_t)(n + 33), step + 2);
      enum vcs_zcode_dht_add_result added =
          vcs_zcode_dht_table_add_contact(s->table, &candidate,
                                          (int64_t)node->monotonic);
      if (added == VCS_ZCODE_DHT_ADD_PENDING_PROBE) {
        uint8_t victim[32] = {0};
        bool found = false;
        for (size_t p = 0; p < VCS_ZCODE_DHT_MAX_PENDING; p++)
          if (s->table->pending[p].active) {
            memcpy(victim, s->table->pending[p].victim_node_id, 32);
            found = true;
            break;
          }
        if (!found || !vcs_zcode_dht_table_probe_started(
                          s->table, victim, (int64_t)node->monotonic) ||
            !vcs_zcode_dht_table_probe_complete(
                s->table, victim, VCS_ZCODE_DHT_PROBE_FAILED, true,
                (int64_t)node->wall))
          goto fail;
      }
      break;
    }
    case 7:
      if (!model_persistence_corruption(n))
        goto fail;
      break;
    case 8:
      node->wall = (draw & 1) ? node->wall + UINT64_C(86400) * 365
                              : (node->wall > 500 ? node->wall - 500 : 0);
      node->monotonic++;
      break;
    case 9: {
      lookup->completed = true;
      lookup->termination = VCS_ZCODE_DHT_TERMINATION_SHORTLIST_STABLE;
      struct vcs_zcode_dht_lookup_result result;
      uint64_t id = lookup->id;
      if (!vcs_zcode_dht_service_lookup_poll(
              s, id, (struct vcs_zcode_dht_time){node->wall, node->monotonic},
              &result))
        goto fail;
      for (uint32_t i = 0; i < result.count; i++) {
        bool authenticated = memcmp(result.node_ids[i], s->self_id, 32) == 0;
        for (size_t p = 0; !authenticated &&
                           p < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; p++)
          authenticated = s->peers[p].used && s->peers[p].authenticated &&
                          memcmp(result.node_ids[i], s->peers[p].node_id,
                                 32) == 0;
        if (!authenticated)
          goto fail;
      }
      if (!model_seed_lookup(s, lookup, n, lookup_index, step + 2))
        goto fail;
      break;
    }
    }
    node->monotonic++;
    if (!model_caps_hold(nodes))
      goto fail;
  }
  for (size_t n = 0; n < MODEL_NODES; n++) {
    free(nodes[n].service->table);
    free(nodes[n].service);
  }
  return true;
fail:
  if (failed_step != UINT32_MAX)
    printf("model failure step=%u op=%u\n", failed_step, failed_op);
  for (size_t n = 0; n < MODEL_NODES; n++)
    if (nodes[n].service) {
      free(nodes[n].service->table);
      free(nodes[n].service);
    }
  return false;
}

enum lock_stress_role {
  LOCK_STRESS_FRAME,
  LOCK_STRESS_POLL,
  LOCK_STRESS_RECONCILE,
  LOCK_STRESS_REFRESH,
  LOCK_STRESS_SAVE,
  LOCK_STRESS_SHUTDOWN,
  LOCK_STRESS_ROLE_COUNT
};

struct lock_stress {
  pthread_mutex_t lock;
  zcl_barrier_t start;
  struct vcs_zcode_dht_service *service;
  uint64_t generation;
  uint8_t genesis[32];
  _Atomic bool snapshot_ready, shutdown_started;
  _Atomic uint32_t operations[LOCK_STRESS_ROLE_COUNT];
  _Atomic bool writer_ok;
};

struct lock_stress_arg {
  struct lock_stress *shared;
  enum lock_stress_role role;
};

static void lock_stress_count(struct lock_stress *shared,
                              enum lock_stress_role role) {
  atomic_fetch_add_explicit(&shared->operations[role], 1,
                            memory_order_relaxed);
}

static void *lock_stress_worker(void *opaque) {
  struct lock_stress_arg *arg = opaque;
  struct lock_stress *shared = arg->shared;
  (void)zcl_barrier_wait(&shared->start);

  if (arg->role == LOCK_STRESS_SAVE) {
    pthread_mutex_lock(&shared->lock);
    struct vcs_zcode_dht_service *service = shared->service;
    service->persistence_dirty = true;
    service->persistence_generation++;
    struct vcs_zcode_dht_persistence_snapshot *snapshot =
        vcs_zcode_dht_service_persistence_snapshot(service, 1000, true);
    uint64_t generation = shared->generation;
    pthread_mutex_unlock(&shared->lock);
    atomic_store_explicit(&shared->snapshot_ready, true,
                          memory_order_release);
    while (!atomic_load_explicit(&shared->shutdown_started,
                                 memory_order_acquire))
      sched_yield();
    if (!snapshot) {
      lock_stress_count(shared, arg->role);
      return NULL;
    }
    bool written = vcs_zcode_dht_persistence_snapshot_write(snapshot);
    pthread_mutex_lock(&shared->lock);
    if (shared->service == service && shared->generation == generation)
      vcs_zcode_dht_service_persistence_commit(service, snapshot, written);
    pthread_mutex_unlock(&shared->lock);
    vcs_zcode_dht_persistence_snapshot_free(snapshot);
    atomic_store_explicit(&shared->writer_ok, written, memory_order_release);
    lock_stress_count(shared, arg->role);
    return NULL;
  }

  if (arg->role == LOCK_STRESS_SHUTDOWN) {
    while (!atomic_load_explicit(&shared->snapshot_ready,
                                 memory_order_acquire))
      sched_yield();
    for (;;) {
      bool ready = true;
      for (int role = LOCK_STRESS_FRAME; role <= LOCK_STRESS_REFRESH; role++)
        ready = ready && atomic_load_explicit(&shared->operations[role],
                                              memory_order_relaxed) >= 32;
      if (ready)
        break;
      sched_yield();
    }
    pthread_mutex_lock(&shared->lock);
    struct vcs_zcode_dht_service *retired = shared->service;
    shared->service = NULL;
    shared->generation++;
    pthread_mutex_unlock(&shared->lock);
    atomic_store_explicit(&shared->shutdown_started, true,
                          memory_order_release);
    /* Retirement is deliberately outside the service lock and overlaps the
     * detached snapshot writer above. */
    vcs_zcode_dht_service_free(retired,
                               (struct vcs_zcode_dht_time){1000, 1000});
    lock_stress_count(shared, arg->role);
    return NULL;
  }

  while (!atomic_load_explicit(&shared->shutdown_started,
                               memory_order_acquire)) {
    if (arg->role == LOCK_STRESS_REFRESH) {
      (void)boot_zcode_dht_reachability_refresh(
          shared->genesis, (struct vcs_zcode_dht_time){1000, 1000});
      lock_stress_count(shared, arg->role);
      continue;
    }
    pthread_mutex_lock(&shared->lock);
    struct vcs_zcode_dht_service *service = shared->service;
    if (service && arg->role == LOCK_STRESS_FRAME) {
      const uint8_t malformed[] = "ZCDHTM";
      enum vcs_zcode_dht_reject_reason rejected;
      (void)vcs_zcode_dht_service_handle_frame(
          service, 1, malformed, sizeof(malformed) - 1,
          (struct vcs_zcode_dht_time){1000, 1000}, &rejected);
    } else if (service && arg->role == LOCK_STRESS_POLL) {
      struct vcs_zcode_dht_lookup_result result;
      (void)vcs_zcode_dht_service_lookup_poll(
          service, service->lookups[0].id,
          (struct vcs_zcode_dht_time){1000, 1000}, &result);
    } else if (service && arg->role == LOCK_STRESS_RECONCILE) {
      struct vcs_zcode_dht_live_session live[4];
      for (size_t i = 0; i < 4; i++)
        live[i] = (struct vcs_zcode_dht_live_session){
            .peer_id = service->peers[i].peer_id,
            .generation = service->peers[i].session.generation,
            .connection_serial =
                service->peers[i].session.connection_serial};
      vcs_zcode_dht_service_sessions_reconcile(
          service, live, 4, (struct vcs_zcode_dht_time){1000, 1000});
    }
    pthread_mutex_unlock(&shared->lock);
    lock_stress_count(shared, arg->role);
  }
  return NULL;
}

static bool run_lock_stress(void) {
  char dir[] = "/tmp/zcl-dht-lock-XXXXXX";
  if (!mkdtemp(dir))
    return false;
  char zcode[160], dht[160], contacts[192];
  (void)snprintf(zcode, sizeof(zcode), "%s/zcode", dir);
  (void)snprintf(dht, sizeof(dht), "%s/dht", zcode);
  (void)snprintf(contacts, sizeof(contacts), "%s/contacts.v2", dht);
  bool ok = mkdir(zcode, 0700) == 0 && mkdir(dht, 0700) == 0;
  struct lock_stress shared;
  memset(&shared, 0, sizeof(shared));
  shared.service = ok ? model_service(0) : NULL;
  shared.generation = 1;
  shared.genesis[0] = 1;
  if (!shared.service)
    ok = false;
  if (ok)
    (void)snprintf(shared.service->datadir, sizeof(shared.service->datadir),
                   "%s", dir);
  /* The scale model's contacts are deliberately hostile/incomplete.  The
   * lock test needs a valid persistence payload, so start its service table
   * empty while retaining the synthetic sessions and lookups. */
  if (ok && !vcs_zcode_dht_table_init(shared.service->table,
                                      shared.service->self_id))
    ok = false;
  if (ok && pthread_mutex_init(&shared.lock, NULL) != 0)
    ok = false;
  if (ok && zcl_barrier_init(&shared.start,
                             LOCK_STRESS_ROLE_COUNT) != 0) {
    pthread_mutex_destroy(&shared.lock);
    ok = false;
  }
  pthread_t threads[LOCK_STRESS_ROLE_COUNT];
  struct lock_stress_arg args[LOCK_STRESS_ROLE_COUNT];
  size_t started = 0;
  for (int role = 0; ok && role < LOCK_STRESS_ROLE_COUNT; role++) {
    args[role] = (struct lock_stress_arg){&shared, role};
    if (pthread_create(&threads[role], NULL, lock_stress_worker,
                       &args[role]) != 0)
      ok = false;
    else
      started++;
  }
  /* A partial barrier cannot be released safely; thread creation failure is
   * fatal infrastructure on this test host, so do not pretend it was a model
   * verdict. */
  if (started == LOCK_STRESS_ROLE_COUNT)
    for (size_t i = 0; i < started; i++)
      ok = pthread_join(threads[i], NULL) == 0 && ok;
  else
    abort();
  if (started == LOCK_STRESS_ROLE_COUNT) {
    zcl_barrier_destroy(&shared.start);
    pthread_mutex_destroy(&shared.lock);
  }
  ok = ok && shared.service == NULL &&
       atomic_load_explicit(&shared.writer_ok, memory_order_acquire) &&
       atomic_load_explicit(&shared.operations[LOCK_STRESS_SAVE],
                            memory_order_relaxed) == 1 &&
       atomic_load_explicit(&shared.operations[LOCK_STRESS_SHUTDOWN],
                            memory_order_relaxed) == 1;
  for (int role = LOCK_STRESS_FRAME; role <= LOCK_STRESS_REFRESH; role++)
    ok = ok && atomic_load_explicit(&shared.operations[role],
                                    memory_order_relaxed) >= 32;
  boot_zcode_dht_reachability_reset();
  (void)unlink(contacts);
  (void)rmdir(dht);
  (void)rmdir(zcode);
  (void)rmdir(dir);
  return ok;
}

int test_zcode_dht_model(void) {
  int failures = 0;
  TEST("zcode dht model: 32 nodes/12000 transitions plus concurrent lock lifecycle") {
    ASSERT(run_model());
    ASSERT(run_lock_stress());
    PASS();
  }
_test_next:;
  return failures;
}
