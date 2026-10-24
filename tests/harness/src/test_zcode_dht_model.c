/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Deterministic 32-node/10k-transition bounded DHT state model. */

#include "test/test_core.h"
#include "platform/barrier.h"

#include "config/boot_zcode_dht_reachability.h"
#include "crypto/ed25519.h"
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

static bool model_service_table_fits(const struct vcs_zcode_dht_service *s) {
  if (!s || !s->table ||
      s->table->contact_count > VCS_ZCODE_DHT_MAX_CONTACTS ||
      s->table->pending_count > VCS_ZCODE_DHT_MAX_PENDING ||
      s->outbound_count > VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND)
    return false;
  return true;
}

static bool model_service_pools_fit(const struct vcs_zcode_dht_service *s) {
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
  return true;
}

static bool model_peer_ids_distinct(const struct vcs_zcode_dht_service *s) {
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
  return true;
}

static bool model_caps_hold(const struct model_node nodes[MODEL_NODES]) {
  for (size_t n = 0; n < MODEL_NODES; n++) {
    const struct vcs_zcode_dht_service *s = nodes[n].service;
    if (!model_service_table_fits(s) || !model_service_pools_fit(s) ||
        !model_peer_ids_distinct(s))
      return false;
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

/* One drawn transition: the random word fixes the node, the lookup slot and
 * the operation, exactly as the model always did. */
struct model_step {
  uint64_t draw;
  uint32_t step, n, lookup_index, op;
};

static void model_op_insert_unverified(struct model_node *node,
                                       const struct model_step *m) {
  struct service_lookup *lookup =
      &node->service->lookups[m->lookup_index];
  uint8_t id[32];
  model_id(id, m->n, 0xf0000000u + m->step);
  (void)vcs_zcode_dht_lookup_insert(
      lookup, id, VCS_ZCODE_DHT_CANDIDATE_UNVERIFIED, 0);
}

static void model_op_mark_unreachable(struct model_node *node,
                                      const struct model_step *m) {
  struct service_lookup *lookup =
      &node->service->lookups[m->lookup_index];
  uint32_t at = (uint32_t)((m->draw >> 24) % lookup->candidate_count);
  if (lookup->candidates[at].state == VCS_ZCODE_DHT_CANDIDATE_UNVERIFIED)
    lookup->candidates[at].state = VCS_ZCODE_DHT_CANDIDATE_UNREACHABLE;
}

static void model_op_toggle_peer(struct model_node *node,
                                 const struct model_step *m) {
  struct vcs_zcode_dht_service *s = node->service;
  uint32_t peer = (uint32_t)((m->draw >> 24) % 4);
  s->peers[peer].connected = !s->peers[peer].connected;
  node->links[(m->n + peer + 1) % MODEL_NODES] = s->peers[peer].connected;
}

static bool model_op_reseed_lookup(struct model_node *node,
                                   const struct model_step *m) {
  struct vcs_zcode_dht_service *s = node->service;
  struct service_lookup *lookup = &s->lookups[m->lookup_index];
  (void)vcs_zcode_dht_service_lookup_cancel(s, lookup->id);
  return model_seed_lookup(s, lookup, m->n, m->lookup_index, m->step + 2);
}

static bool model_op_rotate_session(struct model_node *node,
                                    const struct model_step *m) {
  struct vcs_zcode_dht_service *s = node->service;
  /* Duplicate identity and key-rotation churn: the higher local serial
   * survives, independent of transcript generation ordering. */
  struct service_peer *old = &s->peers[0], *fresh = &s->peers[4];
  old->connected = true;
  old->authenticated = true;
  *fresh = *old;
  fresh->peer_id = 1000 + m->step;
  fresh->session.connection_serial = old->session.connection_serial + 1;
  fresh->session.generation ^= UINT64_C(0xfedcba9876543210);
  if (!vcs_zcode_dht_service_retain_unique_node_session(
          s, fresh,
          (struct vcs_zcode_dht_time){node->wall, node->monotonic}) ||
      old->used || !fresh->used)
    return false;
  *old = *fresh;
  old->peer_id = 1;
  memset(fresh, 0, sizeof(*fresh));
  return true;
}

static void model_op_replay_churn(struct model_node *node,
                                  const struct model_step *m) {
  /* Ledger churn; production namespace admission is checked below. */
  struct service_peer *peer = &node->service->peers[0];
  memset(peer->request_replay[0].id, (int)(m->step & 0xff), 16);
  peer->request_replay[0].used = true;
  peer->request_replay[0].seen_mono = node->monotonic;
  if (peer->response_replay[0].used &&
      memcmp(peer->request_replay[0].id,
             peer->response_replay[0].id, 16) == 0)
    memset(&peer->response_replay[0], 0,
           sizeof(peer->response_replay[0]));
}

static bool model_pending_victim(const struct vcs_zcode_dht_table *table,
                                 uint8_t victim[32]) {
  for (size_t p = 0; p < VCS_ZCODE_DHT_MAX_PENDING; p++)
    if (table->pending[p].active) {
      memcpy(victim, table->pending[p].victim_node_id, 32);
      return true;
    }
  return false;
}

static bool model_pending_probe(struct model_node *node) {
  struct vcs_zcode_dht_service *s = node->service;
  uint8_t victim[32] = {0};
  if (!model_pending_victim(s->table, victim))
    return false;
  return vcs_zcode_dht_table_probe_started(s->table, victim,
                                           (int64_t)node->monotonic) &&
         vcs_zcode_dht_table_probe_complete(
             s->table, victim, VCS_ZCODE_DHT_PROBE_FAILED, true,
             (int64_t)node->wall);
}

static bool model_op_add_contact(struct model_node *node,
                                 const struct model_step *m) {
  struct vcs_zcode_dht_service *s = node->service;
  uint8_t candidate_id[32];
  model_id(candidate_id, (m->n + 1) % MODEL_NODES, 0xe0000000u + m->step);
  struct vcs_zcode_dht_contact candidate;
  model_contact(&candidate, candidate_id, (uint8_t)(m->n + 33), m->step + 2);
  enum vcs_zcode_dht_add_result added =
      vcs_zcode_dht_table_add_contact(s->table, &candidate,
                                      (int64_t)node->monotonic);
  if (added == VCS_ZCODE_DHT_ADD_PENDING_PROBE)
    return model_pending_probe(node);
  return true;
}

static void model_op_clock_jump(struct model_node *node,
                                const struct model_step *m) {
  node->wall = (m->draw & 1) ? node->wall + UINT64_C(86400) * 365
                             : (node->wall > 500 ? node->wall - 500 : 0);
  node->monotonic++;
}

static bool model_result_authenticated(
    const struct vcs_zcode_dht_service *s,
    const struct vcs_zcode_dht_lookup_result *result) {
  for (uint32_t i = 0; i < result->count; i++) {
    bool authenticated = memcmp(result->node_ids[i], s->self_id, 32) == 0;
    for (size_t p = 0; !authenticated &&
                       p < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; p++)
      authenticated = s->peers[p].used && s->peers[p].authenticated &&
                      memcmp(result->node_ids[i], s->peers[p].node_id,
                             32) == 0;
    if (!authenticated)
      return false;
  }
  return true;
}

static bool model_op_poll_lookup(struct model_node *node,
                                 const struct model_step *m) {
  struct vcs_zcode_dht_service *s = node->service;
  struct service_lookup *lookup = &s->lookups[m->lookup_index];
  lookup->completed = true;
  lookup->termination = VCS_ZCODE_DHT_TERMINATION_SHORTLIST_STABLE;
  struct vcs_zcode_dht_lookup_result result;
  uint64_t id = lookup->id;
  if (!vcs_zcode_dht_service_lookup_poll(
          s, id, (struct vcs_zcode_dht_time){node->wall, node->monotonic},
          &result))
    return false;
  if (!model_result_authenticated(s, &result))
    return false;
  return model_seed_lookup(s, lookup, m->n, m->lookup_index, m->step + 2);
}

static bool model_apply_op(struct model_node *node,
                           const struct model_step *m) {
  switch (m->op) {
  case 0:
    model_op_insert_unverified(node, m);
    return true;
  case 1:
    model_op_mark_unreachable(node, m);
    return true;
  case 2:
    model_op_toggle_peer(node, m);
    return true;
  case 3:
    return model_op_reseed_lookup(node, m);
  case 4:
    return model_op_rotate_session(node, m);
  case 5:
    model_op_replay_churn(node, m);
    return true;
  case 6:
    return model_op_add_contact(node, m);
  case 7:
    return model_persistence_corruption(m->n);
  case 8:
    model_op_clock_jump(node, m);
    return true;
  case 9:
    return model_op_poll_lookup(node, m);
  }
  return false; /* op is drawn modulo 10, so this is unreachable */
}

static void model_free_nodes(const struct model_node nodes[MODEL_NODES]) {
  for (size_t n = 0; n < MODEL_NODES; n++)
    if (nodes[n].service) {
      free(nodes[n].service->table);
      free(nodes[n].service);
    }
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
    struct model_step m = {
        .draw = draw,
        .step = step,
        .n = (uint32_t)(draw % MODEL_NODES),
        .lookup_index =
            (uint32_t)((draw >> 8) % VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS),
        .op = (uint32_t)((draw >> 16) % 10),
    };
    struct model_node *node = &nodes[m.n];
    failed_step = step;
    failed_op = m.op;
    if (!model_apply_op(node, &m))
      goto fail;
    node->monotonic++;
    if (!model_caps_hold(nodes))
      goto fail;
  }
  model_free_nodes(nodes);
  return true;
fail:
  if (failed_step != UINT32_MAX)
    printf("model failure step=%u op=%u\n", failed_step, failed_op);
  model_free_nodes(nodes);
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

/* True once every FRAME..REFRESH role has completed at least minimum passes. */
static bool lock_stress_ops_reached(struct lock_stress *shared,
                                    uint32_t minimum) {
  bool ready = true;
  for (int role = LOCK_STRESS_FRAME; role <= LOCK_STRESS_REFRESH; role++)
    ready = ready && atomic_load_explicit(&shared->operations[role],
                                          memory_order_relaxed) >= minimum;
  return ready;
}

static void lock_stress_save(struct lock_stress *shared,
                             enum lock_stress_role role) {
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
    lock_stress_count(shared, role);
    return;
  }
  bool written = vcs_zcode_dht_persistence_snapshot_write(snapshot);
  pthread_mutex_lock(&shared->lock);
  if (shared->service == service && shared->generation == generation)
    vcs_zcode_dht_service_persistence_commit(service, snapshot, written);
  pthread_mutex_unlock(&shared->lock);
  vcs_zcode_dht_persistence_snapshot_free(snapshot);
  atomic_store_explicit(&shared->writer_ok, written, memory_order_release);
  lock_stress_count(shared, role);
}

static void lock_stress_shutdown(struct lock_stress *shared,
                                 enum lock_stress_role role) {
  while (!atomic_load_explicit(&shared->snapshot_ready,
                               memory_order_acquire))
    sched_yield();
  while (!lock_stress_ops_reached(shared, 32))
    sched_yield();
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
  lock_stress_count(shared, role);
}

/* Caller holds shared->lock. */
static void lock_stress_service_op(struct lock_stress *shared,
                                   enum lock_stress_role role) {
  struct vcs_zcode_dht_service *service = shared->service;
  if (service && role == LOCK_STRESS_FRAME) {
    const uint8_t malformed[] = "ZCDHTM";
    enum vcs_zcode_dht_reject_reason rejected;
    (void)vcs_zcode_dht_service_handle_frame(
        service, 1, malformed, sizeof(malformed) - 1,
        (struct vcs_zcode_dht_time){1000, 1000}, &rejected);
  } else if (service && role == LOCK_STRESS_POLL) {
    struct vcs_zcode_dht_lookup_result result;
    (void)vcs_zcode_dht_service_lookup_poll(
        service, service->lookups[0].id,
        (struct vcs_zcode_dht_time){1000, 1000}, &result);
  } else if (service && role == LOCK_STRESS_RECONCILE) {
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
}

static void *lock_stress_worker(void *opaque) {
  struct lock_stress_arg *arg = opaque;
  struct lock_stress *shared = arg->shared;
  (void)zcl_barrier_wait(&shared->start);

  if (arg->role == LOCK_STRESS_SAVE) {
    lock_stress_save(shared, arg->role);
    return NULL;
  }
  if (arg->role == LOCK_STRESS_SHUTDOWN) {
    lock_stress_shutdown(shared, arg->role);
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
    lock_stress_service_op(shared, arg->role);
    pthread_mutex_unlock(&shared->lock);
    lock_stress_count(shared, arg->role);
  }
  return NULL;
}

static bool lock_stress_open_service(struct lock_stress *shared,
                                     const char *dir) {
  shared->service = model_service(0);
  if (!shared->service)
    return false;
  (void)snprintf(shared->service->datadir, sizeof(shared->service->datadir),
                 "%s", dir);
  /* The scale model's contacts are deliberately hostile/incomplete.  The
   * lock test needs a valid persistence payload, so start its service table
   * empty while retaining the synthetic sessions and lookups. */
  return vcs_zcode_dht_table_init(shared->service->table,
                                  shared->service->self_id);
}

static bool lock_stress_init_sync(struct lock_stress *shared) {
  if (pthread_mutex_init(&shared->lock, NULL) != 0)
    return false;
  if (zcl_barrier_init(&shared->start, LOCK_STRESS_ROLE_COUNT) != 0) {
    pthread_mutex_destroy(&shared->lock);
    return false;
  }
  return true;
}

static size_t lock_stress_spawn(struct lock_stress *shared,
                                pthread_t threads[LOCK_STRESS_ROLE_COUNT],
                                struct lock_stress_arg args[LOCK_STRESS_ROLE_COUNT]) {
  size_t started = 0;
  for (int role = 0; role < LOCK_STRESS_ROLE_COUNT; role++) {
    args[role] = (struct lock_stress_arg){shared, role};
    if (pthread_create(&threads[role], NULL, lock_stress_worker,
                       &args[role]) != 0)
      break;
    started++;
  }
  return started;
}

static bool lock_stress_join_all(const pthread_t threads[LOCK_STRESS_ROLE_COUNT],
                                 size_t started) {
  /* A partial barrier cannot be released safely; thread creation failure is
   * fatal infrastructure on this test host, so do not pretend it was a model
   * verdict. */
  if (started != LOCK_STRESS_ROLE_COUNT)
    abort();
  bool ok = true;
  for (size_t i = 0; i < started; i++)
    ok = pthread_join(threads[i], NULL) == 0 && ok;
  return ok;
}

static bool lock_stress_verdict(struct lock_stress *shared) {
  return shared->service == NULL &&
         atomic_load_explicit(&shared->writer_ok, memory_order_acquire) &&
         atomic_load_explicit(&shared->operations[LOCK_STRESS_SAVE],
                              memory_order_relaxed) == 1 &&
         atomic_load_explicit(&shared->operations[LOCK_STRESS_SHUTDOWN],
                              memory_order_relaxed) == 1 &&
         lock_stress_ops_reached(shared, 32);
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
  shared.generation = 1;
  shared.genesis[0] = 1;
  if (ok)
    ok = lock_stress_open_service(&shared, dir);
  if (ok)
    ok = lock_stress_init_sync(&shared);
  pthread_t threads[LOCK_STRESS_ROLE_COUNT];
  struct lock_stress_arg args[LOCK_STRESS_ROLE_COUNT];
  size_t started = ok ? lock_stress_spawn(&shared, threads, args) : 0;
  if (started != LOCK_STRESS_ROLE_COUNT)
    ok = false;
  ok = lock_stress_join_all(threads, started) && ok;
  if (started == LOCK_STRESS_ROLE_COUNT) {
    zcl_barrier_destroy(&shared.start);
    pthread_mutex_destroy(&shared.lock);
  }
  ok = ok && lock_stress_verdict(&shared);
  boot_zcode_dht_reachability_reset();
  (void)unlink(contacts);
  (void)rmdir(dht);
  (void)rmdir(zcode);
  (void)rmdir(dir);
  return ok;
}

static bool model_frame_replay(void) {
  struct vcs_zcode_dht_service *s = model_service(0);
  if (!s) return false;
  memset(s->lookups, 0, sizeof(s->lookups));
  memset(s->queries, 0, sizeof(s->queries));
  memset(s->peers, 0, sizeof(s->peers));
  struct service_peer *p = &s->peers[0];
  p->used = p->connected = p->session.established = true;
  p->peer_id = p->session.generation = p->session.connection_serial = 1;
  memset(p->session.transcript_hash, 0x77, 32);
  memset(p->session.remote_static, 0x33, 32);
  memset(s->genesis, 1, 32);
  uint8_t seed[32] = {0x22}, pub[32], secret[32], master[32] = {0x55};
  uint8_t beacon[32] = {0x44};
  struct vcs_zcode_dht_msg_find_node find = {.session_generation = 1,
      .query_id = {0x66}, .target_node_id = {0x7a}};
  ed25519_keypair(pub, secret, seed);
  bool ok = vcs_zcode_dht_delegation_sign(&find.delegation, s->genesis,
      pub, p->session.remote_static, 120, beacon, 1000, 2000, 1, master) ==
      VCS_ZCODE_DHT_DELEGATION_OK &&
      vcs_zcode_dht_delegation_node_id(find.sender_node_id, &find.delegation);
  master[0] = 0x56;
  ok = ok && vcs_zcode_dht_delegation_sign(&s->delegation, s->genesis,
      pub, p->session.remote_static, 120, beacon, 1000, 2000, 1, master) ==
      VCS_ZCODE_DHT_DELEGATION_OK &&
      vcs_zcode_dht_delegation_node_id(s->self_id, &s->delegation) &&
      vcs_zcode_dht_table_init(s->table, s->self_id);
  memcpy(s->online_seed, seed, 32);
  struct vcs_zcode_dht_msg_nodes nodes = {.session_generation = 1,
      .delegation = find.delegation, .query_id = {0x66}};
  memcpy(nodes.sender_node_id, find.sender_node_id, 32);
  uint8_t request[VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES];
  uint8_t response[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
  size_t nr = 0, ns = 0;
  ok = ok && vcs_zcode_dht_msg_serialize_find_node(&find,
      p->session.transcript_hash, seed, request, sizeof(request), &nr) == VCS_ZCODE_DHT_OK &&
      vcs_zcode_dht_msg_serialize_nodes(&nodes, p->session.transcript_hash,
      seed, response, sizeof(response), &ns) == VCS_ZCODE_DHT_OK;
  s->queries[0] = (struct service_query){.used = true, .peer_id = 1,
      .generation = 1, .kind = QUERY_LOOKUP, .deadline_mono = 1010};
  memcpy(s->queries[0].id, find.query_id, 16);
  struct vcs_zcode_dht_time now = {1001, 1001};
  enum vcs_zcode_dht_reject_reason rejected = VCS_ZCODE_DHT_REJECT_COUNT;
  ok = ok && vcs_zcode_dht_service_handle_frame(s, 1, request, nr, now, &rejected) &&
      vcs_zcode_dht_service_handle_frame(s, 1, response, ns, now, &rejected) &&
      s->frames_accepted == 2 &&
      !vcs_zcode_dht_service_handle_frame(s, 1, request, nr, now, &rejected) &&
      rejected == VCS_ZCODE_DHT_REJECT_REPLAY &&
      !vcs_zcode_dht_service_handle_frame(s, 1, response, ns, now, &rejected) &&
      rejected == VCS_ZCODE_DHT_REJECT_REPLAY;
  s->persistence_dirty = false;
  vcs_zcode_dht_service_free(s, now);
  return ok;
}

int test_zcode_dht_model(void) {
  int failures = 0;
  TEST("zcode dht model: 32 nodes/12000 transitions plus concurrent lock lifecycle") {
    ASSERT(run_model());
    ASSERT(model_frame_replay());
    ASSERT(run_lock_stress());
    PASS();
  }
_test_next:;
  return failures;
}
