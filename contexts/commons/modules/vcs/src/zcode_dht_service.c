/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded long-lived FIND_NODE/NODES service for the ZCODE DHT. */

#include "vcs/zcode_dht_service.h"
#include "base/bytes.h"
#include "zcode_dht_service_internal.h"

#include "base/safe_alloc.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "support/cleanse.h"
#include "util/blocker.h"
#include "vcs/zcode_dht_identity.h"

#include <limits.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool pending_candidate_valid(struct vcs_zcode_dht_service *s,
                                    const struct vcs_zcode_dht_pending *p,
                                    uint64_t wall_now);

const char *
vcs_zcode_dht_reject_reason_string(enum vcs_zcode_dht_reject_reason r) {
  static const char *const names[] = {
      "malformed",    "plaintext",
      "delegation",   "identity",
      "signature",    "wrong-session",
      "replay",       "unsolicited",
      "expired",      "poisoned-contacts",
      "rate-limit",   "capacity",
      "unauthorized", "backpressure"};
  return (unsigned)r < VCS_ZCODE_DHT_REJECT_COUNT ? names[r] : "unknown";
}

void vcs_zcode_dht_service_set_error(struct vcs_zcode_dht_service *s,
                                     const char *e) {
  if (s)
    (void)snprintf(s->last_error, sizeof(s->last_error), "%s", e ? e : "");
}

static void reject(struct vcs_zcode_dht_service *s,
                   enum vcs_zcode_dht_reject_reason r,
                   enum vcs_zcode_dht_reject_reason *out) {
  if ((unsigned)r < VCS_ZCODE_DHT_REJECT_COUNT)
    s->rejected[r]++;
  if (out)
    *out = r;
}

static struct service_peer *peer_find(struct vcs_zcode_dht_service *s,
                                      uint64_t peer_id) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
    if (s->peers[i].used && s->peers[i].peer_id == peer_id)
      return &s->peers[i];
  return NULL;
}

static struct service_query *query_find(struct vcs_zcode_dht_service *s,
                                        uint64_t peer, const uint8_t id[16]) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
    if (s->queries[i].used && s->queries[i].peer_id == peer &&
        memcmp(s->queries[i].id, id, 16) == 0)
      return &s->queries[i];
  return NULL;
}

static bool query_was_expired(const struct vcs_zcode_dht_service *s,
                              uint64_t peer, uint64_t generation,
                              const uint8_t id[16], uint64_t now_mono) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER; i++)
    if (s->expired[i].used && s->expired[i].peer_id == peer &&
        s->expired[i].generation == generation &&
        now_mono - s->expired[i].expired_at_mono <=
            VCS_ZCODE_DHT_SERVICE_REPLAY_SECONDS &&
        memcmp(s->expired[i].id, id, 16) == 0)
      return true;
  return false;
}

static void query_remember_expired(struct vcs_zcode_dht_service *s,
                                   const struct service_query *q,
                                   uint64_t now_mono) {
  size_t slot = 0;
  uint64_t oldest = UINT64_MAX;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER; i++) {
    if (!s->expired[i].used ||
        now_mono - s->expired[i].expired_at_mono >
            VCS_ZCODE_DHT_SERVICE_REPLAY_SECONDS) {
      slot = i;
      break;
    }
    if (s->expired[i].expired_at_mono < oldest) {
      oldest = s->expired[i].expired_at_mono;
      slot = i;
    }
  }
  s->expired[slot].used = true;
  s->expired[slot].peer_id = q->peer_id;
  s->expired[slot].generation = q->generation;
  s->expired[slot].expired_at_mono = now_mono;
  memcpy(s->expired[slot].id, q->id, 16);
}

static uint32_t query_count(const struct vcs_zcode_dht_service *s) {
  uint32_t n = 0;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
    n += s->queries[i].used;
  return n;
}

static void mark_dirty(struct vcs_zcode_dht_service *s, uint64_t now_mono) {
  if (!s->persistence_dirty)
    s->dirty_since_mono = now_mono;
  s->persistence_dirty = true;
  s->persistence_generation++;
}

static bool query_id(struct vcs_zcode_dht_service *s, uint64_t peer,
                     uint64_t generation, uint8_t out[16]) {
  uint8_t digest[32];
  struct sha3_256_ctx h;
  s->serial++;
  sha3_256_init(&h);
  sha3_256_write(&h, (const uint8_t *)"zcl.dht.query.v1", 17);
  sha3_256_write(&h, s->self_id, 32);
  sha3_256_write(&h, (uint8_t *)&peer, 8);
  sha3_256_write(&h, (uint8_t *)&generation, 8);
  sha3_256_write(&h, (uint8_t *)&s->serial, 8);
  sha3_256_finalize(&h, digest);
  memcpy(out, digest, 16);
  return zcl_bytes_any_set(out, 16);
}

static bool outbound_push(struct vcs_zcode_dht_service *s, uint64_t peer,
                          const uint8_t *wire, size_t len) {
  if (!wire || !len || len > VCS_ZCODE_DHT_MAX_FRAME_BYTES ||
      s->outbound_count >= VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND)
    return false;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND; i++)
    if (!s->outbound[i].used) {
      s->outbound[i].used = true;
      s->outbound[i].peer_id = peer;
      s->outbound[i].len = len;
      memcpy(s->outbound[i].wire, wire, len);
      s->outbound_count++;
      s->outbound_enqueued++;
      return true;
    }
  return false;
}

bool vcs_zcode_dht_service_send_find(struct vcs_zcode_dht_service *s,
                                     struct service_peer *p,
                                     enum query_kind kind, uint64_t lookup_id,
                                     const uint8_t target[32],
                                     const uint8_t victim[32],
                                     uint64_t now_mono) {
  struct service_query *q = NULL;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
    if (!s->queries[i].used) {
      q = &s->queries[i];
      break;
    }
  if (!q || !p || !p->connected || !p->session.established)
    return false;
  memset(q, 0, sizeof(*q));
  q->used = true;
  q->kind = kind;
  q->peer_id = p->peer_id;
  q->generation = p->session.generation;
  q->deadline_mono =
      now_mono + (kind == QUERY_PROBE ? VCS_ZCODE_DHT_PROBE_TIMEOUT_S
                                      : VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S);
  q->lookup_id = lookup_id;
  memcpy(q->target, target, 32);
  if (victim)
    memcpy(q->victim, victim, 32);
  if (!query_id(s, p->peer_id, p->session.generation, q->id)) {
    q->used = false;
    return false;
  }
  struct vcs_zcode_dht_msg_find_node m = {.session_generation =
                                              p->session.generation};
  memcpy(m.sender_node_id, s->self_id, 32);
  memcpy(m.query_id, q->id, 16);
  memcpy(m.target_node_id, target, 32);
  m.delegation = s->delegation;
  uint8_t wire[VCS_ZCODE_DHT_FIND_NODE_WIRE_BYTES];
  size_t len = 0;
  if (vcs_zcode_dht_msg_serialize_find_node(&m, p->session.transcript_hash,
                                            s->online_seed, wire, sizeof(wire),
                                            &len) != VCS_ZCODE_DHT_OK ||
      !outbound_push(s, p->peer_id, wire, len)) {
    q->used = false;
    return false;
  }
  s->find_sent++;
  return true;
}

static void query_finish_lookup(struct vcs_zcode_dht_service *s,
                                struct service_query *q,
                                enum query_outcome outcome) {
  struct service_lookup *l = vcs_zcode_dht_lookup_find(s, q->lookup_id);
  struct service_peer *p = peer_find(s, q->peer_id);
  if (l && p) {
    int at = vcs_zcode_dht_lookup_candidate_index(l, p->node_id);
    if (at >= 0)
      l->candidates[at].state = outcome == QUERY_OUTCOME_RESPONSE
                                    ? VCS_ZCODE_DHT_CANDIDATE_RESPONDED
                                    : VCS_ZCODE_DHT_CANDIDATE_FAILED;
  }
  if (l && l->queries_pending)
    l->queries_pending--;
}

static struct vcs_zcode_dht_pending *
probe_pending_for(struct vcs_zcode_dht_service *s, const uint8_t victim[32]) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_MAX_PENDING; i++)
    if (s->table->pending[i].active &&
        memcmp(s->table->pending[i].victim_node_id, victim, 32) == 0)
      return &s->table->pending[i];
  return NULL;
}

static enum vcs_zcode_dht_probe_state
probe_terminal_state(enum query_outcome outcome) {
  if (outcome == QUERY_OUTCOME_RESPONSE)
    return VCS_ZCODE_DHT_PROBE_RESPONDED;
  return outcome == QUERY_OUTCOME_EXPIRED ? VCS_ZCODE_DHT_PROBE_EXPIRED
                                          : VCS_ZCODE_DHT_PROBE_FAILED;
}

static void query_finish_probe(struct vcs_zcode_dht_service *s,
                               struct service_query *q,
                               enum query_outcome outcome,
                               struct vcs_zcode_dht_time now) {
  enum vcs_zcode_dht_probe_state terminal = probe_terminal_state(outcome);
  struct vcs_zcode_dht_pending *pending = probe_pending_for(s, q->victim);
  bool candidate_valid = outcome == QUERY_OUTCOME_RESPONSE ||
                         pending_candidate_valid(s, pending, now.wall_unix);
  if (!candidate_valid)
    (void)vcs_zcode_dht_table_probe_discard(s->table, q->victim, terminal);
  else
    (void)vcs_zcode_dht_table_probe_complete(
        s->table, q->victim, terminal, true, (int64_t)now.wall_unix);
  mark_dirty(s, now.monotonic_s);
}

void vcs_zcode_dht_service_query_finish(
    struct vcs_zcode_dht_service *s, struct service_query *q,
    enum query_outcome outcome, struct vcs_zcode_dht_time now) {
  vcs_zcode_dht_service_record_query_finish(s, q, outcome, now);
  if (q->kind == QUERY_LOOKUP)
    query_finish_lookup(s, q, outcome);
  else if (q->kind == QUERY_PROBE && zcl_bytes_any_set(q->victim, 32))
    query_finish_probe(s, q, outcome, now);
  memset(q, 0, sizeof(*q));
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++)
    vcs_zcode_dht_lookup_assess(s, &s->lookups[i]);
  vcs_zcode_dht_lookup_schedule(s, now);
  vcs_zcode_dht_service_publication_schedule(s, now);
}

static void query_expire(struct vcs_zcode_dht_service *s,
                         struct service_query *q,
                         struct vcs_zcode_dht_time now) {
  query_remember_expired(s, q, now.monotonic_s);
  vcs_zcode_dht_service_query_finish(s, q, QUERY_OUTCOME_EXPIRED, now);
}

static enum vcs_zcode_dht_reject_reason
map_parse_error(enum vcs_zcode_dht_error e) {
  if (e == VCS_ZCODE_DHT_ERR_SESSION)
    return VCS_ZCODE_DHT_REJECT_SESSION;
  if (e == VCS_ZCODE_DHT_ERR_SIGNATURE)
    return VCS_ZCODE_DHT_REJECT_SIGNATURE;
  if (e == VCS_ZCODE_DHT_ERR_IDENTITY)
    return VCS_ZCODE_DHT_REJECT_IDENTITY;
  if (e == VCS_ZCODE_DHT_ERR_EXPIRED)
    return VCS_ZCODE_DHT_REJECT_EXPIRED;
  if (e == VCS_ZCODE_DHT_ERR_DELEGATION || e == VCS_ZCODE_DHT_ERR_NETWORK)
    return VCS_ZCODE_DHT_REJECT_DELEGATION;
  if (e == VCS_ZCODE_DHT_ERR_WIRE_ORDER || e == VCS_ZCODE_DHT_ERR_ID_ZERO)
    return VCS_ZCODE_DHT_REJECT_POISONED;
  return VCS_ZCODE_DHT_REJECT_MALFORMED;
}

static bool replay_seen(const struct replay_entry *ledger,
                        const uint8_t id[16], uint64_t now_mono) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER; i++)
    if (ledger[i].used &&
        now_mono - ledger[i].seen_mono <=
            VCS_ZCODE_DHT_SERVICE_REPLAY_SECONDS &&
        memcmp(ledger[i].id, id, 16) == 0)
      return true;
  return false;
}

struct replay_admission {
  size_t slot;
  struct replay_entry previous;
};

static bool replay_accept(struct replay_entry *ledger, const uint8_t id[16],
                          uint64_t now_mono,
                          struct replay_admission *admission) {
  size_t oldest = 0;
  uint64_t oldest_seen = UINT64_MAX;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER; i++) {
    if (ledger[i].used &&
        now_mono - ledger[i].seen_mono <=
            VCS_ZCODE_DHT_SERVICE_REPLAY_SECONDS &&
        memcmp(ledger[i].id, id, 16) == 0)
      return false;
    if (!ledger[i].used ||
        now_mono - ledger[i].seen_mono >
            VCS_ZCODE_DHT_SERVICE_REPLAY_SECONDS) {
      oldest = i;
      oldest_seen = 0;
      break;
    }
    if (ledger[i].seen_mono < oldest_seen) {
      oldest = i;
      oldest_seen = ledger[i].seen_mono;
    }
  }
  admission->slot = oldest;
  admission->previous = ledger[oldest];
  ledger[oldest].used = true;
  memcpy(ledger[oldest].id, id, 16);
  ledger[oldest].seen_mono = now_mono;
  return true;
}

static void replay_restore(struct replay_entry *ledger,
                           const struct replay_admission *admission) {
  ledger[admission->slot] = admission->previous;
}

static bool rate_accept(struct service_peer *p, uint64_t now_mono) {
  if (p->rate_refill_mono == 0) {
    p->rate_refill_mono = now_mono;
    p->rate_tokens = VCS_ZCODE_DHT_SERVICE_RATE_BURST;
  }
  if (now_mono > p->rate_refill_mono) {
    uint64_t add =
        (now_mono - p->rate_refill_mono) *
        VCS_ZCODE_DHT_SERVICE_RATE_PER_SECOND;
    uint64_t total = p->rate_tokens + add;
    p->rate_tokens = (uint8_t)(total > VCS_ZCODE_DHT_SERVICE_RATE_BURST
                                   ? VCS_ZCODE_DHT_SERVICE_RATE_BURST
                                   : total);
    p->rate_refill_mono = now_mono;
  }
  if (!p->rate_tokens)
    return false;
  p->rate_tokens--;
  return true;
}

static int node_cmp(const void *a, const void *b) { return memcmp(a, b, 32); }

static bool reply_nodes(struct vcs_zcode_dht_service *s, struct service_peer *p,
                        const uint8_t query[16], const uint8_t target[32],
                        uint64_t now,
                        enum vcs_zcode_dht_reject_reason *rejected_out) {
  struct vcs_zcode_dht_contact closest[VCS_ZCODE_DHT_K];
  size_t n = vcs_zcode_dht_table_closest(s->table, target, closest,
                                         VCS_ZCODE_DHT_K - 1);
  struct vcs_zcode_dht_msg_nodes m = {
      .session_generation = p->session.generation, .delegation = s->delegation};
  memcpy(m.sender_node_id, s->self_id, 32);
  memcpy(m.query_id, query, 16);
  memcpy(m.node_ids[m.contact_count++], s->self_id, 32);
  for (size_t i = 0; i < n && m.contact_count < VCS_ZCODE_DHT_K; i++)
    if (closest[i].delegation_expiry > now &&
        memcmp(closest[i].node_id, s->self_id, 32) != 0)
      memcpy(m.node_ids[m.contact_count++], closest[i].node_id, 32);
  qsort(m.node_ids, m.contact_count, 32, node_cmp);
  uint8_t wire[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
  size_t len = 0;
  if (vcs_zcode_dht_msg_serialize_nodes(&m, p->session.transcript_hash,
                                        s->online_seed, wire, sizeof(wire),
                                        &len) != VCS_ZCODE_DHT_OK ||
      !outbound_push(s, p->peer_id, wire, len)) {
    /* Same causal condition as every other outbound failure: our egress
     * could not take the frame. That is not capacity guilt on the peer,
     * so it reports BACKPRESSURE instead of CAP. */
    reject(s, VCS_ZCODE_DHT_REJECT_BACKPRESSURE, rejected_out);
    return false;
  }
  s->nodes_sent++;
  return true;
}

/* Parameter viability, including the datadir length bound. The service
 * binds identity, record and persistence state under one prefix; a path
 * that does not fit s->datadir must refuse before any state exists,
 * because identity material loads from the full caller path while record
 * storage and persistence bind the copied buffer. */
static bool dht_service_params_unusable(
    const struct vcs_zcode_dht_service_params *p) {
  return !p || !p->datadir ||
         strlen(p->datadir) >= VCS_ZCODE_DHT_SERVICE_DATADIR_CAP;
}

/* Loads the delegation and online key from the datadir and checks that the
 * online key matches the delegation on disk. Returns the disabled reason, or
 * NULL when the identity is usable. */
static const char *
dht_service_identity_refusal(struct vcs_zcode_dht_service *s,
                             const struct vcs_zcode_dht_service_params *p) {
  char err[160];
  uint8_t online_pub[32], secret_copy[32];
  if (!vcs_zcode_dht_delegation_load(p->datadir, &s->delegation, err,
                                     sizeof(err)) ||
      !vcs_zcode_dht_online_key_load(p->datadir, s->online_seed, online_pub,
                                     err, sizeof(err))) {
    vcs_zcode_dht_service_set_error(s, err);
    return "IDENTITY_MATERIAL_UNAVAILABLE";
  }
  zcl_ed25519_keypair(online_pub, secret_copy, s->online_seed);
  memory_cleanse(secret_copy, 32);
  if (memcmp(online_pub, s->delegation.online_pubkey, 32) != 0) {
    vcs_zcode_dht_service_set_error(s,
                                    "delegated online key does not match disk");
    return "ONLINE_KEY_MISMATCH";
  }
  return NULL;
}

static void dht_service_report_expired_delegation(void) {
  /* Renewal needs the operator's master identity seed --
   * vcs_zcode_dht_delegation_sign() takes it as an argument and this process
   * never reads or holds it (see the zcode.network.delegate command in
   * tools/command/native_zcode_network_command.c, the only place a delegation
   * is (re-)issued). boot_zcode_dht.c retries vcs_zcode_dht_service_create()
   * every DHT_RETRY_SECONDS forever while the service stays disabled, which
   * would otherwise re-derive this exact "own doc expired" fact and
   * (pre-rate-limit) log it every retry. Name that once as a typed blocker
   * instead of a log line per tick; blocker_set's own rate limit keeps repeat
   * calls here from re-firing it. */
  struct blocker_record b;
  if (blocker_init(&b, "zcode_dht.own_delegation_expired", "zcode_dht",
                   BLOCKER_DEPENDENCY,
                   "own ZCODE DHT delegation (delegation.v1) is expired "
                   "and this process does not hold the master ZID seed "
                   "needed to re-sign it — an operator must run the "
                   "zcode.network.delegate command with that seed file "
                   "to renew"))
    (void)blocker_set(&b);
}

/* Returns true when the delegation verifies. On failure it records the
 * disabled reason and error, and reports the expired-delegation blocker. */
static bool
dht_service_delegation_verified(struct vcs_zcode_dht_service *s,
                                const struct vcs_zcode_dht_service_params *p) {
  enum vcs_zcode_dht_delegation_error delegation_error =
      vcs_zcode_dht_delegation_verify(&s->delegation, s->genesis,
                                      p->local_noise_static, 0, NULL,
                                      p->now.wall_unix);
  if (delegation_error == VCS_ZCODE_DHT_DELEGATION_OK)
    return true;
  snprintf(s->disabled_reason, sizeof(s->disabled_reason), "DELEGATION_%s",
           vcs_zcode_dht_delegation_error_string(delegation_error));
  vcs_zcode_dht_service_set_error(s, "local delegation verification failed");
  if (delegation_error == VCS_ZCODE_DHT_DELEGATION_EXPIRED)
    dht_service_report_expired_delegation();
  return false;
}

/* Loads the record store and sovereignty policy. Load errors are recorded as
 * the service error but do not disable the service. */
static void dht_service_load_records_and_policy(
    struct vcs_zcode_dht_service *s,
    const struct vcs_zcode_dht_service_params *p) {
  char err[160];
  struct vcs_zcode_dht_record_verify_context record_verify = {
      .now_unix = p->now.wall_unix,
      .authority_verify = s->authority_verify,
      .authority_ctx = s->authority_ctx,
  };
  memcpy(record_verify.network_genesis, s->genesis, 32);
  enum vcs_zcode_dht_record_store_result record_load =
      vcs_zcode_dht_record_store_load(s->record_store, s->datadir,
                                      &record_verify, err, sizeof(err));
  if (record_load != VCS_ZCODE_DHT_RECORD_STORE_OK)
    vcs_zcode_dht_service_set_error(s, err);
  enum vcs_zcode_sovereignty_result policy_load =
      vcs_zcode_sovereignty_policy_load(s->owned_policy, s->datadir, err,
                                        sizeof(err));
  if (policy_load != VCS_ZCODE_SOVEREIGNTY_OK)
    vcs_zcode_dht_service_set_error(s, err);
  if (!s->policy_decide) {
    s->policy_decide = vcs_zcode_sovereignty_policy_decide_callback;
    s->policy_ctx = s->owned_policy;
  }
}

struct vcs_zcode_dht_service *
vcs_zcode_dht_service_create(const struct vcs_zcode_dht_service_params *p) {
  if (dht_service_params_unusable(p))
    return NULL;
  struct vcs_zcode_dht_service *s =
      zcl_calloc(1, sizeof(*s), "zcode_dht_service");
  if (!s)
    return NULL;
  /* Disabled services are still observable through status/peer/delegation
   * readers.  Keep their routing state deterministic even when creation
   * returns before identity verification initializes the table. */
  s->table = zcl_calloc(1, sizeof(*s->table), "zcode_dht_table");
  if (!s->table) {
    free(s);
    return NULL;
  }
  snprintf(s->datadir, sizeof(s->datadir), "%s", p->datadir);
  memcpy(s->genesis, p->network_genesis, 32);
  memcpy(s->local_noise_static, p->local_noise_static, 32);
  s->transport_verify = p->transport_verify;
  s->transport_ctx = p->transport_ctx;
  s->authority_verify = p->authority_verify;
  s->authority_ctx = p->authority_ctx;
  s->request_reachability = p->request_reachability;
  s->reachability_ctx = p->reachability_ctx;
  s->policy_decide = p->policy_decide;
  s->policy_ctx = p->policy_ctx;
  s->next_lookup_id = 1;
  s->next_record_operation_id = 1;
  s->next_record_discovery_id = 1;
  if (!p->transport_enabled) {
    snprintf(s->disabled_reason, sizeof(s->disabled_reason),
             "NOISE_TRANSPORT_DISABLED");
    return s;
  }
  s->record_store = vcs_zcode_dht_record_store_create(p->network_genesis);
  s->owned_policy = vcs_zcode_sovereignty_policy_create(p->network_genesis);
  if (!s->record_store || !s->owned_policy) {
    snprintf(s->disabled_reason, sizeof(s->disabled_reason),
             "DISCOVERY_STATE_ALLOCATION_FAILED");
    return s;
  }
  const char *refusal = dht_service_identity_refusal(s, p);
  if (refusal) {
    snprintf(s->disabled_reason, sizeof(s->disabled_reason), "%s", refusal);
    return s;
  }
  if (!dht_service_delegation_verified(s, p))
    return s;
  if (s->authority_verify &&
      !s->authority_verify(s->authority_ctx, &s->delegation)) {
    snprintf(s->disabled_reason, sizeof(s->disabled_reason),
             "DELEGATION_CHAIN_INVALID");
    vcs_zcode_dht_service_set_error(s,
                                    "local delegation chain check failed");
    return s;
  }
  if (!vcs_zcode_dht_delegation_node_id(s->self_id, &s->delegation) ||
      !vcs_zcode_dht_table_init(s->table, s->self_id)) {
    snprintf(s->disabled_reason, sizeof(s->disabled_reason),
             "NODE_ID_INVALID");
    vcs_zcode_dht_service_set_error(s, "local node ID derivation failed");
    return s;
  }
  s->enabled = true;
  (void)vcs_zcode_dht_service_persistence_load(s, p->now.wall_unix);
  dht_service_load_records_and_policy(s, p);
  (void)vcs_zcode_dht_publications_load(s, p->now.wall_unix);
  return s;
}

void vcs_zcode_dht_service_free(struct vcs_zcode_dht_service *s,
                                struct vcs_zcode_dht_time now) {
  (void)now;
  if (!s)
    return;
  if (s->enabled && s->persistence_dirty)
    (void)vcs_zcode_dht_service_persistence_save(s);
  memory_cleanse(s->online_seed, 32);
  vcs_zcode_dht_record_store_free(s->record_store);
  vcs_zcode_sovereignty_policy_free(s->owned_policy);
  free(s->table);
  free(s);
}

bool vcs_zcode_dht_service_enabled(const struct vcs_zcode_dht_service *s) {
  return s && s->enabled;
}

/* Per-frame state shared by the handle_frame steps. Each step keeps the
 * original check order and returns at the same point the inline code did. */
struct handle_frame_ctx {
  struct vcs_zcode_dht_service *s;
  struct service_peer *p;
  uint64_t peer_id;
  struct vcs_zcode_dht_time now;
  enum vcs_zcode_dht_reject_reason *rejected_out;
  struct vcs_zcode_dht_msg *m;
  const uint8_t *qid;
  const struct vcs_zcode_dht_delegation *d;
  bool request;
  struct service_query *q;
  struct replay_entry *ledger;
  struct replay_admission admission;
};

static struct service_peer *
frame_ready_peer(struct vcs_zcode_dht_service *s, uint64_t peer_id,
                 enum vcs_zcode_dht_reject_reason *rejected_out) {
  struct service_peer *p = peer_find(s, peer_id);
  if (!p || !p->connected || !p->session.established) {
    reject(s, VCS_ZCODE_DHT_REJECT_PLAINTEXT, rejected_out);
    return NULL;
  }
  return p;
}

static bool frame_parse(struct handle_frame_ctx *f, const uint8_t *wire,
                        size_t len) {
  struct vcs_zcode_dht_msg_verify_context v = {
      .noise_established = true,
      .session_generation = f->p->session.generation,
      .now_unix = f->now.wall_unix,
      .transport_verify = f->s->transport_verify,
      .transport_ctx = f->s->transport_ctx,
      .authority_verify = f->s->authority_verify,
      .authority_ctx = f->s->authority_ctx};
  memcpy(v.noise_transcript_hash, f->p->session.transcript_hash, 32);
  memcpy(v.remote_noise_static, f->p->session.remote_static, 32);
  memcpy(v.network_genesis, f->s->genesis, 32);
  enum vcs_zcode_dht_error e = vcs_zcode_dht_msg_parse(wire, len, &v, f->m);
  if (e != VCS_ZCODE_DHT_OK) {
    reject(f->s, map_parse_error(e), f->rejected_out);
    return false;
  }
  return true;
}

/* A response must answer a live query we sent to this peer. Requests skip
 * this check and leave f->q NULL. */
static bool frame_match_query(struct handle_frame_ctx *f) {
  struct vcs_zcode_dht_service *s = f->s;
  if (f->request)
    return true;
  f->q = query_find(s, f->peer_id, f->qid);
  if (!f->q) {
    enum vcs_zcode_dht_reject_reason reason = VCS_ZCODE_DHT_REJECT_UNSOLICITED;
    if (query_was_expired(s, f->peer_id, vcs_zcode_dht_message_generation(f->m),
                          f->qid, f->now.monotonic_s))
      reason = VCS_ZCODE_DHT_REJECT_EXPIRED;
    else if (replay_seen(f->p->response_replay, f->qid, f->now.monotonic_s))
      reason = VCS_ZCODE_DHT_REJECT_REPLAY;
    reject(s, reason, f->rejected_out);
    return false;
  }
  if (f->q->deadline_mono <= f->now.monotonic_s) {
    query_expire(s, f->q, f->now);
    reject(s, VCS_ZCODE_DHT_REJECT_EXPIRED, f->rejected_out);
    return false;
  }
  if (!vcs_zcode_dht_response_matches_query(f->m->kind, f->q->kind)) {
    reject(s, VCS_ZCODE_DHT_REJECT_UNSOLICITED, f->rejected_out);
    return false;
  }
  return true;
}

static bool frame_admit_replay(struct handle_frame_ctx *f) {
  f->ledger = f->request ? f->p->request_replay : f->p->response_replay;
  if (!replay_accept(f->ledger, f->qid, f->now.monotonic_s, &f->admission)) {
    reject(f->s, VCS_ZCODE_DHT_REJECT_REPLAY, f->rejected_out);
    return false;
  }
  if (f->request && !rate_accept(f->p, f->now.monotonic_s)) {
    reject(f->s, VCS_ZCODE_DHT_REJECT_RATE, f->rejected_out);
    return false;
  }
  return true;
}

/* Admits the sender into the routing table and marks it authenticated. */
static bool frame_learn_sender(struct handle_frame_ctx *f) {
  struct vcs_zcode_dht_service *s = f->s;
  struct vcs_zcode_dht_contact c;
  if (!vcs_zcode_dht_contact_from_delegation(&c, f->d,
                                             (int64_t)f->now.wall_unix, 0)) {
    reject(s, VCS_ZCODE_DHT_REJECT_DELEGATION, f->rejected_out);
    return false;
  }
  enum vcs_zcode_dht_add_result ar = vcs_zcode_dht_table_add_contact(
      s->table, &c, (int64_t)f->now.monotonic_s);
  if (ar == VCS_ZCODE_DHT_ADD_REJECTED_PENDING_CAP) {
    /* The replacement-probe ledger belongs to this node. Its saturation
     * says nothing about a cryptographically valid sender, and the sender
     * must be able to retry once local capacity returns. */
    replay_restore(f->ledger, &f->admission);
    reject(s, VCS_ZCODE_DHT_REJECT_BACKPRESSURE, f->rejected_out);
    return false;
  }
  if (ar >= VCS_ZCODE_DHT_ADD_REJECTED_SELF &&
      ar != VCS_ZCODE_DHT_ADD_REJECTED_PENDING) {
    reject(s, VCS_ZCODE_DHT_REJECT_IDENTITY, f->rejected_out);
    return false;
  }
  f->p->authenticated = true;
  memcpy(f->p->node_id, c.node_id, 32);
  f->p->contact = c;
  if (!vcs_zcode_dht_service_retain_unique_node_session(s, f->p, f->now)) {
    reject(s, VCS_ZCODE_DHT_REJECT_SESSION, f->rejected_out);
    return false;
  }
  mark_dirty(s, f->now.monotonic_s);
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++) {
    struct service_lookup *l = &s->lookups[i];
    if (l->used && !l->completed)
      (void)vcs_zcode_dht_lookup_insert(
          l, c.node_id, VCS_ZCODE_DHT_CANDIDATE_AUTHENTICATED, f->peer_id);
  }
  return true;
}

static void lookup_note_progress(struct vcs_zcode_dht_service *s,
                                 struct service_lookup *l,
                                 const uint8_t id[32], bool had_previous,
                                 const uint8_t previous[32]) {
  if (had_previous && l->candidate_count > 0 &&
      memcmp(l->candidates[0].node_id, id, 32) == 0 &&
      vcs_zcode_dht_lookup_closer_id(id, previous, l->target)) {
    l->xor_progress++;
    s->lookup_xor_progress++;
  }
}

static void lookup_request_reachability(struct vcs_zcode_dht_service *s,
                                        struct service_lookup *l, int at,
                                        const uint8_t id[32],
                                        struct vcs_zcode_dht_time now) {
  if (!s->request_reachability ||
      !s->request_reachability(s->reachability_ctx, id, now.wall_unix)) {
    l->candidates[at].state = VCS_ZCODE_DHT_CANDIDATE_UNREACHABLE;
  } else {
    l->candidates[at].reachability_deadline_mono =
        now.monotonic_s + VCS_ZCODE_DHT_SERVICE_REACHABILITY_TIMEOUT_S;
  }
}

static void lookup_observe_candidate(struct vcs_zcode_dht_service *s,
                                     struct service_lookup *l,
                                     const uint8_t id[32],
                                     struct vcs_zcode_dht_time now) {
  uint8_t previous[32];
  bool had_previous = l->candidate_count > 0;
  if (had_previous)
    memcpy(previous, l->candidates[0].node_id, 32);
  struct service_peer *known = vcs_zcode_dht_lookup_peer_for_node(s, id);
  enum vcs_zcode_dht_candidate_state state =
      (memcmp(id, s->self_id, 32) == 0 || known)
          ? VCS_ZCODE_DHT_CANDIDATE_AUTHENTICATED
          : VCS_ZCODE_DHT_CANDIDATE_UNVERIFIED;
  (void)vcs_zcode_dht_lookup_insert(l, id, state,
                                    known ? known->peer_id : 0);
  lookup_note_progress(s, l, id, had_previous, previous);
  int at = vcs_zcode_dht_lookup_candidate_index(l, id);
  if (at >= 0 &&
      l->candidates[at].state == VCS_ZCODE_DHT_CANDIDATE_UNVERIFIED &&
      !l->candidates[at].reachability_deadline_mono)
    lookup_request_reachability(s, l, at, id, now);
}

/* A NODES response feeds the lookup it answers, then closes the query. */
static void frame_absorb_nodes(struct handle_frame_ctx *f) {
  struct vcs_zcode_dht_service *s = f->s;
  if (f->q->kind == QUERY_LOOKUP) {
    struct service_lookup *l = vcs_zcode_dht_lookup_find(s, f->q->lookup_id);
    if (l) {
      for (uint32_t i = 0; i < f->m->nodes.contact_count; i++)
        lookup_observe_candidate(s, l, f->m->nodes.node_ids[i], f->now);
    }
  }
  vcs_zcode_dht_service_query_finish(s, f->q, QUERY_OUTCOME_RESPONSE, f->now);
}

static bool frame_handle_records(struct handle_frame_ctx *f) {
  struct vcs_zcode_dht_service *s = f->s;
  struct service_peer *p = f->p;
  /* Every request record frame requires exactly one local reply. Refuse
   * before mutating STORE state when our egress is already full. The
   * per-peer STORE quota remains a peer CAP; capacity after that explicit
   * check is local storage/serialization state and therefore backpressure. */
  if (f->request && s->outbound_count >= VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND) {
    replay_restore(f->ledger, &f->admission);
    reject(s, VCS_ZCODE_DHT_REJECT_BACKPRESSURE, f->rejected_out);
    return false;
  }
  bool peer_store_cap =
      f->m->kind == VCS_ZCODE_DHT_MSG_STORE_RECORD &&
      p->record_admissions >= VCS_ZCODE_DHT_SERVICE_MAX_RECORDS_PER_PEER;
  enum vcs_zcode_dht_reject_reason record_rejected = VCS_ZCODE_DHT_REJECT_CAP;
  if (!vcs_zcode_dht_service_records_handle(s, p, f->q, f->m, f->now,
                                            &record_rejected)) {
    if (record_rejected == VCS_ZCODE_DHT_REJECT_CAP && !peer_store_cap) {
      record_rejected = VCS_ZCODE_DHT_REJECT_BACKPRESSURE;
      if (f->m->kind == VCS_ZCODE_DHT_MSG_STORE_RECORD &&
          p->record_admissions > 0)
        p->record_admissions--;
    }
    if (record_rejected == VCS_ZCODE_DHT_REJECT_BACKPRESSURE)
      replay_restore(f->ledger, &f->admission);
    reject(s, record_rejected, f->rejected_out);
    return false;
  }
  if (!f->request)
    vcs_zcode_dht_service_query_finish(s, f->q, QUERY_OUTCOME_RESPONSE,
                                       f->now);
  return true;
}

static bool frame_dispatch(struct handle_frame_ctx *f) {
  if (f->m->kind == VCS_ZCODE_DHT_MSG_FIND_NODE) {
    f->s->find_received++;
    if (!reply_nodes(f->s, f->p, f->qid, f->m->find_node.target_node_id,
                     f->now.wall_unix, f->rejected_out)) {
      replay_restore(f->ledger, &f->admission);
      return false;
    }
    return true;
  }
  if (f->m->kind == VCS_ZCODE_DHT_MSG_NODES) {
    f->s->nodes_received++;
    frame_absorb_nodes(f);
    return true;
  }
  return frame_handle_records(f);
}

bool vcs_zcode_dht_service_handle_frame(
    struct vcs_zcode_dht_service *s, uint64_t peer_id, const uint8_t *wire,
    size_t len, struct vcs_zcode_dht_time now,
    enum vcs_zcode_dht_reject_reason *rejected_out) {
  if (!s || !s->enabled || !wire)
    return false;
  struct handle_frame_ctx f = {.s = s,
                               .peer_id = peer_id,
                               .now = now,
                               .rejected_out = rejected_out};
  struct vcs_zcode_dht_msg m;
  f.m = &m;
  f.p = frame_ready_peer(s, peer_id, rejected_out);
  if (!f.p)
    return false;
  if (!frame_parse(&f, wire, len))
    return false;
  f.qid = vcs_zcode_dht_message_query_id(&m);
  f.d = vcs_zcode_dht_message_delegation(&m);
  f.request = vcs_zcode_dht_message_is_request(m.kind);
  if (!f.qid || !f.d) {
    reject(s, VCS_ZCODE_DHT_REJECT_MALFORMED, rejected_out);
    return false;
  }
  if (!frame_match_query(&f))
    return false;
  if (!frame_admit_replay(&f))
    return false;
  if (!frame_learn_sender(&f))
    return false;
  if (!frame_dispatch(&f))
    return false;
  s->frames_accepted++;
  return true;
}

bool vcs_zcode_dht_service_next_outbound(struct vcs_zcode_dht_service *s,
                                         uint64_t filter, uint64_t *peer_out,
                                         uint8_t *wire, size_t cap,
                                         size_t *len_out) {
  if (!s || !peer_out || !wire || !len_out)
    return false;
  if (!s->enabled)
    return false;
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND; i++) {
    struct service_outbound *o = &s->outbound[i];
    if (!o->used || (filter && o->peer_id != filter))
      continue;
    if (cap < o->len)
      return false;
    *peer_out = o->peer_id;
    *len_out = o->len;
    memcpy(wire, o->wire, o->len);
    memset(o, 0, sizeof(*o));
    s->outbound_count--;
    return true;
  }
  return false;
}

static bool pending_candidate_valid(struct vcs_zcode_dht_service *s,
                                    const struct vcs_zcode_dht_pending *p,
                                    uint64_t wall_now) {
  struct vcs_zcode_dht_delegation d;
  return p && p->active &&
         vcs_zcode_dht_delegation_decode(
             &d, p->candidate.delegation_wire,
             sizeof(p->candidate.delegation_wire)) ==
             VCS_ZCODE_DHT_DELEGATION_OK &&
         vcs_zcode_dht_delegation_verify(&d, s->genesis, NULL, 0, NULL,
                                         wall_now) ==
             VCS_ZCODE_DHT_DELEGATION_OK &&
         (!s->transport_verify || s->transport_verify(s->transport_ctx, &d));
}

static void tick_expire_queries(struct vcs_zcode_dht_service *s,
                                struct vcs_zcode_dht_time now) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
    if (s->queries[i].used && s->queries[i].deadline_mono <= now.monotonic_s)
      query_expire(s, &s->queries[i], now);
}

static void tick_forget_old_expired(struct vcs_zcode_dht_service *s,
                                    uint64_t now_mono) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER; i++)
    if (s->expired[i].used &&
        now_mono - s->expired[i].expired_at_mono >
            VCS_ZCODE_DHT_SERVICE_REPLAY_SECONDS)
      memset(&s->expired[i], 0, sizeof(s->expired[i]));
}

static void tick_lookup(struct vcs_zcode_dht_service *s,
                        struct service_lookup *l,
                        struct vcs_zcode_dht_time now) {
  for (uint32_t c = 0; c < l->candidate_count; c++)
    if (l->candidates[c].state == VCS_ZCODE_DHT_CANDIDATE_UNVERIFIED &&
        l->candidates[c].reachability_deadline_mono != 0 &&
        l->candidates[c].reachability_deadline_mono <= now.monotonic_s)
      l->candidates[c].state = VCS_ZCODE_DHT_CANDIDATE_UNREACHABLE;
  vcs_zcode_dht_lookup_assess(s, l);
  if (!l->completed && l->deadline_mono <= now.monotonic_s)
    vcs_zcode_dht_lookup_terminate(s, l, VCS_ZCODE_DHT_TERMINATION_TIMEOUT);
}

static void tick_lookups(struct vcs_zcode_dht_service *s,
                         struct vcs_zcode_dht_time now) {
  for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++)
    if (s->lookups[i].used && !s->lookups[i].completed)
      tick_lookup(s, &s->lookups[i], now);
}

static void tick_expire_pending_one(struct vcs_zcode_dht_service *s,
                                    struct vcs_zcode_dht_pending *p,
                                    struct vcs_zcode_dht_time now) {
  uint8_t victim[32];
  memcpy(victim, p->victim_node_id, 32);
  if (p->state == VCS_ZCODE_DHT_PROBE_WAITING) {
    (void)vcs_zcode_dht_table_probe_discard(
        s->table, victim, VCS_ZCODE_DHT_PROBE_EXPIRED);
  } else if (p->state == VCS_ZCODE_DHT_PROBE_IN_FLIGHT) {
    bool valid = pending_candidate_valid(s, p, now.wall_unix);
    if (valid)
      (void)vcs_zcode_dht_table_probe_complete(
          s->table, victim, VCS_ZCODE_DHT_PROBE_EXPIRED, true,
          (int64_t)now.wall_unix);
    else
      (void)vcs_zcode_dht_table_probe_discard(
          s->table, victim, VCS_ZCODE_DHT_PROBE_EXPIRED);
  }
}

/* Returns how many pending probes reached their deadline. */
static size_t tick_expire_pending(struct vcs_zcode_dht_service *s,
                                  struct vcs_zcode_dht_time now) {
  size_t expired = 0;
  for (size_t i = 0; i < VCS_ZCODE_DHT_MAX_PENDING; i++) {
    struct vcs_zcode_dht_pending *p = &s->table->pending[i];
    if (!p->active || p->deadline_mono > (int64_t)now.monotonic_s)
      continue;
    tick_expire_pending_one(s, p, now);
    expired++;
  }
  return expired;
}

static bool tick_probe_in_flight(const struct vcs_zcode_dht_service *s,
                                 const uint8_t victim[32]) {
  for (size_t q = 0; q < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; q++)
    if (s->queries[q].used && memcmp(s->queries[q].victim, victim, 32) == 0)
      return true;
  return false;
}

/* Sends a probe through the first authenticated, connected peer whose node
 * ID is the victim. Only the first matching peer is tried. */
static void tick_start_probe(struct vcs_zcode_dht_service *s,
                             const uint8_t victim[32],
                             struct vcs_zcode_dht_time now) {
  if (tick_probe_in_flight(s, victim))
    return;
  for (size_t p = 0; p < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; p++)
    if (s->peers[p].used && s->peers[p].connected &&
        s->peers[p].authenticated &&
        memcmp(s->peers[p].node_id, victim, 32) == 0) {
      if (vcs_zcode_dht_service_send_find(s, &s->peers[p], QUERY_PROBE, 0,
                                          s->self_id, victim,
                                          now.monotonic_s))
        (void)vcs_zcode_dht_table_probe_started(s->table, victim,
                                                (int64_t)now.monotonic_s);
      break;
    }
}

static void tick_start_probes(struct vcs_zcode_dht_service *s,
                              struct vcs_zcode_dht_time now) {
  for (size_t i = 0;
       i < VCS_ZCODE_DHT_MAX_PENDING &&
       query_count(s) < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES;
       i++)
    if (s->table->pending[i].active &&
        s->table->pending[i].state == VCS_ZCODE_DHT_PROBE_WAITING)
      tick_start_probe(s, s->table->pending[i].victim_node_id, now);
}

void vcs_zcode_dht_service_tick(struct vcs_zcode_dht_service *s,
                                struct vcs_zcode_dht_time now) {
  if (!s || !s->enabled)
    return;
  vcs_zcode_dht_service_expire_unauthenticated(s, now);
  tick_expire_queries(s, now);
  vcs_zcode_dht_records_sweep(s, now.monotonic_s);
  vcs_zcode_dht_records_collect_expired(s, now);
  tick_forget_old_expired(s, now.monotonic_s);
  tick_lookups(s, now);
  if (tick_expire_pending(s, now))
    mark_dirty(s, now.monotonic_s);
  vcs_zcode_dht_lookup_schedule(s, now);
  tick_start_probes(s, now);
  vcs_zcode_dht_service_publication_schedule(s, now);
}
