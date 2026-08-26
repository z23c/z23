/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Private fixed-size state shared by the ZCODE DHT service units. */

#ifndef ZCL_VCS_ZCODE_DHT_SERVICE_INTERNAL_H
#define ZCL_VCS_ZCODE_DHT_SERVICE_INTERNAL_H

#include "vcs/zcode_dht_service.h"

enum query_kind {
  QUERY_BOOTSTRAP = 0,
  QUERY_LOOKUP,
  QUERY_PROBE,
  QUERY_RECORD_LOOKUP,
  QUERY_RECORD_STORE
};
enum query_outcome {
  QUERY_OUTCOME_RESPONSE = 0,
  QUERY_OUTCOME_FAILED,
  QUERY_OUTCOME_EXPIRED
};

struct replay_entry {
  bool used;
  uint8_t id[16];
  uint64_t seen_mono;
};

struct service_peer {
  bool used, connected, authenticated;
  uint64_t peer_id;
  struct vcs_zcode_dht_session session;
  uint8_t node_id[32];
  struct vcs_zcode_dht_contact contact;
  uint8_t rate_tokens;
  uint64_t rate_refill_mono;
  uint64_t opened_mono;
  struct replay_entry request_replay[VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER];
  struct replay_entry response_replay[VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER];
  uint32_t record_admissions;
};

struct retired_session {
  bool used;
  uint64_t peer_id, generation, connection_serial, retired_mono;
};

struct service_query {
  bool used;
  enum query_kind kind;
  uint8_t id[16], target[32], victim[32];
  uint64_t peer_id, generation, deadline_mono, lookup_id;
  uint64_t record_operation_id;
  struct vcs_zcode_dht_record_selector record_selector;
  uint8_t record_page_offset;
  uint8_t record_digest[32];
};

struct expired_query {
  bool used;
  uint8_t id[16];
  uint64_t peer_id, generation, expired_at_mono;
};

struct lookup_candidate {
  bool used;
  uint8_t node_id[32];
  enum vcs_zcode_dht_candidate_state state;
  uint64_t peer_id, reachability_deadline_mono;
};

struct service_lookup {
  bool used, completed;
  uint64_t id, started_mono, deadline_mono, first_query_mono;
  uint8_t target[32];
  /* The candidate pool is the durable lookup working set.  It is kept in
   * deterministic XOR order; only its closest k entries form the active
   * frontier.  Keeping the wider pool means frontier churn never loses an
   * in-flight query or a closer ID arriving later in the same NODES burst. */
  struct lookup_candidate
      candidates[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES];
  uint32_t candidate_count, queries_sent, queries_pending, rounds;
  uint32_t xor_progress;
  enum vcs_zcode_dht_lookup_termination termination;
};

struct service_outbound {
  bool used;
  uint64_t peer_id;
  size_t len;
  uint8_t wire[VCS_ZCODE_DHT_MAX_FRAME_BYTES];
};

enum service_record_operation_kind {
  SERVICE_RECORD_LOOKUP = 0,
  SERVICE_RECORD_STORE
};

struct service_record_operation {
  bool used;
  enum service_record_operation_kind kind;
  uint64_t id;
  /* Monotonic stamp of the transition out of PENDING. State, not zero, says
   * whether this field is live: a result produced during monotonic second
   * zero still expires under the public retention contract. */
  uint64_t terminal_mono;
  enum vcs_zcode_dht_record_operation_state state;
  enum vcs_zcode_dht_store_status store_status;
  struct vcs_zcode_dht_record_selector selector;
  uint8_t page_offset, next_offset;
  uint32_t record_count;
  struct vcs_zcode_dht_record records[VCS_ZCODE_DHT_RECORDS_PER_FRAME];
};

enum service_publication_phase {
  SERVICE_PUBLICATION_NEEDS_LOOKUP = 0,
  SERVICE_PUBLICATION_ROUTING,
  SERVICE_PUBLICATION_STORING,
  SERVICE_PUBLICATION_WAITING
};

struct service_publication {
  bool used, possession_current;
  bool renewal_proof_required, renewal_proof_ready;
  uint64_t possession_proof_epoch;
  enum service_publication_phase phase;
  struct vcs_zcode_dht_record record;
  uint64_t lifetime_s, lookup_id, next_attempt_mono, backoff_s;
  uint8_t node_ids[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES][32];
  uint64_t child_operation_ids[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES];
  bool node_complete[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES];
  bool node_succeeded[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES];
  uint32_t node_count, active_children, attempts, successes;
};

enum service_record_discovery_phase {
  SERVICE_RECORD_DISCOVERY_ROUTING = 0,
  SERVICE_RECORD_DISCOVERY_QUERYING
};

struct service_record_discovery {
  bool used, truncated, incomplete;
  uint64_t id, lookup_id, deadline_mono;
  enum vcs_zcode_dht_record_operation_state state;
  enum service_record_discovery_phase phase;
  struct vcs_zcode_dht_record_selector selector;
  uint32_t routing_rounds, xor_progress;
  uint32_t node_count, next_node, active_children, nodes_queried;
  uint32_t target_successes, successful_nodes, failed_nodes;
  uint8_t node_ids[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES][32];
  uint64_t child_operation_ids[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES];
  uint8_t node_page_offsets[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES];
  bool node_complete[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES];
  bool node_succeeded[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES];
  uint32_t record_count;
  struct vcs_zcode_dht_record
      records[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
};

struct vcs_zcode_dht_service {
  bool enabled;
  char disabled_reason[96], last_error[160], datadir[1024];
  uint8_t genesis[32], self_id[32], online_seed[32], local_noise_static[32];
  struct vcs_zcode_dht_delegation delegation;
  vcs_zcode_dht_chain_verify_fn chain_verify;
  void *chain_ctx;
  vcs_zcode_dht_reachability_fn request_reachability;
  void *reachability_ctx;
  vcs_zcode_sovereignty_decide_fn policy_decide;
  void *policy_ctx;
  struct vcs_zcode_sovereignty_policy *owned_policy;
  struct vcs_zcode_dht_table *table;
  struct service_peer peers[VCS_ZCODE_DHT_SERVICE_MAX_PEERS];
  struct retired_session retired[VCS_ZCODE_DHT_SERVICE_MAX_PEERS];
  struct service_query queries[VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES];
  struct expired_query expired[VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER];
  struct service_lookup lookups[VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS];
  struct service_outbound outbound[VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND];
  struct service_record_operation
      record_operations[VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS];
  struct service_publication
      publications[VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS];
  struct service_record_discovery
      discoveries[VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS];
  struct vcs_zcode_dht_record_store *record_store;
  uint32_t outbound_count;
  uint64_t serial, next_lookup_id, next_record_operation_id;
  uint64_t next_possession_proof_epoch;
  uint64_t next_record_discovery_id;
  bool records_dirty;
  bool publication_intents_dirty;
  bool persistence_loaded, persistence_dirty;
  uint64_t dirty_since_mono, persistence_generation;
  uint64_t persistence_load_count, persistence_save_count;
  uint64_t frames_accepted, rejected[VCS_ZCODE_DHT_REJECT_COUNT];
  uint64_t find_received, nodes_received, find_sent, nodes_sent;
  uint64_t find_record_received, records_received;
  uint64_t store_record_received, store_result_received;
  uint64_t find_record_sent, records_sent;
  uint64_t store_record_sent, store_result_sent;
  uint64_t unauthenticated_expired, duplicate_sessions_retired;
  uint64_t lookup_rounds, lookup_xor_progress, lookup_queue_wait_s;
  uint64_t lookup_terminations[VCS_ZCODE_DHT_TERMINATION_COUNT];
  uint32_t scheduler_cursor;
};

void vcs_zcode_dht_service_set_error(struct vcs_zcode_dht_service *service,
                                     const char *message);
bool vcs_zcode_dht_service_persistence_load(
    struct vcs_zcode_dht_service *service, uint64_t now_unix);
bool vcs_zcode_dht_service_persistence_save(
    struct vcs_zcode_dht_service *service);

/* Cross-unit lookup helpers.  These stay private to lib/vcs even though the
 * service and iterative scheduler are split to honor the file-size ceiling. */
struct service_lookup *vcs_zcode_dht_lookup_find(
    struct vcs_zcode_dht_service *service, uint64_t id);
bool vcs_zcode_dht_lookup_closer_id(const uint8_t a[32], const uint8_t b[32],
                                    const uint8_t target[32]);
int vcs_zcode_dht_lookup_candidate_index(const struct service_lookup *lookup,
                                         const uint8_t node_id[32]);
bool vcs_zcode_dht_lookup_candidate_authenticated(
    enum vcs_zcode_dht_candidate_state state);
uint32_t
vcs_zcode_dht_lookup_frontier_count(const struct service_lookup *lookup);
bool vcs_zcode_dht_lookup_candidate_in_frontier(
    const struct service_lookup *lookup, uint32_t candidate_index);
struct service_peer *vcs_zcode_dht_lookup_peer_for_node(
    struct vcs_zcode_dht_service *service, const uint8_t node_id[32]);
bool vcs_zcode_dht_lookup_insert(
    struct service_lookup *lookup, const uint8_t node_id[32],
    enum vcs_zcode_dht_candidate_state state, uint64_t peer_id);
void vcs_zcode_dht_lookup_terminate(
    struct vcs_zcode_dht_service *service, struct service_lookup *lookup,
    enum vcs_zcode_dht_lookup_termination termination);
void vcs_zcode_dht_lookup_assess(struct vcs_zcode_dht_service *service,
                                 struct service_lookup *lookup);
void vcs_zcode_dht_lookup_schedule(struct vcs_zcode_dht_service *service,
                                   struct vcs_zcode_dht_time now);
bool vcs_zcode_dht_service_send_find(
    struct vcs_zcode_dht_service *service, struct service_peer *peer,
    enum query_kind kind, uint64_t lookup_id, const uint8_t target[32],
    const uint8_t victim[32], uint64_t now_mono);
void vcs_zcode_dht_service_query_finish(
    struct vcs_zcode_dht_service *service, struct service_query *query,
    enum query_outcome outcome, struct vcs_zcode_dht_time now);
bool vcs_zcode_dht_service_retain_unique_node_session(
    struct vcs_zcode_dht_service *service, struct service_peer *current,
    struct vcs_zcode_dht_time now);
void vcs_zcode_dht_service_expire_unauthenticated(
    struct vcs_zcode_dht_service *service, struct vcs_zcode_dht_time now);
bool vcs_zcode_dht_service_records_handle(
    struct vcs_zcode_dht_service *service, struct service_peer *peer,
    struct service_query *query, const struct vcs_zcode_dht_msg *message,
    struct vcs_zcode_dht_time now,
    enum vcs_zcode_dht_reject_reason *rejected_out);
void vcs_zcode_dht_service_record_query_finish(
    struct vcs_zcode_dht_service *service, const struct service_query *query,
    enum query_outcome outcome, struct vcs_zcode_dht_time now);
void vcs_zcode_dht_service_publication_schedule(
    struct vcs_zcode_dht_service *service, struct vcs_zcode_dht_time now);
bool vcs_zcode_dht_publications_load(struct vcs_zcode_dht_service *service,
                                     uint64_t now_unix);
bool vcs_zcode_dht_publications_save(
    const char *datadir, const struct service_publication *publications,
    char *error_out, size_t error_capacity);

/* Publication retry policy and the pieces the plan/commit unit and the
 * drive state machine (zcode_dht_service_publication_drive.c) share. */
#define PUBLICATION_RETRY_MIN_S 30u
#define PUBLICATION_RETRY_MAX_S 3600u
#define PUBLICATION_RENEW_FLOOR_S 60u
void publication_mark_dirty(struct vcs_zcode_dht_service *service,
                            uint64_t monotonic_s);
uint64_t publication_next_proof_epoch(
    struct vcs_zcode_dht_service *service);
uint64_t publication_renew_at(const struct service_publication *publication);
/* Cancel a slot's live lookup and child operations. A commit that supersedes
 * an existing same-stream slot MUST call this before overwriting it: ids
 * wiped from their owner's slot strand their entries until the tick sweeper
 * (or service restart) reclaims them. A no-op on a fresh slot. */
void publication_cancel_active(struct vcs_zcode_dht_service *service,
                               struct service_publication *publication);
void publication_drive(struct vcs_zcode_dht_service *service,
                       struct service_publication *publication,
                       struct vcs_zcode_dht_time now);
struct service_record_operation *vcs_zcode_dht_records_operation_find(
    struct vcs_zcode_dht_service *service, uint64_t id);
void vcs_zcode_dht_records_sweep(struct vcs_zcode_dht_service *service,
                                 uint64_t now_mono);
bool vcs_zcode_dht_message_is_request(enum vcs_zcode_dht_msg_kind kind);
const uint8_t *vcs_zcode_dht_message_query_id(
    const struct vcs_zcode_dht_msg *message);
const struct vcs_zcode_dht_delegation *vcs_zcode_dht_message_delegation(
    const struct vcs_zcode_dht_msg *message);
uint64_t vcs_zcode_dht_message_generation(
    const struct vcs_zcode_dht_msg *message);
bool vcs_zcode_dht_response_matches_query(
    enum vcs_zcode_dht_msg_kind message_kind, enum query_kind query_kind);
bool vcs_zcode_dht_records_policy_allows(
    const struct vcs_zcode_dht_service *service,
    enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_dht_record *record);
int vcs_zcode_dht_records_canonical_compare(const void *left,
                                             const void *right);

#endif /* ZCL_VCS_ZCODE_DHT_SERVICE_INTERNAL_H */
