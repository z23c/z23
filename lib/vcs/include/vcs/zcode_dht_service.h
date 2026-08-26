/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Bounded long-lived FIND_NODE/NODES service for the ZCODE DHT. */

#ifndef ZCL_VCS_ZCODE_DHT_SERVICE_H
#define ZCL_VCS_ZCODE_DHT_SERVICE_H

#include "vcs/zcode_dht_msgs.h"
#include "vcs/zcode_dht_record_store.h"
#include "vcs/zcode_sovereignty_policy.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_DHT_SERVICE_MAX_PEERS 64u
#define VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS 8u
#define VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES 3u
#define VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES 64u
#define VCS_ZCODE_DHT_SERVICE_MAX_CHAIN_DELEGATIONS \
  (VCS_ZCODE_DHT_MAX_CONTACTS + VCS_ZCODE_DHT_MAX_PENDING + 1u)
#define VCS_ZCODE_DHT_SERVICE_REPLAY_SECONDS 30u
#define VCS_ZCODE_DHT_SERVICE_RATE_PER_SECOND 4u
#define VCS_ZCODE_DHT_SERVICE_RATE_BURST 8u
/* One session can receive the rate-bounded FIND_NODE population plus one
 * bootstrap response, one response for each queued lookup, and one incumbent
 * probe response inside the same replay window. Keep all of them. */
#define VCS_ZCODE_DHT_SERVICE_REPLAY_PER_PEER                              \
  (VCS_ZCODE_DHT_SERVICE_RATE_BURST +                                     \
   VCS_ZCODE_DHT_SERVICE_RATE_PER_SECOND *                                \
       VCS_ZCODE_DHT_SERVICE_REPLAY_SECONDS +                             \
   VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS + 2u)
#define VCS_ZCODE_DHT_SERVICE_MAX_OUTBOUND 128u
#define VCS_ZCODE_DHT_SERVICE_MAX_RECORD_OPERATIONS 8u
/* How many records ONE node can keep announced at the same time. Eight is
 * four packages, because a package needs both a POINTER and a PROVIDER
 * record, and any package whose source is independently re-derivable needs
 * a third. `make commons-multihost-acceptance` measured the floor: the host
 * that ends up serving everything announces textstat, the accepted
 * application, that application's source, zprng, and the changed package —
 * eleven records for five things, on a journey with two small libraries and
 * two small applications. At eight the ninth publish was refused `global-cap`
 * and the journey could not finish, which is a node too small to host the
 * product's own demo. Sixteen is still a hard ceiling and still fails closed;
 * it is dimensioned so a node hosting a handful of packages is not one.
 *
 * The cost is fixed-size: this bounds an array of struct service_publication
 * in the service and one stack copy in the publication store loader, so it
 * cannot be raised freely. The on-disk store is count-prefixed and its length
 * is checked against that count, so a file written under the old ceiling
 * still loads unchanged. */
#define VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS 16u
#define VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS 64u
#define VCS_ZCODE_DHT_SERVICE_MAX_RECORDS_PER_PEER 256u
#define VCS_ZCODE_DHT_SERVICE_SAVE_DEBOUNCE_S 5u
#define VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S 5u
#define VCS_ZCODE_DHT_SERVICE_REACHABILITY_TIMEOUT_S 12u
#define VCS_ZCODE_DHT_SERVICE_UNAUTH_TIMEOUT_S 15u

/* Wall time is authority only: signed delegation windows and durable
 * last-success observations. Every timeout, rate bucket and replay window is
 * driven by monotonic_s so an NTP step cannot expire or resurrect work. */
struct vcs_zcode_dht_time {
  uint64_t wall_unix;
  uint64_t monotonic_s;
};

enum vcs_zcode_dht_candidate_state {
  VCS_ZCODE_DHT_CANDIDATE_UNVERIFIED = 0,
  VCS_ZCODE_DHT_CANDIDATE_UNREACHABLE,
  VCS_ZCODE_DHT_CANDIDATE_AUTHENTICATED,
  VCS_ZCODE_DHT_CANDIDATE_QUERIED,
  VCS_ZCODE_DHT_CANDIDATE_IN_FLIGHT,
  VCS_ZCODE_DHT_CANDIDATE_RESPONDED,
  VCS_ZCODE_DHT_CANDIDATE_FAILED,
  VCS_ZCODE_DHT_CANDIDATE_STATE_COUNT
};

enum vcs_zcode_dht_lookup_termination {
  VCS_ZCODE_DHT_TERMINATION_NONE = 0,
  VCS_ZCODE_DHT_TERMINATION_TARGET_AUTHENTICATED,
  VCS_ZCODE_DHT_TERMINATION_SHORTLIST_STABLE,
  VCS_ZCODE_DHT_TERMINATION_TIMEOUT,
  VCS_ZCODE_DHT_TERMINATION_NO_AUTHENTICATED_RESULT,
  VCS_ZCODE_DHT_TERMINATION_COUNT
};

typedef bool (*vcs_zcode_dht_reachability_fn)(void *ctx,
                                               const uint8_t node_id[32],
                                               uint64_t wall_unix);

enum vcs_zcode_dht_reject_reason {
  VCS_ZCODE_DHT_REJECT_MALFORMED = 0,
  VCS_ZCODE_DHT_REJECT_PLAINTEXT,
  VCS_ZCODE_DHT_REJECT_DELEGATION,
  VCS_ZCODE_DHT_REJECT_IDENTITY,
  VCS_ZCODE_DHT_REJECT_SIGNATURE,
  VCS_ZCODE_DHT_REJECT_SESSION,
  VCS_ZCODE_DHT_REJECT_REPLAY,
  VCS_ZCODE_DHT_REJECT_UNSOLICITED,
  VCS_ZCODE_DHT_REJECT_EXPIRED,
  VCS_ZCODE_DHT_REJECT_POISONED,
  VCS_ZCODE_DHT_REJECT_RATE,
  VCS_ZCODE_DHT_REJECT_CAP,
  VCS_ZCODE_DHT_REJECT_UNAUTHORIZED,
  VCS_ZCODE_DHT_REJECT_COUNT
};

const char *
vcs_zcode_dht_reject_reason_string(enum vcs_zcode_dht_reject_reason reason);

struct vcs_zcode_dht_session {
  bool established;
  uint8_t remote_static[32];
  uint8_t transcript_hash[32];
  uint64_t generation;
  uint64_t connection_serial;
};

struct vcs_zcode_dht_live_session {
  uint64_t peer_id;
  uint64_t generation;
  uint64_t connection_serial;
};

struct vcs_zcode_dht_service_params {
  const char *datadir;
  uint8_t network_genesis[32];
  uint8_t local_noise_static[32];
  bool transport_enabled;
  struct vcs_zcode_dht_time now;
  vcs_zcode_dht_chain_verify_fn chain_verify;
  void *chain_ctx;
  vcs_zcode_dht_reachability_fn request_reachability;
  void *reachability_ctx;
  vcs_zcode_sovereignty_decide_fn policy_decide;
  void *policy_ctx;
};

struct vcs_zcode_dht_service;
struct vcs_package_store;

struct vcs_zcode_dht_service_status {
  bool enabled;
  uint8_t local_node_id[32];
  uint32_t contacts;
  uint32_t buckets_used;
  uint32_t connected_authenticated;
  uint32_t cold_contacts;
  uint32_t pending_probes;
  uint64_t probe_transitions[VCS_ZCODE_DHT_PROBE_STATE_COUNT];
  uint64_t unauthenticated_expired;
  uint64_t duplicate_sessions_retired;
  uint32_t active_queries;
  uint32_t queued_lookups;
  uint32_t outbound_queued;
  uint64_t frames_accepted;
  uint64_t frames_rejected[VCS_ZCODE_DHT_REJECT_COUNT];
  uint64_t find_node_received;
  uint64_t nodes_received;
  uint64_t find_node_sent;
  uint64_t nodes_sent;
  uint64_t find_record_received;
  uint64_t records_received;
  uint64_t store_record_received;
  uint64_t store_result_received;
  uint64_t find_record_sent;
  uint64_t records_sent;
  uint64_t store_record_sent;
  uint64_t store_result_sent;
  uint32_t signed_records;
  uint32_t active_record_operations;
  uint32_t publication_intents;
  uint32_t active_publications;
  uint64_t lookup_rounds;
  uint64_t lookup_xor_progress;
  uint64_t lookup_queue_wait_s;
  uint64_t lookup_shortlist_states[VCS_ZCODE_DHT_CANDIDATE_STATE_COUNT];
  uint64_t lookup_terminations[VCS_ZCODE_DHT_TERMINATION_COUNT];
  bool persistence_loaded;
  bool persistence_dirty;
  uint64_t persistence_load_count;
  uint64_t persistence_save_count;
  char disabled_reason[96];
  char last_error[160];
};

struct vcs_zcode_dht_provider_route {
  uint64_t peer_ids[VCS_ZCODE_DHT_K];
  uint32_t authenticated_count;
  uint32_t reachability_pending;
  uint32_t policy_denied;
};

struct vcs_zcode_dht_peer_view {
  uint64_t peer_id;
  uint8_t node_id[32];
  int bucket;
  bool connected;
  bool authenticated;
  bool cold;
  bool probing;
  uint64_t last_seen_age_s;
  uint32_t failures;
  uint64_t delegation_expiry;
  uint32_t beacon_height;
};

enum vcs_zcode_dht_lookup_state {
  VCS_ZCODE_DHT_LOOKUP_PENDING = 0,
  VCS_ZCODE_DHT_LOOKUP_COMPLETE,
  VCS_ZCODE_DHT_LOOKUP_TIMEOUT,
  VCS_ZCODE_DHT_LOOKUP_NOT_FOUND,
};

struct vcs_zcode_dht_lookup_result {
  enum vcs_zcode_dht_lookup_state state;
  enum vcs_zcode_dht_lookup_termination termination;
  uint32_t rounds;
  uint32_t xor_progress;
  uint64_t queue_wait_s;
  uint32_t count;
  uint8_t node_ids[VCS_ZCODE_DHT_K][32];
};

enum vcs_zcode_dht_record_operation_state {
  VCS_ZCODE_DHT_RECORD_OPERATION_PENDING = 0,
  VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE,
  VCS_ZCODE_DHT_RECORD_OPERATION_TIMEOUT,
  VCS_ZCODE_DHT_RECORD_OPERATION_REJECTED,
};

struct vcs_zcode_dht_record_operation_result {
  enum vcs_zcode_dht_record_operation_state state;
  enum vcs_zcode_dht_store_status store_status;
  uint8_t page_offset;
  uint8_t next_offset;
  uint32_t record_count;
  struct vcs_zcode_dht_record records[VCS_ZCODE_DHT_RECORDS_PER_FRAME];
};

struct vcs_zcode_dht_record_discovery_result {
  enum vcs_zcode_dht_record_operation_state state;
  bool truncated;
  /* At least one routed responsible-node/page query could not complete.
   * Records remain useful partial evidence, never complete coverage. */
  bool incomplete;
  uint32_t routing_rounds;
  uint32_t xor_progress;
  uint32_t nodes_queried;
  uint32_t record_count;
  struct vcs_zcode_dht_record
      records[VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS];
};

struct vcs_zcode_dht_service *
vcs_zcode_dht_service_create(const struct vcs_zcode_dht_service_params *params);
void vcs_zcode_dht_service_free(struct vcs_zcode_dht_service *service,
                                struct vcs_zcode_dht_time now);
bool vcs_zcode_dht_service_enabled(const struct vcs_zcode_dht_service *service);

bool vcs_zcode_dht_service_session_open(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    const struct vcs_zcode_dht_session *session,
    struct vcs_zcode_dht_time now);
void vcs_zcode_dht_service_session_close(struct vcs_zcode_dht_service *service,
                                         uint64_t peer_id, uint64_t generation,
                                         struct vcs_zcode_dht_time now);
void vcs_zcode_dht_service_sessions_reconcile(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_live_session *live, size_t live_count,
    struct vcs_zcode_dht_time now);

/* Handle one ZCDHTM frame already extracted from zpkgswm.  The service queues
 * any response; network I/O remains the composition root's responsibility. */
bool vcs_zcode_dht_service_handle_frame(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    const uint8_t *wire, size_t wire_len, struct vcs_zcode_dht_time now,
    enum vcs_zcode_dht_reject_reason *rejected_out);
bool vcs_zcode_dht_service_next_outbound(struct vcs_zcode_dht_service *service,
                                         uint64_t peer_filter,
                                         uint64_t *peer_out, uint8_t *wire_out,
                                         size_t wire_capacity,
                                         size_t *wire_len_out);
void vcs_zcode_dht_service_tick(struct vcs_zcode_dht_service *service,
                                struct vcs_zcode_dht_time now);
#ifdef ZCL_TESTING
struct vcs_zcode_dht_publication_test_view {
  uint64_t next_attempt_mono;
  uint32_t phase;
  uint32_t node_count;
  uint32_t attempts;
  uint32_t successes;
  uint32_t succeeded_beyond_k;
  uint8_t node_ids[VCS_ZCODE_DHT_SERVICE_MAX_CANDIDATES][32];
};
bool vcs_zcode_dht_service_test_publication_retry(
    const struct vcs_zcode_dht_service *service,
    const uint8_t semantic_root[32],
    struct vcs_zcode_dht_publication_test_view *out);
#endif

bool vcs_zcode_dht_service_lookup_begin(struct vcs_zcode_dht_service *service,
                                        const uint8_t target[32],
                                        struct vcs_zcode_dht_time now,
                                        uint64_t *lookup_id_out);
bool vcs_zcode_dht_service_lookup_poll(struct vcs_zcode_dht_service *service,
                                       uint64_t lookup_id,
                                       struct vcs_zcode_dht_time now,
                                       struct vcs_zcode_dht_lookup_result *out);
/* Releases a caller-abandoned lookup slot. In-flight protocol queries retain
 * their own bounded expiry so a late authenticated reply is classified
 * correctly rather than becoming an unsolicited-frame false positive. */
bool vcs_zcode_dht_service_lookup_cancel(
    struct vcs_zcode_dht_service *service, uint64_t lookup_id);

/* Direct record operations share the service's authenticated query slots,
 * replay ledgers, rate bucket, deadline, outbound queue and Noise session.
 * Higher-level iterative discovery may issue these against DHT results. */
bool vcs_zcode_dht_service_record_query_begin(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_time now, uint64_t *operation_id_out);
bool vcs_zcode_dht_service_record_query_page_begin(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    const struct vcs_zcode_dht_record_selector *selector,
    uint8_t page_offset, struct vcs_zcode_dht_time now,
    uint64_t *operation_id_out);
bool vcs_zcode_dht_service_record_store_begin(
    struct vcs_zcode_dht_service *service, uint64_t peer_id,
    const struct vcs_zcode_dht_record *record,
    struct vcs_zcode_dht_time now, uint64_t *operation_id_out);
bool vcs_zcode_dht_service_record_operation_poll(
    struct vcs_zcode_dht_service *service, uint64_t operation_id,
    struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record_operation_result *out);
bool vcs_zcode_dht_service_record_operation_cancel(
    struct vcs_zcode_dht_service *service, uint64_t operation_id);

/* Iterative discovery derives the routing target from the selector, walks the
 * S6 closest-node frontier, then queries up to k freshly authenticated nodes
 * under the same global alpha/query budget. Signed responses are merged
 * deterministically; records.v1 is an optional local cache, never authority. */
bool vcs_zcode_dht_service_record_discovery_begin(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_time now, uint64_t *operation_id_out);
bool vcs_zcode_dht_service_record_discovery_poll(
    struct vcs_zcode_dht_service *service, uint64_t operation_id,
    struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record_discovery_result *out);
bool vcs_zcode_dht_service_record_discovery_cancel(
    struct vcs_zcode_dht_service *service, uint64_t operation_id);
enum vcs_zcode_dht_record_store_result vcs_zcode_dht_service_record_admit(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_record *record, struct vcs_zcode_dht_time now);
size_t vcs_zcode_dht_service_record_local_query(
    const struct vcs_zcode_dht_service *service, uint64_t now_unix,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_record *out, size_t out_capacity);
size_t vcs_zcode_dht_service_record_local_query_page(
    const struct vcs_zcode_dht_service *service, uint64_t now_unix,
    const struct vcs_zcode_dht_record_selector *selector,
    uint8_t page_offset, struct vcs_zcode_dht_record *out,
    size_t out_capacity, uint8_t *next_offset_out);

/* Resolve active signed PROVIDER records to current Noise/delegation-
 * authenticated transport sessions. Missing accepted providers are handed to
 * the existing ZENDP reachability callback; no address crosses this API. */
bool vcs_zcode_dht_service_provider_route(
    struct vcs_zcode_dht_service *service, uint64_t now_unix,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_provider_route *out);

/* Operator-authored publication is a stale-plan-safe mutation.  The plan
 * token binds the exact deterministic signed record and the current canonical
 * record-store digest.  No seed or delegation wire is returned to callers.
 * spec.sequence == 0 means "derive it": the plan (and, deterministically, the
 * commit rebuild) picks max+1 from the service's own record store under the
 * service lock, so concurrent renewals of one stream through one node cannot
 * commit duplicate sequences — the loser's token goes STALE.  An explicit
 * sequence >= 1 pins the sequence as before. */
struct vcs_zcode_dht_publish_spec {
  enum vcs_zcode_dht_record_kind kind;
  char namespace_name[VCS_ZCODE_DHT_RECORD_NAMESPACE_BYTES];
  uint8_t semantic_root[32];
  uint8_t transport_root[32];
  uint8_t owner_group[32];
  uint64_t sequence;
  uint64_t not_before;
  uint64_t expiry;
};
/* On refusal, *reason (nullable) names the failed record contract; OK means
 * the refusal was not a record-contract one (service disabled, null input) —
 * the two call for different operator actions. */
bool vcs_zcode_dht_service_record_publish_plan(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out,
    enum vcs_zcode_dht_record_error *reason);
enum vcs_zcode_dht_record_store_result
vcs_zcode_dht_service_record_publish_commit(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out,
    enum vcs_zcode_dht_record_error *reason);

/* STORAGE_ACK has a separate authorship path. Both plan and commit require a
 * complete, pinned package and re-hash its manifest and every chunk. Generic
 * publication cannot author an ACK. */
bool vcs_zcode_dht_service_storage_ack_plan(
    struct vcs_zcode_dht_service *service,
    struct vcs_package_store *package_store,
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out);
enum vcs_zcode_dht_record_store_result
vcs_zcode_dht_service_storage_ack_commit(
    struct vcs_zcode_dht_service *service,
    struct vcs_package_store *package_store,
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out);

/* Composition-root adapter after an out-of-lock possession proof. These do
 * not inspect storage themselves; ordinary callers use the checked APIs
 * above. */
bool vcs_zcode_dht_storage_ack_plan_verified(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out);
enum vcs_zcode_dht_record_store_result
vcs_zcode_dht_storage_ack_commit_verified(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out);

/* SOURCE_REPRODUCTION_ACK has the same plan/commit integrity boundary, but
 * callers reach these only after reconstructing the complete accepted source
 * carrier outside the DHT lock. It is historical one-shot evidence, not a
 * renewable possession claim. */
bool vcs_zcode_dht_source_reproduction_ack_plan_verified(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out);
enum vcs_zcode_dht_record_store_result
vcs_zcode_dht_source_reproduction_ack_commit_verified(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out);

/* Snapshot/apply the proof state around a composition-root lock. The caller
 * performs the full package-store byte proof with no DHT lock held, then
 * applies the result before the scheduler is driven. */
struct vcs_zcode_dht_storage_ack_proof_request {
  uint8_t transport_root[32];
  bool fresh_required;
  uint64_t proof_epoch;
};
size_t vcs_zcode_dht_service_storage_ack_proof_requests(
    struct vcs_zcode_dht_service *service, struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_storage_ack_proof_request *out, size_t max);
void vcs_zcode_dht_service_storage_ack_validation(
    struct vcs_zcode_dht_service *service, const uint8_t transport_root[32],
    uint64_t proof_epoch, bool valid, struct vcs_zcode_dht_time now);

/* Composition-root lock audit helpers. The snapshot is fixed-size and
 * allocation-free; callbacks may be replaced after boot-time persistence was
 * loaded outside the global service mutex. */
size_t vcs_zcode_dht_service_delegations(
    const struct vcs_zcode_dht_service *service,
    struct vcs_zcode_dht_delegation *out, size_t max);
void vcs_zcode_dht_service_set_chain_verify(
    struct vcs_zcode_dht_service *service,
    vcs_zcode_dht_chain_verify_fn chain_verify, void *chain_ctx);

struct vcs_zcode_dht_persistence_snapshot;
struct vcs_zcode_dht_persistence_snapshot *
vcs_zcode_dht_service_persistence_snapshot(
    struct vcs_zcode_dht_service *service, uint64_t monotonic_s, bool force);
bool vcs_zcode_dht_persistence_snapshot_write(
    struct vcs_zcode_dht_persistence_snapshot *snapshot);
void vcs_zcode_dht_service_persistence_commit(
    struct vcs_zcode_dht_service *service,
    const struct vcs_zcode_dht_persistence_snapshot *snapshot, bool written);
void vcs_zcode_dht_persistence_snapshot_free(
    struct vcs_zcode_dht_persistence_snapshot *snapshot);

void vcs_zcode_dht_service_status(const struct vcs_zcode_dht_service *service,
                                  struct vcs_zcode_dht_service_status *out);
size_t vcs_zcode_dht_service_peers(const struct vcs_zcode_dht_service *service,
                                   uint64_t wall_now_unix,
                                   struct vcs_zcode_dht_peer_view *out,
                                   size_t max, size_t offset);

/* Called by the existing ZID status-generation revalidation worker. */
bool vcs_zcode_dht_service_revalidate(struct vcs_zcode_dht_service *service,
                                      struct vcs_zcode_dht_time now);

#endif /* ZCL_VCS_ZCODE_DHT_SERVICE_H */
