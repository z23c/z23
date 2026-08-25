/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Composition-root adapter between Noise peers and ZCODE DHT. */

#ifndef ZCL_CONFIG_BOOT_ZCODE_DHT_H
#define ZCL_CONFIG_BOOT_ZCODE_DHT_H

#include "vcs/zcode_dht_service.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct boot_svc_ctx;
struct json_value;
struct msg_processor;
struct p2p_node;
struct rpc_table;
struct block_index;
struct vcs_swarm_engine;
struct vcs_swarm_download_status;

/* Lock order (outermost to innermost): public lookup lifecycle -> DHT service
 * -> chain-authorization/reachability caches.  No database, ancestry walk,
 * endpoint scan, connman/socket operation, or disk I/O may run while the DHT
 * service lock is held.  Detached persistence snapshots own their bytes and
 * are committed only after service-pointer + generation revalidation. */

/* True only after Noise and the P2P version/verack handshake are both ready;
 * DHT bootstrap frames must not cross the message layer earlier. */
bool boot_zcode_dht_peer_ready(const struct p2p_node *node);

/* Returns true only when this is the ZCDHTM namespace and is consumed. */
bool boot_zcode_dht_frame(struct msg_processor *mp, struct p2p_node *node,
                          const uint8_t *payload, size_t payload_len,
                          struct boot_svc_ctx *svc);
void boot_zcode_dht_periodic(struct msg_processor *mp,
                             struct boot_svc_ctx *svc);
void boot_zcode_dht_shutdown(void);

/* Short critical-section adapters used by the nonblocking public lifecycle.
 * `generation` binds an opaque public admission to one service instance. */
bool boot_zcode_dht_lookup_begin(
    const uint8_t target[32], struct vcs_zcode_dht_time now,
    uint64_t *lookup_id, uint64_t *generation);
bool boot_zcode_dht_lookup_poll(
    uint64_t lookup_id, uint64_t generation, struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_lookup_result *out);
bool boot_zcode_dht_lookup_cancel(uint64_t lookup_id, uint64_t generation);
bool boot_zcode_dht_record_discovery_begin(
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_time now, uint64_t *operation_id,
    uint64_t *generation);
bool boot_zcode_dht_record_discovery_poll(
    uint64_t operation_id, uint64_t generation,
    struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record_discovery_result *out);
bool boot_zcode_dht_record_discovery_cancel(uint64_t operation_id,
                                            uint64_t generation);
bool boot_zcode_dht_peers(uint64_t wall_now,
                          struct vcs_zcode_dht_peer_view *out, size_t max,
                          size_t offset, size_t *count_out);
bool boot_zcode_dht_record_query(
    uint64_t wall_now, const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_record *out, size_t max, size_t *count_out);
/* One lock-owned view for UI/status consumers that must not combine pointer
 * and provider records from different propagation instants. */
bool boot_zcode_dht_publication_snapshot(
    uint64_t wall_now,
    const struct vcs_zcode_dht_record_selector *pointer_selector,
    const struct vcs_zcode_dht_record_selector *provider_selector,
    uint8_t local_node_id[32], uint64_t *generation_out,
    struct vcs_zcode_dht_record *pointers, size_t pointers_max,
    size_t *pointers_count_out,
    struct vcs_zcode_dht_record *providers, size_t providers_max,
    size_t *providers_count_out);
bool boot_zcode_dht_provider_route(
    uint64_t wall_now,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_provider_route *out);
void boot_zcode_package_import_render(struct vcs_swarm_engine *engine,
                                      const uint8_t transport_root[32],
                                      int fetch_result,
                                      struct json_value *result);
void boot_zcode_package_download_render(
    struct json_value *result,
    const struct vcs_swarm_download_status *status);
bool boot_zcode_dht_record_publish_plan(
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out,
    enum vcs_zcode_dht_record_error *reason);
enum vcs_zcode_dht_record_store_result boot_zcode_dht_record_publish_commit(
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out,
    enum vcs_zcode_dht_record_error *reason);
bool boot_zcode_dht_storage_ack_plan(
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out);
enum vcs_zcode_dht_record_store_result boot_zcode_dht_storage_ack_commit(
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out);
bool boot_zcode_dht_source_reproduction_ack_plan(
    const struct vcs_zcode_dht_publish_spec *spec, uint8_t plan_token[32],
    struct vcs_zcode_dht_record *record_out);
enum vcs_zcode_dht_record_store_result
boot_zcode_dht_source_reproduction_ack_commit(
    const struct vcs_zcode_dht_publish_spec *spec,
    const uint8_t plan_token[32], struct vcs_zcode_dht_time now,
    struct vcs_zcode_dht_record *record_out);
void boot_zcode_dht_public_tick(uint64_t monotonic_s);
void boot_zcode_dht_public_reset(void);
void boot_zcode_dht_record_public_tick(uint64_t monotonic_s);
void boot_zcode_dht_record_public_reset(void);
void boot_zcode_dht_record_register_rpc(struct rpc_table *table);
#ifdef ZCL_TESTING
void boot_zcode_dht_record_test_render(
    struct json_value *result,
    const struct vcs_zcode_dht_record_discovery_result *discovery,
    bool include_evidence_wires);
void boot_zcode_dht_publication_record_test_render(
    struct json_value *result, const struct vcs_zcode_dht_record *record);
void boot_zcode_dht_provider_route_test_render(
    struct json_value *result,
    const struct vcs_zcode_dht_provider_route *route, uint32_t fetch_result);
#endif

/* Snapshot the network binding owned by the running DHT composition root.
 * False means this process has no initialized DHT service; one-shot command
 * clients may then resolve the daemon's genesis through RPC. */
bool boot_zcode_dht_network_genesis(uint8_t out[32]);
/* Slow, generation-revalidated ACTIVE-ZID + beacon proof for a public
 * delegation. Runs outside the DHT lock and is exposed to one-shot native
 * clients only through the internal delegation-check RPC. */
bool boot_zcode_dht_chain_authorize_public(
    const struct vcs_zcode_dht_delegation *delegation);

/* O(log n) ancestry proof used by the chain-binding adapter and its deep-tip
 * regression test. `height_span_out` is diagnostic context only. */
bool boot_zcode_dht_beacon_matches(const struct block_index *header_tip,
                                   uint32_t beacon_height,
                                   const uint8_t beacon_hash[32],
                                   uint64_t *height_span_out);

/* Invoked by the existing ZID status-generation worker, never a new poller. */
bool boot_zcode_dht_revalidate(void);

/* See AGENTS.md "Adding state introspection". Reentrant-safe. */
bool boot_zcode_dht_dump_state_json(struct json_value *out, const char *key);
/* Renderer for the lock-owned service snapshot; caller owns synchronization. */
void boot_zcode_dht_status_json(
    struct json_value *out, const struct vcs_zcode_dht_service *service);
/* Internal RPC composition for one lock-owned pointer/provider projection. */
bool boot_zcode_dht_publication_snapshot_rpc(
    const struct json_value *params, bool help, struct json_value *result);
void boot_zcode_dht_register_rpc(struct rpc_table *table);
void boot_zcode_package_register_rpc(struct rpc_table *table);

#endif /* ZCL_CONFIG_BOOT_ZCODE_DHT_H */
