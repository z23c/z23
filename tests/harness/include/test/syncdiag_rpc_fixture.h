/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Shared fixture for the sync-diagnostic RPC test group: seeding helpers for
 * the progress store (stage cursors, per-stage logs, anchor markers), JSON
 * lookup shorthands, synthetic connman peers, and the list of case groups
 * that test_syncdiag_rpc() runs in order.
 */
#ifndef ZCL_TEST_SYNCDIAG_RPC_FIXTURE_H
#define ZCL_TEST_SYNCDIAG_RPC_FIXTURE_H

#include "test/test_core.h"
#include "coins/undo.h"
#include "chain/checkpoints.h"
#include "controllers/agent_controller.h"
#include "controllers/agent_resources.h"
#include "controllers/agent_restart_watchdog.h"
#include "controllers/agent_security_posture.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_internal.h"
#include "controllers/event_controller.h"
#include "controllers/health_controller.h"
#include "controllers/network_controller.h"
#include "core/arith_uint256.h"
#include "crypto/sha3.h"
#include "framework/condition.h"
#include "jobs/reducer_frontier.h"
#include "jobs/tip_finalize_stage.h"
#include "models/block.h"
#include "models/database.h"
#include "services/block_source_policy.h"
#include "services/legacy_mirror_sync_service.h"
#include "services/node_health_service.h"
#include "services/operator_snapshot_service.h"
#include "services/chain_state_service.h"
#include "services/sync_monitor.h"
#include "storage/boot_auto_reindex.h"
#include "storage/coins_kv.h"
#include "storage/progress_store.h"
#include "validation/mirror_consensus.h"
#include "event/event.h"
#include "net/connman.h"
#include "net/download.h"
#include "net/fast_sync.h"
#include "net/netbase.h"
#include "net/peer_lifecycle.h"
#include "net/version.h"
#include "platform/time_compat.h"
#include "rpc/httpserver.h"
#include "rpc/server.h"
#include "json/json.h"
#include "util/alerts.h"
#include "util/blocker.h"
#include "util/clientversion.h"
#include "validation/main_state.h"
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>

/* No-shell dev-status collector for tests. os-substrate Rung 0 (site 11) made
 * agent_collect_optional_status run ZCL_AGENT_DEV_STATUS_CMD as an argv via
 * execvp (no shell), so the old `printf '...'` shell command no longer works.
 * Write the fixed JSON to a temp file and point the collector at a bare
 * `cat <path>` command — pure argv, no shell quoting or redirection. */
bool set_dev_status_cmd_json(const char *json);

/* Push a 64 KiB frame filled with 0xCC onto the stack, then return.
 * The frame is freed on return but the bytes persist in memory — any
 * subsequent callee with a smaller combined frame size reuses that
 * region, observing 0xCC where `= {0}` would have given zeros. */
void dirty_stack_region(void);

struct syncdiag_peer_lock_hold {
    struct connman *connman;
    _Atomic bool ready;
    _Atomic bool release;
};

void *syncdiag_hold_peer_lock(void *arg);

const struct json_value *find_service(const struct json_value *arr,
                                      const char *name);
const struct json_value *find_source_json(const struct json_value *arr,
                                          const char *source);
const struct json_value *find_object_with_str(const struct json_value *arr,
                                              const char *key,
                                              const char *value);
bool json_array_has_str(const struct json_value *arr, const char *value);
bool json_array_has_substr(const struct json_value *arr, const char *needle);

/* Fetch a criterion object by its "id" from an mvp criteria array (or NULL). */
const struct json_value *mvp_find_criterion(const struct json_value *arr,
                                            const char *id);

bool syncdiag_touch_file(const char *path);
bool syncdiag_set_progress_mtime_seconds_ago(const char *dir,
                                             int64_t seconds_ago);
bool syncdiag_exec_sql(sqlite3 *db, const char *sql);
bool syncdiag_open_fresh_progress_wal(const char *dir, sqlite3 **db_out);
bool syncdiag_set_utxo_sample_ages(const char *dir, int64_t older_age,
                                   int64_t newer_age);
bool syncdiag_set_coins_applied(sqlite3 *db, int32_t height);
void syncdiag_set_ipv4(struct net_address *addr, uint8_t a, uint8_t b,
                       uint8_t c, uint8_t d, uint16_t port);
void syncdiag_set_hash(struct uint256 *hash, uint8_t tag);
bool syncdiag_seed_durable_tip_authority(int height, const uint8_t hash[32]);
bool syncdiag_seed_cursor(sqlite3 *db, const char *name, int cursor);
bool syncdiag_seed_reducer_frontier_at_anchor(sqlite3 *db, int32_t anchor);
void syncdiag_write_le32(uint8_t *p, uint32_t v);
void syncdiag_write_le64(uint8_t *p, uint64_t v);
bool syncdiag_write_empty_anchor_snapshot(const char *dir);
bool syncdiag_seed_meta_blob(sqlite3 *db, const char *key, const void *blob,
                             int len);
bool syncdiag_create_height_log(sqlite3 *db, const char *table);
bool syncdiag_seed_log_point(sqlite3 *db, const char *table, int64_t height);
bool syncdiag_seed_log_verdict(sqlite3 *db, const char *table, int64_t height,
                               const char *status, int ok_value);
bool syncdiag_seed_anchorstatus_progress(const char *dir);
bool syncdiag_seed_body_position_hazard(const char *dir);
bool syncdiag_seed_log_rows(sqlite3 *db, const char *insert_sql,
                            int max_height);
bool syncdiag_seed_lookahead_reducer_progress(int served_height);
struct p2p_node *syncdiag_add_peer(struct connman *cm, uint8_t last_octet,
                                   bool inbound, enum peer_state state);
void syncdiag_note_peer_lifecycle_active(const struct p2p_node *node,
                                         enum peer_lifecycle_source source);
void syncdiag_reset_rpc_globals_for_test(void);

/* Case groups. test_syncdiag_rpc() calls these in this order; each returns
 * the number of failed cases it printed. */
int syncdiag_cases_anchorstatus(void);
int syncdiag_cases_network(void);
int syncdiag_cases_health(void);
int syncdiag_cases_api_catalog(void);
int syncdiag_cases_agent_status(void);
int syncdiag_cases_agent_projection(void);
int syncdiag_cases_agent_codemap(void);
int syncdiag_cases_agent_contracts(void);
int syncdiag_cases_agent_ops(void);
int syncdiag_cases_agent_interface(void);
int syncdiag_cases_operator(void);

#endif /* ZCL_TEST_SYNCDIAG_RPC_FIXTURE_H */
