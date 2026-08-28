/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Native provisioning and live adapters for the ZCODE DHT. */

#include "command/native_command.h"

#include "base/hex.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "models/zid_identity.h"
#include "net/v2_identity.h"
#include "platform/time_compat.h"
#include "platform/positioned_file.h"
#include "platform/file_metadata.h"
#include "support/cleanse.h"
#include "validation/main_constants.h"
#include "vcs/zcode_dht.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_service.h"
#include "vcs/source_bundle.h"
#include "json/json.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ZDN_COMMAND "zcode.network.delegate"

static void zdn_fail(struct zcl_command_reply *reply, const char *code,
                     const char *phase, const char *message,
                     const char *evidence) {
  zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                         ZCL_COMMAND_EXIT_INVALID, code, phase, false, false,
                         message, evidence ? evidence : ZDN_COMMAND);
}

static const char *zdn_str(const struct json_value *in, const char *key) {
  const struct json_value *v = in ? json_get(in, key) : NULL;
  return v && v->type == JSON_STR ? json_get_str(v) : NULL;
}

static bool zdn_u64(const struct json_value *in, const char *key, uint64_t *out,
                    bool *present) {
  const struct json_value *v = in ? json_get(in, key) : NULL;
  *present = v != NULL;
  if (!v)
    return true;
  if (v->type == JSON_INT && json_get_int(v) >= 0) {
    *out = (uint64_t)json_get_int(v);
    return true;
  }
  const char *s = v->type == JSON_STR ? json_get_str(v) : NULL;
  if (!s || !s[0] || s[0] == '-')
    return false;
  errno = 0;
  char *end = NULL;
  unsigned long long parsed = strtoull(s, &end, 10);
  if (errno != 0 || !end || *end != '\0')
    return false;
  *out = (uint64_t)parsed;
  return true;
}

static bool zdn_read_master_seed(const char *path, uint8_t out[32], char *err,
                                 size_t err_cap) {
  struct platform_positioned_file file;
  struct platform_positioned_file_snapshot before, after;
  platform_positioned_file_init(&file);
  if (!platform_positioned_file_open(&file, path)) {
    snprintf(err, err_cap, "cannot open master seed: %s", strerror(errno));
    return false;
  }
  if (!platform_positioned_file_is_current_user_only(&file) ||
      !platform_positioned_file_snapshot(&file, &before) ||
      (before.size != 64 && before.size != 65)) {
    platform_positioned_file_close(&file);
    snprintf(err, err_cap, "master seed must be a private regular file");
    return false;
  }
  char hex[66];
  int64_t n = platform_positioned_file_read(&file, hex, (size_t)before.size, 0);
  bool stable = platform_positioned_file_snapshot(&file, &after) &&
      before.size == after.size && before.volume == after.volume &&
      before.file_low == after.file_low && before.file_high == after.file_high &&
      before.modified_seconds == after.modified_seconds &&
      before.modified_nanoseconds == after.modified_nanoseconds &&
      before.changed_seconds == after.changed_seconds &&
      before.changed_nanoseconds == after.changed_nanoseconds;
  platform_positioned_file_close(&file);
  if (!stable) n = -1;
  if (n != 64 && !(n == 65 && hex[64] == '\n')) {
    memory_cleanse(hex, sizeof(hex));
    snprintf(err, err_cap, "master seed must contain exactly 64 hex chars");
    return false;
  }
  hex[64] = '\0';
  bool ok = zcl_hex_decode_lower(hex, out, 32);
  memory_cleanse(hex, sizeof(hex));
  if (!ok)
    snprintf(err, err_cap, "master seed is not canonical lowercase hex");
  return ok;
}

static bool zdn_rpc_int(const char *method, int64_t arg, bool has_arg,
                        int64_t *out) {
  struct rpc_arg_builder params;
  rpc_arg_builder_init(&params);
  if (has_arg)
    rpc_arg_builder_push_int(&params, arg);
  char *json_params = rpc_arg_builder_to_json(&params);
  char *raw = node_rpc_call(method, json_params);
  free(json_params);
  if (!raw)
    return false;
  struct json_value doc;
  bool ok = json_read(&doc, raw, strlen(raw)) && doc.type == JSON_INT;
  if (ok)
    *out = json_get_int(&doc);
  json_free(&doc);
  free(raw);
  return ok;
}

static bool zdn_rpc_block_hash(int64_t height, struct uint256 *out) {
  struct rpc_arg_builder params;
  rpc_arg_builder_init(&params);
  rpc_arg_builder_push_int(&params, height);
  char *json_params = rpc_arg_builder_to_json(&params);
  char *raw = node_rpc_call("getblockhash", json_params);
  free(json_params);
  if (!raw)
    return false;
  struct json_value doc;
  bool ok = json_read(&doc, raw, strlen(raw)) && doc.type == JSON_STR;
  const char *hex = ok ? json_get_str(&doc) : NULL;
  if (ok && hex && strlen(hex) == 64)
    uint256_set_hex(out, hex);
  else
    ok = false;
  json_free(&doc);
  free(raw);
  return ok;
}

bool zcl_native_zcode_network_genesis(uint8_t out[32]) {
  struct uint256 genesis;
  if (!out || !zdn_rpc_block_hash(0, &genesis))
    return false;
  memcpy(out, genesis.data, 32);
  return true;
}

enum zdn_existing_result {
  ZDN_EXISTING_ABSENT = 0,
  ZDN_EXISTING_VALID,
  ZDN_EXISTING_CORRUPT,
};

static enum zdn_existing_result zdn_existing_sequence(const char *datadir,
                                                      uint64_t *sequence,
                                                      char *err,
                                                      size_t err_cap) {
  char path[1400];
  int n = snprintf(path, sizeof(path), "%s/%s/%s", datadir,
                   VCS_ZCODE_DHT_IDENTITY_DIR, VCS_ZCODE_DHT_DELEGATION_FILE);
  if (n <= 0 || (size_t)n >= sizeof(path)) {
    snprintf(err, err_cap, "delegation path too long");
    return ZDN_EXISTING_CORRUPT;
  }
  struct platform_file_metadata metadata;
  enum platform_file_metadata_result probe =
      platform_file_metadata_read(path, &metadata);
  if (probe != PLATFORM_FILE_METADATA_OK) {
    if (probe == PLATFORM_FILE_METADATA_MISSING) return ZDN_EXISTING_ABSENT;
    snprintf(err, err_cap, "cannot inspect existing delegation safely");
    return ZDN_EXISTING_CORRUPT;
  }
  struct vcs_zcode_dht_delegation old;
  if (!vcs_zcode_dht_delegation_load(datadir, &old, err, err_cap))
    return ZDN_EXISTING_CORRUPT;
  *sequence = old.doc.seq;
  return ZDN_EXISTING_VALID;
}

void zcl_native_handle_zcode_network_delegate(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  if (!request || !reply)
    return;
  const char *seed_file = zdn_str(request->input, "seed_file");
  const char *datadir = zdn_str(request->input, "datadir");
  if (!datadir || !datadir[0])
    datadir = zcl_native_command_datadir();
  if (!seed_file || !seed_file[0] || !datadir || !datadir[0]) {
    zdn_fail(reply, "MISSING_INPUT", "normalize",
             "seed_file and datadir are required", ZDN_COMMAND);
    return;
  }

  uint64_t now = (uint64_t)platform_time_wall_unix();
  bool supplied = false;
  if (!zdn_u64(request->input, "now", &now, &supplied)) {
    zdn_fail(reply, "BAD_NOW", "normalize", "now must be uint64", ZDN_COMMAND);
    return;
  }
  if (now > (uint64_t)INT64_MAX ||
      now > UINT64_MAX - VCS_ZCODE_DHT_DELEGATION_DEFAULT_SECONDS) {
    zdn_fail(reply, "BAD_NOW", "normalize",
             "now is outside the supported signed time range", ZDN_COMMAND);
    return;
  }
  uint64_t expiry = now + VCS_ZCODE_DHT_DELEGATION_DEFAULT_SECONDS;
  if (!zdn_u64(request->input, "expiry", &expiry, &supplied) || expiry <= now) {
    zdn_fail(reply, "BAD_WINDOW", "normalize",
             "expiry must be a uint64 strictly after now", ZDN_COMMAND);
    return;
  }
  if (expiry > (uint64_t)INT64_MAX) {
    zdn_fail(reply, "BAD_WINDOW", "normalize",
             "expiry is outside the supported signed time range", ZDN_COMMAND);
    return;
  }

  uint8_t master_seed[32], master_pub[32], master_secret_copy[32];
  char err[192] = {0};
  if (!zdn_read_master_seed(seed_file, master_seed, err, sizeof(err))) {
    zdn_fail(reply, "MASTER_SEED_UNREADABLE", "normalize", err, seed_file);
    return;
  }
  zcl_ed25519_keypair(master_pub, master_secret_copy, master_seed);
  memory_cleanse(master_secret_copy, sizeof(master_secret_copy));

  sqlite3 *db = NULL;
  struct node_db ndb;
  if (!zcl_native_node_db_require_readonly(
          datadir, reply, "the ZID anchor projection", &db, &ndb)) {
    memory_cleanse(master_seed, sizeof(master_seed));
    return;
  }
  struct zid_identity identity;
  bool found = db_zid_identity_find(&ndb, master_pub, &identity);
  zcl_native_node_db_close_readonly(&db, &ndb);
  if (!found || strcmp(identity.status, ZID_IDENTITY_STATUS_ACTIVE) != 0) {
    memory_cleanse(master_seed, sizeof(master_seed));
    zdn_fail(reply, found ? "MASTER_NOT_ACTIVE" : "MASTER_NOT_ANCHORED",
             "authorize", "master identity must be ACTIVE on-chain",
             ZDN_COMMAND);
    return;
  }
  if (identity.anchor_height < 0 ||
      identity.anchor_height > INT_MAX - 2 * ZCL_FINALITY_DEPTH) {
    memory_cleanse(master_seed, sizeof(master_seed));
    zdn_fail(reply, "ANCHOR_HEIGHT_INVALID", "authorize",
             "anchor height cannot produce a final beacon", ZDN_COMMAND);
    return;
  }
  int64_t tip = -1;
  zcl_native_bridge_ensure_rpc();
  if (!zdn_rpc_int("getblockcount", 0, false, &tip)) {
    memory_cleanse(master_seed, sizeof(master_seed));
    zdn_fail(reply, "CHAIN_UNAVAILABLE", "authorize",
             "running node did not return its provable tip", ZDN_COMMAND);
    return;
  }
  uint32_t beacon_height =
      (uint32_t)(identity.anchor_height + ZCL_FINALITY_DEPTH);
  if (tip < (int64_t)beacon_height + ZCL_FINALITY_DEPTH) {
    memory_cleanse(master_seed, sizeof(master_seed));
    zdn_fail(reply, "BEACON_PROVISIONAL", "authorize",
             "the identity beacon is not itself ten blocks deep", ZDN_COMMAND);
    return;
  }
  struct uint256 beacon;
  if (!zdn_rpc_block_hash(beacon_height, &beacon)) {
    memory_cleanse(master_seed, sizeof(master_seed));
    zdn_fail(reply, "BEACON_UNAVAILABLE", "authorize",
             "running node could not resolve the beacon block", ZDN_COMMAND);
    return;
  }

  uint8_t noise_seed[32], noise_pub[32], online_seed[32], online_pub[32];
  if (!v2_identity_load_or_create(datadir, noise_seed, noise_pub, err,
                                  sizeof(err)) ||
      !vcs_zcode_dht_online_key_load_or_create(datadir, online_seed, online_pub,
                                               err, sizeof(err))) {
    memory_cleanse(master_seed, 32);
    memory_cleanse(noise_seed, 32);
    memory_cleanse(online_seed, 32);
    zdn_fail(reply, "IDENTITY_IO", "persist", err, ZDN_COMMAND);
    return;
  }
  memory_cleanse(noise_seed, sizeof(noise_seed));

  uint64_t sequence = 1, previous = 0;
  bool seq_present = false;
  if (!zdn_u64(request->input, "sequence", &sequence, &seq_present)) {
    memory_cleanse(master_seed, 32);
    memory_cleanse(online_seed, 32);
    zdn_fail(reply, "BAD_SEQUENCE", "normalize", "sequence must be uint64",
             ZDN_COMMAND);
    return;
  }
  enum zdn_existing_result existing =
      zdn_existing_sequence(datadir, &previous, err, sizeof(err));
  if (existing == ZDN_EXISTING_CORRUPT) {
    memory_cleanse(master_seed, 32);
    memory_cleanse(online_seed, 32);
    zdn_fail(reply, "EXISTING_DELEGATION_CORRUPT", "normalize", err,
             ZDN_COMMAND);
    return;
  }
  if (existing == ZDN_EXISTING_VALID) {
    if (!seq_present) {
      if (previous == UINT64_MAX) {
        memory_cleanse(master_seed, 32);
        memory_cleanse(online_seed, 32);
        zdn_fail(reply, "SEQUENCE_OVERFLOW", "normalize",
                 "delegation sequence cannot advance", ZDN_COMMAND);
        return;
      }
      sequence = previous + 1;
    } else if (sequence <= previous) {
      memory_cleanse(master_seed, 32);
      memory_cleanse(online_seed, 32);
      zdn_fail(reply, "STALE_SEQUENCE", "normalize",
               "sequence must exceed the filed delegation", ZDN_COMMAND);
      return;
    }
  }
  if (sequence > (uint64_t)INT64_MAX) {
    memory_cleanse(master_seed, 32);
    memory_cleanse(online_seed, 32);
    zdn_fail(reply, "BAD_SEQUENCE", "normalize",
             "sequence is outside the supported signed range", ZDN_COMMAND);
    return;
  }

  /* Native command processes do not run the node boot path that selects
   * chain_params.  More importantly, the running daemon is the authority
   * for which chain this datadir/RPC endpoint serves.  Resolve block zero
   * through that authenticated endpoint instead of asserting on an
   * unselected global (or silently binding a regtest delegation to mainnet). */
  struct uint256 network_genesis;
  if (!zdn_rpc_block_hash(0, &network_genesis)) {
    memory_cleanse(master_seed, sizeof(master_seed));
    memory_cleanse(online_seed, sizeof(online_seed));
    zdn_fail(reply, "GENESIS_UNAVAILABLE", "authorize",
             "running node could not resolve its network genesis",
             ZDN_COMMAND);
    return;
  }
  struct vcs_zcode_dht_delegation delegation;
  enum vcs_zcode_dht_delegation_error signed_result =
      vcs_zcode_dht_delegation_sign(
          &delegation, network_genesis.data, online_pub,
          noise_pub, beacon_height, beacon.data, now, expiry, sequence,
          master_seed);
  memory_cleanse(master_seed, sizeof(master_seed));
  memory_cleanse(online_seed, sizeof(online_seed));
  if (signed_result != VCS_ZCODE_DHT_DELEGATION_OK ||
      !vcs_zcode_dht_delegation_save(datadir, &delegation, err, sizeof(err))) {
    zdn_fail(reply, "DELEGATION_WRITE_FAILED", "persist",
             signed_result == VCS_ZCODE_DHT_DELEGATION_OK
                 ? err
                 : vcs_zcode_dht_delegation_error_string(signed_result),
             ZDN_COMMAND);
    return;
  }

  uint8_t node_id[32];
  char node_hex[65], beacon_hex[65];
  if (!vcs_zcode_dht_delegation_node_id(node_id, &delegation)) {
    zdn_fail(reply, "NODE_ID_FAILED", "serialize",
             "signed delegation did not derive a node ID", ZDN_COMMAND);
    return;
  }
  zcl_hex_encode(node_id, 32, node_hex);
  zcl_hex_encode(beacon.data, 32, beacon_hex);
  json_push_kv_str(&reply->data, "node_id", node_hex);
  json_push_kv_int(&reply->data, "sequence", (int64_t)sequence);
  json_push_kv_int(&reply->data, "not_before", (int64_t)now);
  json_push_kv_int(&reply->data, "expiry", (int64_t)expiry);
  json_push_kv_int(&reply->data, "beacon_height", beacon_height);
  json_push_kv_str(&reply->data, "beacon_hash", beacon_hex);
  json_push_kv_bool(&reply->data, "key_material_returned", false);
  reply->status = ZCL_COMMAND_STATUS_PASSED;
  reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static bool zdn_rpc_body(const struct json_value *input,
                         struct zcl_command_reply *reply,
                         const char *rpc_method, struct json_value *body) {
  if (!reply || !rpc_method || !body)
    return false;
  struct json_value empty;
  json_init(&empty);
  json_set_object(&empty);
  const struct json_value *normalized =
      input && input->type == JSON_OBJ ? input : &empty;
  struct rpc_arg_builder args;
  rpc_arg_builder_init(&args);
  rpc_arg_builder_push_value(&args, normalized);
  char *params = rpc_arg_builder_to_json(&args);
  json_free(&empty);
  if (!params) {
    zdn_fail(reply, "ARG_BUILD_FAILED", "normalize",
             "could not encode the bounded DHT request", rpc_method);
    return false;
  }
  zcl_native_bridge_ensure_rpc();
  char *raw = node_rpc_call(rpc_method, params);
  free(params);
  if (!raw) {
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_TRANSIENT,
        "NODE_UNAVAILABLE", "dispatch", true, false,
        "the running node returned no DHT response", rpc_method);
    return false;
  }
  json_init(body);
  if (!json_read(body, raw, strlen(raw)) || body->type != JSON_OBJ) {
    free(raw);
    json_free(body);
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
        "BAD_RPC_BODY", "serialize", false, false,
        "the DHT RPC returned an unreadable body", rpc_method);
    return false;
  }
  free(raw);
  return true;
}

static void zdn_apply_body(struct zcl_command_reply *reply,
                           struct json_value *body,
                           const char *rpc_method) {
  if (!json_get_bool_or(body, "ok", false)) {
    const char *code = json_get_str(json_get(body, "code"));
    const char *message = json_get_str(json_get(body, "message"));
    bool timeout = code && strcmp(code, "LOOKUP_TIMEOUT") == 0;
    zcl_command_reply_fail(
        reply, timeout ? ZCL_COMMAND_STATUS_BLOCKED : ZCL_COMMAND_STATUS_FAILED,
        timeout ? ZCL_COMMAND_EXIT_TRANSIENT : ZCL_COMMAND_EXIT_FAILED,
        code && code[0] ? code : "DHT_REFUSED", "execute", timeout, false,
        message && message[0] ? message : "the DHT service refused the request",
        rpc_method);
    /* LOOKUP_TIMEOUT deliberately retains bounded partial node-id evidence. */
    json_copy(&reply->data, body);
    return;
  }
  json_copy(&reply->data, body);
  reply->status = ZCL_COMMAND_STATUS_PASSED;
  reply->exit_code = ZCL_COMMAND_EXIT_OK;
}

static void zdn_forward(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply,
                        const char *rpc_method) {
  if (!request || !reply || !rpc_method)
    return;
  struct json_value body;
  if (!zdn_rpc_body(request->input, reply, rpc_method, &body))
    return;
  zdn_apply_body(reply, &body, rpc_method);
  json_free(&body);
}


/* Give back the bounded lookup capability this wrapper admitted.  A terminal
 * poll leaves the node holding that result for a short retention window, so a
 * client that walks away without cancelling burns one of the node's few
 * discovery slots for the whole window.  The next honest lookup — the second
 * `zcode package fetch` of the same carrier, say — is then refused for a
 * reason that has nothing to do with the network.  The answer is already in
 * hand here, so release the slot.  A failed release is not reportable: the
 * capability expires on its own and the caller's answer still stands. */
static void zdn_release_capability(const char *cancel_method,
                                   const char *lookup, const char *owner) {
  if (!cancel_method || !lookup || !owner)
    return;
  struct json_value cancel;
  json_init(&cancel);
  json_set_object(&cancel);
  json_push_kv_str(&cancel, "lookup_id", lookup);
  json_push_kv_str(&cancel, "owner_token", owner);
  struct rpc_arg_builder args;
  rpc_arg_builder_init(&args);
  rpc_arg_builder_push_value(&args, &cancel);
  char *params = rpc_arg_builder_to_json(&args);
  json_free(&cancel);
  if (!params)
    return;
  zcl_native_bridge_ensure_rpc();
  free(node_rpc_call(cancel_method, params));
  free(params);
}
static void zdn_async_wrapper(const struct zcl_command_request *request,
                              struct zcl_command_reply *reply,
                              const char *begin_method,
                              const char *poll_method,
                              const char *cancel_method,
                              uint64_t deadline_seconds) {
  struct json_value body;
  if (!zdn_rpc_body(request->input, reply, begin_method, &body))
    return;
  if (!json_get_bool_or(&body, "ok", false)) {
    zdn_apply_body(reply, &body, begin_method);
    json_free(&body);
    return;
  }
  const char *lookup = json_get_str(json_get(&body, "lookup_id"));
  const char *owner = json_get_str(json_get(&body, "owner_token"));
  char lookup_copy[33], owner_copy[33];
  if (!lookup || !owner || strlen(lookup) != 32 || strlen(owner) != 32) {
    json_free(&body);
    zdn_fail(reply, "BAD_RPC_BODY", "serialize",
             "lookup admission omitted its bounded capability",
             begin_method);
    return;
  }
  memcpy(lookup_copy, lookup, sizeof(lookup_copy));
  memcpy(owner_copy, owner, sizeof(owner_copy));
  json_free(&body);

  int64_t deadline = platform_time_monotonic_ms() +
                     (int64_t)deadline_seconds * 1000;
  for (;;) {
    struct json_value poll;
    json_init(&poll);
    json_set_object(&poll);
    json_push_kv_str(&poll, "lookup_id", lookup_copy);
    json_push_kv_str(&poll, "owner_token", owner_copy);
    if (!zdn_rpc_body(&poll, reply, poll_method, &body)) {
      json_free(&poll);
      zdn_release_capability(cancel_method, lookup_copy, owner_copy);
      return;
    }
    json_free(&poll);
    const char *state = json_get_str(json_get(&body, "state"));
    if (!json_get_bool_or(&body, "ok", false) || !state ||
        strcmp(state, "pending") != 0) {
      zdn_apply_body(reply, &body, poll_method);
      json_free(&body);
      zdn_release_capability(cancel_method, lookup_copy, owner_copy);
      return;
    }
    json_free(&body);
    if (platform_time_monotonic_ms() >= deadline) {
      zdn_release_capability(cancel_method, lookup_copy, owner_copy);
      zdn_fail(reply, "LOOKUP_TIMEOUT", "execute",
               "lookup capability expired before a terminal poll",
               poll_method);
      return;
    }
    platform_sleep_ms(50);
  }
}

void zcl_native_handle_zcode_network_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_forward(request, reply, "zcode_dht_status");
}

void zcl_native_handle_zcode_network_peers(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_forward(request, reply, "zcode_dht_peers");
}

void zcl_native_handle_zcode_network_find(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_async_wrapper(request, reply, "zcode_dht_find_begin",
                    "zcode_dht_find_poll", "zcode_dht_find_cancel",
                    VCS_ZCODE_DHT_LOOKUP_CEILING_S + 5u);
}

void zcl_native_handle_zcode_network_find_begin(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_forward(request, reply, "zcode_dht_find_begin");
}

void zcl_native_handle_zcode_network_find_poll(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_forward(request, reply, "zcode_dht_find_poll");
}

void zcl_native_handle_zcode_network_find_cancel(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_forward(request, reply, "zcode_dht_find_cancel");
}

void zcl_native_handle_zcode_network_records(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_async_wrapper(request, reply, "zcode_dht_record_begin",
                    "zcode_dht_record_poll", "zcode_dht_record_cancel",
                    VCS_ZCODE_DHT_LOOKUP_CEILING_S +
                        VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S + 5u);
}

void zcl_native_handle_zcode_network_records_begin(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_forward(request, reply, "zcode_dht_record_begin");
}

void zcl_native_handle_zcode_network_records_poll(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_forward(request, reply, "zcode_dht_record_poll");
}

void zcl_native_handle_zcode_network_records_cancel(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_forward(request, reply, "zcode_dht_record_cancel");
}

void zcl_native_handle_zcode_network_providers(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  if (!request || !reply)
    return;
  struct json_value input;
  json_init(&input);
  if (request->input)
    json_copy(&input, request->input);
  else
    json_set_object(&input);
  json_push_kv_str(&input, "kind", "provider");
  struct zcl_command_request forwarded = *request;
  forwarded.input = &input;
  zcl_native_handle_zcode_network_records(&forwarded, reply);
  json_free(&input);
}

void zcl_native_handle_zcode_network_publish(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  if (!request || !reply)
    return;
  struct json_value input;
  json_init(&input);
  if (request->input)
    json_copy(&input, request->input);
  else
    json_set_object(&input);
  json_push_kv_str(&input, "operation", "publish");
  struct zcl_command_request forwarded = *request;
  forwarded.input = &input;
  zdn_forward(&forwarded, reply, "zcode_dht_status");
  json_free(&input);
}

void zcl_native_handle_zcode_network_storage_ack(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_forward(request, reply, "zcode_dht_storage_ack");
}

void zcl_native_handle_zcode_package_source_reproduce(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  if (!request || !reply)
    return;
  const char *mode = zdn_str(request->input, "mode");
  const char *root_hex = zdn_str(request->input, "root");
  const char *namespace_name = zdn_str(request->input, "namespace");
  uint8_t root[32];
  if (!mode || (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0) ||
      !root_hex || strlen(root_hex) != 64 ||
      !zcl_hex_decode_lower(root_hex, root, sizeof(root))) {
    zdn_fail(reply, "BAD_SOURCE_REPRODUCTION_INPUT", "normalize",
             "mode=plan|commit and one canonical lowercase package root are required",
             "zcode.package.source.reproduce");
    return;
  }
  if (!namespace_name || !namespace_name[0])
    namespace_name = "zclassic23.source";

  if (strcmp(mode, "plan") == 0) {
    struct json_value fetch_input;
    json_init(&fetch_input);
    json_set_object(&fetch_input);
    json_push_kv_str(&fetch_input, "root", root_hex);
    json_push_kv_str(&fetch_input, "namespace", namespace_name);
    const char *datadir = zdn_str(request->input, "datadir");
    if (datadir && datadir[0])
      json_push_kv_str(&fetch_input, "datadir", datadir);
    json_push_kv_int(&fetch_input, "maximum_bytes",
                     VCS_SOURCE_BUNDLE_MAX_SOURCE_BYTES);
    struct zcl_command_request fetch_request = *request;
    fetch_request.input = &fetch_input;
    struct zcl_command_reply fetch;
    zcl_command_reply_init(&fetch, "zcl.zcode_package_fetch.v1");
    zcl_native_handle_zcode_package_fetch(&fetch_request, &fetch);
    json_free(&fetch_input);
    if (fetch.exit_code != ZCL_COMMAND_EXIT_OK) {
      zcl_command_reply_fail(
          reply, fetch.status, fetch.exit_code,
          fetch.error.code[0] ? fetch.error.code : "SOURCE_FETCH_FAILED",
          fetch.error.phase[0] ? fetch.error.phase : "fetch",
          fetch.error.retryable, false,
          fetch.error.message[0] ? fetch.error.message
                                 : "source package fetch failed",
          fetch.error.evidence);
      zcl_command_reply_free(&fetch);
      return;
    }
    const char *fetch_result = json_get_str(json_get(&fetch.data, "fetch_result"));
    if (!fetch_result)
      fetch_result = json_get_str(json_get(&fetch.data, "result"));
    bool complete = json_get_bool_or(&fetch.data, "already_complete", false) ||
        (fetch_result && strcmp(fetch_result, "already-complete") == 0);
    zcl_command_reply_free(&fetch);
    if (!complete) {
      char retry[320];
      int n = snprintf(
          retry, sizeof(retry),
          "z23 zcode package source reproduce --input='"
          "{\"mode\":\"plan\",\"root\":\"%s\","
          "\"namespace\":\"%s\"}'",
          root_hex, namespace_name);
      json_push_kv_str(&reply->data, "schema",
                       "zcl.zcode_source_reproduce.v1");
      json_push_kv_str(&reply->data, "status", "FETCH_PENDING");
      json_push_kv_str(&reply->data, "package_root", root_hex);
      json_push_kv_bool(&reply->data, "network_called", true);
      json_push_kv_bool(&reply->data, "reconstructed", false);
      json_push_kv_bool(&reply->data, "evidence_signed", false);
      json_push_kv_str(&reply->data, "blocker",
                       "authenticated_package_fetch_incomplete");
      if (n > 0 && (size_t)n < sizeof(retry))
        json_push_kv_str(&reply->data, "next_command", retry);
      return;
    }
  }

  struct json_value normalized;
  json_init(&normalized);
  json_set_object(&normalized);
  json_push_kv_str(&normalized, "mode", mode);
  json_push_kv_str(&normalized, "namespace", namespace_name);
  json_push_kv_str(&normalized, "transport_root", root_hex);
  uint64_t sequence = 0, not_before = 0, expiry = 0;
  bool present = false;
  if (!zdn_u64(request->input, "sequence", &sequence, &present) ||
      (strcmp(mode, "commit") == 0 && !present)) {
    json_free(&normalized);
    zdn_fail(reply, "BAD_SOURCE_REPRODUCTION_SEQUENCE", "normalize",
             "commit requires the sequence returned by plan",
             "zcode.package.source.reproduce");
    return;
  }
  if (!present) sequence = (uint64_t)platform_time_wall_unix();
  if (!zdn_u64(request->input, "not_before", &not_before, &present) ||
      (strcmp(mode, "commit") == 0 && !present)) {
    json_free(&normalized);
    zdn_fail(reply, "BAD_SOURCE_REPRODUCTION_WINDOW", "normalize",
             "commit requires the not_before returned by plan",
             "zcode.package.source.reproduce");
    return;
  }
  if (!present) not_before = (uint64_t)platform_time_wall_unix();
  if (!zdn_u64(request->input, "expiry", &expiry, &present) ||
      (strcmp(mode, "commit") == 0 && !present)) {
    json_free(&normalized);
    zdn_fail(reply, "BAD_SOURCE_REPRODUCTION_WINDOW", "normalize",
             "commit requires the expiry returned by plan",
             "zcode.package.source.reproduce");
    return;
  }
  if (!present && not_before <= UINT64_MAX - 3600u)
    expiry = not_before + 3600u;
  json_push_kv_int(&normalized, "sequence", (int64_t)sequence);
  json_push_kv_int(&normalized, "not_before", (int64_t)not_before);
  json_push_kv_int(&normalized, "expiry", (int64_t)expiry);
  const char *plan_token = zdn_str(request->input, "plan_token");
  if (strcmp(mode, "commit") == 0 && plan_token)
    json_push_kv_str(&normalized, "plan_token", plan_token);
  struct zcl_command_request forwarded = *request;
  forwarded.input = &normalized;
  zdn_forward(&forwarded, reply, "zcode_dht_source_reproduction_ack");
  if (reply->exit_code == ZCL_COMMAND_EXIT_OK) {
    const struct json_value *record = json_get(&reply->data, "record");
    const char *source_root = record
        ? json_get_str(json_get(record, "semantic_root")) : NULL;
    json_push_kv_str(&reply->data, "schema",
                     "zcl.zcode_source_reproduce.v1");
    json_push_kv_str(&reply->data, "status",
                     strcmp(mode, "commit") == 0
                         ? "SOURCE_REPRODUCTION_PUBLISHED"
                         : "SOURCE_REPRODUCTION_PROVEN");
    json_push_kv_str(&reply->data, "package_root", root_hex);
    if (source_root)
      json_push_kv_str(&reply->data, "source_tree_root", source_root);
    json_push_kv_bool(&reply->data, "reconstructed", true);
    json_push_kv_bool(&reply->data, "evidence_signed", true);
    json_push_kv_bool(&reply->data, "physical_independence_attested", false);
    if (strcmp(mode, "plan") == 0) {
      const char *token = json_get_str(json_get(&reply->data, "plan_token"));
      struct json_value commit;
      json_init(&commit);
      json_set_object(&commit);
      json_push_kv_str(&commit, "mode", "commit");
      json_push_kv_str(&commit, "root", root_hex);
      json_push_kv_str(&commit, "namespace", namespace_name);
      json_push_kv_int(&commit, "sequence", (int64_t)sequence);
      json_push_kv_int(&commit, "not_before", (int64_t)not_before);
      json_push_kv_int(&commit, "expiry", (int64_t)expiry);
      if (token) json_push_kv_str(&commit, "plan_token", token);
      json_push_kv(&reply->data, "commit_input", &commit);
      json_free(&commit);
    }
  }
  json_free(&normalized);
}

void zcl_native_handle_zcode_network_replication(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply) {
  zdn_async_wrapper(request, reply, "zcode_dht_replication_begin",
                    "zcode_dht_replication_poll",
                    "zcode_dht_replication_cancel",
                    VCS_ZCODE_DHT_LOOKUP_CEILING_S +
                        VCS_ZCODE_DHT_SERVICE_QUERY_TIMEOUT_S + 5u);
}
