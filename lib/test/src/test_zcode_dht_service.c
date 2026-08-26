/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Two-node protocol tests for the bounded ZCODE DHT service. */

#include "test/test_core.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "chain/chain.h"
#include "core/uint256.h"
#include "config/boot_zcode_dht.h"
#include "crypto/ed25519.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "net/net.h"
#include "rpc/server.h"
#include "services/metaverse_space_scout_service.h"
#include "services/metaverse_space_service.h"
#include "support/cleanse.h"
#include "util/util.h"
#include "vcs/blob_store.h"
#include "vcs/package_build.h"
#include "vcs/package_manifest.h"
#include "vcs/package_prepare.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"
#include "vcs/package_transport.h"
#include "vcs/package_swarm.h"
#include "vcs/package_swarm_node.h"
#include "vcs/space.h"
#include "vcs/space_scout.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_dht_identity.h"
#include "vcs/zcode_dht_service.h"
#include "vcs/zcode_sovereignty_policy.h"

/* The slot-superseding tests reach the private intent table to stage the
 * polluted state the public API can no longer produce. */
#include "../../vcs/src/zcode_dht_service_internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static struct vcs_zcode_dht_time test_time(uint64_t wall) {
  return (struct vcs_zcode_dht_time){.wall_unix = wall, .monotonic_s = wall};
}

static bool chain_ok(void *ctx, const struct vcs_zcode_dht_delegation *d) {
  (void)ctx;
  return d && d->beacon_height == 120;
}

static uint64_t policy_calls[VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT];

static bool policy_allow(void *ctx, enum vcs_zcode_sovereignty_action action,
                         const struct vcs_zcode_sovereignty_subject *subject) {
  (void)ctx;
  if (action < VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT)
    policy_calls[action]++;
  return action < VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT && subject != NULL;
}

static bool fixture_identity(const char *dir, uint8_t byte,
                             const uint8_t genesis[32],
                             const uint8_t noise[32]) {
  uint8_t online_seed[32], online_pub[32], master[32], beacon[32];
  char err[160];
  memset(master, byte, 32);
  memset(beacon, 0x44, 32);
  if (!vcs_zcode_dht_online_key_load_or_create(dir, online_seed, online_pub,
                                               err, sizeof(err)))
    return false;
  struct vcs_zcode_dht_delegation d;
  bool ok = vcs_zcode_dht_delegation_sign(&d, genesis, online_pub, noise, 120,
                                          beacon, 1000, 90000, 1, master) ==
                VCS_ZCODE_DHT_DELEGATION_OK &&
            vcs_zcode_dht_delegation_save(dir, &d, err, sizeof(err));
  memset(online_seed, 0, sizeof(online_seed));
  memset(master, 0, sizeof(master));
  return ok;
}

static struct vcs_zcode_dht_service *fixture_service_at(
    const char *dir, const uint8_t genesis[32], const uint8_t noise[32],
    uint64_t now_unix) {
  struct vcs_zcode_dht_service_params p = {
      .datadir = dir,
      .transport_enabled = true,
      .now = {.wall_unix = now_unix, .monotonic_s = now_unix},
      .chain_verify = chain_ok,
      .policy_decide = policy_allow,
  };
  memcpy(p.network_genesis, genesis, 32);
  memcpy(p.local_noise_static, noise, 32);
  return vcs_zcode_dht_service_create(&p);
}

static struct vcs_zcode_dht_service *fixture_service(const char *dir,
                                                     const uint8_t genesis[32],
                                                     const uint8_t noise[32]) {
  return fixture_service_at(dir, genesis, noise, 1000);
}

static bool fixture_material(const char *dir,
                             struct vcs_zcode_dht_delegation *delegation,
                             uint8_t online_seed[32], uint8_t node_id[32]) {
  uint8_t online_pub[32];
  char err[160];
  return vcs_zcode_dht_delegation_load(dir, delegation, err, sizeof(err)) &&
         vcs_zcode_dht_online_key_load(dir, online_seed, online_pub, err,
                                       sizeof(err)) &&
         memcmp(online_pub, delegation->online_pubkey, 32) == 0 &&
         vcs_zcode_dht_delegation_node_id(node_id, delegation);
}

static bool signed_find(const char *dir, uint64_t generation,
                        const uint8_t transcript[32], uint8_t query_byte,
                        uint8_t target_byte, uint8_t *wire, size_t cap,
                        size_t *len) {
  uint8_t seed[32], node_id[32];
  struct vcs_zcode_dht_msg_find_node msg;
  memset(&msg, 0, sizeof(msg));
  if (!fixture_material(dir, &msg.delegation, seed, node_id))
    return false;
  msg.session_generation = generation;
  memcpy(msg.sender_node_id, node_id, 32);
  memset(msg.query_id, query_byte, sizeof(msg.query_id));
  memset(msg.target_node_id, target_byte, sizeof(msg.target_node_id));
  enum vcs_zcode_dht_error e = vcs_zcode_dht_msg_serialize_find_node(
      &msg, transcript, seed, wire, cap, len);
  memory_cleanse(seed, sizeof(seed));
  return e == VCS_ZCODE_DHT_OK;
}

static bool signed_nodes(const char *dir, uint64_t generation,
                         const uint8_t transcript[32], uint8_t query_byte,
                         uint8_t *wire, size_t cap, size_t *len) {
  uint8_t seed[32], node_id[32];
  struct vcs_zcode_dht_msg_nodes msg;
  memset(&msg, 0, sizeof(msg));
  if (!fixture_material(dir, &msg.delegation, seed, node_id))
    return false;
  msg.session_generation = generation;
  memcpy(msg.sender_node_id, node_id, 32);
  memset(msg.query_id, query_byte, sizeof(msg.query_id));
  msg.contact_count = 1;
  memcpy(msg.node_ids[0], node_id, 32);
  enum vcs_zcode_dht_error e =
      vcs_zcode_dht_msg_serialize_nodes(&msg, transcript, seed, wire, cap, len);
  memory_cleanse(seed, sizeof(seed));
  return e == VCS_ZCODE_DHT_OK;
}

static bool resign_wire(const char *dir, const uint8_t transcript[32],
                        uint8_t *wire, size_t len) {
  if (len < VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES)
    return false;
  uint8_t seed[32], pub[32], secret[32], node_id[32];
  struct vcs_zcode_dht_delegation delegation;
  if (!fixture_material(dir, &delegation, seed, node_id))
    return false;
  ed25519_keypair(pub, secret, seed);
  uint8_t preimage[sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN) + 32 +
                   VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
  size_t unsigned_len = len - VCS_ZCODE_DHT_MSG_SIGNATURE_BYTES, off = 0;
  memcpy(preimage + off, VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN,
         sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN));
  off += sizeof(VCS_ZCODE_DHT_MSG_SIGNATURE_DOMAIN);
  memcpy(preimage + off, transcript, 32);
  off += 32;
  memcpy(preimage + off, wire, unsigned_len);
  off += unsigned_len;
  ed25519_sign(wire + unsigned_len, preimage, off, secret, pub);
  memory_cleanse(seed, sizeof(seed));
  memory_cleanse(secret, sizeof(secret));
  memory_cleanse(preimage, off);
  return true;
}

static size_t drain(struct vcs_zcode_dht_service *s) {
  uint8_t wire[VCS_ZCODE_DHT_MAX_FRAME_BYTES];
  uint64_t peer;
  size_t len, count = 0;
  while (vcs_zcode_dht_service_next_outbound(s, 0, &peer, wire, sizeof(wire),
                                             &len))
    count++;
  return count;
}

static bool pump(struct vcs_zcode_dht_service *from,
                 struct vcs_zcode_dht_service *to, uint64_t from_peer,
                 uint64_t to_peer, uint64_t now, uint8_t *last,
                 size_t *last_len) {
  uint8_t wire[VCS_ZCODE_DHT_MAX_FRAME_BYTES];
  uint64_t peer = 0;
  size_t len = 0;
  bool moved = false;
  while (vcs_zcode_dht_service_next_outbound(from, 0, &peer, wire, sizeof(wire),
                                             &len)) {
    if (peer != from_peer) {
      printf("pump peer mismatch got=%llu want=%llu\n",
             (unsigned long long)peer, (unsigned long long)from_peer);
      return false;
    }
    if (last && last_len) {
      memcpy(last, wire, len);
      *last_len = len;
    }
    enum vcs_zcode_dht_reject_reason reason;
    if (!vcs_zcode_dht_service_handle_frame(to, to_peer, wire, len,
                                            test_time(now),
                                            &reason)) {
      printf("pump rejected peer=%llu len=%zu reason=%s\n",
             (unsigned long long)to_peer, len,
             vcs_zcode_dht_reject_reason_string(reason));
      return false;
    }
    moved = true;
  }
  return moved;
}

static void cleanup_fixture(const char *dir) {
  char path[512];
  snprintf(path, sizeof(path), "%s/zcode/dht/records.v1", dir);
  (void)unlink(path);
  snprintf(path, sizeof(path), "%s/zcode/dht/publications.v1", dir);
  (void)unlink(path);
  snprintf(path, sizeof(path), "%s/zcode/dht/contacts.v2", dir);
  (void)unlink(path);
  snprintf(path, sizeof(path), "%s/zcode/dht/online_ed25519.key", dir);
  (void)unlink(path);
  snprintf(path, sizeof(path), "%s/zcode/dht/delegation.v1", dir);
  (void)unlink(path);
  snprintf(path, sizeof(path), "%s/zcode/dht", dir);
  (void)rmdir(path);
  snprintf(path, sizeof(path), "%s/zcode", dir);
  (void)rmdir(path);
  (void)rmdir(dir);
}

static bool fixture_pointer_record_named(
    const char *dir, const uint8_t genesis[32], const char *namespace_name,
    const uint8_t semantic_root[32], uint8_t transport_byte,
    uint64_t sequence, struct vcs_zcode_dht_record *record) {
  uint8_t seed[32], node_id[32];
  memset(record, 0, sizeof(*record));
  if (!fixture_material(dir, &record->delegation, seed, node_id))
    return false;
  record->kind = VCS_ZCODE_DHT_RECORD_POINTER;
  (void)snprintf(record->namespace_name, sizeof(record->namespace_name),
                 "%s", namespace_name);
  memcpy(record->network_genesis, genesis, 32);
  memcpy(record->semantic_root, semantic_root, 32);
  memset(record->transport_root, transport_byte, 32);
  memcpy(record->provider_node_id, node_id, 32);
  record->sequence = sequence;
  record->not_before = 1000;
  record->expiry = 4000;
  enum vcs_zcode_dht_record_error result =
      vcs_zcode_dht_record_sign(record, seed);
  memory_cleanse(seed, sizeof(seed));
  return result == VCS_ZCODE_DHT_RECORD_OK;
}

static bool fixture_pointer_record(
    const char *dir, const uint8_t genesis[32], uint8_t semantic_byte,
    uint8_t transport_byte, struct vcs_zcode_dht_record *record) {
  uint8_t semantic_root[32];
  memset(semantic_root, semantic_byte, 32);
  return fixture_pointer_record_named(
      dir, genesis, "science.study", semantic_root, transport_byte, 1,
      record);
}

static bool fixture_provider_record_named(
    const char *dir, const uint8_t genesis[32], const char *namespace_name,
    const uint8_t transport_root[32], struct vcs_zcode_dht_record *record) {
  uint8_t seed[32], node_id[32];
  memset(record, 0, sizeof(*record));
  if (!fixture_material(dir, &record->delegation, seed, node_id))
    return false;
  record->kind = VCS_ZCODE_DHT_RECORD_PROVIDER;
  (void)snprintf(record->namespace_name, sizeof(record->namespace_name),
                 "%s", namespace_name);
  memcpy(record->network_genesis, genesis, 32);
  memcpy(record->transport_root, transport_root, 32);
  memcpy(record->provider_node_id, node_id, 32);
  record->sequence = 1;
  record->not_before = 1000;
  record->expiry = 4000;
  enum vcs_zcode_dht_record_error result =
      vcs_zcode_dht_record_sign(record, seed);
  memory_cleanse(seed, sizeof(seed));
  return result == VCS_ZCODE_DHT_RECORD_OK;
}

static bool fixture_provider_record(
    const char *dir, const uint8_t genesis[32], uint8_t transport_byte,
    struct vcs_zcode_dht_record *record) {
  uint8_t transport_root[32];
  memset(transport_root, transport_byte, 32);
  return fixture_provider_record_named(
      dir, genesis, "science", transport_root, record);
}

#define MULTI_NODES 12u
#define MULTI_MAX_NODES 20u

struct multi_network;
struct multi_reach_ctx {
  struct multi_network *network;
  size_t owner;
};

struct multi_network {
  size_t node_count;
  struct vcs_zcode_dht_service *service[MULTI_MAX_NODES];
  char dir[MULTI_MAX_NODES][80];
  uint8_t noise[MULTI_MAX_NODES][32];
  uint8_t node_id[MULTI_MAX_NODES][32];
  struct multi_reach_ctx reach[MULTI_MAX_NODES];
  bool connected[MULTI_MAX_NODES][MULTI_MAX_NODES];
  bool pending[MULTI_MAX_NODES][MULTI_MAX_NODES];
  bool deny[MULTI_MAX_NODES][MULTI_MAX_NODES];
  bool stall[MULTI_MAX_NODES][MULTI_MAX_NODES];
  uint64_t session_generation[MULTI_MAX_NODES][MULTI_MAX_NODES];
  bool banned[MULTI_MAX_NODES];
  bool allow_unsolicited;
  bool hold_enabled, held_used;
  size_t hold_from, hold_to, held_len;
  uint8_t held_wire[VCS_ZCODE_DHT_MAX_FRAME_BYTES];
  uint8_t banned_root[32];
  uint64_t generation, frames, denied_hints;
  struct vcs_zcode_dht_time now;
};

static bool multi_policy(void *ctx, enum vcs_zcode_sovereignty_action action,
                         const struct vcs_zcode_sovereignty_subject *subject) {
  struct multi_reach_ctx *reach = ctx;
  if (!reach || !reach->network || !subject)
    return false;
  if (reach->network->banned[reach->owner] &&
      (memcmp(subject->semantic_root, reach->network->banned_root, 32) == 0 ||
       memcmp(subject->transport_root, reach->network->banned_root, 32) == 0) &&
      (action == VCS_ZCODE_SOVEREIGNTY_STORE ||
       action == VCS_ZCODE_SOVEREIGNTY_SERVE ||
       action == VCS_ZCODE_SOVEREIGNTY_FORWARD))
    return false;
  return true;
}

static bool multi_request_reachability(void *ctx, const uint8_t id[32],
                                       uint64_t wall_now) {
  (void)wall_now;
  struct multi_reach_ctx *reach = ctx;
  if (!reach || !reach->network)
    return false;
  struct multi_network *net = reach->network;
  for (size_t i = 0; i < net->node_count; i++) {
    if (memcmp(net->node_id[i], id, 32) != 0)
      continue;
    if (net->deny[reach->owner][i]) {
      net->denied_hints++;
      return false;
    }
    if (net->stall[reach->owner][i])
      return true;
    if (!net->connected[reach->owner][i])
      net->pending[reach->owner][i] = true;
    return true;
  }
  net->denied_hints++;
  return false;
}

static struct vcs_zcode_dht_service *multi_service(
    struct multi_network *net, size_t index, const uint8_t genesis[32]) {
  struct vcs_zcode_dht_service_params p = {
      .datadir = net->dir[index],
      .transport_enabled = true,
      .now = net->now,
      .chain_verify = chain_ok,
      .request_reachability = multi_request_reachability,
      .reachability_ctx = &net->reach[index],
      .policy_decide = multi_policy,
      .policy_ctx = &net->reach[index],
  };
  memcpy(p.network_genesis, genesis, 32);
  memcpy(p.local_noise_static, net->noise[index], 32);
  return vcs_zcode_dht_service_create(&p);
}

static bool multi_connect(struct multi_network *net, size_t a, size_t b) {
  if (!net || a >= net->node_count || b >= net->node_count || a == b)
    return false;
  if (net->connected[a][b])
    return true;
  uint64_t generation = ++net->generation;
  uint8_t transcript[32];
  memset(transcript, (int)(0x60u + (a < b ? a * MULTI_MAX_NODES + b
                                             : b * MULTI_MAX_NODES + a)),
         sizeof(transcript));
  struct vcs_zcode_dht_session as = {.established = true,
                                     .generation = generation,
                                     .connection_serial = generation * 2};
  struct vcs_zcode_dht_session bs = as;
  bs.connection_serial = generation * 2 + 1;
  memcpy(as.remote_static, net->noise[b], 32);
  memcpy(bs.remote_static, net->noise[a], 32);
  memcpy(as.transcript_hash, transcript, 32);
  memcpy(bs.transcript_hash, transcript, 32);
  if (!vcs_zcode_dht_service_session_open(net->service[a], b + 1, &as,
                                          net->now) ||
      !vcs_zcode_dht_service_session_open(net->service[b], a + 1, &bs,
                                          net->now))
    return false;
  net->connected[a][b] = net->connected[b][a] = true;
  net->session_generation[a][b] = generation;
  net->session_generation[b][a] = generation;
  return true;
}

static bool multi_drive_one(struct multi_network *net, bool *moved_out) {
  if (!net || !moved_out)
    return false;
  *moved_out = false;
  for (size_t from = 0; from < net->node_count; from++) {
    uint8_t wire[VCS_ZCODE_DHT_MAX_FRAME_BYTES];
    uint64_t peer = 0;
    size_t len = 0;
    if (!vcs_zcode_dht_service_next_outbound(
            net->service[from], 0, &peer, wire, sizeof(wire), &len))
      continue;
    if (peer == 0 || peer > net->node_count)
      return false;
    size_t to = (size_t)peer - 1;
    if (!net->connected[from][to] && net->allow_unsolicited) {
      *moved_out = true;
      return true;
    }
    if (!net->connected[from][to])
      return false;
    if (net->hold_enabled && !net->held_used &&
        from == net->hold_from && to == net->hold_to) {
      memcpy(net->held_wire, wire, len);
      net->held_len = len;
      net->held_used = true;
      *moved_out = true;
      return true;
    }
    enum vcs_zcode_dht_reject_reason rejected;
    if (!vcs_zcode_dht_service_handle_frame(
            net->service[to], from + 1, wire, len, net->now, &rejected)) {
      if (net->allow_unsolicited &&
          rejected == VCS_ZCODE_DHT_REJECT_UNSOLICITED) {
        *moved_out = true;
        return true;
      }
      printf("multi frame %zu->%zu rejected: %s\n", from, to,
             vcs_zcode_dht_reject_reason_string(rejected));
      return false;
    }
    net->frames++;
    *moved_out = true;
    return true;
  }
  for (size_t a = 0; a < net->node_count; a++)
    for (size_t b = a + 1; b < net->node_count; b++)
      if (net->pending[a][b] || net->pending[b][a]) {
        net->pending[a][b] = net->pending[b][a] = false;
        if (!multi_connect(net, a, b))
          return false;
        *moved_out = true;
        return true;
      }
  return true;
}

static bool multi_drive(struct multi_network *net) {
  for (size_t turn = 0; turn < 512; turn++) {
    bool moved = false;
    for (size_t from = 0; from < net->node_count; from++) {
      uint8_t wire[VCS_ZCODE_DHT_MAX_FRAME_BYTES];
      uint64_t peer = 0;
      size_t len = 0;
      while (vcs_zcode_dht_service_next_outbound(
          net->service[from], 0, &peer, wire, sizeof(wire), &len)) {
        if (peer == 0 || peer > net->node_count)
          return false;
        size_t to = (size_t)peer - 1;
        if (!net->connected[from][to] && net->allow_unsolicited) {
          moved = true;
          continue;
        }
        if (!net->connected[from][to])
          return false;
        if (net->hold_enabled && !net->held_used &&
            from == net->hold_from && to == net->hold_to) {
          memcpy(net->held_wire, wire, len);
          net->held_len = len;
          net->held_used = true;
          moved = true;
          continue;
        }
        enum vcs_zcode_dht_reject_reason rejected;
        if (!vcs_zcode_dht_service_handle_frame(
                net->service[to], from + 1, wire, len, net->now, &rejected)) {
          if (net->allow_unsolicited &&
              rejected == VCS_ZCODE_DHT_REJECT_UNSOLICITED) {
            moved = true;
            continue;
          }
          printf("multi frame %zu->%zu rejected: %s\n", from, to,
                 vcs_zcode_dht_reject_reason_string(rejected));
          return false;
        }
        net->frames++;
        moved = true;
      }
    }
    for (size_t a = 0; a < net->node_count; a++)
      for (size_t b = a + 1; b < net->node_count; b++)
        if (net->pending[a][b] || net->pending[b][a]) {
          net->pending[a][b] = net->pending[b][a] = false;
          if (!multi_connect(net, a, b))
            return false;
          moved = true;
        }
    if (!moved)
      return true;
  }
  return false;
}

static bool multi_release_held(struct multi_network *net) {
  if (!net || !net->held_used || net->hold_to >= net->node_count)
    return false;
  enum vcs_zcode_dht_reject_reason rejected;
  bool accepted = vcs_zcode_dht_service_handle_frame(
      net->service[net->hold_to], net->hold_from + 1, net->held_wire,
      net->held_len, net->now, &rejected);
  net->hold_enabled = false;
  net->held_used = false;
  net->held_len = 0;
  return accepted;
}

static void multi_disconnect(struct multi_network *net, size_t a, size_t b) {
  if (!net || a >= net->node_count || b >= net->node_count ||
      !net->connected[a][b])
    return;
  uint64_t generation = net->session_generation[a][b];
  vcs_zcode_dht_service_session_close(net->service[a], b + 1, generation,
                                      net->now);
  vcs_zcode_dht_service_session_close(net->service[b], a + 1, generation,
                                      net->now);
  net->connected[a][b] = net->connected[b][a] = false;
}

static bool farther_node(const uint8_t a[32], const uint8_t b[32],
                         const uint8_t target[32]) {
  uint8_t ad[32], bd[32];
  vcs_zcode_dht_xor_distance(a, target, ad);
  vcs_zcode_dht_xor_distance(b, target, bd);
  int cmp = memcmp(ad, bd, 32);
  return cmp > 0 || (cmp == 0 && memcmp(a, b, 32) > 0);
}

#define SPACE16_NODES 16u
#define SPACE16_MANIFESTS 4u
#define SPACE16_RECORD_MAX 32u

struct space16_observer {
  struct multi_network *network;
  size_t origin;
  const char *workspace;
  struct vcs_package_store *local_store;
  struct vcs_package_store *provider_store;
  struct vcs_swarm_engine *swarm;
  struct vcs_zcode_sovereignty_policy *policy;
  uint8_t genesis[32];
  uint64_t observation_unix;
  uint8_t dead_root[32];
  uint64_t now_ms;
  unsigned observe_calls;
  uint64_t policy_calls[VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT];
};

static int space16_root_compare(const void *left, const void *right) {
  return memcmp(left, right, 32);
}

static bool space16_manifest_make(
    const char *dir, const uint8_t genesis[32], const char *name,
    const uint8_t portals[][32], size_t portal_count, uint8_t service_byte,
    struct vcs_space_manifest_v1 *out, uint8_t root_out[32]) {
  uint8_t online_seed[32], node_id[32];
  memset(out, 0, sizeof(*out));
  if (!fixture_material(dir, &out->delegation, online_seed, node_id) ||
      portal_count > VCS_SPACE_PORTAL_MAX)
    return false;
  out->schema_version = VCS_SPACE_MANIFEST_VERSION;
  out->sequence = 1;
  out->not_before = 1000;
  out->expiry = 4000;
  (void)snprintf(out->name, sizeof(out->name), "%s", name);
  (void)snprintf(out->description, sizeof(out->description),
                 "signed immutable acceptance space");
  out->service_count = 1;
  memset(out->service_roots[0], service_byte, 32);
  out->portal_count = (uint8_t)portal_count;
  if (portal_count)
    memcpy(out->portal_roots, portals, portal_count * 32u);
  qsort(out->portal_roots, portal_count, 32u, space16_root_compare);
  bool ok = memcmp(out->delegation.network_genesis, genesis, 32) == 0 &&
            vcs_space_manifest_sign(out, online_seed) == VCS_SPACE_OK &&
            vcs_space_manifest_root(out, root_out) == VCS_SPACE_OK;
  memory_cleanse(online_seed, sizeof(online_seed));
  return ok;
}

static bool space16_store_manifest(
    const char *workspace, const struct vcs_space_manifest_v1 *manifest,
    const uint8_t root[32]) {
  uint8_t wire[VCS_SPACE_MANIFEST_WIRE_MAX];
  size_t wire_len = 0;
  return vcs_space_manifest_encode(manifest, wire, sizeof(wire), &wire_len) ==
             VCS_SPACE_OK &&
         vcs_object_put_addressed(workspace, root, wire, wire_len);
}

static bool space16_pointer_conflict(
    const char *dir, const uint8_t genesis[32], const uint8_t semantic[32],
    const uint8_t left_transport[32], const uint8_t right_transport[32],
    uint64_t sequence, struct vcs_zcode_dht_record *left,
    struct vcs_zcode_dht_record *right) {
  uint8_t seed[32], node_id[32];
  memset(left, 0, sizeof(*left));
  if (!fixture_material(dir, &left->delegation, seed, node_id))
    return false;
  left->kind = VCS_ZCODE_DHT_RECORD_POINTER;
  (void)snprintf(left->namespace_name, sizeof(left->namespace_name),
                 "space.manifest");
  memcpy(left->network_genesis, genesis, 32);
  memcpy(left->semantic_root, semantic, 32);
  memcpy(left->transport_root, left_transport, 32);
  memcpy(left->provider_node_id, node_id, 32);
  left->sequence = sequence;
  left->not_before = 1000;
  left->expiry = 4000;
  bool ok = vcs_zcode_dht_record_sign(left, seed) ==
            VCS_ZCODE_DHT_RECORD_OK;
  *right = *left;
  memcpy(right->transport_root, right_transport, 32);
  if (ok)
    ok = vcs_zcode_dht_record_sign(right, seed) ==
         VCS_ZCODE_DHT_RECORD_OK;
  memory_cleanse(seed, sizeof(seed));
  return ok;
}

static bool space16_root_after(const uint8_t base[32], uint8_t salt,
                               uint8_t out[32]) {
  memcpy(out, base, 32);
  for (size_t i = 0; i < 32; i++) {
    if (base[i] == UINT8_MAX)
      continue;
    out[i] = (uint8_t)(base[i] + 1u);
    memset(out + i + 1u, salt, 31u - i);
    return memcmp(out, base, 32) > 0;
  }
  return false;
}

static bool multi_discover_records(
    struct multi_network *net, size_t origin,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_record_discovery_result *out);

static bool space16_policy_allows(
    struct space16_observer *observer,
    enum vcs_zcode_sovereignty_action action, const uint8_t semantic[32],
    const uint8_t transport[32], const uint8_t publisher[32]) {
  struct vcs_zcode_sovereignty_subject subject;
  memset(&subject, 0, sizeof(subject));
  memcpy(subject.semantic_root, semantic, 32);
  memcpy(subject.package_root, semantic, 32);
  if (transport)
    memcpy(subject.transport_root, transport, 32);
  if (publisher)
    memcpy(subject.publisher_zid, publisher, 32);
  (void)snprintf(subject.service_type, sizeof(subject.service_type),
                 "space.manifest");
  observer->policy_calls[action]++;
  return vcs_zcode_sovereignty_policy_decide_callback(
      observer->policy, action, &subject);
}

static bool space16_swarm_fetch(
    struct space16_observer *observer, const uint8_t transport[32],
    const uint64_t *providers, size_t provider_count,
    size_t maximum_wire_bytes) {
  uint8_t key[33] = {0};
  key[0] = 2;
  struct vcs_package_store_summary summaries[64];
  size_t summary_count = vcs_package_store_list_summaries(
      observer->provider_store, true, summaries, 64);
  const struct vcs_package_store_summary *summary = NULL;
  for (size_t i = 0; i < summary_count; i++)
    if (memcmp(summaries[i].root, transport, 32) == 0)
      summary = &summaries[i];
  if (!summary)
    return false;
  for (size_t i = 0; i < provider_count; i++) {
    key[32] = (uint8_t)providers[i];
    if (!vcs_swarm_engine_peer_add(observer->swarm, providers[i], key))
      return false;
    struct vcs_package_swarm_message announced;
    memset(&announced, 0, sizeof(announced));
    announced.type = VCS_PACKAGE_SWARM_ANNOUNCE;
    memcpy(announced.body.announce.package_root, transport, 32);
    announced.body.announce.manifest_bytes = summary->manifest_bytes;
    announced.body.announce.file_count = summary->file_count;
    announced.body.announce.total_bytes = summary->total_bytes;
    announced.body.announce.total_chunks = summary->total_chunks;
    uint8_t frame[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t frame_len = 0;
    if (!vcs_package_swarm_serialize(
            &announced, frame, sizeof(frame), &frame_len))
      return false;
    struct vcs_swarm_frame_result handled = vcs_swarm_engine_handle_frame(
        observer->swarm, providers[i], frame, frame_len, 0,
        observer->now_ms);
    free(handled.reply);
    if (handled.penalty != VCS_SWARM_PENALTY_NONE)
      return false;
  }
  enum vcs_swarm_fetch_result started =
      vcs_swarm_engine_fetch_from_bounded(
          observer->swarm, transport, 0, observer->now_ms,
          providers, provider_count, maximum_wire_bytes);
  if (started != VCS_SWARM_FETCH_OK &&
      started != VCS_SWARM_FETCH_ALREADY_COMPLETE) {
    printf("space16 swarm start=%s\n",
           vcs_swarm_fetch_result_string(started));
    return false;
  }
  for (uint64_t round = 0; round < 64; round++) {
    vcs_swarm_engine_tick(observer->swarm, 0,
                          observer->now_ms + round + 1u);
    uint64_t peer = 0;
    uint8_t outbound[VCS_SWARM_OUTBOUND_FRAME_MAX];
    size_t outbound_len = 0;
    while (vcs_swarm_engine_next_outbound(
        observer->swarm, 0, &peer, outbound, &outbound_len)) {
      struct vcs_package_swarm_message request;
      if (!vcs_package_swarm_parse(outbound, outbound_len, &request)) {
        printf("space16 swarm outbound parse failed len=%zu\n", outbound_len);
        return false;
      }
      if (request.type == VCS_PACKAGE_SWARM_CANCEL ||
          request.type == VCS_PACKAGE_SWARM_ANNOUNCE)
        continue;
      if (request.type != VCS_PACKAGE_SWARM_WANT) {
        printf("space16 swarm unexpected type=%u\n", request.type);
        return false;
      }
      uint8_t *bytes = NULL;
      size_t bytes_len = 0;
      enum vcs_package_store_result loaded =
          request.body.want.object_kind ==
                  VCS_PACKAGE_SWARM_OBJECT_MANIFEST
              ? vcs_package_store_get_manifest_wire(
                    observer->provider_store,
                    request.body.want.package_root, &bytes, &bytes_len)
              : vcs_package_store_get_chunk_at(
                    observer->provider_store,
                    request.body.want.package_root,
                    request.body.want.file_index,
                    request.body.want.chunk_index, &bytes, &bytes_len);
      if (loaded != VCS_PACKAGE_STORE_OK ||
          bytes_len > VCS_BLOB_MAX_BYTES) {
        printf("space16 swarm provider load=%s len=%zu kind=%u\n",
               vcs_package_store_result_string(loaded), bytes_len,
               request.body.want.object_kind);
        free(bytes);
        return false;
      }
      struct vcs_package_swarm_message data;
      memset(&data, 0, sizeof(data));
      data.type = VCS_PACKAGE_SWARM_DATA;
      data.body.data.object = request.body.want;
      data.body.data.bytes = bytes;
      data.body.data.bytes_len = (uint32_t)bytes_len;
      size_t capacity = bytes_len + 128u;
      uint8_t *wire = zcl_malloc(capacity, "space16_swarm_data");
      size_t wire_len = 0;
      bool encoded = wire && vcs_package_swarm_serialize(
          &data, wire, capacity, &wire_len);
      free(bytes);
      if (!encoded) {
        printf("space16 swarm data encode failed len=%zu cap=%zu\n",
               bytes_len, capacity);
        free(wire);
        return false;
      }
      struct vcs_swarm_frame_result handled =
          vcs_swarm_engine_handle_frame(
              observer->swarm, peer, wire, wire_len, 0,
              observer->now_ms + round + 1u);
      free(wire);
      free(handled.reply);
      if (handled.penalty != VCS_SWARM_PENALTY_NONE)
        printf("space16 swarm penalty=%u rule=%s\n", handled.penalty,
               handled.rule ? handled.rule : "none");
      if (handled.penalty != VCS_SWARM_PENALTY_NONE)
        return false;
    }
    struct vcs_swarm_download_status status;
    if (!vcs_swarm_engine_download_status(
            observer->swarm, transport, &status)) {
      printf("space16 swarm status absent\n");
      return false;
    }
    if (status.state == VCS_SWARM_DL_COMPLETE)
      return true;
    if (status.state == VCS_SWARM_DL_FAILED) {
      printf("space16 swarm terminal=%s\n",
             status.rule ? status.rule : "unnamed");
      return false;
    }
  }
  printf("space16 swarm rounds exhausted\n");
  return false;
}

static enum vcs_space_scout_manifest_result space16_observe_local(
    struct space16_observer *observer, const uint8_t root[32],
    size_t maximum_wire_bytes, struct vcs_space_manifest_v1 *manifest_out,
    size_t *wire_bytes_out) {
  if (!vcs_object_has(observer->workspace, root))
    return VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
  char root_hex[65];
  zcl_hex_encode(root, 32, root_hex);
  struct metaverse_space_object object;
  struct zcl_result shown = metaverse_space_show_bounded(
      observer->workspace, root_hex, maximum_wire_bytes, &object,
      wire_bytes_out);
  if (!shown.ok && strcmp(shown.message, "space-show-byte-limit") == 0)
    return VCS_SPACE_SCOUT_MANIFEST_BYTE_LIMIT;
  if (!shown.ok)
    return VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
  if (object.kind != METAVERSE_SPACE_OBJECT_MANIFEST)
    return VCS_SPACE_SCOUT_MANIFEST_INVALID;
  struct vcs_space_manifest_verify_context verify = {
      .now_unix = observer->observation_unix,
      .chain_verify = chain_ok,
  };
  memcpy(verify.network_genesis, observer->genesis, 32);
  if (vcs_space_manifest_verify(&object.as.manifest, &verify) != VCS_SPACE_OK)
    return VCS_SPACE_SCOUT_MANIFEST_CHAIN_DENIED;
  *manifest_out = object.as.manifest;
  return VCS_SPACE_SCOUT_MANIFEST_VERIFIED;
}

static enum vcs_space_scout_manifest_result space16_observe(
    void *opaque, const uint8_t root[32], size_t maximum_wire_bytes,
    struct vcs_space_manifest_v1 *manifest_out, size_t *wire_bytes_out) {
  struct space16_observer *observer = opaque;
  observer->observe_calls++;
  *wire_bytes_out = 0;
  if (!space16_policy_allows(
          observer, VCS_ZCODE_SOVEREIGNTY_DISCOVER, root, NULL, NULL) ||
      !space16_policy_allows(
          observer, VCS_ZCODE_SOVEREIGNTY_FETCH, root, NULL, NULL))
    return VCS_SPACE_SCOUT_MANIFEST_POLICY_DENIED;
  if (memcmp(root, observer->dead_root, 32) == 0)
    return VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
  enum vcs_space_scout_manifest_result local = space16_observe_local(
      observer, root, maximum_wire_bytes, manifest_out, wire_bytes_out);
  if (local != VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND)
    return local;

  struct vcs_zcode_dht_record_selector pointer_selector = {
      .kind = VCS_ZCODE_DHT_RECORD_POINTER};
  (void)snprintf(pointer_selector.namespace_name,
                 sizeof(pointer_selector.namespace_name),
                 "space.manifest");
  memcpy(pointer_selector.root, root, 32);
  struct vcs_zcode_dht_record_discovery_result pointers;
  if (!multi_discover_records(
          observer->network, observer->origin, &pointer_selector,
          &pointers))
    return VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
  for (size_t i = 0; i < pointers.record_count; i++) {
    struct vcs_zcode_dht_record *pointer = &pointers.records[i];
    if (vcs_zcode_dht_record_conflicted_at(
            pointers.records, pointers.record_count, i) ||
        vcs_zcode_dht_record_superseded_at(
            pointers.records, pointers.record_count, i) ||
        !space16_policy_allows(
            observer, VCS_ZCODE_SOVEREIGNTY_FETCH, root,
            pointer->transport_root,
            pointer->delegation.doc.master_pubkey))
      continue;
    struct vcs_zcode_dht_record_selector provider_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_PROVIDER};
    (void)snprintf(provider_selector.namespace_name,
                   sizeof(provider_selector.namespace_name),
                   "space.manifest");
    memcpy(provider_selector.root, pointer->transport_root, 32);
    struct vcs_zcode_dht_record_discovery_result providers;
    if (!multi_discover_records(
            observer->network, observer->origin, &provider_selector,
            &providers))
      continue;
    struct vcs_zcode_dht_provider_route route;
    if (!vcs_zcode_dht_service_provider_route(
            observer->network->service[observer->origin],
            observer->network->now.wall_unix, &provider_selector, &route) ||
        !route.authenticated_count)
      continue;
    if (!space16_swarm_fetch(
            observer, pointer->transport_root, route.peer_ids,
            route.authenticated_count, maximum_wire_bytes))
      continue;
    char semantic_hex[65], transport_hex[65];
    zcl_hex_encode(root, 32, semantic_hex);
    zcl_hex_encode(pointer->transport_root, 32, transport_hex);
    enum metaverse_space_object_kind kind;
    bool is_new = false;
    struct zcl_result admitted = metaverse_space_admit_bounded(
        observer->local_store, observer->workspace, semantic_hex,
        transport_hex, maximum_wire_bytes, &kind, &is_new);
    if (!admitted.ok || kind != METAVERSE_SPACE_OBJECT_MANIFEST)
      continue;
    return space16_observe_local(
        observer, root, maximum_wire_bytes, manifest_out, wire_bytes_out);
  }
  return VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
}

static uint64_t space16_clock(void *opaque) {
  struct space16_observer *observer = opaque;
  return observer->now_ms;
}

static bool space16_store_allowed(void *opaque, const uint8_t root[32],
                                  const char *service_type) {
  struct space16_observer *observer = opaque;
  (void)service_type;
  return observer && root &&
         space16_policy_allows(
             observer, VCS_ZCODE_SOVEREIGNTY_STORE, root, NULL, NULL) &&
         space16_policy_allows(
             observer, VCS_ZCODE_SOVEREIGNTY_INDEX, root, NULL, NULL);
}

static bool multi_discover_records(
    struct multi_network *net, size_t origin,
    const struct vcs_zcode_dht_record_selector *selector,
    struct vcs_zcode_dht_record_discovery_result *out) {
  net->now.monotonic_s += 61u;
  uint64_t operation = 0;
  if (!vcs_zcode_dht_service_record_discovery_begin(
          net->service[origin], selector, net->now, &operation) ||
      !multi_drive(net) ||
      !vcs_zcode_dht_service_record_discovery_poll(
          net->service[origin], operation, net->now, out))
    return false;
  for (size_t drive = 0;
       drive < 2 * VCS_ZCODE_DHT_K &&
       out->state == VCS_ZCODE_DHT_RECORD_OPERATION_PENDING; drive++) {
    if (!multi_drive(net) ||
        !vcs_zcode_dht_service_record_discovery_poll(
            net->service[origin], operation, net->now, out))
      return false;
  }
  return out->state == VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE;
}

static int test_publication_monotonic_retry(void) {
  int failures = 0;
  TEST("zcode dht service: publication retry ignores wall-clock jumps") {
    char dir[] = "/tmp/zcl_dht_publication_clock_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    uint8_t genesis[32], noise[32];
    memset(genesis, 0x11, sizeof(genesis));
    memset(noise, 0x42, sizeof(noise));
    ASSERT(fixture_identity(dir, 0x69, genesis, noise));
    struct vcs_zcode_dht_service *service =
        fixture_service_at(dir, genesis, noise, 1000);
    ASSERT(service != NULL);
    struct vcs_zcode_dht_publish_spec spec;
    memset(&spec, 0, sizeof(spec));
    spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                   "science");
    memset(spec.semantic_root, 0x71, 32);
    memset(spec.transport_root, 0x72, 32);
    spec.sequence = 1;
    spec.not_before = 1000;
    spec.expiry = 1300;
    uint8_t token[32];
    struct vcs_zcode_dht_record record;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    struct vcs_zcode_dht_time now = test_time(1000);
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    struct vcs_zcode_dht_service_status status;
    for (size_t i = 0; i < 4; i++) {
      now.monotonic_s++;
      vcs_zcode_dht_service_tick(service, now);
    }
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.active_publications, 0);

    /* Delegation expiry makes renewal fail and arms a 30-second monotonic
     * retry. Neither a huge forward wall jump nor a backward jump may make
     * that queue run early. */
    now.wall_unix = 89999;
    now.monotonic_s = 1100;
    vcs_zcode_dht_service_tick(service, now);
    struct vcs_zcode_dht_publication_test_view retry_view;
    ASSERT(vcs_zcode_dht_service_test_publication_retry(
        service, spec.semantic_root, &retry_view));
    ASSERT_EQ(retry_view.next_attempt_mono, 1130);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.active_publications, 0);
    now.wall_unix = 900000;
    now.monotonic_s = 1101;
    vcs_zcode_dht_service_tick(service, now);
    ASSERT(vcs_zcode_dht_service_test_publication_retry(
        service, spec.semantic_root, &retry_view));
    ASSERT_EQ(retry_view.next_attempt_mono, 1130);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.active_publications, 0);
    now.wall_unix = 1;
    now.monotonic_s = 1129;
    vcs_zcode_dht_service_tick(service, now);
    ASSERT(vcs_zcode_dht_service_test_publication_retry(
        service, spec.semantic_root, &retry_view));
    ASSERT_EQ(retry_view.next_attempt_mono, 1130);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.active_publications, 0);
    now.monotonic_s = 1130;
    vcs_zcode_dht_service_tick(service, now);
    ASSERT(vcs_zcode_dht_service_test_publication_retry(
        service, spec.semantic_root, &retry_view));
    ASSERT_EQ(retry_view.next_attempt_mono, 0);

    vcs_zcode_dht_service_free(service, now);
    cleanup_fixture(dir);
    PASS();
  }
_test_next:;
  return failures;
}

/* A record whose own window is legal but extends past the loaded delegation
 * is an operator mistake with its own remedy — re-delegate or shorten the
 * window — and the refusal must say which, both through the record error and
 * without disturbing DHT_DISABLED's meaning at the RPC edge. */
static int test_publication_delegation_window(void) {
  int failures = 0;
  TEST("zcode dht service: delegation-window refusal names itself") {
    char dir[] = "/tmp/zcl_dht_publication_window_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    uint8_t genesis[32], noise[32];
    memset(genesis, 0x11, sizeof(genesis));
    memset(noise, 0x42, sizeof(noise));
    /* fixture_identity delegates [1000, 90000]. */
    ASSERT(fixture_identity(dir, 0x6a, genesis, noise));
    struct vcs_zcode_dht_service *service =
        fixture_service_at(dir, genesis, noise, 1000);
    ASSERT(service != NULL);
    struct vcs_zcode_dht_publish_spec spec;
    memset(&spec, 0, sizeof(spec));
    spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                   "science");
    memset(spec.semantic_root, 0x73, 32);
    memset(spec.transport_root, 0x74, 32);
    spec.sequence = 1;
    spec.not_before = 1000;
    spec.expiry = 91000; /* legal for a pointer, past the delegation. */
    uint8_t token[32];
    struct vcs_zcode_dht_record record;
    enum vcs_zcode_dht_record_error reason = VCS_ZCODE_DHT_RECORD_OK;
    ASSERT(!vcs_zcode_dht_service_record_publish_plan(service, &spec, token,
                                                      &record, &reason));
    ASSERT_EQ(reason, VCS_ZCODE_DHT_RECORD_DELEGATION_WINDOW);
    ASSERT_STR_EQ(vcs_zcode_dht_record_error_string(reason),
                  "delegation-window-coverage");
    /* The refusal is about coverage, not the record's own shape: a window
     * the delegation covers plans fine with the same inputs otherwise. */
    spec.expiry = 90000;
    reason = VCS_ZCODE_DHT_RECORD_SIGNER;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(service, &spec, token,
                                                     &record, &reason));
    ASSERT_EQ(reason, VCS_ZCODE_DHT_RECORD_OK);
    vcs_zcode_dht_service_free(service, test_time(1000));
    cleanup_fixture(dir);
    PASS();
  }
_test_next:;
  return failures;
}

/* Auto-sequencing: spec.sequence == 0 means "the service picks max+1 from
 * its own store, under its lock". Two renewals of one stream planned from
 * the same store state both derive the same next sequence, but only the
 * first commit can land: the second commit's rebuild sees the advanced
 * store, derives one higher, and the token comparison refuses STALE before
 * anything is admitted. Client-side max+1 derivations raced the store's
 * visibility lag instead, committed duplicate sequences, and left BOTH
 * records of a real provider stream conflicted and unusable. */
static int test_publication_auto_sequence(void) {
  int failures = 0;
  TEST("zcode dht service: publish plan derives sequence server-side") {
    char dir[] = "/tmp/zcl_dht_publication_autoseq_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    uint8_t genesis[32], noise[32];
    memset(genesis, 0x11, sizeof(genesis));
    memset(noise, 0x42, sizeof(noise));
    ASSERT(fixture_identity(dir, 0x6b, genesis, noise));
    struct vcs_zcode_dht_service *service =
        fixture_service_at(dir, genesis, noise, 1000);
    ASSERT(service != NULL);
    struct vcs_zcode_dht_publish_spec spec;
    memset(&spec, 0, sizeof(spec));
    spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                   "science");
    memset(spec.semantic_root, 0x75, 32);
    memset(spec.transport_root, 0x76, 32);
    spec.not_before = 1000;
    spec.expiry = 1400;
    struct vcs_zcode_dht_time now = test_time(1000);
    uint8_t token[32], raced_token[32];
    struct vcs_zcode_dht_record record;

    /* An empty stream derives sequence 1, and the plan's record_out reports
     * the derived number so an operator sees exactly what was signed. */
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(record.sequence, 1);
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);

    /* A second auto publication derives max+1 = 2. */
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(record.sequence, 2);
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);

    /* The incident: two plans from the same store state both derive 3. The
     * first commit lands; the second one's rebuild sees the advanced store,
     * derives 4, and its plan token no longer matches — STALE, refused
     * before the store ever sees a second sequence-3 record. */
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(record.sequence, 3);
    memcpy(raced_token, token, 32);
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(record.sequence, 3);
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, raced_token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, raced_token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_STALE);

    /* The losing operator replans — against the advanced store that now
     * holds 3, so the fresh plan derives 4 and commits cleanly. No
     * duplicate-sequence conflict is ever admitted. */
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(record.sequence, 4);
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);

    /* Explicit pinning still works and still supersedes by number. */
    spec.sequence = 9;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(record.sequence, 9);
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    /* After sequence 9, auto derives 10 — the store max, not plan count. */
    spec.sequence = 0;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(record.sequence, 10);

    vcs_zcode_dht_service_free(service, now);
    cleanup_fixture(dir);
    PASS();
  }
_test_next:;
  return failures;
}

/* Publication slots are the node's renewal intentions, capped at
 * VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS. Two leaks once filled the whole
 * table with historical sequences of streams still alive elsewhere in it:
 * a commit always claimed a FRESH slot even when the same stream already
 * had one — every out-of-band renewal of a live stream cost a slot
 * forever — and a superseded slot kept retrying renewals the store refuses
 * as STALE, never noticing another record of its stream had won. On a real
 * host the table hit 16/16 and every NEW publish on the node was refused
 * "global-cap" while the dead slots spun on futile retries. */
static int test_publication_slot_supersede(void) {
  int failures = 0;
  TEST("zcode dht service: a renewal replaces its slot even at a full table") {
    char dir[] = "/tmp/zcl_dht_publication_slots_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    uint8_t genesis[32], noise[32];
    memset(genesis, 0x11, sizeof(genesis));
    memset(noise, 0x42, sizeof(noise));
    ASSERT(fixture_identity(dir, 0x6c, genesis, noise));
    struct vcs_zcode_dht_service *service =
        fixture_service_at(dir, genesis, noise, 1000);
    ASSERT(service != NULL);
    struct vcs_zcode_dht_time now = test_time(1000);
    struct vcs_zcode_dht_publish_spec spec;
    uint8_t token[32];
    struct vcs_zcode_dht_record record;
    struct vcs_zcode_dht_service_status status;

    /* One live stream, renewed out-of-band the way an operator's script
     * does. Every commit must REPLACE the stream's intention, never add a
     * second one beside it. */
    for (uint64_t seq = 1; seq <= 3; seq++) {
      memset(&spec, 0, sizeof(spec));
      spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
      (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                     "science");
      memset(spec.semantic_root, 0x77, 32);
      memset(spec.transport_root, 0x78, 32);
      spec.sequence = seq;
      spec.not_before = 1000;
      spec.expiry = 1300;
      ASSERT(vcs_zcode_dht_service_record_publish_plan(
          service, &spec, token, &record, NULL));
      ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                    service, &spec, token, now, &record, NULL),
                VCS_ZCODE_DHT_RECORD_STORE_ADDED);
      vcs_zcode_dht_service_status(service, &status);
      ASSERT_EQ(status.publication_intents, 1);
    }

    /* Fill every remaining slot with its OWN stream — the table a busy
     * host actually runs. */
    for (unsigned i = 1; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++) {
      memset(&spec, 0, sizeof(spec));
      spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
      (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                     "science");
      memset(spec.semantic_root, (int)(0x90u + i), 32);
      memset(spec.transport_root, (int)(0xb0u + i), 32);
      spec.sequence = 1;
      spec.not_before = 1000;
      spec.expiry = 1300;
      ASSERT(vcs_zcode_dht_service_record_publish_plan(
          service, &spec, token, &record, NULL));
      ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                    service, &spec, token, now, &record, NULL),
                VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    }
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents,
              VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS);

    /* The incident state: a full table must still accept a renewal of a
     * stream it already holds. Before slot superseding, this was the
     * "global-cap" refusal that left a full host unable to re-publish. */
    memset(&spec, 0, sizeof(spec));
    spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                   "science");
    memset(spec.semantic_root, 0x77, 32);
    memset(spec.transport_root, 0x78, 32);
    spec.sequence = 4;
    spec.not_before = 1000;
    spec.expiry = 1300;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents,
              VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS);

    /* The ceiling is still a ceiling for a genuinely new stream — and it
     * names the table that is actually full. */
    memset(&spec, 0, sizeof(spec));
    spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                   "science");
    memset(spec.semantic_root, 0x7a, 32);
    memset(spec.transport_root, 0x7b, 32);
    spec.sequence = 1;
    spec.not_before = 1000;
    spec.expiry = 1300;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT);
    ASSERT_STR_EQ(vcs_zcode_dht_record_store_result_string(
                      VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT),
                  "no free publication slot");

    vcs_zcode_dht_service_free(service, now);
    cleanup_fixture(dir);
    PASS();
  }
_test_next:;
  return failures;
}

/* A slot superseded by a higher sequence of its own stream is dead weight:
 * every renewal it can attempt is STALE by definition. The drive loop must
 * free it — which is also what heals an intent file polluted before commits
 * learned to supersede in place: the first tick after boot drops the
 * historical sequences the persisted file restored. */
static int test_publication_slot_superseded_freed(void) {
  int failures = 0;
  TEST("zcode dht service: a superseded intention frees on the next tick") {
    char dir[] = "/tmp/zcl_dht_publication_heal_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    uint8_t genesis[32], noise[32];
    memset(genesis, 0x11, sizeof(genesis));
    memset(noise, 0x42, sizeof(noise));
    ASSERT(fixture_identity(dir, 0x6d, genesis, noise));
    struct vcs_zcode_dht_service *service =
        fixture_service_at(dir, genesis, noise, 1000);
    ASSERT(service != NULL);
    struct vcs_zcode_dht_time now = test_time(1000);
    struct vcs_zcode_dht_publish_spec spec;
    uint8_t token[32];
    struct vcs_zcode_dht_record record;
    struct vcs_zcode_dht_service_status status;
    memset(&spec, 0, sizeof(spec));
    spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                   "science");
    memset(spec.semantic_root, 0x79, 32);
    memset(spec.transport_root, 0x7c, 32);
    spec.sequence = 1;
    spec.not_before = 1000;
    spec.expiry = 1300;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents, 1);

    /* Reproduce the polluted table the old commit path and the persisted
     * file produced: a second slot holding the SAME stream at the older
     * sequence, parked where no API can displace it. */
    size_t live = VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS,
           twin = VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS;
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
      if (service->publications[i].used)
        live = i;
    ASSERT(live < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS);
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
      if (!service->publications[i].used) {
        twin = i;
        break;
      }
    ASSERT(twin < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS);
    service->publications[twin] = service->publications[live];
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents, 2);

    /* A higher sequence of the stream lands through the normal path; the
     * stale twin cannot survive the tick that follows. */
    spec.sequence = 2;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    vcs_zcode_dht_service_tick(service, now);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents, 1);

    vcs_zcode_dht_service_free(service, now);
    cleanup_fixture(dir);
    PASS();
  }
_test_next:;
  return failures;
}

/* The runtime twin of this heal (test_publication_slot_superseded_freed)
 * crafts the polluted table in memory and ticks it. But the incident that
 * mattered lived on disk: binaries from before commits learned to supersede
 * in place wrote an intent file holding HISTORICAL sequences of streams
 * still alive elsewhere in the table, and every restart faithfully restored
 * the pollution. The first schedule after boot must heal what load actually
 * produced — the file's bytes, not a runtime-crafted array. */
static int test_publication_heal_survives_restart(void) {
  int failures = 0;
  TEST("zcode dht service: the intent file heals its pollution after restart") {
    char dir[] = "/tmp/zcl_dht_publication_restart_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    uint8_t genesis[32], noise[32];
    memset(genesis, 0x11, sizeof(genesis));
    memset(noise, 0x42, sizeof(noise));
    ASSERT(fixture_identity(dir, 0x6f, genesis, noise));
    struct vcs_zcode_dht_service *service =
        fixture_service_at(dir, genesis, noise, 1000);
    ASSERT(service != NULL);
    struct vcs_zcode_dht_time now = test_time(1000);
    struct vcs_zcode_dht_publish_spec spec;
    uint8_t token[32];
    struct vcs_zcode_dht_record record, first;
    struct vcs_zcode_dht_service_status status;
    memset(&spec, 0, sizeof(spec));
    spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                   "science");
    memset(spec.semantic_root, 0xa1, 32);
    memset(spec.transport_root, 0xa2, 32);
    spec.sequence = 1;
    spec.not_before = 1000;
    spec.expiry = 1300;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    first = record;
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents, 1);

    /* The stream renews through the public path: the live slot now holds
     * sequence 2 and the record store — persisted beside the intents by the
     * same flush — holds max sequence 2 for the stream. */
    spec.sequence = 2;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &spec, token, &record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &spec, token, now, &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents, 1);

    /* Stage the file a pre-supersede binary would have written: a second
     * slot of the SAME stream parked at the historical sequence 1, where no
     * API can displace it (a commit reuses only a slot it supersedes). The
     * struct copy bypasses the writer, so mark the intents dirty the way
     * every real mutation does — free only flushes a dirty table. Only the
     * record and lifetime reach the file; the copied cycle state does not,
     * and load rebuilds each entry at NEEDS_LOOKUP. */
    size_t live = VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS,
           twin = VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS;
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
      if (service->publications[i].used)
        live = i;
    ASSERT(live < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS);
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
      if (!service->publications[i].used) {
        twin = i;
        break;
      }
    ASSERT(twin < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS);
    service->publications[twin] = service->publications[live];
    service->publications[twin].record = first;
    publication_mark_dirty(service, now.monotonic_s);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents, 2);

    /* Restart on the same datadir: free flushes the polluted pair through
     * the same publications.v1 a real host reboots through, and create
     * restores BOTH records — load does not deduplicate a stream. */
    vcs_zcode_dht_service_free(service, now);
    service = fixture_service_at(dir, genesis, noise, 1000);
    ASSERT(service != NULL);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents, 2);

    /* The first tick is also the first schedule since boot: the slot healed
     * out must be the historical sequence the FILE restored, judged against
     * the record store the same restart reloaded. */
    vcs_zcode_dht_service_tick(service, now);
    vcs_zcode_dht_service_status(service, &status);
    ASSERT_EQ(status.publication_intents, 1);
    size_t kept = VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS;
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++)
      if (service->publications[i].used)
        kept = i;
    ASSERT(kept < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS);
    ASSERT_EQ(service->publications[kept].record.sequence, 2);

    vcs_zcode_dht_service_free(service, now);
    cleanup_fixture(dir);
    PASS();
  }
_test_next:;
  return failures;
}

/* Superseding a slot mid-cycle must cancel the cycle, not just overwrite it.
 * A slot mid-ROUTING holds a live lookup id (and mid-STORING holds child
 * operation ids); the lookup and operation tables free only when their owner
 * polls or cancels — an id wiped from its owner's slot is neither, so the
 * entry strands until restart. Eight stranded lookups wedge the lookup table
 * exactly the way publication slots used to wedge. With one authenticated
 * peer, a commit's routing lookup is genuinely live (its FIND_NODE is
 * outstanding), which is the real incident state: renew out-of-band while
 * the cycle is routing. */
static int test_publication_supersede_cancels_children(void) {
  int failures = 0;
  TEST("zcode dht service: superseding a live cycle frees its lookup") {
    char adir[] = "/tmp/zcl_dht_pub_cancel_a_XXXXXX";
    char bdir[] = "/tmp/zcl_dht_pub_cancel_b_XXXXXX";
    ASSERT(mkdtemp(adir) != NULL && mkdtemp(bdir) != NULL);
    uint8_t genesis[32], anoise[32], bnoise[32], transcript[32];
    memset(genesis, 0x11, 32);
    memset(anoise, 0x26, 32);
    memset(bnoise, 0x27, 32);
    memset(transcript, 0x5e, 32);
    ASSERT(fixture_identity(adir, 0x6e, genesis, anoise));
    ASSERT(fixture_identity(bdir, 0x6f, genesis, bnoise));
    struct vcs_zcode_dht_service *a =
        fixture_service_at(adir, genesis, anoise, 1000);
    struct vcs_zcode_dht_service *b =
        fixture_service_at(bdir, genesis, bnoise, 1000);
    ASSERT(a != NULL && b != NULL);
    struct vcs_zcode_dht_session as = {.established = true,
                                       .generation = 7,
                                       .connection_serial = 1};
    struct vcs_zcode_dht_session bs = as;
    bs.connection_serial = 2;
    memcpy(as.remote_static, bnoise, 32);
    memcpy(bs.remote_static, anoise, 32);
    memcpy(as.transcript_hash, transcript, 32);
    memcpy(bs.transcript_hash, transcript, 32);
    ASSERT(vcs_zcode_dht_service_session_open(a, 2, &as, test_time(1001)));
    ASSERT(vcs_zcode_dht_service_session_open(b, 1, &bs, test_time(1001)));
    ASSERT(pump(a, b, 2, 1, 1001, NULL, NULL));
    ASSERT(pump(b, a, 1, 2, 1001, NULL, NULL));
    ASSERT(pump(a, b, 2, 1, 1001, NULL, NULL));

    struct vcs_zcode_dht_publish_spec spec;
    uint8_t token[32];
    struct vcs_zcode_dht_record record;
    struct vcs_zcode_dht_service_status status;
    memset(&spec, 0, sizeof(spec));
    spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                   "science");
    memset(spec.semantic_root, 0x7d, 32);
    memset(spec.transport_root, 0x7e, 32);
    spec.sequence = 1;
    spec.not_before = 1001;
    spec.expiry = 1301;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        a, &spec, token, &record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  a, &spec, token, test_time(1001), &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    vcs_zcode_dht_service_status(a, &status);
    ASSERT_EQ(status.publication_intents, 1);
    /* The commit's own schedule left the intent mid-ROUTING: one live
     * lookup whose FIND_NODE to the peer is still outstanding. */
    ASSERT_EQ(status.queued_lookups, 1u);
    ASSERT_EQ(status.active_record_operations, 0u);

    /* Renew out-of-band while that cycle is live. The overwritten slot must
     * hand its lookup back; the successor then begins exactly one of its
     * own. A stranded predecessor makes this two. */
    spec.sequence = 2;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        a, &spec, token, &record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  a, &spec, token, test_time(1002), &record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    vcs_zcode_dht_service_status(a, &status);
    ASSERT_EQ(status.publication_intents, 1);
    ASSERT_EQ(status.queued_lookups, 1u);
    ASSERT_EQ(status.active_record_operations, 0u);

    /* And it holds across ticks — a lookup nothing polls keeps its slot
     * forever, so a stranded one would resurface here as 2. */
    for (unsigned i = 0; i < 3; i++)
      vcs_zcode_dht_service_tick(a, test_time(1003 + i));
    vcs_zcode_dht_service_status(a, &status);
    ASSERT_EQ(status.queued_lookups, 1u);
    ASSERT_EQ(status.active_record_operations, 0u);

    vcs_zcode_dht_service_free(a, test_time(1006));
    vcs_zcode_dht_service_free(b, test_time(1006));
    cleanup_fixture(adir);
    cleanup_fixture(bdir);
    PASS();
  }
_test_next:;
  return failures;
}

/* The ceiling on how many records ONE node keeps announced is not an abstract
 * number: it decides whether a node can host the product's own demo. The
 * multi-host commons journey measured the floor at eleven records for five
 * things (a library, an application, that application's source, a second
 * library, and a changed package), because a package costs a POINTER plus a
 * PROVIDER and an independently re-derivable source costs a third. At eight
 * the ninth publish was refused `global-cap` and the journey could not finish.
 *
 * So this pins BOTH halves: the ceiling is high enough for that measured
 * floor, and it is still a ceiling that fails closed rather than growing. */
static int test_publication_ceiling_hosts_a_real_node(void) {
  int failures = 0;
  TEST("zcode dht service: the announce ceiling fits a package host, and holds") {
    /* Not >= 11 by accident: below this a node cannot announce the journey
     * `make commons-multihost-acceptance` runs, and the refusal would be
     * correct while the product would be wrong. */
    ASSERT(VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS >= 11u);
    char dir[] = "/tmp/zcl_dht_publication_ceiling_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    uint8_t genesis[32], noise[32];
    memset(genesis, 0x11, sizeof(genesis));
    memset(noise, 0x42, sizeof(noise));
    ASSERT(fixture_identity(dir, 0x69, genesis, noise));
    struct vcs_zcode_dht_service *service =
        fixture_service_at(dir, genesis, noise, 1000);
    ASSERT(service != NULL);
    struct vcs_zcode_dht_time now = test_time(1000);
    /* One distinct record stream per slot: distinct semantic roots, so none
     * of these is an update of another and each must take its own slot. */
    for (unsigned i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PUBLICATIONS; i++) {
      struct vcs_zcode_dht_publish_spec spec;
      uint8_t token[32];
      struct vcs_zcode_dht_record record;
      memset(&spec, 0, sizeof(spec));
      spec.kind = VCS_ZCODE_DHT_RECORD_POINTER;
      (void)snprintf(spec.namespace_name, sizeof(spec.namespace_name),
                     "science");
      memset(spec.semantic_root, (int)(0x80u + i), 32);
      memset(spec.transport_root, (int)(0xc0u + i), 32);
      spec.sequence = 1;
      spec.not_before = 1000;
      spec.expiry = 1300;
      ASSERT(vcs_zcode_dht_service_record_publish_plan(
          service, &spec, token, &record, NULL));
      ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                    service, &spec, token, now, &record, NULL),
                VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    }
    /* The ceiling is still a ceiling, and it says so by name: NO_SLOT, the
     * intent table — not GLOBAL_CAP, which names the record store's much
     * higher cap and sends an operator to the wrong table. */
    struct vcs_zcode_dht_publish_spec over;
    uint8_t over_token[32];
    struct vcs_zcode_dht_record over_record;
    memset(&over, 0, sizeof(over));
    over.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(over.namespace_name, sizeof(over.namespace_name),
                   "science");
    memset(over.semantic_root, 0x7f, 32);
    memset(over.transport_root, 0x7e, 32);
    over.sequence = 1;
    over.not_before = 1000;
    over.expiry = 1300;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        service, &over, over_token, &over_record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  service, &over, over_token, now, &over_record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT);
    ASSERT_STR_EQ(vcs_zcode_dht_record_store_result_string(
                      VCS_ZCODE_DHT_RECORD_STORE_NO_SLOT),
                  "no free publication slot");

    vcs_zcode_dht_service_free(service, now);
    cleanup_fixture(dir);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_record_churn_fallback(void) {
  int failures = 0;
  TEST("zcode dht service: slow responsible nodes and candidates beyond K") {
    struct multi_network net;
    memset(&net, 0, sizeof(net));
    net.node_count = MULTI_MAX_NODES;
    net.allow_unsolicited = true;
    net.now = test_time(1001);
    uint8_t genesis[32];
    memset(genesis, 0x11, sizeof(genesis));
    for (size_t i = 0; i < net.node_count; i++) {
      (void)snprintf(net.dir[i], sizeof(net.dir[i]),
                     "/tmp/zcl_dht_churn_%zu_XXXXXX", i);
      ASSERT(mkdtemp(net.dir[i]) != NULL);
      memset(net.noise[i], (int)(0x20 + i), 32);
      ASSERT(fixture_identity(net.dir[i], (uint8_t)(0x30 + i), genesis,
                              net.noise[i]));
      ASSERT(fixture_material(net.dir[i],
                              &(struct vcs_zcode_dht_delegation){0},
                              (uint8_t[32]){0}, net.node_id[i]));
      net.reach[i].network = &net;
      net.reach[i].owner = i;
      net.service[i] = multi_service(&net, i, genesis);
      ASSERT(net.service[i] != NULL);
    }
    const size_t origin = 0;
    for (size_t i = 1; i < net.node_count; i++)
      ASSERT(multi_connect(&net, origin, i));
    ASSERT(multi_drive(&net));

    struct vcs_zcode_dht_record_selector selector = {
        .kind = VCS_ZCODE_DHT_RECORD_POINTER};
    (void)snprintf(selector.namespace_name, sizeof(selector.namespace_name),
                   "science.study");
    memset(selector.root, 0xa1, 32);
    uint8_t target[32];
    ASSERT(vcs_zcode_dht_record_key(genesis, selector.kind,
                                    selector.namespace_name, selector.root,
                                    target));
    size_t all_order[MULTI_MAX_NODES];
    for (size_t i = 0; i < net.node_count; i++)
      all_order[i] = i;
    for (size_t i = 0; i + 1 < net.node_count; i++)
      for (size_t j = i + 1; j < net.node_count; j++)
        if (farther_node(net.node_id[all_order[i]],
                         net.node_id[all_order[j]], target)) {
          size_t swap = all_order[i];
          all_order[i] = all_order[j];
          all_order[j] = swap;
        }
    ASSERT(all_order[VCS_ZCODE_DHT_K] != origin);
    size_t failed = all_order[0] == origin ? all_order[1] : all_order[0];
    size_t slow = all_order[VCS_ZCODE_DHT_K];
    struct vcs_zcode_dht_record pointer;
    ASSERT(fixture_pointer_record(net.dir[slow], genesis, 0xa1, 0x33,
                                  &pointer));
    ASSERT_EQ(vcs_zcode_dht_service_record_admit(
                  net.service[slow], &pointer, net.now),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);

    uint64_t operation = 0;
    ASSERT(vcs_zcode_dht_service_record_discovery_begin(
        net.service[origin], &selector, net.now, &operation));
    /* Finish only the routing lookup. Record discovery does not consume the
     * completed lookup until poll(), which gives the fixture an exact
     * routing/query churn boundary. */
    for (size_t turn = 0; turn < 8; turn++) {
      ASSERT(multi_drive(&net));
      vcs_zcode_dht_service_tick(net.service[origin], net.now);
    }
    multi_disconnect(&net, origin, failed);
    net.hold_enabled = true;
    net.hold_from = origin;
    net.hold_to = slow;
    struct vcs_zcode_dht_record_discovery_result discovered;
    memset(&discovered, 0, sizeof(discovered));
    for (size_t turn = 0; turn < 64; turn++) {
      ASSERT(multi_drive(&net));
      ASSERT(vcs_zcode_dht_service_record_discovery_poll(
          net.service[origin], operation, net.now, &discovered));
      if (net.held_used && discovered.nodes_queried > VCS_ZCODE_DHT_K)
        break;
    }
    ASSERT(net.held_used);
    ASSERT(discovered.nodes_queried > VCS_ZCODE_DHT_K);
    ASSERT_EQ(discovered.state, VCS_ZCODE_DHT_RECORD_OPERATION_PENDING);
    ASSERT_EQ(discovered.record_count, 0);
    ASSERT(multi_release_held(&net));
    for (size_t turn = 0;
         turn < 16 &&
         discovered.state == VCS_ZCODE_DHT_RECORD_OPERATION_PENDING;
         turn++) {
      ASSERT(multi_drive(&net));
      ASSERT(vcs_zcode_dht_service_record_discovery_poll(
          net.service[origin], operation, net.now, &discovered));
    }
    ASSERT_EQ(discovered.state, VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE);
    ASSERT(!discovered.incomplete);
    ASSERT_EQ(discovered.record_count, 1);
    ASSERT_EQ(memcmp(discovered.records[0].transport_root,
                     pointer.transport_root, 32), 0);
    ASSERT(multi_connect(&net, origin, failed));
    ASSERT(multi_drive(&net));

    /* Publication retains all authenticated lookup candidates. Lose the
     * closest K after routing completes; candidates 17+ still receive the
     * record, while the cycle remains an honest partial retry rather than a
     * false responsible-set success. */
    struct vcs_zcode_dht_publish_spec publish;
    memset(&publish, 0, sizeof(publish));
    publish.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(publish.namespace_name, sizeof(publish.namespace_name),
                   "science");
    memset(publish.semantic_root, 0xb1, 32);
    memset(publish.transport_root, 0xb2, 32);
    publish.sequence = 1;
    publish.not_before = net.now.wall_unix;
    publish.expiry = net.now.wall_unix + 1000;
    uint8_t token[32];
    struct vcs_zcode_dht_record published;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        net.service[origin], &publish, token, &published, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  net.service[origin], &publish, token, net.now, &published,
                  NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    struct vcs_zcode_dht_publication_test_view churn_view;
    bool lookup_ready = false;
    for (size_t frame = 0; frame < 4096; frame++) {
      bool moved = false;
      ASSERT(multi_drive_one(&net, &moved));
      ASSERT(moved);
      ASSERT(vcs_zcode_dht_service_test_publication_retry(
          net.service[origin], publish.semantic_root, &churn_view));
      if (churn_view.node_count == net.node_count - 1) {
        lookup_ready = true;
        break;
      }
    }
    ASSERT(lookup_ready);
    ASSERT_EQ(churn_view.node_count, net.node_count - 1);
    ASSERT_EQ(churn_view.successes, 0);
    for (size_t i = 0; i < VCS_ZCODE_DHT_K; i++) {
      size_t peer = net.node_count;
      for (size_t candidate = 1; candidate < net.node_count; candidate++)
        if (memcmp(churn_view.node_ids[i], net.node_id[candidate], 32) == 0) {
          peer = candidate;
          break;
      }
      ASSERT(peer < net.node_count);
      net.deny[origin][peer] = true;
      net.deny[peer][origin] = true;
      multi_disconnect(&net, origin, peer);
    }
    for (size_t turn = 0; turn < 32; turn++) {
      vcs_zcode_dht_service_tick(net.service[origin], net.now);
      ASSERT(multi_drive(&net));
    }
    struct vcs_zcode_dht_record_selector published_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_POINTER};
    (void)snprintf(published_selector.namespace_name,
                   sizeof(published_selector.namespace_name), "science");
    memcpy(published_selector.root, publish.semantic_root, 32);
    struct vcs_zcode_dht_record found[1];
    for (size_t i = VCS_ZCODE_DHT_K; i < churn_view.node_count; i++) {
      size_t peer = net.node_count;
      for (size_t candidate = 1; candidate < net.node_count; candidate++)
        if (memcmp(churn_view.node_ids[i], net.node_id[candidate], 32) == 0) {
          peer = candidate;
          break;
        }
      ASSERT(peer < net.node_count);
      ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                    net.service[peer], net.now.wall_unix,
                    &published_selector, found, 1),
                1);
    }
    struct vcs_zcode_dht_service_status status;
    vcs_zcode_dht_service_status(net.service[origin], &status);
    ASSERT_EQ(status.active_publications, 0);
    ASSERT(vcs_zcode_dht_service_test_publication_retry(
        net.service[origin], publish.semantic_root, &churn_view));
    ASSERT_EQ(churn_view.succeeded_beyond_k,
              net.node_count - 1 - VCS_ZCODE_DHT_K);

    for (size_t i = 0; i < net.node_count; i++) {
      vcs_zcode_dht_service_free(net.service[i], net.now);
      cleanup_fixture(net.dir[i]);
    }
    PASS();
  }
_test_next:;
  return failures;
}

static int test_disabled_diagnostics(void) {
  int failures = 0;
  TEST("zcode dht service: disabled reasons and diagnostics expose no identity material") {
    char dir[] = "/tmp/zcl_dht_service_disabled_XXXXXX";
    ASSERT(mkdtemp(dir) != NULL);
    struct vcs_zcode_dht_service_params params = {
        .datadir = dir,
        .transport_enabled = false,
        .now = {.wall_unix = 1000, .monotonic_s = 1000},
    };
    memset(params.network_genesis, 0x11, 32);
    memset(params.local_noise_static, 0x22, 32);
    const uint8_t zero_id[32] = {0};
    /* Repeat both early-return paths so the sanitizer lane exercises allocator
     * reuse.  Every public view must stop before routing-table traversal or
     * delegation decoding and must leave caller output untouched. */
    for (size_t round = 0; round < 256; round++) {
      params.transport_enabled = (round & 1u) != 0;
      struct vcs_zcode_dht_service *disabled =
          vcs_zcode_dht_service_create(&params);
      struct vcs_zcode_dht_service_status status;
      struct vcs_zcode_dht_peer_view peers[2], peers_before[2];
      struct vcs_zcode_dht_delegation delegations[2], delegations_before[2];
      ASSERT(disabled != NULL);
      memset(peers, 0xa5, sizeof(peers));
      memcpy(peers_before, peers, sizeof(peers));
      memset(delegations, 0x5a, sizeof(delegations));
      memcpy(delegations_before, delegations, sizeof(delegations));
      memset(&status, 0xcc, sizeof(status));
      vcs_zcode_dht_service_status(disabled, &status);
      ASSERT(!status.enabled);
      ASSERT_STR_EQ(status.disabled_reason,
                    params.transport_enabled
                        ? "IDENTITY_MATERIAL_UNAVAILABLE"
                        : "V2_TRANSPORT_DISABLED");
      ASSERT(memcmp(status.local_node_id, zero_id, sizeof(zero_id)) == 0);
      ASSERT_EQ(status.contacts, 0);
      ASSERT_EQ(status.buckets_used, 0);
      ASSERT_EQ(status.pending_probes, 0);
      ASSERT_EQ(status.active_queries, 0);
      ASSERT_EQ(status.signed_records, 0);
      ASSERT_EQ(vcs_zcode_dht_service_peers(disabled, 1000, peers, 2, 0), 0);
      ASSERT(memcmp(peers, peers_before, sizeof(peers)) == 0);
      ASSERT_EQ(vcs_zcode_dht_service_delegations(disabled, delegations, 2),
                0);
      ASSERT(memcmp(delegations, delegations_before, sizeof(delegations)) ==
             0);
      vcs_zcode_dht_service_free(disabled, test_time(1000));
    }

    struct json_value dump;
    json_init(&dump);
    ASSERT(boot_zcode_dht_dump_state_json(&dump, NULL));
    char rendered[8192];
    size_t rendered_len = json_write(&dump, rendered, sizeof(rendered));
    ASSERT(rendered_len < sizeof(rendered));
    ASSERT(strstr(rendered, "delegation_wire") == NULL);
    ASSERT(strstr(rendered, "master_pubkey") == NULL);
    ASSERT(strstr(rendered, "online_pubkey") == NULL);
    ASSERT(strstr(rendered, "noise_static") == NULL);
    ASSERT(strstr(rendered, "peer_address") == NULL);
    ASSERT_EQ(json_get_int(json_get(&dump, "max_authenticated_peers")), 64);
    ASSERT_EQ(json_get_int(json_get(&dump, "max_active_queries")), 3);
    ASSERT_EQ(json_get_int(json_get(&dump, "buckets_used")), 0);
    ASSERT(!boot_zcode_dht_dump_state_json(&dump, "private"));
    json_free(&dump);
    cleanup_fixture(dir);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_deep_ancestry(void) {
  int failures = 0;
  TEST("zcode dht service: delayed beacon uses logarithmic deep ancestry") {
    struct block_index beacon, tip;
    struct uint256 hash;
    memset(&beacon, 0, sizeof(beacon));
    memset(&tip, 0, sizeof(tip));
    memset(&hash, 0x6d, sizeof(hash));
    beacon.nHeight = 0;
    beacon.phashBlock = &hash;
    tip.nHeight = 524288;
    tip.pskip = &beacon;
    uint64_t span = 0;
    ASSERT(boot_zcode_dht_beacon_matches(&tip, 0, hash.data, &span));
    ASSERT_EQ(span, 524288);
    uint8_t wrong[32];
    memcpy(wrong, hash.data, 32);
    wrong[0] ^= 1;
    ASSERT(!boot_zcode_dht_beacon_matches(&tip, 0, wrong, &span));
    PASS();
  }
_test_next:;
  return failures;
}

static int test_peer_admission_order(void) {
  int failures = 0;
  TEST("zcode dht service: Noise bootstrap waits for version and verack") {
    struct p2p_node node;
    memset(&node, 0, sizeof(node));
    node.transport = (struct v2_transport *)(uintptr_t)1;
    atomic_store(&node.state, PEER_VERSION_RECEIVED);
    ASSERT(!boot_zcode_dht_peer_ready(&node));
    atomic_store(&node.state, PEER_HANDSHAKE_COMPLETE);
    ASSERT(boot_zcode_dht_peer_ready(&node));
    atomic_store(&node.disconnect, true);
    ASSERT(!boot_zcode_dht_peer_ready(&node));
    PASS();
  }
_test_next:;
  return failures;
}

static int test_record_transport_and_restart(void) {
  int failures = 0;
  TEST("zcode dht service: signed records share Noise, bounds and restart") {
    memset(policy_calls, 0, sizeof(policy_calls));
    char adir[] = "/tmp/zcl_dht_records_a_XXXXXX";
    char bdir[] = "/tmp/zcl_dht_records_b_XXXXXX";
    ASSERT(mkdtemp(adir) != NULL && mkdtemp(bdir) != NULL);
    uint8_t genesis[32], anoise[32], bnoise[32], transcript[32];
    memset(genesis, 0x11, 32);
    memset(anoise, 0x22, 32);
    memset(bnoise, 0x33, 32);
    memset(transcript, 0x55, 32);
    ASSERT(fixture_identity(adir, 0x61, genesis, anoise));
    ASSERT(fixture_identity(bdir, 0x62, genesis, bnoise));
    struct vcs_zcode_dht_service *a = fixture_service(adir, genesis, anoise);
    struct vcs_zcode_dht_service *b = fixture_service(bdir, genesis, bnoise);
    ASSERT(a != NULL && b != NULL);
    struct vcs_zcode_dht_session as = {.established = true,
                                       .generation = 42,
                                       .connection_serial = 1};
    struct vcs_zcode_dht_session bs = as;
    bs.connection_serial = 2;
    memcpy(as.remote_static, bnoise, 32);
    memcpy(bs.remote_static, anoise, 32);
    memcpy(as.transcript_hash, transcript, 32);
    memcpy(bs.transcript_hash, transcript, 32);
    ASSERT(vcs_zcode_dht_service_session_open(a, 2, &as, test_time(1001)));
    ASSERT(vcs_zcode_dht_service_session_open(b, 1, &bs, test_time(1001)));
    ASSERT(pump(a, b, 2, 1, 1001, NULL, NULL));
    ASSERT(pump(b, a, 1, 2, 1001, NULL, NULL));
    ASSERT(pump(a, b, 2, 1, 1001, NULL, NULL));

    /* A provider record remains usable across an exact Noise reconnect as
     * soon as the replacement transport is admitted.  The accepting side
     * rechecks the cached signed delegation and its Noise-static binding;
     * it does not wait for a later periodic sweep or bootstrap reply. */
    struct vcs_zcode_dht_record reconnect_provider;
    ASSERT(fixture_provider_record(
        adir, genesis, 0x7a, &reconnect_provider));
    ASSERT_EQ(vcs_zcode_dht_service_record_admit(
                  b, &reconnect_provider, test_time(1001)),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    struct vcs_zcode_dht_record_selector reconnect_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_PROVIDER};
    (void)snprintf(reconnect_selector.namespace_name,
                   sizeof(reconnect_selector.namespace_name), "science");
    memcpy(reconnect_selector.root, reconnect_provider.transport_root, 32);
    struct vcs_zcode_dht_provider_route reconnect_route;
    ASSERT(vcs_zcode_dht_service_provider_route(
        b, 1001, &reconnect_selector, &reconnect_route));
    ASSERT_EQ(reconnect_route.authenticated_count, 1);
    vcs_zcode_dht_service_session_close(b, 1, 42, test_time(1001));
    ASSERT(vcs_zcode_dht_service_provider_route(
        b, 1001, &reconnect_selector, &reconnect_route));
    ASSERT_EQ(reconnect_route.authenticated_count, 0);
    as.generation = bs.generation = 43;
    as.connection_serial = 3;
    bs.connection_serial = 4;
    memset(transcript, 0x56, sizeof(transcript));
    memcpy(as.transcript_hash, transcript, 32);
    memcpy(bs.transcript_hash, transcript, 32);
    ASSERT(vcs_zcode_dht_service_session_open(
        b, 1, &bs, test_time(1001)));
    ASSERT(vcs_zcode_dht_service_provider_route(
        b, 1001, &reconnect_selector, &reconnect_route));
    ASSERT_EQ(reconnect_route.authenticated_count, 1);
    ASSERT(vcs_zcode_dht_service_session_open(
        a, 2, &as, test_time(1001)));
    ASSERT(pump(a, b, 2, 1, 1001, NULL, NULL));
    ASSERT(pump(b, a, 1, 2, 1001, NULL, NULL));

    struct vcs_zcode_dht_publish_spec publish;
    memset(&publish, 0, sizeof(publish));
    publish.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    snprintf(publish.namespace_name, sizeof(publish.namespace_name),
             "science");
    memset(publish.semantic_root, 0x41, 32);
    memset(publish.transport_root, 0x42, 32);
    publish.sequence = 1;
    publish.not_before = 1000;
    publish.expiry = 2000;
    uint8_t plan_token[32];
    struct vcs_zcode_dht_record published_record;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        a, &publish, plan_token, &published_record, NULL));

    /* Unrelated authenticated gossip may arrive between the two operator
     * calls. It changes the global store, but not the intended publication
     * stream, so it must not manufacture a load-sensitive STALE_PLAN. */
    struct vcs_zcode_dht_record unrelated;
    ASSERT(fixture_pointer_record(adir, genesis, 0x62, 0x72, &unrelated));
    ASSERT_EQ(vcs_zcode_dht_service_record_admit(
                  a, &unrelated, test_time(1002)),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  a, &publish, plan_token, test_time(1002), &published_record,
                  NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  a, &publish, plan_token, test_time(1002), &published_record,
                  NULL),
              VCS_ZCODE_DHT_RECORD_STORE_STALE);
    /* The generic publisher refuses evidence kinds without a record-contract
     * complaint — the refusal reason stays OK. */
    publish.kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK;
    enum vcs_zcode_dht_record_error evidence_reason =
        VCS_ZCODE_DHT_RECORD_SIGNER;
    ASSERT(!vcs_zcode_dht_service_record_publish_plan(
        a, &publish, plan_token, &published_record, &evidence_reason));
    ASSERT_EQ(evidence_reason, VCS_ZCODE_DHT_RECORD_OK);
    publish.kind = VCS_ZCODE_DHT_RECORD_POINTER;

    struct vcs_zcode_dht_record first;
    ASSERT(fixture_pointer_record(adir, genesis, 0x61, 0x71, &first));
    ASSERT_EQ(vcs_zcode_dht_service_record_admit(a, &first, test_time(1002)),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    struct vcs_zcode_dht_record_selector selector = {
        .kind = VCS_ZCODE_DHT_RECORD_POINTER};
    (void)snprintf(selector.namespace_name, sizeof(selector.namespace_name),
                   "science.study");
    memcpy(selector.root, first.semantic_root, 32);
    uint64_t operation = 0;
    ASSERT(vcs_zcode_dht_service_record_query_begin(
        b, 1, &selector, test_time(1002), &operation));
    ASSERT(pump(b, a, 1, 2, 1002, NULL, NULL));
    ASSERT(pump(a, b, 2, 1, 1002, NULL, NULL));
    struct vcs_zcode_dht_record_operation_result result;
    ASSERT(vcs_zcode_dht_service_record_operation_poll(
        b, operation, test_time(1002), &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE);
    ASSERT_EQ(result.record_count, 1);
    ASSERT(memcmp(result.records[0].transport_root, first.transport_root, 32) ==
           0);

    /* A responsible peer replaced after routing but before its record page
     * replies makes the discovery explicitly incomplete. Cached records may
     * be retained as evidence, but cannot be promoted to complete evidence. */
    uint64_t discovery = 0;
    ASSERT(vcs_zcode_dht_service_record_discovery_begin(
        b, &selector, test_time(1002), &discovery));
    ASSERT(pump(b, a, 1, 2, 1002, NULL, NULL));
    ASSERT(pump(a, b, 2, 1, 1002, NULL, NULL));
    struct vcs_zcode_dht_record_discovery_result discovery_result;
    ASSERT(vcs_zcode_dht_service_record_discovery_poll(
        b, discovery, test_time(1002), &discovery_result));
    ASSERT_EQ(discovery_result.state,
              VCS_ZCODE_DHT_RECORD_OPERATION_PENDING);
    as.generation = bs.generation = 44;
    as.connection_serial = 5;
    bs.connection_serial = 6;
    memset(transcript, 0x57, sizeof(transcript));
    memcpy(as.transcript_hash, transcript, 32);
    memcpy(bs.transcript_hash, transcript, 32);
    ASSERT(vcs_zcode_dht_service_session_open(b, 1, &bs,
                                               test_time(1002)));
    ASSERT(vcs_zcode_dht_service_session_open(a, 2, &as,
                                               test_time(1002)));
    ASSERT(vcs_zcode_dht_service_record_discovery_poll(
        b, discovery, test_time(1002), &discovery_result));
    ASSERT_EQ(discovery_result.state,
              VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE);
    ASSERT(discovery_result.incomplete);
    ASSERT(!discovery_result.truncated);
    ASSERT(pump(a, b, 2, 1, 1002, NULL, NULL));
    ASSERT(pump(b, a, 1, 2, 1002, NULL, NULL));
    ASSERT(pump(a, b, 2, 1, 1002, NULL, NULL));

    struct vcs_zcode_dht_record second;
    ASSERT(fixture_pointer_record(adir, genesis, 0x62, 0x72, &second));
    ASSERT(vcs_zcode_dht_service_record_store_begin(
        a, 2, &second, test_time(1003), &operation));
    uint8_t replay[VCS_ZCODE_DHT_MAX_FRAME_BYTES];
    size_t replay_len = 0;
    ASSERT(pump(a, b, 2, 1, 1003, replay, &replay_len));
    ASSERT(pump(b, a, 1, 2, 1003, NULL, NULL));
    ASSERT(vcs_zcode_dht_service_record_operation_poll(
        a, operation, test_time(1003), &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE);
    ASSERT_EQ(result.store_status, VCS_ZCODE_DHT_STORE_STORED);
    enum vcs_zcode_dht_reject_reason rejected;
    ASSERT(!vcs_zcode_dht_service_handle_frame(
        b, 1, replay, replay_len, test_time(1003), &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_REPLAY);
    memset(selector.root, 0x62, 32);
    struct vcs_zcode_dht_record local[1];
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  b, 1003, &selector, local, 1),
              1);

    /* Record work cannot escape the three shared authenticated query slots,
     * and all three name their monotonic deadline when no reply arrives. */
    uint64_t pending[VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES];
    memset(selector.root, 0x63, 32);
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++)
      ASSERT(vcs_zcode_dht_service_record_query_begin(
          b, 1, &selector, test_time(1004), &pending[i]));
    ASSERT(!vcs_zcode_dht_service_record_query_begin(
        b, 1, &selector, test_time(1004), &operation));
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES; i++) {
      ASSERT(vcs_zcode_dht_service_record_operation_poll(
          b, pending[i], test_time(1010), &result));
      ASSERT_EQ(result.state, VCS_ZCODE_DHT_RECORD_OPERATION_TIMEOUT);
    }

    vcs_zcode_dht_service_free(b, test_time(1004));
    b = fixture_service(bdir, genesis, bnoise);
    ASSERT(b != NULL);
    memset(selector.root, 0x62, 32);
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  b, 1004, &selector, local, 1),
              1);
    ASSERT(policy_calls[VCS_ZCODE_SOVEREIGNTY_DISCOVER] > 0);
    ASSERT(policy_calls[VCS_ZCODE_SOVEREIGNTY_STORE] > 0);
    ASSERT(policy_calls[VCS_ZCODE_SOVEREIGNTY_INDEX] > 0);
    ASSERT(policy_calls[VCS_ZCODE_SOVEREIGNTY_SERVE] > 0);
    ASSERT(policy_calls[VCS_ZCODE_SOVEREIGNTY_FORWARD] > 0);

    /* ACK authorship crosses the real package-store possession gate. The
     * intent survives restart without a private key, but losing the pin
     * makes its next renewal fail closed while the last signed ACK simply
     * ages toward expiry. */
    char ack_dir[] = "/tmp/zcl_dht_ack_store_XXXXXX";
    ASSERT(mkdtemp(ack_dir) != NULL);
    struct vcs_package_store *ack_store =
        vcs_package_store_open(ack_dir, UINT64_C(4) * 1024 * 1024);
    ASSERT(ack_store != NULL);
    static const uint8_t ack_bytes[] = "possession-backed-storage-ack";
    uint8_t ack_root[32];
    ASSERT_EQ(vcs_blob_put_to(ack_store, ack_bytes, sizeof(ack_bytes),
                              ack_root),
              VCS_BLOB_OK);
    ASSERT_EQ(vcs_package_store_pin(ack_store, ack_root, true),
              VCS_PACKAGE_STORE_OK);
    struct vcs_zcode_dht_publish_spec ack_spec;
    memset(&ack_spec, 0, sizeof(ack_spec));
    ack_spec.kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK;
    (void)snprintf(ack_spec.namespace_name,
                   sizeof(ack_spec.namespace_name), "science");
    memcpy(ack_spec.transport_root, ack_root, 32);
    memset(ack_spec.owner_group, 0xa7, 32);
    ack_spec.sequence = 1;
    ack_spec.not_before = 1000;
    ack_spec.expiry = 2000;
    uint8_t ack_token[32];
    struct vcs_zcode_dht_record ack_record;
    enum vcs_zcode_dht_record_error ack_reason = VCS_ZCODE_DHT_RECORD_SIGNER;
    ASSERT(!vcs_zcode_dht_service_record_publish_plan(
        a, &ack_spec, ack_token, &ack_record, &ack_reason));
    ASSERT_EQ(ack_reason, VCS_ZCODE_DHT_RECORD_OK);
    ASSERT(vcs_zcode_dht_service_storage_ack_plan(
        a, ack_store, &ack_spec, ack_token, &ack_record));
    ASSERT_EQ(vcs_zcode_dht_service_storage_ack_commit(
                  a, ack_store, &ack_spec, ack_token, test_time(1004),
                  &ack_record),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);

    /* Source-reproduction evidence is a separate, one-shot signed fact.
     * Only the reconstruction-verified path may author it; the generic
     * publisher refuses it, an omitted owner group is derived from the
     * signing lineage, and the evidence is never renewed. */
    struct vcs_zcode_dht_publish_spec reproduction_spec = ack_spec;
    reproduction_spec.kind =
        VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK;
    memset(reproduction_spec.semantic_root, 0x6a, 32);
    memset(reproduction_spec.owner_group, 0, 32);
    uint8_t reproduction_token[32];
    struct vcs_zcode_dht_record reproduction_record;
    enum vcs_zcode_dht_record_error reproduction_reason =
        VCS_ZCODE_DHT_RECORD_SIGNER;
    ASSERT(!vcs_zcode_dht_service_record_publish_plan(
        a, &reproduction_spec, reproduction_token,
        &reproduction_record, &reproduction_reason));
    ASSERT_EQ(reproduction_reason, VCS_ZCODE_DHT_RECORD_OK);
    ASSERT(vcs_zcode_dht_source_reproduction_ack_plan_verified(
        a, &reproduction_spec, reproduction_token,
        &reproduction_record));
    ASSERT(reproduction_record.kind ==
           VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK);
    ASSERT(memcmp(reproduction_record.semantic_root,
                  reproduction_spec.semantic_root, 32) == 0);
    ASSERT(memcmp(reproduction_record.transport_root,
                  reproduction_spec.transport_root, 32) == 0);
    ASSERT(memcmp(reproduction_record.owner_group,
                  (uint8_t[32]){0}, 32) != 0);
    ASSERT_EQ(vcs_zcode_dht_source_reproduction_ack_commit_verified(
                  a, &reproduction_spec, reproduction_token,
                  test_time(1004), &reproduction_record),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    struct vcs_zcode_dht_record_selector reproduction_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_SOURCE_REPRODUCTION_ACK};
    (void)snprintf(reproduction_selector.namespace_name,
                   sizeof(reproduction_selector.namespace_name),
                   "science");
    memcpy(reproduction_selector.root, ack_root, 32);
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  a, 1004, &reproduction_selector, local, 1),
              1);
    ASSERT_EQ(local[0].sequence, 1);
    struct vcs_zcode_dht_storage_ack_proof_request proof_request;
    ASSERT_EQ(vcs_zcode_dht_service_storage_ack_proof_requests(
                  a, test_time(1500), &proof_request, 1),
              1);
    ASSERT(!proof_request.fresh_required);
    uint64_t pre_renew_proof_epoch = proof_request.proof_epoch;
    ASSERT_EQ(vcs_zcode_dht_service_storage_ack_proof_requests(
                  a, test_time(1800), &proof_request, 1),
              1);
    ASSERT(proof_request.fresh_required);
    vcs_zcode_dht_service_tick(a, test_time(1800));
    struct vcs_zcode_dht_record_selector renewal_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK};
    (void)snprintf(renewal_selector.namespace_name,
                   sizeof(renewal_selector.namespace_name), "science");
    memcpy(renewal_selector.root, ack_root, 32);
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  a, 1800, &renewal_selector, local, 1),
              1);
    ASSERT_EQ(local[0].sequence, 1);
    vcs_zcode_dht_service_storage_ack_validation(
        a, ack_root, pre_renew_proof_epoch, true, test_time(1800));
    vcs_zcode_dht_service_tick(a, test_time(1800));
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  a, 1800, &renewal_selector, local, 1),
              1);
    ASSERT_EQ(local[0].sequence, 1);
    vcs_zcode_dht_service_storage_ack_validation(
        a, ack_root, proof_request.proof_epoch, true, test_time(1800));
    vcs_zcode_dht_service_tick(a, test_time(1800));
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  a, 1800, &renewal_selector, local, 1),
              1);
    ASSERT_EQ(local[0].sequence, 2);
    uint8_t ack_chunk_hash[32];
    char ack_chunk_hex[65], ack_chunk_path[512];
    ASSERT(vcs_package_chunk_hash(ack_bytes, sizeof(ack_bytes),
                                  ack_chunk_hash));
    zcl_hex_encode(ack_chunk_hash, sizeof(ack_chunk_hash), ack_chunk_hex);
    int ack_path_len = snprintf(
        ack_chunk_path, sizeof(ack_chunk_path), "%s/zcode/cas/sha3/%02x/%s",
        ack_dir, ack_chunk_hash[0], ack_chunk_hex);
    ASSERT(ack_path_len > 0 && (size_t)ack_path_len < sizeof(ack_chunk_path));
    ASSERT(unlink(ack_chunk_path) == 0);
    ASSERT(!vcs_package_store_verify_possession(ack_store, ack_root, true));
    vcs_zcode_dht_service_storage_ack_validation(
        a, ack_root, proof_request.proof_epoch, false, test_time(1800));

    vcs_zcode_dht_service_free(a, test_time(1800));
    a = fixture_service_at(adir, genesis, anoise, 1800);
    ASSERT(a != NULL);
    struct vcs_zcode_dht_service_status publication_status;
    vcs_zcode_dht_service_status(a, &publication_status);
    ASSERT_EQ(publication_status.publication_intents, 3);
    struct vcs_zcode_dht_record_selector published_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_POINTER};
    snprintf(published_selector.namespace_name,
             sizeof(published_selector.namespace_name), "science");
    memset(published_selector.root, 0x41, 32);
    vcs_zcode_dht_service_tick(a, test_time(1800));
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  a, 1800, &published_selector, local, 1),
              1);
    ASSERT_EQ(local[0].sequence, 2);
    struct vcs_zcode_dht_record_selector ack_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_STORAGE_ACK};
    (void)snprintf(ack_selector.namespace_name,
                   sizeof(ack_selector.namespace_name), "science");
    memcpy(ack_selector.root, ack_root, 32);
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  a, 1800, &ack_selector, local, 1),
              1);
    ASSERT_EQ(local[0].sequence, 2);
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  a, 1800, &reproduction_selector, local, 1),
              1);
    ASSERT_EQ(local[0].sequence, 1);
    vcs_zcode_dht_service_tick(a, test_time(2001));
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  a, 2001, &reproduction_selector, local, 1),
              0);
    vcs_zcode_dht_service_status(a, &publication_status);
    ASSERT_EQ(publication_status.publication_intents, 2);
    vcs_package_store_close(ack_store);
    test_rm_rf_recursive(ack_dir);
    vcs_zcode_dht_service_free(a, test_time(2001));
    vcs_zcode_dht_service_free(b, test_time(1004));
    cleanup_fixture(adir);
    cleanup_fixture(bdir);
    PASS();
  }
_test_next:;
  return failures;
}

static int test_sparse_iterative_network(void) {
  int failures = 0;
  TEST("zcode dht service: sparse multi-hop records, local ban and restart") {
    struct multi_network net;
    memset(&net, 0, sizeof(net));
    net.node_count = MULTI_NODES;
    net.now = test_time(1001);
    uint8_t genesis[32];
    memset(genesis, 0x11, sizeof(genesis));
    for (size_t i = 0; i < MULTI_NODES; i++) {
      snprintf(net.dir[i], sizeof(net.dir[i]),
               "/tmp/zcl_dht_multi_%zu_XXXXXX", i);
      ASSERT(mkdtemp(net.dir[i]) != NULL);
      memset(net.noise[i], (int)(0x30 + i), 32);
      ASSERT(fixture_identity(net.dir[i], (uint8_t)(0x70 + i), genesis,
                              net.noise[i]));
      ASSERT(fixture_material(net.dir[i],
                              &(struct vcs_zcode_dht_delegation){0},
                              (uint8_t[32]){0}, net.node_id[i]));
      net.reach[i].network = &net;
      net.reach[i].owner = i;
    }
    for (size_t i = 0; i < MULTI_NODES; i++) {
      net.service[i] = multi_service(&net, i, genesis);
      ASSERT(net.service[i] != NULL);
      ASSERT(vcs_zcode_dht_service_enabled(net.service[i]));
    }

    /* Put six independent identities in descending XOR distance from the
     * target, then connect only that chain plus one B->D escape edge. */
    const size_t target_node = MULTI_NODES - 1;
    size_t order[MULTI_NODES];
    for (size_t i = 0; i < target_node; i++)
      order[i] = i;
    for (size_t i = 0; i < target_node; i++)
      for (size_t j = i + 1; j < target_node; j++)
        if (!farther_node(net.node_id[order[i]], net.node_id[order[j]],
                          net.node_id[target_node])) {
          size_t swap = order[i];
          order[i] = order[j];
          order[j] = swap;
        }
    order[target_node] = target_node;
    for (size_t i = 1; i < MULTI_NODES; i++)
      ASSERT(farther_node(net.node_id[order[i - 1]], net.node_id[order[i]],
                          net.node_id[target_node]));
    for (size_t i = 0; i + 1 < MULTI_NODES; i++)
      ASSERT(multi_connect(&net, order[i], order[i + 1]));
    ASSERT(multi_connect(&net, order[1], order[3]));
    ASSERT(multi_drive(&net));

    const size_t origin = order[0];
    net.deny[origin][order[2]] = true; /* break the obvious next hop */
    struct vcs_zcode_dht_service_status before, after;
    vcs_zcode_dht_service_status(net.service[origin], &before);
    ASSERT_EQ(before.connected_authenticated, 1);
    uint64_t lookup = 0;
    ASSERT(vcs_zcode_dht_service_lookup_begin(
        net.service[origin], net.node_id[target_node], net.now, &lookup));
    uint64_t frames_before = net.frames;
    ASSERT(multi_drive(&net));
    struct vcs_zcode_dht_lookup_result result;
    ASSERT(vcs_zcode_dht_service_lookup_poll(net.service[origin], lookup,
                                             net.now, &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_COMPLETE);
    ASSERT_EQ(result.termination,
              VCS_ZCODE_DHT_TERMINATION_TARGET_AUTHENTICATED);
    ASSERT(result.rounds >= 3);
    ASSERT(result.xor_progress >= 3);
    ASSERT(net.denied_hints >= 1);
    bool found_target = false, found_denied = false;
    for (uint32_t i = 0; i < result.count; i++) {
      found_target |= memcmp(result.node_ids[i], net.node_id[target_node], 32) == 0;
      found_denied |= memcmp(result.node_ids[i], net.node_id[order[2]], 32) == 0;
    }
    ASSERT(found_target);
    ASSERT(!found_denied);
    ASSERT(net.frames - frames_before <= 96);
    vcs_zcode_dht_service_status(net.service[origin], &after);
    ASSERT(after.lookup_rounds >= result.rounds);
    ASSERT(after.lookup_xor_progress >= result.xor_progress);

    /* Resolve the generic record key rather than naming the publisher peer.
     * The iterative record operation reuses the S6 walk, queries the closest
     * authenticated nodes, merges signed results, and treats records.v1 only
     * as its local rebuildable cache. */
    struct vcs_zcode_dht_record pointers[MULTI_NODES];
    for (size_t i = 0; i < MULTI_NODES; i++) {
      ASSERT(fixture_pointer_record(net.dir[i], genesis, 0xc1,
                                    (uint8_t)(0xd0 + i), &pointers[i]));
      ASSERT_EQ(vcs_zcode_dht_service_record_admit(
                    net.service[target_node], &pointers[i], net.now),
                VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    }
    struct vcs_zcode_dht_record pointer = pointers[target_node];
    for (uint8_t conflict = 1; conflict < 8; conflict++) {
      struct vcs_zcode_dht_record flooded;
      ASSERT(fixture_pointer_record(net.dir[target_node], genesis, 0xc1,
                                    (uint8_t)(0xe0 + conflict), &flooded));
      ASSERT_EQ(vcs_zcode_dht_service_record_admit(
                    net.service[target_node], &flooded, net.now),
                VCS_ZCODE_DHT_RECORD_STORE_CONFLICT);
    }
    struct vcs_zcode_dht_record_selector selector = {
        .kind = VCS_ZCODE_DHT_RECORD_POINTER};
    snprintf(selector.namespace_name, sizeof(selector.namespace_name),
             "science.study");
    memcpy(selector.root, pointer.semantic_root, 32);

    /* Recreate the origin as the actual late joiner in the S7.1 proof: its
     * records cache and peer database do not exist, and its sole bootstrap
     * session is not the publisher. The signed pointer remains only at the
     * far target, so discovery below must traverse the sparse DHT. */
    vcs_zcode_dht_service_free(net.service[origin], net.now);
    net.service[origin] = NULL;
    char late_path[512];
    (void)snprintf(late_path, sizeof(late_path),
                   "%s/zcode/dht/contacts.v2", net.dir[origin]);
    (void)unlink(late_path);
    ASSERT(access(late_path, F_OK) != 0);
    (void)snprintf(late_path, sizeof(late_path),
                   "%s/zcode/dht/records.v1", net.dir[origin]);
    (void)unlink(late_path);
    ASSERT(access(late_path, F_OK) != 0);
    for (size_t i = 0; i < MULTI_NODES; i++) {
      net.connected[origin][i] = false;
      net.connected[i][origin] = false;
      net.pending[origin][i] = false;
      net.pending[i][origin] = false;
    }
    net.service[origin] = multi_service(&net, origin, genesis);
    ASSERT(net.service[origin] != NULL);
    struct vcs_zcode_dht_service_status late_status;
    vcs_zcode_dht_service_status(net.service[origin], &late_status);
    ASSERT_EQ(late_status.cold_contacts, 0);
    struct vcs_zcode_dht_record late_cache[1];
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  net.service[origin], net.now.wall_unix, &selector,
                  late_cache, 1),
              0);
    ASSERT(order[1] != target_node);
    ASSERT(multi_connect(&net, origin, order[1]));
    ASSERT(multi_drive(&net));
    ASSERT(!net.connected[origin][target_node]);
    vcs_zcode_dht_service_status(net.service[origin], &late_status);
    ASSERT_EQ(late_status.connected_authenticated, 1);

    uint64_t record_operation = 0;
    ASSERT(vcs_zcode_dht_service_record_discovery_begin(
        net.service[origin], &selector, net.now, &record_operation));
    ASSERT(multi_drive(&net));
    struct vcs_zcode_dht_record_discovery_result discovery_result;
    ASSERT(vcs_zcode_dht_service_record_discovery_poll(
        net.service[origin], record_operation, net.now, &discovery_result));
    ASSERT_EQ(discovery_result.state,
              VCS_ZCODE_DHT_RECORD_OPERATION_PENDING);
    for (size_t drive = 0;
         drive < VCS_ZCODE_DHT_K &&
         discovery_result.state == VCS_ZCODE_DHT_RECORD_OPERATION_PENDING;
         drive++) {
      ASSERT(multi_drive(&net));
      ASSERT(vcs_zcode_dht_service_record_discovery_poll(
          net.service[origin], record_operation, net.now, &discovery_result));
    }
    ASSERT_EQ(discovery_result.state,
              VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE);
    ASSERT_EQ(discovery_result.record_count, MULTI_NODES + 7u);
    ASSERT(!discovery_result.truncated);
    ASSERT(!discovery_result.incomplete);
    for (size_t i = 0; i < MULTI_NODES; i++)
      for (size_t j = i + 1; j < MULTI_NODES; j++)
        ASSERT(memcmp(discovery_result.records[i].provider_node_id,
                      discovery_result.records[j].provider_node_id, 32) != 0);
    size_t target_conflicts = 0;
    for (uint32_t i = 0; i < discovery_result.record_count; i++)
      target_conflicts +=
          memcmp(discovery_result.records[i].provider_node_id,
                 pointer.provider_node_id, 32) == 0;
    ASSERT_EQ(target_conflicts, 8);
    struct vcs_zcode_dht_record cached[1];
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  net.service[origin], net.now.wall_unix, &selector, cached, 1),
              MULTI_NODES + 7u);

    /* Provider routing binds a signed claim to the currently authenticated
     * Noise/delegation session for that exact node ID. Local policy is
     * re-evaluated for FETCH/STORE/INDEX before the peer handle is exposed. */
    struct vcs_zcode_dht_record provider;
    ASSERT(fixture_provider_record(net.dir[target_node], genesis,
                                   0xf1, &provider));
    ASSERT_EQ(vcs_zcode_dht_service_record_admit(
                  net.service[origin], &provider, net.now),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    struct vcs_zcode_dht_record_selector provider_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_PROVIDER};
    (void)snprintf(provider_selector.namespace_name,
                   sizeof(provider_selector.namespace_name), "science");
    memcpy(provider_selector.root, provider.transport_root, 32);
    struct vcs_zcode_dht_provider_route route;
    ASSERT(vcs_zcode_dht_service_provider_route(
        net.service[origin], net.now.wall_unix, &provider_selector, &route));
    ASSERT_EQ(route.authenticated_count, 1);
    ASSERT_EQ(route.peer_ids[0], target_node + 1);
    memcpy(net.banned_root, provider.transport_root, 32);
    net.banned[origin] = true;
    ASSERT(vcs_zcode_dht_service_provider_route(
        net.service[origin], net.now.wall_unix, &provider_selector, &route));
    ASSERT_EQ(route.authenticated_count, 0);
    ASSERT_EQ(route.policy_denied, 1);
    net.banned[origin] = false;

    /* Publication is a lookup against the deterministic record key, not a
     * broadcast to the publisher's current sessions. Select a node that is
     * not directly connected to the publisher, then prove that the closest
     * set walk reaches it and stores the signed record. */
    size_t indirect = MULTI_NODES;
    for (size_t i = 0; i < MULTI_NODES; i++)
      if (i != target_node && !net.connected[target_node][i]) {
        indirect = i;
        break;
      }
    ASSERT(indirect < MULTI_NODES);
    struct vcs_zcode_dht_publish_spec routed_publish;
    memset(&routed_publish, 0, sizeof(routed_publish));
    routed_publish.kind = VCS_ZCODE_DHT_RECORD_POINTER;
    (void)snprintf(routed_publish.namespace_name,
                   sizeof(routed_publish.namespace_name), "science");
    memset(routed_publish.semantic_root, 0xb4, 32);
    memset(routed_publish.transport_root, 0xb5, 32);
    routed_publish.sequence = 1;
    routed_publish.not_before = net.now.wall_unix;
    routed_publish.expiry = net.now.wall_unix + 999;
    uint8_t routed_token[32];
    struct vcs_zcode_dht_record routed_record;
    ASSERT(vcs_zcode_dht_service_record_publish_plan(
        net.service[target_node], &routed_publish, routed_token,
        &routed_record, NULL));
    ASSERT_EQ(vcs_zcode_dht_service_record_publish_commit(
                  net.service[target_node], &routed_publish, routed_token,
                  net.now, &routed_record, NULL),
              VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    uint64_t publish_frames = net.frames;
    struct vcs_zcode_dht_record_selector routed_selector = {
        .kind = VCS_ZCODE_DHT_RECORD_POINTER};
    (void)snprintf(routed_selector.namespace_name,
                   sizeof(routed_selector.namespace_name), "science");
    memcpy(routed_selector.root, routed_publish.semantic_root, 32);
    struct vcs_zcode_dht_record routed_found[1];
    size_t routed_count = 0;
    for (size_t turn = 0; turn < 32 && routed_count == 0; turn++) {
      ASSERT(multi_drive(&net));
      vcs_zcode_dht_service_tick(net.service[target_node], net.now);
      routed_count = vcs_zcode_dht_service_record_local_query(
          net.service[indirect], net.now.wall_unix, &routed_selector,
          routed_found, 1);
    }
    ASSERT_EQ(routed_count, 1);
    ASSERT_EQ(routed_found[0].sequence, 1);
    ASSERT(net.connected[target_node][indirect]);
    struct vcs_zcode_dht_service_status publish_status;
    for (size_t turn = 0; turn < 32; turn++) {
      vcs_zcode_dht_service_status(net.service[target_node], &publish_status);
      if (publish_status.active_publications == 0)
        break;
      ASSERT(multi_drive(&net));
      vcs_zcode_dht_service_tick(net.service[target_node], net.now);
    }
    vcs_zcode_dht_service_status(net.service[target_node], &publish_status);
    ASSERT_EQ(publish_status.active_publications, 0);
    ASSERT(net.frames - publish_frames <= 256);

    /* A local policy change freezes forwarding and renewal. Once the local
     * root ban is removed, the same persisted intent renews and advances its
     * sequence; no global state or shared ban is involved. */
    memcpy(net.banned_root, routed_publish.semantic_root, 32);
    net.banned[target_node] = true;
    net.now.wall_unix = routed_publish.expiry - 300;
    net.now.monotonic_s = net.now.wall_unix;
    uint64_t frames_before_policy = net.frames;
    vcs_zcode_dht_service_tick(net.service[target_node], net.now);
    ASSERT(multi_drive(&net));
    ASSERT_EQ(net.frames, frames_before_policy);
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  net.service[target_node], net.now.wall_unix,
                  &routed_selector, routed_found, 1),
              1);
    ASSERT_EQ(routed_found[0].sequence, 1);
    net.banned[target_node] = false;
    vcs_zcode_dht_service_tick(net.service[target_node], net.now);
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  net.service[target_node], net.now.wall_unix,
                  &routed_selector, routed_found, 1),
              1);
    ASSERT_EQ(routed_found[0].sequence, 2);

    /* A ban is strictly local. Origin stops serving this root while the
     * target still serves the identical signed record to another node. */
    struct vcs_zcode_dht_record_operation_result record_result;
    memcpy(net.banned_root, pointer.semantic_root, 32);
    net.banned[origin] = true;
    ASSERT(vcs_zcode_dht_service_record_query_begin(
        net.service[target_node], origin + 1, &selector, net.now,
        &record_operation));
    ASSERT(multi_drive(&net));
    ASSERT(vcs_zcode_dht_service_record_operation_poll(
        net.service[target_node], record_operation, net.now, &record_result));
    ASSERT_EQ(record_result.record_count, 0);
    size_t alternate = order[target_node - 1];
    ASSERT(vcs_zcode_dht_service_record_query_begin(
        net.service[alternate], target_node + 1, &selector, net.now,
        &record_operation));
    ASSERT(multi_drive(&net));
    ASSERT(vcs_zcode_dht_service_record_operation_poll(
        net.service[alternate], record_operation, net.now, &record_result));
    ASSERT_EQ(record_result.record_count, VCS_ZCODE_DHT_RECORDS_PER_FRAME);

    /* A reachability request can be accepted while the bounded dial itself
     * fails.  The unverified ID must age out monotonically so a nonexistent
     * target reaches shortlist stability instead of the 30-second ceiling. */
    net.deny[origin][order[2]] = false;
    net.stall[origin][order[2]] = true;
    uint8_t absent_target[32];
    memset(absent_target, 0xa5, sizeof(absent_target));
    ASSERT(vcs_zcode_dht_service_lookup_begin(
        net.service[origin], absent_target, net.now, &lookup));
    ASSERT(multi_drive(&net));
    ASSERT(vcs_zcode_dht_service_lookup_poll(net.service[origin], lookup,
                                             net.now, &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_PENDING);
    net.now.monotonic_s +=
        VCS_ZCODE_DHT_SERVICE_REACHABILITY_TIMEOUT_S + 1;
    ASSERT(vcs_zcode_dht_service_lookup_poll(net.service[origin], lookup,
                                             net.now, &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_COMPLETE);
    ASSERT_EQ(result.termination,
              VCS_ZCODE_DHT_TERMINATION_SHORTLIST_STABLE);
    net.stall[origin][order[2]] = false;
    net.deny[origin][order[2]] = true;

    /* All eight requests are admitted while the three global slots are
     * occupied. Scheduler rotation eventually gives every lookup a query. */
    uint64_t ids[VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS];
    uint8_t concurrent_target[32];
    memset(concurrent_target, 0xa6, sizeof(concurrent_target));
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++)
      ASSERT(vcs_zcode_dht_service_lookup_begin(
          net.service[origin], concurrent_target, net.now, &ids[i]));
    vcs_zcode_dht_service_status(net.service[origin], &after);
    ASSERT_EQ(after.queued_lookups, VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS);
    ASSERT_EQ(after.active_queries, VCS_ZCODE_DHT_SERVICE_MAX_ACTIVE_QUERIES);
    net.now.monotonic_s++;
    ASSERT(multi_drive(&net));
    size_t waited = 0;
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++) {
      ASSERT(vcs_zcode_dht_service_lookup_poll(net.service[origin], ids[i],
                                               net.now, &result));
      ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_COMPLETE);
      ASSERT(result.rounds > 0);
      waited += result.queue_wait_s > 0;
    }
    ASSERT(waited >= 5);

    /* Durable authenticated contacts load cold; only a fresh Noise session
     * promotes the neighbour back into connected/authenticated state. */
    vcs_zcode_dht_service_free(net.service[origin], net.now);
    net.service[origin] = multi_service(&net, origin, genesis);
    ASSERT(net.service[origin] != NULL);
    vcs_zcode_dht_service_status(net.service[origin], &after);
    ASSERT(after.persistence_loaded);
    ASSERT(after.cold_contacts >= 1);
    struct vcs_zcode_dht_record cold_record[1];
    ASSERT_EQ(vcs_zcode_dht_service_record_local_query(
                  net.service[origin], net.now.wall_unix, &selector,
                  cold_record, 1),
              MULTI_NODES + 7u);
    ASSERT(memcmp(cold_record[0].semantic_root, pointer.semantic_root, 32) ==
           0);
    ASSERT_EQ(after.connected_authenticated, 0);
    memset(net.connected[origin], 0, sizeof(net.connected[origin]));
    for (size_t i = 0; i < MULTI_NODES; i++)
      net.connected[i][origin] = false;
    /* A new lookup seeds the closest persisted IDs as COLD/UNVERIFIED.  The
     * reachability callback may arrange a connection, but the result remains
     * pending until that connection freshly authenticates its Noise-bound
     * delegation.  No explicit reconnect is injected here. */
    ASSERT(vcs_zcode_dht_service_lookup_begin(
        net.service[origin], net.node_id[target_node], net.now, &lookup));
    ASSERT(net.pending[origin][target_node]);
    ASSERT(multi_drive(&net));
    ASSERT(vcs_zcode_dht_service_lookup_poll(net.service[origin], lookup,
                                             net.now, &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_COMPLETE);
    ASSERT_EQ(result.termination,
              VCS_ZCODE_DHT_TERMINATION_TARGET_AUTHENTICATED);
    vcs_zcode_dht_service_status(net.service[origin], &after);
    ASSERT(after.connected_authenticated >= 1);

    /* Fill the same signed selector to its exact 64-record discovery ceiling.
     * The operation preserves the bounded records and says truncated instead
     * of claiming complete evidence beyond the cap. */
    size_t ceiling_added = 0;
    for (size_t i = 0; i < MULTI_NODES && ceiling_added < 45; i++) {
      if (i == target_node)
        continue;
      for (size_t conflict = 0; conflict < 7 && ceiling_added < 45;
           conflict++) {
        struct vcs_zcode_dht_record flooded;
        ASSERT(fixture_pointer_record(net.dir[i], genesis, 0xc1,
                                      (uint8_t)(0x20 + ceiling_added),
                                      &flooded));
        ASSERT_EQ(vcs_zcode_dht_service_record_admit(
                      net.service[target_node], &flooded, net.now),
                  VCS_ZCODE_DHT_RECORD_STORE_CONFLICT);
        ceiling_added++;
      }
    }
    ASSERT_EQ(ceiling_added, 45);
    uint64_t ceiling_operation = 0;
    ASSERT(vcs_zcode_dht_service_record_discovery_begin(
        net.service[origin], &selector, net.now, &ceiling_operation));
    ASSERT(multi_drive(&net));
    ASSERT(vcs_zcode_dht_service_record_discovery_poll(
        net.service[origin], ceiling_operation, net.now, &discovery_result));
    for (size_t drive = 0;
         drive < 2 * VCS_ZCODE_DHT_K &&
         discovery_result.state == VCS_ZCODE_DHT_RECORD_OPERATION_PENDING;
         drive++) {
      ASSERT(multi_drive(&net));
      ASSERT(vcs_zcode_dht_service_record_discovery_poll(
          net.service[origin], ceiling_operation, net.now,
          &discovery_result));
    }
    ASSERT_EQ(discovery_result.state,
              VCS_ZCODE_DHT_RECORD_OPERATION_COMPLETE);
    ASSERT_EQ(discovery_result.record_count,
              VCS_ZCODE_DHT_RECORD_DISCOVERY_MAX_RESULTS);
    ASSERT(discovery_result.truncated);

    for (size_t i = 0; i < MULTI_NODES; i++) {
      vcs_zcode_dht_service_free(net.service[i], net.now);
      cleanup_fixture(net.dir[i]);
    }
    PASS();
  }
_test_next:;
  return failures;
}

struct space16_record_wire {
  uint8_t bytes[VCS_ZCODE_DHT_RECORD_WIRE_BYTES];
};

static int space16_wire_compare(const void *left, const void *right) {
  return memcmp(left, right, sizeof(struct space16_record_wire));
}

static bool space16_record_set(
    struct vcs_zcode_dht_service *service, uint64_t wall_unix,
    const struct vcs_zcode_dht_record_selector *selector,
    struct space16_record_wire out[SPACE16_RECORD_MAX], size_t *count_out) {
  struct vcs_zcode_dht_record records[SPACE16_RECORD_MAX];
  size_t count = vcs_zcode_dht_service_record_local_query(
      service, wall_unix, selector, records, SPACE16_RECORD_MAX);
  if (count > SPACE16_RECORD_MAX)
    return false;
  for (size_t i = 0; i < count; i++)
    if (vcs_zcode_dht_record_encode(&records[i], out[i].bytes) !=
        VCS_ZCODE_DHT_RECORD_OK)
      return false;
  qsort(out, count, sizeof(out[0]), space16_wire_compare);
  *count_out = count;
  return true;
}

static bool space16_map_has_result(
    const struct vcs_space_scout_map_v1 *map, const uint8_t root[32],
    enum vcs_space_scout_manifest_result result) {
  for (size_t i = 0; i < map->visit_count; i++)
    if (memcmp(map->visits[i].space_root, root, 32) == 0 &&
        map->visits[i].manifest_result == (uint8_t)result)
      return true;
  return false;
}

static bool space16_policy_create(
    const uint8_t genesis[32], const uint8_t blocked_root[32],
    struct vcs_zcode_sovereignty_policy **out) {
  *out = vcs_zcode_sovereignty_policy_create(genesis);
  if (!*out)
    return false;
  uint8_t service[32] = {0};
  (void)snprintf((char *)service, sizeof(service), "space.manifest");
  uint8_t allow_mask =
      (uint8_t)((1u << VCS_ZCODE_SOVEREIGNTY_DISCOVER) |
                (1u << VCS_ZCODE_SOVEREIGNTY_FETCH) |
                (1u << VCS_ZCODE_SOVEREIGNTY_STORE) |
                (1u << VCS_ZCODE_SOVEREIGNTY_INDEX));
  struct vcs_zcode_sovereignty_rule rule;
  if (vcs_zcode_sovereignty_rule_build(
          &rule, VCS_ZCODE_SOVEREIGNTY_LOCAL,
          VCS_ZCODE_SOVEREIGNTY_ALLOW,
          VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE, allow_mask, service) !=
          VCS_ZCODE_SOVEREIGNTY_OK ||
      vcs_zcode_sovereignty_policy_add(*out, &rule) !=
          VCS_ZCODE_SOVEREIGNTY_OK)
    return false;
  if (!blocked_root)
    return true;
  uint8_t block_mask =
      (uint8_t)((1u << VCS_ZCODE_SOVEREIGNTY_DISCOVER) |
                (1u << VCS_ZCODE_SOVEREIGNTY_FETCH));
  return vcs_zcode_sovereignty_rule_build(
             &rule, VCS_ZCODE_SOVEREIGNTY_LOCAL,
             VCS_ZCODE_SOVEREIGNTY_BLOCK,
             VCS_ZCODE_SOVEREIGNTY_FULL_ROOT, block_mask,
             blocked_root) == VCS_ZCODE_SOVEREIGNTY_OK &&
         vcs_zcode_sovereignty_policy_add(*out, &rule) ==
             VCS_ZCODE_SOVEREIGNTY_OK;
}

static bool space16_reset_late_joiner(
    struct multi_network *net, size_t origin, size_t bootstrap,
    const uint8_t genesis[32]) {
  if (net->service[origin])
    vcs_zcode_dht_service_free(net->service[origin], net->now);
  net->service[origin] = multi_service(net, origin, genesis);
  if (!net->service[origin])
    return false;
  for (size_t i = 0; i < net->node_count; i++) {
    net->connected[origin][i] = net->connected[i][origin] = false;
    net->pending[origin][i] = net->pending[i][origin] = false;
  }
  if (!multi_connect(net, origin, bootstrap) || !multi_drive(net))
    return false;
  struct vcs_zcode_dht_service_status status;
  vcs_zcode_dht_service_status(net->service[origin], &status);
  return status.connected_authenticated == 1;
}

static bool space16_load_raw(
    const char *workspace, const uint8_t root[32], uint8_t **wire,
    size_t *wire_len) {
  *wire = NULL;
  *wire_len = 0;
  return vcs_object_load_raw(workspace, root, wire, wire_len) == 0;
}

static int test_sparse_space16_network(void) {
  int failures = 0;
  printf("zcode space: sparse 16-node transport, scout and restart proof... ");
  bool ok = false;
  struct multi_network net;
  memset(&net, 0, sizeof(net));
  net.node_count = SPACE16_NODES;
  net.now = test_time(1500);
  uint8_t genesis[32], roots[SPACE16_MANIFESTS][32], blobs[SPACE16_MANIFESTS][32];
  uint8_t dead_root[32], online_seed[32] = {0}, observer_node_id[32];
  memset(genesis, 0x11, sizeof(genesis));
  memset(dead_root, 0xfe, sizeof(dead_root));
  struct vcs_package_store *provider_store = NULL;
  struct vcs_package_store *local_store_a = NULL, *local_store_b = NULL;
  struct vcs_swarm_engine *swarm_a = NULL, *swarm_b = NULL;
  struct vcs_zcode_sovereignty_policy *policy_a = NULL, *policy_b = NULL;
  struct vcs_space_scout_map_v1 *first = NULL, *second = NULL;
  struct vcs_space_scout_map_v1 *allowed = NULL, *reloaded = NULL;
  uint8_t *space_bytes_before[SPACE16_MANIFESTS - 1u] = {0};
  size_t space_lens_before[SPACE16_MANIFESTS - 1u] = {0};
  char provider_workspace[128] = {0}, workspace_a[128] = {0};
  char workspace_b[128] = {0}, zcode_a[128] = {0}, zcode_b[128] = {0};
  size_t created_dirs = 0;

#define SPACE16_REQUIRE(expr) do {                                           \
    if (!(expr)) {                                                           \
      printf("FAIL (%s at line %d)\n", #expr, __LINE__);                    \
      goto space16_cleanup;                                                  \
    }                                                                        \
  } while (0)

  for (size_t i = 0; i < SPACE16_NODES; i++) {
    (void)snprintf(net.dir[i], sizeof(net.dir[i]),
                   "/tmp/zcl_space16_%zu_XXXXXX", i);
    SPACE16_REQUIRE(mkdtemp(net.dir[i]) != NULL);
    created_dirs++;
    memset(net.noise[i], (int)(0x20 + i), 32);
    SPACE16_REQUIRE(fixture_identity(
        net.dir[i], (uint8_t)(0x50 + i), genesis, net.noise[i]));
    SPACE16_REQUIRE(fixture_material(
        net.dir[i], &(struct vcs_zcode_dht_delegation){0},
        (uint8_t[32]){0}, net.node_id[i]));
    net.reach[i].network = &net;
    net.reach[i].owner = i;
    net.service[i] = multi_service(&net, i, genesis);
    SPACE16_REQUIRE(net.service[i] != NULL);
  }

  const size_t target = SPACE16_NODES - 1u;
  size_t order[SPACE16_NODES];
  for (size_t i = 0; i < target; i++)
    order[i] = i;
  for (size_t i = 0; i < target; i++)
    for (size_t j = i + 1; j < target; j++)
      if (!farther_node(net.node_id[order[i]], net.node_id[order[j]],
                        net.node_id[target])) {
        size_t swap = order[i]; order[i] = order[j]; order[j] = swap;
      }
  order[target] = target;
  for (size_t i = 0; i + 1 < SPACE16_NODES; i++)
    SPACE16_REQUIRE(multi_connect(&net, order[i], order[i + 1]));
  SPACE16_REQUIRE(multi_connect(&net, order[1], order[4]));
  SPACE16_REQUIRE(multi_drive(&net));

  (void)snprintf(provider_workspace, sizeof(provider_workspace),
                 "%s/space-cas", net.dir[target]);
  SPACE16_REQUIRE(mkdir(provider_workspace, 0700) == 0);
  SPACE16_REQUIRE(vcs_object_store_init(provider_workspace));
  struct vcs_space_manifest_v1 manifests[SPACE16_MANIFESTS];
  SPACE16_REQUIRE(space16_manifest_make(
      net.dir[12], genesis, "delta", NULL, 0, 0xd4,
      &manifests[3], roots[3]));
  uint8_t c_portals[1][32]; memcpy(c_portals[0], roots[3], 32);
  SPACE16_REQUIRE(space16_manifest_make(
      net.dir[9], genesis, "charlie", c_portals, 1, 0xc3,
      &manifests[2], roots[2]));
  uint8_t b_portals[1][32]; memcpy(b_portals[0], roots[2], 32);
  SPACE16_REQUIRE(space16_manifest_make(
      net.dir[6], genesis, "bravo", b_portals, 1, 0xb2,
      &manifests[1], roots[1]));
  uint8_t a_portals[3][32];
  memcpy(a_portals[0], roots[1], 32);
  memcpy(a_portals[1], roots[2], 32);
  memcpy(a_portals[2], dead_root, 32);
  SPACE16_REQUIRE(space16_manifest_make(
      net.dir[3], genesis, "alpha", a_portals, 3, 0xa1,
      &manifests[0], roots[0]));
  for (size_t i = 0; i < SPACE16_MANIFESTS; i++)
    SPACE16_REQUIRE(space16_store_manifest(
        provider_workspace, &manifests[i], roots[i]));

  provider_store = vcs_package_store_open(
      net.dir[target], VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
  SPACE16_REQUIRE(provider_store != NULL);
  for (size_t i = 0; i < SPACE16_MANIFESTS; i++) {
    char semantic[65], transport[65];
    zcl_hex_encode(roots[i], 32, semantic);
    enum metaverse_space_object_kind kind;
    SPACE16_REQUIRE(metaverse_space_publish(
        provider_store, provider_workspace, semantic, transport, &kind).ok);
    SPACE16_REQUIRE(kind == METAVERSE_SPACE_OBJECT_MANIFEST &&
                    zcl_hex_decode_lower(transport, blobs[i], 32));
  }

  struct vcs_zcode_dht_record alpha_records[24];
  size_t alpha_count = 0;
  for (size_t i = 0; i < 8; i++) {
    uint8_t left[32], right[32];
    SPACE16_REQUIRE(space16_root_after(blobs[0], (uint8_t)(0x20 + 2 * i),
                                       left));
    SPACE16_REQUIRE(space16_root_after(blobs[0],
                                       (uint8_t)(0x21 + 2 * i), right));
    SPACE16_REQUIRE(space16_pointer_conflict(
        net.dir[i], genesis, roots[0], left, right, 2000u + i,
        &alpha_records[alpha_count], &alpha_records[alpha_count + 1]));
    SPACE16_REQUIRE(vcs_zcode_dht_service_record_admit(
        net.service[target], &alpha_records[alpha_count], net.now) ==
        VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    SPACE16_REQUIRE(vcs_zcode_dht_service_record_admit(
        net.service[target], &alpha_records[alpha_count + 1], net.now) ==
        VCS_ZCODE_DHT_RECORD_STORE_CONFLICT);
    alpha_count += 2;
  }
  for (size_t i = 8; i < target; i++) {
    uint8_t malicious[32];
    SPACE16_REQUIRE(space16_root_after(
        blobs[0], (uint8_t)(0x60 + i), malicious));
      SPACE16_REQUIRE(fixture_pointer_record_named(
        net.dir[i], genesis, "space.manifest", roots[0], 1, 1000u + i,
        &alpha_records[alpha_count]));
    memcpy(alpha_records[alpha_count].transport_root, malicious, 32);
    uint8_t seed[32], ignored[32];
    struct vcs_zcode_dht_delegation delegation;
    SPACE16_REQUIRE(fixture_material(
        net.dir[i], &delegation, seed, ignored));
    SPACE16_REQUIRE(vcs_zcode_dht_record_sign(
        &alpha_records[alpha_count], seed) == VCS_ZCODE_DHT_RECORD_OK);
    memory_cleanse(seed, sizeof(seed));
    SPACE16_REQUIRE(vcs_zcode_dht_service_record_admit(
        net.service[target], &alpha_records[alpha_count], net.now) ==
        VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    alpha_count++;
  }
  SPACE16_REQUIRE(alpha_count == 23);
  SPACE16_REQUIRE(fixture_pointer_record_named(
      net.dir[target], genesis, "space.manifest", roots[0], 1, 1,
      &alpha_records[alpha_count]));
  memcpy(alpha_records[alpha_count].transport_root, blobs[0], 32);
  {
    uint8_t seed[32], ignored[32];
    struct vcs_zcode_dht_delegation delegation;
    SPACE16_REQUIRE(fixture_material(
        net.dir[target], &delegation, seed, ignored));
    SPACE16_REQUIRE(vcs_zcode_dht_record_sign(
        &alpha_records[alpha_count], seed) == VCS_ZCODE_DHT_RECORD_OK);
    memory_cleanse(seed, sizeof(seed));
  }
  SPACE16_REQUIRE(vcs_zcode_dht_service_record_admit(
      net.service[target], &alpha_records[alpha_count], net.now) ==
      VCS_ZCODE_DHT_RECORD_STORE_ADDED);
  alpha_count++;

  for (size_t i = 0; i < SPACE16_MANIFESTS; i++) {
    struct vcs_zcode_dht_record pointer, provider;
    if (i > 0) {
      SPACE16_REQUIRE(fixture_pointer_record_named(
          net.dir[target], genesis, "space.manifest", roots[i], 1, 1,
          &pointer));
      memcpy(pointer.transport_root, blobs[i], 32);
      uint8_t seed[32], ignored[32];
      struct vcs_zcode_dht_delegation delegation;
      SPACE16_REQUIRE(fixture_material(
          net.dir[target], &delegation, seed, ignored));
      SPACE16_REQUIRE(vcs_zcode_dht_record_sign(&pointer, seed) ==
                      VCS_ZCODE_DHT_RECORD_OK);
      memory_cleanse(seed, sizeof(seed));
      SPACE16_REQUIRE(vcs_zcode_dht_service_record_admit(
          net.service[target], &pointer, net.now) ==
          VCS_ZCODE_DHT_RECORD_STORE_ADDED);
    }
    SPACE16_REQUIRE(fixture_provider_record_named(
        net.dir[target], genesis, "space.manifest", blobs[i], &provider));
    SPACE16_REQUIRE(vcs_zcode_dht_service_record_admit(
        net.service[target], &provider, net.now) ==
        VCS_ZCODE_DHT_RECORD_STORE_ADDED);
  }

  const size_t origin_a = order[0], origin_b = order[1];
  SPACE16_REQUIRE(origin_a != target && origin_b != target);
  SPACE16_REQUIRE(space16_reset_late_joiner(
      &net, origin_a, order[2], genesis));
  SPACE16_REQUIRE(space16_reset_late_joiner(
      &net, origin_b, order[2], genesis));
  struct vcs_zcode_dht_record_selector selector = {
      .kind = VCS_ZCODE_DHT_RECORD_POINTER};
  (void)snprintf(selector.namespace_name, sizeof(selector.namespace_name),
                 "space.manifest");
  memcpy(selector.root, roots[0], 32);
  struct vcs_zcode_dht_record_discovery_result discovered;
  SPACE16_REQUIRE(multi_discover_records(
      &net, origin_a, &selector, &discovered));
  SPACE16_REQUIRE(discovered.record_count == alpha_count &&
                  discovered.record_count >
                      VCS_ZCODE_DHT_RECORDS_PER_FRAME &&
                  !discovered.incomplete && !discovered.truncated &&
                  net.connected[origin_a][target]);
  size_t conflicts = 0;
  bool honest_usable = false, hostile_high = false;
  for (size_t i = 0; i < discovered.record_count; i++) {
    bool conflicted = vcs_zcode_dht_record_conflicted_at(
        discovered.records, discovered.record_count, i);
    conflicts += conflicted;
    hostile_high |= discovered.records[i].sequence >= 1000;
    honest_usable |= discovered.records[i].sequence == 1 &&
        memcmp(discovered.records[i].transport_root, blobs[0], 32) == 0 &&
        !conflicted && !vcs_zcode_dht_record_superseded_at(
            discovered.records, discovered.record_count, i);
  }
  SPACE16_REQUIRE(conflicts == 16 && hostile_high && honest_usable);

  selector.kind = VCS_ZCODE_DHT_RECORD_PROVIDER;
  memcpy(selector.root, blobs[0], 32);
  SPACE16_REQUIRE(multi_discover_records(
      &net, origin_a, &selector, &discovered));
  struct vcs_zcode_dht_provider_route route;
  SPACE16_REQUIRE(vcs_zcode_dht_service_provider_route(
      net.service[origin_a], net.now.wall_unix, &selector, &route));
  SPACE16_REQUIRE(route.authenticated_count == 1);
  multi_disconnect(&net, origin_a, target);
  SPACE16_REQUIRE(vcs_zcode_dht_service_provider_route(
      net.service[origin_a], net.now.wall_unix, &selector, &route));
  SPACE16_REQUIRE(route.authenticated_count == 0);
  SPACE16_REQUIRE(multi_drive(&net));
  SPACE16_REQUIRE(vcs_zcode_dht_service_provider_route(
      net.service[origin_a], net.now.wall_unix, &selector, &route));
  SPACE16_REQUIRE(route.authenticated_count == 1);

  (void)snprintf(workspace_a, sizeof(workspace_a),
                 "%s/space-cas", net.dir[origin_a]);
  (void)snprintf(workspace_b, sizeof(workspace_b),
                 "%s/space-cas", net.dir[origin_b]);
  (void)snprintf(zcode_a, sizeof(zcode_a), "%s/zcode", net.dir[origin_a]);
  (void)snprintf(zcode_b, sizeof(zcode_b), "%s/zcode", net.dir[origin_b]);
  SPACE16_REQUIRE(mkdir(workspace_a, 0700) == 0);
  SPACE16_REQUIRE(mkdir(workspace_b, 0700) == 0);
  SPACE16_REQUIRE(vcs_object_store_init(workspace_a));
  SPACE16_REQUIRE(vcs_object_store_init(workspace_b));
  SPACE16_REQUIRE(!vcs_object_has(workspace_a, roots[0]) &&
                  !vcs_object_has(workspace_b, roots[0]));
  local_store_a = vcs_package_store_open(
      net.dir[origin_a], VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
  local_store_b = vcs_package_store_open(
      net.dir[origin_b], VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
  SPACE16_REQUIRE(local_store_a && local_store_b);
  swarm_a = vcs_swarm_engine_create(
      local_store_a, NULL, zcode_a, NULL, NULL);
  swarm_b = vcs_swarm_engine_create(
      local_store_b, NULL, zcode_b, NULL, NULL);
  SPACE16_REQUIRE(swarm_a && swarm_b);
  SPACE16_REQUIRE(space16_policy_create(genesis, roots[3], &policy_a));
  SPACE16_REQUIRE(space16_policy_create(genesis, NULL, &policy_b));

  struct space16_observer observer_a = {
      .network = &net, .origin = origin_a, .workspace = workspace_a,
      .local_store = local_store_a, .provider_store = provider_store,
      .swarm = swarm_a, .policy = policy_a,
      .observation_unix = 1500, .now_ms = 100};
  struct space16_observer observer_b = {
      .network = &net, .origin = origin_b, .workspace = workspace_b,
      .local_store = local_store_b, .provider_store = provider_store,
      .swarm = swarm_b, .policy = policy_b,
      .observation_unix = 1500, .now_ms = 100};
  memcpy(observer_a.genesis, genesis, 32);
  memcpy(observer_b.genesis, genesis, 32);
  memcpy(observer_a.dead_root, dead_root, 32);
  memcpy(observer_b.dead_root, dead_root, 32);
  struct vcs_space_scout_mission_v1 mission;
  memset(&mission, 0, sizeof(mission));
  mission.schema_version = VCS_SPACE_SCOUT_MISSION_VERSION;
  memcpy(mission.network_genesis, genesis, 32);
  mission.observation_unix = 1500;
  mission.start_count = 1;
  memcpy(mission.starting_roots[0], roots[0], 32);
  mission.maximum_depth = 6;
  mission.maximum_spaces = 8;
  mission.maximum_portals = 12;
  mission.maximum_bytes = 65536;
  mission.deadline_ms = 1000;
  struct vcs_space_scout_run_context context_a = {
      .observe = space16_observe, .observe_context = &observer_a,
      .monotonic_ms = space16_clock, .clock_context = &observer_a};
  struct vcs_space_scout_run_context context_b = {
      .observe = space16_observe, .observe_context = &observer_b,
      .monotonic_ms = space16_clock, .clock_context = &observer_b};
  first = zcl_calloc(1, sizeof(*first), "test_space16_first_map");
  second = zcl_calloc(1, sizeof(*second), "test_space16_second_map");
  allowed = zcl_calloc(1, sizeof(*allowed), "test_space16_allowed_map");
  SPACE16_REQUIRE(first && second && allowed);
  SPACE16_REQUIRE(vcs_space_scout_run(
      &mission, &context_a, first) == VCS_SPACE_SCOUT_OK);
  SPACE16_REQUIRE(vcs_object_has(workspace_a, roots[0]) &&
                  vcs_object_has(workspace_a, roots[1]) &&
                  vcs_object_has(workspace_a, roots[2]) &&
                  !vcs_object_has(workspace_a, roots[3]));
  SPACE16_REQUIRE(vcs_space_scout_run(
      &mission, &context_a, second) == VCS_SPACE_SCOUT_OK);
  SPACE16_REQUIRE(memcmp(first, second, sizeof(*first)) == 0 &&
                  first->policy_denial_count == 1 &&
                  space16_map_has_result(
                      first, roots[3],
                      VCS_SPACE_SCOUT_MANIFEST_POLICY_DENIED));
  bool cycle = false, dead = false;
  for (size_t i = 0; i < first->portal_count; i++)
    cycle |= first->portals[i].result == VCS_SPACE_SCOUT_PORTAL_CYCLE;
  for (size_t i = 0; i < first->failure_count; i++)
    dead |= first->failures[i].result ==
            VCS_SPACE_SCOUT_MANIFEST_NOT_FOUND;
  SPACE16_REQUIRE(cycle && dead);
  SPACE16_REQUIRE(vcs_space_scout_run(
      &mission, &context_b, allowed) == VCS_SPACE_SCOUT_OK);
  SPACE16_REQUIRE(allowed->policy_denial_count == 0 &&
                  space16_map_has_result(
                      allowed, roots[3],
                      VCS_SPACE_SCOUT_MANIFEST_VERIFIED) &&
                  vcs_object_has(workspace_b, roots[3]));
  struct vcs_zcode_sovereignty_subject unknown;
  memset(&unknown, 0, sizeof(unknown));
  memcpy(unknown.package_root, manifests[0].service_roots[0], 32);
  SPACE16_REQUIRE(!vcs_zcode_sovereignty_policy_check(
                       policy_a, VCS_ZCODE_SOVEREIGNTY_EXECUTE,
                       &unknown).allow &&
                  !vcs_zcode_sovereignty_policy_check(
                       policy_b, VCS_ZCODE_SOVEREIGNTY_EXECUTE,
                       &unknown).allow &&
                  observer_a.policy_calls[VCS_ZCODE_SOVEREIGNTY_EXECUTE] ==
                      0 &&
                  observer_b.policy_calls[VCS_ZCODE_SOVEREIGNTY_EXECUTE] ==
                      0);

  struct metaverse_space_scout_plan_out plan;
  SPACE16_REQUIRE(metaverse_space_scout_plan(&mission, &plan).ok);
  struct vcs_zcode_dht_delegation delegation;
  SPACE16_REQUIRE(fixture_material(
      net.dir[origin_a], &delegation, online_seed, observer_node_id));
  struct metaverse_space_scout_run_out recorded;
  bool mutated = false;
  SPACE16_REQUIRE(metaverse_space_scout_run(
      workspace_a, &mission, plan.plan_token, true, &context_a,
      &delegation, online_seed, space16_store_allowed, &observer_a,
      &mutated, &recorded).ok);
  SPACE16_REQUIRE(mutated && !recorded.already_recorded);
  struct metaverse_space_scout_run_out initial_recorded = recorded;
  memory_cleanse(online_seed, sizeof(online_seed));

  struct space16_record_wire before[SPACE16_RECORD_MAX];
  struct space16_record_wire after[SPACE16_RECORD_MAX];
  size_t before_count = 0, after_count = 0;
  selector.kind = VCS_ZCODE_DHT_RECORD_POINTER;
  memcpy(selector.root, roots[0], 32);
  SPACE16_REQUIRE(space16_record_set(
      net.service[origin_a], net.now.wall_unix, &selector,
      before, &before_count));
  SPACE16_REQUIRE(before_count == alpha_count);
  for (size_t i = 0; i < SPACE16_MANIFESTS - 1u; i++)
    SPACE16_REQUIRE(space16_load_raw(
        workspace_a, roots[i],
        &space_bytes_before[i], &space_lens_before[i]));

  vcs_swarm_engine_free(swarm_a); swarm_a = NULL;
  vcs_package_store_close(local_store_a); local_store_a = NULL;
  vcs_zcode_dht_service_free(net.service[origin_a], net.now);
  net.service[origin_a] = multi_service(&net, origin_a, genesis);
  SPACE16_REQUIRE(net.service[origin_a] != NULL);
  local_store_a = vcs_package_store_open(
      net.dir[origin_a], VCS_PACKAGE_STORE_DEFAULT_QUOTA_BYTES);
  SPACE16_REQUIRE(local_store_a != NULL);
  swarm_a = vcs_swarm_engine_create(
      local_store_a, NULL, zcode_a, NULL, NULL);
  SPACE16_REQUIRE(swarm_a != NULL);
  observer_a.local_store = local_store_a;
  observer_a.swarm = swarm_a;
  SPACE16_REQUIRE(space16_record_set(
      net.service[origin_a], net.now.wall_unix, &selector,
      after, &after_count));
  SPACE16_REQUIRE(after_count == before_count &&
                  memcmp(before, after,
                         before_count * sizeof(before[0])) == 0);
  for (size_t i = 0; i < SPACE16_MANIFESTS - 1u; i++) {
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    SPACE16_REQUIRE(space16_load_raw(
        workspace_a, roots[i], &wire, &wire_len));
    bool exact_space = wire_len == space_lens_before[i] &&
        memcmp(wire, space_bytes_before[i], wire_len) == 0;
    free(wire);
    SPACE16_REQUIRE(exact_space);
  }
  reloaded = zcl_calloc(
      1, sizeof(*reloaded), "test_space16_reloaded_map");
  SPACE16_REQUIRE(reloaded != NULL);
  SPACE16_REQUIRE(metaverse_space_scout_show(
      workspace_a, recorded.evidence_root, reloaded).ok);
  SPACE16_REQUIRE(memcmp(reloaded, first, sizeof(*first)) == 0);
  SPACE16_REQUIRE(fixture_material(
      net.dir[origin_a], &delegation, online_seed, observer_node_id));
  mutated = true;
  struct metaverse_space_scout_run_out rerun;
  SPACE16_REQUIRE(metaverse_space_scout_run(
      workspace_a, &mission, plan.plan_token, true, &context_a,
      &delegation, online_seed, space16_store_allowed, &observer_a,
      &mutated, &rerun).ok);
  SPACE16_REQUIRE(!mutated && rerun.already_recorded &&
                  strcmp(rerun.evidence_root,
                         initial_recorded.evidence_root) == 0 &&
                  strcmp(rerun.attestation_root,
                         initial_recorded.attestation_root) == 0);
  memory_cleanse(online_seed, sizeof(online_seed));
  ok = true;

space16_cleanup:
  memory_cleanse(online_seed, sizeof(online_seed));
  for (size_t i = 0; i < SPACE16_MANIFESTS - 1u; i++)
    free(space_bytes_before[i]);
  free(reloaded); free(allowed); free(second); free(first);
  vcs_zcode_sovereignty_policy_free(policy_b);
  vcs_zcode_sovereignty_policy_free(policy_a);
  vcs_swarm_engine_free(swarm_b);
  vcs_swarm_engine_free(swarm_a);
  if (local_store_b) vcs_package_store_close(local_store_b);
  if (local_store_a) vcs_package_store_close(local_store_a);
  if (provider_store) vcs_package_store_close(provider_store);
  for (size_t i = 0; i < SPACE16_NODES; i++)
    if (net.service[i])
      vcs_zcode_dht_service_free(net.service[i], net.now);
  for (size_t i = 0; i < created_dirs; i++)
    (void)test_rm_rf_recursive(net.dir[i]);
  if (ok)
    PASS();
  else
    failures++;
#undef SPACE16_REQUIRE
  return failures;
}

/* ── package-pointer reproduction gate (rpc_publish_impl) ────────────── */

static bool gate_rpc(const struct rpc_table *table, const char *method,
                     const struct json_value *input,
                     struct json_value *result) {
  const struct rpc_command *command = rpc_table_find(table, method);
  if (!command || !command->actor)
    return false;
  struct json_value params;
  json_init(&params);
  json_set_array(&params);
  json_push_back(&params, input);
  json_init(result);
  bool ok = command->actor(&params, false, result);
  json_free(&params);
  return ok;
}

static bool gate_mkdir_p(const char *path) {
  char buf[4096];
  size_t len = strlen(path);
  if (len == 0 || len >= sizeof(buf))
    return false;
  memcpy(buf, path, len + 1);
  for (char *p = buf + 1; *p; p++) {
    if (*p != '/')
      continue;
    *p = '\0';
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
      return false;
    *p = '/';
  }
  return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool gate_write_file(const char *path, const uint8_t *bytes,
                            size_t len) {
  FILE *f = fopen(path, "wb");
  if (!f)
    return false;
  size_t written = fwrite(bytes, 1, len, f);
  return fclose(f) == 0 && written == len;
}

/* One installable build receipt: two committed outputs seeded by out_seed,
 * under a fixed lock root. compiler_version varies the receipt id (a
 * distinct build event) without touching the output set. */
static bool gate_receipt(struct vcs_package_build_receipt *r,
                         const uint8_t package_root[32],
                         const uint8_t recipe_root[32],
                         const char *compiler_version, uint8_t out_seed) {
  vcs_package_build_receipt_init(r);
  memcpy(r->package_root, package_root, 32);
  memcpy(r->recipe_root, recipe_root, 32);
  memset(r->lock_root, 0x77, 32);
  (void)snprintf(r->compiler_id, sizeof(r->compiler_id), "gcc");
  (void)snprintf(r->compiler_version, sizeof(r->compiler_version), "%s",
                 compiler_version);
  (void)snprintf(r->flags, sizeof(r->flags), "-std=c23 -O1");
  r->result_class = (uint8_t)VCS_PACKAGE_BUILD_RESULT_TEST_PASS;
  r->isolation = (uint8_t)VCS_PACKAGE_BUILD_ISOLATION_FULL;
  r->test_ran = true;
  r->test_exit_code = 0;
  uint8_t h1[32], h2[32];
  memset(h1, out_seed, 32);
  memset(h2, (uint8_t)(out_seed + 1u), 32);
  return vcs_package_build_add_output(r, "include/add.h", h1, 100) ==
             VCS_PACKAGE_BUILD_OK &&
         vcs_package_build_add_output(r, "lib/libaddpkg.a", h2, 4096) ==
             VCS_PACKAGE_BUILD_OK;
}

/* Persist one receipt under <receipts_dir>/<receipt-id-hex> (the install
 * lifecycle's filing convention). */
static bool gate_store_receipt(const char *receipts_dir,
                               const struct vcs_package_build_receipt *r) {
  uint8_t *wire = NULL;
  size_t wire_len = 0;
  if (vcs_package_build_serialize(r, &wire, &wire_len) !=
      VCS_PACKAGE_BUILD_OK)
    return false;
  uint8_t id[32];
  bool ok = vcs_package_build_id(r, id) == VCS_PACKAGE_BUILD_OK;
  if (ok) {
    char id_hex[65];
    zcl_hex_encode(id, 32, id_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/%s", receipts_dir, id_hex);
    ok = n > 0 && (size_t)n < sizeof(path) && gate_mkdir_p(receipts_dir) &&
         gate_write_file(path, wire, wire_len);
  }
  free(wire);
  return ok;
}

/* A minimal parseable release envelope naming (package_root, recipe_root);
 * the publish gate reads only the committed recipe root from it. */
static bool gate_release(struct vcs_package_release *r,
                         const uint8_t package_root[32],
                         const uint8_t recipe_root[32]) {
  memset(r, 0, sizeof(*r));
  r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
  (void)snprintf(r->name, sizeof(r->name), "gate/pkg");
  (void)snprintf(r->semver, sizeof(r->semver), "1.0.0");
  memcpy(r->package_root, package_root, 32);
  memcpy(r->recipe_root, recipe_root, 32);
  /* The secp256k1 generator point: a valid compressed on-curve pubkey. */
  static const uint8_t generator[33] = {
      0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
      0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
      0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
  memcpy(r->publisher_pubkey, generator, sizeof(generator));
  r->publisher_sequence = 1;
  (void)snprintf(r->license, sizeof(r->license), "MIT");
  (void)snprintf(r->chain_id, sizeof(r->chain_id), "zclassic");
  memset(r->signature, 0, sizeof(r->signature));
  r->signature[63] = 1; /* low-S */
  return vcs_package_release_validate(r) == VCS_PACKAGE_RELEASE_OK;
}

/* Persist the release envelope under <zcode_dir>/releases/<release-id-hex>
 * (the store's publication convention, rebuilt into the package index). */
static bool gate_store_release(const char *zcode_dir,
                               const struct vcs_package_release *r) {
  uint8_t *wire = NULL;
  size_t wire_len = 0;
  if (vcs_package_release_serialize(r, &wire, &wire_len) !=
      VCS_PACKAGE_RELEASE_OK)
    return false;
  uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
  bool ok = vcs_package_release_id(r, id) == VCS_PACKAGE_RELEASE_OK;
  if (ok) {
    char id_hex[65];
    zcl_hex_encode(id, sizeof(id), id_hex);
    char dir[4400], path[4400];
    int dn = snprintf(dir, sizeof(dir), "%s/releases", zcode_dir);
    int pn = snprintf(path, sizeof(path), "%s/%s", dir, id_hex);
    ok = dn > 0 && (size_t)dn < sizeof(dir) && pn > 0 &&
         (size_t)pn < sizeof(path) && gate_mkdir_p(dir) &&
         gate_write_file(path, wire, wire_len);
  }
  free(wire);
  return ok;
}

static void gate_publish_roots(struct json_value *input, const char *mode,
                               const char *kind, const char *namespace_name,
                               const uint8_t semantic_root[32],
                               const uint8_t transport_root[32]) {
  char semantic_hex[65], transport_hex[65], owner_hex[65];
  zcl_hex_encode(semantic_root, 32, semantic_hex);
  uint8_t owner[32];
  memset(owner, 0xa7, 32);
  zcl_hex_encode(transport_root, 32, transport_hex);
  zcl_hex_encode(owner, 32, owner_hex);
  json_set_object(input);
  json_push_kv_str(input, "operation", "publish");
  json_push_kv_str(input, "mode", mode);
  json_push_kv_str(input, "kind", kind);
  json_push_kv_str(input, "namespace", namespace_name);
  json_push_kv_str(input, "semantic_root", semantic_hex);
  json_push_kv_str(input, "transport_root", transport_hex);
  json_push_kv_str(input, "owner_group", owner_hex);
  json_push_kv_int(input, "sequence", 1);
  json_push_kv_int(input, "not_before", 1000);
  json_push_kv_int(input, "expiry", 2000);
}

static void gate_publish_input(struct json_value *input, const char *mode,
                               const char *kind, const char *namespace_name,
                               const uint8_t semantic_root[32]) {
  uint8_t transport[32];
  memset(transport, 0xb2, 32);
  gate_publish_roots(input, mode, kind, namespace_name, semantic_root,
                     transport);
}

static struct json_value *gate_mutable_field(struct json_value *input,
                                             const char *key) {
  if (!input || input->type != JSON_OBJ || !key)
    return NULL;
  for (size_t i = 0; i < input->num_children; i++)
    if (input->keys[i] && strcmp(input->keys[i], key) == 0)
      return &input->children[i];
  return NULL;
}

static void gate_publish_without_sequence(struct json_value *input,
                                          const char *mode,
                                          const uint8_t semantic_root[32]) {
  char semantic_hex[65], transport_hex[65], owner_hex[65];
  uint8_t transport[32], owner[32];
  memset(transport, 0xb2, sizeof(transport));
  memset(owner, 0xa7, sizeof(owner));
  zcl_hex_encode(semantic_root, 32, semantic_hex);
  zcl_hex_encode(transport, 32, transport_hex);
  zcl_hex_encode(owner, 32, owner_hex);
  json_set_object(input);
  json_push_kv_str(input, "operation", "publish");
  json_push_kv_str(input, "mode", mode);
  json_push_kv_str(input, "kind", "pointer");
  json_push_kv_str(input, "namespace", "zclassic23.package");
  json_push_kv_str(input, "semantic_root", semantic_hex);
  json_push_kv_str(input, "transport_root", transport_hex);
  json_push_kv_str(input, "owner_group", owner_hex);
  json_push_kv_int(input, "not_before", 1000);
  json_push_kv_int(input, "expiry", 2000);
}

/* A real signed transport carrier, stored complete in the resident global
 * store: prepare the checked-in source package, sign its release with the
 * fixture key (the registry-pinned sibling of this flow lives in
 * test_zcode_swarm_net.c), build the carrier, store it. The gate's transport
 * checks then run against exactly what a publishing node holds. */
static bool gate_store_transport(const char *source_dir,
                                 uint8_t package_root[32],
                                 uint8_t recipe_root[32],
                                 uint8_t transport_root[32]) {
  struct privkey key;
  memset(&key, 0, sizeof(key));
  memset(key.vch, 0x47, sizeof(key.vch));
  key.fValid = true;
  key.fCompressed = true;
  struct pubkey pubkey;
  if (!privkey_get_pubkey(&key, &pubkey) ||
      pubkey.size != COMPRESSED_PUBLIC_KEY_SIZE)
    return false;
  struct vcs_package_prepare_options options = {
      .dir = source_dir,
      .publisher_sequence = 1,
      .reward_address = "",
      .chain_id = "zclassic-main",
  };
  memcpy(options.publisher_pubkey, pubkey.vch,
         COMPRESSED_PUBLIC_KEY_SIZE);
  char detail[160] = {0};
  struct vcs_package_prepared prepared;
  vcs_package_prepared_init(&prepared);
  struct vcs_package_transport transport;
  vcs_package_transport_init(&transport);
  uint8_t *release_wire = NULL;
  size_t release_wire_len = 0;
  bool ok = vcs_package_prepare(&options, &prepared, detail,
                                sizeof(detail)) == VCS_PACKAGE_PREPARE_OK;
  if (!ok)
    fprintf(stderr, "gate transport prepare: %s\n", detail);
  if (ok) {
    struct uint256 digest;
    memcpy(digest.data, prepared.signing_digest, 32);
    uint8_t compact[COMPACT_SIGNATURE_SIZE];
    ok = privkey_sign_compact(&key, &digest, compact);
    if (ok) {
      memcpy(prepared.release.signature, compact + 1,
             VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
      ok = vcs_package_release_verify(&prepared.release) ==
               VCS_PACKAGE_RELEASE_OK &&
           vcs_package_release_serialize(&prepared.release, &release_wire,
                                         &release_wire_len) ==
               VCS_PACKAGE_RELEASE_OK;
    }
  }
  if (ok)
    ok = vcs_package_transport_build(
             release_wire, release_wire_len, prepared.recipe_wire,
             prepared.recipe_wire_len, prepared.manifest_wire,
             prepared.manifest_wire_len,
             &transport) == VCS_PACKAGE_TRANSPORT_OK;
  if (ok)
    ok = vcs_package_transport_store(vcs_package_store_global(), &transport,
                                     source_dir) == VCS_PACKAGE_TRANSPORT_OK;
  if (ok) {
    memcpy(package_root, prepared.package_root, 32);
    memcpy(recipe_root, prepared.recipe_root, 32);
    memcpy(transport_root, transport.transport_root, 32);
  }
  free(release_wire);
  vcs_package_transport_free(&transport);
  vcs_package_prepared_free(&prepared);
  return ok;
}

/* Leave a complete carrier readable while making only its later inner-recipe
 * admission fail. A directory at the exact recipe path makes the atomic file
 * replacement refuse deterministically, including when the test runs as
 * root; public-shape classification does not consult this inner index. */
static bool gate_block_recipe_admission(const char *zcode_dir,
                                        const uint8_t recipe_root[32],
                                        char path[4400]) {
  char recipe_hex[65];
  zcl_hex_encode(recipe_root, 32, recipe_hex);
  int n = snprintf(path, 4400, "%s/recipes/%s", zcode_dir, recipe_hex);
  return n > 0 && n < 4400 && unlink(path) == 0 && mkdir(path, 0700) == 0;
}

static bool gate_unblock_recipe_admission(const char *path) {
  return rmdir(path) == 0;
}

static const char *gate_code(const struct json_value *result) {
  const struct json_value *code = json_get(result, "code");
  return code && code->type == JSON_STR ? json_get_str(code) : "";
}

/* The DHT publication gate for zclassic23.package POINTER records: without
 * two distinct byte-identical build receipts in the node's own store the
 * claim "this exact package is fetchable from me" is refused by name before
 * a plan token exists. The DHT service itself is disabled in this process,
 * so a publish that PASSES the gate lands on the generic DHT_DISABLED
 * refusal — that code is the observable proof the gate opened. */
static int test_publish_reproduction_gate(void) {
  int failures = 0;
  TEST("zcode dht publish: package pointer requires local reproduction") {
    struct rpc_table table;
    rpc_table_init(&table);
    boot_zcode_dht_register_rpc(&table);
    uint8_t package_root[32], recipe_root[32], foreign_root[32];
    memset(package_root, 0xb1, 32);
    memset(recipe_root, 0x51, 32);
    memset(foreign_root, 0xc3, 32);
    struct json_value input, result;

    /* Sequence omission and integer zero are the only auto-sequence forms.
     * A present value of any other JSON type is malformed, never omission. */
    vcs_package_store_close_global();
    json_init(&input);
    gate_publish_without_sequence(&input, "plan", package_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "NO_PACKAGE_STORE");
    json_free(&result);
    json_free(&input);

    json_init(&input);
    gate_publish_input(&input, "plan", "pointer", "zclassic23.package",
                       package_root);
    struct json_value *sequence = gate_mutable_field(&input, "sequence");
    ASSERT(sequence != NULL);
    json_set_int(sequence, 0);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "NO_PACKAGE_STORE");
    json_free(&result);
    json_free(&input);

    static const char *modes[] = {"plan", "commit"};
    for (size_t mode = 0; mode < sizeof(modes) / sizeof(modes[0]); mode++) {
      for (int malformed = 0; malformed < 3; malformed++) {
        json_init(&input);
        gate_publish_input(&input, modes[mode], "pointer",
                           "zclassic23.package", package_root);
        sequence = gate_mutable_field(&input, "sequence");
        ASSERT(sequence != NULL);
        if (malformed == 0)
          json_set_str(sequence, "7");
        else if (malformed == 1)
          json_set_bool(sequence, true);
        else
          json_set_null(sequence);
        ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
        ASSERT_STR_EQ(gate_code(&result), "INVALID_PUBLISH");
        json_free(&result);
        json_free(&input);
      }
    }

    /* No resident store: the refusal names the missing prerequisite. */
    json_init(&input);
    gate_publish_input(&input, "plan", "pointer", "zclassic23.package",
                       package_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "NO_PACKAGE_STORE");
    json_free(&result);
    json_free(&input);

    /* Resident store, but no committed release names the package root. */
    const char *argv[] = {"zclassic23-test", "-packagehost=1",
                          "-packagequota=1000000"};
    ParseParameters(3, argv);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_dht_service", "publish_gate");
    SetDataDir(dd);
    ASSERT(vcs_package_store_open_global());
    ASSERT(vcs_package_store_global() != NULL);
    const char *zcode_dir =
        vcs_package_store_root_dir(vcs_package_store_global());
    ASSERT(zcode_dir != NULL);
    json_init(&input);
    gate_publish_input(&input, "plan", "pointer", "zclassic23.package",
                       package_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "UNKNOWN_PACKAGE");
    json_free(&result);
    json_free(&input);

    /* A committed release exists but the receipts dir is empty: plan and
     * commit refuse identically, before any plan token is consulted. */
    struct vcs_package_release release;
    ASSERT(gate_release(&release, package_root, recipe_root));
    ASSERT(gate_store_release(zcode_dir, &release));
    json_init(&input);
    gate_publish_input(&input, "plan", "pointer", "zclassic23.package",
                       package_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "REPRODUCTION_NOT_EVIDENCED");
    json_free(&result);
    json_free(&input);
    json_init(&input);
    gate_publish_input(&input, "commit", "pointer", "zclassic23.package",
                       package_root);
    json_push_kv_str(&input, "plan_token",
                     "00000000000000000000000000000000"
                     "00000000000000000000000000000000");
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "REPRODUCTION_NOT_EVIDENCED");
    json_free(&result);
    json_free(&input);

    /* One build is one event: a single matching receipt is not
     * reproduction. */
    char receipts_dir[4400];
    int rn = snprintf(receipts_dir, sizeof(receipts_dir), "%s/receipts",
                      zcode_dir);
    ASSERT(rn > 0 && (size_t)rn < sizeof(receipts_dir));
    struct vcs_package_build_receipt first, second;
    ASSERT(gate_receipt(&first, package_root, recipe_root, "14.2.0", 0x40));
    ASSERT(gate_store_receipt(receipts_dir, &first));
    json_init(&input);
    gate_publish_input(&input, "plan", "pointer", "zclassic23.package",
                       package_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "REPRODUCTION_NOT_EVIDENCED");
    json_free(&result);
    json_free(&input);

    /* Two distinct build events agreeing on every output byte satisfy the
     * reproduction half — but the transport root (the fixture's 0xb2
     * constant, held by no store as a carrier) fails the transport half by
     * name, still before any plan token exists. */
    ASSERT(gate_receipt(&second, package_root, recipe_root, "15.1.0", 0x40));
    ASSERT(gate_store_receipt(receipts_dir, &second));
    json_init(&input);
    gate_publish_input(&input, "plan", "pointer", "zclassic23.package",
                       package_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "TRANSPORT_ROOT_NOT_CARRIER");
    json_free(&result);
    json_free(&input);

    /* A real carrier that reconstructs to a DIFFERENT package than the one
     * named is refused by name too: the record would bind this name to
     * somebody else's bytes. */
    uint8_t real_pkg[32], real_recipe[32], carrier_root[32];
    ASSERT(gate_store_transport("lib/base", real_pkg, real_recipe,
                                carrier_root));
    json_init(&input);
    gate_publish_roots(&input, "plan", "pointer", "zclassic23.package",
                       package_root, carrier_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "TRANSPORT_ROOT_NOT_BOUND");
    json_free(&result);
    json_free(&input);

    /* The same carrier with its own package root, release and two agreeing
     * receipts opens the whole gate; with no DHT service resident the
     * publish then lands on the generic DHT_DISABLED refusal, proving the
     * gate passed it through. */
    struct vcs_package_release real_release;
    ASSERT(gate_release(&real_release, real_pkg, real_recipe));
    ASSERT(gate_store_release(zcode_dir, &real_release));
    struct vcs_package_build_receipt ra, rb;
    ASSERT(gate_receipt(&ra, real_pkg, real_recipe, "14.2.0", 0x40));
    ASSERT(gate_receipt(&rb, real_pkg, real_recipe, "15.1.0", 0x40));
    ASSERT(gate_store_receipt(receipts_dir, &ra));
    ASSERT(gate_store_receipt(receipts_dir, &rb));

    /* Classification proves the carrier closure, not that this node can
     * persist the inner metadata during the consumer-equivalent import.
     * Keep those refusals distinct from a successful import that names a
     * different package root, because the operator remedies differ. */
    char blocked_recipe[4400];
    ASSERT(gate_block_recipe_admission(zcode_dir, real_recipe,
                                       blocked_recipe));
    struct vcs_package_public_verdict blocked_verdict;
    enum vcs_package_public_shape blocked_shape =
        vcs_package_public_shape_classify(vcs_package_store_global(),
                                          carrier_root, &blocked_verdict);
    json_init(&input);
    gate_publish_roots(&input, "plan", "pointer", "zclassic23.package",
                       real_pkg, carrier_root);
    bool blocked_rpc = gate_rpc(&table, "zcode_dht_status", &input, &result);
    char blocked_code[64];
    (void)snprintf(blocked_code, sizeof(blocked_code), "%s",
                   blocked_rpc ? gate_code(&result) : "RPC_FAILED");
    json_free(&result);
    json_free(&input);
    bool unblocked = gate_unblock_recipe_admission(blocked_recipe);
    ASSERT(unblocked);
    ASSERT_EQ(blocked_shape, VCS_PACKAGE_PUBLIC_TRANSPORT);
    ASSERT_STR_EQ(blocked_code, "TRANSPORT_IMPORT_REFUSED");

    json_init(&input);
    gate_publish_roots(&input, "plan", "pointer", "zclassic23.package",
                       real_pkg, carrier_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "DHT_DISABLED");
    json_free(&result);
    json_free(&input);

    /* Receipts naming a different root pair do not count. */
    struct vcs_package_release foreign_release;
    ASSERT(gate_release(&foreign_release, foreign_root, recipe_root));
    ASSERT(gate_store_release(zcode_dir, &foreign_release));
    struct vcs_package_build_receipt fa, fb;
    ASSERT(gate_receipt(&fa, foreign_root, recipe_root, "14.2.0", 0x50));
    ASSERT(gate_receipt(&fb, foreign_root, recipe_root, "15.1.0", 0x60));
    ASSERT(gate_store_receipt(receipts_dir, &fa));
    ASSERT(gate_store_receipt(receipts_dir, &fb));
    json_init(&input);
    gate_publish_input(&input, "plan", "pointer", "zclassic23.package",
                       foreign_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "REPRODUCTION_NOT_EVIDENCED");
    json_free(&result);
    json_free(&input);

    /* Other namespaces and other kinds are never gated. */
    json_init(&input);
    gate_publish_input(&input, "plan", "pointer", "science", package_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "DHT_DISABLED");
    json_free(&result);
    json_free(&input);
    json_init(&input);
    gate_publish_input(&input, "plan", "provider", "zclassic23.package",
                       package_root);
    ASSERT(gate_rpc(&table, "zcode_dht_status", &input, &result));
    ASSERT_STR_EQ(gate_code(&result), "DHT_DISABLED");
    json_free(&result);
    json_free(&input);

    vcs_package_store_close_global();
    const char *reset_argv[] = {"zclassic23-test"};
    ParseParameters(1, reset_argv);
    SetDataDir("");
    test_rm_rf_recursive(dd);
    PASS();
  }
_test_next:;
  return failures;
}

int test_zcode_dht_service(void) {
  int failures = test_disabled_diagnostics();
  failures += test_publish_reproduction_gate();
  failures += test_publication_monotonic_retry();
  failures += test_publication_delegation_window();
  failures += test_publication_auto_sequence();
  failures += test_publication_slot_supersede();
  failures += test_publication_slot_superseded_freed();
  failures += test_publication_heal_survives_restart();
  failures += test_publication_supersede_cancels_children();
  failures += test_publication_ceiling_hosts_a_real_node();
  failures += test_record_churn_fallback();
  failures += test_deep_ancestry();
  failures += test_peer_admission_order();
  failures += test_record_transport_and_restart();
  failures += test_sparse_iterative_network();
  failures += test_sparse_space16_network();
  TEST("zcode dht service: Noise-authenticated two-node lookup and restart") {
    char adir[] = "/tmp/zcl_dht_service_a_XXXXXX";
    char bdir[] = "/tmp/zcl_dht_service_b_XXXXXX";
    ASSERT(mkdtemp(adir) != NULL);
    ASSERT(mkdtemp(bdir) != NULL);
    uint8_t genesis[32], anoise[32], bnoise[32], transcript[32];
    memset(genesis, 0x11, 32);
    memset(anoise, 0x22, 32);
    memset(bnoise, 0x33, 32);
    memset(transcript, 0x55, 32);
    ASSERT(fixture_identity(adir, 0x61, genesis, anoise));
    ASSERT(fixture_identity(bdir, 0x62, genesis, bnoise));
    struct vcs_zcode_dht_service *a = fixture_service(adir, genesis, anoise);
    struct vcs_zcode_dht_service *b = fixture_service(bdir, genesis, bnoise);
    ASSERT(a && b);
    ASSERT(vcs_zcode_dht_service_enabled(a));
    ASSERT(vcs_zcode_dht_service_enabled(b));

    struct vcs_zcode_dht_session as =
                                     {
                                         .established = true,
                                         .generation = 42,
                                         .connection_serial = 1,
                                     },
                                 bs = {.established = true,
                                       .generation = 42,
                                       .connection_serial = 2};
    memcpy(as.remote_static, bnoise, 32);
    memcpy(bs.remote_static, anoise, 32);
    memcpy(as.transcript_hash, transcript, 32);
    memcpy(bs.transcript_hash, transcript, 32);
    ASSERT(vcs_zcode_dht_service_session_open(a, 2, &as, test_time(1001)));
    ASSERT(vcs_zcode_dht_service_session_open(b, 1, &bs, test_time(1001)));

    uint8_t replay[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
    size_t replay_len = 0;
    ASSERT(pump(a, b, 2, 1, 1001, replay, &replay_len));
    ASSERT(pump(b, a, 1, 2, 1001, NULL, NULL));
    ASSERT(pump(a, b, 2, 1, 1001, NULL, NULL));

    struct vcs_zcode_dht_service_status ast, bst;
    vcs_zcode_dht_service_status(a, &ast);
    vcs_zcode_dht_service_status(b, &bst);
    ASSERT_EQ(ast.contacts, 1);
    ASSERT_EQ(bst.contacts, 1);
    ASSERT_EQ(ast.buckets_used, 1);
    ASSERT_EQ(bst.buckets_used, 1);
    ASSERT_EQ(ast.connected_authenticated, 1);
    ASSERT_EQ(bst.connected_authenticated, 1);
    ASSERT(ast.find_node_sent > 0 && ast.nodes_received > 0);

    enum vcs_zcode_dht_reject_reason rejected;
    ASSERT(!vcs_zcode_dht_service_handle_frame(b, 1, replay, replay_len,
                                               test_time(1001),
                                               &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_REPLAY);

    uint8_t target[32];
    memset(target, 0x7a, 32);
    uint64_t lookup = 0;
    ASSERT(vcs_zcode_dht_service_lookup_begin(a, target, test_time(1002),
                                              &lookup));
    ASSERT(pump(a, b, 2, 1, 1002, NULL, NULL));
    ASSERT(pump(b, a, 1, 2, 1002, NULL, NULL));
    struct vcs_zcode_dht_lookup_result result;
    ASSERT(vcs_zcode_dht_service_lookup_poll(a, lookup, test_time(1002),
                                             &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_COMPLETE);
    ASSERT_EQ(result.count, 2);
    uint8_t d0[32], d1[32];
    vcs_zcode_dht_xor_distance(result.node_ids[0], target, d0);
    vcs_zcode_dht_xor_distance(result.node_ids[1], target, d1);
    ASSERT(memcmp(d0, d1, 32) <= 0);

    /* A hostile request may reuse an outstanding response query ID. Request
     * and response replay namespaces are independent, so it cannot poison the
     * legitimate NODES response. */
    ASSERT(vcs_zcode_dht_service_lookup_begin(a, target, test_time(1002),
                                              &lookup));
    uint8_t collision_query[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
    uint64_t collision_peer = 0;
    size_t collision_query_len = 0;
    ASSERT(vcs_zcode_dht_service_next_outbound(
        a, 2, &collision_peer, collision_query, sizeof(collision_query),
        &collision_query_len));
    ASSERT_EQ(collision_peer, 2);
    ASSERT_EQ(collision_query[10], VCS_ZCODE_DHT_MSG_FIND_NODE);
    const size_t query_id_off = VCS_ZCODE_DHT_MSGS_HEADER_BYTES + 8u + 32u;
    uint8_t collision_find[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
    size_t collision_find_len = 0;
    ASSERT(signed_find(bdir, 42, transcript, 0xdd, 0x7a, collision_find,
                       sizeof(collision_find), &collision_find_len));
    memcpy(collision_find + query_id_off, collision_query + query_id_off,
           VCS_ZCODE_DHT_MSG_QUERY_ID_BYTES);
    ASSERT(resign_wire(bdir, transcript, collision_find, collision_find_len));
    ASSERT(vcs_zcode_dht_service_handle_frame(
        a, 2, collision_find, collision_find_len, test_time(1002), &rejected));
    (void)drain(a);
    ASSERT(vcs_zcode_dht_service_handle_frame(
        b, 1, collision_query, collision_query_len, test_time(1002),
        &rejected));
    uint8_t collision_response[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
    uint64_t collision_response_peer = 0;
    size_t collision_response_len = 0;
    ASSERT(vcs_zcode_dht_service_next_outbound(
        b, 1, &collision_response_peer, collision_response,
        sizeof(collision_response), &collision_response_len));
    ASSERT(vcs_zcode_dht_service_handle_frame(
        a, 2, collision_response, collision_response_len, test_time(1002),
        &rejected));
    ASSERT(vcs_zcode_dht_service_lookup_poll(a, lookup, test_time(1002),
                                             &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_COMPLETE);
    ASSERT(!vcs_zcode_dht_service_handle_frame(
        a, 2, collision_response, collision_response_len, test_time(1002),
        &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_REPLAY);

    /* A correctly signed peer may name any ID. The frame is valid, but an
     * unknown ID is only an unreachable hint and never appears in results. */
    ASSERT(vcs_zcode_dht_service_lookup_begin(a, target, test_time(1002),
                                              &lookup));
    ASSERT(pump(a, b, 2, 1, 1002, NULL, NULL));
    uint64_t hinted_peer = 0;
    size_t hinted_len = 0;
    uint8_t hinted[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
    ASSERT(vcs_zcode_dht_service_next_outbound(
        b, 1, &hinted_peer, hinted, sizeof(hinted), &hinted_len));
    size_t hinted_off =
        VCS_ZCODE_DHT_MSGS_HEADER_BYTES + VCS_ZCODE_DHT_MSGS_AUTH_BYTES;
    ASSERT_EQ(hinted[hinted_off], 2);
    memset(hinted + hinted_off + 1 + 32, 0xff, 32);
    ASSERT(resign_wire(bdir, transcript, hinted, hinted_len));
    ASSERT(vcs_zcode_dht_service_handle_frame(
        a, 2, hinted, hinted_len, test_time(1002), &rejected));
    ASSERT(vcs_zcode_dht_service_lookup_poll(a, lookup, test_time(1002),
                                             &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_COMPLETE);
    for (uint32_t i = 0; i < result.count; i++)
      ASSERT(result.node_ids[i][0] != 0xff);

    /* Exact bounds and established Noise are checked before identity or
     * query state, and an arbitrary NODES response is never admitted. */
    ASSERT(!vcs_zcode_dht_service_handle_frame(b, 99, replay, replay_len,
                                               test_time(1002),
                                               &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_PLAINTEXT);
    uint8_t oversized[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES + 1];
    memcpy(oversized, replay, replay_len);
    oversized[replay_len] = 0;
    ASSERT(!vcs_zcode_dht_service_handle_frame(
        b, 1, oversized, replay_len + 1, test_time(1002), &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_MALFORMED);
    size_t forged_len = 0;
    ASSERT(signed_nodes(bdir, 42, transcript, 0xa1, oversized,
                        sizeof(oversized), &forged_len));
    ASSERT(!vcs_zcode_dht_service_handle_frame(
        a, 2, oversized, forged_len, test_time(1002), &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_UNSOLICITED);
    ASSERT(signed_find(adir, 43, transcript, 0xa2, 0x7b, oversized,
                       sizeof(oversized), &forged_len));
    ASSERT(!vcs_zcode_dht_service_handle_frame(
        b, 1, oversized, forged_len, test_time(1002), &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_SESSION);

    /* A response with valid authentication but poisoned ordering is
     * rejected without consuming its query; the later valid response is
     * then rejected under the exact 30-second deadline. */
    ASSERT(vcs_zcode_dht_service_lookup_begin(a, target, test_time(1003),
                                              &lookup));
    ASSERT(pump(a, b, 2, 1, 1003, NULL, NULL));
    uint64_t response_peer = 0;
    size_t response_len = 0;
    uint8_t response[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
    ASSERT(vcs_zcode_dht_service_next_outbound(
        b, 1, &response_peer, response, sizeof(response), &response_len));
    ASSERT_EQ(response_peer, 1);
    uint8_t poisoned[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
    memcpy(poisoned, response, response_len);
    size_t nodes_off =
        VCS_ZCODE_DHT_MSGS_HEADER_BYTES + VCS_ZCODE_DHT_MSGS_AUTH_BYTES;
    ASSERT_EQ(poisoned[nodes_off], 2);
    uint8_t swap[32];
    memcpy(swap, poisoned + nodes_off + 1, 32);
    memcpy(poisoned + nodes_off + 1, poisoned + nodes_off + 33, 32);
    memcpy(poisoned + nodes_off + 33, swap, 32);
    ASSERT(resign_wire(bdir, transcript, poisoned, response_len));
    ASSERT(!vcs_zcode_dht_service_handle_frame(
        a, 2, poisoned, response_len, test_time(1003), &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_POISONED);
    /* The periodic sweep may retire the active slot before a late frame is
     * dispatched.  A bounded tombstone must preserve the exact EXPIRED
     * diagnosis instead of degrading it to UNSOLICITED. */
    vcs_zcode_dht_service_tick(a, test_time(1034));
    ASSERT(!vcs_zcode_dht_service_handle_frame(
        a, 2, response, response_len, test_time(1034), &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_EXPIRED);
    ASSERT(vcs_zcode_dht_service_lookup_poll(a, lookup, test_time(1034),
                                             &result));
    ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_COMPLETE);
    ASSERT_EQ(result.termination,
              VCS_ZCODE_DHT_TERMINATION_SHORTLIST_STABLE);

    /* Four requests/s with burst eight is exact and independent of peer
     * lengths; a ninth same-second request is named rate-limit. */
    (void)drain(b);
    for (uint8_t i = 1; i <= 9; i++) {
      ASSERT(signed_find(adir, 42, transcript, (uint8_t)(0xb0 + i), 0x7c,
                         oversized, sizeof(oversized), &forged_len));
      bool accepted = vcs_zcode_dht_service_handle_frame(
          b, 1, oversized, forged_len, test_time(2000), &rejected);
      if (i <= 8)
        ASSERT(accepted);
      else {
        ASSERT(!accepted);
        ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_RATE);
      }
    }
    ASSERT_EQ(drain(b), 8);
    ASSERT(signed_find(adir, 42, transcript, 0xca, 0x7c, oversized,
                       sizeof(oversized), &forged_len));
    ASSERT(!vcs_zcode_dht_service_handle_frame(
        b, 1, oversized, forged_len,
        (struct vcs_zcode_dht_time){.wall_unix = 80000,
                                    .monotonic_s = 2000},
        &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_RATE);
    ASSERT(signed_find(adir, 42, transcript, 0xcb, 0x7c, oversized,
                       sizeof(oversized), &forged_len));
    ASSERT(vcs_zcode_dht_service_handle_frame(
        b, 1, oversized, forged_len,
        (struct vcs_zcode_dht_time){.wall_unix = 3000,
                                    .monotonic_s = 2001},
        &rejected));
    ASSERT_EQ(drain(b), 1);

    /* The replay ledger is sized for the whole admitted 30-second frame
     * population, not a 16-entry sample. More than sixteen distinct signed
     * frames cannot evict an earlier still-live query ID. */
    uint8_t old_frame[VCS_ZCODE_DHT_NODES_MAX_WIRE_BYTES];
    size_t old_frame_len = 0;
    for (uint8_t i = 0; i < 24; i++) {
      uint64_t mono = 3000 + i / 3;
      ASSERT(signed_find(adir, 42, transcript, (uint8_t)(0x10 + i), 0x7d,
                         oversized, sizeof(oversized), &forged_len));
      if (i == 0) {
        memcpy(old_frame, oversized, forged_len);
        old_frame_len = forged_len;
      }
      struct vcs_zcode_dht_time when = {.wall_unix = 3000,
                                        .monotonic_s = mono};
      ASSERT(vcs_zcode_dht_service_handle_frame(
          b, 1, oversized, forged_len, when, &rejected));
      (void)drain(b);
    }
    ASSERT(!vcs_zcode_dht_service_handle_frame(
        b, 1, old_frame, old_frame_len,
        (struct vcs_zcode_dht_time){.wall_unix = 3000, .monotonic_s = 3007},
        &rejected));
    ASSERT_EQ(rejected, VCS_ZCODE_DHT_REJECT_REPLAY);

    /* A node ID owns one authenticated service session. Newer local serials
     * replace older sessions; equal serials retain the lower peer ID, and a
     * retired exact connection cannot be re-admitted while still live. */
    uint8_t transcript2[32], transcript3[32];
    memset(transcript2, 0x56, sizeof(transcript2));
    memset(transcript3, 0x57, sizeof(transcript3));
    struct vcs_zcode_dht_session newer = {.established = true,
                                          .generation = 43,
                                          .connection_serial = 10};
    memcpy(newer.remote_static, bnoise, 32);
    memcpy(newer.transcript_hash, transcript2, 32);
    ASSERT(vcs_zcode_dht_service_session_open(a, 3, &newer,
                                              test_time(1007)));
    ASSERT(signed_find(bdir, 43, transcript2, 0xe1, 0x7e, oversized,
                       sizeof(oversized), &forged_len));
    ASSERT(vcs_zcode_dht_service_handle_frame(
        a, 3, oversized, forged_len, test_time(1007), &rejected));
    vcs_zcode_dht_service_status(a, &ast);
    ASSERT_EQ(ast.connected_authenticated, 1);
    ASSERT_EQ(ast.duplicate_sessions_retired, 1);
    ASSERT(!vcs_zcode_dht_service_session_open(a, 2, &as,
                                               test_time(1007)));

    struct vcs_zcode_dht_session tied = {.established = true,
                                         .generation = 44,
                                         .connection_serial = 10};
    memcpy(tied.remote_static, bnoise, 32);
    memcpy(tied.transcript_hash, transcript3, 32);
    /* The cached delegation binds the equal-serial replacement before it
     * can send a DHT frame, so the higher peer ID is rejected at admission
     * instead of surviving until frame authentication. */
    ASSERT(!vcs_zcode_dht_service_session_open(a, 4, &tied,
                                               test_time(1007)));
    vcs_zcode_dht_service_status(a, &ast);
    ASSERT_EQ(ast.connected_authenticated, 1);
    ASSERT_EQ(ast.duplicate_sessions_retired, 2);

    vcs_zcode_dht_service_tick(a, test_time(1008));
    vcs_zcode_dht_service_free(a, test_time(1008));
    a = NULL;
    a = fixture_service(adir, genesis, anoise);
    ASSERT(a != NULL);
    vcs_zcode_dht_service_status(a, &ast);
    ASSERT(ast.persistence_loaded);
    ASSERT_EQ(ast.persistence_load_count, 1);
    ASSERT_EQ(ast.cold_contacts, 1);
    ASSERT_EQ(ast.buckets_used, 1);
    ASSERT_EQ(ast.connected_authenticated, 0);

    /* The eight-slot lookup queue is a hard cap even when every lookup
     * completes locally and waits for its caller to collect the result. */
    uint64_t ids[VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS];
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++)
      ASSERT(vcs_zcode_dht_service_lookup_begin(a, target, test_time(1010),
                                                &ids[i]));
    ASSERT(!vcs_zcode_dht_service_lookup_begin(a, target, test_time(1010),
                                               &lookup));
    for (size_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_LOOKUPS; i++) {
      ASSERT(vcs_zcode_dht_service_lookup_poll(a, ids[i], test_time(1010),
                                               &result));
      ASSERT_EQ(result.state, VCS_ZCODE_DHT_LOOKUP_COMPLETE);
    }

    /* Unauthenticated handshakes lose their service slot after a monotonic
     * deadline and the still-live exact connection cannot immediately claim
     * it again. Session freshness follows the local serial, never numeric
     * ordering of the transcript-derived generation token. */
    struct vcs_zcode_dht_session unknown = as;
    memset(unknown.remote_static, 0x99, sizeof(unknown.remote_static));
    ASSERT(vcs_zcode_dht_service_session_open(a, 900, &unknown,
                                              test_time(1011)));
    vcs_zcode_dht_service_tick(a, test_time(1026));
    vcs_zcode_dht_service_status(a, &ast);
    ASSERT_EQ(ast.unauthenticated_expired, 1);
    ASSERT(!vcs_zcode_dht_service_session_open(a, 900, &unknown,
                                               test_time(1026)));
    struct vcs_zcode_dht_session high_token = unknown;
    high_token.generation = UINT64_MAX;
    high_token.connection_serial = 20;
    ASSERT(vcs_zcode_dht_service_session_open(a, 901, &high_token,
                                              test_time(1027)));
    vcs_zcode_dht_service_session_close(a, 901, high_token.generation,
                                        test_time(1027));
    struct vcs_zcode_dht_session low_token = as;
    low_token.generation = 1;
    low_token.connection_serial = 21;
    ASSERT(vcs_zcode_dht_service_session_open(a, 901, &low_token,
                                              test_time(1027)));
    vcs_zcode_dht_service_session_close(a, 901, low_token.generation,
                                        test_time(1027));

    /* Peer session slots are reusable after disconnect; churn cannot
     * permanently exhaust the 64-session authentication budget. */
    for (uint64_t i = 0; i < VCS_ZCODE_DHT_SERVICE_MAX_PEERS; i++)
      ASSERT(vcs_zcode_dht_service_session_open(a, 100 + i, &unknown,
                                                test_time(1028)));
    ASSERT(!vcs_zcode_dht_service_session_open(a, 1000, &unknown,
                                               test_time(1028)));
    vcs_zcode_dht_service_session_close(a, 100, 42, test_time(1028));
    ASSERT(vcs_zcode_dht_service_session_open(a, 1000, &unknown,
                                              test_time(1028)));

    vcs_zcode_dht_service_free(a, test_time(1009));
    vcs_zcode_dht_service_free(b, test_time(1009));

    /* A trailing byte on cold start never partially publishes the valid
     * prefix. The service stays enabled but starts with an empty table and
     * a named persistence error. */
    char contacts_path[512];
    snprintf(contacts_path, sizeof(contacts_path), "%s/zcode/dht/contacts.v2",
             adir);
    FILE *contacts = fopen(contacts_path, "ab");
    ASSERT(contacts != NULL);
    ASSERT(fputc(0, contacts) != EOF);
    ASSERT(fclose(contacts) == 0);
    a = fixture_service(adir, genesis, anoise);
    ASSERT(a != NULL);
    vcs_zcode_dht_service_status(a, &ast);
    ASSERT(!ast.persistence_loaded);
    ASSERT_EQ(ast.contacts, 0);
    ASSERT(ast.last_error[0] != '\0');
    vcs_zcode_dht_service_free(a, test_time(1012));
    cleanup_fixture(adir);
    cleanup_fixture(bdir);
    PASS();
  }
_test_next:;
  return failures;
}
