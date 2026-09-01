/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Deterministic persistent local-sovereignty rule engine. */

#include "vcs/zcode_sovereignty_policy.h"

#include "base/bytes.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"
#include "crypto/sha3.h"
#include "platform/file_metadata.h"
#include "platform/os_proc.h"
#include "platform/positioned_file.h"
#include "platform/private_directory.h"
#include "platform/private_file.h"

#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SOVEREIGNTY_RULE_VERSION 1u
#define SOVEREIGNTY_POLICY_VERSION 1u
#define SOVEREIGNTY_POLICY_HEADER_BYTES 84u
#define SOVEREIGNTY_POLICY_FLAG_ADVISORY 1u
#define SOVEREIGNTY_RULE_DOMAIN "zcl.zcode.sovereignty.rule.v1"
#define SOVEREIGNTY_POLICY_DOMAIN "zcl.zcode.sovereignty.policy.v1"

static const uint8_t rule_magic[8] = {'Z', 'C', 'S', 'O', 'V', 'R', 0x0d,
                                      0x0a};
static const uint8_t policy_magic[8] = {'Z', 'C', 'S', 'O', 'V', 'P', 0x0d,
                                        0x0a};

struct sovereignty_entry {
  struct vcs_zcode_sovereignty_rule rule;
  uint8_t wire[VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES];
};

struct vcs_zcode_sovereignty_policy {
  uint8_t network_genesis[32];
  bool advisory_enabled;
  size_t count;
  struct sovereignty_entry *entries;
};

static _Atomic uint64_t g_policy_temp_sequence;

static enum vcs_zcode_sovereignty_result policy_error(
    char *out, size_t capacity, enum vcs_zcode_sovereignty_result result,
    const char *message)
{
  if (out && capacity)
    (void)snprintf(out, capacity, "%s", message ? message : "policy error");
  return result;
}

const char *vcs_zcode_sovereignty_action_string(
    enum vcs_zcode_sovereignty_action action)
{
  static const char *const names[] = {"DISCOVER", "FETCH", "STORE", "INDEX",
                                      "SERVE", "FORWARD", "EXECUTE"};
  return (unsigned)action < VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT
             ? names[action]
             : "UNKNOWN";
}

const char *vcs_zcode_sovereignty_result_string(
    enum vcs_zcode_sovereignty_result result)
{
  switch (result) {
  case VCS_ZCODE_SOVEREIGNTY_OK: return "ok";
  case VCS_ZCODE_SOVEREIGNTY_INVALID: return "invalid";
  case VCS_ZCODE_SOVEREIGNTY_DUPLICATE: return "duplicate";
  case VCS_ZCODE_SOVEREIGNTY_NOT_FOUND: return "not-found";
  case VCS_ZCODE_SOVEREIGNTY_CAP: return "capacity";
  case VCS_ZCODE_SOVEREIGNTY_IO: return "io";
  case VCS_ZCODE_SOVEREIGNTY_CORRUPT: return "corrupt";
  }
  return "unknown";
}

static bool text_value_valid(const uint8_t value[32])
{
  size_t length = 0;
  while (length < 32 && value[length])
    length++;
  if (!length || length > 31)
    return false;
  for (size_t i = 0; i < length; i++) {
    uint8_t c = value[i];
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
          c == '_' || c == '-'))
      return false;
  }
  for (size_t i = length; i < 32; i++)
    if (value[i])
      return false;
  return true;
}

static bool rule_shape(const struct vcs_zcode_sovereignty_rule *rule)
{
  if (!rule || rule->source < VCS_ZCODE_SOVEREIGNTY_LOCAL ||
      rule->source > VCS_ZCODE_SOVEREIGNTY_ADVISORY ||
      rule->effect < VCS_ZCODE_SOVEREIGNTY_ALLOW ||
      rule->effect > VCS_ZCODE_SOVEREIGNTY_BLOCK ||
      rule->scope < VCS_ZCODE_SOVEREIGNTY_FULL_ROOT ||
      rule->scope > VCS_ZCODE_SOVEREIGNTY_CLASSIFICATION ||
      !rule->action_mask ||
      (rule->action_mask &
       ~((1u << VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT) - 1u)) != 0)
    return false;
  if (rule->scope == VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE ||
      rule->scope == VCS_ZCODE_SOVEREIGNTY_CLASSIFICATION)
    return text_value_valid(rule->value);
  return zcl_bytes_any_set(rule->value, 32);
}

static void rule_write_prefix(const struct vcs_zcode_sovereignty_rule *rule,
                              uint8_t wire[80])
{
  memset(wire, 0, VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES);
  memcpy(wire, rule_magic, 8);
  zcl_write_u16_le(wire + 8, SOVEREIGNTY_RULE_VERSION);
  wire[10] = (uint8_t)rule->source;
  wire[11] = (uint8_t)rule->effect;
  wire[12] = (uint8_t)rule->scope;
  wire[13] = rule->action_mask;
  memcpy(wire + 16, rule->value, 32);
}

static void rule_derive_id(const uint8_t wire[80], uint8_t out[32])
{
  struct sha3_256_ctx sha;
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)SOVEREIGNTY_RULE_DOMAIN,
                 sizeof(SOVEREIGNTY_RULE_DOMAIN));
  sha3_256_write(&sha, wire, 48);
  sha3_256_finalize(&sha, out);
}

static bool rule_encode(const struct vcs_zcode_sovereignty_rule *rule,
                        uint8_t wire[80])
{
  if (!rule_shape(rule))
    return false;
  rule_write_prefix(rule, wire);
  uint8_t derived[32];
  rule_derive_id(wire, derived);
  if (memcmp(derived, rule->id, 32) != 0)
    return false;
  memcpy(wire + 48, rule->id, 32);
  return true;
}

static bool rule_decode(const uint8_t wire[80],
                        struct vcs_zcode_sovereignty_rule *rule)
{
  memset(rule, 0, sizeof(*rule));
  if (memcmp(wire, rule_magic, 8) != 0 ||
      zcl_read_u16_le(wire + 8) != SOVEREIGNTY_RULE_VERSION || wire[14] ||
      wire[15])
    return false;
  rule->source = (enum vcs_zcode_sovereignty_source)wire[10];
  rule->effect = (enum vcs_zcode_sovereignty_effect)wire[11];
  rule->scope = (enum vcs_zcode_sovereignty_scope)wire[12];
  rule->action_mask = wire[13];
  memcpy(rule->value, wire + 16, 32);
  memcpy(rule->id, wire + 48, 32);
  return rule_shape(rule) && rule_encode(rule, (uint8_t[80]){0});
}

enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_rule_build(
    struct vcs_zcode_sovereignty_rule *out,
    enum vcs_zcode_sovereignty_source source,
    enum vcs_zcode_sovereignty_effect effect,
    enum vcs_zcode_sovereignty_scope scope, uint8_t action_mask,
    const uint8_t value[32])
{
  if (!out || !value)
    return VCS_ZCODE_SOVEREIGNTY_INVALID;
  memset(out, 0, sizeof(*out));
  out->source = source;
  out->effect = effect;
  out->scope = scope;
  out->action_mask = action_mask;
  memcpy(out->value, value, 32);
  if (!rule_shape(out)) {
    memset(out, 0, sizeof(*out));
    return VCS_ZCODE_SOVEREIGNTY_INVALID;
  }
  uint8_t wire[80];
  rule_write_prefix(out, wire);
  rule_derive_id(wire, out->id);
  return VCS_ZCODE_SOVEREIGNTY_OK;
}

struct vcs_zcode_sovereignty_policy *vcs_zcode_sovereignty_policy_create(
    const uint8_t network_genesis[32])
{
  if (!network_genesis || !zcl_bytes_any_set(network_genesis, 32))
    return NULL;
  struct vcs_zcode_sovereignty_policy *policy =
      zcl_calloc(1, sizeof(*policy), "sovereignty.policy");
  if (!policy)
    return NULL;
  policy->entries = zcl_calloc(VCS_ZCODE_SOVEREIGNTY_MAX_RULES,
                               sizeof(*policy->entries),
                               "sovereignty.policy.rules");
  if (!policy->entries) {
    free(policy);
    return NULL;
  }
  memcpy(policy->network_genesis, network_genesis, 32);
  return policy;
}

void vcs_zcode_sovereignty_policy_free(
    struct vcs_zcode_sovereignty_policy *policy)
{
  if (!policy)
    return;
  free(policy->entries);
  free(policy);
}

static int entry_compare(const void *left, const void *right)
{
  const struct sovereignty_entry *a = left;
  const struct sovereignty_entry *b = right;
  return memcmp(a->wire, b->wire, VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES);
}

enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_policy_add(
    struct vcs_zcode_sovereignty_policy *policy,
    const struct vcs_zcode_sovereignty_rule *rule)
{
  uint8_t wire[80];
  if (!policy || !rule || !rule_encode(rule, wire))
    return VCS_ZCODE_SOVEREIGNTY_INVALID;
  for (size_t i = 0; i < policy->count; i++)
    if (memcmp(policy->entries[i].rule.id, rule->id, 32) == 0)
      return VCS_ZCODE_SOVEREIGNTY_DUPLICATE;
  if (policy->count >= VCS_ZCODE_SOVEREIGNTY_MAX_RULES)
    return VCS_ZCODE_SOVEREIGNTY_CAP;
  struct sovereignty_entry *entry = &policy->entries[policy->count++];
  entry->rule = *rule;
  memcpy(entry->wire, wire, sizeof(entry->wire));
  qsort(policy->entries, policy->count, sizeof(*policy->entries),
        entry_compare);
  return VCS_ZCODE_SOVEREIGNTY_OK;
}

enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_policy_remove(
    struct vcs_zcode_sovereignty_policy *policy, const uint8_t rule_id[32])
{
  if (!policy || !rule_id)
    return VCS_ZCODE_SOVEREIGNTY_INVALID;
  for (size_t i = 0; i < policy->count; i++)
    if (memcmp(policy->entries[i].rule.id, rule_id, 32) == 0) {
      memmove(&policy->entries[i], &policy->entries[i + 1],
              (policy->count - i - 1) * sizeof(*policy->entries));
      policy->count--;
      memset(&policy->entries[policy->count], 0, sizeof(*policy->entries));
      return VCS_ZCODE_SOVEREIGNTY_OK;
    }
  return VCS_ZCODE_SOVEREIGNTY_NOT_FOUND;
}

void vcs_zcode_sovereignty_policy_set_advisory(
    struct vcs_zcode_sovereignty_policy *policy, bool enabled)
{
  if (policy)
    policy->advisory_enabled = enabled;
}

bool vcs_zcode_sovereignty_policy_advisory(
    const struct vcs_zcode_sovereignty_policy *policy)
{
  return policy && policy->advisory_enabled;
}

size_t vcs_zcode_sovereignty_policy_count(
    const struct vcs_zcode_sovereignty_policy *policy)
{
  return policy ? policy->count : 0;
}

size_t vcs_zcode_sovereignty_policy_rules(
    const struct vcs_zcode_sovereignty_policy *policy,
    struct vcs_zcode_sovereignty_rule *out, size_t capacity)
{
  if (!policy || (!out && capacity))
    return 0;
  size_t copied = policy->count < capacity ? policy->count : capacity;
  for (size_t i = 0; i < copied; i++)
    out[i] = policy->entries[i].rule;
  return policy->count;
}

static bool rule_matches(const struct vcs_zcode_sovereignty_rule *rule,
                         const struct vcs_zcode_sovereignty_subject *subject)
{
  switch (rule->scope) {
  case VCS_ZCODE_SOVEREIGNTY_FULL_ROOT:
    return memcmp(rule->value, subject->semantic_root, 32) == 0 ||
           memcmp(rule->value, subject->transport_root, 32) == 0;
  case VCS_ZCODE_SOVEREIGNTY_PACKAGE:
    return memcmp(rule->value, subject->package_root, 32) == 0;
  case VCS_ZCODE_SOVEREIGNTY_PUBLISHER_ZID:
    return memcmp(rule->value, subject->publisher_zid, 32) == 0;
  case VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE:
    return memcmp(rule->value, subject->service_type, 32) == 0;
  case VCS_ZCODE_SOVEREIGNTY_CLASSIFICATION:
    return memcmp(rule->value, subject->local_classification, 32) == 0;
  }
  return false;
}

struct vcs_zcode_sovereignty_decision vcs_zcode_sovereignty_policy_check(
    const struct vcs_zcode_sovereignty_policy *policy,
    enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_sovereignty_subject *subject)
{
  struct vcs_zcode_sovereignty_decision decision = {0};
  decision.defaulted = true;
  if (!policy || !subject ||
      (unsigned)action >= VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT)
    return decision;
  const struct vcs_zcode_sovereignty_rule *allowed = NULL;
  for (size_t i = 0; i < policy->count; i++) {
    const struct vcs_zcode_sovereignty_rule *rule = &policy->entries[i].rule;
    if (!(rule->action_mask & (1u << action)) ||
        (rule->source == VCS_ZCODE_SOVEREIGNTY_ADVISORY &&
         !policy->advisory_enabled) ||
        !rule_matches(rule, subject))
      continue;
    if (rule->effect == VCS_ZCODE_SOVEREIGNTY_BLOCK) {
      decision.defaulted = false;
      decision.advisory =
          rule->source == VCS_ZCODE_SOVEREIGNTY_ADVISORY;
      memcpy(decision.rule_id, rule->id, 32);
      return decision;
    }
    if (!allowed)
      allowed = rule;
  }
  if (allowed) {
    decision.allow = true;
    decision.defaulted = false;
    decision.advisory =
        allowed->source == VCS_ZCODE_SOVEREIGNTY_ADVISORY;
    memcpy(decision.rule_id, allowed->id, 32);
    return decision;
  }
  decision.allow = action == VCS_ZCODE_SOVEREIGNTY_DISCOVER;
  return decision;
}

bool vcs_zcode_sovereignty_policy_decide_callback(
    void *ctx, enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_sovereignty_subject *subject)
{
  return vcs_zcode_sovereignty_policy_check(ctx, action, subject).allow;
}

static bool policy_paths(const char *datadir, char directory[1400],
                         char path[1500], bool create_directories,
                         char *error, size_t error_capacity)
{
  if (!datadir || !datadir[0]) {
    (void)policy_error(error, error_capacity, VCS_ZCODE_SOVEREIGNTY_IO,
                       "sovereignty datadir is missing");
    return false;
  }
  char zcode[1300];
  int n = snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
  if (n <= 0 || (size_t)n >= sizeof(zcode) ||
      (create_directories && !platform_private_directory_ensure(zcode))) {
    (void)policy_error(error, error_capacity, VCS_ZCODE_SOVEREIGNTY_IO,
                       "cannot create zcode directory");
    return false;
  }
  n = snprintf(directory, 1400, "%s/zcode/policy", datadir);
  if (n <= 0 || n >= 1400 ||
      (create_directories &&
       !platform_private_directory_ensure(directory))) {
    (void)policy_error(error, error_capacity, VCS_ZCODE_SOVEREIGNTY_IO,
                       "cannot create sovereignty policy directory");
    return false;
  }
  n = snprintf(path, 1500, "%s/%s", datadir,
               VCS_ZCODE_SOVEREIGNTY_POLICY_FILE);
  if (n <= 0 || n >= 1500) {
    (void)policy_error(error, error_capacity, VCS_ZCODE_SOVEREIGNTY_IO,
                       "sovereignty policy path too long");
    return false;
  }
  return true;
}

static void policy_digest(const struct vcs_zcode_sovereignty_policy *policy,
                          uint32_t flags, uint8_t out[32])
{
  struct sha3_256_ctx sha;
  uint8_t scalar[4];
  sha3_256_init(&sha);
  sha3_256_write(&sha, (const uint8_t *)SOVEREIGNTY_POLICY_DOMAIN,
                 sizeof(SOVEREIGNTY_POLICY_DOMAIN));
  sha3_256_write(&sha, policy->network_genesis, 32);
  zcl_write_u32_le(scalar, (uint32_t)policy->count);
  sha3_256_write(&sha, scalar, 4);
  zcl_write_u32_le(scalar, flags);
  sha3_256_write(&sha, scalar, 4);
  for (size_t i = 0; i < policy->count; i++)
    sha3_256_write(&sha, policy->entries[i].wire,
                   VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES);
  sha3_256_finalize(&sha, out);
}

void vcs_zcode_sovereignty_policy_digest(
    const struct vcs_zcode_sovereignty_policy *policy, uint8_t out[32])
{
  if (!out)
    return;
  memset(out, 0, 32);
  if (policy)
    policy_digest(policy, policy->advisory_enabled
                              ? SOVEREIGNTY_POLICY_FLAG_ADVISORY : 0, out);
}

enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_policy_save(
    const struct vcs_zcode_sovereignty_policy *policy, const char *datadir,
    char *error_out, size_t error_capacity)
{
  if (!policy)
    return policy_error(error_out, error_capacity,
                        VCS_ZCODE_SOVEREIGNTY_INVALID,
                        "sovereignty policy is missing");
  char directory[1400], path[1500];
  if (!policy_paths(datadir, directory, path, true, error_out,
                    error_capacity))
    return VCS_ZCODE_SOVEREIGNTY_IO;
  size_t bytes = SOVEREIGNTY_POLICY_HEADER_BYTES +
                 policy->count * VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES;
  uint8_t *wire = zcl_calloc(1, bytes, "sovereignty.policy.save");
  if (!wire)
    return policy_error(error_out, error_capacity, VCS_ZCODE_SOVEREIGNTY_IO,
                        "sovereignty save allocation failed");
  memcpy(wire, policy_magic, 8);
  zcl_write_u32_le(wire + 8, SOVEREIGNTY_POLICY_VERSION);
  zcl_write_u32_le(wire + 12, (uint32_t)policy->count);
  memcpy(wire + 16, policy->network_genesis, 32);
  uint32_t flags = policy->advisory_enabled
                       ? SOVEREIGNTY_POLICY_FLAG_ADVISORY
                       : 0;
  zcl_write_u32_le(wire + 48, flags);
  policy_digest(policy, flags, wire + 52);
  for (size_t i = 0; i < policy->count; i++)
    memcpy(wire + SOVEREIGNTY_POLICY_HEADER_BYTES +
               i * VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES,
           policy->entries[i].wire, VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES);
  char resolved[1500], parent[1400], temporary[1600];
  if (!platform_private_destination_resolve(
          path, resolved, sizeof(resolved), parent, sizeof(parent))) {
    free(wire);
    return policy_error(error_out, error_capacity, VCS_ZCODE_SOVEREIGNTY_IO,
                        "sovereignty destination is unsafe");
  }
  struct platform_private_file staged;
  platform_private_file_init(&staged);
  bool created = false;
  for (unsigned int attempt = 0; attempt < 64 && !created; attempt++) {
    uint64_t sequence = atomic_fetch_add_explicit(
        &g_policy_temp_sequence, 1, memory_order_relaxed);
    int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%llu.%llu",
                     resolved, (unsigned long long)os_proc_current_pid(),
                     (unsigned long long)sequence);
    if (n <= 0 || (size_t)n >= sizeof(temporary))
      break;
    created = platform_private_file_create(temporary, &staged);
    if (!created && errno != EEXIST)
      break;
  }
  bool ok = created &&
            platform_private_file_write_at(&staged, wire, bytes, 0) &&
            platform_private_file_truncate(&staged, bytes) &&
            platform_private_file_flush(&staged) &&
            platform_private_file_replace(&staged, temporary, resolved);
  free(wire);
  platform_private_file_close(&staged);
  if (!ok) {
    if (created)
      (void)platform_private_file_unlink_missing_ok(temporary);
    return policy_error(error_out, error_capacity, VCS_ZCODE_SOVEREIGNTY_IO,
                        "sovereignty temp write failed");
  }
  if (!platform_private_parent_flush(parent)) {
    return policy_error(error_out, error_capacity, VCS_ZCODE_SOVEREIGNTY_IO,
                        "sovereignty directory flush failed");
  }
  if (error_out && error_capacity)
    error_out[0] = '\0';
  return VCS_ZCODE_SOVEREIGNTY_OK;
}

static bool policy_snapshot_equal(
    const struct platform_positioned_file_snapshot *a,
    const struct platform_positioned_file_snapshot *b)
{
  return a->size == b->size && a->volume == b->volume &&
         a->file_low == b->file_low && a->file_high == b->file_high &&
         a->modified_seconds == b->modified_seconds &&
         a->modified_nanoseconds == b->modified_nanoseconds &&
         a->changed_seconds == b->changed_seconds &&
         a->changed_nanoseconds == b->changed_nanoseconds;
}

enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_policy_load(
    struct vcs_zcode_sovereignty_policy *policy, const char *datadir,
    char *error_out, size_t error_capacity)
{
  if (!policy)
    return policy_error(error_out, error_capacity,
                        VCS_ZCODE_SOVEREIGNTY_INVALID,
                        "sovereignty policy is missing");
  char directory[1400], path[1500];
  if (!policy_paths(datadir, directory, path, false, error_out,
                    error_capacity))
    return VCS_ZCODE_SOVEREIGNTY_IO;
  struct platform_file_metadata metadata;
  enum platform_file_metadata_result probe =
      platform_file_metadata_read(path, &metadata);
  if (probe == PLATFORM_FILE_METADATA_MISSING)
    return VCS_ZCODE_SOVEREIGNTY_OK;
  struct platform_positioned_file file;
  struct platform_positioned_file_snapshot before, after;
  platform_positioned_file_init(&file);
  size_t max_bytes = SOVEREIGNTY_POLICY_HEADER_BYTES +
                     VCS_ZCODE_SOVEREIGNTY_MAX_RULES *
                         VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES;
  if (probe != PLATFORM_FILE_METADATA_OK ||
      !platform_positioned_file_open(&file, path) ||
      !platform_positioned_file_snapshot(&file, &before) ||
      !platform_positioned_file_is_private(&file) ||
      before.size < SOVEREIGNTY_POLICY_HEADER_BYTES ||
      before.size > max_bytes) {
    platform_positioned_file_close(&file);
    return policy_error(error_out, error_capacity,
                        VCS_ZCODE_SOVEREIGNTY_CORRUPT,
                        "sovereignty policy size or mode is invalid");
  }
  size_t bytes = (size_t)before.size;
  uint8_t *wire = zcl_malloc(bytes, "sovereignty.policy.load");
  if (!wire) {
    platform_positioned_file_close(&file);
    return policy_error(error_out, error_capacity, VCS_ZCODE_SOVEREIGNTY_IO,
                        "sovereignty load allocation failed");
  }
  int64_t got = platform_positioned_file_read(&file, wire, bytes, 0);
  bool valid = got == (int64_t)bytes &&
               platform_positioned_file_snapshot(&file, &after) &&
               policy_snapshot_equal(&before, &after);
  platform_positioned_file_close(&file);
  uint32_t count = valid ? zcl_read_u32_le(wire + 12) : 0;
  uint32_t flags = valid ? zcl_read_u32_le(wire + 48) : 0;
  valid = valid && memcmp(wire, policy_magic, 8) == 0 &&
          zcl_read_u32_le(wire + 8) == SOVEREIGNTY_POLICY_VERSION &&
          memcmp(wire + 16, policy->network_genesis, 32) == 0 &&
          count <= VCS_ZCODE_SOVEREIGNTY_MAX_RULES &&
          (flags & ~SOVEREIGNTY_POLICY_FLAG_ADVISORY) == 0 &&
          bytes == SOVEREIGNTY_POLICY_HEADER_BYTES +
                       (size_t)count * VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES;
  struct vcs_zcode_sovereignty_policy *temporary = NULL;
  if (valid) {
    temporary = vcs_zcode_sovereignty_policy_create(policy->network_genesis);
    valid = temporary != NULL;
  }
  if (valid) {
    temporary->advisory_enabled =
        (flags & SOVEREIGNTY_POLICY_FLAG_ADVISORY) != 0;
    for (uint32_t i = 0; valid && i < count; i++) {
      const uint8_t *rule_wire =
          wire + SOVEREIGNTY_POLICY_HEADER_BYTES +
          (size_t)i * VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES;
      if (i && memcmp(rule_wire - VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES,
                      rule_wire, VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES) >= 0)
        valid = false;
      struct vcs_zcode_sovereignty_rule rule;
      if (valid && !rule_decode(rule_wire, &rule))
        valid = false;
      if (valid && vcs_zcode_sovereignty_policy_add(temporary, &rule) !=
                       VCS_ZCODE_SOVEREIGNTY_OK)
        valid = false;
    }
  }
  if (valid) {
    uint8_t digest[32];
    policy_digest(temporary, flags, digest);
    valid = memcmp(digest, wire + 52, 32) == 0;
  }
  free(wire);
  if (!valid) {
    vcs_zcode_sovereignty_policy_free(temporary);
    return policy_error(error_out, error_capacity,
                        VCS_ZCODE_SOVEREIGNTY_CORRUPT,
                        "sovereignty policy verification failed");
  }
  free(policy->entries);
  policy->entries = temporary->entries;
  policy->count = temporary->count;
  policy->advisory_enabled = temporary->advisory_enabled;
  temporary->entries = NULL;
  vcs_zcode_sovereignty_policy_free(temporary);
  if (error_out && error_capacity)
    error_out[0] = '\0';
  return VCS_ZCODE_SOVEREIGNTY_OK;
}
