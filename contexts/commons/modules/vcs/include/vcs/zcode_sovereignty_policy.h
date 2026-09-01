/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Generic local-sovereignty decisions for discovered objects. */

#ifndef ZCL_VCS_ZCODE_SOVEREIGNTY_POLICY_H
#define ZCL_VCS_ZCODE_SOVEREIGNTY_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE_BYTES 32u
#define VCS_ZCODE_SOVEREIGNTY_CLASSIFICATION_BYTES 32u
#define VCS_ZCODE_SOVEREIGNTY_MAX_RULES 1024u
#define VCS_ZCODE_SOVEREIGNTY_RULE_WIRE_BYTES 80u
#define VCS_ZCODE_SOVEREIGNTY_POLICY_FILE \
  "zcode/policy/sovereignty.v1"

enum vcs_zcode_sovereignty_action {
  VCS_ZCODE_SOVEREIGNTY_DISCOVER = 0,
  VCS_ZCODE_SOVEREIGNTY_FETCH,
  VCS_ZCODE_SOVEREIGNTY_STORE,
  VCS_ZCODE_SOVEREIGNTY_INDEX,
  VCS_ZCODE_SOVEREIGNTY_SERVE,
  VCS_ZCODE_SOVEREIGNTY_FORWARD,
  VCS_ZCODE_SOVEREIGNTY_EXECUTE,
  VCS_ZCODE_SOVEREIGNTY_ACTION_COUNT
};

/* All fields are public object metadata. `publisher_zid` is the signed master
 * identity, never a private key. Zero means that dimension is unknown. */
struct vcs_zcode_sovereignty_subject {
  uint8_t semantic_root[32];
  uint8_t transport_root[32];
  uint8_t package_root[32];
  uint8_t publisher_zid[32];
  char service_type[VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE_BYTES];
  char local_classification[VCS_ZCODE_SOVEREIGNTY_CLASSIFICATION_BYTES];
};

typedef bool (*vcs_zcode_sovereignty_decide_fn)(
    void *ctx, enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_sovereignty_subject *subject);

enum vcs_zcode_sovereignty_effect {
  VCS_ZCODE_SOVEREIGNTY_ALLOW = 1,
  VCS_ZCODE_SOVEREIGNTY_BLOCK = 2,
};

enum vcs_zcode_sovereignty_scope {
  VCS_ZCODE_SOVEREIGNTY_FULL_ROOT = 1,
  VCS_ZCODE_SOVEREIGNTY_PACKAGE = 2,
  VCS_ZCODE_SOVEREIGNTY_PUBLISHER_ZID = 3,
  VCS_ZCODE_SOVEREIGNTY_SERVICE_TYPE = 4,
  VCS_ZCODE_SOVEREIGNTY_CLASSIFICATION = 5,
};

enum vcs_zcode_sovereignty_source {
  VCS_ZCODE_SOVEREIGNTY_LOCAL = 1,
  VCS_ZCODE_SOVEREIGNTY_ADVISORY = 2,
};

struct vcs_zcode_sovereignty_rule {
  uint8_t id[32];
  enum vcs_zcode_sovereignty_source source;
  enum vcs_zcode_sovereignty_effect effect;
  enum vcs_zcode_sovereignty_scope scope;
  uint8_t action_mask;
  uint8_t value[32];
};

struct vcs_zcode_sovereignty_decision {
  bool allow;
  bool defaulted;
  bool advisory;
  uint8_t rule_id[32];
};

enum vcs_zcode_sovereignty_result {
  VCS_ZCODE_SOVEREIGNTY_OK = 0,
  VCS_ZCODE_SOVEREIGNTY_INVALID,
  VCS_ZCODE_SOVEREIGNTY_DUPLICATE,
  VCS_ZCODE_SOVEREIGNTY_NOT_FOUND,
  VCS_ZCODE_SOVEREIGNTY_CAP,
  VCS_ZCODE_SOVEREIGNTY_IO,
  VCS_ZCODE_SOVEREIGNTY_CORRUPT,
};

const char *vcs_zcode_sovereignty_action_string(
    enum vcs_zcode_sovereignty_action action);
const char *vcs_zcode_sovereignty_result_string(
    enum vcs_zcode_sovereignty_result result);

struct vcs_zcode_sovereignty_policy;

struct vcs_zcode_sovereignty_policy *vcs_zcode_sovereignty_policy_create(
    const uint8_t network_genesis[32]);
void vcs_zcode_sovereignty_policy_free(
    struct vcs_zcode_sovereignty_policy *policy);

/* Text scopes require canonical lower-case ASCII with a zero tail. Binary
 * scopes consume all 32 value bytes. id is derived canonically. */
enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_rule_build(
    struct vcs_zcode_sovereignty_rule *out,
    enum vcs_zcode_sovereignty_source source,
    enum vcs_zcode_sovereignty_effect effect,
    enum vcs_zcode_sovereignty_scope scope, uint8_t action_mask,
    const uint8_t value[32]);
enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_policy_add(
    struct vcs_zcode_sovereignty_policy *policy,
    const struct vcs_zcode_sovereignty_rule *rule);
enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_policy_remove(
    struct vcs_zcode_sovereignty_policy *policy, const uint8_t rule_id[32]);
void vcs_zcode_sovereignty_policy_set_advisory(
    struct vcs_zcode_sovereignty_policy *policy, bool enabled);
bool vcs_zcode_sovereignty_policy_advisory(
    const struct vcs_zcode_sovereignty_policy *policy);
size_t vcs_zcode_sovereignty_policy_count(
    const struct vcs_zcode_sovereignty_policy *policy);
size_t vcs_zcode_sovereignty_policy_rules(
    const struct vcs_zcode_sovereignty_policy *policy,
    struct vcs_zcode_sovereignty_rule *out, size_t capacity);
void vcs_zcode_sovereignty_policy_digest(
    const struct vcs_zcode_sovereignty_policy *policy, uint8_t out[32]);

struct vcs_zcode_sovereignty_decision vcs_zcode_sovereignty_policy_check(
    const struct vcs_zcode_sovereignty_policy *policy,
    enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_sovereignty_subject *subject);
bool vcs_zcode_sovereignty_policy_decide_callback(
    void *ctx, enum vcs_zcode_sovereignty_action action,
    const struct vcs_zcode_sovereignty_subject *subject);

enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_policy_save(
    const struct vcs_zcode_sovereignty_policy *policy, const char *datadir,
    char *error_out, size_t error_capacity);
enum vcs_zcode_sovereignty_result vcs_zcode_sovereignty_policy_load(
    struct vcs_zcode_sovereignty_policy *policy, const char *datadir,
    char *error_out, size_t error_capacity);

#endif /* ZCL_VCS_ZCODE_SOVEREIGNTY_POLICY_H */
