/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Transport-neutral status/blocker composition helpers.
 *
 * This is the shared helper web the operator read compositions build on:
 * defaulted JSON accessors, RPC/dumpstate envelope folding, the peer
 * survey, and the target-node blocker-summary builder. Native status command
 * bodies share these helpers instead of re-deriving the same projections.
 *
 * Generic helper names carry a zcl_ prefix to avoid whole-program link
 * collisions.
 */

#ifndef ZCL_CONTROLLERS_STATUS_NATIVE_HELPERS_H
#define ZCL_CONTROLLERS_STATUS_NATIVE_HELPERS_H

#include "json/json.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Peer survey ────────────────────────────────────────────────
 *
 * One fold over the getpeerinfo JSON array, shared by all three
 * callers that used to each re-derive their own subset of these
 * counts with slightly different idioms. Each caller reads only the fields
 * it needs. */
struct peer_survey {
    int total;
    int inbound;
    int outbound;
    int ready;      /* handshaked operational states, including sync/snapshot */
    int zcl23;
    int magicbean;
    int max_height; /* max "startingheight" across all peers */
    bool max_height_known;
    bool direction_known;
    bool ready_known;
};

void status_push_json_error(struct json_value *obj, const char *key,
                            const char *message,
                            const struct json_value *error_obj);
void status_push_rpc_json(struct json_value *obj, const char *key,
                          const char *raw, const char *rpc_name);
void status_push_dumpstate_json(struct json_value *obj, const char *key,
                                const char *expected_subsystem,
                                const char *raw);
bool status_parse_json(struct json_value *out, const char *raw);
bool status_json_is_rpc_error(const struct json_value *value);
bool status_parse_rpc_json(struct json_value *out, const char *raw,
                           enum json_type expected_type);
bool status_read_height(const struct json_value *obj, const char *key,
                        int64_t *out);
bool status_read_bool(const struct json_value *obj, const char *key,
                      bool *out);
bool status_read_nonnegative_int(const struct json_value *obj,
                                 const char *key, int64_t *out);
void status_push_int_if_known(struct json_value *obj, const char *key,
                              bool known, int64_t value);
void status_push_bool_if_known(struct json_value *obj, const char *key,
                               bool known, bool value);
void status_push_rpc_parse_error(struct json_value *obj, const char *key,
                                 const char *raw, const char *message);
long long status_json_int(const struct json_value *obj, const char *key,
                          long long dflt);
const char *status_json_str(const struct json_value *obj, const char *key,
                            const char *dflt);
bool status_json_bool(const struct json_value *obj, const char *key,
                      bool dflt);
bool status_peer_subver_has(const struct json_value *peer, const char *token);
bool status_peer_is_zcl23(const struct json_value *peer);
bool status_peer_is_magicbean(const struct json_value *peer);
bool status_peer_array_is_valid(const struct json_value *peers);
void status_peer_survey(const struct json_value *peers,
                        struct peer_survey *out);
bool status_json_equal(const struct json_value *a, const struct json_value *b);
bool status_push_kv_verified(struct json_value *obj, const char *key,
                             const struct json_value *value);
bool status_push_str_verified(struct json_value *obj, const char *key,
                              const char *value);
const struct json_value *status_dominant_blocker(
    const struct json_value *blockers);
bool status_blocker_counts_match(const struct json_value *state,
                                 const struct json_value *entries);
bool status_build_blocker_summary(const char *raw, bool include_entries,
                                  struct json_value *summary_out,
                                  struct json_value *dominant_out,
                                  struct json_value *error_out);
bool status_push_built_blocker_summary(struct json_value *root,
                                       const struct json_value *summary,
                                       const struct json_value *dominant,
                                       const struct json_value *error,
                                       bool ok);
bool status_push_blocker_summary(struct json_value *root, const char *raw);

/* Serialize v to a malloc'd NUL-terminated JSON body (caller frees).
 * Renamed from json_value_to_body to avoid a whole-program symbol clash. */
char *zcl_json_value_to_body(struct json_value *v, const char *label);

/* Fill buf with the default postmortem-capsule directory. Returns 0 on
 * success, -ENOSPC when the path would not fit. Renamed from
 * postmortem_default_dir to avoid a whole-program symbol clash. */
int zcl_postmortem_default_dir(char *buf, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* ZCL_CONTROLLERS_STATUS_NATIVE_HELPERS_H */
