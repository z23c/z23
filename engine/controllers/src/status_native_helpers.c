/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Transport-neutral status/blocker composition helpers.
 *
 * Shared defaulted JSON accessors, RPC/dumpstate envelope folding, peer
 * survey, and target-node blocker-summary builder for native status bodies. */

#include "controllers/status_native_helpers.h"

#include "json/json.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void status_push_json_error(struct json_value *obj,
                                   const char *key,
                                   const char *message,
                                   const struct json_value *error_obj)
{
    char err_key[96];
    snprintf(err_key, sizeof(err_key), "%s_error", key ? key : "rpc");
    if (error_obj && error_obj->type == JSON_OBJ) {
        json_push_kv(obj, err_key, error_obj);
        return;
    }

    struct json_value err;
    json_init(&err);
    json_set_object(&err);
    json_push_kv_str(&err, "message", message ? message : "unknown error");
    json_push_kv(obj, err_key, &err);
    json_free(&err);
}

bool status_json_is_rpc_error(const struct json_value *value);

void status_push_rpc_json(struct json_value *obj, const char *key,
                                 const char *raw, const char *rpc_name)
{
    struct json_value child;
    json_init(&child);
    if (raw && json_read(&child, raw, strlen(raw))) {
        if (status_json_is_rpc_error(&child)) {
            const struct json_value *wrapped = json_get(&child, "error");
            struct json_value nullv;
            json_init(&nullv);
            json_set_null(&nullv);
            json_push_kv(obj, key, &nullv);
            status_push_json_error(obj, key, NULL,
                                   wrapped && wrapped->type == JSON_OBJ
                                       ? wrapped : &child);
            json_free(&nullv);
            json_free(&child);
            return;
        }
        json_push_kv(obj, key, &child);
        json_free(&child);
        return;
    }

    json_set_null(&child);
    json_push_kv(obj, key, &child);
    json_free(&child);

    char msg[128];
    snprintf(msg, sizeof(msg), "%s RPC returned %s",
             rpc_name ? rpc_name : key,
             raw ? "invalid JSON" : "null");
    status_push_json_error(obj, key, msg, NULL);
}

void status_push_dumpstate_json(struct json_value *obj,
                                       const char *key,
                                       const char *expected_subsystem,
                                       const char *raw)
{
    struct json_value child;
    json_init(&child);
    if (!raw || !json_read(&child, raw, strlen(raw))) {
        struct json_value nullv;
        json_init(&nullv);
        json_set_null(&nullv);
        json_push_kv(obj, key, &nullv);
        status_push_json_error(obj, key,
                               raw ? "invalid dumpstate JSON"
                                   : "dumpstate RPC returned null",
                               NULL);
        json_free(&nullv);
        json_free(&child);
        return;
    }

    const struct json_value *error = json_get(&child, "error");
    if (status_json_is_rpc_error(&child)) {
        struct json_value nullv;
        json_init(&nullv);
        json_set_null(&nullv);
        json_push_kv(obj, key, &nullv);
        status_push_json_error(obj, key, NULL,
                               error && error->type == JSON_OBJ
                                   ? error : &child);
        json_free(&nullv);
        json_free(&child);
        return;
    }

    const char *subsystem =
        json_get_str(json_get(&child, "subsystem"));
    const struct json_value *captured_at = json_get(&child, "captured_at");
    const struct json_value *state = json_get(&child, "state");
    if (!expected_subsystem || !subsystem ||
        strcmp(subsystem, expected_subsystem) != 0 ||
        !captured_at || captured_at->type != JSON_INT ||
        captured_at->val.i < 0 || !state || state->type != JSON_OBJ) {
        struct json_value nullv;
        json_init(&nullv);
        json_set_null(&nullv);
        json_push_kv(obj, key, &nullv);
        status_push_json_error(obj, key,
                               "dumpstate returned an invalid subsystem envelope",
                               NULL);
        json_free(&nullv);
        json_free(&child);
        return;
    }

    json_push_kv(obj, key, state);
    json_free(&child);
}

bool status_parse_json(struct json_value *out, const char *raw)
{
    json_init(out);
    return raw && json_read(out, raw, strlen(raw));
}

bool status_json_is_rpc_error(const struct json_value *value)
{
    if (!value || value->type != JSON_OBJ)
        return false;
    const struct json_value *wrapped = json_get(value, "error");
    if (wrapped && wrapped->type != JSON_NULL)
        return true;
    const struct json_value *code = json_get(value, "code");
    const struct json_value *message = json_get(value, "message");
    return code && code->type == JSON_INT &&
           message && message->type == JSON_STR;
}

bool status_parse_rpc_json(struct json_value *out, const char *raw,
                                  enum json_type expected_type)
{
    return status_parse_json(out, raw) && out->type == expected_type &&
           !status_json_is_rpc_error(out);
}

bool status_read_height(const struct json_value *obj,
                               const char *key, int64_t *out)
{
    const struct json_value *value = obj ? json_get(obj, key) : NULL;
    if (!value || value->type != JSON_INT || value->val.i < 0 ||
        value->val.i > INT_MAX)
        return false;
    if (out)
        *out = value->val.i;
    return true;
}

bool status_read_bool(const struct json_value *obj,
                             const char *key, bool *out)
{
    const struct json_value *value = obj ? json_get(obj, key) : NULL;
    if (!value || value->type != JSON_BOOL)
        return false;
    if (out)
        *out = value->val.b;
    return true;
}

bool status_read_nonnegative_int(const struct json_value *obj,
                                        const char *key, int64_t *out)
{
    const struct json_value *value = obj ? json_get(obj, key) : NULL;
    if (!value || value->type != JSON_INT || value->val.i < 0)
        return false;
    if (out)
        *out = value->val.i;
    return true;
}

void status_push_int_if_known(struct json_value *obj, const char *key,
                                     bool known, int64_t value)
{
    if (known) {
        json_push_kv_int(obj, key, value);
        return;
    }
    struct json_value unknown;
    json_init(&unknown);
    json_set_null(&unknown);
    json_push_kv(obj, key, &unknown);
    json_free(&unknown);
}

void status_push_bool_if_known(struct json_value *obj, const char *key,
                                      bool known, bool value)
{
    if (known) {
        json_push_kv_bool(obj, key, value);
        return;
    }
    struct json_value unknown;
    json_init(&unknown);
    json_set_null(&unknown);
    json_push_kv(obj, key, &unknown);
    json_free(&unknown);
}

void status_push_rpc_parse_error(struct json_value *obj,
                                        const char *key,
                                        const char *raw,
                                        const char *message)
{
    struct json_value parsed;
    json_init(&parsed);
    if (raw && json_read(&parsed, raw, strlen(raw)) &&
        parsed.type == JSON_OBJ) {
        const struct json_value *wrapped = json_get(&parsed, "error");
        if (wrapped && wrapped->type == JSON_OBJ)
            status_push_json_error(obj, key, NULL, wrapped);
        else if (json_get(&parsed, "code") || json_get(&parsed, "message"))
            status_push_json_error(obj, key, NULL, &parsed);
        else
            status_push_json_error(obj, key, message, NULL);
    } else {
        status_push_json_error(obj, key, message, NULL);
    }
    json_free(&parsed);
}

long long status_json_int(const struct json_value *obj,
                                 const char *key,
                                 long long dflt)
{
    const struct json_value *v = json_get(obj, key);
    return v ? json_get_int(v) : dflt;
}

const char *status_json_str(const struct json_value *obj,
                                   const char *key,
                                   const char *dflt)
{
    const struct json_value *v = json_get(obj, key);
    const char *s = json_get_str(v);
    return s && s[0] ? s : dflt;
}

bool status_json_bool(const struct json_value *obj,
                             const char *key,
                             bool dflt)
{
    const struct json_value *v = json_get(obj, key);
    return v ? json_get_bool(v) : dflt;
}

bool status_peer_subver_has(const struct json_value *peer,
                                   const char *token)
{
    const char *subver = status_json_str(peer, "subver", "");
    return token && strstr(subver, token) != NULL;
}

bool status_peer_is_zcl23(const struct json_value *peer)
{
    return status_json_bool(peer, "zclassic23", false) ||
           status_json_bool(peer, "zclassic_c23", false) ||
           status_peer_subver_has(peer, "ZClassic23") ||
           status_peer_subver_has(peer, "ZClassic-C23");
}

bool status_peer_is_magicbean(const struct json_value *peer)
{
    return status_json_bool(peer, "magicbean", false) ||
           status_peer_subver_has(peer, "MagicBean");
}

bool status_peer_array_is_valid(const struct json_value *peers)
{
    if (!peers || peers->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < json_size(peers); i++) {
        const struct json_value *peer = json_at(peers, i);
        if (!peer || peer->type != JSON_OBJ)
            return false;
    }
    return true;
}

void status_peer_survey(const struct json_value *peers,
                               struct peer_survey *out)
{
    struct peer_survey s = {
        .direction_known = true,
        .ready_known = true,
    };

    if (peers && peers->type == JSON_ARR) {
        s.total = (int)json_size(peers);
        for (size_t i = 0; i < json_size(peers); i++) {
            const struct json_value *peer = json_at(peers, i);
            if (!peer || peer->type != JSON_OBJ)
                continue;
            const struct json_value *inbound = json_get(peer, "inbound");
            if (inbound && inbound->type == JSON_BOOL) {
                if (inbound->val.b)
                    s.inbound++;
                else
                    s.outbound++;
            } else {
                s.direction_known = false;
            }
            if (status_peer_is_zcl23(peer))
                s.zcl23++;
            else if (status_peer_is_magicbean(peer))
                s.magicbean++;
            const struct json_value *state_value = json_get(peer, "state");
            if (state_value && state_value->type == JSON_STR) {
                const char *state = json_get_str(state_value);
                if (strcmp(state, "handshake_complete") == 0 ||
                    strcmp(state, "active") == 0 ||
                    strcmp(state, "syncing_headers") == 0 ||
                    strcmp(state, "syncing_blocks") == 0 ||
                    strcmp(state, "snapshot_serving") == 0 ||
                    strcmp(state, "snapshot_receiving") == 0)
                    s.ready++;
            } else {
                s.ready_known = false;
            }
            int64_t h = 0;
            if (status_read_height(peer, "startingheight", &h)) {
                if (!s.max_height_known || h > s.max_height)
                    s.max_height = (int)h;
                s.max_height_known = true;
            }
        }
    }

    if (out) *out = s;
}

static int status_blocker_causal_priority(const struct json_value *candidate)
{
    const char *class_name = json_get_str(json_get(candidate, "class"));
    enum blocker_class blocker_class;
    if (class_name && strcmp(class_name, "resource") == 0)
        blocker_class = BLOCKER_RESOURCE;
    else if (class_name && strcmp(class_name, "permanent") == 0)
        blocker_class = BLOCKER_PERMANENT;
    else if (class_name && strcmp(class_name, "dependency") == 0)
        blocker_class = BLOCKER_DEPENDENCY;
    else if (class_name && strcmp(class_name, "transient") == 0)
        blocker_class = BLOCKER_TRANSIENT;
    else
        return 0;
    return blocker_causal_priority(
        blocker_class, json_get_str(json_get(candidate, "id")));
}

bool status_json_equal(const struct json_value *a,
                              const struct json_value *b)
{
    if (!a || !b || a->type != b->type ||
        a->num_children != b->num_children)
        return false;
    switch (a->type) {
    case JSON_NULL:
        break;
    case JSON_BOOL:
        if (a->val.b != b->val.b) return false;
        break;
    case JSON_INT:
        if (a->val.i != b->val.i) return false;
        break;
    case JSON_REAL:
        if (a->val.d != b->val.d) return false;
        break;
    case JSON_STR:
        if (!a->val.s || !b->val.s || strcmp(a->val.s, b->val.s) != 0)
            return false;
        break;
    case JSON_ARR:
    case JSON_OBJ:
        break;
    }
    for (size_t i = 0; i < a->num_children; i++) {
        if ((a->keys[i] == NULL) != (b->keys[i] == NULL))
            return false;
        if (a->keys[i] && strcmp(a->keys[i], b->keys[i]) != 0)
            return false;
        if (!status_json_equal(&a->children[i], &b->children[i]))
            return false; /* raw-return-ok:recursive-equality-predicate */
    }
    return true;
}

bool status_push_kv_verified(struct json_value *obj, const char *key,
                                    const struct json_value *value)
{
    size_t before = obj ? obj->num_children : 0;
    if (!obj || !key || !value || !json_push_kv(obj, key, value) ||
        obj->num_children != before + 1)
        return false;
    size_t added = obj->num_children - 1;
    return obj->keys[added] && strcmp(obj->keys[added], key) == 0 &&
           status_json_equal(&obj->children[added], value);
}

bool status_push_str_verified(struct json_value *obj, const char *key,
                                     const char *value)
{
    struct json_value child;
    json_init(&child);
    json_set_str(&child, value ? value : "");
    bool ok = child.type == JSON_STR &&
              status_push_kv_verified(obj, key, &child);
    json_free(&child);
    return ok;
}

const struct json_value *status_dominant_blocker(
    const struct json_value *blockers)
{
    const struct json_value *dominant = NULL;
    int dominant_prio = -1;
    for (size_t i = 0; blockers && i < json_size(blockers); i++) {
        const struct json_value *candidate = json_at(blockers, i);
        if (!candidate || candidate->type != JSON_OBJ)
            continue;
        int prio = status_blocker_causal_priority(candidate);
        if (!dominant || prio > dominant_prio ||
            (prio == dominant_prio &&
             json_get_int(json_get(candidate, "age_us")) >
             json_get_int(json_get(dominant, "age_us")))) {
            dominant = candidate;
            dominant_prio = prio;
        }
    }
    return dominant;
}

bool status_blocker_counts_match(const struct json_value *state,
                                        const struct json_value *entries)
{
    static const char *const count_keys[] = {
        "permanent_count", "transient_count",
        "dependency_count", "resource_count",
    };
    static const char *const class_names[] = {
        "permanent", "transient", "dependency", "resource",
    };
    int64_t derived[4] = {0, 0, 0, 0};

    const struct json_value *active = json_get(state, "active_count");
    const struct json_value *escaped =
        json_get(state, "escape_dispatched_total");
    if (!active || active->type != JSON_INT ||
        active->val.i != (int64_t)json_size(entries) ||
        !escaped || escaped->type != JSON_INT || escaped->val.i < 0)
        return false;

    for (size_t i = 0; i < json_size(entries); i++) {
        const struct json_value *entry = json_at(entries, i);
        const char *class_name =
            json_get_str(json_get(entry, "class"));
        if (!entry || entry->type != JSON_OBJ || !class_name)
            return false;
        bool known = false;
        for (size_t c = 0; c < 4; c++) {
            if (strcmp(class_name, class_names[c]) == 0) {
                derived[c]++;
                known = true;
                break;
            }
        }
        if (!known)
            return false;
    }

    for (size_t c = 0; c < 4; c++) {
        const struct json_value *reported = json_get(state, count_keys[c]);
        if (!reported || reported->type != JSON_INT ||
            reported->val.i != derived[c])
            return false;
    }
    return true;
}

/* Build the blocker summary exclusively from the target node's dumpstate RPC
 * response. The native command often runs in a separate client process;
 * reading blocker globals there would describe that empty client and create a
 * dangerous false-green status while the actual node is blocked. */
bool status_build_blocker_summary(const char *raw,
                                         bool include_entries,
                                         struct json_value *summary_out,
                                         struct json_value *dominant_out,
                                         struct json_value *error_out)
{
    json_set_null(summary_out);
    json_set_null(dominant_out);
    json_set_null(error_out);

    struct json_value response;
    json_init(&response);
    if (!raw || !json_read(&response, raw, strlen(raw))) {
        json_set_object(error_out);
        json_push_kv_str(error_out, "message",
                         raw ? "invalid blocker dumpstate JSON"
                             : "blocker dumpstate RPC returned null");
        json_free(&response);
        return false;
    }

    const struct json_value *rpc_error = json_get(&response, "error");
    if (rpc_error && rpc_error->type != JSON_NULL) {
        if (rpc_error->type == JSON_OBJ) {
            json_copy(error_out, rpc_error);
        } else {
            json_set_object(error_out);
            json_push_kv_str(error_out, "message",
                             "blocker dumpstate returned an error indicator");
        }
        json_free(&response);
        return false;
    }

    const struct json_value *state = json_get(&response, "state");
    if (json_get(&response, "code") || json_get(&response, "message")) {
        /* HTTP/in-process RPC failures are normally a bare
         * {code,message,method} object; transport stubs may wrap it under
         * "error". Reject mixed error+state objects too: error evidence
         * cannot be made successful by appending plausible state. */
        json_copy(error_out, &response);
        json_free(&response);
        return false;
    }
    const char *subsystem =
        json_get_str(json_get(&response, "subsystem"));
    const struct json_value *captured_at =
        json_get(&response, "captured_at");
    if (!state || state->type != JSON_OBJ ||
        !subsystem || strcmp(subsystem, "blocker") != 0 ||
        !captured_at || captured_at->type != JSON_INT ||
        captured_at->val.i < 0) {
        json_set_object(error_out);
        json_push_kv_str(error_out, "message",
                         "blocker dumpstate missing valid blocker envelope");
        json_free(&response);
        return false;
    }
    const struct json_value *entries = json_get(state, "blockers");
    if (!entries || entries->type != JSON_ARR) {
        json_set_object(error_out);
        json_push_kv_str(error_out, "message",
                         "blocker dumpstate missing object state/blockers array");
        json_free(&response);
        return false;
    }
    if (!status_blocker_counts_match(state, entries)) {
        json_set_object(error_out);
        json_push_kv_str(error_out, "message",
                         "blocker dumpstate counts contradict blocker entries");
        json_free(&response);
        return false;
    }

    json_set_object(summary_out);
    bool copy_ok = true;
    for (size_t i = 0; i < state->num_children; i++) {
        const char *key = state->keys[i];
        if (!key || strcmp(key, "dominant") == 0 ||
            strcmp(key, "execution_locus") == 0 ||
            strcmp(key, "source_rpc") == 0 ||
            strcmp(key, "captured_at") == 0 ||
            (!include_entries &&
             (strcmp(key, "blockers") == 0 ||
              strcmp(key, "_health") == 0)))
            continue;
        if (!status_push_kv_verified(summary_out, key,
                                     &state->children[i])) {
            copy_ok = false;
            break;
        }
    }
    copy_ok = copy_ok && status_push_str_verified(
        summary_out, "execution_locus", "target_node");
    copy_ok = copy_ok && status_push_str_verified(
        summary_out, "source_rpc", "dumpstate:blocker");
    copy_ok = copy_ok && status_push_kv_verified(
        summary_out, "captured_at", captured_at);

    const struct json_value *selected = status_dominant_blocker(entries);
    if (selected) {
        json_copy(dominant_out, selected);
        copy_ok = copy_ok && status_json_equal(dominant_out, selected);
    }
    copy_ok = copy_ok && status_push_kv_verified(
        summary_out, "dominant", dominant_out);
    if (!copy_ok) {
        json_set_null(summary_out);
        json_set_null(dominant_out);
        json_set_object(error_out);
        json_push_kv_str(error_out, "message",
                         "blocker summary allocation/copy failed");
        json_free(&response);
        return false;
    }
    json_free(&response);
    return true;
}

bool status_push_built_blocker_summary(
    struct json_value *root,
    const struct json_value *summary,
    const struct json_value *dominant,
    const struct json_value *error,
    bool ok)
{
    bool attached = status_push_kv_verified(root, "blockers", summary) &&
                    status_push_kv_verified(root, "dominant_blocker",
                                            dominant);
    if (!ok) {
        struct json_value fallback;
        json_init(&fallback);
        const struct json_value *error_value = error;
        if (!error || error->type != JSON_OBJ) {
            json_set_object(&fallback);
            json_push_kv_str(&fallback, "message",
                             "target blocker state unavailable");
            error_value = &fallback;
        }
        attached = attached && status_push_kv_verified(
            root, "blockers_error", error_value);
        json_free(&fallback);
    }
    return attached;
}

bool status_push_blocker_summary(struct json_value *root,
                                        const char *raw)
{
    struct json_value summary;
    struct json_value dominant;
    struct json_value error;
    json_init(&summary);
    json_init(&dominant);
    json_init(&error);

    bool ok = status_build_blocker_summary(raw, false, &summary, &dominant,
                                           &error);
    bool attached = status_push_built_blocker_summary(
        root, &summary, &dominant, &error, ok);

    json_free(&error);
    json_free(&dominant);
    json_free(&summary);
    return attached;
}

int zcl_postmortem_default_dir(char *buf, size_t cap)
{
    const char *home = getenv("HOME");
    int n;
    if (home && *home) {
        n = snprintf(buf, cap, "%s/.zclassic-c23/postmortems", home);
    } else {
        n = snprintf(buf, cap, "./.zclassic-c23/postmortems");
    }
    if (n < 0 || (size_t)n >= cap) return -ENOSPC;
    return 0;
}

char *zcl_json_value_to_body(struct json_value *v, const char *label)
{
    size_t need = json_write(v, NULL, 0);
    char *out = zcl_malloc(need + 1, label);
    if (!out) return NULL;
    json_write(v, out, need + 1);
    return out;
}
