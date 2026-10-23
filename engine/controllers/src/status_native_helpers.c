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

/* Index of `value` in `names[0..count)`, or `count` when no name matches. */
static size_t status_string_index(const char *const *names, size_t count,
                                  const char *value)
{
    size_t i = 0;
    for (; i < count; i++) {
        if (strcmp(value, names[i]) == 0)
            break;
    }
    return i;
}

/* True for peer sync states that count as ready in the survey. */
static bool status_peer_state_is_ready(const char *state)
{
    static const char *const ready_states[] = {
        "handshake_complete", "active", "syncing_headers",
        "syncing_blocks", "snapshot_serving", "snapshot_receiving",
    };
    return status_string_index(ready_states, 6, state) < 6;
}

/* Fold one object peer into the survey. */
static void status_peer_survey_add(struct peer_survey *s,
                                   const struct json_value *peer)
{
    const struct json_value *inbound = json_get(peer, "inbound");
    if (inbound && inbound->type == JSON_BOOL) {
        if (inbound->val.b)
            s->inbound++;
        else
            s->outbound++;
    } else {
        s->direction_known = false;
    }
    if (status_peer_is_zcl23(peer))
        s->zcl23++;
    else if (status_peer_is_magicbean(peer))
        s->magicbean++;
    const struct json_value *state_value = json_get(peer, "state");
    if (state_value && state_value->type == JSON_STR) {
        if (status_peer_state_is_ready(json_get_str(state_value)))
            s->ready++;
    } else {
        s->ready_known = false;
    }
    int64_t h = 0;
    if (status_read_height(peer, "startingheight", &h)) {
        if (!s->max_height_known || h > s->max_height)
            s->max_height = (int)h;
        s->max_height_known = true;
    }
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
            status_peer_survey_add(&s, peer);
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

/* Compare the scalar payload of two values of the same type. Arrays and
 * objects have no payload of their own; their children are compared by the
 * caller. */
static bool status_json_scalar_equal(const struct json_value *a,
                                     const struct json_value *b)
{
    switch (a->type) {
    case JSON_NULL:
        break;
    case JSON_BOOL:
        return a->val.b == b->val.b;
    case JSON_INT:
        return a->val.i == b->val.i;
    case JSON_REAL:
        return a->val.d == b->val.d;
    case JSON_STR:
        return a->val.s && b->val.s && strcmp(a->val.s, b->val.s) == 0;
    case JSON_ARR:
    case JSON_OBJ:
        break;
    }
    return true;
}

/* Two member keys match when both are absent or both name the same key. */
static bool status_json_key_equal(const char *a, const char *b)
{
    if ((a == NULL) != (b == NULL))
        return false;
    return !a || strcmp(a, b) == 0;
}

bool status_json_equal(const struct json_value *a,
                              const struct json_value *b)
{
    if (!a || !b || a->type != b->type ||
        a->num_children != b->num_children)
        return false;
    if (!status_json_scalar_equal(a, b))
        return false; /* raw-return-ok:pure-equality-predicate */
    for (size_t i = 0; i < a->num_children; i++) {
        if (!status_json_key_equal(a->keys[i], b->keys[i]))
            return false; /* raw-return-ok:pure-equality-predicate */
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

/* The active and escaped totals agree with the entry count and are sane. */
static bool status_blocker_totals_ok(const struct json_value *state,
                                     const struct json_value *entries)
{
    const struct json_value *active = json_get(state, "active_count");
    const struct json_value *escaped =
        json_get(state, "escape_dispatched_total");
    return active && active->type == JSON_INT &&
           active->val.i == (int64_t)json_size(entries) &&
           escaped && escaped->type == JSON_INT && escaped->val.i >= 0;
}

/* Tally each entry into its blocker class; false on an unknown class. */
static bool status_blocker_class_tally(const struct json_value *entries,
                                       int64_t derived[4])
{
    static const char *const class_names[] = {
        "permanent", "transient", "dependency", "resource",
    };
    for (size_t i = 0; i < json_size(entries); i++) {
        const struct json_value *entry = json_at(entries, i);
        const char *class_name =
            json_get_str(json_get(entry, "class"));
        if (!entry || entry->type != JSON_OBJ || !class_name)
            return false;
        size_t c = status_string_index(class_names, 4, class_name);
        if (c == 4)
            return false;
        derived[c]++;
    }
    return true;
}

bool status_blocker_counts_match(const struct json_value *state,
                                        const struct json_value *entries)
{
    static const char *const count_keys[] = {
        "permanent_count", "transient_count",
        "dependency_count", "resource_count",
    };
    int64_t derived[4] = {0, 0, 0, 0};

    if (!status_blocker_totals_ok(state, entries))
        return false; /* raw-return-ok:pure-count-predicate */
    if (!status_blocker_class_tally(entries, derived))
        return false; /* raw-return-ok:pure-count-predicate */

    for (size_t c = 0; c < 4; c++) {
        const struct json_value *reported = json_get(state, count_keys[c]);
        if (!reported || reported->type != JSON_INT ||
            reported->val.i != derived[c])
            return false;
    }
    return true;
}

enum {
    STATUS_BLOCKER_REASON_WIDTH = 80,
    STATUS_BLOCKER_LIST_BYTES = 2304,
};

/* True when row `a` precedes row `b`: higher causal priority first, then the
 * older blocker. */
static bool status_blocker_row_before(const struct json_value *a,
                                      const struct json_value *b)
{
    int pa = status_blocker_causal_priority(a);
    int pb = status_blocker_causal_priority(b);
    return pa != pb ? pa > pb
                    : json_get_int(json_get(a, "age_us")) >
                      json_get_int(json_get(b, "age_us"));
}

/* Build one compact row in `out`: id, owner, class, age_us and the reason cut
 * to STATUS_BLOCKER_REASON_WIDTH bytes (on a character boundary) plus "...". */
static bool status_compact_blocker_row(struct json_value *out,
                                       const struct json_value *row)
{
    static const char *const names[] = {"id", "owner", "class"};
    json_init(out);
    json_set_object(out);
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(names) / sizeof(names[0]); i++) {
        const char *s = json_get_str(json_get(row, names[i]));
        ok = json_push_kv_str(out, names[i], s ? s : "");
    }
    ok = ok && json_push_kv_int(out, "age_us",
                                json_get_int(json_get(row, "age_us")));
    const char *reason = json_get_str(json_get(row, "reason"));
    size_t len = reason ? strlen(reason) : 0;
    size_t keep = len;
    if (len > STATUS_BLOCKER_REASON_WIDTH) {
        keep = STATUS_BLOCKER_REASON_WIDTH;
        while (keep > 0 && ((unsigned char)reason[keep] & 0xC0u) == 0x80u)
            keep--;
    }
    char text[STATUS_BLOCKER_REASON_WIDTH + 4];
    if (keep > 0)
        memcpy(text, reason, keep);
    if (keep < len) {
        memcpy(text + keep, "...", 3);
        keep += 3;
    }
    text[keep] = '\0';
    return ok && json_push_kv_str(out, "reason", text);
}

/* Push "blockers": the active blockers, dominant and permanent first, as
 * compact rows bounded by STATUS_BLOCKER_LIST_BYTES; "blockers_omitted"
 * counts rows that did not fit. Full rows stay behind item_offset/item_limit. */
static bool status_push_compact_blockers(struct json_value *summary,
                                         const struct json_value *entries)
{
    size_t n = json_size(entries);
    size_t order[BLOCKER_CAP];
    if (n > BLOCKER_CAP)
        return false;
    for (size_t i = 0; i < n; i++) {
        size_t j = i;
        for (; j > 0 && status_blocker_row_before(
                            json_at(entries, i), json_at(entries, order[j - 1]));
             j--)
            order[j] = order[j - 1];
        order[j] = i;
    }
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    size_t shown = 0, used = 2;
    bool ok = true;
    for (; ok && shown < n; shown++) {
        struct json_value row;
        ok = status_compact_blocker_row(&row, json_at(entries, order[shown]));
        size_t bytes = json_write(&row, NULL, 0) + 1;
        bool fits = ok && used + bytes <= STATUS_BLOCKER_LIST_BYTES;
        ok = ok && (!fits || json_push_back(&list, &row));
        json_free(&row);
        if (!fits)
            break;
        used += bytes;
    }
    ok = ok && json_push_kv(summary, "blockers", &list) &&
         (shown == n || json_push_kv_int(summary, "blockers_omitted",
                                         (int64_t)(n - shown)));
    json_free(&list);
    return ok;
}

/* True for dumpstate keys the summary rebuilds or must not carry over. */
static bool status_summary_skips_key(const char *key, bool include_entries)
{
    static const char *const rebuilt[] = {
        "dominant", "execution_locus", "source_rpc", "captured_at", "blockers",
    };
    for (size_t i = 0; key && i < sizeof(rebuilt) / sizeof(rebuilt[0]); i++)
        if (strcmp(key, rebuilt[i]) == 0)
            return true;
    return !key || (!include_entries && strcmp(key, "_health") == 0);
}

/* The reason the dumpstate blockers value cannot be summarized, or NULL. */
static const char *status_entries_defect(const struct json_value *entries)
{
    if (!entries || entries->type != JSON_ARR)
        return "blocker dumpstate missing object state/blockers array";
    if (json_size(entries) > BLOCKER_CAP)
        return "blocker dumpstate lists more blockers than the registry cap";
    return NULL;
}

/* Make `error_out` an object carrying only a "message" string. */
static void status_blocker_error_object(struct json_value *error_out,
                                        const char *message)
{
    json_set_object(error_out);
    json_push_kv_str(error_out, "message", message);
}

/* The dumpstate envelope names the blocker subsystem and a non-negative
 * captured_at, and carries an object "state". */
static bool status_blocker_envelope_ok(const struct json_value *response,
                                       const struct json_value *state)
{
    const char *subsystem =
        json_get_str(json_get(response, "subsystem"));
    const struct json_value *captured_at = json_get(response, "captured_at");
    return state && state->type == JSON_OBJ &&
           subsystem && strcmp(subsystem, "blocker") == 0 &&
           captured_at && captured_at->type == JSON_INT &&
           captured_at->val.i >= 0;
}

/* Reject an RPC error, transport error stub or mixed error+state response.
 * Returns false with `error_out` filled; true leaves `*state_out` set to the
 * dumpstate "state" object, which the envelope check has validated. */
static bool status_blocker_response_state(const struct json_value *response,
                                          struct json_value *error_out,
                                          const struct json_value **state_out)
{
    *state_out = NULL;
    const struct json_value *rpc_error = json_get(response, "error");
    if (rpc_error && rpc_error->type != JSON_NULL) {
        if (rpc_error->type == JSON_OBJ) {
            json_copy(error_out, rpc_error);
        } else {
            status_blocker_error_object(error_out,
                "blocker dumpstate returned an error indicator");
        }
        return false;
    }

    if (json_get(response, "code") || json_get(response, "message")) {
        /* HTTP/in-process RPC failures are normally a bare
         * {code,message,method} object; transport stubs may wrap it under
         * "error". Reject mixed error+state objects too: error evidence
         * cannot be made successful by appending plausible state. */
        json_copy(error_out, response);
        return false;
    }
    const struct json_value *state = json_get(response, "state");
    if (!status_blocker_envelope_ok(response, state)) {
        status_blocker_error_object(error_out,
            "blocker dumpstate missing valid blocker envelope");
        return false;
    }
    *state_out = state;
    return true;
}

/* Check the blocker entries and their counts against the dumpstate state. */
static bool status_blocker_entries_ok(const struct json_value *state,
                                      struct json_value *error_out)
{
    const struct json_value *entries = json_get(state, "blockers");
    const char *defect = status_entries_defect(entries);
    if (defect) {
        status_blocker_error_object(error_out, defect);
        return false;
    }
    if (!status_blocker_counts_match(state, entries)) {
        status_blocker_error_object(error_out,
            "blocker dumpstate counts contradict blocker entries");
        return false;
    }
    return true;
}

/* Copy every surviving dumpstate state key into the summary. Stops at the
 * first copy failure. */
static bool status_blocker_summary_copy_state(struct json_value *summary_out,
                                              const struct json_value *state,
                                              bool include_entries)
{
    for (size_t i = 0; i < state->num_children; i++) {
        const char *key = state->keys[i];
        if (status_summary_skips_key(key, include_entries))
            continue;
        if (!status_push_kv_verified(summary_out, key,
                                     &state->children[i]))
            return false;
    }
    return true;
}

/* Fill the summary and dominant blocker from the validated dumpstate state.
 * Returns false when any copy or verification step fails. */
static bool status_blocker_summary_fill(struct json_value *summary_out,
                                        struct json_value *dominant_out,
                                        const struct json_value *state,
                                        const struct json_value *captured_at,
                                        bool include_entries)
{
    const struct json_value *entries = json_get(state, "blockers");
    bool copy_ok = !include_entries ||
                   status_push_compact_blockers(summary_out, entries);
    copy_ok = status_blocker_summary_copy_state(summary_out, state,
                                                include_entries) && copy_ok;
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
    return copy_ok && status_push_kv_verified(
        summary_out, "dominant", dominant_out);
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
        status_blocker_error_object(error_out,
            raw ? "invalid blocker dumpstate JSON"
                : "blocker dumpstate RPC returned null");
        json_free(&response);
        return false;
    }

    const struct json_value *state = NULL;
    if (!status_blocker_response_state(&response, error_out, &state) ||
        !status_blocker_entries_ok(state, error_out)) {
        json_free(&response);
        return false;
    }

    json_set_object(summary_out);
    const struct json_value *captured_at =
        json_get(&response, "captured_at");
    if (!status_blocker_summary_fill(summary_out, dominant_out, state,
                                     captured_at, include_entries)) {
        json_set_null(summary_out);
        json_set_null(dominant_out);
        status_blocker_error_object(error_out,
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
