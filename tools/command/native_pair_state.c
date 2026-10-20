/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: ops.mesh.device.pair.status and the shared epoch reader: every
 * hash-PSK pairing epoch under the fleet state directory with its expiry,
 * revocation, credential and PSK fingerprint. Read-only; public facts only. */
#include "command/native_pair_common.h"
#include "services/device_identity.h"
#include "services/device_host_runtime_entry.h"
#include "platform/clock.h"
#include "base/hex.h"
#include "util/log_macros.h"
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define PAIR_TAG "native.pair_state"
#define PAIR_ROUTE_TEXT_MAX 4096

bool pair_name_ok(const char *text)
{
    if (!text || !text[0] || strlen(text) >= PAIR_NAME_MAX || text[0] < 'a' || text[0] > 'z') return false;
    for (const char *p = text; *p; ++p)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9'))) return false;
    return true;
}

static bool pair_path_byte(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr("/._-", c) != NULL;
}

bool pair_path_ok(const char *text)
{
    if (!text || text[0] != '/' || strlen(text) >= PAIR_PATH_MAX - 64) return false;
    for (const char *p = text; *p; ++p)
        if (!pair_path_byte(*p) || (p[0] == '.' && p[1] == '.')) return false;
    return true;
}

uint64_t pair_now(void)
{
    int64_t wall = clock_now_wall_ms();
    return wall > 0 ? (uint64_t)wall / 1000 : 0;
}

static bool pair_epoch_name(const char *name, const char *prefix, uint32_t *epoch)
{
    size_t length = strlen(prefix);
    if (strncmp(name, prefix, length) || name[length] != '-' || name[length + 1] != 'e') return false;
    const char *digits = name + length + 2;
    if (!*digits || *digits == '0' || strlen(digits) > 6) return false;
    for (const char *p = digits; *p; ++p)
        if (*p < '0' || *p > '9') return false;
    *epoch = (uint32_t)strtoul(digits, NULL, 10);
    return true;
}

uint32_t pair_dir_max(const char *dir, const char *prefix)
{
    DIR *handle = opendir(dir);
    if (!handle) return 0;
    uint32_t best = 0;
    for (const struct dirent *entry = readdir(handle); entry; entry = readdir(handle)) {
        uint32_t epoch;
        if (pair_epoch_name(entry->d_name, prefix, &epoch) && epoch > best) best = epoch;
    }
    closedir(handle);
    return best;
}

static int pair_epoch_cmp(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

size_t pair_epoch_list(const char *state, const char *peer, uint32_t *epochs, size_t cap)
{
    DIR *handle = opendir(state);
    if (!handle) return 0;
    size_t count = 0;
    for (const struct dirent *entry = readdir(handle); entry && count < cap; entry = readdir(handle)) {
        uint32_t epoch;
        char path[PAIR_PATH_MAX + 32];
        if (!pair_epoch_name(entry->d_name, peer, &epoch)) continue;
        if (snprintf(path, sizeof(path), "%s/%s/client.json", state, entry->d_name) >= (int)sizeof(path)) continue;
        if (access(path, F_OK) == 0) epochs[count++] = epoch;
    }
    closedir(handle);
    qsort(epochs, count, sizeof(epochs[0]), pair_epoch_cmp);
    return count;
}

static bool pair_hex_field(const struct json_value *object, const char *key, uint8_t out[32])
{
    const char *text = json_get_str(json_get(object, key));
    return text && strlen(text) == 64 && zcl_hex_decode(text, out, 32);
}

static bool pair_int_field(const struct json_value *object, const char *key, int64_t max, int64_t *out)
{
    const struct json_value *value = json_get(object, key);
    if (!value || value->type != JSON_INT || json_get_int(value) < 1 || json_get_int(value) > max) return false;
    *out = json_get_int(value);
    return true;
}

/* route_id is <client>-<peer>-e<epoch>; the client name is the part before the peer. */
static bool pair_route_client(const char *route, const char *peer, uint32_t epoch, char client[PAIR_NAME_MAX])
{
    char tail[48];
    int n = snprintf(tail, sizeof(tail), "-%s-e%u", peer, (unsigned)epoch);
    size_t length = strlen(route);
    if (n <= 0 || (size_t)n >= sizeof(tail) || length <= (size_t)n || length - (size_t)n >= PAIR_NAME_MAX) return false;
    if (strcmp(route + length - (size_t)n, tail)) return false;
    memcpy(client, route, length - (size_t)n);
    client[length - (size_t)n] = 0;
    return pair_name_ok(client);
}

static bool pair_route_fields(const struct json_value *route, const char *peer, struct pair_epoch *out)
{
    int64_t target, port;
    const char *id = json_get_str(json_get(route, "route_id"));
    const char *address = json_get_str(json_get(route, "route_address"));
    const char *directory = json_get_str(json_get(route, "directory"));
    char want[PAIR_PATH_MAX + 16];
    if (!id || !address || !directory || strlen(id) >= sizeof(out->route_id) || strlen(address) >= sizeof(out->route_address) ||
        !pair_hex_field(route, "peer_key", out->peer_key) || !pair_hex_field(route, "expected_root", out->cfg_root) ||
        !pair_int_field(route, "target_port", UINT16_MAX, &target) || !pair_int_field(route, "route_port", UINT16_MAX, &port) ||
        !pair_route_client(id, peer, out->epoch, out->client)) return false;
    snprintf(want, sizeof(want), "%s/profile", out->dir);
    if (strcmp(directory, want)) return false;
    memcpy(out->route_id, id, strlen(id) + 1);
    memcpy(out->route_address, address, strlen(address) + 1);
    memcpy(out->profile, directory, strlen(directory) + 1);
    out->target_port = (uint16_t)target;
    out->route_port = (uint16_t)port;
    return true;
}

bool pair_psk_fingerprint(const char *profile, const uint8_t peer[32], const uint8_t root[32],
                          uint16_t port, enum device_pairing_host_direction direction,
                          uint64_t now, char out[17])
{
    struct device_identity identity = {0};
    struct device_identity_publication_report report;
    struct device_pairing_store store;
    struct device_pairing_guard guard = {0};
    struct device_pairing_psk_snapshot snapshot = {0};
    out[0] = 0;
    if (!device_identity_open(&identity, profile, false, &report).ok) return false;
    bool ok = device_identity_pair_store(&identity, peer, &store).ok &&
              device_pairing_psk_snapshot_acquire(&store, peer, root, now, direction, port, &guard, &snapshot);
    device_pairing_guard_release(&guard);
    if (ok) zcl_native_device_psk_fingerprint(snapshot.secret, out);
    device_pairing_psk_snapshot_destroy(&snapshot);
    device_identity_close(&identity);
    return ok;
}

static bool pair_grant_read(struct pair_epoch *out, uint64_t now)
{
    struct device_identity identity = {0};
    struct device_identity_publication_report report;
    struct device_pairing_store store;
    if (!device_identity_open(&identity, out->profile, false, &report).ok) return false;
    bool ok = device_identity_pair_store(&identity, out->peer_key, &store).ok &&
              db_device_pairing_inspect(&store, out->peer_key, &out->row, out->root);
    device_identity_close(&identity);
    if (!ok) return false;
    zcl_hex_encode(out->row.host_scope.binding.psk.credential_id, 32, out->credential);
    out->psk_fp[0] = 0;
    if (!out->row.revoked_at && out->row.expires_at > now)
        (void)pair_psk_fingerprint(out->profile, out->peer_key, out->root, out->target_port,
                                   DEVICE_PAIRING_HOST_OUTBOUND, now, out->psk_fp);
    return true;
}

bool pair_epoch_load(const char *state, const char *peer, uint32_t epoch, struct pair_epoch *out)
{
    char path[PAIR_PATH_MAX + 32], text[PAIR_ROUTE_TEXT_MAX];
    size_t length = 0;
    struct json_value route = {0};
    memset(out, 0, sizeof(*out));
    out->epoch = epoch;
    if (snprintf(out->dir, sizeof(out->dir), "%s/%s-e%u", state, peer, (unsigned)epoch) >= (int)sizeof(out->dir) ||
        snprintf(path, sizeof(path), "%s/client.json", out->dir) >= (int)sizeof(path)) return false;
    if (!zcl_native_device_host_input_file_read(path, text, sizeof(text), &length)) {
        LOG_WARN(PAIR_TAG, "epoch %u: route file unreadable or not an owner-only regular file", (unsigned)epoch);
        return false;
    }
    bool ok = json_read(&route, text, length) && route.type == JSON_OBJ && pair_route_fields(&route, peer, out);
    json_free(&route);
    if (!ok) {
        LOG_WARN(PAIR_TAG, "epoch %u: route file is not a valid client route for this peer", (unsigned)epoch);
        return false;
    }
    return pair_grant_read(out, pair_now());
}

enum pair_state pair_epoch_state(const struct pair_epoch *epoch, uint64_t now)
{
    if (epoch->row.revoked_at) return PAIR_REVOKED;
    return epoch->row.expires_at <= now ? PAIR_EXPIRED : PAIR_ACTIVE;
}

const char *pair_state_name(enum pair_state state)
{
    return state == PAIR_ACTIVE ? "active" : state == PAIR_EXPIRED ? "expired" : "revoked";
}

bool pair_renew_due(const struct pair_epoch *epoch, uint64_t now, uint64_t before_s)
{
    return pair_epoch_state(epoch, now) != PAIR_REVOKED && epoch->row.expires_at <= now + before_s;
}

bool pair_epoch_emit(struct json_value *object, const struct pair_epoch *epoch, uint64_t now,
                     uint64_t before_s, bool current)
{
    int64_t left = (int64_t)epoch->row.expires_at - (int64_t)now;
    json_set_object(object);
    return json_push_kv_int(object, "epoch", epoch->epoch) && json_push_kv_str(object, "client", epoch->client) &&
           json_push_kv_str(object, "route_id", epoch->route_id) &&
           json_push_kv_str(object, "state", pair_state_name(pair_epoch_state(epoch, now))) &&
           json_push_kv_int(object, "expires_at", (int64_t)epoch->row.expires_at) &&
           json_push_kv_int(object, "expires_in_s", left) &&
           json_push_kv_int(object, "revoked_at", (int64_t)epoch->row.revoked_at) &&
           json_push_kv_bool(object, "renew_due", pair_renew_due(epoch, now, before_s)) &&
           json_push_kv_bool(object, "current", current) &&
           json_push_kv_str(object, "credential_id", epoch->credential) &&
           json_push_kv_int(object, "key_epoch", (int64_t)epoch->row.host_scope.binding.psk.key_epoch) &&
           json_push_kv_str(object, "psk_fingerprint", epoch->psk_fp) &&
           json_push_kv_int(object, "route_port", epoch->route_port) &&
           json_push_kv_int(object, "target_port", epoch->target_port);
}

/* ── ops.mesh.device.pair.status ─────────────────────────────────────── */

static void pair_status_fail(struct zcl_command_reply *reply, const char *code, const char *message)
{
    LOG_ERROR(PAIR_TAG, "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID, code, "normalize", false,
                           false, message, "state_dir peer renew_before_s");
}

static bool pair_status_inputs(const struct json_value *in, char state[PAIR_PATH_MAX], char peer[PAIR_NAME_MAX],
                               uint64_t *before_s)
{
    const char *dir = json_get_str(json_get(in, "state_dir"));
    const char *name = json_get_str(json_get(in, "peer"));
    const struct json_value *before = json_get(in, "renew_before_s");
    const char *home = getenv("HOME");
    char fallback[PAIR_PATH_MAX];
    if (!dir && home && snprintf(fallback, sizeof(fallback), "%s/.local/state/z23-tunnel", home) < (int)sizeof(fallback))
        dir = fallback;
    if (!pair_path_ok(dir) || !pair_name_ok(name ? name : "r2")) return false;
    snprintf(state, PAIR_PATH_MAX, "%s", dir);
    snprintf(peer, PAIR_NAME_MAX, "%s", name ? name : "r2");
    *before_s = PAIR_RENEW_BEFORE_DEFAULT_S;
    if (!before) return true;
    if (before->type != JSON_INT || json_get_int(before) < (int64_t)PAIR_RENEW_BEFORE_MIN_S ||
        json_get_int(before) > (int64_t)PAIR_RENEW_BEFORE_MAX_S) return false;
    *before_s = (uint64_t)json_get_int(before);
    return true;
}

struct pair_status_scan {
    uint64_t now, before_s, soonest;
    uint32_t current;
    size_t active;
};

static bool pair_status_push(struct json_value *list, struct pair_status_scan *scan, const char *state,
                             const char *peer, uint32_t epoch, uint32_t newest)
{
    struct pair_epoch loaded;
    struct json_value item = {0};
    if (!pair_epoch_load(state, peer, epoch, &loaded)) return true; /* unreadable epochs are skipped, never guessed at */
    bool ok = pair_epoch_emit(&item, &loaded, scan->now, scan->before_s, epoch == newest) && json_push_back(list, &item);
    json_free(&item);
    if (ok && pair_epoch_state(&loaded, scan->now) == PAIR_ACTIVE) {
        ++scan->active;
        if (!scan->soonest || loaded.row.expires_at < scan->soonest) scan->soonest = loaded.row.expires_at;
        if (epoch > scan->current) scan->current = epoch;
    }
    return ok;
}

static bool pair_status_emit(struct zcl_command_reply *reply, const char *peer, const struct pair_status_scan *scan,
                             size_t count, struct json_value *list)
{
    json_set_object(&reply->data);
    return json_push_kv_str(&reply->data, "schema", "zcl.device.pair.status.v1") &&
           json_push_kv_str(&reply->data, "peer", peer) && json_push_kv_int(&reply->data, "now", (int64_t)scan->now) &&
           json_push_kv_int(&reply->data, "renew_before_s", (int64_t)scan->before_s) &&
           json_push_kv_int(&reply->data, "count", (int64_t)count) &&
           json_push_kv_int(&reply->data, "active_count", (int64_t)scan->active) &&
           json_push_kv_int(&reply->data, "current_epoch", scan->current) &&
           json_push_kv_int(&reply->data, "soonest_expiry", (int64_t)scan->soonest) &&
           json_push_kv_bool(&reply->data, "renew_due", scan->active == 0 || scan->soonest <= scan->now + scan->before_s) &&
           json_push_kv(&reply->data, "pairings", list);
}

void zcl_native_handle_ops_mesh_device_pair_status(const struct zcl_command_request *request,
                                                   struct zcl_command_reply *reply)
{
    char state[PAIR_PATH_MAX], peer[PAIR_NAME_MAX];
    struct pair_status_scan scan = {.now = pair_now()};
    uint32_t epochs[PAIR_EPOCH_LIST_MAX];
    if (!reply) return;
    if (!request || !request->input || !pair_status_inputs(request->input, state, peer, &scan.before_s)) {
        pair_status_fail(reply, "PAIR_STATUS_INPUT_REFUSED", "state_dir must be an absolute path, peer a short lowercase name and renew_before_s 3600..2592000");
        return;
    }
    size_t count = pair_epoch_list(state, peer, epochs, PAIR_EPOCH_LIST_MAX);
    uint32_t newest = count ? epochs[count - 1] : 0;
    struct json_value list = {0};
    json_set_array(&list);
    bool ok = true;
    for (size_t i = 0; ok && i < count; ++i) ok = pair_status_push(&list, &scan, state, peer, epochs[i], newest);
    ok = ok && pair_status_emit(reply, peer, &scan, count, &list);
    json_free(&list);
    if (!ok) pair_status_fail(reply, "PAIR_STATUS_SERIALIZE_FAILED", "the pairing list did not fit the bounded reply");
}
