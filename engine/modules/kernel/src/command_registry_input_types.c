/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-key JSON type/range rules for zcl_command_registry_input_validate(),
 * split out of command_registry.c so that dispatcher stays under the
 * cyclomatic cap of 15. Behaviour is unchanged: each former else-if arm
 * is a table row or a small predicate. `key` is already in the leaf's
 * declared input_keys CSV before this runs. */

#include "kernel/command_registry.h"

#include "command_registry_internal.h"

#include "json/json.h"
#include "session/fleet_board_proto.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool cr_key_in(const char *key, const char *const *keys, size_t count)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(key, keys[i]) == 0)
            return true;
    return false;
}

static bool cr_int_range(const struct json_value *value, int64_t lo, int64_t hi)
{
    return value->type == JSON_INT && json_get_int(value) >= lo &&
           json_get_int(value) <= hi;
}

static bool cr_nonempty_str(const struct json_value *value, size_t max_len)
{
    const char *text = json_get_str(value);
    return value->type == JSON_STR && text && text[0] && strlen(text) <= max_len;
}

static bool cr_str_array(const struct json_value *value, size_t max_items,
                         size_t max_len)
{
    if (value->type != JSON_ARR || value->num_children > max_items)
        return false;
    for (size_t j = 0; j < value->num_children; j++) {
        const struct json_value *item = &value->children[j];
        const char *text = json_get_str(item);
        if (item->type != JSON_STR || !text || !text[0] || strlen(text) > max_len)
            return false;
    }
    return true;
}

static bool cr_match_files(const char *key, const struct json_value *value,
                           bool *type_ok)
{
    if (strcmp(key, "paths") == 0 && value->type == JSON_STR) {
        *type_ok = cr_nonempty_str(value, ZCL_COMMAND_INPUT_FILES_PATH_MAX * 4u);
        return true;
    }
    if (strcmp(key, "files") != 0 && strcmp(key, "symbols") != 0 &&
        strcmp(key, "paths") != 0)
        return false;
    *type_ok = cr_str_array(value, ZCL_COMMAND_INPUT_FILES_MAX_ITEMS,
                            ZCL_COMMAND_INPUT_FILES_PATH_MAX);
    return true;
}

static bool cr_match_bool(const char *key, const struct json_value *value,
                          bool *type_ok)
{
    static const char *const keys[] = {
        "verbose",           "details",           "confirm",
        "enabled",           "relink_generation", "wait_for_edit",
        "all",               "allow_high_fees",   "exact",
        "restore",           "release",           "once",
        "dry_run",           "require_existing_watcher", "allow_external",
    };
    if (!cr_key_in(key, keys, sizeof(keys) / sizeof(keys[0])) &&
        !command_registry_devagent_input_extra_bool_key(key))
        return false;
    *type_ok = value->type == JSON_BOOL;
    return true;
}

static bool cr_match_arrays(const char *key, const struct json_value *value,
                            bool *type_ok)
{
    static const char *const root_sets[] = {
        "read_only_verbs", "object_roots", "capability_roots",
        "service_roots",   "portal_roots", "starting_roots",
    };
    if (strcmp(key, "effects") == 0) {
        *type_ok = value->type == JSON_ARR && value->num_children >= 1u &&
                   value->num_children <= 50u;
        return true;
    }
    if (strcmp(key, "inputs") == 0 || strcmp(key, "prevtxs") == 0) {
        *type_ok = value->type == JSON_ARR && value->num_children <= 256u;
        return true;
    }
    if (strcmp(key, "outputs") == 0) {
        *type_ok = value->type == JSON_OBJ && value->num_children <= 256u;
        return true;
    }
    if (cr_key_in(key, root_sets, sizeof(root_sets) / sizeof(root_sets[0]))) {
        *type_ok = cr_str_array(value, 64u, 64u);
        return true;
    }
    return false;
}

static bool cr_match_public_keys(const char *key, const struct json_value *value,
                                 bool *type_ok)
{
    if (strcmp(key, "public_keys") != 0)
        return false;
    *type_ok = value->type == JSON_ARR && value->num_children >= 1u &&
               value->num_children <= 16u;
    for (size_t j = 0; *type_ok && j < value->num_children; j++) {
        const struct json_value *item = &value->children[j];
        const char *text = json_get_str(item);
        size_t len = text ? strlen(text) : 0;
        *type_ok = item->type == JSON_STR && (len == 66u || len == 130u);
        for (size_t k = 0; *type_ok && k < len; k++)
            *type_ok = isxdigit((unsigned char)text[k]) != 0;
    }
    return true;
}

static bool cr_match_units(const char *key, const struct json_value *value,
                           bool *type_ok)
{
    if (strcmp(key, "units") != 0 && strcmp(key, "supply") != 0)
        return false;
    const char *s = json_get_str(value);
    *type_ok = value->type == JSON_INT && json_get_int(value) > 0;
    if (*type_ok || value->type != JSON_STR || !s || !s[0] || strlen(s) > 20)
        return true;
    bool nonzero = false;
    *type_ok = true;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < '0' || *p > '9') {
            *type_ok = false;
            break;
        }
        if (*p != '0')
            nonzero = true;
    }
    *type_ok = *type_ok && nonzero;
    return true;
}

struct cr_int_bound {
    const char *key;
    int64_t lo;
    int64_t hi;
};

static const struct cr_int_bound *cr_find_int_bound(const char *key)
{
    static const struct cr_int_bound k_bounds[] = {
        { "decimals", 0, 8 },
        { "required_signatures", 1, 16 },
        { "action_mask", 1, 127 },
        { "raw_offset", 0, INT64_MAX },
        { "row_offset", 0, INT64_MAX },
        { "raw_bytes", 1, 1024 },
        { "slot", 1, 100 },
        { "window_hours", 1, 168 },
        /* dev.factory report window in hours. */
        { "hours", 1, 720 },
        { "height", 0, INT64_MAX },
        { "start_height", 0, INT64_MAX },
        { "after", 0, INT64_MAX },
        { "after_epoch", 0, INT64_MAX },
        { "facts_offset", 0, 4096 },
        { "day", 0, INT64_MAX },
        { "now_unix", 0, INT64_MAX },
        { "now", 0, INT64_MAX },
        { "created_at", 0, INT64_MAX },
        { "expires", 0, INT64_MAX },
        { "expires_at", 0, INT64_MAX },
        { "issued_unix", 0, INT64_MAX },
        { "expires_unix", 0, INT64_MAX },
        { "amount_zatoshi", 1, 2100000000000000LL },
        { "sequence", 1, INT64_MAX },
        { "not_before", 1, INT64_MAX },
        { "expiry", 1, INT64_MAX },
        { "observation_unix", 1, INT64_MAX },
        { "maximum_depth", 0, 8 },
        { "maximum_spaces", 1, 32 },
        { "maximum_portals", 1, 64 },
        { "deadline_ms", 1, 60000 },
        { "expires_in_seconds", 60, 3600 },
        { "challenge_block_height", 1, INT64_MAX },
        { "action_sequence", 1, INT64_MAX },
        { "result_sequence", 1, INT64_MAX },
        { "reproduction_sequence", 1, INT64_MAX },
        { "publisher_sequence", 1, INT64_MAX },
        { "max", 1, INT64_MAX },
        { "min-height", 0, INT64_MAX },
        { "seen-within", 0, 31536000 },
        { "page", 0, 1000000 },
        { "peer_id", 0, INT64_MAX },
        { "product_id", 1, INT64_MAX },
        { "purchase_id", 1, INT64_MAX },
        { "locktime_blocks", 1, 1000000 },
        { "price_per_mb_zat", 0, 2100000000000000LL },
        { "recipient_value_zat", 1, 2100000000000000LL },
        { "maximum_fee_zat", 0, 2100000000000000LL },
        { "concurrency", 1, 50 },
        { "tokens_per_purchase", 0, INT64_MAX },
        { "timeout_ms", 1, 300000 },
        { "heartbeat_ms", 100, 60000 },
        { "max_cpu_seconds", 1, 600 },
        { "verbosity", 0, 2 },
        { "max_items", 1, 100 },
        { "since_secs", 0, 31536000 },
        { "epoch", 0, INT64_MAX },
        { "rpc_port", 0, 65535 },
        { "watcher_id", 2, INT64_MAX },
        /* dev.loop.stop: a retiring_sessions row's kernel birth token. */
        { "watcher_born", 1, INT64_MAX },
        { "seconds", 1, 60 },
        { "top_n", 1, 32 },
        { "budget", 256, 8192 },
        { "depth", 1, 1000000 },
        /* fleet.steer.grant bearer lifetime: 0 means no expiry. */
        { "ttl_seconds", 0, 2592000 },
        /* fleet.board post/propose lifetime (the only two leaves declaring
         * a `ttl` key, both sharing this one bound): 1..FLEET_BOARD_TTL_MAX
         * (cognition/modules/session/.../fleet_board_proto.h). A shell
         * `--ttl=86400` arrives as a JSON int; before this entry the key
         * fell through to the default string rule and every numeric ttl was
         * refused at normalize. */
        { "ttl", 1, 2592000 },
        { "earned_score", 0, INT64_MAX },
        { "uploaded_bytes", 0, INT64_MAX },
        { "downloaded_bytes", 0, INT64_MAX },
    };
    for (size_t i = 0; i < sizeof(k_bounds) / sizeof(k_bounds[0]); i++) {
        if (strcmp(key, k_bounds[i].key) != 0)
            continue;
        return &k_bounds[i];
    }
    return NULL;
}

static bool cr_match_int_table(const char *key, const struct json_value *value,
                               bool *type_ok)
{
    const struct cr_int_bound *bound = cr_find_int_bound(key);
    if (!bound)
        return false;
    *type_ok = cr_int_range(value, bound->lo, bound->hi);
    return true;
}

static bool cr_match_dual(const char *key, const struct json_value *value,
                          bool *type_ok)
{
    size_t str_max = zcl_command_registry_input_str_max(key);
    if (strcmp(key, "seed") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX) || cr_nonempty_str(value, 32);
        return true;
    }
    if (strcmp(key, "amount") == 0 || strcmp(key, "price_zcl") == 0 ||
        strcmp(key, "price_zatoshi") == 0) {
        *type_ok = value->type == JSON_INT || value->type == JSON_REAL ||
                   cr_nonempty_str(value, 64);
        return true;
    }
    if (strcmp(key, "cursor") == 0) {
        *type_ok = cr_int_range(value, 0, INT64_MAX) ||
                   cr_nonempty_str(value, 256);
        return true;
    }
    if (strcmp(key, "nonce") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX) ||
                   cr_nonempty_str(value, str_max);
        return true;
    }
    if (strcmp(key, "since") == 0 || strcmp(key, "since_epoch") == 0) {
        *type_ok = value->type == JSON_INT
                       ? json_get_int(value) >= 0
                       : cr_nonempty_str(value, str_max);
        return true;
    }
    return false;
}

static bool cr_match_presentation(const char *path, const char *key,
                                  const struct json_value *value, bool *type_ok)
{
    if (strcmp(path, "app.presentation.show") != 0)
        return false;
    if (strcmp(key, "items") == 0) {
        *type_ok = value->type == JSON_ARR && json_size(value) <= 64u;
        return true;
    }
    if (strcmp(key, "actions") == 0) {
        *type_ok = value->type == JSON_ARR && json_size(value) <= 4u;
        return true;
    }
    return false;
}

static bool cr_match_tasks(const char *path, const char *key,
                            const struct json_value *value, bool *type_ok)
{
    if (strcmp(path, "app.tasks") != 0) return false;
    if (strcmp(key, "expected_revision") == 0) {
        *type_ok = cr_int_range(value, 0, INT64_MAX);
        return true;
    }
    if (strcmp(key, "task_id") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX);
        return true;
    }
    return false;
}

/* fleet.vitals.table: the machine list is an array of at most 64 objects (the
 * leaf owns the 16-machine bound and every field refusal, each with its own
 * code) or the same list as JSON text from a shell. */
static bool cr_match_vitals_table(const char *path, const char *key,
                                 const struct json_value *value, bool *type_ok)
{
    if (strcmp(path, "fleet.vitals.table") != 0 || strcmp(key, "machines") != 0)
        return false;
    *type_ok = (value->type == JSON_ARR && value->num_children <= 64u) ||
               cr_nonempty_str(value, 16384);
    return true;
}

/* fleet.steer.send carries its bounded directive batch as objects; the leaf
 * re-validates every item field (recipient alphabet, body bound,
 * idempotency-key alphabet), so the registry gate only bounds shape. Split
 * out so cr_match_path_special stays under the complexity cap. */
static bool cr_match_fleet_steer(const char *path, const char *key,
                               const struct json_value *value, bool *type_ok)
{
    if (cr_match_vitals_table(path, key, value, type_ok))
        return true;
    /* fleet.steer.grant list cursor: the ordinal a previous page returned. */
    if (!strcmp(path, "fleet.steer.grant") && !strcmp(key, "before")) {
        *type_ok = cr_int_range(value, 0, INT64_MAX);
        return true;
    }
    size_t j;
    if (!strcmp(path, "fleet.steer.wiki-write") && !strcmp(key, "text")) {
        *type_ok = cr_nonempty_str(value, FLEET_BOARD_WIKI_TEXT_MAX);
        return true;
    }
    if (strcmp(path, "fleet.steer.send") != 0 || strcmp(key, "items") != 0)
        return false;
    *type_ok = value->type == JSON_ARR && value->num_children >= 1u &&
               value->num_children <= 8u;
    for (j = 0; *type_ok && j < value->num_children; j++)
        *type_ok = value->children[j].type == JSON_OBJ;
    return true;
}

/* core.network.onion.vanity: bounds scoped to the leaf, since the names
 * threads, max_tries and timeout_s are generic. */
static bool cr_match_vanity_ints(const char *path, const char *key,
                                 const struct json_value *value, bool *type_ok)
{
    if (strcmp(path, "core.network.onion.vanity") != 0)
        return false;
    if (strcmp(key, "threads") == 0)
        *type_ok = cr_int_range(value, 1, 64);
    else if (strcmp(key, "max_tries") == 0)
        *type_ok = cr_int_range(value, 1, INT64_MAX);
    else if (strcmp(key, "timeout_s") == 0)
        *type_ok = cr_int_range(value, 1, 31536000);
    else
        return false;
    return true;
}

/* `limit` is an integer on every leaf except `fleet.ledger.add`, whose
 * limit is a string the default branch still types. `fleet.machines`
 * `offset` is an integer too; other leaves keep the string default so a
 * caller that already passes offset as text is unchanged. */
static bool cr_match_wiki_chunk_ints(const char *path, const char *key,
                                    const struct json_value *value, bool *type_ok)
{
    if (strcmp(path, "fleet.wiki.read") != 0 && strcmp(path, "fleet.steer.wiki-read") != 0) return false;
    if (strcmp(key, "offset") == 0)
        *type_ok = cr_int_range(value, 0, 16384);
    else if (strcmp(key, "bytes") == 0)
        *type_ok = cr_int_range(value, 1, 1024);
    else return false;
    return true;
}

/* core.wallet.security.unlock `timeout_seconds` is an integer 1..3600, the
 * same range wallet_lock_arm_timeout and the walletunlock RPC enforce. It is
 * leaf-scoped because zcode.node.verify takes a much larger timeout. */
static bool cr_match_wallet_unlock(const char *path, const char *key,
                                   const struct json_value *value,
                                   bool *type_ok)
{
    if (strcmp(path, "core.wallet.security.unlock") != 0 ||
        strcmp(key, "timeout_seconds") != 0)
        return false;
    *type_ok = cr_int_range(value, 1, 3600);
    return true;
}

static bool cr_match_leaf_ints(const char *path, const char *key,
                               const struct json_value *value, bool *type_ok)
{
    if (cr_match_wallet_unlock(path, key, value, type_ok))
        return true;
    if (cr_match_wiki_chunk_ints(path, key, value, type_ok))
        return true;
    if (cr_match_vanity_ints(path, key, value, type_ok))
        return true;
    if (strcmp(path, "dev.land") == 0 && strcmp(key, "wait_ms") == 0) {
        *type_ok = cr_int_range(value, 1, 900000);
        return true;
    }
    if (strcmp(path, "dev.app.machine.data") == 0 && strcmp(key, "size_mib") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX);
        return true;
    }
    if (strcmp(key, "limit") == 0 && strcmp(path, "fleet.ledger.add") != 0) {
        *type_ok = cr_int_range(value, 1, 1000000);
        return true;
    }
    /* fleet.steer.deliver: size and offset are integers; the handler owns the
     * 1..262144 and alignment refusals so each gets its typed code. */
    if (strcmp(path, "fleet.steer.deliver") == 0 &&
        (strcmp(key, "size") == 0 || strcmp(key, "offset") == 0)) {
        *type_ok = cr_int_range(value, INT64_MIN, INT64_MAX);
        return true;
    }
    if (strcmp(path, "fleet.machines") == 0 && strcmp(key, "offset") == 0) {
        *type_ok = cr_int_range(value, 0, INT64_MAX);
        return true;
    }
    return false;
}

static bool cr_match_blocker_items(const char *path, const char *key,
                                  const struct json_value *value, bool *type_ok)
{
    if (strcmp(path, "core.sync.blockers") != 0) return false;
    if (strcmp(key, "item_offset") == 0) *type_ok = cr_int_range(value, 0, 128);
    else if (strcmp(key, "item_limit") == 0) *type_ok = cr_int_range(value, 1, 128);
    else if (strcmp(key, "expected_snapshot") == 0) *type_ok = value->type == JSON_OBJ;
    else return false;
    return true;
}

/* dev.app.machine.boot, .snapshot and .resume: RAM size, work budget and the
 * test entropy seed are integers, and `type_after` is the console script:
 * at most 32 [marker, text] string pairs (the handler bounds each string). */
static bool cr_machine_ports(const struct json_value *value)
{
    if (value->type != JSON_ARR || value->num_children < 1u ||
        value->num_children > 2u) return false;
    for (size_t j = 0; j < value->num_children; j++)
        if (value->children[j].type != JSON_OBJ) return false;
    return true;
}

static bool cr_machine_boot_object(const char *key, const struct json_value *value,
    bool *type_ok)
{
    if (strcmp(key, "builtin_kernel") == 0) {
        *type_ok = value->type == JSON_BOOL;
        return true;
    }
    if (strcmp(key, "accepted_kernel") != 0 && strcmp(key, "public_unlock") != 0 &&
        strcmp(key, "public_kernel") != 0 && strcmp(key, "protected_kernel") != 0 &&
        strcmp(key, "protected_unlock") != 0) return false;
    *type_ok = value->type == JSON_OBJ;
    return true;
}
static bool cr_machine_path(const char *path)
{
    return strcmp(path, "dev.app.machine.boot") == 0 ||
           strcmp(path, "dev.app.machine.snapshot") == 0 ||
           strcmp(path, "dev.app.machine.resume") == 0;
}
static bool cr_machine_script(const struct json_value *value)
{
    if (value->type != JSON_ARR || value->num_children > 32u) return false;
    for (size_t j = 0; j < value->num_children; j++) {
        const struct json_value *pair = &value->children[j];
        if (pair->type != JSON_ARR || pair->num_children != 2u ||
            pair->children[0].type != JSON_STR || pair->children[1].type != JSON_STR)
            return false;
    }
    return true;
}
/* dev.app.machine.shell: RAM size, work cap and quiet period are integers. */
static bool cr_match_machine_shell(const char *path, const char *key,
                                   const struct json_value *value, bool *type_ok)
{
    if (strcmp(path, "dev.app.machine.shell") != 0)
        return false;
    if (strcmp(key, "ram_mib") == 0)
        *type_ok = cr_int_range(value, 64, 65536);
    else if (strcmp(key, "max_instr") == 0)
        *type_ok = cr_int_range(value, 1, INT64_MAX);
    else if (strcmp(key, "eof_quiet_ms") == 0)
        *type_ok = cr_int_range(value, 0, 3600000);
    else
        return false;
    return true;
}

static bool cr_match_machine_boot(const char *path, const char *key,
                                  const struct json_value *value, bool *type_ok)
{
    if (!cr_machine_path(path))
        return cr_match_machine_shell(path, key, value, type_ok);
    if (cr_machine_boot_object(key, value, type_ok)) return true;
    if (strcmp(key, "ram_mib") == 0) {
        *type_ok = cr_int_range(value, 64, 65536);
        return true;
    }
    if (strcmp(key, "max_instr") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX);
        return true;
    }
    if (strcmp(key, "test_entropy_seed") == 0) {
        *type_ok = cr_int_range(value, 0, INT64_MAX);
        return true;
    }
    if (strcmp(key, "ports") == 0) {
        *type_ok = cr_machine_ports(value);
        return true;
    }
    if (strcmp(key, "entropy") == 0) {
        *type_ok = value->type == JSON_STR;
        return true;
    }
    if (strcmp(key, "type_after") != 0)
        return false;
    *type_ok = cr_machine_script(value);
    return true;
}

/* HOST integers are leaf-scoped: other commands may use string `backend`. */
static const struct cr_int_bound *cr_device_package_bound(const char *path, const char *key)
{
    if (!path || strcmp(path, "ops.mesh.device.host.package.run")) return NULL;
    static const struct cr_int_bound bounds[] = {
        { "launch_ms", 1, 10000 }, { "execution_ms", 1, 600000 }, { "cleanup_ms", 1, 10000 }
    };
    for (size_t i = 0; i < sizeof(bounds) / sizeof(bounds[0]); ++i)
        if (!strcmp(key, bounds[i].key)) return &bounds[i];
    return NULL;
}

static const struct cr_int_bound *cr_device_host_bound(const char *path,
                                                       const char *key)
{
    if (strcmp(path, "ops.mesh.device.plan") != 0 &&
        strcmp(path, "ops.mesh.device.commit") != 0 &&
        strcmp(path, "ops.mesh.device.prepare-secret") != 0 &&
        strcmp(path, "ops.mesh.device.host.client") != 0 &&
        strcmp(path, "ops.mesh.device.host.receiver") != 0)
        return NULL;
    static const struct cr_int_bound bounds[] = {
        { "backend", 1, UINT32_MAX },
        { "inbound_port", 0, UINT16_MAX },
        { "outbound_port", 0, UINT16_MAX },
        { "paired_at", 1, INT64_MAX },
        { "key_epoch", 1, INT64_MAX },
        { "target_port", 1, UINT16_MAX },
        { "route_port", 1, UINT16_MAX },
        { "listen_port", 0, UINT16_MAX },
        { "connect_ms", 1, 10000 },
        { "handshake_ms", 1, 10000 },
        { "session_ms", 1, 28800000 },
        { "idle_ms", 1, 1800000 },
        { "lifetime_ms", 1, 86400000 },
        { "max_sessions", 1, 64 },
        { "max_active", 1, 4 },
    };
    for (size_t i = 0; i < sizeof(bounds) / sizeof(bounds[0]); ++i)
        if (strcmp(key, bounds[i].key) == 0) return &bounds[i];
    return NULL;
}
/* A descriptor owns both discovery and validation for these leaf-scoped
 * integers. Unrelated leaves retain the ordinary string default. */
static const struct cr_int_bound *cr_history_bound(const char *path,
                                                   const char *key)
{
    if (strcmp(path, "fleet.vitals.history") != 0) return NULL;
    static const struct cr_int_bound bounds[] = {
        { "after_seq", 0, INT64_MAX }, { "limit", 1, 64 }
    };
    for (size_t i = 0; i < sizeof bounds / sizeof bounds[0]; i++)
        if (strcmp(key, bounds[i].key) == 0) return &bounds[i];
    return NULL;
}

/* lab.run, lab.test, lab.promote and plugin.call: wall-clock and memory caps of
 * the confined run; plugin.pack: the interface version. */
static const struct cr_int_bound *cr_lab_bound(const char *path, const char *key)
{
    static const struct cr_int_bound bounds[] = {
        { "timeout_ms", 1, 60000 }, { "mem_mb", 1, 2048 }
    };
    static const struct cr_int_bound interface = { "interface", 1, 2 };
    if (strcmp(path, "plugin.pack") == 0 && strcmp(key, interface.key) == 0)
        return &interface;
    if (strcmp(path, "lab.run") != 0 && strcmp(path, "lab.test") != 0 &&
        strcmp(path, "lab.promote") != 0 && strcmp(path, "plugin.call") != 0)
        return NULL;
    for (size_t i = 0; i < sizeof bounds / sizeof bounds[0]; i++)
        if (strcmp(key, bounds[i].key) == 0) return &bounds[i];
    return NULL;
}

/* discover.read integers, and the docs path keys of discover.wiki and
 * discover.read, which are strings here although `page` is an integer
 * elsewhere. */
static const struct cr_int_bound *cr_docs_read_bound(const char *path,
                                                     const char *key)
{
    static const struct cr_int_bound bounds[] = {
        { "offset", 0, INT64_MAX }, { "bytes", 1, 16384 }
    };
    if (strcmp(path, "discover.read") != 0) return NULL;
    for (size_t i = 0; i < sizeof bounds / sizeof bounds[0]; i++)
        if (strcmp(key, bounds[i].key) == 0) return &bounds[i];
    return NULL;
}

static bool cr_docs_path_key(const char *path, const char *key)
{
    if (strcmp(key, "docsdir") == 0)
        return strcmp(path, "discover.read") == 0 ||
               strcmp(path, "discover.wiki") == 0;
    return (strcmp(path, "discover.read") == 0 && strcmp(key, "page") == 0) ||
           (strcmp(path, "discover.wiki") == 0 && strcmp(key, "topic") == 0);
}

static const struct cr_int_bound *cr_leaf_int_bound(const char *path,
                                                   const char *key)
{
    static const struct cr_int_bound examples = { "example_limit", 0, 32 };
    if (strcmp(path, "core.consensus.utxo.compare.offline") == 0 &&
        strcmp(key, examples.key) == 0) return &examples;
    const struct cr_int_bound *lab = cr_lab_bound(path, key);
    if (lab) return lab;
    const struct cr_int_bound *docs = cr_docs_read_bound(path, key);
    if (docs) return docs;
    const struct cr_int_bound *history = cr_history_bound(path, key);
    if (history) return history;
    const struct cr_int_bound *bound = cr_device_host_bound(path, key);
    return bound ? bound : cr_device_package_bound(path, key);
}
/* lab.run, lab.test and plugin.call: stdin may be empty; args and cases are
 * arrays. */
static bool cr_match_lab(const char *path, const char *key,
                         const struct json_value *value, bool *type_ok)
{
    if (strncmp(path, "lab.", 4) != 0 && strcmp(path, "plugin.call") != 0)
        return false;
    const char *text = json_get_str(value);
    if (strcmp(key, "stdin") == 0)
        *type_ok = value->type == JSON_STR && text &&
                   strlen(text) <= zcl_command_registry_input_str_max(key);
    else if (strcmp(key, "args") == 0)
        *type_ok = value->type == JSON_ARR && value->num_children <= 32u;
    else if (strcmp(key, "cases") == 0)
        *type_ok = (value->type == JSON_ARR && value->num_children <= 256u) ||
                   cr_nonempty_str(value, zcl_command_registry_input_str_max(key));
    else if (strcmp(key, "sanitize") == 0 || strcmp(key, "fresh") == 0 ||
             strcmp(key, "compile_only") == 0)
        *type_ok = value->type == JSON_BOOL;
    else
        return false;
    return true;
}

static bool cr_match_lab_or_ints(const char *path, const char *key,
                                 const struct json_value *value, bool *type_ok)
{
    return cr_match_lab(path, key, value, type_ok) ||
           cr_match_leaf_ints(path, key, value, type_ok);
}

static bool cr_match_path_special(const struct zcl_command_spec *spec,
                                  const char *key,
                                  const struct json_value *value,
                                  bool *type_ok)
{
    const char *path = spec && spec->path ? spec->path : "";
    if (cr_match_presentation(path, key, value, type_ok) ||
        cr_match_tasks(path, key, value, type_ok))
        return true;
    if (cr_match_fleet_steer(path, key, value, type_ok) ||
        cr_match_machine_boot(path, key, value, type_ok))
        return true;
    if (strcmp(key, "maximum_bytes") == 0) {
        int64_t maximum = strcmp(path, "zcode.package.fetch") == 0
                              ? 256LL * 1024LL * 1024LL
                              : 8LL * 1024LL * 1024LL;
        *type_ok = cr_int_range(value, 1, maximum);
        return true;
    }
    if (strcmp(key, "days") == 0 && strcmp(path, "fleet.usage") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX);
        return true;
    }
    if (strcmp(key, "cutoff_height") == 0 || strcmp(key, "cutoff_mtp") == 0 ||
        strcmp(key, "epoch_capacity_atoms") == 0) {
        *type_ok = cr_int_range(value, 1, INT64_MAX);
        return true;
    }
    if (cr_match_lab_or_ints(path, key, value, type_ok))
        return true;
    return false;
}

/* `line` is TWO unrelated inputs that happen to share a name, and this table
 * types by NAME rather than by leaf:
 *
 *   dev.agent.mutate `line`  a source line NUMBER, 1..1000000
 *   fleet.import     `line`  one whole base64url roster line, a STRING
 *
 * The integer rule must not apply to fleet.import. Two leaves may declare
 * the same key with different meanings; only the leaf path tells them apart.
 * Any other `line` stays an integer. */
static bool cr_match_chunks_and_lines(const struct zcl_command_spec *spec,
                                      const char *key,
                                      const struct json_value *value,
                                      bool *type_ok)
{
    const char *path = spec && spec->path ? spec->path : "";
    if (strcmp(key, "chunk_start") == 0 || strcmp(key, "chunks_paid") == 0) {
        int64_t lo = strcmp(key, "chunks_paid") == 0 ? 1 : 0;
        *type_ok = cr_int_range(value, lo, 4294967295LL);
        return true;
    }
    if (strcmp(key, "line") == 0 && strcmp(path, "fleet.import") == 0) {
        *type_ok = cr_nonempty_str(value,
                                   zcl_command_registry_input_str_max(key));
        return true;
    }
    if (strcmp(key, "max_lines") == 0 || strcmp(key, "line") == 0) {
        int64_t hi = strcmp(key, "line") ? 1000 : 1000000;
        *type_ok = cr_int_range(value, 1, hi);
        return true;
    }
    return false;
}

static bool cr_default_string(const char *key, const struct json_value *value)
{
    const char *text = json_get_str(value);
    bool type_ok = cr_nonempty_str(value, zcl_command_registry_input_str_max(key));
    if (type_ok && strcmp(key, "side") == 0)
        type_ok = strcmp(text, "input") == 0 || strcmp(text, "output") == 0;
    if (type_ok && strcmp(key, "view") == 0)
        type_ok = strcmp(text, "summary") == 0 || strcmp(text, "normal") == 0 ||
                  strcmp(text, "full") == 0;
    return type_ok;
}

static bool cr_csv_has(const char *csv, const char *value)
{
    if (!csv || !csv[0] || !value)
        return false;
    size_t value_len = strlen(value);
    const char *at = csv;
    while (*at) {
        const char *end = strchr(at, ',');
        size_t len = end ? (size_t)(end - at) : strlen(at);
        if (len == value_len && memcmp(at, value, len) == 0)
            return true;
        if (!end)
            break;
        at = end + 1;
    }
    return false;
}

bool command_registry_input_key_declared(const struct zcl_command_spec *spec,
                                         const struct json_value *input,
                                         size_t i, char *why, size_t why_size)
{
    const char *key = input->keys[i];
    if (!key || !key[0] || !cr_csv_has(spec->input_keys, key)) {
        if (why)
            snprintf(why, why_size, "unknown input key '%s'", key ? key : "");
        return false;
    }
    for (size_t j = 0; j < i; j++) {
        if (input->keys[j] && strcmp(input->keys[j], key) == 0) {
            if (why)
                snprintf(why, why_size, "duplicate input key '%s'", key);
            return false;
        }
    }
    return true;
}

/* The rule behind a rejected core.sync.blockers paging key, or NULL. */
static const char *cr_blocker_key_rule(const char *key)
{
    if (!strcmp(key, "item_offset")) return "an integer from 0 to 128, default 0";
    if (!strcmp(key, "item_limit")) return "an integer from 1 to 128, default 128";
    if (!strcmp(key, "expected_snapshot"))
        return "the unmodified snapshot object of the previous page";
    return NULL;
}

bool command_registry_input_type_why(const char *key,
                                     const struct json_value *value, char *why,
                                     size_t why_size)
{
    const char *text = json_get_str(value);
    size_t str_max = zcl_command_registry_input_str_max(key);
    if (why && value->type == JSON_STR && text && strlen(text) > str_max)
        snprintf(why, why_size,
                 "input key '%s' is %zu characters, over its %zu limit",
                 key, strlen(text), str_max);
    else if (why && cr_blocker_key_rule(key))
        snprintf(why, why_size,
                 "invalid type or range for input key '%s': expected %s", key,
                 cr_blocker_key_rule(key));
    else if (why)
        snprintf(why, why_size, "invalid type or range for input key '%s'",
                 key);
    return false;
}

static const char *cr_required_discovery_key(const char *path)
{
    if (strcmp(path, "discover.search") == 0)
        return "query";
    if (strcmp(path, "discover.describe") == 0 ||
        strcmp(path, "discover.schema") == 0)
        return "path";
    return NULL;
}

bool zcl_command_registry_input_descriptor(
    const struct zcl_command_spec *spec, const char *key,
    struct zcl_command_input_descriptor *out)
{
    static const char *const strings[] = { "path", "query", "side" };
    static const char *const integers[] = {
        "after", "after_epoch", "timeout_ms", "heartbeat_ms"
    };
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!spec || !spec->path || !key || !cr_csv_has(spec->input_keys, key))
        return false;
    const struct cr_int_bound *host_bound = cr_leaf_int_bound(spec->path, key);
    if (host_bound) {
        out->type = JSON_INT;
        out->minimum = host_bound->lo;
        out->maximum = host_bound->hi;
    } else if (cr_key_in(key, strings, sizeof(strings) / sizeof(strings[0])) ||
               cr_docs_path_key(spec->path, key)) {
        out->type = JSON_STR;
        out->max_bytes = zcl_command_registry_input_str_max(key);
    } else if (cr_key_in(key, integers, sizeof(integers) / sizeof(integers[0]))) {
        const struct cr_int_bound *bound = cr_find_int_bound(key);
        if (!bound)
            return false;
        out->type = JSON_INT;
        out->minimum = bound->lo;
        out->maximum = bound->hi;
    } else {
        return false;
    }
    const char *required = cr_required_discovery_key(spec->path);
    out->required = required && strcmp(required, key) == 0;
    return true;
}

bool command_registry_input_required_discovery(
    const struct zcl_command_spec *spec, const struct json_value *input,
    char *why, size_t why_size)
{
    const char *required_key = cr_required_discovery_key(spec->path);
    if (!required_key)
        return true;
    const char *value = json_get_str(json_get(input, required_key));
    if (value && value[0])
        return true;
    if (why)
        snprintf(why, why_size, "missing required input key '%s'",
                 required_key);
    return false;
}

static bool cr_match_shaped(const struct zcl_command_spec *spec,
                            const char *key, const struct json_value *value,
                            bool *type_ok)
{
    if (cr_match_files(key, value, type_ok))
        return true;
    if (cr_match_bool(key, value, type_ok))
        return true;
    if (cr_match_arrays(key, value, type_ok))
        return true;
    if (cr_match_public_keys(key, value, type_ok))
        return true;
    if (cr_match_units(key, value, type_ok))
        return true;
    return cr_match_blocker_items(spec ? spec->path : "", key, value, type_ok);
}

bool command_registry_input_value_type_ok(const struct zcl_command_spec *spec,
                                          const char *key,
                                          const struct json_value *value,
                                          bool *type_ok)
{
    if (!type_ok || !key || !value)
        return false;
    *type_ok = false;
    struct zcl_command_input_descriptor descriptor;
    if (zcl_command_registry_input_descriptor(spec, key, &descriptor)) {
        *type_ok = descriptor.type == JSON_INT
            ? cr_int_range(value, descriptor.minimum, descriptor.maximum)
            : cr_default_string(key, value);
        return true;
    }
    if (cr_match_shaped(spec, key, value, type_ok))
        return true;
    if (cr_match_int_table(key, value, type_ok))
        return true;
    if (cr_match_dual(key, value, type_ok))
        return true;
    if (cr_match_path_special(spec, key, value, type_ok))
        return true;
    if (cr_match_chunks_and_lines(spec, key, value, type_ok))
        return true;
    if (zcl_command_registry_devagent_input_ok(spec ? spec->path : NULL, key,
                                               value, type_ok))
        return true;
    if (strcmp(key, "seq") == 0) {
        *type_ok = command_registry_devagent_input_seq_ok(value);
        return true;
    }
    *type_ok = cr_default_string(key, value);
    return true;
}
