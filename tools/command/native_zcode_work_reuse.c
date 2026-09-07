/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: reusable-package facts behind `zcode work start` — the local
 * index rows the package lifecycle would resolve again, their verified
 * installed receipts and public API text, the composed dependency lock and
 * the signed peer inventory — split out of native_zcode_work_command.c so
 * each function stays under the cyclomatic-complexity cap; sibling
 * declarations live in native_zcode_work_priv.h. Nothing here admits or
 * installs a package: it only reads already-verified local facts. */

#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "native_zcode_work_priv.h"

#include "base/hex.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "services/package_lifecycle.h"
#include "vcs/package_index.h"
#include "vcs/package_manifest.h"
#include "vcs/package_publish.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_reuse.h"
#include "vcs/package_swarm_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The release, manifest and recipe a persisted index row names must parse,
 * verify and validate together before any of its facts may be reused. */
static bool zwork_reuse_release_load(const char *zcode_dir,
                                     const struct vcs_package_index_entry *entry,
                                     struct vcs_package_release *release,
                                     char package_hex[65])
{
    char path[ZWORK_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir,
                     entry->release_id_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (!zwork_read_bounded_regular(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                                    &wire, &wire_len)) return false;
    bool ok = vcs_package_release_parse(wire, wire_len, release) ==
                  VCS_PACKAGE_RELEASE_OK &&
              vcs_package_release_verify(release) == VCS_PACKAGE_RELEASE_OK;
    free(wire);
    if (!ok) return false;
    uint8_t release_id[32];
    char release_hex[65];
    if (vcs_package_release_id(release, release_id) !=
        VCS_PACKAGE_RELEASE_OK) return false;
    zcl_hex_encode(release_id, 32, release_hex);
    zcl_hex_encode(release->package_root, 32, package_hex);
    return strcmp(release_hex, entry->release_id_hex) == 0 &&
           strcmp(package_hex, entry->package_root_hex) == 0;
}

static bool zwork_reuse_manifest_load(const char *zcode_dir,
                                      const char *package_hex,
                                      struct vcs_package_manifest *manifest)
{
    char path[ZWORK_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/manifests/%s", zcode_dir,
                     package_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (!zwork_read_bounded_regular(path,
                                    VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                                    &wire, &wire_len)) return false;
    vcs_package_manifest_init(manifest);
    bool ok = vcs_package_manifest_parse(wire, wire_len, manifest);
    free(wire);
    return ok;
}

static bool zwork_reuse_recipe_load(const char *zcode_dir,
                                    const uint8_t recipe_root[32],
                                    struct vcs_package_recipe *recipe)
{
    char path[ZWORK_PATH_MAX], root_hex[65];
    zcl_hex_encode(recipe_root, 32, root_hex);
    int n = snprintf(path, sizeof(path), "%s/recipes/%s", zcode_dir,
                     root_hex);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    uint8_t *wire = NULL; size_t wire_len = 0;
    if (!zwork_read_bounded_regular(path, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
                                    &wire, &wire_len)) return false;
    bool ok = vcs_package_recipe_parse(wire, wire_len, recipe) ==
              VCS_PACKAGE_RECIPE_OK;
    free(wire);
    return ok;
}

static bool zwork_reuse_publish_validates(
    const struct vcs_package_release *release,
    const struct vcs_package_manifest *manifest,
    struct vcs_package_recipe *recipe)
{
    struct vcs_package_publish_report report;
    vcs_package_publish_report_init(&report);
    vcs_package_publish_validate(release, manifest, &report);
    vcs_package_publish_validate_recipe(release, manifest, recipe, &report);
    return report.failure_count == 0 && report.release_ok &&
           report.manifest_ok && report.recipe_ok;
}

bool zwork_reuse_load_facts(
    const char *zcode_dir, const struct vcs_package_index_entry *entry,
    struct vcs_package_recipe *recipe)
{
    struct vcs_package_release release;
    char package_hex[65];
    if (!zwork_reuse_release_load(zcode_dir, entry, &release, package_hex))
        return false;
    struct vcs_package_manifest manifest;
    if (!zwork_reuse_manifest_load(zcode_dir, package_hex, &manifest))
        return false;
    bool ok = zwork_reuse_recipe_load(zcode_dir, release.recipe_root, recipe) &&
        zwork_reuse_publish_validates(&release, &manifest, recipe);
    vcs_package_manifest_free(&manifest);
    return ok;
}

bool zwork_reuse_api_add(struct zwork_reuse_candidate *candidate,
                         const char *api, size_t len)
{
    if (!candidate || !api || len == 0 ||
        len >= ZWORK_REUSE_API_TEXT_MAX ||
        candidate->input.api_count >= VCS_PACKAGE_REUSE_MAX_APIS)
        return false;
    for (size_t i = 0; i < candidate->input.api_count; i++)
        if (strlen(candidate->api_text[i]) == len &&
            memcmp(candidate->api_text[i], api, len) == 0) return true;
    size_t at = candidate->input.api_count++;
    memcpy(candidate->api_text[at], api, len);
    candidate->api_text[at][len] = '\0';
    candidate->input.apis[at] = candidate->api_text[at];
    return true;
}

static bool zwork_reuse_symbol_char(uint8_t byte)
{
    return (byte >= 'A' && byte <= 'Z') || (byte >= 'a' && byte <= 'z') ||
           (byte >= '0' && byte <= '9') || byte == '_';
}

/* The identifier immediately left of an open parenthesis, minus the C
 * keywords that also take one. Header text is a hint, never a contract. */
static bool zwork_reuse_symbol_bounds(const uint8_t *bytes, size_t open_at,
                                      size_t *start_out, size_t *end_out)
{
    size_t end = open_at;
    while (end > 0 && (bytes[end - 1u] == ' ' ||
                       bytes[end - 1u] == '\t' ||
                       bytes[end - 1u] == '\n' ||
                       bytes[end - 1u] == '\r')) end--;
    size_t start = end;
    while (start > 0 && zwork_reuse_symbol_char(bytes[start - 1u])) start--;
    *start_out = start; *end_out = end;
    return start != end && !(bytes[start] >= '0' && bytes[start] <= '9');
}

static bool zwork_reuse_symbol_rejected(const uint8_t *bytes, size_t start,
                                        size_t end)
{
    static const char *const rejected[] = {
        "if", "for", "while", "switch", "sizeof", "return",
    };
    for (size_t r = 0; r < sizeof(rejected) / sizeof(rejected[0]); r++)
        if (strlen(rejected[r]) == end - start &&
            memcmp(bytes + start, rejected[r], end - start) == 0)
            return true;
    return false;
}

static void zwork_reuse_header_symbols(struct zwork_reuse_candidate *candidate,
                                       const char *path)
{
    uint8_t *bytes = NULL; size_t len = 0;
    if (!zwork_read_bounded_regular(path, ZWORK_REUSE_HEADER_BYTES_MAX,
                                    &bytes, &len)) return;
    for (size_t i = 0; i < len &&
         candidate->input.api_count < VCS_PACKAGE_REUSE_MAX_APIS; i++) {
        size_t start = 0, end = 0;
        if (bytes[i] != '(' ||
            !zwork_reuse_symbol_bounds(bytes, i, &start, &end) ||
            zwork_reuse_symbol_rejected(bytes, start, end))
            continue;
        (void)zwork_reuse_api_add(
            candidate, (const char *)bytes + start, end - start);
    }
    free(bytes);
}

static bool zwork_reuse_output_is_header(const char *path)
{
    size_t len = path ? strlen(path) : 0;
    return len > 10u && strncmp(path, "include/", 8) == 0 &&
           strcmp(path + len - 2u, ".h") == 0;
}

/* The installed tree must be one real directory whose receipt the package
 * lifecycle already verified; anything else marks the row invalid. */
static bool zwork_reuse_installed_dir(const char *zcode_dir,
                                      const struct vcs_package_index_entry *entry,
                                      char installed[ZWORK_PATH_MAX],
                                      bool *invalid_out)
{
    *invalid_out = false;
    int n = snprintf(installed, ZWORK_PATH_MAX, "%s/installed/%s",
                     zcode_dir, entry->package_root_hex);
    if (n <= 0 || n >= ZWORK_PATH_MAX) { *invalid_out = true; return false; }
    char installed_real[ZWORK_PATH_MAX];
    enum platform_directory_probe_result installed_probe =
        platform_directory_probe_real(installed);
    if (installed_probe == PLATFORM_DIRECTORY_PROBE_MISSING) return false;
    if (installed_probe != PLATFORM_DIRECTORY_PROBE_OK ||
        !platform_directory_canonical_real(
            installed, installed_real, sizeof(installed_real))) {
        *invalid_out = true; return false;
    }
    (void)snprintf(installed, ZWORK_PATH_MAX, "%s", installed_real);
    return true;
}

static bool zwork_reuse_installed_receipt(
    const char *datadir, const struct vcs_package_index_entry *entry,
    const uint8_t root[32], struct zwork_reuse_candidate *candidate)
{
    struct package_lifecycle_step step;
    bool verified = false;
    struct zcl_result inspected = package_lifecycle_installed_inspect(
        datadir, root, &step, &verified);
    if (!inspected.ok || !verified) {
        LOG_ERROR(ZWORK_LOG, "installed reuse refused for %s: %s",
                  entry->name, inspected.message);
        return false;
    }
    struct zcl_result read = package_lifecycle_receipt_read(
        datadir, step.receipt_id, &candidate->receipt);
    if (!read.ok) {
        LOG_ERROR(ZWORK_LOG, "installed receipt read refused for %s: %s",
                  entry->name, read.message);
        return false;
    }
    return true;
}

static void zwork_reuse_installed_apis(const char *installed,
                                       struct zwork_reuse_candidate *candidate)
{
    for (size_t i = 0; i < candidate->receipt.output_count &&
         candidate->input.api_count < VCS_PACKAGE_REUSE_MAX_APIS; i++) {
        const char *output = candidate->receipt.outputs[i].path;
        if (!zwork_reuse_output_is_header(output)) continue;
        (void)zwork_reuse_api_add(candidate, output, strlen(output));
        char header_path[ZWORK_PATH_MAX];
        int n = snprintf(header_path, sizeof(header_path), "%s/%s", installed,
                         output);
        if (n > 0 && (size_t)n < sizeof(header_path))
            zwork_reuse_header_symbols(candidate, header_path);
    }
}

void zwork_reuse_installed(
    const char *datadir, const char *zcode_dir,
    const struct vcs_package_index_entry *entry,
    struct zwork_reuse_candidate *candidate)
{
    uint8_t root[32];
    if (!zcl_hex_decode_lower(entry->package_root_hex, root, 32)) {
        candidate->installed_invalid = true; return;
    }
    char installed[ZWORK_PATH_MAX];
    bool invalid = false;
    if (!zwork_reuse_installed_dir(zcode_dir, entry, installed, &invalid)) {
        candidate->installed_invalid = invalid; return;
    }
    if (!zwork_reuse_installed_receipt(datadir, entry, root, candidate)) {
        candidate->installed_invalid = true; return;
    }
    candidate->input.installed = true;
    candidate->receipt_verified = true;
    zwork_reuse_installed_apis(installed, candidate);
}

bool zwork_lock_has_root(const struct vcs_package_lock *lock,
                         const char *root_hex)
{
    char node_hex[65];
    if (!lock || !root_hex) return false;
    for (size_t i = 0; i < lock->count; i++) {
        if (lock->nodes[i].depth == 0) continue;
        zcl_hex_encode(lock->nodes[i].root, 32, node_hex);
        if (strcmp(node_hex, root_hex) == 0) return true;
    }
    return false;
}

static bool zwork_index_lock_node(
    const struct vcs_package_index *index, const uint8_t root[32],
    struct vcs_package_lock_node *out)
{
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    const struct vcs_package_index_entry *match = NULL;
    for (size_t i = 0; i < vcs_package_index_count(index); i++) {
        const struct vcs_package_index_entry *entry =
            vcs_package_index_at(index, i);
        if (strcmp(entry->package_root_hex, root_hex) != 0) continue;
        if (match && (strcmp(match->name, entry->name) != 0 ||
                      strcmp(match->semver, entry->semver) != 0))
            return false;
        match = entry;
    }
    if (!match) return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->root, root, 32);
    (void)snprintf(out->name, sizeof(out->name), "%s", match->name);
    (void)snprintf(out->semver, sizeof(out->semver), "%s", match->semver);
    out->depth = 1;
    return true;
}

static int zwork_lock_node_cmp(const void *left, const void *right)
{
    const struct vcs_package_lock_node *a = left;
    const struct vcs_package_lock_node *b = right;
    return memcmp(a->root, b->root, 32);
}

static bool zwork_lock_insert(
    struct vcs_package_lock *lock,
    const struct vcs_package_lock_node *node)
{
    if (vcs_package_lock_find(lock, node->root) != SIZE_MAX) return true;
    if (lock->count == 0 || lock->count >= VCS_PACKAGE_LOCK_MAX_NODES ||
        lock->count > VCS_PACKAGE_DEPS_MAX_DIRECT)
        return false;
    lock->nodes[lock->count] = lock->nodes[lock->count - 1u];
    lock->nodes[lock->count - 1u] = *node;
    lock->count++;
    return true;
}

/* Every dependency root a selected installed receipt names, then the
 * selected package itself, must already be an unambiguous index row. */
static bool zwork_lock_add_selected(
    struct vcs_package_lock *composed,
    const struct vcs_package_index *index,
    const struct zwork_reuse_candidate *candidate)
{
    if (candidate->input.locked || !candidate->input.installed ||
        !candidate->receipt_verified)
        return true;
    for (size_t d = 0; d < candidate->receipt.dep_count; d++) {
        struct vcs_package_lock_node node;
        if (!zwork_index_lock_node(index, candidate->receipt.dep_roots[d],
                                   &node) ||
            !zwork_lock_insert(composed, &node))
            return false;
    }
    struct vcs_package_lock_node selected;
    uint8_t root[32];
    return zcl_hex_decode_lower(candidate->input.package->package_root_hex,
                                root, sizeof(root)) &&
           zwork_index_lock_node(index, root, &selected) &&
           zwork_lock_insert(composed, &selected);
}

static bool zwork_lock_reseal(struct vcs_package_prepared *prepared,
                              struct vcs_package_lock *composed)
{
    size_t dependency_count = composed->count - 1u;
    if (dependency_count > VCS_PACKAGE_DEPS_MAX_DIRECT) return false;
    qsort(composed->nodes, dependency_count, sizeof(composed->nodes[0]),
          zwork_lock_node_cmp);
    for (size_t i = 0; i < dependency_count; i++) {
        composed->nodes[i].depth = 1;
        composed->nodes[i].direct_deps = 0;
    }
    composed->nodes[dependency_count].depth = 0;
    composed->nodes[dependency_count].direct_deps =
        (uint16_t)dependency_count;
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    uint8_t root[32];
    if (vcs_package_lock_serialize(composed, &wire, &wire_len) !=
            VCS_PACKAGE_DEPS_OK ||
        vcs_package_lock_root(composed, root) != VCS_PACKAGE_DEPS_OK) {
        free(wire);
        return false;
    }
    free(prepared->lock_wire);
    prepared->lock = *composed;
    prepared->lock_wire = wire;
    prepared->lock_wire_len = wire_len;
    memcpy(prepared->lock_root, root, sizeof(root));
    return true;
}

bool zwork_compose_selected_lock(
    struct vcs_package_prepared *prepared,
    const struct vcs_package_index *index,
    const struct zwork_reuse_candidate *candidates,
    const struct vcs_package_reuse_plan *reuse, size_t *added_out)
{
    *added_out = 0;
    if (reuse->disposition != VCS_PACKAGE_REUSE_PARTIAL) return true;
    struct vcs_package_lock composed = prepared->lock;
    size_t before = composed.count;
    for (size_t s = 0; s < reuse->selected_count; s++)
        if (!zwork_lock_add_selected(
                &composed, index,
                &candidates[reuse->selected[s].input_index]))
            return false;
    if (composed.count == before) return true;
    if (!zwork_lock_reseal(prepared, &composed)) return false;
    *added_out = composed.count - before;
    return true;
}

/* The package lifecycle resolves a root to the highest-sequence release;
 * equal sequences use its deterministic publisher/release ordering.  Reuse
 * may hand that root to zcode.use only when the displayed index row is the
 * exact envelope that the lifecycle will resolve again. */
static bool zwork_reuse_release_precedes(
    const struct vcs_package_index_entry *entry,
    const struct vcs_package_index_entry *best)
{
    return entry->publisher_sequence > best->publisher_sequence ||
        (entry->publisher_sequence == best->publisher_sequence &&
         (strcmp(entry->publisher_hex, best->publisher_hex) < 0 ||
          (strcmp(entry->publisher_hex, best->publisher_hex) == 0 &&
           strcmp(entry->release_id_hex, best->release_id_hex) < 0)));
}

bool zwork_reuse_is_lifecycle_release(
    const struct vcs_package_index *index,
    const struct vcs_package_index_entry *candidate)
{
    const struct vcs_package_index_entry *best = NULL;
    size_t count = vcs_package_index_count(index);
    for (size_t i = 0; i < count; i++) {
        const struct vcs_package_index_entry *entry =
            vcs_package_index_at(index, i);
        if (strcmp(entry->package_root_hex,
                   candidate->package_root_hex) != 0)
            continue;
        if (!best || zwork_reuse_release_precedes(entry, best))
            best = entry;
    }
    return best && strcmp(best->release_id_hex,
                          candidate->release_id_hex) == 0;
}

/* The live swarm engine owns the advertised rows; without it the same rows
 * are read back from the bounded status projection. */
static size_t zwork_peer_advertised_json(struct vcs_swarm_advertised *rows,
                                         struct zwork_peer_inventory *inventory)
{
    struct json_value status;
    if (!zcl_native_zcode_swarm_status_read(&status)) return 0;
    inventory->live = json_get_bool_or(&status, "enabled", false) &&
        json_get_bool_or(&status, "present", false);
    const struct json_value *advertised = json_get(&status, "advertised");
    size_t seen = advertised && advertised->type == JSON_ARR
        ? json_size(advertised) : 0;
    inventory->truncated = seen > VCS_SWARM_MAX_LOCAL_ANNOUNCES;
    if (seen > VCS_SWARM_MAX_LOCAL_ANNOUNCES)
        seen = VCS_SWARM_MAX_LOCAL_ANNOUNCES;
    size_t count = 0;
    for (size_t i = 0; i < seen; i++) {
        const struct json_value *row = json_at(advertised, i);
        const char *root = row
            ? json_get_str(json_get(row, "root")) : NULL;
        int64_t advertisers = row
            ? json_get_int(json_get(row, "advertisers")) : 0;
        if (!root || strlen(root) != 64u || advertisers <= 0 ||
            advertisers > UINT32_MAX ||
            !zcl_hex_decode_lower(root, rows[count].root,
                                  sizeof(rows[count].root)))
            continue;
        rows[count++].advertisers = (uint32_t)advertisers;
    }
    json_free(&status);
    return count;
}

static size_t zwork_peer_advertised(struct vcs_swarm_advertised *rows,
                                    struct zwork_peer_inventory *inventory)
{
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    if (!engine) return zwork_peer_advertised_json(rows, inventory);
    inventory->live = true;
    return vcs_swarm_engine_advertised(
        engine, rows, VCS_SWARM_MAX_LOCAL_ANNOUNCES + 1u);
}

/* One signed pointer record binds a semantic package root to the transport
 * root the swarm advertises; the strongest matching announce wins. */
static uint32_t zwork_peer_advertisers_for(
    const struct json_value *records, size_t record_count,
    const char *package_root_hex, const struct vcs_swarm_advertised *rows,
    size_t count)
{
    uint32_t advertisers = 0;
    for (size_t p = 0; p < record_count; p++) {
        const struct json_value *record = json_at(records, p);
        const char *semantic = record
            ? json_get_str(json_get(record, "semantic_root")) : NULL;
        const char *transport = record
            ? json_get_str(json_get(record, "transport_root")) : NULL;
        uint8_t transport_root[32];
        if (!semantic || strcmp(semantic, package_root_hex) != 0 ||
            !transport || strlen(transport) != 64u ||
            !zcl_hex_decode_lower(
                transport, transport_root, sizeof(transport_root)))
            continue;
        for (size_t i = 0; i < count; i++)
            if (memcmp(transport_root, rows[i].root,
                       sizeof(transport_root)) == 0 &&
                rows[i].advertisers > advertisers)
                advertisers = rows[i].advertisers;
    }
    return advertisers;
}

/* Correlate transient peer availability only with release rows whose signed
 * package facts are already verified by the local index.  An ANNOUNCE is not
 * package metadata and therefore never creates a candidate or changes
 * compatibility; it only orders otherwise-equal verified candidates. */
void zwork_peer_inventory_apply(
    struct zwork_reuse_candidate *candidates, size_t candidate_count,
    struct zwork_peer_inventory *inventory)
{
    memset(inventory, 0, sizeof(*inventory));
    struct vcs_swarm_advertised rows[VCS_SWARM_MAX_LOCAL_ANNOUNCES + 1u];
    size_t count = zwork_peer_advertised(rows, inventory);
    if (!inventory->live) return;
    if (count > VCS_SWARM_MAX_LOCAL_ANNOUNCES) {
        inventory->truncated = true;
        count = VCS_SWARM_MAX_LOCAL_ANNOUNCES;
    }
    inventory->roots_seen = count;
    struct json_value selector, board;
    json_init(&selector); json_set_object(&selector);
    json_push_kv_str(&selector, "kind", "pointer");
    json_push_kv_str(&selector, "namespace", "zclassic23.package");
    json_push_kv_bool(&selector, "board", true);
    inventory->pointer_board_available =
        zcl_native_zcode_records_local(&selector, &board);
    json_free(&selector);
    if (!inventory->pointer_board_available) return;
    inventory->pointer_board_truncated =
        json_get_bool_or(&board, "truncated", false);
    const struct json_value *records = json_get(&board, "records");
    inventory->pointer_records_seen =
        records && records->type == JSON_ARR ? json_size(records) : 0;
    for (size_t c = 0; c < candidate_count; c++) {
        uint32_t advertisers = zwork_peer_advertisers_for(
            records, inventory->pointer_records_seen,
            candidates[c].input.package->package_root_hex, rows, count);
        candidates[c].input.peer_advertisers = advertisers;
        inventory->roots_matched += advertisers > 0;
    }
    json_free(&board);
}
