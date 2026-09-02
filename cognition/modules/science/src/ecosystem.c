/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: derive the live Z23 C23 ecosystem snapshot from checkout evidence. */

#include "science/ecosystem.h"

#include "base/log_macros.h"
#include "json/json.h"
#include "platform/directory_compat.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

enum { ECO_WALK_PATH_MAX = 4096 };

static bool eco_error(char *error, size_t cap, const char *message)
{
    if (error && cap)
        (void)snprintf(error, cap, "%s", message);
    return false;
}

static bool eco_add_named(struct science_ecosystem_named_count *rows,
                          uint32_t cap, uint32_t *listed, bool *truncated,
                          const char *name, const char *detail,
                          uint32_t count)
{
    if (*listed >= cap) {
        *truncated = true;
        return true;
    }
    struct science_ecosystem_named_count *row = &rows[(*listed)++];
    (void)snprintf(row->name, sizeof(row->name), "%s", name ? name : "");
    (void)snprintf(row->detail, sizeof(row->detail), "%s",
                   detail ? detail : "");
    row->count = count;
    return true;
}

static bool eco_read_small(const char *path, char *buf, size_t cap,
                           size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(buf, 1, cap - 1u, f);
    bool err = ferror(f) != 0;
    bool extra = false;
    if (n == cap - 1u) {
        char overflow;
        extra = fread(&overflow, 1, 1, f) == 1u;
    }
    if (fclose(f) != 0)
        err = true;
    if (err || extra)
        return false;
    buf[n] = '\0';
    *len = n;
    return true;
}

static void eco_package_identity(const char *manifest, const char *dir_name,
                                 char name[SCIENCE_ECOSYSTEM_NAME_MAX],
                                 char detail[SCIENCE_ECOSYSTEM_DETAIL_MAX])
{
    (void)snprintf(name, SCIENCE_ECOSYSTEM_NAME_MAX, "%s",
                   dir_name ? dir_name : "");
    detail[0] = '\0';
    char buf[8192];
    size_t len = 0;
    struct json_value root;
    json_init(&root);
    if (eco_read_small(manifest, buf, sizeof(buf), &len) &&
        json_read(&root, buf, len) && root.type == JSON_OBJ) {
        const char *json_name = json_get_str(json_get(&root, "name"));
        const char *language = json_get_str(json_get(&root, "language"));
        if (json_name && json_name[0])
            (void)snprintf(name, SCIENCE_ECOSYSTEM_NAME_MAX, "%s", json_name);
        if (language && language[0])
            (void)snprintf(detail, SCIENCE_ECOSYSTEM_DETAIL_MAX, "%s",
                           language);
    }
    json_free(&root);
}

static bool eco_collect_packages(const char *root, const char *rel,
                                 struct science_ecosystem_snapshot *out)
{
    char full[ECO_WALK_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof(full))
        LOG_FAIL("science.ecosystem", "package path too long under %s", rel);
    if (platform_directory_probe_real(full) != PLATFORM_DIRECTORY_PROBE_OK)
        return true;

    struct platform_directory_list dirs = {0};
    if (!platform_directory_list_real_sorted(full, &dirs))
        LOG_FAIL("science.ecosystem", "could not list packages under %s", full);
    bool ok = true;
    for (size_t i = 0; ok && i < dirs.count; i++) {
        const char *name = dirs.entries[i].name;
        if (!name || !name[0])
            continue;
        char manifest[ECO_WALK_PATH_MAX];
        int m = snprintf(manifest, sizeof(manifest), "%s/%s/zcode-package.json",
                         full, name);
        if (m <= 0 || (size_t)m >= sizeof(manifest)) {
            ok = false;
            break;
        }
        FILE *probe = fopen(manifest, "rb");
        if (!probe)
            continue;
        (void)fclose(probe);
        char pkg_name[SCIENCE_ECOSYSTEM_NAME_MAX];
        char detail[SCIENCE_ECOSYSTEM_DETAIL_MAX];
        eco_package_identity(manifest, name, pkg_name, detail);
        out->package_count++;
        ok = eco_add_named(out->packages, SCIENCE_ECOSYSTEM_PACKAGES_MAX,
                           &out->package_listed, &out->packages_truncated,
                           pkg_name, detail, 1u);
    }
    platform_directory_list_free(&dirs);
    return ok;
}

static bool eco_collect_contexts(const char *root,
                                 struct science_ecosystem_snapshot *out)
{
    char full[ECO_WALK_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/contexts", root);
    if (n <= 0 || (size_t)n >= sizeof(full))
        LOG_FAIL("science.ecosystem", "contexts path too long");
    if (platform_directory_probe_real(full) != PLATFORM_DIRECTORY_PROBE_OK)
        return true;

    struct platform_directory_list dirs = {0};
    if (!platform_directory_list_real_sorted(full, &dirs))
        LOG_FAIL("science.ecosystem", "could not list architectural contexts");
    bool ok = true;
    for (size_t i = 0; ok && i < dirs.count; i++) {
        const char *name = dirs.entries[i].name;
        if (!name || !name[0])
            continue;
        out->context_count++;
        ok = eco_add_named(out->contexts, SCIENCE_ECOSYSTEM_CONTEXTS_MAX,
                           &out->context_listed, &out->contexts_truncated,
                           name, "feature room", 1u);
    }
    platform_directory_list_free(&dirs);
    return ok;
}

static bool eco_sha3_nonzero(const uint8_t sha3[32])
{
    if (!sha3)
        return false;
    for (size_t i = 0; i < 32u; i++)
        if (sha3[i] != 0)
            return true;
    return false;
}

static bool text_append(char *out, size_t cap, size_t *used, const char *text)
{
    if (!out || !used || cap == 0)
        return false;
    size_t len = strlen(text);
    if (*used >= cap)
        return false;
    size_t room = cap - *used - 1u;
    if (len > room)
        return false;
    memcpy(out + *used, text, len);
    *used += len;
    out[*used] = '\0';
    return true;
}

static bool text_u64(char *out, size_t cap, size_t *used, const char *key,
                     uint64_t value)
{
    char line[160];
    (void)snprintf(line, sizeof(line), "%s: %" PRIu64 "\n", key, value);
    return text_append(out, cap, used, line);
}

static bool text_str(char *out, size_t cap, size_t *used, const char *key,
                     const char *value)
{
    char line[SCIENCE_ECOSYSTEM_PATH_MAX + 64u];
    (void)snprintf(line, sizeof(line), "%s: %s\n", key, value ? value : "");
    return text_append(out, cap, used, line);
}

static bool text_named_list(char *out, size_t cap, size_t *used,
                            const char *prefix,
                            const struct science_ecosystem_named_count *rows,
                            uint32_t listed, bool truncated)
{
    bool ok = true;
    for (uint32_t i = 0; ok && i < listed; i++) {
        char line[SCIENCE_ECOSYSTEM_NAME_MAX +
                  SCIENCE_ECOSYSTEM_DETAIL_MAX + 48u];
        if (rows[i].detail[0])
            (void)snprintf(line, sizeof(line), "%s[%" PRIu32 "]: %s (%s)\n",
                           prefix, i, rows[i].name, rows[i].detail);
        else
            (void)snprintf(line, sizeof(line), "%s[%" PRIu32 "]: %s\n",
                           prefix, i, rows[i].name);
        ok = text_append(out, cap, used, line);
    }
    if (ok && truncated)
        ok = text_append(out, cap, used, "truncated: true\n");
    return ok;
}

bool science_ecosystem_collect(
    const char *root,
    const struct science_ecosystem_collect_options *options,
    struct science_ecosystem_snapshot *out,
    char *error, size_t error_cap)
{
    if (!root || !root[0] || !out)
        return eco_error(error, error_cap, "source root/snapshot is missing");
    memset(out, 0, sizeof(*out));
    (void)snprintf(out->source_root, sizeof(out->source_root), "%s", root);
    (void)snprintf(out->growth_error, sizeof(out->growth_error),
                   "not collected");

    if (!eco_collect_packages(root, "contexts/commons/packages", out) ||
        !eco_collect_packages(root, "packages", out))
        return eco_error(error, error_cap, "package manifest walk failed");
    if (!eco_collect_contexts(root, out))
        return eco_error(error, error_cap,
                         "architectural context walk failed");

    char inventory[ECO_WALK_PATH_MAX];
    const char *inventory_path = options ? options->inventory_path : NULL;
    if (!inventory_path || !inventory_path[0]) {
        int n = snprintf(inventory, sizeof(inventory),
                         "%s/docs/CAPABILITY_INVENTORY.jsonl", root);
        if (n <= 0 || (size_t)n >= sizeof(inventory))
            return eco_error(error, error_cap, "inventory path is too long");
        inventory_path = inventory;
    }
    if (!science_corpus_measure(root, inventory_path, &out->corpus))
        return eco_error(error, error_cap, "maintained C23 census failed");

    if (options && options->collect_growth) {
        if (science_code_growth_collect(root, &out->growth, out->growth_error,
                                        sizeof(out->growth_error))) {
            out->growth_present = true;
            out->growth_error[0] = '\0';
        } else {
            out->growth_present = false;
            if (!out->growth_error[0])
                (void)snprintf(out->growth_error, sizeof(out->growth_error),
                               "Git growth reconstruction failed");
        }
    }

    if (error && error_cap)
        error[0] = '\0';
    return true;
}

void science_ecosystem_bind_index(
    struct science_ecosystem_snapshot *out, bool present,
    const uint8_t sha3[32], uint32_t c23_files, uint32_t registry_nodes,
    bool include_available, int64_t include_edges,
    const struct science_ecosystem_named_count *roots, uint32_t root_count)
{
    if (!out)
        return;
    out->index_present = present;
    out->source_root_sha3_present = present && eco_sha3_nonzero(sha3);
    memset(out->source_root_sha3, 0, sizeof(out->source_root_sha3));
    if (out->source_root_sha3_present)
        memcpy(out->source_root_sha3, sha3, 32u);
    out->indexed_c23_files = present ? c23_files : 0;
    out->indexed_registry_nodes = present ? registry_nodes : 0;
    out->include_edges_available = present && include_available;
    out->include_edge_count = out->include_edges_available ? include_edges : 0;
    out->indexed_root_count = 0;
    out->indexed_root_listed = 0;
    out->indexed_roots_truncated = false;
    memset(out->indexed_roots, 0, sizeof(out->indexed_roots));
    if (!present || !roots)
        return;
    out->indexed_root_count = root_count;
    uint32_t copy = root_count;
    if (copy > SCIENCE_ECOSYSTEM_ROOTS_MAX) {
        copy = SCIENCE_ECOSYSTEM_ROOTS_MAX;
        out->indexed_roots_truncated = true;
    }
    for (uint32_t i = 0; i < copy; i++)
        out->indexed_roots[i] = roots[i];
    out->indexed_root_listed = copy;
}

void science_ecosystem_bind_growth(
    struct science_ecosystem_snapshot *out,
    const struct science_code_growth_history *history)
{
    if (!out)
        return;
    if (!history || history->day_count == 0) {
        out->growth_present = false;
        if (!out->growth_error[0])
            (void)snprintf(out->growth_error, sizeof(out->growth_error),
                           "growth history is empty");
        return;
    }
    out->growth_present = true;
    out->growth_error[0] = '\0';
    out->growth = *history;
}

bool science_ecosystem_format_text(
    const struct science_ecosystem_snapshot *snap,
    char *out, size_t cap, size_t *len)
{
    if (!snap || !out || cap == 0)
        return false;
    size_t used = 0;
    out[0] = '\0';
    bool ok = text_append(out, cap, &used, "Z23 C23 ecosystem\n") &&
        text_str(out, cap, &used, "authority", "display-only") &&
        text_str(out, cap, &used, "source_root", snap->source_root);
    if (ok) {
        if (snap->source_root_sha3_present) {
            char hex[65];
            static const char digits[] = "0123456789abcdef";
            for (size_t i = 0; i < 32u; i++) {
                hex[2u * i] = digits[(snap->source_root_sha3[i] >> 4) & 0xf];
                hex[2u * i + 1u] =
                    digits[snap->source_root_sha3[i] & 0xf];
            }
            hex[64] = '\0';
            ok = text_str(out, cap, &used, "source_root_sha3", hex);
        } else {
            ok = text_str(out, cap, &used, "source_root_sha3", "unavailable");
        }
    }
    ok = ok &&
        text_str(out, cap, &used, "packages_authority",
                 "zcode-package.json manifests") &&
        text_u64(out, cap, &used, "packages", snap->package_count) &&
        text_named_list(out, cap, &used, "package", snap->packages,
                        snap->package_listed, snap->packages_truncated) &&
        text_u64(out, cap, &used, "production_c23_lines",
                 snap->corpus.non_test_lines) &&
        text_u64(out, cap, &used, "test_c23_lines",
                 snap->corpus.test_lines) &&
        text_u64(out, cap, &used, "files_walked",
                 snap->corpus.files_walked) &&
        text_u64(out, cap, &used, "architectural_contexts",
                 snap->context_count) &&
        text_named_list(out, cap, &used, "context", snap->contexts,
                        snap->context_listed, snap->contexts_truncated);

    if (ok && snap->index_present) {
        ok = text_u64(out, cap, &used, "indexed_c23_files",
                      snap->indexed_c23_files) &&
            text_u64(out, cap, &used, "indexed_registry_nodes",
                     snap->indexed_registry_nodes) &&
            text_u64(out, cap, &used, "indexed_source_roots",
                     snap->indexed_root_count) &&
            text_named_list(out, cap, &used, "indexed_root",
                            snap->indexed_roots, snap->indexed_root_listed,
                            snap->indexed_roots_truncated);
        if (ok && snap->include_edges_available) {
            if (snap->include_edge_count == 0)
                ok = text_str(out, cap, &used, "include_edges",
                              "unanswered (depfile graph absent)");
            else
                ok = text_u64(out, cap, &used, "include_edges",
                              (uint64_t)snap->include_edge_count);
        } else if (ok) {
            ok = text_str(out, cap, &used, "include_edges", "unavailable");
        }
    } else if (ok) {
        ok = text_str(out, cap, &used, "indexed_c23_files", "unavailable") &&
            text_str(out, cap, &used, "indexed_registry_nodes",
                     "unavailable") &&
            text_str(out, cap, &used, "indexed_source_roots",
                     "unavailable") &&
            text_str(out, cap, &used, "include_edges", "unavailable");
    }

    if (ok && snap->corpus.inventory_present) {
        ok = text_u64(out, cap, &used, "capabilities",
                      snap->corpus.capabilities) &&
            text_u64(out, cap, &used, "symbols_exposed",
                     snap->corpus.symbols_exposed) &&
            text_u64(out, cap, &used, "symbols_test_reached",
                     snap->corpus.symbols_test_reached) &&
            text_u64(out, cap, &used, "duplicates",
                     snap->corpus.duplicates) &&
            text_u64(out, cap, &used, "untested_invariants",
                     snap->corpus.untested_invariants) &&
            text_str(out, cap, &used, "inventory", "present") &&
            text_str(out, cap, &used, "scope_agrees",
                     snap->corpus.scope_agrees ? "true" : "false");
        if (ok && !snap->corpus.scope_agrees)
            ok = text_str(out, cap, &used, "inventory_scope",
                          "STALE (run make docs-capability-inventory)");
    } else if (ok) {
        ok = text_str(out, cap, &used, "capabilities",
                      "unavailable (inventory absent)") &&
            text_str(out, cap, &used, "symbols_exposed", "unavailable") &&
            text_str(out, cap, &used, "symbols_test_reached",
                     "unavailable") &&
            text_str(out, cap, &used, "duplicates", "unavailable") &&
            text_str(out, cap, &used, "untested_invariants",
                     "unavailable") &&
            text_str(out, cap, &used, "inventory", "absent") &&
            text_str(out, cap, &used, "scope_agrees", "n/a");
    }

    if (ok && snap->growth_present) {
        const struct science_code_growth_history *g = &snap->growth;
        const struct science_code_growth_day *latest =
            g->day_count ? &g->days[g->day_count - 1u] : NULL;
        ok = text_str(out, cap, &used, "growth", "present") &&
            text_u64(out, cap, &used, "growth_days", g->day_count) &&
            text_u64(out, cap, &used, "growth_non_test_lines",
                     g->non_test_lines) &&
            text_u64(out, cap, &used, "growth_test_lines", g->test_lines);
        if (ok && latest) {
            ok = text_str(out, cap, &used, "growth_latest_date",
                          latest->date) &&
                text_str(out, cap, &used, "growth_latest_commit",
                         latest->head_commit) &&
                text_u64(out, cap, &used, "growth_latest_non_test_added",
                         latest->non_test_added) &&
                text_u64(out, cap, &used, "growth_latest_non_test_deleted",
                         latest->non_test_deleted) &&
                text_u64(out, cap, &used, "growth_latest_test_added",
                         latest->test_added) &&
                text_u64(out, cap, &used, "growth_latest_test_deleted",
                         latest->test_deleted);
        }
    } else if (ok) {
        ok = text_str(out, cap, &used, "growth", "unavailable") &&
            text_str(out, cap, &used, "growth_error",
                     snap->growth_error[0] ? snap->growth_error
                                           : "not collected");
    }

    if (!ok)
        return false;
    if (len)
        *len = used;
    return true;
}
