/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Derive origin lane heads, worktrees, and in-flight files for
 *          `z23 dev fleet` using Git as the only lane authority. */

#include "command/native_dev_fleet.h"
#include "command/native_dev_fleet_internal.h"

#include "base/safe_alloc.h"
#include "json/json.h"

#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLEET_CAPTURE_BYTES (1024u * 1024u)
#define FLEET_MAX_LANES 128u
#define FLEET_MAX_FILES 2048u

struct fleet_files {
    char **items;
    size_t count;
    size_t capacity;
};

struct fleet_lane {
    char branch[256];
    char remote[288];
    char ref[320];
    char head[ZCL_FLEET_OID_MAX];
    struct zcl_fleet_worktree worktree;
    struct fleet_files files;
};

static void fleet_reason(char *why, size_t cap, const char *format,
                         const char *detail)
{
    if (why && cap) (void)snprintf(why, cap, format, detail ? detail : "");
}

static bool fleet_oid(const char *text)
{
    size_t length = text ? strlen(text) : 0;
    if (length != 40 && length != 64) return false;
    for (size_t i = 0; i < length; i++)
        if (!isdigit((unsigned char)text[i]) &&
            !(text[i] >= 'a' && text[i] <= 'f')) return false;
    return true;
}

static bool fleet_run(const char *root, const char *const args[], char *capture,
                      char *why, size_t why_size)
{
    bool truncated = false;
    int rc = zcl_dev_fleet_git_capture(root, args, capture,
                                       FLEET_CAPTURE_BYTES, &truncated);
    if (rc != 0) {
        fleet_reason(why, why_size, "Git inventory command failed: %s", args[0]);
        return false;
    }
    if (truncated) {
        fleet_reason(why, why_size, "Git inventory exceeded its bound: %s",
                     args[0]);
        return false;
    }
    return true;
}

static int fleet_lane_compare(const void *left, const void *right)
{
    const struct fleet_lane *a = left, *b = right;
    if (strcmp(a->branch, "main") == 0)
        return strcmp(b->branch, "main") == 0 ? 0 : -1;
    if (strcmp(b->branch, "main") == 0) return 1;
    return strcmp(a->branch, b->branch);
}

static int fleet_string_compare(const void *left, const void *right)
{
    const char *const *a = left, *const *b = right;
    return strcmp(*a, *b);
}

static void fleet_files_free(struct fleet_files *files)
{
    for (size_t i = 0; i < files->count; i++) free(files->items[i]);
    free(files->items);
    memset(files, 0, sizeof(*files));
}

static bool fleet_files_add(struct fleet_files *files, const char *path)
{
    if (!path || !path[0]) return true;
    for (size_t i = 0; i < files->count; i++)
        if (strcmp(files->items[i], path) == 0) return true;
    if (files->count >= FLEET_MAX_FILES) return false;
    if (files->count == files->capacity) {
        size_t next = files->capacity ? files->capacity * 2u : 32u;
        if (next > FLEET_MAX_FILES) next = FLEET_MAX_FILES;
        char **grown = zcl_realloc(files->items, next * sizeof(*grown),
                                   "fleet_file_set");
        if (!grown) return false;
        files->items = grown;
        files->capacity = next;
    }
    char *copy = zcl_strdup(path, "fleet_file_path");
    if (!copy) return false;
    files->items[files->count++] = copy;
    return true;
}

static bool fleet_add_lines(struct fleet_files *files, char *capture)
{
    char *line = capture;
    while (*line) {
        char *end = strchr(line, '\n');
        if (end) *end = 0;
        size_t length = strlen(line);
        if (length && line[length - 1] == '\r') line[length - 1] = 0;
        if (!fleet_files_add(files, line)) return false;
        if (!end) break;
        line = end + 1;
    }
    return true;
}

static bool fleet_load_lanes(const char *root, char *capture,
                             struct fleet_lane **out, size_t *count,
                             char *why, size_t why_size)
{
    const char *args[] = {
        "for-each-ref", "--format=%(refname:short) %(objectname)",
        "refs/remotes/origin/main", "refs/remotes/origin/agent", NULL};
    if (!fleet_run(root, args, capture, why, why_size)) return false;
    struct fleet_lane *lanes = zcl_calloc(FLEET_MAX_LANES, sizeof(*lanes),
                                          "fleet_lanes");
    if (!lanes) { fleet_reason(why, why_size, "%s", "cannot allocate lanes"); return false; }
    char *line = capture;
    bool main_seen = false, ok = true;
    while (*line && ok) {
        char *end = strchr(line, '\n');
        if (end) *end = 0;
        char *space = strchr(line, ' ');
        if (!space) { ok = false; break; }
        *space++ = 0;
        size_t prefix = strlen("origin/agent/");
        const char *branch = NULL;
        if (strcmp(line, "origin/main") == 0) branch = "main";
        else if (strncmp(line, "origin/agent/", prefix) == 0 && line[prefix])
            branch = line + strlen("origin/");
        else { if (!end) break; line = end + 1; continue; }
        if (*count >= FLEET_MAX_LANES || !fleet_oid(space) ||
            strlen(branch) >= sizeof(lanes[0].branch)) { ok = false; break; }
        struct fleet_lane *lane = &lanes[(*count)++];
        (void)snprintf(lane->branch, sizeof(lane->branch), "%s", branch);
        (void)snprintf(lane->remote, sizeof(lane->remote), "origin/%s", branch);
        (void)snprintf(lane->ref, sizeof(lane->ref),
                       "refs/remotes/origin/%s", branch);
        (void)snprintf(lane->head, sizeof(lane->head), "%s", space);
        if (strcmp(branch, "main") == 0) main_seen = true;
        if (!end) break;
        line = end + 1;
    }
    if (!ok || !main_seen) {
        free(lanes);
        fleet_reason(why, why_size, "%s", !main_seen ?
                     "origin/main is missing from the local Git refs" :
                     "remote lane inventory is malformed or too large");
        return false;
    }
    qsort(lanes, *count, sizeof(*lanes), fleet_lane_compare);
    *out = lanes;
    return true;
}

static struct fleet_lane *fleet_lane_for_branch(struct fleet_lane lanes[],
                                                 size_t count,
                                                 const char *full_branch)
{
    const char *prefix = "refs/heads/";
    if (strncmp(full_branch, prefix, strlen(prefix)) != 0) return NULL;
    const char *branch = full_branch + strlen(prefix);
    for (size_t i = 0; i < count; i++)
        if (strcmp(lanes[i].branch, branch) == 0) return &lanes[i];
    return NULL;
}

static bool fleet_load_worktrees(const char *root, char *capture,
                                 struct fleet_lane lanes[], size_t count,
                                 char *why, size_t why_size)
{
    const char *args[] = {"worktree", "list", "--porcelain", NULL};
    if (!fleet_run(root, args, capture, why, why_size)) return false;
    char path[ZCL_FLEET_PATH_MAX] = "", head[ZCL_FLEET_OID_MAX] = "";
    char *line = capture;
    while (true) {
        char *end = strchr(line, '\n');
        if (end) *end = 0;
        if (strncmp(line, "worktree ", 9) == 0)
            (void)snprintf(path, sizeof(path), "%s", line + 9);
        else if (strncmp(line, "HEAD ", 5) == 0)
            (void)snprintf(head, sizeof(head), "%s", line + 5);
        else if (strncmp(line, "branch ", 7) == 0) {
            struct fleet_lane *lane = fleet_lane_for_branch(lanes, count,
                                                             line + 7);
            if (lane) {
                if (lane->worktree.present || !path[0] || !fleet_oid(head)) {
                    fleet_reason(why, why_size,
                                 "ambiguous or malformed worktree for %s",
                                 lane->branch);
                    return false;
                }
                lane->worktree.present = true;
                (void)snprintf(lane->worktree.path,
                               sizeof(lane->worktree.path), "%s", path);
                (void)snprintf(lane->worktree.head,
                               sizeof(lane->worktree.head), "%s", head);
                (void)snprintf(lane->worktree.branch,
                               sizeof(lane->worktree.branch), "%s",
                               lane->branch);
            }
        }
        if (!end) break;
        line = end + 1;
        if (!*line) break;
        if (*line == '\n') { path[0] = 0; head[0] = 0; }
    }
    return true;
}

static bool fleet_lane_files(const char *root, struct fleet_lane *lane,
                             char *capture, char *why, size_t why_size)
{
    const char *remote_args[] = {"diff", "--name-only", "--diff-filter=ACMRD",
                                 "origin/main...", NULL};
    char range[640];
    if (snprintf(range, sizeof(range), "origin/main...%s", lane->remote) >=
        (int)sizeof(range)) return false;
    remote_args[3] = range;
    if (strcmp(lane->branch, "main") != 0) {
        if (!fleet_run(root, remote_args, capture, why, why_size) ||
            !fleet_add_lines(&lane->files, capture))
            return false;
    }
    if (!lane->worktree.present) return true;
    char local_range[640];
    if (snprintf(local_range, sizeof(local_range), "%s..HEAD", lane->remote) >=
        (int)sizeof(local_range)) return false;
    const char *local_args[] = {"diff", "--name-only", "--diff-filter=ACMRD",
                                local_range, NULL};
    if (!fleet_run(lane->worktree.path, local_args, capture, why, why_size) ||
        !fleet_add_lines(&lane->files, capture))
        return false;
    const char *const dirty_args[][6] = {
        {"diff", "--name-only", "--diff-filter=ACMRD", NULL},
        {"diff", "--cached", "--name-only", "--diff-filter=ACMRD", NULL},
        {"ls-files", "--others", "--exclude-standard", NULL},
    };
    for (size_t i = 0; i < 3; i++) {
        if (!fleet_run(lane->worktree.path, dirty_args[i], capture, why,
                       why_size) ||
            !fleet_add_lines(&lane->files, capture))
            return false;
    }
    if (lane->files.count > 1)
        qsort(lane->files.items, lane->files.count,
              sizeof(*lane->files.items), fleet_string_compare);
    return true;
}

static bool fleet_files_json(const struct fleet_files *files,
                             struct json_value *out)
{
    json_set_array(out);
    for (size_t i = 0; i < files->count; i++) {
        struct json_value item;
        json_init(&item); json_set_str(&item, files->items[i]);
        bool ok = json_push_back(out, &item);
        json_free(&item);
        if (!ok) return false;
    }
    return true;
}

static bool fleet_lane_json(struct fleet_lane *lane, struct json_value *out,
                            size_t *owner_red, char *why, size_t why_size)
{
    json_set_object(out);
    struct json_value files;
    json_init(&files);
    if (!fleet_files_json(&lane->files, &files)) {
        json_free(&files); fleet_reason(why, why_size, "%s", "cannot allocate file list");
        return false;
    }
    bool ok = json_push_kv_str(out, "branch", lane->branch) &&
              json_push_kv_str(out, "remote_ref", lane->ref) &&
              json_push_kv_str(out, "head", lane->head) &&
              json_push_kv_bool(out, "worktree_present", lane->worktree.present) &&
              json_push_kv_str(out, "worktree_path", lane->worktree.present ?
                               lane->worktree.path : "") &&
              json_push_kv_str(out, "local_head", lane->worktree.present ?
                               lane->worktree.head : "") &&
              json_push_kv(out, "in_flight_files", &files) &&
              json_push_kv_int(out, "in_flight_file_count",
                               (int64_t)lane->files.count);
    json_free(&files);
    if (ok) ok = zcl_dev_fleet_receipts_json(&lane->worktree, out, owner_red,
                                              why, why_size);
    if (!ok && (!why || !why[0]))
        fleet_reason(why, why_size, "%s", "cannot allocate lane projection");
    return ok;
}

bool zcl_dev_fleet_collect(const char *checkout_root, struct json_value *out,
                           char *why, size_t why_size)
{
    if (why && why_size) why[0] = 0;
    if (!checkout_root || !out) {
        fleet_reason(why, why_size, "%s", "fleet collector needs a checkout root");
        return false;
    }
    char *capture = zcl_malloc(FLEET_CAPTURE_BYTES, "fleet_git_capture");
    if (!capture) {
        fleet_reason(why, why_size, "%s", "cannot allocate Git capture buffer");
        return false;
    }
    struct fleet_lane *lanes = NULL;
    size_t count = 0;
    bool ok = fleet_load_lanes(checkout_root, capture, &lanes, &count, why,
                               why_size) &&
              fleet_load_worktrees(checkout_root, capture, lanes, count, why,
                                   why_size);
    for (size_t i = 0; ok && i < count; i++)
        ok = fleet_lane_files(checkout_root, &lanes[i], capture, why, why_size);
    struct json_value rows;
    json_init(&rows); json_set_array(&rows);
    size_t owner_total = 0;
    for (size_t i = 0; ok && i < count; i++) {
        struct json_value row;
        json_init(&row);
        size_t owner = 0;
        ok = fleet_lane_json(&lanes[i], &row, &owner, why, why_size) &&
             json_push_back(&rows, &row);
        owner_total += owner;
        json_free(&row);
    }
    if (ok) {
        json_set_object(out);
        ok = json_push_kv_str(out, "schema", "zcl.dev_fleet.v1") &&
             json_push_kv_str(out, "source", "git_and_lint_receipts_only") &&
             json_push_kv_bool(out, "live_node_read", false) &&
             json_push_kv_str(out, "remote", "origin") &&
             json_push_kv_str(out, "main_head", lanes[0].head) &&
             json_push_kv_int(out, "lane_count", (int64_t)count) &&
             json_push_kv(out, "lanes", &rows) &&
             json_push_kv_int(out, "owner_only_red_gate_count",
                              (int64_t)owner_total) &&
             json_push_kv_bool(out, "inventory_complete", true);
    }
    for (size_t i = 0; i < count; i++) fleet_files_free(&lanes[i].files);
    free(lanes); free(capture); json_free(&rows);
    if (!ok && (!why || !why[0]))
        fleet_reason(why, why_size, "%s", "cannot build fleet projection");
    return ok;
}
