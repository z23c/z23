/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: exact ZVCS-backed native code-change instrument. */

#include "command/native_command.h"

#include "base/hex.h"
#include "controllers/agent_impact_rules.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "presentation/model.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NPC_LEAF "app.presentation.code-change"
#define NPC_SOURCE_MAX (256u * 1024u)
#define NPC_LINE_MAX 8192u
#define NPC_DIFF_SIDE_MAX 8u
#define NPC_INCLUDE_MAX 8u

struct npc_line {
    const uint8_t *bytes;
    size_t len;
};

static void npc_fail(struct zcl_command_reply *reply, const char *code,
                     const char *message)
{
    LOG_ERROR("native.presentation.code_change", "%s: %s", code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, code, "verify", false, false, message,
        NPC_LEAF);
}

static const char *npc_str(const struct json_value *input, const char *key)
{
    const struct json_value *value = input ? json_get(input, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool npc_source_path(const char *path)
{
    if (!path || !path[0] || path[0] == '/' || strstr(path, ".."))
        return false;
    size_t len = strlen(path);
    return len > 2u && len <= 255u &&
           (strcmp(path + len - 2u, ".c") == 0 ||
            strcmp(path + len - 2u, ".h") == 0);
}

static const struct vcs_entry *npc_entry(const struct vcs_manifest *manifest,
                                         const char *path)
{
    size_t lo = 0, hi = manifest ? manifest->count : 0;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = strcmp(manifest->entries[mid].path, path);
        if (cmp < 0) lo = mid + 1u;
        else hi = mid;
    }
    return manifest && lo < manifest->count &&
           strcmp(manifest->entries[lo].path, path) == 0
        ? &manifest->entries[lo] : NULL;
}

static void npc_item(struct zcl_present_model_v1 *model, uint16_t kind,
                     uint16_t status, const char *id, const char *label,
                     const char *value)
{
    if (model->item_count >= ZCL_PRESENT_MODEL_ITEMS_MAX) return;
    struct zcl_present_model_item_v1 *item =
        &model->items[model->item_count++];
    item->kind = kind;
    item->status = status;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    (void)snprintf(item->id, sizeof(item->id), "%s", id);
    (void)snprintf(item->label, sizeof(item->label), "%s", label);
    (void)snprintf(item->value, sizeof(item->value), "%s", value);
}

static bool npc_lines(const uint8_t *bytes, size_t len,
                      struct npc_line **out, size_t *count,
                      char *why, size_t why_cap)
{
    *out = NULL;
    *count = 0;
    if ((!bytes && len) || len > NPC_SOURCE_MAX || memchr(bytes, '\0', len)) {
        (void)snprintf(why, why_cap,
                       "source must be bounded NUL-free C text");
        return false;
    }
    size_t n = len ? 1u : 0u;
    for (size_t i = 0; i < len; i++)
        if (bytes[i] == '\n' && i + 1u < len) n++;
    if (n > NPC_LINE_MAX) {
        (void)snprintf(why, why_cap, "source exceeds the 8192-line bound");
        return false;
    }
    if (n == 0) return true;
    struct npc_line *lines = zcl_malloc(n * sizeof(*lines),
                                        "presentation.code_change.lines");
    if (!lines) {
        (void)snprintf(why, why_cap, "could not allocate bounded line view");
        return false;
    }
    size_t start = 0, used = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i != len && bytes[i] != '\n') continue;
        if (i == len && start == len) break;
        size_t line_len = i - start;
        if (line_len && bytes[start + line_len - 1u] == '\r') line_len--;
        lines[used++] = (struct npc_line){bytes + start, line_len};
        start = i + 1u;
    }
    *out = lines;
    *count = used;
    return true;
}

static bool npc_line_equal(const struct npc_line *a, const struct npc_line *b)
{
    return a->len == b->len && memcmp(a->bytes, b->bytes, a->len) == 0;
}

static void npc_line_text(const struct npc_line *line, char out[220])
{
    size_t used = 0;
    for (size_t i = 0; i < line->len && used + 1u < 220u; i++) {
        unsigned char ch = line->bytes[i];
        if (ch == '\t') ch = ' ';
        out[used++] = isprint(ch) ? (char)ch : '?';
    }
    if (used + 3u < 220u && used < line->len) {
        out[used++] = '.'; out[used++] = '.'; out[used++] = '.';
    }
    out[used] = '\0';
}

static void npc_diff_line(struct zcl_present_model_v1 *model, uint16_t kind,
                          const char *id_prefix, size_t number,
                          const struct npc_line *line)
{
    char id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
    char label[ZCL_PRESENT_MODEL_LABEL_MAX + 1u];
    char text[220];
    npc_line_text(line, text);
    (void)snprintf(id, sizeof(id), "%s-%zu", id_prefix, number);
    (void)snprintf(label, sizeof(label), "%s line %zu",
                   kind == ZCL_PRESENT_ITEM_DIFF_ADD ? "AFTER" :
                   kind == ZCL_PRESENT_ITEM_DIFF_REMOVE ? "BEFORE" :
                   "CONTEXT", number);
    npc_item(model, kind,
             kind == ZCL_PRESENT_ITEM_DIFF_ADD ? ZCL_PRESENT_STATUS_GREEN :
             kind == ZCL_PRESENT_ITEM_DIFF_REMOVE ? ZCL_PRESENT_STATUS_RED :
                                                    ZCL_PRESENT_STATUS_NEUTRAL,
             id, label, text);
}

static void npc_omitted(struct zcl_present_model_v1 *model,
                        const char *id, size_t count, const char *side)
{
    if (!count) return;
    char text[96];
    (void)snprintf(text, sizeof(text), "%zu %s line(s) omitted", count, side);
    npc_item(model, ZCL_PRESENT_ITEM_DIFF_CONTEXT,
             ZCL_PRESENT_STATUS_YELLOW, id, "BOUNDED DIFF", text);
}

static bool npc_word(const uint8_t *bytes, size_t len, size_t *at,
                     const char *word)
{
    size_t n = strlen(word);
    if (*at + n > len || memcmp(bytes + *at, word, n) != 0) return false;
    *at += n;
    return true;
}

static size_t npc_includes(const uint8_t *bytes, size_t len,
                           char values[NPC_INCLUDE_MAX][128],
                           size_t *total)
{
    size_t shown = 0;
    *total = 0;
    size_t start = 0;
    while (start < len) {
        size_t end = start;
        while (end < len && bytes[end] != '\n') end++;
        size_t at = start;
        while (at < end && isspace(bytes[at])) at++;
        if (at < end && bytes[at] == '#') {
            at++;
            while (at < end && isspace(bytes[at])) at++;
            if (npc_word(bytes, end, &at, "include") &&
                (at == end || isspace(bytes[at]) || bytes[at] == '"' ||
                 bytes[at] == '<')) {
                while (at < end && isspace(bytes[at])) at++;
                uint8_t close = at < end && bytes[at] == '"' ? '"' : '>';
                if (at < end && (bytes[at] == '"' || bytes[at] == '<')) {
                    size_t value_start = ++at;
                    while (at < end && bytes[at] != close) at++;
                    if (at < end && at > value_start) {
                        (*total)++;
                        if (shown < NPC_INCLUDE_MAX) {
                            size_t n = at - value_start;
                            if (n >= 128u) n = 127u;
                            memcpy(values[shown], bytes + value_start, n);
                            values[shown][n] = '\0';
                            shown++;
                        }
                    }
                }
            }
        }
        start = end + (end < len ? 1u : 0u);
    }
    return shown;
}

static void npc_tests_value(const char *path, char out[257])
{
    struct agent_impact_acc impact = {0};
    bool risk = false;
    const char *route = zcl_native_code_route_for_path(path, &impact, &risk);
    size_t used = 0;
    for (size_t i = 0; i < impact.groups_len; i++) {
        int wrote = snprintf(out + used, 257u - used, "%s%s",
                             used ? ", " : "", impact.groups[i]);
        if (wrote < 0 || (size_t)wrote >= 257u - used) break;
        used += (size_t)wrote;
    }
    bool route_seen = false;
    for (size_t i = 0; i < impact.groups_len; i++)
        if (strcmp(route, impact.groups[i]) == 0) route_seen = true;
    if (!route_seen && used < 256u)
        (void)snprintf(out + used, 257u - used, "%s%s",
                       used ? ", " : "", route);
    if (risk) {
        size_t now = strlen(out);
        if (now < 256u) (void)snprintf(out + now, 257u - now, " [consensus]");
    }
}

bool zcl_native_presentation_code_change_model_from_facts(
    const uint8_t *before, size_t before_len,
    const uint8_t *after, size_t after_len, const char *path,
    const char *requested, const char *before_behavior,
    const char *after_behavior, const char *before_blob_hex,
    const char *candidate_blob_hex, const char *candidate_root_hex,
    struct zcl_present_model_v1 *model, char *why, size_t why_cap)
{
    if (!model || !npc_source_path(path) || !requested || !before_behavior ||
        !after_behavior || !before_blob_hex || !candidate_blob_hex ||
        !candidate_root_hex || strlen(requested) > 256u ||
        strlen(before_behavior) > 256u || strlen(after_behavior) > 256u ||
        strlen(before_blob_hex) != 64u || strlen(candidate_blob_hex) != 64u ||
        strlen(candidate_root_hex) != 64u) {
        (void)snprintf(why, why_cap, "code-change facts are missing or unbounded");
        return false;
    }
    uint8_t root_check[32];
    if (!zcl_hex_decode_lower(before_blob_hex, root_check, 32) ||
        !zcl_hex_decode_lower(candidate_blob_hex, root_check, 32) ||
        !zcl_hex_decode_lower(candidate_root_hex, root_check, 32)) {
        (void)snprintf(why, why_cap, "roots must be lowercase 32-byte hex");
        return false;
    }
    struct npc_line *old_lines = NULL, *new_lines = NULL;
    size_t old_count = 0, new_count = 0;
    if (!npc_lines(before, before_len, &old_lines, &old_count, why, why_cap) ||
        !npc_lines(after, after_len, &new_lines, &new_count, why, why_cap)) {
        free(old_lines); free(new_lines);
        return false;
    }
    size_t prefix = 0;
    while (prefix < old_count && prefix < new_count &&
           npc_line_equal(&old_lines[prefix], &new_lines[prefix])) prefix++;
    size_t suffix = 0;
    while (suffix < old_count - prefix && suffix < new_count - prefix &&
           npc_line_equal(&old_lines[old_count - suffix - 1u],
                          &new_lines[new_count - suffix - 1u])) suffix++;
    size_t removed = old_count - prefix - suffix;
    size_t added = new_count - prefix - suffix;
    if (removed == 0 && added == 0) {
        free(old_lines); free(new_lines);
        (void)snprintf(why, why_cap, "selected path has no byte change");
        return false;
    }

    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_CODE_DIFF);
    (void)snprintf(model->request_id, sizeof(model->request_id),
                   "code-%.12s", candidate_root_hex);
    (void)snprintf(model->title, sizeof(model->title), "Exact code change");
    (void)snprintf(model->summary, sizeof(model->summary),
                   "Exact ZVCS C bytes and local routes; behavior prose is agent-supplied context.");
    (void)snprintf(model->exact_root, sizeof(model->exact_root), "%s",
                   candidate_root_hex);
    npc_item(model, ZCL_PRESENT_ITEM_TEXT, ZCL_PRESENT_STATUS_INFO,
             "requested", "AGENT SUMMARY - Requested behavior", requested);
    npc_item(model, ZCL_PRESENT_ITEM_TEXT, ZCL_PRESENT_STATUS_NEUTRAL,
             "before-behavior", "AGENT SUMMARY - Before behavior",
             before_behavior);
    npc_item(model, ZCL_PRESENT_ITEM_TEXT, ZCL_PRESENT_STATUS_INFO,
             "after-behavior", "AGENT SUMMARY - After behavior", after_behavior);
    npc_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_GREEN,
             "source-path", "LOCAL OBSERVATION - C path", path);
    npc_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_NEUTRAL,
             "before-blob", "LOCAL OBSERVATION - Before blob", before_blob_hex);
    npc_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_GREEN,
             "candidate-blob", "LOCAL OBSERVATION - Candidate blob",
             candidate_blob_hex);
    npc_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_GREEN,
             "candidate-root", "LOCAL OBSERVATION - Candidate tree",
             candidate_root_hex);
    char value[257] = {0};
    npc_tests_value(path, value);
    npc_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_INFO,
             "tests", "LOCAL OBSERVATION - Affected tests", value);

    char includes[NPC_INCLUDE_MAX][128];
    size_t include_total = 0;
    size_t include_shown = npc_includes(after, after_len, includes,
                                        &include_total);
    value[0] = '\0';
    size_t used = 0;
    for (size_t i = 0; i < include_shown; i++) {
        int wrote = snprintf(value + used, sizeof(value) - used, "%s%s",
                             used ? ", " : "", includes[i]);
        if (wrote < 0 || (size_t)wrote >= sizeof(value) - used) break;
        used += (size_t)wrote;
    }
    if (include_total > include_shown && used < sizeof(value) - 1u)
        (void)snprintf(value + used, sizeof(value) - used, " +%zu more",
                       include_total - include_shown);
    if (include_total == 0) (void)snprintf(value, sizeof(value), "none");
    npc_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_INFO,
             "dependencies", "LOCAL OBSERVATION - Candidate includes", value);
    (void)snprintf(value, sizeof(value),
                   "%zu before bytes -> %zu candidate bytes; %zu removed / %zu added lines",
                   before_len, after_len, removed, added);
    npc_item(model, ZCL_PRESENT_ITEM_KEY_VALUE, ZCL_PRESENT_STATUS_INFO,
             "observation", "LOCAL OBSERVATION - Changed span", value);

    if (prefix)
        npc_diff_line(model, ZCL_PRESENT_ITEM_DIFF_CONTEXT, "ctx-before",
                      prefix, &old_lines[prefix - 1u]);
    size_t remove_show = removed < NPC_DIFF_SIDE_MAX ? removed : NPC_DIFF_SIDE_MAX;
    for (size_t i = 0; i < remove_show; i++)
        npc_diff_line(model, ZCL_PRESENT_ITEM_DIFF_REMOVE, "remove",
                      prefix + i + 1u, &old_lines[prefix + i]);
    npc_omitted(model, "remove-more", removed - remove_show, "removed");
    size_t add_show = added < NPC_DIFF_SIDE_MAX ? added : NPC_DIFF_SIDE_MAX;
    for (size_t i = 0; i < add_show; i++)
        npc_diff_line(model, ZCL_PRESENT_ITEM_DIFF_ADD, "add",
                      prefix + i + 1u, &new_lines[prefix + i]);
    npc_omitted(model, "add-more", added - add_show, "added");
    if (suffix)
        npc_diff_line(model, ZCL_PRESENT_ITEM_DIFF_CONTEXT, "ctx-after",
                      new_count - suffix + 1u, &new_lines[new_count - suffix]);
    free(old_lines); free(new_lines);
    return zcl_present_model_validate_v1(model, why, why_cap);
}

void zcl_native_handle_presentation_code_change(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const char *workspace_arg = npc_str(request->input, "workspace");
    const char *before_root_hex = npc_str(request->input, "before_root");
    const char *candidate_root_hex = npc_str(request->input, "candidate_root");
    const char *path = npc_str(request->input, "path");
    const char *requested = npc_str(request->input, "requested_behavior");
    const char *before_behavior = npc_str(request->input, "before_behavior");
    const char *after_behavior = npc_str(request->input, "after_behavior");
    char workspace[PATH_MAX];
    uint8_t before_root[32], candidate_root[32];
    if (!workspace_arg ||
        !platform_directory_canonical_real(workspace_arg, workspace,
                                           sizeof(workspace)) ||
        !before_root_hex || !candidate_root_hex ||
        !zcl_hex_decode_lower(before_root_hex, before_root, 32) ||
        !zcl_hex_decode_lower(candidate_root_hex, candidate_root, 32) ||
        !npc_source_path(path) || !requested || !before_behavior ||
        !after_behavior) {
        npc_fail(reply, "BAD_CODE_CHANGE_INPUT",
                 "workspace, two lowercase ZVCS roots, one C path, and three bounded behavior summaries are required");
        return;
    }
    struct vcs_manifest before_manifest, candidate_manifest;
    if (!vcs_tree_load(workspace, before_root, &before_manifest)) {
        npc_fail(reply, "BEFORE_ROOT_UNVERIFIED",
                 "before_root did not rederive from the local ZVCS CAS");
        return;
    }
    if (!vcs_tree_load(workspace, candidate_root, &candidate_manifest)) {
        vcs_manifest_free(&before_manifest);
        npc_fail(reply, "CANDIDATE_ROOT_UNVERIFIED",
                 "candidate_root did not rederive from the local ZVCS CAS");
        return;
    }
    const struct vcs_entry *before_entry = npc_entry(&before_manifest, path);
    const struct vcs_entry *candidate_entry = npc_entry(&candidate_manifest, path);
    if (!before_entry || !candidate_entry || before_entry->size > NPC_SOURCE_MAX ||
        candidate_entry->size > NPC_SOURCE_MAX) {
        vcs_manifest_free(&before_manifest);
        vcs_manifest_free(&candidate_manifest);
        npc_fail(reply, "CODE_PATH_UNVERIFIED",
                 "the bounded C path must exist in both exact source trees");
        return;
    }
    uint8_t before_blob_root[32], candidate_blob_root[32];
    memcpy(before_blob_root, before_entry->blob, 32);
    memcpy(candidate_blob_root, candidate_entry->blob, 32);
    size_t expected_before_len = (size_t)before_entry->size;
    size_t expected_candidate_len = (size_t)candidate_entry->size;
    vcs_manifest_free(&before_manifest);
    vcs_manifest_free(&candidate_manifest);
    uint8_t *before_bytes = NULL, *candidate_bytes = NULL;
    size_t before_len = 0, candidate_len = 0;
    if (vcs_object_get(workspace, before_blob_root, VCS_TAG_BLOB,
                       &before_bytes, &before_len) != 0 ||
        before_len != expected_before_len ||
        vcs_object_get(workspace, candidate_blob_root, VCS_TAG_BLOB,
                       &candidate_bytes, &candidate_len) != 0 ||
        candidate_len != expected_candidate_len) {
        free(before_bytes); free(candidate_bytes);
        npc_fail(reply, "CODE_BLOB_UNVERIFIED",
                 "one source blob failed its exact ZVCS address or size check");
        return;
    }
    char before_blob_hex[65], candidate_blob_hex[65];
    zcl_hex_encode(before_blob_root, 32, before_blob_hex);
    zcl_hex_encode(candidate_blob_root, 32, candidate_blob_hex);
    struct zcl_present_model_v1 model;
    char why[192];
    bool built = zcl_native_presentation_code_change_model_from_facts(
        before_bytes, before_len, candidate_bytes, candidate_len, path,
        requested, before_behavior, after_behavior, before_blob_hex,
        candidate_blob_hex, candidate_root_hex, &model, why, sizeof(why));
    free(before_bytes); free(candidate_bytes);
    if (!built) {
        npc_fail(reply, "CODE_CHANGE_MODEL_INVALID", why);
        return;
    }
    zcl_native_present_model(&model, NPC_LEAF, request->input, reply);
    if (reply->status == ZCL_COMMAND_STATUS_PASSED) {
        (void)json_push_kv_str(&reply->data, "fact_authority", "local_zvcs_cas");
        (void)json_push_kv_str(&reply->data, "summary_authority", "agent");
        (void)json_push_kv_str(&reply->data, "claim_class", "LOCAL_OBSERVATION");
        (void)json_push_kv_str(&reply->data, "before_root", before_root_hex);
        (void)json_push_kv_str(&reply->data, "candidate_root", candidate_root_hex);
        (void)json_push_kv_str(&reply->data, "path", path);
    }
}
