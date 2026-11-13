/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded provisional hot-swap facts from a source-qualified index. */
#include "command/native_command.h"
#include "codeindex/codeindex.h"
#include "base/hex.h"
#include "json/json.h"
#include "util/safe_alloc.h"
#include "../dev/hotswap_shape_policy.h"

#include "util/ere_match.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { HF_SYMBOLS = 128, HF_PATHS = 64, HF_ROWS = 64, HF_PAGE = 128,
       HF_TEXT = 24000, HF_OUTPUT = 60000 };
struct hf_state {
    struct codeindex *ci;
    struct json_value symbols, paths;
    struct zcl_ere shape, deny;
    char *text;
    size_t used;
    int census;
    uint8_t source_root[32], projection_root[32];
    char requested[HF_SYMBOLS + HF_PATHS][256];
    bool found[HF_SYMBOLS + HF_PATHS];
    size_t path_count;
};

static bool hf_ident_start(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_';
}

static bool hf_ident(const char *s)
{
    if (!s || !hf_ident_start(*s)) return false;
    size_t n = 0;
    for (; *s; s++, n++)
        if (n >= 127 || !(hf_ident_start(*s) || (*s >= '0' && *s <= '9'))) return false;
    return true;
}

static bool hf_text(struct hf_state *s, const char *a, const char *b, const char *c)
{
    int n = snprintf(s->text + s->used, HF_TEXT - s->used, "%s\t%s%s%s\n",
                     a, b, c ? "\t" : "", c ? c : "");
    if (n < 0 || (size_t)n >= HF_TEXT - s->used) return false;
    s->used += (size_t)n;
    return true;
}

static bool hf_safe_path(const char *p)
{
    if (!p || !*p) return false;
    for (; *p; p++)
        if ((unsigned char)*p < 32 || (unsigned char)*p == 127) return false;
    return true;
}

static bool hf_current(struct codeindex *ci)
{
    bool source = false, projection = false;
    return codeindex_source_view_is_current(ci, &source) && source &&
        codeindex_retrieval_projection_is_current(ci, &projection) && projection;
}

static bool hf_census_file(struct hf_state *s, const char *path)
{
    if (!hf_safe_path(path)) return false;
    for (size_t i = 0; i < s->path_count; i++)
        if (strcmp(s->requested[i], path) == 0) s->found[i] = true;
    if (!codeindex_path_is_translation_unit(path)) return true;
    bool denied = zcl_ere_search(&s->deny, path, strlen(path));
    bool allowed = zcl_ere_search(&s->shape, path, strlen(path));
    if (allowed && !denied) s->census++;
    return true;
}

static bool hf_census(struct hf_state *s)
{
    int total = codeindex_file_count(s->ci);
    if (total <= 0) return false;
    struct ci_file *rows = zcl_malloc(sizeof(*rows) * HF_PAGE, "hotswap facts files");
    if (!rows) return false;
    bool ok = true;
    for (int at = 0; at < total && ok;) {
        int want = total - at < HF_PAGE ? total - at : HF_PAGE;
        int n = codeindex_files_page(s->ci, at, rows, want);
        if (n != want) { ok = false; break; }
        for (int i = 0; i < n && ok; i++) ok = hf_census_file(s, rows[i].path);
        at += n;
    }
    if (ok && codeindex_files_page(s->ci, total, rows, 1) != 0) ok = false;
    free(rows);
    char count[32];
    int n = snprintf(count, sizeof count, "%d", s->census);
    return ok && s->census > 0 && n > 0 && (size_t)n < sizeof count &&
        hf_text(s, "census", count, NULL);
}

static const char *hf_resolve(struct hf_state *s, const char *name, char path[256])
{
    struct ci_symbol *rows = zcl_malloc(sizeof(*rows) * HF_ROWS, "hotswap facts symbols");
    if (!rows) return NULL;
    int n = 0;
    enum codeindex_exact_status status = codeindex_find_exact_checked(s->ci, name, rows, HF_ROWS, &n);
    const char *reason = "missing";
    int definitions = 0;
    if (status != CODEINDEX_EXACT_COMPLETE) reason = "incomplete_index";
    else for (int i = 0; i < n; i++) {
        if (rows[i].partial) { reason = "partial"; definitions = -1; break; }
        if ((rows[i].kind == 'T' || rows[i].kind == 't') && rows[i].def_path[0]) {
            if (!hf_safe_path(rows[i].def_path) || rows[i].def_line <= 0) {
                reason = "invalid_definition"; definitions = -1; break;
            }
            if (++definitions == 1) snprintf(path, 256, "%s", rows[i].def_path);
        }
    }
    if (status == CODEINDEX_EXACT_COMPLETE && definitions == 1) reason = "indexed_candidate";
    else if (definitions > 1) reason = "ambiguous";
    free(rows);
    return reason;
}

static bool hf_symbol(struct hf_state *s, const char *name)
{
    char path[256] = {0};
    const char *status = hf_resolve(s, name, path);
    if (!status) return false;
    bool candidate = strcmp(status, "indexed_candidate") == 0;
    struct json_value row = {0};
    json_set_object(&row);
    bool ok = json_push_kv_str(&row, "name", name) &&
        json_push_kv_str(&row, "status", candidate ? status : "unknown") &&
        json_push_kv_str(&row, candidate ? "path" : "reason", candidate ? path : status) &&
        json_push_back(&s->symbols, &row) &&
        hf_text(s, candidate ? "owner" : "unknown", name, candidate ? path : status);
    json_free(&row);
    return ok;
}

static bool hf_path_valid(const char *path)
{
    if (!hf_safe_path(path) || path[0] == '/' || strlen(path) >= 256) return false;
    const char *part = path;
    for (const char *p = path;; p++) {
        if (*p != '/' && *p != '\0') continue;
        size_t n = (size_t)(p - part);
        if (!n || (n == 1 && part[0] == '.') ||
            (n == 2 && part[0] == '.' && part[1] == '.')) return false;
        if (!*p) return true;
        part = p + 1;
    }
}

static bool hf_input_array(const struct json_value *input, const char *key,
                           size_t cap, bool (*valid)(const char *))
{
    const struct json_value *array = json_get(input, key);
    if (!array || array->type != JSON_ARR || json_size(array) > cap) return false;
    for (size_t i = 0; i < json_size(array); i++) {
        const struct json_value *v = json_at(array, i);
        if (!v || v->type != JSON_STR || !valid(json_get_str(v))) return false;
    }
    return true;
}

static bool hf_input_valid(const struct json_value *input)
{
    return input && input->type == JSON_OBJ &&
        hf_input_array(input, "symbols", HF_SYMBOLS, hf_ident) &&
        hf_input_array(input, "paths", HF_PATHS, hf_path_valid);
}

static bool hf_path(struct hf_state *s, const char *path)
{
    if (!hf_path_valid(path)) return false;
    for (size_t i = 0; i < s->path_count; i++)
        if (strcmp(s->requested[i], path) == 0) return true;
    if (s->path_count >= HF_SYMBOLS + HF_PATHS) return false;
    snprintf(s->requested[s->path_count++], 256, "%s", path);
    return true;
}

static bool hf_path_output(struct hf_state *s, size_t i)
{
    const char *path = s->requested[i];
    const char *kind = !s->found[i] ? "unknown" :
        zcl_ere_search(&s->deny, path, strlen(path)) ? "forbidden" :
        codeindex_path_is_translation_unit(path) && zcl_ere_search(&s->shape, path, strlen(path)) ? "allowed" : "other";
    struct json_value row = {0};
    json_set_object(&row);
    const char *text_kind = strcmp(kind, "unknown") == 0 ? "path_unknown" : kind;
    bool ok = json_push_kv_str(&row, "path", path) &&
        json_push_kv_str(&row, "classification", kind) &&
        json_push_back(&s->paths, &row) && hf_text(s, text_kind, path, NULL);
    json_free(&row);
    return ok;
}

static bool hf_paths_output(struct hf_state *s)
{
    for (size_t i = 0; i < s->path_count; i++)
        if (!hf_path_output(s, i)) return false;
    return true;
}

static bool hf_paths(struct hf_state *s, const struct json_value *input)
{
    const struct json_value *paths = json_get(input, "paths");
    if (!paths || paths->type != JSON_ARR || json_size(paths) > HF_PATHS) return false;
    for (size_t i = 0; i < json_size(paths); i++) {
        const struct json_value *v = json_at(paths, i);
        if (!v || v->type != JSON_STR || !hf_path(s, json_get_str(v))) return false;
    }
    for (size_t i = 0; i < json_size(&s->symbols); i++) {
        const struct json_value *row = json_at(&s->symbols, i);
        const char *path = json_get_str(json_get(row, "path"));
        if (path && path[0] && !hf_path(s, path)) return false;
    }
    return true;
}

static bool hf_symbol_seen(const struct json_value *array, size_t before,
                           const char *name)
{
    for (size_t i = 0; i < before; i++) {
        const struct json_value *v = json_at(array, i);
        if (v && v->type == JSON_STR && strcmp(json_get_str(v), name) == 0)
            return true;
    }
    return false;
}

static bool hf_symbols(struct hf_state *s, const struct json_value *input)
{
    const struct json_value *array = json_get(input, "symbols");
    if (!array || array->type != JSON_ARR || json_size(array) > HF_SYMBOLS) return false;
    for (size_t i = 0; i < json_size(array); i++) {
        const struct json_value *v = json_at(array, i);
        if (!v || v->type != JSON_STR || !hf_ident(json_get_str(v))) return false;
        const char *name = json_get_str(v);
        if (!hf_symbol_seen(array, i, name) && !hf_symbol(s, name)) return false;
    }
    return true;
}

static bool hf_output(struct hf_state *s, struct json_value *result, size_t budget)
{
    char source[65], projection[65];
    zcl_hex_encode(s->source_root, sizeof s->source_root, source);
    zcl_hex_encode(s->projection_root, sizeof s->projection_root, projection);
    if (!hf_text(s, "identity", source, projection)) return false;
    json_set_object(result);
    return json_push_kv_str(result, "schema", "zcl.code_hotswap_facts.v1") &&
        json_push_kv_str(result, "source_root_sha3", source) &&
        json_push_kv_str(result, "projection_root_sha3", projection) &&
        json_push_kv_str(result, "ownership_basis", "indexed_definitions") &&
        json_push_kv_str(result, "semantic_completeness", "unproven") &&
        json_push_kv(result, "symbols", &s->symbols) &&
        json_push_kv(result, "paths", &s->paths) &&
        json_push_kv_int(result, "census", s->census) &&
        json_push_kv_str(result, "text", s->text) &&
        json_write(result, NULL, 0) < budget;
}

static bool hf_observe(struct hf_state *s, const struct json_value *input,
                       struct json_value *result, size_t budget)
{
    uint8_t source_after[32], projection_after[32];
    if (!hf_current(s->ci) ||
        !codeindex_source_root_sha3(s->ci, s->source_root) ||
        !codeindex_retrieval_projection_root_sha3(s->ci, s->projection_root)) return false;
    if (!hf_symbols(s, input) || !hf_paths(s, input) || !hf_census(s) ||
        !hf_paths_output(s) ||
        !hf_output(s, result, budget) || !hf_current(s->ci)) return false;
    return codeindex_source_root_sha3(s->ci, source_after) &&
        codeindex_retrieval_projection_root_sha3(s->ci, projection_after) &&
        memcmp(s->source_root, source_after, 32) == 0 &&
        memcmp(s->projection_root, projection_after, 32) == 0;
}

void zcl_native_handle_code_hotswap_facts(const struct zcl_command_request *request,
                                           struct zcl_command_reply *reply)
{
    if (!request || !hf_input_valid(request->input)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_INVALID, "HOTSWAP_FACTS_INVALID_INPUT", "validate", false, false,
            "symbols and paths must be bounded arrays of valid identifiers and paths", "");
        return;
    }
    struct hf_state *s = zcl_calloc(1, sizeof(*s), "hotswap facts state");
    struct json_value result = {0};
    if (!s) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
            ZCL_COMMAND_EXIT_FAILED, "HOTSWAP_FACTS_UNAVAILABLE", "query", false, false,
            "could not allocate bounded indexed advisory facts", "");
        return;
    }
    json_set_array(&s->symbols); json_set_array(&s->paths);
    s->text = zcl_calloc(HF_TEXT, 1, "hotswap facts text");
    bool shape = zcl_ere_compile(&s->shape, ZCL_HOTSWAP_SHAPE_ALLOWED);
    bool deny = zcl_ere_compile(&s->deny, ZCL_HOTSWAP_SHAPE_FORBIDDEN);
    s->ci = codeindex_open_retrieval_view(zcl_native_source_root(request));
    size_t budget = request->success_data_budget_provided ? request->success_data_budget : HF_OUTPUT;
    if (budget > HF_OUTPUT) budget = HF_OUTPUT;
    bool ok = s->text && shape && deny && s->ci &&
        hf_observe(s, request->input, &result, budget);
    if (ok) {
        json_free(&reply->data);
        ok = json_copy_checked(&reply->data, &result);
    }
    if (!ok) zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_FAILED, "HOTSWAP_FACTS_UNAVAILABLE", "query", false, false,
        "could not produce complete bounded indexed advisory facts", "");
    json_free(&result); json_free(&s->symbols); json_free(&s->paths);
    if (s->ci) codeindex_close(s->ci);
    free(s->text);
    free(s);
}
