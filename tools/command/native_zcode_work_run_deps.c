/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: locked-dependency reuse context and candidate metadata composition
 * for the native `zcode work run` command — split out of
 * native_zcode_work_run_command.c so each function stays under the
 * cyclomatic-complexity cap; sibling declarations live in
 * native_zcode_work_run_priv.h. */

#include "command/native_command.h"
#include "native_zcode_work_run_priv.h"

#include "base/hex.h"
#include "json/json.h"
#include "platform/directory_transaction.h"
#include "sha3/sha3.h"
#include "services/package_lifecycle.h"
#include "util/safe_alloc.h"
#include "vcs/vcs_object.h"
#include "vcs/package_deps.h"
#include "vcs/package_recipe.h"
#include "vcs/package_reuse.h"
#include "vcs/zcode_agent_context.h"
#include "vcs/zcode_dev.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <process.h>
#endif
#include <sys/stat.h>
#include <unistd.h>

struct run_dependency_candidate {
    struct vcs_package_index_entry package;
    struct vcs_package_reuse_input reuse;
    char api_text[VCS_PACKAGE_REUSE_MAX_APIS][ZWORK_DEPENDENCY_API_MAX];
    struct vcs_package_build_receipt receipt;
};

static bool run_output_is_header(const char *path)
{
    size_t len = path ? strlen(path) : 0;
    return len > 10u && strncmp(path, "include/", 8) == 0 &&
           strcmp(path + len - 2u, ".h") == 0;
}

static bool run_dependency_api_add(struct run_dependency_candidate *candidate,
                                   const char *api, size_t len)
{
    if (!candidate || !api || len == 0 ||
        len >= ZWORK_DEPENDENCY_API_MAX ||
        candidate->reuse.api_count >= VCS_PACKAGE_REUSE_MAX_APIS)
        return false;
    for (size_t i = 0; i < candidate->reuse.api_count; i++)
        if (strlen(candidate->api_text[i]) == len &&
            memcmp(candidate->api_text[i], api, len) == 0)
            return true;
    size_t at = candidate->reuse.api_count++;
    memcpy(candidate->api_text[at], api, len);
    candidate->api_text[at][len] = '\0';
    candidate->reuse.apis[at] = candidate->api_text[at];
    return true;
}

/* run_symbol_span/byte helpers: each significance test (whitespace byte,
 * identifier byte) is its own tiny predicate so the caller's loop reads the
 * bounds it walked rather than repeating the boolean run. */
static bool run_space_byte(uint8_t c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static bool run_ident_byte(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
           (c >= '0' && c <= '9') || c == '_';
}

static bool run_symbol_span(
    const uint8_t *bytes, size_t before_paren,
    size_t *start_out, size_t *end_out)
{
    size_t end = before_paren;
    while (end > 0 && run_space_byte(bytes[end - 1u])) end--;
    size_t start = end;
    while (start > 0 && run_ident_byte(bytes[start - 1u])) start--;
    if (start == end || (bytes[start] >= '0' && bytes[start] <= '9'))
        return false;
    *start_out = start;
    *end_out = end;
    return true;
}

static bool run_symbol_is_keyword(const uint8_t *bytes, size_t start,
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

static void run_dependency_header_symbols(
    struct run_dependency_candidate *candidate,
    const uint8_t *bytes, size_t len)
{
    for (size_t i = 0; i < len &&
         candidate->reuse.api_count < VCS_PACKAGE_REUSE_MAX_APIS; i++) {
        if (bytes[i] != '(') continue;
        size_t start, end;
        if (!run_symbol_span(bytes, i, &start, &end)) continue;
        if (!run_symbol_is_keyword(bytes, start, end))
            (void)run_dependency_api_add(
                candidate, (const char *)bytes + start, end - start);
    }
}

static bool run_ascii_contains_ci(const char *haystack, const char *needle)
{
    size_t haystack_len = haystack ? strlen(haystack) : 0;
    size_t needle_len = needle ? strlen(needle) : 0;
    if (needle_len == 0 || needle_len > haystack_len) return false;
    for (size_t i = 0; i + needle_len <= haystack_len; i++) {
        bool equal = true;
        for (size_t j = 0; j < needle_len; j++) {
            unsigned char left = (unsigned char)haystack[i + j];
            unsigned char right = (unsigned char)needle[j];
            if (tolower(left) != tolower(right)) {
                equal = false;
                break;
            }
        }
        if (equal) return true;
    }
    return false;
}

static bool run_dependency_header_relevant(
    const char *goal, const char *path, const uint8_t *bytes, size_t len)
{
    const char *base = path ? strrchr(path, '/') : NULL;
    base = base ? base + 1u : path;
    size_t base_len = base ? strlen(base) : 0;
    if (base_len > 2u && strcmp(base + base_len - 2u, ".h") == 0) {
        char stem[VCS_PACKAGE_BUILD_PATH_MAX + 1u];
        size_t stem_len = base_len - 2u;
        if (stem_len < sizeof(stem)) {
            memcpy(stem, base, stem_len);
            stem[stem_len] = '\0';
            if (run_ascii_contains_ci(goal, stem)) return true;
        }
    }
    struct run_dependency_candidate symbols = {0};
    run_dependency_header_symbols(&symbols, bytes, len);
    for (size_t i = 0; i < symbols.reuse.api_count; i++)
        if (run_ascii_contains_ci(goal, symbols.reuse.apis[i])) return true;
    return false;
}

#if defined(_WIN32)
static bool run_read_dependency_header_win32(
    const char *path, uint64_t expect_bytes, uint8_t **bytes_out,
    size_t *len_out)
{
    uint8_t *bytes = zcl_malloc((size_t)expect_bytes + 1u,
                                "zcode.work.locked_header");
    size_t off = 0;
    bool ok = bytes && run_stable_read(path, bytes, (size_t)expect_bytes,
                                       &off, true) && off == expect_bytes;
    if (!ok) {
        free(bytes);
        return false;
    }
    *bytes_out = bytes;
    *len_out = off;
    return true;
}
#else
static bool run_read_dependency_header_posix(
    const char *path, uint64_t expect_bytes, uint8_t **bytes_out,
    size_t *len_out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        (uint64_t)st.st_size == expect_bytes;
    uint8_t *bytes = ok
        ? zcl_malloc((size_t)expect_bytes + 1u, "zcode.work.locked_header")
        : NULL;
    ok = ok && bytes;
    size_t off = 0;
    while (ok && off < (size_t)expect_bytes) {
        ssize_t got = read(fd, bytes + off, (size_t)expect_bytes - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) ok = false;
        else off += (size_t)got;
    }
    if (close(fd) != 0) ok = false;
    if (!ok) {
        free(bytes);
        return false;
    }
    *bytes_out = bytes;
    *len_out = off;
    return true;
}
#endif

static bool run_read_dependency_header(
    const char *datadir, const char root_hex[65],
    const struct vcs_package_build_output *output,
    uint8_t **bytes_out, size_t *len_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    if (!datadir || !datadir[0] || !run_output_is_header(output->path) ||
        output->bytes == 0 || output->bytes > ZWORK_DEPENDENCY_HEADER_MAX)
        return false;
    char path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/zcode/installed/%s/%s",
                     datadir, root_hex, output->path);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    uint8_t *bytes = NULL;
    size_t off = 0;
#if defined(_WIN32)
    bool ok = run_read_dependency_header_win32(
        path, output->bytes, &bytes, &off);
#else
    bool ok = run_read_dependency_header_posix(
        path, output->bytes, &bytes, &off);
#endif
    if (ok) {
        uint8_t check[32];
        sha3_256(bytes, off, check);
        ok = memcmp(check, output->sha3, 32) == 0 &&
             memchr(bytes, '\0', off) == NULL;
    }
    if (!ok) {
        free(bytes);
        return false;
    }
    bytes[off] = '\0';
    *bytes_out = bytes;
    *len_out = off;
    return true;
}

static bool run_load_lock(const char *workspace,
                          const struct vcs_zcode_task_v1 *task,
                          struct vcs_package_lock *lock)
{
    uint8_t *wire = NULL, check[32];
    size_t len = 0;
    bool ok = vcs_object_load_raw_bounded(
            workspace, task->dependency_lock_root,
            VCS_PACKAGE_LOCK_MAX_WIRE_BYTES, &wire, &len) == 0 &&
        vcs_package_lock_parse(wire, len, lock) == VCS_PACKAGE_DEPS_OK &&
        vcs_package_lock_root(lock, check) == VCS_PACKAGE_DEPS_OK &&
        memcmp(check, task->dependency_lock_root, 32) == 0;
    free(wire);
    return ok;
}

/* One locked node's receipt-verified installed state and header-derived API
 * symbols, gathered into `candidate` (already zero-initialized by the
 * caller). Returns false with `detail` set when the node is not a
 * receipt-verified installed package. */
static bool run_dep_locked_candidate_build(
    const char *datadir, const struct vcs_package_lock_node *node,
    struct run_dependency_candidate *candidate, char detail[256])
{
    (void)snprintf(candidate->package.name, sizeof(candidate->package.name),
                   "%s", node->name);
    (void)snprintf(candidate->package.semver,
                   sizeof(candidate->package.semver), "%s", node->semver);
    zcl_hex_encode(node->root, 32, candidate->package.package_root_hex);
    candidate->reuse.package = &candidate->package;
    candidate->reuse.locked = true;
    candidate->reuse.installed = true;
    candidate->reuse.compatible = true;
    struct package_lifecycle_step step;
    bool installed = false;
    struct zcl_result inspected = package_lifecycle_installed_inspect(
        datadir, node->root, &step, &installed);
    struct zcl_result receipt = inspected.ok && installed
        ? package_lifecycle_receipt_read(
              datadir, step.receipt_id, &candidate->receipt)
        : ZCL_ERR(-1, "locked package is not receipt-verified and installed");
    if (!inspected.ok || !installed || !receipt.ok) {
        (void)snprintf(detail, 256,
                       "locked C23 package %s@%s is unavailable or failed receipt verification",
                       node->name, node->semver);
        return false;
    }
    return true;
}

static void run_dep_locked_candidate_headers(
    const char *datadir, struct run_dependency_candidate *candidate)
{
    for (size_t h = 0; h < candidate->receipt.output_count &&
         candidate->reuse.api_count < VCS_PACKAGE_REUSE_MAX_APIS; h++) {
        const struct vcs_package_build_output *output =
            &candidate->receipt.outputs[h];
        if (!run_output_is_header(output->path)) continue;
        (void)run_dependency_api_add(candidate, output->path,
                                     strlen(output->path));
        uint8_t *bytes = NULL; size_t len = 0;
        if (run_read_dependency_header(
                datadir, candidate->package.package_root_hex,
                output, &bytes, &len)) {
            run_dependency_header_symbols(candidate, bytes, len);
            free(bytes);
        }
    }
}

static bool run_dep_locked_row_append(
    struct json_value *locked_out, const struct vcs_package_lock_node *node,
    const struct run_dependency_candidate *candidate)
{
    struct json_value row;
    json_init(&row); json_set_object(&row);
    bool ok = json_push_kv_str(&row, "name", node->name) &&
         json_push_kv_str(&row, "semver", node->semver) &&
         json_push_kv_str(&row, "package_root",
                          candidate->package.package_root_hex) &&
         json_push_back(locked_out, &row);
    json_free(&row);
    return ok;
}

/* Builds every locked-node candidate (receipt-verified inspect + header
 * symbol gather) and appends its `locked_out` row. Returns false with
 * `detail` set on the first node that fails receipt verification. */
static bool run_dep_locked_pass(
    const char *datadir, const struct vcs_package_lock *lock, size_t count,
    struct run_dependency_candidate *candidates,
    struct vcs_package_reuse_input *inputs, struct json_value *locked_out,
    char detail[256])
{
    for (size_t i = 0; i < count; i++) {
        const struct vcs_package_lock_node *node = &lock->nodes[i];
        struct run_dependency_candidate *candidate = &candidates[i];
        if (!run_dep_locked_candidate_build(datadir, node, candidate, detail))
            return false;
        run_dep_locked_candidate_headers(datadir, candidate);
        inputs[i] = candidate->reuse;
        if (!run_dep_locked_row_append(locked_out, node, candidate))
            return false;
    }
    return true;
}

/* Which of a selected candidate's headers are goal-relevant; when none are,
 * every header stays in play (relevant_count == 0 is "no preference"). */
static bool run_dep_selected_relevant_scan(
    const char *datadir, const char *goal,
    struct run_dependency_candidate *candidate,
    bool relevant[VCS_PACKAGE_BUILD_MAX_OUTPUTS], size_t *relevant_count_out,
    char detail[256])
{
    size_t relevant_count = 0;
    for (size_t h = 0; h < candidate->receipt.output_count; h++) {
        const struct vcs_package_build_output *output =
            &candidate->receipt.outputs[h];
        if (!run_output_is_header(output->path)) continue;
        uint8_t *bytes = NULL;
        size_t len = 0;
        if (!run_read_dependency_header(
                datadir, candidate->package.package_root_hex,
                output, &bytes, &len)) {
            (void)snprintf(detail, 256,
                           "selected header %s changed after receipt verification",
                           output->path);
            return false;
        }
        relevant[h] = run_dependency_header_relevant(
            goal, output->path, bytes, len);
        if (relevant[h]) relevant_count++;
        free(bytes);
    }
    *relevant_count_out = relevant_count;
    return true;
}

/* Reads each selected header once more (post-selection reverification),
 * appends its content object to `headers_out`, and folds its API symbols
 * into `selected_apis`. */
static bool run_dep_selected_headers_json(
    const char *datadir, struct run_dependency_candidate *candidate,
    const bool relevant[VCS_PACKAGE_BUILD_MAX_OUTPUTS], size_t relevant_count,
    struct json_value *headers_out,
    struct run_dependency_candidate *selected_apis, size_t *selected_bytes,
    char detail[256])
{
    for (size_t h = 0; h < candidate->receipt.output_count; h++) {
        const struct vcs_package_build_output *output =
            &candidate->receipt.outputs[h];
        if (!run_output_is_header(output->path) ||
            (relevant_count > 0 && !relevant[h])) continue;
        uint8_t *bytes = NULL; size_t len = 0;
        if (!run_read_dependency_header(
                datadir, candidate->package.package_root_hex,
                output, &bytes, &len)) {
            (void)snprintf(detail, 256,
                           "selected header %s changed after receipt verification",
                           output->path);
            return false;
        }
        (void)run_dependency_api_add(
            selected_apis, output->path, strlen(output->path));
        run_dependency_header_symbols(selected_apis, bytes, len);
        if (len > ZWORK_DEPENDENCY_CONTEXT_MAX - *selected_bytes) {
            free(bytes);
            (void)snprintf(detail, 256,
                           "selected dependency headers exceed the context budget");
            return false;
        }
        struct json_value header;
        json_init(&header); json_set_object(&header);
        bool ok = json_push_kv_str(&header, "path", output->path) &&
             json_push_kv_int(&header, "bytes", (int64_t)len) &&
             json_push_kv_str(&header, "content", (const char *)bytes) &&
             json_push_back(headers_out, &header);
        json_free(&header);
        free(bytes);
        if (!ok) return false;
        *selected_bytes += len;
    }
    return true;
}

static bool run_dep_selected_row_build(
    struct json_value *row_out, const struct run_dependency_candidate *cand,
    const struct run_dependency_candidate *selected_apis,
    struct json_value *apis, struct json_value *headers)
{
    for (size_t a = 0; a < selected_apis->reuse.api_count; a++) {
        struct json_value api;
        json_init(&api);
        json_set_str(&api, selected_apis->reuse.apis[a]);
        bool ok = json_push_back(apis, &api);
        json_free(&api);
        if (!ok) return false;
    }
    return json_push_kv_str(row_out, "name", cand->package.name) &&
        json_push_kv_str(row_out, "semver", cand->package.semver) &&
        json_push_kv_str(row_out, "package_root",
                         cand->package.package_root_hex) &&
        json_push_kv(row_out, "apis", apis) &&
        json_push_kv(row_out, "headers", headers);
}

/* One reuse-plan-selected candidate's full `selected_out` row: relevance
 * scan, header content + API gather, then the row object itself. */
static bool run_dep_selected_pass_one(
    const char *datadir, const char *goal,
    struct run_dependency_candidate *candidate, struct json_value *selected_out,
    size_t *selected_bytes, char detail[256])
{
    bool relevant[VCS_PACKAGE_BUILD_MAX_OUTPUTS] = {0};
    size_t relevant_count = 0;
    if (!run_dep_selected_relevant_scan(
            datadir, goal, candidate, relevant, &relevant_count, detail))
        return false;
    struct json_value row, apis, headers;
    json_init(&row); json_set_object(&row);
    json_init(&apis); json_set_array(&apis);
    json_init(&headers); json_set_array(&headers);
    struct run_dependency_candidate selected_apis = {0};
    bool ok = run_dep_selected_headers_json(
        datadir, candidate, relevant, relevant_count, &headers,
        &selected_apis, selected_bytes, detail);
    ok = ok && run_dep_selected_row_build(
        &row, candidate, &selected_apis, &apis, &headers);
    ok = ok && json_push_back(selected_out, &row);
    json_free(&headers); json_free(&apis); json_free(&row);
    return ok;
}

static bool run_dep_selected_pass(
    const struct vcs_package_reuse_plan *plan, const char *datadir,
    const char *goal, struct run_dependency_candidate *candidates,
    struct json_value *selected_out, char detail[256])
{
    size_t selected_bytes = 0;
    for (size_t s = 0; s < plan->selected_count; s++) {
        size_t at = plan->selected[s].input_index;
        if (!run_dep_selected_pass_one(
                datadir, goal, &candidates[at], selected_out,
                &selected_bytes, detail))
            return false;
    }
    return true;
}

bool run_dependency_context_json(
    struct json_value *locked_out, struct json_value *selected_out,
    const char *workspace, const char *datadir,
    const struct vcs_zcode_task_v1 *task, const char *goal,
    char detail[256])
{
    json_init(locked_out); json_set_array(locked_out);
    json_init(selected_out); json_set_array(selected_out);
    struct vcs_package_lock lock;
    vcs_package_lock_init(&lock);
    if (!run_load_lock(workspace, task, &lock) || lock.count == 0) {
        (void)snprintf(detail, 256, "the task dependency lock did not reverify");
        return false;
    }
    size_t count = lock.count - 1u;
    if (count == 0) return true;
    if (!datadir || !datadir[0]) {
        (void)snprintf(detail, 256,
                       "locked packages require the existing node datadir");
        return false;
    }
    struct run_dependency_candidate *candidates = zcl_calloc(
        count, sizeof(*candidates), "zcode.work.locked_dependencies");
    struct vcs_package_reuse_input *inputs = zcl_calloc(
        count, sizeof(*inputs), "zcode.work.locked_dependency_inputs");
    if (!candidates || !inputs) {
        free(inputs); free(candidates);
        (void)snprintf(detail, 256, "locked dependency context allocation failed");
        return false;
    }
    bool ok = run_dep_locked_pass(
        datadir, &lock, count, candidates, inputs, locked_out, detail);
    struct vcs_package_reuse_plan plan;
    ok = ok && vcs_package_reuse_plan_build(goal, inputs, count, &plan);
    ok = ok && run_dep_selected_pass(
        &plan, datadir, goal, candidates, selected_out, detail);
    free(inputs); free(candidates);
    return ok;
}

bool run_excerpts_json(
    struct json_value *out, const struct vcs_zcode_agent_context_v1 *context)
{
    json_init(out); json_set_array(out);
    for (size_t i = 0; i < context->file_count; i++) {
        const struct vcs_zcode_agent_context_entry_v1 *entry =
            &context->files[i];
        if (memchr(entry->content, '\0', entry->content_len)) return false;
        char *content = zcl_malloc(entry->content_len + 1u,
                                   "zcode.work.run.excerpt");
        if (!content) return false;
        memcpy(content, entry->content, entry->content_len);
        content[entry->content_len] = '\0';
        struct json_value row;
        json_init(&row); json_set_object(&row);
        bool ok = json_push_kv_str(&row, "path", entry->path) &&
            json_push_kv_int(&row, "start_line", entry->start_line) &&
            json_push_kv_int(&row, "full_file_bytes",
                             (int64_t)entry->full_file_bytes) &&
            json_push_kv_str(&row, "content", content) &&
            json_push_back(out, &row);
        json_free(&row); free(content);
        if (!ok) return false;
    }
    return true;
}

#if defined(_WIN32)
static bool run_metadata_read_bytes(
    const char *path, char **wire_out, size_t *len_out)
{
    char *wire = zcl_malloc(VCS_PACKAGE_DEPS_META_MAX_BYTES + 1u,
                            "zcode.work.candidate_metadata");
    size_t len = 0;
    bool ok = wire && run_stable_read(path, wire,
                                      VCS_PACKAGE_DEPS_META_MAX_BYTES,
                                      &len, true) && len > 0;
    if (!ok) {
        free(wire);
        return false;
    }
    *wire_out = wire;
    *len_out = len;
    return true;
}
#else
static bool run_metadata_read_bytes(
    const char *path, char **wire_out, size_t *len_out)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    bool ok = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0 &&
        (uint64_t)st.st_size <= VCS_PACKAGE_DEPS_META_MAX_BYTES;
    size_t len = ok ? (size_t)st.st_size : 0;
    char *wire = ok ? zcl_malloc(len + 1u,
                                 "zcode.work.candidate_metadata") : NULL;
    if (ok && !wire) ok = false;
    size_t off = 0;
    while (ok && off < len) {
        ssize_t got = read(fd, wire + off, len - off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) ok = false;
        else off += (size_t)got;
    }
    if (close(fd) != 0) ok = false;
    if (!ok) {
        free(wire);
        return false;
    }
    *wire_out = wire;
    *len_out = len;
    return true;
}
#endif

bool run_candidate_metadata_read(
    const char *candidate_workspace, struct json_value *document)
{
    char path[ZWORK_RUN_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", candidate_workspace,
                     VCS_PACKAGE_DEPS_META_PATH);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    char *wire = NULL;
    size_t len = 0;
    if (!run_metadata_read_bytes(path, &wire, &len)) return false;
    wire[len] = '\0';
    json_init(document);
    bool ok = json_read(document, wire, len) && document->type == JSON_OBJ;
    if (!ok) json_free(document);
    free(wire);
    return ok;
}

#if defined(_WIN32)
static bool run_metadata_write_bytes(
    const char *candidate_workspace, const char *wire, size_t len)
{
    struct platform_directory_transaction directory;
    struct platform_directory_child staged;
    platform_directory_transaction_init(&directory);
    platform_directory_child_init(&staged);
    char temporary[64];
    int tn = snprintf(temporary, sizeof(temporary),
                      ".zcode-package.compose.%ld.tmp", (long)_getpid());
    bool staged_created = false;
    bool ok = tn > 0 && (size_t)tn < sizeof(temporary) &&
        platform_directory_transaction_open(&directory, candidate_workspace) &&
        platform_directory_child_create(&directory, temporary, &staged) &&
        (staged_created = true) &&
        platform_directory_child_write_exact(&staged, wire, len, 0) &&
        platform_directory_child_flush(&staged) &&
        platform_directory_child_replace(&directory, &staged,
                                         VCS_PACKAGE_DEPS_META_PATH, false) &&
        platform_directory_transaction_flush(&directory);
    platform_directory_child_close(&staged);
    if (!ok && staged_created)
        (void)platform_directory_child_unlink(&directory, temporary, true);
    platform_directory_transaction_close(&directory);
    return ok;
}
#else
static bool run_metadata_write_bytes(
    const char *candidate_workspace, const char *wire, size_t len)
{
    char path[ZWORK_RUN_PATH_MAX] = {0};
    char temporary[ZWORK_RUN_PATH_MAX] = {0};
    int pn = snprintf(path, sizeof(path), "%s/%s", candidate_workspace,
                      VCS_PACKAGE_DEPS_META_PATH);
    int tn = snprintf(temporary, sizeof(temporary),
                      "%s.zcode-package.compose.XXXXXX", candidate_workspace);
    int fd = pn > 0 && (size_t)pn < sizeof(path) && tn > 0 &&
                     (size_t)tn < sizeof(temporary)
        ? mkstemp(temporary)
        : -1;
    bool ok = fd >= 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0;
    size_t off = 0;
    while (ok && off < len) {
        ssize_t wrote = write(fd, wire + off, len - off);
        if (wrote < 0 && errno == EINTR) continue;
        if (wrote <= 0) ok = false;
        else off += (size_t)wrote;
    }
    if (ok) ok = fsync(fd) == 0;
    if (fd >= 0 && close(fd) != 0) ok = false;
    if (ok) ok = rename(temporary, path) == 0;
    if (ok) {
        int dir_fd = open(candidate_workspace,
                          O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        ok = dir_fd >= 0 && fsync(dir_fd) == 0;
        if (dir_fd >= 0 && close(dir_fd) != 0) ok = false;
    }
    if (!ok && temporary[0]) (void)unlink(temporary);
    return ok;
}
#endif

bool run_candidate_metadata_write(
    const char *candidate_workspace, const struct json_value *document)
{
    size_t len = json_write(document, NULL, 0);
    if (len == 0 || len > VCS_PACKAGE_DEPS_META_MAX_BYTES) return false;
    char *wire = zcl_malloc(len + 1u, "zcode.work.composed_metadata");
    if (!wire || json_write(document, wire, len + 1u) != len) {
        free(wire);
        return false;
    }
    struct vcs_package_deps checked;
    bool valid = vcs_package_deps_parse_meta(
        (const uint8_t *)wire, len, &checked, NULL, 0) ==
        VCS_PACKAGE_DEPS_OK;
    bool ok = valid && run_metadata_write_bytes(candidate_workspace, wire, len);
    free(wire);
    return ok;
}

static bool run_metadata_has_root(
    const struct json_value *dependencies, const uint8_t root[32])
{
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    for (size_t i = 0; dependencies && i < json_size(dependencies); i++) {
        const struct json_value *row = json_at(dependencies, i);
        const char *value = row && row->type == JSON_OBJ
            ? run_str(row, "root") : NULL;
        if (value && strcmp(value, root_hex) == 0) return true;
    }
    return false;
}

static struct json_value *run_compose_dependencies_array(
    struct json_value *document)
{
    struct json_value *dependencies = (struct json_value *)json_get(
        document, "dependencies");
    if (dependencies) return dependencies;
    struct json_value empty;
    json_init(&empty); json_set_array(&empty);
    bool added = json_push_kv(document, "dependencies", &empty);
    json_free(&empty);
    return added ? (struct json_value *)json_get(document, "dependencies")
                 : NULL;
}

static bool run_compose_dependencies_append(
    struct json_value *dependencies, const struct vcs_package_lock *lock,
    bool *changed_out)
{
    for (size_t i = 0; i + 1u < lock->count; i++) {
        const struct vcs_package_lock_node *node = &lock->nodes[i];
        if (run_metadata_has_root(dependencies, node->root)) continue;
        char root_hex[65];
        zcl_hex_encode(node->root, 32, root_hex);
        struct json_value row;
        json_init(&row); json_set_object(&row);
        bool ok = json_push_kv_str(&row, "root", root_hex) &&
            json_push_kv_str(&row, "name", node->name) &&
            json_push_kv_str(&row, "semver", node->semver) &&
            json_push_back(dependencies, &row);
        json_free(&row);
        if (!ok) return false;
        *changed_out = true;
    }
    return true;
}

bool run_compose_candidate_metadata(
    const char *candidate_workspace, const struct vcs_zcode_task_v1 *task,
    const char *workspace, bool *changed_out)
{
    *changed_out = false;
    struct vcs_package_lock lock;
    vcs_package_lock_init(&lock);
    if (!run_load_lock(workspace, task, &lock) || lock.count == 0)
        return false;
    struct json_value document;
    if (!run_candidate_metadata_read(candidate_workspace, &document))
        return false;
    struct json_value *dependencies = run_compose_dependencies_array(&document);
    bool ok = dependencies && dependencies->type == JSON_ARR &&
        run_compose_dependencies_append(dependencies, &lock, changed_out);
    if (ok && *changed_out)
        ok = run_candidate_metadata_write(candidate_workspace, &document);
    json_free(&document);
    return ok;
}
