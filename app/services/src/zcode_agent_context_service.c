/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Capture immutable code-index context into the existing ZCODE CAS. */

#include "services/zcode_agent_context_service.h"

#include "base/hex.h"
#include "codeindex/codeindex.h"
#include "codeindex/codeindex_merkle.h"
#include "crypto/sha3.h"
#include "util/safe_alloc.h"
#include "vcs/package_manifest.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"
#include "vcs/zcode_agent_context.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZAC_CAPTURE_READ_MAX (4u * 1024u * 1024u)

struct zac_path {
    char path[VCS_ZCODE_AGENT_CONTEXT_PATH_MAX + 1u];
    uint32_t line;
    off_t byte_offset;
};

static bool zac_source_root(const char *workspace, uint8_t out[32])
{
    return vcs_tree_capture_path(workspace, out) == VCS_OK;
}

static int zac_path_cmp(const void *a, const void *b)
{
    const struct zac_path *pa = a, *pb = b;
    return strcmp(pa->path, pb->path);
}

static bool zac_add_path(struct zac_path *paths, size_t *count,
                         const char *path, int line)
{
    if (!path || !path[0] || !vcs_package_path_valid(path) ||
        strlen(path) > VCS_ZCODE_AGENT_CONTEXT_PATH_MAX)
        return true;
    for (size_t i = 0; i < *count; i++) {
        if (strcmp(paths[i].path, path) == 0) {
            if (paths[i].line <= 1 && line > 1) paths[i].line = (uint32_t)line;
            return true;
        }
    }
    if (*count >= VCS_ZCODE_AGENT_CONTEXT_MAX_FILES) return false;
    (void)snprintf(paths[*count].path, sizeof(paths[*count].path), "%s", path);
    paths[*count].line = line > 0 ? (uint32_t)line : 1u;
    (*count)++;
    return true;
}

static bool zac_select_paths(struct codeindex *ci, const struct ci_symbol *sym,
                             struct zac_path *paths, size_t *count,
                             bool *truncated)
{
    *count = 0; *truncated = false;
    if (!zac_add_path(paths, count, sym->def_path, sym->def_line) ||
        !zac_add_path(paths, count, sym->decl_path, sym->decl_line))
        *truncated = true;
    struct ci_ref refs[7];
    int n = codeindex_callers_for_symbol(ci, sym, refs, 7);
    if (n < 0) return false;
    for (int i = 0; i < n; i++)
        if (!zac_add_path(paths, count, refs[i].ref_file, refs[i].ref_line))
            *truncated = true;
    char includes[7][256];
    const char *primary = sym->def_path[0] ? sym->def_path : sym->decl_path;
    n = primary[0] ? codeindex_includes_of_file(ci, primary, includes, 7) : 0;
    if (n < 0) return false;
    for (int i = 0; i < n; i++)
        if (!zac_add_path(paths, count, includes[i], 1)) *truncated = true;
    qsort(paths, *count, sizeof(paths[0]), zac_path_cmp);
    return *count > 0;
}

static bool zac_read_all(int fd, uint8_t *bytes, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t got = pread(fd, bytes + off, len - off, (off_t)off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) return false;
        off += (size_t)got;
    }
    return true;
}

static size_t zac_line_offset(const uint8_t *bytes, size_t len, uint32_t line)
{
    if (line <= 1) return 0;
    uint32_t at_line = 1;
    for (size_t i = 0; i < len; i++) {
        if (bytes[i] == '\n' && ++at_line == line) return i + 1u;
    }
    return 0;
}

static uint32_t zac_line_at(const uint8_t *bytes, size_t offset)
{
    uint32_t line = 1;
    for (size_t i = 0; i < offset; i++)
        if (bytes[i] == '\n') line++;
    return line;
}

static bool zac_capture_file(
    int root_fd, struct zac_path *selected,
    struct vcs_zcode_agent_context_entry_v1 *entry, size_t byte_budget,
    bool *truncated)
{
    size_t selected_path_len = strlen(selected->path);
    if (selected_path_len >= sizeof(entry->path))
        return false;
    int fd = openat(root_fd, selected->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size <= 0) {
        if (fd >= 0) close(fd);
        return false;
    }
    size_t cap = byte_budget < VCS_ZCODE_AGENT_CONTEXT_EXCERPT_MAX
        ? byte_budget : VCS_ZCODE_AGENT_CONTEXT_EXCERPT_MAX;
    if (cap == 0) { close(fd); return false; }
    size_t inspect_len = (uint64_t)st.st_size < ZAC_CAPTURE_READ_MAX
        ? (size_t)st.st_size : ZAC_CAPTURE_READ_MAX;
    uint8_t *inspect = zcl_malloc(inspect_len, "zcode.context.inspect");
    if (!inspect || !zac_read_all(fd, inspect, inspect_len)) {
        free(inspect); close(fd); return false;
    }
    size_t take = (size_t)st.st_size < cap ? (size_t)st.st_size : cap;
    size_t target = zac_line_offset(inspect, inspect_len, selected->line);
    size_t start = target > take / 4u ? target - take / 4u : 0;
    if (start > 0) {
        while (start < inspect_len && inspect[start - 1u] != '\n') start++;
        if (start >= inspect_len) start = 0;
    }
    if ((uint64_t)start + take > (uint64_t)st.st_size)
        start = (size_t)st.st_size - take;
    entry->content = zcl_malloc(take, "zcode.context.excerpt");
    if (!entry->content) { free(inspect); close(fd); return false; }
    size_t copied = 0;
    while (copied < take) {
        ssize_t got = pread(fd, entry->content + copied, take - copied,
                            (off_t)start + (off_t)copied);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        copied += (size_t)got;
    }
    close(fd);
    if (copied != take) { free(inspect); free(entry->content); return false; }
    memcpy(entry->path, selected->path, selected_path_len + 1);
    entry->start_line = zac_line_at(inspect, start);
    entry->full_file_bytes = (uint64_t)st.st_size;
    entry->content_len = take;
    sha3_256(entry->content, take, entry->content_root);
    selected->byte_offset = (off_t)start;
    if (take != (size_t)st.st_size) *truncated = true;
    free(inspect);
    return true;
}

static bool zac_reread_matches(
    int root_fd, const struct zac_path *selected,
    const struct vcs_zcode_agent_context_entry_v1 *entry)
{
    int fd = openat(root_fd, selected->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        (uint64_t)st.st_size != entry->full_file_bytes) {
        if (fd >= 0) close(fd);
        return false;
    }
    uint8_t *check = zcl_malloc(entry->content_len, "zcode.context.reread");
    if (!check) { close(fd); return false; }
    size_t off = 0;
    while (off < entry->content_len) {
        ssize_t got = pread(fd, check + off, entry->content_len - off,
                            selected->byte_offset + (off_t)off);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0) break;
        off += (size_t)got;
    }
    close(fd);
    bool matches = off == entry->content_len &&
                   memcmp(check, entry->content, entry->content_len) == 0;
    free(check);
    return matches;
}

struct zcl_result zcode_agent_context_capture(
    const char *workspace, const struct vcs_zcode_task_v1 *task,
    const uint8_t task_root[32], const char *query,
    struct zcode_agent_context_status *out)
{
    if (!workspace || !task || !task_root || !query || !query[0] || !out ||
        strlen(query) > VCS_ZCODE_AGENT_CONTEXT_QUERY_MAX)
        return ZCL_ERR(-1, "agent context requires workspace, task, and bounded symbol");
    memset(out, 0, sizeof(*out));
    uint8_t source_root_before[32];
    if (!zac_source_root(workspace, source_root_before))
        return ZCL_ERR(-1, "source snapshot could not be captured");
    if (memcmp(source_root_before, task->source_root, 32) != 0)
        return ZCL_ERR(-1, "task source root is not the current source snapshot");
    struct codeindex *ci = codeindex_open(workspace);
    if (!ci) return ZCL_ERR(-1, "code index could not open for agent context");
    struct ci_symbol sym = {0}; bool found = false;
    if (strchr(query, ':'))
        (void)codeindex_symbol_by_id(ci, query, &sym, &found);
    else
        (void)codeindex_symbol(ci, query, &sym, &found);
    if (!found) {
        codeindex_close(ci);
        return ZCL_ERR(-1, "context symbol is not an exact indexed symbol");
    }
    struct ci_merkle_cost cost = {0};
    struct ci_merkle *before = ci_merkle_build_cold(workspace, &cost);
    struct ci_merkle_node before_root;
    if (!before || !ci_merkle_root(before, &before_root)) {
        ci_merkle_free(before); codeindex_close(ci);
        return ZCL_ERR(-1, "source tree identity could not be captured");
    }
    struct zac_path paths[VCS_ZCODE_AGENT_CONTEXT_MAX_FILES] = {0};
    size_t path_count = 0; bool truncated = false;
    if (!zac_select_paths(ci, &sym, paths, &path_count, &truncated)) {
        ci_merkle_free(before); codeindex_close(ci);
        return ZCL_ERR(-1, "code index could not select a source context");
    }
    int root_fd = open(workspace, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root_fd < 0) {
        ci_merkle_free(before); codeindex_close(ci);
        return ZCL_ERR(-1, "workspace could not be opened for context capture");
    }
    struct vcs_zcode_agent_context_v1 context;
    vcs_zcode_agent_context_init(&context);
    memcpy(context.task_root, task_root, 32);
    memcpy(context.source_root, task->source_root, 32);
    memcpy(context.goal_root, task->goal_root, 32);
    memcpy(context.source_tree_root, before_root.digest.bytes, 32);
    (void)snprintf(context.query, sizeof(context.query), "%s", query);
    size_t overhead = VCS_ZCODE_AGENT_CONTEXT_FIXED_BYTES + strlen(query) +
        path_count * (VCS_ZCODE_AGENT_CONTEXT_ENTRY_FIXED_BYTES +
                      VCS_ZCODE_AGENT_CONTEXT_PATH_MAX);
    size_t budget = task->max_context_bytes > overhead
        ? (size_t)task->max_context_bytes - overhead : 0;
    for (size_t i = 0; i < path_count; i++) {
        size_t left = path_count - i;
        size_t share = left > 0 ? budget / left : 0;
        if (!zac_capture_file(root_fd, &paths[i], &context.files[i], share,
                              &truncated)) {
            vcs_zcode_agent_context_free(&context); close(root_fd);
            ci_merkle_free(before); codeindex_close(ci);
            return ZCL_ERR(-1, "selected source file changed or could not be read");
        }
        budget -= context.files[i].content_len;
        context.file_count++;
    }
    struct ci_merkle *after = ci_merkle_build_cold(workspace, NULL);
    struct ci_merkle_node after_root;
    bool stable = after && ci_merkle_root(after, &after_root) &&
        memcmp(before_root.digest.bytes, after_root.digest.bytes, 32) == 0;
    for (size_t i = 0; stable && i < context.file_count; i++)
        stable = zac_reread_matches(root_fd, &paths[i], &context.files[i]);
    close(root_fd); ci_merkle_free(after); ci_merkle_free(before);
    codeindex_close(ci);
    uint8_t source_root_after[32];
    stable = stable && zac_source_root(workspace, source_root_after) &&
        memcmp(source_root_before, source_root_after, 32) == 0;
    if (!stable) {
        vcs_zcode_agent_context_free(&context);
        return ZCL_ERR(-1, "source changed during agent context capture");
    }
    if (truncated) context.flags |= VCS_ZCODE_AGENT_CONTEXT_TRUNCATED;
    uint8_t *wire = NULL; size_t wire_len = 0; uint8_t root[32];
    enum vcs_zcode_agent_context_result encoded =
        vcs_zcode_agent_context_serialize(
            &context, (size_t)task->max_context_bytes, &wire, &wire_len);
    if (encoded == VCS_ZCODE_AGENT_CONTEXT_OK)
        encoded = vcs_zcode_agent_context_root(
            &context, (size_t)task->max_context_bytes, root);
    if (encoded != VCS_ZCODE_AGENT_CONTEXT_OK ||
        !vcs_object_store_init(workspace) ||
        !vcs_object_put_addressed(workspace, root, wire, wire_len)) {
        free(wire); vcs_zcode_agent_context_free(&context);
        return ZCL_ERR(-1, "canonical agent context could not enter CAS");
    }
    uint8_t *checked_wire = NULL; size_t checked_len = 0;
    struct vcs_zcode_agent_context_v1 checked;
    bool verified = vcs_object_load_raw(
            workspace, root, &checked_wire, &checked_len) == 0 &&
        checked_len == wire_len && memcmp(checked_wire, wire, wire_len) == 0 &&
        vcs_zcode_agent_context_parse(
            checked_wire, checked_len, (size_t)task->max_context_bytes,
            &checked) == VCS_ZCODE_AGENT_CONTEXT_OK;
    if (verified) vcs_zcode_agent_context_free(&checked);
    free(checked_wire); free(wire);
    if (!verified) {
        vcs_zcode_agent_context_free(&context);
        return ZCL_ERR(-1, "agent context CAS readback verification failed");
    }
    zcl_hex_encode(root, 32, out->context_root_sha3);
    zcl_hex_encode(context.source_tree_root, 32, out->source_tree_root_sha3);
    (void)snprintf(out->resolved_symbol, sizeof(out->resolved_symbol), "%s",
                   sym.name);
    out->file_count = context.file_count;
    out->wire_bytes = wire_len;
    out->truncated = truncated;
    for (size_t i = 0; i < context.file_count; i++)
        out->excerpt_bytes += context.files[i].content_len;
    vcs_zcode_agent_context_free(&context);
    return ZCL_OK;
}
