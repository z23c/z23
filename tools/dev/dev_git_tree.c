/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Observe exact committed Git blobs, paths and modes through isolated metadata. */
#include "dev_git_tree.h"
#include "base/bytes.h"
#include "base/hex.h"
#include "base/serialize_le.h"
#include "crypto/sha256.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/temp_directory.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"
#include "util/file_tree_ops.h"
#include "vcs/vcs_object.h"
#include "vcs/vcs.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_publication.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void zcl_dev_git_tree_free(struct zcl_dev_git_tree *tree)
{
    if (!tree) return;
    vcs_manifest_free(&tree->files);
    for (size_t i = 0; i < tree->gitlinks; ++i) free(tree->links[i].path);
    free(tree->links);
    memset(tree, 0, sizeof(*tree));
}

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define DGT_LIST_MAX (8u * 1024u * 1024u)
#define DGT_BLOB_MAX (64u * 1024u * 1024u)
#define DGT_TOTAL_MAX (512u * 1024u * 1024u)
#define DGT_ENTRY_MAX 32768u

struct dgt_context {
    char scratch[PLATFORM_TEMP_PATH_MAX];
    char object_env[VCS_PATH_MAX + 32];
    int64_t deadline;
    size_t oid_len;
    char **paths;
    size_t path_count;
};

struct dgt_entry {
    char oid[65];
    char *path;
    uint32_t mode;
    size_t size;
};

static bool dgt_oid(const char *s, size_t len)
{
    if (len != 40 && len != 64) return false;
    if (strlen(s) != len) return false;
    for (size_t i = 0; i < len; ++i)
        if (!strchr("0123456789abcdef", s[i])) return false;
    return true;
}

static struct zcl_result dgt_run(
    const struct dgt_context *ctx, const char *repo, bool objects,
    const char *const args[], void *bytes, size_t cap, size_t *len)
{
    *len = 0;
    int64_t left = ctx->deadline - platform_time_monotonic_ms();
    if (left <= 0) return ZCL_ERR(-1, "git-tree: deadline exhausted");
    const char *argv[40] = {
        "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=",
        objects ? ctx->object_env : "GIT_OPTIONAL_LOCKS=0",
        "git", "--no-replace-objects", "-c", "protocol.allow=never",
        objects ? "--git-dir" : "-C", repo
    };
    size_t n = 15;
    for (size_t i = 0; args[i]; ++i) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return ZCL_ERR(-1, "git-tree: argument budget");
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    struct zcl_spawn_binary_observation observation = {0};
    struct zcl_result r = zcl_spawn_capture_binary(
        argv, bytes, cap, left > INT_MAX ? INT_MAX : (int)left, &observation);
    if (r.ok) *len = observation.output_len;
    return r;
}

static bool dgt_scratch_write(const char *root, const char *name, const char *text)
{
    char path[PLATFORM_TEMP_PATH_MAX + 16];
    (void)snprintf(path, sizeof(path), "%s/%s", root, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return false;
    size_t off = 0, len = strlen(text);
    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { close(fd); return false; }
        off += (size_t)n;
    }
    return close(fd) == 0;
}

static bool dgt_cleanup(struct dgt_context *ctx)
{
    if (!ctx->scratch[0]) return true;
    char path[PLATFORM_TEMP_PATH_MAX + 16];
    bool ok = true;
    const char *files[] = { "HEAD", "config" };
    for (size_t i = 0; i < 2; ++i) {
        (void)snprintf(path, sizeof(path), "%s/%s", ctx->scratch, files[i]);
        if (unlink(path) != 0 && errno != ENOENT) ok = false;
    }
    (void)snprintf(path, sizeof(path), "%s/refs", ctx->scratch);
    if (rmdir(path) != 0 && errno != ENOENT) ok = false;
    if (rmdir(ctx->scratch) != 0) ok = false;
    return ok;
}

static struct zcl_result dgt_prepare(struct dgt_context *ctx, const char *repo)
{
    const char *format[] = { "rev-parse", "--show-object-format", NULL };
    char format_bytes[16]; size_t format_len = 0;
    struct zcl_result format_result = dgt_run(
        ctx, repo, false, format, format_bytes, sizeof(format_bytes), &format_len);
    if (!format_result.ok) return format_result;
    const char *expected = ctx->oid_len == 64 ? "sha256\n" : "sha1\n";
    if (format_len != strlen(expected) || memcmp(format_bytes, expected, format_len))
        return ZCL_ERR(-1, "git-tree: source object format mismatch");
    const char *locate[] = { "rev-parse", "--path-format=absolute", "--git-path", "objects", NULL };
    char path[VCS_PATH_MAX]; size_t len = 0;
    struct zcl_result r = dgt_run(ctx, repo, false, locate, path, sizeof(path) - 1, &len);
    if (!r.ok) return r;
    if (len < 2 || path[0] != '/' || path[len - 1] != '\n')
        return ZCL_ERR(-1, "git-tree: object directory locator malformed");
    path[len - 1] = '\0';
    (void)snprintf(ctx->object_env, sizeof(ctx->object_env), "GIT_OBJECT_DIRECTORY=%s", path);
    if (!platform_temp_directory_create("z23-git-tree-", ctx->scratch, sizeof(ctx->scratch)))
        return ZCL_ERR(-1, "git-tree: private metadata allocation failed");
    char refs[PLATFORM_TEMP_PATH_MAX + 16];
    (void)snprintf(refs, sizeof(refs), "%s/refs", ctx->scratch);
    const char *config = ctx->oid_len == 64
        ? "[core]\nrepositoryformatversion = 1\nbare = true\n[extensions]\nobjectformat = sha256\n"
        : "[core]\nrepositoryformatversion = 0\nbare = true\n";
    if (platform_directory_create(refs, 0700) != 0 ||
        !dgt_scratch_write(ctx->scratch, "HEAD", "ref: refs/heads/unused\n") ||
        !dgt_scratch_write(ctx->scratch, "config", config))
        return ZCL_ERR(-1, "git-tree: private metadata setup failed");
    return ZCL_OK;
}

static bool dgt_size(const char *s, size_t *out)
{
    *out = 0;
    if (!s[0]) return false;
    for (size_t i = 0; s[i]; ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        unsigned digit = (unsigned)(s[i] - '0');
        if (*out > (DGT_BLOB_MAX - digit) / 10u) return false;
        *out = *out * 10u + digit;
    }
    return true;
}

static bool dgt_path(const char *path)
{
    if (!path[0] || strlen(path) >= VCS_PATH_MAX) return false;
    for (const char *p = path; ; ) {
        const char *slash = strchr(p, '/');
        size_t len = slash ? (size_t)(slash - p) : strlen(p);
        if (!len || (len == 1 && p[0] == '.') ||
            (len == 2 && !memcmp(p, "..", 2))) return false;
        if (!slash) return true;
        p = slash + 1;
    }
}

static bool dgt_mode(const char *mode, const char *type, const char *size,
                     struct dgt_entry *entry)
{
    if (!strcmp(mode, "160000")) {
        entry->mode = 0160000u; entry->size = 0;
        return !strcmp(type, "commit") && !strcmp(size, "-");
    }
    if (!strcmp(mode, "100644")) entry->mode = 0100644u;
    else if (!strcmp(mode, "100755")) entry->mode = 0100755u;
    else if (!strcmp(mode, "120000")) entry->mode = 0120000u;
    else return false;
    return !strcmp(type, "blob") && dgt_size(size, &entry->size);
}

static bool dgt_parse(char *record, size_t oid_len, struct dgt_entry *entry)
{
    char *tab = strchr(record, '\t');
    if (!tab || tab == record || !tab[1]) return false;
    *tab = '\0'; entry->path = tab + 1;
    if (!dgt_path(entry->path)) return false;
    char mode[7], type[7], size[21]; int used = 0;
    if (sscanf(record, "%6s %6s %64s %20s%n", mode, type, entry->oid, size, &used) != 4)
        return false;
    if (record[used] || !dgt_oid(entry->oid, oid_len)) return false;
    return dgt_mode(mode, type, size, entry);
}

static struct zcl_result dgt_link(const struct dgt_entry *entry, struct zcl_dev_git_tree *tree)
{
    struct zcl_dev_gitlink *links = zcl_realloc(tree->links,
        (tree->gitlinks + 1) * sizeof(*links), "git-tree-links");
    if (!links) return ZCL_ERR(-1, "git-tree: dependency allocation failed");
    tree->links = links;
    struct zcl_dev_gitlink *link = &links[tree->gitlinks];
    link->path = zcl_strdup(entry->path, "git-tree-link-path");
    if (!link->path) return ZCL_ERR(-1, "git-tree: dependency path allocation failed");
    memcpy(link->oid, entry->oid, sizeof(link->oid));
    ++tree->gitlinks;
    return ZCL_OK;
}

static int dgt_path_compare(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static int dgt_link_compare(const void *a, const void *b)
{
    const struct zcl_dev_gitlink *left = a, *right = b;
    return strcmp(left->path, right->path);
}

static struct zcl_result dgt_source_closure(
    struct zcl_dev_git_tree *tree)
{
    if (!vcs_manifest_tree_hash(&tree->files, tree->file_manifest_root))
        return ZCL_ERR(-1, "git-tree: file manifest root unavailable");
    if (tree->gitlinks > 1)
        qsort(tree->links, tree->gitlinks, sizeof(*tree->links), dgt_link_compare);
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    static const char domain[] = "zcl.dev.git_source_closure.v1";
    sha3_256_write(&hash, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&hash, tree->file_manifest_root, 32);
    uint8_t count[8];
    zcl_write_u64_le(count, tree->gitlinks);
    sha3_256_write(&hash, count, sizeof(count));
    for (size_t i = 0; i < tree->gitlinks; i++) {
        const struct zcl_dev_gitlink *link = &tree->links[i];
        size_t path_len = strlen(link->path), oid_len = strlen(link->oid);
        uint8_t path_size[2], oid[32], oid_bytes = (uint8_t)(oid_len / 2u);
        if (path_len == 0 || path_len > UINT16_MAX ||
            !dgt_oid(link->oid, oid_len) ||
            !zcl_hex_decode_lower(link->oid, oid, oid_bytes))
            return ZCL_ERR(-1, "git-tree: invalid source dependency");
        zcl_write_u16_le(path_size, (uint16_t)path_len);
        sha3_256_write(&hash, path_size, sizeof(path_size));
        sha3_256_write(&hash, (const uint8_t *)link->path, path_len);
        sha3_256_write(&hash, &oid_bytes, 1);
        sha3_256_write(&hash, oid, oid_bytes);
    }
    sha3_256_finalize(&hash, tree->source_closure_root);
    return ZCL_OK;
}

static bool dgt_ancestor_present(const struct dgt_context *ctx, const char *path)
{
    char prefix[VCS_PATH_MAX];
    memcpy(prefix, path, strlen(path) + 1);
    for (char *p = prefix; *p; ++p) {
        if (*p != '/') continue;
        *p = 0;
        const char *key = prefix;
        bool found = bsearch(&key, ctx->paths, ctx->path_count,
                              sizeof(*ctx->paths), dgt_path_compare) != NULL;
        *p = '/';
        if (found) return true;
    }
    return false;
}

static struct zcl_result dgt_paths_check(struct dgt_context *ctx)
{
    qsort(ctx->paths, ctx->path_count, sizeof(*ctx->paths), dgt_path_compare);
    for (size_t i = 0; i < ctx->path_count; ++i) {
        if (i && !strcmp(ctx->paths[i - 1], ctx->paths[i]))
            return ZCL_ERR(-1, "git-tree: duplicate path");
        if (dgt_ancestor_present(ctx, ctx->paths[i]))
            return ZCL_ERR(-1, "git-tree: file or gitlink ancestor collision");
    }
    if (platform_time_monotonic_ms() >= ctx->deadline)
        return ZCL_ERR(-1, "git-tree: validation deadline exhausted");
    return ZCL_OK;
}

static struct zcl_result dgt_blob(
    struct dgt_context *ctx, const struct dgt_entry *entry,
    struct zcl_dev_git_tree *tree)
{
    if (entry->size > DGT_TOTAL_MAX - tree->payload_bytes)
        return ZCL_ERR(-1, "git-tree: combined payload budget");
    unsigned char *bytes = zcl_malloc(entry->size ? entry->size : 1, "git-tree-blob");
    if (!bytes) return ZCL_ERR(-1, "git-tree: blob allocation failed");
    const char *args[] = { "cat-file", "blob", entry->oid, NULL };
    size_t len = 0;
    struct zcl_result r = dgt_run(ctx, ctx->scratch, true, args, bytes,
                                 entry->size ? entry->size : 1, &len);
    if (r.ok && len != entry->size) r = ZCL_ERR(-1, "git-tree: blob length mismatch");
    if (r.ok) {
        unsigned char tag = VCS_TAG_BLOB, hash[32];
        struct sha3_256_ctx hash_ctx;
        sha3_256_init(&hash_ctx);
        sha3_256_write(&hash_ctx, &tag, 1);
        sha3_256_write(&hash_ctx, bytes, len);
        sha3_256_finalize(&hash_ctx, hash);
        if (!vcs_manifest_add(&tree->files, entry->path, entry->mode, len, hash))
            r = ZCL_ERR(-1, "git-tree: manifest allocation failed");
        tree->payload_bytes += len;
        if (entry->mode == 0120000u) ++tree->symlinks;
    }
    free(bytes);
    return r;
}

static struct zcl_result dgt_records(
    struct dgt_context *ctx, char *wire, size_t len, struct zcl_dev_git_tree *tree)
{
    size_t off = 0, count = 0;
    while (off < len) {
        char *end = memchr(wire + off, 0, len - off);
        if (!end || ++count > DGT_ENTRY_MAX)
            return ZCL_ERR(-1, "git-tree: listing framing or entry budget");
        struct dgt_entry entry = {0};
        if (!dgt_parse(wire + off, ctx->oid_len, &entry))
            return ZCL_ERR(-1, "git-tree: invalid tree entry");
        ctx->paths[ctx->path_count++] = entry.path;
        struct zcl_result r = entry.mode == 0160000u
            ? dgt_link(&entry, tree) : dgt_blob(ctx, &entry, tree);
        if (!r.ok) return r;
        off = (size_t)(end - wire) + 1;
        if (platform_time_monotonic_ms() >= ctx->deadline)
            return ZCL_ERR(-1, "git-tree: processing deadline exhausted");
    }
    vcs_manifest_sort(&tree->files);
    struct zcl_result result = dgt_paths_check(ctx);
    if (result.ok) result = dgt_source_closure(tree);
    return result;
}

static struct zcl_result dgt_read(
    struct dgt_context *ctx, const char *head, struct zcl_dev_git_tree *tree)
{
    char type[16]; size_t len = 0;
    const char *check[] = { "cat-file", "-t", head, NULL };
    struct zcl_result r = dgt_run(ctx, ctx->scratch, true, check, type, sizeof(type), &len);
    if (!r.ok) return r;
    if (len != 7 || memcmp(type, "commit\n", 7))
        return ZCL_ERR(-1, "git-tree: head must name a commit");
    char *wire = zcl_malloc(DGT_LIST_MAX, "git-tree-listing");
    if (!wire) return ZCL_ERR(-1, "git-tree: listing allocation failed");
    ctx->paths = zcl_calloc(DGT_ENTRY_MAX, sizeof(*ctx->paths), "git-tree-paths");
    if (!ctx->paths) {
        free(wire);
        return ZCL_ERR(-1, "git-tree: path allocation failed");
    }
    const char *list[] = { "ls-tree", "-rlz", "--full-tree", head, "--", NULL };
    r = dgt_run(ctx, ctx->scratch, true, list, wire, DGT_LIST_MAX, &len);
    if (r.ok) r = dgt_records(ctx, wire, len, tree);
    free(ctx->paths); ctx->paths = NULL;
    free(wire);
    return r;
}
#endif

struct zcl_result zcl_dev_git_tree_read(
    const char *repo, const char *head, int timeout_ms, struct zcl_dev_git_tree *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !repo || !repo[0] || !head || timeout_ms <= 0)
        return ZCL_ERR(-1, "git-tree: missing bounded observation inputs");
#ifdef _WIN32
    return ZCL_ERR(-1, "git-tree: native binary capture unavailable on Windows");
#else
    struct dgt_context ctx = { .oid_len = strlen(head),
        .deadline = platform_time_monotonic_ms() + timeout_ms };
    if (!dgt_oid(head, ctx.oid_len)) return ZCL_ERR(-1, "git-tree: exact head required");
    struct zcl_result r = dgt_prepare(&ctx, repo);
    if (r.ok) r = dgt_read(&ctx, head, out);
    if (!dgt_cleanup(&ctx)) r = ZCL_ERR(-1, "git-tree: private metadata cleanup failed");
    if (!r.ok) {
        zcl_dev_git_tree_free(out);
    }
    return r;
#endif
}

static bool dgt_dependency_inputs_valid(const char *repo, const char *head,
    const struct zcl_dev_git_dependency_input *inputs, size_t input_count,
    int timeout_ms, const struct zcl_dev_git_dependency_check *out)
{
    return out && repo && head && (!input_count || inputs) &&
        input_count <= 32768u && timeout_ms > 0;
}

#ifndef _WIN32
static struct zcl_result dgt_dependency_link_check(
    const struct zcl_dev_gitlink *link,
    const struct zcl_dev_git_dependency_input *input,
    int64_t deadline, struct sha3_256_ctx *hash)
{
    if (!input->path || !input->repo_locator || !input->repo_locator[0] ||
        strcmp(input->path, link->path) != 0 ||
        !zcl_bytes_any_set(input->expected_source_closure_root, 32))
        return ZCL_ERR(-1, "git-dependencies: locator or pinned path mismatch");
    int64_t left = deadline - platform_time_monotonic_ms();
    if (left <= 0)
        return ZCL_ERR(-1, "git-dependencies: observation deadline exhausted");
    struct zcl_dev_git_tree dependency = {0};
    struct zcl_result result = zcl_dev_git_tree_read(input->repo_locator,
        link->oid, left > INT_MAX ? INT_MAX : (int)left, &dependency);
    if (result.ok && (dependency.gitlinks != 0 ||
        memcmp(dependency.source_closure_root,
               input->expected_source_closure_root, 32) != 0))
        result = ZCL_ERR(-1, "git-dependencies: pinned source closure mismatch");
    if (result.ok) {
        size_t path_len = strlen(link->path), oid_len = strlen(link->oid);
        uint8_t path_size[2], oid[32], oid_bytes = (uint8_t)(oid_len / 2u);
        zcl_write_u16_le(path_size, (uint16_t)path_len);
        if (!zcl_hex_decode_lower(link->oid, oid, oid_bytes))
            result = ZCL_ERR(-1, "git-dependencies: invalid pinned object");
        if (result.ok) {
            sha3_256_write(hash, path_size, sizeof(path_size));
            sha3_256_write(hash, (const uint8_t *)link->path, path_len);
            sha3_256_write(hash, &oid_bytes, 1);
            sha3_256_write(hash, oid, oid_bytes);
            sha3_256_write(hash, dependency.source_closure_root, 32);
        }
    }
    zcl_dev_git_tree_free(&dependency);
    return result;
}
#endif

struct zcl_result zcl_dev_git_tree_verify_dependencies(
    const char *repo, const char *head,
    const struct zcl_dev_git_dependency_input *inputs, size_t input_count,
    int timeout_ms, struct zcl_dev_git_dependency_check *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!dgt_dependency_inputs_valid(repo, head, inputs, input_count,
                                     timeout_ms, out))
        return ZCL_ERR(-1, "git-dependencies: missing bounded inputs");
#ifdef _WIN32
    return ZCL_ERR(-1, "git-dependencies: native Git observation unavailable on Windows");
#else
    int64_t deadline = platform_time_monotonic_ms() + timeout_ms;
    struct zcl_dev_git_tree super = {0};
    struct zcl_result result = zcl_dev_git_tree_read(
        repo, head, timeout_ms, &super);
    if (!result.ok) return result;
    if (super.gitlinks != input_count) {
        zcl_dev_git_tree_free(&super);
        return ZCL_ERR(-1, "git-dependencies: incomplete gitlink coverage");
    }
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    static const char domain[] = "zcl.dev.git_dependency_observation.v1";
    sha3_256_write(&hash, (const uint8_t *)domain, sizeof(domain));
    sha3_256_write(&hash, super.source_closure_root, 32);
    uint8_t count[8];
    zcl_write_u64_le(count, input_count);
    sha3_256_write(&hash, count, sizeof(count));
    for (size_t i = 0; i < input_count; i++) {
        result = dgt_dependency_link_check(&super.links[i], &inputs[i],
                                           deadline, &hash);
        if (!result.ok) break;
    }
    if (result.ok) {
        memcpy(out->super_source_closure_root, super.source_closure_root, 32);
        sha3_256_finalize(&hash, out->verified_dependency_root);
        out->dependencies_verified = input_count;
        out->complete = true;
    }
    zcl_dev_git_tree_free(&super);
    return result;
#endif
}

#ifndef _WIN32
static struct zcl_result dgt_remote_run(int64_t deadline,
    const char *const args[], void *out, size_t cap, size_t *out_len)
{
    *out_len = 0;
    int64_t left = deadline - platform_time_monotonic_ms();
    if (left <= 0) return ZCL_ERR(-1, "git-remote: observation deadline exhausted");
    const char *argv[40] = {
        "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
        "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=file:ssh:https",
        "git", "--no-replace-objects", "-c", "protocol.allow=never",
        "-c", "protocol.file.allow=always", "-c", "protocol.ssh.allow=always",
        "-c", "protocol.https.allow=always",
    };
    size_t n = 18;
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= sizeof(argv) / sizeof(argv[0]))
            return ZCL_ERR(-1, "git-remote: argument budget exceeded");
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    struct zcl_spawn_binary_observation observation = {0};
    struct zcl_result result = zcl_spawn_capture_binary(argv, out, cap,
        left > INT_MAX ? INT_MAX : (int)left, &observation);
    if (result.ok) *out_len = observation.output_len;
    return result;
}

static bool dgt_remote_ref_char(unsigned char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
}

static bool dgt_remote_ref_component(const char *s, size_t n)
{
    if (!n || s[0] == '.' || s[n - 1] == '.') return false;
    if (n >= 5 && memcmp(s + n - 5, ".lock", 5) == 0) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!dgt_remote_ref_char(c)) return false;
        if (i && c == '.' && s[i - 1] == '.') return false;
    }
    return true;
}

static bool dgt_remote_ref_valid(const char *ref)
{
    if (!ref) return false;
    size_t n = strnlen(ref, VCS_ZCODE_PUBLICATION_REF_BYTES);
    if (n <= 11 || n >= VCS_ZCODE_PUBLICATION_REF_BYTES ||
        strncmp(ref, "refs/heads/", 11) != 0) return false;
    size_t start = 11;
    for (size_t i = start; i <= n; i++) {
        if (i != n && ref[i] != '/') continue;
        if (!dgt_remote_ref_component(ref + start, i - start)) return false;
        start = i + 1;
    }
    return true;
}

static struct zcl_result dgt_remote_fetch(int64_t deadline,
    const char *scratch, const char *locator, const char *ref,
    size_t oid_len, char tip[65])
{
    char output[128]; size_t got = 0;
    char template[PLATFORM_TEMP_PATH_MAX + 16];
    if ((size_t)snprintf(template, sizeof(template), "%s/template", scratch) >= sizeof(template) ||
        platform_directory_create(template, 0700) != 0)
        return ZCL_ERR(-1, "git-remote: empty hook template unavailable");
    const char *init_sha1[] = { "init", "--bare", "--quiet", "--template", template, scratch, NULL };
    const char *init_sha256[] = {
        "init", "--bare", "--quiet", "--object-format=sha256", "--template", template, scratch, NULL
    };
    struct zcl_result result = dgt_remote_run(deadline,
        oid_len == 64 ? init_sha256 : init_sha1, output, sizeof(output), &got);
    if (!result.ok) return ZCL_ERR(-1, "git-remote: private repository initialization failed");
    char refspec[VCS_ZCODE_PUBLICATION_REF_BYTES + 32];
    int written = snprintf(refspec, sizeof(refspec),
        "%s:refs/heads/observed", ref);
    if (written <= 0 || (size_t)written >= sizeof(refspec))
        return ZCL_ERR(-1, "git-remote: target ref exceeds bound");
    const char *fetch[] = { "--git-dir", scratch, "fetch", "--quiet",
        "--no-tags", "--no-write-fetch-head", "--depth=128", locator,
        refspec, NULL };
    result = dgt_remote_run(deadline, fetch, output, sizeof(output), &got);
    if (!result.ok) return ZCL_ERR(-1, "git-remote: fresh target fetch failed");
    const char *resolve[] = { "--git-dir", scratch, "rev-parse", "--verify",
        "refs/heads/observed^{commit}", NULL };
    result = dgt_remote_run(deadline, resolve, output, sizeof(output), &got);
    if (!result.ok || got != oid_len + 1 || output[oid_len] != '\n')
        return ZCL_ERR(-1, "git-remote: fetched tip is not one exact commit");
    memcpy(tip, output, oid_len);
    tip[oid_len] = '\0';
    if (!dgt_oid(tip, oid_len))
        return ZCL_ERR(-1, "git-remote: malformed fetched tip");
    return ZCL_OK;
}

static struct zcl_result dgt_remote_ancestry(int64_t deadline,
    const char *scratch, const char *base, const char *head,
    const char *tip)
{
    char output[32]; size_t got = 0;
    const char *first[] = { "--git-dir", scratch, "merge-base",
        "--is-ancestor", base, head, NULL };
    const char *second[] = { "--git-dir", scratch, "merge-base",
        "--is-ancestor", head, tip, NULL };
    if (!dgt_remote_run(deadline, first, output, sizeof(output), &got).ok ||
        !dgt_remote_run(deadline, second, output, sizeof(output), &got).ok)
        return ZCL_ERR(-1, "git-remote: expected ancestry unavailable or divergent");
    return ZCL_OK;
}

static void dgt_remote_roots(const uint8_t target[32], const char *ref,
    const char *base, const char *head,
    const struct zcl_dev_git_remote_observation *observation,
    uint8_t ancestry[32], uint8_t evidence[32])
{
    size_t oid_bytes = strlen(head) / 2u, ref_len = strlen(ref);
    uint8_t base_oid[32], head_oid[32], tip_oid[32], ref_size[2];
    (void)zcl_hex_decode_lower(base, base_oid, oid_bytes);
    (void)zcl_hex_decode_lower(head, head_oid, oid_bytes);
    (void)zcl_hex_decode_lower(observation->fetched_tip, tip_oid, oid_bytes);
    zcl_write_u16_le(ref_size, (uint16_t)ref_len);
    static const char ancestry_domain[] = "zcl.dev.git_remote_ancestry.v1";
    struct sha3_256_ctx hash;
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)ancestry_domain, sizeof(ancestry_domain));
    sha3_256_write(&hash, target, 32);
    sha3_256_write(&hash, ref_size, sizeof(ref_size));
    sha3_256_write(&hash, (const uint8_t *)ref, ref_len);
    sha3_256_write(&hash, base_oid, oid_bytes);
    sha3_256_write(&hash, head_oid, oid_bytes);
    sha3_256_write(&hash, tip_oid, oid_bytes);
    sha3_256_finalize(&hash, ancestry);
    static const char evidence_domain[] = "zcl.dev.git_remote_observation.v2";
    sha3_256_init(&hash);
    sha3_256_write(&hash, (const uint8_t *)evidence_domain, sizeof(evidence_domain));
    sha3_256_write(&hash, ancestry, 32);
    sha3_256_write(&hash, observation->intended_source_root, 32);
    sha3_256_write(&hash, observation->fetched_source_root, 32);
    sha3_256_write(&hash, observation->intended_closure_root, 32);
    sha3_256_write(&hash, observation->fetched_closure_root, 32);
    sha3_256_write(&hash, observation->intended_verified_dependency_root, 32);
    sha3_256_write(&hash, observation->fetched_verified_dependency_root, 32);
    sha3_256_finalize(&hash, evidence);
}

static struct zcl_result dgt_remote_dependencies(int64_t deadline,
    const char *scratch, const char *head, const char *tip,
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count, struct zcl_dev_git_remote_observation *out)
{
    int64_t left = deadline - platform_time_monotonic_ms();
    if (left <= 0) return ZCL_ERR(-1, "git-remote: dependency deadline exhausted");
    struct zcl_dev_git_dependency_check intended = {0}, fetched = {0};
    struct zcl_result result = zcl_dev_git_tree_verify_dependencies(
        scratch, head, dependencies, dependency_count,
        left > INT_MAX ? INT_MAX : (int)left, &intended);
    if (!result.ok) return result;
    left = deadline - platform_time_monotonic_ms();
    if (left <= 0) return ZCL_ERR(-1, "git-remote: tip dependency deadline exhausted");
    result = zcl_dev_git_tree_verify_dependencies(scratch, tip,
        dependencies, dependency_count,
        left > INT_MAX ? INT_MAX : (int)left, &fetched);
    if (result.ok) {
        memcpy(out->intended_verified_dependency_root,
               intended.verified_dependency_root, 32);
        memcpy(out->fetched_verified_dependency_root,
               fetched.verified_dependency_root, 32);
    }
    return result;
}

static bool dgt_remote_links_match(const struct zcl_dev_git_tree *intended,
    const struct zcl_dev_git_tree *fetched)
{
    if (intended->gitlinks != fetched->gitlinks) return false;
    for (size_t i = 0; i < intended->gitlinks; i++) {
        if (strcmp(intended->links[i].path, fetched->links[i].path) != 0 ||
            strcmp(intended->links[i].oid, fetched->links[i].oid) != 0)
            return false;
    }
    return true;
}

static struct zcl_result dgt_remote_sources(int64_t deadline,
    const char *scratch, const char *head, const uint8_t source_root[32],
    const uint8_t closure_root[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count,
    struct zcl_dev_git_remote_observation *out)
{
    int64_t left = deadline - platform_time_monotonic_ms();
    if (left <= 0) return ZCL_ERR(-1, "git-remote: source deadline exhausted");
    struct zcl_dev_git_tree intended = {0}, fetched = {0};
    struct zcl_result result = zcl_dev_git_tree_read(scratch, head,
        left > INT_MAX ? INT_MAX : (int)left, &intended);
    if (result.ok) {
        left = deadline - platform_time_monotonic_ms();
        result = left <= 0 ? ZCL_ERR(-1, "git-remote: tip deadline exhausted")
            : zcl_dev_git_tree_read(scratch, out->fetched_tip,
                left > INT_MAX ? INT_MAX : (int)left, &fetched);
    }
    if (result.ok && (intended.gitlinks != dependency_count ||
        !dgt_remote_links_match(&intended, &fetched) ||
        memcmp(intended.file_manifest_root, source_root, 32) != 0 ||
        memcmp(intended.source_closure_root, closure_root, 32) != 0))
        result = ZCL_ERR(-1, "git-remote: unresolved dependency or intended source mismatch");
    if (result.ok) result = dgt_remote_dependencies(deadline, scratch,
        head, out->fetched_tip, dependencies, dependency_count, out);
    if (result.ok) {
        memcpy(out->intended_source_root, intended.file_manifest_root, 32);
        memcpy(out->fetched_source_root, fetched.file_manifest_root, 32);
        memcpy(out->intended_closure_root, intended.source_closure_root, 32);
        memcpy(out->fetched_closure_root, fetched.source_closure_root, 32);
    }
    zcl_dev_git_tree_free(&intended);
    zcl_dev_git_tree_free(&fetched);
    return result;
}
#endif

static bool dgt_remote_roots_present(const uint8_t target[32],
    const uint8_t source[32], const uint8_t closure[32])
{
    return target && source && closure &&
        zcl_bytes_any_set(target, 32) && zcl_bytes_any_set(source, 32) &&
        zcl_bytes_any_set(closure, 32);
}

static bool dgt_remote_inputs_present(const char *locator, const char *ref,
    const uint8_t target[32], const char *base, const char *head,
    const uint8_t source[32], const uint8_t closure[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count, int timeout_ms,
    const struct zcl_dev_git_remote_observation *out)
{
    return out && locator && locator[0] && locator[0] != '-' && ref &&
        base && head && timeout_ms > 0 &&
        dependency_count <= 32768u &&
        (!dependency_count || dependencies) &&
        dgt_remote_roots_present(target, source, closure);
}

struct zcl_result zcl_dev_git_remote_observe(
    const char *target_locator, const char *target_ref,
    const uint8_t target_identity_root[32],
    const char *expected_base, const char *intended_head,
    const uint8_t expected_head_source_root[32],
    const uint8_t expected_head_closure_root[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count,
    int timeout_ms, struct zcl_dev_git_remote_observation *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!dgt_remote_inputs_present(target_locator, target_ref,
            target_identity_root, expected_base, intended_head,
            expected_head_source_root, expected_head_closure_root,
            dependencies, dependency_count,
            timeout_ms, out))
        return ZCL_ERR(-1, "git-remote: missing bounded observation inputs");
#ifdef _WIN32
    return ZCL_ERR(-1, "git-remote: native Git observation unavailable on Windows");
#else
    size_t oid_len = strlen(intended_head);
    if (!dgt_remote_ref_valid(target_ref) ||
        !dgt_oid(intended_head, oid_len) || !dgt_oid(expected_base, oid_len) ||
        strcmp(expected_base, intended_head) == 0)
        return ZCL_ERR(-1, "git-remote: exact ref/base/head required");
    int64_t deadline = platform_time_monotonic_ms() + timeout_ms;
    char scratch[PLATFORM_TEMP_PATH_MAX] = {0};
    if (!platform_temp_directory_create("z23-git-remote-", scratch, sizeof(scratch)))
        return ZCL_ERR(-1, "git-remote: private fetch store unavailable");
    struct zcl_dev_git_remote_observation staged = {0};
    struct zcl_result result = dgt_remote_fetch(deadline, scratch,
        target_locator, target_ref, oid_len, staged.fetched_tip);
    if (result.ok) result = dgt_remote_ancestry(deadline, scratch,
        expected_base, intended_head, staged.fetched_tip);
    if (result.ok) result = dgt_remote_sources(deadline, scratch,
        intended_head, expected_head_source_root,
        expected_head_closure_root, dependencies, dependency_count, &staged);
    if (result.ok) {
        dgt_remote_roots(target_identity_root, target_ref, expected_base,
            intended_head, &staged, staged.verified_ancestry_root,
            staged.evidence_root);
        staged.complete = true;
    }
    if (!zcl_tree_remove(scratch).ok)
        result = ZCL_ERR(-1, "git-remote: private fetch cleanup failed");
    if (result.ok) *out = staged;
    return result;
#endif
}

#ifndef _WIN32
static int dgt_entry_path_compare(const void *key, const void *value)
{
    const struct vcs_entry *entry = value;
    return strcmp(key, entry->path);
}

static const struct vcs_entry *dgt_find(const struct vcs_manifest *tree, const char *path)
{
    if (!tree->count) return NULL;
    return bsearch(path, tree->entries, tree->count, sizeof(*tree->entries), dgt_entry_path_compare);
}

static void dgt_expected_check(const struct vcs_manifest *expected,
                               const struct vcs_manifest *observed,
                               struct zcl_dev_git_source_check *check)
{
    for (size_t i = 0; i < expected->count; ++i) {
        const struct vcs_entry *a = &expected->entries[i];
        if (a->mode != 0100644u && a->mode != 0100755u) ++check->unrepresentable_modes;
        const struct vcs_entry *b = dgt_find(observed, a->path);
        if (!b) { ++check->missing; continue; }
        if (a->mode != b->mode || a->size != b->size || memcmp(a->blob, b->blob, 32))
            ++check->changed;
        else ++check->matched;
    }
}

static void dgt_extra_check(const struct vcs_manifest *expected,
                            const struct zcl_dev_git_tree *observed,
                            struct zcl_dev_git_source_check *check)
{
    for (size_t i = 0; i < observed->files.count; ++i) {
        const char *path = observed->files.entries[i].path;
        if (dgt_find(expected, path)) continue;
        if (vcs_path_ignored(path)) ++check->excluded;
        else ++check->unexpected;
    }
    check->gitlinks = observed->gitlinks;
    check->symlinks = observed->symlinks;
    check->source_projection_matches = !check->missing && !check->changed &&
        !check->unexpected && !check->unrepresentable_modes;
    check->complete_content_matches = check->source_projection_matches &&
        !check->excluded && !check->gitlinks && !check->symlinks;
}

static struct zcl_result dgt_source_observe(
    const char *repo, const char *head, const uint8_t source_root[32],
    int64_t deadline, const struct vcs_manifest *expected,
    bool allow_pinned_links, struct zcl_dev_git_source_check *out)
{
    int64_t remaining = deadline - platform_time_monotonic_ms();
    if (remaining <= 0) return ZCL_ERR(-1, "git-source: manifest deadline exhausted");
    struct zcl_dev_git_tree observed = {0};
    struct zcl_result r = zcl_dev_git_tree_read(repo, head,
        remaining > INT_MAX ? INT_MAX : (int)remaining, &observed);
    if (!r.ok) return r;
    struct zcl_dev_git_source_check check = {0};
    dgt_expected_check(expected, &observed.files, &check);
    dgt_extra_check(expected, &observed, &check);
    zcl_dev_git_tree_free(&observed);
    if (platform_time_monotonic_ms() >= deadline)
        return ZCL_ERR(-1, "git-source: comparison deadline exhausted");
    memcpy(check.source_root, source_root, 32);
    (void)snprintf(check.head, sizeof(check.head), "%s", head);
    check.observed = true;
    *out = check;
    if (!check.complete_content_matches &&
        !(allow_pinned_links && check.source_projection_matches &&
          !check.excluded && !check.symlinks && check.gitlinks))
        return ZCL_ERR(-1, "git-source: content unresolved (missing=%zu changed=%zu unexpected=%zu excluded=%zu links=%zu symlinks=%zu modes=%zu)",
            check.missing, check.changed, check.unexpected, check.excluded,
            check.gitlinks, check.symlinks, check.unrepresentable_modes);
    return ZCL_OK;
}
#endif

struct zcl_result zcl_dev_git_tree_check_source(
    const char *repo, const char *head, const uint8_t source_root[32],
    int timeout_ms, struct zcl_dev_git_source_check *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !repo || !head || !source_root || timeout_ms <= 0)
        return ZCL_ERR(-1, "git-source: missing bounded comparison inputs");
#ifdef _WIN32
    return ZCL_ERR(-1, "git-source: native binary capture unavailable on Windows");
#else
    if (!dgt_oid(head, strlen(head))) return ZCL_ERR(-1, "git-source: exact head required");
    int64_t deadline = platform_time_monotonic_ms() + timeout_ms;
    struct vcs_manifest expected;
    if (!vcs_tree_load_bounded(repo, source_root, 8u * 1024u * 1024u,
                               DGT_ENTRY_MAX, &expected))
        return ZCL_ERR(-1, "git-source: canonical source manifest unavailable");
    struct zcl_result r = dgt_source_observe(repo, head, source_root,
                                            deadline, &expected, false, out);
    vcs_manifest_free(&expected);
    return r;
#endif
}

static bool dgt_pinned_source_inputs_valid(
    const char *repo, const char *head, const uint8_t source_root[32],
    const uint8_t expected_closure_root[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count, int timeout_ms,
    const struct zcl_dev_git_source_check *out,
    const struct zcl_dev_git_dependency_check *dependency_out)
{
    return out && dependency_out && expected_closure_root && repo && head &&
        source_root && timeout_ms > 0 &&
        (!dependency_count || dependencies);
}

struct zcl_result zcl_dev_git_tree_check_source_with_dependencies(
    const char *repo, const char *head, const uint8_t source_root[32],
    const uint8_t expected_closure_root[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count, int timeout_ms,
    struct zcl_dev_git_source_check *out,
    struct zcl_dev_git_dependency_check *dependency_out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (dependency_out) memset(dependency_out, 0, sizeof(*dependency_out));
    if (!dgt_pinned_source_inputs_valid(repo, head, source_root,
            expected_closure_root, dependencies, dependency_count,
            timeout_ms, out, dependency_out))
        return ZCL_ERR(-1, "git-source: missing pinned dependency inputs");
#ifdef _WIN32
    return ZCL_ERR(-1, "git-source: native Git observation unavailable on Windows");
#else
    if (!dgt_oid(head, strlen(head)))
        return ZCL_ERR(-1, "git-source: exact head required");
    int64_t deadline = platform_time_monotonic_ms() + timeout_ms;
    struct vcs_manifest expected;
    if (!vcs_tree_load_bounded(repo, source_root, 8u * 1024u * 1024u,
                               DGT_ENTRY_MAX, &expected))
        return ZCL_ERR(-1, "git-source: canonical source manifest unavailable");
    struct zcl_dev_git_source_check source = {0};
    struct zcl_result result = dgt_source_observe(repo, head, source_root,
        deadline, &expected, true, &source);
    vcs_manifest_free(&expected);
    if (!result.ok) return result;
    int64_t left = deadline - platform_time_monotonic_ms();
    if (left <= 0)
        return ZCL_ERR(-1, "git-source: dependency deadline exhausted");
    struct zcl_dev_git_dependency_check verified = {0};
    result = zcl_dev_git_tree_verify_dependencies(repo, head,
        dependencies, dependency_count,
        left > INT_MAX ? INT_MAX : (int)left, &verified);
    if (!result.ok || !verified.complete ||
        memcmp(verified.super_source_closure_root,
               expected_closure_root, 32) != 0 ||
        verified.dependencies_verified != source.gitlinks)
        return ZCL_ERR(-1, "git-source: pinned dependency closure mismatch");
    source.complete_content_matches = true;
    *out = source;
    *dependency_out = verified;
    return ZCL_OK;
#endif
}

#ifndef _WIN32
static bool dgt_bundle_sha256(const char *path, uint64_t max_bytes,
                              int64_t deadline, uint8_t out[32])
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path)) return false;
    bool ok = platform_positioned_file_snapshot(&file, &before) &&
              before.size <= max_bytes;
    struct sha256_ctx hash;
    sha256_init(&hash);
    uint8_t bytes[65536];
    uint64_t offset = 0;
    while (ok && offset < before.size) {
        if (platform_time_monotonic_ms() >= deadline) { ok = false; break; }
        size_t want = before.size - offset > sizeof(bytes) ? sizeof(bytes) :
                      (size_t)(before.size - offset);
        int64_t got = platform_positioned_file_read(&file, bytes, want, offset);
        if (got <= 0) { ok = false; break; }
        sha256_write(&hash, bytes, (size_t)got);
        offset += (uint64_t)got;
    }
    ok = ok && platform_time_monotonic_ms() < deadline &&
         platform_positioned_file_snapshot(&file, &after) &&
         platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (ok) sha256_finalize(&hash, out);
    return ok;
}

static struct zcl_result dgt_publication_bundle_check(
    const char *repo, const uint8_t publication_root[32],
    const uint8_t attachment_root[32], const char *bundle_path,
    const uint8_t publisher_signer[32], uint64_t max_bundle_bytes,
    int64_t deadline, uint8_t digest[32])
{
    struct vcs_zcode_publication_attachment_v1 attachment;
    if (!vcs_zcode_publication_attachment_load_verified(repo, attachment_root,
            publisher_signer, &attachment) ||
        memcmp(attachment.publication_root, publication_root, 32) != 0)
        return ZCL_ERR(-1, "git-publication: signed bundle attachment unavailable");
    if (!dgt_bundle_sha256(bundle_path, max_bundle_bytes, deadline, digest) ||
        memcmp(digest, attachment.bundle_sha256, 32) != 0)
        return ZCL_ERR(-1, "git-publication: actual bundle digest mismatch");
    return ZCL_OK;
}

static bool dgt_publication_coordinates(
    const struct vcs_zcode_publication_v1 *intent,
    const uint8_t expected_target_identity_root[32],
    const char *expected_target_ref, const char *expected_base,
    const char *head)
{
    size_t oid_chars = intent->git_object_format == VCS_ZCODE_PUBLICATION_GIT_OID_20
        ? 40u : 64u;
    if (!dgt_oid(expected_base, oid_chars) || !dgt_oid(head, oid_chars) ||
        strcmp(expected_base, head) == 0 ||
        strcmp(intent->target_ref, expected_target_ref) != 0 ||
        memcmp(intent->target_identity_root,
               expected_target_identity_root, 32) != 0)
        return false;
    char sealed_base[65], sealed_head[65];
    zcl_hex_encode(intent->expected_base, oid_chars / 2u, sealed_base);
    zcl_hex_encode(intent->head_commit, oid_chars / 2u, sealed_head);
    return strcmp(sealed_base, expected_base) == 0 &&
           strcmp(sealed_head, head) == 0;
}

static bool dgt_publication_candidate(const char *repo,
    const uint8_t candidate_root[32], struct vcs_zcode_candidate_v1 *candidate)
{
    uint8_t *wire = NULL, checked_root[32];
    size_t wire_len = 0;
    bool ok = vcs_object_load_raw_bounded(repo, candidate_root,
            VCS_ZCODE_CANDIDATE_WIRE_BYTES, &wire, &wire_len) == 0 &&
        vcs_zcode_candidate_parse(wire, wire_len, candidate) == VCS_ZCODE_DEV_OK &&
        vcs_zcode_candidate_root(candidate, checked_root) == VCS_ZCODE_DEV_OK &&
        memcmp(checked_root, candidate_root, 32) == 0;
    free(wire);
    return ok;
}

static struct zcl_result dgt_publication_source(
    const char *repo, const char *expected_base, const char *head,
    const uint8_t source_root[32],
    const uint8_t expected_closure_root[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count, int timeout_ms,
    struct zcl_dev_git_source_check *source)
{
    struct dgt_context ctx = {0};
    ctx.deadline = platform_time_monotonic_ms() + timeout_ms;
    const char *ancestry[] = {
        "merge-base", "--is-ancestor", expected_base, head, NULL
    };
    char output[64];
    size_t output_len = 0;
    if (!dgt_run(&ctx, repo, false, ancestry, output, sizeof(output),
                 &output_len).ok)
        return ZCL_ERR(-1, "git-publication: expected base is not an ancestor");
    int64_t left = ctx.deadline - platform_time_monotonic_ms();
    if (left <= 0)
        return ZCL_ERR(-1, "git-publication: source comparison deadline exhausted");
    struct zcl_result result;
    if (expected_closure_root) {
        struct zcl_dev_git_dependency_check verified;
        result = zcl_dev_git_tree_check_source_with_dependencies(repo, head,
            source_root, expected_closure_root, dependencies, dependency_count,
            left > INT_MAX ? INT_MAX : (int)left, source, &verified);
    } else {
        result = zcl_dev_git_tree_check_source(repo, head, source_root,
            left > INT_MAX ? INT_MAX : (int)left, source);
    }
    if (!result.ok || !source->complete_content_matches)
        return ZCL_ERR(-1, "git-publication: committed source differs from candidate");
    return ZCL_OK;
}
#endif

static bool dgt_publication_inputs_valid(
    const char *repo, const uint8_t publication_root[32],
    const uint8_t attachment_root[32], const char *bundle_path,
    const uint8_t publisher_signer[32],
    const uint8_t expected_target_identity_root[32],
    const char *expected_target_ref, const char *expected_base,
    const char *head, uint64_t max_bundle_bytes, int timeout_ms,
    const struct zcl_dev_git_publication_check *out)
{
    return out && repo && publication_root && attachment_root &&
        bundle_path && bundle_path[0] && publisher_signer &&
        expected_target_identity_root && expected_target_ref &&
        expected_base && head && max_bundle_bytes > 0 && timeout_ms > 0;
}

struct zcl_result zcl_dev_git_publication_check(
    const char *repo, const uint8_t publication_root[32],
    const uint8_t attachment_root[32], const char *bundle_path,
    const uint8_t publisher_signer[32],
    const uint8_t expected_target_identity_root[32],
    const char *expected_target_ref, const char *expected_base,
    const char *head, uint64_t max_bundle_bytes, int timeout_ms,
    struct zcl_dev_git_publication_check *out)
{
    return zcl_dev_git_publication_check_with_dependencies(repo,
        publication_root, attachment_root, bundle_path, publisher_signer,
        expected_target_identity_root, expected_target_ref, expected_base,
        head, NULL, NULL, 0, max_bundle_bytes, timeout_ms, out);
}

struct zcl_result zcl_dev_git_publication_check_with_dependencies(
    const char *repo, const uint8_t publication_root[32],
    const uint8_t attachment_root[32], const char *bundle_path,
    const uint8_t publisher_signer[32],
    const uint8_t expected_target_identity_root[32],
    const char *expected_target_ref, const char *expected_base,
    const char *head, const uint8_t expected_closure_root[32],
    const struct zcl_dev_git_dependency_input *dependencies,
    size_t dependency_count, uint64_t max_bundle_bytes, int timeout_ms,
    struct zcl_dev_git_publication_check *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!dgt_publication_inputs_valid(repo, publication_root, attachment_root,
            bundle_path, publisher_signer, expected_target_identity_root,
            expected_target_ref, expected_base, head, max_bundle_bytes,
            timeout_ms, out) || (dependency_count && !dependencies))
        return ZCL_ERR(-1, "git-publication: missing bounded inputs");
#ifdef _WIN32
    return ZCL_ERR(-1, "git-publication: native Git observation unavailable on Windows");
#else
    int64_t deadline = platform_time_monotonic_ms() + timeout_ms;
    struct vcs_zcode_publication_v1 intent;
    if (!vcs_zcode_publication_load_verified(repo, publication_root,
                                              publisher_signer, &intent))
        return ZCL_ERR(-1, "git-publication: signed intent unavailable");
    if (!dgt_publication_coordinates(&intent, expected_target_identity_root,
            expected_target_ref, expected_base, head))
        return ZCL_ERR(-1, "git-publication: target or exact pair mismatch");
    uint8_t bundle_sha256[32];
    struct zcl_result result = dgt_publication_bundle_check(repo,
        publication_root, attachment_root, bundle_path, publisher_signer,
        max_bundle_bytes, deadline, bundle_sha256);
    if (!result.ok) return result;
    struct vcs_zcode_candidate_v1 candidate;
    if (!dgt_publication_candidate(repo, intent.candidate_root, &candidate))
        return ZCL_ERR(-1, "git-publication: canonical candidate unavailable");
    struct zcl_dev_git_source_check source = {0};
    int64_t left = deadline - platform_time_monotonic_ms();
    if (left <= 0)
        return ZCL_ERR(-1, "git-publication: admission deadline exhausted");
    result = dgt_publication_source(repo, expected_base,
        head, candidate.candidate_source_root, expected_closure_root,
        dependencies, dependency_count,
        left > INT_MAX ? INT_MAX : (int)left, &source);
    if (!result.ok) return result;

    memcpy(out->publication_root, publication_root, 32);
    memcpy(out->attachment_root, attachment_root, 32);
    memcpy(out->bundle_sha256, bundle_sha256, 32);
    memcpy(out->candidate_root, intent.candidate_root, 32);
    memcpy(out->source_root, candidate.candidate_source_root, 32);
    (void)snprintf(out->expected_base, sizeof(out->expected_base), "%s",
                   expected_base);
    (void)snprintf(out->head, sizeof(out->head), "%s", head);
    out->source = source;
    out->verified = true;
    return ZCL_OK;
#endif
}
