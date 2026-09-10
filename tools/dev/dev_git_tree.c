/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Observe exact committed Git blobs, paths and modes through isolated metadata. */
#include "dev_git_tree.h"
#include "platform/directory_compat.h"
#include "platform/temp_directory.h"
#include "platform/time_compat.h"
#include "sha3/sha3.h"
#include "util/safe_alloc.h"
#include "util/spawn.h"
#include "vcs/vcs_object.h"
#include "vcs/vcs.h"
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
    return dgt_paths_check(ctx);
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
    struct zcl_dev_git_source_check *out)
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
    if (!check.complete_content_matches)
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
                                            deadline, &expected, out);
    vcs_manifest_free(&expected);
    return r;
#endif
}
