/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: safely traverse package trees and derive canonical release inputs. */

#define _POSIX_C_SOURCE 200809L

#include "vcs/package_prepare.h"

#include "json/json.h"
#include "util/safe_alloc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define PREPARE_META_MAX VCS_PACKAGE_DEPS_META_MAX_BYTES
#define PREPARE_TEST_SECONDS 60u
#define PREPARE_TEST_MEMORY (UINT64_C(512) * 1024u * 1024u)

struct prepare_walk {
    struct vcs_package_prepared *out;
    uint8_t *meta;
    size_t meta_len;
    enum vcs_package_prepare_error error;
    char *detail;
    size_t detail_cap;
};

static void prepare_detail(struct prepare_walk *walk, const char *fmt, ...)
{
    if (!walk->detail || walk->detail_cap == 0)
        return;
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(walk->detail, walk->detail_cap, fmt, ap);
    va_end(ap);
}

const char *vcs_package_prepare_error_string(
    enum vcs_package_prepare_error error)
{
    switch (error) {
    case VCS_PACKAGE_PREPARE_OK: return "ok";
    case VCS_PACKAGE_PREPARE_ERR_NULL: return "null-argument";
    case VCS_PACKAGE_PREPARE_ERR_PATH: return "path";
    case VCS_PACKAGE_PREPARE_ERR_FILE_TYPE: return "file-type";
    case VCS_PACKAGE_PREPARE_ERR_CHANGED: return "file-changed";
    case VCS_PACKAGE_PREPARE_ERR_IO: return "io";
    case VCS_PACKAGE_PREPARE_ERR_ALLOC: return "allocation";
    case VCS_PACKAGE_PREPARE_ERR_META: return "package-metadata";
    case VCS_PACKAGE_PREPARE_ERR_MANIFEST: return "content-manifest";
    case VCS_PACKAGE_PREPARE_ERR_RECIPE: return "build-recipe";
    case VCS_PACKAGE_PREPARE_ERR_LOCK: return "dependency-lock";
    case VCS_PACKAGE_PREPARE_ERR_CAPSULE: return "api-capsule";
    case VCS_PACKAGE_PREPARE_ERR_RELEASE: return "release-body";
    }
    return "unknown-error";
}

void vcs_package_prepared_init(struct vcs_package_prepared *prepared)
{
    if (!prepared)
        return;
    memset(prepared, 0, sizeof(*prepared));
    vcs_package_manifest_init(&prepared->manifest);
    vcs_package_recipe_init(&prepared->recipe);
    vcs_package_lock_init(&prepared->lock);
    vcs_package_capsule_init(&prepared->capsule);
}

void vcs_package_prepared_free(struct vcs_package_prepared *prepared)
{
    if (!prepared)
        return;
    vcs_package_manifest_free(&prepared->manifest);
    vcs_package_recipe_free(&prepared->recipe);
    free(prepared->manifest_wire);
    free(prepared->recipe_wire);
    free(prepared->lock_wire);
    free(prepared->capsule_wire);
    free(prepared->release_body);
    memset(prepared, 0, sizeof(*prepared));
}

static bool prepare_stat_same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}

static bool prepare_read_exact(int fd, uint8_t *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t got = read(fd, buf + off, len - off);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            return false;
        off += (size_t)got;
    }
    return true;
}

static bool prepare_recipe_file(struct prepare_walk *walk, const char *path)
{
    enum vcs_package_recipe_error err = VCS_PACKAGE_RECIPE_OK;
    size_t len = strlen(path);
    if (strncmp(path, "include/", 8) == 0 && len > 2u &&
        strcmp(path + len - 2u, ".h") == 0)
        return vcs_package_recipe_add_header(&walk->out->recipe, path, &err);
    if (strncmp(path, "src/", 4) == 0 && len > 2u &&
        strcmp(path + len - 2u, ".c") == 0)
        return vcs_package_recipe_add_source(&walk->out->recipe, path, &err);
    if (strncmp(path, "tests/", 6) == 0 && len > 2u &&
        strcmp(path + len - 2u, ".c") == 0)
        return vcs_package_recipe_add_test_source(&walk->out->recipe, path,
                                                   &err);
    return true;
}

static bool prepare_regular(struct prepare_walk *walk, int parent_fd,
                            const char *name, const char *path,
                            const struct stat *listed)
{
    int fd = openat(parent_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
        prepare_detail(walk, "%s: open: %s", path, strerror(errno));
        return false;
    }
    struct stat before;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_dev != listed->st_dev || before.st_ino != listed->st_ino ||
        before.st_size < 0 ||
        (uint64_t)before.st_size > VCS_PACKAGE_MAX_FILE_BYTES) {
        close(fd);
        walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
        prepare_detail(walk, "%s: changed before read", path);
        return false;
    }
    uint64_t size = (uint64_t)before.st_size;
    uint32_t chunks = size == 0 ? 0u :
        (uint32_t)(1u + (size - 1u) / VCS_PACKAGE_CHUNK_BYTES);
    uint8_t *hashes = NULL;
    uint8_t *buf = NULL;
    if (chunks) {
        hashes = zcl_malloc((size_t)chunks * 32u,
                            "vcs.package.prepare.hashes");
        buf = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES,
                         "vcs.package.prepare.chunk");
        if (!hashes || !buf) {
            free(hashes); free(buf); close(fd);
            walk->error = VCS_PACKAGE_PREPARE_ERR_ALLOC;
            prepare_detail(walk, "%s: chunk allocation", path);
            return false;
        }
    }
    uint64_t left = size;
    for (uint32_t i = 0; i < chunks; i++) {
        size_t want = left > VCS_PACKAGE_CHUNK_BYTES
            ? VCS_PACKAGE_CHUNK_BYTES : (size_t)left;
        if (!prepare_read_exact(fd, buf, want) ||
            !vcs_package_chunk_hash(buf, want, hashes + (size_t)i * 32u)) {
            free(hashes); free(buf); close(fd);
            walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
            prepare_detail(walk, "%s: read chunk %u", path, i);
            return false;
        }
        left -= want;
    }
    struct stat after;
    if (fstat(fd, &after) != 0 || !prepare_stat_same(&before, &after)) {
        free(hashes); free(buf); close(fd);
        walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
        prepare_detail(walk, "%s: changed while read", path);
        return false;
    }
    if (strcmp(path, VCS_PACKAGE_DEPS_META_PATH) == 0) {
        if (size > PREPARE_META_MAX || lseek(fd, 0, SEEK_SET) < 0) {
            free(hashes); free(buf); close(fd);
            walk->error = VCS_PACKAGE_PREPARE_ERR_META;
            prepare_detail(walk, "%s: metadata exceeds bound", path);
            return false;
        }
        walk->meta = zcl_malloc((size_t)size + 1u,
                                "vcs.package.prepare.meta");
        if (!walk->meta || !prepare_read_exact(fd, walk->meta, (size_t)size)) {
            free(walk->meta); walk->meta = NULL;
            free(hashes); free(buf); close(fd);
            walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
            prepare_detail(walk, "%s: metadata read", path);
            return false;
        }
        struct stat metadata_after;
        if (fstat(fd, &metadata_after) != 0 ||
            !prepare_stat_same(&before, &metadata_after)) {
            free(walk->meta); walk->meta = NULL;
            free(hashes); free(buf); close(fd);
            walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
            prepare_detail(walk, "%s: changed during metadata read", path);
            return false;
        }
        walk->meta[size] = 0;
        walk->meta_len = (size_t)size;
    }
    close(fd);
    uint32_t mode = (before.st_mode & 0111u)
        ? VCS_PACKAGE_MODE_EXECUTABLE : VCS_PACKAGE_MODE_FILE;
    bool ok = vcs_package_manifest_add(&walk->out->manifest, path, mode,
                                       size, hashes, chunks) &&
              prepare_recipe_file(walk, path);
    free(hashes); free(buf);
    if (!ok) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_MANIFEST;
        prepare_detail(walk, "%s: manifest or recipe admission", path);
    }
    return ok;
}

/* Root-level local control and generated-output directories do not enter
 * package identity. Nested same-named directories stay visible. A symlink
 * or special file with these names is refused by the walk caller. */
static bool prepare_local_control_dir(const char *prefix, const char *name)
{
    return prefix[0] == '\0' &&
           (strcmp(name, ".zvcs") == 0 || strcmp(name, ".codeindex") == 0 ||
            strcmp(name, "build") == 0);
}

static bool prepare_walk_dir(struct prepare_walk *walk, int dir_fd,
                             const char *prefix)
{
    int scan_fd = dup(dir_fd);
    if (scan_fd < 0) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
        prepare_detail(walk, "%s: dup directory", prefix);
        return false;
    }
    DIR *dir = fdopendir(scan_fd);
    if (!dir) {
        close(scan_fd);
        walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
        prepare_detail(walk, "%s: fdopendir", prefix);
        return false;
    }
    bool ok = true;
    struct dirent *entry;
    while (ok) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno != 0) {
                walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
                prepare_detail(walk, "%s: readdir: %s", prefix,
                               strerror(errno));
                ok = false;
            }
            break;
        }
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;
        char path[VCS_PACKAGE_PATH_MAX + 1u];
        int n = prefix[0]
            ? snprintf(path, sizeof(path), "%s/%s", prefix, entry->d_name)
            : snprintf(path, sizeof(path), "%s", entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(path) ||
            !vcs_package_path_valid(path)) {
            walk->error = VCS_PACKAGE_PREPARE_ERR_PATH;
            prepare_detail(walk, "%s: non-canonical package path", path);
            ok = false;
            break;
        }
        struct stat listed;
        if (fstatat(dir_fd, entry->d_name, &listed,
                    AT_SYMLINK_NOFOLLOW) != 0) {
            walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
            prepare_detail(walk, "%s: stat: %s", path, strerror(errno));
            ok = false;
        } else if (S_ISDIR(listed.st_mode) &&
                   prepare_local_control_dir(prefix, entry->d_name)) {
            continue;
        } else if (S_ISDIR(listed.st_mode)) {
            int child = openat(dir_fd, entry->d_name,
                               O_RDONLY | O_DIRECTORY | O_CLOEXEC |
                               O_NOFOLLOW);
            if (child < 0 || !prepare_walk_dir(walk, child, path))
                ok = false;
            if (child >= 0)
                close(child);
        } else if (S_ISREG(listed.st_mode)) {
            ok = prepare_regular(walk, dir_fd, entry->d_name, path, &listed);
        } else {
            walk->error = VCS_PACKAGE_PREPARE_ERR_FILE_TYPE;
            prepare_detail(walk, "%s: symlink or special file refused", path);
            ok = false;
        }
    }
    closedir(dir);
    return ok;
}

static const char *prepare_meta_string(const struct json_value *meta,
                                       const char *key)
{
    const struct json_value *value = json_get(meta, key);
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static bool prepare_copy_field(char *out, size_t cap, const char *value)
{
    if (!value || strlen(value) >= cap)
        return false;
    memcpy(out, value, strlen(value) + 1u);
    return true;
}

static bool prepare_key_allowed(const char *key, const char *const *allowed,
                                size_t allowed_count)
{
    for (size_t i = 0; i < allowed_count; i++)
        if (strcmp(key, allowed[i]) == 0)
            return true;
    return false;
}

static bool prepare_meta_closed(const struct json_value *meta,
                                char *detail, size_t detail_cap)
{
    static const char *const top_keys[] = {
        "schema", "name", "semver", "language", "license",
        "include_dir", "source_dir", "dependencies", "files",
    };
    static const char *const dep_keys[] = { "root", "name", "semver" };
    for (size_t i = 0; i < meta->num_children; i++) {
        if (!prepare_key_allowed(meta->keys[i], top_keys,
                                 sizeof(top_keys) / sizeof(top_keys[0]))) {
            if (detail && detail_cap)
                (void)snprintf(detail, detail_cap,
                               "unknown metadata key: %s", meta->keys[i]);
            return false;
        }
    }
    const struct json_value *dependencies = json_get(meta, "dependencies");
    if (!dependencies || dependencies->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < dependencies->num_children; i++) {
        const struct json_value *dep = &dependencies->children[i];
        if (dep->type != JSON_OBJ)
            return false;
        for (size_t j = 0; j < dep->num_children; j++) {
            if (!prepare_key_allowed(dep->keys[j], dep_keys,
                                     sizeof(dep_keys) / sizeof(dep_keys[0]))) {
                if (detail && detail_cap)
                    (void)snprintf(detail, detail_cap,
                                   "dependency %zu unknown key: %s", i,
                                   dep->keys[j]);
                return false;
            }
        }
    }
    const struct json_value *files = json_get(meta, "files");
    if (files && files->type != JSON_ARR)
        return false;
    if (files) {
        for (size_t i = 0; i < files->num_children; i++)
            if (files->children[i].type != JSON_STR)
                return false;
    }
    return true;
}

static const struct vcs_package_file *prepare_manifest_find(
    const struct vcs_package_manifest *manifest, const char *path)
{
    size_t lo = 0, hi = manifest->count;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2u;
        int cmp = strcmp(manifest->files[mid].path, path);
        if (cmp < 0)
            lo = mid + 1u;
        else
            hi = mid;
    }
    return lo < manifest->count &&
                   strcmp(manifest->files[lo].path, path) == 0
        ? &manifest->files[lo] : NULL;
}

/* An optional exact file list makes a real module subset declarative without
 * copying its implementation into a package-shaped directory. The package
 * manifest still commits the configuration itself, and only selected bytes
 * enter the recipe and content root. Omission preserves the original
 * whole-directory behavior. */
static bool prepare_apply_file_selection(struct prepare_walk *walk,
                                         const struct json_value *meta)
{
    const struct json_value *files = json_get(meta, "files");
    if (!files)
        return true;
    if (files->num_children == 0 ||
        files->num_children > VCS_PACKAGE_MAX_FILES) {
        prepare_detail(walk, "files must contain 1..%u paths",
                       VCS_PACKAGE_MAX_FILES);
        return false;
    }

    struct vcs_package_manifest selected;
    vcs_package_manifest_init(&selected);
    bool has_config = false;
    const char *previous = NULL;
    for (size_t i = 0; i < files->num_children; i++) {
        const char *path = json_get_str(&files->children[i]);
        if (!path || !vcs_package_path_valid(path) ||
            (previous && strcmp(previous, path) >= 0)) {
            prepare_detail(walk, "files[%zu] is not strict canonical order",
                           i);
            vcs_package_manifest_free(&selected);
            return false;
        }
        const struct vcs_package_file *source =
            prepare_manifest_find(&walk->out->manifest, path);
        if (!source || !vcs_package_manifest_add(
                &selected, source->path, source->mode, source->size,
                source->chunk_hashes, source->chunk_count)) {
            prepare_detail(walk, "files[%zu] is absent: %s", i, path);
            vcs_package_manifest_free(&selected);
            return false;
        }
        if (strcmp(path, VCS_PACKAGE_DEPS_META_PATH) == 0)
            has_config = true;
        previous = path;
    }
    if (!has_config) {
        prepare_detail(walk, "files must include %s",
                       VCS_PACKAGE_DEPS_META_PATH);
        vcs_package_manifest_free(&selected);
        return false;
    }

    vcs_package_manifest_free(&walk->out->manifest);
    walk->out->manifest = selected;
    vcs_package_recipe_free(&walk->out->recipe);
    vcs_package_recipe_init(&walk->out->recipe);
    for (size_t i = 0; i < selected.count; i++) {
        if (!prepare_recipe_file(walk, selected.files[i].path)) {
            prepare_detail(walk, "files recipe admission: %s",
                           selected.files[i].path);
            return false;
        }
    }
    return true;
}

static enum vcs_package_prepare_error prepare_finish(
    const struct vcs_package_prepare_options *options,
    struct prepare_walk *walk)
{
    struct vcs_package_prepared *out = walk->out;
    if (!walk->meta || walk->meta_len == 0) {
        prepare_detail(walk, "missing %s", VCS_PACKAGE_DEPS_META_PATH);
        return VCS_PACKAGE_PREPARE_ERR_META;
    }
    struct json_value meta;
    if (!json_read(&meta, (const char *)walk->meta, walk->meta_len) ||
        meta.type != JSON_OBJ) {
        prepare_detail(walk, "%s is not a JSON object",
                       VCS_PACKAGE_DEPS_META_PATH);
        return VCS_PACKAGE_PREPARE_ERR_META;
    }
    const struct json_value *schema = json_get(&meta, "schema");
    const char *name = prepare_meta_string(&meta, "name");
    const char *semver = prepare_meta_string(&meta, "semver");
    const char *license = prepare_meta_string(&meta, "license");
    const char *language = prepare_meta_string(&meta, "language");
    const char *include_dir = prepare_meta_string(&meta, "include_dir");
    const char *source_dir = prepare_meta_string(&meta, "source_dir");
    if (!schema || schema->type != JSON_INT || json_get_int(schema) != 1 ||
        !name || !semver || !license || !language || !include_dir ||
        !source_dir || strcmp(language, "c23") != 0 ||
        strcmp(include_dir, "include") != 0 ||
        strcmp(source_dir, "src") != 0 ||
        !prepare_meta_closed(&meta, walk->detail, walk->detail_cap)) {
        json_free(&meta);
        if (!walk->detail || walk->detail[0] == '\0')
            prepare_detail(walk, "metadata schema is not the closed C23 v1 shape");
        return VCS_PACKAGE_PREPARE_ERR_META;
    }
    if (!prepare_apply_file_selection(walk, &meta)) {
        json_free(&meta);
        return VCS_PACKAGE_PREPARE_ERR_META;
    }
    struct vcs_package_deps deps;
    char dep_detail[160] = {0};
    enum vcs_package_deps_error derr = vcs_package_deps_parse_meta(
        walk->meta, walk->meta_len, &deps, dep_detail, sizeof(dep_detail));
    if (derr != VCS_PACKAGE_DEPS_OK) {
        json_free(&meta);
        prepare_detail(walk, "dependencies: %s (%s)",
                       vcs_package_deps_error_string(derr), dep_detail);
        return VCS_PACKAGE_PREPARE_ERR_LOCK;
    }
    enum vcs_package_recipe_error rerr = VCS_PACKAGE_RECIPE_OK;
    if (out->recipe.public_headers.count > 0 &&
        !vcs_package_recipe_add_include_dir(&out->recipe, "include", &rerr)) {
        json_free(&meta);
        prepare_detail(walk, "recipe include: %s",
                       vcs_package_recipe_error_string(rerr));
        return VCS_PACKAGE_PREPARE_ERR_RECIPE;
    }
    vcs_package_recipe_set_test_limits(&out->recipe, 0,
                                       PREPARE_TEST_SECONDS,
                                       PREPARE_TEST_MEMORY);
    rerr = vcs_package_recipe_validate(&out->recipe);
    if (rerr != VCS_PACKAGE_RECIPE_OK ||
        !vcs_package_recipe_files_in_manifest(&out->recipe, &out->manifest,
                                               dep_detail,
                                               sizeof(dep_detail))) {
        json_free(&meta);
        prepare_detail(walk, "recipe: %s (%s)",
                       vcs_package_recipe_error_string(rerr), dep_detail);
        return VCS_PACKAGE_PREPARE_ERR_RECIPE;
    }
    if (!vcs_package_manifest_serialize(&out->manifest, &out->manifest_wire,
                                        &out->manifest_wire_len) ||
        !vcs_package_manifest_root(&out->manifest, out->package_root)) {
        json_free(&meta);
        return VCS_PACKAGE_PREPARE_ERR_MANIFEST;
    }
    rerr = vcs_package_recipe_serialize(&out->recipe, &out->recipe_wire,
                                        &out->recipe_wire_len);
    if (rerr != VCS_PACKAGE_RECIPE_OK ||
        vcs_package_recipe_root(&out->recipe, out->recipe_root) !=
            VCS_PACKAGE_RECIPE_OK) {
        json_free(&meta);
        return VCS_PACKAGE_PREPARE_ERR_RECIPE;
    }
    if (deps.count + 1u > VCS_PACKAGE_LOCK_MAX_NODES) {
        json_free(&meta);
        return VCS_PACKAGE_PREPARE_ERR_LOCK;
    }
    /* THIS IS THE DECLARATION GRAPH, NOT THE TRANSITIVE CLOSURE, AND THE
     * DIFFERENCE IS LOAD-BEARING. prepare() reads ONE directory. A declared
     * dependency is named only by its 32-byte root, and nothing here can turn
     * a root into that package's own metadata: there is no store handle, no
     * index, and no root -> directory map in the options. So this lock states
     * exactly what this package's own zcode-package.json says and nothing
     * more -- the target, its directly declared edges, and depth 1 for each
     * of them, which is the true longest path in a graph that HAS no other
     * edges. `direct_deps` is 0 on a dependency node for the same reason: this
     * graph records no edge out of it. That is a complete statement about the
     * declaration, not a truncated one about the closure.
     *
     * The real transitive DAG -- deduplicated, cycle-checked, with
     * longest-path depth and true direct_deps -- is vcs_package_lock_resolve()
     * in package_deps.c, which takes a loader and is what the install
     * lifecycle pins into a build receipt. A caller that needs the closure
     * must go through that, never through this projection. */
    for (size_t i = 0; i < deps.count; i++) {
        struct vcs_package_lock_node *node = &out->lock.nodes[out->lock.count++];
        memcpy(node->root, deps.items[i].root, 32);
        memcpy(node->name, deps.items[i].name, strlen(deps.items[i].name) + 1u);
        memcpy(node->semver, deps.items[i].semver,
               strlen(deps.items[i].semver) + 1u);
        node->depth = 1;
        node->direct_deps = 0;
    }
    struct vcs_package_lock_node *target =
        &out->lock.nodes[out->lock.count++];
    memcpy(target->root, out->package_root, 32);
    if (!prepare_copy_field(target->name, sizeof(target->name), name) ||
        !prepare_copy_field(target->semver, sizeof(target->semver), semver)) {
        json_free(&meta);
        return VCS_PACKAGE_PREPARE_ERR_META;
    }
    target->depth = 0;
    target->direct_deps = (uint16_t)deps.count;
    derr = vcs_package_lock_serialize(&out->lock, &out->lock_wire,
                                      &out->lock_wire_len);
    if (derr != VCS_PACKAGE_DEPS_OK ||
        vcs_package_lock_root(&out->lock, out->lock_root) !=
            VCS_PACKAGE_DEPS_OK) {
        json_free(&meta);
        prepare_detail(walk, "lock: %s", vcs_package_deps_error_string(derr));
        return VCS_PACKAGE_PREPARE_ERR_LOCK;
    }
    enum vcs_package_capsule_error cerr = vcs_package_capsule_derive(
        &out->manifest, &out->recipe, &out->capsule);
    if (cerr != VCS_PACKAGE_CAPSULE_OK ||
        vcs_package_capsule_serialize(&out->capsule, &out->capsule_wire,
                                      &out->capsule_wire_len) !=
            VCS_PACKAGE_CAPSULE_OK ||
        vcs_package_capsule_root(&out->capsule, out->capsule_root) !=
            VCS_PACKAGE_CAPSULE_OK) {
        json_free(&meta);
        prepare_detail(walk, "capsule: %s",
                       vcs_package_capsule_error_string(cerr));
        return VCS_PACKAGE_PREPARE_ERR_CAPSULE;
    }
    memset(&out->release, 0, sizeof(out->release));
    out->release.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    memcpy(out->release.package_root, out->package_root, 32);
    memcpy(out->release.recipe_root, out->recipe_root, 32);
    memcpy(out->release.publisher_pubkey, options->publisher_pubkey,
           VCS_PACKAGE_RELEASE_PUBKEY_BYTES);
    out->release.publisher_sequence = options->publisher_sequence;
    const char *reward = options->reward_address ? options->reward_address : "";
    const char *chain = options->chain_id ? options->chain_id : "zclassic-main";
    bool fields_ok =
        prepare_copy_field(out->release.name, sizeof(out->release.name), name) &&
        prepare_copy_field(out->release.semver, sizeof(out->release.semver), semver) &&
        prepare_copy_field(out->release.license, sizeof(out->release.license), license) &&
        prepare_copy_field(out->release.reward_address,
                           sizeof(out->release.reward_address), reward) &&
        prepare_copy_field(out->release.chain_id,
                           sizeof(out->release.chain_id), chain);
    json_free(&meta);
    if (!fields_ok || vcs_package_release_validate(&out->release) !=
                          VCS_PACKAGE_RELEASE_OK ||
        vcs_package_release_id(&out->release, out->signing_digest) !=
                          VCS_PACKAGE_RELEASE_OK)
        return VCS_PACKAGE_PREPARE_ERR_RELEASE;
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    enum vcs_package_release_error relerr = vcs_package_release_serialize(
        &out->release, &release_wire, &release_wire_len);
    if (relerr != VCS_PACKAGE_RELEASE_OK ||
        release_wire_len < VCS_PACKAGE_RELEASE_SIGNATURE_BYTES) {
        free(release_wire);
        return VCS_PACKAGE_PREPARE_ERR_RELEASE;
    }
    out->release_body_len =
        release_wire_len - VCS_PACKAGE_RELEASE_SIGNATURE_BYTES;
    out->release_body = zcl_malloc(out->release_body_len,
                                   "vcs.package.prepare.release_body");
    if (!out->release_body) {
        free(release_wire);
        return VCS_PACKAGE_PREPARE_ERR_ALLOC;
    }
    memcpy(out->release_body, release_wire, out->release_body_len);
    free(release_wire);
    return VCS_PACKAGE_PREPARE_OK;
}

enum vcs_package_prepare_error vcs_package_prepare(
    const struct vcs_package_prepare_options *options,
    struct vcs_package_prepared *out, char *detail, size_t detail_cap)
{
    if (!options || !options->dir || !out)
        return VCS_PACKAGE_PREPARE_ERR_NULL;
    vcs_package_prepared_init(out);
    if (detail && detail_cap)
        detail[0] = '\0';
    int root_fd = open(options->dir,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap, "%s: %s", options->dir,
                           strerror(errno));
        return VCS_PACKAGE_PREPARE_ERR_PATH;
    }
    struct prepare_walk walk = {
        .out = out,
        .error = VCS_PACKAGE_PREPARE_OK,
        .detail = detail,
        .detail_cap = detail_cap,
    };
    bool walked = prepare_walk_dir(&walk, root_fd, "");
    close(root_fd);
    enum vcs_package_prepare_error err = walked
        ? prepare_finish(options, &walk) : walk.error;
    free(walk.meta);
    if (err != VCS_PACKAGE_PREPARE_OK) {
        vcs_package_prepared_free(out);
        vcs_package_prepared_init(out);
    }
    return err;
}

enum vcs_package_prepare_error vcs_package_scan_layout(
    const char *dir, struct vcs_package_prepared *out,
    bool *has_package_config, char *detail, size_t detail_cap)
{
    if (!dir || !out || !has_package_config)
        return VCS_PACKAGE_PREPARE_ERR_NULL;
    vcs_package_prepared_init(out);
    *has_package_config = false;
    if (detail && detail_cap)
        detail[0] = '\0';
    int root_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap, "%s: %s", dir,
                           strerror(errno));
        return VCS_PACKAGE_PREPARE_ERR_PATH;
    }
    struct prepare_walk walk = {
        .out = out,
        .error = VCS_PACKAGE_PREPARE_OK,
        .detail = detail,
        .detail_cap = detail_cap,
    };
    bool walked = prepare_walk_dir(&walk, root_fd, "");
    close(root_fd);
    enum vcs_package_prepare_error err = walked
        ? VCS_PACKAGE_PREPARE_OK : walk.error;
    *has_package_config = walk.meta != NULL;
    free(walk.meta);
    if (err == VCS_PACKAGE_PREPARE_OK) {
        enum vcs_package_recipe_error rerr = VCS_PACKAGE_RECIPE_OK;
        if (out->recipe.public_headers.count > 0 &&
            !vcs_package_recipe_add_include_dir(&out->recipe, "include",
                                                &rerr)) {
            if (detail && detail_cap)
                (void)snprintf(detail, detail_cap, "recipe include: %s",
                               vcs_package_recipe_error_string(rerr));
            err = VCS_PACKAGE_PREPARE_ERR_RECIPE;
        }
        if (err == VCS_PACKAGE_PREPARE_OK) {
            vcs_package_recipe_set_test_limits(&out->recipe, 0,
                                               PREPARE_TEST_SECONDS,
                                               PREPARE_TEST_MEMORY);
            rerr = vcs_package_recipe_validate(&out->recipe);
            if (rerr != VCS_PACKAGE_RECIPE_OK) {
                if (detail && detail_cap)
                    (void)snprintf(detail, detail_cap, "recipe: %s",
                                   vcs_package_recipe_error_string(rerr));
                err = VCS_PACKAGE_PREPARE_ERR_RECIPE;
            }
        }
    }
    if (err != VCS_PACKAGE_PREPARE_OK) {
        vcs_package_prepared_free(out);
        vcs_package_prepared_init(out);
        *has_package_config = false;
    }
    return err;
}
