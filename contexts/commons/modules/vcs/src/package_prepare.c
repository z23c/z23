/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: safely traverse package trees and derive canonical release inputs. */

#define _POSIX_C_SOURCE 200809L

#include "vcs/package_prepare.h"
#include "json/json.h"
#include "util/safe_alloc.h"

#include "package_prepare_internal.h"

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* Allocates the chunk digests and the one read buffer for a file of `chunks`
 * chunks. Both stay NULL for an empty file. On failure either may be set, so
 * the caller frees both. */
static bool prepare_regular_alloc(struct prepare_walk *walk, const char *path,
                                  uint32_t chunks, uint8_t **hashes,
                                  uint8_t **buf)
{
    if (!chunks)
        return true;
    *hashes = zcl_malloc((size_t)chunks * 32u, "vcs.package.prepare.hashes");
    *buf = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES, "vcs.package.prepare.chunk");
    if (!*hashes || !*buf) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_ALLOC;
        prepare_detail(walk, "%s: chunk allocation", path);
        return false;
    }
    return true;
}

/* Reads and digests the file in bounded chunks, in order. */
static bool prepare_regular_hash(struct prepare_walk *walk, int fd,
                                 const char *path, uint64_t size,
                                 uint32_t chunks, uint8_t *hashes,
                                 uint8_t *buf)
{
    uint64_t left = size;
    for (uint32_t i = 0; i < chunks; i++) {
        size_t want = left > VCS_PACKAGE_CHUNK_BYTES
            ? VCS_PACKAGE_CHUNK_BYTES : (size_t)left;
        if (!prepare_read_exact(fd, buf, want) ||
            !vcs_package_chunk_hash(buf, want, hashes + (size_t)i * 32u)) {
            walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
            prepare_detail(walk, "%s: read chunk %u", path, i);
            return false;
        }
        left -= want;
    }
    return true;
}

static bool prepare_recipe_file(struct prepare_walk *walk, const char *path)
{
    enum vcs_package_recipe_error err = VCS_PACKAGE_RECIPE_OK;
    size_t len = strlen(path);
    /* A file under app/ is NEVER classified here. Programs are DECLARED by
     * the author in zcode-package.json (see prepare_apply_programs) and
     * inferring them from the tree would silently move the root of every
     * package that happens to carry an app/ directory, and would declare a
     * program the recipe's libc/libm/pthread allowlist may not be able to
     * link. Fetched C is inert until its author says what it ships. */
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

/* Root-level local control and generated-output directories do not enter
 * package identity. Nested same-named directories stay visible. A symlink
 * or special file with these names is refused by the walk caller. */
static bool prepare_local_control_dir(const char *prefix, const char *name)
{
    return prefix[0] == '\0' &&
           (strcmp(name, ".zvcs") == 0 || strcmp(name, ".codeindex") == 0 ||
            strcmp(name, "build") == 0);
}

/* Joins one listed name under the walk prefix into a canonical package path.
 * A name that does not fit the buffer or is not a valid package path is
 * refused before anything is opened. */
static bool prepare_child_path(struct prepare_walk *walk, const char *prefix,
                               const char *name, char *path, size_t cap)
{
    int n = prefix[0]
        ? snprintf(path, cap, "%s/%s", prefix, name)
        : snprintf(path, cap, "%s", name);
    if (n <= 0 || (size_t)n >= cap || !vcs_package_path_valid(path)) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_PATH;
        prepare_detail(walk, "%s: non-canonical package path", path);
        return false;
    }
    return true;
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

/* Each declared program must be an app/<stem>.c path that is one of the
 * package's own files and is not repeated. The recipe holds the list. */
static bool prepare_programs_entries(struct prepare_walk *walk,
                                     const struct json_value *programs)
{
    for (size_t i = 0; i < programs->num_children; i++) {
        const char *path = json_get_str(&programs->children[i]);
        if (!path || !vcs_package_recipe_program_path_valid(path)) {
            prepare_detail(walk, "programs[%zu] is not app/<stem>.c: %s", i,
                           path ? path : "(not a string)");
            return false;
        }
        if (!prepare_manifest_find(&walk->out->manifest, path)) {
            prepare_detail(walk, "programs[%zu] is not in files: %s", i, path);
            return false;
        }
        enum vcs_package_recipe_error rerr = VCS_PACKAGE_RECIPE_OK;
        if (!vcs_package_recipe_add_program(&walk->out->recipe, path, &rerr)) {
            prepare_detail(walk, "programs[%zu] %s: %s", i,
                           rerr == VCS_PACKAGE_RECIPE_ERR_LIST_ORDER
                               ? "repeats" : "rejected",
                           path);
            return false;
        }
    }
    return true;
}

/* No two declared programs may emit one install output. The short name is
 * the part of the package name after the publisher's slash. */
static bool prepare_programs_collide(struct prepare_walk *walk,
                                     const char *name)
{
    const char *slash = strchr(name, '/');
    const char *short_name = slash ? slash + 1 : name;
    const struct vcs_package_recipe_strings *list = &walk->out->recipe.programs;
    for (size_t i = 0; i < list->count; i++) {
        char output[VCS_PACKAGE_PATH_MAX];
        if (!vcs_package_recipe_program_output(list->items[i], short_name,
                                               output, sizeof(output))) {
            prepare_detail(walk, "program output undefined: %s",
                           list->items[i]);
            return false;
        }
        for (size_t j = i + 1u; j < list->count; j++) {
            char other[VCS_PACKAGE_PATH_MAX];
            if (!vcs_package_recipe_program_output(list->items[j], short_name,
                                                   other, sizeof(other)))
                continue; /* named on its own pass */
            if (strcmp(output, other) == 0) {
                prepare_detail(walk,
                               "program output collision: %s and %s both "
                               "emit %s", list->items[i], list->items[j],
                               output);
                return false;
            }
        }
    }
    return true;
}

/* The optional "programs" key is how an author says which of the package's
 * own translation units are the applications a person runs, as opposed to
 * the library everything else links. It is DECLARED, never inferred: a
 * package may carry an app/ directory whose mains this recipe's system
 * library allowlist could never link, and a package that ships no program
 * must keep encoding as schema 1 so its recipe root does not move. An
 * absent key and an empty array are the same statement — this package
 * installs no executable.
 *
 * Each entry must be exactly `app/<stem>.c`, must be one of the package's
 * own files, must not repeat, and must not share an install output with
 * another entry. That last rule is real: `app/main.c` emits
 * bin/<package short name>, so a package that also declares
 * `app/<short name>.c` has two translation units claiming one path, and the
 * build receipt the external verifier writes could only carry it as a
 * duplicate output — a rejection at the end of a full compile instead of
 * here, where the publisher can still rename the file. The short name is
 * the part of `name` after the publisher's slash, exactly as the verifier
 * derives lib<short name>.a. */
static bool prepare_apply_programs(struct prepare_walk *walk,
                                   const struct json_value *meta,
                                   const char *name)
{
    const struct json_value *programs = json_get(meta, "programs");
    if (!programs)
        return true;
    if (programs->type != JSON_ARR) {
        prepare_detail(walk, "programs must be an array of app/<stem>.c paths");
        return false;
    }
    if (programs->num_children > VCS_PACKAGE_RECIPE_MAX_PROGRAMS) {
        prepare_detail(walk, "programs must contain at most %u paths",
                       VCS_PACKAGE_RECIPE_MAX_PROGRAMS);
        return false;
    }
    return prepare_programs_entries(walk, programs) &&
           prepare_programs_collide(walk, name);
}

/* The C23 v1 layout strings, read once from the parsed metadata. The pointers
 * borrow from that tree and are valid only until it is freed. */
struct prepare_meta_strings {
    const char *name;
    const char *semver;
    const char *license;
    const char *language;
    const char *include_dir;
    const char *source_dir;
};

/* Working state of the finish stages. The dependency detail buffer is shared
 * by the dependency parse and the recipe check, as it always was. */
struct prepare_finish_state {
    struct prepare_meta_strings fields;
    struct vcs_package_deps deps;
    char dep_detail[160];
};

/* True iff the metadata is schema 1 with every required string present and
 * the fixed c23 language and include/src layout. Reads only. */
static bool prepare_meta_fields(const struct json_value *meta,
                                struct prepare_meta_strings *f)
{
    const struct json_value *schema = json_get(meta, "schema");
    f->name = prepare_meta_string(meta, "name");
    f->semver = prepare_meta_string(meta, "semver");
    f->license = prepare_meta_string(meta, "license");
    f->language = prepare_meta_string(meta, "language");
    f->include_dir = prepare_meta_string(meta, "include_dir");
    f->source_dir = prepare_meta_string(meta, "source_dir");
    return schema && schema->type == JSON_INT && json_get_int(schema) == 1 &&
           f->name && f->semver && f->license && f->language &&
           f->include_dir && f->source_dir &&
           strcmp(f->language, "c23") == 0 &&
           strcmp(f->include_dir, "include") == 0 &&
           strcmp(f->source_dir, "src") == 0;
}

/* Stage 1: the closed shape, the file selection, the declared dependencies
 * and the declared programs. Each refusal names its own error. */
static enum vcs_package_prepare_error prepare_finish_admit(
    struct prepare_walk *walk, const struct json_value *meta,
    struct prepare_finish_state *st)
{
    if (!prepare_meta_fields(meta, &st->fields) ||
        !prepare_meta_closed(meta, walk->detail, walk->detail_cap)) {
        if (!walk->detail || walk->detail[0] == '\0')
            prepare_detail(walk, "metadata schema is not the closed C23 v1 shape");
        return VCS_PACKAGE_PREPARE_ERR_META;
    }
    if (!prepare_apply_file_selection(walk, meta))
        return VCS_PACKAGE_PREPARE_ERR_META;
    enum vcs_package_deps_error derr = vcs_package_deps_parse_meta(
        walk->meta, walk->meta_len, &st->deps, st->dep_detail,
        sizeof(st->dep_detail));
    if (derr != VCS_PACKAGE_DEPS_OK) {
        prepare_detail(walk, "dependencies: %s (%s)",
                       vcs_package_deps_error_string(derr), st->dep_detail);
        return VCS_PACKAGE_PREPARE_ERR_LOCK;
    }
    if (!prepare_apply_programs(walk, meta, st->fields.name))
        return VCS_PACKAGE_PREPARE_ERR_RECIPE;
    return VCS_PACKAGE_PREPARE_OK;
}

/* The include directory and the test limits every recipe carries. */
static bool prepare_recipe_limits(struct prepare_walk *walk)
{
    struct vcs_package_prepared *out = walk->out;
    enum vcs_package_recipe_error rerr = VCS_PACKAGE_RECIPE_OK;
    if (out->recipe.public_headers.count > 0 &&
        !vcs_package_recipe_add_include_dir(&out->recipe, "include", &rerr)) {
        prepare_detail(walk, "recipe include: %s",
                       vcs_package_recipe_error_string(rerr));
        return false;
    }
    vcs_package_recipe_set_test_limits(&out->recipe, 0,
                                       PREPARE_TEST_SECONDS,
                                       PREPARE_TEST_MEMORY);
    return true;
}

/* Stage 2: the include directory, the test limits, a valid recipe whose files
 * are all in the manifest, and the manifest and recipe wire forms and roots. */
static enum vcs_package_prepare_error prepare_finish_recipe(
    struct prepare_walk *walk, struct prepare_finish_state *st)
{
    struct vcs_package_prepared *out = walk->out;
    if (!prepare_recipe_limits(walk))
        return VCS_PACKAGE_PREPARE_ERR_RECIPE;
    enum vcs_package_recipe_error rerr =
        vcs_package_recipe_validate(&out->recipe);
    if (rerr != VCS_PACKAGE_RECIPE_OK ||
        !vcs_package_recipe_files_in_manifest(&out->recipe, &out->manifest,
                                               st->dep_detail,
                                               sizeof(st->dep_detail))) {
        prepare_detail(walk, "recipe: %s (%s)",
                       vcs_package_recipe_error_string(rerr), st->dep_detail);
        return VCS_PACKAGE_PREPARE_ERR_RECIPE;
    }
    if (!vcs_package_manifest_serialize(&out->manifest, &out->manifest_wire,
                                        &out->manifest_wire_len) ||
        !vcs_package_manifest_root(&out->manifest, out->package_root))
        return VCS_PACKAGE_PREPARE_ERR_MANIFEST;
    rerr = vcs_package_recipe_serialize(&out->recipe, &out->recipe_wire,
                                        &out->recipe_wire_len);
    if (rerr != VCS_PACKAGE_RECIPE_OK ||
        vcs_package_recipe_root(&out->recipe, out->recipe_root) !=
            VCS_PACKAGE_RECIPE_OK)
        return VCS_PACKAGE_PREPARE_ERR_RECIPE;
    return VCS_PACKAGE_PREPARE_OK;
}

/* Stage 4: the declared-graph lock. Its target node is the package itself, and
 * each declared dependency is a depth-1 node. */
static enum vcs_package_prepare_error prepare_finish_lock(
    struct prepare_walk *walk, const struct prepare_finish_state *st)
{
    struct vcs_package_prepared *out = walk->out;
    const struct vcs_package_deps *deps = &st->deps;
    if (deps->count + 1u > VCS_PACKAGE_LOCK_MAX_NODES)
        return VCS_PACKAGE_PREPARE_ERR_LOCK;
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
    for (size_t i = 0; i < deps->count; i++) {
        struct vcs_package_lock_node *node = &out->lock.nodes[out->lock.count++];
        memcpy(node->root, deps->items[i].root, 32);
        memcpy(node->name, deps->items[i].name, strlen(deps->items[i].name) + 1u);
        memcpy(node->semver, deps->items[i].semver,
               strlen(deps->items[i].semver) + 1u);
        node->depth = 1;
        node->direct_deps = 0;
    }
    struct vcs_package_lock_node *target =
        &out->lock.nodes[out->lock.count++];
    memcpy(target->root, out->package_root, 32);
    if (!prepare_copy_field(target->name, sizeof(target->name), st->fields.name) ||
        !prepare_copy_field(target->semver, sizeof(target->semver),
                            st->fields.semver))
        return VCS_PACKAGE_PREPARE_ERR_META;
    target->depth = 0;
    target->direct_deps = (uint16_t)deps->count;
    enum vcs_package_deps_error derr = vcs_package_lock_serialize(
        &out->lock, &out->lock_wire, &out->lock_wire_len);
    if (derr != VCS_PACKAGE_DEPS_OK ||
        vcs_package_lock_root(&out->lock, out->lock_root) !=
            VCS_PACKAGE_DEPS_OK) {
        prepare_detail(walk, "lock: %s", vcs_package_deps_error_string(derr));
        return VCS_PACKAGE_PREPARE_ERR_LOCK;
    }
    return VCS_PACKAGE_PREPARE_OK;
}

/* Stage 5: the API capsule derived from the manifest and the recipe. */
static enum vcs_package_prepare_error prepare_finish_capsule(
    struct prepare_walk *walk)
{
    struct vcs_package_prepared *out = walk->out;
    enum vcs_package_capsule_error cerr = vcs_package_capsule_derive(
        &out->manifest, &out->recipe, &out->capsule);
    if (cerr != VCS_PACKAGE_CAPSULE_OK ||
        vcs_package_capsule_serialize(&out->capsule, &out->capsule_wire,
                                      &out->capsule_wire_len) !=
            VCS_PACKAGE_CAPSULE_OK ||
        vcs_package_capsule_root(&out->capsule, out->capsule_root) !=
            VCS_PACKAGE_CAPSULE_OK) {
        prepare_detail(walk, "capsule: %s",
                       vcs_package_capsule_error_string(cerr));
        return VCS_PACKAGE_PREPARE_ERR_CAPSULE;
    }
    return VCS_PACKAGE_PREPARE_OK;
}

/* Stage 6: the release body the publisher signs. The signature bytes are not
 * part of the body that is kept. */
static enum vcs_package_prepare_error prepare_finish_release(
    struct prepare_walk *walk,
    const struct vcs_package_prepare_options *options,
    const struct prepare_meta_strings *f)
{
    struct vcs_package_prepared *out = walk->out;
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
        prepare_copy_field(out->release.name, sizeof(out->release.name), f->name) &&
        prepare_copy_field(out->release.semver, sizeof(out->release.semver), f->semver) &&
        prepare_copy_field(out->release.license, sizeof(out->release.license), f->license) &&
        prepare_copy_field(out->release.reward_address,
                           sizeof(out->release.reward_address), reward) &&
        prepare_copy_field(out->release.chain_id,
                           sizeof(out->release.chain_id), chain);
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

/* Runs the stages in order and stops at the first refusal. The parsed metadata
 * stays alive until the caller frees it, after every stage has read it. */
static enum vcs_package_prepare_error prepare_finish_meta(
    const struct vcs_package_prepare_options *options,
    struct prepare_walk *walk, const struct json_value *meta)
{
    struct prepare_finish_state st = {0};
    enum vcs_package_prepare_error err =
        prepare_finish_admit(walk, meta, &st);
    if (err == VCS_PACKAGE_PREPARE_OK)
        err = prepare_finish_recipe(walk, &st);
    if (err == VCS_PACKAGE_PREPARE_OK)
        err = prepare_finish_lock(walk, &st);
    if (err == VCS_PACKAGE_PREPARE_OK)
        err = prepare_finish_capsule(walk);
    if (err == VCS_PACKAGE_PREPARE_OK)
        err = prepare_finish_release(walk, options, &st.fields);
    return err;
}

static enum vcs_package_prepare_error prepare_finish(
    const struct vcs_package_prepare_options *options,
    struct prepare_walk *walk)
{
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
    enum vcs_package_prepare_error err =
        prepare_finish_meta(options, walk, &meta);
    json_free(&meta);
    return err;
}

/* The recipe half of a layout scan: the include, test-limit and validity
 * rules of the full prepare, run only after a clean walk. */
static enum vcs_package_prepare_error prepare_scan_recipe(
    struct prepare_walk *walk)
{
    if (!prepare_recipe_limits(walk))
        return VCS_PACKAGE_PREPARE_ERR_RECIPE;
    enum vcs_package_recipe_error rerr =
        vcs_package_recipe_validate(&walk->out->recipe);
    if (rerr != VCS_PACKAGE_RECIPE_OK) {
        prepare_detail(walk, "recipe: %s",
                       vcs_package_recipe_error_string(rerr));
        return VCS_PACKAGE_PREPARE_ERR_RECIPE;
    }
    return VCS_PACKAGE_PREPARE_OK;
}

#ifdef _WIN32

#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <wchar.h>
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *prepare_nt_create_file_fn)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *prepare_nt_query_directory_file_fn)(
    HANDLE, HANDLE, PVOID, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG,
    FILE_INFORMATION_CLASS, BOOLEAN, PUNICODE_STRING, BOOLEAN);

struct prepare_windows_entry {
    char *name;
    uint64_t file_id;
};

struct prepare_windows_snapshot {
    uint64_t size;
    uint64_t volume;
    uint64_t file_id;
    int64_t modified;
    int64_t changed;
};

static wchar_t *prepare_utf8_to_wide(const char *path)
{
    if (!path) return NULL;
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                NULL, 0);
    if (n <= 0) return NULL;
    wchar_t *wide = zcl_malloc((size_t)n * sizeof(*wide),
                               "vcs.package.prepare.wide");
    if (!wide || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                                      wide, n)) {
        free(wide);
        return NULL;
    }
    return wide;
}

static bool prepare_nt_functions(
    prepare_nt_create_file_fn *create_file,
    prepare_nt_query_directory_file_fn *query_directory)
{
    HMODULE module = GetModuleHandleW(L"ntdll.dll");
    FARPROC create_symbol = module ? GetProcAddress(module, "NtCreateFile") : NULL;
    FARPROC query_symbol = module
        ? GetProcAddress(module, "NtQueryDirectoryFile") : NULL;
    if (!create_symbol || !query_symbol)
        return false;
    static_assert(sizeof(*create_file) == sizeof(create_symbol));
    static_assert(sizeof(*query_directory) == sizeof(query_symbol));
    memcpy(create_file, &create_symbol, sizeof(*create_file));
    memcpy(query_directory, &query_symbol, sizeof(*query_directory));
    return true;
}

static bool prepare_windows_snapshot(HANDLE handle,
                                     struct prepare_windows_snapshot *out)
{
    BY_HANDLE_FILE_INFORMATION info = {0};
    FILE_BASIC_INFO basic = {0};
    if (!out || !GetFileInformationByHandle(handle, &info) ||
        !GetFileInformationByHandleEx(handle, FileBasicInfo, &basic,
                                      sizeof(basic)))
        return false;
    out->size = ((uint64_t)info.nFileSizeHigh << 32) | info.nFileSizeLow;
    out->volume = info.dwVolumeSerialNumber;
    out->file_id = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    out->modified = basic.LastWriteTime.QuadPart;
    out->changed = basic.ChangeTime.QuadPart;
    return true;
}

static bool prepare_windows_snapshot_same(
    const struct prepare_windows_snapshot *a,
    const struct prepare_windows_snapshot *b)
{
    return a->size == b->size && a->volume == b->volume &&
           a->file_id == b->file_id && a->modified == b->modified &&
           a->changed == b->changed;
}

static HANDLE prepare_open_child(HANDLE parent, const char *name,
                                 prepare_nt_create_file_fn create_file)
{
    wchar_t wide[260];
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, name, -1,
                                    wide, 260);
    if (count <= 1 || strchr(name, '/') || strchr(name, '\\') ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return INVALID_HANDLE_VALUE;
    UNICODE_STRING leaf = {
        .Length = (USHORT)((count - 1) * (int)sizeof(*wide)),
        .MaximumLength = (USHORT)((count - 1) * (int)sizeof(*wide)),
        .Buffer = wide,
    };
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes, &leaf, 0, parent, NULL);
    IO_STATUS_BLOCK io_status = {0};
    HANDLE child = INVALID_HANDLE_VALUE;
    NTSTATUS status = create_file(
        &child, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes, &io_status, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    return status >= 0 ? child : INVALID_HANDLE_VALUE;
}

static bool prepare_append_entry(struct prepare_windows_entry **entries,
                                 size_t *count, const wchar_t *wide,
                                 int wide_count, uint64_t file_id)
{
    int bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide,
                                    wide_count, NULL, 0, NULL, NULL);
    if (bytes <= 0 || *count >= SIZE_MAX / sizeof(**entries))
        return false;
    char *name = zcl_malloc((size_t)bytes + 1u,
                            "vcs.package.prepare.win.name");
    struct prepare_windows_entry *grown = name ? zcl_realloc(
        *entries, (*count + 1u) * sizeof(**entries),
        "vcs.package.prepare.win.entries") : NULL;
    if (!grown) {
        free(name);
        return false;
    }
    *entries = grown;
    if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wide, wide_count,
                            name, bytes, NULL, NULL) != bytes) {
        free(name);
        return false;
    }
    name[bytes] = '\0';
    grown[*count] = (struct prepare_windows_entry){name, file_id};
    (*count)++;
    return true;
}

static int prepare_entry_compare(const void *left, const void *right)
{
    const struct prepare_windows_entry *a = left;
    const struct prepare_windows_entry *b = right;
    return strcmp(a->name, b->name);
}

static void prepare_entries_free(struct prepare_windows_entry *entries,
                                 size_t count)
{
    for (size_t i = 0; i < count; i++)
        free(entries[i].name);
    free(entries);
}

/* Admits the listed handle while it still names the listed object and is
 * within the size bound, then makes it a regular-file descriptor that owns the
 * handle. Returns the descriptor, or -1 after releasing the handle. */
static int prepare_regular_open_win(struct prepare_walk *walk, HANDLE handle,
                                    const char *pkg_path,
                                    uint64_t listed_file_id,
                                    struct prepare_windows_snapshot *before,
                                    struct stat *mode_info)
{
    if (!prepare_windows_snapshot(handle, before) ||
        (listed_file_id != 0 && before->file_id != 0 &&
         before->file_id != listed_file_id) ||
        before->size > VCS_PACKAGE_MAX_FILE_BYTES) {
        CloseHandle(handle);
        walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
        prepare_detail(walk, "%s: changed before read", pkg_path);
        return -1;
    }
    int fd = _open_osfhandle((intptr_t)handle, _O_RDONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(handle);
        walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
        prepare_detail(walk, "%s: _open_osfhandle", pkg_path);
        return -1;
    }
    if (fstat(fd, mode_info) != 0 || !S_ISREG(mode_info->st_mode)) {
        close(fd);
        walk->error = VCS_PACKAGE_PREPARE_ERR_FILE_TYPE;
        prepare_detail(walk, "%s: not a regular file", pkg_path);
        return -1;
    }
    return fd;
}

/* The snapshot taken before the read must still describe the handle. */
static bool prepare_regular_unchanged_win(
    struct prepare_walk *walk, HANDLE handle, const char *pkg_path,
    const struct prepare_windows_snapshot *before)
{
    struct prepare_windows_snapshot after;
    if (prepare_windows_snapshot(handle, &after) &&
        prepare_windows_snapshot_same(before, &after))
        return true;
    walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
    prepare_detail(walk, "%s: changed while read", pkg_path);
    return false;
}

/* Only the closed package-config path is read into memory, bounded and
 * re-checked against the same snapshot as the content. */
static bool prepare_regular_metadata_win(
    struct prepare_walk *walk, int fd, HANDLE handle, const char *pkg_path,
    const struct prepare_windows_snapshot *before)
{
    if (strcmp(pkg_path, VCS_PACKAGE_DEPS_META_PATH) != 0)
        return true;
    uint64_t size = before->size;
    if (size > PREPARE_META_MAX || lseek(fd, 0, SEEK_SET) < 0) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_META;
        prepare_detail(walk, "%s: metadata exceeds bound", pkg_path);
        return false;
    }
    walk->meta = zcl_malloc((size_t)size + 1u, "vcs.package.prepare.meta");
    if (!walk->meta || !prepare_read_exact(fd, walk->meta, (size_t)size)) {
        free(walk->meta); walk->meta = NULL;
        walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
        prepare_detail(walk, "%s: metadata read", pkg_path);
        return false;
    }
    struct prepare_windows_snapshot metadata_after;
    if (!prepare_windows_snapshot(handle, &metadata_after) ||
        !prepare_windows_snapshot_same(before, &metadata_after)) {
        free(walk->meta); walk->meta = NULL;
        walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
        prepare_detail(walk, "%s: changed during metadata read", pkg_path);
        return false;
    }
    walk->meta[size] = 0;
    walk->meta_len = (size_t)size;
    return true;
}

static bool prepare_regular(struct prepare_walk *walk, HANDLE handle,
                            const char *pkg_path,
                            uint64_t listed_file_id)
{
    struct prepare_windows_snapshot before;
    struct stat mode_info;
    int fd = prepare_regular_open_win(walk, handle, pkg_path, listed_file_id,
                                      &before, &mode_info);
    if (fd < 0)
        return false;
    uint64_t size = before.size;
    uint32_t chunks = size == 0 ? 0u :
        (uint32_t)(1u + (size - 1u) / VCS_PACKAGE_CHUNK_BYTES);
    uint8_t *hashes = NULL;
    uint8_t *buf = NULL;
    if (!prepare_regular_alloc(walk, pkg_path, chunks, &hashes, &buf) ||
        !prepare_regular_hash(walk, fd, pkg_path, size, chunks, hashes, buf) ||
        !prepare_regular_unchanged_win(walk, handle, pkg_path, &before) ||
        !prepare_regular_metadata_win(walk, fd, handle, pkg_path, &before)) {
        free(hashes); free(buf); close(fd);
        return false;
    }
    close(fd);
    uint32_t mode = (mode_info.st_mode & 0111u)
        ? VCS_PACKAGE_MODE_EXECUTABLE : VCS_PACKAGE_MODE_FILE;
    bool ok = vcs_package_manifest_add(&walk->out->manifest, pkg_path, mode,
                                       size, hashes, chunks) &&
              prepare_recipe_file(walk, pkg_path);
    free(hashes); free(buf);
    if (!ok) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_MANIFEST;
        prepare_detail(walk, "%s: manifest or recipe admission", pkg_path);
    }
    return ok;
}

/* Lists one directory with the native query, skipping . and .. and keeping
 * each entry's file id. A failed query or allocation leaves the entries read
 * so far in *entries for the caller to free. */
static bool prepare_list_records(struct prepare_walk *walk, const char *prefix,
                                 FILE_ID_BOTH_DIR_INFO *entry,
                                 struct prepare_windows_entry **entries,
                                 size_t *count)
{
    for (;;) {
        int chars = (int)(entry->FileNameLength / sizeof(wchar_t));
        bool dot = (chars == 1 && entry->FileName[0] == L'.') ||
            (chars == 2 && entry->FileName[0] == L'.' &&
             entry->FileName[1] == L'.');
        if (!dot && !prepare_append_entry(
                entries, count, entry->FileName, chars,
                (uint64_t)entry->FileId.QuadPart)) {
            walk->error = VCS_PACKAGE_PREPARE_ERR_ALLOC;
            prepare_detail(walk, "%s: directory entry allocation", prefix);
            return false;
        }
        if (!entry->NextEntryOffset)
            return true;
        entry = (FILE_ID_BOTH_DIR_INFO *)
            ((unsigned char *)entry + entry->NextEntryOffset);
    }
}

static bool prepare_walk_list(struct prepare_walk *walk, HANDLE directory,
                              const char *prefix,
                              prepare_nt_query_directory_file_fn query_directory,
                              struct prepare_windows_entry **entries,
                              size_t *count)
{
    bool restart = true;
    unsigned char buffer[16384];
    for (;;) {
        IO_STATUS_BLOCK io_status = {0};
        NTSTATUS status = query_directory(
            directory, NULL, NULL, NULL, &io_status, buffer, sizeof(buffer),
            FileIdBothDirectoryInformation, FALSE, NULL, restart ? TRUE : FALSE);
        restart = false;
        if ((ULONG)status == 0x80000006u)
            return true;
        if (status < 0 || io_status.Information == 0) {
            walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
            prepare_detail(walk, "%s: directory query failed (0x%08lx)",
                           prefix, (unsigned long)(ULONG)status);
            return false;
        }
        if (!prepare_list_records(walk, prefix,
                                  (FILE_ID_BOTH_DIR_INFO *)buffer,
                                  entries, count))
            return false;
    }
}

static bool prepare_walk_dir(
    struct prepare_walk *walk, HANDLE directory, const char *prefix,
    prepare_nt_create_file_fn create_file,
    prepare_nt_query_directory_file_fn query_directory);

/* Opens one listed child and admits it only while it is still the listed
 * object, is not a reparse point, and is a real directory or disk file. A
 * local control directory at the root is skipped without error. */
static bool prepare_walk_entry(
    struct prepare_walk *walk, HANDLE directory, const char *prefix,
    const char *name, const char *path, uint64_t listed_id,
    prepare_nt_create_file_fn create_file,
    prepare_nt_query_directory_file_fn query_directory)
{
    HANDLE child = prepare_open_child(directory, name, create_file);
    if (child == INVALID_HANDLE_VALUE) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
        prepare_detail(walk, "%s: changed before open", path);
        return false;
    }
    BY_HANDLE_FILE_INFORMATION info = {0};
    if (!GetFileInformationByHandle(child, &info)) {
        CloseHandle(child);
        walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
        prepare_detail(walk, "%s: handle information", path);
        return false;
    }
    uint64_t file_id = ((uint64_t)info.nFileIndexHigh << 32) | info.nFileIndexLow;
    if (file_id != 0 && listed_id != 0 && file_id != listed_id) {
        CloseHandle(child);
        walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
        prepare_detail(walk, "%s: changed after listing", path);
        return false;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
        CloseHandle(child);
        walk->error = VCS_PACKAGE_PREPARE_ERR_FILE_TYPE;
        prepare_detail(walk, "%s: reparse point refused", path);
        return false;
    }
    if ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        bool ok = true;
        if (!prepare_local_control_dir(prefix, name))
            ok = prepare_walk_dir(walk, child, path, create_file,
                                  query_directory);
        CloseHandle(child);
        return ok;
    }
    if (GetFileType(child) == FILE_TYPE_DISK)
        return prepare_regular(walk, child, path, listed_id);
    CloseHandle(child);
    walk->error = VCS_PACKAGE_PREPARE_ERR_FILE_TYPE;
    prepare_detail(walk, "%s: special file refused", path);
    return false;
}

static bool prepare_walk_dir(
    struct prepare_walk *walk, HANDLE directory, const char *prefix,
    prepare_nt_create_file_fn create_file,
    prepare_nt_query_directory_file_fn query_directory)
{
    struct prepare_windows_entry *entries = NULL;
    size_t count = 0;
    bool ok = prepare_walk_list(walk, directory, prefix, query_directory,
                                &entries, &count);
    if (count > 1)
        qsort(entries, count, sizeof(*entries), prepare_entry_compare);
    for (size_t i = 0; i < count && ok; i++) {
        char path[VCS_PACKAGE_PATH_MAX + 1u];
        ok = prepare_child_path(walk, prefix, entries[i].name, path,
                                sizeof(path)) &&
             prepare_walk_entry(walk, directory, prefix, entries[i].name,
                                path, entries[i].file_id, create_file,
                                query_directory);
    }
    prepare_entries_free(entries, count);
    return ok;
}

static HANDLE prepare_open_root(const char *dir, char *detail,
                                size_t detail_cap)
{
    wchar_t *wide = prepare_utf8_to_wide(dir);
    if (!wide) {
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap, "%s: utf8 conversion", dir);
        return INVALID_HANDLE_VALUE;
    }
    HANDLE root = CreateFileW(
        wide, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    free(wide);
    BY_HANDLE_FILE_INFORMATION info = {0};
    if (root == INVALID_HANDLE_VALUE ||
        !GetFileInformationByHandle(root, &info) ||
        !(info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        if (root != INVALID_HANDLE_VALUE)
            CloseHandle(root);
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap, "%s: not a real directory", dir);
        return INVALID_HANDLE_VALUE;
    }
    return root;
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
    prepare_nt_create_file_fn create_file = NULL;
    prepare_nt_query_directory_file_fn query_directory = NULL;
    HANDLE root = prepare_open_root(options->dir, detail, detail_cap);
    if (root == INVALID_HANDLE_VALUE)
        return VCS_PACKAGE_PREPARE_ERR_PATH;
    if (!prepare_nt_functions(&create_file, &query_directory)) {
        CloseHandle(root);
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap,
                           "Windows native directory APIs unavailable");
        return VCS_PACKAGE_PREPARE_ERR_IO;
    }
    struct prepare_walk walk = {
        .out = out,
        .error = VCS_PACKAGE_PREPARE_OK,
        .detail = detail,
        .detail_cap = detail_cap,
    };
    bool walked = prepare_walk_dir(&walk, root, "", create_file,
                                   query_directory);
    CloseHandle(root);
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
    prepare_nt_create_file_fn create_file = NULL;
    prepare_nt_query_directory_file_fn query_directory = NULL;
    HANDLE root = prepare_open_root(dir, detail, detail_cap);
    if (root == INVALID_HANDLE_VALUE)
        return VCS_PACKAGE_PREPARE_ERR_PATH;
    if (!prepare_nt_functions(&create_file, &query_directory)) {
        CloseHandle(root);
        if (detail && detail_cap)
            (void)snprintf(detail, detail_cap,
                           "Windows native directory APIs unavailable");
        return VCS_PACKAGE_PREPARE_ERR_IO;
    }
    struct prepare_walk walk = {
        .out = out,
        .error = VCS_PACKAGE_PREPARE_OK,
        .detail = detail,
        .detail_cap = detail_cap,
    };
    bool walked = prepare_walk_dir(&walk, root, "", create_file,
                                   query_directory);
    CloseHandle(root);
    enum vcs_package_prepare_error err = walked
        ? VCS_PACKAGE_PREPARE_OK : walk.error;
    *has_package_config = walk.meta != NULL;
    free(walk.meta);
    if (err == VCS_PACKAGE_PREPARE_OK)
        err = prepare_scan_recipe(&walk);
    if (err != VCS_PACKAGE_PREPARE_OK) {
        vcs_package_prepared_free(out);
        vcs_package_prepared_init(out);
        *has_package_config = false;
    }
    return err;
}

#else

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static bool prepare_stat_same(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
           a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}

/* Opens the listed name without following links and admits only a regular
 * file that is still the listed object and is within the size bound. On
 * success *fd is open and *before holds the stat the read is checked against. */
static bool prepare_regular_open(struct prepare_walk *walk, int parent_fd,
                                 const char *name, const char *path,
                                 const struct stat *listed, int *fd,
                                 struct stat *before)
{
    *fd = openat(parent_fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (*fd < 0) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
        prepare_detail(walk, "%s: open: %s", path, strerror(errno));
        return false;
    }
    if (fstat(*fd, before) != 0 || !S_ISREG(before->st_mode) ||
        before->st_dev != listed->st_dev || before->st_ino != listed->st_ino ||
        before->st_size < 0 ||
        (uint64_t)before->st_size > VCS_PACKAGE_MAX_FILE_BYTES) {
        close(*fd);
        walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
        prepare_detail(walk, "%s: changed before read", path);
        return false;
    }
    return true;
}

/* The stat taken before the read must still describe the descriptor. */
static bool prepare_regular_unchanged(struct prepare_walk *walk, int fd,
                                      const char *path,
                                      const struct stat *before)
{
    struct stat after;
    if (fstat(fd, &after) == 0 && prepare_stat_same(before, &after))
        return true;
    walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
    prepare_detail(walk, "%s: changed while read", path);
    return false;
}

/* Only the closed package-config path is read into memory, bounded and
 * re-checked against the same stat as the content. */
static bool prepare_regular_metadata(struct prepare_walk *walk, int fd,
                                     const char *path,
                                     const struct stat *before)
{
    if (strcmp(path, VCS_PACKAGE_DEPS_META_PATH) != 0)
        return true;
    uint64_t size = (uint64_t)before->st_size;
    if (size > PREPARE_META_MAX || lseek(fd, 0, SEEK_SET) < 0) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_META;
        prepare_detail(walk, "%s: metadata exceeds bound", path);
        return false;
    }
    walk->meta = zcl_malloc((size_t)size + 1u, "vcs.package.prepare.meta");
    if (!walk->meta || !prepare_read_exact(fd, walk->meta, (size_t)size)) {
        free(walk->meta); walk->meta = NULL;
        walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
        prepare_detail(walk, "%s: metadata read", path);
        return false;
    }
    struct stat metadata_after;
    if (fstat(fd, &metadata_after) != 0 ||
        !prepare_stat_same(before, &metadata_after)) {
        free(walk->meta); walk->meta = NULL;
        walk->error = VCS_PACKAGE_PREPARE_ERR_CHANGED;
        prepare_detail(walk, "%s: changed during metadata read", path);
        return false;
    }
    walk->meta[size] = 0;
    walk->meta_len = (size_t)size;
    return true;
}

static bool prepare_regular(struct prepare_walk *walk, int parent_fd,
                            const char *name, const char *path,
                            const struct stat *listed)
{
    int fd = -1;
    struct stat before;
    if (!prepare_regular_open(walk, parent_fd, name, path, listed, &fd,
                              &before))
        return false;
    uint64_t size = (uint64_t)before.st_size;
    uint32_t chunks = size == 0 ? 0u :
        (uint32_t)(1u + (size - 1u) / VCS_PACKAGE_CHUNK_BYTES);
    uint8_t *hashes = NULL;
    uint8_t *buf = NULL;
    if (!prepare_regular_alloc(walk, path, chunks, &hashes, &buf) ||
        !prepare_regular_hash(walk, fd, path, size, chunks, hashes, buf) ||
        !prepare_regular_unchanged(walk, fd, path, &before) ||
        !prepare_regular_metadata(walk, fd, path, &before)) {
        free(hashes); free(buf); close(fd);
        return false;
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

static bool prepare_walk_dir(struct prepare_walk *walk, int dir_fd,
                             const char *prefix);

/* Walks a real child directory through its own descriptor. A local control
 * directory at the root is skipped without error. A child that cannot be
 * opened fails the walk without setting walk->error, as it always has. */
static bool prepare_walk_subdir(struct prepare_walk *walk, int dir_fd,
                                const char *prefix, const char *name,
                                const char *path)
{
    if (prepare_local_control_dir(prefix, name))
        return true;
    int child = openat(dir_fd, name,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    bool ok = child >= 0 && prepare_walk_dir(walk, child, path);
    if (child >= 0)
        close(child);
    return ok;
}

/* Admits one listed entry: a directory is walked, a regular file is read, and
 * anything else (a symlink or special file) is refused. */
static bool prepare_walk_entry(struct prepare_walk *walk, int dir_fd,
                               const char *prefix, const char *name,
                               const char *path)
{
    struct stat listed;
    if (fstatat(dir_fd, name, &listed, AT_SYMLINK_NOFOLLOW) != 0) {
        walk->error = VCS_PACKAGE_PREPARE_ERR_IO;
        prepare_detail(walk, "%s: stat: %s", path, strerror(errno));
        return false;
    }
    if (S_ISDIR(listed.st_mode))
        return prepare_walk_subdir(walk, dir_fd, prefix, name, path);
    if (S_ISREG(listed.st_mode))
        return prepare_regular(walk, dir_fd, name, path, &listed);
    walk->error = VCS_PACKAGE_PREPARE_ERR_FILE_TYPE;
    prepare_detail(walk, "%s: symlink or special file refused", path);
    return false;
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
        ok = prepare_child_path(walk, prefix, entry->d_name, path,
                                sizeof(path)) &&
             prepare_walk_entry(walk, dir_fd, prefix, entry->d_name, path);
    }
    closedir(dir);
    return ok;
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
    if (err == VCS_PACKAGE_PREPARE_OK)
        err = prepare_scan_recipe(&walk);
    if (err != VCS_PACKAGE_PREPARE_OK) {
        vcs_package_prepared_free(out);
        vcs_package_prepared_init(out);
        *has_package_config = false;
    }
    return err;
}

#endif
