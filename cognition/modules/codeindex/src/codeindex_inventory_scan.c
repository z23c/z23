/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Enumerate and stably scan the maintained C23 capability universe. */

#define _GNU_SOURCE
#include "codeindex_inventory_internal.h"

#include "base/serialize_le.h"
#include "sha3/sha3.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#if !defined(_WIN32)
#include <dirent.h>
#include <unistd.h>
#else
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#endif

enum { INV_PATH_MAX = 4096 };

/* Three shapes for the same two timestamps. Windows is the odd one out: its
 * struct stat carries only whole-second st_mtime/st_ctime, with no
 * nanosecond field of any spelling, so the sub-second component is reported
 * as zero rather than faked. Callers compare (sec, nsec) pairs, and a
 * constant zero nsec degrades that to second resolution on Windows instead
 * of making it wrong. */
#if defined(_WIN32)
#define INV_MTIME_SEC(st)  ((st).st_mtime)
#define INV_MTIME_NSEC(st) (0)
#define INV_CTIME_SEC(st)  ((st).st_ctime)
#define INV_CTIME_NSEC(st) (0)
#elif defined(__APPLE__)
#define INV_MTIME_SEC(st)  ((st).st_mtimespec.tv_sec)
#define INV_MTIME_NSEC(st) ((st).st_mtimespec.tv_nsec)
#define INV_CTIME_SEC(st)  ((st).st_ctimespec.tv_sec)
#define INV_CTIME_NSEC(st) ((st).st_ctimespec.tv_nsec)
#else
#define INV_MTIME_SEC(st)  ((st).st_mtim.tv_sec)
#define INV_MTIME_NSEC(st) ((st).st_mtim.tv_nsec)
#define INV_CTIME_SEC(st)  ((st).st_ctim.tv_sec)
#define INV_CTIME_NSEC(st) ((st).st_ctim.tv_nsec)
#endif

void inv_cpy(char *dst, size_t cap, const char *src)
{
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = '\0'; return; }
    size_t i = 0;
    for (; i + 1 < cap && src[i]; i++) dst[i] = src[i];
    dst[i] = '\0';
}

static bool inv_has_segment(const char *path, const char *segment)
{
    size_t n = strlen(segment);
    const char *p = path;
    while ((p = strstr(p, segment)) != NULL) {
        bool left = p == path || p[-1] == '/';
        bool right = p[n] == '\0' || p[n] == '/';
        if (left && right) return true;
        p++;
    }
    return false;
}

bool inv_is_test_path(const char *path)
{
    if (!path) return false;
    if (strncmp(path, "tests/harness/", sizeof("tests/harness/") - 1) == 0)
        return true;
    if (strncmp(path, "contexts/commons/packages/",
                sizeof("contexts/commons/packages/") - 1) == 0 &&
        (inv_has_segment(path, "tests") || inv_has_segment(path, "test")))
        return true;
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    return strncmp(base, "test_", 5) == 0 || strstr(path, "/test_") != NULL;
}

bool inv_is_public_header_path(const char *path)
{
    if (!path) return false;
    size_t n = strlen(path);
    if (n < 3 || strcmp(path + n - 2, ".h") != 0) return false;
    if (strncmp(path, "tests/harness/", sizeof("tests/harness/") - 1) == 0)
        return false;
    return strstr(path, "/include/") != NULL;
}

static void inv_second_component(const char *path, const char *top,
                                 char out[64])
{
    size_t n = strlen(top);
    const char *p = path + n + 1;
    const char *slash = strchr(p, '/');
    size_t len = slash ? (size_t)(slash - p) : strlen(p);
    if (len > 46) len = 46;
    (void)snprintf(out, 64, "%s/%.*s", top, (int)len, p);
}

void inv_group_for_path(const char *path, char out[64])
{
    out[0] = '\0';
    if (!path || !path[0]) return;
    static const char *const split[] = {
        "core", "engine", "contexts", "cognition", "platform", NULL
    };
    for (size_t i = 0; split[i]; i++) {
        size_t n = strlen(split[i]);
        if (strncmp(path, split[i], n) == 0 && path[n] == '/') {
            inv_second_component(path, split[i], out);
            return;
        }
    }
    const char *slash = strchr(path, '/');
    size_t n = slash ? (size_t)(slash - path) : strlen(path);
    if (n > 63) n = 63;
    (void)snprintf(out, 64, "%.*s", (int)n, path);
}

static bool inv_source_name(const char *name)
{
    size_t n = strlen(name);
    return n >= 2 && name[n - 2] == '.' &&
        (name[n - 1] == 'c' || name[n - 1] == 'h');
}

static bool inv_prune_dir(const char *name)
{
#define SOURCE_PRUNE_DIR(name_) if (strcmp(name, name_) == 0) return true;
#include "codeindex/source_prune_dirs.def"
#undef SOURCE_PRUNE_DIR
    return strncmp(name, "test-tmp", 8) == 0;
}

#if !defined(_WIN32)
static bool inv_path_push(struct inv_scan *s, const char *path,
                          const struct stat *st)
{
    if (s->path_count == s->path_cap) {
        int cap = s->path_cap ? s->path_cap * 2 : 1024;
        void *p = zcl_realloc(s->paths, (size_t)cap * sizeof(*s->paths),
                              "ci_inventory_paths");
        if (!p) return false;
        s->paths = p;
        s->path_cap = cap;
    }
    struct inv_path *row = &s->paths[s->path_count++];
    memset(row, 0, sizeof(*row));
    inv_cpy(row->path, sizeof(row->path), path);
    row->size = (int64_t)st->st_size;
    row->mtime_ns = (int64_t)INV_MTIME_SEC((*st)) * INT64_C(1000000000) +
                    (int64_t)INV_MTIME_NSEC((*st));
    row->ctime_ns = (int64_t)INV_CTIME_SEC((*st)) * INT64_C(1000000000) +
                    (int64_t)INV_CTIME_NSEC((*st));
    row->device = (uint64_t)st->st_dev;
    row->inode = (uint64_t)st->st_ino;
    return true;
}
#endif

#if defined(_WIN32)
static bool inv_snapshot_push(
    struct inv_scan *s, const char *path,
    const struct platform_positioned_file_snapshot *snapshot)
{
    if (s->path_count == s->path_cap) {
        int cap = s->path_cap ? s->path_cap * 2 : 1024;
        void *p = zcl_realloc(s->paths, (size_t)cap * sizeof(*s->paths),
                              "ci_inventory_paths");
        if (!p) return false;
        s->paths = p;
        s->path_cap = cap;
    }
    struct inv_path *row = &s->paths[s->path_count++];
    memset(row, 0, sizeof(*row));
    inv_cpy(row->path, sizeof(row->path), path);
    row->size = (int64_t)snapshot->size;
    row->mtime_ns = snapshot->modified_seconds * INT64_C(1000000000) +
                    snapshot->modified_nanoseconds;
    row->ctime_ns = snapshot->changed_seconds * INT64_C(1000000000) +
                    snapshot->changed_nanoseconds;
    row->device = snapshot->volume;
    row->inode = snapshot->file_low;
    return true;
}
#endif

#if !defined(_WIN32)
static bool inv_collect_dir(struct inv_scan *s, const char *rel)
{
    char full[INV_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", s->root, rel);
    if (n <= 0 || (size_t)n >= sizeof(full)) return false;
    DIR *dir = opendir(full);
    if (!dir) return errno == ENOENT;
    bool ok = true;
    struct dirent *entry;
    while (ok && (entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        char child[INV_PATH_MAX];
        n = snprintf(child, sizeof(child), "%s/%s", rel, entry->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) { ok = false; break; }
        char child_full[INV_PATH_MAX];
        n = snprintf(child_full, sizeof(child_full), "%s/%s", s->root, child);
        if (n <= 0 || (size_t)n >= sizeof(child_full)) { ok = false; break; }
        struct stat st;
        if (lstat(child_full, &st) != 0) { ok = false; break; }
        if (S_ISDIR(st.st_mode)) {
            if (!inv_prune_dir(entry->d_name)) ok = inv_collect_dir(s, child);
        } else if (S_ISREG(st.st_mode) && inv_source_name(entry->d_name)) {
            ok = inv_path_push(s, child, &st);
        }
    }
    int saved = errno;
    if (closedir(dir) != 0 && ok) { ok = false; saved = errno; }
    if (!ok) errno = saved ? saved : EIO;
    return ok;
}
#endif

#if defined(_WIN32)
static bool inv_collect_dir(struct inv_scan *s, const char *rel)
{
    char full[INV_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", s->root, rel);
    if (n <= 0 || (size_t)n >= sizeof(full)) return false;
    enum platform_directory_probe_result probe =
        platform_directory_probe_real(full);
    if (probe == PLATFORM_DIRECTORY_PROBE_MISSING) return true;
    if (probe != PLATFORM_DIRECTORY_PROBE_OK) return false;

    struct platform_directory_list directories = {0}, files = {0};
    if (!platform_directory_list_real_sorted(full, &directories) ||
        !platform_directory_list_regular_sorted(full, &files)) {
        platform_directory_list_free(&directories);
        platform_directory_list_free(&files);
        return false;
    }
    bool ok = true;
    for (size_t i = 0; ok && i < directories.count; i++) {
        const char *name = directories.entries[i].name;
        if (inv_prune_dir(name)) continue;
        char child[INV_PATH_MAX];
        n = snprintf(child, sizeof(child), "%s/%s", rel, name);
        ok = n > 0 && (size_t)n < sizeof(child) &&
             inv_collect_dir(s, child);
    }
    for (size_t i = 0; ok && i < files.count; i++) {
        const char *name = files.entries[i].name;
        if (!inv_source_name(name)) continue;
        char child[INV_PATH_MAX];
        n = snprintf(child, sizeof(child), "%s/%s", rel, name);
        struct platform_positioned_file file;
        struct platform_positioned_file_snapshot before, after;
        platform_positioned_file_init(&file);
        ok = n > 0 && (size_t)n < sizeof(child) &&
             platform_positioned_file_open_beneath(&file, s->root, child) &&
             platform_positioned_file_snapshot(&file, &before) &&
             platform_positioned_file_snapshot(&file, &after) &&
             platform_positioned_file_snapshot_equal(&before, &after) &&
             before.size <= INT64_MAX &&
             inv_snapshot_push(s, child, &after);
        platform_positioned_file_close(&file);
    }
    platform_directory_list_free(&directories);
    platform_directory_list_free(&files);
    return ok;
}
#endif

static int inv_path_cmp(const void *a, const void *b)
{
    return strcmp(((const struct inv_path *)a)->path,
                  ((const struct inv_path *)b)->path);
}

bool inv_collect_paths(struct inv_scan *s)
{
    if (!s || !s->root || !s->root[0]) return false;
    static const char *const roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!inv_collect_dir(s, roots[i]))
            LOG_FAIL("codeindex.inventory", "scan root %s failed: %s",
                     roots[i], strerror(errno));
    qsort(s->paths, (size_t)s->path_count, sizeof(*s->paths), inv_path_cmp);
    int write = 0;
    for (int i = 0; i < s->path_count; i++) {
        if (write > 0 && strcmp(s->paths[write - 1].path,
                                s->paths[i].path) == 0)
            continue;
        if (write != i) s->paths[write] = s->paths[i];
        write++;
    }
    s->path_count = write;
    return s->path_count > 0;
}

bool inv_read_stable(const struct inv_scan *s, int file_index,
                     char **out, size_t *out_len)
{
    if (out) *out = NULL;
    if (out_len) *out_len = 0;
    if (!s || file_index < 0 || file_index >= s->path_count || !out || !out_len)
        return false;
#if defined(_WIN32)
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(
            &file, s->root, s->paths[file_index].path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size > SIZE_MAX) {
        platform_positioned_file_close(&file);
        return false;
    }
    size_t len = (size_t)before.size;
    char *buf = zcl_malloc(len ? len : 1, "ci_inventory_source");
    if (!buf) { platform_positioned_file_close(&file); return false; }
    size_t offset = 0;
    bool ok = true;
    while (offset < len) {
        size_t wanted = len - offset < 64 * 1024 ? len - offset : 64 * 1024;
        int64_t got = platform_positioned_file_read(
            &file, buf + offset, wanted, (uint64_t)offset);
        if (got <= 0) { ok = false; break; }
        offset += (size_t)got;
    }
    ok = ok && offset == len &&
         platform_positioned_file_snapshot(&file, &after) &&
         platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok) { free(buf); return false; }
    *out = buf;
    *out_len = len;
    return true;
#else
    char full[INV_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", s->root,
                     s->paths[file_index].path);
    if (n <= 0 || (size_t)n >= sizeof(full)) return false;
    FILE *f = fopen(full, "rb");
    if (!f) return false;
    struct stat before, after;
    if (fstat(fileno(f), &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_size < 0 || (uint64_t)before.st_size > SIZE_MAX) {
        fclose(f);
        return false;
    }
    size_t len = (size_t)before.st_size;
    char *buf = zcl_malloc(len ? len : 1, "ci_inventory_source");
    if (!buf) { fclose(f); return false; }
    size_t got = len ? fread(buf, 1, len, f) : 0;
    bool ok = got == len && !ferror(f) && fstat(fileno(f), &after) == 0 &&
        before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
        before.st_size == after.st_size &&
        INV_MTIME_SEC(before) == INV_MTIME_SEC(after) &&
        INV_MTIME_NSEC(before) == INV_MTIME_NSEC(after) &&
        INV_CTIME_SEC(before) == INV_CTIME_SEC(after) &&
        INV_CTIME_NSEC(before) == INV_CTIME_NSEC(after);
    fclose(f);
    if (!ok) { free(buf); return false; }
    *out = buf;
    *out_len = len;
    return true;
#endif
}

static bool inv_file_push(struct inv_scan *s, int index, const char *purpose)
{
    if (s->file_count == s->file_cap) {
        int cap = s->file_cap ? s->file_cap * 2 : 1024;
        void *p = zcl_realloc(s->files, (size_t)cap * sizeof(*s->files),
                              "ci_inventory_files");
        if (!p) return false;
        s->files = p;
        s->file_cap = cap;
    }
    struct inv_file *f = &s->files[s->file_count++];
    memset(f, 0, sizeof(*f));
    inv_cpy(f->path, sizeof(f->path), s->paths[index].path);
    inv_group_for_path(f->path, f->group);
    inv_cpy(f->purpose, sizeof(f->purpose), purpose);
    size_t n = strlen(f->path);
    f->is_header = n >= 2 && strcmp(f->path + n - 2, ".h") == 0;
    f->is_public_header = inv_is_public_header_path(f->path);
    f->is_test = inv_is_test_path(f->path);
    f->is_example = strncmp(f->path, "examples/", 9) == 0;
    return true;
}

struct inv_cb_env { struct inv_scan *scan; int file_index; };

static void inv_symbol_cb(const struct ci_symbol *symbol, void *user)
{
    struct inv_cb_env *env = user;
    struct inv_scan *s = env->scan;
    if (s->failed) return;
    if (s->occurrence_count == s->occurrence_cap) {
        int cap = s->occurrence_cap ? s->occurrence_cap * 2 : 4096;
        void *p = zcl_realloc(s->occurrences,
                              (size_t)cap * sizeof(*s->occurrences),
                              "ci_inventory_symbols");
        if (!p) { s->failed = true; return; }
        s->occurrences = p;
        s->occurrence_cap = cap;
    }
    struct inv_symbol_occurrence *o = &s->occurrences[s->occurrence_count++];
    memset(o, 0, sizeof(*o));
    o->symbol = *symbol;
    o->file_index = env->file_index;
    if (symbol->partial) s->scanner_partial_symbols++;
}

static void inv_ref_cb(const char *callee, const char *file, int line,
                       const char *enclosing, void *user)
{
    (void)file;
    struct inv_cb_env *env = user;
    struct inv_scan *s = env->scan;
    if (s->failed) return;
    if (s->ref_count == s->ref_cap) {
        int cap = s->ref_cap ? s->ref_cap * 2 : 8192;
        void *p = zcl_realloc(s->refs, (size_t)cap * sizeof(*s->refs),
                              "ci_inventory_refs");
        if (!p) { s->failed = true; return; }
        s->refs = p;
        s->ref_cap = cap;
    }
    struct inv_ref *r = &s->refs[s->ref_count++];
    memset(r, 0, sizeof(*r));
    inv_cpy(r->callee, sizeof(r->callee), callee);
    inv_cpy(r->enclosing, sizeof(r->enclosing), enclosing);
    r->file_index = env->file_index;
    r->line = line;
}

static void inv_sha_u64(struct sha3_256_ctx *sha, uint64_t v)
{
    unsigned char b[8];
    zcl_write_u64_le(b, v);
    sha3_256_write(sha, b, sizeof(b));
}

static bool inv_hash_extra(struct inv_scan *s, struct sha3_256_ctx *sha,
                           const char *rel)
{
    char full[INV_PATH_MAX];
    int n = snprintf(full, sizeof(full), "%s/%s", s->root, rel);
    if (n <= 0 || (size_t)n >= sizeof(full)) return false;
    FILE *f = fopen(full, "rb");
    if (!f) return false;
    sha3_256_write(sha, (const unsigned char *)rel, strlen(rel) + 1);
    unsigned char buf[8192];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0)
        sha3_256_write(sha, buf, got);
    bool ok = !ferror(f);
    fclose(f);
    return ok;
}

bool inv_read_arm_symbol_baseline(struct inv_scan *s)
{
    char path[INV_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", s->root,
                     "tools/lint/arm_symbol_single_baseline.txt");
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    FILE *f = fopen(path, "rb");
    if (!f) {
        LOG_ERROR("codeindex.inventory",
                  "arm-symbol artifact absent; multi-arm claims UNPROVEN: %s",
                  path);
        return false;
    }
    bool schema = false, artifact = false, assertion = false;
    bool generated_by = false, regenerate = false, ok = true;
    char line[768];
    while (ok && fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        if (len == sizeof(line) - 1 && line[len - 1] != '\n') {
            ok = false;
            break;
        }
        while (len && (line[len - 1] == '\n' || line[len - 1] == '\r'))
            line[--len] = '\0';
        if (strcmp(line,
                   "# z23-generated-artifact: zcl.generated_artifact.v1") == 0)
            schema = true;
        else if (strcmp(line,
                        "# artifact-id: zcl.arm_symbol_single_baseline.v1") == 0)
            artifact = true;
        else if (strcmp(line,
                        "# asserts: multi_arm_definition(path,symbol)") == 0)
            assertion = true;
        else if (strcmp(line,
                        "# generated-by: tools/lint/check_arm_symbol_single.sh") == 0)
            generated_by = true;
        else if (strcmp(line,
                        "# regenerate: ZCL_LINT_MODE=UPDATE tools/lint/check_arm_symbol_single.sh") == 0)
            regenerate = true;
        if (!line[0] || line[0] == '#') continue;
        char *tab = strchr(line, '\t');
        if (!tab || tab == line || !tab[1] || strchr(tab + 1, '\t')) {
            ok = false;
            break;
        }
        *tab++ = '\0';
        for (int i = 0; i < s->arm_symbol_count; i++)
            if (strcmp(s->arm_symbols[i].path, line) == 0 &&
                strcmp(s->arm_symbols[i].name, tab) == 0)
                ok = false;
        if (!ok) break;
        if (s->arm_symbol_count == s->arm_symbol_cap) {
            int cap = s->arm_symbol_cap ? s->arm_symbol_cap * 2 : 256;
            void *p = zcl_realloc(s->arm_symbols,
                                  (size_t)cap * sizeof(*s->arm_symbols),
                                  "ci_inventory_arm_symbols");
            if (!p) { ok = false; break; }
            s->arm_symbols = p;
            s->arm_symbol_cap = cap;
        }
        struct inv_arm_symbol *row = &s->arm_symbols[s->arm_symbol_count++];
        memset(row, 0, sizeof(*row));
        inv_cpy(row->path, sizeof(row->path), line);
        inv_cpy(row->name, sizeof(row->name), tab);
    }
    if (ferror(f)) ok = false;
    fclose(f);
    if (!schema || !artifact || !assertion || !generated_by || !regenerate) {
        LOG_ERROR("codeindex.inventory",
                  "arm-symbol artifact lacks self-describing generated header; claims UNPROVEN");
        ok = false;
    }
    if (!ok)
        LOG_ERROR("codeindex.inventory",
                  "arm-symbol artifact malformed or stale-looking; claims UNPROVEN");
    return ok;
}

bool inv_scan_all(struct inv_scan *s, uint8_t source_root[32])
{
    if (!s || !source_root || !inv_collect_paths(s)) return false;
    struct sha3_256_ctx sha;
    static const char domain[] = "zcl.code_capability_inventory.source.v1";
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    for (int i = 0; i < s->path_count; i++) {
        char *src = NULL;
        size_t len = 0;
        if (!inv_read_stable(s, i, &src, &len)) {
            LOG_FAIL("codeindex.inventory", "stable read failed: %s",
                     s->paths[i].path);
        }
        sha3_256_write(&sha, (const unsigned char *)s->paths[i].path,
                       strlen(s->paths[i].path) + 1);
        inv_sha_u64(&sha, (uint64_t)len);
        if (len) sha3_256_write(&sha, (const unsigned char *)src, len);

        char group[64], purpose[CI_FILE_PURPOSE_MAX] = "";
        inv_group_for_path(s->paths[i].path, group);
        bool is_header = strlen(s->paths[i].path) >= 2 &&
            strcmp(s->paths[i].path + strlen(s->paths[i].path) - 2, ".h") == 0;
        struct inv_cb_env env = { .scan = s, .file_index = i };
        ci_scan_text(src, len, s->paths[i].path, is_header, group,
                     inv_symbol_cb, inv_ref_cb, &env, purpose);
        if (s->failed || !inv_file_push(s, i, purpose)) {
            free(src);
            return false;
        }
        inv_scan_includes_and_bodies(s, i, src, len);
        free(src);
        if (s->failed) return false;
    }
    if (!inv_hash_extra(s, &sha, "tools/dev/test_group_catalog.def") ||
        !inv_hash_extra(s, &sha,
                        "tools/lint/arm_symbol_single_baseline.txt") ||
        !inv_read_registered_groups(s) ||
        !inv_read_arm_symbol_baseline(s))
        return false;
    sha3_256_finalize(&sha, source_root);
    return true;
}

void inv_scan_release(struct inv_scan *s)
{
    if (!s) return;
    free(s->paths);
    free(s->files);
    free(s->occurrences);
    free(s->refs);
    free(s->includes);
    free(s->bodies);
    free(s->groups);
    free(s->arm_symbols);
    memset(s, 0, sizeof(*s));
}

bool codeindex_inventory_stat_root(const char *root, uint8_t out[32])
{
    if (!root || !root[0] || !out) return false;
    struct inv_scan scan = { .root = root };
    if (!inv_collect_paths(&scan)) { inv_scan_release(&scan); return false; }
    struct sha3_256_ctx sha;
    static const char domain[] = "zcl.code_capability_inventory.stat.v1";
    sha3_256_init(&sha);
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    for (int i = 0; i < scan.path_count; i++) {
        const struct inv_path *p = &scan.paths[i];
        sha3_256_write(&sha, (const unsigned char *)p->path,
                       strlen(p->path) + 1);
        inv_sha_u64(&sha, p->device);
        inv_sha_u64(&sha, p->inode);
        inv_sha_u64(&sha, (uint64_t)p->size);
        inv_sha_u64(&sha, (uint64_t)p->mtime_ns);
        inv_sha_u64(&sha, (uint64_t)p->ctime_ns);
    }
    static const char *const extras[] = {
        "tools/dev/test_group_catalog.def",
        "tools/lint/arm_symbol_single_baseline.txt",
    };
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(extras) / sizeof(extras[0]); i++) {
        char path[INV_PATH_MAX];
        int n = snprintf(path, sizeof(path), "%s/%s", root, extras[i]);
        struct stat st;
        ok = n > 0 && (size_t)n < sizeof(path) && stat(path, &st) == 0;
        if (!ok) break;
        sha3_256_write(&sha, (const unsigned char *)extras[i],
                       strlen(extras[i]) + 1);
        inv_sha_u64(&sha, (uint64_t)st.st_size);
        inv_sha_u64(&sha, (uint64_t)INV_MTIME_SEC(st));
        inv_sha_u64(&sha, (uint64_t)INV_MTIME_NSEC(st));
    }
    if (ok) sha3_256_finalize(&sha, out);
    inv_scan_release(&scan);
    return ok;
}

const char *codeindex_inventory_duplicate_kind_name(
    enum ci_inventory_duplicate_kind kind)
{
    if (kind == CI_INVENTORY_DUPLICATE_EXACT_BODY)
        return "normalized_body_equal";
    if (kind == CI_INVENTORY_DUPLICATE_ALPHA_SHAPE)
        return "alpha_shape_equal_UNPROVEN";
    return "unknown";
}

const char *codeindex_inventory_test_evidence_name(
    enum ci_inventory_test_evidence evidence)
{
    if (evidence == CI_INVENTORY_TEST_REGISTERED_REACHABLE)
        return "registered_test_reachable";
    if (evidence == CI_INVENTORY_TEST_SOURCE_ONLY)
        return "test_source_reference_only_UNPROVEN";
    return "none_UNPROVEN";
}
