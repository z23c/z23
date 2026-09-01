/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Native Windows codeindex enumeration and retained-handle atomic
 * publication without pathname reconstruction or reparse-point traversal. */
#if defined(_WIN32)

#include "codeindex_priv.h"
#include "codeindex/codeindex_build.h"

#include "platform/directory_compat.h"
#include "platform/private_directory.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <errno.h>
#include <process.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <windows.h>

struct source_path {
    char *value;
    struct platform_directory_entry snapshot;
};

struct strvec { struct source_path *items; size_t count, capacity; };

static bool strvec_push(struct strvec *vec, const char *value,
                        const struct platform_directory_entry *snapshot)
{
    if (vec->count == vec->capacity) {
        size_t next_capacity = vec->capacity ? vec->capacity * 2 : 256;
        struct source_path *next = zcl_realloc(
            vec->items, next_capacity * sizeof(*vec->items),
            "windows codeindex paths");
        if (!next) return false;
        vec->items = next;
        vec->capacity = next_capacity;
    }
    vec->items[vec->count] = (struct source_path){0};
    vec->items[vec->count].value =
        zcl_strdup(value, "windows codeindex path");
    if (!vec->items[vec->count].value) return false;
    if (!snapshot || !snapshot->snapshot_valid) {
        free(vec->items[vec->count].value);
        vec->items[vec->count].value = NULL;
        return false;
    }
    vec->items[vec->count].snapshot = *snapshot;
    vec->items[vec->count].snapshot.name = NULL;
    vec->count++;
    return true;
}

static void strvec_free(struct strvec *vec)
{
    for (size_t i = 0; i < vec->count; i++) free(vec->items[i].value);
    free(vec->items);
    memset(vec, 0, sizeof(*vec));
}

static int path_compare(const void *left, const void *right)
{
    const struct source_path *a = left;
    const struct source_path *b = right;
    return strcmp(a->value, b->value);
}

static bool registry_name(const char *name)
{
    size_t length = name ? strlen(name) : 0;
    return length >= 4 && strcmp(name + length - 4, ".def") == 0;
}

bool ci_path_is_registry(const char *relpath)
{
    return relpath && relpath[0] && registry_name(relpath);
}

static bool source_name(const char *name)
{
    size_t length = name ? strlen(name) : 0;
    return (length >= 2 && name[length - 2] == '.' &&
            (name[length - 1] == 'c' || name[length - 1] == 'h')) ||
           registry_name(name);
}

static bool pruned_directory(const char *name)
{
#define SOURCE_PRUNE_DIR(name_) if (strcmp(name, name_) == 0) return true;
#include "codeindex/source_prune_dirs.def"
#undef SOURCE_PRUNE_DIR
    return strncmp(name, "test-tmp", 8) == 0;
}

static bool collect_directory(const char *root, const char *relative,
                              struct strvec *paths)
{
    char full[CI_PATH_MAX];
    int length = relative[0]
        ? snprintf(full, sizeof(full), "%s/%s", root, relative)
        : snprintf(full, sizeof(full), "%s", root);
    if (length <= 0 || (size_t)length >= sizeof(full)) {
        errno = ENAMETOOLONG;
        return false;
    }
    enum platform_directory_probe_result probe =
        platform_directory_probe_real(full);
    if (probe == PLATFORM_DIRECTORY_PROBE_MISSING) return true;
    if (probe != PLATFORM_DIRECTORY_PROBE_OK) return false;

    struct platform_directory_list directories = {0}, files = {0};
    if (!platform_directory_list_real_sorted(full, &directories)) {
        platform_directory_list_free(&directories);
        platform_directory_list_free(&files);
        LOG_FAIL("codeindex", "list Windows source directories: %s", full);
    }
    if (!platform_directory_list_regular_sorted(full, &files)) {
        platform_directory_list_free(&directories);
        platform_directory_list_free(&files);
        LOG_FAIL("codeindex", "list Windows source files: %s", full);
    }

    bool ok = true;
    for (size_t i = 0; ok && i < directories.count; i++) {
        const char *name = directories.entries[i].name;
        if (pruned_directory(name)) continue;
        char child[CI_PATH_MAX];
        int n = relative[0]
            ? snprintf(child, sizeof(child), "%s/%s", relative, name)
            : snprintf(child, sizeof(child), "%s", name);
        ok = n > 0 && (size_t)n < sizeof(child) &&
             collect_directory(root, child, paths);
    }
    for (size_t i = 0; ok && i < files.count; i++) {
        const char *name = files.entries[i].name;
        if (!source_name(name)) continue;
        char child[CI_PATH_MAX];
        int n = relative[0]
            ? snprintf(child, sizeof(child), "%s/%s", relative, name)
            : snprintf(child, sizeof(child), "%s", name);
        ok = n > 0 && (size_t)n < sizeof(child) &&
             strvec_push(paths, child, &files.entries[i]);
    }
    platform_directory_list_free(&directories);
    platform_directory_list_free(&files);
    return ok;
}

#if !defined(CI_WINDOWS_FRESHNESS_ONLY)
static void snapshot_to_stat(
    const struct platform_positioned_file_snapshot *snapshot, struct stat *st)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG;
    st->st_nlink = 1;
    st->st_dev = (dev_t)snapshot->volume;
    st->st_ino = (ino_t)snapshot->file_low;
    st->st_size = (off_t)snapshot->size;
    st->st_mtime = (time_t)snapshot->modified_seconds;
    st->st_ctime = (time_t)snapshot->changed_seconds;
}
#endif

static void directory_snapshot_to_stat(
    const struct platform_directory_entry *snapshot, struct stat *st)
{
    memset(st, 0, sizeof(*st));
    st->st_mode = S_IFREG;
    st->st_nlink = 1;
    st->st_dev = (dev_t)snapshot->volume;
    st->st_ino = (ino_t)snapshot->file_low;
    st->st_size = (off_t)snapshot->size;
    st->st_mtime = (time_t)snapshot->modified_seconds;
    st->st_ctime = (time_t)snapshot->changed_seconds;
}

bool ci_enumerate_sources(const char *root, ci_enum_cb callback, void *user)
{
    if (!root || !callback)
        LOG_FAIL("codeindex", "null argument to Windows source enumeration");
    struct strvec paths = {0};

    static const char *const roots[] = {
#define SOURCE_ROOT(name_) name_,
#include "codeindex/source_roots.def"
#undef SOURCE_ROOT
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++)
        if (!collect_directory(root, roots[i], &paths)) goto collect_failed;

    qsort(paths.items, paths.count, sizeof(paths.items[0]), path_compare);
    bool ok = true;
    for (size_t i = 0; ok && i < paths.count; i++) {
        if (i > 0 && strcmp(paths.items[i].value,
                            paths.items[i - 1].value) == 0)
            continue;
        struct stat st;
        directory_snapshot_to_stat(&paths.items[i].snapshot, &st);
        ok = callback(paths.items[i].value, &st, user);
    }
    strvec_free(&paths);
    return ok;

collect_failed:
    strvec_free(&paths);
    LOG_FAIL("codeindex", "Windows source enumeration failed: %s",
             strerror(errno ? errno : EIO));
}

static void write_u64le(struct sha3_256_ctx *sha, uint64_t value)
{
    unsigned char encoded[8];
    for (unsigned int i = 0; i < sizeof(encoded); i++)
        encoded[i] = (unsigned char)((value >> (i * 8U)) & 0xffU);
    sha3_256_write(sha, encoded, sizeof(encoded));
}

static void source_stat_root_init(struct sha3_256_ctx *sha)
{
    static const char domain[] = "zcl.codeindex.source_stat_root.v1";
    sha3_256_init(sha);
    sha3_256_write(sha, (const unsigned char *)domain, sizeof(domain));
}

static void source_stat_root_add(struct sha3_256_ctx *sha,
                                 const char *relpath, const struct stat *st)
{
    sha3_256_write(sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    write_u64le(sha, (uint64_t)st->st_dev);
    write_u64le(sha, (uint64_t)st->st_ino);
    write_u64le(sha, (uint64_t)st->st_size);
    write_u64le(sha, (uint64_t)st->st_mtime);
    write_u64le(sha, 0);
    write_u64le(sha, (uint64_t)st->st_ctime);
    write_u64le(sha, 0);
}

#if !defined(CI_WINDOWS_FRESHNESS_ONLY)
static bool source_file_sha3(const char *root, const char *relpath,
                             uint8_t out[32], struct stat *out_st)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(&file, root, relpath) ||
        !platform_positioned_file_snapshot(&file, &before)) {
        platform_positioned_file_close(&file);
        LOG_FAIL("codeindex", "open stable source digest path=%s", relpath);
    }
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const uint8_t content_tag = 0x02;
    sha3_256_write(&sha, &content_tag, 1);
    unsigned char buffer[64 * 1024];
    uint64_t offset = 0;
    bool ok = true;
    while (offset < before.size) {
        size_t wanted = before.size - offset < sizeof(buffer)
            ? (size_t)(before.size - offset) : sizeof(buffer);
        int64_t got = platform_positioned_file_read(&file, buffer, wanted,
                                                    offset);
        if (got <= 0) { ok = false; break; }
        sha3_256_write(&sha, buffer, (size_t)got);
        ci_test_note_exact_bytes((uint64_t)got);
        offset += (uint64_t)got;
    }
    ok = ok && offset == before.size &&
         platform_positioned_file_snapshot(&file, &after) &&
         platform_positioned_file_snapshot_equal(&before, &after);
    platform_positioned_file_close(&file);
    if (!ok)
        LOG_FAIL("codeindex", "read stable source digest path=%s", relpath);
    sha3_256_finalize(&sha, out);
    if (out_st) snapshot_to_stat(&after, out_st);
    return true;
}
#endif

#if !defined(CI_WINDOWS_FRESHNESS_ONLY)
struct stamp_context {
    const char *root;
    struct sha3_256_ctx exact, stat;
};

static bool exact_stamp_cb(const char *relpath, const struct stat *ignored,
                           void *user)
{
    struct stamp_context *context = user;
    uint8_t content[32];
    struct stat opened;
    (void)ignored;
    if (!source_file_sha3(context->root, relpath, content, &opened))
        return false;
    ci_source_root_add(&context->exact, relpath, content);
    source_stat_root_add(&context->stat, relpath, &opened);
    return true;
}
#endif

static bool stat_stamp_cb(const char *relpath, const struct stat *st, void *user)
{
    source_stat_root_add(user, relpath, st);
    return true;
}

#if !defined(CI_WINDOWS_FRESHNESS_ONLY)
bool ci_source_roots_sha3(const char *root, uint8_t exact_out[32],
                          uint8_t stat_out[32])
{
    if (!root || !exact_out || !stat_out)
        LOG_FAIL("codeindex", "null argument to Windows source roots");
    struct stamp_context context = { .root = root };
    ci_source_root_init(&context.exact);
    source_stat_root_init(&context.stat);
    if (!ci_enumerate_sources(root, exact_stamp_cb, &context))
        LOG_FAIL("codeindex", "enumerate Windows source roots failed");
    sha3_256_finalize(&context.exact, exact_out);
    sha3_256_finalize(&context.stat, stat_out);
    return true;
}
#endif

bool ci_source_stat_root_sha3(const char *root, uint8_t out[32])
{
    if (!root || !out)
        LOG_FAIL("codeindex", "null argument to Windows source stat root");
    struct sha3_256_ctx sha;
    source_stat_root_init(&sha);
    if (!ci_enumerate_sources(root, stat_stamp_cb, &sha))
        LOG_FAIL("codeindex", "enumerate Windows source metadata failed");
    sha3_256_finalize(&sha, out);
    return true;
}

#if !defined(CI_WINDOWS_FRESHNESS_ONLY)
static _Atomic uint64_t g_stage_sequence = 1;

#ifdef ZCL_TESTING
static _Atomic int g_test_crash_point = CODEINDEX_TEST_CRASH_NONE;
static _Atomic int g_test_stage_tamper = CODEINDEX_TEST_STAGE_TAMPER_NONE;
static _Atomic bool g_test_remove_lock_directory = false;
static _Atomic uint64_t g_test_exact_bytes_read = 0;
static char g_test_stage_victim[CI_PATH_MAX];

void ci_test_note_exact_bytes(uint64_t bytes)
{
    (void)atomic_fetch_add_explicit(&g_test_exact_bytes_read, bytes,
                                    memory_order_relaxed);
}
void codeindex_test_reset_exact_bytes_read(void)
{
    atomic_store_explicit(&g_test_exact_bytes_read, 0, memory_order_relaxed);
}
uint64_t codeindex_test_exact_bytes_read(void)
{
    return atomic_load_explicit(&g_test_exact_bytes_read, memory_order_relaxed);
}
void codeindex_test_set_crash_point(enum codeindex_test_crash_point point)
{
    atomic_store_explicit(&g_test_crash_point, (int)point,
                          memory_order_relaxed);
}
void codeindex_test_set_stage_tamper(
    enum codeindex_test_stage_tamper tamper, const char *victim_path)
{
    (void)snprintf(g_test_stage_victim, sizeof(g_test_stage_victim), "%s",
                   victim_path ? victim_path : "");
    atomic_store_explicit(&g_test_stage_tamper, (int)tamper,
                          memory_order_relaxed);
}
void codeindex_test_remove_lock_directory_once(void)
{
    atomic_store_explicit(&g_test_remove_lock_directory, true,
                          memory_order_relaxed);
}
static bool test_consume_remove_directory(void)
{
    return atomic_exchange_explicit(&g_test_remove_lock_directory, false,
                                    memory_order_relaxed);
}
static bool test_maybe_tamper_stage(
    struct platform_directory_transaction *directory, const char *name)
{
    int tamper = atomic_exchange_explicit(&g_test_stage_tamper,
        CODEINDEX_TEST_STAGE_TAMPER_NONE, memory_order_relaxed);
    if (tamper == CODEINDEX_TEST_STAGE_TAMPER_NONE) return true;
    if (!name || !name[0] || !g_test_stage_victim[0]) return false;
    /* Windows publication never reopens this pathname for writes. Removing
     * it proves that a namespace substitution is detected before the retained
     * child can be published or the named victim can be touched. */
    (void)platform_directory_child_unlink(directory, name, false);
    return false;
}
static void test_maybe_crash(enum codeindex_test_crash_point point)
{
    if (atomic_load_explicit(&g_test_crash_point, memory_order_relaxed) ==
        (int)point) {
        (void)TerminateProcess(GetCurrentProcess(), 128 + 9);
        ExitProcess(128 + 9);
    }
}
#else
#define test_consume_remove_directory() false
#define test_maybe_tamper_stage(...) true
#define test_maybe_crash(...) ((void)0)
#endif

struct rebuild_lock {
    struct platform_directory_transaction directory;
    struct platform_directory_lock lock;
};

static void rebuild_lock_init(struct rebuild_lock *lock)
{
    platform_directory_transaction_init(&lock->directory);
    platform_directory_lock_init(&lock->lock);
}

static void rebuild_lock_close(struct rebuild_lock *lock)
{
    platform_directory_lock_release(&lock->lock);
    platform_directory_transaction_close(&lock->directory);
}

static bool rebuild_lock_open(const char *root, char path[CI_PATH_MAX],
                              struct rebuild_lock *lock)
{
    int n = snprintf(path, CI_PATH_MAX, "%s/.codeindex", root);
    if (n <= 0 || n >= CI_PATH_MAX)
        LOG_FAIL("codeindex", "Windows index directory path too long");
    int64_t deadline = platform_time_monotonic_ms() + INT64_C(120000);
    for (;;) {
        if (!platform_private_directory_ensure(path) ||
            !platform_directory_transaction_open(&lock->directory, path))
            LOG_FAIL("codeindex", "open private Windows index directory failed");
        if (test_consume_remove_directory()) {
            platform_directory_transaction_close(&lock->directory);
            (void)platform_private_directory_remove_empty(path);
            platform_sleep_ms(1);
            continue;
        }
        enum platform_directory_result acquired =
            platform_directory_lock_acquire(&lock->directory, "rebuild.lock",
                true, PLATFORM_DIRECTORY_LOCK_EXCLUSIVE, &lock->lock);
        if (acquired == PLATFORM_DIRECTORY_OK) return true;
        platform_directory_transaction_close(&lock->directory);
        if (acquired != PLATFORM_DIRECTORY_REFUSED ||
            platform_time_monotonic_ms() >= deadline)
            LOG_FAIL("codeindex", "acquire Windows rebuild lock failed result=%d",
                     (int)acquired);
        platform_sleep_ms(2);
    }
}

static bool cleanup_named_files(struct platform_directory_transaction *directory,
                                const char *prefix)
{
    struct platform_directory_names names = {0};
    if (!platform_directory_transaction_list_regular(directory, &names))
        LOG_FAIL("codeindex", "list Windows index directory failed");
    bool ok = true;
    size_t prefix_length = strlen(prefix);
    for (size_t i = 0; ok && i < names.count; i++)
        if (strncmp(names.items[i], prefix, prefix_length) == 0)
            ok = platform_directory_child_unlink(directory, names.items[i],
                                                  true);
    platform_directory_names_free(&names);
    if (!ok) LOG_FAIL("codeindex", "remove Windows staging file failed");
    return true;
}

static bool create_unique_stage(
    struct platform_directory_transaction *directory, char name[128],
    struct platform_directory_child *stage,
    struct platform_directory_child_info *identity)
{
    for (unsigned int attempt = 0; attempt < 128; attempt++) {
        uint64_t sequence = atomic_fetch_add_explicit(&g_stage_sequence, 1,
                                                       memory_order_relaxed);
        int n = snprintf(name, 128, "index.kv.tmp.%d.%llu", _getpid(),
                         (unsigned long long)sequence);
        if (n <= 0 || n >= 128)
            LOG_FAIL("codeindex", "Windows staging name overflow");
        enum platform_directory_result opened =
            platform_directory_child_open_result(directory, name, true, false,
                                                  stage, NULL);
        if (opened == PLATFORM_DIRECTORY_EXISTS) continue;
        if (opened != PLATFORM_DIRECTORY_OK)
            LOG_FAIL("codeindex", "create Windows staging child failed result=%d",
                     (int)opened);
        if (!platform_directory_child_info(stage, identity) ||
            identity->link_count != 1 || !identity->current_user_only) {
            platform_directory_child_close(stage);
            (void)platform_directory_child_unlink(directory, name, true);
            LOG_FAIL("codeindex", "Windows staging child is not private regular");
        }
        return true;
    }
    LOG_FAIL("codeindex", "could not allocate Windows staging child");
}

static bool child_identity_equal(const struct platform_directory_child_info *a,
                                 const struct platform_directory_child_info *b)
{
    return a->volume == b->volume && a->file_low == b->file_low &&
           a->file_high == b->file_high;
}

static bool remove_legacy_sidecars(
    struct platform_directory_transaction *directory)
{
    return platform_directory_child_unlink(directory, "index.kv-wal", true) &&
           platform_directory_child_unlink(directory, "index.kv-shm", true);
}

static bool codeindex_rebuild_internal(struct codeindex *ci,
                                       bool coalesce_if_fresh)
{
    if (!ci) LOG_FAIL("codeindex", "null codeindex to Windows rebuild");
    struct rebuild_lock rebuild;
    rebuild_lock_init(&rebuild);
    char directory_path[CI_PATH_MAX];
    if (!rebuild_lock_open(ci->root, directory_path, &rebuild)) return false;

    const char *failure = "unknown Windows rebuild failure";
    bool success = false, stage_named = false;
    char stage_name[128] = "";
    struct platform_directory_child stage;
    struct platform_directory_child_info stage_identity;
    platform_directory_child_init(&stage);
    memset(&stage_identity, 0, sizeof(stage_identity));
    struct ci_store *store = NULL;

    if (!cleanup_named_files(&rebuild.directory, "index.kv.tmp.")) {
        failure = "orphan Windows staging cleanup failed";
        goto out;
    }
    if (coalesce_if_fresh) {
        struct ci_store *fresh = ci_store_open(ci->root);
        if (fresh) {
            bool stale = true;
            struct codeindex view = {.store = fresh};
            (void)snprintf(view.root, sizeof(view.root), "%s", ci->root);
            if (codeindex_is_stale(&view, &stale) && !stale) {
                struct ci_store *old = ci->store;
                ci->store = fresh;
                if (old) ci_store_close(old);
                success = true;
                goto out;
            }
            ci_store_close(fresh);
        }
    }
    if (!create_unique_stage(&rebuild.directory, stage_name, &stage,
                             &stage_identity)) {
        failure = "unique Windows staging allocation failed";
        goto out;
    }
    stage_named = true;
    if (!test_maybe_tamper_stage(&rebuild.directory, stage_name)) {
        failure = "test Windows staging substitution failed";
        goto out;
    }

    uint8_t built_source_stat[32], built_dep_stat[32];
    if (!ci_build_store_memory(ci->root, &store, built_source_stat,
                               built_dep_stat) ||
        !ci_store_write_image_child(store, &stage)) {
        failure = "build or serialize Windows staging store failed";
        goto out;
    }
    ci_store_close(store);
    store = NULL;

    uint8_t final_source_stat[32], final_dep_stat[32];
    if (!ci_source_stat_root_sha3(ci->root, final_source_stat) ||
        memcmp(built_source_stat, final_source_stat, 32) != 0 ||
        !ci_deps_stat_root_sha3(ci->root, final_dep_stat) ||
        memcmp(built_dep_stat, final_dep_stat, 32) != 0) {
        failure = "source or depfile metadata changed during Windows rebuild";
        goto out;
    }

    struct platform_directory_child_info before_publish;
    unsigned char journal_versions[2];
    if (!platform_directory_child_info(&stage, &before_publish) ||
        !child_identity_equal(&stage_identity, &before_publish) ||
        before_publish.link_count != 1 || !before_publish.current_user_only ||
        !platform_directory_child_read_exact(&stage, journal_versions,
                                             sizeof(journal_versions), 18) ||
        journal_versions[0] != 1 || journal_versions[1] != 1 ||
        !platform_directory_child_flush(&stage)) {
        failure = "Windows staging identity or journal format changed";
        goto out;
    }

    test_maybe_crash(CODEINDEX_TEST_CRASH_BEFORE_RENAME);
    enum platform_directory_result published =
        platform_directory_child_move_between(&rebuild.directory, &stage,
            &rebuild.directory, "index.kv", false);
    if (published != PLATFORM_DIRECTORY_OK) {
        if (published == PLATFORM_DIRECTORY_OUTCOME_UNKNOWN)
            stage_named = false;
        failure = "atomic Windows staging publication failed";
        goto out;
    }
    stage_named = false;
    struct platform_directory_child_info after_publish;
    if (!platform_directory_child_info(&stage, &after_publish) ||
        !child_identity_equal(&stage_identity, &after_publish) ||
        after_publish.link_count != 1 || !after_publish.current_user_only) {
        failure = "published Windows index identity changed";
        goto out;
    }
    test_maybe_crash(CODEINDEX_TEST_CRASH_AFTER_RENAME);
    if (!remove_legacy_sidecars(&rebuild.directory) ||
        !platform_directory_transaction_flush(&rebuild.directory)) {
        failure = "Windows legacy sidecar cleanup failed";
        goto out;
    }
    platform_directory_child_close(&stage);

    struct ci_store *next = ci_store_open(ci->root);
    if (!next) {
        failure = "reopen published Windows index failed";
        goto out;
    }
    struct ci_store *old = ci->store;
    ci->store = next;
    if (old) ci_store_close(old);
    success = true;

out:
    if (store) ci_store_close(store);
    platform_directory_child_close(&stage);
    if (stage_named)
        (void)platform_directory_child_unlink(&rebuild.directory, stage_name,
                                              true);
    rebuild_lock_close(&rebuild);
    if (!success) LOG_FAIL("codeindex", "Windows rebuild failed: %s", failure);
    return true;
}

bool ci_codeindex_refresh(struct codeindex *ci)
{
    return codeindex_rebuild_internal(ci, true);
}

bool codeindex_rebuild(struct codeindex *ci)
{
    return codeindex_rebuild_internal(ci, false);
}
#endif

#else
typedef int codeindex_build_windows_not_built;
#endif
