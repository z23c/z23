/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_deps — turn the compiler's own dependency files (the depfiles
 * under build/, extension .d) into include edges. Each depfile records
 * "<obj>: <src.c> <prereq> ..."; we emit a (source, prerequisite) pair for
 * EVERY in-tree prerequisite the compiler listed, which is the exact include
 * graph the build already computed — no re-parsing of #include lines, no
 * guessing search paths.
 *
 * The prerequisite list is taken verbatim, never filtered by file extension.
 * The compiler records every byte it read, and plenty of those are not .h:
 * the ~23 tracked X-macro registries (`*.def` — the command catalog, the
 * condition registry, the sync-kernel catalog, the diagnostics dumpers) are
 * `#include`d exactly like headers and change a translation unit's behavior
 * exactly like headers. An extension allowlist silently dropped them from the
 * graph, so a registry edit moved no downstream content key and busted no
 * cache. The depfile is the authority; if the compiler read it, it is an edge.
 *
 * Depfiles are written into a per-build compile epoch,
 * `<object-root>/epochs/<64-hex>/`. Every build mints a new epoch and the
 * previous few are retained, so the directory accumulates immutable receipts of
 * trees that are no longer checked out: reading them all inflates a warm lookup
 * to tens of thousands of files and duplicates every edge. Exactly one of them
 * is the live graph — the epoch the build actually compiled into — and
 * `tools/dev/build-epoch-session.sh` names it in `<object-root>/.current-epoch`
 * while holding the lock that mints the epoch directory and hands out the
 * compile lease. A compile cannot land in an epoch that file does not name, so
 * the name and the build cannot disagree.
 *
 * An object root that has an `epochs/` directory is therefore read through that
 * pointer and through nothing else. Loose `.d` files beside it are pre-epoch
 * leftovers that no current compile wrote; they describe a tree that is days
 * stale, and reading them is how this scan came to see 0 of 3,111 live
 * depfiles. `history/` generations are excluded for the same reason.
 *
 * If build/ is absent (a fresh tree), no edges are produced. An epoch-managed
 * root with no resolvable current epoch contributes nothing and says so.
 * Other I/O failures fail closed. */

#include "codeindex_priv.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *dep_strtok(char *text, const char *delimiters, char **save)
{
    char *cursor = text ? text : *save;
    if (!cursor) return NULL;
    cursor += strspn(cursor, delimiters);
    if (!*cursor) { *save = NULL; return NULL; }
    char *end = cursor + strcspn(cursor, delimiters);
    if (*end) *end++ = '\0'; else end = NULL;
    *save = end;
    return cursor;
}

/* Rewrite an absolute or ./-relative depfile token to repo-relative, or return
 * false if the token is outside the tree (a system header). */
static bool to_relpath(const char *root, const char *tok, char out[CI_PATH_MAX])
{
    size_t rl = strlen(root);
    if (strncmp(tok, root, rl) == 0 && tok[rl] == '/') {
        snprintf(out, CI_PATH_MAX, "%s", tok + rl + 1);
        return true;
    }
    if (tok[0] == '/' || (isalpha((unsigned char)tok[0]) && tok[1] == ':'))
        return false;  /* absolute, outside root */
    /* already relative (build usually emits repo-relative prereqs) */
    if (strncmp(tok, "./", 2) == 0) tok += 2;
    if (tok[0] == '/') return false;
    /* reject paths that escape upward or reference vendored system trees */
    if (strncmp(tok, "../", 3) == 0) return false;
    snprintf(out, CI_PATH_MAX, "%s", tok);
    return true;
}

static bool has_ext(const char *s, const char *ext)
{
    size_t a = strlen(s), b = strlen(ext);
    return a >= b && strcmp(s + a - b, ext) == 0;
}

/* Parse one depfile's text; emit (src, dep) edges. */
static void parse_depfile(const char *root, char *text, size_t len,
                          ci_dep_cb cb, void *user)
{
    /* fold line continuations: "\\\n" → "  " */
    for (size_t i = 0; i + 1 < len; i++) {
        if (text[i] == '\\' && text[i + 1] == '\n') {
            text[i] = ' ';
            text[i + 1] = ' ';
        }
    }
    /* process one logical rule per physical line */
    char *save = NULL;
    for (char *line = dep_strtok(text, "\n", &save); line;
         line = dep_strtok(NULL, "\n", &save)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *rhs = colon + 1;
        /* tokenize prerequisites */
        char src_rel[CI_PATH_MAX];
        bool have_src = false;
        char *tsave = NULL;
        for (char *tok = dep_strtok(rhs, " \t", &tsave); tok;
             tok = dep_strtok(NULL, " \t", &tsave)) {
            char rel[CI_PATH_MAX];
            if (!to_relpath(root, tok, rel)) continue;
            if (!have_src && (has_ext(rel, ".c") || has_ext(rel, ".cc") ||
                              has_ext(rel, ".c23"))) {
                snprintf(src_rel, sizeof(src_rel), "%s", rel);
                have_src = true;
                continue;
            }
            /* Every remaining in-tree prerequisite is an edge — no extension
             * filter (see the file header: *.def registries are prerequisites
             * too, and an allowlist dropped them). */
            if (have_src)
                cb(src_rel, rel, user);
        }
    }
}

struct dep_paths {
    char **items;
    size_t count;
    size_t capacity;
};

static void dep_paths_free(struct dep_paths *paths)
{
    if (!paths) return;
    for (size_t i = 0; i < paths->count; i++) free(paths->items[i]);
    free(paths->items);
    memset(paths, 0, sizeof(*paths));
}

static bool dep_paths_push(struct dep_paths *paths, const char *path)
{
    if (paths->count == paths->capacity) {
        size_t next = paths->capacity ? paths->capacity * 2 : 128;
        char **items = zcl_realloc(paths->items, next * sizeof(*items),
                                   "codeindex dep paths");
        if (!items) return false;
        paths->items = items;
        paths->capacity = next;
    }
    paths->items[paths->count] = zcl_strdup(path, "codeindex dep path");
    if (!paths->items[paths->count]) return false;
    paths->count++;
    return true;
}

static int dep_path_cmp(const void *left, const void *right)
{
    return strcmp(*(const char *const *)left, *(const char *const *)right);
}

/* A compile epoch's directory name is exactly 64 lowercase hex digits. Nothing
 * else is accepted, so a pointer can never name a parent, a sibling tree, or an
 * absolute path. */
static bool epoch_name_valid(const char *name, size_t len)
{
    if (len != 64) return false;
    for (size_t i = 0; i < len; i++) {
        char c = name[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

enum epoch_state {
    EPOCH_NONE,     /* not an epoch-managed root: read the directory as-is */
    EPOCH_CURRENT,  /* `out` is the repo-relative dir of the live epoch */
    EPOCH_UNKNOWN,  /* epoch-managed, but no epoch is claimed as current */
};

static enum epoch_state epoch_current_dir(const char *root, const char *reldir,
                                          char out[CI_PATH_MAX])
{
    char path[CI_PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s/epochs", root, reldir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return EPOCH_NONE;
    enum platform_directory_probe_result epochs =
        platform_directory_probe_real(path);
    if (epochs == PLATFORM_DIRECTORY_PROBE_MISSING) return EPOCH_NONE;
    if (epochs != PLATFORM_DIRECTORY_PROBE_OK) return EPOCH_UNKNOWN;

    n = snprintf(path, sizeof(path), "%s/%s/.current-epoch", root, reldir);
    if (n <= 0 || (size_t)n >= sizeof(path)) return EPOCH_UNKNOWN;
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path) ||
        !platform_positioned_file_snapshot(&file, &before) ||
        before.size >= 72) {
        platform_positioned_file_close(&file);
        LOG_WARN("codeindex",
                 "%s keeps compile epochs but claims no current one (%s) — its "
                 "depfiles are OUTSIDE the include graph; rebuild to restore it",
                 reldir, strerror(errno));
        return EPOCH_UNKNOWN;
    }
    char name[72];
    int64_t got = platform_positioned_file_read(&file, name,
                                                 (size_t)before.size, 0);
    bool stable = got == (int64_t)before.size &&
                  platform_positioned_file_snapshot(&file, &after) &&
                  before.volume == after.volume &&
                  before.file_low == after.file_low &&
                  before.file_high == after.file_high &&
                  before.size == after.size &&
                  before.modified_seconds == after.modified_seconds &&
                  before.modified_nanoseconds == after.modified_nanoseconds;
    platform_positioned_file_close(&file);
    size_t len = stable ? (size_t)got : 0;
    while (len > 0 && (name[len - 1] == '\n' || name[len - 1] == '\r')) len--;
    if (!epoch_name_valid(name, len)) {
        LOG_WARN("codeindex",
                 "%s names an unreadable current compile epoch — its depfiles "
                 "are OUTSIDE the include graph", reldir);
        return EPOCH_UNKNOWN;
    }
    int cn = snprintf(out, CI_PATH_MAX, "%s/epochs/%.*s", reldir, (int)len,
                      name);
    if (cn <= 0 || (size_t)cn >= CI_PATH_MAX) return EPOCH_UNKNOWN;
    int fn = snprintf(path, sizeof(path), "%s/%s", root, out);
    if (fn <= 0 || (size_t)fn >= sizeof(path) ||
        platform_directory_probe_real(path) != PLATFORM_DIRECTORY_PROBE_OK) {
        LOG_WARN("codeindex",
                 "%s names current compile epoch %.*s, which is not a "
                 "directory — its depfiles are OUTSIDE the include graph",
                 reldir, (int)len, name);
        return EPOCH_UNKNOWN;
    }
    return EPOCH_CURRENT;
}

static bool collect_dep_paths(const char *root, const char *reldir,
                              struct dep_paths *paths)
{
    char current[CI_PATH_MAX];
    switch (epoch_current_dir(root, reldir, current)) {
    case EPOCH_CURRENT:
        /* The live generation is the whole of this root's contribution. */
        return collect_dep_paths(root, current, paths);
    case EPOCH_UNKNOWN:
        return true;
    case EPOCH_NONE:
        break;
    }

    char full[CI_PATH_MAX];
    int fn = snprintf(full, sizeof(full), "%s/%s", root, reldir);
    if (fn <= 0 || (size_t)fn >= sizeof(full))
        return false;
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
        if (name[0] == '.' || strcmp(name, "history") == 0) continue;
        char child[CI_PATH_MAX];
        int cn = snprintf(child, sizeof(child), "%s/%s", reldir, name);
        if (cn <= 0 || (size_t)cn >= sizeof(child)) {
            ok = false;
            break;
        }
        ok = collect_dep_paths(root, child, paths);
    }
    for (size_t i = 0; ok && i < files.count; i++) {
        const char *name = files.entries[i].name;
        if (name[0] == '.' || !has_ext(name, ".d")) continue;
        char child[CI_PATH_MAX];
        int cn = snprintf(child, sizeof(child), "%s/%s", reldir, name);
        ok = cn > 0 && (size_t)cn < sizeof(child) &&
             dep_paths_push(paths, child);
    }
    platform_directory_list_free(&directories);
    platform_directory_list_free(&files);
    if (!ok) errno = EIO;
    return ok;
}

static void dep_root_init(struct sha3_256_ctx *sha, bool build_present)
{
    static const char domain[] = "zcl.codeindex.dep_root.v1";
    sha3_256_init(sha);
    sha3_256_write(sha, (const unsigned char *)domain, sizeof(domain));
    const unsigned char marker = build_present ? 1U : 0U;
    sha3_256_write(sha, &marker, 1);
}

static void dep_stat_root_init(struct sha3_256_ctx *sha, bool build_present)
{
    static const char domain[] = "zcl.codeindex.dep_stat_root.v1";
    sha3_256_init(sha);
    sha3_256_write(sha, (const unsigned char *)domain, sizeof(domain));
    const unsigned char marker = build_present ? 1U : 0U;
    sha3_256_write(sha, &marker, 1);
}

static void dep_sha_write_u64le(struct sha3_256_ctx *sha, uint64_t value)
{
    unsigned char encoded[8];
    for (unsigned int i = 0; i < sizeof(encoded); i++)
        encoded[i] = (unsigned char)((value >> (i * 8U)) & 0xffU);
    sha3_256_write(sha, encoded, sizeof(encoded));
}

static void dep_stat_root_add(struct sha3_256_ctx *sha, const char *relpath,
                              const struct platform_positioned_file_snapshot *st)
{
    sha3_256_write(sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    dep_sha_write_u64le(sha, st->volume);
    dep_sha_write_u64le(sha, st->file_low);
    dep_sha_write_u64le(sha, st->size);
    dep_sha_write_u64le(sha, (uint64_t)st->modified_seconds);
    dep_sha_write_u64le(sha, st->modified_nanoseconds);
    dep_sha_write_u64le(sha, (uint64_t)st->changed_seconds);
    dep_sha_write_u64le(sha, st->changed_nanoseconds);
}

static bool scan_one_depfile(const char *root, const char *relpath,
                             ci_dep_cb cb, void *user,
                             struct sha3_256_ctx *sha,
                             struct sha3_256_ctx *stat_sha)
{
    char full[CI_PATH_MAX];
    int fn = snprintf(full, sizeof(full), "%s/%s", root, relpath);
    if (fn <= 0 || (size_t)fn >= sizeof(full))
        LOG_FAIL("codeindex", "depfile path too long: %s", relpath);
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, full))
        LOG_FAIL("codeindex", "open depfile failed path=%s: %s", relpath,
                 strerror(errno));
    if (!platform_positioned_file_snapshot(&file, &before) ||
        before.size > UINT64_C(67108864)) {
        int saved = errno ? errno : EFBIG;
        platform_positioned_file_close(&file);
        LOG_FAIL("codeindex", "invalid depfile path=%s: %s", relpath,
                 strerror(saved));
    }
    size_t len = (size_t)before.size;
    char *buf = zcl_malloc(len + 1, "codeindex depfile bytes");
    if (!buf) {
        platform_positioned_file_close(&file);
        LOG_FAIL("codeindex", "allocate depfile path=%s", relpath);
    }
    bool ok = platform_positioned_file_read(&file, buf, len, 0) ==
                  (int64_t)len &&
              platform_positioned_file_snapshot(&file, &after) &&
              before.size == after.size && before.volume == after.volume &&
              before.file_low == after.file_low &&
              before.file_high == after.file_high &&
              before.modified_seconds == after.modified_seconds &&
              before.modified_nanoseconds == after.modified_nanoseconds &&
              before.changed_seconds == after.changed_seconds &&
              before.changed_nanoseconds == after.changed_nanoseconds;
    platform_positioned_file_close(&file);
    if (!ok) {
        free(buf);
        LOG_FAIL("codeindex", "read depfile failed path=%s: %s", relpath,
                 strerror(errno ? errno : EIO));
    }
    buf[len] = '\0';
    sha3_256_write(sha, (const unsigned char *)relpath, strlen(relpath) + 1);
    unsigned char encoded_len[8];
    for (unsigned int i = 0; i < 8; i++)
        encoded_len[i] = (unsigned char)(((uint64_t)len >> (i * 8)) & 0xffU);
    sha3_256_write(sha, encoded_len, sizeof(encoded_len));
    sha3_256_write(sha, (const unsigned char *)buf, len);
    ci_test_note_exact_bytes((uint64_t)len);
    if (stat_sha) dep_stat_root_add(stat_sha, relpath, &after);
    if (cb) parse_depfile(root, buf, len, cb, user);
    free(buf);
    return true;
}

static bool deps_scan_exact(const char *root, ci_dep_cb cb, void *user,
                            uint8_t exact_out[32], uint8_t stat_out[32])
{
    if (!root || !exact_out)
        LOG_FAIL("codeindex", "null arg to deps_scan");
    char build[CI_PATH_MAX];
    int bn = snprintf(build, sizeof(build), "%s/build", root);
    if (bn <= 0 || (size_t)bn >= sizeof(build))
        LOG_FAIL("codeindex", "build path too long");
    enum platform_directory_probe_result build_probe =
        platform_directory_probe_real(build);
    bool present = build_probe == PLATFORM_DIRECTORY_PROBE_OK;
    if (build_probe == PLATFORM_DIRECTORY_PROBE_REFUSED)
        LOG_FAIL("codeindex", "inspect build directory failed: %s",
                 strerror(errno));

    struct sha3_256_ctx sha;
    dep_root_init(&sha, present);
    struct sha3_256_ctx stat_sha;
    if (stat_out) dep_stat_root_init(&stat_sha, present);
    if (!present) {
        sha3_256_finalize(&sha, exact_out);
        if (stat_out) sha3_256_finalize(&stat_sha, stat_out);
        return true;
    }

    struct dep_paths paths = {0};
    if (!collect_dep_paths(root, "build", &paths)) {
        dep_paths_free(&paths);
        LOG_FAIL("codeindex", "collect depfiles failed: %s", strerror(errno));
    }
    qsort(paths.items, paths.count, sizeof(paths.items[0]), dep_path_cmp);
    bool ok = true;
    for (size_t i = 0; i < paths.count && ok; i++)
        ok = scan_one_depfile(root, paths.items[i], cb, user, &sha,
                              stat_out ? &stat_sha : NULL);
    dep_paths_free(&paths);
    if (!ok)
        LOG_FAIL("codeindex", "scan depfiles failed");
    sha3_256_finalize(&sha, exact_out);
    if (stat_out) sha3_256_finalize(&stat_sha, stat_out);
    return true;
}

bool ci_deps_scan(const char *root, ci_dep_cb cb, void *user,
                  uint8_t out_root[32])
{
    return deps_scan_exact(root, cb, user, out_root, NULL);
}

bool ci_deps_scan_roots(const char *root, ci_dep_cb cb, void *user,
                        uint8_t exact_out[32], uint8_t stat_out[32])
{
    if (!stat_out)
        LOG_FAIL("codeindex", "null dep stat root output");
    return deps_scan_exact(root, cb, user, exact_out, stat_out);
}

bool codeindex_depfile_graph(const char *root, size_t *out_count,
                             int64_t *out_newest_mtime_ns)
{
    if (!root || !out_count || !out_newest_mtime_ns)
        LOG_FAIL("codeindex", "null arg to depfile_graph");
    *out_count = 0;
    *out_newest_mtime_ns = 0;

    char build[CI_PATH_MAX];
    int bn = snprintf(build, sizeof(build), "%s/build", root);
    if (bn <= 0 || (size_t)bn >= sizeof(build))
        LOG_FAIL("codeindex", "build path too long");
    enum platform_directory_probe_result build_probe =
        platform_directory_probe_real(build);
    if (build_probe != PLATFORM_DIRECTORY_PROBE_OK) {
        if (build_probe == PLATFORM_DIRECTORY_PROBE_MISSING)
            return true;  /* fresh tree: the graph is absent, not broken */
        LOG_FAIL("codeindex", "inspect build directory failed: %s",
                 strerror(errno));
    }

    struct dep_paths paths = {0};
    if (!collect_dep_paths(root, "build", &paths)) {
        dep_paths_free(&paths);
        LOG_FAIL("codeindex", "collect depfile inventory failed: %s",
                 strerror(errno));
    }
    bool ok = true;
    size_t count = 0;
    int64_t newest = 0;
    for (size_t i = 0; i < paths.count; i++) {
        char full[CI_PATH_MAX];
        int fn = snprintf(full, sizeof(full), "%s/%s", root, paths.items[i]);
        struct platform_positioned_file file;
        struct platform_positioned_file_snapshot snapshot;
        platform_positioned_file_init(&file);
        if (fn <= 0 || (size_t)fn >= sizeof(full) ||
            !platform_positioned_file_open(&file, full) ||
            !platform_positioned_file_snapshot(&file, &snapshot)) {
            platform_positioned_file_close(&file);
            ok = false;
            break;
        }
        platform_positioned_file_close(&file);
        count++;
        if (snapshot.modified_seconds > INT64_MAX / INT64_C(1000000000) ||
            snapshot.modified_seconds < INT64_MIN / INT64_C(1000000000)) {
            errno = EOVERFLOW;
            ok = false;
            break;
        }
        int64_t mt = snapshot.modified_seconds * INT64_C(1000000000) +
                     (int64_t)snapshot.modified_nanoseconds;
        if (mt > newest) newest = mt;
    }
    dep_paths_free(&paths);
    if (!ok)
        LOG_FAIL("codeindex", "inspect depfile inventory failed: %s",
                 strerror(errno ? errno : EIO));
    *out_count = count;
    *out_newest_mtime_ns = newest;
    return true;
}

bool ci_deps_stat_root_sha3(const char *root, uint8_t out_root[32])
{
    if (!root || !out_root)
        LOG_FAIL("codeindex", "null arg to deps_stat_root");
    char build[CI_PATH_MAX];
    int bn = snprintf(build, sizeof(build), "%s/build", root);
    if (bn <= 0 || (size_t)bn >= sizeof(build))
        LOG_FAIL("codeindex", "build path too long");
    enum platform_directory_probe_result build_probe =
        platform_directory_probe_real(build);
    bool present = build_probe == PLATFORM_DIRECTORY_PROBE_OK;
    if (build_probe == PLATFORM_DIRECTORY_PROBE_REFUSED)
        LOG_FAIL("codeindex", "inspect build directory failed: %s",
                 strerror(errno));

    struct sha3_256_ctx sha;
    dep_stat_root_init(&sha, present);
    if (!present) {
        sha3_256_finalize(&sha, out_root);
        return true;
    }

    struct dep_paths paths = {0};
    if (!collect_dep_paths(root, "build", &paths)) {
        dep_paths_free(&paths);
        LOG_FAIL("codeindex", "collect depfile metadata failed: %s",
                 strerror(errno));
    }
    qsort(paths.items, paths.count, sizeof(paths.items[0]), dep_path_cmp);
    bool ok = true;
    for (size_t i = 0; i < paths.count; i++) {
        char full[CI_PATH_MAX];
        int fn = snprintf(full, sizeof(full), "%s/%s", root, paths.items[i]);
        struct platform_positioned_file file;
        struct platform_positioned_file_snapshot snapshot;
        platform_positioned_file_init(&file);
        if (fn <= 0 || (size_t)fn >= sizeof(full) ||
            !platform_positioned_file_open(&file, full) ||
            !platform_positioned_file_snapshot(&file, &snapshot)) {
            platform_positioned_file_close(&file);
            ok = false;
            break;
        }
        platform_positioned_file_close(&file);
        dep_stat_root_add(&sha, paths.items[i], &snapshot);
    }
    dep_paths_free(&paths);
    if (!ok)
        LOG_FAIL("codeindex", "inspect depfile metadata failed: %s",
                 strerror(errno ? errno : EIO));
    sha3_256_finalize(&sha, out_root);
    return true;
}
