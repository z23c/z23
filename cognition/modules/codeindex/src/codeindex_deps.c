/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * codeindex_deps — turn the compiler's own dependency files (the depfiles
 * under build/, extension .d) into include edges. Each depfile records
 * "<obj>: <src.c> <prereq> ..."; we emit a (source, prerequisite) pair for
 * EVERY in-tree prerequisite the compiler listed, which is the include graph
 * the build already computed for its configuration. Only the quoted includes
 * a depfile omits are read from source text (below).
 *
 * The prerequisite list is taken verbatim, never filtered by file extension.
 * The compiler records every byte it read, and plenty of those are not .h:
 * the ~23 tracked X-macro registries (`*.def` — the command catalog, the
 * condition registry, the sync-kernel catalog, the diagnostics dumpers) are
 * `#include`d exactly like headers and change a translation unit's behavior
 * exactly like headers. An extension allowlist silently dropped them from the
 * graph, so a registry edit moved no downstream content key and busted no
 * cache. The depfile is the authority; if the compiler read it, it is an edge.
 * A listed path that is not a regular file in this checkout is still an edge:
 * the header was deleted or renamed after the compile, a generated input has
 * not been generated yet, or the live epoch describes an older layout. The
 * unit still read that path, so its change must still impact the unit;
 * dropping the edge would narrow every plan past it. Such a path, or a
 * depfile that is incomplete or older than its translation unit, makes the
 * include answer not complete.
 *
 * A depfile describes one configuration of the compile. A quoted include
 * inside an inactive conditional (a Windows-only .inc on Linux) names an
 * in-tree file that configuration never read, so the depfile omits it. That
 * file still shapes the unit elsewhere, so it is added as an edge from the
 * translation unit and scanned the same way for what it includes. Such an
 * edge only adds work, and a text scan that cannot finish still refuses.
 * Only quoted includes the scan resolves are added: one found at the checkout
 * root, beside the including file or the unit, or under that file's module
 * include/ directory. A quoted include that resolves at none of those places,
 * or an angle-bracket include, adds no edge and does not refuse, so an
 * inactive include reached only through another -I directory is not in the
 * graph.
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
 * The live epoch is shared by every tree built into it, so it can hold the
 * depfile of a translation unit this tree does not have (a failed candidate
 * added it). A depfile whose primary unit is a source outside build/ that is
 * absent is foreign: it is hashed but adds no edge and no refusal, and the
 * scan logs how many it skipped. A present unit's missing or unreadable
 * input, and an absent generated unit under build/, still refuse.
 *
 * If build/ is absent (a fresh tree), no edges are produced. An epoch-managed
 * root with no resolvable current epoch contributes nothing and says so.
 * Other I/O failures fail closed. */

#include "codeindex_priv.h"

#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "util/path_util.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

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

/* Lexically fold "." and ".." segments so an edge names a file by its
 * checkout path, however the source spelled it ("tools/command/../../x.def"
 * is "x.def"). False when the path climbs out of the checkout. */
static bool dep_fold_dots(char path[CI_PATH_MAX])
{
    char folded[CI_PATH_MAX];
    size_t used = 0;
    const char *seg = path;
    while (*seg) {
        const char *slash = strchr(seg, '/');
        size_t len = slash ? (size_t)(slash - seg) : strlen(seg);
        if (len == 2 && seg[0] == '.' && seg[1] == '.') {
            if (used == 0)
                return false;
            while (used > 0 && folded[used - 1] != '/')
                used--;
            if (used > 0)
                used--;
        } else if (len > 0 && !(len == 1 && seg[0] == '.')) {
            if (used > 0)
                folded[used++] = '/';
            memcpy(folded + used, seg, len);
            used += len;
        }
        seg += len;
        if (*seg == '/')
            seg++;
    }
    folded[used] = '\0';
    memcpy(path, folded, used + 1);
    return used > 0;
}

/* Rewrite an absolute or ./-relative depfile token to a folded repo-relative
 * path, or return false if the token is outside the tree (a system header). */
static bool to_relpath(const char *root, const char *tok, char out[CI_PATH_MAX])
{
    size_t rl = strlen(root);
    if (strncmp(tok, root, rl) == 0 && tok[rl] == '/') {
        snprintf(out, CI_PATH_MAX, "%s", tok + rl + 1);
        return dep_fold_dots(out);
    }
    if (tok[0] == '/' || (isalpha((unsigned char)tok[0]) && tok[1] == ':'))
        return false;  /* absolute, outside root */
    /* already relative (build usually emits repo-relative prereqs) */
    if (strncmp(tok, "./", 2) == 0) tok += 2;
    if (tok[0] == '/') return false;
    /* reject paths that escape upward or reference vendored system trees */
    if (strncmp(tok, "../", 3) == 0) return false;
    snprintf(out, CI_PATH_MAX, "%s", tok);
    return dep_fold_dots(out);
}

static bool has_ext(const char *s, const char *ext)
{
    size_t a = strlen(s), b = strlen(ext);
    return a >= b && strcmp(s + a - b, ext) == 0;
}

/* True when `rel` is a regular file in this checkout. */
static bool rel_is_regular_file(const char *root, const char *rel)
{
    char path[CI_PATH_MAX];
    struct stat st;
    int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    if (stat(path, &st) != 0) return false;
    return S_ISREG(st.st_mode);
}

/* Set when a scanned depfile cannot support a complete narrow include answer.
 * Reset at the start of each deps scan. The build stores the bit, and beside
 * it the FIRST rule that set it and the file that rule fired on: the scan
 * order is sorted, so that first cause is deterministic, and it is what a
 * closure-truncated refusal reports as its evidence. */
static int g_include_narrow_unsafe;
static char g_include_narrow_cause[CODEINDEX_INCLUDE_UNSAFE_CAUSE_MAX];
/* The depfile whose text is being checked, named in every cause. */
static const char *g_scan_depfile = "";

bool ci_deps_include_narrow_unsafe(void)
{
    return g_include_narrow_unsafe != 0;
}

const char *ci_deps_include_narrow_cause(void)
{
    return g_include_narrow_cause;
}

/* `rule` is a short stable tag; `path` is the repo-relative file it fired
 * on, or NULL when the depfile itself is the evidence. */
static void note_include_narrow_unsafe(const char *rule, const char *path)
{
    if (!g_include_narrow_unsafe) {
        if (path && path[0])
            (void)snprintf(g_include_narrow_cause,
                           sizeof g_include_narrow_cause, "%s %s -> %s", rule,
                           g_scan_depfile, path);
        else
            (void)snprintf(g_include_narrow_cause,
                           sizeof g_include_narrow_cause, "%s %s", rule,
                           g_scan_depfile);
    }
    g_include_narrow_unsafe = 1;
}

/* Digest of every include edge the latest deps scan produced, in scan order,
 * whether or not a caller consumed them. The index stores it with the rows it
 * built; an incremental refresh that reuses those rows compares it to decide
 * whether they still hold every current edge. */
static struct sha3_256_ctx g_edge_sha;
static uint8_t g_edge_root[32];
static bool g_edge_root_valid;

bool ci_deps_include_edge_root(uint8_t out[32]);
bool ci_deps_include_edge_root(uint8_t out[32])
{
    if (!out || !g_edge_root_valid)
        return false;
    memcpy(out, g_edge_root, sizeof g_edge_root);
    return true;
}

static void dep_edge_root_begin(void)
{
    static const char domain[] = "zcl.codeindex.include_edge_root.v1";
    g_edge_root_valid = false;
    sha3_256_init(&g_edge_sha);
    sha3_256_write(&g_edge_sha, (const unsigned char *)domain, sizeof(domain));
}

static void dep_edge_root_end(void)
{
    sha3_256_finalize(&g_edge_sha, g_edge_root);
    g_edge_root_valid = true;
}

static void dep_emit_edge(const char *src, const char *dep, ci_dep_cb cb,
                          void *user)
{
    sha3_256_write(&g_edge_sha, (const unsigned char *)src, strlen(src) + 1);
    sha3_256_write(&g_edge_sha, (const unsigned char *)dep, strlen(dep) + 1);
    if (cb)
        cb(src, dep, user);
}

/* Every in-tree prerequisite is kept. One this checkout no longer holds stays
 * an edge and refuses a complete include answer. */
static bool dep_prerequisite_kept(const char *root, const char *rel)
{
    if (rel_is_regular_file(root, rel))
        return true;
    note_include_narrow_unsafe("prereq_not_regular", rel);
    return true;
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
            if (have_src && dep_prerequisite_kept(root, rel))
                dep_emit_edge(src_rel, rel, cb, user);
        }
    }
}

struct dep_paths {
    char **items;
    size_t count;
    size_t capacity;
    size_t limit; /* 0: unbounded; else collection stops past it */
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
    if (paths->limit && paths->count >= paths->limit) return false;
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

/* Empty collections have a null items pointer; qsort needs a nonnull base. */
static void dep_paths_sort(struct dep_paths *paths)
{
    if (paths->count > 1)
        qsort(paths->items, paths->count, sizeof(paths->items[0]),
              dep_path_cmp);
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

static bool dep_child_ignored(const char *reldir, const char *name)
{
    /* This directory is the hot-swap/HOT_FORK action cache, whose owner
     * verifies its own depfiles. Its temporary .resident-* compile inputs
     * are deleted after use and are not ordinary object-epoch authority. */
    return name[0] == '.' || strcmp(name, "history") == 0 ||
           (strcmp(reldir, "build") == 0 &&
            strcmp(name, "hotswap-fast") == 0);
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
        if (dep_child_ignored(reldir, name)) continue;
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

static void note_depfile_incomplete(const char *text, size_t len)
{
    if (len == 0)
        return;
    if (text[len - 1] != '\n' || (len >= 2 && text[len - 2] == '\\'))
        note_include_narrow_unsafe("depfile_incomplete", NULL);
}

static bool dep_text_lists(const char *text, const char *token)
{
    size_t n = strlen(token);
    const char *p = text;
    while ((p = strstr(p, token)) != NULL) {
        char before = p == text ? ' ' : p[-1];
        char after = p[n];
        if ((before == ' ' || before == '\t' || before == '\n' ||
             before == ':' || before == '/') &&
            (after == '\0' || after == ' ' || after == '\t' ||
             after == '\n' || after == '\\' || after == ':'))
            return true;
        p += n;
    }
    return false;
}

static bool dep_outside_tree(const char *tok)
{
    return tok[0] == '/' || strncmp(tok, "../", 3) == 0 ||
           (isalpha((unsigned char)tok[0]) && tok[1] == ':');
}

/* A quoted include is resolved against its candidate directories, so only an
 * absolute one is outside the checkout; "../x.h" climbs from the includer. */
static bool dep_quoted_absolute(const char *quoted)
{
    return quoted[0] == '/' ||
           (isalpha((unsigned char)quoted[0]) && quoted[1] == ':');
}

/* Text-found include edges of one translation unit. `added` holds every file
 * already added as an edge; it is also the worklist of files still to scan,
 * so a cycle or a shared include is scanned once. */
#define CI_TEXT_INCLUDE_FILES 256

struct text_includes {
    const char *root;
    const char *unit;
    const char *dep_text;
    ci_dep_cb cb;
    void *user;
    struct dep_paths added;
};

static bool dep_paths_has(const struct dep_paths *paths, const char *path)
{
    for (size_t i = 0; i < paths->count; i++)
        if (strcmp(paths->items[i], path) == 0)
            return true;
    return false;
}

/* A candidate that is a regular file the depfile does not list becomes an
 * include edge of the unit. A listed one was read by the compile, and what it
 * read is listed too. Every existing candidate is kept, so an include that
 * could resolve more than one way keeps each way. */
static void text_include_candidate(struct text_includes *t,
                                   char rel[CI_PATH_MAX])
{
    if (!dep_fold_dots(rel) || !rel_is_regular_file(t->root, rel) ||
        dep_text_lists(t->dep_text, rel) || strcmp(rel, t->unit) == 0 ||
        dep_paths_has(&t->added, rel))
        return;
    if (t->added.count >= CI_TEXT_INCLUDE_FILES ||
        !dep_paths_push(&t->added, rel)) {
        note_include_narrow_unsafe("text_include_cap", t->unit);
        return;
    }
    dep_emit_edge(t->unit, rel, t->cb, t->user);
}

/* A quoted include resolves beside the file that names it, or, for a file
 * under a module's src/ tree, under that module's include/ directory. */
static void text_include_near(struct text_includes *t, const char *file,
                              const char *quoted)
{
    char dir[CI_PATH_MAX];
    char rel[CI_PATH_MAX];
    const char *slash = strrchr(file, '/');
    size_t dlen = slash ? (size_t)(slash - file) : 0;
    if (dlen == 0 || dlen >= sizeof dir)
        return;
    memcpy(dir, file, dlen);
    dir[dlen] = '\0';
    if (zcl_path_join(rel, sizeof rel, dir, quoted))
        text_include_candidate(t, rel);
    char *src_at = strstr(dir, "/src");
    if (!src_at || (src_at[4] != '\0' && src_at[4] != '/'))
        return;
    *src_at = '\0';
    int n = snprintf(rel, sizeof rel, "%s/include/%s", dir, quoted);
    if (n > 0 && (size_t)n < sizeof rel)
        text_include_candidate(t, rel);
}

/* Candidates: the checkout root, the including file's places, and the
 * translation unit's places. */
static void text_include_resolve(struct text_includes *t, const char *from,
                                 const char *quoted)
{
    char rel[CI_PATH_MAX];
    int n = snprintf(rel, sizeof rel, "%s", quoted);
    if (n > 0 && (size_t)n < sizeof rel)
        text_include_candidate(t, rel);
    text_include_near(t, from, quoted);
    if (strcmp(from, t->unit) != 0)
        text_include_near(t, t->unit, quoted);
}

/* Preserve the measured extent even when a source line contains zero bytes. */
static size_t text_read_line(FILE *file, char *line, size_t cap)
{
    size_t used = 0;
    int byte;
    while (used < cap - 1 && (byte = fgetc(file)) != EOF) {
        line[used++] = (char)byte;
        if (byte == '\n')
            break;
    }
    line[used] = '\0';
    return used;
}

static void text_scan_file(struct text_includes *t, const char *from)
{
    char path[CI_PATH_MAX];
    int n = snprintf(path, sizeof path, "%s/%s", t->root, from);
    FILE *file = n > 0 && (size_t)n < sizeof path ? fopen(path, "r") : NULL;
    if (!file) {
        note_include_narrow_unsafe("scan_unreadable", from);
        return;
    }
    /* Most source lines fit the stack buffer; a larger bound also covers the
     * existing generated registries without turning normal scans into a
     * closure refusal. Lines beyond it still fail closed below. */
    char line[8192];
    size_t used;
    while ((used = text_read_line(file, line, sizeof line)) > 0) {
        if (memchr(line, '\0', used) != NULL) {
            note_include_narrow_unsafe("text_line_nul", from);
            continue;
        }
        /* A directive can straddle two bounded chunks. Do not certify a
         * complete include closure when this bounded text scan cannot see
         * one whole source line. A short final line needs no newline. */
        if (used > 0 && line[used - 1] != '\n' && !feof(file))
            note_include_narrow_unsafe("text_line_truncated", from);
        char *quoted = strstr(line, "#include \"");
        char *end;
        if (!quoted)
            continue;
        quoted += 10;
        end = strchr(quoted, '"');
        if (!end)
            continue;
        *end = '\0';
        if (!dep_quoted_absolute(quoted))
            text_include_resolve(t, from, quoted);
    }
    if (ferror(file))
        note_include_narrow_unsafe("scan_unreadable", from);
    fclose(file);
}

/* Scan the unit's quoted includes, then each file that scan added. */
static void note_text_includes(const char *root, const char *unit,
                               const char *dep_text, ci_dep_cb cb, void *user)
{
    struct text_includes t = {
        .root = root, .unit = unit, .dep_text = dep_text,
        .cb = cb, .user = user,
    };
    text_scan_file(&t, unit);
    for (size_t i = 0; i < t.added.count; i++)
        text_scan_file(&t, t.added.items[i]);
    dep_paths_free(&t.added);
}

/* Edges name the unit by the repo-relative path parse_depfile gives it. */
static void note_unit_text_includes(const char *root, const char *token,
                                    const char *dep_text, ci_dep_cb cb,
                                    void *user)
{
    char unit[CI_PATH_MAX];
    if (to_relpath(root, token, unit))
        note_text_includes(root, unit, dep_text, cb, user);
}

static void note_source_newer_than_depfile(
    const char *root, const char *src,
    const struct platform_positioned_file_snapshot *dep)
{
    char path[CI_PATH_MAX];
    struct stat st;
    int n = snprintf(path, sizeof path, "%s/%s", root, src);
    if (n <= 0 || (size_t)n >= sizeof path || stat(path, &st) != 0) {
        note_include_narrow_unsafe("prereq_unstatable", src);
        return;
    }
#if defined(_WIN32)
    int64_t sec = (int64_t)st.st_mtime;
    uint32_t nsec = 0;
#else
    int64_t sec = (int64_t)st.st_mtim.tv_sec;
    uint32_t nsec = (uint32_t)st.st_mtim.tv_nsec;
#endif
    if (sec > dep->modified_seconds ||
        (sec == dep->modified_seconds && nsec > dep->modified_nanoseconds))
        note_include_narrow_unsafe("prereq_newer_than_depfile", src);
}

static bool dep_take_token(const char *text, size_t len, size_t *io,
                           char *out, size_t cap)
{
    size_t i = *io;
    size_t start;
    size_t n;
    while (i < len && (text[i] == ' ' || text[i] == '\t'))
        i++;
    if (i >= len || text[i] == '\n') {
        *io = i;
        return false;
    }
    start = i;
    while (i < len && text[i] != ' ' && text[i] != '\t' && text[i] != '\n' &&
           !(text[i] == '\\' && i + 1 < len && text[i + 1] == '\n'))
        i++;
    n = i - start;
    *io = i;
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, text + start, n);
    out[n] = '\0';
    return true;
}

static void note_depfile_rule_gaps(
    const char *root, const char *text, size_t len,
    const struct platform_positioned_file_snapshot *dep, ci_dep_cb cb,
    void *user)
{
    bool after_colon = false;
    bool saw_source = false;
    char token[CI_PATH_MAX];
    size_t i = 0;
    while (i < len) {
        if (text[i] == '\\' && i + 1 < len && text[i + 1] == '\n') {
            i += 2;
            continue;
        }
        if (!after_colon) {
            if (text[i] == ':')
                after_colon = true;
            i++;
            continue;
        }
        if (text[i] == '\n') {
            after_colon = false;
            saw_source = false;
            i++;
            continue;
        }
        if (!dep_take_token(text, len, &i, token, sizeof token))
            continue;
        if (dep_outside_tree(token))
            continue;
        if (!saw_source && (has_ext(token, ".c") || has_ext(token, ".cc") ||
                            has_ext(token, ".c23"))) {
            saw_source = true;
            note_unit_text_includes(root, token, text, cb, user);
        }
        if (!rel_is_regular_file(root, token))
            note_include_narrow_unsafe("prereq_not_regular", token);
        else
            note_source_newer_than_depfile(root, token, dep);
    }
}

/* A shared build epoch holds the objects of every tree built into it. A
 * candidate that added a translation unit and then failed leaves that unit's
 * depfile behind, and a later tree does not have the unit. Such a depfile is
 * foreign: it describes no unit of this tree, so it adds no edge and cannot
 * make this tree's include answer incomplete. Only an ABSENT primary unit
 * (ENOENT/ENOTDIR) outside build/ makes a depfile foreign. A generated unit
 * under build/ (a HOT_FORK .resident wrapper, a generated source) is
 * recreated by the build, so its absence still refuses. A present unit keeps
 * every check above, including a listed header that is missing. */
static size_t g_foreign_depfiles;
static char g_foreign_first[CI_PATH_MAX];

/* The primary unit a depfile names: the first in-tree .c/.cc/.c23
 * prerequisite of its first rule, repo-relative. */
static bool depfile_primary_unit(const char *root, const char *text,
                                 size_t len, char out[CI_PATH_MAX])
{
    char token[CI_PATH_MAX];
    size_t i = 0;
    while (i < len && text[i] != ':')
        i++;
    for (i++; i < len && text[i] != '\n';) {
        if (text[i] == '\\' && i + 1 < len && text[i + 1] == '\n') {
            i += 2;
            continue;
        }
        if (!dep_take_token(text, len, &i, token, sizeof token))
            continue;
        if ((has_ext(token, ".c") || has_ext(token, ".cc") ||
             has_ext(token, ".c23")) && to_relpath(root, token, out))
            return true;
    }
    return false;
}

static bool depfile_unit_foreign(const char *root, const char *text,
                                 size_t len)
{
    char unit[CI_PATH_MAX];
    char path[CI_PATH_MAX];
    struct stat st;
    if (!depfile_primary_unit(root, text, len, unit) ||
        strncmp(unit, "build/", 6) == 0)
        return false;
    int n = snprintf(path, sizeof path, "%s/%s", root, unit);
    if (n <= 0 || (size_t)n >= sizeof path)
        return false;
    errno = 0;
    return stat(path, &st) != 0 && (errno == ENOENT || errno == ENOTDIR);
}

static void note_foreign_depfile(const char *relpath)
{
    if (g_foreign_depfiles++ == 0)
        (void)snprintf(g_foreign_first, sizeof g_foreign_first, "%s",
                       relpath);
}

static void report_foreign_depfiles(void)
{
    if (g_foreign_depfiles > 0)
        LOG_INFO("codeindex",
                 "skipped %zu foreign depfile(s) whose translation unit is "
                 "absent from this tree (first: %s)",
                 g_foreign_depfiles, g_foreign_first);
}

static void note_depfile_narrow_safety(
    const char *root, const char *text, size_t len,
    const struct platform_positioned_file_snapshot *dep, ci_dep_cb cb,
    void *user)
{
    note_depfile_incomplete(text, len);
    note_depfile_rule_gaps(root, text, len, dep, cb, user);
}

/* A foreign depfile is hashed by the caller but adds no edge or refusal. */
static void scan_depfile_text(
    const char *root, const char *relpath, char *buf, size_t len,
    const struct platform_positioned_file_snapshot *dep, ci_dep_cb cb,
    void *user)
{
    g_scan_depfile = relpath;
    if (depfile_unit_foreign(root, buf, len)) {
        note_foreign_depfile(relpath);
    } else {
        note_depfile_narrow_safety(root, buf, len, dep, cb, user);
        parse_depfile(root, buf, len, cb, user);
    }
    g_scan_depfile = "";
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
    scan_depfile_text(root, relpath, buf, len, &after, cb, user);
    free(buf);
    return true;
}

static bool deps_scan_exact(const char *root, ci_dep_cb cb, void *user,
                            uint8_t exact_out[32], uint8_t stat_out[32])
{
    g_include_narrow_unsafe = 0;
    g_include_narrow_cause[0] = '\0';
    g_foreign_depfiles = 0;
    g_foreign_first[0] = '\0';
    dep_edge_root_begin();
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
        dep_edge_root_end();
        if (stat_out) sha3_256_finalize(&stat_sha, stat_out);
        return true;
    }

    struct dep_paths paths = {0};
    if (!collect_dep_paths(root, "build", &paths)) {
        dep_paths_free(&paths);
        LOG_FAIL("codeindex", "collect depfiles failed: %s", strerror(errno));
    }
    dep_paths_sort(&paths);
    bool ok = true;
    for (size_t i = 0; i < paths.count && ok; i++)
        ok = scan_one_depfile(root, paths.items[i], cb, user, &sha,
                              stat_out ? &stat_sha : NULL);
    dep_paths_free(&paths);
    if (!ok)
        LOG_FAIL("codeindex", "scan depfiles failed");
    report_foreign_depfiles();
    sha3_256_finalize(&sha, exact_out);
    dep_edge_root_end();
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

static bool dep_paths_stat_hash(const char *root, const struct dep_paths *paths,
                                struct sha3_256_ctx *sha)
{
    for (size_t i = 0; i < paths->count; i++) {
        char full[CI_PATH_MAX];
        int fn = snprintf(full, sizeof(full), "%s/%s", root, paths->items[i]);
        struct platform_positioned_file file;
        struct platform_positioned_file_snapshot snapshot;
        platform_positioned_file_init(&file);
        if (fn <= 0 || (size_t)fn >= sizeof(full) ||
            !platform_positioned_file_open(&file, full) ||
            !platform_positioned_file_snapshot(&file, &snapshot)) {
            platform_positioned_file_close(&file);
            LOG_FAIL("codeindex", "inspect depfile metadata failed: %s",
                     strerror(errno ? errno : EIO));
        }
        platform_positioned_file_close(&file);
        dep_stat_root_add(sha, paths->items[i], &snapshot);
    }
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
    dep_paths_sort(&paths);
    bool ok = dep_paths_stat_hash(root, &paths, &sha);
    dep_paths_free(&paths);
    if (!ok)
        LOG_FAIL("codeindex", "inspect depfile metadata failed: %s",
                 strerror(errno ? errno : EIO));
    sha3_256_finalize(&sha, out_root);
    return true;
}

/* The active depfile inventory with one stat() key per file, for a caller that
 * later re-stats exactly these paths. The inventory is collect_dep_paths'
 * own, so the epoch-current redirect and the history / hotswap-fast /
 * dot-name skips stay single-sourced. Collection stops the moment it passes
 * `cap` files and the call fails with nothing held; a caller must not trust a partial inventory. */
void ci_deps_keys_free(struct ci_deps_keys *keys)
{
    if (!keys) return;
    free(keys->names);
    free(keys->ent);
    memset(keys, 0, sizeof(*keys));
}

/* The (dev, ino, size, mtime, ctime) key of one depfile. Windows stat has no
 * nanosecond timestamps, so the key carries whole seconds there. */
static struct ci_merkle_stat_key dep_stat_key(const struct stat *st)
{
    struct ci_merkle_stat_key k = {.dev = (uint64_t)st->st_dev,
                                   .ino = (uint64_t)st->st_ino,
                                   .size = (uint64_t)st->st_size};
#if defined(_WIN32)
    k.mtime_sec = (uint64_t)st->st_mtime;
    k.ctime_sec = (uint64_t)st->st_ctime;
#else
    k.mtime_sec = (uint64_t)st->st_mtim.tv_sec;
    k.mtime_nsec = (uint64_t)st->st_mtim.tv_nsec;
    k.ctime_sec = (uint64_t)st->st_ctim.tv_sec;
    k.ctime_nsec = (uint64_t)st->st_ctim.tv_nsec;
#endif
    return k;
}

static bool dep_keys_fill(const char *root, const struct dep_paths *paths,
                          struct ci_deps_keys *out)
{
    size_t total = 0;
    for (size_t i = 0; i < paths->count; i++) total += strlen(paths->items[i]) + 1;
    out->names = zcl_malloc(total ? total : 1, "codeindex dep key names");
    out->ent = zcl_malloc((paths->count ? paths->count : 1) * sizeof(*out->ent),
                          "codeindex dep key entries");
    if (!out->names || !out->ent) return false;
    for (size_t i = 0; i < paths->count; i++) {
        char full[CI_PATH_MAX];
        int fn = snprintf(full, sizeof(full), "%s/%s", root, paths->items[i]);
        struct stat st;
        if (fn <= 0 || (size_t)fn >= sizeof(full) || stat(full, &st) != 0)
            LOG_FAIL("codeindex", "stat depfile failed path=%s: %s",
                     paths->items[i], strerror(errno));
        size_t len = strlen(paths->items[i]) + 1;
        memcpy(out->names + out->names_len, paths->items[i], len);
        out->ent[i].off = (uint32_t)out->names_len;
        const char *slash = strrchr(paths->items[i], '/');
        out->ent[i].dirlen = slash ? (uint32_t)(slash - paths->items[i]) : 0;
        out->names_len += len;
        out->ent[i].key = dep_stat_key(&st);
        out->count++;
    }
    return true;
}

bool ci_deps_stat_keys(const char *root, struct ci_deps_keys *out, size_t cap)
{
    if (!root || !out)
        LOG_FAIL("codeindex", "null arg to deps_stat_keys");
    memset(out, 0, sizeof(*out));
    char build[CI_PATH_MAX];
    int bn = snprintf(build, sizeof(build), "%s/build", root);
    if (bn <= 0 || (size_t)bn >= sizeof(build))
        LOG_FAIL("codeindex", "build path too long");
    enum platform_directory_probe_result probe =
        platform_directory_probe_real(build);
    if (probe == PLATFORM_DIRECTORY_PROBE_MISSING) return true;
    if (probe != PLATFORM_DIRECTORY_PROBE_OK)
        LOG_FAIL("codeindex", "inspect build directory failed: %s",
                 strerror(errno));
    struct dep_paths paths = {.limit = cap};
    bool ok = collect_dep_paths(root, "build", &paths) &&
              dep_keys_fill(root, &paths, out);
    dep_paths_free(&paths);
    if (!ok) ci_deps_keys_free(out);
    return ok;
}
