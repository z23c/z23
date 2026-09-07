/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * corpus-census: git-backed scope enumeration and claim resolution
 * (slice 1b). Enumerates each repo scope's tracked files with
 * `git ls-files -z` (untracked scratch — test-tmp/, build/, .zvcs — can
 * never enter the census) and resolves every matched path to exactly one
 * scope under the FILE-CLAIM PRECEDENCE rule documented at the top of
 * tools/corpus_census.c. Also holds file_load(), the plain repo-file
 * reader shared by measurement and by main()'s census-core feed.
 */

#define _GNU_SOURCE

#include "corpus_census_priv.h"

#include "base/checked.h"
#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "vcs/zcode_c23_corpus_census.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/* Does `path` match prefix `pfx`? Directory prefixes (trailing '/') match
 * the whole tree; other prefixes are literal file prefixes. */
static bool prefix_matches(const struct prefix *pfx, const char *path)
{
    return strncmp(path, pfx->text, strlen(pfx->text)) == 0;
}

struct match {
    char *path;
    size_t scope;
    size_t plen;
    bool via_tests;
};

static int cmp_match(const void *a, const void *b)
{
    const struct match *ma = a, *mb = b;
    int c = strcmp(ma->path, mb->path);
    if (c) return c;
    if (ma->via_tests != mb->via_tests) return ma->via_tests ? -1 : 1;
    if (ma->plen != mb->plen) return ma->plen > mb->plen ? -1 : 1;
    if (ma->scope != mb->scope) return ma->scope < mb->scope ? -1 : 1;
    return 0;
}

void scope_files_free(struct scope_files *sf)
{
    if (!sf) return;
    for (size_t i = 0; i < sf->n; i++) free(sf->paths[i]);
    free(sf->paths);
    free(sf->via_tests);
    memset(sf, 0, sizeof(*sf));
}

bool scope_files_push(struct scope_files *sf, const char *path,
                      bool via_tests)
{
    if (sf->n == sf->cap) {
        size_t next = sf->cap ? sf->cap * 2u : 32u;
        size_t pb = 0, fb = 0;
        if (!zcl_size_mul(next, sizeof(char *), &pb) ||
            !zcl_size_mul(next, sizeof(uint8_t), &fb))
            LOG_FAIL(CENSUS_LOG, "scope files capacity overflow");
        /* zcl_realloc never frees the original on failure; grow the two
         * arrays one at a time so a half-grown pair stays consistent. */
        char **np = zcl_realloc(sf->paths, pb, "corpus.files");
        if (!np)
            LOG_FAIL(CENSUS_LOG, "scope paths realloc to %zu", sf->n + 1u);
        sf->paths = np;
        uint8_t *nf = zcl_realloc(sf->via_tests, fb, "corpus.files.vt");
        if (!nf)
            LOG_FAIL(CENSUS_LOG, "scope flags realloc to %zu", sf->n + 1u);
        sf->via_tests = nf;
        sf->cap = next;
    }
    sf->paths[sf->n] = dup_str(path, "corpus.file.path");
    if (!sf->paths[sf->n])
        LOG_FAIL(CENSUS_LOG, "file path dup %s", path);
    sf->via_tests[sf->n] = via_tests ? 1u : 0u;
    sf->n++;
    return true;
}

/* ── one prefix's git ls-files enumeration ────────────────────────── */

static bool git_ls_files_cmd_build(char *cmd, size_t cmd_sz, const char *root,
                                   const struct prefix *pfx)
{
    if (pfx->is_dir) {
        char stripped[1024];
        size_t len = strlen(pfx->text);
        if (len >= sizeof(stripped))
            LOG_FAIL(CENSUS_LOG, "prefix too long: %s", pfx->text);
        memcpy(stripped, pfx->text, len - 1u);
        stripped[len - 1u] = '\0';
        if (snprintf(cmd, cmd_sz, "git -C '%s' ls-files -z -- '%s'", root,
                     stripped) >= (int)cmd_sz)
            LOG_FAIL(CENSUS_LOG, "git command over %u bytes",
                     CORPUS_CENSUS_CMD_MAX);
    } else {
        if (snprintf(cmd, cmd_sz, "git -C '%s' ls-files -z -- '%s' '%s*'",
                     root, pfx->text, pfx->text) >= (int)cmd_sz)
            LOG_FAIL(CENSUS_LOG, "git command over %u bytes",
                     CORPUS_CENSUS_CMD_MAX);
    }
    return true;
}

static bool git_ls_files_capture(const char *cmd, const struct prefix *pfx,
                                 struct buf *raw)
{
    FILE *pipe = popen(cmd, "r"); /* shellout-ok: standalone CLI tool */
    if (!pipe)
        LOG_FAIL(CENSUS_LOG, "popen git ls-files for %s", pfx->text);
    bool ok = true;
    uint8_t chunk[65536];
    size_t got;
    while ((got = fread(chunk, 1, sizeof(chunk), pipe)) > 0) {
        if (!buf_put(raw, chunk, got)) {
            ok = false;
            break;
        }
    }
    int status = pclose(pipe); /* shellout-ok: standalone CLI tool */
    if (!ok || status == -1 || !WIFEXITED(status) || WEXITSTATUS(status)) {
        buf_free(raw);
        LOG_FAIL(CENSUS_LOG, "git ls-files failed for prefix %s",
                 pfx->text);
    }
    return true;
}

static bool git_ls_files_filter_push(const struct buf *raw,
                                     const struct prefix *pfx,
                                     struct str_vec *out)
{
    size_t off = 0;
    while (off < raw->len) {
        size_t end = off;
        while (end < raw->len && raw->p[end] != 0) end++;
        if (end > off && prefix_matches(pfx, (const char *)raw->p + off) &&
            counted_extension((const char *)raw->p + off)) {
            if (!vec_push_len(out, (const char *)raw->p + off, end - off))
                LOG_FAIL(CENSUS_LOG, "enumeration push failed for %s",
                         pfx->text);
        }
        off = end + 1u;
    }
    return true;
}

/* Enumerate one prefix's tracked files under `root` via git ls-files -z.
 * The git pathspec is a deliberate SUPERSET of the prefix semantics (the
 * bare prefix: git recurses into directory pathspecs and accepts globs);
 * the exact prefix_matches() filter plus the counted-extension filter
 * decide membership, so untracked scratch can never enter the census. */
static bool git_ls_files_prefix(const char *root, const struct prefix *pfx,
                                struct str_vec *out)
{
    char cmd[CORPUS_CENSUS_CMD_MAX];
    if (!git_ls_files_cmd_build(cmd, sizeof(cmd), root, pfx)) return false;
    struct buf raw = {0};
    if (!git_ls_files_capture(cmd, pfx, &raw)) return false;
    bool ok = git_ls_files_filter_push(&raw, pfx, out);
    buf_free(&raw);
    return ok;
}

/* ── match collection and precedence resolution ───────────────────── */

static void matches_free(struct match *matches, size_t count)
{
    for (size_t i = 0; i < count; i++) free(matches[i].path);
    free(matches);
}

static bool claims_match_push(struct match **matches, size_t *match_count,
                              size_t *match_cap, const char *path,
                              size_t scope, size_t plen, bool via_tests)
{
    if (*match_count == *match_cap) {
        size_t next = *match_cap ? *match_cap * 2u : 256u;
        size_t bytes = 0;
        if (!zcl_size_mul(next, sizeof(**matches), &bytes))
            LOG_FAIL(CENSUS_LOG, "match capacity overflow");
        struct match *nm = zcl_realloc(*matches, bytes, "corpus.matches");
        if (!nm)
            LOG_FAIL(CENSUS_LOG, "match realloc to %zu", *match_count + 1u);
        *matches = nm;
        *match_cap = next;
    }
    (*matches)[*match_count].path = dup_str(path, "corpus.match.path");
    if (!(*matches)[*match_count].path)
        return false;
    (*matches)[*match_count].scope = scope;
    (*matches)[*match_count].plen = plen;
    (*matches)[*match_count].via_tests = via_tests;
    (*match_count)++;
    return true;
}

/* Enumerate every scope's prefixes and collect every matched path as a
 * candidate claim, in scope/prefix order. */
static bool claims_collect_matches(const char *root,
                                   const struct scope_def *defs,
                                   size_t scope_count,
                                   struct match **matches_out,
                                   size_t *match_count_out)
{
    struct match *matches = NULL;
    size_t match_count = 0, match_cap = 0;
    for (size_t s = 0; s < scope_count; s++) {
        for (size_t pi = 0; pi < defs[s].nsrc + defs[s].ntests; pi++) {
            const struct prefix *pfx =
                pi < defs[s].nsrc ? &defs[s].src[pi]
                                  : &defs[s].tests[pi - defs[s].nsrc];
            bool via_tests = pi >= defs[s].nsrc;
            struct str_vec paths = {0};
            if (!git_ls_files_prefix(root, pfx, &paths)) {
                vec_free(&paths);
                matches_free(matches, match_count);
                return false;
            }
            for (size_t k = 0; k < paths.n; k++) {
                if (!claims_match_push(&matches, &match_count, &match_cap,
                                       paths.v[k], s, strlen(pfx->text),
                                       via_tests)) {
                    vec_free(&paths);
                    matches_free(matches, match_count);
                    return false;
                }
            }
            vec_free(&paths);
        }
    }
    *matches_out = matches;
    *match_count_out = match_count;
    return true;
}

/* Group the sorted matches by path, refuse an equal-precedence tie, and
 * push each path's winner into its scope's resolved file list. */
static bool claims_assign_winners(struct match *matches, size_t match_count,
                                  const struct scope_def *defs,
                                  struct scope_files *resolved)
{
    if (!match_count) return true;
    qsort(matches, match_count, sizeof(*matches), cmp_match);
    size_t i = 0;
    while (i < match_count) {
        size_t j = i;
        while (j < match_count &&
               strcmp(matches[j].path, matches[i].path) == 0)
            j++;
        const struct match *win = &matches[i];
        for (size_t k = i + 1; k < j; k++) {
            const struct match *m = &matches[k];
            if (m->scope != win->scope &&
                m->via_tests == win->via_tests &&
                m->plen == win->plen) {
                LOG_ERROR(CENSUS_LOG,
                          "file %s claimed by scopes %s and %s at "
                          "equal precedence; fix the scopes def",
                          win->path, defs[win->scope].name,
                          defs[m->scope].name);
                return false;
            }
        }
        if (!scope_files_push(&resolved[win->scope], win->path,
                              win->via_tests))
            return false;
        i = j;
    }
    return true;
}

/* Enumerate every scope under `root` and resolve each matched path to
 * exactly one scope. Precedence: tests-kind claims beat src-kind claims;
 * among same-kind claims the longest prefix wins; equal-length competition
 * between two scopes is a fatal overlap error. */
bool claims_resolve(const char *root, const struct scope_def *defs,
                    size_t scope_count, struct scope_files **out)
{
    struct match *matches = NULL;
    size_t match_count = 0;
    struct scope_files *resolved = NULL;
    bool ok = false;

    if (!claims_collect_matches(root, defs, scope_count, &matches,
                                &match_count))
        return false;

    resolved = zcl_calloc(scope_count, sizeof(*resolved), "corpus.resolved");
    if (!resolved) {
        LOG_ERROR(CENSUS_LOG, "resolved alloc %zu", scope_count);
        goto done;
    }
    if (!claims_assign_winners(matches, match_count, defs, resolved))
        goto done;
    /* Matches were globally sorted by path, so each scope's push order is
     * ascending: resolved[s].paths needs no second sort. */
    *out = resolved;
    resolved = NULL;
    ok = true;
done:
    if (resolved) {
        for (size_t s = 0; s < scope_count; s++)
            scope_files_free(&resolved[s]);
        free(resolved);
    }
    matches_free(matches, match_count);
    return ok;
}

/* ── plain repo file loading ───────────────────────────────────────── */

/* Read one repo file. Content over VCS_ZCODE_C23_MAX_FILE_BYTES is NOT
 * read: bytes stays NULL and declared carries the real size, which the
 * census core turns into the OVERSIZE exclusion. */
bool file_load(const char *root, const char *relpath, uint8_t **bytes_out,
               size_t *len_out, uint64_t *declared_out)
{
    *bytes_out = NULL;
    *len_out = 0;
    *declared_out = 0;
    size_t full_len = strlen(root) + strlen(relpath) + 2u;
    char *full = zcl_malloc(full_len, "corpus.path");
    if (!full)
        LOG_FAIL(CENSUS_LOG, "path alloc for %s", relpath);
    (void)snprintf(full, full_len, "%s/%s", root, relpath);
    int fd = open(full, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        LOG_ERROR(CENSUS_LOG, "open %s: %s", full, strerror(errno));
        free(full);
        return false;
    }
    free(full);
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        LOG_ERROR(CENSUS_LOG, "stat %s: %s", relpath, strerror(errno));
        close(fd);
        return false;
    }
    *declared_out = (uint64_t)st.st_size;
    if ((uint64_t)st.st_size > VCS_ZCODE_C23_MAX_FILE_BYTES) {
        close(fd);
        return true; /* oversize: no bytes, declared size only */
    }
    size_t len = (size_t)st.st_size;
    uint8_t *bytes = zcl_malloc(len ? len : 1u, "corpus.file.bytes");
    if (!bytes) {
        close(fd);
        LOG_FAIL(CENSUS_LOG, "file bytes alloc %zu for %s", len, relpath);
    }
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, bytes + off, len - off);
        if (r <= 0) {
            LOG_ERROR(CENSUS_LOG, "read %s: %s", relpath,
                      r == 0 ? "short file" : strerror(errno));
            free(bytes);
            close(fd);
            return false;
        }
        off += (size_t)r;
    }
    close(fd);
    *bytes_out = bytes;
    *len_out = len;
    return true;
}
