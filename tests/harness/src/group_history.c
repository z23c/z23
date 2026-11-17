/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: the persistent per-group outcome ledger the parallel test
 *          runner appends beside last-run.json, and dev.test.history
 *          reads. One JSON line per EXECUTED group; skipped and cache-hit
 *          groups are absent (a cache hit already has its row from the
 *          run that stored the key).
 *
 * ROW (zcl.test_group_history.v1, one object per line):
 *   {"ts":"2026-11-17T18:00:00Z","group":"alpha","rc":0,
 *    "verdict":"PASS","wall_ms":1234,"load_flaky":0,
 *    "tree":"76ffcc4885843f63df1f69fc8c531911ba5f1181"}
 * ts is the shared run timestamp (UTC, the timing artifact's own format);
 * rc mirrors the timing row (a signaled group carries the negated signal);
 * verdict is tally_group's pass rule; wall_ms is null when the child's
 * duration was not measured; tree is the worktree HEAD at run time or ""
 * when unresolvable. Group names come from the compile-time registry, so
 * they need no JSON escaping — the timing rows print them the same way.
 *
 * The append is best-effort like the timing artifact: a failure is the
 * caller's one stderr line, never a failed test run. This is a mutable
 * diagnostic ledger, never signed evidence or an admission authority. */

#include "test/group_history.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* ── line rendering ─────────────────────────────────────────────────── */

size_t zcl_group_history_line(char *buf, size_t cap,
                              const struct zcl_group_history_row *row,
                              const char *ts, const char *tree)
{
    if (!buf || cap == 0 || !row || !row->group || !ts || !tree)
        return 0;
    int n;
    if (row->timing_valid) {
        n = snprintf(buf, cap,
                     "{\"ts\":\"%s\",\"group\":\"%s\",\"rc\":%d,"
                     "\"verdict\":\"%s\",\"wall_ms\":%lld,"
                     "\"load_flaky\":%d,\"tree\":\"%s\"}",
                     ts, row->group, row->rc, row->pass ? "PASS" : "FAIL",
                     row->wall_ms, row->load_flaky, tree);
    } else {
        n = snprintf(buf, cap,
                     "{\"ts\":\"%s\",\"group\":\"%s\",\"rc\":%d,"
                     "\"verdict\":\"%s\",\"wall_ms\":null,"
                     "\"load_flaky\":%d,\"tree\":\"%s\"}",
                     ts, row->group, row->rc, row->pass ? "PASS" : "FAIL",
                     row->load_flaky, tree);
    }
    if (n < 0 || (size_t)n >= cap) {
        if (cap > 0)
            buf[0] = '\0';
        return 0;
    }
    return (size_t)n;
}

/* write() until all `len` bytes land; false with errno on a hard failure. */
static bool gh_write_all(int fd, const char *data, size_t len)
{
    size_t done = 0;
    while (done < len) {
        ssize_t w = write(fd, data + done, len - done);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return false;
        }
        done += (size_t)w;
    }
    return true;
}

int zcl_group_history_append(const char *path, const char *ts,
                             const char *tree,
                             const struct zcl_group_history_row *rows,
                             size_t count)
{
    if (count == 0)
        return 0;
    if (!path || !path[0] || !ts || !tree) {
        errno = EINVAL;
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0)
        return -1;
    int appended = 0;
    for (size_t i = 0; i < count; i++) {
        char line[512];
        size_t n = zcl_group_history_line(line, sizeof(line), &rows[i], ts,
                                          tree);
        if (n == 0 || n + 1 >= sizeof(line)) {
            errno = EMSGSIZE;
            close(fd);
            return -1;
        }
        line[n] = '\n';
        if (!gh_write_all(fd, line, n + 1)) {
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        appended++;
    }
    return close(fd) == 0 ? appended : -1;
}

/* ── worktree HEAD resolution ───────────────────────────────────────── */

/* Lowercase hex, exactly 40 digits. */
static bool gh_sha40(const char *s)
{
    if (!s || strlen(s) != 40)
        return false;
    for (const char *p = s; *p; p++) {
        if ((*p < '0' || *p > '9') && (*p < 'a' || *p > 'f'))
            return false;
    }
    return true;
}

/* Read one small text file, NUL-terminated and trailing-newline-trimmed. */
static bool gh_read_small(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;
    ssize_t r = read(fd, buf, cap - 1);
    int saved = errno;
    close(fd);
    if (r < 0) {
        errno = saved;
        return false;
    }
    buf[r] = '\0';
    while (r > 0 && (buf[r - 1] == '\n' || buf[r - 1] == '\r'))
        buf[--r] = '\0';
    return true;
}

static bool gh_join(const char *base, const char *rel, char *out, size_t cap)
{
    int n = snprintf(out, cap, "%s/%s", base, rel);
    return n > 0 && (size_t)n < cap;
}

/* The git dir of `root`: .git itself when it is a directory, else the
 * target of the `gitdir: <path>` file a linked worktree keeps there. */
static bool gh_gitdir(const char *root, char *out, size_t cap)
{
    char dotgit[1024], body[1024];
    struct stat st;
    if (snprintf(dotgit, sizeof(dotgit), "%s/.git", root) >=
        (int)sizeof(dotgit))
        return false;
    if (stat(dotgit, &st) != 0)
        return false;
    if (S_ISDIR(st.st_mode)) {
        int n = snprintf(out, cap, "%s", dotgit);
        return n > 0 && (size_t)n < cap;
    }
    if (!S_ISREG(st.st_mode) || !gh_read_small(dotgit, body, sizeof(body)))
        return false;
    if (strncmp(body, "gitdir: ", 8) != 0 || body[8] == '\0')
        return false;
    if (body[8] == '/') {
        int n = snprintf(out, cap, "%s", body + 8);
        return n > 0 && (size_t)n < cap;
    }
    return gh_join(root, body + 8, out, cap);
}

/* Ref names are identifiers with slashes; whitespace or a dot cannot
 * appear in one, so anything holding them is not a ref we resolve. */
static bool gh_ref_name_ok(const char *s)
{
    if (!s || !s[0])
        return false;
    for (const char *p = s; *p; p++) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '.')
            return false;
    }
    return true;
}

/* `<dir>/<ref>` when it holds exactly one 40-hex line. */
static bool gh_loose_ref(const char *dir, const char *ref, char *out,
                         size_t cap)
{
    char path[1280], body[80];
    if (!gh_join(dir, ref, path, sizeof(path)))
        return false;
    if (!gh_read_small(path, body, sizeof(body)) || !gh_sha40(body))
        return false;
    (void)snprintf(out, cap, "%s", body);
    return true;
}

/* The `<sha> <ref>` line for `ref` in `<dir>/packed-refs`. */
static bool gh_packed_ref(const char *dir, const char *ref, char *out,
                          size_t cap)
{
    char path[1280], body[8192];
    if (!gh_join(dir, "packed-refs", path, sizeof(path)))
        return false;
    if (!gh_read_small(path, body, sizeof(body)))
        return false;
    char *save = NULL;
    for (char *line = strtok_r(body, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *sp = strchr(line, ' ');
        if (!sp)
            continue;
        *sp = '\0';
        if (strcmp(sp + 1, ref) != 0 || !gh_sha40(line))
            continue;
        (void)snprintf(out, cap, "%s", line);
        return true;
    }
    return false;
}

/* The shared dir behind a linked worktree's git dir (its commondir file),
 * or `gitdir` itself when the worktree owns everything. */
static void gh_common_dir(const char *gitdir, char *out, size_t cap)
{
    char rel[512];
    out[0] = '\0';
    if (gh_join(gitdir, "commondir", rel, sizeof(rel)) &&
        gh_read_small(rel, out, cap) && out[0]) {
        if (out[0] != '/') {
            char abs[768];
            if (gh_join(gitdir, out, abs, sizeof(abs)))
                (void)snprintf(out, cap, "%s", abs);
        }
        return;
    }
    (void)snprintf(out, cap, "%s", gitdir);
}

/* Resolve one ref the way git would: loose in the worktree's git dir,
 * loose in the common dir, then packed in the common dir. */
static bool gh_resolve_ref(const char *gitdir, const char *ref, char *out,
                           size_t cap)
{
    if (gh_loose_ref(gitdir, ref, out, cap))
        return true;
    char common[768];
    gh_common_dir(gitdir, common, sizeof(common));
    if (gh_loose_ref(common, ref, out, cap))
        return true;
    return gh_packed_ref(common, ref, out, cap);
}

void zcl_group_history_tree(const char *root, char *out, size_t cap)
{
    if (!out || cap == 0)
        return;
    out[0] = '\0';
    if (!root || !root[0] || cap < ZCL_GROUP_HISTORY_TREE_LEN)
        return;
    char gitdir[1024], head[512];
    if (!gh_gitdir(root, gitdir, sizeof(gitdir)))
        return;
    char path[1280];
    if (!gh_join(gitdir, "HEAD", path, sizeof(path)) ||
        !gh_read_small(path, head, sizeof(head)))
        return;
    if (gh_sha40(head)) {
        (void)snprintf(out, cap, "%s", head);
        return;
    }
    if (strncmp(head, "ref: ", 5) != 0)
        return;
    const char *ref = head + 5;
    if (!gh_ref_name_ok(ref))
        return;
    char sha[ZCL_GROUP_HISTORY_TREE_LEN];
    if (gh_resolve_ref(gitdir, ref, sha, sizeof(sha)) && gh_sha40(sha))
        (void)snprintf(out, cap, "%s", sha);
}
