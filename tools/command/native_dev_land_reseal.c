/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land re-derives the core seal files when a row that ran the
 *          unseal ritual is rebased onto a main that ran it too.
 *
 * WHY. Every core commit carries four derived files: core/MANIFEST.sha3,
 * the two hot-swap mirrors of it, and one appended core/UNSEAL.md entry.
 * Two ritual rows therefore always conflict on all four, and each rebase
 * was a manual replay of `make core-unseal` + `make core-seal` per commit.
 *
 * RULE. A rebase stop is settled here only when
 *   - every unmerged path is one of the four seal files (dl_seal_paths_only;
 *     any other path is reported and aborted exactly as before), and
 *   - the commit being picked itself ran the ritual: it changed the manifest
 *     AND its UNSEAL.md is its parent's bytes plus a non-empty tail.
 * A row that edits core/ without that never gets an unseal from the queue:
 * its conflict stands, or the proof's seal gate fails it as before.
 *
 * RESOLUTION, per stopped pick (git stops once per conflicting commit, so
 * each commit keeps a valid seal of its own):
 *   - core/UNSEAL.md = the new base's bytes, then the pick's own tail,
 *     verbatim. No line is dropped or rewritten; the carried entry keeps the
 *     author's "old ROOT". `git merge-file --union` is not used: it folds the
 *     identical "by:" trailer of two appended entries into one.
 *   - the manifest and both mirrors are taken from the new base, then the
 *     landing tree's own `make core-seal` (tools/core_seal.c and its two
 *     header generators) re-derives all three over the combined core tree.
 *     `make core-unseal` is never run: it would mint the token that lifts
 *     the seal gate and write an entry nobody made.
 *   - only those three files may change; the pick is committed with its own
 *     message and authorship (`commit -C REBASE_HEAD`) and the rebase
 *     continues.
 * The proof then runs check-core-seal and test_core_seal on the result like
 * any other. The row records the ROOT its last ritual commit carried and the
 * ROOT that commit carries now (seal_old_root, seal_new_root), and its log
 * names every re-derived pick. */

#include "command/native_dev_land_internal.h"

#include "base/safe_alloc.h"
#include "util/spawn.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DL_SEAL_MANIFEST "core/MANIFEST.sha3"
#define DL_SEAL_LOG "core/UNSEAL.md"
#define DL_SEAL_STOPS 256
#define DL_SEAL_BLOB_MAX (16u * 1024u * 1024u)

static const char *const DL_SEAL_DERIVED[] = {
    DL_SEAL_MANIFEST,
    "engine/modules/hotswap/include/hotswap/core_seal_root.h",
    "engine/modules/hotswap/include/hotswap/core_seal_sections.h",
};
#define DL_SEAL_DERIVED_N (sizeof(DL_SEAL_DERIVED) / sizeof(DL_SEAL_DERIVED[0]))

static bool dl_seal_path(const char *p, size_t len)
{
    if (len == strlen(DL_SEAL_LOG) && strncmp(p, DL_SEAL_LOG, len) == 0)
        return true;
    for (size_t i = 0; i < DL_SEAL_DERIVED_N; i++) {
        if (len == strlen(DL_SEAL_DERIVED[i]) &&
            strncmp(p, DL_SEAL_DERIVED[i], len) == 0)
            return true;
    }
    return false;
}

bool dl_seal_paths_only(const char *paths)
{
    size_t seen = 0;
    for (const char *p = paths; p && *p;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        while (len > 0 && (p[len - 1] == '\r' || p[len - 1] == ' '))
            len--;
        if (len > 0 && !dl_seal_path(p, len))
            return false;
        seen += len > 0;
        p = eol ? eol + 1 : NULL;
    }
    return seen > 0;
}

/* ── blobs ──────────────────────────────────────────────────────────────── */

struct dl_blob {
    char *text;
    size_t len;
};

static void dl_blob_free(struct dl_blob *b)
{
    free(b->text);
    b->text = NULL;
    b->len = 0;
}

static void dl_seal_trim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' '))
        s[--n] = '\0';
}

/* `rev`:`path` in full. The size git reports must equal the bytes captured,
 * so a truncated capture or a NUL byte is a refusal, never a short file. */
static bool dl_blob_read(const char *wt, const char *rev, const char *path,
                         struct dl_blob *b)
{
    char spec[512], size[64];
    const char *size_args[] = { "cat-file", "-s", spec, NULL };
    const char *blob_args[] = { "cat-file", "blob", spec, NULL };
    char *end = NULL;
    b->text = NULL;
    b->len = 0;
    if (snprintf(spec, sizeof(spec), "%s:%s", rev, path) >= (int)sizeof(spec) ||
        dl_git(wt, size_args, size, sizeof(size), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    errno = 0;
    unsigned long long want = strtoull(size, &end, 10);
    if (errno || end == size || want >= DL_SEAL_BLOB_MAX)
        return false;
    b->text = zcl_malloc((size_t)want + 2, "dev.land.seal.blob");
    if (!b->text)
        return false;
    if (dl_git(wt, blob_args, b->text, (size_t)want + 2, DL_GIT_TIMEOUT_MS) != 0 ||
        strlen(b->text) != (size_t)want) {
        dl_blob_free(b);
        return false;
    }
    b->len = (size_t)want;
    return true;
}

/* The 64-hex ROOT line of a manifest's text ("ROOT", blanks, the digest). */
static bool dl_seal_root(const char *text, char root[65])
{
    root[0] = '\0';
    for (const char *p = text; p && *p;) {
        const char *h = p + 4 + strspn(p + 4, " \t");
        if (strncmp(p, "ROOT", 4) == 0 && h > p + 4 &&
            strspn(h, "0123456789abcdef") == 64) {
            memcpy(root, h, 64);
            root[64] = '\0';
            return true;
        }
        p = strchr(p, '\n');
        p = p ? p + 1 : NULL;
    }
    return false;
}

static bool dl_seal_root_at(const char *wt, const char *rev, char root[65])
{
    struct dl_blob m;
    if (!dl_blob_read(wt, rev, DL_SEAL_MANIFEST, &m))
        return false;
    bool ok = dl_seal_root(m.text, root);
    dl_blob_free(&m);
    return ok;
}

/* ── rule 1: the pick ran the ritual itself ────────────────────────────── */

/* Read-only object queries: they never touch the worktree or its index, so
 * the queued precheck may ask them of any commit in the store too. */
static bool dl_pick_froze_manifest(const char *wt, const char *commit)
{
    char parent[96];
    const char *args[] = { "diff", "--quiet", parent, commit,
                           "--", DL_SEAL_MANIFEST, NULL };
    if (snprintf(parent, sizeof(parent), "%s^", commit) >= (int)sizeof(parent))
        return false;
    return dl_git(wt, args, NULL, 0, DL_GIT_TIMEOUT_MS) == 1;
}

/* The bytes `commit` appended to UNSEAL.md: its parent's log must be a
 * strict byte prefix of its own. Anything else (an edited or dropped line,
 * no entry at all) is not the ritual and is refused. */
static bool dl_pick_log_tail(const char *wt, const char *commit,
                             struct dl_blob *tail)
{
    struct dl_blob parent, own;
    char up[96];
    bool ok = false;
    tail->text = NULL;
    tail->len = 0;
    if (snprintf(up, sizeof(up), "%s^", commit) >= (int)sizeof(up) ||
        !dl_blob_read(wt, up, DL_SEAL_LOG, &parent))
        return false;
    if (dl_blob_read(wt, commit, DL_SEAL_LOG, &own)) {
        ok = own.len > parent.len &&
             memcmp(own.text, parent.text, parent.len) == 0;
        if (ok) {
            tail->len = own.len - parent.len;
            memmove(own.text, own.text + parent.len, tail->len + 1);
            tail->text = own.text;
        } else {
            dl_blob_free(&own);
        }
    }
    dl_blob_free(&parent);
    return ok;
}

bool dl_seal_ritual_commit(const char *wt, const char *commit)
{
    struct dl_blob tail;
    if (!dl_pick_froze_manifest(wt, commit) ||
        !dl_pick_log_tail(wt, commit, &tail))
        return false;
    dl_blob_free(&tail);
    return true;
}

/* The tip's own seal holds: a tip that re-froze the manifest since `main`
 * must verify against it in its own tree (the worktree is at the tip), or
 * the queue would seal edits the author never sealed. A live unseal token
 * would lift that check, so one in the landing tree is a refusal. */
bool dl_reseal_tip_sealed(const char *wt, const char *main)
{
    char base[96], token[4096 + 32];
    const char *mb[] = { "merge-base", main, "HEAD", NULL };
    const char *diff[] = { "diff", "--quiet", base, "HEAD", "--",
                           DL_SEAL_MANIFEST, NULL };
    const char *argv[] = { "make", "-s", "-C", wt, "core-seal-check", NULL };
    char *out;
    if (dl_git(wt, mb, base, sizeof(base), DL_GIT_TIMEOUT_MS) != 0)
        return false;
    dl_seal_trim(base);
    if (!dl_sha_ok(base) || dl_git(wt, diff, NULL, 0, DL_GIT_TIMEOUT_MS) != 1 ||
        snprintf(token, sizeof(token), "%s/.core-unseal-token", wt) >=
            (int)sizeof(token))
        return false;
    FILE *f = fopen(token, "rb");
    if (f) {
        (void)fclose(f);
        return false;
    }
    out = zcl_malloc(DL_LOG_CAP, "dev.land.seal.check");
    if (!out)
        return false;
    int rc = zcl_spawn_capture(argv, out, DL_LOG_CAP, DL_GIT_TIMEOUT_MS);
    free(out);
    return rc == 0;
}

/* ── resolution ─────────────────────────────────────────────────────────── */

static bool dl_write_bytes(FILE *f, const struct dl_blob *b)
{
    return b->len == 0 || fwrite(b->text, 1, b->len, f) == b->len;
}

/* UNSEAL.md = the new base's log, then the pick's own appended entries. */
static bool dl_reseal_log(const char *wt, const struct dl_blob *tail)
{
    char path[4096 + 32];
    const char *add[] = { "add", "--", DL_SEAL_LOG, NULL };
    struct dl_blob ours;
    if (snprintf(path, sizeof(path), "%s/%s", wt, DL_SEAL_LOG) >=
            (int)sizeof(path) ||
        !dl_blob_read(wt, "HEAD", DL_SEAL_LOG, &ours))
        return false;
    FILE *f = fopen(path, "wb");
    bool ok = f && dl_write_bytes(f, &ours) && dl_write_bytes(f, tail);
    if (f && fclose(f) != 0)
        ok = false;
    dl_blob_free(&ours);
    return ok && dl_git(wt, add, NULL, 0, DL_GIT_TIMEOUT_MS) == 0;
}

/* Take the three derived files from the new base, clearing their unmerged
 * entries, so the sealer reads one index entry per sealed path. */
static bool dl_reseal_take_base(const char *wt)
{
    for (size_t i = 0; i < DL_SEAL_DERIVED_N; i++) {
        const char *args[] = { "checkout", "HEAD", "--", DL_SEAL_DERIVED[i],
                               NULL };
        if (dl_git(wt, args, NULL, 0, DL_GIT_TIMEOUT_MS) != 0)
            return false;
    }
    return true;
}

/* The landing tree's own `make core-seal`. Its output goes to the row log. */
static bool dl_reseal_make(const char *wt, const struct dl_row *row)
{
    const char *argv[] = { "make", "-s", "-C", wt, "core-seal", NULL };
    char *out = zcl_malloc(DL_LOG_CAP, "dev.land.seal.make");
    if (!out)
        return false;
    int rc = zcl_spawn_capture(argv, out, DL_LOG_CAP, DL_GIT_TIMEOUT_MS);
    dl_log(row, out);
    free(out);
    return rc == 0;
}

/* After the seal: nothing unmerged, and nothing but the three derived files
 * differs from the index. Then stage them. */
static bool dl_reseal_confined(const char *wt)
{
    char changed[8192];
    const char *unmerged[] = { "diff", "--name-only", "--diff-filter=U", NULL };
    const char *dirty[] = { "diff", "--name-only", NULL };
    const char *add[] = { "add", "--", DL_SEAL_DERIVED[0], DL_SEAL_DERIVED[1],
                          DL_SEAL_DERIVED[2], NULL };
    if (dl_git(wt, unmerged, changed, sizeof(changed), DL_GIT_TIMEOUT_MS) != 0 ||
        changed[0] != '\0' ||
        dl_git(wt, dirty, changed, sizeof(changed), DL_GIT_TIMEOUT_MS) != 0 ||
        strlen(changed) + 1 >= sizeof(changed))
        return false;
    for (const char *p = changed; *p;) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        if (len > 0 && (!dl_seal_path(p, len) ||
                        strncmp(p, DL_SEAL_LOG, len) == 0))
            return false;
        p = eol ? eol + 1 : p + len;
    }
    return dl_git(wt, add, NULL, 0, DL_GIT_TIMEOUT_MS) == 0;
}

static bool dl_reseal_record(const char *wt, struct dl_row *row)
{
    char pick[256], old_root[65], new_root[65], note[512];
    const char *pick_args[] = { "rev-parse", "REBASE_HEAD", NULL };
    if (dl_git(wt, pick_args, pick, sizeof(pick), DL_GIT_TIMEOUT_MS) != 0 ||
        !dl_seal_root_at(wt, "REBASE_HEAD", old_root) ||
        !dl_seal_root_at(wt, ":0", new_root))
        return false;
    dl_seal_trim(pick);
    (void)snprintf(row->seal_old_root, sizeof(row->seal_old_root), "%s", old_root);
    (void)snprintf(row->seal_new_root, sizeof(row->seal_new_root), "%s", new_root);
    (void)snprintf(note, sizeof(note),
                   "core seal re-derived for %.40s: old ROOT %s new ROOT %s\n",
                   pick, old_root, new_root);
    dl_log(row, note);
    return true;
}

/* Settle one stopped pick, or refuse it with the worktree left for the
 * caller's `rebase --abort`. */
static bool dl_reseal_pick(const char *wt, struct dl_row *row)
{
    const char *commit[] = { "commit", "--quiet", "--no-verify",
                             "-C", "REBASE_HEAD", NULL };
    struct dl_blob tail;
    if (!dl_pick_froze_manifest(wt, "REBASE_HEAD") ||
        !dl_pick_log_tail(wt, "REBASE_HEAD", &tail))
        return false;
    bool ok = dl_reseal_log(wt, &tail);
    dl_blob_free(&tail);
    return ok && dl_reseal_take_base(wt) && dl_reseal_make(wt, row) &&
           dl_reseal_confined(wt) && dl_reseal_record(wt, row) &&
           dl_git(wt, commit, NULL, 0, DL_GIT_TIMEOUT_MS) == 0;
}

int dl_reseal_rebase(const char *wt, struct dl_row *row, bool tip_sealed,
                     char *paths, size_t cap)
{
    const char *cont[] = { "-c", "rerere.autoupdate=false", "rebase",
                           "--continue", NULL };
    const char *unmerged[] = { "diff", "--name-only", "--diff-filter=U", NULL };
    for (int stop = 0; tip_sealed && stop < DL_SEAL_STOPS; stop++) {
        if (!dl_seal_paths_only(paths) || !dl_reseal_pick(wt, row))
            break;
        if (dl_git(wt, cont, NULL, 0, DL_GIT_TIMEOUT_MS) == 0)
            return 1;
        (void)dl_git(wt, unmerged, paths, cap, DL_GIT_TIMEOUT_MS);
        dl_seal_trim(paths);
    }
    row->seal_old_root[0] = '\0';
    row->seal_new_root[0] = '\0';
    return 0;
}

size_t dl_seal_append(const struct dl_row *r, char *out, size_t cap,
                      size_t size)
{
    char member[192];
    if (!r->seal_old_root[0] || !r->seal_new_root[0] || size < 2)
        return size;
    int n = snprintf(member, sizeof(member),
                     ",\"seal_old_root\":\"%.64s\",\"seal_new_root\":\"%.64s\"}\n",
                     r->seal_old_root, r->seal_new_root);
    if (n <= 0 || n >= (int)sizeof(member) || (size_t)n >= cap - (size - 2))
        return size;
    memcpy(out + size - 2, member, (size_t)n + 1);
    return size - 2 + (size_t)n;
}
