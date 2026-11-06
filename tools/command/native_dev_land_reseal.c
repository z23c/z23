/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: dev.land re-derives the core seal files when a row that ran the
 *          unseal ritual is rebased onto a main that ran it too.
 *
 * WHY. Every core commit carries four derived files: core/MANIFEST.sha3,
 * the two hot-swap mirrors of it, and one appended core/UNSEAL.md entry.
 * Two ritual rows therefore always conflict on all four, and each rebase
 * was a manual replay of `make core-unseal` + `make core-seal` per commit.
 *
 * RULE. A rebase stop is settled here only when every unmerged path is one
 * of the four seal files (dl_seal_paths_only; any other path is reported
 * and aborted exactly as before) and all of these hold:
 *   - the row as a whole (dl_reseal_gate, read at the tip before the replay
 *     moves the checkout): its tip re-froze the manifest since
 *     merge-base(main, tip); that seal verifies in the tip's own tree
 *     (`make core-seal-check`, no unseal token present), so the queue never
 *     seals an edit its author did not; and no core/ path other than the
 *     manifest and the log changed on BOTH sides of that merge base, so no
 *     core file is a merge nobody sealed, even one git merged cleanly;
 *   - the commit being picked itself ran the ritual: it changed the manifest
 *     AND its UNSEAL.md is its parent's bytes plus a non-empty tail;
 *   - at most DL_SEAL_STOPS picks need it.
 * A declined reseal leaves the conflict exactly as before, with the reason
 * appended to its detail. A tool that fails or times out (git, make) is a
 * host-load failure the step retries, never a conflict.
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
 *     message and authorship (`commit -C REBASE_HEAD -S`, unsigned only in
 *     the unsigned fixture, as the queue's linear commit) and the rebase
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
#define DL_SEAL_STOPS 8
#define DL_SEAL_TOOL_MS (5 * 60 * 1000)
#define DL_SEAL_BLOB_MAX (16u * 1024u * 1024u)
#define DL_SEAL_LIST_CAP (1024u * 1024u)

static const char *const DL_SEAL_DERIVED[] = {
    DL_SEAL_MANIFEST,
    "engine/modules/hotswap/include/hotswap/core_seal_root.h",
    "engine/modules/hotswap/include/hotswap/core_seal_sections.h",
};
#define DL_SEAL_DERIVED_N (sizeof(DL_SEAL_DERIVED) / sizeof(DL_SEAL_DERIVED[0]))

static bool dl_path_is(const char *p, size_t len, const char *want)
{
    return len == strlen(want) && strncmp(p, want, len) == 0;
}

static bool dl_seal_path(const char *p, size_t len)
{
    if (dl_path_is(p, len, DL_SEAL_LOG))
        return true;
    for (size_t i = 0; i < DL_SEAL_DERIVED_N; i++) {
        if (dl_path_is(p, len, DL_SEAL_DERIVED[i]))
            return true;
    }
    return false;
}

/* The next line of a newline-separated list: its length without trailing
 * CR or blanks, and where the line after it starts (NULL at the end). */
static const char *dl_seal_line(const char *p, size_t *len)
{
    const char *eol = strchr(p, '\n');
    *len = eol ? (size_t)(eol - p) : strlen(p);
    while (*len > 0 && (p[*len - 1] == '\r' || p[*len - 1] == ' '))
        (*len)--;
    return eol ? eol + 1 : NULL;
}

bool dl_seal_paths_only(const char *paths)
{
    size_t seen = 0, len = 0;
    for (const char *p = paths, *next; p && *p; p = next) {
        next = dl_seal_line(p, &len);
        if (len > 0 && !dl_seal_path(p, len))
            return false;
        seen += len > 0;
    }
    return seen > 0;
}

/* ── git, held to the caller's runner ───────────────────────────────────── */

static int dl_seal_wt_run(void *ctx, const char *const *args, char *out,
                          size_t cap)
{
    return dl_git((const char *)ctx, args, out, cap, DL_SEAL_TOOL_MS);
}

static int dl_seal_run(const struct dl_seal_git *g, const char *const *args,
                       char *out, size_t cap)
{
    return g->run(g->ctx, args, out, cap);
}

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
static bool dl_blob_read(const struct dl_seal_git *g, const char *rev,
                         const char *path, struct dl_blob *b)
{
    char spec[512], size[64];
    const char *size_args[] = { "cat-file", "-s", spec, NULL };
    const char *blob_args[] = { "cat-file", "blob", spec, NULL };
    char *end = NULL;
    b->text = NULL;
    b->len = 0;
    if (snprintf(spec, sizeof(spec), "%s:%s", rev, path) >= (int)sizeof(spec) ||
        dl_seal_run(g, size_args, size, sizeof(size)) != 0)
        return false;
    errno = 0;
    unsigned long long want = strtoull(size, &end, 10);
    if (errno || end == size || want >= DL_SEAL_BLOB_MAX)
        return false;
    b->text = zcl_malloc((size_t)want + 2, "dev.land.seal.blob");
    if (!b->text)
        return false;
    if (dl_seal_run(g, blob_args, b->text, (size_t)want + 2) != 0 ||
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

static bool dl_seal_root_at(const struct dl_seal_git *g, const char *rev,
                            char root[65])
{
    struct dl_blob m;
    if (!dl_blob_read(g, rev, DL_SEAL_MANIFEST, &m))
        return false;
    bool ok = dl_seal_root(m.text, root);
    dl_blob_free(&m);
    return ok;
}

/* ── the commit ran the ritual itself ──────────────────────────────────── */

/* Object reads only: they never touch a worktree or its index. */
static int dl_pick_froze_manifest(const struct dl_seal_git *g,
                                  const char *commit)
{
    char parent[96];
    const char *args[] = { "diff", "--quiet", parent, commit,
                           "--", DL_SEAL_MANIFEST, NULL };
    if (snprintf(parent, sizeof(parent), "%s^", commit) >= (int)sizeof(parent))
        return DL_SEAL_ERR;
    int rc = dl_seal_run(g, args, NULL, 0);
    return rc == 1 ? DL_SEAL_YES : rc == 0 ? DL_SEAL_NO : DL_SEAL_ERR;
}

/* The bytes `commit` appended to UNSEAL.md: its parent's log must be a
 * strict byte prefix of its own. Anything else (an edited or dropped line,
 * no entry at all) is not the ritual. */
static int dl_pick_log_tail(const struct dl_seal_git *g, const char *commit,
                            struct dl_blob *tail)
{
    struct dl_blob parent, own;
    char up[96];
    tail->text = NULL;
    tail->len = 0;
    if (snprintf(up, sizeof(up), "%s^", commit) >= (int)sizeof(up) ||
        !dl_blob_read(g, up, DL_SEAL_LOG, &parent))
        return DL_SEAL_ERR;
    if (!dl_blob_read(g, commit, DL_SEAL_LOG, &own)) {
        dl_blob_free(&parent);
        return DL_SEAL_ERR;
    }
    size_t kept = parent.len;
    bool appended = own.len > kept && memcmp(own.text, parent.text, kept) == 0;
    dl_blob_free(&parent);
    if (!appended) {
        dl_blob_free(&own);
        return DL_SEAL_NO;
    }
    tail->len = own.len - kept;
    memmove(own.text, own.text + kept, tail->len + 1);
    tail->text = own.text;
    return DL_SEAL_YES;
}

static int dl_pick_ritual(const struct dl_seal_git *g, const char *commit,
                          struct dl_blob *tail)
{
    int froze = dl_pick_froze_manifest(g, commit);
    if (froze != DL_SEAL_YES)
        return froze;
    return dl_pick_log_tail(g, commit, tail);
}

int dl_seal_ritual_commit(const struct dl_seal_git *g, const char *commit)
{
    struct dl_blob tail;
    int ritual = dl_pick_ritual(g, commit, &tail);
    dl_blob_free(&tail);
    return ritual;
}

/* ── the row as a whole: dl_reseal_gate ─────────────────────────────────── */

static int dl_gate_set(struct dl_seal_gate *gate, int verdict, const char *why)
{
    gate->verdict = verdict;
    (void)snprintf(gate->why, sizeof(gate->why), "%s", why);
    return verdict;
}

/* The core/ paths `from`..`to` changed, newline separated (heap; NULL on a
 * git failure or a list that may be truncated). */
static char *dl_core_paths(const char *wt, const char *from, const char *to)
{
    const char *args[] = { "diff", "--name-only", "--no-renames", from, to,
                           "--", "core/", NULL };
    char *out = zcl_malloc(DL_SEAL_LIST_CAP, "dev.land.seal.paths");
    if (out && (dl_git(wt, args, out, DL_SEAL_LIST_CAP, DL_SEAL_TOOL_MS) != 0 ||
                strlen(out) + 1 >= DL_SEAL_LIST_CAP)) {
        free(out);
        out = NULL;
    }
    return out;
}

static bool dl_list_has(const char *list, const char *p, size_t len)
{
    size_t n = 0;
    for (const char *q = list, *next; q && *q; q = next) {
        next = dl_seal_line(q, &n);
        if (n == len && strncmp(q, p, len) == 0)
            return true;
    }
    return false;
}

/* No core/ file but the manifest and the log changed on both sides. */
static int dl_gate_overlap(const char *wt, const char *base, const char *main,
                           struct dl_seal_gate *gate)
{
    char *theirs = dl_core_paths(wt, base, main);
    char *ours = theirs ? dl_core_paths(wt, base, "HEAD") : NULL;
    int verdict = ours ? DL_SEAL_YES : DL_SEAL_ERR;
    size_t len = 0;
    for (const char *p = ours, *next; p && *p && verdict == DL_SEAL_YES;
         p = next) {
        next = dl_seal_line(p, &len);
        if (len == 0 || dl_seal_path(p, len) || !dl_list_has(theirs, p, len))
            continue;
        verdict = DL_SEAL_NO;
        (void)snprintf(gate->why, sizeof(gate->why),
                       "core paths changed on both sides of the merge base: "
                       "%.*s", (int)len, p);
    }
    free(theirs);
    free(ours);
    if (verdict == DL_SEAL_ERR)
        (void)snprintf(gate->why, sizeof(gate->why), "%s",
                       "cannot list the core paths either side changed");
    gate->verdict = verdict;
    return verdict;
}

/* The tip's own seal verifies in its own tree, with nothing lifting it. */
static int dl_gate_check(const char *wt, struct dl_seal_gate *gate)
{
    char token[4096 + 32];
    const char *argv[] = { "make", "-s", "-C", wt, "core-seal-check", NULL };
    bool timed_out = false;
    if (snprintf(token, sizeof(token), "%s/.core-unseal-token", wt) >=
        (int)sizeof(token))
        return dl_gate_set(gate, DL_SEAL_ERR, "landing tree path too long");
    FILE *f = fopen(token, "rb");
    if (f) {
        (void)fclose(f);
        return dl_gate_set(gate, DL_SEAL_NO,
                           "an unseal token is present in the landing tree");
    }
    char *out = zcl_malloc(DL_LOG_CAP, "dev.land.seal.check");
    if (!out)
        return dl_gate_set(gate, DL_SEAL_ERR, "out of memory");
    int rc = zcl_spawn_capture_merged_observed(argv, out, DL_LOG_CAP,
                                               DL_SEAL_TOOL_MS, &timed_out);
    bool verdict = strstr(out, "core_seal:") != NULL;
    free(out);
    if (rc == 0 && !timed_out)
        return dl_gate_set(gate, DL_SEAL_YES, "");
    if (!timed_out && verdict)
        return dl_gate_set(gate, DL_SEAL_NO,
                           "the tip's own seal does not verify");
    return dl_gate_set(gate, DL_SEAL_ERR, "make core-seal-check failed or "
                                          "timed out");
}

/* `side` re-froze the manifest since `base`. */
static int dl_gate_froze(const char *wt, const char *base, const char *side,
                         const char *who, struct dl_seal_gate *gate)
{
    const char *args[] = { "diff", "--quiet", base, side, "--",
                           DL_SEAL_MANIFEST, NULL };
    int rc = dl_git(wt, args, NULL, 0, DL_SEAL_TOOL_MS);
    if (rc == 1)
        return dl_gate_set(gate, DL_SEAL_YES, "");
    (void)snprintf(gate->why, sizeof(gate->why), rc == 0
                   ? "%s did not re-freeze " DL_SEAL_MANIFEST
                   : "cannot read the manifest change of %s", who);
    gate->verdict = rc == 0 ? DL_SEAL_NO : DL_SEAL_ERR;
    return gate->verdict;
}

/* Only a row whose tip and main both re-froze the manifest can stop on a
 * seal-only conflict, so only such a row pays for the overlap listing and
 * the seal check. */
void dl_reseal_gate(const char *wt, const char *main, struct dl_seal_gate *gate)
{
    char base[96];
    const char *mb[] = { "merge-base", main, "HEAD", NULL };
    if (dl_git(wt, mb, base, sizeof(base), DL_SEAL_TOOL_MS) != 0) {
        (void)dl_gate_set(gate, DL_SEAL_ERR, "cannot name the merge base with main");
        return;
    }
    dl_seal_trim(base);
    if (!dl_sha_ok(base)) {
        (void)dl_gate_set(gate, DL_SEAL_ERR, "cannot name the merge base with main");
        return;
    }
    if (dl_gate_froze(wt, base, "HEAD", "the row", gate) == DL_SEAL_YES &&
        dl_gate_froze(wt, base, main, "main", gate) == DL_SEAL_YES &&
        dl_gate_overlap(wt, base, main, gate) == DL_SEAL_YES)
        (void)dl_gate_check(wt, gate);
}

/* ── resolution of one stopped pick ─────────────────────────────────────── */

static bool dl_write_bytes(FILE *f, const struct dl_blob *b)
{
    return b->len == 0 || fwrite(b->text, 1, b->len, f) == b->len;
}

/* UNSEAL.md = the new base's log, then the pick's own appended entries. */
static bool dl_reseal_log(const char *wt, const struct dl_blob *tail)
{
    char path[4096 + 32];
    const char *add[] = { "add", "--", DL_SEAL_LOG, NULL };
    const struct dl_seal_git g = { dl_seal_wt_run, (void *)wt };
    struct dl_blob ours;
    if (snprintf(path, sizeof(path), "%s/%s", wt, DL_SEAL_LOG) >=
            (int)sizeof(path) ||
        !dl_blob_read(&g, "HEAD", DL_SEAL_LOG, &ours))
        return false;
    FILE *f = fopen(path, "wb");
    bool ok = f && dl_write_bytes(f, &ours) && dl_write_bytes(f, tail);
    if (f && fclose(f) != 0)
        ok = false;
    dl_blob_free(&ours);
    return ok && dl_git(wt, add, NULL, 0, DL_SEAL_TOOL_MS) == 0;
}

/* Take the three derived files from the new base, clearing their unmerged
 * entries, so the sealer reads one index entry per sealed path. */
static bool dl_reseal_take_base(const char *wt)
{
    for (size_t i = 0; i < DL_SEAL_DERIVED_N; i++) {
        const char *args[] = { "checkout", "HEAD", "--", DL_SEAL_DERIVED[i],
                               NULL };
        if (dl_git(wt, args, NULL, 0, DL_SEAL_TOOL_MS) != 0)
            return false;
    }
    return true;
}

/* The landing tree's own `make core-seal`. Its output goes to the row log. */
static bool dl_reseal_make(const char *wt, const struct dl_row *row)
{
    const char *argv[] = { "make", "-s", "-C", wt, "core-seal", NULL };
    bool timed_out = false;
    char *out = zcl_malloc(DL_LOG_CAP, "dev.land.seal.make");
    if (!out)
        return false;
    int rc = zcl_spawn_capture_merged_observed(argv, out, DL_LOG_CAP,
                                               DL_SEAL_TOOL_MS, &timed_out);
    dl_log(row, out);
    free(out);
    return rc == 0 && !timed_out;
}

/* After the seal: nothing unmerged, and nothing but the three derived files
 * differs from the index. Then stage them. */
static int dl_reseal_confined(const char *wt)
{
    char changed[8192];
    const char *unmerged[] = { "diff", "--name-only", "--diff-filter=U", NULL };
    const char *dirty[] = { "diff", "--name-only", NULL };
    const char *add[] = { "add", "--", DL_SEAL_DERIVED[0], DL_SEAL_DERIVED[1],
                          DL_SEAL_DERIVED[2], NULL };
    size_t len = 0;
    if (dl_git(wt, unmerged, changed, sizeof(changed), DL_SEAL_TOOL_MS) != 0)
        return DL_SEAL_ERR;
    dl_seal_trim(changed);
    if (changed[0] != '\0')
        return DL_SEAL_NO;
    if (dl_git(wt, dirty, changed, sizeof(changed), DL_SEAL_TOOL_MS) != 0 ||
        strlen(changed) + 1 >= sizeof(changed))
        return DL_SEAL_ERR;
    for (const char *p = changed, *next; *p; p = next ? next : "") {
        next = dl_seal_line(p, &len);
        if (len > 0 && (!dl_seal_path(p, len) || dl_path_is(p, len, DL_SEAL_LOG)))
            return DL_SEAL_NO;
    }
    return dl_git(wt, add, NULL, 0, DL_SEAL_TOOL_MS) == 0 ? DL_SEAL_YES
                                                          : DL_SEAL_ERR;
}

static bool dl_reseal_record(const char *wt, struct dl_row *row)
{
    const struct dl_seal_git g = { dl_seal_wt_run, (void *)wt };
    char pick[256], old_root[65], new_root[65], note[512];
    const char *pick_args[] = { "rev-parse", "REBASE_HEAD", NULL };
    if (dl_git(wt, pick_args, pick, sizeof(pick), DL_SEAL_TOOL_MS) != 0 ||
        !dl_seal_root_at(&g, "REBASE_HEAD", old_root) ||
        !dl_seal_root_at(&g, ":0", new_root))
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

static int dl_reseal_fail(char *why, size_t cap, int verdict, const char *text)
{
    (void)snprintf(why, cap, "%s", text);
    return verdict;
}

/* Re-derive the seal for the pick git stopped on and commit it. YES, or NO
 * (declined, `why` says why) or ERR (a tool failed). */
static int dl_reseal_pick(const char *wt, struct dl_row *row, char *why,
                          size_t cap)
{
    const char *commit[] = { "commit", "--quiet", "--no-verify", "-C",
                             "REBASE_HEAD", dl_fixture_unsigned() ? NULL : "-S",
                             NULL };
    const struct dl_seal_git g = { dl_seal_wt_run, (void *)wt };
    struct dl_blob tail;
    int ritual = dl_pick_ritual(&g, "REBASE_HEAD", &tail);
    if (ritual != DL_SEAL_YES)
        return dl_reseal_fail(why, cap, ritual, ritual == DL_SEAL_NO
            ? "a conflicting commit did not run the unseal ritual"
            : "cannot read the conflicting commit's seal files");
    bool ok = dl_reseal_log(wt, &tail);
    dl_blob_free(&tail);
    if (!ok || !dl_reseal_take_base(wt))
        return dl_reseal_fail(why, cap, DL_SEAL_ERR, "cannot stage the seal files");
    if (!dl_reseal_make(wt, row))
        return dl_reseal_fail(why, cap, DL_SEAL_ERR,
                              "make core-seal failed or timed out");
    int confined = dl_reseal_confined(wt);
    if (confined != DL_SEAL_YES)
        return dl_reseal_fail(why, cap, confined, confined == DL_SEAL_NO
            ? "make core-seal changed files outside the seal"
            : "cannot read the resealed index");
    if (!dl_reseal_record(wt, row) ||
        dl_git(wt, commit, NULL, 0, DL_SEAL_TOOL_MS) != 0)
        return dl_reseal_fail(why, cap, DL_SEAL_ERR,
                              "cannot commit the resealed pick");
    return DL_SEAL_YES;
}

static int dl_reseal_end(struct dl_row *row, int rc)
{
    if (rc != 1) {
        row->seal_old_root[0] = '\0';
        row->seal_new_root[0] = '\0';
    }
    return rc;
}

int dl_reseal_rebase(const char *wt, struct dl_row *row,
                     const struct dl_seal_gate *gate, char *paths, size_t cap,
                     char *why, size_t why_cap)
{
    const char *cont[] = { "-c", "rerere.autoupdate=false", "rebase",
                           "--continue", NULL };
    const char *unmerged[] = { "diff", "--name-only", "--diff-filter=U", NULL };
    if (why_cap)
        why[0] = '\0';
    if (!dl_seal_paths_only(paths))
        return dl_reseal_end(row, 0);
    if (gate->verdict != DL_SEAL_YES) {
        (void)snprintf(why, why_cap, "%s", gate->why);
        return dl_reseal_end(row, gate->verdict == DL_SEAL_NO ? 0 : -1);
    }
    for (int stop = 0; stop < DL_SEAL_STOPS; stop++) {
        int picked = dl_reseal_pick(wt, row, why, why_cap);
        if (picked != DL_SEAL_YES)
            return dl_reseal_end(row, picked == DL_SEAL_NO ? 0 : -1);
        if (dl_git(wt, cont, NULL, 0, DL_SEAL_TOOL_MS) == 0)
            return dl_reseal_end(row, 1);
        (void)dl_git(wt, unmerged, paths, cap, DL_SEAL_TOOL_MS);
        dl_seal_trim(paths);
        if (!dl_seal_paths_only(paths))
            return dl_reseal_end(row, 0);
    }
    (void)snprintf(why, why_cap, "more than %d commits need the seal re-derived",
                   DL_SEAL_STOPS);
    return dl_reseal_end(row, 0);
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
