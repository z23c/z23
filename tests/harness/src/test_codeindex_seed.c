/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove a code index seeded from a sibling checkout answers exactly what a cold build answers, and refuses every donor it cannot verify.
 *
 * A fresh worktree's first query used to rescan the whole tree. It now looks
 * for a checkout registered in the same git worktree set whose published index
 * already describes almost this tree, copies that generation, and rescans only
 * the files that differ (cognition/modules/codeindex/src/codeindex_seed.c).
 *
 * That shortcut is only allowed to exist if it is invisible in the answers, so
 * every case below asserts BOTH halves: what the seeding receipt says the
 * generation cost, and that the generation is fresh and answers the queries a
 * consumer actually asks. The refusal cases matter as much as the adoptions —
 * a donor that cannot be reconciled, or a checkout a resident mind owns, must
 * take the deterministic path instead of a cheap wrong one.
 *
 * The fixtures build git's worktree registry by hand — a `.git` file naming an
 * admin directory, and that directory's `gitdir`/`commondir` records — because
 * that registry, and nothing else, is what donor discovery reads.
 */

#include "test/test_core.h"

#include "codeindex/codeindex.h"

#include "platform/directory_compat.h"
#include "platform/temp_directory.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CIS_CHECK(name, expression)                                    \
    do {                                                               \
        bool cis_ok_ = (expression);                                   \
        printf("codeindex_seed: %s %s\n",                              \
               cis_ok_ ? "OK  " : "FAIL", (name));                     \
        if (!cis_ok_) failures++;                                      \
    } while (0)

/* Two directories so a changed subtree is a real subtree. Every unit defines a
 * revision-stamped leaf, so a stale row is visible as a wrong symbol name. */
static const char *const cis_units[] = {
    "lib/net/src/alpha.c",
    "lib/net/src/beta.c",
    "lib/net/src/gamma.c",
    "lib/wallet/src/delta.c",
    "lib/wallet/src/epsilon.c",
};
#define CIS_UNIT_COUNT (sizeof(cis_units) / sizeof(cis_units[0]))

/* A deliberately different file set: same shape, no path in common with
 * cis_units. This is what "a donor from another repository" looks like to an
 * index that compares sealed inventories. */
static const char *const cis_foreign_units[] = {
    "lib/net/src/zulu.c",
    "lib/net/src/yankee.c",
    "lib/wallet/src/xray.c",
};
#define CIS_FOREIGN_COUNT \
    (sizeof(cis_foreign_units) / sizeof(cis_foreign_units[0]))

/* platform_directory_ensure makes ONE level; a fixture path is several. */
static bool cis_ensure_tree(char *path)
{
    for (char *at = path + 1; *at; at++) {
        if (*at != '/') continue;
        *at = '\0';
        bool made = platform_directory_ensure(path, 0700);
        *at = '/';
        if (!made) return false;
    }
    return platform_directory_ensure(path, 0700);
}

static bool cis_write_file(const char *root, const char *relpath,
                           const char *body)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, relpath);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    for (char *at = path + 1; *at; at++) {
        if (*at != '/') continue;
        *at = '\0';
        bool made = platform_directory_ensure(path, 0700);
        *at = '/';
        if (!made) return false;
    }
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    size_t length = strlen(body);
    bool ok = fwrite(body, 1, length, file) == length;
    if (fclose(file) != 0) ok = false;
    return ok;
}

static void cis_stem(const char *relpath, char out[64])
{
    const char *slash = strrchr(relpath, '/');
    (void)snprintf(out, 64, "%s", slash ? slash + 1 : relpath);
    char *dot = strrchr(out, '.');
    if (dot) *dot = '\0';
}

/* `revision` is woven into the body, so bumping it is a real content change:
 * a new symbol name, a new call edge, and different bytes. */
static bool cis_write_unit(const char *root, const char *relpath, int revision)
{
    char body[1024], stem[64];
    cis_stem(relpath, stem);
    int n = snprintf(body, sizeof(body),
                     "/* Purpose: code index seeding fixture unit %s r%d. */\n"
                     "int %s_leaf_r%d(int x)\n"
                     "{\n"
                     "    return x + %d;\n"
                     "}\n"
                     "int %s_caller(int x)\n"
                     "{\n"
                     "    return %s_leaf_r%d(x) + %d;\n"
                     "}\n",
                     stem, revision, stem, revision, revision + 1, stem, stem,
                     revision, revision);
    if (n <= 0 || (size_t)n >= sizeof(body)) return false;
    return cis_write_file(root, relpath, body);
}

static bool cis_write_tree(const char *root, const char *const *units,
                           size_t count, int revision)
{
    for (size_t i = 0; i < count; i++)
        if (!cis_write_unit(root, units[i], revision)) return false;
    return true;
}

/* ── git's worktree registry, written by hand ─────────────────────────── */

static bool cis_write_text(const char *path, const char *text)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    size_t length = strlen(text);
    bool ok = fwrite(text, 1, length, file) == length;
    if (fclose(file) != 0) ok = false;
    return ok;
}

static bool cis_write_record(const char *dir, const char *leaf,
                             const char *text)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", dir, leaf);
    return n > 0 && (size_t)n < sizeof(path) && cis_write_text(path, text);
}

static bool cis_admin_dir(const char *main_root, const char *name,
                          char out[PATH_MAX])
{
    int n = snprintf(out, PATH_MAX, "%s/.git/worktrees/%s", main_root, name);
    return n > 0 && n < PATH_MAX && cis_ensure_tree(out);
}

/* Register `worktree` as a linked worktree of `main_root`, exactly the way git
 * does: an admin directory under the shared git directory holding `gitdir` and
 * `commondir`, and a `.git` FILE in the worktree naming that admin directory. */
static bool cis_register_worktree(const char *main_root, const char *name,
                                  const char *worktree)
{
    char admin[PATH_MAX], dir[PATH_MAX], text[PATH_MAX];
    if (!cis_admin_dir(main_root, name, admin)) return false;
    int n = snprintf(text, sizeof(text), "%s/.git\n", worktree);
    if (n <= 0 || (size_t)n >= sizeof(text)) return false;
    if (!cis_write_record(admin, "gitdir", text) ||
        !cis_write_record(admin, "commondir", "../..\n"))
        return false;
    n = snprintf(dir, sizeof(dir), "%s", worktree);
    if (n <= 0 || (size_t)n >= sizeof(dir) || !cis_ensure_tree(dir))
        return false;
    n = snprintf(text, sizeof(text), "gitdir: %s\n", admin);
    return n > 0 && (size_t)n < sizeof(text) &&
           cis_write_record(worktree, ".git", text);
}

/* ── observing one generation ─────────────────────────────────────────── */

static bool cis_derived_path(const char *root, const char *leaf,
                             char out[PATH_MAX])
{
    int n = snprintf(out, PATH_MAX, "%s/.codeindex/%s", root, leaf);
    return n > 0 && n < PATH_MAX;
}

/* Drop the published generation so the next open has nothing of its own and
 * must decide between seeding and a cold build. */
static bool cis_drop_store(const char *root)
{
    static const char *const leaves[] = { "index.kv", "index.kv.spare" };
    for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
        char path[PATH_MAX];
        struct stat st;
        if (!cis_derived_path(root, leaves[i], path)) return false;
        if (remove(path) != 0 && stat(path, &st) == 0) return false;
    }
    return true;
}

/* Leave a donor image that is present, the right name, and unusable. */
static bool cis_truncate_store(const char *root)
{
    char path[PATH_MAX];
    if (!cis_derived_path(root, "index.kv", path)) return false;
    FILE *file = fopen(path, "r+b");
    if (!file) return false;
    bool ok = fseek(file, 0, SEEK_SET) == 0 && fputs("not-a-store", file) >= 0;
    if (fclose(file) != 0) ok = false;
    return ok && truncate(path, 11) == 0;
}

struct cis_observation {
    bool      opened;
    bool      fresh;
    bool      seeded;
    char      donor_kind[32];
    long long files_refreshed;
    int       file_count;
};

/* Open the checkout the way a query leaf does, then record what the resulting
 * generation says about itself. */
static void cis_observe(const char *root, struct cis_observation *out)
{
    memset(out, 0, sizeof(*out));
    struct codeindex *index = codeindex_open(root);
    if (!index) return;
    out->opened = true;
    bool current = false;
    if (codeindex_source_view_is_current(index, &current)) out->fresh = current;
    out->seeded = codeindex_seed_receipt(index, out->donor_kind,
                                         &out->files_refreshed);
    out->file_count = codeindex_file_count(index);
    codeindex_close(index);
}

/* Does the unit at `relpath` report the leaf symbol of exactly `revision`?
 * This is the question a stale seeded row gets wrong. */
static bool cis_unit_is_revision(const char *root, const char *relpath,
                                 int revision)
{
    char stem[64], wanted[128];
    cis_stem(relpath, stem);
    if (snprintf(wanted, sizeof(wanted), "%s_leaf_r%d", stem, revision) <= 0)
        return false;
    struct codeindex *index = codeindex_open(root);
    if (!index) return false;
    struct ci_symbol symbols[16];
    int n = codeindex_symbols_in_file(index, relpath, symbols, 16);
    bool found = false;
    for (int i = 0; i < n; i++)
        if (strcmp(symbols[i].name, wanted) == 0) found = true;
    codeindex_close(index);
    return found;
}

/* ── one fixture repository: a main checkout plus one linked worktree ─── */

struct cis_repo {
    char main_root[PATH_MAX];
    char target_root[PATH_MAX];
};

static bool cis_repo_make(const char *workspace, const char *name,
                          const char *const *units, size_t count,
                          struct cis_repo *repo)
{
    char git_dir[PATH_MAX];
    int a = snprintf(repo->main_root, sizeof(repo->main_root), "%s/%s_main",
                     workspace, name);
    int b = snprintf(repo->target_root, sizeof(repo->target_root),
                     "%s/%s_target", workspace, name);
    if (a <= 0 || (size_t)a >= sizeof(repo->main_root) || b <= 0 ||
        (size_t)b >= sizeof(repo->target_root))
        return false;
    int c = snprintf(git_dir, sizeof(git_dir), "%s/.git", repo->main_root);
    if (c <= 0 || (size_t)c >= sizeof(git_dir)) return false;
    return cis_ensure_tree(git_dir) &&
           cis_write_tree(repo->main_root, units, count, 1) &&
           cis_register_worktree(repo->main_root, name, repo->target_root);
}

/* ── the cases ────────────────────────────────────────────────────────── */

static int cis_identical_and_near(const struct cis_repo *repo)
{
    int failures = 0;
    struct cis_observation donor, seeded;

    cis_observe(repo->main_root, &donor);
    CIS_CHECK("the donor checkout builds its own index cold",
              donor.opened && donor.fresh && !donor.seeded &&
              donor.file_count == (int)CIS_UNIT_COUNT);

    /* 1. An identical tree: adopted whole, nothing rescanned. */
    (void)cis_write_tree(repo->target_root, cis_units, CIS_UNIT_COUNT, 1);
    cis_observe(repo->target_root, &seeded);
    CIS_CHECK("an identical donor seeds the fresh worktree",
              seeded.opened && seeded.fresh && seeded.seeded &&
              strcmp(seeded.donor_kind, "the main checkout") == 0);
    CIS_CHECK("an identical donor needs no file rescanned",
              seeded.files_refreshed == 0);
    CIS_CHECK("a seeded generation holds the same inventory as its donor",
              seeded.file_count == donor.file_count);
    CIS_CHECK("a seeded generation answers for an unchanged file",
              cis_unit_is_revision(repo->target_root, cis_units[0], 1));

    /* 2. Two files differ: adopted, and exactly those two rescanned. */
    bool edited = cis_drop_store(repo->target_root) &&
                  cis_write_unit(repo->target_root, cis_units[0], 7) &&
                  cis_write_unit(repo->target_root, cis_units[3], 7);
    cis_observe(repo->target_root, &seeded);
    CIS_CHECK("a donor two files away still seeds the worktree",
              edited && seeded.opened && seeded.fresh && seeded.seeded);
    CIS_CHECK("exactly the two differing files are rescanned",
              seeded.files_refreshed == 2);
    CIS_CHECK("a changed file answers with its NEW definition",
              cis_unit_is_revision(repo->target_root, cis_units[0], 7) &&
              cis_unit_is_revision(repo->target_root, cis_units[3], 7));
    CIS_CHECK("an unchanged file keeps the donor's definition",
              cis_unit_is_revision(repo->target_root, cis_units[1], 1));
    return failures;
}

static int cis_corrupt_donor(const struct cis_repo *repo)
{
    int failures = 0;
    struct cis_observation built;
    bool broken = cis_truncate_store(repo->main_root) &&
                  cis_drop_store(repo->target_root);
    cis_observe(repo->target_root, &built);
    CIS_CHECK("a truncated donor image is refused, not adopted",
              broken && built.opened && !built.seeded);
    CIS_CHECK("refusing a donor still yields a fresh built generation",
              built.fresh && built.file_count == (int)CIS_UNIT_COUNT);
    CIS_CHECK("the built generation answers with the current definitions",
              cis_unit_is_revision(repo->target_root, cis_units[0], 7) &&
              cis_unit_is_revision(repo->target_root, cis_units[1], 1));
    return failures;
}

static int cis_foreign_donor(const struct cis_repo *foreign)
{
    int failures = 0;
    struct cis_observation donor, built;
    cis_observe(foreign->main_root, &donor);
    CIS_CHECK("the foreign checkout has a published index to offer",
              donor.opened && donor.fresh &&
              donor.file_count == (int)CIS_FOREIGN_COUNT);

    (void)cis_write_tree(foreign->target_root, cis_units, CIS_UNIT_COUNT, 1);
    cis_observe(foreign->target_root, &built);
    CIS_CHECK("a donor holding a different file set is ignored",
              built.opened && !built.seeded);
    CIS_CHECK("ignoring a foreign donor still yields this tree's own answer",
              built.fresh && built.file_count == (int)CIS_UNIT_COUNT);
    return failures;
}

/* Seeding is a rebuild, and a rebuild belongs to the resident that owns the
 * checkout. The refusal contract at codeindex.c must not have moved. */
static int cis_owner_refusal(const struct cis_repo *repo)
{
    int failures = 0;
    struct codeindex_stale_refusal refusal;
    memset(&refusal, 0, sizeof(refusal));
    long long now = 4000000000LL;
    bool claimed = codeindex_owner_claim(repo->target_root, 424242, now) &&
                   cis_drop_store(repo->target_root);
    struct codeindex *refused = codeindex_open(repo->target_root);
    CIS_CHECK("a checkout a resident owns is refused, never seeded",
              claimed && refused == NULL);
    CIS_CHECK("the refusal is reported as an owned index_stale",
              codeindex_last_stale_refusal(&refusal) && refusal.recorded &&
              refusal.owner_present && refusal.owner_pid == 424242);
    if (refused) codeindex_close(refused);
    CIS_CHECK("releasing the claim restores the ordinary open",
              codeindex_owner_release(repo->target_root, 424242));
    return failures;
}

int test_codeindex_seed(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    struct cis_repo repo, foreign;
    bool ready = platform_temp_directory_create("z23-codeindex-seed-",
                                                temporary, sizeof(temporary));
    ready = ready && platform_directory_canonical_real(temporary, workspace,
                                                       sizeof(workspace));
    ready = ready &&
            cis_repo_make(workspace, "near", cis_units, CIS_UNIT_COUNT,
                          &repo) &&
            cis_repo_make(workspace, "other", cis_foreign_units,
                          CIS_FOREIGN_COUNT, &foreign);
    CIS_CHECK("two fixture repositories are registered", ready);
    if (!ready) return failures;

    failures += cis_identical_and_near(&repo);
    failures += cis_corrupt_donor(&repo);
    failures += cis_foreign_donor(&foreign);
    failures += cis_owner_refusal(&repo);
    return failures;
}
