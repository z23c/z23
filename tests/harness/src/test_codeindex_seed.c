/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove a code index seeded from a sibling checkout answers exactly what a cold build answers, and refuses every donor it cannot verify.
 *
 * A fresh worktree seeds its index from a checkout registered in the same git
 * worktree set: it copies that generation and rescans only the differing
 * files (cognition/modules/codeindex/src/codeindex_seed.c).
 *
 * Every case asserts both what the seeding receipt says the generation cost
 * and that the generation is fresh and answers queries. A donor that cannot
 * be reconciled, or a checkout a resident mind owns, must take the
 * deterministic path.
 *
 * Fixtures build git's worktree registry by hand (a `.git` file naming an
 * admin directory, plus its `gitdir`/`commondir` records), which is all donor
 * discovery reads.
 */

#include "test/test_core.h"

#include "codeindex/codeindex.h"
#include "codeindex/codeindex_build.h"
#include "codeindex/codeindex_pages.h"

#include "platform/directory_compat.h"
#include "platform/temp_directory.h"

#include <sqlite3.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>

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

/* A donor's page hints name artifacts in the donor's object store; a seeded worktree must not adopt them. */
static int cis_donor_pages(const struct cis_repo *repo)
{
    static const char body[] = "{\"dir\":\"lib/net\",\"tree\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\","
        "\"topic\":\"net\",\"summary\":\"donor hint\",\"lessons\":[],\"applies_to\":[],"
        "\"updated\":\"2026-11-04T00:00:00Z\"}";
    int failures = 0;
    struct ci_page in = {0}, out;
    snprintf(in.directory, sizeof(in.directory), "lib/net");
    snprintf(in.tree_oid, sizeof(in.tree_oid), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    snprintf(in.source_commit, sizeof(in.source_commit), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    snprintf(in.body, sizeof(in.body), "%s", body);
    uint8_t artifact[32];
    struct codeindex *donor = codeindex_open_retrieval_view(repo->main_root);
    bool imported = donor && codeindex_pages_import_hints(donor, body, strlen(body), &in, 1, artifact);
    codeindex_close(donor);
    bool ready = imported && cis_drop_store(repo->target_root) &&
                 cis_write_tree(repo->target_root, cis_units, CIS_UNIT_COUNT, 1);
    struct cis_observation seeded;
    if (ready) cis_observe(repo->target_root, &seeded);
    struct codeindex *ix = ready ? codeindex_open_retrieval_view(repo->target_root) : NULL;
    bool untrusted = true, truncated = true;
    CIS_CHECK("a seeded worktree does not adopt its donor's page hints",
              ready && seeded.seeded && ix &&
              codeindex_pages_list_bounded(ix, "lib/net", &out, 1, &untrusted, &truncated) == 0 &&
              !untrusted && !truncated);
    codeindex_close(ix);
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

static int cis_different_depfiles(const struct cis_repo *repo)
{
    int failures = 0;
    struct cis_observation donor, built;
    bool prepared =
        cis_write_file(repo->main_root, "build/obj/alpha.d",
                       "build/obj/alpha.o: lib/net/src/alpha.c "
                       "lib/net/src/beta.c\n") &&
        cis_write_file(repo->target_root, "build/obj/alpha.d",
                       "build/obj/alpha.o: lib/net/src/alpha.c "
                       "lib/net/src/gamma.c\n") &&
        cis_drop_store(repo->target_root);
    cis_observe(repo->main_root, &donor);
    cis_observe(repo->target_root, &built);
    CIS_CHECK("different depfile edges are reconciled onto a sibling seed",
              prepared && donor.opened && built.opened && built.seeded);
    struct codeindex *index = codeindex_open(repo->target_root);
    char includes[4][256] = {{0}};
    int count = index ? codeindex_includes_of_file(
        index, "lib/net/src/alpha.c", includes, 4) : -1;
    CIS_CHECK("seeded graph uses the target depfile",
              count == 1 &&
              strcmp(includes[0], "lib/net/src/gamma.c") == 0);
    if (index) codeindex_close(index);
    return failures;
}

static int cis_absolute_depfile_paths(const struct cis_repo *repo)
{
    int failures = 0;
    char depfile[PATH_MAX * 2 + 128];
    int n = snprintf(depfile, sizeof(depfile),
                     "build/obj/alpha.o: %s/lib/net/src/alpha.c "
                     "%s/lib/net/src/beta.c\n",
                     repo->main_root, repo->main_root);
    bool prepared = n > 0 && (size_t)n < sizeof(depfile) &&
        cis_write_file(repo->main_root, "build/obj/alpha.d", depfile) &&
        cis_write_file(repo->target_root, "build/obj/alpha.d", depfile) &&
        cis_drop_store(repo->target_root);
    struct cis_observation donor, built;
    cis_observe(repo->main_root, &donor);
    struct codeindex *donor_index = codeindex_open(repo->main_root);
    char donor_includes[4][256] = {{0}};
    int donor_count = donor_index ? codeindex_includes_of_file(
        donor_index, "lib/net/src/alpha.c", donor_includes, 4) : -1;
    CIS_CHECK("donor absolute path yields one include edge",
              donor_count == 1 &&
              strcmp(donor_includes[0], "lib/net/src/beta.c") == 0);
    if (donor_index) codeindex_close(donor_index);
    cis_observe(repo->target_root, &built);
    CIS_CHECK("root-dependent donor paths are reconciled onto a seed",
              prepared && donor.opened && built.opened && built.seeded);
    struct codeindex *index = codeindex_open(repo->target_root);
    char includes[4][256] = {{0}};
    int count = index ? codeindex_includes_of_file(
        index, "lib/net/src/alpha.c", includes, 4) : -1;
    CIS_CHECK("target graph excludes donor absolute paths", count == 0);
    if (index) codeindex_close(index);
    return failures;
}

static int cis_altered_donor_includes(const struct cis_repo *repo)
{
    int failures = 0;
    static const char depfile[] =
        "build/obj/alpha.o: lib/net/src/alpha.c lib/net/src/beta.c\n";
    bool prepared =
        cis_write_file(repo->main_root, "build/obj/alpha.d", depfile) &&
        cis_write_file(repo->target_root, "build/obj/alpha.d", depfile) &&
        cis_drop_store(repo->target_root);
    struct cis_observation donor, built;
    cis_observe(repo->main_root, &donor);
    char image[PATH_MAX];
    sqlite3 *db = NULL;
    bool altered = cis_derived_path(repo->main_root, "index.kv", image) &&
                   sqlite3_open_v2(image, &db, SQLITE_OPEN_READWRITE,
                                   NULL) == SQLITE_OK;
    if (altered)
        altered = sqlite3_exec(db,
            "INSERT INTO includes(file_id,dep_path)"
            " SELECT id,'lib/wallet/src/epsilon.c' FROM files"
            " WHERE path='lib/net/src/alpha.c'", NULL, NULL, NULL) ==
            SQLITE_OK; // raw-sql-ok:codeindex-derived
    if (db) sqlite3_close(db);
    cis_observe(repo->target_root, &built);
    CIS_CHECK("altered donor include row is reconciled onto a seed",
              prepared && donor.opened && altered && built.opened &&
              built.seeded);
    struct codeindex *index = codeindex_open(repo->target_root);
    char includes[4][256] = {{0}};
    int count = index ? codeindex_includes_of_file(
        index, "lib/net/src/alpha.c", includes, 4) : -1;
    CIS_CHECK("target graph excludes altered donor row",
              count == 1 &&
              strcmp(includes[0], "lib/net/src/beta.c") == 0);
    if (index) codeindex_close(index);
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

/* A donor built in another checkout holds depfile bytes that differ from this
 * checkout's even when every include edge is the same. That must not stop
 * the seed, and the generation must read each depfile once, not once per step. */
static int cis_equal_edges_different_bytes(const struct cis_repo *repo)
{
    int failures = 0;
    static const char donor_depfile[] =
        "build/obj/alpha.o: lib/net/src/alpha.c lib/net/src/beta.c\n";
    static const char target_depfile[] =
        "build/other/alpha.o: lib/net/src/alpha.c \\\n"
        " lib/net/src/beta.c\n";
    bool prepared =
        cis_write_file(repo->main_root, "build/obj/alpha.d", donor_depfile) &&
        cis_write_file(repo->target_root, "build/obj/alpha.d", target_depfile) &&
        cis_drop_store(repo->target_root);
    struct cis_observation donor, seeded;
    cis_observe(repo->main_root, &donor);
    uint64_t before = codeindex_test_exact_bytes_read();
    cis_observe(repo->target_root, &seeded);
    const uint64_t scans_bytes = codeindex_test_exact_bytes_read() - before;
    CIS_CHECK("equal edges in different depfile bytes still seed",
              prepared && donor.opened && seeded.opened && seeded.fresh &&
              seeded.seeded && seeded.files_refreshed == 2);
    CIS_CHECK("seeding scans the depfiles once",
              scans_bytes == sizeof(target_depfile) - 1);
    struct codeindex *index = codeindex_open(repo->target_root);
    char includes[4][256] = {{0}};
    int count = index ? codeindex_includes_of_file(
        index, "lib/net/src/alpha.c", includes, 4) : -1;
    CIS_CHECK("the seeded graph equals the target depfile graph",
              count == 1 && strcmp(includes[0], "lib/net/src/beta.c") == 0);
    if (index) codeindex_close(index);
    return failures;
}

#if !defined(_WIN32)
enum { CIS_RANK_ENTRIES = 132 };
struct cis_rank_paths { char roots[CIS_RANK_ENTRIES][PATH_MAX]; int count; };

static bool cis_rank_register(const char *workspace, const struct cis_repo *repo,
                              const char *tag)
{
    for (int i = 0; i < CIS_RANK_ENTRIES; i++) {
        char name[32], root[PATH_MAX];
        int a = snprintf(name, sizeof(name), "donor-%03d", i);
        int b = snprintf(root, sizeof(root), "%s/%s-donor-%03d", workspace, tag, i);
        if (a <= 0 || (size_t)a >= sizeof(name) || b <= 0 || (size_t)b >= sizeof(root) ||
            !cis_register_worktree(repo->main_root, name, root)) return false;
    }
    return true;
}

static bool cis_rank_record(const char *registry, const char *name, char out[PATH_MAX])
{
    char record[PATH_MAX], line[PATH_MAX];
    int n = snprintf(record, sizeof(record), "%s/%s/gitdir", registry, name);
    if (n <= 0 || (size_t)n >= sizeof(record)) return false;
    FILE *f = fopen(record, "r");
    if (!f) return false;
    bool read = fgets(line, sizeof(line), f) != NULL;
    if (fclose(f) != 0) read = false;
    size_t len = read ? strlen(line) : 0;
    if (len < 7 || strcmp(line + len - 6, "/.git\n")) return false;
    line[len - 6] = 0;
    memcpy(out, line, len - 5);
    return true;
}

/* Observe the fixture's actual registry order: POSIX does not order readdir. */
static bool cis_rank_order(const struct cis_repo *repo, struct cis_rank_paths *paths)
{
    char registry[PATH_MAX];
    int n = snprintf(registry, sizeof(registry), "%s/.git/worktrees", repo->main_root);
    if (n <= 0 || (size_t)n >= sizeof(registry)) return false;
    DIR *dir = opendir(registry);
    if (!dir) return false;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "donor-", 6)) continue;
        if (paths->count >= CIS_RANK_ENTRIES ||
            !cis_rank_record(registry, entry->d_name, paths->roots[paths->count])) {
            closedir(dir); return false;
        }
        paths->count++;
    }
    bool ok = closedir(dir) == 0;
    return ok && paths->count == CIS_RANK_ENTRIES;
}

static bool cis_rank_copy_stream(FILE *in, FILE *out)
{
    char buf[8192];
    for (;;) {
        size_t got = fread(buf, 1, sizeof(buf), in);
        if (got && fwrite(buf, 1, got, out) != got) return false;
        if (got < sizeof(buf)) return !ferror(in);
    }
}

static bool cis_rank_private(const char *path, bool directory)
{
    struct stat st;
    if (lstat(path, &st) != 0 || st.st_uid != geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH))) return false;
    if (directory) return S_ISDIR(st.st_mode);
    return S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600 &&
        st.st_nlink == 1 && st.st_size > 0;
}

static bool cis_rank_copy_image(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb"), *out = fopen(to, "wb");
    bool ok = in && out && fchmod(fileno(out), 0600) == 0 &&
        cis_rank_copy_stream(in, out);
    if (in && fclose(in) != 0) ok = false;
    if (out && fclose(out) != 0) ok = false;
    return ok;
}

static bool cis_rank_copy(const char *from_root, const char *to_root, time_t when)
{
    char from[PATH_MAX], to[PATH_MAX], dir[PATH_MAX];
    if (!cis_derived_path(from_root, "index.kv", from) ||
        !cis_derived_path(to_root, "index.kv", to)) return false;
    int n = snprintf(dir, sizeof(dir), "%s/.codeindex", to_root);
    if (n <= 0 || (size_t)n >= sizeof(dir) || !cis_ensure_tree(dir)) return false;
    struct timespec times[2] = {{when, 0}, {when, 0}};
    return cis_rank_copy_image(from, to) && utimensat(AT_FDCWD, to, times, 0) == 0 &&
        cis_rank_private(dir, true) && cis_rank_private(to, false);
}

static bool cis_rank_old_donors(const struct cis_repo *foreign,
                                const struct cis_rank_paths *paths)
{
    for (int i = 0; i < 16; i++)
        if (!cis_rank_copy(foreign->main_root, paths->roots[i], 1000000000)) return false;
    return true;
}

static bool cis_rank_prepare(const char *workspace, const char *name, bool past_registry,
                             struct cis_repo *repo, struct cis_rank_paths *paths)
{
    struct cis_repo foreign;
    struct cis_observation near = {0}, other = {0};
    bool ready = cis_repo_make(workspace, name, cis_units, CIS_UNIT_COUNT, repo) &&
        cis_repo_make(workspace, past_registry ? "rank-foreign-a" : "rank-foreign-b",
                      cis_foreign_units, CIS_FOREIGN_COUNT, &foreign);
    if (ready) { cis_observe(repo->main_root, &near); cis_observe(foreign.main_root, &other); }
    ready = ready && near.opened && other.opened &&
        cis_write_tree(repo->target_root, cis_units, CIS_UNIT_COUNT, 1) &&
        cis_write_unit(repo->target_root, cis_units[0], 7) &&
        cis_rank_register(workspace, repo, name) && cis_rank_order(repo, paths);
    int selected = past_registry ? 129 : 17;
    return ready && cis_rank_copy(repo->main_root, paths->roots[selected], 2000000000) &&
        (past_registry || cis_rank_old_donors(&foreign, paths)) && cis_drop_store(repo->main_root);
}

static int cis_rank_case(const char *workspace, const char *name, bool past_registry)
{
    int failures = 0;
    struct cis_repo repo;
    struct cis_observation result = {0};
    struct cis_rank_paths *paths = calloc(1, sizeof(*paths));
    bool ready = paths && cis_rank_prepare(workspace, name, past_registry, &repo, paths);
    if (ready) cis_observe(repo.target_root, &result);
    printf("codeindex_seed: rank case=%s ready=%d seeded=%d refreshed=%lld\n",
           name, ready, result.seeded, result.files_refreshed);
    CIS_CHECK("late recent donor seeds a fresh generation", ready && result.opened &&
              result.fresh && result.seeded && !strcmp(result.donor_kind, "a sibling worktree"));
    CIS_CHECK("late donor refreshes exactly the changed unit", ready && result.files_refreshed == 1 &&
              result.file_count == (int)CIS_UNIT_COUNT &&
              cis_unit_is_revision(repo.target_root, cis_units[0], 7) &&
              cis_unit_is_revision(repo.target_root, cis_units[1], 1));
    free(paths);
    return failures;
}
#endif

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
    failures += cis_different_depfiles(&repo);
    failures += cis_absolute_depfile_paths(&repo);
    failures += cis_altered_donor_includes(&repo);
    failures += cis_equal_edges_different_bytes(&repo);
    failures += cis_corrupt_donor(&repo);
    failures += cis_foreign_donor(&foreign);
    failures += cis_owner_refusal(&repo);
    failures += cis_donor_pages(&repo); /* last: it imports a page hint into the donor */
#if !defined(_WIN32)
    failures += cis_rank_case(workspace, "rank-registry", true);
    failures += cis_rank_case(workspace, "rank-comparisons", false);
#endif
    return failures;
}
