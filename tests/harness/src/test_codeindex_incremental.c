/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Prove an incrementally patched code index answers exactly what a cold rebuild answers.
 *
 * The index no longer rescans the whole checkout when one file moves: the
 * source Merkle snapshot names the changed leaves and only those files are
 * re-read, and the staging image is a clone of the previous generation with
 * those rows replaced. Both shortcuts are only worth having if the result is
 * indistinguishable from the from-scratch answer, so every case below runs the
 * same edit against two fixtures — one kept incrementally, one rebuilt cold by
 * deleting its derived directory first — and requires them to agree on the
 * sealed generation roots AND on the queries a consumer actually asks.
 *
 * The cases are the ones that behave differently inside the builder: one file,
 * three files, a whole directory, a file added to the inventory (which is NOT
 * incremental and must fall back), and a corrupted Merkle snapshot (which must
 * be discarded rather than trusted).
 */

#include "test/test_core.h"

#include "codeindex/codeindex.h"

#include "platform/directory_compat.h"
#include "platform/temp_directory.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define CIN_CHECK(name, expression)                                    \
    do {                                                               \
        bool cin_ok_ = (expression);                                   \
        printf("codeindex_incremental: %s %s\n",                       \
               cin_ok_ ? "OK  " : "FAIL", (name));                     \
        if (!cin_ok_) failures++;                                      \
    } while (0)

/* Two directories so "change a whole directory" is a real subtree and not the
 * whole fixture. Every unit defines one leaf and one caller of it, so the call
 * graph has edges to get wrong. */
static const char *const cin_units[] = {
    "lib/net/src/alpha.c",
    "lib/net/src/beta.c",
    "lib/net/src/gamma.c",
    "lib/wallet/src/delta.c",
    "lib/wallet/src/epsilon.c",
};
#define CIN_UNIT_COUNT (sizeof(cin_units) / sizeof(cin_units[0]))

static bool cin_write_file(const char *root, const char *relpath,
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

/* `revision` is woven into the body so a bumped revision is a real content
 * change: a new symbol name, a new call edge, and different text. */
static bool cin_write_unit(const char *root, size_t index, int revision)
{
    char body[1024];
    char stem[64];
    const char *slash = strrchr(cin_units[index], '/');
    (void)snprintf(stem, sizeof(stem), "%s", slash ? slash + 1 : cin_units[index]);
    char *dot = strrchr(stem, '.');
    if (dot) *dot = '\0';
    int n = snprintf(body, sizeof(body),
                     "/* Purpose: incremental code index fixture unit %s r%d. */\n"
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
    return cin_write_file(root, cin_units[index], body);
}

static bool cin_seed(const char *root)
{
    for (size_t i = 0; i < CIN_UNIT_COUNT; i++)
        if (!cin_write_unit(root, i, 1)) return false;
    return true;
}

static bool cin_derived_path(const char *root, const char *leaf,
                             char out[PATH_MAX])
{
    int n = snprintf(out, PATH_MAX, "%s/.codeindex/%s", root, leaf);
    return n > 0 && n < PATH_MAX;
}

static bool cin_exists(const char *root, const char *leaf)
{
    char path[PATH_MAX];
    struct stat st;
    return cin_derived_path(root, leaf, path) && stat(path, &st) == 0;
}

static bool cin_remove(const char *root, const char *leaf)
{
    char path[PATH_MAX];
    if (!cin_derived_path(root, leaf, path)) return false;
    return remove(path) == 0 || !cin_exists(root, leaf);
}

/* Drop the whole derived directory so the next open has nothing to reuse and
 * must take the deterministic cold path. This is the reference answer. */
static bool cin_force_cold(const char *root)
{
    static const char *const leaves[] = {
        "index.kv", "index.kv.spare", "source_tree.merkle", "rebuild.lock",
    };
    for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++)
        if (!cin_remove(root, leaves[i])) return false;
    return true;
}

/* Overwrite the snapshot with bytes that are the right length and the wrong
 * content. A snapshot that is merely absent is an easy case; one that is
 * present, plausible and WRONG is the case that must not be trusted. */
static bool cin_corrupt_snapshot(const char *root)
{
    char path[PATH_MAX];
    if (!cin_derived_path(root, "source_tree.merkle", path)) return false;
    FILE *file = fopen(path, "r+b");
    if (!file) return false;
    bool ok = fseek(file, 0, SEEK_SET) == 0;
    for (int i = 0; ok && i < 4096; i++)
        ok = fputc(0x5a, file) != EOF;
    if (fclose(file) != 0) ok = false;
    return ok;
}

/* Everything a consumer reads out of one generation, reduced to a string so
 * two generations can be compared as a whole instead of field by field. */
struct cin_answer {
    uint8_t source_root[32];
    uint8_t projection_root[32];
    int     file_count;
    char    text[4096];
};

static bool cin_append(struct cin_answer *answer, size_t *pos,
                       const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(answer->text + *pos, sizeof(answer->text) - *pos, fmt, ap);
    va_end(ap);
    if (n <= 0 || (size_t)n >= sizeof(answer->text) - *pos) return false;
    *pos += (size_t)n;
    return true;
}

static bool cin_capture(const char *root, struct cin_answer *answer)
{
    memset(answer, 0, sizeof(*answer));
    struct codeindex *index = codeindex_open(root);
    if (!index) return false;
    bool ok = codeindex_source_root_sha3(index, answer->source_root) &&
              codeindex_retrieval_projection_root_sha3(index,
                                                       answer->projection_root);
    answer->file_count = ok ? codeindex_file_count(index) : -1;
    size_t pos = 0;
    for (size_t i = 0; ok && i < CIN_UNIT_COUNT; i++) {
        struct ci_file file;
        bool found = false;
        memset(&file, 0, sizeof(file));
        ok = codeindex_file(index, cin_units[i], &file, &found) && found &&
             cin_append(answer, &pos, "file %s|%s;", file.path, file.group);
        struct ci_symbol symbols[16];
        int n = ok ? codeindex_symbols_in_file(index, cin_units[i], symbols, 16)
                   : -1;
        ok = ok && n >= 0 && cin_append(answer, &pos, "syms %d:", n);
        for (int s = 0; ok && s < n; s++)
            ok = cin_append(answer, &pos, "%s@%d,", symbols[s].name,
                            symbols[s].def_line);
        struct ci_ref refs[16];
        char caller[128];
        const char *slash = strrchr(cin_units[i], '/');
        (void)snprintf(caller, sizeof(caller), "%s", slash ? slash + 1 : "");
        char *dot = strrchr(caller, '.');
        if (dot) *dot = '\0';
        (void)strncat(caller, "_caller", sizeof(caller) - strlen(caller) - 1);
        int edges = ok ? codeindex_callees(index, caller, refs, 16) : -1;
        ok = ok && edges >= 0 && cin_append(answer, &pos, "|calls %d:", edges);
        for (int e = 0; ok && e < edges; e++)
            ok = cin_append(answer, &pos, "%s,", refs[e].callee);
        ok = ok && cin_append(answer, &pos, "\n");
    }
    codeindex_close(index);
    return ok;
}

/* Apply one edit to both fixtures, keep `live` incremental and rebuild
 * `reference` from nothing, then require the two to be indistinguishable. */
static bool cin_agrees(const char *live, const char *reference,
                       int *out_file_count)
{
    struct cin_answer incremental, cold;
    if (!cin_force_cold(reference)) return false;
    if (!cin_capture(live, &incremental) || !cin_capture(reference, &cold))
        return false;
    if (out_file_count) *out_file_count = incremental.file_count;
    return memcmp(incremental.source_root, cold.source_root, 32) == 0 &&
           memcmp(incremental.projection_root, cold.projection_root, 32) == 0 &&
           incremental.file_count == cold.file_count &&
           incremental.file_count > 0 &&
           strcmp(incremental.text, cold.text) == 0;
}

static bool cin_edit_both(const char *live, const char *reference,
                          size_t index, int revision)
{
    return cin_write_unit(live, index, revision) &&
           cin_write_unit(reference, index, revision);
}

int test_codeindex_incremental(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    char live[PATH_MAX], reference[PATH_MAX];
    bool ready = platform_temp_directory_create(
        "z23-codeindex-incremental-", temporary, sizeof(temporary));
    ready = ready && platform_directory_canonical_real(
        temporary, workspace, sizeof(workspace));
    int live_n = ready ? snprintf(live, sizeof(live), "%s/live", workspace) : -1;
    int reference_n = ready ? snprintf(reference, sizeof(reference),
                                       "%s/reference", workspace) : -1;
    ready = ready && live_n > 0 && (size_t)live_n < sizeof(live) &&
            reference_n > 0 && (size_t)reference_n < sizeof(reference) &&
            cin_seed(live) && cin_seed(reference);
    CIN_CHECK("two identical fixtures are ready", ready);
    if (!ready) return failures;

    int baseline_files = 0;
    CIN_CHECK("cold builds of identical trees are identical",
              cin_agrees(live, reference, &baseline_files));

    /* One file. The narrowest incremental case and the one the dev loop
     * actually runs; the spare it leaves behind is what makes the NEXT
     * publication cheap, so its presence is the observable that the
     * incremental branch — not the full rebuild — produced this generation. */
    CIN_CHECK("one changed file matches a cold rebuild",
              cin_edit_both(live, reference, 0, 2) &&
              cin_agrees(live, reference, NULL));
    CIN_CHECK("a one-file update took the incremental branch",
              cin_exists(live, "index.kv.spare"));

    /* Three files at once, spanning both directories. */
    CIN_CHECK("three changed files match a cold rebuild",
              cin_edit_both(live, reference, 1, 3) &&
              cin_edit_both(live, reference, 2, 3) &&
              cin_edit_both(live, reference, 3, 3) &&
              cin_agrees(live, reference, NULL));

    /* A whole directory. Every unit under lib/net/src moves at once, which is
     * where a stale per-file row or a stale scan shard would show up. */
    CIN_CHECK("a whole changed directory matches a cold rebuild",
              cin_edit_both(live, reference, 0, 4) &&
              cin_edit_both(live, reference, 1, 4) &&
              cin_edit_both(live, reference, 2, 4) &&
              cin_agrees(live, reference, NULL));

    /* The reverse edit. Restoring a file's exact previous bytes is the case
     * that a cache keyed on "something moved" gets wrong most easily. */
    CIN_CHECK("reverting a file to its earlier bytes matches a cold rebuild",
              cin_edit_both(live, reference, 0, 2) &&
              cin_agrees(live, reference, NULL));

    /* A new file is an INVENTORY change, not a content change: the builder
     * must decline the incremental branch and rebuild, and the answer must
     * still be the cold one. */
    bool added = cin_write_file(
        live, "lib/net/src/zeta.c",
        "/* Purpose: incremental fixture inventory growth. */\n"
        "int zeta_leaf(int x) { return x + 9; }\n") &&
        cin_write_file(
        reference, "lib/net/src/zeta.c",
        "/* Purpose: incremental fixture inventory growth. */\n"
        "int zeta_leaf(int x) { return x + 9; }\n");
    int grown_files = 0;
    CIN_CHECK("a new file matches a cold rebuild",
              added && cin_agrees(live, reference, &grown_files));
    CIN_CHECK("a new file is admitted into the indexed inventory",
              grown_files == baseline_files + 1);

    /* A corrupted snapshot is never trusted. Discarding it costs one cold
     * pass, which also means the incremental branch is declined and the spare
     * it would have left is removed. */
    bool corrupted = cin_corrupt_snapshot(live);
    CIN_CHECK("a corrupted Merkle snapshot still yields the cold answer",
              corrupted && cin_edit_both(live, reference, 4, 5) &&
              cin_agrees(live, reference, NULL));
    CIN_CHECK("a corrupted Merkle snapshot forces the full rebuild branch",
              corrupted && !cin_exists(live, "index.kv.spare"));

    /* And the recovery is complete: the very next edit is incremental again. */
    CIN_CHECK("indexing is incremental again after the discarded snapshot",
              cin_edit_both(live, reference, 4, 6) &&
              cin_agrees(live, reference, NULL) &&
              cin_exists(live, "index.kv.spare"));

    return failures;
}
