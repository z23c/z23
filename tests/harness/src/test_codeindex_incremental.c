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
#include <stdlib.h>
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

static bool cin_include_is(const char *root, const char *expected)
{
    struct codeindex *index = codeindex_open(root);
    if (!index) return false;
    char includes[2][256];
    int count = codeindex_includes_of_file(index, cin_units[0], includes, 2);
    bool ok = count == 1 && strcmp(includes[0], expected) == 0;
    codeindex_close(index);
    return ok;
}

static bool cin_depfile_seed(const char *live, const char *reference)
{
    static const char depfile[] =
        "build/fixture.o: lib/net/src/alpha.c lib/net/src/beta.c\n";
    return cin_write_file(live, "build/fixture.d", depfile) &&
           cin_write_file(reference, "build/fixture.d", depfile) &&
           cin_agrees(live, reference, NULL);
}

static bool cin_depfile_rewrite_same(const char *live, const char *reference)
{
    /* A compiler can rewrite a depfile without changing any prerequisite.
     * Its stat seal moves, but exact bytes keep the cloned include rows valid. */
    static const char depfile[] =
        "build/fixture.o: lib/net/src/alpha.c lib/net/src/beta.c\n";
    return cin_write_file(live, "build/fixture.d", depfile) &&
           cin_write_file(reference, "build/fixture.d", depfile) &&
           cin_edit_both(live, reference, 0, 7) &&
           cin_agrees(live, reference, NULL) &&
           cin_include_is(live, "lib/net/src/beta.c") &&
           cin_include_is(reference, "lib/net/src/beta.c") &&
           cin_exists(live, "index.kv.spare");
}

static bool cin_depfile_rewrite_changed(const char *live,
                                        const char *reference)
{
    static const char changed_depfile[] =
        "build/fixture.o: lib/net/src/alpha.c lib/net/src/gamma.c\n";
    return cin_write_file(live, "build/fixture.d", changed_depfile) &&
           cin_write_file(reference, "build/fixture.d", changed_depfile) &&
           cin_edit_both(live, reference, 0, 8) &&
           cin_agrees(live, reference, NULL) &&
           cin_include_is(live, "lib/net/src/gamma.c") &&
           !cin_exists(live, "index.kv.spare");
}

static bool cin_count_includes(const char *root, int *present, int *missing)
{
    struct codeindex *index = codeindex_open(root);
    char includes[8][256];
    int count;
    *present = 0;
    *missing = 0;
    if (!index) return false;
    count = codeindex_includes_of_file(index, cin_units[0], includes, 8);
    if (count < 0) {
        codeindex_close(index);
        return false;
    }
    int path_bytes = 0;
    for (int i = 0; i < count; i++) {
        path_bytes += (int)strlen(includes[i]);
        if (strcmp(includes[i], "lib/net/src/beta.c") == 0) (*present)++;
        if (strcmp(includes[i],
                   "lib/base/include/base/format_attribute.h") == 0)
            (*missing)++;
    }
    printf("missing_prereq_edges=%d present_prereq_edges=%d include_rows=%d include_path_bytes=%d\n",
           *missing, *present, count, path_bytes);
    codeindex_close(index);
    return true;
}

/* A depfile can name a header this checkout no longer contains: the header was
 * deleted or renamed after the compile. The source still depends on that path,
 * so the scan keeps the edge. Dropping it would let the deletion impact nothing
 * and narrow the plan past the unit that read the header. */
static bool cin_depfile_keeps_missing(const char *live, const char *reference)
{
    static const char depfile[] =
        "build/fixture.o: lib/net/src/alpha.c lib/net/src/beta.c "
        "lib/base/include/base/format_attribute.h\n";
    int live_present = -1, live_missing = -1;
    int ref_present = -1, ref_missing = -1;
    if (!cin_write_file(live, "build/fixture.d", depfile) ||
        !cin_write_file(reference, "build/fixture.d", depfile) ||
        !cin_force_cold(live) || !cin_force_cold(reference))
        return false;
    if (!cin_count_includes(live, &live_present, &live_missing) ||
        !cin_count_includes(reference, &ref_present, &ref_missing))
        return false;
    return live_missing == 1 && ref_missing == 1 &&
           live_present == 1 && ref_present == 1;
}

/* The unit that read `dep` is a forward include of the unit AND a reverse
 * include of `dep` — the second is what code.impact asks when `dep` changes.
 * Both must hold whether or not `dep` is still in the checkout. A vanished
 * prerequisite keeps its edge and refuses a complete answer: `want` is
 * COMPLETE only while every named prerequisite exists. */
static bool cin_impact_edge(const char *root, const char *dep,
                            enum codeindex_include_dim want)
{
    struct codeindex *index = codeindex_open(root);
    if (!index) return false;
    char rows[8][256];
    bool forward = false, reverse = false;
    int count = codeindex_includes_of_file(index, cin_units[0], rows, 8);
    for (int i = 0; i < count; i++)
        forward = forward || strcmp(rows[i], dep) == 0;
    enum codeindex_include_dim dim = CODEINDEX_INCLUDE_DIM_UNAVAILABLE;
    count = codeindex_reverse_includes(index, dep, rows, 8, &dim);
    for (int i = 0; i < count; i++)
        reverse = reverse || strcmp(rows[i], cin_units[0]) == 0;
    codeindex_close(index);
    printf("impact_edge dep=%s forward=%d reverse=%d dim=%s\n", dep, forward,
           reverse, codeindex_include_dim_label(dim));
    return forward && reverse && dim == want;
}

static bool cin_vanished_edge(const char *root, const char *dep)
{
    return cin_impact_edge(root, dep, CODEINDEX_INCLUDE_DIM_TRUNCATED);
}

/* A depfile naming `dep` for alpha.c, written to `depfile`. */
static bool cin_write_depfile(const char *root, const char *depfile,
                              const char *dep)
{
    char body[512];
    int n = snprintf(body, sizeof(body),
                     "build/fixture.o: lib/net/src/alpha.c %s\n", dep);
    return n > 0 && (size_t)n < sizeof(body) &&
           cin_write_file(root, depfile, body);
}

static bool cin_unlink(const char *root, const char *rel)
{
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/%s", root, rel);
    return n > 0 && (size_t)n < sizeof(path) && remove(path) == 0;
}

/* Header existed at compile time, then was deleted. The deletion must
 * still impact alpha.c, on the incremental open and on a cold rebuild. */
static bool cin_deleted_header(const char *root)
{
    static const char dep[] = "lib/net/include/net/deleted_wire.h";
    return cin_write_file(root, dep, "#define DELETED_WIRE 1\n") &&
           cin_write_depfile(root, "build/deleted.d", dep) &&
           cin_force_cold(root) &&
           cin_impact_edge(root, dep, CODEINDEX_INCLUDE_DIM_COMPLETE) &&
           cin_unlink(root, dep) && cin_vanished_edge(root, dep) &&
           cin_force_cold(root) && cin_vanished_edge(root, dep);
}

/* Header renamed after the compile: the depfile still names the old path, so
 * the rename impacts alpha.c through it until the next compile. */
static bool cin_renamed_header(const char *root)
{
    static const char old_dep[] = "lib/net/include/net/old_frame.h";
    static const char new_dep[] = "lib/net/include/net/new_frame.h";
    char from[PATH_MAX], to[PATH_MAX];
    int fn = snprintf(from, sizeof(from), "%s/%s", root, old_dep);
    int tn = snprintf(to, sizeof(to), "%s/%s", root, new_dep);
    return fn > 0 && (size_t)fn < sizeof(from) && tn > 0 &&
           (size_t)tn < sizeof(to) &&
           cin_write_file(root, old_dep, "#define FRAME 1\n") &&
           cin_write_depfile(root, "build/renamed.d", old_dep) &&
           rename(from, to) == 0 && cin_force_cold(root) &&
           cin_vanished_edge(root, old_dep);
}

/* A generated header the depfile names but this checkout has not generated. */
static bool cin_missing_generated(const char *root)
{
    static const char dep[] =
        "contexts/wallet/views/include/views/wallet_templates_gen.h";
    return cin_write_depfile(root, "build/generated.d", dep) &&
           cin_force_cold(root) && cin_vanished_edge(root, dep);
}

/* The live epoch of an epoch-managed object root names a vanished path. The
 * pointer selects the live graph; it never licenses dropping its edges. */
static bool cin_stale_epoch(const char *root)
{
    static const char epoch[] =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    static const char dep[] = "lib/base/include/base/retired_layout.h";
    char depfile[PATH_MAX], pointer[128];
    int dn = snprintf(depfile, sizeof(depfile), "build/obj/epochs/%s/unit.d",
                      epoch);
    int pn = snprintf(pointer, sizeof(pointer), "%s\n", epoch);
    return dn > 0 && (size_t)dn < sizeof(depfile) && pn > 0 &&
           (size_t)pn < sizeof(pointer) &&
           cin_write_depfile(root, depfile, dep) &&
           cin_write_file(root, "build/obj/.current-epoch", pointer) &&
           cin_force_cold(root) && cin_vanished_edge(root, dep);
}

/* Every vanished prerequisite stays an impact edge. Runs on its own fixture so
 * the extra depfiles never reach the live/reference comparison. */
static int cin_vanished_cases(const char *workspace)
{
    int failures = 0;
    char root[PATH_MAX];
    int n = snprintf(root, sizeof(root), "%s/vanished", workspace);
    bool ready = n > 0 && (size_t)n < sizeof(root) && cin_seed(root);
    CIN_CHECK("a vanished-prerequisite fixture is ready", ready);
    if (!ready) return failures;
    CIN_CHECK("a deleted header still impacts the unit that read it",
              cin_deleted_header(root));
    CIN_CHECK("a renamed header's old path still impacts the unit",
              cin_renamed_header(root));
    CIN_CHECK("a missing generated prerequisite still impacts the unit",
              cin_missing_generated(root));
    CIN_CHECK("the live epoch keeps an edge to a vanished path",
              cin_stale_epoch(root));
    return failures;
}

static bool cin_file_has(const char *path, const char *needle)
{
    FILE *file = fopen(path, "r");
    char buf[256];
    bool found = false;
    if (!file)
        return false;
    while (fgets(buf, sizeof buf, file) != nullptr) {
        if (strstr(buf, needle) != nullptr)
            found = true;
    }
    fclose(file);
    return found;
}

static bool cin_prefix_eq(const char *left, const char *right, size_t n)
{
    FILE *a = fopen(left, "r");
    FILE *b = fopen(right, "r");
    char abuf[80];
    char bbuf[80];
    bool same = false;
    if (!a || !b) {
        if (a) fclose(a);
        if (b) fclose(b);
        return false;
    }
    if (fgets(abuf, sizeof abuf, a) != nullptr &&
        fgets(bbuf, sizeof bbuf, b) != nullptr &&
        strlen(abuf) >= n && strlen(bbuf) >= n)
        same = memcmp(abuf, bbuf, n) == 0;
    fclose(a);
    fclose(b);
    return same;
}

/* Paths cin_identity_reread stages under one workspace directory, grouped so
 * the path construction can be built and checked as a single step. */
typedef struct {
    char payload_path[PATH_MAX];
    char paths_path[PATH_MAX];
    char out1[PATH_MAX];
    char out2[PATH_MAX];
    char err1[PATH_MAX];
    char err2[PATH_MAX];
} cin_identity_paths;

static bool cin_identity_locate_binary(char *bin, size_t bin_capacity)
{
    FILE *boot = popen("tools/dev/source-identity-batch-bootstrap.sh", "r");
    bool ready = boot != nullptr;
    if (ready && fgets(bin, bin_capacity, boot) == nullptr)
        ready = false;
    if (boot && pclose(boot) != 0)
        ready = false;
    size_t bin_len = strlen(bin);
    if (bin_len > 0 && bin[bin_len - 1] == '\n')
        bin[--bin_len] = '\0';
    return ready && bin_len > 0;
}

static bool cin_identity_path(char *out, size_t out_capacity,
                              const char *workspace, const char *leaf)
{
    int n = snprintf(out, out_capacity, "%s/%s", workspace, leaf);
    return n > 0 && (size_t)n < out_capacity;
}

static bool cin_identity_build_paths(const char *workspace,
                                     cin_identity_paths *p)
{
    bool ready = cin_identity_path(p->payload_path, sizeof p->payload_path,
                                   workspace, "payload.c");
    ready = ready && cin_identity_path(p->paths_path, sizeof p->paths_path,
                                       workspace, "paths");
    ready = ready && cin_identity_path(p->out1, sizeof p->out1, workspace,
                                       "out1");
    ready = ready && cin_identity_path(p->out2, sizeof p->out2, workspace,
                                       "out2");
    ready = ready && cin_identity_path(p->err1, sizeof p->err1, workspace,
                                       "err1");
    ready = ready && cin_identity_path(p->err2, sizeof p->err2, workspace,
                                       "err2");
    return ready;
}

static bool cin_identity_write_payload(const cin_identity_paths *p,
                                       const char *payload)
{
    FILE *body = fopen(p->payload_path, "w");
    FILE *paths = fopen(p->paths_path, "wb");
    bool ready = body != nullptr && paths != nullptr;
    if (body) {
        fputs(payload, body);
        fclose(body);
    }
    if (paths) {
        fputs("payload.c", paths);
        fputc('\0', paths);
        fclose(paths);
    }
    return ready;
}

static int cin_identity_run_hash(const char *workspace, const char *bin,
                                 const char *paths_path, const char *out,
                                 const char *err)
{
    char cmd[4 * PATH_MAX];
    int n = snprintf(cmd, sizeof cmd,
                     "cd '%s' && '%s' hash --cache '%s/digest-cache' "
                     "--report-bytes < '%s' > '%s' 2> '%s'",
                     workspace, bin, workspace, paths_path, out, err);
    return (n > 0 && (size_t)n < sizeof cmd) ? system(cmd) : 1;
}

static void cin_identity_report(const char *err1, const char *err2,
                                bool ready, const char *paid)
{
    printf("identity_first %s\n", ready && cin_file_has(err1, paid) ? paid : "unread");
    printf("identity_second ");
    if (ready && cin_file_has(err2, "content_bytes_read=")) {
        FILE *err = fopen(err2, "r");
        char line[128];
        if (err) {
            while (fgets(line, sizeof line, err) != nullptr)
                fputs(line, stdout);
            fclose(err);
        }
    } else {
        printf("missing\n");
    }
}

/* The second hash of an unchanged payload must not read those bytes again.
 * The three compile-scope refusals stay in cin_scope_refusals. */
static int cin_identity_reread(void)
{
    int failures = 0;
    char temporary[PLATFORM_TEMP_PATH_MAX] = {0};
    char workspace[PLATFORM_TEMP_PATH_MAX] = {0};
    char bin[PATH_MAX] = {0};
    bool ready = platform_temp_directory_create(
        "z23-identity-bytes-", temporary, sizeof temporary);
    ready = ready && platform_directory_canonical_real(
        temporary, workspace, sizeof workspace);
    ready = ready && cin_identity_locate_binary(bin, sizeof bin);
    static const char payload[] = "static int payload;\n";
    cin_identity_paths p;
    ready = ready && cin_identity_build_paths(workspace, &p);
    if (ready)
        ready = cin_identity_write_payload(&p, payload);
    int first = 1;
    int second = 1;
    if (ready) {
        first = cin_identity_run_hash(workspace, bin, p.paths_path, p.out1,
                                      p.err1);
        second = cin_identity_run_hash(workspace, bin, p.paths_path, p.out2,
                                       p.err2);
    }
    char paid[64];
    snprintf(paid, sizeof paid, "content_bytes_read=%zu", strlen(payload));
    cin_identity_report(p.err1, p.err2, ready, paid);
    CIN_CHECK("unchanged payload is not read again",
              ready && first == 0 && second == 0 &&
              cin_file_has(p.err1, paid) &&
              cin_file_has(p.err2, "content_bytes_read=0") &&
              cin_prefix_eq(p.out1, p.out2, 64));
    return failures;
}

static int cin_scope_refusals(void)
{
    int failures = 0;
    char buf[1024];
    size_t used = 0;
    FILE *pipe = popen("tools/agent_fast_ci.sh compile-scope-selftest", "r");
    if (!pipe) return 1;
    buf[0] = '\0';
    while (used + 1 < sizeof(buf)) {
        size_t got = fread(buf + used, 1, sizeof(buf) - used - 1, pipe);
        if (got == 0) break;
        used += got;
    }
    buf[used] = '\0';
    printf("%s\n", buf);
    CIN_CHECK("scope proof still refuses conflict, incomplete closure, and missing receipt",
              pclose(pipe) == 0 &&
              strstr(buf, "proof_observation_conflict") != NULL &&
              strstr(buf, "closure_incomplete") != NULL &&
              strstr(buf, "missing_receipt") != NULL);
    return failures;
}

static int cin_depfile_cases(const char *live, const char *reference)
{
    int failures = 0;
    CIN_CHECK("depfile keeps a prerequisite the checkout no longer contains",
              cin_depfile_keeps_missing(live, reference));
    CIN_CHECK("depfile fixtures match a cold rebuild",
              cin_depfile_seed(live, reference));
    CIN_CHECK("identical depfile rewrite preserves incremental include rows",
              cin_depfile_rewrite_same(live, reference));
    CIN_CHECK("changed depfile bytes force a cold include rebuild",
              cin_depfile_rewrite_changed(live, reference));
    return failures;
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

    failures += cin_scope_refusals();
    failures += cin_identity_reread();
    failures += cin_depfile_cases(live, reference);
    failures += cin_vanished_cases(workspace);

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
