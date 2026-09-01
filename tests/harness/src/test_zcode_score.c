/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_score — bounded deterministic contribution scoring and the
 * reward eligibility gate list (slice 7: contexts/commons/modules/vcs/package_score.*,
 * contexts/commons/modules/vcs/package_eligible.*, and the zcode reward score/eligible
 * handlers in tools/command/native_zcode_reward_command.c).
 *
 * Coverage (adversarial first — anti-gaming is the heart of the slice):
 *   1. Line classifier: blank / comment-only (incl. block comments
 *      spanning lines and comment markers inside string literals) /
 *      brace-only / semantic.
 *   2. File classification: extension, vendored path, generated path,
 *      generated marker (and a marker past the head window NOT
 *      excluding), test-path detection.
 *   3. Unitization + lineage diff: whitespace-only changes, statement
 *      line-splitting, line joining, brace re-styling, renames, moved
 *      code, delete-and-re-add against the grandparent lineage,
 *      within-release duplicates, and copied-source farming all score
 *      ZERO and are named.
 *   4. Scoring: tests out-credit source (2:1), the 500 line-point cap,
 *      the auto categories and their bases, the per-release total cap,
 *      and run-to-run determinism.
 *   5. Period caps: the weekly contributor cap clamps, the daily
 *      rewarded-release cap zeroes, and the trailing-7-day window edges
 *      are exact.
 *   6. Eligibility library: the frozen eight-gate strings, a full-pass
 *      report, and every gate failing by name.
 *   7. Commands over a fixture store: score breakdown + determinism for
 *      a root release; whitespace-only / rename-only / new-code /
 *      test-only child releases against the parent lineage; eligible
 *      full-pass; eligible=false naming bad signature, missing LICENSE
 *      file, missing quorum, and broken lineage; BAD_ROOT and
 *      UNKNOWN_PACKAGE. */

#include "test/test_core.h"

#include "command/native_command.h"

#include "core/uint256.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "util/safe_alloc.h"
#include "vcs/package_attest.h"
#include "vcs/package_eligible.h"
#include "vcs/package_manifest.h"
#include "vcs/package_release.h"
#include "vcs/package_score.h"
#include "vcs/package_verify_policy.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ZS_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_score: %s... OK\n", (name)); }        \
    else { printf("  zcode_score: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── small fixtures (the test_zcode_verify pattern) ─────────────────── */

static void zs_hex_enc(const uint8_t *in, size_t len, char *out)
{
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[2 * len] = '\0';
}

static bool zs_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool zs_pubkey_hex(uint8_t seed, char out[67])
{
    struct privkey sk;
    struct pubkey pk;
    if (!zs_keypair(seed, &sk, &pk))
        return false;
    zs_hex_enc(pk.vch, pk.size, out);
    return true;
}

static bool zs_mkdir_p(const char *path)
{
    char buf[4096];
    size_t len = strlen(path);
    if (len == 0 || len >= sizeof(buf))
        return false;
    memcpy(buf, path, len + 1);
    for (char *p = buf + 1; *p; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return false;
        *p = '/';
    }
    return mkdir(buf, 0700) == 0 || errno == EEXIST;
}

static bool zs_rm_rf(const char *path)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *dir = opendir(path);
    if (!dir)
        return false;
    bool ok = true;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        char child[4096];
        int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
        if (n <= 0 || (size_t)n >= sizeof(child)) {
            ok = false;
            continue;
        }
        if (!zs_rm_rf(child))
            ok = false;
    }
    closedir(dir);
    if (rmdir(path) != 0)
        ok = false;
    return ok;
}

static bool zs_write_file(const char *path, const void *data, size_t len,
                          mode_t mode)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t written = fwrite(data, 1, len, f);
    if (fclose(f) != 0 || written != len)
        return false;
    return chmod(path, mode) == 0;
}

/* ── 1. line classifier ─────────────────────────────────────────────── */

static int t_classifier(void)
{
    int failures = 0;
    struct vcs_score_line_tally t;

    vcs_score_classify_lines((const uint8_t *)"  \n\t\n", 5, &t);
    ZS_CHECK("classify: whitespace-only lines are blank",
             t.blank == 2 && t.semantic == 0);

    vcs_score_classify_lines((const uint8_t *)"// hi\n/* x */\n", 14, &t);
    ZS_CHECK("classify: comment-only lines",
             t.comment_only == 2 && t.semantic == 0);

    vcs_score_classify_lines((const uint8_t *)"/* a\n b\n c */\nint x;\n",
                             21, &t);
    ZS_CHECK("classify: block comment interior is comment-only",
             t.comment_only == 3 && t.semantic == 1);

    vcs_score_classify_lines((const uint8_t *)"/* unterminated\nint x;\n",
                             23, &t);
    ZS_CHECK("classify: unterminated block swallows later lines",
             t.comment_only == 2 && t.semantic == 0);

    vcs_score_classify_lines((const uint8_t *)"{\n}  \n{} \n", 10, &t);
    ZS_CHECK("classify: brace-only lines",
             t.brace_only == 3 && t.semantic == 0);

    vcs_score_classify_lines((const uint8_t *)"};\n", 3, &t);
    ZS_CHECK("classify: '};' is semantic (not brace-only)",
             t.semantic == 1 && t.brace_only == 0);

    vcs_score_classify_lines(
        (const uint8_t *)"const char *s = \"// not comment\";\n", 34, &t);
    ZS_CHECK("classify: // inside a string literal is code",
             t.semantic == 1 && t.comment_only == 0);

    vcs_score_classify_lines(
        (const uint8_t *)"const char *s = \"/*\";\nint y; // c\n", 33, &t);
    ZS_CHECK("classify: /* inside a string literal starts no comment",
             t.semantic == 2);

    vcs_score_classify_lines((const uint8_t *)"int x; // trailing\n", 19,
                             &t);
    ZS_CHECK("classify: code with a trailing comment is semantic",
             t.semantic == 1 && t.comment_only == 0);
    return failures;
}

/* ── 2. file classification ─────────────────────────────────────────── */

static int t_paths(void)
{
    int failures = 0;
    enum vcs_score_exclude_reason r = VCS_SCORE_EXCLUDE_NONE;

    ZS_CHECK("path: .c/.h/.def are scorable source",
             vcs_score_classify_path("src/foo.c", &r) ==
                 VCS_SCORE_FILE_SOURCE &&
             vcs_score_classify_path("include/foo.h", &r) ==
                 VCS_SCORE_FILE_SOURCE &&
             vcs_score_classify_path("config/x.def", &r) ==
                 VCS_SCORE_FILE_SOURCE);
    ZS_CHECK("path: non-C files excluded with the extension rule",
             vcs_score_classify_path("LICENSE", &r) ==
                 VCS_SCORE_FILE_EXCLUDED &&
             r == VCS_SCORE_EXCLUDE_EXTENSION &&
             vcs_score_classify_path("README.md", &r) ==
                 VCS_SCORE_FILE_EXCLUDED &&
             r == VCS_SCORE_EXCLUDE_EXTENSION &&
             vcs_score_classify_path("zcode-package.json", &r) ==
                 VCS_SCORE_FILE_EXCLUDED &&
             r == VCS_SCORE_EXCLUDE_EXTENSION);
    ZS_CHECK("path: vendored segments excluded by name",
             vcs_score_classify_path("vendor/foo.c", &r) ==
                 VCS_SCORE_FILE_EXCLUDED &&
             r == VCS_SCORE_EXCLUDE_VENDORED &&
             vcs_score_classify_path("third_party/foo.c", &r) ==
                 VCS_SCORE_FILE_EXCLUDED &&
             r == VCS_SCORE_EXCLUDE_VENDORED);
    ZS_CHECK("path: generated segment excluded by name",
             vcs_score_classify_path("out/generated/foo.c", &r) ==
                 VCS_SCORE_FILE_EXCLUDED &&
             r == VCS_SCORE_EXCLUDE_GENERATED_PATH);
    ZS_CHECK("path: test detection (segment, prefix, suffix)",
             vcs_score_classify_path("tests/foo.c", &r) ==
                 VCS_SCORE_FILE_TEST &&
             vcs_score_classify_path("test/foo.c", &r) ==
                 VCS_SCORE_FILE_TEST &&
             vcs_score_classify_path("src/test_foo.c", &r) ==
                 VCS_SCORE_FILE_TEST &&
             vcs_score_classify_path("src/foo_test.c", &r) ==
                 VCS_SCORE_FILE_TEST);

    struct vcs_score_file_scan scan;
    ZS_CHECK("path: generated marker in the head excludes",
             vcs_score_scan_file(
                 "src/tables.c",
                 (const uint8_t *)"/* auto-generated by mk */\nint x;\n",
                 34, &scan) &&
             scan.kind == VCS_SCORE_FILE_EXCLUDED &&
             scan.reason == VCS_SCORE_EXCLUDE_GENERATED_MARKER);
    vcs_score_file_scan_free(&scan);
    ZS_CHECK("path: DO NOT EDIT marker excludes",
             vcs_score_scan_file(
                 "src/tables.c",
                 (const uint8_t *)"// Code generated by tool. DO NOT EDIT.\n"
                                  "int x;\n",
                 47, &scan) &&
             scan.kind == VCS_SCORE_FILE_EXCLUDED &&
             scan.reason == VCS_SCORE_EXCLUDE_GENERATED_MARKER);
    vcs_score_file_scan_free(&scan);
    /* A marker past the 5-line head window does NOT exclude (the named,
     * documented bound; under-excluding is the unsafe direction so the
     * window is deliberately small). */
    static const uint8_t marker_after_head[] =
        "// a\n// b\n// c\n// d\n// e\n"
        "// generated noise\nint x;\n";
    ZS_CHECK("path: marker past the head window does not exclude",
             vcs_score_scan_file(
                 "src/real.c", marker_after_head,
                 sizeof(marker_after_head) - 1u, &scan) &&
             scan.kind == VCS_SCORE_FILE_SOURCE);
    vcs_score_file_scan_free(&scan);
    return failures;
}

/* ── 3. unitization + lineage diff (the anti-gaming core) ───────────── */

/* Scan one in-memory file and finalize its unit set. */
static bool zs_units(const char *path, const char *content,
                     struct vcs_score_set *out)
{
    vcs_score_set_init(out);
    return vcs_score_set_absorb_file(out, path, (const uint8_t *)content,
                                     strlen(content)) &&
           (vcs_score_set_finalize(out), true);
}

static bool zs_unit_has(struct vcs_score_set *set, const char *unit)
{
    return vcs_score_set_contains(set, unit, strlen(unit));
}

static int t_unitization(void)
{
    int failures = 0;
    struct vcs_score_set a, b;

    ZS_CHECK("unit: one statement is one unit",
             zs_units("src/x.c", "int x = 1;\n", &a) && a.count == 1 &&
             zs_unit_has(&a, "intx=1"));
    vcs_score_set_free(&a);

    /* Line-splitting: one statement broken across lines (and the opening
     * brace moved to its own line) reproduces the byte-identical units. */
    ZS_CHECK("unit: unsplit baseline",
             zs_units("src/x.c",
                      "int add(int a, int b) { return a + b; }\n", &a));
    ZS_CHECK("unit: line-split + brace-style twin",
             zs_units("src/x.c",
                      "int add(int a,\n        int b)\n{\n    return a +\n"
                      "           b;\n}\n", &b));
    ZS_CHECK("unit: line-splitting produces identical units",
             a.count == 2 && b.count == 2 &&
             zs_unit_has(&b, "intadd(inta,intb)") &&
             zs_unit_has(&b, "returna+b"));
    vcs_score_set_free(&a);
    vcs_score_set_free(&b);

    /* Line joining: two statements on one line split at the top-level
     * ';' exactly as if they were on separate lines. */
    ZS_CHECK("unit: joined statements split like separate lines",
             zs_units("src/x.c", "a();\nb();\n", &a) &&
             zs_units("src/x.c", "a(); b();\n", &b) &&
             a.count == 2 && b.count == 2 &&
             zs_unit_has(&a, "a()") && zs_unit_has(&b, "b()"));
    vcs_score_set_free(&a);
    vcs_score_set_free(&b);

    /* A for-header split across lines does NOT split at the inner ';'
     * (paren depth). */
    ZS_CHECK("unit: split for-header is one unit",
             zs_units("src/x.c",
                      "for (i = 0;\n     i < n;\n     i++) {\n", &a) &&
             a.count == 1 && zs_unit_has(&a, "for(i=0;i<n;i++)"));
    vcs_score_set_free(&a);

    /* Preprocessor lines are self-contained units. */
    ZS_CHECK("unit: preprocessor line",
             zs_units("src/x.c", "#include <stdio.h>\n", &a) &&
             a.count == 1 && zs_unit_has(&a, "#include<stdio.h>"));
    vcs_score_set_free(&a);

    /* Set dedup: the same unit twice in one file dedups on finalize. */
    ZS_CHECK("unit: within-file duplicate dedups",
             zs_units("src/x.c", "int x = 1;\nint x = 1;\n", &a) &&
             a.count == 1);
    vcs_score_set_free(&a);
    return failures;
}

/* Build a lineage set from a list of (path, content) files. */
struct zs_file {
    const char *path;
    const char *content;
};

static bool zs_lineage(struct vcs_score_set *lineage,
                       const struct zs_file *files, size_t count)
{
    vcs_score_set_init(lineage);
    for (size_t i = 0; i < count; i++) {
        if (!vcs_score_set_absorb_file(lineage, files[i].path,
                                       (const uint8_t *)files[i].content,
                                       strlen(files[i].content))) {
            vcs_score_set_free(lineage);
            return false;
        }
    }
    vcs_score_set_finalize(lineage);
    return true;
}

/* Compute the score of one release against a lineage. */
static bool zs_compute(const struct zs_file *files, size_t count,
                       const struct vcs_score_set *lineage, bool has_parent,
                       struct vcs_score_release *out)
{
    struct vcs_score_input_file *inputs =
        zcl_calloc(count ? count : 1, sizeof(*inputs), "zs_inputs");
    if (!inputs)
        return false;
    for (size_t i = 0; i < count; i++) {
        inputs[i].path = files[i].path;
        inputs[i].bytes = (const uint8_t *)files[i].content;
        inputs[i].len = strlen(files[i].content);
        inputs[i].declared_size = inputs[i].len;
    }
    bool ok = vcs_score_release_compute(inputs, count, lineage, has_parent,
                                        out);
    free(inputs);
    return ok;
}

static int t_lineage_antigaming(void)
{
    int failures = 0;
    struct vcs_score_set lineage;
    struct vcs_score_release s;
    static const char *k_add =
        "int add(int a, int b) { return a + b; }\n";

    /* Whitespace-only change against the parent lineage: zero. */
    ZS_CHECK("lineage: parent absorbs", zs_lineage(&lineage,
        (const struct zs_file[]){{"src/add.c", k_add}}, 1));
    ZS_CHECK("lineage: whitespace-only change scores 0",
             zs_compute((const struct zs_file[]){{
                 "src/add.c",
                 "int  add(  int a , int b )  {  return  a + b ;  }\n"}},
                 1, &lineage, true, &s) &&
             s.new_source_units == 0 && s.new_test_units == 0 &&
             s.total == 0 && s.category == VCS_SCORE_CATEGORY_NONE &&
             s.units_already_rewarded == s.units_total &&
             s.units_total == 2);
    vcs_score_set_free(&lineage);

    /* Line-splitting attack against the parent lineage: zero. */
    ZS_CHECK("lineage: parent absorbs (split attack)", zs_lineage(&lineage,
        (const struct zs_file[]){{"src/add.c", k_add}}, 1));
    ZS_CHECK("lineage: line-splitting scores 0",
             zs_compute((const struct zs_file[]){{
                 "src/add.c",
                 "int add(int a,\n        int b)\n{\n    return a +\n"
                 "           b;\n}\n"}}, 1, &lineage, true, &s) &&
             s.new_source_units == 0 && s.total == 0);
    vcs_score_set_free(&lineage);

    /* Rename-only: identical content at a new path scores zero (content
     * hashing, never filenames). */
    ZS_CHECK("lineage: parent absorbs (rename)", zs_lineage(&lineage,
        (const struct zs_file[]){{"src/add.c", k_add}}, 1));
    ZS_CHECK("lineage: rename-only file scores 0",
             zs_compute((const struct zs_file[]){{
                 "src/plus.c", k_add}}, 1, &lineage, true, &s) &&
             s.new_source_units == 0 && s.total == 0 &&
             s.units_already_rewarded == 2);
    vcs_score_set_free(&lineage);

    /* Delete-and-re-add: the unit was deleted in the parent but lives in
     * the GRANDPARENT — the ancestor chain still holds it, so the re-add
     * scores zero. */
    {
        ZS_CHECK("lineage: grandparent + parent absorb",
                 zs_lineage(&lineage,
                            (const struct zs_file[]){
                                {"src/old.c", k_add},      /* grandparent */
                                {"src/empty.c", "\n"}},    /* parent */
                            2));
        ZS_CHECK("lineage: delete-and-re-add scores 0",
                 zs_compute((const struct zs_file[]){{
                     "src/old.c", k_add}}, 1, &lineage, true, &s) &&
                 s.new_source_units == 0 && s.total == 0 &&
                 s.units_already_rewarded == 2);
        vcs_score_set_free(&lineage);
    }

    /* Within-release copy-paste: the same unit in two files earns once. */
    ZS_CHECK("lineage: empty", zs_lineage(&lineage, NULL, 0));
    ZS_CHECK("lineage: within-release duplicate earns once",
             zs_compute((const struct zs_file[]){
                            {"src/a.c", k_add},
                            {"src/b.c", k_add}}, 2, &lineage, true, &s) &&
             s.new_source_units == 2 && s.units_duplicate == 2 &&
             s.raw_line_points == 2);
    vcs_score_set_free(&lineage);

    /* Copied-source farming: a file copied from the lineage under a new
     * path AND a new comment scores zero new units. */
    ZS_CHECK("lineage: parent absorbs (copied source)",
             zs_lineage(&lineage,
                        (const struct zs_file[]){{"src/add.c", k_add}}, 1));
    ZS_CHECK("lineage: copied source + comment scores 0",
             zs_compute((const struct zs_file[]){{
                 "src/stolen.c",
                 "/* totally new work */\nint add(int a, int b) "
                 "{ return a + b; }\n"}}, 1, &lineage, true, &s) &&
             s.new_source_units == 0 && s.total == 0 &&
             s.comment_lines == 1);
    vcs_score_set_free(&lineage);
    return failures;
}

/* ── 4. scoring: weights, caps, categories, determinism ─────────────── */

static int t_scoring(void)
{
    int failures = 0;
    struct vcs_score_set lineage;
    struct vcs_score_release s;
    ZS_CHECK("scoring: empty lineage", zs_lineage(&lineage, NULL, 0));

    /* Tests out-credit source: the same statement count earns double in
     * a test file. */
    ZS_CHECK("scoring: source weight 1",
             zs_compute((const struct zs_file[]){{
                 "src/f.c", "int a = 1;\nint b = 2;\n"}}, 1, &lineage,
                 true, &s) &&
             s.new_source_units == 2 && s.new_test_units == 0 &&
             s.raw_line_points == 2);
    ZS_CHECK("scoring: test weight 2 (tests out-credit source)",
             zs_compute((const struct zs_file[]){{
                 "tests/f.c", "int a = 1;\nint b = 2;\n"}}, 1, &lineage,
                 true, &s) &&
             s.new_test_units == 2 && s.new_source_units == 0 &&
             s.raw_line_points == 4);

    /* The 500 line-point cap. */
    {
        static char big[65536];
        size_t off = 0;
        for (int i = 0; i < 600; i++)
            off += (size_t)snprintf(big + off, sizeof(big) - off,
                                    "int v%d = %d;\n", i, i);
        ZS_CHECK("scoring: 500 line-point cap at 600 new units",
                 zs_compute((const struct zs_file[]){{
                     "src/big.c", big}}, 1, &lineage, true, &s) &&
                 s.raw_line_points == 600 &&
                 s.line_points == VCS_SCORE_MAX_LINE_POINTS_PER_RELEASE &&
                 s.line_cap_applied);
    }

    /* Categories. */
    ZS_CHECK("scoring: root release is new-package (base 500)",
             zs_compute((const struct zs_file[]){{
                 "src/f.c", "int a = 1;\n"}}, 1, &lineage, false, &s) &&
             s.category == VCS_SCORE_CATEGORY_NEW_PACKAGE &&
             s.category_base == VCS_SCORE_CATEGORY_NEW_PACKAGE_POINTS &&
             s.total == 500 + 1);
    ZS_CHECK("scoring: source update is package-update (base 100)",
             zs_compute((const struct zs_file[]){{
                 "src/f.c", "int a = 1;\n"}}, 1, &lineage, true, &s) &&
             s.category == VCS_SCORE_CATEGORY_PACKAGE_UPDATE &&
             s.category_base == VCS_SCORE_CATEGORY_PACKAGE_UPDATE_MIN &&
             s.total == 100 + 1);
    ZS_CHECK("scoring: test-only update is test-contribution (base 100)",
             zs_compute((const struct zs_file[]){{
                 "tests/f.c", "int a = 1;\n"}}, 1, &lineage, true, &s) &&
             s.category == VCS_SCORE_CATEGORY_TEST_CONTRIBUTION &&
             s.category_base == VCS_SCORE_CATEGORY_TEST_CONTRIBUTION_MIN &&
             s.total == 100 + 2);
    ZS_CHECK("scoring: empty update is category none (total 0)",
             zs_compute((const struct zs_file[]){{
                 "src/f.c", "\n\n"}}, 1, &lineage, true, &s) &&
             s.category == VCS_SCORE_CATEGORY_NONE &&
             s.category_base == 0 && s.total == 0);

    /* The per-release total cap binds at the top: a root release cannot
     * pass 5000 even with a saturated line component. */
    {
        static char huge[131072];
        size_t off = 0;
        for (int i = 0; i < 3000; i++)
            off += (size_t)snprintf(huge + off, sizeof(huge) - off,
                                    "int w%d = %d;\n", i, i);
        ZS_CHECK("scoring: saturated lines stay under the release cap",
                 zs_compute((const struct zs_file[]){{
                     "src/huge.c", huge}}, 1, &lineage, false, &s) &&
                 s.total == 500 + 500 && !s.release_cap_applied &&
                 s.line_cap_applied);
    }

    /* Excluded files contribute nothing and are named in the report. */
    ZS_CHECK("scoring: excluded files named (vendored/generated/ext)",
             zs_compute((const struct zs_file[]){
                 {"vendor/v.c", "int q = 1;\n"},
                 {"gen/generated/g.c", "int q = 2;\n"},
                 {"notes.txt", "int q = 3;\n"},
                 {"src/real.c", "int q = 4;\n"}}, 4, &lineage, true,
                 &s) &&
             s.files_excluded == 3 && s.files_scored == 1 &&
             s.new_source_units == 1 &&
             s.files[0].reason == VCS_SCORE_EXCLUDE_VENDORED &&
             s.files[1].reason == VCS_SCORE_EXCLUDE_GENERATED_PATH &&
             s.files[2].reason == VCS_SCORE_EXCLUDE_EXTENSION);

    /* Oversize by declared size: never read, named. */
    {
        struct vcs_score_input_file over = {
            .path = "src/huge.c", .bytes = NULL, .len = 0,
            .declared_size = VCS_SCORE_MAX_FILE_BYTES + 1u,
        };
        ZS_CHECK("scoring: oversize file excluded by declared size",
                 vcs_score_release_compute(&over, 1, &lineage, true, &s) &&
                 s.files_excluded == 1 &&
                 s.files[0].reason == VCS_SCORE_EXCLUDE_OVERSIZE &&
                 s.total == 0);
    }

    /* Determinism: identical inputs, identical report. */
    {
        struct vcs_score_release s2;
        static const struct zs_file k_files[] = {
            {"src/f.c", "int a = 1;\nint b = 2;\n"},
            {"tests/f.c", "int c = 3;\n"},
        };
        bool ok1 = zs_compute(k_files, 2, &lineage, false, &s);
        bool ok2 = zs_compute(k_files, 2, &lineage, false, &s2);
        ZS_CHECK("scoring: two runs are byte-identical",
                 ok1 && ok2 && s.total == s2.total &&
                 s.category == s2.category &&
                 s.new_source_units == s2.new_source_units &&
                 s.new_test_units == s2.new_test_units &&
                 s.units_duplicate == s2.units_duplicate &&
                 s.semantic_lines == s2.semantic_lines &&
                 s.file_report_count == s2.file_report_count &&
                 s.files[0].points == s2.files[0].points &&
                 s.files[1].points == s2.files[1].points);
    }

    /* The scoring table carries every owner-directive constant. */
    {
        size_t n = 0;
        const struct vcs_score_category_constant *tbl =
            vcs_score_category_table(&n);
        bool names = n == 8 &&
            tbl[0].min_points == 500 && tbl[0].automatic &&
            tbl[1].min_points == 100 && tbl[1].max_points == 500 &&
            tbl[2].min_points == 250 && !tbl[2].automatic &&
            tbl[3].min_points == 100 && tbl[3].max_points == 500 &&
            tbl[4].min_points == 100 && !tbl[4].automatic &&
            tbl[5].min_points == 500 && tbl[5].max_points == 5000 &&
            tbl[6].min_points == 100 && !tbl[6].automatic &&
            tbl[7].min_points == 50 && tbl[7].max_points == 500;
        ZS_CHECK("scoring: owner-directive constants table", names);
    }
    vcs_score_set_free(&lineage);
    return failures;
}

/* ── 5. period caps ─────────────────────────────────────────────────── */

static int t_period_caps(void)
{
    int failures = 0;
    struct vcs_score_period_caps c;

    /* Weekly cap clamps. */
    vcs_score_apply_period_caps(
        (const struct vcs_score_period_entry[]){{100, 9800}}, 1, 100, 500,
        &c);
    ZS_CHECK("caps: weekly cap clamps to the remaining budget",
             c.allowed_score == 200 && c.weekly_cap_hit &&
             c.week_spent == 9800 && c.week_remaining == 200 &&
             !c.daily_release_cap_hit);

    /* Daily release cap zeroes outright. */
    {
        struct vcs_score_period_entry h[10];
        for (size_t i = 0; i < 10; i++) {
            h[i].day = 100;
            h[i].score = 10;
        }
        vcs_score_apply_period_caps(h, 10, 100, 500, &c);
        ZS_CHECK("caps: 10th same-day release caps the day",
                 c.releases_today == 10 && c.daily_release_cap_hit &&
                 c.allowed_score == 0);
        vcs_score_apply_period_caps(h, 9, 100, 500, &c);
        ZS_CHECK("caps: 9 same-day releases leave room",
                 c.releases_today == 9 && !c.daily_release_cap_hit &&
                 c.allowed_score == 500);
    }

    /* The trailing-7-day window edges are exact. */
    vcs_score_apply_period_caps(
        (const struct vcs_score_period_entry[]){{93, 9999}, {94, 300}},
        2, 100, 500, &c);
    ZS_CHECK("caps: day-6 counts, day-7 does not",
             c.week_spent == 300 && c.allowed_score == 500 &&
             !c.weekly_cap_hit);

    /* A full week spent caps any candidate to zero via the weekly rule. */
    vcs_score_apply_period_caps(
        (const struct vcs_score_period_entry[]){{97, 6000}, {99, 5000}},
        2, 100, 500, &c);
    ZS_CHECK("caps: exhausted week allows zero",
             c.week_spent == 11000 && c.week_remaining == 0 &&
             c.allowed_score == 0 && c.weekly_cap_hit);
    return failures;
}

/* ── 6. eligibility library ─────────────────────────────────────────── */

static int t_eligibility_lib(void)
{
    int failures = 0;
    ZS_CHECK("elig: gate strings frozen",
             strcmp(vcs_reward_gate_string(VCS_REWARD_GATE_PACKAGE_ROOT),
                    "package-root-verifies") == 0 &&
             strcmp(vcs_reward_gate_string(VCS_REWARD_GATE_RELEASE_SIGNATURE),
                    "release-signature-verifies") == 0 &&
             strcmp(vcs_reward_gate_string(VCS_REWARD_GATE_LICENSE),
                    "license-accepted") == 0 &&
             strcmp(vcs_reward_gate_string(VCS_REWARD_GATE_PARENT_LINEAGE),
                    "parent-lineage-valid") == 0 &&
             strcmp(vcs_reward_gate_string(VCS_REWARD_GATE_GCC_BUILD),
                    "gcc-build-passes") == 0 &&
             strcmp(vcs_reward_gate_string(VCS_REWARD_GATE_CLANG_BUILD),
                    "clang-build-passes") == 0 &&
             strcmp(vcs_reward_gate_string(VCS_REWARD_GATE_TESTS_PASS),
                    "tests-pass") == 0 &&
             strcmp(vcs_reward_gate_string(VCS_REWARD_GATE_VERIFIER_QUORUM),
                    "verifier-quorum") == 0 &&
             VCS_REWARD_GATE_COUNT == 8);

    struct vcs_reward_eligibility_input in;
    memset(&in, 0, sizeof(in));
    in.manifest_parsed = true;
    in.root_matches = true;
    in.chunks_checked = true;
    in.chunks_verified = 3;
    in.chunks_total = 3;
    in.release_verifies = true;
    in.license_accepted = true;
    in.lineage_valid = true;
    in.lineage_detail = "root release (no parent)";
    in.quorum_verified = true;
    in.gcc_pass = true;
    in.clang_pass = true;
    in.tests_pass = true;

    struct vcs_reward_eligibility e;
    vcs_reward_eligibility_evaluate(&in, &e);
    ZS_CHECK("elig: full pass is eligible",
             e.eligible && e.failed_count == 0 &&
             e.gates[0].passed && e.gates[7].passed);

    struct vcs_reward_eligibility_input bad = in;
    bad.release_verifies = false;
    vcs_reward_eligibility_evaluate(&bad, &e);
    ZS_CHECK("elig: bad signature named",
             !e.eligible && e.failed_count == 1 &&
             !e.gates[VCS_REWARD_GATE_RELEASE_SIGNATURE].passed &&
             strcmp(vcs_reward_gate_string(
                        e.gates[VCS_REWARD_GATE_RELEASE_SIGNATURE].gate),
                    "release-signature-verifies") == 0);

    bad = in;
    bad.license_accepted = false;
    vcs_reward_eligibility_evaluate(&bad, &e);
    ZS_CHECK("elig: license failure named",
             !e.eligible && e.failed_count == 1 &&
             !e.gates[VCS_REWARD_GATE_LICENSE].passed);

    bad = in;
    bad.lineage_valid = false;
    bad.lineage_detail = "parent release not hosted";
    vcs_reward_eligibility_evaluate(&bad, &e);
    ZS_CHECK("elig: broken lineage named with its detail",
             !e.eligible && e.failed_count == 1 &&
             !e.gates[VCS_REWARD_GATE_PARENT_LINEAGE].passed &&
             strcmp(e.gates[VCS_REWARD_GATE_PARENT_LINEAGE].detail,
                    "parent release not hosted") == 0);

    bad = in;
    bad.quorum_verified = false;
    bad.gcc_pass = bad.clang_pass = bad.tests_pass = false;
    vcs_reward_eligibility_evaluate(&bad, &e);
    ZS_CHECK("elig: missing quorum fails all four verification gates",
             !e.eligible && e.failed_count == 4 &&
             !e.gates[VCS_REWARD_GATE_GCC_BUILD].passed &&
             !e.gates[VCS_REWARD_GATE_CLANG_BUILD].passed &&
             !e.gates[VCS_REWARD_GATE_TESTS_PASS].passed &&
             !e.gates[VCS_REWARD_GATE_VERIFIER_QUORUM].passed &&
             strcmp(e.gates[VCS_REWARD_GATE_GCC_BUILD].detail,
                    "no verified quorum") == 0);

    bad = in;
    bad.chunks_verified = 2;
    vcs_reward_eligibility_evaluate(&bad, &e);
    ZS_CHECK("elig: short chunk verification named",
             !e.eligible && e.failed_count == 1 &&
             !e.gates[VCS_REWARD_GATE_PACKAGE_ROOT].passed);

    /* Multiple simultaneous failures are all named. */
    bad = in;
    bad.release_verifies = false;
    bad.quorum_verified = false;
    vcs_reward_eligibility_evaluate(&bad, &e);
    ZS_CHECK("elig: simultaneous failures all named",
             !e.eligible && e.failed_count == 5);

    /* The headline signal: a recorded bit-identical reproduction passes
     * gates 5-8 with NO quorum facts at all — the signer quorum is the
     * latency fast path over reproduction, never the other way round. */
    bad = in;
    bad.quorum_verified = false;
    bad.gcc_pass = bad.clang_pass = bad.tests_pass = false;
    bad.reproduction_verified = true;
    vcs_reward_eligibility_evaluate(&bad, &e);
    ZS_CHECK("elig: reproduction outranks the signer quorum",
             e.eligible && e.failed_count == 0 &&
             e.reproduction_verified &&
             e.gates[VCS_REWARD_GATE_GCC_BUILD].passed &&
             e.gates[VCS_REWARD_GATE_CLANG_BUILD].passed &&
             e.gates[VCS_REWARD_GATE_TESTS_PASS].passed &&
             e.gates[VCS_REWARD_GATE_VERIFIER_QUORUM].passed &&
             strstr(e.gates[VCS_REWARD_GATE_VERIFIER_QUORUM].detail,
                    "reproduction") != NULL);
    return failures;
}

/* ── 7. commands over a fixture store ───────────────────────────────── */

struct zs_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zs_cmd_init(struct zs_cmd *c, const char *datadir,
                        const char *root_hex)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_score_test.v1");
    (void)json_push_kv_str(&c->input, "datadir", datadir);
    (void)json_push_kv_str(&c->input, "root", root_hex);
}

static void zs_cmd_free(struct zs_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Publish one fixture package: manifest + chunks + a signed release by
 * publisher key 0x11. The recipe root is a fixed nonzero pattern (the
 * score/eligible surfaces never read the recipe wire; the attestations
 * commit to the same pattern). corrupt_sig flips one signature byte
 * after signing (the envelope still parses; verification fails). */
static bool zs_publish(const char *store, const struct zs_file *files,
                       size_t file_count, const char *semver,
                       bool has_parent, const uint8_t parent_id[32],
                       uint64_t sequence, bool corrupt_sig,
                       uint8_t package_root_out[32],
                       uint8_t release_id_out[32],
                       uint8_t recipe_root_out[32])
{
    char dir[4400];
    snprintf(dir, sizeof(dir), "%s/manifests", store);
    if (!zs_mkdir_p(dir))
        return false;
    snprintf(dir, sizeof(dir), "%s/releases", store);
    if (!zs_mkdir_p(dir))
        return false;
    snprintf(dir, sizeof(dir), "%s/cas/sha3", store);
    if (!zs_mkdir_p(dir))
        return false;

    struct vcs_package_manifest m;
    vcs_package_manifest_init(&m);
    bool ok = true;
    for (size_t i = 0; i < file_count && ok; i++) {
        size_t len = strlen(files[i].content);
        uint8_t hash[32] = {0};
        uint32_t chunks = 0;
        if (len > 0) {
            struct sha3_256_ctx c;
            sha3_256_init(&c);
            sha3_256_write(&c, (const uint8_t *)files[i].content, len);
            sha3_256_finalize(&c, hash);
            chunks = 1;
        }
        ok = vcs_package_manifest_add(&m, files[i].path,
                                      VCS_PACKAGE_MODE_FILE, len, hash,
                                      chunks);
        if (ok && chunks) {
            char hex[65];
            zs_hex_enc(hash, 32, hex);
            char chunk_dir[4400];
            snprintf(chunk_dir, sizeof(chunk_dir), "%s/cas/sha3/%.2s",
                     store, hex);
            char chunk_path[4400];
            snprintf(chunk_path, sizeof(chunk_path), "%s/%s", chunk_dir,
                     hex);
            ok = zs_mkdir_p(chunk_dir) &&
                 zs_write_file(chunk_path, files[i].content, len, 0600);
        }
    }
    if (ok)
        ok = vcs_package_manifest_root(&m, package_root_out);
    uint8_t *mwire = NULL;
    size_t mwire_len = 0;
    if (ok)
        ok = vcs_package_manifest_serialize(&m, &mwire, &mwire_len);
    vcs_package_manifest_free(&m);
    if (!ok)
        return false;
    char root_hex[65];
    zs_hex_enc(package_root_out, 32, root_hex);
    char path[4400];
    snprintf(path, sizeof(path), "%s/manifests/%s", store, root_hex);
    ok = zs_write_file(path, mwire, mwire_len, 0600);
    free(mwire);
    if (!ok)
        return false;

    for (size_t i = 0; i < 32; i++)
        recipe_root_out[i] = (uint8_t)(0x80 + i);
    struct privkey sk;
    struct pubkey pk;
    if (!zs_keypair(0x11, &sk, &pk))
        return false;
    struct vcs_package_release rel;
    memset(&rel, 0, sizeof(rel));
    rel.schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(rel.name, sizeof(rel.name), "alice/addpkg");
    snprintf(rel.semver, sizeof(rel.semver), "%s", semver);
    memcpy(rel.package_root, package_root_out, 32);
    rel.has_parent = has_parent;
    if (has_parent)
        memcpy(rel.parent_root, parent_id, 32);
    memcpy(rel.publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    rel.publisher_sequence = sequence;
    snprintf(rel.reward_address, sizeof(rel.reward_address), "t1fixture");
    snprintf(rel.license, sizeof(rel.license), "MIT");
    memcpy(rel.recipe_root, recipe_root_out, 32);
    rel.has_znam = false;
    snprintf(rel.chain_id, sizeof(rel.chain_id), "zclassic-main");
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(&rel, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(rel.signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    if (corrupt_sig)
        rel.signature[9] ^= 0x01;
    uint8_t *relwire = NULL;
    size_t relwire_len = 0;
    if (vcs_package_release_serialize(&rel, &relwire, &relwire_len) !=
        VCS_PACKAGE_RELEASE_OK)
        return false;
    memcpy(release_id_out, id, 32);
    char id_hex[65];
    zs_hex_enc(id, 32, id_hex);
    snprintf(path, sizeof(path), "%s/releases/%s", store, id_hex);
    ok = zs_write_file(path, relwire, relwire_len, 0600);
    free(relwire);
    return ok;
}

static bool zs_store_attestation(const char *store,
                                 const uint8_t package_root[32],
                                 const uint8_t release_id[32],
                                 const uint8_t recipe_root[32],
                                 uint8_t signer_seed)
{
    char dir[4400];
    snprintf(dir, sizeof(dir), "%s/attestations", store);
    if (!zs_mkdir_p(dir))
        return false;
    struct privkey sk;
    struct pubkey pk;
    if (!zs_keypair(signer_seed, &sk, &pk))
        return false;
    struct vcs_package_attest a;
    memset(&a, 0, sizeof(a));
    a.schema_version = VCS_PACKAGE_ATTEST_VERSION;
    memcpy(a.package_root, package_root, 32);
    memcpy(a.release_id, release_id, 32);
    memcpy(a.recipe_root, recipe_root, 32);
    a.result_class = VCS_PACKAGE_ATTEST_RESULT_TEST_PASS;
    snprintf(a.compilers[0].id, sizeof(a.compilers[0].id), "clang");
    snprintf(a.compilers[0].version, sizeof(a.compilers[0].version),
             "18.1.3");
    snprintf(a.compilers[1].id, sizeof(a.compilers[1].id), "gcc");
    snprintf(a.compilers[1].version, sizeof(a.compilers[1].version),
             "13.2.0");
    a.compiler_count = 2;
    a.compilers[0].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    a.compilers[1].outcome = VCS_PACKAGE_ATTEST_OUTCOME_PASS;
    a.isolation = VCS_PACKAGE_ATTEST_ISOLATION_FULL;
    a.test_ran = true;
    a.test_exit_code = 0;
    memcpy(a.verifier_pubkey, pk.vch, 33);
    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    if (vcs_package_attest_id(&a, id) != VCS_PACKAGE_ATTEST_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&sk, &hash, compact))
        return false;
    memcpy(a.signature, compact + 1, VCS_PACKAGE_ATTEST_SIGNATURE_BYTES);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (vcs_package_attest_serialize(&a, &wire, &wire_len) !=
        VCS_PACKAGE_ATTEST_OK)
        return false;
    char id_hex[65];
    zs_hex_enc(id, 32, id_hex);
    char path[4400];
    snprintf(path, sizeof(path), "%s/attestations/%s", store, id_hex);
    bool ok = zs_write_file(path, wire, wire_len, 0600);
    free(wire);
    return ok;
}

static bool zs_write_policy(const char *store)
{
    char ka[67], kb[67];
    if (!zs_pubkey_hex(0x22, ka) || !zs_pubkey_hex(0x33, kb))
        return false;
    char text[256];
    int n = snprintf(text, sizeof(text),
                     "# local approved verifiers\n%s\n%s\n", ka, kb);
    char path[4400];
    snprintf(path, sizeof(path), "%s/approved_verifiers", store);
    return n > 0 && zs_write_file(path, text, (size_t)n, 0600);
}

/* The v1 fixture: LICENSE + a header + one source + one test. */
static const struct zs_file k_v1_files[] = {
    { "LICENSE", "MIT License\n" },
    { "src/add.c",
      "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n" },
    { "src/add.h", "#pragma once\nint add(int a, int b);\n" },
    { "test/test_add.c",
      "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n" },
};

static bool zs_gate_failed(const struct json_value *failed,
                           const char *gate)
{
    for (size_t i = 0; failed && json_at(failed, i); i++) {
        const char *g = json_get_str(json_at(failed, i));
        if (g && strcmp(g, gate) == 0)
            return true;
    }
    return false;
}

static int t_command(void)
{
    int failures = 0;
    char datadir[4400];
    snprintf(datadir, sizeof(datadir), "test-tmp/zs_cmd_%ld",
             (long)getpid());
    char store[4400];
    snprintf(store, sizeof(store), "%s/zcode", datadir);
    zs_rm_rf(datadir);

    uint8_t pr[32], ri[32], rr[32];
    bool f1 = zs_publish(store, k_v1_files,
                         sizeof(k_v1_files) / sizeof(k_v1_files[0]),
                         "1.0.0", false, NULL, 1, false, pr, ri, rr);
    ZS_CHECK("command: v1 fixture publishes", f1);
    if (!f1)
        return failures + 1;
    char pr_hex[65];
    zs_hex_enc(pr, 32, pr_hex);

    /* Score the root release: new-package 500 + 8 line points = 508. */
    {
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr_hex);
        zcl_native_handle_zcode_reward_score(&c.request, &c.reply);
        const char *cat = json_get_str(json_get(&c.reply.data, "category"));
        ZS_CHECK("command: root release scores new-package 508",
                 cat && strcmp(cat, "new-package") == 0 &&
                 json_get_int(json_get(&c.reply.data, "category_base")) ==
                     500 &&
                 json_get_int(json_get(json_get(&c.reply.data, "units"),
                                       "new_source")) == 4 &&
                 json_get_int(json_get(json_get(&c.reply.data, "units"),
                                       "new_test")) == 2 &&
                 json_get_int(json_get(json_get(&c.reply.data, "units"),
                                       "duplicate_within_release")) == 2 &&
                 json_get_int(json_get(json_get(&c.reply.data, "points"),
                                       "total")) == 508 &&
                 !json_get_bool(json_get(json_get(&c.reply.data, "points"),
                                         "line_cap_applied")));
        /* LICENSE is excluded with the extension rule, named per file. */
        const struct json_value *files = json_get(&c.reply.data, "files");
        bool license_named = false;
        for (size_t i = 0; files && json_at(files, i); i++) {
            const struct json_value *row = json_at(files, i);
            const char *path = json_get_str(json_get(row, "path"));
            const char *reason = json_get_str(json_get(row, "reason"));
            if (path && strcmp(path, "LICENSE") == 0 && reason &&
                strcmp(reason, "not-c-source") == 0)
                license_named = true;
        }
        ZS_CHECK("command: LICENSE excluded with the named rule",
                 license_named);
        zs_cmd_free(&c);
    }

    /* Determinism at the command surface: two runs, identical report. */
    {
        struct zs_cmd c1, c2;
        zs_cmd_init(&c1, datadir, pr_hex);
        zcl_native_handle_zcode_reward_score(&c1.request, &c1.reply);
        zs_cmd_init(&c2, datadir, pr_hex);
        zcl_native_handle_zcode_reward_score(&c2.request, &c2.reply);
        ZS_CHECK("command: two score runs are identical",
                 json_get_int(json_get(json_get(&c1.reply.data, "points"),
                                       "total")) ==
                     json_get_int(json_get(json_get(&c2.reply.data,
                                                    "points"), "total")) &&
                 json_get_int(json_get(json_get(&c1.reply.data, "units"),
                                       "new_source")) ==
                     json_get_int(json_get(json_get(&c2.reply.data,
                                                    "units"),
                                           "new_source")) &&
                 json_get_int(json_get(json_get(&c1.reply.data, "lines"),
                                       "semantic")) ==
                     json_get_int(json_get(json_get(&c2.reply.data,
                                                    "lines"), "semantic")));
        zs_cmd_free(&c1);
        zs_cmd_free(&c2);
    }

    /* Child v2: whitespace-only re-edit of add.c. Zero. */
    {
        const struct zs_file v2[] = {
            { "LICENSE", "MIT License\n" },
            { "src/add.c",
              "#include  \"add.h\"\nint  add( int a , int b )\n{\n"
              "    return  a + b ;\n}\n" },
            { "src/add.h", "#pragma once\nint add(int a, int b);\n" },
            { "test/test_add.c",
              "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n" },
        };
        uint8_t pr2[32], ri2[32], rr2[32];
        bool f2 = zs_publish(store, v2, sizeof(v2) / sizeof(v2[0]),
                             "1.0.1", true, ri, 2, false, pr2, ri2, rr2);
        char pr2_hex[65];
        zs_hex_enc(pr2, 32, pr2_hex);
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr2_hex);
        zcl_native_handle_zcode_reward_score(&c.request, &c.reply);
        const char *cat = json_get_str(json_get(&c.reply.data, "category"));
        ZS_CHECK("command: whitespace-only child scores 0",
                 f2 && cat && strcmp(cat, "none") == 0 &&
                 json_get_int(json_get(json_get(&c.reply.data, "points"),
                                       "total")) == 0 &&
                 json_get_int(json_get(json_get(&c.reply.data, "units"),
                                       "already_rewarded")) ==
                     json_get_int(json_get(json_get(&c.reply.data, "units"),
                                           "total")) &&
                 json_get_int(json_get(json_get(&c.reply.data, "lineage"),
                                       "ancestors_walked")) == 1 &&
                 json_get_bool(json_get(json_get(&c.reply.data, "lineage"),
                                        "complete")));
        zs_cmd_free(&c);
    }

    /* Child v3: add.c renamed to plus.c, identical content. Zero. */
    {
        const struct zs_file v3[] = {
            { "LICENSE", "MIT License\n" },
            { "src/add.h", "#pragma once\nint add(int a, int b);\n" },
            { "src/plus.c",
              "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n" },
            { "test/test_add.c",
              "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n" },
        };
        uint8_t pr3[32], ri3[32], rr3[32];
        bool f3 = zs_publish(store, v3, sizeof(v3) / sizeof(v3[0]),
                             "1.0.2", true, ri, 2, false, pr3, ri3, rr3);
        char pr3_hex[65];
        zs_hex_enc(pr3, 32, pr3_hex);
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr3_hex);
        zcl_native_handle_zcode_reward_score(&c.request, &c.reply);
        ZS_CHECK("command: rename-only child scores 0",
                 f3 &&
                 json_get_int(json_get(json_get(&c.reply.data, "points"),
                                       "total")) == 0 &&
                 json_get_int(json_get(json_get(&c.reply.data, "units"),
                                       "new_source")) == 0);
        zs_cmd_free(&c);
    }

    /* Child v4: one genuinely new function. package-update 100 + 2. */
    {
        const struct zs_file v4[] = {
            { "LICENSE", "MIT License\n" },
            { "src/add.c",
              "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n"
              "int sub(int a, int b) { return a - b; }\n" },
            { "src/add.h", "#pragma once\nint add(int a, int b);\n" },
            { "test/test_add.c",
              "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n" },
        };
        uint8_t pr4[32], ri4[32], rr4[32];
        bool f4 = zs_publish(store, v4, sizeof(v4) / sizeof(v4[0]),
                             "1.1.0", true, ri, 2, false, pr4, ri4, rr4);
        char pr4_hex[65];
        zs_hex_enc(pr4, 32, pr4_hex);
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr4_hex);
        zcl_native_handle_zcode_reward_score(&c.request, &c.reply);
        const char *cat = json_get_str(json_get(&c.reply.data, "category"));
        ZS_CHECK("command: new function scores package-update 102",
                 f4 && cat && strcmp(cat, "package-update") == 0 &&
                 json_get_int(json_get(json_get(&c.reply.data, "units"),
                                       "new_source")) == 2 &&
                 json_get_int(json_get(json_get(&c.reply.data, "units"),
                                       "already_rewarded")) == 6 &&
                 json_get_int(json_get(json_get(&c.reply.data, "points"),
                                       "total")) == 102);
        zs_cmd_free(&c);
    }

    /* Child v5: a new test only. test-contribution 100 + 2*2. */
    {
        const struct zs_file v5[] = {
            { "LICENSE", "MIT License\n" },
            { "src/add.c",
              "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n" },
            { "src/add.h", "#pragma once\nint add(int a, int b);\n" },
            { "test/test_add.c",
              "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n"
              "int extra(void) { return add(1, 1) == 2 ? 0 : 1; }\n" },
        };
        uint8_t pr5[32], ri5[32], rr5[32];
        bool f5 = zs_publish(store, v5, sizeof(v5) / sizeof(v5[0]),
                             "1.1.1", true, ri, 2, false, pr5, ri5, rr5);
        char pr5_hex[65];
        zs_hex_enc(pr5, 32, pr5_hex);
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr5_hex);
        zcl_native_handle_zcode_reward_score(&c.request, &c.reply);
        const char *cat = json_get_str(json_get(&c.reply.data, "category"));
        ZS_CHECK("command: new test scores test-contribution 104",
                 f5 && cat && strcmp(cat, "test-contribution") == 0 &&
                 json_get_int(json_get(json_get(&c.reply.data, "units"),
                                       "new_test")) == 2 &&
                 json_get_int(json_get(json_get(&c.reply.data, "points"),
                                       "total")) == 104);
        zs_cmd_free(&c);
    }

    /* Rejections. */
    {
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, "zz");
        zcl_native_handle_zcode_reward_score(&c.request, &c.reply);
        ZS_CHECK("command: score BAD_ROOT",
                 strcmp(c.reply.error.code, "BAD_ROOT") == 0);
        zs_cmd_free(&c);
    }
    {
        uint8_t other[32];
        for (size_t i = 0; i < 32; i++)
            other[i] = (uint8_t)(0x55 + i);
        char other_hex[65];
        zs_hex_enc(other, 32, other_hex);
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, other_hex);
        zcl_native_handle_zcode_reward_eligible(&c.request, &c.reply);
        ZS_CHECK("command: eligible UNKNOWN_PACKAGE",
                 strcmp(c.reply.error.code, "UNKNOWN_PACKAGE") == 0);
        zs_cmd_free(&c);
    }

    /* Eligible: no allowlist -> the four verification gates fail. */
    {
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr_hex);
        zcl_native_handle_zcode_reward_eligible(&c.request, &c.reply);
        const struct json_value *failed =
            json_get(&c.reply.data, "failed_gates");
        ZS_CHECK("command: no quorum named on all four gates",
                 !json_get_bool(json_get(&c.reply.data, "eligible")) &&
                 json_get_int(json_get(&c.reply.data, "failed_count")) ==
                     4 &&
                 zs_gate_failed(failed, "verifier-quorum") &&
                 zs_gate_failed(failed, "gcc-build-passes") &&
                 zs_gate_failed(failed, "clang-build-passes") &&
                 zs_gate_failed(failed, "tests-pass"));
        zs_cmd_free(&c);
    }

    /* Eligible: allowlist + 2 approved matching attestations -> pass. */
    ZS_CHECK("command: allowlist writes", zs_write_policy(store));
    ZS_CHECK("command: attestation A persists",
             zs_store_attestation(store, pr, ri, rr, 0x22));
    ZS_CHECK("command: attestation B persists",
             zs_store_attestation(store, pr, ri, rr, 0x33));
    {
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr_hex);
        zcl_native_handle_zcode_reward_eligible(&c.request, &c.reply);
        const struct json_value *gates = json_get(&c.reply.data, "gates");
        ZS_CHECK("command: full-pass eligibility",
                 json_get_bool(json_get(&c.reply.data, "eligible")) &&
                 json_get_int(json_get(&c.reply.data, "failed_count")) ==
                     0 &&
                 gates && json_at(gates, 7) != NULL &&
                 json_at(gates, 8) == NULL);
        zs_cmd_free(&c);
    }

    /* Eligible: corrupted release signature named (the license gate
     * still passes — the envelope parsed, so the SPDX id is allowlist
     * grammar; the LICENSE file is present). The LICENSE text differs by
     * one newline so this fixture's package root does NOT collide with
     * v1's (same release id would clobber v1's persisted envelope). */
    {
        const struct zs_file corrupt_files[] = {
            { "LICENSE", "MIT License\n\n" },
            { "src/add.c",
              "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n" },
            { "src/add.h", "#pragma once\nint add(int a, int b);\n" },
            { "test/test_add.c",
              "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n" },
        };
        uint8_t pr6[32], ri6[32], rr6[32];
        bool f6 = zs_publish(store, corrupt_files,
                             sizeof(corrupt_files) /
                                 sizeof(corrupt_files[0]),
                             "1.0.0", false, NULL, 1, true, pr6, ri6, rr6);
        char pr6_hex[65];
        zs_hex_enc(pr6, 32, pr6_hex);
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr6_hex);
        zcl_native_handle_zcode_reward_eligible(&c.request, &c.reply);
        const struct json_value *failed =
            json_get(&c.reply.data, "failed_gates");
        ZS_CHECK("command: bad signature named",
                 f6 && !json_get_bool(json_get(&c.reply.data, "eligible")) &&
                 zs_gate_failed(failed, "release-signature-verifies") &&
                 !zs_gate_failed(failed, "license-accepted") &&
                 !zs_gate_failed(failed, "parent-lineage-valid"));
        zs_cmd_free(&c);
    }

    /* Eligible: a manifest without a LICENSE file fails the license
     * gate (the envelope SPDX allowlist is grammar-enforced at parse, so
     * an off-allowlist license can never persist — the LICENSE text file
     * is the checkable half). */
    {
        const struct zs_file nolicense[] = {
            { "src/add.c",
              "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n" },
            { "src/add.h", "#pragma once\nint add(int a, int b);\n" },
        };
        uint8_t pr7[32], ri7[32], rr7[32];
        bool f7 = zs_publish(store, nolicense,
                             sizeof(nolicense) / sizeof(nolicense[0]),
                             "1.0.0", false, NULL, 1, false, pr7, ri7, rr7);
        ZS_CHECK("command: no-license fixture attestations persist",
                 f7 && zs_store_attestation(store, pr7, ri7, rr7, 0x22) &&
                 zs_store_attestation(store, pr7, ri7, rr7, 0x33));
        char pr7_hex[65];
        zs_hex_enc(pr7, 32, pr7_hex);
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr7_hex);
        zcl_native_handle_zcode_reward_eligible(&c.request, &c.reply);
        const struct json_value *failed =
            json_get(&c.reply.data, "failed_gates");
        ZS_CHECK("command: missing LICENSE file named",
                 !json_get_bool(json_get(&c.reply.data, "eligible")) &&
                 zs_gate_failed(failed, "license-accepted") &&
                 json_get_int(json_get(&c.reply.data, "failed_count")) ==
                     1);
        zs_cmd_free(&c);
    }

    /* Eligible: a child naming a parent release that is not hosted
     * fails the lineage gate. */
    {
        uint8_t ghost[32];
        for (size_t i = 0; i < 32; i++)
            ghost[i] = (uint8_t)(0xee - i);
        uint8_t pr8[32], ri8[32], rr8[32];
        bool f8 = zs_publish(store, k_v1_files,
                             sizeof(k_v1_files) / sizeof(k_v1_files[0]),
                             "2.0.0", true, ghost, 2, false, pr8, ri8, rr8);
        ZS_CHECK("command: broken-lineage attestations persist",
                 f8 && zs_store_attestation(store, pr8, ri8, rr8, 0x22) &&
                 zs_store_attestation(store, pr8, ri8, rr8, 0x33));
        char pr8_hex[65];
        zs_hex_enc(pr8, 32, pr8_hex);
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr8_hex);
        zcl_native_handle_zcode_reward_eligible(&c.request, &c.reply);
        const struct json_value *failed =
            json_get(&c.reply.data, "failed_gates");
        ZS_CHECK("command: broken lineage named",
                 !json_get_bool(json_get(&c.reply.data, "eligible")) &&
                 zs_gate_failed(failed, "parent-lineage-valid") &&
                 json_get_int(json_get(&c.reply.data, "failed_count")) ==
                     1);
        zs_cmd_free(&c);
    }

    /* Eligible: a proper child of v1 passes the lineage gate. */
    {
        const struct zs_file v4[] = {
            { "LICENSE", "MIT License\n" },
            { "src/add.c",
              "#include \"add.h\"\nint add(int a, int b) { return a + b; }\n"
              "int sub(int a, int b) { return a - b; }\n" },
            { "src/add.h", "#pragma once\nint add(int a, int b);\n" },
            { "test/test_add.c",
              "#include \"add.h\"\nint main(void) { return add(2, 3) == 5 ? 0 : 1; }\n" },
        };
        uint8_t pr9[32], ri9[32], rr9[32];
        bool f9 = zs_publish(store, v4, sizeof(v4) / sizeof(v4[0]),
                             "1.1.0", true, ri, 2, false, pr9, ri9, rr9);
        ZS_CHECK("command: good-child attestations persist",
                 f9 && zs_store_attestation(store, pr9, ri9, rr9, 0x22) &&
                 zs_store_attestation(store, pr9, ri9, rr9, 0x33));
        char pr9_hex[65];
        zs_hex_enc(pr9, 32, pr9_hex);
        struct zs_cmd c;
        zs_cmd_init(&c, datadir, pr9_hex);
        zcl_native_handle_zcode_reward_eligible(&c.request, &c.reply);
        ZS_CHECK("command: child of v1 fully eligible",
                 json_get_bool(json_get(&c.reply.data, "eligible")) &&
                 json_get_int(json_get(&c.reply.data, "failed_count")) ==
                     0);
        zs_cmd_free(&c);
    }

    zs_rm_rf(datadir);
    return failures;
}

int test_zcode_score(void)
{
    printf("\n=== zcode_score: contribution scoring + eligibility ===\n");
    int failures = 0;
    failures += t_classifier();
    failures += t_paths();
    failures += t_unitization();
    failures += t_lineage_antigaming();
    failures += t_scoring();
    failures += t_period_caps();
    failures += t_eligibility_lib();
    failures += t_command();
    printf("=== zcode_score complete: %d failure(s) ===\n", failures);
    return failures;
}
