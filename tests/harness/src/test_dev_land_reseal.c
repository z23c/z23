/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: the queue re-derives the core seal files when a
 * row that ran the unseal ritual rebases onto a main that ran it too.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h.
 *
 * Each rig carries a sealed core/ tree, the two hot-swap mirror headers and
 * a fixture Makefile whose core-seal target pipes `git ls-files -z core/`
 * into the real tools/core_seal binary (build/bin/core_seal, a build need of
 * this group) and writes both headers from the manifest. The queue runs that
 * target in its landing worktree exactly as an author runs `make core-seal`. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"

#include <unistd.h>

#if !defined(_WIN32)

#define RS_MANIFEST "core/MANIFEST.sha3"
#define RS_UNSEAL "core/UNSEAL.md"
#define RS_ROOT_H "engine/modules/hotswap/include/hotswap/core_seal_root.h"
#define RS_SECT_H "engine/modules/hotswap/include/hotswap/core_seal_sections.h"

/* The fixture Makefile: the real sealer, and both mirrors derived from the
 * manifest the way the repository derives them (ROOT line; SECTION and TREE
 * lines). */
static bool rs_makefile(const char *clone)
{
    char cwd[1024], seal[1200], text[4096];
    if (!getcwd(cwd, sizeof(cwd)) ||
        snprintf(seal, sizeof(seal), "%s/build/bin/core_seal", cwd) >=
            (int)sizeof(seal) ||
        !dlx_file_exists(seal))
        return false;
    int n = snprintf(text, sizeof(text),
        "SEAL := %s\n"
        ".PHONY: core-seal core-seal-check\n"
        "core-seal:\n"
        "\ttest -z \"$(RS_SEAL_FAIL)\"\n"
        "\tgit ls-files -z core/ | $(SEAL) seal " RS_MANIFEST "\n"
        "\tawk '$$1 == \"ROOT\" { print \"#define ZCL_CORE_SEAL_ROOT \\\"\" $$2 \"\\\"\" }' "
        RS_MANIFEST " > " RS_ROOT_H "\n"
        "\tawk '$$1 == \"SECTION\" || $$1 == \"TREE\"' " RS_MANIFEST
        " > " RS_SECT_H "\n"
        "core-seal-check:\n"
        "\tgit ls-files -z core/ | $(SEAL) check " RS_MANIFEST "\n",
        seal);
    return n > 0 && n < (int)sizeof(text) &&
           dlx_write_dep(clone, "Makefile", text);
}

static bool rs_make(const char *dir, const char *target)
{
    char sink[8192];
    const char *argv[] = { "make", "-s", "-C", dir, target, NULL };
    return zcl_spawn_capture(argv, sink, sizeof(sink), 120000) == 0;
}

/* The ROOT line of `rev`'s manifest in `dir`. */
static bool rs_root_at(const char *dir, const char *rev, char root[80])
{
    char spec[160], text[65536];
    const char *show[] = { "show", spec, NULL };
    root[0] = '\0';
    (void)snprintf(spec, sizeof(spec), "%s:" RS_MANIFEST, rev);
    if (dlx_git_out(dir, show, text, sizeof(text)) != 0)
        return false;
    /* The manifest's one line that starts "ROOT", then blanks, then hex. */
    const char *p = strstr(text, "\nROOT");
    if (!p)
        return false;
    p += 5;
    p += strspn(p, " \t");
    (void)snprintf(root, 80, "%.64s", p);
    return strlen(root) == 64 && strspn(root, "0123456789abcdef") == 64;
}

static bool rs_file_at(const char *dir, const char *rev, const char *path,
                       char *out, size_t cap)
{
    /* Exact bytes: dlx_git_out() strips the trailing newline the log ends in. */
    char spec[400];
    const char *argv[] = { "git", "-C", dir, "cat-file", "blob", spec, NULL };
    (void)snprintf(spec, sizeof(spec), "%s:%s", rev, path);
    return zcl_spawn_capture(argv, out, cap, 60000) == 0 &&
           strlen(out) + 1 < cap;
}

/* One unseal-ritual entry, appended verbatim to core/UNSEAL.md. */
static bool rs_entry(char *out, size_t cap, const char *reason,
                     const char *old_root)
{
    int n = snprintf(out, cap,
                     "\n- 2026-11-06T00:00:00Z \xe2\x80\x94 REASON: %s\n"
                     "  old ROOT: %s\n"
                     "  by: owner unseal ritual (make core-unseal)\n",
                     reason, old_root);
    return n > 0 && (size_t)n < cap;
}

static bool rs_append(const char *clone, const char *rel, const char *text)
{
    char path[1400];
    (void)snprintf(path, sizeof(path), "%s/%s", clone, rel);
    FILE *f = fopen(path, "ab");
    if (!f)
        return false;
    size_t len = strlen(text);
    bool ok = fwrite(text, 1, len, f) == len;
    return fclose(f) == 0 && ok;
}

/* A core edit on the current checkout. `ritual` appends the UNSEAL entry the
 * owner ritual writes; the manifest and mirrors are re-frozen, and `seal`
 * false edits another core file after that (a stale seal). The
 * entry text is copied into `entry` (may be NULL). */
static bool rs_core_commit(const char *clone, const char *file,
                           const char *body, const char *reason, bool ritual,
                           bool seal, char *entry, size_t entry_cap,
                           char out[64])
{
    char root[80], text[512];
    if (!rs_root_at(clone, "HEAD", root) ||
        !dlx_write_dep(clone, file, body))
        return false;
    if (ritual && (!rs_entry(text, sizeof(text), reason, root) ||
                   !rs_append(clone, RS_UNSEAL, text)))
        return false;
    if (entry)
        (void)snprintf(entry, entry_cap, "%s", ritual ? text : "");
    /* !seal: the author seals, then edits core/c.c before committing, so
     * the commit's own manifest no longer verifies. */
    return rs_make(clone, "core-seal") &&
           (seal || dlx_write_dep(clone, "core/c.c", "int c = 9;\n")) &&
           dlx_commit_tree(clone, reason, out);
}

/* origin/main: a sealed core/ of three files, the log and both mirrors. */
static bool rs_rig(struct dlx_rig *rig, const char *tag, char base[64])
{
    const char *reset[] = { "reset", "--quiet", "--hard", "origin/main",
                            NULL };
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    return dlx_rig_make(rig, tag) && dlx_git(rig->clone, reset) == 0 &&
           rs_makefile(rig->clone) &&
           dlx_write_dep(rig->clone, "core/a.c", "int a = 1;\n") &&
           dlx_write_dep(rig->clone, "core/b.c", "int b = 1;\n") &&
           dlx_write_dep(rig->clone, "core/c.c", "int c = 1;\n") &&
           dlx_write_dep(rig->clone, RS_UNSEAL,
                         "# core/ UNSEAL log\n\n"
                         "<!-- UNSEAL-ENTRIES -->\n") &&
           dlx_write_dep(rig->clone, RS_ROOT_H, "") &&
           dlx_write_dep(rig->clone, RS_SECT_H, "") &&
           dlx_git(rig->clone, (const char *[]){ "add", "-A", NULL }) == 0 &&
           rs_make(rig->clone, "core-seal") &&
           dlx_commit_tree(rig->clone, "sealed core", base) &&
           dlx_git(rig->clone, push) == 0;
}

static bool rs_checkout(const char *clone, const char *branch,
                        const char *start)
{
    const char *co[] = { "checkout", "--quiet", "-B", branch, start, NULL };
    return dlx_git(clone, co) == 0;
}

static bool rs_outcome_line(const char *tip, char *line, size_t cap);

/* Step until `tip` has a terminal outcome and nothing is queued, or `beats`
 * run out. dlx_queue_empty() does not count the in-flight row. */
static bool rs_drain(const char *tip, int beats)
{
    static char line[16384];
    for (int i = 0; i < beats; i++) {
        if (dlx_queue_empty() && rs_outcome_line(tip, line, sizeof(line)))
            return true;
        struct dlx_call c;
        dlx_begin(&c, "step");
        bool ok = dlx_run(&c) && dlx_ok(&c);
        dlx_end(&c);
        if (!ok)
            return false;
    }
    return dlx_queue_empty() && rs_outcome_line(tip, line, sizeof(line));
}

/* The last outcomes.jsonl line naming `tip`. */
static bool rs_outcome_line(const char *tip, char *line, size_t cap)
{
    static char text[262144];
    char landdir[1200], path[1300], anchor[128];
    const char *hit = NULL;
    size_t len = 0;
    dlx_landdir(landdir, sizeof(landdir));
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", landdir);
    (void)snprintf(anchor, sizeof(anchor), "\"tip\":\"%s\"", tip);
    if (!dlx_slurp(path, text, sizeof(text) - 1, &len))
        return false;
    text[len] = '\0';
    for (const char *p = text; (p = strstr(p, anchor)) != NULL; p++)
        hit = p;
    if (!hit)
        return false;
    const char *start = hit, *end = strchr(hit, '\n');
    while (start > text && start[-1] != '\n')
        start--;
    if (!end)
        end = text + len;
    if ((size_t)(end - start) >= cap)
        return false;
    (void)snprintf(line, cap, "%.*s", (int)(end - start), start);
    return true;
}

static bool rs_has(const char *line, const char *key, const char *value)
{
    char needle[256];
    (void)snprintf(needle, sizeof(needle), "\"%s\":\"%s\"", key, value);
    return strstr(line, needle) != NULL;
}

/* origin/main checked out in the clone verifies against its own manifest,
 * and a fresh seal of it changes no byte of the three derived files. */
static bool rs_main_sealed(const char *clone, char root[80])
{
    const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
    const char *status[] = { "status", "--porcelain", NULL };
    char dirty[1024];
    return dlx_git(clone, fetch) == 0 &&
           rs_checkout(clone, "landed", "origin/main") &&
           rs_make(clone, "core-seal-check") &&
           rs_make(clone, "core-seal") &&
           dlx_git_out(clone, status, dirty, sizeof(dirty)) == 0 &&
           dirty[0] == '\0' && rs_root_at(clone, "HEAD", root);
}

/* Two rows that both ran the ritual on different core files. A lands first;
 * B (two ritual commits) then rebases onto A with every seal file in
 * conflict. The queue re-derives each pick's seal, carries B's own entries
 * after A's, and records the submitted and the landed ROOT. */
static int rs_case_two_rituals(void)
{
    int failures = 0;
    TEST("land: a ritual row rebased onto another ritual row re-derives the "
         "core seal, keeps both UNSEAL entries in order and records the "
         "old and new ROOT") {
        struct dlx_rig rig;
        char base[64], a[64], b1[64], b2[64], a_landed[64];
        char ea[512], eb1[512], eb2[512], old_root[80], new_root[80];
        char want[8192], got[8192], line[16384];
        dlx_isolate("reseal_two");
        ASSERT(rs_rig(&rig, "reseal_two_rig", base));
        ASSERT(rs_checkout(rig.clone, "row-a", base));
        ASSERT(rs_core_commit(rig.clone, "core/a.c", "int a = 2;\n",
                              "row A edits a", true, true, ea, sizeof(ea),
                              a));
        ASSERT(rs_checkout(rig.clone, "row-b", base));
        ASSERT(rs_core_commit(rig.clone, "core/b.c", "int b = 2;\n",
                              "row B edits b", true, true, eb1, sizeof(eb1),
                              b1));
        ASSERT(rs_core_commit(rig.clone, "core/c.c", "int c = 2;\n",
                              "row B edits c", true, true, eb2, sizeof(eb2),
                              b2));
        ASSERT(rs_root_at(rig.clone, b2, old_root));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        ASSERT(dlx_qp_submit(&rig, a, 1));
        ASSERT(dlx_qp_submit(&rig, b2, 2));
        ASSERT(rs_drain(b2, 12));
        ASSERT(rs_outcome_line(a, line, sizeof(line)));
        ASSERT(rs_has(line, "state", "landed"));
        ASSERT(strstr(line, "seal_new_root") == NULL);
        ASSERT(rs_outcome_line(b2, line, sizeof(line)));
        if (!rs_has(line, "state", "landed"))
            printf("[outcome %s] ", line);
        ASSERT(rs_has(line, "state", "landed"));
        ASSERT(rs_main_sealed(rig.clone, new_root));
        ASSERT(strcmp(old_root, new_root) != 0);
        ASSERT(rs_has(line, "seal_old_root", old_root));
        ASSERT(rs_has(line, "seal_new_root", new_root));
        /* The log: main's bytes, then B's two entries verbatim, in order. */
        ASSERT(rs_has(line, "tip", b2));
        (void)snprintf(a_landed, sizeof(a_landed), "%s", "origin/main~2");
        ASSERT(rs_file_at(rig.clone, a_landed, RS_UNSEAL, want,
                          sizeof(want)));
        ASSERT(strstr(want, ea + 1) != NULL);
        ASSERT(strlen(want) + strlen(eb1) + strlen(eb2) < sizeof(want));
        (void)strcat(want, eb1);
        (void)strcat(want, eb2);
        ASSERT(rs_file_at(rig.clone, "origin/main", RS_UNSEAL, got,
                          sizeof(got)));
        ASSERT_STR_EQ(got, want);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A row whose only conflict with a moved main is the seal is not ended by
 * the queued check: the real rebase decides, and re-derives it. */
static int rs_case_precheck_defers(void)
{
    int failures = 0;
    TEST("land: the queued check leaves a seal-only conflict to the real "
         "rebase instead of ending the row") {
        struct dlx_rig rig;
        char base[64], b[64], m1[64];
        struct dlx_call c;
        dlx_isolate("reseal_pc");
        ASSERT(rs_rig(&rig, "reseal_pc_rig", base));
        ASSERT(rs_checkout(rig.clone, "row-a", base));
        ASSERT(dlx_commit(rig.clone, "change.txt", "one\n", rig.tip));
        ASSERT(rs_checkout(rig.clone, "row-b", base));
        ASSERT(rs_core_commit(rig.clone, "core/b.c", "int b = 2;\n",
                              "row B edits b", true, true, NULL, 0, b));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        ASSERT(dlx_qp_submit(&rig, rig.tip, 1));
        ASSERT(dlx_qp_submit(&rig, b, 2));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        /* Someone else's ritual reaches main directly. */
        ASSERT(rs_checkout(rig.clone, "mover", base));
        ASSERT(rs_core_commit(rig.clone, "core/a.c", "int a = 2;\n",
                              "main edits a", true, true, NULL, 0, m1));
        ASSERT(dlx_git(rig.clone, (const char *[]){ "push", "--quiet",
                       "origin", "HEAD:main", NULL }) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        ASSERT(dlx_int(&c, "queued_conflicts") == 0);
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        ASSERT(rs_drain(b, 12));
        char line[16384], root[80];
        ASSERT(rs_outcome_line(b, line, sizeof(line)));
        ASSERT(rs_has(line, "state", "landed"));
        ASSERT(rs_main_sealed(rig.clone, root));
        ASSERT(rs_has(line, "seal_new_root", root));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* One row against a main that ran the ritual on core/a.c: `file` and
 * `ritual` shape the row's own commit. Returns the row's terminal outcome
 * line and leaves origin/main's id in `main_after`. */
static bool rs_single_row(const char *tag, const char *file, bool ritual,
                          bool fresh, char tip[64], char *line, size_t cap,
                          char before[64], char after[64])
{
    struct dlx_rig rig;
    char rig_tag[64], base[64], m1[64];
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    (void)snprintf(rig_tag, sizeof(rig_tag), "%s_rig", tag);
    dlx_isolate(tag);
    if (!rs_rig(&rig, rig_tag, base) ||
        !rs_checkout(rig.clone, "row", base) ||
        !rs_core_commit(rig.clone, file, "int row = 3;\n", "the row's edit",
                        ritual, fresh, NULL, 0, tip) ||
        !rs_checkout(rig.clone, "mover", base) ||
        !rs_core_commit(rig.clone, "core/a.c", "int a = 2;\n",
                        "main edits a", true, true, NULL, 0, m1) ||
        dlx_git(rig.clone, push) != 0 || !dlx_origin_main(&rig, before))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    return dlx_qp_submit(&rig, tip, 1) && rs_drain(tip, 6) &&
           rs_outcome_line(tip, line, cap) && dlx_origin_main(&rig, after);
}

/* Rule 1: the queue never creates an unseal the author did not. A row that
 * re-froze the manifest without an UNSEAL entry conflicts exactly as before. */
static int rs_case_no_ritual(void)
{
    int failures = 0;
    TEST("land: a row that resealed core without an UNSEAL entry still "
         "ends as a seal conflict, nothing re-derived") {
        char tip[64], before[64], after[64], line[16384];
        ASSERT(rs_single_row("reseal_none", "core/b.c", false, true, tip, line,
                             sizeof(line), before, after));
        ASSERT(rs_has(line, "state", "conflict"));
        ASSERT(rs_has(line, "dimension", "rebase"));
        ASSERT(strstr(line, RS_MANIFEST) != NULL);
        ASSERT(strstr(line, "seal_new_root") == NULL);
        ASSERT_STR_EQ(after, before);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Rule 2: a conflict in a sealed source file is never auto-resolved, even
 * when every other conflicted path is a seal file the row re-froze. */
static int rs_case_source_conflict(void)
{
    int failures = 0;
    TEST("land: a ritual row with a real conflict in a core source file "
         "still ends as a conflict naming that file") {
        char tip[64], before[64], after[64], line[16384];
        ASSERT(rs_single_row("reseal_src", "core/a.c", true, true, tip, line,
                             sizeof(line), before, after));
        ASSERT(rs_has(line, "state", "conflict"));
        ASSERT(strstr(line, "core/a.c") != NULL);
        ASSERT(strstr(line, "seal_new_root") == NULL);
        ASSERT_STR_EQ(after, before);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* Rule 1 again: the ritual ran, but the author edited core/c.c after the
 * seal, so the tip's own manifest does not verify. Re-deriving would seal
 * an edit the author never sealed; the conflict stands. */
static int rs_case_stale_seal(void)
{
    int failures = 0;
    TEST("land: a ritual row whose own seal does not verify is not "
         "re-derived; it ends as a seal conflict") {
        char tip[64], before[64], after[64], line[16384];
        ASSERT(rs_single_row("reseal_stale", "core/b.c", true, false, tip,
                             line, sizeof(line), before, after));
        ASSERT(rs_has(line, "state", "conflict"));
        ASSERT(strstr(line, RS_MANIFEST) != NULL);
        ASSERT(strstr(line, "seal_new_root") == NULL);
        ASSERT_STR_EQ(after, before);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* The queued check still ends a seal-only conflict at once when the row's
 * commit did not run the ritual, exactly as before. */
static int rs_case_precheck_no_ritual(void)
{
    int failures = 0;
    TEST("land: the queued check still ends a seal-only conflict of a row "
         "that did not run the ritual") {
        struct dlx_rig rig;
        char base[64], b[64], m1[64], detail[512];
        struct dlx_call c;
        dlx_isolate("reseal_pcn");
        ASSERT(rs_rig(&rig, "reseal_pcn_rig", base));
        ASSERT(rs_checkout(rig.clone, "row-a", base));
        ASSERT(dlx_commit(rig.clone, "change.txt", "one\n", rig.tip));
        ASSERT(rs_checkout(rig.clone, "row-b", base));
        ASSERT(rs_core_commit(rig.clone, "core/b.c", "int b = 2;\n",
                              "row B edits b", false, true, NULL, 0, b));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        ASSERT(dlx_qp_submit(&rig, rig.tip, 1));
        ASSERT(dlx_qp_submit(&rig, b, 2));
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        ASSERT(rs_checkout(rig.clone, "mover", base));
        ASSERT(rs_core_commit(rig.clone, "core/a.c", "int a = 2;\n",
                              "main edits a", true, true, NULL, 0, m1));
        ASSERT(dlx_git(rig.clone, (const char *[]){ "push", "--quiet",
                       "origin", "HEAD:main", NULL }) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        ASSERT(dlx_int(&c, "queued_conflicts") == 1);
        dlx_end(&c);
        ASSERT(dlx_qp_outcome(b, "conflict", detail, sizeof(detail)));
        ASSERT(strstr(detail, "detected while queued") != NULL);
        ASSERT(strstr(detail, RS_MANIFEST) != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A 60-line core/a.c: the first five lines carry `top`, the last ten
 * `bottom`, so two edits of it touch disjoint hunks git merges cleanly. */
static bool rs_long_body(char *out, size_t cap, int top, int bottom)
{
    size_t used = 0;
    for (int i = 0; i < 60; i++) {
        int v = i < 5 ? top : i >= 50 ? bottom : 1;
        int n = snprintf(out + used, cap - used, "int a%02d = %d;\n", i, v);
        if (n <= 0 || (size_t)n >= cap - used)
            return false;
        used += (size_t)n;
    }
    return true;
}

/* MUST 1 shape: main's ritual edits the top of core/a.c; the row edits its
 * bottom, either in its one ritual commit or (`unsealed_first`) in a commit
 * that neither ran the ritual nor resealed, followed by a ritual commit on
 * core/b.c. git merges core/a.c cleanly either way, and only the seal files
 * stop the rebase: the merged core/a.c is a file nobody sealed. */
static bool rs_overlap_row(const char *tag, bool unsealed_first, char tip[64],
                           char *line, size_t cap, char before[64],
                           char after[64])
{
    struct dlx_rig rig;
    char rig_tag[64], base[64], grown[64], c1[64], m1[64], body[2048];
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    (void)snprintf(rig_tag, sizeof(rig_tag), "%s_rig", tag);
    dlx_isolate(tag);
    if (!rs_rig(&rig, rig_tag, base) || !rs_long_body(body, sizeof(body), 1, 1) ||
        !rs_core_commit(rig.clone, "core/a.c", body, "grow a", true, true,
                        NULL, 0, grown) ||
        dlx_git(rig.clone, push) != 0 || !rs_checkout(rig.clone, "row", grown) ||
        !rs_long_body(body, sizeof(body), 1, 2))
        return false;
    if (unsealed_first
            ? !dlx_write_dep(rig.clone, "core/a.c", body) ||
              !dlx_commit_tree(rig.clone, "the row edits a, unsealed", c1) ||
              !rs_core_commit(rig.clone, "core/b.c", "int b = 4;\n",
                              "the row's ritual on b", true, true, NULL, 0, tip)
            : !rs_core_commit(rig.clone, "core/a.c", body, "the row edits a",
                              true, true, NULL, 0, tip))
        return false;
    if (!rs_checkout(rig.clone, "mover", grown) ||
        !rs_long_body(body, sizeof(body), 2, 1) ||
        !rs_core_commit(rig.clone, "core/a.c", body, "main edits a", true, true,
                        NULL, 0, m1) ||
        dlx_git(rig.clone, push) != 0 || !dlx_origin_main(&rig, before))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    return dlx_qp_submit(&rig, tip, 1) && rs_drain(tip, 6) &&
           rs_outcome_line(tip, line, cap) && dlx_origin_main(&rig, after);
}

static int rs_case_same_file_hunks(void)
{
    int failures = 0;
    TEST("land: two ritual rows editing disjoint hunks of one core file are "
         "not re-derived; the row ends as a conflict naming that file") {
        char tip[64], before[64], after[64], line[16384];
        ASSERT(rs_overlap_row("reseal_hunks", false, tip, line, sizeof(line),
                              before, after));
        if (!rs_has(line, "state", "conflict"))
            printf("[outcome %s] ", line);
        ASSERT(rs_has(line, "state", "conflict"));
        ASSERT(strstr(line, "core paths changed on both sides") != NULL);
        ASSERT(strstr(line, "core/a.c") != NULL);
        ASSERT(strstr(line, "seal_new_root") == NULL);
        ASSERT_STR_EQ(after, before);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

static int rs_case_unsealed_then_ritual(void)
{
    int failures = 0;
    TEST("land: a row whose unsealed commit merges cleanly into a core file "
         "main resealed is not re-derived at its later ritual commit") {
        char tip[64], before[64], after[64], line[16384];
        ASSERT(rs_overlap_row("reseal_c1c2", true, tip, line, sizeof(line),
                              before, after));
        if (!rs_has(line, "state", "conflict"))
            printf("[outcome %s] ", line);
        ASSERT(rs_has(line, "state", "conflict"));
        ASSERT(strstr(line, "core paths changed on both sides") != NULL);
        ASSERT(strstr(line, "seal_new_root") == NULL);
        ASSERT_STR_EQ(after, before);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* A step killed mid-reseal leaves a stopped rebase in the landing worktree.
 * The next row's rebase must not inherit it as a conflict. */
static int rs_case_leftover_rebase(void)
{
    int failures = 0;
    TEST("land: a rebase left in the landing worktree is aborted before the "
         "next row rebases, which then lands") {
        struct dlx_rig rig;
        char base[64], a[64], b[64], wt[1400], line[16384], at[2048];
        const char *stop[] = { "-c", "user.name=t", "-c",
                               "user.email=t@example.invalid", "rebase",
                               "--exec", "false", "HEAD~1", NULL };
        const char *where[] = { "rev-parse", "--path-format=absolute",
                                "--git-path", "rebase-merge", NULL };
        dlx_isolate("reseal_left");
        ASSERT(rs_rig(&rig, "reseal_left_rig", base));
        ASSERT(rs_checkout(rig.clone, "row-a", base));
        ASSERT(dlx_commit(rig.clone, "change.txt", "one\n", a));
        ASSERT(rs_checkout(rig.clone, "row-b", base));
        ASSERT(dlx_commit(rig.clone, "b.txt", "two\n", b));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        ASSERT(dlx_qp_submit(&rig, a, 1));
        ASSERT(rs_drain(a, 6));
        ASSERT(rs_outcome_line(a, line, sizeof(line)));
        ASSERT(rs_has(line, "state", "landed"));
        /* What a kill leaves: a rebase stopped with its state directory. */
        dlx_landdir(wt, sizeof(wt));
        ASSERT(strlen(wt) + 4 < sizeof(wt));
        (void)strcat(wt, "/wt");
        ASSERT(dlx_git(wt, stop) != 0);
        ASSERT(dlx_git_out(wt, where, at, sizeof(at)) == 0);
        ASSERT(dlx_file_exists(at));
        ASSERT(dlx_qp_submit(&rig, b, 2));
        ASSERT(rs_drain(b, 6));
        ASSERT(rs_outcome_line(b, line, sizeof(line)));
        if (!rs_has(line, "state", "landed"))
            printf("[outcome %s] ", line);
        ASSERT(rs_has(line, "state", "landed"));
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
    return failures;
}

/* `make core-seal` failing in the landing tree says nothing about the row:
 * the row is requeued as a host-load failure, then lands once it works. */
static int rs_case_tool_fails(void)
{
    int failures = 0;
    TEST("land: a failing make core-seal requeues the row as host load "
         "instead of ending it as a conflict") {
        struct dlx_rig rig;
        char base[64], tip[64], m1[64], line[16384];
        struct dlx_call c;
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
        dlx_isolate("reseal_tool");
        ASSERT(rs_rig(&rig, "reseal_tool_rig", base));
        ASSERT(rs_checkout(rig.clone, "row", base));
        ASSERT(rs_core_commit(rig.clone, "core/b.c", "int b = 5;\n",
                              "the row edits b", true, true, NULL, 0, tip));
        ASSERT(rs_checkout(rig.clone, "mover", base));
        ASSERT(rs_core_commit(rig.clone, "core/a.c", "int a = 2;\n",
                              "main edits a", true, true, NULL, 0, m1));
        ASSERT(dlx_git(rig.clone, push) == 0);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        ASSERT(dlx_qp_submit(&rig, tip, 1));
        setenv("RS_SEAL_FAIL", "1", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        if (strcmp(dlx_str(&c, "state"), "rebased") != 0)
            printf("[state %s] ", dlx_str(&c, "state"));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        dlx_end(&c);
        ASSERT(!rs_outcome_line(tip, line, sizeof(line)));
        unsetenv("RS_SEAL_FAIL");
        ASSERT(rs_drain(tip, 6));
        ASSERT(rs_outcome_line(tip, line, sizeof(line)));
        ASSERT(rs_has(line, "state", "landed"));
        ASSERT(strstr(line, "seal_new_root") != NULL);
        dlx_restore();
        PASS();
    }
_test_next:;
    unsetenv("RS_SEAL_FAIL");
    dlx_restore();
    return failures;
}

/* A train member stacked on a ritual head re-derives its seal in the
 * stacking rebase; its outcome carries the ROOTs like a single row's. */
static int rs_case_train_member(void)
{
    int failures = 0;
    TEST("land: a ritual row stacked in a train on a ritual head records "
         "its old and new ROOT") {
        struct dlx_rig rig;
        char base[64], a[64], b[64], old_root[80], new_root[80];
        char line[16384];
        dlx_isolate("reseal_train");
        ASSERT(rs_rig(&rig, "reseal_train_rig", base));
        ASSERT(rs_checkout(rig.clone, "row-a", base));
        ASSERT(rs_core_commit(rig.clone, "core/a.c", "int a = 6;\n",
                              "row A edits a", true, true, NULL, 0, a));
        ASSERT(rs_checkout(rig.clone, "row-b", base));
        ASSERT(rs_core_commit(rig.clone, "core/b.c", "int b = 6;\n",
                              "row B edits b", true, true, NULL, 0, b));
        ASSERT(rs_root_at(rig.clone, b, old_root));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        setenv("ZCL_LAND_TRAIN_WIDTH", "2", 1);
        ASSERT(dlx_qp_submit(&rig, a, 1));
        ASSERT(dlx_qp_submit(&rig, b, 2));
        ASSERT(rs_drain(b, 8));
        ASSERT(rs_outcome_line(b, line, sizeof(line)));
        if (!rs_has(line, "state", "landed") || !strstr(line, "train_commit"))
            printf("[outcome %s] ", line);
        ASSERT(rs_has(line, "state", "landed"));
        ASSERT(strstr(line, "train_commit") != NULL);
        ASSERT(rs_main_sealed(rig.clone, new_root));
        ASSERT(rs_has(line, "seal_old_root", old_root));
        ASSERT(rs_has(line, "seal_new_root", new_root));
        dlx_restore();
        PASS();
    }
_test_next:;
    unsetenv("ZCL_LAND_TRAIN_WIDTH");
    dlx_restore();
    return failures;
}

int dlx_case_core_reseal(void)
{
    int failures = 0;
    failures += rs_case_two_rituals();
    failures += rs_case_precheck_defers();
    failures += rs_case_no_ritual();
    failures += rs_case_source_conflict();
    failures += rs_case_stale_seal();
    failures += rs_case_precheck_no_ritual();
    failures += rs_case_same_file_hunks();
    failures += rs_case_unsealed_then_ritual();
    failures += rs_case_leftover_rebase();
    failures += rs_case_tool_fails();
    failures += rs_case_train_member();
    return failures;
}

#endif /* !defined(_WIN32) */
