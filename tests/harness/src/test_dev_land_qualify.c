/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * dev.land acceptance tests: qualify make caps, groups and verdicts, stubs and priority.
 * Part of the test_dev_land group; shared fixtures live in
 * test/test_dev_land_common.h. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "test/test_dev_land_common.h"


int test_dev_land_prove_drive2(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: drive prove stops at the first proof failure with the gate and log") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char before[64], main_tip[64];
        dlx_isolate("prove_drive_fail");
        ASSERT(dlx_prove_rig(&p, "prove_drive_fail_rig", DLX_PRODUCER_BROKEN));
        ASSERT(dlx_origin_main(&p.rig, before));
        ASSERT(dlx_prove_drive(&c, 2) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_REFUSED");
        ASSERT(strstr(dlx_str(&c, "reason"), "PROOF_RECEIPT_MISSING") != NULL);
        ASSERT(strstr(dlx_str(&c, "reason"), "gate=proof_receipt") != NULL);
        ASSERT(strstr(dlx_str(&c, "reason"), "prove-") != NULL);
        const struct json_value *rows = dlx_arr(&c, "rows");
        ASSERT(rows != NULL && rows->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&rows->children[0], "outcome")),
                      "refused");
        dlx_end(&c);
        ASSERT_EQ((int64_t)dlx_runs(p.count), 1);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, before);
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_prove_drive3(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: drive prove refuses while another drive holds the lander lock") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char land[1200], lock[1400], before[64], main_tip[64];
        dlx_isolate("prove_drive_busy");
        ASSERT(dlx_prove_rig(&p, "prove_drive_busy_rig", DLX_PRODUCER_OK));
        dlx_landdir(land, sizeof(land));
        (void)snprintf(lock, sizeof(lock), "%s/drive.lock", land);
        int fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        ASSERT(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0);
        ASSERT(dlx_origin_main(&p.rig, before));
        ASSERT(dlx_prove_drive(&c, 1) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_BUSY");
        ASSERT(c.reply.error.retryable);
        dlx_end(&c);
        ASSERT_EQ((int64_t)dlx_runs(p.count), 0);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, before);
        ASSERT(flock(fd, LOCK_UN) == 0 && close(fd) == 0);
        ASSERT(dlx_prove_drive(&c, 1) && dlx_ok(&c));
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_prove_drive4(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: an interrupted prove drive resumes from the receipt without rebuilding") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char queue[16384], local[41], base[41], dir[1800], receipt[2000];
        char main_tip[64], before[64];
        size_t len = 0;
        const char *at;
        dlx_isolate("prove_drive_resume");
        ASSERT(dlx_prove_rig(&p, "prove_drive_resume_rig", DLX_PRODUCER_QUIET));
        ASSERT(dlx_origin_main(&p.rig, before));
        /* The first drive dies (here: refuses) with row 1 in flight. */
        ASSERT(dlx_prove_drive(&c, 1) && !dlx_ok(&c));
        dlx_end(&c);
        ASSERT_EQ((int64_t)dlx_runs(p.count), 1);
        ASSERT(dlx_queue_bytes(queue, sizeof(queue), &len));
        at = strstr(queue, "\"local\":\"");
        ASSERT(at != NULL);
        memcpy(local, at + 9, 40);
        local[40] = '\0';
        at = strstr(queue, "\"base\":\"");
        ASSERT(at != NULL);
        memcpy(base, at + 8, 40);
        base[40] = '\0';
        /* The killed drive's proof had finished: its receipt is on disk. */
        dlx_landdir(dir, sizeof(dir));
        (void)snprintf(dir + strlen(dir), sizeof(dir) - strlen(dir),
                       "/wt/.cache/zcl-dev-proof/receipts");
        ASSERT(dlx_mkdir_p(dir));
        (void)snprintf(receipt, sizeof(receipt), "%s/%s-%s.receipt", dir,
                       local, base);
        ASSERT(dlx_write(receipt, "receipt\n"));
        /* The make that would rebuild is gone: resuming must not need it. */
        setenv("ZCL_LAND_MAKE", "/nonexistent/make", 1);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, before);
        ASSERT(dlx_prove_drive(&c, 1) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "rows_landed"), 1);
        const struct json_value *rows = dlx_arr(&c, "rows");
        ASSERT(rows != NULL && rows->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&rows->children[0], "proof")),
                      "receipt_present");
        dlx_end(&c);
        ASSERT_EQ((int64_t)dlx_runs(p.count), 1);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, p.rig.tip);
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

int test_dev_land_prove_drive5(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a prove drive never publishes a pair whose proof left no receipt") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char before[64], main_tip[64];
        dlx_isolate("prove_drive_noreceipt");
        ASSERT(dlx_prove_rig(&p, "prove_drive_noreceipt_rig",
                             DLX_PRODUCER_QUIET));
        ASSERT(dlx_origin_main(&p.rig, before));
        /* The producer exits 0 and writes nothing. */
        ASSERT(dlx_prove_drive(&c, 2) && !dlx_ok(&c));
        ASSERT(strstr(dlx_str(&c, "reason"), "PROOF_RECEIPT_MISSING") != NULL);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, before);
        PASS();
    }
#endif
_test_next:;
    dlx_restore();
    return failures;
}

int test_dev_land_prove_drive6(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: a plain drive refuses while another drive holds the lander lock") {
        struct dlx_prove_rig p;
        struct dlx_call c;
        char land[1200], lock[1400], before[64], main_tip[64];
        dlx_isolate("plain_drive_busy");
        ASSERT(dlx_prove_rig(&p, "plain_drive_busy_rig", DLX_PRODUCER_OK));
        dlx_landdir(land, sizeof(land));
        (void)snprintf(lock, sizeof(lock), "%s/drive.lock", land);
        int fd = open(lock, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
        ASSERT(fd >= 0 && flock(fd, LOCK_EX | LOCK_NB) == 0);
        ASSERT(dlx_origin_main(&p.rig, before));
        dlx_begin(&c, "drive");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_BUSY");
        dlx_end(&c);
        dlx_begin(&c, "drive");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "DRIVE_BUSY");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&p.rig, main_tip));
        ASSERT_STR_EQ(main_tip, before);
        ASSERT(flock(fd, LOCK_UN) == 0 && close(fd) == 0);
        dlx_begin(&c, "drive");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        PASS();
    }
#endif
_test_next:;
    dlx_restore();
    return failures;
}

/* ── submit --qualify: the pre-submit gates ────────────────────────────── */

/* A stand-in worktree Makefile: every goal the gates run, steered by QFX
 * (the failure to play) and QFAIL (the group that reports FAIL). */
static const char dlx_qualify_makefile[] =
    "T_FAST_EXACT_ARGS := fixture-default\n"
    ".PHONY: docs-capability-inventory dev-bin install-hooks lint-ready lint "
    "t-fast-exact\n"
    "docs-capability-inventory dev-bin install-hooks lint-ready:\n"
    "\t@printf '%s|%s|%s\\n' '$@' '$(filter -j%,$(MAKEFLAGS))' "
    "'$(ONLY)' >> qualify-jobs.txt\n"
    "\t@printf '%s\\n' '$(T_FAST_EXACT_ARGS)' > qualify-default-args.txt\n"
    "ifneq ($(QFX),missing-complexity)\n"
    ".PHONY: check-cyclomatic-complexity\n"
    "check-cyclomatic-complexity:\n"
    "\t@printf '%s|%s|%s\\n' '$@' '$(filter -j%,$(MAKEFLAGS))' "
    "'$(ONLY)' >> qualify-jobs.txt\n"
    "\t@echo complexity >> build/scratch/qualify-stages\n"
    "\t@if [ \"$(QFX)\" = complexity ]; then echo \"FAIL complexity\"; exit 1; fi\n"
    "\t@if [ \"$(QFX)\" = complexity-tree ]; then echo changed >> tracked.txt; fi\n"
    "endif\n"
    "lint:\n"
    "\t@printf '%s|%s|%s\\n' '$@' '$(filter -j%,$(MAKEFLAGS))' "
    "'$(ONLY)' >> qualify-jobs.txt\n"
    "\t@echo lint >> build/scratch/qualify-stages\n"
    "\t@if [ \"$(QFX)\" = lint ]; then echo \"FAIL gate-x\"; exit 1; fi\n"
    "\t@if [ \"$(QFX)\" = fold ]; then echo regenerated >> "
    "docs/dev/CODEBASE_MAP.md; fi\n"
    "\t@if [ \"$(QFX)\" = tree ]; then echo changed >> tracked.txt; fi\n"
    "\t@echo \"== LINT: all checks passed ==\"\n"
    "t-fast-exact:\n"
    "\t@printf 'ONLY=%s\\nARGS=%s\\n' '$(ONLY)' '$(T_FAST_EXACT_ARGS)' > qualify-args.txt\n"
    "\t@printf '%s\\n' '$(ONLY)' > qualify-only.txt\n"
    "\t@printf '%s|%s|%s\\n' '$@' '$(filter -j%,$(MAKEFLAGS))' "
    "'$(ONLY)' >> qualify-jobs.txt\n"
    "\t@echo tests >> build/scratch/qualify-stages\n"
    "\t@for g in `echo \"$(ONLY)\" | tr , ' '`; do \\\n"
    "\t  [ \"$$g\" = \"test_$(QCRASH)\" ] && continue; \\\n"
    "\t  v=PASS; [ \"$$g\" = \"test_$(QFAIL)\" ] && v=FAIL; \\\n"
    "\t  echo \"==================== $$g ($$v, 1s) "
    "====================\"; \\\n"
    "\t  [ \"$(QFX)\" = parse ] && echo \"PARSE FAIL at x.c:1 expected\"; \\\n"
    "\t  [ \"$(QFX)\" = linestart ] && echo \"FAIL at y.c:3 (bad)\"; \\\n"
    "\t  [ \"$$g\" = \"test_$(QFAIL)\" ] && echo \"FAIL at x.c:2 (bad)\"; \\\n"
    "\t  true; done\n"
    "\t@[ -n \"$(QFAIL)\" ] && { echo \"SOME TESTS FAILED\"; exit 2; }; "
    "echo \"ALL TESTS PASSED - fixture\"\n";

/* Fixture test files the lane changes: each routes to its own group. */
#define DLX_Q_LEAF_SMOKE 1U
#define DLX_Q_LAND_WINDOW 2U
#define DLX_Q_MAP 4U

static bool dlx_qualify_rig(struct dlx_rig *rig, const char *tag,
                            const char *mode, const char *fail_group,
                            unsigned files)
{
    char path[1300], head[64];
    if (!dlx_rig_make(rig, tag))
        return false;
    (void)snprintf(path, sizeof(path), "%s/.git/info/exclude", rig->clone);
    if (!dlx_write(path, "/Makefile\n"))
        return false;
    (void)snprintf(path, sizeof(path), "%s/Makefile", rig->clone);
    if (!dlx_write(path, dlx_qualify_makefile) ||
        ((files & DLX_Q_MAP) &&
         !dlx_write_dep(rig->clone, "docs/dev/CODEBASE_MAP.md", "map\n")) ||
        !dlx_write_dep(rig->clone, "tracked.txt", "tracked\n") ||
        ((files & DLX_Q_LEAF_SMOKE) &&
         !dlx_write_dep(rig->clone, "tests/harness/src/test_leaf_smoke.c",
                        "int leaf;\n")) ||
        ((files & DLX_Q_LAND_WINDOW) &&
         !dlx_write_dep(rig->clone, "tests/harness/src/test_dev_land_window.c",
                        "int window;\n")) ||
        !dlx_commit_tree(rig->clone, "qualify fixture", head))
        return false;
    setenv("GIT_AUTHOR_NAME", "land", 1);
    setenv("GIT_AUTHOR_EMAIL", "land@z23.invalid", 1);
    setenv("GIT_COMMITTER_NAME", "land", 1);
    setenv("GIT_COMMITTER_EMAIL", "land@z23.invalid", 1);
    setenv("QFX", mode, 1);
    setenv("QFAIL", fail_group, 1);
    setenv("QCRASH", "", 1);
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    return true;
}

static void dlx_qualify_restore(void)
{
    zcl_dev_land_qualify_test_limits(NULL, 0);
    unsetenv("QFX");
    unsetenv("QFAIL");
    unsetenv("QCRASH");
    unsetenv("GIT_AUTHOR_NAME");
    unsetenv("GIT_AUTHOR_EMAIL");
    unsetenv("GIT_COMMITTER_NAME");
    unsetenv("GIT_COMMITTER_EMAIL");
    dlx_restore();
}

static bool dlx_qualify_submit(struct dlx_call *c, const struct dlx_rig *rig)
{
    dlx_begin(c, "submit");
    (void)json_push_kv_str(&c->input, "worktree", rig->clone);
    (void)json_push_kv_bool(&c->input, "qualify", true);
    return dlx_run(c);
}

static bool dlx_qualify_refused(const struct dlx_call *c, const char *code)
{
    return c->reply.status == ZCL_COMMAND_STATUS_FAILED &&
           strcmp(dlx_err_code(c), code) == 0 && !dlx_queue_has_one();
}

static bool dlx_qualify_make_field(FILE *f, const char *text, int delimiter)
{
    for (const unsigned char *p = (const unsigned char *)text; *p; p++) {
        if (fgetc(f) != *p)
            return false;
    }
    return fgetc(f) == delimiter;
}

/* The real Make recipes record normalized job flags after argv processing. */
static bool dlx_qualify_make_trace(const struct dlx_rig *rig,
                                  const char *jobs, const char *prepare,
                                  const char *inherited_only)
{
    static const char *const goals[] = { "docs-capability-inventory", "dev-bin",
        "install-hooks", "lint-ready", "check-cyclomatic-complexity",
        "lint", "t-fast-exact" };
    char path[1400];
    if (snprintf(path, sizeof(path), "%s/qualify-jobs.txt", rig->clone) >=
        (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    bool ok = true;
    for (size_t i = 0; ok && i < sizeof(goals) / sizeof(goals[0]); i++) {
        ok = dlx_qualify_make_field(f, goals[i], '|') &&
             dlx_qualify_make_field(f, i == 1 ? prepare : jobs, '|') &&
             dlx_qualify_make_field(f,
                 i == 6 ? "test_leaf_smoke" : inherited_only, '\n');
    }
    ok = ok && fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0) ok = false;
    return ok;
}

static void dlx_qualify_env_restore(const char *name, char *saved, bool present)
{
    if (saved) (void)setenv(name, saved, 1);
    else if (!present) (void)unsetenv(name);
    free(saved);
}

static int dlx_qualify_make_cap_case(const char *cap, bool valid,
                                      const char *tag)
{
    int failures = 0;
    const char *old_cap = getenv("ZCL_BUILD_MAX_JOBS");
    const char *old_flags = getenv("MAKEFLAGS");
    const char *old_only = getenv("ONLY");
    bool had_cap = old_cap != NULL, had_flags = old_flags != NULL;
    char *saved_cap = old_cap ? strdup(old_cap) : NULL;
    char *saved_flags = old_flags ? strdup(old_flags) : NULL;
    char *saved_only = old_only ? strdup(old_only) : NULL;
    struct dlx_call c;
    bool called = false;
    TEST("land: explicit Make cap controls every phase before queue admission") {
        struct dlx_rig rig;
        char jobs[16], path[1400];
        struct stat st;
        ASSERT(!old_cap || saved_cap);
        ASSERT(!old_flags || saved_flags);
        ASSERT(!old_only || saved_only);
        ASSERT(setenv("MAKEFLAGS", "-j2", 1) == 0);
        ASSERT(cap ? setenv("ZCL_BUILD_MAX_JOBS", cap, 1) == 0 :
                     unsetenv("ZCL_BUILD_MAX_JOBS") == 0);
        ASSERT(!valid || platform_build_jobs_arg(jobs));
        dlx_isolate(tag);
        ASSERT(dlx_qualify_rig(&rig, tag, "", "",
                               DLX_Q_LEAF_SMOKE));
        called = true;
        ASSERT(dlx_qualify_submit(&c, &rig));
        if (valid) {
            ASSERT(dlx_ok(&c));
            ASSERT(dlx_queue_has_one());
            ASSERT(dlx_qualify_make_trace(&rig, cap ? jobs : "-j2", jobs,
                saved_only ? saved_only : ""));
        } else {
            ASSERT(dlx_qualify_refused(&c, "QUALIFY_STEP_FAILED"));
            ASSERT_STR_EQ(dlx_str(&c, "step"), "ZCL_BUILD_MAX_JOBS");
            ASSERT(snprintf(path, sizeof(path), "%s/qualify-jobs.txt", rig.clone)
                   < (int)sizeof(path));
            ASSERT(stat(path, &st) != 0 && errno == ENOENT);
        }
        PASS();
    }
_test_next:;
    if (called) dlx_end(&c);
    dlx_qualify_restore();
    dlx_qualify_env_restore("ZCL_BUILD_MAX_JOBS", saved_cap, had_cap);
    dlx_qualify_env_restore("MAKEFLAGS", saved_flags, had_flags);
    free(saved_only);
    return failures;
}

static int dlx_qualify_make_long_only(void)
{
    static const char selection[] =
        "test_binary_ab_fallback,test_boot_shutdown_marker,test_code_inventory,"
        "test_command_handler_snapshot,test_command_registry_catalog,"
        "test_dev_land,test_dev_platform,test_hotswap_loader,test_hotswap_module,"
        "test_hotswap_module_v2,test_hotswap_simnet,test_make_lint_gates,"
        "test_native_api_contract,test_self_backtrace,test_test_group_selector,"
        "test_dev_land_window";
    int failures = 0;
    const char *old_only = getenv("ONLY");
    bool present = old_only != NULL, ready = false;
    char *saved = old_only ? strdup(old_only) : NULL;
    TEST("land: Make cap trace retains a long inherited exact selection") {
        ASSERT(!present || saved);
        ASSERT(strlen(selection) > 335);
        ASSERT(setenv("ONLY", selection, 1) == 0);
        ready = true;
        PASS();
    }
_test_next:;
    if (ready)
        failures += dlx_qualify_make_cap_case("4", true,
                                             "qualify_make_cap_long_only");
    dlx_qualify_env_restore("ONLY", saved, present);
    return failures;
}

int test_dev_land_qualify_make_caps(void)
{
    return dlx_qualify_make_cap_case(NULL, true, "qualify_make_cap_unset") +
           dlx_qualify_make_cap_case("4", true, "qualify_make_cap_four") +
           dlx_qualify_make_cap_case("2", true, "qualify_make_cap_two") +
           dlx_qualify_make_cap_case("", false, "qualify_make_cap_empty") +
           dlx_qualify_make_cap_case("0", false, "qualify_make_cap_zero") +
           dlx_qualify_make_cap_case("4x", false, "qualify_make_cap_malformed") +
           dlx_qualify_make_cap_case("4294967296", false, "qualify_make_cap_overflow") +
           dlx_qualify_make_long_only();
}

/* These are real registry aliases, including a group with a test_ basename. */
static void dlx_route_canonical_aliases(const char *path,
                                       struct agent_impact_acc *acc)
{
    (void)path;
    agent_impact_add_group_list(acc,
        "test_group_selector test_test_group_selector test_fdt");
}

static void dlx_route_unregistered(const char *path,
                                    struct agent_impact_acc *acc)
{
    (void)path;
    agent_impact_add_group(acc, "qualifier_unregistered_fixture_group");
}

static bool dlx_qualify_only_is(const struct dlx_rig *rig, const char *expected)
{
    char path[1400], line[256];
    if (snprintf(path, sizeof(path), "%s/qualify-only.txt", rig->clone) >=
        (int)sizeof(path))
        return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    bool ok = fgets(line, sizeof(line), f) && strcmp(line, expected) == 0 &&
              fgetc(f) == EOF && !ferror(f);
    if (fclose(f) != 0) ok = false;
    return ok;
}

int test_dev_land_qualify_canonical_aliases(void)
{
    int failures = 0;
    struct dlx_call c;
    bool called = false;
    TEST("land: qualify deduplicates exact registry aliases before verdicts") {
        struct dlx_rig rig;
        const struct json_value *groups;
        dlx_isolate("qualify_aliases");
        ASSERT(dlx_qualify_rig(&rig, "qualify_aliases", "", "",
                               DLX_Q_LEAF_SMOKE));
        zcl_dev_land_qualify_test_limits(dlx_route_canonical_aliases, 0);
        called = true;
        ASSERT(dlx_qualify_submit(&c, &rig) && dlx_ok(&c));
        groups = dlx_arr(&c, "groups");
        ASSERT(groups != NULL && groups->num_children == 2);
        ASSERT(dlx_qualify_only_is(&rig,
            "test_test_fdt,test_test_group_selector\n"));
        ASSERT(dlx_queue_has_one());
        PASS();
    }
_test_next:;
    if (called) dlx_end(&c);
    dlx_qualify_restore();
    return failures;
}

int test_dev_land_qualify_unregistered_group(void)
{
    int failures = 0;
    struct dlx_call c;
    bool called = false;
    TEST("land: qualify refuses an unresolved registry group before tests") {
        struct dlx_rig rig;
        char path[1400];
        dlx_isolate("qualify_unregistered");
        ASSERT(dlx_qualify_rig(&rig, "qualify_unregistered", "", "",
                               DLX_Q_LEAF_SMOKE));
        zcl_dev_land_qualify_test_limits(dlx_route_unregistered, 0);
        called = true;
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_GROUP_SELECTION"));
        ASSERT(snprintf(path, sizeof(path), "%s/qualify-only.txt", rig.clone)
               < (int)sizeof(path));
        ASSERT(!dlx_file_exists(path));
        PASS();
    }
_test_next:;
    if (called) dlx_end(&c);
    dlx_qualify_restore();
    return failures;
}

static bool dlx_qualify_same_tail(FILE *actual, FILE *baseline)
{
    int want;
    while ((want = fgetc(baseline)) != EOF)
        if (fgetc(actual) != want) return false;
    return fgetc(actual) == EOF && !ferror(actual) && !ferror(baseline);
}

static bool dlx_qualify_args_tail(FILE *f, const struct dlx_rig *rig,
                                  const char *jobs)
{
    if (jobs) {
        const char *inherited = getenv("T_FAST_EXACT_ARGS");
        if (inherited && inherited[0] &&
            !dlx_qualify_make_field(f, inherited, ' ')) return false;
        return dlx_qualify_make_field(f, "--jobs", '=') &&
            dlx_qualify_make_field(f, jobs + 2, '\n') &&
            fgetc(f) == EOF && !ferror(f);
    }
    char path[1400];
    if (snprintf(path, sizeof(path), "%s/qualify-default-args.txt", rig->clone)
        >= (int)sizeof(path)) return false;
    FILE *baseline = fopen(path, "r");
    if (!baseline) return false;
    bool ok = dlx_qualify_same_tail(f, baseline);
    if (fclose(baseline) != 0) ok = false;
    return ok;
}

static bool dlx_qualify_job_args(const struct dlx_rig *rig, const char *jobs)
{
    char path[1400];
    if (snprintf(path, sizeof(path), "%s/qualify-args.txt", rig->clone)
        >= (int)sizeof(path)) return false;
    FILE *f = fopen(path, "r");
    if (!f) return false;
    bool ok = dlx_qualify_make_field(f, "ONLY=test_leaf_smoke", '\n') &&
        dlx_qualify_make_field(f, "ARGS", '=') &&
        dlx_qualify_args_tail(f, rig, jobs);
    if (fclose(f) != 0) ok = false;
    return ok;
}

static int dlx_qualify_job_cap_case(const char *cap, const char *refusal_step)
{
    int failures = 0;
    char saved[4096] = {0};
    const char *prior = getenv("ZCL_BUILD_MAX_JOBS");
    bool had = prior != NULL;
    bool saved_ok = !had || strlen(prior) < sizeof(saved);
    if (saved_ok && had) (void)snprintf(saved, sizeof(saved), "%s", prior);
    struct dlx_call c;
    bool called = false;
    TEST("land: selected tests preserve the explicit job cap and uncapped default") {
        struct dlx_rig rig;
        char jobs[16];
        ASSERT(saved_ok);
        ASSERT(cap ? setenv("ZCL_BUILD_MAX_JOBS", cap, 1) == 0 :
                     unsetenv("ZCL_BUILD_MAX_JOBS") == 0);
        bool valid = !refusal_step;
        ASSERT(!valid || !cap || platform_build_jobs_arg(jobs));
        dlx_isolate("qualify_job_cap");
        ASSERT(dlx_qualify_rig(&rig, "qualify_job_cap", "", "", DLX_Q_LEAF_SMOKE));
        called = true;
        ASSERT(dlx_qualify_submit(&c, &rig));
        if (valid) {
            ASSERT(dlx_ok(&c));
            ASSERT(dlx_qualify_job_args(&rig, cap ? jobs : NULL));
            ASSERT(dlx_queue_has_one());
        } else {
            ASSERT(dlx_qualify_refused(&c, "QUALIFY_STEP_FAILED"));
            ASSERT_STR_EQ(dlx_str(&c, "step"), refusal_step);
        }
        PASS();
    }
_test_next:;
    if (called) dlx_end(&c);
    dlx_qualify_restore();
    if (saved_ok) {
        if (had) (void)setenv("ZCL_BUILD_MAX_JOBS", saved, 1);
        else (void)unsetenv("ZCL_BUILD_MAX_JOBS");
    }
    return failures;
}

static int dlx_qualify_job_args_size(bool overflow)
{
    int failures = 0;
    char inherited[4096];
    const char *prior = getenv("T_FAST_EXACT_ARGS");
    bool had = prior != NULL;
    char *saved = prior ? strdup(prior) : NULL;
    TEST("land: selected test arguments preserve long valid input and refuse overflow") {
        ASSERT(!had || saved);
        size_t len = overflow ? sizeof(inherited) - 1 : 3900;
        memset(inherited, ' ', len);
        memcpy(inherited, "--no-cache --jobs=28", strlen("--no-cache --jobs=28"));
        inherited[len] = '\0';
        ASSERT(setenv("T_FAST_EXACT_ARGS", inherited, 1) == 0);
        failures += dlx_qualify_job_cap_case("4", overflow ? "T_FAST_EXACT_ARGS" : NULL);
        PASS();
    }
_test_next:;
    dlx_qualify_env_restore("T_FAST_EXACT_ARGS", saved, had);
    return failures;
}

int test_dev_land_qualify_job_caps(void)
{
    return dlx_qualify_job_cap_case("4", NULL) +
           dlx_qualify_job_cap_case("2", NULL) +
           dlx_qualify_job_cap_case(NULL, NULL) +
           dlx_qualify_job_cap_case("0", "ZCL_BUILD_MAX_JOBS") +
           dlx_qualify_job_cap_case("bad", "ZCL_BUILD_MAX_JOBS") +
           dlx_qualify_job_cap_case("4294967296", "ZCL_BUILD_MAX_JOBS") +
           dlx_qualify_job_cap_case("", "ZCL_BUILD_MAX_JOBS") +
           dlx_qualify_job_args_size(false) +
           dlx_qualify_job_args_size(true);
}

int test_dev_land_qualify_passes(void)
{
    int failures = 0;
    TEST("land: submit --qualify queues the tip exactly as committed") {
        struct dlx_rig rig;
        struct dlx_call c;
        char head[64], path[1300], stages[128] = {0};
        const char *rev[] = { "rev-parse", "HEAD", NULL };
        dlx_isolate("qualify_passes");
        ASSERT(dlx_qualify_rig(&rig, "qualify_passes", "", "",
                               DLX_Q_LEAF_SMOKE | DLX_Q_MAP));
        ASSERT(dlx_git_out(rig.clone, rev, head, sizeof(head)) == 0);
        ASSERT(dlx_qualify_submit(&c, &rig) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "queued");
        ASSERT_STR_EQ(dlx_str(&c, "tip"), head);
        ASSERT(dlx_queue_has_one());
        (void)snprintf(path, sizeof(path), "%s/build/scratch/qualify-stages", rig.clone);
        ASSERT(dlx_slurp(path, stages, sizeof(stages) - 1, NULL));
        ASSERT_STR_EQ(stages, "complexity\nlint\ntests\n");
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

/* A gate that rewrites a generated document (lint-ready refreshing a stale
 * block) used to be folded into the tip by a signed amend. Now the tree it
 * leaves is refused, the files and the make target are named, the tip is
 * untouched and nothing is queued. */
int test_dev_land_qualify_stale_doc_refused(void)
{
    int failures = 0;
    TEST("land: submit --qualify refuses a stale generated document, naming "
         "the make target, and never amends the tip") {
        struct dlx_rig rig;
        struct dlx_call c;
        char head[64], after[64];
        const char *rev[] = { "rev-parse", "HEAD", NULL };
        dlx_isolate("qualify_stale");
        ASSERT(dlx_qualify_rig(&rig, "qualify_stale", "fold", "",
                               DLX_Q_LEAF_SMOKE | DLX_Q_MAP));
        ASSERT(dlx_git_out(rig.clone, rev, head, sizeof(head)) == 0);
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_TREE_CHANGED"));
        ASSERT(strstr(dlx_str(&c, "paths"), "docs/dev/CODEBASE_MAP.md") !=
               NULL);
        ASSERT(strstr(dlx_str(&c, "detail"), "`make fix-doc-counts`") !=
               NULL);
        dlx_end(&c);
        ASSERT(dlx_git_out(rig.clone, rev, after, sizeof(after)) == 0);
        ASSERT_STR_EQ(after, head);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

int test_dev_land_qualify_complexity(void)
{
    int failures = 0;
    TEST("land: complexity refuses early, missing targets refuse, and source "
         "mutation cannot queue") {
        const char *modes[] = { "complexity", "missing-complexity", "complexity-tree" };
        for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
            struct dlx_rig rig;
            struct dlx_call c;
            char path[1300], stages[128] = {0};
            dlx_isolate(modes[i]);
            ASSERT(dlx_qualify_rig(&rig, modes[i], modes[i], "", DLX_Q_LEAF_SMOKE));
            ASSERT(dlx_qualify_submit(&c, &rig));
            ASSERT(dlx_qualify_refused(&c, i == 2 ? "QUALIFY_TREE_CHANGED"
                                                : "QUALIFY_STEP_FAILED"));
            (void)snprintf(path, sizeof(path), "%s/build/scratch/qualify-stages", rig.clone);
            if (i == 1) {
                ASSERT(!dlx_file_exists(path));
            } else {
                ASSERT(dlx_slurp(path, stages, sizeof(stages) - 1, NULL));
                ASSERT_STR_EQ(stages, i == 0 ? "complexity\n"
                                             : "complexity\nlint\ntests\n");
            }
            if (i != 2) {
                ASSERT(strstr(dlx_str(&c, "log"), "qualify-complexity.log"));
                ASSERT(dlx_file_exists(dlx_str(&c, "log")));
            }
            dlx_end(&c);
        }
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

int test_dev_land_qualify_verdict_rule(void)
{
    int failures = 0;
    TEST("land: qualify counts only a line that begins with FAIL at") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("qualify_parse");
        ASSERT(dlx_qualify_rig(&rig, "qualify_parse", "parse", "", DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_qualify_submit(&c, &rig) && dlx_ok(&c));
        dlx_end(&c);
        setenv("QFX", "linestart", 1);
        dlx_isolate("qualify_linestart");
        ASSERT(dlx_qualify_rig(&rig, "qualify_linestart", "linestart", "", DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_GROUP_FAILED"));
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

int test_dev_land_qualify_refusals(void)
{
    int failures = 0;
    TEST("land: qualify refuses lint, group, tree and signature failures") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("qualify_lint");
        ASSERT(dlx_qualify_rig(&rig, "qualify_lint", "lint", "", DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_LINT_FAILED"));
        ASSERT_STR_EQ(dlx_str(&c, "refusal"), "lint_failed");
        ASSERT(dlx_file_exists(dlx_str(&c, "log")));
        dlx_end(&c);
        dlx_isolate("qualify_group");
        ASSERT(dlx_qualify_rig(&rig, "qualify_group", "", "leaf_smoke", DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_GROUP_FAILED"));
        ASSERT_STR_EQ(dlx_str(&c, "group"), "test_leaf_smoke");
        ASSERT(strstr(dlx_str(&c, "log"), "qualify-group-test_leaf_smoke.log"));
        ASSERT(dlx_file_exists(dlx_str(&c, "log")));
        dlx_end(&c);
        dlx_isolate("qualify_tree");
        ASSERT(dlx_qualify_rig(&rig, "qualify_tree", "tree", "", DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_TREE_CHANGED"));
        ASSERT(strstr(dlx_str(&c, "paths"), "tracked.txt") != NULL);
        dlx_end(&c);
        dlx_isolate("qualify_unsigned");
        ASSERT(dlx_qualify_rig(&rig, "qualify_unsigned", "", "", DLX_Q_LEAF_SMOKE));
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_UNSIGNED_TIP"));
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

int test_dev_land_qualify_dirty_tree(void)
{
    int failures = 0;
    TEST("land: qualify refuses a worktree with uncommitted tracked changes") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("qualify_dirty");
        ASSERT(dlx_qualify_rig(&rig, "qualify_dirty", "", "", DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_write_dep(rig.clone, "tracked.txt", "edited\n"));
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_DIRTY_TREE"));
        ASSERT(strstr(dlx_str(&c, "paths"), "tracked.txt") != NULL);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

/* A second clone of the origin that lands `file` on main, so the lane's
 * clone is behind (or in conflict with) origin/main. */
static bool dlx_origin_advances(const struct dlx_rig *rig, const char *file,
                                const char *body)
{
    char other[700], moved[64];
    const char *clone[] = { "clone", "--quiet", rig->bare, other, NULL };
    const char *push[] = { "push", "--quiet", "origin", "HEAD:main", NULL };
    (void)snprintf(other, sizeof(other), "%s_other", rig->clone);
    return dlx_git(NULL, clone) == 0 &&
           dlx_commit(other, file, body, moved) &&
           dlx_git(other, push) == 0;
}

static bool dlx_clone_clean(const struct dlx_rig *rig)
{
    const char *status[] = { "status", "--porcelain", "--untracked-files=no",
                             NULL };
    char out[256], dir[1300];
    (void)snprintf(dir, sizeof(dir), "%s/.git/rebase-merge", rig->clone);
    return dlx_git_out(rig->clone, status, out, sizeof(out)) == 0 && !out[0] &&
           !dlx_file_exists(dir);
}

int test_dev_land_qualify_group_verdicts(void)
{
    int failures = 0;
    TEST("land: qualify attributes a group that fails or reports nothing") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("qualify_two");
        ASSERT(dlx_qualify_rig(&rig, "qualify_two", "", "leaf_smoke",
                               DLX_Q_LEAF_SMOKE | DLX_Q_LAND_WINDOW));
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_GROUP_FAILED"));
        ASSERT_STR_EQ(dlx_str(&c, "group"), "test_leaf_smoke");
        ASSERT_STR_EQ(dlx_str(&c, "paths"), "test_leaf_smoke");
        dlx_end(&c);
        dlx_isolate("qualify_crash");
        ASSERT(dlx_qualify_rig(&rig, "qualify_crash", "", "", DLX_Q_LEAF_SMOKE));
        setenv("QCRASH", "leaf_smoke", 1);
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_GROUP_FAILED"));
        ASSERT_STR_EQ(dlx_str(&c, "group"), "test_leaf_smoke");
        ASSERT(strstr(dlx_str(&c, "detail"), "no verdict") != NULL);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

int test_dev_land_qualify_groups_reported(void)
{
    int failures = 0;
    TEST("land: a qualified submission lists its groups, [] when none") {
        struct dlx_rig rig;
        struct dlx_call c;
        const struct json_value *groups;
        dlx_isolate("qualify_groups");
        ASSERT(dlx_qualify_rig(&rig, "qualify_groups", "", "",
                               DLX_Q_LEAF_SMOKE | DLX_Q_LAND_WINDOW));
        ASSERT(dlx_qualify_submit(&c, &rig) && dlx_ok(&c));
        groups = dlx_arr(&c, "groups");
        ASSERT(groups != NULL && groups->num_children >= 2);
        dlx_end(&c);
        dlx_isolate("qualify_no_groups");
        ASSERT(dlx_qualify_rig(&rig, "qualify_no_groups", "", "", 0));
        ASSERT(dlx_qualify_submit(&c, &rig) && dlx_ok(&c));
        groups = dlx_arr(&c, "groups");
        ASSERT(groups != NULL && groups->num_children == 0);
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

static void dlx_route_lost(const char *path, struct agent_impact_acc *acc)
{
    (void)path;
    memset(acc, 0, sizeof(*acc));
    acc->groups_lost = true;
}

int test_dev_land_qualify_selection_refusals(void)
{
    int failures = 0;
    TEST("land: qualify refuses a selection that lost groups or paths") {
        struct dlx_rig rig;
        struct dlx_call c;
        dlx_isolate("qualify_lost");
        ASSERT(dlx_qualify_rig(&rig, "qualify_lost", "", "", DLX_Q_LEAF_SMOKE));
        zcl_dev_land_qualify_test_limits(dlx_route_lost, 0);
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_GROUP_SELECTION"));
        ASSERT_STR_EQ(dlx_str(&c, "step"), "groups_lost");
        ASSERT(dlx_str(&c, "paths")[0] != '\0');
        dlx_end(&c);
        zcl_dev_land_qualify_test_limits(NULL, 16);
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_GROUP_SELECTION"));
        ASSERT_STR_EQ(dlx_str(&c, "step"), "path_list_truncated");
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

int test_dev_land_qualify_origin_moves(void)
{
    int failures = 0;
    TEST("land: qualify rebases a lane behind origin and refuses a conflict") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *contains[] = { "merge-base", "--is-ancestor", "origin/main",
                                   "HEAD", NULL };
        dlx_isolate("qualify_behind");
        ASSERT(dlx_qualify_rig(&rig, "qualify_behind", "", "", DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_origin_advances(&rig, "elsewhere.txt", "far away\n"));
        ASSERT(dlx_qualify_submit(&c, &rig) && dlx_ok(&c));
        ASSERT(dlx_git(rig.clone, contains) == 0);
        dlx_end(&c);
        dlx_isolate("qualify_conflict");
        ASSERT(dlx_qualify_rig(&rig, "qualify_conflict", "", "", DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_origin_advances(&rig, "change.txt", "theirs\n"));
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_REBASE_CONFLICT"));
        ASSERT(strstr(dlx_str(&c, "paths"), "change.txt") != NULL);
        ASSERT(dlx_clone_clean(&rig));
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

int test_dev_land_qualify_rebase_and_fetch_failures(void)
{
    int failures = 0;
    TEST("land: qualify types a rebase that is no conflict and a fetch failure") {
        struct dlx_rig rig;
        struct dlx_call c;
        char hook[1300];
        const char *unset[] = { "remote", "set-url", "origin", "/nonexistent",
                                NULL };
        dlx_isolate("qualify_rebase_failed");
        ASSERT(dlx_qualify_rig(&rig, "qualify_rebase_failed", "", "",
                               DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_origin_advances(&rig, "elsewhere.txt", "far away\n"));
        (void)snprintf(hook, sizeof(hook), "%s/.git/hooks/pre-rebase", rig.clone);
        ASSERT(dlx_write_dep(rig.clone, ".git/hooks/pre-rebase",
                             "#!/bin/sh\nexit 1\n"));
        ASSERT(chmod(hook, 0755) == 0);
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_REBASE_FAILED"));
        ASSERT(dlx_clone_clean(&rig));
        dlx_end(&c);
        dlx_isolate("qualify_fetch");
        ASSERT(dlx_qualify_rig(&rig, "qualify_fetch", "", "", DLX_Q_LEAF_SMOKE));
        ASSERT(dlx_git(rig.clone, unset) == 0);
        ASSERT(dlx_qualify_submit(&c, &rig));
        ASSERT(dlx_qualify_refused(&c, "QUALIFY_FETCH_FAILED"));
        dlx_end(&c);
        PASS();
    }
_test_next:;
    dlx_qualify_restore();
    return failures;
}

/* ── drive --seq: the landed reply stands alone; stubs are test-build only ── */

static int g_dlx_judged_hook_runs;

/* Corrupt the ledger the judge read, after the judge and before the reply. */
static void dlx_break_outcomes(void)
{
    char land[1200], path[1400];
    FILE *f;
    g_dlx_judged_hook_runs++;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(path, sizeof(path), "%s/outcomes.jsonl", land);
    f = fopen(path, "ab");
    if (f) {
        (void)fputs("not a ledger row\n", f);
        (void)fclose(f);
    }
}

int test_dev_land_drive_seq_landed_reply_stands_alone(void)
{
    int failures = 0;
    TEST("land: a landed drive reply does not read the ledger a second time") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64];
        dlx_isolate("drive_seq_landed_alone");
        ASSERT(dlx_attach_proven_pair(&rig, "drive_seq_landed_alone", base));
        g_dlx_judged_hook_runs = 0;
        zcl_native_dev_land_test_judged_hook(dlx_break_outcomes);
        ASSERT(dlx_drive_seq(&c, 1));
        zcl_native_dev_land_test_judged_hook(NULL);
        ASSERT_EQ(g_dlx_judged_hook_runs, 1);
        ASSERT(dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "");
        ASSERT_STR_EQ(dlx_str(&c, "outcome"), "landed");
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        PASS();
    }
_test_next:;
    zcl_native_dev_land_test_judged_hook(NULL);
    dlx_restore();
    return failures;
}

/* The text of one function's guard: the first preprocessor condition after
 * its signature line. */
static bool dlx_guard_is_test_only(const char *source, const char *signature)
{
    const char *at = strstr(source, signature);
    const char *guard = at ? strstr(at, "#if") : NULL;
    static const char want[] = "#if defined(ZCL_TESTING)\n";
    return guard && strncmp(guard, want, sizeof(want) - 1) == 0;
}

int test_dev_land_stubs_are_test_build_only(void)
{
    int failures = 0;
    TEST("land: the proof stub and unsigned bypass compile only in the test build") {
        static char source[1u << 20];
        FILE *f = fopen("tools/command/native_dev_land.c", "rb");
        size_t n;
        ASSERT(f != NULL);
        n = fread(source, 1, sizeof(source) - 1, f);
        (void)fclose(f);
        ASSERT(n > 0 && n < sizeof(source) - 1);
        source[n] = '\0';
        ASSERT(dlx_guard_is_test_only(source,
                                      "static const char *dl_stub(void)"));
        ASSERT(dlx_guard_is_test_only(
            source, "static const char *dl_allow_unsigned(void)"));
        PASS();
    }
_test_next:;
    return failures;
}

static int test_dev_land_pending_proof_move(void)
{
    int failures = 0;
    TEST("land: moving main requeues a still-running proof") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char stranger[64], main_now[64];
        dlx_isolate("move_pending");
        ASSERT(dlx_rig_make(&rig, "move_pending_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        ASSERT(dlx_git(rig.clone, branch) == 0);
        ASSERT(dlx_commit(rig.clone, "stranger.txt", "elsewhere\n", stranger));
        ASSERT(dlx_git(rig.clone, push) == 0);
        ASSERT(dlx_git(rig.clone, back) == 0);
        ASSERT(dlx_git(rig.clone, fetch) == 0);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "rebased");
        ASSERT_EQ(dlx_int(&c, "attempt"), 2);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, main_now));
        ASSERT_STR_EQ(main_now, stranger);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_restore();
        PASS();
    }
_test_next:;
    return failures;
}

int test_dev_land_main_moves_converge(void)
{
    int failures = test_dev_land_pending_proof_move();
    TEST("land: three proof-time main advances yield then converge") {
        struct dlx_rig rig;
        struct dlx_call c;
        const char *push[] = { "push", "--quiet", "origin", "HEAD:main",
                               NULL };
        const char *fetch[] = { "fetch", "--quiet", "origin", NULL };
        const char *branch[] = { "checkout", "--quiet", "-B", "side",
                                 "origin/main", NULL };
        const char *back[] = { "checkout", "--quiet", "-B", "main", NULL };
        char side[600], stranger[64], original_ts[64], landed[64];
        char following[64];
        int i;
        dlx_isolate("moveforever");
        ASSERT(dlx_rig_make(&rig, "moveforever_rig"));
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c));
        ASSERT(dlx_ok(&c));
        dlx_end(&c);
        ASSERT(dlx_commit(rig.clone, "following.txt", "following\n",
                          following));
        dlx_submit(&c, &rig, following);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_EQ(dlx_int(&c, "seq"), 2);
        dlx_end(&c);
        dlx_begin(&c, "cancel");
        (void)json_push_kv_int(&c.input, "seq", 2);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "cancelled");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *queued = dlx_arr(&c, "queued");
        const struct json_value *outcomes = dlx_arr(&c, "outcomes");
        ASSERT(queued && queued->num_children == 1);
        ASSERT(outcomes && outcomes->num_children == 1);
        ASSERT_EQ(json_get_int(json_get(&outcomes->children[0], "seq")), 2);
        (void)snprintf(original_ts, sizeof(original_ts), "%s",
                       json_get_str(json_get(&queued->children[0], "ts")));
        dlx_end(&c);
        (void)snprintf(side, sizeof(side), "%s", rig.clone);
        for (i = 0; i < 3; i++) {
            char tag[32];
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            ASSERT(strcmp(dlx_str(&c, "state"), "started") == 0);
            dlx_end(&c);
            (void)snprintf(tag, sizeof(tag), "s%d.txt", i);
            ASSERT(dlx_git(side, branch) == 0);
            ASSERT(dlx_commit(side, tag, "elsewhere\n", stranger));
            ASSERT(dlx_git(side, push) == 0);
            ASSERT(dlx_git(side, back) == 0);
            ASSERT(dlx_git(side, fetch) == 0);
            dlx_begin(&c, "step");
            ASSERT(dlx_run(&c));
            ASSERT(dlx_ok(&c));
            ASSERT_STR_EQ(dlx_str(&c, "state"),
                          i == 2 ? "queued" : "rebased");
            ASSERT_EQ(dlx_int(&c, "attempt"), i == 2 ? 1 : i + 2);
            if (i == 2) {
                ASSERT_EQ(dlx_int(&c, "predecessor_seq"), 1);
                ASSERT_EQ(dlx_int(&c, "seq"), 3);
            }
            dlx_end(&c);
            dlx_begin(&c, "status");
            ASSERT(dlx_run(&c) && dlx_ok(&c));
            queued = dlx_arr(&c, "queued");
            ASSERT(queued && queued->num_children == 1);
            ASSERT_STR_EQ(json_get_str(json_get(&queued->children[0], "ts")),
                          original_ts);
            dlx_end(&c);
        }
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        (void)snprintf(landed, sizeof(landed), "%s",
                       dlx_str(&c, "tip_pushed"));
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, stranger));
        ASSERT_STR_EQ(stranger, landed);
        PASS();
    }

_test_next:;
    dlx_restore();
    return failures;
}

bool dlx_priority_snapshot(struct dlx_call *c, char ts[64])
{
    dlx_begin(c, "status");
    bool ok = dlx_run(c) && dlx_ok(c);
    if (ok) {
        const struct json_value *queued = dlx_arr(c, "queued");
        ok = queued && queued->num_children == 2;
        if (ok) {
            const char *value =
                json_get_str(json_get(&queued->children[0], "ts"));
            ok = value && snprintf(ts, 64, "%s", value) > 0;
        }
    }
    dlx_end(c);
    return ok;
}

bool dlx_priority_successor_status(struct dlx_call *c,
                                           const char *original_ts)
{
    dlx_begin(c, "status");
    bool ok = dlx_run(c) && dlx_ok(c);
    if (ok) {
        const struct json_value *queued = dlx_arr(c, "queued");
        const struct json_value *steer = json_get(&c->reply.data, "steer");
        const char *ts = queued && queued->num_children == 2
            ? json_get_str(json_get(&queued->children[1], "ts")) : NULL;
        ok = queued && queued->num_children == 2 && steer &&
             json_get_int(json_get(&queued->children[0], "seq")) == 2 &&
             json_get_int(json_get(&queued->children[1], "seq")) == 3 &&
             json_get_int(json_get(&queued->children[0], "priority_seq")) == 2 &&
             json_get_int(json_get(&queued->children[1], "priority_seq")) == 1 &&
             ts && strcmp(ts, original_ts) == 0 &&
             json_get_int(json_get(steer, "seq")) == 3;
    }
    dlx_end(c);
    return ok;
}

int test_dev_land_signed_intent(void)
{
    int failures = 0;
#if !defined(_WIN32)
    TEST("land: signed Git intent gates push and yields a remote receipt") {
        struct dlx_rig rig;
        struct dlx_call c;
        char base[64], remote[64];
        dlx_isolate("signed_intent");
        ASSERT(dlx_rig_make(&rig, "signed_intent_rig"));
        ASSERT(dlx_origin_main(&rig, base));
        setenv("ZCL_LAND_PROOF_STUB", "running", 1);
        setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
        dlx_submit(&c, &rig, rig.tip);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "started");
        dlx_end(&c);
        unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
        setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && !dlx_ok(&c));
        ASSERT_STR_EQ(dlx_err_code(&c), "PUBLICATION_INTENT_REQUIRED");
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, base);
        dlx_begin(&c, "attach");
        (void)json_push_kv_int(&c.input, "seq", 1);
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "attached");
        dlx_end(&c);
        dlx_begin(&c, "step");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        ASSERT_STR_EQ(dlx_str(&c, "state"), "landed");
        dlx_end(&c);
        dlx_begin(&c, "status");
        ASSERT(dlx_run(&c) && dlx_ok(&c));
        const struct json_value *outcomes = dlx_arr(&c, "outcomes");
        ASSERT(outcomes && outcomes->num_children == 1);
        ASSERT_STR_EQ(json_get_str(json_get(&outcomes->children[0],
                                          "acceptance_state")), "unknown");
        ASSERT(strlen(json_get_str(json_get(&outcomes->children[0],
                                          "remote_source"))) == 40);
        ASSERT(strlen(json_get_str(json_get(&outcomes->children[0],
                                          "remote_signature"))) == 128);
        dlx_end(&c);
        ASSERT(dlx_origin_main(&rig, remote));
        ASSERT_STR_EQ(remote, rig.tip);
        dlx_restore();
        PASS();
    }
_test_next:;
    dlx_restore();
#endif
    return failures;
}

#if !defined(_WIN32)
/* Persist a signed remote observation, then lose only the terminal append.
 * The original pair remains inflight with its receipt for another driver. */
static bool dlx_receipt_prepare(struct dlx_rig *rig)
{
    struct dlx_call c;
    bool ok;
    if (!dlx_rig_make(rig, "receipt_pending_rig"))
        return false;
    setenv("ZCL_LAND_PROOF_STUB", "running", 1);
    setenv("ZCL_LAND_ALLOW_UNSIGNED", "1", 1);
    dlx_submit(&c, rig, rig->tip);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    return ok;
}

static bool dlx_receipt_publisher_death(struct dlx_rig *rig)
{
    char hook[1400];
    int child_status = 0;
    (void)snprintf(hook, sizeof(hook), "%s/hooks/post-receive", rig->bare);
    pid_t child = fork();
    if (child < 0) return false;
    if (child == 0) {
        char kill_script[256];
        (void)setsid();
        (void)alarm(30);
        (void)snprintf(kill_script, sizeof(kill_script),
                      "#!/bin/sh\nkill -KILL %ld\n", (long)getpid());
        if (!dlx_write(hook, kill_script) || chmod(hook, 0700) != 0)
            _exit(2);
        struct dlx_call child_call;
        dlx_begin(&child_call, "step");
        (void)dlx_run(&child_call);
        _exit(90);
    }
    bool ok = dlx_wait_publisher(child, &child_status) == child &&
         WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGKILL;
    if (unlink(hook) != 0) ok = false;
    char remote[64];
    return ok && dlx_origin_main(rig, remote) && strcmp(remote, rig->tip) == 0;
}

bool dlx_signed_receipt_pending(struct dlx_rig *rig, char *queue,
                                      size_t queue_cap, char *marker,
                                      size_t marker_cap, bool persist_receipt)
{
    struct dlx_call c;
    char land[1200], wt[1400], wrapper[1400], script[3000];
    bool ok;
    if (!dlx_receipt_prepare(rig)) return false;
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok) return false;
    unsetenv("ZCL_LAND_ALLOW_UNSIGNED");
    setenv("ZCL_LAND_PROOF_STUB", "pass", 1);
    dlx_begin(&c, "attach");
    (void)json_push_kv_int(&c.input, "seq", 1);
    ok = dlx_run(&c) && dlx_ok(&c);
    dlx_end(&c);
    if (!ok) return false;
    dlx_landdir(land, sizeof(land));
    (void)snprintf(wt, sizeof(wt), "%s/wt", land);
    (void)snprintf(queue, queue_cap, "%s/queue.jsonl", land);
    (void)snprintf(marker, marker_cap, "%s/receive-count", land);
    (void)snprintf(wrapper, sizeof(wrapper), "%s/count-receive", land);
    (void)snprintf(script, sizeof(script),
        "#!/bin/sh\nprintf 'invoked\\n' >> '%s' || exit 73\n"
        "exec git-receive-pack \"$@\"\n", marker);
    if (!dlx_write(wrapper, script) || chmod(wrapper, 0700) != 0)
        return false;
    const char *intercept[] = { "config", "remote.origin.receivepack", wrapper, NULL };
    if (dlx_git(wt, intercept) != 0) return false;
    if (!persist_receipt) return dlx_receipt_publisher_death(rig);
    setenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND", "1", 1);
    setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1);
    dlx_begin(&c, "step");
    ok = dlx_run(&c) && dlx_ok(&c) &&
        strcmp(dlx_str(&c, "persist"), "failed") == 0;
    dlx_end(&c);
    unsetenv("ZCL_LAND_TEST_REFUSE_OUTCOME_APPEND");
    unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    return ok;
}

#endif /* !defined(_WIN32) */
