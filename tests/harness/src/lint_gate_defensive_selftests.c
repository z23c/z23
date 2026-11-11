/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Self-tests for the gates that stop a defensive-coding rule from being
 * quietly loosened: check-raw-sqlite (no raw sqlite3_step/exec outside the
 * ActiveRecord lifecycle), check-raw-malloc (every allocation through
 * zcl_malloc), the coins-lookup null-check guard, the observability
 * stderr-pairing scan, the active-chain tip-mutation gate, the deleted-engine
 * name scan, and the build_commit macro getter contract.
 *
 * Each check plants a known-bad fixture, asserts the gate trips, removes the
 * fixture, and asserts the gate recovers — so a widened exemption pattern
 * fails here instead of silently passing in production. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

/* The lint-gate self-test family fork+execs POSIX bash gate scripts; native
 * Windows has no fork/exec/waitpid, so on _WIN32 every check compiles out and
 * the registered group entry points (test_make_lint_gates.c) report a loud
 * skip instead. */
#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"
#include "util/spawn.h"

int check_coins_guard_file(const char *path)
{
    char *buf = NULL;
    if (read_entire_file(path, &buf) != 0) return -1;

    int rc = 0;
    if (strstr(buf, "coins_view_cache_get_coins(") &&
        !strstr(buf, "rpc_require_chainstate_lookup_ready(")) {
        rc = 1;
    }

    free(buf);
    return rc;
}

bool line_has_obs_ok(const char *line)
{
    const char *tag = strstr(line, "// obs-ok:");
    return tag && tag[10] != '\0' && tag[10] != '\n' && tag[10] != ' ';
}

bool line_has_event_emit(const char *line)
{
    return strstr(line, "event_emit(") || strstr(line, "event_emitf(");
}

bool line_has_terminal_propagation(const char *line)
{
    return strstr(line, "return false;") ||
           strstr(line, "return -1;") ||
           strstr(line, "return 1;") ||
           strstr(line, "return NULL;") ||
           strstr(line, "exit(") ||
           strstr(line, "abort(");
}

bool observability_line_allowed(char lines[][4096], size_t count,
                                       size_t idx)
{
    if (line_has_obs_ok(lines[idx])) return true;

    size_t start = idx > 3 ? idx - 3 : 0;
    size_t end = idx + 3 < count ? idx + 3 : count - 1;
    for (size_t i = start; i <= end; i++) {
        if (line_has_event_emit(lines[i])) return true;
        if (i >= idx && line_has_terminal_propagation(lines[i])) return true;
    }
    return false;
}

int check_observability_file(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    char lines[512][4096];
    size_t count = 0;
    while (count < 512 && fgets(lines[count], sizeof(lines[count]), fp)) {
        count++;
    }
    int read_error = ferror(fp) ? -1 : 0;
    fclose(fp);
    if (read_error != 0) return read_error;

    for (size_t i = 0; i < count; i++) {
        if (strstr(lines[i], "fprintf(stderr") &&
            !observability_line_allowed(lines, count, i))
            return 1;
    }
    return 0;
}

bool active_chain_set_tip_file_allowed(const char *path)
{
    return strstr(path, "/engine/services/src/chain_tip.c") ||
           strstr(path, "/engine/services/src/chain_state_service.c");
}

int check_active_chain_set_tip_file(const char *path)
{
    if (active_chain_set_tip_file_allowed(path))
        return 0;

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;

    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        char *hit = strstr(line, "active_chain_set_tip(");
        if (!hit)
            continue;
        char *block_comment = strstr(line, "/*");
        char *star_comment = strstr(line, "*");
        char *line_comment = strstr(line, "//");
        bool comment_only = (block_comment && block_comment < hit) ||
                            (star_comment && star_comment < hit) ||
                            (line_comment && line_comment < hit);
        if (!comment_only) {
            fclose(fp);
            return 1;
        }
    }

    fclose(fp);
    return 0;
}

static bool deleted_engine_names_file_allowed(const char *path)
{
    return strstr(path, "/tests/harness/include/test/") ||
           strstr(path, "/contexts/explorer/views/");
}

/* Copy one line of source into code, dropping // comments and block
 * comments. block_comment carries an open slash-star across lines. */
static void deleted_engine_names_strip_line(const char *line, char *code,
                                            size_t code_cap,
                                            bool *block_comment)
{
    size_t out = 0;
    for (size_t pos = 0; line[pos] && out + 1 < code_cap; pos++) {
        if (*block_comment) {
            if (line[pos] == '*' && line[pos + 1] == '/') {
                *block_comment = false;
                pos++;
            }
            continue;
        }
        if (line[pos] == '/' && line[pos + 1] == '*') {
            *block_comment = true;
            pos++;
            continue;
        }
        if (line[pos] == '/' && line[pos + 1] == '/')
            break;
        code[out++] = line[pos];
    }
    code[out] = '\0';
}

static const char *deleted_engine_names_find(const char *code)
{
    const char *stale[] = {
        "connect_tip",
        "disconnect_tip",
        "activate_best_chain",
        "process_new_block",
        "accept_block()",
    };
    for (size_t i = 0; i < sizeof(stale) / sizeof(stale[0]); i++) {
        if (strstr(code, stale[i]))
            return stale[i];
    }
    return NULL;
}

int check_deleted_engine_names_file(const char *path)
{
    if (deleted_engine_names_file_allowed(path))
        return 0;

    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    bool block_comment = false;
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        char code[4096];
        deleted_engine_names_strip_line(line, code, sizeof(code),
                                        &block_comment);
        const char *hit = deleted_engine_names_find(code);
        if (hit) {
            fprintf(stderr,
                    "deleted engine name %s still present in %s\n",
                    hit, path);
            fclose(fp);
            return 1;
        }
    }
    int rc = ferror(fp) ? -1 : 0;
    fclose(fp);
    return rc;
}

bool build_commit_macro_file_allowed(const char *path)
{
    return strstr(path, "/platform/modules/util/src/clientversion.c") ||
           strstr(path, "/platform/modules/util/include/util/clientversion.h") ||
           strstr(path, "/tests/harness/src/lint_gate_defensive_selftests.c") ||
           /* the VCS SHA-1 lint gate names ZCL_BUILD_COMMIT only as search
            * text while scanning the Makefile for baked-commit macros */
           strstr(path, "/tools/lint/lintc/gate_vcs_sha1_fence.c");
}

int check_build_commit_macro_file(const char *path)
{
    if (build_commit_macro_file_allowed(path))
        return 0;

    char *buf = NULL;
    if (read_entire_file(path, &buf) != 0)
        return -1;

    int rc = 0;
    if (strstr(buf, "ZCL_BUILD_COMMIT")) {
        fprintf(stderr,
                "ZCL_BUILD_COMMIT used outside clientversion getter: %s\n",
                path);
        rc = 1;
    }

    free(buf);
    return rc;
}

int run_check_build_commit_macro_contract(void)
{
    const char *roots[] = {
        "core", "engine", "contexts", "cognition", "platform", "tools",
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        char dir[PATH_MAX];
        if (repo_path(dir, sizeof(dir), roots[i]) != 0)
            return -1;
        int rc = walk_ch_files(dir, check_build_commit_macro_file);
        if (rc != 0)
            return rc;
    }
    return 0;
}

int run_check_raw_sqlite(void)
{
    return run_gate_script(RAW_SQLITE_SCRIPT_REL, NULL);
}

int run_check_coins_lookup_nullcheck(void)
{
    char controllers_dir[PATH_MAX];
    if (repo_path(controllers_dir, sizeof(controllers_dir),
                  "engine/controllers/src") != 0)
        return -1;
    return walk_c_files(controllers_dir, check_coins_guard_file);
}

int run_check_service_tip_mutation_gate(void)
{
    char services_dir[PATH_MAX];
    if (repo_path(services_dir, sizeof(services_dir), "engine/services/src") != 0)
        return -1;
    return walk_c_files(services_dir, check_active_chain_set_tip_file);
}

int run_check_deleted_engine_names(void)
{
    const char *roots[] = {
        "core", "engine", "contexts", "cognition", "platform", "tools",
    };
    for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
        char dir[PATH_MAX];
        if (repo_path(dir, sizeof(dir), roots[i]) != 0)
            return -1;
        int rc = walk_ch_files(dir, check_deleted_engine_names_file);
        if (rc != 0)
            return rc;
    }
    return 0;
}

int t_observability_fixture_trips_gate(void)
{
    int failures = 0;
    char fixture_src[PATH_MAX];
    char fixture_dst[PATH_MAX];
    if (repo_path(fixture_src, sizeof(fixture_src), OBS_FIXTURE_SRC_REL) != 0 ||
        repo_path(fixture_dst, sizeof(fixture_dst), OBS_FIXTURE_DST_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve observability fixture paths\n");
        return 1;
    }
    (void)unlink(fixture_dst);
    if (copy_file(fixture_src, fixture_dst) != 0) {
        fprintf(stderr,
                "[lint-gate] could not plant observability fixture -- aborting\n");
        return 1;
    }
    int rc = check_observability_file(fixture_dst);
    (void)unlink(fixture_dst);
    TEST("[lint-gate] unpaired stderr fixture trips observability gate") {
        ASSERT(rc != 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_observability_positive_controls_pass(void)
{
    int failures = 0;
    char fixture_src[PATH_MAX];
    char fixture_dst[PATH_MAX];
    if (repo_path(fixture_src, sizeof(fixture_src), OBS_OK_FIXTURE_SRC_REL) != 0 ||
        repo_path(fixture_dst, sizeof(fixture_dst), OBS_OK_FIXTURE_DST_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve observability-ok fixture paths\n");
        return 1;
    }
    (void)unlink(fixture_dst);
    if (copy_file(fixture_src, fixture_dst) != 0) {
        fprintf(stderr,
                "[lint-gate] could not plant observability-ok fixture -- aborting\n");
        return 1;
    }
    int rc = check_observability_file(fixture_dst);
    (void)unlink(fixture_dst);
    TEST("[lint-gate] observable stderr positive controls pass") {
        ASSERT(rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_baseline_passes(void)
{
    int failures = 0;
    TEST("[lint-gate] baseline passes (no fixture)") {
        ASSERT(run_check_raw_sqlite() == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_fixture_trips_gate(void)
{
    int failures = 0;
    char fixture_src[PATH_MAX];
    char fixture_dst[PATH_MAX];
    if (repo_path(fixture_src, sizeof(fixture_src), FIXTURE_SRC_REL) != 0 ||
        repo_path(fixture_dst, sizeof(fixture_dst), FIXTURE_DST_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve raw sqlite fixture paths\n");
        return 1;
    }
    (void)unlink(fixture_dst);
    if (copy_file(fixture_src, fixture_dst) != 0) {
        fprintf(stderr, "[lint-gate] could not plant fixture — aborting\n");
        return 1;
    }
    int rc = run_check_raw_sqlite();
    (void)unlink(fixture_dst);
    TEST("[lint-gate] planted fixture trips the gate (exit != 0)") {
        ASSERT(rc != 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_node_db_exec_fixture_trips_gate(void)
{
    int failures = 0;
    char fixture_src[PATH_MAX];
    char fixture_dst[PATH_MAX];
    if (repo_path(fixture_src, sizeof(fixture_src),
                  NODE_DB_EXEC_FIXTURE_SRC_REL) != 0 ||
        repo_path(fixture_dst, sizeof(fixture_dst),
                  NODE_DB_EXEC_FIXTURE_DST_REL) != 0) {
        fprintf(stderr,
                "[lint-gate] could not resolve node_db exec fixture paths\n");
        return 1;
    }
    (void)unlink(fixture_dst);
    if (copy_file(fixture_src, fixture_dst) != 0) {
        fprintf(stderr,
                "[lint-gate] could not plant node_db exec fixture -- aborting\n");
        return 1;
    }
    int rc = run_check_raw_sqlite();
    (void)unlink(fixture_dst);
    TEST("[lint-gate] forwarded node_db_exec wallet DML fixture trips the gate") {
        ASSERT(rc == 1);
        PASS();
    } _test_next:;
    return failures;
}

int t_gate_recovers_after_removal(void)
{
    int failures = 0;
    char fixture_dst[PATH_MAX];
    if (repo_path(fixture_dst, sizeof(fixture_dst), FIXTURE_DST_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve raw sqlite fixture path\n");
        return 1;
    }
    (void)unlink(fixture_dst);
    TEST("[lint-gate] gate passes again after fixture removed") {
        ASSERT(run_check_raw_sqlite() == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_coins_guard_baseline_passes(void)
{
    int failures = 0;
    TEST("[lint-gate] baseline guarded coin-lookups pass") {
        ASSERT(run_check_coins_lookup_nullcheck() == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_coins_guard_fixture_trips_gate(void)
{
    int failures = 0;
    char fixture_src[PATH_MAX];
    char fixture_dst[PATH_MAX];
    if (repo_path(fixture_src, sizeof(fixture_src), COINS_FIXTURE_SRC_REL) != 0 ||
        repo_path(fixture_dst, sizeof(fixture_dst), COINS_FIXTURE_DST_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve coins guard fixture paths\n");
        return 1;
    }
    (void)unlink(fixture_dst);
    if (copy_file(fixture_src, fixture_dst) != 0) {
        fprintf(stderr,
                "[lint-gate] could not plant coins guard fixture — aborting\n");
        return 1;
    }
    int rc = run_check_coins_lookup_nullcheck();
    (void)unlink(fixture_dst);
    TEST("[lint-gate] unguarded coin lookup fixture trips the gate (exit != 0)") {
        ASSERT(rc != 0);
        PASS();
    } _test_next:;
    return failures;
}

/* Invokes ./build/bin/z23-lint check-raw-malloc and returns the script's
 * exit status (0 = clean, non-zero = violations). */
int run_check_raw_malloc_script(void)
{
    char script[PATH_MAX];
    if (repo_path(script, sizeof(script), RAW_MALLOC_SCRIPT_REL) != 0)
        return -1;

    char out_path[PATH_MAX];
    if (repo_path(out_path, sizeof(out_path),
                  "test-tmp/zcl_raw_malloc_lint.out") != 0)
        return -1;

    struct sigaction old_chld;
    struct sigaction dfl_chld;
    int restore_chld = 0;
    memset(&old_chld, 0, sizeof(old_chld));
    memset(&dfl_chld, 0, sizeof(dfl_chld));
    dfl_chld.sa_handler = SIG_DFL;
    sigemptyset(&dfl_chld.sa_mask);
    if (sigaction(SIGCHLD, NULL, &old_chld) == 0 &&
        sigaction(SIGCHLD, &dfl_chld, NULL) == 0) {
        restore_chld = 1;
    }

    pid_t pid = fork_with_retry();
    if (pid < 0) {
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (pid == 0) {
        int fd = open(out_path, O_CREAT | O_WRONLY | O_TRUNC, 0600);
        if (fd >= 0) {
            (void)dup2(fd, STDOUT_FILENO);
            (void)dup2(fd, STDERR_FILENO);
            close(fd);
        }
        gate_exec(script, NULL);
        _exit(127);
    }

    int rc = 0;
    while (waitpid(pid, &rc, 0) < 0) {
        if (errno == EINTR)
            continue;
        if (restore_chld)
            (void)sigaction(SIGCHLD, &old_chld, NULL);
        return -1;
    }
    if (restore_chld)
        (void)sigaction(SIGCHLD, &old_chld, NULL);
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

int t_coins_guard_gate_fails_loud_on_no_lookup_surface(void)
{
    int failures = 0;
    char test_tmp[PATH_MAX];
    char scan_dir[PATH_MAX];
    char fixture[PATH_MAX];

    if (repo_path(test_tmp, sizeof(test_tmp), "test-tmp") != 0 ||
        repo_path(scan_dir, sizeof(scan_dir),
                  "test-tmp/_coins_lookup_nohit_scan_dir") != 0) {
        fprintf(stderr,
                "[lint-gate] could not resolve coins no-hit fixture dir\n");
        return 1;
    }
    (void)mkdir(test_tmp, 0700);
    (void)mkdir(scan_dir, 0700);
    if (snprintf(fixture, sizeof(fixture), "%s/nohit.c", scan_dir) >=
        (int)sizeof(fixture)) {
        fprintf(stderr, "[lint-gate] coins no-hit fixture path too long\n");
        return 1;
    }

    (void)unlink(fixture);
    int planted = write_file(fixture,
        "int coins_lookup_nohit_fixture(void){ return 23; }\n");
    int trip_rc = planted == 0
        ? run_gate_script_with_env(
              "build/bin/z23-lint check-coins-lookup-nullcheck",
              "ZCL_COINS_LOOKUP_SCAN_DIR",
              scan_dir)
        : -1;
    (void)unlink(fixture);
    (void)rmdir(scan_dir);

    int green_rc = run_gate_script(
        "build/bin/z23-lint check-coins-lookup-nullcheck", NULL);

    TEST("[lint-gate] coins lookup guard fails loud when lookup surface disappears") {
        ASSERT(planted == 0);
        ASSERT(trip_rc == 2);
        ASSERT(green_rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* An inaccessible subtree must not disappear from the shared module set,
 * even when another accessible module satisfies the declaration minimum. */
static int raw_module_capture(const char *root, char *out, size_t cap)
{
    char binary[PATH_MAX];
    struct sigaction saved, normal = {.sa_handler = SIG_DFL};
    if (repo_path(binary, sizeof binary, "build/bin/z23-lint") != 0 ||
        sigemptyset(&normal.sa_mask) != 0 ||
        sigaction(SIGCHLD, &normal, &saved) != 0)
        return -1;
    const char *argv[] = {binary, "check-raw-malloc", NULL};
    bool timed_out = false;
    int rc = zcl_spawn_capture_merged_in_dir_observed(
        argv, root, out, cap, 5000, &timed_out);
    if (sigaction(SIGCHLD, &saved, NULL) != 0)
        return -1;
    if (timed_out)
        return -1;
    return rc;
}

static int raw_module_fixture(const char *root, char *hidden, char *plant)
{
    static const char *const dirs[] = {
        "engine", "engine/modules", "engine/modules/good", "engine/composition",
        "contexts", "contexts/hidden", "contexts/hidden/modules",
        "contexts/hidden/modules/bad"
    };
    char path[PATH_MAX];
    for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
        if (snprintf(path, sizeof path, "%s/%s", root, dirs[i]) >= (int)sizeof path ||
            mkdir(path, 0700) != 0)
            return 1;
    }
    if (snprintf(hidden, PATH_MAX, "%s/contexts/hidden", root) >= PATH_MAX ||
        snprintf(plant, PATH_MAX, "%s/modules/bad/bad.c", hidden) >= PATH_MAX)
        return 1;
    if (snprintf(path, sizeof path, "%s/Makefile", root) >= (int)sizeof path ||
        write_file(path, "PRODUCT_CONTEXTS = hidden\nAPP_DIRS = services\n") != 0)
        return 1;
    if (snprintf(path, sizeof path, "%s/engine/composition/lib_module_order.def", root)
            >= (int)sizeof path || write_file(path, "LIB_MODULE(\"good\")\n") != 0)
        return 1;
    return write_file(plant, "void *bad(void) { return malloc(12); }\n");
}

static int raw_module_cases(const char *root, const char *hidden, const char *plant)
{
    char out[4096] = "";
    if (chmod(hidden, 0000) != 0)
        return 1;
    int bad = 0;
    if (access(plant, R_OK) == 0) {
        fprintf(stderr, "[lint-gate] UNQUALIFIED permission-denial case: "
                        "process bypasses directory mode; readable controls still run\n");
    } else {
        int rc = raw_module_capture(root, out, sizeof out);
        bad = rc != 2 || strstr(out, "contexts/hidden") == NULL ||
              strstr(out, "OK:") != NULL;
        fprintf(stderr, "[lint-gate] module permission denial rc=%d: %s", rc, out);
    }
    if (chmod(hidden, 0700) != 0)
        return 1;
    int rc = raw_module_capture(root, out, sizeof out);
    bad |= rc != 1 || strstr(out, "contexts/hidden/modules/bad/bad.c") == NULL;
    if (write_file(plant, "int clean;\n") != 0)
        return 1;
    rc = raw_module_capture(root, out, sizeof out);
    bad |= rc != 0 || strstr(out, "OK: check_raw_malloc") == NULL;
    return bad;
}

static int raw_malloc_module_permissions_witness(void)
{
    char root[PATH_MAX], hidden[PATH_MAX] = "", plant[PATH_MAX];
    if (!test_mkdtemp(root, sizeof root, "lint_module_permissions"))
        return 1;
    int bad = raw_module_fixture(root, hidden, plant);
    if (!bad)
        bad = raw_module_cases(root, hidden, plant);
    if (hidden[0])
        (void)chmod(hidden, 0700);
    if (test_rm_rf_recursive(root) != 0)
        bad = 1;
    return bad;
}

int t_raw_malloc_fixture_trips_gate(void)
{
    int failures = 0;
    char fixture_dst[PATH_MAX];
    if (repo_path(fixture_dst, sizeof(fixture_dst), RAW_MALLOC_FIXTURE_DST_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve raw_malloc fixture path\n");
        return 1;
    }
    (void)unlink(fixture_dst);
    const char *bad = "/* fixture */\n#include <stdlib.h>\nvoid *f(void){return malloc(16);}\n";
    if (write_file(fixture_dst, bad) != 0) {
        fprintf(stderr, "[lint-gate] could not plant raw_malloc fixture — aborting\n");
        return 1;
    }
    int rc = run_check_raw_malloc_script();
    (void)unlink(fixture_dst);
    TEST("[lint-gate] raw malloc fixture trips the gate (exit != 0)") {
        ASSERT(rc != 0);
        PASS();
    } _test_next:;
    failures += raw_malloc_module_permissions_witness();
    return failures;
}

int t_raw_malloc_zcl_fixture_passes(void)
{
    int failures = 0;
    char fixture_dst[PATH_MAX];
    if (repo_path(fixture_dst, sizeof(fixture_dst), RAW_MALLOC_OK_FIXTURE_DST_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve raw_malloc-ok fixture path\n");
        return 1;
    }
    unlink_lint_fixtures();
    const char *good =
        "/* fixture */\n"
        "#include \"util/safe_alloc.h\"\n"
        "void *f(void){return zcl_malloc(16, \"fixture\");}\n";
    if (write_file(fixture_dst, good) != 0) {
        fprintf(stderr, "[lint-gate] could not plant raw_malloc-ok fixture — aborting\n");
        return 1;
    }
    int rc = run_check_raw_malloc_script();
    unlink_lint_fixtures();
    TEST("[lint-gate] zcl_malloc-only fixture passes the gate (exit == 0)") {
        ASSERT(rc == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_raw_malloc_gate_recovers(void)
{
    int failures = 0;
    char fixture_dst1[PATH_MAX];
    char fixture_dst2[PATH_MAX];
    if (repo_path(fixture_dst1, sizeof(fixture_dst1), RAW_MALLOC_FIXTURE_DST_REL) != 0 ||
        repo_path(fixture_dst2, sizeof(fixture_dst2), RAW_MALLOC_OK_FIXTURE_DST_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve raw_malloc fixture paths\n");
        return 1;
    }
    (void)fixture_dst1;
    (void)fixture_dst2;
    unlink_lint_fixtures();
    TEST("[lint-gate] raw_malloc gate passes after fixtures removed") {
        ASSERT(run_check_raw_malloc_script() == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_coins_guard_gate_recovers(void)
{
    int failures = 0;
    char fixture_dst[PATH_MAX];
    if (repo_path(fixture_dst, sizeof(fixture_dst), COINS_FIXTURE_DST_REL) != 0) {
        fprintf(stderr, "[lint-gate] could not resolve coins guard fixture path\n");
        return 1;
    }
    (void)unlink(fixture_dst);
    TEST("[lint-gate] guarded coin-lookups pass again after fixture removed") {
        ASSERT(run_check_coins_lookup_nullcheck() == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_service_tip_mutation_gate(void)
{
    int failures = 0;
    TEST("[lint-gate] services do not bypass canonical tip publication") {
        ASSERT(run_check_service_tip_mutation_gate() == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_legacy_candidate_source_has_no_override_scope(void)
{
    int failures = 0;
    char *mirror = NULL;
    TEST("legacy mirror monitor has no tip-mutation path") {
        char mirror_path[PATH_MAX];
        ASSERT(repo_path(mirror_path, sizeof(mirror_path),
                         "engine/services/src/legacy_mirror_sync_service.c") == 0);
        ASSERT(read_entire_file(mirror_path, &mirror) == 0);
        ASSERT(strstr(mirror, "CSR_ROLLBACK_SOURCE_MIRROR") == NULL);
        ASSERT(strstr(mirror, "chain_set_active_tip(") == NULL);
        ASSERT(strstr(mirror, "active_chain_set_tip(") == NULL);
        PASS();
    } _test_next:;
    free(mirror);
    return failures;
}

int t_deleted_engine_names_absent_from_production_sources(void)
{
    int failures = 0;
    TEST("deleted engine names are absent from production C/H sources") {
        ASSERT(run_check_deleted_engine_names() == 0);
        PASS();
    } _test_next:;
    return failures;
}

int t_build_commit_macro_stays_behind_getter(void)
{
    int failures = 0;
    TEST("build commit macro stays behind runtime getter") {
        ASSERT(run_check_build_commit_macro_contract() == 0);
        PASS();
    } _test_next:;
    return failures;
}

/* A fake compiler records every optimization/candidate pair and exposes
 * distinct probe failures without relying on the host libc's masked set. */
static const char k_fmd_fake[] =
    "#!/bin/sh\n"
    "src= opt=\n"
    "for a do case $a in *control.c|*probe.c) src=$a;; -O0|-O2) opt=$a;; esac; done\n"
    "case $src in *control.c) name=control; echo x >> \"$FMD_CTL\";; "
    "*) name=$(sed -n 's/.*&\\([a-zA-Z_]*\\);.*/\\1/p' \"$src\");; esac\n"
    "printf '%s %s\\n' \"$opt\" \"$name\" >> \"$FMD_TRACE\"\n"
    "if [ \"$name\" = control ]; then\n"
    " n=$(wc -l < \"$FMD_CTL\")\n"
    " [ \"$FMD_MODE:$n\" = initial:1 ] && exit 1\n"
    " [ \"$FMD_MODE:$n\" = final:2 ] && exit 1\n"
    " [ \"$FMD_MODE:$n\" = fixture:2 ] && : > \"${src%/*}/st\"\n"
    " exit 0\nfi\n"
    "[ \"$FMD_MODE\" = exec127 ] && exit 127\n"
    "[ \"$FMD_MODE\" = exec126 ] && exit 126\n"
    "[ \"$FMD_MODE\" = signal ] && kill -TERM $$\n"
    "[ \"$FMD_MODE\" != empty ] && [ \"$name:$opt\" = realpath:-O0 ] && exit 1\n"
    "exit 0\n";

static int fmd_fixture_source(const char *dir, const char *mode)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/fixture.c", dir) >= (int)sizeof path) return 1;
    const char *body = "#include <stdlib.h>\nvoid f(void){ zcl_synthetic_masked_decl(); }\n";
    if (!strcmp(mode, "masked_bad") || !strcmp(mode, "empty"))
        body = "#include <stdlib.h>\nvoid f(void){ realpath(0,0); zcl_synthetic_masked_decl(); }\n";
    if (!strcmp(mode, "guarded"))
        body = "#define _DEFAULT_SOURCE\n#include <stdlib.h>\nvoid f(void){ realpath(0,0); }\n";
    if (!strcmp(mode, "comment"))
        body = "#include <stdlib.h>\n/* realpath(0,0) */\n";
    return write_file(path, body);
}

static int fmd_spawn_isolated(const char *const argv[], const char *dir, char *out, size_t cap);

static int fmd_fake_run(const char *dir, const char *mode, const char *arg, char *out, size_t cap)
{
    char bin[PATH_MAX], cc[PATH_MAX], trace[PATH_MAX], ctl[PATH_MAX];
    if (repo_path(bin, sizeof bin, "build/bin/z23-lint") ||
        snprintf(cc, sizeof cc, "%s/cc", dir) >= (int)sizeof cc ||
        snprintf(trace, sizeof trace, "%s/trace", dir) >= (int)sizeof trace ||
        snprintf(ctl, sizeof ctl, "%s/control", dir) >= (int)sizeof ctl) return -1;
    (void)unlink(trace); (void)unlink(ctl);
    if (fmd_fixture_source(dir, mode) || setenv("CC", cc, 1) || setenv("FMD_TRACE", trace, 1) ||
        setenv("FMD_CTL", ctl, 1) || setenv("FMD_MODE", mode, 1)) return -1;
    const char *argv[] = {bin, "check-fortify-masked-decls", arg, NULL};
    return fmd_spawn_isolated(argv, dir, out, cap);
}

static int fmd_trace_pairs(const char *trace)
{
    static const char *const names[] = {"realpath", "ptsname_r", "getwd", "gethostname", "mktemp", "getcwd",
        "readlink", "readlinkat", "stpcpy", "stpncpy", "mempcpy", "strcasestr", "memmem", "strsep",
        "strdup", "strndup", "asprintf", "vasprintf", "getline", "getdelim", "usleep", "random",
        "srandom", "initstate", "setstate", "lockf", "pread", "pwrite", "ftruncate", "truncate",
        "fchdir", "symlink", "chroot", "wcpcpy", "wcpncpy"};
    char line[80];
    for (size_t i = 0; i < sizeof names / sizeof names[0]; ++i)
        for (int opt = 0; opt <= 2; opt += 2) {
            if (snprintf(line, sizeof line, "-O%d %s\n", opt, names[i]) >= (int)sizeof line || !strstr(trace, line)) return 1;
        }
    return 0;
}

static int fmd_trace_check(const char *dir, int want)
{
    char path[PATH_MAX], *text = NULL;
    if (snprintf(path, sizeof path, "%s/trace", dir) >= (int)sizeof path || read_entire_file(path, &text)) return 1;
    int lines = 0; for (char *p = text; *p; ++p) lines += *p == '\n';
    int bad = lines != want || (want == 72 && fmd_trace_pairs(text));
    free(text); return bad;
}

static int fmd_fake_cases(const char *dir)
{
    static const struct { const char *mode, *arg; int exit_code, calls; const char *expected; } cases[] = {
        {"masked", "--verify", 0, 72, "masked set:realpath"},
        {"masked_bad", "--verify", 1, 72, "fixture.c calls: realpath"},
        {"guarded", "--verify", 0, 72, "masked set:realpath"},
        {"comment", "--verify", 0, 72, "masked set:realpath"},
        {"empty", "--verify", 0, 72, "masks no candidate"},
        {"masked", "--selftest", 0, 72, "selftest: OK"},
        {"masked", NULL, 0, 72, "masked set:realpath"},
        {"initial", "--verify", 2, 1, "control probe does not compile"},
        {"final", "--verify", 2, 72, "control probe does not compile"},
        {"exec127", "--verify", 2, 3, "compiler invocation failed"},
        {"exec126", "--verify", 2, 3, "compiler invocation failed"},
        {"signal", "--verify", 2, 3, "compiler invocation failed"},
        {"fixture", "--verify", 2, 72, NULL}};
    char out[16384]; int bad = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; ++i) {
        out[0] = '\0';
        int rc = fmd_fake_run(dir, cases[i].mode, cases[i].arg, out, sizeof out);
        if (rc != cases[i].exit_code || fmd_trace_check(dir, cases[i].calls) ||
            (cases[i].expected && !strstr(out, cases[i].expected)) ||
            (!strcmp(cases[i].mode, "empty") && !strstr(out, "selftest uses a synthetic masked")) ||
            (cases[i].exit_code == 2 && strstr(out, "no unguarded caller"))) {
            fprintf(stderr, "fortify fake mode=%s rc=%d output=%s\n", cases[i].mode, rc, out);
            bad = 1;
        }
    }
    return bad;
}

struct fmd_saved_env { const char *name; char *value; bool present; };

static int fmd_env_save(struct fmd_saved_env *env, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        const char *value = getenv(env[i].name);
        env[i].present = value != NULL;
        if (value && !(env[i].value = strdup(value))) {
            while (i) free(env[--i].value);
            return 1;
        }
    }
    return 0;
}

static int fmd_env_restore(struct fmd_saved_env *env, size_t n)
{
    int bad = 0;
    for (size_t i = 0; i < n; ++i) {
        if (env[i].present && env[i].value) bad |= setenv(env[i].name, env[i].value, 1) != 0;
        else if (!env[i].present) bad |= unsetenv(env[i].name) != 0;
        free(env[i].value);
    }
    return bad;
}

static int fmd_spawn_isolated(const char *const argv[], const char *dir, char *out, size_t cap)
{
    struct fmd_saved_env env[] = {{"GIT_DIR", NULL, false}, {"GIT_INDEX_FILE", NULL, false},
        {"GIT_WORK_TREE", NULL, false}, {"GIT_COMMON_DIR", NULL, false},
        {"GIT_OBJECT_DIRECTORY", NULL, false}, {"GIT_ALTERNATE_OBJECT_DIRECTORIES", NULL, false}};
    size_t n = sizeof env / sizeof env[0];
    if (fmd_env_save(env, n)) return -1;
    int bad = 0;
    for (size_t i = 0; i < n; ++i) bad |= unsetenv(env[i].name) != 0;
    bool timeout = false;
    int rc = bad ? -1 : zcl_spawn_capture_merged_in_dir_observed(argv, dir, out, cap, 30000, &timeout);
    bad |= fmd_env_restore(env, n);
    return bad || timeout ? -1 : rc;
}

static int fmd_git_init(const char *dir)
{
    const char *init[] = {"git", "init", "-q", NULL};
    const char *add[] = {"git", "add", "fixture.c", NULL};
    char out[4096];
    if (fmd_fixture_source(dir, "empty") ||
        fmd_spawn_isolated(init, dir, out, sizeof out)) return 1;
    return fmd_spawn_isolated(add, dir, out, sizeof out);
}

static int fmd_poison_git(const char *foreign, char *index, size_t cap)
{
    char gitdir[PATH_MAX], objects[PATH_MAX];
    if (snprintf(gitdir, sizeof gitdir, "%s/.git", foreign) >= (int)sizeof gitdir ||
        snprintf(objects, sizeof objects, "%s/objects", gitdir) >= (int)sizeof objects ||
        snprintf(index, cap, "%s/index", gitdir) >= (int)cap) return 1;
    return setenv("GIT_DIR", gitdir, 1) || setenv("GIT_WORK_TREE", foreign, 1) ||
        setenv("GIT_INDEX_FILE", index, 1) || setenv("GIT_COMMON_DIR", gitdir, 1) ||
        setenv("GIT_OBJECT_DIRECTORY", objects, 1) || setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", objects, 1);
}

static int fmd_read_index(const char *path, unsigned char *buf, size_t cap, size_t *used)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 1;
    *used = fread(buf, 1, cap, f);
    int bad = ferror(f) || !feof(f);
    return bad | (fclose(f) != 0);
}

int t_fortify_combined_measurement(void)
{
    int failures = 0; char dir[PATH_MAX], cc[PATH_MAX], foreign[PATH_MAX], index[PATH_MAX];
    unsigned char before[8192], after[8192]; size_t n_before = 0, n_after = 0;
    struct fmd_saved_env env[] = {{"CC", NULL, false}, {"FMD_TRACE", NULL, false},
        {"FMD_CTL", NULL, false}, {"FMD_MODE", NULL, false}, {"GIT_DIR", NULL, false},
        {"GIT_INDEX_FILE", NULL, false}, {"GIT_WORK_TREE", NULL, false}, {"GIT_COMMON_DIR", NULL, false},
        {"GIT_OBJECT_DIRECTORY", NULL, false}, {"GIT_ALTERNATE_OBJECT_DIRECTORIES", NULL, false}};
    int saved = fmd_env_save(env, sizeof env / sizeof env[0]);
    TEST("[lint-gate] fortify combined measurement runs once and fails closed") {
        ASSERT(saved == 0);
        ASSERT(test_mkdtemp(dir, sizeof dir, "fortify_combined"));
        ASSERT(snprintf(foreign, sizeof foreign, "%s/foreign", dir) < (int)sizeof foreign);
        ASSERT(mkdir(foreign, 0700) == 0 && fmd_git_init(foreign) == 0);
        ASSERT(fmd_poison_git(foreign, index, sizeof index) == 0);
        ASSERT(fmd_read_index(index, before, sizeof before, &n_before) == 0);
        ASSERT(snprintf(cc, sizeof cc, "%s/cc", dir) < (int)sizeof cc);
        ASSERT(write_file(cc, k_fmd_fake) == 0 && chmod(cc, 0700) == 0);
        ASSERT(fmd_git_init(dir) == 0);
        ASSERT(fmd_fake_cases(dir) == 0);
        ASSERT(fmd_read_index(index, after, sizeof after, &n_after) == 0);
        ASSERT(n_before == n_after && memcmp(before, after, n_before) == 0);
        PASS();
    } _test_next:;
    if (!saved && fmd_env_restore(env, sizeof env / sizeof env[0])) ++failures;
    return failures;
}

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_def_unit;

#endif /* ZCL_TESTING */
