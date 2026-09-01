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

int check_deleted_engine_names_file(const char *path)
{
    if (strstr(path, "/tests/harness/include/test/") || strstr(path, "/contexts/explorer/views/"))
        return 0;

    const char *stale[] = {
        "connect_tip",
        "disconnect_tip",
        "activate_best_chain",
        "process_new_block",
        "accept_block()",
    };
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    bool block_comment = false;
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        char code[4096];
        size_t out = 0;
        for (size_t pos = 0; line[pos] && out + 1 < sizeof(code); pos++) {
            if (block_comment) {
                if (line[pos] == '*' && line[pos + 1] == '/') {
                    block_comment = false;
                    pos++;
                }
                continue;
            }
            if (line[pos] == '/' && line[pos + 1] == '*') {
                block_comment = true;
                pos++;
                continue;
            }
            if (line[pos] == '/' && line[pos + 1] == '/')
                break;
            code[out++] = line[pos];
        }
        code[out] = '\0';
        for (size_t i = 0; i < sizeof(stale) / sizeof(stale[0]); i++) {
            if (strstr(code, stale[i])) {
                fprintf(stderr,
                        "deleted engine name %s still present in %s\n",
                        stale[i], path);
                fclose(fp);
                return 1;
            }
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
           strstr(path, "/tests/harness/src/lint_gate_defensive_selftests.c");
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

/* Invokes tools/scripts/check_raw_malloc.sh and returns the script's
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
        execl(script, script, (char *)NULL);
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
              "tools/scripts/check_coins_lookup_nullcheck.sh",
              "ZCL_COINS_LOOKUP_SCAN_DIR",
              scan_dir)
        : -1;
    (void)unlink(fixture);
    (void)rmdir(scan_dir);

    int green_rc = run_gate_script(
        "tools/scripts/check_coins_lookup_nullcheck.sh", NULL);

    TEST("[lint-gate] coins lookup guard fails loud when lookup surface disappears") {
        ASSERT(planted == 0);
        ASSERT(trip_rc == 2);
        ASSERT(green_rc == 0);
        PASS();
    } _test_next:;
    return failures;
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

#else  /* !ZCL_TESTING */

/* Without ZCL_TESTING the lint-gate self-tests compile to nothing; this
 * keeps the translation unit non-empty. */
typedef int zcl_lint_gate_def_unit;

#endif /* ZCL_TESTING */
