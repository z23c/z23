/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_agent_baseline against a private git fixture. */

#include "test/test_core.h"

#include "agent_baseline.h"

#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_make[] =
    "# check-before\n"
    "prelude check-nope\n"
    "LINT_GATES := check-header \\\n"
    "    check-alpha \\   \n"
    "    skipped-token \\\n"
    "    check-beta\n"
    "check-after \\\n"
    "LINT_GATES := \\\n"
    "    check-ignored\n";

static const char k_counter[] = "#!/bin/sh\nprintf '4\\n'\n";

struct abt_env {
    char gates[256];
    char files[2048];
    int have_gates;
    int have_files;
};

static void abt_save(struct abt_env *env)
{
    const char *gates = getenv("ZCL_BASELINE_LINT_GATES");
    const char *files = getenv("BASELINE_FILES");
    env->have_gates = 0;
    env->have_files = 0;
    env->gates[0] = '\0';
    env->files[0] = '\0';
    if (gates != NULL && strlen(gates) < sizeof env->gates) {
        memcpy(env->gates, gates, strlen(gates) + 1);
        env->have_gates = 1;
    }
    if (files != NULL && strlen(files) < sizeof env->files) {
        memcpy(env->files, files, strlen(files) + 1);
        env->have_files = 1;
    }
}

static void abt_restore(const struct abt_env *env)
{
    if (env->have_gates)
        setenv("ZCL_BASELINE_LINT_GATES", env->gates, 1);
    else
        unsetenv("ZCL_BASELINE_LINT_GATES");
    if (env->have_files)
        setenv("BASELINE_FILES", env->files, 1);
    else
        unsetenv("BASELINE_FILES");
}

static void abt_clear(void)
{
    unsetenv("ZCL_BASELINE_LINT_GATES");
    unsetenv("BASELINE_FILES");
}

static int abt_write(const char *path, const char *body, mode_t mode)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(body, fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    if (mode != 0 && chmod(path, mode) != 0)
        return -1;
    return 0;
}

static int abt_cmd(const char *cmd, char *out, size_t cap)
{
    FILE *fp = popen(cmd, "r");
    size_t n = 0;
    if (fp == NULL || cap < 2)
        return -1;
    while (n + 1 < cap) {
        size_t got = fread(out + n, 1, cap - 1 - n, fp);
        if (got == 0)
            break;
        n += got;
    }
    out[n] = '\0';
    while (n > 0 && out[n - 1] == '\n')
        out[--n] = '\0';
    if (pclose(fp) != 0)
        return -1;
    return 0;
}

static int abt_field(const char *text, const char *key, char *out, size_t cap)
{
    char needle[160];
    const char *hit;
    size_t k = strlen(key);
    size_t n = 0;
    int wrote;
    if (strncmp(text, key, k) == 0 && text[k] == '=') {
        hit = text + k + 1;
    } else {
        wrote = snprintf(needle, sizeof needle, "\n%s=", key);
        if (wrote < 0 || (size_t)wrote >= sizeof needle)
            return -1;
        hit = strstr(text, needle);
        if (hit == NULL)
            return -1;
        hit += (size_t)wrote;
    }
    while (hit[n] != '\0' && hit[n] != '\n') {
        if (n + 1 >= cap)
            return -1;
        out[n] = hit[n];
        n++;
    }
    out[n] = '\0';
    return 0;
}

static int abt_capture(const char *root, int argc, char **files, const char *log,
                       char *got, size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved = dup(STDOUT_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved < 0)
        goto fail;
    fflush(stdout);
    if (dup2(fd, STDOUT_FILENO) < 0)
        goto fail;
    *rc = zcl_agent_baseline(root, argc, files);
    fflush(stdout);
    dup2(saved, STDOUT_FILENO);
    close(saved);
    close(fd);
    file = fopen(log, "r");
    if (file == NULL)
        return -1;
    used = fread(got, 1, cap - 1, file);
    fclose(file);
    if (used == cap - 1)
        return -1;
    got[used] = '\0';
    return 0;
fail:
    if (saved >= 0) {
        dup2(saved, STDOUT_FILENO);
        close(saved);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int abt_join(char *dst, size_t cap, const char *dir, const char *name)
{
    int wrote = snprintf(dst, cap, "%s/%s", dir, name);
    if (wrote < 0 || (size_t)wrote >= cap)
        return -1;
    return 0;
}

/* Beside the fixture, not inside it: a log created before the pin runs
 * would otherwise show up in git status. */
static int abt_log(const char *repo, const char *tag, char *out, size_t cap)
{
    int wrote = snprintf(out, cap, "%s-%s.log", repo, tag);
    if (wrote < 0 || (size_t)wrote >= cap)
        return -1;
    return 0;
}

static int abt_setup(const char *repo)
{
    char cmd[2400];
    char path[1200];
    char link[1200];
    int n = snprintf(cmd, sizeof cmd,
                     "git init -q -b main '%s' && "
                     "git -C '%s' config user.name agent-baseline-test && "
                     "git -C '%s' config user.email agent-baseline-test@example.invalid && "
                     "git -C '%s' config commit.gpgsign false && "
                     "mkdir -p '%s/build/bin'",
                     repo, repo, repo, repo, repo);
    if (n < 0 || (size_t)n >= sizeof cmd || system(cmd) != 0)
        return -1;
    if (abt_join(path, sizeof path, repo, "pin.txt") != 0)
        return -1;
    if (abt_write(path, "pin\n", 0644) != 0)
        return -1;
    if (abt_join(path, sizeof path, repo, "Makefile") != 0)
        return -1;
    if (abt_write(path, k_make, 0644) != 0)
        return -1;
    if (abt_join(path, sizeof path, repo, "build/bin/test-group-list") != 0)
        return -1;
    if (abt_write(path, k_counter, 0755) != 0)
        return -1;
    if (abt_join(link, sizeof link, repo, "link.txt") != 0)
        return -1;
    if (symlink("pin.txt", link) != 0)
        return -1;
    n = snprintf(cmd, sizeof cmd,
                 "git -C '%s' add -A && git -C '%s' commit -q --no-verify -m pin",
                 repo, repo);
    if (n < 0 || (size_t)n >= sizeof cmd || system(cmd) != 0)
        return -1;
    return 0;
}

static int abt_digest(const char *path, char *out, size_t cap)
{
    char cmd[1400];
    char raw[PATH_MAX + 96];
    char *sp;
    int n = snprintf(cmd, sizeof cmd, "sha256sum -- '%s'", path);
    if (n < 0 || (size_t)n >= sizeof cmd)
        return -1;
    if (abt_cmd(cmd, raw, sizeof raw) != 0)
        return -1;
    sp = strchr(raw, ' ');
    if (sp != NULL)
        *sp = '\0';
    if (strlen(raw) + 1 > cap)
        return -1;
    memcpy(out, raw, strlen(raw) + 1);
    return 0;
}

static int test_abl_missing(const char *repo)
{
    struct abt_env saved;
    char log[1200];
    int failures = 0;
    abt_save(&saved);
    abt_clear();
    if (abt_log(repo, "missing", log, sizeof log) != 0)
        return 1;
    TEST("agent baseline: missing file fails and a symlink shares the digest") {
        char abs[1200];
        char pin[1200];
        char got[8192];
        char digest[80];
        char field[PATH_MAX];
        char *files[4];
        int rc = 0;
        ASSERT(abt_join(abs, sizeof abs, repo, "pin.txt") == 0);
        ASSERT(abt_join(pin, sizeof pin, repo, "pin.txt") == 0);
        ASSERT(abt_digest(pin, digest, sizeof digest) == 0);
        files[0] = "pin.txt";
        files[1] = "gone.txt";
        files[2] = "link.txt";
        files[3] = abs;
        ASSERT(abt_capture(repo, 4, files, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(abt_field(got, "baseline_schema", field, sizeof field) == 0);
        ASSERT(strcmp(field, "zcl.agent_baseline.v1") == 0);
        ASSERT(abt_field(got, "repo_root", field, sizeof field) == 0);
        ASSERT(strcmp(field, repo) == 0);
        ASSERT(abt_field(got, "tree_dirty", field, sizeof field) == 0);
        ASSERT(strcmp(field, "0") == 0);
        ASSERT(abt_field(got, "tree_dirty_files", field, sizeof field) == 0);
        ASSERT(strcmp(field, "0") == 0);
        ASSERT(abt_field(got, "registered_test_groups", field, sizeof field) == 0);
        ASSERT(strcmp(field, "4") == 0);
        ASSERT(abt_field(got, "lint_gates", field, sizeof field) == 0);
        ASSERT(strcmp(field, "3") == 0);
        ASSERT(strstr(got, "lint_gates_parse_mismatch=") == NULL);
        ASSERT(abt_field(got, "baseline_file_count", field, sizeof field) == 0);
        ASSERT(strcmp(field, "4") == 0);
        ASSERT(abt_field(got, "sha256.pin.txt", field, sizeof field) == 0);
        ASSERT(strcmp(field, digest) == 0);
        ASSERT(abt_field(got, "sha256.gone.txt", field, sizeof field) == 0);
        ASSERT(strcmp(field, "MISSING") == 0);
        ASSERT(abt_field(got, "sha256.link.txt", field, sizeof field) == 0);
        ASSERT(strcmp(field, digest) == 0);
        ASSERT(snprintf(pin, sizeof pin, "sha256.%s", abs) > 0);
        ASSERT(abt_field(got, pin, field, sizeof field) == 0);
        ASSERT(strcmp(field, digest) == 0);
        PASS();
    } _test_next:;
    (void)unlink(log);
    abt_restore(&saved);
    return failures;
}

static int test_abl_ok(const char *repo)
{
    struct abt_env saved;
    char log[1200];
    int failures = 0;
    abt_save(&saved);
    abt_clear();
    if (abt_log(repo, "ok", log, sizeof log) != 0)
        return 1;
    TEST("agent baseline: a clean tree matches git, the counter, and sha256sum") {
        char pin[1200];
        char cmd[1400];
        char got[8192];
        char want[8192];
        char head[160];
        char branch[160];
        char base[160];
        char ahead[64];
        char brief[16];
        char digest[80];
        char *files[1];
        int rc = 1;
        int n;
        size_t i;
        ASSERT(abt_join(pin, sizeof pin, repo, "pin.txt") == 0);
        ASSERT(abt_digest(pin, digest, sizeof digest) == 0);
        ASSERT(snprintf(cmd, sizeof cmd, "git -C '%s' rev-parse HEAD", repo) > 0);
        ASSERT(abt_cmd(cmd, head, sizeof head) == 0);
        ASSERT(snprintf(cmd, sizeof cmd, "git -C '%s' rev-parse --abbrev-ref HEAD",
                        repo) > 0);
        ASSERT(abt_cmd(cmd, branch, sizeof branch) == 0);
        ASSERT(snprintf(cmd, sizeof cmd, "git -C '%s' merge-base HEAD main", repo) > 0);
        ASSERT(abt_cmd(cmd, base, sizeof base) == 0);
        ASSERT(snprintf(cmd, sizeof cmd, "git -C '%s' rev-list --count main..HEAD",
                        repo) > 0);
        ASSERT(abt_cmd(cmd, ahead, sizeof ahead) == 0);
        for (i = 0; i < 9 && head[i] != '\0'; i++)
            brief[i] = head[i];
        brief[i] = '\0';
        n = snprintf(want, sizeof want,
                     "baseline_schema=zcl.agent_baseline.v1\n"
                     "repo_root=%s\n"
                     "head_sha=%s\n"
                     "head_short=%s\n"
                     "branch=%s\n"
                     "tree_dirty=0\n"
                     "tree_dirty_files=0\n"
                     "merge_base_main=%s\n"
                     "commits_ahead_of_main=%s\n"
                     "registered_test_groups=4\n"
                     "lint_gates=3\n"
                     "baseline_file_count=1\n"
                     "sha256.pin.txt=%s\n",
                     repo, head, brief, branch, base, ahead, digest);
        ASSERT(n > 0 && (size_t)n < sizeof want);
        files[0] = "pin.txt";
        ASSERT(abt_capture(repo, 1, files, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strcmp(got, want) == 0);
        PASS();
    } _test_next:;
    (void)unlink(log);
    abt_restore(&saved);
    return failures;
}

static int test_abl_gates(const char *repo)
{
    struct abt_env saved;
    char log[1200];
    int failures = 0;
    abt_save(&saved);
    abt_clear();
    if (abt_log(repo, "gates", log, sizeof log) != 0)
        return 1;
    TEST("agent baseline: lint gate env matches, mismatches, or stays empty") {
        char got[8192];
        char field[64];
        char *pin[1];
        int rc = 0;
        pin[0] = "pin.txt";
        ASSERT(setenv("ZCL_BASELINE_LINT_GATES", "3", 1) == 0);
        ASSERT(abt_capture(repo, 1, pin, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(abt_field(got, "lint_gates", field, sizeof field) == 0);
        ASSERT(strcmp(field, "3") == 0);
        ASSERT(strstr(got, "lint_gates_parse_mismatch=") == NULL);
        ASSERT(setenv("ZCL_BASELINE_LINT_GATES", "99", 1) == 0);
        ASSERT(abt_capture(repo, 0, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(abt_field(got, "lint_gates", field, sizeof field) == 0);
        ASSERT(strcmp(field, "99") == 0);
        ASSERT(abt_field(got, "lint_gates_parse_mismatch", field, sizeof field) == 0);
        ASSERT(strcmp(field, "3") == 0);
        ASSERT(abt_field(got, "baseline_file_count", field, sizeof field) == 0);
        ASSERT(strcmp(field, "0") == 0);
        ASSERT(setenv("ZCL_BASELINE_LINT_GATES", "", 1) == 0);
        ASSERT(abt_capture(repo, 0, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(abt_field(got, "lint_gates", field, sizeof field) == 0);
        ASSERT(strcmp(field, "3") == 0);
        ASSERT(strstr(got, "lint_gates_parse_mismatch=") == NULL);
        PASS();
    } _test_next:;
    (void)unlink(log);
    abt_restore(&saved);
    return failures;
}

static int test_abl_env_files(const char *repo)
{
    struct abt_env saved;
    char log[1200];
    int failures = 0;
    abt_save(&saved);
    abt_clear();
    if (abt_log(repo, "env", log, sizeof log) != 0)
        return 1;
    TEST("agent baseline: BASELINE_FILES splits and argv wins") {
        char got[8192];
        char field[128];
        char *pin[1];
        int rc = 0;
        ASSERT(setenv("BASELINE_FILES", "pin.txt\tgone.txt\nlink.txt", 1) == 0);
        ASSERT(abt_capture(repo, 0, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(abt_field(got, "baseline_file_count", field, sizeof field) == 0);
        ASSERT(strcmp(field, "3") == 0);
        ASSERT(abt_field(got, "sha256.gone.txt", field, sizeof field) == 0);
        ASSERT(strcmp(field, "MISSING") == 0);
        ASSERT(abt_field(got, "sha256.link.txt", field, sizeof field) == 0);
        ASSERT(strcmp(field, "MISSING") != 0);
        pin[0] = "pin.txt";
        ASSERT(setenv("BASELINE_FILES", "gone.txt", 1) == 0);
        ASSERT(abt_capture(repo, 1, pin, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(abt_field(got, "baseline_file_count", field, sizeof field) == 0);
        ASSERT(strcmp(field, "1") == 0);
        ASSERT(strstr(got, "sha256.gone.txt=") == NULL);
        ASSERT(abt_field(got, "sha256.pin.txt", field, sizeof field) == 0);
        ASSERT(strcmp(field, "MISSING") != 0);
        PASS();
    } _test_next:;
    (void)unlink(log);
    abt_restore(&saved);
    return failures;
}

static int test_abl_counter(const char *repo)
{
    struct abt_env saved;
    char path[1200];
    char log[1200];
    int failures = 0;
    abt_save(&saved);
    abt_clear();
    if (abt_join(path, sizeof path, repo, "build/bin/test-group-list") != 0)
        return 1;
    if (abt_log(repo, "counter", log, sizeof log) != 0)
        return 1;
    TEST("agent baseline: a failing or missing counter is UNKNOWN") {
        char got[8192];
        char field[64];
        int rc = 0;
        ASSERT(abt_write(path, "#!/bin/sh\nprintf '9\\n'\nexit 3\n", 0755) == 0);
        ASSERT(abt_capture(repo, 0, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(abt_field(got, "registered_test_groups", field, sizeof field) == 0);
        ASSERT(strcmp(field, "UNKNOWN") == 0);
        ASSERT(strstr(got, "registered_test_groups=9") == NULL);
        ASSERT(unlink(path) == 0);
        ASSERT(abt_capture(repo, 0, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT(abt_field(got, "registered_test_groups", field, sizeof field) == 0);
        ASSERT(strcmp(field, "UNKNOWN") == 0);
        PASS();
    } _test_next:;
    (void)unlink(log);
    (void)abt_write(path, k_counter, 0755);
    abt_restore(&saved);
    return failures;
}

static int test_abl_dirty(const char *repo)
{
    struct abt_env saved;
    char extra[1200];
    char log[1200];
    int failures = 0;
    abt_save(&saved);
    abt_clear();
    if (abt_join(extra, sizeof extra, repo, "extra.txt") != 0)
        return 1;
    if (abt_log(repo, "dirty", log, sizeof log) != 0)
        return 1;
    TEST("agent baseline: porcelain lines count as a dirty tree") {
        char cmd[1400];
        char got[8192];
        char field[64];
        char counted[64];
        size_t r;
        size_t w = 0;
        int rc = 0;
        ASSERT(abt_write(extra, "extra\n", 0644) == 0);
        ASSERT(abt_capture(repo, 0, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(abt_field(got, "tree_dirty", field, sizeof field) == 0);
        ASSERT(strcmp(field, "1") == 0);
        ASSERT(snprintf(cmd, sizeof cmd, "git -C '%s' status --porcelain | wc -l",
                        repo) > 0);
        ASSERT(abt_cmd(cmd, counted, sizeof counted) == 0);
        for (r = 0; counted[r] != '\0'; r++) {
            if (counted[r] != ' ')
                counted[w++] = counted[r];
        }
        counted[w] = '\0';
        ASSERT(abt_field(got, "tree_dirty_files", field, sizeof field) == 0);
        ASSERT(strcmp(field, counted) == 0);
        PASS();
    } _test_next:;
    (void)unlink(log);
    (void)unlink(extra);
    abt_restore(&saved);
    return failures;
}

static int test_abl_unreadable(const char *repo)
{
    struct abt_env saved;
    char locked[1200];
    char after[1200];
    char log[1200];
    int failures = 0;
    abt_save(&saved);
    abt_clear();
    if (abt_join(locked, sizeof locked, repo, "locked.txt") != 0)
        return 1;
    if (abt_join(after, sizeof after, repo, "after.txt") != 0)
        return 1;
    if (abt_log(repo, "locked", log, sizeof log) != 0)
        return 1;
    TEST("agent baseline: a digest tool failure does not pretend the file is missing") {
        char rel_locked[] = "locked.txt";
        char rel_after[] = "after.txt";
        char *files[2];
        char got[8192];
        int rc = 0;
        ASSERT(abt_write(locked, "secret\n", 0644) == 0);
        ASSERT(abt_write(after, "later\n", 0644) == 0);
        ASSERT(chmod(locked, 0) == 0);
        files[0] = rel_locked;
        files[1] = rel_after;
        ASSERT(abt_capture(repo, 2, files, log, got, sizeof got, &rc) == 0);
        ASSERT(strstr(got, "baseline_file_count=2\n") != NULL);
        if (geteuid() == 0) {
            ASSERT(rc == 0);
            ASSERT(strstr(got, "sha256.locked.txt=") != NULL);
            ASSERT(strstr(got, "sha256.locked.txt=MISSING") == NULL);
            ASSERT(strstr(got, "sha256.after.txt=") != NULL);
        } else {
            ASSERT(rc == 1);
            ASSERT(strstr(got, "sha256.locked.txt=") == NULL);
            ASSERT(strstr(got, "sha256.after.txt=") == NULL);
        }
        PASS();
    } _test_next:;
    (void)unlink(log);
    (void)chmod(locked, 0644);
    (void)unlink(locked);
    (void)unlink(after);
    abt_restore(&saved);
    return failures;
}

static int test_abl_no_makefile(void)
{
    struct abt_env saved;
    char dir[1024];
    char log[1200];
    char cmd[1400];
    int failures = 0;
    abt_save(&saved);
    abt_clear();
    test_make_tmpdir(dir, sizeof dir, "agent_baseline", "bare");
    if (abt_log(dir, "bare", log, sizeof log) != 0)
        return 1;
    TEST("agent baseline: a missing Makefile aborts like awk") {
        char got[8192];
        char field[64];
        int rc = 0;
        int n = snprintf(cmd, sizeof cmd, "git init -q -b main '%s'", dir);
        ASSERT(n > 0 && (size_t)n < sizeof cmd);
        ASSERT(system(cmd) == 0);
        ASSERT(abt_capture(dir, 0, NULL, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT(abt_field(got, "head_sha", field, sizeof field) == 0);
        ASSERT(strcmp(field, "UNKNOWN") == 0);
        ASSERT(abt_field(got, "head_short", field, sizeof field) == 0);
        ASSERT(strcmp(field, "UNKNOWN") == 0);
        ASSERT(strstr(got, "\nlint_gates=") == NULL);
        ASSERT(strstr(got, "registered_test_groups=UNKNOWN\n") != NULL);
        PASS();
    } _test_next:;
    (void)unlink(log);
    (void)test_rm_rf_recursive(dir);
    abt_restore(&saved);
    return failures;
}

int test_agent_baseline(void);
int test_agent_baseline(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "agent_baseline", "root");
    if (abt_setup(dir) != 0) {
        printf("test_agent_baseline: setup failed\n");
        (void)test_rm_rf_recursive(dir);
        return 1;
    }
    failures = test_abl_missing(dir);
    failures += test_abl_ok(dir);
    failures += test_abl_gates(dir);
    failures += test_abl_env_files(dir);
    failures += test_abl_dirty(dir);
    failures += test_abl_counter(dir);
    failures += test_abl_unreadable(dir);
    failures += test_abl_no_makefile();
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_agent_baseline: all passed\n");
    else
        printf("test_agent_baseline: %d FAILED\n", failures);
    return failures;
}
