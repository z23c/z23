/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `z23 <developer command>` hands off to the z23-dev beside it (interactive
 * CLI only). Each case forks a child that arms the handoff exactly as
 * cli_main does and runs the real zcl_native_command_main; the sibling is a
 * tiny fixture binary in a temp directory, found through the test seam that
 * stands in for "the directory of the running executable". The test binary
 * is a release-profile build, so dev.land.check_offer is a COMPAT leaf here. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_command_handoff.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "util/spawn.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define NDH_FIXTURE_EXIT 37

enum ndh_env { NDH_ENV_NONE, NDH_ENV_OPT_OUT, NDH_ENV_GUARD };

struct ndh_result {
    int exit_code;
    char out[8192];
    char err[2048];
};

static bool ndh_slurp(const char *path, char *buf, size_t cap)
{
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    size_t n = fread(buf, 1, cap - 1, f);
    buf[n] = '\0';
    return fclose(f) == 0;
}

static bool ndh_write(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    ok = fclose(f) == 0 && ok;
    return ok && chmod(path, mode) == 0;
}

/* Compile the fixture sibling: it echoes its argv words, then reports the
 * handoff guard it inherited on stderr and exits NDH_FIXTURE_EXIT. */
static bool ndh_build_fixture(const char *dir, const char *out)
{
    char src[1100], text[512];
    (void)snprintf(src, sizeof(src), "%s/fixture.c", dir);
    (void)snprintf(text, sizeof(text),
        "#include <stdio.h>\n#include <stdlib.h>\n"
        "int main(int argc, char **argv)\n{\n"
        "    printf(\"HANDOFF\");\n"
        "    for (int i = 1; i < argc; i++) printf(\" %%s\", argv[i]);\n"
        "    printf(\"\\n\");\n"
        "    const char *g = getenv(\"ZCL_DEV_HANDOFF_ACTIVE\");\n"
        "    fprintf(stderr, \"guard=%%s\\n\", g ? g : \"unset\");\n"
        "    return %d;\n}\n", NDH_FIXTURE_EXIT);
    if (!ndh_write(src, text, 0600))
        return false;
    const char *argv[] = {"cc", "-std=c23", "-O0", src, "-o", out, NULL};
    char log[2048];
    int rc = zcl_spawn_capture(argv, log, sizeof(log), 60000);
    if (rc != 0)
        printf("handoff fixture compile failed: rc=%d %s\n", rc, log);
    return rc == 0 && chmod(out, 0755) == 0;
}

static void ndh_child(const char *dir, bool armed, enum ndh_env env,
                      const char *const *words, int count, const char *out_path,
                      const char *err_path)
{
    int out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    int err = open(err_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0 || err < 0 || dup2(out, STDOUT_FILENO) < 0 ||
        dup2(err, STDERR_FILENO) < 0)
        _exit(120);
    (void)unsetenv("ZCL_NO_DEV_HANDOFF");
    (void)unsetenv("ZCL_DEV_HANDOFF_ACTIVE");
    if (env == NDH_ENV_OPT_OUT)
        (void)setenv("ZCL_NO_DEV_HANDOFF", "1", 1);
    if (env == NDH_ENV_GUARD)
        (void)setenv("ZCL_DEV_HANDOFF_ACTIVE", "1", 1);
    zcl_native_handoff_set_dir_for_test(dir);
    if (armed)
        zcl_native_handoff_arm(count, (char *const *)words);
    int rc = zcl_native_command_main(words[1], words + 2, count - 2, "", 0,
                                     CHAIN_MAIN, false);
    (void)fflush(NULL);
    _exit(rc);
}

/* words[0] is the program name, as in argv. */
static bool ndh_run(const char *dir, const char *scratch, bool armed,
                    enum ndh_env env, const char *const *words, int count,
                    struct ndh_result *res)
{
    char out_path[1100], err_path[1100];
    (void)snprintf(out_path, sizeof(out_path), "%s/stdout.txt", scratch);
    (void)snprintf(err_path, sizeof(err_path), "%s/stderr.txt", scratch);
    (void)fflush(NULL);
    pid_t pid = fork();
    if (pid < 0)
        return false;
    if (pid == 0)
        ndh_child(dir, armed, env, words, count, out_path, err_path);
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
        return false;
    res->exit_code = WEXITSTATUS(status);
    return ndh_slurp(out_path, res->out, sizeof(res->out)) &&
           ndh_slurp(err_path, res->err, sizeof(res->err));
}

static bool ndh_refused_with_new_text(const struct ndh_result *r)
{
    return r->exit_code == ZCL_COMMAND_EXIT_BLOCKED &&
           strstr(r->out, "COMMAND_COMPAT_ONLY") &&
           strstr(r->out, "this command runs in the developer build") &&
           strstr(r->out, "z23-dev dev land check_offer") &&
           strstr(r->out, "make z23-dev") && !strstr(r->out, "not executable yet");
}

int test_native_dev_handoff(void);
int test_native_dev_handoff(void)
{
    int failures = 0;
    char base[900], sibling[1000], empty[1000];
    test_make_tmpdir(base, sizeof(base), "native_dev_handoff", "rig");
    (void)snprintf(sibling, sizeof(sibling), "%s/bin", base);
    (void)snprintf(empty, sizeof(empty), "%s/none", base);
    if (mkdir(sibling, 0700) != 0 || mkdir(empty, 0700) != 0) {
        printf("handoff rig setup FAILED\n");
        return 1;
    }
    char fake[1100];
    (void)snprintf(fake, sizeof(fake), "%s/z23-dev", sibling);
    if (!ndh_build_fixture(sibling, fake)) {
        printf("handoff fixture build FAILED\n");
        return 1;
    }
    const char *const words[] = {"z23", "dev", "land", "check_offer", "--bundle=/x/a b.bundle", "--offer=/x/o.json"};
    const int count = 6;
    struct ndh_result r;

    TEST("handoff: a trusted z23-dev beside z23 replaces the process, keeps args and exit code") {
        ASSERT(ndh_run(sibling, base, true, NDH_ENV_NONE, words, count, &r));
        ASSERT_EQ(r.exit_code, NDH_FIXTURE_EXIT);
        ASSERT(strstr(r.out, "HANDOFF dev land check_offer --bundle=/x/a b.bundle --offer=/x/o.json\n") != NULL);
        ASSERT(strstr(r.err, "guard=1") != NULL);
        PASS();
    }
    TEST("handoff: an absent sibling keeps COMMAND_COMPAT_ONLY with a runnable hint") {
        ASSERT(ndh_run(empty, base, true, NDH_ENV_NONE, words, count, &r));
        ASSERT(ndh_refused_with_new_text(&r));
        PASS();
    }
    TEST("handoff: a group-writable sibling is refused and named on stderr") {
        ASSERT_EQ(chmod(fake, 0775), 0);
        ASSERT(ndh_run(sibling, base, true, NDH_ENV_NONE, words, count, &r));
        ASSERT(ndh_refused_with_new_text(&r));
        ASSERT(strstr(r.err, "group or world writable") != NULL);
        ASSERT_EQ(chmod(fake, 0755), 0);
        PASS();
    }
    TEST("handoff: a sibling owned by another user is refused and named on stderr") {
        if (geteuid() != 0) {
            printf("  (skipped: faking st_uid needs root chown; the seam only redirects the directory)\n");
        } else {
            ASSERT_EQ(chown(fake, 65534, (gid_t)-1), 0);
            ASSERT(ndh_run(sibling, base, true, NDH_ENV_NONE, words, count, &r));
            ASSERT(ndh_refused_with_new_text(&r));
            ASSERT(strstr(r.err, "owned by another user") != NULL);
            ASSERT_EQ(chown(fake, 0, (gid_t)-1), 0);
        }
        PASS();
    }
    TEST("handoff: zcl_native_handoff_arm has exactly one non-test caller, cli_main") {
        const char *argv[] = {"git", "grep", "-n", "-w", "zcl_native_handoff_arm", "--",
            "engine", "platform", "tools", "apps", "contexts", "cognition", "core",
            ":!tools/command/native_command_handoff.c",
            ":!tools/command/native_command_handoff.h", NULL};
        char hits[4096];
        int rc = zcl_spawn_capture(argv, hits, sizeof(hits), 60000);
        ASSERT_EQ(rc, 0);
        ASSERT(strstr(hits, "engine/entry/main_cli_modes.c:") != NULL);
        const char *nl = strchr(hits, 10);
        ASSERT(nl != NULL && nl[1] == 0);
        PASS();
    }
    TEST("handoff: a symlinked sibling is refused") {
        char real[1100], link[1100];
        (void)snprintf(real, sizeof(real), "%s/z23-dev", sibling);
        (void)snprintf(link, sizeof(link), "%s/z23-dev", empty);
        ASSERT_EQ(symlink(real, link), 0);
        ASSERT(ndh_run(empty, base, true, NDH_ENV_NONE, words, count, &r));
        ASSERT(ndh_refused_with_new_text(&r));
        ASSERT(strstr(r.err, "symlink") != NULL);
        ASSERT_EQ(unlink(link), 0);
        PASS();
    }
    TEST("handoff: ZCL_NO_DEV_HANDOFF=1 restores the refusal") {
        ASSERT(ndh_run(sibling, base, true, NDH_ENV_OPT_OUT, words, count, &r));
        ASSERT(ndh_refused_with_new_text(&r));
        PASS();
    }
    TEST("handoff: the loop guard stops a sibling from handing back") {
        ASSERT(ndh_run(sibling, base, true, NDH_ENV_GUARD, words, count, &r));
        ASSERT(ndh_refused_with_new_text(&r));
        PASS();
    }
    TEST("handoff: a process that never called zcl_native_handoff_arm refuses even with a sibling present") {
        ASSERT(ndh_run(sibling, base, false, NDH_ENV_NONE, words, count, &r));
        ASSERT(ndh_refused_with_new_text(&r));
        PASS();
    }
    TEST("handoff: registry execution never hands off even with a sibling and an armed CLI") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        const struct zcl_command_spec *spec =
            zcl_command_registry_find(reg, "dev.land.check_offer", NULL);
        ASSERT(spec != NULL);
        ASSERT(spec->handler == NULL);
        zcl_native_handoff_set_dir_for_test(sibling);
        zcl_native_handoff_arm(count, (char *const *)words);
        struct zcl_command_context ctx = {.registry = reg,
            .granted_capabilities = ~(uint64_t)0,
            .authority_ceiling = ZCL_COMMAND_AUTH_OWNER, .operator_lane = "dev"};
        struct json_value input;
        json_init(&input);
        json_set_object(&input);
        char wire[8192];
        enum zcl_command_exit code = ZCL_COMMAND_EXIT_OK;
        size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input, false,
            spec->path, NULL, 0, 0, NULL, wire, sizeof(wire), &code);
        json_free(&input);
        zcl_native_handoff_arm(0, NULL);
        zcl_native_handoff_set_dir_for_test(NULL);
        ASSERT(n > 0);
        ASSERT_EQ(code, ZCL_COMMAND_EXIT_BLOCKED);
        ASSERT(strstr(wire, "COMMAND_COMPAT_ONLY") != NULL);
        ASSERT(strstr(wire, "this command runs in the developer build") != NULL);
        PASS();
    }

_test_next:;
    (void)test_rm_rf_recursive(base);
    if (failures == 0)
        printf("test_native_dev_handoff: all passed\n");
    else
        printf("test_native_dev_handoff: %d FAILED\n", failures);
    return failures;
}
