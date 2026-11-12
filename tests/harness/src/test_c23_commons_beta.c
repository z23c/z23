/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_c23_commons_beta with a stand-in make and acceptance script. */

#include "test/test_core.h"

#include "c23_commons_beta.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_make[] =
    "#!/bin/sh\n"
    "printf '%s\\n' \"$*\" >> make.log\n"
    "if [ -f make-fail ]; then exit 3; fi\n"
    "dest=\n"
    "repo=\n"
    "prev=\n"
    "for a in \"$@\"; do\n"
    "  case \"$a\" in\n"
    "    DESTDIR=*) dest=${a#DESTDIR=} ;;\n"
    "  esac\n"
    "  if [ \"$prev\" = -C ]; then repo=$a; fi\n"
    "  prev=$a\n"
    "done\n"
    "case \" $* \" in\n"
    "  *' c23-portable-install '*)\n"
    "    mkdir -p \"$dest/bin\"\n"
    "    for p in zclassic23 zcl-rpc zclassic23-package-sign zclassic23-package-verify; do\n"
    "      if [ -f skip-rpc ] && [ \"$p\" = zcl-rpc ]; then continue; fi\n"
    "      printf 'bin\\n' > \"$dest/bin/$p\"\n"
    "      chmod 0755 \"$dest/bin/$p\"\n"
    "    done ;;\n"
    "esac\n"
    "case \" $* \" in\n"
    "  *' tools/arena-product-journey-c23 '*|*' tools/arena-runner '*)\n"
    "    mkdir -p \"$repo/build/bin\"\n"
    "    if printf '%s\\n' \"$*\" | grep -q arena-product-journey-c23; then\n"
    "      printf 'j\\n' > \"$repo/build/bin/arena_product_journey_c23\"\n"
    "      chmod 0755 \"$repo/build/bin/arena_product_journey_c23\"\n"
    "    fi\n"
    "    if printf '%s\\n' \"$*\" | grep -q 'tools/arena-runner'; then\n"
    "      printf 'r\\n' > \"$repo/build/bin/arena_runner\"\n"
    "      printf 'd\\n' > \"$repo/build/bin/zclassic23-dev\"\n"
    "      chmod 0755 \"$repo/build/bin/arena_runner\" \"$repo/build/bin/zclassic23-dev\"\n"
    "    fi ;;\n"
    "esac\n"
    "exit 0\n";

static const char k_accept[] =
    "#!/bin/sh\n"
    "seen=\"$CBT_SEEN\"\n"
    "{\n"
    "  printf 'cwd=%s\\n' \"$(pwd)\"\n"
    "  printf 'node=%s\\n' \"$ZCL_NODE_BIN\"\n"
    "  printf 'rpc=%s\\n' \"$ZCL_RPC_BIN\"\n"
    "  printf 'dht=%s\\n' \"$DHT_ACCEPTANCE_C23\"\n"
    "  printf 'work=%s\\n' \"$DHT_WORK_PARENT\"\n"
    "  printf 'params=%s\\n' \"$DHT_PARAMS_DIR\"\n"
    "  printf 'host=%s\\n' \"$DHT_PACKAGEHOST\"\n"
    "  printf 'workers=%s\\n' \"$DHT_BUILDWORKERS\"\n"
    "  printf 'keep=%s\\n' \"$DHT_KEEP\"\n"
    "  printf 'hook=%s\\n' \"$DHT_AFTER_SPARSE_HOOK\"\n"
    "  printf 'src=%s\\n' \"$C23_BETA_FIXTURE_SOURCE\"\n"
    "  printf 'install=%s\\n' \"$C23_BETA_INSTALL_BIN\"\n"
    "  if [ -x \"$C23_BETA_INSTALL_BIN/arena_runner\" ]; then printf 'runner=yes\\n'; else printf 'runner=no\\n'; fi\n"
    "  if [ -x \"$C23_BETA_DEV_BIN\" ]; then printf 'dev=yes\\n'; else printf 'dev=no\\n'; fi\n"
    "} > \"$seen\"\n"
    "exit 0\n";

struct cbt_env {
    char path[8192];
    char keep[32];
    char label[128];
    char hook[PATH_MAX];
    char journey[8];
    char arena[8];
    char display[256];
    int have_path, have_keep, have_label, have_hook, have_journey, have_arena, have_display;
};

static void cbt_copy(char *dst, size_t cap, const char *src, int *flag)
{
    *flag = 0;
    dst[0] = '\0';
    if (src != NULL && strlen(src) < cap) {
        memcpy(dst, src, strlen(src) + 1);
        *flag = 1;
    }
}

static void cbt_save(struct cbt_env *env)
{
    cbt_copy(env->path, sizeof env->path, getenv("PATH"), &env->have_path);
    cbt_copy(env->keep, sizeof env->keep, getenv("C23_BETA_KEEP"), &env->have_keep);
    cbt_copy(env->label, sizeof env->label, getenv("C23_BETA_LABEL"), &env->have_label);
    cbt_copy(env->hook, sizeof env->hook, getenv("C23_BETA_HOOK"), &env->have_hook);
    cbt_copy(env->journey, sizeof env->journey, getenv("C23_BETA_NATIVE_UI_JOURNEY"),
             &env->have_journey);
    cbt_copy(env->arena, sizeof env->arena, getenv("C23_BETA_INSTALL_ARENA_RUNNER"),
             &env->have_arena);
    cbt_copy(env->display, sizeof env->display, getenv("DISPLAY"), &env->have_display);
}

static void cbt_put(const char *name, int have, const char *value)
{
    if (have)
        setenv(name, value, 1);
    else
        unsetenv(name);
}

static void cbt_restore(const struct cbt_env *env)
{
    cbt_put("PATH", env->have_path, env->path);
    cbt_put("C23_BETA_KEEP", env->have_keep, env->keep);
    cbt_put("C23_BETA_LABEL", env->have_label, env->label);
    cbt_put("C23_BETA_HOOK", env->have_hook, env->hook);
    cbt_put("C23_BETA_NATIVE_UI_JOURNEY", env->have_journey, env->journey);
    cbt_put("C23_BETA_INSTALL_ARENA_RUNNER", env->have_arena, env->arena);
    cbt_put("DISPLAY", env->have_display, env->display);
}

static void cbt_clear(void)
{
    unsetenv("C23_BETA_KEEP");
    unsetenv("C23_BETA_LABEL");
    unsetenv("C23_BETA_HOOK");
    unsetenv("C23_BETA_NATIVE_UI_JOURNEY");
    unsetenv("C23_BETA_INSTALL_ARENA_RUNNER");
    unsetenv("C23_BETA_NATIVE_UI_DRIVER");
}

static int cbt_write(const char *path, const char *body, mode_t mode)
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

static int cbt_mkdir(const char *path)
{
    if (mkdir(path, 0755) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

static int cbt_setup(const char *root)
{
    char path[PATH_MAX];
    char seen[PATH_MAX];
    char body[4096];
    if (cbt_mkdir("bin") != 0 || cbt_mkdir("tools") != 0 || cbt_mkdir("tools/dev") != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/bin/make", root) >= (int)sizeof path)
        return -1;
    if (cbt_write(path, k_make, 0755) != 0)
        return -1;
    if (snprintf(seen, sizeof seen, "%s/seen", root) >= (int)sizeof seen)
        return -1;
    if (snprintf(body, sizeof body,
                 "#!/bin/sh\nCBT_SEEN='%s'\n%s", seen, k_accept) >= (int)sizeof body)
        return -1;
    if (snprintf(path, sizeof path, "%s/tools/dev/zcode_dht_acceptance.sh", root) >=
        (int)sizeof path)
        return -1;
    if (cbt_write(path, body, 0755) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/tools/dev/c23_commons_beta_hook.sh", root) >=
        (int)sizeof path)
        return -1;
    if (cbt_write(path, "hook\n", 0644) != 0)
        return -1;
    if (snprintf(path, sizeof path, "%s/bin:%s", root, getenv("PATH")) >= (int)sizeof path)
        return -1;
    if (setenv("PATH", path, 1) != 0)
        return -1;
    return 0;
}

static int cbt_capture(const char *root, const char *out_path, const char *err_path,
                       char *out, size_t out_cap, char *err, size_t err_cap, int *rc)
{
    int fd_out = open(out_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int fd_err = open(err_path, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *fp;
    size_t n;
    if (fd_out < 0 || fd_err < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd_out, STDOUT_FILENO) < 0 || dup2(fd_err, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_c23_commons_beta(root);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
    close(fd_out);
    close(fd_err);
    fp = fopen(out_path, "r");
    if (fp == NULL)
        return -1;
    n = fread(out, 1, out_cap - 1, fp);
    fclose(fp);
    out[n] = '\0';
    fp = fopen(err_path, "r");
    if (fp == NULL)
        return -1;
    n = fread(err, 1, err_cap - 1, fp);
    fclose(fp);
    err[n] = '\0';
    return 0;
fail:
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd_out >= 0)
        close(fd_out);
    if (fd_err >= 0)
        close(fd_err);
    return -1;
}

static int cbt_field(const char *text, const char *key, char *out, size_t cap)
{
    char needle[64];
    const char *hit;
    size_t n = 0;
    int wrote = snprintf(needle, sizeof needle, "%s=", key);
    if (wrote < 0 || (size_t)wrote >= sizeof needle)
        return -1;
    hit = strstr(text, needle);
    if (hit == NULL)
        return -1;
    hit += (size_t)wrote;
    while (hit[n] != '\0' && hit[n] != '\n' && n + 1 < cap) {
        out[n] = hit[n];
        n++;
    }
    out[n] = '\0';
    return 0;
}

static void cbt_drop_preserved(const char *err)
{
    const char *hit = strstr(err, "preserved run at ");
    char path[PATH_MAX];
    char cmd[PATH_MAX + 16];
    size_t n = 0;
    if (hit == NULL)
        return;
    hit += strlen("preserved run at ");
    while (hit[n] != '\0' && hit[n] != '\n' && n + 1 < sizeof path) {
        path[n] = hit[n];
        n++;
    }
    path[n] = '\0';
    if (n == 0)
        return;
    if (snprintf(cmd, sizeof cmd, "rm -rf '%s'", path) > 0 && system(cmd) != 0)
        return;
}

static int cbt_read(const char *path, char *out, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL)
        return -1;
    n = fread(out, 1, cap - 1, fp);
    fclose(fp);
    out[n] = '\0';
    return 0;
}

static int test_cbt_pass(const char *root)
{
    struct cbt_env saved;
    int failures = 0;
    cbt_save(&saved);
    cbt_clear();
    TEST("commons beta: a stand-in install runs the journey outside the checkout") {
        char out[4096];
        char err[2048];
        char seen[4096];
        char log[2048];
        char cwd[PATH_MAX];
        char node[PATH_MAX];
        char hook[PATH_MAX];
        char field[PATH_MAX];
        char node_before[PATH_MAX];
        char host_before[64];
        char xdg_before[PATH_MAX];
        const char *node_env = getenv("ZCL_NODE_BIN");
        const char *host_env = getenv("DHT_PACKAGEHOST");
        const char *xdg_env = getenv("XDG_RUNTIME_DIR");
        struct stat st;
        int rc = 1;
        node_before[0] = '\0';
        host_before[0] = '\0';
        xdg_before[0] = '\0';
        if (node_env != NULL && strlen(node_env) < sizeof node_before)
            memcpy(node_before, node_env, strlen(node_env) + 1);
        if (host_env != NULL && strlen(host_env) < sizeof host_before)
            memcpy(host_before, host_env, strlen(host_env) + 1);
        if (xdg_env != NULL && strlen(xdg_env) < sizeof xdg_before)
            memcpy(xdg_before, xdg_env, strlen(xdg_env) + 1);
        unlink("make.log");
        unlink("seen");
        ASSERT(cbt_capture(root, "pass.out", "pass.err", out, sizeof out, err,
                           sizeof err, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(out, "c23-commons-beta: installing ordinary product into ") != NULL);
        ASSERT(strstr(out, "=== c23-commons-beta: PASSED ===\n") != NULL);
        if (node_before[0] == '\0')
            ASSERT(getenv("ZCL_NODE_BIN") == NULL);
        else
            ASSERT(strcmp(getenv("ZCL_NODE_BIN"), node_before) == 0);
        if (host_before[0] == '\0')
            ASSERT(getenv("DHT_PACKAGEHOST") == NULL);
        else
            ASSERT(strcmp(getenv("DHT_PACKAGEHOST"), host_before) == 0);
        if (xdg_before[0] == '\0')
            ASSERT(getenv("XDG_RUNTIME_DIR") == NULL);
        else
            ASSERT(strcmp(getenv("XDG_RUNTIME_DIR"), xdg_before) == 0);
        ASSERT(cbt_read("seen", seen, sizeof seen) == 0);
        ASSERT(cbt_field(seen, "cwd", cwd, sizeof cwd) == 0);
        ASSERT(cbt_field(seen, "node", node, sizeof node) == 0);
        ASSERT(strstr(node, "/install/bin/zclassic23") != NULL);
        ASSERT(strncmp(node, cwd, strlen(cwd)) == 0);
        ASSERT(stat(cwd, &st) != 0);
        ASSERT(cbt_field(seen, "rpc", field, sizeof field) == 0);
        ASSERT(strstr(field, "/install/bin/zcl-rpc") != NULL);
        ASSERT(cbt_field(seen, "dht", field, sizeof field) == 0);
        ASSERT(strstr(field, "/install/bin/arena_product_journey_c23") != NULL);
        ASSERT(cbt_field(seen, "work", field, sizeof field) == 0);
        ASSERT(strstr(field, "/work") != NULL);
        ASSERT(cbt_field(seen, "params", field, sizeof field) == 0);
        ASSERT(strstr(field, "/no-zk-params") != NULL);
        ASSERT(cbt_field(seen, "host", field, sizeof field) == 0);
        ASSERT(strcmp(field, "1") == 0);
        ASSERT(cbt_field(seen, "workers", field, sizeof field) == 0);
        ASSERT(strcmp(field, "1") == 0);
        ASSERT(cbt_field(seen, "keep", field, sizeof field) == 0);
        ASSERT(strcmp(field, "1") == 0);
        ASSERT(cbt_field(seen, "src", field, sizeof field) == 0);
        ASSERT(strcmp(field, root) == 0);
        ASSERT(snprintf(hook, sizeof hook, "%s/tools/dev/c23_commons_beta_hook.sh",
                        root) > 0);
        ASSERT(cbt_field(seen, "hook", field, sizeof field) == 0);
        ASSERT(strcmp(field, hook) == 0);
        ASSERT(cbt_field(seen, "runner", field, sizeof field) == 0);
        ASSERT(strcmp(field, "no") == 0);
        ASSERT(cbt_read("make.log", log, sizeof log) == 0);
        ASSERT(strstr(log, "c23-portable-install") != NULL);
        ASSERT(strstr(log, "tools/arena-product-journey-c23") != NULL);
        ASSERT(strstr(log, "tools/arena-runner") == NULL);
        ASSERT(strstr(log, "PREFIX=") != NULL);
        PASS();
    } _test_next:;
    cbt_restore(&saved);
    return failures;
}

static int test_cbt_arena(const char *root)
{
    struct cbt_env saved;
    int failures = 0;
    cbt_save(&saved);
    cbt_clear();
    TEST("commons beta: the arena runner is installed only when asked") {
        char out[2048];
        char err[1024];
        char seen[2048];
        char log[2048];
        char field[64];
        int rc = 1;
        unlink("make.log");
        unlink("seen");
        ASSERT(setenv("C23_BETA_INSTALL_ARENA_RUNNER", "1", 1) == 0);
        ASSERT(setenv("C23_BETA_LABEL", "arena-label", 1) == 0);
        ASSERT(cbt_capture(root, "arena.out", "arena.err", out, sizeof out, err,
                           sizeof err, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(strstr(out, "arena-label: installing ordinary product into ") != NULL);
        ASSERT(strstr(out, "=== arena-label: PASSED ===\n") != NULL);
        ASSERT(cbt_read("seen", seen, sizeof seen) == 0);
        ASSERT(cbt_field(seen, "runner", field, sizeof field) == 0);
        ASSERT(strcmp(field, "yes") == 0);
        ASSERT(cbt_field(seen, "dev", field, sizeof field) == 0);
        ASSERT(strcmp(field, "yes") == 0);
        ASSERT(cbt_read("make.log", log, sizeof log) == 0);
        ASSERT(strstr(log, "tools/arena-runner dev-bin") != NULL);
        PASS();
    } _test_next:;
    cbt_restore(&saved);
    return failures;
}

static int test_cbt_fail(const char *root)
{
    struct cbt_env saved;
    int failures = 0;
    cbt_save(&saved);
    cbt_clear();
    TEST("commons beta: a missing hook, product, or display preserves the run") {
        char out[2048];
        char err[2048];
        char hook[PATH_MAX];
        char cwd[PATH_MAX];
        char seen[2048];
        struct stat st;
        int rc = 0;
        ASSERT(snprintf(hook, sizeof hook, "%s/tools/dev/c23_commons_beta_hook.sh",
                        root) > 0);
        ASSERT(unlink(hook) == 0);
        ASSERT(cbt_capture(root, "miss.out", "miss.err", out, sizeof out, err,
                           sizeof err, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT(strstr(err, "composition hook is unavailable") != NULL);
        ASSERT(strstr(err, "preserved run at ") != NULL);
        cbt_drop_preserved(err);
        ASSERT(cbt_write(hook, "hook\n", 0644) == 0);
        ASSERT(cbt_write("skip-rpc", "1\n", 0644) == 0);
        ASSERT(cbt_capture(root, "skip.out", "skip.err", out, sizeof out, err,
                           sizeof err, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT(strstr(err, "installed product missing: zcl-rpc") != NULL);
        cbt_drop_preserved(err);
        unlink("skip-rpc");
        ASSERT(cbt_write("make-fail", "1\n", 0644) == 0);
        ASSERT(cbt_capture(root, "mk.out", "mk.err", out, sizeof out, err,
                           sizeof err, &rc) == 0);
        ASSERT(rc == 3);
        ASSERT(strstr(err, "preserved run at ") != NULL);
        cbt_drop_preserved(err);
        unlink("make-fail");
        ASSERT(setenv("C23_BETA_NATIVE_UI_JOURNEY", "1", 1) == 0);
        unsetenv("DISPLAY");
        ASSERT(cbt_capture(root, "ui.out", "ui.err", out, sizeof out, err,
                           sizeof err, &rc) == 0);
        ASSERT(rc == 2);
        ASSERT(strstr(err, "native journey requires DISPLAY") != NULL);
        cbt_drop_preserved(err);
        unsetenv("C23_BETA_NATIVE_UI_JOURNEY");
        ASSERT(setenv("C23_BETA_KEEP", "1", 1) == 0);
        unlink("seen");
        ASSERT(cbt_capture(root, "keep.out", "keep.err", out, sizeof out, err,
                           sizeof err, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT(cbt_read("seen", seen, sizeof seen) == 0);
        ASSERT(cbt_field(seen, "cwd", cwd, sizeof cwd) == 0);
        ASSERT(stat(cwd, &st) == 0 && S_ISDIR(st.st_mode));
        ASSERT(strstr(err, "preserved run at ") != NULL);
        cbt_drop_preserved(err);
        ASSERT(stat(cwd, &st) != 0);
        PASS();
    } _test_next:;
    cbt_drop_preserved("preserved run at ");
    unlink("skip-rpc");
    unlink("make-fail");
    cbt_restore(&saved);
    return failures;
}

int test_c23_commons_beta(void);
int test_c23_commons_beta(void)
{
    char root[PATH_MAX];
    char cwd[PATH_MAX];
    struct cbt_env saved;
    int failures;
    if (getcwd(cwd, sizeof cwd) == NULL)
        return 1;
    cbt_save(&saved);
    test_make_tmpdir(root, sizeof root, "c23_commons_beta", "root");
    if (chdir(root) != 0) {
        cbt_restore(&saved);
        return 1;
    }
    if (cbt_setup(root) != 0) {
        if (chdir(cwd) != 0)
            return 1;
        cbt_restore(&saved);
        (void)test_rm_rf_recursive(root);
        printf("test_c23_commons_beta: setup failed\n");
        return 1;
    }
    failures = test_cbt_pass(root);
    failures += test_cbt_arena(root);
    failures += test_cbt_fail(root);
    if (chdir(cwd) != 0)
        failures += 1;
    cbt_restore(&saved);
    (void)test_rm_rf_recursive(root);
    if (failures == 0)
        printf("test_c23_commons_beta: all passed\n");
    else
        printf("test_c23_commons_beta: %d FAILED\n", failures);
    return failures;
}
