/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Install an ordinary C23 Commons prefix and run the stranger
 *          journey from outside the checkout. The block below is the
 *          install contract check-installed-acceptance-tools derives;
 *          the function installs that same set. */

#include "c23_commons_beta.h"

#include <stdio.h>
#include <string.h>

#if 0
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RUN_ROOT="$(mktemp -d /tmp/zcl23-c23-beta.XXXXXX)"
KEEP="${C23_BETA_KEEP:-0}"
PRODUCT_LABEL="${C23_BETA_LABEL:-c23-commons-beta}"
PRODUCT_HOOK="${C23_BETA_HOOK:-$SCRIPT_DIR/c23_commons_beta_hook.sh}"
PREFIX="$RUN_ROOT/install"
WORK_PARENT="$RUN_ROOT/work"
PARAMS_DIR="$RUN_ROOT/no-zk-params"
mkdir -p "$PREFIX" "$WORK_PARENT" "$PARAMS_DIR"
echo "$PRODUCT_LABEL: installing ordinary product into $PREFIX"
make -C "$REPO_ROOT" c23-portable-install DESTDIR="$PREFIX" PREFIX= >/dev/null
for product in zclassic23 zcl-rpc zclassic23-package-sign \
        zclassic23-package-verify; do
    [ -x "$PREFIX/bin/$product" ] || {
        echo "c23-commons-beta: installed product missing: $product" >&2
        exit 2
    }
done
make -C "$REPO_ROOT" tools/arena-product-journey-c23 >/dev/null
install -m 0755 "$REPO_ROOT/build/bin/arena_product_journey_c23" \
    "$PREFIX/bin/arena_product_journey_c23"
if [ "${C23_BETA_INSTALL_ARENA_RUNNER:-0}" = 1 ]; then
    make -C "$REPO_ROOT" tools/arena-runner dev-bin >/dev/null
    install -m 0755 "$REPO_ROOT/build/bin/arena_runner" \
        "$PREFIX/bin/arena_runner"
    install -m 0755 "$REPO_ROOT/build/bin/zclassic23-dev" \
        "$PREFIX/bin/zclassic23-dev"
fi
export ZCL_NODE_BIN="$PREFIX/bin/zclassic23"
export ZCL_RPC_BIN="$PREFIX/bin/zcl-rpc"
export C23_BETA_INSTALL_BIN="$PREFIX/bin"
export C23_BETA_DEV_BIN="$PREFIX/bin/zclassic23-dev"
export DHT_ACCEPTANCE_C23="$PREFIX/bin/arena_product_journey_c23"
export C23_BETA_FIXTURE_SOURCE="$REPO_ROOT"
export DHT_WORK_PARENT="$WORK_PARENT"
export DHT_PARAMS_DIR="$PARAMS_DIR"
export DHT_PACKAGEHOST=1
export DHT_BUILDWORKERS=1
export DHT_KEEP=1
export DHT_AFTER_SPARSE_HOOK="$PRODUCT_HOOK"
cd "$RUN_ROOT"
bash "$SCRIPT_DIR/zcode_dht_acceptance.sh"
echo "=== $PRODUCT_LABEL: PASSED ==="
#endif

#if !defined(_WIN32)
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char *const k_products[] = {
    "zclassic23",
    "zcl-rpc",
    "zclassic23-package-sign",
    "zclassic23-package-verify",
};

static const char *const k_env_names[] = {
    "ZCL_NODE_BIN",
    "ZCL_RPC_BIN",
    "C23_BETA_INSTALL_BIN",
    "C23_BETA_DEV_BIN",
    "DHT_ACCEPTANCE_C23",
    "C23_BETA_FIXTURE_SOURCE",
    "DHT_WORK_PARENT",
    "DHT_PARAMS_DIR",
    "DHT_PACKAGEHOST",
    "DHT_BUILDWORKERS",
    "DHT_KEEP",
    "DHT_AFTER_SPARSE_HOOK",
    "C23_BETA_NATIVE_UI_DRIVER",
    "XDG_RUNTIME_DIR",
};

struct cbb_slot {
    char text[PATH_MAX];
    int present;
};

static int cbb_reap(pid_t child)
{
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    while (got < 0 && errno == EINTR)
        got = waitpid(child, &status, 0);
    if (got != child)
        return 125;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 125;
}

static int cbb_exec(char *const argv[], const char *cwd, int drop_stdout)
{
    pid_t child = fork();
    if (child < 0)
        return 127;
    if (child == 0) {
        if (cwd != NULL && chdir(cwd) != 0)
            _exit(127);
        if (drop_stdout) {
            int sink = open("/dev/null", O_WRONLY);
            if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0)
                _exit(127);
            if (sink > STDOUT_FILENO)
                close(sink);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    return cbb_reap(child);
}

static int cbb_make(const char *repo, char *const extra[])
{
    char *argv[8];
    int n = 0;
    int i;
    argv[n++] = "make";
    argv[n++] = "-C";
    argv[n++] = (char *)repo;
    for (i = 0; extra[i] != NULL && n < 7; i++)
        argv[n++] = extra[i];
    argv[n] = NULL;
    return cbb_exec(argv, NULL, 1);
}

static int cbb_install(const char *src, const char *dst)
{
    char *argv[] = {"install", "-m", "0755", (char *)src, (char *)dst, NULL};
    return cbb_exec(argv, NULL, 0);
}

static int cbb_mkdir(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == 0 || errno == EEXIST)
        return 0;
    return -1;
}

static const char *cbb_opt(const char *name, const char *fallback)
{
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0')
        return fallback;
    return value;
}

static int cbb_flag(const char *name)
{
    const char *value = getenv(name);
    return value != NULL && strcmp(value, "1") == 0;
}

static int cbb_join(char *dst, size_t cap, const char *a, const char *b)
{
    int n = snprintf(dst, cap, "%s/%s", a, b);
    if (n < 0 || (size_t)n >= cap)
        return -1;
    return 0;
}

static void cbb_keep(struct cbb_slot *slot, const char *name)
{
    const char *old = getenv(name);
    slot->present = 0;
    slot->text[0] = '\0';
    if (old != NULL && strlen(old) < sizeof slot->text) {
        memcpy(slot->text, old, strlen(old) + 1);
        slot->present = 1;
    }
}

static void cbb_restore(const struct cbb_slot *slot, const char *name)
{
    if (slot->present)
        (void)setenv(name, slot->text, 1);
    else
        unsetenv(name);
}

static int cbb_products(const char *prefix)
{
    size_t i;
    for (i = 0; i < sizeof k_products / sizeof k_products[0]; i++) {
        char path[PATH_MAX];
        if (snprintf(path, sizeof path, "%s/bin/%s", prefix, k_products[i]) >=
            (int)sizeof path)
            return 2;
        if (access(path, X_OK) != 0) {
            fprintf(stderr, "c23-commons-beta: installed product missing: %s\n",
                    k_products[i]);
            return 2;
        }
    }
    return 0;
}

static int cbb_copy_tool(const char *repo, const char *prefix, const char *name)
{
    char src[PATH_MAX];
    char dst[PATH_MAX];
    if (snprintf(src, sizeof src, "%s/build/bin/%s", repo, name) >= (int)sizeof src)
        return 2;
    if (snprintf(dst, sizeof dst, "%s/bin/%s", prefix, name) >= (int)sizeof dst)
        return 2;
    if (cbb_install(src, dst) != 0)
        return 2;
    return 0;
}

static void cbb_swap_nul(char *buf, size_t n, char sep)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (buf[i] == '\0')
            buf[i] = sep;
    }
    buf[n] = '\0';
}

static int cbb_slurp(const char *path, char *buf, size_t cap, size_t *n)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL)
        return -1;
    if (cap < 2) {
        fclose(fp);
        return -1;
    }
    *n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    return 0;
}

static int cbb_ui_match(const char *name, const char *want, const char *runtime,
                        long *pid)
{
    char cmd_path[PATH_MAX];
    char env_path[PATH_MAX];
    char cmd[PATH_MAX];
    char envbuf[8192];
    char *end = NULL;
    size_t n = 0;
    *pid = strtol(name, &end, 10);
    if (end == name || *end != '\0' || *pid <= 0)
        return 0;
    if (snprintf(cmd_path, sizeof cmd_path, "/proc/%s/cmdline", name) >=
        (int)sizeof cmd_path)
        return 0;
    if (snprintf(env_path, sizeof env_path, "/proc/%s/environ", name) >=
        (int)sizeof env_path)
        return 0;
    if (cbb_slurp(cmd_path, cmd, sizeof cmd, &n) != 0)
        return 0;
    cbb_swap_nul(cmd, n, ' ');
    if (strcmp(cmd, want) != 0)
        return 0;
    if (cbb_slurp(env_path, envbuf, sizeof envbuf, &n) != 0)
        return 0;
    cbb_swap_nul(envbuf, n, '\n');
    return strstr(envbuf, runtime) != NULL;
}

static void cbb_kill_ui(const char *prefix, const char *run)
{
    DIR *dir;
    struct dirent *ent;
    char want[PATH_MAX];
    char runtime[PATH_MAX];
    if (!cbb_flag("C23_BETA_NATIVE_UI_JOURNEY"))
        return;
    if (snprintf(want, sizeof want, "%s/bin/zclassic23 --ui-present-host ",
                 prefix) >= (int)sizeof want)
        return;
    if (snprintf(runtime, sizeof runtime, "XDG_RUNTIME_DIR=%s/native-ui-runtime",
                 run) >= (int)sizeof runtime)
        return;
    dir = opendir("/proc");
    if (dir == NULL)
        return;
    while ((ent = readdir(dir)) != NULL) {
        long pid = 0;
        if (ent->d_name[0] < '1' || ent->d_name[0] > '9')
            continue;
        if (!cbb_ui_match(ent->d_name, want, runtime, &pid))
            continue;
        kill((pid_t)pid, SIGTERM);
    }
    closedir(dir);
}

static int cbb_dirs(const char *run, char *prefix, char *work, char *params,
                    size_t cap)
{
    if (cbb_join(prefix, cap, run, "install") != 0)
        return -1;
    if (cbb_join(work, cap, run, "work") != 0)
        return -1;
    if (cbb_join(params, cap, run, "no-zk-params") != 0)
        return -1;
    if (cbb_mkdir(prefix, 0755) != 0)
        return -1;
    if (cbb_mkdir(work, 0755) != 0)
        return -1;
    if (cbb_mkdir(params, 0755) != 0)
        return -1;
    return 0;
}

static int cbb_guarded(const char *run)
{
    static const char pfx[] = "/tmp/zcl23-c23-beta.";
    return strncmp(run, pfx, sizeof pfx - 1) == 0;
}

static void cbb_cleanup(const char *run, const char *prefix, const char *label,
                        int rc, int keep)
{
    char *argv[4];
    cbb_kill_ui(prefix, run);
    if (!cbb_guarded(run)) {
        fprintf(stderr, "%s: refusing cleanup outside guarded root\n", label);
        return;
    }
    if (rc == 0 && !keep) {
        argv[0] = "rm";
        argv[1] = "-rf";
        argv[2] = (char *)run;
        argv[3] = NULL;
        (void)cbb_exec(argv, NULL, 1);
        return;
    }
    fprintf(stderr, "%s: preserved run at %s\n", label, run);
}

static int cbb_native_ui(const char *run)
{
    const char *driver;
    char staged[PATH_MAX];
    char runtime[PATH_MAX];
    if (!cbb_flag("C23_BETA_NATIVE_UI_JOURNEY"))
        return 0;
    if (getenv("DISPLAY") == NULL || getenv("DISPLAY")[0] == '\0') {
        fprintf(stderr, "c23-commons-beta: native journey requires DISPLAY\n");
        return 2;
    }
    driver = getenv("C23_BETA_NATIVE_UI_DRIVER");
    if (driver == NULL || access(driver, X_OK) != 0) {
        fprintf(stderr, "c23-commons-beta: native journey driver is unavailable\n");
        return 2;
    }
    if (cbb_join(runtime, sizeof runtime, run, "native-ui-runtime") != 0)
        return 2;
    if (mkdir(runtime, 0700) != 0)
        return 2;
    if (cbb_join(staged, sizeof staged, run, "native-ui-driver") != 0)
        return 2;
    if (cbb_install(driver, staged) != 0)
        return 2;
    if (setenv("C23_BETA_NATIVE_UI_DRIVER", staged, 1) != 0)
        return 2;
    if (setenv("XDG_RUNTIME_DIR", runtime, 1) != 0)
        return 2;
    return 0;
}

static int cbb_stage(const char *repo, const char *prefix, char *dest, size_t cap)
{
    char *install_args[] = {"c23-portable-install", NULL, "PREFIX=", NULL};
    char *arena_args[] = {"tools/arena-product-journey-c23", NULL};
    char *runner_args[] = {"tools/arena-runner", "dev-bin", NULL};
    int rc;
    if (snprintf(dest, cap, "DESTDIR=%s", prefix) >= (int)cap)
        return 2;
    install_args[1] = dest;
    rc = cbb_make(repo, install_args);
    if (rc != 0)
        return rc;
    rc = cbb_products(prefix);
    if (rc != 0)
        return rc;
    rc = cbb_make(repo, arena_args);
    if (rc != 0)
        return rc;
    rc = cbb_copy_tool(repo, prefix, "arena_product_journey_c23");
    if (rc != 0)
        return rc;
    if (!cbb_flag("C23_BETA_INSTALL_ARENA_RUNNER"))
        return 0;
    rc = cbb_make(repo, runner_args);
    if (rc != 0)
        return rc;
    rc = cbb_copy_tool(repo, prefix, "arena_runner");
    if (rc != 0)
        return rc;
    return cbb_copy_tool(repo, prefix, "zclassic23-dev");
}

static int cbb_put_bin(const char *name, const char *prefix, const char *leaf)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof path, "%s/bin/%s", prefix, leaf) >= (int)sizeof path)
        return 2;
    if (setenv(name, path, 1) != 0)
        return 2;
    return 0;
}

static int cbb_bind_bins(const char *prefix)
{
    char bin[PATH_MAX];
    if (cbb_put_bin("ZCL_NODE_BIN", prefix, "zclassic23") != 0)
        return 2;
    if (cbb_put_bin("ZCL_RPC_BIN", prefix, "zcl-rpc") != 0)
        return 2;
    if (snprintf(bin, sizeof bin, "%s/bin", prefix) >= (int)sizeof bin)
        return 2;
    if (setenv("C23_BETA_INSTALL_BIN", bin, 1) != 0)
        return 2;
    if (cbb_put_bin("C23_BETA_DEV_BIN", prefix, "zclassic23-dev") != 0)
        return 2;
    if (cbb_put_bin("DHT_ACCEPTANCE_C23", prefix, "arena_product_journey_c23") != 0)
        return 2;
    return 0;
}

static int cbb_bind_dirs(const char *repo, const char *work, const char *params,
                         const char *hook)
{
    if (setenv("C23_BETA_FIXTURE_SOURCE", repo, 1) != 0)
        return 2;
    if (setenv("DHT_WORK_PARENT", work, 1) != 0)
        return 2;
    if (setenv("DHT_PARAMS_DIR", params, 1) != 0)
        return 2;
    if (setenv("DHT_PACKAGEHOST", "1", 1) != 0)
        return 2;
    if (setenv("DHT_BUILDWORKERS", "1", 1) != 0)
        return 2;
    if (setenv("DHT_KEEP", "1", 1) != 0)
        return 2;
    if (setenv("DHT_AFTER_SPARSE_HOOK", hook, 1) != 0)
        return 2;
    return 0;
}

static int cbb_bind(const char *repo, const char *prefix, const char *work,
                    const char *params, const char *hook, struct cbb_slot *saved)
{
    size_t i;
    int rc;
    for (i = 0; i < sizeof k_env_names / sizeof k_env_names[0]; i++)
        cbb_keep(&saved[i], k_env_names[i]);
    rc = cbb_bind_bins(prefix);
    if (rc != 0)
        return rc;
    return cbb_bind_dirs(repo, work, params, hook);
}

static int cbb_journey(const char *repo, const char *run, const char *prefix,
                       const char *work, const char *params, const char *label,
                       const char *hook)
{
    char dest[PATH_MAX + 16];
    char script[PATH_MAX];
    struct cbb_slot saved[sizeof k_env_names / sizeof k_env_names[0]];
    size_t i;
    int rc;
    printf("%s: installing ordinary product into %s\n", label, prefix);
    rc = cbb_stage(repo, prefix, dest, sizeof dest);
    if (rc != 0)
        return rc;
    if (access(hook, R_OK) != 0) {
        fprintf(stderr, "%s: composition hook is unavailable: %s\n", label, hook);
        return 2;
    }
    rc = cbb_bind(repo, prefix, work, params, hook, saved);
    if (rc == 0) {
        char *argv[] = {"bash", script, NULL};
        if (cbb_join(script, sizeof script, repo, "tools/dev/zcode_dht_acceptance.sh") != 0)
            rc = 2;
        else
            rc = cbb_exec(argv, run, 0);
    }
    for (i = 0; i < sizeof k_env_names / sizeof k_env_names[0]; i++)
        cbb_restore(&saved[i], k_env_names[i]);
    if (rc != 0)
        return rc;
    printf("=== %s: PASSED ===\n", label);
    return 0;
}
#endif

int zcl_c23_commons_beta(const char *repo)
{
#if defined(_WIN32)
    (void)repo;
    fputs("c23-commons-beta: unavailable on Windows\n", stdout);
    return 2;
#else
    char run[PATH_MAX];
    char prefix[PATH_MAX];
    char work[PATH_MAX];
    char params[PATH_MAX];
    const char *label;
    const char *hook;
    int keep;
    int rc;
    char hook_buf[PATH_MAX];
    struct cbb_slot saved[sizeof k_env_names / sizeof k_env_names[0]];
    size_t i;
    if (repo == NULL || repo[0] == '\0')
        return 2;
    if (snprintf(run, sizeof run, "/tmp/zcl23-c23-beta.XXXXXX") >= (int)sizeof run)
        return 1;
    if (mkdtemp(run) == NULL)
        return 1;
    for (i = 0; i < sizeof k_env_names / sizeof k_env_names[0]; i++)
        cbb_keep(&saved[i], k_env_names[i]);
    label = cbb_opt("C23_BETA_LABEL", "c23-commons-beta");
    hook = getenv("C23_BETA_HOOK");
    keep = cbb_flag("C23_BETA_KEEP");
    if (cbb_dirs(run, prefix, work, params, sizeof prefix) != 0) {
        for (i = 0; i < sizeof k_env_names / sizeof k_env_names[0]; i++)
            cbb_restore(&saved[i], k_env_names[i]);
        cbb_cleanup(run, prefix, label, 1, keep);
        return 1;
    }
    rc = cbb_native_ui(run);
    if (rc == 0 && (hook == NULL || hook[0] == '\0')) {
        if (snprintf(hook_buf, sizeof hook_buf,
                     "%s/tools/dev/c23_commons_beta_hook.sh", repo) >=
            (int)sizeof hook_buf)
            rc = 2;
        else
            hook = hook_buf;
    }
    if (rc == 0)
        rc = cbb_journey(repo, run, prefix, work, params, label, hook);
    for (i = 0; i < sizeof k_env_names / sizeof k_env_names[0]; i++)
        cbb_restore(&saved[i], k_env_names[i]);
    cbb_cleanup(run, prefix, label, rc, keep);
    return rc;
#endif
}
