/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Drives zcl_dev_wallet_credential. Stub executables sit on a private
 * PATH and XDG_DATA_HOME points at a temp directory, so the operator's
 * Secret Service and user systemd are never touched. */

#include "test/test_core.h"

#include "dev_wallet_credential.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char k_bar0[] =
    "dev-wallet-credential: [---] 0/3 state=blocked "
    "secret=redacted config=encrypted\n";
static const char k_bar1[] =
    "dev-wallet-credential: [#--] 1/3 state=blocked "
    "secret=redacted config=encrypted\n";
static const char k_bar2[] =
    "dev-wallet-credential: [##-] 2/3 state=blocked "
    "secret=redacted config=encrypted\n";
static const char k_bar3[] =
    "dev-wallet-credential: [###] 3/3 state=ready "
    "secret=redacted config=encrypted\n";
static const char k_secret[] = "fixture-wallet-secret";

static const char k_secret_tool[] =
    "#!/bin/sh\n"
    "d='%s'\n"
    "if [ \"$1\" = lookup ]; then\n"
    "    if [ -f \"$d/secret\" ]; then\n"
    "        /bin/cat \"$d/secret\"\n"
    "        exit 0\n"
    "    fi\n"
    "    exit 1\n"
    "fi\n"
    "if [ \"$1\" = store ]; then\n"
    "    /bin/cat > \"$d/secret\"\n"
    "    exit 0\n"
    "fi\n"
    "exit 1\n";

static const char k_openssl[] =
    "#!/bin/sh\n"
    "printf '%s\\n' 'fixture-wallet-secret'\n"
    "exit 0\n";

static const char k_creds[] =
    "#!/bin/sh\n"
    "out=\n"
    "while [ $# -gt 0 ]; do\n"
    "    out=$1\n"
    "    shift\n"
    "done\n"
    "/bin/cat > \"$out\"\n"
    "exit 0\n";

static const char k_systemctl[] =
    "#!/bin/sh\n"
    "d='%s'\n"
    "if [ \"$1\" = --user ]; then\n"
    "    shift\n"
    "fi\n"
    "act=$1\n"
    "shift\n"
    "if [ \"$act\" = cat ]; then\n"
    "    if [ -f \"$d/dropin\" ]; then\n"
    "        /bin/cat \"$d/dropin\"\n"
    "        exit 0\n"
    "    fi\n"
    "    exit 1\n"
    "fi\n"
    "if [ \"$act\" = edit ]; then\n"
    "    /bin/cat > \"$d/dropin\"\n"
    "    printf '%%s\\n' \"$@\" > \"$d/edit-args\"\n"
    "    exit 0\n"
    "fi\n"
    "if [ \"$act\" = daemon-reload ]; then\n"
    "    printf 'reloaded\\n' > \"$d/reloaded\"\n"
    "    exit 0\n"
    "fi\n"
    "exit 1\n";

struct dwc_saved {
    char path[8192];
    char xdg[1024];
    int have_path;
    int have_xdg;
};

static int dwc_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    if (n < 0)
        return -1;
    if ((size_t)n >= cap)
        return -1;
    return 0;
}

static int dwc_put(const char *path, const char *body, unsigned mode)
{
    FILE *f = fopen(path, "w");
    size_t n;
    if (f == NULL)
        return -1;
    n = strlen(body);
    if (fwrite(body, 1, n, f) != n) {
        fclose(f);
        return -1;
    }
    if (fclose(f) != 0)
        return -1;
    if (chmod(path, (mode_t)mode) != 0)
        return -1;
    return 0;
}

static int dwc_ensure(const char *path, unsigned mode)
{
    if (mkdir(path, (mode_t)mode) != 0 && errno != EEXIST)
        return -1;
    if (chmod(path, (mode_t)mode) != 0)
        return -1;
    return 0;
}

static int dwc_tree(const char *xdg, unsigned leaf, char *root, size_t cap)
{
    char mid[1024];
    if (dwc_ensure(xdg, 0700) != 0)
        return -1;
    if (dwc_join(mid, sizeof mid, xdg, "zclassic23") != 0)
        return -1;
    if (dwc_ensure(mid, 0700) != 0)
        return -1;
    if (dwc_join(root, cap, mid, "credentials") != 0)
        return -1;
    return dwc_ensure(root, leaf);
}

static int dwc_load(const char *path, char *buf, size_t cap, size_t *n_out)
{
    FILE *f = fopen(path, "r");
    size_t n;
    if (f == NULL)
        return -1;
    n = fread(buf, 1, cap - 1, f);
    fclose(f);
    if (n == cap - 1)
        return -1;
    buf[n] = '\0';
    *n_out = n;
    return 0;
}

static int dwc_eq_file(const char *path, const char *want)
{
    char buf[2048];
    size_t n = 0;
    if (dwc_load(path, buf, sizeof buf, &n) != 0)
        return 0;
    if (n != strlen(want))
        return 0;
    return memcmp(buf, want, n) == 0;
}

static int dwc_has(const char *path, const char *needle)
{
    char buf[2048];
    size_t n = 0;
    if (dwc_load(path, buf, sizeof buf, &n) != 0)
        return 0;
    return strstr(buf, needle) != NULL;
}

static int dwc_is_mode(const char *path, unsigned mode)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return (st.st_mode & 07777u) == mode;
}

static int dwc_save(struct dwc_saved *s)
{
    const char *path = getenv("PATH");
    const char *xdg = getenv("XDG_DATA_HOME");
    int n;
    s->have_path = path != NULL;
    s->have_xdg = xdg != NULL;
    s->path[0] = '\0';
    s->xdg[0] = '\0';
    if (path != NULL) {
        n = snprintf(s->path, sizeof s->path, "%s", path);
        if (n < 0 || (size_t)n >= sizeof s->path)
            return -1;
    }
    if (xdg != NULL) {
        n = snprintf(s->xdg, sizeof s->xdg, "%s", xdg);
        if (n < 0 || (size_t)n >= sizeof s->xdg)
            return -1;
    }
    return 0;
}

static void dwc_restore(const struct dwc_saved *s)
{
    if (s->have_path)
        (void)setenv("PATH", s->path, 1);
    else
        unsetenv("PATH");
    if (s->have_xdg)
        (void)setenv("XDG_DATA_HOME", s->xdg, 1);
    else
        unsetenv("XDG_DATA_HOME");
}

static int dwc_bind_env(const char *bin, const char *xdg)
{
    if (setenv("PATH", bin, 1) != 0)
        return -1;
    if (setenv("XDG_DATA_HOME", xdg, 1) != 0)
        return -1;
    return 0;
}

static int dwc_capture(const char *action, const char *repo, const char *log,
                       char *got, size_t cap, int *rc)
{
    int fd = open(log, O_CREAT | O_TRUNC | O_RDWR, 0600);
    int saved_out = dup(STDOUT_FILENO);
    int saved_err = dup(STDERR_FILENO);
    FILE *file;
    size_t used;
    if (fd < 0 || saved_out < 0 || saved_err < 0)
        goto fail;
    fflush(stdout);
    fflush(stderr);
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0)
        goto fail;
    *rc = zcl_dev_wallet_credential("dev-wallet-credential", action, repo);
    fflush(stdout);
    fflush(stderr);
    dup2(saved_out, STDOUT_FILENO);
    dup2(saved_err, STDERR_FILENO);
    close(saved_out);
    close(saved_err);
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
    if (saved_out >= 0) {
        dup2(saved_out, STDOUT_FILENO);
        close(saved_out);
    }
    if (saved_err >= 0) {
        dup2(saved_err, STDERR_FILENO);
        close(saved_err);
    }
    if (fd >= 0)
        close(fd);
    return -1;
}

static int dwc_fmt_tool(const char *bin, const char *name, const char *fmt,
                        const char *state)
{
    char body[2048];
    char path[1024];
    int n = snprintf(body, sizeof body, fmt, state);
    if (n < 0 || (size_t)n >= sizeof body)
        return -1;
    if (dwc_join(path, sizeof path, bin, name) != 0)
        return -1;
    return dwc_put(path, body, 0755);
}

static int dwc_plain_tool(const char *bin, const char *name, const char *body)
{
    char path[1024];
    if (dwc_join(path, sizeof path, bin, name) != 0)
        return -1;
    return dwc_put(path, body, 0755);
}

static int dwc_tools_status(const char *bin, const char *state)
{
    if (dwc_fmt_tool(bin, "secret-tool", k_secret_tool, state) != 0)
        return -1;
    return dwc_fmt_tool(bin, "systemctl", k_systemctl, state);
}

static int dwc_tools_all(const char *bin, const char *state)
{
    if (dwc_tools_status(bin, state) != 0)
        return -1;
    if (dwc_plain_tool(bin, "openssl", k_openssl) != 0)
        return -1;
    return dwc_plain_tool(bin, "systemd-creds", k_creds);
}

static int dwc_layout(const char *root, const char *name, char *bin, size_t bin_n,
                      char *xdg, size_t xdg_n, char *repo, size_t repo_n,
                      char *log, size_t log_n, char *state, size_t state_n)
{
    char dir[1024];
    if (dwc_join(dir, sizeof dir, root, name) != 0)
        return -1;
    if (dwc_ensure(dir, 0700) != 0)
        return -1;
    if (dwc_join(bin, bin_n, dir, "bin") != 0)
        return -1;
    if (dwc_ensure(bin, 0700) != 0)
        return -1;
    if (dwc_join(xdg, xdg_n, dir, "xdg") != 0)
        return -1;
    if (dwc_ensure(xdg, 0700) != 0)
        return -1;
    if (dwc_join(repo, repo_n, dir, "repo") != 0)
        return -1;
    if (dwc_join(state, state_n, dir, "state") != 0)
        return -1;
    if (dwc_ensure(state, 0700) != 0)
        return -1;
    return dwc_join(log, log_n, dir, "log");
}

static int dwc_case_blocked(const char *root)
{
    struct dwc_saved saved;
    int failures = 0;
    if (dwc_save(&saved) != 0)
        return 1;
    TEST("dev-wallet credential: status with nothing ready is 0/3") {
        char bin[1024], xdg[1024], repo[1024], log[1024], state[1024];
        char got[1024];
        int rc = 1;
        ASSERT(dwc_layout(root, "blocked", bin, sizeof bin, xdg, sizeof xdg,
                          repo, sizeof repo, log, sizeof log, state,
                          sizeof state) == 0);
        ASSERT(dwc_bind_env(bin, xdg) == 0);
        ASSERT(dwc_capture(NULL, repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_bar0);
        ASSERT(dwc_capture("status", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_bar0);
        PASS();
    } _test_next:;
    dwc_restore(&saved);
    return failures;
}

static int dwc_case_file(const char *root)
{
    struct dwc_saved saved;
    int failures = 0;
    if (dwc_save(&saved) != 0)
        return 1;
    TEST("dev-wallet credential: mode 600 counts and mode 644 does not") {
        char bin[1024], xdg[1024], repo[1024], log[1024], state[1024];
        char cred_root[1024], cred[1024], got[1024];
        int rc = 1;
        ASSERT(dwc_layout(root, "file", bin, sizeof bin, xdg, sizeof xdg,
                          repo, sizeof repo, log, sizeof log, state,
                          sizeof state) == 0);
        ASSERT(dwc_tree(xdg, 0700, cred_root, sizeof cred_root) == 0);
        ASSERT(dwc_join(cred, sizeof cred, cred_root,
                        "dev-wallet-passphrase.cred") == 0);
        ASSERT(dwc_put(cred, "x", 0600) == 0);
        ASSERT(dwc_bind_env(bin, xdg) == 0);
        ASSERT(dwc_capture("status", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_bar1);
        ASSERT(chmod(cred, 0644) == 0);
        ASSERT(dwc_capture("status", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_bar0);
        PASS();
    } _test_next:;
    dwc_restore(&saved);
    return failures;
}

static int dwc_case_ready(const char *root)
{
    struct dwc_saved saved;
    int failures = 0;
    if (dwc_save(&saved) != 0)
        return 1;
    TEST("dev-wallet credential: secret, file, and unit line reach ready") {
        char bin[1024], xdg[1024], repo[1024], log[1024], state[1024];
        char cred_root[1024], cred[1024], got[1024], dropin[1024];
        char secret[1024];
        int rc = 1;
        ASSERT(dwc_layout(root, "ready", bin, sizeof bin, xdg, sizeof xdg,
                          repo, sizeof repo, log, sizeof log, state,
                          sizeof state) == 0);
        ASSERT(dwc_tools_status(bin, state) == 0);
        ASSERT(dwc_join(secret, sizeof secret, state, "secret") == 0);
        ASSERT(dwc_put(secret, "present", 0600) == 0);
        ASSERT(dwc_tree(xdg, 0700, cred_root, sizeof cred_root) == 0);
        ASSERT(dwc_join(cred, sizeof cred, cred_root,
                        "dev-wallet-passphrase.cred") == 0);
        ASSERT(dwc_put(cred, "x", 0600) == 0);
        ASSERT(dwc_join(dropin, sizeof dropin, state, "dropin") == 0);
        ASSERT(dwc_put(dropin,
                       "# comment\n"
                       " notLoadCredentialEncrypted=wallet-passphrase:no\n",
                       0600) == 0);
        ASSERT(dwc_bind_env(bin, xdg) == 0);
        ASSERT(dwc_capture("status", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_bar2);
        ASSERT(dwc_put(dropin,
                       "LoadCredentialEncrypted=wallet-passphrase:ignored\n",
                       0600) == 0);
        ASSERT(dwc_capture("status", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_bar3);
        ASSERT(strstr(got, k_secret) == NULL);
        PASS();
    } _test_next:;
    dwc_restore(&saved);
    return failures;
}

static int dwc_case_setup(const char *root)
{
    struct dwc_saved saved;
    int failures = 0;
    if (dwc_save(&saved) != 0)
        return 1;
    TEST("dev-wallet credential: setup stores, encrypts, and binds") {
        char bin[1024], xdg[1024], repo[1024], log[1024], state[1024];
        char mid[1024], cred_root[1024], cred[1024], got[1024], want[1200];
        char secret[1024], dropin[1024], args[1024], reloaded[1024];
        int rc = 1;
        int n;
        ASSERT(dwc_layout(root, "setup", bin, sizeof bin, xdg, sizeof xdg,
                          repo, sizeof repo, log, sizeof log, state,
                          sizeof state) == 0);
        ASSERT(dwc_tools_all(bin, state) == 0);
        ASSERT(dwc_bind_env(bin, xdg) == 0);
        ASSERT(dwc_capture("setup", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_bar3);
        ASSERT(strstr(got, k_secret) == NULL);
        ASSERT(dwc_join(mid, sizeof mid, xdg, "zclassic23") == 0);
        ASSERT(dwc_join(cred_root, sizeof cred_root, mid, "credentials") == 0);
        ASSERT(dwc_is_mode(cred_root, 0700) == 1);
        ASSERT(dwc_join(cred, sizeof cred, cred_root,
                        "dev-wallet-passphrase.cred") == 0);
        ASSERT(dwc_eq_file(cred, k_secret) == 1);
        ASSERT(dwc_is_mode(cred, 0600) == 1);
        ASSERT(dwc_join(secret, sizeof secret, state, "secret") == 0);
        ASSERT(dwc_eq_file(secret, k_secret) == 1);
        n = snprintf(want, sizeof want,
                     "[Service]\nLoadCredentialEncrypted=wallet-passphrase:%s\n",
                     cred);
        ASSERT(n > 0);
        ASSERT((size_t)n < sizeof want);
        ASSERT(dwc_join(dropin, sizeof dropin, state, "dropin") == 0);
        ASSERT(dwc_eq_file(dropin, want) == 1);
        ASSERT(dwc_join(args, sizeof args, state, "edit-args") == 0);
        ASSERT(dwc_has(args, "--drop-in=91-wallet-credential.conf") == 1);
        ASSERT(dwc_has(args, "zcl23-dev.service") == 1);
        ASSERT(dwc_join(reloaded, sizeof reloaded, state, "reloaded") == 0);
        ASSERT(access(reloaded, F_OK) == 0);
        PASS();
    } _test_next:;
    dwc_restore(&saved);
    return failures;
}

static int dwc_case_missing(const char *root)
{
    struct dwc_saved saved;
    int failures = 0;
    if (dwc_save(&saved) != 0)
        return 1;
    TEST("dev-wallet credential: setup refuses a missing secret-tool") {
        char bin[1024], xdg[1024], repo[1024], log[1024], state[1024];
        char got[1024];
        int rc = 0;
        ASSERT(dwc_layout(root, "missing", bin, sizeof bin, xdg, sizeof xdg,
                          repo, sizeof repo, log, sizeof log, state,
                          sizeof state) == 0);
        ASSERT(dwc_bind_env(bin, xdg) == 0);
        ASSERT(dwc_capture("setup", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(got, "dev-wallet-credential: secret-tool is required\n");
        PASS();
    } _test_next:;
    dwc_restore(&saved);
    return failures;
}

static int dwc_case_unsafe(const char *root)
{
    struct dwc_saved saved;
    int failures = 0;
    if (dwc_save(&saved) != 0)
        return 1;
    TEST("dev-wallet credential: setup refuses a root inside the checkout") {
        char bin[1024], xdg[1024], repo[1024], log[1024], state[1024];
        char mid[1024], got[1024];
        int rc = 0;
        ASSERT(dwc_layout(root, "unsafe", bin, sizeof bin, xdg, sizeof xdg,
                          repo, sizeof repo, log, sizeof log, state,
                          sizeof state) == 0);
        ASSERT(dwc_tools_all(bin, state) == 0);
        ASSERT(dwc_join(mid, sizeof mid, xdg, "zclassic23") == 0);
        ASSERT(dwc_join(repo, sizeof repo, mid, "credentials") == 0);
        ASSERT(dwc_bind_env(bin, xdg) == 0);
        ASSERT(dwc_capture("setup", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(got, "dev-wallet-credential: credential root is unsafe\n");
        PASS();
    } _test_next:;
    dwc_restore(&saved);
    return failures;
}

static int dwc_case_relative(const char *root)
{
    struct dwc_saved saved;
    int failures = 0;
    if (dwc_save(&saved) != 0)
        return 1;
    TEST("dev-wallet credential: setup refuses a relative credential root") {
        char bin[1024], xdg[1024], repo[1024], log[1024], state[1024];
        char got[1024];
        int rc = 0;
        ASSERT(dwc_layout(root, "relative", bin, sizeof bin, xdg, sizeof xdg,
                          repo, sizeof repo, log, sizeof log, state,
                          sizeof state) == 0);
        ASSERT(dwc_tools_all(bin, state) == 0);
        ASSERT(dwc_bind_env(bin, xdg) == 0);
        ASSERT(setenv("XDG_DATA_HOME", "not-absolute", 1) == 0);
        ASSERT(dwc_capture("setup", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(got,
                      "dev-wallet-credential: credential root must be absolute\n");
        PASS();
    } _test_next:;
    dwc_restore(&saved);
    return failures;
}

static int dwc_case_private(const char *root)
{
    struct dwc_saved saved;
    int failures = 0;
    if (dwc_save(&saved) != 0)
        return 1;
    TEST("dev-wallet credential: setup chmods an owned credential dir to 700") {
        char bin[1024], xdg[1024], repo[1024], log[1024], state[1024];
        char cred_root[1024], cred[1024], got[1024];
        int rc = 1;
        ASSERT(dwc_layout(root, "private", bin, sizeof bin, xdg, sizeof xdg,
                          repo, sizeof repo, log, sizeof log, state,
                          sizeof state) == 0);
        ASSERT(dwc_tools_all(bin, state) == 0);
        ASSERT(dwc_tree(xdg, 0755, cred_root, sizeof cred_root) == 0);
        ASSERT(dwc_is_mode(cred_root, 0755) == 1);
        ASSERT(dwc_join(cred, sizeof cred, cred_root,
                        "dev-wallet-passphrase.cred") == 0);
        ASSERT(dwc_bind_env(bin, xdg) == 0);
        ASSERT(dwc_capture("setup", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 0);
        ASSERT_STR_EQ(got, k_bar3);
        ASSERT(strstr(got, k_secret) == NULL);
        ASSERT(dwc_is_mode(cred_root, 0700) == 1);
        ASSERT(dwc_eq_file(cred, k_secret) == 1);
        ASSERT(dwc_is_mode(cred, 0600) == 1);
        PASS();
    } _test_next:;
    dwc_restore(&saved);
    return failures;
}

static int dwc_case_usage(const char *root)
{
    struct dwc_saved saved;
    int failures = 0;
    if (dwc_save(&saved) != 0)
        return 1;
    TEST("dev-wallet credential: an unknown action prints usage") {
        char bin[1024], xdg[1024], repo[1024], log[1024], state[1024];
        char got[1024];
        int rc = 0;
        ASSERT(dwc_layout(root, "usage", bin, sizeof bin, xdg, sizeof xdg,
                          repo, sizeof repo, log, sizeof log, state,
                          sizeof state) == 0);
        ASSERT(dwc_bind_env(bin, xdg) == 0);
        ASSERT(dwc_capture("nope", repo, log, got, sizeof got, &rc) == 0);
        ASSERT(rc == 1);
        ASSERT_STR_EQ(got,
                      "dev-wallet-credential: usage: dev-wallet-credential "
                      "{setup|status}\n");
        PASS();
    } _test_next:;
    dwc_restore(&saved);
    return failures;
}

int test_dev_wallet_credential(void);
int test_dev_wallet_credential(void)
{
    char dir[1024];
    int failures;
    test_make_tmpdir(dir, sizeof dir, "dev_wallet_credential", "root");
    failures = dwc_case_blocked(dir);
    failures += dwc_case_file(dir);
    failures += dwc_case_ready(dir);
    failures += dwc_case_setup(dir);
    failures += dwc_case_missing(dir);
    failures += dwc_case_unsafe(dir);
    failures += dwc_case_relative(dir);
    failures += dwc_case_private(dir);
    failures += dwc_case_usage(dir);
    (void)test_rm_rf_recursive(dir);
    if (failures == 0)
        printf("test_dev_wallet_credential: all passed\n");
    else
        printf("test_dev_wallet_credential: %d FAILED\n", failures);
    return failures;
}
