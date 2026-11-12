/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Encrypt the dev-wallet passphrase into a user credential and
 *          report whether the secret, file, and unit binding are ready.
 *          Secret bytes are never printed. */

#include "dev_wallet_credential.h"

#include <stdio.h>
#include <string.h>

static int dwc_fail(const char *msg)
{
    fprintf(stderr, "dev-wallet-credential: %s\n", msg);
    return 1;
}

#if !defined(_WIN32)
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static const char k_dwc_prefix[] = "LoadCredentialEncrypted=wallet-passphrase:";
static const char k_dwc_unit[] = "zcl23-dev.service";
static const char k_dwc_dropin[] = "91-wallet-credential.conf";

static int dwc_fit(int n, size_t cap)
{
    return n > 0 && (size_t)n < cap;
}

static void dwc_close_high(int fd)
{
    if (fd > STDERR_FILENO)
        close(fd);
}

static int dwc_child(char *const argv[], int in_fd, int out_fd)
{
    int nullfd = open("/dev/null", O_RDWR);
    if (in_fd >= 0 && dup2(in_fd, STDIN_FILENO) < 0)
        _exit(127);
    if (out_fd >= 0 && dup2(out_fd, STDOUT_FILENO) < 0)
        _exit(127);
    if (out_fd < 0 && (nullfd < 0 || dup2(nullfd, STDOUT_FILENO) < 0))
        _exit(127);
    if (nullfd >= 0 && dup2(nullfd, STDERR_FILENO) < 0)
        _exit(127);
    dwc_close_high(nullfd);
    dwc_close_high(in_fd);
    if (out_fd != in_fd)
        dwc_close_high(out_fd);
    execvp(argv[0], argv);
    _exit(127);
}

static int dwc_write_all(int fd, const char *text)
{
    size_t n = text == NULL ? 0 : strlen(text);
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, text + off, n - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

static int dwc_reap(pid_t pid)
{
    int status = 0;
    pid_t got;
    do {
        got = waitpid(pid, &status, 0);
    } while (got < 0 && errno == EINTR);
    if (got != pid)
        return -1;
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return -1;
}

static void dwc_close_pair(int fds[2])
{
    if (fds[0] >= 0)
        close(fds[0]);
    if (fds[1] >= 0)
        close(fds[1]);
}

static int dwc_slurp(int fd, char *out, size_t cap)
{
    size_t used = 0;
    char chunk[512];
    ssize_t n;
    int overflow = 0;
    out[0] = '\0';
    for (;;) {
        n = read(fd, chunk, sizeof chunk);
        if (n == 0)
            break;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        size_t take = (size_t)n;
        if (used + 1 >= cap) {
            overflow = 1;
            continue;
        }
        if (used + take >= cap) {
            overflow = 1;
            take = cap > used + 1 ? cap - 1 - used : 0;
        }
        if (take == 0)
            continue;
        memcpy(out + used, chunk, take);
        used += take;
        out[used] = '\0';
    }
    close(fd);
    return overflow ? -1 : 0;
}

static int dwc_spawn(char *const argv[], int in_r, int in_w, int out_r, int out_w)
{
    pid_t pid = fork();
    if (pid < 0)
        return -1;
    if (pid == 0) {
        if (in_w >= 0)
            close(in_w);
        if (out_r >= 0)
            close(out_r);
        dwc_child(argv, in_r, out_w);
        _exit(127);
    }
    if (in_r >= 0)
        close(in_r);
    if (out_w >= 0)
        close(out_w);
    return (int)pid;
}

static int dwc_parent(pid_t pid, int in_w, int out_r, const char *input,
                      char *out, size_t cap, int *status)
{
    int slurp = 0;
    if (input != NULL && dwc_write_all(in_w, input) != 0) {
        if (in_w >= 0)
            close(in_w);
        if (out_r >= 0)
            close(out_r);
        dwc_reap(pid);
        return -1;
    }
    if (in_w >= 0)
        close(in_w);
    if (out != NULL)
        slurp = dwc_slurp(out_r, out, cap);
    *status = dwc_reap(pid);
    if (slurp != 0 || *status < 0)
        return -1;
    return 0;
}

static int dwc_open_pipes(const char *input, char *out, int in_pipe[2],
                          int out_pipe[2])
{
    in_pipe[0] = -1;
    in_pipe[1] = -1;
    out_pipe[0] = -1;
    out_pipe[1] = -1;
    if (input != NULL && pipe(in_pipe) != 0)
        return -1;
    if (out != NULL && pipe(out_pipe) != 0) {
        dwc_close_pair(in_pipe);
        return -1;
    }
    return 0;
}

/* Run argv. input, when set, is the child's stdin. stdout is captured
 * into out when out is non-NULL; otherwise it is discarded. */
static int dwc_run(char *const argv[], const char *input, char *out, size_t cap,
                   int *status)
{
    int in_pipe[2];
    int out_pipe[2];
    int pid;
    if (status == NULL)
        return -1;
    if (dwc_open_pipes(input, out, in_pipe, out_pipe) != 0)
        return -1;
    pid = dwc_spawn(argv, in_pipe[0], in_pipe[1], out_pipe[0], out_pipe[1]);
    if (pid < 0) {
        dwc_close_pair(in_pipe);
        dwc_close_pair(out_pipe);
        return -1;
    }
    return dwc_parent(pid, in_pipe[1], out_pipe[0], input, out, cap, status);
}

static int dwc_on_path(const char *name)
{
    const char *path = getenv("PATH");
    const char *p;
    if (name == NULL || path == NULL || path[0] == '\0')
        return 0;
    p = path;
    while (*p != '\0') {
        char buf[PATH_MAX];
        const char *colon = strchr(p, ':');
        size_t n = colon != NULL ? (size_t)(colon - p) : strlen(p);
        int wr;
        if (n == 0) {
            p = colon != NULL ? colon + 1 : p + strlen(p);
            continue;
        }
        wr = snprintf(buf, sizeof buf, "%.*s/%s", (int)n, p, name);
        if (dwc_fit(wr, sizeof buf) && access(buf, X_OK) == 0)
            return 1;
        if (colon == NULL)
            break;
        p = colon + 1;
    }
    return 0;
}

/* File readiness matches `stat -c %a` == 600: a regular file, no owner
 * check. Directory readiness matches `%u:%a` == "<uid>:700". */
static int dwc_mode_is(const char *path, const char *octal, int want_dir)
{
    struct stat st;
    char got[16];
    unsigned mode;
    if (stat(path, &st) != 0)
        return 0;
    if (want_dir) {
        if (!S_ISDIR(st.st_mode) || st.st_uid != getuid())
            return 0;
    } else if (!S_ISREG(st.st_mode)) {
        return 0;
    }
    mode = (unsigned)(st.st_mode & 07777);
    if (snprintf(got, sizeof got, "%o", mode) >= (int)sizeof got)
        return 0;
    return strcmp(got, octal) == 0;
}

static int dwc_cred_root(char *out, size_t cap)
{
    const char *xdg = getenv("XDG_DATA_HOME");
    const char *home = getenv("HOME");
    int n;
    if (xdg != NULL && xdg[0] != '\0')
        n = snprintf(out, cap, "%s/zclassic23/credentials", xdg);
    else if (home != NULL && home[0] != '\0')
        n = snprintf(out, cap, "%s/.local/share/zclassic23/credentials", home);
    else
        return -1;
    return dwc_fit(n, cap) ? 0 : -1;
}

static int dwc_unsafe(const char *root, const char *repo)
{
    size_t n;
    if (strcmp(root, "/") == 0 || strcmp(root, "/tmp") == 0)
        return 1;
    if (repo == NULL || repo[0] == '\0')
        return 0;
    if (strcmp(root, repo) == 0)
        return 1;
    n = strlen(repo);
    return strncmp(root, repo, n) == 0 && root[n] == '/';
}

static int dwc_mkdir_p(const char *path)
{
    char buf[PATH_MAX];
    size_t i;
    size_t n;
    if (path == NULL || path[0] != '/')
        return -1;
    n = strlen(path);
    if (n >= sizeof buf)
        return -1;
    memcpy(buf, path, n + 1);
    for (i = 1; i < n; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, 0700) != 0 && errno != EEXIST)
            return -1;
        buf[i] = '/';
    }
    if (mkdir(buf, 0700) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int dwc_secret_present(void)
{
    char *argv[] = {
        "secret-tool", "lookup", "application", "zclassic23",
        "wallet-scope", "dev", "credential", "wallet-passphrase", NULL
    };
    int status = 1;
    if (dwc_run(argv, NULL, NULL, 0, &status) != 0)
        return 0;
    return status == 0;
}

static int dwc_file_ready(const char *cred_file)
{
    return dwc_mode_is(cred_file, "600", 0);
}

static int dwc_unit_ready(void)
{
    char *argv[] = {"systemctl", "--user", "cat", (char *)k_dwc_unit, NULL};
    char text[8192];
    int status = 1;
    const char *p;
    if (dwc_run(argv, NULL, text, sizeof text, &status) != 0 || status != 0)
        return 0;
    p = text;
    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t n = nl != NULL ? (size_t)(nl - p) : strlen(p);
        if (n >= sizeof k_dwc_prefix - 1 &&
            memcmp(p, k_dwc_prefix, sizeof k_dwc_prefix - 1) == 0)
            return 1;
        if (nl == NULL)
            break;
        p = nl + 1;
    }
    return 0;
}

static void dwc_emit(int n)
{
    const char *bar = "---";
    const char *state = "blocked";
    if (n >= 1)
        bar = "#--";
    if (n >= 2)
        bar = "##-";
    if (n == 3) {
        bar = "###";
        state = "ready";
    }
    printf("dev-wallet-credential: [%s] %d/3 state=%s "
           "secret=redacted config=encrypted\n",
           bar, n, state);
}

static int dwc_status(const char *cred_file)
{
    int n = 0;
    if (dwc_secret_present())
        n++;
    if (dwc_file_ready(cred_file))
        n++;
    if (dwc_unit_ready())
        n++;
    dwc_emit(n);
    return 0;
}

static void dwc_strip_trailing(char *text)
{
    size_t n;
    if (text == NULL)
        return;
    n = strlen(text);
    while (n > 0 && text[n - 1] == '\n')
        text[--n] = '\0';
}

static void dwc_strip_newlines(char *text)
{
    char *r = text;
    char *w = text;
    if (text == NULL)
        return;
    while (*r != '\0') {
        if (*r != '\n')
            *w++ = *r;
        r++;
    }
    *w = '\0';
}

static int dwc_lookup(char *secret, size_t cap)
{
    char *argv[] = {
        "secret-tool", "lookup", "application", "zclassic23",
        "wallet-scope", "dev", "credential", "wallet-passphrase", NULL
    };
    int status = 1;
    secret[0] = '\0';
    if (dwc_run(argv, NULL, secret, cap, &status) != 0)
        return -1;
    if (status != 0)
        secret[0] = '\0';
    dwc_strip_trailing(secret);
    return 0;
}

static int dwc_mint(char *secret, size_t cap)
{
    char *argv[] = {"openssl", "rand", "-base64", "48", NULL};
    int status = 1;
    if (dwc_run(argv, NULL, secret, cap, &status) != 0 || status != 0)
        return -1;
    dwc_strip_newlines(secret);
    return secret[0] == '\0' ? -1 : 0;
}

static int dwc_store(const char *secret)
{
    char *argv[] = {
        "secret-tool", "store", "--label=Z23 dev wallet unlock",
        "application", "zclassic23", "wallet-scope", "dev",
        "credential", "wallet-passphrase", NULL
    };
    int status = 1;
    if (dwc_run(argv, secret, NULL, 0, &status) != 0)
        return -1;
    return status == 0 ? 0 : -1;
}

static int dwc_encrypt(const char *secret, const char *candidate)
{
    char *argv[] = {
        "systemd-creds", "--user", "--name=wallet-passphrase",
        "--newline=no", "encrypt", "-", (char *)candidate, NULL
    };
    int status = 1;
    if (dwc_run(argv, secret, NULL, 0, &status) != 0)
        return -1;
    return status == 0 ? 0 : -1;
}

static int dwc_bind(const char *cred_file)
{
    char body[PATH_MAX + 80];
    char dropin[64];
    char *edit[] = {
        "systemctl", "--user", "edit", dropin,
        "--stdin", (char *)k_dwc_unit, NULL
    };
    char *reload[] = {"systemctl", "--user", "daemon-reload", NULL};
    int status = 1;
    int n = snprintf(dropin, sizeof dropin, "--drop-in=%s", k_dwc_dropin);
    if (!dwc_fit(n, sizeof dropin))
        return -1;
    n = snprintf(body, sizeof body,
                 "[Service]\nLoadCredentialEncrypted=wallet-passphrase:%s\n",
                 cred_file);
    if (!dwc_fit(n, sizeof body))
        return -1;
    if (dwc_run(edit, body, NULL, 0, &status) != 0 || status != 0)
        return -1;
    if (dwc_run(reload, NULL, NULL, 0, &status) != 0 || status != 0)
        return -1;
    return 0;
}

static int dwc_require_tools(void)
{
    if (!dwc_on_path("secret-tool"))
        return dwc_fail("secret-tool is required");
    if (!dwc_on_path("systemd-creds"))
        return dwc_fail("systemd-creds is required");
    if (!dwc_on_path("openssl"))
        return dwc_fail("openssl is required");
    return 0;
}

static int dwc_check_root(const char *root, const char *repo)
{
    if (dwc_unsafe(root, repo))
        return dwc_fail("credential root is unsafe");
    if (root[0] != '/')
        return dwc_fail("credential root must be absolute");
    return 0;
}

static int dwc_secret(char *secret, size_t cap)
{
    if (dwc_lookup(secret, cap) != 0)
        return -1;
    if (secret[0] != '\0')
        return 0;
    if (dwc_mint(secret, cap) != 0)
        return -1;
    return dwc_store(secret);
}

/* install -d -m 700 creates the leaf and chmods it even when it already
 * exists. Parents are left as mkdir created them. The uid:700 check is
 * the shell's stat -c '%u:%a' comparison. */
static int dwc_prepare_root(const char *root)
{
    struct stat st;
    if (dwc_mkdir_p(root) != 0)
        return -1;
    if (stat(root, &st) != 0)
        return dwc_fail("credential root must be private and owned by the current user");
    if (!S_ISDIR(st.st_mode) || st.st_uid != getuid())
        return dwc_fail("credential root must be private and owned by the current user");
    if (chmod(root, 0700) != 0)
        return dwc_fail("credential root must be private and owned by the current user");
    if (!dwc_mode_is(root, "700", 1))
        return dwc_fail("credential root must be private and owned by the current user");
    return 0;
}

static int dwc_install_file(const char *root, const char *secret, char *cred,
                            size_t cap)
{
    char candidate[PATH_MAX];
    int n;
    int prepared = dwc_prepare_root(root);
    if (prepared != 0)
        return prepared;
    n = snprintf(cred, cap, "%s/dev-wallet-passphrase.cred", root);
    if (!dwc_fit(n, cap))
        return -1;
    n = snprintf(candidate, sizeof candidate,
                 "%s/.dev-wallet-passphrase.cred.tmp", root);
    if (!dwc_fit(n, sizeof candidate))
        return -1;
    unlink(candidate);
    if (dwc_encrypt(secret, candidate) != 0)
        return -1;
    if (chmod(candidate, 0600) != 0)
        return -1;
    if (rename(candidate, cred) != 0)
        return -1;
    return 0;
}

static int dwc_setup(const char *repo)
{
    char root[PATH_MAX];
    char cred[PATH_MAX];
    char secret[512];
    int rc;
    if (dwc_require_tools() != 0)
        return 1;
    if (dwc_cred_root(root, sizeof root) != 0)
        return dwc_fail("HOME is unset");
    if (dwc_check_root(root, repo) != 0)
        return 1;
    if (dwc_secret(secret, sizeof secret) != 0) {
        memset(secret, 0, sizeof secret);
        return dwc_fail("could not provision the wallet secret");
    }
    rc = dwc_install_file(root, secret, cred, sizeof cred);
    memset(secret, 0, sizeof secret);
    if (rc != 0)
        return rc < 0 ? dwc_fail("could not write the encrypted credential") : rc;
    if (dwc_bind(cred) != 0)
        return dwc_fail("could not bind the wallet credential into the dev unit");
    return dwc_status(cred);
}

static int dwc_report(void)
{
    char root[PATH_MAX];
    char cred[PATH_MAX];
    if (dwc_cred_root(root, sizeof root) != 0)
        return dwc_fail("HOME is unset");
    if (snprintf(cred, sizeof cred, "%s/dev-wallet-passphrase.cred", root) >=
        (int)sizeof cred)
        return dwc_fail("credential path does not fit");
    return dwc_status(cred);
}

static int dwc_invoke(const char *argv0, const char *action, const char *repo)
{
    const char *name = (argv0 != NULL && argv0[0] != '\0')
                           ? argv0 : "dev-wallet-credential";
    if (action == NULL || strcmp(action, "status") == 0)
        return dwc_report();
    if (strcmp(action, "setup") == 0)
        return dwc_setup(repo);
    fprintf(stderr, "dev-wallet-credential: usage: %s {setup|status}\n", name);
    return 1;
}

#endif /* !_WIN32 */

int zcl_dev_wallet_credential(const char *argv0, const char *action,
                              const char *repo)
{
#if defined(_WIN32)
    (void)argv0;
    (void)action;
    (void)repo;
    return dwc_fail("unavailable on Windows");
#else
    return dwc_invoke(argv0, action, repo);
#endif
}
