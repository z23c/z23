/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Born-green, born-red, and exact-revert proof for source-bundle
 *          policy. Stages each candidate onto the owner file, asks dev drive
 *          for a bound hotfork story, and restores the saved backup. */

#include "reflex_hotfork_source_bundle.h"

#include <stdio.h>
#include <string.h>

#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define RSB_FILE_MAX 262144
#define RSB_OUT_MAX 262144
#define RSB_HEX 80

static char g_file[RSB_FILE_MAX];
static char g_cap[RSB_OUT_MAX];
static size_t g_cap_n;
static char g_sig_source[PATH_MAX];
static char g_sig_backup[PATH_MAX];
static char g_sig_bin[PATH_MAX];
static char g_sig_arg[640];
static char *g_sig_argv[6];
static volatile sig_atomic_t g_armed;
static volatile sig_atomic_t g_stop_ready;
static struct sigaction g_old_int, g_old_term;
static int g_handlers;

struct rsb_story {
    char event[32];
    long long feedback_us;
    char object_root[RSB_HEX];
    char module_root[RSB_HEX];
    char observation[RSB_HEX];
};

struct rsb_wait {
    long long compilers;
    long long linkers;
};

struct rsb_job {
    char root[PATH_MAX];
    char bin[PATH_MAX];
    char source[PATH_MAX];
    char output[PATH_MAX];
    char backup[PATH_MAX];
    char nonce[64];
    long long watcher_id;
    char session[256];
    long long epoch;
    long long green_epoch;
    long long revert_epoch;
    int armed;
    int have_watcher;
    struct rsb_story green, red, revert;
    struct rsb_wait cached;
};

struct rsb_spec {
    const char *label;
    const char *source_tail;
    const char *output_tail;
    const char *backup_leaf;
    const char *stage_leaf;
    const char *stamp_mark;
    const char *story_id;
    const char *owner;
    const char *mut_from;
    const char *mut_to;
    int mut_exact;
};

static const struct rsb_spec k_source_spec = {
    "reflex-hotfork-source-bundle-acceptance",
    "/tools/command/native_zcode_source_bundle_command.c",
    "/build/dev-loop/reflex-hotfork-source-bundle-acceptance.json",
    "zcl-reflex-source-bundle",
    ".reflex-source-bundle",
    "ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE",
    "zcode-source-bundle-input-policy.v1",
    "tools/command/native_zcode_source_bundle_command.c",
    "return strcmp(left, right) != 0 &&",
    "return strcmp(left, right) == 0 &&",
    1,
};

static const struct rsb_spec k_transport_spec = {
    "reflex-hotfork-transport-acceptance",
    "/contexts/commons/modules/vcs/src/source_package_transport.c",
    "/build/dev-loop/reflex-hotfork-transport-acceptance.json",
    "zcl-reflex-transport",
    ".reflex-transport",
    "ZCL_REFLEX_TRANSPORT_ACCEPTANCE",
    "source-package-transport-shape.v1",
    "contexts/commons/modules/vcs/src/source_package_transport.c",
    "if (index == 0) {",
    "if (index == 1) {",
    0,
};

static const struct rsb_spec *g_spec = &k_source_spec;

static int rsb_fail(const char *msg)
{
    fprintf(stderr, "%s: %s\n", g_spec->label, msg);
    return 2;
}

static int rsb_fail2(const char *prefix, const char *detail)
{
    fprintf(stderr, "%s: %s%s\n", g_spec->label, prefix, detail);
    return 2;
}

static int rsb_gap(unsigned char c)
{
    switch (c) {
    case ' ':
    case '\t':
    case '\n':
    case '\r':
        return 1;
    default:
        return 0;
    }
}

static const char *rsb_ws(const char *p, const char *end)
{
    while (p < end && rsb_gap((unsigned char)*p) != 0)
        p++;
    return p;
}

static int rsb_delim(char c)
{
    return c == ',' || c == '}' || c == ']' || c == ' ' || c == '\n' ||
           c == '\r' || c == '\t';
}

static const char *rsb_skip_str(const char *p, const char *end)
{
    if (p >= end || *p != '"')
        return NULL;
    for (p++; p < end; p++) {
        if (*p == '\\') {
            if (p + 1 >= end)
                return NULL;
            p++;
            continue;
        }
        if (*p == '"')
            return p + 1;
    }
    return NULL;
}

static const char *rsb_skip_atom(const char *p, const char *end)
{
    while (p < end && !rsb_delim(*p))
        p++;
    return p;
}

static const char *rsb_skip_box(const char *p, const char *end)
{
    int depth = 0;
    if (p >= end || (*p != '{' && *p != '['))
        return NULL;
    for (; p < end; p++) {
        if (*p == '"') {
            p = rsb_skip_str(p, end);
            if (p == NULL)
                return NULL;
            p--;
            continue;
        }
        if (*p == '{' || *p == '[')
            depth++;
        else if (*p == '}' || *p == ']') {
            depth--;
            if (depth == 0)
                return p + 1;
        }
    }
    return NULL;
}

static const char *rsb_skip_val(const char *p, const char *end)
{
    p = rsb_ws(p, end);
    if (p >= end)
        return NULL;
    if (*p == '"')
        return rsb_skip_str(p, end);
    if (*p == '{' || *p == '[')
        return rsb_skip_box(p, end);
    return rsb_skip_atom(p, end);
}

static int rsb_key_is(const char *p, const char *end, const char *key,
                      const char **after)
{
    size_t n = strlen(key);
    if (p >= end || *p != '"')
        return 0;
    if ((size_t)(end - p) < n + 2)
        return 0;
    if (memcmp(p + 1, key, n) != 0 || p[1 + n] != '"')
        return 0;
    *after = p + n + 2;
    return 1;
}

static const char *rsb_after_field(const char *p, const char *end)
{
    const char *val = rsb_skip_str(p, end);
    if (val == NULL)
        return NULL;
    val = rsb_ws(val, end);
    if (val >= end || *val != ':')
        return NULL;
    val = rsb_skip_val(val + 1, end);
    if (val == NULL)
        return NULL;
    val = rsb_ws(val, end);
    if (val < end && *val == ',')
        return val + 1;
    return val;
}

static const char *rsb_field(const char *p, const char *end, const char *key)
{
    const char *after = NULL;
    p = rsb_ws(p, end);
    if (p >= end || *p != '{')
        return NULL;
    p++;
    for (;;) {
        p = rsb_ws(p, end);
        if (p >= end || *p == '}')
            return NULL;
        if (rsb_key_is(p, end, key, &after)) {
            after = rsb_ws(after, end);
            if (after >= end || *after != ':')
                return NULL;
            return rsb_ws(after + 1, end);
        }
        p = rsb_after_field(p, end);
        if (p == NULL)
            return NULL;
    }
}

static int rsb_unquote(const char *p, const char *end, char *out, size_t cap)
{
    size_t n = 0;
    if (p >= end || *p != '"')
        return -1;
    for (p++; p < end; p++) {
        char c = *p;
        if (c == '"') {
            if (n >= cap)
                return -1;
            out[n] = 0;
            return 0;
        }
        if (c == '\\') {
            if (p + 1 >= end)
                return -1;
            p++;
            c = *p;
        }
        if (n + 1 >= cap)
            return -1;
        out[n++] = c;
    }
    return -1;
}

static int rsb_is_lit(const char *p, const char *end, const char *lit, size_t n)
{
    if (p == NULL || (size_t)(end - p) < n || memcmp(p, lit, n) != 0)
        return 0;
    if ((size_t)(end - p) == n)
        return 1;
    return rsb_delim(p[n]);
}

static int rsb_u64_digits(const char *p, const char *end, long long *out)
{
    long long v = 0;
    int saw = 0;
    p = rsb_ws(p, end);
    while (p < end && *p >= '0' && *p <= '9') {
        if (v > (9223372036854775807LL - 9) / 10)
            return -1;
        v = v * 10 + (*p - '0');
        p++;
        saw = 1;
    }
    if (!saw)
        return -1;
    if (p < end && !rsb_delim(*p))
        return -1;
    *out = v;
    return 0;
}

static int rsb_copy_str(const char *obj, const char *end, const char *key,
                        char *out, size_t cap)
{
    const char *v = rsb_field(obj, end, key);
    if (v == NULL)
        return -1;
    return rsb_unquote(v, end, out, cap);
}

static int rsb_copy_i64(const char *obj, const char *end, const char *key,
                        long long *out)
{
    const char *v = rsb_field(obj, end, key);
    if (v == NULL)
        return -1;
    return rsb_u64_digits(v, end, out);
}

static const char *rsb_data(const char *json, const char *end, const char **dend)
{
    const char *data = rsb_field(json, end, "data");
    if (data == NULL || *data != '{')
        return NULL;
    *dend = rsb_skip_box(data, end);
    if (*dend == NULL)
        return NULL;
    return data;
}

static int rsb_reap(pid_t child)
{
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    while (got < 0 && errno == EINTR)
        got = waitpid(child, &status, 0);
    if (got != child)
        return 125;
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 125;
}

static int rsb_read_all(int fd, char *buf, size_t cap, size_t *out)
{
    size_t n = 0;
    if (cap < 2)
        return -1;
    for (;;) {
        ssize_t got;
        if (n + 1 >= cap)
            return 1;
        got = read(fd, buf + n, cap - 1 - n);
        if (got == 0)
            break;
        if (got < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        n += (size_t)got;
    }
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        n--;
    buf[n] = 0;
    *out = n;
    return 0;
}

static int rsb_exec(char *const argv[], char *buf, size_t cap, size_t *out)
{
    int fds[2];
    pid_t child;
    int rd;
    if (pipe(fds) != 0)
        return 127;
    child = fork();
    if (child < 0) {
        close(fds[0]);
        close(fds[1]);
        return 127;
    }
    if (child == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0)
            _exit(127);
        if (fds[1] != STDOUT_FILENO)
            close(fds[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(fds[1]);
    rd = rsb_read_all(fds[0], buf, cap, out);
    close(fds[0]);
    if (rd != 0) {
        (void)rsb_reap(child);
        if (rd > 0)
            return rsb_fail("dev reply is too large");
        return 127;
    }
    return rsb_reap(child);
}

static int rsb_exec_quiet(char *const argv[])
{
    pid_t child = fork();
    int sink;
    if (child < 0)
        return 127;
    if (child == 0) {
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        sink = open("/dev/null", O_WRONLY);
        if (sink < 0)
            _exit(127);
        if (dup2(sink, STDOUT_FILENO) < 0 || dup2(sink, STDERR_FILENO) < 0)
            _exit(127);
        if (sink > STDERR_FILENO)
            close(sink);
        execvp(argv[0], argv);
        _exit(127);
    }
    return rsb_reap(child);
}

static void rsb_restore_fd(void)
{
    char buf[4096];
    int in;
    int out;
    if (!g_armed)
        return;
    in = open(g_sig_backup, O_RDONLY);
    if (in < 0)
        return;
    out = open(g_sig_source, O_WRONLY | O_TRUNC);
    if (out < 0) {
        close(in);
        return;
    }
    for (;;) {
        ssize_t n = read(in, buf, sizeof buf);
        ssize_t off = 0;
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        while (off < n) {
            ssize_t w = write(out, buf + off, (size_t)(n - off));
            if (w < 0 && errno == EINTR)
                continue;
            if (w <= 0) {
                close(in);
                close(out);
                return;
            }
            off += w;
        }
    }
    close(in);
    close(out);
}

static void rsb_stop_async(void)
{
    pid_t child;
    if (!g_stop_ready)
        return;
    g_stop_ready = 0;
    child = fork();
    if (child < 0)
        return;
    if (child == 0) {
        execv(g_sig_bin, g_sig_argv);
        _exit(127);
    }
    for (;;) {
        int status = 0;
        pid_t got = waitpid(child, &status, 0);
        if (got == child || (got < 0 && errno != EINTR))
            break;
    }
}

static void rsb_on_sig(int sig)
{
    rsb_stop_async();
    rsb_restore_fd();
    _exit(128 + (sig & 127));
}

static void rsb_arm_signals(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = rsb_on_sig;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGINT);
    sigaddset(&sa.sa_mask, SIGTERM);
    if (sigaction(SIGINT, &sa, &g_old_int) == 0 &&
        sigaction(SIGTERM, &sa, &g_old_term) == 0)
        g_handlers = 1;
}

static void rsb_disarm_signals(void)
{
    if (!g_handlers)
        return;
    sigaction(SIGINT, &g_old_int, NULL);
    sigaction(SIGTERM, &g_old_term, NULL);
    g_handlers = 0;
}

static int rsb_slurp(const char *path, char *buf, size_t cap, size_t *out,
                     mode_t *mode)
{
    struct stat st;
    int fd;
    size_t n = 0;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode))
        return -1;
    if (st.st_size < 0 || (size_t)st.st_size + 1 > cap)
        return -1;
    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    while (n < (size_t)st.st_size) {
        ssize_t got = read(fd, buf + n, (size_t)st.st_size - n);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        n += (size_t)got;
    }
    close(fd);
    if (n != (size_t)st.st_size)
        return -1;
    buf[n] = 0;
    *out = n;
    if (mode != NULL)
        *mode = st.st_mode & 0777;
    return 0;
}

static int rsb_write_all(int fd, const char *body, size_t n)
{
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, body + off, n - off);
        if (w < 0 && errno == EINTR)
            continue;
        if (w <= 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

static int rsb_stage(const char *dir, const char *dest, const char *body,
                     size_t n, mode_t mode)
{
    char temp[PATH_MAX];
    int fd;
    int nw = snprintf(temp, sizeof temp, "%s/%s.XXXXXX", dir, g_spec->stage_leaf);
    if (nw < 0)
        return -1;
    if ((size_t)nw >= sizeof temp)
        return -1;
    fd = mkstemp(temp);
    if (fd < 0)
        return -1;
    if (rsb_write_all(fd, body, n) != 0 || fchmod(fd, mode) != 0) {
        close(fd);
        unlink(temp);
        return -1;
    }
    if (close(fd) != 0) {
        unlink(temp);
        return -1;
    }
    if (rename(temp, dest) != 0) {
        unlink(temp);
        return -1;
    }
    return 0;
}

static int rsb_dirname(const char *path, char *out, size_t cap)
{
    const char *slash = strrchr(path, '/');
    size_t n;
    if (slash == NULL || slash == path)
        return -1;
    n = (size_t)(slash - path);
    if (n + 1 > cap)
        return -1;
    memcpy(out, path, n);
    out[n] = 0;
    return 0;
}

static int rsb_install(struct rsb_job *job, const char *body, size_t n)
{
    char dir[PATH_MAX];
    struct stat st;
    mode_t mode = 0644;
    if (stat(job->source, &st) == 0)
        mode = st.st_mode & 0777;
    if (rsb_dirname(job->source, dir, sizeof dir) != 0)
        return rsb_fail("cannot stage candidate");
    if (rsb_stage(dir, job->source, body, n, mode) != 0)
        return rsb_fail("cannot stage candidate");
    return 0;
}

static int rsb_put(char *out, size_t cap, const char *text)
{
    size_t n = strlen(text);
    if (n + 1 > cap)
        return -1;
    memcpy(out, text, n + 1);
    return 0;
}

static int rsb_root(struct rsb_job *job)
{
    const char *env = getenv("ZCL_SOURCE_ROOT");
    if (env != NULL && env[0] != '\0')
        return rsb_put(job->root, sizeof job->root, env);
    if (getcwd(job->root, sizeof job->root) == NULL)
        return -1;
    return 0;
}

static int rsb_join(char *out, size_t cap, const char *root, const char *tail)
{
    int nw = snprintf(out, cap, "%s%s", root, tail);
    if (nw < 0)
        return -1;
    if ((size_t)nw >= cap)
        return -1;
    return 0;
}

static const char *rsb_output_env(void)
{
    if (g_spec == &k_transport_spec)
        return getenv("ZCL_REFLEX_TRANSPORT_ACCEPTANCE_OUTPUT");
    return getenv("ZCL_REFLEX_SOURCE_BUNDLE_ACCEPTANCE_OUTPUT");
}

static int rsb_output(struct rsb_job *job)
{
    const char *env = rsb_output_env();
    if (env != NULL && env[0] != '\0')
        return rsb_put(job->output, sizeof job->output, env);
    return rsb_join(job->output, sizeof job->output, job->root, g_spec->output_tail);
}

static int rsb_resolve(struct rsb_job *job)
{
    const char *dev = getenv("ZCL_DEV_BIN");
    if (rsb_root(job) != 0)
        return rsb_fail("cannot resolve the source root");
    if (dev != NULL && dev[0] != '\0') {
        if (rsb_put(job->bin, sizeof job->bin, dev) != 0)
            return rsb_fail("acceptance path is too long");
    } else if (rsb_join(job->bin, sizeof job->bin, job->root,
                        "/build/bin/z23-dev") != 0) {
        return rsb_fail("acceptance path is too long");
    }
    if (rsb_join(job->source, sizeof job->source, job->root,
                 g_spec->source_tail) != 0)
        return rsb_fail("acceptance path is too long");
    if (rsb_output(job) != 0)
        return rsb_fail("acceptance path is too long");
    return 0;
}

static int rsb_backup(struct rsb_job *job)
{
    const char *tmp = getenv("TMPDIR");
    char tmpl[PATH_MAX];
    size_t n = 0;
    mode_t mode = 0644;
    int fd;
    int nw;
    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    nw = snprintf(tmpl, sizeof tmpl, "%s/%s.XXXXXX", tmp, g_spec->backup_leaf);
    if (nw < 0 || (size_t)nw >= sizeof tmpl)
        return rsb_fail("cannot save the owner source");
    if (rsb_slurp(job->source, g_file, sizeof g_file, &n, &mode) != 0)
        return rsb_fail("cannot read the owner source");
    fd = mkstemp(tmpl);
    if (fd < 0)
        return rsb_fail("cannot save the owner source");
    if (rsb_write_all(fd, g_file, n) != 0 || fchmod(fd, mode) != 0) {
        close(fd);
        unlink(tmpl);
        return rsb_fail("cannot save the owner source");
    }
    if (close(fd) != 0) {
        unlink(tmpl);
        return rsb_fail("cannot save the owner source");
    }
    if (rsb_put(job->backup, sizeof job->backup, tmpl) != 0 ||
        rsb_put(g_sig_source, sizeof g_sig_source, job->source) != 0 ||
        rsb_put(g_sig_backup, sizeof g_sig_backup, job->backup) != 0) {
        unlink(tmpl);
        return rsb_fail("cannot save the owner source");
    }
    g_armed = 1;
    job->armed = 1;
    rsb_arm_signals();
    return 0;
}

static int rsb_prepare(struct rsb_job *job)
{
    struct stat st;
    int rc = rsb_resolve(job);
    if (rc != 0)
        return rc;
    if (access(job->bin, X_OK) != 0)
        return rsb_fail2("missing dev binary: ", job->bin);
    if (lstat(job->source, &st) != 0 || !S_ISREG(st.st_mode))
        return rsb_fail2("owner source is not a regular file: ", job->source);
    return rsb_backup(job);
}

static int rsb_begin(struct rsb_job *job)
{
    char *argv[] = {job->bin, "dev", "begin", NULL};
    const char *data;
    const char *dend;
    int rc = rsb_exec(argv, g_cap, sizeof g_cap, &g_cap_n);
    if (rc != 0)
        return rc;
    data = rsb_data(g_cap, g_cap + g_cap_n, &dend);
    if (data == NULL ||
        rsb_copy_i64(data, dend, "watcher_id", &job->watcher_id) != 0)
        return rsb_fail("watcher id missing");
    job->have_watcher = job->watcher_id > 0;
    if (rsb_copy_str(data, dend, "watcher_session", job->session,
                     sizeof job->session) != 0)
        return rsb_fail("watcher session missing");
    if (rsb_copy_i64(data, dend, "epoch", &job->epoch) != 0)
        return rsb_fail("event cursor missing");
    if (job->have_watcher) {
        int nw = snprintf(g_sig_arg, sizeof g_sig_arg,
                          "--input={\"watcher_id\":%lld,\"watcher_session\":\"%s\"}",
                          job->watcher_id, job->session);
        if (nw > 0 && (size_t)nw < sizeof g_sig_arg &&
            rsb_put(g_sig_bin, sizeof g_sig_bin, job->bin) == 0) {
            g_sig_argv[0] = g_sig_bin;
            g_sig_argv[1] = "dev";
            g_sig_argv[2] = "loop";
            g_sig_argv[3] = "stop";
            g_sig_argv[4] = g_sig_arg;
            g_sig_argv[5] = NULL;
            g_stop_ready = 1;
        }
    }
    return 0;
}

static int rsb_nonce(struct rsb_job *job)
{
    char *argv[] = {"date", "+%s%N", NULL};
    char buf[64];
    size_t n = 0;
    int rc = rsb_exec(argv, buf, sizeof buf, &n);
    if (rc != 0)
        return rc;
    if (n == 0 || n + 1 > sizeof job->nonce)
        return rsb_fail("nonce unavailable");
    memcpy(job->nonce, buf, n + 1);
    return 0;
}

static int rsb_stamp(char *buf, size_t *len, size_t cap, const char *nonce)
{
    int nw;
    if (*len >= cap)
        return -1;
    nw = snprintf(buf + *len, cap - *len, "\n/* %s:%s */\n", g_spec->stamp_mark,
                  nonce);
    if (nw < 0)
        return -1;
    if (*len + (size_t)nw >= cap)
        return -1;
    *len += (size_t)nw;
    return 0;
}

static void rsb_replace_all(char *buf, size_t n)
{
    const char *from = g_spec->mut_from;
    const char *to = g_spec->mut_to;
    size_t fn = strlen(from);
    size_t i = 0;
    if (fn == 0 || fn != strlen(to))
        return;
    while (i + fn <= n) {
        if (memcmp(buf + i, from, fn) == 0) {
            memcpy(buf + i, to, fn);
            i += fn;
        } else {
            i++;
        }
    }
}

static size_t rsb_line_hits(const char *buf, size_t n, const char *needle)
{
    size_t hits = 0;
    size_t i = 0;
    size_t needle_n = strlen(needle);
    int on_line = 0;
    while (i < n) {
        if (!on_line && i + needle_n <= n &&
            memcmp(buf + i, needle, needle_n) == 0)
            on_line = 1;
        if (buf[i] == '\n') {
            hits += (size_t)on_line;
            on_line = 0;
        }
        i++;
    }
    return hits + (size_t)on_line;
}

static int rsb_epoch_value(const char *data, const char *dend, long long *out)
{
    const char *v = rsb_field(data, dend, "epoch");
    if (v == NULL || rsb_is_lit(v, dend, "null", 4)) {
        *out = 0;
        return 0;
    }
    return rsb_u64_digits(v, dend, out);
}

static void rsb_event_value(const char *data, const char *dend, char *out,
                            size_t cap)
{
    const char *v = rsb_field(data, dend, "event");
    out[0] = 0;
    if (v == NULL || rsb_is_lit(v, dend, "null", 4))
        return;
    if (rsb_unquote(v, dend, out, cap) != 0)
        out[0] = 0;
}

static int rsb_take_story(const char *data, const char *dend,
                          struct rsb_story *story)
{
    if (rsb_copy_str(data, dend, "event", story->event, sizeof story->event) != 0)
        return -1;
    if (rsb_copy_i64(data, dend, "feedback_us", &story->feedback_us) != 0)
        return -1;
    if (rsb_copy_str(data, dend, "candidate_object_root", story->object_root,
                     sizeof story->object_root) != 0)
        return -1;
    if (rsb_copy_str(data, dend, "candidate_module_root", story->module_root,
                     sizeof story->module_root) != 0)
        return -1;
    if (rsb_copy_str(data, dend, "observation_root", story->observation,
                     sizeof story->observation) != 0)
        return -1;
    return 0;
}

static int rsb_hex64(const char *s)
{
    size_t i;
    if (strlen(s) != 64)
        return 0;
    for (i = 0; i < 64; i++) {
        char c = s[i];
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f'))
            return 0;
    }
    return 1;
}

static int rsb_hex_field(const char *obj, const char *end, const char *key)
{
    char got[RSB_HEX];
    if (rsb_copy_str(obj, end, key, got, sizeof got) != 0)
        return 0;
    return rsb_hex64(got);
}

static int rsb_streq(const char *obj, const char *end, const char *key,
                     const char *want)
{
    char got[160];
    if (rsb_copy_str(obj, end, key, got, sizeof got) != 0)
        return 0;
    return strcmp(got, want) == 0;
}

static int rsb_flags_a(const char *data, const char *end)
{
    if (!rsb_streq(data, end, "feedback_class", "HOT_FORK"))
        return 0;
    if (!rsb_streq(data, end, "story_fixture_id", g_spec->story_id))
        return 0;
    if (!rsb_streq(data, end, "story_adapter", g_spec->story_id))
        return 0;
    {
        long long timeout = 0;
        if (rsb_copy_i64(data, end, "story_timeout_ms", &timeout) != 0 ||
            timeout != 1000)
            return 0;
    }
    if (!rsb_streq(data, end, "forbidden_effect_mask",
                   "git|github|make|shell|sqlite|dht|network|publication|"
                   "full_link|full_suite"))
        return 0;
    return 1;
}

static int rsb_flags_b(const char *data, const char *end, struct rsb_story *story)
{
    char loaded[RSB_HEX];
    const char *executed = rsb_field(data, end, "candidate_bytes_executed");
    const char *published = rsb_field(data, end, "runtime_published");
    if (!rsb_is_lit(executed, end, "true", 4))
        return 0;
    if (!rsb_is_lit(published, end, "false", 5))
        return 0;
    if (story->feedback_us >= 1000000)
        return 0;
    if (!rsb_hex64(story->object_root) || !rsb_hex64(story->module_root) ||
        !rsb_hex64(story->observation))
        return 0;
    if (!rsb_hex_field(data, end, "story_root") ||
        !rsb_hex_field(data, end, "story_fixture_root"))
        return 0;
    if (rsb_copy_str(data, end, "loaded_mapping_root", loaded, sizeof loaded) != 0)
        return 0;
    return strcmp(loaded, story->module_root) == 0;
}

static int rsb_fail_bound(const char *expected)
{
    fprintf(stderr,
            "%s: candidate did not return bound %s: %s\n",
            g_spec->label, expected, g_cap);
    return 2;
}

static int rsb_accept(const char *expected, struct rsb_story *story)
{
    const char *end = g_cap + g_cap_n;
    const char *data;
    const char *dend;
    const char *ok = rsb_field(g_cap, end, "ok");
    data = rsb_data(g_cap, end, &dend);
    if (ok == NULL || !rsb_is_lit(ok, end, "true", 4) || data == NULL)
        return rsb_fail_bound(expected);
    if (rsb_take_story(data, dend, story) != 0 ||
        strcmp(story->event, expected) != 0)
        return rsb_fail_bound(expected);
    if (!rsb_flags_a(data, dend) || !rsb_flags_b(data, dend, story))
        return rsb_fail_bound(expected);
    return 0;
}

static int rsb_one_drive(struct rsb_job *job, const char *expected, int wait_edit,
                         int *br)
{
    char input[160];
    char arg[192];
    char *argv[5];
    char event[64];
    const char *data;
    const char *dend;
    long long next = 0;
    int nw;
    int rc;
    *br = 0;
    nw = snprintf(input, sizeof input,
                  "{\"after_epoch\":%lld,\"wait_for_edit\":%s,\"timeout_ms\":5000}",
                  job->epoch, wait_edit ? "true" : "false");
    if (nw < 0)
        return rsb_fail("drive input overflow");
    if ((size_t)nw >= sizeof input)
        return rsb_fail("drive input overflow");
    nw = snprintf(arg, sizeof arg, "--input=%s", input);
    if (nw < 0)
        return rsb_fail("drive input overflow");
    if ((size_t)nw >= sizeof arg)
        return rsb_fail("drive input overflow");
    argv[0] = job->bin;
    argv[1] = "dev";
    argv[2] = "drive";
    argv[3] = arg;
    argv[4] = NULL;
    rc = rsb_exec(argv, g_cap, sizeof g_cap, &g_cap_n);
    if (rc != 0)
        return rc;
    data = rsb_data(g_cap, g_cap + g_cap_n, &dend);
    if (data == NULL || rsb_epoch_value(data, dend, &next) != 0 ||
        next <= job->epoch)
        return rsb_fail2("event cursor did not advance: ", g_cap);
    job->epoch = next;
    rsb_event_value(data, dend, event, sizeof event);
    if (strcmp(event, expected) == 0 || strcmp(event, "STORY_RED") == 0 ||
        strcmp(event, "COMPILE_RED") == 0)
        *br = 1;
    return 0;
}

static int rsb_drive(struct rsb_job *job, const char *body, size_t n,
                     const char *expected, struct rsb_story *story)
{
    int wait_edit = 1;
    int loops;
    int rc = rsb_install(job, body, n);
    if (rc != 0)
        return rc;
    for (loops = 0; loops < 16; loops++) {
        int br = 0;
        rc = rsb_one_drive(job, expected, wait_edit, &br);
        if (rc != 0)
            return rc;
        if (br)
            break;
        wait_edit = 0;
    }
    return rsb_accept(expected, story);
}

static int rsb_phase_stamp(struct rsb_job *job, struct rsb_story *story,
                           long long *saved)
{
    size_t n = 0;
    int rc;
    if (rsb_slurp(job->backup, g_file, sizeof g_file, &n, NULL) != 0)
        return rsb_fail("cannot read the owner source");
    if (rsb_stamp(g_file, &n, sizeof g_file, job->nonce) != 0)
        return rsb_fail("cannot stamp the candidate");
    rc = rsb_drive(job, g_file, n, "STORY_GREEN", story);
    if (rc != 0)
        return rc;
    *saved = job->epoch;
    return 0;
}

static int rsb_phase_red(struct rsb_job *job)
{
    size_t n = 0;
    int rc;
    if (rsb_slurp(job->source, g_file, sizeof g_file, &n, NULL) != 0)
        return rsb_fail("cannot read the staged source");
    rsb_replace_all(g_file, n);
    {
        size_t hits = rsb_line_hits(g_file, n, g_spec->mut_to);
        if ((g_spec->mut_exact && hits != 1) || (!g_spec->mut_exact && hits < 1))
            return rsb_fail("compile-valid semantic mutation was not staged");
    }
    rc = rsb_drive(job, g_file, n, "STORY_RED", &job->red);
    return rc;
}

static int rsb_wait_raw(struct rsb_job *job, long long epoch)
{
    char input[96];
    char arg[128];
    char *argv[6];
    int nw = snprintf(input, sizeof input,
                      "{\"after_epoch\":%lld,\"timeout_ms\":100}", epoch - 1);
    if (nw < 0)
        return rsb_fail("wait input overflow");
    if ((size_t)nw >= sizeof input)
        return rsb_fail("wait input overflow");
    nw = snprintf(arg, sizeof arg, "--input=%s", input);
    if (nw < 0)
        return rsb_fail("wait input overflow");
    if ((size_t)nw >= sizeof arg)
        return rsb_fail("wait input overflow");
    argv[0] = job->bin;
    argv[1] = "dev";
    argv[2] = "loop";
    argv[3] = "wait";
    argv[4] = arg;
    argv[5] = NULL;
    return rsb_exec(argv, g_cap, sizeof g_cap, &g_cap_n);
}

static int rsb_procs_zero(const char *rec, const char *rend, struct rsb_wait *out)
{
    const char *hit = rsb_field(rec, rend, "artifact_cache_hit");
    if (!rsb_is_lit(hit, rend, "true", 4))
        return 0;
    if (rsb_copy_i64(rec, rend, "compiler_processes", &out->compilers) != 0)
        return 0;
    if (out->compilers != 0)
        return 0;
    if (rsb_copy_i64(rec, rend, "linker_processes", &out->linkers) != 0)
        return 0;
    return out->linkers == 0;
}

static int rsb_cache_match(const char *data, const char *dend,
                           const struct rsb_story *green)
{
    char object[RSB_HEX];
    char module[RSB_HEX];
    if (rsb_copy_str(data, dend, "candidate_object_root", object,
                     sizeof object) != 0)
        return 0;
    if (rsb_copy_str(data, dend, "candidate_module_root", module,
                     sizeof module) != 0)
        return 0;
    if (strcmp(object, green->object_root) != 0)
        return 0;
    return strcmp(module, green->module_root) == 0;
}

static int rsb_cache_ok(const struct rsb_story *green, struct rsb_wait *out)
{
    const char *end = g_cap + g_cap_n;
    const char *data;
    const char *dend;
    const char *rec;
    const char *rend;
    const char *ok = rsb_field(g_cap, end, "ok");
    char phase[32];
    if (ok == NULL || !rsb_is_lit(ok, end, "true", 4))
        return 0;
    data = rsb_data(g_cap, end, &dend);
    if (data == NULL)
        return 0;
    if (rsb_copy_str(data, dend, "phase", phase, sizeof phase) != 0 ||
        strcmp(phase, "STORY_GREEN") != 0)
        return 0;
    rec = rsb_field(data, dend, "build_receipt");
    if (rec == NULL || *rec != '{')
        return 0;
    rend = rsb_skip_box(rec, dend);
    if (rend == NULL || !rsb_procs_zero(rec, rend, out))
        return 0;
    return rsb_cache_match(data, dend, green);
}

static int rsb_phase_cache(struct rsb_job *job)
{
    int rc = rsb_wait_raw(job, job->green_epoch);
    if (rc != 0)
        return rc;
    rc = rsb_wait_raw(job, job->revert_epoch);
    if (rc != 0)
        return rc;
    if (!rsb_cache_ok(&job->green, &job->cached))
        return rsb_fail("exact revert did not reuse the exact verified capsule cache");
    return 0;
}

static int rsb_mkdir_p(char *dir)
{
    size_t i;
    if (dir[0] == '\0')
        return 0;
    for (i = 1; dir[i] != '\0'; i++) {
        if (dir[i] != '/')
            continue;
        dir[i] = 0;
        if (mkdir(dir, 0755) != 0 && errno != EEXIST)
            return -1;
        dir[i] = '/';
    }
    if (mkdir(dir, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int rsb_mkdir_parent(const char *file)
{
    char dir[PATH_MAX];
    char *slash;
    if (rsb_put(dir, sizeof dir, file) != 0)
        return -1;
    slash = strrchr(dir, '/');
    if (slash == NULL || slash == dir)
        return 0;
    *slash = 0;
    return rsb_mkdir_p(dir);
}

static const char *rsb_json_bool(int v)
{
    return v ? "true" : "false";
}

static int rsb_receipt(const struct rsb_job *job)
{
    FILE *fp;
    int same_object =
        strcmp(job->green.object_root, job->revert.object_root) == 0;
    int same_module =
        strcmp(job->green.module_root, job->revert.module_root) == 0;
    int wrote;
    if (rsb_mkdir_parent(job->output) != 0)
        return rsb_fail("cannot create receipt directory");
    fp = fopen(job->output, "w");
    if (fp == NULL)
        return rsb_fail("cannot write receipt");
    wrote = fprintf(
        fp,
        "{\n"
        "  \"schema\": \"zcl.reflex_owner_acceptance.v1\",\n"
        "  \"owner\": \"%s\",\n"
        "  \"green\": {\n"
        "    \"event\": \"%s\",\n"
        "    \"feedback_us\": %lld,\n"
        "    \"candidate_object_root\": \"%s\",\n"
        "    \"candidate_module_root\": \"%s\",\n"
        "    \"observation_root\": \"%s\"\n"
        "  },\n"
        "  \"born_red\": {\n"
        "    \"event\": \"%s\",\n"
        "    \"feedback_us\": %lld,\n"
        "    \"compile_valid\": true,\n"
        "    \"candidate_bytes_executed\": true,\n"
        "    \"observation_root\": \"%s\"\n"
        "  },\n"
        "  \"exact_revert\": {\n"
        "    \"event\": \"%s\",\n"
        "    \"feedback_us\": %lld,\n"
        "    \"artifact_cache_hit\": true,\n"
        "    \"compiler_processes\": %lld,\n"
        "    \"linker_processes\": %lld,\n"
        "    \"same_object\": %s,\n"
        "    \"same_module\": %s\n"
        "  },\n"
        "  \"runtime_published\": false\n"
        "}\n",
        g_spec->owner, job->green.event, job->green.feedback_us,
        job->green.object_root,
        job->green.module_root, job->green.observation, job->red.event,
        job->red.feedback_us, job->red.observation, job->revert.event,
        job->revert.feedback_us, job->cached.compilers, job->cached.linkers,
        rsb_json_bool(same_object), rsb_json_bool(same_module));
    if (wrote < 0 || fclose(fp) != 0)
        return rsb_fail("cannot write receipt");
    return 0;
}

static int rsb_stop(struct rsb_job *job)
{
    char input[512];
    char arg[560];
    char *argv[6];
    int nw;
    if (!job->have_watcher)
        return 0;
    nw = snprintf(input, sizeof input,
                  "{\"watcher_id\":%lld,\"watcher_session\":\"%s\"}",
                  job->watcher_id, job->session);
    if (nw < 0)
        return rsb_fail("stop input overflow");
    if ((size_t)nw >= sizeof input)
        return rsb_fail("stop input overflow");
    nw = snprintf(arg, sizeof arg, "--input=%s", input);
    if (nw < 0)
        return rsb_fail("stop input overflow");
    if ((size_t)nw >= sizeof arg)
        return rsb_fail("stop input overflow");
    argv[0] = job->bin;
    argv[1] = "dev";
    argv[2] = "loop";
    argv[3] = "stop";
    argv[4] = arg;
    argv[5] = NULL;
    {
        int rc = rsb_exec_quiet(argv);
        if (rc == 0)
            g_stop_ready = 0;
        return rc;
    }
}

static void rsb_cleanup(struct rsb_job *job)
{
    sigset_t blocked;
    sigset_t old;
    if (job->have_watcher)
        (void)rsb_stop(job);
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGTERM);
    sigprocmask(SIG_BLOCK, &blocked, &old);
    if (job->armed)
        rsb_restore_fd();
    g_armed = 0;
    job->armed = 0;
    sigprocmask(SIG_SETMASK, &old, NULL);
    if (job->backup[0] != '\0')
        unlink(job->backup);
    job->backup[0] = 0;
    job->have_watcher = 0;
}

static int rsb_run(const struct rsb_spec *spec)
{
    struct rsb_job job;
    int rc;
    g_spec = spec;
    memset(&job, 0, sizeof job);
    g_armed = 0;
    g_stop_ready = 0;
    rc = rsb_prepare(&job);
    if (rc == 0)
        rc = rsb_begin(&job);
    if (rc == 0)
        rc = rsb_nonce(&job);
    if (rc == 0)
        rc = rsb_phase_stamp(&job, &job.green, &job.green_epoch);
    if (rc == 0)
        rc = rsb_phase_red(&job);
    if (rc == 0)
        rc = rsb_phase_stamp(&job, &job.revert, &job.revert_epoch);
    if (rc == 0)
        rc = rsb_phase_cache(&job);
    if (rc == 0)
        rc = rsb_receipt(&job);
    if (rc == 0) {
        rc = rsb_stop(&job);
        if (rc == 0)
            job.have_watcher = 0;
    }
    rsb_cleanup(&job);
    rsb_disarm_signals();
    if (rc == 0)
        printf("%s: PASS receipt=%s\n", spec->label, job.output);
    g_spec = &k_source_spec;
    return rc;
}

#endif

int zcl_reflex_hotfork_source_bundle(void)
{
#if defined(_WIN32)
    fputs("reflex-hotfork-source-bundle-acceptance: unavailable on Windows\n",
          stdout);
    return 2;
#else
    return rsb_run(&k_source_spec);
#endif
}

int zcl_reflex_hotfork_transport(void)
{
#if defined(_WIN32)
    fputs("reflex-hotfork-transport-acceptance: unavailable on Windows\n",
          stdout);
    return 2;
#else
    return rsb_run(&k_transport_spec);
#endif
}
