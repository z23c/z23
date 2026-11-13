/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Atomic alias publication for one compile-epoch candidate.
 *          Cross-process publishers take the alias flock, ask the session
 *          tool to check, copy the candidate, ask it to verify, then rename. */

#ifndef _WIN32
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#endif

#include "publish_build_alias.h"

#include "build_epoch_lock_wait.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void pba_write_all(int fd, const char *text, size_t n)
{
    if (fd < 0)
        fd = STDERR_FILENO;
    while (n > 0) {
        ssize_t w = write(fd, text, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return;
        }
        text += w;
        n -= (size_t)w;
    }
}

static void pba_msg(int fd, const char *text)
{
    char buf[1024];
    int n = snprintf(buf, sizeof buf, "publish-build-alias: %s\n",
                     text ? text : "");
    if (n > 0)
        pba_write_all(fd, buf, (size_t)n);
}

#if !defined(_WIN32)

static int pba_hex64(const char *text)
{
    size_t i;
    if (!text)
        return 0;
    for (i = 0; i < 64; i++) {
        char c = text[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return 0;
    }
    return text[64] == '\0';
}

static int pba_exec_file(const char *path)
{
    struct stat st;
    if (!path || stat(path, &st) != 0)
        return 0;
    return S_ISREG(st.st_mode) && access(path, X_OK) == 0;
}

static int pba_in_epoch(const char *candidate, const char *epoch)
{
    char wrapped[PATH_MAX];
    char marker[80];
    int nw;
    int nm = snprintf(marker, sizeof marker, "/epochs/%s/", epoch);
    if (nm < 0 || nm >= (int)sizeof marker)
        return 0;
    nw = snprintf(wrapped, sizeof wrapped, "/%s/", candidate);
    if (nw < 0 || nw >= (int)sizeof wrapped)
        return 0;
    return strstr(wrapped, marker) != NULL;
}

static int pba_field(const struct zcl_publish_alias *req, const char *text,
                     const char *what)
{
    char buf[128];
    if (pba_hex64(text))
        return 0;
    (void)snprintf(buf, sizeof buf, "%s is not lowercase SHA-256", what);
    pba_msg(req->err_fd, buf);
    return -1;
}

static int pba_usage(const struct zcl_publish_alias *req)
{
    pba_msg(req ? req->err_fd : -1,
            "usage: publish-build-alias CANDIDATE ALIAS SESSION SOURCE "
            "COMPLETE MUTATION EPOCH COMPILER_ID PROFILE COMPILE_FLAGS "
            "LINK_FLAGS CC CXX [VERIFY_TOOL]");
    return -1;
}

static int pba_have_args(const struct zcl_publish_alias *req)
{
    if (!req || !req->candidate || !req->alias || !req->session)
        return pba_usage(req);
    if (!req->profile || !req->compile_flags || !req->link_flags)
        return pba_usage(req);
    if (!req->cc || !req->cxx || !req->session_tool)
        return pba_usage(req);
    return 0;
}

static int pba_ids(const struct zcl_publish_alias *req)
{
    if (pba_field(req, req->source_id, "source id") != 0)
        return -1;
    if (!req->complete || strcmp(req->complete, "1") != 0) {
        pba_msg(req->err_fd, "source capture is incomplete");
        return -1;
    }
    if (pba_field(req, req->mutation, "mutation token") != 0)
        return -1;
    if (pba_field(req, req->epoch, "compile epoch") != 0)
        return -1;
    if (pba_field(req, req->compiler_id, "compiler id") != 0)
        return -1;
    return 0;
}

static int pba_refuse_exec(const struct zcl_publish_alias *req, const char *path,
                           const char *what)
{
    char buf[PATH_MAX + 64];
    if (pba_exec_file(path))
        return 0;
    (void)snprintf(buf, sizeof buf, "%s is not executable: %s", what, path);
    pba_msg(req->err_fd, buf);
    return -1;
}

static int pba_validate(const struct zcl_publish_alias *req)
{
    const char *verify;
    if (pba_have_args(req) != 0 || pba_ids(req) != 0)
        return -1;
    verify = req->verify_tool ? req->verify_tool
                              : "tools/dev/source-identity.sh";
    if (pba_refuse_exec(req, verify, "source verifier") != 0)
        return -1;
    if (pba_refuse_exec(req, req->session_tool, "epoch verifier") != 0)
        return -1;
    if (!pba_exec_file(req->candidate)) {
        char buf[PATH_MAX + 64];
        (void)snprintf(buf, sizeof buf,
                       "candidate is not a regular executable: %s",
                       req->candidate);
        pba_msg(req->err_fd, buf);
        return -1;
    }
    if (!pba_in_epoch(req->candidate, req->epoch)) {
        char buf[160];
        (void)snprintf(buf, sizeof buf,
                       "candidate path is outside compile epoch %s",
                       req->epoch);
        pba_msg(req->err_fd, buf);
        return -1;
    }
    return 0;
}

static int pba_object_root(const char *session, const char *epoch,
                           char *root, size_t cap)
{
    char marker[80];
    const char *hit;
    size_t n;
    int nm = snprintf(marker, sizeof marker, "/epochs/%s/", epoch);
    if (nm < 0 || nm >= (int)sizeof marker)
        return -1;
    hit = strstr(session, marker);
    if (!hit || hit == session)
        return -1;
    n = (size_t)(hit - session);
    if (n + 1 > cap)
        return -1;
    memcpy(root, session, n);
    root[n] = '\0';
    return 0;
}

static int pba_mkdir_p(const char *path)
{
    char buf[PATH_MAX];
    size_t n;
    size_t i;
    if (!path || !path[0] || strlen(path) >= sizeof buf)
        return -1;
    n = strlen(path);
    memcpy(buf, path, n + 1);
    for (i = 1; i < n; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (buf[0] && mkdir(buf, 0755) != 0 && errno != EEXIST)
            return -1;
        buf[i] = '/';
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int pba_lock(const struct zcl_publish_alias *req)
{
    char lock_path[PATH_MAX];
    char dir[PATH_MAX];
    char note[PATH_MAX + 64];
    const char *slash;
    int fd;
    int nw = snprintf(lock_path, sizeof lock_path, "%s.lock", req->alias);
    if (nw < 0 || nw >= (int)sizeof lock_path)
        return -1;
    slash = strrchr(req->alias, '/');
    if (!slash) {
        memcpy(dir, ".", 2);
    } else if ((size_t)(slash - req->alias) >= sizeof dir) {
        return -1;
    } else {
        size_t n = (size_t)(slash - req->alias);
        memcpy(dir, req->alias, n);
        dir[n] = '\0';
        if (n == 0)
            memcpy(dir, "/", 2);
    }
    if (pba_mkdir_p(dir) != 0)
        return -1;
    fd = open(lock_path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    if (zcl_build_epoch_flock_bounded("publish-build-alias", fd, lock_path,
                                     "alias", req->err_fd) != 0) {
        (void)snprintf(note, sizeof note, "could not acquire alias lock %s",
                       lock_path);
        pba_msg(req->err_fd, note);
        (void)close(fd);
        return -1;
    }
    return fd;
}

static void pba_sha256_child(const char *path, int pipefd[2])
{
    int in = open(path, O_RDONLY);
    if (in < 0 || dup2(in, STDIN_FILENO) < 0 ||
        dup2(pipefd[1], STDOUT_FILENO) < 0)
        _exit(127);
    (void)close(pipefd[0]);
    (void)close(pipefd[1]);
    if (in != STDIN_FILENO)
        (void)close(in);
    execlp("sha256sum", "sha256sum", (char *)NULL);
    _exit(127);
}

static int pba_read_digest(int fd, char hex[65])
{
    char raw[80];
    size_t got = 0;
    while (got + 1 < sizeof raw) {
        ssize_t n = read(fd, raw + got, sizeof raw - 1 - got);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            break;
        got += (size_t)n;
    }
    if (got < 64)
        return -1;
    memcpy(hex, raw, 64);
    hex[64] = '\0';
    return pba_hex64(hex) ? 0 : -1;
}

static int pba_wait_ok(pid_t pid)
{
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;
    return 0;
}

static int pba_sha256_file(const char *path, char hex[65])
{
    int pipefd[2];
    pid_t pid;
    int rc;
    if (pipe(pipefd) != 0)
        return -1;
    pid = fork();
    if (pid < 0) {
        (void)close(pipefd[0]);
        (void)close(pipefd[1]);
        return -1;
    }
    if (pid == 0)
        pba_sha256_child(path, pipefd);
    (void)close(pipefd[1]);
    rc = pba_read_digest(pipefd[0], hex);
    (void)close(pipefd[0]);
    if (pba_wait_ok(pid) != 0)
        return -1;
    return rc;
}

static int pba_copy(const char *src, const char *dst)
{
    int in = open(src, O_RDONLY);
    int out;
    struct stat st;
    char buf[65536];
    if (in < 0 || fstat(in, &st) != 0)
        return -1;
    out = open(dst, O_WRONLY | O_TRUNC);
    if (out < 0) {
        (void)close(in);
        return -1;
    }
    for (;;) {
        ssize_t n = read(in, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            (void)close(in);
            (void)close(out);
            return -1;
        }
        if (n == 0)
            break;
        {
            size_t left = (size_t)n;
            char *p = buf;
            while (left > 0) {
                ssize_t w = write(out, p, left);
                if (w < 0) {
                    if (errno == EINTR)
                        continue;
                    (void)close(in);
                    (void)close(out);
                    return -1;
                }
                p += w;
                left -= (size_t)w;
            }
        }
    }
    if (fchmod(out, st.st_mode & 07777) != 0) {
        (void)close(in);
        (void)close(out);
        return -1;
    }
    (void)close(in);
    return close(out) == 0 ? 0 : -1;
}

static int pba_stage(const struct zcl_publish_alias *req, char *tmp,
                     size_t tmp_cap, char hex[65])
{
    char dir[PATH_MAX];
    char base[256];
    char src_hex[65];
    const char *slash = strrchr(req->alias, '/');
    const char *name = slash ? slash + 1 : req->alias;
    int fd;
    if (strlen(name) >= sizeof base)
        return -1;
    memcpy(base, name, strlen(name) + 1);
    if (!slash) {
        memcpy(dir, ".", 2);
    } else {
        size_t n = (size_t)(slash - req->alias);
        if (n >= sizeof dir)
            return -1;
        memcpy(dir, req->alias, n);
        dir[n] = '\0';
        if (n == 0)
            memcpy(dir, "/", 2);
    }
    if (snprintf(tmp, tmp_cap, "%s/.build-alias.%s.XXXXXX", dir, base) >=
        (int)tmp_cap) {
        pba_msg(req->err_fd, "could not create alias publication temporary");
        return -1;
    }
    fd = mkstemp(tmp);
    if (fd < 0) {
        pba_msg(req->err_fd, "could not create alias publication temporary");
        return -1;
    }
    (void)close(fd);
    if (pba_copy(req->candidate, tmp) != 0 ||
        pba_sha256_file(req->candidate, src_hex) != 0 ||
        pba_sha256_file(tmp, hex) != 0) {
        (void)unlink(tmp);
        if (pba_sha256_file(req->candidate, src_hex) != 0)
            pba_msg(req->err_fd, "sha256sum is required for alias publication");
        else
            pba_msg(req->err_fd, "could not create alias publication temporary");
        return -1;
    }
    if (strcmp(src_hex, hex) != 0) {
        (void)unlink(tmp);
        pba_msg(req->err_fd, "candidate changed while it was copied");
        return -1;
    }
    return 0;
}

static int pba_session(const struct zcl_publish_alias *req, const char *mode,
                       const char *root)
{
    char lease[PATH_MAX];
    char pid_text[32];
    const char *verify = req->verify_tool ? req->verify_tool
                                          : "tools/dev/source-identity.sh";
    pid_t pid;
    int status = 0;
    int nw = snprintf(lease, sizeof lease,
                      "%s/epochs/%s/.leases/publisher-check", root, req->epoch);
    if (nw < 0 || nw >= (int)sizeof lease)
        return 2;
    (void)snprintf(pid_text, sizeof pid_text, "%ld", (long)getpid());
    pid = fork();
    if (pid < 0)
        return 2;
    if (pid == 0) {
        int sink = open("/dev/null", O_WRONLY);
        const char *argv[] = {
            req->session_tool, mode, req->session, lease, root, "-", "1",
            req->source_id, req->complete, req->mutation, req->compiler_id,
            req->epoch, req->profile, req->compile_flags, req->link_flags,
            req->cc, req->cxx, pid_text, verify, NULL};
        if (sink >= 0) {
            (void)dup2(sink, STDOUT_FILENO);
            (void)close(sink);
        }
        execv(req->session_tool, (char *const *)argv);
        _exit(127);
    }
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR)
            return 2;
    }
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 2;
}

static void pba_announce(const struct zcl_publish_alias *req, const char *hex)
{
    char line[PATH_MAX * 2 + 128];
    int n = snprintf(line, sizeof line,
                     "publish-build-alias: %s <= epoch %s sha256=%s\n",
                     req->alias, req->epoch, hex);
    if (n > 0)
        pba_write_all(STDOUT_FILENO, line, (size_t)n);
}

#endif /* !_WIN32 */

int zcl_publish_build_alias(const struct zcl_publish_alias *req)
{
#if defined(_WIN32)
    (void)req;
    pba_msg(req ? req->err_fd : -1,
            "Windows alias publication is unavailable");
    return 2;
#else
    char root[PATH_MAX];
    char tmp_path[PATH_MAX];
    char hex[65];
    int lock_fd;
    int rc;
    if (pba_validate(req) != 0)
        return 2;
    if (pba_object_root(req->session, req->epoch, root, sizeof root) != 0) {
        pba_msg(req->err_fd, "could not derive object root from session path");
        return 2;
    }
    lock_fd = pba_lock(req);
    if (lock_fd < 0)
        return 2;
    rc = pba_session(req, "check", root);
    if (rc != 0) {
        (void)close(lock_fd);
        return rc;
    }
    if (pba_stage(req, tmp_path, sizeof tmp_path, hex) != 0) {
        (void)close(lock_fd);
        return 2;
    }
    /* Source authority is rechecked immediately before the rename. */
    rc = pba_session(req, "verify", root);
    if (rc != 0) {
        (void)unlink(tmp_path);
        (void)close(lock_fd);
        return rc;
    }
    if (rename(tmp_path, req->alias) != 0) {
        (void)unlink(tmp_path);
        pba_msg(req->err_fd, "could not publish alias");
        (void)close(lock_fd);
        return 2;
    }
    pba_announce(req, hex);
    (void)close(lock_fd);
    return 0;
#endif
}
