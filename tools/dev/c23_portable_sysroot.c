/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Prepare the pinned Debian glibc 2.31 sysroot and prove the
 *          portable compiler wrapper stays on the x86-64 baseline. */

#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif

#include "c23_portable_sysroot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(_WIN32)

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#define CPS_PATH 4096
#define CPS_PKG_N 3

struct cps_pkg {
    const char *name;
    const char *sha;
    const char *url;
};

static const struct cps_pkg k_pkg[CPS_PKG_N] = {
    {"libc6_2.31-13+deb11u14_amd64.deb",
     "718e3ed8c92207caf5b541e7332affad4f62501cbab3f0cffbe9e6db0b89eae9",
     "https://snapshot.debian.org/archive/debian-security/20260608T043349Z/pool/updates/main/g/glibc/libc6_2.31-13%2Bdeb11u14_amd64.deb"},
    {"libc6-dev_2.31-13+deb11u14_amd64.deb",
     "7d4002192e09c3cc97f31dcc85ecd7741adbec9011abbdd14fb1790cab20bffa",
     "https://snapshot.debian.org/archive/debian-security/20260608T043349Z/pool/updates/main/g/glibc/libc6-dev_2.31-13%2Bdeb11u14_amd64.deb"},
    {"linux-libc-dev_6.1.176-1_amd64.deb",
     "8bb258735b9dffbb111da778ebdd024750878e435ffd9dfcadcb6762ede6b4cf",
     "https://deb.debian.org/debian/pool/main/l/linux/linux-libc-dev_6.1.176-1_amd64.deb"},
};

static const char k_layout[] = "absolute-glibc-links-v2";
static const char k_tail[] = "/build/toolchains/debian-bullseye-glibc-2.31-amd64";
static const char k_loader_rel[] = "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2";
static const char k_abs_lib[] = "/lib/x86_64-linux-gnu/";

struct cps_paths {
    char toolchain[CPS_PATH];
    char downloads[CPS_PATH];
    char sysroot[CPS_PATH];
    char wrapper[CPS_PATH];
    char stamp[CPS_PATH];
};

static int cps_join(char *out, size_t cap, const char *a, const char *b)
{
    size_t na = strlen(a);
    size_t nb = strlen(b);
    if (na + nb + 1 > cap)
        return -1;
    memcpy(out, a, na);
    memcpy(out + na, b, nb + 1);
    return 0;
}

static int cps_under(char *out, size_t cap, const char *dir, const char *leaf)
{
    size_t nd = strlen(dir);
    size_t nl = strlen(leaf);
    if (nd + 1 + nl + 1 > cap)
        return -1;
    memcpy(out, dir, nd);
    out[nd] = '/';
    memcpy(out + nd + 1, leaf, nl + 1);
    return 0;
}

static int cps_append(char *buf, size_t cap, size_t *used, const char *text)
{
    size_t n = strlen(text);
    if (*used + n + 1 > cap)
        return -1;
    memcpy(buf + *used, text, n + 1);
    *used += n;
    return 0;
}

static int cps_meta(unsigned char c, int at_start)
{
    static const char k_meta[] = " !\"$&'()*,;<>?[\\]^`{|}";
    if (memchr(k_meta, c, sizeof k_meta - 1) != NULL)
        return 1;
    if (at_start && (c == '#' || c == '~'))
        return 1;
    return 0;
}

static int cps_needs_ansic(const unsigned char *s)
{
    size_t i;
    for (i = 0; s[i] != '\0'; i++) {
        if (s[i] < 32 || s[i] == 127)
            return 1;
    }
    return 0;
}

static const char *cps_named_esc(unsigned char c)
{
    switch (c) {
    case '\a':
        return "\\a";
    case 8:
        return "\\" "b";
    case '\t':
        return "\\t";
    case '\n':
        return "\\n";
    case '\v':
        return "\\v";
    case '\f':
        return "\\f";
    case '\r':
        return "\\r";
    case 0x1b:
        return "\\E";
    default:
        return NULL;
    }
}

static int cps_which(const char *name, char *out, size_t cap)
{
    const char *path;
    size_t name_n;
    if (name == NULL || name[0] == '\0')
        return -1;
    if (strchr(name, '/') != NULL) {
        if (access(name, X_OK) != 0)
            return -1;
        return cps_join(out, cap, name, "") == 0 ? 0 : -1;
    }
    path = getenv("PATH");
    if (path == NULL)
        return -1;
    name_n = strlen(name);
    while (*path != '\0') {
        const char *end = strchr(path, ':');
        size_t n = end == NULL ? strlen(path) : (size_t)(end - path);
        const char *dir = path;
        size_t dn = n;
        if (n == 0) {
            dir = ".";
            dn = 1;
        }
        if (dn + 1 + name_n + 1 <= cap) {
            memcpy(out, dir, dn);
            out[dn] = '/';
            memcpy(out + dn + 1, name, name_n + 1);
            if (access(out, X_OK) == 0)
                return 0;
        }
        if (end == NULL)
            break;
        path = end + 1;
    }
    return -1;
}

static int cps_reap(pid_t child)
{
    for (;;) {
        int status = 0;
        pid_t got = waitpid(child, &status, 0);
        if (got == child) {
            if (WIFEXITED(status))
                return WEXITSTATUS(status);
            if (WIFSIGNALED(status))
                return 128 + WTERMSIG(status);
            return 125;
        }
        if (errno != EINTR)
            return 125;
    }
}

static void cps_drop(int fd)
{
    if (fd > STDERR_FILENO)
        close(fd);
}

static void cps_child_exec(char *const argv[], int in_r, int out_w, int null_out,
                           int drop_a, int drop_b)
{
    if (in_r >= 0 && dup2(in_r, STDIN_FILENO) < 0)
        _exit(127);
    if (null_out) {
        int sink = open("/dev/null", O_WRONLY);
        if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0)
            _exit(127);
        cps_drop(sink);
    } else if (out_w >= 0 && dup2(out_w, STDOUT_FILENO) < 0) {
        _exit(127);
    }
    cps_drop(in_r);
    cps_drop(out_w);
    cps_drop(drop_a);
    cps_drop(drop_b);
    execvp(argv[0], argv);
    _exit(127);
}

static int cps_fork_exec(char *const argv[], int in_r, int out_w, int null_out,
                         int drop_a, int drop_b, pid_t *child_out)
{
    pid_t child = fork();
    if (child < 0)
        return -1;
    if (child == 0)
        cps_child_exec(argv, in_r, out_w, null_out, drop_a, drop_b);
    *child_out = child;
    return 0;
}

static int cps_slurp(int fd, char *out, size_t cap)
{
    size_t used = 0;
    if (out == NULL || cap < 2)
        return -1;
    for (;;) {
        ssize_t n;
        if (used + 1 >= cap)
            return -1;
        n = read(fd, out + used, cap - 1 - used);
        if (n == 0)
            break;
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return -1;
        used += (size_t)n;
    }
    while (used > 0 && (out[used - 1] == '\n' || out[used - 1] == '\r'))
        used--;
    out[used] = '\0';
    return 0;
}

static int cps_write_all(int fd, const char *text)
{
    const char *p = text;
    size_t left = strlen(text);
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0)
            return -1;
        p += n;
        left -= (size_t)n;
    }
    return 0;
}

static int cps_status(char *const argv[], int null_out)
{
    pid_t child;
    if (cps_fork_exec(argv, -1, -1, null_out, -1, -1, &child) != 0)
        return 127;
    return cps_reap(child);
}

static int cps_capture(char *const argv[], char *out, size_t cap)
{
    int fds[2];
    pid_t child;
    int slurp;
    int rc;
    if (pipe(fds) != 0)
        return 127;
    if (cps_fork_exec(argv, -1, fds[1], 0, fds[0], -1, &child) != 0) {
        close(fds[0]);
        close(fds[1]);
        return 127;
    }
    close(fds[1]);
    slurp = cps_slurp(fds[0], out, cap);
    close(fds[0]);
    rc = cps_reap(child);
    if (rc == 0 && slurp != 0)
        return 127;
    return rc;
}

static int cps_feed(char *const argv[], const char *text, char *out, size_t cap, int null_out)
{
    int in[2];
    int outp[2] = {-1, -1};
    pid_t child;
    int slurp = 0;
    int rc;
    int want = out != NULL && !null_out;
    if (pipe(in) != 0)
        return 127;
    if (want && pipe(outp) != 0) {
        close(in[0]);
        close(in[1]);
        return 127;
    }
    if (cps_fork_exec(argv, in[0], want ? outp[1] : -1, null_out, in[1],
                      want ? outp[0] : -1, &child) != 0) {
        close(in[0]);
        close(in[1]);
        if (want) {
            close(outp[0]);
            close(outp[1]);
        }
        return 127;
    }
    close(in[0]);
    if (want)
        close(outp[1]);
    if (cps_write_all(in[1], text) != 0) {
        close(in[1]);
        if (want)
            close(outp[0]);
        cps_reap(child);
        return 127;
    }
    close(in[1]);
    if (want) {
        slurp = cps_slurp(outp[0], out, cap);
        close(outp[0]);
    }
    rc = cps_reap(child);
    if (rc == 0 && slurp != 0)
        return 127;
    return rc;
}

static int cps_need(const char *name)
{
    char found[CPS_PATH];
    if (cps_which(name, found, sizeof found) == 0)
        return 0;
    fprintf(stderr, "c23-portable-sysroot: required tool not found: %s\n", name);
    return 1;
}

static int cps_need_all(void)
{
    static const char *k_tools[] = {
        "ar", "tar", "xz", "sha256sum", "mktemp", "objdump", NULL};
    int i;
    for (i = 0; k_tools[i] != NULL; i++) {
        if (cps_need(k_tools[i]) != 0)
            return 1;
    }
    return 0;
}

static int cps_arch(void)
{
    struct utsname u;
    if (uname(&u) != 0 || strcmp(u.machine, "x86_64") != 0) {
        fprintf(stderr,
                "c23-portable-sysroot: the pinned release sysroot currently supports x86_64 only\n");
        return 1;
    }
    return 0;
}

static int cps_mkdir_p(const char *path)
{
    char buf[CPS_PATH];
    size_t n;
    size_t i;
    if (path == NULL || path[0] == '\0')
        return -1;
    n = strlen(path);
    if (n + 1 > sizeof buf)
        return -1;
    memcpy(buf, path, n + 1);
    for (i = 1; i < n; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, 0755) != 0 && errno != EEXIST)
            return -1;
        buf[i] = '/';
    }
    if (mkdir(buf, 0755) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

static int cps_both_regular(const char *stdio_path, const char *crt_path)
{
    struct stat stdio_st;
    struct stat crt_st;
    if (stat(stdio_path, &stdio_st) != 0)
        return 0;
    if (stat(crt_path, &crt_st) != 0)
        return 0;
    if (!S_ISREG(stdio_st.st_mode))
        return 0;
    if (!S_ISREG(crt_st.st_mode))
        return 0;
    return 1;
}

static int cps_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

static int cps_first_field(const char *text, char *out, size_t cap)
{
    size_t i = 0;
    if (text == NULL)
        return -1;
    while (text[i] != '\0' && text[i] != ' ' && text[i] != '\t' && text[i] != '\n')
        i++;
    if (i == 0 || i + 1 > cap)
        return -1;
    memcpy(out, text, i);
    out[i] = '\0';
    return 0;
}

static int cps_digest_text(char *buf, size_t cap)
{
    size_t used = 0;
    int i;
    buf[0] = '\0';
    if (cps_append(buf, cap, &used, k_layout) != 0 || cps_append(buf, cap, &used, "\n") != 0)
        return -1;
    for (i = 0; i < CPS_PKG_N; i++) {
        if (cps_append(buf, cap, &used, k_pkg[i].name) != 0)
            return -1;
        if (cps_append(buf, cap, &used, "|") != 0)
            return -1;
        if (cps_append(buf, cap, &used, k_pkg[i].sha) != 0)
            return -1;
        if (cps_append(buf, cap, &used, "|") != 0)
            return -1;
        if (cps_append(buf, cap, &used, k_pkg[i].url) != 0)
            return -1;
        if (cps_append(buf, cap, &used, "\n") != 0)
            return -1;
    }
    return 0;
}

static int cps_digest(char *out, size_t cap)
{
    char text[2048];
    char raw[256];
    char *argv[] = {"sha256sum", NULL};
    int rc = cps_digest_text(text, sizeof text);
    if (rc != 0)
        return 1;
    rc = cps_feed(argv, text, raw, sizeof raw, 0);
    if (rc != 0)
        return rc;
    if (cps_first_field(raw, out, cap) != 0)
        return 1;
    return 0;
}

static int cps_sha_ok(const char *sha, const char *path)
{
    char line[CPS_PATH + 80];
    char *argv[] = {"sha256sum", "-c", "-", NULL};
    size_t used = 0;
    line[0] = '\0';
    if (cps_append(line, sizeof line, &used, sha) != 0)
        return -1;
    if (cps_append(line, sizeof line, &used, "  ") != 0)
        return -1;
    if (cps_append(line, sizeof line, &used, path) != 0)
        return -1;
    if (cps_append(line, sizeof line, &used, "\n") != 0)
        return -1;
    return cps_feed(argv, line, NULL, 0, 1);
}

static int cps_download(const char *url, const char *part)
{
    char curl[CPS_PATH];
    char wget[CPS_PATH];
    if (cps_which("curl", curl, sizeof curl) == 0) {
        char *argv[] = {curl, "-fsSL", "--retry", "3", "-o", (char *)part, (char *)url, NULL};
        return cps_status(argv, 0);
    }
    if (cps_which("wget", wget, sizeof wget) != 0) {
        fprintf(stderr, "c23-portable-sysroot: required tool not found: wget\n");
        return 1;
    }
    {
        char *argv[] = {wget, "-q", "-O", (char *)part, (char *)url, NULL};
        return cps_status(argv, 0);
    }
}

static int cps_fetch_one(const struct cps_pkg *pkg, const char *downloads)
{
    char out[CPS_PATH];
    char part[CPS_PATH];
    int rc;
    if (cps_under(out, sizeof out, downloads, pkg->name) != 0)
        return 1;
    if (cps_join(part, sizeof part, out, ".part") != 0)
        return 1;
    if (cps_both_regular(out, out) && cps_sha_ok(pkg->sha, out) == 0)
        return 0;
    if (cps_exists(out) && unlink(out) != 0)
        return 1;
    fprintf(stderr, "c23-portable-sysroot: fetch %s\n", pkg->url);
    rc = cps_download(pkg->url, part);
    if (rc != 0)
        return rc;
    if (cps_sha_ok(pkg->sha, part) != 0) {
        fprintf(stderr, "c23-portable-sysroot: checksum mismatch for %s\n", pkg->name);
        return 1;
    }
    if (rename(part, out) != 0)
        return 1;
    return 0;
}

static int cps_fetch_all(const struct cps_paths *p)
{
    int i;
    for (i = 0; i < CPS_PKG_N; i++) {
        int rc = cps_fetch_one(&k_pkg[i], p->downloads);
        if (rc != 0)
            return rc;
    }
    return 0;
}

static int cps_mktemp(const char *templ, char *out, size_t cap, int directory)
{
    char *dirv[] = {"mktemp", "-d", (char *)templ, NULL};
    char *filev[] = {"mktemp", (char *)templ, NULL};
    return cps_capture(directory ? dirv : filev, out, cap);
}

static int cps_pipeline(char *const left[], char *const right[])
{
    int fds[2];
    pid_t a;
    pid_t b;
    int ra;
    int rb;
    if (pipe(fds) != 0)
        return 127;
    if (cps_fork_exec(left, -1, fds[1], 0, fds[0], -1, &a) != 0) {
        close(fds[0]);
        close(fds[1]);
        return 127;
    }
    if (cps_fork_exec(right, fds[0], -1, 0, fds[1], -1, &b) != 0) {
        close(fds[0]);
        close(fds[1]);
        cps_reap(a);
        return 127;
    }
    close(fds[0]);
    close(fds[1]);
    ra = cps_reap(a);
    rb = cps_reap(b);
    if (rb != 0)
        return rb;
    return ra;
}

static int cps_extract_one(const char *deb, const char *dest)
{
    char *left[] = {"ar", "p", (char *)deb, "data.tar.xz", NULL};
    char *right[] = {"tar", "-xJ", "-C", (char *)dest, NULL};
    return cps_pipeline(left, right);
}

static int cps_rm_tree(const char *path)
{
    char *argv[5];
    pid_t pid;
    if (path == NULL || strstr(path, "/build/toolchains/") == NULL)
        return -1;
    argv[0] = "rm";
    argv[1] = "-rf";
    argv[2] = "--";
    argv[3] = (char *)path;
    argv[4] = NULL;
    pid = fork();
    if (pid < 0)
        return -1;
    if (pid != 0)
        return cps_reap(pid) == 0 ? 0 : -1;
    execvp(argv[0], argv);
    _exit(126);
}

static int cps_fix_loader(const char *root)
{
    char loader[CPS_PATH];
    struct stat st;
    if (cps_join(loader, sizeof loader, root, "/lib64/ld-linux-x86-64.so.2") != 0)
        return -1;
    if (lstat(loader, &st) != 0 || !S_ISLNK(st.st_mode)) {
        fprintf(stderr, "c23-portable-sysroot: Debian sysroot is missing its ELF loader\n");
        return -1;
    }
    if (unlink(loader) != 0)
        return -1;
    if (symlink(k_loader_rel, loader) != 0)
        return -1;
    return 0;
}

static int cps_ends(const char *name, const char *suf)
{
    size_t n = strlen(name);
    size_t s = strlen(suf);
    if (n < s)
        return 0;
    return memcmp(name + n - s, suf, s) == 0;
}

static int cps_one_so(const char *dir, const char *name)
{
    char link[CPS_PATH];
    char target[CPS_PATH];
    char next[CPS_PATH];
    struct stat st;
    ssize_t n;
    if (name[0] == '.' || !cps_ends(name, ".so"))
        return 0;
    if (cps_under(link, sizeof link, dir, name) != 0)
        return -1;
    if (lstat(link, &st) != 0 || !S_ISLNK(st.st_mode))
        return 0;
    n = readlink(link, target, sizeof target - 1);
    if (n < 0)
        return -1;
    target[n] = '\0';
    if (strncmp(target, k_abs_lib, strlen(k_abs_lib)) != 0)
        return 0;
    if (cps_join(next, sizeof next, "../../../", target + 1) != 0)
        return -1;
    if (unlink(link) != 0)
        return -1;
    if (symlink(next, link) != 0)
        return -1;
    return 0;
}

static int cps_fix_sos(const char *root)
{
    char dir[CPS_PATH];
    DIR *dp;
    struct dirent *ent;
    if (cps_join(dir, sizeof dir, root, "/usr/lib/x86_64-linux-gnu") != 0)
        return -1;
    dp = opendir(dir);
    if (dp == NULL)
        return 0;
    while ((ent = readdir(dp)) != NULL) {
        if (cps_one_so(dir, ent->d_name) != 0) {
            closedir(dp);
            return -1;
        }
    }
    closedir(dp);
    return 0;
}

static int cps_commit_root(const struct cps_paths *p, const char *stage, const char *staged)
{
    char expect[CPS_PATH];
    if (cps_join(expect, sizeof expect, p->toolchain, "/root") != 0)
        return -1;
    if (strcmp(p->sysroot, expect) != 0) {
        fprintf(stderr, "c23-portable-sysroot: unsafe sysroot path\n");
        return -1;
    }
    if (cps_rm_tree(p->sysroot) != 0)
        return -1;
    if (rename(staged, p->sysroot) != 0)
        return -1;
    if (rmdir(stage) != 0)
        return -1;
    return 0;
}

static int cps_write_stamp(const char *path, const char *expected)
{
    FILE *fp = fopen(path, "w");
    if (fp == NULL)
        return -1;
    if (fputs(expected, fp) < 0 || fputc('\n', fp) == EOF) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int cps_stage(const struct cps_paths *p, const char *expected)
{
    char pattern[CPS_PATH];
    char stage[CPS_PATH];
    char staged[CPS_PATH];
    char deb[CPS_PATH];
    int i;
    int rc;
    if (cps_join(pattern, sizeof pattern, p->toolchain, "/.root.XXXXXX") != 0)
        return 1;
    rc = cps_mktemp(pattern, stage, sizeof stage, 1);
    if (rc != 0)
        return rc;
    if (cps_join(staged, sizeof staged, stage, "/root") != 0 || mkdir(staged, 0755) != 0) {
        cps_rm_tree(stage);
        return 1;
    }
    for (i = 0; i < CPS_PKG_N; i++) {
        if (cps_under(deb, sizeof deb, p->downloads, k_pkg[i].name) != 0) {
            cps_rm_tree(stage);
            return 1;
        }
        rc = cps_extract_one(deb, staged);
        if (rc != 0) {
            cps_rm_tree(stage);
            return rc;
        }
    }
    if (cps_fix_loader(staged) != 0 || cps_fix_sos(staged) != 0 ||
        cps_commit_root(p, stage, staged) != 0) {
        cps_rm_tree(stage);
        return 1;
    }
    if (cps_write_stamp(p->stamp, expected) != 0)
        return 1;
    return 0;
}

static int cps_read_stamp(const char *path, char *out, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (out == NULL || cap < 2)
        return -1;
    out[0] = '\0';
    if (fp == NULL)
        return 0;
    n = fread(out, 1, cap - 1, fp);
    fclose(fp);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        n--;
    out[n] = '\0';
    return 0;
}

static int cps_fresh(const struct cps_paths *p, const char *expected)
{
    char current[128];
    char stdio[CPS_PATH];
    char crt[CPS_PATH];
    if (cps_read_stamp(p->stamp, current, sizeof current) != 0)
        return 0;
    if (strcmp(current, expected) != 0)
        return 0;
    if (cps_join(stdio, sizeof stdio, p->sysroot, "/usr/include/stdio.h") != 0)
        return 0;
    if (cps_join(crt, sizeof crt, p->sysroot, "/usr/lib/x86_64-linux-gnu/crt1.o") != 0)
        return 0;
    if (!cps_both_regular(stdio, crt))
        return 0;
    return 1;
}

static int cps_compiler(char *out, size_t cap)
{
    const char *name = getenv("ZCL_PORTABLE_CC");
    if (name == NULL || name[0] == '\0')
        name = "cc";
    if (cps_which(name, out, cap) == 0)
        return 0;
    fprintf(stderr, "c23-portable-sysroot: C23 compiler not found: %s\n", name);
    return -1;
}

static int cps_emit_octal(FILE *fp, unsigned char c)
{
    char oct[5];
    oct[0] = '\\';
    oct[1] = (char)('0' + ((c >> 6) & 7));
    oct[2] = (char)('0' + ((c >> 3) & 7));
    oct[3] = (char)('0' + (c & 7));
    oct[4] = '\0';
    return fputs(oct, fp) < 0 ? -1 : 0;
}

static int cps_emit_ansic_char(FILE *fp, unsigned char c)
{
    const char *named = cps_named_esc(c);
    if (named != NULL)
        return fputs(named, fp) < 0 ? -1 : 0;
    if (c == '\\' || c == '\'') {
        if (fputc('\\', fp) == EOF)
            return -1;
        return fputc((int)c, fp) == EOF ? -1 : 0;
    }
    if (c < 32 || c == 127)
        return cps_emit_octal(fp, c);
    return fputc((int)c, fp) == EOF ? -1 : 0;
}

static int cps_emit_ansic(FILE *fp, const unsigned char *s)
{
    size_t i;
    if (fputs("$'", fp) < 0)
        return -1;
    for (i = 0; s[i] != '\0'; i++) {
        if (cps_emit_ansic_char(fp, s[i]) != 0)
            return -1;
    }
    return fputc('\'', fp) == EOF ? -1 : 0;
}

static int cps_emit_bs(FILE *fp, const unsigned char *s)
{
    size_t i;
    for (i = 0; s[i] != '\0'; i++) {
        if (cps_meta(s[i], i == 0) && fputc('\\', fp) == EOF)
            return -1;
        if (fputc((int)s[i], fp) == EOF)
            return -1;
    }
    return 0;
}

static int cps_emit(FILE *fp, const char *text)
{
    const unsigned char *s = (const unsigned char *)text;
    if (s[0] == '\0')
        return fputs("''", fp) < 0 ? -1 : 0;
    if (cps_needs_ansic(s))
        return cps_emit_ansic(fp, s);
    return cps_emit_bs(fp, s);
}

static int cps_emit_piece(FILE *fp, const char *prefix, const char *text)
{
    if (fputs(prefix, fp) < 0)
        return -1;
    return cps_emit(fp, text);
}

static int cps_emit_wrap(FILE *fp, const char *compiler, const struct cps_paths *p)
{
    char b_path[CPS_PATH];
    char l_usr[CPS_PATH];
    char l_lib[CPS_PATH];
    char inc[CPS_PATH];
    if (cps_join(b_path, sizeof b_path, p->sysroot, "/usr/lib/x86_64-linux-gnu/") != 0)
        return -1;
    if (cps_join(l_usr, sizeof l_usr, p->sysroot, "/usr/lib/x86_64-linux-gnu") != 0)
        return -1;
    if (cps_join(l_lib, sizeof l_lib, p->sysroot, "/lib/x86_64-linux-gnu") != 0)
        return -1;
    if (cps_join(inc, sizeof inc, p->sysroot, "/usr/include/x86_64-linux-gnu") != 0)
        return -1;
    if (fputs("#!/bin/sh\nset -eu\nexec ", fp) < 0)
        return -1;
    if (cps_emit(fp, compiler) != 0)
        return -1;
    if (cps_emit_piece(fp, " --sysroot=", p->sysroot) != 0)
        return -1;
    if (cps_emit_piece(fp, " -B", b_path) != 0)
        return -1;
    if (cps_emit_piece(fp, " -L", l_usr) != 0)
        return -1;
    if (cps_emit_piece(fp, " -L", l_lib) != 0)
        return -1;
    if (cps_emit_piece(fp, " -isystem ", inc) != 0)
        return -1;
    if (fputs(" \"$@\" -march=x86-64 -mtune=generic\n", fp) < 0)
        return -1;
    return 0;
}

static int cps_write_wrapper(const struct cps_paths *p)
{
    char compiler[CPS_PATH];
    char pattern[CPS_PATH];
    char tmp[CPS_PATH];
    FILE *fp;
    int rc;
    if (cps_compiler(compiler, sizeof compiler) != 0)
        return 1;
    if (cps_join(pattern, sizeof pattern, p->toolchain, "/.cc.XXXXXX") != 0)
        return 1;
    rc = cps_mktemp(pattern, tmp, sizeof tmp, 0);
    if (rc != 0)
        return rc;
    fp = fopen(tmp, "w");
    if (fp == NULL) {
        unlink(tmp);
        return 1;
    }
    if (cps_emit_wrap(fp, compiler, p) != 0 || fclose(fp) != 0) {
        unlink(tmp);
        return 1;
    }
    if (chmod(tmp, 0755) != 0 || rename(tmp, p->wrapper) != 0) {
        unlink(tmp);
        return 1;
    }
    return 0;
}

static int cps_prepare(struct cps_paths *p, int announce)
{
    char expected[80];
    int rc;
    if (cps_need_all() != 0)
        return 1;
    if (cps_arch() != 0)
        return 1;
    if (cps_mkdir_p(p->downloads) != 0)
        return 1;
    rc = cps_digest(expected, sizeof expected);
    if (rc != 0)
        return rc;
    if (!cps_fresh(p, expected)) {
        rc = cps_fetch_all(p);
        if (rc != 0)
            return rc;
        rc = cps_stage(p, expected);
        if (rc != 0)
            return rc;
    }
    rc = cps_write_wrapper(p);
    if (rc != 0)
        return rc;
    if (announce)
        printf("%s\n", p->wrapper);
    return 0;
}

static int cps_smoke_source(const char *src)
{
    FILE *fp = fopen(src, "w");
    if (fp == NULL)
        return -1;
    if (fputs("#include <stdio.h>\n"
              "int main(void) { return puts(\"portable-c23\") < 0; }\n",
              fp) < 0) {
        fclose(fp);
        return -1;
    }
    if (fclose(fp) != 0)
        return -1;
    return 0;
}

static int cps_smoke_build(const struct cps_paths *p, char *bin, size_t cap)
{
    char pattern[CPS_PATH];
    char src[CPS_PATH];
    char *compile[6];
    char *run[2];
    int rc;
    if (cps_join(pattern, sizeof pattern, p->toolchain, "/.smoke.XXXXXX") != 0)
        return 1;
    rc = cps_mktemp(pattern, bin, cap, 0);
    if (rc != 0)
        return rc;
    if (cps_join(src, sizeof src, bin, ".c") != 0) {
        unlink(bin);
        return 1;
    }
    if (cps_smoke_source(src) != 0) {
        unlink(bin);
        unlink(src);
        return 1;
    }
    compile[0] = (char *)p->wrapper;
    compile[1] = "-std=c23";
    compile[2] = src;
    compile[3] = "-o";
    compile[4] = bin;
    compile[5] = NULL;
    rc = cps_status(compile, 0);
    if (rc != 0) {
        unlink(bin);
        unlink(src);
        return rc;
    }
    run[0] = bin;
    run[1] = NULL;
    rc = cps_status(run, 1);
    if (rc != 0) {
        unlink(bin);
        unlink(src);
        return rc;
    }
    return 0;
}

static void cps_unlink_smoke(const char *bin)
{
    char src[CPS_PATH];
    if (bin == NULL || bin[0] == '\0')
        return;
    unlink(bin);
    if (cps_join(src, sizeof src, bin, ".c") == 0)
        unlink(src);
}

static int cps_line_leaks(const char *line)
{
    static const char *k_mark[] = {
        "#define __AVX", "#define __AVX2__", "#define __BMI", "#define __FMA__", NULL};
    int i;
    for (i = 0; k_mark[i] != NULL; i++) {
        size_t n = strlen(k_mark[i]);
        if (strncmp(line, k_mark[i], n) == 0)
            return 1;
    }
    return 0;
}

static int cps_isa_leak(const char *text)
{
    const char *p = text == NULL ? "" : text;
    while (*p != '\0') {
        if (cps_line_leaks(p))
            return 1;
        while (*p != '\0' && *p != '\n')
            p++;
        if (*p == '\n')
            p++;
    }
    return 0;
}

static size_t cps_glibc_len(const char *s)
{
    size_t i = 6;
    int dots = 0;
    if (s[i] < '0' || s[i] > '9')
        return 0;
    while (s[i] >= '0' && s[i] <= '9')
        i++;
    while (s[i] == '.') {
        size_t j = i + 1;
        if (s[j] < '0' || s[j] > '9')
            break;
        while (s[j] >= '0' && s[j] <= '9')
            j++;
        i = j;
        dots++;
    }
    if (dots == 0)
        return 0;
    return i;
}

static int cps_gather(const char *text, char *buf, size_t cap)
{
    const char *p = text;
    size_t used = 0;
    buf[0] = '\0';
    while ((p = strstr(p, "GLIBC_")) != NULL) {
        size_t n = cps_glibc_len(p);
        if (n == 0) {
            p += 6;
            continue;
        }
        if (used + n + 2 > cap)
            return -1;
        memcpy(buf + used, p, n);
        used += n;
        buf[used++] = '\n';
        buf[used] = '\0';
        p += n;
    }
    return 0;
}

static char *cps_last_line(char *text)
{
    char *p = text;
    char *last = text;
    if (*p == '\0')
        return p;
    while (*p != '\0') {
        if (*p == '\n') {
            *p = '\0';
            if (p[1] != '\0')
                last = p + 1;
        }
        p++;
    }
    return last;
}

static int cps_highest(const char *lines, char *out, size_t cap)
{
    char sorted[65536];
    char *argv[] = {"sort", "-V", NULL};
    const char *last;
    int rc;
    if (lines == NULL || lines[0] == '\0') {
        if (cap < 1)
            return -1;
        out[0] = '\0';
        return 0;
    }
    rc = cps_feed(argv, lines, sorted, sizeof sorted, 0);
    if (rc != 0)
        return rc;
    last = cps_last_line(sorted);
    if (strlen(last) + 1 > cap)
        return -1;
    memcpy(out, last, strlen(last) + 1);
    return 0;
}

static int cps_floor_holds(const char *max)
{
    char text[256];
    char sorted[256];
    char *argv[] = {"sort", "-V", NULL};
    const char *last;
    int rc;
    if (cps_join(text, sizeof text, max, "\nGLIBC_2.31\n") != 0)
        return -1;
    rc = cps_feed(argv, text, sorted, sizeof sorted, 0);
    if (rc != 0)
        return -1;
    last = cps_last_line(sorted);
    if (strcmp(last, "GLIBC_2.31") == 0)
        return 0;
    return 1;
}

static int cps_finish(const struct cps_paths *p, const char *smoke, const char *cc_name)
{
    char macros[65536];
    char dump[65536];
    char versions[65536];
    char max[128];
    char *macro_argv[] = {(char *)p->wrapper, "-dM", "-E", "-x", "c", "/dev/null", NULL};
    char *dump_argv[] = {"objdump", "-T", (char *)smoke, NULL};
    int rc = cps_capture(macro_argv, macros, sizeof macros);
    int floor;
    if (rc != 0) {
        cps_unlink_smoke(smoke);
        return rc;
    }
    if (cps_isa_leak(macros)) {
        cps_unlink_smoke(smoke);
        fprintf(stderr,
                "c23-portable-sysroot: portable compiler wrapper leaked a post-x86-64-baseline ISA\n");
        return 1;
    }
    rc = cps_capture(dump_argv, dump, sizeof dump);
    if (rc != 0) {
        cps_unlink_smoke(smoke);
        return rc;
    }
    if (cps_gather(dump, versions, sizeof versions) != 0 ||
        cps_highest(versions, max, sizeof max) != 0) {
        cps_unlink_smoke(smoke);
        return 1;
    }
    floor = cps_floor_holds(max);
    if (floor < 0) {
        cps_unlink_smoke(smoke);
        return 1;
    }
    if (floor != 0) {
        fprintf(stderr,
                "c23-portable-sysroot: compiler support objects raised the ABI above GLIBC_2.31: %s\n",
                max);
        cps_unlink_smoke(smoke);
        return 1;
    }
    fprintf(stderr,
            "c23-portable-sysroot: PASS compiler=%s cpu=x86-64 max_abi=%s sysroot=%s\n",
            cc_name, max, p->sysroot);
    cps_unlink_smoke(smoke);
    return 0;
}

static int cps_verify(struct cps_paths *p)
{
    char smoke[CPS_PATH];
    char cc_name[CPS_PATH];
    const char *env;
    int rc = cps_prepare(p, 0);
    if (rc != 0)
        return rc;
    env = getenv("ZCL_PORTABLE_CC");
    if (env == NULL || env[0] == '\0')
        env = "cc";
    if (strlen(env) + 1 > sizeof cc_name)
        return 1;
    memcpy(cc_name, env, strlen(env) + 1);
    rc = cps_smoke_build(p, smoke, sizeof smoke);
    if (rc != 0)
        return rc;
    return cps_finish(p, smoke, cc_name);
}

static int cps_paths_from(const char *repo, struct cps_paths *p)
{
    if (cps_join(p->toolchain, sizeof p->toolchain, repo, k_tail) != 0)
        return -1;
    if (cps_join(p->downloads, sizeof p->downloads, p->toolchain, "/downloads") != 0)
        return -1;
    if (cps_join(p->sysroot, sizeof p->sysroot, p->toolchain, "/root") != 0)
        return -1;
    if (cps_join(p->wrapper, sizeof p->wrapper, p->toolchain, "/cc") != 0)
        return -1;
    if (cps_join(p->stamp, sizeof p->stamp, p->toolchain, "/inputs.sha256") != 0)
        return -1;
    return 0;
}

static int cps_dispatch(const char *repo, const char *mode)
{
    struct cps_paths paths;
    int rc;
    if (repo == NULL || repo[0] == '\0') {
        fprintf(stderr, "c23-portable-sysroot: repo is required\n");
        return 1;
    }
    if (mode == NULL || mode[0] == '\0')
        mode = "prepare";
    if (cps_paths_from(repo, &paths) != 0) {
        fprintf(stderr, "c23-portable-sysroot: path does not fit\n");
        return 1;
    }
    if (strcmp(mode, "prepare") == 0 || strcmp(mode, "cc-path") == 0)
        return cps_prepare(&paths, 1);
    if (strcmp(mode, "root-path") == 0) {
        rc = cps_prepare(&paths, 0);
        if (rc != 0)
            return rc;
        printf("%s\n", paths.sysroot);
        return 0;
    }
    if (strcmp(mode, "verify") == 0)
        return cps_verify(&paths);
    fprintf(stderr,
            "c23-portable-sysroot: usage: c23-portable-sysroot "
            "[prepare|cc-path|root-path|verify]\n");
    return 1;
}

#endif /* !_WIN32 */

int zcl_c23_portable_sysroot(const char *repo, const char *mode)
{
#if defined(_WIN32)
    (void)repo;
    (void)mode;
    fprintf(stdout, "c23-portable-sysroot: unavailable on Windows\n");
    return 2;
#else
    return cps_dispatch(repo, mode);
#endif
}
