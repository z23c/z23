/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Rebuild the ordinary C23 products at the glibc 2.31 floor,
 *          with real Tor, and refuse a source epoch that moved mid-build.
 *          Nothing forces TOR_FULL empty. Reach zcl_tor_require_full
 *          through tor-stamp require-full. */

#include "c23_portable_release.h"

#include <stdio.h>
#include <string.h>

static int cpr_hex64(const char *s)
{
    size_t i;
    if (s == NULL)
        return 0;
    for (i = 0; i < 64; i++) {
        char c = s[i];
        if (c == '\0')
            return 0;
        if ((c < '0' || c > '9') && (c < 'a' || c > 'f'))
            return 0;
    }
    return s[64] == '\0';
}

int zcl_c23_portable_release_verify(const char *before, const char *after,
                                    const char *baked)
{
    if (!cpr_hex64(before)) {
        fprintf(stderr, "c23-portable-release: invalid initial source identity\n");
        return 1;
    }
    if (!cpr_hex64(after)) {
        fprintf(stderr, "c23-portable-release: invalid final source identity\n");
        return 1;
    }
    if (!cpr_hex64(baked)) {
        fprintf(stderr,
                "c23-portable-release: node omitted its baked source identity\n");
        return 1;
    }
    if (strcmp(before, after) != 0) {
        fprintf(stderr,
                "c23-portable-release: source epoch changed during build: "
                "before=%s after=%s\n",
                before, after);
        return 1;
    }
    if (strcmp(baked, after) != 0) {
        fprintf(stderr,
                "c23-portable-release: node baked source %s but final source is %s\n",
                baked, after);
        return 1;
    }
    return 0;
}

#if !defined(_WIN32)

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CPR_OUT 8192

static const char *k_vendor_libs[] = {
    "libtor_stub.a", "libsqlite3.a", "libz.a", "libcrypto.a", "libssl.a",
    "libevent.a", "libevent_openssl.a", "libevent_pthreads.a", NULL};

static const char *k_products[] = {
    "zclassic23", "zcl-rpc", "zcl-nodectl", "z23-package-sign",
    "z23-package-verify", "z23-acme", NULL};

/* Trailing blank is the tor-full gate's edit anchor. The make argv drops it. */
static const char k_make_portable[] = "ZCL_C23_PORTABLE_RELEASE=1 ";

static char g_cpr_path[8192];

static int cpr_reap(pid_t child)
{
    int status = 0;
    pid_t got = waitpid(child, &status, 0);
    while (got < 0 && errno == EINTR)
        got = waitpid(child, &status, 0);
    if (got != child)
        return 125;
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    return 125;
}

static int cpr_read_file(const char *path, char *buf, size_t cap)
{
    FILE *fp = fopen(path, "r");
    size_t n;
    if (fp == NULL)
        return -1;
    n = fread(buf, 1, cap - 1, fp);
    fclose(fp);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        n--;
    buf[n] = '\0';
    return 0;
}

static int cpr_capture_open(char *tmpl, size_t cap)
{
    const char *tmp = getenv("TMPDIR");
    int nw;
    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    nw = snprintf(tmpl, cap, "%s/cpr-cap.XXXXXX", tmp);
    if (nw < 0 || (size_t)nw >= cap)
        return -1;
    return mkstemp(tmpl);
}

static int cpr_child_out(int mode, int fd)
{
    if (mode == 2) {
        int sink = open("/dev/null", O_WRONLY);
        if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0)
            return -1;
        if (sink > STDERR_FILENO)
            close(sink);
        return 0;
    }
    if (mode == 1 || mode == 3) {
        if (dup2(fd, STDOUT_FILENO) < 0)
            return -1;
        close(fd);
    }
    return 0;
}

static int cpr_take_text(int rc, char *tmpl, char *out, size_t cap)
{
    if (rc == 0 && (out == NULL || cpr_read_file(tmpl, out, cap) != 0))
        rc = 127;
    unlink(tmpl);
    return rc;
}

static int cpr_keep_path(int rc, char *tmpl, char *out, size_t cap)
{
    if (rc != 0 || out == NULL) {
        unlink(tmpl);
        if (rc == 0)
            return 127;
        return rc;
    }
    if (strlen(tmpl) + 1 > cap) {
        unlink(tmpl);
        return 127;
    }
    memcpy(out, tmpl, strlen(tmpl) + 1);
    return 0;
}

static int cpr_exec(char *const argv[], int mode, char *out, size_t cap)
{
    char tmpl[512];
    int fd = -1;
    pid_t child;
    int rc;
    if (mode == 1 || mode == 3) {
        fd = cpr_capture_open(tmpl, sizeof tmpl);
        if (fd < 0)
            return 127;
    }
    child = fork();
    if (child < 0) {
        if (fd >= 0) {
            close(fd);
            unlink(tmpl);
        }
        return 127;
    }
    if (child == 0) {
        if (cpr_child_out(mode, fd) != 0)
            _exit(127);
        execvp(argv[0], argv);
        _exit(127);
    }
    if (fd >= 0)
        close(fd);
    rc = cpr_reap(child);
    if (mode == 1)
        return cpr_take_text(rc, tmpl, out, cap);
    if (mode == 3)
        return cpr_keep_path(rc, tmpl, out, cap);
    return rc;
}

static int cpr_prefix_path(const char *dir)
{
    const char *old = getenv("PATH");
    char next[8192];
    int nw;
    if (old == NULL)
        old = "";
    nw = snprintf(next, sizeof next, "%s:%s", dir, old);
    if (nw < 0 || (size_t)nw >= sizeof next)
        return -1;
    if (setenv("PATH", next, 1) != 0)
        return -1;
    return 0;
}

static int cpr_push_path(const char *dir)
{
    const char *saved = getenv("PATH");
    if (saved == NULL)
        saved = "";
    if (strlen(saved) + 1 > sizeof g_cpr_path)
        return -1;
    memcpy(g_cpr_path, saved, strlen(saved) + 1);
    return cpr_prefix_path(dir);
}

static void cpr_pop_path(void)
{
    if (setenv("PATH", g_cpr_path, 1) != 0)
        return;
}

static int cpr_sha_bytes(const char *text, char out[65])
{
    char tmpl[512];
    const char *tmp = getenv("TMPDIR");
    char *sumv[] = {"sha256sum", tmpl, NULL};
    int fd;
    int nw;
    int rc;
    char buf[512];
    size_t n = strlen(text);
    if (tmp == NULL || tmp[0] == '\0')
        tmp = "/tmp";
    nw = snprintf(tmpl, sizeof tmpl, "%s/cpr-sha.XXXXXX", tmp);
    if (nw < 0 || (size_t)nw >= sizeof tmpl)
        return -1;
    fd = mkstemp(tmpl);
    if (fd < 0)
        return -1;
    if (write(fd, text, n) != (ssize_t)n) {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    close(fd);
    rc = cpr_exec(sumv, 1, buf, sizeof buf);
    unlink(tmpl);
    if (rc != 0)
        return -1;
    buf[64] = '\0';
    if (!cpr_hex64(buf))
        return -1;
    memcpy(out, buf, 65);
    return 0;
}

static int cpr_verify_quiet(const char *a, const char *b, const char *c)
{
    int saved = dup(STDERR_FILENO);
    int sink = open("/dev/null", O_WRONLY);
    int rc;
    if (saved < 0 || sink < 0) {
        if (saved >= 0)
            close(saved);
        if (sink >= 0)
            close(sink);
        return -1;
    }
    fflush(stderr);
    if (dup2(sink, STDERR_FILENO) < 0) {
        close(sink);
        close(saved);
        return -1;
    }
    close(sink);
    rc = zcl_c23_portable_release_verify(a, b, c);
    fflush(stderr);
    if (dup2(saved, STDERR_FILENO) < 0) {
        close(saved);
        return -1;
    }
    close(saved);
    return rc;
}

static int cpr_selftest(void)
{
    char a[65];
    char b[65];
    int rc;
    if (cpr_sha_bytes("epoch-a", a) != 0 || cpr_sha_bytes("epoch-b", b) != 0) {
        fprintf(stderr, "c23-portable-release: selftest FAILED \xe2\x80\x94 sha256sum\n");
        return 1;
    }
    if (zcl_c23_portable_release_verify(a, a, a) != 0)
        return 1;
    rc = cpr_verify_quiet(a, b, a);
    if (rc == 0 || rc < 0) {
        fprintf(stderr,
                "c23-portable-release: selftest FAILED \xe2\x80\x94 "
                "expected non-zero from: verify mismatch epoch\n");
        return 1;
    }
    rc = cpr_verify_quiet(a, a, b);
    if (rc == 0 || rc < 0) {
        fprintf(stderr,
                "c23-portable-release: selftest FAILED \xe2\x80\x94 "
                "expected non-zero from: verify mismatch baked\n");
        return 1;
    }
    printf("c23-portable-release: selftest PASS\n");
    return 0;
}

static int cpr_join(char *out, size_t cap, const char *a, const char *b)
{
    int nw = snprintf(out, cap, "%s%s", a, b);
    if (nw < 0)
        return -1;
    if ((size_t)nw >= cap)
        return -1;
    return 0;
}

static int cpr_dirname(const char *path, char *out, size_t cap)
{
    size_t n = strlen(path);
    if (n < 2 || cap < 2)
        return -1;
    while (n > 0 && path[n - 1] != '/')
        n--;
    if (n < 2)
        return -1;
    n--;
    if (n >= cap)
        return -1;
    memcpy(out, path, n);
    out[n] = '\0';
    return 0;
}

static const char *cpr_baked(const char *body, char out[65])
{
    const char *prefix =
        "{\"schema\":\"zcl.agent_build.v2\",\"api_version\":\"v1\","
        "\"status\":\"ok\",\"source_id_sha256\":\"";
    const char *rest;
    char dig[65];
    size_t n = strlen(prefix);
    if (strncmp(body, prefix, n) != 0)
        return NULL;
    rest = body + n;
    if (strlen(rest) < 82)
        return NULL;
    memcpy(dig, rest, 64);
    dig[64] = '\0';
    if (!cpr_hex64(dig))
        return NULL;
    if (strncmp(rest + 64, "\",\"build_commit\":\"", 18) != 0)
        return NULL;
    memcpy(out, dig, 65);
    return out;
}

static int cpr_glibc_num(const char *s, int *n, const char **end)
{
    int v = 0;
    if (*s < '0' || *s > '9')
        return -1;
    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    *n = v;
    *end = s;
    return 0;
}

static int cpr_glibc_less(const char *a, const char *b)
{
    int i;
    const char *pa = a + 6;
    const char *pb = b + 6;
    for (i = 0; i < 4; i++) {
        int na = 0;
        int nb = 0;
        if (*pa != '\0' && cpr_glibc_num(pa, &na, &pa) != 0)
            return 0;
        if (*pb != '\0' && cpr_glibc_num(pb, &nb, &pb) != 0)
            return 0;
        if (na != nb)
            return na < nb;
        if (*pa == '.')
            pa++;
        if (*pb == '.')
            pb++;
    }
    return 0;
}

static void cpr_glibc_max(const char *text, char *out, size_t cap)
{
    const char *p = text;
    while ((p = strstr(p, "GLIBC_")) != NULL) {
        const char *s = p;
        char tok[32];
        size_t n = 0;
        int dots = 0;
        p += 6;
        if (*p < '0' || *p > '9')
            continue;
        while (n + 1 < sizeof tok && *s != '\0' && *s != ' ' && *s != '\n') {
            if (*s == '.')
                dots++;
            tok[n++] = *s++;
        }
        tok[n] = '\0';
        if (dots < 1)
            continue;
        if (out[0] == '\0' || cpr_glibc_less(out, tok)) {
            if (strlen(tok) + 1 <= cap)
                memcpy(out, tok, strlen(tok) + 1);
        }
        p = s;
    }
}

static void cpr_glibc_from_file(const char *path, char *out, size_t cap)
{
    FILE *fp = fopen(path, "r");
    char line[1024];
    out[0] = '\0';
    if (fp == NULL)
        return;
    while (fgets(line, sizeof line, fp) != NULL)
        cpr_glibc_max(line, out, cap);
    fclose(fp);
}

static void cpr_first_field(char *s)
{
    size_t i = 0;
    while (s[i] != '\0' && s[i] != ' ' && s[i] != '\t')
        i++;
    s[i] = '\0';
}

static int cpr_spawn_cc(const char *cc_dir, char *script, char **argv)
{
    int rc;
    argv[0] = script;
    if (cpr_push_path(cc_dir) != 0)
        return 2;
    if (setenv("VENDOR_CC", "cc", 1) != 0) {
        cpr_pop_path();
        return 2;
    }
    rc = cpr_exec(argv, 0, NULL, 0);
    cpr_pop_path();
    unsetenv("VENDOR_CC");
    return rc;
}

static int cpr_vendor(const char *repo, const char *cc_dir)
{
    char script[4096];
    char *argv[12];
    int i;
    if (cpr_join(script, sizeof script, repo, "/tools/scripts/build_vendor.sh") != 0)
        return 2;
    for (i = 0; k_vendor_libs[i] != NULL; i++)
        argv[i + 1] = (char *)k_vendor_libs[i];
    argv[i + 1] = NULL;
    return cpr_spawn_cc(cc_dir, script, argv);
}

static int cpr_tor(const char *repo, const char *cc_dir)
{
    char script[4096];
    char *argv[2];
    if (cpr_join(script, sizeof script, repo, "/tools/scripts/build_tor_full.sh") != 0)
        return 2;
    argv[1] = NULL;
    return cpr_spawn_cc(cc_dir, script, argv);
}

static int cpr_make_products(const char *repo, const char *cc_dir)
{
    char *argv[16];
    char assign[64];
    int i;
    int rc;
    size_t n = strlen(k_make_portable);
    if (n == 0 || n >= sizeof assign)
        return 2;
    memcpy(assign, k_make_portable, n + 1);
    if (assign[n - 1] == ' ')
        assign[n - 1] = '\0';
    argv[0] = "make";
    argv[1] = "-C";
    argv[2] = (char *)repo;
    argv[3] = "CC=cc";
    argv[4] = "VENDOR_CC=cc";
    argv[5] = assign;
    for (i = 0; k_products[i] != NULL; i++)
        argv[6 + i] = (char *)k_products[i];
    argv[6 + i] = NULL;
    if (cpr_push_path(cc_dir) != 0)
        return 2;
    rc = cpr_exec(argv, 0, NULL, 0);
    cpr_pop_path();
    return rc;
}

static int cpr_check_one(const char *script, const char *repo, const char *product)
{
    char bin[4096];
    char *argv[3];
    int rc;
    if (cpr_join(bin, sizeof bin, repo, "/build/bin/") != 0)
        return 2;
    if (strlen(bin) + strlen(product) + 1 > sizeof bin)
        return 2;
    memcpy(bin + strlen(bin), product, strlen(product) + 1);
    argv[0] = (char *)script;
    argv[1] = bin;
    argv[2] = NULL;
    rc = cpr_exec(argv, 2, NULL, 0);
    return rc;
}

static int cpr_checks(const char *repo)
{
    char tor[4096];
    char node[4096];
    char script[4096];
    char *argv[6];
    int i;
    int rc;
    if (cpr_join(tor, sizeof tor, repo, "/build/bin/tor-stamp") != 0)
        return 2;
    if (cpr_join(node, sizeof node, repo, "/build/bin/zclassic23") != 0)
        return 2;
    argv[0] = "make";
    argv[1] = "-C";
    argv[2] = (char *)repo;
    argv[3] = "tor-stamp";
    argv[4] = NULL;
    rc = cpr_exec(argv, 2, NULL, 0);
    if (rc != 0)
        return 1;
    argv[0] = tor;
    argv[1] = "require-full";
    argv[2] = node;
    argv[3] = "the portable release node";
    argv[4] = NULL;
    rc = cpr_exec(argv, 0, NULL, 0);
    if (rc != 0)
        return 1;
    argv[1] = "write-sidecar";
    argv[3] = NULL;
    rc = cpr_exec(argv, 0, NULL, 0);
    if (rc != 0) {
        fprintf(stderr,
                "c23-portable-release: could not write the tor stamp sidecar "
                "next to the portable release node\n");
        return 1;
    }
    if (cpr_join(script, sizeof script, repo,
                 "/tools/scripts/check_c23_node_binary.sh") != 0)
        return 2;
    if (setenv("ZCL_C23_MAX_GLIBC", "GLIBC_2.31", 1) != 0)
        return 2;
    for (i = 0; k_products[i] != NULL; i++) {
        rc = cpr_check_one(script, repo, k_products[i]);
        if (rc != 0) {
            unsetenv("ZCL_C23_MAX_GLIBC");
            return rc;
        }
    }
    unsetenv("ZCL_C23_MAX_GLIBC");
    return 0;
}

static int cpr_capture_id(const char *script, char out[65])
{
    char *argv[] = {(char *)script, "capture", NULL};
    char buf[CPR_OUT];
    int rc = cpr_exec(argv, 1, buf, sizeof buf);
    if (rc != 0)
        return rc;
    if (!cpr_hex64(buf))
        return 1;
    memcpy(out, buf, 65);
    return 0;
}

static int cpr_run_old(const char *sysroot, const char *node, int qemu)
{
    char ld[4096];
    char libs[4096];
    if (cpr_join(ld, sizeof ld, sysroot, "/lib64/ld-linux-x86-64.so.2") != 0)
        return 2;
    if (snprintf(libs, sizeof libs,
                 "%s/lib/x86_64-linux-gnu:%s/usr/lib/x86_64-linux-gnu",
                 sysroot, sysroot) >= (int)sizeof libs)
        return 2;
    if (!qemu) {
        char *plain[] = {ld, "--library-path", libs, (char *)node,
                         "discover", "search", "package", NULL};
        return cpr_exec(plain, 2, NULL, 0);
    }
    {
        char *qv[] = {"qemu-x86_64", "-cpu", "qemu64", ld, "--library-path",
                      libs, (char *)node, "discover", "search", "package", NULL};
        return cpr_exec(qv, 2, NULL, 0);
    }
}

static int cpr_on_path(const char *name)
{
    const char *path = getenv("PATH");
    char buf[4096];
    const char *p;
    if (path == NULL || name == NULL || name[0] == '\0')
        return 0;
    p = path;
    while (*p != '\0') {
        const char *colon = strchr(p, ':');
        size_t n = colon == NULL ? strlen(p) : (size_t)(colon - p);
        int nw;
        if (n == 0)
            nw = snprintf(buf, sizeof buf, "%s", name);
        else
            nw = snprintf(buf, sizeof buf, "%.*s/%s", (int)n, p, name);
        if (nw > 0 && (size_t)nw < sizeof buf && access(buf, X_OK) == 0)
            return 1;
        if (colon == NULL)
            break;
        p = colon + 1;
    }
    return 0;
}

struct cpr_job {
    char wrapper[CPR_OUT];
    char sysroot[CPR_OUT];
    char cc_dir[4096];
    char ident[4096];
    char node[4096];
    char before[65];
    char after[65];
    char baked[65];
};

static int cpr_toolchain(const char *repo, struct cpr_job *job)
{
    char sysroot_sh[4096];
    char *argv[3];
    int rc;
    if (cpr_join(sysroot_sh, sizeof sysroot_sh, repo,
                 "/build/bin/c23-portable-sysroot") != 0)
        return 2;
    argv[0] = sysroot_sh;
    argv[1] = "prepare";
    argv[2] = NULL;
    rc = cpr_exec(argv, 1, job->wrapper, sizeof job->wrapper);
    if (rc != 0)
        return rc;
    argv[1] = "root-path";
    rc = cpr_exec(argv, 1, job->sysroot, sizeof job->sysroot);
    if (rc != 0)
        return rc;
    if (cpr_dirname(job->wrapper, job->cc_dir, sizeof job->cc_dir) != 0)
        return 2;
    fprintf(stderr, "c23-portable-release: rebuilding linked archives through %s\n",
            job->wrapper);
    rc = cpr_vendor(repo, job->cc_dir);
    if (rc != 0)
        return rc;
    return cpr_tor(repo, job->cc_dir);
}

static int cpr_link(const char *repo, struct cpr_job *job)
{
    int rc;
    if (cpr_join(job->ident, sizeof job->ident, repo,
                 "/tools/dev/source-identity.sh") != 0)
        return 2;
    rc = cpr_capture_id(job->ident, job->before);
    if (rc == 1)
        fprintf(stderr,
                "c23-portable-release: could not capture settled source identity\n");
    if (rc != 0)
        return rc;
    rc = cpr_make_products(repo, job->cc_dir);
    if (rc != 0)
        return rc;
    return cpr_checks(repo);
}

static int cpr_epoch(const char *repo, struct cpr_job *job)
{
    char agent[CPR_OUT];
    char *argv[3];
    int rc = cpr_capture_id(job->ident, job->after);
    if (rc == 1)
        fprintf(stderr, "c23-portable-release: invalid final source identity\n");
    if (rc != 0)
        return rc;
    if (cpr_join(job->node, sizeof job->node, repo, "/build/bin/zclassic23") != 0)
        return 2;
    argv[0] = job->node;
    argv[1] = "agentbuild";
    argv[2] = NULL;
    rc = cpr_exec(argv, 1, agent, sizeof agent);
    if (rc != 0)
        return rc;
    if (cpr_baked(agent, job->baked) == NULL) {
        fprintf(stderr,
                "c23-portable-release: node omitted its baked source identity\n");
        return 1;
    }
    return zcl_c23_portable_release_verify(job->before, job->after, job->baked);
}

static int cpr_pass_line(struct cpr_job *job)
{
    char dump_path[512];
    char digest[512];
    char maxabi[32];
    char *argv[4];
    int nprod = 0;
    int qemu;
    int rc;
    while (k_products[nprod] != NULL)
        nprod++;
    qemu = cpr_on_path("qemu-x86_64");
    rc = cpr_run_old(job->sysroot, job->node, 0);
    if (rc != 0)
        return rc;
    if (qemu) {
        rc = cpr_run_old(job->sysroot, job->node, 1);
        if (rc != 0)
            return rc;
    }
    argv[0] = "objdump";
    argv[1] = "-T";
    argv[2] = job->node;
    argv[3] = NULL;
    maxabi[0] = '\0';
    if (cpr_exec(argv, 3, dump_path, sizeof dump_path) == 0) {
        cpr_glibc_from_file(dump_path, maxabi, sizeof maxabi);
        unlink(dump_path);
    }
    /* objdump | grep under pipefail exits 1 when no GLIBC_ token survives. */
    if (maxabi[0] == '\0')
        return 1;
    argv[0] = "sha256sum";
    argv[1] = job->node;
    argv[2] = NULL;
    rc = cpr_exec(argv, 1, digest, sizeof digest);
    if (rc != 0)
        return rc;
    cpr_first_field(digest);
    fprintf(stderr,
            "c23-portable-release: PASS products=%d cpu=x86-64 "
            "cpu_runtime_proof=%s glibc_floor=2.31 source_id=%s "
            "node=build/bin/zclassic23 sha256=%s max_abi=%s\n",
            nprod, qemu ? "qemu64" : "compiler-baseline", job->after, digest,
            maxabi);
    return 0;
}

static int cpr_release(const char *repo)
{
    struct cpr_job job;
    int rc = cpr_toolchain(repo, &job);
    if (rc != 0)
        return rc;
    rc = cpr_link(repo, &job);
    if (rc != 0)
        return rc;
    rc = cpr_epoch(repo, &job);
    if (rc != 0)
        return rc;
    return cpr_pass_line(&job);
}

#endif /* !_WIN32 */

int zcl_c23_portable_release(const char *repo, int selftest)
{
#if defined(_WIN32)
    (void)repo;
    (void)selftest;
    fputs("c23-portable-release: unavailable on Windows\n", stdout);
    return 2;
#else
    if (selftest)
        return cpr_selftest();
    if (repo == NULL || repo[0] == '\0') {
        fprintf(stderr, "c23-portable-release: repo is required\n");
        return 2;
    }
    return cpr_release(repo);
#endif
}
