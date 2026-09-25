/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: verify a premise base commit through a fresh private Git store —
 * ls-remote names the tip, `git fetch` copies tip history into an empty
 * store (index-pack re-derives every object id there, so a planted object
 * in the persistent store fails the copy), the base must be an ancestor of
 * the tip, and base blob bytes are read only from that store.
 *
 * Same recipe as dev land's remote observation (tools/dev/dev_git_tree.c):
 * Git runs under `env -i` with no system/global config, replace objects
 * off, fsmonitor off, no protocol but file and https, fsck on transfer, an
 * empty hook template, and cat-file without filters. Object ids stay opaque
 * locators passed to Git; z23 code never hashes them.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif
#include "premise.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum { PG_ARGV_MAX = 48, PG_OUT_MAX = 64 * 1024 * 1024, PG_DEPTH = 256 };

struct premise_git {
    char store[PREMISE_PATH_MAX];
    char git_dir[PREMISE_PATH_MAX + 16];
    char home_env[PREMISE_PATH_MAX + 32];
    pid_t batch_pid;
    FILE *batch_in;
    FILE *batch_out;
};

static const char *const k_env_prefix[] = {
    "/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LC_ALL=C",
    "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
    "GIT_NO_REPLACE_OBJECTS=1", "GIT_TERMINAL_PROMPT=0",
    "GIT_ALLOW_PROTOCOL=file:https",
};

static const char *const k_git_prefix[] = {
    "git", "--no-replace-objects", "-c", "core.fsmonitor=false",
    "-c", "protocol.allow=never", "-c", "protocol.file.allow=always",
    "-c", "protocol.https.allow=always", "-c", "fetch.fsckObjects=true",
    "-c", "transfer.fsckObjects=true",
};

static int build_argv(const struct premise_git *g, const char *const *args,
                      bool in_store, const char **argv)
{
    size_t n = 0;
    for (size_t i = 0; i < sizeof k_env_prefix / sizeof *k_env_prefix; i++)
        argv[n++] = k_env_prefix[i];
    argv[n++] = g->home_env;
    for (size_t i = 0; i < sizeof k_git_prefix / sizeof *k_git_prefix; i++)
        argv[n++] = k_git_prefix[i];
    if (in_store) {
        argv[n++] = "--git-dir";
        argv[n++] = g->git_dir;
    }
    for (size_t i = 0; args[i]; i++) {
        if (n + 1 >= PG_ARGV_MAX)
            return 2;
        argv[n++] = args[i];
    }
    argv[n] = NULL;
    return 0;
}

static int cloexec_pipe(int p[2])
{
    if (pipe(p) != 0)
        return 2;
    (void)fcntl(p[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(p[1], F_SETFD, FD_CLOEXEC);
    return 0;
}

static void child_exec(const char **argv, int in_fd, int out_fd)
{
    int null_fd = open("/dev/null", O_RDWR);
    if (dup2(in_fd >= 0 ? in_fd : null_fd, 0) < 0
        || dup2(out_fd >= 0 ? out_fd : null_fd, 1) < 0)
        _exit(127);
    execv(argv[0], (char *const *)argv);
    _exit(127);
}

static void close_if(int fd)
{
    if (fd >= 0)
        close(fd);
}

/* Spawn Git. *in_w (optional) writes its stdin, *out_r (optional) reads
 * its stdout; stderr is inherited so a refusal names itself. */
static pid_t spawn_git(const struct premise_git *g, const char *const *args,
                       bool in_store, int *in_w, int *out_r)
{
    const char *argv[PG_ARGV_MAX];
    int inp[2] = { -1, -1 }, outp[2] = { -1, -1 };
    if (build_argv(g, args, in_store, argv)
        || (in_w && cloexec_pipe(inp)) || (out_r && cloexec_pipe(outp)))
        return -1;
    fflush(NULL);
    pid_t pid = fork();
    if (pid == 0)
        child_exec(argv, inp[0], outp[1]);
    close_if(inp[0]);
    close_if(outp[1]);
    if (in_w)
        *in_w = inp[1];
    if (out_r)
        *out_r = outp[0];
    return pid;
}

static int wait_status(pid_t pid)
{
    int st = 0;
    while (waitpid(pid, &st, 0) < 0)
        if (errno != EINTR)
            return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static int grow(char **buf, size_t *cap)
{
    char *grown = *cap < PG_OUT_MAX ? realloc(*buf, *cap * 2) : NULL; // raw-alloc-ok:lint-runtime
    if (!grown)
        return 2;
    *buf = grown;
    *cap *= 2;
    return 0;
}

static int drain(int fd, char **out, size_t *len)
{
    size_t cap = 8192, used = 0;
    char *buf = malloc(cap); // raw-alloc-ok:lint-runtime
    int rc = buf ? 0 : 2;
    while (rc == 0) {
        if (used + 1 >= cap && grow(&buf, &cap)) {
            rc = 2;
            break;
        }
        ssize_t n = read(fd, buf + used, cap - used - 1);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            rc = n < 0 ? 2 : 0;
            break;
        }
        used += (size_t)n;
    }
    if (rc) {
        free(buf);
        return rc;
    }
    buf[used] = '\0';
    *out = buf;
    *len = used;
    return 0;
}

/* Run Git to completion. Returns its exit code (0 success), -1 on spawn or
 * read failure. *out (optional) receives stdout, NUL-terminated. */
static int run_git(const struct premise_git *g, const char *const *args,
                   bool in_store, char **out, size_t *len)
{
    int out_fd = -1;
    pid_t pid = spawn_git(g, args, in_store, NULL, &out_fd);
    if (pid < 0)
        return -1;
    char *buf = NULL;
    size_t n = 0;
    int rc = drain(out_fd, &buf, &n);
    close(out_fd);
    int code = wait_status(pid);
    if (rc == 0 && out) {
        *out = buf;
        if (len)
            *len = n;
    } else {
        free(buf);
    }
    return rc ? -1 : code;
}

static bool oid_ok(const char *s, size_t n)
{
    if (n != 40 && n != 64)
        return false;
    for (size_t i = 0; i < n; i++)
        if (s[i] == '\0' || !strchr("0123456789abcdef", s[i]))
            return false;
    return true;
}

static int ls_remote_tip(const struct premise_git *g, const char *remote,
                         const char *ref, char tip[PREMISE_OID_MAX])
{
    const char *args[] = { "ls-remote", "--", remote, ref, NULL };
    char *out = NULL;
    if (run_git(g, args, false, &out, NULL) != 0)
        return 1;
    char *tab = strchr(out, '\t');
    size_t n = tab ? (size_t)(tab - out) : 0, r = strlen(ref);
    bool ok = tab && oid_ok(out, n) && strncmp(tab + 1, ref, r) == 0
              && strcmp(tab + 1 + r, "\n") == 0;
    if (ok) {
        memcpy(tip, out, n);
        tip[n] = '\0';
    }
    free(out);
    return ok ? 0 : 1;
}

static int make_store(struct premise_git *g, const char *scratch, bool sha256)
{
    int k = snprintf(g->store, sizeof g->store, "%s/premise-store-XXXXXX",
                     scratch);
    if (k < 0 || (size_t)k >= sizeof g->store - 32 || !mkdtemp(g->store))
        return 2;
    char home[PREMISE_PATH_MAX + 16], tmpl[PREMISE_PATH_MAX + 16];
    char tflag[PREMISE_PATH_MAX + 32];
    snprintf(home, sizeof home, "%s/home", g->store);
    snprintf(tmpl, sizeof tmpl, "%s/template", g->store);
    snprintf(tflag, sizeof tflag, "--template=%s", tmpl);
    snprintf(g->git_dir, sizeof g->git_dir, "%s/objects.git", g->store);
    snprintf(g->home_env, sizeof g->home_env, "HOME=%s", home);
    if (mkdir(home, 0700) != 0 || mkdir(tmpl, 0700) != 0)
        return 2;
    const char *args[] = { "init", "--bare", "--quiet", tflag,
                           "--object-format", sha256 ? "sha256" : "sha1",
                           g->git_dir, NULL };
    return run_git(g, args, false, NULL, NULL) == 0 ? 0 : 2;
}

static int fetch_tip(const struct premise_git *g, const char *objects,
                     const char *tip, unsigned depth)
{
    char spec[PREMISE_OID_MAX + 32], dflag[32];
    snprintf(spec, sizeof spec, "%s:refs/heads/tip", tip);
    snprintf(dflag, sizeof dflag, "--depth=%u", depth ? depth : PG_DEPTH);
    const char *args[] = { "fetch", "--quiet", "--no-tags",
                           "--no-write-fetch-head", dflag, "--", objects,
                           spec, NULL };
    return run_git(g, args, true, NULL, NULL) == 0 ? 0 : 1;
}

static int base_is_commit_ancestor(const struct premise_git *g,
                                   const char *base, const char *tip)
{
    char spec[PREMISE_OID_MAX + 16];
    snprintf(spec, sizeof spec, "%s^{commit}", base);
    const char *verify[] = { "rev-parse", "--verify", "--quiet", spec, NULL };
    char *out = NULL;
    int rc = run_git(g, verify, true, &out, NULL);
    bool exact = rc == 0 && out && strncmp(out, base, strlen(base)) == 0;
    free(out);
    if (!exact)
        return 1;
    const char *anc[] = { "merge-base", "--is-ancestor", base, tip, NULL };
    return run_git(g, anc, true, NULL, NULL) == 0 ? 0 : 1;
}

static int parse_record(struct premise_tree *t, char *rec)
{
    char *tab = strchr(rec, '\t');
    if (!tab)
        return 2;
    *tab = '\0';
    char mode[8], type[8], oid[PREMISE_OID_MAX];
    int used = 0;
    if (sscanf(rec, "%7s %7s %64s%n", mode, type, oid, &used) != 3
        || rec[used] != '\0' || !oid_ok(oid, strlen(oid)))
        return 2;
    const char *path = tab + 1;
    if (strcmp(mode, "160000") == 0 || premise_path_pruned(path))
        return 0;
    if (strcmp(type, "blob") != 0)
        return 2;
    return premise_tree_add(t, path, oid, strcmp(mode, "120000") == 0);
}

static int list_base(struct premise_tree *t, const char *base)
{
    const char *args[] = { "ls-tree", "-rz", "--full-tree", base, NULL };
    char *out = NULL;
    size_t len = 0;
    if (run_git(t->git, args, true, &out, &len) != 0)
        return 2;
    int rc = 0;
    for (size_t off = 0; rc == 0 && off < len;) {
        size_t n = strlen(out + off);
        rc = parse_record(t, out + off);
        off += n + 1;
    }
    free(out);
    return rc ? rc : premise_tree_finish(t);
}

static int open_batch(struct premise_git *g)
{
    const char *args[] = { "cat-file", "--batch", NULL };
    int in_w = -1, out_r = -1;
    g->batch_pid = spawn_git(g, args, true, &in_w, &out_r);
    if (g->batch_pid < 0)
        return 2;
    g->batch_in = fdopen(in_w, "w");
    g->batch_out = fdopen(out_r, "r");
    return g->batch_in && g->batch_out ? 0 : 2;
}

int premise_git_blob(struct premise_git *g, const char *oid, uint8_t **bytes,
                     size_t *len)
{
    char head[PREMISE_OID_MAX + 64], got[PREMISE_OID_MAX], type[16];
    unsigned long long size = 0;
    if (!g->batch_in || fprintf(g->batch_in, "%s\n", oid) < 0
        || fflush(g->batch_in) != 0 || !fgets(head, sizeof head, g->batch_out))
        return 2;
    if (sscanf(head, "%64s %15s %llu", got, type, &size) != 3
        || strcmp(got, oid) != 0 || strcmp(type, "blob") != 0
        || size > PG_OUT_MAX)
        return 2;
    uint8_t *buf = malloc(size ? size : 1); // raw-alloc-ok:lint-runtime
    if (!buf)
        return 2;
    if (fread(buf, 1, size, g->batch_out) != size
        || fgetc(g->batch_out) != '\n') {
        free(buf);
        return 2;
    }
    *bytes = buf;
    *len = (size_t)size;
    return 0;
}

static int rm_entry(const char *path, const struct stat *st, int flag,
                    struct FTW *ftw)
{
    (void)st;
    (void)ftw;
    return (flag == FTW_DP ? rmdir(path) : unlink(path)) == 0 ? 0 : 1;
}

void premise_git_close(struct premise_git *g)
{
    if (!g)
        return;
    if (g->batch_in)
        fclose(g->batch_in);
    if (g->batch_out)
        fclose(g->batch_out);
    if (g->batch_pid > 0)
        (void)wait_status(g->batch_pid);
    if (g->store[0])
        (void)nftw(g->store, rm_entry, 16, FTW_DEPTH | FTW_PHYS);
    free(g);
}

static int verify_chain(struct premise_git *g, const struct premise_base_opts *o,
                        char *why, size_t cap)
{
    char tip[PREMISE_OID_MAX];
    const char *ref = o->ref ? o->ref : "refs/heads/main";
    if (ls_remote_tip(g, o->remote, ref, tip)) {
        snprintf(why, cap, "base-unverified:ls-remote %s gave no exact tip", ref);
        return 1;
    }
    if (strlen(tip) != strlen(o->base)) {
        snprintf(why, cap, "base-unverified:object format differs from tip");
        return 1;
    }
    if (fetch_tip(g, o->objects, tip, o->depth)) {
        snprintf(why, cap, "base-unverified:fresh-store fetch of tip %.12s "
                           "failed (missing or corrupt object)", tip);
        return 1;
    }
    if (base_is_commit_ancestor(g, o->base, tip)) {
        snprintf(why, cap, "base-unverified:%.12s is not an ancestor of the "
                           "%s tip %.12s", o->base, ref, tip);
        return 1;
    }
    return 0;
}

static bool opts_complete(const struct premise_base_opts *o)
{
    return o->base && oid_ok(o->base, strlen(o->base)) && o->remote
           && o->remote[0] && o->remote[0] != '-' && o->objects
           && o->objects[0] && o->objects[0] != '-' && o->scratch;
}

int premise_git_open(const struct premise_base_opts *o,
                     struct premise_tree *base, char *why, size_t why_cap,
                     FILE *err)
{
    if (!opts_complete(o)) {
        snprintf(why, why_cap, "base-unverified:exact base, remote, objects "
                               "and scratch are required");
        return 1;
    }
    struct premise_git *g = calloc(1, sizeof *g); // raw-alloc-ok:lint-runtime
    if (!g || make_store(g, o->scratch, strlen(o->base) == 64)) {
        fprintf(err, "premise: cannot create a private Git store under %s\n",
                o->scratch);
        premise_git_close(g);
        return 2;
    }
    base->git = g;
    int rc = verify_chain(g, o, why, why_cap);
    if (rc == 0 && list_base(base, o->base)) {
        snprintf(why, why_cap, "base-unverified:cannot list the base tree");
        rc = 1;
    }
    if (rc == 0 && open_batch(g)) {
        snprintf(why, why_cap, "base-unverified:cannot open the blob reader");
        rc = 1;
    }
    return rc;
}
