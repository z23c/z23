/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: the temp lab the dev.batch groups (test_dev_batch_ledger.c,
 *          test_dev_batch_restack.c, test_dev_batch_slim.c) run against: a
 *          fake $HOME holding the handoff state directory, a bare origin, the
 *          main checkout and lane clones, with every external program
 *          (`dev land status`, systemctl) replaced by a small generated sh
 *          fake written at run time, so no shell file is tracked and no real
 *          lab state is ever read. */

#ifndef ZCL_TEST_DEV_BATCH_FIXTURE_H
#define ZCL_TEST_DEV_BATCH_FIXTURE_H

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "util/spawn.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#define DBF_HANDOFF "development/z23/handoff/handoff-20261025"

struct dbf {
    char root[600];
    char home[700];
    char state[800];
    char origin[800];
    char mainco[800];
    char fakes[800];
};

typedef void (*dbf_handler)(const struct zcl_command_request *,
                            struct zcl_command_reply *);

static inline bool dbf_mkdirs(const char *path)
{
    char buf[1400];
    size_t i;
    if (snprintf(buf, sizeof(buf), "%s", path) >= (int)sizeof(buf))
        return false;
    for (i = 1; buf[i]; i++) {
        if (buf[i] != '/')
            continue;
        buf[i] = '\0';
        if (mkdir(buf, 0755) != 0 && access(buf, F_OK) != 0)
            return false;
        buf[i] = '/';
    }
    return mkdir(buf, 0755) == 0 || access(buf, F_OK) == 0;
}

static inline bool dbf_put(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    size_t n = strlen(text);
    bool ok;
    if (!f)
        return false;
    ok = fwrite(text, 1, n, f) == n;
    return fclose(f) == 0 && ok;
}

static inline bool dbf_slurp(const char *path, char *out, size_t cap)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) {
        out[0] = '\0';
        return false;
    }
    n = fread(out, 1, cap - 1, f);
    (void)fclose(f);
    out[n] = '\0';
    return true;
}

static inline bool dbf_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

/* A fake program: the script text, mode 0755. */
static inline bool dbf_exec(const char *path, const char *text)
{
    return dbf_put(path, text) && chmod(path, 0755) == 0;
}

/* git -C dir -c identity ... ARGS (a NULL-terminated list). */
static inline bool dbf_git(const char *dir, const char *const *args)
{
    const char *argv[40];
    char out[4096];
    size_t n = 0, i;
    argv[n++] = "git";
    argv[n++] = "-C";
    argv[n++] = dir;
    argv[n++] = "-c";
    argv[n++] = "user.name=Batch Test";
    argv[n++] = "-c";
    argv[n++] = "user.email=batch@example.invalid";
    argv[n++] = "-c";
    argv[n++] = "commit.gpgsign=false";
    for (i = 0; args[i] && n + 1 < sizeof(argv) / sizeof(argv[0]); i++)
        argv[n++] = args[i];
    argv[n] = NULL;
    return zcl_spawn_capture(argv, out, sizeof(out), 60000) == 0;
}

static inline bool dbf_rev(const char *dir, const char *rev, char sha[41])
{
    const char *argv[] = {"git", "-C", dir, "rev-parse", rev, NULL};
    char out[256];
    if (zcl_spawn_capture(argv, out, sizeof(out), 30000) != 0 ||
        strlen(out) < 40)
        return false;
    memcpy(sha, out, 40);
    sha[40] = '\0';
    return true;
}

/* Commit `text` as `file` in `dir` (parents made). */
static inline bool dbf_commit_file(const char *dir, const char *file,
                                   const char *text)
{
    char path[1600], parent[1600];
    const char *add[] = {"add", "-A", NULL};
    const char *commit[] = {"commit", "-q", "-m", "change", NULL};
    char *slash;
    (void)snprintf(path, sizeof(path), "%s/%s", dir, file);
    (void)snprintf(parent, sizeof(parent), "%s", path);
    slash = strrchr(parent, '/');
    if (slash)
        *slash = '\0';
    return dbf_mkdirs(parent) && dbf_put(path, text) && dbf_git(dir, add) &&
           dbf_git(dir, commit);
}

/* A lab: HOME/development/{z23/{main,handoff/...},lanes/z23}, a bare origin
 * whose main holds a.c and a complexity baseline naming cx_old.c. */
static inline bool dbf_setup(struct dbf *f, const char *tag)
{
    char p[1600];
    const char *init[] = {"init", "-q", "--bare", "-b", "main", NULL};
    const char *push[] = {"push", "-q", "origin", "main", NULL};
    const char *branch[] = {"checkout", "-q", "-b", "main", NULL};
    test_make_tmpdir(f->root, sizeof(f->root), "dev_batch", tag);
    (void)snprintf(f->home, sizeof(f->home), "%s/home", f->root);
    (void)snprintf(f->state, sizeof(f->state), "%s/" DBF_HANDOFF, f->home);
    (void)snprintf(f->origin, sizeof(f->origin), "%s/origin.git", f->root);
    (void)snprintf(f->mainco, sizeof(f->mainco), "%s/development/z23/main",
                   f->home);
    (void)snprintf(f->fakes, sizeof(f->fakes), "%s/fakes", f->root);
    (void)snprintf(p, sizeof(p), "%s/development/lanes/z23", f->home);
    if (!dbf_mkdirs(f->state) || !dbf_mkdirs(p) || !dbf_mkdirs(f->fakes) ||
        !dbf_mkdirs(f->origin))
        return false;
    if (!dbf_git(f->origin, init))
        return false;
    {
        char seed[1000];
        const char *seed_init[] = {"init", "-q", NULL};
        (void)snprintf(seed, sizeof(seed), "%s/seed", f->root);
        if (!dbf_mkdirs(seed) || !dbf_git(seed, seed_init) ||
            !dbf_git(seed, branch))
            return false;
        (void)snprintf(p, sizeof(p), "%s/tools/lint", seed);
        if (!dbf_mkdirs(p))
            return false;
        (void)snprintf(p, sizeof(p), "%s/tools/lint/cyclomatic_complexity_baseline.txt",
                       seed);
        if (!dbf_put(p, "cx_old.c:old_fn:21\n") ||
            !dbf_commit_file(seed, "a.c", "int a;\n"))
            return false;
        {
            const char *remote[] = {"remote", "add", "origin", f->origin, NULL};
            if (!dbf_git(seed, remote) || !dbf_git(seed, push))
                return false;
        }
    }
    {
        const char *c[] = {"clone", "-q", f->origin, f->mainco, NULL};
        char par[900];
        (void)snprintf(par, sizeof(par), "%s/development/z23", f->home);
        return dbf_git(par, c);
    }
}

/* A lane clone of origin under HOME/development/lanes/z23/NAME with one
 * commit adding `file` (none when file is NULL); sha_out is its HEAD. */
static inline bool dbf_lane(const struct dbf *f, const char *name,
                            const char *file, char path_out[900],
                            char sha_out[41])
{
    char par[900];
    const char *c[] = {"clone", "-q", f->origin, path_out, NULL};
    (void)snprintf(par, sizeof(par), "%s/development/lanes/z23", f->home);
    (void)snprintf(path_out, 900, "%s/%s", par, name);
    if (!dbf_git(par, c))
        return false;
    if (file && !dbf_commit_file(path_out, file, "int x;\n"))
        return false;
    return dbf_rev(path_out, "HEAD", sha_out);
}

/* Run a handler on a fresh input holding home and any extra string pairs
 * (key, value, ..., NULL); the reply's data is dumped into `dump`. */
static inline void dbf_call(dbf_handler h, const struct dbf *f,
                            const char *const *pairs, const char *const *flags,
                            struct zcl_command_reply *reply, char *dump,
                            size_t cap)
{
    struct json_value input;
    struct zcl_command_context ctx;
    struct zcl_command_request request;
    size_t i;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "home", f->home);
    for (i = 0; pairs && pairs[i] && pairs[i + 1]; i += 2)
        (void)json_push_kv_str(&input, pairs[i], pairs[i + 1]);
    for (i = 0; flags && flags[i]; i++)
        (void)json_push_kv_bool(&input, flags[i], true);
    memset(&ctx, 0, sizeof(ctx));
    ctx.source_root = f->mainco;
    memset(&request, 0, sizeof(request));
    request.context = &ctx;
    request.input = &input;
    zcl_command_reply_init(reply, "zcl.test.dev_batch.v1");
    h(&request, reply);
    dump[0] = '\0';
    (void)json_write(&reply->data, dump, cap);
    json_free(&input);
}

#endif
