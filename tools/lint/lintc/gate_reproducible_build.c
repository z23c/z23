/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-reproducible-build — build the node binary TWICE in two
 * isolated build dirs under the shared release flag profile
 * (tools/scripts/repro_build_vars.sh, the file tools/release.sh also sources)
 * and assert the two artifacts are byte-identical (cmp is the verdict; the
 * SHA3-256 hash via openssl, or SHA-256 via sha256sum, is for reporting).
 * Ported from tools/scripts/check_reproducible_build.sh (deleted). Env knobs
 * kept: BINARY, KEEP, JOBS. Every child sees the environment from
 * rpb_child_env() (gate_reproducible_build_env.c). The selftest
 * (gate_reproducible_build_selftest.c) replaces the make step with a fixture
 * command through rpb_run_root().
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "lintc.h"
#include "lintc_text.h"
#include "gate_reproducible_build_priv.h"

extern char **environ;

void rpb_info(FILE *out, const char *msg)
{
    fprintf(out, "\033[36m[repro]\033[0m %s\n", msg);
    fflush(out);
}

void rpb_ok(FILE *out, const char *msg)
{
    fprintf(out, "\033[32m[repro]\033[0m %s\n", msg);
}

void rpb_err(const char *msg)
{
    fflush(stdout);
    fprintf(stderr, "\033[31m[repro] ERROR:\033[0m %s\n", msg);
}

static int rpb_which(const char *name)
{
    char full[RP_PATH];
    return rpb_resolve(name, full, sizeof full) == 0;
}

/* The child's output: stdout to our stderr (the build log), or captured in a
 * pipe read by the caller, with stderr merged into the pipe too (cmp's own
 * divergence wording goes to stderr at EOF). The program is resolved on the
 * forced PATH, not the caller's. */
static int rpb_start(char *const argv[], char *const envp[], int mode,
                     const int pfd[2], pid_t *pid)
{
    char prog[RP_PATH];
    if (rpb_resolve(argv[0], prog, sizeof prog) != 0)
        return 2;
    posix_spawn_file_actions_t fa;
    if (posix_spawn_file_actions_init(&fa))
        return 2;
    int rc;
    if (mode == RPB_OUT_STDERR) {
        rc = posix_spawn_file_actions_adddup2(&fa, 2, 1);
    } else {
        rc = posix_spawn_file_actions_adddup2(&fa, pfd[1], 1) ||
             posix_spawn_file_actions_addclose(&fa, pfd[0]);
        if (rc == 0 && mode == RPB_OUT_BOTH)
            rc = posix_spawn_file_actions_adddup2(&fa, pfd[1], 2);
    }
    if (rc == 0)
        rc = posix_spawn(pid, prog, &fa, NULL, argv, envp);
    posix_spawn_file_actions_destroy(&fa);
    return rc ? 2 : 0;
}

/* Copy stdout into out (NUL-terminated, truncated at cap) until EOF; bytes past
 * cap are still read so the child never blocks on a full pipe. */
/* Copy stdout into out (NUL-terminated, cap bytes at most) until EOF; bytes
 * past the buffer are still read so the child never blocks on a full pipe.
 * Returns 1 when any byte did not fit, so the caller can refuse the output. */
static int rpb_drain(int fd, char *out, size_t cap)
{
    char scratch[512];
    size_t got = 0;
    if (out && cap)
        out[0] = '\0';
    for (;;) {
        ssize_t r = read(fd, scratch, sizeof scratch);
        if (r < 0 && errno == EINTR)
            continue;
        if (r <= 0)
            break;
        for (ssize_t i = 0; i < r; i++, got++) {
            if (out && got + 1 < cap)
                out[got] = scratch[i];
        }
    }
    if (out && cap)
        out[got < cap ? got : cap - 1] = '\0';
    return cap ? got + 1 > cap : got > 0;
}

static int rpb_reap(pid_t pid, int *st)
{
    for (;;) {
        pid_t r = waitpid(pid, st, 0);
        if (r == pid)
            return 0;
        if (r < 0 && errno == EINTR)
            continue;
        return 2;
    }
}

static int rpb_status_code(int st)
{
    if (WIFEXITED(st))
        return WEXITSTATUS(st);
    if (WIFSIGNALED(st))
        return 128 + WTERMSIG(st);
    return 1;
}

/* Run argv under envp. mode says where stdout goes (see rpb_start). A captured
 * output that did not fit in out is an error (2), never a silent truncation. */
int rpb_spawn(char *const argv[], char *const envp[], int mode, char *out,
              size_t cap, int *code)
{
    int pfd[2] = { -1, -1 };
    pid_t pid;
    int st = 0;
    int piped = mode != RPB_OUT_STDERR;
    int truncated = 0;
    if (piped && pipe(pfd) != 0)
        return 2;
    if (rpb_start(argv, envp, mode, pfd, &pid)) {
        if (piped) {
            close(pfd[0]);
            close(pfd[1]);
        }
        return 2;
    }
    if (piped) {
        close(pfd[1]);
        truncated = rpb_drain(pfd[0], out, cap);
        close(pfd[0]);
    }
    if (rpb_reap(pid, &st))
        return 2;
    if (truncated)
        return 2;
    *code = rpb_status_code(st);
    return 0;
}

/* A positive decimal count, optionally followed by one newline (nproc). */
static int rpb_positive(const char *s, int *out)
{
    long v = 0;
    const char *p = s;
    if (*p < '0' || *p > '9')
        return 0;
    for (; *p >= '0' && *p <= '9'; p++) {
        v = v * 10 + (*p - '0');
        if (v > 4096)
            return 0;
    }
    if (*p == '\n')
        p++;
    if (*p || v <= 0)
        return 0;
    *out = (int)v;
    return 1;
}

/* JOBS (as the shell script read it) or nproc, defaulting to 4. */
static int rpb_jobs(char *const envp[], int *jobs)
{
    const char *env = getenv("JOBS");
    if (env && env[0])
        return rpb_positive(env, jobs) ? 0 : 1;
    char buf[32];
    int code;
    char *argv[] = { (char *)"nproc", NULL };
    if (rpb_spawn(argv, envp, RPB_OUT_PIPE, buf, sizeof buf, &code) == 0 &&
        code == 0 && rpb_positive(buf, jobs))
        return 0;
    *jobs = 4;
    return 0;
}

static int rpb_pick_hash(char *const envp[], char *tool, char *algo)
{
    char *argv[] = { (char *)"openssl", (char *)"dgst", (char *)"-sha3-256",
                     (char *)"/dev/null", NULL };
    char buf[256];
    int code;
    if (rpb_spawn(argv, envp, RPB_OUT_PIPE, buf, sizeof buf, &code) == 0 &&
        code == 0) {
        strcpy(tool, "openssl");
        strcpy(algo, "SHA3-256");
        return 0;
    }
    if (rpb_which("sha256sum")) {
        strcpy(tool, "sha256sum");
        strcpy(algo, "SHA-256");
        return 0;
    }
    return 1;
}

static int rpb_precheck(char *const envp[], char *tool, char *algo)
{
    static const char *const need[] = { "make", "git", "cmp" };
    for (size_t i = 0; i < sizeof need / sizeof need[0]; i++) {
        if (!rpb_which(need[i])) {
            char m[128];
            if (ovf(snprintf(m, sizeof m, "%s not found on PATH", need[i]),
                     sizeof m))
                return 2;
            rpb_err(m);
            return 1;
        }
    }
    if (rpb_pick_hash(envp, tool, algo)) {
        rpb_err("neither 'openssl dgst -sha3-256' nor 'sha256sum' is available");
        return 1;
    }
    return 0;
}

static int rpb_store_field(struct rpb_vars *v, const char *key, const char *val)
{
    if (!strcmp(key, "SOURCE_DATE_EPOCH"))
        return ovf(snprintf(v->sde, sizeof v->sde, "%s", val), sizeof v->sde);
    if (!strcmp(key, "REL_CFLAGS"))
        return ovf(snprintf(v->cflags, sizeof v->cflags, "%s", val),
                   sizeof v->cflags);
    if (!strcmp(key, "REL_LDFLAGS"))
        return ovf(snprintf(v->ldflags, sizeof v->ldflags, "%s", val),
                   sizeof v->ldflags);
    return 0;
}

static int rpb_vars_parse(struct rpb_vars *v, char *buf);

/* Parse the loader's capture into v, the release profile the gate builds
 * with. 0 when CFLAGS and LDFLAGS are both resolved; 1 when either is empty;
 * 3 when either still holds an unresolved Make expression ("$("), which the
 * shell gate refused; 2 on a malformed capture. Pure: no spawn, no env. */
int rpb_profile_parse(char *buf, struct rpb_vars *v)
{
    if (rpb_vars_parse(v, buf))
        return 2;
    if (!v->cflags[0] || !v->ldflags[0])
        return 1;
    if (strstr(v->cflags, "$(") || strstr(v->ldflags, "$("))
        return 3;
    return 0;
}

/* The record bit of a loader key: all three must appear once each. */
static int rpb_key_bit(const char *key)
{
    if (!strcmp(key, "SOURCE_DATE_EPOCH"))
        return 1;
    if (!strcmp(key, "REL_CFLAGS"))
        return 2;
    if (!strcmp(key, "REL_LDFLAGS"))
        return 4;
    return 0;
}

/* The capture must end with the record separator (a cut-off tail is refused),
 * and every record is key=value. */
static int rpb_vars_parse(struct rpb_vars *v, char *buf)
{
    memset(v, 0, sizeof *v);
    size_t n = strlen(buf);
    if (n == 0 || buf[n - 1] != '\036')
        return 2;
    int seen = 0;
    char *tok = buf;
    while (tok < buf + n) {
        char *sep = strchr(tok, '\036');
        *sep = '\0';
        char *eq = strchr(tok, '=');
        if (!eq)
            return 2;
        *eq = '\0';
        int bit = rpb_key_bit(tok);
        if (bit && (seen & bit))
            return 2;
        if (rpb_store_field(v, tok, eq + 1))
            return 2;
        seen |= bit;
        tok = sep + 1;
    }
    return seen == 7 ? 0 : 2;
}

/* Write <work>/loadvars.sh, which sources the shared profile in bash and
 * prints its three values separated by record separators. */
static int rpb_write_loader(const char *varsfile, const char *emit)
{
    FILE *f = fopen(emit, "w");
    if (!f)
        return 2;
    int pr = fprintf(f,
        "#!/usr/bin/env bash\nset -euo pipefail\n. '%s'\n"
        "printf 'SOURCE_DATE_EPOCH=%%s\\036REL_CFLAGS=%%s\\036"
        "REL_LDFLAGS=%%s\\036' \"$SOURCE_DATE_EPOCH\" "
        "\"$REL_CFLAGS\" \"$REL_LDFLAGS\"\n", varsfile);
    if (pr < 0 || fclose(f) != 0)
        return 2;
    return 0;
}

static int rpb_load_vars(char *const envp[], const char *root, const char *work,
                         struct rpb_vars *v)
{
    char varsfile[RP_PATH], emit[RP_PATH];
    if (ovf(snprintf(varsfile, sizeof varsfile,
                     "%s/tools/scripts/repro_build_vars.sh", root),
             sizeof varsfile))
        return 2;
    if (strchr(varsfile, '\''))
        return 2;
    if (ovf(snprintf(emit, sizeof emit, "%s/loadvars.sh", work), sizeof emit))
        return 2;
    if (rpb_write_loader(varsfile, emit))
        return 2;
    char *argv[] = { (char *)"bash", emit, NULL };
    char buf[RP_LOAD];
    int code;
    if (rpb_spawn(argv, envp, RPB_OUT_PIPE, buf, sizeof buf, &code))
        return 2;
    if (code != 0) {
        rpb_err("sourcing repro_build_vars.sh failed");
        return 1;
    }
    int pr = rpb_profile_parse(buf, v);
    if (pr == 2)
        return 2;
    if (pr == 1) {
        rpb_err(v->cflags[0]
                    ? "REL_LDFLAGS resolved empty \342\200\224 "
                      "repro_build_vars.sh failed"
                    : "REL_CFLAGS resolved empty \342\200\224 "
                      "repro_build_vars.sh failed");
        return 1;
    }
    if (pr == 3) {
        rpb_err("release profile retained an unresolved Make expression");
        return 1;
    }
    return 0;
}

/* The make (or selftest fixture) argv for one build; argv has room for 7. */
static int rpb_make_argv(char *argv[8], char args[4][RP_ARG],
                         const char *bdir, const char *binary,
                         const char *buildcmd, const struct rpb_vars *v,
                         int jobs)
{
    if (buildcmd) {
        argv[0] = (char *)buildcmd;
        argv[1] = (char *)bdir;
        argv[2] = (char *)binary;
        argv[3] = NULL;
        return 0;
    }
    if (ovf(snprintf(args[0], RP_ARG, "-j%d", jobs), RP_ARG) ||
        ovf(snprintf(args[1], RP_ARG, "BUILD_DIR=%s", bdir), RP_ARG) ||
        ovf(snprintf(args[2], RP_ARG, "CFLAGS=%s", v->cflags), RP_ARG) ||
        ovf(snprintf(args[3], RP_ARG, "LDFLAGS=%s", v->ldflags), RP_ARG))
        return 2;
    argv[0] = (char *)"make";
    argv[1] = args[0];
    argv[2] = args[1];
    argv[3] = args[2];
    argv[4] = args[3];
    argv[5] = (char *)binary;
    argv[6] = NULL;
    return 0;
}

static int rpb_build_once(char *const envp[], FILE *out, const char *label,
                          const char *bdir, const char *binary,
                          const char *buildcmd, const struct rpb_vars *v,
                          int jobs)
{
    char line[RP_PATH], m[RP_PATH], bin[RP_PATH];
    char args[4][RP_ARG];
    char *argv[8];
    if (ovf(snprintf(line, sizeof line,
                     "\342\224\200\342\224\200 Build %s: BUILD_DIR=%s "
                     "\342\224\200\342\224\200", label, bdir), sizeof line))
        return 2;
    rpb_info(out, line);
    if (rpb_make_argv(argv, args, bdir, binary, buildcmd, v, jobs))
        return 2;
    time_t t0 = time(NULL);
    int code;
    if (rpb_spawn(argv, envp, RPB_OUT_STDERR, NULL, 0, &code))
        return 2;
    if (code != 0) {
        if (ovf(snprintf(m, sizeof m, "Build %s failed (see stderr above)",
                         label), sizeof m))
            return 2;
        rpb_err(m);
        return 1;
    }
    if (ovf(snprintf(bin, sizeof bin, "%s/bin/%s", bdir, binary), sizeof bin))
        return 2;
    struct stat sb;
    if (stat(bin, &sb) != 0) {
        if (ovf(snprintf(m, sizeof m,
                         "Build %s finished but %s/bin/%s not found", label,
                         bdir, binary), sizeof m))
            return 2;
        rpb_err(m);
        return 1;
    }
    if (ovf(snprintf(m, sizeof m, "Build %s done in %llds (%lld bytes)", label,
                     (long long)(time(NULL) - t0), (long long)sb.st_size),
             sizeof m))
        return 2;
    rpb_info(out, m);
    return 0;
}

/* Hash <path>: openssl prints "SHA3-256(path)= hash" (last field); sha256sum
 * prints "hash  path" (first field). */
static int rpb_hash(char *const envp[], const char *tool, const char *path,
                    char *out, size_t cap)
{
    char buf[1024];
    char *argv_o[] = { (char *)"openssl", (char *)"dgst", (char *)"-sha3-256",
                       (char *)path, NULL };
    char *argv_s[] = { (char *)"sha256sum", (char *)path, NULL };
    int ossl = !strcmp(tool, "openssl");
    char *const *argv = ossl ? argv_o : argv_s;
    int code;
    if (rpb_spawn(argv, envp, RPB_OUT_PIPE, buf, sizeof buf, &code) || code != 0)
        return 2;
    size_t n = strlen(buf);
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
                     buf[n - 1] == ' '))
        buf[--n] = '\0';
    if (ossl) {
        const char *last = strrchr(buf, ' ');
        return ovf(snprintf(out, cap, "%s", last ? last + 1 : buf), cap) ? 2 : 0;
    }
    return ovf(snprintf(out, cap, "%.*s", (int)strcspn(buf, " "), buf), cap)
        ? 2 : 0;
}

static long rpb_size(const char *path)
{
    struct stat sb;
    return stat(path, &sb) == 0 ? (long)sb.st_size : -1;
}

/* Byte-compare a and b: 0 when identical, 1 when they differ, 2 on an I/O
 * error. The divergence wording comes from cmp itself (rpb_diag). */
/* Byte-compare a and b: 0 when identical, 1 when they differ, 2 on an I/O
 * error (a read that fails is never taken for end of file). The divergence
 * wording comes from cmp itself (rpb_diag). */
int rpb_cmp_files(const char *a, const char *b)
{
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    if (!fa || !fb) {
        if (fa)
            fclose(fa);
        if (fb)
            fclose(fb);
        return 2;
    }
    char ba[65536], bb[65536];
    int rc = 0;
    for (;;) {
        size_t na = fread(ba, 1, sizeof ba, fa);
        size_t nb = fread(bb, 1, sizeof bb, fb);
        if (ferror(fa) || ferror(fb)) {
            rc = 2;
            break;
        }
        if (na != nb || memcmp(ba, bb, na) != 0) {
            rc = 1;
            break;
        }
        if (na == 0)
            break;
    }
    fclose(fa);
    fclose(fb);
    return rc;
}

static int rpb_build_line(FILE *out, const char *label, const char *algo,
                          const char *hash, long size)
{
    char m[RP_PATH + 96];
    if (ovf(snprintf(m, sizeof m, "%s: %s=%s  size=%ld", label, algo, hash,
                     size), sizeof m))
        return 2;
    rpb_info(out, m);
    return 0;
}

static int rpb_identical(FILE *out, const char *binary, const char *algo,
                         const char *hash, long size)
{
    char m[RP_PATH + 96];
    if (ovf(snprintf(m, sizeof m, "BYTE-IDENTICAL: two independent builds of "
                     "'%s' match exactly.", binary), sizeof m))
        return 2;
    rpb_ok(out, m);
    fprintf(out, "\n  %s : %s\n  size       : %ld bytes\n"
            "  This is the project's first build-twice reproducibility "
            "proof.\n", algo, hash, size);
    return 0;
}

/* Returns 0 when identical, 1 on a mismatch (diagnosis on stderr), 2 on error.
 * *mismatch is set on the mismatch path so KEEP can name it. */
static int rpb_verdict(char *const envp[], FILE *out, const char *ba,
                       const char *bb, const char *binary, const char *tool,
                       const char *algo, const char *work, int *mismatch)
{
    char ha[RP_HASH] = "", hb[RP_HASH] = "";
    if (rpb_hash(envp, tool, ba, ha, sizeof ha) ||
        rpb_hash(envp, tool, bb, hb, sizeof hb))
        return 2;
    long sa = rpb_size(ba), sb = rpb_size(bb);
    if (sa < 0 || sb < 0)
        return 2;
    if (rpb_build_line(out, "Build A", algo, ha, sa) ||
        rpb_build_line(out, "Build B", algo, hb, sb))
        return 2;
    int c = rpb_cmp_files(ba, bb);
    if (c == 2)
        return 2;
    if (c == 0 && strcmp(ha, hb) == 0)
        return rpb_identical(out, binary, algo, ha, sa) ? 2 : 0;
    *mismatch = 1;
    return rpb_diag(stderr, envp, ba, bb, ha, hb, algo, binary, sa, sb, work)
        ? 2 : 1;
}

static int rpb_banner(FILE *out, const char *binary, const char *algo,
                      const struct rpb_vars *v)
{
    char m[RP_PATH + 96];
    if (ovf(snprintf(m, sizeof m, "Binary target : %s", binary), sizeof m))
        return 2;
    rpb_info(out, m);
    if (ovf(snprintf(m, sizeof m, "Hash algorithm: %s", algo), sizeof m))
        return 2;
    rpb_info(out, m);
    rpb_info(out, "Network policy: vendor-offline (forced)");
    if (ovf(snprintf(m, sizeof m, "SOURCE_DATE_EPOCH=%s (pinned across both "
                     "builds)", v->sde), sizeof m))
        return 2;
    rpb_info(out, m);
    if (ovf(snprintf(m, sizeof m, "CFLAGS         : %s", v->cflags), sizeof m))
        return 2;
    rpb_info(out, m);
    if (ovf(snprintf(m, sizeof m, "LDFLAGS        : %s", v->ldflags), sizeof m))
        return 2;
    rpb_info(out, m);
    return 0;
}

struct rpb_job {
    const char *work;
    const char *binary;
    const char *buildcmd;
    const char *tool;
    const char *algo;
};

static int rpb_flow(char *const envp[], FILE *out, const struct rpb_job *j,
                    const struct rpb_vars *v, int *mismatch)
{
    char bdir_a[RP_PATH], bdir_b[RP_PATH], ba[RP_PATH], bb[RP_PATH];
    if (ovf(snprintf(bdir_a, sizeof bdir_a, "%s/build_a", j->work),
             sizeof bdir_a) ||
        ovf(snprintf(bdir_b, sizeof bdir_b, "%s/build_b", j->work),
             sizeof bdir_b) ||
        ovf(snprintf(ba, sizeof ba, "%s/bin/%s", bdir_a, j->binary),
             sizeof ba) ||
        ovf(snprintf(bb, sizeof bb, "%s/bin/%s", bdir_b, j->binary),
             sizeof bb))
        return 2;
    int jobs = 0;
    if (rpb_jobs(envp, &jobs) || rpb_banner(out, j->binary, j->algo, v))
        return 2;
    int rc = rpb_build_once(envp, out, "A", bdir_a, j->binary, j->buildcmd, v,
                            jobs);
    if (rc == 0)
        rc = rpb_build_once(envp, out, "B", bdir_b, j->binary, j->buildcmd, v,
                            jobs);
    if (rc)
        return rc;
    return rpb_verdict(envp, out, ba, bb, j->binary, j->tool, j->algo, j->work,
                       mismatch);
}

/* Remove the build dirs unless KEEP=1 keeps them for forensics: a failed build
 * or a mismatch keeps them (named on stdout); success always removes them. */
static int rpb_cleanup(FILE *out, const char *work, int keep, int rc,
                       int mismatch)
{
    if (!work[0])
        return rc;
    if (keep && rc != 0) {
        char m[RP_PATH + 96];
        if (ovf(snprintf(m, sizeof m, mismatch
                         ? "KEEP=1: retaining build dirs at %s (remove "
                           "manually when done)"
                         : "KEEP=1: leaving build dirs at %s for forensics",
                         work), sizeof m))
            return 2;
        rpb_info(out, m);
        return rc;
    }
    if (rap_rm_rf(work)) {
        rpb_err("could not remove the build dirs");
        return rc ? rc : 2;
    }
    return rc;
}

static int rpb_setup(const char *root)
{
    umask(022);
    if (chdir(root) != 0) {
        fprintf(stderr, "z23-lint: cannot chdir to %s\n", root);
        return 2;
    }
    return 0;
}

int rpb_run_root(const char *root, FILE *out, const char *buildcmd)
{
    if (rpb_setup(root))
        return 2;
    struct rpb_env env;
    if (rpb_child_env(environ, &env))
        return 2;
    char *const *envp = env.ptr;
    struct rpb_job job = { .work = "", .binary = env_or("BINARY", "zclassic23"),
                           .buildcmd = buildcmd, .tool = "", .algo = "" };
    int keep = strcmp(env_or("KEEP", "0"), "1") == 0;
    char tool[16] = "", algo[16] = "", work[RP_PATH] = "";
    struct rpb_vars v;
    int mismatch = 0;
    int rc = rpb_precheck(envp, tool, algo);
    if (!rc && lct_scratch_dir(work, sizeof work, "zcl-repro")) {
        work[0] = '\0';
        rc = 2;
    }
    job.work = work;
    job.tool = tool;
    job.algo = algo;
    if (!rc)
        rc = rpb_load_vars(envp, root, work, &v);
    if (!rc)
        rc = rpb_flow(envp, out, &job, &v, &mismatch);
    return rpb_cleanup(out, work, keep, rc, mismatch);
}

int check_reproducible_build_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char root[4096];
    if (cic_repo_root(root, sizeof root))
        return 2;
    return rpb_run_root(root, stdout, NULL);
}
