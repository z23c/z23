/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The campaign core: turn a list of mutation sites into a mutation score.
 *
 * THE COST MODEL, because it is the whole design. Naively one mutant means
 * one build and one test run, and a build of this tree is minutes. Four
 * decisions bring one mutant to a few seconds:
 *
 *   1. The mutant is compiled from a SCRATCH COPY of the translation unit,
 *      never by editing the checkout. That is a safety property first — the
 *      target file is never opened for writing on any path, so no interrupt
 *      can leave it truncated — but it is also the speed property: the
 *      shared object tree, its epoch, its session lease and the
 *      source-identity stamp are all left alone, so `make` never has to
 *      re-derive them. A `#line` directive at the top of the copy keeps
 *      __FILE__ and __LINE__ exactly what they were.
 *
 *   2. `make` runs ONCE per campaign, as `make -n`, only to learn the exact
 *      compile and link argv. Per mutant the harness runs those two commands
 *      itself. Measured on this tree: `make` needs 26s for a one-file
 *      incremental rebuild of test_parallel, of which 13s is its no-op
 *      dependency scan over ~3,000 objects; the direct compile plus link is
 *      4.5s for the same result.
 *
 *   3. Only the ONE affected group runs, through `--exact=`, not the suite.
 *      One group here is 66ms against 200-plus seconds for the suite.
 *
 *   4. A (mutant, group) pair is cached by content, keyed on the source
 *      digest, the site, the compiler argv AND the baseline binary — so any
 *      change anywhere in the link closure misses the cache rather than
 *      answering from a stale tree.
 *
 * The baseline is never cached and never skipped. A mutation score measured
 * against a red or non-executing group is worse than no number at all.
 */

#include "mutation_harness.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "command/native_devagent.h"
#include "platform/clock.h"
#include "platform/directory_compat.h"
#include "platform/path_compat.h"
#include "sha3/sha3.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <poll.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/wait.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define MUT_READ_MAX (256u * 1024u * 1024u)

const char *zcl_mut_outcome_name(enum zcl_mut_outcome o)
{
    switch (o) {
    case ZCL_MUT_OUTCOME_KILLED:     return "KILLED";
    case ZCL_MUT_OUTCOME_SURVIVED:   return "SURVIVED";
    case ZCL_MUT_OUTCOME_STILLBORN:  return "STILLBORN";
    case ZCL_MUT_OUTCOME_EQUIVALENT: return "EQUIVALENT";
    case ZCL_MUT_OUTCOME_ERROR:      return "ERROR";
    case ZCL_MUT_OUTCOME_COUNT:
    default:                         return "UNKNOWN";
    }
}

/* ── files and digests ──────────────────────────────────────────────── */

char *zcl_mut_read_file(const char *path, size_t *len_out)
{
    if (len_out)
        *len_out = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        (void)fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0 || (unsigned long)size > MUT_READ_MAX ||
        fseek(f, 0, SEEK_SET) != 0) {
        (void)fclose(f);
        return NULL;
    }
    char *buf = zcl_malloc((size_t)size + 1, "mutation.file");
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)size, f);
    (void)fclose(f);
    if (got != (size_t)size) {
        free(buf);
        return NULL;
    }
    buf[size] = '\0';
    if (len_out)
        *len_out = (size_t)size;
    return buf;
}

bool zcl_mut_write_file(const char *path, const char *bytes, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "mutation: cannot write %s: %s\n", path,
                strerror(errno));
        return false;
    }
    bool ok = len == 0 || fwrite(bytes, 1, len, f) == len;
    if (fclose(f) != 0)
        ok = false; /* a write that fails only at close is still a failure */
    if (!ok)
        fprintf(stderr, "mutation: short write to %s\n", path);
    return ok;
}

void zcl_mut_digest_hex(const void *bytes, size_t len, char *hex)
{
    unsigned char d[32];
    zcl_sha3_256((const unsigned char *)bytes, len, d);
    zcl_hex_encode(d, sizeof d, hex);
}

static long long mut_now_ms(void)
{
    return clock_now_monotonic_ns() / 1000000;
}

/* ── bounded spawn ──────────────────────────────────────────────────── */

int zcl_mut_spawn(const char *dir, char *const argv[], int timeout_ms,
                  char **out, size_t *out_len)
{
    if (out)
        *out = NULL;
    if (out_len)
        *out_len = 0;
#if defined(_WIN32)
    /* CreateProcess + PeekNamedPipe capture: no fork/execvp on this lane.
     * lpCurrentDirectory plays the child-side chdir; TerminateProcess is
     * the SIGKILL analogue; rc stays -2 on timeout, else the exit code. */
    if (!argv || !argv[0]) {
        fprintf(stderr, "mutation: empty argv\n");
        return -1;
    }
    char cmd[8192];
    size_t used = 0;
    cmd[0] = '\0';
    for (size_t i = 0; argv[i]; i++) {
        if (i > 0 && used + 1 < sizeof(cmd))
            cmd[used++] = ' ';
        cmd[used] = '\0';
        const char *a = argv[i];
        bool quote = strchr(a, ' ') != NULL || strchr(a, '\t') != NULL ||
                     a[0] == '\0';
        size_t alen = strlen(a);
        if (used + alen + 3 >= sizeof(cmd)) {
            fprintf(stderr, "mutation: command line too long\n");
            return -1;
        }
        if (quote)
            cmd[used++] = '"';
        memcpy(cmd + used, a, alen);
        used += alen;
        if (quote)
            cmd[used++] = '"';
        cmd[used] = '\0';
    }

    SECURITY_ATTRIBUTES sa;
    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) {
        fprintf(stderr, "mutation: CreatePipe failed (%lu)\n",
                (unsigned long)GetLastError());
        return -1;
    }
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = wr;
    si.hStdError = wr;
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, dir,
                        &si, &pi)) {
        fprintf(stderr, "mutation: CreateProcess(%s) failed (%lu)\n",
                argv[0], (unsigned long)GetLastError());
        CloseHandle(rd);
        CloseHandle(wr);
        return -1;
    }
    CloseHandle(pi.hThread);
    CloseHandle(wr); /* ours must close so the read end sees EOF */

    size_t cap = 65536, len = 0;
    char *buf = zcl_malloc(cap, "mutation.capture");
    if (!buf) {
        CloseHandle(rd);
        TerminateProcess(pi.hProcess, 137);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        return -1;
    }
    long long deadline = mut_now_ms() + (timeout_ms > 0 ? timeout_ms : 600000);
    bool timed_out = false;
    for (;;) {
        long long left = deadline - mut_now_ms();
        if (left <= 0) {
            timed_out = true;
            break;
        }
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL))
            break; /* child hung up */
        if (avail == 0) {
            if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0)
                break;
            Sleep(10);
            continue;
        }
        if (len + 8192 > cap) {
            size_t ncap = cap * 2;
            char *nb = zcl_realloc(buf, ncap, "mutation.capture");
            if (!nb)
                break;
            buf = nb;
            cap = ncap;
        }
        DWORD want = (DWORD)(cap - len - 1);
        if (want > avail)
            want = avail;
        DWORD got = 0;
        if (!ReadFile(rd, buf + len, want, &got, NULL) || got == 0)
            break;
        len += (size_t)got;
    }
    buf[len] = '\0';
    CloseHandle(rd);

    int rc;
    if (timed_out) {
        TerminateProcess(pi.hProcess, 137);
        WaitForSingleObject(pi.hProcess, INFINITE);
        rc = -2;
    } else {
        WaitForSingleObject(pi.hProcess, INFINITE);
        DWORD code = 0;
        if (!GetExitCodeProcess(pi.hProcess, &code))
            code = (DWORD)-1;
        rc = (int)code;
    }
    CloseHandle(pi.hProcess);
    if (out) {
        *out = buf;
        if (out_len)
            *out_len = len;
    } else {
        free(buf);
    }
    return rc;
#else
    int fds[2];
    if (pipe(fds) != 0) {
        fprintf(stderr, "mutation: pipe failed: %s\n", strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        (void)close(fds[0]);
        (void)close(fds[1]);
        fprintf(stderr, "mutation: fork failed: %s\n", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* test_parallel needs an unlimited stack for the deep-recursion
         * groups; a child that inherits 8 MiB SIGSEGVs and would be scored
         * as a kill the mutant did not earn. */
        struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
        (void)setrlimit(RLIMIT_STACK, &rl);
        if (dir && chdir(dir) != 0)
            _exit(127);
        (void)close(fds[0]);
        if (dup2(fds[1], STDOUT_FILENO) < 0 || dup2(fds[1], STDERR_FILENO) < 0)
            _exit(127);
        (void)close(fds[1]);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            (void)dup2(devnull, STDIN_FILENO);
            (void)close(devnull);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    (void)close(fds[1]);

    size_t cap = 65536, len = 0;
    char *buf = zcl_malloc(cap, "mutation.capture");
    if (!buf) {
        (void)close(fds[0]);
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, NULL, 0);
        return -1;
    }
    long long deadline = mut_now_ms() + (timeout_ms > 0 ? timeout_ms : 600000);
    bool timed_out = false;
    for (;;) {
        long long left = deadline - mut_now_ms();
        if (left <= 0) {
            timed_out = true;
            break;
        }
        struct pollfd p = { .fd = fds[0], .events = POLLIN, .revents = 0 };
        int pr = poll(&p, 1, left > 1000 ? 1000 : (int)left);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (pr == 0)
            continue;
        if (len + 8192 > cap) {
            size_t ncap = cap * 2;
            char *nb = zcl_realloc(buf, ncap, "mutation.capture");
            if (!nb)
                break;
            buf = nb;
            cap = ncap;
        }
        ssize_t got = read(fds[0], buf + len, cap - len - 1);
        if (got < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (got == 0)
            break;
        len += (size_t)got;
    }
    buf[len] = '\0';
    (void)close(fds[0]);

    int status = 0, rc;
    if (timed_out) {
        (void)kill(pid, SIGKILL);
        (void)waitpid(pid, &status, 0);
        rc = -2;
    } else {
        while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
            ;
        if (WIFSIGNALED(status))
            rc = 128 + WTERMSIG(status);
        else
            rc = WEXITSTATUS(status);
    }
    if (out) {
        *out = buf;
        if (out_len)
            *out_len = len;
    } else {
        free(buf);
    }
    return rc;
#endif
}

/* ── shell word splitting ───────────────────────────────────────────── */

void zcl_mut_argv_free(struct zcl_mut_argv *a)
{
    if (!a)
        return;
    for (size_t i = 0; i < a->count; i++)
        free(a->argv[i]);
    memset(a, 0, sizeof *a);
}

static bool mut_argv_push(struct zcl_mut_argv *a, const char *word, size_t n)
{
    if (a->count >= ZCL_MUT_ARGV_MAX)
        return false;
    char *copy = zcl_malloc(n + 1, "mutation.word");
    if (!copy)
        return false;
    memcpy(copy, word, n);
    copy[n] = '\0';
    a->argv[a->count++] = copy;
    a->argv[a->count] = NULL;
    return true;
}

bool zcl_mut_shell_split(const char *cmd, struct zcl_mut_argv *out)
{
    if (!cmd || !out)
        return false;
    memset(out, 0, sizeof *out);
    char word[8192];
    size_t wn = 0;
    bool in_word = false;
    for (const char *p = cmd;; p++) {
        char c = *p;
        if (c == '\0' || ((c == ' ' || c == '\t' || c == '\n') && true)) {
            if (in_word) {
                if (!mut_argv_push(out, word, wn)) {
                    zcl_mut_argv_free(out);
                    return false;
                }
                wn = 0;
                in_word = false;
            }
            if (c == '\0')
                break;
            continue;
        }
        if (c == '\'' || c == '"') {
            char q = c;
            in_word = true;
            for (p++; *p && *p != q; p++) {
                /* No expansion: a `$tmp` inside quotes stays four literal
                 * characters so the caller can recognise the placeholder. */
                if (q == '"' && *p == '\\' && p[1])
                    p++;
                if (wn + 1 < sizeof word)
                    word[wn++] = *p;
            }
            if (*p != q) {
                zcl_mut_argv_free(out);
                return false; /* unterminated quote: never guess */
            }
            continue;
        }
        if (c == '\\' && p[1]) {
            p++;
            c = *p;
        }
        in_word = true;
        if (wn + 1 < sizeof word)
            word[wn++] = c;
    }
    return out->count > 0;
}

/* ── recovering the build plan from `make -n` ───────────────────────── */

void zcl_mut_plan_free(struct zcl_mut_plan *p)
{
    if (!p)
        return;
    zcl_mut_argv_free(&p->compile);
    zcl_mut_argv_free(&p->link);
    memset(p, 0, sizeof *p);
}

/* Join `\`-continued recipe lines, then split on unquoted `;` so each
 * sub-command of a compound recipe can be inspected on its own. Returns a
 * fresh NUL-separated list terminated by an empty segment. */
static char *mut_segments(const char *text, size_t len)
{
    char *buf = zcl_malloc(len + 2, "mutation.segments");
    if (!buf)
        return NULL;
    size_t o = 0;
    char quote = '\0';
    for (size_t i = 0; i < len; i++) {
        char c = text[i];
        if (c == '\\' && i + 1 < len && text[i + 1] == '\n') {
            buf[o++] = ' ';
            i++;
            continue;
        }
        if (quote) {
            if (c == quote)
                quote = '\0';
            buf[o++] = c;
            continue;
        }
        if (c == '\'' || c == '"') {
            quote = c;
            buf[o++] = c;
            continue;
        }
        if (c == ';' || c == '\n') {
            buf[o++] = '\0';
            continue;
        }
        buf[o++] = c;
    }
    buf[o++] = '\0';
    buf[o] = '\0';
    return buf;
}

static bool mut_seg_has(const char *seg, const char *needle)
{
    return strstr(seg, needle) != NULL;
}

/* The compile recipe is `compile-epoch-object.sh dep "OBJ" "SRC" ... --
 * COMPILER FLAGS...`; the wrapper then appends -MMD -MP -c -o OBJ SRC. Only
 * the tail after ` -- ` is wanted, because the harness supplies its own -c
 * -o and its own scratch source. */
static bool mut_plan_compile(const char *seg, const char *src_rel,
                             struct zcl_mut_plan *out)
{
    struct zcl_mut_argv all;
    if (!zcl_mut_shell_split(seg, &all))
        return false;
    size_t dash = 0;
    bool found = false;
    for (size_t i = 0; i < all.count; i++) {
        if (strcmp(all.argv[i], "--") == 0) {
            dash = i;
            found = true;
            break;
        }
    }
    if (!found || dash + 1 >= all.count) {
        zcl_mut_argv_free(&all);
        return false;
    }
    /* The object is the first argument that ends in `.o`. */
    out->object[0] = '\0';
    for (size_t i = 0; i < dash; i++) {
        size_t n = strlen(all.argv[i]);
        if (n > 2 && strcmp(all.argv[i] + n - 2, ".o") == 0) {
            (void)snprintf(out->object, sizeof out->object, "%s", all.argv[i]);
            break;
        }
    }
    (void)src_rel;
    if (out->object[0] == '\0') {
        zcl_mut_argv_free(&all);
        return false;
    }
    memset(&out->compile, 0, sizeof out->compile);
    for (size_t i = dash + 1; i < all.count; i++) {
        if (!mut_argv_push(&out->compile, all.argv[i], strlen(all.argv[i]))) {
            zcl_mut_argv_free(&all);
            zcl_mut_argv_free(&out->compile);
            return false;
        }
    }
    zcl_mut_argv_free(&all);
    return out->compile.count > 0;
}

/* The link recipe names the response file and writes through a mktemp
 * target. Both are replaced with placeholders the campaign fills in, so the
 * harness links its own binary from its own object list and never touches
 * the build tree's candidate. */
static bool mut_plan_link(const char *seg, struct zcl_mut_plan *out)
{
    struct zcl_mut_argv all;
    if (!zcl_mut_shell_split(seg, &all))
        return false;
    memset(&out->link, 0, sizeof out->link);
    out->rsp[0] = '\0';
    bool have_out = false, have_rsp = false;
    for (size_t i = 0; i < all.count; i++) {
        const char *w = all.argv[i];
        if (strcmp(w, "-o") == 0 && i + 1 < all.count) {
            if (!mut_argv_push(&out->link, "-o", 2) ||
                !mut_argv_push(&out->link, "%OUT%", 5))
                goto fail;
            i++;
            have_out = true;
            continue;
        }
        if (w[0] == '@' && strstr(w, ".rsp") != NULL) {
            (void)snprintf(out->rsp, sizeof out->rsp, "%s", w + 1);
            if (!mut_argv_push(&out->link, "%RSP%", 5))
                goto fail;
            have_rsp = true;
            continue;
        }
        if (!mut_argv_push(&out->link, w, strlen(w)))
            goto fail;
    }
    zcl_mut_argv_free(&all);
    if (!have_out || !have_rsp) {
        zcl_mut_argv_free(&out->link);
        return false;
    }
    return true;
fail:
    zcl_mut_argv_free(&all);
    zcl_mut_argv_free(&out->link);
    return false;
}

bool zcl_mut_plan_from_dryrun(const char *text, const char *src_rel,
                              struct zcl_mut_plan *out, char *err,
                              size_t err_cap)
{
    if (err && err_cap)
        err[0] = '\0';
    if (out)
        memset(out, 0, sizeof *out);
    if (!text || !src_rel || !out)
        return false;
    char *segs = mut_segments(text, strlen(text));
    if (!segs) {
        if (err)
            (void)snprintf(err, err_cap, "out of memory splitting the recipe");
        return false;
    }
    bool have_compile = false, have_link = false;
    for (const char *s = segs; *s; s += strlen(s) + 1) {
        if (!have_compile && mut_seg_has(s, "compile-epoch-object.sh") &&
            mut_seg_has(s, src_rel) && mut_seg_has(s, " -- "))
            have_compile = mut_plan_compile(s, src_rel, out);
        else if (!have_link && mut_seg_has(s, ".rsp") && mut_seg_has(s, "-o "))
            have_link = mut_plan_link(s, out);
    }
    free(segs);
    if (!have_compile) {
        if (err)
            (void)snprintf(err, err_cap,
                           "no compile recipe for %s in the make transcript "
                           "(is the file part of this target?)",
                           src_rel);
        zcl_mut_plan_free(out);
        return false;
    }
    if (!have_link) {
        if (err)
            (void)snprintf(err, err_cap,
                           "no link recipe with a response file in the make "
                           "transcript");
        zcl_mut_plan_free(out);
        return false;
    }
    return true;
}

/* ── the campaign ───────────────────────────────────────────────────── */

void zcl_mut_report_free(struct zcl_mut_report *r)
{
    if (!r)
        return;
    free(r->results);
    r->results = NULL;
    r->result_count = 0;
}

int zcl_mut_score_tenths(const struct zcl_mut_report *r)
{
    if (!r)
        return -1;
    size_t k = r->counts[ZCL_MUT_OUTCOME_KILLED];
    size_t s = r->counts[ZCL_MUT_OUTCOME_SURVIVED];
    if (k + s == 0)
        return -1;
    return (int)((k * 2000 + (k + s)) / ((k + s) * 2));
}

struct mut_ctx {
    const struct zcl_mut_config *cfg;
    const struct zcl_mut_plan *plan;
    char subject_c[PATH_MAX];
    char object[PATH_MAX];
    char binary[PATH_MAX];
    char rsp[PATH_MAX];
    char cache_dir[PATH_MAX];
    char runner_arg[128];
    char *baseline_obj;
    size_t baseline_obj_len;
    char src_digest[65];
    char tool_digest[65];
    char base_digest[65];
};

static bool mut_join(char *out, size_t cap, const char *a, const char *b)
{
    int n = snprintf(out, cap, "%s/%s", a, b);
    return n > 0 && (size_t)n < cap;
}

/* The scratch translation unit: a #line directive so every __FILE__ and
 * __LINE__ in the mutant matches the real file, then the (possibly mutated)
 * bytes. This is what makes compiling a copy indistinguishable from
 * compiling the original, without ever writing to the original. */
static bool mut_write_subject(const struct mut_ctx *c, const char *bytes,
                              size_t len)
{
    size_t cap = len + strlen(c->cfg->src_rel) + 32;
    char *buf = zcl_malloc(cap, "mutation.subject");
    if (!buf)
        return false;
    int n = snprintf(buf, cap, "#line 1 \"%s\"\n", c->cfg->src_rel);
    if (n <= 0 || (size_t)n >= cap) {
        free(buf);
        return false;
    }
    memcpy(buf + n, bytes, len);
    bool ok = zcl_mut_write_file(c->subject_c, buf, (size_t)n + len);
    free(buf);
    return ok;
}

static int mut_compile(const struct mut_ctx *c)
{
    struct zcl_mut_argv a;
    memset(&a, 0, sizeof a);
    for (size_t i = 0; i < c->plan->compile.count; i++)
        if (!mut_argv_push(&a, c->plan->compile.argv[i],
                           strlen(c->plan->compile.argv[i])))
            goto fail;
    if (!mut_argv_push(&a, "-c", 2) || !mut_argv_push(&a, "-o", 2) ||
        !mut_argv_push(&a, c->object, strlen(c->object)) ||
        !mut_argv_push(&a, c->subject_c, strlen(c->subject_c)))
        goto fail;
    (void)unlink(c->object);
    char *diagnostic = NULL;
    size_t diagnostic_len = 0;
    int rc = zcl_mut_spawn(c->cfg->root, a.argv, c->cfg->build_timeout_ms,
                           &diagnostic, &diagnostic_len);
    if (rc != 0) {
        int shown = diagnostic_len > 2000u ? 2000 : (int)diagnostic_len;
        fprintf(stderr, "mutation: compile failed rc=%d: %.*s\n", rc, shown,
                diagnostic ? diagnostic : "(no compiler diagnostic)");
    }
    free(diagnostic);
    zcl_mut_argv_free(&a);
    return rc;
fail:
    zcl_mut_argv_free(&a);
    return -1;
}

static int mut_link(const struct mut_ctx *c)
{
    struct zcl_mut_argv a;
    memset(&a, 0, sizeof a);
    char rsparg[PATH_MAX + 2];
    (void)snprintf(rsparg, sizeof rsparg, "@%s", c->rsp);
    for (size_t i = 0; i < c->plan->link.count; i++) {
        const char *w = c->plan->link.argv[i];
        const char *use = w;
        if (strcmp(w, "%OUT%") == 0)
            use = c->binary;
        else if (strcmp(w, "%RSP%") == 0)
            use = rsparg;
        if (!mut_argv_push(&a, use, strlen(use))) {
            zcl_mut_argv_free(&a);
            return -1;
        }
    }
    char *diagnostic = NULL;
    size_t diagnostic_len = 0;
    int rc = zcl_mut_spawn(c->cfg->root, a.argv, c->cfg->build_timeout_ms,
                           &diagnostic, &diagnostic_len);
    if (rc != 0) {
        int shown = diagnostic_len > 2000u ? 2000 : (int)diagnostic_len;
        fprintf(stderr, "mutation: link failed rc=%d: %.*s\n", rc, shown,
                diagnostic ? diagnostic : "(no compiler diagnostic)");
    }
    free(diagnostic);
    zcl_mut_argv_free(&a);
    return rc;
}

/* Run the one affected group and classify. Anything that is not a clean,
 * executed, all-green run is a KILL — except an unusable transcript, which
 * is an ERROR. A mutant must never be scored SURVIVED because the runner
 * printed nothing. */
static enum zcl_mut_outcome mut_run_group(const struct mut_ctx *c,
                                          const char **killed_by)
{
    *killed_by = "";
    char *argv[4];
    char bin[PATH_MAX];
    (void)snprintf(bin, sizeof bin, "%s", c->binary);
    char arg0[128];
    (void)snprintf(arg0, sizeof arg0, "%s", c->runner_arg);
    argv[0] = bin;
    argv[1] = arg0;
    argv[2] = (char *)"--no-cache";
    argv[3] = NULL;

    char *text = NULL;
    size_t len = 0;
    int rc = zcl_mut_spawn(c->cfg->root, argv, c->cfg->test_timeout_ms, &text,
                           &len);
    if (rc == -1) {
        free(text);
        return ZCL_MUT_OUTCOME_ERROR;
    }
    if (rc == -2) {
        free(text);
        *killed_by = "timeout";
        return ZCL_MUT_OUTCOME_KILLED;
    }
    struct zcl_devagent_verdict v;
    bool present = zcl_devagent_verdict_parse(text ? text : "", &v);
    free(text);
    if (rc >= 128) {
        *killed_by = "crash";
        return ZCL_MUT_OUTCOME_KILLED;
    }
    if (!present || v.groups_ran <= 0)
        return ZCL_MUT_OUTCOME_ERROR;
    if (v.groups_failed > 0 || rc != 0) {
        *killed_by = "test";
        return ZCL_MUT_OUTCOME_KILLED;
    }
    return ZCL_MUT_OUTCOME_SURVIVED;
}

/* Cache key: the source, the exact site, the compiler argv and the baseline
 * binary. The last one is what makes the cache safe across other lanes'
 * builds — anything that changes the link closure changes the baseline
 * binary and therefore misses. */
static void mut_cache_key(const struct mut_ctx *c,
                          const struct zcl_mut_site *s, char *hex)
{
    char blob[1024];
    int n = snprintf(blob, sizeof blob, "%s|%s|%s|%s|%s|%zu|%zu|%s",
                     c->src_digest, c->tool_digest, c->base_digest,
                     c->cfg->group, s->rule, s->offset, s->span, s->after);
    if (n < 0)
        n = 0;
    zcl_mut_digest_hex(blob, (size_t)n < sizeof blob ? (size_t)n : sizeof blob,
                       hex);
}

static bool mut_cache_get(const struct mut_ctx *c, const char *key,
                          enum zcl_mut_outcome *out, const char **killed_by)
{
    char path[PATH_MAX];
    if (!mut_join(path, sizeof path, c->cache_dir, key))
        return false;
    size_t len = 0;
    char *text = zcl_mut_read_file(path, &len);
    if (!text)
        return false;
    bool ok = false;
    for (int i = 0; i < ZCL_MUT_OUTCOME_COUNT; i++) {
        const char *name = zcl_mut_outcome_name((enum zcl_mut_outcome)i);
        if (strncmp(text, name, strlen(name)) == 0 &&
            text[strlen(name)] == ' ') {
            *out = (enum zcl_mut_outcome)i;
            const char *rest = text + strlen(name) + 1;
            if (strncmp(rest, "test", 4) == 0)
                *killed_by = "test";
            else if (strncmp(rest, "timeout", 7) == 0)
                *killed_by = "timeout";
            else if (strncmp(rest, "crash", 5) == 0)
                *killed_by = "crash";
            else
                *killed_by = "";
            ok = true;
            break;
        }
    }
    free(text);
    return ok;
}

static void mut_cache_put(const struct mut_ctx *c, const char *key,
                          enum zcl_mut_outcome o, const char *killed_by)
{
    char path[PATH_MAX], line[128];
    if (!mut_join(path, sizeof path, c->cache_dir, key))
        return;
    int n = snprintf(line, sizeof line, "%s %s\n", zcl_mut_outcome_name(o),
                     killed_by && killed_by[0] ? killed_by : "-");
    if (n > 0)
        (void)zcl_mut_write_file(path, line, (size_t)n);
}

static bool mut_prepare(struct mut_ctx *c, struct zcl_mut_report *rep)
{
    const struct zcl_mut_config *cfg = c->cfg;
    if (!mut_join(c->subject_c, sizeof c->subject_c, cfg->work_dir,
                  "subject.c") ||
        !mut_join(c->object, sizeof c->object, cfg->work_dir, "subject.o") ||
        !mut_join(c->binary, sizeof c->binary, cfg->work_dir, "subject.bin") ||
        !mut_join(c->rsp, sizeof c->rsp, cfg->work_dir, "link.rsp") ||
        !mut_join(c->cache_dir, sizeof c->cache_dir, cfg->work_dir, "cache")) {
        (void)snprintf(rep->error, sizeof rep->error,
                       "scratch paths do not fit under %s", cfg->work_dir);
        return false;
    }
    if (!platform_directory_ensure(cfg->work_dir, 0755) ||
        !platform_directory_ensure(c->cache_dir, 0755)) {
        (void)snprintf(rep->error, sizeof rep->error,
                       "cannot create mutation scratch directories under %.180s",
                       cfg->work_dir);
        return false;
    }
    (void)snprintf(c->runner_arg, sizeof c->runner_arg,
                   cfg->runner_arg_fmt ? cfg->runner_arg_fmt : "--exact=%s",
                   cfg->group);

    /* The link input list, with this campaign's object swapped in for the
     * build tree's. The build tree's own object is never rewritten. */
    if (c->plan->rsp[0]) {
        char rsp_path[PATH_MAX];
        const char *p = c->plan->rsp;
        if (platform_path_is_absolute(p)) {
            size_t path_len = strlen(p);
            if (path_len >= sizeof rsp_path) {
                (void)snprintf(rep->error, sizeof rep->error,
                               "absolute response path is too long");
                return false;
            }
            memcpy(rsp_path, p, path_len + 1u);
        } else if (!mut_join(rsp_path, sizeof rsp_path, cfg->root, p)) {
            (void)snprintf(rep->error, sizeof rep->error, "rsp path too long");
            return false;
        }
        size_t rlen = 0;
        char *rsp = zcl_mut_read_file(rsp_path, &rlen);
        if (!rsp) {
            (void)snprintf(rep->error, sizeof rep->error,
                           "cannot read the link response file %.180s", rsp_path);
            return false;
        }
        char *at = strstr(rsp, c->plan->object);
        if (!at) {
            free(rsp);
            (void)snprintf(rep->error, sizeof rep->error,
                           "the link response file does not list %.180s",
                           c->plan->object);
            return false;
        }
        size_t head = (size_t)(at - rsp);
        size_t objn = strlen(c->plan->object);
        size_t need = rlen - objn + strlen(c->object) + 1;
        char *swapped = zcl_malloc(need + 1, "mutation.rsp");
        if (!swapped) {
            free(rsp);
            return false;
        }
        memcpy(swapped, rsp, head);
        memcpy(swapped + head, c->object, strlen(c->object));
        memcpy(swapped + head + strlen(c->object), rsp + head + objn,
               rlen - head - objn);
        swapped[need - 1] = '\0';
#if defined(_WIN32)
        /* GCC response files use backslash as an escape character even when
         * the driver is native Windows.  Convert path separators before the
         * file is parsed or C:\\Users becomes the relative C:Users token. */
        for (size_t i = 0; i + 1u < need; i++)
            if (swapped[i] == '\\') swapped[i] = '/';
#endif
        bool ok = zcl_mut_write_file(c->rsp, swapped, need - 1);
        free(swapped);
        free(rsp);
        if (!ok) {
            (void)snprintf(rep->error, sizeof rep->error,
                           "cannot write %.180s", c->rsp);
            return false;
        }
    }

    /* Tool digest: the compiler argv, so a flag change misses the cache. */
    char tool[8192];
    size_t to = 0;
    for (size_t i = 0; i < c->plan->compile.count && to + 2 < sizeof tool; i++) {
        int n = snprintf(tool + to, sizeof tool - to, "%s ",
                         c->plan->compile.argv[i]);
        if (n <= 0)
            break;
        to += (size_t)n;
    }
    zcl_mut_digest_hex(tool, to, c->tool_digest);
    return true;
}

bool zcl_mut_campaign_run(const struct zcl_mut_config *cfg,
                          const struct zcl_mut_plan *plan,
                          struct zcl_mut_report *out)
{
    if (!cfg || !plan || !out)
        return false;
    memset(out, 0, sizeof *out);
    long long started = mut_now_ms();

    char src_abs[PATH_MAX];
    if (!mut_join(src_abs, sizeof src_abs, cfg->root, cfg->src_rel)) {
        (void)snprintf(out->error, sizeof out->error, "source path too long");
        return false;
    }
    size_t src_len = 0;
    char *src = zcl_mut_read_file(src_abs, &src_len);
    if (!src) {
        (void)snprintf(out->error, sizeof out->error, "cannot read %.180s",
                       src_abs);
        return false;
    }
    zcl_sha3_256((const unsigned char *)src, src_len, out->source_digest_before);

    size_t total = zcl_mut_enumerate(src, src_len, NULL, 0);
    out->total_sites = total;
    if (total == 0) {
        free(src);
        (void)snprintf(out->error, sizeof out->error,
                       "no mutation site in %s", cfg->src_rel);
        return false;
    }
    struct zcl_mut_site *sites =
        zcl_calloc(total, sizeof *sites, "mutation.sites");
    if (!sites) {
        free(src);
        return false;
    }
    (void)zcl_mut_enumerate(src, src_len, sites, total);

    struct mut_ctx c;
    memset(&c, 0, sizeof c);
    c.cfg = cfg;
    c.plan = plan;
    char hex[65];
    zcl_mut_digest_hex(src, src_len, hex);
    (void)snprintf(c.src_digest, sizeof c.src_digest, "%s", hex);
    if (!mut_prepare(&c, out)) {
        free(sites);
        free(src);
        return false;
    }

    /* ── baseline, never cached ─────────────────────────────────────── */
    if (!mut_write_subject(&c, src, src_len)) {
        (void)snprintf(out->error, sizeof out->error,
                       "cannot stage the scratch translation unit");
        goto fail;
    }
    if (mut_compile(&c) != 0) {
        (void)snprintf(out->error, sizeof out->error,
                       "the unmodified file does not compile on its own");
        goto fail;
    }
    c.baseline_obj = zcl_mut_read_file(c.object, &c.baseline_obj_len);
    if (!c.baseline_obj) {
        (void)snprintf(out->error, sizeof out->error,
                       "the baseline object was not produced");
        goto fail;
    }
    if (mut_link(&c) != 0) {
        (void)snprintf(out->error, sizeof out->error,
                       "the baseline link failed");
        goto fail;
    }
    {
        size_t blen = 0;
        char *bin = zcl_mut_read_file(c.binary, &blen);
        if (bin) {
            zcl_mut_digest_hex(bin, blen, c.base_digest);
            free(bin);
        } else {
            (void)snprintf(c.base_digest, sizeof c.base_digest, "nobin");
        }
    }
    {
        const char *by = "";
        enum zcl_mut_outcome base = mut_run_group(&c, &by);
        if (base != ZCL_MUT_OUTCOME_SURVIVED) {
            (void)snprintf(out->error, sizeof out->error,
                           "baseline %s is not green and executing (%s); a "
                           "mutation score against it would mean nothing",
                           cfg->group, zcl_mut_outcome_name(base));
            goto fail;
        }
    }

    out->results = zcl_calloc(total, sizeof *out->results, "mutation.results");
    if (!out->results)
        goto fail;

    for (size_t i = 0; i < total; i++) {
        struct zcl_mut_result *r = &out->results[out->result_count];
        r->site = sites[i];
        r->killed_by = "";
        long long t0 = mut_now_ms();

        char key[65];
        mut_cache_key(&c, &sites[i], key);
        if (cfg->use_cache &&
            mut_cache_get(&c, key, &r->outcome, &r->killed_by)) {
            r->cached = true;
        } else {
            char *image = NULL;
            size_t ilen = 0;
            if (!zcl_mut_apply(src, src_len, &sites[i], &image, &ilen) ||
                !mut_write_subject(&c, image, ilen)) {
                free(image);
                r->outcome = ZCL_MUT_OUTCOME_ERROR;
            } else {
                free(image);
                if (mut_compile(&c) != 0) {
                    r->outcome = ZCL_MUT_OUTCOME_STILLBORN;
                } else {
                    size_t olen = 0;
                    char *obj = zcl_mut_read_file(c.object, &olen);
                    bool same = obj && olen == c.baseline_obj_len &&
                                memcmp(obj, c.baseline_obj, olen) == 0;
                    free(obj);
                    if (same)
                        r->outcome = ZCL_MUT_OUTCOME_EQUIVALENT;
                    else if (mut_link(&c) != 0)
                        r->outcome = ZCL_MUT_OUTCOME_STILLBORN;
                    else
                        r->outcome = mut_run_group(&c, &r->killed_by);
                }
            }
            if (cfg->use_cache && r->outcome != ZCL_MUT_OUTCOME_ERROR)
                mut_cache_put(&c, key, r->outcome, r->killed_by);
        }
        r->ms = mut_now_ms() - t0;
        out->counts[r->outcome]++;
        out->result_count++;
        if (cfg->verbose)
            fprintf(stderr, "  [%zu/%zu] %s:%zu:%zu %s -> %s  %s%s\n", i + 1,
                    total, cfg->src_rel, r->site.line, r->site.column,
                    r->site.rule, r->site.after[0] ? r->site.after : "(delete)",
                    zcl_mut_outcome_name(r->outcome),
                    r->cached ? " (cached)" : "");
        if (cfg->abort_after && out->result_count >= cfg->abort_after) {
            out->aborted = true;
            break;
        }
    }

    /* The file was never opened for writing; this proves it rather than
     * asserting it. */
    {
        size_t again_len = 0;
        char *again = zcl_mut_read_file(src_abs, &again_len);
        if (again) {
            zcl_sha3_256((const unsigned char *)again, again_len,
                         out->source_digest_after);
            out->source_unchanged =
                again_len == src_len &&
                memcmp(again, src, src_len) == 0 &&
                memcmp(out->source_digest_before, out->source_digest_after,
                       32) == 0;
            free(again);
        }
    }
    out->wall_ms = mut_now_ms() - started;
    free(c.baseline_obj);
    free(sites);
    free(src);
    return true;

fail:
    free(c.baseline_obj);
    free(sites);
    free(src);
    zcl_mut_report_free(out);
    return false;
}
