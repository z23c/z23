/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate check-no-live-lab-history — keep funded transaction-lab
 * history out of the tracked repository. Reproducible simnet evidence and
 * public consensus fixtures are allowed in the canonical baseline;
 * owner-funded broadcasts and recipient-wallet manifests are private local
 * state only. Ported from tools/scripts/check_no_live_lab_history.sh
 * (deleted). Selftest: gate_no_live_lab_history_selftest.c.
 *
 * The canonical baselines (docs/quality/transaction-lab-events.jsonl and
 * docs/quality/transaction-micro-lab-events.jsonl) must each appear exactly
 * once among the tracked files; the micro baseline must stay an empty
 * one-line campaign template (worktree AND Git index); no tracked .json or
 * .jsonl may contain a private recipient-wallet manifest, a funded
 * micro-lab event, or a live-confirmed receipt.
 *
 * Fail closed: unreadable files and failed git subprocesses are errors.
 * Exit 0 = pass, 1 = violation, 2 = tool error. Never weaken a needle or
 * drop the index side of the check to get a green result.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_no_live_lab_history_priv.h"

const char nllh_lab_baseline[] = "docs/quality/transaction-lab-events.jsonl";
const char nllh_micro_baseline[] =
    "docs/quality/transaction-micro-lab-events.jsonl";
static const char nllh_lab_name[] = "transaction-lab-events.jsonl";
static const char nllh_micro_name[] = "transaction-micro-lab-events.jsonl";
const char nllh_micro_header[] =
    "{\"schema\":\"zcl.transaction_micro_lab_campaign.v1\",\"campaign_id\":"
    "\"mainnet-micro-100-v1\",\"created_at\":\"2026-08-05T00:00:00Z\","
    "\"target_count\":100,\"recipient_zat_each\":1000,"
    "\"fee_ceiling_zat_each\":10000,\"setup_envelope_zat\":900000,"
    "\"campaign_envelope_zat\":2000000,\"lifetime_lab_cap_zat\":5000000,"
    "\"reserve_floor_zat\":25000000}";

static char nllh_content[NLLH_CAP];
static char nllh_lsbuf[NLLH_CAP];
static char nllh_sink[64];
static char *nllh_paths[NLLH_NPATHS];

static void nllh_fail(FILE *err, const char *fmt, const char *a,
                      const char *b)
{
    if (!err)
        return;
    if (b)
        fprintf(err, "check-no-live-lab-history: FAIL — %s%s%s\n", fmt, a, b);
    else if (a)
        fprintf(err, "check-no-live-lab-history: FAIL — %s%s\n", fmt, a);
    else
        fprintf(err, "check-no-live-lab-history: FAIL — %s\n", fmt);
}

static int nllh_ext(const char *p, const char *ext)
{
    size_t n = strlen(p), m = strlen(ext);
    return n >= m && strcmp(p + n - m, ext) == 0;
}

static int nllh_json_file(const char *p)
{
    return nllh_ext(p, ".json") || nllh_ext(p, ".jsonl");
}

static size_t nllh_count_nl(const char *s, size_t n)
{
    size_t c = 0;
    for (size_t i = 0; i < n; i++)
        c += s[i] == '\n';
    return c;
}

/* Strips trailing newlines in place (the $(<file) semantics) and returns
 * the stripped length. */
static size_t nllh_strip_nl(char *s, size_t n)
{
    while (n > 0 && s[n - 1] == '\n')
        n--;
    s[n] = '\0';
    return n;
}

/* Drops NUL bytes in place, as bash's $(<file) does, so no marker can hide
 * behind one. Returns the new length. */
static size_t nllh_drop_nul(char *s, size_t n)
{
    size_t w = 0;
    for (size_t i = 0; i < n; i++)
        if (s[i] != '\0')
            s[w++] = s[i];
    s[w] = '\0';
    return w;
}

static int nllh_has(const char *s, size_t n, const char *needle)
{
    return memmem(s, n, needle, strlen(needle)) != NULL;
}

static int nllh_json_content_ok(const char *path, char *content, size_t len,
                                FILE *err)
{
    len = nllh_drop_nul(content, len);
    if (nllh_has(content, len, "\"schema\":\"zcl.transaction_micro_lab_recipient_wallet.v1\"")) {
        nllh_fail(err, "tracked private recipient-wallet manifest: ", path, NULL);
        return 1;
    }
    if (nllh_has(content, len, "\"schema\":\"zcl.transaction_micro_lab_event.v1\"")) {
        nllh_fail(err, "tracked funded micro-lab event history: ", path, NULL);
        return 1;
    }
    if (nllh_has(content, len, "\"proof\":\"live_confirmed\"")) {
        nllh_fail(err, "tracked live-confirmed transaction receipt: ", path, NULL);
        return 1;
    }
    return 0;
}

/* Reads root/rel fully into buf (cap bytes, NUL-terminated); *len is the
 * raw length. Returns 0 ok, 1 unreadable, 2 exceeds cap. */
static int nllh_read_rel(const char *root, const char *rel, char *buf,
                         size_t cap, size_t *len)
{
    char path[NLLH_PLEN * 2];
    if (ovf(snprintf(path, sizeof path, "%s/%s", root, rel), sizeof path))
        return 2;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 1;
    size_t r = fread(buf, 1, cap - 1, f);
    buf[r] = '\0';
    int bad = ferror(f) != 0;
    int over = r == cap - 1 && fgetc(f) != EOF;
    fclose(f);
    if (bad)
        return 1;
    if (over) {
        fprintf(stderr,
                "check-no-live-lab-history: content of %s exceeds %zu bytes\n",
                rel, cap - 1);
        return 2;
    }
    *len = r;
    return 0;
}

static int nllh_io_fail(const char *what)
{
    fprintf(stderr, "check-no-live-lab-history: %s\n", what);
    return 2;
}

/* Child side of a failed setup or exec: send errno up the close-on-exec
 * pipe efd, then leave with 127. The parent turns the report into a spawn
 * error, so a child failure is never read as a git exit status. */
static void nllh_child_fail(int efd)
{
    int e = errno;
    ssize_t w = write(efd, &e, sizeof e);
    (void)w;
    _exit(127);
}

/* Child side: stdout to wfd, stderr to /dev/null when quiet, then exec. */
static void nllh_child_exec(char *const av[], int rfd, int wfd, int quiet,
                            int efd)
{
    close(rfd);
    if (quiet) {
        int nul = open("/dev/null", O_WRONLY);
        if (nul < 0 || dup2(nul, 2) < 0)
            nllh_child_fail(efd);
    }
    if (dup2(wfd, 1) < 0)
        nllh_child_fail(efd);
    execvp(av[0], av);
    nllh_child_fail(efd);
}

/* Parent side: the pipe reaches EOF when exec succeeded (close-on-exec),
 * or carries the child's errno when setup or exec failed. The failed child
 * is reaped here. Returns 0 when git is running, 2 otherwise. */
static int nllh_spawn_status(int efd, pid_t p)
{
    int e = 0;
    ssize_t r;
    do
        r = read(efd, &e, sizeof e);
    while (r < 0 && errno == EINTR);
    if (r == 0)
        return 0;
    if (r < 0)
        return nllh_io_fail("cannot read git spawn status");
    int st = 0;
    while (waitpid(p, &st, 0) < 0 && errno == EINTR)
        ;
    fprintf(stderr, "check-no-live-lab-history: cannot run git: %s\n",
            strerror(e));
    return 2;
}

/* Forks av (av[0] == "git") with stdout on wfd and, when quiet, stderr on
 * /dev/null. The child closes rfd. Returns 0 and sets *pid, or 2 when the
 * fork, pipe or exec fails (the message is printed). */
static int nllh_spawn(char *const av[], int rfd, int wfd, int quiet,
                      pid_t *pid)
{
    int ep[2];
    if (pipe(ep) != 0)
        return nllh_io_fail("pipe failed");
    if (fcntl(ep[1], F_SETFD, FD_CLOEXEC) != 0) {
        close(ep[0]);
        close(ep[1]);
        return nllh_io_fail("fcntl failed");
    }
    pid_t p = fork();
    if (p < 0) {
        close(ep[0]);
        close(ep[1]);
        return nllh_io_fail("fork failed");
    }
    if (p == 0) {
        close(ep[0]);
        nllh_child_exec(av, rfd, wfd, quiet, ep[1]);
    }
    close(ep[1]);
    *pid = p;
    int rc = nllh_spawn_status(ep[0], p);
    close(ep[0]);
    return rc;
}

/* Reads rfd to EOF into buf (cap bytes). Returns 0 with *len set, 2 on a
 * read error or when the output exceeds cap (never a silent truncation). */
static int nllh_drain(int rfd, char *buf, size_t cap, size_t *len)
{
    size_t total = 0;
    for (;;) {
        if (total == cap) {
            char probe;
            ssize_t more;
            do
                more = read(rfd, &probe, 1);
            while (more < 0 && errno == EINTR);
            if (more < 0)
                return nllh_io_fail("read from git failed");
            if (more > 0) {
                fprintf(stderr,
                        "check-no-live-lab-history: git output exceeds %zu bytes\n",
                        cap);
                return 2;
            }
            break;
        }
        ssize_t r = read(rfd, buf + total, cap - total);
        if (r < 0 && errno == EINTR)
            continue;
        if (r < 0)
            return nllh_io_fail("read from git failed");
        if (r == 0)
            break;
        total += (size_t)r;
    }
    buf[total] = '\0';
    *len = total;
    return 0;
}

/* Reaps pid; EINTR is retried, any other waitpid failure or abnormal exit
 * is an error. Sets *code to the exit status. */
static int nllh_wait(pid_t pid, int *code)
{
    int st = 0;
    pid_t got;
    do
        got = waitpid(pid, &st, 0);
    while (got < 0 && errno == EINTR);
    if (got != pid || !WIFEXITED(st)) {
        fprintf(stderr, "check-no-live-lab-history: git did not exit cleanly\n");
        return 2;
    }
    *code = WEXITSTATUS(st);
    return 0;
}

/* Runs git with av, capturing stdout into buf (cap bytes, NUL-terminated,
 * *len set). *code receives the exit status. Returns 0 ok, 2 spawn, read,
 * reap or overflow failure (fail closed, never a silent skip). */
static int nllh_run_git(char *const av[], char *buf, size_t cap, size_t *len,
                        int *code, int quiet)
{
    int fds[2];
    pid_t pid = -1;
    if (pipe(fds) != 0)
        return nllh_io_fail("pipe failed");
    int rc = nllh_spawn(av, fds[0], fds[1], quiet, &pid);
    close(fds[1]);
    if (rc) {
        close(fds[0]);
        return rc;
    }
    rc = nllh_drain(fds[0], buf, cap, len);
    close(fds[0]);
    int wrc = nllh_wait(pid, code);
    return rc ? rc : wrc;
}

static int nllh_cat_file_ok(const char *rel)
{
    char spec[NLLH_PLEN + 2];
    char *av[6];
    int code = 0;
    size_t len = 0;
    if (ovf(snprintf(spec, sizeof spec, ":%s", rel), sizeof spec))
        return 2;
    av[0] = (char *)"git";
    av[1] = (char *)"cat-file";
    av[2] = (char *)"-e";
    av[3] = spec;
    av[4] = NULL;
    if (nllh_run_git(av, nllh_sink, sizeof nllh_sink, &len, &code, 1))
        return 2;
    return code == 0;
}

static int nllh_git_show(const char *rel, char *buf, size_t cap, size_t *len,
                         int *code)
{
    char spec[NLLH_PLEN + 2];
    char *av[4];
    if (ovf(snprintf(spec, sizeof spec, ":%s", rel), sizeof spec))
        return 2;
    av[0] = (char *)"git";
    av[1] = (char *)"show";
    av[2] = spec;
    av[3] = NULL;
    return nllh_run_git(av, buf, cap, len, code, 0);
}

static int nllh_name_seen(const char *path, int *lab, int *micro, FILE *err)
{
    const char *slash = strrchr(path, '/');
    const char *base = slash ? slash + 1 : path;
    if (strcmp(base, nllh_lab_name) == 0) {
        if (strcmp(path, nllh_lab_baseline) != 0) {
            nllh_fail(err, "tracked duplicate lab ledger: ", path, NULL);
            return 1;
        }
        (*lab)++;
    } else if (strcmp(base, nllh_micro_name) == 0) {
        if (strcmp(path, nllh_micro_baseline) != 0) {
            nllh_fail(err, "tracked duplicate micro-lab ledger: ", path, NULL);
            return 1;
        }
        (*micro)++;
    }
    return 0;
}

static int nllh_wt_json(const char *root, const char *path, FILE *err)
{
    size_t len = 0;
    int rc = nllh_read_rel(root, path, nllh_content, sizeof nllh_content,
                           &len);
    if (rc == 1) {
        nllh_fail(err, "cannot read tracked file: ", path, NULL);
        return 1;
    }
    if (rc)
        return 2;
    return nllh_json_content_ok(path, nllh_content, len, err);
}

/* True when the content, NULs dropped and trailing newlines stripped as the
 * shell's $(<file) does, is exactly the campaign template. The length is
 * compared first, so a NUL or junk after the header cannot pass. */
static int nllh_template_match(char *content, size_t len)
{
    size_t want = strlen(nllh_micro_header);
    len = nllh_drop_nul(content, len);
    len = nllh_strip_nl(content, len);
    return len == want && memcmp(content, nllh_micro_header, want) == 0;
}

static int nllh_micro_template_wt(const char *root, FILE *err)
{
    size_t len = 0;
    int rc = nllh_read_rel(root, nllh_micro_baseline, nllh_content,
                           sizeof nllh_content, &len);
    if (rc == 1) {
        nllh_fail(err, "cannot read tracked file: ", nllh_micro_baseline, NULL);
        return 1;
    }
    if (rc)
        return 2;
    if (nllh_count_nl(nllh_content, len) != 1) {
        nllh_fail(err,
                  "micro-lab baseline must remain an empty one-line campaign template",
                  NULL, NULL);
        return 1;
    }
    if (!nllh_template_match(nllh_content, len)) {
        nllh_fail(err, "micro-lab campaign template changed unexpectedly", NULL,
                  NULL);
        return 1;
    }
    return 0;
}

int nllh_check_paths(const char *root, const char *const *paths, size_t n,
                     FILE *err)
{
    int lab = 0, micro = 0;
    for (size_t i = 0; i < n; i++) {
        int rc = nllh_name_seen(paths[i], &lab, &micro, err);
        if (rc)
            return rc;
        if (!nllh_json_file(paths[i]))
            continue;
        rc = nllh_wt_json(root, paths[i], err);
        if (rc)
            return rc;
    }
    if (lab != 1) {
        nllh_fail(err, "canonical lab baseline is missing or duplicated", NULL,
                  NULL);
        return 1;
    }
    if (micro != 1) {
        nllh_fail(err, "canonical micro-lab baseline is missing or duplicated",
                  NULL, NULL);
        return 1;
    }
    return nllh_micro_template_wt(root, err);
}

static int nllh_idx_json(const char *path, FILE *err)
{
    char label[NLLH_PLEN + 32];
    size_t len = 0;
    int code = 0;
    if (ovf(snprintf(label, sizeof label, "%s (Git index)", path),
             sizeof label))
        return 2;
    if (nllh_git_show(path, nllh_content, sizeof nllh_content, &len, &code))
        return 2;
    if (code != 0) {
        nllh_fail(err, "cannot read indexed JSON content: ", path, NULL);
        return 1;
    }
    return nllh_json_content_ok(label, nllh_content, len, err);
}

static int nllh_micro_template_idx(FILE *err)
{
    size_t len = 0;
    int code = 0;
    if (nllh_git_show(nllh_micro_baseline, nllh_content,
                      sizeof nllh_content, &len, &code))
        return 2;
    if (code != 0) {
        nllh_fail(err, "cannot read indexed JSON content: ",
                  nllh_micro_baseline, NULL);
        return 1;
    }
    if (nllh_count_nl(nllh_content, len) != 1) {
        nllh_fail(err, "indexed micro-lab baseline must remain a one-line template",
                  NULL, NULL);
        return 1;
    }
    if (!nllh_template_match(nllh_content, len)) {
        nllh_fail(err, "indexed micro-lab campaign template changed unexpectedly",
                  NULL, NULL);
        return 1;
    }
    return 0;
}

static int nllh_check_index(const char *const *paths, size_t n, FILE *err)
{
    int rc = nllh_cat_file_ok(nllh_lab_baseline);
    if (rc == 0) {
        nllh_fail(err, "canonical lab baseline is absent from the Git index",
                  NULL, NULL);
        return 1;
    }
    if (rc == 2)
        return 2;
    rc = nllh_cat_file_ok(nllh_micro_baseline);
    if (rc == 0) {
        nllh_fail(err, "canonical micro-lab baseline is absent from the Git index",
                  NULL, NULL);
        return 1;
    }
    if (rc == 2)
        return 2;
    for (size_t i = 0; i < n; i++) {
        if (!nllh_json_file(paths[i]))
            continue;
        rc = nllh_idx_json(paths[i], err);
        if (rc)
            return rc;
    }
    return nllh_micro_template_idx(err);
}

static int nllh_collect(int *nout)
{
    char *av[3];
    size_t len = 0;
    int code = 0;
    av[0] = (char *)"git";
    av[1] = (char *)"ls-files";
    av[2] = NULL;
    int rc = nllh_run_git(av, nllh_lsbuf, sizeof nllh_lsbuf, &len, &code, 0);
    if (rc)
        return 2;
    if (code != 0) {
        fprintf(stderr, "check-no-live-lab-history: git ls-files failed (%d)\n",
                code);
        return 2;
    }
    int np = 0;
    size_t i = 0;
    while (i < len) {
        size_t j = i;
        while (j < len && nllh_lsbuf[j] != '\n')
            j++;
        if (np >= NLLH_NPATHS) {
            fprintf(stderr,
                    "check-no-live-lab-history: tracked file list exceeds %d\n",
                    NLLH_NPATHS);
            return 2;
        }
        if (j > i + NLLH_PLEN - 1) {
            fprintf(stderr,
                    "check-no-live-lab-history: tracked path exceeds %d\n",
                    NLLH_PLEN - 1);
            return 2;
        }
        nllh_lsbuf[j] = '\0';
        nllh_paths[np++] = nllh_lsbuf + i;
        i = j + 1;
    }
    *nout = np;
    return 0;
}

int check_no_live_lab_history_run(int argc, char **argv)
{
    if (argc >= 1) {
        if (strcmp(argv[0], "--selftest") == 0) {
            extern int check_no_live_lab_history_selftest(void);
            return check_no_live_lab_history_selftest();
        }
        nllh_fail(stderr, "unknown argument: ", argv[0], NULL);
        return 1;
    }
    int np = 0;
    if (nllh_collect(&np))
        return 2;
    int rc = nllh_check_paths(".", (const char *const *)nllh_paths,
                              (size_t)np, stderr);
    if (rc)
        return rc;
    rc = nllh_check_index((const char *const *)nllh_paths, (size_t)np,
                          stderr);
    if (rc)
        return rc;
    printf("%s\n",
           "check-no-live-lab-history: PASS — funded receipts remain private local state");
    return 0;
}
