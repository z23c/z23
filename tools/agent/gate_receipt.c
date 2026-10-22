/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_receipt - run a gate and leave behind evidence that it ran.
 *
 * Invoked through tools/agent/gate-receipt.sh, which builds this file and
 * passes the repository root as the first argument:
 *
 *   gate_receipt REPO_ROOT [options] -- COMMAND [ARG...]
 *
 * The wrapper runs COMMAND in the repository root with stdout and stderr
 * merged, stores that output in the receipt directory, and writes a
 * zcl.gate_receipt.v1 receipt (key=value lines, SHA3-256 sealed, chained to
 * the previous receipt). It exits with COMMAND's status, 128+N when COMMAND
 * died of signal N, and 2 for its own failures. `--help` prints the contract
 * and the forgery model; the receipt format is read by `make check-claims`.
 *
 * Signals (gate_receipt_proc.c): an interrupted run is forwarded to the child,
 * reaped, cleaned up and re-raised; no receipt is published for it and its
 * output log is kept.
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#define _DARWIN_C_SOURCE 1
#endif

#include "gate_receipt.h"

#include "base/hex.h"
#include "base/safe_alloc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <locale.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

constexpr long GTR_LOCK_POLL_MS = 10;

static const char *const gtr_help_text[] = {
    "# Copyright 2026 Rhett Creighton - Apache License 2.0\n",
    "#\n",
    "# gate-receipt.sh — run a gate and leave behind evidence that it ran.\n",
    "#\n",
    "# ── WHY THIS EXISTS ────────────────────────────────────────────────────────\n",
    "# A lane agent reports \"make lint passed\". The orchestrator cannot tell that\n",
    "# apart from a confident guess without re-running lint, and has been burned\n",
    "# twice by exactly this class: a test that was green only because it read the\n",
    "# live node's datadir, and a lint gate that reported CLEAN because a\n",
    "# `printf | grep -q` under pipefail inverted its verdict. Re-running every\n",
    "# claimed gate costs more than the lane did.\n",
    "#\n",
    "# So: wrap the gate. The receipt is a BYPRODUCT of running it — the wrapper\n",
    "# holds the child's combined output, times it, and commits to it with a\n",
    "# SHA3-256 — and it is transparent (same stdout, same exit status), so the\n",
    "# honest path is `tools/agent/gate-receipt.sh --gate lint -- make lint`\n",
    "# instead of `make lint`, and nothing else changes.\n",
    "#\n",
    "# ── WHAT THIS DEFENDS AGAINST, AND WHAT IT DOES NOT ────────────────────────\n",
    "# DEFENDS (the common case): an agent that did not run the gate and reports\n",
    "# success from memory. To forge a passing receipt it must produce the gate's\n",
    "# entire literal output — 128 banner lines for lint, 866 group lines for the\n",
    "# suite — with a matching SHA3, a matching HEAD and working-tree digest, a\n",
    "# plausible wall time and child CPU time, and a valid link into the receipt\n",
    "# chain. That is strictly more work than running the gate.\n",
    "# DEFENDS: a STALE receipt replayed after the tree moved (head_sha and the\n",
    "#   working-tree digests are recorded and re-derived by `make check-claims`).\n",
    "# DEFENDS: a receipt produced in another worktree, on another host, or before\n",
    "#   a reboot (worktree_path, hostname, kernel_boot_id).\n",
    "# DEFENDS: exit-status laundering — the verdict is derived from the wrapper's\n",
    "#   observed status AND independently re-derived by `make check-claims` from the\n",
    "#   stored log's success/failure tokens, so \"PASS\" with a log containing\n",
    "#   `SOME TESTS FAILED` is caught.\n",
    "# DOES NOT DEFEND: a lane agent writing a receipt file (and a matching log)\n",
    "#   directly. Nothing here is signed by a key the agent lacks; every field is\n",
    "#   computable by anything with a shell in this checkout. This is EVIDENCE,\n",
    "#   not proof. Do not describe it as tamper-proof.\n",
    "# DOES NOT DEFEND: a gate run in a doctored environment (patched gate script,\n",
    "#   fixture stub). The receipt records what ran, not that what ran was honest.\n",
    "# The upgrade that would close the first gap is an out-of-band signature\n",
    "# (ssh-keygen -Y sign, as platform/deploy/promotion-receipts.jsonl already does) with a\n",
    "# key the lane cannot read. On this host the lane and the orchestrator share a\n",
    "# user, so that buys nothing today; it buys everything once lanes run as\n",
    "# separate users or on separate machines.\n",
    "#\n",
    "# ── USAGE ──────────────────────────────────────────────────────────────────\n",
    "#   tools/agent/gate-receipt.sh --gate lint -- make lint\n",
    "#   tools/agent/gate-receipt.sh --gate t-fast -- make t-fast ONLY=boot_phase\n",
    "#   tools/agent/gate-receipt.sh --gate custom --expect 'MY OK TOKEN' -- ./thing\n",
    "#   make gate-receipt GATE=lint CMD='make lint'\n",
    "#\n",
    "#   --gate <slug>      names the claim. Repeated runs of the same slug are all\n",
    "#                      kept; `make check-claims` judges the NEWEST per slug and\n",
    "#                      counts the rest as iterations.\n",
    "#   --dir <path>       receipt directory (default .cache/agent-receipts, or\n",
    "#                      $ZCL_RECEIPT_DIR). Gitignored; hand the path back to\n",
    "#                      the orchestrator.\n",
    "#   --expect <token>   literal that MUST appear in the output for PASS.\n",
    "#   --forbid <token>   literal that must NOT appear. Both may repeat.\n",
    "#   --label <text>     free-text note carried into the receipt.\n",
    "#   --quiet            do not mirror the child's output to this terminal.\n",
    "#   --selftest-helper  compile the helper into a fresh temporary directory,\n",
    "#                      verify SHA3-256(\"abc\"), then exit without running a gate.\n",
    "#\n",
    "# Known slugs carry default tokens (see TOKEN DEFAULTS below) so that\n",
    "# `--gate lint` already means \"and the literal all-checks-passed banner was\n",
    "# printed\", not merely \"exit 0\". A zero exit alone is not green in this repo.\n",
};

/* ---- options ------------------------------------------------------------ */

struct gtr_list {
    const char **v;
    size_t n;
};

struct gtr_opts {
    const char *repo;
    const char *gate;
    const char *dir;
    const char *label;
    bool quiet;
    bool selftest;
    struct gtr_list expect;
    struct gtr_list forbid;
    char *const *cmd;
    size_t ncmd;
};

static void gtr_list_add(struct gtr_list *l, const char *s)
{
    l->v = gtr_grow(l->v, (l->n + 1) * sizeof *l->v);
    l->v[l->n++] = s;
}

[[noreturn]] static void gtr_help(void)
{
    struct gtr_buf b = {0};

    for (size_t i = 0; i < sizeof gtr_help_text / sizeof gtr_help_text[0]; i++)
        gtr_buf_add(&b, gtr_help_text[i], strlen(gtr_help_text[i]));
    gtr_write_all(1, gtr_buf_str(&b), b.len);
    exit(0);
}

static bool gtr_take_value(struct gtr_opts *o, int argc, char **argv, int *i)
{
    const char *a = argv[*i];
    bool gate = strcmp(a, "--gate") == 0;
    bool dir = strcmp(a, "--dir") == 0;
    bool label = strcmp(a, "--label") == 0;
    bool expect = strcmp(a, "--expect") == 0;
    bool forbid = strcmp(a, "--forbid") == 0;

    if (!gate && !dir && !label && !expect && !forbid)
        return false;
    if (argc - *i < 2)
        gtr_die("%s needs a value", a);
    const char *v = argv[*i + 1];

    if (gate)
        o->gate = v;
    else if (dir)
        o->dir = v;
    else if (label)
        o->label = v;
    else
        gtr_list_add(expect ? &o->expect : &o->forbid, v);
    *i += 2;
    return true;
}

static void gtr_parse(struct gtr_opts *o, int argc, char **argv)
{
    int i = 2;

    while (i < argc) {
        const char *a = argv[i];

        if (gtr_take_value(o, argc, argv, &i))
            continue;
        if (strcmp(a, "--quiet") == 0)
            o->quiet = true;
        else if (strcmp(a, "--selftest-helper") == 0)
            o->selftest = true;
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0)
            gtr_help();
        else if (strcmp(a, "--") == 0) {
            o->cmd = argv + i + 1;
            o->ncmd = (size_t)(argc - i - 1);
            return;
        } else
            gtr_die("unknown option '%s' (the command goes after --)", a);
        i++;
    }
}

static void gtr_default_tokens(struct gtr_opts *o)
{
    static const char *const lint[] = {"lint", "lint-cached", "lint-cold-audit"};
    static const char *const tests[] = {"test", "test-parallel", "t", "t-fast", "t-asan", "t-tsan", "ci"};

    if (o->expect.n != 0 || o->forbid.n != 0)
        return;
    for (size_t i = 0; i < sizeof lint / sizeof lint[0]; i++)
        if (strcmp(o->gate, lint[i]) == 0)
            gtr_list_add(&o->expect, "LINT: all checks passed");
    for (size_t i = 0; i < sizeof tests / sizeof tests[0]; i++) {
        if (strcmp(o->gate, tests[i]) != 0)
            continue;
        gtr_list_add(&o->expect, "ALL TESTS PASSED");
        gtr_list_add(&o->forbid, "SOME TESTS FAILED");
    }
}

static void gtr_validate(struct gtr_opts *o)
{
    if (o->gate == nullptr || *o->gate == '\0')
        gtr_die("--gate <slug> is required; it is the name of the claim");
    if (o->ncmd == 0)
        gtr_die("no command \xe2\x80\x94 put it after --, e.g. -- make lint");
    if (!gtr_slug_ok(o->gate))
        gtr_die("--gate '%s' must be [A-Za-z0-9_.-] only", o->gate);
    gtr_default_tokens(o);
}

/* ---- helper binary ------------------------------------------------------ */

static int gtr_compile_helper(const char *repo, const char *out, bool to_stderr)
{
    const char *cc = getenv("CC");
    char *inc[4] = {
        gtr_fmt("-I%s/platform/modules/sha3/include", repo),
        gtr_fmt("-I%s/core/modules/crypto/include", repo),
        gtr_fmt("-I%s/platform/modules/support/include", repo),
        gtr_fmt("-I%s/platform/modules/base/include", repo),
    };
    char *src1 = gtr_fmt("%s/tools/agent/agent_sha3.c", repo);
    char *src2 = gtr_fmt("%s/platform/modules/sha3/src/sha3.c", repo);
    char *const argv[] = {(char *)(cc != nullptr && *cc != '\0' ? cc : "cc"), "-std=c23", "-O2", "-Wall",
                          "-Wextra", "-Werror", inc[0], inc[1], inc[2], inc[3], "-o", (char *)out,
                          src1, src2, nullptr};
    struct gtr_job job = {.argv = argv, .in_fd = -1, .out_to_err = to_stderr};

    return gtr_run(&job);
}

/* Tools that hash receipts with build/bin/agent_sha3 expect it; a receipt run builds it
 * when it is absent, so a fresh checkout needs no separate make step. */
static void gtr_ensure_helper(const char *repo)
{
    char *bin = gtr_fmt("%s/build/bin/agent_sha3", repo);
    char *dir = gtr_fmt("%s/build/bin", repo);
    char *tmp = gtr_fmt("%s.%ld", bin, (long)getpid());

    if (access(bin, X_OK) == 0)
        return;
    if (gtr_mkdir_p(dir) != 0)
        gtr_die("cannot build %s (see above)", bin);
    gtr_track_file(1, tmp);
    if (gtr_compile_helper(repo, tmp, true) != 0 || rename(tmp, bin) != 0)
        gtr_die("cannot build %s (see above)", bin);
    gtr_untrack_file(1);
}

static void gtr_sink_buf(void *ctx, const char *p, size_t n)
{
    gtr_buf_add(ctx, p, n);
}

static int gtr_selftest(const char *repo)
{
    static const char want[] = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    const char *base = getenv("TMPDIR");
    char *tmpl = gtr_fmt("%s/zcl-gate-receipt-selftest.XXXXXX", base != nullptr && *base != '\0' ? base : "/tmp");
    struct gtr_buf got = {0};
    char *bin;
    int pf[2];

    if (mkdtemp(tmpl) == nullptr)
        gtr_die("selftest mktemp failed");
    gtr_track_dir(tmpl);
    bin = gtr_fmt("%s/agent_sha3", tmpl);
    gtr_track_file(0, bin);
    if (gtr_compile_helper(repo, bin, false) != 0)
        gtr_die("selftest could not build a fresh agent_sha3 helper");
    if (pipe(pf) != 0 || write(pf[1], "abc", 3) != 3)
        gtr_die("selftest cannot feed the helper");
    close(pf[1]);
    char *const argv[] = {bin, "-", nullptr};
    struct gtr_job job = {.argv = argv, .in_fd = pf[0], .capture = true, .sink = gtr_sink_buf, .ctx = &got};

    gtr_run(&job);
    close(pf[0]);
    gtr_buf_chomp(&got);
    if (strcmp(gtr_buf_str(&got), want) != 0)
        gtr_die("selftest SHA3-256(abc) mismatch: got=%s want=%s", gtr_buf_str(&got), want);
    puts("gate-receipt: selftest PASS \xe2\x80\x94 fresh scalar helper links and hashes SHA3-256(abc)");
    return 0;
}

/* ---- snapshot ----------------------------------------------------------- */

struct gtr_snap {
    char *head;
    char *branch;
    bool dirty;
    size_t dirty_files;
    char status_sha3[65];
    char diff_before[65];
    char *host;
    char *boot_id;
    char *user;
};

static int gtr_git(char *const argv[], gtr_sink_fn sink, void *ctx)
{
    struct gtr_job job = {.argv = argv, .in_fd = -1, .capture = true, .err = GTR_ERR_NULL,
                          .sink = sink, .ctx = ctx};

    return gtr_run(&job);
}

/* `$(git ... || echo UNKNOWN)` */
static char *gtr_git_value(char *const argv[])
{
    struct gtr_buf b = {0};

    if (gtr_git(argv, gtr_sink_buf, &b) != 0)
        gtr_buf_add(&b, "UNKNOWN\n", 8);
    gtr_buf_chomp(&b);
    return gtr_fmt("%s", gtr_buf_str(&b));
}

/* The old wrapper aborted without a receipt, silently, when `git diff`
 * failed; the exit status is git's. */
static void gtr_diff_hash(char hex[65])
{
    char *const argv[] = {"git", "diff", "HEAD", nullptr};
    struct sha3_256_ctx ctx;
    int rc;

    sha3_256_init(&ctx);
    rc = gtr_git(argv, gtr_sha3_sink, &ctx);
    if (rc != 0) {
        gtr_cleanup();
        exit(rc);
    }
    gtr_sha3_done(&ctx, hex);
}

static void gtr_snap_tree(struct gtr_snap *s)
{
    char *const status[] = {"git", "status", "--porcelain", nullptr};
    struct gtr_buf porcelain = {0};

    gtr_git(status, gtr_sink_buf, &porcelain);
    gtr_buf_chomp(&porcelain);
    s->dirty = porcelain.len > 0;
    s->dirty_files = s->dirty ? gtr_count_newlines(&(struct gtr_map){porcelain.p, porcelain.len}) + 1 : 0;
    gtr_sha3_buf(porcelain.p, porcelain.len, s->status_sha3);
    gtr_diff_hash(s->diff_before);
}

static char *gtr_read_line_file(const char *path)
{
    struct gtr_buf b = {0};
    char chunk[256];
    ssize_t n;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return gtr_fmt("UNKNOWN");
    while ((n = read(fd, chunk, sizeof chunk)) > 0)
        gtr_buf_add(&b, chunk, (size_t)n);
    close(fd);
    if (n < 0)
        return gtr_fmt("UNKNOWN");
    gtr_buf_chomp(&b);
    return gtr_fmt("%s", gtr_buf_str(&b));
}

static void gtr_snap_host(struct gtr_snap *s)
{
    struct utsname un;
    const char *user = getenv("USER");
    struct passwd *pw;

    s->host = gtr_fmt("%s", uname(&un) == 0 ? un.nodename : "UNKNOWN");
    s->boot_id = gtr_read_line_file("/proc/sys/kernel/random/boot_id");
    if (user != nullptr && *user != '\0') {
        s->user = gtr_fmt("%s", user);
        return;
    }
    pw = getpwuid(geteuid());
    s->user = gtr_fmt("%s", pw != nullptr ? pw->pw_name : "UNKNOWN");
}

static void gtr_snapshot(struct gtr_snap *s)
{
    char *const head[] = {"git", "rev-parse", "HEAD", nullptr};
    char *const branch[] = {"git", "rev-parse", "--abbrev-ref", "HEAD", nullptr};

    s->head = gtr_git_value(head);
    s->branch = gtr_git_value(branch);
    gtr_snap_tree(s);
    gtr_snap_host(s);
}

/* ---- execution ---------------------------------------------------------- */

struct gtr_logsink {
    int fd;
    bool mirror;
    bool failed;
};

static void gtr_log_sink(void *ctx, const char *p, size_t n)
{
    struct gtr_logsink *s = ctx;

    if (gtr_write_all(s->fd, p, n) != 0)
        s->failed = true;
    if (s->mirror && gtr_mirror(1, p, n) != 0)
        s->mirror = false;
}

struct gtr_run_result {
    int rc;
    long long t0;
    long long wall_ms;
    long long cpu_ms;
    char started[32];
    char ended[32];
    char stamp[32];
};

static long long gtr_children_cpu_ms(void)
{
    struct rusage ru;

    getrusage(RUSAGE_CHILDREN, &ru);
    return ((long long)ru.ru_utime.tv_sec * 1000 + ru.ru_utime.tv_usec / 1000) +
           ((long long)ru.ru_stime.tv_sec * 1000 + ru.ru_stime.tv_usec / 1000);
}

static long long gtr_realtime_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_REALTIME, &ts); // platform-ok: receipt timestamps are wall-clock evidence
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void gtr_format_utc(long long ns, const char *fmt, char out[32])
{
    time_t t = (time_t)(ns / 1000000000LL);
    struct tm tm;

    gmtime_r(&t, &tm);
    strftime(out, 32, fmt, &tm);
}

static char *gtr_new_id(void)
{
    unsigned char raw[16];
    char hex[33];
    size_t got = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

    while (fd >= 0 && got < sizeof raw) {
        ssize_t n = read(fd, raw + got, sizeof raw - got);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        got += (size_t)n;
    }
    if (fd >= 0)
        close(fd);
    if (got != sizeof raw)
        gtr_die("cannot read /dev/urandom");
    zcl_hex_encode(raw, sizeof raw, hex);
    return gtr_fmt("%s", hex);
}

static void gtr_begin(struct gtr_run_result *r)
{
    r->t0 = gtr_realtime_ns();
    gtr_format_utc(r->t0, "%Y%m%dT%H%M%SZ", r->stamp);
    gtr_format_utc(r->t0, "%Y-%m-%dT%H:%M:%SZ", r->started);
}

static void gtr_execute(const struct gtr_opts *o, const char *log, struct gtr_run_result *r)
{
    long long cpu0, t1;
    int fd = open(log, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    struct gtr_logsink sink = {.fd = fd, .mirror = !o->quiet};
    struct gtr_job job = {.argv = o->cmd, .in_fd = -1, .capture = true, .err = GTR_ERR_MERGE,
                          .sink = gtr_log_sink, .ctx = &sink};

    if (fd < 0)
        gtr_die("cannot open %s: %s", log, strerror(errno));
    cpu0 = gtr_children_cpu_ms();
    r->rc = gtr_run(&job);
    t1 = gtr_realtime_ns();
    close(fd);
    if (sink.failed)
        gtr_die("cannot write %s", log);
    gtr_format_utc(t1, "%Y-%m-%dT%H:%M:%SZ", r->ended);
    r->wall_ms = (t1 - r->t0) / 1000000;
    r->cpu_ms = gtr_children_cpu_ms() - cpu0;
    if (r->cpu_ms < 0)
        r->cpu_ms = 0;
}

/* ---- receipt ------------------------------------------------------------ */

struct gtr_chain {
    long long index;
    char prev_sha3[65];
    char *prev_name;
};

struct gtr_rec {
    const struct gtr_opts *opts;
    const struct gtr_snap *snap;
    const struct gtr_run_result *run;
    const char *repo;
    const char *id;
    const char *log_name;
    char *head_sha_after;
    char diff_after[65];
    char out_sha3[65];
    size_t out_bytes;
    size_t out_lines;
    size_t expect_missing;
    size_t forbid_present;
    char *display;
    char argv_sha3[65];
};

/* The recorded index of a receipt: the first `chain_index=` line. Anything
 * that is not a plain decimal counts as 0; a decimal too large to compare is
 * reported as -1 and never becomes the newest. */
static long long gtr_receipt_index(const char *path)
{
    FILE *f = fopen(path, "r");
    char *line = nullptr;
    size_t cap = 0;
    long long idx = 0;

    if (f == nullptr)
        gtr_die("cannot read %s: %s", path, strerror(errno));
    while (getline(&line, &cap, f) >= 0) {
        if (strncmp(line, "chain_index=", 12) != 0)
            continue;
        line[strcspn(line, "\n")] = '\0';
        if (gtr_is_digits(line + 12)) {
            errno = 0;
            unsigned long long v = strtoull(line + 12, nullptr, 10);

            idx = (errno == ERANGE || v > (unsigned long long)LLONG_MAX) ? -1 : (long long)v;
        }
        break;
    }
    free(line);
    fclose(f);
    return idx;
}

static bool gtr_is_receipt_name(const char *name)
{
    size_t n = strlen(name);

    return name[0] != '.' && n > 8 && strcmp(name + n - 8, ".receipt") == 0;
}

static void gtr_chain_find(const char *dir, struct gtr_chain *c)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    long long best = -1;
    char *name = nullptr;

    c->index = 0;
    snprintf(c->prev_sha3, sizeof c->prev_sha3, "GENESIS");
    c->prev_name = gtr_fmt("NONE");
    if (d == nullptr)
        return;
    while ((e = readdir(d)) != nullptr) {
        char *path = gtr_fmt("%s/%s", dir, e->d_name);
        struct stat st;
        long long idx;

        if (gtr_is_receipt_name(e->d_name) && stat(path, &st) == 0) {
            idx = gtr_receipt_index(path);
            if (idx > best || (idx == best && name != nullptr && strcmp(e->d_name, name) < 0)) {
                best = idx;
                free(name);
                name = gtr_fmt("%s", e->d_name);
            }
        }
        free(path);
    }
    closedir(d);
    if (name == nullptr)
        return;
    if (best == LLONG_MAX)
        gtr_die("chain_index %lld cannot be extended", best);
    c->index = best + 1;
    c->prev_name = name;
    char *newest = gtr_fmt("%s/%s", dir, name);

    if (gtr_sha3_file(newest, c->prev_sha3) != 0)
        gtr_die("cannot read %s: %s", newest, strerror(errno));
}

static void gtr_render_head(struct gtr_buf *b, const struct gtr_rec *r, const struct gtr_chain *c)
{
    const struct gtr_snap *s = r->snap;

    gtr_buf_addf(b, "receipt_schema=zcl.gate_receipt.v1\nreceipt_id=%s\nchain_index=%lld\n", r->id, c->index);
    gtr_buf_addf(b, "prev_receipt=%s\nprev_receipt_sha3=%s\n", c->prev_name, c->prev_sha3);
    gtr_buf_addf(b, "gate=%s\nlabel=%s\ncommand_display=%s\n", r->opts->gate,
                 r->opts->label != nullptr ? r->opts->label : "", r->display);
    gtr_buf_addf(b, "command_argv_sha3=%s\ncommand_argc=%zu\n", r->argv_sha3, r->opts->ncmd);
    gtr_buf_addf(b, "worktree_path=%s\nbranch=%s\nhead_sha=%s\nhead_sha_after=%s\n", r->repo, s->branch,
                 s->head, r->head_sha_after);
    gtr_buf_addf(b, "tree_dirty=%d\ntree_dirty_files=%zu\ntree_status_sha3=%s\n", s->dirty ? 1 : 0,
                 s->dirty_files, s->status_sha3);
    gtr_buf_addf(b, "tree_diff_sha3_before=%s\ntree_diff_sha3_after=%s\n", s->diff_before, r->diff_after);
}

static void gtr_render_tail(struct gtr_buf *b, const struct gtr_rec *r)
{
    const struct gtr_snap *s = r->snap;
    const struct gtr_run_result *x = r->run;
    const char *verdict = x->rc == 0 && r->expect_missing == 0 && r->forbid_present == 0 ? "PASS" : "FAIL";

    gtr_buf_addf(b, "hostname=%s\nkernel_boot_id=%s\nrun_user=%s\nrunner_pid=%ld\n", s->host, s->boot_id,
                 s->user, (long)getpid());
    gtr_buf_addf(b, "started_at_utc=%s\nended_at_utc=%s\nwall_ms=%lld\nchild_cpu_ms=%lld\nexit_status=%d\n",
                 x->started, x->ended, x->wall_ms, x->cpu_ms, x->rc);
    gtr_buf_addf(b, "output_path=%s\noutput_bytes=%zu\noutput_lines=%zu\noutput_sha3=%s\n", r->log_name,
                 r->out_bytes, r->out_lines, r->out_sha3);
    gtr_buf_addf(b, "expect_tokens=%zu\nforbid_tokens=%zu\nexpect_missing=%zu\nforbid_present=%zu\nverdict=%s\n",
                 r->opts->expect.n, r->opts->forbid.n, r->expect_missing, r->forbid_present, verdict);
    for (size_t i = 0; i < r->opts->expect.n; i++)
        gtr_buf_addf(b, "expect_token=%s\n", r->opts->expect.v[i]);
    for (size_t i = 0; i < r->opts->forbid.n; i++)
        gtr_buf_addf(b, "forbid_token=%s\n", r->opts->forbid.v[i]);
}

/* The sealed receipt text: the body without trailing newlines, a newline,
 * then receipt_sha3 over that same text. */
static char *gtr_render(const struct gtr_rec *r, const struct gtr_chain *c)
{
    struct gtr_buf body = {0};
    char hex[65];

    gtr_render_head(&body, r, c);
    gtr_render_tail(&body, r);
    gtr_buf_chomp(&body);
    gtr_buf_add(&body, "\n", 1);
    gtr_sha3_buf(body.p, body.len, hex);
    gtr_buf_addf(&body, "receipt_sha3=%s\n", hex);
    return body.p;
}

static int gtr_lock_open(const char *dir)
{
    char *path = gtr_fmt("%s/.receipt.lock", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0666);

    if (fd < 0)
        gtr_die("cannot open receipt lock");
    return fd;
}

/* Polls rather than blocking in flock(2) so a signal is never ignored. */
static void gtr_lock_take(int fd)
{
    while (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        if (errno != EWOULDBLOCK && errno != EINTR)
            gtr_die("cannot acquire receipt lock");
        gtr_nap(GTR_LOCK_POLL_MS);
    }
}

static char *gtr_publish(const char *dir, struct gtr_rec *r, const char *stamp)
{
    int lock = gtr_lock_open(dir);
    struct gtr_chain chain;
    char *text, *final, *tmp;
    int fd;

    gtr_lock_take(lock);
    gtr_chain_find(dir, &chain);
    text = gtr_render(r, &chain);
    final = gtr_fmt("%s/%06lld-%s-%s-%s.receipt", dir, chain.index, r->opts->gate, stamp, r->id);
    tmp = gtr_fmt("%s.tmp", final);
    gtr_track_file(1, tmp);
    fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0 || gtr_write_all(fd, text, strlen(text)) != 0)
        gtr_fail("cannot write %s: %s", tmp, strerror(errno));
    close(fd);
    gtr_poll();
    if (rename(tmp, final) != 0)
        gtr_die("cannot publish receipt");
    gtr_untrack_file(1);
    if (flock(lock, LOCK_UN) != 0)
        gtr_die("cannot release receipt lock");
    close(lock);
    return final;
}

/* ---- main flow ---------------------------------------------------------- */

static void gtr_argv_display(const struct gtr_opts *o, struct gtr_rec *r)
{
    struct gtr_buf disp = {0};
    struct gtr_buf raw = {0};

    for (size_t i = 0; i < o->ncmd; i++) {
        if (i > 0)
            gtr_buf_add(&disp, " ", 1);
        gtr_quote_word(&disp, o->cmd[i]);
        gtr_buf_add(&raw, o->cmd[i], strlen(o->cmd[i]) + 1);
    }
    r->display = gtr_fmt("%s", gtr_buf_str(&disp));
    gtr_sha3_buf(raw.p, raw.len, r->argv_sha3);
}

static void gtr_judge(const struct gtr_opts *o, const char *log, struct gtr_rec *r)
{
    struct gtr_map m;

    if (gtr_map_open(log, &m) != 0)
        gtr_die("cannot read %s: %s", log, strerror(errno));
    r->out_bytes = m.len;
    r->out_lines = gtr_count_newlines(&m);
    gtr_sha3_buf(m.p, m.len, r->out_sha3);
    for (size_t i = 0; i < o->expect.n; i++)
        r->expect_missing += !gtr_token_present(&m, o->expect.v[i]);
    for (size_t i = 0; i < o->forbid.n; i++)
        r->forbid_present += gtr_token_present(&m, o->forbid.v[i]);
    gtr_map_close(&m);
}

static char *gtr_prepare_dir(const char *dir)
{
    struct stat st;
    char *abs;

    if (gtr_mkdir_p(dir) != 0)
        gtr_fail("cannot create directory '%s': %s", dir, strerror(errno));
    abs = gtr_logical_path(dir);
    if (stat(abs, &st) != 0 || !S_ISDIR(st.st_mode))
        gtr_fail("cannot enter '%s'", dir);
    return abs;
}

static void gtr_summary(const struct gtr_opts *o, const struct gtr_rec *r, const char *receipt, const char *log)
{
    struct gtr_buf b = {0};
    const char *verdict = r->run->rc == 0 && r->expect_missing == 0 && r->forbid_present == 0 ? "PASS" : "FAIL";

    gtr_buf_addf(&b, "gate-receipt: %s %s (exit %d, %lldms wall, %lldms child CPU)\n", o->gate, verdict,
                 r->run->rc, r->run->wall_ms, r->run->cpu_ms);
    gtr_buf_addf(&b, "gate-receipt: receipt %s\ngate-receipt: output  %s (%zu lines, %zu bytes)\n", receipt,
                 log, r->out_lines, r->out_bytes);
    gtr_write_all(2, b.p, b.len);
}

static void gtr_record(struct gtr_opts *o, const char *repo)
{
    struct gtr_snap snap = {0};
    struct gtr_run_result run = {0};
    struct gtr_rec rec = {.opts = o, .snap = &snap, .run = &run, .repo = repo};
    char *dir = gtr_prepare_dir(o->dir);
    char *log;
    char *receipt;

    gtr_ensure_helper(repo);
    if (chdir(repo) != 0)
        gtr_fail("cannot enter '%s'", repo);
    gtr_snapshot(&snap);
    rec.id = gtr_new_id();
    gtr_begin(&run);
    rec.log_name = gtr_fmt("%s-%s-%s.log", rec.id, o->gate, run.stamp);
    log = gtr_fmt("%s/%s", dir, rec.log_name);
    gtr_execute(o, log, &run);
    char *const head[] = {"git", "rev-parse", "HEAD", nullptr};

    rec.head_sha_after = gtr_git_value(head);
    gtr_diff_hash(rec.diff_after);
    gtr_judge(o, log, &rec);
    gtr_argv_display(o, &rec);
    receipt = gtr_publish(dir, &rec, run.stamp);
    gtr_summary(o, &rec, receipt, log);
    gtr_cleanup();
    exit(run.rc);
}

int main(int argc, char **argv)
{
    struct gtr_opts o = {0};
    const char *env;

    setlocale(LC_CTYPE, "");
    if (argc < 2) {
        fputs("usage: gate_receipt REPO_ROOT [options] -- COMMAND [ARG...]\n", stderr);
        return GTR_EXIT_USAGE;
    }
    o.repo = argv[1];
    gtr_signals_init();
    gtr_parse(&o, argc, argv);
    gtr_poll();
    if (o.selftest) {
        int rc = gtr_selftest(o.repo);

        gtr_cleanup();
        return rc;
    }
    gtr_validate(&o);
    env = getenv("ZCL_RECEIPT_DIR");
    if (o.dir == nullptr)
        o.dir = env != nullptr && *env != '\0' ? env : gtr_fmt("%s/.cache/agent-receipts", o.repo);
    gtr_record(&o, o.repo);
}
