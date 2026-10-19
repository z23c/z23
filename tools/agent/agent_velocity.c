/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * agent_velocity - what a lane actually cost and produced, computed instead
 * of remembered.
 *
 * The owner asks the same questions of every lane: capability landed, unique
 * authored lines, manually touched files, assignment-to-green iterations,
 * agent wall-clock, compiler launches, focused/full test time, merge
 * conflicts, verifier-found defects, post-integration fixes. Most of them are
 * in git and in the gate receipts written by tools/agent/gate-receipt.sh.
 *
 * Every metric is either derived or printed as an explicit NOT-DERIVABLE line
 * naming what the orchestrator must supply. A missing metric that looks like
 * a zero would be averaged into a summary; a stated gap gets asked about.
 *
 * "Generated" is not guessed. Source 1 is the repository's own declaration:
 * .gitattributes `linguist-generated`, read through `git check-attr`. Source 2
 * is an in-file DO-NOT-EDIT / generated-by marker in the first 40 lines, for
 * generated sources that carry no attribute. Everything else counts as
 * hand-authored, which can overstate hand-authored work but never understate
 * it.
 *
 * Usage (run inside the repository; relative --receipts paths are relative
 * to the repository root):
 *   make agent-velocity BASE=b82b40e77 HEAD=HEAD
 *   build/bin/agent_velocity --base b82b40e77 --head HEAD \
 *       --receipts .cache/agent-receipts
 *   build/bin/agent_velocity --against main   merge-conflict surface
 *   build/bin/agent_velocity --selftest
 *
 * Environment: BASE, HEAD and ZCL_RECEIPT_DIR supply the defaults of --base,
 * --head and --receipts.
 *
 * Exit: 0 report printed; 2 bad usage, an unresolvable commit, a failed git
 * call, or input beyond the fixed size limits (refused, never truncated).
 * The tool writes no files and holds no temporary state, so SIGINT and
 * SIGTERM leave nothing to clean up.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <locale.h>
#include <regex.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "base/safe_alloc.h"

/* The report is built in memory and written only when every section was
 * derived, so a refusal never follows partial output. */
static FILE *av_rep;

static void av_rprintf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void av_rprintf(const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vfprintf(av_rep, fmt, ap);
    va_end(ap);
}

static void av_rputs(const char *s)
{
    fputs(s, av_rep);
    fputc('\n', av_rep);
}

constexpr size_t AV_OUT_CAP = 64u << 20;
constexpr size_t AV_LINE_CAP = 1u << 20;
constexpr size_t AV_MARKER_LINES = 40;
constexpr size_t AV_MARKER_LEN = 14;
constexpr size_t AV_DIGITS_MAX = 18;

[[noreturn]] static void av_die(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static void av_die(const char *fmt, ...)
{
    va_list ap;

    fputs("agent-velocity: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(2);
}

static void *av_mem_grow(void *p, size_t n)
{
    void *q = zcl_realloc(p, n, "agent_velocity");

    if (q == nullptr)
        av_die("out of memory");
    return q;
}

static char *av_mem_dup(const char *s)
{
    return strcpy(av_mem_grow(nullptr, strlen(s) + 1), s);
}

/* ---- git child processes ------------------------------------------------ */

struct av_child {
    pid_t pid;
    int fd;
};

static struct av_child av_spawn_git(const char *const *argv)
{
    int fds[2];
    pid_t pid;

    if (pipe(fds) != 0)
        av_die("pipe: %s", strerror(errno));
    pid = fork();
    if (pid < 0)
        av_die("fork: %s", strerror(errno));
    if (pid == 0) {
        int nul = open("/dev/null", O_RDWR);

        if (nul < 0 || dup2(fds[1], 1) < 0 || dup2(nul, 0) < 0 || dup2(nul, 2) < 0)
            _exit(127);
        close(fds[0]);
        close(fds[1]);
        execvp("git", (char *const *)argv);
        _exit(127);
    }
    close(fds[1]);
    return (struct av_child){pid, fds[0]};
}

static int av_reap(struct av_child c)
{
    int st;

    close(c.fd);
    while (waitpid(c.pid, &st, 0) < 0)
        if (errno != EINTR)
            av_die("waitpid: %s", strerror(errno));
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
}

/* Runs git; *out receives all stdout, NUL-terminated and malloc'd. Returns the
 * git exit status. Output beyond OUT_CAP is refused. */
static int av_git_capture(const char *const *argv, char **out)
{
    struct av_child c = av_spawn_git(argv);
    size_t n = 0, cap = 4096;
    char *buf = av_mem_grow(nullptr, cap);

    for (;;) {
        ssize_t got;

        if (n + 1 == cap)
            buf = av_mem_grow(buf, cap *= 2);
        got = read(c.fd, buf + n, cap - n - 1);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        n += (size_t)got;
        if (n > AV_OUT_CAP)
            av_die("output of git %s exceeds %zu bytes", argv[1], AV_OUT_CAP);
    }
    buf[n] = '\0';
    *out = buf;
    return av_reap(c);
}

static void av_chomp(char *s)
{
    size_t n = strlen(s);

    while (n > 0 && s[n - 1] == '\n')
        s[--n] = '\0';
}

/* Stdout of a git call that must succeed, trailing newlines removed. */
static char *av_git_must(const char *const *argv)
{
    char *out;

    if (av_git_capture(argv, &out) != 0)
        av_die("git %s failed", argv[1]);
    av_chomp(out);
    return out;
}

/* `$(git ...)` with errors silenced: the value, or nullptr when git failed or
 * printed nothing. */
static char *av_git_value(const char *const *argv)
{
    char *out;
    int rc = av_git_capture(argv, &out);

    av_chomp(out);
    if (rc != 0 || out[0] == '\0') {
        free(out);
        return nullptr;
    }
    return out;
}

/* ---- line lists --------------------------------------------------------- */

struct av_lines {
    char **v;
    size_t n;
};

static void av_lines_push(struct av_lines *l, char *s)
{
    l->v = av_mem_grow(l->v, (l->n + 1) * sizeof *l->v);
    l->v[l->n++] = s;
}

/* Splits `text` in place at '\n'; a final unterminated line counts. */
static struct av_lines av_split_lines(char *text)
{
    struct av_lines l = {nullptr, 0};
    char *nl;

    while (*text != '\0') {
        av_lines_push(&l, text);
        nl = strchr(text, '\n');
        if (nl == nullptr)
            break;
        *nl = '\0';
        text = nl + 1;
    }
    return l;
}

static size_t av_count_newlines(const char *s)
{
    size_t n = 0;

    for (; *s != '\0'; s++)
        n += *s == '\n';
    return n;
}

/* ---- numeric parsing ---------------------------------------------------- */

static bool av_all_digits(const char *s, size_t len)
{
    if (len == 0)
        return false;
    for (size_t i = 0; i < len; i++)
        if (s[i] < '0' || s[i] > '9')
            return false;
    return true;
}

/* Decimal value of `s[0..len)`: -1 when it is longer than DIGITS_MAX. The
 * caller has checked all_digits. */
static int64_t av_digits_value(const char *s, size_t len)
{
    int64_t v = 0;

    if (len > AV_DIGITS_MAX)
        return -1;
    for (size_t i = 0; i < len; i++)
        v = v * 10 + (s[i] - '0');
    return v;
}

static bool av_add_checked(int64_t *acc, int64_t v)
{
    return !__builtin_add_overflow(*acc, v, acc);
}

/* ---- numstat tally ------------------------------------------------------ */

static char *av_next_token(char **p, size_t *len)
{
    char *s = *p + strspn(*p, " \t");
    size_t n = strcspn(s, " \t");

    *p = s + n;
    *len = n;
    return s;
}

/* Adds a numstat field to *acc when it is all digits (binary files print
 * "-"). False when it is too long to be a line count. */
static bool av_tally_field(const char *tok, size_t len, int64_t *acc)
{
    int64_t v;

    if (!av_all_digits(tok, len))
        return true;
    v = av_digits_value(tok, len);
    return v >= 0 && av_add_checked(acc, v);
}

/* Sums the added and removed columns of `git diff --numstat` output. */
static bool av_tally_numstat(char *text, int64_t *added, int64_t *removed)
{
    struct av_lines l = av_split_lines(text);
    bool ok = true;

    *added = *removed = 0;
    for (size_t i = 0; ok && i < l.n; i++) {
        char *p = l.v[i];
        size_t len1, len2;
        char *t1 = av_next_token(&p, &len1);
        char *t2 = av_next_token(&p, &len2);

        ok = av_tally_field(t1, len1, added) && av_tally_field(t2, len2, removed);
    }
    free(l.v);
    return ok;
}

/* ---- generated-file markers --------------------------------------------- */

struct av_scan {
    size_t lines;
    size_t hits;
    bool hit_in_line;
    char tail[AV_MARKER_LEN + 1];
    size_t tail_n;
};

static bool av_span_has(const char *hay, size_t n, const char *needle)
{
    size_t m = strlen(needle);

    for (size_t i = 0; i + m <= n; i++)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, m) == 0)
            return true;
    return false;
}

/* Binary-safe: the span may contain NUL bytes, as `grep -c` allows. */
static bool av_has_marker(const char *s, size_t n)
{
    return av_span_has(s, n, "GENERATED FILE") || av_span_has(s, n, "Generated by") ||
           av_span_has(s, n, "DO NOT EDIT") || av_span_has(s, n, "generated by");
}

static void av_scan_end_line(struct av_scan *s)
{
    s->hits += s->hit_in_line;
    s->lines++;
    s->hit_in_line = false;
    s->tail_n = 0;
}

/* Looks for a marker in a partial line, joining the bytes carried over from
 * the previous chunk so a marker split across chunks is still found. */
static void av_scan_segment(struct av_scan *s, const char *seg, size_t n)
{
    char *joined = av_mem_grow(nullptr, s->tail_n + n + 1);
    size_t total = s->tail_n + n;

    memcpy(joined, s->tail, s->tail_n);
    memcpy(joined + s->tail_n, seg, n);
    if (av_has_marker(joined, total))
        s->hit_in_line = true;
    s->tail_n = total < AV_MARKER_LEN ? total : AV_MARKER_LEN;
    memcpy(s->tail, joined + total - s->tail_n, s->tail_n);
    free(joined);
}

/* Feeds one chunk; stops counting after MARKER_LINES lines (head -40). */
static void av_scan_chunk(struct av_scan *s, const char *chunk, size_t n)
{
    size_t i = 0;

    while (i < n && s->lines < AV_MARKER_LINES) {
        const char *nl = memchr(chunk + i, '\n', n - i);
        size_t seg = nl != nullptr ? (size_t)(nl - (chunk + i)) : n - i;

        av_scan_segment(s, chunk + i, seg);
        if (nl == nullptr)
            return;
        av_scan_end_line(s);
        i += seg + 1;
    }
}

static void av_scan_finish(struct av_scan *s)
{
    if (s->lines < AV_MARKER_LINES && (s->tail_n > 0 || s->hit_in_line))
        av_scan_end_line(s);
}

static size_t av_marker_lines_in_head(const char *head_sha, const char *path)
{
    size_t need = strlen(head_sha) + strlen(path) + 2;
    char *spec = av_mem_grow(nullptr, need);
    const char *argv[] = {"git", "show", spec, nullptr};
    struct av_scan s = {};
    struct av_child c;
    char buf[8192];
    ssize_t got;

    snprintf(spec, need, "%s:%s", head_sha, path);
    c = av_spawn_git(argv);
    while (s.lines < AV_MARKER_LINES && (got = read(c.fd, buf, sizeof buf)) != 0) {
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0)
            break;
        av_scan_chunk(&s, buf, (size_t)got);
    }
    av_scan_finish(&s);
    av_reap(c);
    free(spec);
    return s.hits;
}

static bool av_attr_generated(const char *path)
{
    const char *argv[] = {"git", "check-attr", "linguist-generated", "--", path, nullptr};
    char *out = av_git_must(argv);
    const char *sep = strstr(out, ": "), *last = nullptr;
    bool set;

    for (; sep != nullptr; sep = strstr(sep + 1, ": "))
        last = sep;
    set = strcmp(last != nullptr ? last + 2 : out, "set") == 0;
    free(out);
    return set;
}

static bool av_is_generated(const char *head_sha, const char *path)
{
    return av_attr_generated(path) || av_marker_lines_in_head(head_sha, path) > 0;
}

/* ---- shared registry files ---------------------------------------------- */

static const char AV_REGISTRY_RE[] =
    "^(Makefile|.*\\.mk|tests/harness/src/test_parallel\\.c|"
    "engine/composition/commands/.*\\.def|"
    "engine/controllers/include/controllers/diagnostics_dumpers.*\\.def|"
    "tools/lint/.*baseline.*\\.txt|core/MANIFEST\\.sha3|docs/DEFENSIVE_CODING\\.md|"
    "docs/dev/CODEBASE_MAP\\.md|CLAUDE\\.md|\\.gitattributes|\\.gitignore)$";

static bool av_is_registry(const char *path)
{
    regex_t re;
    bool hit;

    if (regcomp(&re, AV_REGISTRY_RE, REG_EXTENDED | REG_NOSUB) != 0)
        av_die("internal: registry pattern does not compile");
    hit = regexec(&re, path, 0, nullptr, 0) == 0;
    regfree(&re);
    return hit;
}

/* ---- gate receipts ------------------------------------------------------ */

struct av_receipt {
    char *gate;
    bool pass;
    int64_t wall;
    int64_t cpu;
};

/* Value of a *_ms field: digits, or 0 when it is empty or not a number.
 * -1 when it is longer than DIGITS_MAX. */
static int64_t av_ms_value(const char *v)
{
    size_t len = strlen(v);

    return av_all_digits(v, len) ? av_digits_value(v, len) : 0;
}

static bool av_receipt_field(struct av_receipt *r, const char *line)
{
    if (strncmp(line, "gate=", 5) == 0) {
        free(r->gate);
        r->gate = av_mem_dup(line + 5);
    } else if (strncmp(line, "verdict=", 8) == 0) {
        r->pass = strcmp(line + 8, "PASS") == 0;
    } else if (strncmp(line, "wall_ms=", 8) == 0) {
        r->wall = av_ms_value(line + 8);
    } else if (strncmp(line, "child_cpu_ms=", 13) == 0) {
        r->cpu = av_ms_value(line + 13);
    }
    return r->wall >= 0 && r->cpu >= 0;
}

/* Reads one line without its newline into *buf (grown as needed). 1 when a
 * line was read, 0 at end of input, -1 when it exceeds LINE_CAP. */
static int av_read_line(FILE *fp, char **buf, size_t *cap)
{
    size_t n = 0;
    int c;

    while ((c = fgetc(fp)) != EOF && c != '\n') {
        if (n + 1 >= *cap)
            *buf = av_mem_grow(*buf, *cap = *cap != 0 ? *cap * 2 : 256);
        if (n >= AV_LINE_CAP)
            return -1;
        (*buf)[n++] = (char)c;
    }
    if (c == EOF && n == 0)
        return 0;
    if (n + 1 > *cap)
        *buf = av_mem_grow(*buf, *cap = n + 1);
    (*buf)[n] = '\0';
    return 1;
}

/* Reads one receipt; the last occurrence of each key wins. False when a line
 * exceeds LINE_CAP or a value is out of range. */
static bool av_parse_receipt(FILE *fp, struct av_receipt *r)
{
    char *line = nullptr;
    size_t cap = 0;
    bool ok = true;
    int got;

    *r = (struct av_receipt){};
    while (ok && (got = av_read_line(fp, &line, &cap)) > 0)
        ok = av_receipt_field(r, line);
    free(line);
    return ok && got >= 0 && !ferror(fp);
}

struct av_gate {
    char *name;
    int64_t runs, fails, last_wall, tot_wall, tot_cpu;
    bool last_pass;
};

struct av_gates {
    struct av_gate *v;
    size_t n;
};

static struct av_gate *av_gate_find(struct av_gates *g, const char *name)
{
    for (size_t i = 0; i < g->n; i++)
        if (strcmp(g->v[i].name, name) == 0)
            return &g->v[i];
    g->v = av_mem_grow(g->v, (g->n + 1) * sizeof *g->v);
    g->v[g->n] = (struct av_gate){};
    g->v[g->n].name = av_mem_dup(name);
    return &g->v[g->n++];
}

/* Folds one receipt into the per-gate totals; receipts without a gate are
 * skipped. False on counter overflow. */
static bool av_gates_add(struct av_gates *g, const struct av_receipt *r)
{
    struct av_gate *e;

    if (r->gate == nullptr || r->gate[0] == '\0')
        return true;
    e = av_gate_find(g, r->gate);
    e->runs++;
    e->fails += !r->pass;
    e->last_wall = r->wall;
    e->last_pass = r->pass;
    return av_add_checked(&e->tot_wall, r->wall) && av_add_checked(&e->tot_cpu, r->cpu);
}

static int av_gate_order(const void *a, const void *b)
{
    const struct av_gate *x = a, *y = b;
    int c = strcoll(x->name, y->name);

    return c != 0 ? c : strcmp(x->name, y->name);
}

static void av_print_gate(FILE *o, const struct av_gate *e)
{
    fprintf(o, "gate.%s.runs=%lld\n", e->name, (long long)e->runs);
    fprintf(o, "gate.%s.failed_runs=%lld\n", e->name, (long long)e->fails);
    if (e->last_pass)
        fprintf(o, "gate.%s.iterations_to_green=%lld\n", e->name, (long long)e->runs);
    else
        fprintf(o, "gate.%s.iterations_to_green=NOT-GREEN\n", e->name);
    fprintf(o, "gate.%s.last_wall_ms=%lld\n", e->name, (long long)e->last_wall);
    fprintf(o, "gate.%s.total_wall_ms=%lld\n", e->name, (long long)e->tot_wall);
    fprintf(o, "gate.%s.total_child_cpu_ms=%lld\n", e->name, (long long)e->tot_cpu);
}

static bool av_print_gates(FILE *o, struct av_gates *g)
{
    int64_t total = 0;

    qsort(g->v, g->n, sizeof *g->v, av_gate_order);
    for (size_t i = 0; i < g->n; i++) {
        av_print_gate(o, &g->v[i]);
        if (!av_add_checked(&total, g->v[i].tot_wall))
            return false;
    }
    fprintf(o, "gate_total_wall_ms=%lld\n", (long long)total);
    return true;
}

static bool av_read_receipt(const char *path, struct av_receipt *r)
{
    FILE *fp = fopen(path, "r");
    bool ok;

    if (fp == nullptr)
        av_die("cannot read %s: %s", path, strerror(errno));
    ok = av_parse_receipt(fp, r);
    fclose(fp);
    return ok;
}

static bool av_receipt_files(const char *dir, glob_t *g)
{
    size_t n = strlen(dir);
    char *pat = av_mem_grow(nullptr, 2 * n + sizeof "/*.receipt");
    size_t k = 0;
    int rc;

    for (size_t i = 0; i < n; i++) {
        if (strchr("*?[\\", dir[i]) != nullptr)
            pat[k++] = '\\';
        pat[k++] = dir[i];
    }
    strcpy(pat + k, "/*.receipt");
    rc = glob(pat, GLOB_NOSORT, nullptr, g);
    free(pat);
    return rc == 0;
}

static int av_path_order(const void *a, const void *b)
{
    const char *x = *(char *const *)a, *y = *(char *const *)b;
    int c = strcoll(x, y);

    return c != 0 ? c : strcmp(x, y);
}

static void av_print_no_receipts(const char *dir, bool exists)
{
    av_rputs("gate_receipts=0");
    if (!exists)
        av_rprintf("NOT-DERIVABLE=gate wall-time and pass/fail iterations \xe2\x80\x94 no receipt "
               "directory at %s. Run gates as: tools/agent/gate-receipt.sh --gate <slug> "
               "-- make <slug>\n",
               dir);
    else
        av_rputs("NOT-DERIVABLE=gate wall-time and pass/fail iterations \xe2\x80\x94 the receipt "
             "directory is empty");
}

static bool av_is_directory(const char *path)
{
    struct stat st;

    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static void av_fold_receipts(const glob_t *g, struct av_gates *gates)
{
    for (size_t n = 0; n < g->gl_pathc; n++) {
        struct av_receipt r;

        if (!av_read_receipt(g->gl_pathv[n], &r) || !av_gates_add(gates, &r))
            av_die("unusable receipt %s", g->gl_pathv[n]);
        free(r.gate);
    }
}

/* Prints the receipt section; returns the number of receipt files. */
static size_t av_print_receipts(const char *dir)
{
    glob_t g = {};
    struct av_gates gates = {};
    bool exists = av_is_directory(dir);
    size_t n = 0;

    if (!exists || !av_receipt_files(dir, &g)) {
        av_print_no_receipts(dir, exists);
        globfree(&g);
        return 0;
    }
    qsort(g.gl_pathv, g.gl_pathc, sizeof *g.gl_pathv, av_path_order);
    av_rprintf("gate_receipts=%zu\n", g.gl_pathc);
    av_fold_receipts(&g, &gates);
    if (!av_print_gates(av_rep, &gates))
        av_die("gate wall-time total overflows");
    n = g.gl_pathc;
    free(gates.v);
    globfree(&g);
    return n;
}

/* Full id of `rev^{commit}`, or nullptr when it is not a commit. */
static char *av_resolve_commit_quiet(const char *rev)
{
    size_t need = strlen(rev) + sizeof "^{commit}";
    char *spec = av_mem_grow(nullptr, need);
    const char *argv[] = {"git", "rev-parse", "--verify", spec, nullptr};
    char *sha;

    snprintf(spec, need, "%s^{commit}", rev);
    sha = av_git_value(argv);
    free(spec);
    return sha;
}

static char *av_resolve_commit(const char *what, const char *rev)
{
    char *sha = av_resolve_commit_quiet(rev);

    if (sha == nullptr)
        av_die("--%s '%s' is not a commit", what, rev);
    return sha;
}

/* ---- merge-conflict surface --------------------------------------------- */

/* Prints the conflict lines of `git merge-tree --write-tree --name-only`
 * output: the lines after the tree id up to the first blank line. */
static void av_print_conflicts(FILE *o, char *mt_out)
{
    struct av_lines l;
    size_t end = 1;

    av_chomp(mt_out);
    if (mt_out[0] == '\0') {
        fputs("merge_conflicts=UNKNOWN (git merge-tree produced no output)\n", o);
        return;
    }
    l = av_split_lines(mt_out);
    while (end < l.n && l.v[end][0] != '\0')
        end++;
    fprintf(o, "merge_conflicts=%zu\n", end - 1);
    for (size_t i = 1; i < end; i++)
        fprintf(o, "merge_conflict_file=%s\n", l.v[i]);
    free(l.v);
}

static void av_print_merge_trial(const char *head_sha, const char *against, const char *sha)
{
    const char *argv[] = {"git", "merge-tree", "--write-tree", "--name-only", head_sha, sha,
                          nullptr};
    char *out;

    av_rprintf("merge_against=%s(%.9s)\n", against, sha);
    av_git_capture(argv, &out);
    av_print_conflicts(av_rep, out);
    free(out);
}

static void av_print_merge(const char *head_sha, const char *against)
{
    char *sha = av_resolve_commit_quiet(against);

    if (sha == nullptr) {
        av_rprintf("merge_conflicts=NOT-DERIVABLE (no such ref: %s)\n", against);
        return;
    }
    av_print_merge_trial(head_sha, against, sha);
    free(sha);
}

/* ---- report sections ---------------------------------------------------- */

struct av_opts {
    const char *base;
    const char *head;
    const char *receipts;
    const char *against;
};

static void av_print_identity(const char *repo, const char *base, const char *head)
{
    const char *b_argv[] = {"git", "rev-parse", "--abbrev-ref", "HEAD", nullptr};
    char *branch = av_git_value(b_argv);

    av_rputs("velocity_schema=zcl.agent_velocity.v1");
    av_rprintf("repo_root=%s\nbase_sha=%s\nhead_sha=%s\n", repo, base, head);
    av_rprintf("range=%.9s..%.9s\n", base, head);
    av_rprintf("branch=%s\n", branch != nullptr ? branch : "UNKNOWN");
    free(branch);
}

static void av_print_commits(const char *range)
{
    const char *c_argv[] = {"git", "rev-list", "--count", range, nullptr};
    const char *m_argv[] = {"git", "rev-list", "--count", "--merges", range, nullptr};
    const char *s_argv[] = {"git", "status", "--porcelain", nullptr};
    char *count = av_git_must(c_argv), *merges = av_git_must(m_argv), *status;

    av_rprintf("commits=%s\ncommits_merge=%s\n", count, merges);
    free(count);
    free(merges);
    av_git_capture(s_argv, &status);
    av_chomp(status);
    if (status[0] == '\0') {
        av_rputs("uncommitted_files=0");
    } else {
        av_rprintf("uncommitted_files=%zu\n", av_count_newlines(status) + 1);
        av_rputs("NOTE=the working tree is DIRTY; everything below describes committed work only");
    }
    free(status);
}

static void av_sum_diff(const char *range, struct av_lines *paths, int64_t *added, int64_t *removed)
{
    const char *fixed[] = {"git", "diff", "--numstat", "-M", "-C", range, "--"};
    constexpr size_t NFIXED = sizeof fixed / sizeof fixed[0];
    const char **argv;
    char *out;

    *added = *removed = 0;
    if (paths->n == 0)
        return;
    argv = av_mem_grow(nullptr, (NFIXED + paths->n + 1) * sizeof *argv);
    memcpy(argv, fixed, sizeof fixed);
    memcpy(argv + NFIXED, paths->v, paths->n * sizeof *argv);
    argv[NFIXED + paths->n] = nullptr;
    if (av_git_capture(argv, &out) != 0 || !av_tally_numstat(out, added, removed))
        av_die("cannot total the diff of %s", range);
    free(out);
    free(argv);
}

static void av_print_lines_pair(const char *name, int64_t added, int64_t removed)
{
    av_rprintf("lines_added%s=%lld\nlines_removed%s=%lld\n", name, (long long)added, name,
           (long long)removed);
}

static void av_print_files(const char *range, const char *head, struct av_lines *touched)
{
    struct av_lines hand = {}, gen = {};
    int64_t a_all, r_all, a_hand, r_hand, a_gen, r_gen;

    for (size_t i = 0; i < touched->n; i++)
        av_lines_push(av_is_generated(head, touched->v[i]) ? &gen : &hand, touched->v[i]);
    av_rprintf("files_touched=%zu\nfiles_touched_hand=%zu\nfiles_touched_generated=%zu\n", touched->n,
           hand.n, gen.n);
    av_sum_diff(range, touched, &a_all, &r_all);
    av_sum_diff(range, &hand, &a_hand, &r_hand);
    av_sum_diff(range, &gen, &a_gen, &r_gen);
    av_print_lines_pair("", a_all, r_all);
    av_print_lines_pair("_hand", a_hand, r_hand);
    av_print_lines_pair("_generated", a_gen, r_gen);
    av_rprintf("unique_authored_lines=%lld\n", (long long)a_hand);
    av_rputs("unique_authored_lines_basis=git diff --numstat -M -C over hand-authored files "
         "(renames/copies excluded; a retyped copy is NOT detectable)");
    free(hand.v);
    free(gen.v);
}

static void av_print_shared(struct av_lines *touched)
{
    struct av_lines shared = {};

    for (size_t i = 0; i < touched->n; i++)
        if (av_is_registry(touched->v[i]))
            av_lines_push(&shared, touched->v[i]);
    av_rprintf("shared_registry_files_touched=%zu\n", shared.n);
    for (size_t i = 0; i < shared.n; i++)
        av_rprintf("shared_registry_file=%s\n", shared.v[i]);
    free(shared.v);
}

static void av_print_gaps(bool have_receipts)
{
    av_rputs("NOT-DERIVABLE=capability_landed \xe2\x80\x94 a judgement about what the lane is FOR. "
         "Orchestrator must state it in one sentence.");
    av_rputs("NOT-DERIVABLE=agent_wall_clock_s \xe2\x80\x94 lives in the dispatcher, not in git. "
         "Orchestrator must supply dispatch and return timestamps.");
    av_rputs("NOT-DERIVABLE=opus_tokens_in/out \xe2\x80\x94 API accounting. Orchestrator must "
         "supply from its own usage records.");
    av_rputs("NOT-DERIVABLE=verifier_found_defects \xe2\x80\x94 the verifier's report is prose. "
         "Orchestrator must supply a count, or run the verifier under gate-receipt.sh so at "
         "least its verdict is receipted.");
    av_rputs("NOT-DERIVABLE=post_integration_fixes \xe2\x80\x94 needs the merge commit AND a "
         "decision about which later commits are fixes to THIS lane. Re-run with --base "
         "<merge-sha> --head <later-sha> once that is known.");
    av_rputs("NOT-DERIVABLE=compiler_child_launches \xe2\x80\x94 not in git and not in a receipt. "
         "Would need the build wrapped and $(CC) counted; `make -n build-only | grep -c '^cc '` "
         "is the closest cheap proxy and is NOT run here because it costs a Makefile parse.");
    if (!have_receipts)
        av_rputs("NOT-DERIVABLE=focused_test_time / full_test_time \xe2\x80\x94 derived from "
             "receipts named t-fast / test-parallel; none present.");
}

static int av_report(const struct av_opts *o, const char *repo)
{
    const char *n_argv[] = {"git", "diff", "--name-only", nullptr, nullptr};
    char *base = av_resolve_commit("base", o->base), *head = av_resolve_commit("head", o->head);
    char *range = av_mem_grow(nullptr, strlen(base) + strlen(head) + 3), *names;
    struct av_lines touched;
    size_t nrec;

    sprintf(range, "%s..%s", base, head);
    av_print_identity(repo, base, head);
    av_print_commits(range);
    n_argv[3] = range;
    names = av_git_must(n_argv);
    touched = av_split_lines(names);
    av_print_files(range, head, &touched);
    av_print_shared(&touched);
    av_print_merge(head, o->against);
    nrec = av_print_receipts(o->receipts);
    av_print_gaps(nrec > 0);
    free(touched.v);
    free(names);
    free(range);
    free(base);
    free(head);
    return 0;
}

/* ---- command line -------------------------------------------------------- */

/* The text the bash tool printed for --help: its header comment, lines 2-30. */
static const char AV_HELP_TEXT[] =
    "# Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    "#\n"
    "# agent-velocity.sh — what a lane actually cost and produced, computed instead\n"
    "# of remembered.\n"
    "#\n"
    "# ── WHY THIS EXISTS ────────────────────────────────────────────────────────\n"
    "# The owner asks the same eleven questions of every lane: capability landed,\n"
    "# unique authored lines, manually touched files, assignment-to-green\n"
    "# iterations, agent wall-clock, compiler child launches, focused/full test\n"
    "# time, merge conflicts, verifier-found defects, post-integration fixes. Most\n"
    "# of them are sitting in git and in the gate receipts. None was computed.\n"
    "#\n"
    "# ── THE RULE THIS FILE FOLLOWS ─────────────────────────────────────────────\n"
    "# Every metric is either DERIVED or printed as an explicit NOT-DERIVABLE line\n"
    "# naming what the orchestrator must supply. Nothing is silently omitted: a\n"
    "# missing metric that looks like a zero is worse than a stated gap, because a\n"
    "# zero gets averaged into a summary and a gap gets asked about.\n"
    "#\n"
    "# ── USAGE ──────────────────────────────────────────────────────────────────\n"
    "#   make agent-velocity BASE=b82b40e77 HEAD=HEAD\n"
    "#   tools/agent/agent-velocity.sh --base b82b40e77 --head HEAD \\\n"
    "#       --receipts .cache/agent-receipts\n"
    "#   ... --against main        # merge-conflict surface vs an integration branch\n"
    "set -euo pipefail\n"
    "\n"
    "SCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
    "REPO=\"$(cd \"$SCRIPT_DIR/../..\" && pwd)\"\n"
    "# shellcheck source=tools/scripts/sh_str.sh\n"
    ". \"$REPO/tools/scripts/sh_str.sh\"\n";

static const char *av_option_value(int argc, char **argv, int *i)
{
    if (*i + 1 >= argc)
        av_die("%s needs a value", argv[*i]);
    return argv[(*i += 2) - 1];
}

static bool av_parse_option(struct av_opts *o, int argc, char **argv, int *i)
{
    const char *a = argv[*i];

    if (strcmp(a, "--base") == 0)
        o->base = av_option_value(argc, argv, i);
    else if (strcmp(a, "--head") == 0)
        o->head = av_option_value(argc, argv, i);
    else if (strcmp(a, "--receipts") == 0)
        o->receipts = av_option_value(argc, argv, i);
    else if (strcmp(a, "--against") == 0)
        o->against = av_option_value(argc, argv, i);
    else
        return false;
    return true;
}

/* Applies argv in order; true when --help was requested. Bad options exit
 * before any repository access, so --help and usage errors work anywhere. */
static bool av_parse_args(struct av_opts *o, int argc, char **argv)
{
    int i = 1;

    while (i < argc) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
            return true;
        if (!av_parse_option(o, argc, argv, &i))
            av_die("unknown option '%s'", argv[i]);
    }
    return false;
}

static const char *av_env_or(const char *name, const char *fallback)
{
    const char *v = getenv(name);

    return v != nullptr && v[0] != '\0' ? v : fallback;
}

static char *av_repo_root(void)
{
    const char *argv[] = {"git", "rev-parse", "--show-toplevel", nullptr};
    char *root = av_git_value(argv);

    if (root == nullptr || chdir(root) != 0)
        av_die("not inside a git work tree");
    return root;
}

static const char *av_default_base(struct av_opts *o)
{
    const char *argv[] = {"git", "merge-base", o->head, o->against, nullptr};
    char *mb = av_git_value(argv);

    if (mb == nullptr)
        av_die("no --base given and no merge-base with '%s'", o->against);
    return mb;
}

static int av_failures;
static int av_checks;

static void av_check(bool ok, const char *what)
{
    av_checks++;
    if (!ok) {
        av_failures++;
        fprintf(stderr, "agent_velocity selftest: FAIL %s\n", what);
    }
}

static void av_selftest_numstat(void)
{
    int64_t a, r;
    char ok[] = "10\t2\ta.c\n-\t-\timg.png\n3\t0\told => new\n";
    char big[] = "99999999999999999999\t1\tx\n";

    av_check(av_tally_numstat(ok, &a, &r) && a == 13 && r == 2, "numstat totals skip binary");
    av_check(!av_tally_numstat(big, &a, &r), "numstat refuses an over-long count");
    av_check(!av_add_checked(&(int64_t){INT64_MAX}, 1), "add_checked detects overflow");
}

static size_t av_scan_two(const char *x, const char *y)
{
    struct av_scan s = {};

    av_scan_chunk(&s, x, strlen(x));
    av_scan_chunk(&s, y, strlen(y));
    av_scan_finish(&s);
    return s.hits;
}

static void av_selftest_markers(void)
{
    struct av_scan s = {};
    char buf[200] = "";

    av_check(av_scan_two("// x DO NO", "T EDIT\nplain\n") == 1, "marker split across chunks");
    av_check(av_scan_two("// do not edit\n", "") == 0, "marker match is case exact");
    av_check(av_scan_two("a GENERATED F", "ILE here\nb\n") == 1, "marker split mid-word");
    av_check(av_scan_two("one\ngenerated by x", "") == 1, "unterminated last line counts");
    av_check(av_has_marker("ab\0Generated by x", 17), "marker after a NUL byte is found");
    av_check(!av_has_marker("Generated\0by", 12), "NUL inside a marker does not match");
    for (int i = 0; i < 40; i++)
        strcat(buf, "x\n");
    strcat(buf, "DO NOT EDIT\n");
    av_scan_chunk(&s, buf, strlen(buf));
    av_scan_finish(&s);
    av_check(s.hits == 0 && s.lines == AV_MARKER_LINES, "only the first 40 lines are read");
}

static void av_selftest_registry(void)
{
    av_check(av_is_registry("Makefile") && !av_is_registry("sub/Makefile"), "Makefile only at root");
    av_check(av_is_registry("a/b.mk") && av_is_registry("CLAUDE.md"), "mk and CLAUDE.md");
    av_check(av_is_registry("engine/composition/commands/x.def"), "command def");
    av_check(av_is_registry("tools/lint/foo_baseline_2.txt"), "lint baseline");
    av_check(!av_is_registry("src/main.c") && !av_is_registry("Makefile.bak"), "non-registry");
}

static bool av_parse_text(const char *text, struct av_receipt *r)
{
    size_t n = strlen(text);
    char *copy = av_mem_grow(nullptr, n);
    FILE *fp;
    bool ok;

    memcpy(copy, text, n);
    fp = fmemopen(copy, n, "r");
    ok = fp != nullptr && av_parse_receipt(fp, r);
    if (fp != nullptr)
        fclose(fp);
    free(copy);
    return ok;
}

static void av_selftest_receipts(void)
{
    struct av_receipt r;
    char *big = av_mem_grow(nullptr, AV_LINE_CAP + 64);

    av_check(av_parse_text("gate=a\ngate=b\nverdict=FAIL\nverdict=PASS\nwall_ms=12\nchild_cpu_ms=x", &r) &&
              strcmp(r.gate, "b") == 0 && r.pass && r.wall == 12 && r.cpu == 0,
          "last key wins, bad number is 0, no trailing newline");
    av_check(av_parse_text("gate=a\nverdict=PASSED\n", &r) && !r.pass, "verdict must equal PASS");
    av_check(!av_parse_text("wall_ms=1234567890123456789\n", &r), "over-long number refused");
    memcpy(big, "gate=a\ncommand=", 15);
    memset(big + 15, 'x', 65536);
    strcpy(big + 15 + 65536, "\nverdict=PASS\n");
    av_check(av_parse_text(big, &r) && strcmp(r.gate, "a") == 0 && r.pass, "64 KiB line is read");
    memset(big, 'x', AV_LINE_CAP + 1);
    big[AV_LINE_CAP + 1] = '\0';
    av_check(!av_parse_text(big, &r), "line over 1 MiB refused");
    free(big);
}

static void av_selftest_gates(void)
{
    struct av_gates g = {};
    struct av_receipt r1 = {"a", false, 5, 1}, r2 = {"a", true, 7, 2}, r3 = {"b", false, 9, 0};
    char *text = nullptr;
    size_t len = 0;
    FILE *o = open_memstream(&text, &len);

    av_gates_add(&g, &r1);
    av_gates_add(&g, &r2);
    av_gates_add(&g, &r3);
    av_print_gates(o, &g);
    fclose(o);
    av_check(strstr(text, "gate.a.iterations_to_green=2\n") != nullptr, "a is green at run 2");
    av_check(strstr(text, "gate.b.iterations_to_green=NOT-GREEN\n") != nullptr, "b is not green");
    av_check(strstr(text, "gate.a.total_wall_ms=12\n") != nullptr, "wall totals add");
    av_check(strstr(text, "gate_total_wall_ms=21\n") != nullptr, "grand total adds");
    free(text);
    free(g.v);
}

static void av_conflicts_text(const char *in, const char *want, const char *what)
{
    char *mt = av_mem_grow(nullptr, strlen(in) + 1);
    char *text = nullptr;
    size_t len = 0;
    FILE *o = open_memstream(&text, &len);

    strcpy(mt, in);
    av_print_conflicts(o, mt);
    fclose(o);
    av_check(strcmp(text, want) == 0, what);
    free(text);
    free(mt);
}

static void av_selftest_conflicts(void)
{
    av_conflicts_text("T\nf1\nf2\n\nAuto-merging f1\n",
                   "merge_conflicts=2\nmerge_conflict_file=f1\nmerge_conflict_file=f2\n",
                   "conflicts stop at the blank line");
    av_conflicts_text("T\n", "merge_conflicts=0\n", "clean merge");
    av_conflicts_text("", "merge_conflicts=UNKNOWN (git merge-tree produced no output)\n",
                   "no output is UNKNOWN");
}

static char *av_child_argv_bad[] = {"agent_velocity", "--bogus"};
static char *av_child_argv_novalue[] = {"agent_velocity", "--base"};

static void av_child_bad_option(void)
{
    struct av_opts o = {};

    av_parse_args(&o, 2, av_child_argv_bad);
}

static void av_child_missing_value(void)
{
    struct av_opts o = {};

    av_parse_args(&o, 2, av_child_argv_novalue);
}

static void av_child_refusal_after_output(void)
{
    char *text = nullptr;
    size_t len = 0;

    av_rep = open_memstream(&text, &len);
    av_rprintf("velocity_schema=partial\n");
    av_die("unusable receipt");
}

/* Runs fn in a child; returns its exit status and captures its stdout. */
static int av_run_child(void (*fn)(void), char *out, size_t cap)
{
    int fds[2], st = -1;
    pid_t pid;
    ssize_t got;

    out[0] = '\0';
    if (pipe(fds) != 0 || (pid = fork()) < 0)
        return -1;
    if (pid == 0) {
        int nul = open("/dev/null", O_WRONLY);

        if (nul < 0 || dup2(fds[1], 1) < 0 || dup2(nul, 2) < 0)
            _exit(127);
        fn();
        _exit(0);
    }
    close(fds[1]);
    got = read(fds[0], out, cap - 1);
    out[got > 0 ? got : 0] = '\0';
    close(fds[0]);
    waitpid(pid, &st, 0);
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void av_selftest_options(void)
{
    char out[256];
    char *help[] = {"agent_velocity", "--base", "b", "-h"};
    char *good[] = {"agent_velocity", "--base", "b", "--head", "h", "--receipts", "r",
                    "--against", "a"};
    struct av_opts o = {};

    av_check(av_parse_args(&o, 4, help) && strcmp(o.base, "b") == 0, "-h is reported after options");
    av_check(!av_parse_args(&o, 9, good) && strcmp(o.head, "h") == 0 &&
              strcmp(o.receipts, "r") == 0 && strcmp(o.against, "a") == 0,
          "all four options parse");
    av_check(av_run_child(av_child_bad_option, out, sizeof out) == 2 && out[0] == '\0',
          "unknown option exits 2 without a repository");
    av_check(av_run_child(av_child_missing_value, out, sizeof out) == 2 && out[0] == '\0',
          "option without a value exits 2");
    av_check(strncmp(AV_HELP_TEXT, "# Copyright 2026", 16) == 0, "help starts with the header");
}

static void av_selftest_buffered_refusal(void)
{
    char out[256];

    av_check(av_run_child(av_child_refusal_after_output, out, sizeof out) == 2 && out[0] == '\0',
          "a refusal after report output prints no partial report");
}

static int av_selftest(void)
{
    av_selftest_numstat();
    av_selftest_markers();
    av_selftest_registry();
    av_selftest_receipts();
    av_selftest_gates();
    av_selftest_conflicts();
    av_selftest_options();
    av_selftest_buffered_refusal();
    printf("agent_velocity selftest: %d checks, %d failed\n", av_checks, av_failures);
    return av_failures == 0 ? 0 : 1;
}

static int av_emit_report(const struct av_opts *o, const char *repo)
{
    char *text = nullptr;
    size_t len = 0;
    int rc;

    av_rep = open_memstream(&text, &len);
    if (av_rep == nullptr)
        av_die("cannot buffer the report");
    rc = av_report(o, repo);
    fclose(av_rep);
    av_rep = nullptr;
    if (fwrite(text, 1, len, stdout) != len || fflush(stdout) != 0)
        av_die("cannot write the report");
    free(text);
    return rc;
}

int main(int argc, char **argv)
{
    struct av_opts o = {av_env_or("BASE", ""), av_env_or("HEAD", "HEAD"), av_env_or("ZCL_RECEIPT_DIR", nullptr),
                     "main"};
    char *root, *receipts;

    setlocale(LC_COLLATE, "");
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return av_selftest();
    if (av_parse_args(&o, argc, argv))
        return fputs(AV_HELP_TEXT, stdout) < 0 ? 2 : 0;
    root = av_repo_root();
    if (o.receipts == nullptr) {
        receipts = av_mem_grow(nullptr, strlen(root) + sizeof "/.cache/agent-receipts");
        sprintf(receipts, "%s/.cache/agent-receipts", root);
        o.receipts = receipts;
    }
    if (o.base[0] == '\0')
        o.base = av_default_base(&o);
    return av_emit_report(&o, root);
}
