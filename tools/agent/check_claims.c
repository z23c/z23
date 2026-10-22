/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * check_claims - judge a lane's gate claims from the receipts left by
 * tools/agent/gate-receipt.sh, without re-running any gate.
 *
 * Usage: check_claims [--require a,b] [--dir PATH] [--max-age-hours N]
 *                     [--strict] [--json] | --help | --selftest
 * Environment: CLAIMS (required gates), ZCL_RECEIPT_DIR (receipt directory).
 *
 * Exit: 0 every receipt verified; 1 a problem was found, or a receipt log
 * cannot be read; 2 bad usage or an unreadable receipt. The report is built in
 * memory and written only when complete, so an error never follows partial
 * output. The tool writes no files and holds no temporary state; SIGINT and
 * SIGTERM keep their default action and leave nothing to clean up. SHA3-256
 * is computed in-process with the tree's own implementation.
 */
#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "crypto/sha3.h"

constexpr size_t CCL_RECEIPT_CAP = 256u << 20;
constexpr size_t CCL_SCAN_CHUNK = 1u << 20;
constexpr size_t CCL_HEAD_PREFIX = 9;

/* ---- memory, errors, strings -------------------------------------------- */

[[noreturn]] static void ccl_die(int status, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void ccl_die(int status, const char *fmt, ...)
{
    va_list ap;

    fputs("check-claims: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(status);
}

static void *ccl_grow(void *p, size_t n)
{
    void *q = zcl_realloc(p, n, "check_claims");

    if (q == nullptr)
        ccl_die(2, "out of memory");
    return q;
}

static char *ccl_dup(const char *s)
{
    return strcpy(ccl_grow(nullptr, strlen(s) + 1), s);
}

static char *ccl_dupn(const char *s, size_t n)
{
    char *d = ccl_grow(nullptr, n + 1);

    memcpy(d, s, n);
    d[n] = '\0';
    return d;
}

static char *ccl_vfmt(const char *fmt, va_list ap) __attribute__((format(printf, 1, 0)));

static char *ccl_vfmt(const char *fmt, va_list ap)
{
    char *s = nullptr;
    size_t len = 0;
    FILE *m = open_memstream(&s, &len);

    if (m == nullptr || vfprintf(m, fmt, ap) < 0 || fclose(m) != 0)
        ccl_die(2, "out of memory");
    return s;
}

static char *ccl_fmt(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static char *ccl_fmt(const char *fmt, ...)
{
    va_list ap;
    char *s;

    va_start(ap, fmt);
    s = ccl_vfmt(fmt, ap);
    va_end(ap);
    return s;
}

static void ccl_chomp(char *s)
{
    size_t n = strlen(s);

    while (n > 0 && s[n - 1] == '\n')
        s[--n] = '\0';
}

/* A growing string; add() joins entries with the separator. */
struct ccl_str {
    char *s;
    size_t len;
};

static void ccl_str_add(struct ccl_str *b, char sep, const char *text)
{
    size_t n = strlen(text), need = b->len + n + 2;

    b->s = ccl_grow(b->s, need);
    if (b->len > 0 && sep != '\0')
        b->s[b->len++] = sep;
    memcpy(b->s + b->len, text, n + 1);
    b->len += n;
}

static void ccl_note(struct ccl_str *notes, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void ccl_note(struct ccl_str *notes, const char *fmt, ...)
{
    va_list ap;
    char *t;

    va_start(ap, fmt);
    t = ccl_vfmt(fmt, ap);
    va_end(ap);
    ccl_str_add(notes, ',', t);
    free(t);
}

/* ---- numbers ------------------------------------------------------------ */

/* The integer accepted by `[ A -gt B ]`: optional surrounding blanks and sign,
 * digits only, within int64. */
static bool ccl_test_int(const char *s, int64_t *out)
{
    bool neg = false;
    uint64_t v = 0;
    size_t digits = 0;

    while (isspace((unsigned char)*s))
        s++;
    if (*s == '+' || *s == '-')
        neg = *s++ == '-';
    for (; *s >= '0' && *s <= '9'; s++, digits++) {
        if (v > (UINT64_MAX - 9) / 10)
            return false;
        v = v * 10 + (uint64_t)(*s - '0');
    }
    while (isspace((unsigned char)*s))
        s++;
    if (digits == 0 || *s != '\0' || v > (neg ? (uint64_t)INT64_MAX + 1 : (uint64_t)INT64_MAX))
        return false;
    *out = neg ? (int64_t)(0 - v) : (int64_t)v;
    return true;
}

static bool ccl_int_gt(const char *a, const char *b)
{
    int64_t x, y;

    return ccl_test_int(a, &x) && ccl_test_int(b, &y) && x > y;
}

/* Days since 1970-01-01 of a proleptic Gregorian date. */
static int64_t ccl_days_from_civil(int64_t y, unsigned m, unsigned d)
{
    int64_t era;
    unsigned yoe, doy, doe;

    y -= m <= 2;
    era = (y >= 0 ? y : y - 399) / 400;
    yoe = (unsigned)(y - era * 400);
    doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + (int64_t)doe - 719468;
}

static bool ccl_digits_at(const char *s, size_t n, unsigned *v)
{
    *v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        *v = *v * 10 + (unsigned)(s[i] - '0');
    }
    return true;
}

static unsigned ccl_days_in_month(unsigned y, unsigned m)
{
    static const unsigned dm[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;

    return dm[m - 1] + (m == 2 && leap);
}

static bool ccl_iso_shape(const char *s)
{
    static const char shape[] = "dddd-dd-ddTdd:dd:ddZ";

    if (strlen(s) != sizeof shape - 1)
        return false;
    for (size_t i = 0; i < sizeof shape - 1; i++)
        if (shape[i] == 'd' ? (s[i] < '0' || s[i] > '9') : s[i] != shape[i])
            return false;
    return true;
}

/* Exactly YYYY-MM-DDTHH:MM:SSZ with a valid calendar time. */
static bool ccl_parse_iso_utc(const char *s, int64_t *epoch)
{
    static const unsigned char at[6] = {0, 5, 8, 11, 14, 17}, width[6] = {4, 2, 2, 2, 2, 2};
    unsigned f[6];

    if (!ccl_iso_shape(s))
        return false;
    for (size_t i = 0; i < 6; i++)
        ccl_digits_at(s + at[i], width[i], &f[i]);
    if (f[1] < 1 || f[1] > 12 || f[2] < 1 || f[2] > ccl_days_in_month(f[0], f[1]) || f[3] > 23 || f[4] > 59 ||
        f[5] > 59)
        return false;
    *epoch = ccl_days_from_civil(f[0], f[1], f[2]) * 86400 + (int64_t)f[3] * 3600 + (int64_t)f[4] * 60 + f[5];
    return true;
}

/* ---- child processes ---------------------------------------------------- */

struct ccl_child {
    pid_t pid;
    int fd;
};

static struct ccl_child ccl_spawn(const char *const *argv)
{
    int fds[2];
    pid_t pid;

    if (pipe(fds) != 0)
        ccl_die(2, "pipe: %s", strerror(errno));
    pid = fork();
    if (pid < 0)
        ccl_die(2, "fork: %s", strerror(errno));
    if (pid == 0) {
        int nul = open("/dev/null", O_RDWR);

        if (nul < 0 || dup2(fds[1], 1) < 0 || dup2(nul, 0) < 0 || dup2(nul, 2) < 0)
            _exit(127);
        close(fds[0]);
        close(fds[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(fds[1]);
    return (struct ccl_child){pid, fds[0]};
}

/* Closes the pipe and returns the exit status (128 + signal when killed). */
static int ccl_reap(struct ccl_child c)
{
    int st;

    close(c.fd);
    while (waitpid(c.pid, &st, 0) < 0)
        if (errno != EINTR)
            ccl_die(2, "waitpid: %s", strerror(errno));
    return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
}

/* Runs argv; *out receives its stdout, NUL-terminated. Returns its status. */
static int ccl_capture(const char *const *argv, char **out)
{
    struct ccl_child c = ccl_spawn(argv);
    size_t n = 0, cap = 256;
    char *buf = ccl_grow(nullptr, cap);

    for (;;) {
        ssize_t got;

        if (n + 1 == cap)
            buf = ccl_grow(buf, cap *= 2);
        got = read(c.fd, buf + n, cap - n - 1);
        if (got < 0 && errno == EINTR)
            continue;
        if (got <= 0)
            break;
        n += (size_t)got;
    }
    buf[n] = '\0';
    *out = buf;
    return ccl_reap(c);
}

/* ---- SHA3-256 ----------------------------------------------------------- */

/* Streams `fp` to the digest; false on a read error. */
static bool ccl_hash_stream(FILE *fp, char hex[65])
{
    struct sha3_256_ctx ctx;
    unsigned char buf[65536];
    unsigned char digest[SHA3_256_OUTPUT_SIZE];
    size_t got;

    sha3_256_init(&ctx);
    while ((got = fread(buf, 1, sizeof buf, fp)) > 0)
        sha3_256_write(&ctx, buf, got);
    if (ferror(fp))
        return false;
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
    return true;
}

static void ccl_hash_bytes(const void *p, size_t n, char hex[65])
{
    struct sha3_256_ctx ctx;
    unsigned char digest[SHA3_256_OUTPUT_SIZE];

    sha3_256_init(&ctx);
    sha3_256_write(&ctx, p, n);
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
}

/* ---- receipts ----------------------------------------------------------- */

struct ccl_receipt {
    char *buf;
    size_t len;
    char *schema, *gate, *idx, *self_sha3, *out_path, *out_sha3, *head, *worktree, *tree_diff, *exit_status,
        *verdict, *n_expect, *n_forbid, *started, *wall, *prev_sha3;
    char **expect, **forbid;
    size_t n_exp, n_forb;
    char body_sha3[65], file_sha3[65];
};

static const struct {
    const char *name;
    size_t off;
} CCL_KEYS[] = {
    {"receipt_schema", offsetof(struct ccl_receipt, schema)},
    {"gate", offsetof(struct ccl_receipt, gate)},
    {"chain_index", offsetof(struct ccl_receipt, idx)},
    {"receipt_sha3", offsetof(struct ccl_receipt, self_sha3)},
    {"output_path", offsetof(struct ccl_receipt, out_path)},
    {"output_sha3", offsetof(struct ccl_receipt, out_sha3)},
    {"head_sha", offsetof(struct ccl_receipt, head)},
    {"worktree_path", offsetof(struct ccl_receipt, worktree)},
    {"tree_diff_sha3_after", offsetof(struct ccl_receipt, tree_diff)},
    {"exit_status", offsetof(struct ccl_receipt, exit_status)},
    {"verdict", offsetof(struct ccl_receipt, verdict)},
    {"expect_tokens", offsetof(struct ccl_receipt, n_expect)},
    {"forbid_tokens", offsetof(struct ccl_receipt, n_forbid)},
    {"started_at_utc", offsetof(struct ccl_receipt, started)},
    {"wall_ms", offsetof(struct ccl_receipt, wall)},
    {"prev_receipt_sha3", offsetof(struct ccl_receipt, prev_sha3)},
};

static bool ccl_slurp(const char *path, char **buf, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    size_t n = 0, cap = 4096, got;
    char *b;

    if (fp == nullptr)
        return false;
    b = ccl_grow(nullptr, cap);
    while ((got = fread(b + n, 1, cap - n - 1, fp)) > 0) {
        n += got;
        if (n > CCL_RECEIPT_CAP)
            ccl_die(2, "%s exceeds %zu bytes", path, CCL_RECEIPT_CAP);
        if (n + 1 >= cap)
            b = ccl_grow(b, cap *= 2);
    }
    if (ferror(fp)) {
        free(b);
        fclose(fp);
        return false;
    }
    fclose(fp);
    b[n] = '\0';
    *buf = b;
    *len = n;
    return true;
}

/* Length of everything before the last line (`sed '$d'`). */
static size_t ccl_body_len(const char *b, size_t len)
{
    size_t n = len;

    if (n > 0 && b[n - 1] == '\n')
        n--;
    while (n > 0 && b[n - 1] != '\n')
        n--;
    return n;
}

static size_t ccl_drop_nul(char *line, size_t n)
{
    size_t w = 0;

    for (size_t i = 0; i < n; i++)
        if (line[i] != '\0')
            line[w++] = line[i];
    line[w] = '\0';
    return w;
}

static void ccl_token_add(char ***v, size_t *n, char *tok)
{
    if (tok[0] == '\0')
        return;
    *v = ccl_grow(*v, (*n + 1) * sizeof **v);
    (*v)[(*n)++] = tok;
}

static void ccl_receipt_line(struct ccl_receipt *r, char *line)
{
    if (strncmp(line, "expect_token=", 13) == 0)
        ccl_token_add(&r->expect, &r->n_exp, line + 13);
    else if (strncmp(line, "forbid_token=", 13) == 0)
        ccl_token_add(&r->forbid, &r->n_forb, line + 13);
    for (size_t i = 0; i < sizeof CCL_KEYS / sizeof CCL_KEYS[0]; i++) {
        size_t k = strlen(CCL_KEYS[i].name);

        if (strncmp(line, CCL_KEYS[i].name, k) == 0 && line[k] == '=')
            *(char **)((char *)r + CCL_KEYS[i].off) = line + k + 1;
    }
}

/* Takes ownership of buf. Missing keys read as empty; the last occurrence of
 * a key wins; token lines accumulate. */
static void ccl_receipt_parse(struct ccl_receipt *r, char *buf, size_t len)
{
    char *p = buf, *end = buf + len;

    *r = (struct ccl_receipt){.buf = buf, .len = len};
    ccl_hash_bytes(buf, ccl_body_len(buf, len), r->body_sha3);
    ccl_hash_bytes(buf, len, r->file_sha3);
    for (size_t i = 0; i < sizeof CCL_KEYS / sizeof CCL_KEYS[0]; i++)
        *(char **)((char *)r + CCL_KEYS[i].off) = (char *)"";
    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t n = nl != nullptr ? (size_t)(nl - p) : (size_t)(end - p);

        ccl_drop_nul(p, n);
        if (nl != nullptr)
            *nl = '\0';
        ccl_receipt_line(r, p);
        p += n + (nl != nullptr);
    }
}

static void ccl_receipt_free(struct ccl_receipt *r)
{
    free(r->buf);
    free(r->expect);
    free(r->forbid);
}

/* ---- log scanning ------------------------------------------------------- */

static const char *ccl_find(const char *hay, size_t n, const char *needle, size_t m)
{
    const char *p;

    while (n >= m && (p = memchr(hay, needle[0], n - m + 1)) != nullptr) {
        if (memcmp(p, needle, m) == 0)
            return p;
        n -= (size_t)(p + 1 - hay);
        hay = p + 1;
    }
    return nullptr;
}

/* Sets found[i] when tok[i] (non-empty, no newline) occurs in the stream. One
 * pass; matches spanning two reads are kept by carrying the tail. */
static bool ccl_scan_tokens(FILE *fp, const char *const *tok, size_t n, bool *found, size_t chunk)
{
    size_t maxlen = 1, keep = 0, have, got, cap;
    char *buf;

    for (size_t i = 0; i < n; i++)
        if (strlen(tok[i]) > maxlen)
            maxlen = strlen(tok[i]);
    cap = maxlen + chunk;
    buf = ccl_grow(nullptr, cap);
    do {
        got = fread(buf + keep, 1, cap - keep, fp);
        have = keep + got;
        for (size_t i = 0; i < n; i++)
            found[i] = found[i] || ccl_find(buf, have, tok[i], strlen(tok[i])) != nullptr;
        keep = have < maxlen - 1 ? have : maxlen - 1;
        memmove(buf, buf + have - keep, keep);
    } while (got > 0);
    free(buf);
    return !ferror(fp);
}

static bool ccl_is_gate_line(const char *h, size_t n)
{
    static const char *const pre[] = {"PASS check-", "FAIL check-", "CACHED check-"};

    for (size_t i = 0; i < 3; i++)
        if (n >= strlen(pre[i]) && strncmp(h, pre[i], strlen(pre[i])) == 0)
            return true;
    return false;
}

/* Lines of the stream starting `(PASS|FAIL|CACHED) check-`. */
static bool ccl_count_gate_lines(FILE *fp, size_t *count)
{
    char head[16], chunk[65536];
    size_t pos = 0, got;

    *count = 0;
    while ((got = fread(chunk, 1, sizeof chunk, fp)) > 0) {
        for (size_t i = 0; i < got; i++) {
            if (chunk[i] == '\n') {
                *count += ccl_is_gate_line(head, pos);
                pos = 0;
            } else if (pos < sizeof head) {
                head[pos++] = chunk[i];
            }
        }
    }
    *count += ccl_is_gate_line(head, pos);
    return !ferror(fp);
}

static bool ccl_ends_with_continuation(const char *line)
{
    size_t n = strlen(line);

    while (n > 0 && isspace((unsigned char)line[n - 1]))
        n--;
    return n > 0 && line[n - 1] == '\\';
}

static bool ccl_is_lint_gates_line(const char *line)
{
    size_t k = strlen("LINT_GATES");

    if (strncmp(line, "LINT_GATES", k) != 0)
        return false;
    line += k;
    while (isspace((unsigned char)*line))
        line++;
    if (*line == ':')
        line++;
    return *line == '=';
}

static size_t ccl_count_check_words(const char *line)
{
    size_t c = 0;

    while (*line != '\0') {
        const char *w;

        while (isspace((unsigned char)*line))
            line++;
        w = line;
        while (*line != '\0' && !isspace((unsigned char)*line))
            line++;
        c += line > w && strncmp(w, "check-", 6) == 0;
    }
    return c;
}

/* The `check-*` words of the Makefile's first LINT_GATES definition. */
static size_t ccl_lint_gate_count(FILE *mk)
{
    char *line = nullptr;
    size_t cap = 0, count = 0;
    bool inside = false;
    ssize_t got;

    while ((got = getline(&line, &cap, mk)) >= 0) {
        ccl_drop_nul(line, (size_t)got);
        inside = inside || ccl_is_lint_gates_line(line);
        if (!inside)
            continue;
        count += ccl_count_check_words(line);
        if (!ccl_ends_with_continuation(line))
            break;
    }
    free(line);
    return count;
}

/* Verdict of the shape floor: true when the log has enough gate lines. */
static bool ccl_shape_ok(size_t want, size_t got, bool serial, struct ccl_str *notes)
{
    if (want == 0)
        return true;
    if (got == 0 && serial) {
        ccl_note(notes, "SHAPE_SERIAL");
        return true;
    }
    if (got >= want)
        return true;
    ccl_note(notes, "SHAPE_TOO_SMALL(%zu/%zu gate lines)", got, want);
    return false;
}

/* ---- judging one receipt ------------------------------------------------ */

struct ccl_ctx {
    const char *repo, *dir, *head, *diff, *max_age;
    int64_t now;
    int64_t lint_gates;
    bool strict;
};

static size_t ccl_ctx_lint_gates(struct ccl_ctx *c)
{
    if (c->lint_gates < 0) {
        char *path = ccl_fmt("%s/Makefile", c->repo);
        FILE *mk = fopen(path, "r");

        if (mk == nullptr)
            ccl_die(2, "cannot read %s: %s", path, strerror(errno));
        c->lint_gates = (int64_t)ccl_lint_gate_count(mk);
        fclose(mk);
        free(path);
    }
    return (size_t)c->lint_gates;
}

static bool ccl_judge_header(struct ccl_receipt *r, struct ccl_str *notes)
{
    bool ok = true;

    if (strcmp(r->schema, "zcl.gate_receipt.v1") != 0) {
        ccl_note(notes, "BAD_SCHEMA(%s)", r->schema);
        ok = false;
    }
    if (r->gate[0] == '\0') {
        r->gate = (char *)"(unnamed)";
        ccl_note(notes, "NO_GATE_FIELD");
        ok = false;
    }
    if (strcmp(r->self_sha3, r->body_sha3) != 0) {
        ccl_note(notes, "RECEIPT_ALTERED");
        ok = false;
    }
    return ok;
}

static bool ccl_judge_tokens(const struct ccl_receipt *r, FILE *log, struct ccl_str *notes)
{
    size_t n = r->n_exp + r->n_forb, miss = 0, forb = 0;
    const char **tok;
    bool *found, ok = true;

    if (n == 0)
        return true;
    tok = ccl_grow(nullptr, n * sizeof *tok);
    found = ccl_grow(nullptr, n * sizeof *found);
    for (size_t i = 0; i < n; i++) {
        tok[i] = i < r->n_exp ? r->expect[i] : r->forbid[i - r->n_exp];
        found[i] = false;
    }
    if (!ccl_scan_tokens(log, tok, n, found, CCL_SCAN_CHUNK))
        ccl_die(1, "read error on %s", r->out_path);
    for (size_t i = 0; i < n; i++) {
        miss += i < r->n_exp && !found[i];
        forb += i >= r->n_exp && found[i];
    }
    if (miss > 0) {
        ccl_note(notes, "SUCCESS_TOKEN_ABSENT");
        ok = false;
    }
    if (forb > 0) {
        ccl_note(notes, "FAILURE_TOKEN_PRESENT");
        ok = false;
    }
    free(tok);
    free(found);
    return ok;
}

static bool ccl_is_lint_gate(const char *gate)
{
    return strcmp(gate, "lint") == 0;
}

static bool ccl_judge_shape(struct ccl_ctx *c, const struct ccl_receipt *r, FILE *log, struct ccl_str *notes)
{
    static const char *const serial_tok[] = {"all checks passed (serial)"};
    size_t want, got;
    bool serial = false;

    if (!ccl_is_lint_gate(r->gate) || (want = ccl_ctx_lint_gates(c)) == 0)
        return true;
    if (!ccl_count_gate_lines(log, &got))
        ccl_die(1, "read error on %s", r->out_path);
    if (got == 0) {
        rewind(log);
        if (!ccl_scan_tokens(log, serial_tok, 1, &serial, CCL_SCAN_CHUNK))
            ccl_die(1, "read error on %s", r->out_path);
    }
    return ccl_shape_ok(want, got, serial, notes);
}

/* The stored log must hash to the recorded digest and still carry the
 * receipt's success and failure tokens; lint logs also need their gate lines. */
static bool ccl_judge_log(struct ccl_ctx *c, const struct ccl_receipt *r, FILE *log, struct ccl_str *notes)
{
    char hex[65];
    bool ok;

    if (!ccl_hash_stream(log, hex))
        ccl_die(1, "read error on %s", r->out_path);
    if (strcmp(hex, r->out_sha3) != 0) {
        ccl_note(notes, "OUTPUT_ALTERED");
        return false;
    }
    rewind(log);
    ok = ccl_judge_tokens(r, log, notes);
    rewind(log);
    return ccl_judge_shape(c, r, log, notes) && ok;
}

static bool ccl_judge_output(struct ccl_ctx *c, const struct ccl_receipt *r, struct ccl_str *notes)
{
    char *path;
    struct stat st;
    FILE *log;
    bool ok;

    path = ccl_fmt("%s/%s", c->dir, r->out_path);
    if (r->out_path[0] == '\0' || stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        ccl_note(notes, "OUTPUT_MISSING");
        free(path);
        return false;
    }
    log = fopen(path, "rb");
    if (log == nullptr)
        ccl_die(1, "cannot read %s: %s", path, strerror(errno));
    ok = ccl_judge_log(c, r, log, notes);
    fclose(log);
    free(path);
    return ok;
}

static bool ccl_judge_tree(const struct ccl_ctx *c, const struct ccl_receipt *r, struct ccl_str *notes)
{
    bool ok = true;

    if (strcmp(r->head, c->head) != 0) {
        ccl_note(notes, "STALE_HEAD(%.*s)", (int)CCL_HEAD_PREFIX, r->head);
        ok = false;
    }
    if (strcmp(r->worktree, c->repo) != 0) {
        ccl_note(notes, "FOREIGN_WORKTREE");
        ok = false;
    }
    if (strcmp(r->tree_diff, c->diff) != 0) {
        ccl_note(notes, "TREE_MOVED");
        ok = ok && !c->strict;
    }
    return ok;
}

static bool ccl_judge_status(const struct ccl_receipt *r, struct ccl_str *notes)
{
    bool ok = true;

    if (strcmp(r->exit_status, "0") != 0) {
        ccl_note(notes, "EXIT_%s", r->exit_status);
        ok = false;
    }
    if (strcmp(r->verdict, "PASS") != 0) {
        ccl_note(notes, "RECORDED_%s", r->verdict);
        ok = false;
    }
    if (strcmp(r->n_expect, "0") == 0 && strcmp(r->n_forbid, "0") == 0)
        ccl_note(notes, "EXIT_STATUS_ONLY");
    return ok;
}

/* Epoch seconds of a receipt timestamp; 0 when unparsable. ISO UTC is parsed
 * here; any other form is left to date(1), as before. */
static int64_t ccl_epoch_of(const char *start)
{
    const char *argv[] = {"date", "-u", "-d", start, "+%s", nullptr};
    int64_t v = 0;
    char *out = nullptr;

    if (ccl_parse_iso_utc(start, &v))
        return v;
    if (ccl_capture(argv, &out) == 0) {
        ccl_chomp(out);
        if (!ccl_test_int(out, &v))
            v = 0;
    }
    free(out);
    return v;
}

static bool ccl_judge_age(const struct ccl_ctx *c, const struct ccl_receipt *r, struct ccl_str *notes)
{
    int64_t epoch, age_h;
    char *age;
    bool stale;

    if (strcmp(c->max_age, "0") == 0)
        return true;
    epoch = ccl_epoch_of(r->started);
    if (epoch <= 0)
        return true;
    age_h = (c->now - epoch) / 3600;
    age = ccl_fmt("%lld", (long long)age_h);
    stale = ccl_int_gt(age, c->max_age);
    if (stale)
        ccl_note(notes, "STALE_AGE(%lldh)", (long long)age_h);
    free(age);
    return !stale;
}

static bool ccl_judge_receipt(struct ccl_ctx *c, struct ccl_receipt *r, struct ccl_str *notes)
{
    bool ok = ccl_judge_header(r, notes);

    ok = ccl_judge_output(c, r, notes) && ok;
    ok = ccl_judge_tree(c, r, notes) && ok;
    ok = ccl_judge_status(r, notes) && ok;
    return ccl_judge_age(c, r, notes) && ok;
}

/* ---- chain and gate table ----------------------------------------------- */

struct ccl_chain {
    int64_t expected;
    char *expected_text;
    char prev[65];
    struct ccl_str broken;
};

/* chain_index as the script read it: digits only, else -1. Digits beyond
 * int64 saturate. */
static bool ccl_idx_is_digits(const char *s)
{
    return s[0] != '\0' && s[strspn(s, "0123456789")] == '\0';
}

static int64_t ccl_parse_idx(const char *s)
{
    int64_t v;

    if (!ccl_idx_is_digits(s))
        return -1;
    return ccl_test_int(s, &v) ? v : INT64_MAX;
}

static const char *ccl_base_name(const char *path)
{
    const char *slash = strrchr(path, '/');

    return slash != nullptr ? slash + 1 : path;
}

static void ccl_chain_step(struct ccl_chain *ch, const struct ccl_receipt *r, const char *path, struct ccl_str *notes)
{
    int64_t idx = ccl_parse_idx(r->idx);
    const char *text = ccl_idx_is_digits(r->idx) ? r->idx : "-1";
    char *msg;

    if (ch->expected == INT64_MAX || idx != ch->expected + 1) {
        msg = ccl_fmt("index %s follows %s; ", text, ch->expected_text);
        ccl_str_add(&ch->broken, '\0', msg);
        free(msg);
    }
    if (strcmp(r->prev_sha3, ch->prev) != 0) {
        msg = ccl_fmt("%s does not link to its predecessor; ", ccl_base_name(path));
        ccl_str_add(&ch->broken, '\0', msg);
        free(msg);
        ccl_note(notes, "CHAIN_BREAK");
    }
    ch->expected = idx;
    free(ch->expected_text);
    ch->expected_text = ccl_dup(text);
    memcpy(ch->prev, r->file_sha3, sizeof ch->prev);
}

struct ccl_gate {
    char *name, *wall, *note, *receipt;
    int64_t latest_idx;
    size_t runs, failed;
    bool ok;
};

struct ccl_gates {
    struct ccl_gate *v;
    size_t n;
};

static struct ccl_gate *ccl_gate_get(struct ccl_gates *g, const char *name)
{
    for (size_t i = 0; i < g->n; i++)
        if (strcmp(g->v[i].name, name) == 0)
            return &g->v[i];
    g->v = ccl_grow(g->v, (g->n + 1) * sizeof *g->v);
    g->v[g->n] = (struct ccl_gate){.name = ccl_dup(name), .latest_idx = -1};
    return &g->v[g->n++];
}

static void ccl_gate_record(struct ccl_gates *g, const struct ccl_receipt *r, const char *path, bool ok,
                            const struct ccl_str *notes)
{
    struct ccl_gate *e = ccl_gate_get(g, r->gate);
    int64_t idx = ccl_parse_idx(r->idx);

    e->runs++;
    e->failed += !ok;
    if (idx < e->latest_idx)
        return;
    e->latest_idx = idx;
    e->ok = ok;
    free(e->wall);
    free(e->note);
    free(e->receipt);
    e->receipt = ccl_dup(path);
    e->wall = ccl_dup(r->wall);
    e->note = ccl_dup(notes->len > 0 ? notes->s : "-");
}

static void ccl_gates_free(struct ccl_gates *g)
{
    for (size_t i = 0; i < g->n; i++) {
        free(g->v[i].name);
        free(g->v[i].wall);
        free(g->v[i].note);
        free(g->v[i].receipt);
    }
    free(g->v);
}

static int ccl_gate_order(const void *a, const void *b)
{
    const struct ccl_gate *x = a, *y = b;
    int c = strcoll(x->name, y->name);

    return c != 0 ? c : strcmp(x->name, y->name);
}

/* ---- receipt discovery and required gates ------------------------------- */

struct ccl_names {
    char **v;
    size_t n;
};

static bool ccl_names_has(const struct ccl_names *l, const char *s)
{
    for (size_t i = 0; i < l->n; i++)
        if (strcmp(l->v[i], s) == 0)
            return true;
    return false;
}

static void ccl_names_push(struct ccl_names *l, char *s)
{
    l->v = ccl_grow(l->v, (l->n + 1) * sizeof *l->v);
    l->v[l->n++] = s;
}

static void ccl_names_free(struct ccl_names *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->v[i]);
    free(l->v);
    *l = (struct ccl_names){};
}

/* First line of raw split at commas and blanks, empty and repeated entries
 * dropped, order kept. */
static struct ccl_names ccl_split_required(const char *raw)
{
    struct ccl_names l = {};
    size_t line = strcspn(raw, "\n"), i = 0;

    while (i < line) {
        size_t n = strcspn(raw + i, ", \n");
        char *g = ccl_dupn(raw + i, n);

        if (n > 0 && !ccl_names_has(&l, g))
            ccl_names_push(&l, g);
        else
            free(g);
        i += n + 1;
    }
    return l;
}

static int ccl_path_order(const void *a, const void *b)
{
    const char *const *x = a, *const *y = b;
    int c = strcoll(*x, *y);

    return c != 0 ? c : strcmp(*x, *y);
}

static bool ccl_is_receipt_name(const char *name)
{
    size_t n = strlen(name);

    return name[0] != '.' && n > 8 && strcmp(name + n - 8, ".receipt") == 0;
}

/* Paths of the *.receipt files in dir, in the collation order of sort(1). */
static struct ccl_names ccl_list_receipts(const char *dir)
{
    struct ccl_names l = {};
    DIR *d = opendir(dir);
    struct dirent *e;

    if (d == nullptr)
        return l;
    while ((e = readdir(d)) != nullptr)
        if (ccl_is_receipt_name(e->d_name))
            ccl_names_push(&l, ccl_fmt("%s/%s", dir, e->d_name));
    closedir(d);
    qsort(l.v, l.n, sizeof *l.v, ccl_path_order);
    return l;
}

/* Absolute form of dir relative to base, with "." and ".." folded textually
 * (what `cd DIR && pwd` prints). */
static char *ccl_logical_path(const char *base, const char *dir)
{
    char *full = dir[0] == '/' ? ccl_dup(dir) : ccl_fmt("%s/%s", base, dir);
    char *out = ccl_grow(nullptr, strlen(full) + 2);
    size_t w = 0;

    for (char *p = full, *save; (p = strtok_r(p, "/", &save)) != nullptr; p = nullptr) {
        if (strcmp(p, ".") == 0)
            continue;
        if (strcmp(p, "..") == 0) {
            while (w > 0 && out[--w] != '/')
                ;
            continue;
        }
        out[w++] = '/';
        memcpy(out + w, p, strlen(p));
        w += strlen(p);
    }
    if (w == 0)
        out[w++] = '/';
    out[w] = '\0';
    free(full);
    return out;
}

/* ---- repository state ---------------------------------------------------- */

static char *ccl_git_head(void)
{
    const char *argv[] = {"git", "rev-parse", "HEAD", nullptr};
    char *out;

    if (ccl_capture(argv, &out) != 0) {
        out = ccl_grow(out, strlen(out) + sizeof "UNKNOWN");
        strcat(out, "UNKNOWN");
    }
    ccl_chomp(out);
    return out;
}

/* SHA3-256 of `git diff HEAD`; a failing git ends the run with its status. */
static void ccl_git_diff_hash(char hex[65])
{
    const char *argv[] = {"git", "diff", "HEAD", nullptr};
    struct ccl_child c = ccl_spawn(argv);
    FILE *fp = fdopen(c.fd, "rb");
    bool ok = fp != nullptr && ccl_hash_stream(fp, hex);
    int rc;

    if (fp != nullptr)
        fclose(fp);
    c.fd = -1;
    rc = ccl_reap(c);
    if (rc != 0)
        ccl_die(rc, "git diff HEAD failed");
    if (!ok)
        ccl_die(1, "read error on git diff HEAD");
}

static char *ccl_repo_root(void)
{
    const char *argv[] = {"git", "rev-parse", "--show-toplevel", nullptr};
    const char *pwd = getenv("PWD");
    struct stat a, b;
    char *root;

    if (ccl_capture(argv, &root) != 0)
        ccl_die(2, "not inside a git work tree");
    ccl_chomp(root);
    if (chdir(root) != 0)
        ccl_die(2, "not inside a git work tree");
    if (pwd != nullptr && pwd[0] == '/' && stat(pwd, &a) == 0 && stat(root, &b) == 0 && a.st_dev == b.st_dev &&
        a.st_ino == b.st_ino) {
        free(root);
        return ccl_dup(pwd);
    }
    return root;
}

/* ---- report ------------------------------------------------------------- */

struct ccl_result {
    struct ccl_gates gates;
    struct ccl_chain chain;
    struct ccl_names missing;
    size_t receipts;
};

static void ccl_collect(struct ccl_ctx *c, const struct ccl_names *paths, struct ccl_result *res)
{
    for (size_t i = 0; i < paths->n; i++) {
        struct ccl_receipt r;
        struct ccl_str notes = {};
        char *buf;
        size_t len;
        bool ok;

        if (!ccl_slurp(paths->v[i], &buf, &len))
            ccl_die(2, "cannot read %s: %s", paths->v[i], strerror(errno));
        ccl_receipt_parse(&r, buf, len);
        ok = ccl_judge_receipt(c, &r, &notes);
        ccl_chain_step(&res->chain, &r, paths->v[i], &notes);
        ccl_gate_record(&res->gates, &r, paths->v[i], ok, &notes);
        ccl_receipt_free(&r);
        free(notes.s);
    }
    res->receipts = paths->n;
    qsort(res->gates.v, res->gates.n, sizeof *res->gates.v, ccl_gate_order);
}

static void ccl_find_missing(const struct ccl_names *req, struct ccl_result *res)
{
    for (size_t i = 0; i < req->n; i++) {
        bool seen = false;

        for (size_t j = 0; j < res->gates.n; j++)
            seen = seen || strcmp(res->gates.v[j].name, req->v[i]) == 0;
        if (!seen)
            ccl_names_push(&res->missing, ccl_dup(req->v[i]));
    }
}

static void ccl_print_table(FILE *o, const struct ccl_ctx *c, const struct ccl_names *req, const struct ccl_result *res)
{
    static const char *const fmt = "%-3s %-22s %-7s %5s %5s %10s  %s\n";

    fprintf(o, "check-claims: %s\n", c->dir);
    fprintf(o, "check-claims: HEAD %s  (%zu receipt(s), %zu distinct gate(s))\n\n", c->head, res->receipts,
            res->gates.n);
    fprintf(o, fmt, "REQ", "GATE", "VERDICT", "RUNS", "FAIL", "WALL_MS", "NOTES");
    fprintf(o, fmt, "---", "----------------------", "-------", "-----", "-----", "----------", "-----");
    for (size_t i = 0; i < res->gates.n; i++) {
        const struct ccl_gate *g = &res->gates.v[i];
        char *runs = ccl_fmt("%zu", g->runs), *failed = ccl_fmt("%zu", g->failed);

        fprintf(o, fmt, ccl_names_has(req, g->name) ? "*" : " ", g->name, g->ok ? "OK" : "BAD", runs, failed,
                g->wall[0] != '\0' ? g->wall : "?", g->note);
        free(runs);
        free(failed);
    }
    fputc('\n', o);
    for (size_t i = 0; i < res->missing.n; i++)
        fprintf(o,
                "  MISSING  %s — claimed, but no receipt exists. Run it as:\n"
                "             tools/agent/gate-receipt.sh --gate %s -- make %s\n",
                res->missing.v[i], res->missing.v[i], res->missing.v[i]);
    if (res->chain.broken.len > 0)
        fprintf(o,
                "  CHAIN    receipt chain does not link: %.*s\n"
                "           (a receipt written or removed after the fact; the chain\n"
                "            is a tell, not a proof — see gate-receipt.sh)\n",
                (int)res->chain.broken.len - 2, res->chain.broken.s);
}

static void ccl_print_json(FILE *o, const struct ccl_ctx *c, const struct ccl_names *req, const struct ccl_result *res)
{
    fprintf(o, "{\n  \"head\": \"%s\",\n  \"receipt_dir\": \"%s\",\n  \"gates\": [\n", c->head, c->dir);
    for (size_t i = 0; i < res->gates.n; i++) {
        const struct ccl_gate *g = &res->gates.v[i];

        if (i > 0)
            fputs("  ,\n", o);
        fprintf(o,
                "    {\"gate\":\"%s\",\"verdict\":\"%s\",\"runs\":%zu,\"failed_runs\":%zu,\"wall_ms\":%s,"
                "\"receipt\":\"%s\",\"notes\":\"%s\",\"required\":%s}\n",
                g->name, g->ok ? "OK" : "BAD", g->runs, g->failed, g->wall[0] != '\0' ? g->wall : "0",
                ccl_base_name(g->receipt), g->note, ccl_names_has(req, g->name) ? "true" : "false");
    }
    fputs("  ],\n  \"missing_required\": [", o);
    for (size_t i = 0; i < res->missing.n; i++)
        fprintf(o, "%s\"%s\"", i > 0 ? ", " : "", res->missing.v[i]);
    fputs("]\n}\n", o);
}

static int ccl_finish(FILE *o, const struct ccl_ctx *c, bool json, const struct ccl_result *res)
{
    size_t problems = res->missing.n + (res->chain.broken.len > 0);

    for (size_t i = 0; i < res->gates.n; i++)
        problems += !res->gates.v[i].ok;
    if (problems > 0) {
        if (!json)
            fprintf(o, "check-claims: FAIL — %zu problem(s); %zu claimed gate(s) without a receipt.\n", problems,
                    res->missing.n);
        return 1;
    }
    if (!json)
        fprintf(o,
                "check-claims: PASS — every receipt is well-formed, describes HEAD %s, and its stored output "
                "still says so.\n",
                c->head);
    return 0;
}

/* Verdict lines for a run that found no receipts to judge. */
static int ccl_no_receipts(FILE *o, const struct ccl_names *req, const char *what, bool fail_line)
{
    fputs(what, o);
    for (size_t i = 0; i < req->n; i++)
        fprintf(o, "check-claims: NO RECEIPT for required gate: %s\n", req->v[i]);
    if (req->n > 0 && fail_line)
        fprintf(o, "check-claims: FAIL — %zu claimed gate(s) have no evidence at all.\n", req->n);
    return req->n > 0 ? 1 : 0;
}

/* ---- run and command line ----------------------------------------------- */

struct ccl_opts {
    const char *require_raw, *dir, *max_age;
    char *require_buf;
    bool strict, json;
};

static int ccl_judge_dir(FILE *o, struct ccl_ctx *c, const struct ccl_opts *op, const struct ccl_names *req,
                         const struct ccl_names *paths)
{
    struct ccl_result res = {.chain = {.expected = -1, .expected_text = ccl_dup("-1"), .prev = "GENESIS"}};
    int rc;

    ccl_collect(c, paths, &res);
    ccl_find_missing(req, &res);
    if (op->json)
        ccl_print_json(o, c, req, &res);
    else
        ccl_print_table(o, c, req, &res);
    rc = ccl_finish(o, c, op->json, &res);
    ccl_gates_free(&res.gates);
    ccl_names_free(&res.missing);
    free(res.chain.broken.s);
    free(res.chain.expected_text);
    return rc;
}

static int ccl_judge_receipts(FILE *o, const struct ccl_opts *op, const char *repo, const struct ccl_names *req)
{
    char diff[65], *head, *dir = ccl_logical_path(repo, op->dir);
    struct ccl_names paths;
    struct ccl_ctx c = {.repo = repo, .dir = dir, .max_age = op->max_age, .lint_gates = -1, .strict = op->strict};
    int rc;

    if (access(dir, X_OK) != 0)
        ccl_die(1, "cannot enter %s: %s", dir, strerror(errno));
    head = ccl_git_head();
    ccl_git_diff_hash(diff);
    c.head = head;
    c.diff = diff;
    c.now = (int64_t)time(nullptr);
    paths = ccl_list_receipts(dir);
    if (paths.n == 0) {
        char *what = ccl_fmt("check-claims: %s holds no *.receipt files\n", dir);

        rc = ccl_no_receipts(o, req, what, false);
        free(what);
    } else {
        rc = ccl_judge_dir(o, &c, op, req, &paths);
    }
    ccl_names_free(&paths);
    free(head);
    free(dir);
    return rc;
}

static int ccl_run(const struct ccl_opts *op, const char *repo, FILE *o)
{
    struct ccl_names req = ccl_split_required(op->require_raw);
    struct stat st;
    int rc;

    if (stat(op->dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        char *what = ccl_fmt("check-claims: no receipt directory at %s\n", op->dir);

        rc = ccl_no_receipts(o, &req, what, true);
        if (req.n == 0)
            fputs("check-claims: nothing claimed and nothing to check.\n", o);
        free(what);
    } else {
        rc = ccl_judge_receipts(o, op, repo, &req);
    }
    ccl_names_free(&req);
    return rc;
}

static const char CCL_HELP[] =
    "# Copyright 2026 Rhett Creighton - Apache License 2.0\n"
    "#\n"
    "# check_claims — judge a lane's gate claims from its receipts, without\n"
    "# re-running a single gate.\n"
    "#\n"
    "# ── WHY THIS EXISTS ────────────────────────────────────────────────────────\n"
    "# \"make lint passed\" costs the orchestrator a full re-run to check. This reads\n"
    "# the receipts tools/agent/gate-receipt.sh left behind and answers three\n"
    "# questions the prose cannot:\n"
    "#\n"
    "#   1. Did the gate run AT ALL for the gate the lane claims? (a claimed gate\n"
    "#      with no receipt is the whole point — it exits non-zero.)\n"
    "#   2. Does the receipt describe THIS tree? (head_sha, worktree, working-tree\n"
    "#      digest — a receipt from three commits ago is not evidence about now.)\n"
    "#   3. Does the STORED OUTPUT still say what the receipt says it says? The\n"
    "#      verdict is re-derived here from the log's own success/failure tokens\n"
    "#      and from the log's SHA3, never taken on the receipt's word.\n"
    "#\n"
    "# Check 3 is what makes the receipt awkward to forge: a `verdict=PASS` line is\n"
    "# one edit, but it has to be backed by a log whose bytes hash to the recorded\n"
    "# digest AND which literally contains the gate's success banner. See the\n"
    "# forgery-model section of gate-receipt.sh for what this does NOT defend\n"
    "# against — chiefly, a lane that writes both files by hand. This is evidence,\n"
    "# not proof.\n"
    "#\n"
    "# ── USAGE ──────────────────────────────────────────────────────────────────\n"
    "#   make check-claims CLAIMS=\"lint t-fast\"\n"
    "#   build/bin/check_claims --require lint,t-fast --dir .cache/agent-receipts\n"
    "#   build/bin/check_claims                    # judge whatever is there\n"
    "#\n"
    "#   --require <a,b>     gates that MUST have a passing receipt. Missing one is\n"
    "#                       a non-zero exit; that is the F7 answer.\n"
    "#   --dir <path>        receipt directory (default $ZCL_RECEIPT_DIR or\n"
    "#                       .cache/agent-receipts).\n"
    "#   --max-age-hours <N> a receipt older than this is STALE_AGE (default: off).\n"
    "#   --strict            also fail on a working-tree digest that has moved\n"
    "#                       since the receipt (default: reported, not fatal —\n"
    "#                       editing a file after a green lint is normal and the\n"
    "#                       orchestrator should see it, not be blocked by it).\n"
    "#   --json              emit machine-readable rows instead of the table.\n"
    ;

static const char *ccl_value(int argc, char **argv, int *i)
{
    const char *v;

    if (*i + 1 >= argc)
        ccl_die(2, "%s needs a value", argv[*i]);
    v = argv[*i + 1];
    *i += 2;
    return v;
}

static void ccl_add_require(struct ccl_opts *op, const char *value)
{
    char *joined = ccl_fmt("%s,%s", op->require_raw, value);

    free(op->require_buf);
    op->require_buf = joined;
    op->require_raw = joined;
}

static void ccl_check_max_age(const char *v)
{
    int64_t n;

    if (!ccl_test_int(v, &n) || n < 0)
        ccl_die(2, "--max-age-hours needs a non-negative integer\n"
                   "usage: check_claims [--require a,b] [--dir PATH] [--max-age-hours N] [--strict] [--json]");
}

/* Applies the options in order; true when --help was printed. */
static bool ccl_parse_args(struct ccl_opts *op, int argc, char **argv)
{
    for (int i = 1; i < argc;) {
        const char *a = argv[i];

        if (strcmp(a, "--require") == 0) {
            ccl_add_require(op, ccl_value(argc, argv, &i));
        } else if (strcmp(a, "--dir") == 0) {
            op->dir = ccl_value(argc, argv, &i);
        } else if (strcmp(a, "--max-age-hours") == 0) {
            op->max_age = ccl_value(argc, argv, &i);
            ccl_check_max_age(op->max_age);
        } else if (strcmp(a, "--strict") == 0) {
            op->strict = true;
            i++;
        } else if (strcmp(a, "--json") == 0) {
            op->json = true;
            i++;
        } else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            if (fputs(CCL_HELP, stdout) < 0)
                ccl_die(2, "cannot write the help text");
            return true;
        } else {
            ccl_die(2, "unknown option '%s'", a);
        }
    }
    return false;
}

static int ccl_emit(const struct ccl_opts *op, const char *repo)
{
    char *text = nullptr;
    size_t len = 0;
    FILE *o = open_memstream(&text, &len);
    int rc;

    if (o == nullptr)
        ccl_die(2, "cannot buffer the report");
    rc = ccl_run(op, repo, o);
    fclose(o);
    if (fwrite(text, 1, len, stdout) != len || fflush(stdout) != 0)
        ccl_die(2, "cannot write the report");
    free(text);
    return rc;
}

/* ---- selftest ----------------------------------------------------------- */

static int ccl_failures;
static int ccl_checks;

static void ccl_check(bool ok, const char *what)
{
    ccl_checks++;
    if (!ok) {
        ccl_failures++;
        fprintf(stderr, "check_claims selftest: FAIL %s\n", what);
    }
}

static void ccl_check_str(const char *got, const char *want, const char *what)
{
    bool ok = strcmp(got, want) == 0;

    ccl_check(ok, what);
    if (!ok)
        fprintf(stderr, "  got:  %s\n  want: %s\n", got, want);
}

static FILE *ccl_stream(const char *text)
{
    return fmemopen((void *)(uintptr_t)text, strlen(text), "rb");
}

static void ccl_selftest_numbers(void)
{
    int64_t v = 0;
    char hex[65];

    ccl_hash_bytes("abc", 3, hex);
    ccl_check_str(hex, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532", "sha3-256 of abc");
    ccl_check(ccl_test_int(" -12 ", &v) && v == -12, "test_int accepts blanks and sign");
    ccl_check(!ccl_test_int("abc", &v) && !ccl_test_int("", &v) && !ccl_test_int("1.5", &v), "test_int refuses text");
    ccl_check(!ccl_test_int("99999999999999999999", &v), "test_int refuses overflow");
    ccl_check(ccl_test_int("9223372036854775807", &v) && v == INT64_MAX, "test_int int64 max");
    ccl_check(ccl_int_gt("3", "2") && !ccl_int_gt("2", "2") && !ccl_int_gt("x", "1"), "int_gt");
    ccl_check(ccl_parse_iso_utc("2026-10-14T09:02:48Z", &v) && v == 1791968568, "iso epoch");
    ccl_check(ccl_parse_iso_utc("2024-02-29T00:00:00Z", &v) && v == 1709164800, "iso leap day");
    ccl_check(ccl_parse_iso_utc("1970-01-01T00:00:00Z", &v) && v == 0, "iso zero");
    ccl_check(!ccl_parse_iso_utc("2026-02-30T00:00:00Z", &v), "iso refuses Feb 30");
    ccl_check(!ccl_parse_iso_utc("2026-10-14T09:02:48+00:00", &v), "iso refuses offsets");
    ccl_check(!ccl_parse_iso_utc("2026-10-14T24:00:00Z", &v), "iso refuses hour 24");
    ccl_check(ccl_parse_idx("007") == 7 && ccl_parse_idx("x") == -1 && ccl_parse_idx("") == -1, "chain index");
    ccl_check(ccl_parse_idx("99999999999999999999") == INT64_MAX, "chain index saturates");
}

static void ccl_selftest_text(void)
{
    struct ccl_names l = ccl_split_required("lint, t-fast,lint,,x\nignored");
    char *p;

    ccl_check(l.n == 3 && strcmp(l.v[0], "lint") == 0 && strcmp(l.v[1], "t-fast") == 0 && strcmp(l.v[2], "x") == 0,
              "required list is deduped and stops at newline");
    ccl_names_free(&l);
    l = ccl_split_required(", ,");
    ccl_check(l.n == 0, "required list of separators is empty");
    ccl_names_free(&l);
    p = ccl_logical_path("/r", "a/../b/./c");
    ccl_check_str(p, "/r/b/c", "logical path folds dot segments");
    free(p);
    p = ccl_logical_path("/r", "/x//y/..");
    ccl_check_str(p, "/x", "logical path of an absolute path");
    free(p);
    p = ccl_logical_path("/r", "..");
    ccl_check_str(p, "/", "logical path of the root");
    free(p);
    ccl_check(ccl_body_len("a\nb\n", 4) == 2 && ccl_body_len("a", 1) == 0 && ccl_body_len("", 0) == 0 &&
                  ccl_body_len("a\n\n", 3) == 2 && ccl_body_len("a\nb", 3) == 2,
              "body drops exactly the last line");
    ccl_check(ccl_is_receipt_name("a.receipt") && !ccl_is_receipt_name(".receipt") &&
                  !ccl_is_receipt_name(".a.receipt") && !ccl_is_receipt_name("a.receipts"),
              "receipt names follow the glob");
}

static void ccl_selftest_receipt(void)
{
    static const char text[] = "receipt_schema=zcl.gate_receipt.v1\ngate=lint\ngate=lint2\nexpect_token=a b\n"
                               "expect_token=\nforbid_token=BAD\nexpect_tokens=1\nreceipt_sha3=zz";
    struct ccl_receipt r;
    char hex[65];

    ccl_receipt_parse(&r, ccl_dup(text), strlen(text));
    ccl_check_str(r.gate, "lint2", "last key occurrence wins");
    ccl_check_str(r.verdict, "", "absent key reads empty");
    ccl_check_str(r.n_expect, "1", "expect_tokens count is its own key");
    ccl_check_str(r.self_sha3, "zz", "unterminated final line is read");
    ccl_check(r.n_exp == 1 && strcmp(r.expect[0], "a b") == 0 && r.n_forb == 1 && strcmp(r.forbid[0], "BAD") == 0,
              "token lines accumulate and empty ones are skipped");
    ccl_hash_bytes(text, strlen(text) - strlen("receipt_sha3=zz"), hex);
    ccl_check_str(r.body_sha3, hex, "body digest excludes the last line");
    ccl_receipt_free(&r);
}

static void ccl_selftest_scan(void)
{
    static const char *const tok[] = {"PASS check-", "absent", "yy"};
    static const char text[] = "xxPASS check-yy";

    for (size_t chunk = 1; chunk <= 8; chunk++) {
        bool found[3] = {false, false, false};
        FILE *fp = ccl_stream(text);

        ccl_check(ccl_scan_tokens(fp, tok, 3, found, chunk) && found[0] && !found[1] && found[2],
                  "token spanning two reads is found");
        fclose(fp);
    }
}

static void ccl_selftest_shape(void)
{
    static const char gates[] = "PASS check-a\nFAIL check-b\nCACHED check-c\nPASS other\n  PASS check-x\n"
                                "################################ long junk line\nPASS check-d";
    static const char mk[] = "A=1\nLINT_GATES := check-a \\\n   check-b $(X) \\\n check-c\nLINT_GATES = check-z\n";
    size_t n = 0;
    FILE *fp = ccl_stream(gates);
    struct ccl_str notes = {};

    ccl_check(ccl_count_gate_lines(fp, &n) && n == 4, "gate lines counted");
    fclose(fp);
    fp = ccl_stream(mk);
    ccl_check(ccl_lint_gate_count(fp) == 3, "lint gate count follows continuations");
    fclose(fp);
    fp = ccl_stream("LINT_GATES ::= check-q\n");
    ccl_check(ccl_lint_gate_count(fp) == 0, "only := and = define LINT_GATES");
    fclose(fp);
    ccl_check(ccl_shape_ok(0, 0, false, &notes) && ccl_shape_ok(5, 5, false, &notes) && notes.len == 0,
              "shape floor met");
    ccl_check(ccl_shape_ok(5, 0, true, &notes) && strcmp(notes.s, "SHAPE_SERIAL") == 0, "serial log accepted");
    ccl_check(!ccl_shape_ok(5, 3, false, &notes) && strstr(notes.s, "SHAPE_TOO_SMALL(3/5 gate lines)") != nullptr,
              "short log refused");
    free(notes.s);
}

static void ccl_selftest_log(void)
{
    static const char log[] = "PASS check-a\nall checks passed\n";
    struct ccl_ctx c = {.repo = "/r", .dir = "/d", .lint_gates = 3};
    struct ccl_str notes = {};
    struct ccl_receipt r;
    char text[512], hex[65];
    FILE *fp;

    ccl_hash_bytes(log, strlen(log), hex);
    snprintf(text, sizeof text, "gate=t-fast\noutput_sha3=%s\nexpect_token=all checks passed\nforbid_token=FAIL\n", hex);
    ccl_receipt_parse(&r, ccl_dup(text), strlen(text));
    fp = ccl_stream(log);
    ccl_check(ccl_judge_log(&c, &r, fp, &notes) && notes.len == 0, "log with its tokens passes");
    fclose(fp);
    r.expect[0] = (char *)"never printed";
    fp = ccl_stream(log);
    ccl_check(!ccl_judge_log(&c, &r, fp, &notes) && strcmp(notes.s, "SUCCESS_TOKEN_ABSENT") == 0, "absent token");
    fclose(fp);
    r.expect[0] = (char *)"all checks";
    r.forbid[0] = (char *)"PASS";
    fp = ccl_stream(log);
    ccl_check(!ccl_judge_log(&c, &r, fp, &notes) && strstr(notes.s, "FAILURE_TOKEN_PRESENT") != nullptr,
              "forbidden token");
    fclose(fp);
    r.gate = (char *)"lint";
    r.forbid[0] = (char *)"zzz";
    fp = ccl_stream(log);
    ccl_check(!ccl_judge_log(&c, &r, fp, &notes) && strstr(notes.s, "SHAPE_TOO_SMALL(1/3 gate lines)") != nullptr,
              "lint log below the gate-line floor");
    fclose(fp);
    r.out_sha3 = (char *)"0";
    fp = ccl_stream(log);
    ccl_check(!ccl_judge_log(&c, &r, fp, &notes) && strstr(notes.s, "OUTPUT_ALTERED") != nullptr, "digest mismatch");
    fclose(fp);
    free(notes.s);
    ccl_receipt_free(&r);
}

static void ccl_selftest_fields(void)
{
    static const char text[] = "receipt_schema=bad\nexit_status=2\nverdict=FAIL\nhead_sha=0123456789abcdef\n"
                               "worktree_path=/other\ntree_diff_sha3_after=x\nexpect_tokens=0\nforbid_tokens=0\n";
    struct ccl_ctx c = {.repo = "/r", .head = "fedcba", .diff = "y", .max_age = "0"};
    struct ccl_str notes = {};
    struct ccl_receipt r;

    ccl_receipt_parse(&r, ccl_dup(text), strlen(text));
    ccl_check(!ccl_judge_header(&r, &notes) && strcmp(notes.s, "BAD_SCHEMA(bad),NO_GATE_FIELD,RECEIPT_ALTERED") == 0,
              "header notes");
    free(notes.s);
    notes = (struct ccl_str){};
    ccl_check(!ccl_judge_tree(&c, &r, &notes) &&
                  strcmp(notes.s, "STALE_HEAD(012345678),FOREIGN_WORKTREE,TREE_MOVED") == 0,
              "tree notes");
    free(notes.s);
    notes = (struct ccl_str){};
    ccl_check(!ccl_judge_status(&r, &notes) && strcmp(notes.s, "EXIT_2,RECORDED_FAIL,EXIT_STATUS_ONLY") == 0,
              "status notes");
    free(notes.s);
    notes = (struct ccl_str){};
    c.head = c.repo = "";
    r.worktree = r.head = r.tree_diff = (char *)"";
    c.diff = "q";
    ccl_check(ccl_judge_tree(&c, &r, &notes) && strcmp(notes.s, "TREE_MOVED") == 0, "moved tree is not fatal");
    c.strict = true;
    ccl_check(!ccl_judge_tree(&c, &r, &notes), "moved tree is fatal under --strict");
    free(notes.s);
    ccl_receipt_free(&r);
}

static void ccl_selftest_parse(struct ccl_receipt *r, const char *text)
{
    ccl_receipt_parse(r, ccl_dup(text), strlen(text));
}

static void ccl_selftest_judges(void)
{
    static const char sealed[] = "receipt_schema=zcl.gate_receipt.v1\ngate=g\n";
    struct ccl_ctx c = {.dir = "/nonexistent-check-claims-dir", .max_age = "1"};
    struct ccl_str notes = {};
    struct ccl_receipt r;
    char text[256], hex[65];
    int64_t t0 = 0;

    ccl_parse_iso_utc("2026-10-14T09:02:48Z", &t0);
    ccl_check(ccl_epoch_of("2026-10-14T09:02:48Z") == t0, "epoch of an ISO timestamp");
    ccl_check(ccl_epoch_of("not a date at all") == 0, "epoch of an unparsable timestamp");
    ccl_selftest_parse(&r, "started_at_utc=2026-10-14T09:02:48Z\n");
    c.now = t0 + 60;
    ccl_check(ccl_judge_age(&c, &r, &notes) && notes.len == 0, "fresh receipt is not stale");
    c.now = t0 + 7200;
    ccl_check(!ccl_judge_age(&c, &r, &notes) && strcmp(notes.s, "STALE_AGE(2h)") == 0, "old receipt is stale");
    c.max_age = "0";
    ccl_check(ccl_judge_age(&c, &r, &notes), "age check is off at 0");
    ccl_receipt_free(&r);
    free(notes.s);
    notes = (struct ccl_str){};
    ccl_selftest_parse(&r, "gate=g\noutput_path=x.log\n");
    ccl_check(!ccl_judge_output(&c, &r, &notes) && strcmp(notes.s, "OUTPUT_MISSING") == 0, "missing log");
    ccl_receipt_free(&r);
    free(notes.s);
    notes = (struct ccl_str){};
    ccl_hash_bytes(sealed, strlen(sealed), hex);
    snprintf(text, sizeof text, "%sreceipt_sha3=%s\n", sealed, hex);
    ccl_receipt_parse(&r, ccl_dup(text), strlen(text));
    ccl_check(ccl_judge_header(&r, &notes) && notes.len == 0, "matching self digest passes");
    ccl_receipt_free(&r);
    text[strlen(sealed) - 2] = 'h';
    ccl_receipt_parse(&r, ccl_dup(text), strlen(text));
    ccl_check(!ccl_judge_header(&r, &notes) && strcmp(notes.s, "RECEIPT_ALTERED") == 0, "one altered byte");
    ccl_receipt_free(&r);
    free(notes.s);
}

static void ccl_selftest_chain_overflow(void)
{
    struct ccl_chain ch = {.expected = INT64_MAX, .expected_text = ccl_dup("x"), .prev = "GENESIS"};
    struct ccl_str notes = {};
    struct ccl_receipt r;

    ccl_selftest_parse(&r, "chain_index=99999999999999999999\nprev_receipt_sha3=GENESIS\n");
    ccl_chain_step(&ch, &r, "/d/x.receipt", &notes);
    ccl_check(ch.broken.len > 0 && strncmp(ch.broken.s, "index 99999999999999999999 follows x", 36) == 0,
              "chain index overflow is a break");
    ccl_receipt_free(&r);
    free(ch.broken.s);
    free(ch.expected_text);
    free(notes.s);
}

static void ccl_selftest_report(void)
{
    static const char want[] =
        "check-claims: /d\n"
        "check-claims: HEAD h  (2 receipt(s), 1 distinct gate(s))\n\n"
        "REQ GATE                   VERDICT  RUNS  FAIL    WALL_MS  NOTES\n"
        "--- ---------------------- ------- ----- ----- ----------  -----\n"
        "*   lint                   BAD         2     1         12  EXIT_1\n\n"
        "  MISSING  t-fast — claimed, but no receipt exists. Run it as:\n"
        "             tools/agent/gate-receipt.sh --gate t-fast -- make t-fast\n"
        "  CHAIN    receipt chain does not link: index 5 follows 0\n"
        "           (a receipt written or removed after the fact; the chain\n"
        "            is a tell, not a proof — see gate-receipt.sh)\n"
        "check-claims: FAIL — 3 problem(s); 1 claimed gate(s) without a receipt.\n";
    static const char r0[] = "gate=lint\nchain_index=0\nwall_ms=5\nprev_receipt_sha3=GENESIS\n";
    struct ccl_ctx c = {.dir = "/d", .head = "h"};
    struct ccl_result res = {.chain = {.expected = -1, .expected_text = ccl_dup("-1"), .prev = "GENESIS"}};
    struct ccl_names req = ccl_split_required("lint,t-fast");
    struct ccl_str ok = {}, bad = {};
    char *text = nullptr;
    size_t len = 0;
    struct ccl_receipt r;
    FILE *o = open_memstream(&text, &len);
    char r1[256], hex[65];

    ccl_hash_bytes(r0, strlen(r0), hex);
    snprintf(r1, sizeof r1, "gate=lint\nchain_index=5\nwall_ms=12\nprev_receipt_sha3=%s\n", hex);

    ccl_str_add(&bad, ',', "EXIT_1");
    for (int i = 0; i < 2; i++) {
        ccl_receipt_parse(&r, ccl_dup(i == 0 ? r0 : r1), strlen(i == 0 ? r0 : r1));
        ccl_chain_step(&res.chain, &r, "/d/x.receipt", i == 0 ? &ok : &bad);
        ccl_gate_record(&res.gates, &r, "/d/x.receipt", i == 0, i == 0 ? &ok : &bad);
        ccl_receipt_free(&r);
    }
    res.receipts = 2;
    ccl_find_missing(&req, &res);
    ccl_print_table(o, &c, &req, &res);
    ccl_check(ccl_finish(o, &c, false, &res) == 1, "a broken chain fails the run");
    fclose(o);
    ccl_check_str(text, want, "table report");
    free(text);
    ccl_gates_free(&res.gates);
    ccl_names_free(&res.missing);
    ccl_names_free(&req);
    free(res.chain.broken.s);
    free(res.chain.expected_text);
    free(ok.s);
    free(bad.s);
}

static int ccl_selftest(void)
{
    ccl_selftest_numbers();
    ccl_selftest_text();
    ccl_selftest_receipt();
    ccl_selftest_scan();
    ccl_selftest_shape();
    ccl_selftest_log();
    ccl_selftest_fields();
    ccl_selftest_judges();
    ccl_selftest_chain_overflow();
    ccl_selftest_report();
    printf("check_claims selftest: %d checks, %d failed\n", ccl_checks, ccl_failures);
    return ccl_failures == 0 ? 0 : 1;
}

int main(int argc, char **argv)
{
    const char *env_dir = getenv("ZCL_RECEIPT_DIR"), *claims = getenv("CLAIMS");
    struct ccl_opts op = {.require_raw = claims != nullptr ? claims : "",
                          .dir = env_dir != nullptr && env_dir[0] != '\0' ? env_dir : nullptr,
                          .max_age = "0"};
    char *repo, *dir = nullptr;
    int rc;

    setlocale(LC_COLLATE, "");
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return ccl_selftest();
    if (ccl_parse_args(&op, argc, argv)) {
        free(op.require_buf);
        return 0;
    }
    repo = ccl_repo_root();
    if (op.dir == nullptr) {
        dir = ccl_fmt("%s/.cache/agent-receipts", repo);
        op.dir = dir;
    }
    rc = ccl_emit(&op, repo);
    free(dir);
    free(repo);
    free(op.require_buf);
    return rc;
}
