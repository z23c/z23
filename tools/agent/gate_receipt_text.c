/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_receipt - buffers, SHA3-256 digests, file mappings, shell-compatible
 * argv display, token search and path helpers.
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "gate_receipt.h"

#include "base/hex.h"
#include "base/safe_alloc.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>
#include <wctype.h>

/* ---- memory ------------------------------------------------------------- */

void *gtr_grow(void *p, size_t n)
{
    void *q = zcl_realloc(p, n, "gate_receipt");

    if (q == nullptr)
        gtr_die("out of memory");
    return q;
}

void gtr_buf_add(struct gtr_buf *b, const void *p, size_t n)
{
    size_t cap = b->cap;

    if (n == 0)
        return;
    if (b->len + n + 1 > cap) {
        cap = cap ? cap : 256;
        while (cap < b->len + n + 1)
            cap *= 2;
        b->p = gtr_grow(b->p, cap);
        b->cap = cap;
    }
    memcpy(b->p + b->len, p, n);
    b->len += n;
    b->p[b->len] = '\0';
}

const char *gtr_buf_str(struct gtr_buf *b)
{
    return b->p != nullptr ? b->p : "";
}


void gtr_buf_addf(struct gtr_buf *b, const char *fmt, ...)
{
    va_list ap, cp;
    int n;

    va_start(ap, fmt);
    va_copy(cp, ap);
    n = vsnprintf(nullptr, 0, fmt, cp);
    va_end(cp);
    if (n < 0)
        gtr_die("formatting failed");
    char *tmp = gtr_grow(nullptr, (size_t)n + 1);
    vsnprintf(tmp, (size_t)n + 1, fmt, ap);
    va_end(ap);
    gtr_buf_add(b, tmp, (size_t)n);
    free(tmp);
}

/* Command substitution drops trailing newlines; the receipt format
 * depends on the same trimming. */
void gtr_buf_chomp(struct gtr_buf *b)
{
    while (b->len > 0 && b->p[b->len - 1] == '\n')
        b->p[--b->len] = '\0';
}


char *gtr_fmt(const char *fmt, ...)
{
    va_list ap, cp;
    int n;
    char *out;

    va_start(ap, fmt);
    va_copy(cp, ap);
    n = vsnprintf(nullptr, 0, fmt, cp);
    va_end(cp);
    if (n < 0)
        gtr_die("formatting failed");
    out = gtr_grow(nullptr, (size_t)n + 1);
    vsnprintf(out, (size_t)n + 1, fmt, ap);
    va_end(ap);
    return out;
}


/* ---- digests ------------------------------------------------------------ */

void gtr_sha3_buf(const void *p, size_t n, char hex[65])
{
    struct sha3_256_ctx ctx;
    unsigned char digest[SHA3_256_OUTPUT_SIZE];

    sha3_256_init(&ctx);
    if (n > 0)
        sha3_256_write(&ctx, p, n);
    sha3_256_finalize(&ctx, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
}

void gtr_sha3_sink(void *ctx, const char *p, size_t n)
{
    sha3_256_write(ctx, (const unsigned char *)p, n);
}

void gtr_sha3_done(struct sha3_256_ctx *ctx, char hex[65])
{
    unsigned char digest[SHA3_256_OUTPUT_SIZE];

    sha3_256_finalize(ctx, digest);
    zcl_hex_encode(digest, sizeof digest, hex);
}

int gtr_map_open(const char *path, struct gtr_map *m)
{
    struct stat st;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    void *p;

    m->p = "";
    m->len = 0;
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || st.st_size < 0) {
        close(fd);
        return -1;
    }
    if (st.st_size > 0) {
        p = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        if (p == MAP_FAILED) {
            close(fd);
            return -1;
        }
        m->p = p;
        m->len = (size_t)st.st_size;
    }
    close(fd);
    return 0;
}

void gtr_map_close(struct gtr_map *m)
{
    if (m->len > 0)
        munmap((void *)m->p, m->len);
}

/* ---- shell-compatible argv display (printf %q) -------------------------- */

static bool gtr_mb_char(const char *s, size_t left, size_t *clen)
{
    mbstate_t st = {0};
    wchar_t wc;
    size_t n;

    if (MB_CUR_MAX == 1) {
        *clen = 1;
        return isprint((unsigned char)*s) != 0;
    }
    n = mbrtowc(&wc, s, left, &st);
    if (n == (size_t)-1 || n == (size_t)-2 || n == 0) {
        *clen = 1;
        return false;
    }
    *clen = n;
    return iswprint((wint_t)wc) != 0;
}

static bool gtr_needs_ansic(const char *s)
{
    size_t left = strlen(s);

    while (left > 0) {
        size_t clen;

        if (!gtr_mb_char(s, left, &clen))
            return true;
        s += clen;
        left -= clen;
    }
    return false;
}

static void gtr_ansic_byte(struct gtr_buf *b, unsigned char c)
{
    static const char esc[] = {7, 'a', 8, 'b', 9, 't', 10, 'n', 11, 'v', 12, 'f', 13, 'r',
                               27, 'E', '\\', '\\', '\'', '\''};

    for (size_t i = 0; i < sizeof esc; i += 2) {
        if (esc[i] == (char)c) {
            gtr_buf_addf(b, "\\%c", esc[i + 1]);
            return;
        }
    }
    gtr_buf_addf(b, "\\%03o", c);
}

static void gtr_quote_ansic(struct gtr_buf *b, const char *s)
{
    size_t left = strlen(s);

    gtr_buf_add(b, "$'", 2);
    while (left > 0) {
        size_t clen;
        bool printable = gtr_mb_char(s, left, &clen);
        bool plain = (unsigned char)*s >= 0x20 && *s != 0x7f && *s != '\\' && *s != '\'';

        if (printable && (plain || (unsigned char)*s >= 0x80)) {
            gtr_buf_add(b, s, clen);
        } else {
            gtr_ansic_byte(b, (unsigned char)*s);
            clen = 1;
        }
        s += clen;
        left -= clen;
    }
    gtr_buf_add(b, "'", 1);
}

void gtr_quote_word(struct gtr_buf *b, const char *s)
{
    static const char special[] = " !\"$&'()*,;<>?[\\]^`{|}";

    if (*s == '\0') {
        gtr_buf_add(b, "''", 2);
        return;
    }
    if (gtr_needs_ansic(s)) {
        gtr_quote_ansic(b, s);
        return;
    }
    for (const char *p = s; *p != '\0'; p++) {
        bool lead = p == s && (*p == '~' || *p == '#');

        if (lead || strchr(special, *p) != nullptr)
            gtr_buf_add(b, "\\", 1);
        gtr_buf_add(b, p, 1);
    }
}

/* ---- text helpers ------------------------------------------------------- */

bool gtr_is_digits(const char *s)
{
    if (*s == '\0')
        return false;
    for (; *s != '\0'; s++)
        if (*s < '0' || *s > '9')
            return false;
    return true;
}

bool gtr_slug_ok(const char *s)
{
    for (; *s != '\0'; s++) {
        bool ok = (*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') ||
                  (*s >= '0' && *s <= '9') || *s == '_' || *s == '.' || *s == '-';

        if (!ok)
            return false;
    }
    return true;
}

/* grep -F semantics: a newline separates alternatives and an empty
 * alternative matches every line, so it matches any non-empty input. */
static bool gtr_find(const struct gtr_map *m, const char *pat, size_t plen)
{
    if (plen == 0)
        return m->len > 0;
    for (size_t i = 0; i + plen <= m->len; i++) {
        const char *at = memchr(m->p + i, (unsigned char)pat[0], m->len - i - plen + 1);

        if (at == nullptr)
            return false;
        i = (size_t)(at - m->p);
        if (memcmp(at, pat, plen) == 0)
            return true;
    }
    return false;
}

bool gtr_token_present(const struct gtr_map *m, const char *token)
{
    const char *start = token;

    for (;;) {
        const char *nl = strchr(start, '\n');
        size_t plen = nl != nullptr ? (size_t)(nl - start) : strlen(start);

        if (gtr_find(m, start, plen))
            return true;
        if (nl == nullptr)
            return false;
        start = nl + 1;
    }
}

size_t gtr_count_newlines(const struct gtr_map *m)
{
    size_t n = 0;

    for (size_t i = 0; i < m->len; i++)
        n += m->p[i] == '\n';
    return n;
}

/* ---- filesystem --------------------------------------------------------- */

int gtr_mkdir_p(const char *path)
{
    char *copy = gtr_fmt("%s", path);
    struct stat st;
    int rc = 0;

    if (*path == '\0') {
        free(copy);
        errno = ENOENT;
        return -1;
    }
    for (char *p = copy + 1; *p != '\0' && rc == 0; p++) {
        if (*p != '/')
            continue;
        *p = '\0';
        if (mkdir(copy, 0777) != 0 && errno != EEXIST)
            rc = -1;
        *p = '/';
    }
    if (rc == 0 && mkdir(copy, 0777) != 0 && (errno != EEXIST || stat(copy, &st) != 0 || !S_ISDIR(st.st_mode)))
        rc = -1;
    free(copy);
    return rc;
}

static bool gtr_same_dir(const char *a, const char *b)
{
    struct stat sa, sb;

    return stat(a, &sa) == 0 && stat(b, &sb) == 0 && sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

static char *gtr_logical_cwd(void)
{
    const char *pwd = getenv("PWD");
    char *buf;

    if (pwd != nullptr && pwd[0] == '/' && gtr_same_dir(pwd, "."))
        return gtr_fmt("%s", pwd);
    buf = gtr_grow(nullptr, PATH_MAX);
    if (getcwd(buf, PATH_MAX) == nullptr)
        gtr_die("cannot determine the working directory: %s", strerror(errno));
    return buf;
}

/* The absolute path a shell `cd DIR && pwd` reports: lexical, symlinks kept. */
char *gtr_logical_path(const char *dir)
{
    struct gtr_buf out = {0};
    char *joined = dir[0] == '/' ? gtr_fmt("%s", dir) : gtr_fmt("%s/%s", gtr_logical_cwd(), dir);
    char *save = nullptr;

    for (char *part = strtok_r(joined, "/", &save); part != nullptr; part = strtok_r(nullptr, "/", &save)) {
        if (strcmp(part, ".") == 0 || *part == '\0')
            continue;
        if (strcmp(part, "..") == 0) {
            char *slash = out.len > 0 ? strrchr(out.p, '/') : nullptr;

            out.len = slash != nullptr ? (size_t)(slash - out.p) : 0;
            if (out.p != nullptr)
                out.p[out.len] = '\0';
            continue;
        }
        gtr_buf_add(&out, "/", 1);
        gtr_buf_add(&out, part, strlen(part));
    }
    if (out.len == 0)
        gtr_buf_add(&out, "/", 1);
    free(joined);
    return out.p;
}

