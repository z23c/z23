/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Purpose: dependency vulnerability audit for the vendored libraries (OpenSSL,
 * SQLite, libevent, leveldb, zlib, libsecp256k1). The C successor of the old
 * tools/dep_audit.sh: the same checks, the same text and --json layout, and the
 * same exit status: 0 when every check passes, 1 when any finding exists.
 *
 * Usage:  build/bin/dep_audit [--json]        (make audit, make vendor-ready)
 *
 * The repository root is the nearest ancestor of the working directory that
 * holds tools/scripts/build_vendor.sh, else the working directory itself.
 *
 * Installed bytes must first match the deterministic build provenance. The
 * provenance check runs build_vendor.sh --check-provenance with no shell, its
 * output captured and discarded, and only an observed exit 0 is a pass; a
 * launch failure, a timeout or an unobserved status fails closed.
 *
 * Version strings are found the way `strings` plus the old grep patterns found
 * them: printable runs of at least four bytes, first match wins. Versions
 * compare in `sort -V` order, numerically per digit run. An unreadable or
 * unmatched version is "unknown", which is a finding.
 */

#include "base/safe_alloc.h"
#include "platform/clock.h"
#include "util/spawn.h"

#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define BUILD_VENDOR_REL "tools/scripts/build_vendor.sh"
#define VENDOR_LIB_REL "vendor/lib"
#define VENDOR_INC_REL "vendor/include"
#define PROVENANCE_TIMEOUT_MS 600000
#define PROVENANCE_CAPTURE_BYTES (64u * 1024u)
#define ARCHIVE_MAX_BYTES (512ull * 1024ull * 1024ull)
#define MIN_RUN 4
#define VERSION_CAP 128
#define DETAIL_CAP 512
#define JSON_ROW_CAP 1024
#define MAX_ROWS 8
#define UNKNOWN "unknown"
#define GREEN "\033[32m"
#define RED "\033[31m"
#define RESET "\033[0m"
#define SQLITE_DEFINE "#define SQLITE_VERSION "
#define STAMP_KEY "version="

/* Minimum safe versions. Update when new advisories drop. */
#define OPENSSL_MIN "3.0.16"
#define OPENSSL_NOTE "CVE-2024-12797 (MITM on RFC7250), CVE-2024-9143 (low-level bignum OOB)"
#define SQLITE_MIN "3.46.0"
#define SQLITE_NOTE "CVE-2024-0232 (jsonb blob crash)"
#define LIBEVENT_MIN "2.1.12"
#define LIBEVENT_NOTE "no known CVEs in 2.1.12"
#define LEVELDB_MIN "1.18"
#define LEVELDB_NOTE "no known CVEs"
#define ZLIB_MIN "1.2.12"
#define ZLIB_NOTE "CVE-2022-37434 (heap OOB inflate)"

/* What a version string looks like inside an archive: a fixed prefix, a count
 * of dotted numeric components, an optional extra component and a literal
 * suffix the version must be followed by. */
struct probe {
    const char *prefix;
    unsigned components;
    bool optional_tail;
    const char *suffix;
};

static const struct probe PROBE_OPENSSL = { "OpenSSL ", 3, false, "" };
static const struct probe PROBE_ZLIB = { "deflate ", 2, true, "" };
static const struct probe PROBE_LIBEVENT = { "", 3, false, "-stable" };

struct versions {
    char openssl[VERSION_CAP];
    char sqlite[VERSION_CAP];
    char libevent[VERSION_CAP];
    char leveldb[VERSION_CAP];
    char zlib[VERSION_CAP];
};

struct row {
    const char *name;
    const char *version;
    const char *minimum;
    bool at_least;
    bool pass;
    const char *text_detail;
    const char *json_detail;
};

struct audit {
    bool json;
    int fail;
    size_t rows;
    char json_rows[MAX_ROWS][JSON_ROW_CAP];
};

static unsigned char scratch[PROVENANCE_CAPTURE_BYTES];

/* ── byte helpers ─────────────────────────────────────────────────────── */

static bool is_digit(unsigned char c)
{
    return c >= '0' && c <= '9';
}

static bool is_printable(unsigned char c)
{
    return (c >= 0x20 && c <= 0x7e) || c == '\t';
}

static void build_path(char *out, size_t cap, const char *root, const char *rel)
{
    int n = snprintf(out, cap, "%s/%s", root, rel);
    if (n < 0 || (size_t)n >= cap)
        out[0] = '\0';
}

/* Reads a regular file whole, bounded. NULL when it is missing, not a regular
 * file, too large or unreadable. The caller frees the buffer. */
static unsigned char *read_regular(const char *path, size_t *len)
{
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (unsigned long long)st.st_size > ARCHIVE_MAX_BYTES)
        return NULL;
    size_t n = (size_t)st.st_size;
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return NULL;
    unsigned char *buf = zcl_malloc(n + 1, "dep_audit file");
    bool ok = buf != NULL && fread(buf, 1, n, fp) == n && !ferror(fp);
    fclose(fp);
    if (!ok) {
        free(buf);
        return NULL;
    }
    *len = n;
    return buf;
}

static bool copy_span(const unsigned char *s, size_t n, char *out, size_t cap)
{
    if (n >= cap)
        return false;
    memcpy(out, s, n);
    out[n] = '\0';
    return true;
}

static bool contains(const unsigned char *s, size_t n, const char *needle)
{
    size_t m = strlen(needle);
    for (size_t i = 0; m <= n && i <= n - m; i++) {
        if (memcmp(s + i, needle, m) == 0)
            return true;
    }
    return false;
}

/* ── version extraction ───────────────────────────────────────────────── */

static void take_digits(const unsigned char *s, size_t n, size_t *pos)
{
    while (*pos < n && is_digit(s[*pos]))
        (*pos)++;
}

static bool take_dotted(const unsigned char *s, size_t n, size_t *pos,
                        unsigned components)
{
    for (unsigned k = 0; k < components; k++) {
        if (k > 0) {
            if (*pos >= n || s[*pos] != '.')
                return false;
            (*pos)++;
        }
        size_t start = *pos;
        take_digits(s, n, pos);
        if (*pos == start)
            return false;
    }
    return true;
}

static bool probe_at(const unsigned char *s, size_t n, size_t at,
                     const struct probe *p, size_t *vs, size_t *ve)
{
    size_t plen = strlen(p->prefix);
    if (n - at < plen || memcmp(s + at, p->prefix, plen) != 0)
        return false;
    size_t pos = at + plen;
    if (!take_dotted(s, n, &pos, p->components))
        return false;
    if (p->optional_tail && pos + 1 < n && s[pos] == '.' &&
        is_digit(s[pos + 1])) {
        pos++;
        take_digits(s, n, &pos);
    }
    size_t slen = strlen(p->suffix);
    if (n - pos < slen || memcmp(s + pos, p->suffix, slen) != 0)
        return false;
    *vs = at + plen;
    *ve = pos;
    return true;
}

/* The first match in one printable run. An unprefixed probe can only begin at
 * the start of a digit run: a match from inside a run has the same tail, so it
 * matches exactly when the run start does. */
static bool probe_run(const unsigned char *run, size_t n,
                      const struct probe *p, size_t *vs, size_t *ve)
{
    bool anchored = p->prefix[0] != '\0';
    for (size_t i = 0; i < n; i++) {
        if (!anchored && (!is_digit(run[i]) || (i > 0 && is_digit(run[i - 1]))))
            continue;
        if (probe_at(run, n, i, p, vs, ve))
            return true;
    }
    return false;
}

static bool scan_runs(const unsigned char *buf, size_t n,
                      const struct probe *p, char *out, size_t cap)
{
    size_t i = 0;
    while (i < n) {
        if (!is_printable(buf[i])) {
            i++;
            continue;
        }
        size_t end = i;
        while (end < n && is_printable(buf[end]))
            end++;
        size_t vs = 0, ve = 0;
        if (end - i >= MIN_RUN && probe_run(buf + i, end - i, p, &vs, &ve) &&
            copy_span(buf + i + vs, ve - vs, out, cap))
            return true;
        i = end;
    }
    return false;
}

static void set_unknown(char *out, size_t cap)
{
    snprintf(out, cap, "%s", UNKNOWN);
}

static void detect_archive(const char *path, const struct probe *p,
                           char *out, size_t cap)
{
    size_t n = 0;
    unsigned char *buf = read_regular(path, &n);
    bool found = buf != NULL && scan_runs(buf, n, p, out, cap);
    free(buf);
    if (!found)
        set_unknown(out, cap);
}

static bool first_quoted_version(const unsigned char *s, size_t n, char *out,
                                 size_t cap)
{
    for (size_t i = 0; i + 1 < n; i++) {
        if (s[i] != '"' || !(is_digit(s[i + 1]) || s[i + 1] == '.'))
            continue;
        size_t end = i + 1;
        while (end < n && (is_digit(s[end]) || s[end] == '.'))
            end++;
        return copy_span(s + i + 1, end - i - 1, out, cap);
    }
    return false;
}

/* The first line that carries the SQLite define, then its first quoted
 * version. The header defines the macro once, so the first line is the line. */
static bool sqlite_version_in(const unsigned char *buf, size_t n, char *out,
                              size_t cap)
{
    size_t start = 0;
    while (start < n) {
        size_t end = start;
        while (end < n && buf[end] != '\n')
            end++;
        const unsigned char *line = buf + start;
        size_t len = end - start;
        if (contains(line, len, SQLITE_DEFINE))
            return first_quoted_version(line, len, out, cap);
        start = end + 1;
    }
    return false;
}

static void detect_sqlite(const char *path, char *out, size_t cap)
{
    size_t n = 0;
    unsigned char *buf = read_regular(path, &n);
    bool found = buf != NULL && sqlite_version_in(buf, n, out, cap);
    free(buf);
    if (!found)
        set_unknown(out, cap);
}

/* The first line beginning "version=", its value kept verbatim. A stamp with
 * no such line has an empty version, which then fails the minimum check. */
static bool stamp_version_in(const unsigned char *buf, size_t n, char *out,
                             size_t cap)
{
    size_t klen = strlen(STAMP_KEY);
    size_t start = 0;
    while (start < n) {
        size_t end = start;
        while (end < n && buf[end] != '\n')
            end++;
        if (end - start >= klen && memcmp(buf + start, STAMP_KEY, klen) == 0)
            return copy_span(buf + start + klen, end - start - klen, out, cap);
        start = end + 1;
    }
    out[0] = '\0';
    return true;
}

static void detect_leveldb(const char *path, char *out, size_t cap)
{
    size_t n = 0;
    unsigned char *buf = read_regular(path, &n);
    bool found = buf != NULL && stamp_version_in(buf, n, out, cap);
    free(buf);
    if (!found)
        set_unknown(out, cap);
}

static void detect_versions(const char *root, struct versions *v)
{
    char path[PATH_MAX];
    build_path(path, sizeof path, root, VENDOR_LIB_REL "/libcrypto.a");
    detect_archive(path, &PROBE_OPENSSL, v->openssl, sizeof v->openssl);
    build_path(path, sizeof path, root, VENDOR_INC_REL "/sqlite3.h");
    detect_sqlite(path, v->sqlite, sizeof v->sqlite);
    build_path(path, sizeof path, root, VENDOR_LIB_REL "/libevent.a");
    detect_archive(path, &PROBE_LIBEVENT, v->libevent, sizeof v->libevent);
    build_path(path, sizeof path, root,
               VENDOR_LIB_REL "/.provenance/libleveldb.a.stamp");
    detect_leveldb(path, v->leveldb, sizeof v->leveldb);
    build_path(path, sizeof path, root, VENDOR_LIB_REL "/libz.a");
    detect_archive(path, &PROBE_ZLIB, v->zlib, sizeof v->zlib);
}

/* ── version order (sort -V) ──────────────────────────────────────────── */

static size_t digit_run(const char *s)
{
    size_t n = 0;
    while (is_digit((unsigned char)s[n]))
        n++;
    return n;
}

static int numeric_cmp(const char **a, const char **b)
{
    while (**a == '0' && is_digit((unsigned char)(*a)[1]))
        (*a)++;
    while (**b == '0' && is_digit((unsigned char)(*b)[1]))
        (*b)++;
    size_t la = digit_run(*a);
    size_t lb = digit_run(*b);
    if (la != lb)
        return la < lb ? -1 : 1;
    int c = strncmp(*a, *b, la);
    *a += la;
    *b += lb;
    return c < 0 ? -1 : (c > 0 ? 1 : 0);
}

static int version_cmp(const char *a, const char *b)
{
    for (;;) {
        if (*a == '\0' && *b == '\0')
            return 0;
        if (is_digit((unsigned char)*a) && is_digit((unsigned char)*b)) {
            int c = numeric_cmp(&a, &b);
            if (c != 0)
                return c;
            continue;
        }
        if (*a != *b)
            return (unsigned char)*a < (unsigned char)*b ? -1 : 1;
        a++;
        b++;
    }
}

/* The element `sort -V | head -1` keeps: version order, then byte order. */
static const char *older_of(const char *cur, const char *min)
{
    int c = version_cmp(cur, min);
    if (c == 0)
        c = strcmp(cur, min);
    return c <= 0 ? cur : min;
}

/* ── output ───────────────────────────────────────────────────────────── */

static void format_now(char *out, size_t cap)
{
    time_t t = (time_t)(clock_now_wall_ms() / 1000);
    struct tm tm;
    gmtime_r(&t, &tm);
    strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

static void print_header(void)
{
    char date[32];
    format_now(date, sizeof date);
    printf("=== Z23 Dependency Vulnerability Audit ===\n");
    printf("    Date: %s\n\n", date);
    printf("  %-20s %-14s %-10s %-6s %s\n", "DEPENDENCY", "VERSION", "MINIMUM",
           "STATUS", "DETAIL");
    printf("  %-20s %-14s %-10s %-6s %s\n", "----------", "-------", "-------",
           "------", "------");
}

static void print_json(const struct audit *a)
{
    char date[32];
    format_now(date, sizeof date);
    printf("{\n  \"date\": \"%s\",\n  \"fail\": %d,\n  \"warn\": 0,\n", date,
           a->fail);
    printf("  \"results\": [");
    for (size_t i = 0; i < a->rows; i++)
        printf("%s%s", i > 0 ? "," : "", a->json_rows[i]);
    printf("]\n}\n");
}

static void print_footer(const struct audit *a)
{
    if (a->fail > 0) {
        printf("\n" RED "  \xe2\x9c\x97 %d dependency provenance/version finding(s)." RESET "\n",
               a->fail);
        printf("    Action: run make vendor, inspect pins, and re-run make audit.\n");
        return;
    }
    printf("\n" GREEN "  \xe2\x9c\x93 All dependencies at or above minimum safe versions." RESET "\n");
}

static void emit_json_row(struct audit *a, const struct row *r)
{
    if (a->rows >= MAX_ROWS)
        return;
    snprintf(a->json_rows[a->rows], JSON_ROW_CAP,
             "{\"name\":\"%s\",\"version\":\"%s\",\"minimum\":\"%s\","
             "\"status\":\"%s\",\"detail\":\"%s\"}",
             r->name, r->version, r->minimum, r->pass ? "PASS" : "FAIL",
             r->json_detail);
    a->rows++;
}

static void emit_row(struct audit *a, const struct row *r)
{
    if (!r->pass)
        a->fail++;
    if (a->json) {
        emit_json_row(a, r);
        return;
    }
    char shown[32];
    snprintf(shown, sizeof shown, "%s%s", r->at_least ? ">= " : "", r->minimum);
    printf("  %-20s %-14s %-10s %s%-6s" RESET " %s\n", r->name, r->version,
           shown, r->pass ? GREEN : RED, r->pass ? "PASS" : "FAIL",
           r->text_detail);
}

/* ── checks ───────────────────────────────────────────────────────────── */

/* Classifies one detected version against its minimum. "unknown" fails
 * closed; a version below the minimum fails with the CVE note. */
static void check_version(struct audit *a, const char *name, const char *cur,
                          const char *min, const char *note)
{
    char detail[DETAIL_CAP];
    bool pass = true;
    if (strcmp(cur, UNKNOWN) == 0) {
        pass = false;
        snprintf(detail, sizeof detail,
                 "version could not be detected (audit fails closed)");
    } else if (strcmp(older_of(cur, min), min) != 0 && strcmp(cur, min) != 0) {
        pass = false;
        snprintf(detail, sizeof detail, "%s (need >= %s, have %s)", note, min,
                 cur);
    } else if (strcmp(cur, min) == 0) {
        snprintf(detail, sizeof detail, "at minimum safe version");
    } else {
        snprintf(detail, sizeof detail, "ahead of minimum (%s)", min);
    }
    struct row r = { name, cur, min, true, pass, detail, detail };
    emit_row(a, &r);
}

static void check_all(struct audit *a, const struct versions *v)
{
    check_version(a, "OpenSSL", v->openssl, OPENSSL_MIN, OPENSSL_NOTE);
    check_version(a, "SQLite", v->sqlite, SQLITE_MIN, SQLITE_NOTE);
    check_version(a, "libevent", v->libevent, LIBEVENT_MIN, LIBEVENT_NOTE);
    check_version(a, "leveldb", v->leveldb, LEVELDB_MIN, LEVELDB_NOTE);
    check_version(a, "zlib", v->zlib, ZLIB_MIN, ZLIB_NOTE);
}

static void emit_provenance(struct audit *a, bool current)
{
    const char *state = current ? "current" : "STALE_OR_UNPROVEN";
    char text[DETAIL_CAP];
    char json[DETAIL_CAP];
    if (current)
        snprintf(text, sizeof text, "all installed archives match deterministic stamps");
    else
        snprintf(text, sizeof text, "%s \xe2\x80\x94 run make vendor", state);
    snprintf(json, sizeof json,
             "%s \xe2\x80\x94 archive SHA256 must match source/recipe/toolchain/dependency stamp",
             state);
    struct row r = { "vendor-provenance", "v1", "exact", false, current, text,
                     json };
    emit_row(a, &r);
}

static void emit_secp(struct audit *a, bool locked)
{
    const char *state = locked ? "HASH_LOCKED" : "MANIFEST_MISMATCH";
    char json[DETAIL_CAP];
    snprintf(json, sizeof json,
             "%s \xe2\x80\x94 exact committed hash; replacement requires proven source",
             state);
    const char *text = locked
        ? "exact manifest hash; source unresolved, replacement prohibited"
        : state;
    struct row r = { "libsecp256k1", "legacy", "hash-lock", false, locked, text,
                     json };
    emit_row(a, &r);
}

/* ── provenance and root discovery ────────────────────────────────────── */

/* build_vendor.sh --check-provenance [archive], launched without a shell.
 * VENDOR_PROVENANCE_QUIET is inherited from the environment set in main(). */
static bool provenance_ok(const char *root, const char *archive)
{
    char script[PATH_MAX];
    build_path(script, sizeof script, root, BUILD_VENDOR_REL);
    const char *const argv[] = { script, "--check-provenance", archive, NULL };
    struct zcl_spawn_binary_observation obs;
    struct zcl_result res = zcl_spawn_capture_binary(
        argv, scratch, sizeof scratch, PROVENANCE_TIMEOUT_MS, &obs);
    return res.ok;
}

static bool probe_root(const char *dir)
{
    char probe[PATH_MAX];
    struct stat st;
    build_path(probe, sizeof probe, dir, BUILD_VENDOR_REL);
    return probe[0] != '\0' && stat(probe, &st) == 0 && S_ISREG(st.st_mode);
}

static bool step_up(char *dir)
{
    char *slash = strrchr(dir, '/');
    if (!slash)
        return false;
    if (slash == dir) {
        if (dir[1] == '\0')
            return false;
        dir[1] = '\0';
        return true;
    }
    *slash = '\0';
    return true;
}

static bool find_repo_root(char *root, size_t cap)
{
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof cwd))
        return false;
    snprintf(root, cap, "%s", cwd);
    do {
        if (probe_root(root))
            return true;
    } while (step_up(root));
    snprintf(root, cap, "%s", cwd);
    return true;
}

int main(int argc, char **argv)
{
    struct audit a;
    memset(&a, 0, sizeof a);
    a.json = argc > 1 && strcmp(argv[1], "--json") == 0;

    char root[PATH_MAX];
    if (!find_repo_root(root, sizeof root)) {
        fprintf(stderr, "dep_audit: working directory is not resolvable\n");
        return 1;
    }
    if (setenv("VENDOR_PROVENANCE_QUIET", "1", 1) != 0) {
        fprintf(stderr, "dep_audit: cannot set VENDOR_PROVENANCE_QUIET\n");
        return 1;
    }

    bool archives_current = provenance_ok(root, NULL);
    struct versions v;
    memset(&v, 0, sizeof v);
    detect_versions(root, &v);
    bool secp_locked = provenance_ok(root, "libsecp256k1.a");

    if (!a.json)
        print_header();
    emit_provenance(&a, archives_current);
    check_all(&a, &v);
    emit_secp(&a, secp_locked);
    if (a.json)
        print_json(&a);
    else
        print_footer(&a);
    return a.fail > 0 ? 1 : 0;
}
