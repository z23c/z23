/* Copyright 2026 Rhett Creighton - Licensed under Apache-2.0
 *
 * purpose: Support for the check-object-reproducible lint gate
 * (gate_object_reproducible.c): a FIPS 180-4 SHA-256, bounded no-shell file
 * helpers (read, hash, copy, recursive remove, PATH lookup), the ELF64
 * section walk that bounds-checks every header and names the first differing
 * section, and the gate's pure self-test (SHA-256 known answers, ELF bounds,
 * argument refusals, report-only excusing only a mismatch, and the real
 * compile runner driven by false, true, find, cp so a failed or empty compile
 * can never be satisfied by a stale object). Split from the gate only to keep
 * each file under the 1500-line ceiling.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_object_reproducible_priv.h"
#include "base/safe_alloc.h"
#include "base/serialize_le.h"

/* ---- SHA-256 (FIPS 180-4) ------------------------------------------- */

static const uint32_t k_or_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static uint32_t or_ror(uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32 - n));
}

static void or_sha_block(struct or_sha *s, const uint8_t *p)
{
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = zcl_read_u32_be(p + 4 * i);
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = or_ror(w[i - 15], 7) ^ or_ror(w[i - 15], 18)
                      ^ (w[i - 15] >> 3);
        uint32_t s1 = or_ror(w[i - 2], 17) ^ or_ror(w[i - 2], 19)
                      ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t v[8];
    memcpy(v, s->h, sizeof v);
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = v[7] + (or_ror(v[4], 6) ^ or_ror(v[4], 11)
                              ^ or_ror(v[4], 25))
                      + ((v[4] & v[5]) ^ (~v[4] & v[6])) + k_or_k[i] + w[i];
        uint32_t t2 = (or_ror(v[0], 2) ^ or_ror(v[0], 13) ^ or_ror(v[0], 22))
                      + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        memmove(v + 1, v, 7 * sizeof v[0]);
        v[4] += t1;
        v[0] = t1 + t2;
    }
    for (int i = 0; i < 8; i++)
        s->h[i] += v[i];
}

void or_sha_init(struct or_sha *s)
{
    static const uint32_t iv[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };
    memcpy(s->h, iv, sizeof iv);
    s->total = 0;
    s->fill = 0;
}

void or_sha_update(struct or_sha *s, const void *data, size_t len)
{
    const uint8_t *p = data;
    s->total += len;
    while (len > 0) {
        size_t n = 64 - s->fill;
        if (n > len)
            n = len;
        memcpy(s->blk + s->fill, p, n);
        s->fill += n;
        p += n;
        len -= n;
        if (s->fill == 64) {
            or_sha_block(s, s->blk);
            s->fill = 0;
        }
    }
}

void or_sha_hex(struct or_sha *s, char out[65])
{
    uint64_t bits = s->total * 8;
    uint8_t pad = 0x80;
    or_sha_update(s, &pad, 1);
    pad = 0;
    while (s->fill != 56)
        or_sha_update(s, &pad, 1);
    uint8_t len[8];
    zcl_write_u64_be(len, bits);
    or_sha_update(s, len, 8);
    for (int i = 0; i < 8; i++)
        (void)snprintf(out + 8 * i, 9, "%08x", s->h[i]);
}

void or_sha_buf(const void *data, size_t len, char out[65])
{
    struct or_sha s;
    or_sha_init(&s);
    or_sha_update(&s, data, len);
    or_sha_hex(&s, out);
}


/* ---- bounded file helpers ------------------------------------------- */

unsigned char *or_read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    unsigned char *buf = zcl_malloc(OR_OBJ_MAX + 1, "or_read_file");
    if (!buf) {
        (void)fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1, OR_OBJ_MAX + 1, f);
    bool bad = ferror(f) != 0 || n > OR_OBJ_MAX;
    (void)fclose(f);
    if (bad) {
        free(buf);
        return NULL;
    }
    *len = n;
    return buf;
}

/* Streamed SHA-256 of a file of any size; false when it cannot be read. */
bool or_hash_file(const char *path, char out[65])
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    struct or_sha s;
    unsigned char buf[65536];
    size_t n;
    or_sha_init(&s);
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        or_sha_update(&s, buf, n);
    bool ok = ferror(f) == 0;
    (void)fclose(f);
    if (ok)
        or_sha_hex(&s, out);
    return ok;
}

bool or_copy_file(const char *src, const char *dst)
{
    size_t n = 0;
    unsigned char *buf = or_read_file(src, &n);
    if (!buf)
        return false;
    FILE *f = fopen(dst, "wb");
    bool ok = f && fwrite(buf, 1, n, f) == n;
    if (f && fclose(f) != 0)
        ok = false;
    free(buf);
    return ok;
}

bool or_mkparent(const char *path)
{
    char buf[OR_PATH];
    if (snprintf(buf, sizeof buf, "%s", path) >= (int)sizeof buf)
        return false;
    char *slash = strrchr(buf, '/');
    if (!slash)
        return true;
    *slash = '\0';
    return csr_mkdirs(buf) == 0;
}

bool or_join(char *out, size_t cap, const char *a, const char *b)
{
    return snprintf(out, cap, "%s/%s", a, b) < (int)cap;
}

bool or_copy_tree(const char *src, const char *dst, int depth)
{
    struct stat st;
    if (depth > OR_DEPTH_MAX || stat(src, &st) != 0)
        return false;
    if (!S_ISDIR(st.st_mode))
        return or_mkparent(dst) && or_copy_file(src, dst);
    DIR *d = opendir(src);
    if (!d || csr_mkdirs(dst) != 0) {
        if (d)
            (void)closedir(d);
        return false;
    }
    bool ok = true;
    struct dirent *e;
    while (ok && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char s2[OR_PATH], d2[OR_PATH];
        ok = or_join(s2, sizeof s2, src, e->d_name)
             && or_join(d2, sizeof d2, dst, e->d_name)
             && or_copy_tree(s2, d2, depth + 1);
    }
    (void)closedir(d);
    return ok;
}

/* Checked, non-shell recursive remove. Symlinks are unlinked, never followed.
 * A path that is already gone counts as removed. */
bool or_rm_rf(const char *path, int depth)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return errno == ENOENT;
    if (!S_ISDIR(st.st_mode))
        return unlink(path) == 0;
    DIR *d = depth > OR_RM_DEPTH ? NULL : opendir(path);
    if (!d)
        return false;
    bool ok = true;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char c[OR_PATH];
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (!or_join(c, sizeof c, path, e->d_name)
            || !or_rm_rf(c, depth + 1))
            ok = false;
    }
    (void)closedir(d);
    return rmdir(path) == 0 && ok;
}

/* Resolve a compiler name to an executable path; false when absent. */
bool or_find_exe(const char *name, char *out, size_t cap)
{
    if (strchr(name, '/'))
        return snprintf(out, cap, "%s", name) < (int)cap
               && access(out, X_OK) == 0;
    const char *path = getenv("PATH");
    if (!path)
        return false;
    char dir[OR_PATH];
    while (*path) {
        size_t n = strcspn(path, ":");
        if (n > 0 && n < sizeof dir) {
            memcpy(dir, path, n);
            dir[n] = '\0';
            if (or_join(out, cap, dir, name) && access(out, X_OK) == 0)
                return true;
        }
        path += n + (path[n] == ':' ? 1 : 0);
    }
    return false;
}

/* ---- ELF section comparison ----------------------------------------- */

struct or_sec {
    const char *name;
    const unsigned char *data;
    uint64_t size;
    uint32_t type;
};

static uint64_t or_le(const unsigned char *p, int n)
{
    if (n == 2)
        return zcl_read_u16_le(p);
    return n == 4 ? zcl_read_u32_le(p) : zcl_read_u64_le(p);
}

struct or_elf {
    const unsigned char *b;
    size_t len;
    uint64_t shoff, shnum, shstr;
};

static bool or_elf_open(struct or_elf *e, const unsigned char *b, size_t len)
{
    if (len < 64 || memcmp(b, "\177ELF", 4) != 0 || b[4] != 2 || b[5] != 1)
        return false;
    e->b = b;
    e->len = len;
    e->shoff = or_le(b + 40, 8);
    e->shnum = or_le(b + 60, 2);
    e->shstr = or_le(b + 62, 2);
    return or_le(b + 58, 2) == 64 && e->shnum > 0 && e->shstr < e->shnum
           && e->shoff <= len && e->shnum * 64 <= len - e->shoff;
}

static bool or_elf_sec(const struct or_elf *e, uint64_t i, struct or_sec *s)
{
    const unsigned char *h = e->b + e->shoff + i * 64;
    const unsigned char *sh = e->b + e->shoff + e->shstr * 64;
    uint64_t noff = or_le(h, 4);
    uint64_t stroff = or_le(sh + 24, 8), strsz = or_le(sh + 32, 8);
    s->type = (uint32_t)or_le(h + 4, 4);
    uint64_t off = or_le(h + 24, 8);
    s->size = or_le(h + 32, 8);
    if (stroff > e->len || strsz > e->len - stroff || noff >= strsz)
        return false;
    s->name = (const char *)e->b + stroff + noff;
    if (memchr(s->name, 0, strsz - noff) == NULL)
        return false;
    s->data = e->b + off;
    return s->type == 8 /* NOBITS */
           || (off <= e->len && s->size <= e->len - off);
}

/* An ELF64 little-endian file of e_type `t` (1 relocatable) whose every
 * section header, name and data range lies inside the buffer; `t2` is an
 * alternative accepted type (pass `t` again for none). */
static bool or_elf_typed(const unsigned char *b, size_t len, int t, int t2)
{
    struct or_elf e;
    if (!or_elf_open(&e, b, len)
        || (or_le(b + 16, 2) != (uint64_t)t && or_le(b + 16, 2) != (uint64_t)t2))
        return false;
    for (uint64_t i = 0; i < e.shnum; i++) {
        struct or_sec s;
        if (!or_elf_sec(&e, i, &s))
            return false;
    }
    return true;
}

bool or_elf_valid(const unsigned char *b, size_t len)
{
    return or_elf_typed(b, len, 1, 1);
}

/* A linked executable: ET_EXEC or ET_DYN (position independent). */
bool or_elf_linked(const unsigned char *b, size_t len)
{
    return or_elf_typed(b, len, 2, 3);
}

/* First section (by header order) whose name or contents differ. Writes the
 * name into out; always writes a non-empty description. */
void or_elf_first_diff(const unsigned char *a, size_t la,
                              const unsigned char *b, size_t lb, char *out,
                              size_t cap)
{
    struct or_elf ea, eb;
    if (!or_elf_open(&ea, a, la) || !or_elf_open(&eb, b, lb)) {
        (void)snprintf(out, cap, "<not-elf64-le>");
        return;
    }
    uint64_t n = ea.shnum < eb.shnum ? ea.shnum : eb.shnum;
    for (uint64_t i = 0; i < n; i++) {
        struct or_sec sa, sb;
        if (!or_elf_sec(&ea, i, &sa) || !or_elf_sec(&eb, i, &sb)) {
            (void)snprintf(out, cap, "<bad-section-header-%llu>",
                           (unsigned long long)i);
            return;
        }
        if (strcmp(sa.name, sb.name) != 0 || sa.size != sb.size
            || sa.type != sb.type
            || (sa.type != 8 && memcmp(sa.data, sb.data, sa.size) != 0)) {
            (void)snprintf(out, cap, "%s", sa.name[0] ? sa.name : "<null>");
            return;
        }
    }
    (void)snprintf(out, cap, ea.shnum != eb.shnum
                   ? "<section-count>" : "<elf-header-or-section-table>");
}
/* ---- pure-logic selftest ---------------------------------------------- */

static void or_fixture_elf(unsigned char *a, size_t cap)
{
    memset(a, 0, cap);
    memcpy(a, "\177ELF", 4);
    a[4] = 2;
    a[5] = 1;
    a[16] = 1;                /* ET_REL */
    a[40] = 64 + 16;          /* e_shoff: headers after 16 data bytes */
    a[58] = 64;               /* e_shentsize */
    a[60] = 2;                /* e_shnum */
    a[62] = 1;                /* e_shstrndx */
    /* section 0: PROGBITS at offset 64, size 8, name offset 1 (".text") */
    unsigned char *h0 = a + 64 + 16, *h1 = h0 + 64;
    h0[0] = 1;
    h0[4] = 1;
    h0[24] = 64;
    h0[32] = 8;
    /* section 1: STRTAB holding "\0.text\0" at offset 72, size 8 */
    h1[4] = 3;
    h1[24] = 72;
    h1[32] = 8;
    memcpy(a + 73, ".text", 6);
}

static int or_fail(const char *what)
{
    fprintf(stderr, "check_object_reproducible selftest: FAIL - %s\n", what);
    return 1;
}

static int or_selftest_elf(void)
{
    enum { N = 64 + 16 + 64 * 2 };
    unsigned char a[N], b[N];
    char sec[OR_NAME];
    or_fixture_elf(a, sizeof a);
    memcpy(b, a, sizeof a);
    b[66] = 0xff;
    or_elf_first_diff(a, sizeof a, b, sizeof b, sec, sizeof sec);
    if (strcmp(sec, ".text") != 0)
        return or_fail("section differ did not name .text");
    or_elf_first_diff(a, sizeof a, a, sizeof a, sec, sizeof sec);
    if (strcmp(sec, "<elf-header-or-section-table>") != 0)
        return or_fail("equal objects reported a differing section");
    if (!or_elf_valid(a, sizeof a))
        return or_fail("a well-formed ELF was refused");
    return 0;
}

/* Negative bounds: each corruption of the fixture must be refused. */
static int or_selftest_elf_bounds(void)
{
    enum { N = 64 + 16 + 64 * 2 };
    unsigned char a[N], b[N];
    or_fixture_elf(a, sizeof a);
    if (or_elf_valid(a, sizeof a - 1))
        return or_fail("a truncated file (last header cut) was accepted");
    if (or_elf_valid(a, 60))
        return or_fail("a file shorter than the ELF header was accepted");
    memcpy(b, a, sizeof a);
    b[41] = 0xff;                          /* e_shoff far past the end */
    if (or_elf_valid(b, sizeof b))
        return or_fail("a section table offset past the end was accepted");
    memcpy(b, a, sizeof a);
    b[64 + 16 + 24 + 1] = 0xff;            /* section 0 data offset past end */
    if (or_elf_valid(b, sizeof b))
        return or_fail("a section data offset past the end was accepted");
    memcpy(b, a, sizeof a);
    b[16] = 3;                             /* ET_DYN is not an object */
    if (or_elf_valid(b, sizeof b))
        return or_fail("a non-relocatable ELF was accepted");
    return 0;
}

/* The root-path scan must find a path anywhere in a binary, and only there. */
static int or_selftest_contains(void)
{
    const unsigned char h[] = "xx/q/r/y\0/q/checkout";
    if (!or_contains(h, sizeof h - 1, "/q/r"))
        return or_fail("a path inside the output was not found");
    if (!or_contains(h, sizeof h - 1, "/q/checkout"))
        return or_fail("a path at the very end of the output was not found");
    if (or_contains(h, sizeof h - 1, "/q/zzz") || or_contains(h, 3, "xxx")
        || or_contains(h, sizeof h - 1, ""))
        return or_fail("an absent path was reported as present");
    return 0;
}

#define OR_GOOD_ARGS(SEED) \
    "--tree-root", "/t", "--repro-cflags", "-fx", "--base-cflags", "-O2", \
    "--shipped-cflags", "-O3", "--link-flags", "-pthread", \
    "--link-libs", "-lm", "--cross-flags", "-nostdlibinc", \
    "--targets", "clang-riscv64=--target=a,clang-aarch64=--target=b", \
    "--red-strip", "-ffile-prefix-map=", "--seed-flag", SEED

static int or_selftest_args(void)
{
    char *good[] = { OR_GOOD_ARGS("-frandom-seed=@UNIT@") };
    char *empty[] = { OR_GOOD_ARGS("") };
    char *unsub[] = { OR_GOOD_ARGS("-frandom-seed=tools/lint/z23-lint") };
    char *notgt[] = { OR_GOOD_ARGS("none"), "--targets", "clang-riscv64=--t=a" };
    char *host[] = { OR_GOOD_ARGS("none"), "--unsupported-host", "Darwin" };
    const int n = (int)(sizeof good / sizeof good[0]);
    struct or_cfg cfg;
    if (!or_parse(n, good, &cfg) || or_cfg_flaw(&cfg) != NULL)
        return or_fail("a complete argument set was refused");
    if (!or_parse(n, empty, &cfg) || or_cfg_flaw(&cfg) == NULL)
        return or_fail("an empty seed flag was accepted");
    if (!or_parse(n, unsub, &cfg) || or_cfg_flaw(&cfg) == NULL)
        return or_fail("an unsubstituted seed flag was accepted");
    unsub[n - 1] = "none";
    if (!or_parse(n, unsub, &cfg) || or_cfg_flaw(&cfg) != NULL)
        return or_fail("an explicit seed none was refused");
    if (or_parse(n - 1, good, &cfg))
        return or_fail("an unpaired option was accepted");
    if (!or_parse(n + 2, notgt, &cfg) || or_cfg_flaw(&cfg) == NULL)
        return or_fail("a --targets list missing a cross case was accepted");
    if (!or_parse(n + 2, host, &cfg) || or_cfg_flaw(&cfg) != NULL
        || strcmp(cfg.unsupported, "Darwin") != 0)
        return or_fail("--unsupported-host was not parsed");
    return 0;
}

/* Report-only excuses a hash MISMATCH of the named case and nothing else. */
static int or_selftest_excuse(void)
{
    struct or_cfg cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.report = "shipped-recipe";
    const struct or_case rep = { "shipped-recipe", NULL, false, true, false };
    const struct or_case other = { "host-cc", NULL, false, false, false };
    if (or_excuse(&cfg, &rep, OR_MISMATCH) != OR_OK)
        return or_fail("a report-only MISMATCH was not excused");
    if (or_excuse(&cfg, &rep, OR_REFUSED) != OR_REFUSED)
        return or_fail("a report-only non-mismatch refusal was swallowed");
    if (or_excuse(&cfg, &other, OR_MISMATCH) != OR_MISMATCH)
        return or_fail("a MISMATCH of a gating case was excused");
    char t[64];
    if (!or_target_of("a=--t=x,b=--t=y", "b", t, sizeof t)
        || strcmp(t, "--t=y") != 0 || or_target_of("a=--t=x", "b", t, sizeof t))
        return or_fail("--targets lookup is wrong");
    return 0;
}

/* Build a one-compiler command and run it through the real compile runner in
 * the current directory; 1 object accepted, 0 refused, -1 setup failure. */
static int or_rt_run(const char *const *words, int nw, bool stale)
{
    struct or_cmd *c = zcl_malloc(sizeof *c, "or_rt_run cmd");
    char *diag = zcl_malloc(OR_DIAG, "or_rt_run diag");
    int res = -1;
    bool ok = c && diag;
    if (ok)
        c->n = 0;
    for (int i = 0; ok && i < nw; i++)
        ok = or_add(c, words[i]);
    ok = ok && or_seal(c, true) && (!stale || or_copy_file("fixture.o",
                                                            "out.o"));
    if (ok) {
        size_t len = 0;
        const char *why = "";
        unsigned char *o = or_compile_run(c, diag, &len, &why);
        res = o ? 1 : 0;
        free(o);
    }
    free(c);
    free(diag);
    return res;
}

/* One runner check: `what` fails the selftest unless the result is `want`. */
static int or_rt_expect(const char *what, const char *const *w, int nw,
                        bool stale, int want)
{
    return or_rt_run(w, nw, stale) == want ? 0 : or_fail(what);
}

/* t: the paths of false, true, cp and find. */
static int or_selftest_runner_checks(const char *const *t)
{
    const char *const w_false[] = { t[0] };
    const char *const w_true[] = { t[1] };
    const char *const w_cp[] = { t[2], "fixture.o", "out.o" };
    const char *const w_bad[] = { t[2], "bad.o", "out.o" };
    /* writes a valid out.o, then exits non-zero: only the exit status
     * check can refuse it (find -exec ... + reports the failure). */
    const char *const w_wf[] = { t[3], ".", "-maxdepth", "1", "-name",
                                 "fixture.o", "-exec", t[2], "fixture.o",
                                 "out.o", ";", "-exec", t[0], "{}", "+" };
    if (or_rt_expect("a failing compiler (false) was accepted over a stale "
                     "valid object", w_false, 1, true, 0)
        || or_rt_expect("a compiler that exits 0 and writes nothing (true) "
                        "was accepted over a stale valid object", w_true, 1,
                        true, 0)
        || or_rt_expect("a compiler that exits 0 and writes nothing (true) "
                        "was accepted with no object", w_true, 1, false, 0)
        || or_rt_expect("a compiler that wrote a valid object and then exited "
                        "non-zero was accepted", w_wf, 15, false, 0)
        || or_rt_expect("a compiler that wrote a non-ELF file was accepted",
                        w_bad, 3, false, 0)
        || or_rt_expect("the positive control (a compiler that writes a "
                        "valid object) was refused", w_cp, 3, false, 1))
        return 1;
    g_or_deadline_ms = or_now_ms() - 1;
    if (or_rt_expect("a compile past the process deadline was run", w_cp, 3,
                     false, 0))
        return 1;
    g_or_deadline_ms = or_now_ms() + 60000;
    g_or_sig = SIGTERM;
    int bad = or_rt_expect("a compile after a stop signal was run", w_cp, 3,
                           false, 0);
    g_or_sig = 0;
    return bad;
}

static bool or_selftest_files(void)
{
    unsigned char elf[64 + 16 + 64 * 2];
    or_fixture_elf(elf, sizeof elf);
    FILE *f = fopen("fixture.o", "wb");
    bool ok = f && fwrite(elf, 1, sizeof elf, f) == sizeof elf;
    if (f && fclose(f) != 0)
        ok = false;
    f = fopen("bad.o", "wb");
    ok = ok && f && fputs("not an elf object at all\n", f) >= 0;
    if (f && fclose(f) != 0)
        ok = false;
    return ok;
}

/* Drive the real compile runner with false, true, find (writes then fails),
 * a non-ELF writer and a
 * valid-object writer, in a scratch directory that is removed afterwards. */
static int or_selftest_runner(void)
{
    static const char *const names[4] = { "false", "true", "cp", "find" };
    char paths[4][OR_PATH], tmpl[OR_PATH], saved[OR_PATH];
    const char *ptrs[4];
    const char *tmp = env_or("TMPDIR", "test-tmp");
    for (int i = 0; i < 4; i++) {
        ptrs[i] = paths[i];
        if (!or_find_exe(names[i], paths[i], sizeof paths[i]))
            return or_fail("false, true, cp and find were not found on PATH");
    }
    if (csr_mkdirs(tmp) != 0
        || !or_join(tmpl, sizeof tmpl, tmp, "z23-lint-objrepro-st.XXXXXX")
        || !mkdtemp(tmpl) || !getcwd(saved, sizeof saved))
        return or_fail("cannot create the selftest scratch directory");
    g_or_deadline_ms = or_now_ms() + 60000;
    int rc = 1;
    if (chdir(tmpl) == 0) {
        rc = or_selftest_files() ? or_selftest_runner_checks(ptrs)
                                 : or_fail("cannot write the scratch files");
        if (chdir(saved) != 0)
            rc = or_fail("cannot return from the scratch directory");
    }
    if (!or_rm_rf(tmpl, 0))
        rc = or_fail("cannot remove the selftest scratch directory");
    return rc;
}

int check_object_reproducible_selftest(void)
{
    char hex[65];
    or_sha_buf("abc", 3, hex);
    if (strcmp(hex, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61"
                    "f20015ad") != 0)
        return or_fail("SHA-256 known answer for \"abc\" is wrong");
    const char *two = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    or_sha_buf(two, strlen(two), hex);
    if (strcmp(hex, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd4"
                    "19db06c1") != 0)
        return or_fail("SHA-256 known answer for the two-block message");
    if (or_selftest_elf() != 0 || or_selftest_elf_bounds() != 0
        || or_selftest_args() != 0 || or_selftest_contains() != 0
        || or_selftest_excuse() != 0 || or_selftest_runner() != 0)
        return 1;
    printf("check_object_reproducible selftest: ok (sha256 KATs, ELF section "
           "differ and bounds, argument refusals, report-only excuses only a "
           "mismatch, the compile runner refuses a failing compiler, one that "
           "writes an object then fails, a "
           "compiler that writes nothing, a non-ELF writer, a stop signal "
           "and an expired deadline, and accepts a valid object). The real "
           "run adds RED/GREEN controls for host-cc, clang-host, "
           "clang-riscv64 and clang-aarch64 (unit level) and shipped-link "
           "(link level); shipped-recipe has none\n");
    return 0;
}
