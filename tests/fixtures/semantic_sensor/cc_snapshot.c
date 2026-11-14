/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Exercise private exact-byte session snapshot bounds and reuse. */
#if !defined(_WIN32) && !defined(_DEFAULT_SOURCE)
#define _DEFAULT_SOURCE
#endif
#define CM_CC_SNAPSHOT_MAX 64u
#include "../../../tools/sensors/clang_manifest_cc.c"

static bool cs_write(const char *path, size_t n, unsigned char value)
{
    FILE *f = fopen(path, "wb"); if (!f) return false;
    bool ok = true;
    for (size_t i = 0; i < n; ++i) if (fputc(value, f) == EOF) ok = false;
    return fclose(f) == 0 && ok;
}
static bool cs_digest(const char *path, struct cm_cc_snapshot *s)
{
    uint8_t actual[32], expected[32]; struct sha3_256_ctx c; sha3_256_init(&c);
    if (!cm_cc_sha3(path, &c)) return false;
    sha3_256_finalize(&c, expected);
    return cm_cc_digest(path, s, actual) && !memcmp(actual, expected, 32);
}
static bool cs_hit(const char *path, struct cm_cc_snapshot *s)
{
    struct cm_cc_snapshot_entry *e = NULL;
    for (size_t i = 0; i < 2; ++i)
        if (s->entries[i].bytes && !strcmp(s->entries[i].path, path)) e = &s->entries[i];
    if (!e) return false;
    uint8_t d[32], saved[32];
    memcpy(saved, e->digest, 32); memset(e->digest, 0xa5, 32);
    bool ok = cm_cc_digest(path, s, d) && !memcmp(d, e->digest, 32);
    memcpy(e->digest, saved, 32); return ok;
}
static bool cs_initial(const char *a, const char *b, const char *c, struct cm_cc_snapshot *s)
{
    return cs_write(a, 30, 'a') && cs_write(b, 20, 'b') && cs_write(c, 5, 'c') &&
        cs_digest(a, s) && cs_digest(b, s) && cs_hit(a, s) && cs_hit(b, s) &&
        cs_digest(c, s) && cs_hit(a, s) && cs_hit(b, s);
}
static bool cs_changes(const char *a, const char *d, struct cm_cc_snapshot *s)
{
    return cs_write(a, 30, 'x') && cs_digest(a, s) && cs_write(a, 7, 'y') && cs_digest(a, s) &&
        cs_write(d, 50, 'd') && cs_digest(d, s) && cs_hit(d, s) &&
        s->entries[0].len + s->entries[1].len <= 64 &&
        cs_write(a, 65, 'z') && cs_digest(a, s) && cs_hit(d, s) &&
        s->entries[0].len + s->entries[1].len <= 64;
}
int main(void)
{
    char dir[PATH_MAX - 16], a[PATH_MAX], b[PATH_MAX], c[PATH_MAX], d[PATH_MAX], absent[PATH_MAX];
    const char *tmp = getenv("TMPDIR");
    if (!tmp || snprintf(dir, sizeof(dir), "%s/z23-cc-snapshot-XXXXXX", tmp) >= (int)sizeof(dir) || !mkdtemp(dir)) return 2;
    (void)snprintf(a, sizeof(a), "%s/a", dir); (void)snprintf(b, sizeof(b), "%s/b", dir);
    (void)snprintf(c, sizeof(c), "%s/c", dir); (void)snprintf(d, sizeof(d), "%s/d", dir);
    (void)snprintf(absent, sizeof(absent), "%s/absent", dir);
    struct cm_cc_snapshot s = {0}; uint8_t out[32];
    bool ok = cs_initial(a, b, c, &s) && cs_changes(a, d, &s) && !cm_cc_digest(absent, &s, out);
    for (size_t i = 0; i < 2; ++i) free(s.entries[i].bytes);
    (void)unlink(a); (void)unlink(b); (void)unlink(c); (void)unlink(d); (void)rmdir(dir);
    puts(ok ? "cc snapshot fixture PASS" : "cc snapshot fixture FAIL");
    return ok ? 0 : 1;
}
