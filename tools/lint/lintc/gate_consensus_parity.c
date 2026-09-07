/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — consensus-parity guard of the C23 lint runtime
 * (check-consensus-parity). Tracked files via lint_git_index_foreach;
 * filesystem walk when .git is absent.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "base/hex.h"
#include "lintc.h"

enum { CP_MAX = 8192, CP_LINE = 8192, CP_FLOOR = 3100000 };

struct cp_set { char p[CP_MAX][RS_PATH]; int n; };

static const char *const k_cp_paths[] = {
    "core/params", "core/chainparams", "core/modules/validation",
    "core/modules/chain", "core/modules/mining", "engine/jobs",
    "engine/reducer/jobs", "core/consensus"
};
static const char k_cp_reg[] = "tools/lint/FLAG_DAYS.txt";
static const char k_cp_forb[] =
    "versionbits|VersionBitsState|ComputeBlockVersion|ehUpgrade|"
    "eh_upgrade|nSignalBit|vbits_|equihash_n_at|equihash_k_at|BIP9|BIP8";
static const char k_cp_ok[] =
    "(//|/\\*) ?consensus-parity-ok:[A-Za-z][A-Za-z0-9_-]+";
static const char k_cp_ht[] =
    "(>=|<=|==|<|>)[[:space:]]*[0-9]{7,}|[0-9]{7,}[[:space:]]*(>=|<=|==|<|>)";
static const char k_cp_ck[] =
    "(^|[^[:alnum:]_])time[[:space:]]*\\([[:space:]]*NULL[[:space:]]*\\)"
    "|(^|[^[:alnum:]_])GetTime[[:space:]]*\\([[:space:]]*\\)"
    "|(^|[^[:alnum:]_])GetAdjustedTime[[:space:]]*\\([[:space:]]*\\)"
    "|(^|[^[:alnum:]_])gettimeofday[[:space:]]*\\("
    "|(^|[^[:alnum:]_])clock_gettime[[:space:]]*\\(";

static uint32_t cp_rotr(uint32_t x, int n)
{ return (x >> n) | (x << (32 - n)); }

static void cp_xform(uint32_t h[8], const unsigned char *c)
{
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,
        0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
        0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,
        0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,
        0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
        0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,
        0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,
        0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
        0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t w[64], a, b, c2, d, e, f, g, hh, t1, t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)c[i * 4] << 24) | ((uint32_t)c[i * 4 + 1] << 16)
             | ((uint32_t)c[i * 4 + 2] << 8) | c[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        uint32_t s0 = cp_rotr(w[i - 15], 7) ^ cp_rotr(w[i - 15], 18)
                      ^ (w[i - 15] >> 3);
        uint32_t s1 = cp_rotr(w[i - 2], 17) ^ cp_rotr(w[i - 2], 19)
                      ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = h[0]; b = h[1]; c2 = h[2]; d = h[3];
    e = h[4]; f = h[5]; g = h[6]; hh = h[7];
    for (i = 0; i < 64; i++) {
        t1 = hh + (cp_rotr(e, 6) ^ cp_rotr(e, 11) ^ cp_rotr(e, 25))
           + ((e & f) ^ ((~e) & g)) + k[i] + w[i];
        t2 = (cp_rotr(a, 2) ^ cp_rotr(a, 13) ^ cp_rotr(a, 22))
           + ((a & b) ^ (a & c2) ^ (b & c2));
        hh = g; g = f; f = e; e = d + t1; d = c2; c2 = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c2; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

static void cp_sha256(const unsigned char *msg, size_t len, char hex[65])
{
    uint32_t h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    unsigned char block[64], out[32];
    uint64_t bits = (uint64_t)len * 8;
    size_t n = len, i;
    const unsigned char *p = msg;
    while (n >= 64) {
        cp_xform(h, p);
        p += 64;
        n -= 64;
    }
    memcpy(block, p, n);
    block[n++] = 0x80;
    if (n > 56) {
        memset(block + n, 0, 64 - n);
        cp_xform(h, block);
        n = 0;
    }
    memset(block + n, 0, 56 - n);
    for (i = 0; i < 8; i++)
        block[63 - i] = (unsigned char)(bits >> (8 * i));
    cp_xform(h, block);
    for (i = 0; i < 8; i++) {
        out[i * 4] = (unsigned char)(h[i] >> 24);
        out[i * 4 + 1] = (unsigned char)(h[i] >> 16);
        out[i * 4 + 2] = (unsigned char)(h[i] >> 8);
        out[i * 4 + 3] = (unsigned char)h[i];
    }
    zcl_hex_encode(out, sizeof out, hex);
}

static int cp_file_sha(const char *path, char hex[65])
{
    static unsigned char buf[1 << 20];
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f)
        return 2;
    n = fread(buf, 1, sizeof buf, f);
    if (ferror(f) || !feof(f)) {
        fclose(f);
        return die("z23-lint: read failed: %s\n", path);
    }
    fclose(f);
    cp_sha256(buf, n, hex);
    return 0;
}

static int cp_add(struct cp_set *s, const char *path)
{
    size_t n;
    int i;
    for (i = 0; i < s->n; i++)
        if (strcmp(s->p[i], path) == 0)
            return 0;
    n = strlen(path);
    if (s->n >= CP_MAX || n >= RS_PATH)
        return die("z23-lint: consensus-parity overflow\n", "");
    memcpy(s->p[s->n++], path, n + 1);
    return 0;
}

static int cp_is_src(const char *path)
{
    size_t n = strlen(path), i;
    if (n < 2 || path[n - 2] != '.'
        || (path[n - 1] != 'c' && path[n - 1] != 'h'))
        return 0;
    for (i = 0; i < sizeof k_cp_paths / sizeof k_cp_paths[0]; i++) {
        size_t k = strlen(k_cp_paths[i]);
        if (strncmp(path, k_cp_paths[i], k) == 0
            && (path[k] == '/' || path[k] == '\0'))
            return !lint_path_is_excluded(path);
    }
    return 0;
}

static int cp_on_idx(const char *path, int stage, void *ctx)
{
    (void)stage;
    return cp_is_src(path) ? cp_add(ctx, path) : 0;
}

static int cp_on_walk(const char *path, void *ctx)
{
    return cp_is_src(path) ? cp_add(ctx, path) : 0;
}

static int cp_re(regex_t *re, const char *pat)
{
    return reg_fail(re, regcomp(re, pat, REG_EXTENDED));
}

static int cp_preflight(void)
{
    size_t i;
    for (i = 0; i < sizeof k_cp_paths / sizeof k_cp_paths[0]; i++) {
        struct stat st;
        if (stat(k_cp_paths[i], &st) == 0 && S_ISDIR(st.st_mode))
            continue;
        fprintf(stderr, "check_consensus_parity: FATAL — consensus path '%s' "
                        "is missing.\n  The consensus source surface drifted. "
                        "Update PATHS in this gate\n  deliberately and re-verify "
                        "the zclassicd parity boundary before\n  re-greening. "
                        "Refusing to report 'clean' off a partial scan.\n",
                k_cp_paths[i]);
        return 2;
    }
    return 0;
}

static int cp_collect(struct cp_set *s)
{
    char bad[8] = {0};
    struct stat st;
    int rc, i;
    s->n = 0;
    if (stat(".git", &st) == 0) {
        rc = lint_git_index_foreach(cp_on_idx, s, bad);
        if (rc && bad[0])
            fprintf(stderr, "z23-lint: UNPROVEN — git index extension %s\n",
                    bad);
        return rc;
    }
    for (i = 0; i < (int)(sizeof k_cp_paths / sizeof k_cp_paths[0]); i++) {
        rc = walk_src(k_cp_paths[i], 1, cp_on_walk, s);
        if (rc)
            return rc;
    }
    return 0;
}

static int cp_comment(const char *line)
{
    const char *p = line;
    while (*p == ' ' || *p == '\t')
        p++;
    if (p[0] == '/' && (p[1] == '/' || p[1] == '*'))
        return 1;
    return p[0] == '*' && (p[1] == ' ' || p[1] == '\t');
}

static int cp_flag(const char *reg, const char *key, const char *cls,
                   const char *dig, char *st, size_t cap)
{
    FILE *f = fopen(reg, "r");
    char buf[CP_LINE];
    int seen = 0;
    if (!f) {
        snprintf(st, cap, "missing-file");
        return 0;
    }
    while (fgets(buf, (int)sizeof buf, f)) {
        char *p, *rkey, *rcls, *rdig, *save;
        size_t n = strlen(buf);
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        if (buf[0] == '\0' || buf[0] == '#')
            continue;
        rkey = buf;
        p = strchr(buf, '|');
        if (!p)
            continue;
        *p++ = '\0';
        rcls = p;
        p = strchr(p, '|');
        if (!p)
            continue;
        *p++ = '\0';
        p = strchr(p, '|');
        if (!p)
            continue;
        rdig = p + 1;
        save = strchr(rdig, '|');
        if (save)
            *save = '\0';
        if (strcmp(rkey, key) == 0 && strcmp(rcls, cls) == 0) {
            seen = 1;
            if (strcmp(rdig, dig) == 0) {
                fclose(f);
                snprintf(st, cap, "ok");
                return 0;
            }
        }
    }
    fclose(f);
    snprintf(st, cap, seen ? "stale" : "unregistered");
    return 0;
}

static int cp_has_height(const char *line)
{
    const char *p;
    for (p = line; *p; p++) {
        unsigned char c = (unsigned char)*p;
        if (c >= 'A' && c <= 'Z')
            c = (unsigned char)(c - 'A' + 'a');
        if (strncmp(p, "height", 6) == 0
            || (c == 'h' && strncmp(p + 1, "eight", 5) == 0))
            return 1;
    }
    return strstr(line, "height") != NULL || strstr(line, "HEIGHT") != NULL
        || strstr(line, "Height") != NULL;
}

static int cp_rel2(char a, char b)
{
    return (a == '>' && b == '=') || (a == '<' && b == '=')
        || (a == '=' && b == '=');
}

static int cp_op_around(const char *line, const char *tok)
{
    const char *p = line;
    size_t n = strlen(tok);
    while ((p = strstr(p, tok)) != NULL) {
        const char *l = p, *r = p + n;
        while (l > line && (l[-1] == ' ' || l[-1] == '\t'))
            l--;
        if (l - line >= 2 && cp_rel2(l[-2], l[-1]))
            return 1;
        if (l > line && (l[-1] == '>' || l[-1] == '<'))
            return 1;
        while (*r == ' ' || *r == '\t')
            r++;
        if (cp_rel2(r[0], r[1]))
            return 1;
        if (r[0] == '>' || r[0] == '<')
            return 1;
        p += n;
    }
    return 0;
}

static int cp_hexish(const char *line, const char *tok)
{
    char a[64], b[64];
    if (ovf(snprintf(a, sizeof a, "0x%s", tok), sizeof a)
        || ovf(snprintf(b, sizeof b, "0X%s", tok), sizeof b))
        return 1;
    return strstr(line, a) != NULL || strstr(line, b) != NULL;
}

static int cp_height_hits(const char *path, int lineno, const char *content,
                          const char *reg, int *fail)
{
    const char *p = content;
    while (*p) {
        char tok[32], key[RS_PATH + 32], dig[65], st[32];
        size_t k = 0;
        unsigned long v;
        if (*p < '0' || *p > '9') {
            p++;
            continue;
        }
        while (p[k] >= '0' && p[k] <= '9' && k + 1 < sizeof tok)
            tok[k] = p[k], k++;
        tok[k] = '\0';
        p += k;
        if (k < 7)
            continue;
        v = strtoul(tok, NULL, 10);
        if (v < CP_FLOOR || cp_hexish(content, tok) || !cp_op_around(content, tok))
            continue;
        cp_sha256((const unsigned char *)content, strlen(content), dig);
        if (ovf(snprintf(key, sizeof key, "%s:%d", path, lineno), sizeof key))
            return 2;
        cp_flag(reg, key, "HEIGHT", dig, st, sizeof st);
        if (strcmp(st, "ok") == 0)
            continue;
        printf("FAIL[HEIGHT:%s] %s:%d: %s\n"
               "    literal %s >= floor %d in a height comparison.\n"
               "    Register in %s:\n"
               "        %s:%d|HEIGHT|%s|%s|<tag>|<one-line rationale>\n",
               st, path, lineno, content, tok, CP_FLOOR, k_cp_reg, path,
               lineno, tok, dig);
        *fail = 1;
    }
    return 0;
}

static int cp_clock_hit(const char *path, int lineno, const char *content,
                        const char *reg, const regex_t *ck, int *fail)
{
    char key[RS_PATH + 32], dig[65], st[32];
    if (regexec(ck, content, 0, NULL, 0) != 0)
        return 0;
    cp_sha256((const unsigned char *)content, strlen(content), dig);
    if (ovf(snprintf(key, sizeof key, "%s:%d", path, lineno), sizeof key))
        return 2;
    cp_flag(reg, key, "CLOCK", dig, st, sizeof st);
    if (strcmp(st, "ok") == 0)
        return 0;
    printf("FAIL[CLOCK:%s] %s:%d: %s\n"
           "    wall-clock read in the consensus surface.\n"
           "    Register in %s:\n"
           "        %s:%d|CLOCK|-|%s|<tag>|<one-line rationale>\n",
           st, path, lineno, content, k_cp_reg, path, lineno, dig);
    *fail = 1;
    return 0;
}

static int cp_scan_line(const char *path, int lineno, char *buf,
                        const char *reg, const regex_t *forb, const regex_t *ok,
                        const regex_t *ht, const regex_t *ck, int do0, int *c0,
                        int *c12)
{
    if (do0 && regexec(forb, buf, 0, NULL, 0) == 0
        && regexec(ok, buf, 0, NULL, 0) != 0) {
        printf("%s:%d:%s\n", path, lineno, buf);
        *c0 = 1;
    }
    if (cp_comment(buf))
        return 0;
    if (regexec(ht, buf, 0, NULL, 0) == 0 && cp_has_height(buf)
        && cp_height_hits(path, lineno, buf, reg, c12))
        return 2;
    return cp_clock_hit(path, lineno, buf, reg, ck, c12);
}

static int cp_scan_file(const char *path, const char *reg, const regex_t *forb,
                        const regex_t *ok, const regex_t *ht, const regex_t *ck,
                        int do0, int *c0, int *c12)
{
    FILE *f = fopen(path, "r");
    char buf[CP_LINE];
    int lineno = 0, rc = 0;
    if (!f) {
        fprintf(stderr, "z23-lint: UNPROVEN — cannot read %s\n", path);
        return 2;
    }
    while (rc == 0 && fgets(buf, (int)sizeof buf, f)) {
        size_t n = strlen(buf);
        lineno++;
        if (n && buf[n - 1] == '\n')
            buf[--n] = '\0';
        rc = cp_scan_line(path, lineno, buf, reg, forb, ok, ht, ck, do0, c0,
                          c12);
    }
    if (rc == 0 && ferror(f))
        rc = die("z23-lint: read failed: %s\n", path);
    if (fclose(f) != 0 && rc == 0)
        rc = die("z23-lint: fclose failed: %s\n", path);
    return rc;
}

static void cp_emit_digest(void)
{
    char hex[65];
    if (cp_file_sha(k_cp_reg, hex) == 0)
        printf("FLAG_DAYS_REGISTRY_DIGEST: sha256:%s\n", hex);
    else
        fprintf(stderr, "FLAG_DAYS_REGISTRY_DIGEST: MISSING — %s does not "
                        "exist\n", k_cp_reg);
}

static int cp_cmp(const void *a, const void *b)
{
    return strcmp((const char *)a, (const char *)b);
}

static int cp_load_re(regex_t *forb, regex_t *ok, regex_t *ht, regex_t *ck)
{
    int rc = cp_re(forb, k_cp_forb);
    if (rc)
        return rc;
    rc = cp_re(ok, k_cp_ok);
    if (rc) {
        regfree(forb);
        return rc;
    }
    rc = cp_re(ht, k_cp_ht);
    if (rc) {
        drop2(forb, ok);
        return rc;
    }
    rc = cp_re(ck, k_cp_ck);
    if (rc) {
        drop2(forb, ok);
        regfree(ht);
        return rc;
    }
    return 0;
}

static int cp_main(void)
{
    static struct cp_set set;
    regex_t forb, ok, ht, ck;
    int rc, i, c0 = 0, c12 = 0;
    struct stat st;
    rc = cp_preflight();
    if (rc)
        return rc;
    if (stat(k_cp_reg, &st) != 0) {
        fprintf(stderr, "check_consensus_parity: FATAL — registry '%s' "
                        "is missing.\n  Scan classes 1 (future-height "
                        "literal) and 2 (wall-clock read) can\n  only "
                        "clear a hit against this registry. Refusing to "
                        "report 'clean'\n  off a scan with nothing to "
                        "check hits against.\n", k_cp_reg);
        return 2;
    }
    rc = cp_load_re(&forb, &ok, &ht, &ck);
    if (rc)
        return rc;
    rc = cp_collect(&set);
    if (rc) {
        drop2(&forb, &ok);
        drop2(&ht, &ck);
        return rc;
    }
    qsort(set.p, (size_t)set.n, RS_PATH, cp_cmp);
    for (i = 0; rc == 0 && i < set.n; i++)
        rc = cp_scan_file(set.p[i], k_cp_reg, &forb, &ok, &ht, &ck, 1, &c0,
                          &c12);
    drop2(&forb, &ok);
    drop2(&ht, &ck);
    if (rc)
        return rc;
    if (c0 || c12) {
        if (c0) {
            fputs("\nFAIL: a non-zclassicd consensus mechanism appears in "
                  "the consensus path.\n  zclassic23 MUST stay bit-for-bit "
                  "consensus-compatible with zclassicd.\n  See "
                  "docs/CONSENSUS_PARITY_DOCTRINE.md. Equihash (N,K) and "
                  "every upgrade\n  activation resolve from the STATIC, "
                  "height-keyed table ONLY — never from\n  miner signaling / "
                  "versionbits / a dynamic per-height override.\n  If this is "
                  "genuinely not a divergence, mark the line:\n"
                  "      // consensus-parity-ok:<reason>\n", stdout);
        }
        cp_emit_digest();
        return 1;
    }
    fputs("check_consensus_parity: clean — no non-zclassicd consensus "
          "mechanism, no\n  unregistered future-height literal, no "
          "unregistered wall-clock read in\n  the consensus path\n", stdout);
    cp_emit_digest();
    return 0;
}

static int cp_st_scan(const char *path, const char *reg)
{
    regex_t forb, ok, ht, ck;
    int c0 = 0, c12 = 0, rc;
    rc = cp_re(&forb, k_cp_forb) || cp_re(&ok, k_cp_ok) || cp_re(&ht, k_cp_ht)
        || cp_re(&ck, k_cp_ck);
    if (rc)
        return rc;
    rc = cp_scan_file(path, reg, &forb, &ok, &ht, &ck, 0, &c0, &c12);
    drop2(&forb, &ok);
    drop2(&ht, &ck);
    if (rc)
        return rc;
    return c12 ? 1 : 0;
}

static int cp_nth_line(const char *path, int want, char *out, size_t cap)
{
    FILE *f = fopen(path, "r");
    int i;
    size_t n;
    if (!f)
        return 2;
    out[0] = '\0';
    for (i = 0; i < want; i++)
        if (!fgets(out, (int)cap, f))
            break;
    fclose(f);
    n = strlen(out);
    if (n && out[n - 1] == '\n')
        out[n - 1] = '\0';
    return 0;
}

static int cp_st_reg(const char *path, const char *reg, int lineno,
                     const char *cls, const char *tok)
{
    char line[CP_LINE], dig[65], row[CP_LINE];
    if (cp_nth_line(path, lineno, line, sizeof line))
        return 2;
    cp_sha256((const unsigned char *)line, strlen(line), dig);
    if (strcmp(cls, "HEIGHT") == 0)
        snprintf(row, sizeof row,
                 "%s:%d|HEIGHT|%s|%s|selftest-bomb|selftest fixture: "
                 "deliberately planted, this row exists only to prove the "
                 "registered form passes.\n", path, lineno, tok, dig);
    else
        snprintf(row, sizeof row,
                 "%s:%d|CLOCK|-|%s|selftest-clock|selftest fixture: "
                 "deliberately planted, this row exists only to prove the "
                 "registered form passes.\n", path, lineno, dig);
    return csr_write(reg, row);
}

static int cp_st_pair(const char *path, const char *reg, const char *unreg_msg,
                      int lineno, const char *cls, const char *tok, int *bad)
{
    int rc;
    fputs(unreg_msg, stdout);
    rc = cp_st_scan(path, reg);
    if (rc != 1) {
        fprintf(stderr, "FAIL: selftest expected the unregistered case to "
                        "trip the gate, but it passed clean.\n");
        *bad = 1;
    }
    if (cp_st_reg(path, reg, lineno, cls, tok))
        return 2;
    rc = cp_st_scan(path, reg);
    if (rc) {
        fputs("FAIL: selftest expected the REGISTERED form to pass, but the "
              "gate still tripped:\n", stderr);
        *bad = 1;
    } else {
        fputs("-- registered form correctly PASSED (no output).\n", stdout);
    }
    return 0;
}

int check_consensus_parity_selftest(void)
{
    char tmp[] = "/tmp/zcl-cp-XXXXXX";
    char hf[4096], cf[4096], rg[4096];
    int bad = 0;
    if (!mkdtemp(tmp))
        return die("z23-lint: mkdtemp failed\n", "");
    if (ovf(snprintf(hf, sizeof hf, "%s/subsidy_fixture.c", tmp), sizeof hf)
        || ovf(snprintf(cf, sizeof cf, "%s/clock_fixture.c", tmp), sizeof cf)
        || ovf(snprintf(rg, sizeof rg, "%s/FLAG_DAYS.txt", tmp), sizeof rg)
        || csr_write(hf,
                     "/* selftest fixture — not part of the build */\n"
                     "int consensus_halving(int n_height)\n{\n"
                     "    int halvings = n_height / 100;\n"
                     "    if (n_height >= 3400000)\n"
                     "        halvings--;\n    return halvings;\n}\n")
        || csr_write(cf,
                     "/* selftest fixture — not part of the build */\n"
                     "bool clock_fixture_reject(void)\n{\n"
                     "    return time(NULL) > 1234567890;\n}\n")
        || csr_write(rg, "")) {
        rap_rm_rf(tmp);
        return 2;
    }
    fputs("== class-1 (HEIGHT) selftest ==\n", stdout);
    if (cp_st_pair(hf, rg,
                   "-- unregistered planted bomb correctly FAILED:\n",
                   5, "HEIGHT", "3400000", &bad)) {
        rap_rm_rf(tmp);
        return 2;
    }
    fputs("\n== class-2 (CLOCK) selftest ==\n", stdout);
    if (csr_write(rg, "")
        || cp_st_pair(cf, rg,
                      "-- unregistered wall-clock read correctly FAILED:\n",
                      4, "CLOCK", "-", &bad)) {
        rap_rm_rf(tmp);
        return 2;
    }
    rap_rm_rf(tmp);
    fputs("\n", stdout);
    if (bad) {
        fputs("check_consensus_parity --selftest: FAIL\n", stdout);
        return 1;
    }
    fputs("check_consensus_parity --selftest: PASS\n", stdout);
    return 0;
}

int check_consensus_parity_run(int argc, char **argv)
{
    if (argc >= 1 && argv[0] && argv[0][0]
        && strcmp(argv[0], "--selftest") != 0) {
        fprintf(stderr, "check_consensus_parity: unknown argument: %s\n",
                argv[0]);
        return 2;
    }
    return cp_main();
}
