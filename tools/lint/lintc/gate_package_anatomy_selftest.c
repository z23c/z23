/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check_package_anatomy
 * (gate_package_anatomy.c). Ported from the selftest of
 * tools/lint/check_package_anatomy.sh (deleted). Builds the same 70-good /
 * 70-bad / 69-hollow fixture matrix under $HOME/.local/state/zclassic23/
 * scratch (never a bare /tmp literal) and drives the production entrypoint
 * pka_check_root over each root with stdout+stderr captured: the good root
 * passes; the bad root (macro, inline, manifest_substring, duplicate_file,
 * missing_comma, trailing_comma variants) is refused with exactly the six
 * production violation rows; the 69-package hollow root is refused as a
 * hollow scan (exit 2, FATAL floor message).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_package_anatomy_priv.h"

/* Defined in gate_package_anatomy.c. */
int pka_check_root(const char *root, int run_kats);

enum { PKS_PATH = 1024, PKS_TEXT = 4096, PKS_OUT = 262144 };

static int pks_app(char *b, size_t cap, size_t *o, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(b + *o, cap - *o, fmt, ap);
    va_end(ap);
    if (ovf(n, (int)(cap - *o)))
        return 2;
    *o += (size_t)n;
    return 0;
}

static int pks_write_header(const char *d, const char *pkg, const char *guard,
                            const char *extra, int pad)
{
    char path[PKS_PATH], text[PKS_TEXT];
    if (ovf(snprintf(path, sizeof path, "%s/include/%s/%s.h", d, pkg, pkg),
            sizeof path))
        return 2;
    if (ovf(snprintf(text, sizeof text,
                     "#ifndef %s_H\n#define %s_H\n"
                     "/* inline and #define COMMENT_FN(x) are prose, not code. */\n"
                     "#define COMMENT_SPLIT/**/(x) (x)\n"
                     "%s\n"
                     "int %s(void);\n"
                     "#endif\n",
                     guard, guard, extra, pkg), sizeof text))
        return 2;
    int rc = csr_write(path, text);
    if (rc)
        return rc;
    if (!pad)
        return 0;
    /* Keep the header larger than a pipe buffer: the first match must stay
     * a violation, not a producer SIGPIPE (mirrors the shell selftest). */
    FILE *f = fopen(path, "a");
    if (!f)
        return die("z23-lint: cannot reopen fixture %s\n", path);
    for (int i = 0; i < 8192; i++)
        fputs("int zfixture_padding(void);\n", f);
    int bad = ferror(f) != 0;
    fclose(f);
    return bad ? die("z23-lint: cannot pad fixture %s\n", path) : 0;
}

static int pks_manifest_head(char *text, size_t cap, size_t *o,
                             const char *pkg)
{
    if (pks_app(text, cap, o, "{\n  \"schema\": 1,\n  \"name\": "
             "\"%s/%s\",\n", pkg, pkg))
        return 2;
    return pks_app(text, cap, o,
                   "  \"language\": \"c23\",\n  \"license\": \"MIT\",\n");
}

static int pks_manifest_lic(char *text, size_t cap, size_t *o,
                            const char *invalid)
{
    if (!strcmp(invalid, "manifest_substring")
        && pks_app(text, cap, o, "  \"note\": \"README.md\",\n"))
        return 2;
    if (!strcmp(invalid, "missing_comma")) {
        if (pks_app(text, cap, o, "  \"files\": [\n    \"LICENSE\"\n"))
            return 2;
    } else if (pks_app(text, cap, o, "  \"files\": [\n    \"LICENSE\",\n")) {
        return 2;
    }
    if (!strcmp(invalid, "duplicate_file")
        && pks_app(text, cap, o, "    \"LICENSE\",\n"))
        return 2;
    if (strcmp(invalid, "manifest_substring") != 0
        && pks_app(text, cap, o, "    \"README.md\",\n"))
        return 2;
    return 0;
}

static int pks_manifest_tail(char *text, size_t cap, size_t *o,
                             const char *pkg, const char *invalid)
{
    if (pks_app(text, cap, o, "    \"include/%s/%s.h\",\n", pkg, pkg))
        return 2;
    if (pks_app(text, cap, o, "    \"src/%s.c\",\n    \"tests/"
             "test_%s.c\",\n", pkg, pkg))
        return 2;
    if (!strcmp(invalid, "trailing_comma"))
        return pks_app(text, cap, o,
                       "    \"zcode-package.json\",\n  ]\n}\n");
    return pks_app(text, cap, o, "    \"zcode-package.json\"\n  ]\n}\n");
}

static int pks_write_manifest(const char *d, const char *pkg,
                              const char *invalid)
{
    char path[PKS_PATH], text[PKS_TEXT];
    size_t o = 0;
    if (ovf(snprintf(path, sizeof path, "%s/zcode-package.json", d),
            sizeof path))
        return 2;
    if (pks_manifest_head(text, sizeof text, &o, pkg))
        return 2;
    if (pks_manifest_lic(text, sizeof text, &o, invalid))
        return 2;
    if (pks_manifest_tail(text, sizeof text, &o, pkg, invalid))
        return 2;
    return csr_write(path, text);
}

static int pks_extra(const char *invalid, const char *pkg, const char *guard,
                     char *extra, size_t cap)
{
    if (!strcmp(invalid, "macro")) {
        if (ovf(snprintf(extra, cap, "#define %s_MAX(a,b) "
                     "((a)>(b)?(a):(b))", guard), cap))
            return 2;
    } else if (!strcmp(invalid, "inline")) {
        if (ovf(snprintf(extra, cap, "static/**/inline int "
                     "%s_inline(void) { return 0; }", pkg), cap))
            return 2;
    } else if (strcmp(invalid, "clean")
               && strcmp(invalid, "manifest_substring")
               && strcmp(invalid, "duplicate_file")
               && strcmp(invalid, "missing_comma")
               && strcmp(invalid, "trailing_comma")) {
        fprintf(stderr, "FAIL: unknown package-anatomy selftest mode %s\n",
                invalid);
        return 2;
    }
    return 0;
}

static int pks_write_dirs(const char *d, const char *pkg)
{
    char p[PKS_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/include/%s", d, pkg), sizeof p))
        return 2;
    int rc = csr_mkdirs(p);
    if (rc)
        return rc;
    if (ovf(snprintf(p, sizeof p, "%s/src", d), sizeof p))
        return 2;
    rc = csr_mkdirs(p);
    if (rc)
        return rc;
    if (ovf(snprintf(p, sizeof p, "%s/tests", d), sizeof p))
        return 2;
    return csr_mkdirs(p);
}

static int pks_write_sources(const char *d, const char *pkg)
{
    char p[PKS_PATH], text[512];
    if (ovf(snprintf(p, sizeof p, "%s/src/%s.c", d, pkg), sizeof p))
        return 2;
    if (ovf(snprintf(text, sizeof text, "int %s(void) { return 0; }\n", pkg),
            sizeof text))
        return 2;
    int rc = csr_write(p, text);
    if (rc)
        return rc;
    if (ovf(snprintf(p, sizeof p, "%s/tests/test_%s.c", d, pkg), sizeof p))
        return 2;
    return csr_write(p, "int main(void) { return 0; }\n");
}

static int pks_write_meta(const char *d)
{
    char p[PKS_PATH];
    if (ovf(snprintf(p, sizeof p, "%s/LICENSE", d), sizeof p))
        return 2;
    int rc = csr_write(p, "x\n");
    if (rc)
        return rc;
    if (ovf(snprintf(p, sizeof p, "%s/README.md", d), sizeof p))
        return 2;
    return csr_write(p, "x\n");
}

static int pks_write_pkg(const char *root, const char *pkg,
                         const char *invalid)
{
    char d[PKS_PATH], guard[256], extra[600] = "";
    pka_upper(pkg, guard, sizeof guard);
    if (pks_extra(invalid, pkg, guard, extra, sizeof extra))
        return 2;
    if (ovf(snprintf(d, sizeof d, "%s/%s", root, pkg), sizeof d))
        return 2;
    int rc = pks_write_dirs(d, pkg);
    if (rc)
        return rc;
    rc = pks_write_header(d, pkg, guard, extra,
                          !strcmp(invalid, "macro") || !strcmp(invalid,
                                                              "inline"));
    if (rc)
        return rc;
    rc = pks_write_sources(d, pkg);
    if (rc)
        return rc;
    rc = pks_write_meta(d);
    if (rc)
        return rc;
    return pks_write_manifest(d, pkg, invalid);
}

static int pks_build(const char *tmp)
{
    static const char *const k_modes[] = { "macro", "inline",
                                           "manifest_substring",
                                           "duplicate_file", "missing_comma",
                                           "trailing_comma" };
    char root[PKS_PATH], pkg[64];
    for (int i = 0; i < 70; i++) {
        if (ovf(snprintf(pkg, sizeof pkg, "zfixture%02d", i), sizeof pkg))
            return 2;
        const char *badmode = (i < 6) ? k_modes[i] : "clean";
        if (ovf(snprintf(root, sizeof root, "%s/good", tmp), sizeof root))
            return 2;
        int rc = pks_write_pkg(root, pkg, "clean");
        if (rc)
            return rc;
        if (ovf(snprintf(root, sizeof root, "%s/bad", tmp), sizeof root))
            return 2;
        rc = pks_write_pkg(root, pkg, badmode);
        if (rc)
            return rc;
        if (i >= 69)
            continue;
        if (ovf(snprintf(root, sizeof root, "%s/hollow", tmp), sizeof root))
            return 2;
        rc = pks_write_pkg(root, pkg, "clean");
        if (rc)
            return rc;
    }
    return 0;
}

/* Run the production check on root with stdout+stderr captured into out. */
static int pks_capture(const char *tmpdir, const char *root, int *rc,
                       char *out, size_t cap)
{
    char tmpl[PKS_PATH];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/cap.XXXXXX", tmpdir),
            sizeof tmpl))
        return 2;
    int fd = mkstemp(tmpl);
    if (fd < 0)
        return die("z23-lint: mkstemp failed for selftest capture\n", "");
    unlink(tmpl);
    fflush(NULL);
    int s1 = dup(1), s2 = dup(2);
    if (s1 < 0 || s2 < 0) {
        close(fd);
        return die("z23-lint: dup failed for selftest capture\n", "");
    }
    dup2(fd, 1);
    dup2(fd, 2);
    *rc = pka_check_root(root, 0);
    fflush(NULL);
    dup2(s1, 1);
    dup2(s2, 2);
    close(s1);
    close(s2);
    lseek(fd, 0, SEEK_SET);
    ssize_t n = read(fd, out, cap - 1);
    out[n > 0 ? (size_t)n : 0] = '\0';
    close(fd);
    return 0;
}

static int pks_all(const char *out, const char *const *need, size_t nneed)
{
    for (size_t i = 0; i < nneed; i++)
        if (!strstr(out, need[i]))
            return 0;
    return 1;
}

static int pks_case_good(const char *tmp, char *out)
{
    char root[PKS_PATH];
    int rc = 0;
    if (ovf(snprintf(root, sizeof root, "%s/good", tmp), sizeof root))
        return 2;
    if (pks_capture(tmp, root, &rc, out, PKS_OUT))
        return 2;
    if (rc != 0) {
        fprintf(stderr, "FAIL: selftest production entrypoint rejected "
                "conforming fixture:\n  %s\n", out);
        return 2;
    }
    return 0;
}

static int pks_case_bad(const char *tmp, char *out)
{
    static const char *const k_need[] = {
        "6 package-anatomy violation(s)", "function-like macro",
        "inline function", "exists but is not listed", "more than once",
        "files[] is missing, duplicated, or malformed"
    };
    char root[PKS_PATH];
    int rc = 0;
    if (ovf(snprintf(root, sizeof root, "%s/bad", tmp), sizeof root))
        return 2;
    if (pks_capture(tmp, root, &rc, out, PKS_OUT))
        return 2;
    if (rc == 0) {
        fprintf(stderr, "FAIL: selftest production entrypoint accepted "
                "invalid macro fixture:\n  %s\n", out);
        return 2;
    }
    if (rc != 1 || !pks_all(out, k_need, sizeof k_need / sizeof k_need[0])) {
        fprintf(stderr, "FAIL: selftest invalid fixture refusal was not the "
                "production gate verdict:\n  exit=%d output=%s\n", rc, out);
        return 2;
    }
    return 0;
}

static int pks_case_hollow(const char *tmp, char *out)
{
    static const char *const k_need[] = {
        "FATAL", "scan set is '69' (< floor 70)"
    };
    char root[PKS_PATH];
    int rc = 0;
    if (ovf(snprintf(root, sizeof root, "%s/hollow", tmp), sizeof root))
        return 2;
    if (pks_capture(tmp, root, &rc, out, PKS_OUT))
        return 2;
    if (rc == 0) {
        fprintf(stderr, "FAIL: selftest production entrypoint accepted "
                "below-floor fixture:\n  %s\n", out);
        return 2;
    }
    if (rc != 2 || !pks_all(out, k_need, sizeof k_need / sizeof k_need[0])) {
        fprintf(stderr, "FAIL: selftest below-floor fixture was not a "
                "hollow-scan refusal:\n  exit=%d output=%s\n", rc, out);
        return 2;
    }
    return 0;
}

static int pks_verify(const char *tmp)
{
    static char out[PKS_OUT];
    int rc = pks_case_good(tmp, out);
    if (rc)
        return rc;
    rc = pks_case_bad(tmp, out);
    if (rc)
        return rc;
    return pks_case_hollow(tmp, out);
}

int check_package_anatomy_selftest(void)
{
    static char base[PKS_PATH], tmp[PKS_PATH];
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return die("z23-lint: HOME unset; cannot place selftest scratch\n",
                   "");
    if (ovf(snprintf(base, sizeof base, "%s/.local/state/zclassic23/scratch",
                     home), sizeof base))
        return 2;
    int rc = csr_mkdirs(base);
    if (rc)
        return rc;
    if (ovf(snprintf(tmp, sizeof tmp, "%s/pkg-anatomy.XXXXXX", base),
            sizeof tmp))
        return 2;
    if (!mkdtemp(tmp))
        return die("z23-lint: mkdtemp failed for selftest scratch\n", "");
    rc = pks_build(tmp);
    if (!rc)
        rc = pks_verify(tmp);
    rap_rm_rf(tmp);
    if (rc) {
        fputs("FAIL: check_package_anatomy selftest\n", stderr);
        return rc;
    }
    return st_ok(0, "check_package_anatomy: selftest PASS — production "
               "entrypoint accepts commented clean code, rejects "
               "macro/inline/exact JSON files[], and refuses hollow scans\n");
}
