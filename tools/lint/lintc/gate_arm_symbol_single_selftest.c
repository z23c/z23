/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * check-arm-symbol-single family — --selftest. Port of the six-case
 * --selftest of tools/lint/check_arm_symbol_single.sh: (1) a cross-arm
 * non-static duplicate must FAIL; (2) the same shape but both bodies
 * static must PASS; (3) a function-generating macro invoked twice under
 * different names must PASS (no false hit from the macro's own braces);
 * (4) an __attribute__-prefixed function on its own line must PASS; (5) a
 * clean, singly-defined function must PASS; (6) coverage: a full scan
 * clears its own expectation, a scan missing a whole declared root is
 * UNPROVEN exit 2, and a stale coverage allowance is a ratchet VIOLATION
 * exit 1. Every fixture lives under a private sandbox directory (never
 * /tmp — getenv("TMPDIR") or "test-tmp"), removed on the way out.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_arm_symbol_single_priv.h"

static const char k_gate[] = "check_arm_symbol_single";

/* ── quiet in-process re-invocation (this port's spawn-free replacement
 * for the shell original's `env VAR=val "$self"` self-re-exec) ─────────── */

static int asy_quiet(int (*fn)(void), int *code)
{
    FILE *t = tmpfile();
    if (!t)
        return die("z23-lint: tmpfile failed\n", "");
    fflush(stdout);
    fflush(stderr);
    int fd = fileno(t);
    int ou = dup(STDOUT_FILENO), eu = dup(STDERR_FILENO);
    if (ou < 0 || eu < 0 || dup2(fd, STDOUT_FILENO) < 0
        || dup2(fd, STDERR_FILENO) < 0)
        return die("z23-lint: dup2 failed\n", "");
    *code = fn();
    fflush(stdout);
    fflush(stderr);
    if (dup2(ou, STDOUT_FILENO) < 0 || dup2(eu, STDERR_FILENO) < 0)
        return die("z23-lint: dup2 failed\n", "");
    close(ou);
    close(eu);
    fclose(t);
    return 0;
}

/* ── (1)-(5): fixture-driven analyzer probes ───────────────────────────── */

struct asy_names { char n[256][256]; int stat[256]; int n_used; };

static int asy_st_collect(const char *file, void *ctx, const char *name,
                          int line, int is_static)
{
    (void)file;
    (void)line;
    struct asy_names *s = ctx;
    if (s->n_used >= 256)
        return die("z23-lint: scan-set overflow\n", "");
    snprintf(s->n[s->n_used], sizeof s->n[0], "%s", name);
    s->stat[s->n_used] = is_static;
    s->n_used++;
    return 0;
}

/* run_dup_names: non-static names occurring >=2 times in one file, as a
 * newline-joined string (mirrors the shell's captured awk|awk pipeline,
 * embedded verbatim in the SELFTEST FAILED text on the divergent path). */
static void asy_dup_names(const char *path, char *out, size_t cap)
{
    struct asy_names s = { .n_used = 0 };
    (void)asy_analyze_file(path, asy_st_collect, &s);
    out[0] = '\0';
    size_t used = 0;
    for (int i = 0; i < s.n_used; i++) {
        if (s.stat[i])
            continue;
        int count = 0;
        for (int j = 0; j < s.n_used; j++)
            if (!s.stat[j] && strcmp(s.n[j], s.n[i]) == 0)
                count++;
        if (count < 2)
            continue;
        int already = 0;
        for (int j = 0; j < i; j++)
            if (!s.stat[j] && strcmp(s.n[j], s.n[i]) == 0) { already = 1; break; }
        if (already)
            continue;
        int k = snprintf(out + used, cap - used, "%s%s", used ? "\n" : "",
                         s.n[i]);
        if (k < 0 || (size_t)k >= cap - used)
            break;
        used += (size_t)k;
    }
}

static int asy_expect_dup(const char *sandbox, const char *msg,
                          const char *name, const char *body)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", sandbox, name);
    if (csr_write(path, body))
        return 2;
    char hits[4096];
    asy_dup_names(path, hits, sizeof hits);
    if (hits[0] == '\0') {
        fprintf(stderr,
                "%s: SELFTEST FAILED — %s (expected a duplicate, found none)\n",
                k_gate, msg);
        return 2;
    }
    return 0;
}

static int asy_expect_clean(const char *sandbox, const char *msg,
                            const char *name, const char *body)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s", sandbox, name);
    if (csr_write(path, body))
        return 2;
    char hits[4096];
    asy_dup_names(path, hits, sizeof hits);
    if (hits[0] != '\0') {
        fprintf(stderr,
                "%s: SELFTEST FAILED — %s (unexpected duplicate: %s)\n",
                k_gate, msg, hits);
        return 2;
    }
    return 0;
}

/* ── (6): coverage re-checks under a perturbed environment ─────────────── */

struct asy_envsave { const char *key; char *old; int was_set; };

static int asy_cov_case(int want_rc, const char *msg, const char *const *keys,
                        const char *const *vals, int nvars)
{
    struct asy_envsave save[4];
    for (int i = 0; i < nvars; i++) {
        const char *cur = getenv(keys[i]);
        save[i].key = keys[i];
        save[i].was_set = cur != NULL;
        save[i].old = cur ? strdup(cur) : NULL;
        setenv(keys[i], vals[i], 1);
    }
    int rc = 0;
    if (asy_quiet(asy_run, &rc))
        return 2;
    for (int i = 0; i < nvars; i++) {
        if (save[i].was_set)
            setenv(save[i].key, save[i].old, 1);
        else
            unsetenv(save[i].key);
        free(save[i].old);
    }
    if (rc != want_rc) {
        fprintf(stderr,
                "%s: SELFTEST FAILED — %s (wanted exit %d, got %d)\n",
                k_gate, msg, want_rc, rc);
        return 2;
    }
    return 0;
}

/* ── entry point ────────────────────────────────────────────────────────── */

int check_arm_symbol_single_selftest(void)
{
    const char *base = getenv("TMPDIR");
    if (!base || !base[0])
        base = "test-tmp";
    if (csr_mkdirs(base))
        return 2;
    char tmpl[512];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/asy_st.XXXXXX", base),
            sizeof tmpl))
        return 2;
    char *sandbox = mkdtemp(tmpl);
    if (!sandbox)
        return die("z23-lint: mkdir failed: %s\n", base);

    int rc = 0;
    rc |= asy_expect_dup(sandbox,
        "two non-static bodies of the same name in #ifdef/#else arms did not trip",
        "dup.c",
        "#ifdef _WIN32\n"
        "bool fs_parse_thing(const uint8_t *p, uint32_t n)\n"
        "{\n"
        "    return n != 4;\n"
        "}\n"
        "#else\n"
        "bool fs_parse_thing(const uint8_t *p, uint32_t n)\n"
        "{\n"
        "    return n < 4;\n"
        "}\n"
        "#endif\n");
    if (rc) { (void)rap_rm_rf(sandbox); return rc; }

    rc |= asy_expect_clean(sandbox,
        "a static duplicate across arms was flagged (should be out of scope)",
        "static_dup.c",
        "#ifdef _WIN32\n"
        "static bool fs_parse_thing(const uint8_t *p, uint32_t n)\n"
        "{\n"
        "    return n != 4;\n"
        "}\n"
        "#else\n"
        "static bool fs_parse_thing(const uint8_t *p, uint32_t n)\n"
        "{\n"
        "    return n < 4;\n"
        "}\n"
        "#endif\n");
    if (rc) { (void)rap_rm_rf(sandbox); return rc; }

    rc |= asy_expect_clean(sandbox,
        "a function-defining macro invoked under two different names was flagged",
        "macro.c",
        "#define FS_WINDOWS_TRANSPORT_REFUSAL(name_, args_) \\\n"
        "    bool name_ args_ { errno = ENOTSUP; return false; }\n"
        "\n"
        "FS_WINDOWS_TRANSPORT_REFUSAL(fs_send_frame,\n"
        "    (struct fs_session *s, uint32_t n))\n"
        "FS_WINDOWS_TRANSPORT_REFUSAL(fs_recv_frame,\n"
        "    (struct fs_session *s, uint32_t n))\n"
        "\n"
        "void fs_server_start(const char *datadir, uint16_t port)\n"
        "{ (void)datadir; (void)port; }\n");
    if (rc) { (void)rap_rm_rf(sandbox); return rc; }

    rc |= asy_expect_clean(sandbox,
        "an __attribute__-prefixed function was flagged / misnamed",
        "attr.c",
        "__attribute__((target(\"sha,sse4.1\")))\n"
        "static void sha256_transform_shani(uint32_t *state, const unsigned char *data)\n"
        "{\n"
        "    (void)state; (void)data;\n"
        "}\n"
        "\n"
        "void sha256_transform_generic(uint32_t *state, const unsigned char *data)\n"
        "{\n"
        "    (void)state; (void)data;\n"
        "}\n");
    if (rc) { (void)rap_rm_rf(sandbox); return rc; }

    rc |= asy_expect_clean(sandbox, "a singly-defined function was flagged",
        "clean.c",
        "bool fs_parse_once(const uint8_t *p, uint32_t n)\n"
        "{\n"
        "    return p && n > 0;\n"
        "}\n");
    if (rc) { (void)rap_rm_rf(sandbox); return rc; }

    {
        const char *k[1] = { "ZCL_LINT_MODE" };
        const char *v[1] = { "FAIL" };
        rc = asy_cov_case(0,
            "the complete scan did not pass its coverage expectation", k, v, 1);
    }
    if (rc) { (void)rap_rm_rf(sandbox); return rc; }

    {
        const char *k[2] = { "ZCL_ARM_SYMBOL_SCAN_ROOTS",
                             "ZCL_ARM_SYMBOL_FILE_FLOOR" };
        const char *v[2] = { "core engine contexts cognition platform", "1" };
        rc = asy_cov_case(2,
            "a scan missing a whole declared root was not UNPROVEN", k, v, 2);
    }
    if (rc) { (void)rap_rm_rf(sandbox); return rc; }

    {
        const char *k[1] = { "ZCL_ARM_SYMBOL_COVERAGE_ALLOWANCE" };
        const char *v[1] = { "1" };
        rc = asy_cov_case(1,
            "an allowance above the true shortfall was silently tolerated",
            k, v, 1);
    }
    (void)rap_rm_rf(sandbox);
    if (rc)
        return rc;

    printf("[%s] SELFTEST PASS (cross-arm non-static dup fails; static dup, "
          "macro-generated pair, __attribute__-prefixed fn and a clean "
          "singleton all pass; a full scan passes coverage, a scan short one "
          "declared root is UNPROVEN exit 2, and an allowance above the true "
          "shortfall is a stale-ratchet exit 1)\n", k_gate);
    return 0;
}
