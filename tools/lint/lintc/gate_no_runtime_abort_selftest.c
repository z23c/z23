/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check-no-runtime-abort — plants each case from
 * tools/lint/check_no_runtime_abort.sh's own --selftest into a sandboxed
 * scan root and asserts the gate's verdict, in-process (no subshell —
 * unlike the shell, which re-execs itself; nra_run_gate() is the shared
 * entry point both the production path and this selftest call directly).
 *
 * Gates: (selftest sibling of check-no-runtime-abort)
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_no_runtime_abort_priv.h"

static const char k_gate[] = "check_no_runtime_abort";

struct nra_st_ctx {
    char root[4096];
    char lib_root[4096];
    char probe_path[4096];
    char baseline[4096];
    int fails;
};

static int nra_st_plant(const struct nra_st_ctx *s, const char *body)
{
    char text[4096];
    if (ovf(snprintf(text, sizeof text,
                     "#include <assert.h>\n#include <stdlib.h>\n"
                     "bool probe_check(int x)\n{\n%s\n    return true;\n}\n",
                     body), sizeof text))
        return 1;
    return csr_write(s->probe_path, text) != 0;
}

static int nra_st_setup(struct nra_st_ctx *s)
{
    const char *td = env_or("TMPDIR", "/tmp");
    char tmpl[4096];
    if (ovf(snprintf(tmpl, sizeof tmpl, "%s/z23-lint-nra-XXXXXX", td),
            sizeof tmpl))
        return 1;
    char *root = mkdtemp(tmpl);
    if (!root)
        return die("z23-lint: mkdtemp failed: %s\n", tmpl);
    memset(s, 0, sizeof *s);
    if (ovf(snprintf(s->root, sizeof s->root, "%s", root), sizeof s->root))
        return 1;
    if (ovf(snprintf(s->lib_root, sizeof s->lib_root, "%s/lib", s->root),
            sizeof s->lib_root))
        return 1;
    if (ovf(snprintf(s->probe_path, sizeof s->probe_path,
                     "%s/lib/probe/src/selftest_probe.c", s->root),
            sizeof s->probe_path))
        return 1;
    if (ovf(snprintf(s->baseline, sizeof s->baseline,
                     "%s/empty_baseline.txt", s->root), sizeof s->baseline))
        return 1;
    return csr_write(s->baseline, "");
}

static int nra_st_run(struct nra_st_ctx *s, int site_floor)
{
    const char *roots[1] = { s->lib_root };
    struct nra_ctx c = {
        .baseline = s->baseline,
        .roots = roots,
        .nroots = 1,
        .file_floor = 1,
        .site_floor = site_floor,
        .mode = NRA_MODE_FAIL,
    };
    FILE *out = fopen("/dev/null", "w");
    FILE *err = fopen("/dev/null", "w");
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        return -1;
    }
    int rc = nra_run_gate(&c, out, err);
    fclose(out);
    fclose(err);
    return rc;
}

/* Runs the gate with stdout captured to a real file (not /dev/null) so a
 * caller can inspect the printed report text — used to assert the
 * per-site "path:lineno: text" detail line survives into the violation
 * report, matching check_no_runtime_abort.sh's DETAIL[] output. */
static int nra_st_run_capture(struct nra_st_ctx *s, char *outbuf, size_t outbuf_sz)
{
    const char *roots[1] = { s->lib_root };
    struct nra_ctx c = {
        .baseline = s->baseline,
        .roots = roots,
        .nroots = 1,
        .file_floor = 1,
        .site_floor = 0,
        .mode = NRA_MODE_FAIL,
    };
    char outpath[4096];
    if (ovf(snprintf(outpath, sizeof outpath, "%s/out.txt", s->root),
            sizeof outpath))
        return -1;
    FILE *out = fopen(outpath, "w");
    FILE *err = fopen("/dev/null", "w");
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        return -1;
    }
    int rc = nra_run_gate(&c, out, err);
    fclose(out);
    fclose(err);
    FILE *rf = fopen(outpath, "r");
    if (!rf)
        return -1;
    size_t n = fread(outbuf, 1, outbuf_sz - 1, rf);
    outbuf[n] = '\0';
    fclose(rf);
    return rc;
}

static void nra_st_expect_detail(struct nra_st_ctx *s)
{
    const char *name = "the violation report dropped the per-site detail line";
    if (nra_st_plant(s, "    if (x < 0) abort();")) {
        fprintf(stderr, "%s: SELFTEST FAIL — %s: could not plant fixture\n",
                k_gate, name);
        s->fails++;
        return;
    }
    char outbuf[8192];
    int rc = nra_st_run_capture(s, outbuf, sizeof outbuf);
    int has_detail = strstr(outbuf, "selftest_probe.c:5:") != NULL &&
                     strstr(outbuf, "abort();") != NULL;
    if (rc != 1 || !has_detail) {
        fprintf(stderr, "%s: SELFTEST FAIL — %s (rc=%d, has_detail=%d)\n",
                k_gate, name, rc, has_detail);
        s->fails++;
    } else {
        fprintf(stdout, "%s: selftest ok — %s\n", k_gate,
                "violation report names the file:line:text of the site");
    }
}

static void nra_st_expect(struct nra_st_ctx *s, const char *name,
                          const char *body, int want)
{
    if (nra_st_plant(s, body)) {
        fprintf(stderr, "%s: SELFTEST FAIL — %s: could not plant fixture\n",
                k_gate, name);
        s->fails++;
        return;
    }
    int rc = nra_st_run(s, 0);
    if (rc != want) {
        fprintf(stderr, "%s: SELFTEST FAIL — %s (want rc=%d, got %d)\n",
                k_gate, name, want, rc);
        s->fails++;
    } else {
        fprintf(stdout, "%s: selftest ok — %s (exit %d)\n", k_gate, name, rc);
    }
}

int check_no_runtime_abort_selftest(void)
{
    struct nra_st_ctx s;
    if (nra_st_setup(&s))
        return 2;

    nra_st_expect(&s, "a runtime assert() did not fail the gate",
                 "    assert(x > 0);", 1);
    nra_st_expect(&s, "a LOG_FAIL rejection was reported as an abort primitive",
                 "    if (x <= 0) LOG_FAIL(\"probe\", \"x out of range\");", 0);
    /* NEGATIVE CONTROL. _Static_assert is compile-time and correct; a gate
     * that flags it makes the codebase worse. Non-negotiable. */
    nra_st_expect(&s, "a _Static_assert was flagged — the prefix guard is broken",
                 "    _Static_assert(sizeof(int) == 4, \"m\");", 0);
    nra_st_expect(&s, "a C23 static_assert was flagged — the prefix guard is broken",
                 "    static_assert(sizeof(int) == 4, \"m\");", 0);
    nra_st_expect(&s, "a bare abort() did not fail the gate",
                 "    if (x < 0) abort();", 1);
    nra_st_expect_detail(&s);
    nra_st_expect(&s, "the // abort-ok escape hatch was not honoured",
                 "    if (x < 0) abort(); // abort-ok: entropy failure, keys would be forgeable",
                 0);
    nra_st_expect(&s, "the /* abort-ok */ escape hatch was not honoured",
                 "    if (x < 0) abort(); /* abort-ok: entropy failure, keys forgeable */",
                 0);
    nra_st_expect(&s, "an empty abort-ok reason was accepted",
                 "    if (x < 0) abort(); // abort-ok:", 1);
    nra_st_expect(&s, "a line comment mentioning assert() was counted",
                 "    /* we used to assert(x > 0) here; it is a return now. */", 0);
    /* The case a naive per-line comment-stripper gets wrong: the word
     * lands on a block-comment CONTINUATION line with no comment opener
     * of its own. */
    nra_st_expect(&s, "a block-comment continuation mentioning assert() was counted",
                 "    /* Rationale:\n"
                 "     * the old assert(x > 0) let one hostile RPC argument abort the node,\n"
                 "     * and abort() on that path is a remote process kill.\n"
                 "     */", 0);
    nra_st_expect(&s, "a string literal containing assert( was counted",
                 "    const char *m = \"assert(x) was removed\";", 0);

    /* A scan that matches nothing must be LOUD, never a quiet PASS. */
    if (nra_st_plant(&s, "    return x > 0;")) {
        fprintf(stderr, "%s: SELFTEST FAIL — could not plant the empty-scan fixture\n",
                k_gate);
        s.fails++;
    } else {
        int rc = nra_st_run(&s, 999);
        if (rc != 2) {
            fprintf(stderr, "%s: SELFTEST FAIL — an empty scan did not abort "
                    "on the site floor (rc=%d)\n", k_gate, rc);
            s.fails++;
        } else {
            fprintf(stdout, "%s: selftest ok — empty scan aborts loud "
                    "(exit %d)\n", k_gate, rc);
        }
    }

    (void)rap_rm_rf(s.root);
    if (s.fails) {
        fprintf(stderr, "%s: SELFTEST FAILED (%d)\n", k_gate, s.fails);
        return 2;
    }
    fprintf(stdout,
            "[%s] SELFTEST PASS (runtime assert/abort and an empty hatch reason FAIL;\n"
            "        LOG_FAIL, _Static_assert, static_assert, both hatch forms, line and\n"
            "        block comments and string literals PASS; empty scan aborts loud)\n",
            k_gate);
    return 0;
}
