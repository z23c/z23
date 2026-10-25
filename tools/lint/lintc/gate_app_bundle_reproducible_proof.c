/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: proof half of the check-app-bundle-reproducible gate family.
 * Compiles the jsonq subject, runs the bundler, verifies the ad-hoc
 * signature with codesign, runs the launch probe and drives the two-run
 * comparison. Child output is judged as strictly as the bash gate judged
 * it: the exact "Signature=adhoc" token, the exact probe stdout for jsonq
 * and the required substring for a --bin subject.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_app_bundle_reproducible_priv.h"
#include "lintc.h"

/* The gate's own fixed flag set, applied identically to both compiles. */
int abr_compile_subject(const char *out)
{
    char *const argv[] = {
        (char *)"cc", (char *)"-std=c23", (char *)"-O2", (char *)"-Wall", (char *)"-Wextra",
        (char *)"-Werror", (char *)"-pedantic", (char *)"-D_POSIX_C_SOURCE=200809L",
        (char *)"-D_DARWIN_C_SOURCE", (char *)"-fblocks",
        (char *)"-Icontexts/commons/packages/zjsonp/include",
        (char *)"-Icontexts/commons/packages/zutf8/include", (char *)"-o", (char *)out,
        (char *)"tools/jsonq.c", (char *)"tools/jsonq_standalone.c",
        (char *)"contexts/commons/packages/zjsonp/src/zjsonp.c",
        (char *)"contexts/commons/packages/zutf8/src/zutf8.c", NULL
    };
    int code, rc = abr_exec(argv, LCP_PASS, NULL, NULL, &code);
    if (rc)
        return rc;
    if (code != 0)
        return abr_fatal("subject compile failed");
    if (access(out, X_OK) != 0)
        return abr_fatal("subject compile produced no executable at %s", out);
    return ABR_OK;
}

static void abr_indent(FILE *err, const char *text)
{
    for (const char *p = text; *p;) {
        size_t n = strcspn(p, "\n");
        fprintf(err, "    %.*s\n", (int)n, p);
        p += n + (p[n] == '\n');
    }
}

/* ABR_OK when codesign accepts the bundle strictly and reports it ad-hoc
 * signed, ABR_FAIL otherwise. */
int abr_verify_signature(const char *bundle, FILE *err)
{
    char *const verify[] = { (char *)"codesign", (char *)"--verify", (char *)"--strict",
                             (char *)bundle, NULL };
    char *const show[] = { (char *)"codesign", (char *)"-dv", (char *)bundle, NULL };
    struct lcp_buf info = { 0 };
    int code, rc = abr_exec(verify, LCP_QUIET, NULL, NULL, &code);
    if (rc)
        return rc;
    if (code != 0) {
        abr_note(err, "FAIL — codesign --verify --strict rejected %s", bundle);
        return ABR_FAIL;
    }
    if ((rc = abr_exec(show, LCP_BOTH, NULL, &info, &code)))
        return rc;
    lcp_buf_subst(&info);
    if (!info.data || !strstr(info.data, "Signature=adhoc")) {
        abr_note(err, "FAIL — %s is not ad-hoc signed:", bundle);
        if (err)
            abr_indent(err, info.data ? info.data : "");
        rc = ABR_FAIL;
    }
    lcp_buf_free(&info);
    return rc;
}

/* Splits a flag list on blanks into argv[1..]; argv[0] is exe. */
static int abr_split_args(const char *exe, const char *flags, char ***out, char **store)
{
    size_t cap;
    char *copy = strdup(flags ? flags : ""), *save = NULL;
    char **v = malloc((strlen(copy ? copy : "") / 2 + 3) * sizeof *v); // raw-alloc-ok:lint-runtime
    if (!copy || !v) {
        free(copy);
        free(v);
        return abr_fatal("out of memory");
    }
    v[0] = (char *)exe;
    cap = 1;
    for (char *t = strtok_r(copy, " \t\n", &save); t; t = strtok_r(NULL, " \t\n", &save))
        v[cap++] = t;
    v[cap] = NULL;
    *out = v;
    *store = copy;
    return ABR_OK;
}

static int abr_probe_judge(const struct abr_ctx *c, const char *out, FILE *err)
{
    const char *want = c->probe_expect;
    if (!c->bin) {
        want = want ? want : ABR_PROBE_EXPECT;
        if (strcmp(out, want) == 0)
            return ABR_OK;
        abr_note(err, "FAIL — bundled %s printed '%s' (wanted '%s')", c->app, out, want);
        return ABR_FAIL;
    }
    if (want) {
        const char *nl = strrchr(out, '\n');
        if (strstr(out, want))
            return ABR_OK;
        abr_note(err, "FAIL — bundled %s output did not contain '%s' (last line: '%s')",
                 c->app, want, nl ? nl + 1 : out);
        return ABR_FAIL;
    }
    if (*out == '\0') {
        abr_note(err, "FAIL — bundled %s printed nothing; the probe cannot tell a launch "
                      "from a silent crash", c->app);
        return ABR_FAIL;
    }
    return ABR_OK;
}

/* Launch probe: the bundled executable must exit 0 and satisfy the output
 * contract (exact equality for jsonq, substring or non-empty for --bin).
 * Input comes from a file, never a pipe, and a kernel signature rejection
 * shows up as a signal exit code. err NULL silences the messages. */
int abr_probe(const struct abr_ctx *c, const char *exe, const char *json_file, FILE *err)
{
    char *const jsonq_argv[] = { (char *)exe, (char *)"get", (char *)"a.b", NULL };
    char *const *argv = jsonq_argv;
    char **dyn = NULL, *store = NULL;
    struct lcp_buf out = { 0 };
    int code, rc = ABR_OK;
    if (c->bin && (rc = abr_split_args(exe, c->probe_args, &dyn, &store)))
        return rc;
    if (dyn)
        argv = dyn;
    rc = abr_exec(argv, err ? LCP_OUT_ERRPASS : LCP_OUT, c->bin ? "/dev/null" : json_file,
                  &out, &code);
    if (rc == ABR_OK) {
        lcp_buf_subst(&out);
        if (code != 0) {
            abr_note(err, "FAIL — bundled %s exited %d (wanted 0); a kernel signature "
                          "rejection kills rather than exits", c->app, code);
            rc = ABR_FAIL;
        } else {
            rc = abr_probe_judge(c, out.data ? out.data : "", err);
        }
    }
    lcp_buf_free(&out);
    free(dyn);
    free(store);
    return rc;
}

/* Runs the bundler and returns the bundle path it prints. */
int abr_bundle(const struct abr_ctx *c, const char *bin, const char *outdir,
               char bundle[ABR_PATH], const char *which)
{
    char *const argv[] = { (char *)ABR_BUNDLER, (char *)bin, (char *)c->app, (char *)outdir, NULL };
    struct lcp_buf out = { 0 };
    int code, rc = abr_exec(argv, LCP_OUT_ERRPASS, NULL, &out, &code);
    if (rc == ABR_OK) {
        lcp_buf_subst(&out);
        if (code != 0)
            rc = abr_fatal("%s", which);
        else if (snprintf(bundle, ABR_PATH, "%s", out.data ? out.data : "") >= ABR_PATH)
            rc = abr_fatal("path too long");
    }
    lcp_buf_free(&out);
    return rc;
}

/* Puts the subject binary at dir/<app>: compiled, or the prebuilt copy. */
static int abr_stage(const struct abr_ctx *c, const char *dir, char exe[ABR_PATH])
{
    int rc = abr_pathf(exe, "%s/%s", dir, c->app);
    if (rc)
        return rc;
    if (mkdir(dir, 0777) != 0)
        return abr_fatal("could not create %s", dir);
    if (!c->bin)
        return abr_compile_subject(exe);
    if (abr_copy_file(c->bin, exe))
        return abr_fatal("could not copy the subject binary");
    return chmod(exe, 0755) == 0 ? ABR_OK : abr_fatal("could not copy the subject binary");
}

static int abr_compare_all(const struct abr_ctx *c, FILE *err)
{
    static const struct { const char *kind, *label; } k[] = {
        { "content", "file content (sha256, signature included)" },
        { "meta", "file mode + mtime" },
        { "shape", "directory shape" },
    };
    int fail = 0;
    for (size_t i = 0; i < 3; i++) {
        char a[ABR_PATH], b[ABR_PATH];
        int rc = abr_pathf(a, "%s/%s.a", c->tmp, k[i].kind);
        if (rc || (rc = abr_pathf(b, "%s/%s.b", c->tmp, k[i].kind)))
            return rc;
        rc = abr_compare(k[i].label, a, b, err);
        if (rc == ABR_FAIL)
            fail = 1;
        else if (rc)
            return rc;
    }
    return fail ? ABR_FAIL : ABR_OK;
}

static int abr_check_inputs(const char *ea, const char *eb)
{
    int rc = abr_same_file(ea, eb);
    if (rc == ABR_FAIL) {
        fputs(ABR_GATE ": FAIL — the subject compiler itself is not deterministic:\n"
              "  two compiles of the same sources differ, so the two bundles below\n"
              "  would not be comparable. Fix the compile flags before trusting the\n"
              "  bundle proof.\n", stderr);
    }
    return rc;
}

static int abr_stage_both(const struct abr_ctx *c, const char *ra, const char *rb,
                          char ea[ABR_PATH], char eb[ABR_PATH])
{
    int rc = abr_stage(c, ra, ea);
    if (rc || (rc = abr_stage(c, rb, eb)))
        return rc;
    return abr_check_inputs(ea, eb);
}

static int abr_bundle_both(const struct abr_ctx *c, const char *ra, const char *rb,
                           const char *ea, const char *eb, char ba[ABR_PATH], char bb[ABR_PATH])
{
    char oa[ABR_PATH], ob[ABR_PATH];
    int rc = abr_pathf(oa, "%s/out", ra);
    if (rc || (rc = abr_pathf(ob, "%s/out", rb)) || (rc = abr_bundle(c, ea, oa, ba, "bundler failed on run A"))
        || (rc = abr_bundle(c, eb, ob, bb, "bundler failed on run B")))
        return rc;
    return strcmp(ba, bb) != 0 ? ABR_OK
                               : abr_fatal("the two runs wrote to the same bundle path — the proof is void");
}

/* Anti-hollow floor: executable, Info.plist, PkgInfo and CodeResources. */
static int abr_floor(int lines)
{
    return gate_require_scanned(lines, 4, ABR_GATE,
        "a signed .app bundle has at least MacOS/<exe>, Info.plist, PkgInfo and "
        "_CodeSignature/CodeResources") ? ABR_FATAL : ABR_OK;
}

static int abr_manifests(struct abr_ctx *c, const char *ba, const char *bb)
{
    int lines_b;
    char sha_b[ZSHA256_HEX_LEN];
    int rc = abr_manifest_tree(ba, c->tmp, "a", &c->lines, c->sha);
    if (rc || (rc = abr_manifest_tree(bb, c->tmp, "b", &lines_b, sha_b)))
        return rc;
    return abr_floor(c->lines);
}

static int abr_launch_both(const struct abr_ctx *c, const char *ba, const char *bb)
{
    char json[ABR_PATH], exe[ABR_PATH];
    const char *b[2] = { ba, bb };
    int rc = abr_pathf(json, "%s/probe.json", c->tmp);
    if (rc || (rc = abr_write_file(json, ABR_PROBE_JSON, strlen(ABR_PROBE_JSON))))
        return rc;
    for (int i = 0; i < 2; i++) {
        if ((rc = abr_verify_signature(b[i], stderr)))
            return rc;
    }
    for (int i = 0; i < 2; i++) {
        if ((rc = abr_pathf(exe, "%s/Contents/MacOS/%s", b[i], c->app))
            || (rc = abr_probe(c, exe, json, stderr)))
            return rc;
    }
    return ABR_OK;
}

/* Two runs, end to end, into two temp dirs: ABR_OK iff identical and launching. */
int abr_prove(struct abr_ctx *c)
{
    char ra[ABR_PATH], rb[ABR_PATH], ea[ABR_PATH], eb[ABR_PATH], ba[ABR_PATH], bb[ABR_PATH];
    int rc = abr_pathf(ra, "%s/a", c->tmp);
    if (rc || (rc = abr_pathf(rb, "%s/b", c->tmp)) || (rc = abr_stage_both(c, ra, rb, ea, eb))
        || (rc = abr_bundle_both(c, ra, rb, ea, eb, ba, bb)) || (rc = abr_manifests(c, ba, bb))
        || (rc = abr_compare_all(c, stderr)))
        return rc;
    return abr_launch_both(c, ba, bb);
}
