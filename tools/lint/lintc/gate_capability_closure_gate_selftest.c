/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of the capability-closure gate. Each case builds a fixture
 * tree in a throwaway directory, with a build epoch of real compiled objects,
 * and requires the gate to refuse what it must refuse and accept the positive
 * controls with the same status and the same words as the script it replaces.
 * Fixtures need no build epoch of this checkout.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "gate_capability_closure_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

enum { CGS_CASES = 25, CGS_FILLER = 500 };

static const char k_fx0[] = "build/dev-obj/epochs/fx0";

static const char k_use[] = "extern int connect(int, int, int);\nint use_it(void) { return connect(1, 2, 3); }\n";

static const char k_arm[] = "platform/modules/platform/src/os_sandbox_linux.c";

static const char k_plain[] = "static int local_only(int x) { return x + 1; }\n"
                              "int platform_export(int x) { return local_only(x); }\n";

struct cgs_res { char *text; int rc; };

/* The host's gate setup with every ambient knob pinned for the fixture. */
static void cgs_cfg(struct ccg_cfg *cfg)
{
    ccg_host_cfg(cfg);
    cfg->symmetry = 1;
    cfg->baseline = 0;
    cfg->cflags = NULL;
    cfg->record = NULL;
    cfg->repo = NULL;
}

static int cgs_cc_once(const char *src, const char *obj, const char *flag, int c23)
{
    char *argv[8] = { (char *)"cc" };
    int k = 1, code = 1;
    struct lcp_spec sp = { .argv = argv, .mode = LCP_QUIET, .grace_ms = 1000 };
    if (c23)
        argv[k++] = (char *)"-std=c23";
    if (flag)
        argv[k++] = (char *)flag;
    argv[k++] = (char *)"-c";
    argv[k++] = (char *)src;
    argv[k++] = (char *)"-o";
    argv[k++] = (char *)obj;
    argv[k] = NULL;
    return lcp_run(&sp, NULL, &code) == 0 && code == 0;
}

/* Compiles fx/src_rel to fx/obj_rel as C23, else as the compiler's default. */
static int cgs_cc(const struct ccs_fx *fx, const char *src_rel, const char *obj_rel, const char *flag)
{
    char src[CCD_PATH], obj[CCD_PATH], dir[CCD_PATH];
    ccs_path(fx, src_rel, src);
    ccs_path(fx, obj_rel, obj);
    snprintf(dir, sizeof dir, "%s", obj);
    *strrchr(dir, '/') = '\0';
    return csr_mkdirs(dir) == 0 && (cgs_cc_once(src, obj, flag, 1) || cgs_cc_once(src, obj, flag, 0)) ? 0 : -1;
}

/* The unit every filler shares: no undefined symbol. */
static int cgs_filler(const struct ccs_fx *fx)
{
    return ccs_put(fx, ".filler.c", "static int filler_fn(int x) { return x + 1; }\n"
                                    "int filler_export(int x) { return filler_fn(x) + 1; }\n") == 0
           && cgs_cc(fx, ".filler.c", ".filler.o", NULL) == 0 ? 0 : -1;
}

/* Hard links filler_1..N of one compiled unit under fx/dir_rel. */
static int cgs_links(const struct ccs_fx *fx, const char *from_rel, const char *dir_rel, const char *ext)
{
    char from[CCD_PATH], to[CCD_PATH], rel[CCD_PATH];
    ccs_path(fx, from_rel, from);
    ccs_path(fx, dir_rel, to);
    if (csr_mkdirs(to) != 0)
        return -1;
    for (int i = 1; i <= CGS_FILLER; i++) {
        snprintf(rel, sizeof rel, "%s/filler_%d.%s", dir_rel, i, ext);
        ccs_path(fx, rel, to);
        if (link(from, to) != 0)
            return -1;
    }
    return 0;
}

/* The anti-hollow floor of filler objects, each with its source: an object
 * without a source in the tree is foreign and not graded. */
static int cgs_epoch(const struct ccs_fx *fx, const char *dir)
{
    char objs[CCD_PATH], srcs[CCD_PATH];
    snprintf(objs, sizeof objs, "%s/%s/filler", dir, k_fx0);
    snprintf(srcs, sizeof srcs, "%s/filler", dir);
    return cgs_links(fx, ".filler.o", objs, "o") == 0 && cgs_links(fx, ".filler.c", srcs, "c") == 0 ? 0 : -1;
}

/* A fixture root: the filler epoch, the one classified symbol (connect is
 * CAP_NETWORK) and exactly the given module rows. */
static int cgs_base(const struct ccs_fx *fx, const char *dir, const char *rows)
{
    char rel[CCD_PATH];
    int bad = cgs_epoch(fx, dir);
    snprintf(rel, sizeof rel, "%s/engine/composition/capability_symbols.def", dir);
    bad |= ccs_put(fx, rel, "ZCL_CAPABILITY_SYMBOL(\"connect\", CAP_NETWORK, \"\")\n");
    snprintf(rel, sizeof rel, "%s/engine/composition/module_capabilities.def", dir);
    return bad | ccs_put(fx, rel, rows);
}

/* Writes dir/src and compiles it to its epoch object, .c becoming .o. */
static int cgs_unit(const struct ccs_fx *fx, const char *dir, const char *src, const char *code, const char *flag)
{
    char s[CCD_PATH], o[CCD_PATH];
    snprintf(s, sizeof s, "%s/%s", dir, src);
    snprintf(o, sizeof o, "%s/%s/%.*s.o", dir, k_fx0, (int)(strlen(src) - 2), src);
    return ccs_put(fx, s, code) == 0 && cgs_cc(fx, s, o, flag) == 0 ? 0 : -1;
}

static int cgs_is(const struct ccd_map *m, const char *key)
{
    const char *v = ccd_map_get(m, key);
    return v && strcmp(v, "CAP_NETWORK") == 0;
}

/* A pre-formatted module row. */
static const char *cgs_row(char *buf, size_t cap, const char *path, const char *caps)
{
    snprintf(buf, cap, "ZCL_MODULE_CAPABILITY(\"%s\", %s, \"test\")\n", path, caps);
    return buf;
}

static int cgs_run(const struct ccs_fx *fx, const char *dir, const struct ccg_cfg *base, struct cgs_res *r)
{
    struct ccg_cfg cfg = *base;
    char root[CCD_PATH];
    size_t n = 0;
    FILE *m;
    ccs_path(fx, dir, root);
    r->text = NULL;
    if (!(m = open_memstream(&r->text, &n)))
        return r->rc = -1;
    cfg.out = cfg.err = m;
    r->rc = ccg_check_root(&cfg, root);
    fclose(m);
    return r->rc;
}

/* The gate text a failed case leaves for the reader. */
static void cgs_show(const char *text)
{
    for (const char *p = text ? text : ""; *p;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        printf("    %.*s\n", (int)n, p);
        p += n + (nl != NULL);
    }
}

/* The gate ended with status want (any nonzero when want is negative) and its
 * text holds every needle. */
static int cgs_verdict(struct cgs_res *r, int want, const char *const *needles, const char *label)
{
    char name[600] = "";
    int ok = want < 0 ? r->rc > 0 : r->rc == want;
    for (; ok && needles && *needles; needles++)
        ok = r->text && strstr(r->text, *needles);
    if (want < 0)
        snprintf(name, sizeof name, "%s (rc=%d)", label, r->rc);
    if (!ok)
        cgs_show(r->text);
    free(r->text);
    return ccs_say(ok, want < 0 ? name : label);
}

/* Runs the gate on fx/dir and judges it. */
static int cgs_check(const struct ccs_fx *fx, const char *dir, const struct ccg_cfg *cfg, int want,
                     const char *const *needles, const char *label)
{
    struct cgs_res r;
    cgs_run(fx, dir, cfg, &r);
    return cgs_verdict(&r, want, needles, label);
}

/* A. an undeclared strong-undefined reach is the core property. */
static int cgs_case_a(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    const char *const need[] = { "undeclared reach", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "a", "") != 0 || cgs_unit(fx, "a", "fixture_src/undeclared_user.c", k_use, NULL) != 0)
        return ccs_say(0, "A: fixture");
    return cgs_check(fx, "a", &cfg, -1, need, "A: undeclared strong-undefined reach to a classified symbol");
}

/* B. a row granting a class the object never uses. */
static int cgs_case_b(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    const char *const need[] = { "overdeclared", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "b", cgs_row(row, sizeof row, "fixture_src/overdeclared_user.c", "CAP_NETWORK")) != 0
        || cgs_unit(fx, "b", "fixture_src/overdeclared_user.c",
                    "static int nothing_dangerous(int x) { return x * 2; }\n"
                    "int overdeclared_export(int x) { return nothing_dangerous(x); }\n", NULL) != 0)
        return ccs_say(0, "B: fixture");
    return cgs_check(fx, "b", &cfg, -1, need, "B: declared CAP_NETWORK never used by the object");
}

/* D. a correct fixture passes; restart-base.o, a relocatable aggregate of the
 * same objects, carries an unclassified edge and must stay unscanned. */
static int cgs_case_d(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    cgs_cfg(&cfg);
    if (cgs_base(fx, "d", cgs_row(row, sizeof row, "fixture_src/declared_user.c", "CAP_NETWORK")) != 0
        || cgs_unit(fx, "d", "fixture_src/declared_user.c", k_use, NULL) != 0
        || ccs_put(fx, "d/.restart-base.c", "extern int aggregate_only_unknown(void);\n"
                                           "int aggregate_edge(void) { return aggregate_only_unknown(); }\n") != 0
        || cgs_cc(fx, "d/.restart-base.c", "d/build/dev-obj/epochs/fx0/restart-base.o", NULL) != 0)
        return ccs_say(0, "D: fixture");
    return cgs_check(fx, "d", &cfg, 0, NULL, "D: a correctly declared, fully-used fixture passes (positive control)");
}

/* E. an epoch below the object floor is UNPROVEN, never a clean pass. */
static int cgs_case_e(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    const char *const need[] = { "UNPROVEN", NULL };
    char rel[CCD_PATH];
    cgs_cfg(&cfg);
    ccs_path(fx, "e/build/dev-obj/epochs/fx0", rel);
    if (csr_mkdirs(rel) != 0 || ccs_put(fx, "e/engine/composition/capability_symbols.def",
                                        "ZCL_CAPABILITY_SYMBOL(\"connect\", CAP_NETWORK, \"\")\n") != 0
        || ccs_put(fx, "e/engine/composition/module_capabilities.def", "") != 0)
        return ccs_say(0, "E: fixture");
    return cgs_check(fx, "e", &cfg, 2, need, "E: an epoch below the object floor is UNPROVEN, exit 2, never 0");
}

/* C. a WEAK-undefined reach is still a reach: the regression case for an
 * extraction that kept only strong references. */
static int cgs_case_c(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    const char *const need[] = { "undeclared reach", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "c", "") != 0
        || cgs_unit(fx, "c", "fixture_src/weak_undeclared_user.c",
                    "extern __attribute__((weak)) int connect(int, int, int);\n"
                    "int use_weak(void) { return connect(1, 2, 3); }\n", NULL) != 0)
        return ccs_say(0, "C: fixture");
    return cgs_check(fx, "c", &cfg, -1, need, "C: undeclared WEAK-undefined reach to a classified symbol (regression)");
}

/* F. a declared row with no compiled object, above the baseline, is a scan
 * that did not happen: the partial-epoch regression that the object floor
 * cannot see. */
static int cgs_case_f(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    const char *const need[] = { "UNPROVEN", "phantom_tool.c", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "f", cgs_row(row, sizeof row, "fixture_src/phantom_tool.c", "CAP_NETWORK")) != 0
        || ccs_put(fx, "f/fixture_src/phantom_tool.c", "int phantom_export(int x) { return x + 1; }\n") != 0)
        return ccs_say(0, "F: fixture");
    return cgs_check(fx, "f", &cfg, 2, need,
                     "F: a partial epoch missing a declared file (above the coverage baseline) is UNPROVEN, exit 2, never 0 or 1");
}

/* G. a baseline above the true unobserved count is a violation, so the ratchet
 * cannot rust shut at a stale number. */
static int cgs_case_g(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    const char *const need[] = { "coverage baseline is stale", NULL };
    cgs_cfg(&cfg);
    cfg.baseline = 1;
    if (cgs_base(fx, "g", cgs_row(row, sizeof row, "fixture_src/declared_user_g.c", "CAP_NETWORK")) != 0
        || cgs_unit(fx, "g", "fixture_src/declared_user_g.c", k_use, NULL) != 0)
        return ccs_say(0, "G: fixture");
    return cgs_check(fx, "g", &cfg, 1, need,
                     "G: a coverage baseline held above the true (improved) unobserved count is a VIOLATION, exit 1, not silently tolerated");
}

/* H. a drive-letter colon is not the record delimiter of an nm line. */
static int cgs_case_h(void)
{
    struct ccd_nm nm = { 0 };
    int ok = ccd_parse_nm("C:/work/epoch/core/modules/net/dialer.o:         U connect\n", 0, &nm) == 0 && nm.n == 1
             && strcmp(nm.row[0].path, "C:/work/epoch/core/modules/net/dialer.o") == 0
             && strcmp(nm.row[0].type, "U") == 0 && strcmp(nm.row[0].name, "connect") == 0;
    ccd_nm_free(&nm);
    return ccs_say(ok, "H: Windows drive-letter nm records preserve the full object path");
}

/* I. COFF import pointers and MinGW wrappers are spellings of a reviewed entry. */
static int cgs_case_i(const struct ccs_fx *fx)
{
    char file[CCD_PATH];
    struct ccd_map m = { 0 };
    size_t n = 0;
    int ok = ccs_put(fx, "i/capability_symbols.def", "ZCL_CAPABILITY_SYMBOL(\"connect\", CAP_NETWORK, \"\")\n") == 0;
    ccs_path(fx, "i/capability_symbols.def", file);
    ok = ok && ccd_symbols_load(file, 1, &m, &n) == 0;
    ok = ok && cgs_is(&m, "__imp_connect") && cgs_is(&m, "__imp__connect") && cgs_is(&m, "__mingw_connect");
    ccd_map_free(&m);
    return ccs_say(ok, "I: MinGW import and wrapper decorations inherit the base symbol class");
}

/* J. a Windows exact override replaces the portable row, CAP_NONE included, and
 * the platform skips apply to the named Linux arm only. */
static int cgs_case_j(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char rows[2 * CCD_PATH], one[CCD_PATH];
    cgs_cfg(&cfg);
    cfg.os = CCD_WINDOWS;
    snprintf(rows, sizeof rows, "%s", cgs_row(one, sizeof one, "fixture_src/platform_user.c", "CAP_NETWORK"));
    strncat(rows, cgs_row(one, sizeof one, k_arm, "CAP_NETWORK"), sizeof rows - strlen(rows) - 1);
    if (cgs_base(fx, "j", rows) != 0 || cgs_unit(fx, "j", "fixture_src/platform_user.c", k_plain, NULL) != 0
        || ccs_put(fx, "j/platform/modules/platform/src/os_sandbox_linux.c", "int linux_only_fixture(void) { return 1; }\n") != 0
        || ccs_put(fx, "j/engine/composition/module_capabilities_windows.def",
                   cgs_row(one, sizeof one, "fixture_src/platform_user.c", "CAP_NONE")) != 0)
        return ccs_say(0, "J: fixture");
    return cgs_check(fx, "j", &cfg, 0, NULL,
                     "J: Windows exact CAP_NONE override replaces portable reach and skips only the named Linux arm");
}

/* K. a Linux exact override has the same replacement semantics. */
static int cgs_case_k(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    cgs_cfg(&cfg);
    cfg.os = CCD_LINUX;
    if (cgs_base(fx, "k", cgs_row(row, sizeof row, "fixture_src/platform_user.c", "CAP_NETWORK")) != 0
        || cgs_unit(fx, "k", "fixture_src/platform_user.c", k_plain, NULL) != 0
        || ccs_put(fx, "k/engine/composition/module_capabilities_linux.def",
                   cgs_row(row, sizeof row, "fixture_src/platform_user.c", "CAP_NONE")) != 0)
        return ccs_say(0, "K: fixture");
    return cgs_check(fx, "k", &cfg, 0, NULL, "K: Linux exact CAP_NONE override replaces portable cross-target reach");
}

/* L. coverage grades the exact host-selected graph while the two standalone
 * rows stay applicable everywhere. */
static int cgs_case_l(void)
{
    static const char *const stub = "platform/modules/platform/src/os_sandbox_stub.c";
    static const char *const pkg = "platform/modules/platform/src/os_sandbox_package_linux.c";
    static const char *const terminal = "platform/modules/platform/src/os_sandbox_terminal_worker.c";
    int linux_ok = !ccd_coverage_applicable(CCD_LINUX, stub)
                   && ccd_coverage_applicable(CCD_LINUX, terminal)
                   && ccd_coverage_applicable(CCD_LINUX, "tests/harness/src/test_thread_qos.c")
                   && ccd_coverage_applicable(CCD_LINUX, "tools/dev/wallet_gui_load.c")
                   && ccd_coverage_applicable(CCD_LINUX, "tools/rebuild_recent.c");
    int darwin_ok = !ccd_coverage_applicable(CCD_DARWIN, k_arm) && !ccd_coverage_applicable(CCD_DARWIN, pkg)
                    && !ccd_coverage_applicable(CCD_DARWIN, terminal)
                    && !ccd_coverage_applicable(CCD_DARWIN, "platform/modules/util/src/self_backtrace.c")
                    && !ccd_coverage_applicable(CCD_DARWIN, "tools/dev/wallet_gui_load.c");
    int windows_ok = !ccd_coverage_applicable(CCD_WINDOWS, k_arm) && !ccd_coverage_applicable(CCD_WINDOWS, pkg)
                     && !ccd_coverage_applicable(CCD_WINDOWS, terminal)
                     && !ccd_coverage_applicable(CCD_WINDOWS, "contexts/commons/modules/vcs/src/vcs_devloop.c")
                     && !ccd_coverage_applicable(CCD_WINDOWS, "tools/package_verify.c");
    return ccs_say(linux_ok && darwin_ok && windows_ok,
                   "L: coverage follows exact host-source selection and retains the two standalone rows");
}

/* M. a valid object with no symbols is still compiled evidence: nm prints no
 * row for it, so coverage must come from the frozen object list. */
static int cgs_case_m(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    cgs_cfg(&cfg);
    cfg.os = CCD_LINUX;
    if (cgs_base(fx, "m", cgs_row(row, sizeof row, "fixture_src/empty_user.c", "CAP_NONE")) != 0
        || cgs_unit(fx, "m", "fixture_src/empty_user.c", "typedef int empty_user_not_on_this_platform;\n", NULL) != 0)
        return ccs_say(0, "M: fixture");
    return cgs_check(fx, "m", &cfg, 0, NULL, "M: a symbol-free object is present coverage evidence");
}

/* N1. a declaration behind a guard macro this build never defines is
 * UNOBSERVED: clean exit, never a violation. */
static int cgs_case_n1(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    struct cgs_res r;
    char row[CCD_PATH];
    cgs_cfg(&cfg);
    cfg.cflags = "";
    if (cgs_base(fx, "n", cgs_row(row, sizeof row, "fixture_src/compiled_out_user.c", "CAP_NETWORK")) != 0
        || cgs_unit(fx, "n", "fixture_src/compiled_out_user.c",
                    "#if defined(FIXTURE_N_MISSING_MACRO)\nextern int connect(int, int, int);\n"
                    "int use_compiled_out(void) { return connect(1, 2, 3); }\n#else\n"
                    "typedef int compiled_out_user_unused;\n#endif\n", NULL) != 0)
        return ccs_say(0, "N1: fixture");
    cgs_run(fx, "n", &cfg, &r);
    int ok = r.rc == 0 && r.text && strstr(r.text, "UNOBSERVED (compiled out: FIXTURE_N_MISSING_MACRO)")
             && !strstr(r.text, "check_capability_closure: VIOLATION");
    if (!ok)
        cgs_show(r.text);
    free(r.text);
    return ccs_say(ok, "N1: a declaration behind a guard this build never defines is UNOBSERVED, exit 0, never a VIOLATION");
}

static const char k_n2_src[] = "#if defined(FIXTURE_N_PRESENT_MACRO)\nstatic int nothing_dangerous(int x) { return x + 1; }\n"
                               "int still_overdeclared_export(int x) { return nothing_dangerous(x); }\n#else\n"
                               "typedef int still_overdeclared_user_unused;\n#endif\n";

/* N2. the same guard shape with the macro defined is not compiled out, so a
 * genuine overdeclaration behind it still fails. */
static int cgs_case_n2(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    const char *const need[] = { "still_overdeclared_user.c declares CAP_NETWORK", NULL };
    cgs_cfg(&cfg);
    cfg.cflags = "-DFIXTURE_N_PRESENT_MACRO";
    if (cgs_base(fx, "n2", cgs_row(row, sizeof row, "fixture_src/still_overdeclared_user.c", "CAP_NETWORK")) != 0
        || cgs_unit(fx, "n2", "fixture_src/still_overdeclared_user.c", k_n2_src, "-DFIXTURE_N_PRESENT_MACRO") != 0)
        return ccs_say(0, "N2: fixture");
    return cgs_check(fx, "n2", &cfg, -1, need,
                     "N2: a guard this build DOES define is not compiled-out \xe2\x80\x94 genuine overdeclaration still VIOLATIONs");
}

/* Lines of the file the flag query appends to, or -1. */
static int cgs_loads(const struct ccs_fx *fx)
{
    char path[CCD_PATH], line[64];
    int n = 0;
    FILE *f;
    ccs_path(fx, "n2/flags-loads", path);
    if (!(f = fopen(path, "r")))
        return -1;
    while (fgets(line, sizeof line, f))
        n++;
    fclose(f);
    return n;
}

/* O. several capabilities share one flags observation per check, but a later
 * check must see changed flags rather than inherit that cache. */
static int cgs_case_o(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    struct cgs_res r;
    int ok;
    cgs_cfg(&cfg);
    if (ccs_put(fx, "n2/engine/composition/module_capabilities.def",
                "ZCL_MODULE_CAPABILITY(\"fixture_src/still_overdeclared_user.c\", CAP_NETWORK|CAP_CLOCK, \"test\")\n") != 0
        || ccs_put(fx, "n2/Makefile", "print-CFLAGS:\n\t@echo load >> flags-loads\n") != 0)
        return ccs_say(0, "O: fixture");
    ok = cgs_run(fx, "n2", &cfg, &r) == 0 && cgs_loads(fx) == 1;
    free(r.text);
    if (ok) {
        cfg.cflags = "-DFIXTURE_N_PRESENT_MACRO -UFIXTURE_N_PRESENT_MACRO -DFIXTURE_N_PRESENT_MACRO";
        ok = cgs_run(fx, "n2", &cfg, &r) == 1 && r.text && strstr(r.text, "declares CAP_NETWORK");
        free(r.text);
    }
    return ccs_say(ok, "O: flags load once per check and changed flags still reject overdeclaration");
}

/* P. a source-owned declaration removes the central row edit without weakening
 * closure; a misplaced one and a duplicate of a central row refuse. */
static int cgs_case_p(const struct ccs_fx *fx)
{
    static const char sc[] = "p/contexts/commons/modules/vcs/src/owned.c.capabilities.def";
    static const char own[] = "contexts/commons/modules/vcs/src/owned.c";
    struct ccg_cfg cfg;
    char row[CCD_PATH], other[CCD_PATH];
    const char *const bad[] = { "invalid source-owned", NULL }, *const dup[] = { "duplicate central row", NULL };
    int f;
    cgs_cfg(&cfg);
    if (cgs_base(fx, "p", "") != 0 || cgs_unit(fx, "p", own, k_use, NULL) != 0)
        return ccs_say(0, "P: fixture");
    cgs_row(row, sizeof row, own, "CAP_NETWORK");
    cgs_row(other, sizeof other, "contexts/commons/modules/vcs/src/other.c", "CAP_NETWORK");
    f = ccs_put(fx, sc, row) != 0;
    f += cgs_check(fx, "p", &cfg, 0, NULL, "P1: source-owned declaration closes the compiled object");
    f += ccs_put(fx, sc, other) != 0;
    f += cgs_check(fx, "p", &cfg, -1, bad, "P2: misplaced source-owned declaration refuses");
    f += ccs_put(fx, sc, row) != 0;
    f += ccs_put(fx, "p/engine/composition/module_capabilities.def", row) != 0;
    return f + cgs_check(fx, "p", &cfg, -1, dup, "P3: central and source-owned duplicate refuses");
}

/* Q. the raw syscall ban reports a source that has no object in this epoch. The
 * fixture text is split so that this file does not itself trip the ban. */
static int cgs_case_q(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    const char *const need[] = { "raw syscall", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "q", "") != 0
        || ccs_put(fx, "q/fixture_src/raw_user.c", "extern long sys" "call(long, ...);\n"
                                                  "long raw_use(void) { return sys" "call(0); }\n") != 0)
        return ccs_say(0, "Q: fixture");
    return cgs_check(fx, "q", &cfg, -1, need, "Q: raw syscall in an uncompiled source still refuses");
}

/* V. a source with embedded NUL bytes is scanned in bounds: a ban hit after the NUL on
 * the same line is found (line 1), and the line after it is still numbered (line 2). */
static int cgs_case_v(const struct ccs_fx *fx)
{
    static const char src[] = "a\0 sys" "call(0);\nlong raw_use(void) { return sys" "call(0); }\n";
    struct ccg_cfg cfg;
    char path[CCD_PATH];
    FILE *f;
    const char *const need[] = { "raw syscall", "    1: sys" "call(0);", "    2:long raw_use", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "v", "") != 0 || ccs_put(fx, "v/fixture_src/seed.txt", "x\n") != 0)
        return ccs_say(0, "V: fixture");
    ccs_path(fx, "v/fixture_src/nul_user.c", path);
    f = fopen(path, "wb");
    if (!f || fwrite(src, 1, sizeof src - 1, f) != sizeof src - 1 || fclose(f) != 0)
        return ccs_say(0, "V: write");
    return cgs_check(fx, "v", &cfg, -1, need, "V: a ban hit after an embedded NUL is found, later lines are numbered");
}

/* R. the leftover object of a failed candidate has no source in this tree: it is
 * foreign, counted and not graded. Case A is the other half. */
static int cgs_case_r(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    const char *const need[] = { "foreign-objects=1", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "r", "") != 0 || ccs_put(fx, ".foreign_verify_attest.c", k_use) != 0
        || cgs_cc(fx, ".foreign_verify_attest.c", "r/build/dev-obj/epochs/fx0/tools/dev/verify_attest.o", NULL) != 0)
        return ccs_say(0, "R: fixture");
    return cgs_check(fx, "r", &cfg, 0, need, "R: an object whose source is absent is foreign, counted, and not graded");
}

/* W. an object older than its source is a stale build: UNPROVEN (2) and named
 * as stale, never graded. The source's mtime is set into the future. */
static int cgs_case_w(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char src[CCD_PATH], obj[CCD_PATH];
    struct stat ost;
    struct timespec t[2] = { { 0, UTIME_OMIT }, { 0, 0 } };
    const char *const need[] = { "UNPROVEN", "older than their sources", "fixture_src/stale_user.o", NULL };
    cgs_cfg(&cfg);
    if (cgs_base(fx, "w", "") != 0 || cgs_unit(fx, "w", "fixture_src/stale_user.c", k_use, NULL) != 0)
        return ccs_say(0, "W: fixture");
    ccs_path(fx, "w/fixture_src/stale_user.c", src);
    ccs_path(fx, "w/build/dev-obj/epochs/fx0/fixture_src/stale_user.o", obj);
    if (stat(obj, &ost) != 0)
        return ccs_say(0, "W: stat object");
    t[1].tv_sec = ost.st_mtime + 100;
    if (utimensat(AT_FDCWD, src, t, 0) != 0)
        return ccs_say(0, "W: utimensat");
    return cgs_check(fx, "w", &cfg, 2, need, "W: an object older than its source is UNPROVEN, never graded");
}

/* X. the same tree with every object newer than its source grades as before:
 * clean (0) and not reported stale. */
static int cgs_case_x(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH];
    cgs_cfg(&cfg);
    if (cgs_base(fx, "x", cgs_row(row, sizeof row, "fixture_src/fresh_user.c", "CAP_NETWORK")) != 0
        || cgs_unit(fx, "x", "fixture_src/fresh_user.c", k_use, NULL) != 0)
        return ccs_say(0, "X: fixture");
    return cgs_check(fx, "x", &cfg, 0, NULL, "X: objects newer than their sources grade as before, not stale");
}

static int cgs_skip_root(const char *label)
{
    if (geteuid() != 0)
        return 0;
    printf("  SKIP %s: running as root, chmod 000 does not deny the read\n", label);
    return 1;
}

/* S. an object subdirectory that cannot be opened is FATAL: its objects were
 * not scanned, so a clean verdict would be a guess. Q-like control: case D. */
static int cgs_case_s(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char row[CCD_PATH], dir[CCD_PATH];
    const char *const need[] = { "FATAL", "cannot open directory", "Permission denied", NULL };
    int f;
    if (cgs_skip_root("S: unreadable object subdirectory"))
        return 0;
    cgs_cfg(&cfg);
    if (cgs_base(fx, "s", cgs_row(row, sizeof row, "fixture_src/declared_user.c", "CAP_NETWORK")) != 0
        || cgs_unit(fx, "s", "fixture_src/declared_user.c", k_use, NULL) != 0)
        return ccs_say(0, "S: fixture");
    ccs_path(fx, "s/build/dev-obj/epochs/fx0/fixture_src", dir);
    if (chmod(dir, 0) != 0)
        return ccs_say(0, "S: chmod");
    f = cgs_check(fx, "s", &cfg, 2, need, "S: an unopenable object subdirectory is FATAL, never an empty one");
    return f + (chmod(dir, 0755) != 0);
}

/* T. a tracked source the ban cannot open is FATAL, never skipped. */
static int cgs_case_t(const struct ccs_fx *fx)
{
    struct ccg_cfg cfg;
    char src[CCD_PATH];
    const char *const need[] = { "FATAL", "cannot scan fixture_src/raw_user.c", "Permission denied", NULL };
    int f;
    if (cgs_skip_root("T: unreadable source"))
        return 0;
    cgs_cfg(&cfg);
    if (cgs_base(fx, "t", "") != 0
        || ccs_put(fx, "t/fixture_src/raw_user.c", "long raw_use(void) { return sys" "call(0); }\n") != 0)
        return ccs_say(0, "T: fixture");
    ccs_path(fx, "t/fixture_src/raw_user.c", src);
    if (chmod(src, 0) != 0)
        return ccs_say(0, "T: chmod");
    f = cgs_check(fx, "t", &cfg, 2, need, "T: an unreadable source cannot escape the raw syscall ban");
    return f + (chmod(src, 0644) != 0);
}

static int cgs_count_line(void *ctx, const char *line, size_t len)
{
    (void)line;
    (void)len;
    ++*(int *)ctx;
    return 0;
}

/* U. lc_each_line, called directly, on a directory: fopen succeeds on Linux and
 * getline then fails with EISDIR. It must return 2 with errno EISDIR and never
 * call the callback. The gate cannot reach this path because its walk keeps
 * only regular files. */
static int cgs_case_u(const struct ccs_fx *fx)
{
    char dir[CCD_PATH];
    int calls = 0, rc;
    if (cgs_base(fx, "u", "") != 0)
        return ccs_say(0, "U: fixture");
    ccs_path(fx, "u", dir);
    errno = 0;
    rc = lc_each_line(dir, cgs_count_line, &calls, 0);
    if (rc != 2 || errno != EISDIR || calls != 0)
        return ccs_say(0, "U: lc_each_line on a directory must return 2 with EISDIR and no callback");
    puts("  selftest ok: U: lc_each_line fails a read after a successful open (rc=2, EISDIR, no callback)");
    return 0;
}

static int cgs_cases(const struct ccs_fx *fx)
{
    return cgs_case_a(fx) + cgs_case_b(fx) + cgs_case_c(fx) + cgs_case_d(fx) + cgs_case_e(fx) + cgs_case_f(fx) +
           cgs_case_g(fx) + cgs_case_h() + cgs_case_i(fx) + cgs_case_j(fx) + cgs_case_k(fx) + cgs_case_l() +
           cgs_case_m(fx) + cgs_case_n1(fx) + cgs_case_n2(fx) + cgs_case_o(fx) + cgs_case_p(fx) + cgs_case_q(fx) +
           cgs_case_r(fx) + cgs_case_s(fx) + cgs_case_t(fx) + cgs_case_u(fx) + cgs_case_v(fx) + cgs_case_w(fx) +
           cgs_case_x(fx);
}

int check_capability_closure_selftest(void)
{
    struct ccs_fx fx;
    int fails;
    if (lsc_install() != 0 || ccs_scratch(&fx) != 0) {
        fputs("check_capability_closure selftest: cannot prepare the scratch directory\n", stderr);
        return 2;
    }
    if (cgs_filler(&fx) != 0) {
        fputs("check_capability_closure --selftest: FATAL \xe2\x80\x94 cannot compile fixture objects with cc\n", stderr);
        lsc_unblock();
        rap_rm_rf(fx.base);
        return 2;
    }
    puts("== check_capability_closure selftest ==");
    fails = cgs_cases(&fx);
    lsc_unblock();
    rap_rm_rf(fx.base);
    if (fails == 0)
        printf("== selftest: PASS (%d/%d) ==\n", CGS_CASES, CGS_CASES);
    else
        puts("== selftest: FAIL ==");
    return fails == 0 ? 0 : 1;
}
