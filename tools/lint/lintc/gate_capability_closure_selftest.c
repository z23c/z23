/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: selftest of the capability-closure data layer. Parses nm records
 * in the GNU, Darwin and MinGW spellings, runs the real nm over compiled
 * objects (symbol-free, corrupt, batched), and loads symbol and module tables
 * from throwaway fixture trees (Windows aliases, platform overrides, sidecars).
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
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

static const char k_own[] = "contexts/commons/modules/vcs/src/owned.c";
static const char k_arm[] = "platform/modules/platform/src/os_sandbox_linux.c";

int ccs_say(int ok, const char *name)
{
    printf(ok ? "  selftest ok: %s\n" : "SELFTEST FAIL: %s\n", name);
    return ok ? 0 : 1;
}

static int ccs_eq(const struct ccd_map *m, const char *k, const char *v)
{
    const char *got = ccd_map_get(m, k);
    return got && strcmp(got, v) == 0;
}

static int ccs_row(const struct ccd_nm *nm, size_t i, const char *p, const char *t, const char *n)
{
    return i < nm->n && !strcmp(nm->row[i].path, p) && !strcmp(nm->row[i].type, t) && !strcmp(nm->row[i].name, n);
}

static int ccs_parse(const char *text, int strip, struct ccd_nm *nm)
{
    *nm = (struct ccd_nm){ 0 };
    return ccd_parse_nm(text, strip, nm);
}

static int ccs_case_parse(void)
{
    struct ccd_nm a = {0}, b = {0}, c = {0}, d = {0}, empty = {0};
    int ok = ccs_parse("C:/work/epoch/dialer.o:         U connect\nD:\\obj\\x.o:0000000000000000 T main\n", 0, &a) == 0;
    int f = ccs_say(ok && a.n == 2 && ccs_row(&a, 0, "C:/work/epoch/dialer.o", "U", "connect")
                    && ccs_row(&a, 1, "D:\\obj\\x.o", "T", "main"),
                    "H: Windows drive-letter nm records keep the whole object path");
    ok = ccs_parse("a.o:0000000000000010 T main\na.o:                 w weak_one\nnm: warning: bad object file\n"
                   "no colon here\na.o: 1 2 3 4\nC:/x\n\nb.o:  v weak_obj\n", 0, &b) == 0;
    f += ccs_say(ok && b.n == 3 && ccs_row(&b, 0, "a.o", "T", "main") && ccs_row(&b, 1, "a.o", "w", "weak_one")
                 && ccs_row(&b, 2, "b.o", "v", "weak_obj"), "nm: bare and address rows parse, other token counts drop");
    const char *text = "a.o: U _open$UNIX2003\na.o: U _fopen$DARWIN_EXTSN\na.o: U _plain\na.o: U _x$lower\n";
    ok = ccs_parse(text, 1, &c) == 0 && ccs_parse(text, 0, &d) == 0;
    f += ccs_say(ok && c.n == 4 && !strcmp(c.row[0].name, "open") && !strcmp(c.row[1].name, "fopen")
                 && !strcmp(c.row[2].name, "plain") && !strcmp(c.row[3].name, "x$lower")
                 && !strcmp(d.row[0].name, "_open$UNIX2003"), "nm: Darwin decoration is stripped only when asked");
    f += ccs_say(ccs_parse("", 0, &empty) == 0 && empty.n == 0 && !ccd_nm_failed(&empty),
                 "nm: empty output adds no rows and no failure");
    ccd_nm_free(&a);
    ccd_nm_free(&b);
    ccd_nm_free(&c);
    ccd_nm_free(&d);
    ccd_nm_free(&empty);
    return f;
}

int ccs_scratch(struct ccs_fx *fx)
{
    const char *tmp = getenv("TMPDIR");
    char parent[512];
    if (tmp && tmp[0] == '/')
        snprintf(parent, sizeof parent, "%s", tmp);
    else if (cic_repo_root(parent, 400) != 0 || !strcat(parent, "/test-tmp") || csr_mkdirs(parent) != 0)
        return -1;
    if (snprintf(fx->base, sizeof fx->base, "%s/capclosure-selftest.XXXXXX", parent) >= (int)sizeof fx->base)
        return -1;
    return mkdtemp(fx->base) ? 0 : -1;
}

void ccs_path(const struct ccs_fx *fx, const char *rel, char *out)
{
    snprintf(out, CCD_PATH, "%s/%.1024s", fx->base, rel);
}

int ccs_put(const struct ccs_fx *fx, const char *rel, const char *text)
{
    char path[CCD_PATH];
    ccs_path(fx, rel, path);
    return csr_write(path, text);
}

static int ccs_cc(const struct ccs_fx *fx, const char *src, const char *obj)
{
    char s[CCD_PATH], o[CCD_PATH], *argv[] = { (char *)"cc", (char *)"-std=c23", (char *)"-c", s, (char *)"-o", o, NULL };
    struct lcp_spec sp = { .argv = argv, .mode = LCP_QUIET, .grace_ms = 1000 };
    int code = 1;
    ccs_path(fx, src, s);
    ccs_path(fx, obj, o);
    return lcp_run(&sp, NULL, &code) == 0 ? code : -1;
}

/* Compiles empty translation units, one with an export, and a corrupt file.
 * Mach-O empty units still carry compiler-generated local section labels. */
static int ccs_nm_objs(const struct ccs_fx *fx, char paths[4][CCD_PATH])
{
    static const char *const rel[] = { "o/empty.o", "o/fill.o", "o/empty2.o", "o/bad.o" };
    for (int i = 0; i < 4; i++)
        ccs_path(fx, rel[i], paths[i]);
    return ccs_put(fx, "o/empty.c", "typedef int empty_not_on_this_platform;\n") == 0
        && ccs_put(fx, "o/fill.c", "static int g(int x) { return x + 1; }\nint filler_export(int x) { return g(x); }\n") == 0
        && ccs_put(fx, "o/bad.o", "this is not an object file\n") == 0 && ccs_cc(fx, "o/empty.c", "o/empty.o") == 0
        && ccs_cc(fx, "o/fill.c", "o/fill.o") == 0 && ccs_cc(fx, "o/empty.c", "o/empty2.o") == 0;
}

static int ccs_case_nm(const struct ccs_fx *fx)
{
    char p[4][CCD_PATH];
    int ok = ccs_nm_objs(fx, p);
    char *objs[] = { p[0], p[1], p[2] }, *badv[] = { p[1], p[3] };
    struct ccd_nm one = { 0 }, all = { 0 }, broken = { 0 };
#if defined(__APPLE__)
    const int strip = 1;
#else
    const int strip = 0;
#endif
    ok = ok && ccd_run_nm(objs, 3, 0, 1, strip, &one) == 0 && ccd_run_nm(objs, 3, 0, 0, strip, &all) == 0;
    int same = ok && one.n == all.n, named = 0;
    for (size_t i = 0; ok && i < one.n; i++) {
        int filled = !strcmp(one.row[i].path, p[1]);
        int empty = !strcmp(one.row[i].path, p[0]) || !strcmp(one.row[i].path, p[2]);
        int marker = strip && empty && !strcmp(one.row[i].type, "t") && !strncmp(one.row[i].name, "ltmp", 4);
        same = same && (filled || marker)
            && ccs_row(&all, i, one.row[i].path, one.row[i].type, one.row[i].name);
        named = named || (filled && !strcmp(one.row[i].name, "filler_export") && !strcmp(one.row[i].type, "T"));
    }
    int fail = ok && ccd_run_nm(badv, 2, 0, 1, strip, &broken) == 0 && ccd_nm_failed(&broken);
    int s = ccs_say(ok && !ccd_nm_failed(&one) && !ccd_nm_failed(&all) && named,
                    "M: native empty units parse without failure; the export is a T row");
    s += ccs_say(same, "nm: one object per call yields the same rows as one batch");
    s += ccs_say(fail, "nm: a corrupt object makes the scan failed (caller reports UNPROVEN)");
    ccd_nm_free(&one);
    ccd_nm_free(&all);
    ccd_nm_free(&broken);
    return s;
}

static int ccs_case_symbols(const struct ccs_fx *fx)
{
    char file[CCD_PATH];
    struct ccd_map plain = { 0 }, win = { 0 };
    size_t np = 0, nw = 0;
    int ok = ccs_put(fx, "i/capability_symbols.def",
                     "/* header */\nZCL_CAPABILITY_SYMBOL(\"connect\", CAP_NETWORK, \"\")\n"
                     "ZCL_CAPABILITY_SYMBOL(\n    \"a_long_wrapped_name\",\n    CAP_FILESYSTEM_WRITE, \"x\")\n") == 0;
    ccs_path(fx, "i/capability_symbols.def", file);
    ok = ok && ccd_symbols_load(file, 0, &plain, &np) == 0 && ccd_symbols_load(file, 1, &win, &nw) == 0;
    int f = ccs_say(ok && np == 2 && nw == 2 && plain.n == 2 && ccs_eq(&plain, "connect", "CAP_NETWORK")
                    && ccs_eq(&plain, "a_long_wrapped_name", "CAP_FILESYSTEM_WRITE"),
                    "symbols: a call wrapped across lines loads; the count is the row count");
    f += ccs_say(ok && win.n == 8 && !ccd_map_get(&plain, "__imp_connect") && ccs_eq(&win, "__imp_connect", "CAP_NETWORK")
                 && ccs_eq(&win, "__imp__connect", "CAP_NETWORK") && ccs_eq(&win, "__mingw_connect", "CAP_NETWORK"),
                 "I: MinGW import and wrapper decorations inherit the base symbol class");
    ccd_map_free(&plain);
    ccd_map_free(&win);
    return f;
}

static int ccs_case_platform(const struct ccs_fx *fx)
{
    char cent[CCD_PATH], plat[CCD_PATH], root[CCD_PATH];
    struct ccd_mods m = {0};
    ccs_path(fx, "j/engine/composition/module_capabilities.def", cent);
    ccs_path(fx, "j/engine/composition/module_capabilities_windows.def", plat);
    ccs_path(fx, "j", root);
    int ok = ccs_put(fx, "j/engine/composition/module_capabilities.def",
                     "ZCL_MODULE_CAPABILITY(\"fixture_src/platform_user.c\", CAP_NETWORK, \"portable arm\")\n"
                     "ZCL_MODULE_CAPABILITY(\"platform/modules/platform/src/os_sandbox_linux.c\",\n"
                     "                      CAP_NETWORK|CAP_PROCESS, \"Linux-only arm\")\n") == 0
          && ccs_put(fx, "j/engine/composition/module_capabilities_windows.def",
                     "ZCL_MODULE_CAPABILITY(\"fixture_src/platform_user.c\", CAP_NONE, \"exact empty arm\")\n") == 0;
    int rc = ok ? ccd_modules_load(cent, plat, root, &m) : 1;
    int f = ccs_say(rc == 0 && m.count == 2 && m.platform_count == 1 && ccs_eq(&m.raw, "fixture_src/platform_user.c", "CAP_NONE")
                    && ccs_eq(&m.uni, "fixture_src/platform_user.c", "CAP_NETWORK")
                    && ccs_eq(&m.raw, k_arm, "CAP_NETWORK|CAP_PROCESS") && ccs_eq(&m.uni, k_arm, "CAP_NETWORK|CAP_PROCESS"),
                    "J/K: an exact CAP_NONE platform row replaces the active class and keeps the portable union");
    ccd_mods_free(&m);
    ccs_put(fx, "j/engine/composition/module_capabilities.def",
            "ZCL_MODULE_CAPABILITY(\"a.c\", CAP_A, \"x\")\nZCL_MODULE_CAPABILITY(\"a.c\", CAP_B, \"y\")\n");
    rc = ccd_modules_load(cent, NULL, root, &m);
    f += ccs_say(rc == 0 && m.count == 1 && ccs_eq(&m.raw, "a.c", "CAP_B") && ccs_eq(&m.uni, "a.c", "CAP_A|CAP_B"),
                 "modules: a repeated central row keeps the last class and unions both");
    ccd_mods_free(&m);
    ccs_path(fx, "j/none.def", plat);
    f += ccs_say(ccd_modules_load(plat, NULL, root, &m) == 1, "modules: a missing central table reports 1");
    ccd_mods_free(&m);
    return f;
}

static int ccs_sidecar(const struct ccs_fx *fx, const char *name, const char *why, int want)
{
    char cent[CCD_PATH], root[CCD_PATH], msg[CCD_ERR];
    struct ccd_mods m = {0};
    ccs_path(fx, "p/engine/composition/module_capabilities.def", cent);
    ccs_path(fx, "p", root);
    int rc = ccd_modules_load(cent, NULL, root, &m);
    snprintf(msg, sizeof msg, "check_capability_closure: FATAL \xe2\x80\x94 invalid source-owned capability sidecar: "
             "%s/p/%s.capabilities.def%s", fx->base, k_own, why);
    int ok = rc == want && (want ? !strcmp(m.error, msg) : m.count == 1 && ccs_eq(&m.uni, k_own, "CAP_NETWORK"));
    ccd_mods_free(&m);
    return ccs_say(ok, name);
}

static int ccs_case_sidecar(const struct ccs_fx *fx)
{
    char own[256], other[256], longer[256];
    snprintf(own, sizeof own, "ZCL_MODULE_CAPABILITY(\"%s\", CAP_NETWORK, \"fixture\")\n", k_own);
    snprintf(other, sizeof other, "ZCL_MODULE_CAPABILITY(\"%s\", CAP_NETWORK, \"fixture\")\n", "contexts/commons/modules/vcs/src/other.c");
    snprintf(longer, sizeof longer, "ZCL_MODULE_CAPABILITY(\"%sx\", CAP_NETWORK, \"fixture\")\n", k_own);
    int f = ccs_put(fx, "p/engine/composition/module_capabilities.def", "") != 0
         || ccs_put(fx, "p/contexts/commons/modules/vcs/src/owned.c.capabilities.def", own) != 0;
    f += ccs_sidecar(fx, "P1: a source-owned declaration becomes the module row", "", 0);
    ccs_put(fx, "p/contexts/commons/modules/vcs/src/owned.c.capabilities.def", other);
    f += ccs_sidecar(fx, "P2: a misplaced source-owned declaration refuses with the exact message", "", 1);
    ccs_put(fx, "p/contexts/commons/modules/vcs/src/owned.c.capabilities.def", longer);
    f += ccs_sidecar(fx, "P2: a declaration naming a longer path refuses", "", 1);
    ccs_put(fx, "p/contexts/commons/modules/vcs/src/owned.c.capabilities.def", own);
    ccs_put(fx, "p/engine/composition/module_capabilities.def", own);
    return f + ccs_sidecar(fx, "P3: a central and source-owned duplicate refuses with the exact message",
                           " (duplicate central row)", 1);
}

/* Repeated valid tokens make the exact declaration exceed the old buffer;
 * the distinct final grant must survive both raw storage and normalized union. */
static int ccs_case_long_class(const struct ccs_fx *fx)
{
    static const char prefix[] = "CAP_NETWORK|", tail[] = "CAP_PROCESS";
    char raw[512], declaration[1024], cent[CCD_PATH], root[CCD_PATH];
    size_t used = 0;
    for (unsigned i = 0; i < 32; ++i) {
        memcpy(raw + used, prefix, sizeof prefix - 1);
        used += sizeof prefix - 1;
    }
    memcpy(raw + used, tail, sizeof tail);
    int length = snprintf(declaration, sizeof declaration,
        "ZCL_MODULE_CAPABILITY(\"%s\", %s, \"long union\")\n", k_own, raw);
    int ok = length > 0 && (size_t)length < sizeof declaration && strlen(raw) > 255 &&
        ccs_put(fx, "q/engine/composition/module_capabilities.def", "") == 0 &&
        ccs_put(fx, "q/contexts/commons/modules/vcs/src/owned.c.capabilities.def", declaration) == 0;
    ccs_path(fx, "q/engine/composition/module_capabilities.def", cent);
    ccs_path(fx, "q", root);
    struct ccd_mods m = {0};
    int rc = ok ? ccd_modules_load(cent, NULL, root, &m) : 1;
    int failures = ccs_say(rc == 0 && m.count == 1 && ccs_eq(&m.raw, k_own, raw) &&
        ccs_eq(&m.uni, k_own, "CAP_NETWORK|CAP_PROCESS") &&
        ccd_grants(ccd_map_get(&m.uni, k_own), "CAP_PROCESS"),
        "sidecar: long raw class and final grant survive without truncation");
    ccd_mods_free(&m);
    return failures;
}

#ifdef ZCL_TESTING
/* All faults hit real owned tools paths, independent of uid/permissions. */
static int ccs_scan_case(const char *cent, const char *root, const char *tools,
                         const char *leaf, enum ccd_scan_fault fault)
{
    struct ccd_mods m = {0};
    ccd_scan_test = (struct ccd_scan_test){.fault = fault,
        .path = fault == CCD_SCAN_LSTAT ? leaf : tools};
    int rc = ccd_modules_load(cent, NULL, root, &m);
    int accepts = fault == CCD_SCAN_NONE || fault == CCD_SCAN_DIRTY;
    int ok = accepts ? rc == 0 && m.count == 1 && ccs_eq(&m.raw, "tools/owned.c", "CAP_NETWORK") :
                      rc != 0 && m.raw.n == 0 && m.count == 0;
    ok = ok && ccd_scan_test.opened == ccd_scan_test.closed;
    ccd_scan_test = (struct ccd_scan_test){0};
    ccd_mods_free(&m);
    return ccs_say(ok, accepts ? "census: complete scan and cleared stale errno retain sidecar" :
                                "census: injected I/O refuses partial rows and closes directories");
}

static int ccs_case_scan(const struct ccs_fx *fx)
{
    char cent[CCD_PATH], root[CCD_PATH], tools[CCD_PATH], leaf[CCD_PATH];
    ccs_path(fx, "w/engine/composition/module_capabilities.def", cent);
    ccs_path(fx, "w", root);
    ccs_path(fx, "w/tools", tools);
    ccs_path(fx, "w/tools/owned.c.capabilities.def", leaf);
    int made = ccs_put(fx, "w/core", "non-directory optional root\n") == 0 &&
        ccs_put(fx, "w/engine/composition/module_capabilities.def", "") == 0 &&
        ccs_put(fx, "w/tools/owned.c.capabilities.def",
            "ZCL_MODULE_CAPABILITY(\"tools/owned.c\", CAP_NETWORK, \"fixture\")\n") == 0;
    if (!made) return ccs_say(0, "census: create owned fixture");
    int failures = 0;
    for (int fault = CCD_SCAN_NONE; fault <= CCD_SCAN_DIRTY; ++fault)
        failures += ccs_scan_case(cent, root, tools, leaf, (enum ccd_scan_fault)fault);
    char overlong[CCD_PATH + 32];
    memset(overlong, 'x', sizeof overlong - 1);
    overlong[sizeof overlong - 1] = '\0';
    struct ccd_mods m = {0};
    int rc = ccd_modules_load(cent, NULL, overlong, &m);
    failures += ccs_say(rc != 0 && m.raw.n == 0 && m.count == 0,
                        "census: root path overflow refuses without accepting partial map");
    ccd_mods_free(&m);
    return failures;
}
#else
static int ccs_case_scan(const struct ccs_fx *fx)
{
    (void)fx;
    return ccs_say(0, "census: missing ZCL_TESTING fault seam");
}
#endif

static int ccs_case_sets(void)
{
    char *u1 = ccd_union_caps("CAP_A", "CAP_B|CAP_A|CAP_NONE||CAP_C"), *u2 = ccd_union_caps("", "CAP_NONE|CAP_X");
    int f = ccs_say(u1 && u2 && !strcmp(u1, "CAP_A|CAP_B|CAP_C") && !strcmp(u2, "CAP_X"),
                    "union: skips empty tokens, CAP_NONE and members already present");
    free(u1);
    free(u2);
    return f + ccs_say(ccd_grants("CAP_A|CAP_NETWORK_X", "CAP_A") && !ccd_grants("CAP_NETWORK_X", "CAP_NETWORK")
                       && !ccd_grants("", "CAP_A"), "grants: whole-token membership only");
}

static int ccs_case_coverage(void)
{
    int f = ccs_say(!ccd_coverage_applicable(CCD_LINUX, "platform/modules/platform/src/os_sandbox_stub.c")
                    && ccd_coverage_applicable(CCD_LINUX, "tests/harness/src/test_thread_qos.c")
                    && ccd_coverage_applicable(CCD_LINUX, "tools/rebuild_recent.c"),
                    "L: Linux drops only the sandbox stub; standalone rows stay applicable");
    return f + ccs_say(!ccd_coverage_applicable(CCD_DARWIN, k_arm)
                       && !ccd_coverage_applicable(CCD_DARWIN, "tools/dev/wallet_gui_load.c")
                       && ccd_coverage_applicable(CCD_DARWIN, "tools/package_verify.c")
                       && !ccd_coverage_applicable(CCD_WINDOWS, "tools/package_verify.c")
                       && !ccd_coverage_applicable(CCD_WINDOWS, "contexts/commons/modules/vcs/src/vcs_devloop.c")
                       && ccd_coverage_applicable(CCD_WINDOWS, "tools/dev/wallet_gui_load.c")
                       && ccd_coverage_applicable(CCD_OTHER, k_arm),
                       "coverage: Darwin and Windows drop exactly their named arms");
}

static int ccs_epoch_dir(const struct ccs_fx *fx, const char *name, long age)
{
    char dir[CCD_PATH], file[CCD_PATH];
    struct timespec ts[2] = { { 1700000000 + age, 0 }, { 1700000000 + age, 0 } };
    snprintf(file, sizeof file, "e/build/dev-obj/epochs/%s/x", name);
    snprintf(dir, sizeof dir, "%s/e/build/dev-obj/epochs/%s", fx->base, name);
    return ccs_put(fx, file, "x") == 0 && utimensat(AT_FDCWD, dir, ts, 0) == 0;
}

static int ccs_case_epoch(const struct ccs_fx *fx)
{
    char root[CCD_PATH], out[CCD_PATH];
    ccs_path(fx, "e", root);
    int none = ccd_find_epoch(root, out, sizeof out) == 0;
    int made = ccs_epoch_dir(fx, "old", 0) && ccs_epoch_dir(fx, "new", 50) && ccs_epoch_dir(fx, ".hidden", 900)
            && ccs_epoch_dir(fx, "tie", 50);
    char *tail = ccd_find_epoch(root, out, sizeof out) == 1 ? strrchr(out, '/') : NULL;
    return ccs_say(none, "epoch: a tree without build/dev-obj/epochs has none")
         + ccs_say(made && tail && !strcmp(tail, "/new"),
                   "epoch: the newest directory wins, dot directories are ignored, ties take the smaller name");
}

static int ccs_case_epoch_refusal(struct ccs_fx *fx)
{
    char root[CCD_PATH], out[CCD_PATH], linkp[CCD_PATH];
    ccs_path(fx, "r", root);
    if (ccs_put(fx, "r/build/dev-obj/epochs/stale/x", "x") != 0)
        return ccs_say(0, "epoch refusal: fixture setup");
    /* The newest entry is a dangling symlink: stat(2) fails. A partial
     * epoch census must refuse, never silently freeze on the older
     * epoch and grade it as newest. */
    ccs_path(fx, "r/build/dev-obj/epochs/fresh", linkp);
    if (symlink("no-such-target", linkp) != 0)
        return ccs_say(0, "epoch refusal: fixture symlink");
    int rc = ccd_find_epoch(root, out, sizeof out);
    return ccs_say(rc == -2,
                   "epoch: an unstatable newest entry refuses (-2), never silently freezes on an older epoch");
}

static int ccs_case_epoch_unreadable(struct ccs_fx *fx)
{
    char root[CCD_PATH], out[CCD_PATH], dir[CCD_PATH];
    if (geteuid() == 0) {
        printf("  SKIP epoch: unreadable epochs directory: running as root, chmod 0000 does not deny the read\n");
        return 0;
    }
    ccs_path(fx, "u", root);
    if (ccs_put(fx, "u/build/dev-obj/epochs/sub/x", "x") != 0)
        return ccs_say(0, "epoch unreadable: fixture setup");
    ccs_path(fx, "u/build/dev-obj/epochs", dir);
    if (chmod(dir, 0000) != 0)
        return ccs_say(0, "epoch unreadable: fixture chmod");
    int rc = ccd_find_epoch(root, out, sizeof out);
    chmod(dir, 0755);
    return ccs_say(rc == -2, "epoch: an unreadable epochs directory refuses (-2), never reads as none");
}

int capability_closure_data_selftest(void)
{
    struct ccs_fx fx;
    if (lsc_install() != 0 || ccs_scratch(&fx) != 0) {
        fputs("capability_closure_data selftest: cannot prepare the scratch directory\n", stderr);
        return 2;
    }
    int fails = ccs_case_parse() + ccs_case_nm(&fx) + ccs_case_symbols(&fx) + ccs_case_platform(&fx)
              + ccs_case_scan(&fx) + ccs_case_sidecar(&fx) + ccs_case_long_class(&fx) + ccs_case_sets() + ccs_case_coverage() + ccs_case_epoch(&fx)
              + ccs_case_epoch_refusal(&fx) + ccs_case_epoch_unreadable(&fx);
    lsc_unblock();
    rap_rm_rf(fx.base);
    puts(fails == 0 ? "== selftest: PASS ==" : "== selftest: FAIL ==");
    return fails == 0 ? 0 : 1;
}
