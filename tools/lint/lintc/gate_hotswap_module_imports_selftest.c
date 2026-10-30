/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: --selftest for check_hotswap_module_imports
 * (gate_hotswap_module_imports.c). Builds fixture modules with cc in a
 * mkdtemp sandbox under the state scratch dir, then proves: the clean
 * baseline passes; a module importing an undeclared node symbol trips the
 * gate and both module and symbol are named; removal restores the baseline
 * verdict; the sandbox/allowlist/capability/class-table overrides are all
 * refused without the selftest marker and refused outside scratch; a
 * forbidden-capability allowlist row (socket/CAP_NETWORK) trips the
 * crossing leg; a continuation-line capability row is classified; a thin
 * crossing hits the coverage floor; a class with no verdict in either list
 * FATALs and is named.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_hotswap_module_imports_priv.h"

static const char k_gate[] = "check_hotswap_module_imports";
static const char k_def[] = "engine/composition/hotswap_module_imports.def";
static const char k_classfile[] = "engine/composition/capability_classes.def";

static const char k_clean_src[] =
    "/* Built ONLY by the selftest, into a scratch sandbox. */\n"
    "#include <stdlib.h>\n"
    "#include <string.h>\n"
    "extern void *json_init(void);\n"
    "void *zcl_selftest_clean_leaf(const char *s);\n"
    "void *zcl_selftest_clean_leaf(const char *s) {\n"
    "    if (s == NULL || strlen(s) == 0u) { return NULL; }\n"
    "    char *copy = (char *)malloc(strlen(s) + 1u);\n"
    "    if (copy == NULL) { return NULL; }\n"
    "    memcpy(copy, s, strlen(s) + 1u);\n"
    "    free(copy);\n"
    "    return json_init();\n"
    "}\n";

static const char k_bad_src[] =
    "/* Built ONLY by the selftest; deleted before return. */\n"
    "extern int zcl_selftest_undeclared_node_reach(int height);\n"
    "int zcl_selftest_violating_leaf(void);\n"
    "int zcl_selftest_violating_leaf(void) { return zcl_selftest_undeclared_node_reach(1); }\n";

static void hms_clear_env(void)
{
    unsetenv("ZCL_HOTSWAP_IMPORTS_SELFTEST");
    unsetenv("ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR");
    unsetenv("ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE");
    unsetenv("ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE");
    unsetenv("ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE");
}

/* Runs the gate core with the given overrides, capturing its combined
 * output into out. Returns the gate's exit code. */
static int hms_run(const char *def, const char *capf, const char *cls,
                   const char *sodir, int marker, char *out, size_t cap)
{
    hms_clear_env();
    if (def)
        setenv("ZCL_HOTSWAP_IMPORTS_DEF_OVERRIDE", def, 1);
    if (capf)
        setenv("ZCL_HOTSWAP_IMPORTS_CAPFILE_OVERRIDE", capf, 1);
    if (cls)
        setenv("ZCL_HOTSWAP_IMPORTS_CLASSFILE_OVERRIDE", cls, 1);
    if (sodir)
        setenv("ZCL_HOTSWAP_IMPORTS_SANDBOX_DIR", sodir, 1);
    if (marker)
        setenv("ZCL_HOTSWAP_IMPORTS_SELFTEST", k_gate, 1);
    FILE *tf = tmpfile();
    if (!tf) {
        hms_clear_env();
        return -1;
    }
    int rc = hmi_run_core(tf, tf);
    fflush(tf);
    rewind(tf);
    size_t n = fread(out, 1, cap - 1, tf);
    out[n] = '\0';
    fclose(tf);
    hms_clear_env();
    return rc;
}

static int hms_append(const char *path, const char *text)
{
    FILE *f = fopen(path, "a");
    if (!f)
        return -1;
    fputs(text, f);
    fclose(f);
    return 0;
}

static int hms_copy(const char *src, const char *dst)
{
    FILE *a = fopen(src, "r");
    if (!a)
        return -1;
    FILE *b = fopen(dst, "w");
    if (!b) {
        fclose(a);
        return -1;
    }
    static char buf[8192];
    size_t n;
    int bad = 0;
    while (!bad && (n = fread(buf, 1, sizeof buf, a)) > 0)
        bad = fwrite(buf, 1, n, b) != n;
    fclose(a);
    return (fclose(b) == 0 && !bad) ? 0 : -1;
}

/* PATH lookup for cc, falling back to gcc — no subprocess needed. */
static int hms_find_cc(char *out, size_t cap)
{
    const char *path = getenv("PATH");
    if (!path)
        return -1;
    static char pbuf[HMI_TXT];
    const char *names[2] = {"cc", "gcc"};
    for (int k = 0; k < 2; k++) {
        snprintf(pbuf, sizeof pbuf, "%s", path);
        char *save = NULL;
        for (char *d = strtok_r(pbuf, ":", &save); d;
             d = strtok_r(NULL, ":", &save)) {
            char full[HMI_PATH];
            if (ovf(snprintf(full, sizeof full, "%s/%s", d, names[k]),
                    sizeof full))
                continue;
            if (access(full, X_OK) == 0) {
                if (ovf(snprintf(out, cap, "%s", full), cap))
                    return -1;
                return 0;
            }
        }
    }
    return -1;
}

static int hms_compile(const char *cc, const char *src, const char *so,
                       int darwin, char *out, size_t cap)
{
    char *argv[10];
    int i = 0;
    argv[i++] = (char *)cc;
    argv[i++] = (char *)"-shared";
    argv[i++] = (char *)"-fPIC";
    argv[i++] = (char *)"-O0";
    if (darwin) {
        argv[i++] = (char *)"-undefined";
        argv[i++] = (char *)"dynamic_lookup";
    }
    argv[i++] = (char *)"-o";
    argv[i++] = (char *)so;
    argv[i++] = (char *)src;
    argv[i] = NULL;
    size_t olen = 0;
    int code = 0;
    if (hmi_spawn_argv(argv, 1, out, cap, &olen, &code) != 0)
        return -1;
    struct stat st;
    return (stat(so, &st) == 0 && S_ISREG(st.st_mode)) ? 0 : -1;
}

static int hms_scratch(char *scratch, size_t cap, char *sandbox, size_t scap)
{
    const char *home = getenv("HOME");
    if (!home || !home[0])
        return -1;
    if (ovf(snprintf(scratch, cap,
                     "%s/.local/state/zclassic23/scratch/lane-imports", home),
            cap))
        return -1;
    if (csr_mkdirs(scratch))
        return -1;
    if (ovf(snprintf(sandbox, scap, "%s/sandbox.XXXXXX", scratch), scap))
        return -1;
    return mkdtemp(sandbox) ? 0 : -1;
}

/* Asserts got == want; prints the script's FAIL shape on a miss. */
static int hms_want_eq(int got, int want, const char *what, const char *out)
{
    if (got == want)
        return 0;
    fprintf(stderr, "%s: selftest FAIL — %s (rc=%d, want rc=%d)\n", k_gate,
            what, got, want);
    if (out && out[0])
        fprintf(stderr, "%s\n", out);
    return 1;
}

static int hms_want_str(const char *out, const char *needle, const char *what)
{
    if (strstr(out, needle))
        return 0;
    fprintf(stderr, "%s: selftest FAIL — %s\n", k_gate, what);
    if (out && out[0])
        fprintf(stderr, "%s\n", out);
    return 1;
}

static int hms_write_cont_scenario(const char *cont_def, const char *cont_cap)
{
    if (hms_copy(k_def, cont_def))
        return -1;
    for (int k = 1; k <= 35; k++) {
        char row[HMI_LINE];
        if (ovf(snprintf(row, sizeof row,
                         "ZCL_CAPABILITY_SYMBOL(\"zcl_selftest_pad_sym_%d\", CAP_HARMLESS, \"selftest pad row\")\n",
                         k), sizeof row))
            return -1;
        if (hms_append(cont_cap, row))
            return -1;
        if (ovf(snprintf(row, sizeof row,
                         "HOTSWAP_MODULE_IMPORT(\"zcl_selftest_pad_sym_%d\", \"LIBC\")\n",
                         k), sizeof row))
            return -1;
        if (hms_append(cont_def, row))
            return -1;
    }
    if (hms_append(cont_cap,
                   "ZCL_CAPABILITY_SYMBOL(\"zcl_selftest_continuation_symbol\",\n"
                   "    CAP_RANDOM, \"selftest continuation-line row\")\n"))
        return -1;
    return hms_append(cont_def,
                      "HOTSWAP_MODULE_IMPORT(\"zcl_selftest_continuation_symbol\", \"LIBC\")\n");
}

static int hms_write_floor_scenario(const char *floor_def)
{
    static const char *rows[] = {"malloc", "free", "strlen", "memcpy", "open"};
    FILE *f = fopen(floor_def, "w");
    if (!f)
        return -1;
    fclose(f);
    for (int i = 0; i < 5; i++) {
        char row[HMI_LINE];
        if (ovf(snprintf(row, sizeof row,
                         "HOTSWAP_MODULE_IMPORT(\"%s\", \"LIBC\")\n", rows[i]),
                sizeof row))
            return -1;
        if (hms_append(floor_def, row))
            return -1;
    }
    for (int k = 1; k <= 100; k++) {
        char row[HMI_LINE];
        if (ovf(snprintf(row, sizeof row,
                         "HOTSWAP_MODULE_IMPORT(\"zcl_selftest_floor_pad_%d\", \"LIBC\")\n",
                         k), sizeof row))
            return -1;
        if (hms_append(floor_def, row))
            return -1;
    }
    return 0;
}

/* Mirrors build/hotswap modules into the sandbox; returns count copied. */
static int hms_mirror(const char *sandbox)
{
    DIR *d = opendir("build/hotswap");
    if (!d)
        return 0;
    int copied = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        size_t len = strlen(e->d_name);
        if (len < 4 || strcmp(e->d_name + len - 3, ".so") != 0)
            continue;
        char src[HMI_PATH], dst[HMI_PATH];
        if (ovf(snprintf(src, sizeof src, "build/hotswap/%s", e->d_name),
                 sizeof src))
            continue;
        if (ovf(snprintf(dst, sizeof dst, "%s/%s", sandbox, e->d_name),
                 sizeof dst))
            continue;
        if (hms_copy(src, dst) == 0)
            copied++;
    }
    closedir(d);
    return copied;
}

/* Builds both fixture modules and parks the violating one. */
static int hms_build_fixtures(const char *sandbox, const char *cc, int darwin,
                              char *clean_so, char *bad_so)
{
    static char cout[HMI_TXT];
    char src[HMI_PATH], parked[HMI_PATH];
    if (ovf(snprintf(src, sizeof src, "%s/clean_fixture.c", sandbox), sizeof src) ||
        ovf(snprintf(clean_so, HMI_PATH, "%s/zcl_selftest_clean.so", sandbox), HMI_PATH) ||
        ovf(snprintf(parked, sizeof parked, "%s/violating.so.parked", sandbox), sizeof parked))
        return 2;
    if (csr_write(src, k_clean_src))
        return 2;
    if (hms_compile(cc, src, clean_so, darwin, cout, sizeof cout))
        return die("check_hotswap_module_imports: could not build the clean fixture module\n%s", cout);
    if (ovf(snprintf(src, sizeof src, "%s/violating_fixture.c", sandbox), sizeof src))
        return 2;
    if (csr_write(src, k_bad_src))
        return 2;
    if (ovf(snprintf(bad_so, HMI_PATH, "%s/zcl_selftest_violating.so", sandbox), HMI_PATH))
        return 2;
    if (hms_compile(cc, src, bad_so, darwin, cout, sizeof cout))
        return die("check_hotswap_module_imports: could not build the violating fixture module\n%s", cout);
    return rename(bad_so, parked) == 0 ? 0 : 2;
}

/* Every captured output and exit code of one selftest run. */
struct hms_st {
    char sandbox[HMI_PATH], cc[HMI_PATH], clean_so[HMI_PATH], bad_so[HMI_PATH];
    char cap_so_dir[HMI_PATH], forbidden_def[HMI_PATH], cont_def[HMI_PATH];
    char cont_cap[HMI_PATH], floor_def[HMI_PATH], vocab_cf[HMI_PATH];
    int darwin, present, mirrored;
    int baseline_rc, tripped_rc, recovered_rc, stray_rc, outside_rc;
    int forbidden_rc, cont_rc, floor_rc, defov_stray_rc, defov_outside_rc;
    int capov_stray_rc, capov_outside_rc, vocab_rc;
    int vocabov_stray_rc, vocabov_outside_rc;
    char base_out[HMI_STEXT], trip_out[HMI_STEXT], rec_out[HMI_STEXT];
    char o1[HMI_STEXT], o2[HMI_STEXT], f_out[HMI_STEXT], c_out[HMI_STEXT];
    char fl_out[HMI_STEXT], d1[HMI_STEXT], d2[HMI_STEXT], c1[HMI_STEXT];
    char c2[HMI_STEXT], v_out[HMI_STEXT], vo1[HMI_STEXT], vo2[HMI_STEXT];
};

static struct hms_st g_st;

static int hms_probes(void)
{
    char probe[HMI_SYM];
    hmi_canonical("_memcpy", 1, probe, sizeof probe);
    if (strcmp(probe, "memcpy") != 0)
        return die("check_hotswap_module_imports: Mach-O C-name normalization failed\n", "");
    hmi_canonical("___memcpy_chk", 1, probe, sizeof probe);
    if (strcmp(probe, "__memcpy_chk") != 0)
        return die("check_hotswap_module_imports: Mach-O normalization widened a private symbol\n", "");
    hmi_canonical("_dyld_stub_binder", 1, probe, sizeof probe);
    if (probe[0])
        return die("check_hotswap_module_imports: dyld loader plumbing was not isolated\n", "");
    return 0;
}

/* Sandbox, compiler, fixture modules, mirrored build/hotswap modules. */
static int hms_setup(struct hms_st *s)
{
    char scratch[HMI_PATH];
    if (hms_scratch(scratch, sizeof scratch, s->sandbox, sizeof s->sandbox))
        return die("check_hotswap_module_imports: cannot create selftest sandbox\n", "");
    if (hms_find_cc(s->cc, sizeof s->cc))
        return die("check_hotswap_module_imports: no C compiler on PATH; cannot build the fixture modules\n", "");
    struct utsname u;
    s->darwin = uname(&u) == 0 && strcmp(u.sysname, "Darwin") == 0;
    int rc = hms_build_fixtures(s->sandbox, s->cc, s->darwin, s->clean_so,
                                s->bad_so);
    if (rc)
        return rc;
    s->mirrored = hms_mirror(s->sandbox);
    s->present = 1 + s->mirrored;
    if (s->present < 1)
        return die("check_hotswap_module_imports: sandbox holds no module .so\n", "");
    return 0;
}

/* Baseline, tripped, recovered and the two sandbox-override refusals. */
static int hms_run_basic(struct hms_st *s)
{
    s->baseline_rc = hms_run(NULL, NULL, NULL, s->sandbox, 1, s->base_out,
                             sizeof s->base_out);
    if (s->baseline_rc != 0)
        return die("check_hotswap_module_imports: sandbox baseline is not clean\n%s", s->base_out);
    if (strstr(s->base_out, "zcl_selftest_undeclared_node_reach"))
        return die("check_hotswap_module_imports: baseline already names the forbidden symbol\n%s", s->base_out);
    char parked[HMI_PATH];
    if (ovf(snprintf(parked, sizeof parked, "%s/violating.so.parked",
                     s->sandbox), sizeof parked))
        return 2;
    (void)rename(parked, s->bad_so);
    s->tripped_rc = hms_run(NULL, NULL, NULL, s->sandbox, 1, s->trip_out,
                            sizeof s->trip_out);
    unlink(s->bad_so);
    s->recovered_rc = hms_run(NULL, NULL, NULL, s->sandbox, 1, s->rec_out,
                              sizeof s->rec_out);
    s->stray_rc = hms_run(NULL, NULL, NULL, s->sandbox, 0, s->o1, sizeof s->o1);
    s->outside_rc = hms_run(NULL, NULL, NULL, "/etc", 1, s->o2, sizeof s->o2);
    return 0;
}

static int hms_cross_paths(struct hms_st *s)
{
    char cap_so[HMI_PATH];
    if (ovf(snprintf(s->cap_so_dir, sizeof s->cap_so_dir, "%s/capcross_so", s->sandbox), sizeof s->cap_so_dir))
        return 2;
    if (csr_mkdirs(s->cap_so_dir))
        return 2;
    if (ovf(snprintf(cap_so, sizeof cap_so, "%s/zcl_selftest_clean.so", s->cap_so_dir), sizeof cap_so))
        return 2;
    if (hms_copy(s->clean_so, cap_so))
        return die("check_hotswap_module_imports: cannot stage a clean module for the capability-crossing selftest: %s\n", cap_so);
    if (ovf(snprintf(s->forbidden_def, sizeof s->forbidden_def, "%s/capcross_forbidden.def", s->sandbox), sizeof s->forbidden_def) ||
        ovf(snprintf(s->cont_def, sizeof s->cont_def, "%s/capcross_continuation_imports.def", s->sandbox), sizeof s->cont_def) ||
        ovf(snprintf(s->cont_cap, sizeof s->cont_cap, "%s/capcross_continuation_cap.def", s->sandbox), sizeof s->cont_cap) ||
        ovf(snprintf(s->floor_def, sizeof s->floor_def, "%s/capcross_floor.def", s->sandbox), sizeof s->floor_def) ||
        ovf(snprintf(s->vocab_cf, sizeof s->vocab_cf, "%s/capcross_vocab_classes.def", s->sandbox), sizeof s->vocab_cf))
        return 2;
    return 0;
}

/* Writes the capability-crossing and vocabulary scenario files. */
static int hms_cross_stage(struct hms_st *s)
{
    int rc = hms_cross_paths(s);
    if (rc)
        return rc;
    if (hms_copy(k_def, s->forbidden_def))
        return die("check_hotswap_module_imports: cannot copy the allowlist for the crossing selftest: %s\n", k_def);
    if (hms_append(s->forbidden_def, "HOTSWAP_MODULE_IMPORT(\"socket\", \"LIBC\")\n"))
        return 2;
    if (hms_write_cont_scenario(s->cont_def, s->cont_cap))
        return 2;
    if (hms_write_floor_scenario(s->floor_def))
        return 2;
    if (hms_copy(k_classfile, s->vocab_cf))
        return die("check_hotswap_module_imports: cannot copy the class table for the vocabulary selftest: %s\n", k_classfile);
    if (hms_append(s->vocab_cf,
                   "ZCL_CAPABILITY_CLASS(ZCL_SELFTEST_UNVERDICTED, \"selftest\", \"a class added after this gate was written\")\n"))
        return 2;
    return 0;
}

static void hms_run_cross(struct hms_st *s)
{
    const char *sd = s->cap_so_dir;
    s->forbidden_rc = hms_run(s->forbidden_def, NULL, NULL, sd, 1, s->f_out, sizeof s->f_out);
    s->cont_rc = hms_run(s->cont_def, s->cont_cap, NULL, sd, 1, s->c_out, sizeof s->c_out);
    s->floor_rc = hms_run(s->floor_def, NULL, NULL, NULL, 1, s->fl_out, sizeof s->fl_out);
    s->defov_stray_rc = hms_run(s->forbidden_def, NULL, NULL, NULL, 0, s->d1, sizeof s->d1);
    s->defov_outside_rc = hms_run("/etc", NULL, NULL, NULL, 1, s->d2, sizeof s->d2);
    s->capov_stray_rc = hms_run(NULL, s->cont_cap, NULL, NULL, 0, s->c1, sizeof s->c1);
    s->capov_outside_rc = hms_run(NULL, "/etc", NULL, NULL, 1, s->c2, sizeof s->c2);
    s->vocab_rc = hms_run(NULL, NULL, s->vocab_cf, sd, 1, s->v_out, sizeof s->v_out);
    s->vocabov_stray_rc = hms_run(NULL, NULL, s->vocab_cf, NULL, 0, s->vo1, sizeof s->vo1);
    s->vocabov_outside_rc = hms_run(NULL, NULL, "/etc/hosts", NULL, 1, s->vo2, sizeof s->vo2);
}

static int hms_check_basic(const struct hms_st *s)
{
    int bad = 0;
    if (s->tripped_rc == 0) {
        fprintf(stderr, "%s: selftest FAIL — the module importing an undeclared symbol did not trip the gate (rc=0)\n", k_gate);
        fputs(s->trip_out, stderr);
        bad = 1;
    }
    bad |= hms_want_str(s->trip_out, "zcl_selftest_undeclared_node_reach", "gate did not name the forbidden symbol; it may have failed for an unrelated reason");
    bad |= hms_want_str(s->trip_out, "zcl_selftest_violating.so", "gate did not name the offending module file");
    if (access(s->bad_so, F_OK) == 0) {
        fprintf(stderr, "%s: selftest FAIL — violating fixture was not removed\n", k_gate);
        bad = 1;
    }
    if (strstr(s->rec_out, "zcl_selftest_undeclared_node_reach")) {
        fprintf(stderr, "%s: selftest FAIL — gate still names the forbidden symbol after cleanup\n", k_gate);
        bad = 1;
    }
    if (s->recovered_rc != s->baseline_rc) {
        fprintf(stderr, "%s: selftest FAIL — gate did not return to its baseline exit code (baseline=%d recovered=%d)\n", k_gate, s->baseline_rc, s->recovered_rc);
        bad = 1;
    }
    bad |= hms_want_eq(s->stray_rc, 2, "sandbox override without the selftest marker was accepted; a stray env var could redirect a real lint scan", s->o1);
    bad |= hms_want_eq(s->outside_rc, 2, "sandbox override pointing outside scratch was accepted", s->o2);
    return bad;
}

static int hms_check_cross(const struct hms_st *s)
{
    int bad = 0;
    if (s->forbidden_rc == 0) {
        fprintf(stderr, "%s: selftest FAIL — an allowlist row for a forbidden-capability symbol (socket / CAP_NETWORK) did not trip the crossing leg (rc=0)\n", k_gate);
        fputs(s->f_out, stderr);
        bad = 1;
    }
    if (s->forbidden_rc != 0 && (!strstr(s->f_out, "socket") || !strstr(s->f_out, "CAP_NETWORK"))) {
        fprintf(stderr, "%s: selftest FAIL — crossing leg did not name both the forbidden symbol and its capability class\n", k_gate);
        fputs(s->f_out, stderr);
        bad = 1;
    }
    bad |= hms_want_eq(s->cont_rc, 0, "a capability row with its class on a CONTINUATION line was not classified; the 8-row trap is not handled", s->c_out);
    bad |= hms_want_str(s->c_out, "random=1", "the continuation-line row (CAP_RANDOM) was not counted in the crossing; it may have been silently dropped");
    bad |= hms_want_eq(s->floor_rc, 2, "a crossing that resolves far fewer than CAPABILITY_CROSS_FLOOR symbols did not FATAL", s->fl_out);
    bad |= hms_want_str(s->fl_out, "coverage floor", "the coverage-floor FATAL did not name the floor");
    bad |= hms_want_eq(s->defov_stray_rc, 2, "allowlist override without the selftest marker was accepted", s->d1);
    bad |= hms_want_eq(s->defov_outside_rc, 2, "allowlist override pointing outside scratch was accepted", s->d2);
    bad |= hms_want_eq(s->capov_stray_rc, 2, "capability table override without the selftest marker was accepted", s->c1);
    bad |= hms_want_eq(s->capov_outside_rc, 2, "capability table override pointing outside scratch was accepted", s->c2);
    bad |= hms_want_eq(s->vocab_rc, 2, "a class with no verdict in either list did not FATAL", s->v_out);
    bad |= hms_want_str(s->v_out, "CAP_ZCL_SELFTEST_UNVERDICTED", "the vocabulary refusal did not name the offending class");
    if (s->vocabov_stray_rc != 2 || s->vocabov_outside_rc != 2) {
        fprintf(stderr, "%s: selftest FAIL — class-table override accepted without the marker (rc=%d) or outside scratch (rc=%d)\n", k_gate, s->vocabov_stray_rc, s->vocabov_outside_rc);
        bad = 1;
    }
    return bad;
}

static int hms_stage_all(struct hms_st *s)
{
    int rc = hms_probes();
    if (!rc)
        rc = hms_setup(s);
    if (!rc)
        rc = hms_run_basic(s);
    if (!rc)
        rc = hms_cross_stage(s);
    return rc;
}

int check_hotswap_module_imports_selftest(void)
{
    struct hms_st *s = &g_st;
    s->sandbox[0] = '\0';
    int rc = hms_stage_all(s);
    if (rc) {
        /* Every early failure still removes the sandbox (old trap EXIT). */
        if (s->sandbox[0])
            rap_rm_rf(s->sandbox);
        hms_clear_env();
        return rc;
    }
    hms_run_cross(s);
    int bad = hms_check_basic(s) | hms_check_cross(s);
    rap_rm_rf(s->sandbox);
    hms_clear_env();
    if (bad) {
        fputs("check_hotswap_module_imports: selftest FAILED\n", stderr);
        return 1;
    }
    printf("%s: selftest PASS — a sandbox module importing an undeclared node symbol tripped the gate (rc=%d; module and symbol both named); removing it restored the baseline verdict (rc=%d) over %d sandbox module(s) (%d mirrored from build/hotswap); the sandbox override is refused without the marker and refused outside scratch; a forbidden-capability allowlist row (socket/CAP_NETWORK) tripped the crossing leg (rc=%d); a continuation-line capability row was classified (CAP_RANDOM counted); a thin crossing hit the coverage floor (rc=%d); a class with no verdict in either list FATALed (rc=%d) and was named; both new overrides are refused without the marker and refused outside scratch\n",
           k_gate, s->tripped_rc, s->baseline_rc, s->present, s->mirrored,
           s->forbidden_rc, s->floor_rc, s->vocab_rc);
    return 0;
}
