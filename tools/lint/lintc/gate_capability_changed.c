/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Check compiled changed engine objects for undeclared capabilities. */
#include "gate_capability_closure_priv.h"
#include "lintc.h"
#include "lintc_sig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Use the declaration union: a conditional arm not selected by this proof
 * profile must never become a false hard rejection here. Full closure chooses
 * the exact host arm and remains the authority for symmetry and coverage. */
static int changed_check(const char *source, const struct ccd_nm *nm,
                         const struct ccd_map *symbols, const struct ccd_map *modules)
{
    int bad = 0;
    const char *granted = ccd_map_get(modules, source);
    for (size_t i = 0; i < nm->n; ++i) {
        const struct ccd_nmrow *r = &nm->row[i];
        if (strcmp(r->type, "U") && strcmp(r->type, "w") && strcmp(r->type, "v")) continue;
        const char *cls = ccd_map_get(symbols, r->name);
        if (!cls || !strcmp(cls, "CAP_HARMLESS") || (granted && ccd_grants(granted, cls))) continue;
        fprintf(stderr, "changed capability: %s reaches %s via %s without a declaration\n",
                source, cls, r->name);
        bad = 1;
    }
    return bad;
}

static int changed_object(const char *source, char *object,
                          const struct ccd_map *symbols, const struct ccd_map *modules,
                          int strip)
{
    struct ccd_nm nm = {0};
    char *objects[] = {object};
    int rc = ccd_run_nm(objects, 1, 0, CCD_NM_BATCH, strip, &nm);
    if (rc || ccd_nm_failed(&nm)) {
        fprintf(stderr, "changed capability: UNPROVEN cannot read object for %s\n", source);
        ccd_nm_free(&nm);
        return 2;
    }
    int bad = changed_check(source, &nm, symbols, modules);
    ccd_nm_free(&nm);
    return bad;
}

int check_capability_changed_run(int argc, char **argv)
{
    if (argc % 2) return 2;
    if (!argc) { puts("changed capability: UNPROVEN no compiled engine objects"); return 0; }
    char root[CCD_PATH], sym[CCD_PATH], mod[CCD_PATH], platform[CCD_PATH];
    struct ccg_cfg cfg;
    struct ccd_map symbols = {0}; struct ccd_mods modules = {0}; size_t count = 0;
    if (cic_repo_root(root, sizeof root) || lsc_install()) return 2;
    ccg_host_cfg(&cfg);
    const char *os = cfg.os == CCD_LINUX ? "linux" : cfg.os == CCD_WINDOWS ? "windows" : "";
    if (snprintf(sym, sizeof sym, "%s/engine/composition/capability_symbols.def", root) >= (int)sizeof sym ||
        snprintf(mod, sizeof mod, "%s/engine/composition/module_capabilities.def", root) >= (int)sizeof mod ||
        snprintf(platform, sizeof platform, "%s/engine/composition/module_capabilities_%s.def", root, os) >= (int)sizeof platform)
        return 2;
    if (ccd_symbols_load(sym, cfg.os == CCD_WINDOWS, &symbols, &count) || !count ||
        ccd_modules_load(mod, platform, root, &modules)) {
        fputs("changed capability: UNPROVEN cannot load capability tables\n", stderr);
        ccd_map_free(&symbols); ccd_mods_free(&modules); return 0;
    }
    int bad = 0, unproven = 0;
    for (int i = 0; i < argc; i += 2) {
        if (strncmp(argv[i], "engine/", 7)) { ++unproven; continue; }
        int result = changed_object(argv[i], argv[i + 1], &symbols, &modules.uni, cfg.strip);
        bad += result == 1;
        unproven += result == 2;
    }
    ccd_map_free(&symbols); ccd_mods_free(&modules);
    int sig = lsc_pending();
    if (sig) lsc_finish(sig);
    if (bad || unproven)
        fprintf(stderr, "changed capability: WARNING %d need review, %d unproven; test profile may differ from release\n", bad, unproven);
    else printf("changed capability: checked %d compiled engine object(s)\n", argc / 2);
    return 0;
}

int check_capability_changed_selftest(void)
{
    struct ccd_map symbols = {0}, modules = {0}; struct ccd_nm nm = {0};
    int bad = ccd_map_put(&symbols, "fopen", "CAP_FS_READ") ||
        ccd_parse_nm("obj.o: U fopen\n", 0, &nm);
    bad |= changed_check("engine/example.c", &nm, &symbols, &modules) != 1;
    bad |= ccd_map_put(&modules, "engine/example.c", "CAP_FS_READ") != 0;
    bad |= changed_check("engine/example.c", &nm, &symbols, &modules) != 0;
    ccd_nm_free(&nm); ccd_map_free(&symbols); ccd_map_free(&modules);
    return st_ok(bad, "check_capability_changed selftest: OK\n");
}
