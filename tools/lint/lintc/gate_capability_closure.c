/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the capability-closure gate in C23. Every undefined symbol in the
 * newest build epoch must be classified; every object that reaches a
 * classified capability must be declared to; a declared capability must be
 * used; a scan below the object floor or missing declared files is UNPROVEN;
 * a raw syscall or inline-asm trap in a file without CAP_PRIVILEGE is banned.
 * Output strings and exit statuses (0 clean, 1 violations, 2 unproven) are
 * those of the shell gate this replaced.
 */
#define _POSIX_C_SOURCE 200809L
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include "base/safe_alloc.h"
#include "gate_capability_closure_priv.h"
#include "lintc.h"
#include "lintc_proc.h"
#include "lintc_sig.h"

#define CCG_DASH "\xe2\x80\x94"

/* Anti-hollow floor: a tree below it is refused, never reported clean. */
enum { CCG_MIN_OBJECTS = 500, CCG_FOREIGN_SHOWN = 5, CCG_UNOBS_SHOWN = 20 };

/* Declared rows with no compiled object anywhere in a complete epoch: the
 * standalone tools tests/harness/src/test_thread_qos.c and
 * tools/rebuild_recent.c, which neither z23-dev nor the package verifier
 * links. Shrink-only: a lower measurement must lower this in the same commit. */
enum { CCG_HOST_BASELINE = 2 };

static const char k_ccg_nm_long[] = " Likely a concurrent build rewriting\n"
                                    "  an object underneath this scan. Refusing to trust a partial read:\n";
static const char k_ccg_nm_short[] = " Refusing to trust a partial read:\n";

struct ccg_list { char **s; size_t n, cap; };

struct ccg_counts {
    int unclassified, undeclared, overdeclared, platform_unobserved, missing;
    int syscall, unobserved, excluded, stale, compiled_out;
};

struct ccg_scan {
    const struct ccg_cfg *cfg;
    const char *root;
    char epoch[CCD_PATH];
    struct ccd_map sym, compiled, used, defined, undef, foreign;
    size_t n_sym;
    struct ccd_mods mods;
    struct ccg_list objs, uses, unobs, compiled_out;
    struct ccg_macros macros;
    struct ccd_nm nm;
    struct ccg_counts c;
};

static void ccg_say(const struct ccg_scan *s, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void ccg_say(const struct ccg_scan *s, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(s->cfg->out, fmt, ap);
    va_end(ap);
}

static int ccg_list_add(struct ccg_list *l, const char *str)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 64;
        char **p = zcl_realloc(l->s, cap * sizeof *p, "ccg_list");
        if (!p)
            return -1;
        l->s = p;
        l->cap = cap;
    }
    l->s[l->n] = zcl_strdup(str, "ccg_list item");
    return l->s[l->n++] ? 0 : -1;
}

static void ccg_list_free(struct ccg_list *l)
{
    for (size_t i = 0; i < l->n; i++)
        free(l->s[i]);
    free(l->s);
    *l = (struct ccg_list){ 0 };
}

static void ccg_free(struct ccg_scan *s)
{
    ccd_map_free(&s->sym);
    ccd_map_free(&s->compiled);
    ccd_map_free(&s->used);
    ccd_map_free(&s->defined);
    ccd_map_free(&s->undef);
    ccd_map_free(&s->foreign);
    ccd_map_free(&s->macros.def);
    ccd_mods_free(&s->mods);
    ccd_nm_free(&s->nm);
    ccg_list_free(&s->objs);
    ccg_list_free(&s->uses);
    ccg_list_free(&s->unobs);
    ccg_list_free(&s->compiled_out);
}

static int ccg_is_file(const char *root, const char *rel)
{
    char path[CCD_PATH];
    struct stat st;
    return snprintf(path, sizeof path, "%s/%s", root, rel) < (int)sizeof path && stat(path, &st) == 0
           && S_ISREG(st.st_mode);
}

static int ccg_has_suffix(const char *name, const char *suffix)
{
    size_t n = strlen(name), k = strlen(suffix);
    return n >= k && strcmp(name + n - k, suffix) == 0;
}

/* "dir/x.o" becomes "dir/x.c"; any other name is kept. */
static void ccg_c_of(const char *obj, char *out, size_t cap)
{
    if (ccg_has_suffix(obj, ".o"))
        snprintf(out, cap, "%.*s.c", (int)(strlen(obj) - 2), obj);
    else
        snprintf(out, cap, "%s", obj);
}

/* ccg_walk result for a failure already reported to the gate's output (the
 * remaining nonzero result, -1, is an allocation failure). */
enum { CCG_REPORTED = 2 };

static int ccg_walk_fail(const struct ccg_scan *s, const char *what, const char *path, int err)
{
    ccg_say(s, "check_capability_closure: FATAL " CCG_DASH " %s %s: %s\n", what, path,
            err ? strerror(err) : "path too long");
    return CCG_REPORTED;
}

static int ccg_walk(const struct ccg_scan *s, const char *base, const char *rel,
                    const char *suffix, struct ccd_map *out);

/* One directory entry: recurse into a directory, take a name with the suffix.
 * Symbolic links are not followed. A name that cannot be pathed or typed is
 * FATAL, never skipped: a skipped entry is an unscanned object. */
static int ccg_walk_entry(const struct ccg_scan *s, const char *base, const char *rel,
                          const char *name, const char *suffix, struct ccd_map *out)
{
    char r[CCD_PATH], p[CCD_PATH];
    struct stat st;
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;
    if (snprintf(r, sizeof r, "%s%s%s", rel, rel[0] ? "/" : "", name) >= (int)sizeof r
        || snprintf(p, sizeof p, "%s/%s", base, r) >= (int)sizeof p)
        return ccg_walk_fail(s, "path too long under", base, 0);
    if (lstat(p, &st) != 0)
        return ccg_walk_fail(s, "cannot stat", p, errno);
    if (S_ISDIR(st.st_mode))
        return ccg_walk(s, base, r, suffix, out);
    return ccg_has_suffix(name, suffix) ? ccd_map_put(out, r, "") : 0;
}

/* Collects the base-relative names under base/rel that end in suffix. An
 * open, stat, path or readdir error is FATAL, never an empty directory. */
static int ccg_walk(const struct ccg_scan *s, const char *base, const char *rel,
                    const char *suffix, struct ccd_map *out)
{
    char dir[CCD_PATH];
    DIR *d;
    int rc = 0;
    if (snprintf(dir, sizeof dir, "%s/%s", base, rel) >= (int)sizeof dir)
        return ccg_walk_fail(s, "path too long under", base, 0);
    if (!(d = opendir(dir)))
        return ccg_walk_fail(s, "cannot open directory", dir, errno);
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(d);
        if (!e) {
            if (errno)
                rc = ccg_walk_fail(s, "cannot read directory", dir, errno);
            break;
        }
        rc = ccg_walk_entry(s, base, rel, e->d_name, suffix, out);
        if (rc != 0)
            break;
    }
    closedir(d);
    return rc;
}

static int ccg_fatal(const struct ccg_scan *s, const char *what, const char *path)
{
    ccg_say(s, "check_capability_closure: FATAL " CCG_DASH " %s %s\n", what, path);
    return 2;
}

static int ccg_tables(struct ccg_scan *s)
{
    char sym[CCD_PATH], mod[CCD_PATH], plat[CCD_PATH];
    const char *pn = s->cfg->os == CCD_LINUX ? "linux" : s->cfg->os == CCD_WINDOWS ? "windows" : NULL;
    if (snprintf(sym, sizeof sym, "%s/engine/composition/capability_symbols.def", s->root) >= (int)sizeof sym
        || snprintf(mod, sizeof mod, "%s/engine/composition/module_capabilities.def", s->root) >= (int)sizeof mod
        || snprintf(plat, sizeof plat, "%s/engine/composition/module_capabilities_%s.def", s->root,
                    pn ? pn : "") >= (int)sizeof plat)
        return ccg_fatal(s, "cannot read", s->root);
    if (ccd_symbols_load(sym, s->cfg->os == CCD_WINDOWS, &s->sym, &s->n_sym) != 0) {
        ccg_fatal(s, "cannot read", sym);
        ccg_say(s, "  This file is the symbol->class table; without it, closure and\n"
                   "  declaration cannot be checked at all. Refusing to report clean\n"
                   "  off input this script cannot see.\n");
        return 2;
    }
    if (s->n_sym < 1) {
        ccg_fatal(s, "parsed 0 rows from", sym);
        ccg_say(s, "  Either the file is empty or this script's parser no longer\n"
                   "  matches its ZCL_CAPABILITY_SYMBOL(...) shape. Refusing to\n"
                   "  report clean off a scan that saw nothing.\n");
        return 2;
    }
    if (ccd_modules_load(mod, pn ? plat : NULL, s->root, &s->mods) != 0) {
        if (s->mods.error[0])
            fprintf(s->cfg->err, "%s\n", s->mods.error);
        return ccg_fatal(s, "cannot read", mod);
    }
    return 0;
}

/* Keeps an object whose translation unit exists here (or is generated under
 * build/); a leftover of a failed candidate is foreign and never graded. */
static int ccg_grade_object(struct ccg_scan *s, const char *rel)
{
    char src[CCD_PATH], abs[CCD_PATH];
    const char *slash = strrchr(rel, '/');
    if (strcmp(slash ? slash + 1 : rel, "restart-base.o") == 0)
        return 0;
    ccg_c_of(rel, src, sizeof src);
    if (!ccg_is_file(s->root, src) && strncmp(rel, "build/", 6) != 0)
        return ccd_map_put(&s->foreign, rel, "");
    if (snprintf(abs, sizeof abs, "%s/%s", s->epoch, rel) >= (int)sizeof abs)
        return -1;
    return ccd_map_put(&s->compiled, src, "") || ccg_list_add(&s->objs, abs) ? -1 : 0;
}

static void ccg_foreign_report(const struct ccg_scan *s)
{
    if (s->foreign.n == 0)
        return;
    ccg_say(s, "check_capability_closure: %zu foreign object(s) under %s\n"
               "  have no source in this tree (a failed candidate's leftovers);\n"
               "  not graded. First %d:\n", s->foreign.n, s->epoch, CCG_FOREIGN_SHOWN);
    for (size_t i = 0; i < s->foreign.n && i < CCG_FOREIGN_SHOWN; i++)
        ccg_say(s, "    %s\n", s->foreign.ent[i].key);
}

/* Freezes the object list once, so a build running underneath cannot change
 * the evidence set. */
static int ccg_objects(struct ccg_scan *s)
{
    struct ccd_map rel = { 0 };
    int rc = ccd_find_epoch(s->root, s->epoch, sizeof s->epoch);
    if (rc == -2) {
        ccg_say(s, "check_capability_closure: FATAL " CCG_DASH " cannot read %s/build/dev-obj/epochs "
                   "completely (%s).\n  A partial epoch census is never graded.\n",
                s->root, strerror(errno));
        return 2;
    }
    if (rc <= 0) {
        ccg_say(s, "check_capability_closure: UNPROVEN " CCG_DASH " no build/dev-obj/epochs/* found.\n"
                   "  Populate it with the normal dev build (e.g. 'make z23-dev') and\n"
                   "  re-run. Never treat an absent object tree as zero violations.\n");
        return 2;
    }
    rc = ccg_walk(s, s->epoch, "", ".o", &rel);
    for (size_t i = 0; rc == 0 && i < rel.n; i++)
        rc = ccg_grade_object(s, rel.ent[i].key);
    ccd_map_free(&rel);
    if (rc == CCG_REPORTED)
        return 2;
    if (rc != 0)
        return ccg_fatal(s, "out of memory scanning", s->epoch);
    ccg_foreign_report(s);
    if (s->objs.n < CCG_MIN_OBJECTS) {
        ccg_say(s, "check_capability_closure: UNPROVEN " CCG_DASH " %s holds only %zu\n"
                   "  production objects (floor %d).\n"
                   "  A stale or partial build epoch, not a clean scan.\n", s->epoch, s->objs.n, CCG_MIN_OBJECTS);
        return 2;
    }
    return 0;
}

static void ccg_indent(const struct ccg_scan *s, const char *text)
{
    for (const char *p = text ? text : ""; *p;) {
        const char *nl = strchr(p, '\n');
        size_t n = nl ? (size_t)(nl - p) : strlen(p);
        ccg_say(s, "    %.*s\n", (int)n, p);
        p += n + (nl != NULL);
    }
}

/* The status xargs reports for the nm it would have run. */
static int ccg_xargs_rc(int rc)
{
    if (rc == 126 || rc == 127)
        return rc;
    return rc == 255 ? 124 : rc > 127 ? 125 : rc ? 123 : 0;
}

/* A concurrent rewrite of an object makes nm fail or complain while it still
 * lists the objects that read cleanly: trust no row of such a scan. */
static int ccg_nm_unproven(const struct ccg_scan *s, const struct ccd_nm *nm, const char *pass, const char *tail)
{
    ccg_say(s, "check_capability_closure: UNPROVEN " CCG_DASH " nm reported an error scanning\n"
               "  %s (%src=%d).%s", s->epoch, pass, ccg_xargs_rc(nm->rc), tail);
    ccg_indent(s, nm->err);
    return 2;
}

static int ccg_is_undef(const char *type)
{
    return strcmp(type, "U") == 0 || strcmp(type, "w") == 0 || strcmp(type, "v") == 0;
}

/* Names defined in this tree and names referenced undefined (U, w and v alike:
 * a weak reference is still a reach). Without a defined-only listing the full
 * one already holds both sides. */
static int ccg_name_sets(struct ccg_scan *s, const struct ccd_nm *def)
{
    for (size_t i = 0; i < s->nm.n; i++) {
        const struct ccd_nmrow *r = &s->nm.row[i];
        struct ccd_map *to = ccg_is_undef(r->type) ? &s->undef : def ? NULL : &s->defined;
        if (to && ccd_map_put(to, r->name, "") != 0)
            return -1;
    }
    for (size_t i = 0; def && i < def->n; i++)
        if (ccd_map_put(&s->defined, def->row[i].name, "") != 0)
            return -1;
    return 0;
}

static int ccg_nm_defined(struct ccg_scan *s, struct ccd_nm *def)
{
    int rc = ccd_run_nm(s->objs.s, s->objs.n, 1, 0, s->cfg->strip, def);
    return rc == 0 && ccd_nm_failed(def) ? ccg_nm_unproven(s, def, "defined-only ", k_ccg_nm_short) : rc;
}

/* Never `nm -u`: Apple nm drops the type column there, so strong and weak
 * references cannot be told apart. */
static int ccg_nm(struct ccg_scan *s)
{
    struct ccd_nm def = { 0 };
    int one = s->cfg->os == CCD_LINUX;
    int rc = ccd_run_nm(s->objs.s, s->objs.n, 0, 0, s->cfg->strip, &s->nm);
    if (rc == 0 && ccd_nm_failed(&s->nm))
        rc = ccg_nm_unproven(s, &s->nm, "", k_ccg_nm_long);
    else if (rc == 0 && !one)
        rc = ccg_nm_defined(s, &def);
    if (rc == 0 && ccg_name_sets(s, one ? NULL : &def) != 0)
        rc = -1;
    if (rc < 0)
        ccg_fatal(s, "cannot run nm over", s->epoch);
    ccd_nm_free(&def);
    return rc ? 2 : 0;
}

/* -1 when a name cannot be recorded (out of memory). Counts first: a failed
 * add must never leave the unobserved total under-counted. */
static int ccg_coverage_scan(struct ccg_scan *s)
{
    for (size_t i = 0; i < s->mods.raw.n; i++) {
        const char *path = s->mods.raw.ent[i].key;
        if (!ccg_is_file(s->root, path))
            continue;
        if (!ccd_coverage_applicable(s->cfg->os, path)) {
            s->c.excluded++;
        } else if (!ccd_map_get(&s->compiled, path)) {
            s->c.unobserved++;
            if (ccg_list_add(&s->unobs, path) != 0)
                return -1;
        }
    }
    return 0;
}

/* A partial epoch (a z23-dev-only rebuild) holds thousands of objects yet
 * silently misses declared files; more of those than the baseline allows is
 * a scan that did not happen. */
static int ccg_coverage_floor(struct ccg_scan *s)
{
    if (ccg_coverage_scan(s) != 0)
        return ccg_fatal(s, "out of memory recording unobserved rows in", s->epoch);
    if (s->c.unobserved <= s->cfg->baseline)
        return 0;
    ccg_say(s, "check_capability_closure: UNPROVEN " CCG_DASH " %d module_capabilities.def\n"
               "  row(s) have no compiled object anywhere in %s " CCG_DASH " above the\n"
               "  shrink-only coverage baseline of %ld.\n"
               "  This looks like a PARTIAL epoch (e.g. a 'make z23-dev'-only\n"
               "  rebuild), not a scan complete enough to grade. 'I scanned an\n"
               "  incomplete epoch' is not a pass and it is not a violation; it is\n"
               "  a scan that did not happen. Missing (first %d of %d):\n",
            s->c.unobserved, s->epoch, s->cfg->baseline, CCG_UNOBS_SHOWN, s->c.unobserved);
    for (size_t i = 0; i < s->unobs.n && i < CCG_UNOBS_SHOWN; i++)
        ccg_say(s, "    %s\n", s->unobs.s[i]);
    if (s->c.unobserved > CCG_UNOBS_SHOWN)
        ccg_say(s, "    ... and %d more\n", s->c.unobserved - CCG_UNOBS_SHOWN);
    ccg_say(s, "  Build a COMPLETE epoch and re-run:\n"
               "    tools/dev/checkout-lock.sh foreground build/.checkout.lock -- \\\n"
               "      %s\n", s->cfg->os == CCD_WINDOWS ? "make -j16 z23-dev"
                                                      : "make -j16 build/bin/z23-dev build/bin/z23-package-verify-dev");
    return 2;
}

/* Item 1: a symbol undefined here and defined nowhere in the tree must be in
 * the table, even if the table calls it harmless. */
static void ccg_closure(struct ccg_scan *s)
{
    for (size_t i = 0; i < s->undef.n; i++) {
        const char *name = s->undef.ent[i].key;
        if (ccd_map_get(&s->defined, name) || ccd_map_get(&s->sym, name))
            continue;
        ccg_say(s, "check_capability_closure: VIOLATION " CCG_DASH " unclassified external symbol '%s'\n"
                   "  Reached by this tree, absent from config/capability_symbols.def.\n"
                   "  Add a row: ZCL_CAPABILITY_SYMBOL(\"%s\", CAP_..., \"why\")\n", name, name);
        s->c.unclassified++;
    }
}

/* Records that source src uses class cls, once, in first-seen order. */
static int ccg_use_add(struct ccg_scan *s, const char *src, const char *cls)
{
    char key[2 * CCD_PATH];
    if (snprintf(key, sizeof key, "%s\t%s", src, cls) >= (int)sizeof key)
        return -1;
    if (ccd_map_get(&s->used, key))
        return 0;
    return ccd_map_put(&s->used, key, "") || ccg_list_add(&s->uses, key) ? -1 : 0;
}

/* Classes each source uses, from the undefined rows of its object; the table's
 * harmless class is no use. */
static int ccg_uses(struct ccg_scan *s)
{
    size_t el = strlen(s->epoch);
    char src[CCD_PATH];
    for (size_t i = 0; i < s->nm.n; i++) {
        const struct ccd_nmrow *r = &s->nm.row[i];
        const char *cls = ccg_is_undef(r->type) ? ccd_map_get(&s->sym, r->name) : NULL;
        if (!cls || strcmp(cls, "CAP_HARMLESS") == 0)
            continue;
        ccg_c_of(strncmp(r->path, s->epoch, el) == 0 && r->path[el] == '/' ? r->path + el + 1 : r->path,
                 src, sizeof src);
        if (ccg_use_add(s, src, cls) != 0)
            return -1;
    }
    return 0;
}

static void ccg_undeclared(struct ccg_scan *s, const char *src, const char *cls, const char *granted)
{
    ccg_say(s, "check_capability_closure: VIOLATION " CCG_DASH " undeclared reach: %s uses %s\n", src, cls);
    if (granted)
        ccg_say(s, "  but its row only grants: %s\n", granted);
    else
        ccg_say(s, "  with no module_capabilities.def row at all (declares CAP_NONE).\n");
    ccg_say(s, "  Add/extend: ZCL_MODULE_CAPABILITY(\"%s\", ...|%s, \"why\")\n", src, cls);
    s->c.undeclared++;
}

/* Item 2: every class a source uses must be granted by its row. */
static void ccg_declaration(struct ccg_scan *s)
{
    for (size_t i = 0; i < s->uses.n; i++) {
        char use[2 * CCD_PATH], *cls;
        const char *granted;
        snprintf(use, sizeof use, "%s", s->uses.s[i]);
        cls = strchr(use, '\t');
        *cls++ = '\0';
        granted = ccd_map_get(&s->mods.raw, use);
        granted = granted && granted[0] ? granted : NULL;
        if (!granted || !ccd_grants(granted, cls))
            ccg_undeclared(s, use, cls, granted);
    }
}

static void ccg_overdeclared(struct ccg_scan *s, const char *path, const char *tok)
{
    ccg_say(s, "check_capability_closure: VIOLATION " CCG_DASH " %s declares %s but its\n"
               "  compiled object does not reference any symbol classified %s.\n"
               "  Shrink the row: ZCL_MODULE_CAPABILITY(\"%s\", <without %s>, why)\n", path, tok, tok, path, tok);
    s->c.overdeclared++;
}

/* A declared class nothing used, in a file whose primary arm no guard macro of
 * this build lets compile, proves nothing either way. */
static void ccg_unobserved(struct ccg_scan *s, const char *path, const char *tok, const char *macros)
{
    char row[2 * CCD_PATH];
    ccg_say(s, "check_capability_closure: UNOBSERVED (compiled out: %s) " CCG_DASH "\n"
               "  %s declares %s but its primary implementation never\n"
               "  compiled here: the guard macro(s) %s are not defined in\n"
               "  this build's CFLAGS. Not a violation and not a pass " CCG_DASH " the code\n"
               "  that would prove or disprove %s did not run through this host's\n"
               "  compiler. Validate on a host that defines %s.\n", macros, path, tok, macros, tok, macros);
    snprintf(row, sizeof row, "    %s declares %s, undefined macro(s): %s", path, tok, macros);
    s->c.compiled_out += ccg_list_add(&s->compiled_out, row) == 0;
}

/* 2 when the compile line cannot be read. */
static int ccg_unused_class(struct ccg_scan *s, const char *path, const char *tok)
{
    char *macros;
    if (!s->macros.loaded && ccg_macros_load(s->cfg, s->root, &s->macros) != 0)
        return 2;
    macros = ccg_compiled_out(&s->macros, s->root, path);
    if (macros)
        ccg_unobserved(s, path, tok, macros);
    else
        ccg_overdeclared(s, path, tok);
    free(macros);
    return 0;
}

/* Item 3a for one granted class of a compiled source. */
static int ccg_symmetry_class(struct ccg_scan *s, const char *path, const char *tok)
{
    char key[2 * CCD_PATH];
    if (strcmp(tok, "CAP_NONE") == 0 || snprintf(key, sizeof key, "%s\t%s", path, tok) >= (int)sizeof key
        || ccd_map_get(&s->used, key))
        return 0;
    if (!s->cfg->symmetry) {
        s->c.platform_unobserved++;
        return 0;
    }
    return ccg_unused_class(s, path, tok);
}

/* Items 3a and 3b: a granted class must be used, and a row's source must
 * exist. A source with no object here is unobserved, not unused. */
static int ccg_symmetry(struct ccg_scan *s)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < s->mods.raw.n; i++) {
        const char *path = s->mods.raw.ent[i].key;
        char *raw = zcl_strdup(s->mods.raw.ent[i].val, "ccg_symmetry raw"), *save = NULL;
        if (!ccg_is_file(s->root, path)) {
            ccg_say(s, "check_capability_closure: VIOLATION " CCG_DASH " module_capabilities.def row\n"
                       "  names '%s', which does not exist in this tree.\n", path);
            s->c.missing++;
        } else if (ccd_map_get(&s->compiled, path)) {
            for (char *tok = raw ? strtok_r(raw, "|", &save) : NULL; tok && rc == 0; tok = strtok_r(NULL, "|", &save))
                rc = ccg_symmetry_class(s, path, tok);
        }
        free(raw);
    }
    return rc;
}

/* Coverage floor, other half: a baseline above the true count is a ratchet
 * that can only rust. */
static void ccg_stale_baseline(struct ccg_scan *s)
{
    if (s->c.unobserved >= s->cfg->baseline)
        return;
    ccg_say(s, "check_capability_closure: VIOLATION " CCG_DASH " coverage baseline is stale:\n"
               "  only %d module_capabilities.def row(s) are unobserved in\n"
               "  %s, below CAP_CLOSURE_COVERAGE_BASELINE=%ld\n"
               "  recorded in build/bin/z23-lint check-capability-closure. Coverage\n"
               "  improved without lowering the baseline " CCG_DASH " that is what keeps this a\n"
               "  shrink-only ratchet instead of a number that only ever grows.\n"
               "  Lower CAP_CLOSURE_COVERAGE_BASELINE to %d (with the reason)\n"
               "  in the same commit.\n", s->c.unobserved, s->epoch, s->cfg->baseline, s->c.unobserved);
    s->c.stale = 1;
}

/* A hand-rolled syscall leaves no symbol for nm to see: the word-bounded call
 * (no space before the paren, so prose is not a hit), the x86 and ARM traps,
 * and the bare mnemonic inside an asm string. */
static const char k_ccg_raw[] = "(^|[^A-Za-z0-9_])syscall\\(|int[[:space:]]+\\$0x80|svc[[:space:]]+#"
                                "|\"[[:space:]]*syscall[[:space:]\\\\]";

struct ccg_ban {
    struct ccg_scan *s;
    const regex_t *re;
    const char *rel;
    size_t no;
    int hit;
};

/* The first NUL-separated piece of the len bytes at line that the ban matches. */
static const char *ccg_ban_piece(const regex_t *re, const char *line, size_t len)
{
    for (const char *p = line; p < line + len; p += strlen(p) + 1)
        if (regexec(re, p, 0, NULL, 0) == 0)
            return p;
    return NULL;
}

/* lc_each_line callback: one source line, newline stripped, against the ban;
 * each piece between embedded NUL bytes is judged. */
static int ccg_ban_line(void *vctx, const char *raw, size_t len)
{
    struct ccg_ban *b = vctx;
    char *line = len < SIZE_MAX ? zcl_malloc(len + 1, "ccg_ban line") : NULL;
    if (!line)
        return -1;
    memcpy(line, raw, len);
    line[len] = '\0';
    b->no++;
    if (len > 0 && line[len - 1] == '\n')
        line[len - 1] = '\0';
    const char *hit = ccg_ban_piece(b->re, line, len);
    if (hit) {
        if (!b->hit++)
            ccg_say(b->s, "check_capability_closure: VIOLATION " CCG_DASH " %s reaches the kernel through a\n"
                          "  raw syscall or inline-asm trap with no CAP_PRIVILEGE declaration:\n", b->rel);
        ccg_say(b->s, "    %zu:%s\n", b->no, hit);
    }
    free(line);
    return 0;
}

/* 0 scanned, 2 FATAL: an unreadable tracked source must never escape the ban. */
static int ccg_ban_file(struct ccg_scan *s, const regex_t *re, const char *rel)
{
    char path[CCD_PATH];
    struct ccg_ban b = { s, re, rel, 0, 0 };
    if (snprintf(path, sizeof path, "%s/%s", s->root, rel) >= (int)sizeof path)
        return ccg_walk_fail(s, "path too long under", s->root, 0);
    if (lc_each_line(path, ccg_ban_line, &b, 0) != 0) {
        ccg_say(s, "check_capability_closure: FATAL " CCG_DASH " cannot scan %s for raw syscalls: %s\n",
                rel, strerror(errno));
        return 2;
    }
    s->c.syscall += b.hit != 0;
    return 0;
}

/* Tracked C sources outside vendor/; a tree without a usable index is walked.
 * 1 when a termination signal arrived, -1 when out of memory. */
static int ccg_sources(const struct ccg_scan *s, struct ccg_list *out)
{
    char *argv[] = { (char *)"git", (char *)"-C", (char *)s->root, (char *)"ls-files", (char *)"-z",
                     (char *)"*.c", (char *)"--", (char *)":!:vendor/*", NULL };
    struct lcp_spec sp = { .argv = argv, .mode = LCP_OUT, .grace_ms = CCD_GRACE_MS };
    struct lcp_buf buf = { 0 };
    struct ccd_map walked = { 0 };
    int code = 1, rc = lcp_run(&sp, &buf, &code);
    for (size_t at = 0; rc == 0 && code == 0 && at < buf.len; at += strlen(buf.data + at) + 1)
        rc = ccg_list_add(out, buf.data + at);
    lcp_buf_free(&buf);
    if (rc > 0)
        return 1;
    if (rc == 0 && out->n == 0)
        rc = ccg_walk(s, s->root, "", ".c", &walked);
    for (size_t i = 0; rc == 0 && i < walked.n; i++) {
        const char *k = walked.ent[i].key;
        if (strncmp(k, "build/", 6) && strncmp(k, "vendor/", 7) && strncmp(k, ".git/", 5))
            rc = ccg_list_add(out, k);
    }
    ccd_map_free(&walked);
    return rc < 0 ? -1 : rc == CCG_REPORTED ? 2 : 0;
}

/* Item 5: files that declared CAP_PRIVILEGE on any target have told a reviewer
 * to look; every other tracked source is scanned. */
static int ccg_syscall_ban(struct ccg_scan *s)
{
    struct ccg_list src = { 0 };
    regex_t re;
    if (regcomp(&re, k_ccg_raw, REG_EXTENDED | REG_NOSUB) != 0)
        return -1; /* regfree on a failed regcomp would free an undefined regex_t */
    int rc = ccg_sources(s, &src);
    for (size_t i = 0; rc == 0 && i < src.n; i++) {
        const char *uni = ccd_map_get(&s->mods.uni, src.s[i]);
        if (!uni || !ccd_grants(uni, "CAP_PRIVILEGE"))
            rc = ccg_ban_file(s, &re, src.s[i]);
    }
    regfree(&re);
    ccg_list_free(&src);
    return rc;
}

static void ccg_summary(const struct ccg_scan *s)
{
    const struct ccg_counts *c = &s->c;
    ccg_say(s, "check_capability_closure: scanned %zu objects under %s,\n"
               "  %zu classified symbols, %zu module rows.\n"
               "  unclassified=%d undeclared=%d overdeclared=%d\n"
               "  platform-unobserved=%d symmetry-enforced=%d\n"
               "  missing-source-rows=%d raw-syscall=%d\n"
               "  declared-but-unobserved=%d (coverage baseline=%ld)\n"
               "  platform-target-excluded=%d\n"
               "  foreign-objects=%zu (no source in this tree; not graded)\n"
               "  platform-exact-overrides=%zu\n"
               "  compiled-out-unobserved=%d (never a violation, never a pass " CCG_DASH " see UNOBSERVED lines above)\n",
            s->objs.n, s->epoch, s->n_sym, s->mods.count, c->unclassified, c->undeclared, c->overdeclared,
            c->platform_unobserved, s->cfg->symmetry, c->missing, c->syscall, c->unobserved, s->cfg->baseline,
            c->excluded, s->foreign.n, s->mods.platform_count, c->compiled_out);
    if (c->compiled_out > 0)
        ccg_say(s, "  compiled-out rows:\n");
    for (size_t i = 0; i < s->compiled_out.n; i++)
        ccg_say(s, "%s\n", s->compiled_out.s[i]);
}

static int ccg_verdict(const struct ccg_scan *s)
{
    const struct ccg_counts *c = &s->c;
    int bad = c->unclassified + c->undeclared + c->overdeclared + c->missing + c->stale + c->syscall;
    if (bad > 0) {
        ccg_say(s, "check_capability_closure: FAIL " CCG_DASH " %d violation(s)\n", bad);
        return 1;
    }
    ccg_say(s, "check_capability_closure: OK " CCG_DASH " closed\n");
    return 0;
}

/* The grading passes over the collected evidence; 2 when a pass could not run. */
static int ccg_grade(struct ccg_scan *s)
{
    ccg_closure(s);
    if (ccg_uses(s) != 0)
        return 2;
    ccg_declaration(s);
    if (ccg_symmetry(s) != 0)
        return 2;
    ccg_stale_baseline(s);
    return ccg_syscall_ban(s) == 0 ? 0 : 2;
}

int ccg_check_root(const struct ccg_cfg *cfg, const char *root)
{
    struct ccg_scan s = { .cfg = cfg, .root = root };
    int rc = ccg_tables(&s);
    rc = rc ? rc : ccg_objects(&s);
    rc = rc ? rc : ccg_nm(&s);
    rc = rc ? rc : ccg_coverage_floor(&s);
    rc = rc ? rc : ccg_grade(&s);
    if (rc == 0) {
        ccg_summary(&s);
        rc = ccg_verdict(&s);
    }
    ccg_free(&s);
    return rc;
}

static enum ccd_os ccg_host_os(void)
{
    struct utsname u;
    if (uname(&u) != 0)
        return CCD_OTHER;
    if (strcmp(u.sysname, "Linux") == 0)
        return CCD_LINUX;
    if (strcmp(u.sysname, "Darwin") == 0)
        return CCD_DARWIN;
    if (strncmp(u.sysname, "MINGW", 5) == 0 || strncmp(u.sysname, "MSYS", 4) == 0
        || strncmp(u.sysname, "CYGWIN", 6) == 0)
        return CCD_WINDOWS;
    return CCD_OTHER;
}

/* Linux produced the declaration snapshot and stays the symmetry authority;
 * Darwin still enforces closure and every undeclared reach. */
void ccg_host_cfg(struct ccg_cfg *cfg)
{
    char base[16];
    snprintf(base, sizeof base, "%d", CCG_HOST_BASELINE);
    cfg->os = ccg_host_os();
    cfg->strip = cfg->os == CCD_DARWIN;
    cfg->symmetry = strcmp(env_or("ZCL_CAP_CLOSURE_ENFORCE_SYMMETRY", cfg->os == CCD_DARWIN ? "0" : "1"), "1") == 0;
    cfg->baseline = strtol(env_or("ZCL_CAP_CLOSURE_COVERAGE_BASELINE", base), NULL, 10);
    cfg->cflags = getenv("CAP_CLOSURE_CFLAGS_OVERRIDE");
    cfg->record = env_or("ZCL_CAP_CLOSURE_SOURCE_RECORD", NULL);
    cfg->out = stdout;
    cfg->err = stderr;
}

int check_capability_closure_run(int argc, char **argv)
{
    char root[CCD_PATH];
    struct ccg_cfg cfg;
    int rc, sig;
    (void)argv;
    if (argc > 0) {
        fputs("usage: build/bin/z23-lint check-capability-closure [--selftest]\n", stderr);
        return 2;
    }
    if (cic_repo_root(root, sizeof root) != 0 || lsc_install() != 0)
        return 2;
    ccg_host_cfg(&cfg);
    cfg.repo = root;
    rc = ccg_check_root(&cfg, root);
    fflush(stdout);
    sig = lsc_pending();
    if (sig)
        lsc_finish(sig);
    return rc;
}
