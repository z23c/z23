/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: data layer of the capability-closure gate. Declarations shared by
 * the table loaders, the nm parser and runner, and their selftest, and used by
 * the gate core, its guards and their selftest.
 */
#ifndef GATE_CAPABILITY_CLOSURE_PRIV_H
#define GATE_CAPABILITY_CLOSURE_PRIV_H

#include <stddef.h>
#include <stdio.h>

enum { CCD_PATH = 4096, CCD_ERR = CCD_PATH + 256, CCD_NM_BATCH = 512,
       CCD_NM_BYTES = 96 * 1024, CCD_GRACE_MS = 5000 };

enum ccd_os { CCD_LINUX, CCD_DARWIN, CCD_WINDOWS, CCD_OTHER };

/* String-keyed table kept sorted bytewise by key, so iteration is in
 * LC_ALL=C order. Put copies key and value and replaces a known key's value. */
struct ccd_ent { char *key; char *val; };
struct ccd_map { struct ccd_ent *ent; size_t n, cap; };

int ccd_map_put(struct ccd_map *m, const char *key, const char *val);
const char *ccd_map_get(const struct ccd_map *m, const char *key);
void ccd_map_free(struct ccd_map *m);

/* Zero when the declared source is not part of this host's complete epoch. */
int ccd_coverage_applicable(enum ccd_os os, const char *path);
/* Newest build/dev-obj/epochs/<hash> under root: 1 and out set, 0 when the
 * epochs directory does not exist or holds no epoch, -1 on path overflow,
 * -2 (errno set) when the directory cannot be opened for another reason,
 * read completely, or an entry cannot be stat'ed — a partial census must
 * never pick an older epoch while calling it newest. */
int ccd_find_epoch(const char *root, char *out, size_t cap);

/* One nm record, "path\0type\0name\0" in a single block. */
struct ccd_nmrow { char *path, *type, *name; };
struct ccd_nm {
    struct ccd_nmrow *row;
    size_t n, cap;
    int rc;        /* first nonzero nm exit status, 0 when every call succeeded */
    char *err;     /* all nm stderr text, NULL when none */
    size_t errlen;
};

/* Parses `nm --print-file-name` text, dropping unparsable lines. strip applies
 * the Mach-O underscore and $VARIANT rules. */
int ccd_parse_nm(const char *text, int strip, struct ccd_nm *out);
/* Full nm listing (never -u) over the objects in batches, stderr kept apart;
 * defined_only adds -U. 0, 1 when a termination signal was forwarded, -1 when
 * out of memory. Needs lsc_install(). */
int ccd_run_nm(char *const *objs, size_t n, int defined_only, size_t batch, int strip, struct ccd_nm *out);
/* Nonzero on a nonzero nm exit or any stderr: report UNPROVEN, trust no rows. */
int ccd_nm_failed(const struct ccd_nm *nm);
void ccd_nm_free(struct ccd_nm *nm);

/* capability_symbols.def into sym (symbol to class); *count is the row count.
 * windows adds the __imp_, __imp__ and __mingw_ aliases. 1 when unreadable. */
int ccd_symbols_load(const char *file, int windows, struct ccd_map *sym, size_t *count);

/* Shared module-row reader: 0 success, 1 absent, -1 unreadable/malformed/OOM, or callback error. */
int ccd_module_each(const char *file, int (*fn)(void *, const char *, const char *), void *ctx);

/* module_capabilities.def, source-owned sidecars and the platform supplement.
 * raw is the active-target class per source, uni the union of all rows; error
 * holds the exact sidecar_error text when the load returns 1. */
struct ccd_mods {
    struct ccd_map raw, uni;
    size_t count, platform_count;
    char error[CCD_ERR];
};
#ifdef ZCL_TESTING
/* Local census fault seam, like the app-bundle walk seam. path is borrowed
 * for one synchronous selftest call; zero state never injects a fault. */
enum ccd_scan_fault { CCD_SCAN_NONE, CCD_SCAN_OPEN, CCD_SCAN_READ,
    CCD_SCAN_STAT, CCD_SCAN_LSTAT, CCD_SCAN_CLOSE, CCD_SCAN_DIRTY };
struct ccd_scan_test {
    enum ccd_scan_fault fault;
    const char *path;
    size_t opened, closed;
};
extern struct ccd_scan_test ccd_scan_test;
#endif
int ccd_modules_load(const char *file, const char *platform_file, const char *root, struct ccd_mods *m);
void ccd_mods_free(struct ccd_mods *m);

/* "CAP_A|CAP_B" sets: union skips empty tokens and CAP_NONE (result malloc'd);
 * grants tests whole-token membership. */
char *ccd_union_caps(const char *out, const char *add);
int ccd_grants(const char *raw, const char *want);

/* Gate configuration. Production derives it from the host and the
 * environment; the selftest builds its own per fixture. */
struct ccg_cfg {
    enum ccd_os os;       /* host class: target selection and coverage exclusions */
    int strip;            /* Mach-O underscore and $VARIANT decoration in nm names */
    int symmetry;         /* a declared class the object never uses is a violation */
    long baseline;        /* shrink-only count of declared rows with no compiled object */
    const char *cflags;   /* the compile line, or NULL to ask `make print-CFLAGS` */
    const char *record;   /* BUILD_SOURCE_RECORD for the repository's own flag query */
    const char *repo;     /* the checkout whose unreadable flags are fatal, or NULL */
    FILE *out, *err;      /* the report, and the sidecar diagnostic */
};

/* Grades one tree and returns the gate exit status: 0 clean, 1 violations,
 * 2 unproven. Needs lsc_install(). */
int ccg_check_root(const struct ccg_cfg *cfg, const char *root);
/* The host's class and the environment's settings, writing to stdout and stderr. */
void ccg_host_cfg(struct ccg_cfg *cfg);

/* Macros the compile line defines: -D adds one, a later -U blanks it. */
struct ccg_macros { struct ccd_map def; int loaded; };
/* 0 once loaded, 1 when the repository's own flag query failed. */
int ccg_macros_load(const struct ccg_cfg *cfg, const char *root, struct ccg_macros *m);
/* Comma-joined guard macros of the file's first code line when none of them is
 * defined, else NULL; the caller frees it. The line must open with `#if`. */
char *ccg_compiled_out(const struct ccg_macros *m, const char *root, const char *path);

/* Fixture helpers of the data-layer selftest, shared with the gate selftest. */
struct ccs_fx { char base[1024]; };
int ccs_say(int ok, const char *name);
int ccs_scratch(struct ccs_fx *fx);
void ccs_path(const struct ccs_fx *fx, const char *rel, char *out);
int ccs_put(const struct ccs_fx *fx, const char *rel, const char *text);

#endif
