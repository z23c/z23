/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for the check-windows-acceptance gate port.
 * The gate lives in gate_windows_acceptance.c (mode dispatch),
 * gate_windows_acceptance_parse.c (catalog and registry parsing),
 * gate_windows_acceptance_reconcile.c (the reconcile step) and
 * gate_windows_acceptance_steps.c (the make-driving compile steps), with the
 * selftest in gate_windows_acceptance_selftest.c. Not a compilation unit.
 */
#ifndef GATE_WINDOWS_ACCEPTANCE_PRIV_H
#define GATE_WINDOWS_ACCEPTANCE_PRIV_H

#include <stddef.h>
#include <stdio.h>

#define WA_CATALOG_REL "platform/modules/platform/tests/windows_acceptance.mk"
#define WA_REGISTRY_REL "tools/dev/test_group_catalog.def"

enum {
    WA_PATH = 1024,
    WA_LINE = 4096,
    WA_ID = 64,
    WA_IDS = 128,
    WA_NAMES = 8192,
    WA_TEXT = 1 << 18,
};

struct wa_ids { char v[WA_IDS][WA_ID]; int n; };
struct wa_names { char v[WA_NAMES][WA_PATH]; int n; };

/* Shared line iteration over a slurped NUL-terminated buffer. */
int wa_next_line(const char *buf, size_t *pos, char *out, size_t cap);
int wa_slurp_rel(const char *root, const char *rel, char *buf, size_t cap);

/* Parsers. 0 ok; 2 on unreadable, malformed or overflow. */
int wa_catalog_tests(const char *root, struct wa_ids *out);
int wa_catalog_source_ids(const char *root, struct wa_ids *out);
int wa_catalog_sources(const char *root, struct wa_names *out);
int wa_catalog_program_dirs(const char *root, struct wa_names *out);
int wa_registry_groups(const char *root, struct wa_names *out);
int wa_exempt_paths(struct wa_names *out);
int wa_exempt_reasonless(FILE *out);

/* List helpers. */
int wa_has(const struct wa_names *s, const char *name);
int wa_ids_has(const struct wa_ids *s, const char *name);
void wa_ids_sort(struct wa_ids *s);
void wa_names_sort_unique(struct wa_names *s);
int wa_ids_equal(const struct wa_ids *a, const struct wa_ids *b);
int wa_ids_dup(const struct wa_ids *s);

/* 1 when path defines the entry of a group in groups. */
int wa_file_group(const char *path, const struct wa_names *groups);
int wa_scan_dir(const char *root, const char *dir, struct wa_names *out);
int wa_repo_root(char *buf, size_t cap);

/* Steps. */
int wa_reconcile_root(const char *root, FILE *out);
int wa_compile_step_io(FILE *out, FILE *err, int quiet);
int wa_global_main_io(FILE *out);
int wa_rows_main_io(int argc, char **argv, FILE *out, FILE *err);
int wa_cross_link_jobs(void);

int check_windows_acceptance_selftest(void);
#endif
