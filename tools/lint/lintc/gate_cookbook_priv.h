/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: private declarations shared by the check-cookbook gate files and
 * its selftest.
 */
#ifndef GATE_COOKBOOK_PRIV_H
#define GATE_COOKBOOK_PRIV_H

#include <stddef.h>

/* CK_ROOT_CAP bounds the repository root path; a longer one is refused. */
enum { CK_PATH = 4096, CK_ROOT_CAP = 65536, CK_GRACE_MS = 5000, CK_FIELDS = 6 };

struct ck_str {
    char *p;
    size_t n;
    size_t cap;
};

/* One registry record per entry: KIND, a tab and each quoted field in order,
 * plus a trailing tab and Z23_DEV for a row naming that tool. */
struct ck_recs {
    char **line;
    size_t n;
    size_t cap;
};

struct ck_cfg {
    const char *root;
    const char *def;
    const char *doc;
    const char *bin_dir;
    const char *floor;
    const char *timeout;
    const char *warm_timeout;
    int fix;
    int grace_ms;
};

int ck_cat(struct ck_str *s, const char *text);
void ck_str_free(struct ck_str *s);
int ck_parse(const char *text, struct ck_recs *r);
void ck_recs_free(struct ck_recs *r);
/* Splits a record the way `IFS=<tab> read -r kind f1 f2 f3 f4 f5` does:
 * runs of tabs separate fields, so empty quoted fields vanish, and the last
 * field takes the remainder. line is modified; f[0..5] point into it. */
void ck_split(char *line, char *f[CK_FIELDS]);
int ck_args_safe(const char *s);
int ck_doc(const struct ck_recs *r, struct ck_str *out);

/* Runs the gate; returns the process exit code. A termination signal stops
 * the running child and is re-raised, so the function does not return then. */
int ck_gate(const struct ck_cfg *cfg);

#endif
