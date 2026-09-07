/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_source_identity_authority_priv — the seam between the
 * check-source-identity-authority family files (the 700-line family
 * ceiling split): gate_source_identity_authority.c holds the shared list
 * helpers and the gate body; gate_source_identity_authority_scan.c holds
 * the find-mirror walk and the awk per-file counter;
 * gate_source_identity_authority_ratchet.c holds the baseline, the
 * evaluation and the report; gate_source_identity_authority_selftest.c
 * holds the planted-violation selftest.
 * NOT a public header: nothing outside tools/lint/lintc/ includes this.
 */

#ifndef ZCL_LINTC_GATE_SOURCE_IDENTITY_AUTHORITY_PRIV_H
#define ZCL_LINTC_GATE_SOURCE_IDENTITY_AUTHORITY_PRIV_H

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>

enum { SIA_WIN = 6, SIA_LINE = 8192 };

struct sia_list { char **v; size_t n, cap; };
struct sia_kv { char *k, *val; int hit; };
struct sia_kvset { struct sia_kv *v; size_t n, cap; };
struct sia_count { char *path; long debt; };
struct sia_counts { struct sia_count *v; size_t n, cap; };

struct sia_acc {
    long count, p_count;
    int has_capture;
};

struct sia_eval {
    struct sia_list violations, tolerated, stale;
    long total_copies, baseline_sum;
};

/* The gate's compiled matchers. One instance lives in sia_impl's frame
 * and is threaded through the scan calls, so the family carries no
 * file-scope regex state. */
struct sia_rx {
    regex_t excl, r1, r2, r3;
};

/* gate_source_identity_authority.c */
void sia_free(struct sia_list *l);
int sia_add(struct sia_list *l, const char *s);
int sia_addf(struct sia_list *l, const char *fmt, const char *a,
             const char *b, const char *c);
void sia_sort(struct sia_list *l);
int sia_impl(FILE *out, FILE *err);

/* gate_source_identity_authority_scan.c */
int sia_walk(struct sia_rx *rx, const char *dir, struct sia_list *files);
int sia_scan_file(struct sia_rx *rx, const char *path,
                  struct sia_counts *counts);
void sia_counts_free(struct sia_counts *c);

/* gate_source_identity_authority_ratchet.c */
void sia_kvset_free(struct sia_kvset *s);
int sia_base_load(const char *path, struct sia_kvset *s);
int sia_evaluate(struct sia_counts *counts, struct sia_kvset *base,
                 struct sia_eval *e);
void sia_eval_free(struct sia_eval *e);
int sia_finish(struct sia_eval *e, struct sia_counts *counts,
               const char *baseline, const char *ceiling,
               const char *mode, int nfiles, int baseline_count, FILE *out);

#endif
