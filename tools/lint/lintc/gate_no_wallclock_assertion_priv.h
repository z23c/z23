/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations of the check-no-wallclock-assertion family
 * (the clock-taint detector and its scoping half, the gate body and its
 * selftest).
 */
#ifndef GATE_NO_WALLCLOCK_ASSERTION_PRIV_H
#define GATE_NO_WALLCLOCK_ASSERTION_PRIV_H

#include <regex.h>
#include <stddef.h>
#include <stdio.h>

#define WCA_GATE "check_no_wallclock_assertion"

/* One gate invocation. glob == NULL scans the git-tracked test sources;
 * otherwise glob is a whitespace-separated list of shell patterns (the
 * ZCL_WALLCLOCK_GATE_SCAN_GLOB seam). out/err receive the report. */
struct wca_cfg {
    const char *glob;
    const char *allowlist;
    long ceiling;
    int floor;
    const char *mode; /* FAIL, WARN or UPDATE */
    FILE *out;
    FILE *err;
};

/* Runs the gate; returns 0, 1 or 2. */
int wca_run_cfg(const struct wca_cfg *cfg);

/* The detector: clock-graded assertions found in one file. */
struct wca_hit {
    int count;
    int first_line;
};
int wca_scan_init(void);
void wca_scan_fini(void);
int wca_scan_file(const char *path, struct wca_hit *hit);

/* ── detector internals, shared by the scan and scoping files ───────────── */

enum { WCA_FN = 512, WCA_NAME = 256 };

struct wca_buf { char *p; size_t n, cap; };
struct wca_set { char **slot; size_t cap, n; };
struct wca_shadow { char *id; int depth; };
struct wca_snap { char **id; int n; };

/* The per-file model: stripped lines, the function each belongs to, the
 * declarations visible on it, and the four name sets of the fixpoint. */
struct wca_state {
    regex_t decl, init, assertion, time_re;
    int ready;
    struct wca_buf text, pending, entry;
    size_t *off;
    int *lno;
    char **line;
    int *scope;
    int *snap;
    int nlines, lcap;
    struct wca_buf names;
    struct wca_set readers, taint, stamp, amb;
    struct wca_shadow *sh;
    int nsh, shcap;
    struct wca_snap *snaps;
    int nsnaps, snapcap;
    char curfn[WCA_FN];
    int body_depth, cur;
    const char *scan_line;
};
extern struct wca_state wca_g;

void *wca_grow(void *p, size_t bytes);
char *wca_dup(const char *s, size_t n);
int wca_buf_put(struct wca_buf *b, const char *s, size_t n);
const char *wca_buf_str(const struct wca_buf *b);
void wca_buf_clear(struct wca_buf *b);
int wca_wordc(char c);
int wca_idstart(char c);
int wca_blank(char c);

/* Scoping half (gate_no_wallclock_assertion_bind.c). */
int wca_note_funcdef(const char *s, int *err);
void wca_note_reset(void);
void wca_shadow_clear(void);
int wca_index_bindings(void);

#endif
