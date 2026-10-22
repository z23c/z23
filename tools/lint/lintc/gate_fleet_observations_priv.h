/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: shared declarations for check-fleet-observations
 * (gate_fleet_observations.c, gate_fleet_observations_proc.c and
 * gate_fleet_observations_selftest.c) — the C23 port of
 * tools/lint/lintc/gate_fleet_observations.c.
 */
#ifndef GATE_FLEET_OBSERVATIONS_PRIV_H
#define GATE_FLEET_OBSERVATIONS_PRIV_H
#include <signal.h>
#include <stddef.h>
#include "lintc.h"

enum { FO_PATH = 4096 };
enum { FO_SPAWN_FAILED = -1, FO_INTERRUPTED = -2 };

/* Growable byte buffer. A failed allocation sets err; later appends are
 * no-ops and callers test err once. */
struct fo_buf {
    char *p;
    size_t n;
    size_t cap;
    int err;
};

void fo_buf_put(struct fo_buf *b, const char *s, size_t n);
void fo_buf_puts(struct fo_buf *b, const char *s);
void fo_buf_free(struct fo_buf *b);
int fo_slurp(const char *path, struct fo_buf *out);

/* The generator, its fixture ledger, the committed .def and the document the
 * gate holds to that .def; every path is relative to the current directory
 * once fo_cfg_load has entered root. */
struct fo_cfg {
    char root[FO_PATH];
    char bin[FO_PATH];
    char fixture[FO_PATH];
    char def[FO_PATH];
    char doc[FO_PATH];
};

extern const char k_fo_gate[];
extern const char k_fo_doc_rel[];

int fo_cfg_load(struct fo_cfg *c);
int fo_render_doc(const char *def, struct fo_buf *out);

/* INT, TERM and HUP are blocked while armed except inside the waits of
 * fo_run; the handler only records the number. fo_finish restores the
 * previous state and re-raises a recorded signal. */
struct fo_sigs {
    sigset_t old;
    struct sigaction prev[3];
};

void fo_sigs_arm(struct fo_sigs *s);
int fo_finish(struct fo_sigs *s, int rc);
int fo_stopped(void);

/* Runs bin with args (argv[0] first), merging stdout and stderr into out
 * (discarded when out is NULL). Returns the exit status, 128+signal for a
 * killed child, FO_SPAWN_FAILED, or FO_INTERRUPTED after a recorded signal
 * stopped and reaped the child. */
int fo_run(const char *bin, char *const argv[], struct fo_buf *out);

#endif
