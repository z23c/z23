/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * gate_fleet_airship_rules_priv — the seam between the
 * check-fleet-airship-rules family files (the 700-line family ceiling
 * split): gate_fleet_airship_rules.c holds the gate body, the floor and
 * the report; gate_fleet_airship_rules_parse.c holds the awk row reader
 * and the list/field helpers; gate_fleet_airship_rules_rules.c holds the
 * scan checks; gate_fleet_airship_rules_selftest.c holds the
 * planted-table selftest.
 * NOT a public header: nothing outside tools/lint/lintc/ includes this.
 */

#ifndef ZCL_LINTC_GATE_FLEET_AIRSHIP_RULES_PRIV_H
#define ZCL_LINTC_GATE_FLEET_AIRSHIP_RULES_PRIV_H

#include <regex.h>
#include <stdio.h>
#include <stdlib.h>

enum { FAR_VAL = 4096, FAR_VER_CAP = 65536 };
enum { FAR_WHY_MAX = 191, FAR_PER_MAX = 8 };

struct far_list { char **v; size_t n, cap; };

struct far_state {
    int in, want;
    char tag[8];
    char *buf;
    size_t len, cap;
};

/* The gate's compiled matchers. One instance lives in far_impl's frame and
 * is threaded through the parse and rules calls, so the family carries no
 * file-scope regex state. */
struct far_rx {
    regex_t start, close, quote, name, per;
};

/* gate_fleet_airship_rules_parse.c */
int far_compile(struct far_rx *rx);
void far_drop(struct far_rx *rx);
void far_free(struct far_list *l);
int far_add(struct far_list *l, const char *s);
int far_addf(struct far_list *l, const char *fmt, const char *a,
             const char *b, const char *c, const char *d, const char *e);
int far_row_is(const char *row, const char *tag);
int far_field(const char *row, int n, char *out, size_t cap);
int far_read_tail(const char *row, int tabs, char *out, size_t cap);
int far_parse(struct far_rx *rx, const char *def, struct far_list *rows);

/* gate_fleet_airship_rules_rules.c */
int far_scan(struct far_rx *rx, const struct far_list *rows,
             struct far_list *faults, int *paying);

/* gate_fleet_airship_rules.c */
int far_impl(FILE *out, FILE *err);

#endif
