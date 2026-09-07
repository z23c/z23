/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: gate family — check-fleet-airship-rules (port of
 * tools/lint/check_fleet_airship_rules.sh, now a shim). No fleet node is
 * ever paid for a fact it reported about itself (HARD):
 * engine/composition/fleet_airship_rules.def maps a fact about a fleet
 * node to the in-game assets it earns; a row that pays out for a
 * self-reported number pays whoever types the largest one, so the gate
 * refuses it at the table rather than after a fleet has been rewarded on
 * it. Names unique, bounded, lowercase; verification PEER_VERIFIED or
 * SELF_REPORTED; every rule names a declared fact and asset; a paying
 * rule names a PEER_VERIFIED fact and is OBSERVED; a zero rule is
 * DOCTRINE; no repeated fact/asset pair; no unread declaration; at least
 * one rule pays.
 *
 * First file of the check-fleet-airship-rules family (the 700-line
 * family ceiling split): the gate body — env knobs, the floor, the
 * report, and the run entry. gate_fleet_airship_rules_parse.c holds the
 * awk row reader and the list/field helpers;
 * gate_fleet_airship_rules_rules.c holds the scan checks;
 * gate_fleet_airship_rules_selftest.c holds the planted-table selftest.
 * The files share their internals through gate_fleet_airship_rules_priv.h.
 *
 * Port notes (parity contract with the shell original):
 *  - The awk row reader is reproduced exactly: a row starts at
 *    ^AIRSHIP_(FACT|ASSET|RULE)\( , accumulates raw line text (no
 *    newlines), and closes on a line ending in `)` plus blanks; a fresh
 *    start line discards an unclosed row. Quoted strings (escapes kept
 *    verbatim) are lifted out first and the leftover commas position the
 *    bare fields; the trailing-paren cut is the leftmost `)` followed
 *    only by blanks.
 *  - Field reads follow the shell's split-on-TAB semantics, including
 *    the read-style remainder (leading/trailing TABs stripped) for the
 *    per-fact verification column and the rule `why`.
 *  - The verification lookup key passes through awk -v escape processing
 *    (gawk unescapes C-style sequences in the assigned value), so a fact
 *    name containing a backslash escape compares unescaped against the
 *    verbatim row fields, exactly as the shell does (far_awk_unescape).
 *  - The duplicate-name, duplicate-pair and used-name orderings are the
 *    shell's LC_ALL=C sort (strcmp); every other section prints in
 *    declaration order, as in the original.
 *  - `why` length is counted in BYTES (the message says bytes); bash
 *    ${#why} counts characters in a multibyte locale — a divergence only
 *    for a non-ASCII why within a few bytes of the 191 ceiling.
 *  - An unreadable table (present but not openable) exits 2 naming the
 *    path; the shell's awk error left zero rows, which surfaced as the
 *    floor FATAL — same exit code, less honest text. A missing table
 *    keeps the original FATAL text byte-for-byte.
 *  - Individual field copies are bounded (FAR_VAL); a field longer than
 *    that dies exit 2 (fail-closed) where the shell ran unbounded.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_fleet_airship_rules_priv.h"

static const char k_gate[] = "check_fleet_airship_rules";
static const char k_def_rel[] = "engine/composition/fleet_airship_rules.def";

/* ── the gate ─────────────────────────────────────────────────────────── */

static int far_count_tag(const struct far_list *rows, const char *tag)
{
    int n = 0;
    for (size_t i = 0; i < rows->n; i++)
        if (far_row_is(rows->v[i], tag))
            n++;
    return n;
}

static int far_count_verified(const struct far_list *rows)
{
    int n = 0;
    for (size_t i = 0; i < rows->n; i++) {
        if (!far_row_is(rows->v[i], "FACT"))
            continue;
        char ver[FAR_VAL];
        if (far_field(rows->v[i], 3, ver, sizeof ver) != 0)
            continue;
        if (strcmp(ver, "PEER_VERIFIED") == 0)
            n++;
    }
    return n;
}

static int far_floor(const char *floor, int rules, int facts, int assets)
{
    long fl = strtol(floor, NULL, 10);
    if (rules >= fl && facts >= 1 && assets >= 1)
        return 0;
    fprintf(stderr, "[%s] FATAL — %d rules over %d facts and %d assets is "
                    "below the floor of %s rules and one of each "
                    "vocabulary\n", k_gate, rules, facts, assets, floor);
    fputs("        A table that stopped parsing must never read as "
          "clean.\n", stderr);
    return 2;
}

static int far_report(const struct far_list *rows,
                      const struct far_list *faults, FILE *out)
{
    if (faults->n) {
        if (fprintf(out, "[%s] FAIL — the airship rule table would reward "
                    "an unverified claim:\n", k_gate) < 0)
            return die("z23-lint: write failed\n", "");
        for (size_t i = 0; i < faults->n; i++)
            if (fprintf(out, "%s\n", faults->v[i]) < 0)
                return die("z23-lint: write failed\n", "");
        return 1;
    }
    if (fprintf(out, "[%s] OK — %d rules over %d facts (%d peer-verified) "
                "and %d assets; every paying rule names a fact a peer "
                "observed\n", k_gate, far_count_tag(rows, "RULE"),
                far_count_tag(rows, "FACT"), far_count_verified(rows),
                far_count_tag(rows, "ASSET")) < 0)
        return die("z23-lint: write failed\n", "");
    return 0;
}

int far_impl(FILE *out, FILE *err)
{
    char rootbuf[4096];
    const char *root = getenv("ZCL_AIRSHIP_ROOT");
    if (!root || !root[0]) {
        if (cic_repo_root(rootbuf, sizeof rootbuf))
            return 2;
        root = rootbuf;
    }
    char def[8192];
    if (ovf(snprintf(def, sizeof def, "%s/%s", root,
                     env_or("ZCL_AIRSHIP_DEF", k_def_rel)), sizeof def))
        return 2;
    struct stat st;
    if (stat(def, &st) != 0 || !S_ISREG(st.st_mode)) {
        fprintf(err, "[%s] FATAL — %s is missing; refusing to report a "
                "clean scan\n", k_gate, def);
        return 2;
    }
    struct far_rx rx;
    int rc = far_compile(&rx);
    if (rc)
        return rc;
    struct far_list rows = { 0 }, faults = { 0 };
    int paying = 0;
    rc = far_parse(&rx, def, &rows);
    if (rc == 0)
        rc = far_floor(env_or("ZCL_AIRSHIP_FLOOR", "5"),
                       far_count_tag(&rows, "RULE"),
                       far_count_tag(&rows, "FACT"),
                       far_count_tag(&rows, "ASSET"));
    if (rc == 0)
        rc = far_scan(&rx, &rows, &faults, &paying);
    if (rc == 0)
        rc = far_report(&rows, &faults, out);
    far_free(&rows);
    far_free(&faults);
    far_drop(&rx);
    return rc;
}

int check_fleet_airship_rules_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    return far_impl(stdout, stderr);
}
