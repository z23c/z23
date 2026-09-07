/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the scan checks of the check-fleet-airship-rules family (the
 * 700-line family ceiling split) — name/token/verification validation,
 * the per-rule pay lattice, the duplicate-pair and unused-declaration
 * sweeps, and far_scan() itself. The gate body lives in
 * gate_fleet_airship_rules.c, the awk row reader in
 * gate_fleet_airship_rules_parse.c, and the planted-table selftest in
 * gate_fleet_airship_rules_selftest.c; the files share their internals
 * through gate_fleet_airship_rules_priv.h. The parity contract for these
 * checks is documented in gate_fleet_airship_rules.c's header.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lintc.h"
#include "gate_fleet_airship_rules_priv.h"

/* ── the scan checks ──────────────────────────────────────────────────── */

static int far_names(const struct far_list *rows, struct far_list *names)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        if (!far_row_is(rows->v[i], "FACT") && !far_row_is(rows->v[i], "ASSET"))
            continue;
        char name[FAR_VAL];
        rc = far_field(rows->v[i], 2, name, sizeof name);
        if (rc == 0)
            rc = far_add(names, name);
    }
    return rc;
}

static int far_check_tokens(struct far_rx *rx, const struct far_list *names,
                            struct far_list *faults)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < names->n; i++) {
        if (!names->v[i][0])
            continue;
        if (regexec(&rx->name, names->v[i], 0, NULL, 0) != 0)
            rc = far_addf(faults, "  '%s' is not a bounded lowercase token",
                          names->v[i], "", "", "", "");
    }
    return rc;
}

static int far_strcmp(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* LC_ALL=C sort | uniq -d: each value seen two or more times, once. */
static int far_report_dupes(char **v, size_t n, const char *fmt,
                            struct far_list *faults)
{
    qsort(v, n, sizeof v[0], far_strcmp);
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < n; i++) {
        size_t run = 1;
        while (i + run < n && strcmp(v[i], v[i + run]) == 0)
            run++;
        if (run >= 2 && v[i][0])
            rc = far_addf(faults, fmt, v[i], "", "", "", "");
        i += run - 1;
    }
    return rc;
}

static int far_check_dup_names(const struct far_list *names,
                               struct far_list *faults)
{
    struct far_list copy = { 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < names->n; i++)
        rc = far_add(&copy, names->v[i]);
    if (rc == 0 && copy.n)
        rc = far_report_dupes(copy.v, copy.n, "  '%s' is declared twice",
                              faults);
    far_free(&copy);
    return rc;
}

static int far_check_verifs(const struct far_list *rows,
                            struct far_list *faults)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        if (!far_row_is(rows->v[i], "FACT"))
            continue;
        char name[FAR_VAL], ver[FAR_VAL];
        if (far_field(rows->v[i], 2, name, sizeof name) != 0
            || far_read_tail(rows->v[i], 2, ver, sizeof ver) != 0)
            return 2;
        if (!name[0])
            continue;
        if (strcmp(ver, "PEER_VERIFIED") != 0
            && strcmp(ver, "SELF_REPORTED") != 0)
            rc = far_addf(faults,
                          "  fact '%s' claims verification '%s', which is "
                          "neither PEER_VERIFIED nor SELF_REPORTED",
                          name, ver, "", "", "");
    }
    return rc;
}

/* awk -v f="$fact" processes C-style escapes in the assigned value before
 * the comparison runs (gawk: \\ \" \/ \a \b \f \n \r \t \v, \ooo octal,
 * \xhh hex; an unknown escape drops the backslash). The rule loop's $fact
 * stays verbatim — only the lookup key is unescaped — so a fact named
 * esc\"aped is reported undeclared even when a FACT row carries it. */
/* \ooo: up to three octal digits; *pi is left on the last digit used. */
static char far_esc_octal(const char *s, size_t *pi)
{
    size_t i = *pi;
    int v = 0, d = 0;
    while (d < 3 && s[i] >= '0' && s[i] <= '7') {
        v = v * 8 + (s[i] - '0');
        i++;
        d++;
    }
    *pi = i - 1;
    return (char)v;
}

/* \xhh: up to two hex digits; no digits at all yields a literal 'x'. */
static char far_esc_hex(const char *s, size_t *pi)
{
    size_t i = *pi;
    int v = 0, d = 0;
    while (d < 2 && isxdigit((unsigned char)s[i + 1])) {
        i++;
        d++;
        v = v * 16 + (isdigit((unsigned char)s[i])
               ? s[i] - '0' : tolower((unsigned char)s[i]) - 'a' + 10);
    }
    *pi = i;
    return d ? (char)v : 'x';
}

static int far_awk_unescape(const char *s, char *out, size_t cap)
{
    size_t w = 0;
    for (size_t i = 0; s[i]; i++) {
        if (w + 1 >= cap)
            return die("z23-lint: derived buffer overflow\n", "");
        if (s[i] != '\\') {
            out[w++] = s[i];
            continue;
        }
        char c = s[++i];
        if (!c)
            break;
        if (c >= '0' && c <= '7')
            out[w++] = far_esc_octal(s, &i);
        else if (c == 'x')
            out[w++] = far_esc_hex(s, &i);
        else {
            const char *esc = "abfnrtv\\\"/";
            const char *rep = "\a\b\f\n\r\t\v\\\"/";
            const char *hit = strchr(esc, c);
            out[w++] = hit ? rep[hit - esc] : c;
        }
    }
    out[w] = '\0';
    return 0;
}

/* awk '$2 == f { print $3 }' over the FACT rows: every match's exact
 * third field, newline-joined, trailing newline stripped. */
static int far_lookup_verif(const struct far_list *rows, const char *fact,
                            char *out, size_t cap)
{
    char key[FAR_VAL];
    int rc = far_awk_unescape(fact, key, sizeof key);
    size_t used = 0;
    out[0] = '\0';
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        if (!far_row_is(rows->v[i], "FACT"))
            continue;
        char name[FAR_VAL], v3[FAR_VAL];
        if (far_field(rows->v[i], 2, name, sizeof name) != 0
            || far_field(rows->v[i], 3, v3, sizeof v3) != 0)
            return 2;
        if (strcmp(name, key) != 0)
            continue;
        int k = snprintf(out + used, cap - used, "%s%s",
                         used ? "\n" : "", v3);
        if (ovf(k, cap - used))
            return 2;
        used += (size_t)k;
    }
    return 0;
}

static int far_asset_declared(const struct far_list *rows, const char *asset)
{
    for (size_t i = 0; i < rows->n; i++) {
        if (!far_row_is(rows->v[i], "ASSET"))
            continue;
        char name[FAR_VAL];
        if (far_field(rows->v[i], 2, name, sizeof name) != 0)
            return 0;
        if (strcmp(name, asset) == 0)
            return 1;
    }
    return 0;
}

static int far_rule_refs(const struct far_list *rows, const char *fact,
                         const char *asset, char *ver, size_t vcap,
                         struct far_list *faults)
{
    int rc = far_lookup_verif(rows, fact, ver, vcap);
    if (rc == 0 && !ver[0])
        rc = far_addf(faults, "  rule on '%s' names a fact no row declares",
                      fact, "", "", "", "");
    if (rc == 0 && !far_asset_declared(rows, asset))
        rc = far_addf(faults,
                      "  rule '%s' awards '%s', which no row declares",
                      fact, asset, "", "", "");
    return rc;
}

/* The per_node/confidence lattice; an invalid per_node skips every later
 * check for the row (the shell's `continue`). */
static int far_rule_pay(struct far_rx *rx, const char *fact,
                        const char *asset, const char *per,
                        const char *conf, const char *ver,
                        struct far_list *faults, int *paying, int *valid)
{
    *valid = 0;
    long pv = strtol(per, NULL, 10);
    if (regexec(&rx->per, per, 0, NULL, 0) != 0 || pv > FAR_PER_MAX)
        return far_addf(faults,
                        "  rule '%s' -> '%s' pays '%s', which is not a "
                        "decimal count at or under 8", fact, asset, per,
                        "", "");
    *valid = 1;
    int rc = 0;
    if (pv > 0)
        (*paying)++;
    if (strcmp(conf, "OBSERVED") != 0 && strcmp(conf, "DOCTRINE") != 0)
        rc = far_addf(faults,
                      "  rule '%s' -> '%s' carries confidence '%s', which "
                      "is neither OBSERVED nor DOCTRINE", fact, asset, conf,
                      "", "");
    if (rc == 0 && pv > 0 && strcmp(ver, "PEER_VERIFIED") != 0)
        rc = far_addf(faults,
                      "  rule '%s' -> '%s' pays %s for a fact the node "
                      "reports about itself", fact, asset, per, "", "");
    if (rc == 0 && pv > 0 && strcmp(conf, "OBSERVED") != 0)
        rc = far_addf(faults,
                      "  rule '%s' -> '%s' pays %s but is not OBSERVED",
                      fact, asset, per, "", "");
    if (rc == 0 && pv == 0 && strcmp(conf, "DOCTRINE") != 0)
        rc = far_addf(faults,
                      "  rule '%s' -> '%s' pays nothing, so it is this "
                      "table's assertion and must be DOCTRINE",
                      fact, asset, "", "", "");
    return rc;
}

static int far_rule_why(const char *fact, const char *asset, const char *why,
                        struct far_list *faults)
{
    int blank = 1;
    for (const char *p = why; *p; p++) {
        if (!isspace((unsigned char)*p)) {
            blank = 0;
            break;
        }
    }
    if (blank)
        return far_addf(faults, "  rule '%s' -> '%s' has an empty why",
                        fact, asset, "", "", "");
    if (strlen(why) > FAR_WHY_MAX)
        return far_addf(faults,
                        "  rule '%s' -> '%s': why is longer than 191 bytes",
                        fact, asset, "", "", "");
    return 0;
}

static int far_check_rules(struct far_rx *rx, const struct far_list *rows,
                           struct far_list *faults, int *paying)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        if (!far_row_is(rows->v[i], "RULE"))
            continue;
        char fact[FAR_VAL], asset[FAR_VAL], per[FAR_VAL], conf[FAR_VAL];
        char ver[FAR_VER_CAP], why[FAR_VER_CAP];
        if (far_field(rows->v[i], 2, fact, sizeof fact) != 0
            || far_field(rows->v[i], 3, asset, sizeof asset) != 0
            || far_field(rows->v[i], 4, per, sizeof per) != 0
            || far_field(rows->v[i], 5, conf, sizeof conf) != 0
            || far_read_tail(rows->v[i], 5, why, sizeof why) != 0)
            return 2;
        if (!fact[0])
            continue;
        rc = far_rule_refs(rows, fact, asset, ver, sizeof ver, faults);
        int valid = 0;
        if (rc == 0)
            rc = far_rule_pay(rx, fact, asset, per, conf, ver, faults,
                              paying, &valid);
        if (rc == 0 && valid)
            rc = far_rule_why(fact, asset, why, faults);
    }
    return rc;
}

static int far_check_pairs(const struct far_list *rows,
                           struct far_list *faults)
{
    struct far_list keys = { 0 };
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        if (!far_row_is(rows->v[i], "RULE"))
            continue;
        char fact[FAR_VAL], asset[FAR_VAL];
        if (far_field(rows->v[i], 2, fact, sizeof fact) != 0
            || far_field(rows->v[i], 3, asset, sizeof asset) != 0) {
            rc = 2;
            break;
        }
        rc = far_addf(&keys, "%s|%s", fact, asset, "", "", "");
    }
    if (rc == 0 && keys.n)
        rc = far_report_dupes(keys.v, keys.n, "  a second rule repeats '%s'",
                              faults);
    far_free(&keys);
    return rc;
}

/* The sorted-unique set of the nth field over the RULE rows. */
static int far_used_set(const struct far_list *rows, int fieldno,
                        struct far_list *used)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        if (!far_row_is(rows->v[i], "RULE"))
            continue;
        char val[FAR_VAL];
        rc = far_field(rows->v[i], fieldno, val, sizeof val);
        if (rc == 0)
            rc = far_add(used, val);
    }
    if (rc == 0 && used->n) {
        qsort(used->v, used->n, sizeof used->v[0], far_strcmp);
        size_t w = 1;
        for (size_t i = 1; i < used->n; i++) {
            if (strcmp(used->v[i], used->v[w - 1]) == 0)
                continue;
            used->v[w++] = used->v[i];
        }
        used->n = w;
    }
    return rc;
}

static int far_set_has(const struct far_list *set, const char *s)
{
    for (size_t i = 0; i < set->n; i++)
        if (strcmp(set->v[i], s) == 0)
            return 1;
    return 0;
}

static int far_check_unused(const struct far_list *rows, const char *tag,
                            const struct far_list *used, const char *msg,
                            struct far_list *faults)
{
    int rc = 0;
    for (size_t i = 0; rc == 0 && i < rows->n; i++) {
        if (!far_row_is(rows->v[i], tag))
            continue;
        char name[FAR_VAL];
        rc = far_field(rows->v[i], 2, name, sizeof name);
        if (rc == 0 && name[0] && !far_set_has(used, name))
            rc = far_addf(faults, msg, name, "", "", "", "");
    }
    return rc;
}

static int far_scan_shape(struct far_rx *rx, const struct far_list *rows,
                          struct far_list *faults, int *paying)
{
    struct far_list names = { 0 };
    int rc = far_names(rows, &names);
    int malformed = 0;
    for (size_t i = 0; i < rows->n; i++)
        if (far_row_is(rows->v[i], "MALFORMED"))
            malformed = 1;
    if (rc == 0 && malformed)
        rc = far_add(faults,
                     "  a row does not carry the right number of strings");
    if (rc == 0)
        rc = far_check_tokens(rx, &names, faults);
    if (rc == 0)
        rc = far_check_dup_names(&names, faults);
    if (rc == 0)
        rc = far_check_verifs(rows, faults);
    if (rc == 0)
        rc = far_check_rules(rx, rows, faults, paying);
    if (rc == 0)
        rc = far_check_pairs(rows, faults);
    far_free(&names);
    return rc;
}

static int far_scan_usage(const struct far_list *rows,
                          struct far_list *faults, int paying)
{
    struct far_list used_facts = { 0 }, used_assets = { 0 };
    int rc = far_used_set(rows, 2, &used_facts);
    if (rc == 0)
        rc = far_used_set(rows, 3, &used_assets);
    if (rc == 0)
        rc = far_check_unused(rows, "FACT", &used_facts,
                              "  fact '%s' is declared but no rule reads it",
                              faults);
    if (rc == 0)
        rc = far_check_unused(rows, "ASSET", &used_assets,
                              "  asset '%s' is declared but no rule awards "
                              "it", faults);
    if (rc == 0 && paying == 0)
        rc = far_add(faults,
                     "  no rule pays anything, so the table rewards "
                     "nothing at all");
    far_free(&used_facts);
    far_free(&used_assets);
    return rc;
}

int far_scan(struct far_rx *rx, const struct far_list *rows,
             struct far_list *faults, int *paying)
{
    int rc = far_scan_shape(rx, rows, faults, paying);
    if (rc == 0)
        rc = far_scan_usage(rows, faults, *paying);
    return rc;
}
