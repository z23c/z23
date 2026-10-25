/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Producers for the shrink-only lint baselines that the brief leaf
 *          turns into one-row work cards (baseline_hardening_banned_str).
 *
 * WHAT IT MEASURES. The sum of the COUNT column over the `banned-str` rows of
 * tools/lint/hardening_ratchet_baseline.txt, read under options->repo. The
 * gate (check-hardening-ratchet) only lets those counts shrink, so the sum is
 * the number of banned string calls still owed a bounded form. A row the gate
 * would refuse is unmeasured with the reason, never a guessed zero. */

#include "native_fleet_objectives.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BASE_HARDENING_PATH "tools/lint/hardening_ratchet_baseline.txt"
#define BASE_RULE "banned-str "
#define BASE_LINE_MAX 1024
#define BASE_COUNT_MAX 100000

/* The COUNT of a `banned-str PATH COUNT` line: -1 when the line is another
 * rule, a comment or blank, -2 when it is a banned-str row without a sane
 * count. */
static int64_t base_banned_count(const char *line)
{
    const char *sp;
    char *end = NULL;
    long n;
    if (strncmp(line, BASE_RULE, strlen(BASE_RULE)) != 0)
        return -1;
    sp = strrchr(line, ' ');
    if (!sp || sp == line + strlen(BASE_RULE) - 1)
        return -2;
    n = strtol(sp + 1, &end, 10);
    if (end == sp + 1 || (*end != '\n' && *end != '\0'))
        return -2;
    return (n >= 0 && n <= BASE_COUNT_MAX) ? n : -2;
}

/* The count sum of the file, -1 when it cannot be read, -2 when a banned-str
 * row is malformed (or longer than the line buffer). */
static int64_t base_banned_sum(const char *path)
{
    char line[BASE_LINE_MAX];
    int64_t sum = 0;
    FILE *fp = fopen(path, "r");
    if (!fp)
        return -1;
    while (sum >= 0 && fgets(line, sizeof(line), fp)) {
        bool whole = strchr(line, '\n') != NULL || feof(fp);
        int64_t n = whole ? base_banned_count(line)
                          : (strncmp(line, BASE_RULE, strlen(BASE_RULE)) == 0
                                 ? -2
                                 : -1);
        if (n == -2)
            sum = -2;
        else if (n >= 0)
            sum += n;
        while (!whole && fgets(line, sizeof(line), fp))
            whole = strchr(line, '\n') != NULL;
    }
    if (ferror(fp))
        sum = -1;
    (void)fclose(fp);
    return sum;
}

struct zcl_objective_value zcl_objectives_baseline_hardening_banned_str(
    const struct zcl_objectives_options *options)
{
    struct zcl_objective_value v = {0};
    char path[1024];
    int64_t sum;
    if (snprintf(path, sizeof(path), "%s/" BASE_HARDENING_PATH,
                 options && options->repo ? options->repo : ".") >=
        (int)sizeof(path)) {
        (void)snprintf(v.reason, sizeof(v.reason), "repo path too long");
        return v;
    }
    sum = base_banned_sum(path);
    if (sum < 0) {
        (void)snprintf(v.reason, sizeof(v.reason), "%s hardening baseline %.200s",
                       sum == -2 ? "malformed row in" : "no", path);
        return v;
    }
    v.measured = true;
    v.value = sum;
    return v;
}
