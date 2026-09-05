/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: CLI shim for build/bin/z23-fleet-observe. All logic lives in
 *          tools/dev/fleet_observe.c so the test harness can call it
 *          directly; this file only parses argv, does file I/O, and prints.
 *
 * Usage:
 *   z23-fleet-observe [--ledger=PATH] [--days=N] [--out=PATH] [--check]
 *
 * --ledger  default: $XDG_STATE_HOME/zclassic23/experiments/rows.tsv (or
 *           ~/.local/state/zclassic23/experiments/rows.tsv)
 * --days    trailing window, anchored on the ledger's own newest row.
 *           Default 7.
 * --out     default: engine/composition/fleet_observations.def
 * --check   regenerate to memory and diff against --out; print a summary
 *           and exit 1 on any difference, 0 if identical. Without --check,
 *           the tool overwrites --out.
 */
#include "fleet_observe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { FO_BUF_CAP = 1 << 20 };

static char g_generated[FO_BUF_CAP];
static char g_committed[FO_BUF_CAP];
static struct fo_row g_rows[FO_MAX_ROWS];
static struct fo_pair g_pairs[FO_MAX_PAIRS];
static struct fo_observation g_obs[FO_MAX_OBS_ROWS * 2];

static const char *fo_default_ledger(char *buf, size_t cap)
{
    const char *xdg = getenv("XDG_STATE_HOME");
    const char *home = getenv("HOME");

    if (xdg && xdg[0]) {
        (void)snprintf(buf, cap, "%s/zclassic23/experiments/rows.tsv", xdg);
        return buf;
    }
    if (home && home[0]) {
        (void)snprintf(buf, cap,
                       "%s/.local/state/zclassic23/experiments/rows.tsv",
                       home);
        return buf;
    }
    return "rows.tsv";
}

static bool fo_arg_value(const char *arg, const char *flag, const char **out)
{
    size_t n = strlen(flag);

    if (strncmp(arg, flag, n) != 0)
        return false;
    *out = arg + n;
    return true;
}

int main(int argc, char **argv)
{
    const char *ledger_arg = NULL;
    const char *out_arg = "engine/composition/fleet_observations.def";
    const char *days_arg = NULL;
    bool check_mode = false;
    char ledger_default[1024];
    char err[256];
    size_t row_count = 0, pair_count = 0, obs_count = 0;
    int window_days = FO_DEFAULT_WINDOW_DAYS;
    int64_t anchor;

    for (int i = 1; i < argc; i++) {
        const char *v;

        if (fo_arg_value(argv[i], "--ledger=", &v)) ledger_arg = v;
        else if (fo_arg_value(argv[i], "--out=", &v)) out_arg = v;
        else if (fo_arg_value(argv[i], "--days=", &v)) days_arg = v;
        else if (strcmp(argv[i], "--check") == 0) check_mode = true;
        else {
            (void)fprintf(stderr, "z23-fleet-observe: unknown argument '%s'\n",
                          argv[i]);
            return 2;
        }
    }
    if (days_arg)
        window_days = atoi(days_arg);
    if (window_days <= 0) {
        (void)fprintf(stderr, "z23-fleet-observe: --days must be positive\n");
        return 2;
    }
    if (!ledger_arg)
        ledger_arg = fo_default_ledger(ledger_default, sizeof(ledger_default));

    if (!fo_read_ledger(ledger_arg, g_rows, FO_MAX_ROWS, &row_count, err,
                        sizeof(err))) {
        (void)fprintf(stderr, "z23-fleet-observe: FATAL — %s\n", err);
        return 2;
    }

    anchor = fo_latest_ts(g_rows, row_count);
    pair_count = fo_aggregate(g_rows, row_count, anchor, window_days, g_pairs,
                              FO_MAX_PAIRS);
    for (size_t i = 0; i < pair_count && obs_count + 2 <= FO_MAX_OBS_ROWS * 2;
         i++)
        obs_count += fo_classify(&g_pairs[i], &g_obs[obs_count]);

    (void)fo_render_def(g_obs, obs_count, window_days, anchor, ledger_arg,
                        g_generated, sizeof(g_generated));

    if (!check_mode) {
        FILE *f = fopen(out_arg, "w");

        if (!f) {
            (void)fprintf(stderr,
                          "z23-fleet-observe: cannot write '%s'\n", out_arg);
            return 2;
        }
        (void)fputs(g_generated, f);
        (void)fclose(f);
        (void)printf("z23-fleet-observe: wrote %zu rows over %zu pairs to "
                     "%s\n",
                     obs_count, pair_count, out_arg);
        return 0;
    }

    {
        FILE *f = fopen(out_arg, "r");
        size_t committed_len = 0;

        if (f) {
            committed_len = fread(g_committed, 1, sizeof(g_committed) - 1, f);
            g_committed[committed_len] = '\0';
            (void)fclose(f);
        } else {
            g_committed[0] = '\0';
        }
        if (strcmp(g_generated, g_committed) == 0) {
            (void)printf("z23-fleet-observe: --check OK — %s matches %zu "
                         "rows regenerated from %s\n",
                         out_arg, obs_count, ledger_arg);
            return 0;
        }
        (void)fprintf(stderr,
                      "z23-fleet-observe: --check FAIL — %s does not match "
                      "a regeneration from %s (committed %zu bytes, "
                      "regenerated %zu bytes)\n",
                      out_arg, ledger_arg, strlen(g_committed),
                      strlen(g_generated));
        return 1;
    }
}
