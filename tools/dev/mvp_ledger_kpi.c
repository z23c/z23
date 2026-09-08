/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: measure the 144-loop MVP experiment — the KPI the owner asked
 *          for on 2026-09-08: VERIFIED MVP PROGRESS PER TOKEN. Numerator:
 *          base plan loops whose verifier wrote LAND at or after t0.
 *          Denominator: every measured agent in the window, in three token
 *          views, of which TCU is primary. See tools/dev/mvp_ledger.h. */
#define _POSIX_C_SOURCE 200809L
#include "mvp_ledger.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "base/safe_alloc.h"
#include "mvp_ledger_internal.h"
#include "platform/directory_compat.h"

/* ── which lanes a verifier landed after t0 ───────────────────────────── */

/* `vfaillocator4` names lane `faillocator`: drop the leading v, then the
 * round number a re-verification appends. */
static bool mvl_lane_of_verdict_dir(const char *dir, char *lane, size_t cap)
{
    size_t n;

    if (dir[0] != 'v' || dir[1] == '\0')
        return false;
    mvl_copy(lane, cap, dir + 1);
    n = strlen(lane);
    while (n > 0 && lane[n - 1] >= '0' && lane[n - 1] <= '9')
        lane[--n] = '\0';
    return n > 0;
}

/* The VERDICT's own modified time, from the one directory listing that also
 * proves the file is a real regular file. Returns false when the directory
 * holds no VERDICT with a valid metadata snapshot. */
static bool mvl_verdict_mtime(const char *dir, int64_t *mtime_out)
{
    struct platform_directory_list files = {0};
    bool found = false;

    if (!platform_directory_list_regular_sorted(dir, &files))
        return false;
    for (size_t i = 0; i < files.count; i++) {
        if (strcmp(files.entries[i].name, "VERDICT") != 0)
            continue;
        if (!files.entries[i].snapshot_valid)
            break;
        *mtime_out = files.entries[i].modified_seconds;
        found = true;
        break;
    }
    platform_directory_list_free(&files);
    return found;
}

static bool mvl_verdict_is_land(const char *dir, char *err, size_t err_cap)
{
    char path[MVL_PATH_CAP];
    char *buf = zcl_malloc(MVL_LINE_CAP + 2, "mvl_verdict_line");
    FILE *f;
    bool land = false;

    if (!buf) {
        mvl_err(err, err_cap, dir, 0, "mvl_overflow: no line buffer");
        return false;
    }
    if (!mvl_path_of(path, sizeof path, dir, "/VERDICT", "", "")) {
        mvl_err(err, err_cap, dir, 0,
                "mvl_overflow: VERDICT path longer than MVL_PATH_CAP");
        free(buf);
        return false;
    }
    f = fopen(path, "r");
    if (f) {
        if (mvl_read_line(f, buf, MVL_LINE_CAP + 2) == 1)
            land = strncmp(buf, "LAND", 4) == 0;
        (void)fclose(f);
    }
    free(buf);
    return land;
}

static bool mvl_lane_seen(const char (*lanes)[MVL_LANE_CAP], size_t count,
                          const char *lane)
{
    for (size_t i = 0; i < count; i++)
        if (strcmp(lanes[i], lane) == 0)
            return true;
    return false;
}

bool mvl_verified_lanes(const char *scratch_dir, int64_t t0_unix,
                        char (*lanes)[MVL_LANE_CAP], size_t cap,
                        size_t *count, char *err, size_t err_cap)
{
    struct platform_directory_list dirs = {0};
    bool ok = true;

    *count = 0;
    if (!platform_directory_list_real_sorted(scratch_dir, &dirs)) {
        mvl_err(err, err_cap, scratch_dir, 0,
                "mvl_open: cannot list the scratch directory");
        return false;
    }
    for (size_t i = 0; ok && i < dirs.count; i++) {
        char lane[MVL_LANE_CAP];
        char path[MVL_PATH_CAP];
        int64_t mtime = 0;

        if (!mvl_lane_of_verdict_dir(dirs.entries[i].name, lane, sizeof lane))
            continue;
        if (!mvl_path_of(path, sizeof path, scratch_dir, "/",
                         dirs.entries[i].name, ""))
            continue;
        if (!mvl_verdict_mtime(path, &mtime) || mtime < t0_unix)
            continue;
        if (!mvl_verdict_is_land(path, err, err_cap))
            continue;
        if (mvl_lane_seen(lanes, *count, lane))
            continue;
        if (*count >= cap) {
            mvl_err(err, err_cap, scratch_dir, *count,
                    "mvl_overflow: more verified lanes than the table holds");
            ok = false;
            break;
        }
        mvl_copy(lanes[(*count)++], MVL_LANE_CAP, lane);
    }
    platform_directory_list_free(&dirs);
    return ok;
}

/* ── the KPI itself ───────────────────────────────────────────────────── */

static void mvl_kpi_numerator(const struct mvl_plan *plan,
                              const char (*lanes)[MVL_LANE_CAP],
                              size_t lane_count,
                              const char (*anc)[MVL_ID_CAP], size_t anc_count,
                              struct mvl_kpi *out)
{
    for (size_t i = 0; i < plan->loop_count; i++) {
        const struct mvl_loop *l = &plan->loops[i];
        bool verified = mvl_lane_seen(lanes, lane_count, l->lane);

        if (verified && l->counted)
            out->verified_loops++;
        if (verified && !l->counted)
            out->verified_subrows++;
        if (!l->counted || anc_count == 0)
            continue;
        if (mvl_evidence_landed(l->evidence, anc, anc_count))
            out->landed_loops++;
    }
}

static void mvl_kpi_denominator(const struct mvl_agents *agents,
                                struct mvl_kpi *out)
{
    int64_t tcu_hundredths = 0;

    for (size_t i = 0; i < agents->count; i++) {
        const struct mvl_agent *a = &agents->rows[i];

        out->tokens_out += a->tokens_out;
        out->tokens_raw += a->tokens_out + a->tokens_in;
        tcu_hundredths += a->tokens_out * MVL_TCU_OUT;
        tcu_hundredths += a->tokens_input * MVL_TCU_INPUT;
        tcu_hundredths += a->tokens_cache_creation * MVL_TCU_CACHE_CREATION;
        tcu_hundredths += a->tokens_cache_read * MVL_TCU_CACHE_READ;
    }
    out->tcu = tcu_hundredths / MVL_TCU_SCALE;
}

void mvl_compute_kpi(const struct mvl_plan *plan,
                     const struct mvl_agents *agents,
                     const char (*lanes)[MVL_LANE_CAP], size_t lane_count,
                     const char (*anc)[MVL_ID_CAP], size_t anc_count,
                     struct mvl_kpi *out)
{
    memset(out, 0, sizeof *out);
    mvl_kpi_numerator(plan, lanes, lane_count, anc, anc_count, out);
    mvl_kpi_denominator(agents, out);
}

/* Verified loops per million TCU, in thousandths — the ratio is carried as
 * an integer so the KPI never moves with the host's floating point. */
static int64_t mvl_loops_per_mtcu_milli(const struct mvl_kpi *kpi)
{
    if (kpi->tcu <= 0)
        return 0;
    return (kpi->verified_loops * 1000000000LL) / kpi->tcu;
}

static int64_t mvl_tcu_per_loop(const struct mvl_kpi *kpi)
{
    if (kpi->verified_loops <= 0)
        return 0;
    return kpi->tcu / kpi->verified_loops;
}

const char *mvl_kpi_header(void)
{
    return "utc\twindow\tverified_loops\tverified_subrows\tlanded_loops\t"
           "tokens_raw\ttokens_out\ttcu\tloops_per_mtcu\ttcu_per_loop\tnote";
}

static const char *mvl_kpi_cell(const char *s)
{
    return (s && s[0] != '\0') ? s : "-";
}

bool mvl_append_kpi(const char *path, const struct mvl_kpi *kpi,
                    const char *utc, const char *window, const char *note,
                    char *err, size_t err_cap)
{
    int64_t milli = mvl_loops_per_mtcu_milli(kpi);
    bool fresh;
    FILE *f;

    if (!mvl_check_header(path, mvl_kpi_header(), err, err_cap))
        return false;
    fresh = mvl_ledger_is_fresh(path);
    f = fopen(path, "a");
    if (!f) {
        mvl_err(err, err_cap, path, 0, "mvl_open: cannot append the KPI row");
        return false;
    }
    if (fresh)
        fprintf(f, "%s\n", mvl_kpi_header());
    fprintf(f, "%s\t%s\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld.%03lld"
               "\t%lld\t%s\n",
            utc, mvl_kpi_cell(window), (long long)kpi->verified_loops,
            (long long)kpi->verified_subrows, (long long)kpi->landed_loops,
            (long long)kpi->tokens_raw, (long long)kpi->tokens_out,
            (long long)kpi->tcu, (long long)(milli / 1000),
            (long long)(milli % 1000), (long long)mvl_tcu_per_loop(kpi),
            mvl_kpi_cell(note));
    if (fclose(f) != 0) {
        mvl_err(err, err_cap, path, 0, "mvl_open: kpi.tsv did not close");
        return false;
    }
    return true;
}

size_t mvl_render_kpi(const struct mvl_kpi *kpi, char *out, size_t out_cap)
{
    int64_t milli = mvl_loops_per_mtcu_milli(kpi);
    int n = snprintf(out, out_cap,
                     "kpi: %lld verified loops (+%lld sub-rows, %lld landed)"
                     " for %lld TCU = %lld.%03lld loops/MTCU,"
                     " %lld TCU/loop\n",
                     (long long)kpi->verified_loops,
                     (long long)kpi->verified_subrows,
                     (long long)kpi->landed_loops, (long long)kpi->tcu,
                     (long long)(milli / 1000), (long long)(milli % 1000),
                     (long long)mvl_tcu_per_loop(kpi));

    return n > 0 ? (size_t)n : 0;
}
