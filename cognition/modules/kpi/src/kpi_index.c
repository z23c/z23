/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * kpi_index — the metrics that need a code index handle (territories and
 * files owned), layered over the file-only collection in kpi_metrics.c.
 * Without a verified handle they stay UNAVAILABLE, never 0.
 */

#include "kpi/kpi.h"

#include "codeindex/codeindex.h"
#include "territory/territory.h"

#include <string.h>

enum { KPI_TERRITORY_CAP = 128 };

static bool kpi_territory_counts(struct codeindex *ci, uint64_t *territories,
                                 uint64_t *files_owned)
{
    if (!ci)
        return false;
    char names[KPI_TERRITORY_CAP][TERRITORY_NAME_MAX];
    int n = territory_list(ci, names, KPI_TERRITORY_CAP);
    if (n <= 0)
        return false;
    uint64_t total = 0;
    for (int i = 0; i < n; i++) {
        int fc = codeindex_count_files_in_group(ci, names[i], false);
        if (fc > 0)
            total += (uint64_t)fc;
    }
    *territories = (uint64_t)n;
    *files_owned = total;
    return true;
}

static void kpi_overlay(struct kpi_entry *e, bool ok, uint64_t v)
{
    e->state = ok ? KPI_STATE_PRESENT : KPI_STATE_UNAVAILABLE;
    e->value = ok ? v : 0;
}

void kpi_collect_masked(const char *root, struct codeindex *ci, uint32_t mask,
                        struct kpi_frame *out)
{
    if (!out)
        return;
    kpi_collect_files(root, mask, out);
    if (!(mask & KPI_GROUP_CODE))
        return;

    /* The tree this frame measured. Left all-zero when there is no verified
     * index handle: codeindex_source_root_sha3() never fabricates an all-zero
     * generation, so all-zero unambiguously reads as "unknown tree" rather
     * than as some tree that happened to hash to nothing. */
    if (ci)
        (void)codeindex_source_root_sha3(ci, out->source_root_sha3);

    uint64_t territories = 0, files_owned = 0;
    bool ok = kpi_territory_counts(ci, &territories, &files_owned);
    for (uint32_t i = 0; i < out->count; i++) {
        if (strcmp(out->metric[i].id, "territories") == 0)
            kpi_overlay(&out->metric[i], ok, territories);
        else if (strcmp(out->metric[i].id, "files_owned") == 0)
            kpi_overlay(&out->metric[i], ok, files_owned);
    }
}

void kpi_collect(const char *root, struct codeindex *ci, struct kpi_frame *out)
{
    kpi_collect_masked(root, ci, KPI_GROUP_ALL, out);
}
