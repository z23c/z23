/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * sysinit — the explicit-table registrar behind util/sysinit.h.
 *
 * Fixed-capacity static table (no malloc, no linker set): registration copies
 * records in; the table is sorted on demand by (stage, order, name); a stage
 * run executes its slice in that deterministic order then advances the
 * boot-stage machine. See the header for the design and ordering key. */

#include "util/sysinit.h"

#include "util/log_macros.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Capacity: the wired boot boundaries plus generous headroom for future
 * per-subsystem records. A register past this is a build-time-sized bug, so
 * it logs and refuses rather than growing. */
#define SYSINIT_MAX 64

static struct sysinit_record g_records[SYSINIT_MAX];
static size_t g_count;
static bool   g_sorted;

/* Records that actually ran, in execution order, with the ctx they ran with —
 * the LIFO teardown list for sysinit_run_fini_all(). */
static struct {
    const struct sysinit_record *rec;
    void *ctx;
} g_ran[SYSINIT_MAX];
static size_t g_ran_count;

/* Total order: stage asc, then order asc, then name strcmp. A total order (not
 * just stage,order) keeps the golden file stable when two records share a
 * (stage, order). */
static int sysinit_cmp(const void *a, const void *b)
{
    const struct sysinit_record *ra = a;
    const struct sysinit_record *rb = b;
    if (ra->stage != rb->stage)
        return (int)ra->stage - (int)rb->stage;
    if (ra->order != rb->order)
        return ra->order - rb->order;
    return strcmp(ra->name, rb->name);
}

static void sysinit_sort(void)
{
    if (g_sorted) return;
    qsort(g_records, g_count, sizeof(g_records[0]), sysinit_cmp);
    g_sorted = true;
}

bool sysinit_register(const struct sysinit_record *rec)
{
    if (!rec || !rec->init || !rec->name)
        LOG_FAIL("sysinit", "malformed record (rec=%p)", (const void *)rec);
    if (g_count >= SYSINIT_MAX)
        LOG_FAIL("sysinit", "table full (%d) — cannot register '%s'",
                 SYSINIT_MAX, rec->name);
    for (size_t i = 0; i < g_count; i++) {
        if (strcmp(g_records[i].name, rec->name) == 0)
            LOG_WARN("sysinit", "duplicate record name '%s'", rec->name);
    }
    g_records[g_count++] = *rec;
    g_sorted = false;
    return true;
}

struct zcl_result sysinit_run_stage(enum boot_stage stage, void *ctx)
{
    sysinit_sort();
    for (size_t i = 0; i < g_count; i++) {
        if (g_records[i].stage != stage) continue;
        struct zcl_result r = g_records[i].init(ctx);
        if (!r.ok) {
            fprintf(stderr,  // obs-ok:sysinit-boundary-fail-precedes-return
                "[sysinit] %s record '%s' (%s) FAILED code=%d %s — "
                "boundary NOT advanced\n",
                boot_stage_name(stage), g_records[i].name,
                g_records[i].subsystem ? g_records[i].subsystem : "?",
                r.code, r.message);
            fflush(stderr);
            return r;
        }
        if (g_ran_count < SYSINIT_MAX) {
            g_ran[g_ran_count].rec = &g_records[i];
            g_ran[g_ran_count].ctx = ctx;
            g_ran_count++;
        }
    }
    boot_stage_advance_to(stage);
    return ZCL_OK;
}

void sysinit_run_fini_all(void)
{
    while (g_ran_count > 0) {
        g_ran_count--;
        const struct sysinit_record *rec = g_ran[g_ran_count].rec;
        if (rec && rec->fini)
            rec->fini(g_ran[g_ran_count].ctx);
    }
}

size_t sysinit_stage_record_count(enum boot_stage stage)
{
    size_t n = 0;
    for (size_t i = 0; i < g_count; i++)
        if (g_records[i].stage == stage) n++;
    return n;
}

size_t sysinit_ordering_snapshot(char *buf, size_t buf_sz)
{
    sysinit_sort();
    size_t off = 0;
    if (buf && buf_sz) buf[0] = '\0';
    for (size_t i = 0; i < g_count; i++) {
        int n = snprintf(buf ? buf + off : NULL,
                         buf && buf_sz > off ? buf_sz - off : 0,
                         "%s %d %s\n", boot_stage_name(g_records[i].stage),
                         g_records[i].order, g_records[i].name);
        if (n > 0) off += (size_t)n;
    }
    return g_count;
}

#ifdef ZCL_TESTING
void sysinit_reset_for_testing(void)
{
    g_count = 0;
    g_ran_count = 0;
    g_sorted = false;
    memset(g_records, 0, sizeof(g_records));
    memset(g_ran, 0, sizeof(g_ran));
}
#endif
