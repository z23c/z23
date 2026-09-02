/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handler for `code provenance facts` — the durable-slot mutation
 * census on the agent surface.
 *
 * Answers which RESOLVED durable named slots have source mutations in more
 * than one file. With no argument it renders the ranked multi-surface slots
 * plus the per-store honesty counters; with a `key` it renders each resolved
 * mutation site as file:line via <fn|SQL verb>. It deliberately does not infer
 * completeness, runtime reachability, authority roles, serialized ownership,
 * target database identity, or duplicate fact homes.
 *
 * Local, read-only, deterministic. The answer is recomputed for each exact
 * source generation. A process-local memo is keyed by the code index's sealed
 * content root, so repeated reads avoid rescanning unchanged source while an
 * edit forces a new census. There is no independently authored finding set.
 */

#define _GNU_SOURCE
#include "command/native_command.h"

#include "base/log_macros.h"
#include "codeindex/codeindex.h"
#include "controllers/fact_writers.h"
#include "json/json.h"
#include "kernel/command_registry.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    FACTS_TOP_CAP    = 14,   /* ranked slots rendered by the no-arg form */
    FACTS_STORE_CAP  = 8,
    FACTS_SITE_CAP   = 12,
};

/* The report is about 1 MiB and immutable after construction. Hold this lock
 * while rendering so a concurrent source-generation refresh cannot free the
 * report underneath a reader. Facts commands are diagnostic and rare; one
 * census/render at a time is the simpler, bounded ownership rule. */
static pthread_mutex_t g_facts_cache_mu = PTHREAD_MUTEX_INITIALIZER;
static struct fact_writers_report *g_facts_cache;
static uint8_t g_facts_cache_source_root[32];
static char g_facts_cache_checkout[4096];

static struct fact_writers_report *facts_report_lock(
    const char *root, struct codeindex *ci)
{
    uint8_t source_root[32];
    if (!codeindex_source_root_sha3(ci, source_root)) return NULL;
    if (pthread_mutex_lock(&g_facts_cache_mu) != 0)
        LOG_NULL("native.code.facts", "lock generation cache");
    if (g_facts_cache && strcmp(g_facts_cache_checkout, root) == 0 &&
        memcmp(g_facts_cache_source_root, source_root, sizeof(source_root)) == 0)
        return g_facts_cache;

    struct fact_writers_report *fresh = fact_writers_analyze(root, ci);
    if (!fresh) {
        (void)pthread_mutex_unlock(&g_facts_cache_mu);
        return NULL;
    }
    fact_writers_report_free(g_facts_cache);
    g_facts_cache = fresh;
    memcpy(g_facts_cache_source_root, source_root, sizeof(source_root));
    int n = snprintf(g_facts_cache_checkout, sizeof(g_facts_cache_checkout),
                     "%s", root);
    if (n < 0 || (size_t)n >= sizeof(g_facts_cache_checkout)) {
        fact_writers_report_free(g_facts_cache);
        g_facts_cache = NULL;
        (void)pthread_mutex_unlock(&g_facts_cache_mu);
        LOG_NULL("native.code.facts", "source root too long for cache key");
    }
    return g_facts_cache;
}

static void facts_report_unlock(void)
{
    (void)pthread_mutex_unlock(&g_facts_cache_mu);
}

static const char *facts_source_root(const struct zcl_command_request *request)
{
    if (request && request->context && request->context->source_root &&
        request->context->source_root[0])
        return request->context->source_root;
    const char *env = getenv("ZCL_DEV_SOURCE_ROOT");
    return env && env[0] ? env : ".";
}

static void facts_push_line(struct json_value *arr, const char *s)
{
    struct json_value item;
    json_init(&item);
    json_set_str(&item, s);
    (void)json_push_back(arr, &item);
    json_free(&item);
}

static void facts_push_obj(struct json_value *arr, struct json_value *obj)
{
    (void)json_push_back(arr, obj);
    json_free(obj);
}

/* Tail of a path — the census reports file:line, and the leading directories
 * eat the reply budget without adding information at this altitude. */
static const char *facts_short_path(const char *p)
{
    const char *keep = p;
    int slashes = 0;
    for (const char *q = p + strlen(p); q > p; q--) {
        if (q[-1] != '/') continue;
        if (++slashes == 2) { keep = q; break; }
    }
    return keep;
}

void zcl_native_handle_code_facts(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply)
{
    const char *root = facts_source_root(request);
    /* This census consumes only indexed source rows. Exact source freshness is
     * required, but compiler depfile movement cannot change its answer and
     * must not tax the warm diagnostic latency budget. */
    struct codeindex *ci = codeindex_open_source_view(root);
    if (!ci) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "CODEINDEX_OPEN",
                               "dispatch", true, false,
                               "could not open or rebuild the code index", root);
        return;
    }

    struct fact_writers_report *rep = facts_report_lock(root, ci);
    codeindex_close(ci);
    if (!rep) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "FACT_CENSUS_FAILED",
                               "dispatch", true, false,
                               "the writer census could not read the source "
                               "tree; see node log for the failing path", root);
        return;
    }

    const char *want_key = json_get_str(json_get(request->input, "key"));
    if (want_key && !want_key[0]) want_key = NULL;
    const char *want_store = json_get_str(json_get(request->input, "store"));
    if (want_store && !want_store[0]) want_store = NULL;

    struct json_value arr, lines;
    json_init(&arr);   json_set_array(&arr);
    json_init(&lines); json_set_array(&lines);

    if (want_key) {
        const struct fact_row *row = fact_writers_find(rep, want_store, want_key);
        if (!row) {
            json_free(&arr);
            json_free(&lines);
            char detail[256];
            (void)snprintf(detail, sizeof(detail),
                           "no durable slot named '%s' has a resolvable writer; "
                           "run `code provenance facts` with no argument for the slots the "
                           "census did resolve", want_key);
            facts_report_unlock();
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "FACT_NOT_FOUND",
                                   "input", false, false, detail, want_key);
            return;
        }
        for (int i = 0; i < row->n_sites && i < FACTS_SITE_CAP; i++) {
            const struct fact_writer_site *s = &row->sites[i];
            struct json_value o;
            json_init(&o); json_set_object(&o);
            (void)json_push_kv_str(&o, "path", s->path);
            (void)json_push_kv_int(&o, "line", s->line);
            (void)json_push_kv_str(&o, "via", s->via_name);
            (void)json_push_kv_str(&o, "via_kind",
                                   s->via == FACT_VIA_API ? "api" : "raw_sql");
            facts_push_obj(&arr, &o);
            char l[224];
            (void)snprintf(l, sizeof(l), "%s:%d  %s%s",
                           facts_short_path(s->path), s->line, s->via_name,
                           s->via == FACT_VIA_RAW_SQL ? " (raw SQL)" : "");
            facts_push_line(&lines, l);
        }
        (void)json_push_kv_str(&reply->data, "scope", "slot");
        (void)json_push_kv_bool(&reply->data, "authority_proven", false);
        (void)json_push_kv_bool(&reply->data, "source_coverage_complete", false);
        (void)json_push_kv_bool(&reply->data, "runtime_reachability_proven", false);
        (void)json_push_kv_str(
            &reply->data, "evidence_ceiling",
            "resolved named-literal source mutation sites under the declared "
            "derivations only; completeness, runtime reachability, ownership "
            "role, target database, serialization, and duplicate fact homes "
            "are UNPROVEN");
        (void)json_push_kv_str(&reply->data, "store", row->store);
        (void)json_push_kv_str(&reply->data, "key", row->key);
        (void)json_push_kv_int(&reply->data, "writer_files", row->writer_files);
        (void)json_push_kv_int(&reply->data, "writer_sites", row->writer_sites);
        (void)json_push_kv(&reply->data, "writers", &arr);
        (void)json_push_kv(&reply->data, "lines", &lines);
        (void)json_push_kv_bool(&reply->data, "truncated", row->sites_truncated);
        char summary[512];
        (void)snprintf(summary, sizeof(summary),
                       "%s/%s: %d writer file(s), %d site(s)%s",
                       row->store, row->key, row->writer_files,
                       row->writer_sites,
                       row->writer_files > 1
                           ? " — MULTI-SURFACE: authority and duplicate-home "
                             "claims remain UNPROVEN"
                           : " — single resolved mutation surface; authority "
                             "still UNPROVEN");
        (void)json_push_kv_str(&reply->data, "summary", summary);
        json_free(&arr);
        json_free(&lines);
        facts_report_unlock();
        return;
    }

    int shown = 0;
    for (int i = 0; i < rep->n_rows && shown < FACTS_TOP_CAP; i++) {
        const struct fact_row *row = &rep->rows[i];
        if (row->writer_files < 2) break;   /* rows are ranked desc */
        if (want_store && strcmp(row->store, want_store) != 0) continue;
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "store", row->store);
        (void)json_push_kv_str(&o, "key", row->key);
        (void)json_push_kv_int(&o, "writer_files", row->writer_files);
        (void)json_push_kv_int(&o, "writer_sites", row->writer_sites);
        facts_push_obj(&arr, &o);
        char l[224];
        (void)snprintf(l, sizeof(l), "%d files  %s/%s", row->writer_files,
                       row->store, row->key);
        facts_push_line(&lines, l);
        shown++;
    }

    struct json_value stores;
    json_init(&stores); json_set_array(&stores);
    for (int i = 0; i < rep->n_stores && i < FACTS_STORE_CAP; i++) {
        const struct fact_store_stat *st = &rep->stores[i];
        struct json_value o;
        json_init(&o); json_set_object(&o);
        (void)json_push_kv_str(&o, "store", st->store);
        (void)json_push_kv_int(&o, "facts", st->facts);
        (void)json_push_kv_int(&o, "facts_multi_writer", st->facts_multi_writer);
        (void)json_push_kv_int(&o, "sites_resolved", st->sites_resolved);
        (void)json_push_kv_int(&o, "sites_unresolved", st->sites_unresolved);
        facts_push_obj(&stores, &o);
    }

    (void)json_push_kv_str(&reply->data, "scope", "census");
    (void)json_push_kv_bool(&reply->data, "authority_proven", false);
    (void)json_push_kv_bool(&reply->data, "source_coverage_complete", false);
    (void)json_push_kv_bool(&reply->data, "runtime_reachability_proven", false);
    (void)json_push_kv_str(
        &reply->data, "evidence_ceiling",
        "resolved named-literal source mutation sites under the declared "
        "derivations only; completeness, runtime reachability, ownership role, "
        "target database, serialization, and duplicate fact homes are UNPROVEN");
    (void)json_push_kv_int(&reply->data, "files_scanned", rep->files_scanned);
    (void)json_push_kv_int(&reply->data, "facts_total", rep->facts_total);
    (void)json_push_kv_int(&reply->data, "facts_multi_writer",
                           rep->facts_multi_writer);
    (void)json_push_kv_int(&reply->data, "writer_sites", rep->sites_total);
    (void)json_push_kv_int(&reply->data, "sites_unresolved",
                           rep->sites_unresolved);
    (void)json_push_kv_int(&reply->data, "rows_dropped", rep->rows_dropped);
    (void)json_push_kv(&reply->data, "multi_writer", &arr);
    (void)json_push_kv(&reply->data, "stores", &stores);
    (void)json_push_kv(&reply->data, "lines", &lines);
    (void)json_push_kv_bool(&reply->data, "truncated",
                            shown < rep->facts_multi_writer);
    char summary[512];
    (void)snprintf(summary, sizeof(summary),
                   "%d resolved named-literal slot(s) across %d store(s); "
                   "%d have "
                   "mutation sites in MORE THAN ONE file (%d shown); %d write "
                   "site(s) had a non-literal key and are unattributed. "
                   "Authority roles and duplicate fact homes are UNPROVEN. "
                   "`code provenance facts <key>` names each resolved site.",
                   rep->facts_total, rep->n_stores, rep->facts_multi_writer,
                   shown, rep->sites_unresolved);
    (void)json_push_kv_str(&reply->data, "summary", summary);

    json_free(&arr);
    json_free(&lines);
    json_free(&stores);
    facts_report_unlock();
}
