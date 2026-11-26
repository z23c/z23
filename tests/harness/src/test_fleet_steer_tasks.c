/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: pure task projection contracts; no node, process or state root. */
#include "command/native_fleet_steer_tasks.h"
#include "base/safe_alloc.h"
#include <stdio.h>
#include <string.h>
#define FT_CHECK(x) do { if (!(x)) { \
    fprintf(stderr, "task projection:%d: %s\n", __LINE__, #x); return 1; } } while (0)
#define FT_HEAD "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define FT_BASE "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define FT_OLD "cccccccccccccccccccccccccccccccccccccccc"

static struct json_value ft_parse(const char *text)
{
    struct json_value out = {0};
    if (!json_read(&out, text, strlen(text)))
        fprintf(stderr, "task fixture: invalid JSON\n");
    return out;
}

static bool ft_is(const struct json_value *row, const char *key, const char *text)
{
    const struct json_value *v = json_get(row, key);
    return v && v->type == JSON_STR && strcmp(json_get_str(v), text) == 0;
}

static const struct json_value *ft_task(const struct zcl_fmc_tasks *v,
    const char *ref)
{
    for (size_t i = 0; i < json_size(&v->rows); i++)
        if (ft_is(json_at(&v->rows, i), "ref", ref)) return json_at(&v->rows, i);
    return NULL;
}

static int ft_queue_cases(void)
{
    struct zcl_fmc_tasks v;
    zcl_fmc_tasks_init(&v);
    struct json_value queue = ft_parse("{\"queued\":["
        "{\"seq\":1,\"name\":\"ready\",\"attempt\":2,\"ready\":true,\"blocker\":null,\"depends_on\":\"\"},"
        "{\"seq\":2,\"name\":\"absent\",\"attempt\":1,\"ready\":false,\"blocker\":{\"ref\":\"missing\",\"state\":\"absent\",\"attempt\":null,\"verdict\":null}},"
        "{\"seq\":3,\"name\":\"failed\",\"attempt\":1,\"ready\":false,\"depends_on\":\"dep\",\"blocker\":{\"ref\":\"dep\",\"state\":\"terminal\",\"attempt\":3,\"verdict\":\"failed\"}},"
        "{\"seq\":4,\"name\":\"retry-wait\",\"attempt\":1,\"ready\":false,\"blocker\":{\"ref\":\"dep\",\"state\":\"running\",\"attempt\":4,\"verdict\":null}}],"
        "\"running\":[{\"seq\":5,\"name\":\"live\",\"attempt\":2,\"worker\":\"node-a\",\"owner_liveness\":\"running\",\"age_s\":6},"
        "{\"seq\":6,\"name\":\"dead\",\"attempt\":2,\"worker\":null,\"owner_liveness\":\"dead\"},"
        "{\"seq\":7,\"name\":\"unknown\",\"attempt\":2,\"owner_liveness\":\"unknown\"}],"
        "\"outcomes\":[{\"name\":\"dep\",\"attempt\":3,\"verdict\":\"pass\",\"rc\":0}]} ");
    FT_CHECK(zcl_fmc_tasks_queue(&v, &queue, 1000, 1000));
    FT_CHECK(ft_is(ft_task(&v, "ready"), "state", "queued"));
    FT_CHECK(json_is_null(json_get(ft_task(&v, "ready"), "owner")));
    FT_CHECK(ft_is(ft_task(&v, "live"), "state", "executing"));
    FT_CHECK(ft_is(ft_task(&v, "dead"), "state", "blocked"));
    FT_CHECK(ft_is(ft_task(&v, "unknown"), "state", "unknown"));
    FT_CHECK(ft_is(ft_task(&v, "absent"), "state", "blocked"));
    FT_CHECK(ft_is(ft_task(&v, "failed"), "state", "blocked"));
    FT_CHECK(ft_is(ft_task(&v, "retry-wait"), "state", "blocked"));
    FT_CHECK(json_get_int(json_get(json_get(ft_task(&v, "retry-wait"), "blocker"), "attempt")) == 4);
    FT_CHECK(ft_is(json_at(&v.rows, 0), "state", "blocked"));
    struct json_value rendered = {0}; char screen[8192];
    json_set_object(&rendered); FT_CHECK(zcl_fmc_tasks_emit(&v, &rendered));
    zcl_fmc_tasks_screen(&rendered, screen, sizeof(screen));
    FT_CHECK(strstr(screen, "dependency=dep a4 running") != NULL);
    FT_CHECK(strstr(screen, "--ref=live --seq=5 --attempt=2") != NULL);
    json_free(&rendered);
    const struct json_value *detail = json_get(ft_task(&v, "live"), "detail");
    FT_CHECK(json_get_int(json_get(detail, "seq")) == 5);
    FT_CHECK(json_get_int(json_get(detail, "attempt")) == 2);
    zcl_fmc_tasks_free(&v);
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_queue(&v, &queue, 1, 1000));
    FT_CHECK(ft_is(ft_task(&v, "live"), "state", "unknown"));
    FT_CHECK(ft_is(ft_task(&v, "live"), "freshness", "stale"));
    zcl_fmc_tasks_free(&v);
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_queue(&v, &queue, 1001, 1000));
    FT_CHECK(ft_is(ft_task(&v, "live"), "state", "unknown"));
    FT_CHECK(json_is_null(json_get(ft_task(&v, "live"), "observed_age_s")));
    zcl_fmc_tasks_free(&v);
    json_free(&queue);
    return 0;
}

static int ft_landing_case(const char *proof_text, const char *state,
    const char *phase, bool exact)
{
    char text[2048], before[2048], after[2048], screen[8192];
    (void)snprintf(text, sizeof(text), "{\"queued\":[],\"outcomes\":[],\"in_flight\":{"
        "\"seq\":390,\"attempt\":2,\"tip\":\"%s\",\"local\":\"%s\",\"base\":\"%s\","
        "\"phase\":\"%s\",\"acceptance_state\":\"unknown\",\"publication_signer\":\"signed-intent\","
        "\"review\":\"approved-old-head\",\"proof_state\":\"running\",\"detail\":\"old-stored-running\"}}",
        FT_HEAD, FT_HEAD, FT_BASE, phase);
    struct json_value land = ft_parse(text), proof = ft_parse(proof_text), out = {0};
    struct zcl_fmc_tasks v;
    zcl_fmc_tasks_init(&v);
    (void)json_write(&land, before, sizeof(before));
    FT_CHECK(zcl_fmc_tasks_land(&v, &land, &proof, 1000, 1000));
    const struct json_value *row = json_at(&v.rows, 0);
    FT_CHECK(ft_is(row, "state", state));
    FT_CHECK(ft_is(row, "review", "unknown"));
    FT_CHECK(ft_is(row, "publication", "unknown"));
    FT_CHECK(json_is_null(json_get(row, "canonical_task")));
    FT_CHECK(json_get_bool(json_get(json_get(row, "proof"), "exact_pair")) == exact);
    json_set_object(&out);
    FT_CHECK(zcl_fmc_tasks_emit(&v, &out));
    zcl_fmc_tasks_screen(&out, screen, sizeof(screen));
    FT_CHECK(strstr(screen, state) != NULL);
    FT_CHECK(strstr(screen, "partial inventory") != NULL);
    FT_CHECK(strstr(screen, "prepared=aaaaaaaaaaaa base=bbbbbbbbbbbb") != NULL);
    FT_CHECK(strstr(screen, "review=unknown publication=unknown") != NULL);
    (void)json_write(&land, after, sizeof(after));
    FT_CHECK(strcmp(before, after) == 0);
    json_free(&out); json_free(&land); json_free(&proof);
    zcl_fmc_tasks_free(&v);
    return 0;
}

static int ft_landing_cases(void)
{
#define FT_PAIR "\"local_commit\":\"" FT_HEAD "\",\"remote_base\":\"" FT_BASE "\","
    FT_CHECK(ft_landing_case("{" FT_PAIR "\"status\":\"running\",\"detail\":\"resident_proof_request_queued\"}", "queued", "prove", true) == 0);
    FT_CHECK(ft_landing_case("{" FT_PAIR "\"status\":\"running\",\"detail\":\"background_verification_running\",\"worker_id\":88,\"started_unix\":999}", "executing", "prove", true) == 0);
    FT_CHECK(ft_landing_case("{" FT_PAIR "\"status\":\"running\",\"detail\":\"background_verification_running\"}", "unknown", "prove", true) == 0);
    FT_CHECK(ft_landing_case("{" FT_PAIR "\"status\":\"running\",\"detail\":\"background_verification_running\",\"worker_id\":88,\"started_unix\":1001}", "unknown", "prove", true) == 0);
    FT_CHECK(ft_landing_case("{" FT_PAIR "\"status\":\"passed\",\"detail\":\"exact_receipt_admitted\"}", "verified", "prove", true) == 0);
    FT_CHECK(ft_landing_case("{" FT_PAIR "\"status\":\"failed\"}", "blocked", "prove", true) == 0);
    FT_CHECK(ft_landing_case("{" FT_PAIR "\"status\":\"missing\"}", "queued", "prove", true) == 0);
    FT_CHECK(ft_landing_case("{" FT_PAIR "\"status\":\"passed\"}", "unknown", "push", true) == 0);
    FT_CHECK(ft_landing_case("{\"local_commit\":\"" FT_HEAD "\",\"remote_base\":\"" FT_OLD "\",\"status\":\"passed\"}", "unknown", "prove", false) == 0);
    FT_CHECK(ft_landing_case("null", "unknown", "prove", false) == 0);
    return 0;
}

static int ft_landing_steer_mismatch(const char *candidate, int seq)
{
    char text[2048];
    (void)snprintf(text, sizeof(text), "{\"queued\":[{\"seq\":390,"
        "\"attempt\":2,\"tip\":\"" FT_HEAD "\",\"state\":\"queued\"}],"
        "\"outcomes\":[],\"incident\":\"none\",\"steer\":{"
        "\"candidate\":\"%s\",\"seq\":%d}}", candidate, seq);
    struct json_value land = ft_parse(text);
    struct zcl_fmc_tasks v;
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_land(&v, &land, NULL, 1000, 1000));
    const struct json_value *row = json_at(&v.rows, 0);
    FT_CHECK(ft_is(row, "landing_steer_link", "unknown"));
    FT_CHECK(json_is_null(json_get(row, "landing_steer")));
    FT_CHECK(!json_get_bool(json_get(row, "landing_steer_complete")));
    json_free(&land);
    zcl_fmc_tasks_free(&v);
    return 0;
}

static int ft_landing_steer_partial(void)
{
    struct json_value land = ft_parse("{\"queued\":[{\"seq\":390,"
        "\"attempt\":2,\"tip\":\"" FT_HEAD "\",\"state\":\"queued\"}],"
        "\"outcomes\":[],\"steer\":{\"candidate\":\"" FT_HEAD "\",\"seq\":390}}");
    struct zcl_fmc_tasks v;
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_land(&v, &land, NULL, 1000, 1000));
    const struct json_value *row = json_at(&v.rows, 0);
    const struct json_value *steer = json_get(row, "landing_steer");
    FT_CHECK(ft_is(row, "landing_steer_link", "exact"));
    FT_CHECK(!json_get_bool(json_get(row, "landing_steer_complete")));
    FT_CHECK(steer && steer->type == JSON_OBJ);
    FT_CHECK(json_is_null(json_get(steer, "owner")));
    FT_CHECK(json_is_null(json_get(steer, "remote_state")));
    FT_CHECK(json_is_null(json_get(steer, "incident")));
    json_free(&land);
    zcl_fmc_tasks_free(&v);
    return 0;
}

static int ft_landing_steer_cases(void)
{
    struct zcl_fmc_tasks v;
    struct json_value land = ft_parse("{\"queued\":["
        "{\"seq\":390,\"attempt\":2,\"tip\":\"" FT_HEAD "\",\"state\":\"queued\"},"
        "{\"seq\":391,\"attempt\":1,\"tip\":\"" FT_OLD "\",\"state\":\"queued\"}],"
        "\"outcomes\":[],\"incident\":\"drain_absent\",\"steer\":{"
        "\"candidate\":\"" FT_HEAD "\",\"seq\":390,\"phase\":\"queued\","
        "\"owner\":\"unclaimed\",\"lease\":\"none\",\"proof_state\":\"not_requested\","
        "\"receiver_driver\":\"no_active_drain timer_unit=absent\","
        "\"first_missing_transition\":\"claim\","
        "\"wake_command\":\"z23 dev land step\","
        "\"remote_state\":\"cached:" FT_BASE "\"}}");
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_land(&v, &land, NULL, 1000, 1000));
    const struct json_value *row = ft_task(&v, FT_HEAD);
    const struct json_value *steer = json_get(row, "landing_steer");
    FT_CHECK(ft_is(row, "landing_steer_link", "exact"));
    FT_CHECK(json_get_bool(json_get(row, "landing_steer_complete")));
    FT_CHECK(steer && steer->type == JSON_OBJ);
    FT_CHECK(ft_is(steer, "owner", "unclaimed"));
    FT_CHECK(ft_is(steer, "first_missing_transition", "claim"));
    FT_CHECK(ft_is(steer, "receiver_driver", "no_active_drain timer_unit=absent"));
    FT_CHECK(ft_is(steer, "wake_command", "z23 dev land step"));
    FT_CHECK(ft_is(steer, "remote_state", "cached:" FT_BASE));
    FT_CHECK(ft_is(steer, "remote_state_basis", "submitter_cached_origin_main_not_fresh_acceptance"));
    FT_CHECK(ft_is(steer, "incident", "drain_absent"));
    FT_CHECK(json_is_null(json_get(row, "owner")));
    row = ft_task(&v, FT_OLD);
    FT_CHECK(ft_is(row, "landing_steer_link", "unknown"));
    FT_CHECK(json_is_null(json_get(row, "landing_steer")));
    json_free(&land);
    zcl_fmc_tasks_free(&v);

    land = ft_parse("{\"queued\":[],\"outcomes\":[],\"in_flight\":{"
        "\"seq\":390,\"attempt\":2,\"tip\":\"" FT_HEAD "\",\"local\":\"" FT_HEAD "\","
        "\"base\":\"" FT_BASE "\",\"phase\":\"prove\"},\"incident\":\"none\",\"steer\":{"
        "\"candidate\":\"" FT_HEAD "\",\"seq\":390,\"phase\":\"prove\","
        "\"owner\":\"pid:42\",\"lease\":\"step.lock:held\",\"proof_state\":\"running\","
        "\"receiver_driver\":\"beat_active\",\"first_missing_transition\":\"proof\","
        "\"wake_command\":\"busy\",\"remote_state\":\"unknown: gitdir unreadable\"}}");
    struct json_value proof = ft_parse("{\"local_commit\":\"" FT_HEAD "\","
        "\"remote_base\":\"" FT_BASE "\",\"status\":\"passed\",\"worker_id\":88}");
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_land(&v, &land, &proof, 1000, 1000));
    row = json_at(&v.rows, 0);
    steer = json_get(row, "landing_steer");
    FT_CHECK(json_get_int(json_get(row, "owner")) == 88);
    FT_CHECK(ft_is(steer, "owner", "pid:42"));
    FT_CHECK(ft_is(steer, "lease", "step.lock:held"));
    FT_CHECK(ft_is(steer, "incident", "none"));
    json_free(&proof);
    json_free(&land);
    zcl_fmc_tasks_free(&v);
    FT_CHECK(ft_landing_steer_mismatch(FT_HEAD, 391) == 0);
    FT_CHECK(ft_landing_steer_mismatch(FT_OLD, 390) == 0);
    FT_CHECK(ft_landing_steer_partial() == 0);
    return 0;
}

static int ft_missing_and_overflow(void)
{
    struct zcl_fmc_tasks v;
    struct json_value queue = ft_parse("{\"queued\":[{\"name\":\"broken\"}],\"running\":null}"), out = {0};
    zcl_fmc_tasks_init(&v);
    FT_CHECK(!zcl_fmc_tasks_queue(&v, &queue, 1000, 1000));
    FT_CHECK(ft_is(json_at(&v.rows, 0), "state", "unknown"));
    FT_CHECK(v.malformed > 0);
    json_free(&queue);
    zcl_fmc_tasks_free(&v);
    zcl_fmc_tasks_init(&v);
    queue = ft_parse("{\"queued\":[],\"running\":[]}");
    struct json_value *arr = (struct json_value *)json_get(&queue, "queued");
    for (size_t i = 0; i < ZCL_FMC_TASK_CAP + 3; i++) {
        char text[256];
        (void)snprintf(text, sizeof(text), "{\"seq\":%zu,\"attempt\":1,\"name\":\"task-%zu\",\"ready\":true,\"blocker\":null}", i + 1, i);
        struct json_value row = ft_parse(text);
        FT_CHECK(json_push_back(arr, &row)); json_free(&row);
    }
    FT_CHECK(zcl_fmc_tasks_queue(&v, &queue, 1000, 1000));
    FT_CHECK(json_size(&v.rows) == ZCL_FMC_TASK_CAP);
    FT_CHECK(v.dropped == 3);
    json_set_object(&out); FT_CHECK(zcl_fmc_tasks_emit(&v, &out));
    FT_CHECK(!json_get_bool(json_get(&out, "tasks_sources_complete")));
    FT_CHECK(!json_get_bool(json_get(&out, "tasks_inventory_complete")));
    json_free(&queue); json_free(&out); zcl_fmc_tasks_free(&v);
    return 0;
}

static int ft_reports_are_not_authority(void)
{
    struct zcl_fmc_tasks v;
    struct json_value queue = ft_parse("{\"queued\":[],\"running\":[],"
        "\"mail\":[{\"ref\":\"same-name\",\"state\":\"acknowledged\"},{\"ref\":\"same-name\",\"state\":\"completed\"}],"
        "\"board\":[{\"ref\":\"same-name\",\"receipt\":\"pointer-only\"}]} ");
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_queue(&v, &queue, 1000, 1000));
    FT_CHECK(json_size(&v.rows) == 0);
    struct json_value land = ft_parse("{\"queued\":[],\"outcomes\":[{\"seq\":1,\"attempt\":2,"
        "\"tip\":\"" FT_HEAD "\",\"ts\":\"2020-01-01T00:00:00Z\",\"state\":\"landed\","
        "\"remote_signature\":\"signature-bytes\",\"remote_tip\":\"" FT_HEAD "\","
        "\"remote_source\":\"independent-copy-reported\",\"acceptance_state\":\"unknown\",\"rc\":0}]} ");
    FT_CHECK(zcl_fmc_tasks_land(&v, &land, NULL, 1000, 1000));
    const struct json_value *row = json_at(&v.rows, 0);
    FT_CHECK(ft_is(row, "state", "unknown"));
    FT_CHECK(ft_is(row, "publication", "unknown"));
    FT_CHECK(json_get_bool(json_get(row, "reported_published")));
    FT_CHECK(json_get_bool(json_get(row, "historical")));
    struct json_value rendered = {0}; char screen[4096];
    json_set_object(&rendered); FT_CHECK(zcl_fmc_tasks_emit(&v, &rendered));
    zcl_fmc_tasks_screen(&rendered, screen, sizeof(screen));
    FT_CHECK(strstr(screen, "history unknown") != NULL);
    FT_CHECK(strstr(screen, "landed") != NULL);
    json_free(&rendered);
    FT_CHECK(ft_is(row, "source_ts", "2020-01-01T00:00:00Z"));
    FT_CHECK(ft_is(row, "review", "unknown"));
    json_free(&queue); json_free(&land); zcl_fmc_tasks_free(&v);
    return 0;
}

static int ft_screen_incomplete_cases(void)
{
    struct zcl_fmc_tasks v;
    struct json_value queue = ft_parse("{\"queued\":[],\"running\":[]}"), row = {0}, data = {0};
    char name[200], screen[4096];
    memset(name, 'x', sizeof(name)-1); name[sizeof(name)-1] = 0;
    json_set_object(&row); json_push_kv_int(&row, "seq", 1);
    json_push_kv_int(&row, "attempt", 1); json_push_kv_str(&row, "name", name);
    json_push_kv_bool(&row, "ready", true);
    struct json_value none = {0}; json_push_kv(&row, "blocker", &none);
    FT_CHECK(json_push_back((struct json_value *)json_get(&queue, "queued"), &row));
    zcl_fmc_tasks_init(&v);
    FT_CHECK(!zcl_fmc_tasks_queue(&v, &queue, 1000, 1000));
    json_set_object(&data); FT_CHECK(zcl_fmc_tasks_emit(&v, &data));
    struct json_value missing = ft_parse("[{\"source\":\"dev.land\",\"reason\":\"status_unavailable\"}]");
    json_push_kv(&data, "missing", &missing);
    zcl_fmc_tasks_screen(&data, screen, sizeof(screen));
    FT_CHECK(strstr(screen, "sources=incomplete") != NULL);
    FT_CHECK(strstr(screen, "unavailable dev.land: status_unavailable") != NULL);
    FT_CHECK(strstr(screen, "next=dev.agent.queue status") != NULL);
    FT_CHECK(strstr(screen, "--ref=") == NULL);
    json_free(&queue); json_free(&row); json_free(&data); json_free(&missing);
    zcl_fmc_tasks_free(&v);
    return 0;
}

static bool ft_hist_false(const struct json_value *row)
{
    const struct json_value *h = row ? json_get(row, "historical") : NULL;
    return h && h->type == JSON_BOOL && !json_get_bool(h);
}

static int ft_metadata_cases(void)
{
    struct zcl_fmc_tasks v;
    char before[8192], after[8192];
    struct json_value queue = ft_parse("{\"queued\":["
        "{\"seq\":11,\"name\":\"meta-q\",\"attempt\":2,\"ready\":true,\"blocker\":null,"
        "\"depends_on\":\"\",\"kind\":\"file\",\"group\":\"fleet_steer\","
        "\"path\":\"tools/command/native_fleet_steer_tasks.c\","
        "\"brief\":\"docs/work/meta-brief.md\",\"model\":\"model-strong\",\"priority\":1},"
        "{\"seq\":12,\"name\":\"meta-bare\",\"attempt\":1,\"ready\":true,\"blocker\":null}],"
        "\"running\":[{\"seq\":13,\"name\":\"meta-r\",\"attempt\":3,\"worker\":\"node-a\","
        "\"owner_liveness\":\"running\",\"age_s\":6,\"kind\":\"file\",\"group\":\"devagent_queue\","
        "\"path\":\"tools/command/native_devagent_queue.c\",\"brief\":\"docs/work/run-brief.md\","
        "\"model\":\"model-fast\",\"priority\":0,\"depends_on\":\"meta-q\"}]}");
    zcl_fmc_tasks_init(&v);
    (void)json_write(&queue, before, sizeof(before));
    FT_CHECK(zcl_fmc_tasks_queue(&v, &queue, 1000, 1000));
    const struct json_value *q = ft_task(&v, "meta-q");
    const struct json_value *r = ft_task(&v, "meta-r");
    const struct json_value *bare = ft_task(&v, "meta-bare");
    FT_CHECK(q && r && bare);
    /* Persisted queue metadata surfaces whole, under reference names that
     * never claim verification. */
    FT_CHECK(ft_is(q, "test_group", "fleet_steer"));
    FT_CHECK(ft_is(q, "work_path", "tools/command/native_fleet_steer_tasks.c"));
    FT_CHECK(ft_is(q, "brief_path_reference", "docs/work/meta-brief.md"));
    FT_CHECK(ft_is(q, "requested_model", "model-strong"));
    FT_CHECK(ft_is(q, "observed_model", "unknown"));
    FT_CHECK(json_get_int(json_get(q, "priority")) == 1);
    FT_CHECK(ft_is(q, "column", "queued"));
    FT_CHECK(ft_hist_false(q));
    FT_CHECK(ft_hist_false(r));
    FT_CHECK(ft_hist_false(bare));
    /* Queued-to-running: the same persisted metadata on the running row. */
    FT_CHECK(ft_is(r, "state", "executing"));
    FT_CHECK(ft_is(r, "column", "executing"));
    FT_CHECK(ft_is(r, "test_group", "devagent_queue"));
    FT_CHECK(ft_is(r, "work_path", "tools/command/native_devagent_queue.c"));
    FT_CHECK(ft_is(r, "brief_path_reference", "docs/work/run-brief.md"));
    FT_CHECK(ft_is(r, "requested_model", "model-fast"));
    FT_CHECK(ft_is(r, "observed_model", "unknown"));
    FT_CHECK(json_get_int(json_get(r, "priority")) == 0);
    /* Exact selectors are unchanged by the metadata additions. */
    const struct json_value *d = json_get(r, "detail");
    FT_CHECK(json_get_int(json_get(d, "seq")) == 13);
    FT_CHECK(json_get_int(json_get(d, "attempt")) == 3);
    FT_CHECK(ft_is(d, "type", "queue"));
    FT_CHECK(ft_is(d, "ref", "meta-r"));
    /* Absent metadata is an explicit null key, never "" or 0. */
    FT_CHECK(json_get(bare, "test_group") != NULL &&
        json_is_null(json_get(bare, "test_group")));
    FT_CHECK(json_get(bare, "work_path") != NULL &&
        json_is_null(json_get(bare, "work_path")));
    FT_CHECK(json_get(bare, "brief_path_reference") != NULL &&
        json_is_null(json_get(bare, "brief_path_reference")));
    FT_CHECK(json_get(bare, "requested_model") != NULL &&
        json_is_null(json_get(bare, "requested_model")));
    FT_CHECK(json_get(bare, "priority") != NULL &&
        json_is_null(json_get(bare, "priority")));
    FT_CHECK(ft_is(bare, "observed_model", "unknown"));
    FT_CHECK(ft_is(bare, "column", "queued"));
    /* The projection never mutates its input. */
    (void)json_write(&queue, after, sizeof(after));
    FT_CHECK(strcmp(before, after) == 0);
    json_free(&queue);
    zcl_fmc_tasks_free(&v);
    /* Historical rows keep priority unknown and derive the history column. */
    struct json_value land = ft_parse("{\"queued\":[],\"outcomes\":[{\"seq\":21,"
        "\"attempt\":2,\"tip\":\"" FT_HEAD "\",\"ts\":\"2020-01-01T00:00:00Z\","
        "\"state\":\"landed\",\"rc\":0}]}");
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_land(&v, &land, NULL, 1000, 1000));
    const struct json_value *h = json_at(&v.rows, 0);
    FT_CHECK(json_get_bool(json_get(h, "historical")));
    FT_CHECK(ft_is(h, "column", "history"));
    FT_CHECK(json_get(h, "priority") != NULL &&
        json_is_null(json_get(h, "priority")));
    FT_CHECK(ft_is(h, "observed_model", "unknown"));
    json_free(&land);
    zcl_fmc_tasks_free(&v);
    /* Budget trim survivors keep whole metadata and a per-row column, so a
     * client grouping only the final tasks[] is exact. */
    struct json_value big = ft_parse("{\"queued\":[],\"running\":[]}");
    struct json_value *arr = (struct json_value *)json_get(&big, "queued");
    for (size_t i = 0; i < ZCL_FMC_TASK_CAP + 2; i++) {
        char text[512];
        (void)snprintf(text, sizeof(text),
            "{\"seq\":%zu,\"attempt\":1,\"name\":\"m-%zu\",\"ready\":true,"
            "\"blocker\":null,\"kind\":\"file\",\"group\":\"fleet_steer\","
            "\"path\":\"tools/command/file-%zu.c\",\"brief\":\"docs/work/b-%zu.md\","
            "\"model\":\"m%zu\",\"priority\":%zu}", i + 1, i, i, i, i, i % 4);
        struct json_value row = ft_parse(text);
        FT_CHECK(json_push_back(arr, &row));
        json_free(&row);
    }
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_queue(&v, &big, 1000, 1000));
    FT_CHECK(json_size(&v.rows) == ZCL_FMC_TASK_CAP);
    FT_CHECK(v.dropped == 2);
    for (size_t i = 0; i < json_size(&v.rows); i++) {
        const struct json_value *row = json_at(&v.rows, i);
        const struct json_value *wp = json_get(row, "work_path");
        FT_CHECK(wp && wp->type == JSON_STR && json_get_str(wp)[0]);
        FT_CHECK(ft_is(row, "column", "queued"));
        FT_CHECK(json_get(row, "requested_model") != NULL);
        FT_CHECK(json_get(row, "priority") != NULL);
    }
    json_free(&big);
    zcl_fmc_tasks_free(&v);
    return 0;
}

static int ft_metadata_escape_cases(void)
{
    struct zcl_fmc_tasks v;
    char text[65536];
    /* Metadata needing JSON escapes must survive the projection and a
     * full emit/serialize/parse round-trip with every byte retained. */
    struct json_value queue = ft_parse("{\"queued\":["
        "{\"seq\":31,\"name\":\"meta-esc\",\"attempt\":1,\"ready\":true,\"blocker\":null,"
        "\"kind\":\"file\",\"group\":\"fleet\\\"steer\","
        "\"path\":\"tools\\\\command\\\\native.c\","
        "\"brief\":\"docs/work/br\\nief.md\",\"model\":\"mod\\tel\",\"priority\":2}],"
        "\"running\":[]}");
    char big[3900];
    memset(big, 'p', sizeof(big) - 3);
    big[sizeof(big) - 3] = '\\';
    big[sizeof(big) - 2] = '"';
    big[sizeof(big) - 1] = '\0';
    struct json_value row = {0}, none = {0};
    json_set_object(&row);
    json_push_kv_int(&row, "seq", 32);
    json_push_kv_int(&row, "attempt", 1);
    json_push_kv_str(&row, "name", "meta-big");
    json_push_kv_bool(&row, "ready", true);
    json_push_kv(&row, "blocker", &none);
    json_push_kv_str(&row, "kind", "file");
    json_push_kv_str(&row, "group", "fleet_steer");
    json_push_kv_str(&row, "path", big);
    json_push_kv_str(&row, "brief", big);
    json_push_kv_str(&row, "model", "m");
    json_push_kv_int(&row, "priority", 3);
    FT_CHECK(json_push_back((struct json_value *)json_get(&queue, "queued"), &row));
    json_free(&row);
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_queue(&v, &queue, 1000, 1000));
    const struct json_value *q = ft_task(&v, "meta-esc");
    FT_CHECK(q != NULL);
    FT_CHECK(ft_is(q, "test_group", "fleet\"steer"));
    FT_CHECK(ft_is(q, "work_path", "tools\\command\\native.c"));
    FT_CHECK(ft_is(q, "brief_path_reference", "docs/work/br\nief.md"));
    FT_CHECK(ft_is(q, "requested_model", "mod\tel"));
    FT_CHECK(json_get_int(json_get(q, "priority")) == 2);
    const struct json_value *b = ft_task(&v, "meta-big");
    FT_CHECK(b != NULL);
    FT_CHECK(ft_is(b, "work_path", big));
    FT_CHECK(ft_is(b, "brief_path_reference", big));
    /* The serialized projection reparses to the same retained values. */
    struct json_value out = {0}, reparsed = {0};
    json_set_object(&out);
    FT_CHECK(zcl_fmc_tasks_emit(&v, &out));
    FT_CHECK(json_write(&out, text, sizeof(text)) < sizeof(text));
    FT_CHECK(json_read(&reparsed, text, strlen(text)));
    const struct json_value *tasks = json_get(&reparsed, "tasks");
    FT_CHECK(tasks && tasks->type == JSON_ARR);
    bool esc_found = false, big_found = false;
    for (size_t i = 0; i < json_size(tasks); i++) {
        const struct json_value *t = json_at(tasks, i);
        if (ft_is(t, "ref", "meta-esc")) {
            esc_found = true;
            FT_CHECK(ft_is(t, "test_group", "fleet\"steer"));
            FT_CHECK(ft_is(t, "work_path", "tools\\command\\native.c"));
            FT_CHECK(ft_is(t, "brief_path_reference", "docs/work/br\nief.md"));
            FT_CHECK(ft_is(t, "requested_model", "mod\tel"));
        }
        if (ft_is(t, "ref", "meta-big")) {
            big_found = true;
            FT_CHECK(ft_is(t, "work_path", big));
            FT_CHECK(ft_is(t, "brief_path_reference", big));
        }
    }
    FT_CHECK(esc_found && big_found);
    json_free(&queue);
    json_free(&out);
    json_free(&reparsed);
    zcl_fmc_tasks_free(&v);
    return 0;
}

/* The persisted metadata fields one projected meta-oom row must keep
 * whole: every field present in the fixture lands with its exact value. */
static bool ft_queue_meta_ok(const struct zcl_fmc_tasks *v)
{
    const struct json_value *q = ft_task(v, "meta-oom");
    return q && v->malformed == 0 &&
        ft_is(q, "test_group", "fleet_steer") &&
        ft_is(q, "work_path", "tools/command/native_fleet_steer_tasks.c") &&
        ft_is(q, "brief_path_reference", "docs/work/meta-brief.md") &&
        ft_is(q, "requested_model", "model-strong") &&
        json_get_int(json_get(q, "priority")) == 1;
}

/* One armed ingestion of the parsed fixture: *hit reports whether the
 * armed failure fired inside zcl_fmc_tasks_queue. Every fire must drop the
 * row malformed rather than ship present fields read as null; a run that
 * never reaches the nth consult keeps every metadata field whole. The hook
 * is cleared before returning either way. */
static bool ft_queue_oom_run(const char *fixture, const char *label,
                             unsigned nth, bool *hit)
{
    struct zcl_fmc_tasks v;
    struct json_value queue = ft_parse(fixture);
    bool ok;
    zcl_fmc_tasks_init(&v);
    zcl_alloc_fault_fail_nth(label, nth);
    ok = zcl_fmc_tasks_queue(&v, &queue, 1000, 1000);
    *hit = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    if (*hit)
        ok = !ok && v.observed == 1 && v.malformed == 1 &&
             json_size(&v.rows) == 0 && ft_task(&v, "meta-oom") == NULL;
    else
        ok = ok && ft_queue_meta_ok(&v);
    json_free(&queue);
    zcl_fmc_tasks_free(&v);
    return ok;
}

/* One armed emission of the built projection: every fired consult must
 * refuse the emit; a run that never reaches the nth consult lands the
 * whole one-row tasks array. The hook is cleared before returning. */
static bool ft_emit_oom_run(const struct zcl_fmc_tasks *v, const char *label,
                            unsigned nth, bool *hit)
{
    struct json_value target = {0};
    const struct json_value *tasks;
    bool ok;
    json_set_object(&target);
    zcl_alloc_fault_fail_nth(label, nth);
    ok = zcl_fmc_tasks_emit(v, &target);
    *hit = zcl_alloc_fault_armed_label() == NULL;
    zcl_alloc_fault_clear();
    if (*hit)
        ok = !ok;
    else {
        tasks = json_get(&target, "tasks");
        ok = ok && tasks && tasks->type == JSON_ARR && json_size(tasks) == 1;
    }
    json_free(&target);
    return ok;
}

static int ft_metadata_oom_cases(void)
{
    /* Loop each checked-copy seam label until an arming does not fire: the
     * verified count of live consults, with no assumed ordinals. hits > 0
     * per label proves the seam is really exercised on this path. */
    static const char *labels[] = {
        "json_set_str", "json_copy_str", "json_copy_key",
        "json_push_kv_key", "json_copy_children", "json_copy_keys"
    };
    const char *fixture = "{\"queued\":["
        "{\"seq\":41,\"name\":\"meta-oom\",\"attempt\":1,\"ready\":true,\"blocker\":null,"
        "\"depends_on\":\"\",\"kind\":\"file\",\"group\":\"fleet_steer\","
        "\"path\":\"tools/command/native_fleet_steer_tasks.c\","
        "\"brief\":\"docs/work/meta-brief.md\",\"model\":\"model-strong\",\"priority\":1}],"
        "\"running\":[]}";
    struct zcl_fmc_tasks v;
    struct json_value queue;
    size_t site;
    for (site = 0; site < sizeof(labels) / sizeof(labels[0]); site++) {
        unsigned hits = 0, nth;
        bool hit = true;
        for (nth = 1; hit && nth < 256; nth++) {
            FT_CHECK(ft_queue_oom_run(fixture, labels[site], nth, &hit));
            hits += hit ? 1 : 0;
        }
        FT_CHECK(!hit);
        FT_CHECK(hits > 0);
    }
    queue = ft_parse(fixture);
    zcl_fmc_tasks_init(&v);
    FT_CHECK(zcl_fmc_tasks_queue(&v, &queue, 1000, 1000));
    FT_CHECK(ft_queue_meta_ok(&v));
    json_free(&queue);
    for (site = 0; site < sizeof(labels) / sizeof(labels[0]); site++) {
        unsigned hits = 0, nth;
        bool hit = true;
        for (nth = 1; hit && nth < 256; nth++) {
            FT_CHECK(ft_emit_oom_run(&v, labels[site], nth, &hit));
            hits += hit ? 1 : 0;
        }
        FT_CHECK(!hit);
        FT_CHECK(hits > 0);
    }
    zcl_fmc_tasks_free(&v);
    return 0;
}

int fmx_task_projection_checks(void);
int fmx_task_projection_checks(void)
{
    int failures = ft_queue_cases() + ft_landing_cases() + ft_landing_steer_cases() + ft_missing_and_overflow() + ft_reports_are_not_authority() + ft_screen_incomplete_cases() + ft_metadata_cases() + ft_metadata_escape_cases() + ft_metadata_oom_cases();
    if (!failures) printf("fleet task projection: queue, liveness, freshness, exact proof and landing steering, review/publication separation, metadata and bounds passed\n");
    return failures;
}
