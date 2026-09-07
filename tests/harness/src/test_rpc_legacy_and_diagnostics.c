/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * rpc scenario checks: legacy balance-observer parsing, JSON value
 * read/write/roundtrip, the diagnostics registry catalog, and dumpstate
 * subsystem checks.
 *
 * Split out of test_rpc.c (which keeps the includes and the group entry
 * point) so no family member crosses the 1,500-line ceiling. Each
 * sibling's fixtures stay private to its own scenarios. */

#include "test/test_core.h"
#include "keys/key.h"
#include "storage/dbwrapper.h"
#include "core/core_io.h"
#include "rpc/async_rpc_queue.h"
#include "validation/main_state.h"
#include "controllers/diagnostics_controller.h"
#include "controllers/diagnostics_internal.h"
#include "controllers/rpc_client.h"
#include "platform/clock.h"
#include "rpc/client.h"
#include "rpc/httpserver.h"
#include "rpc/legacy_rpc_client.h"
#include "services/legacy_balance_observer.h"
#include "util/ere_match.h"
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "platform/socket_compat.h"
#include <unistd.h>
#include "test/test_rpc_priv.h"


static struct block_index *rpc_test_insert_bi(struct main_state *ms,
                                              struct uint256 *hash,
                                              int height,
                                              struct block_index *prev)
{
    memset(hash, 0, sizeof(*hash));
    hash->data[0] = (uint8_t)(height & 0xff);
    hash->data[1] = 0x52;
    struct block_index *bi =
        chainstate_insert_block_index((struct chainstate *)ms, hash);
    if (!bi)
        return NULL;
    bi->nHeight = height;
    bi->pprev = prev;
    bi->nStatus = BLOCK_VALID_HEADER;
    arith_uint256_set_u64(&bi->nChainWork, (uint64_t)height + 1u);
    return bi;
}

static uint32_t balance_observer_seen_timeout;
static bool balance_observer_call_seen;

static bool balance_observer_fake_call(const char *body_json,
                                       uint32_t timeout_ms,
                                       char **out_resp,
                                       char *err, size_t err_sz)
{
    static const char response[] =
        "HTTP/1.1 200 OK\r\n\r\n"
        "{\"result\":{\"transparent\":\"0.00999662\","
        "\"private\":\"0.01970000\",\"total\":\"0.02969662\"},"
        "\"error\":null,\"id\":\"z23-holdings\"}";
    balance_observer_call_seen = body_json &&
        strstr(body_json, "\"method\":\"z_gettotalbalance\"") != NULL;
    balance_observer_seen_timeout = timeout_ms;
    *out_resp = strdup(response);
    if (!*out_resp && err && err_sz)
        (void)snprintf(err, err_sz, "fixture allocation failed");
    return *out_resp != NULL;
}


int check_rpc_legacy_balance_observer_parse(void)
{
    int failures = 0;

    printf("legacy balance observer exact decimals... ");
    {
        static const char raw[] =
            "HTTP/1.1 200 OK\r\n\r\n"
            "{\"result\":{\"transparent\":\"0.00999662\","
            "\"private\":\"0.01970000\",\"total\":\"0.02969662\"},"
            "\"error\":null}";
        struct legacy_balance_observation observed;
        struct zcl_result r = legacy_balance_observation_parse(raw, &observed);
        bool ok = r.ok && observed.complete &&
            observed.source == LEGACY_BALANCE_SOURCE_ZCLASSICD &&
            observed.transparent_zat == 999662 &&
            observed.shielded_zat == 1970000 &&
            observed.total_zat == 2969662;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("legacy balance observer rejects imprecise or inconsistent data... ");
    {
        static const char imprecise[] =
            "HTTP/1.1 200 OK\r\n\r\n"
            "{\"result\":{\"transparent\":\"0.000000001\","
            "\"private\":\"0\",\"total\":\"0.000000001\"},"
            "\"error\":null}";
        static const char inconsistent[] =
            "HTTP/1.1 200 OK\r\n\r\n"
            "{\"result\":{\"transparent\":\"1.00000000\","
            "\"private\":\"2.00000000\",\"total\":\"4.00000000\"},"
            "\"error\":null}";
        static const char overflow[] =
            "HTTP/1.1 200 OK\r\n\r\n"
            "{\"result\":{\"transparent\":\"92233720369\","
            "\"private\":\"0\",\"total\":\"92233720369\"},"
            "\"error\":null}";
        static const char rpc_error[] =
            "HTTP/1.1 500 Error\r\n\r\n"
            "{\"result\":null,\"error\":{\"code\":-1,"
            "\"message\":\"wallet unavailable\"}}";
        struct legacy_balance_observation observed;
        struct zcl_result a = legacy_balance_observation_parse(
            imprecise, &observed);
        struct zcl_result b = legacy_balance_observation_parse(
            inconsistent, &observed);
        struct zcl_result c = legacy_balance_observation_parse(
            overflow, &observed);
        struct zcl_result d = legacy_balance_observation_parse(
            rpc_error, &observed);
        struct zcl_result e = legacy_balance_observation_parse(
            "HTTP/1.1 200 OK\r\n\r\n{", &observed);
        struct zcl_result f = legacy_balance_observation_parse(NULL,
                                                               &observed);
        bool ok = !a.ok && !b.ok && !c.ok && !d.ok && !e.ok && !f.ok &&
            !observed.complete;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }


    return failures;
}

int check_rpc_legacy_balance_observer_timeout(void)
{
    int failures = 0;

    printf("legacy balance observer enforces 250 ms transport budget... ");
    {
        struct legacy_balance_observation observed;
        balance_observer_call_seen = false;
        balance_observer_seen_timeout = 0;
        struct zcl_result r = legacy_balance_observe_with_call(
            balance_observer_fake_call,
            LEGACY_BALANCE_OBSERVER_TIMEOUT_MS, &observed);
        bool ok = r.ok && observed.complete && balance_observer_call_seen &&
            balance_observer_seen_timeout == 250u &&
            observed.observed_at_unix > 0;
        balance_observer_call_seen = false;
        struct zcl_result refused = legacy_balance_observe_with_call(
            balance_observer_fake_call, 251u, &observed);
        ok = ok && !refused.ok && !balance_observer_call_seen;
        legacy_balance_observer_set_test_call(balance_observer_fake_call);
        struct zcl_result hooked = legacy_balance_observe(&observed);
        legacy_balance_observer_set_test_call(NULL);
        ok = ok && hooked.ok && observed.complete;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int check_rpc_json_null_bool_int_str(void)
{
    int failures = 0;

    printf("json null/bool/int/str... ");
    {
        struct json_value v;
        json_init(&v);
        bool ok = json_is_null(&v);

        json_set_bool(&v, true);
        ok = ok && json_get_bool(&v);

        json_set_int(&v, 42);
        ok = ok && json_get_int(&v) == 42;

        json_set_str(&v, "hello");
        ok = ok && strcmp(json_get_str(&v), "hello") == 0;

        json_set_real(&v, 3.14);
        ok = ok && json_get_real(&v) > 3.13 && json_get_real(&v) < 3.15;

        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int check_rpc_json_object_write(void)
{
    int failures = 0;

    printf("json object write... ");
    {
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        json_push_kv_str(&obj, "method", "getinfo");
        json_push_kv_int(&obj, "id", 1);

        char buf[256];
        json_write(&obj, buf, sizeof(buf));
        bool ok = strstr(buf, "\"method\":\"getinfo\"") != NULL;
        ok = ok && strstr(buf, "\"id\":1") != NULL;

        json_free(&obj);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int check_rpc_json_array_write(void)
{
    int failures = 0;

    printf("json array write... ");
    {
        struct json_value arr;
        json_init(&arr);
        json_set_array(&arr);
        struct json_value v;
        json_init(&v);
        json_set_int(&v, 10);
        json_push_back(&arr, &v);
        json_set_int(&v, 20);
        json_push_back(&arr, &v);
        json_free(&v);

        char buf[64];
        json_write(&arr, buf, sizeof(buf));
        bool ok = strcmp(buf, "[10,20]") == 0;

        json_free(&arr);
        if (ok) printf("OK\n"); else { printf("FAIL (got: %s)\n", buf); failures++; }
    }

    return failures;
}

int check_rpc_json_read_object(void)
{
    int failures = 0;

    printf("json read object... ");
    {
        const char *input = "{\"name\":\"zcl\",\"port\":8233,\"active\":true}";
        struct json_value v;
        bool ok = json_read(&v, input, strlen(input));
        ok = ok && v.type == JSON_OBJ;
        ok = ok && json_size(&v) == 3;

        const struct json_value *name = json_get(&v, "name");
        ok = ok && name && strcmp(json_get_str(name), "zcl") == 0;

        const struct json_value *port = json_get(&v, "port");
        ok = ok && port && json_get_int(port) == 8233;

        const struct json_value *active = json_get(&v, "active");
        ok = ok && active && json_get_bool(active);

        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }


    return failures;
}

int check_rpc_json_read_array(void)
{
    int failures = 0;

    printf("json read array... ");
    {
        const char *input = "[1,\"two\",null,false]";
        struct json_value v;
        bool ok = json_read(&v, input, strlen(input));
        ok = ok && v.type == JSON_ARR;
        ok = ok && json_size(&v) == 4;
        ok = ok && json_get_int(json_at(&v, 0)) == 1;
        ok = ok && strcmp(json_get_str(json_at(&v, 1)), "two") == 0;
        ok = ok && json_is_null(json_at(&v, 2));
        ok = ok && !json_get_bool(json_at(&v, 3));

        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int check_rpc_json_roundtrip(void)
{
    int failures = 0;

    printf("json roundtrip... ");
    {
        struct json_value obj;
        json_init(&obj);
        json_set_object(&obj);
        json_push_kv_str(&obj, "result", "ok");
        json_push_kv_int(&obj, "code", 200);

        char buf[256];
        size_t n = json_write(&obj, buf, sizeof(buf));

        struct json_value parsed;
        bool ok = json_read(&parsed, buf, n);
        ok = ok && parsed.type == JSON_OBJ;
        const struct json_value *r = json_get(&parsed, "result");
        ok = ok && r && strcmp(json_get_str(r), "ok") == 0;
        const struct json_value *c = json_get(&parsed, "code");
        ok = ok && c && json_get_int(c) == 200;

        json_free(&obj);
        json_free(&parsed);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int check_rpc_json_rpc_request_and_error(void)
{
    int failures = 0;

    printf("json_rpc_request... ");
    {
        struct json_value params, id;
        json_init(&params);
        json_set_array(&params);
        json_init(&id);
        json_set_int(&id, 1);

        char buf[512];
        json_rpc_request("getinfo", &params, &id, buf, sizeof(buf));
        bool ok = strstr(buf, "\"method\":\"getinfo\"") != NULL;
        ok = ok && strstr(buf, "\"id\":1") != NULL;

        json_free(&params);
        json_free(&id);
        if (ok) printf("OK\n"); else { printf("FAIL (got: %s)\n", buf); failures++; }
    }

    printf("json_rpc_error... ");
    {
        struct json_value err;
        json_rpc_error(&err, RPC_METHOD_NOT_FOUND, "Method not found");
        const struct json_value *code = json_get(&err, "code");
        const struct json_value *msg = json_get(&err, "message");
        bool ok = code && json_get_int(code) == RPC_METHOD_NOT_FOUND;
        ok = ok && msg && strcmp(json_get_str(msg), "Method not found") == 0;
        json_free(&err);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }


    return failures;
}

static bool check_rpc_diagnostics_entry_core(
    const struct diagnostics_dump_entry *e,
    size_t i, size_t count,
    const char *csv, int csv_len, size_t *csv_pos_p)
{
    bool ok = true;
    size_t csv_pos = *csv_pos_p;
            const char *required[] = {
                e->name, e->desc, e->state_class, e->owner_shape,
                e->owner_file, e->freshness, e->cost, e->primary_test,
            };
            ok = ok && e->fn != NULL;
            for (size_t j = 0; j < sizeof(required) / sizeof(required[0]); j++)
                ok = ok && required[j] && required[j][0];
            for (size_t j = i + 1; j < count; j++) {
                const struct diagnostics_dump_entry *other =
                    diagnostics_dumper_at(j);
                ok = ok && other && strcmp(e->name, other->name) != 0;
            }

            if (i > 0) {
                if (csv_pos >= (size_t)csv_len || csv[csv_pos] != ',')
                    ok = false;
                else
                    csv_pos++;
            }
            size_t name_len = strlen(e->name);
            if (csv_pos + name_len > (size_t)csv_len ||
                strncmp(csv + csv_pos, e->name, name_len) != 0)
                ok = false;
            csv_pos += name_len;
    *csv_pos_p = csv_pos;
    return ok;
}

static bool check_rpc_diagnostics_entry_metadata(
    const struct diagnostics_dump_entry *e,
    const struct json_value *item)
{
    bool ok = true;
            struct {
                const char *key;
                const char *value;
            } metadata[] = {
                { "name", e->name },
                { "subsystem", e->name },
                { "description", e->desc },
                { "state_class", e->state_class },
                { "owner_shape", e->owner_shape },
                { "owner_file", e->owner_file },
                { "freshness", e->freshness },
                { "cost", e->cost },
            };
            for (size_t j = 0; j < sizeof(metadata) / sizeof(metadata[0]); j++)
                ok = ok && strcmp(json_get_str(json_get(item, metadata[j].key)),
                                  metadata[j].value) == 0;

            bool accepts_key = e->key_hint && e->key_hint[0];
            ok = ok && json_get_bool(json_get(item, "accepts_key")) ==
                           accepts_key;
            ok = ok && strcmp(json_get_str(json_get(item, "key_hint")),
                              accepts_key ? e->key_hint : "") == 0;
    return ok;
}

static bool check_rpc_diagnostics_entry_keys(
    const struct diagnostics_dump_entry *e,
    const struct json_value *item)
{
    bool ok = true;
            const struct json_value *examples = json_get(item, "key_examples");
            size_t example_count = (e->key_example_1 ? 1u : 0u) +
                                   (e->key_example_2 ? 1u : 0u);
            ok = ok && examples && json_size(examples) == example_count;
            if (e->key_example_1)
                ok = ok && strcmp(json_get_str(json_at(examples, 0)),
                                  e->key_example_1) == 0;
            if (e->key_example_2)
                ok = ok && strcmp(json_get_str(json_at(examples, 1)),
                                  e->key_example_2) == 0;
            const struct json_value *tests = json_get(item, "tests");
            ok = ok && tests && json_size(tests) == 2 &&
                 strcmp(json_get_str(json_at(tests, 1)), e->primary_test) == 0;
            const struct json_value *drilldowns = json_get(item, "drilldowns");
            ok = ok && drilldowns && json_size(drilldowns) ==
                           (e->include_supervisor_drilldown ? 2u : 1u);
    return ok;
}

static bool check_rpc_diagnostics_catalog_entries(
    size_t count, const struct json_value *subsystems,
    const char *csv, int csv_len)
{
    bool ok = true;
    size_t csv_pos = 0;
        for (size_t i = 0; i < count; i++) {
            const struct diagnostics_dump_entry *e = diagnostics_dumper_at(i);
            const struct json_value *item = json_at(subsystems, i);
            if (!e || !item) {
                ok = false;
                continue;
            }
            ok = ok && check_rpc_diagnostics_entry_core(
                e, i, count, csv, csv_len, &csv_pos);
            ok = ok && check_rpc_diagnostics_entry_metadata(e, item);
            ok = ok && check_rpc_diagnostics_entry_keys(e, item);
        }
        ok = ok && csv[csv_pos] == '\0' && diagnostics_dumper_at(count) == NULL;
    return ok;
}

int check_rpc_diagnostics_registry_catalog(void)
{
    int failures = 0;

    printf("diagnostics registry is the complete catalog manifest... ");
    {
        /* diagnostics_dumpers_def_row_count() (diagnostics_internal.h) is a
         * SECOND array built by re-including diagnostics_dumpers.def with a
         * dummy element type; g_dumpers[] (behind diagnostics_dumper_count())
         * is a separately-compiled array over the SAME .def file. Comparing
         * the two is a real cross-check between independent derivations of
         * one source of truth, not count==count. The >0 floor guards against
         * both collapsing to zero together (e.g. a busted include). */
        const size_t count = diagnostics_dumper_count();
        const size_t def_count = diagnostics_dumpers_def_row_count();
        char csv[4096];
        int csv_len = diagnostics_subsystems_csv(csv, sizeof(csv));
        bool ok = count > 0 && count == def_count &&
                  csv_len > 0 && (size_t)csv_len < sizeof(csv);

        struct json_value params, catalog;
        json_init(&params);
        json_set_array(&params);
        json_init(&catalog);
        ok = ok && diag_rpc_statecatalog(&params, false, &catalog);
        const struct json_value *subsystems = json_get(&catalog, "subsystems");
        ok = ok && json_get_int(json_get(&catalog, "count")) ==
                       (int64_t)count;
        ok = ok && subsystems && subsystems->type == JSON_ARR &&
             json_size(subsystems) == count;

        ok = ok && check_rpc_diagnostics_catalog_entries(
            count, subsystems, csv, csv_len);
        json_free(&catalog);
        json_free(&params);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int check_rpc_dumpstate_unknown_subsystem(void)
{
    int failures = 0;

    printf("dumpstate unknown subsystem lists registry... ");
    {
        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value sub;
        json_init(&sub);
        json_set_str(&sub, "missing_test_subsystem");
        bool ok = json_push_back(&params, &sub);
        json_free(&sub);

        struct json_value result;
        json_init(&result);
        ok = ok && !diag_rpc_dumpstate(&params, false, &result);
        const char *msg = json_get_str(&result);
        ok = ok && msg && strstr(msg, "unknown subsystem") != NULL;
        ok = ok && strstr(msg, "known_subsystems=") != NULL;
        ok = ok && strstr(msg, "reducer_frontier") != NULL;

        json_free(&params);
        json_free(&result);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int check_rpc_dumpstate_help(void)
{
    int failures = 0;

    printf("dumpstate help lists registry... ");
    {
        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value result;
        json_init(&result);

        bool ok = diag_rpc_dumpstate(&params, true, &result);
        const char *msg = json_get_str(&result);
        ok = ok && msg && strstr(msg, "Known subsystems:") != NULL;
        ok = ok && strstr(msg, "reducer_frontier") != NULL;
        ok = ok && strstr(msg, "block_index") != NULL;
        ok = ok && strstr(msg, "block_intake") != NULL;

        json_free(&params);
        json_free(&result);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static bool check_rpc_dumpstate_block_intake_fields(
    const struct json_value *result)
{
        const struct json_value *state = json_get(result, "state");
        bool ok = state && state->type == JSON_OBJ;
        ok = ok && json_get(state, "running") != NULL;
        ok = ok && json_get(state, "current_depth") != NULL;
        ok = ok && json_get(state, "capacity") != NULL;
        ok = ok && json_get(state, "saturated") != NULL;
        ok = ok && json_get(state, "enqueued") != NULL;
        ok = ok && json_get(state, "processed") != NULL;
        ok = ok && json_get(state, "dropped") != NULL;
        return ok;
}

int check_rpc_dumpstate_block_intake(void)
{
    int failures = 0;

    printf("dumpstate block_intake exposes queue telemetry... ");
    {
        struct json_value params;
        json_init(&params);
        json_set_array(&params);

        struct json_value sub;
        json_init(&sub);
        json_set_str(&sub, "block_intake");
        bool ok = json_push_back(&params, &sub);
        json_free(&sub);

        struct json_value result;
        json_init(&result);
        ok = ok && diag_rpc_dumpstate(&params, false, &result);
        ok = ok && check_rpc_dumpstate_block_intake_fields(&result);

        json_free(&params);
        json_free(&result);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

static bool check_rpc_dumpstate_block_index_state(bool ok,
    const struct json_value *result)
{
        const struct json_value *state = json_get(result, "state");
        ok = ok && state && state->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(state, "found"));
        ok = ok && json_get_int(json_get(state, "nHeight")) == 1;
        ok = ok && strcmp(json_get_str(json_get(state, "lookup_source")),
                          "best_header_ancestor") == 0;
        ok = ok && !json_get_bool(json_get(state, "on_active_chain"));
        return ok;
}

int check_rpc_dumpstate_block_index(void)
{
    int failures = 0;

    printf("dumpstate block_index resolves best-header height... ");
    {
        struct main_state ms;
        struct uint256 h0, h1;
        main_state_init(&ms);
        struct block_index *b0 = rpc_test_insert_bi(&ms, &h0, 0, NULL);
        struct block_index *b1 = rpc_test_insert_bi(&ms, &h1, 1, b0);
        bool ok = b0 && b1 &&
                  active_chain_move_window_tip(&ms.chain_active, b0);
        if (ok)
            ms.pindex_best_header = b1;

        diagnostics_controller_set_state(&ms, "");
        struct json_value params;
        json_init(&params);
        json_set_array(&params);
        struct json_value v;
        json_init(&v);
        json_set_str(&v, "block_index");
        ok = ok && json_push_back(&params, &v);
        json_set_str(&v, "1");
        ok = ok && json_push_back(&params, &v);
        json_free(&v);

        struct json_value result;
        json_init(&result);
        ok = ok && diag_rpc_dumpstate(&params, false, &result);
        ok = check_rpc_dumpstate_block_index_state(ok, &result);

        json_free(&params);
        json_free(&result);
        diagnostics_controller_set_state(NULL, "");
        main_state_free(&ms);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

