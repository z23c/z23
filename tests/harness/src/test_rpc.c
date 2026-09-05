/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

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

/* Every on-disk and on-network resource this group touches must be unique to
 * this process. Two copies of the suite run concurrently (and each worktree
 * runs its own), so a fixed /tmp path or a fixed port is a cross-run
 * collision: a LevelDB LOCK held by the other run, or an EADDRINUSE from its
 * listener, fails a test that has nothing wrong with it. */
static void rpc_test_tmpdir(char *buf, size_t n, const char *tag)
{
    test_make_tmpdir(buf, n, "rpc", tag);
}

/* Ask the kernel for a free loopback port, then release it. */
static uint16_t rpc_test_free_port(void)
{
    platform_socket_t fd = platform_socket_open(AF_INET, SOCK_STREAM, 0,
                                                true, false);
    if (fd == PLATFORM_SOCKET_INVALID) return 0;
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);
    uint16_t port = 0;
    if (platform_socket_bind(fd, (struct sockaddr *)&addr,
                             sizeof(addr)) == 0) {
        size_t len = sizeof(addr);
        if (platform_socket_local_address(fd, (struct sockaddr *)&addr,
                                          &len) == 0)
            port = ntohs(addr.sin_port);
    }
    platform_socket_close(fd);
    return port;
}

struct rpc_fake_clock {
    int64_t wall_ms;
};

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

static int64_t rpc_fake_now_mono(void *self)
{
    (void)self;
    return 0;
}

static int64_t rpc_fake_now_wall(void *self)
{
    struct rpc_fake_clock *c = (struct rpc_fake_clock *)self;
    return c ? c->wall_ms : 0;
}

static bool rpc_test_file_contains(FILE *f, const char *needle)
{
    if (!needle)
        return true;
    if (!f || fflush(f) != 0 || fseek(f, 0, SEEK_SET) != 0)
        return false;
    char buf[1024];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

static bool rpc_test_cli_print_case(const char *body, bool want_ok,
                                    const char *out_needle,
                                    const char *err_needle)
{
    FILE *out = tmpfile();
    FILE *err = tmpfile();
    if (!out || !err) {
        if (out) fclose(out);
        if (err) fclose(err);
        return false;
    }
    int rc = rpc_cli_print_json_result(body, out, err);
    bool ok = want_ok ? rc == 0 : rc != 0;
    ok = ok && rpc_test_file_contains(out, out_needle);
    ok = ok && rpc_test_file_contains(err, err_needle);
    fclose(out);
    fclose(err);
    return ok;
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

int test_rpc(void) {
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
        size_t csv_pos = 0;
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

        for (size_t i = 0; i < count; i++) {
            const struct diagnostics_dump_entry *e = diagnostics_dumper_at(i);
            const struct json_value *item = json_at(subsystems, i);
            if (!e || !item) {
                ok = false;
                continue;
            }
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
        }
        ok = ok && csv[csv_pos] == '\0' && diagnostics_dumper_at(count) == NULL;
        json_free(&catalog);
        json_free(&params);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

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
        const struct json_value *state = json_get(&result, "state");
        ok = ok && state && state->type == JSON_OBJ;
        ok = ok && json_get(state, "running") != NULL;
        ok = ok && json_get(state, "current_depth") != NULL;
        ok = ok && json_get(state, "capacity") != NULL;
        ok = ok && json_get(state, "saturated") != NULL;
        ok = ok && json_get(state, "enqueued") != NULL;
        ok = ok && json_get(state, "processed") != NULL;
        ok = ok && json_get(state, "dropped") != NULL;

        json_free(&params);
        json_free(&result);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

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
        const struct json_value *state = json_get(&result, "state");
        ok = ok && state && state->type == JSON_OBJ;
        ok = ok && json_get_bool(json_get(state, "found"));
        ok = ok && json_get_int(json_get(state, "nHeight")) == 1;
        ok = ok && strcmp(json_get_str(json_get(state, "lookup_source")),
                          "best_header_ancestor") == 0;
        ok = ok && !json_get_bool(json_get(state, "on_active_chain"));

        json_free(&params);
        json_free(&result);
        diagnostics_controller_set_state(NULL, "");
        main_state_free(&ms);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("legacy_rpc parse scalar results... ");
    {
        const char *sraw =
            "HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n"
            "{\"result\":\"abc123\",\"error\":null,\"id\":1}";
        const char *iraw =
            "HTTP/1.1 200 OK\r\nContent-Length: 34\r\n\r\n"
            "{\"result\":8232,\"error\":null,\"id\":1}";
        const char *eraw =
            "HTTP/1.1 200 OK\r\nContent-Length: 60\r\n\r\n"
            "{\"result\":null,\"error\":{\"message\":\"boom\"},\"id\":1}";
        char out[16] = {0};
        char errbuf[64] = {0};
        int64_t n = 0;
        bool ok = legacy_rpc_parse_result_string(sraw, out, sizeof(out),
                                                 errbuf, sizeof(errbuf));
        ok = ok && strcmp(out, "abc123") == 0;
        ok = ok && legacy_rpc_parse_result_int(iraw, &n, errbuf,
                                               sizeof(errbuf));
        ok = ok && n == 8232;
        ok = ok && !legacy_rpc_parse_result_string(eraw, out, sizeof(out),
                                                   errbuf, sizeof(errbuf));
        ok = ok && strstr(errbuf, "boom") != NULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("legacy_rpc parse string array results... ");
    {
        const char *raw =
            "HTTP/1.1 200 OK\r\nContent-Length: 94\r\n\r\n"
            "[{\"result\":\"aa\",\"error\":null,\"id\":0},"
            "{\"result\":\"bb\",\"error\":null,\"id\":1}]";
        const char *bad =
            "HTTP/1.1 200 OK\r\nContent-Length: 56\r\n\r\n"
            "[{\"result\":null,\"error\":{\"message\":\"bad item\"},\"id\":0}]";
        char slots[2][8] = {{0}};
        char errbuf[64] = {0};
        bool ok = legacy_rpc_parse_result_string_array(raw, 2, slots[0],
                                                       sizeof(slots[0]),
                                                       errbuf,
                                                       sizeof(errbuf));
        ok = ok && strcmp(slots[0], "aa") == 0;
        ok = ok && strcmp(slots[1], "bb") == 0;
        ok = ok && !legacy_rpc_parse_result_string_array(bad, 1, slots[0],
                                                         sizeof(slots[0]),
                                                         errbuf,
                                                         sizeof(errbuf));
        ok = ok && strstr(errbuf, "bad item") != NULL;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("legacy_rpc bounded timeout rejects unsafe budgets... ");
    {
        char sentinel = '\0';
        char *resp = &sentinel;
        char errbuf[64] = {0};
        bool ok = !legacy_rpc_call_with_timeout(
            "127.0.0.1", 1, "u", "p", "{}", 0, &resp,
            errbuf, sizeof(errbuf));
        ok = ok && resp == NULL && strcmp(errbuf, "bad args") == 0;
        resp = &sentinel;
        errbuf[0] = '\0';
        ok = ok && !legacy_rpc_call_with_timeout(
            "127.0.0.1", 1, "u", "p", "{}", 60001, &resp,
            errbuf, sizeof(errbuf));
        ok = ok && resp == NULL && strcmp(errbuf, "bad args") == 0;
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_table init/append/find... ");
    {
        struct rpc_table t;
        rpc_table_init(&t);
        struct rpc_command cmd = { "control", "test_cmd", NULL, true };
        bool ok = rpc_table_append(&t, &cmd);
        ok = ok && rpc_table_find(&t, "test_cmd") != NULL;
        ok = ok && rpc_table_find(&t, "nonexistent") == NULL;
        ok = ok && !rpc_table_append(&t, &cmd);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc warmup state... ");
    {
        set_rpc_warmup_status("Loading blocks...");
        char status[256];
        bool ok = rpc_is_in_warmup(status, sizeof(status));
        ok = ok && strcmp(status, "Loading blocks...") == 0;
        set_rpc_warmup_finished();
        ok = ok && !rpc_is_in_warmup(NULL, 0);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("getnodelog since_secs timestamp filtering... ");
    {
        char dir_template[] = "/tmp/zcl_nodelog_rpc_XXXXXX";
        char *dir = mkdtemp(dir_template);
        char log_path[1024] = {0};
        bool ok = dir != NULL;
        if (ok) {
            int n = snprintf(log_path, sizeof(log_path), "%s/node.log", dir);
            ok = n > 0 && (size_t)n < sizeof(log_path);
        }
        if (ok) {
            FILE *fp = fopen(log_path, "w");
            ok = fp != NULL;
            if (fp) {
                ok = fputs("{\"ts\":\"2026-06-23T18:30:00.000000Z\","
                           "\"level\":\"info\","
                           "\"event\":\"node_log_since_old\"}\n", fp) >= 0;
                ok = ok && fputs("undated node_log_since_undated\n", fp) >= 0;
                ok = ok && fputs("{\"ts\":\"2026-06-23T18:34:19.000000Z\","
                                 "\"level\":\"info\","
                                 "\"event\":\"node_log_since_recent\"}\n", fp) >= 0;
                ok = ok && fclose(fp) == 0;
            }
        }

        struct rpc_fake_clock fake = { .wall_ms = 1782239670000LL };
        const clock_iface_t iface = {
            .now_monotonic_ns = rpc_fake_now_mono,
            .now_wall_ms = rpc_fake_now_wall,
            .self = &fake,
        };
        bool clock_installed = false;

        struct json_value params;
        json_init(&params);
        struct json_value result;
        json_init(&result);

        if (ok) {
            clock_set_default(&iface);
            clock_installed = true;
            diagnostics_controller_set_state(NULL, dir);

            json_set_array(&params);
            struct json_value v;
            json_init(&v);
            json_set_str(&v, "node_log_since");
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 60);
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 10);
            ok = ok && json_push_back(&params, &v);
            json_set_str(&v, "all");
            ok = ok && json_push_back(&params, &v);
            json_free(&v);
        }

        if (ok) {
            struct rpc_table tbl;
            rpc_table_init(&tbl);
            register_diagnostics_rpc_commands(&tbl);
            ok = rpc_table_execute(&tbl, "getnodelog", &params, &result);
        }

        if (ok) {
            const struct json_value *lines = json_get(&result, "lines");
            const struct json_value *skipped =
                json_get(&result, "timestamped_lines_skipped");
            const struct json_value *undated =
                json_get(&result, "undated_lines_included");
            const struct json_value *complete =
                json_get(&result, "since_filter_complete");
            ok = lines && lines->type == JSON_ARR && json_size(lines) == 2;
            ok = ok && strstr(json_get_str(json_at(lines, 0)),
                              "node_log_since_recent") != NULL;
            ok = ok && strstr(json_get_str(json_at(lines, 1)),
                              "node_log_since_undated") != NULL;
            ok = ok && skipped && json_get_int(skipped) == 1;
            ok = ok && undated && json_get_int(undated) == 1;
            ok = ok && complete && !json_get_bool(complete);
        }

        json_free(&params);
        json_free(&result);
        diagnostics_controller_set_state(NULL, "");
        if (clock_installed)
            clock_reset_default();
        if (dir) {
            unlink(log_path);
            rmdir(dir);
        }

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("getnodelog level filter on ISO-timestamped LOG_* lines... ");
    {
        char dir_template[] = "/tmp/zcl_nodelog_lvl_XXXXXX";
        char *dir = mkdtemp(dir_template);
        char log_path[1024] = {0};
        bool ok = dir != NULL;
        if (ok) {
            int n = snprintf(log_path, sizeof(log_path), "%s/node.log", dir);
            ok = n > 0 && (size_t)n < sizeof(log_path);
        }
        if (ok) {
            FILE *fp = fopen(log_path, "w");
            ok = fp != NULL;
            if (fp) {
                /* Current LOG_* format (zcl_log_emit_at): ISO-8601 UTC
                 * timestamp + level token prefix; plus one pre-timestamp
                 * legacy line to prove the old "WARN:" sniffing survives. */
                ok = fputs("2026-06-23T18:34:18Z ERROR [sync] sync.c:1 f(): nlv_err\n", fp) >= 0;
                ok = ok && fputs("2026-06-23T18:34:19Z WARN [net] net.c:2 g(): nlv_warn\n", fp) >= 0;
                ok = ok && fputs("2026-06-23T18:34:20Z INFO [net] net.c:3 h(): nlv_info\n", fp) >= 0;
                ok = ok && fputs("[net] WARN: net.c:4 old(): nlv_legacy_warn\n", fp) >= 0;
                ok = ok && fclose(fp) == 0;
            }
        }

        /* Fake "now" = 2026-06-23T18:34:30Z: every dated line above is
         * within the 60 s since window. */
        struct rpc_fake_clock fake = { .wall_ms = 1782239670000LL };
        const clock_iface_t iface = {
            .now_monotonic_ns = rpc_fake_now_mono,
            .now_wall_ms = rpc_fake_now_wall,
            .self = &fake,
        };
        bool clock_installed = false;
        if (ok) {
            clock_set_default(&iface);
            clock_installed = true;
            diagnostics_controller_set_state(NULL, dir);
        }

        /* level=warn keeps WARN+ERROR, drops INFO; reverse scan order. */
        if (ok) {
            struct json_value params;
            json_init(&params);
            struct json_value result;
            json_init(&result);
            json_set_array(&params);
            struct json_value v;
            json_init(&v);
            json_set_str(&v, "nlv_");
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 60);
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 10);
            ok = ok && json_push_back(&params, &v);
            json_set_str(&v, "warn");
            ok = ok && json_push_back(&params, &v);
            json_free(&v);

            struct rpc_table tbl;
            rpc_table_init(&tbl);
            register_diagnostics_rpc_commands(&tbl);
            ok = rpc_table_execute(&tbl, "getnodelog", &params, &result);
            if (ok) {
                const struct json_value *lines = json_get(&result, "lines");
                ok = lines && lines->type == JSON_ARR && json_size(lines) == 3;
                ok = ok && strstr(json_get_str(json_at(lines, 0)),
                                  "nlv_legacy_warn") != NULL;
                ok = ok && strstr(json_get_str(json_at(lines, 1)),
                                  "nlv_warn") != NULL;
                ok = ok && strstr(json_get_str(json_at(lines, 2)),
                                  "nlv_err") != NULL;
            }
            json_free(&params);
            json_free(&result);
        }

        /* level=error keeps only the ERROR line. */
        if (ok) {
            struct json_value params;
            json_init(&params);
            struct json_value result;
            json_init(&result);
            json_set_array(&params);
            struct json_value v;
            json_init(&v);
            json_set_str(&v, "nlv_");
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 60);
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 10);
            ok = ok && json_push_back(&params, &v);
            json_set_str(&v, "error");
            ok = ok && json_push_back(&params, &v);
            json_free(&v);

            struct rpc_table tbl;
            rpc_table_init(&tbl);
            register_diagnostics_rpc_commands(&tbl);
            ok = rpc_table_execute(&tbl, "getnodelog", &params, &result);
            if (ok) {
                const struct json_value *lines = json_get(&result, "lines");
                ok = lines && lines->type == JSON_ARR && json_size(lines) == 1;
                ok = ok && strstr(json_get_str(json_at(lines, 0)),
                                  "nlv_err") != NULL;
            }
            json_free(&params);
            json_free(&result);
        }

        /* level=ERROR (uppercase) is accepted — case-insensitive parse. */
        if (ok) {
            struct json_value params;
            json_init(&params);
            struct json_value result;
            json_init(&result);
            json_set_array(&params);
            struct json_value v;
            json_init(&v);
            json_set_str(&v, "nlv_");
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 60);
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 10);
            ok = ok && json_push_back(&params, &v);
            json_set_str(&v, "ERROR");
            ok = ok && json_push_back(&params, &v);
            json_free(&v);

            struct rpc_table tbl;
            rpc_table_init(&tbl);
            register_diagnostics_rpc_commands(&tbl);
            ok = rpc_table_execute(&tbl, "getnodelog", &params, &result);
            if (ok) {
                const struct json_value *lines = json_get(&result, "lines");
                ok = lines && lines->type == JSON_ARR && json_size(lines) == 1;
                ok = ok && strstr(json_get_str(json_at(lines, 0)),
                                  "nlv_err") != NULL;
            }
            json_free(&params);
            json_free(&result);
        }

        /* Unknown level is rejected loudly (string error body), never a
         * silent fall-through to "all". */
        if (ok) {
            struct json_value params;
            json_init(&params);
            struct json_value result;
            json_init(&result);
            json_set_array(&params);
            struct json_value v;
            json_init(&v);
            json_set_str(&v, "nlv_");
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 60);
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 10);
            ok = ok && json_push_back(&params, &v);
            json_set_str(&v, "loud");
            ok = ok && json_push_back(&params, &v);
            json_free(&v);

            struct rpc_table tbl;
            rpc_table_init(&tbl);
            register_diagnostics_rpc_commands(&tbl);
            bool rc = rpc_table_execute(&tbl, "getnodelog", &params, &result);
            ok = ok && !rc && result.type == JSON_STR &&
                 strstr(json_get_str(&result), "bad level") != NULL;
            json_free(&params);
            json_free(&result);
        }

        diagnostics_controller_set_state(NULL, "");
        if (clock_installed)
            clock_reset_default();
        if (dir) {
            unlink(log_path);
            rmdir(dir);
        }

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* The in-tree ERE matcher behind `getnodelog`. Every expectation below
     * was taken from glibc regcomp/regexec with REG_EXTENDED|REG_NOSUB — the
     * implementation this replaced — so this pins the contract the help text
     * states rather than whatever the new code happens to do. The same
     * comparison was run over 400,000 generated pattern/subject pairs while
     * developing the matcher; these are the cases worth keeping. */
    printf("ere matcher: POSIX-extended grammar matches the old contract... ");
    {
        static const struct {
            const char *pattern;
            const char *subject;
            bool expect;
        } cases[] = {
            /* literals, and an unanchored search */
            {"", "abc", true}, {"abc", "xxabcxx", true}, {"abc", "abx", false},
            {"tip_finalize", "[sync] tip_finalize(): done", true},
            /* '.' is any byte, and a literal dot needs the escape */
            {"a.c", "abc", true}, {"a.c", "ac", false},
            {"block_index\\.bin", "block_index.bin", true},
            {"block_index\\.bin", "block_indexXbin", false},
            /* quantifiers */
            {"ab*c", "ac", true}, {"ab*c", "abbbc", true},
            {"ab+c", "ac", false}, {"ab+c", "abc", true},
            {"ab?c", "ac", true}, {"ab?c", "abbc", false},
            {"a{2}", "a", false}, {"a{2}", "aa", true},
            {"^a{2}$", "aaa", false},
            {"^ab{2,}$", "abb", true}, {"^ab{2,}$", "ab", false},
            {"^ab{1,3}$", "abbb", true}, {"^ab{1,3}$", "abbbb", false},
            {"^a{,2}$", "aa", true}, {"^a{,2}$", "aaa", false},
            /* alternation and grouping */
            {"sync|net", "[net] hello", true},
            {"sync|net", "[rpc] hello", false},
            {"^(a|b)+c$", "abbac", true}, {"^(a|b)+c$", "abxc", false},
            {"^(ab){2}$", "abab", true}, {"^(ab){2}$", "aba", false},
            /* anchors */
            {"^\\[net\\]", "[net] up", true}, {"^\\[net\\]", " [net] up", false},
            {"done$", "job done", true}, {"done$", "done job", false},
            {"^$", "", true}, {"^$", "x", false},
            /* bracket expressions */
            {"^[abc]+$", "cab", true}, {"^[abc]+$", "cad", false},
            {"^[^abc]+$", "xyz", true}, {"^[^abc]+$", "xya", false},
            {"^[a-c]+$", "abc", true}, {"^[a-c]+$", "abd", false},
            {"^[]a]+$", "]a]", true}, {"^[a-]+$", "a-a", true},
            {"^[[:digit:]]+$", "12345", true},
            {"^[[:digit:]]+$", "12x45", false},
            {"^[[:alpha:]][[:digit:]]$", "a1", true},
            {"^[[:alpha:]][[:digit:]]$", "1a", false},
            {"^[[:space:]]+$", " \t", true},
            {"^[[:xdigit:]]+$", "9fA", true},
            {"^[[:xdigit:]]+$", "9gA", false},
            {"^[[:upper:]]+$", "AB", true}, {"^[[:upper:]]+$", "Ab", false},
            {"^[[:punct:]]+$", ".,;", true}, {"^[[:punct:]]+$", ".a", false},
            /* escapes of punctuation metacharacters */
            {"^\\*$", "*", true}, {"^\\[$", "[", true}, {"^\\{$", "{", true},
            {"^\\\\$", "\\", true},
            /* a backslash inside a bracket expression is an ordinary member,
             * as POSIX specifies and glibc implements */
            {"^[\\.]+$", "\\.", true}, {"^[\\.]+$", "a", false},
            /* a lone '}' is an ordinary character */
            {"^a}$", "a}", true},
            /* a pattern that can match empty matches every subject */
            {"x*", "yyy", true},
            /* no catastrophic backtracking: this returns, it does not hang */
            {"(a|a)*(a|a)*(a|a)*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", false},
        };
        struct zcl_ere *re = malloc(sizeof(*re));
        bool ok = re != NULL;
        for (size_t i = 0; ok && i < sizeof(cases) / sizeof(cases[0]); i++) {
            if (!zcl_ere_compile(re, cases[i].pattern)) {
                printf("\n  compile refused <%s>: %s ", cases[i].pattern,
                       zcl_ere_error(re));
                ok = false;
                break;
            }
            bool got = zcl_ere_search(re, cases[i].subject,
                                      strlen(cases[i].subject));
            if (got != cases[i].expect) {
                printf("\n  <%s> vs <%s>: got %d want %d ", cases[i].pattern,
                       cases[i].subject, got, cases[i].expect);
                ok = false;
                break;
            }
        }
        free(re);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    /* A pattern the matcher cannot honour must be REFUSED with a reason, so
     * a pattern that used to work never silently stops matching. */
    printf("ere matcher: an unhonourable pattern is refused, not ignored... ");
    {
        static const char *refused[] = {
            "\\w", "\\d", "\\s", "\\b",   /* GNU-only escapes, never literals */
            "[a-", "[z-a]", "[[.a.]]", "[[=a=]]", "[[:bogus:]]",
            "(a", "a)", "*a", "^*", "$?", "a\\",
            "a{2", "a{}", "a{ }", "{2}x", "a{3,2}", "a{99}",
        };
        struct zcl_ere *re = malloc(sizeof(*re));
        bool ok = re != NULL;
        for (size_t i = 0; ok && i < sizeof(refused) / sizeof(refused[0]); i++) {
            if (zcl_ere_compile(re, refused[i])) {
                printf("\n  <%s> was accepted ", refused[i]);
                ok = false;
            } else if (zcl_ere_error(re)[0] == '\0' ||
                       strcmp(zcl_ere_error(re), "ok") == 0) {
                printf("\n  <%s> refused without a reason ", refused[i]);
                ok = false;
            }
        }
        /* An over-long pattern is refused rather than truncated. */
        if (ok) {
            char big[ZCL_ERE_MAX_PATTERN + 8];
            memset(big, 'a', sizeof(big) - 1);
            big[sizeof(big) - 1] = '\0';
            ok = !zcl_ere_compile(re, big);
        }
        free(re);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("getnodelog accepts a regex and refuses a bad one... ");
    {
        char dir_template[] = "/tmp/zcl_nodelog_re_XXXXXX";
        char *dir = mkdtemp(dir_template);
        char log_path[1024] = {0};
        bool ok = dir != NULL;
        if (ok) {
            int n = snprintf(log_path, sizeof(log_path), "%s/node.log", dir);
            ok = n > 0 && (size_t)n < sizeof(log_path);
        }
        if (ok) {
            FILE *fp = fopen(log_path, "w");
            ok = fp != NULL;
            if (fp) {
                ok = fputs("[net] nre_alpha connected\n", fp) >= 0;
                ok = ok && fputs("[sync] nre_beta stalled\n", fp) >= 0;
                ok = ok && fputs("[rpc] nre_gamma served\n", fp) >= 0;
                ok = ok && fclose(fp) == 0;
            }
        }
        if (ok)
            diagnostics_controller_set_state(NULL, dir);

        /* Alternation + anchor, the shape an operator actually types. */
        if (ok) {
            struct json_value params, result, v;
            json_init(&params);
            json_init(&result);
            json_init(&v);
            json_set_array(&params);
            json_set_str(&v, "^\\[(net|rpc)\\] nre_");
            ok = json_push_back(&params, &v);
            json_set_int(&v, 0);
            ok = ok && json_push_back(&params, &v);
            json_set_int(&v, 10);
            ok = ok && json_push_back(&params, &v);
            json_free(&v);
            struct rpc_table tbl;
            rpc_table_init(&tbl);
            register_diagnostics_rpc_commands(&tbl);
            ok = ok && rpc_table_execute(&tbl, "getnodelog", &params, &result);
            if (ok) {
                const struct json_value *lines = json_get(&result, "lines");
                ok = lines && lines->type == JSON_ARR && json_size(lines) == 2;
                ok = ok && strstr(json_get_str(json_at(lines, 0)),
                                  "nre_gamma") != NULL;
                ok = ok && strstr(json_get_str(json_at(lines, 1)),
                                  "nre_alpha") != NULL;
            }
            json_free(&params);
            json_free(&result);
        }

        /* An unhonourable pattern is an error, not an empty result set. */
        if (ok) {
            struct json_value params, result, v;
            json_init(&params);
            json_init(&result);
            json_init(&v);
            json_set_array(&params);
            json_set_str(&v, "nre_\\w+");
            ok = json_push_back(&params, &v);
            json_free(&v);
            struct rpc_table tbl;
            rpc_table_init(&tbl);
            register_diagnostics_rpc_commands(&tbl);
            bool rc = rpc_table_execute(&tbl, "getnodelog", &params, &result);
            ok = !rc && result.type == JSON_STR &&
                 strstr(json_get_str(&result), "bad regex") != NULL;
            json_free(&params);
            json_free(&result);
        }

        diagnostics_controller_set_state(NULL, "");
        if (dir) {
            unlink(log_path);
            rmdir(dir);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("value_from_amount... ");
    {
        struct json_value v;
        value_from_amount(123456789LL, &v);
        bool ok = v.type == JSON_STR;
        ok = ok && strcmp(json_get_str(&v), "1.23456789") == 0;
        json_free(&v);

        value_from_amount(-50000000LL, &v);
        ok = ok && strcmp(json_get_str(&v), "-0.50000000") == 0;
        json_free(&v);

        value_from_amount(0, &v);
        ok = ok && strcmp(json_get_str(&v), "0.00000000") == 0;
        json_free(&v);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("dbwrapper open/write/read/close... ");
    {
        char dbdir[512];
        rpc_test_tmpdir(dbdir, sizeof(dbdir), "dbwrapper1");
        struct db_wrapper db;
        bool ok = db_wrapper_open(&db, dbdir, 1024 * 1024,
                                  false, true);
        if (ok) {
            ok = ok && db_is_empty(&db);

            ok = ok && db_write(&db, "key1", 4, "value1", 6, false);
            ok = ok && !db_is_empty(&db);
            ok = ok && db_exists(&db, "key1", 4);
            ok = ok && !db_exists(&db, "key2", 4);

            char *val = NULL;
            size_t vallen = 0;
            ok = ok && db_read(&db, "key1", 4, &val, &vallen);
            ok = ok && vallen == 6 && memcmp(val, "value1", 6) == 0;
            free(val);

            ok = ok && db_erase(&db, "key1", 4, false);
            ok = ok && !db_exists(&db, "key1", 4);

            db_wrapper_close(&db);
        }
        test_rm_rf(dbdir);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("dbwrapper batch... ");
    {
        char dbdir[512];
        rpc_test_tmpdir(dbdir, sizeof(dbdir), "dbwrapper2");
        struct db_wrapper db;
        bool ok = db_wrapper_open(&db, dbdir, 1024 * 1024,
                                  false, true);
        if (ok) {
            struct db_batch batch;
            db_batch_init(&batch);
            db_batch_put(&batch, "a", 1, "1", 1);
            db_batch_put(&batch, "b", 1, "2", 1);
            db_batch_put(&batch, "c", 1, "3", 1);
            ok = ok && db_write_batch(&db, &batch, false);
            db_batch_free(&batch);

            ok = ok && db_exists(&db, "a", 1);
            ok = ok && db_exists(&db, "b", 1);
            ok = ok && db_exists(&db, "c", 1);

            db_wrapper_close(&db);
        }
        test_rm_rf(dbdir);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("dbwrapper iterator... ");
    {
        char dbdir[512];
        rpc_test_tmpdir(dbdir, sizeof(dbdir), "dbwrapper3");
        struct db_wrapper db;
        bool ok = db_wrapper_open(&db, dbdir, 1024 * 1024,
                                  false, true);
        if (ok) {
            db_write(&db, "x", 1, "10", 2, false);
            db_write(&db, "y", 1, "20", 2, false);
            db_write(&db, "z", 1, "30", 2, false);

            struct db_iterator it;
            db_iter_init(&it, &db);
            db_iter_seek_to_first(&it);
            int count = 0;
            while (db_iter_valid(&it)) {
                count++;
                db_iter_next(&it);
            }
            ok = ok && count == 3;
            db_iter_free(&it);
            db_wrapper_close(&db);
        }
        test_rm_rf(dbdir);
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_convert_values... ");
    {
        const char *params[] = { "1000", "abc123" };
        struct json_value result;
        bool ok = rpc_convert_values("getblockhash", params, 2, &result);
        ok = ok && result.type == JSON_ARR && json_size(&result) == 2;
        ok = ok && json_get_int(json_at(&result, 0)) == 1000;
        ok = ok && strcmp(json_get_str(json_at(&result, 1)), "abc123") == 0;
        json_free(&result);

        ok = ok && rpc_should_convert_param("estimatefee", 0);
        ok = ok && !rpc_should_convert_param("estimatefee", 1);
        ok = ok && rpc_should_convert_param("sendtoaddress", 1);
        ok = ok && !rpc_should_convert_param("sendtoaddress", 0);
        ok = ok && rpc_should_convert_param("agentsession", 1);
        ok = ok && !rpc_should_convert_param("agentsession", 0);

        const char *agent_params[] = {
            "custody", "{\"wallet_scope\":\"dev\"}"
        };
        struct json_value agent_result;
        ok = ok && rpc_convert_values("agentsession", agent_params, 2,
                                      &agent_result);
        ok = ok && agent_result.type == JSON_ARR &&
            json_size(&agent_result) == 2;
        ok = ok && strcmp(json_get_str(json_at(&agent_result, 0)),
                          "custody") == 0;
        const struct json_value *agent_scope = json_at(&agent_result, 1);
        ok = ok && agent_scope && agent_scope->type == JSON_OBJ &&
            strcmp(json_get_str(json_get(agent_scope, "wallet_scope")),
                   "dev") == 0;
        json_free(&agent_result);

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_convert_values msg_send/msg_inbox peer-id and flag rows... ");
    {
        /* msg_send on the default p2p channel: argument 0 is a numeric
         * peer ID and must come out as JSON_INT, not JSON_STR — this is
         * the exact row that fixed "Peer not found or disconnected" for
         * every peer, because the handler reads it with json_get_int()
         * (which returns 0 for a string). */
        bool ok = rpc_should_convert_param("msg_send", 0);

        const char *p2p_params[] = { "60", "hello" };
        struct json_value p2p_result;
        ok = ok && rpc_convert_values("msg_send", p2p_params, 2, &p2p_result);
        ok = ok && p2p_result.type == JSON_ARR &&
            json_size(&p2p_result) == 2;
        ok = ok && json_at(&p2p_result, 0)->type == JSON_INT;
        ok = ok && json_get_int(json_at(&p2p_result, 0)) == 60;
        json_free(&p2p_result);

        /* msg_send on the onchain channel: argument 0 is a z-address
         * string. The static (method, idx) table cannot see argument 2,
         * so rpc_convert_values() itself must leave argument 0 alone here
         * or every onchain CLI send would fail to parse. */
        const char *onchain_params[] = {
            "zs1exampleaddress", "hello", "onchain", "zs1fromaddress"
        };
        struct json_value onchain_result;
        ok = ok && rpc_convert_values("msg_send", onchain_params, 4,
                                      &onchain_result);
        ok = ok && onchain_result.type == JSON_ARR &&
            json_size(&onchain_result) == 4;
        ok = ok && json_at(&onchain_result, 0)->type == JSON_STR;
        ok = ok && strcmp(json_get_str(json_at(&onchain_result, 0)),
                          "zs1exampleaddress") == 0;
        json_free(&onchain_result);

        /* msg_inbox: one audited method besides msg_send whose handler
         * (msg_inbox_unread_only) reads its only argument with
         * json_get_int(...) != 0. */
        ok = ok && rpc_should_convert_param("msg_inbox", 0);
        ok = ok && rpc_should_convert_param("msg_inbox_index", 0);

        const char *inbox_params[] = { "1" };
        struct json_value inbox_result;
        ok = ok && rpc_convert_values("msg_inbox", inbox_params, 1,
                                      &inbox_result);
        ok = ok && inbox_result.type == JSON_ARR &&
            json_size(&inbox_result) == 1;
        ok = ok && json_at(&inbox_result, 0)->type == JSON_INT;
        ok = ok && json_get_int(json_at(&inbox_result, 0)) == 1;
        json_free(&inbox_result);

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_convert_values msg_send rejects a non-numeric peer id... ");
    {
        /* Before the msg_send row existed, a non-numeric first argument
         * was sent through as a JSON string and the node's
         * json_get_int() silently read it as peer 0. Now that argument 0
         * is a convert-table entry, an unquoted non-numeric token is not
         * valid JSON, and rpc_convert_values() must refuse with a typed
         * failure (false) instead of ever producing a JSON_STR or
         * JSON_INT 0 for it. */
        const char *bad_params[] = { "not-a-peer-id", "hello" };
        struct json_value bad_result;
        bool ok = !rpc_convert_values("msg_send", bad_params, 2, &bad_result);
        /* rpc_convert_values() documents that on failure *result is left
         * partially built and still owned by the caller; free it and
         * confirm no element was ever appended for the rejected argument. */
        ok = ok && json_size(&bad_result) == 0;
        json_free(&bad_result);

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("rpc_cli_print_json_result... ");
    {
        bool ok = rpc_test_cli_print_case(
            "{\"result\":42,\"error\":null,\"id\":\"cli\"}",
            true, "42\n", NULL);
        ok = ok && rpc_test_cli_print_case(
            "{\"result\":null,\"error\":{\"code\":-32601,"
            "\"message\":\"Method not found\"},\"id\":\"cli\"}",
            false, NULL, "Method not found");
        ok = ok && rpc_test_cli_print_case("", false, NULL,
                                           "empty RPC response");
        ok = ok && rpc_test_cli_print_case("not-json", false, NULL,
                                           "invalid JSON-RPC response");
        ok = ok && rpc_test_cli_print_case("{\"error\":null,\"id\":\"cli\"}",
                                           false, NULL, "missing result");

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    printf("ecc_init_sanity_check... ");
    {
        if (ecc_init_sanity_check())
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("parse_script... ");
    {
        struct script s;
        bool ok = parse_script("OP_DUP OP_HASH160 OP_EQUAL", &s);
        if (ok && s.size == 3 &&
            s.data[0] == OP_DUP &&
            s.data[1] == OP_HASH160 &&
            s.data[2] == OP_EQUAL)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("parse_script number... ");
    {
        struct script s;
        bool ok = parse_script("1 2 OP_ADD", &s);
        if (ok && s.size >= 3)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("parse_script shorthand... ");
    {
        struct script s;
        bool ok = parse_script("DUP HASH160 EQUAL", &s);
        if (ok && s.size == 3 &&
            s.data[0] == OP_DUP &&
            s.data[1] == OP_HASH160 &&
            s.data[2] == OP_EQUAL)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("script_to_asm_str... ");
    {
        struct script s;
        script_init(&s);
        script_push_op(&s, OP_DUP);
        script_push_op(&s, OP_HASH160);
        unsigned char hash[20] = {0};
        script_push_data(&s, hash, 20);
        script_push_op(&s, OP_EQUALVERIFY);
        script_push_op(&s, OP_CHECKSIG);
        char asm_str[256];
        script_to_asm_str(&s, false, asm_str, sizeof(asm_str));
        if (strstr(asm_str, "OP_DUP") && strstr(asm_str, "OP_HASH160") &&
            strstr(asm_str, "OP_CHECKSIG"))
            printf("OK (%s)\n", asm_str);
        else {
            printf("FAIL (%s)\n", asm_str);
            failures++;
        }
    }

    printf("decode_hex_tx roundtrip... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = 1;
        tx.lock_time = 0;
        tx.vin[0].sequence = 0xffffffff;
        outpoint_set_null(&tx.vin[0].prevout);
        tx.vin[0].script_sig.size = 0;
        tx.vout[0].value = 5000000000LL;
        tx.vout[0].script_pub_key.size = 0;
        transaction_compute_hash(&tx);

        char hex[2048];
        encode_hex_tx(&tx, hex, sizeof(hex));

        struct transaction tx2;
        transaction_init(&tx2);
        bool ok = decode_hex_tx(&tx2, hex);
        if (ok && tx2.version == 1 && tx2.num_vin == 1 && tx2.num_vout == 1 &&
            tx2.vout[0].value == 5000000000LL)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        transaction_free(&tx);
        transaction_free(&tx2);
    }

    printf("parse_hash_str... ");
    {
        struct uint256 h;
        bool ok = parse_hash_str(
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            &h);
        char hex[65];
        uint256_get_hex(&h, hex);
        if (ok && strcmp(hex, "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f") == 0)
            printf("OK\n");
        else {
            printf("FAIL (%s)\n", hex);
            failures++;
        }
    }

    printf("tx_to_json... ");
    {
        struct transaction tx;
        transaction_init(&tx);
        transaction_alloc(&tx, 1, 1);
        tx.version = 1;
        tx.lock_time = 0;
        tx.vin[0].sequence = 0xffffffff;
        outpoint_set_null(&tx.vin[0].prevout);
        tx.vin[0].script_sig.size = 0;
        tx.vout[0].value = 5000000000LL;
        tx.vout[0].script_pub_key.size = 0;
        transaction_compute_hash(&tx);

        struct json_value entry;
        struct uint256 null_hash;
        uint256_set_null(&null_hash);
        tx_to_json(&tx, &null_hash, &entry);

        if (entry.type == JSON_OBJ && entry.num_children > 0) {
            const struct json_value *v = json_get(&entry, "version");
            if (v && v->type == JSON_INT && v->val.i == 1)
                printf("OK\n");
            else {
                printf("FAIL (version)\n");
                failures++;
            }
        } else {
            printf("FAIL (not obj)\n");
            failures++;
        }
        json_free(&entry);
        transaction_free(&tx);
    }

    printf("async_op init/state... ");
    {
        struct async_rpc_operation op;
        async_op_init(&op);
        if (async_op_is_ready(&op) &&
            strncmp(op.id, "opid-", 5) == 0 &&
            strcmp(async_op_state_str(ASYNC_OP_READY), "queued") == 0)
            printf("OK (%s)\n", op.id);
        else {
            printf("FAIL\n");
            failures++;
        }
        async_op_free(&op);
    }

    printf("async_op execute/result... ");
    {
        struct async_rpc_operation op;
        async_op_init(&op);
        async_op_default_main(&op);
        if (async_op_is_success(&op)) {
            struct json_value res;
            async_op_get_result_json(&op, &res);
            if (res.type == JSON_STR)
                printf("OK\n");
            else {
                printf("FAIL (result type=%d)\n", res.type);
                failures++;
            }
            json_free(&res);
        } else {
            printf("FAIL (state=%s)\n", async_op_state_str(async_op_get_state(&op)));
            failures++;
        }
        async_op_free(&op);
    }

    printf("async_op error... ");
    {
        struct async_rpc_operation op;
        async_op_init(&op);
        async_op_set_error(&op, 42, "test error");
        async_op_set_state(&op, ASYNC_OP_FAILED);
        struct json_value err;
        async_op_get_error_json(&op, &err);
        if (err.type == JSON_OBJ) {
            const struct json_value *code = json_get(&err, "code");
            if (code && code->type == JSON_INT && code->val.i == 42)
                printf("OK\n");
            else {
                printf("FAIL (code)\n");
                failures++;
            }
        } else {
            printf("FAIL (not obj)\n");
            failures++;
        }
        json_free(&err);
        async_op_free(&op);
    }

    printf("async_op status_json... ");
    {
        struct async_rpc_operation op;
        async_op_init(&op);
        struct json_value status;
        async_op_get_status_json(&op, &status);
        const struct json_value *id_val = json_get(&status, "id");
        const struct json_value *st_val = json_get(&status, "status");
        if (id_val && id_val->type == JSON_STR &&
            st_val && st_val->type == JSON_STR &&
            strcmp(st_val->val.s, "queued") == 0)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        json_free(&status);
        async_op_free(&op);
    }

    printf("async_queue add/execute... ");
    {
        struct async_rpc_queue q;
        async_queue_init(&q);

        struct async_rpc_operation op;
        async_op_init(&op);
        char saved_id[ASYNC_OP_ID_SIZE];
        memcpy(saved_id, op.id, ASYNC_OP_ID_SIZE);

        async_queue_add_op(&q, &op);
        bool ok = async_queue_add_worker(&q);

        async_queue_finish_and_wait(&q);

        if (ok && async_op_is_success(&op))
            printf("OK\n");
        else {
            printf("FAIL (state=%s)\n",
                async_op_state_str(async_op_get_state(&op)));
            failures++;
        }
        async_op_free(&op);
        async_queue_free(&q);
    }

    printf("async_queue refuses workers after finish... ");
    {
        struct async_rpc_queue q;
        async_queue_init(&q);
        async_queue_finish(&q);
        if (!async_queue_add_worker(&q))
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
        async_queue_free(&q);
    }

    printf("async_queue tracks worker count across shutdown... ");
    {
        struct async_rpc_queue q;
        async_queue_init(&q);

        bool ok = async_queue_add_worker(&q);
        size_t started = async_queue_num_workers(&q);
        async_queue_finish_and_wait(&q);
        size_t after = async_queue_num_workers(&q);

        if (ok && started == 1 && after == 0)
            printf("OK\n");
        else {
            printf("FAIL (ok=%d started=%zu after=%zu)\n",
                   ok ? 1 : 0, started, after);
            failures++;
        }
        async_queue_free(&q);
    }

    /* ── Wave 11 #6: RPC TLS tests ─────────────────────────────────── */

    printf("rpc_http_tls_active when no TLS configured... ");
    {
        /* Without TLS env vars, tls_active should be false */
        unsetenv("ZCL_RPC_TLS_CERT");
        unsetenv("ZCL_RPC_TLS_KEY");
        bool active = rpc_http_tls_active();
        if (!active)
            printf("OK\n");
        else {
            printf("FAIL (expected false)\n");
            failures++;
        }
    }

    printf("rpc TLS start with self-signed cert... ");
    {
        /* Generate a self-signed cert+key in temp files */
        char cert_path[] = "/tmp/zcl_test_cert_XXXXXX";
        char key_path[] = "/tmp/zcl_test_key_XXXXXX";
        int cfd = mkstemp(cert_path);
        int kfd = mkstemp(key_path);
        bool ok = false;
        /* Private datadir: rpc_http_start writes <datadir>/.cookie, so a
         * shared "/tmp" would have two concurrent runs overwriting and then
         * unlinking each other's credential file. */
        char rpcdir[512];
        rpc_test_tmpdir(rpcdir, sizeof(rpcdir), "tls");
        const uint16_t tls_port = rpc_test_free_port();
        const uint16_t http_port = rpc_test_free_port();

        if (cfd >= 0 && kfd >= 0) {
            /* Generate RSA key + self-signed cert via OpenSSL */
            EVP_PKEY *pkey = EVP_PKEY_new();
            EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
            if (kctx && EVP_PKEY_keygen_init(kctx) > 0) {
                EVP_PKEY_CTX_set_rsa_keygen_bits(kctx, 2048);
                EVP_PKEY_keygen(kctx, &pkey);
            }
            if (kctx) EVP_PKEY_CTX_free(kctx);

            X509 *x509 = X509_new();
            if (x509 && pkey) {
                X509_set_version(x509, 2);
                ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
                X509_gmtime_adj(X509_getm_notBefore(x509), 0);
                X509_gmtime_adj(X509_getm_notAfter(x509), 3600);
                X509_set_pubkey(x509, pkey);
                X509_NAME *name = X509_get_subject_name(x509);
                X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                    (const unsigned char *)"localhost", -1, -1, 0);
                X509_set_issuer_name(x509, name);
                X509_sign(x509, pkey, EVP_sha256());

                /* Write cert */
                FILE *cf = fdopen(cfd, "w");
                if (cf) {
                    PEM_write_X509(cf, x509);
                    fclose(cf);
                    cfd = -1;  /* fdopen took ownership */
                }
                /* Write key */
                FILE *kf = fdopen(kfd, "w");
                if (kf) {
                    PEM_write_PrivateKey(kf, pkey, NULL, NULL, 0, NULL, NULL);
                    fclose(kf);
                    kfd = -1;
                }

                /* Set env vars and start RPC with TLS */
                char tls_port_s[16];
                snprintf(tls_port_s, sizeof(tls_port_s), "%u",
                         (unsigned)tls_port);
                setenv("ZCL_RPC_TLS_CERT", cert_path, 1);
                setenv("ZCL_RPC_TLS_KEY", key_path, 1);
                setenv("ZCL_RPC_TLS_PORT", tls_port_s, 1);

                /* Create a minimal RPC table */
                struct rpc_table tbl;
                rpc_table_init(&tbl);

                bool started = tls_port && http_port &&
                    rpc_http_start(&tbl, http_port, NULL, NULL, rpcdir);
                if (started) {
                    ok = rpc_http_tls_active();

                    /* Try connecting with TLS */
                    if (ok) {
                        SSL_CTX *cctx = SSL_CTX_new(TLS_client_method());
                        if (cctx) {
                            platform_socket_t sock = platform_socket_open(
                                AF_INET, SOCK_STREAM, 0, true, false);
                            struct sockaddr_in sa;
                            memset(&sa, 0, sizeof(sa));
                            sa.sin_family = AF_INET;
                            sa.sin_port = htons(tls_port);
                            sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                            if (platform_socket_connect(
                                    sock, (struct sockaddr *)&sa,
                                    sizeof(sa)) == 0) {
                                SSL *ssl = SSL_new(cctx);
                                SSL_set_fd(ssl, (int)(intptr_t)sock);
                                if (SSL_connect(ssl) == 1) {
                                    /* Send a minimal JSON-RPC request */
                                    const char *req =
                                        "POST / HTTP/1.1\r\n"
                                        "Content-Length: 44\r\n"
                                        "\r\n"
                                        "{\"method\":\"getblockcount\","
                                        "\"params\":[],\"id\":1}";
                                    SSL_write(ssl, req, (int)strlen(req));

                                    char rbuf[4096];
                                    int n = SSL_read(ssl, rbuf,
                                                     (int)sizeof(rbuf) - 1);
                                    if (n > 0) {
                                        rbuf[n] = '\0';
                                        /* Should get HTTP 200 back */
                                        ok = ok && (strstr(rbuf,
                                                    "HTTP/1.1 200") != NULL ||
                                                    strstr(rbuf,
                                                    "HTTP/1.1 401") != NULL);
                                    } else {
                                        ok = false;
                                    }
                                } else {
                                    ok = false;
                                }
                                SSL_shutdown(ssl);
                                SSL_free(ssl);
                            }
                            platform_socket_close(sock);
                            SSL_CTX_free(cctx);
                        }
                    }

                    rpc_http_stop();
                    (void)tbl;
                } else {
                    ok = false;
                    (void)tbl;
                }

                X509_free(x509);
            }
            if (pkey) EVP_PKEY_free(pkey);
        }
        if (cfd >= 0) close(cfd);
        if (kfd >= 0) close(kfd);
        unlink(cert_path);
        unlink(key_path);
        unsetenv("ZCL_RPC_TLS_CERT");
        unsetenv("ZCL_RPC_TLS_KEY");
        unsetenv("ZCL_RPC_TLS_PORT");
        /* Clean up cookie file (ours, not a shared /tmp/.cookie) */
        test_rm_rf(rpcdir);

        if (ok)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    printf("rpc TLS not started without env vars... ");
    {
        unsetenv("ZCL_RPC_TLS_CERT");
        unsetenv("ZCL_RPC_TLS_KEY");
        char rpcdir[512];
        rpc_test_tmpdir(rpcdir, sizeof(rpcdir), "notls");
        const uint16_t port = rpc_test_free_port();
        struct rpc_table tbl;
        rpc_table_init(&tbl);
        bool started = port && rpc_http_start(&tbl, port, NULL, NULL, rpcdir);
        bool tls = rpc_http_tls_active();
        if (started) rpc_http_stop();
        (void)tbl;
        test_rm_rf(rpcdir);
        if (started && !tls)
            printf("OK\n");
        else {
            printf("FAIL (started=%d tls=%d)\n", started, tls);
            failures++;
        }
    }

    printf("rpc port listening oracle... ");
    {
        /* node_rpc_port_listening is the liveness oracle
         * core.consensus.producer-session.retire refuses a live node on.
         * It must track the kernel's view of the port exactly: true only
         * while a loopback listener holds it, false the instant it closes,
         * and false for ports no listener can hold. The node_rpc_call*
         * paths cannot answer this question — they return non-NULL
         * self-describing error bodies on refused connects, which is how
         * "any reply means running" once read a stopped node as live. */
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        bool ok = fd >= 0 &&
                  bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 &&
                  listen(fd, 1) == 0;
        uint16_t port = 0;
        if (ok) {
            socklen_t len = sizeof(addr);
            ok = getsockname(fd, (struct sockaddr *)&addr, &len) == 0;
            port = ntohs(addr.sin_port);
        }
        ok = ok && port != 0 && node_rpc_port_listening((int)port, 250);
        close(fd);
        ok = ok && !node_rpc_port_listening((int)port, 250);
        ok = ok && !node_rpc_port_listening(0, 250);
        ok = ok && !node_rpc_port_listening(70000, 250);
        if (ok)
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}
