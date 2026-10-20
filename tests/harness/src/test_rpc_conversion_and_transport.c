/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * rpc scenario checks: amount/value conversion, dbwrapper open/write/
 * read and batch+iterator, CLI JSON printing, script/tx parsing, the
 * async op queue, and the RPC HTTP/TLS server.
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
#include "platform/time_compat.h"
#include "command/native_command.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <unistd.h>
#include "test/test_rpc_priv.h"
/* ZCL_TESTING seam in tools/command/native_fleet_board_command.c. */
void zcl_native_fleet_board_test_set_bootstrap(void (*fn)(void));


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

int check_rpc_value_from_amount(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_dbwrapper_open_write_read(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_dbwrapper_batch_and_iterator(void)
{
    int failures = 0;

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

    return failures;
}

static bool check_rpc_convert_values_agentsession(void)
{
    bool ok = true;
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
    return ok;
}

int check_rpc_convert_values(void)
{
    int failures = 0;

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

        ok = ok && check_rpc_convert_values_agentsession();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    failures += check_rpc_string_conversion_cases();
    return failures;
}

static bool check_rpc_convert_msg_send_onchain(void)
{
    bool ok = true;
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
    return ok;
}

static bool check_rpc_convert_msg_inbox(void)
{
    bool ok = true;
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
    return ok;
}

int check_rpc_convert_values_msg_send_inbox(void)
{
    int failures = 0;

    printf("rpc_convert_values msg_send/msg_inbox peer-id and flag rows... ");
    {
        /* msg_send on the default p2p channel: argument 0 is a numeric peer
         * ID and must come out as JSON_INT, not JSON_STR (the handler reads
         * it with json_get_int(), which returns 0 for a string). */
        bool ok = rpc_should_convert_param("msg_send", 0);

        const char *p2p_params[] = { "60", "hello" };
        struct json_value p2p_result;
        ok = ok && rpc_convert_values("msg_send", p2p_params, 2, &p2p_result);
        ok = ok && p2p_result.type == JSON_ARR &&
            json_size(&p2p_result) == 2;
        ok = ok && json_at(&p2p_result, 0)->type == JSON_INT;
        ok = ok && json_get_int(json_at(&p2p_result, 0)) == 60;
        json_free(&p2p_result);


        ok = ok && check_rpc_convert_msg_send_onchain();
        ok = ok && check_rpc_convert_msg_inbox();
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int check_rpc_convert_msg_send_non_numeric(void)
{
    int failures = 0;

    printf("rpc_convert_values msg_send rejects a non-numeric peer id... ");
    {
        /* Argument 0 is a convert-table entry, so an unquoted non-numeric
         * token is invalid JSON and rpc_convert_values() must refuse with a
         * typed failure (false), never producing JSON_STR or JSON_INT 0. */
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

    return failures;
}

int check_rpc_cli_print_json_result(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_ecc_init_sanity_check(void)
{
    int failures = 0;

    printf("ecc_init_sanity_check... ");
    {
        if (ecc_init_sanity_check())
            printf("OK\n");
        else {
            printf("FAIL\n");
            failures++;
        }
    }

    return failures;
}

int check_rpc_parse_script(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_script_to_asm_str(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_decode_hex_tx_and_parse_hash(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_tx_to_json(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_async_op_init_state(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_async_op_execute_result(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_async_op_error(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_async_op_status_json(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_async_queue(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_http_tls_inactive(void)
{
    int failures = 0;

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

    return failures;
}

static bool check_rpc_tls_serve_with_cert(X509 *x509, EVP_PKEY *pkey,
                                         int *cfd_inout, int *kfd_inout,
                                         const char *cert_path,
                                         const char *key_path,
                                         uint16_t tls_port,
                                         uint16_t http_port,
                                         const char *rpcdir)
{
    bool ok = false;
    int cfd = *cfd_inout;
    int kfd = *kfd_inout;
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
    *cfd_inout = cfd;
    *kfd_inout = kfd;
    return ok;
}

int check_rpc_tls_start_self_signed(void)
{
    int failures = 0;

    printf("rpc TLS start with self-signed cert... ");
    {
        /* Generate a self-signed cert+key in temp files */
        char cert_path[] = "/tmp/zcl_test_cert_XXXXXX";
        char key_path[] = "/tmp/zcl_test_key_XXXXXX";
        int cfd = mkstemp(cert_path);
        int kfd = mkstemp(key_path);
        bool ok = false;
        /* Private datadir: rpc_http_start writes <datadir>/.cookie, so a
         * shared "/tmp" would let concurrent runs clobber each other. */
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
                ok = check_rpc_tls_serve_with_cert(x509, pkey, &cfd, &kfd,
                    cert_path, key_path, tls_port, http_port, rpcdir);
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

    return failures;
}

/* ── absolute-deadline RPC transport and optional board observation ───────
 * Synthetic cookies, private fixture dirs and loopback listeners only; hooks,
 * env, the client endpoint and SIGUSR1 are restored when the suite returns. */
#define RT_BODY "{\"ok\":true,\"posts\":[{\"id\":\"synthetic\",\"kind\":" \
    "\"need\",\"agent\":\"test-observer\",\"text\":\"retained\"}]}"
#define RT_ENVELOPE "{\"result\":" RT_BODY ",\"error\":null,\"id\":1}"

#define RT_BIG_LEN 66000 /* just past the client's 64 KiB first buffer: growth comes with a few KB still unread */
enum rt_mode { RT_STALL, RT_HEALTHY, RT_DRIP, RT_BIG };
struct rt_server {
    platform_socket_t listener;
    uint16_t port;
    enum rt_mode mode;
    int delay_ms;
    atomic_bool stop;
    atomic_int requests;
    pthread_t thread;
};
static int g_rt_failures;
static int64_t rt_now(void) { return platform_time_monotonic_ms(); }
static bool rt_has(const char *body, const char *needle) { return body && strstr(body, needle); }
static void rt_expect(bool ok, const char *name, int64_t ms, int requests)
{
    printf("  %s: %s (ms=%lld requests=%d)\n", name, ok ? "OK" : "FAIL", (long long)ms, requests);
    g_rt_failures += !ok;
}
static bool rt_sleep(struct rt_server *s, int ms)
{
    for (int w = 0; w < ms && !atomic_load(&s->stop); w += 5) platform_sleep_ms(5);
    return !atomic_load(&s->stop);
}

/* Count one request once its headers and Content-Length body have arrived. */
static void rt_read_request(struct rt_server *s, platform_socket_t conn)
{
    char buf[4096];
    size_t len = 0;
    while (len < sizeof(buf) - 1 && !atomic_load(&s->stop)) {
        if (platform_socket_wait_readable(conn, 20) <= 0) continue;
        int n = platform_socket_receive(conn, buf + len, sizeof(buf) - 1 - len);
        if (n <= 0) return;
        buf[len += (size_t)n] = '\0';
        const char *end = strstr(buf, "\r\n\r\n"), *cl = strstr(buf, "Content-Length:");
        if (end && cl && len >= (size_t)(end - buf) + 4 + strtoul(cl + 15, NULL, 10)) {
            atomic_fetch_add(&s->requests, 1);
            return;
        }
    }
}

static void *rt_serve(void *arg)
{
    struct rt_server *s = arg;
    static char big[RT_BIG_LEN + 128], reply[RT_BIG_LEN + 256]; /* one server runs at a time */
    const char *env = RT_ENVELOPE;
    if (s->mode == RT_BIG) { /* a valid envelope padded past the first buffer, forcing growth */
        int n = snprintf(big, sizeof(big), "{\"result\":{\"pad\":\"");
        memset(big + n, 'x', RT_BIG_LEN), env = big;
        snprintf(big + n + RT_BIG_LEN, 64, "\",\"t\":\"retained\"},\"error\":null,\"id\":1}");
    }
    int rlen = snprintf(reply, sizeof(reply), "HTTP/1.1 200 OK\r\nContent-Length: "
        "%zu\r\nConnection: close\r\n\r\n%s", strlen(env), env);
    while (!atomic_load(&s->stop)) {
        if (platform_socket_wait_readable(s->listener, 20) <= 0) continue;
        struct sockaddr_in peer;
        size_t peer_len = sizeof(peer);
        platform_socket_t conn = platform_socket_accept(s->listener, (struct sockaddr *)&peer, &peer_len);
        if (conn == PLATFORM_SOCKET_INVALID) continue;
        rt_read_request(s, conn);
        if (s->mode == RT_STALL) {
            while (rt_sleep(s, 10)) {}
        } else if (rt_sleep(s, s->delay_ms)) { /* healthy: one write; drip: a byte per 20ms */
            size_t step = s->mode == RT_DRIP ? 1 : (size_t)rlen;
            for (size_t off = 0; off < (size_t)rlen; off += step)
                if (send(conn, reply + off, step, MSG_NOSIGNAL) <= 0 ||
                    (s->mode == RT_DRIP && !rt_sleep(s, 20))) break;
        }
        platform_socket_close(conn);
    }
    return NULL;
}

static bool rt_listen(platform_socket_t *fd, uint16_t *port, int backlog)
{
    *fd = platform_socket_open(AF_INET, SOCK_STREAM, 0, true, false);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    size_t len = sizeof(a);
    if (*fd == PLATFORM_SOCKET_INVALID || platform_socket_bind(*fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        platform_socket_listen(*fd, backlog) != 0 ||
        platform_socket_local_address(*fd, (struct sockaddr *)&a, &len) != 0)
        return false;
    *port = ntohs(a.sin_port);
    return true;
}
static bool rt_server_start(struct rt_server *s, enum rt_mode mode, int delay_ms)
{
    memset(s, 0, sizeof(*s));
    s->mode = mode, s->delay_ms = delay_ms;
    return rt_listen(&s->listener, &s->port, 4) && pthread_create(&s->thread, NULL, rt_serve, s) == 0;
}
static int rt_server_stop(struct rt_server *s)
{
    atomic_store(&s->stop, true);
    pthread_join(s->thread, NULL);
    platform_socket_close(s->listener);
    return atomic_load(&s->requests);
}

/* A cookie file, or a FIFO filled after 300ms (a blocking read nothing preempts). */
enum rt_cookie { RT_NO_COOKIE, RT_FILE_COOKIE, RT_FIFO_COOKIE };
struct rt_fifo_writer { char path[640]; pthread_t thread; };
static void *rt_fifo_write(void *arg)
{
    struct rt_fifo_writer *w = arg;
    platform_sleep_ms(300);
    for (int64_t until = rt_now() + 3000; rt_now() < until; platform_sleep_ms(5)) {
        int fd = open(w->path, O_WRONLY | O_NONBLOCK);
        if (fd < 0) continue;
        (void)!write(fd, "user:pass\n", 10);
        close(fd);
        break;
    }
    return NULL;
}

static bool rt_fixture(char *dir, size_t n, const char *tag, enum rt_cookie kind, struct rt_fifo_writer *w)
{
    char path[640];
    rpc_test_tmpdir(dir, n, tag);
    snprintf(path, sizeof(path), "%s/.cookie", dir);
    if (kind == RT_FILE_COOKIE) {
        FILE *f = fopen(path, "w");
        if (!f) return false;
        fputs("user:pass\n", f);
        fclose(f);
    } else if (kind == RT_FIFO_COOKIE) {
        snprintf(w->path, sizeof(w->path), "%s", path);
        return mkfifo(path, 0600) == 0 && pthread_create(&w->thread, NULL, rt_fifo_write, w) == 0;
    }
    return true;
}

/* The RPC env knobs and process endpoint, saved once and restored at suite end. */
static struct { char *knob[2], *datadir; int port; } g_rt_saved;
static const char *const rt_env_names[2] = {"ZCL_RPC_CONNECT_MS", "ZCL_RPC_DEADLINE_MS"};
static void rt_knob(int i, const char *v) /* NULL unsets */
{
    if (v) setenv(rt_env_names[i], v, 1);
    else unsetenv(rt_env_names[i]);
}
static void rt_save(void)
{
    for (int i = 0; i < 2; i++)
        g_rt_saved.knob[i] = getenv(rt_env_names[i]) ? strdup(getenv(rt_env_names[i])) : NULL;
    g_rt_saved.datadir = strdup(node_rpc_client_datadir()), g_rt_saved.port = node_rpc_test_client_port();
}
static void rt_restore(void)
{
    rt_knob(0, g_rt_saved.knob[0]), rt_knob(1, g_rt_saved.knob[1]);
    node_rpc_client_init(g_rt_saved.datadir ? g_rt_saved.datadir : "", g_rt_saved.port);
    free(g_rt_saved.knob[0]), free(g_rt_saved.knob[1]), free(g_rt_saved.datadir);
}

/* {now, deadline, want remaining}: zero, equal-now, 1ms and INT64 bounds. */
static void rt_case_arithmetic(void)
{
    static const struct { int64_t now, deadline; int want; } rem[] = {
        {0, 0, 0}, {100, 100, 0}, {100, 99, 0}, {100, 101, 1}, {1, 0, 0}, {INT64_MIN, INT64_MAX, INT32_MAX},
        {INT64_MAX, INT64_MIN, 0}, {INT64_MIN, INT64_MIN, 0}, {0, INT64_MAX, INT32_MAX}, {-5, 5, 10},
        {INT64_MAX - 1, INT64_MAX, 1}, {INT64_MIN, 0, INT32_MAX} };
    bool ok = node_rpc_test_deadline_after(INT64_MAX, 1) == INT64_MAX && node_rpc_test_deadline_after(5, 10) == 15 &&
        node_rpc_test_deadline_after(INT64_MIN, -1) == INT64_MIN && node_rpc_test_deadline_after(INT64_MAX, INT64_MIN) == -1;
    for (size_t i = 0; i < sizeof(rem) / sizeof(rem[0]); i++)
        ok = ok && node_rpc_test_deadline_remaining_ms(rem[i].now, rem[i].deadline) == rem[i].want;
    ok = ok && node_rpc_test_phase_deadline_ms(0, 40, 2000) == 40 && /* min(deadline, now + phase), saturating */
        node_rpc_test_phase_deadline_ms(0, INT64_MAX, 250) == 250 && node_rpc_test_phase_deadline_ms(30, 40, 250) == 40 &&
        node_rpc_test_phase_deadline_ms(INT64_MAX - 10, INT64_MAX, INT64_MAX) == INT64_MAX &&
        node_rpc_test_phase_deadline_ms(0, INT64_MIN, 250) == INT64_MIN;
    rt_expect(ok, "deadline arithmetic: zero/equal/1ms/INT64 bounds, saturation", 0, 0);
}

/* Calls under test; rt_board answers "PASSED" or the error code (arg > 0 = observation). */
typedef char *(*rt_call_fn)(const char *dir, int port, int64_t arg);
static char *rt_until(const char *d, int p, int64_t ms) { return node_rpc_call_at_until(d, p, "fleet_board", "[]", 2000, rt_now() + ms); }
static char *rt_until_at(const char *d, int p, int64_t at) { return node_rpc_call_at_until(d, p, "fleet_board", "[]", 2000, at); }
static char *rt_direct(const char *d, int p, int64_t unused) { (void)unused; return node_rpc_call_at_deadline(d, p, "fleet_board", "[]", 2000, 10000); }
static char *rt_relative40(const char *d, int p, int64_t unused) { (void)unused; return node_rpc_call_at_deadline(d, p, "fleet_board", "[]", 40, 40); }
/* "identical" when the absolute and the direct call return the same payload. */
static char *rt_same(const char *d, int p, int64_t unused)
{
    char *a = rt_until(d, p, 2000), *b = rt_direct(d, p, unused);
    char *out = strdup(a && b && !strcmp(a, b) && rt_has(a, "retained") ? "identical" : "differs");
    free(a), free(b);
    return out;
}
/* A port nothing listens on: the call never reaches the server `rt_run` started. */
static char *rt_refused(const char *d, int p, int64_t unused)
{
    platform_socket_t lf;
    uint16_t dead = 0;
    (void)p, (void)unused;
    if (!rt_listen(&lf, &dead, 1)) return NULL;
    platform_socket_close(lf);
    return rt_until(d, dead, 2000);
}
static char *rt_env_default(const char *d, int p, int64_t unused) /* the endpoint `rt_run` set */
{ (void)unused, (void)d, (void)p; return node_rpc_call_http("fleet_board", "[]"); }
static char *rt_board(const char *d, int p, int64_t ms)
{
    struct json_value input;
    const char *text = "{\"open\":true,\"limit\":20}";
    char *out = NULL;
    (void)d, (void)p;
    if (json_read(&input, text, strlen(text))) {
        struct zcl_command_request request = { .input = &input, .view = "normal",
            .spec = zcl_command_registry_find(zcl_command_catalog(), "fleet.board.list", NULL) };
        struct zcl_command_reply reply;
        zcl_command_reply_init(&reply, "zcl.fleet_board_list.v1");
        if (ms > 0) zcl_native_fleet_board_list_until(&request, &reply, rt_now() + ms);
        else zcl_native_handle_fleet_board_list(&request, &reply);
        out = strdup(reply.status == ZCL_COMMAND_STATUS_PASSED ? "PASSED" : reply.error.code);
        zcl_command_reply_free(&reply);
        json_free(&input);
    }
    return out;
}
struct rt_run { char *body; int64_t ms; int req; };
/* One call against a fresh loopback server; reports body, time, requests. */
static struct rt_run rt_run(enum rt_mode mode, int delay, const char *dir, rt_call_fn call, int64_t arg)
{
    struct rt_server s;
    struct rt_run r = {0};
    if (!rt_server_start(&s, mode, delay)) return r;
    int64_t t0 = rt_now();
    node_rpc_client_init(dir, s.port);
    r.body = call(dir, s.port, arg), r.ms = rt_now() - t0;
    r.req = rt_server_stop(&s);
    return r;
}
static void rt_done(struct rt_run *r, bool ok, const char *name)
{
    rt_expect(ok && r->body, name, r->ms, r->req);
    free(r->body);
}
static void rt_slow_bootstrap(void) { platform_sleep_ms(300); }
static void rt_no_bootstrap(void) {}

/* A real-socket row: want/forbid substrings, time window (max 0 = none), request
 * count (-1 = unchecked), env knobs (default 60s), board bootstrap, cookie kind. */
struct rt_real {
    const char *name, *want, *forbid, *env;
    enum rt_mode mode;
    int delay, min_ms, max_ms, req;
    rt_call_fn call;
    int64_t arg;
    void (*boot)(void);
    bool nodir, fifo;
};
#define RT_EXH "BOARD_OBSERVATION_BUDGET_EXHAUSTED"
static const struct rt_real rt_real_cases[] = {
    { .name = "1ms deadline ends promptly without an answer", .want = "error", .forbid = "retained",
      .max_ms = 150, .req = -1, .call = rt_until, .arg = 1 },
    { .name = "INT64_MAX deadline: no overflow, healthy answer", .want = "retained", .mode = RT_HEALTHY,
      .max_ms = 500, .req = 1, .call = rt_until_at, .arg = INT64_MAX },
    { .name = "healthy: absolute and direct payloads identical", .want = "identical", .mode = RT_HEALTHY, .req = 2, .call = rt_same },
    { .name = "refused port: typed connection-refused error", .want = "connection refused", .req = 0, .call = rt_refused },
    { .name = "direct healthy reply delayed 300ms unchanged", .want = "retained", .mode = RT_HEALTHY,
      .delay = 300, .min_ms = 280, .req = 1, .call = rt_direct },
    { .name = "stall: 200ms absolute ignores 60s env", .want = "did not answer",
      .min_ms = 185, .max_ms = 450, .req = 1, .call = rt_until, .arg = 200 },
    { .name = "drip: bounded by the absolute deadline", .want = "error", .forbid = "retained",
      .mode = RT_DRIP, .min_ms = 105, .max_ms = 350, .req = 1, .call = rt_until, .arg = 120 },
    { .name = "missing cookie: unknown, no request", .want = "auth cookie", .mode = RT_HEALTHY,
      .max_ms = 100, .req = 0, .call = rt_until, .arg = 2000, .nodir = true },
    { .name = "oversized env falls back: direct default path healthy", .want = "retained",
      .env = "99999999999999999999", .mode = RT_HEALTHY, .req = 1, .call = rt_env_default },
    { .name = "40ms + 300ms cookie: no request after expiry (limit: ~300ms cookie read)",
      .want = "during the cookie read", .min_ms = 250, .max_ms = 1500, .req = 0, .call = rt_until, .arg = 40, .fifo = true },
    { .name = "control: relative 40ms + 300ms cookie still sends", .want = "", .min_ms = 250, .req = 1, .call = rt_relative40, .fifo = true },
    { .name = "board observation: healthy data", .want = "PASSED", .mode = RT_HEALTHY, .req = 1, .call = rt_board, .arg = 2000 },
    { .name = "direct board: healthy reply delayed 300ms unchanged", .want = "PASSED", .mode = RT_HEALTHY, .delay = 300, .min_ms = 280, .req = 1, .call = rt_board },
    { .name = "board observation: 300ms reply honestly unknown at FAST cap", .want = "NODE_UNAVAILABLE",
      .mode = RT_HEALTHY, .delay = 300, .min_ms = 230, .max_ms = 450, .req = 1, .call = rt_board, .arg = 2000 },
    { .name = "board: bootstrap 300ms exhausts 40ms with 0 RPC", .want = RT_EXH, .min_ms = 280,
      .max_ms = 1000, .req = 0, .call = rt_board, .arg = 40, .boot = rt_slow_bootstrap },
    { .name = "board observation: missing cookie unknown, no request", .want = "NODE_UNAVAILABLE", .max_ms = 100, .req = 0, .call = rt_board, .arg = 2000, .nodir = true },
    { .name = "board observation: 40ms + 300ms cookie, 0 RPC", .want = RT_EXH, .min_ms = 250,
      .max_ms = 1500, .req = 0, .call = rt_board, .arg = 40, .fifo = true },
};
static bool rt_real_ok(const struct rt_real *c, const struct rt_run *r)
{
    return rt_has(r->body, c->want) && !(c->forbid && rt_has(r->body, c->forbid)) &&
           r->ms >= c->min_ms && (!c->max_ms || r->ms < c->max_ms) && (c->req < 0 || r->req == c->req);
}

static void rt_case_real(const char *dir, const char *nodir)
{
    zcl_native_fleet_board_test_set_bootstrap(rt_no_bootstrap); /* never the real bridge */
    for (size_t i = 0; i < sizeof(rt_real_cases) / sizeof(rt_real_cases[0]); i++) {
        const struct rt_real *c = &rt_real_cases[i];
        struct rt_fifo_writer w;
        char fifo[512];
        const char *d = c->nodir ? nodir : dir;
        if (c->fifo && !rt_fixture(fifo, sizeof(fifo), "fifo", RT_FIFO_COOKIE, &w)) {
            rt_expect(false, "fifo setup", 0, 0);
            continue;
        }
        rt_knob(0, c->env ? c->env : "60000"), rt_knob(1, c->env ? c->env : "60000");
        zcl_native_fleet_board_test_set_bootstrap(c->boot ? c->boot : rt_no_bootstrap);
        struct rt_run r = rt_run(c->mode, c->delay, c->fifo ? fifo : d, c->call, c->arg);
        zcl_native_fleet_board_test_set_bootstrap(rt_no_bootstrap);
        if (c->fifo) pthread_join(w.thread, NULL), test_rm_rf(fifo);
        rt_done(&r, rt_real_ok(c, &r), c->name);
    }
    zcl_native_fleet_board_test_set_bootstrap(NULL);
}
static void rt_noop_signal(int sig) { (void)sig; }
struct rt_signal_sender {
    pthread_t target;
    atomic_bool ready;
    atomic_bool start;
};

/* Ten SIGUSR1s at real 20ms intervals. Sleep coalescing on background Mac
 * threads can exceed the entire 40ms verdict window, so yield against a
 * monotonic schedule for this bounded 200ms stimulus instead. */
static void *rt_signal_loop(void *target)
{
    struct rt_signal_sender *sender = target;
    atomic_store(&sender->ready, true);
    while (!atomic_load(&sender->start)) sched_yield();
    const int64_t start = rt_now();
    for (int i = 1; i <= 10; i++) {
        while (rt_now() < start + i * 20) sched_yield();
        pthread_kill(sender->target, SIGUSR1);
    }
    return NULL;
}

struct rt_connect_wait {
    platform_socket_t fd;
    int interrupted;
};

static int rt_connect_wait_real(int wait_ms, void *ctx)
{
    struct rt_connect_wait *wait = ctx;
    int result = platform_socket_wait_writable(wait->fd, wait_ms);
    if (result < 0 && platform_socket_error_interrupted(platform_socket_last_error()))
        wait->interrupted++;
    return result;
}

static bool rt_connect_eintr_pass(const char *dir, uint16_t port,
                                  platform_socket_t fd, int pass)
{
    pthread_t signaler;
    struct rt_signal_sender sender = { .target = pthread_self() };
    struct rt_connect_wait wait = { .fd = fd };
    if (pthread_create(&signaler, NULL, rt_signal_loop, &sender) != 0) {
        rt_expect(false, "real-signal sender setup", 0, 0);
        return false;
    }
    const int64_t ready_until = rt_now() + 1000;
    while (!atomic_load(&sender.ready) && rt_now() < ready_until)
        sched_yield();
    if (!atomic_load(&sender.ready)) {
        atomic_store(&sender.start, true);
        pthread_join(signaler, NULL);
        rt_expect(false, "real-signal sender ready before deadline measurement", 0, 0);
        return false;
    }
    node_rpc_test_set_connect_wait(rt_connect_wait_real, &wait);
    int64_t t0 = rt_now();
    atomic_store(&sender.start, true);
    char *b = pass ? rt_relative40(dir, port, 0) : rt_until(dir, port, 40);
    int64_t ms = rt_now() - t0;
    node_rpc_test_set_connect_wait(NULL, NULL);
    pthread_join(signaler, NULL);
    printf("  real-signal connect-phase: interrupted=%d\n", wait.interrupted);
    rt_expect(wait.interrupted > 0 && rt_has(b, "connect timed out") && ms >= 35 && ms < 150,
              pass ? "same for the relative-deadline entry"
                   : "40ms + real signals: connect phase keeps original deadline", ms, 0);
    free(b);
    return true;
}

/* A full local stream supplies a real nonwritable descriptor to the production
 * connect-phase loop. TCP backlog saturation is not portable: a kernel may
 * complete handshakes despite the requested accept queue limit. The clock,
 * poll and SIGUSR1 interruptions here are real; only connect readiness is
 * controlled. Healthy TCP connections are exercised by rt_case_real. */
static void rt_case_connect_eintr(const char *dir)
{
    platform_socket_t listener = PLATFORM_SOCKET_INVALID;
    platform_socket_t pair[2] = { PLATFORM_SOCKET_INVALID, PLATFORM_SOCKET_INVALID };
    uint16_t port = 0;
    bool full = false;
    if (!rt_listen(&listener, &port, 4) || !platform_socket_pair(pair) ||
        !platform_socket_set_nonblocking(pair[0], true)) {
        rt_expect(false, "real-signal connect-phase fixture setup", 0, 0);
        goto cleanup;
    }
    const char bytes[4096] = {0};
    for (int i = 0; i < 1024; i++) {
        ssize_t sent = send(pair[0], bytes, sizeof(bytes), MSG_NOSIGNAL);
        if (sent < 0) {
            full = platform_socket_error_would_block(platform_socket_last_error());
            break;
        }
    }
    if (!full || platform_socket_wait_writable(pair[0], 0) != 0) {
        rt_expect(false, "real-signal connect-phase descriptor remains nonwritable", 0, 0);
        goto cleanup;
    }
    struct sigaction act = { .sa_handler = rt_noop_signal }, old;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGUSR1, &act, &old) != 0) {
        rt_expect(false, "real-signal handler setup", 0, 0);
        goto cleanup;
    }
    for (int pass = 0; pass < 2; pass++) {
        if (!rt_connect_eintr_pass(dir, port, pair[0], pass))
            break;
    }
    sigaction(SIGUSR1, &old, NULL);
cleanup:
    node_rpc_test_set_connect_wait(NULL, NULL);
    platform_socket_close(pair[0]);
    platform_socket_close(pair[1]);
    platform_socket_close(listener);
}

/* Scripted transport (node_rpc_test_script): fake clock and polls drive the production
 * loops; `ww`/`wr` = first writable/readable wait arguments expected (0 = unchecked). */
struct rt_io_case {
    const char *name;
    enum rt_mode mode;
    int64_t until;
    long connect_ms; /* 0 = 2000 */
    struct node_rpc_test_script s; /* s.now 0 = 1000 */
    const char *want;
    int req, ww[5], wr[5];
    bool grow_stops; /* no readable wait follows the buffer growth */
};
static bool rt_waits_match(const int *want, const int *got, int calls)
{
    for (int i = 0; i < 5 && want[i]; i++) if (i >= calls || i >= 8 || got[i] != want[i]) return false;
    return true;
}
static void rt_case_scripted(const char *dir, const struct rt_io_case *c)
{
    struct rt_server srv;
    struct node_rpc_test_script sc = c->s; /* a copy: the loops advance its clock and counters */
    if (!rt_server_start(&srv, c->mode, 0)) { rt_expect(false, c->name, 0, 0); return; }
    if (!sc.now) sc.now = 1000;
    node_rpc_test_set_script(&sc);
    int64_t t0 = rt_now();
    char *b = node_rpc_call_at_until(dir, srv.port, "fleet_board", "[]", c->connect_ms ? c->connect_ms : 2000, c->until);
    node_rpc_test_set_script(NULL);
    int64_t ms = rt_now() - t0;
    /* Give the server time to read whatever the client sent before counting. */
    for (int64_t end = rt_now() + (c->req ? 1000 : 60); rt_now() < end && (!c->req || atomic_load(&srv.requests) < c->req);)
        platform_sleep_ms(2);
    int req = rt_server_stop(&srv);
    rt_expect(rt_has(b, c->want) && req == c->req && rt_waits_match(c->ww, sc.ww, sc.nw) &&
              rt_waits_match(c->wr, sc.wr, sc.nr) && (!c->grow_stops || (sc.grown_at && sc.nr == sc.grown_at)), c->name, ms, req);
    free(b);
}

#define H RT_HEALTHY
#define RT_NOCOOKIE(nm, at) { nm, .until = at, .want = "before the cookie read" }
static const struct rt_io_case rt_io_cases[] = {
    RT_NOCOOKIE("deadline zero: no request", 0),
    RT_NOCOOKIE("deadline INT64_MIN: no request", INT64_MIN),
    RT_NOCOOKIE("deadline equal to now: no request", 1000),
    { "clock reaches the deadline before the cookie read", .until = 1100, .s.seq = {1100}, .want = "before the cookie read" },
    { "clock crosses the deadline during the cookie read", .until = 1100, .s.seq = {1000, 1100}, .want = "during the cookie read" },
    { "deadline passes before connect", .until = 1100, .s.seq = {1000, 1000, 1100}, .want = "before connect" },
    { "deadline passes before transmit", .until = 1100, .s.seq = {1000, 1000, 1000, 1000, 1100}, .want = "before transmit" },
    { "connect EINTR storm keeps the original deadline", .until = 1040, .s.pending = true,
      .s.w = {{'i', 20}, {'i', 20}}, .want = "connect timed out", .ww = {40, 20} },
    { "connect readiness after the phase deadline is a timeout", .until = 1200, .connect_ms = 30,
      .s.pending = true, .s.w = {{'r', 31}}, .s.r = {{'r', 500}}, .want = "connect timed out", .ww = {30} },
    { "connect readiness at the phase deadline is a timeout", .until = 1200, .connect_ms = 30,
      .s.pending = true, .s.w = {{'r', 30}}, .s.r = {{'r', 500}}, .want = "connect timed out", .ww = {30} },
    { "connect readiness 1ms inside the phase deadline succeeds", H, .until = 1200, .connect_ms = 30,
      .s.pending = true, .s.w = {{'r', 29}}, .want = "retained", .req = 1, .ww = {30, 171, 171}, .wr = {171} },
    { "connect zero-timeout wake then readiness, one deadline", H, .until = 1100, .s.pending = true,
      .s.w = {{'z', 10}, {'r', 0}}, .want = "retained", .req = 1, .ww = {100, 90, 90, 90}, .wr = {90} },
    { "send readiness after the deadline: no byte", .until = 1100, .s.w = {{'r', 200}},
      .want = "before transmit", .ww = {100} },
    { "send EINTR storm then healthy answer", H, .until = 1100, .s.w = {{'i', 20}, {'i', 20}},
      .want = "retained", .req = 1, .ww = {100, 80, 60, 60}, .wr = {60} },
    { "send EINTR to the deadline: no byte", .until = 1040, .s.w = {{'i', 20}, {'i', 25}},
      .want = "before transmit", .ww = {40, 20} },
    { "receive spurious readiness keeps the deadline", .until = 1040, .s.r = {{'r', 15}, {'r', 15}, {'r', 15}},
      .want = "did not answer", .req = 1, .wr = {40, 25, 10} },
    { "receive EINTR then healthy answer", H, .until = 1100, .s.r = {{'i', 10}},
      .want = "retained", .req = 1, .wr = {100, 90} },
    { "receive readiness after the deadline, bytes queued: not read", H, .until = 1100,
      .s.r = {{'q', 200}}, .want = "did not answer", .req = 1, .wr = {100} },
    { "receive readiness at the deadline, bytes queued: not read", H, .until = 1100,
      .s.r = {{'q', 100}}, .want = "did not answer", .req = 1, .wr = {100} },
    { "receive readiness 1ms before the deadline, bytes queued: read", H, .until = 1100,
      .s.r = {{'q', 99}}, .want = "retained", .req = 1, .wr = {100, 1} },
    { "receive buffer growth keeps the deadline when the allocation is not slow", .mode = RT_BIG,
      .until = 1100, .want = "retained", .req = 1, .wr = {100} },
    { "receive buffer growth: a slow allocation stops the wait at zero", .mode = RT_BIG, .until = 1100,
      .s.alloc_adv_ms = 100, .want = "truncated reply", .req = 1, .wr = {100}, .grow_stops = true },
    { "receive buffer growth: a slow allocation that stays inside the deadline", .mode = RT_BIG,
      .until = 1100, .s.alloc_adv_ms = 49, .want = "retained", .req = 1, .wr = {100} },
    { "INT64_MIN..INT64_MAX: every wait saturates to INT32_MAX", H, .until = INT64_MAX, .s.now = INT64_MIN,
      .want = "retained", .req = 1, .ww = {INT32_MAX, INT32_MAX}, .wr = {INT32_MAX} },
    { "INT64_MAX-5: connect phase saturates, readiness keeps 5ms", H, .until = INT64_MAX, .connect_ms = 60000,
      .s.now = INT64_MAX - 5, .s.pending = true, .s.w = {{'r', 0}}, .want = "retained", .req = 1,
      .ww = {5, 5, 5}, .wr = {5} },
};
#undef H

static int check_rpc_absolute_deadline_suite(void)
{
    char dir[512] = "", nodir[512] = "";
    printf("rpc absolute deadline transport and board observation:\n");
    g_rt_failures = 0, rt_save();
    node_rpc_client_set_test_hook(NULL), node_rpc_test_set_script(NULL);
    if (!rt_fixture(dir, sizeof(dir), "abs", RT_FILE_COOKIE, NULL) ||
        !rt_fixture(nodir, sizeof(nodir), "absno", RT_NO_COOKIE, NULL))
        rt_expect(false, "fixture setup", 0, 0);
    else {
        rt_case_arithmetic();
        rt_case_real(dir, nodir);
        rt_case_connect_eintr(dir);
        for (size_t i = 0; i < sizeof(rt_io_cases) / sizeof(rt_io_cases[0]); i++)
            rt_case_scripted(dir, &rt_io_cases[i]);
    }
    test_rm_rf(dir), test_rm_rf(nodir);
    node_rpc_client_set_test_hook(NULL), node_rpc_test_set_script(NULL);
    rt_restore();
    return g_rt_failures;
}

int check_rpc_tls_without_env_and_port_oracle(void)
{
    int failures = 0;

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
         * core.consensus.producer-session.retire refuses a live node on. It
         * must track the kernel's view exactly: true only while a loopback
         * listener holds the port, false once it closes, and false for ports
         * no listener can hold. node_rpc_call* paths cannot answer this;
         * they return non-NULL error bodies on refused connects. */
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

    failures += check_rpc_absolute_deadline_suite();
    return failures;
}

#if defined(ZCL_TESTING)
extern const char *(*db_iter_value_raw_test_hook)(void *iter, size_t *vallen);

static size_t db_test_reported_len;
static const char db_test_payload[64] = {0};

static const char *db_test_raw_fetch(void *iter, size_t *vallen)
{
    (void)iter;
    *vallen = db_test_reported_len;
    return db_test_payload;
}

/* db_iter_value growth guard: a reported value length so large that
 * *vallen + 256 is unrepresentable must be refused with the reusable
 * deobfuscation buffer untouched. The raw fetch runs through the
 * ZCL_TESTING hook so the edge is exercised without a giant allocation.
 * Pre-fix the capacity addition wrapped and the deobfuscation overflowed
 * the tiny wrapped buffer. */
int check_rpc_dbwrapper_deobf_growth_guard(void)
{
    int failures = 0;
    char *keep = malloc(8);
    if (!keep) {
        printf("dbwrapper deobf growth guard... FAIL (fixture allocation)\n");
        return 1;
    }
    memset(keep, 0, 8);
    struct db_iterator it = {0};
    it.iter = NULL; /* the hook intercepts before any deref */
    it.obfuscate_key_len = 4;
    memset(it.obfuscate_key, 0x5a, sizeof(it.obfuscate_key));
    it.deobf_buf = keep;
    it.deobf_cap = 8;
    db_iter_value_raw_test_hook = db_test_raw_fetch;

    printf("dbwrapper deobf unrepresentable growth refused... ");
    db_test_reported_len = SIZE_MAX - 255; /* one past the edge */
    size_t vallen = 0;
    const char *got = db_iter_value(&it, &vallen);
    if (got == NULL && vallen == SIZE_MAX - 255 && it.deobf_buf == keep &&
        it.deobf_cap == 8)
        printf("OK\n");
    else {
        printf("FAIL\n");
        failures++;
    }

    printf("dbwrapper deobf representable growth still served... ");
    db_test_reported_len = 32;
    got = db_iter_value(&it, &vallen);
    if (got != NULL && got != keep && vallen == 32)
        printf("OK\n");
    else {
        printf("FAIL\n");
        failures++;
    }

    if (it.deobf_buf != keep) free(it.deobf_buf);
    it.deobf_buf = NULL;
    db_iter_value_raw_test_hook = NULL;
    return failures;
}
#endif
