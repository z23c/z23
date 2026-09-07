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
#include <unistd.h>
#include "test/test_rpc_priv.h"


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

