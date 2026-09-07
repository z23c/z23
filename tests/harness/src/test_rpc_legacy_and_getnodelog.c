/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * rpc scenario checks: legacy RPC parse/timeout tables and the
 * getnodelog since/level/regex family, exercised through the ERE
 * matcher.
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


struct rpc_fake_clock {
    int64_t wall_ms;
};

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

int check_rpc_legacy_rpc_parse_results(void)
{
    int failures = 0;

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


    return failures;
}

int check_rpc_legacy_rpc_timeout_table_warmup(void)
{
    int failures = 0;

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

    return failures;
}

static bool check_rpc_getnodelog_write_since_log(const char *log_path)
{
            FILE *fp = fopen(log_path, "w");
            bool ok = fp != NULL;
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
            return ok;
}

static bool check_rpc_getnodelog_push_since_params(struct json_value *params)
{
    bool ok = true;
            json_set_array(params);
            struct json_value v;
            json_init(&v);
            json_set_str(&v, "node_log_since");
            ok = ok && json_push_back(params, &v);
            json_set_int(&v, 60);
            ok = ok && json_push_back(params, &v);
            json_set_int(&v, 10);
            ok = ok && json_push_back(params, &v);
            json_set_str(&v, "all");
            ok = ok && json_push_back(params, &v);
            json_free(&v);
    return ok;
}

static bool check_rpc_getnodelog_since_lines_ok(const struct json_value *result)
{
            const struct json_value *lines = json_get(result, "lines");
            const struct json_value *skipped =
                json_get(result, "timestamped_lines_skipped");
            const struct json_value *undated =
                json_get(result, "undated_lines_included");
            const struct json_value *complete =
                json_get(result, "since_filter_complete");
            bool ok = lines && lines->type == JSON_ARR && json_size(lines) == 2;
            ok = ok && strstr(json_get_str(json_at(lines, 0)),
                              "node_log_since_recent") != NULL;
            ok = ok && strstr(json_get_str(json_at(lines, 1)),
                              "node_log_since_undated") != NULL;
            ok = ok && skipped && json_get_int(skipped) == 1;
            ok = ok && undated && json_get_int(undated) == 1;
            ok = ok && complete && !json_get_bool(complete);
    return ok;
}

int check_rpc_getnodelog_since_secs(void)
{
    int failures = 0;

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
        if (ok)
            ok = check_rpc_getnodelog_write_since_log(log_path);

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

            ok = ok && check_rpc_getnodelog_push_since_params(&params);
        }

        if (ok) {
            struct rpc_table tbl;
            rpc_table_init(&tbl);
            register_diagnostics_rpc_commands(&tbl);
            ok = rpc_table_execute(&tbl, "getnodelog", &params, &result);
        }

        if (ok)
            ok = check_rpc_getnodelog_since_lines_ok(&result);

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

    return failures;
}

static bool check_rpc_getnodelog_write_level_log(const char *log_path)
{
            FILE *fp = fopen(log_path, "w");
            bool ok = fp != NULL;
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
            return ok;
}

static bool check_rpc_getnodelog_level_warn_lines(
    const struct json_value *result)
{
                const struct json_value *lines = json_get(result, "lines");
                bool ok = lines && lines->type == JSON_ARR && json_size(lines) == 3;
                ok = ok && strstr(json_get_str(json_at(lines, 0)),
                                  "nlv_legacy_warn") != NULL;
                ok = ok && strstr(json_get_str(json_at(lines, 1)),
                                  "nlv_warn") != NULL;
                ok = ok && strstr(json_get_str(json_at(lines, 2)),
                                  "nlv_err") != NULL;
                return ok;
}

static bool check_rpc_getnodelog_level_warn(void)
{
    bool ok = true;
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
            if (ok)
                ok = check_rpc_getnodelog_level_warn_lines(&result);
            json_free(&params);
            json_free(&result);

    return ok;
}

static bool check_rpc_getnodelog_level_error_lines(
    const struct json_value *result)
{
                const struct json_value *lines = json_get(result, "lines");
                bool ok = lines && lines->type == JSON_ARR && json_size(lines) == 1;
                ok = ok && strstr(json_get_str(json_at(lines, 0)),
                                  "nlv_err") != NULL;
                return ok;
}

static bool check_rpc_getnodelog_level_error(void)
{
    bool ok = true;
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
            if (ok)
                ok = check_rpc_getnodelog_level_error_lines(&result);
            json_free(&params);
            json_free(&result);

    return ok;
}

static bool check_rpc_getnodelog_level_error_uc_lines(
    const struct json_value *result)
{
                const struct json_value *lines = json_get(result, "lines");
                bool ok = lines && lines->type == JSON_ARR && json_size(lines) == 1;
                ok = ok && strstr(json_get_str(json_at(lines, 0)),
                                  "nlv_err") != NULL;
                return ok;
}

static bool check_rpc_getnodelog_level_error_uc(void)
{
    bool ok = true;
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
            if (ok)
                ok = check_rpc_getnodelog_level_error_uc_lines(&result);
            json_free(&params);
            json_free(&result);

    return ok;
}

static bool check_rpc_getnodelog_level_unknown_rc(bool ok, bool rc,
    const struct json_value *result)
{
            ok = ok && !rc && result->type == JSON_STR &&
                 strstr(json_get_str(result), "bad level") != NULL;
            return ok;
}

static bool check_rpc_getnodelog_level_unknown(void)
{
    bool ok = true;
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
            ok = check_rpc_getnodelog_level_unknown_rc(ok, rc, &result);
            json_free(&params);
            json_free(&result);

    return ok;
}

static bool check_rpc_getnodelog_write_regex_log(const char *log_path)
{
            FILE *fp = fopen(log_path, "w");
            bool ok = fp != NULL;
            if (fp) {
                ok = fputs("[net] nre_alpha connected\n", fp) >= 0;
                ok = ok && fputs("[sync] nre_beta stalled\n", fp) >= 0;
                ok = ok && fputs("[rpc] nre_gamma served\n", fp) >= 0;
                ok = ok && fclose(fp) == 0;
            }
            return ok;
}

static bool check_rpc_getnodelog_regex_alt_lines(
    const struct json_value *result)
{
                const struct json_value *lines = json_get(result, "lines");
                bool ok = lines && lines->type == JSON_ARR && json_size(lines) == 2;
                ok = ok && strstr(json_get_str(json_at(lines, 0)),
                                  "nre_gamma") != NULL;
                ok = ok && strstr(json_get_str(json_at(lines, 1)),
                                  "nre_alpha") != NULL;
                return ok;
}

static bool check_rpc_getnodelog_regex_alternation(void)
{
    bool ok = true;
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
            if (ok)
                ok = check_rpc_getnodelog_regex_alt_lines(&result);
            json_free(&params);
            json_free(&result);

    return ok;
}

static bool check_rpc_getnodelog_regex_refused(void)
{
    bool ok = true;
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

    return ok;
}

int check_rpc_getnodelog_level_filter(void)
{
    int failures = 0;

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
        if (ok)
            ok = check_rpc_getnodelog_write_level_log(log_path);

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
        if (ok)
            ok = check_rpc_getnodelog_level_warn();

        /* level=error keeps only the ERROR line. */
        if (ok)
            ok = check_rpc_getnodelog_level_error();

        /* level=ERROR (uppercase) is accepted — case-insensitive parse. */
        if (ok)
            ok = check_rpc_getnodelog_level_error_uc();

        /* Unknown level is rejected loudly (string error body), never a
         * silent fall-through to "all". */
        if (ok)
            ok = check_rpc_getnodelog_level_unknown();

        diagnostics_controller_set_state(NULL, "");
        if (clock_installed)
            clock_reset_default();
        if (dir) {
            unlink(log_path);
            rmdir(dir);
        }

        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

int check_rpc_ere_matcher(void)
{
    int failures = 0;

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

    return failures;
}

int check_rpc_getnodelog_regex(void)
{
    int failures = 0;

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
        if (ok)
            ok = check_rpc_getnodelog_write_regex_log(log_path);
        if (ok)
            diagnostics_controller_set_state(NULL, dir);

        /* Alternation + anchor, the shape an operator actually types. */
        if (ok)
            ok = check_rpc_getnodelog_regex_alternation();

        /* An unhonourable pattern is an error, not an empty result set. */
        if (ok)
            ok = check_rpc_getnodelog_regex_refused();

        diagnostics_controller_set_state(NULL, "");
        if (dir) {
            unlink(log_path);
            rmdir(dir);
        }
        if (ok) printf("OK\n"); else { printf("FAIL\n"); failures++; }
    }

    return failures;
}

