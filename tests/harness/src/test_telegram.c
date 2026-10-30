/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: ops.telegram leaves against a scripted transport and a loopback
 * Bot API: chunking, secret refusal, offset persistence, allowlist, 409,
 * credential modes, configure, and a canary token that must never surface. */
#include "test/test_core.h"
#include "command/native_command.h"
#include "command/native_telegram.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "mcp/mcp_policy.h"
#include "platform/process_lock.h"
#include "platform/temp_directory.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(__linux__) || defined(__APPLE__)
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define TGT_CANARY "7777777777:CANARYtokenCANARYtokenCANARYtoken1234"
#define TGT_ENV_TEXT \
    "TELEGRAM_BOT_TOKEN=" TGT_CANARY "\nTELEGRAM_CHAT_ID=4242\nTELEGRAM_ALLOW_FROM=99, 100\n"
#define TGT_BODY 20000
#define TGT_CALLS 8

struct tgt_fake {
    int calls;
    char method[TGT_CALLS][24];
    char body[TGT_CALLS][TGT_BODY];
    int script_status;
    const char *script_body;
    bool fail_transport;
    int next_id;
};

static struct tgt_fake g_fake;
static struct zcl_command_reply r;
static bool clean;
static char g_root[PLATFORM_TEMP_PATH_MAX];
static char g_env[PLATFORM_TEMP_PATH_MAX + 32];

static bool tgt_respond(struct tg_response *out, int status, const char *body)
{
    out->status = status;
    out->body = strdup(body);
    out->len = strlen(body);
    return out->body != NULL;
}

static bool tgt_transport(void *ctx, const char *token, const char *method, const char *body,
                          int timeout_s, struct tg_response *out)
{
    struct tgt_fake *f = ctx;
    char text[160];
    (void)timeout_s;
    if (strcmp(token, TGT_CANARY) != 0 || f->calls >= TGT_CALLS)
        return false;
    snprintf(f->method[f->calls], sizeof(f->method[0]), "%s", method);
    snprintf(f->body[f->calls], TGT_BODY, "%s", body);
    f->calls++;
    if (f->fail_transport)
        return false;
    if (f->script_body) {
        const char *scripted = f->script_body;
        f->script_body = NULL;
        return tgt_respond(out, f->script_status, scripted);
    }
    if (!strcmp(method, "sendMessage")) {
        snprintf(text, sizeof(text), "{\"ok\":true,\"result\":{\"message_id\":%d}}", ++f->next_id);
        return tgt_respond(out, 200, text);
    }
    if (!strcmp(method, "getMe"))
        return tgt_respond(out, 200,
                           "{\"ok\":true,\"result\":{\"id\":7777777777,\"is_bot\":true,"
                           "\"first_name\":\"Vibebot\",\"username\":\"Vibecodercbot\"}}");
    return tgt_respond(out, 200, "{\"ok\":true,\"result\":[]}");
}

static void tgt_script(int status, const char *body)
{
    g_fake.script_status = status;
    g_fake.script_body = body;
}

static bool tgt_write_file(const char *path, const char *text, mode_t mode)
{
    FILE *f = fopen(path, "w");
    if (!f)
        return false;
    bool ok = fputs(text, f) >= 0;
    ok = fclose(f) == 0 && ok;
    return ok && chmod(path, mode) == 0;
}

static bool tgt_setup(void)
{
    char state[PLATFORM_TEMP_PATH_MAX + 16];
    if (!platform_temp_directory_create("z23-telegram-test", g_root, sizeof(g_root)))
        return false;
    snprintf(g_env, sizeof(g_env), "%s/telegram.env", g_root);
    snprintf(state, sizeof(state), "%s/state", g_root);
    memset(&g_fake, 0, sizeof(g_fake));
    setenv("Z23_TELEGRAM_ENV", g_env, 1);
    setenv("XDG_STATE_HOME", state, 1);
    unsetenv("Z23_TELEGRAM_API");
    tg_transport_override(tgt_transport, &g_fake);
    return tgt_write_file(g_env, TGT_ENV_TEXT, 0600);
}

/* Run one leaf with a JSON input; the serialized reply must never hold the canary. */
static bool tgt_call(const char *path, const char *input_json, struct zcl_command_reply *reply,
                     bool *canary_free)
{
    struct json_value input = {0};
    char out[65536];
    zcl_command_reply_init(reply, NULL);
    const struct zcl_command_spec *spec = zcl_command_registry_find(zcl_command_catalog(), path, NULL);
    if (!spec || !spec->handler || !json_read(&input, input_json, strlen(input_json)))
        return false;
    struct zcl_command_request request = {.spec = spec, .input = &input};
    spec->handler(&request, reply);
    size_t n = json_write(&reply->data, out, sizeof(out));
    snprintf(out + (n < sizeof(out) - 1 ? n : sizeof(out) - 1), sizeof(out) - (n < sizeof(out) - 1 ? n : sizeof(out) - 1),
             "%s%s%s%s", reply->error.code, reply->error.message, reply->error.evidence, reply->error.next_action);
    *canary_free = strstr(out, "CANARYtoken") == NULL;
    json_free(&input);
    return true;
}

static bool tgt_failed(const struct zcl_command_reply *r, const char *code)
{
    return r->status == ZCL_COMMAND_STATUS_FAILED && !strcmp(r->error.code, code);
}

static int64_t tgt_int(const struct zcl_command_reply *r, const char *key)
{
    return json_get_int(json_get(&r->data, key));
}

static int tgt_case_0(void)
{
    int failures = 0;
    char *text = malloc(9001);
    char input[9200];
    memset(text, 'a', 9000);
    text[9000] = '\0';
    snprintf(input, sizeof(input), "{\"text\":\"%s\"}", text);
    TEST_CASE("telegram send splits 9000 characters into 3 messages") {
        memset(&g_fake, 0, sizeof(g_fake));
        ASSERT(tgt_call("ops.telegram.send", input, &r, &clean));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(tgt_int(&r, "chunks"), 3);
        ASSERT_EQ(g_fake.calls, 3);
        ASSERT(clean);
        struct json_value b = {0};
        ASSERT(json_read(&b, g_fake.body[0], strlen(g_fake.body[0])));
        ASSERT_EQ(strlen(json_get_str(json_get(&b, "text"))), 4096);
        ASSERT_EQ(json_get_int(json_get(&b, "chat_id")), 4242);
        json_free(&b);
        ASSERT_EQ(json_get_int(json_at(json_get(&r.data, "message_ids"), 2)), 3);
        json_free(&r.data);
    } TEST_END
    free(text);
    return failures;
}

static int tgt_case_1(void)
{
    int failures = 0;
    TEST_CASE("telegram chunks keep UTF-8 whole and count UTF-16 units") {
        char two[8200], four[8200];
        for (int i = 0; i < 4097; i++)
            memcpy(two + 2 * i, "\xC3\xA9", 2);
        ASSERT_EQ(tg_chunk_len(two, 2 * 4097), 2 * 4096);
        for (int i = 0; i < 2049; i++)
            memcpy(four + 4 * i, "\xF0\x9F\x98\x80", 4);
        ASSERT_EQ(tg_chunk_len(four, 4 * 2049), 4 * 2048);
        ASSERT(tg_utf8_valid("caf\xC3\xA9", 5));
        ASSERT(!tg_utf8_valid("\xC3", 1));
        ASSERT(!tg_utf8_valid("\xED\xA0\x80", 3));
    } TEST_END
    return failures;
}

static int tgt_case_2(void)
{
    int failures = 0;
    TEST_CASE("telegram send refuses secrets before any request") {
        static const char *const bad[] = {
            "{\"text\":\"my seed phrase is above\"}",
            "{\"text\":\"token 7777777777:CANARYtokenCANARYtokenCANARYtoken1234\"}",
            "{\"text\":\"key sk-abcdefghijklmnopqrstuvwxyz0123\"}", /* api-key-example-ok */
            "{\"text\":\"Bearer abcdefghijklmnopqrstuvwxyz\"}", /* api-key-example-ok */
            "{\"text\":\"see abcdefghij.onion now\"}",
            "{\"text\":\"1234567890:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}",
        };
        memset(&g_fake, 0, sizeof(g_fake));
        for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
            ASSERT(tgt_call("ops.telegram.send", bad[i], &r, &clean));
            ASSERT(tgt_failed(&r, "TELEGRAM_SECRET_REFUSED"));
            ASSERT(clean);
        }
        ASSERT_EQ(g_fake.calls, 0);
    } TEST_END
    return failures;
}

static int tgt_case_3(void)
{
    int failures = 0;
    TEST_CASE("telegram send idempotency key returns the first send") {
        memset(&g_fake, 0, sizeof(g_fake));
        ASSERT(tgt_call("ops.telegram.send", "{\"text\":\"hello\",\"idempotency_key\":\"job-1\"}", &r, &clean));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(g_fake.calls, 1);
        json_free(&r.data);
        ASSERT(tgt_call("ops.telegram.send", "{\"text\":\"hello\",\"idempotency_key\":\"job-1\"}", &r, &clean));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(json_get_bool(json_get(&r.data, "duplicate")));
        ASSERT_EQ(g_fake.calls, 1);
        json_free(&r.data);
        ASSERT(tgt_call("ops.telegram.send", "{\"text\":\"x\",\"idempotency_key\":\"bad key\"}", &r, &clean));
        ASSERT(tgt_failed(&r, "TELEGRAM_BAD_KEY"));
    } TEST_END
    return failures;
}

static int tgt_case_4(void)
{
    int failures = 0;
    TEST_CASE("telegram send only reaches allowlisted chats and reports API errors safely") {
        memset(&g_fake, 0, sizeof(g_fake));
        ASSERT(tgt_call("ops.telegram.send", "{\"text\":\"hi\",\"chat_id\":555}", &r, &clean));
        ASSERT(tgt_failed(&r, "TELEGRAM_CHAT_NOT_ALLOWED"));
        ASSERT_EQ(g_fake.calls, 0);
        ASSERT(tgt_call("ops.telegram.send", "{\"text\":\"hi\",\"chat_id\":99}", &r, &clean));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        json_free(&r.data);
        tgt_script(400, "{\"ok\":false,\"error_code\":400,\"description\":\"Bad Request: " TGT_CANARY " chat not found\"}");
        ASSERT(tgt_call("ops.telegram.send", "{\"text\":\"hi\"}", &r, &clean));
        ASSERT(tgt_failed(&r, "TELEGRAM_REJECTED"));
        ASSERT(clean);
        g_fake.fail_transport = true;
        ASSERT(tgt_call("ops.telegram.send", "{\"text\":\"hi\"}", &r, &clean));
        ASSERT(tgt_failed(&r, "TELEGRAM_UNREACHABLE"));
        ASSERT(clean);
        g_fake.fail_transport = false;
    } TEST_END
    return failures;
}

static const char updates[] =
        "{\"ok\":true,\"result\":["
        "{\"update_id\":10,\"message\":{\"message_id\":1,\"date\":1,\"text\":\"hello\","
        "\"from\":{\"id\":4242,\"username\":\"owner\"},\"chat\":{\"id\":4242,\"type\":\"private\"}}},"
        "{\"update_id\":11,\"message\":{\"message_id\":2,\"date\":2,\"text\":\"stranger\","
        "\"from\":{\"id\":555},\"chat\":{\"id\":555,\"type\":\"private\"}}},"
        "{\"update_id\":12,\"message\":{\"message_id\":3,\"date\":3,\"text\":\"in a group\","
        "\"from\":{\"id\":4242},\"chat\":{\"id\":-9,\"type\":\"group\"}}}]}";

static int tgt_case_5(void)
{
    int failures = 0;
    TEST_CASE("telegram inbox keeps allowlisted DMs, drops strangers, persists the offset") {
        memset(&g_fake, 0, sizeof(g_fake));
        tgt_script(200, updates);
        ASSERT(tgt_call("ops.telegram.inbox", "{\"wait_s\":0}", &r, &clean));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_EQ(tgt_int(&r, "count"), 1);
        ASSERT_EQ(tgt_int(&r, "dropped"), 2);
        ASSERT_EQ(tgt_int(&r, "next_offset"), 13);
        ASSERT_STR_EQ(json_get_str(json_get(json_at(json_get(&r.data, "messages"), 0), "text")), "hello");
        ASSERT(strstr(g_fake.body[0], "\"offset\":0") != NULL);
        json_free(&r.data);
        ASSERT(tgt_call("ops.telegram.inbox", "{}", &r, &clean));
        ASSERT(strstr(g_fake.body[1], "\"offset\":13") != NULL);
        ASSERT_EQ(tgt_int(&r, "count"), 0);
        ASSERT(clean);
        json_free(&r.data);
    } TEST_END
    return failures;
}

static int tgt_case_6(void)
{
    int failures = 0;
    TEST_CASE("telegram inbox maps 409 to POLLER_CONFLICT and keeps the offset") {
        tgt_script(409, "{\"ok\":false,\"error_code\":409,\"description\":\"Conflict: terminated by other getUpdates request\"}");
        ASSERT(tgt_call("ops.telegram.inbox", "{}", &r, &clean));
        ASSERT(tgt_failed(&r, "POLLER_CONFLICT"));
        ASSERT(strstr(r.error.message, "another host or process") != NULL);
        ASSERT(tgt_call("ops.telegram.inbox", "{}", &r, &clean));
        ASSERT(strstr(g_fake.body[g_fake.calls - 1], "\"offset\":13") != NULL);
        json_free(&r.data);
    } TEST_END
    return failures;
}

static int tgt_case_7(void)
{
    int failures = 0;
    TEST_CASE("telegram inbox refuses while a local poll lock is held") {
        char dir[1100], lock_path[1200];
        struct platform_process_lock lock;
        int before = g_fake.calls;
        ASSERT(tg_state_dir(dir, sizeof(dir)));
        snprintf(lock_path, sizeof(lock_path), "%s/poll.lock", dir);
        platform_process_lock_init(&lock);
        ASSERT(platform_process_lock_try_acquire(&lock, lock_path, true));
        ASSERT(tgt_call("ops.telegram.inbox", "{}", &r, &clean));
        ASSERT(tgt_failed(&r, "POLL_LOCKED"));
        ASSERT_EQ(g_fake.calls, before);
        ASSERT(tgt_call("ops.telegram.status", "{}", &r, &clean));
        ASSERT(json_get_bool(json_get(&r.data, "poll_lock_held")));
        json_free(&r.data);
        platform_process_lock_release(&lock);
    } TEST_END
    return failures;
}

static int tgt_status_case(void)
{
    int failures = 0;
    TEST_CASE("telegram status reports the bot and never the token") {
        memset(&g_fake, 0, sizeof(g_fake));
        ASSERT(tgt_call("ops.telegram.status", "{}", &r, &clean));
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&r.data, "bot"), "username")), "Vibecodercbot");
        ASSERT(json_get_bool(json_get(&r.data, "chat_configured")));
        ASSERT_EQ(tgt_int(&r, "allow_count"), 3);
        ASSERT(!json_get_bool(json_get(&r.data, "poll_lock_held")));
        ASSERT(clean);
        json_free(&r.data);
    } TEST_END
    return failures;
}

static int tgt_case_9(void)
{
    int failures = 0;
    TEST_CASE("telegram refuses a group- or world-readable credentials file") {
        memset(&g_fake, 0, sizeof(g_fake));
        ASSERT(chmod(g_env, 0644) == 0);
        ASSERT(tgt_call("ops.telegram.status", "{}", &r, &clean));
        ASSERT(tgt_failed(&r, "TELEGRAM_CREDENTIALS_NOT_PRIVATE"));
        ASSERT(tgt_call("ops.telegram.send", "{\"text\":\"hi\"}", &r, &clean));
        ASSERT(tgt_failed(&r, "TELEGRAM_CREDENTIALS_NOT_PRIVATE"));
        ASSERT(chmod(g_env, 0640) == 0);
        ASSERT(tgt_call("ops.telegram.inbox", "{}", &r, &clean));
        ASSERT(tgt_failed(&r, "TELEGRAM_CREDENTIALS_NOT_PRIVATE"));
        ASSERT_EQ(g_fake.calls, 0);
        ASSERT(clean);
        ASSERT(chmod(g_env, 0600) == 0);
        ASSERT(unlink(g_env) == 0);
        ASSERT(tgt_call("ops.telegram.status", "{}", &r, &clean));
        ASSERT(tgt_failed(&r, "TELEGRAM_NOT_CONFIGURED"));
    } TEST_END
    return failures;
}

static int tgt_case_10(void)
{
    int failures = 0;
    TEST_CASE("telegram configure writes mode 0600 and never echoes the token") {
        static const char fresh[] =
            "TELEGRAM_BOT_TOKEN=1234567890:CANARYtokenFRESHFRESHFRESHFRESH12\nTELEGRAM_CHAT_ID=4242\n";
        char nested[PLATFORM_TEMP_PATH_MAX + 64];
        struct stat st;
        char out[4096];
        snprintf(nested, sizeof(nested), "%s/home/.config/z23/telegram.env", g_root);
        char home[PLATFORM_TEMP_PATH_MAX + 16];
        snprintf(home, sizeof(home), "%s/home", g_root);
        ASSERT(mkdir(home, 0700) == 0);
        setenv("Z23_TELEGRAM_ENV", nested, 1);
        zcl_command_reply_init(&r, NULL);
        tg_configure_text(fresh, &r);
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT(stat(nested, &st) == 0);
        ASSERT_EQ(st.st_mode & 0777, 0600);
        size_t n = json_write(&r.data, out, sizeof(out));
        ASSERT(n < sizeof(out));
        ASSERT(strstr(out, "CANARYtoken") == NULL);
        json_free(&r.data);
        zcl_command_reply_init(&r, NULL);
        tg_configure_text("TELEGRAM_BOT_TOKEN=CANARYtokenBADBADBAD\nTELEGRAM_CHAT_ID=4242\n", &r);
        ASSERT(tgt_failed(&r, "TELEGRAM_CREDENTIALS_INVALID"));
        ASSERT(strstr(r.error.message, "CANARYtoken") == NULL);
        zcl_command_reply_init(&r, NULL);
        tg_configure_text("TELEGRAM_BOT_TOKEN=1234567890:CANARYtokenFRESHFRESHFRESHFRESH12\n", &r);
        ASSERT(tgt_failed(&r, "TELEGRAM_CREDENTIALS_INVALID"));
        setenv("Z23_TELEGRAM_ENV", g_env, 1);
    } TEST_END
    return failures;
}

static int tgt_registry_cases(void)
{
    int failures = 0;
    struct mcp_refusal why;
    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *send = zcl_command_registry_find(reg, "telegram.send", NULL);
    const struct zcl_command_spec *config = zcl_command_registry_find(reg, "ops.telegram.configure", NULL);
    const struct zcl_command_spec *inbox = zcl_command_registry_find(reg, "telegram.inbox", NULL);
    struct json_value with_key = {0}, without_key = {0}, empty = {0};
    static const char keyed[] = "{\"text\":\"hi\",\"idempotency_key\":\"k1\"}";
    static const char plain[] = "{\"text\":\"hi\"}";
    TEST_CASE("telegram leaves carry the right MCP classification") {
        ASSERT(send && config && inbox);
        ASSERT_STR_EQ(send->path, "ops.telegram.send");
        ASSERT(json_read(&with_key, keyed, strlen(keyed)));
        ASSERT(json_read(&without_key, plain, strlen(plain)));
        ASSERT(json_read(&empty, "{}", 2));
        ASSERT(mcp_policy_allows(send, reg, &with_key, &why));
        ASSERT(!mcp_policy_allows(send, reg, &without_key, &why));
        ASSERT(!mcp_policy_allows(config, reg, &empty, &why));
        ASSERT(mcp_policy_allows(inbox, reg, &empty, &why));
        json_free(&with_key);
        json_free(&without_key);
        json_free(&empty);
    } TEST_END
    return failures;
}

/* One-shot loopback Bot API: proves the real curl transport sends the token
 * only in the request path and returns the parsed answer. */
struct tgt_server {
    int listener;
    uint16_t port;
    char request_line[256];
    char body[64];
};

static void *tgt_serve(void *opaque)
{
    struct tgt_server *s = opaque;
    char buf[4096];
    size_t used = 0;
    struct pollfd ready = {.fd = s->listener, .events = POLLIN};
    int fd = poll(&ready, 1, 8000) > 0 ? accept(s->listener, NULL, NULL) : -1;
    static const char answer[] =
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: 93\r\n\r\n"
        "{\"ok\":true,\"result\":{\"id\":7777777777,\"is_bot\":true,\"first_name\":\"Loop\",\"username\":\"loopbot\"}}";
    if (fd < 0)
        return NULL;
    while (used < sizeof(buf) - 1) {
        ssize_t n = read(fd, buf + used, sizeof(buf) - 1 - used);
        if (n <= 0)
            break;
        used += (size_t)n;
        buf[used] = '\0';
        const char *end = strstr(buf, "\r\n\r\n");
        if (end && used >= (size_t)(end - buf) + 4 + 2)
            break;
    }
    buf[used] = '\0';
    snprintf(s->request_line, sizeof(s->request_line), "%.*s", (int)strcspn(buf, "\r"), buf);
    const char *body = strstr(buf, "\r\n\r\n");
    snprintf(s->body, sizeof(s->body), "%s", body ? body + 4 : "");
    (void)!write(fd, answer, sizeof(answer) - 1);
    close(fd);
    return NULL;
}

static bool tgt_have_curl(void)
{
    const char *path = getenv("PATH");
    char candidate[1100];
    for (const char *at = path; at && *at;) {
        size_t n = strcspn(at, ":");
        snprintf(candidate, sizeof(candidate), "%.*s/curl", (int)n, at);
        if (access(candidate, X_OK) == 0)
            return true;
        at += n + (at[n] ? 1 : 0);
    }
    return false;
}

static bool tgt_listen(struct tgt_server *s)
{
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t len = sizeof(addr);
    s->listener = socket(AF_INET, SOCK_STREAM, 0);
    if (s->listener < 0 || bind(s->listener, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(s->listener, 1) != 0 || getsockname(s->listener, (struct sockaddr *)&addr, &len) != 0)
        return false;
    s->port = ntohs(addr.sin_port);
    return true;
}

static int tgt_curl_case(void)
{
    int failures = 0;
    struct tgt_server server = {0};
    pthread_t thread;
    char base[64];
    if (!tgt_have_curl()) {
        printf("telegram curl transport... SKIP (no curl on PATH)\n");
        return 0;
    }
    if (!tgt_write_file(g_env, TGT_ENV_TEXT, 0600))
        return 1;
    TEST_CASE("telegram curl transport talks to a loopback Bot API without the token in argv") {
        ASSERT(tgt_listen(&server));
        ASSERT(pthread_create(&thread, NULL, tgt_serve, &server) == 0);
        snprintf(base, sizeof(base), "http://127.0.0.1:%u", (unsigned)server.port);
        setenv("Z23_TELEGRAM_API", base, 1);
        tg_transport_override(NULL, NULL);
        ASSERT(tgt_call("ops.telegram.status", "{}", &r, &clean));
        pthread_join(thread, NULL);
        close(server.listener);
        unsetenv("Z23_TELEGRAM_API");
        tg_transport_override(tgt_transport, &g_fake);
        ASSERT_EQ(r.status, ZCL_COMMAND_STATUS_PASSED);
        ASSERT_STR_EQ(json_get_str(json_get(json_get(&r.data, "bot"), "username")), "loopbot");
        ASSERT_STR_EQ(server.request_line, "POST /bot" TGT_CANARY "/getMe HTTP/1.1");
        ASSERT_STR_EQ(server.body, "{}");
        ASSERT(clean);
        json_free(&r.data);
    } TEST_END
    return failures;
}

#endif

int test_telegram(void)
{
    int failures = 0;
#if defined(__linux__) || defined(__APPLE__)
    if (!tgt_setup()) {
        printf("telegram fixture... FAIL (setup)\n");
        return 1;
    }
    failures += tgt_case_0() + tgt_case_1() + tgt_case_2() + tgt_case_3() + tgt_case_4();
    failures += tgt_case_5() + tgt_case_6() + tgt_case_7();
    failures += tgt_status_case() + tgt_case_9() + tgt_case_10() + tgt_registry_cases();
    failures += tgt_curl_case();
    tg_transport_override(NULL, NULL);
#endif
    return failures;
}
