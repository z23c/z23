/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Judge direct cycle evidence for the isolated compiler-failure selftest. */
#include "json/json.h"
#include "zutf8/zutf8.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(_WIN32)
#include <fcntl.h>
#include <io.h>
#endif

static bool text_is(const struct json_value *v, const char *key, const char *text)
{
    const char *s = json_get_str(json_get(v, key));
    return s && strcmp(s, text) == 0;
}

static bool unique(const struct json_value *v)
{
    for (size_t i = 0; i < v->num_children; ++i) {
        if (v->type == JSON_OBJ)
            for (size_t j = 0; j < i; ++j)
                if (!strcmp(v->keys[i], v->keys[j])) return false;
        if (!unique(&v->children[i])) return false;
    }
    return true;
}

static bool failure_id(const struct json_value *v)
{
    const char *s = json_get_str(v);
    if (!s || strlen(s) != 64) return false;
    for (size_t i = 0; i < 64; ++i)
        if (!strchr("0123456789abcdef", s[i])) return false;
    return true;
}

static bool frame(const struct json_value *reply, int64_t after)
{
    const struct json_value *ok = json_get(reply, "ok");
    const struct json_value *data = json_get(reply, "data");
    const struct json_value *epoch = json_get(data, "epoch");
    return reply->type == JSON_OBJ && unique(reply) &&
        ok && ok->type == JSON_BOOL && ok->val.b &&
        text_is(reply, "data_schema", "zcl.dev_cycle.v1") &&
        text_is(data, "schema", "zcl.dev_cycle.v1") &&
        epoch && epoch->type == JSON_INT && epoch->val.i > after;
}

static bool transient(const struct json_value *data)
{
    const char *states[] = {"edit_seen", "impact_ready", "proof_pending", "superseded", "fallback_ready"};
    for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); ++i)
        if (text_is(data, "status", states[i])) return true;
    return false;
}

static bool terminal(const struct json_value *data, const char *mode)
{
    bool coalesced = strcmp(mode, "coalesced") == 0;
    if (!text_is(data, "status", coalesced ? "unchanged_failure" : "rejected")) return false;
    const struct json_value *id = json_get(data, "failure_id");
    const struct json_value *flag = json_get(data, "coalesced");
    if (id && !failure_id(id)) return false;
    if (flag && flag->type != JSON_BOOL) return false;
    if (coalesced) return id && flag && flag->val.b;
    if (flag && flag->val.b) return false;
    return strcmp(mode, "compiler") != 0 || id;
}

static bool project(const struct json_value *data, char out[512])
{
    const char *keys[] = {"status", "epoch", "failure_id", "coalesced"};
    struct json_value result = {0};
    json_set_object(&result);
    bool ok = true;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i) {
        const struct json_value *v = json_get(data, keys[i]);
        if (v && !json_push_kv(&result, keys[i], v)) ok = false;
    }
    size_t n = json_write(&result, out, 512);
    json_free(&result);
    return ok && n < 512;
}

/* 0 expected terminal, 3 valid transient, 1 unusable/unexpected evidence. */
static int judge(const char *raw, size_t size, int64_t after,
                 const char *mode, char out[512])
{
    struct json_value reply = {0};
    if (memchr(raw, 0, size) || !zutf8_validate_n(raw, size) ||
        !json_read(&reply, raw, size)) return 1;
    int rc = 1;
    const struct json_value *data = json_get(&reply, "data");
    if (frame(&reply, after)) {
        if (transient(data)) {
            int n = snprintf(out, 512, "%" PRId64, json_get_int(json_get(data, "epoch")));
            if (n > 0 && n < 512) rc = 3;
        } else if (terminal(data, mode) && project(data, out)) rc = 0;
    }
    json_free(&reply);
    return rc;
}

static int selftest(void)
{
    static const char id[] = ",\"failure_id\":\"0000000000000000000000000000000000000000000000000000000000000000\"";
    static const char cached[] = ",\"failure_id\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"coalesced\":true";
    const struct { const char *status, *fields, *tail, *mode; int64_t after; int want; } cases[] = {
        {"proof_pending", "", ",\"decoy\":{\"status\":\"rejected\",\"epoch\":999}", "compiler", 0, 3},
        {"edit_seen", "", "", "compiler", 0, 3},
        {"impact_ready", "", "", "compiler", 0, 3},
        {"superseded", "", "", "compiler", 0, 3},
        {"fallback_ready", "", "", "compiler", 0, 3},
        {"rejected", id, ",\"decoy\":{\"epoch\":999}", "compiler", 0, 0},
        {"rejected", "", "", "rejected", 0, 0},
        {"unchanged_failure", cached, "", "coalesced", 0, 0},
        {"unchanged_failure", id, "", "coalesced", 0, 1},
        {"rejected", cached, "", "compiler", 0, 1},
        {"passed", id, ",\"decoy\":{\"status\":\"rejected\"}", "compiler", 0, 1},
        {"rejected", "", "", "compiler", 0, 1},
        {"unknown", "", "", "rejected", 0, 1},
        {"rejected", id, "", "compiler", 1, 1},
        {"proof_pending", ",\"epoch\":2", "", "compiler", 0, 1},
        {"proof_pending", "", ",\"bad\":\"\xff\"", "compiler", 0, 1},
        {"proof_pending", "", "garbage", "compiler", 0, 1}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char raw[2048], out[512];
        int n = snprintf(raw, sizeof(raw),
            "{\"ok\":true,\"data_schema\":\"zcl.dev_cycle.v1\",\"data\":{\"schema\":\"zcl.dev_cycle.v1\",\"status\":\"%s\",\"epoch\":1%s}%s}",
            cases[i].status, cases[i].fields, cases[i].tail);
        if (n < 0 || (size_t)n >= sizeof(raw)) return 1;
        int rc = judge(raw, (size_t)n, cases[i].after, cases[i].mode, out);
        if (rc != cases[i].want) return 1;
        if (rc == 3 && strcmp(out, "1")) return 1;
        if (rc == 0 && strstr(out, "999")) return 1;
    }
    puts("dev-failure-cycle: judge controls PASS");
    return 0;
}

static bool arguments(int argc, char **argv, int64_t *value)
{
    if (argc != 3 || !*argv[1]) return false;
    if (strspn(argv[1], "0123456789") != strlen(argv[1])) return false;
    char *end;
    errno = 0;
    intmax_t after = strtoimax(argv[1], &end, 10);
    if (errno || *end || after > INT64_MAX) return false;
    if (strcmp(argv[2], "compiler") && strcmp(argv[2], "coalesced") &&
        strcmp(argv[2], "rejected")) return false;
    *value = (int64_t)after;
    return true;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--selftest")) return selftest();
    int64_t after;
    if (!arguments(argc, argv, &after)) return 2;
#if defined(_WIN32)
    if (_setmode(_fileno(stdin), _O_BINARY) == -1 ||
        _setmode(_fileno(stdout), _O_BINARY) == -1) {
        perror("dev-failure-cycle: binary evidence I/O");
        return 1;
    }
#endif
    char raw[65536], out[512];
    size_t size = fread(raw, 1, sizeof(raw), stdin);
    if (ferror(stdin) || size == sizeof(raw)) return 1;
    int rc = judge(raw, size, after, argv[2], out);
    if (rc == 0 || rc == 3) puts(out);
    else fprintf(stderr, "dev-failure-cycle: invalid, nonadvancing, or unexpected direct verdict\n");
    return rc;
}
