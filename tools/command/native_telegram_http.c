/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Telegram Bot API transport. The node binary links no TLS client and
 * no trust store by design, so requests go through the host curl with the
 * bot URL in an owner-private config file, never in argv. */
#include "command/native_telegram.h"
#include "base/cleanse.h"
#include "base/safe_alloc.h"
#include "platform/private_directory.h"
#include "platform/temp_directory.h"
#include "util/spawn.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#define TG_RESPONSE_MAX (512u * 1024u)
#define TG_DEFAULT_API "https://api.telegram.org"

static tg_transport_fn g_override;
static void *g_override_ctx;

void tg_transport_override(tg_transport_fn fn, void *ctx)
{
    g_override = fn;
    g_override_ctx = ctx;
}

void tg_response_free(struct tg_response *response)
{
    free(response->body);
    memset(response, 0, sizeof(*response));
}

bool tg_call(const char *token, const char *method, const char *body, int timeout_s,
             struct tg_response *out)
{
    memset(out, 0, sizeof(*out));
    if (g_override)
        return g_override(g_override_ctx, token, method, body, timeout_s, out);
    return tg_transport_curl(NULL, token, method, body, timeout_s, out);
}

static enum tg_api tg_api_kind(int64_t code, int status)
{
    if (code == 409 || status == 409)
        return TG_API_CONFLICT;
    if (code == 429 || status == 429)
        return TG_API_RATE_LIMITED;
    if (code == 401 || code == 403 || status == 401)
        return TG_API_UNAUTHORIZED;
    return code ? TG_API_REJECTED : TG_API_MALFORMED;
}

enum tg_api tg_api_parse(const struct tg_response *response, const char *token,
                         struct json_value *doc, char *desc, size_t desc_cap)
{
    desc[0] = '\0';
    if (!response->body || !json_read(doc, response->body, response->len) || doc->type != JSON_OBJ)
        return TG_API_MALFORMED;
    const struct json_value *ok = json_get(doc, "ok");
    if (ok && ok->type == JSON_BOOL && json_get_bool(ok))
        return TG_API_OK;
    const char *text = json_get_str(json_get(doc, "description"));
    int64_t code = json_get_int(json_get(doc, "error_code"));
    snprintf(desc, desc_cap, "%s", text);
    if (token && token[0] && strstr(desc, token))
        desc[0] = '\0';
    return tg_api_kind(code, response->status);
}

#if !defined(_WIN32)
/* Only the real API or a loopback fake may receive the token. */
static const char *tg_api_base(void)
{
    const char *base = getenv("Z23_TELEGRAM_API");
    if (!base || !base[0])
        return TG_DEFAULT_API;
    bool scheme = !strncmp(base, "https://", 8) || !strncmp(base, "http://127.0.0.1:", 17) ||
                  !strncmp(base, "http://localhost:", 17);
    for (const char *p = base; *p && scheme; p++)
        scheme = isgraph((unsigned char)*p) && *p != '"' && *p != '\\';
    return scheme && strlen(base) < 200 ? base : NULL;
}

static bool tg_method_valid(const char *method)
{
    size_t n = method ? strlen(method) : 0;
    for (size_t i = 0; i < n; i++) {
        if (!isalpha((unsigned char)method[i]))
            return false;
    }
    return n > 0 && n < 40;
}

static bool tg_private_file(const char *path, const char *data, size_t len)
{
    return tg_atomic_write_private(path, data, len);
}

static bool tg_split_status(char *raw, struct tg_response *out)
{
    char *nl = strrchr(raw, '\n');
    if (!nl || strlen(nl + 1) != 3)
        return false;
    int status = atoi(nl + 1);
    if (status < 100 || status > 599)
        return false;
    *nl = '\0';
    out->status = status;
    out->len = (size_t)(nl - raw);
    out->body = raw;
    return true;
}

/* The request runs inside a private temporary directory that holds the curl
 * config (URL with the token) and the JSON body; both are removed before the
 * function returns. */
static bool tg_run_curl(const char *dir, const char *base, const char *token, const char *method,
                        const char *body, int timeout_s, struct tg_response *out)
{
    char cfg_path[TG_PATH_MAX], body_path[TG_PATH_MAX], cfg[1024];
    char limit[16];
    const char *argv[] = {"curl", "-q", "-K", cfg_path, NULL};
    char *raw = zcl_malloc(TG_RESPONSE_MAX, "telegram.response");
    bool ok = false;
    snprintf(cfg_path, sizeof(cfg_path), "%s/curl.cfg", dir);
    snprintf(body_path, sizeof(body_path), "%s/body.json", dir);
    snprintf(limit, sizeof(limit), "%d", timeout_s);
    int n = snprintf(cfg, sizeof(cfg),
                     "silent\nconnect-timeout = 15\nmax-time = %s\n"
                     "url = \"%s/bot%s/%s\"\nheader = \"Content-Type: application/json\"\n"
                     "data-binary = \"@%s\"\nwrite-out = \"\\n%%{http_code}\"\n",
                     limit, base, token, method, body_path);
    if (raw && n > 0 && (size_t)n < sizeof(cfg) && strchr(body_path, '"') == NULL &&
        tg_private_file(body_path, body, strlen(body)) && tg_private_file(cfg_path, cfg, (size_t)n)) {
        int rc = zcl_spawn_capture(argv, raw, TG_RESPONSE_MAX, (timeout_s + 10) * 1000);
        ok = rc == 0 && tg_split_status(raw, out);
    }
    (void)unlink(cfg_path);
    (void)unlink(body_path);
    memory_cleanse(cfg, sizeof(cfg));
    if (!ok)
        free(raw);
    return ok;
}

static bool tg_curl_posix(const char *token, const char *method, const char *body,
                          int timeout_s, struct tg_response *out)
{
    char dir[PLATFORM_TEMP_PATH_MAX];
    const char *base = tg_api_base();
    memset(out, 0, sizeof(*out));
    if (!base || !tg_token_valid(token) || !tg_method_valid(method) || timeout_s < 1 || timeout_s > 120)
        return false;
    if (!platform_temp_directory_create("z23-telegram", dir, sizeof(dir)))
        return false;
    bool ok = tg_run_curl(dir, base, token, method, body, timeout_s, out);
    (void)platform_private_directory_remove_empty(dir);
    return ok;
}
#else
static bool tg_curl_posix(const char *token, const char *method, const char *body,
                          int timeout_s, struct tg_response *out)
{
    (void)token; (void)method; (void)body; (void)timeout_s;
    memset(out, 0, sizeof(*out));
    return false;
}
#endif

bool tg_transport_curl(void *ctx, const char *token, const char *method, const char *body,
                       int timeout_s, struct tg_response *out)
{
    (void)ctx;
    return tg_curl_posix(token, method, body, timeout_s, out);
}
