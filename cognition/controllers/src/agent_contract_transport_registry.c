/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "controllers/agent_controller.h"

#include "json/json.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static void agent_transport_push_str(struct json_value *arr, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s ? s : "");
    json_push_back(arr, &v);
    json_free(&v);
}

static void agent_transport_append(char *buf, size_t buf_sz, size_t *pos,
                                   const char *separator, const char *text)
{
    if (!buf || buf_sz == 0 || !pos || !text || !text[0])
        return;
    if (*pos >= buf_sz) {
        buf[buf_sz - 1] = '\0';
        return;
    }
    int n = snprintf(buf + *pos, buf_sz - *pos, "%s%s",
                     separator ? separator : "", text);
    if (n < 0)
        return;
    size_t wrote = (size_t)n;
    if (wrote >= buf_sz - *pos)
        *pos = buf_sz - 1;
    else
        *pos += wrote;
}

static bool agent_transport_seen(const char *const *seen, size_t seen_len,
                                 const char *text)
{
    if (!text || !text[0])
        return true;
    for (size_t i = 0; i < seen_len; i++) {
        if (seen[i] && strcmp(seen[i], text) == 0)
            return true;
    }
    return false;
}

static void agent_transport_append_unique(char *buf, size_t buf_sz,
                                          size_t *pos, bool *first,
                                          const char *separator,
                                          const char *text,
                                          const char **seen,
                                          size_t *seen_len,
                                          size_t seen_cap)
{
    if (!buf || !pos || !first || !seen || !seen_len || !text || !text[0])
        return;
    if (agent_transport_seen(seen, *seen_len, text))
        return;
    if (*seen_len < seen_cap)
        seen[(*seen_len)++] = text;
    agent_transport_append(buf, buf_sz, pos, *first ? "" : separator, text);
    *first = false;
}

void agent_push_contract_transport_summary_json(struct json_value *arr)
{
    if (!arr)
        return;

    char native[4096];
    char rest[2048];
    const char *native_seen[128] = {0};
    const char *rest_seen[128] = {0};
    size_t native_seen_len = 0;
    size_t rest_seen_len = 0;
    size_t native_pos = 0;
    size_t rest_pos = 0;
    bool native_first = true;
    bool rest_first = true;

    native[0] = '\0';
    rest[0] = '\0';
    agent_transport_append(native, sizeof(native), &native_pos, "",
                           "native: ");
    agent_transport_append(rest, sizeof(rest), &rest_pos, "", "rest: ");

    for (size_t i = 0; i < agent_contract_count(); i++) {
        const struct agent_contract *c = agent_contract_at(i);
        if (!c)
            continue;
        agent_transport_append_unique(native, sizeof(native), &native_pos,
                                      &native_first, " | ",
                                      c->native_command, native_seen,
                                      &native_seen_len, 128);
        agent_transport_append_unique(rest, sizeof(rest), &rest_pos,
                                      &rest_first, "; ", c->rest_route,
                                      rest_seen, &rest_seen_len, 128);
    }

    agent_transport_push_str(arr, native);
    agent_transport_push_str(arr,
                             rest_first ? "rest: no REST-only agent route"
                                        : rest);
}
