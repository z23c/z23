/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * purpose: the tip_parity health check of ops.slot.activate. After a restart
 *          the node under test and a reference zclassicd must report the same
 *          getbestblockhash. Both endpoints are explicit inputs: credentials
 *          come from the two rpc conf files named in the health object, the
 *          reference host is named, and nothing defaults to a live host. Any
 *          unreadable conf, unreachable endpoint, RPC error or malformed hash
 *          is a failed check.
 */

#include "command/native_slot_common.h"

#include "base/cleanse.h"
#include "rpc/legacy_rpc_client.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TIP_RPC_TIMEOUT_MS 2000u
#define TIP_BODY \
    "{\"jsonrpc\":\"1.0\",\"id\":\"z23-slot\",\"method\":\"getbestblockhash\"," \
    "\"params\":[]}"

static slot_tip_rpc_fn tip_rpc;

void slot_tip_set_rpc(slot_tip_rpc_fn fn)
{
    tip_rpc = fn;
}

static char *tip_rpc_real(const char *host, int port, const char *user,
                          const char *pass, uint32_t timeout_ms)
{
    char *raw = NULL;
    char err[128];
    if (!legacy_rpc_call_with_timeout(host, port, user, pass, TIP_BODY,
                                      timeout_ms, &raw, err, sizeof(err)))
        return NULL;
    return raw;
}

static bool tip_hash_ok(const char *s)
{
    if (strlen(s) != 64)
        return false;
    for (size_t i = 0; i < 64; i++)
        if (!isxdigit((unsigned char)s[i]) || isupper((unsigned char)s[i]))
            return false;
    return true;
}

static bool tip_endpoint_ok(const struct slot_tip_endpoint *e, char out[65])
{
    char *raw = (tip_rpc ? tip_rpc : tip_rpc_real)(
        e->host, e->port, e->user, e->pass, TIP_RPC_TIMEOUT_MS);
    char err[128];
    bool ok;
    if (!raw)
        return false;
    ok = legacy_rpc_parse_result_string(raw, out, 65, err, sizeof(err)) &&
         tip_hash_ok(out);
    free(raw);
    return ok;
}

bool slot_tip_equal(const struct slot_tip_spec *s)
{
    char node[65], ref[65];
    return tip_endpoint_ok(&s->node, node) && tip_endpoint_ok(&s->ref, ref) &&
           strcmp(node, ref) == 0;
}

static bool tip_host_ok(const char *h)
{
    size_t n = h ? strlen(h) : 0;
    if (n == 0 || n >= sizeof(((struct slot_tip_endpoint *)0)->host))
        return false;
    for (size_t i = 0; i < n; i++)
        if (!isalnum((unsigned char)h[i]) && !strchr(".-:", h[i]))
            return false;
    return true;
}

static bool tip_load(struct slot_tip_endpoint *e, const char *host,
                     const char *conf, const struct json_value *port)
{
    int conf_port = 0;
    if (!tip_host_ok(host) || !conf || conf[0] != '/' ||
        !legacy_rpc_parse_conf_file(conf, e->user, sizeof(e->user), e->pass,
                                    sizeof(e->pass), &conf_port))
        return false;
    snprintf(e->host, sizeof(e->host), "%s", host);
    e->port = port && port->type == JSON_INT ? (int)json_get_int(port)
                                             : conf_port;
    return e->port >= 1 && e->port <= 65535;
}

bool slot_tip_spec_parse(const struct json_value *health,
                         struct slot_tip_spec *s)
{
    bool ok = tip_load(&s->node, "127.0.0.1", slot_json_str(health, "node_conf"),
                       json_get(health, "node_port")) &&
              tip_load(&s->ref, slot_json_str(health, "reference_host"),
                       slot_json_str(health, "reference_conf"),
                       json_get(health, "reference_port"));
    if (!ok)
        slot_tip_spec_wipe(s);
    return ok;
}

void slot_tip_spec_wipe(struct slot_tip_spec *s)
{
    memory_cleanse(s, sizeof(*s));
}
