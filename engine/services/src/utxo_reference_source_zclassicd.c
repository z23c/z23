/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * zclassicd reference source (production, COARSE) — attests the co-located
 * legacy daemon's UTXO-set height via `gettxoutsetinfo`, but cannot return a
 * zclassic23-format SHA3 commitment. It is therefore exact=false: the parity
 * comparator asserts only height parity and NEVER declares a byte DRIFT from
 * this source, so it can never false-page the operator.
 *
 * This path is dormant by default: boot wires it only behind cfg.enabled /
 * ZCL_PARITY_ENABLE, and unit tests use the fixture instead. It is a
 * transport over legacy_rpc_call — no sockets are opened at init.
 */

#include "services/utxo_reference_source.h"

#include "rpc/legacy_rpc_client.h"
#include "rpc/zclassicd_port.h"
#include "json/json.h"
#include "util/log_macros.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define PARITY_RPC_DEFAULT_HOST "127.0.0.1"

/* Extract an integer field from the `.result` OBJECT of a JSON-RPC response.
 * gettxoutsetinfo returns {"result":{"height":H,"transactions":N,...}}, which
 * the hex-result parser cannot handle, so this walks the object directly. */
static bool parse_result_obj_int(const char *raw, const char *field,
                                 int64_t *out, char *err, size_t err_sz)
{
    const char *body = strstr(raw, "\r\n\r\n");
    if (!body) {
        snprintf(err, err_sz, "no http body separator");
        return false;
    }
    body += 4;

    struct json_value v = {0};
    if (!json_read(&v, body, strlen(body))) {
        snprintf(err, err_sz, "json parse failed");
        json_free(&v);
        return false;
    }
    const struct json_value *result = json_get(&v, "result");
    if (!result || result->type != JSON_OBJ) {
        const struct json_value *jerr = json_get(&v, "error");
        if (jerr && jerr->type == JSON_OBJ) {
            const struct json_value *msg = json_get(jerr, "message");
            if (msg && msg->type == JSON_STR) {
                snprintf(err, err_sz, "rpc error: %s", json_get_str(msg));
                json_free(&v);
                return false;
            }
        }
        snprintf(err, err_sz, "no .result object");
        json_free(&v);
        return false;
    }
    const struct json_value *f = json_get(result, field);
    if (!f || f->type != JSON_INT) {
        snprintf(err, err_sz, "result.%s missing or not an int", field);
        json_free(&v);
        return false;
    }
    if (out)
        *out = json_get_int(f);
    json_free(&v);
    return true;
}

static struct zcl_result zclassicd_commitment_at(void *self, int32_t height,
                                                 char ref_sha3[65],
                                                 int32_t *ref_height)
{
    (void)height; /* coarse: we report zclassicd's own height, not a query */
    struct utxo_reference_source_zclassicd *z = self;
    if (!z || !ref_sha3 || !ref_height)
        return ZCL_ERR(-1, "zclassicd_commitment_at: null arg");

    /* Coarse: zclassicd has no zclassic23-format SHA3 — leave it empty so
     * the comparator's same-height/height-only branch handles it. */
    ref_sha3[0] = '\0';
    *ref_height = 0;

    const char *host = z->rpc.host[0] ? z->rpc.host : PARITY_RPC_DEFAULT_HOST;
    int port = z->rpc.port > 0 ? z->rpc.port : ZCLASSICD_RPC_DEFAULT_PORT;

    char *resp = NULL;
    char err[160] = {0};
    const char *body =
        "{\"jsonrpc\":\"1.0\",\"id\":\"zcl-parity\","
        "\"method\":\"gettxoutsetinfo\",\"params\":[]}";
    if (!legacy_rpc_call(host, port, z->rpc.user, z->rpc.password,
                         body, &resp, err, sizeof(err)) || !resp) {
        if (resp)
            free(resp);
        return ZCL_ERR(-2, "gettxoutsetinfo unreachable: %s", err);
    }

    int64_t h = 0;
    bool ok = parse_result_obj_int(resp, "height", &h, err, sizeof(err));
    free(resp);
    if (!ok)
        return ZCL_ERR(-3, "gettxoutsetinfo parse: %s", err);

    if (h < 0 || h > INT32_MAX)
        return ZCL_ERR(-4, "gettxoutsetinfo height out of range: %lld",
                       (long long)h);
    *ref_height = (int32_t)h;
    return ZCL_OK;
}

struct zcl_result utxo_reference_source_zclassicd_init(
    struct utxo_reference_source *src,
    struct utxo_reference_source_zclassicd *z,
    const struct utxo_parity_rpc_config *cfg)
{
    if (!src || !z)
        return ZCL_ERR(-1, "zclassicd_init: null arg");

    memset(z, 0, sizeof(*z));
    if (cfg)
        z->rpc = *cfg;
    if (!z->rpc.host[0])
        snprintf(z->rpc.host, sizeof(z->rpc.host), "%s", PARITY_RPC_DEFAULT_HOST);
    if (z->rpc.port <= 0)
        z->rpc.port = ZCLASSICD_RPC_DEFAULT_PORT;

    /* Resolve credentials from the conf file when not supplied so the source
     * is usable on a stock layout; refuse (dormant) when none are found. */
    bool need_user = (z->rpc.user[0] == '\0');
    bool need_pass = (z->rpc.password[0] == '\0');
    if (need_user || need_pass) {
        int port_from_conf = z->rpc.port;
        char u[64] = {0}, p[128] = {0};
        if (legacy_rpc_parse_conf(u, sizeof(u), p, sizeof(p), &port_from_conf)) {
            if (need_user)
                snprintf(z->rpc.user, sizeof(z->rpc.user), "%s", u);
            if (need_pass)
                snprintf(z->rpc.password, sizeof(z->rpc.password), "%s", p);
            if (!cfg || cfg->port <= 0)
                z->rpc.port = port_from_conf;
        } else {
            return ZCL_ERR(-2,
                "no RPC credentials for zclassicd reference (config or "
                "~/.zclassic/zclassic.conf)");
        }
    }

    src->name = "zclassicd-coarse";
    src->exact = false; /* gettxoutsetinfo cannot prove UTXO-set bytes */
    src->commitment_at = zclassicd_commitment_at;
    src->self = z;
    return ZCL_OK;
}
