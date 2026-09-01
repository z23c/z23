/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Safe JSON-RPC params builder: routes every string through the project's
 * JSON encoder so untrusted input cannot inject into the params array.
 * See controllers/rpc_params.h for the public API. */

#include "controllers/rpc_params.h"

#include "json/json.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"

#include <stdlib.h>

void rpc_arg_builder_init(struct rpc_arg_builder *p)
{
    json_init(&p->arr);
    json_set_array(&p->arr);
}

void rpc_arg_builder_free(struct rpc_arg_builder *p)
{
    json_free(&p->arr);
}

void rpc_arg_builder_push_str(struct rpc_arg_builder *p, const char *s)
{
    struct json_value v;
    json_init(&v);
    json_set_str(&v, s ? s : "");
    json_push_back(&p->arr, &v);
    json_free(&v);
}

void rpc_arg_builder_push_int(struct rpc_arg_builder *p, int64_t i)
{
    struct json_value v;
    json_init(&v);
    json_set_int(&v, i);
    json_push_back(&p->arr, &v);
    json_free(&v);
}

void rpc_arg_builder_push_real(struct rpc_arg_builder *p, double d)
{
    struct json_value v;
    json_init(&v);
    json_set_real(&v, d);
    json_push_back(&p->arr, &v);
    json_free(&v);
}

void rpc_arg_builder_push_value(struct rpc_arg_builder *p,
                                const struct json_value *v)
{
    if (!v) {
        struct json_value nul;
        json_init(&nul);
        json_set_null(&nul);
        json_push_back(&p->arr, &nul);
        json_free(&nul);
        return;
    }
    /* json_push_back deep-copies; the caller keeps ownership of *v. */
    json_push_back(&p->arr, v);
}

char *rpc_arg_builder_to_json(struct rpc_arg_builder *p)
{
    /* Two-pass: size then allocate. json_write is safe with NULL/0 —
     * every write is guarded by a bounds check, so it just counts. */
    size_t need = json_write(&p->arr, NULL, 0);
    char *buf = zcl_malloc(need + 1, "rpc argument json");
    if (!buf) {
        rpc_arg_builder_free(p);
        LOG_NULL("rpc.params", "malloc failed for %zu byte json array", need + 1);
    }
    size_t wrote = json_write(&p->arr, buf, need + 1);
    buf[wrote] = '\0';
    rpc_arg_builder_free(p);
    return buf;
}
