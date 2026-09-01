/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: the shared zcl.fastobj.v1 cache-key authority (vcs/fastobj.h). */

#include "vcs/fastobj.h"

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "sha3/sha3.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The build_action.c hashing convention: u64 LE length, then the bytes. */
static void fastobj_hash_text(struct sha3_256_ctx *sha, const char *value)
{
    uint64_t length = value ? strlen(value) : 0;
    uint8_t le[8];
    for (unsigned i = 0; i < sizeof(le); i++)
        le[i] = (uint8_t)(length >> (8U * i) & 0xffU);
    sha3_256_write(sha, le, sizeof(le));
    if (length)
        sha3_256_write(sha, (const unsigned char *)value, (size_t)length);
}

bool vcs_fastobj_key(const uint8_t capsule_root[32], const char *target,
                     const char *profile, const char *const *argv,
                     const uint8_t preproc_sha3[32], uint8_t out[32])
{
    if (!capsule_root || !target || !profile || !preproc_sha3 || !out)
        return false;
    struct sha3_256_ctx sha;
    sha3_256_init(&sha);
    static const char domain[] = VCS_FASTOBJ_DOMAIN;
    sha3_256_write(&sha, (const unsigned char *)domain, sizeof(domain));
    sha3_256_write(&sha, capsule_root, 32);
    fastobj_hash_text(&sha, target);
    fastobj_hash_text(&sha, profile);
    for (size_t i = 0; argv && argv[i]; i++)
        fastobj_hash_text(&sha, argv[i]);
    sha3_256_write(&sha, preproc_sha3, 32);
    sha3_256_finalize(&sha, out);
    return true;
}

bool vcs_fastobj_cache_paths(const char *cache_dir, const char *key_hex,
                             char *obj_path, size_t obj_cap,
                             char *side_path, size_t side_cap)
{
    if (!cache_dir || !key_hex || strlen(key_hex) != 64)
        return false;
    int on = snprintf(obj_path, obj_cap, "%s/objects/%.2s/%s.o", cache_dir,
                      key_hex, key_hex + 2);
    int sn = snprintf(side_path, side_cap, "%s/objects/%.2s/%s.json",
                      cache_dir, key_hex, key_hex + 2);
    return on > 0 && (size_t)on < obj_cap && sn > 0 &&
           (size_t)sn < side_cap;
}

/* Decode a 64-hex field into out, naming the field on failure. */
static bool fastobj_hex_field(const struct json_value *doc, const char *field,
                              uint8_t out[32], char *err, size_t err_cap)
{
    const char *hex = json_get_str(json_get(doc, field));
    if (!hex || strlen(hex) != 64 || !zcl_hex_decode(hex, out, 32)) {
        (void)snprintf(err, err_cap, "sidecar %s is not 64 hex chars",
                       field);
        return false;
    }
    return true;
}

bool vcs_fastobj_sidecar_verify(const uint8_t *side, size_t side_len,
                                const char *key_hex,
                                uint8_t object_sha3_out[32],
                                char *err, size_t err_cap)
{
    if (!side || !side_len || !key_hex || !object_sha3_out)
        return false;
    struct json_value doc;
    json_init(&doc);
    if (!json_read(&doc, (const char *)side, side_len)) {
        (void)snprintf(err, err_cap, "sidecar is not valid JSON");
        return false;
    }
    bool ok = true;
    do {
        const char *schema = json_get_str(json_get(&doc, "schema"));
        if (!schema || strcmp(schema, VCS_FASTOBJ_SIDECAR_SCHEMA) != 0) {
            (void)snprintf(err, err_cap, "sidecar schema is not %s",
                           VCS_FASTOBJ_SIDECAR_SCHEMA);
            ok = false;
            break;
        }
        const struct json_value *kc = json_get(&doc, "key_components");
        if (!kc || kc->type != JSON_OBJ) {
            (void)snprintf(err, err_cap,
                           "sidecar has no key_components object");
            ok = false;
            break;
        }
        uint8_t capsule[32], preproc[32];
        if (!fastobj_hex_field(kc, "capsule_root", capsule, err, err_cap) ||
            !fastobj_hex_field(kc, "preprocessed_sha3", preproc, err,
                               err_cap)) {
            ok = false;
            break;
        }
        const char *target = json_get_str(json_get(kc, "target"));
        const char *profile = json_get_str(json_get(kc, "profile"));
        const struct json_value *jargv = json_get(kc, "argv");
        if (!target || !profile || !jargv || jargv->type != JSON_ARR ||
            json_size(jargv) == 0) {
            (void)snprintf(err, err_cap,
                           "sidecar key_components is incomplete");
            ok = false;
            break;
        }
        /* argv elements must all be strings; bound the count so a hostile
         * document cannot drive unbounded work. */
        size_t argc = json_size(jargv);
        if (argc > 4096) {
            (void)snprintf(err, err_cap, "sidecar argv is absurdly long");
            ok = false;
            break;
        }
        const char **argv = zcl_calloc(argc + 1u, sizeof(*argv),
                                       "fastobj-sidecar-argv");
        if (!argv) {
            (void)snprintf(err, err_cap, "sidecar argv alloc failed");
            ok = false;
            break;
        }
        for (size_t i = 0; i < argc; i++) {
            const struct json_value *el = json_at(jargv, i);
            argv[i] = (el && el->type == JSON_STR) ? json_get_str(el)
                                                   : NULL;
            if (!argv[i]) {
                (void)snprintf(err, err_cap,
                               "sidecar argv element %zu is not a string",
                               i);
                ok = false;
                break;
            }
        }
        uint8_t derived[32] = {0};
        if (ok) {
            ok = vcs_fastobj_key(capsule, target, profile, argv, preproc,
                                 derived);
            if (!ok)
                (void)snprintf(err, err_cap, "sidecar key derivation "
                                             "failed");
        }
        free(argv);
        if (!ok)
            break;
        char derived_hex[65];
        zcl_hex_encode(derived, 32, derived_hex);
        if (strcmp(derived_hex, key_hex) != 0) {
            (void)snprintf(err, err_cap,
                           "sidecar key_components hash to %.16s... but "
                           "the entry is filed under %.16s...",
                           derived_hex, key_hex);
            ok = false;
            break;
        }
        ok = fastobj_hex_field(&doc, "object_sha3", object_sha3_out, err,
                               err_cap);
    } while (false);
    json_free(&doc);
    return ok;
}
