/* Copyright 2026 Rhett Creighton. Licensed under Apache-2.0.
 * Purpose: rederive and verify the checked-in ZCODE package root projection. */

#include "base/hex.h"
#include "base/safe_alloc.h"
#include "json/json.h"
#include "vcs/package_prepare.h"

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct registry_row {
    const char *name, *dir;
    uint64_t sequence;
    const char *content, *release, *recipe, *lock, *capsule, *publisher;
    const char *signature;
};

#define ZCODE_PACKAGE(name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature) \
    {name, dir, sequence, content, release, recipe, lock, capsule, publisher, signature},
static const struct registry_row rows[] = {
#include "../engine/composition/zcode_package_registry.def"
#include "../engine/composition/zcode_c23_commons_app.def"
};
#undef ZCODE_PACKAGE

static bool root_equal(const uint8_t root[32], const char *expected)
{
    uint8_t decoded[32];
    return zcl_hex_decode_lower(expected, decoded, sizeof(decoded)) &&
           memcmp(root, decoded, sizeof(decoded)) == 0;
}

static void print_derived_roots(const struct vcs_package_prepared *prepared)
{
    char content[65], release[65], recipe[65], lock[65], capsule[65];
    zcl_hex_encode(prepared->package_root, 32, content);
    zcl_hex_encode(prepared->signing_digest, 32, release);
    zcl_hex_encode(prepared->recipe_root, 32, recipe);
    zcl_hex_encode(prepared->lock_root, 32, lock);
    zcl_hex_encode(prepared->capsule_root, 32, capsule);
    fprintf(stderr,
            "  derived content=%s release=%s recipe=%s lock=%s capsule=%s\n",
            content, release, recipe, lock, capsule);
}

/* This key is the public alpha fixture identity already embedded in the
 * checked projection. It has no owner, wallet, or stable-release authority. */
static bool derive_fixture_signature(secp256k1_context *ctx,
                                     const uint8_t digest[32], char out[129])
{
    uint8_t secret[32], compact[64];
    memset(secret, 0x47, sizeof(secret));
    secp256k1_ecdsa_recoverable_signature signature;
    int recovery_id = -1;
    bool ok = ctx && secp256k1_ec_seckey_verify(ctx, secret) == 1 &&
        secp256k1_ecdsa_sign_recoverable(ctx, &signature, digest, secret,
            secp256k1_nonce_function_rfc6979, NULL) == 1 &&
        secp256k1_ecdsa_recoverable_signature_serialize_compact(
            ctx, compact, &recovery_id, &signature) == 1 && recovery_id >= 0;
    memset(secret, 0, sizeof(secret));
    if (!ok)
        return false;
    zcl_hex_encode(compact, sizeof(compact), out);
    memset(compact, 0, sizeof(compact));
    return true;
}

static bool derive_fixture_public(secp256k1_context *ctx, uint8_t out[33])
{
    uint8_t secret[32];
    memset(secret, 0x47, sizeof(secret));
    secp256k1_pubkey public_key;
    size_t out_len = 33;
    bool ok = ctx && secp256k1_ec_pubkey_create(ctx, &public_key, secret) == 1 &&
        secp256k1_ec_pubkey_serialize(ctx, out, &out_len, &public_key,
                                     SECP256K1_EC_COMPRESSED) == 1 &&
        out_len == 33;
    memset(secret, 0, sizeof(secret));
    return ok;
}

static bool print_derived_row(const char *name,
                              const struct vcs_package_prepared *prepared,
                              secp256k1_context *ctx)
{
    char content[65], release[65], recipe[65], lock[65], capsule[65];
    char publisher[67], signature[129];
    zcl_hex_encode(prepared->package_root, 32, content);
    zcl_hex_encode(prepared->signing_digest, 32, release);
    zcl_hex_encode(prepared->recipe_root, 32, recipe);
    zcl_hex_encode(prepared->lock_root, 32, lock);
    zcl_hex_encode(prepared->capsule_root, 32, capsule);
    zcl_hex_encode(prepared->release.publisher_pubkey, 33, publisher);
    if (!derive_fixture_signature(ctx, prepared->signing_digest, signature))
        return false;
    printf("%s content=%s release=%s recipe=%s lock=%s capsule=%s "
           "publisher=%s signature=%s\n", name, content, release,
           recipe, lock, capsule, publisher, signature);
    return true;
}

static int derive_directory(const char *dir)
{
    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t pubkey[33];
    if (!derive_fixture_public(ctx, pubkey)) {
        if (ctx) secp256k1_context_destroy(ctx);
        return 1;
    }
    struct vcs_package_prepare_options options = {
        .dir = dir, .publisher_sequence = 1,
        .reward_address = "", .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, pubkey, sizeof(pubkey));
    struct vcs_package_prepared prepared;
    char detail[256] = {0};
    enum vcs_package_prepare_error err = vcs_package_prepare(
        &options, &prepared, detail, sizeof(detail));
    if (err != VCS_PACKAGE_PREPARE_OK) {
        fprintf(stderr, "zcode package derive failed: %s (%s: %s)\n", dir,
                vcs_package_prepare_error_string(err), detail);
        secp256k1_context_destroy(ctx);
        return 1;
    }
    bool ok = print_derived_row(prepared.release.name, &prepared, ctx);
    for (size_t i = 0; ok && i + 1u < prepared.lock.count; i++) {
        char root[65];
        zcl_hex_encode(prepared.lock.nodes[i].root, 32, root);
        printf("dependency name=%s root=%s\n",
               prepared.lock.nodes[i].name, root);
    }
    vcs_package_prepared_free(&prepared);
    secp256k1_context_destroy(ctx);
    return ok ? 0 : 1;
}

static bool row_publisher_key(const struct registry_row *row, bool derive, secp256k1_context *ctx,
                              uint8_t pubkey[33])
{
    return derive ? derive_fixture_public(ctx, pubkey) :
                    zcl_hex_decode_lower(row->publisher, pubkey, 33);
}

static bool row_roots_match(struct vcs_package_prepared *prepared,
                            const struct registry_row *row)
{
    return strcmp(prepared->release.name, row->name) == 0 &&
           root_equal(prepared->package_root, row->content) &&
           root_equal(prepared->signing_digest, row->release) &&
           root_equal(prepared->recipe_root, row->recipe) &&
           root_equal(prepared->lock_root, row->lock) &&
           root_equal(prepared->capsule_root, row->capsule) &&
           zcl_hex_decode_lower(row->signature, prepared->release.signature,
                                sizeof(prepared->release.signature)) &&
           vcs_package_release_verify(&prepared->release) ==
               VCS_PACKAGE_RELEASE_OK;
}

static bool lock_dag_matches(const struct vcs_package_prepared *prepared,
                             size_t row_index)
{
    bool ok = prepared->lock.count >= 1 &&
        prepared->lock.nodes[prepared->lock.count - 1u].depth == 0 &&
        prepared->lock.nodes[prepared->lock.count - 1u].direct_deps ==
            prepared->lock.count - 1u;
    for (size_t d = 0; ok && d + 1u < prepared->lock.count; d++) {
        bool found = false;
        for (size_t p = 0; p < row_index; p++)
            found = found || root_equal(
                prepared->lock.nodes[d].root, rows[p].content);
        ok = found && prepared->lock.nodes[d].depth >= 1 &&
             prepared->lock.nodes[d].depth <=
                 VCS_PACKAGE_LOCK_MAX_DEPTH;
    }
    return ok;
}

static void report_registry_mismatch(const struct registry_row *row,
                                     struct vcs_package_prepared *prepared,
                                     enum vcs_package_prepare_error err,
                                     const char *detail)
{
    fprintf(stderr, "zcode registry mismatch: %s (%s: %s)\n",
            row->name, vcs_package_prepare_error_string(err), detail);
    if (err == VCS_PACKAGE_PREPARE_OK)
        print_derived_roots(prepared);
    if (err == VCS_PACKAGE_PREPARE_OK && prepared->lock.count > 0) {
        const size_t root = prepared->lock.count - 1u;
        fprintf(stderr,
                "  release_verify=%d lock_count=%zu root_depth=%u "
                "root_direct_deps=%u\n",
                (int)vcs_package_release_verify(&prepared->release),
                prepared->lock.count,
                (unsigned)prepared->lock.nodes[root].depth,
                (unsigned)prepared->lock.nodes[root].direct_deps);
    }
    /* Naming the values is not enough to act on: this row's new
     * content root is ALSO pinned in dependencies[].root of every
     * dependent's zcode-package.json, and rewriting those moves
     * their own roots in turn. Fixing one row by hand therefore
     * never terminates -- point at the tool that iterates the
     * cascade to a fixpoint. */
    fprintf(stderr,
            "  fix: tools/scripts/zcode_registry_rederive.sh\n"
            "  (re-derives this row AND every dependent's pinned\n"
            "   copy of it, iterating to a fixpoint)\n");
}

static int check_registry_row(size_t i, bool derive, bool *derived)
{
    secp256k1_context *ctx = derive ? secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY) : NULL;
    uint8_t pubkey[33];
    if (!row_publisher_key(&rows[i], derive, ctx, pubkey)) {
        if (ctx) secp256k1_context_destroy(ctx);
        return 1;
    }
    struct vcs_package_prepare_options options = {
        .dir = rows[i].dir, .publisher_sequence = rows[i].sequence,
        .reward_address = "", .chain_id = "zclassic-main",
    };
    memcpy(options.publisher_pubkey, pubkey, sizeof(pubkey));
    struct vcs_package_prepared prepared; char detail[256] = {0};
    enum vcs_package_prepare_error err = vcs_package_prepare(
        &options, &prepared, detail, sizeof(detail));
    bool ok = err == VCS_PACKAGE_PREPARE_OK &&
        row_roots_match(&prepared, &rows[i]);
    if (ok)
        ok = lock_dag_matches(&prepared, i);
    if (derive && err == VCS_PACKAGE_PREPARE_OK) {
        *derived = print_derived_row(rows[i].name, &prepared, ctx);
    }
    if (!ok && !derive) {
        report_registry_mismatch(&rows[i], &prepared, err, detail);
        vcs_package_prepared_free(&prepared);
        return 1;
    }
    vcs_package_prepared_free(&prepared);
    if (ctx) secp256k1_context_destroy(ctx);
    return 0;
}

static int check_all_rows(bool derive, const char *derive_name, bool *derived)
{
    for (size_t i = 0; i < sizeof(rows) / sizeof(rows[0]); i++) {
        if (derive && strcmp(rows[i].name, derive_name) != 0)
            continue;
        if (check_registry_row(i, derive, derived) != 0)
            return 1;
    }
    return 0;
}

/* A bounded, per-invocation projection; never a durable registry authority. */
#define CORPUS_MAX 1024u
#define CORPUS_OUTPUT_MAX (16u * 1024u * 1024u)
struct corpus_item {
    const char *manifest;
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    uint8_t root[32];
    struct vcs_package_lock_node *deps;
    size_t count;
};
static bool corpus_component_valid(const char *start, const char *end)
{
    size_t len = (size_t)(end - start);
    return len && !(len == 1 && start[0] == '.') &&
           !(len == 2 && start[0] == '.' && start[1] == '.');
}
static bool corpus_components_valid(const char *path)
{
    const char *component = path;
    for (const unsigned char *p = (const unsigned char *)path; ; ++p) {
        if (*p && (*p < 32 || *p == 127 || *p == '\\')) return false;
        if (*p == '/' || !*p) {
            if (!corpus_component_valid(component, (const char *)p)) return false;
            if (!*p) return true;
            component = (const char *)p + 1;
        }
    }
}
static bool corpus_path(const char *path, size_t *dirlen)
{
    static const char suffix[] = "/zcode-package.json";
    size_t n = strlen(path), s = sizeof(suffix) - 1u;
    if (n <= s || n >= 4096 || path[0] == '/' || strcmp(path + n - s, suffix)) return false;
    if (!corpus_components_valid(path)) return false;
    *dirlen = n - s;
    return true;
}
static void corpus_free(struct corpus_item *items, size_t count)
{
    if (!items) return;
    for (size_t i = 0; i < count; ++i) free(items[i].deps);
    free(items);
}
static bool corpus_prepare(struct corpus_item *item, const char *root,
                           const char *manifest, const uint8_t pubkey[33])
{
    size_t dirlen;
    char dir[8192];
    if (!corpus_path(manifest, &dirlen)) {
        fprintf(stderr, "invalid corpus manifest: %s\n", manifest);
        return false;
    }
    int n = snprintf(dir, sizeof(dir), "%s/%.*s", root, (int)dirlen, manifest);
    if (n < 0 || (size_t)n >= sizeof(dir)) {
        fprintf(stderr, "corpus path too long: %s\n", manifest);
        return false;
    }
    struct vcs_package_prepare_options options = {
        .dir = dir, .publisher_sequence = 1, .reward_address = "", .chain_id = "zclassic-main"};
    memcpy(options.publisher_pubkey, pubkey, 33);
    struct vcs_package_prepared prepared;
    vcs_package_prepared_init(&prepared);
    char detail[256] = {0};
    enum vcs_package_prepare_error err = vcs_package_prepare(&options, &prepared, detail, sizeof(detail));
    if (err != VCS_PACKAGE_PREPARE_OK || !prepared.lock.count) {
        fprintf(stderr, "corpus prepare failed: %s (%s: %s)\n", manifest,
                vcs_package_prepare_error_string(err), detail);
        vcs_package_prepared_free(&prepared);
        return false;
    }
    item->manifest = manifest;
    memcpy(item->name, prepared.release.name, sizeof(item->name));
    memcpy(item->root, prepared.package_root, 32);
    item->count = prepared.lock.count - 1u;
    if (item->count) {
        item->deps = zcl_malloc(item->count * sizeof(*item->deps), "corpus.dependencies");
        if (item->deps) memcpy(item->deps, prepared.lock.nodes, item->count * sizeof(*item->deps));
    }
    vcs_package_prepared_free(&prepared);
    if (item->count && !item->deps) fprintf(stderr, "corpus dependency allocation failed: %s\n", manifest);
    return !item->count || item->deps;
}
static bool corpus_unique(const struct corpus_item *items, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        for (size_t k = 0; k < i; ++k) {
            if (!strcmp(items[i].name, items[k].name)) {
                fprintf(stderr, "duplicate corpus package: %s\n", items[i].name);
                return false;
            }
        }
    }
    return true;
}
static bool corpus_mismatch(struct json_value *array, const struct corpus_item *item,
                            const struct vcs_package_lock_node *dep, const uint8_t expected[32], size_t *used)
{
    char pinned[65], actual[65];
    zcl_hex_encode(dep->root, 32, pinned);
    zcl_hex_encode(expected, 32, actual);
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    bool ok = row.type == JSON_OBJ && json_push_kv_str(&row, "manifest", item->manifest) &&
        json_push_kv_str(&row, "name", dep->name) && json_push_kv_str(&row, "pinned", pinned) &&
        json_push_kv_str(&row, "expected", actual);
    size_t n = ok ? json_write(&row, NULL, 0) : 0;
    ok = n && *used < CORPUS_OUTPUT_MAX && n < CORPUS_OUTPUT_MAX - *used;
    if (ok) ok = json_push_back(array, &row);
    if (ok) *used += n + 1u;
    json_free(&row);
    return ok;
}
static bool corpus_compare(struct corpus_item *items, size_t count, struct json_value *mismatches)
{
    size_t used = 256u; /* Includes the fixed envelope, count, separators and newline. */
    for (size_t i = 0; i < count; ++i) {
        for (size_t d = 0; d < items[i].count; ++d) {
            size_t k = 0;
            while (k < count && strcmp(items[k].name, items[i].deps[d].name)) ++k;
            if (k == count) {
                fprintf(stderr, "missing corpus dependency: %s\n", items[i].deps[d].name);
                return false;
            }
            if (memcmp(items[i].deps[d].root, items[k].root, 32) &&
                !corpus_mismatch(mismatches, &items[i], &items[i].deps[d], items[k].root, &used)) return false;
        }
    }
    return true;
}
static bool corpus_emit(struct json_value *mismatches, size_t count)
{
    struct json_value obj;
    json_init(&obj);
    json_set_object(&obj);
    bool ok = obj.type == JSON_OBJ && json_push_kv_str(&obj, "schema", "zcl.package_corpus.v1") &&
        json_push_kv_int(&obj, "manifest_count", (int64_t)count) && json_push_kv(&obj, "mismatches", mismatches);
    size_t len = ok ? json_write(&obj, NULL, 0) : 0;
    char *wire = len && len < CORPUS_OUTPUT_MAX ? zcl_malloc(len + 1u, "corpus.output") : NULL;
    ok = ok && wire && json_write(&obj, wire, len + 1u) == len &&
        fwrite(wire, 1, len, stdout) == len && putchar('\n') != EOF;
    free(wire);
    json_free(&obj);
    return ok;
}
static int corpus_run(const char *root, char **manifests, size_t count)
{
    if (!root || !root[0] || !count || count > CORPUS_MAX) {
        fprintf(stderr, "invalid corpus inputs\n");
        return 2;
    }
    struct corpus_item *items = zcl_calloc(count, sizeof(*items), "corpus.items");
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    uint8_t pubkey[33];
    bool ok = items && derive_fixture_public(ctx, pubkey);
    for (size_t i = 0; ok && i < count; ++i) ok = corpus_prepare(&items[i], root, manifests[i], pubkey);
    if (ctx) secp256k1_context_destroy(ctx);
    struct json_value mismatches;
    json_init(&mismatches);
    json_set_array(&mismatches);
    ok = ok && mismatches.type == JSON_ARR && corpus_unique(items, count) &&
        corpus_compare(items, count, &mismatches) && corpus_emit(&mismatches, count);
    if (!ok) fprintf(stderr, "corpus comparison failed\n");
    json_free(&mismatches);
    corpus_free(items, count);
    return ok ? 0 : 1;
}

static int run_registry_check(int argc, char **argv)
{
    if (argc >= 4 && strcmp(argv[1], "--corpus") == 0)
        return corpus_run(argv[2], argv + 3, (size_t)argc - 3u);
    bool derive = argc == 3 && strcmp(argv[1], "--derive") == 0;
    bool derive_dir = argc == 3 && strcmp(argv[1], "--derive-dir") == 0;
    const char *derive_name = derive ? argv[2] : NULL;
    if (argc != 1 && !derive && !derive_dir) {
        fprintf(stderr,
                "usage: zcode-package-registry-check "
                "[--derive NAME|--derive-dir DIR|--corpus ROOT MANIFEST...]\n");
        return 2;
    }
    if (derive_dir)
        return derive_directory(argv[2]);
    if (sizeof(rows) / sizeof(rows[0]) < 8)
        return 1;
    bool derived = false;
    if (check_all_rows(derive, derive_name, &derived) != 0)
        return 1;
    if (derive)
        return derived ? 0 : 1;
    printf("zcode package registry: %zu roots and exact dependency DAG rederived\n",
           sizeof(rows) / sizeof(rows[0]));
    return 0;
}

int main(int argc, char **argv)
{
    int status = run_registry_check(argc, argv);
    if (fflush(stdout) == EOF || ferror(stdout)) {
        fprintf(stderr, "zcode package registry: could not write complete output\n");
        return status ? status : 1;
    }
    return status;
}
