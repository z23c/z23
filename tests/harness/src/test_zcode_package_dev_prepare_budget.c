/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: `zcode package dev prepare` must fit its reply budget for a package
 * of any size. A stranger who ran it on apps/skycombat (167 files) got
 * RESPONSE_BUDGET_EXCEEDED because the manifest, recipe, lock and capsule wires
 * were all inlined as hex. This builds a 220-file fixture and runs the leaf the
 * way the CLI does (registry execute under the leaf's budget): the reply must
 * succeed, keep the exact roots and the file count, say that it omitted the
 * large wires, and the full wires must stay reachable through
 * `zcode package dev prepare export`. */

#include "test/test_core.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/pubkey.h"
#include "vcs/package_prepare.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZPB_FILES 220u

static bool zpb_write(const char *root, const char *rel, const char *text)
{
    char path[640];
    (void)snprintf(path, sizeof(path), "%s/%s", root, rel);
    FILE *f = fopen(path, "wb");
    bool ok = f && fputs(text, f) >= 0;
    if (f) ok = fclose(f) == 0 && ok;
    return ok;
}

static bool zpb_fixture(char root[512])
{
    if (!test_mkdtemp(root, 512, "zcode_prepare_budget")) return false;
    char path[640];
    static const char *const dirs[] = { "src", "include" };
    for (size_t i = 0; i < 2; i++) {
        (void)snprintf(path, sizeof(path), "%s/%s", root, dirs[i]);
        if (mkdir(path, 0700) != 0) return false;
    }
    bool ok = zpb_write(root, "LICENSE", "MIT\n") &&
        zpb_write(root, "include/x.h", "int x(void);\n") &&
        zpb_write(root, "zcode-package.json",
            "{\"schema\":1,\"name\":\"zclassic23/bigfixture\",\"semver\":\"0.1.0-dev.1\","
            "\"language\":\"c23\",\"license\":\"MIT\",\"include_dir\":\"include\","
            "\"source_dir\":\"src\",\"dependencies\":[]}\n");
    for (unsigned i = 0; ok && i < ZPB_FILES; i++) {
        char rel[64], body[96];
        (void)snprintf(rel, sizeof(rel), "src/module_%03u_with_a_long_name.c", i);
        (void)snprintf(body, sizeof(body), "int f%03u(void) { return %u; }\n", i, i);
        ok = zpb_write(root, rel, body);
    }
    return ok;
}

static const struct zcl_command_spec *zpb_leaf(const char *path)
{
    return zcl_command_registry_find(zcl_command_catalog(), path, NULL);
}

static bool zpb_input(struct json_value *input, const char *root,
                      const char *pubkey_hex, const char *artifact_dir)
{
    json_init(input);
    json_set_object(input);
    bool ok = json_push_kv_str(input, "dir", root) &&
        json_push_kv_str(input, "publisher_pubkey", pubkey_hex) &&
        json_push_kv_int(input, "publisher_sequence", 1);
    if (artifact_dir)
        ok = ok && json_push_kv_str(input, "artifact_dir", artifact_dir) &&
             json_push_kv_bool(input, "confirm", true);
    return ok;
}

static size_t zpb_execute(const char *path, struct json_value *input,
                          char *out, size_t out_size,
                          enum zcl_command_exit *exit_code)
{
    const struct zcl_command_registry *registry = zcl_command_catalog();
    const struct zcl_command_spec *spec = zpb_leaf(path);
    struct zcl_command_context context = {
        .registry = registry,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
        .granted_capabilities = ~(uint64_t)0,
    };
    *exit_code = ZCL_COMMAND_EXIT_INTERNAL;
    if (!spec) return 0;
    return zcl_command_registry_execute_json(registry, spec, &context, input,
        false, spec->path, "full", 0, 0, NULL, out, out_size, exit_code);
}

static bool zpb_next_names_export(const struct json_value *envelope)
{
    const struct json_value *next = json_get(envelope, "next");
    for (size_t i = 0; next && i < json_size(next); i++) {
        const char *cmd = json_get_str(json_get(json_at(next, i), "command"));
        if (cmd && strstr(cmd, "prepare.export")) return true;
    }
    return false;
}

static bool zpb_file_equals(const char *dir, const char *name,
                            const uint8_t *bytes, size_t len)
{
    char path[640];
    (void)snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    uint8_t *buf = malloc(len + 1u);
    bool ok = buf && fread(buf, 1, len + 1u, f) == len && memcmp(buf, bytes, len) == 0;
    free(buf);
    (void)fclose(f);
    return ok;
}

static bool zpb_reply_matches(const struct json_value *data,
                              const struct vcs_package_prepared *prepared)
{
    char hex[65];
    zcl_hex_encode(prepared->package_root, 32, hex);
    const char *root = json_get_str(json_get(data, "package_root"));
    const struct json_value *count = json_get(data, "file_count");
    const struct json_value *truncated = json_get(data, "truncated");
    return root && strcmp(root, hex) == 0 && count &&
        json_get_int(count) == (int64_t)prepared->manifest.count &&
        prepared->manifest.count >= ZPB_FILES && truncated &&
        json_get_bool(truncated) && json_get(data, "release_body_hex") &&
        json_get(data, "manifest_bytes") &&
        json_get_int(json_get(data, "manifest_bytes")) ==
            (int64_t)prepared->manifest_wire_len &&
        !json_get(data, "manifest_hex");
}

static bool zpb_content_fixture(char root[512])
{
    if (!zpb_fixture(root)) return false;
    char path[640];
    (void)snprintf(path, sizeof(path), "%s/app", root);
    return mkdir(path, 0700) == 0 &&
        zpb_write(root, "app/main.c", "int main(void) { return 0; }\n") &&
        zpb_write(root, "zcode-package.json",
            "{\"schema\":1,\"name\":\"zclassic23/bigfixture\",\"semver\":\"0.1.0\","
            "\"language\":\"c23\",\"license\":\"MIT\",\"include_dir\":\"include\","
            "\"source_dir\":\"src\",\"dependencies\":[],\"programs\":[\"app/main.c\"],"
            "\"files\":[\"LICENSE\",\"app/main.c\",\"include/x.h\","
            "\"src/module_000_with_a_long_name.c\",\"zcode-package.json\"]}\n");
}

static bool zpb_no_release(const struct vcs_package_prepared *p)
{
    static const struct vcs_package_release zero = {0};
    static const uint8_t digest[32] = {0};
    return !p->release_body && p->release_body_len == 0 &&
        !memcmp(&p->release, &zero, sizeof(zero)) &&
        !memcmp(p->signing_digest, digest, sizeof(digest));
}

static bool zpb_content_equal(const struct vcs_package_prepared *a,
                               const struct vcs_package_prepared *b)
{
    const uint8_t *aw[] = {a->manifest_wire, a->recipe_wire, a->lock_wire, a->capsule_wire};
    const uint8_t *bw[] = {b->manifest_wire, b->recipe_wire, b->lock_wire, b->capsule_wire};
    const size_t al[] = {a->manifest_wire_len, a->recipe_wire_len, a->lock_wire_len, a->capsule_wire_len};
    const size_t bl[] = {b->manifest_wire_len, b->recipe_wire_len, b->lock_wire_len, b->capsule_wire_len};
    const uint8_t *ar[] = {a->package_root, a->recipe_root, a->lock_root, a->capsule_root};
    const uint8_t *br[] = {b->package_root, b->recipe_root, b->lock_root, b->capsule_root};
    for (size_t i = 0; i < 4; ++i)
        if (!al[i] || al[i] != bl[i] || memcmp(aw[i], bw[i], al[i]) || memcmp(ar[i], br[i], 32))
            return false;
    return true;
}

/* Compare actual canonical wires, not a second implementation of prepare. */
static bool zpb_content_parity(const char *root, const struct vcs_package_prepared *content)
{
    struct privkey sk; struct pubkey pk;
    memset(sk.vch, 0x41, 32); sk.fValid = true; sk.fCompressed = true;
    if (!privkey_get_pubkey(&sk, &pk) || pk.size != 33) return false;
    struct vcs_package_prepare_options options = { .dir = root, .publisher_sequence = 1 };
    memcpy(options.publisher_pubkey, pk.vch, 33);
    struct vcs_package_prepared full;
    char detail[256];
    bool ok = vcs_package_prepare(&options, &full, detail, sizeof(detail)) ==
        VCS_PACKAGE_PREPARE_OK && full.release_body && full.release_body_len &&
        zpb_content_equal(content, &full);
    vcs_package_prepared_free(&full);
    memset(options.publisher_pubkey, 0, sizeof(options.publisher_pubkey));
    if (ok) ok = vcs_package_prepare(&options, &full, detail, sizeof(detail)) ==
        VCS_PACKAGE_PREPARE_ERR_RELEASE && zpb_no_release(&full);
    vcs_package_prepared_free(&full);
    return ok;
}

static bool zpb_content_refusals(const char *root)
{
    static const char *const invalid[] = {
        "{", "{}", "{\"schema\":1,\"unknown\":true}"
    };
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        if (!zpb_write(root, "zcode-package.json", invalid[i])) return false;
        struct vcs_package_prepared p;
        char detail[256];
        bool ok = vcs_package_prepare_content(root, &p, detail, sizeof(detail)) ==
            VCS_PACKAGE_PREPARE_ERR_META && zpb_no_release(&p) &&
            !p.manifest_wire && !p.recipe_wire && !p.lock_wire && !p.capsule_wire;
        vcs_package_prepared_free(&p);
        if (!ok) return false;
    }
    return true;
}

static bool zpb_content_control(const char *root)
{
    struct vcs_package_prepared content;
    char detail[256], control[640];
    /* This call precedes even the in-memory public-key fixture derivation. */
    bool ok = vcs_package_prepare_content(root, &content, detail, sizeof(detail)) ==
        VCS_PACKAGE_PREPARE_OK && zpb_no_release(&content) &&
        content.manifest.count == 5 && content.recipe.sources.count == 1 &&
        content.recipe.programs.count == 1 && zpb_content_parity(root, &content);
    (void)snprintf(control, sizeof(control), "%s/.zvcs", root);
    struct stat st;
    ok = ok && stat(control, &st) != 0 && errno == ENOENT;
    struct vcs_package_prepared again;
    vcs_package_prepared_init(&again);
    if (ok) ok = vcs_package_prepare_content(root, &again, detail, sizeof(detail)) ==
        VCS_PACKAGE_PREPARE_OK && zpb_content_equal(&content, &again);
    vcs_package_prepared_free(&again);
    vcs_package_prepared_free(&content);
    return ok && zpb_content_refusals(root);
}

static int zpb_content_tests(void)
{
    int failures = 0;
    TEST("package prepare content: full metadata/program parity without release authority") {
        char root[512] = {0};
        bool ok = zpb_content_fixture(root) && zpb_content_control(root);
        if (root[0]) (void)test_rm_rf_recursive(root);
        ASSERT(ok);
        PASS();
    } _test_next:;
    return failures;
}

int test_zcode_package_dev_prepare_budget(void)
{
    int failures = 0;
    chain_params_select(CHAIN_MAIN);
    failures += zpb_content_tests();
    TEST("zcode package dev prepare: a 220-file package fits the reply budget") {
        char root[512], artifacts[640], pubkey_hex[67];
        struct privkey sk; struct pubkey pk;
        memset(sk.vch, 0x41, 32); sk.fValid = true; sk.fCompressed = true;
        ASSERT(privkey_get_pubkey(&sk, &pk) && pk.size == 33);
        zcl_hex_encode(pk.vch, 33, pubkey_hex);
        ASSERT(zpb_fixture(root));
        (void)snprintf(artifacts, sizeof(artifacts), "%s_artifacts", root);

        struct vcs_package_prepare_options options = {
            .dir = root, .publisher_sequence = 1, .reward_address = "",
            .chain_id = "zclassic-main",
        };
        memcpy(options.publisher_pubkey, pk.vch, 33);
        struct vcs_package_prepared prepared;
        char detail[256];
        ASSERT(vcs_package_prepare(&options, &prepared, detail, sizeof(detail)) ==
               VCS_PACKAGE_PREPARE_OK);

        struct json_value input;
        ASSERT(zpb_input(&input, root, pubkey_hex, NULL));
        static char envelope[ZCL_COMMAND_LIST_BUDGET + 1u];
        enum zcl_command_exit exit_code;
        size_t bytes = zpb_execute("zcode.package.dev.prepare", &input,
                                   envelope, sizeof(envelope), &exit_code);
        json_free(&input);
        ASSERT(exit_code == ZCL_COMMAND_EXIT_OK);
        ASSERT(bytes > 0 && bytes <= ZCL_COMMAND_LIST_BUDGET);
        ASSERT(strstr(envelope, "RESPONSE_BUDGET_EXCEEDED") == NULL);
        struct json_value parsed;
        json_init(&parsed);
        ASSERT(json_read(&parsed, envelope, bytes));
        ASSERT(zpb_reply_matches(json_get(&parsed, "data"), &prepared));
        ASSERT(zpb_next_names_export(&parsed));
        json_free(&parsed);

        /* The full wires stay reachable through the explicit export option. */
        ASSERT(zpb_input(&input, root, pubkey_hex, artifacts));
        bytes = zpb_execute("zcode.package.dev.prepare.export", &input,
                            envelope, sizeof(envelope), &exit_code);
        json_free(&input);
        ASSERT(exit_code == ZCL_COMMAND_EXIT_OK && bytes > 0);
        ASSERT(zpb_file_equals(artifacts, "manifest.wire",
                               prepared.manifest_wire, prepared.manifest_wire_len));
        ASSERT(zpb_file_equals(artifacts, "release-body.wire",
                               prepared.release_body, prepared.release_body_len));
        vcs_package_prepared_free(&prepared);
        (void)test_rm_rf_recursive(root);
        (void)test_rm_rf_recursive(artifacts);
        PASS();
    } _test_next:;
    return failures;
}
