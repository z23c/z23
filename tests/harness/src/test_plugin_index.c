/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: prove the signed plugin index: entries are canonical and verified,
 * search marks publishers pinned or unpinned, folds to the latest version per
 * publisher and plugin, refuses rollbacks, bad signatures and malformed
 * entries, and folds byte-identical copies. Fixtures sign with real Ed25519. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "json/json.h"
#include "plugin/plugin_index.h"
#include "plugin/plugin_pack.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define ROOT_A "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define ROOT_B "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

struct pix {
    char base[1024], index[1100], pins[1100], key_a[1100], key_b[1100];
    uint8_t seed_a[32], seed_b[32];
    char pub_a[65], pub_b[65];
};

static bool pix_write(const char *path, const char *bytes, size_t len, mode_t mode)
{
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(bytes, 1, len, f) == len;
    if (f)
        ok = fclose(f) == 0 && ok;
    return ok && chmod(path, mode) == 0;
}

static bool pix_seed(const char *path, uint8_t seed[32])
{
    FILE *f = fopen(path, "rb");
    bool ok = f && fread(seed, 1, 32, f) == 32;
    if (f)
        fclose(f);
    return ok;
}

static bool pix_open(struct pix *p)
{
    char pins_text[200];
    memset(p, 0, sizeof(*p));
    return test_mkdtemp(p->base, sizeof(p->base), "plugin_index") &&
           snprintf(p->index, sizeof(p->index), "%s/index", p->base) > 0 &&
           snprintf(p->pins, sizeof(p->pins), "%s/pins", p->base) > 0 &&
           snprintf(p->key_a, sizeof(p->key_a), "%s/a.key", p->base) > 0 &&
           snprintf(p->key_b, sizeof(p->key_b), "%s/b.key", p->base) > 0 &&
           plugin_keygen(p->key_a, p->pub_a) == PLUGIN_OK &&
           plugin_keygen(p->key_b, p->pub_b) == PLUGIN_OK &&
           pix_seed(p->key_a, p->seed_a) && pix_seed(p->key_b, p->seed_b) &&
           snprintf(pins_text, sizeof(pins_text), "%s\n", p->pub_a) > 0 &&
           pix_write(p->pins, pins_text, strlen(pins_text), 0600);
}

static void pix_close(struct pix *p)
{
    if (p->base[0])
        (void)test_rm_rf_recursive(p->base);
}

/* Builds a signed entry; the encoded bytes land in bytes. */
static bool pix_entry(const uint8_t seed[32], const char *name,
                      const char *version, const char *root, int64_t ts,
                      unsigned caps, char *bytes, size_t *len,
                      struct plugin_index_entry *e)
{
    struct plugin_index_entry local;
    if (!e)
        e = &local;
    memset(e, 0, sizeof(*e));
    snprintf(e->name, sizeof(e->name), "%s", name);
    snprintf(e->version, sizeof(e->version), "%s", version);
    snprintf(e->root, sizeof(e->root), "%s", root);
    e->interface_version = 2;
    e->capabilities = caps;
    e->timestamp = ts;
    return plugin_index_encode(e, seed, bytes, PLUGIN_INDEX_ENTRY_MAX + 1, len) ==
           PLUGIN_INDEX_OK;
}

/* Plants entry bytes by hand, as a hostile peer's directory would hold them. */
static bool pix_plant(const struct pix *p, const char *leaf, const char *bytes,
                      size_t len)
{
    char path[1300];
    (void)mkdir(p->index, 0755); /* already present on a second plant */
    return snprintf(path, sizeof(path), "%s/%s" PLUGIN_INDEX_SUFFIX, p->index,
                    leaf) > 0 && pix_write(path, bytes, len, 0644);
}

static bool pix_has_refusal(const struct plugin_index_report *r, const char *code)
{
    for (size_t i = 0; i < r->refusal_count; i++)
        if (strcmp(r->refusals[i].code, code) == 0)
            return true;
    return false;
}

static int pix_case_bad_signature(void)
{
    int failures = 0;
    struct pix p;
    bool ready = pix_open(&p);
    TEST_CASE("plugin index: a bad signature is refused and never listed") {
        char good[PLUGIN_INDEX_ENTRY_MAX + 1], bad[PLUGIN_INDEX_ENTRY_MAX + 1];
        size_t len = 0;
        struct plugin_index_entry e;
        struct plugin_index_report rep;
        ASSERT(ready);
        ASSERT(pix_entry(p.seed_a, "hello", "1.0.0", ROOT_A, 100, 0, good, &len, &e));
        ASSERT_EQ(plugin_index_parse(good, len, &e), PLUGIN_INDEX_OK);
        /* Same canonical shape, one signature digit changed. */
        memcpy(bad, good, len + 1);
        char *sig = strstr(bad, "\"signature\":\"") + 13;
        *sig = *sig == '0' ? '1' : '0';
        ASSERT_EQ(plugin_index_parse(bad, len, &e), PLUGIN_INDEX_BAD_SIGNATURE);
        /* Same signature, a different signed field: the version. */
        memcpy(bad, good, len + 1);
        char *ver = strstr(bad, "1.0.0");
        ASSERT(ver != NULL);
        ver[4] = '1';
        ASSERT_EQ(plugin_index_parse(bad, len, &e), PLUGIN_INDEX_BAD_SIGNATURE);
        /* The publisher key swapped for another key: the signature is not theirs. */
        memcpy(bad, good, len + 1);
        char *pub = strstr(bad, p.pub_a);
        ASSERT(pub != NULL);
        memcpy(pub, p.pub_b, 64);
        ASSERT_EQ(plugin_index_parse(bad, len, &e), PLUGIN_INDEX_BAD_SIGNATURE);
        ASSERT_EQ(plugin_index_add(p.index, bad, len, NULL, NULL), PLUGIN_INDEX_BAD_SIGNATURE);
        ASSERT(pix_plant(&p, "forged", bad, len));
        ASSERT_EQ(plugin_index_search(p.index, p.pins, NULL, &rep), PLUGIN_INDEX_OK);
        ASSERT_EQ(rep.row_count, 0);
        ASSERT(pix_has_refusal(&rep, "PLUGIN_INDEX_BAD_SIGNATURE"));
        plugin_index_report_free(&rep);
    } TEST_END
    pix_close(&p);
    return failures;
}

static int pix_case_pinned(void)
{
    int failures = 0;
    struct pix p;
    bool ready = pix_open(&p);
    TEST_CASE("plugin index: search marks each publisher pinned or unpinned") {
        char a[PLUGIN_INDEX_ENTRY_MAX + 1], b[PLUGIN_INDEX_ENTRY_MAX + 1];
        size_t la = 0, lb = 0;
        struct plugin_index_report rep;
        struct plugin_index_query q = { .name = NULL, .capabilities = 0 };
        ASSERT(ready);
        ASSERT(pix_entry(p.seed_a, "alpha", "1.0.0", ROOT_A, 100, 0, a, &la, NULL));
        ASSERT(pix_entry(p.seed_b, "beta", "2.0.0", ROOT_B, 100, 1u, b, &lb, NULL));
        ASSERT_EQ(plugin_index_add(p.index, a, la, NULL, NULL), PLUGIN_INDEX_OK);
        ASSERT_EQ(plugin_index_add(p.index, b, lb, NULL, NULL), PLUGIN_INDEX_OK);
        ASSERT_EQ(plugin_index_search(p.index, p.pins, &q, &rep), PLUGIN_INDEX_OK);
        ASSERT_EQ(rep.row_count, 2);
        ASSERT_STR_EQ(rep.rows[0].entry.name, "alpha");
        ASSERT(rep.rows[0].pinned);
        ASSERT_STR_EQ(rep.rows[1].entry.name, "beta");
        ASSERT(!rep.rows[1].pinned);
        plugin_index_report_free(&rep);
        /* Filters: exact name, and required capability bits. */
        q.name = "beta";
        ASSERT_EQ(plugin_index_search(p.index, p.pins, &q, &rep), PLUGIN_INDEX_OK);
        ASSERT_EQ(rep.row_count, 1);
        plugin_index_report_free(&rep);
        q.name = NULL;
        q.capabilities = 1u;
        ASSERT_EQ(plugin_index_search(p.index, p.pins, &q, &rep), PLUGIN_INDEX_OK);
        ASSERT_EQ(rep.row_count, 1);
        ASSERT_STR_EQ(rep.rows[0].entry.name, "beta");
        plugin_index_report_free(&rep);
        /* A pin file that is not owner-only is refused, not read as empty. */
        ASSERT_EQ(chmod(p.pins, 0666), 0);
        ASSERT_EQ(plugin_index_search(p.index, p.pins, NULL, &rep), PLUGIN_INDEX_PINS);
        ASSERT_EQ(chmod(p.pins, 0600), 0);
    } TEST_END
    pix_close(&p);
    return failures;
}

static int pix_case_rollback(void)
{
    int failures = 0;
    struct pix p;
    bool ready = pix_open(&p);
    TEST_CASE("plugin index: a lower version from the same publisher is a rollback") {
        char v1[PLUGIN_INDEX_ENTRY_MAX + 1], v2[PLUGIN_INDEX_ENTRY_MAX + 1];
        char v10[PLUGIN_INDEX_ENTRY_MAX + 1], eq[PLUGIN_INDEX_ENTRY_MAX + 1];
        size_t l1 = 0, l2 = 0, l10 = 0, leq = 0;
        struct plugin_index_report rep;
        ASSERT(ready);
        ASSERT_EQ(plugin_index_version_cmp("1.10.0", "1.9.0") > 0, 1);
        ASSERT_EQ(plugin_index_version_cmp("1.02", "1.2"), 0);
        ASSERT(plugin_index_version_cmp("1.0.0", "1.0.1") < 0);
        ASSERT(pix_entry(p.seed_a, "hello", "1.9.0", ROOT_A, 100, 0, v1, &l1, NULL));
        ASSERT(pix_entry(p.seed_a, "hello", "1.10.0", ROOT_B, 200, 0, v2, &l2, NULL));
        ASSERT(pix_entry(p.seed_a, "hello", "1.0.0", ROOT_A, 300, 0, v10, &l10, NULL));
        ASSERT(pix_entry(p.seed_a, "hello", "1.10.0", ROOT_A, 400, 0, eq, &leq, NULL));
        ASSERT_EQ(plugin_index_add(p.index, v1, l1, NULL, NULL), PLUGIN_INDEX_OK);
        ASSERT_EQ(plugin_index_add(p.index, v2, l2, NULL, NULL), PLUGIN_INDEX_OK);
        ASSERT_EQ(plugin_index_add(p.index, v10, l10, NULL, NULL), PLUGIN_INDEX_ROLLBACK);
        /* Same version, a different root: one version names one package. */
        ASSERT_EQ(plugin_index_add(p.index, eq, leq, NULL, NULL),
                  PLUGIN_INDEX_EQUIVOCATION);
        /* A hand-planted rollback with the newest timestamp does not win. */
        ASSERT(pix_plant(&p, "rollback", v10, l10));
        ASSERT(pix_plant(&p, "equivocation", eq, leq));
        ASSERT_EQ(plugin_index_search(p.index, p.pins, NULL, &rep), PLUGIN_INDEX_OK);
        ASSERT_EQ(rep.row_count, 1);
        ASSERT_STR_EQ(rep.rows[0].entry.version, "1.10.0");
        ASSERT_STR_EQ(rep.rows[0].entry.root, ROOT_B);
        ASSERT(pix_has_refusal(&rep, "PLUGIN_INDEX_ROLLBACK"));
        ASSERT(pix_has_refusal(&rep, "PLUGIN_INDEX_EQUIVOCATION"));
        ASSERT_EQ(rep.superseded, 1);
        plugin_index_report_free(&rep);
    } TEST_END
    pix_close(&p);
    return failures;
}

static int pix_case_malformed(void)
{
    int failures = 0;
    struct pix p;
    bool ready = pix_open(&p);
    TEST_CASE("plugin index: malformed entries are refused, never parsed leniently") {
        char good[PLUGIN_INDEX_ENTRY_MAX + 1], bad[PLUGIN_INDEX_ENTRY_MAX + 8];
        size_t len = 0;
        struct plugin_index_entry e;
        struct plugin_index_report rep;
        ASSERT(ready);
        ASSERT(pix_entry(p.seed_a, "hello", "1.0.0", ROOT_A, 100, 3u, good, &len, NULL));
        ASSERT_EQ(plugin_index_parse(good, len, &e), PLUGIN_INDEX_OK);
        ASSERT_EQ(e.capabilities, 3u);
        ASSERT_EQ(plugin_index_parse("", 0, &e), PLUGIN_INDEX_MALFORMED);
        ASSERT_EQ(plugin_index_parse("{}\n", 3, &e), PLUGIN_INDEX_MALFORMED);
        ASSERT_EQ(plugin_index_parse("not json at all", 15, &e), PLUGIN_INDEX_MALFORMED);
        ASSERT_EQ(plugin_index_parse(good, len - 1, &e), PLUGIN_INDEX_MALFORMED); /* no LF */
        ASSERT_EQ(plugin_index_parse(good, len / 2, &e), PLUGIN_INDEX_MALFORMED);
        /* Trailing byte, leading space, extra key, repeated key, upper case hex. */
        snprintf(bad, sizeof(bad), "%s ", good);
        ASSERT_EQ(plugin_index_parse(bad, len + 1, &e), PLUGIN_INDEX_MALFORMED);
        snprintf(bad, sizeof(bad), " %s", good);
        ASSERT_EQ(plugin_index_parse(bad, len + 1, &e), PLUGIN_INDEX_MALFORMED);
        memcpy(bad, good, len + 1);
        memcpy(strstr(bad, "\"name\""), "\"nane\"", 6);
        ASSERT_EQ(plugin_index_parse(bad, len, &e), PLUGIN_INDEX_MALFORMED);
        memcpy(bad, good, len + 1);
        memcpy(strstr(bad, "\"root\""), "\"name\"", 6); /* repeated key */
        ASSERT_EQ(plugin_index_parse(bad, len, &e), PLUGIN_INDEX_MALFORMED);
        memcpy(bad, good, len + 1);
        *strstr(bad, "aaaa") = 'A';
        ASSERT_EQ(plugin_index_parse(bad, len, &e), PLUGIN_INDEX_MALFORMED);
        /* No single-byte change of a valid entry may still be accepted. */
        for (size_t i = 0; i < len; i++) {
            memcpy(bad, good, len + 1);
            bad[i] = (char)(bad[i] ^ 0x01);
            ASSERT(plugin_index_parse(bad, len, &e) != PLUGIN_INDEX_OK);
        }
        ASSERT(pix_plant(&p, "junk", "{\"schema\":", 10));
        ASSERT_EQ(plugin_index_search(p.index, p.pins, NULL, &rep), PLUGIN_INDEX_OK);
        ASSERT_EQ(rep.row_count, 0);
        ASSERT(pix_has_refusal(&rep, "PLUGIN_INDEX_MALFORMED"));
        plugin_index_report_free(&rep);
    } TEST_END
    pix_close(&p);
    return failures;
}

static int pix_case_dedupe(void)
{
    int failures = 0;
    struct pix p;
    bool ready = pix_open(&p);
    TEST_CASE("plugin index: a duplicate entry is folded into one") {
        char a[PLUGIN_INDEX_ENTRY_MAX + 1];
        size_t la = 0;
        bool present = true;
        struct plugin_index_report rep;
        ASSERT(ready);
        ASSERT(pix_entry(p.seed_a, "hello", "1.0.0", ROOT_A, 100, 0, a, &la, NULL));
        ASSERT_EQ(plugin_index_add(p.index, a, la, NULL, &present), PLUGIN_INDEX_OK);
        ASSERT(!present);
        ASSERT_EQ(plugin_index_add(p.index, a, la, NULL, &present), PLUGIN_INDEX_OK);
        ASSERT(present);
        ASSERT(pix_plant(&p, "copy-of-the-same-entry", a, la));
        ASSERT_EQ(plugin_index_search(p.index, p.pins, NULL, &rep), PLUGIN_INDEX_OK);
        ASSERT_EQ(rep.scanned, 2);
        ASSERT_EQ(rep.row_count, 1);
        ASSERT_EQ(rep.duplicates, 1);
        ASSERT_EQ(rep.refusal_count, 0);
        plugin_index_report_free(&rep);
    } TEST_END
    pix_close(&p);
    return failures;
}

static bool pix_call(zcl_command_handler_fn fn, const char *input_json,
                     struct zcl_command_reply *reply)
{
    struct json_value input;
    json_init(&input);
    bool ok = json_read(&input, input_json, strlen(input_json));
    struct zcl_command_request request = { .input = &input, .view = "normal" };
    zcl_command_reply_init(reply, "zcl.plugin_index_test.v1");
    if (ok)
        fn(&request, reply);
    json_free(&input);
    return ok;
}

static int pix_case_commands(void)
{
    int failures = 0;
    struct pix p;
    bool ready = pix_open(&p);
    TEST_CASE("plugin index: index_add and search work end to end and fetch nothing") {
        char exe[1100], dist[1100], manifest[1200], in[4400];
        struct plugin_pack_request pack = {0};
        struct plugin_pack_result packed;
        struct zcl_command_reply r;
        ASSERT(ready);
        ASSERT(snprintf(exe, sizeof(exe), "%s/image", p.base) > 0);
        ASSERT(snprintf(dist, sizeof(dist), "%s/dist", p.base) > 0);
        ASSERT(pix_write(exe, "inert image\n", 12, 0700));
        pack.exe_path = exe;
        pack.name = "hello";
        pack.version = "1.0.0";
        pack.key_path = p.key_a;
        pack.out_dir = dist;
        pack.interface_version = 2;
        ASSERT_EQ(plugin_pack(&pack, &packed), PLUGIN_OK);
        snprintf(manifest, sizeof(manifest), "%s", packed.manifest_path);
        snprintf(in, sizeof(in),
                 "{\"root\":\"%s\",\"manifest\":\"%s\",\"key\":\"%s\",\"index\":\"%s\"}",
                 ROOT_A, manifest, p.key_a, p.index);
        ASSERT(pix_call(zcl_native_handle_plugin_index_add, in, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_STR_EQ(json_get_str(json_get(&r.data, "publisher")), p.pub_a);
        zcl_command_reply_free(&r);
        /* A manifest signed by a different key than the entry key is refused. */
        snprintf(in, sizeof(in),
                 "{\"root\":\"%s\",\"manifest\":\"%s\",\"key\":\"%s\",\"index\":\"%s\"}",
                 ROOT_A, manifest, p.key_b, p.index);
        ASSERT(pix_call(zcl_native_handle_plugin_index_add, in, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_KEY_UNKNOWN");
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in),
                 "{\"root\":\"nothex\",\"manifest\":\"%s\",\"key\":\"%s\",\"index\":\"%s\"}",
                 manifest, p.key_a, p.index);
        ASSERT(pix_call(zcl_native_handle_plugin_index_add, in, &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_INDEX_ARGUMENT");
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in), "{\"name\":\"hello\",\"index\":\"%s\",\"publishers\":\"%s\"}",
                 p.index, p.pins);
        ASSERT(pix_call(zcl_native_handle_plugin_search, in, &r));
        ASSERT_EQ(r.exit_code, ZCL_COMMAND_EXIT_OK);
        ASSERT_EQ(json_get_int(json_get(&r.data, "count")), 1);
        const struct json_value *row = json_at(json_get(&r.data, "plugins"), 0);
        ASSERT_STR_EQ(json_get_str(json_get(row, "publisher_status")), "pinned");
        ASSERT_STR_EQ(json_get_str(json_get(row, "root")), ROOT_A);
        zcl_command_reply_free(&r);
        snprintf(in, sizeof(in),
                 "{\"cap\":\"clock\",\"index\":\"%s\",\"publishers\":\"%s\"}",
                 p.index, p.pins);
        ASSERT(pix_call(zcl_native_handle_plugin_search, in, &r));
        ASSERT_EQ(json_get_int(json_get(&r.data, "count")), 0);
        zcl_command_reply_free(&r);
        ASSERT(pix_call(zcl_native_handle_plugin_search, "{\"cap\":\"bogus\"}", &r));
        ASSERT_STR_EQ(r.error.code, "PLUGIN_INDEX_ARGUMENT");
        zcl_command_reply_free(&r);
    } TEST_END
    pix_close(&p);
    return failures;
}

int test_plugin_index(void)
{
    int failures = 0;
    failures += pix_case_bad_signature();
    failures += pix_case_pinned();
    failures += pix_case_rollback();
    failures += pix_case_malformed();
    failures += pix_case_dedupe();
    failures += pix_case_commands();
    return failures;
}
