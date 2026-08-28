/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Tests for `app shop init` / `app shop status` (slice B of
 * docs/work/SHOP_COMMAND.md; handlers in
 * app/controllers/src/shop_native_handler.c).
 *
 * Covered:
 *   1. status on a fresh datadir is a read leaf that NAMES every gap
 *      (identity, wallet, announcement — and the Tor stub build when this
 *      binary links the stub), never a silent partial
 *   2. init refuses a plaintext wallet by name (WALLET_NOT_ENCRYPTED) with
 *      the credential recipe in the message — and the refusal mutates
 *      NOTHING (no identity minted, no apps.csv written)
 *   3. init on a stub-Tor build names TOR_STUB_BUILD with the make tor-full
 *      remedy; on a real build the same commit succeeds end to end and is
 *      idempotent on re-run
 *   4. the plan path is non-mutating, and the bare plan serializes inside
 *      the CLI's real reply budget (ZCL_COMMAND_LIST_BUDGET + 1) instead of
 *      collapsing to an empty RESPONSE_BUDGET_EXCEEDED
 *   5. the products.json path: shop_provision_products_json copies the
 *      --input file to <datadir>/store/products.json and the existing
 *      loader (store_ensure_schema) provisions it, which status then
 *      reports
 *   6. the directory announcement: shop_announce_directory_app writes
 *      "shop" into <datadir>/directory/apps.csv, deduped, and lib/net's
 *      onion_directory_extra_apps_csv reads it back
 *   7. the wallet posture probe's four states (absent / plaintext /
 *      encrypted-via-envelope / encrypted-via-wrapped-DEK / unreadable)
 *
 * No node, no network, no running Tor: every case is an in-process call
 * against a fixture datadir under ./test-tmp. The two Tor-gated cases
 * branch on shop_tor_real_build_linked() so the group passes on both the
 * default stub build and a tor-full build. */

#include "test/test_core.h"

#include "command/native_command.h"
#include "config/command_catalog.h"     /* zcl_command_catalog */
#include "controllers/shop_native_handler.h"
#include "controllers/store_controller_internal.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "models/store.h"
#include "net/onion_service.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SH_CHECK(name, expr) do {                                       \
    printf("shop: %s... ", (name));                                     \
    if (expr) { printf("OK\n"); }                                       \
    else { printf("FAIL\n"); failures++; }                              \
} while (0)

/* ── fixture helpers ────────────────────────────────────────────────── */

/* Make a fixture datadir under ./test-tmp and hand it back as an ABSOLUTE
 * path.
 *
 * test_make_tmpdir spells the directory relative to the working directory
 * ("./test-tmp/shop_<pid>_<tag>"). The shop handlers write products.json and
 * the /directory apps.csv row through shp_write_file_atomic ->
 * platform_private_path_resolve, which realpath()s the destination's parent
 * and refuses any pathname that does not start at the root ("destination
 * parent is not a safe real directory"). A relative datadir is rejected
 * before a byte is written, so the fixture must hand the handlers the
 * absolute spelling of the same in-tree directory. */
static void sh_tmpdir(char *dir, size_t dir_size, const char *tag)
{
    char rel[192];
    test_make_tmpdir(rel, sizeof(rel), "shop", tag);

    const char *leaf = rel;
    if (leaf[0] == '.' && leaf[1] == '/')
        leaf += 2;

    char cwd[256];
    if (!getcwd(cwd, sizeof(cwd))) {
        (void)snprintf(dir, dir_size, "%s", rel);  /* write fails loudly */
        return;
    }
    (void)snprintf(dir, dir_size, "%s/%s", cwd, leaf);
}

/* Create <dir> with a migrated node.db inside it. */
static bool sh_mk_datadir(char *dir, size_t dir_size, const char *tag)
{
    sh_tmpdir(dir, dir_size, tag);
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    struct node_db ndb;
    if (!node_db_open(&ndb, path))
        return false;
    node_db_close(&ndb);
    return true;
}

static bool sh_file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Run one handler and hand the reply back; the caller owns both. */
static void sh_call(void (*fn)(const struct zcl_command_request *,
                               struct zcl_command_reply *),
                    struct json_value *input,
                    struct zcl_command_reply *reply)
{
    struct zcl_command_request request = { .input = input };
    zcl_command_reply_init(reply, "zcl.test.v1");
    fn(&request, reply);
}

static void sh_input_open(struct json_value *input, const char *dir)
{
    json_init(input);
    json_set_object(input);
    if (dir)
        (void)json_push_kv_str(input, "datadir", dir);
}

static const char *sh_str(const struct json_value *obj, const char *key)
{
    const char *s = json_get_str(json_get(obj, key));
    return s ? s : "";
}

/* Is `gap` one of the named gaps in the reply's gaps array? */
static bool sh_gap_present(const struct zcl_command_reply *reply,
                           const char *gap)
{
    const struct json_value *gaps = json_get(&reply->data, "gaps");
    if (!gaps || gaps->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < gaps->num_children; i++) {
        const char *g = json_get_str(json_get(&gaps->children[i], "gap"));
        if (g && strcmp(g, gap) == 0)
            return true;
    }
    return false;
}

/* Run one SQL statement against the fixture's node.db (test-side fixture
 * setup — the controllers raw-sql gate does not apply to lib/test). */
static bool sh_exec_sql(const char *dir, const char *sql)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/node.db", dir);
    sqlite3 *db = NULL;
    if (sqlite3_open(path, &db) != SQLITE_OK || !db) {
        if (db) sqlite3_close(db);
        return false;
    }
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (errmsg) {
        printf("  (fixture sql error: %s)\n", errmsg);
        sqlite3_free(errmsg);
    }
    sqlite3_close(db);
    return rc == SQLITE_OK;
}

/* Plant a wallet_seed row. encrypted=false writes a raw 32-byte seed
 * (plaintext posture); encrypted=true writes a blob carrying the WKS1
 * envelope magic (encrypted posture). */
static bool sh_plant_wallet_seed(const char *dir, bool encrypted)
{
    char sql[512];
    if (encrypted)
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO wallet_seed(id, seed, next_child)"
                 " VALUES(1, x'574B5331AABBCCDDEEFF00112233445566778899"
                 "AABBCCDDEEFF00112233445566778899AABBCCDDEEFF001122334455"
                 "66778899AABBCCDDEEFF0011', 0)");
    else
        snprintf(sql, sizeof(sql),
                 "INSERT OR REPLACE INTO wallet_seed(id, seed, next_child)"
                 " VALUES(1, x'000102030405060708090A0B0C0D0E0F10111213"
                 "1415161718191A1B1C1D1E1F', 0)");
    return sh_exec_sql(dir, sql);
}

static bool sh_write_text(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    size_t len = strlen(text);
    bool ok = fwrite(text, 1, len, f) == len;
    fclose(f);
    return ok;
}

static bool sh_read_text(const char *path, char *out, size_t out_size)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    size_t n = fread(out, 1, out_size - 1, f);
    fclose(f);
    out[n] = '\0';
    return true;
}

/* ── 1. status on a fresh datadir names every gap ───────────────────── */
static int shop_status_fresh_datadir(void)
{
    int failures = 0;
    char dir[512];
    if (!sh_mk_datadir(dir, sizeof(dir), "status_fresh")) {
        SH_CHECK("fixture datadir", false);
        return failures + 1;
    }

    struct json_value input;
    sh_input_open(&input, dir);
    struct zcl_command_reply reply;
    sh_call(zcl_native_handle_shop_status, &input, &reply);

    SH_CHECK("status passes on a fresh datadir",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    SH_CHECK("shop_live is false, not silent",
             !json_get_bool(json_get(&reply.data, "shop_live")));
    SH_CHECK("tor build posture is named",
             strcmp(sh_str(json_get(&reply.data, "tor"), "build"),
                    shop_tor_real_build_linked() ? "real_tor"
                                                 : "tor_stub") == 0);
    SH_CHECK("a stub build names its gap",
             shop_tor_real_build_linked() ||
             sh_gap_present(&reply, "tor_stub_build"));
    SH_CHECK("wallet posture is absent on a fresh wallet",
             strcmp(sh_str(json_get(&reply.data, "wallet"), "posture"),
                    "absent") == 0);
    SH_CHECK("store schema exists with zero products",
             json_get_bool(json_get(json_get(&reply.data, "store"),
                                    "schema_present")) &&
             json_get_int(json_get(json_get(&reply.data, "store"),
                                   "products")) == 0);
    SH_CHECK("identity gap is named with a remedy",
             sh_gap_present(&reply, "no_persistent_onion_identity"));
    SH_CHECK("wallet gap is named with a remedy",
             sh_gap_present(&reply, "wallet_absent"));
    SH_CHECK("announcement gap is named with a remedy",
             sh_gap_present(&reply, "shop_not_announced"));
    SH_CHECK("no phantom wallet-refusal: encrypted wallet has no gap",
             !sh_gap_present(&reply, "wallet_plaintext_at_rest"));

    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 2. init refuses a plaintext wallet, mutating nothing ───────────── */
static int shop_init_refuses_plaintext_wallet(void)
{
    int failures = 0;
    char dir[512];
    if (!sh_mk_datadir(dir, sizeof(dir), "plaintext")) {
        SH_CHECK("fixture datadir", false);
        return failures + 1;
    }
    SH_CHECK("plaintext seed planted", sh_plant_wallet_seed(dir, false));

    struct json_value input;
    sh_input_open(&input, dir);
    (void)json_push_kv_bool(&input, "confirm", true);
    struct zcl_command_reply reply;
    sh_call(zcl_native_handle_shop_init, &input, &reply);

    SH_CHECK("commit is BLOCKED on a plaintext wallet",
             reply.status == ZCL_COMMAND_STATUS_BLOCKED);
    SH_CHECK("the refusal is named WALLET_NOT_ENCRYPTED",
             strcmp(reply.error.code, "WALLET_NOT_ENCRYPTED") == 0);
    SH_CHECK("the refusal carries the credential recipe",
             strstr(reply.error.message, "walletencrypt") != NULL);
    SH_CHECK("the refusal is not marked mutated", !reply.error.mutated);

    char probe[640];
    snprintf(probe, sizeof(probe), "%s/tor_data/onion_service/identity_seed",
             dir);
    SH_CHECK("no onion identity was minted before the refusal",
             !sh_file_exists(probe));
    snprintf(probe, sizeof(probe), "%s/directory/apps.csv", dir);
    SH_CHECK("no directory announcement was written before the refusal",
             !sh_file_exists(probe));

    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 3. the Tor build gate: stub named, real proceeds ───────────────── */
static int shop_init_commit_tor_gate(void)
{
    int failures = 0;
    char dir[512];
    if (!sh_mk_datadir(dir, sizeof(dir), "torgate")) {
        SH_CHECK("fixture datadir", false);
        return failures + 1;
    }
    SH_CHECK("encrypted seed planted", sh_plant_wallet_seed(dir, true));

    struct json_value input;
    sh_input_open(&input, dir);
    (void)json_push_kv_bool(&input, "confirm", true);
    struct zcl_command_reply reply;
    sh_call(zcl_native_handle_shop_init, &input, &reply);

    if (!shop_tor_real_build_linked()) {
        SH_CHECK("a stub build refuses by name, not by crash",
                 reply.status == ZCL_COMMAND_STATUS_BLOCKED &&
                 strcmp(reply.error.code, "TOR_STUB_BUILD") == 0);
        SH_CHECK("the refusal names the make tor-full remedy",
                 strstr(reply.error.message, "make tor-full") != NULL);
    } else {
        SH_CHECK("a real build passes the gate",
                 reply.status == ZCL_COMMAND_STATUS_PASSED);
    }

    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 3b. full commit on a real-Tor build (skipped on the stub) ──────── */
static int shop_init_commit_success_real_build(void)
{
    int failures = 0;
    if (!shop_tor_real_build_linked()) {
        printf("shop: full commit success path... SKIP (stub Tor build)\n");
        return 0;
    }

    char dir[512];
    if (!sh_mk_datadir(dir, sizeof(dir), "commit_ok")) {
        SH_CHECK("fixture datadir", false);
        return failures + 1;
    }
    SH_CHECK("encrypted seed planted", sh_plant_wallet_seed(dir, true));

    struct json_value input;
    sh_input_open(&input, dir);
    (void)json_push_kv_bool(&input, "confirm", true);
    struct zcl_command_reply reply;
    sh_call(zcl_native_handle_shop_init, &input, &reply);

    SH_CHECK("commit passes", reply.status == ZCL_COMMAND_STATUS_PASSED);
    SH_CHECK("commit is marked mutated", reply.error.mutated);
    SH_CHECK("the identity was minted",
             json_get_bool(json_get(&reply.data, "identity_created")));
    const char *addr = sh_str(json_get(&reply.data, "tor"), "address");
    SH_CHECK("a 56-char onion address is printed", strlen(addr) == 56);
    const char *url = sh_str(&reply.data, "shop_url");
    SH_CHECK("the shop URL is <address>.onion/store",
             strstr(url, ".onion/store") != NULL &&
             strncmp(url, "http://", 7) == 0);
    SH_CHECK("the verification block reports the shop live",
             json_get_bool(json_get(&reply.data, "shop_live")));
    SH_CHECK("the announcement is reported",
             json_get_bool(json_get(json_get(&reply.data, "discovery"),
                                    "announced")));
    SH_CHECK("the buyer's next command is printed",
             strstr(sh_str(&reply.data, "buyer_next_command"),
                    "app store catalog") != NULL);

    char addr1[64];
    snprintf(addr1, sizeof(addr1), "%s", addr);
    zcl_command_reply_free(&reply);

    /* Re-run: idempotent — the identity is reused, not reminted. */
    sh_call(zcl_native_handle_shop_init, &input, &reply);
    SH_CHECK("re-init passes", reply.status == ZCL_COMMAND_STATUS_PASSED);
    SH_CHECK("re-init reuses the identity",
             !json_get_bool(json_get(&reply.data, "identity_created")) &&
             strcmp(sh_str(json_get(&reply.data, "tor"), "address"),
                    addr1) == 0);
    zcl_command_reply_free(&reply);

    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 4. the plan path mutates nothing ───────────────────────────────── */
static int shop_init_plan_nonmutating(void)
{
    int failures = 0;
    char dir[512];
    if (!sh_mk_datadir(dir, sizeof(dir), "plan")) {
        SH_CHECK("fixture datadir", false);
        return failures + 1;
    }

    struct json_value input;
    sh_input_open(&input, dir);     /* no confirm key at all */
    struct zcl_command_reply reply;
    sh_call(zcl_native_handle_shop_init, &input, &reply);

    SH_CHECK("the plan passes without confirm",
             reply.status == ZCL_COMMAND_STATUS_PASSED);
    SH_CHECK("mode is plan", strcmp(sh_str(&reply.data, "mode"), "plan") == 0);
    const struct json_value *plan = json_get(&reply.data, "plan");
    SH_CHECK("the plan enumerates its steps",
             plan && plan->type == JSON_ARR && plan->num_children >= 5);
    SH_CHECK("the commit input is handed back",
             strstr(sh_str(&reply.data, "commit_input"), "confirm") != NULL);
    SH_CHECK("the plan names its gaps too",
             sh_gap_present(&reply, "no_persistent_onion_identity"));

    char probe[640];
    snprintf(probe, sizeof(probe), "%s/tor_data/onion_service/identity_seed",
             dir);
    SH_CHECK("the plan minted no identity", !sh_file_exists(probe));
    snprintf(probe, sizeof(probe), "%s/directory/apps.csv", dir);
    SH_CHECK("the plan wrote no announcement", !sh_file_exists(probe));

    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 4b. the bare plan fits the CLI's real reply budget ───────────────
 * Regression: the plan reply used to carry a next[] entry pointing back
 * at app.shop.init ITSELF, and the envelope's push_next_array rejects a
 * self-referential next by dropping the WHOLE reply — a first-time
 * operator typing bare `app shop init` got an empty
 * RESPONSE_BUDGET_EXCEEDED at the feature's front door instead of the
 * plan. The commit instruction now rides in data (commit_input /
 * commit_command) per the every-where-else convention. Drive the real
 * registry with the CLI's own out-buffer size
 * (ZCL_COMMAND_LIST_BUDGET + 1, tools/command/native_command.c), not a
 * generous test buffer. */
static int shop_init_plan_fits_reply_budget(void)
{
    int failures = 0;
    char dir[512];
    if (!sh_mk_datadir(dir, sizeof(dir), "planbudget")) {
        SH_CHECK("fixture datadir", false);
        return failures + 1;
    }

    const struct zcl_command_registry *reg = zcl_command_catalog();
    const struct zcl_command_spec *spec = NULL;
    for (size_t i = 0; reg && i < reg->count; i++)
        if (strcmp(reg->commands[i].path, "app.shop.init") == 0)
            spec = &reg->commands[i];
    SH_CHECK("the app.shop.init leaf is in the catalog", spec != NULL);
    if (!spec) {
        test_rm_rf(dir);
        return failures;
    }

    struct zcl_command_context ctx = {
        .registry = reg,
        .granted_capabilities = ~(uint64_t)0,
        .authority_ceiling = ZCL_COMMAND_AUTH_OWNER,
    };
    struct json_value input;
    sh_input_open(&input, dir);     /* bare: no confirm — the plan path */
    char out[ZCL_COMMAND_LIST_BUDGET + 1];
    enum zcl_command_exit code = ZCL_COMMAND_EXIT_INTERNAL;
    size_t n = zcl_command_registry_execute_json(reg, spec, &ctx, &input,
                                                 false, spec->path, "normal",
                                                 0, 0, NULL, out, sizeof(out),
                                                 &code);
    json_free(&input);
    SH_CHECK("the bare plan serializes inside the CLI's reply budget",
             n > 0 && n <= ZCL_COMMAND_LIST_BUDGET &&
             strstr(out, "RESPONSE_BUDGET_EXCEEDED") == NULL);

    struct json_value doc;
    json_init(&doc);
    if (n > 0 && json_read(&doc, out, n) && doc.type == JSON_OBJ) {
        const struct json_value *data = json_get(&doc, "data");
        SH_CHECK("the serialized reply is the plan",
                 data && strcmp(sh_str(data, "mode"), "plan") == 0);
    } else {
        SH_CHECK("the serialized reply parses", false);
    }
    json_free(&doc);

    test_rm_rf(dir);
    return failures;
}

/* ── 5. products.json: provision copies, the loader loads, status shows */
static int shop_products_json_load_path(void)
{
    int failures = 0;
    char dir[512];
    if (!sh_mk_datadir(dir, sizeof(dir), "products")) {
        SH_CHECK("fixture datadir", false);
        return failures + 1;
    }

    char input_path[600];
    snprintf(input_path, sizeof(input_path), "%s/operator-input.json", dir);
    SH_CHECK("operator products.json written",
             sh_write_text(input_path,
                 "[{\"name\":\"Field Guide\",\"description\":\"d\","
                 "\"price_zcl\":0.01,\"token_id\":\"GUIDE\","
                 "\"tokens_per_purchase\":1}]"));

    char err[160] = "";
    SH_CHECK("provision copies the input into <datadir>/store",
             shop_provision_products_json(dir, input_path, err, sizeof(err)));
    char dst[640];
    snprintf(dst, sizeof(dst), "%s/store/products.json", dir);
    SH_CHECK("the copy landed at the loader's path", sh_file_exists(dst));

    /* The same call init's commit makes. */
    char db_path[600];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);
    struct node_db ndb;
    if (!node_db_open_runtime(&ndb, db_path, "test.shop.products")) {
        SH_CHECK("node.db opens for the loader", false);
        test_rm_rf(dir);
        return failures + 1;
    }
    store_ensure_schema(ndb.db, dir);
    int count = db_store_product_count(&ndb);
    node_db_close(&ndb);
    SH_CHECK("the existing loader provisions exactly the one product",
             count == 1);

    /* An unreadable input is a named refusal, never a silent skip. */
    err[0] = '\0';
    SH_CHECK("a missing --input file is refused by name",
             !shop_provision_products_json(dir, "/nonexistent/nope.json",
                                           err, sizeof(err)) && err[0]);

    struct json_value input;
    sh_input_open(&input, dir);
    struct zcl_command_reply reply;
    sh_call(zcl_native_handle_shop_status, &input, &reply);
    SH_CHECK("status reports the loaded product count",
             json_get_int(json_get(json_get(&reply.data, "store"),
                                   "products")) == 1);
    SH_CHECK("status reports products.json present",
             json_get_bool(json_get(json_get(&reply.data, "store"),
                                    "products_json_present")));
    SH_CHECK("no store-schema gap remains",
             !sh_gap_present(&reply, "store_schema_missing"));
    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 6. the directory announcement round-trips through lib/net ──────── */
static int shop_directory_announcement(void)
{
    int failures = 0;
    char dir[512];
    if (!sh_mk_datadir(dir, sizeof(dir), "announce")) {
        SH_CHECK("fixture datadir", false);
        return failures + 1;
    }

    char csv[ONION_DIR_APPS_CSV_MAX + 1] = "x";
    SH_CHECK("an unannounced datadir reads as no extra apps",
             onion_directory_extra_apps_csv(dir, csv, sizeof(csv)) == 0 &&
             csv[0] == '\0');

    char err[160] = "";
    SH_CHECK("the announcement is written",
             shop_announce_directory_app(dir, err, sizeof(err)));
    SH_CHECK("lib/net reads \"shop\" back from the apps file",
             onion_directory_extra_apps_csv(dir, csv, sizeof(csv)) > 0 &&
             strcmp(csv, "shop") == 0);

    /* Idempotent: a second announce leaves exactly one token. */
    SH_CHECK("a second announce is a no-op success",
             shop_announce_directory_app(dir, err, sizeof(err)));
    char path[640];
    snprintf(path, sizeof(path), "%s/directory/apps.csv", dir);
    char content[128] = "";
    SH_CHECK("the file still holds exactly \"shop\"",
             sh_read_text(path, content, sizeof(content)) &&
             strcmp(content, "shop") == 0);

    struct json_value input;
    sh_input_open(&input, dir);
    struct zcl_command_reply reply;
    sh_call(zcl_native_handle_shop_status, &input, &reply);
    SH_CHECK("status reports the announced discovery state",
             json_get_bool(json_get(json_get(&reply.data, "discovery"),
                                    "announced")));
    SH_CHECK("no announcement gap remains",
             !sh_gap_present(&reply, "shop_not_announced"));
    zcl_command_reply_free(&reply);
    json_free(&input);
    test_rm_rf(dir);
    return failures;
}

/* ── 7. the wallet posture probe's states ───────────────────────────── */
static int shop_wallet_probe_states(void)
{
    int failures = 0;

    char empty_dir[512];
    sh_tmpdir(empty_dir, sizeof(empty_dir), "no_db");
    SH_CHECK("a datadir with no node.db is UNREADABLE",
             shop_probe_wallet_posture(empty_dir) == SHOP_WALLET_UNREADABLE);
    test_rm_rf(empty_dir);

    char dir[512];
    if (!sh_mk_datadir(dir, sizeof(dir), "posture")) {
        SH_CHECK("fixture datadir", false);
        return failures + 1;
    }
    SH_CHECK("a fresh wallet is ABSENT",
             shop_probe_wallet_posture(dir) == SHOP_WALLET_ABSENT);
    SH_CHECK("a raw seed row is PLAINTEXT",
             sh_plant_wallet_seed(dir, false) &&
             shop_probe_wallet_posture(dir) == SHOP_WALLET_PLAINTEXT);
    SH_CHECK("a WKS1 envelope row is ENCRYPTED",
             sh_plant_wallet_seed(dir, true) &&
             shop_probe_wallet_posture(dir) == SHOP_WALLET_ENCRYPTED);

    char dek_dir[512];
    if (sh_mk_datadir(dek_dir, sizeof(dek_dir), "posture_dek")) {
        SH_CHECK("a wrapped-DEK row alone is ENCRYPTED",
                 sh_exec_sql(dek_dir,
                     "INSERT INTO wallet_key_encryption(id, wrapped_dek)"
                     " VALUES(1, x'574B4431AABBCCDD')") &&
                 shop_probe_wallet_posture(dek_dir) == SHOP_WALLET_ENCRYPTED);
        test_rm_rf(dek_dir);
    } else {
        SH_CHECK("fixture datadir (dek)", false);
    }

    test_rm_rf(dir);
    return failures;
}

int test_shop(void)
{
    int failures = 0;
    failures += shop_status_fresh_datadir();
    failures += shop_init_refuses_plaintext_wallet();
    failures += shop_init_commit_tor_gate();
    failures += shop_init_commit_success_real_build();
    failures += shop_init_plan_nonmutating();
    failures += shop_init_plan_fits_reply_budget();
    failures += shop_products_json_load_path();
    failures += shop_directory_announcement();
    failures += shop_wallet_probe_states();
    return failures;
}
