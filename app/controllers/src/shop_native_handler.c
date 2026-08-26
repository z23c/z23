/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Registry handlers for `app shop init` / `app shop status` — slice B of
 * docs/work/SHOP_COMMAND.md: one command that takes a node from "has a
 * store table" to "live private shop", and one read leaf that reports the
 * same verification block on demand with every unmet prerequisite named.
 *
 * Nothing here re-implements a primitive — the handlers compose:
 *
 *   - the persistent onion identity of slice A (onion_identity_ensure in
 *     lib/net/src/tor_integration.c); the stub-vs-real build fact is read
 *     off the same weak dynhost symbol network_telemetry_fill.c reads
 *   - wallet custody from the on-disk envelopes the wallet persistence
 *     layer already writes (WKS1/WKD1 magics, the wrapped-DEK row) — a
 *     plaintext wallet is a named refusal with the credential recipe,
 *     never a silently-minted plaintext shop wallet
 *   - the store schema + products.json provisioning loader
 *     (store_ensure_schema, store_controller_schema.c) against the SAME
 *     <datadir>/node.db the /store HTTP surface serves from, so a product
 *     loaded here is live on the next request with no restart
 *   - the directory announcement as one id in
 *     <datadir>/directory/apps.csv (ONION_DIR_EXTRA_APPS_REL), which
 *     lib/net's register_self() folds into the node's own /directory.json
 *     apps row on its next round — running node or not
 *
 * The datadir-local file/DB helpers those steps run on (the wallet probe,
 * the products.json copy, the announcement write, the read-only identity
 * read) live in shop_native_probes.c — small enough to keep this TU under
 * the app/ file-size ceiling, and reusable unchanged by a future isolated
 * storefront worker process.
 *
 * `init` is plan/commit: a first call with no confirm:true returns the
 * non-mutating plan (every check, every gap, the commit input); only the
 * confirmed call mints, writes, or announces. `status` never mutates.
 *
 * Bound in config/commands/store.def. The closed HOT_FORK story executes the
 * copied-snapshot posture core without granting it storefront authority. */

#include "controllers/shop_native_handler.h"

#include "controllers/native_handler_body.h" /* json_get_bool_or/json_get_str_or */
#include "controllers/store_controller_internal.h" /* store_ensure_schema */
#include "command/native_command.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/activerecord.h"        /* AR_STEP_ROW */
#include "models/database.h"
#include "models/store.h"
#include "net/onion_service.h"
#include "net/tor_integration.h"
#include "services/shop_status_view_service.h"
#include "util/log_macros.h"

#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define SHOP_TAG "native.app.shop"

/* The named custody recipe, one string so the refusal, the plan gap, and
 * the status gap never drift apart. */
#define SHOP_WALLET_RECIPE SHOP_STATUS_WALLET_RECIPE
#define SHOP_REMEDY_INIT SHOP_STATUS_REMEDY_INIT
#define SHOP_REMEDY_TOR SHOP_STATUS_REMEDY_TOR
#define SHOP_REMEDY_PERSIST SHOP_STATUS_REMEDY_PERSIST

/* ── failures ───────────────────────────────────────────────────────── */
static void sh_fail(struct zcl_command_reply *reply,
                    enum zcl_command_status status,
                    enum zcl_command_exit exit_code, const char *code,
                    const char *phase, const char *message,
                    const char *evidence)
{
    LOG_ERROR(SHOP_TAG, "%s: %s (%s)", code, message,
              evidence && evidence[0] ? evidence : "-");
    zcl_command_reply_fail(reply, status, exit_code, code, phase, false,
                           false, message, evidence ? evidence : "");
}

/* Explicit input.datadir wins, else the CLI's --datadir. NULL when neither
 * is set (the same rule the store merchant leaves use). */
static const char *sh_datadir(const struct zcl_command_request *request)
{
    const char *dd = json_get_str(json_get(request->input, "datadir"));
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* ── the posture snapshot both leaves render ────────────────────────── */
struct shop_snapshot {
    bool tor_real;
    bool identity_present;
    char address[64];            /* 56 chars + NUL, "" when absent */
    enum shop_wallet_posture wallet;
    bool node_db_present;
    bool node_db_unreadable;     /* present, and not a readable database */
    bool store_schema;           /* the products table exists */
    int schema_version;          /* -1 when unknown */
    int product_count;           /* -1 when unknown */
    bool products_json_present;
    bool announced;
};

/* The read-only node.db facts: schema version, whether the store schema
 * exists, and the product count when it does. A present-but-unreadable
 * node.db is flagged, never read past: both leaves then refuse by name
 * (sh_refuse_unreadable_db) instead of rendering "unknown" fields over a
 * store they could not read — absent and unreadable are not the same
 * answer. */
static void sh_read_store_state(const char *datadir,
                                struct shop_snapshot *snap)
{
    char path[1024];
    struct stat st;
    snap->node_db_present =
        shop_internal_path_join(path, sizeof(path), datadir, "node.db") &&
        stat(path, &st) == 0 && S_ISREG(st.st_mode);
    if (!snap->node_db_present)
        return;

    sqlite3 *db = NULL;
    struct node_db ndb;
    if (zcl_native_node_db_open_readonly(datadir, &db, &ndb, NULL, 0)
            != ZCL_NODE_DB_RO_OK) {
        snap->node_db_unreadable = true;
        return;
    }

    snap->schema_version = node_db_schema_version(&ndb);

    static const char *const sql =
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='products'";
    sqlite3_stmt *s = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &s, NULL) == SQLITE_OK && s) { // raw-controller-sql-ok
        if (AR_STEP_ROW(s))
            snap->store_schema = true;
        sqlite3_finalize(s);
    } else if (s) {
        sqlite3_finalize(s);
    }
    if (snap->store_schema)
        snap->product_count = db_store_product_count(&ndb);
    zcl_native_node_db_close_readonly(&db, &ndb);
}

static void shop_snapshot_collect(const char *datadir,
                                  struct shop_snapshot *snap)
{
    memset(snap, 0, sizeof(*snap));
    snap->schema_version = -1;
    snap->product_count = -1;
    snap->tor_real = shop_tor_real_build_linked();
    snap->identity_present =
        shop_internal_read_identity(datadir, snap->address);
    snap->wallet = shop_probe_wallet_posture(datadir);
    sh_read_store_state(datadir, snap);
    char pj[1024];
    struct stat st;
    snap->products_json_present =
        shop_internal_path_join(pj, sizeof(pj), datadir,
                                "store/products.json") &&
        stat(pj, &st) == 0 && S_ISREG(st.st_mode);
    char csv[ONION_DIR_APPS_CSV_MAX + 1];
    if (onion_directory_extra_apps_csv(datadir, csv, sizeof(csv)) > 0) {
        /* token-exact membership, not substring ("shopify" is not "shop") */
        const char *p = csv;
        while (*p && !snap->announced) {
            const char *comma = strchr(p, ',');
            size_t tl = comma ? (size_t)(comma - p) : strlen(p);
            if (tl == strlen(SHOP_DIRECTORY_APP_ID) &&
                memcmp(p, SHOP_DIRECTORY_APP_ID, tl) == 0)
                snap->announced = true;
            p += tl + (comma ? 1 : 0);
        }
    }
}

static enum shop_status_wallet_v1
shop_status_wallet(enum shop_wallet_posture wallet)
{
    switch (wallet) {
    case SHOP_WALLET_PLAINTEXT: return SHOP_STATUS_WALLET_PLAINTEXT;
    case SHOP_WALLET_ENCRYPTED: return SHOP_STATUS_WALLET_ENCRYPTED;
    case SHOP_WALLET_UNREADABLE: return SHOP_STATUS_WALLET_UNREADABLE;
    case SHOP_WALLET_ABSENT: return SHOP_STATUS_WALLET_ABSENT;
    }
    return SHOP_STATUS_WALLET_UNREADABLE;
}

static bool shop_status_render(const struct shop_snapshot *snap,
                               struct shop_status_view_result_v1 *out)
{
    struct shop_status_view_input_v1 input = {
        .tor_real = snap->tor_real,
        .identity_present = snap->identity_present,
        .wallet = shop_status_wallet(snap->wallet),
        .node_db_present = snap->node_db_present,
        .store_schema = snap->store_schema,
        .schema_version = snap->schema_version,
        .product_count = snap->product_count,
        .products_json_present = snap->products_json_present,
        .announced = snap->announced,
    };
    (void)snprintf(input.address, sizeof(input.address), "%s", snap->address);
    struct zcl_hotswap_service_lease lease = {0};
    const struct shop_status_view_service_v1 *service =
        zcl_hotswap_service_acquire(SHOP_STATUS_VIEW_SERVICE_ID, &lease);
    if (!service)
        service = shop_status_view_service_builtin();
    bool ok = service->render(&input, out);
    zcl_hotswap_service_release(&lease);
    return ok;
}

static bool shop_status_frozen_kat(const void *opaque, char *why,
                                   size_t why_sz)
{
    const struct shop_status_view_service_v1 *service = opaque;
    struct shop_status_view_input_v1 input = {
        .wallet = SHOP_STATUS_WALLET_ABSENT,
        .schema_version = -1,
        .product_count = -1,
    };
    struct shop_status_view_result_v1 out;
    if (!service || !service->render || !service->render(&input, &out) ||
        out.shop_live || out.gap_count != 5 ||
        strcmp(out.gaps[0].gap, "tor_stub_build") != 0 ||
        strcmp(out.gaps[4].gap, "shop_not_announced") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen storefront posture vector failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_shop_status_contract = {
    .service_id = SHOP_STATUS_VIEW_SERVICE_ID,
    .source_tu = "app/services/src/shop_status_view_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct shop_status_view_service_v1),
    .abi_fingerprint = SHOP_STATUS_VIEW_ABI_FINGERPRINT,
    .schema_fingerprint = SHOP_STATUS_VIEW_SCHEMA_FINGERPRINT,
    .wire_fingerprint = SHOP_STATUS_VIEW_WIRE_FINGERPRINT,
    .kat_fingerprint = SHOP_STATUS_VIEW_KAT_FINGERPRINT,
    .frozen_kat = shop_status_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_shop_status_view_service_contract(void)
{
    return &k_shop_status_contract;
}

/* A present-but-unreadable node.db is a named refusal in both leaves,
 * never an ok answer over a store that could not be read (the wallet
 * probe's UNREADABLE over garbage would otherwise render as the
 * "wallet_unreadable" gap with a remedy that sends the operator to boot a
 * node — the wrong instruction for a corrupt file). The read touches
 * nothing: no rename, no repair, no fresh install. */
static bool sh_refuse_unreadable_db(const struct shop_snapshot *snap,
                                    const char *datadir,
                                    struct zcl_command_reply *reply)
{
    if (!snap->node_db_unreadable)
        return false;
    sh_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
            "NODE_DB_UNREADABLE", "read",
            "<datadir>/node.db exists but is not a readable database — "
            "the shop leaves it untouched (never renamed, never repaired, "
            "never reinstalled); restore it from a known-good copy before "
            "asking about the shop",
            datadir);
    return true;
}

/* ── rendering ──────────────────────────────────────────────────────── */
static void shop_push_snapshot(struct json_value *into,
                               const struct shop_status_view_result_v1 *view)
{
    struct json_value tor;
    json_init(&tor);
    json_set_object(&tor);
    (void)json_push_kv_str(&tor, "build",
                           view->tor_build);
    (void)json_push_kv_bool(&tor, "identity_present", view->address[0] != 0);
    if (view->address[0])
        (void)json_push_kv_str(&tor, "address", view->address);
    (void)json_push_kv_str(&tor, "persistence_flag", "-onion-persist");
    (void)json_push_kv_str(&tor, "persistence_note",
        "the CLI cannot read the running node's boot flags; the identity "
        "is used only when the node is booted with -tor -onion-persist");
    (void)json_push_kv(into, "tor", &tor);
    json_free(&tor);

    struct json_value wallet;
    json_init(&wallet);
    json_set_object(&wallet);
    (void)json_push_kv_str(&wallet, "posture",
                           view->wallet_posture);
    (void)json_push_kv_bool(&wallet, "encrypted_at_rest",
                            view->wallet_encrypted);
    (void)json_push_kv(into, "wallet", &wallet);
    json_free(&wallet);

    struct json_value store;
    json_init(&store);
    json_set_object(&store);
    (void)json_push_kv_bool(&store, "node_db_present", view->node_db_present);
    (void)json_push_kv_bool(&store, "schema_present", view->store_schema);
    if (view->schema_version >= 0)
        (void)json_push_kv_int(&store, "schema_version",
                               view->schema_version);
    if (view->product_count >= 0)
        (void)json_push_kv_int(&store, "products", view->product_count);
    (void)json_push_kv_bool(&store, "products_json_present",
                            view->products_json_present);
    (void)json_push_kv(into, "store", &store);
    json_free(&store);

    struct json_value discovery;
    json_init(&discovery);
    json_set_object(&discovery);
    (void)json_push_kv_bool(&discovery, "announced", view->announced);
    (void)json_push_kv_str(&discovery, "app_id", SHOP_DIRECTORY_APP_ID);
    (void)json_push_kv_str(&discovery, "apps_file",
                           ONION_DIR_EXTRA_APPS_REL);
    (void)json_push_kv_str(&discovery, "note",
        "the node's register_self() folds this file into its own "
        "/directory.json apps row on its next round");
    (void)json_push_kv(into, "discovery", &discovery);
    json_free(&discovery);
}

static void shop_push_gap(struct json_value *gaps, const char *gap,
                          const char *remedy)
{
    struct json_value g;
    json_init(&g);
    json_set_object(&g);
    (void)json_push_kv_str(&g, "gap", gap);
    (void)json_push_kv_str(&g, "remedy", remedy);
    (void)json_push_back(gaps, &g);
    json_free(&g);
}

static void shop_push_gaps(struct json_value *into,
                           const struct shop_status_view_result_v1 *view)
{
    struct json_value gaps;
    json_init(&gaps);
    json_set_array(&gaps);
    for (size_t i = 0; i < view->gap_count; i++)
        shop_push_gap(&gaps, view->gaps[i].gap, view->gaps[i].remedy);
    (void)json_push_kv(into, "gaps", &gaps);
    json_free(&gaps);
}

/* The printed "your shop is live" verification block, shared by the
 * successful commit and (with shop_live false) by plan/status. */
static void shop_push_verification(struct json_value *into,
                                   const struct shop_status_view_result_v1 *view)
{
    (void)json_push_kv_bool(into, "shop_live", view->shop_live);
    if (view->shop_url[0])
        (void)json_push_kv_str(into, "shop_url", view->shop_url);
    (void)json_push_kv_str(into, "buyer_next_command",
                           "z23 app store catalog");
    (void)json_push_kv_str(into, "buyer_note",
        "a buyer finds the shop at its onion /store URL, or by fetching "
        "/directory.json from any seed and looking for \"shop\" in the "
        "apps array");
}

/* ── app shop status (READ) ─────────────────────────────────────────── */
void zcl_native_handle_shop_status(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = sh_datadir(request);
    if (!datadir) {
        sh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_DATADIR", "normalize",
                "no datadir given and no --datadir default", "datadir");
        return;
    }

    struct shop_snapshot snap;
    shop_snapshot_collect(datadir, &snap);
    if (sh_refuse_unreadable_db(&snap, datadir, reply))
        return;
    struct shop_status_view_result_v1 view;
    if (!shop_status_render(&snap, &view)) {
        sh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "SHOP_STATUS_VIEW_FAILED", "render",
                "the pure storefront view refused the caller-owned posture",
                datadir);
        return;
    }

    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_int(&reply->data, "view_service_generation",
                           zcl_hotswap_service_generation());
    shop_push_snapshot(&reply->data, &view);
    shop_push_verification(&reply->data, &view);
    shop_push_gaps(&reply->data, &view);
}

/* ── app shop init (plan/commit) ────────────────────────────────────── */
static void shop_init_plan(const char *datadir,
                           const struct shop_snapshot *snap,
                           struct zcl_command_reply *reply)
{
    struct shop_status_view_result_v1 view;
    if (!shop_status_render(snap, &view)) {
        sh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "SHOP_STATUS_VIEW_FAILED", "render",
                "the pure storefront view refused the caller-owned posture",
                datadir);
        return;
    }
    (void)json_push_kv_str(&reply->data, "mode", "plan");
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    shop_push_snapshot(&reply->data, &view);
    shop_push_verification(&reply->data, &view);
    shop_push_gaps(&reply->data, &view);

    struct json_value plan;
    json_init(&plan);
    json_set_array(&plan);
    static const char *const steps[] = {
        "verify the wallet is encrypted at rest (refuse by name otherwise)",
        "verify this binary links the real vendored Tor (refuse by name "
            "on the stub build)",
        "ensure the persistent onion identity at "
            "<datadir>/tor_data/onion_service (mint on first run, reuse "
            "after) and print the address",
        "copy --input products.json to <datadir>/store/products.json when "
            "given",
        "ensure the store schema in <datadir>/node.db and provision "
            "products.json through the existing loader",
        "add \"shop\" to <datadir>/" ONION_DIR_EXTRA_APPS_REL " so the "
            "node's /directory.json apps row announces the storefront",
        "print the verification block: shop URL, product count, wallet "
            "state, discovery state, and the buyer's next command",
    };
    for (size_t i = 0; i < sizeof(steps) / sizeof(steps[0]); i++) {
        struct json_value step;
        json_init(&step);
        json_set_str(&step, steps[i]);
        (void)json_push_back(&plan, &step);
        json_free(&step);
    }
    (void)json_push_kv(&reply->data, "plan", &plan);
    json_free(&plan);
    /* The commit instruction rides in DATA, not in next[]: a next entry
     * pointing back at this same leaf is rejected by the envelope's
     * push_next_array (self-reference), which drops the WHOLE reply to an
     * empty RESPONSE_BUDGET_EXCEEDED — the front-door failure this field
     * now carries the fix for. */
    (void)json_push_kv_str(&reply->data, "commit_input",
                           "{\"confirm\":true}");
    (void)json_push_kv_str(&reply->data, "commit_command",
                           SHOP_REMEDY_INIT);
}

void zcl_native_handle_shop_init(const struct zcl_command_request *request,
                                 struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = sh_datadir(request);
    if (!datadir) {
        sh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "MISSING_DATADIR", "normalize",
                "no datadir given and no --datadir default", "datadir");
        return;
    }

    struct shop_snapshot snap;
    shop_snapshot_collect(datadir, &snap);
    if (sh_refuse_unreadable_db(&snap, datadir, reply))
        return;

    if (!json_get_bool_or(request->input, "confirm", false)) {
        shop_init_plan(datadir, &snap, reply);
        return;
    }

    /* Commit. Custody gates BEFORE anything is minted or written: the
     * most dangerous misconfiguration (keys plaintext on disk) is named
     * first, even on a stub-Tor build where step 2 would otherwise mask
     * it. */
    if (snap.wallet != SHOP_WALLET_ENCRYPTED) {
        const char *code = snap.wallet == SHOP_WALLET_PLAINTEXT
            ? "WALLET_NOT_ENCRYPTED"
            : snap.wallet == SHOP_WALLET_ABSENT
                ? "WALLET_ABSENT" : "WALLET_UNAVAILABLE";
        sh_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_DENIED,
                code, "custody", SHOP_WALLET_RECIPE,
                shop_wallet_posture_name(snap.wallet));
        return;
    }
    if (!snap.tor_real) {
        sh_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "TOR_STUB_BUILD", "tor", SHOP_REMEDY_TOR, "tor_stub");
        return;
    }

    /* Persistent identity: mint on first init, reuse after. A short or
     * corrupt seed is a named refusal inside onion_identity_ensure, never
     * a silent remint. */
    uint8_t seed[32];
    char address[64];
    bool identity_created = false;
    if (!onion_identity_ensure(datadir, seed, address, sizeof(address),
                               &identity_created)) {
        sh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "IDENTITY_FAILED", "identity",
                "the persistent onion identity exists but is unreadable or "
                "corrupt — inspect <datadir>/tor_data/onion_service/"
                "identity_seed (it is never silently reminted)",
                datadir);
        return;
    }
    memset(seed, 0, sizeof(seed));

    /* --input products.json, copied before the schema step so the loader
     * provisions it. */
    const char *input = json_get_str_or(request->input, "input", NULL);
    if (input && input[0]) {
        char err[160] = "";
        if (!shop_provision_products_json(datadir, input, err, sizeof(err))) {
            sh_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                    ZCL_COMMAND_EXIT_INVALID, "INPUT_UNREADABLE", "provision",
                    "the --input products.json could not be provisioned",
                    err);
            return;
        }
    }

    /* Store schema + products, through the same loader the /store surface
     * uses, against the same node.db it serves from. The file must already
     * exist: node_db_open_runtime would happily mint one on a mistyped
     * datadir, so a missing file is named instead. */
    char db_path[1024];
    if (!shop_internal_path_join(db_path, sizeof(db_path), datadir,
                                 "node.db")) {
        sh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "DATADIR_PATH_TOO_LONG", "normalize",
                "datadir path is too long to address node.db", datadir);
        return;
    }
    struct stat st;
    if (stat(db_path, &st) != 0 || !S_ISREG(st.st_mode)) {
        sh_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "STORE_NOT_INITIALISED", "schema",
                "no node.db at this datadir — boot the node once to create "
                "the store schema, then re-run init", db_path);
        return;
    }
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open_runtime(&ndb, db_path, "shop.init")) {
        sh_fail(reply, ZCL_COMMAND_STATUS_BLOCKED, ZCL_COMMAND_EXIT_BLOCKED,
                "STORE_NOT_INITIALISED", "schema",
                "node.db exists but could not be opened for the store",
                db_path);
        return;
    }
    int products_before = db_store_product_count(&ndb);
    bool had_products_json = snap.products_json_present;
    store_ensure_schema(ndb.db, datadir);
    int products_after = db_store_product_count(&ndb);
    node_db_close(&ndb);
    int products_loaded = products_after - products_before;
    /* products.json present and a still-empty store means the loader
     * found nothing valid; a repopulated store with no products.json
     * means the demo seeds fell back. Both are named, neither is silent. */
    bool demo_seeded = products_before == 0 && products_after > 0 &&
                       !had_products_json && !(input && input[0]);

    char err[160] = "";
    if (!shop_announce_directory_app(datadir, err, sizeof(err))) {
        sh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "ANNOUNCE_FAILED", "discovery",
                "the shop could not be registered on the node's "
                "/directory.json apps row", err);
        return;
    }

    /* The verification block describes what the operator now HAS, so
     * re-collect rather than trusting the pre-mutation snapshot. */
    struct shop_snapshot after;
    shop_snapshot_collect(datadir, &after);
    struct shop_status_view_result_v1 view;
    if (!shop_status_render(&after, &view)) {
        sh_fail(reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "SHOP_STATUS_VIEW_FAILED", "render",
                "the pure storefront view refused the committed posture",
                datadir);
        return;
    }
    (void)json_push_kv_str(&reply->data, "mode", "commit");
    (void)json_push_kv_str(&reply->data, "datadir", datadir);
    (void)json_push_kv_bool(&reply->data, "identity_created",
                            identity_created);
    (void)json_push_kv_int(&reply->data, "products_loaded", products_loaded);
    (void)json_push_kv_bool(&reply->data, "demo_products_seeded",
                            demo_seeded);
    if (input && input[0] && products_before > 0)
        (void)json_push_kv_str(&reply->data, "products_note",
            "products.json was copied but the products table is not empty; "
            "the loader only provisions an empty store");
    if (!snap.identity_present)
        (void)json_push_kv_str(&reply->data, "persistence_note",
            SHOP_REMEDY_PERSIST);
    shop_push_snapshot(&reply->data, &view);
    shop_push_verification(&reply->data, &view);
    reply->error.mutated = true;
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * Read-only SHOP status projection.
 *
 * The mutating siblings in this file are absent from both tables. Their
 * bytes are compiled into the module, but the loader refuses to re-point
 * any leaf missing from this file's row in config/hotswap_swappable.def. */
#ifdef ZCL_HOTSWAP_GEN
#define ZCL_HOTSWAP_PROBE_LEAF "app.shop.status"
#include "hotswap/hotswap.h"
static const struct zcl_hotswap_leaf_replacement k_shop_leaves[] = {
    { "app.shop.status", zcl_native_handle_shop_status },
};
ZCL_HOTSWAP_EXPORT_LEAVES(k_shop_leaves,
                          sizeof(k_shop_leaves) / sizeof(k_shop_leaves[0]))
#endif /* ZCL_HOTSWAP_GEN */

#ifdef ZCL_HOTSWAP_MODULE_GEN
#include "hotswap/hotswap_module.h"
#include <stdio.h>
static const struct zcl_hotswap_leaf k_shop_module_leaves[] = {
    { "app.shop.status", zcl_native_handle_shop_status },
};
/* Structural health hook: a table that lost a name or a body would
 * otherwise publish a leaf that dispatches into nothing. */
static bool shop_module_selftest(char *error, size_t error_cap)
{
    const size_t n = sizeof(k_shop_module_leaves) /
                     sizeof(k_shop_module_leaves[0]);
    for (size_t i = 0; i < n; i++) {
        if (!k_shop_module_leaves[i].name ||
            !k_shop_module_leaves[i].name[0] ||
            !k_shop_module_leaves[i].fn) {
            if (error && error_cap)
                (void)snprintf(error, error_cap,
                               "shop leaf %zu has no name or no body",
                               i);
            return false;
        }
    }
    return true;
}
ZCL_HOTSWAP_MODULE_LEAVES(k_shop_module_leaves, shop_module_selftest)
#endif /* ZCL_HOTSWAP_MODULE_GEN */
