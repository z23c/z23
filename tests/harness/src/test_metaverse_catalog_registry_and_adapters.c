/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * metaverse_catalog scenario checks: the ZNAM and ZSLP adapters
 * (fixture setup, list, show, and ownership/removal transitions); the
 * read-only contract — `metaverse property list` must not mutate the
 * datadir, proven against the orphan-CAS-deleting recovery sweep in
 * vcs_package_store_open(); the CLI path through both leaves via
 * zcl_command_registry_input_validate plus the handler they bind; and
 * the unreadable-store disclosure (store.read = false with a reason,
 * nothing rendered as owned, show refuses rather than answering
 * absent).
 *
 * Split out of test_metaverse_catalog.c (which keeps the includes,
 * the fixture helpers shared across siblings — hex formatting and the
 * in-process command runner — and the group entry point) so no family
 * member crosses the 1,500-line ceiling. */


#include "test/test_core.h"

#include "command/native_command.h"

#include "chain/chainparams.h"
#include "config/command_catalog.h"
#include "core/arith_uint256.h"
#include "core/uint256.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "metaverse/property_action.h"
#include "metaverse/property_adapter.h"
#include "metaverse/property_id.h"
#include "metaverse/property_view.h"
#include "metaverse/property_work.h"
#include "models/database.h"
#include "models/zslp.h"
#include "models/znam.h"
#include "services/property_catalog.h"
#include "vcs/blob_store.h"
#include "vcs/package_accept.h"
#include "vcs/package_index.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_store.h"

/* Test-only seam for deterministic mutation between the hash and final
 * fingerprint pass. Production callers only see the ordinary property API. */
#include "../../metaverse/src/metaverse_priv.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test/test_metaverse_catalog_priv.h"

/* ── 6: the read-only contract (the parent-failing case) ──────────── */

/* Count every regular file under `dir`, recursively. A read command that
 * mutated the datadir would change this number (the store's recovery sweep
 * deletes orphans and staged temps). */
static size_t mv_count_files(const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *ent;
    size_t n = 0;

    if (!d)
        return 0;
    while ((ent = readdir(d)) != NULL) {
        char path[1024];
        struct stat st;

        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
        if (stat(path, &st) != 0)
            continue;
        if (S_ISDIR(st.st_mode))
            n += mv_count_files(path);
        else if (S_ISREG(st.st_mode))
            n++;
    }
    closedir(d);
    return n;
}

/* ZNAM through the canonical model and the strict read-only native open. */
struct znam_adapter_ctx {
    char dd[256];
    char db_path[512];
    char root_hex[65];
    char update_hex[65];
    char id_text[METAVERSE_ID_TEXT_MAX];
    struct znam_entry entry;
};

static int znam_case_fixture_setup(struct znam_adapter_ctx *zc)
{
    int failures = 0;
    struct node_db ndb;

    memset(&ndb, 0, sizeof(ndb));
    memset(&zc->entry, 0, sizeof(zc->entry));
    MV_CHECK("znam: canonical node database opens for fixture setup",
             node_db_open(&ndb, zc->db_path));
    snprintf(zc->entry.name, sizeof(zc->entry.name), "alice");
    snprintf(zc->entry.owner_address, sizeof(zc->entry.owner_address),
             "t1AlicePropertyOwner11111111111111111");
    zc->entry.target_type = ZNAM_TYPE_CONTENT;
    snprintf(zc->entry.target_value, sizeof(zc->entry.target_value),
             "sha3:alice");
    memset(zc->entry.reg_txid, 0x71, sizeof(zc->entry.reg_txid));
    memset(zc->entry.last_update_txid, 0x72,
           sizeof(zc->entry.last_update_txid));
    zc->entry.reg_height = 777;
    zc->entry.expiry_height = 1777;
    MV_CHECK("znam: fixture is saved through the canonical model",
             ndb.open && db_znam_save(&ndb, &zc->entry));
    node_db_close(&ndb);

    mv_hex32(zc->entry.reg_txid, zc->root_hex);
    mv_hex32(zc->entry.last_update_txid, zc->update_hex);
    snprintf(zc->id_text, sizeof(zc->id_text), "znam_name:%s", zc->root_hex);
    return failures;
}

static int znam_case_list(struct znam_adapter_ctx *zc)
{
    int failures = 0;
    struct mv_cmd c;

    mv_list(&c, zc->dd, "znam_name");
    {
        const struct json_value *item =
            mv_find_item(&c.reply.data, zc->id_text);
        const struct json_value *kind =
            mv_find_kind(&c.reply.data, "znam_name");

        MV_CHECK("znam: list reads the canonical registration by its stable "
                 "transaction root",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && item &&
                 kind && json_get_bool(json_get(kind, "available")) &&
                 json_get_int(json_get(kind, "total")) == 1);
        MV_CHECK("znam: list projects owner and indexed-chain evidence",
                 item && strcmp(mv_str(item, "display_name"), "alice") == 0 &&
                 strcmp(mv_str(item, "owner_principal"),
                                zc->entry.owner_address) == 0 &&
                 strcmp(mv_str(item, "owner_principal_kind"),
                        "zcl_address") == 0 &&
                 strcmp(mv_str(item, "evidence_grade"),
                        "chain_indexed_unvalidated") == 0 &&
                 !json_get_bool(json_get(item, "chain_bound")));
    }
    mv_cmd_free(&c);
    return failures;
}

static int znam_case_show(struct znam_adapter_ctx *zc)
{
    int failures = 0;
    struct mv_cmd c;

    mv_show(&c, zc->dd, zc->id_text);
    {
        const struct json_value *work = json_get(&c.reply.data, "work");

        MV_CHECK("znam: show reports the registration height without "
                 "inventing a live tip",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 strcmp(mv_str(&c.reply.data, "status"), "present") == 0 &&
                 json_get_bool(json_get(&c.reply.data,
                                        "has_freshness_height")) &&
                 json_get_int(json_get(&c.reply.data,
                                       "freshness_height")) == 777 &&
                 work && strcmp(mv_str(work, "gap"), "no_tip") == 0 &&
                 json_get_int(json_get(work, "confirmation_depth")) == -1);
        MV_CHECK("znam: latest transaction is a descriptor, not a "
                 "fabricated revision counter",
                 strcmp(mv_str(&c.reply.data, "descriptor_root"),
                        zc->update_hex) == 0 &&
                 !json_get_bool(json_get(&c.reply.data, "has_revision")) &&
                 strstr(mv_str(&c.reply.data, "actions_csv"),
                        "update_pointer") != NULL &&
                 strstr(mv_str(&c.reply.data, "actions_csv"),
                        "transfer") != NULL);
    }
    mv_cmd_free(&c);
    return failures;
}

static int znam_case_list_and_show(struct znam_adapter_ctx *zc)
{
    int failures = 0;
    failures += znam_case_list(zc);
    failures += znam_case_show(zc);
    return failures;
}

static int znam_case_ownership_transition(struct znam_adapter_ctx *zc)
{
    int failures = 0;
    struct node_db ndb;
    struct mv_cmd c;

    /* No catalog ownership cache: the immutable registration root stays
     * stable while the authoritative owner changes. */
    memset(&ndb, 0, sizeof(ndb));
    MV_CHECK("znam: fixture reopens for an ownership transition",
             node_db_open(&ndb, zc->db_path));
    snprintf(zc->entry.owner_address, sizeof(zc->entry.owner_address),
             "t1BobPropertyOwner222222222222222222");
    memset(zc->entry.last_update_txid, 0x73,
           sizeof(zc->entry.last_update_txid));
    MV_CHECK("znam: ownership transition saves through the model",
             ndb.open && db_znam_save(&ndb, &zc->entry));
    node_db_close(&ndb);
    mv_show(&c, zc->dd, zc->id_text);
    MV_CHECK("znam: same property id immediately projects the new owner",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "property_id"), zc->id_text) ==
                 0 &&
             strcmp(mv_str(&c.reply.data, "owner_principal"),
                    zc->entry.owner_address) == 0);
    mv_cmd_free(&c);
    return failures;
}

int t_znam_adapter(void)
{
    int failures = 0;
    struct znam_adapter_ctx zc;
    size_t files_before;
    size_t files_after;

    memset(&zc, 0, sizeof(zc));
    test_make_tmpdir(zc.dd, sizeof(zc.dd), "metaverse", "znam");
    snprintf(zc.db_path, sizeof(zc.db_path), "%s/node.db", zc.dd);

    failures += znam_case_fixture_setup(&zc);
    files_before = mv_count_files(zc.dd);
    failures += znam_case_list_and_show(&zc);
    files_after = mv_count_files(zc.dd);
    MV_CHECK("znam: list/show create no WAL or SHM sidecars and change no "
             "datadir files", files_after == files_before);
    failures += znam_case_ownership_transition(&zc);

    test_rm_rf_recursive(zc.dd);
    return failures;
}

/* ZSLP through the canonical chain-derived token model and the same strict
 * read-only node.db open. */
struct zslp_adapter_ctx {
    char dd[256];
    char db_path[512];
    char root_hex[65];
    char id_text[METAVERSE_ID_TEXT_MAX];
    uint8_t token_id[32];
};

static int zslp_case_fixture_setup(struct zslp_adapter_ctx *zc)
{
    int failures = 0;
    struct node_db ndb;
    struct db_zslp_token_info token_probe;
    size_t asset_count = 0;

    memset(zc->token_id, 0x81, sizeof(zc->token_id));
    memset(&ndb, 0, sizeof(ndb));
    MV_CHECK("zslp: canonical node database opens for fixture setup",
             node_db_open(&ndb, zc->db_path));
    MV_CHECK("zslp: chain-derived GENESIS saves through the canonical model",
             ndb.open && db_zslp_token_save(&ndb, zc->token_id, "META",
                 "Metaverse Asset", 8, "https://example.invalid/meta",
                 888, 21000000));
    MV_CHECK("zslp: application-local token key also saves for exclusion "
             "proof",
             ndb.open && db_zslp_token_save_key(&ndb, "ZCL23ACCESS",
                 "ACCESS", "Store Access", 0, "", 0, 1));
    memset(&token_probe, 0, sizeof(token_probe));
    MV_CHECK("zslp: model-owned count excludes application-local keys",
             ndb.open && db_zslp_asset_count(&ndb, &asset_count) &&
             asset_count == 1);
    MV_CHECK("zslp: model-owned lookup distinguishes the real GENESIS",
             ndb.open &&
             db_zslp_asset_lookup(&ndb, zc->token_id, &token_probe) == 1 &&
             strcmp(token_probe.ticker, "META") == 0);
    node_db_close(&ndb);

    mv_hex32(zc->token_id, zc->root_hex);
    snprintf(zc->id_text, sizeof(zc->id_text), "zslp_asset:%s",
             zc->root_hex);
    return failures;
}

static int zslp_case_list(struct zslp_adapter_ctx *zc)
{
    int failures = 0;
    struct mv_cmd c;

    mv_list(&c, zc->dd, "zslp_asset");
    {
        const struct json_value *item =
            mv_find_item(&c.reply.data, zc->id_text);
        const struct json_value *kind =
            mv_find_kind(&c.reply.data, "zslp_asset");

        if (!item || !kind ||
            c.reply.status != ZCL_COMMAND_STATUS_PASSED) {
            char doc[4096];
            (void)json_write(&c.reply.data, doc, sizeof(doc));
            printf("  metaverse_catalog: zslp list diagnostic: %s\n", doc);
        }

        MV_CHECK("zslp: list exposes exactly the real GENESIS and excludes "
                 "the application-local token key",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && item &&
                 kind && json_get_bool(json_get(kind, "available")) &&
                 json_get_int(json_get(kind, "total")) == 1);
        MV_CHECK("zslp: asset name and indexed-chain evidence come from the "
                 "canonical model",
                 item && strcmp(mv_str(item, "display_name"),
                                "META (Metaverse Asset)") == 0 &&
                 strcmp(mv_str(item, "evidence_grade"),
                        "chain_indexed_unvalidated") == 0 &&
                 strcmp(mv_str(item, "evidence_source"),
                        "db_zslp_asset_lookup") == 0);
    }
    mv_cmd_free(&c);
    return failures;
}

static int zslp_case_show(struct zslp_adapter_ctx *zc)
{
    int failures = 0;
    struct mv_cmd c;

    mv_show(&c, zc->dd, zc->id_text);
    {
        const struct json_value *work = json_get(&c.reply.data, "work");

        if (c.reply.status != ZCL_COMMAND_STATUS_PASSED) {
            char doc[4096];
            (void)json_write(&c.reply.data, doc, sizeof(doc));
            printf("  metaverse_catalog: zslp show diagnostic: %s\n", doc);
        }

        MV_CHECK("zslp: show reports GENESIS height without manufacturing a "
                 "tip or confirmation depth",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
                 strcmp(mv_str(&c.reply.data, "status"), "present") == 0 &&
                 json_get_bool(json_get(&c.reply.data,
                                        "has_freshness_height")) &&
                 json_get_int(json_get(&c.reply.data,
                                       "freshness_height")) == 888 &&
                 work && strcmp(mv_str(work, "gap"), "no_tip") == 0 &&
                 json_get_int(json_get(work, "confirmation_depth")) == -1);
        MV_CHECK("zslp: fungible definition fabricates neither a single "
                 "owner nor mutating authority",
                 strcmp(mv_str(&c.reply.data, "owner_principal"), "") == 0 &&
                 strcmp(mv_str(&c.reply.data, "owner_principal_kind"),
                        "none") == 0 &&
                 strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0 &&
                 strstr(mv_str(&c.reply.data, "provenance"),
                        "no mint-baton controller") != NULL);
    }
    mv_cmd_free(&c);
    return failures;
}

static int zslp_case_list_and_show(struct zslp_adapter_ctx *zc)
{
    int failures = 0;
    failures += zslp_case_list(zc);
    failures += zslp_case_show(zc);
    return failures;
}

static int zslp_case_removal(struct zslp_adapter_ctx *zc)
{
    int failures = 0;
    struct node_db ndb;
    struct mv_cmd c;
    size_t asset_count;

    /* No catalog cache: removal from the authority is visible immediately. */
    memset(&ndb, 0, sizeof(ndb));
    MV_CHECK("zslp: fixture reopens for authoritative projection removal",
             node_db_open(&ndb, zc->db_path));
    if (ndb.open)
        db_zslp_clear_all(&ndb);
    asset_count = SIZE_MAX;
    MV_CHECK("zslp: authoritative removal leaves zero chain assets",
             ndb.open && db_zslp_asset_count(&ndb, &asset_count) &&
             asset_count == 0);
    node_db_close(&ndb);
    mv_show(&c, zc->dd, zc->id_text);
    if (c.reply.status != ZCL_COMMAND_STATUS_PASSED ||
        strcmp(mv_str(&c.reply.data, "status"), "absent") != 0) {
        char doc[4096];
        (void)json_write(&c.reply.data, doc, sizeof(doc));
        printf("  metaverse_catalog: zslp absent diagnostic: status=%d "
               "error=%s data=%s\n", (int)c.reply.status,
               c.reply.error.code, doc);
    }
    MV_CHECK("zslp: the same property id immediately reads absent after the "
             "authoritative rows are removed",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "absent") == 0 &&
             json_get_bool(json_get(&c.reply.data, "determined")));
    mv_cmd_free(&c);
    return failures;
}

int t_zslp_adapter(void)
{
    int failures = 0;
    struct zslp_adapter_ctx zc;
    size_t files_before;
    size_t files_after;

    memset(&zc, 0, sizeof(zc));
    test_make_tmpdir(zc.dd, sizeof(zc.dd), "metaverse", "zslp");
    snprintf(zc.db_path, sizeof(zc.db_path), "%s/node.db", zc.dd);

    failures += zslp_case_fixture_setup(&zc);
    files_before = mv_count_files(zc.dd);
    failures += zslp_case_list_and_show(&zc);
    files_after = mv_count_files(zc.dd);
    MV_CHECK("zslp: list/show create no WAL or SHM sidecars and change no "
             "datadir files", files_after == files_before);
    failures += zslp_case_removal(&zc);

    test_rm_rf_recursive(zc.dd);
    return failures;
}

int t_readonly_contract(void)
{
    int failures = 0;
    char dd[256];
    char zcode_dir[512];
    char orphan_dir[768];
    char orphan_path[900];
    char root_hex[65];
    char id_text[METAVERSE_ID_TEXT_MAX];
    const char orphan_hex[65] =
        "beef00112233445566778899aabbccddeeff00112233445566778899aabbccdd";
    uint8_t orphan_hash[32];
    const uint8_t bytes[] = "read means read";
    uint8_t root[32];
    struct vcs_package_store *store;
    struct mv_cmd c;
    size_t before, after;
    FILE *f;

    test_make_tmpdir(dd, sizeof(dd), "metaverse", "readonly");
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);

    store = vcs_package_store_open(dd, 4u * 1024u * 1024u);
    MV_CHECK("readonly: fixture store opens", store != NULL);
    if (!store) {
        test_rm_rf_recursive(dd);
        return failures;
    }
    MV_CHECK("readonly: blob stores",
             vcs_blob_put_to(store, bytes, sizeof(bytes) - 1, root) ==
                 VCS_BLOB_OK);
    vcs_package_store_close(store);
    mv_hex32(root, root_hex);
    snprintf(id_text, sizeof(id_text), "content:%s", root_hex);

    /* Plant a CAS object no manifest references. The store's open-time
     * orphan GC exists precisely to delete this. */
    snprintf(orphan_dir, sizeof(orphan_dir), "%s/cas/sha3/%.2s", zcode_dir,
             orphan_hex);
    (void)mkdir(orphan_dir, 0755);
    snprintf(orphan_path, sizeof(orphan_path), "%s/%s", orphan_dir,
             orphan_hex);
    f = fopen(orphan_path, "wb");
    MV_CHECK("readonly: the orphan CAS object is planted",
             f != NULL && fwrite("orphan", 1, 6, f) == 6);
    if (f)
        fclose(f);

    for (int i = 0; i < 32; i++) {
        int hi = orphan_hex[2 * i], lo = orphan_hex[2 * i + 1];

        hi = hi <= '9' ? hi - '0' : 10 + (hi - 'a');
        lo = lo <= '9' ? lo - '0' : 10 + (lo - 'a');
        orphan_hash[i] = (uint8_t)((hi << 4) | lo);
    }
    /* The getter this change adds: a CAS presence answer that needs no
     * store handle, and therefore no recovery sweep. */
    MV_CHECK("readonly: the CAS probe finds a present object without opening "
             "a store",
             vcs_package_cas_present_in(zcode_dir, orphan_hash));
    {
        uint8_t absent[32];

        memset(absent, 0x5c, sizeof(absent));
        MV_CHECK("readonly: the CAS probe is NULL-safe and rejects a missing "
                 "object",
                 !vcs_package_cas_present_in(NULL, orphan_hash) &&
                 !vcs_package_cas_present_in(zcode_dir, NULL) &&
                 !vcs_package_cas_present_in(zcode_dir, absent));
    }

    before = mv_count_files(dd);
    MV_CHECK("readonly: the fixture datadir has files to protect",
             before > 0);

    mv_list(&c, dd, NULL);
    MV_CHECK("readonly: list succeeds against the fixture",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             mv_find_item(&c.reply.data, id_text) != NULL);
    mv_cmd_free(&c);
    mv_show(&c, dd, id_text);
    MV_CHECK("readonly: show succeeds against the fixture",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    mv_cmd_free(&c);

    after = mv_count_files(dd);
    MV_CHECK("readonly: the catalog read changed NOTHING on disk",
             after == before);
    MV_CHECK("readonly: the orphan CAS object survived the read",
             access(orphan_path, F_OK) == 0);

    /* The contrast that makes the point: the pre-existing way to ask a
     * store anything is to OPEN it, and opening runs the orphan GC. A read
     * command routed through that would have deleted the operator's file. */
    store = vcs_package_store_open(dd, 4u * 1024u * 1024u);
    MV_CHECK("readonly: the store reopens", store != NULL);
    vcs_package_store_close(store);
    MV_CHECK("readonly: opening the store DELETES the orphan — which is why "
             "the read path may not open one",
             access(orphan_path, F_OK) != 0);
    MV_CHECK("readonly: the CAS probe now agrees the object is gone",
             !vcs_package_cas_present_in(zcode_dir, orphan_hash));

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 7: the CLI path ──────────────────────────────────────────────── */

static int registry_case_leaves_registered(const struct zcl_command_spec *list,
                                            const struct zcl_command_spec *show)
{
    int failures = 0;
    MV_CHECK("cli: both leaves are registered", list && show);
    MV_CHECK("cli: both leaves bind a handler",
             list && show && list->handler && show->handler);
    MV_CHECK("cli: the leaves bind the handlers the direct tests call",
             list && show &&
             list->handler == zcl_native_handle_metaverse_property_list &&
             show->handler == zcl_native_handle_metaverse_property_show);
    MV_CHECK("cli: metaverse is a canonical root word",
             zcl_native_command_is_root("metaverse"));
    return failures;
}

static int registry_case_list_and_show_valid(const char *dd,
                                              const struct zcl_command_spec *list,
                                              const struct zcl_command_spec *show)
{
    int failures = 0;
    char why[192] = {0};
    struct mv_cmd c;

    /* list — the operator's exact input, through input_validate. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "kind", "content");
    (void)json_push_kv_int(&c.input, "limit", 4);
    MV_CHECK("cli: list accepts the keys it declares",
             list && zcl_command_registry_input_validate(list, &c.input, why,
                                                         sizeof(why)));
    if (list && list->handler) {
        c.request.spec = list;
        c.request.invoked_name = list->path;
        list->handler(&c.request, &c.reply);
    }
    MV_CHECK("cli: an empty store lists cleanly, not as a failure",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_int(json_get(&c.reply.data, "rendered")) == 0 &&
             json_get_int(json_get(&c.reply.data, "kinds_scanned")) ==
                 (int64_t)METAVERSE_KIND_COUNT - 1);
    mv_cmd_free(&c);

    /* show — declared keys accepted, malformed id refused by name. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "property_id", "content:nothex");
    why[0] = '\0';
    MV_CHECK("cli: show accepts the keys it declares",
             show && zcl_command_registry_input_validate(show, &c.input, why,
                                                         sizeof(why)));
    if (show && show->handler) {
        c.request.spec = show;
        c.request.invoked_name = show->path;
        show->handler(&c.request, &c.reply);
    }
    MV_CHECK("cli: a malformed property id is refused by name",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             strcmp(c.reply.error.code, "BAD_PROPERTY_ID") == 0);
    mv_cmd_free(&c);
    return failures;
}

static int registry_case_named_refusals(const char *dd,
                                         const struct zcl_command_spec *list)
{
    int failures = 0;
    char why[192] = {0};
    struct mv_cmd c;

    /* A kind with no reader is a NAMED refusal, never an empty answer. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(
        &c.input, "property_id",
        "hosted_service:a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbb"
        "cbdbebf");
    zcl_native_handle_metaverse_property_show(&c.request, &c.reply);
    MV_CHECK("cli: an unwired kind is refused with KIND_UNAVAILABLE",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             strcmp(c.reply.error.code, "KIND_UNAVAILABLE") == 0);
    mv_cmd_free(&c);

    /* An unknown kind name in list must be named, not silently ignored. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "kind", "world");
    zcl_native_handle_metaverse_property_list(&c.request, &c.reply);
    MV_CHECK("cli: an unknown kind filter is refused by name",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             strcmp(c.reply.error.code, "UNKNOWN_KIND") == 0);
    mv_cmd_free(&c);

    /* The validator is real, not bypassed. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "not_a_catalog_key", "x");
    why[0] = '\0';
    MV_CHECK("cli: an undeclared key is refused by input_validate",
             list && !zcl_command_registry_input_validate(list, &c.input, why,
                                                          sizeof(why)) &&
             why[0] != '\0');
    mv_cmd_free(&c);

    /* No datadir at all must be a named refusal, never a global fallback. */
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "property_id",
                           "content:a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
                           "b4b5b6b7b8b9babbbcbdbebf");
    zcl_native_handle_metaverse_property_show(&c.request, &c.reply);
    MV_CHECK("cli: no datadir is MISSING_DATADIR, not a silent global",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             strcmp(c.reply.error.code, "MISSING_DATADIR") == 0);
    mv_cmd_free(&c);
    return failures;
}

int t_registry_path(void)
{
    int failures = 0;
    char dd[256];
    const struct zcl_command_spec *list = mv_leaf("metaverse.property.list");
    const struct zcl_command_spec *show = mv_leaf("metaverse.property.show");

    test_make_tmpdir(dd, sizeof(dd), "metaverse", "registry");

    failures += registry_case_leaves_registered(list, show);
    failures += registry_case_list_and_show_valid(dd, list, show);
    failures += registry_case_named_refusals(dd, list);

    test_rm_rf_recursive(dd);
    return failures;
}

/* ── an unreadable store must not read as an empty one ───────────────────
 *
 * A catalog that answers "0 properties" over a store it could not open has
 * told the operator they own nothing. That is the same conflation this
 * project already paid for on node.db, and it is worse here: the whole
 * purpose of this surface is to state what you hold.
 *
 * The store is made PRESENT and unreadable by putting a plain file where
 * <datadir>/zcode/manifests belongs, so opendir() fails with ENOTDIR. What
 * is asserted is disclosure, not a particular verb: list may answer as
 * long as it says "store": {"read": false} and names the affected kinds
 * unavailable; show must refuse outright, because a bare "absent" from it
 * IS the lie. */
static int unreadable_case_plant_blocker(const char *dd, char *mpath,
                                          size_t mpath_cap)
{
    int failures = 0;
    char zdir[512];
    FILE *f;

    snprintf(zdir, sizeof(zdir), "%s/zcode", dd);
    (void)mkdir(zdir, 0700);
    snprintf(mpath, mpath_cap, "%s/manifests", zdir);
    f = fopen(mpath, "wb");
    MV_CHECK("unreadable: a plain file sits where the store belongs",
             f != NULL);
    if (f) {
        fputs("not a directory", f);
        fclose(f);
    }
    return failures;
}

static int unreadable_case_list_discloses(const char *dd)
{
    int failures = 0;
    struct mv_cmd c;
    const struct json_value *store;
    const struct json_value *kinds;
    bool content_named = false;

    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    zcl_native_handle_metaverse_property_list(&c.request, &c.reply);
    store = json_get(&c.reply.data, "store");
    MV_CHECK("unreadable: list discloses store.read = false",
             store && json_get(store, "read") &&
             !json_get_bool(json_get(store, "read")));
    {
        const struct json_value *why = store ? json_get(store, "reason")
                                             : NULL;
        const char *s = why ? json_get_str(why) : NULL;

        MV_CHECK("unreadable: the disclosure carries a reason", s && *s);
    }
    kinds = json_get(&c.reply.data, "kinds");
    if (kinds && kinds->type == JSON_ARR) {
        for (size_t i = 0; i < kinds->num_children; i++) {
            const struct json_value *row = &kinds->children[i];
            const char *name = json_get_str(json_get(row, "kind"));
            const char *reason =
                json_get_str(json_get(row, "unavailable_reason"));

            if (!name || strcmp(name, "content") != 0)
                continue;
            content_named = !json_get_bool(json_get(row, "available")) &&
                            reason && *reason;
        }
    }
    MV_CHECK("unreadable: the content row is unavailable with a reason",
             content_named);
    MV_CHECK("unreadable: nothing is rendered as owned",
             json_get_int(json_get(&c.reply.data, "rendered")) == 0);
    mv_cmd_free(&c);
    return failures;
}

static int unreadable_case_show_refuses(const char *dd)
{
    int failures = 0;
    struct mv_cmd c;

    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "property_id",
                           "content:a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3"
                           "b4b5b6b7b8b9babbbcbdbebf");
    zcl_native_handle_metaverse_property_show(&c.request, &c.reply);
    MV_CHECK("unreadable: show refuses rather than answering absent",
             c.reply.status != ZCL_COMMAND_STATUS_PASSED &&
             c.reply.error.code[0] != '\0');
    mv_cmd_free(&c);
    return failures;
}

static int unreadable_case_absent_store_control(const char *dd,
                                                 const char *mpath)
{
    int failures = 0;
    struct mv_cmd c;

    /* And the control: with the ZCODE store simply ABSENT, its own content
     * row remains readable.  The top-level aggregate may still be false
     * because this deliberately never-booted fixture has no node.db from
     * which the independent ZNAM authority could be read. */
    (void)unlink(mpath);
    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    zcl_native_handle_metaverse_property_list(&c.request, &c.reply);
    {
        const struct json_value *content =
            mv_find_kind(&c.reply.data, "content");
        MV_CHECK("unreadable: an absent ZCODE store is a readable empty "
                 "content authority",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && content &&
                 json_get_bool(json_get(content, "available")) &&
                 json_get_int(json_get(content, "total")) == 0);
    }
    mv_cmd_free(&c);
    return failures;
}

int t_unreadable_store_is_disclosed(void)
{
    int failures = 0;
    char dd[256];
    char mpath[768];

    test_make_tmpdir(dd, sizeof(dd), "metaverse", "unreadable");

    failures += unreadable_case_plant_blocker(dd, mpath, sizeof(mpath));
    failures += unreadable_case_list_discloses(dd);
    failures += unreadable_case_show_refuses(dd);
    failures += unreadable_case_absent_store_control(dd, mpath);

    test_rm_rf_recursive(dd);
    return failures;
}

