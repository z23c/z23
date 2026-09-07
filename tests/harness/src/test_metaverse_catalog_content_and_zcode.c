/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * metaverse_catalog scenario checks: the CONTENT adapter against a
 * real blob (present with local_content_hash grade, then a deleted
 * CAS chunk reports incomplete, a malformed manifest reports an
 * integrity gap, deletion alone reports absent, and no stale caching
 * across any of it), and the ZCODE_PACKAGE adapter against a really
 * published release (owner is the publisher key, revision is the
 * publisher sequence, the grade is local_signature because the
 * envelope's signature is verified in that call, and deleting the
 * envelope drops the grade rather than keeping an unearned claim).
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

/* ── 4: CONTENT adapter against a real blob ───────────────────────── */

struct content_adapter_ctx {
    char dd[256];
    char zcode_dir[512];
    char root_hex[65];
    char id_text[METAVERSE_ID_TEXT_MAX];
    char chunk_path[768];
    char manifest_path[768];
    uint8_t root[32];
    uint8_t chunk_hash[32];
    char chunk_hex[65];
};

static int content_case_fixture_and_id(struct content_adapter_ctx *cc,
                                        const uint8_t *bytes,
                                        size_t bytes_len, bool *store_ok)
{
    int failures = 0;
    struct vcs_package_store *store =
        vcs_package_store_open(cc->dd, 4u * 1024u * 1024u);
    MV_CHECK("content: fixture store opens", store != NULL);
    if (!store) {
        *store_ok = false;
        return failures;
    }
    *store_ok = true;
    MV_CHECK("content: blob stores",
             vcs_blob_put_to(store, bytes, bytes_len, cc->root) ==
                 VCS_BLOB_OK);
    vcs_package_store_close(store);

    mv_hex32(cc->root, cc->root_hex);
    snprintf(cc->id_text, sizeof(cc->id_text), "content:%s", cc->root_hex);
    {
        struct metaverse_property_id id;

        MV_CHECK("content: blob root parses as a content property id",
                 metaverse_property_id_parse(cc->id_text, &id) &&
                 id.kind == METAVERSE_KIND_CONTENT &&
                 memcmp(id.root, cc->root, 32) == 0);
    }
    return failures;
}

static int content_case_show_present_status(const struct json_value *data)
{
    int failures = 0;
    MV_CHECK("content: show reports the property present and determined",
             strcmp(mv_str(data, "status"), "present") == 0 &&
             json_get_bool(json_get(data, "determined")));
    MV_CHECK("content: the evidence grade is the locally re-derived root",
             strcmp(mv_str(data, "evidence_grade"),
                    "local_content_hash") == 0 &&
             strcmp(mv_str(data, "evidence_source"),
                    "mv_manifest_verify_possession") == 0);
    MV_CHECK("content: the view is explicitly NOT chain-bound and carries "
             "no freshness height",
             !json_get_bool(json_get(data, "chain_bound")) &&
             !json_get_bool(json_get(data, "has_freshness_height")) &&
             json_get_int(json_get(data, "freshness_height")) == -1);
    /* And the same on a REAL adapter-filled view, not just view_begin: the
     * content adapter must not have overwritten the class or minted a
     * measurement out of the tip. */
    MV_CHECK("content: a really-read blob still reports content_addressed "
             "with no work measurement",
             strcmp(mv_str(data, "settlement"), "content_addressed") == 0 &&
             json_get(data, "work") &&
             !json_get_bool(json_get(json_get(data, "work"),
                                     "measurable")) &&
             json_get_int(json_get(json_get(data, "work"),
                                   "confirmation_depth")) == -1);
    MV_CHECK("content: no owner is recorded, and it says so by name",
             strcmp(mv_str(data, "owner_principal"), "") == 0 &&
             strcmp(mv_str(data, "owner_principal_kind"), "none") == 0);
    return failures;
}

static int content_case_show_present_details(struct content_adapter_ctx *cc,
                                              const struct json_value *data,
                                              size_t bytes_len)
{
    int failures = 0;
    MV_CHECK("content: authority source is the blob store",
             strcmp(mv_str(data, "authority_source"),
                    "vcs.blob_store") == 0);
    MV_CHECK("content: complete bytes support host and deliver, never "
             "transfer (there is no title to move)",
             strstr(mv_str(data, "actions_csv"), "host") != NULL &&
             strstr(mv_str(data, "actions_csv"), "deliver") != NULL &&
             strstr(mv_str(data, "actions_csv"), "transfer") == NULL &&
             strstr(mv_str(data, "actions_csv"),
                    "publish_revision") == NULL);
    {
        const char *ir = mv_str(data, "immutable_root");
        const char *cr = mv_str(data, "content_root");

        MV_CHECK("content: the content root is the chunk hash, and the "
                 "immutable root is the manifest root",
                 strcmp(ir, cc->root_hex) == 0 && strlen(cr) == 64 &&
                 strcmp(cr, cc->root_hex) != 0);
    }
    MV_CHECK("content: chunk accounting is complete",
             json_get_int(json_get(data, "chunk_total")) == 1 &&
             json_get_int(json_get(data, "chunks_present")) == 1 &&
             json_get_int(json_get(data, "chunks_verified")) == 1 &&
             json_get_int(json_get(data, "bytes_verified")) ==
                 (int64_t)bytes_len &&
             json_get_bool(json_get(data, "manifest_root_verified")) &&
             json_get_bool(json_get(data, "verification_complete")) &&
             strcmp(mv_str(data, "verification_gap"), "") == 0 &&
             json_get_int(json_get(data, "file_count")) == 1);
    /* Keep the chunk hash for the deletion step below. */
    snprintf(cc->chunk_hex, sizeof(cc->chunk_hex), "%s",
             mv_str(data, "content_root"));
    snprintf(cc->chunk_path, sizeof(cc->chunk_path), "%s/cas/sha3/%.2s/%s",
             cc->zcode_dir, cc->chunk_hex, cc->chunk_hex);
    return failures;
}

static int content_case_show_present(struct content_adapter_ctx *cc,
                                      size_t bytes_len)
{
    int failures = 0;
    struct mv_cmd c;

    /* show — present, byte-identity evidence, and NOT chain bound. */
    mv_show(&c, cc->dd, cc->id_text);
    MV_CHECK("content: show succeeds",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    failures += content_case_show_present_status(&c.reply.data);
    failures += content_case_show_present_details(cc, &c.reply.data,
                                                   bytes_len);
    mv_cmd_free(&c);
    return failures;
}

static int content_case_list_catalog(struct content_adapter_ctx *cc)
{
    int failures = 0;
    struct mv_cmd c;

    /* list — the blob is in the catalog, and every kind reports a row. */
    mv_list(&c, cc->dd, NULL);
    MV_CHECK("content: list succeeds",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    MV_CHECK("content: the blob appears in the unfiltered catalog",
             mv_find_item(&c.reply.data, cc->id_text) != NULL);
    MV_CHECK("content: a complete store reports no hidden integrity gap",
             json_get_bool(json_get(&c.reply.data, "integrity_ok")) &&
             json_get_int(json_get(&c.reply.data,
                                   "integrity_gap_count")) == 0);
    MV_CHECK("content: every property kind produces a coverage row",
             json_get_int(json_get(&c.reply.data, "kinds_scanned")) ==
                 (int64_t)METAVERSE_KIND_COUNT - 1);
    {
        const struct json_value *kinds = json_get(&c.reply.data, "kinds");
        size_t n = kinds ? json_size(kinds) : 0;
        bool ok = n == (size_t)METAVERSE_KIND_COUNT - 1;

        for (size_t i = 0; i < n; i++) {
            const struct json_value *row = json_at(kinds, i);
            if (!json_get_bool(json_get(row, "available")) &&
                mv_str(row, "unavailable_reason")[0] == '\0')
                ok = false;
        }
        MV_CHECK("content: kinds without a reader are reported unavailable "
                 "with a reason, not dropped", ok);
    }
    mv_cmd_free(&c);
    return failures;
}

static int content_case_wrong_bytes_and_symlink(struct content_adapter_ctx *cc,
                                                 const uint8_t *bytes,
                                                 size_t bytes_len)
{
    int failures = 0;
    struct mv_cmd c;
    uint8_t wrong[sizeof("sovereign content, byte-identical everywhere") -
                  1u];
    FILE *f;

    /* A pathname-shaped CAS entry is not possession. Exercise every cheap
     * false-positive shape before the missing-file case below. */
    memset(wrong, 0xa5, bytes_len);
    f = fopen(cc->chunk_path, "wb");
    MV_CHECK("content: same-length wrong bytes are planted",
             f && fwrite(wrong, 1, bytes_len, f) == bytes_len);
    if (f)
        fclose(f);
    mv_show(&c, cc->dd, cc->id_text);
    MV_CHECK("content: same-length wrong bytes never become PRESENT",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
             json_get_int(json_get(&c.reply.data, "chunks_present")) == 1 &&
             json_get_int(json_get(&c.reply.data, "chunks_verified")) == 0 &&
             !json_get_bool(json_get(&c.reply.data,
                                     "verification_complete")) &&
             strcmp(mv_str(&c.reply.data, "verification_gap"),
                    "chunk_hash_mismatch") == 0 &&
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
    mv_cmd_free(&c);

    f = fopen(cc->chunk_path, "wb");
    MV_CHECK("content: canonical bytes restore after hash mismatch",
             f && fwrite(bytes, 1, bytes_len, f) == bytes_len);
    if (f)
        fclose(f);
    MV_CHECK("content: canonical CAS path is removed for symlink case",
             unlink(cc->chunk_path) == 0);
    MV_CHECK("content: symlink is planted at the CAS coordinate",
             symlink("/dev/null", cc->chunk_path) == 0);
    mv_show(&c, cc->dd, cc->id_text);
    MV_CHECK("content: O_NOFOLLOW rejects a symlink as possession",
             strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
             strcmp(mv_str(&c.reply.data, "verification_gap"),
                    "chunk_symlink") == 0 &&
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
    mv_cmd_free(&c);
    MV_CHECK("content: symlink is removed", unlink(cc->chunk_path) == 0);
    return failures;
}

static int content_case_zero_length_and_dir(struct content_adapter_ctx *cc,
                                             const uint8_t *bytes,
                                             size_t bytes_len)
{
    int failures = 0;
    struct mv_cmd c;
    FILE *f;

    f = fopen(cc->chunk_path, "wb");
    MV_CHECK("content: zero-length CAS object is planted", f != NULL);
    if (f)
        fclose(f);
    mv_show(&c, cc->dd, cc->id_text);
    MV_CHECK("content: wrong length never becomes possession",
             strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
             strcmp(mv_str(&c.reply.data, "verification_gap"),
                    "chunk_length_mismatch") == 0 &&
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
    mv_cmd_free(&c);

    MV_CHECK("content: zero-length object is removed",
             unlink(cc->chunk_path) == 0);
    MV_CHECK("content: directory is planted at the CAS coordinate",
             mkdir(cc->chunk_path, 0700) == 0);
    mv_show(&c, cc->dd, cc->id_text);
    MV_CHECK("content: non-regular CAS coordinate never becomes present",
             strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
             strcmp(mv_str(&c.reply.data, "verification_gap"),
                    "chunk_not_regular") == 0 &&
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
    mv_cmd_free(&c);
    MV_CHECK("content: directory coordinate is removed",
             rmdir(cc->chunk_path) == 0);
    f = fopen(cc->chunk_path, "wb");
    MV_CHECK("content: canonical bytes restore after shape cases",
             f && fwrite(bytes, 1, bytes_len, f) == bytes_len);
    if (f)
        fclose(f);
    return failures;
}

static int content_case_false_positive_shapes(struct content_adapter_ctx *cc,
                                               const uint8_t *bytes,
                                               size_t bytes_len)
{
    int failures = 0;
    failures += content_case_wrong_bytes_and_symlink(cc, bytes, bytes_len);
    failures += content_case_zero_length_and_dir(cc, bytes, bytes_len);
    return failures;
}

static int content_case_no_stale_cache_delete(struct content_adapter_ctx *cc)
{
    int failures = 0;
    struct mv_cmd c;

    /* THE NO-STALE-CACHE PROOF, step 1: delete the CAS byte. */
    MV_CHECK("content: the chunk hash was captured",
             strlen(cc->chunk_hex) == 64);
    MV_CHECK("content: the CAS object exists before deletion",
             access(cc->chunk_path, F_OK) == 0);
    MV_CHECK("content: the CAS object is deleted",
             unlink(cc->chunk_path) == 0);

    mv_show(&c, cc->dd, cc->id_text);
    MV_CHECK("content: the very next read reports incomplete — the "
             "projection cached nothing",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
             json_get_int(json_get(&c.reply.data, "chunks_present")) == 0);
    /* Inspection is a QUERY now, so the action set an incomplete property
     * supports is genuinely empty — the field must render as the empty string
     * and not fall back to naming the reserved bit, which would read to a
     * caller as a right it does not have. */
    MV_CHECK("content: an incomplete property supports no ACTION at all",
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
    MV_CHECK("content: the incomplete view says why",
             strcmp(mv_str(&c.reply.data, "verification_gap"),
                    "chunk_missing") == 0 &&
             strstr(mv_str(&c.reply.data, "reason"), "chunk_missing") != NULL);
    mv_cmd_free(&c);
    return failures;
}

static int content_case_corrupt_manifest_show(struct content_adapter_ctx *cc)
{
    int failures = 0;
    struct mv_cmd c;

    /* Step 2: corruption is not absence, and must not vanish from list
     * accounting without an explicit integrity gap. */
    snprintf(cc->manifest_path, sizeof(cc->manifest_path), "%s/manifests/%s",
             cc->zcode_dir, cc->root_hex);
    {
        FILE *f = fopen(cc->manifest_path, "wb");
        bool wrote = f && fwrite("x", 1, 1, f) == 1;

        if (f)
            fclose(f);
        MV_CHECK("content: the manifest is replaced by malformed bytes",
                 wrote);
    }
    mv_show(&c, cc->dd, cc->id_text);
    MV_CHECK("content: malformed is unknown, not absent or determined",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "unknown") == 0 &&
             !json_get_bool(json_get(&c.reply.data, "determined")) &&
             strcmp(mv_str(&c.reply.data, "evidence_grade"), "unknown") == 0 &&
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0 &&
             strstr(mv_str(&c.reply.data, "reason"), "invalid") != NULL);
    mv_cmd_free(&c);
    return failures;
}

static int content_case_corrupt_manifest_list(struct content_adapter_ctx *cc)
{
    int failures = 0;
    struct mv_cmd c;

    mv_list(&c, cc->dd, "content");
    {
        const struct json_value *row =
            mv_find_kind(&c.reply.data, "content");
        MV_CHECK("content: malformed cannot disappear as an empty inventory",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && row &&
                 !json_get_bool(json_get(&c.reply.data, "integrity_ok")) &&
                 json_get_int(json_get(&c.reply.data,
                                       "integrity_gap_count")) == 1 &&
                 json_get_bool(json_get(row, "integrity_checked")) &&
                 !json_get_bool(json_get(row, "integrity_ok")) &&
                 json_get_int(json_get(row, "integrity_gap_count")) == 1 &&
                 strstr(mv_str(row, "integrity_reason"), "invalid") != NULL);
    }
    mv_cmd_free(&c);
    return failures;
}

static int content_case_corruption_not_absence(struct content_adapter_ctx *cc)
{
    int failures = 0;
    failures += content_case_corrupt_manifest_show(cc);
    failures += content_case_corrupt_manifest_list(cc);
    return failures;
}

static int content_case_deletion_absent(struct content_adapter_ctx *cc)
{
    int failures = 0;
    struct mv_cmd c;

    /* Step 3: deletion alone means the object is gone entirely. */
    MV_CHECK("content: the manifest is deleted",
             unlink(cc->manifest_path) == 0);
    mv_show(&c, cc->dd, cc->id_text);
    MV_CHECK("content: a removed object reads as absent, determined",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "absent") == 0 &&
             json_get_bool(json_get(&c.reply.data, "determined")) &&
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_store_read") == 0 &&
             !json_get_bool(json_get(&c.reply.data,
                                     "manifest_root_verified")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "verification_complete")));
    mv_cmd_free(&c);

    mv_list(&c, cc->dd, "content");
    MV_CHECK("content: the removed blob is gone from the catalog too",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             mv_find_item(&c.reply.data, cc->id_text) == NULL &&
             json_get_int(json_get(&c.reply.data, "rendered")) == 0 &&
             json_get_bool(json_get(&c.reply.data, "integrity_ok")));
    mv_cmd_free(&c);
    return failures;
}

int t_content_adapter(void)
{
    int failures = 0;
    const uint8_t bytes[] = "sovereign content, byte-identical everywhere";
    size_t bytes_len = sizeof(bytes) - 1u;
    struct content_adapter_ctx cc;
    bool store_ok = false;

    memset(&cc, 0, sizeof(cc));
    test_make_tmpdir(cc.dd, sizeof(cc.dd), "metaverse", "content");
    snprintf(cc.zcode_dir, sizeof(cc.zcode_dir), "%s/zcode", cc.dd);

    failures += content_case_fixture_and_id(&cc, bytes, bytes_len,
                                            &store_ok);
    if (!store_ok) {
        test_rm_rf_recursive(cc.dd);
        return failures;
    }
    failures += content_case_show_present(&cc, bytes_len);
    failures += content_case_list_catalog(&cc);
    failures += content_case_false_positive_shapes(&cc, bytes, bytes_len);
    failures += content_case_no_stale_cache_delete(&cc);
    failures += content_case_corruption_not_absence(&cc);
    failures += content_case_deletion_absent(&cc);

    (void)vcs_package_cas_present_in(cc.zcode_dir, cc.chunk_hash);
    test_rm_rf_recursive(cc.dd);
    return failures;
}

/* ── zcode publication fixture (the test_zcode_publish pattern) ────── */

struct mv_pkg {
    struct vcs_package_manifest manifest;
    uint8_t *wire;
    size_t wire_len;
    uint8_t root[32];
    char root_hex[65];
};

static char *g_mv_recipe_hex;
static uint8_t g_mv_recipe_root[32];

static bool mv_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static bool mv_sign(struct vcs_package_release *r, struct privkey *sk)
{
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    struct uint256 hash;
    unsigned char compact[COMPACT_SIGNATURE_SIZE];

    if (vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    memcpy(hash.data, id, 32);
    if (!privkey_sign_compact(sk, &hash, compact))
        return false;
    memcpy(r->signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return true;
}

static bool mv_t1_reward(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    size_t pubkey_len = 0, script_len = 0;
    const unsigned char *pubkey_prefix, *script_prefix;
    struct tx_destination dest;

    if (!params)
        return false;
    pubkey_prefix = chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS,
                                               &pubkey_len);
    script_prefix = chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS,
                                               &script_len);
    if (!pubkey_prefix || !script_prefix)
        return false;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x44, 20);
    return encode_destination(&dest, pubkey_prefix, pubkey_len, script_prefix,
                              script_len, out, out_size);
}

static bool mv_add_file(struct mv_pkg *p, const char *dir, const char *path,
                        const char *content)
{
    char full[1024];
    const char *slash = strrchr(path, '/');
    FILE *f;
    size_t len = strlen(content);
    bool wrote;
    uint8_t hash[32];

    snprintf(full, sizeof(full), "%s/%s", dir, path);
    if (slash) {
        char parent[1024];

        snprintf(parent, sizeof(parent), "%s/%.*s", dir,
                 (int)(slash - path), path);
        (void)mkdir(parent, 0700);
    }
    f = fopen(full, "wb");
    if (!f)
        return false;
    wrote = fwrite(content, 1, len, f) == len;
    fclose(f);
    if (!wrote || !vcs_package_chunk_hash((const uint8_t *)content, len, hash))
        return false;
    return vcs_package_manifest_add(&p->manifest, path,
                                    VCS_PACKAGE_MODE_FILE, len, hash, 1);
}

static bool mv_make_package(struct mv_pkg *p, const char *dir)
{
    memset(p, 0, sizeof(*p));
    vcs_package_manifest_init(&p->manifest);
    (void)mkdir(dir, 0700);
    if (!mv_add_file(p, dir, "LICENSE",
                     "MIT License\n\nPermission is hereby granted.\n") ||
        !mv_add_file(p, dir, "include/prop.h",
                     "#pragma once\nstruct prop { unsigned id; };\n") ||
        !mv_add_file(p, dir, "src/prop.c",
                     "#include \"prop.h\"\nint prop_id(void){return 1;}\n"))
        return false;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire, &p->wire_len))
        return false;
    if (!vcs_package_manifest_root(&p->manifest, p->root))
        return false;
    mv_hex32(p->root, p->root_hex);
    return true;
}

static bool mv_use_recipe_add_file(struct vcs_package_recipe *r,
                                   const char *path)
{
    size_t len = strlen(path);
    bool ok = true;

    if (len > 2 && strcmp(path + len - 2, ".h") == 0) {
        const char *slash = strrchr(path, '/');

        ok = vcs_package_recipe_add_header(r, path, NULL);
        if (ok && slash) {
            char dir[1024];
            enum vcs_package_recipe_error rerr = VCS_PACKAGE_RECIPE_OK;

            snprintf(dir, sizeof(dir), "%.*s", (int)(slash - path), path);
            if (!vcs_package_recipe_add_include_dir(r, dir, &rerr) &&
                rerr != VCS_PACKAGE_RECIPE_ERR_LIST_ORDER)
                ok = false;
        }
    } else if (len > 2 && strcmp(path + len - 2, ".c") == 0) {
        ok = vcs_package_recipe_add_source(r, path, NULL);
    }
    return ok;
}

static bool mv_use_recipe(const struct vcs_package_manifest *m)
{
    struct vcs_package_recipe r;
    bool ok = true;
    uint8_t *wire = NULL;
    size_t wire_len = 0;

    vcs_package_recipe_init(&r);
    for (size_t i = 0; ok && i < m->count; i++)
        ok = mv_use_recipe_add_file(&r, m->files[i].path);
    if (ok)
        ok = vcs_package_recipe_add_define(&r, "ZCL_FIXTURE=1", NULL) &&
             vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                            NULL);
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    if (ok)
        ok = vcs_package_recipe_root(&r, g_mv_recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &wire, &wire_len) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok) {
        free(wire);
        return false;
    }
    free(g_mv_recipe_hex);
    g_mv_recipe_hex = mv_hex(wire, wire_len);
    free(wire);
    return g_mv_recipe_hex != NULL;
}

static bool mv_release(struct vcs_package_release *r, uint8_t key_seed,
                       const char *name, const uint8_t package_root[32])
{
    struct privkey sk;
    struct pubkey pk;

    memset(r, 0, sizeof(*r));
    if (!mv_keypair(key_seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    memcpy(r->package_root, package_root, 32);
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = 7u;
    if (!mv_t1_reward(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "MIT");
    memcpy(r->recipe_root, g_mv_recipe_root, 32);
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return mv_sign(r, &sk);
}

/* Publish a package into `dd` through the real zcode commit handler.
 * Returns the publisher pubkey hex in pub_hex and the release id hex. */
static bool mv_publish(const char *dd, struct mv_pkg *p, char pub_hex[67],
                       char release_id_hex[65])
{
    struct vcs_package_release r;
    char pkgdir[512];
    char *release_hex;
    char *manifest_hex;
    struct mv_cmd c;
    bool ok;
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    struct privkey sk;
    struct pubkey pk;

    snprintf(pkgdir, sizeof(pkgdir), "%s/pkg", dd);
    if (!mv_make_package(p, pkgdir) || !mv_use_recipe(&p->manifest) ||
        !mv_release(&r, 0x7b, "rhett/property-kit", p->root))
        return false;
    if (!mv_keypair(0x7b, &sk, &pk))
        return false;
    for (size_t i = 0; i < pk.size; i++) {
        pub_hex[2 * i]     = k_hexd[(pk.vch[i] >> 4) & 0xf];
        pub_hex[2 * i + 1] = k_hexd[pk.vch[i] & 0xf];
    }
    pub_hex[2 * pk.size] = '\0';
    if (vcs_package_release_id(&r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    mv_hex32(id, release_id_hex);

    release_hex = NULL;
    {
        uint8_t *wire = NULL;
        size_t wire_len = 0;

        if (vcs_package_release_serialize(&r, &wire, &wire_len) !=
            VCS_PACKAGE_RELEASE_OK)
            return false;
        release_hex = mv_hex(wire, wire_len);
        free(wire);
    }
    manifest_hex = mv_hex(p->wire, p->wire_len);
    if (!release_hex || !manifest_hex || !g_mv_recipe_hex) {
        free(release_hex);
        free(manifest_hex);
        return false;
    }

    mv_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "release_hex", release_hex);
    (void)json_push_kv_str(&c.input, "manifest_hex", manifest_hex);
    (void)json_push_kv_str(&c.input, "recipe_hex", g_mv_recipe_hex);
    (void)json_push_kv_str(&c.input, "dir", pkgdir);
    zcl_native_handle_zcode_package_publish_commit(&c.request, &c.reply);
    ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED;
    mv_cmd_free(&c);
    free(release_hex);
    free(manifest_hex);
    return ok;
}

struct mv_verify_mutation {
    const char *path;
    size_t length;
    bool fired;
};

static void mv_mutate_after_first_hash(void *context,
                                       uint32_t chunks_verified)
{
    struct mv_verify_mutation *mutation = context;
    uint8_t *wrong;
    FILE *f;

    if (!mutation || mutation->fired || chunks_verified != 1)
        return;
    wrong = malloc(mutation->length);
    if (!wrong)
        return;
    memset(wrong, 0x5a, mutation->length);
    f = fopen(mutation->path, "wb");
    mutation->fired =
        f && fwrite(wrong, 1, mutation->length, f) == mutation->length;
    if (f)
        fclose(f);
    free(wrong);
}

/* ── 5: ZCODE_PACKAGE adapter against a real publication ──────────── */

struct zcode_adapter_ctx {
    char dd[256];
    char zcode_dir[512];
    char id_text[METAVERSE_ID_TEXT_MAX];
    char pub_hex[67];
    char release_id_hex[65];
    char release_path[768];
    char manifest_path[768];
    struct mv_pkg p;
};

static int zcode_case_toctou_race(struct zcode_adapter_ctx *zc)
{
    int failures = 0;
    /* Deterministic TOCTOU proof: mutate the first coordinate after it was
     * hashed but before the verifier's final fingerprint pass. */
    static const char first_file[] =
        "MIT License\n\nPermission is hereby granted.\n";
    struct mv_manifest_read manifest;
    struct mv_verify_mutation mutation;
    char first_hash[65];
    char first_path[768];
    uint64_t bytes_used = 0;
    uint32_t operations_used = 0;
    FILE *f;

    mv_hex32(zc->p.manifest.files[0].chunk_hashes, first_hash);
    snprintf(first_path, sizeof(first_path), "%s/cas/sha3/%.2s/%s",
             zc->zcode_dir, first_hash, first_hash);
    mutation = (struct mv_verify_mutation){
        .path = first_path,
        .length = sizeof(first_file) - 1u,
        .fired = false,
    };
    MV_CHECK("zcode: canonical manifest opens for bounded race proof",
             mv_manifest_read(zc->zcode_dir, zc->p.root_hex, &manifest) ==
                 MV_MANIFEST_READ_OK);
    mv_manifest_verify_possession_test(
        zc->zcode_dir, &manifest, MV_PROPERTY_VERIFY_BYTES,
        MV_PROPERTY_SHOW_VERIFY_OPS, mv_mutate_after_first_hash, &mutation,
        &bytes_used, &operations_used);
    MV_CHECK("zcode: mutation between hash and final recheck is caught",
             mutation.fired && !manifest.verification_complete &&
             strcmp(manifest.verification_gap,
                    "chunk_mutated_during_verification") == 0 &&
             bytes_used == manifest.total_bytes &&
             operations_used > manifest.chunk_total);
    mv_manifest_free(&manifest);

    f = fopen(first_path, "wb");
    MV_CHECK("zcode: canonical first chunk restores after race proof",
             f && fwrite(first_file, 1, sizeof(first_file) - 1u, f) ==
                      sizeof(first_file) - 1u);
    if (f)
        fclose(f);

    MV_CHECK("zcode: canonical manifest opens for strict budget proof",
             mv_manifest_read(zc->zcode_dir, zc->p.root_hex, &manifest) ==
                 MV_MANIFEST_READ_OK);
    mv_manifest_verify_possession_test(
        zc->zcode_dir, &manifest, 0, MV_PROPERTY_SHOW_VERIFY_OPS, NULL, NULL,
        &bytes_used, &operations_used);
    MV_CHECK("zcode: zero byte budget performs no content read",
             !manifest.verification_complete && bytes_used == 0 &&
             operations_used == 0 &&
             strcmp(manifest.verification_gap,
                    "byte_budget_exhausted") == 0);
    mv_manifest_free(&manifest);
    return failures;
}

static int zcode_case_show_present(struct zcode_adapter_ctx *zc)
{
    int failures = 0;
    struct mv_cmd c;

    mv_show(&c, zc->dd, zc->id_text);
    MV_CHECK("zcode: show succeeds",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED);
    MV_CHECK("zcode: the published package reads as present",
             strcmp(mv_str(&c.reply.data, "status"), "present") == 0 &&
             json_get_bool(json_get(&c.reply.data, "determined")));
    MV_CHECK("zcode: the evidence grade is the signature verified in THIS "
             "call, not one inherited from publication",
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_signature") == 0 &&
             strcmp(mv_str(&c.reply.data, "evidence_source"),
                    "vcs_package_release_verify") == 0);
    MV_CHECK("zcode: a verified signature is still NOT chain-bound",
             !json_get_bool(json_get(&c.reply.data, "chain_bound")) &&
             !json_get_bool(json_get(&c.reply.data,
                                     "has_freshness_height")));
    MV_CHECK("zcode: the controller principal is the publisher key",
             strcmp(mv_str(&c.reply.data, "owner_principal"),
                    zc->pub_hex) == 0 &&
             strcmp(mv_str(&c.reply.data, "owner_principal_kind"),
                    "publisher_pubkey") == 0);
    MV_CHECK("zcode: the revision is the publisher sequence",
             json_get_bool(json_get(&c.reply.data, "has_revision")) &&
             json_get_int(json_get(&c.reply.data, "revision")) == 7);
    MV_CHECK("zcode: the descriptor root is the signed release id",
             strcmp(mv_str(&c.reply.data, "descriptor_root"),
                    zc->release_id_hex) == 0);
    MV_CHECK("zcode: the immutable root is the manifest root",
             strcmp(mv_str(&c.reply.data, "immutable_root"),
                    zc->p.root_hex) == 0 &&
             strcmp(mv_str(&c.reply.data, "content_root"),
                    zc->p.root_hex) == 0);
    MV_CHECK("zcode: a signed, complete package may publish a revision",
             strstr(mv_str(&c.reply.data, "actions_csv"),
                    "publish_revision") != NULL &&
             strstr(mv_str(&c.reply.data, "actions_csv"), "sell") != NULL);
    MV_CHECK("zcode: all three files and chunks are accounted for",
             json_get_int(json_get(&c.reply.data, "file_count")) == 3 &&
             json_get_int(json_get(&c.reply.data, "chunk_total")) == 3 &&
             json_get_int(json_get(&c.reply.data, "chunks_present")) == 3 &&
             json_get_int(json_get(&c.reply.data, "chunks_verified")) == 3 &&
             json_get_bool(json_get(&c.reply.data,
                                    "manifest_root_verified")) &&
             json_get_bool(json_get(&c.reply.data,
                                    "verification_complete")) &&
             strcmp(mv_str(&c.reply.data, "verification_gap"), "") == 0);
    mv_cmd_free(&c);
    return failures;
}

static int zcode_case_list_filtered(struct zcode_adapter_ctx *zc)
{
    int failures = 0;
    struct mv_cmd c;

    mv_list(&c, zc->dd, "zcode_package");
    MV_CHECK("zcode: the package appears in the filtered catalog",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             mv_find_item(&c.reply.data, zc->id_text) != NULL);
    {
        const struct json_value *kinds = json_get(&c.reply.data, "kinds");
        size_t n = kinds ? json_size(kinds) : 0;
        bool found = false;

        for (size_t i = 0; i < n; i++) {
            const struct json_value *row = json_at(kinds, i);
            if (strcmp(mv_str(row, "kind"), "content") == 0 &&
                !json_get_bool(json_get(row, "available")) &&
                strstr(mv_str(row, "unavailable_reason"), "filter") != NULL)
                found = true;
        }
        MV_CHECK("zcode: a filtered-out kind is still listed, marked "
                 "not-scanned", found);
    }
    mv_cmd_free(&c);
    return failures;
}

static int zcode_case_corrupt_manifest(struct zcode_adapter_ctx *zc)
{
    int failures = 0;
    struct mv_cmd c;

    /* A signed release still proves authorship when its manifest is corrupt,
     * but it cannot prove possession or a locally re-derived content root.
     * The item stays visible and the catalog separately reports integrity. */
    snprintf(zc->manifest_path, sizeof(zc->manifest_path), "%s/manifests/%s",
             zc->zcode_dir, zc->p.root_hex);
    {
        FILE *f = fopen(zc->manifest_path, "wb");
        bool wrote = f && fwrite("x", 1, 1, f) == 1;

        if (f)
            fclose(f);
        MV_CHECK("zcode: fixture manifest is made malformed", wrote);
    }
    mv_show(&c, zc->dd, zc->id_text);
    MV_CHECK("zcode: malformed manifest keeps only verified authorship",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&c.reply.data, "determined")) &&
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_signature") == 0 &&
             strcmp(mv_str(&c.reply.data, "status"), "incomplete") == 0 &&
             strstr(mv_str(&c.reply.data, "reason"), "invalid") != NULL &&
             strcmp(mv_str(&c.reply.data, "actions_csv"), "") == 0);
    mv_cmd_free(&c);

    mv_list(&c, zc->dd, "zcode_package");
    {
        const struct json_value *row =
            mv_find_kind(&c.reply.data, "zcode_package");
        MV_CHECK("zcode: malformed manifest is rendered and disclosed",
                 c.reply.status == ZCL_COMMAND_STATUS_PASSED && row &&
                 mv_find_item(&c.reply.data, zc->id_text) != NULL &&
                 !json_get_bool(json_get(row, "integrity_ok")) &&
                 json_get_int(json_get(row, "integrity_gap_count")) == 1);
    }
    mv_cmd_free(&c);
    {
        FILE *f = fopen(zc->manifest_path, "wb");
        bool restored = f && fwrite(zc->p.wire, 1, zc->p.wire_len, f) ==
                                 zc->p.wire_len;

        if (f)
            fclose(f);
        MV_CHECK("zcode: canonical manifest bytes are restored", restored);
    }
    return failures;
}

static int zcode_case_unearned_claim(struct zcode_adapter_ctx *zc)
{
    int failures = 0;
    struct mv_cmd c;

    /* THE UNEARNED-CLAIM PROOF: remove the signed envelope. The bytes are
     * untouched, so the package stays present — but the signature can no
     * longer be verified, so the grade must DROP. */
    snprintf(zc->release_path, sizeof(zc->release_path), "%s/releases/%s",
             zc->zcode_dir, zc->release_id_hex);
    MV_CHECK("zcode: the release envelope exists before deletion",
             access(zc->release_path, F_OK) == 0);
    MV_CHECK("zcode: the release envelope is deleted",
             unlink(zc->release_path) == 0);

    mv_show(&c, zc->dd, zc->id_text);
    /* The index is built from releases/, so with the envelope gone the
     * package root is no longer claimed by any release: absent, and still
     * a determined verdict. */
    MV_CHECK("zcode: with no release naming it, the root reads absent",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             strcmp(mv_str(&c.reply.data, "status"), "absent") == 0 &&
             json_get_bool(json_get(&c.reply.data, "determined")));
    MV_CHECK("zcode: an absent package claims no signature evidence",
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_signature") != 0 &&
             strcmp(mv_str(&c.reply.data, "evidence_grade"),
                    "local_store_read") == 0 &&
             strcmp(mv_str(&c.reply.data, "descriptor_root"), "") == 0);
    mv_cmd_free(&c);
    return failures;
}

static int zcode_case_content_shape_mismatch(struct zcode_adapter_ctx *zc)
{
    int failures = 0;
    /* The SAME bytes are still a content property, because the blob shape
     * question is about the manifest, not the release. A three-file package
     * is not a blob, and the content adapter says so by name rather than
     * claiming the object does not exist. */
    char content_id[METAVERSE_ID_TEXT_MAX];
    struct mv_cmd c;

    snprintf(content_id, sizeof(content_id), "content:%s", zc->p.root_hex);
    mv_show(&c, zc->dd, content_id);
    MV_CHECK("zcode: a multi-file package is not answered as an absent "
             "blob — the shape mismatch is named",
             c.reply.status == ZCL_COMMAND_STATUS_PASSED &&
             !json_get_bool(json_get(&c.reply.data, "determined")) &&
             strstr(mv_str(&c.reply.data, "reason"), "zcode_package") !=
                 NULL);
    mv_cmd_free(&c);
    return failures;
}

int t_zcode_adapter(void)
{
    int failures = 0;
    struct zcode_adapter_ctx zc;
    bool published;

    memset(&zc, 0, sizeof(zc));
    chain_params_select(CHAIN_MAIN);
    test_make_tmpdir(zc.dd, sizeof(zc.dd), "metaverse", "zcode");
    snprintf(zc.zcode_dir, sizeof(zc.zcode_dir), "%s/zcode", zc.dd);

    published = mv_publish(zc.dd, &zc.p, zc.pub_hex, zc.release_id_hex);
    MV_CHECK("zcode: the fixture package publishes", published);
    if (!published) {
        vcs_package_manifest_free(&zc.p.manifest);
        free(zc.p.wire);
        test_rm_rf_recursive(zc.dd);
        return failures;
    }
    snprintf(zc.id_text, sizeof(zc.id_text), "zcode_package:%s",
             zc.p.root_hex);

    failures += zcode_case_toctou_race(&zc);
    failures += zcode_case_show_present(&zc);
    failures += zcode_case_list_filtered(&zc);
    failures += zcode_case_corrupt_manifest(&zc);
    failures += zcode_case_unearned_claim(&zc);
    failures += zcode_case_content_shape_mismatch(&zc);

    vcs_package_manifest_free(&zc.p.manifest);
    free(zc.p.wire);
    free(g_mv_recipe_hex);
    g_mv_recipe_hex = NULL;
    test_rm_rf_recursive(zc.dd);
    return failures;
}

