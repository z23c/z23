/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_metaverse_catalog — the sovereign-property catalog gate
 * (contexts/commons/modules/metaverse, engine/services/property_catalog_service.c, and the
 * metaverse.property.* handlers in contexts/commons/controllers/src/metaverse_controller.c).
 *
 * Coverage:
 *   1. property_id pure rules: kind/authority names, make/format/parse
 *      round-trip, and every rejection (zero root, unknown kind, missing or
 *      doubled ':', short/long/non-hex root, trailing bytes).
 *   2. The action vocabulary: single-bit naming, name round-trip, mask
 *      validity, and the refusal to render a truncated action list.
 *   3. The adapter registry: EVERY property kind has exactly one row, wired
 *      or explicitly unavailable — no kind may drop out of the catalog.
 *   4. CONTENT adapter against a real blob: show/list report present with
 *      the local_content_hash grade and chain_bound false; then the CAS
 *      chunk is deleted and the SAME query reports incomplete; a malformed
 *      manifest reports an integrity gap rather than absent or disappearing;
 *      then deletion alone reports absent. No stale caching.
 *   5. ZCODE_PACKAGE adapter against a really published release: owner is
 *      the publisher key, revision is the publisher sequence, and the grade
 *      is local_signature because the envelope's signature is verified IN
 *      THAT CALL. Deleting the envelope DROPS the grade to
 *      local_content_hash instead of keeping an unearned claim.
 *   6. THE READ-ONLY CONTRACT (t_readonly_contract) — the parent-failing
 *      case. `metaverse property list` must not mutate the datadir, and
 *      before vcs_package_cas_present_in() the only way to ask the store
 *      about its CAS was vcs_package_store_open(), whose recovery sweep
 *      DELETES orphan CAS objects. The test plants an orphan, proves the
 *      catalog leaves it untouched, and then proves store_open removes it —
 *      the contrast that makes the read-only path necessary rather than
 *      merely tidy.
 *   7. The CLI path: both leaves through zcl_command_registry_input_validate
 *      plus the handler they BIND, so the declared input keys are proven
 *      callable and an undeclared key is still refused.
 *
 * Handlers run in-process on ./test-tmp datadirs; CHAIN_MAIN is pinned so
 * the zcode acceptance rules are deterministic. */

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

void mv_hex32(const uint8_t in[32], char out[65])
{
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = k_hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = k_hexd[in[i] & 0xf];
    }
    out[64] = '\0';
}

char *mv_hex(const uint8_t *data, size_t len)
{
    char *out = malloc(2 * len + 1);

    if (!out)
        return NULL;
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = k_hexd[(data[i] >> 4) & 0xf];
        out[2 * i + 1] = k_hexd[data[i] & 0xf];
    }
    out[2 * len] = '\0';
    return out;
}

/* ── in-process command runner ────────────────────────────────────── */


void mv_cmd_init(struct mv_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.metaverse_test.v1");
}

void mv_cmd_free(struct mv_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

const struct zcl_command_spec *mv_leaf(const char *path)
{
    const struct zcl_command_registry *reg = zcl_command_catalog();

    if (!reg)
        return NULL;
    for (size_t i = 0; i < reg->count; i++) {
        if (strcmp(reg->commands[i].path, path) == 0)
            return &reg->commands[i];
    }
    return NULL;
}

/* Call `metaverse property show` for one id text against `dd`. */
void mv_show(struct mv_cmd *c, const char *dd, const char *id_text)
{
    mv_cmd_init(c);
    (void)json_push_kv_str(&c->input, "datadir", dd);
    (void)json_push_kv_str(&c->input, "property_id", id_text);
    zcl_native_handle_metaverse_property_show(&c->request, &c->reply);
}

void mv_list(struct mv_cmd *c, const char *dd, const char *kind)
{
    mv_cmd_init(c);
    (void)json_push_kv_str(&c->input, "datadir", dd);
    if (kind)
        (void)json_push_kv_str(&c->input, "kind", kind);
    zcl_native_handle_metaverse_property_list(&c->request, &c->reply);
}

const char *mv_str(const struct json_value *v, const char *key)
{
    const char *s = json_get_str(json_get(v, key));

    return s ? s : "";
}

/* The array element whose "property_id" equals id_text, or NULL. */
const struct json_value *mv_find_item(const struct json_value *data,
                                             const char *id_text)
{
    const struct json_value *arr = json_get(data, "properties");
    size_t n = arr ? json_size(arr) : 0;

    for (size_t i = 0; i < n; i++) {
        const struct json_value *row = json_at(arr, i);

        if (row && strcmp(mv_str(row, "property_id"), id_text) == 0)
            return row;
    }
    return NULL;
}

/* ── 3d: settlement + work reach the inspection surfaces ──────────── */

/* Find the kinds[] coverage row for one kind name. */
const struct json_value *mv_find_kind(const struct json_value *data,
                                             const char *kind_name)
{
    const struct json_value *arr = json_get(data, "kinds");
    size_t n = arr ? json_size(arr) : 0;

    for (size_t i = 0; i < n; i++) {
        const struct json_value *row = json_at(arr, i);

        if (row && strcmp(mv_str(row, "kind"), kind_name) == 0)
            return row;
    }
    return NULL;
}

/* Render one kind's view straight from view_begin, i.e. the state every
 * adapter starts from. No fixture needed: the settlement class and the
 * not-measured work block are derived from the KIND, so they are already
 * correct before any store is read. */
bool mv_render_begin(enum metaverse_kind kind, struct json_value *out)
{
    struct metaverse_property_id id;
    struct metaverse_property_view view;
    uint8_t root[32];

    for (int i = 0; i < 32; i++)
        root[i] = (uint8_t)(0x11 + i);
    if (!metaverse_property_id_make(kind, root, &id))
        return false;
    if (!metaverse_view_begin(&view, &id))
        return false;
    return metaverse_view_to_json(&view, out);
}


int test_metaverse_catalog(void)
{
    printf("\n=== metaverse_catalog: sovereign property catalog ===\n");
    int failures = 0;

    failures += t_property_id_rules();
    failures += t_action_vocabulary();
    failures += t_adapter_registry();
    failures += t_mvp_scope_decision();
    failures += t_settlement_classes();
    failures += t_work_measurement();
    failures += t_settlement_is_surfaced();
    failures += t_content_adapter();
    failures += t_zcode_adapter();
    failures += t_znam_adapter();
    failures += t_zslp_adapter();
    failures += t_readonly_contract();
    failures += t_registry_path();
    failures += t_unreadable_store_is_disclosed();
    printf("=== metaverse_catalog complete: %d failure(s) ===\n", failures);
    return failures;
}
