/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the slice-4 `zcode` leaves — contributor identity
 * and ZNAM pointers:
 *
 *   zcode contributor show      profile for one publisher pubkey: the
 *                               authoritative release facts (from the
 *                               signed envelopes via the package index),
 *                               the slice-8 reward ledger facts (earned
 *                               score / queued / settled — earned_score
 *                               and token_rewards_received stay SEPARATE
 *                               facts; no balances anywhere), plus the
 *                               ZNAM publisher-profile pointer when one
 *                               is bound
 *   zcode contributor packages  the published releases of one publisher
 *                               key, from the slice-3 index
 *   zcode package resolve       resolve a ZNAM package name to its
 *                               pointer and through it to the signed
 *                               release — pointer facts and identity
 *                               facts are separate output objects, and
 *                               the binding proof is explicit
 *
 * IDENTITY RULE (owner directive): the secp256k1 publisher key is the only
 * authoritative identity; ZNAM records are mutable pointers and a pointer
 * change never changes an existing release. These handlers enforce it
 * structurally: identity fields are ALWAYS read from the signed release /
 * package index, never from the ZNAM record.
 *
 * Reads are over <datadir>/zcode (rebuilt package index) and
 * <datadir>/node.db (canonical ZNAM model, read-only). One-shot CLI
 * boundary, same as the publish leaves: do not run against a datadir
 * whose node is mid-write. CHAIN_MAIN is selected when nothing selected a
 * chain (the binding check derives chain P2PKH addresses). */

#include "base/hex.h"
#include "command/native_command.h"

#include "kernel/command_registry.h"

#include "base/log_macros.h"
#include "chain/chainparams.h"
#include "json/json.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "services/zcode_pointer.h"
#include "vcs/package_contributor.h"
#include "vcs/package_index.h"
#include "vcs/package_rank.h"
#include "vcs/package_reward.h"

#include <stdio.h>
#include <string.h>

#define ZC4_LOG "zcode.contributor"

#define ZC4_SEARCH_MAX_ROWS 16u
#define ZC4_SHOW_MAX_ROOTS 16u

/* ── small input helpers (native_zcode_command.c pattern) ───────────── */

static const char *zc4_input_str(const struct json_value *input,
                                 const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zc4_datadir(const struct zcl_command_request *request)
{
    const char *dd = zc4_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

static bool zc4_pubkey_hex_valid(const char *hex)
{
    if (!hex || strlen(hex) != 66)
        return false;
    for (size_t i = 0; i < 66; i++) {
        char ch = hex[i];
        bool ok = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') ||
                  (ch >= 'A' && ch <= 'F');
        if (!ok)
            return false;
    }
    return true;
}

static void zc4_lower(char *s)
{
    for (; s && *s; s++)
        if (*s >= 'A' && *s <= 'F')
            *s = (char)(*s - 'A' + 'a');
}

/* Both leaves in this file are READY_READ, so neither opens node.db
 * itself: they go through zcl_native_node_db_{open,require}_readonly
 * (command/native_command.h). The helper this file used to carry called
 * node_db_open(), which is the boot ceremony — READWRITE|CREATE, then
 * create_schema + node_db_migrate + the snapshot_staging DELETEs — against
 * a caller-supplied datadir that defaults to the live node's. */

/* Build the rebuilt package index over <datadir>/zcode or fail the reply. */
static struct vcs_package_index *zc4_build_index(
    const char *datadir, struct zcl_command_reply *reply)
{
    char zcode_dir[4400];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(zcode_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return NULL;
    }
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INDEX_BUILD",
                               "execute", false, false,
                               "the package index could not be built",
                               zcode_dir);
    }
    return index;
}

static void zc4_push_binding(struct json_value *parent,
                             const struct zcode_pointer *pointer)
{
    struct json_value binding;
    json_init(&binding);
    json_set_object(&binding);
    (void)json_push_kv_bool(&binding, "bound", pointer->bound);
    (void)json_push_kv_str(&binding, "proof",
                           "znam-owner-equals-publisher-p2pkh");
    (void)json_push_kv_str(&binding, "owner_address",
                           pointer->owner_address);
    (void)json_push_kv_str(&binding, "expected_owner",
                           pointer->expected_owner);
    (void)json_push_kv(parent, "binding", &binding);
    json_free(&binding);
}

static void zc4_show_profile_fields(const struct vcs_zcode_contributor *profile,
                                    struct zcl_command_reply *reply)
{
    (void)json_push_kv_int(&reply->data, "release_count",
                           (int64_t)profile->release_count);
    (void)json_push_kv_int(&reply->data, "latest_sequence",
                           (int64_t)profile->latest_sequence);
    (void)json_push_kv_str(&reply->data, "latest_name",
                           profile->latest_name);
    (void)json_push_kv_str(&reply->data, "latest_semver",
                           profile->latest_semver);
    (void)json_push_kv_str(&reply->data, "latest_release_id",
                           profile->latest_release_id_hex);
    (void)json_push_kv_str(&reply->data, "latest_license",
                           profile->latest_license);
    (void)json_push_kv_str(&reply->data, "reward_address",
                           profile->reward_address);
    if (profile->has_znam_pointer)
        (void)json_push_kv_str(&reply->data, "release_znam_pointer",
                               profile->znam_pointer);
}

static void zc4_show_package_roots(struct vcs_package_index *index,
                                   const char *pubkey_hex,
                                   struct zcl_command_reply *reply)
{
    /* Package roots (authoritative, bounded page). */
    struct vcs_package_search search = { .publisher = pubkey_hex };
    const struct vcs_package_index_entry *roots[ZC4_SHOW_MAX_ROOTS];
    size_t total = vcs_package_index_search(index, &search, roots,
                                            ZC4_SHOW_MAX_ROOTS);
    size_t rendered = total < ZC4_SHOW_MAX_ROOTS
        ? total : ZC4_SHOW_MAX_ROOTS;
    struct json_value roots_arr;
    json_init(&roots_arr);
    json_set_array(&roots_arr);
    for (size_t i = 0; i < rendered; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "package_root",
                               roots[i]->package_root_hex);
        (void)json_push_kv_str(&row, "name", roots[i]->name);
        (void)json_push_kv_str(&row, "semver", roots[i]->semver);
        (void)json_push_back(&roots_arr, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "package_roots", &roots_arr);
    json_free(&roots_arr);
    (void)json_push_kv_bool(&reply->data, "package_roots_truncated",
                            total > rendered);
}

static void zc4_show_rewards_totals(
    const struct vcs_reward_contributor_totals *totals,
    struct zcl_command_reply *reply)
{
    struct json_value rw;
    json_init(&rw);
    json_set_object(&rw);
    (void)json_push_kv_int(&rw, "earned_score",
                           (int64_t)totals->earned_score);
    (void)json_push_kv_int(
        &rw, "token_rewards_received",
        (int64_t)totals->token_rewards_received);
    (void)json_push_kv_int(&rw, "settled_entries",
                           (int64_t)totals->settled_entries);
    (void)json_push_kv_int(&rw, "queued_entries",
                           (int64_t)totals->queued_entries);
    (void)json_push_kv_int(&rw, "queued_points",
                           (int64_t)totals->queued_points);
    (void)json_push_kv_int(&rw, "rejected_entries",
                           (int64_t)totals->rejected_entries);
    char token_hex[65];
    vcs_reward_placeholder_token_id_hex(token_hex);
    (void)json_push_kv_str(&rw, "placeholder_token_id",
                           token_hex);
    (void)json_push_kv_bool(&rw, "simulated", true);
    (void)json_push_kv_str(
        &rw, "note",
        "facts from the reward-history ledger: earned_score is "
        "settled score points (the ranking input); "
        "token_rewards_received is the SIMULATED "
        "placeholder-token tally — a separate fact, never a "
        "balance; queued_points are requested points awaiting "
        "settlement (caps apply at plan time)");
    (void)json_push_kv(&reply->data, "rewards", &rw);
    json_free(&rw);
}

/* One period of the overall rank table: a period with no window or no
 * projection contributes nothing to the periods object. */
static void zc4_rank_period_into(struct vcs_reward_ledger *ledger,
                                 enum vcs_rank_period period, int64_t today,
                                 uint8_t *pubkey_bytes,
                                 struct json_value *periods)
{
    struct vcs_rank_window window;
    if (!vcs_rank_window_for(period, today, &window))
        return;
    struct vcs_rank_projection *proj =
        vcs_rank_projection_build(ledger, &window);
    if (!proj)
        return;
    struct vcs_rank_entry entry;
    bool ranked = vcs_rank_contributor(
        proj, VCS_RANK_CATEGORY_OVERALL, pubkey_bytes,
        &entry);
    size_t total_ranked = vcs_rank_table(
        proj, VCS_RANK_CATEGORY_OVERALL, NULL, 0);
    struct json_value po;
    json_init(&po);
    json_set_object(&po);
    (void)json_push_kv_bool(&po, "ranked", ranked);
    if (ranked) {
        (void)json_push_kv_int(&po, "rank",
                               (int64_t)entry.rank);
        (void)json_push_kv_int(&po, "points",
                               (int64_t)entry.points);
    }
    (void)json_push_kv_int(&po, "total_ranked",
                           (int64_t)total_ranked);
    if (window.bounded) {
        (void)json_push_kv_int(&po, "first_day",
                               window.first_day);
        (void)json_push_kv_int(&po, "last_day",
                               window.last_day);
    }
    (void)json_push_kv(
        periods,
        vcs_rank_period_string(period), &po);
    json_free(&po);
    vcs_rank_projection_free(proj);
}

static void zc4_show_rankings(const struct zcl_command_request *request,
                              struct vcs_reward_ledger *ledger,
                              uint8_t *pubkey_bytes,
                              struct zcl_command_reply *reply)
{
    /* The slice-9 current-period ranks (overall category),
     * from the SAME rebuildable projection the zcode
     * leaderboard leaves serve — a pointer to the
     * contributor's leaderboard position, never a second
     * ranking truth. `day` (a civil day number) selects
     * "today"; the host clock only when omitted. */
    int64_t today = 0;
    const struct json_value *dv =
        json_get(request->input, "day");
    if (dv)
        today = json_get_int(dv);
    else
        today = vcs_rank_day_from_unix(
            platform_time_wall_unix());
    static const enum vcs_rank_period k_periods[4] = {
        VCS_RANK_PERIOD_DAILY, VCS_RANK_PERIOD_WEEKLY,
        VCS_RANK_PERIOD_MONTHLY, VCS_RANK_PERIOD_ALL_TIME,
    };
    struct json_value ranks;
    json_init(&ranks);
    json_set_object(&ranks);
    (void)json_push_kv_int(&ranks, "day", today);
    (void)json_push_kv_str(&ranks, "category", "overall");
    struct json_value periods;
    json_init(&periods);
    json_set_object(&periods);
    for (size_t pi = 0; pi < 4; pi++)
        zc4_rank_period_into(ledger, k_periods[pi], today,
                             pubkey_bytes, &periods);
    (void)json_push_kv(&ranks, "periods", &periods);
    json_free(&periods);
    (void)json_push_kv_str(
        &ranks, "note",
        "current-period leaderboard positions (overall, "
        "earned score only) from the same projection as "
        "zcode leaderboard daily|weekly|monthly|all — "
        "ranked:false means no settled points inside the "
        "period window");
    (void)json_push_kv(&reply->data, "rankings", &ranks);
    json_free(&ranks);
}

static void zc4_show_ledger_facts(const struct zcl_command_request *request,
                                  struct vcs_reward_ledger *ledger,
                                  const char *pubkey_hex,
                                  struct zcl_command_reply *reply)
{
    uint8_t pubkey_bytes[33];
    struct vcs_reward_contributor_totals totals;
    memset(&totals, 0, sizeof(totals));
    if (zcl_hex_decode(pubkey_hex, pubkey_bytes, 33))
        vcs_reward_contributor_totals(ledger, pubkey_bytes,
                                      &totals);
    zc4_show_rewards_totals(&totals, reply);
    zc4_show_rankings(request, ledger, pubkey_bytes, reply);
}

static void zc4_show_rewards_section(const struct zcl_command_request *request,
                                     const char *datadir,
                                     const char *pubkey_hex,
                                     struct zcl_command_reply *reply)
{
    char zcode_dir[4400];
    int zn = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (zn > 0 && (size_t)zn < sizeof(zcode_dir)) {
        struct vcs_reward_ledger *ledger =
            vcs_reward_ledger_load(zcode_dir);
        if (ledger) {
            zc4_show_ledger_facts(request, ledger, pubkey_hex, reply);
            vcs_reward_ledger_free(ledger);
        }
    }
}

static void zc4_show_znam_pointer_fields(const struct zcode_pointer *pointer,
                                         struct json_value *zp)
{
    (void)json_push_kv_str(zp, "name", pointer->name);
    if (pointer->display[0])
        (void)json_push_kv_str(zp, "display_name",
                               pointer->display);
    if (pointer->onion[0])
        (void)json_push_kv_str(zp, "onion", pointer->onion);
    if (pointer->profile_root_hex[0])
        (void)json_push_kv_str(zp, "profile_root",
                               pointer->profile_root_hex);
    if (pointer->index_root_hex[0])
        (void)json_push_kv_str(zp, "package_index_root",
                               pointer->index_root_hex);
    if (pointer->reward_address[0])
        (void)json_push_kv_str(zp, "reward_address",
                               pointer->reward_address);
    zc4_push_binding(zp, pointer);
}

static void zc4_show_znam_unread(enum zcl_node_db_ro_status zst,
                                 struct zcl_command_reply *reply)
{
    struct json_value zp;
    json_init(&zp);
    json_set_object(&zp);
    (void)json_push_kv_bool(&zp, "read", false);
    (void)json_push_kv_str(
        &zp, "reason",
        zst == ZCL_NODE_DB_RO_ABSENT
            ? "no node.db at this datadir — the ZNAM pointer was NOT "
              "looked up; this is not the same as 'no claimants'"
            : "node.db could not be opened read-only — the ZNAM pointer "
              "was NOT looked up; this is not the same as 'no claimants'");
    (void)json_push_kv(&reply->data, "znam_profile", &zp);
    json_free(&zp);
}

static void zc4_show_znam_read(const char *pubkey_hex, struct node_db *ndb,
                               struct zcl_command_reply *reply)
{
    struct zcode_pointer pointer;
    size_t claimants =
        zcode_pointer_find_publisher_profiles(ndb, pubkey_hex,
                                              &pointer);
    struct json_value zp;
    json_init(&zp);
    json_set_object(&zp);
    (void)json_push_kv_bool(&zp, "read", true);
    (void)json_push_kv_bool(&zp, "found", claimants > 0);
    (void)json_push_kv_int(&zp, "claimant_names",
                           (int64_t)claimants);
    if (claimants > 0)
        zc4_show_znam_pointer_fields(&pointer, &zp);
    (void)json_push_kv_str(&zp, "note",
                           "a ZNAM record is a mutable pointer; the "
                           "publisher key and the signed releases are "
                           "the identity");
    (void)json_push_kv(&reply->data, "znam_profile", &zp);
    json_free(&zp);
}

static void zc4_show_znam_profile(const char *datadir, const char *pubkey_hex,
                                  struct zcl_command_reply *reply)
{
    sqlite3 *zdb = NULL;
    struct node_db ndb;
    char zpath[1200];
    enum zcl_node_db_ro_status zst = zcl_native_node_db_open_readonly(
        datadir, &zdb, &ndb, zpath, sizeof(zpath));
    if (zst != ZCL_NODE_DB_RO_OK) {
        zc4_show_znam_unread(zst, reply);
        return;
    }
    zc4_show_znam_read(pubkey_hex, &ndb, reply);
    zcl_native_node_db_close_readonly(&zdb, &ndb);
}

static bool zc4_resolve_registered_pointer(const char *datadir,
                                           const char *name,
                                           struct zcl_command_reply *reply,
                                           struct zcode_pointer *pointer)
{
    sqlite3 *db = NULL;
    struct node_db ndb;
    if (!zcl_native_node_db_require_readonly(datadir, reply,
                                             "the ZNAM registry", &db, &ndb))
        return false;
    bool registered = zcode_pointer_resolve(&ndb, name, pointer);
    zcl_native_node_db_close_readonly(&db, &ndb);
    if (!registered) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_NAME",
                               "execute", false, false,
                               "no ZNAM name registered under this name",
                               name);
        return false;
    }
    return true;
}

static bool zc4_check_package_pointer(const char *name,
                                      const struct zcode_pointer *pointer,
                                      struct zcl_command_reply *reply)
{
    if (pointer->kind == ZCODE_POINTER_NONE) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "NOT_A_ZCODE_POINTER", "execute", false,
                               false,
                               "the name carries no zcode:kind record",
                               name);
        return false;
    }
    if (pointer->kind != ZCODE_POINTER_PACKAGE) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "WRONG_POINTER_KIND", "execute", false,
                               false,
                               "the name is a publisher profile, not a "
                               "package pointer", name);
        return false;
    }
    if (!pointer->bound) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "POINTER_NOT_BOUND", "execute", false, false,
                               "the pointer is not bound: the name's owner "
                               "is not the claimed publisher key",
                               name);
        return false;
    }
    return true;
}

static void zc4_resolve_pointer_json(const struct zcode_pointer *pointer,
                                     struct zcl_command_reply *reply)
{
    (void)json_push_kv_str(&reply->data, "name", pointer->name);
    struct json_value zp;
    json_init(&zp);
    json_set_object(&zp);
    (void)json_push_kv_str(&zp, "kind", "package");
    (void)json_push_kv_str(&zp, "claimed_package_root",
                           pointer->package_root_hex);
    (void)json_push_kv_str(&zp, "claimed_publisher",
                           pointer->publisher_hex);
    if (pointer->description[0])
        (void)json_push_kv_str(&zp, "description", pointer->description);
    if (pointer->onion[0])
        (void)json_push_kv_str(&zp, "onion", pointer->onion);
    if (pointer->protocol[0])
        (void)json_push_kv_str(&zp, "protocol", pointer->protocol);
    zc4_push_binding(&zp, pointer);
    (void)json_push_kv_str(&zp, "source", "znam-record");
    (void)json_push_kv(&reply->data, "pointer", &zp);
    json_free(&zp);
}

static void zc4_resolve_identity_json(
    const struct vcs_package_index_entry *identity,
    const struct zcode_pointer *pointer,
    struct zcl_command_reply *reply)
{
    struct json_value zi;
    json_init(&zi);
    json_set_object(&zi);
    (void)json_push_kv_str(&zi, "source", "signed-release");
    (void)json_push_kv_str(&zi, "release_id", identity->release_id_hex);
    (void)json_push_kv_str(&zi, "package_root",
                           identity->package_root_hex);
    (void)json_push_kv_str(&zi, "publisher", identity->publisher_hex);
    (void)json_push_kv_str(&zi, "name", identity->name);
    (void)json_push_kv_str(&zi, "semver", identity->semver);
    (void)json_push_kv_str(&zi, "license", identity->license);
    (void)json_push_kv_int(&zi, "publisher_sequence",
                           (int64_t)identity->publisher_sequence);
    (void)json_push_kv_bool(&zi, "manifest_present",
                            identity->manifest_present);
    (void)json_push_kv_bool(
        &zi, "matches_pointer_root",
        strcmp(identity->package_root_hex, pointer->package_root_hex) == 0);
    (void)json_push_kv_bool(
        &zi, "matches_pointer_publisher",
        strcmp(identity->publisher_hex, pointer->publisher_hex) == 0);
    (void)json_push_kv(&reply->data, "identity", &zi);
    json_free(&zi);
}

/* ── zcode contributor show ─────────────────────────────────────────── */

void zcl_native_handle_zcode_contributor_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc4_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.contributor.show");
        return;
    }
    const char *pubkey = zc4_input_str(request->input, "pubkey");
    if (!zc4_pubkey_hex_valid(pubkey)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PUBKEY",
                               "normalize", false, false,
                               "pubkey must be 66-hex compressed secp256k1",
                               pubkey ? pubkey : "");
        return;
    }
    char pubkey_hex[67];
    snprintf(pubkey_hex, sizeof(pubkey_hex), "%s", pubkey);
    zc4_lower(pubkey_hex);
    chain_params_select(CHAIN_MAIN);

    struct vcs_package_index *index = zc4_build_index(datadir, reply);
    if (!index)
        return;
    struct vcs_zcode_contributor profile;
    bool published = vcs_zcode_contributor_from_index(index, pubkey_hex,
                                                      &profile);

    (void)json_push_kv_str(&reply->data, "publisher", pubkey_hex);
    (void)json_push_kv_str(&reply->data, "identity",
                           "secp256k1-publisher-key");
    (void)json_push_kv_bool(&reply->data, "has_published", published);
    if (published) {
        zc4_show_profile_fields(&profile, reply);
        zc4_show_package_roots(index, pubkey_hex, reply);
    }

    /* The slice-8 reward ledger facts (replayed from the durable wires
     * under <datadir>/zcode/rewards). earned_score and
     * token_rewards_received are SEPARATE facts by owner directive — the
     * ranking input and the simulated placeholder-token tally; neither is
     * a balance (balances arrive with the real token in slice 14, and
     * rankings must never use them). Emitted always, zeros included, so
     * the schema is stable whether or not the key has published here. */
    zc4_show_rewards_section(request, datadir, pubkey_hex, reply);

    /* The ZNAM publisher-profile pointer (a pointer, never identity).
     * READ leaf: the chain is opened strictly read-only. The chain read is
     * OPTIONAL here — the package index and reward ledger above are the
     * leaf's real payload — so a missing node.db degrades this one section
     * rather than failing the leaf. It therefore MUST say so: "read":false
     * plus a reason, never a silent absence that reads identically to
     * "nobody claims this key". */
    zc4_show_znam_profile(datadir, pubkey_hex, reply);
    vcs_package_index_free(index);
}

/* ── zcode contributor packages ─────────────────────────────────────── */

void zcl_native_handle_zcode_contributor_packages(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc4_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.contributor.packages");
        return;
    }
    const char *pubkey = zc4_input_str(request->input, "pubkey");
    if (!zc4_pubkey_hex_valid(pubkey)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PUBKEY",
                               "normalize", false, false,
                               "pubkey must be 66-hex compressed secp256k1",
                               pubkey ? pubkey : "");
        return;
    }
    char pubkey_hex[67];
    snprintf(pubkey_hex, sizeof(pubkey_hex), "%s", pubkey);
    zc4_lower(pubkey_hex);

    struct vcs_package_index *index = zc4_build_index(datadir, reply);
    if (!index)
        return;
    struct vcs_package_search search = { .publisher = pubkey_hex };
    const struct vcs_package_index_entry *rows[ZC4_SEARCH_MAX_ROWS];
    size_t total = vcs_package_index_search(index, &search, rows,
                                            ZC4_SEARCH_MAX_ROWS);
    size_t rendered =
        total < ZC4_SEARCH_MAX_ROWS ? total : ZC4_SEARCH_MAX_ROWS;
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < rendered; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "name", rows[i]->name);
        (void)json_push_kv_str(&row, "semver", rows[i]->semver);
        (void)json_push_kv_str(&row, "license", rows[i]->license);
        (void)json_push_kv_int(&row, "publisher_sequence",
                               (int64_t)rows[i]->publisher_sequence);
        (void)json_push_kv_str(&row, "release_id",
                               rows[i]->release_id_hex);
        (void)json_push_kv_str(&row, "package_root",
                               rows[i]->package_root_hex);
        (void)json_push_kv_int(&row, "bytes",
                               (int64_t)rows[i]->total_bytes);
        (void)json_push_back(&arr, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "packages", &arr);
    json_free(&arr);
    (void)json_push_kv_str(&reply->data, "publisher", pubkey_hex);
    (void)json_push_kv_int(&reply->data, "total_matches", (int64_t)total);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_bool(&reply->data, "items_truncated",
                            total > rendered);
    vcs_package_index_free(index);
}

/* ── zcode package resolve ──────────────────────────────────────────── */

void zcl_native_handle_zcode_package_resolve(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc4_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.package.resolve");
        return;
    }
    const char *name = zc4_input_str(request->input, "name");
    if (!name || !name[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_NAME",
                               "normalize", false, false,
                               "no ZNAM name given",
                               "zcode.package.resolve");
        return;
    }
    chain_params_select(CHAIN_MAIN);

    /* READ leaf: strictly read-only, and REQUIRED — the whole answer is the
     * on-chain pointer, so an unreadable node.db must fail loudly rather
     * than fall through to UNKNOWN_NAME, which would say "no such name"
     * when the truth is "I could not look". */
    struct zcode_pointer pointer;
    if (!zc4_resolve_registered_pointer(datadir, name, reply, &pointer))
        return;
    if (!zc4_check_package_pointer(name, &pointer, reply))
        return;

    /* The pointer resolved; now the identity lookup — ALWAYS from the
     * signed release, never from the ZNAM record. */
    uint8_t root[32];
    bool have_root = zcl_hex_decode(pointer.package_root_hex, root, 32);
    if (!have_root) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_POINTER_ROOT",
                               "execute", false, false,
                               "the pointer's CONTENT target is not a "
                               "64-hex package root",
                               pointer.package_root_hex);
        return;
    }
    struct vcs_package_index *index = zc4_build_index(datadir, reply);
    if (!index)
        return;
    const struct vcs_package_index_entry *identity =
        vcs_package_index_find_root(index, root);
    if (!identity) {
        vcs_package_index_free(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "RELEASE_NOT_HOSTED", "execute", false,
                               false,
                               "the pointer names a release root with no "
                               "signed release in the local store",
                               pointer.package_root_hex);
        return;
    }

    /* Output: pointer facts and identity facts in separate objects. */
    zc4_resolve_pointer_json(&pointer, reply);
    zc4_resolve_identity_json(identity, &pointer, reply);
    (void)json_push_kv_str(
        &reply->data, "identity_note",
        "the ZNAM record is a mutable pointer; the signed release and the "
        "package root are the identity — moving the pointer never changes "
        "an existing release");
    vcs_package_index_free(index);
}
