/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the slice-11 `zcode seed` / `zcode storage` leaves —
 * the LOCAL P2P ratio + anti-spam policy surfaces:
 *
 *   zcode seed status     local serving facts per contributor key: verified
 *                         bytes up/down, the local ratio, the resolved tier,
 *                         and current allowances vs usage (publishes this
 *                         ISO week, downloads this week, offences)
 *   zcode seed ratio      the ratio + exactly how it is computed:
 *                         verified-only accounting, with the frozen list of
 *                         what NEVER earns credit stated explicitly
 *   zcode storage status  the store quota pools plus the policy view
 *                         (per-tier pin allowances against the live PINS
 *                         pool usage)
 *
 * THE FACTS ARE LOCAL (owner directive): the ratio is this node's own
 * verified_bytes_uploaded / max(verified_bytes_downloaded, 1) per
 * contributor key, replayed from the durable service book under
 * <datadir>/zcode/service on every call (never a second truth). There is
 * NO global ZCODE mint for bandwidth: earned score enters tier resolution
 * only as an input read from the slice-8 reward ledger, so a Sybil pair
 * uploading to each other with zero earned score stays at the new-user
 * tier. The free allowance is absolute: a zero-score user can always
 * download public packages (the weekly allowance is a rate limit, never a
 * permanent denial). Every policy constant in the replies is the frozen
 * table from contexts/commons/modules/vcs/package_policy.*. */

#include "base/hex.h"
#include "command/native_command.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "vcs/package_policy.h"
#include "vcs/package_rank.h"
#include "vcs/package_reward.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

/* Render cap for per-key rows (the LIST budget). */
#define ZS_MAX_ROWS 32u

/* ── small input helpers (the native_zcode_* pattern) ───────────────── */

static const char *zs_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zs_datadir(const struct zcl_command_request *request)
{
    const char *dd = zs_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* Resolve the zcode dir from the request. False with the error body set
 * when no datadir exists or the path is too long. */
static bool zs_zcode_dir(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply,
                         const char *command, char out[4400])
{
    const char *datadir = zs_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               command);
        return false;
    }
    int n = snprintf(out, 4400, "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= 4400) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return false;
    }
    return true;
}

static int64_t zs_day(const struct zcl_command_request *request)
{
    const struct json_value *dv = json_get(request->input, "day");
    if (dv)
        return json_get_int(dv);
    return vcs_rank_day_from_unix(platform_time_wall_unix());
}

/* Parse the optional `pubkey` input. Returns 1 with out filled, 0 when
 * absent (no filter), -1 with the error body set on bad input. */
static int zs_pubkey(const struct zcl_command_request *request,
                     struct zcl_command_reply *reply, uint8_t out[33])
{
    const char *hex = zs_input_str(request->input, "pubkey");
    if (!hex || !hex[0])
        return 0;
    if (!zcl_hex_decode(hex, out, 33)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PUBKEY",
                               "normalize", false, false,
                               "pubkey must be 66 lowercase hex chars (a "
                               "compressed secp256k1 key)", hex);
        return -1;
    }
    return 1;
}

static void zs_push_limits(struct json_value *obj, enum vcs_policy_tier tier)
{
    const struct vcs_policy_limits *l = vcs_policy_limits_for(tier);
    (void)json_push_kv_int(obj, "publish_per_week",
                           (int64_t)l->publish_per_week);
    (void)json_push_kv_int(obj, "weekly_download_bytes",
                           (int64_t)l->weekly_download_bytes);
    (void)json_push_kv_int(obj, "max_concurrent_downloads",
                           (int64_t)l->max_concurrent_downloads);
    (void)json_push_kv_int(obj, "queue_priority",
                           (int64_t)l->queue_priority);
    (void)json_push_kv_int(obj, "pin_allowance_bytes",
                           (int64_t)l->pin_allowance_bytes);
    (void)json_push_kv_int(obj, "announces_per_hour",
                           (int64_t)l->announces_per_hour);
    (void)json_push_kv_int(obj, "request_burst_per_window",
                           (int64_t)l->request_burst_per_window);
}

/* The frozen policy table, stated explicitly in every seed reply. */
static void zs_push_policy_table(struct json_value *obj)
{
    struct json_value table;
    json_init(&table);
    json_set_object(&table);

    struct json_value thresholds;
    json_init(&thresholds);
    json_set_object(&thresholds);
    (void)json_push_kv_int(&thresholds, "earned_contributor_min_score",
                           (int64_t)VCS_POLICY_TIER_CONTRIBUTOR_MIN_SCORE);
    (void)json_push_kv_int(&thresholds, "verified_seeder_min_score",
                           (int64_t)VCS_POLICY_TIER_SEEDER_MIN_SCORE);
    (void)json_push_kv_int(&thresholds,
                           "verified_seeder_min_upload_bytes",
                           (int64_t)VCS_POLICY_TIER_SEEDER_MIN_UPLOAD_BYTES);
    (void)json_push_kv_int(&thresholds,
                           "verified_seeder_min_ratio_milli",
                           (int64_t)VCS_POLICY_TIER_SEEDER_MIN_RATIO_MILLI);
    (void)json_push_kv_int(&thresholds, "verifier_min_score",
                           (int64_t)VCS_POLICY_VERIFIER_MIN_SCORE);
    (void)json_push_kv_int(&thresholds, "offence_disconnect_threshold",
                           (int64_t)VCS_POLICY_OFFENCE_DISCONNECT_THRESHOLD);
    (void)json_push_kv(&table, "thresholds", &thresholds);
    json_free(&thresholds);

    struct json_value free_allowance;
    json_init(&free_allowance);
    json_set_object(&free_allowance);
    (void)json_push_kv_int(&free_allowance, "weekly_download_bytes",
                           (int64_t)VCS_POLICY_FREE_WEEKLY_DOWNLOAD_BYTES);
    (void)json_push_kv_int(&free_allowance, "publish_per_week",
                           (int64_t)VCS_POLICY_FREE_PUBLISH_PER_WEEK);
    (void)json_push_kv_str(
        &free_allowance, "note",
        "the free allowance is absolute: a zero-score new user can always "
        "download public packages; the weekly allowance is a per-window "
        "rate limit, never a permanent denial for lacking tokens");
    (void)json_push_kv(&table, "free_allowance", &free_allowance);
    json_free(&free_allowance);

    struct json_value tiers;
    json_init(&tiers);
    json_set_object(&tiers);
    for (size_t i = 0; i < VCS_POLICY_TIER_COUNT; i++) {
        enum vcs_policy_tier t = (enum vcs_policy_tier)i;
        struct json_value tier;
        json_init(&tier);
        json_set_object(&tier);
        zs_push_limits(&tier, t);
        (void)json_push_kv(&tiers, vcs_policy_tier_string(t), &tier);
        json_free(&tier);
    }
    (void)json_push_kv(&table, "tiers", &tiers);
    json_free(&tiers);

    (void)json_push_kv(obj, "policy_table", &table);
    json_free(&table);
}

/* The frozen never-earns-credit list, stated explicitly. */
static void zs_push_never_credit(struct json_value *obj)
{
    static const char *const reasons[VCS_POLICY_NO_CREDIT_COUNT] = {
        "package announcements are control traffic, not service",
        "bytes that failed SHA3 chunk verification earn nothing",
        "a repeated copy of the same request id earns nothing (replays "
        "are deduped; the replay is a named offence)",
        "bytes never requested earn nothing (unsolicited data)",
        "a chunk whose hash mismatches the manifest earns nothing",
        "incomplete staging data earns nothing (only complete, verified "
        "packages count)",
    };
    struct json_value list;
    json_init(&list);
    json_set_array(&list);
    for (size_t i = 0; i < VCS_POLICY_NO_CREDIT_COUNT; i++) {
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "kind",
                               vcs_policy_no_credit_string(
                                   (enum vcs_policy_no_credit)i));
        (void)json_push_kv_str(&row, "reason", reasons[i]);
        (void)json_push_back(&list, &row);
        json_free(&row);
    }
    (void)json_push_kv(obj, "never_earns_credit", &list);
    json_free(&list);
}

/* ── zcode seed status ──────────────────────────────────────────────── */

void zcl_native_handle_zcode_seed_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!zs_zcode_dir(request, reply, "zcode.seed.status", zcode_dir))
        return;
    uint8_t filter[33];
    int pf = zs_pubkey(request, reply, filter);
    if (pf < 0)
        return;
    int64_t day = zs_day(request);

    struct vcs_service_book *book = vcs_service_book_load(zcode_dir);
    struct vcs_reward_ledger *ledger = vcs_reward_ledger_load(zcode_dir);
    if (!book || !ledger) {
        vcs_service_book_free(book);
        vcs_reward_ledger_free(ledger);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "POLICY_LOAD",
                               "execute", false, false,
                               "the policy facts (service book / reward "
                               "ledger) could not be replayed", zcode_dir);
        return;
    }

    (void)json_push_kv_int(&reply->data, "day", day);
    (void)json_push_kv_int(&reply->data, "week_start",
                           vcs_policy_week_start(day));

    struct vcs_service_book_totals bt;
    vcs_service_book_totals(book, &bt);
    struct json_value bj;
    json_init(&bj);
    json_set_object(&bj);
    (void)json_push_kv_int(&bj, "keys",
                           (int64_t)vcs_service_book_key_count(book));
    (void)json_push_kv_int(&bj, "events",
                           (int64_t)vcs_service_book_event_count(book));
    (void)json_push_kv_int(&bj, "corrupt_wires",
                           (int64_t)vcs_service_book_corrupt_count(book));
    (void)json_push_kv_bool(&bj, "truncated",
                            vcs_service_book_truncated(book));
    (void)json_push_kv_int(&bj, "verified_bytes_uploaded",
                           (int64_t)bt.verified_bytes_uploaded);
    (void)json_push_kv_int(&bj, "verified_bytes_downloaded",
                           (int64_t)bt.verified_bytes_downloaded);
    (void)json_push_kv_int(&bj, "offence_total",
                           (int64_t)bt.offence_total);
    (void)json_push_kv_int(&bj, "no_credit_bytes",
                           (int64_t)bt.no_credit_bytes);
    (void)json_push_kv(&reply->data, "book", &bj);
    json_free(&bj);

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    size_t key_count = vcs_service_book_key_count(book);
    size_t rendered = 0;
    for (size_t i = 0; i < key_count && rendered < ZS_MAX_ROWS; i++) {
        uint8_t key[33];
        if (!vcs_service_book_key_at(book, i, key))
            continue;
        if (pf == 1 && memcmp(key, filter, 33) != 0)
            continue;
        struct vcs_reward_contributor_totals ct;
        vcs_reward_contributor_totals(ledger, key, &ct);
        struct vcs_service_key_totals kt;
        if (!vcs_service_key_totals(book, key, day, &kt))
            continue;
        char hex[67];
        zcl_hex_encode(key, 33, hex);
        enum vcs_policy_tier tier =
            vcs_policy_tier_for(ct.earned_score,
                                kt.verified_bytes_uploaded,
                                kt.verified_bytes_downloaded);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "pubkey", hex);
        (void)json_push_kv_int(&row, "verified_bytes_uploaded",
                               (int64_t)kt.verified_bytes_uploaded);
        (void)json_push_kv_int(&row, "verified_bytes_downloaded",
                               (int64_t)kt.verified_bytes_downloaded);
        (void)json_push_kv_int(&row, "ratio_milli",
                               (int64_t)kt.ratio_milli);
        (void)json_push_kv_int(&row, "earned_score",
                               (int64_t)ct.earned_score);
        (void)json_push_kv_str(&row, "tier",
                               vcs_policy_tier_string(tier));

        struct json_value usage;
        json_init(&usage);
        json_set_object(&usage);
        (void)json_push_kv_int(&usage, "publishes_this_week",
                               (int64_t)kt.publishes_this_week);
        (void)json_push_kv_int(&usage, "publish_events",
                               (int64_t)kt.publish_events);
        (void)json_push_kv_int(&usage, "downloaded_this_week",
                               (int64_t)kt.downloaded_this_week);
        (void)json_push_kv_int(&usage, "offence_total",
                               (int64_t)kt.offence_total);
        (void)json_push_kv(&row, "usage", &usage);
        json_free(&usage);

        struct json_value allowances;
        json_init(&allowances);
        json_set_object(&allowances);
        zs_push_limits(&allowances, tier);
        (void)json_push_kv(&row, "allowances", &allowances);
        json_free(&allowances);

        if (pf == 1) {
            struct json_value offs;
            json_init(&offs);
            json_set_object(&offs);
            for (size_t o = 0; o < VCS_POLICY_OFFENCE_COUNT; o++)
                (void)json_push_kv_int(
                    &offs, vcs_policy_offence_string(
                               (enum vcs_policy_offence)o),
                    (int64_t)kt.offences[o]);
            (void)json_push_kv(&row, "offences_by_kind", &offs);
            json_free(&offs);

            struct json_value ncs;
            json_init(&ncs);
            json_set_object(&ncs);
            for (size_t c = 0; c < VCS_POLICY_NO_CREDIT_COUNT; c++)
                (void)json_push_kv_int(
                    &ncs, vcs_policy_no_credit_string(
                              (enum vcs_policy_no_credit)c),
                    (int64_t)kt.no_credit_events[c]);
            (void)json_push_kv_int(&ncs, "bytes",
                                   (int64_t)kt.no_credit_bytes);
            (void)json_push_kv(&row, "no_credit_events_by_kind", &ncs);
            json_free(&ncs);
        }

        (void)json_push_back(&rows, &row);
        json_free(&row);
        rendered++;
    }
    (void)json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_bool(&reply->data, "rows_truncated",
                            pf == 0 && rendered < key_count);
    if (pf == 1)
        (void)json_push_kv_bool(&reply->data, "key_known", rendered > 0);

    zs_push_policy_table(&reply->data);
    zs_push_never_credit(&reply->data);
    (void)json_push_kv_str(
        &reply->data, "locality_note",
        "all facts are LOCAL to this node: the ratio is this node's own "
        "verified-bytes accounting per contributor key; there is no "
        "global ZCODE mint for bandwidth — earned score (the tier gate) "
        "comes only from the reward ledger, so a Sybil pair uploading to "
        "each other earns nothing");
    vcs_reward_ledger_free(ledger);
    vcs_service_book_free(book);
}

/* ── zcode seed ratio ───────────────────────────────────────────────── */

void zcl_native_handle_zcode_seed_ratio(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!zs_zcode_dir(request, reply, "zcode.seed.ratio", zcode_dir))
        return;
    uint8_t filter[33];
    int pf = zs_pubkey(request, reply, filter);
    if (pf < 0)
        return;

    struct vcs_service_book *book = vcs_service_book_load(zcode_dir);
    if (!book) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "POLICY_LOAD",
                               "execute", false, false,
                               "the service book could not be replayed",
                               zcode_dir);
        return;
    }

    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    size_t key_count = vcs_service_book_key_count(book);
    size_t rendered = 0;
    for (size_t i = 0; i < key_count && rendered < ZS_MAX_ROWS; i++) {
        uint8_t key[33];
        if (!vcs_service_book_key_at(book, i, key))
            continue;
        if (pf == 1 && memcmp(key, filter, 33) != 0)
            continue;
        struct vcs_service_key_totals kt;
        if (!vcs_service_key_totals(book, key, -1, &kt))
            continue;
        char hex[67];
        zcl_hex_encode(key, 33, hex);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "pubkey", hex);
        (void)json_push_kv_int(&row, "verified_bytes_uploaded",
                               (int64_t)kt.verified_bytes_uploaded);
        (void)json_push_kv_int(&row, "verified_bytes_downloaded",
                               (int64_t)kt.verified_bytes_downloaded);
        (void)json_push_kv_int(&row, "ratio_milli",
                               (int64_t)kt.ratio_milli);
        (void)json_push_kv_int(&row, "no_credit_bytes",
                               (int64_t)kt.no_credit_bytes);
        (void)json_push_back(&rows, &row);
        json_free(&row);
        rendered++;
    }
    (void)json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_bool(&reply->data, "rows_truncated",
                            pf == 0 && rendered < key_count);

    (void)json_push_kv_str(
        &reply->data, "computed_as",
        "ratio_milli = verified_bytes_uploaded * 1000 / "
        "max(verified_bytes_downloaded, 1) — integer arithmetic, "
        "deterministic; 1000 means a 1.0 ratio");
    (void)json_push_kv_bool(&reply->data, "verified_only", true);
    (void)json_push_kv_str(
        &reply->data, "verified_means",
        "the bytes were (a) requested under a distinct request id, (b) "
        "delivered, and (c) passed SHA3 chunk verification against the "
        "package manifest — anything else is in never_earns_credit");
    zs_push_never_credit(&reply->data);
    (void)json_push_kv_str(
        &reply->data, "locality_note",
        "the ratio is LOCAL per contributor key on this node's own "
        "accounting: there is no global ZCODE mint for bandwidth, so two "
        "Sybil nodes uploading to each other earn nothing — local ratio "
        "plus EARNED ZCODE Score (never token balance) sets service "
        "priority");
    vcs_service_book_free(book);
}

/* ── zcode storage status ───────────────────────────────────────────── */

void zcl_native_handle_zcode_storage_status(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zs_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.storage.status");
        return;
    }
    char zcode_dir[4400];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(zcode_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return;
    }

    uint64_t quota = vcs_package_store_quota_bytes();
    (void)json_push_kv_bool(&reply->data, "hosting_enabled",
                            vcs_package_store_hosting_enabled());
    (void)json_push_kv_int(&reply->data, "quota_bytes", (int64_t)quota);

    struct stat st;
    bool present = stat(zcode_dir, &st) == 0 && S_ISDIR(st.st_mode);
    (void)json_push_kv_bool(&reply->data, "store_present", present);

    static const struct {
        enum vcs_package_store_pool pool;
        unsigned tenths;
        const char *name;
    } pools[4] = {
        { VCS_PACKAGE_STORE_POOL_PINS, VCS_PACKAGE_STORE_PINS_TENTHS,
          "pins" },
        { VCS_PACKAGE_STORE_POOL_HOT, VCS_PACKAGE_STORE_HOT_TENTHS,
          "hot" },
        { VCS_PACKAGE_STORE_POOL_RARE, VCS_PACKAGE_STORE_RARE_TENTHS,
          "rare" },
        { VCS_PACKAGE_STORE_POOL_STAGING,
          VCS_PACKAGE_STORE_STAGING_TENTHS, "staging" },
    };

    uint64_t pins_used = 0;
    struct json_value pj;
    json_init(&pj);
    json_set_object(&pj);
    if (present) {
        /* Open (creating nothing new on an existing store; the open-time
         * recovery sweep is the standard store discipline) just to read
         * pool usage, then close. */
        struct vcs_package_store *store =
            vcs_package_store_open(datadir, quota);
        if (!store) {
            json_free(&pj);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "STORE_OPEN",
                                   "execute", false, false,
                                   "the package store failed to open",
                                   zcode_dir);
            return;
        }
        for (size_t i = 0; i < 4; i++) {
            uint64_t used =
                vcs_package_store_pool_usage(store, pools[i].pool);
            if (pools[i].pool == VCS_PACKAGE_STORE_POOL_PINS)
                pins_used = used;
            struct json_value pool;
            json_init(&pool);
            json_set_object(&pool);
            (void)json_push_kv_int(&pool, "budget_bytes",
                                   (int64_t)(quota * pools[i].tenths / 10u));
            (void)json_push_kv_int(&pool, "used_bytes", (int64_t)used);
            (void)json_push_kv(&pj, pools[i].name, &pool);
            json_free(&pool);
        }
        vcs_package_store_close(store);
    } else {
        for (size_t i = 0; i < 4; i++) {
            struct json_value pool;
            json_init(&pool);
            json_set_object(&pool);
            (void)json_push_kv_int(&pool, "budget_bytes",
                                   (int64_t)(quota * pools[i].tenths / 10u));
            (void)json_push_kv_int(&pool, "used_bytes", 0);
            (void)json_push_kv(&pj, pools[i].name, &pool);
            json_free(&pool);
        }
    }
    (void)json_push_kv(&reply->data, "pools", &pj);
    json_free(&pj);

    /* The policy view: contributor-requested pin allowances (per tier)
     * against the live PINS pool. The operator's own pins are a separate
     * store path and are never tier-gated. */
    uint64_t pins_budget = quota * VCS_PACKAGE_STORE_PINS_TENTHS / 10u;
    uint64_t pins_headroom =
        pins_used < pins_budget ? pins_budget - pins_used : 0;
    struct json_value view;
    json_init(&view);
    json_set_object(&view);
    (void)json_push_kv_int(&view, "pins_pool_used_bytes",
                           (int64_t)pins_used);
    (void)json_push_kv_int(&view, "pins_pool_budget_bytes",
                           (int64_t)pins_budget);
    (void)json_push_kv_int(&view, "pins_pool_headroom_bytes",
                           (int64_t)pins_headroom);
    struct json_value tiers;
    json_init(&tiers);
    json_set_object(&tiers);
    for (size_t i = 0; i < VCS_POLICY_TIER_COUNT; i++) {
        enum vcs_policy_tier t = (enum vcs_policy_tier)i;
        uint64_t allowance = vcs_policy_limits_for(t)->pin_allowance_bytes;
        struct json_value tier;
        json_init(&tier);
        json_set_object(&tier);
        (void)json_push_kv_int(&tier, "pin_allowance_bytes",
                               (int64_t)allowance);
        (void)json_push_kv_bool(&tier, "allowance_fits_pool",
                                allowance <= pins_headroom);
        (void)json_push_kv(&tiers, vcs_policy_tier_string(t), &tier);
        json_free(&tier);
    }
    (void)json_push_kv(&view, "tiers", &tiers);
    json_free(&tiers);
    (void)json_push_kv_str(
        &view, "note",
        "contributor-requested pins are tier-gated (vcs_policy_check_pin, "
        "rule pin-allowance-exceeded; new users have no pin allowance — "
        "pins are earned); the operator's own pins are never tier-gated; "
        "the PINS pool is never evicted");
    (void)json_push_kv(&reply->data, "policy_view", &view);
    json_free(&view);
}
