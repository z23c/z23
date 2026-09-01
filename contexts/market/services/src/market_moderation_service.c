/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Per-node community content moderation for the marketplace: the local
 * visibility profile, its per-datadir persistence, the local-only
 * review_state store, and the serving gate every surface that hands
 * content to another party asks. Ingest and storage are untouched and
 * nothing is ever deleted; consensus is never consulted (see header).
 *
 * The fallible operations here (profile save, set-active, review marks,
 * review counts) DO return struct zcl_result. The three exceptions are
 * the gates — may_serve_root, may_serve_offer_id, may_relay_root — and
 * they are bool on purpose, not by omission: for a gate, "an error
 * occurred" and "no" must be THE SAME ANSWER. Handing a caller a result
 * it could split into ok-but-false versus failed would invite exactly
 * the branch that re-opens a gate on an unreadable database, which is
 * the failure this whole module exists to prevent. */
// one-result-type-ok:gates-are-predicates-error-and-refusal-must-be-indistinguishable

#include "services/market_moderation_service.h"
#include "services/market_moderation_view_service.h"

#include "models/database.h"
#include "models/file_offer.h"
#include "base/log_macros.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/private_file.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

#define MM_TAG "market.moderation"
#define MM_POLICY_MAGIC "zcl.market.moderation.v1"
#define MM_POLICY_MAX_BYTES 4096

const char *market_moderation_profile_string(
    enum market_moderation_profile profile)
{
    switch (profile) {
    case MARKET_MODERATION_PROFILE_DEFAULT:
        return MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1;
    case MARKET_MODERATION_PROFILE_OPEN:
        return MARKET_MODERATION_PROFILE_OPEN_VIEW;
    default: return "unknown";
    }
}

int market_moderation_profile_from_string(const char *name)
{
    if (!name) return -1; // raw-return-ok:null-parse-input-is-a-sentinel-not-an-error
    if (strcmp(name, MARKET_MODERATION_PROFILE_GENERAL_AUDIENCE_V1) == 0)
        return MARKET_MODERATION_PROFILE_DEFAULT;
    if (strcmp(name, MARKET_MODERATION_PROFILE_OPEN_VIEW) == 0)
        return MARKET_MODERATION_PROFILE_OPEN;
    return -1; // raw-return-ok:unknown-profile-name-is-a-sentinel-caller-logs
}

const char *market_moderation_relay_rule_string(
    enum market_moderation_relay_rule rule)
{
    switch (rule) {
    case MARKET_MODERATION_RELAY_ALL:
        return MARKET_MODERATION_RELAY_ALL_V1;
    case MARKET_MODERATION_RELAY_REVIEWED_ONLY:
        return MARKET_MODERATION_RELAY_REVIEWED_ONLY_V1;
    default: return "unknown";
    }
}

int market_moderation_relay_rule_from_string(const char *name)
{
    if (!name) return -1; // raw-return-ok:null-parse-input-is-a-sentinel-not-an-error
    if (strcmp(name, MARKET_MODERATION_RELAY_ALL_V1) == 0)
        return MARKET_MODERATION_RELAY_ALL;
    if (strcmp(name, MARKET_MODERATION_RELAY_REVIEWED_ONLY_V1) == 0)
        return MARKET_MODERATION_RELAY_REVIEWED_ONLY;
    return -1; // raw-return-ok:unknown-relay-rule-name-is-a-sentinel-caller-logs
}

/* ── Per-datadir policy persistence ─────────────────────────────── */

static bool mm_policy_paths(const char *datadir, char directory[1400],
                            char path[1500], bool create_directories,
                            char *error, size_t error_capacity)
{
    if (error && error_capacity) error[0] = '\0';
    if (!datadir || !datadir[0]) {
        if (error && error_capacity)
            snprintf(error, error_capacity, "moderation datadir is missing");
        LOG_ERROR(MM_TAG, "policy path: datadir is missing");
        return false;
    }
    int n = snprintf(directory, 1400, "%s/market", datadir);
    if (n <= 0 || n >= 1400 ||
        (create_directories && !platform_directory_ensure(directory, 0700))) {
        if (error && error_capacity)
            snprintf(error, error_capacity,
                     "cannot create market policy directory");
        LOG_ERROR(MM_TAG, "policy path: cannot prepare %s/market: %s",
                  datadir, strerror(errno));
        return false;
    }
    n = snprintf(path, 1500, "%s/%s", datadir, MARKET_MODERATION_POLICY_FILE);
    if (n <= 0 || n >= 1500) {
        if (error && error_capacity)
            snprintf(error, error_capacity, "moderation policy path too long");
        LOG_ERROR(MM_TAG, "policy path: path too long under %s", datadir);
        return false;
    }
    return true;
}

/* The two legs' strict sides, applied together whenever the policy file
 * is PRESENT but cannot be read as a known pair. A file we cannot parse
 * is an operator statement we cannot hear, so no leg gets its permissive
 * value — in particular a corrupt file can never turn a deliberately
 * strict relay back into an open one. An ABSENT file is a different
 * state and is handled separately: never configured means the defaults. */
static enum market_moderation_profile mm_unreadable(
    enum market_moderation_relay_rule *relay_out)
{
    if (relay_out) *relay_out = MARKET_MODERATION_RELAY_REVIEWED_ONLY;
    return MARKET_MODERATION_PROFILE_DEFAULT;
}

enum market_moderation_profile market_moderation_profile_load(
    const char *datadir, enum market_moderation_relay_rule *relay_out,
    bool *ok_out, char *error, size_t error_capacity)
{
    if (ok_out) *ok_out = false;
    char directory[1400], path[1500];
    if (!mm_policy_paths(datadir, directory, path, false, error,
                         error_capacity))
        return mm_unreadable(relay_out);
    struct platform_positioned_file file;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open(&file, path)) {
        if (platform_private_path_absent(path)) {
            /* First boot / never configured: each leg's own default. */
            if (relay_out) *relay_out = MARKET_MODERATION_RELAY_ALL;
            if (ok_out) *ok_out = true;
            return MARKET_MODERATION_PROFILE_DEFAULT;
        }
        if (error && error_capacity)
            snprintf(error, error_capacity,
                     "cannot open moderation policy: %s", strerror(errno));
        LOG_ERROR(MM_TAG, "policy load: open %s failed: %s", path,
                  strerror(errno));
        return mm_unreadable(relay_out);
    }
    struct platform_positioned_file_snapshot before, after;
    char buf[MM_POLICY_MAX_BYTES + 1];
    int64_t got = -1;
    if (platform_positioned_file_snapshot(&file, &before) &&
        platform_positioned_file_is_private(&file) && before.size > 0 &&
        before.size <= MM_POLICY_MAX_BYTES &&
        platform_positioned_file_read(&file, buf, (size_t)before.size, 0) ==
            (int64_t)before.size &&
        platform_positioned_file_snapshot(&file, &after) &&
        before.size == after.size && before.volume == after.volume &&
        before.file_low == after.file_low &&
        before.file_high == after.file_high &&
        before.modified_seconds == after.modified_seconds &&
        before.modified_nanoseconds == after.modified_nanoseconds &&
        before.changed_seconds == after.changed_seconds &&
        before.changed_nanoseconds == after.changed_nanoseconds)
        got = (int64_t)before.size;
    platform_positioned_file_close(&file);
    if (got < 0) {
        if (error && error_capacity)
            snprintf(error, error_capacity,
                     "moderation policy size or mode is invalid");
        LOG_ERROR(MM_TAG, "policy load: %s size/mode/read invalid", path);
        return mm_unreadable(relay_out);
    }
    buf[(size_t)got] = '\0';
    /* Exact match against every legal document, both legs enumerated —
     * the file is a choice from a closed set, never a parsed grammar, so
     * a byte an operator added by hand is a rejection rather than a
     * partially-honoured policy. A pre-relay file (profile line only) is
     * still legal and means relay-all.v1: it was written before the relay
     * leg existed, so it never expressed strictness and must not be read
     * as having done so. */
    char expected[160];
    int profile = -1;
    int relay = MARKET_MODERATION_RELAY_ALL;
    for (int i = 0; profile < 0 && i < MARKET_MODERATION_PROFILE_COUNT; i++) {
        const char *profile_name = market_moderation_profile_string(
            (enum market_moderation_profile)i);
        snprintf(expected, sizeof(expected), "%s\nprofile=%s\n",
                 MM_POLICY_MAGIC, profile_name);
        if (strcmp(buf, expected) == 0) {
            profile = i;
            relay = MARKET_MODERATION_RELAY_ALL;
            break;
        }
        for (int r = 0; r < MARKET_MODERATION_RELAY_RULE_COUNT; r++) {
            snprintf(expected, sizeof(expected), "%s\nprofile=%s\nrelay=%s\n",
                     MM_POLICY_MAGIC, profile_name,
                     market_moderation_relay_rule_string(
                         (enum market_moderation_relay_rule)r));
            if (strcmp(buf, expected) == 0) {
                profile = i;
                relay = r;
                break;
            }
        }
    }
    if (profile < 0) {
        if (error && error_capacity)
            snprintf(error, error_capacity,
                     "moderation policy content is not a known profile");
        LOG_ERROR(MM_TAG, "policy load: %s content rejected", path);
        return mm_unreadable(relay_out);
    }
    if (relay_out) *relay_out = (enum market_moderation_relay_rule)relay;
    if (ok_out) *ok_out = true;
    return (enum market_moderation_profile)profile;
}

struct zcl_result market_moderation_profile_save(
    const char *datadir, enum market_moderation_profile profile,
    enum market_moderation_relay_rule relay_rule)
{
    if (!market_moderation_profile_valid(profile)) {
        LOG_ERROR(MM_TAG, "policy save: unknown profile %d", profile);
        return ZCL_ERR(-1, "unknown moderation profile %d", profile);
    }
    if (!market_moderation_relay_rule_valid(relay_rule)) {
        LOG_ERROR(MM_TAG, "policy save: unknown relay rule %d", relay_rule);
        return ZCL_ERR(-8, "unknown moderation relay rule %d", relay_rule);
    }
    char error[192];
    char directory[1400], path[1500];
    if (!mm_policy_paths(datadir, directory, path, true, error,
                         sizeof(error)))
        return ZCL_ERR(-2, "%s", error[0] ? error : "policy path failed");
    /* Always the full two-leg document: a saved file states both rules
     * explicitly, so a later reader never has to infer one leg from the
     * other or from the absence of a line. */
    char body[160];
    int body_len = snprintf(body, sizeof(body), "%s\nprofile=%s\nrelay=%s\n",
                            MM_POLICY_MAGIC,
                            market_moderation_profile_string(profile),
                            market_moderation_relay_rule_string(relay_rule));
    if (body_len <= 0 || (size_t)body_len >= sizeof(body)) {
        LOG_ERROR(MM_TAG, "policy save: encode failed");
        return ZCL_ERR(-3, "moderation policy encode failed");
    }
    static _Atomic unsigned long long g_temp_sequence = 0;
    unsigned long long sequence =
        atomic_fetch_add_explicit(&g_temp_sequence, 1, memory_order_relaxed);
    char temporary[1600];
    int n = snprintf(temporary, sizeof(temporary), "%s.tmp.%llu", path,
                     sequence);
    if (n <= 0 || (size_t)n >= sizeof(temporary)) {
        LOG_ERROR(MM_TAG, "policy save: temp path too long");
        return ZCL_ERR(-4, "moderation policy temp path too long");
    }
    struct platform_private_file staging;
    platform_private_file_init(&staging);
    bool created = platform_private_file_create(temporary, &staging);
    bool wrote = created && platform_private_file_write_at(
        &staging, body, (size_t)body_len, 0) &&
        platform_private_file_flush(&staging);
    if (!wrote) {
        if (created) (void)platform_private_file_retire(&staging, temporary);
        platform_private_file_close(&staging);
        LOG_ERROR(MM_TAG, "policy save: temp write failed for %s", path);
        return ZCL_ERR(-5, "moderation policy temp write failed for %s",
                       path);
    }
    if (!platform_private_file_replace(&staging, temporary, path)) {
        (void)platform_private_file_retire(&staging, temporary);
        platform_private_file_close(&staging);
        LOG_ERROR(MM_TAG, "policy save: rename to %s failed: %s", path,
                  strerror(errno));
        return ZCL_ERR(-6, "moderation policy rename failed: %s",
                       strerror(errno));
    }
    if (!platform_private_parent_flush(directory)) {
        LOG_ERROR(MM_TAG, "policy save: directory fsync failed");
        return ZCL_ERR(-7, "moderation policy directory fsync failed");
    }
    return ZCL_OK;
}

/* ── Node-process context ───────────────────────────────────────── */

static pthread_mutex_t g_mm_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct node_db *g_mm_ndb = NULL;
static char g_mm_datadir[1024] = "";
static _Atomic int g_mm_active_profile = MARKET_MODERATION_PROFILE_DEFAULT;
static _Atomic int g_mm_active_relay = MARKET_MODERATION_RELAY_ALL;

void market_moderation_set_context(struct node_db *ndb, const char *datadir)
{
    pthread_mutex_lock(&g_mm_mutex);
    g_mm_ndb = ndb;
    if (datadir) {
        snprintf(g_mm_datadir, sizeof(g_mm_datadir), "%s", datadir);
        char error[192] = {0};
        bool ok = false;
        enum market_moderation_relay_rule relay = MARKET_MODERATION_RELAY_ALL;
        enum market_moderation_profile profile =
            market_moderation_profile_load(datadir, &relay, &ok, error,
                                           sizeof(error));
        /* Both legs land on their strict side together when the file is
         * present but unreadable — the load decided that; boot only
         * reports it, loudly, naming both resulting rules so an operator
         * can see that a broken file narrowed relay rather than silently
         * re-opening it. */
        if (!ok)
            LOG_WARN(MM_TAG,
                     "moderation policy unreadable (%s); strict fallback in "
                     "force: profile=%s relay=%s",
                     error[0] ? error : "unknown",
                     market_moderation_profile_string(profile),
                     market_moderation_relay_rule_string(relay));
        atomic_store_explicit(&g_mm_active_profile, profile,
                              memory_order_release);
        atomic_store_explicit(&g_mm_active_relay, relay,
                              memory_order_release);
    }
    pthread_mutex_unlock(&g_mm_mutex);
}

bool market_moderation_store_ready(void)
{
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    bool ready = ndb && ndb->open;
    pthread_mutex_unlock(&g_mm_mutex);
    return ready;
}

enum market_moderation_profile market_moderation_active_profile(void)
{
    return (enum market_moderation_profile)atomic_load_explicit(
        &g_mm_active_profile, memory_order_acquire);
}

enum market_moderation_relay_rule market_moderation_active_relay_rule(void)
{
    return (enum market_moderation_relay_rule)atomic_load_explicit(
        &g_mm_active_relay, memory_order_acquire);
}

struct zcl_result market_moderation_set_active_profile(
    enum market_moderation_profile profile)
{
    if (!market_moderation_profile_valid(profile)) {
        LOG_ERROR(MM_TAG, "set active profile: unknown profile %d", profile);
        return ZCL_ERR(-1, "unknown moderation profile %d", profile);
    }
    pthread_mutex_lock(&g_mm_mutex);
    const char *datadir = g_mm_datadir[0] ? g_mm_datadir : NULL;
    /* Carry the other leg through untouched: setting the serve profile
     * must never move the relay rule, in either direction. */
    enum market_moderation_relay_rule relay =
        (enum market_moderation_relay_rule)atomic_load_explicit(
            &g_mm_active_relay, memory_order_acquire);
    if (datadir) {
        struct zcl_result saved =
            market_moderation_profile_save(datadir, profile, relay);
        if (!saved.ok) {
            pthread_mutex_unlock(&g_mm_mutex);
            LOG_ERROR(MM_TAG, "set active profile: save failed: %s",
                      saved.message);
            return saved;
        }
    }
    atomic_store_explicit(&g_mm_active_profile, profile,
                          memory_order_release);
    pthread_mutex_unlock(&g_mm_mutex);
    LOG_INFO(MM_TAG, "moderation profile set: %s (relay unchanged: %s)",
             market_moderation_profile_string(profile),
             market_moderation_relay_rule_string(relay));
    return ZCL_OK;
}

struct zcl_result market_moderation_set_active_relay_rule(
    enum market_moderation_relay_rule rule)
{
    if (!market_moderation_relay_rule_valid(rule)) {
        LOG_ERROR(MM_TAG, "set active relay rule: unknown rule %d", rule);
        return ZCL_ERR(-1, "unknown moderation relay rule %d", rule);
    }
    pthread_mutex_lock(&g_mm_mutex);
    const char *datadir = g_mm_datadir[0] ? g_mm_datadir : NULL;
    /* Mirror image of the profile setter: the serve leg rides through. */
    enum market_moderation_profile profile =
        (enum market_moderation_profile)atomic_load_explicit(
            &g_mm_active_profile, memory_order_acquire);
    if (datadir) {
        struct zcl_result saved =
            market_moderation_profile_save(datadir, profile, rule);
        if (!saved.ok) {
            pthread_mutex_unlock(&g_mm_mutex);
            LOG_ERROR(MM_TAG, "set active relay rule: save failed: %s",
                      saved.message);
            return saved;
        }
    }
    atomic_store_explicit(&g_mm_active_relay, rule, memory_order_release);
    pthread_mutex_unlock(&g_mm_mutex);
    LOG_INFO(MM_TAG, "moderation relay rule set: %s (profile unchanged: %s)",
             market_moderation_relay_rule_string(rule),
             market_moderation_profile_string(profile));
    return ZCL_OK;
}

/* ── Local-only review_state store ──────────────────────────────── */

int market_moderation_review_state_for_root(const uint8_t root_hash[32])
{
    if (!root_hash) return MARKET_REVIEW_UNREVIEWED;
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    pthread_mutex_unlock(&g_mm_mutex);
    if (!ndb || !ndb->open) return MARKET_REVIEW_UNREVIEWED;
    char text[16] = {0};
    if (!db_file_offer_get_review_state(ndb, root_hash, text, sizeof(text)))
        return MARKET_REVIEW_UNREVIEWED;
    int state = market_review_state_from_string(text);
    return state >= 0 ? state : MARKET_REVIEW_UNREVIEWED;
}

int market_moderation_review_state_for_offer_id(const uint8_t offer_id[32])
{
    if (!offer_id) return MARKET_REVIEW_UNREVIEWED; // raw-return-ok:absent-id-is-unreviewed-which-the-default-profile-hides
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    pthread_mutex_unlock(&g_mm_mutex);
    if (!ndb || !ndb->open) return MARKET_REVIEW_UNREVIEWED; // raw-return-ok:no-db-is-unreviewed-not-an-error
    struct file_offer offer;
    if (!db_file_offer_find_by_id(ndb, offer_id, &offer))
        return MARKET_REVIEW_UNREVIEWED; // raw-return-ok:unknown-offer-is-unreviewed
    return market_moderation_review_state_for_root(offer.root_hash);
}

/* ── The serving gate ───────────────────────────────────────────── */

/* The single decision both public entry points share. Every failure
 * path below answers false; there is no branch on which an error, an
 * absent dependency, or an out-of-range value yields "serve". */
static bool mm_may_serve_with_review(int review_state)
{
    int profile = (int)market_moderation_active_profile();
    if (!market_moderation_profile_valid(profile)) {
        LOG_ERROR(MM_TAG,
                  "serving gate: active profile %d is out of range — hiding",
                  profile);
        return false;
    }
    const struct market_moderation_view_service_v1 *view =
        market_moderation_view_service_builtin();
    if (!view || !view->decide) {
        LOG_ERROR(MM_TAG, "serving gate: view service unavailable — hiding");
        return false;
    }
    struct market_moderation_decision_result_v1 decision;
    if (!view->decide(profile, review_state, &decision)) {
        LOG_ERROR(MM_TAG, "serving gate: decide() refused — hiding");
        return false;
    }
    return decision.valid && decision.visible;
}

bool market_moderation_may_serve_root(const uint8_t root_hash[32])
{
    if (!root_hash) return false; // raw-return-ok:null-id-hides-fail-closed
    return mm_may_serve_with_review(
        market_moderation_review_state_for_root(root_hash));
}

bool market_moderation_may_serve_offer_id(const uint8_t offer_id[32])
{
    if (!offer_id) return false; // raw-return-ok:null-id-hides-fail-closed
    return mm_may_serve_with_review(
        market_moderation_review_state_for_offer_id(offer_id));
}

bool market_moderation_may_relay_root(const uint8_t root_hash[32])
{
    /* Malformed input, not a policy question: there is nothing to relay. */
    if (!root_hash) return false; // raw-return-ok:null-id-is-malformed-input
    int rule = (int)market_moderation_active_relay_rule();
    if (!market_moderation_relay_rule_valid(rule)) {
        /* Unreachable through the setters, which validate. If it ever
         * happens the value came from memory corruption, and the strict
         * side is the only safe reading of a rule we cannot name. */
        LOG_ERROR(MM_TAG,
                  "relay gate: active relay rule %d is out of range — "
                  "refusing to relay", rule);
        return false;
    }
    /* The default. Forwarding a pointer to somebody else's content is
     * not hosting it, and refusing by default would shrink an honest
     * seller's reach to whoever happens to have a reviewer awake. */
    if (rule == MARKET_MODERATION_RELAY_ALL)
        return true;
    /* The operator's explicit opt-in: same profile, same decide(), so
     * strict relay inherits every fail-closed property the serve leg
     * has, including an absent context and an unreadable review mark. */
    return mm_may_serve_with_review(
        market_moderation_review_state_for_root(root_hash));
}

struct zcl_result market_moderation_review_counts(
    int64_t counts[MARKET_REVIEW_STATE_COUNT])
{
    if (!counts) {
        LOG_ERROR(MM_TAG, "review counts: out is NULL");
        return ZCL_ERR(-1, "review counts: out is NULL");
    }
    counts[0] = counts[1] = counts[2] = 0;
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    pthread_mutex_unlock(&g_mm_mutex);
    if (!ndb || !ndb->open) {
        LOG_ERROR(MM_TAG, "review counts: node db unavailable");
        return ZCL_ERR(-2, "review counts: node db unavailable");
    }
    if (!db_file_offer_review_counts(ndb, counts)) {
        LOG_ERROR(MM_TAG, "review counts: query failed");
        return ZCL_ERR(-3, "review counts: query failed");
    }
    return ZCL_OK;
}

struct zcl_result market_moderation_set_review_state(
    const uint8_t offer_id[32], enum market_review_state state)
{
    if (!offer_id) {
        LOG_ERROR(MM_TAG, "set review state: offer_id is NULL");
        return ZCL_ERR(-1, "set review state: offer_id is NULL");
    }
    if (!market_review_state_valid(state)) {
        LOG_ERROR(MM_TAG, "set review state: invalid state %d", state);
        return ZCL_ERR(-2, "set review state: invalid state %d", state);
    }
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    pthread_mutex_unlock(&g_mm_mutex);
    if (!ndb || !ndb->open) {
        LOG_ERROR(MM_TAG, "set review state: node db unavailable");
        return ZCL_ERR(-3, "set review state: node db unavailable");
    }
    if (!db_file_offer_set_review_state(
            ndb, offer_id, market_review_state_string(state))) {
        LOG_ERROR(MM_TAG, "set review state: no signed offer matched");
        return ZCL_ERR(-4,
                       "set review state: no signed offer carries that id");
    }
    return ZCL_OK;
}

struct zcl_result market_moderation_compare_set_review_state(
    const uint8_t offer_id[32], enum market_review_state expected,
    enum market_review_state state)
{
    if (!offer_id) {
        LOG_ERROR(MM_TAG, "review CAS: offer_id is NULL");
        return ZCL_ERR(-1, "review CAS: offer_id is NULL");
    }
    if (!market_review_state_valid(expected) ||
        !market_review_state_valid(state)) {
        LOG_ERROR(MM_TAG, "review CAS: invalid expected=%d next=%d",
                  expected, state);
        return ZCL_ERR(-2, "review CAS: invalid expected or next state");
    }
    pthread_mutex_lock(&g_mm_mutex);
    struct node_db *ndb = g_mm_ndb;
    pthread_mutex_unlock(&g_mm_mutex);
    if (!ndb || !ndb->open) {
        LOG_ERROR(MM_TAG, "review CAS: node db unavailable");
        return ZCL_ERR(-3, "review CAS: node db unavailable");
    }

    enum db_file_offer_review_cas_result changed =
        db_file_offer_compare_set_review_state(
            ndb, offer_id, market_review_state_string(expected),
            market_review_state_string(state));
    if (changed == DB_FILE_OFFER_REVIEW_CAS_UPDATED)
        return ZCL_OK;
    if (changed == DB_FILE_OFFER_REVIEW_CAS_ERROR) {
        LOG_ERROR(MM_TAG, "review CAS: persistence failed");
        return ZCL_ERR(-6, "review CAS persistence failed");
    }

    /* Zero changed rows is authoritative for "expected no longer matches".
     * Preserve the existing unknown-offer diagnostic when possible; this
     * read is diagnostic only and cannot turn a failed CAS into success. */
    struct file_offer offer;
    if (!db_file_offer_find_by_id(ndb, offer_id, &offer)) {
        LOG_ERROR(MM_TAG, "review CAS: no signed offer matched");
        return ZCL_ERR(-4, "no signed offer carries that id");
    }
    LOG_WARN(MM_TAG, "review CAS stale: expected=%s next=%s",
             market_review_state_string(expected),
             market_review_state_string(state));
    return ZCL_ERR(MARKET_MODERATION_REVIEW_STALE,
                   "review mark no longer matches the planned state");
}

/* ── dumpstate dumper ───────────────────────────────────────────── */

bool market_moderation_dump_state_json(struct json_value *out,
                                       const char *key)
{
    if (!out)
        LOG_FAIL(MM_TAG, "dump state: out is NULL");
    (void)key;
    json_set_object(out);
    enum market_moderation_profile active =
        market_moderation_active_profile();
    json_push_kv_str(out, "active_profile",
                     market_moderation_profile_string(active));
    struct json_value profiles;
    json_init(&profiles);
    json_set_array(&profiles);
    for (int i = 0; i < MARKET_MODERATION_PROFILE_COUNT; i++) {
        struct json_value p;
        json_init(&p);
        json_set_str(&p, market_moderation_profile_string(
                             (enum market_moderation_profile)i));
        json_push_back(&profiles, &p);
        json_free(&p);
    }
    json_push_kv(out, "available_profiles", &profiles);
    /* The two legs, side by side and separately valued. Strict relay is
     * a name an operator can read here, never an absence they have to
     * infer from the serve rule. */
    json_push_kv_str(out, "serve_rule",
                     market_moderation_profile_string(active));
    json_push_kv_str(out, "relay_rule",
                     market_moderation_relay_rule_string(
                         market_moderation_active_relay_rule()));
    json_free(&profiles);

    pthread_mutex_lock(&g_mm_mutex);
    bool have_datadir = g_mm_datadir[0] != '\0';
    pthread_mutex_unlock(&g_mm_mutex);
    json_push_kv_bool(out, "datadir_bound", have_datadir);
    json_push_kv_str(out, "policy_file", MARKET_MODERATION_POLICY_FILE);

    int64_t counts[MARKET_REVIEW_STATE_COUNT] = {0, 0, 0};
    struct zcl_result counted = market_moderation_review_counts(counts);
    struct json_value by_state;
    json_init(&by_state);
    json_set_object(&by_state);
    for (int i = 0; i < MARKET_REVIEW_STATE_COUNT; i++)
        json_push_kv_int(&by_state,
                         market_review_state_string(
                             (enum market_review_state)i),
                         counted.ok ? counts[i] : 0);
    json_push_kv(out, "review_counts", &by_state);
    json_free(&by_state);
    json_push_kv_bool(out, "review_counts_live", counted.ok);
    /* See the same key on zmarket_moderation_status: the profile now also
     * gates what this node hands to another party, so reporting
     * view-filtering-only would understate its effect. */
    json_push_kv_bool(out, "view_filter_only", false);
    json_push_kv_bool(out, "serving_gated", true);
    json_push_kv_bool(out, "relay_gated",
                      market_moderation_active_relay_rule() ==
                          MARKET_MODERATION_RELAY_REVIEWED_ONLY);
    return true;
}
