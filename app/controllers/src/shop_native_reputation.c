/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * `app shop reputation` — slice C of docs/work/SHOP_COMMAND.md: the
 * evidence readout for one ZCODE publisher, over records this node already
 * holds under <datadir>/zcode. READ-ONLY: nothing here writes, and the
 * collectors below are the same scans the package leaves already run
 * (publish replay, the reproduction scan, the attestation scan, the reward
 * ledger replay).
 *
 * THE DOCTRINE (owner-approved, non-negotiable): render only facts the
 * node can prove, with the evidence class and the counting window stated
 * on the row. Absent evidence is "no_record" — never a zero, never an
 * adjective. Concretely this means:
 *
 *   - releases/packages published: secp256k1-signed release envelopes,
 *     verified at publication, counted over the local store
 *   - reproductions: build receipts filed under <zcode>/receipts whose
 *     output sets are byte-identical across DISTINCT receipt ids — distinct
 *     build events; receipts carry no signer identity (vcs/package_reproduce.h),
 *     so nothing about WHO built them is established and the row says so
 *   - distinct signing identities: verifier pubkeys over attestations
 *     whose secp256k1 signature verifies at read time
 *   - days observed: the oldest release envelope's mtime in THIS node's
 *     store — a local observation record, unsigned, labeled as such
 *   - dependent packages: root-committed dependency declarations
 *     (zcode-package.json is a manifest member; the package root commits it)
 *   - simulated settlements: settled facts in the simulated reward ledger
 *     (placeholder token; ZC23 issuance stays simulation-only)
 *   - availability challenges: NO durable source exists (the chunk-challenge
 *     loop keeps pass/fail in per-download memory) — the row is rendered
 *     "unavailable" with the gap named, never fabricated
 *
 * Two doctrine-wanted classes have no datadir-local source and are gaps,
 * not fabrications: paid fulfillments (patronage settlement lives on the
 * scratch-workspace lane, tools/command/native_zcode_patronage_command.c)
 * and availability (above). The shop's seller identity is the publisher
 * key: releases are signed by it and the reward ledger settles to it, so
 * one 33-byte pubkey is the join key across every row.
 *
 * Bound in config/commands/store.def. Tests: lib/test/src/test_shop_reputation.c.
 * HOT_FORK executes only copied evidence facts and pure set/render helpers. */

#include "controllers/shop_native_handler.h"

#include "base/hex.h"
#include "command/native_command.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "platform/clock.h"
#include "services/shop_reputation_view_service.h"
#include "util/log_macros.h"
#include "util/safe_alloc.h"
#include "vcs/package_attest.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/package_publish.h"
#include "vcs/package_release.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_reward.h"

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define SHOP_REP_TAG "native.app.shop.reputation"

/* Scan caps. The store's own caps bind releases (4096); attestation and
 * verifier lists are bounded here so a read leaf stays a read leaf. */
#define SHOP_REP_MAX_PACKAGES VCS_PACKAGE_PUBLISH_MAX_RELEASES
#define SHOP_REP_MAX_ATTEST_SCAN 4096u
#define SHOP_REP_MAX_VERIFIERS 1024u

struct shop_rep_pair {          /* one (package, recipe) reproduction key */
    uint8_t package_root[32];
    uint8_t recipe_root[32];
};

/* ── small set helpers (bounded linear scans over 32-byte roots) ────── */
static bool rep_root_seen(const uint8_t (*set)[32], size_t count,
                          const uint8_t root[32])
{
    for (size_t i = 0; i < count; i++)
        if (memcmp(set[i], root, 32) == 0)
            return true;
    return false;
}

static bool rep_pair_seen(const struct shop_rep_pair *set, size_t count,
                          const uint8_t package_root[32],
                          const uint8_t recipe_root[32])
{
    for (size_t i = 0; i < count; i++)
        if (memcmp(set[i].package_root, package_root, 32) == 0 &&
            memcmp(set[i].recipe_root, recipe_root, 32) == 0)
            return true;
    return false;
}

/* ── publication + the local observation window ─────────────────────── */
static void rep_collect_publication(const char *zcode_dir,
                                    const uint8_t publisher[33],
                                    struct shop_reputation_view_input_v1 *ev,
                                    uint8_t (*subject_pkgs)[32],
                                    size_t *subject_pkg_count,
                                    struct shop_rep_pair *pairs,
                                    size_t *pair_count,
                                    uint8_t (*all_pkgs)[32],
                                    size_t *all_pkg_count)
{
    struct vcs_package_release *releases = zcl_malloc(
        sizeof(*releases) * VCS_PACKAGE_PUBLISH_MAX_RELEASES,
        "shop_rep_releases");
    if (!releases)
        return;     /* logged inside zcl_malloc */
    size_t count = 0, skipped = 0;
    if (!vcs_package_publish_load_releases(
            zcode_dir, releases, VCS_PACKAGE_PUBLISH_MAX_RELEASES, &count,
            &skipped)) {
        free(releases);
        LOG_ERROR(SHOP_REP_TAG, "release load failed for %s", zcode_dir);
        return;
    }
    int64_t oldest = 0;
    for (size_t i = 0; i < count; i++) {
        const struct vcs_package_release *r = &releases[i];
        if (*all_pkg_count < SHOP_REP_MAX_PACKAGES &&
            !rep_root_seen(all_pkgs, *all_pkg_count, r->package_root))
            memcpy(all_pkgs[(*all_pkg_count)++], r->package_root, 32);
        if (memcmp(r->publisher_pubkey, publisher, 33) != 0)
            continue;
        ev->releases++;
        if (r->publisher_sequence > ev->max_publisher_sequence)
            ev->max_publisher_sequence = r->publisher_sequence;
        if (*subject_pkg_count < SHOP_REP_MAX_PACKAGES &&
            !rep_root_seen(subject_pkgs, *subject_pkg_count, r->package_root))
            memcpy(subject_pkgs[(*subject_pkg_count)++], r->package_root, 32);
        if (*pair_count < SHOP_REP_MAX_PACKAGES &&
            !rep_pair_seen(pairs, *pair_count, r->package_root,
                           r->recipe_root)) {
            memcpy(pairs[*pair_count].package_root, r->package_root, 32);
            memcpy(pairs[*pair_count].recipe_root, r->recipe_root, 32);
            (*pair_count)++;
        }
        /* The observation record: the envelope file's mtime in THIS store. */
        uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
        if (vcs_package_release_id(r, id) == VCS_PACKAGE_RELEASE_OK) {
            char id_hex[65];
            zcl_hex_encode(id, 32, id_hex);
            char path[4400];
            int n = snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir,
                             id_hex);
            struct stat st;
            if (n > 0 && (size_t)n < sizeof(path) && stat(path, &st) == 0 &&
                (oldest == 0 || st.st_mtime < oldest))
                oldest = st.st_mtime;
        }
    }
    free(releases);
    ev->packages = (uint32_t)*subject_pkg_count;
    if (oldest > 0) {
        ev->observed = true;
        ev->first_observed_unix = (int64_t)oldest;
    }
}

/* ── reproduction: the existing receipts-dir scan per (package, recipe) ─ */
static void rep_collect_reproduction(const char *zcode_dir,
                                     const struct shop_rep_pair *pairs,
                                     size_t pair_count,
                                     struct shop_reputation_view_input_v1 *ev)
{
    char dir[4400];
    int n = snprintf(dir, sizeof(dir), "%s/receipts", zcode_dir);
    if (n < 0 || (size_t)n >= sizeof(dir)) {
        LOG_ERROR(SHOP_REP_TAG, "receipts path too long: %s", zcode_dir);
        return;
    }
    for (size_t i = 0; i < pair_count; i++) {
        struct vcs_reproduce_report repro;
        if (!vcs_package_reproduce_scan(dir, pairs[i].package_root,
                                        pairs[i].recipe_root, &repro)) {
            LOG_ERROR(SHOP_REP_TAG, "receipts dir unreadable: %s", dir);
            return;
        }
        ev->matching_receipts += repro.matching;
        if (repro.reproduced)
            ev->reproduced_packages++;
    }
}

/* ── attestations: parse + verify, dedupe signer pubkeys ────────────── */
static void rep_collect_attestations(const char *zcode_dir,
                                     const uint8_t (*subject_pkgs)[32],
                                     size_t subject_pkg_count,
                                     struct shop_reputation_view_input_v1 *ev)
{
    char dir[4400];
    int n = snprintf(dir, sizeof(dir), "%s/attestations", zcode_dir);
    if (n < 0 || (size_t)n >= sizeof(dir)) {
        LOG_ERROR(SHOP_REP_TAG, "attestations path too long: %s", zcode_dir);
        return;
    }
    DIR *d = opendir(dir);
    if (!d)
        return;     /* no attestations filed: an empty class, not an error */
    uint8_t *wire = zcl_malloc(VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES,
                               "shop_rep_attest_wire");
    uint8_t (*verifiers)[33] = zcl_malloc(
        sizeof(*verifiers) * SHOP_REP_MAX_VERIFIERS, "shop_rep_verifiers");
    if (!wire || !verifiers) {
        free(wire);
        free(verifiers);
        closedir(d);
        return;
    }
    size_t verifier_count = 0;
    size_t scanned = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        uint8_t scratch[32];
        size_t scratch_len = 0;
        if (!zcl_hex_decode_n(de->d_name, scratch, 32, &scratch_len) ||
            scratch_len != 32)
            continue;
        if (scanned >= SHOP_REP_MAX_ATTEST_SCAN) {
            ev->attestations_truncated = true;
            break;
        }
        scanned++;
        char path[4400];
        n = snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(path))
            continue;
        FILE *f = fopen(path, "rb");
        if (!f)
            continue;
        size_t len = fread(wire, 1, VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES, f);
        bool trailing = !feof(f);
        fclose(f);
        if (trailing || len == 0)
            continue;
        struct vcs_package_attest a;
        /* Only a signature-verified attestation is evidence; an unparseable
         * or bad-signature file is ignored, never counted either way. */
        if (vcs_package_attest_parse(wire, len, &a) != VCS_PACKAGE_ATTEST_OK ||
            vcs_package_attest_verify(&a) != VCS_PACKAGE_ATTEST_OK)
            continue;
        if (!rep_root_seen(subject_pkgs, subject_pkg_count, a.package_root))
            continue;
        ev->valid_attestations++;
        bool seen = false;
        for (size_t v = 0; v < verifier_count && !seen; v++)
            seen = memcmp(verifiers[v], a.verifier_pubkey, 33) == 0;
        if (!seen && verifier_count < SHOP_REP_MAX_VERIFIERS)
            memcpy(verifiers[verifier_count++], a.verifier_pubkey, 33);
    }
    ev->distinct_verifiers = (uint32_t)verifier_count;
    free(verifiers);
    free(wire);
    closedir(d);
}

/* ── dependent packages: root-committed declarations, read locally ──── */

/* Read the zcode-package.json declaration member of one package from the
 * local CAS. Returns false when the bytes are not held locally (the member
 * chunks were never fetched) or the read fails — the caller counts that as
 * unavailable, never as "no dependencies". */
static bool rep_read_declaration(const char *zcode_dir,
                                 const uint8_t package_root[32],
                                 uint8_t *text, size_t *len_out)
{
    char root_hex[65];
    zcl_hex_encode(package_root, 32, root_hex);
    char path[4400];
    int n = snprintf(path, sizeof(path), "%s/manifests/%s", zcode_dir,
                     root_hex);
    if (n < 0 || (size_t)n >= sizeof(path))
        return false;   // raw-return-ok:path-too-long-reads-as-unavailable
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;   // raw-return-ok:absent-manifest-reads-as-unavailable
    uint8_t *wire = zcl_malloc(VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                               "shop_rep_manifest_wire");
    if (!wire) {
        fclose(f);
        return false;
    }
    size_t len = fread(wire, 1, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, f);
    bool trailing = !feof(f);
    fclose(f);
    bool ok = false;
    struct vcs_package_manifest manifest;
    if (!trailing && len > 0 &&
        vcs_package_manifest_parse(wire, len, &manifest)) {
        /* The package root commits the manifest: a persisted manifest whose
         * root no longer matches carries no committed declaration at all. */
        uint8_t mroot[32];
        if (!vcs_package_manifest_root(&manifest, mroot) ||
            memcmp(mroot, package_root, 32) != 0) {
            vcs_package_manifest_free(&manifest);
            free(wire);
            return false;
        }
        const struct vcs_package_file *meta = NULL;
        for (size_t i = 0; i < manifest.count; i++)
            if (strcmp(manifest.files[i].path, VCS_PACKAGE_DEPS_META_PATH) == 0)
                meta = &manifest.files[i];
        if (!meta) {
            *len_out = 0;   /* no declaration file: no dependencies */
            ok = true;
        } else if (meta->size <= VCS_PACKAGE_DEPS_META_MAX_BYTES &&
                   meta->chunk_count == 1) {
            char chunk_hex[65];
            zcl_hex_encode(meta->chunk_hashes, 32, chunk_hex);
            n = snprintf(path, sizeof(path), "%s/cas/sha3/%.2s/%s",
                         zcode_dir, chunk_hex, chunk_hex);
            FILE *cf = n > 0 && (size_t)n < sizeof(path) ? fopen(path, "rb")
                                                         : NULL;
            if (cf) {
                size_t got = fread(text, 1, (size_t)meta->size, cf);
                int extra = fgetc(cf);
                fclose(cf);
                /* The chunk hash binds the bytes to the manifest (and so to
                 * the package root): verify before trusting a declaration. */
                uint8_t chash[32];
                if (got == (size_t)meta->size && extra == EOF &&
                    vcs_package_chunk_hash(text, got, chash) &&
                    memcmp(chash, meta->chunk_hashes, 32) == 0) {
                    *len_out = got;
                    ok = true;
                }
            }
        }
        vcs_package_manifest_free(&manifest);
    }
    free(wire);
    return ok;
}

static void rep_collect_dependents(const char *zcode_dir,
                                   const uint8_t (*subject_pkgs)[32],
                                   size_t subject_pkg_count,
                                   const uint8_t (*all_pkgs)[32],
                                   size_t all_pkg_count,
                                   struct shop_reputation_view_input_v1 *ev)
{
    uint8_t *text = zcl_malloc(VCS_PACKAGE_DEPS_META_MAX_BYTES + 1u,
                               "shop_rep_deps_text");
    if (!text)
        return;
    for (size_t i = 0; i < all_pkg_count; i++) {
        if (rep_root_seen(subject_pkgs, subject_pkg_count, all_pkgs[i]))
            continue;   /* the subject's own packages are not "dependents" */
        size_t len = 0;
        if (!rep_read_declaration(zcode_dir, all_pkgs[i], text, &len)) {
            ev->declarations_unavailable++;
            continue;
        }
        ev->declarations_read++;
        struct vcs_package_deps deps;
        enum vcs_package_deps_error derr = vcs_package_deps_parse_meta(
            text, len, &deps, NULL, 0);
        if (derr != VCS_PACKAGE_DEPS_OK) {
            ev->declarations_read--;
            ev->declarations_unavailable++;
            continue;
        }
        for (size_t k = 0; k < deps.count; k++) {
            if (rep_root_seen(subject_pkgs, subject_pkg_count,
                              deps.items[k].root)) {
                ev->dependent_packages++;
                break;
            }
        }
    }
    free(text);
}

/* ── simulated settlements: the reward ledger's settled facts ───────── */
static void rep_collect_settlements(const char *zcode_dir,
                                    const uint8_t publisher[33],
                                    struct shop_reputation_view_input_v1 *ev)
{
    struct vcs_reward_ledger *ledger = vcs_reward_ledger_load(zcode_dir);
    if (!ledger)
        return;     /* allocation failure, already logged */
    struct vcs_reward_contributor_totals totals;
    vcs_reward_contributor_totals(ledger, publisher, &totals);
    ev->settled_entries = totals.settled_entries;
    vcs_reward_ledger_free(ledger);
}

/* ── rendering ──────────────────────────────────────────────────────── */
static bool reputation_view_frozen_kat(const void *opaque, char *why,
                                       size_t why_sz)
{
    const struct shop_reputation_view_service_v1 *service = opaque;
    struct shop_reputation_view_input_v1 input = {
        .store_present = true,
        .releases = 2,
        .packages = 1,
        .observed = true,
        .first_observed_unix = 86400,
        .days_observed = 2,
        .matching_receipts = 3,
        .reproduced_packages = 1,
        .valid_attestations = 4,
        .distinct_verifiers = 2,
        .dependent_packages = 1,
        .declarations_read = 3,
        .settled_entries = 1,
    };
    struct shop_reputation_view_result_v1 result;
    if (!service || !service->render || !service->render(&input, &result) ||
        result.row_count != SHOP_REPUTATION_VIEW_ROW_COUNT ||
        strcmp(result.rows[0].fact, "releases_published") != 0 ||
        !result.rows[0].has_value || result.rows[0].value != 2 ||
        strcmp(result.rows[2].fact, "days_observed") != 0 ||
        result.rows[2].value != 2 ||
        strcmp(result.rows[7].state, "unavailable") != 0 ||
        strcmp(result.rows[8].fact, "paid_fulfillments") != 0) {
        if (why && why_sz)
            (void)snprintf(why, why_sz,
                           "frozen marketplace evidence-row vector failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_reputation_view_contract = {
    .service_id = SHOP_REPUTATION_VIEW_SERVICE_ID,
    .source_tu = "app/services/src/shop_reputation_view_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct shop_reputation_view_service_v1),
    .abi_fingerprint = SHOP_REPUTATION_VIEW_ABI_FINGERPRINT,
    .schema_fingerprint = SHOP_REPUTATION_VIEW_SCHEMA_FINGERPRINT,
    .wire_fingerprint = SHOP_REPUTATION_VIEW_WIRE_FINGERPRINT,
    .kat_fingerprint = SHOP_REPUTATION_VIEW_KAT_FINGERPRINT,
    .frozen_kat = reputation_view_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_shop_reputation_view_service_contract(void)
{
    return &k_reputation_view_contract;
}

static void rep_row_json(struct json_value *rows,
                         const struct shop_reputation_view_row_v1 *view)
{
    struct json_value row;
    json_init(&row);
    json_set_object(&row);
    (void)json_push_kv_str(&row, "fact", view->fact);
    (void)json_push_kv_str(&row, "state", view->state);
    if (view->has_value)
        (void)json_push_kv_int(&row, "value", view->value);
    (void)json_push_kv_str(&row, "evidence_class", view->evidence_class);
    (void)json_push_kv_str(&row, "window", view->window);
    (void)json_push_kv_str(&row, "detail", view->detail);
    (void)json_push_back(rows, &row);
    json_free(&row);
}

static bool rep_render(struct json_value *data, const char *publisher_hex,
                       const char *datadir, int64_t now_unix,
                       const struct shop_reputation_view_input_v1 *ev)
{
    struct zcl_hotswap_service_lease lease = {0};
    const struct shop_reputation_view_service_v1 *service =
        zcl_hotswap_service_acquire(SHOP_REPUTATION_VIEW_SERVICE_ID, &lease);
    if (!service)
        service = shop_reputation_view_service_builtin();
    struct shop_reputation_view_result_v1 result;
    if (!service->render(ev, &result)) {
        zcl_hotswap_service_release(&lease);
        return false;
    }
    zcl_hotswap_service_release(&lease);

    (void)json_push_kv_str(data, "publisher", publisher_hex);
    (void)json_push_kv_str(data, "datadir", datadir);
    (void)json_push_kv_int(data, "now_unix", now_unix);
    (void)json_push_kv_bool(data, "zcode_store_present", ev->store_present);
    (void)json_push_kv_int(data, "view_service_generation",
                           zcl_hotswap_service_generation());
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < result.row_count; i++)
        rep_row_json(&rows, &result.rows[i]);
    (void)json_push_kv(data, "evidence", &rows);
    json_free(&rows);
    (void)json_push_kv_str(data, "doctrine", result.doctrine);
    return true;
}

/* ── the handler ────────────────────────────────────────────────────── */
void zcl_native_handle_shop_reputation(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = json_get_str(json_get(request->input, "datadir"));
    if (!datadir || !datadir[0])
        datadir = zcl_native_command_datadir();
    if (!datadir || !datadir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given and no --datadir default",
                               "datadir");
        return;
    }
    const char *publisher_hex =
        json_get_str(json_get(request->input, "publisher"));
    uint8_t publisher[33];
    if (!publisher_hex || strlen(publisher_hex) != 66 ||
        !zcl_hex_decode_lower(publisher_hex, publisher, 33)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_PUBLISHER_INPUT",
                               "validate", false, false,
                               "publisher must be the 66-hex compressed "
                               "secp256k1 pubkey the releases are signed "
                               "with (the publisher column of zcode package "
                               "search)", "publisher");
        return;
    }
    int64_t now_unix = clock_now_wall_ms() / 1000;
    const struct json_value *now = json_get(request->input, "now_unix");
    if (now) {
        if (now->type != JSON_INT || json_get_int(now) <= 0) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID, "BAD_NOW_UNIX",
                                   "validate", false, false,
                                   "now_unix must be a positive integer",
                                   "now_unix");
            return;
        }
        now_unix = json_get_int(now);
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

    struct shop_reputation_view_input_v1 ev;
    memset(&ev, 0, sizeof(ev));
    struct stat st;
    /* Absent and unreadable are not the same answer: a present
     * non-directory at the store path — or at any of the store's known
     * subdirectories — must refuse by name, never be reported as an
     * empty store (the read-leaf doctrine, asserted by
     * test_read_leaf_no_datadir_write's payload-store case, which breaks
     * zcode/manifests for this leaf). A fresh store has none of these
     * subdirectories yet, and that absence is the legitimate empty
     * answer. */
    static const char *const subdirs[] = {
        "", "releases", "manifests", "receipts", "attestations", "rewards"
    };
    for (size_t i = 0; i < sizeof(subdirs) / sizeof(subdirs[0]); i++) {
        char probe[4400];
        int pn = snprintf(probe, sizeof(probe), "%s%s%s", zcode_dir,
                          subdirs[i][0] ? "/" : "", subdirs[i]);
        if (pn < 0 || (size_t)pn >= sizeof(probe))
            continue;
        if (stat(probe, &st) == 0 && !S_ISDIR(st.st_mode)) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_BLOCKED,
                                   ZCL_COMMAND_EXIT_BLOCKED,
                                   "ZCODE_STORE_UNREADABLE", "execute",
                                   false, false,
                                   "a path inside <datadir>/zcode exists "
                                   "but is not a readable store directory "
                                   "— inspect it before trusting any "
                                   "'no_record' row", probe);
            return;
        }
    }
    ev.store_present = stat(zcode_dir, &st) == 0 && S_ISDIR(st.st_mode);

    uint8_t (*subject_pkgs)[32] = zcl_calloc(
        SHOP_REP_MAX_PACKAGES, sizeof(*subject_pkgs), "shop_rep_subject_pkgs");
    uint8_t (*all_pkgs)[32] = zcl_calloc(
        SHOP_REP_MAX_PACKAGES, sizeof(*all_pkgs), "shop_rep_all_pkgs");
    struct shop_rep_pair *pairs = zcl_calloc(
        SHOP_REP_MAX_PACKAGES, sizeof(*pairs), "shop_rep_pairs");
    if (!subject_pkgs || !all_pkgs || !pairs) {
        free(subject_pkgs);
        free(all_pkgs);
        free(pairs);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "evidence buffers", zcode_dir);
        return;
    }
    size_t subject_pkg_count = 0, all_pkg_count = 0, pair_count = 0;
    if (ev.store_present) {
        rep_collect_publication(zcode_dir, publisher, &ev, subject_pkgs,
                                &subject_pkg_count, pairs, &pair_count,
                                all_pkgs, &all_pkg_count);
        rep_collect_reproduction(zcode_dir, pairs, pair_count, &ev);
        rep_collect_attestations(zcode_dir, subject_pkgs, subject_pkg_count,
                                 &ev);
        rep_collect_dependents(zcode_dir, subject_pkgs, subject_pkg_count,
                               all_pkgs, all_pkg_count, &ev);
        rep_collect_settlements(zcode_dir, publisher, &ev);
    }
    free(pairs);
    free(all_pkgs);
    free(subject_pkgs);

    if (ev.observed && now_unix >= ev.first_observed_unix) {
        ev.days_observed = (now_unix - ev.first_observed_unix) / 86400;
    } else {
        ev.observed = false;
    }

    if (!rep_render(&reply->data, publisher_hex, datadir, now_unix, &ev))
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "REPUTATION_VIEW_FAILED", "render", false,
                               false,
                               "the pure marketplace evidence view refused "
                               "the caller-owned evidence snapshot",
                               "app.shop.reputation");
}

/* ── Hot-swappable leaves ──────────────────────────────────────────────────
 * Read-only REPUTATION projection over completed shop trades. Every mutating sibling in this file is
 * absent from the table; the loader refuses to re-point a leaf that is
 * missing from this file's row in config/hotswap_swappable.def. */
#if defined(ZCL_HOTSWAP_GEN) || defined(ZCL_HOTSWAP_MODULE_GEN)
#define ZCL_HOTSWAP_PROBE_LEAF "app.shop.reputation"
#include "hotswap/hotswap_register.h"
ZCL_HOTSWAP_LEAVES_BEGIN(shop_reputation)
ZCL_HOTSWAP_LEAF("app.shop.reputation", zcl_native_handle_shop_reputation)
ZCL_HOTSWAP_LEAVES_END(shop_reputation)
#endif
