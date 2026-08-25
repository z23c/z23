/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the registry-owned `zcode` tree (slice 3: package
 * publication and local search — LOCAL only: no P2P gossip, no reward
 * credit, no install/build/execution of published content).
 *
 *   zcode package publish plan    validate a candidate release + manifest +
 *                                 chunk source WITHOUT persisting; the reply
 *                                 names every failed rule or the plan token
 *   zcode package publish commit  re-validate, then persist manifest +
 *                                 recipe + chunks into the CAS store and the
 *                                 release into releases/ (idempotent: a
 *                                 redelivered release id reports "duplicate")
 *   zcode package search          bounded local search over the rebuildable
 *                                 package index projection
 *   zcode package library         complete tracked packages in the local
 *                                 store (the shelf this node can seed);
 *                                 each row carries the local reproduction
 *                                 evidence summary (the exact predicate the
 *                                 pointer publish gate applies), and the
 *                                 reply counts evaluated/reproduced rows;
 *                                 the JSON names one next_command (fetch
 *                                 by a listed local name/root, or how to
 *                                 fetch when the shelf is empty)
 *   zcode package show            one package's full release record +
 *                                 manifest summary
 *   zcode package recipe          the decoded, bounded declarative build
 *                                 recipe (slice 5) for one package root —
 *                                 display JSON from the canonical wire
 *   zcode package verify          external-verifier attestation quorum
 *                                 (slice 6) for one package root against
 *                                 the LOCAL approved-verifier allowlist —
 *                                 the node reads attestations, it never
 *                                 compiles or executes downloaded code
 *   zcode package attest import   files a signed third-party attestation
 *                                 wire into attestations/ (idempotent;
 *                                 filing is not acceptance — the quorum
 *                                 policy applies at verify time)
 *
 * Slice 11 adds the LOCAL publish-frequency policy checkpoint to commit:
 * a FRESH release (acceptance OK — a redelivery classifying DUPLICATE
 * skips the gate, so re-commit stays idempotent) is admitted only when
 * the publisher key's tier allowance for the current ISO week is not
 * exhausted (new user: 1 publication/week — the free allowance; the
 * tier resolves from the reward ledger's earned score plus the local
 * service book's verified-bytes ratio, lib/vcs/package_policy.*). A
 * denial names the exact rule (publish-frequency-limit); a successful
 * fresh publish records the publication event in the service book so the
 * next commit counts it. The optional `day` input pins the window for
 * deterministic tests; the host clock fills it when omitted.
 *
 * Publication requires a declarative build recipe whose root equals the
 * release envelope's recipe_root (slice 5): a missing or invalid recipe is
 * a named plan failure / commit rejection (recipe-*). The recipe is
 * declarative ONLY — nothing here compiles or executes downloaded code.
 *
 * Truth discipline: the CAS manifest/release bytes under <datadir>/zcode
 * are authoritative; the search index (lib/vcs/package_index.*) is a
 * rebuildable projection re-read from those bytes on every call, and
 * acceptance state is replayed from the persisted releases before any
 * classification, so a one-shot CLI process agrees with the node's own
 * store. No second package database exists.
 *
 * Commit opens a fresh store on the target datadir for the duration of the
 * command. The store's temp/fsync/atomic-rename discipline makes a crash
 * mid-commit resumable, never partially visible; running commit
 * CONCURRENTLY with a hosting node mid-put on the same datadir is an
 * operator-discipline boundary for v1 (the open-time recovery sweep is not
 * cross-process coordinated).
 *
 * Acceptance is node-bound (chain id, t1/t3 reward address), so plan and
 * commit select CHAIN_MAIN when nothing selected a chain — the same
 * one-shot-CLI precedent as core.sync.frontier.offline. */

#include "base/hex.h"
#include "command/native_command.h"

#include "kernel/command_registry.h"

#include "base/log_macros.h"
#include "base/safe_alloc.h"
#include "chain/chainparams.h"
#include "config/runtime.h"
#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "services/zcode_package_view_service.h"
#include "platform/time_compat.h"
#include "vcs/package_attest.h"
#include "vcs/package_attest_transport.h"
#include "vcs/package_index.h"
#include "vcs/package_policy.h"
#include "vcs/package_publish.h"
#include "vcs/package_rank.h"
#include "vcs/package_reproduce.h"
#include "vcs/package_reward.h"
#include "vcs/package_service.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_store.h"
#include "vcs/package_transport.h"
#include "vcs/package_verify_policy.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define ZC_LOG "zcode.command"

/* Render caps: search rows omit the long optional fields (show carries the
 * full record) so 16 rows stay inside the LIST budget even at maximum name
 * length; show renders at most 32 manifest files per page. The library
 * catalog matches the local-announce bound (VCS_SWARM_MAX_LOCAL_ANNOUNCES). */
#define ZC_SEARCH_MAX_ROWS 16u
#define ZC_SHOW_MAX_FILES 32u
#define ZC_LIBRARY_MAX_ROWS 64u

/* ── small input helpers ──────────────────────────────────────────── */

static const char *zc_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

/* Resolve the target datadir: explicit input.datadir wins, else the CLI's
 * --datadir. NULL when neither is set (core.node.bootstatus precedent). */
static const char *zc_datadir(const struct zcl_command_request *request)
{
    const char *dd = zc_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

/* ── candidate parsing + validation (shared by plan and commit) ────── */

struct zc_candidate {
    struct vcs_package_release release;
    bool release_parsed;
    struct vcs_package_manifest manifest;
    bool manifest_parsed;
    uint8_t *manifest_wire;
    size_t manifest_wire_len;
    struct vcs_package_recipe recipe;
    bool recipe_parsed;
    uint8_t *recipe_wire;
    size_t recipe_wire_len;
};

static void zc_candidate_free(struct zc_candidate *c)
{
    /* The manifest is init'd at the top of zc_validate and parse re-inits
     * on rejection, so this is always a balanced free. The recipe is
     * init'd likewise (recipe parse re-inits on rejection). */
    vcs_package_manifest_free(&c->manifest);
    vcs_package_recipe_free(&c->recipe);
    free(c->manifest_wire);
    free(c->recipe_wire);
    memset(c, 0, sizeof(*c));
}

/* Parse the release_hex and manifest_hex inputs and run every publication
 * rule (envelope, manifest, structure, license text, acceptance replay,
 * chunk verification when dir is given). The report collects every failed
 * rule. Returns false only on a hard error already reported via
 * reply_fail (missing/undecodable inputs, I/O failure); a true return can
 * still carry a non-empty failure list — that is the plan report. */
static bool zc_validate(const struct zcl_command_request *request,
                        struct zcl_command_reply *reply,
                        struct zc_candidate *cand,
                        struct vcs_package_publish_report *report,
                        const char *datadir, const char *dir,
                        size_t *replayed_out)
{
    memset(cand, 0, sizeof(*cand));
    vcs_package_manifest_init(&cand->manifest);
    vcs_package_recipe_init(&cand->recipe);

    const char *release_hex = zc_input_str(request->input, "release_hex");
    if (!release_hex || !release_hex[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_RELEASE",
                               "normalize", false, false,
                               "no release_hex given",
                               "zcode.package.publish");
        return false;
    }
    uint8_t *release_wire =
        zcl_malloc(VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES, "zc_release_wire");
    if (!release_wire) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "normalize", false, false,
                               "release wire buffer", "zcode.package.publish");
        return false;
    }
    size_t release_wire_len = 0;
    bool decoded = zcl_hex_decode_n(release_hex, release_wire,
                                 VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                                 &release_wire_len);
    enum vcs_package_release_error perr = VCS_PACKAGE_RELEASE_OK;
    if (decoded)
        perr = vcs_package_release_parse(release_wire, release_wire_len,
                                         &cand->release);
    free(release_wire);
    if (!decoded || perr != VCS_PACKAGE_RELEASE_OK) {
        vcs_package_publish_fail(
            report, VCS_PACKAGE_PUBLISH_RULE_RELEASE_PARSE,
            decoded ? vcs_package_release_error_string(perr)
                    : "release_hex is not bounded strict hex");
    } else {
        cand->release_parsed = true;
    }

    const char *manifest_hex = zc_input_str(request->input, "manifest_hex");
    if (!manifest_hex || !manifest_hex[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_MANIFEST",
                               "normalize", false, false,
                               "no manifest_hex given",
                               "zcode.package.publish");
        return false;
    }
    cand->manifest_wire =
        zcl_malloc(VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, "zc_manifest_wire");
    if (!cand->manifest_wire) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "normalize", false, false,
                               "manifest wire buffer",
                               "zcode.package.publish");
        return false;
    }
    if (!zcl_hex_decode_n(manifest_hex, cand->manifest_wire,
                       VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                       &cand->manifest_wire_len) ||
        !vcs_package_manifest_parse(cand->manifest_wire,
                                    cand->manifest_wire_len,
                                    &cand->manifest)) {
        vcs_package_publish_fail(
            report, VCS_PACKAGE_PUBLISH_RULE_MANIFEST_PARSE,
            "manifest wire violates the content.v2 grammar (paths, modes, "
            "counts, order, or the 1 MiB wire bound)");
    } else {
        cand->manifest_parsed = true;
    }

    /* The declarative build recipe (slice 5): REQUIRED. A missing recipe
     * is a plan failure rule (recipe-missing), never silently skipped. */
    const char *recipe_hex = zc_input_str(request->input, "recipe_hex");
    if (!recipe_hex || !recipe_hex[0]) {
        vcs_package_publish_fail(
            report, VCS_PACKAGE_PUBLISH_RULE_RECIPE_MISSING,
            "no recipe_hex given (the declarative build recipe is "
            "required; the node never compiles without one)");
    } else {
        cand->recipe_wire =
            zcl_malloc(VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES, "zc_recipe_wire");
        if (!cand->recipe_wire) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                                   "normalize", false, false,
                                   "recipe wire buffer",
                                   "zcode.package.publish");
            return false;
        }
        enum vcs_package_recipe_error rcerr = VCS_PACKAGE_RECIPE_OK;
        bool rc_decoded = zcl_hex_decode_n(recipe_hex, cand->recipe_wire,
                                        VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES,
                                        &cand->recipe_wire_len);
        if (rc_decoded)
            rcerr = vcs_package_recipe_parse(cand->recipe_wire,
                                             cand->recipe_wire_len,
                                             &cand->recipe);
        if (!rc_decoded || rcerr != VCS_PACKAGE_RECIPE_OK) {
            vcs_package_publish_fail(
                report, VCS_PACKAGE_PUBLISH_RULE_RECIPE_PARSE,
                rc_decoded ? vcs_package_recipe_error_string(rcerr)
                           : "recipe_hex is not bounded strict hex");
            free(cand->recipe_wire);
            cand->recipe_wire = NULL;
            cand->recipe_wire_len = 0;
        } else {
            cand->recipe_parsed = true;
        }
    }

    if (!cand->release_parsed || !cand->manifest_parsed)
        return true; /* the report already names the failed rules */

    vcs_package_publish_validate(&cand->release, &cand->manifest, report);
    if (cand->recipe_parsed)
        vcs_package_publish_validate_recipe(&cand->release, &cand->manifest,
                                            &cand->recipe, report);
    if (!report->release_ok || !report->manifest_ok)
        return true;

    /* Acceptance (rule 7): replay the persisted releases, then classify.
     * A one-shot CLI selects its argv chain here.  A handler running inside
     * the live node must retain that node's already-selected chain instead
     * of replacing regtest/testnet with the CLI's default mainnet value. */
    struct node_db *runtime_db = app_runtime_node_db();
    if (!runtime_db || !app_runtime_node_db_handle_open(runtime_db))
        chain_params_select(zcl_native_command_network());
    char zcode_dir[4400];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(zcode_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return false;
    }
    struct vcs_package_accept *accept = vcs_package_accept_new();
    if (!accept) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "validate", false, false,
                               "acceptance context", "zcode.package.publish");
        return false;
    }
    size_t replayed = 0;
    if (!vcs_package_publish_replay(zcode_dir, accept, &replayed)) {
        vcs_package_accept_free(accept);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "REPLAY_IO",
                               "validate", false, false,
                               "persisted releases could not be replayed",
                               zcode_dir);
        return false;
    }
    report->accept = vcs_package_accept(accept, &cand->release);
    vcs_package_accept_free(accept);
    if (replayed_out)
        *replayed_out = replayed;
    if (report->accept != VCS_PACKAGE_ACCEPT_OK &&
        report->accept != VCS_PACKAGE_ACCEPT_DUPLICATE) {
        vcs_package_publish_fail(
            report, VCS_PACKAGE_PUBLISH_RULE_ACCEPT,
            vcs_package_accept_result_string(report->accept));
        return true; /* acceptance failure: chunk checks are moot */
    }

    /* Chunks (rule 8): only when a source directory is given. */
    if (dir && dir[0])
        vcs_package_publish_verify_chunks(&cand->manifest, dir, report);
    return true;
}

/* ── reply projection ───────────────────────────────────────────────── */

static void zc_failures_json(struct json_value *out,
                             const struct vcs_package_publish_report *report)
{
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < report->failure_count; i++) {
        struct json_value f;
        json_init(&f);
        json_set_object(&f);
        (void)json_push_kv_str(
            &f, "rule",
            vcs_package_publish_rule_string(report->failures[i].rule));
        (void)json_push_kv_str(&f, "detail", report->failures[i].detail);
        (void)json_push_back(&arr, &f);
        json_free(&f);
    }
    (void)json_push_kv(out, "failures", &arr);
    json_free(&arr);
    (void)json_push_kv_bool(out, "failures_truncated",
                            report->failures_truncated);
}

static void zc_summary_json(struct json_value *out,
                            const struct zc_candidate *cand,
                            const struct vcs_package_publish_report *report,
                            bool chunks_checked, size_t replayed)
{
    char hex[65];
    if (report->release_ok) {
        struct json_value rel;
        json_init(&rel);
        json_set_object(&rel);
        zcl_hex_encode(report->release_id, 32, hex);
        (void)json_push_kv_str(&rel, "release_id", hex);
        (void)json_push_kv_str(&rel, "name", cand->release.name);
        (void)json_push_kv_str(&rel, "semver", cand->release.semver);
        (void)json_push_kv_str(&rel, "license", cand->release.license);
        char pub[2 * VCS_PACKAGE_RELEASE_PUBKEY_BYTES + 1];
        zcl_hex_encode(cand->release.publisher_pubkey,
                      VCS_PACKAGE_RELEASE_PUBKEY_BYTES, pub);
        (void)json_push_kv_str(&rel, "publisher", pub);
        (void)json_push_kv_int(&rel, "publisher_sequence",
                               (int64_t)cand->release.publisher_sequence);
        (void)json_push_kv_str(&rel, "acceptance",
                               vcs_package_accept_result_string(
                                   report->accept));
        (void)json_push_kv_int(&rel, "replayed_releases",
                               (int64_t)replayed);
        (void)json_push_kv(out, "release", &rel);
        json_free(&rel);
    }
    if (report->manifest_ok) {
        struct json_value pkg;
        json_init(&pkg);
        json_set_object(&pkg);
        zcl_hex_encode(cand->release.package_root, 32, hex);
        (void)json_push_kv_str(&pkg, "package_root", hex);
        (void)json_push_kv_int(&pkg, "files", (int64_t)report->file_count);
        (void)json_push_kv_int(&pkg, "bytes", (int64_t)report->total_bytes);
        (void)json_push_kv_int(&pkg, "chunks",
                               (int64_t)report->chunk_count);
        (void)json_push_kv_bool(&pkg, "chunks_checked", chunks_checked);
        if (chunks_checked)
            (void)json_push_kv_int(&pkg, "chunks_verified",
                                   (int64_t)report->chunks_verified);
        (void)json_push_kv(out, "package", &pkg);
        json_free(&pkg);
    }
    if (cand->recipe_parsed) {
        const struct vcs_package_recipe *r = &cand->recipe;
        struct json_value rcp;
        json_init(&rcp);
        json_set_object(&rcp);
        uint8_t rroot[32];
        if (vcs_package_recipe_root(r, rroot) == VCS_PACKAGE_RECIPE_OK) {
            zcl_hex_encode(rroot, 32, hex);
            (void)json_push_kv_str(&rcp, "recipe_root", hex);
        }
        (void)json_push_kv_bool(&rcp, "valid", report->recipe_ok);
        (void)json_push_kv_int(&rcp, "public_headers",
                               (int64_t)r->public_headers.count);
        (void)json_push_kv_int(&rcp, "sources",
                               (int64_t)r->sources.count);
        (void)json_push_kv_int(&rcp, "test_sources",
                               (int64_t)r->test_sources.count);
        (void)json_push_kv_int(&rcp, "include_dirs",
                               (int64_t)r->include_dirs.count);
        (void)json_push_kv_int(&rcp, "defines",
                               (int64_t)r->defines.count);
        struct json_value libs;
        json_init(&libs);
        json_set_array(&libs);
        for (size_t i = 0; i < r->library_count; i++) {
            struct json_value lib;
            json_init(&lib);
            json_set_str(&lib, vcs_package_recipe_library_name(
                                   r->libraries[i]));
            (void)json_push_back(&libs, &lib);
            json_free(&lib);
        }
        (void)json_push_kv(&rcp, "allowed_system_libraries", &libs);
        json_free(&libs);
        (void)json_push_kv_int(&rcp, "expected_test_exit_code",
                               (int64_t)r->expected_test_exit_code);
        (void)json_push_kv_int(&rcp, "maximum_test_seconds",
                               (int64_t)r->maximum_test_seconds);
        (void)json_push_kv_int(&rcp, "maximum_memory_bytes",
                               (int64_t)r->maximum_memory_bytes);
        (void)json_push_kv(out, "recipe", &rcp);
        json_free(&rcp);
    }
}

/* ── zcode package publish plan ─────────────────────────────────────── */

void zcl_native_handle_zcode_package_publish_plan(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.package.publish.plan");
        return;
    }
    const char *dir = zc_input_str(request->input, "dir");
    struct zc_candidate cand;
    struct vcs_package_publish_report report;
    vcs_package_publish_report_init(&report);
    size_t replayed = 0;
    if (!zc_validate(request, reply, &cand, &report, datadir, dir,
                     &replayed)) {
        zc_candidate_free(&cand);
        return; /* hard failure: error body already set */
    }

    const struct zcode_package_publish_plan_input_v1 plan_input = {
        .validation_complete = true,
        .chunks_checked = report.chunks_checked,
        .failure_count = (uint32_t)report.failure_count,
    };
    struct zcode_package_publish_plan_result_v1 plan;
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_package_view_service_v1 *view_service =
        zcl_hotswap_service_acquire(ZCODE_PACKAGE_VIEW_SERVICE_ID, &lease);
    if (!view_service)
        view_service = zcode_package_view_service_builtin();
    bool rendered = view_service->render_publish_plan(&plan_input, &plan);
    zcl_hotswap_service_release(&lease);
    if (!rendered) {
        zc_candidate_free(&cand);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "PACKAGE_VIEW_FAILED", "render", false,
                               false,
                               "the pure package view service refused the publication plan",
                               "zcode.package.publish.plan");
        return;
    }
    (void)json_push_kv_str(&reply->data, "stage", plan.stage);
    (void)json_push_kv_bool(&reply->data, "valid", plan.valid);
    (void)json_push_kv_bool(&reply->data, "ready_to_commit",
                            plan.ready_to_commit);
    (void)json_push_kv_str(&reply->data, "readiness", plan.readiness);
    (void)json_push_kv_str(&reply->data, "next_action", plan.next_action);
    if (report.release_ok) {
        char token[65];
        zcl_hex_encode(report.release_id, 32, token);
        (void)json_push_kv_str(&reply->data, "plan_token", token);
    }
    zc_summary_json(&reply->data, &cand, &report, report.chunks_checked,
                    replayed);
    zc_failures_json(&reply->data, &report);
    zc_candidate_free(&cand);
}

/* ── zcode package publish commit ───────────────────────────────────── */

/* Close only a handle this call opened. The resident store outlives every
 * command that borrows it. */
static void zc_store_release(struct vcs_package_store *store, bool owned)
{
    if (owned)
        vcs_package_store_close(store);
}

void zcl_native_handle_zcode_package_publish_commit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.package.publish.commit");
        return;
    }
    const char *dir = zc_input_str(request->input, "dir");
    if (!dir || !dir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DIR",
                               "normalize", false, false,
                               "commit requires the chunk source dir",
                               "zcode.package.publish.commit");
        return;
    }
    struct zc_candidate cand;
    struct vcs_package_publish_report report;
    vcs_package_publish_report_init(&report);
    size_t replayed = 0;
    if (!zc_validate(request, reply, &cand, &report, datadir, dir,
                     &replayed)) {
        zc_candidate_free(&cand);
        return;
    }
    if (report.failure_count > 0) {
        /* The exact failed rule leads; the rest fit the evidence budget. */
        const struct vcs_package_publish_failure *first =
            &report.failures[0];
        char evidence[256];
        snprintf(evidence, sizeof(evidence), "%s (%zu rule%s failed)",
                 first->detail, report.failure_count,
                 report.failure_count == 1 ? "" : "s");
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            vcs_package_publish_rule_string(first->rule), "validate", false,
            false, "candidate release failed publication validation",
            evidence);
        zc_candidate_free(&cand);
        return;
    }

    char zcode_dir[4400];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(zcode_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        zc_candidate_free(&cand);
        return;
    }

    /* ── slice 11 policy checkpoint: publish frequency ─────────────────
     * A FRESH release (acceptance OK) is admitted only within the
     * publisher key's per-ISO-week tier allowance; a redelivery
     * classifying DUPLICATE skips the gate, so re-commit stays
     * idempotent. The tier resolves from the reward ledger's earned
     * score plus the local service book's verified-bytes facts. */
    const bool fresh_publish = report.accept == VCS_PACKAGE_ACCEPT_OK;
    struct vcs_service_book *book = NULL;
    enum vcs_policy_tier policy_tier = VCS_POLICY_TIER_NEW_USER;
    int64_t policy_day = 0;
    if (fresh_publish) {
        const struct json_value *dv = json_get(request->input, "day");
        if (dv)
            policy_day = json_get_int(dv);
        else
            policy_day =
                vcs_rank_day_from_unix(platform_time_wall_unix());
        book = vcs_service_book_load(zcode_dir);
        struct vcs_reward_ledger *ledger =
            vcs_reward_ledger_load(zcode_dir);
        if (!book || !ledger) {
            vcs_service_book_free(book);
            vcs_reward_ledger_free(ledger);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL,
                                   "POLICY_LOAD", "validate", false, false,
                                   "the policy facts (service book / reward "
                                   "ledger) could not be replayed",
                                   zcode_dir);
            zc_candidate_free(&cand);
            return;
        }
        struct vcs_reward_contributor_totals ct;
        vcs_reward_contributor_totals(
            ledger, cand.release.publisher_pubkey, &ct);
        struct vcs_service_key_totals kt;
        (void)vcs_service_key_totals(book, cand.release.publisher_pubkey,
                                     policy_day, &kt);
        policy_tier = vcs_policy_tier_for(ct.earned_score,
                                          kt.verified_bytes_uploaded,
                                          kt.verified_bytes_downloaded);
        struct vcs_policy_decision decision =
            vcs_policy_check_publish(policy_tier, kt.publishes_this_week);
        vcs_reward_ledger_free(ledger);
        if (!decision.allow) {
            char evidence[256];
            snprintf(evidence, sizeof(evidence),
                     "rule=%s tier=%s publishes_this_week=%u allowance=%u "
                     "(per ISO week, day=%lld)",
                     decision.rule, vcs_policy_tier_string(policy_tier),
                     kt.publishes_this_week,
                     vcs_policy_limits_for(policy_tier)->publish_per_week,
                     (long long)policy_day);
            vcs_service_book_free(book);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED,
                ZCL_COMMAND_EXIT_INVALID, "PUBLISH_FREQUENCY_LIMIT",
                "validate", false, false,
                "publish-frequency-limit: the publisher key's tier "
                "allowance for this ISO week is exhausted",
                evidence);
            zc_candidate_free(&cand);
            return;
        }
    }

    /* A running node already owns one store over its own datadir, and that
     * object — not the bytes on disk — is what its package swarm answers
     * from. Opening a second handle here writes the manifest, chunks and
     * carrier correctly and still leaves the serving engine with an index
     * that never heard of this package: the node announces a root it then
     * refuses to send, until it is restarted. So when this commit names the
     * datadir the resident handle was opened from, publish through that
     * handle. Any other datadir keeps the one-shot owned-store path. */
    struct vcs_package_store *resident = vcs_package_store_global();
    const char *resident_root = vcs_package_store_root_dir(resident);
    bool own_store = !(resident_root && strcmp(resident_root, zcode_dir) == 0);
    struct vcs_package_store *store = own_store
        ? vcs_package_store_open(datadir, vcs_package_store_quota_bytes())
        : resident;
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "STORE_OPEN",
                               "persist", false, false,
                               "the package store failed to open", zcode_dir);
        vcs_service_book_free(book);
        zc_candidate_free(&cand);
        return;
    }

    uint8_t root[32];
    enum vcs_package_store_result sres = vcs_package_store_put_manifest(
        store, cand.manifest_wire, cand.manifest_wire_len, root);
    if (sres != VCS_PACKAGE_STORE_OK) {
        zc_store_release(store, own_store);
        vcs_service_book_free(book);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               vcs_package_store_result_string(sres),
                               "persist", false, false,
                               "manifest admission failed",
                               cand.release.name);
        zc_candidate_free(&cand);
        return;
    }

    /* The declarative recipe persists beside the manifest (verify-before-
     * store: the store re-parses the wire before writing it). */
    sres = vcs_package_store_put_recipe(store, cand.recipe_wire,
                                        cand.recipe_wire_len, NULL);
    if (sres != VCS_PACKAGE_STORE_OK) {
        zc_store_release(store, own_store);
        vcs_service_book_free(book);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               vcs_package_store_result_string(sres),
                               "persist", false, true,
                               "recipe admission failed", cand.release.name);
        zc_candidate_free(&cand);
        return;
    }

    uint8_t *buf = zcl_malloc(VCS_PACKAGE_CHUNK_BYTES, "zc_chunk_buf");
    if (!buf) {
        zc_store_release(store, own_store);
        vcs_service_book_free(book);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "persist", false, false, "chunk buffer",
                               "zcode.package.publish.commit");
        zc_candidate_free(&cand);
        return;
    }
    uint64_t chunks_stored = 0;
    bool io_failed = false;
    char evidence[256] = "";
    for (size_t i = 0; i < cand.manifest.count && !io_failed; i++) {
        const struct vcs_package_file *f = &cand.manifest.files[i];
        for (uint32_t c = 0; c < f->chunk_count; c++) {
            size_t len = 0;
            enum vcs_package_publish_rule rule;
            if (!vcs_package_publish_read_chunk(dir, f, c, buf, &len,
                                                &rule)) {
                snprintf(evidence, sizeof(evidence), "%s#%u: %s", f->path,
                         c, vcs_package_publish_rule_string(rule));
                io_failed = true;
                break;
            }
            sres = vcs_package_store_put_chunk(store, root, f->path, c, buf,
                                               len);
            if (sres != VCS_PACKAGE_STORE_OK) {
                snprintf(evidence, sizeof(evidence), "%s#%u: %s", f->path,
                         c, vcs_package_store_result_string(sres));
                io_failed = true;
                break;
            }
            chunks_stored++;
        }
    }
    free(buf);
    if (io_failed) {
        /* Staging survives: a later commit of the same candidate resumes. */
        zc_store_release(store, own_store);
        vcs_service_book_free(book);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "CHUNK_PERSIST", "persist", true, true,
                               "chunk admission failed; staged bytes are "
                               "resumable on retry", evidence);
        zc_candidate_free(&cand);
        return;
    }

    /* The network object is a closed ordinary content.v2 carrier containing
     * the signed release, recipe, inner manifest, and exact source bytes.
     * Persist it before naming the release locally so every searchable
     * package is immediately publishable by one immutable transport root. */
    struct vcs_package_transport transport;
    vcs_package_transport_init(&transport);
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    enum vcs_package_transport_result transport_result =
        vcs_package_release_serialize(&cand.release, &release_wire,
                                      &release_wire_len) ==
                VCS_PACKAGE_RELEASE_OK
            ? vcs_package_transport_build(
                  release_wire, release_wire_len, cand.recipe_wire,
                  cand.recipe_wire_len, cand.manifest_wire,
                  cand.manifest_wire_len, &transport)
            : VCS_PACKAGE_TRANSPORT_ERR_RELEASE;
    free(release_wire);
    if (transport_result == VCS_PACKAGE_TRANSPORT_OK)
        transport_result = vcs_package_transport_store(
            store, &transport, dir);
    if (transport_result != VCS_PACKAGE_TRANSPORT_OK) {
        vcs_package_transport_free(&transport);
        zc_store_release(store, own_store);
        vcs_service_book_free(book);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "TRANSPORT_PERSIST", "persist", true, true,
            "the signed package transport carrier could not be persisted",
            vcs_package_transport_result_string(transport_result));
        zc_candidate_free(&cand);
        return;
    }

    bool committed = report.accept == VCS_PACKAGE_ACCEPT_OK;
    if (committed) {
        enum vcs_package_accept_result ar;
        sres = vcs_package_store_put_release(store, &cand.release, &ar);
        if (sres != VCS_PACKAGE_STORE_OK) {
            zc_store_release(store, own_store);
            vcs_package_transport_free(&transport);
            vcs_service_book_free(book);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED,
                ZCL_COMMAND_EXIT_INTERNAL,
                vcs_package_store_result_string(sres), "persist", false,
                true, "release persistence failed",
                vcs_package_accept_result_string(ar));
            zc_candidate_free(&cand);
            return;
        }
    }
    zc_store_release(store, own_store);

    /* Slice 11: a successful FRESH local commit records the admission event
     * in the local service book (dedup by release id — a redelivered
     * release id never mints a second event). A record failure degrades
     * the frequency gate's history, never the local commit itself; the reply
     * says so honestly. */
    bool policy_recorded = false;
    uint32_t policy_week_usage = 0;
    if (committed && book) {
        enum vcs_service_record_result rr = vcs_service_record_publish(
            book, cand.release.publisher_pubkey, report.release_id,
            policy_day);
        policy_recorded = rr == VCS_SERVICE_RECORD_OK ||
                          rr == VCS_SERVICE_RECORD_DUPLICATE;
        struct vcs_service_key_totals kt2;
        if (vcs_service_key_totals(book, cand.release.publisher_pubkey,
                                   policy_day, &kt2))
            policy_week_usage = kt2.publishes_this_week;
    }
    vcs_service_book_free(book);

    char hex[65];
    (void)json_push_kv_str(&reply->data, "stage", "commit");
    (void)json_push_kv_str(&reply->data, "result",
                           committed ? "committed" : "duplicate");
    (void)json_push_kv_bool(&reply->data, "local_commit_complete", true);
    (void)json_push_kv_bool(&reply->data,
                           "human_confirmation_bound", false);
    (void)json_push_kv_bool(&reply->data,
                           "pointer_publication_observed", false);
    (void)json_push_kv_bool(&reply->data,
                           "provider_publication_observed", false);
    (void)json_push_kv_bool(&reply->data, "peer_discovery_observed", false);
    (void)json_push_kv_bool(&reply->data, "exact_fetch_observed", false);
    (void)json_push_kv_bool(&reply->data,
                           "network_publication_performed", false);
    zcl_hex_encode(report.release_id, 32, hex);
    (void)json_push_kv_str(&reply->data, "release_id", hex);
    (void)json_push_kv_str(&reply->data, "plan_token", hex);
    char package_root_hex[65];
    char transport_root_hex[65];
    zcl_hex_encode(root, 32, package_root_hex);
    (void)json_push_kv_str(&reply->data, "package_root", package_root_hex);
    zcl_hex_encode(transport.transport_root, 32, transport_root_hex);
    (void)json_push_kv_str(&reply->data, "transport_root",
                           transport_root_hex);
    (void)json_push_kv_str(&reply->data, "name", cand.release.name);
    (void)json_push_kv_int(&reply->data, "files",
                           (int64_t)report.file_count);
    (void)json_push_kv_int(&reply->data, "bytes",
                           (int64_t)report.total_bytes);
    (void)json_push_kv_int(&reply->data, "chunks_stored",
                           (int64_t)chunks_stored);
    (void)json_push_kv_int(&reply->data, "replayed_releases",
                           (int64_t)replayed);
    if (committed) {
        struct json_value pol;
        json_init(&pol);
        json_set_object(&pol);
        (void)json_push_kv_str(&pol, "tier",
                               vcs_policy_tier_string(policy_tier));
        (void)json_push_kv_int(
            &pol, "publish_per_week",
            (int64_t)vcs_policy_limits_for(policy_tier)->publish_per_week);
        (void)json_push_kv_int(&pol, "publishes_this_week",
                               (int64_t)policy_week_usage);
        (void)json_push_kv_int(&pol, "day", policy_day);
        (void)json_push_kv_bool(&pol, "policy_recorded", policy_recorded);
        if (!policy_recorded)
            (void)json_push_kv_str(
                &pol, "policy_record_warning",
                "the local admission event could not be recorded in the "
                "service book; the publish-frequency gate's history is "
                "degraded (the local commit itself succeeded)");
        (void)json_push_kv(&reply->data, "policy", &pol);
        json_free(&pol);
    }
    {
        /* Local CAS admission is not network publication. Name the one
         * next command that binds package_root to transport_root on the
         * DHT so another node can fetch without this publisher. */
        int64_t now = platform_time_wall_unix();
        int64_t expiry = now + 2592000;
        char next[900];
        int nn = snprintf(
            next, sizeof(next),
            "z23 zcode network publish --input='{\"mode\":\"plan\","
            "\"kind\":\"pointer\",\"namespace\":\"zclassic23.package\","
            "\"semantic_root\":\"%s\",\"transport_root\":\"%s\","
            "\"sequence\":1,\"not_before\":%lld,\"expiry\":%lld}'",
            package_root_hex, transport_root_hex, (long long)now,
            (long long)expiry);
        if (nn > 0 && (size_t)nn < sizeof(next))
            (void)json_push_kv_str(&reply->data, "next_command", next);
        (void)json_push_kv_str(&reply->data, "next_kind", "pointer");
        (void)json_push_kv_str(
            &reply->data, "next_action",
            "install this exact package (zcode use) and file the distinct "
            "rebuild receipt (zcode package reproduce) so the pointer gate "
            "admits it, then plan then commit the pointer record so peers "
            "can discover this exact package_root after this node is gone");
    }
    reply->error.mutated = committed;
    vcs_package_transport_free(&transport);
    zc_candidate_free(&cand);
}

/* ── zcode package recipe ───────────────────────────────────────────── */

/* Read one bounded file fully (allocates *out; caller frees). False when
 * missing, unreadable, empty, or over cap (trailing bytes = not the exact
 * object). */
static bool zc_read_object(const char *path, size_t cap, uint8_t **out,
                           size_t *out_len)
{
    *out = NULL;
    *out_len = 0;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    uint8_t *buf = zcl_malloc(cap, "zc_read_object");
    if (!buf) {
        fclose(f);
        return false;
    }
    size_t len = fread(buf, 1, cap, f);
    bool ok = !ferror(f) && feof(f) && len > 0;
    fclose(f);
    if (!ok) {
        free(buf);
        return false;
    }
    *out = buf;
    *out_len = len;
    return true;
}

/* Render one bounded recipe string list (cap ZC_SHOW_MAX_FILES entries;
 * sets <key>_truncated when the rest is elided). */
static void zc_recipe_list_json(struct json_value *out, const char *key,
                                const struct vcs_package_recipe_strings *list)
{
    size_t shown = list->count < ZC_SHOW_MAX_FILES ? list->count
                                                   : ZC_SHOW_MAX_FILES;
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    for (size_t i = 0; i < shown; i++) {
        struct json_value item;
        json_init(&item);
        json_set_str(&item, list->items[i]);
        (void)json_push_back(&arr, &item);
        json_free(&item);
    }
    (void)json_push_kv(out, key, &arr);
    json_free(&arr);
    char trunc_key[64];
    snprintf(trunc_key, sizeof(trunc_key), "%s_truncated", key);
    (void)json_push_kv_bool(out, trunc_key, list->count > shown);
}

void zcl_native_handle_zcode_package_recipe(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.package.recipe");
        return;
    }
    const char *root_hex = zc_input_str(request->input, "root");
    uint8_t root[32];
    size_t root_len = 0;
    if (!root_hex || !zcl_hex_decode_n(root_hex, root, 32, &root_len) ||
        root_len != 32) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "root must be a 64-hex package root",
                               root_hex ? root_hex : "");
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
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INDEX_BUILD",
                               "execute", false, false,
                               "the package index could not be built",
                               zcode_dir);
        return;
    }
    const struct vcs_package_index_entry *e =
        vcs_package_index_find_root(index, root);
    if (!e) {
        vcs_package_index_free(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_PACKAGE",
                               "execute", false, false,
                               "no locally committed release names this package root",
                               root_hex);
        return;
    }

    /* The envelope commits the recipe root: read the persisted release to
     * learn WHICH recipe this release names (identity from the signed
     * bytes, never from a side index). */
    char path[4400];
    snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir,
             e->release_id_hex);
    vcs_package_index_free(index);
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    struct vcs_package_release release;
    if (!zc_read_object(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                        &release_wire, &release_wire_len) ||
        vcs_package_release_parse(release_wire, release_wire_len,
                                  &release) != VCS_PACKAGE_RELEASE_OK) {
        free(release_wire);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RELEASE_READ",
                               "execute", false, false,
                               "the persisted release envelope is unreadable",
                               e->release_id_hex);
        return;
    }
    free(release_wire);
    char recipe_root_hex[65];
    zcl_hex_encode(release.recipe_root, 32, recipe_root_hex);

    snprintf(path, sizeof(path), "%s/recipes/%s", zcode_dir,
             recipe_root_hex);
    uint8_t *recipe_wire = NULL;
    size_t recipe_wire_len = 0;
    if (!zc_read_object(path, VCS_PACKAGE_RECIPE_MAX_WIRE_BYTES, &recipe_wire,
                        &recipe_wire_len)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "RECIPE_NOT_HOSTED",
                               "execute", false, false,
                               "the release names a recipe root with no "
                               "recipe wire in the local store",
                               recipe_root_hex);
        return;
    }
    struct vcs_package_recipe recipe;
    enum vcs_package_recipe_error rerr =
        vcs_package_recipe_parse(recipe_wire, recipe_wire_len, &recipe);
    free(recipe_wire);
    if (rerr != VCS_PACKAGE_RECIPE_OK) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RECIPE_PARSE",
                               "execute", false, false,
                               "the persisted recipe wire is not canonical",
                               vcs_package_recipe_error_string(rerr));
        return;
    }

    (void)json_push_kv_str(&reply->data, "name", release.name);
    (void)json_push_kv_str(&reply->data, "semver", release.semver);
    (void)json_push_kv_str(&reply->data, "recipe_root", recipe_root_hex);
    (void)json_push_kv_str(&reply->data, "source",
                           "canonical-recipe-wire");
    struct json_value rcp;
    json_init(&rcp);
    json_set_object(&rcp);
    zc_recipe_list_json(&rcp, "public_headers", &recipe.public_headers);
    zc_recipe_list_json(&rcp, "sources", &recipe.sources);
    zc_recipe_list_json(&rcp, "test_sources", &recipe.test_sources);
    zc_recipe_list_json(&rcp, "include_dirs", &recipe.include_dirs);
    zc_recipe_list_json(&rcp, "preprocessor_defines", &recipe.defines);
    struct json_value libs;
    json_init(&libs);
    json_set_array(&libs);
    for (size_t i = 0; i < recipe.library_count; i++) {
        struct json_value lib;
        json_init(&lib);
        json_set_str(&lib, vcs_package_recipe_library_name(
                               recipe.libraries[i]));
        (void)json_push_back(&libs, &lib);
        json_free(&lib);
    }
    (void)json_push_kv(&rcp, "allowed_system_libraries", &libs);
    json_free(&libs);
    (void)json_push_kv_int(&rcp, "expected_test_exit_code",
                           (int64_t)recipe.expected_test_exit_code);
    (void)json_push_kv_int(&rcp, "maximum_test_seconds",
                           (int64_t)recipe.maximum_test_seconds);
    (void)json_push_kv_int(&rcp, "maximum_memory_bytes",
                           (int64_t)recipe.maximum_memory_bytes);
    (void)json_push_kv(&reply->data, "recipe", &rcp);
    json_free(&rcp);
    vcs_package_recipe_free(&recipe);
    (void)json_push_kv_str(
        &reply->data, "execution_note",
        "declarative only: the node never compiles or executes downloaded "
        "code; compilation belongs to the external verifier "
        "(zclassic23-package-verify)");
}

/* ── zcode package verify (slice 6) ─────────────────────────────────── */

/* Bound on attestation files scanned per call. */
#define ZC_VERIFY_MAX_SCAN 256u

void zcl_native_handle_zcode_package_verify(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.package.verify");
        return;
    }
    const char *root_hex = zc_input_str(request->input, "root");
    uint8_t root[32];
    size_t root_len = 0;
    if (!root_hex || !zcl_hex_decode_n(root_hex, root, 32, &root_len) ||
        root_len != 32) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "root must be a 64-hex package root",
                               root_hex ? root_hex : "");
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
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INDEX_BUILD",
                               "execute", false, false,
                               "the package index could not be built",
                               zcode_dir);
        return;
    }
    const struct vcs_package_index_entry *e =
        vcs_package_index_find_root(index, root);
    if (!e) {
        vcs_package_index_free(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_PACKAGE",
                               "execute", false, false,
                               "no locally committed release names this package root",
                               root_hex);
        return;
    }

    /* The envelope is the self-verification reference (publisher key) and
     * commits the recipe root every matching attestation must name. */
    char path[4400];
    snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir,
             e->release_id_hex);
    char name[VCS_PACKAGE_RELEASE_NAME_MAX + 1u];
    char semver[VCS_PACKAGE_RELEASE_SEMVER_MAX + 1u];
    char publisher_hex[67];
    snprintf(name, sizeof(name), "%s", e->name);
    snprintf(semver, sizeof(semver), "%s", e->semver);
    snprintf(publisher_hex, sizeof(publisher_hex), "%s", e->publisher_hex);
    char release_id_hex[65];
    snprintf(release_id_hex, sizeof(release_id_hex), "%s", e->release_id_hex);
    vcs_package_index_free(index);
    uint8_t *release_wire = NULL;
    size_t release_wire_len = 0;
    struct vcs_package_release release;
    if (!zc_read_object(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                        &release_wire, &release_wire_len) ||
        vcs_package_release_parse(release_wire, release_wire_len,
                                  &release) != VCS_PACKAGE_RELEASE_OK) {
        free(release_wire);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "RELEASE_READ",
                               "execute", false, false,
                               "the persisted release envelope is unreadable",
                               release_id_hex);
        return;
    }
    free(release_wire);

    /* The approved-verifier allowlist: explicit local configuration, never
     * the network. A missing/unloadable file means NO quorum is possible —
     * a named rejection, not a silent "unverified". */
    snprintf(path, sizeof(path), "%s/approved_verifiers", zcode_dir);
    struct vcs_verifier_policy policy;
    vcs_verifier_policy_init(&policy);
    enum vcs_verifier_policy_error perr = VCS_VERIFIER_POLICY_OK;
    if (!vcs_verifier_policy_load(&policy, path, &perr)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "NO_APPROVED_VERIFIERS", "execute", false,
                               false,
                               "the approved-verifier allowlist is missing "
                               "or invalid — create it with one 66-hex "
                               "verifier pubkey per line (explicit local "
                               "configuration; anonymous peers are not a "
                               "quorum)",
                               vcs_verifier_policy_error_string(perr));
        return;
    }

    /* Scan the attestations dir (bounded): every hex64 file is a candidate;
     * unparseable wires stay in the report as attestation-invalid rows. */
    snprintf(path, sizeof(path), "%s/attestations", zcode_dir);
    struct vcs_verify_candidate *candidates = zcl_malloc(
        ZC_VERIFY_MAX_SCAN * sizeof(*candidates), "zc_verify_candidates");
    if (!candidates) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "execute", false, false,
                               "verify candidate buffer", path);
        return;
    }
    size_t candidate_count = 0;
    size_t scanned = 0;
    bool scan_truncated = false;
    DIR *dir = opendir(path);
    if (dir) {
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            uint8_t scratch[32];
            size_t scratch_len = 0;
            if (!zcl_hex_decode_n(ent->d_name, scratch, 32, &scratch_len) ||
                scratch_len != 32)
                continue;
            if (candidate_count == ZC_VERIFY_MAX_SCAN) {
                scan_truncated = true;
                break;
            }
            scanned++;
            char apath[4400];
            int an = snprintf(apath, sizeof(apath), "%s/%s", path,
                              ent->d_name);
            if (an < 0 || (size_t)an >= sizeof(apath))
                continue;
            uint8_t *wire = NULL;
            size_t wire_len = 0;
            struct vcs_verify_candidate *cand =
                &candidates[candidate_count];
            cand->parsed = false;
            if (zc_read_object(apath, VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES,
                               &wire, &wire_len)) {
                cand->parsed =
                    vcs_package_attest_parse(wire, wire_len,
                                             &cand->attestation) ==
                    VCS_PACKAGE_ATTEST_OK;
            }
            free(wire);
            candidate_count++;
        }
        closedir(dir);
    }

    struct vcs_verify_quorum quorum;
    vcs_verify_evaluate(candidates, candidate_count, root,
                        release.recipe_root, release.publisher_pubkey,
                        &policy, &quorum);
    free(candidates);

    /* The headline signal: bit-identical reproduction among the build
     * receipts filed under <zcode>/receipts (the install lifecycle files
     * one receipt per build event; two DISTINCT receipt ids with
     * byte-identical output sets is a recorded third-party reproduction).
     * The signer quorum above is the latency fast path over this. */
    snprintf(path, sizeof(path), "%s/receipts", zcode_dir);
    struct vcs_reproduce_report repro;
    bool repro_scanned =
        vcs_package_reproduce_scan(path, root, release.recipe_root, &repro);

    (void)json_push_kv_str(&reply->data, "name", name);
    (void)json_push_kv_str(&reply->data, "semver", semver);
    (void)json_push_kv_str(&reply->data, "package_root", root_hex);
    (void)json_push_kv_str(&reply->data, "release_id", release_id_hex);
    (void)json_push_kv_str(&reply->data, "publisher", publisher_hex);
    char recipe_root_hex[65];
    zcl_hex_encode(release.recipe_root, 32, recipe_root_hex);
    (void)json_push_kv_str(&reply->data, "recipe_root", recipe_root_hex);
    (void)json_push_kv_int(&reply->data, "approved_verifiers",
                           (int64_t)policy.count);
    (void)json_push_kv_bool(&reply->data, "verified", quorum.verified);
    (void)json_push_kv_int(&reply->data, "quorum_required",
                           (int64_t)VCS_VERIFY_QUORUM_REQUIRED);
    (void)json_push_kv_bool(&reply->data, "quorum_reached",
                            quorum.quorum_reached);
    (void)json_push_kv_str(
        &reply->data, "quorum_class",
        quorum.quorum_reached
            ? vcs_package_attest_result_string(quorum.quorum_class)
            : "");
    (void)json_push_kv_int(&reply->data, "quorum_signers",
                           (int64_t)quorum.quorum_signers);
    (void)json_push_kv_int(&reply->data, "attestations_scanned",
                           (int64_t)scanned);
    (void)json_push_kv_bool(&reply->data, "attestations_truncated",
                            scan_truncated);
    (void)json_push_kv_int(&reply->data, "candidates",
                           (int64_t)quorum.candidates);
    (void)json_push_kv_int(&reply->data, "counted",
                           (int64_t)quorum.counted);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < quorum.row_count; i++) {
        const struct vcs_verify_row *row = &quorum.rows[i];
        struct json_value r;
        json_init(&r);
        json_set_object(&r);
        if (row->has_pubkey) {
            char pk_hex[67];
            zcl_hex_encode(row->verifier_pubkey, 33, pk_hex);
            (void)json_push_kv_str(&r, "verifier", pk_hex);
        } else {
            (void)json_push_kv_str(&r, "verifier", "");
        }
        (void)json_push_kv_str(
            &r, "result",
            row->result_class
                ? vcs_package_attest_result_string(row->result_class)
                : "");
        (void)json_push_kv_str(&r, "rule",
                               vcs_verify_row_rule_string(row->rule));
        (void)json_push_kv_bool(&r, "counted",
                                row->rule == VCS_VERIFY_ROW_COUNTED);
        (void)json_push_back(&rows, &r);
        json_free(&r);
    }
    (void)json_push_kv(&reply->data, "rows", &rows);
    json_free(&rows);
    (void)json_push_kv_bool(&reply->data, "rows_truncated",
                            quorum.rows_truncated);

    struct json_value rj;
    json_init(&rj);
    json_set_object(&rj);
    (void)json_push_kv_bool(&rj, "scanned_ok", repro_scanned);
    (void)json_push_kv_int(&rj, "receipts_scanned",
                           (int64_t)repro.scanned);
    (void)json_push_kv_int(&rj, "matching_receipts",
                           (int64_t)repro.matching);
    (void)json_push_kv_bool(&rj, "reproduced", repro.reproduced);
    (void)json_push_kv_int(&rj, "distinct_toolchains",
                           (int64_t)repro.distinct_toolchains);
    (void)json_push_kv_bool(&rj, "cross_toolchain", repro.cross_toolchain);
    struct json_value rrows;
    json_init(&rrows);
    json_set_array(&rrows);
    for (size_t i = 0; i < repro.row_count; i++) {
        const struct vcs_reproduce_row *row = &repro.rows[i];
        struct json_value r;
        json_init(&r);
        json_set_object(&r);
        char rid_hex[65];
        zcl_hex_encode(row->receipt_id, 32, rid_hex);
        (void)json_push_kv_str(&r, "receipt_id", rid_hex);
        (void)json_push_kv_bool(&r, "reference", row->reference);
        (void)json_push_kv_str(
            &r, "rule",
            vcs_reproduce_rule_string((enum vcs_reproduce_rule)row->rule));
        (void)json_push_kv_str(&r, "detail", row->detail);
        (void)json_push_back(&rrows, &r);
        json_free(&r);
    }
    (void)json_push_kv(&rj, "rows", &rrows);
    json_free(&rrows);
    (void)json_push_kv_bool(&rj, "rows_truncated", repro.rows_truncated);
    (void)json_push_kv(&reply->data, "reproduction", &rj);
    json_free(&rj);
    (void)json_push_kv_str(
        &reply->data, "verification_note",
        "headline signal: bit-identical reproduction — two or "
        "more DISTINCT build receipts (any verifier's --emit build-report, "
        "filed under <datadir>/zcode/receipts) committing byte-identical "
        "output sets for this package+recipe; reproduce an installed "
        "package on this node with zcode package reproduce, or externally "
        "with zclassic23-package-verify --emit=... "
        "--reproduce-against=<report>. "
        "The signer quorum (2+ approved independent verifier keys signing "
        "matching attestations) is the latency fast path over "
        "reproduction, never a substitute for it; attestations are "
        "produced by the external zclassic23-package-verify program — the "
        "node never compiles or executes downloaded code");
}

/* ── zcode package attest import ────────────────────────────────────── */

/* Filing discipline (mkdir -p, tmp+fsync+rename, idempotence, and the
 * fail-closed same-name conflict) lives in ONE place:
 * vcs_package_attest_transport_file(). The operator import path below and
 * the swarm pull path call that same function with the same argument
 * list; neither keeps its own copy. */

void zcl_native_handle_zcode_package_attest_import(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.package.attest.import");
        return;
    }
    const char *wire_hex = zc_input_str(request->input, "attestation_wire");
    if (!wire_hex || !wire_hex[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_WIRE",
                               "normalize", false, false,
                               "no attestation_wire given",
                               "zcode.package.attest.import");
        return;
    }
    if (strlen(wire_hex) / 2 > VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "WIRE_OVERSIZE",
                               "normalize", false, false,
                               "attestation_wire exceeds the canonical wire "
                               "bound",
                               vcs_package_attest_error_string(
                                   VCS_PACKAGE_ATTEST_ERR_WIRE_OVERSIZE));
        return;
    }
    uint8_t *wire =
        zcl_malloc(VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES, "zc_attest_wire");
    if (!wire) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ALLOC",
                               "normalize", false, false,
                               "attestation wire buffer",
                               "zcode.package.attest.import");
        return;
    }
    size_t wire_len = 0;
    if (!zcl_hex_decode_n(wire_hex, wire, VCS_PACKAGE_ATTEST_MAX_WIRE_BYTES,
                          &wire_len)) {
        free(wire);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_WIRE_HEX",
                               "normalize", false, false,
                               "attestation_wire must be even, non-empty hex "
                               "within the wire bound",
                               "zcode.package.attest.import");
        return;
    }

    /* The codec names the failed rule: grammar/consistency first, then the
     * embedded secp256k1 signature over the attestation id. */
    struct vcs_package_attest att;
    enum vcs_package_attest_error aerr =
        vcs_package_attest_parse(wire, wire_len, &att);
    if (aerr != VCS_PACKAGE_ATTEST_OK) {
        free(wire);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "ATTEST_INVALID",
                               "execute", false, false,
                               "the wire is not a canonical attestation",
                               vcs_package_attest_error_string(aerr));
        return;
    }
    aerr = vcs_package_attest_verify(&att);
    if (aerr != VCS_PACKAGE_ATTEST_OK) {
        free(wire);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "ATTEST_SIGNATURE",
                               "execute", false, false,
                               "the embedded verifier signature does not "
                               "verify",
                               vcs_package_attest_error_string(aerr));
        return;
    }
    uint8_t id[VCS_PACKAGE_ATTEST_ID_BYTES];
    aerr = vcs_package_attest_id(&att, id);
    if (aerr != VCS_PACKAGE_ATTEST_OK) {
        free(wire);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "ATTEST_ID",
                               "execute", false, false,
                               "a verified attestation has no id",
                               vcs_package_attest_error_string(aerr));
        return;
    }
    char id_hex[65];
    zcl_hex_encode(id, sizeof(id), id_hex);

    char zcode_dir[4400];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(zcode_dir)) {
        free(wire);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return;
    }

    /* The single filer: mkdir -p, tmp+fsync+rename, idempotent on
     * identical bytes, and fail-closed on a same-name object that does not
     * read back identical. */
    bool filed = false;
    bool already_present = false;
    enum vcs_package_attest_transport_result tr =
        vcs_package_attest_transport_file(zcode_dir, wire, wire_len, id,
                                          &filed, &already_present);
    free(wire);
    if (tr != VCS_PACKAGE_ATTEST_TRANSPORT_OK) {
        if (tr == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_PATH) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID,
                                   "DATADIR_TOO_LONG", "normalize", false,
                                   false, "datadir path too long", datadir);
            return;
        }
        if (tr == VCS_PACKAGE_ATTEST_TRANSPORT_ERR_CONFLICT) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL,
                                   "STORE_CONFLICT", "execute", false, false,
                                   "a different or unreadable object already "
                                   "occupies this attestation id",
                                   id_hex);
            return;
        }
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "STORE_WRITE",
                               "execute", false, false,
                               "the attestation could not be filed",
                               vcs_package_attest_transport_result_string(
                                   tr));
        return;
    }

    char signer_hex[67];
    zcl_hex_encode(att.verifier_pubkey, sizeof(att.verifier_pubkey),
                   signer_hex);
    (void)json_push_kv_bool(&reply->data, "filed", filed);
    (void)json_push_kv_bool(&reply->data, "already_present",
                            already_present);
    (void)json_push_kv_str(&reply->data, "attestation_id", id_hex);
    (void)json_push_kv_str(&reply->data, "signer_pubkey", signer_hex);
    (void)json_push_kv_str(&reply->data, "result_class",
                           vcs_package_attest_result_string(
                               att.result_class));
    (void)json_push_kv_str(
        &reply->data, "note",
        "filing is not acceptance: import validates only the wire's "
        "internal consistency and embedded signature — the local "
        "approved-verifier quorum policy applies at evaluation time "
        "(zcode package verify), and the attested package need not be "
        "locally present");
}

/* ── zcode package search ───────────────────────────────────────────── */

static void zc_search_row_json(struct json_value *row,
                               const struct zcode_package_view_entry_v1 *e)
{
    json_set_object(row);
    (void)json_push_kv_str(row, "name", e->name);
    (void)json_push_kv_str(row, "semver", e->semver);
    (void)json_push_kv_str(row, "license", e->license);
    (void)json_push_kv_str(row, "publisher", e->publisher);
    (void)json_push_kv_int(row, "publisher_sequence",
                           (int64_t)e->publisher_sequence);
    (void)json_push_kv_str(row, "release_id", e->release_id);
    (void)json_push_kv_str(row, "package_root", e->package_root);
    (void)json_push_kv_bool(row, "manifest_present", e->manifest_present);
    (void)json_push_kv_int(row, "files", (int64_t)e->file_count);
    (void)json_push_kv_int(row, "bytes", (int64_t)e->total_bytes);
}

void zcl_native_handle_zcode_package_search(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.package.search");
        return;
    }
    int64_t limit = 0;
    const struct json_value *lv = json_get(request->input, "limit");
    if (lv)
        limit = json_get_int(lv);
    if (limit <= 0)
        limit = ZC_SEARCH_MAX_ROWS;
    if (limit > (int64_t)ZC_SEARCH_MAX_ROWS)
        limit = ZC_SEARCH_MAX_ROWS;

    char zcode_dir[4400];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(zcode_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return;
    }
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INDEX_BUILD",
                               "execute", false, false,
                               "the package index could not be built",
                               zcode_dir);
        return;
    }
    struct vcs_package_search search = {
        .publisher = zc_input_str(request->input, "publisher"),
        .name_prefix = zc_input_str(request->input, "name_prefix"),
        .license = zc_input_str(request->input, "license"),
        .keyword = zc_input_str(request->input, "keyword"),
    };
    const struct vcs_package_index_entry *rows[ZC_SEARCH_MAX_ROWS];
    size_t total = vcs_package_index_search(index, &search, rows,
                                            (size_t)limit);
    size_t rendered = total < (size_t)limit ? total : (size_t)limit;
    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_package_view_service_v1 *view_service =
        zcl_hotswap_service_acquire(ZCODE_PACKAGE_VIEW_SERVICE_ID, &lease);
    if (!view_service)
        view_service = zcode_package_view_service_builtin();
    bool view_ok = true;
    for (size_t i = 0; i < rendered; i++) {
        struct zcode_package_view_entry_v1 view;
        if (!view_service->render_entry(rows[i], &view) || !view.valid) {
            view_ok = false;
            break;
        }
        struct json_value row;
        json_init(&row);
        zc_search_row_json(&row, &view);
        (void)json_push_back(&arr, &row);
        json_free(&row);
    }
    zcl_hotswap_service_release(&lease);
    if (!view_ok) {
        json_free(&arr);
        vcs_package_index_free(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "PACKAGE_VIEW_FAILED", "render", false,
                               false,
                               "the pure package view service refused a search row",
                               "zcode.package.search");
        return;
    }
    (void)json_push_kv(&reply->data, "results", &arr);
    json_free(&arr);
    (void)json_push_kv_int(&reply->data, "total_matches", (int64_t)total);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_bool(&reply->data, "items_truncated",
                            total > rendered);
    (void)json_push_kv_int(&reply->data, "packages_scanned",
                           (int64_t)vcs_package_index_count(index));
    (void)json_push_kv_int(&reply->data, "limit", limit);
    vcs_package_index_free(index);
}

/* ── zcode package library ──────────────────────────────────────────── */

static void zc_library_emit(struct zcl_command_reply *reply,
                            struct json_value *packages, size_t rendered,
                            bool truncated, int64_t limit,
                            size_t evaluated, size_t reproduced)
{
    char next[384];
    if (rendered == 0) {
        (void)snprintf(
            next, sizeof(next),
            "z23 zcode package fetch --input='{\"root\":\"<64hex>\"}'");
    } else {
        const char *name = NULL;
        const char *root = NULL;
        size_t n = packages ? packages->num_children : 0;
        for (size_t i = 0; i < n; i++) {
            const struct json_value *row = json_at(packages, i);
            const char *row_name =
                row ? json_get_str(json_get(row, "name")) : NULL;
            const char *row_root =
                row ? json_get_str(json_get(row, "package_root")) : NULL;
            if (!root && row_root && row_root[0])
                root = row_root;
            if (row_name && row_name[0]) {
                name = row_name;
                root = row_root;
                break;
            }
        }
        if (name && name[0])
            (void)snprintf(next, sizeof(next),
                           "z23 zcode package fetch --input='{\"name\":\"%s\"}'",
                           name);
        else if (root && root[0])
            (void)snprintf(next, sizeof(next),
                           "z23 zcode package fetch --input='{\"root\":\"%s\"}'",
                           root);
        else
            (void)snprintf(
                next, sizeof(next),
                "z23 zcode package fetch --input='{\"root\":\"<64hex>\"}'");
    }
    (void)json_push_kv(&reply->data, "packages", packages);
    (void)json_push_kv_int(&reply->data, "count", (int64_t)rendered);
    (void)json_push_kv_int(&reply->data, "rendered", (int64_t)rendered);
    (void)json_push_kv_bool(&reply->data, "items_truncated", truncated);
    (void)json_push_kv_int(&reply->data, "limit", limit);
    /* The shelf census: how many rendered rows carried evaluable
     * reproduction evidence, and how many of those prove the exact
     * predicate the pointer publish gate applies. */
    (void)json_push_kv_int(&reply->data, "evaluated_count",
                           (int64_t)evaluated);
    (void)json_push_kv_int(&reply->data, "reproduced_count",
                           (int64_t)reproduced);
    (void)json_push_kv_str(&reply->data, "next_command", next);
}

/* True when <zcode_dir>/manifests holds at least one committed 64-hex
 * manifest. Unreadable (a file where the directory belongs, or opendir
 * failure on a present path) sets *unreadable so the leaf can refuse
 * instead of answering an empty shelf. Absent is empty, not unreadable. */
static bool zc_library_has_manifests(const char *zcode_dir, bool *unreadable)
{
    char path[4400];
    int n;

    if (unreadable)
        *unreadable = false;
    if (!zcode_dir)
        return false;
    n = snprintf(path, sizeof(path), "%s/manifests", zcode_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        if (unreadable)
            *unreadable = true;
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    if (!S_ISDIR(st.st_mode)) {
        if (unreadable)
            *unreadable = true;
        return false;
    }
    DIR *d = opendir(path);
    if (!d) {
        if (unreadable)
            *unreadable = true;
        return false;
    }
    bool present = false;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        uint8_t root[32];
        if (strlen(ent->d_name) == 64 &&
            zcl_hex_decode_lower(ent->d_name, root, 32)) {
            present = true;
            break;
        }
    }
    closedir(d);
    return present;
}

/* Per-row reproduction evidence: the same local receipts scan the pointer
 * publish gate applies (boot_zcode_dht_publish_gate.c refuses unless
 * vcs_package_reproduce_scan reports reproduced=true), with the exact field
 * names zcode package show emits. The object is always present so the
 * contract is uniform: the real fields on success, {"error": ...} when the
 * row is unevaluable (no persisted release names the root) or the evidence
 * is unreadable — library is a read-only view, never failed by evidence.
 * *evaluated counts rows carrying real fields; *reproduced counts rows
 * with reproduced=true. */
static void zc_library_row_reproduction(
    struct json_value *row, const char *zcode_dir, const uint8_t root[32],
    const struct vcs_package_index_entry *named, size_t *evaluated,
    size_t *reproduced)
{
    struct json_value repro;
    json_init(&repro);
    json_set_object(&repro);
    if (!named) {
        (void)json_push_kv_str(&repro, "error",
                               "no persisted release names this root");
    } else {
        char path[4400];
        int n = snprintf(path, sizeof(path), "%s/releases/%s", zcode_dir,
                         named->release_id_hex);
        uint8_t *release_wire = NULL;
        size_t release_wire_len = 0;
        struct vcs_package_release release;
        bool envelope_ok =
            n > 0 && (size_t)n < sizeof(path) &&
            zc_read_object(path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                           &release_wire, &release_wire_len) &&
            vcs_package_release_parse(release_wire, release_wire_len,
                                      &release) == VCS_PACKAGE_RELEASE_OK;
        free(release_wire);
        if (!envelope_ok) {
            (void)json_push_kv_str(&repro, "error",
                                   "persisted release envelope unreadable");
        } else {
            n = snprintf(path, sizeof(path), "%s/receipts", zcode_dir);
            struct vcs_reproduce_report report;
            if (n <= 0 || (size_t)n >= sizeof(path) ||
                !vcs_package_reproduce_scan(path, root, release.recipe_root,
                                            &report)) {
                (void)json_push_kv_str(&repro, "error",
                                       "the receipt scan failed");
            } else {
                (void)json_push_kv_int(&repro, "receipts_scanned",
                                       (int64_t)report.scanned);
                (void)json_push_kv_int(&repro, "receipts_matching",
                                       (int64_t)report.matching);
                (void)json_push_kv_bool(&repro, "reproduced",
                                        report.reproduced);
                /* The exact gate predicate the pointer publish applies. */
                (void)json_push_kv_bool(&repro, "publishable",
                                        report.reproduced);
                (void)json_push_kv_int(&repro, "distinct_toolchains",
                                       (int64_t)report.distinct_toolchains);
                (void)json_push_kv_bool(&repro, "cross_toolchain",
                                        report.cross_toolchain);
                (void)json_push_kv_bool(&repro, "rows_truncated",
                                        report.rows_truncated);
                (*evaluated)++;
                if (report.reproduced)
                    (*reproduced)++;
            }
        }
    }
    (void)json_push_kv(row, "reproduction", &repro);
    json_free(&repro);
}

void zcl_native_handle_zcode_package_library(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.package.library");
        return;
    }
    int64_t limit = 0;
    const struct json_value *lv = json_get(request->input, "limit");
    if (lv)
        limit = json_get_int(lv);
    if (limit <= 0)
        limit = (int64_t)ZC_LIBRARY_MAX_ROWS;
    if (limit > (int64_t)ZC_LIBRARY_MAX_ROWS)
        limit = (int64_t)ZC_LIBRARY_MAX_ROWS;

    char zcode_dir[4400];
    int n = snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(zcode_dir)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "DATADIR_TOO_LONG",
                               "normalize", false, false,
                               "datadir path too long", datadir);
        return;
    }

    struct json_value arr;
    json_init(&arr);
    json_set_array(&arr);

    /* A running node already owns the store this datadir maps to. Borrow
     * that handle so a one-shot open does not run recovery against a live
     * shelf. Any other datadir stays one-shot — and an absent or empty
     * manifests tree is a passed empty list, never a mkdir/lock/GC. */
    struct vcs_package_store *resident = vcs_package_store_global();
    const char *resident_root = vcs_package_store_root_dir(resident);
    bool own_store = !(resident_root && strcmp(resident_root, zcode_dir) == 0);
    struct vcs_package_store *store = NULL;
    if (!own_store) {
        store = resident;
    } else {
        struct stat st;
        if (stat(zcode_dir, &st) != 0) {
            zc_library_emit(reply, &arr, 0, false, limit, 0, 0);
            json_free(&arr);
            return;
        }
        if (!S_ISDIR(st.st_mode)) {
            json_free(&arr);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "STORE_UNREADABLE", "execute", false, false,
                "zcode path exists and is not a directory", zcode_dir);
            return;
        }
        bool unreadable = false;
        if (!zc_library_has_manifests(zcode_dir, &unreadable)) {
            if (unreadable) {
                json_free(&arr);
                zcl_command_reply_fail(
                    reply, ZCL_COMMAND_STATUS_FAILED,
                    ZCL_COMMAND_EXIT_INVALID, "STORE_UNREADABLE",
                    "execute", false, false,
                    "package manifests path exists and is not enumerable",
                    zcode_dir);
                return;
            }
            zc_library_emit(reply, &arr, 0, false, limit, 0, 0);
            json_free(&arr);
            return;
        }
        store = vcs_package_store_open(datadir,
                                       vcs_package_store_quota_bytes());
        if (!store) {
            json_free(&arr);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "STORE_OPEN", "execute", false, false,
                "the package store failed to open", zcode_dir);
            return;
        }
    }

    /* Probe one extra slot so a full cap can still flag truncation. */
    struct vcs_package_store_summary summaries[ZC_LIBRARY_MAX_ROWS + 1u];
    size_t want = (size_t)limit + 1u;
    if (want > ZC_LIBRARY_MAX_ROWS + 1u)
        want = ZC_LIBRARY_MAX_ROWS + 1u;
    size_t total = vcs_package_store_list_summaries(store, true, summaries,
                                                    want);
    size_t rendered = total < (size_t)limit ? total : (size_t)limit;
    bool truncated = total > rendered;

    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    size_t evaluated = 0;
    size_t reproduced = 0;
    for (size_t i = 0; i < rendered; i++) {
        char root_hex[65];
        zcl_hex_encode(summaries[i].root, 32, root_hex);
        const struct vcs_package_index_entry *named =
            index ? vcs_package_index_find_root(index, summaries[i].root)
                  : NULL;
        enum vcs_package_public_shape shape =
            vcs_package_public_shape_classify(store, summaries[i].root,
                                              NULL);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_str(&row, "package_root", root_hex);
        (void)json_push_kv_str(&row, "name", named ? named->name : "");
        (void)json_push_kv_bool(&row, "complete", summaries[i].complete);
        (void)json_push_kv_bool(&row, "pinned", summaries[i].pinned);
        (void)json_push_kv_int(&row, "file_count",
                               (int64_t)summaries[i].file_count);
        (void)json_push_kv_int(&row, "total_bytes",
                               (int64_t)summaries[i].total_bytes);
        (void)json_push_kv_int(&row, "total_chunks",
                               (int64_t)summaries[i].total_chunks);
        (void)json_push_kv_bool(&row, "public_serveable",
                                shape != VCS_PACKAGE_PUBLIC_REFUSED);
        zc_library_row_reproduction(&row, zcode_dir, summaries[i].root,
                                    named, &evaluated, &reproduced);
        (void)json_push_back(&arr, &row);
        json_free(&row);
    }
    vcs_package_index_free(index);
    zc_store_release(store, own_store);
    zc_library_emit(reply, &arr, rendered, truncated, limit, evaluated,
                    reproduced);
    json_free(&arr);
}

/* ── zcode package show ─────────────────────────────────────────────── */

void zcl_native_handle_zcode_package_show(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    const char *datadir = zc_datadir(request);
    if (!datadir) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_DATADIR",
                               "normalize", false, false,
                               "no datadir given (input datadir or --datadir)",
                               "zcode.package.show");
        return;
    }
    const char *root_hex = zc_input_str(request->input, "root");
    uint8_t root[32];
    size_t root_len = 0;
    if (!root_hex || !zcl_hex_decode_n(root_hex, root, 32, &root_len) ||
        root_len != 32) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "root must be a 64-hex package root",
                               root_hex ? root_hex : "");
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
    struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
    if (!index) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "INDEX_BUILD",
                               "execute", false, false,
                               "the package index could not be built",
                               zcode_dir);
        return;
    }
    const struct vcs_package_index_entry *e =
        vcs_package_index_find_root(index, root);
    if (!e) {
        vcs_package_index_free(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_PACKAGE",
                               "execute", false, false,
                               "no locally committed release names this package root",
                               root_hex);
        return;
    }

    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_package_view_service_v1 *view_service =
        zcl_hotswap_service_acquire(ZCODE_PACKAGE_VIEW_SERVICE_ID, &lease);
    if (!view_service)
        view_service = zcode_package_view_service_builtin();
    struct zcode_package_view_entry_v1 view;
    if (!view_service->render_entry(e, &view) || !view.valid) {
        zcl_hotswap_service_release(&lease);
        vcs_package_index_free(index);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL,
                               "PACKAGE_VIEW_FAILED", "render", false,
                               false,
                               "the pure package view service refused the release summary",
                               "zcode.package.show");
        return;
    }

    struct json_value rel;
    json_init(&rel);
    json_set_object(&rel);
    (void)json_push_kv_str(&rel, "release_id", view.release_id);
    (void)json_push_kv_str(&rel, "name", view.name);
    (void)json_push_kv_str(&rel, "semver", view.semver);
    (void)json_push_kv_str(&rel, "license", view.license);
    (void)json_push_kv_str(&rel, "publisher", view.publisher);
    (void)json_push_kv_int(&rel, "publisher_sequence",
                           (int64_t)view.publisher_sequence);
    (void)json_push_kv_str(&rel, "chain_id", view.chain_id);
    (void)json_push_kv_str(&rel, "reward_address", view.reward_address);
    (void)json_push_kv_bool(&rel, "has_parent", view.has_parent);
    if (view.has_parent)
        (void)json_push_kv_str(&rel, "parent_root", view.parent_root);
    (void)json_push_kv_bool(&rel, "has_znam", view.has_znam);
    if (view.has_znam)
        (void)json_push_kv_str(&rel, "znam", view.znam);
    (void)json_push_kv(&reply->data, "release", &rel);
    json_free(&rel);

    (void)json_push_kv_str(&reply->data, "package_root",
                           view.package_root);
    (void)json_push_kv_bool(&reply->data, "manifest_present",
                            view.manifest_present);
    (void)json_push_kv_int(&reply->data, "files", (int64_t)view.file_count);
    (void)json_push_kv_int(&reply->data, "bytes", (int64_t)view.total_bytes);
    (void)json_push_kv_int(&reply->data, "chunks", (int64_t)view.chunk_total);
    (void)json_push_kv_bool(&reply->data, "license_present",
                            view.license_present);
    (void)json_push_kv_int(&reply->data, "executable_files",
                           (int64_t)view.executable_count);
    zcl_hotswap_service_release(&lease);

    /* Reproduction evidence summary: the same local receipts the pointer
     * publish gate counts (boot_zcode_dht_publish_gate.c refuses unless
     * vcs_package_reproduce_scan reports reproduced=true). The persisted
     * release envelope commits the recipe root the receipts must name. An
     * unreadable envelope or a failed scan degrades this section to an
     * error string — show is a read-only view, never failed by evidence. */
    {
        char repro_path[4400];
        n = snprintf(repro_path, sizeof(repro_path), "%s/releases/%s",
                     zcode_dir, view.release_id);
        uint8_t *release_wire = NULL;
        size_t release_wire_len = 0;
        struct vcs_package_release release;
        bool envelope_ok =
            n > 0 && (size_t)n < sizeof(repro_path) &&
            zc_read_object(repro_path, VCS_PACKAGE_RELEASE_MAX_WIRE_BYTES,
                           &release_wire, &release_wire_len) &&
            vcs_package_release_parse(release_wire, release_wire_len,
                                      &release) == VCS_PACKAGE_RELEASE_OK;
        free(release_wire);
        if (!envelope_ok) {
            (void)json_push_kv_str(&reply->data, "reproduction.error",
                                   "persisted release envelope unreadable");
        } else {
            n = snprintf(repro_path, sizeof(repro_path), "%s/receipts",
                         zcode_dir);
            struct vcs_reproduce_report report;
            if (n <= 0 || (size_t)n >= sizeof(repro_path) ||
                !vcs_package_reproduce_scan(repro_path, root,
                                            release.recipe_root, &report)) {
                (void)json_push_kv_str(&reply->data, "reproduction.error",
                                       "the receipt scan failed");
            } else {
                struct json_value repro;
                json_init(&repro);
                json_set_object(&repro);
                (void)json_push_kv_int(&repro, "receipts_scanned",
                                       (int64_t)report.scanned);
                (void)json_push_kv_int(&repro, "receipts_matching",
                                       (int64_t)report.matching);
                (void)json_push_kv_bool(&repro, "reproduced",
                                        report.reproduced);
                /* The exact gate predicate the pointer publish applies. */
                (void)json_push_kv_bool(&repro, "publishable",
                                        report.reproduced);
                (void)json_push_kv_int(&repro, "distinct_toolchains",
                                       (int64_t)report.distinct_toolchains);
                (void)json_push_kv_bool(&repro, "cross_toolchain",
                                        report.cross_toolchain);
                (void)json_push_kv_bool(&repro, "rows_truncated",
                                        report.rows_truncated);
                (void)json_push_kv(&reply->data, "reproduction", &repro);
                json_free(&repro);
            }
        }
    }

    /* The bounded file page: parse the persisted manifest again (the index
     * projects summaries only; the CAS wire stays the truth). */
    if (view.manifest_present) {
        char path[4400];
        n = snprintf(path, sizeof(path), "%s/manifests/%s", zcode_dir,
                     view.package_root);
        uint8_t *wire = (n > 0 && (size_t)n < sizeof(path))
            ? zcl_malloc(VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES,
                         "zc_show_manifest")
            : NULL;
        struct vcs_package_manifest manifest;
        bool parsed = false;
        if (wire) {
            FILE *f = fopen(path, "rb");
            if (f) {
                size_t len = fread(wire, 1,
                                   VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, f);
                bool trailing = !feof(f);
                fclose(f);
                parsed = !trailing &&
                    vcs_package_manifest_parse(wire, len, &manifest);
            }
            free(wire);
        }
        if (parsed) {
            size_t shown = manifest.count < ZC_SHOW_MAX_FILES
                ? manifest.count : ZC_SHOW_MAX_FILES;
            struct json_value arr;
            json_init(&arr);
            json_set_array(&arr);
            for (size_t i = 0; i < shown; i++) {
                const struct vcs_package_file *mf = &manifest.files[i];
                struct json_value row;
                json_init(&row);
                json_set_object(&row);
                (void)json_push_kv_str(&row, "path", mf->path);
                (void)json_push_kv_int(&row, "mode", (int64_t)mf->mode);
                (void)json_push_kv_int(&row, "size", (int64_t)mf->size);
                (void)json_push_kv_int(&row, "chunks",
                                       (int64_t)mf->chunk_count);
                (void)json_push_back(&arr, &row);
                json_free(&row);
            }
            (void)json_push_kv(&reply->data, "files_page", &arr);
            json_free(&arr);
            (void)json_push_kv_bool(&reply->data, "files_truncated",
                                    manifest.count > shown);
            vcs_package_manifest_free(&manifest);
        } else {
            (void)json_push_kv_str(&reply->data, "files_page_error",
                                   "persisted manifest unreadable");
        }
    }
    vcs_package_index_free(index);
}
