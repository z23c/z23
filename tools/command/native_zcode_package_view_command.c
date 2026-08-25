/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Static host contract and no-state guide for pure package views.
 * Candidate execution is bound by the closed HOT_FORK story registry. */

#include "command/native_command.h"
#include "command/native_zcode_join.h"

#include "hotswap/hotswap_service.h"
#include "json/json.h"
#include "services/zcode_package_view_service.h"
#include "vcs/build_action.h"

#include <stdio.h>
#include <string.h>

static bool package_view_frozen_kat(const void *opaque, char *why,
                                    size_t why_sz)
{
    const struct zcode_package_view_service_v1 *service = opaque;
    struct vcs_package_index_entry entry = {0};
    struct zcode_package_view_entry_v1 rendered;
    struct zcode_package_guide_result_v1 guide;
    struct zcode_package_publish_plan_result_v1 plan;
    (void)snprintf(entry.release_id_hex, sizeof(entry.release_id_hex), "%064x",
                   1);
    (void)snprintf(entry.package_root_hex, sizeof(entry.package_root_hex),
                   "%064x", 2);
    (void)snprintf(entry.name, sizeof(entry.name), "%s", "alice/ring");
    (void)snprintf(entry.semver, sizeof(entry.semver), "%s", "1.2.3");
    (void)snprintf(entry.license, sizeof(entry.license), "%s", "Apache-2.0");
    (void)snprintf(entry.publisher_hex, sizeof(entry.publisher_hex), "%066x",
                   3);
    (void)snprintf(entry.chain_id, sizeof(entry.chain_id), "%s", "main");
    entry.publisher_sequence = 7;
    entry.manifest_present = true;
    entry.file_count = 12;
    entry.total_bytes = 3456;
    entry.chunk_total = 4;
    entry.license_present = true;
    entry.executable_count = 1;
    if (!service || !service->render_entry || !service->render_guide ||
        !service->render_publish_plan ||
        !service->render_entry(&entry, &rendered) || !rendered.valid ||
        strcmp(rendered.name, "alice/ring") != 0 ||
        strcmp(rendered.semver, "1.2.3") != 0 ||
        strcmp(rendered.license, "Apache-2.0") != 0 ||
        rendered.publisher_sequence != 7 || !rendered.manifest_present ||
        rendered.file_count != 12 || rendered.total_bytes != 3456 ||
        rendered.chunk_total != 4 || !rendered.license_present ||
        rendered.executable_count != 1 ||
        !service->render_guide(&guide) || !guide.cas_authority_static ||
        !guide.index_reads_static || !guide.publication_static ||
        !guide.execution_static) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen package entry/authority vector failed");
        return false;
    }
    const struct zcode_package_publish_plan_input_v1 ready = {
        .validation_complete = true,
        .chunks_checked = true,
        .failure_count = 0,
    };
    if (!service->render_publish_plan(&ready, &plan) || !plan.valid ||
        !plan.ready_to_commit || strcmp(plan.stage, "plan") != 0 ||
        strcmp(plan.readiness, "ready_to_commit") != 0 ||
        strcmp(plan.next_action, "zcode package publish commit") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen ready-to-commit plan vector failed");
        return false;
    }
    const struct zcode_package_publish_plan_input_v1 needs_source = {
        .validation_complete = true,
        .chunks_checked = false,
        .failure_count = 0,
    };
    if (!service->render_publish_plan(&needs_source, &plan) || !plan.valid ||
        plan.ready_to_commit ||
        strcmp(plan.readiness, "needs_chunk_source") != 0 ||
        strcmp(plan.next_action,
               "rerun zcode package publish plan with dir") != 0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen missing-chunk-source plan vector failed");
        return false;
    }
    const struct zcode_package_publish_plan_input_v1 blocked = {
        .validation_complete = true,
        .chunks_checked = true,
        .failure_count = 2,
    };
    if (!service->render_publish_plan(&blocked, &plan) || plan.valid ||
        plan.ready_to_commit || strcmp(plan.readiness, "blocked") != 0 ||
        strcmp(plan.next_action,
               "fix the first reported failure, then rerun zcode package publish plan") !=
            0) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen blocked plan vector failed");
        return false;
    }
    const struct zcode_package_publish_plan_input_v1 incomplete = {0};
    if (service->render_publish_plan(&incomplete, &plan)) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "incomplete validation plan vector was accepted");
        return false;
    }
    entry.release_id_hex[0] = '\0';
    if (!service->render_entry(&entry, &rendered) || rendered.valid) {
        if (why && why_sz) (void)snprintf(
            why, why_sz, "frozen incomplete package-entry vector failed");
        return false;
    }
    return true;
}

static const struct zcl_hotswap_service_contract k_package_view_contract = {
    .service_id = ZCODE_PACKAGE_VIEW_SERVICE_ID,
    .source_tu = "app/services/src/zcode_package_view_service.c",
    .abi_version = ZCL_HOTSWAP_SERVICE_ABI_V1,
    .vtable_size = sizeof(struct zcode_package_view_service_v1),
    .abi_fingerprint = ZCODE_PACKAGE_VIEW_ABI_FINGERPRINT,
    .schema_fingerprint = ZCODE_PACKAGE_VIEW_SCHEMA_FINGERPRINT,
    .wire_fingerprint = ZCODE_PACKAGE_VIEW_WIRE_FINGERPRINT,
    .kat_fingerprint = ZCODE_PACKAGE_VIEW_KAT_FINGERPRINT,
    .frozen_kat = package_view_frozen_kat,
};

const struct zcl_hotswap_service_contract *
zcl_native_zcode_package_view_service_contract(void)
{
    return &k_package_view_contract;
}

static void package_guide_step(struct json_value *steps, const char *command,
                               const char *subject,
                               const char *status, const char *evidence,
                               const char *next)
{
    struct json_value step;
    json_init(&step);
    json_set_object(&step);
    (void)json_push_kv_str(&step, "command", command);
    (void)json_push_kv_str(&step, "subject", subject);
    (void)json_push_kv_str(&step, "status", status);
    (void)json_push_kv_str(&step, "evidence", evidence);
    (void)json_push_kv_str(&step, "next", next);
    (void)json_push_back(steps, &step);
    json_free(&step);
}

static void package_guide_journeys(struct json_value *data)
{
    struct json_value author;
    json_init(&author);
    json_set_array(&author);
    package_guide_step(
        &author, "zclassic23-package-sign --generate <key>",
        "publisher_pubkey", "local-author-key-created", "public key only",
        "zcode package dev prepare");
    package_guide_step(
        &author, "zcode package dev prepare",
        "package, recipe and dependency-lock roots", "unsigned",
        "manifest, API and signing roots", "offline sign, then seal");
    package_guide_step(
        &author, "zcode package dev seal",
        "release_id for the exact package_root", "author-signed",
        "verified detached author signature", "zcode create plan, then commit");
    package_guide_step(
        &author, "zcode create (plan, then commit)",
        "package_root + transport_root", "locally-available",
        "verified CAS admission", "install and reproduce on this node");
    package_guide_step(
        &author, "zcode use, then zcode package reproduce",
        "package_root", "locally-reproduced",
        "two distinct byte-identical build receipts filed",
        "announce pointer and provider records");
    package_guide_step(
        &author, "zcode network publish (pointer/provider plan+commit)",
        "package_root -> transport_root", "availability-claimed",
        "signed record_root and record_wire", "share package_root with consumers");

    struct json_value consumer;
    json_init(&consumer);
    json_set_array(&consumer);
    package_guide_step(
        &consumer, "zcode network records",
        "user-supplied package_root",
        "signed-pointer-discovered", "verified pointer/provider records",
        "select transport_root; package search is local");
    package_guide_step(
        &consumer, "zcode package fetch", "transport_root",
        "inert-fetch-or-resume", "verified chunks and reconstructed package_root",
        "repeat idempotently until reconstructed=true");
    package_guide_step(
        &consumer, "zcode package show", "package_root", "verified-local",
        "release, recipe, dependency and publisher roots", "zcode use by root");
    package_guide_step(
        &consumer, "zcode use (plan, then commit)", "package_root + lock_root",
        "explicitly-built-tested-installed", "build receipt and artifact roots",
        "link the installed static archive from local policy");

    struct json_value reproducer;
    json_init(&reproducer);
    json_set_array(&reproducer);
    package_guide_step(
        &reproducer, "zcode use on a second installed node",
        "same package, lock and target/profile", "independent-local-run",
        "second receipt and artifact roots", "compare exact observations");
    package_guide_step(
        &reproducer, "zcode package verify", "package_root",
        "match-or-named-mismatch", "locally filed reproduction observations",
        "accept or reject under local policy");
    package_guide_step(
        &reproducer, "zcode evidence --input={action_id,...}",
        "an exact async action_id, not a package name", "signed-worker-evidence",
        "signer, inputs, output root and latency",
        "do not relabel candidate evidence as released-package evidence");

    (void)json_push_kv(data, "author", &author);
    (void)json_push_kv(data, "consumer", &consumer);
    (void)json_push_kv(data, "reproducer", &reproducer);
    json_free(&author);
    json_free(&consumer);
    json_free(&reproducer);
}

void zcl_native_handle_zcode_package_guide(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    if (!request || !request->input || !reply ||
        request->input->type != JSON_OBJ || request->input->num_children != 0) {
        if (reply) zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "BAD_PACKAGE_GUIDE_INPUT", "validate", false, false,
            "zcode package guide accepts no input keys",
            "zcode.package.guide");
        return;
    }
    struct zcl_hotswap_service_lease lease = {0};
    const struct zcode_package_view_service_v1 *service =
        zcl_hotswap_service_acquire(ZCODE_PACKAGE_VIEW_SERVICE_ID, &lease);
    if (!service) service = zcode_package_view_service_builtin();
    struct zcode_package_guide_result_v1 guide;
    if (!service->render_guide(&guide)) {
        zcl_hotswap_service_release(&lease);
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
            "PACKAGE_VIEW_FAILED", "render", false, false,
            "the pure package view service refused guide rendering",
            "zcode.package.guide");
        return;
    }
    (void)json_push_kv_str(&reply->data, "service_id",
                           ZCODE_PACKAGE_VIEW_SERVICE_ID);
    (void)json_push_kv_int(&reply->data, "service_generation",
                           zcl_hotswap_service_generation());
    (void)json_push_kv_bool(&reply->data, "cas_authority_static",
                            guide.cas_authority_static);
    (void)json_push_kv_bool(&reply->data, "index_reads_static",
                            guide.index_reads_static);
    (void)json_push_kv_bool(&reply->data, "publication_static",
                            guide.publication_static);
    (void)json_push_kv_bool(&reply->data, "execution_static",
                            guide.execution_static);
    (void)json_push_kv_str(&reply->data, "live_surface", guide.live_surface);
    (void)json_push_kv_str(&reply->data, "static_boundary",
                           guide.static_boundary);
    (void)json_push_kv_str(&reply->data, "next_command", guide.next_command);
    (void)json_push_kv_str(&reply->data, "preflight",
                           "zcode network status");
    {
        struct zcl_zcode_join_posture join;
        if (!zcl_zcode_join_posture_fill(&join) ||
            !zcl_zcode_join_posture_push_json(&reply->data, &join)) {
            zcl_hotswap_service_release(&lease);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
                "JOIN_POSTURE_FAILED", "render", false, false,
                "the Commons join posture could not be rendered",
                "zcode.package.guide");
            return;
        }
    }
    (void)json_push_kv_str(
        &reply->data, "disabled_network_next",
        "zcode network delegate with an active finalized ZID master");
    (void)json_push_kv_str(
        &reply->data, "policy_requirement",
        "allow zclassic23.package with zcode network policy mutate plan/commit, then restart");
    (void)json_push_kv_str(
        &reply->data, "identity_rule",
        "name and semver select; package_root is exact identity");
    (void)json_push_kv_str(
        &reply->data, "verification_rule",
        "verify roots and evidence locally; never trust identity or arrival order");
    (void)json_push_kv_str(
        &reply->data, "authority_not_granted",
        "evidence does not prove general safety, usefulness or human acceptance");
    (void)json_push_kv_bool(&reply->data, "fetch_executes", false);
    (void)json_push_kv_bool(&reply->data, "remote_name_search", false);
    (void)json_push_kv_str(
        &reply->data, "package_root_entry",
        "obtain package_root separately, then discover signed DHT records by root");
    (void)json_push_kv_bool(&reply->data, "source_identity_portable", true);
    (void)json_push_kv_str(&reply->data, "current_build_target",
                           VCS_BUILD_TARGET_V1);
    (void)json_push_kv_bool(&reply->data, "other_build_targets_proven", false);
    (void)json_push_kv_str(
        &reply->data, "signed_released_package_reproduction",
        "not exposed: signed async evidence binds candidates; local receipts bind releases");
    package_guide_journeys(&reply->data);
    zcl_hotswap_service_release(&lease);
}
