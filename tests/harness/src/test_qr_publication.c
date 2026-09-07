/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * qr scenario checks: publication/release confirm flows,
 * reproduction/package progress, bounded-table rendering, typed command
 * dispatch, shared presentation/text paging, and the visual
 * command-smuggling guard.
 *
 * Split out of test_qr.c (which keeps the includes and the group entry
 * point) so no family member crosses the 1,500-line ceiling. Every
 * scenario grades itself through QR_CHECK, shared via qr_failures_ptr()
 * — see test_qr_priv.h. */

#include "encoding/qr.h"
#include "command/native_command.h"
#include "json/json.h"
#include "presentation/canvas.h"
#include "presentation/model.h"
#include "presentation/model_render.h"
#include "presentation/model_text.h"
#include "presentation/presentation.h"
#include "presentation/zclassic_brand.h"
#include "views/qr_popup.h"
#include "views/ui_present.h"
#include "views/ui_present_document.h"
#include "views/ui_present_host_transport.h"
#include "vcs/zcode_work_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "test/test_qr_priv.h"


static void qr_reproduction_facts(struct json_value *facts,
                                  const char *action, const char *candidate,
                                  const char *event, const char *receipt,
                                  const char *state)
{
    json_init(facts); json_set_object(facts);
    json_push_kv_str(facts, "schema", "zcl.build_fabric_action_state.v1");
    json_push_kv_bool(facts, "found", true);
    json_push_kv_bool(facts, "event_root_rederived", true);
    json_push_kv_str(facts, "action_id", action);
    json_push_kv_str(facts, "candidate_root", candidate);
    json_push_kv_str(facts, "event_root", event);
    json_push_kv_str(facts, "receipt_root", receipt);
    json_push_kv_str(facts, "state", state);
}

static void qr_publication_records(struct json_value *projection,
                                   const char *kind,
                                   const char *package_root,
                                   const char *transport_root,
                                   const char *provider_node_id,
                                   bool include)
{
    json_init(projection); json_set_object(projection);
    json_push_kv_bool(projection, "local_projection", true);
    struct json_value records;
    json_init(&records); json_set_array(&records);
    if (include) {
        struct json_value row;
        json_init(&row); json_set_object(&row);
        json_push_kv_str(&row, "kind", kind);
        json_push_kv_str(&row, "record_root", package_root);
        json_push_kv_str(&row, "namespace", "zclassic23.package");
        json_push_kv_str(&row, "semantic_root", package_root);
        json_push_kv_str(&row, "transport_root", transport_root);
        json_push_kv_str(&row, "provider_node_id", provider_node_id);
        json_push_back(&records, &row);
        json_free(&row);
    }
    json_push_kv(projection, "records", &records);
    json_free(&records);
}

static void qr_publication_facts(struct json_value *facts,
                                 const char *package_root,
                                 const char *transport_root,
                                 const char *confirmation_identity,
                                 const char *local_node_id,
                                 const char *record_node_id,
                                 bool local_complete, bool pointer,
                                 bool provider, bool download_complete,
                                 int64_t fetched_bytes)
{
    json_init(facts); json_set_object(facts);
    json_push_kv_str(facts, "schema", "zcl.package_publication_facts.v1");
    json_push_kv_str(facts, "package_root", package_root);
    json_push_kv_str(facts, "transport_root", transport_root);
    json_push_kv_str(facts, "confirmation_identity", confirmation_identity);
    json_push_kv_str(facts, "local_node_id", local_node_id);
    json_push_kv_bool(facts, "local_package_committed", local_complete);
    struct json_value package, local, download;
    json_init(&package); json_set_object(&package);
    json_init(&local); json_set_object(&local);
    json_push_kv_bool(&local, "found", local_complete);
    json_push_kv_bool(&local, "complete", local_complete);
    json_push_kv(&package, "local_package", &local);
    json_free(&local);
    json_push_kv_bool(&package, "download_found", download_complete);
    if (download_complete) {
        json_init(&download); json_set_object(&download);
        json_push_kv_str(&download, "state", "complete");
        json_push_kv_int(&download, "present_chunks", 3);
        json_push_kv_int(&download, "total_chunks", 3);
        json_push_kv_int(&download, "present_bytes", 4096);
        json_push_kv_int(&download, "total_bytes", 4096);
        json_push_kv_int(&download, "fetched_bytes", fetched_bytes);
        json_push_kv(&package, "download", &download);
        json_free(&download);
    }
    json_push_kv(facts, "package", &package);
    json_free(&package);
    struct json_value pointers, providers;
    qr_publication_records(&pointers, "pointer", package_root,
                           transport_root, record_node_id, pointer);
    qr_publication_records(&providers, "provider", package_root,
                           transport_root, record_node_id, provider);
    json_push_kv(facts, "pointer_records", &pointers);
    json_push_kv(facts, "provider_records", &providers);
    json_free(&pointers);
    json_free(&providers);
}

static void qr_fill_roots(char root_a[65], char root_b[65], char tree_root[65])
{
    memset(root_a, 'a', 64u); root_a[64] = '\0';
    memset(root_b, 'b', 64u); root_b[64] = '\0';
    memset(tree_root, 'c', 64u); tree_root[64] = '\0';
}

static void qr_fill_long_table(struct zcl_present_model_v1 *long_table)
{
    uint32_t i;
    zcl_present_model_init_v1(long_table, ZCL_PRESENT_MODEL_TABLE);
    (void)snprintf(long_table->request_id, sizeof(long_table->request_id),
                   "bounded-table-64");
    (void)snprintf(long_table->title, sizeof(long_table->title),
                   "Every bounded row is reachable");
    long_table->item_count = ZCL_PRESENT_MODEL_ITEMS_MAX;
    for (i = 0; i < long_table->item_count; i++) {
        long_table->items[i].kind = ZCL_PRESENT_ITEM_TABLE_ROW;
        long_table->items[i].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        (void)snprintf(long_table->items[i].id,
                       sizeof(long_table->items[i].id), "row-%u", i + 1u);
        (void)snprintf(long_table->items[i].label,
                       sizeof(long_table->items[i].label), "Owner %u", i + 1u);
        (void)snprintf(long_table->items[i].value,
                       sizeof(long_table->items[i].value), "Exact value %u",
                       i + 1u);
    }
}
void qr_case_unchanged_candidate_bytes(void)
{
    char why[128];
    static const uint8_t code_before[] =
        "#include \"presentation/model.h\"\n"
        "int exact_value(void) {\n"
        "    return 1;\n"
        "}\n";
    char root_a[65], root_b[65], tree_root[65];
    qr_fill_roots(root_a, root_b, tree_root);
    struct zcl_present_model_v1 code_model;
    QR_CHECK("unchanged candidate bytes cannot masquerade as a code change",
             !zcl_native_presentation_code_change_model_from_facts(
                 code_before, sizeof(code_before) - 1u,
                 code_before, sizeof(code_before) - 1u,
                 "tools/command/native_qr_command.c", "return two",
                 "returned one", "returns two", root_a, root_a, tree_root,
                 &code_model, why, sizeof(why)));
}

void qr_case_publication_confirm(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    qr_fill_roots(root_a, root_b, tree_root);
    struct json_value publication_plan, publication_release;
    struct json_value publication_package;
    json_init(&publication_plan); json_set_object(&publication_plan);
    json_push_kv_bool(&publication_plan, "valid", true);
    json_push_kv_bool(&publication_plan, "ready_to_commit", true);
    json_push_kv_str(&publication_plan, "plan_token", root_a);
    json_init(&publication_release); json_set_object(&publication_release);
    json_push_kv_str(&publication_release, "name", "stranger/hello-c23");
    json_push_kv_str(&publication_release, "semver", "1.0.0");
    json_push_kv_str(&publication_release, "license", "Apache-2.0");
    json_push_kv(&publication_plan, "release", &publication_release);
    json_free(&publication_release);
    json_init(&publication_package); json_set_object(&publication_package);
    json_push_kv_str(&publication_package, "package_root", root_b);
    json_push_kv_int(&publication_package, "files", 3);
    json_push_kv_int(&publication_package, "bytes", 4096);
    json_push_kv_int(&publication_package, "chunks", 3);
    json_push_kv_bool(&publication_package, "chunks_checked", true);
    json_push_kv(&publication_plan, "package", &publication_package);
    json_free(&publication_package);
    struct zcl_present_model_v1 publication_model;
    QR_CHECK("canonical package plan builds exact inert confirmation",
             zcl_native_presentation_publication_confirm_model_from_plan(
                 &publication_plan, &publication_model,
                 why, sizeof(why)) &&
             publication_model.kind == ZCL_PRESENT_MODEL_CONFIRMATION &&
             strcmp(publication_model.exact_root, root_a) == 0 &&
             publication_model.item_count == 13 &&
             publication_model.action_count == 2 &&
             publication_model.actions[0].kind ==
                 ZCL_PRESENT_ACTION_CANCEL &&
             publication_model.actions[1].kind ==
                 ZCL_PRESENT_ACTION_CONFIRM);
    json_free(&publication_plan);
}

void qr_case_publication_confirm_chrome(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    qr_fill_roots(root_a, root_b, tree_root);
    struct json_value publication_plan, publication_release;
    struct json_value publication_package;
    json_init(&publication_plan); json_set_object(&publication_plan);
    json_push_kv_bool(&publication_plan, "valid", true);
    json_push_kv_bool(&publication_plan, "ready_to_commit", true);
    json_push_kv_str(&publication_plan, "plan_token", root_a);
    json_init(&publication_release); json_set_object(&publication_release);
    json_push_kv_str(&publication_release, "name", "stranger/hello-c23");
    json_push_kv_str(&publication_release, "semver", "1.0.0");
    json_push_kv_str(&publication_release, "license", "Apache-2.0");
    json_push_kv(&publication_plan, "release", &publication_release);
    json_free(&publication_release);
    json_init(&publication_package); json_set_object(&publication_package);
    json_push_kv_str(&publication_package, "package_root", root_b);
    json_push_kv_int(&publication_package, "files", 3);
    json_push_kv_int(&publication_package, "bytes", 4096);
    json_push_kv_int(&publication_package, "chunks", 3);
    json_push_kv_bool(&publication_package, "chunks_checked", true);
    json_push_kv(&publication_plan, "package", &publication_package);
    json_free(&publication_package);
    struct zcl_present_model_v1 publication_model;
    (void)zcl_native_presentation_publication_confirm_model_from_plan(
        &publication_plan, &publication_model, why, sizeof(why));
    QR_CHECK("canonical confirmation focuses the harmless decision first",
             strcmp(publication_model.actions[0].id, "cancel") == 0 &&
             strcmp(publication_model.actions[1].id, "confirm") == 0);
    QR_CHECK("confirmation chrome and effect text are Z23-authored",
             strcmp(publication_model.actions[0].label,
                    "Cancel - make no change") == 0 &&
             strcmp(publication_model.actions[1].label,
                    "Confirm exact local commit") == 0 &&
             strncmp(publication_model.items[0].label,
                     "LOCAL OBSERVATION - ", 20) == 0 &&
             strstr(publication_model.summary, "HUMAN DECISION - ") != NULL);
    json_free(&publication_plan);
}

void qr_case_publication_evidence_boundaries(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    qr_fill_roots(root_a, root_b, tree_root);
    struct json_value publication_plan, publication_release;
    struct json_value publication_package;
    json_init(&publication_plan); json_set_object(&publication_plan);
    json_push_kv_bool(&publication_plan, "valid", true);
    json_push_kv_bool(&publication_plan, "ready_to_commit", true);
    json_push_kv_str(&publication_plan, "plan_token", root_a);
    json_init(&publication_release); json_set_object(&publication_release);
    json_push_kv_str(&publication_release, "name", "stranger/hello-c23");
    json_push_kv_str(&publication_release, "semver", "1.0.0");
    json_push_kv_str(&publication_release, "license", "Apache-2.0");
    json_push_kv(&publication_plan, "release", &publication_release);
    json_free(&publication_release);
    json_init(&publication_package); json_set_object(&publication_package);
    json_push_kv_str(&publication_package, "package_root", root_b);
    json_push_kv_int(&publication_package, "files", 3);
    json_push_kv_int(&publication_package, "bytes", 4096);
    json_push_kv_int(&publication_package, "chunks", 3);
    json_push_kv_bool(&publication_package, "chunks_checked", true);
    json_push_kv(&publication_plan, "package", &publication_package);
    json_free(&publication_package);
    struct zcl_present_model_v1 publication_model;
    (void)zcl_native_presentation_publication_confirm_model_from_plan(
        &publication_plan, &publication_model, why, sizeof(why));
    QR_CHECK("confirmation names every later publication evidence boundary",
             strcmp(publication_model.items[7].value,
                    "Pending this exact decision") == 0 &&
             strcmp(publication_model.items[8].value,
                    "Not started - separate commit required") == 0 &&
             strcmp(publication_model.items[9].value, "Not observed") == 0 &&
             strcmp(publication_model.items[10].value, "Not observed") == 0 &&
             strcmp(publication_model.items[11].value, "Not observed") == 0 &&
             strcmp(publication_model.items[12].value, "Not observed") == 0);
    json_free(&publication_plan);
    json_init(&publication_plan); json_set_object(&publication_plan);
    QR_CHECK("agent facts alone cannot fabricate a ready confirmation",
             !zcl_native_presentation_publication_confirm_model_from_plan(
                 &publication_plan, &publication_model,
                 why, sizeof(why)));
    json_free(&publication_plan);
}

void qr_case_release_confirm(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    qr_fill_roots(root_a, root_b, tree_root);
    struct json_value release_status, release_expert, release_evidence;
    json_init(&release_status); json_set_object(&release_status);
    json_push_kv_str(&release_status, "state", "EVIDENCE_READY");
    json_push_kv_str(&release_status, "goal",
                     "Reject an empty note before hashing");
    json_init(&release_expert); json_set_object(&release_expert);
    json_push_kv_str(&release_expert, "task_root", root_a);
    json_push_kv_str(&release_expert, "candidate_root", root_b);
    json_push_kv_str(&release_expert, "proof_policy_root", tree_root);
    json_push_kv_str(&release_status, "work_id", "work-aaaaaaaaaaaa");
    json_push_kv(&release_status, "expert", &release_expert);
    json_free(&release_expert);
    json_init(&release_evidence); json_set_object(&release_evidence);
    json_push_kv_str(&release_evidence, "proof_set_root", root_a);
    json_push_kv_str(&release_evidence, "authority",
                     "LOCAL_CLEAN_SHADOW");
    json_push_kv_int(&release_evidence, "compile_receipts", 2);
    json_push_kv_int(&release_evidence, "test_receipts", 2);
    json_push_kv_int(&release_evidence, "approved_distinct_signers", 2);
    json_push_kv_bool(&release_evidence, "local_reproduced", true);
    json_push_kv_bool(&release_evidence, "quorum_satisfied", true);
    json_push_kv_bool(&release_evidence, "compile_satisfied", true);
    json_push_kv_bool(&release_evidence, "test_satisfied", true);
    json_push_kv_bool(&release_evidence, "policy_satisfied", true);
    struct zcl_present_model_v1 release_model;
    char release_identity[65], changed_release_identity[65];
    QR_CHECK("proven candidate facts build one exact inert release decision",
             zcl_native_presentation_release_confirm_model_from_facts(
                 &release_status, &release_evidence, &release_model,
                 release_identity, why, sizeof(why)) &&
             release_model.kind == ZCL_PRESENT_MODEL_CONFIRMATION &&
             strcmp(release_model.exact_root, release_identity) == 0 &&
             release_model.action_count == 2 &&
             release_model.actions[0].kind == ZCL_PRESENT_ACTION_CANCEL &&
             release_model.actions[1].kind == ZCL_PRESENT_ACTION_CONFIRM &&
             strstr(release_model.items[0].value,
                    "source and network stay unchanged") != NULL);
    struct json_value *candidate_value = (struct json_value *)json_get(
        json_get(&release_status, "expert"), "candidate_root");
    json_set_str(candidate_value, tree_root);
    QR_CHECK("changed candidate bytes change the human decision identity",
             zcl_native_presentation_release_confirm_model_from_facts(
                 &release_status, &release_evidence, &release_model,
                 changed_release_identity, why, sizeof(why)) &&
             strcmp(release_identity, changed_release_identity) != 0);
    json_set_str(candidate_value, root_b);
    json_set_bool((struct json_value *)json_get(
                      &release_evidence, "policy_satisfied"), false);
    QR_CHECK("incomplete proof policy cannot fabricate release confirmation",
             !zcl_native_presentation_release_confirm_model_from_facts(
                 &release_status, &release_evidence, &release_model,
                 release_identity, why, sizeof(why)));
    json_free(&release_evidence);
    json_free(&release_status);
}

void qr_case_publication_local_commit(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    qr_fill_roots(root_a, root_b, tree_root);
    struct json_value publication_facts;
    struct zcl_present_model_v1 publication_status;
    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_a, true, false, false, false, 0);
    QR_CHECK("local commit alone cannot fabricate network publication",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.item_count == 6 &&
             publication_status.items[0].numerator == 0 &&
             publication_status.items[1].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[2].status == ZCL_PRESENT_STATUS_NEUTRAL &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_NEUTRAL &&
             strcmp(publication_status.request_id,
                    "publish-aaaaaaaaaaaa") == 0);
    json_free(&publication_facts);
}

void qr_case_publication_pointer_and_self(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    qr_fill_roots(root_a, root_b, tree_root);
    struct json_value publication_facts;
    struct zcl_present_model_v1 publication_status;
    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_a, true, true, false, false, 0);
    QR_CHECK("signed pointer advances only its exact evidence stage",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[2].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[3].status == ZCL_PRESENT_STATUS_NEUTRAL &&
             publication_status.items[4].status == ZCL_PRESENT_STATUS_NEUTRAL);
    json_free(&publication_facts);

    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_a, true, true, true, true, 4096);
    QR_CHECK("self-published records cannot masquerade as peer discovery",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[2].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[3].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[4].status == ZCL_PRESENT_STATUS_NEUTRAL &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_NEUTRAL);
    json_free(&publication_facts);
}

void qr_case_publication_peer_fetch(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    qr_fill_roots(root_a, root_b, tree_root);
    struct json_value publication_facts;
    struct zcl_present_model_v1 publication_status;
    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_b, true, true, true, false, 0);
    QR_CHECK("matching non-self signed records prove peer discovery only",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[4].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_NEUTRAL);
    json_free(&publication_facts);

    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_b, true, true, true, true, 4096);
    QR_CHECK("exact imported peer bytes complete only the final stage",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[5].numerator == 1 &&
             publication_status.items[0].numerator == 0);
    json_free(&publication_facts);

    qr_publication_facts(&publication_facts, root_b, tree_root, root_a,
                         root_a, root_b, true, true, true, true, 0);
    QR_CHECK("CAS completion without received peer bytes is not a peer fetch",
             zcl_native_presentation_publication_status_model_from_facts(
                 &publication_facts, &publication_status,
                 why, sizeof(why)) &&
             publication_status.items[4].status == ZCL_PRESENT_STATUS_GREEN &&
             publication_status.items[5].status == ZCL_PRESENT_STATUS_NEUTRAL);
    json_free(&publication_facts);
}

void qr_case_reproduction_progress(void)
{
    char why[128];
    char root_a[65], root_b[65], tree_root[65];
    qr_fill_roots(root_a, root_b, tree_root);
    struct json_value reproduction_facts;
    qr_reproduction_facts(&reproduction_facts, root_a, tree_root, root_b,
                          "", "RUNNING");
    struct zcl_present_model_v1 reproduction_model;
    QR_CHECK("canonical running event builds six fixed progress stages",
             zcl_native_presentation_reproduction_model_from_facts(
                 &reproduction_facts, &reproduction_model,
                 why, sizeof(why)) &&
             reproduction_model.kind == ZCL_PRESENT_MODEL_PROGRESS &&
             reproduction_model.item_count == 6 &&
             reproduction_model.items[2].numerator == 1 &&
             reproduction_model.items[3].numerator == 0);
    char running_request_id[ZCL_PRESENT_MODEL_ID_MAX + 1u];
    (void)snprintf(running_request_id, sizeof(running_request_id), "%s",
                   reproduction_model.request_id);
    json_free(&reproduction_facts);
    qr_reproduction_facts(&reproduction_facts, root_a, tree_root, root_b,
                          root_b, "REPRODUCED");
    QR_CHECK("matching evidence updates the same action-bound window",
             zcl_native_presentation_reproduction_model_from_facts(
                 &reproduction_facts, &reproduction_model,
                 why, sizeof(why)) &&
             strcmp(reproduction_model.request_id, running_request_id) == 0 &&
             reproduction_model.items[5].numerator == 1 &&
             reproduction_model.items[5].status == ZCL_PRESENT_STATUS_GREEN);
    json_free(&reproduction_facts);
    qr_reproduction_facts(&reproduction_facts, root_a, tree_root, root_b,
                          root_b, "REMOTE_RED");
    QR_CHECK("remote mismatch stays a named red output refusal",
             zcl_native_presentation_reproduction_model_from_facts(
                 &reproduction_facts, &reproduction_model,
                 why, sizeof(why)) &&
             reproduction_model.items[3].status == ZCL_PRESENT_STATUS_RED &&
             strstr(reproduction_model.summary, "named refusal") != NULL);
    json_free(&reproduction_facts);
}

void qr_case_package_worker_diagnostic(void)
{
    struct json_value work_dump;
    json_init(&work_dump);
    vcs_zcode_work_node_set_global(NULL);
    QR_CHECK("package-worker diagnostic reports exact disabled capacity",
             vcs_zcode_work_node_dump_state_json(&work_dump, NULL) &&
             !json_get_bool(json_get(&work_dump, "enabled")) &&
             json_get_int(json_get(&work_dump, "worker_capacity")) == 0 &&
             json_get_int(json_get(&work_dump, "worker_available")) == 0 &&
             json_get_int(json_get(&work_dump, "capable_peers")) == 0 &&
             strstr(json_get_str(json_get(&work_dump, "next_action")),
                    "z23 join") != NULL &&
             strstr(json_get_str(json_get(&work_dump, "next_action")),
                    "-buildworker=1") == NULL);
    json_free(&work_dump);
}

void qr_case_progress_native_pixels(void)
{
    char why[128];
    struct zcl_present_model_v1 visual;
    zcl_present_model_init_v1(&visual, ZCL_PRESENT_MODEL_PROGRESS);
    (void)snprintf(visual.request_id, sizeof(visual.request_id),
                   "reproduce-42");
    (void)snprintf(visual.title, sizeof(visual.title),
                   "Independent reproduction");
    (void)snprintf(visual.summary, sizeof(visual.summary),
                   "Builder two is reproducing the exact candidate bytes.");
    visual.item_count = 1;
    visual.items[0].kind = ZCL_PRESENT_ITEM_PROGRESS;
    visual.items[0].status = ZCL_PRESENT_STATUS_INFO;
    visual.items[0].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    visual.items[0].numerator = 7;
    visual.items[0].denominator = 10;
    (void)snprintf(visual.items[0].id, sizeof(visual.items[0].id),
                   "builder-two");
    (void)snprintf(visual.items[0].label, sizeof(visual.items[0].label),
                   "Builder two");
    (void)snprintf(visual.items[0].value, sizeof(visual.items[0].value),
                   "Compiling");
    visual.action_count = 1;
    visual.actions[0].kind = ZCL_PRESENT_ACTION_CLOSE;
    (void)snprintf(visual.actions[0].id, sizeof(visual.actions[0].id),
                   "close");
    (void)snprintf(visual.actions[0].label,
                   sizeof(visual.actions[0].label), "Close");
    struct zcl_present_model_bitmap_v1 visual_bitmap;
    QR_CHECK("renderer-neutral progress card becomes native RGB pixels",
             zcl_present_model_render_v1(
                 &visual, &visual_bitmap, why, sizeof(why)) &&
             visual_bitmap.pixels &&
             visual_bitmap.width == ZCL_PRESENT_MODEL_BITMAP_WIDTH &&
             visual_bitmap.height == ZCL_PRESENT_MODEL_BITMAP_HEIGHT);
    bool visual_has_orange = false;
    bool visual_has_info = false;
    for (size_t i = 0; visual_bitmap.pixels &&
         i < ZCL_PRESENT_MODEL_BITMAP_BYTES; i += 3u) {
        visual_has_orange |= visual_bitmap.pixels[i] == 0xc8 &&
            visual_bitmap.pixels[i + 1u] == 0x70 &&
            visual_bitmap.pixels[i + 2u] == 0x35;
        visual_has_info |= visual_bitmap.pixels[i] == 0x32 &&
            visual_bitmap.pixels[i + 1u] == 0x68 &&
            visual_bitmap.pixels[i + 2u] == 0x91;
    }
    QR_CHECK("native model pixels preserve brand and semantic status",
             visual_has_orange && visual_has_info);
    zcl_present_model_bitmap_free_v1(&visual_bitmap);
}

void qr_case_bounded_table_pages(void)
{
    char why[128];
    struct zcl_present_model_v1 long_table;
    zcl_present_model_init_v1(&long_table, ZCL_PRESENT_MODEL_TABLE);
    (void)snprintf(long_table.request_id, sizeof(long_table.request_id),
                   "bounded-table-64");
    (void)snprintf(long_table.title, sizeof(long_table.title),
                   "Every bounded row is reachable");
    long_table.item_count = ZCL_PRESENT_MODEL_ITEMS_MAX;
    for (uint32_t i = 0; i < long_table.item_count; i++) {
        long_table.items[i].kind = ZCL_PRESENT_ITEM_TABLE_ROW;
        long_table.items[i].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        (void)snprintf(long_table.items[i].id,
                       sizeof(long_table.items[i].id), "row-%u", i + 1u);
        (void)snprintf(long_table.items[i].label,
                       sizeof(long_table.items[i].label), "Owner %u", i + 1u);
        (void)snprintf(long_table.items[i].value,
                       sizeof(long_table.items[i].value), "Exact value %u",
                       i + 1u);
    }
    uint32_t table_pages = 0;
    QR_CHECK("maximum bounded table partitions into eight exact pages",
             zcl_present_model_page_count_v1(
                 &long_table, &table_pages, why, sizeof(why)) &&
             table_pages == 8u);
    struct ui_present_document table_document;
    QR_CHECK("resident and cold hosts receive the same complete page set",
             ui_present_document_from_model(
                 &long_table, &table_document, why, sizeof(why)) &&
             table_document.page_count == table_pages &&
             table_document.windows[0].pixels ==
                 table_document.bitmaps[0].pixels &&
             table_document.windows[table_pages - 1u].pixels ==
                 table_document.bitmaps[table_pages - 1u].pixels &&
             memcmp(table_document.windows[0].pixels,
                    table_document.windows[table_pages - 1u].pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    ui_present_document_free(&table_document);
}

void qr_case_bounded_table_text(void)
{
    char why[128];
    struct zcl_present_model_v1 long_table;
    zcl_present_model_init_v1(&long_table, ZCL_PRESENT_MODEL_TABLE);
    (void)snprintf(long_table.request_id, sizeof(long_table.request_id),
                   "bounded-table-64");
    (void)snprintf(long_table.title, sizeof(long_table.title),
                   "Every bounded row is reachable");
    long_table.item_count = ZCL_PRESENT_MODEL_ITEMS_MAX;
    for (uint32_t i = 0; i < long_table.item_count; i++) {
        long_table.items[i].kind = ZCL_PRESENT_ITEM_TABLE_ROW;
        long_table.items[i].parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
        (void)snprintf(long_table.items[i].id,
                       sizeof(long_table.items[i].id), "row-%u", i + 1u);
        (void)snprintf(long_table.items[i].label,
                       sizeof(long_table.items[i].label), "Owner %u", i + 1u);
        (void)snprintf(long_table.items[i].value,
                       sizeof(long_table.items[i].value), "Exact value %u",
                       i + 1u);
    }
    char table_text[ZCL_PRESENT_MODEL_TEXT_MAX];
    size_t table_text_len = 0;
    uint32_t table_text_pages = 0;
    QR_CHECK("maximum table text export is bounded and fully paged",
             zcl_present_model_text_page_v1(
                 &long_table, 63u, table_text, sizeof(table_text),
                 &table_text_len, &table_text_pages, why, sizeof(why)) &&
             table_text_pages == 64u &&
             table_text_len < sizeof(table_text) &&
             strstr(table_text, "id: row-64") != NULL &&
             !zcl_present_model_text_page_v1(
                 &long_table, table_text_pages, table_text,
                 sizeof(table_text), &table_text_len, &table_text_pages,
                 why, sizeof(why)));
    QR_CHECK("oversized complete text export refuses instead of truncating",
             !zcl_present_model_text_all_v1(
                 &long_table, table_text, sizeof(table_text),
                 &table_text_len, why, sizeof(why)) &&
             strstr(why, "exceeds its byte bound") != NULL);
}

void qr_case_bounded_table_pixels(void)
{
    char why[128];
    struct zcl_present_model_v1 long_table;
    uint32_t table_pages = 0;
    struct zcl_present_model_bitmap_v1 visual_bitmap;
    struct zcl_present_model_bitmap_v1 first_page, last_page;
    bool first_page_ok;
    bool last_page_ok;
    qr_fill_long_table(&long_table);
    (void)zcl_present_model_page_count_v1(
        &long_table, &table_pages, why, sizeof(why));
    first_page_ok = zcl_present_model_render_page_v1(
        &long_table, 0, &first_page, why, sizeof(why));
    last_page_ok = zcl_present_model_render_page_v1(
        &long_table, table_pages - 1u, &last_page, why, sizeof(why));
    QR_CHECK("first and last bounded table pages render distinct pixels",
             first_page_ok && last_page_ok &&
             memcmp(first_page.pixels, last_page.pixels,
                    ZCL_PRESENT_MODEL_BITMAP_BYTES) != 0);
    QR_CHECK("page past the exact model bound fails closed",
             !zcl_present_model_render_page_v1(
                 &long_table, table_pages, &visual_bitmap,
                 why, sizeof(why)));
    zcl_present_model_bitmap_free_v1(&first_page);
    zcl_present_model_bitmap_free_v1(&last_page);
}

void qr_case_bounded_table_keys(void)
{
    char why[128];
    struct zcl_present_model_v1 long_table;
    uint32_t table_pages = 0;
    uint32_t next_page = UINT32_MAX;
    qr_fill_long_table(&long_table);
    (void)zcl_present_model_page_count_v1(
        &long_table, &table_pages, why, sizeof(why));
    QR_CHECK("keyboard page movement advances and clamps deterministically",
             zcl_present_window_page_step_v1(
                 0, table_pages, 1, &next_page) && next_page == 1u &&
             zcl_present_window_page_step_v1(
                 table_pages - 1u, table_pages, 1, &next_page) &&
             next_page == table_pages - 1u &&
             zcl_present_window_page_step_v1(
                 0, table_pages, -1, &next_page) && next_page == 0u);
    uint32_t next_action = UINT32_MAX;
    QR_CHECK("keyboard action focus wraps without selecting authority",
             zcl_present_window_action_focus_step_v1(
                 0, 2, 1, &next_action) && next_action == 1u &&
             zcl_present_window_action_focus_step_v1(
                 1, 2, 1, &next_action) && next_action == 0u &&
             zcl_present_window_action_focus_step_v1(
                 0, 2, -1, &next_action) && next_action == 1u &&
             !zcl_present_window_action_focus_step_v1(
                 0, 0, 1, &next_action));
}

void qr_case_typed_visual_json(void)
{
    char why[128];
    static const char model_json[] =
        "{\"kind\":\"code-diff\",\"request_id\":\"diff-1\","
        "\"title\":\"Exact candidate diff\","
        "\"summary\":\"One candidate-owned line changed.\","
        "\"items\":[{\"kind\":\"diff-remove\",\"value\":\"return 0;\"},"
        "{\"kind\":\"diff-add\",\"status\":\"green\","
        "\"value\":\"return verified;\"}]}";
    struct json_value visual_json;
    json_init(&visual_json);
    QR_CHECK("typed native visual JSON parses",
             json_read(&visual_json, model_json, sizeof(model_json) - 1u));
    struct zcl_present_model_v1 json_model;
    bool visual_json_ok = ui_present_model_from_json(
        &visual_json, &json_model, why, sizeof(why));
    if (!visual_json_ok) printf("  visual JSON diagnostic: %s\n", why);
    QR_CHECK("closed visual JSON becomes the renderer-neutral model",
             visual_json_ok &&
             json_model.kind == ZCL_PRESENT_MODEL_CODE_DIFF &&
             json_model.item_count == 2 &&
             json_model.items[1].kind == ZCL_PRESENT_ITEM_DIFF_ADD);
    json_free(&visual_json);
}

void qr_case_typed_chart_command(void)
{
    static const char chart_json[] =
        "{\"kind\":\"chart\",\"request_id\":\"coverage-chart\","
        "\"title\":\"Exact candidate coverage\",\"output\":\"text\","
        "\"items\":[{\"kind\":\"chart-point\",\"status\":\"green\","
        "\"id\":\"candidate\",\"label\":\"Candidate\",\"value\":\"81%\","
        "\"numerator\":81,\"denominator\":100}]}";
    struct json_value chart_input;
    json_init(&chart_input);
    QR_CHECK("typed chart request parses as one bounded model",
             json_read(&chart_input, chart_json,
                       sizeof(chart_json) - 1u));
    struct zcl_command_request chart_request = {.input = &chart_input};
    struct zcl_command_reply chart_reply;
    zcl_command_reply_init(&chart_reply, "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&chart_request, &chart_reply);
    const char *typed_chart_text =
        json_get_str(json_get(&chart_reply.data, "plain_text"));
    QR_CHECK("agent chart command exports the exact plotted fraction",
             chart_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_chart_text &&
             strstr(typed_chart_text, "kind: chart") != NULL &&
             strstr(typed_chart_text, "chart-point: 81/100") != NULL &&
             strcmp(json_get_str(json_get(&chart_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&chart_reply);
    json_free(&chart_input);
}

void qr_case_typed_timeline_command(void)
{
    static const char timeline_json[] =
        "{\"kind\":\"timeline\",\"request_id\":\"proof-timeline\","
        "\"title\":\"Exact proof sequence\",\"output\":\"text\","
        "\"items\":[{\"kind\":\"timeline-event\",\"status\":\"green\","
        "\"id\":\"receipt\",\"label\":\"Receipt verified\","
        "\"value\":\"independent signer\"}]}";
    struct json_value timeline_input;
    json_init(&timeline_input);
    QR_CHECK("typed timeline request parses as one bounded model",
             json_read(&timeline_input, timeline_json,
                       sizeof(timeline_json) - 1u));
    struct zcl_command_request timeline_request = {.input = &timeline_input};
    struct zcl_command_reply timeline_reply;
    zcl_command_reply_init(&timeline_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&timeline_request, &timeline_reply);
    const char *typed_timeline_text =
        json_get_str(json_get(&timeline_reply.data, "plain_text"));
    QR_CHECK("agent timeline command preserves the exact event companion",
             timeline_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_timeline_text &&
             strstr(typed_timeline_text, "kind: timeline") != NULL &&
             strstr(typed_timeline_text, "timeline-event [green]") != NULL &&
             strstr(typed_timeline_text,
                    "value: independent signer") != NULL &&
             strcmp(json_get_str(json_get(&timeline_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&timeline_reply);
    json_free(&timeline_input);
}

void qr_case_typed_evidence_graph_command(void)
{
    static const char graph_json[] =
        "{\"kind\":\"evidence-graph\",\"request_id\":\"evidence-graph\","
        "\"title\":\"Candidate evidence\",\"output\":\"text\","
        "\"items\":[{\"kind\":\"graph-node\",\"status\":\"info\","
        "\"id\":\"candidate\",\"label\":\"Candidate root\","
        "\"value\":\"exact source\"},{\"kind\":\"graph-node\","
        "\"status\":\"green\",\"id\":\"receipt\","
        "\"label\":\"Verified receipt\",\"value\":\"independent signer\","
        "\"parent_index\":0}]}";
    struct json_value graph_input;
    json_init(&graph_input);
    QR_CHECK("typed evidence graph parses as one bounded parent chain",
             json_read(&graph_input, graph_json,
                       sizeof(graph_json) - 1u));
    struct zcl_command_request graph_request = {.input = &graph_input};
    struct zcl_command_reply graph_reply;
    zcl_command_reply_init(&graph_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&graph_request, &graph_reply);
    const char *typed_graph_text =
        json_get_str(json_get(&graph_reply.data, "plain_text"));
    QR_CHECK("agent evidence graph exports the exact parent relationship",
             graph_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_graph_text &&
             strstr(typed_graph_text, "kind: evidence-graph") != NULL &&
             strstr(typed_graph_text, "parent-item: 1") != NULL &&
             strcmp(json_get_str(json_get(&graph_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&graph_reply);
    json_free(&graph_input);
}

void qr_case_typed_choice_command(void)
{
    static const char choice_json[] =
        "{\"kind\":\"choice\",\"request_id\":\"proof-choice\","
        "\"title\":\"Choose the next proof\",\"output\":\"text\","
        "\"items\":[{\"kind\":\"choice\",\"status\":\"info\","
        "\"id\":\"focused\",\"label\":\"Focused story\","
        "\"value\":\"fast exact evidence\",\"selected\":true},"
        "{\"kind\":\"choice\",\"status\":\"neutral\","
        "\"id\":\"broad\",\"label\":\"Broader suite\","
        "\"value\":\"slower coverage\"}],\"actions\":["
        "{\"kind\":\"select\",\"id\":\"focused\","
        "\"label\":\"Focused story\"},{\"kind\":\"select\","
        "\"id\":\"broad\",\"label\":\"Broader suite\"}]}";
    struct json_value choice_input;
    json_init(&choice_input);
    QR_CHECK("typed choice parses only matching bounded action IDs",
             json_read(&choice_input, choice_json,
                       sizeof(choice_json) - 1u));
    struct zcl_command_request choice_request = {.input = &choice_input};
    struct zcl_command_reply choice_reply;
    zcl_command_reply_init(&choice_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&choice_request, &choice_reply);
    const char *typed_choice_text =
        json_get_str(json_get(&choice_reply.data, "plain_text"));
    QR_CHECK("agent choice exports the exact display/action mapping",
             choice_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_choice_text &&
             strstr(typed_choice_text, "kind: choice") != NULL &&
             strstr(typed_choice_text, "flags: selected") != NULL &&
             strstr(typed_choice_text, "action 2: select") != NULL &&
             strcmp(json_get_str(json_get(&choice_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&choice_reply);
    json_free(&choice_input);
}

void qr_case_typed_form_command(void)
{
    static const char form_json[] =
        "{\"kind\":\"form\",\"request_id\":\"release-form\","
        "\"title\":\"Describe exact release\",\"output\":\"text\","
        "\"exact_root\":"
        "\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\","
        "\"items\":[{\"kind\":\"form-field\",\"id\":\"release-note\","
        "\"label\":\"Release note\",\"value\":\"\",\"required\":true},"
        "{\"kind\":\"form-field\",\"id\":\"candidate-root\","
        "\"label\":\"Candidate root\",\"value\":\"immutable-root\","
        "\"read_only\":true}],\"actions\":["
        "{\"kind\":\"cancel\",\"id\":\"cancel\",\"label\":\"Cancel\"},"
        "{\"kind\":\"submit\",\"id\":\"submit-release-note\","
        "\"label\":\"Submit\"}]}";
    struct json_value form_input;
    json_init(&form_input);
    QR_CHECK("typed form parses as one exact bounded edit contract",
             json_read(&form_input, form_json, sizeof(form_json) - 1u));
    struct zcl_command_request form_request = {.input = &form_input};
    struct zcl_command_reply form_reply;
    zcl_command_reply_init(&form_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&form_request, &form_reply);
    const char *typed_form_text =
        json_get_str(json_get(&form_reply.data, "plain_text"));
    QR_CHECK("agent form text exposes the same fields and safe actions",
             form_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_form_text &&
             strstr(typed_form_text, "kind: form") != NULL &&
             strstr(typed_form_text, "id: release-note") != NULL &&
             strstr(typed_form_text, "flags: required") != NULL &&
             strstr(typed_form_text, "flags: read-only") != NULL &&
             strstr(typed_form_text, "action 1: cancel") != NULL &&
             strstr(typed_form_text, "action 2: submit") != NULL &&
             strcmp(json_get_str(json_get(&form_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&form_reply);
    json_free(&form_input);
}

void qr_case_typed_canvas_command(void)
{
    static const char canvas_json[] =
        "{\"kind\":\"canvas\",\"request_id\":\"placement-canvas\","
        "\"title\":\"Place exact label\",\"output\":\"text\","
        "\"exact_root\":"
        "\"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\","
        "\"items\":[{\"kind\":\"canvas-point\","
        "\"id\":\"label-origin\",\"label\":\"Label origin\","
        "\"numerator\":250,\"denominator\":300,\"selected\":true},"
        "{\"kind\":\"canvas-point\",\"status\":\"info\","
        "\"id\":\"fixed-anchor\",\"label\":\"Fixed anchor\","
        "\"numerator\":800,\"denominator\":700,"
        "\"read_only\":true}],\"actions\":["
        "{\"kind\":\"cancel\",\"id\":\"cancel\",\"label\":\"Cancel\"},"
        "{\"kind\":\"submit\",\"id\":\"submit-placement\","
        "\"label\":\"Submit\"}]}";
    struct json_value canvas_input;
    json_init(&canvas_input);
    QR_CHECK("typed canvas parses as one exact bounded point contract",
             json_read(&canvas_input, canvas_json,
                       sizeof(canvas_json) - 1u));
    struct zcl_command_request canvas_request = {.input = &canvas_input};
    struct zcl_command_reply canvas_reply;
    zcl_command_reply_init(&canvas_reply,
                           "zcl.app_presentation_show.v1");
    zcl_native_handle_presentation_show(&canvas_request, &canvas_reply);
    const char *typed_canvas_text =
        json_get_str(json_get(&canvas_reply.data, "plain_text"));
    QR_CHECK("agent canvas text preserves exact point and safe actions",
             canvas_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             typed_canvas_text &&
             strstr(typed_canvas_text, "kind: canvas") != NULL &&
             strstr(typed_canvas_text,
                    "canvas-point-x-y: 250/300") != NULL &&
             strstr(typed_canvas_text, "flags: read-only") != NULL &&
             strstr(typed_canvas_text, "action 1: cancel") != NULL &&
             strstr(typed_canvas_text, "action 2: submit") != NULL &&
             strcmp(json_get_str(json_get(&canvas_reply.data, "authority")),
                    "display-only") == 0);
    zcl_command_reply_free(&canvas_reply);
    json_free(&canvas_input);
}

void qr_case_shared_presentation_response(void)
{
    char why[128];
    static const char model_json[] =
        "{\"kind\":\"code-diff\",\"request_id\":\"diff-1\","
        "\"title\":\"Exact candidate diff\","
        "\"summary\":\"One candidate-owned line changed.\","
        "\"items\":[{\"kind\":\"diff-remove\",\"value\":\"return 0;\"},"
        "{\"kind\":\"diff-add\",\"status\":\"green\","
        "\"value\":\"return verified;\"}]}";
    struct json_value visual_json;
    json_init(&visual_json);
    (void)json_read(&visual_json, model_json, sizeof(model_json) - 1u);
    struct zcl_present_model_v1 json_model;
    (void)ui_present_model_from_json(
        &visual_json, &json_model, why, sizeof(why));
    json_free(&visual_json);
    struct json_value text_delivery;
    json_init(&text_delivery);
    json_set_object(&text_delivery);
    json_push_kv_str(&text_delivery, "output", "text");
    struct zcl_command_reply text_reply;
    zcl_command_reply_init(&text_reply, "zcl.app_presentation_show.v1");
    zcl_native_present_model(&json_model, "app.presentation.show",
                             &text_delivery, &text_reply);
    QR_CHECK("shared presentation response proves no privileged action",
             text_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             json_get_bool(json_get(&text_reply.data, "text_complete")) &&
             json_get_int(json_get(&text_reply.data,
                                   "text_page_count")) == 1 &&
             strstr(json_get_str(json_get(&text_reply.data, "plain_text")),
                    "value: return 0;") != NULL &&
             strstr(json_get_str(json_get(&text_reply.data, "plain_text")),
                    "value: return verified;") != NULL &&
             strcmp(json_get_str(json_get(&text_reply.data, "authority")),
                    "display-only") == 0 &&
             !json_get_bool(json_get(&text_reply.data,
                                     "privileged_action_performed")));
    zcl_command_reply_free(&text_reply);
    json_free(&text_delivery);
}

void qr_case_shared_text_paging_fallback(void)
{
    struct zcl_present_model_v1 long_table;
    struct json_value text_delivery;
    struct zcl_command_reply text_reply;
    qr_fill_long_table(&long_table);
    json_init(&text_delivery);
    json_set_object(&text_delivery);
    json_push_kv_str(&text_delivery, "output", "text");
    zcl_command_reply_init(&text_reply, "zcl.app_presentation_show.v1");
    zcl_native_present_model(&long_table, "app.presentation.show",
                             &text_delivery, &text_reply);
    QR_CHECK("oversized shared text response falls back to exact paging",
             text_reply.status == ZCL_COMMAND_STATUS_PASSED &&
             !json_get_bool(json_get(&text_reply.data, "text_complete")) &&
             json_get_int(json_get(&text_reply.data,
                                   "text_page_count")) == 64 &&
             strstr(json_get_str(json_get(&text_reply.data, "plain_text")),
                    "id: row-1") != NULL &&
             strstr(json_get_str(json_get(&text_reply.data, "plain_text")),
                    "id: row-2") == NULL);
    zcl_command_reply_free(&text_reply);
    json_free(&text_delivery);
}

void qr_case_visual_command_smuggling(void)
{
    char why[128];
    struct json_value visual_json;
    struct zcl_present_model_v1 json_model;
    static const char smuggled_json[] =
        "{\"kind\":\"status\",\"request_id\":\"bad-1\","
        "\"title\":\"Bad\",\"items\":[{\"kind\":\"text\","
        "\"value\":\"x\",\"command\":\"/bin/sh\"}]}";
    json_init(&visual_json);
    QR_CHECK("unknown visual item key fixture parses as JSON",
             json_read(&visual_json, smuggled_json,
                       sizeof(smuggled_json) - 1u));
    QR_CHECK("visual model rejects command smuggling",
             !ui_present_model_from_json(&visual_json, &json_model,
                                         why, sizeof(why)));
    json_free(&visual_json);
}

