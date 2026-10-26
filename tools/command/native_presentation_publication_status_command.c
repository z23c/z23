/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: display-only publication progress from canonical local facts. */

#include "command/native_command.h"
#include "command/native_zcode_discovery.h"

#include "base/hex.h"
#include "json/json.h"
#include "presentation/model.h"
#include "util/log_macros.h"

#include <stdio.h>
#include <string.h>

#define NPPS_LEAF "app.presentation.publication-status"
#define NPPS_NAMESPACE "zclassic23.package"

static const char *npps_str(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_STR ? json_get_str(value) : NULL;
}

static const struct json_value *npps_object(
    const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_OBJ ? value : NULL;
}

static bool npps_bool(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_BOOL && json_get_bool(value);
}

static int64_t npps_int(const struct json_value *object, const char *key)
{
    const struct json_value *value = object ? json_get(object, key) : NULL;
    return value && value->type == JSON_INT ? json_get_int(value) : -1;
}

static bool npps_root(const char *root, bool optional)
{
    uint8_t decoded[32];
    return optional && (!root || !root[0]) ? true :
        root && strlen(root) == 64u &&
        zcl_hex_decode_lower(root, decoded, sizeof(decoded));
}

static void npps_item(struct zcl_present_model_v1 *model, const char *id,
                      const char *label, const char *value, uint16_t status,
                      bool observed)
{
    struct zcl_present_model_item_v1 *item =
        &model->items[model->item_count++];
    item->kind = ZCL_PRESENT_ITEM_PROGRESS;
    item->status = status;
    item->parent_index = ZCL_PRESENT_MODEL_PARENT_NONE;
    item->flags = ZCL_PRESENT_ITEM_READ_ONLY;
    item->denominator = 1u;
    item->numerator = observed ? 1u : 0u;
    (void)snprintf(item->id, sizeof(item->id), "%s", id);
    (void)snprintf(item->label, sizeof(item->label), "%s", label);
    (void)snprintf(item->value, sizeof(item->value), "%s", value);
}

static bool npps_record_matches(
    const struct json_value *row, const char *kind,
    const char *package_root, const char *transport_root,
    const char *local_node_id, bool *remote)
{
    const char *row_kind = npps_str(row, "kind");
    const char *namespace_name = npps_str(row, "namespace");
    const char *semantic = npps_str(row, "semantic_root");
    const char *transport = npps_str(row, "transport_root");
    const char *provider = npps_str(row, "provider_node_id");
    const char *record_root = npps_str(row, "record_root");
    if (!row_kind || strcmp(row_kind, kind) != 0 || !namespace_name ||
        strcmp(namespace_name, NPPS_NAMESPACE) != 0 ||
        !npps_root(transport, false) || strcmp(transport, transport_root) != 0 ||
        !npps_root(provider, false) || !npps_root(record_root, false))
        return false;
    if (strcmp(kind, "pointer") == 0 &&
        (!npps_root(semantic, false) || strcmp(semantic, package_root) != 0))
        return false;
    if (remote)
        *remote = npps_root(local_node_id, false) &&
                  strcmp(provider, local_node_id) != 0;
    return true;
}

static bool npps_records_scan(
    const struct json_value *projection, const char *kind,
    const char *package_root, const char *transport_root,
    const char *local_node_id, bool *found, bool *remote,
    char providers[][65], size_t *provider_count)
{
    *found = false;
    *remote = false;
    *provider_count = 0;
    if (!projection || projection->type != JSON_OBJ ||
        !npps_bool(projection, "local_projection"))
        return false;
    const struct json_value *rows = json_get(projection, "records");
    if (!rows || rows->type != JSON_ARR)
        return false;
    for (size_t i = 0; i < json_size(rows); i++) {
        const struct json_value *row = json_at(rows, i);
        bool row_remote = false;
        if (!npps_record_matches(row, kind, package_root, transport_root,
                                 local_node_id, &row_remote))
            continue;
        *found = true;
        *remote |= row_remote;
        const char *provider = npps_str(row, "provider_node_id");
        if (*provider_count < VCS_ZCODE_DHT_RECORDS_PER_FRAME) {
            (void)snprintf(providers[*provider_count], 65, "%s", provider);
            (*provider_count)++;
        }
    }
    return true;
}

static bool npps_provider_intersection(
    char pointers[][65], size_t pointer_count,
    char providers[][65], size_t provider_count,
    const char *local_node_id)
{
    if (!npps_root(local_node_id, false)) return false;
    for (size_t i = 0; i < pointer_count; i++)
        for (size_t j = 0; j < provider_count; j++)
            if (strcmp(pointers[i], providers[j]) == 0 &&
                strcmp(pointers[i], local_node_id) != 0)
                return true;
    return false;
}

static bool npps_publication_facts_unusable(
    const char *schema, const char *package_root,
    const char *transport_root, const char *confirmation,
    const char *local_node_id, const struct json_value *package)
{
    return !schema || strcmp(schema, "zcl.package_publication_facts.v1") != 0 ||
        !npps_root(package_root, false) || !npps_root(transport_root, false) ||
        !npps_root(confirmation, false) || !npps_root(local_node_id, true) ||
        !package;
}

static bool npps_download_complete(const struct json_value *download,
                                   bool download_found,
                                   const char *download_state,
                                   int64_t *fetched_bytes)
{
    int64_t present_chunks = npps_int(download, "present_chunks");
    int64_t total_chunks = npps_int(download, "total_chunks");
    int64_t present_bytes = npps_int(download, "present_bytes");
    int64_t total_bytes = npps_int(download, "total_bytes");
    *fetched_bytes = npps_int(download, "fetched_bytes");
    return download_found && download_state &&
        strcmp(download_state, "complete") == 0 && total_chunks > 0 &&
        present_chunks == total_chunks && total_bytes > 0 &&
        present_bytes == total_bytes;
}

static bool npps_download_failed(bool download_found,
                                 const char *download_state)
{
    return download_found && download_state &&
           strcmp(download_state, "failed") == 0;
}

static void npps_signed_observation_items(
    struct zcl_present_model_v1 *model, bool pointer_found, bool pointer_read,
    bool provider_found, bool provider_read)
{
    npps_item(model, "pointer", "SIGNED OBSERVATION - Pointer published",
              pointer_found ? "Exact package -> carrier record observed" :
              pointer_read ? "No exact signed pointer observed" :
                             "DHT projection unavailable",
              pointer_found ? ZCL_PRESENT_STATUS_GREEN :
              pointer_read ? ZCL_PRESENT_STATUS_NEUTRAL :
                             ZCL_PRESENT_STATUS_RED,
              pointer_found);
    npps_item(model, "provider", "SIGNED OBSERVATION - Provider published",
              provider_found ? "Exact carrier provider record observed" :
              provider_read ? "No exact signed provider observed" :
                              "DHT projection unavailable",
              provider_found ? ZCL_PRESENT_STATUS_GREEN :
              provider_read ? ZCL_PRESENT_STATUS_NEUTRAL :
                              ZCL_PRESENT_STATUS_RED,
              provider_found);
}

static void npps_peer_observation_items(
    struct zcl_present_model_v1 *model, bool peer_discovered,
    bool exact_fetch, bool download_failed)
{
    npps_item(model, "discovery", "PEER OBSERVATION - Peer discovered",
              peer_discovered ? "Same non-self provider binds both records" :
                                "No exact non-self record pair observed",
              peer_discovered ? ZCL_PRESENT_STATUS_GREEN :
                                ZCL_PRESENT_STATUS_NEUTRAL,
              peer_discovered);
    npps_item(model, "fetch", "PEER OBSERVATION - Exact bytes fetched",
              exact_fetch ? "Carrier complete, imported, and peer bytes received" :
              download_failed ? "Named carrier download failure" :
                                "No complete peer-bound fetch observed",
              exact_fetch ? ZCL_PRESENT_STATUS_GREEN :
              download_failed ? ZCL_PRESENT_STATUS_RED :
                                ZCL_PRESENT_STATUS_NEUTRAL,
              exact_fetch);
}

bool zcl_native_presentation_publication_status_model_from_facts(
    const struct json_value *facts, struct zcl_present_model_v1 *model,
    char *why, size_t why_cap)
{
    const char *schema = npps_str(facts, "schema");
    const char *package_root = npps_str(facts, "package_root");
    const char *transport_root = npps_str(facts, "transport_root");
    const char *confirmation = npps_str(facts, "confirmation_identity");
    const char *local_node_id = npps_str(facts, "local_node_id");
    const struct json_value *package = npps_object(facts, "package");
    const struct json_value *pointer = npps_object(facts, "pointer_records");
    const struct json_value *provider = npps_object(facts, "provider_records");
    if (npps_publication_facts_unusable(schema, package_root,
                                        transport_root, confirmation,
                                        local_node_id, package)) {
        (void)snprintf(why, why_cap,
                       "exact package publication facts are unavailable");
        return false;
    }

    bool local_complete = npps_bool(facts, "local_package_committed");
    char pointer_ids[VCS_ZCODE_DHT_RECORDS_PER_FRAME][65] = {{0}};
    char provider_ids[VCS_ZCODE_DHT_RECORDS_PER_FRAME][65] = {{0}};
    size_t pointer_count = 0, provider_count = 0;
    bool pointer_found = false, pointer_remote = false;
    bool provider_found = false, provider_remote = false;
    bool pointer_read = npps_records_scan(
        pointer, "pointer", package_root, transport_root, local_node_id,
        &pointer_found, &pointer_remote, pointer_ids, &pointer_count);
    bool provider_read = npps_records_scan(
        provider, "provider", package_root, transport_root, local_node_id,
        &provider_found, &provider_remote, provider_ids, &provider_count);
    bool peer_discovered = pointer_read && provider_read && pointer_remote &&
        provider_remote && npps_provider_intersection(
            pointer_ids, pointer_count, provider_ids, provider_count,
            local_node_id);

    bool download_found = npps_bool(package, "download_found");
    const struct json_value *download = npps_object(package, "download");
    const char *download_state = npps_str(download, "state");
    int64_t fetched_bytes = 0;
    bool download_complete = npps_download_complete(download, download_found,
                                                    download_state,
                                                    &fetched_bytes);
    bool exact_fetch = local_complete && peer_discovered && download_complete &&
                       fetched_bytes > 0;
    bool download_failed = npps_download_failed(download_found, download_state);

    zcl_present_model_init_v1(model, ZCL_PRESENT_MODEL_PROGRESS);
    (void)snprintf(model->request_id, sizeof(model->request_id),
                   "publish-%.12s", confirmation);
    (void)snprintf(model->title, sizeof(model->title),
                   "Exact package publication");
    unsigned observed = (unsigned)local_complete + (unsigned)pointer_found +
        (unsigned)provider_found + (unsigned)peer_discovered +
        (unsigned)exact_fetch;
    (void)snprintf(model->summary, sizeof(model->summary),
                   "%u/5 re-derivable stages observed for package %.12s...; human confirmation remains in its exact response.",
                   observed, package_root);
    (void)snprintf(model->exact_root, sizeof(model->exact_root), "%s",
                   package_root);
    npps_item(model, "confirmation", "HUMAN DECISION - Confirmation",
              "Separate exact response; intentionally not re-derived",
              ZCL_PRESENT_STATUS_YELLOW, false);
    npps_item(model, "local-commit", "LOCAL OBSERVATION - Local commit",
              local_complete ? "Exact package is complete in this node" :
                               "Not observed on this node",
              local_complete ? ZCL_PRESENT_STATUS_GREEN :
                               ZCL_PRESENT_STATUS_NEUTRAL,
              local_complete);
    npps_signed_observation_items(model, pointer_found, pointer_read,
                                  provider_found, provider_read);
    npps_peer_observation_items(model, peer_discovered, exact_fetch,
                                download_failed);
    return zcl_present_model_validate_v1(model, why, why_cap);
}

static void npps_fail(struct zcl_command_reply *reply, const char *code,
                      const char *message)
{
    LOG_ERROR("native.presentation.publication_status", "%s: %s",
              code, message);
    zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
        ZCL_COMMAND_EXIT_INVALID, code, "observe", true, false, message,
        NPPS_LEAF);
}

void zcl_native_handle_presentation_publication_status(
    const struct zcl_command_request *request, struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    const char *package_root = npps_str(input, "package_root");
    const char *transport_root = npps_str(input, "transport_root");
    const char *confirmation = npps_str(input, "confirmation_identity");
    if (!npps_root(package_root, false) ||
        !npps_root(transport_root, false) ||
        !npps_root(confirmation, false)) {
        npps_fail(reply, "INVALID_PUBLICATION_IDENTITIES",
                  "package_root, transport_root and confirmation_identity must be exact lowercase roots");
        return;
    }

    struct json_value show_input;
    json_init(&show_input);
    json_set_object(&show_input);
    json_push_kv_str(&show_input, "root", package_root);
    struct zcl_command_request show_request = *request;
    show_request.input = &show_input;
    struct zcl_command_reply show_reply;
    zcl_command_reply_init(&show_reply, "zcl.zcode_package_show.v1");
    zcl_native_handle_zcode_package_show(&show_request, &show_reply);
    const char *shown_root = npps_str(&show_reply.data, "package_root");
    bool local_committed = show_reply.status == ZCL_COMMAND_STATUS_PASSED &&
        shown_root && strcmp(shown_root, package_root) == 0;
    zcl_command_reply_free(&show_reply);
    json_free(&show_input);

    zcl_native_bridge_ensure_rpc();
    struct json_value package, publication;
    if (!zcl_native_zcode_package_status_read(
            package_root, transport_root, &package)) {
        npps_fail(reply, "PACKAGE_FACTS_UNAVAILABLE",
                  "the target node did not return exact package observations");
        return;
    }
    if (!zcl_native_zcode_publication_snapshot_read(
            NPPS_NAMESPACE, package_root, transport_root, &publication)) {
        json_free(&package);
        npps_fail(reply, "PUBLICATION_SNAPSHOT_UNAVAILABLE",
                  "the target node did not return one coherent DHT publication snapshot");
        return;
    }
    const char *local_node_id = npps_str(&publication, "local_node_id");
    const struct json_value *pointer =
        npps_object(&publication, "pointer_records");
    const struct json_value *provider =
        npps_object(&publication, "provider_records");

    struct json_value facts;
    json_init(&facts);
    json_set_object(&facts);
    json_push_kv_str(&facts, "schema", "zcl.package_publication_facts.v1");
    json_push_kv_str(&facts, "package_root", package_root);
    json_push_kv_str(&facts, "transport_root", transport_root);
    json_push_kv_str(&facts, "confirmation_identity", confirmation);
    json_push_kv_str(&facts, "local_node_id", local_node_id ? local_node_id : "");
    json_push_kv_bool(&facts, "local_package_committed", local_committed);
    json_push_kv(&facts, "package", &package);
    if (pointer) json_push_kv(&facts, "pointer_records", pointer);
    if (provider) json_push_kv(&facts, "provider_records", provider);
    struct zcl_present_model_v1 model;
    char why[192];
    bool built = zcl_native_presentation_publication_status_model_from_facts(
        &facts, &model, why, sizeof(why));
    json_free(&facts);
    json_free(&package);
    json_free(&publication);
    if (!built) {
        npps_fail(reply, "PUBLICATION_FACTS_INVALID", why);
        return;
    }

    zcl_native_present_model(&model, NPPS_LEAF, input, reply);
    if (reply->status != ZCL_COMMAND_STATUS_PASSED) return;
    json_push_kv_str(&reply->data, "fact_authority",
                     "rebuilt_package_index_resident_swarm_and_signed_dht_projection");
    json_push_kv_str(&reply->data, "package_root", package_root);
    json_push_kv_str(&reply->data, "transport_root", transport_root);
    json_push_kv_str(&reply->data, "confirmation_identity", confirmation);
    json_push_kv_bool(&reply->data, "human_confirmation_rederived", false);
    json_push_kv_bool(&reply->data, "local_commit_complete",
                      model.items[1].status == ZCL_PRESENT_STATUS_GREEN);
    json_push_kv_bool(&reply->data, "pointer_publication_observed",
                      model.items[2].status == ZCL_PRESENT_STATUS_GREEN);
    json_push_kv_bool(&reply->data, "provider_publication_observed",
                      model.items[3].status == ZCL_PRESENT_STATUS_GREEN);
    json_push_kv_bool(&reply->data, "peer_discovery_observed",
                      model.items[4].status == ZCL_PRESENT_STATUS_GREEN);
    json_push_kv_bool(&reply->data, "exact_fetch_observed",
                      model.items[5].status == ZCL_PRESENT_STATUS_GREEN);
}
