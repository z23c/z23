/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * Purpose: `app discover` — first-contact discovery. One explicit onion or
 * app link, fetched over Tor by the same sandboxed one-shot worker the
 * open-link flow uses. Without --offer it lists the room's offers exactly
 * like the `app get` catalog and stores nothing. With --offer=<64 hex> and
 * --yes it fetches that one signed offer post and hands the raw frame to
 * the node's fleet_board_ingest RPC, whose chain (validate, time window,
 * Ed25519 verify, PUBLIC gate, quota) is the ONLY path that writes the
 * local board. Nothing is ever executed here; the existing
 * `app get ... --yes` flow completes the journey unchanged. */
#include "command/native_command.h"
#include "command/native_app_compose.h"
#include "command/native_app_front_door.h"
#include "command/native_app_get_stage.h"
#include "command/native_app_network.h"
#include "command/native_app_network_job.h"
#include "command/native_app_network_link.h"
#include "command/native_app_offer.h"
#include "command/native_app_receive_command.h"
#include "command/native_app_scratch.h"
#include "command/native_zcode_package_copy.h"
#include "base/hex.h"
#include "base/safe_alloc.h"
#include "controllers/rpc_client.h"
#include "platform/rng.h"
#include "platform/time_compat.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ADC_COMMAND "app.discover"
#define ADC_RPC "fleet_board_ingest"
#define ADC_TIMEOUT_MS 120000u
#define ADC_PARAMS_MAX (APP_NETWORK_FRAME_HEX_CAP + 64u)
#define ADC_PATH AG_PATH

#if defined(ZCL_TESTING)
/* The harness's stand-in for the sandboxed worker child; declared in
 * tests/harness/src/test_app_network_link.h and defined by
 * tests/harness/src/test_app_get.c. */
extern bool (*zcl_test_app_discover_job)(void *context,
    const struct app_network_job_args *args,
    struct app_network_job_result *result);
extern void *zcl_test_app_discover_job_context;
#endif

static bool adc_hex_id(const char *text)
{
    uint8_t id[32];
    return text && strlen(text) == 64u && zcl_hex_decode_lower(text, id, sizeof(id));
}

#if !defined(_WIN32)
/* The same APP_NETWORK_* refusal shape the open-link flow reports. */
static void adc_fail_network(struct zcl_command_reply *reply,
                             enum app_network_error error)
{
    static const struct { enum app_network_error error; const char *code, *message, *action; } table[] = {
        {APP_NETWORK_CANCELLED, "NETWORK_UNAVAILABLE", "the connection was canceled", "start discovery again when ready"},
        {APP_NETWORK_TIMEOUT, "NETWORK_TIMEOUT", "the connection timed out; the publisher may be offline", "try again later"},
        {APP_NETWORK_INVALID_RESPONSE, "INVALID_SIGNED_RESPONSE", "the endpoint returned an invalid or unverifiable reply", "ask the publisher for a fresh link"},
        {APP_NETWORK_CHANGED_OFFER, "OFFER_CHANGED", "the offer changed", "ask the publisher for a fresh link"},
        {APP_NETWORK_CONTENT_MISMATCH, "CONTENT_MISMATCH", "the received content did not match the offer", "ask the publisher for a fresh link"},
        {APP_NETWORK_STORE_REFUSED, "STORE_REFUSED", "the local store refused the received content", "inspect the local store before retrying"},
    };
    const char *code = "NETWORK_UNAVAILABLE", *message = "the connection could not be completed";
    const char *action = "check the link and try again";
    for (size_t i = 0; i < sizeof(table) / sizeof(table[0]); i++) {
        if (table[i].error != error) continue;
        code = table[i].code; message = table[i].message; action = table[i].action;
        break;
    }
    zcl_package_copy_fail(reply, code, false, message, ADC_COMMAND);
    (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action), "%s", action);
}

#endif

/* List each distinct signed post so every displayed offer can be selected. */
static bool adc_lines(struct zcl_command_reply *reply,
                      const struct zcl_app_offer_row *rows, size_t count)
{
    struct json_value lines;
    json_init(&lines);
    json_set_array(&lines);
    size_t identities = 0;
    for (size_t i = 0; i < count; i++) {
        bool seen = false;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(rows[i].post_id, rows[j].post_id)) {
                seen = true; break;
            }
        if (seen) continue;
        char line[512], age[32], shortfp[20];
        zcl_app_offer_age(rows[i].created_at, platform_time_wall_unix(), age, sizeof(age));
        if (!zcl_app_short_fingerprint(rows[i].offer.publisher, shortfp)) {
            json_free(&lines); return false;
        }
        int n = snprintf(line, sizeof(line), "%s %s %.16s %s ago offer=%s",
                         rows[i].offer.name, shortfp, rows[i].offer.root, age, rows[i].post_id);
        struct json_value item;
        json_init(&item);
        json_set_str(&item, line);
        bool ok = n > 0 && (size_t)n < sizeof(line) && json_push_back(&lines, &item);
        json_free(&item);
        if (!ok) { json_free(&lines); return false; }
        identities++;
    }
    bool ok = json_push_kv(&reply->data, "lines", &lines) &&
        json_push_kv_int(&reply->data, "count", (int64_t)identities) &&
        json_push_kv_bool(&reply->data, "stored", false);
    json_free(&lines);
    return ok;
}

/* One owned scratch round trip; the child is reaped before cleanup. The
 * sandboxed worker machinery is POSIX-only: on Windows the command fails
 * closed as unavailable rather than compiling a path it cannot honor —
 * the same shape the app get flow uses for its private stage. */
static bool adc_job(const char *datadir, const char *mode, const char *url,
                    struct app_network_job_result *result,
                    struct zcl_command_reply *reply)
{
#if defined(_WIN32)
    (void)datadir; (void)mode; (void)url; (void)result;
    zcl_package_copy_fail(reply, "NETWORK_UNAVAILABLE", false,
                          "the sandboxed connection worker is unavailable on this platform",
                          ADC_COMMAND);
    return false;
#else
    char anchor[ADC_PATH];
    uint8_t random[18];
    char token[33];
    if (!app_receive_profile_validate(datadir, anchor, sizeof(anchor), reply)) return false;
    if (!rng_host_fill(random, sizeof(random))) {
        zcl_package_copy_fail(reply, "NETWORK_UNAVAILABLE", false,
                              "cannot prepare a private connection", ADC_COMMAND);
        return false;
    }
    zcl_hex_encode(random, 16, token);
    struct an_scratch scratch;
    if (!an_scratch_create(&scratch, anchor, token)) {
        bool clean = scratch.created && an_scratch_cleanup(&scratch, true);
        if (!scratch.created) {
            if (scratch.root >= 0) close(scratch.root);
            if (scratch.parent >= 0) close(scratch.parent);
        }
        zcl_package_copy_fail(reply, "TEMP_UNAVAILABLE", scratch.created && !clean,
                              "cannot safely prepare a private connection", ADC_COMMAND);
        return false;
    }
    unsigned port = 1024u + ((((unsigned)random[16] << 8) | random[17]) %
                             (53569u - 1024u + 1u));
    struct app_network_job_args args = {.mode = mode, .url = url,
        .scratch = scratch.path, .scratch_dev = (uint64_t)scratch.dev,
        .scratch_ino = (uint64_t)scratch.ino, .bootstrap_port = port,
        .timeout_ms = ADC_TIMEOUT_MS, .network = zcl_native_command_network()};
    bool ran;
#if defined(ZCL_TESTING)
    ran = zcl_test_app_discover_job
        ? zcl_test_app_discover_job(zcl_test_app_discover_job_context, &args, result)
        : app_network_job_run(&args, result);
#else
    ran = app_network_job_run(&args, result);
#endif
    bool clean = an_scratch_cleanup(&scratch, true);
    /* Discover never keeps carrier bytes: the listing stores nothing and an
     * ingested offer hands over only the verified frame. */
    free(result->bytes); result->bytes = NULL; result->len = 0;
    if (!clean) {
        zcl_package_copy_fail(reply, "TEMP_CLEANUP_FAILED", true,
                              "private connection cleanup could not be confirmed", ADC_COMMAND);
        return false;
    }
    if (result->error != APP_NETWORK_OK || (ran && !result->protocol_valid)) {
        adc_fail_network(reply, result->error);
        if (app_network_tor_deadline(result, args.timeout_ms)) {
            (void)snprintf(reply->error.message, sizeof(reply->error.message),
                "Tor did not become ready before the connection timed out.");
            (void)snprintf(reply->error.next_action, sizeof(reply->error.next_action),
                "Check connectivity and try discovery again.");
        }
        return false;
    }
    return true;
#endif
}

/* One fleet_board_ingest round trip. `body` stays owned by the caller. */
static bool adc_ingest_call(const char *frame, struct json_value *body,
                            struct zcl_command_reply *reply)
{
    char *params = zcl_malloc(ADC_PARAMS_MAX, "app.discover.rpc");
    if (!params) {
        zcl_package_copy_fail(reply, "ALLOC", false, "cannot prepare the board request", ADC_COMMAND);
        return false;
    }
    int n = snprintf(params, ADC_PARAMS_MAX, "[{\"frame\":\"%s\"}]", frame);
    if (n <= 0 || (size_t)n >= ADC_PARAMS_MAX) {
        free(params);
        zcl_package_copy_fail(reply, "INPUT_TOO_LARGE", false,
                              "the signed offer frame does not fit one board request", ADC_COMMAND);
        return false;
    }
    zcl_native_bridge_ensure_rpc();
    char *raw = node_rpc_call(ADC_RPC, params);
    free(params);
    json_init(body);
    size_t len = raw ? strlen(raw) : 0;
    bool ok = raw && json_read(body, raw, len) && body->type == JSON_OBJ;
    free(raw);
    if (!ok) {
        json_free(body);
        zcl_package_copy_fail(reply, "BOARD_UNREADABLE", true,
                              "the node did not confirm the board ingest; the offer may already be stored",
                              ADC_COMMAND);
        return false;
    }
    return true;
}

/* The node's ingest chain answers; a refusal stores nothing and is final. */
static bool adc_ingest(const char *frame, const char *expected_id, bool *stored,
                       struct zcl_command_reply *reply)
{
    struct json_value body;
    json_init(&body);
    if (!adc_ingest_call(frame, &body, reply)) return false;
    const struct json_value *ok = json_get(&body, "ok");
    const char *id = json_get_str(json_get(&body, "id"));
    const struct json_value *stored_value = json_get(&body, "stored");
    bool accepted = ok && ok->type == JSON_BOOL && json_get_bool(ok) &&
        id && !strcmp(id, expected_id) && stored_value && stored_value->type == JSON_BOOL;
    if (accepted) {
        *stored = json_get_bool(stored_value);
    } else if (ok && ok->type == JSON_BOOL && !json_get_bool(ok)) {
        const char *message = json_get_str(json_get(&body, "message"));
        zcl_package_copy_fail(reply, "BOARD_REFUSED", false,
            message && message[0] ? message
                                  : "the node's board refused the signed offer post",
            ADC_RPC);
    } else {
        zcl_package_copy_fail(reply, "BOARD_UNREADABLE", true,
            "the node returned an inconsistent board receipt; the offer may already be stored",
            ADC_RPC);
    }
    json_free(&body);
    return accepted;
}

static bool adc_exact_url(const struct app_network_link *link, const char *offer,
                          char *url, size_t cap)
{
    int n = snprintf(url, cap, "http://%s/board/apps/v1/%s", link->onion, offer);
    return n > 0 && (size_t)n < cap;
}

/* --offer: fetch the one signed post frame (the worker verifies it, and the
 * parent re-verifies the frame it hands over), then ingest. The carrier the
 * direct fetch also verifies is released here, never stored; `app get`
 * fetches it again under its own plan and confirm. */
static bool adc_offer(struct zcl_command_reply *reply,
                      const struct app_network_link *link, const char *offer,
                      bool confirmed, const char *datadir)
{
    if (!confirmed) {
        zcl_package_copy_fail(reply, "CONFIRM_REQUIRED", false,
                              "ingesting a fetched offer writes this node's board; rerun with --yes",
                              ADC_COMMAND);
        return false;
    }
    char url[320];
    if (!adc_exact_url(link, offer, url, sizeof(url))) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false, "the offer id does not fit one link", ADC_COMMAND);
        return false;
    }
    struct app_network_job_result result;
    memset(&result, 0, sizeof(result));
    if (!adc_job(datadir, "direct", url, &result, reply)) return false;
    struct zcl_app_offer_row row = {0};
    if (!result.frame[0] ||
        !app_network_frame_row(result.frame, offer, platform_time_wall_unix(), &row)) {
        zcl_package_copy_fail(reply, "INVALID_SIGNED_RESPONSE", false,
                              "the fetched offer frame does not verify", ADC_COMMAND);
        return false;
    }
    bool stored = false;
    if (!adc_ingest(result.frame, offer, &stored, reply)) return false;
    char next[4900];
    bool hinted = zcl_app_hint(next, sizeof(next), datadir,
        "get %s --root=%s --publisher=%s --offer=%s", row.offer.name,
        row.offer.root, row.offer.publisher, offer);
    bool ok = json_push_kv_str(&reply->data, "offer_id", offer) &&
        json_push_kv_str(&reply->data, "name", row.offer.name) &&
        json_push_kv_str(&reply->data, "root", row.offer.root) &&
        json_push_kv_str(&reply->data, "publisher", row.offer.publisher) &&
        json_push_kv_bool(&reply->data, "ingested", true) &&
        json_push_kv_bool(&reply->data, "stored", stored);
    if (hinted) ok = json_push_kv_str(&reply->data, "next", next) && ok;
    if (!ok) zcl_package_copy_fail(reply, "ALLOC", stored, "cannot describe the ingested offer", ADC_COMMAND);
    return ok;
}

/* No --offer: the room listing. Stores nothing anywhere. */
static bool adc_list(struct zcl_command_reply *reply,
                     const struct app_network_link *link, const char *datadir)
{
    if (link->exact) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false,
                              "this link names one offer; pass --offer=<64 hex> to fetch and ingest it",
                              ADC_COMMAND);
        return false;
    }
    char url[96];
    int n = snprintf(url, sizeof(url), "http://%s/board/apps/v1", link->onion);
    if (n <= 0 || (size_t)n >= sizeof(url)) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false, "the endpoint does not fit one link", ADC_COMMAND);
        return false;
    }
    struct app_network_job_result result;
    memset(&result, 0, sizeof(result));
    if (!adc_job(datadir, "catalog", url, &result, reply)) return false;
    if (!adc_lines(reply, result.rows, result.count)) {
        zcl_package_copy_fail(reply, "ALLOC", false, "catalog output", ADC_COMMAND);
        return false;
    }
    return json_push_kv_str(&reply->data, "source", link->onion);
}

void zcl_native_handle_app_discover(const struct zcl_command_request *request,
                                    struct zcl_command_reply *reply)
{
    const struct json_value *input = request ? request->input : NULL;
    const char *text = zcl_package_copy_str(input, "link");
    const char *offer = zcl_package_copy_str(input, "offer");
    const struct json_value *yes = input ? json_get(input, "yes") : NULL;
    bool confirmed = yes && yes->type == JSON_BOOL && json_get_bool(yes);
    struct app_network_link link;
    if (!text || !text[0] || !app_network_link_parse(text, &link)) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false,
            "give a 62-char v3 onion, host:port, or the http://…/board/apps/v1[/id] link",
            ADC_COMMAND);
        return;
    }
    if (offer && (!adc_hex_id(offer) || (link.exact && strcmp(link.post_id, offer)))) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false,
                              "offer must be a 64-hex post id matching any exact link", ADC_COMMAND);
        return;
    }
    if (link.port) {
        zcl_package_copy_fail(reply, "BAD_INPUT", false,
            "the board fetch dials the endpoint's default port; a host:port endpoint is refused",
            ADC_COMMAND);
        return;
    }
    const char *datadir = zcl_package_copy_datadir(input, reply, ADC_COMMAND);
    if (!datadir) return;
    if (offer) adc_offer(reply, &link, offer, confirmed, datadir);
    else adc_list(reply, &link, datadir);
}
