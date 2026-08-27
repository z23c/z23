/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Native handlers for the slice-12 `zcode package` swarm leaves — the
 * authenticated package swarm's operator surface:
 *
 *   zcode package fetch    start (or resume) a swarm download of one
 *                          package root: `root` (64 hex) is identity;
 *                          optional `name` is a LOCAL library label from
 *                          the rebuildable store index (never ZNAM).
 *                          Against the live node-global engine when the
 *                          hosting node is running, otherwise a one-shot
 *                          engine over the datadir store persists the
 *                          resumable download record
 *                          (<datadir>/zcode/downloads/<root-hex>) for the
 *                          next hosting boot to resume
 *   zcode package peers    the live swarm's view of the peers advertising
 *                          one package root (tier, in-flight, verified
 *                          served/fetched bytes, allowance + offence
 *                          state) plus THIS node's store-side possession:
 *                          complete, operator-pinned, public-serveable
 *                          (would_serve). Engine-down replies are
 *                          live:false with an empty peer list and still
 *                          report store facts, fail closed.
 *   zcode package offered  the live union of roots peers have ANNOUNCEd
 *                          this session (advertisers from the engine,
 *                          have_local from the observed store). Engine-
 *                          down replies are live:false with an empty
 *                          list — a successful read, never a faked
 *                          catalog. Replica counts are never invented.
 *   zcode package pin      operator-pin a tracked package (PINS pool,
 *                          never evicted, never tier-gated)
 *   zcode package unpin    release an operator pin
 *   zcode package fastobj export  turn one VERIFIED zcl.fastobj.v1
 *                          compile cache into the store as a single
 *                          ordinary content.v2 carrier (the publish-here
 *                          half of the wire compile cache): deterministic
 *                          root, entry/byte counts, and the public-shape
 *                          verdict so the operator sees whether this node
 *                          would serve it
 *   zcode package fastobj admit   re-verify a carrier the store already
 *                          tracks and reconstruct the compile cache into
 *                          cache_dir (the consume-there half) in the
 *                          worker's own store-on-miss format. The swarm
 *                          fetch (zcode package fetch by root) moves the
 *                          carrier between nodes — never these leaves.
 *
 * LIVE VS ONE-SHOT (the same discipline as the publish branch): the CAS
 * bytes under <datadir>/zcode are the only package truth. fetch reads
 * the node-global engine (set by the boot glue when -packagehost=1) so a
 * running node downloads immediately; a one-shot CLI never fakes liveness
 * — it persists the download record and reports live:false, and the
 * engine's resume replay picks the record up at the next hosting boot.
 * Every rejection names the exact rule. */

#include "base/hex.h"
#include "base/log_macros.h"
#include "command/native_command.h"
#include "command/native_zcode_discovery.h"
#include "command/native_zcode_join.h"
#include "controllers/rpc_client.h"
#include "controllers/rpc_params.h"

#include "json/json.h"
#include "platform/time_compat.h"
#include "vcs/fastobj_carrier.h"
#include "vcs/package_index.h"
#include "vcs/package_public_shape.h"
#include "vcs/package_reward.h"
#include "vcs/package_service.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Render cap for peer rows (the LIST budget). */
#define ZW_MAX_PEERS 32u

/* ── small input helpers (the native_zcode_* pattern) ───────────────── */

static const char *zw_input_str(const struct json_value *input,
                                const char *key)
{
    const struct json_value *v = json_get(input, key);
    return v ? json_get_str(v) : NULL;
}

static const char *zw_datadir(const struct zcl_command_request *request)
{
    const char *dd = zw_input_str(request->input, "datadir");
    if (dd && dd[0])
        return dd;
    dd = zcl_native_command_datadir();
    return (dd && dd[0]) ? dd : NULL;
}

static bool zw_zcode_dir(const struct zcl_command_request *request,
                         struct zcl_command_reply *reply,
                         const char *command, char out[4400])
{
    const char *datadir = zw_datadir(request);
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

/* Parse the required `root` input (64 lowercase hex). False with the
 * error body set on bad input. */
static bool zw_root(const struct zcl_command_request *request,
                    struct zcl_command_reply *reply, const char *command,
                    uint8_t out[32])
{
    const char *hex = zw_input_str(request->input, "root");
    if (!hex || !zcl_hex_decode(hex, out, 32)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "root must be 64 lowercase hex chars (the "
                               "package root)", hex ? hex : "(missing)");
        return false;
    }
    (void)command;
    return true;
}

/* Resolve fetch identity: `root` (64 hex) and/or a LOCAL library `name`
 * from the rebuildable package index. Name is not ZNAM. False with the
 * error body set. */
static bool zw_resolve_fetch_root(const struct zcl_command_request *request,
                                  struct zcl_command_reply *reply,
                                  const char *zcode_dir, uint8_t out[32])
{
    const char *hex = zw_input_str(request->input, "root");
    const char *name = zw_input_str(request->input, "name");
    bool have_root = hex && hex[0];
    bool have_name = name && name[0];
    uint8_t from_root[32];
    uint8_t from_name[32];
    bool named = false;

    if (!have_root && !have_name) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "MISSING_ROOT_OR_NAME", "normalize", false, false,
            "supply root (64 hex package identity) or a local library name",
            "zcode.package.fetch");
        return false;
    }
    if (have_root && !zcl_hex_decode(hex, from_root, 32)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "root must be 64 lowercase hex chars (the "
                               "package root)", hex);
        return false;
    }
    if (have_name) {
        struct vcs_package_index *index = vcs_package_index_build(zcode_dir);
        if (!index) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INTERNAL,
                "INDEX_OPEN", "normalize", false, false,
                "the local package index failed to rebuild", zcode_dir);
            return false;
        }
        const struct vcs_package_index_entry *found = NULL;
        bool ambiguous = false;
        for (size_t i = 0; i < vcs_package_index_count(index); i++) {
            const struct vcs_package_index_entry *e =
                vcs_package_index_at(index, i);
            if (!e || strcmp(e->name, name) != 0)
                continue;
            uint8_t candidate[32];
            if (!zcl_hex_decode_lower(e->package_root_hex, candidate, 32)) {
                vcs_package_index_free(index);
                zcl_command_reply_fail(
                    reply, ZCL_COMMAND_STATUS_FAILED,
                    ZCL_COMMAND_EXIT_INTERNAL, "BAD_ROOT", "normalize",
                    false, false,
                    "local library name maps to a non-hex package root",
                    e->package_root_hex);
                return false;
            }
            if (!found) {
                memcpy(from_name, candidate, 32);
                found = e;
            } else if (memcmp(from_name, candidate, 32) != 0) {
                ambiguous = true;
                break;
            }
        }
        vcs_package_index_free(index);
        if (ambiguous) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "AMBIGUOUS_NAME", "normalize", false, false,
                "local library name maps to more than one package root",
                name);
            return false;
        }
        if (!found) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "UNKNOWN_NAME", "normalize", false, false,
                "no local library name matches (name is a store-index "
                "label, not ZNAM)", name);
            return false;
        }
        named = true;
    }
    if (have_root && named && memcmp(from_root, from_name, 32) != 0) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "NAME_ROOT_MISMATCH", "normalize", false, false,
            "name and root identify different 32-byte package roots",
            name);
        return false;
    }
    memcpy(out, named ? from_name : from_root, 32);
    return true;
}

static void zw_push_status(struct json_value *obj,
                           const struct vcs_swarm_download_status *st)
{
    (void)json_push_kv_str(obj, "state",
                           vcs_swarm_download_state_string(st->state));
    if (st->rule)
        (void)json_push_kv_str(obj, "rule", st->rule);
    (void)json_push_kv_int(obj, "advertisers", (int64_t)st->advertisers);
    (void)json_push_kv_int(obj, "inflight", (int64_t)st->inflight);
    (void)json_push_kv_int(obj, "present_chunks",
                           (int64_t)st->present_chunks);
    (void)json_push_kv_int(obj, "total_chunks", (int64_t)st->total_chunks);
    (void)json_push_kv_int(obj, "present_bytes", (int64_t)st->present_bytes);
    (void)json_push_kv_int(obj, "total_bytes", (int64_t)st->total_bytes);
    (void)json_push_kv_int(obj, "fetched_bytes", (int64_t)st->fetched_bytes);
    (void)json_push_kv_int(obj, "requested_bytes",
                           (int64_t)st->requested_bytes);
    (void)json_push_kv_int(obj, "transferred_bytes",
                           (int64_t)st->transferred_bytes);
    (void)json_push_kv_int(obj, "reused_bytes",
                           (int64_t)st->reused_bytes);
    (void)json_push_kv_int(obj, "requested_objects",
                           (int64_t)st->requested_objects);
    (void)json_push_kv_int(obj, "transferred_objects",
                           (int64_t)st->transferred_objects);
    (void)json_push_kv_int(obj, "reused_objects",
                           (int64_t)st->reused_objects);
    (void)json_push_kv_int(obj, "maximum_package_bytes",
                           (int64_t)st->maximum_package_bytes);
}

/* Observe the datadir store without creating one as a READ side-effect
 * and without racing a resident daemon. Global handle first; otherwise
 * open only an already-present <datadir>/zcode. Implicit datadir with a
 * live cookie is the resident's store — a second recovery owner can
 * sweep CAS the daemon is writing. Explicit input datadir is the
 * offline/copy path. */
static struct vcs_package_store *zw_observe_store(
    const struct zcl_command_request *request, bool *own_out)
{
    if (own_out)
        *own_out = false;
    struct vcs_package_store *store = vcs_package_store_global();
    if (store)
        return store;
    const char *datadir = zw_datadir(request);
    if (!datadir || !datadir[0])
        return NULL;
    char zcode[4400];
    int n = snprintf(zcode, sizeof(zcode), "%s/zcode", datadir);
    if (n < 0 || (size_t)n >= sizeof(zcode) || access(zcode, F_OK) != 0)
        return NULL;
    if (!zw_input_str(request->input, "datadir")) {
        char cookie[4400];
        int cn = snprintf(cookie, sizeof(cookie), "%s/.cookie", datadir);
        if (cn > 0 && (size_t)cn < sizeof(cookie) &&
            access(cookie, F_OK) == 0)
            return NULL;
    }
    store = vcs_package_store_open(datadir, vcs_package_store_quota_bytes());
    if (!store) {
        LOG_ERROR("zcode.package.peers",
                  "package store failed to open under %s", zcode);
        return NULL;
    }
    if (own_out)
        *own_out = true;
    return store;
}

/* Store-side possession for one root. Missing store, untracked root, or
 * classify refusal all fail closed: would_serve is false and no replica
 * count is invented. */
static void zw_push_possession(struct json_value *obj,
                               struct vcs_package_store *store,
                               const uint8_t root[32])
{
    bool observed = false;
    bool tracked = false;
    bool complete = false;
    bool pinned = false;
    bool public_serveable = false;
    const char *shape =
        vcs_package_public_shape_string(VCS_PACKAGE_PUBLIC_REFUSED);
    const char *rule = "store-unobserved";
    int64_t present_bytes = 0;
    int64_t total_bytes = 0;

    if (store && root) {
        observed = true;
        struct vcs_package_store_status st;
        memset(&st, 0, sizeof(st));
        if (vcs_package_store_package_status(store, root, &st) &&
            st.tracked) {
            tracked = true;
            complete = st.complete;
            pinned = st.pinned;
            present_bytes = (int64_t)st.present_bytes;
            total_bytes = (int64_t)st.total_bytes;
        }
        struct vcs_package_public_verdict verdict;
        memset(&verdict, 0, sizeof(verdict));
        enum vcs_package_public_shape ps =
            vcs_package_public_shape_classify(store, root, &verdict);
        public_serveable = ps != VCS_PACKAGE_PUBLIC_REFUSED;
        shape = vcs_package_public_shape_string(ps);
        rule = verdict.rule ? verdict.rule : "null-input";
    }

    struct json_value local;
    json_init(&local);
    json_set_object(&local);
    (void)json_push_kv_bool(&local, "observed", observed);
    (void)json_push_kv_bool(&local, "tracked", tracked);
    (void)json_push_kv_bool(&local, "complete", complete);
    (void)json_push_kv_bool(&local, "pinned", pinned);
    (void)json_push_kv_bool(&local, "public_serveable", public_serveable);
    (void)json_push_kv_bool(&local, "would_serve",
                            tracked && complete && public_serveable);
    (void)json_push_kv_str(&local, "public_shape", shape);
    (void)json_push_kv_str(&local, "serve_rule", rule);
    (void)json_push_kv_int(&local, "present_bytes", present_bytes);
    (void)json_push_kv_int(&local, "total_bytes", total_bytes);
    (void)json_push_kv(obj, "possession", &local);
    json_free(&local);
}

static void zw_push_peer_transfer(struct json_value *row,
                                  const struct vcs_swarm_peer_info *p)
{
    struct json_value transfer;
    json_init(&transfer);
    json_set_object(&transfer);
    (void)json_push_kv_int(&transfer, "verified_bytes_served",
                           (int64_t)p->verified_served);
    (void)json_push_kv_int(&transfer, "verified_bytes_fetched",
                           (int64_t)p->verified_from);
    (void)json_push_kv(row, "transfer", &transfer);
    json_free(&transfer);
    (void)json_push_kv_int(row, "verified_bytes_served",
                           (int64_t)p->verified_served);
    (void)json_push_kv_int(row, "verified_bytes_received",
                           (int64_t)p->verified_from);
}

/* ── zcode package fetch ────────────────────────────────────────────── */

void zcl_native_handle_zcode_package_fetch(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    if (!zw_zcode_dir(request, reply, "zcode.package.fetch", zcode_dir))
        return;
    uint8_t root[32];
    if (!zw_resolve_fetch_root(request, reply, zcode_dir, root))
        return;
    /* Live engine first: a running hosting node downloads immediately. */
    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    bool live = engine != NULL;

    /* A command process cannot share the daemon's node-global engine. When
     * the operator supplies a DHT namespace, route the exact root through
     * the running node: provider discovery selects authenticated live peers
     * and the daemon starts the bounded swarm fetch in-process. */
    const char *namespace_name = zw_input_str(request->input, "namespace");
    if (!live && namespace_name && namespace_name[0]) {
        struct json_value selector, routed;
        json_init(&selector);
        json_init(&routed);
        json_set_object(&selector);
        char root_hex[65];
        zcl_hex_encode(root, 32, root_hex);
        bool selector_ok =
            json_push_kv_str(&selector, "kind", "provider") &&
            json_push_kv_str(&selector, "namespace", namespace_name) &&
            json_push_kv_str(&selector, "transport_root", root_hex);
        const struct json_value *maximum =
            json_get(request->input, "maximum_bytes");
        if (selector_ok && maximum)
            selector_ok = maximum->type == JSON_INT &&
                json_push_kv_int(&selector, "maximum_bytes",
                                 json_get_int(maximum));
        uint32_t records = 0;
        bool routed_ok = selector_ok &&
            zcl_native_zcode_provider_discover_and_route(
                &selector, &routed, &records);
        json_free(&selector);
        if (!routed_ok) {
            /* Name the boundary that actually refused. Three unrelated facts
             * used to wear one coat here: nobody published a provider record,
             * the records name peers this node is not authenticated to right
             * now, or the routed carrier arrived and something further along
             * — the swarm fetch, the signed-release import — said no. Only
             * the first two are discovery, and each has a different next step
             * (wait, connect, change a policy rule, or stop retrying because
             * the carrier itself is wrong). A failed reply carries no data
             * object, so what the reader needs belongs in the message. */
            const char *route_code = json_get_str(json_get(&routed, "code"));
            const char *route_error = json_get_str(json_get(&routed, "error"));
            const char *fetch_result = json_get_str(
                json_get(&routed, "fetch_result"));
            char detail[192];
            if (route_code && route_code[0]) {
                /* The node routed the root and then refused under its own
                 * name. Pass that name through rather than blaming discovery
                 * for a failure that happened after it succeeded. The routed
                 * tree is freed before the reply is built, so the code must
                 * be copied out first. */
                char code_copy[64];
                (void)snprintf(code_copy, sizeof(code_copy), "%s", route_code);
                bool transient = strcmp(code_copy, "FETCH_REFUSED") == 0;
                (void)snprintf(detail, sizeof(detail),
                               "%s: %s (fetch=%s, %lu provider record(s))",
                               code_copy,
                               route_error ? route_error : "no reason given",
                               fetch_result ? fetch_result : "none",
                               (unsigned long)records);
                json_free(&routed);
                zcl_command_reply_fail(
                    reply, ZCL_COMMAND_STATUS_BLOCKED,
                    transient ? ZCL_COMMAND_EXIT_TRANSIENT
                              : ZCL_COMMAND_EXIT_BLOCKED,
                    code_copy, "fetch", transient, false, detail,
                    "zcode.package.fetch");
                return;
            }
            (void)snprintf(
                detail, sizeof(detail),
                "no authenticated DHT provider routed the root: "
                "records=%lu authenticated=%lld denied=%lld pending=%lld",
                (unsigned long)records,
                (long long)json_get_int(
                    json_get(&routed, "authenticated_providers")),
                (long long)json_get_int(json_get(&routed, "policy_denied")),
                (long long)json_get_int(
                    json_get(&routed, "reachability_pending")));
            json_free(&routed);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_BLOCKED,
                ZCL_COMMAND_EXIT_TRANSIENT, "PROVIDER_DISCOVERY_FAILED",
                "discover", true, false, detail, "zcode.package.fetch");
            return;
        }
        json_copy(&reply->data, &routed);
        json_free(&routed);
        (void)json_push_kv_str(&reply->data, "transport_root", root_hex);
        if (strcmp(namespace_name, "zclassic23.package") != 0)
            (void)json_push_kv_str(&reply->data, "package_root", root_hex);
        (void)json_push_kv_bool(&reply->data, "live", true);
        (void)json_push_kv_int(&reply->data, "provider_records", records);
        return;
    }

    /* One-shot fallback: open the datadir store + service book and build
     * a temporary engine whose ONLY lasting effect is the persisted,
     * resumable download record (the engine replays <zcode_dir>/
     * downloads at creation, so the next hosting boot resumes it). */
    struct vcs_package_store *store = NULL;
    struct vcs_service_book *book = NULL;
    if (!live) {
        store = vcs_package_store_open(zw_datadir(request),
                                       vcs_package_store_quota_bytes());
        if (!store) {
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                                   "execute", false, false,
                                   "the package store failed to open",
                                   zcode_dir);
            return;
        }
        book = vcs_service_book_load(zcode_dir);
        engine = vcs_swarm_engine_create(store, book, zcode_dir, NULL, NULL);
        if (!engine) {
            vcs_service_book_free(book);
            vcs_package_store_close(store);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INTERNAL, "ENGINE",
                                   "execute", false, false,
                                   "the swarm engine failed to initialize",
                                   zcode_dir);
            return;
        }
    }

    int64_t day = (int64_t)platform_time_wall_unix() / 86400;
    const struct json_value *dv = json_get(request->input, "day");
    if (dv)
        day = json_get_int(dv);
    uint64_t now = (uint64_t)platform_time_wall_unix();
    enum vcs_swarm_fetch_result r =
        vcs_swarm_engine_fetch(engine, root, day, now);

    struct vcs_swarm_download_status st;
    memset(&st, 0, sizeof(st));
    bool have_status = vcs_swarm_engine_download_status(engine, root, &st);

    if (!live) {
        vcs_swarm_engine_free(engine);
        vcs_service_book_free(book);
        vcs_package_store_close(store);
    }

    if (r != VCS_SWARM_FETCH_OK && r != VCS_SWARM_FETCH_ALREADY_COMPLETE) {
        const char *code = "FETCH_REFUSED";
        if (r == VCS_SWARM_FETCH_NO_STORE)
            code = "NO_STORE";
        else if (r == VCS_SWARM_FETCH_FULL)
            code = "DOWNLOAD_SLOTS_FULL";
        else if (r == VCS_SWARM_FETCH_RECORD_IO)
            code = "RECORD_IO";
        else if (r == VCS_SWARM_FETCH_BAD_INPUT)
            code = "BAD_ROOT";
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "execute",
                               false, true,
                               vcs_swarm_fetch_result_string(r),
                               "zcode.package.fetch");
        return;
    }

    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(&reply->data, "transport_root", hex);
    (void)json_push_kv_str(&reply->data, "package_root", hex);
    (void)json_push_kv_bool(&reply->data, "live", live);
    (void)json_push_kv_bool(&reply->data, "already_complete",
                            r == VCS_SWARM_FETCH_ALREADY_COMPLETE);
    (void)json_push_kv_str(
        &reply->data, "result", vcs_swarm_fetch_result_string(r));
    if (have_status) {
        struct json_value sj;
        json_init(&sj);
        json_set_object(&sj);
        zw_push_status(&sj, &st);
        (void)json_push_kv(&reply->data, "download", &sj);
        json_free(&sj);
    }
    if (!live) {
        /* The record is inert until a hosting node loads it. Name `z23 join`
         * (or the restart, once this process is already hosting) instead of
         * reciting `-packagehost=1` as the next boot action. */
        struct zcl_zcode_join_posture join;
        char note[1200];
        const char *dd = zw_datadir(request);
        if (!zcl_zcode_join_posture_fill(&join))
            join.package_hosting = false;
        int n;
        if (join.package_hosting)
            n = snprintf(
                note, sizeof(note),
                "no live hosting engine: the resumable download record is "
                "persisted under <datadir>/zcode/downloads; "
                "systemctl --user restart zclassic23 so the live engine "
                "resumes it (manifest-first, then chunks rarest-first from "
                "the peers advertising the root)");
        else if (dd && dd[0])
            n = snprintf(
                note, sizeof(note),
                "no live hosting engine: the resumable download record is "
                "persisted under <datadir>/zcode/downloads; run "
                "z23 join -datadir=%s then restart so the live engine "
                "resumes it (manifest-first, then chunks rarest-first from "
                "the peers advertising the root)",
                dd);
        else
            n = snprintf(
                note, sizeof(note),
                "no live hosting engine: the resumable download record is "
                "persisted under <datadir>/zcode/downloads; run z23 join "
                "then restart so the live engine resumes it "
                "(manifest-first, then chunks rarest-first from the peers "
                "advertising the root)");
        if (n < 0 || (size_t)n >= sizeof(note))
            (void)snprintf(note, sizeof(note),
                           "no live hosting engine: run z23 join then restart");
        (void)json_push_kv_str(&reply->data, "note", note);
    }
}

/* ── zcode package peers ────────────────────────────────────────────── */

void zcl_native_handle_zcode_package_peers(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    uint8_t root[32];
    if (!zw_root(request, reply, "zcode.package.peers", root))
        return;

    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(&reply->data, "package_root", hex);

    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    bool live = engine != NULL;
    (void)json_push_kv_bool(&reply->data, "live", live);

    bool own_store = false;
    struct vcs_package_store *store = zw_observe_store(request, &own_store);
    zw_push_possession(&reply->data, store, root);
    if (own_store)
        vcs_package_store_close(store);

    if (!live) {
        struct json_value rows;
        json_init(&rows);
        json_set_array(&rows);
        (void)json_push_kv(&reply->data, "peers", &rows);
        json_free(&rows);
        (void)json_push_kv_int(&reply->data, "peer_count", 0);
        (void)json_push_kv_bool(&reply->data, "peers_truncated", false);
        {
            /* Session-scoped peer facts need a live engine. Name `z23 join`
             * (or the restart, once this process is already hosting) instead
             * of reciting `-packagehost=1` as the way to wire it. */
            struct zcl_zcode_join_posture join;
            char note[1200];
            const char *dd = zw_datadir(request);
            if (!zcl_zcode_join_posture_fill(&join))
                join.package_hosting = false;
            int n;
            if (join.package_hosting)
                n = snprintf(
                    note, sizeof(note),
                    "no live hosting engine on this process; "
                    "systemctl --user restart zclassic23 wires it. "
                    "peer facts are session-scoped and never persisted, so a "
                    "one-shot CLI has none to report. possession is "
                    "store-side and is still reported; missing store facts "
                    "fail closed and replica counts are never invented");
            else if (dd && dd[0])
                n = snprintf(
                    note, sizeof(note),
                    "no live hosting engine on this process; run "
                    "z23 join -datadir=%s then restart to wire it. "
                    "peer facts are session-scoped and never persisted, so a "
                    "one-shot CLI has none to report. possession is "
                    "store-side and is still reported; missing store facts "
                    "fail closed and replica counts are never invented",
                    dd);
            else
                n = snprintf(
                    note, sizeof(note),
                    "no live hosting engine on this process; run z23 join "
                    "then restart to wire it. peer facts are session-scoped "
                    "and never persisted, so a one-shot CLI has none to "
                    "report. possession is store-side and is still reported; "
                    "missing store facts fail closed and replica counts are "
                    "never invented");
            if (n < 0 || (size_t)n >= sizeof(note))
                (void)snprintf(
                    note, sizeof(note),
                    "no live hosting engine: run z23 join then restart");
            (void)json_push_kv_str(&reply->data, "note", note);
        }
        return;
    }

    struct vcs_swarm_download_status st;
    memset(&st, 0, sizeof(st));
    if (vcs_swarm_engine_download_status(engine, root, &st)) {
        struct json_value sj;
        json_init(&sj);
        json_set_object(&sj);
        zw_push_status(&sj, &st);
        (void)json_push_kv(&reply->data, "download", &sj);
        json_free(&sj);
    }

    struct vcs_swarm_peer_info infos[ZW_MAX_PEERS];
    size_t count = vcs_swarm_engine_peers_for(engine, root, infos,
                                              ZW_MAX_PEERS);
    struct json_value rows;
    json_init(&rows);
    json_set_array(&rows);
    for (size_t i = 0; i < count; i++) {
        const struct vcs_swarm_peer_info *p = &infos[i];
        char key_hex[67];
        zcl_hex_encode(p->key, 33, key_hex);
        struct json_value row;
        json_init(&row);
        json_set_object(&row);
        (void)json_push_kv_int(&row, "peer", (int64_t)p->peer);
        (void)json_push_kv_str(&row, "session_key", key_hex);
        (void)json_push_kv_str(&row, "tier", vcs_policy_tier_string(p->tier));
        (void)json_push_kv_int(&row, "inflight", (int64_t)p->inflight);
        zw_push_peer_transfer(&row, p);
        (void)json_push_kv_bool(&row, "allowance_exhausted",
                                p->allowance_exhausted);
        (void)json_push_kv_int(&row, "offence_total",
                               (int64_t)p->offence_total);
        (void)json_push_back(&rows, &row);
        json_free(&row);
    }
    (void)json_push_kv(&reply->data, "peers", &rows);
    json_free(&rows);
    (void)json_push_kv_int(&reply->data, "peer_count", (int64_t)count);
    (void)json_push_kv_bool(&reply->data, "peers_truncated",
                            count == ZW_MAX_PEERS);
    (void)json_push_kv_str(
        &reply->data, "note",
        "session_key is the LOCAL transport pseudo-key (0x02 || "
        "SHA3-256(domain || host identity)) — it scopes the service book "
        "to a transport session and is NOT a contributor identity");
}

/* ── zcode package offered ──────────────────────────────────────────── */

void zcl_native_handle_zcode_package_offered(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;

    const char *datadir = zw_datadir(request);
    if (datadir && datadir[0]) {
        char manifests[4400];
        int n = snprintf(manifests, sizeof(manifests), "%s/zcode/manifests",
                         datadir);
        struct stat st;
        if (n > 0 && (size_t)n < sizeof(manifests) &&
            stat(manifests, &st) == 0 && !S_ISDIR(st.st_mode)) {
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "STORE_UNREADABLE", "execute", false, false,
                "package manifests path exists and is not enumerable",
                manifests);
            return;
        }
    }

    struct vcs_swarm_engine *engine = vcs_swarm_engine_global();
    bool live = engine != NULL;
    uint64_t peer_ids[VCS_SWARM_MAX_PEERS];
    size_t peer_count = live ? vcs_swarm_engine_peer_ids(
                                   engine, peer_ids, VCS_SWARM_MAX_PEERS)
                             : 0;
    (void)json_push_kv_bool(&reply->data, "live", live);
    (void)json_push_kv_int(&reply->data, "peer_count",
                           (int64_t)peer_count);
    (void)json_push_kv_bool(&reply->data, "serving_ready",
                            live && peer_count > 0);
    struct zcl_zcode_join_posture join;
    if (!zcl_zcode_join_posture_fill(&join) ||
        !zcl_zcode_join_posture_push_json(&reply->data, &join)) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_FAILED,
            "JOIN_POSTURE_FAILED", "status", false, false,
            "the Commons join posture could not be rendered",
            "zcode.package.offered");
        return;
    }

    struct json_value items;
    json_init(&items);
    json_set_array(&items);

    size_t offered = 0;
    bool truncated = false;
    char first_root[65];
    first_root[0] = '\0';

    if (live) {
        struct vcs_swarm_advertised rows[VCS_SWARM_MAX_LOCAL_ANNOUNCES + 1u];
        size_t n = vcs_swarm_engine_advertised(
            engine, rows, VCS_SWARM_MAX_LOCAL_ANNOUNCES + 1u);
        if (n > VCS_SWARM_MAX_LOCAL_ANNOUNCES) {
            truncated = true;
            n = VCS_SWARM_MAX_LOCAL_ANNOUNCES;
        }

        bool own_store = false;
        struct vcs_package_store *store =
            zw_observe_store(request, &own_store);
        for (size_t i = 0; i < n; i++) {
            char hex[65];
            zcl_hex_encode(rows[i].root, 32, hex);
            if (i == 0)
                memcpy(first_root, hex, sizeof(first_root));

            bool have_local = false;
            if (store) {
                struct vcs_package_store_status st;
                memset(&st, 0, sizeof(st));
                if (vcs_package_store_package_status(store, rows[i].root,
                                                     &st) &&
                    st.tracked && st.complete)
                    have_local = true;
            }

            struct json_value row;
            json_init(&row);
            json_set_object(&row);
            (void)json_push_kv_str(&row, "root", hex);
            (void)json_push_kv_int(&row, "advertisers",
                                   (int64_t)rows[i].advertisers);
            (void)json_push_kv_bool(&row, "have_local", have_local);
            (void)json_push_back(&items, &row);
            json_free(&row);
        }
        if (own_store)
            vcs_package_store_close(store);
        offered = n;
    }

    (void)json_push_kv_int(&reply->data, "offered_count", (int64_t)offered);
    (void)json_push_kv(&reply->data, "items", &items);
    json_free(&items);
    (void)json_push_kv_bool(&reply->data, "truncated", truncated);

    char next[384];
    if (!live) {
        int wn;
        if (join.package_hosting && datadir && datadir[0])
            wn = snprintf(next, sizeof(next),
                          "systemctl --user restart zclassic23, then "
                          "z23 zcode package offered -datadir=%s",
                          datadir);
        else if (join.package_hosting)
            wn = snprintf(next, sizeof(next), "%s",
                          join.offline_next_command);
        else if (datadir && datadir[0])
            wn = snprintf(next, sizeof(next), "z23 join -datadir=%s",
                          datadir);
        else
            wn = snprintf(next, sizeof(next), "z23 join");
        if (wn < 0 || (size_t)wn >= sizeof(next))
            (void)snprintf(next, sizeof(next), "%s",
                           join.offline_next_command);
    } else if (peer_count == 0) {
        (void)snprintf(next, sizeof(next),
                       "wait for an eligible NODE_ZCL23 peer");
    } else if (offered == 0) {
        (void)snprintf(
            next, sizeof(next),
            "wait for ANNOUNCE / z23 zcode package peers "
            "--input='{\"root\":\"<64hex>\"}'");
    } else {
        (void)snprintf(
            next, sizeof(next),
            "z23 zcode package fetch --input='{\"root\":\"%s\"}'",
            first_root);
    }
    (void)json_push_kv_str(&reply->data, "next_command", next);
}

/* ── zcode package pin / unpin ──────────────────────────────────────── */

/* The one-shot CLI must never open the resident's package store: open runs
 * recovery + orphan GC and a second process can race the daemon between its
 * manifest and CAS writes. Route implicit-datadir pin work to the resident.
 * An explicit input datadir remains the deliberate offline/copy path. */
static bool zw_pin_via_resident(const struct zcl_command_request *request,
                                struct zcl_command_reply *reply, bool pinned,
                                const char *command)
{
    if (zw_input_str(request->input, "datadir") ||
        vcs_package_store_global())
        return false;
    const char *datadir = zw_datadir(request);
    char cookie[4400];
    int n = datadir ? snprintf(cookie, sizeof(cookie), "%s/.cookie", datadir)
                     : -1;
    if (n <= 0 || (size_t)n >= sizeof(cookie) || access(cookie, F_OK) != 0)
        return false;

    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, request->input);
    char *params = rpc_arg_builder_to_json(&args);
    zcl_native_bridge_ensure_rpc();
    char *raw = params ? node_rpc_call(
        pinned ? "zcode_package_pin" : "zcode_package_unpin", params) : NULL;
    free(params);
    if (!raw)
        return false; /* the exclusive store lock makes fallback fail safe */

    struct json_value body;
    json_init(&body);
    bool parsed = json_read(&body, raw, strlen(raw)) &&
                  body.type == JSON_OBJ;
    free(raw);
    if (!parsed) {
        json_free(&body);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY",
                               "serialize", false, false,
                               "resident returned an unreadable pin response",
                               command);
        return true;
    }
    const struct json_value *data = json_get(&body, "data");
    if (json_get_bool_or(&body, "ok", false) && data &&
        data->type == JSON_OBJ) {
        json_free(&reply->data);
        json_init(&reply->data);
        json_copy(&reply->data, data);
        json_free(&body);
        return true;
    }
    const char *code = json_get_str(json_get(&body, "code"));
    const char *phase = json_get_str(json_get(&body, "phase"));
    const char *message = json_get_str(json_get(&body, "message"));
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
        code && code[0] ? code : "PIN_RPC_REFUSED",
        phase && phase[0] ? phase : "execute",
        json_get_bool_or(&body, "retryable", false),
        json_get_bool_or(&body, "mutated", false),
        message && message[0] ? message : "resident refused pin operation",
        command);
    json_free(&body);
    return true;
}

static void zw_handle_pin(const struct zcl_command_request *request,
                          struct zcl_command_reply *reply, bool pinned,
                          const char *command)
{
    if (!request || !reply)
        return;
    char zcode_dir[4400];
    struct vcs_package_store *resident_store = vcs_package_store_global();
    if (resident_store) {
        (void)snprintf(zcode_dir, sizeof(zcode_dir), "%s",
                       "resident-package-store");
    } else if (!zw_zcode_dir(request, reply, command, zcode_dir)) {
        return;
    }
    uint8_t root[32];
    if (!zw_root(request, reply, command, root))
        return;
    const char *mode = zw_input_str(request->input, "mode");
    if (!mode || (strcmp(mode, "plan") != 0 && strcmp(mode, "commit") != 0)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "INVALID_MODE",
                               "normalize", false, false,
                               "mode must be exactly plan or commit", command);
        return;
    }
    if (zw_pin_via_resident(request, reply, pinned, command))
        return;

    /* A live daemon owns one store and may be writing CAS temp files while
     * this status/plan runs. Borrow that handle for the node's implicit
     * datadir; opening a second recovery owner over the same files can sweep
     * or GC state that belongs to the live engine. Explicit offline datadirs
     * retain the one-shot owned-store path. */
    bool own_store = false;
    struct vcs_package_store *store =
        zw_input_str(request->input, "datadir")
            ? NULL : resident_store;
    if (!store) {
        store = vcs_package_store_open(
            zw_datadir(request), vcs_package_store_quota_bytes());
        own_store = true;
    }
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                               "execute", false, false,
                               "the package store failed to open", zcode_dir);
        return;
    }
    struct vcs_package_store_status st;
    uint8_t token[32];
    bool have_status = vcs_package_store_pin_plan(
        store, root, pinned, &st, token);
    if (!have_status) {
        if (own_store) vcs_package_store_close(store);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_PACKAGE",
                               "plan", false, true,
                               "package root is not tracked", command);
        return;
    }
    enum vcs_package_store_result r = VCS_PACKAGE_STORE_OK;
    if (strcmp(mode, "commit") == 0) {
        const char *supplied_hex = zw_input_str(request->input, "plan_token");
        uint8_t supplied[32], difference = 0;
        if (!supplied_hex || strlen(supplied_hex) != 64 ||
            !zcl_hex_decode_lower(supplied_hex, supplied, 32)) {
            if (own_store) vcs_package_store_close(store);
            zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                                   ZCL_COMMAND_EXIT_INVALID,
                                   "INVALID_PLAN_TOKEN", "commit", false,
                                   false, "commit requires canonical plan_token",
                                   command);
            return;
        }
        for (size_t i = 0; i < 32; i++)
            difference |= supplied[i] ^ token[i];
        if (difference) {
            if (own_store) vcs_package_store_close(store);
            char root_hex[65], next_input[160];
            zcl_hex_encode(root, 32, root_hex);
            (void)snprintf(next_input, sizeof(next_input),
                           "{\"root\":\"%s\",\"mode\":\"plan\"}", root_hex);
            zcl_command_reply_fail(
                reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
                "STALE_PLAN", "commit", true, false,
                "pin-relevant package state changed after plan; run zcode "
                "package pin mode=plan again",
                command);
            (void)zcl_command_reply_add_next(
                reply, "zcode.package.pin", next_input,
                "re-observe the exact pin plan");
            return;
        }
        r = vcs_package_store_pin(store, root, pinned);
        memset(&st, 0, sizeof(st));
        have_status = vcs_package_store_package_status(store, root, &st);
    }
    if (own_store) vcs_package_store_close(store);

    if (r != VCS_PACKAGE_STORE_OK) {
        const char *code = "STORE_IO";
        if (r == VCS_PACKAGE_STORE_ERR_UNKNOWN_PACKAGE)
            code = "UNKNOWN_PACKAGE";
        else if (r == VCS_PACKAGE_STORE_ERR_QUOTA)
            code = "PINS_POOL_FULL";
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, code, "execute",
                               false, true,
                               vcs_package_store_result_string(r), command);
        return;
    }

    char hex[65];
    char token_hex[65];
    zcl_hex_encode(root, 32, hex);
    zcl_hex_encode(token, 32, token_hex);
    (void)json_push_kv_str(&reply->data, "package_root", hex);
    (void)json_push_kv_str(&reply->data, "mode", mode);
    (void)json_push_kv_str(&reply->data, "plan_token", token_hex);
    (void)json_push_kv_bool(&reply->data, "committed",
                            strcmp(mode, "commit") == 0);
    (void)json_push_kv_bool(&reply->data, "pinned",
                            strcmp(mode, "commit") == 0 ? pinned : st.pinned);
    (void)json_push_kv_str(&reply->data, "result",
                           vcs_package_store_result_string(r));
    if (have_status) {
        struct json_value sj;
        json_init(&sj);
        json_set_object(&sj);
        (void)json_push_kv_bool(&sj, "tracked", st.tracked);
        (void)json_push_kv_bool(&sj, "pinned", st.pinned);
        (void)json_push_kv_bool(&sj, "complete", st.complete);
        (void)json_push_kv_str(&sj, "pool",
                               vcs_package_store_pool_string(st.pool));
        (void)json_push_kv_int(&sj, "present_bytes",
                               (int64_t)st.present_bytes);
        (void)json_push_kv_int(&sj, "total_bytes", (int64_t)st.total_bytes);
        (void)json_push_kv(&reply->data, "package", &sj);
        json_free(&sj);
    }
    (void)json_push_kv_str(
        &reply->data, "note",
        "operator pins are never tier-gated and the PINS pool is never "
        "evicted; contributor-requested pins (pin-allowance-exceeded, "
        "vcs_policy_check_pin) are a separate, earned allowance");
}

void zcl_native_handle_zcode_package_pin(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    zw_handle_pin(request, reply, true, "zcode.package.pin");
}

void zcl_native_handle_zcode_package_unpin(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    zw_handle_pin(request, reply, false, "zcode.package.unpin");
}

/* ── zcode package fastobj export / admit ───────────────────────────── */

/* One shared stats render: the carrier counts are the operator's proof
 * of what moved, in the same vocabulary the lib reports. */
static void zw_push_carrier_stats(struct json_value *obj,
                                  const struct vcs_fastobj_carrier_stats *st)
{
    (void)json_push_kv_int(obj, "entries", (int64_t)st->entries);
    (void)json_push_kv_int(obj, "object_bytes", (int64_t)st->object_bytes);
    (void)json_push_kv_int(obj, "files", (int64_t)st->files);
    (void)json_push_kv_int(obj, "chunks", (int64_t)st->chunks);
    (void)json_push_kv_int(obj, "total_bytes", (int64_t)st->total_bytes);
}

/* The export writes the store, and a serving engine answers wants from
 * the in-memory table of ITS store object. A one-shot CLI export opens a
 * second handle and the bytes land on disk where the resident never
 * looks — it would refuse the very root its own record advertises, as
 * "not-tracked", until restart. Route the export to the resident (same
 * rule as pin): no store in this process, a live cookie at the target
 * datadir, and the input datadir — if any — is that same datadir rather
 * than a deliberate offline copy. The forwarded input drops datadir; the
 * resident contributes its own. */
static bool zw_export_via_resident(const struct zcl_command_request *request,
                                   struct zcl_command_reply *reply,
                                   const char *cache_dir)
{
    if (vcs_package_store_global())
        return false;
    const char *input_dd = zw_input_str(request->input, "datadir");
    const char *cli_dd = zcl_native_command_datadir();
    if (input_dd && input_dd[0]) {
        if (!cli_dd || !cli_dd[0] || strcmp(input_dd, cli_dd) != 0)
            return false;
    }
    const char *datadir = input_dd && input_dd[0] ? input_dd : cli_dd;
    if (!datadir || !datadir[0])
        return false;
    char cookie[4400];
    int n = snprintf(cookie, sizeof(cookie), "%s/.cookie", datadir);
    if (n <= 0 || (size_t)n >= sizeof(cookie) || access(cookie, F_OK) != 0)
        return false;

    struct json_value fwd;
    json_init(&fwd);
    json_set_object(&fwd);
    (void)json_push_kv_str(&fwd, "cache_dir", cache_dir);
    struct rpc_arg_builder args;
    rpc_arg_builder_init(&args);
    rpc_arg_builder_push_value(&args, &fwd);
    char *params = rpc_arg_builder_to_json(&args);
    json_free(&fwd);
    zcl_native_bridge_ensure_rpc();
    char *raw = params ? node_rpc_call(
        "zcode_package_fastobj_export", params) : NULL;
    free(params);
    if (!raw)
        return false; /* the exclusive store lock makes fallback fail safe */

    struct json_value body;
    json_init(&body);
    bool parsed = json_read(&body, raw, strlen(raw)) &&
                  body.type == JSON_OBJ;
    free(raw);
    if (!parsed) {
        json_free(&body);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "BAD_RPC_BODY",
                               "serialize", false, false,
                               "resident returned an unreadable export "
                               "response",
                               "zcode.package.fastobj.export");
        return true;
    }
    const struct json_value *data = json_get(&body, "data");
    if (json_get_bool_or(&body, "ok", false) && data &&
        data->type == JSON_OBJ) {
        json_free(&reply->data);
        json_init(&reply->data);
        json_copy(&reply->data, data);
        json_free(&body);
        return true;
    }
    const char *code = json_get_str(json_get(&body, "code"));
    const char *phase = json_get_str(json_get(&body, "phase"));
    const char *message = json_get_str(json_get(&body, "message"));
    zcl_command_reply_fail(
        reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
        code && code[0] ? code : "EXPORT_RPC_REFUSED",
        phase && phase[0] ? phase : "execute",
        json_get_bool_or(&body, "retryable", false),
        json_get_bool_or(&body, "mutated", false),
        message && message[0] ? message
                              : "resident refused carrier export",
        "zcode.package.fastobj.export");
    json_free(&body);
    return true;
}

void zcl_native_handle_zcode_package_fastobj_export(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    static const char *const command = "zcode.package.fastobj.export";
    /* A resident handler already owns its store directory; only a one-shot
     * CLI (or an explicit offline datadir) must spell it out — the bridge
     * datadir context does not exist inside the daemon. */
    struct vcs_package_store *resident = vcs_package_store_global();
    char zcode_dir[4400];
    if (resident) {
        const char *root_dir = vcs_package_store_root_dir(resident);
        (void)snprintf(zcode_dir, sizeof(zcode_dir), "%s",
                       root_dir && root_dir[0] ? root_dir
                                               : "resident-package-store");
    } else if (!zw_zcode_dir(request, reply, command, zcode_dir)) {
        return;
    }
    const char *cache_dir = zw_input_str(request->input, "cache_dir");
    if (!cache_dir || !cache_dir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_CACHE_DIR",
                               "normalize", false, false,
                               "cache_dir is required (the zcl.fastobj.v1 "
                               "compile-cache directory to export)",
                               command);
        return;
    }
    if (zw_export_via_resident(request, reply, cache_dir))
        return;

    /* The publish-commit store rule: writes go through the resident
     * handle when it owns exactly this <datadir>/zcode — a running host
     * answers from that object, not from the bytes on disk, so publishing
     * through a second handle would leave its engine announcing a root it
     * cannot send until restart. Any other datadir keeps the one-shot
     * owned-store path (which may create the store). */
    const char *resident_root = vcs_package_store_root_dir(resident);
    bool own_store = !(resident_root && strcmp(resident_root, zcode_dir) == 0);
    struct vcs_package_store *store = own_store
        ? vcs_package_store_open(zw_datadir(request),
                                 vcs_package_store_quota_bytes())
        : resident;
    if (!store) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INTERNAL, "NO_STORE",
                               "execute", false, false,
                               "the package store failed to open", zcode_dir);
        return;
    }

    uint8_t root[32];
    struct vcs_fastobj_carrier_stats stats;
    char err[256] = "";
    bool ok = vcs_fastobj_carrier_export(cache_dir, store, root, &stats, err,
                                         sizeof(err));
    if (ok) {
        /* The operator's real question after publish-here: would this
         * node hand the carrier to a stranger? Render the same possession
         * block the peers leaf renders — one classifier, one vocabulary;
         * a refused shape is an honest verdict, never an error. */
        zw_push_possession(&reply->data, store, root);
    }
    if (own_store)
        vcs_package_store_close(store);
    if (!ok) {
        /* The lib refuses the WHOLE cache before any store write when an
         * entry fails verification; a mid-store failure leaves resumable
         * staging (the store never shows a partial package complete). */
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "CARRIER_EXPORT_REFUSED", "verify", true, true,
                               err[0] ? err : "the cache refused export",
                               command);
        return;
    }

    char hex[65];
    zcl_hex_encode(root, 32, hex);
    (void)json_push_kv_str(&reply->data, "package_root", hex);
    (void)json_push_kv_str(&reply->data, "cache_dir", cache_dir);
    (void)json_push_kv_str(&reply->data, "carrier_prefix",
                           VCS_FASTOBJ_CARRIER_PREFIX);
    zw_push_carrier_stats(&reply->data, &stats);
    char pin_input[160];
    if (snprintf(pin_input, sizeof(pin_input),
                 "{\"root\":\"%s\",\"mode\":\"plan\"}", hex) > 0)
        (void)zcl_command_reply_add_next(
            reply, "zcode.package.pin", pin_input,
            "protect the carrier from eviction (the PINS pool is never "
            "evicted; the carrier itself lands in the evictable pool)");
    (void)json_push_kv_str(
        &reply->data, "note",
        "the carrier is an ORDINARY content.v2 package: cross-node "
        "transport is not this leaf (fetch the root with 'zcode package "
        "fetch' on the receiving node, then 'zcode package fastobj "
        "admit'); nothing was compiled, linked, executed or announced "
        "here, and possession.public_shape says whether this node would "
        "serve it publicly");
}

void zcl_native_handle_zcode_package_fastobj_admit(
    const struct zcl_command_request *request,
    struct zcl_command_reply *reply)
{
    if (!request || !reply)
        return;
    static const char *const command = "zcode.package.fastobj.admit";
    /* package_root is the documented field; root stays accepted because
     * every sibling leaf (and fetch's own reply) spells it that way. */
    const char *hex = zw_input_str(request->input, "package_root");
    if (!hex || !hex[0])
        hex = zw_input_str(request->input, "root");
    uint8_t root[32];
    if (!hex || !zcl_hex_decode(hex, root, 32)) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "BAD_ROOT",
                               "normalize", false, false,
                               "package_root must be 64 lowercase hex chars "
                               "(the carrier's package root)",
                               hex ? hex : "(missing)");
        return;
    }
    const char *cache_dir = zw_input_str(request->input, "cache_dir");
    if (!cache_dir || !cache_dir[0]) {
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "MISSING_CACHE_DIR",
                               "normalize", false, false,
                               "cache_dir is required (the compile cache to "
                               "reconstruct; it is created on demand)",
                               command);
        return;
    }
    char zcode_dir[4400];
    if (!zw_zcode_dir(request, reply, command, zcode_dir))
        return;

    /* The observe rule (the peers leaf): admit only READS the store — the
     * cache is what it writes — so it never creates <datadir>/zcode as a
     * read side-effect and never opens a second recovery owner behind a
     * live daemon's cookie. An explicit input datadir is the deliberate
     * offline/copy path and must already hold the carrier. When the
     * in-process resident owns exactly this store, borrowing its handle is
     * the only safe read — a second open of the same root would contend
     * with it on the store's own process lock. */
    bool own_store = false;
    struct vcs_package_store *store = NULL;
    struct vcs_package_store *resident = vcs_package_store_global();
    const char *resident_root = vcs_package_store_root_dir(resident);
    if (resident_root && strcmp(resident_root, zcode_dir) == 0) {
        store = resident;
    } else if (zw_input_str(request->input, "datadir")) {
        if (access(zcode_dir, F_OK) == 0) {
            store = vcs_package_store_open(
                zw_datadir(request), vcs_package_store_quota_bytes());
            own_store = store != NULL;
        }
    } else {
        store = zw_observe_store(request, &own_store);
    }
    if (!store) {
        zcl_command_reply_fail(
            reply, ZCL_COMMAND_STATUS_FAILED, ZCL_COMMAND_EXIT_INVALID,
            "NO_STORE", "execute", false, false,
            "no package store to admit from (fetch the carrier root first: "
            "'zcode package fetch --input={\"root\":\"<64hex>\"}')",
            zcode_dir);
        return;
    }

    struct vcs_package_store_status st;
    memset(&st, 0, sizeof(st));
    if (!vcs_package_store_package_status(store, root, &st) || !st.tracked) {
        if (own_store)
            vcs_package_store_close(store);
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID, "UNKNOWN_PACKAGE",
                               "execute", false, false,
                               "package root is not tracked by this store "
                               "(fetch it first: 'zcode package fetch')",
                               command);
        return;
    }

    struct vcs_fastobj_carrier_stats stats;
    char err[256] = "";
    bool ok = vcs_fastobj_carrier_admit(cache_dir, store, root, &stats, err,
                                        sizeof(err));
    if (own_store)
        vcs_package_store_close(store);
    if (!ok) {
        /* Admit writes entries as it verifies them, so a refusal can hold
         * a verified prefix — every landed entry was fully re-checked, and
         * the divergent entry itself never landed. */
        zcl_command_reply_fail(reply, ZCL_COMMAND_STATUS_FAILED,
                               ZCL_COMMAND_EXIT_INVALID,
                               "CARRIER_ADMIT_REFUSED", "verify", true, true,
                               err[0] ? err : "the carrier refused admit",
                               command);
        return;
    }

    /* hex aliases the request's input string; render into a local buffer
     * rather than mutating the caller's JSON. */
    char root_hex[65];
    zcl_hex_encode(root, 32, root_hex);
    (void)json_push_kv_str(&reply->data, "package_root", root_hex);
    (void)json_push_kv_str(&reply->data, "cache_dir", cache_dir);
    (void)json_push_kv_str(&reply->data, "carrier_prefix",
                           VCS_FASTOBJ_CARRIER_PREFIX);
    zw_push_carrier_stats(&reply->data, &stats);
    (void)json_push_kv_str(
        &reply->data, "note",
        "every entry re-verified (manifest re-rooted, chunks re-hashed, "
        "sidecar + key + object SHA3 re-checked) and landed in the "
        "confined build worker's own store-on-miss format, so its hit path "
        "re-verifies imported bytes unchanged; nothing was compiled, "
        "linked, executed or installed here. Cross-node transport happened "
        "before this leaf: 'zcode package fetch' by this root");
}
