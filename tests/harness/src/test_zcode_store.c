/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_store — the local ZCODE package store gate
 * (contexts/commons/modules/vcs/package_store.*).
 *
 * Coverage:
 *   1. Flags (-packagehost default off, -packagequota default 10 GiB),
 *      layout creation, result/pool strings.
 *   2. Manifest admission: valid, idempotent re-put, 64 MiB cap, quota
 *      feasibility, and rejection of traversal paths / symlink modes /
 *      garbage wires (the store only ever writes hash-named files, but a
 *      hostile manifest must never be admitted at all).
 *   3. Chunk flow: wrong package, wrong coordinates, hash mismatch,
 *      verify-before-store, completion commit sweep, get round-trip.
 *   4. Dedup: shared chunk stored once, per-package accounting, shared
 *      chunk survives eviction of the other package.
 *   5. Crash recovery: resumable staging, temp sweep, orphan GC,
 *      commit-at-open sweep, completion rebuilt from the CAS, and a corrupt
 *      local CAS object quarantined on read then repaired by a verified put.
 *   6. Quota: staging pool exhaustion (in-flight work preserved),
 *      deterministic HOT (LRU) and RARE (replicas desc) eviction,
 *      pins never evicted + pins budget, pre-existing pin markers.
 *   7. Release envelope storage through the acceptance layer.
 *   8. dump_state_json: disabled shape, enabled totals, key drilldown.
 *      Swarm engine dumpstate (`zcode_swarm`): hosting-off shape, injected
 *      engine peer rows, dumpstate registry key. Receipt dumpstate
 *      (`zcode_swarm_receipts`): hosting-off shape, open-session peer
 *      rows, dumpstate registry key.
 *   9. Blob surface (vcs/blob_store.h): the FROZEN golden root vector,
 *      root purity across independent constructions, length commitment,
 *      put/get round-trip, idempotent re-put, the size ceiling refused by
 *      name with nothing stored, absent-root and small-buffer failures,
 *      and a CAS object corrupted on disk failing verification on read.
 *
 * Stores open on ./test-tmp dirs with explicit quotas; the only global
 * state touched (args + datadir, for the enabled-dump case) is restored
 * before the group returns. */

#include "test/test_core.h"

#include "models/build_fabric.h"
#include "services/build_fabric_cache.h"
#include "services/build_fabric_service.h"
#include "vcs/build_action.h"
#include "vcs/build_execution_observation.h"
#include "vcs/package_store.h"

#include "vcs/blob_store.h"
#include "vcs/package_deps.h"
#include "vcs/package_manifest.h"
#include "vcs/package_recipe.h"
#include "vcs/package_possession_scheduler.h"
#include "vcs/package_swarm_node.h"
#include "vcs/package_swarm_status.h"
#include "vcs/zcode_work_output.h"
#include "vcs/zcode_action_input.h"
#include "vcs/zcode_dev.h"
#include "vcs/zcode_task_authority.h"
#include "vcs/vcs.h"
#include "vcs/vcs_object.h"

#include "config/boot_zcode_swarm_receipt.h"
#include "controllers/diagnostics_internal.h"

#include "base/hex.h"
#include "chain/chainparams.h"
#include "core/uint256.h"
#include "crypto/ed25519.h"
#include "crypto/sha3.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "util/util.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test/test_zcode_store_priv.h"

void zs_hex32(const uint8_t in[32], char out[65])
{
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[2 * i]     = hexd[(in[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[in[i] & 0xf];
    }
    out[64] = '\0';
}

/* A package of `count` single-chunk files; file i is paths[i] of lens[i]
 * bytes, content byte j = (uint8_t)(seed + i * 7 + j). */
bool zs_make_package(struct zs_pkg *p, size_t count,
                            const char *const paths[], const size_t lens[],
                            uint8_t seed)
{
    memset(p, 0, sizeof(*p));
    if (count > ZS_MAX_FILES)
        return false;
    vcs_package_manifest_init(&p->manifest);
    for (size_t i = 0; i < count; i++) {
        if (lens[i] == 0 || lens[i] > ZS_MAX_FILE)
            return false;
        for (size_t j = 0; j < lens[i]; j++)
            p->contents[i][j] = (uint8_t)(seed + i * 7u + j);
        p->lens[i] = lens[i];
        snprintf(p->paths[i], sizeof(p->paths[i]), "%s", paths[i]);
        uint8_t hash[32];
        if (!vcs_package_chunk_hash(p->contents[i], lens[i], hash))
            return false;
        if (!vcs_package_manifest_add(&p->manifest, paths[i],
                                      VCS_PACKAGE_MODE_FILE, lens[i], hash,
                                      1))
            return false;
    }
    p->count = count;
    if (!vcs_package_manifest_serialize(&p->manifest, &p->wire,
                                        &p->wire_len))
        return false;
    if (!vcs_package_manifest_root(&p->manifest, p->root))
        return false;
    zs_hex32(p->root, p->root_hex);
    return true;
}

void zs_free_package(struct zs_pkg *p)
{
    vcs_package_manifest_free(&p->manifest);
    free(p->wire);
    p->wire = NULL;
}

/* Hand-encode a one-file manifest wire with caller-chosen path and mode —
 * the only way to get a traversal path or a symlink mode past the
 * builder, which is exactly what the store must reject. */
size_t zs_raw_wire(uint8_t *out, const char *path, uint32_t mode)
{
    size_t n = 0;
    memcpy(out + n, "ZCLPKG\r\n", 8); n += 8;
    out[n++] = 1; out[n++] = 0;                 /* version */
    out[n++] = 0; out[n++] = 0; out[n++] = 16; out[n++] = 0; /* 1 MiB */
    out[n++] = 1; out[n++] = 0; out[n++] = 0; out[n++] = 0;  /* 1 file */
    size_t plen = strlen(path);
    out[n++] = (uint8_t)plen; out[n++] = (uint8_t)(plen >> 8);
    memcpy(out + n, path, plen); n += plen;
    for (int b = 0; b < 4; b++) out[n++] = (uint8_t)(mode >> (8 * b));
    out[n++] = 1; for (int b = 1; b < 8; b++) out[n++] = 0;  /* size 1 */
    out[n++] = 1; out[n++] = 0; out[n++] = 0; out[n++] = 0;  /* 1 chunk */
    memset(out + n, 0xaa, 32); n += 32;
    return n;
}

bool zs_path_exists(const char *path)
{
    return access(path, F_OK) == 0;
}

void zs_store_path(char *out, size_t n, const char *datadir,
                          const char *suffix)
{
    snprintf(out, n, "%s/zcode/%s", datadir, suffix);
}

/* Put every chunk of every file of p. Stops at the first non-OK. The
 * manifest sorts files by path, so contents are matched back by name. */
enum vcs_package_store_result zs_put_all(
    struct vcs_package_store *store, const struct zs_pkg *p)
{
    for (size_t i = 0; i < p->count; i++) {
        const char *path = p->manifest.files[i].path;
        size_t at = p->count;
        for (size_t j = 0; j < p->count; j++)
            if (strcmp(p->paths[j], path) == 0)
                at = j;
        if (at == p->count)
            return VCS_PACKAGE_STORE_ERR_CHUNK_COORD;
        enum vcs_package_store_result r = vcs_package_store_put_chunk(
            store, p->root, path, 0, p->contents[at], p->lens[at]);
        if (r != VCS_PACKAGE_STORE_OK)
            return r;
    }
    return VCS_PACKAGE_STORE_OK;
}

struct vcs_package_store *zs_open(char *datadir, size_t n,
                                         const char *tag, uint64_t quota)
{
    test_make_tmpdir(datadir, n, "zcode_store", tag);
    return vcs_package_store_open(datadir, quota);
}

/* ── release fixture (acceptance-layer consumption) ───────────────── */

bool zs_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

bool zs_sign(struct vcs_package_release *r, struct privkey *sk)
{
    uint8_t id[VCS_PACKAGE_RELEASE_ID_BYTES];
    if (vcs_package_release_id(r, id) != VCS_PACKAGE_RELEASE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(sk, &hash, compact))
        return false;
    memcpy(r->signature, compact + 1, VCS_PACKAGE_RELEASE_SIGNATURE_BYTES);
    return true;
}

bool zs_t1(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pk_len = 0, sc_len = 0;
    const unsigned char *pk =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pk_len);
    const unsigned char *sc =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &sc_len);
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x44, 20);
    return encode_destination(&dest, pk, pk_len, sc, sc_len, out, out_size);
}

bool zs_release(struct vcs_package_release *r, uint8_t seed,
                       uint64_t sequence, const char *name)
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!zs_keypair(seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    for (int i = 0; i < 32; i++) {
        r->package_root[i] = (uint8_t)(0x10 + i);
        r->recipe_root[i]  = (uint8_t)(0x50 + i);
    }
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = sequence;
    if (!zs_t1(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "MIT");
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return zs_sign(r, &sk);
}

/* ── 11: dump_state_json ──────────────────────────────────────────── */
static int store_case_dump_disabled(void)
{
    int failures = 0;
    struct json_value v;
    json_init(&v);
    ZS_CHECK("dump: disabled store reports enabled=false",
             vcs_package_store_dump_state_json(&v, NULL) &&
             json_get(&v, "enabled") &&
             !json_get_bool(json_get(&v, "enabled")));
    json_free(&v);
    return failures;
}

static int store_case_dump_enable_and_open(const char *dd)
{
    int failures = 0;
    ZS_CHECK("dump: hosting flag now on",
             vcs_package_store_hosting_enabled() &&
             vcs_package_store_quota_bytes() == 1000000u);
    ZS_CHECK("dump: global store opens",
             vcs_package_store_open_global() &&
             vcs_package_store_global() != NULL);

    /* A command handed a datadir has to decide whether the resident store
     * already covers it: publishing through a second handle over the same
     * directory writes correct bytes into a store the running node's serving
     * engine never hears about. The answer is this exact string, so it is
     * asserted here rather than guessed at each call site. */
    char expect_root[512];
    (void)snprintf(expect_root, sizeof(expect_root), "%s/zcode", dd);
    ZS_CHECK("dump: the store names the directory it owns",
             vcs_package_store_root_dir(vcs_package_store_global()) != NULL &&
             strcmp(vcs_package_store_root_dir(vcs_package_store_global()),
                    expect_root) == 0);
    ZS_CHECK("dump: no store owns no directory",
             vcs_package_store_root_dir(NULL) == NULL);
    return failures;
}

static int store_case_dump_package_totals(struct vcs_package_store *s,
                                           struct zs_pkg *p)
{
    int failures = 0;
    const char *paths[] = { "dump.txt" };
    const size_t lens[] = { 64 };
    ZS_CHECK("dump: fixture builds", zs_make_package(p, 1, paths, lens,
                                                     0xbb));
    ZS_CHECK("dump: package admitted + complete",
             vcs_package_store_put_manifest(s, p->wire, p->wire_len, NULL) ==
                 VCS_PACKAGE_STORE_OK &&
             zs_put_all(s, p) == VCS_PACKAGE_STORE_OK);

    struct json_value v;
    json_init(&v);
    bool ok = vcs_package_store_dump_state_json(&v, NULL);
    ZS_CHECK("dump: enabled store reports totals",
             ok && json_get(&v, "enabled") &&
             json_get_bool(json_get(&v, "enabled")) &&
             json_get_int(json_get(&v, "quota_bytes")) == 1000000 &&
             json_get_int(json_get(&v, "tracked_packages")) == 1 &&
             json_get_int(json_get(&v, "pins_budget_bytes")) == 200000 &&
             json_get_int(json_get(&v, "rare_usage_bytes")) == 64 &&
             json_get_int(json_get(&v, "cas_chunks")) == 1);
    json_free(&v);
    return failures;
}

static int store_case_dump_release_publication(struct vcs_package_store *s)
{
    int failures = 0;
    /* Slice 3 publication state: a persisted release is counted and the
     * last acceptance outcome is reported. */
    chain_params_select(CHAIN_MAIN);
    struct vcs_package_release r;
    ZS_CHECK("dump: release fixture signs",
             zs_release(&r, 0x22, 1u, "rhett/dump-pkg"));
    enum vcs_package_accept_result ar = VCS_PACKAGE_ACCEPT_ERR_NULL;
    ZS_CHECK("dump: release admitted",
             vcs_package_store_put_release(s, &r, &ar) ==
                 VCS_PACKAGE_STORE_OK && ar == VCS_PACKAGE_ACCEPT_OK);
    struct json_value v;
    json_init(&v);
    bool ok = vcs_package_store_dump_state_json(&v, NULL);
    ZS_CHECK("dump: publication state reported",
             ok &&
             json_get_int(json_get(&v, "releases_total")) == 1 &&
             json_get_str(json_get(&v, "last_release_accept")) &&
             strcmp(json_get_str(json_get(&v, "last_release_accept")),
                    "accepted") == 0 &&
             json_get(&v, "last_release_id") != NULL);
    json_free(&v);
    return failures;
}

static int store_case_dump_key_drilldown(const char *root_hex)
{
    int failures = 0;
    struct json_value v;
    json_init(&v);
    bool ok = vcs_package_store_dump_state_json(&v, root_hex);
    ZS_CHECK("dump: package-root key drills down",
             ok && json_get(&v, "complete") &&
             json_get_bool(json_get(&v, "complete")) &&
             json_get_int(json_get(&v, "present_bytes")) == 64);
    json_free(&v);

    json_init(&v);
    ok = vcs_package_store_dump_state_json(&v, "not-a-root");
    ZS_CHECK("dump: bad key names the error",
             ok && json_get(&v, "error") != NULL);
    json_free(&v);
    return failures;
}

static int t_store_dump_state(void)
{
    int failures = 0;
    failures += store_case_dump_disabled();

    /* Enabled global store via the real flag + datadir path. */
    const char *argv[] = { "zclassic23-test", "-packagehost=1",
                           "-packagequota=1000000" };
    ParseParameters(3, argv);
    char dd[256];
    test_make_tmpdir(dd, sizeof(dd), "zcode_store", "dump");
    SetDataDir(dd);
    failures += store_case_dump_enable_and_open(dd);

    struct zs_pkg p;
    struct vcs_package_store *s = vcs_package_store_global();
    failures += store_case_dump_package_totals(s, &p);
    failures += store_case_dump_release_publication(s);
    failures += store_case_dump_key_drilldown(p.root_hex);

    vcs_package_store_close_global();
    ZS_CHECK("dump: global closed", vcs_package_store_global() == NULL);

    /* Restore global flags/datadir for the rest of the process. */
    const char *reset_argv[] = { "zclassic23-test" };
    ParseParameters(1, reset_argv);
    SetDataDir("");
    zs_free_package(&p);
    test_rm_rf_recursive(dd);
    return failures;
}

/* ── 12: swarm engine dump_state_json ─────────────────────────────── */
static int store_case_swarm_dump_unwired_shape(struct json_value *v)
{
    int failures = 0;
    ZS_CHECK("swarm dump: unwired engine reports present=false",
             vcs_package_swarm_status_dump_state_json(v, NULL) &&
             json_get(v, "enabled") &&
             !json_get_bool(json_get(v, "enabled")) &&
             json_get(v, "present") &&
             !json_get_bool(json_get(v, "present")) &&
             json_get_int(json_get(v, "peer_count")) == 0 &&
             json_get_int(json_get(v, "active_downloads")) == 0 &&
             json_get_int(json_get(v, "advertised_count")) == 0 &&
             json_get(v, "peers") &&
             json_get(v, "peers")->type == JSON_ARR &&
             json_size(json_get(v, "peers")) == 0 &&
             json_get(v, "advertised") &&
             json_get(v, "advertised")->type == JSON_ARR &&
             json_size(json_get(v, "advertised")) == 0);
    return failures;
}

static int store_case_swarm_dump_unwired(void)
{
    int failures = 0;
    struct json_value v;
    json_init(&v);
    failures += store_case_swarm_dump_unwired_shape(&v);
    char rendered[2048];
    size_t rendered_len = json_write(&v, rendered, sizeof(rendered));
    ZS_CHECK("swarm dump: hosting-off snapshot leaks no paths or keys",
             rendered_len < sizeof(rendered) &&
             strstr(rendered, "datadir") == NULL &&
             strstr(rendered, "wallet") == NULL &&
             strstr(rendered, "/home/") == NULL &&
             strstr(rendered, "secret") == NULL);
    json_free(&v);
    return failures;
}

static int store_case_swarm_dump_rpc_integration(void)
{
    int failures = 0;
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    struct json_value sub;
    json_init(&sub);
    json_set_str(&sub, "zcode_swarm");
    bool dumpstate_ok = json_push_back(&params, &sub);
    json_free(&sub);
    struct json_value result;
    json_init(&result);
    dumpstate_ok = dumpstate_ok &&
                   diag_rpc_dumpstate(&params, false, &result);
    const struct json_value *state = json_get(&result, "state");
    const char *sys = json_get_str(json_get(&result, "subsystem"));
    ZS_CHECK("swarm dump: dumpstate includes zcode_swarm",
             dumpstate_ok && sys && strcmp(sys, "zcode_swarm") == 0 &&
             state && state->type == JSON_OBJ &&
             json_get(state, "enabled") &&
             !json_get_bool(json_get(state, "enabled")) &&
             json_get(state, "present") &&
             !json_get_bool(json_get(state, "present")));
    json_free(&params);
    json_free(&result);
    return failures;
}

static int store_case_swarm_dump_wired_peers_register(
    struct vcs_swarm_engine *engine)
{
    int failures = 0;
    uint8_t key_a[33];
    uint8_t key_b[33];
    key_a[0] = 0x02;
    key_b[0] = 0x02;
    memset(key_a + 1, 0x11, 32);
    memset(key_b + 1, 0x22, 32);
    ZS_CHECK("swarm dump: two peers register",
             vcs_swarm_engine_peer_add(engine, 7, key_a) &&
             vcs_swarm_engine_peer_add(engine, 11, key_b));
    vcs_swarm_engine_set_global(engine);
    return failures;
}

static int store_case_swarm_dump_wired_shape_row0(
    bool ok, const struct json_value *v, const struct json_value *peers,
    const struct json_value *row0)
{
    int failures = 0;
    ZS_CHECK("swarm dump: wired engine reports peers and zero transfers",
             ok && json_get(v, "enabled") &&
             json_get_bool(json_get(v, "enabled")) &&
             json_get_bool(json_get(v, "present")) &&
             json_get_int(json_get(v, "peer_count")) == 2 &&
             json_get_int(json_get(v, "active_downloads")) == 0 &&
             json_get_int(json_get(v, "advertised_count")) == 0 &&
             peers && json_size(peers) == 2 &&
             json_get(v, "advertised") &&
             json_size(json_get(v, "advertised")) == 0 &&
             row0 && json_get_int(json_get(row0, "peer_id")) == 7 &&
             json_get_int(json_get(row0, "served_bytes")) == 0 &&
             json_get_int(json_get(row0, "fetched_bytes")) == 0);
    return failures;
}

static int store_case_swarm_dump_wired_shape(struct json_value *v)
{
    int failures = 0;
    bool ok = vcs_package_swarm_status_dump_state_json(v, NULL);
    const struct json_value *peers = json_get(v, "peers");
    const struct json_value *row0 = peers ? json_at(peers, 0) : NULL;
    const struct json_value *row1 = peers ? json_at(peers, 1) : NULL;
    failures += store_case_swarm_dump_wired_shape_row0(ok, v, peers, row0);
    ZS_CHECK("swarm dump: second peer row present",
             row1 && json_get_int(json_get(row1, "peer_id")) == 11);
    return failures;
}

static int store_case_swarm_dump_wired_snapshot(
    struct vcs_swarm_engine *engine)
{
    int failures = 0;
    failures += store_case_swarm_dump_wired_peers_register(engine);

    struct json_value v;
    json_init(&v);
    failures += store_case_swarm_dump_wired_shape(&v);
    char rendered[2048];
    size_t rendered_len = json_write(&v, rendered, sizeof(rendered));
    ZS_CHECK("swarm dump: live snapshot leaks no accounting keys",
             rendered_len < sizeof(rendered) &&
             strstr(rendered, "datadir") == NULL &&
             strstr(rendered, "wallet") == NULL &&
             strstr(rendered, "key") == NULL);
    json_free(&v);
    return failures;
}

static int t_swarm_engine_dump_state(void)
{
    int failures = 0;
    struct vcs_swarm_engine *prev = vcs_swarm_engine_global();
    vcs_swarm_engine_set_global(NULL);

    failures += store_case_swarm_dump_unwired();
    failures += store_case_swarm_dump_rpc_integration();

    struct vcs_swarm_engine *engine =
        vcs_swarm_engine_create(NULL, NULL, NULL, NULL, NULL);
    ZS_CHECK("swarm dump: engine creates without store or datadir",
             engine != NULL);
    if (!engine) {
        vcs_swarm_engine_set_global(prev);
        return failures;
    }
    failures += store_case_swarm_dump_wired_snapshot(engine);

    vcs_swarm_engine_set_global(NULL);
    vcs_swarm_engine_free(engine);
    vcs_swarm_engine_set_global(prev);
    return failures;
}

/* ── 13: swarm receipt dump_state_json ────────────────────────────── */
static int receipt_case_dump_closed(void)
{
    int failures = 0;
    struct json_value v;
    json_init(&v);
    ZS_CHECK("receipt dump: closed session reports present=false",
             boot_zcode_swarm_receipt_dump_state_json(&v, NULL) &&
             json_get(&v, "enabled") &&
             !json_get_bool(json_get(&v, "enabled")) &&
             json_get(&v, "present") &&
             !json_get_bool(json_get(&v, "present")) &&
             json_get_int(json_get(&v, "settled_peers")) == 0 &&
             json_get(&v, "peers") &&
             json_get(&v, "peers")->type == JSON_ARR &&
             json_size(json_get(&v, "peers")) == 0 &&
             json_get(&v, "local_pub_prefix") == NULL);
    char rendered[2048];
    size_t rendered_len = json_write(&v, rendered, sizeof(rendered));
    ZS_CHECK("receipt dump: hosting-off snapshot leaks no paths or keys",
             rendered_len < sizeof(rendered) &&
             strstr(rendered, "datadir") == NULL &&
             strstr(rendered, "wallet") == NULL &&
             strstr(rendered, "/home/") == NULL &&
             strstr(rendered, "secret") == NULL);
    json_free(&v);
    return failures;
}

static int receipt_case_dump_rpc_shape(const struct json_value *result,
                                        bool dumpstate_ok)
{
    int failures = 0;
    const struct json_value *state = json_get(result, "state");
    const char *sys = json_get_str(json_get(result, "subsystem"));
    ZS_CHECK("receipt dump: dumpstate includes zcode_swarm_receipts",
             dumpstate_ok && sys && strcmp(sys, "zcode_swarm_receipts") == 0 &&
             state && state->type == JSON_OBJ &&
             json_get(state, "enabled") &&
             !json_get_bool(json_get(state, "enabled")) &&
             json_get(state, "present") &&
             !json_get_bool(json_get(state, "present")) &&
             json_get_int(json_get(state, "settled_peers")) == 0 &&
             json_get(state, "peers") &&
             json_size(json_get(state, "peers")) == 0);
    return failures;
}

static int receipt_case_dump_rpc_integration(void)
{
    int failures = 0;
    struct json_value params;
    json_init(&params);
    json_set_array(&params);
    struct json_value sub;
    json_init(&sub);
    json_set_str(&sub, "zcode_swarm_receipts");
    bool dumpstate_ok = json_push_back(&params, &sub);
    json_free(&sub);
    struct json_value result;
    json_init(&result);
    dumpstate_ok = dumpstate_ok &&
                   diag_rpc_dumpstate(&params, false, &result);
    failures += receipt_case_dump_rpc_shape(&result, dumpstate_ok);
    json_free(&params);
    json_free(&result);
    return failures;
}

static int receipt_case_dump_session_setup(
    struct vcs_swarm_receipt_session *local,
    struct vcs_swarm_receipt_session *remote, char expect_prefix[9])
{
    int failures = 0;
    uint8_t ident[VCS_SWARM_RECEIPT_IDENTITY_BYTES];
    size_t ident_len = 0;
    ZS_CHECK("receipt dump: remote identity noted",
             vcs_swarm_receipt_identity_take(remote, 7, ident, sizeof(ident),
                                             &ident_len) &&
             vcs_swarm_receipt_identity_note(local, 7, ident, ident_len));

    uint64_t ids[VCS_SWARM_MAX_PEERS];
    size_t n = vcs_swarm_receipt_session_peer_ids(local, ids,
                                                  VCS_SWARM_MAX_PEERS);
    ZS_CHECK("receipt dump: enumerator returns the noted peer",
             n == 1 && ids[0] == 7 &&
             !vcs_swarm_receipt_session_settled(local, 7));

    uint8_t pub[33];
    memset(pub, 0, sizeof(pub));
    memset(expect_prefix, 0, 9);
    ZS_CHECK("receipt dump: local pub is present",
             vcs_swarm_receipt_session_local_pub(local, pub));
    zcl_hex_encode(pub, 4, expect_prefix);
    return failures;
}

static int receipt_case_dump_session_shape_prefix(
    bool ok, const struct json_value *v, const char *expect_prefix,
    const struct json_value *peers, const struct json_value *row0)
{
    int failures = 0;
    const char *prefix = json_get_str(json_get(v, "local_pub_prefix"));
    ZS_CHECK("receipt dump: open session reports prefix and peer row",
             ok && json_get_bool(json_get(v, "enabled")) &&
             json_get_bool(json_get(v, "present")) &&
             prefix && strcmp(prefix, expect_prefix) == 0 &&
             strlen(prefix) == 8 &&
             json_get_int(json_get(v, "settled_peers")) == 0 &&
             peers && json_size(peers) == 1 &&
             row0 && json_get_int(json_get(row0, "peer_id")) == 7);
    return failures;
}

static int receipt_case_dump_session_shape_peer_row(
    const struct json_value *row0)
{
    int failures = 0;
    ZS_CHECK("receipt dump: peer row reports settled/have_remote",
             row0 && json_get(row0, "settled") &&
             !json_get_bool(json_get(row0, "settled")) &&
             json_get(row0, "have_remote") &&
             json_get_bool(json_get(row0, "have_remote")));
    return failures;
}

static int receipt_case_dump_session_shape(struct json_value *v,
                                            struct vcs_swarm_receipt_session
                                                *local,
                                            const char *expect_prefix)
{
    int failures = 0;
    bool ok = boot_zcode_swarm_receipt_dump_session_json(v, local);
    const struct json_value *peers = json_get(v, "peers");
    const struct json_value *row0 = peers ? json_at(peers, 0) : NULL;
    failures += receipt_case_dump_session_shape_prefix(ok, v, expect_prefix,
                                                        peers, row0);
    failures += receipt_case_dump_session_shape_peer_row(row0);
    return failures;
}

static int receipt_case_dump_session_snapshot(
    struct vcs_swarm_receipt_session *local, const char *expect_prefix)
{
    int failures = 0;
    struct json_value v;
    json_init(&v);
    failures += receipt_case_dump_session_shape(&v, local, expect_prefix);
    char rendered[2048];
    size_t rendered_len = json_write(&v, rendered, sizeof(rendered));
    ZS_CHECK("receipt dump: live snapshot leaks no secrets or paths",
             rendered_len < sizeof(rendered) &&
             strstr(rendered, "datadir") == NULL &&
             strstr(rendered, "wallet") == NULL &&
             strstr(rendered, "secret") == NULL &&
             strstr(rendered, "/home/") == NULL &&
             strstr(rendered, expect_prefix) != NULL);
    json_free(&v);
    return failures;
}

static int receipt_case_dump_boot_singleton_closed(void)
{
    int failures = 0;
    struct json_value v;
    json_init(&v);
    ZS_CHECK("receipt dump: boot singleton stays closed",
             boot_zcode_swarm_receipt_dump_state_json(&v, NULL) &&
             !json_get_bool(json_get(&v, "enabled")) &&
             !json_get_bool(json_get(&v, "present")));
    json_free(&v);
    return failures;
}

static int t_swarm_receipt_dump_state(void)
{
    int failures = 0;

    failures += receipt_case_dump_closed();
    failures += receipt_case_dump_rpc_integration();

    uint8_t sec_a[32];
    uint8_t sec_b[32];
    memset(sec_a, 0, sizeof(sec_a));
    memset(sec_b, 0, sizeof(sec_b));
    sec_a[31] = 0x91;
    sec_b[31] = 0x92;
    struct vcs_swarm_receipt_session *local =
        vcs_swarm_receipt_session_open_secret(sec_a);
    struct vcs_swarm_receipt_session *remote =
        vcs_swarm_receipt_session_open_secret(sec_b);
    ZS_CHECK("receipt dump: secret-backed sessions open",
             local != NULL && remote != NULL);
    if (!local || !remote) {
        vcs_swarm_receipt_session_free(local);
        vcs_swarm_receipt_session_free(remote);
        return failures;
    }

    char expect_prefix[9];
    failures += receipt_case_dump_session_setup(local, remote,
                                                 expect_prefix);
    failures += receipt_case_dump_session_snapshot(local, expect_prefix);
    failures += receipt_case_dump_boot_singleton_closed();

    vcs_swarm_receipt_session_free(local);
    vcs_swarm_receipt_session_free(remote);
    return failures;
}


int test_zcode_store(void)
{
    printf("\n=== zcode_store: local content-addressed package store ===\n");
    int failures = 0;
    failures += t_store_layout_and_flags();
    failures += t_store_manifest_admission();
    failures += t_store_chunk_flow();
    failures += t_store_dedup();
    failures += t_store_recovery();
    failures += t_store_corrupt_read_repair();
    failures += t_store_staging_quota();
    failures += t_store_hot_eviction();
    failures += t_store_rare_eviction();
    failures += t_store_pins();
    failures += t_store_possession_scheduler();
    failures += t_store_releases();
    failures += t_store_blob();
    failures += t_store_work_output();
    failures += t_store_exact_cache_restore();
    failures += t_store_serialized_recovery();
    failures += t_store_dump_state();
    failures += t_swarm_engine_dump_state();
    failures += t_swarm_receipt_dump_state();
    printf("=== zcode_store complete: %d failure(s) ===\n", failures);
    return failures;
}
