/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * test_zcode_site — the ZCODE Library onion/HTTPS site gate (slice 13:
 * contexts/commons/controllers/src/zcode_site_controller.c +
 * contexts/explorer/views/src/zcode_view{,_pages}.c).
 *
 * Coverage:
 *   1. Route coverage: every route in the slice contract (/zcode,
 *      /zcode/packages, /zcode/package/<root>, /zcode/publisher/<key>,
 *      /zcode/leaderboard + the four periods, /zcode/badges,
 *      /zcode/download/<root>[/f/c]) renders a complete HTTP response
 *      from one fixture store.
 *   2. PROJECTION AGREEMENT (the adversarial one): the same fixture state
 *      is read by the typed commands (zcode.package.search/show,
 *      zcode.contributor.show, zcode.leaderboard.all) and by the site —
 *      the name, semver, package root, byte count, earned score, and
 *      rank facts rendered into the HTML match the command projections
 *      exactly. No website database, no second package truth.
 *   3. HTML escaping: a reflected hostile search query and a hostile
 *      view-level package/publisher name render escaped (&lt;...&gt;),
 *      never as raw markup.
 *   4. Bounded output: a 20-package store renders the capped 16-row
 *      search page with the truncation note, inside the onion response
 *      budget.
 *   5. Download safety: the manifest route serves the exact persisted
 *      wire bytes and a chunk route serves the exact chunk bytes, both
 *      with Content-Disposition: attachment + X-Content-Type-Options:
 *      nosniff; a corrupted CAS object is a named integrity failure,
 *      never served bytes.
 *   6. Honest 404s: unknown package root, unknown publisher, unknown
 *      route, malformed hex, and an unknown period all render named 404
 *      pages.
 *   7. Swarm advertisers: a peer ANNOUNCE delivered to a node-global
 *      engine shows up as the package page's advertiser count.
 *
 * Fixtures run in-process on ./test-tmp datadirs (the
 * test_zcode_contributor/test_zcode_rank/test_zcode_badge patterns). */

#include "test/test_core.h"

#include "command/native_command.h"

#include "controllers/zcode_site_controller.h"
#include "views/zcode_view.h"

#include "chain/chainparams.h"
#include "json/json.h"
#include "keys/key.h"
#include "keys/key_io.h"
#include "keys/pubkey.h"
#include "vcs/package_badge.h"
#include "vcs/package_index.h"
#include "vcs/package_manifest.h"
#include "vcs/package_publish.h"
#include "vcs/package_recipe.h"
#include "vcs/package_release.h"
#include "vcs/package_reward.h"
#include "vcs/package_store.h"
#include "vcs/package_swarm.h"
#include "vcs/package_swarm_node.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ZS_CHECK(name, expr) do {                                     \
    if (expr) { printf("  zcode_site: %s... OK\n", (name)); }         \
    else { printf("  zcode_site: %s... FAIL\n", (name)); failures++; } \
} while (0)

/* ── fixtures (the test_zcode_contributor pattern) ────────────────── */

static bool zs_keypair(uint8_t seed, struct privkey *sk, struct pubkey *pk)
{
    memset(sk->vch, seed, 32);
    sk->fValid = true;
    sk->fCompressed = true;
    return privkey_get_pubkey(sk, pk) &&
           pk->size == COMPRESSED_PUBLIC_KEY_SIZE;
}

static char g_zs_recipe_hex[2 * 1024 + 1];
static uint8_t g_zs_recipe_root[32];
static bool g_zs_recipe_ready;

static bool zs_use_recipe(void)
{
    struct vcs_package_recipe r;
    vcs_package_recipe_init(&r);
    bool ok = vcs_package_recipe_add_source(&r, "src/x.c", NULL) &&
              vcs_package_recipe_add_define(&r, "ZCL_FIXTURE=1", NULL) &&
              vcs_package_recipe_add_library(&r, VCS_PACKAGE_RECIPE_LIB_LIBC,
                                             NULL);
    vcs_package_recipe_set_test_limits(&r, 0, 60,
                                       UINT64_C(64) * 1024u * 1024u);
    uint8_t *wire = NULL;
    size_t wire_len = 0;
    if (ok)
        ok = vcs_package_recipe_root(&r, g_zs_recipe_root) ==
                 VCS_PACKAGE_RECIPE_OK &&
             vcs_package_recipe_serialize(&r, &wire, &wire_len) ==
                 VCS_PACKAGE_RECIPE_OK;
    vcs_package_recipe_free(&r);
    if (!ok || !wire || 2 * wire_len + 1 > sizeof(g_zs_recipe_hex)) {
        free(wire);
        return false;
    }
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < wire_len; i++) {
        g_zs_recipe_hex[2 * i]     = hexd[(wire[i] >> 4) & 0xf];
        g_zs_recipe_hex[2 * i + 1] = hexd[wire[i] & 0xf];
    }
    g_zs_recipe_hex[2 * wire_len] = '\0';
    free(wire);
    g_zs_recipe_ready = true;
    return true;
}

static bool zs_pubkey_hex(uint8_t seed, char out[67])
{
    static const char hexd[] = "0123456789abcdef";
    struct privkey sk;
    struct pubkey pk;
    if (!zs_keypair(seed, &sk, &pk))
        return false;
    for (size_t i = 0; i < pk.size; i++) {
        out[2 * i]     = hexd[(pk.vch[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[pk.vch[i] & 0xf];
    }
    out[2 * pk.size] = '\0';
    return true;
}

static bool zs_sign(struct vcs_package_release *r, struct privkey *sk)
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

static bool zs_t1_reward(char *out, size_t out_size)
{
    const struct chain_params *params = chain_params_get();
    if (!params)
        return false;
    size_t pubkey_len = 0;
    size_t script_len = 0;
    const unsigned char *pubkey_prefix =
        chain_params_base58_prefix(params, B58_PUBKEY_ADDRESS, &pubkey_len);
    const unsigned char *script_prefix =
        chain_params_base58_prefix(params, B58_SCRIPT_ADDRESS, &script_len);
    if (!pubkey_prefix || !script_prefix)
        return false;
    struct tx_destination dest;
    dest.type = DEST_KEY_ID;
    memset(dest.id.key.id.data, 0x33, 20);
    return encode_destination(&dest, pubkey_prefix, pubkey_len,
                              script_prefix, script_len, out, out_size);
}

static bool zs_release(struct vcs_package_release *r, uint8_t key_seed,
                       uint64_t sequence, const char *name,
                       const char *license, const uint8_t package_root[32])
{
    memset(r, 0, sizeof(*r));
    struct privkey sk;
    struct pubkey pk;
    if (!zs_keypair(key_seed, &sk, &pk))
        return false;
    r->schema_version = VCS_PACKAGE_RELEASE_VERSION;
    snprintf(r->name, sizeof(r->name), "%s", name);
    snprintf(r->semver, sizeof(r->semver), "1.0.0");
    memcpy(r->package_root, package_root, 32);
    r->has_parent = false;
    memcpy(r->publisher_pubkey, pk.vch, COMPRESSED_PUBLIC_KEY_SIZE);
    r->publisher_sequence = sequence;
    if (!zs_t1_reward(r->reward_address, sizeof(r->reward_address)))
        return false;
    snprintf(r->license, sizeof(r->license), "%s", license);
    memcpy(r->recipe_root, g_zs_recipe_root, 32);
    r->has_znam = false;
    if (!vcs_package_accept_chain_id(r->chain_id, sizeof(r->chain_id)))
        return false;
    return zs_sign(r, &sk);
}

static char *zs_hex(const uint8_t *data, size_t len)
{
    static const char hexd[] = "0123456789abcdef";
    char *out = malloc(2 * len + 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < len; i++) {
        out[2 * i]     = hexd[(data[i] >> 4) & 0xf];
        out[2 * i + 1] = hexd[data[i] & 0xf];
    }
    out[2 * len] = '\0';
    return out;
}

/* ── in-process command runner (the test_zcode_contributor pattern) ── */

struct zs_cmd {
    struct json_value input;
    struct zcl_command_request request;
    struct zcl_command_reply reply;
};

static void zs_cmd_init(struct zs_cmd *c)
{
    json_init(&c->input);
    json_set_object(&c->input);
    memset(&c->request, 0, sizeof(c->request));
    c->request.input = &c->input;
    zcl_command_reply_init(&c->reply, "zcl.zcode_site_test.v1");
}

static void zs_cmd_free(struct zs_cmd *c)
{
    zcl_command_reply_free(&c->reply);
    json_free(&c->input);
}

/* Commit one small package; root_hex_out (65) gets the package root.
 * Returns the license text via lic_out (its bytes are chunk (0,0)). */
static unsigned g_zs_week_seq = 0;

static bool zs_commit_one(const char *dd, uint8_t key_seed, uint64_t seq,
                          const char *name, const char *license,
                          int content_seed, char root_hex_out[65],
                          char lic_out[96])
{
    if (!g_zs_recipe_ready && !zs_use_recipe())
        return false;
    char pkgdir[512];
    snprintf(pkgdir, sizeof(pkgdir), "%s/src-%d-%d", dd, key_seed,
             content_seed);
    mkdir(pkgdir, 0700);

    struct vcs_package_manifest manifest;
    vcs_package_manifest_init(&manifest);
    snprintf(lic_out, 96, "%s\nsee the LICENSE file, variant %d\n",
             license, content_seed);
    char source[64];
    snprintf(source, sizeof(source), "int x_%d;\n", content_seed);
    char path[512];
    snprintf(path, sizeof(path), "%s/LICENSE", pkgdir);
    FILE *f = fopen(path, "wb");
    char srcdir[512];
    snprintf(srcdir, sizeof(srcdir), "%s/src", pkgdir);
    mkdir(srcdir, 0700);
    char srcpath[512];
    snprintf(srcpath, sizeof(srcpath), "%s/x.c", srcdir);
    FILE *g = fopen(srcpath, "wb");
    bool ok = f && g;
    uint8_t lic_hash[32];
    uint8_t src_hash[32];
    if (ok)
        ok = fwrite(lic_out, 1, strlen(lic_out), f) == strlen(lic_out);
    if (f)
        fclose(f);
    if (ok)
        ok = fwrite(source, 1, strlen(source), g) == strlen(source);
    if (g)
        fclose(g);
    if (ok)
        ok = vcs_package_chunk_hash((const uint8_t *)lic_out,
                                    strlen(lic_out), lic_hash) &&
             vcs_package_chunk_hash((const uint8_t *)source,
                                    strlen(source), src_hash) &&
             vcs_package_manifest_add(&manifest, "LICENSE",
                                      VCS_PACKAGE_MODE_FILE,
                                      strlen(lic_out), lic_hash, 1) &&
             vcs_package_manifest_add(&manifest, "src/x.c",
                                      VCS_PACKAGE_MODE_FILE,
                                      strlen(source), src_hash, 1);
    uint8_t *m_wire = NULL;
    size_t m_wire_len = 0;
    uint8_t root[32];
    if (ok)
        ok = vcs_package_manifest_serialize(&manifest, &m_wire,
                                            &m_wire_len) &&
             vcs_package_manifest_root(&manifest, root);
    vcs_package_manifest_free(&manifest);

    struct vcs_package_release r;
    if (ok)
        ok = zs_release(&r, key_seed, seq, name, license, root);
    char *r_hex = NULL;
    char *m_hex = NULL;
    uint8_t *r_wire = NULL;
    size_t r_wire_len = 0;
    if (ok)
        ok = vcs_package_release_serialize(&r, &r_wire, &r_wire_len) ==
             VCS_PACKAGE_RELEASE_OK;
    if (ok) {
        r_hex = zs_hex(r_wire, r_wire_len);
        m_hex = zs_hex(m_wire, m_wire_len);
        ok = r_hex && m_hex;
    }
    if (ok) {
        /* Each commit lands in its own ISO week (the slice-11
         * publish-frequency checkpoint is 1/week for a new key; this gate
         * commits several releases to exercise the site, never the gate). */
        struct zs_cmd c;
        zs_cmd_init(&c);
        (void)json_push_kv_str(&c.input, "datadir", dd);
        (void)json_push_kv_str(&c.input, "release_hex", r_hex);
        (void)json_push_kv_str(&c.input, "manifest_hex", m_hex);
        (void)json_push_kv_str(&c.input, "recipe_hex", g_zs_recipe_hex);
        (void)json_push_kv_str(&c.input, "dir", pkgdir);
        (void)json_push_kv_int(&c.input, "day",
                               20000 + 7 * (int64_t)g_zs_week_seq++);
        zcl_native_handle_zcode_package_publish_commit(&c.request,
                                                       &c.reply);
        ok = c.reply.status == ZCL_COMMAND_STATUS_PASSED;
        zs_cmd_free(&c);
    }
    if (ok && root_hex_out) {
        static const char hexd[] = "0123456789abcdef";
        for (int i = 0; i < 32; i++) {
            root_hex_out[2 * i]     = hexd[(root[i] >> 4) & 0xf];
            root_hex_out[2 * i + 1] = hexd[root[i] & 0xf];
        }
        root_hex_out[64] = '\0';
    }
    free(r_hex);
    free(m_hex);
    free(r_wire);
    free(m_wire);
    test_rm_rf_recursive(pkgdir);
    return ok;
}

/* ── reward-ledger + badge fixtures (the test_zcode_rank/badge pattern) */

static void zs_root_seed(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(seed + i);
    if (out[0] == 0)
        out[0] = 1;
}

static void zs_facts_seed(uint8_t seed, uint8_t out[32])
{
    for (size_t i = 0; i < 32; i++)
        out[i] = (uint8_t)(0xf0 - seed - i);
    if (out[0] == 0)
        out[0] = 0xaa;
}

static enum vcs_reward_commit_error zs_settle(struct vcs_reward_ledger *l,
                                              int64_t day)
{
    struct vcs_reward_plan plan;
    if (!vcs_reward_plan_build(l, day, &plan))
        return VCS_REWARD_COMMIT_IO;
    uint8_t plan_id[32];
    memcpy(plan_id, plan.plan_id, 32);
    enum vcs_reward_plan_persist_error perr =
        vcs_reward_plan_persist(l, &plan);
    vcs_reward_plan_free(&plan);
    if (perr != VCS_REWARD_PLAN_PERSIST_OK &&
        perr != VCS_REWARD_PLAN_PERSIST_DUPLICATE)
        return VCS_REWARD_COMMIT_IO;
    struct vcs_reward_commit_result result;
    char detail[256];
    return vcs_reward_commit(l, plan_id, &result, detail, sizeof(detail));
}

/* Settle one NEW_PACKAGE auto reward of `points` for the key of seed
 * `key_seed` into <dd>/zcode's reward ledger. */
static bool zs_seed_score(const char *dd, uint8_t key_seed, uint32_t points)
{
    char zcode_dir[512];
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);
    struct vcs_reward_ledger *l = vcs_reward_ledger_load(zcode_dir);
    if (!l)
        return false;
    struct privkey sk;
    struct pubkey pk;
    uint8_t root[32], facts[32], id[32];
    zs_root_seed(90, root);
    zs_facts_seed(91, facts);
    bool ok = zs_keypair(key_seed, &sk, &pk) &&
              vcs_reward_enqueue_auto(l, root, pk.vch,
                                      VCS_REWARD_CATEGORY_NEW_PACKAGE,
                                      points, facts, id) ==
                  VCS_REWARD_ENQUEUE_OK &&
              zs_settle(l, 20000) == VCS_REWARD_COMMIT_OK;
    vcs_reward_ledger_free(l);
    return ok;
}

/* Write <dd>/zcode/badge_policy and persist one FIRST_PACKAGE badge
 * (recipient = the key of `key_seed`). */
static bool zs_seed_badge(const char *dd, uint8_t key_seed)
{
    char zcode_dir[512];
    snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);
    struct privkey issuer_sk;
    struct pubkey issuer_pk;
    struct privkey recip_sk;
    struct pubkey recip_pk;
    if (!zs_keypair(77, &issuer_sk, &issuer_pk) ||
        !zs_keypair(key_seed, &recip_sk, &recip_pk))
        return false;

    char hex[67];
    char path[512];
    snprintf(path, sizeof(path), "%s/badge_policy", zcode_dir);
    uint8_t policy_id[32];
    zs_root_seed(78, policy_id);
    FILE *f = fopen(path, "wb");
    if (!f)
        return false;
    char *pid_hex = zs_hex(policy_id, 32);
    fprintf(f, "%s\n", pid_hex ? pid_hex : "");
    free(pid_hex);
    for (size_t i = 0; i < 33; i++)
        snprintf(hex + 2 * i, 3, "%02x", issuer_pk.vch[i]);
    fprintf(f, "%s\n", hex);
    if (fclose(f) != 0)
        return false;

    struct vcs_badge badge;
    memset(&badge, 0, sizeof(badge));
    badge.schema_version = VCS_PACKAGE_BADGE_VERSION;
    badge.type = (uint8_t)VCS_BADGE_FIRST_PACKAGE;
    memcpy(badge.recipient, recip_pk.vch, 33);
    badge.period_first_day = VCS_BADGE_PERIOD_NONE;
    badge.period_last_day = VCS_BADGE_PERIOD_NONE;
    zs_root_seed(79, badge.evidence_root);
    memcpy(badge.policy_id, policy_id, 32);
    badge.sequence = 1;
    memcpy(badge.issuer_pubkey, issuer_pk.vch, 33);
    uint8_t id[VCS_PACKAGE_BADGE_ID_BYTES];
    if (vcs_badge_id(&badge, id) != VCS_BADGE_OK)
        return false;
    struct uint256 hash;
    memcpy(hash.data, id, 32);
    unsigned char compact[COMPACT_SIGNATURE_SIZE];
    if (!privkey_sign_compact(&issuer_sk, &hash, compact))
        return false;
    memcpy(badge.signature, compact + 1, VCS_PACKAGE_BADGE_SIGNATURE_BYTES);

    struct vcs_badge_store *s = vcs_badge_store_load(zcode_dir);
    if (!s)
        return false;
    uint8_t id_out[32];
    enum vcs_badge_persist_error perr =
        vcs_badge_store_persist(s, &badge, id_out);
    vcs_badge_store_free(s);
    return perr == VCS_BADGE_PERSIST_OK ||
           perr == VCS_BADGE_PERSIST_DUPLICATE;
}

/* ── request helper ────────────────────────────────────────────────── */

static uint8_t *g_resp = NULL;
#define ZS_RESP_CAP (160u * 1024u)

/* Issue one GET against the fixture datadir; NUL-terminates the response
 * (responses here are always short of the cap in these fixtures). */
static const char *zs_get(const char *dd, const char *path, size_t *len_out)
{
    size_t n = zcode_site_handle_request("GET", path, NULL, 0, g_resp,
                                         ZS_RESP_CAP - 1, dd);
    g_resp[n] = '\0';
    if (len_out)
        *len_out = n;
    return (const char *)g_resp;
}

/* ══ 1+2. route coverage + projection agreement ═══════════════════════ */

static int t_routes_and_agreement(const char *dd)
{
    int failures = 0;
    char root_hex[65], lic[96], pub_hex[67];
    bool seeded = zs_commit_one(dd, 11, 1, "alice/demo", "MIT", 1,
                                root_hex, lic) &&
                  zs_pubkey_hex(11, pub_hex) &&
                  zs_seed_score(dd, 11, 100) &&
                  zs_seed_badge(dd, 11);
    ZS_CHECK("fixture: package + score + badge seeded", seeded);
    if (!seeded)
        return failures + 1;
    size_t len = 0;

    /* Route coverage. */
    const char *r = zs_get(dd, "/zcode", &len);
    ZS_CHECK("route /zcode: 200 + landing",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "Build, verify, and share exact C23 software") &&
             strstr(r, "Browse exact packages") &&
             strstr(r, "1") /* counts */);

    r = zs_get(dd, "/zcode/packages", &len);
    ZS_CHECK("route /zcode/packages: 200 + row",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "alice/demo") && strstr(r, root_hex));

    char route[160];
    snprintf(route, sizeof(route), "/zcode/package/%s", root_hex);
    r = zs_get(dd, route, &len);
    ZS_CHECK("route /zcode/package/<root>: 200 + envelope + signature",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "What it does") &&
             strstr(r, "Try it") &&
             strstr(r, "Change it") &&
             strstr(r, "Tell your agent") &&
             !strstr(r, "Workshop") &&
             strstr(r, "What changed") &&
             strstr(r, "Verify") &&
             strstr(r, "Use and share") &&
             strstr(r, "No runnable example is published") &&
             strstr(r, "<details") &&
             strstr(r, "Signed release envelope") &&
             strstr(r, "publisher signature") &&
             strstr(r, "Verifier attestations") &&
             strstr(r, "LICENSE"));

    snprintf(route, sizeof(route), "/zcode/publisher/%s", pub_hex);
    r = zs_get(dd, route, &len);
    ZS_CHECK("route /zcode/publisher/<key>: 200 + score + badge",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "Contributor profile") &&
             strstr(r, "ZCODE Score") && strstr(r, "first-package"));

    r = zs_get(dd, "/zcode/leaderboard", &len);
    ZS_CHECK("route /zcode/leaderboard: 200 selector",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "Daily") && strstr(r, "All-time"));

    const char *periods[] = {"daily", "weekly", "monthly", "all"};
    bool period_ok = true;
    for (size_t i = 0; i < 4; i++) {
        snprintf(route, sizeof(route), "/zcode/leaderboard/%s",
                 periods[i]);
        r = zs_get(dd, route, &len);
        if (!(len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
              strstr(r, "ZCODE Rankings")))
            period_ok = false;
    }
    ZS_CHECK("route /zcode/leaderboard/<all four periods>: 200", period_ok);

    r = zs_get(dd, "/zcode/badges", &len);
    ZS_CHECK("route /zcode/badges: 200 + badge row",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "ZCODE Badges") && strstr(r, "first-package"));

    /* ── projection agreement: commands vs pages over the same store ── */

    /* zcode.package.search ↔ /zcode/packages. */
    struct zs_cmd c;
    zs_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "keyword", "demo");
    zcl_native_handle_zcode_package_search(&c.request, &c.reply);
    const struct json_value *rows = json_get(&c.reply.data, "results");
    const struct json_value *row0 = rows ? json_at(rows, 0) : NULL;
    const char *cmd_name =
        row0 ? json_get_str(json_get(row0, "name")) : NULL;
    const char *cmd_semver =
        row0 ? json_get_str(json_get(row0, "semver")) : NULL;
    const char *cmd_root =
        row0 ? json_get_str(json_get(row0, "package_root")) : NULL;
    r = zs_get(dd, "/zcode/packages?q=demo", &len);
    ZS_CHECK("agreement: search row == packages page",
             cmd_name && cmd_semver && cmd_root &&
             strstr(r, cmd_name) && strstr(r, cmd_semver) &&
             strstr(r, cmd_root) &&
             json_get_int(json_get(&c.reply.data, "total_matches")) == 1);
    zs_cmd_free(&c);

    /* zcode.package.show ↔ /zcode/package/<root> (byte/file counts). */
    zs_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "root", root_hex);
    zcl_native_handle_zcode_package_show(&c.request, &c.reply);
    int64_t cmd_bytes = json_get_int(json_get(&c.reply.data, "bytes"));
    int64_t cmd_files = json_get_int(json_get(&c.reply.data, "files"));
    char bytes_str[24];
    snprintf(bytes_str, sizeof(bytes_str), "%llu",
             (unsigned long long)cmd_bytes);
    snprintf(route, sizeof(route), "/zcode/package/%s", root_hex);
    r = zs_get(dd, route, &len);
    ZS_CHECK("agreement: show counts == package page",
             cmd_bytes > 0 && cmd_files == 2 && strstr(r, bytes_str) &&
             strstr(r, "LICENSE") && strstr(r, "src/x.c"));
    zs_cmd_free(&c);

    /* zcode.contributor.show ↔ /zcode/publisher/<key> (earned score). */
    zs_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    (void)json_push_kv_str(&c.input, "pubkey", pub_hex);
    zcl_native_handle_zcode_contributor_show(&c.request, &c.reply);
    const struct json_value *rewards = json_get(&c.reply.data, "rewards");
    int64_t cmd_score =
        rewards ? json_get_int(json_get(rewards, "earned_score")) : -1;
    const struct json_value *ranks = json_get(&c.reply.data, "rankings");
    const struct json_value *rank_periods =
        ranks ? json_get(ranks, "periods") : NULL;
    const struct json_value *overall =
        rank_periods ? json_get(rank_periods, "all-time") : NULL;
    int64_t cmd_rank =
        overall ? json_get_int(json_get(overall, "rank")) : -1;
    snprintf(route, sizeof(route), "/zcode/publisher/%s", pub_hex);
    r = zs_get(dd, route, &len);
    char score_str[24], rank_str[24];
    snprintf(score_str, sizeof(score_str), ">%llu<",
             (unsigned long long)cmd_score);
    snprintf(rank_str, sizeof(rank_str), "#%llu",
             (unsigned long long)cmd_rank);
    ZS_CHECK("agreement: contributor score + rank == publisher page",
             cmd_score == 100 && cmd_rank == 1 && strstr(r, score_str) &&
             strstr(r, rank_str));
    zs_cmd_free(&c);

    /* zcode.leaderboard.all ↔ /zcode/leaderboard/all. */
    zs_cmd_init(&c);
    (void)json_push_kv_str(&c.input, "datadir", dd);
    zcl_native_handle_zcode_leaderboard_all(&c.request, &c.reply);
    const struct json_value *lb_rows = json_get(&c.reply.data, "rows");
    const struct json_value *lb0 = lb_rows ? json_at(lb_rows, 0) : NULL;
    int64_t cmd_points =
        lb0 ? json_get_int(json_get(lb0, "points")) : -1;
    r = zs_get(dd, "/zcode/leaderboard/all", &len);
    ZS_CHECK("agreement: leaderboard.all row == rankings page",
             cmd_points == 100 && strstr(r, pub_hex) /* publisher link */ &&
             strstr(r, ">#1<") && strstr(r, score_str));
    zs_cmd_free(&c);

    return failures;
}

/* ══ 3. downloads: exact bytes + attachment semantics ════════════════ */

static int t_downloads(const char *dd, const char *root_hex,
                       const char *lic)
{
    int failures = 0;
    size_t len = 0;
    char route[192];

    /* Manifest: exact persisted wire bytes, attachment semantics. */
    snprintf(route, sizeof(route), "/zcode/download/%s", root_hex);
    const char *r = zs_get(dd, route, &len);
    bool hdr_ok = len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
                  strstr(r, "Content-Type: engine/application/octet-stream") &&
                  strstr(r, "Content-Disposition: attachment; filename="
                            "\"zcode-manifest-") &&
                  strstr(r, "X-Content-Type-Options: nosniff");
    ZS_CHECK("download manifest: 200 + attachment + nosniff", hdr_ok);

    char mpath[512];
    snprintf(mpath, sizeof(mpath), "%s/zcode/manifests/%s", dd, root_hex);
    FILE *f = fopen(mpath, "rb");
    uint8_t *disk = malloc(VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES);
    size_t disk_len = (f && disk)
        ? fread(disk, 1, VCS_PACKAGE_MANIFEST_MAX_WIRE_BYTES, f) : 0;
    if (f)
        fclose(f);
    const char *body = strstr(r, "\r\n\r\n");
    ZS_CHECK("download manifest: exact CAS bytes",
             body && disk_len > 0 &&
             (size_t)(r + len - (body + 4)) == disk_len &&
             memcmp(body + 4, disk, disk_len) == 0);
    free(disk);

    /* Chunk (0,0) = the LICENSE bytes (canonical path order: LICENSE is
     * file index 0). */
    snprintf(route, sizeof(route), "/zcode/download/%s/0/0", root_hex);
    r = zs_get(dd, route, &len);
    body = strstr(r, "\r\n\r\n");
    ZS_CHECK("download chunk 0/0: exact chunk bytes + attachment",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "Content-Disposition: attachment") && body &&
             (size_t)(r + len - (body + 4)) == strlen(lic) &&
             memcmp(body + 4, lic, strlen(lic)) == 0);

    /* Chunk (1,0) = src/x.c. */
    snprintf(route, sizeof(route), "/zcode/download/%s/1/0", root_hex);
    r = zs_get(dd, route, &len);
    ZS_CHECK("download chunk 1/0: 200",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "int x_1;"));

    /* Out-of-range chunk: honest 404, nothing invented. */
    snprintf(route, sizeof(route), "/zcode/download/%s/0/9", root_hex);
    r = zs_get(dd, route, &len);
    ZS_CHECK("download chunk 0/9: 404",
             len > 0 && strstr(r, "HTTP/1.1 404") == r);

    /* Corrupt the CAS object: a named integrity failure, never bytes. */
    char cpath[512];
    uint8_t hash[32];
    (void)vcs_package_chunk_hash((const uint8_t *)lic, strlen(lic), hash);
    char hh[65];
    for (size_t i = 0; i < 32; i++)
        snprintf(hh + 2 * i, 3, "%02x", hash[i]);
    snprintf(cpath, sizeof(cpath), "%s/zcode/cas/sha3/%02x/%s", dd,
             hash[0], hh);
    f = fopen(cpath, "r+b");
    int corrupt_ok = 0;
    if (f) {
        int ch = fgetc(f);
        rewind(f);
        fputc(ch ^ 0xff, f);
        corrupt_ok = fclose(f) == 0;
    }
    snprintf(route, sizeof(route), "/zcode/download/%s/0/0", root_hex);
    r = zs_get(dd, route, &len);
    ZS_CHECK("download corrupted chunk: 500 integrity, no bytes",
             corrupt_ok && len > 0 &&
             strstr(r, "HTTP/1.1 500") == r &&
             strstr(r, "integrity"));

    return failures;
}

/* ══ 4. HTML escaping ════════════════════════════════════════════════ */

static int t_escaping(const char *dd)
{
    int failures = 0;
    size_t len = 0;

    /* Reflected hostile search query: escaped, never raw markup. */
    const char *r = zs_get(dd, "/zcode/packages?q=%3Cscript%3Ealert(1)%3C/script%3E", &len);
    ZS_CHECK("escaping: reflected query is HTML-escaped",
             len > 0 && strstr(r, "HTTP/1.1 200 OK") == r &&
             !strstr(r, "<script>alert") &&
             strstr(r, "&lt;script&gt;"));

    /* Hostile view-level rows (a pre-validation store row could carry
     * hostile bytes — the views escape regardless of grammar). */
    struct vcs_package_index_entry hostile;
    memset(&hostile, 0, sizeof(hostile));
    snprintf(hostile.release_id_hex, sizeof(hostile.release_id_hex),
             "%064x", 1);
    snprintf(hostile.package_root_hex, sizeof(hostile.package_root_hex),
             "%064x", 2);
    snprintf(hostile.name, sizeof(hostile.name), "a/<script>alert(1)</script>");
    snprintf(hostile.semver, sizeof(hostile.semver), "1.0.0");
    snprintf(hostile.license, sizeof(hostile.license), "MIT");
    snprintf(hostile.publisher_hex, sizeof(hostile.publisher_hex),
             "%066x", 3);
    snprintf(hostile.chain_id, sizeof(hostile.chain_id), "zclassic");
    hostile.has_znam = true;
    snprintf(hostile.znam, sizeof(hostile.znam), "\"><img src=x>");
    const struct vcs_package_index_entry *hrows[1] = {&hostile};
    size_t n = zcode_view_packages(hrows, 1, 1, 1, NULL, g_resp,
                                   ZS_RESP_CAP - 1);
    g_resp[n] = '\0';
    r = (const char *)g_resp;
    ZS_CHECK("escaping: hostile package name + znam pointer escaped",
             n > 0 && !strstr(r, "<script>alert") &&
             !strstr(r, "\"><img") && strstr(r, "&lt;script&gt;"));

    /* The 404 page escapes an attacker-controlled route path. */
    r = zs_get(dd, "/zcode/nope-<script>", &len);
    ZS_CHECK("escaping: unknown-route 404 escapes the path",
             len > 0 && strstr(r, "HTTP/1.1 404") == r &&
             !strstr(r, "nope-<script>") &&
             strstr(r, "nope-&lt;script&gt;"));
    return failures;
}

/* ══ 5. bounded output on a large store ══════════════════════════════ */

static int t_bounded(const char *dd)
{
    int failures = 0;
    int committed = 0;
    for (int i = 0; i < 20; i++) {
        char root_hex[65], lic[96], name[64];
        snprintf(name, sizeof(name), "pub%02d/pkg%02d", i, i);
        if (zs_commit_one(dd, (uint8_t)(30 + i), 1, name, "Apache-2.0",
                          100 + i, root_hex, lic))
            committed++;
    }
    ZS_CHECK("bounded: 20 packages committed", committed == 20);

    size_t len = 0;
    const char *r = zs_get(dd, "/zcode/packages", &len);
    ZS_CHECK("bounded: page capped at 16 rows + truncation note",
             len > 0 && len < 65536 /* the onion budget */ &&
             strstr(r, "HTTP/1.1 200 OK") == r &&
             strstr(r, "not shown (page cap"));
    return failures;
}

/* ══ 6. honest 404s ══════════════════════════════════════════════════ */

static int t_not_found(const char *dd)
{
    int failures = 0;
    size_t len = 0;
    char zeros[65];
    memset(zeros, '0', 64);
    zeros[64] = '\0';
    char route[192];

    snprintf(route, sizeof(route), "/zcode/package/%s", zeros);
    const char *r = zs_get(dd, route, &len);
    ZS_CHECK("404: unknown package root named honestly",
             len > 0 && strstr(r, "HTTP/1.1 404") == r &&
             strstr(r, "Package not found"));

    r = zs_get(dd, "/zcode/package/nothex", &len);
    ZS_CHECK("404: malformed package root",
             len > 0 && strstr(r, "HTTP/1.1 404") == r &&
             strstr(r, "Package not found"));

    char pub_zeros[67];
    memset(pub_zeros, '0', 66);
    pub_zeros[66] = '\0';
    snprintf(route, sizeof(route), "/zcode/publisher/%s", pub_zeros);
    r = zs_get(dd, route, &len);
    ZS_CHECK("404: unknown publisher named honestly",
             len > 0 && strstr(r, "HTTP/1.1 404") == r &&
             strstr(r, "Publisher not found"));

    r = zs_get(dd, "/zcode/leaderboard/hourly", &len);
    ZS_CHECK("404: unknown leaderboard period",
             len > 0 && strstr(r, "HTTP/1.1 404") == r &&
             strstr(r, "Unknown ZCODE route"));

    snprintf(route, sizeof(route), "/zcode/download/%s", zeros);
    r = zs_get(dd, route, &len);
    ZS_CHECK("404: unknown download root",
             len > 0 && strstr(r, "HTTP/1.1 404") == r);

    r = zs_get(dd, "/zcode/definitely-not-a-route", &len);
    ZS_CHECK("404: unknown /zcode route",
             len > 0 && strstr(r, "HTTP/1.1 404") == r &&
             strstr(r, "Unknown ZCODE route"));
    return failures;
}

/* ══ 7. swarm advertisers on the package page ════════════════════════ */

/* A pseudo-key peer resolves to zero earned score, whose frozen tier
 * allowance is 0 announces/hour — the ANNOUNCE is rate-limited by design
 * (test_zcode_swarm.c header point 5). Earn the contributor tier so one
 * announce is allowed. */
static uint64_t zs_swarm_score(const uint8_t contributor[33], void *ctx)
{
    (void)contributor;
    (void)ctx;
    return 1000; /* >= VCS_POLICY_TIER_CONTRIBUTOR_MIN_SCORE */
}

static int t_swarm(const char *dd, const char *root_hex)
{
    int failures = 0;

    /* The advertiser count lives on the DOWNLOAD entry: an ANNOUNCE alone
     * records the peer ad, but download_status only reports it once a
     * fetch for the root is active (vcs_swarm_engine_download_status).
     * Fetch needs a store — a scratch one (the package is intentionally
     * NOT in it, so the download stays active). */
    char sw_dir[512];
    snprintf(sw_dir, sizeof(sw_dir), "%s/swarm_scratch", dd);
    mkdir(sw_dir, 0755);
    struct vcs_package_store *store =
        vcs_package_store_open(sw_dir, UINT64_C(1073741824));
    struct vcs_swarm_engine *engine =
        vcs_swarm_engine_create(store, NULL, NULL, zs_swarm_score, NULL);
    ZS_CHECK("swarm: engine created", store != NULL && engine != NULL);
    if (!store || !engine) {
        if (engine)
            vcs_swarm_engine_free(engine);
        if (store)
            vcs_package_store_close(store);
        return failures + 1;
    }

    uint8_t root[32];
    for (size_t i = 0; i < 32; i++) {
        unsigned v = 0;
        (void)sscanf(root_hex + 2 * i, "%02x", &v);
        root[i] = (uint8_t)v;
    }
    uint8_t peer_key[33];
    peer_key[0] = 0x02;
    memset(peer_key + 1, 0x55, 32);
    bool ok = vcs_swarm_engine_peer_add(engine, 1, peer_key);

    struct vcs_package_swarm_message msg;
    memset(&msg, 0, sizeof(msg));
    msg.type = VCS_PACKAGE_SWARM_ANNOUNCE;
    memcpy(msg.body.announce.package_root, root, 32);
    msg.body.announce.manifest_bytes = 256;
    msg.body.announce.file_count = 2;
    msg.body.announce.total_bytes = 200;
    msg.body.announce.total_chunks = 2;
    uint8_t frame[VCS_PACKAGE_SWARM_HEADER_BYTES + 88u];
    size_t frame_len = 0;
    bool ser = vcs_package_swarm_serialize(&msg, frame, sizeof(frame),
                                           &frame_len);
    ok = ok && ser;
    if (ok) {
        struct vcs_swarm_frame_result fr = vcs_swarm_engine_handle_frame(
            engine, 1, frame, frame_len, 20000, 1);
        free(fr.reply);
        ok = fr.penalty == VCS_SWARM_PENALTY_NONE;
    }
    enum vcs_swarm_fetch_result fetch_r =
        vcs_swarm_engine_fetch(engine, root, 20000, 1);
    struct vcs_swarm_download_status st;
    bool status_ok = vcs_swarm_engine_download_status(engine, root, &st);
    ok = ok && fetch_r == VCS_SWARM_FETCH_OK && status_ok &&
         st.advertisers == 1;
    ZS_CHECK("swarm: one peer ANNOUNCE counts one advertiser", ok);

    vcs_swarm_engine_set_global(engine);
    char route[160];
    snprintf(route, sizeof(route), "/zcode/package/%s", root_hex);
    size_t len = 0;
    const char *r = zs_get(dd, route, &len);
    ZS_CHECK("swarm: package page shows the advertiser count",
             len > 0 &&
             strstr(r, "peers advertising this package</b>"
                       "<span class='val'>1</span>"));
    vcs_swarm_engine_set_global(NULL);
    vcs_swarm_engine_free(engine);
    vcs_package_store_close(store);
    return failures;
}

/* ══ group entry ═════════════════════════════════════════════════════ */

int test_zcode_site(void)
{
    int failures = 0;
    printf("zcode_site: starting\n");

    g_resp = malloc(ZS_RESP_CAP);
    if (!g_resp) {
        printf("  zcode_site: alloc... FAIL\n");
        return 1;
    }

    const char *dd = "./test-tmp/zcode_site_main";
    test_rm_rf_recursive(dd);
    mkdir("./test-tmp", 0755);
    mkdir(dd, 0755);

    char root_hex[65] = "", lic[96] = "";
    failures += t_routes_and_agreement(dd);
    /* Re-derive the fixture root/license for the download + swarm tests
     * (the agreement test committed exactly one package: alice/demo). */
    {
        char zcode_dir[512];
        snprintf(zcode_dir, sizeof(zcode_dir), "%s/zcode", dd);
        struct vcs_package_index *index =
            vcs_package_index_build(zcode_dir);
        if (index && vcs_package_index_count(index) == 1) {
            const struct vcs_package_index_entry *e =
                vcs_package_index_at(index, 0);
            snprintf(root_hex, sizeof(root_hex), "%s",
                     e->package_root_hex);
        }
        if (index)
            vcs_package_index_free(index);
        snprintf(lic, sizeof(lic),
                 "MIT\nsee the LICENSE file, variant 1\n");
    }
    if (root_hex[0]) {
        failures += t_downloads(dd, root_hex, lic);
        failures += t_swarm(dd, root_hex);
    } else {
        printf("  zcode_site: fixture root missing... FAIL\n");
        failures++;
    }
    failures += t_escaping(dd);
    failures += t_not_found(dd);

    const char *dd2 = "./test-tmp/zcode_site_bounded";
    test_rm_rf_recursive(dd2);
    mkdir(dd2, 0755);
    failures += t_bounded(dd2);
    test_rm_rf_recursive(dd2);

    test_rm_rf_recursive(dd);
    free(g_resp);
    g_resp = NULL;
    printf("zcode_site: %s (%d failures)\n",
           failures == 0 ? "PASSED" : "FAILED", failures);
    return failures;
}
