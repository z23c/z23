/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * A leaf declared READ must not WRITE the datadir it is pointed at.
 *
 * Booting through node_db_open() (quick_check with rename-aside,
 * create_schema, node_db_migrate, DELETEs of snapshot staging rows) on the
 * default datadir would modify an operator's live database. Each leaf is
 * invoked against a FIXTURE datadir (always an explicit `datadir` input)
 * and only what it leaves on disk is checked, in these states:
 *
 *   absent    - empty datadir: no "node.db*" file may appear.
 *   present   - migrated node.db with seeded snapshot_staging rows: same
 *               size, FNV-1a hash and staging counts; no node.db.corrupt-*.
 *   foreign   - a real SQLite database that is not a node database: it
 *               must keep the same tables (catches create_schema).
 *   garbage   - a node.db that is not SQLite: still present, identical.
 *   walset    - both stores in WAL mode: the directory FILE SET is
 *               unchanged (read-only WAL opens create -shm/-wal sidecars).
 *   walopen   - the same with a live writer attached; the read must not be
 *               "assume immutable" (it would return pre-log data) and the
 *               writer must still commit.
 *
 * The absent/present/garbage states are also asserted for the kernel
 * store, <datadir>/consensus.db (progress_store_open opens it
 * READWRITE|CREATE and quarantines a failed one).
 *
 * The reply is not asserted on: a read leaf may refuse or answer with
 * data; it may not change the directory.
 *
 * The population is derived: case 8 walks zcl_command_catalog() and
 * requires every READY, non-branch, READ-effect leaf with a `datadir`
 * input to be exercised here or named in g_rlw_uncovered with a reason.
 * The uncovered list is shrink-only and the derived population is
 * floor-gated so an unlinked catalog cannot pass vacuously.
 *
 * Sibling: test_offline_datadir_query.c covers the SCOPE_OFFLINE_COPY
 * leaves' answers; this file covers every read leaf's side effects. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include "command/native_command.h"
#include "command/native_fleet.h"
#include "config/command_catalog.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include "models/database.h"
#include "storage/consensus_db.h"

#include <dirent.h>
#include <sqlite3.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define RLW_CHECK(name, expr) do {                                     \
    printf("read_leaf_no_datadir_write: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                                      \
    else { printf("FAIL\n"); failures++; }                             \
} while (0)

/* ── the leaves under test ─────────────────────────────────────────────
 *
 * Each is a READ leaf taking a caller-supplied `datadir`; k1/k2 are the
 * other inputs the handler needs to reach the datadir. This table is not
 * the population: t_registry_coverage derives that from the compiled
 * registry, and every derived leaf must be here or in g_rlw_uncovered. */

typedef void (*rlw_handler_fn)(const struct zcl_command_request *,
                               struct zcl_command_reply *);

struct rlw_leaf {
    const char *path;
    rlw_handler_fn fn;
    const char *k1, *v1;
    const char *k2, *v2;
    /* Where the payload lives under the datadir when it is not node.db or
     * consensus.db; NULL for the sqlite leaves. Case 5 makes this
     * directory unreadable (a plain file where it belongs) to check the
     * leaf discloses that it could not read. */
    const char *payload_dir;
};

/* A syntactically valid compressed secp256k1 key. */
#define RLW_PUBKEY \
    "02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737"

/* core.identity.resolve wants a bare 32-byte key (64 hex, not all-zero). */
#define RLW_ZID_PUBKEY \
    "b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737"

/* metaverse.property.show wants "<kind>:<64 lowercase hex>"; well-formed
 * and non-zero is enough. */
#define RLW_PROPERTY_ID "content:" RLW_ZID_PUBKEY
#define RLW_DATADIR_VALUE "@fixture-datadir@"

static const struct rlw_leaf g_rlw_leaves[] = {
    { "core.zdir.list",         zcl_native_handle_core_zdir_list,
      NULL, NULL,               NULL, NULL, NULL },
    { "app.service.access",     zcl_native_handle_service_access,
      "service", "reference",   NULL, NULL, NULL },
    { "zcode.release.prove",    zcl_native_handle_zcode_release_prove,
      "name", "demo",           "version", "0.1.0", NULL },
    { "zcode.domain.list",      zcl_native_handle_zcode_domain_list,
      NULL, NULL,               NULL, NULL, NULL },
    { "zcode.domain.status",    zcl_native_handle_zcode_domain_status,
      "domain", "zcode",        NULL, NULL, NULL },
    { "zcode.contributor.show", zcl_native_handle_zcode_contributor_show,
      "pubkey", RLW_PUBKEY,     NULL, NULL, NULL },
    { "zcode.package.resolve",  zcl_native_handle_zcode_package_resolve,
      "name", "ringbuffer",     NULL, NULL, NULL },
    { "zcode.package.dev.lane", zcl_native_handle_zcode_lane,
      "workspace", ".",         "source_root", RLW_ZID_PUBKEY, NULL },
    { "zcode.package.dev.publish.plan",
      zcl_native_handle_zcode_publish_plan,
      "workspace", ".",         "source_root", RLW_ZID_PUBKEY, NULL },
    { "zcode.work.status", zcl_native_handle_zcode_work_status,
      "workspace", RLW_DATADIR_VALUE, "work", RLW_ZID_PUBKEY, NULL },
    { "zcode.work.preflight", zcl_native_handle_zcode_work_preflight,
      "workspace", RLW_DATADIR_VALUE, "work", RLW_ZID_PUBKEY, NULL },
    /* The same handler under its discoverable name; the coverage check
     * keys on the leaf path, so the alias is listed separately. */
    { "zcode.work.show", zcl_native_handle_zcode_work_status,
      "workspace", RLW_DATADIR_VALUE, "work", RLW_ZID_PUBKEY, NULL },
    /* Pull receipt read from <datadir>/zcode by root; the fixture holds
     * none, so the answer is WORK_RECEIPT_NOT_FOUND and nothing moves. */
    { "zcode.work.receipt", zcl_native_handle_zcode_work_receipt,
      "receipt_root", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    { "story.focus", zcl_native_handle_story_focus,
      "work", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    { "story.show", zcl_native_handle_story_show,
      "work", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    { "story.why", zcl_native_handle_story_why,
      "work", RLW_ZID_PUBKEY, "event", "user_accepts", NULL },
    { "story.diff", zcl_native_handle_story_diff,
      "before", RLW_ZID_PUBKEY, "after", RLW_ZID_PUBKEY, NULL },
    /* Task-carrier board: `datadir` input only; the seen-set projection
     * answers from the local record store without writing. */
    { "zcode.task.board", zcl_native_handle_zcode_task_board,
      NULL, NULL,               NULL, NULL, NULL },
    /* Reads through zcl_native_node_db_open_readonly(); a damaged database
     * must not be renamed aside. */
    { "core.wallet.recovery.status",
      zcl_native_handle_wallet_recovery_status,
      NULL, NULL,               NULL, NULL, NULL },
    /* Fleet roster reads pairing and observation projections through
     * zcl_native_node_db_require_readonly(), so a copied datadir hashes
     * the same afterwards. */
    { "ops.mesh.roster",        zcl_native_handle_fleet_roster,
      NULL, NULL,               NULL, NULL, NULL },
    /* fleet.doctor composes fleet.nodes.table (the guarded read-only open)
     * and node RPC reads; it never writes the datadir it is pointed at. */
    { "fleet.doctor",           zcl_native_handle_fleet_doctor,
      NULL, NULL,               NULL, NULL, NULL },
/* z23-toolgen:begin datadir-leaves - generated, do not edit */
    { "fleet.nodes.table",      zcl_native_handle_fleet_nodes_table,
      NULL, NULL,               NULL, NULL, NULL },
    { "fleet.vitals.history",   zcl_native_handle_fleet_vitals_history,
      NULL, NULL,               NULL, NULL, NULL },
/* z23-toolgen:end datadir-leaves */
    /* app.store.products opens through
     * zcl_native_node_db_require_readonly(); core.sync.frontier.offline
     * opens consensus.db through zcl_native_kernel_store_open_readonly(),
     * so the kernel-store observations below watch it. */
    { "app.store.products",     zcl_native_handle_store_products,
      NULL, NULL,               NULL, NULL, NULL },
    { "core.sync.frontier.offline",
      zcl_native_handle_core_sync_frontier_offline,
      NULL, NULL,               NULL, NULL, NULL },
    /* Shop posture read: payload is node.db (wallet posture + schema),
     * opened through zcl_native_node_db_open_readonly, so payload_dir stays
     * NULL. The identity seed and directory/apps.csv are presence
     * disclosures. An unreadable node.db is refused by name
     * (NODE_DB_UNREADABLE), never answered ok with "unknown" fields. */
    { "app.shop.status",        zcl_native_handle_shop_status,
      NULL, NULL,               NULL, NULL, NULL },
    /* Evidence readout: payload is the <datadir>/zcode file store and no
     * database, so case 5 breaks zcode/manifests; an unreadable store is
     * the named ZCODE_STORE_UNREADABLE refusal, never an empty "no_record". */
    { "app.shop.reputation",    zcl_native_handle_shop_reputation,
      "publisher", RLW_PUBKEY,  NULL, NULL, "zcode/manifests" },
    /* Want board reads: payload is the shop_wants table in node.db via the
     * guarded read-only open (payload_dir NULL), preceded by a
     * table-presence probe; a pre-v66 node.db is the named
     * WANT_STORE_NOT_MIGRATED refusal. The moderation policy file is a
     * presence disclosure. status gets a well-formed id so the handler
     * reaches the datadir. */
    { "app.shop.want.list",     zcl_native_handle_shop_want_list,
      NULL, NULL,               NULL, NULL, NULL },
    { "app.shop.want.status",   zcl_native_handle_shop_want_status,
      "want_id", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    /* Slice-E reads use the guarded node.db projection and inspect CAS
     * evidence without opening the mutable package store. */
    { "app.shop.want.fulfill.list",
      zcl_native_handle_shop_want_fulfill_list,
      "want_id", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    { "app.shop.want.fulfill.status",
      zcl_native_handle_shop_want_fulfill_status,
      "fulfill_id", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    /* Real inputs, so each leaf reaches the datadir: core.identity.resolve
     * gets a selector and core.storage.query.offline a runnable
     * statement. */
    { "core.epoch.status",      zcl_native_handle_core_epoch_status,
      NULL, NULL,               NULL, NULL, NULL },
    { "core.epoch.verify",      zcl_native_handle_core_epoch_verify,
      NULL, NULL,               NULL, NULL, NULL },
    { "core.identity.list",     zcl_native_handle_core_identity_list,
      NULL, NULL,               NULL, NULL, NULL },
    { "core.identity.resolve",  zcl_native_handle_core_identity_resolve,
      "pubkey", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    { "core.storage.query.offline",
      zcl_native_handle_core_storage_query_offline,
      "sql", "SELECT 1",        NULL, NULL, NULL },
    /* core.storage.schema.offline: the classifier stat()s the path and
     * reads the raw SQLite header with open(O_RDONLY), so it needs no
     * input beyond datadir. */
    { "core.storage.schema.offline",
      zcl_native_handle_core_storage_schema_offline,
      NULL, NULL,               NULL, NULL, NULL },
    /* bootstatus reads <datadir>/boot_status.json and opens no database;
     * only proves it creates and quarantines nothing. */
    { "core.node.bootstatus",   zcl_native_handle_core_node_bootstatus,
      NULL, NULL,               NULL, NULL, NULL },
    /* Property catalog: both leaves reach store bytes by path and never
     * call vcs_package_store_open() (its recovery sweep deletes orphan CAS
     * objects). Real inputs so the handler reaches the datadir. The
     * payload is the frozen <datadir>/zcode tree, so case 5 breaks that. */
    { "metaverse.property.list", zcl_native_handle_metaverse_property_list,
      "kind", "content",        NULL, NULL, "zcode/manifests" },
    { "metaverse.property.show", zcl_native_handle_metaverse_property_show,
      "property_id", RLW_PROPERTY_ID, NULL, NULL, "zcode/manifests" },
    /* Build-ledger reads use the same read-only node.db attachment as the
     * older application leaves. */
    { "metaverse.build.status", zcl_native_handle_metaverse_build_status,
      "job_id", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    { "metaverse.build.receipt", zcl_native_handle_metaverse_build_receipt,
      "receipt_id", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    { "metaverse.build.worker.list",
      zcl_native_handle_metaverse_build_worker_list,
      NULL, NULL, NULL, NULL, NULL },
    /* S3 science projection reads answer from the rebuildable SQL
     * projection in node.db, so payload_dir stays NULL. Well-formed root
     * so the handler reaches the datadir. */
    { "zcode.science.study.show",
      zcl_native_handle_zcode_science_study_show,
      "study_root", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    { "zcode.science.study.list",
      zcl_native_handle_zcode_science_study_list,
      NULL, NULL, NULL, NULL, NULL },
    { "zcode.science.work.status",
      zcl_native_handle_zcode_science_work_status,
      "root", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    { "zcode.science.work.receipt",
      zcl_native_handle_zcode_science_work_receipt,
      "root", RLW_ZID_PUBKEY, NULL, NULL, NULL },
    /* S5 discovery read: read-only node.db projection, then the workspace
     * CAS (defaults to <datadir>/zcode; an absent one is an empty corpus),
     * so payload_dir stays NULL. Real category so the handler reaches the
     * datadir. */
    { "zcode.science.discover",
      zcl_native_handle_zcode_science_discover,
      "category", "active",     NULL, NULL, NULL },
    /* Local package-store catalog. Absent <datadir>/zcode/manifests is an
     * empty list and never opens the store (open runs recovery GC);
     * payload_dir is zcode/manifests so a file there is STORE_UNREADABLE. */
    { "zcode.package.library",  zcl_native_handle_zcode_package_library,
      NULL, NULL,               NULL, NULL, "zcode/manifests" },
    /* Live ANNOUNCE catalog: one-shot returns live:false and an empty list
     * without opening the store; a non-directory zcode/manifests is
     * STORE_UNREADABLE. */
    { "zcode.package.offered",  zcl_native_handle_zcode_package_offered,
      NULL, NULL,               NULL, NULL, "zcode/manifests" },
    /* Policy inspection is a READ leaf: its loader must not create
     * zcode/policy on an absent datadir or repair an unreadable store. */
    { "zcode.network.policy.list",
      zcl_native_handle_zcode_network_policy_list,
      NULL, NULL,               NULL, NULL, "zcode/policy" },
    /* Sovereign-space reads use public delegation/key material or the
     * immutable workspace CAS. The plan leaves get their array and integer
     * inputs in rlw_add_complex_input so they reach the datadir. */
    { "metaverse.space.plan", zcl_native_handle_metaverse_space_plan,
      "kind", "space_manifest", "name", "read-leaf-probe", "zcode/dht" },
    { "metaverse.space.show", zcl_native_handle_metaverse_space_show,
      "root", RLW_ZID_PUBKEY, NULL, NULL, "zcode/.zvcs" },
    { "metaverse.space.status", zcl_native_handle_metaverse_space_status,
      "root", RLW_ZID_PUBKEY, NULL, NULL, "zcode/.zvcs" },
    { "metaverse.space.scout.plan",
      zcl_native_handle_metaverse_space_scout_plan,
      NULL, NULL, NULL, NULL, "zcode/dht" },
    { "metaverse.space.scout.show",
      zcl_native_handle_metaverse_space_scout_show,
      "root", RLW_ZID_PUBKEY, NULL, NULL, "zcode/.zvcs" },
};

#define RLW_LEAF_COUNT ((int)(sizeof(g_rlw_leaves) / sizeof(g_rlw_leaves[0])))

static void rlw_push_single_root_array(struct json_value *input,
                                       const char *key)
{
    struct json_value roots;
    struct json_value root;
    json_init(&roots);
    json_set_array(&roots);
    json_init(&root);
    json_set_str(&root, RLW_ZID_PUBKEY);
    (void)json_push_back(&roots, &root);
    (void)json_push_kv(input, key, &roots);
    json_free(&root);
    json_free(&roots);
}

/* Supply the non-string inputs the two plan handlers need to get past
 * validation and reach their datadir. Keyed by registered path. */
static void rlw_add_complex_input(const struct rlw_leaf *lf,
                                  struct json_value *input)
{
    if (strcmp(lf->path, "zcode.package.dev.publish.plan") == 0) {
        (void)json_push_kv_str(input, "publisher_pubkey", RLW_PUBKEY);
        (void)json_push_kv_str(input, "name", "fixture/read-probe");
        (void)json_push_kv_str(input, "semver", "1.0.0");
        (void)json_push_kv_str(input, "license", "MIT");
        return;
    }
    if (strcmp(lf->path, "metaverse.space.plan") == 0) {
        (void)json_push_kv_int(input, "sequence", 1);
        (void)json_push_kv_int(input, "not_before", 1);
        (void)json_push_kv_int(input, "expiry", 2);
        (void)json_push_kv_str(input, "description",
                               "read-only datadir integrity probe");
        return;
    }
    if (strcmp(lf->path, "metaverse.space.scout.plan") == 0) {
        rlw_push_single_root_array(input, "starting_roots");
        (void)json_push_kv_int(input, "observation_unix", 1);
        (void)json_push_kv_int(input, "maximum_depth", 1);
        (void)json_push_kv_int(input, "maximum_spaces", 2);
        (void)json_push_kv_int(input, "maximum_portals", 2);
        (void)json_push_kv_int(input, "maximum_bytes", 4096);
        (void)json_push_kv_int(input, "deadline_ms", 1000);
    }
}

/* ── the read leaves this file does NOT exercise, and why ──────────────
 *
 * Every READ leaf with a `datadir` not in the table above is listed here
 * with a reason. t_registry_coverage refuses any derived leaf on neither
 * list; the count is ceilinged (RLW_UNCOVERED_MAX) and shrink-only. */
#define RLW_UNCOVERED_REASON_PREEXISTING                                 \
    "pre-existing gap: declared READ, takes datadir, never exercised "   \
    "here. Made visible by the registry-derived coverage check; delete "  \
    "this line by adding the leaf to g_rlw_leaves"

struct rlw_uncovered {
    const char *path;
    const char *why;
};

static const struct rlw_uncovered g_rlw_uncovered[] = {
    { "core.node.bootwait",           RLW_UNCOVERED_REASON_PREEXISTING },
    { "ops.debug.producer",           RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.package.publish.plan",   RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.package.search",         RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.package.show",           RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.package.recipe",         RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.package.verify",         RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.package.peers",          RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.contributor.packages",   RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.contributor.badges",     RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.reward.score",           RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.reward.eligible",        RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.reward.queue",           RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.reward.receipt",         RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.leaderboard.daily",      RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.leaderboard.weekly",     RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.leaderboard.monthly",    RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.leaderboard.all",        RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.badge.eligible",         RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.seed.status",            RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.seed.ratio",             RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.storage.status",         RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.release.verify",         RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.proof.walk",             RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.desc.resolve",           RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.endpoint.verify",        RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.endpoint.resolve",       RLW_UNCOVERED_REASON_PREEXISTING },
    { "zcode.endpoint.list",          RLW_UNCOVERED_REASON_PREEXISTING },
};

#define RLW_UNCOVERED_COUNT \
    ((int)(sizeof(g_rlw_uncovered) / sizeof(g_rlw_uncovered[0])))

/* SHRINK-ONLY ceiling. */
#define RLW_UNCOVERED_MAX 28

/* Anti-vacuous floor on the derived population (below the live count). */
#define RLW_DERIVED_FLOOR 35

/* ── on-disk observation helpers ───────────────────────────────────── */

/* FNV-1a over the whole file. 0 means "could not read". */
static uint64_t rlw_file_hash(const char *path, int64_t *size_out)
{
    if (size_out)
        *size_out = -1;
    FILE *f = fopen(path, "rb");
    if (!f)
        return 0;
    uint64_t h = 1469598103934665603ULL;
    int64_t total = 0;
    unsigned char buf[65536];
    size_t got;
    while ((got = fread(buf, 1, sizeof(buf), f)) > 0) {
        total += (int64_t)got;
        for (size_t i = 0; i < got; i++) {
            h ^= buf[i];
            h *= 1099511628211ULL;
        }
    }
    fclose(f);
    if (size_out)
        *size_out = total;
    /* Never return the "unreadable" sentinel for a real read. */
    return h ? h : 1;
}

/* Count directory entries whose name starts with `prefix`. -1 on a
 * directory that cannot be opened. */
static int rlw_count_entries(const char *dir, const char *prefix)
{
    DIR *d = opendir(dir);
    if (!d)
        return -1;
    int n = 0;
    size_t plen = strlen(prefix);
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        if (plen == 0 || strncmp(e->d_name, prefix, plen) == 0)
            n++;
    }
    closedir(d);
    return n;
}

/* The datadir's recursive FILE SET, as a sorted newline-joined list of
 * typed relative paths, since per-file hashes cannot see a file or
 * directory appearing. False on overflow or an unreadable directory.
 * lstat() records symlinks without following them. */
#define RLW_SET_MAX_ENTRIES 128
#define RLW_SET_NAME_MAX 512

static char g_rlw_set_names[RLW_SET_MAX_ENTRIES][RLW_SET_NAME_MAX];

static bool rlw_set_add(const char *name, int *count)
{
    if (!name || !count || *count >= RLW_SET_MAX_ENTRIES ||
        strlen(name) >= RLW_SET_NAME_MAX)
        return false;
    int i = (*count)++;
    while (i > 0 && strcmp(g_rlw_set_names[i - 1], name) > 0) {
        memcpy(g_rlw_set_names[i], g_rlw_set_names[i - 1],
               RLW_SET_NAME_MAX);
        i--;
    }
    snprintf(g_rlw_set_names[i], RLW_SET_NAME_MAX, "%s", name);
    return true;
}

static char rlw_dir_set_kind(mode_t mode)
{
    return S_ISDIR(mode) ? 'd'
         : S_ISREG(mode) ? 'f'
         : S_ISLNK(mode) ? 'l' : 'o';
}

static bool rlw_dir_set_walk(const char *base, const char *relative,
                             int *count);

static bool rlw_dir_set_entry(const char *base, const char *relative,
                              const char *name, int *count)
{
    char child[RLW_SET_NAME_MAX - 3];
    int n = relative && relative[0]
                ? snprintf(child, sizeof(child), "%s/%s", relative, name)
                : snprintf(child, sizeof(child), "%s", name);
    char path[1200];
    if (n <= 0 || (size_t)n >= sizeof(child) ||
        snprintf(path, sizeof(path), "%s/%s", base, child) >=
            (int)sizeof(path))
        return false;
    struct stat st;
    if (lstat(path, &st) != 0)
        return false;
    char typed[RLW_SET_NAME_MAX];
    char kind = rlw_dir_set_kind(st.st_mode);
    n = snprintf(typed, sizeof(typed), "%c %s", kind, child);
    if (n <= 0 || (size_t)n >= sizeof(typed) ||
        !rlw_set_add(typed, count) ||
        (S_ISDIR(st.st_mode) && !rlw_dir_set_walk(base, child, count)))
        return false;
    return true;
}

static bool rlw_dir_set_walk(const char *base, const char *relative,
                             int *count)
{
    char directory[1200];
    int n = relative && relative[0]
                ? snprintf(directory, sizeof(directory), "%s/%s", base,
                           relative)
                : snprintf(directory, sizeof(directory), "%s", base);
    if (n <= 0 || (size_t)n >= sizeof(directory))
        return false;
    DIR *d = opendir(directory);
    if (!d)
        return false;
    bool ok = true;
    struct dirent *e;
    while (ok && (e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        ok = rlw_dir_set_entry(base, relative, e->d_name, count);
    }
    closedir(d);
    return ok;
}

static bool rlw_dir_set(const char *dir, char *out, size_t out_size)
{
    if (!out || !out_size)
        return false;
    out[0] = '\0';
    int n = 0;
    if (!rlw_dir_set_walk(dir, "", &n))
        return false;
    for (int i = 0; i < n; i++) {
        size_t used = strlen(out);
        int wrote = snprintf(out + used, out_size - used, "%s\n",
                             g_rlw_set_names[i]);
        if (wrote <= 0 || (size_t)wrote >= out_size - used)
            return false;
    }
    return true;
}

/* Is the database at `path` in WAL mode? Header byte 18 is 2 for WAL;
 * read from the file so the code under test cannot satisfy it. */
static bool rlw_is_wal(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return false;
    unsigned char h[20] = { 0 };
    size_t got = fread(h, 1, sizeof(h), f);
    fclose(f);
    return got == sizeof(h) && memcmp(h, "SQLite format 3", 16) == 0 &&
           h[18] == 2;
}

/* Print every entry under `dir` — the evidence line for a failed case. */
static void rlw_list_dir(const char *tag, const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) {
        printf("    [%s] %s: unreadable\n", tag, dir);
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
            continue;
        char p[1200];
        snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(p, &st) == 0)
            printf("    [%s] %s (%lld bytes)\n", tag, e->d_name,
                   (long long)st.st_size);
        else
            printf("    [%s] %s\n", tag, e->d_name);
    }
    closedir(d);
}

/* SELECT one integer, read-only. -1 on any failure. */
static int64_t rlw_scalar(const char *db_path, const char *sql)
{
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return -1;
    }
    sqlite3_stmt *st = NULL;
    int64_t v = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW)
            v = sqlite3_column_int64(st, 0);
        sqlite3_finalize(st);
    }
    sqlite3_close(db);
    return v;
}

/* ── fixture builders ──────────────────────────────────────────────── */

static void rlw_mkfixture(char *dir, size_t n, const char *tag)
{
    test_fmt_tmpdir(dir, n, "read_leaf_no_write", tag);
    mkdir("./test-tmp", 0700);
    test_rm_rf(dir);
    mkdir(dir, 0700);
    /* Package-index leaves need zcode/ or they return before node.db. */
    char zdir[1200];
    snprintf(zdir, sizeof(zdir), "%s/zcode", dir);
    mkdir(zdir, 0700);
}

/* The shared fixture supplies zcode/; sovereign-space reads must not
 * materialize even that directory, so remove it for those leaves. */
static bool rlw_require_truly_empty_space_fixture(const struct rlw_leaf *lf,
                                                  const char *dir)
{
    if (strncmp(lf->path, "metaverse.space.", 16) != 0)
        return true;
    char zdir[1200];
    snprintf(zdir, sizeof(zdir), "%s/zcode", dir);
    return rmdir(zdir) == 0;
}

/* Bytes for every "this is not a database" fixture. */
static const char *const g_rlw_junk =
    "this is an operator file, not a SQLite database\n";

static bool rlw_write_junk(const char *path)
{
    size_t len = strlen(g_rlw_junk);
    FILE *f = fopen(path, "wb");
    bool ok = f && fwrite(g_rlw_junk, 1, len, f) == len;
    if (f)
        fclose(f);
    return ok;
}

/* ── kernel-store (consensus.db) fixture ───────────────────────────────
 *
 * A valid but empty SQLite file at <datadir>/consensus.db with one real
 * table, so any changed byte is DDL the leaf wrote and a quarantine is
 * unambiguous damage. */
static bool rlw_seed_kernel_store(const char *dir, char *path_out,
                                  size_t path_size)
{
    snprintf(path_out, path_size, "%s/%s", dir, CONSENSUS_DB_FILENAME);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path_out, &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)
        != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return false;
    }
    bool ok = sqlite3_exec(db, "CREATE TABLE rlw_fixture(x INTEGER)", NULL,
                           NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    return ok;
}

/* A migrated node.db with rows in the two places the boot ceremony
 * deletes from. Returns false if the fixture is not as assumed. */
static bool rlw_seed_node_db(const char *dir, const char *db_path)
{
    (void)dir;
    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    if (!node_db_open(&ndb, db_path) || !ndb.open) {
        fprintf(stderr, "[read_leaf_no_datadir_write] fixture: node_db_open "
                        "failed for %s\n", db_path);
        return false;
    }
    static const char *const seed =
        "INSERT OR REPLACE INTO snapshot_staging_utxos"
        "(txid,vout,value,script,script_type,address_hash,height,is_coinbase)"
        " VALUES(x'11', 0, 5000, x'76a914', 0, NULL, 700000, 0);"
        "INSERT OR REPLACE INTO snapshot_staging_utxos"
        "(txid,vout,value,script,script_type,address_hash,height,is_coinbase)"
        " VALUES(x'22', 1, 6000, x'76a914', 0, NULL, 700001, 0);"
        "INSERT OR REPLACE INTO node_state(key,value)"
        " VALUES('snapshot_staging_height','700001');"
        "INSERT OR REPLACE INTO node_state(key,value)"
        " VALUES('snapshot_staging_root','deadbeef');";
    char *err = NULL;
    bool ok = sqlite3_exec(ndb.db, seed, NULL, NULL, &err) == SQLITE_OK;
    if (!ok) {
        fprintf(stderr, "[read_leaf_no_datadir_write] fixture seed: %s\n",
                err ? err : "(null)");
        sqlite3_free(err);
    }
    node_db_close(&ndb);
    return ok;
}

/* ── leaf invocation ───────────────────────────────────────────────── */

/* Same call, but reports whether the leaf DISCLOSED that the read did not
 * happen. Honest shapes: refuse with an error code; answer the rest with a
 * section marked "read": false and a reason; or answer "ready": false with
 * a typed blocker. A bare empty answer counts as none of them. */
static void rlw_invoke_build_input(const struct rlw_leaf *lf,
                                   const char *datadir,
                                   struct json_value *input)
{
    json_init(input);
    json_set_object(input);
    (void)json_push_kv_str(input, "datadir", datadir);
    if (lf->k1)
        (void)json_push_kv_str(input, lf->k1,
            strcmp(lf->v1, RLW_DATADIR_VALUE) == 0 ? datadir : lf->v1);
    if (lf->k2)
        (void)json_push_kv_str(input, lf->k2,
            strcmp(lf->v2, RLW_DATADIR_VALUE) == 0 ? datadir : lf->v2);
    rlw_add_complex_input(lf, input);
}

static bool rlw_reply_declares_not_ready(const struct json_value *data)
{
    const struct json_value *ready = json_get(data, "ready");
    const char *blocker = json_get_str(json_get(data, "blocker"));
    const char *current = json_get_str(json_get(data, "current_state"));
    const char *next = json_get_str(json_get(data, "next_action"));
    return ready && ready->type == JSON_BOOL &&
        !json_get_bool(ready) && blocker && blocker[0] &&
        strcmp(blocker, "NONE") != 0 && current && current[0] &&
        next && next[0];
}

static bool rlw_reply_discloses_unread(const struct json_value *data)
{
    bool refused = false;
    for (size_t i = 0; i < data->num_children && !refused; i++) {
        const struct json_value *sec = &data->children[i];
        if (sec->type != JSON_OBJ)
            continue;
        const struct json_value *r = json_get(sec, "read");
        if (r && r->type == JSON_BOOL && !json_get_bool(r) &&
            json_get(sec, "reason"))
            refused = true;
    }
    return refused;
}

static bool rlw_invoke_refused(const struct rlw_leaf *lf, const char *datadir,
                               char *code_out, size_t code_size)
{
    struct json_value input;
    rlw_invoke_build_input(lf, datadir, &input);

    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.read_leaf_probe.v1");
    lf->fn(&request, &reply);
    bool refused = reply.exit_code != 0 || reply.error.code[0] != '\0';
    if (!refused && reply.data.type == JSON_OBJ)
        refused = rlw_reply_declares_not_ready(&reply.data);
    /* Degrade-and-disclose: any top-level section with "read": false
     * says in the reply that it did not look. */
    if (!refused && reply.data.type == JSON_OBJ)
        refused = rlw_reply_discloses_unread(&reply.data);
    if (code_out && code_size)
        snprintf(code_out, code_size, "%s",
                 reply.error.code[0]      ? reply.error.code
                 : refused                ? "read:false+reason"
                                          : "-");
    printf("    [%s] status=%d exit=%d code=%s\n", lf->path, (int)reply.status,
           (int)reply.exit_code, reply.error.code[0] ? reply.error.code : "-");
    zcl_command_reply_free(&reply);
    json_free(&input);
    return refused;
}

static void rlw_invoke(const struct rlw_leaf *lf, const char *datadir)
{
    struct json_value input;
    json_init(&input);
    json_set_object(&input);
    (void)json_push_kv_str(&input, "datadir", datadir);
    if (lf->k1)
        (void)json_push_kv_str(&input, lf->k1,
            strcmp(lf->v1, RLW_DATADIR_VALUE) == 0 ? datadir : lf->v1);
    if (lf->k2)
        (void)json_push_kv_str(&input, lf->k2,
            strcmp(lf->v2, RLW_DATADIR_VALUE) == 0 ? datadir : lf->v2);
    rlw_add_complex_input(lf, &input);

    struct zcl_command_request request = { .input = &input };
    struct zcl_command_reply reply;
    zcl_command_reply_init(&reply, "zcl.read_leaf_probe.v1");
    lf->fn(&request, &reply);
    printf("    [%s] status=%d exit=%d code=%s\n", lf->path, (int)reply.status,
           (int)reply.exit_code, reply.error.code[0] ? reply.error.code : "-");
    zcl_command_reply_free(&reply);
    json_free(&input);
}

/* ── case 1: an empty datadir must stay empty of node.db ───────────── */

static int t_absent_node_db_is_not_created(void)
{
    int failures = 0;

    for (int i = 0; i < RLW_LEAF_COUNT; i++) {
        const struct rlw_leaf *lf = &g_rlw_leaves[i];
        char dir[256];
        char tag[64];
        snprintf(tag, sizeof(tag), "absent%d", i);
        rlw_mkfixture(dir, sizeof(dir), tag);

        char name[160];
        bool literal_empty = strncmp(lf->path, "metaverse.space.", 16) == 0;
        snprintf(name, sizeof(name),
                 "%s: sovereign-space fixture starts literally empty",
                 lf->path);
        if (literal_empty)
            RLW_CHECK(name, rlw_require_truly_empty_space_fixture(lf, dir));

        char db_path[1200];
        snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

        snprintf(name, sizeof(name),
                 "%s: fixture starts with no node.db", lf->path);
        RLW_CHECK(name, access(db_path, F_OK) != 0);

        char before[4096];
        bool got_before = rlw_dir_set(dir, before, sizeof(before));
        snprintf(name, sizeof(name),
                 "%s: empty fixture tree observed before the read", lf->path);
        RLW_CHECK(name, got_before);
        if (literal_empty) {
            snprintf(name, sizeof(name),
                     "%s: absent datadir contains zero entries before read",
                     lf->path);
            RLW_CHECK(name, got_before && before[0] == '\0');
        }

        rlw_invoke(lf, dir);

        char after[4096];
        bool got_after = rlw_dir_set(dir, after, sizeof(after));
        snprintf(name, sizeof(name),
                 "%s: empty fixture tree observed after the read", lf->path);
        RLW_CHECK(name, got_after);
        bool same_tree = got_before && got_after &&
                         strcmp(before, after) == 0;
        if (!same_tree) {
            printf("    recursive tree BEFORE:\n%s", before);
            printf("    recursive tree AFTER:\n%s", after);
        }
        snprintf(name, sizeof(name),
                 "%s: read leaf created nothing in an empty datadir",
                 lf->path);
        RLW_CHECK(name, same_tree);

        int left = rlw_count_entries(dir, "node.db");
        /* Same for the kernel store, under the current and legacy names. */
        int kleft = rlw_count_entries(dir, CONSENSUS_DB_FILENAME);
        int pleft = rlw_count_entries(dir, CONSENSUS_DB_LEGACY_KERNEL_FILENAME);
        if (left != 0 || kleft != 0 || pleft != 0)
            rlw_list_dir(lf->path, dir);
        snprintf(name, sizeof(name),
                 "%s: read leaf created no node.db* in an empty datadir",
                 lf->path);
        RLW_CHECK(name, left == 0);
        snprintf(name, sizeof(name),
                 "%s: read leaf created no kernel store in an empty datadir",
                 lf->path);
        RLW_CHECK(name, kleft == 0 && pleft == 0);

        test_rm_rf(dir);
    }
    return failures;
}

/* ── case 2: a real node.db must come out byte-identical ───────────── */

static int t_present_node_db_is_not_mutated(void)
{
    int failures = 0;
    char dir[256];
    rlw_mkfixture(dir, sizeof(dir), "present");
    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    RLW_CHECK("present: fixture node.db seeded",
              rlw_seed_node_db(dir, db_path));

    char kernel_path[1200];
    RLW_CHECK("present: fixture consensus.db seeded",
              rlw_seed_kernel_store(dir, kernel_path, sizeof(kernel_path)));
    int64_t kernel_size_before = -1;
    uint64_t kernel_hash_before = rlw_file_hash(kernel_path,
                                               &kernel_size_before);
    RLW_CHECK("present: consensus.db readable before the calls",
              kernel_hash_before != 0 && kernel_size_before > 0);

    static const char *const q_utxos =
        "SELECT COUNT(*) FROM snapshot_staging_utxos";
    static const char *const q_state =
        "SELECT COUNT(*) FROM node_state WHERE key LIKE 'snapshot_staging_%'";

    int64_t utxos_before = rlw_scalar(db_path, q_utxos);
    int64_t state_before = rlw_scalar(db_path, q_state);
    /* Anti-vacuous: with zero seeded rows the DELETEs are invisible. */
    RLW_CHECK("present: 2 snapshot_staging_utxos rows to lose",
              utxos_before == 2);
    RLW_CHECK("present: 2 snapshot_staging_% node_state rows to lose",
              state_before == 2);

    int64_t size_before = -1;
    uint64_t hash_before = rlw_file_hash(db_path, &size_before);
    RLW_CHECK("present: node.db readable before the calls",
              hash_before != 0 && size_before > 0);

    for (int i = 0; i < RLW_LEAF_COUNT; i++)
        rlw_invoke(&g_rlw_leaves[i], dir);

    int64_t size_after = -1;
    uint64_t hash_after = rlw_file_hash(db_path, &size_after);
    int64_t utxos_after = rlw_scalar(db_path, q_utxos);
    int64_t state_after = rlw_scalar(db_path, q_state);
    int quarantined = rlw_count_entries(dir, "node.db.corrupt");

    if (hash_after != hash_before || utxos_after != utxos_before ||
        state_after != state_before || quarantined != 0) {
        printf("    size %lld -> %lld, hash %016llx -> %016llx\n",
               (long long)size_before, (long long)size_after,
               (unsigned long long)hash_before,
               (unsigned long long)hash_after);
        printf("    snapshot_staging_utxos %lld -> %lld, "
               "node_state snapshot_staging_%% %lld -> %lld\n",
               (long long)utxos_before, (long long)utxos_after,
               (long long)state_before, (long long)state_after);
        rlw_list_dir("present", dir);
    }

    RLW_CHECK("present: node.db byte length unchanged",
              size_after == size_before && size_after > 0);
    RLW_CHECK("present: node.db content hash unchanged",
              hash_after == hash_before && hash_after != 0);
    RLW_CHECK("present: snapshot_staging_utxos rows survived",
              utxos_after == utxos_before);
    RLW_CHECK("present: node_state snapshot_staging_% rows survived",
              state_after == state_before);
    RLW_CHECK("present: nothing was quarantined to node.db.corrupt-*",
              quarantined == 0);

    int64_t kernel_size_after = -1;
    uint64_t kernel_hash_after = rlw_file_hash(kernel_path,
                                              &kernel_size_after);
    int kernel_quarantined = rlw_count_entries(dir, "consensus.db.corrupt");
    if (kernel_hash_after != kernel_hash_before || kernel_quarantined != 0) {
        printf("    consensus.db size %lld -> %lld, hash %016llx -> %016llx\n",
               (long long)kernel_size_before, (long long)kernel_size_after,
               (unsigned long long)kernel_hash_before,
               (unsigned long long)kernel_hash_after);
        rlw_list_dir("present", dir);
    }
    RLW_CHECK("present: consensus.db byte length unchanged",
              kernel_size_after == kernel_size_before &&
              kernel_size_after > 0);
    RLW_CHECK("present: consensus.db content hash unchanged",
              kernel_hash_after == kernel_hash_before &&
              kernel_hash_after != 0);
    RLW_CHECK("present: nothing was quarantined to consensus.db.corrupt-*",
              kernel_quarantined == 0);

    test_rm_rf(dir);
    return failures;
}

/* ── case 3: a valid database that is not a NODE database ───────────────
 *
 * Re-running create_schema()/node_db_migrate() on a migrated node.db is
 * byte-identical, so the present case cannot see a schema install. Point
 * every read leaf at a real SQLite file that is not a node database and
 * require the same tables come back. */

static int64_t rlw_table_count(const char *db_path)
{
    return rlw_scalar(db_path,
                      "SELECT COUNT(*) FROM sqlite_master WHERE type='table'");
}

static int t_foreign_node_db_gets_no_schema(void)
{
    int failures = 0;
    char dir[256];
    rlw_mkfixture(dir, sizeof(dir), "foreign");
    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    sqlite3 *seed = NULL;
    bool made = sqlite3_open_v2(db_path, &seed,
                                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                                NULL) == SQLITE_OK &&
                sqlite3_exec(seed,
                             "CREATE TABLE operator_notes(note TEXT);"
                             "INSERT INTO operator_notes VALUES('mine');",
                             NULL, NULL, NULL) == SQLITE_OK;
    if (seed)
        sqlite3_close(seed);
    RLW_CHECK("foreign: fixture is a real SQLite file, not a node database",
              made);

    int64_t tables_before = rlw_table_count(db_path);
    /* Anti-vacuous: one table, so any schema install is a visible jump. */
    RLW_CHECK("foreign: fixture holds exactly its own 1 table",
              tables_before == 1);
    int64_t size_before = -1;
    uint64_t hash_before = rlw_file_hash(db_path, &size_before);
    RLW_CHECK("foreign: fixture readable before the calls",
              hash_before != 0 && size_before > 0);

    for (int i = 0; i < RLW_LEAF_COUNT; i++)
        rlw_invoke(&g_rlw_leaves[i], dir);

    int64_t tables_after = rlw_table_count(db_path);
    int64_t size_after = -1;
    uint64_t hash_after = rlw_file_hash(db_path, &size_after);
    int quarantined = rlw_count_entries(dir, "node.db.corrupt");

    if (tables_after != tables_before || hash_after != hash_before ||
        quarantined != 0) {
        printf("    tables %lld -> %lld, size %lld -> %lld, "
               "hash %016llx -> %016llx\n",
               (long long)tables_before, (long long)tables_after,
               (long long)size_before, (long long)size_after,
               (unsigned long long)hash_before,
               (unsigned long long)hash_after);
        rlw_list_dir("foreign", dir);
    }

    RLW_CHECK("foreign: no schema was installed into the operator's file",
              tables_after == tables_before && tables_after == 1);
    RLW_CHECK("foreign: the file is still byte-identical",
              size_after == size_before && hash_after == hash_before &&
              hash_after != 0);
    RLW_CHECK("foreign: nothing was quarantined to node.db.corrupt-*",
              quarantined == 0);

    test_rm_rf(dir);
    return failures;
}

/* ── case 4: a node.db that is not a database must not be renamed ──── */

static int t_garbage_node_db_is_not_quarantined(void)
{
    int failures = 0;
    char dir[256];
    rlw_mkfixture(dir, sizeof(dir), "garbage");
    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    RLW_CHECK("garbage: fixture node.db written", rlw_write_junk(db_path));

    /* Same fixture for the kernel store: progress_store_open renames a
     * non-database aside and installs a fresh empty fact log. */
    char kernel_path[1200];
    snprintf(kernel_path, sizeof(kernel_path), "%s/%s", dir,
             CONSENSUS_DB_FILENAME);
    RLW_CHECK("garbage: fixture consensus.db written",
              rlw_write_junk(kernel_path));

    int64_t size_before = -1;
    uint64_t hash_before = rlw_file_hash(db_path, &size_before);
    RLW_CHECK("garbage: fixture readable before the calls",
              hash_before != 0 &&
              size_before == (int64_t)strlen(g_rlw_junk));
    int64_t kernel_size_before = -1;
    uint64_t kernel_hash_before = rlw_file_hash(kernel_path,
                                               &kernel_size_before);
    RLW_CHECK("garbage: consensus.db fixture readable before the calls",
              kernel_hash_before != 0 &&
              kernel_size_before == (int64_t)strlen(g_rlw_junk));

    for (int i = 0; i < RLW_LEAF_COUNT; i++)
        rlw_invoke(&g_rlw_leaves[i], dir);

    int64_t size_after = -1;
    uint64_t hash_after = rlw_file_hash(db_path, &size_after);
    int quarantined = rlw_count_entries(dir, "node.db.corrupt");
    int64_t kernel_size_after = -1;
    uint64_t kernel_hash_after = rlw_file_hash(kernel_path,
                                              &kernel_size_after);
    int kernel_quarantined = rlw_count_entries(dir, "consensus.db.corrupt");

    if (hash_after != hash_before || quarantined != 0 ||
        kernel_hash_after != kernel_hash_before || kernel_quarantined != 0)
        rlw_list_dir("garbage", dir);

    RLW_CHECK("garbage: node.db still exists under its own name",
              access(db_path, F_OK) == 0);
    RLW_CHECK("garbage: node.db still byte-identical",
              size_after == size_before && hash_after == hash_before &&
              hash_after != 0);
    RLW_CHECK("garbage: no node.db.corrupt-* rename happened",
              quarantined == 0);
    RLW_CHECK("garbage: consensus.db still exists under its own name",
              access(kernel_path, F_OK) == 0);
    RLW_CHECK("garbage: consensus.db still byte-identical",
              kernel_size_after == kernel_size_before &&
              kernel_hash_after == kernel_hash_before &&
              kernel_hash_after != 0);
    RLW_CHECK("garbage: no consensus.db.corrupt-* rename happened",
              kernel_quarantined == 0);

    test_rm_rf(dir);
    return failures;
}

/* ── case 5: a corrupt node.db must REFUSE, not answer empty ───────── */

/* sqlite3_open_v2 is lazy and opens a non-database with SQLITE_OK; the
 * failure only shows at the first statement, so absent and unreadable
 * must not be reported as the same answer.
 * Make <dir>/<rel> unreadable as a directory by putting a plain file
 * where it belongs, creating parents (opendir() fails with ENOTDIR). */
static bool rlw_break_dir(const char *dir, const char *rel)
{
    char path[1400];
    size_t base;

    if (snprintf(path, sizeof(path), "%s/%s", dir, rel) >= (int)sizeof(path))
        return false;
    base = strlen(dir) + 1;
    for (size_t i = base; path[i]; i++) {
        if (path[i] != '/')
            continue;
        path[i] = '\0';
        if (mkdir(path, 0700) != 0 && access(path, F_OK) != 0)
            return false;
        path[i] = '/';
    }
    return rlw_write_junk(path);
}

static int t_garbage_node_db_is_refused_not_empty(void)
{
    int failures = 0;
    char dir[256];
    rlw_mkfixture(dir, sizeof(dir), "refuse");
    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    RLW_CHECK("refuse: fixture node.db written", rlw_write_junk(db_path));

    /* Break whatever store each leaf actually reads. */
    for (int i = 0; i < RLW_LEAF_COUNT; i++) {
        char what[256];

        if (!g_rlw_leaves[i].payload_dir)
            continue;
        snprintf(what, sizeof(what), "refuse: %s payload store %s made "
                                     "unreadable",
                 g_rlw_leaves[i].path, g_rlw_leaves[i].payload_dir);
        RLW_CHECK(what, rlw_break_dir(dir, g_rlw_leaves[i].payload_dir));
    }

    /* The kernel store is unreadable too, so a leaf whose payload is in
     * consensus.db must disclose it. */
    char kernel_path[1200];
    snprintf(kernel_path, sizeof(kernel_path), "%s/%s", dir,
             CONSENSUS_DB_FILENAME);
    RLW_CHECK("refuse: fixture consensus.db written",
              rlw_write_junk(kernel_path));

    for (int i = 0; i < RLW_LEAF_COUNT; i++) {
        char code[64] = { 0 };
        bool refused = rlw_invoke_refused(&g_rlw_leaves[i], dir, code,
                                          sizeof(code));
        char what[192];
        snprintf(what, sizeof(what),
                 "refuse: %s answers a refusal over an unreadable %s "
                 "(got code=%s)", g_rlw_leaves[i].path,
                 g_rlw_leaves[i].payload_dir ? g_rlw_leaves[i].payload_dir
                                             : "node.db", code);
        RLW_CHECK(what, refused);
    }

    test_rm_rf(dir);
    return failures;
}

/* ── case 6: a WAL datadir must come back with the same FILE SET ────────
 *
 * A READONLY connection to a WAL database still creates <db>-shm and
 * <db>-wal and cannot unlink them on close. Both node.db and consensus.db
 * are WAL, so this is the ordinary case. Per-file hashes cannot see a file
 * appearing, so the property asserted is that the set of names in the
 * directory is the set that went in (a copy-proof depends on it). */

/* Floor on how many leaves must still ANSWER over a healthy WAL datadir;
 * guards against keeping the directory clean by refusing to open WAL. */
#define RLW_WAL_ANSWER_FLOOR 5

/* A kernel store in WAL mode, matching what progress_store_open() leaves
 * on disk (rlw_seed_kernel_store uses the default rollback journal). */
static bool rlw_seed_kernel_store_wal(const char *dir, char *path_out,
                                      size_t path_size)
{
    snprintf(path_out, path_size, "%s/%s", dir, CONSENSUS_DB_FILENAME);
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(path_out, &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)
        != SQLITE_OK) {
        if (db)
            sqlite3_close(db);
        return false;
    }
    bool ok = sqlite3_exec(db, "PRAGMA journal_mode=WAL", NULL, NULL, NULL)
                  == SQLITE_OK &&
              sqlite3_exec(db, "CREATE TABLE rlw_fixture(x INTEGER)", NULL,
                           NULL, NULL) == SQLITE_OK;
    /* A clean close checkpoints and unlinks the sidecars, leaving exactly
     * the two database files. */
    sqlite3_close(db);
    return ok;
}

static int t_wal_datadir_file_set_is_unchanged(void)
{
    int failures = 0;
    char dir[256];
    rlw_mkfixture(dir, sizeof(dir), "walset");
    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    RLW_CHECK("walset: fixture node.db seeded",
              rlw_seed_node_db(dir, db_path));
    char kernel_path[1200];
    RLW_CHECK("walset: fixture consensus.db seeded",
              rlw_seed_kernel_store_wal(dir, kernel_path,
                                        sizeof(kernel_path)));

    /* Anti-vacuous: a rollback-journal database grows no sidecars. */
    RLW_CHECK("walset: node.db really is in WAL mode (header byte 18 == 2)",
              rlw_is_wal(db_path));
    RLW_CHECK("walset: consensus.db really is in WAL mode",
              rlw_is_wal(kernel_path));

    /* The fixture must start clean. */
    char before[4096];
    bool got_before = rlw_dir_set(dir, before, sizeof(before));
    RLW_CHECK("walset: fixture file set observed before the calls", got_before);
    RLW_CHECK("walset: fixture starts with no node.db-wal/-shm",
              rlw_count_entries(dir, "node.db-") == 0);
    RLW_CHECK("walset: fixture starts with no consensus.db-wal/-shm",
              rlw_count_entries(dir, "consensus.db-") == 0);

    int64_t size_before = -1;
    uint64_t hash_before = rlw_file_hash(db_path, &size_before);
    int64_t kernel_size_before = -1;
    uint64_t kernel_hash_before = rlw_file_hash(kernel_path,
                                                &kernel_size_before);

    /* Anti-vacuous: a refusing open trivially leaves the directory
     * untouched, so count the leaves that answered and require that a
     * healthy WAL datadir still gets read. */
    int answered = 0;
    for (int i = 0; i < RLW_LEAF_COUNT; i++) {
        char code[64] = { 0 };
        if (!rlw_invoke_refused(&g_rlw_leaves[i], dir, code, sizeof(code)))
            answered++;
    }
    {
        char what[192];
        snprintf(what, sizeof(what),
                 "walset: %d leaves still READ the WAL datadir (floor %d) — "
                 "the clean directory is not just a failed open",
                 answered, RLW_WAL_ANSWER_FLOOR);
        RLW_CHECK(what, answered >= RLW_WAL_ANSWER_FLOOR);
    }

    char after[4096];
    bool got_after = rlw_dir_set(dir, after, sizeof(after));
    RLW_CHECK("walset: fixture file set observed after the calls", got_after);

    bool same_set = got_before && got_after && strcmp(before, after) == 0;
    if (!same_set) {
        printf("    file set BEFORE:\n%s", before);
        printf("    file set AFTER:\n%s", after);
        rlw_list_dir("walset", dir);
    }
    RLW_CHECK("walset: the datadir's file set is exactly what went in",
              same_set);

    /* Separate from the set comparison so a failure names the files. */
    int node_sidecars = rlw_count_entries(dir, "node.db-");
    int kernel_sidecars = rlw_count_entries(dir, "consensus.db-");
    if (node_sidecars != 0 || kernel_sidecars != 0)
        rlw_list_dir("walset", dir);
    RLW_CHECK("walset: no node.db-wal/-shm was created by a read",
              node_sidecars == 0);
    RLW_CHECK("walset: no consensus.db-wal/-shm was created by a read",
              kernel_sidecars == 0);

    /* The earlier assertions still hold on a WAL fixture. */
    int64_t size_after = -1;
    uint64_t hash_after = rlw_file_hash(db_path, &size_after);
    int64_t kernel_size_after = -1;
    uint64_t kernel_hash_after = rlw_file_hash(kernel_path,
                                               &kernel_size_after);
    RLW_CHECK("walset: node.db is still byte-identical",
              size_after == size_before && hash_after == hash_before &&
              hash_after != 0);
    RLW_CHECK("walset: consensus.db is still byte-identical",
              kernel_size_after == kernel_size_before &&
              kernel_hash_after == kernel_hash_before &&
              kernel_hash_after != 0);
    RLW_CHECK("walset: nothing was quarantined",
              rlw_count_entries(dir, "node.db.corrupt") == 0 &&
              rlw_count_entries(dir, "consensus.db.corrupt") == 0);

    test_rm_rf(dir);
    return failures;
}

/* ── case 7: a WAL datadir a LIVE writer is attached to ─────────────────
 *
 * The immutable open is not an option: it does not consult the log and
 * returns stale rows. With a writer attached the wal-index exists, so the
 * file set must still be unchanged and the writer must still be able to
 * write afterwards. */
static int t_wal_datadir_with_live_writer(void)
{
    int failures = 0;
    char dir[256];
    rlw_mkfixture(dir, sizeof(dir), "walopen");
    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    RLW_CHECK("walopen: fixture node.db seeded",
              rlw_seed_node_db(dir, db_path));
    char kernel_path[1200];
    RLW_CHECK("walopen: fixture consensus.db seeded",
              rlw_seed_kernel_store_wal(dir, kernel_path,
                                        sizeof(kernel_path)));

    /* Stand-in for the running node: a READWRITE connection that stays
     * open with an INSERT in its log. */
    struct node_db live;
    memset(&live, 0, sizeof(live));
    bool live_open = node_db_open(&live, db_path) && live.open;
    RLW_CHECK("walopen: a live writer holds node.db open", live_open);
    if (live_open)
        RLW_CHECK("walopen: the live writer has a row in its log",
                  sqlite3_exec(live.db,
                               "INSERT OR REPLACE INTO node_state(key,value)"
                               " VALUES('rlw_live','1')",
                               NULL, NULL, NULL) == SQLITE_OK);

    /* The writer's own sidecars are legitimate; the set must not change. */
    RLW_CHECK("walopen: the live writer's wal-index exists",
              rlw_count_entries(dir, "node.db-") > 0);

    char before[4096];
    bool got_before = rlw_dir_set(dir, before, sizeof(before));
    RLW_CHECK("walopen: file set observed before the calls", got_before);

    int answered = 0;
    for (int i = 0; i < RLW_LEAF_COUNT; i++) {
        char code[64] = { 0 };
        if (!rlw_invoke_refused(&g_rlw_leaves[i], dir, code, sizeof(code)))
            answered++;
    }
    {
        char what[192];
        snprintf(what, sizeof(what),
                 "walopen: %d leaves still READ through the live wal-index "
                 "(floor %d)", answered, RLW_WAL_ANSWER_FLOOR);
        RLW_CHECK(what, answered >= RLW_WAL_ANSWER_FLOOR);
    }

    char after[4096];
    bool got_after = rlw_dir_set(dir, after, sizeof(after));
    RLW_CHECK("walopen: file set observed after the calls", got_after);
    bool same_set = got_before && got_after && strcmp(before, after) == 0;
    if (!same_set) {
        printf("    file set BEFORE:\n%s", before);
        printf("    file set AFTER:\n%s", after);
    }
    RLW_CHECK("walopen: the file set is unchanged with a writer attached",
              same_set);
    RLW_CHECK("walopen: nothing was quarantined",
              rlw_count_entries(dir, "node.db.corrupt") == 0 &&
              rlw_count_entries(dir, "consensus.db.corrupt") == 0);

    /* The read must not have wedged the writer. */
    if (live_open) {
        RLW_CHECK("walopen: the live writer can still write afterwards",
                  sqlite3_exec(live.db,
                               "INSERT OR REPLACE INTO node_state(key,value)"
                               " VALUES('rlw_live_after','1')",
                               NULL, NULL, NULL) == SQLITE_OK);
        node_db_close(&live);
    }

    test_rm_rf(dir);
    return failures;
}

/* ── case 9: a writer that attaches AFTER the read-only open ────────────
 *
 * The handle is queried after it is returned, so "no wal-index means no
 * writer" must hold for the handle's whole life. The handle may report the
 * fresh state or refuse; it must never report the stale count as current. */
static int rlw_wal_race_check_untouched(sqlite3 *ro, const char *count_sql)
{
    int failures = 0;
    sqlite3_stmt *stmt = NULL;
    int64_t seen = -1;
    if (sqlite3_prepare_v2(ro, count_sql, -1, &stmt, NULL) == SQLITE_OK &&
        sqlite3_step(stmt) == SQLITE_ROW)
        seen = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    RLW_CHECK("walrace: the untouched snapshot answers its 2 seeded rows",
              seen == 2);
    return failures;
}

static int rlw_wal_race_check_fresh(sqlite3 *ro, const char *db_path,
                                    const char *count_sql)
{
    int failures = 0;
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(ro, count_sql, -1, &stmt, NULL);
    int64_t answered = -1;
    int step_rc = SQLITE_OK;
    if (rc == SQLITE_OK) {
        step_rc = sqlite3_step(stmt);
        if (step_rc == SQLITE_ROW)
            answered = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);

    bool refused = rc != SQLITE_OK || step_rc == SQLITE_INTERRUPT ||
                   (step_rc != SQLITE_ROW && step_rc != SQLITE_DONE);
    bool fresh = answered == 3;
    if (!refused && !fresh)
        printf("    read-only handle answered %lld (prepare rc=%d, step "
               "rc=%d) where the committed truth is 3\n",
               (long long)answered, rc, step_rc);
    RLW_CHECK("walrace: the handle reports the fresh state or refuses — "
              "never the pre-commit count",
              refused || fresh);
    /* The fresh truth really is 3, so a refusal above was a refusal to
     * report 2. A plain READONLY open is safe now: the writer's
     * wal-index is already on disk. */
    RLW_CHECK("walrace: the committed truth on disk is 3 rows",
              rlw_scalar(db_path, count_sql) == 3);
    return failures;
}

static int t_wal_snapshot_writer_arrives_after_open(void)
{
    int failures = 0;
    char dir[256];
    rlw_mkfixture(dir, sizeof(dir), "walrace");
    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    RLW_CHECK("walrace: fixture node.db seeded",
              rlw_seed_node_db(dir, db_path));
    /* Premise: a quiescent WAL database, which takes the immutable open. */
    RLW_CHECK("walrace: fixture node.db really is in WAL mode",
              rlw_is_wal(db_path));
    RLW_CHECK("walrace: fixture starts with no node.db-wal/-shm",
              rlw_count_entries(dir, "node.db-") == 0);

    /* The starting count is read through the handle under test, not
     * rlw_scalar(): a plain READONLY open of a quiescent WAL database
     * materializes the sidecars this case needs absent. */
    const char *const count_sql =
        "SELECT COUNT(*) FROM snapshot_staging_utxos";

    /* 1. the read-only open, exactly as a read leaf gets it */
    sqlite3 *ro = NULL;
    struct node_db ro_shim;
    char ro_path[1200];
    enum zcl_node_db_ro_status st = zcl_native_node_db_open_readonly(
        dir, &ro, &ro_shim, ro_path, sizeof(ro_path));
    RLW_CHECK("walrace: the read-only open succeeds on a quiescent WAL db",
              st == ZCL_NODE_DB_RO_OK && ro != NULL);
    RLW_CHECK("walrace: no sidecar was created by the read-only open",
              rlw_count_entries(dir, "node.db-") == 0);

    /* 1b. it answers, and answers correctly, while nothing has changed */
    if (ro)
        failures += rlw_wal_race_check_untouched(ro, count_sql);

    /* 2. Now the writer arrives, commits, and stays attached. A bare
     *    READWRITE connection, not node_db_open(): the boot ceremony
     *    would delete the seeded staging rows and move the count. */
    sqlite3 *live = NULL;
    bool live_open = st == ZCL_NODE_DB_RO_OK &&
                     sqlite3_open_v2(db_path, &live, SQLITE_OPEN_READWRITE,
                                     NULL) == SQLITE_OK;
    RLW_CHECK("walrace: a writer attaches after the read-only open", live_open);
    if (live_open)
        RLW_CHECK("walrace: the writer commits a third row",
                  sqlite3_exec(live,
                               "INSERT OR REPLACE INTO snapshot_staging_utxos"
                               "(txid,vout,value,script,script_type,"
                               "address_hash,height,is_coinbase)"
                               " VALUES(x'33', 2, 7000, x'76a914', 0, NULL,"
                               " 700002, 0)",
                               NULL, NULL, NULL) == SQLITE_OK);

    /* 3. the query the leaf would have run. Either answer is acceptable;
     *    "2" is not. */
    if (live_open && ro)
        failures += rlw_wal_race_check_fresh(ro, db_path, count_sql);

    zcl_native_node_db_close_readonly(&ro, &ro_shim);

    /* Nothing may be quarantined and the writer must still be able to
     * commit. */
    RLW_CHECK("walrace: nothing was quarantined",
              rlw_count_entries(dir, "node.db.corrupt") == 0);
    if (live_open) {
        RLW_CHECK("walrace: the writer can still write afterwards",
                  sqlite3_exec(live,
                               "INSERT OR REPLACE INTO node_state(key,value)"
                               " VALUES('rlw_race_after','1')",
                               NULL, NULL, NULL) == SQLITE_OK);
    }
    if (live)
        sqlite3_close(live);

    test_rm_rf(dir);
    return failures;
}

/* ── case 8: the population comes from the registry ──────────────────
 *
 * Every READ leaf that takes a `datadir` is derived from the command
 * registry, so a newly added leaf cannot be silently absent. */

/* Is `key` one comma-separated token of `csv`? (Substring matching would
 * accept "datadirs" and "no_datadir".) */
static bool rlw_csv_has(const char *csv, const char *key)
{
    if (!csv || !key || !key[0])
        return false;
    size_t klen = strlen(key);
    for (const char *p = csv; *p;) {
        while (*p == ' ' || *p == ',')
            p++;
        const char *start = p;
        while (*p && *p != ',')
            p++;
        size_t len = (size_t)(p - start);
        while (len && start[len - 1] == ' ')
            len--;
        if (len == klen && strncmp(start, key, klen) == 0)
            return true;
    }
    return false;
}

/* A leaf this file is responsible for: dispatchable, declared READ, and
 * pointable at a caller-named datadir. */
static bool rlw_is_datadir_read_leaf(const struct zcl_command_spec *s)
{
    return s && s->path && s->path[0] &&
           s->availability == ZCL_COMMAND_READY &&
           s->mode != ZCL_COMMAND_MODE_BRANCH &&
           s->effect == ZCL_COMMAND_EFFECT_READ &&
           s->handler != NULL &&
           rlw_csv_has(s->input_keys, "datadir");
}

static const struct rlw_leaf *rlw_coverage_find_leaf(const char *path)
{
    for (int j = 0; j < RLW_LEAF_COUNT; j++)
        if (strcmp(g_rlw_leaves[j].path, path) == 0)
            return &g_rlw_leaves[j];
    return NULL;
}

static const struct rlw_uncovered *rlw_coverage_find_uncovered(
    const char *path)
{
    for (int j = 0; j < RLW_UNCOVERED_COUNT; j++)
        if (strcmp(g_rlw_uncovered[j].path, path) == 0)
            return &g_rlw_uncovered[j];
    return NULL;
}

static int rlw_coverage_check_command(const struct zcl_command_spec *s,
                                      int *uncovered_seen)
{
    int failures = 0;
    const struct rlw_leaf *exercised = rlw_coverage_find_leaf(s->path);
    const struct rlw_uncovered *listed =
        rlw_coverage_find_uncovered(s->path);

    char what[224];
    if (exercised && listed) {
        snprintf(what, sizeof(what),
                 "coverage: %s is exercised AND listed uncovered — pick "
                 "one", s->path);
        RLW_CHECK(what, false);
        return failures;
    }
    if (!exercised && !listed) {
        printf("    [%s] declared READ, takes `datadir`, and is in "
               "neither g_rlw_leaves nor g_rlw_uncovered\n", s->path);
        snprintf(what, sizeof(what),
                 "coverage: %s is accounted for (exercised or listed "
                 "with a reason)", s->path);
        RLW_CHECK(what, false);
        return failures;
    }
    if (listed) {
        (*uncovered_seen)++;
        /* An entry needs a stated reason. */
        snprintf(what, sizeof(what),
                 "coverage: %s is listed uncovered WITH a stated reason",
                 s->path);
        RLW_CHECK(what, listed->why != NULL && listed->why[0] != '\0');
        return failures;
    }
    /* Exercised: the pointer this file calls must be the pointer the
     * registry dispatches, or the case below proves a different leaf. */
    snprintf(what, sizeof(what),
             "coverage: %s is exercised through the registry's own "
             "handler pointer", s->path);
    RLW_CHECK(what, exercised->fn == s->handler);
    return failures;
}

static int t_registry_coverage(void)
{
    int failures = 0;
    const struct zcl_command_registry *reg = zcl_command_catalog();

    RLW_CHECK("coverage: the command catalog is readable",
              reg != NULL && reg->commands != NULL && reg->count > 0);
    if (!reg || !reg->commands)
        return failures;   /* RLW_CHECK above already counted this */

    int derived = 0, uncovered_seen = 0;
    for (size_t i = 0; i < reg->count; i++) {
        const struct zcl_command_spec *s = &reg->commands[i];
        if (!rlw_is_datadir_read_leaf(s))
            continue;
        derived++;
        failures += rlw_coverage_check_command(s, &uncovered_seen);
    }

    printf("    derived=%d exercised_table=%d uncovered_table=%d "
           "uncovered_matched=%d\n",
           derived, RLW_LEAF_COUNT, RLW_UNCOVERED_COUNT, uncovered_seen);

    /* Anti-vacuous: an empty or unlinked catalog would pass every check. */
    {
        char what[192];
        snprintf(what, sizeof(what),
                 "coverage: %d READ leaves take a datadir (floor %d) — the "
                 "population is real", derived, RLW_DERIVED_FLOOR);
        RLW_CHECK(what, derived >= RLW_DERIVED_FLOOR);
    }

    /* Every table entry must name a leaf that still exists and is a
     * datadir READ leaf. */
    for (int j = 0; j < RLW_LEAF_COUNT; j++) {
        bool found = false;
        for (size_t i = 0; i < reg->count && !found; i++)
            found = rlw_is_datadir_read_leaf(&reg->commands[i]) &&
                    strcmp(reg->commands[i].path, g_rlw_leaves[j].path) == 0;
        char what[224];
        snprintf(what, sizeof(what),
                 "coverage: exercised leaf %s is still a READ leaf taking a "
                 "datadir", g_rlw_leaves[j].path);
        RLW_CHECK(what, found);
    }
    {
        char what[192];
        snprintf(what, sizeof(what),
                 "coverage: every uncovered line matched a live leaf "
                 "(%d/%d)", uncovered_seen, RLW_UNCOVERED_COUNT);
        RLW_CHECK(what, uncovered_seen == RLW_UNCOVERED_COUNT);
    }

    /* SHRINK-ONLY. Covering a leaf deletes a line; nothing may add one. */
    {
        char what[192];
        snprintf(what, sizeof(what),
                 "coverage: uncovered list is %d, at or under its "
                 "shrink-only ceiling of %d",
                 RLW_UNCOVERED_COUNT, RLW_UNCOVERED_MAX);
        RLW_CHECK(what, RLW_UNCOVERED_COUNT <= RLW_UNCOVERED_MAX);
    }

    return failures;
}

int test_read_leaf_no_datadir_write(void)
{
    printf("\n=== read leaf writes nothing to the datadir ===\n");
    int failures = 0;

    failures += t_registry_coverage();
    failures += t_absent_node_db_is_not_created();
    failures += t_present_node_db_is_not_mutated();
    failures += t_foreign_node_db_gets_no_schema();
    failures += t_garbage_node_db_is_not_quarantined();
    failures += t_garbage_node_db_is_refused_not_empty();
    failures += t_wal_datadir_file_set_is_unchanged();
    failures += t_wal_datadir_with_live_writer();
    failures += t_wal_snapshot_writer_arrives_after_open();

    return failures;
}
