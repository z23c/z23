/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Signed endpoint records at the composition root: the chain binding and
 * the discovery projection. See config/boot_endpoint_records.h.
 *
 * ── THE SEAM THAT IS DELIBERATELY LEFT OPEN ────────────────────────
 * A verified record carries clearnet address + port as well as an onion
 * hostname, and this file projects ONLY the onion half, because the
 * narrow discovery path (struct onion_peer) has nowhere to put an IP.
 * Feeding the clearnet half in as an addrman candidate is a real next
 * step and it is not built here: the only sanctioned way for a
 * directory to influence peer selection is addrman_publish_reputation_weights
 * (lib/net/src/addrman.c), bounded to a [1.0, 4.0] dial-chance
 * multiplier that structurally cannot exclude a peer, and wiring it is
 * its own slice with its own proof. The clearnet fields are carried,
 * verified, and unused — stated, not hidden. */

#include "config/boot_endpoint_records.h"
#include "config/boot_zcode_dht.h"

#include "config/runtime.h"

#include "models/zid_identity.h"

#include "encoding/utilstrencodings.h"
#include "json/json.h"
#include "platform/directory_compat.h"
#include "platform/positioned_file.h"
#include "platform/time_compat.h"
#include "supervisors/domains.h"
#include "util/supervisor.h"
#include "util/thread_registry.h"
#include "vcs/zendp_swarm.h"
#include "zid/zid.h"

#include "base/log_macros.h"

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define BER_LOG "boot.endpoint_records"

/* Bounded by the directory itself; a stack array of this size is one
 * page and the call is on the discovery path, never the hot path. */
#define BER_RECORDS_MAX ZENDP_DIR_MAX

/* A bound on the boot-time directory scan. The directory holds at most
 * ZENDP_DIR_MAX live identities, so reading further cannot install more
 * — this only stops a datadir full of stale files from turning start-up
 * into an unbounded walk. */
#define BER_SCAN_MAX 256

/* Map one zid_identities row to the anchor verdict. The ONE place a
 * projection row becomes a chain answer.
 *
 * Returning false means "the question could not be asked" (no node.db,
 * or a row whose status literal is not one this build knows). It never
 * means "no such identity" — that is a true return carrying
 * ZENDP_ANCHOR_ABSENT, and the two are reported by different names all
 * the way up. */
bool boot_endpoint_anchor_from_db(struct node_db *ndb,
                                  const uint8_t pubkey[32],
                                  struct zendp_anchor *out)
{
    if (!pubkey || !out)
        LOG_FAIL(BER_LOG, "anchor lookup: NULL argument (pk=%p out=%p)",
                 (const void *)pubkey, (void *)out);
    memset(out, 0, sizeof(*out));

    if (!ndb)
        LOG_FAIL(BER_LOG,
                 "anchor lookup: node.db is not open yet — the chain cannot "
                 "be asked, so no record may be treated as anchored");

    struct zid_identity row;
    if (!db_zid_identity_find(ndb, pubkey, &row)) {
        /* A legitimate negative answer, not a failure. */
        out->state = ZENDP_ANCHOR_ABSENT;
        return true;
    }

    out->anchor_height = row.anchor_height;
    out->updated_height = row.updated_height;
    if (strcmp(row.status, ZID_IDENTITY_STATUS_ACTIVE) == 0)
        out->state = ZENDP_ANCHOR_ACTIVE;
    else if (strcmp(row.status, ZID_IDENTITY_STATUS_ROTATED) == 0)
        out->state = ZENDP_ANCHOR_ROTATED;
    else if (strcmp(row.status, ZID_IDENTITY_STATUS_REVOKED) == 0)
        out->state = ZENDP_ANCHOR_REVOKED;
    else
        LOG_FAIL(BER_LOG,
                 "anchor lookup: identity row carries an unknown status '%s' "
                 "— refusing to guess a verdict",
                 row.status);
    return true;
}

/* The port's shape, over whichever node.db the process has. The mapping
 * itself is NOT repeated here — the running node reads the runtime
 * handle, the CLI opens its own read-only one, and both land on the one
 * implementation above. */
static bool boot_endpoint_anchor_lookup(void *ctx, const uint8_t pubkey[32],
                                        struct zendp_anchor *out)
{
    (void)ctx;
    return boot_endpoint_anchor_from_db(app_runtime_node_db(), pubkey, out);
}

void boot_endpoint_records_register(void)
{
    zendp_set_anchor_lookup(boot_endpoint_anchor_lookup, NULL);
}

/* ── loading filed records at start ────────────────────────────────── */

/* Read one <record_key>.zid file's hex into `wire`. Returns the byte
 * count, or 0 for anything malformed — a file that is not even-length
 * hex is not a record, and guessing at it is how a witness becomes an
 * authority. */
static size_t ber_read_record_file(const char *dir, const char *name,
                                   uint8_t *wire, size_t wire_size)
{
    struct platform_positioned_file file;
    struct platform_positioned_file_snapshot before, after;
    platform_positioned_file_init(&file);
    if (!platform_positioned_file_open_beneath(&file, dir, name))
        return 0;
    if (!platform_positioned_file_snapshot(&file, &before) ||
        before.size == 0 || before.size >= ZID_DOC_MAX * 2 + 2) {
        platform_positioned_file_close(&file);
        return 0;
    }
    char hex[ZID_DOC_MAX * 2 + 2];
    int64_t read = platform_positioned_file_read(
        &file, hex, (size_t)before.size, 0);
    bool stable = read == (int64_t)before.size &&
                  platform_positioned_file_snapshot(&file, &after) &&
                  before.size == after.size &&
                  before.modified_seconds == after.modified_seconds &&
                  before.modified_nanoseconds == after.modified_nanoseconds &&
                  before.changed_seconds == after.changed_seconds &&
                  before.changed_nanoseconds == after.changed_nanoseconds &&
                  before.volume == after.volume &&
                  before.file_low == after.file_low &&
                  before.file_high == after.file_high;
    platform_positioned_file_close(&file);
    if (!stable)
        return 0;
    size_t r = (size_t)read;
    while (r > 0 && (hex[r - 1] == '\n' || hex[r - 1] == '\r' ||
                     hex[r - 1] == ' '))
        r--;
    hex[r] = '\0';
    if (r == 0 || (r & 1) != 0 || !IsHex(hex))
        return 0;
    int decoded = ParseHex(hex, wire, wire_size);
    return decoded > 0 ? (size_t)decoded : 0;
}

int boot_endpoint_records_load(const char *datadir)
{
    if (!datadir || !datadir[0])
        return 0;

    char dir[1200];
    int n = snprintf(dir, sizeof(dir), "%s/zcode/endpoints", datadir);
    if (n <= 0 || (size_t)n >= sizeof(dir))
        LOG_RETURN(0, BER_LOG, "load: path too long under datadir");

    struct platform_directory_list files;
    if (!platform_directory_list_regular_sorted(dir, &files))
        return 0; /* No records filed yet — the common, non-error case. */

    struct zendp_directory *gdir = zendp_directory_global();
    uint64_t now = (uint64_t)platform_time_wall_unix();

    int installed = 0, discarded = 0, scanned = 0;
    for (size_t i = 0; i < files.count && scanned < BER_SCAN_MAX; ++i) {
        const char *name = files.entries[i].name;
        size_t len = strlen(name);
        /* <64 hex chars>.zid — anything else is not one of ours. */
        if (len != 68 || strcmp(name + 64, ".zid") != 0)
            continue;
        bool name_is_hex = true;
        for (size_t j = 0; j < 64; ++j)
            if (!((name[j] >= '0' && name[j] <= '9') ||
                  (name[j] >= 'a' && name[j] <= 'f') ||
                  (name[j] >= 'A' && name[j] <= 'F'))) {
                name_is_hex = false;
                break;
            }
        if (!name_is_hex) continue;
        scanned++;

        uint8_t wire[ZID_DOC_MAX];
        size_t wire_len = ber_read_record_file(dir, name, wire,
                                               sizeof(wire));
        if (wire_len == 0) {
            discarded++;
            LOG_WARN(BER_LOG,
                     "load: %s does not hold a well-formed record — "
                     "discarded", name);
            continue;
        }

        /* THE WHOLE PIPELINE, on the bytes that came off disk: decode,
         * signature, both validity windows, the ZIDE body tag, and the
         * chain. zendp_accept installs NOTHING unless every rung holds,
         * so a discarded record leaves no trace in the directory and
         * can never be projected to discovery. */
        enum zendp_result r =
            zendp_accept(gdir, wire, wire_len, now, NULL, NULL);
        if (r != ZENDP_OK) {
            discarded++;
            LOG_WARN(BER_LOG,
                     "load: discarded %s — %s. A record that does not "
                     "resolve to an ACTIVE on-chain identity is dropped, "
                     "not kept in a lesser state",
                     name, zendp_result_string(r));
            continue;
        }
        installed++;
    }
    platform_directory_list_free(&files);

    if (scanned > 0)
        LOG_INFO(BER_LOG,
                 "load: %d endpoint record(s) verified against the chain and "
                 "loaded, %d discarded (of %d filed)",
                 installed, discarded, scanned);
    return installed;
}

int boot_endpoint_record_peers(void *ctx, struct onion_peer *out, size_t max)
{
    (void)ctx;
    if (!out || max == 0)
        return 0;
    if (max > BER_RECORDS_MAX)
        max = BER_RECORDS_MAX;

    uint64_t now = (uint64_t)platform_time_wall_unix();

    struct zendp_record_view views[BER_RECORDS_MAX];
    size_t n = zendp_global_records(now, views, max);
    if (n == 0)
        return 0;

    /* Widen into the rich type (which carries the port, the services
     * bitmask, the expiry and the provenance), then narrow through the
     * one adapter, so the extra facts exist and are auditable even
     * though this path can only carry the hostname. */
    struct onion_endpoint eps[BER_RECORDS_MAX];
    int built = 0;
    for (size_t i = 0; i < n; i++) {
        const struct zendp_record_view *v = &views[i];
        struct onion_endpoint *ep = &eps[built];
        memset(ep, 0, sizeof(*ep));
        if (v->ep.flags & ZENDP_HAS_ONION)
            snprintf(ep->hostname, sizeof(ep->hostname), "%s", v->ep.onion);
        ep->onion_port = v->ep.onion_port;
        memcpy(ep->ipv4, v->ep.ipv4, sizeof(ep->ipv4));
        ep->ipv4_port = v->ep.ipv4_port;
        memcpy(ep->ipv6, v->ep.ipv6, sizeof(ep->ipv6));
        ep->ipv6_port = v->ep.ipv6_port;
        ep->services = v->ep.services;
        ep->height = (int)v->ep.height;
        ep->expiry = v->expiry;
        ep->seq = v->seq;
        memcpy(ep->master_pubkey, v->master_pubkey,
               sizeof(ep->master_pubkey));
        ep->anchor_height = v->anchor_height;
        ep->provenance = ONION_PROV_ANCHORED;
        built++;
    }

    int rejected = 0;
    int kept = onion_endpoints_to_peers(eps, built, out, max, now, &rejected);
    if (rejected > 0)
        LOG_WARN(BER_LOG,
                 "discovery: dropped %d endpoint record(s) with a malformed "
                 "or expired onion hostname (%d kept)", rejected, kept);
    return kept;
}

/* ── revalidation: a key revoked mid-run stops being advertised ─────
 *
 * See config/boot_endpoint_records.h for the whole contract. The two
 * facts that shape every line below:
 *
 *   1. The signal is a COUNTER THE FOLD BUMPS, and this end POLLS it.
 *      Nothing is pushed. A callback from the fold would run the sweep
 *      below — one node.db read per held identity — on the block-fold
 *      thread.
 *   2. The sweep runs on ITS OWN THREAD, never on the shared supervisor
 *      tick runner. That runner also drives onion_directory_tick, which
 *      reads the very directory the sweep writes; a blocking database
 *      read there is how this node has been SIGABRT'd by its own
 *      watchdog. boot_seniority.c is the in-tree precedent and this
 *      follows it exactly.
 */

/* How often the worker asks whether an identity status changed. The
 * question is one atomic load; only a moved counter costs a database
 * read. Short because a revoked key should stop being advertised in
 * seconds, not minutes. */
#define BER_REVAL_POLL_SECS 5

/* Heartbeat deadline. The sweep reads node.db and can queue behind a
 * fold commit, which runs 120-330 s at tip on this chain — so a slow
 * pass is a busy node, not a wedged worker. Well above that, so a
 * TIME_DEADLINE stall means something is actually wrong. */
#define BER_REVAL_DEADLINE_SECS 600

/* NO_PROGRESS quiet window. Between status changes the worker reports
 * itself idle every poll, which refreshes this clock without moving the
 * marker — so quiet only accumulates while a status change is PENDING
 * AND UNRESOLVABLE (records held that the chain cannot be asked about).
 * Fifteen minutes of that is a defect worth a named blocker. */
#define BER_REVAL_MAX_QUIET_US (15 * 60 * 1000000LL)

/* The generation this node has already acted on. Starts at 0, which is
 * also the counter's start: a node that has folded no status change
 * since boot has nothing to re-derive, because the boot load already
 * checked every record against the chain. */
static _Atomic uint64_t g_reval_applied_gen;
static _Atomic uint64_t g_reval_sweeps;        /* the progress marker */
static _Atomic uint64_t g_reval_dropped;       /* records invalidated */
static _Atomic uint64_t g_reval_checked;       /* definitive answers seen */
static _Atomic uint64_t g_reval_unavailable;   /* passes the chain refused */
static _Atomic int64_t  g_reval_last_us;       /* monotonic-us of last sweep */
static _Atomic bool     g_reval_running;
static _Atomic supervisor_child_id g_reval_sup_id = SUPERVISOR_INVALID_ID;
static struct liveness_contract g_reval_contract;

enum boot_endpoint_reval_outcome boot_endpoint_records_revalidate_once(void)
{
    /* Read the counter BEFORE the sweep and record THAT value after it,
     * so a status change folded while the sweep was running leaves the
     * generations unequal and is re-derived on the next pass rather than
     * being swallowed. */
    const uint64_t gen = zid_identity_status_generation();
    if (gen == atomic_load(&g_reval_applied_gen))
        return BOOT_ENDPOINT_REVAL_IDLE;

    struct zendp_revalidation tally;
    memset(&tally, 0, sizeof(tally));
    enum zendp_result r = zendp_global_revalidate(&tally);

    atomic_fetch_add(&g_reval_checked, (uint64_t)tally.checked);
    atomic_fetch_add(&g_reval_dropped, (uint64_t)tally.dropped);
    atomic_store(&g_reval_last_us, platform_time_monotonic_us());

    if (r != ZENDP_OK) {
        /* At least one held identity could not be resolved. The applied
         * generation is deliberately NOT advanced: the change is still
         * pending, and the next pass retries it. */
        atomic_fetch_add(&g_reval_unavailable, 1);
        LOG_WARN(BER_LOG,
                 "revalidate: %d held record(s) could not be resolved against "
                 "the chain (%s) — left in place and retried; a record is "
                 "never dropped on a non-answer",
                 tally.unavailable, zendp_result_string(r));
        return BOOT_ENDPOINT_REVAL_UNAVAILABLE;
    }

    atomic_store(&g_reval_applied_gen, gen);
    atomic_fetch_add(&g_reval_sweeps, 1);
    (void)boot_zcode_dht_revalidate();
    return BOOT_ENDPOINT_REVAL_APPLIED;
}

static void *ber_reval_worker_main(void *arg)
{
    (void)arg;
    supervisor_child_id id = atomic_load(&g_reval_sup_id);

    while (atomic_load(&g_reval_running) &&
           !thread_registry_shutdown_requested()) {
        switch (boot_endpoint_records_revalidate_once()) {
        case BOOT_ENDPOINT_REVAL_IDLE:
            /* POSITIVELY established there is no work: no identity status
             * has been folded since the last applied sweep, so every
             * recorded verdict is still the chain's current answer.
             * Refreshes the quiet clock without moving the marker. */
            supervisor_progress_idle(id);
            break;
        case BOOT_ENDPOINT_REVAL_APPLIED:
            supervisor_progress(id, (int64_t)atomic_load(&g_reval_sweeps));
            break;
        case BOOT_ENDPOINT_REVAL_UNAVAILABLE:
            /* Report NEITHER progress NOR idle. A status change this node
             * knows about and cannot resolve is exactly the state
             * NO_PROGRESS exists to catch; calling it idle would rebuild
             * the silent stall this whole slice is here to remove. */
            break;
        }
        supervisor_tick(id);

        for (int i = 0; i < BER_REVAL_POLL_SECS &&
                        atomic_load(&g_reval_running) &&
                        !thread_registry_shutdown_requested(); i++) {
            struct timespec ts = { .tv_sec = 1, .tv_nsec = 0 };
            nanosleep(&ts, NULL);
        }
    }
    return NULL;
}

void boot_endpoint_records_start_revalidation(void)
{
    if (atomic_load(&g_reval_running))
        return;

    liveness_contract_init(&g_reval_contract, "net.endpoint_revalidate");
    /* period_secs 0: the worker heartbeats itself. It must not be driven
     * by the shared tick runner — the sweep reads node.db, and the same
     * runner drives the discovery projection that reads this directory. */
    atomic_store(&g_reval_contract.period_secs, (int64_t)0);
    atomic_store(&g_reval_contract.deadline_secs,
                 (int64_t)BER_REVAL_DEADLINE_SECS);
    g_reval_contract.on_tick = NULL;
    g_reval_contract.on_stall = NULL;
    supervisor_domains_init();
    supervisor_child_id id =
        supervisor_register_in_domain(g_net_sup, &g_reval_contract);
    atomic_store(&g_reval_sup_id, id);
    if (id == SUPERVISOR_INVALID_ID) {
        LOG_WARN(BER_LOG,
                 "revalidation: supervisor register failed; a key revoked "
                 "mid-run would keep being advertised until its record "
                 "expires — not starting unsupervised");
        return;
    }
    supervisor_tick(id);
    /* Count RESULTS: one applied sweep per resolved status change. While
     * nothing changes the worker reports idle, so a frozen marker means a
     * change is pending AND failing, never merely "nothing to do". Armed
     * AFTER register so the child id is valid. */
    supervisor_set_progress_max_quiet(id, BER_REVAL_MAX_QUIET_US);
    supervisor_progress(id, (int64_t)atomic_load(&g_reval_sweeps));

    atomic_store(&g_reval_running, true);
    /* supervised:net.endpoint_revalidate */
    int rc = thread_registry_spawn("zcl_endp_reval", ber_reval_worker_main,
                                   NULL, NULL);
    if (rc != 0) {
        atomic_store(&g_reval_running, false);
        supervisor_child_complete(id);
        LOG_WARN(BER_LOG,
                 "revalidation: worker spawn failed (%d); accepted records "
                 "keep their boot-time chain verdict until restart", rc);
    }
}

bool boot_endpoint_records_dump_state_json(struct json_value *out,
                                           const char *key)
{
    (void)key;
    if (!out)
        LOG_FAIL(BER_LOG, "dump_state_json: out is NULL");
    json_set_object(out);

    struct zid_identity_status_signal sig;
    zid_identity_status_signal_read(&sig);
    const uint64_t applied = atomic_load(&g_reval_applied_gen);

    /* The signal, and whether this node has caught up with it. */
    json_push_kv_int(out, "identity_status_generation",
                     (int64_t)sig.generation);
    json_push_kv_int(out, "identity_status_last_height", sig.last_height);
    json_push_kv_int(out, "revalidated_generation", (int64_t)applied);
    json_push_kv_bool(out, "revalidation_pending", sig.generation != applied);

    /* What the worker has actually achieved, separated from whether it ran. */
    json_push_kv_bool(out, "worker_running", atomic_load(&g_reval_running));
    json_push_kv_int(out, "sweeps_applied",
                     (int64_t)atomic_load(&g_reval_sweeps));
    json_push_kv_int(out, "records_invalidated",
                     (int64_t)atomic_load(&g_reval_dropped));
    json_push_kv_int(out, "identities_checked",
                     (int64_t)atomic_load(&g_reval_checked));
    json_push_kv_int(out, "chain_unavailable_passes",
                     (int64_t)atomic_load(&g_reval_unavailable));

    const int64_t last_us = atomic_load(&g_reval_last_us);
    json_push_kv_int(out, "last_sweep_age_us",
                     last_us > 0 ? platform_time_monotonic_us() - last_us : -1);

    /* How many records the discovery projection would offer right now.
     * A locked in-memory snapshot — no database read on the reader's
     * thread, whichever thread that turns out to be. */
    struct zendp_record_view views[BER_RECORDS_MAX];
    json_push_kv_int(out, "records_projected",
                     (int64_t)zendp_global_records(
                         (uint64_t)platform_time_wall_unix(), views,
                         BER_RECORDS_MAX));
    json_push_kv_bool(out, "anchor_lookup_registered",
                      zendp_anchor_lookup_registered());
    return true;
}
