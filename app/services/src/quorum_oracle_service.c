// one-result-type-ok:json-dump-bool — E2 (one way out): the sole remaining
// Dump-state export: quorum_oracle_dump_state_json.
// introspection dumper. The dump convention (CLAUDE.md "Adding state
// introspection") mandates a bool return (false = couldn't populate), not
// struct zcl_result; every other fallible surface in this file already
// returns zcl_result.

/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Quorum oracle — see services/quorum_oracle_service.h for the contract.
 *
 * Today three sources are wired:
 *   - QO_SRC_LOCAL:     active_chain_at(height) → blockhash
 *   - QO_SRC_ZCLASSICD: zclassicd_oracle_probe(height)
 *   - QO_SRC_PEER:      recent zclassic23 peer header votes
 *
 * The verdict logic accepts arbitrary N — a future P2P source plugs in
 * without changing callers. */

#include "platform/time_compat.h"
#include "services/quorum_oracle_service.h"
#include "services/oracle_policy.h"
#include "services/zclassicd_oracle_service.h"

#include "chain/chain.h"
#include "core/uint256.h"
#include "controllers/wallet_helpers.h"
#include "json/json.h"
#include "util/log_macros.h"
#include "validation/chainstate.h"
#include "validation/main_state.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#define QO_DEFAULT_MIN_AGREE 2
#define QO_MAX_PEER_VOTES 64
#define QO_PEER_VOTE_TTL_SECS 1800

static struct {
    pthread_mutex_t lock;
    bool   initialized;
    int    min_agree;

    _Atomic int64_t total_probes;
    _Atomic int64_t total_matches;
    _Atomic int64_t total_splits;
    _Atomic int64_t total_no_data;
    _Atomic int     last_height;
    _Atomic int64_t last_probe_unix;
    _Atomic int     last_verdict;
    _Atomic int     last_agreeing_sources;
    char last_winning_hash[65];
    char last_split_a[65];
    char last_split_b[65];

    struct {
        bool present;
        uint32_t peer_id;
        int height;
        char hash_hex[65];
        int64_t unix_time;
    } peer_votes[QO_MAX_PEER_VOTES];
    size_t peer_vote_cursor;
} g_qo = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
};

static const char *qo_source_name(enum quorum_oracle_source s)
{
    switch (s) {
    case QO_SRC_LOCAL:     return "local";
    case QO_SRC_ZCLASSICD: return "zclassicd";
    case QO_SRC_PEER:      return "zclassic23_peer";
    default:               return "unknown";
    }
}

static const char *qo_verdict_name(enum quorum_oracle_verdict v)
{
    switch (v) {
    case QO_VERDICT_NO_DATA:      return "no_data";
    case QO_VERDICT_QUORUM_MATCH: return "quorum_match";
    case QO_VERDICT_QUORUM_SPLIT: return "quorum_split";
    default:                      return "unknown";
    }
}

static bool qo_hash_hex_valid(const char *hash_hex)
{
    if (!hash_hex || strlen(hash_hex) != 64)
        return false;
    for (int i = 0; i < 64; i++) {
        char c = hash_hex[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F')))
            return false;
    }
    return true;
}

void quorum_oracle_record_peer_header_vote(uint32_t peer_id,
                                           int height,
                                           const char hash_hex[65])
{
    if (peer_id == 0 || height < 0 || !qo_hash_hex_valid(hash_hex))
        return;
    if (!g_qo.initialized) quorum_oracle_init(NULL);

    pthread_mutex_lock(&g_qo.lock);
    size_t slot = QO_MAX_PEER_VOTES;
    for (size_t i = 0; i < QO_MAX_PEER_VOTES; i++) {
        if (g_qo.peer_votes[i].present &&
            g_qo.peer_votes[i].peer_id == peer_id) {
            slot = i;
            break;
        }
    }
    /* One slot is the latest accepted-header evidence for one peer. The old
     * per-(peer,height) ring let one chatty peer or a bounded historical
     * repair occupy every slot and evict unrelated peers long before the
     * advertised TTL. A lower page proves history availability, not a lower
     * current tip, and must neither downgrade nor refresh the live vote. */
    if (slot != QO_MAX_PEER_VOTES &&
        height < g_qo.peer_votes[slot].height) {
        pthread_mutex_unlock(&g_qo.lock);
        return;
    }
    if (slot == QO_MAX_PEER_VOTES) {
        slot = g_qo.peer_vote_cursor++ % QO_MAX_PEER_VOTES;
    }
    g_qo.peer_votes[slot].present = true;
    g_qo.peer_votes[slot].peer_id = peer_id;
    g_qo.peer_votes[slot].height = height;
    snprintf(g_qo.peer_votes[slot].hash_hex,
             sizeof(g_qo.peer_votes[slot].hash_hex), "%s", hash_hex);
    g_qo.peer_votes[slot].unix_time = (int64_t)platform_time_wall_time_t();
    pthread_mutex_unlock(&g_qo.lock);
}

void quorum_oracle_init(const struct quorum_oracle_config *cfg)
{
    pthread_mutex_lock(&g_qo.lock);
    if (g_qo.initialized) {
        pthread_mutex_unlock(&g_qo.lock);
        return;
    }
    g_qo.min_agree = (cfg && cfg->min_agree > 0)
                         ? cfg->min_agree : QO_DEFAULT_MIN_AGREE;
    g_qo.initialized = true;
    pthread_mutex_unlock(&g_qo.lock);
}

static void qo_probe_local(int height,
                            struct quorum_oracle_source_result *out)
{
    out->present = false;
    out->error = false;
    out->hash_hex[0] = '\0';
    out->peer_count = 0;
    struct main_state *ms = wallet_rpc_main_state();
    if (!ms) return;
    struct block_index *bi = active_chain_at(&ms->chain_active, height);
    if (!bi || !bi->phashBlock) return;
    uint256_get_hex(bi->phashBlock, out->hash_hex);
    out->present = true;
}

static void qo_probe_zclassicd(int height,
                                struct quorum_oracle_source_result *out)
{
    out->present = false;
    out->error = false;
    out->hash_hex[0] = '\0';
    struct zclassicd_oracle_probe_result r;
    if (!zclassicd_oracle_probe(height, &r).ok) return;
    if (r.error) {
        out->present = true;
        out->error = true;
        return;
    }
    if (r.their_hash[0] == '\0') return;
    snprintf(out->hash_hex, sizeof(out->hash_hex), "%s", r.their_hash);
    out->present = true;
}

static void qo_probe_peer(int height,
                          struct quorum_oracle_source_result *out)
{
    int best_count = 0;
    char best_hash[65] = {0};
    int64_t now = (int64_t)platform_time_wall_time_t();

    out->present = false;
    out->error = false;
    out->hash_hex[0] = '\0';

    pthread_mutex_lock(&g_qo.lock);
    for (size_t i = 0; i < QO_MAX_PEER_VOTES; i++) {
        if (!g_qo.peer_votes[i].present ||
            g_qo.peer_votes[i].height != height ||
            now - g_qo.peer_votes[i].unix_time > QO_PEER_VOTE_TTL_SECS)
            continue;
        int count = 0;
        for (size_t j = 0; j < QO_MAX_PEER_VOTES; j++) {
            if (!g_qo.peer_votes[j].present ||
                g_qo.peer_votes[j].height != height ||
                now - g_qo.peer_votes[j].unix_time > QO_PEER_VOTE_TTL_SECS)
                continue;
            if (strcasecmp(g_qo.peer_votes[i].hash_hex,
                           g_qo.peer_votes[j].hash_hex) == 0)
                count++;
        }
        if (count > best_count) {
            best_count = count;
            snprintf(best_hash, sizeof(best_hash), "%s",
                     g_qo.peer_votes[i].hash_hex);
        }
    }
    pthread_mutex_unlock(&g_qo.lock);

    if (best_count > 0) {
        out->present = true;
        out->peer_count = best_count;
        snprintf(out->hash_hex, sizeof(out->hash_hex), "%s", best_hash);
    }
}

struct zcl_result quorum_oracle_probe(int height, struct quorum_oracle_result *out)
{
    if (!out)
        return ZCL_ERR(-1, "quorum_oracle_probe: NULL out");
    if (height < 0)
        return ZCL_ERR(-2, "quorum_oracle_probe: negative height %d", height);
    memset(out, 0, sizeof(*out));
    out->height = height;

    if (!g_qo.initialized) quorum_oracle_init(NULL);

    qo_probe_local    (height, &out->by_source[QO_SRC_LOCAL]);
    qo_probe_zclassicd(height, &out->by_source[QO_SRC_ZCLASSICD]);
    qo_probe_peer     (height, &out->by_source[QO_SRC_PEER]);

    /* For each source, count how many sources (incl. itself) report the same
     * hash, so counts[i] is the size of source i's agreement group. The matrix
     * is symmetric (every group member carries the full group size), so
     * max(counts) is the largest agreeing group regardless of source order —
     * the property the min_agree gate below relies on. */
    int counts[QO_SRC_NUM] = {0};
    int total_with_hash = 0;
    for (int i = 0; i < QO_SRC_NUM; i++) {
        if (!out->by_source[i].present) continue;
        if (out->by_source[i].error) continue;
        if (out->by_source[i].hash_hex[0] == '\0') continue;
        total_with_hash++;
        for (int j = 0; j < QO_SRC_NUM; j++) {
            if (!out->by_source[j].present || out->by_source[j].error)
                continue;
            if (out->by_source[j].hash_hex[0] == '\0') continue;
            if (strcasecmp(out->by_source[i].hash_hex,
                           out->by_source[j].hash_hex) == 0) {
                counts[i]++;
            }
        }
    }

    int min_agree = g_qo.min_agree;
    int best_idx = -1, best_count = 0;
    for (int i = 0; i < QO_SRC_NUM; i++) {
        if (counts[i] > best_count) {
            best_count = counts[i];
            best_idx = i;
        }
    }

    atomic_fetch_add(&g_qo.total_probes, 1);
    atomic_store(&g_qo.last_height, height);
    atomic_store(&g_qo.last_probe_unix, (int64_t)platform_time_wall_time_t());

    if (total_with_hash == 0) {
        out->verdict = QO_VERDICT_NO_DATA;
        out->agreeing_sources = 0;
        atomic_store(&g_qo.last_verdict, out->verdict);
        atomic_store(&g_qo.last_agreeing_sources, 0);
        atomic_fetch_add(&g_qo.total_no_data, 1);
        return ZCL_OK;
    }
    if (best_count >= min_agree) {
        out->verdict = QO_VERDICT_QUORUM_MATCH;
        out->agreeing_sources = best_count;
        snprintf(out->winning_hash_hex, sizeof(out->winning_hash_hex),
                 "%s", out->by_source[best_idx].hash_hex);
        pthread_mutex_lock(&g_qo.lock);
        snprintf(g_qo.last_winning_hash, sizeof(g_qo.last_winning_hash),
                 "%s", out->winning_hash_hex);
        g_qo.last_split_a[0] = '\0';
        g_qo.last_split_b[0] = '\0';
        pthread_mutex_unlock(&g_qo.lock);
        atomic_store(&g_qo.last_verdict, out->verdict);
        atomic_store(&g_qo.last_agreeing_sources, best_count);
        atomic_fetch_add(&g_qo.total_matches, 1);
        return ZCL_OK;
    }

    /* Split. Find any two non-matching sources and feed their pair to
     * oracle_policy so the HALT/PANIC ladder engages. */
    out->verdict = QO_VERDICT_QUORUM_SPLIT;
    out->agreeing_sources = best_count;
    atomic_store(&g_qo.last_verdict, out->verdict);
    atomic_store(&g_qo.last_agreeing_sources, best_count);
    atomic_fetch_add(&g_qo.total_splits, 1);

    const char *a = NULL, *b = NULL;
    for (int i = 0; i < QO_SRC_NUM; i++) {
        if (!out->by_source[i].present || out->by_source[i].error)
            continue;
        if (out->by_source[i].hash_hex[0] == '\0') continue;
        if (!a) {
            a = out->by_source[i].hash_hex;
        } else if (strcasecmp(a, out->by_source[i].hash_hex) != 0) {
            b = out->by_source[i].hash_hex;
            break;
        }
    }
    if (a && b) {
        pthread_mutex_lock(&g_qo.lock);
        snprintf(g_qo.last_split_a, sizeof(g_qo.last_split_a), "%s", a);
        snprintf(g_qo.last_split_b, sizeof(g_qo.last_split_b), "%s", b);
        g_qo.last_winning_hash[0] = '\0';
        pthread_mutex_unlock(&g_qo.lock);
        oracle_policy_record_disagreement(height, a, b);
        LOG_INFO("quorum_oracle", "[quorum_oracle] split at h=%d: %s vs %s", height, a, b);
    }
    return ZCL_OK;
}

bool quorum_oracle_dump_state_json(struct json_value *out, const char *key)
{
    (void)key;
    if (!out) return false;
    json_set_object(out);
    json_push_kv_int(out, "min_agree", g_qo.min_agree);
    json_push_kv_int(out, "total_probes",
                     atomic_load(&g_qo.total_probes));
    json_push_kv_int(out, "total_matches",
                     atomic_load(&g_qo.total_matches));
    json_push_kv_int(out, "total_splits",
                     atomic_load(&g_qo.total_splits));
    json_push_kv_int(out, "total_no_data",
                     atomic_load(&g_qo.total_no_data));
    json_push_kv_int(out, "last_height",
                     atomic_load(&g_qo.last_height));
    json_push_kv_int(out, "last_probe_unix",
                     atomic_load(&g_qo.last_probe_unix));
    json_push_kv_str(out, "last_verdict",
                     qo_verdict_name((enum quorum_oracle_verdict)
                         atomic_load(&g_qo.last_verdict)));
    json_push_kv_int(out, "last_agreeing_sources",
                     atomic_load(&g_qo.last_agreeing_sources));
    pthread_mutex_lock(&g_qo.lock);
    if (g_qo.last_winning_hash[0])
        json_push_kv_str(out, "last_winning_hash", g_qo.last_winning_hash);
    if (g_qo.last_split_a[0] || g_qo.last_split_b[0]) {
        struct json_value split = {0};
        json_set_object(&split);
        json_push_kv_str(&split, "hash_a", g_qo.last_split_a);
        json_push_kv_str(&split, "hash_b", g_qo.last_split_b);
        json_push_kv(out, "last_split", &split);
        json_free(&split);
    }
    int64_t now = (int64_t)platform_time_wall_time_t();
    int live_peer_votes = 0;
    struct json_value peer_votes = {0};
    json_set_array(&peer_votes);
    for (size_t i = 0; i < QO_MAX_PEER_VOTES; i++) {
        if (g_qo.peer_votes[i].present &&
            now - g_qo.peer_votes[i].unix_time <= QO_PEER_VOTE_TTL_SECS) {
            live_peer_votes++;
            struct json_value pv = {0};
            json_set_object(&pv);
            json_push_kv_int(&pv, "source_id",
                             (int64_t)g_qo.peer_votes[i].peer_id);
            json_push_kv_str(&pv, "source_class", "zclassic23_peer");
            json_push_kv_int(&pv, "height", g_qo.peer_votes[i].height);
            json_push_kv_str(&pv, "hash", g_qo.peer_votes[i].hash_hex);
            json_push_kv_int(&pv, "ttl_age_seconds",
                             now - g_qo.peer_votes[i].unix_time);
            json_push_back(&peer_votes, &pv);
            json_free(&pv);
        }
    }
    pthread_mutex_unlock(&g_qo.lock);
    json_push_kv_int(out, "live_peer_votes", live_peer_votes);
    json_push_kv(out, "peer_votes", &peer_votes);
    json_free(&peer_votes);
    {
        struct json_value sources = {0};
        json_set_array(&sources);
        for (int i = 0; i < QO_SRC_NUM; i++) {
            struct json_value src = {0};
            json_set_object(&src);
            json_push_kv_int(&src, "id", i);
            json_push_kv_str(&src, "source_class",
                             qo_source_name((enum quorum_oracle_source)i));
            json_push_kv_str(&src, "status", "wired");
            json_push_back(&sources, &src);
            json_free(&src);
        }
        json_push_kv(out, "sources", &sources);
        json_free(&sources);
    }
    /* Source roster (advertises future expansion). */
    json_push_kv_str(out, "source_local",     "wired");
    json_push_kv_str(out, "source_zclassicd", "wired");
    json_push_kv_str(out, "source_peer",      "wired");
    return true;
}

#ifdef ZCL_TESTING
void quorum_oracle_peer_votes_reset_for_test(void)
{
    pthread_mutex_lock(&g_qo.lock);
    memset(g_qo.peer_votes, 0, sizeof(g_qo.peer_votes));
    g_qo.peer_vote_cursor = 0;
    pthread_mutex_unlock(&g_qo.lock);
}
#endif
