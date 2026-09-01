/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "services/chain_evidence_persistence_service.h"

#include "config/runtime.h"
#include "models/database.h"
#include "platform/time_compat.h"
#include "util/log_macros.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CEC_RECORD_MAGIC 0x43454345u
#define CEC_RECORD_VERSION 2u
#define CEC_STATE_SET_RETRY_ATTEMPTS 8
#define CEC_STATE_SET_RETRY_BASE_MS 25

struct persisted_evidence_record {
    uint32_t magic;
    uint32_t version;
    uint32_t source_class;
    uint32_t publish_state;
    uint8_t header_ancestry_linked;
    uint8_t chainwork_recomputed;
    uint8_t nakamoto_selected_best_work;
    uint8_t block_bytes_hash_checked;
    uint8_t utxo_sha3_verified;
    uint8_t mmb_flyclient_proof_verified;
    uint8_t chunk_hash_coverage_verified;
    uint8_t full_validation_complete;
};

struct persisted_evidence_record_v1 {
    uint32_t magic;
    uint32_t version;
    uint8_t header_ancestry_linked;
    uint8_t chainwork_recomputed;
    uint8_t nakamoto_selected_best_work;
    uint8_t block_bytes_hash_checked;
    uint8_t utxo_sha3_verified;
    uint8_t mmb_flyclient_proof_verified;
    uint8_t chunk_hash_coverage_verified;
    uint8_t full_validation_complete;
};

static bool cec_retryable_sqlite_rc(int rc)
{
    return rc == SQLITE_BUSY || rc == SQLITE_LOCKED ||
           rc == SQLITE_ERROR || rc == SQLITE_MISUSE;
}

struct zcl_result chain_evidence_state_set_retry(struct node_db *ndb,
                                                 const char *key,
                                                 const void *value,
                                                 size_t len,
                                                 const char *owner)
{
    if (!ndb || !ndb->open) {
        LOG_WARN("cec.store",
                 "state_set_retry: unavailable ndb owner=%s key=%s",
                 owner ? owner : "(unknown)", key ? key : "(null)");
        return ZCL_ERR(-1, "state_set_retry: unavailable ndb owner=%s key=%s",
                       owner ? owner : "(unknown)", key ? key : "(null)");
    }
    if (!key || !value) {
        LOG_WARN("cec.store",
                 "state_set_retry: invalid input owner=%s key=%s value=%d",
                 owner ? owner : "(unknown)", key ? key : "(null)",
                 value != NULL);
        return ZCL_ERR(-2,
                       "state_set_retry: invalid input owner=%s key=%s value=%d",
                       owner ? owner : "(unknown)", key ? key : "(null)",
                       value != NULL);
    }

    for (int i = 0; i < CEC_STATE_SET_RETRY_ATTEMPTS; i++) {
        if (app_runtime_node_db_state_set(ndb, key, value, len))
            return ZCL_OK;

        struct node_db_status st;
        node_db_get_status(ndb, &st);
        int rc = st.last_sqlite_rc;
        if (node_db_state_set_detached(ndb, key, value, len))
            return ZCL_OK;
        node_db_get_status(ndb, &st);
        rc = st.last_sqlite_rc;
        if (!cec_retryable_sqlite_rc(rc) ||
            i + 1 >= CEC_STATE_SET_RETRY_ATTEMPTS) {
            LOG_WARN("cec.store",
                     "state_set_retry: failed owner=%s key=%s "
                     "attempts=%d rc=%d op=%s err=%s",
                     owner ? owner : "(unknown)", key,
                     i + 1, rc, st.last_op[0] ? st.last_op : "(none)",
                     sqlite3_errstr(rc));
            return ZCL_ERR(-3,
                           "state_set_retry: failed owner=%s key=%s "
                           "attempts=%d rc=%d op=%s err=%s",
                           owner ? owner : "(unknown)", key,
                           i + 1, rc, st.last_op[0] ? st.last_op : "(none)",
                           sqlite3_errstr(rc));
        }
        platform_sleep_ms(CEC_STATE_SET_RETRY_BASE_MS * (i + 1));
    }
    LOG_WARN("cec.store",
             "state_set_retry: exhausted owner=%s key=%s",
             owner ? owner : "(unknown)", key);
    return ZCL_ERR(-4, "state_set_retry: exhausted owner=%s key=%s",
                   owner ? owner : "(unknown)", key);
}

struct zcl_result chain_evidence_state_set_int_retry(struct node_db *ndb,
                                                     const char *key,
                                                     int64_t value,
                                                     const char *owner)
{
    return chain_evidence_state_set_retry(ndb, key, &value, sizeof(value),
                                          owner);
}

static void evidence_to_persisted(const struct chain_evidence_record *in,
                                  struct persisted_evidence_record *out)
{
    memset(out, 0, sizeof(*out));
    out->magic = CEC_RECORD_MAGIC;
    out->version = CEC_RECORD_VERSION;
    if (!in)
        return;
    out->source_class = (uint32_t)in->source_class;
    out->publish_state = (uint32_t)in->publish_state;
    out->header_ancestry_linked = in->header_ancestry_linked ? 1 : 0;
    out->chainwork_recomputed = in->chainwork_recomputed ? 1 : 0;
    out->nakamoto_selected_best_work =
        in->nakamoto_selected_best_work ? 1 : 0;
    out->block_bytes_hash_checked = in->block_bytes_hash_checked ? 1 : 0;
    out->utxo_sha3_verified = in->utxo_sha3_verified ? 1 : 0;
    out->mmb_flyclient_proof_verified =
        in->mmb_flyclient_proof_verified ? 1 : 0;
    out->chunk_hash_coverage_verified =
        in->chunk_hash_coverage_verified ? 1 : 0;
    out->full_validation_complete = in->full_validation_complete ? 1 : 0;
}

static bool evidence_from_persisted(const void *buf, size_t len,
                                    struct chain_evidence_record *out)
{
    const struct persisted_evidence_record *p = buf;
    if (!buf || !out || len < sizeof(struct persisted_evidence_record_v1))
        return false;
    memset(out, 0, sizeof(*out));
    if (len == sizeof(struct persisted_evidence_record_v1)) {
        const struct persisted_evidence_record_v1 *v1 = buf;
        if (v1->magic != CEC_RECORD_MAGIC || v1->version != 1u)
            return false;
        out->publish_state = CEC_PUBLISH_LOCAL_EVIDENCE;
        out->header_ancestry_linked = v1->header_ancestry_linked != 0;
        out->chainwork_recomputed = v1->chainwork_recomputed != 0;
        out->nakamoto_selected_best_work =
            v1->nakamoto_selected_best_work != 0;
        out->block_bytes_hash_checked = v1->block_bytes_hash_checked != 0;
        out->utxo_sha3_verified = v1->utxo_sha3_verified != 0;
        out->mmb_flyclient_proof_verified =
            v1->mmb_flyclient_proof_verified != 0;
        out->chunk_hash_coverage_verified =
            v1->chunk_hash_coverage_verified != 0;
        out->full_validation_complete = v1->full_validation_complete != 0;
        if (out->utxo_sha3_verified &&
            out->mmb_flyclient_proof_verified &&
            out->chunk_hash_coverage_verified)
            out->source_class = CEC_SOURCE_CLASS_SNAPSHOT;
        else if (out->block_bytes_hash_checked)
            out->source_class = CEC_SOURCE_CLASS_NATIVE_P2P;
        return true;
    }
    if (len != sizeof(*p) ||
        p->magic != CEC_RECORD_MAGIC ||
        p->version != CEC_RECORD_VERSION)
        return false;

    out->source_class = (enum chain_evidence_source_class)p->source_class;
    out->publish_state = (enum chain_evidence_publish_state)p->publish_state;
    out->header_ancestry_linked = p->header_ancestry_linked != 0;
    out->chainwork_recomputed = p->chainwork_recomputed != 0;
    out->nakamoto_selected_best_work = p->nakamoto_selected_best_work != 0;
    out->block_bytes_hash_checked = p->block_bytes_hash_checked != 0;
    out->utxo_sha3_verified = p->utxo_sha3_verified != 0;
    out->mmb_flyclient_proof_verified =
        p->mmb_flyclient_proof_verified != 0;
    out->chunk_hash_coverage_verified =
        p->chunk_hash_coverage_verified != 0;
    out->full_validation_complete = p->full_validation_complete != 0;
    return true;
}

struct zcl_result chain_evidence_store_persist(
    struct chain_evidence_controller *authority,
    const char *key,
    const struct chain_evidence_record *evidence)
{
    struct persisted_evidence_record p;
    evidence_to_persisted(evidence, &p);
    /* Preserve the original decision exactly: success iff authority &&
     * authority->ndb && node_db_state_set(...) all held. Each failure now
     * carries a reason instead of a bare false. */
    if (!authority) {
        LOG_WARN("cec.store", "persist: null authority key=%s",
                 key ? key : "(null)");
        return ZCL_ERR(-1, "persist: null authority key=%s",
                       key ? key : "(null)");
    }
    if (!authority->ndb) {
        LOG_WARN("cec.store", "persist: null ndb key=%s",
                 key ? key : "(null)");
        return ZCL_ERR(-2, "persist: null ndb key=%s",
                       key ? key : "(null)");
    }
    struct zcl_result set_r = chain_evidence_state_set_retry(
        authority->ndb, key, &p, sizeof(p), "chain_evidence_store_persist");
    if (!set_r.ok) {
        LOG_WARN("cec.store", "persist: node_db_state_set failed key=%s reason=%s",
                 key ? key : "(null)", set_r.message);
        return set_r;
    }
    return ZCL_OK;
}

/* Load misses on a fresh/restored datadir are the common, expected case,
 * and chain_evidence_controller_snapshot issues 4 loads per call from the
 * health heartbeat, event controller, and `z23 dumpstate` — unthrottled that is
 * 4 identical WARNs per tick, forever. Throttle the WARN per key: log the
 * first miss, then at most once per 300s with the running miss count. The
 * typed ZCL_ERR(-3) result is always returned unchanged, so every caller
 * still receives a contextful error. Keys are a tiny fixed set of cec.*
 * singletons; if the table somehow fills, fail open to logging. */
#define CEC_MISS_LOG_SLOTS 8
#define CEC_MISS_LOG_PERIOD_SECS 300

static bool load_miss_should_log(const char *key, uint64_t *misses_out)
{
    static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
    static struct {
        char key[64];
        uint64_t misses;
        int64_t last_log_unix;
    } slots[CEC_MISS_LOG_SLOTS];
    const char *k = key ? key : "(null)";
    int64_t now = platform_time_wall_unix();
    int free_slot = -1;

    pthread_mutex_lock(&mu);
    for (int i = 0; i < CEC_MISS_LOG_SLOTS; i++) {
        if (slots[i].key[0] == '\0') {
            if (free_slot < 0)
                free_slot = i;
            continue;
        }
        if (strcmp(slots[i].key, k) == 0) {
            bool log = (now - slots[i].last_log_unix) >=
                       CEC_MISS_LOG_PERIOD_SECS;
            slots[i].misses++;
            *misses_out = slots[i].misses;
            if (log)
                slots[i].last_log_unix = now;
            pthread_mutex_unlock(&mu);
            return log;
        }
    }
    if (free_slot >= 0) {
        snprintf(slots[free_slot].key, sizeof(slots[free_slot].key),
                 "%s", k);
        slots[free_slot].misses = 1;
        slots[free_slot].last_log_unix = now;
        *misses_out = 1;
        pthread_mutex_unlock(&mu);
        return true;
    }
    /* Table full: unexpected for the fixed cec.* key set — fail open. */
    *misses_out = 0;
    pthread_mutex_unlock(&mu);
    return true;
}

struct zcl_result chain_evidence_store_load(struct node_db *ndb,
                                            const char *key,
                                            struct chain_evidence_record *out)
{
    struct persisted_evidence_record p;
    size_t len = 0;
    /* Reject null out before clearing caller storage; then load and parse.
     * Each branch reports why instead of returning a bare false. */
    if (!out) {
        LOG_WARN("cec.store", "load: null out key=%s", key ? key : "(null)");
        return ZCL_ERR(-1, "load: null out key=%s", key ? key : "(null)");
    }
    memset(out, 0, sizeof(*out));
    if (!ndb) {
        LOG_WARN("cec.store", "load: null ndb key=%s", key ? key : "(null)");
        return ZCL_ERR(-2, "load: null ndb key=%s", key ? key : "(null)");
    }
    if (!node_db_state_get(ndb, key, &p, sizeof(p), &len)) {
        /* Missing key is the common, expected case at boot; report it but
         * keep it diagnostic (out stays zeroed, exactly as before). The
         * WARN is per-key throttled; the typed error is not. */
        uint64_t misses = 0;
        if (load_miss_should_log(key, &misses))
            LOG_WARN("cec.store",
                     "load: node_db_state_get miss key=%s misses=%llu",
                     key ? key : "(null)", (unsigned long long)misses);
        return ZCL_ERR(-3, "load: node_db_state_get miss key=%s",
                       key ? key : "(null)");
    }
    if (!evidence_from_persisted(&p, len, out)) {
        LOG_WARN("cec.store",
                 "load: evidence_from_persisted rejected key=%s len=%zu",
                 key ? key : "(null)", len);
        return ZCL_ERR(-4,
                       "load: evidence_from_persisted rejected key=%s len=%zu",
                       key ? key : "(null)", len);
    }
    return ZCL_OK;
}

static bool block_evidence_key(const struct uint256 *hash,
                               char out[sizeof("cec.block_evidence.") + 64])
{
    char hex[65];
    if (!hash || !out)
        return false;
    uint256_get_hex(hash, hex);
    snprintf(out, sizeof("cec.block_evidence.") + 64,
             "cec.block_evidence.%s", hex);
    return true;
}

struct zcl_result chain_evidence_controller_mark_block_evidence(
    struct chain_evidence_controller *authority,
    const struct uint256 *block_hash,
    const struct chain_evidence_record *evidence)
{
    char key[sizeof("cec.block_evidence.") + 64];
    /* Same combined guard as before, now reporting which input was bad.
     * block_evidence_key only fails on the null checks already covered, so
     * the original combined `||` decision is preserved bit-for-bit. */
    if (!authority || !authority->ndb || !block_hash || !evidence ||
        !block_evidence_key(block_hash, key)) {
        LOG_WARN("cec.store",
                 "mark_block_evidence: bad args authority=%d ndb=%d "
                 "block_hash=%d evidence=%d",
                 authority != NULL, authority && authority->ndb,
                 block_hash != NULL, evidence != NULL);
        return ZCL_ERR(-1,
                       "mark_block_evidence: bad args authority=%d ndb=%d "
                       "block_hash=%d evidence=%d",
                       authority != NULL, authority && authority->ndb,
                       block_hash != NULL, evidence != NULL);
    }
    return chain_evidence_store_persist(authority, key, evidence);
}
