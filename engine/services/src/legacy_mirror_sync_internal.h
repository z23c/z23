#ifndef ZCL_LEGACY_MIRROR_SYNC_INTERNAL_H
#define ZCL_LEGACY_MIRROR_SYNC_INTERNAL_H

#include "services/legacy_mirror_sync_service.h"
#include "rpc/zclassicd_port.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define LMS_DEFAULT_HOST       "127.0.0.1"
#define LMS_DEFAULT_CADENCE    3
#define LMS_DEFAULT_MAX_BLOCKS 64
#define LMS_DEFAULT_LAG_SLA    1
#define LMS_DEFAULT_LAG_SLA_BREACH_BLOCKS   10
#define LMS_DEFAULT_LAG_SLA_BREACH_SECS     60
#define LMS_DEFAULT_LAG_SLA_CRITICAL_BLOCKS 100
#define LMS_DEFAULT_LAG_SLA_CRITICAL_SECS   300

struct legacy_mirror_sync_runtime {
    pthread_mutex_t lock;
    pthread_mutex_t flight;
    bool initialized;
    bool enabled;
    char rpc_host[64];
    int  rpc_port;
    char rpc_user[64];
    char rpc_password[128];
    int  cadence_secs;
    int  max_blocks_tick;
    int  lag_sla;
    /* SLA thresholds: written under g_lms.lock by init/reload_from_env,
     * read lock-free by lms_evaluate_lag_slo (catchup tick) and the
     * stats snapshot. _Atomic to make those cross-thread reads/writes
     * data-race-free. */
    _Atomic int lag_sla_breach_blocks;
    _Atomic int lag_sla_breach_secs;
    _Atomic int lag_sla_critical_blocks;
    _Atomic int lag_sla_critical_secs;
    _Atomic int64_t lag_breach_since;
    _Atomic int64_t lag_critical_since;
    _Atomic int lag_breach_emitted;
    _Atomic int lag_critical_emitted;
    char datadir[1024];
    struct main_state *ms;
    struct coins_view_cache *coins_tip;
    const struct chain_params *params;

    _Atomic int reachable;
    _Atomic int in_flight;
    _Atomic int legacy_height;
    _Atomic int legacy_headers;
    _Atomic int local_height;
    _Atomic int best_header_height;
    _Atomic int target_height;
    _Atomic int authority_rewind_target;
    _Atomic int csr_sqlite_rc;
    _Atomic int last_advanced_height;
    _Atomic int last_progress_blocks;
    _Atomic int stuck_height;
    _Atomic unsigned int stuck_status_flags;
    _Atomic int64_t stalls_total;
    _Atomic int64_t last_catchup;
    _Atomic int64_t last_attempt;
    _Atomic int64_t catchups_total;
    _Atomic int64_t rpc_errors;
    _Atomic int64_t blocks_applied;
    _Atomic int64_t headers_added;
    /* Protected by lock.  Tip hashes are sampled independently; comparison
     * fields are one coherent same-height observation. */
    char zclassic23_hash[65];
    char zclassicd_hash[65];
    bool comparison_known;
    bool comparison_hashes_agree;
    int comparison_height;
    int hash_disagreement_height;
    char comparison_zclassic23_hash[65];
    char comparison_zclassicd_hash[65];
    char stuck_reason[64];
    enum blocker_class last_blocker_class;
    char last_blocker_id[64];
    char csr_failure_reason[160];
    char last_error[160];
};

extern struct legacy_mirror_sync_runtime g_lms;

#ifdef ZCL_TESTING
extern bool g_lms_test_fake_running;
extern _Atomic int g_lms_test_catchup_enabled;
extern _Atomic int g_lms_test_catchup_result;
extern _Atomic int g_lms_test_catchup_clear_stuck;
extern _Atomic int g_lms_test_catchup_calls;
#endif

void lms_set_error(const char *msg);
int lms_env_int(const char *name, int fallback, int min, int max);
bool lms_env_disabled(void);
struct zcl_result lms_local_hash_at(int height, char out_hex[65]);
/* Remote getblockhash probe for the mirror divergence locator (check 6):
 * thin export of the static lms_fetch_hash. Counts RPC errors like every
 * other mirror RPC. */
struct zcl_result lms_remote_hash_at(int height, char out_hex[65]);
void lms_refresh_local_heights(int *out_local, int *out_header);
struct zcl_result lms_request_catchup_result_internal(const char *reason);

/* Trend-history write for one comparison outcome (parity_slo, see
 * legacy_mirror_sync_parity_trend.c). Best-effort: a missing/unopened
 * node.db is a silent no-op. `height` is the comparison height passed to
 * lms_cache_comparison (-1 when no common height was available yet);
 * `known`/`agree` mirror that call's own known/agree flags. */
void lms_record_parity_sample(int height, bool known, bool agree);

#endif /* ZCL_LEGACY_MIRROR_SYNC_INTERNAL_H */
