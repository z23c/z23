/* purpose: schedule verified UTXO mirror rewind recovery without rebuild storms. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#include "platform/time_compat.h"
#include "services/utxo_mirror_sync_service.h"
#include "support/log_throttle.h"
#include "util/log_macros.h"

#define MIRROR_REWIND_WINDOW_MS INT64_C(60000)

void utxo_mirror_rewind_request_if_due(struct utxo_mirror_sync_service *svc)
{
    if (!atomic_load(&svc->thread_started) || atomic_load(&svc->stop_requested))
        return;
    int64_t now = platform_time_monotonic_ms();
    if (now <= 0) {
        LOG_WARN("utxo_mirror", "rewind rebuild refused: monotonic clock unavailable");
        return;
    }
    int64_t last = atomic_load(&svc->auto_rewind_last_ms);
    for (;;) {
        if (last && (now < last || now - last < MIRROR_REWIND_WINDOW_MS)) {
            static struct log_throttle throttle = LOG_THROTTLE_INIT;
            uint64_t reps = 0;
            if (log_throttle_should_emit(&throttle, 1, now / 1000, 60, &reps))
                LOG_WARN("utxo_mirror",
                         "rewind rebuild throttled; mirror remains quarantined (repeats=%llu)",
                         (unsigned long long)reps);
            return;
        }
        if (atomic_compare_exchange_weak(&svc->auto_rewind_last_ms, &last, now))
            break;
    }
    if (utxo_mirror_rebuild_request(svc, NULL) != 0)
        (void)atomic_compare_exchange_strong(&svc->auto_rewind_last_ms, &now, last);
}
