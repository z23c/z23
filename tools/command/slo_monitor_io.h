/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Host observers for the node SLO monitors: the loopback and legacy RPC
 * clients, systemd, procfs, disk usage and wall(1). The services in
 * services/slo_monitor.h stay pure over these. */

#ifndef ZCL_COMMAND_SLO_MONITOR_IO_H
#define ZCL_COMMAND_SLO_MONITOR_IO_H

#include "services/slo_monitor.h"

/* Instance table and thresholds, from the unit files and ZCL_SLO_* env. */
bool slo_io_probe_config(struct slo_probe_config *cfg);

/* Observers bound to the local host. `timeouts` come from ZCL_SLO_* env. */
const struct slo_probe_io *slo_io_probe(void);

/* Pager observers. The blocker snapshot is read from `canonical`. */
const struct slo_page_io *slo_io_page(const struct slo_instance *canonical);

/* Pager and judge thresholds from ZCL_SLO_* env; `now` honours ZCL_SLO_NOW. */
void slo_io_page_config(struct slo_page_config *cfg);
void slo_io_hold_config(struct slo_hold_config *cfg);

/* The pages file the judge reads (ZCL_SLO_PAGES_FILE or the ledger dir). */
bool slo_io_pages_path(char *out, size_t cap);

/* Pure helpers exposed for tests. */
bool slo_io_chain_parse(const char *raw, struct slo_chain_answer *out);
struct slo_opt slo_io_peer_count(const char *raw);
void slo_io_self_parse(const char *explorer_raw, const char *blocker_raw,
                       struct slo_self_report *out);
bool slo_io_epoch_parse(const char *text, int64_t *out);
bool slo_io_rss_parse(const char *status_text, int64_t *out_kb);

#endif /* ZCL_COMMAND_SLO_MONITOR_IO_H */
