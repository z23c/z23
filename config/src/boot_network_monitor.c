/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * boot glue for the network-observability maintenance services — see
 * config/boot_network_monitor.h. Adapts network_monitor_start/stop AND
 * network_crawler_start/stop to the service-kernel start/stop contract and
 * registers each as an OPTIONAL maintenance service. Kept out of boot.c so the
 * boot service table stays under the file-size ceiling. */

#include "config/boot_network_monitor.h"

#include "kernel/service_kernel.h"
#include "models/database.h"
#include "net/connman.h"
#include "services/network_monitor.h"
#include "services/mesh_observation.h"
#include "services/network_crawler.h"
#include "services/sync_monitor.h"
#include "util/result.h"

#include <stdio.h>

static bool boot_network_monitor_service_start(void *ctx)
{
    struct node_db *db = ctx;
    struct network_monitor_config cfg;
    network_monitor_config_defaults(&cfg);
    struct zcl_result nr =
        network_monitor_start(&cfg, db && db->open ? db : NULL);
    if (nr.ok) {
        printf("Network monitor started (interval=%ds retain=%d rows)\n",
               cfg.sample_interval_secs, cfg.retain_rows);
        return true;
    }
    fprintf(stderr, "[boot] %s:%d network_monitor_start failed: code=%d %s\n",
            nr.source_file, nr.source_line, nr.code, nr.message);
    return false;
}

static void boot_network_monitor_service_stop(void *ctx)
{
    (void)ctx;
    network_monitor_stop();
}

bool boot_register_network_monitor_service(struct zcl_service_kernel *k,
                                           struct node_db *db)
{
    const struct zcl_service_spec spec = {
        .name = "network_monitor",
        .start = boot_network_monitor_service_start,
        .stop = boot_network_monitor_service_stop,
        .ctx = db,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(k, &spec);
}

/* ── network crawler (whole-network observatory) ─────────────────────────
 *
 * By the time maintenance services start (SERVICES_RUNNING boot stage),
 * NETWORK_READY has already run app_init_services -> sync_monitor_set_context,
 * so sync_monitor_connman() is populated here. The crawler only READs the
 * address table it is seeded with. */

static bool boot_network_crawler_service_start(void *ctx)
{
    (void)ctx;
    struct connman *cm = sync_monitor_connman();
    struct addr_man *am = cm ? connman_addrman(cm) : NULL;
    /* A NULL addrman is not a boot failure: the crawler worker still registers
     * and idles (each round no-ops on a NULL address table), naming the
     * degradation instead of stopping the node. Pass NULL cfg so the crawler
     * builds its own defaults and applies the -netcrawl / ZCL_NETWORK_CRAWLER
     * opt-out itself, then logs its real enabled/idle state. */
    struct zcl_result nr = network_crawler_start(NULL, am);
    if (nr.ok) {
        printf("Network crawler registered (seed_addrman=%s)\n",
               am ? "wired" : "none-yet");
        return true;
    }
    fprintf(stderr, "[boot] %s:%d network_crawler_start failed: code=%d %s\n",
            nr.source_file, nr.source_line, nr.code, nr.message);
    return false;
}

static void boot_network_crawler_service_stop(void *ctx)
{
    (void)ctx;
    network_crawler_stop();
}

bool boot_register_network_crawler_service(struct zcl_service_kernel *k)
{
    const struct zcl_service_spec spec = {
        .name = "network_crawler",
        .start = boot_network_crawler_service_start,
        .stop = boot_network_crawler_service_stop,
        .ctx = NULL,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(k, &spec);
}

/* ── mesh observation surface (services/mesh_observation.h) ──────────────
 *
 * The node's own OBSERVATION record plus the reader-side collector. It
 * publishes what this box saw and recomputes what other boxes published; it
 * pronounces nothing, gates nothing, and feeds no watchdog. OPTIONAL like
 * its neighbours: a node with the surface off still validates and still
 * follows the most-work valid-PoW chain, it just cannot corroborate. */

static bool boot_mesh_observation_service_start(void *ctx)
{
    (void)ctx;
    struct zcl_result sampler = mesh_observation_register_sampler();
    struct zcl_result collector = mesh_observation_collect_register();
    if (!sampler.ok)
        fprintf(stderr, "[boot] %s:%d mesh_observation sampler: code=%d %s\n",
                sampler.source_file, sampler.source_line, sampler.code,
                sampler.message);
    if (!collector.ok)
        fprintf(stderr, "[boot] %s:%d mesh_observation collector: code=%d %s\n",
                collector.source_file, collector.source_line, collector.code,
                collector.message);
    printf("Mesh observation surface (sampler=%s collector=%s)\n",
           sampler.ok ? "running" : "declined",
           collector.ok ? "running" : "declined");
    /* A declined worker is NAMED above, never silently treated as running,
     * and it is not a boot failure: this surface reports, so its absence
     * costs coverage and nothing else. */
    return true;
}

static void boot_mesh_observation_service_stop(void *ctx)
{
    (void)ctx;
    mesh_observation_collect_unregister();
    mesh_observation_unregister_sampler();
}

bool boot_register_mesh_observation_service(struct zcl_service_kernel *k)
{
    const struct zcl_service_spec spec = {
        .name = "mesh_observation",
        .start = boot_mesh_observation_service_start,
        .stop = boot_mesh_observation_service_stop,
        .ctx = NULL,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
    return zcl_service_kernel_register(k, &spec);
}

/* ── one registrar for the network-observability family ──────────────────
 *
 * The three services above are the file's whole subject; registering them
 * one call at a time from boot.c only spread that fact across the boot
 * table. This is the seam the file was extracted along, so boot.c names the
 * family and this file owns the members. */
bool boot_register_network_observability_services(struct zcl_service_kernel *k,
                                                  struct node_db *db)
{
    return boot_register_network_monitor_service(k, db) &&
           boot_register_network_crawler_service(k) &&
           boot_register_mesh_observation_service(k);
}
