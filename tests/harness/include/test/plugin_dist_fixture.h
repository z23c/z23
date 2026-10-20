/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * purpose: Shared fixture for the plugin distribution tests (plugin_dist and
 *          plugin_fetch_job): two isolated swarm nodes, a packed demo plugin,
 *          a publish and a pumped transfer between them. */
#ifndef ZCL_TEST_PLUGIN_DIST_FIXTURE_H
#define ZCL_TEST_PLUGIN_DIST_FIXTURE_H

#include "test/test_core.h"
#include "test/test_zcode_swarm_priv.h"
#include "plugin/plugin_dist.h"
#include "plugin/plugin_pack.h"
#include "plugin/plugin_store.h"

#define PD_CAP (4u * VCS_PACKAGE_CHUNK_BYTES)

struct pd_fixture {
    struct sw_node publisher, receiver;
    char base[1024], signing[1200], release_key[1200], license[1200];
    char plugins[1200], scratch[1200], pub_plugins[1200];
    char public_key[65];
    bool ready;
};

bool pd_path(char *out, size_t cap, const char *base, const char *leaf);
bool pd_write(const char *path, const char *bytes, size_t len, mode_t mode);
bool pd_keys(const char *dir, const char *key);
bool pd_open(struct pd_fixture *f);
void pd_close(struct pd_fixture *f);
bool pd_pack(struct pd_fixture *f, const char *leaf, const char *version,
             struct plugin_pack_result *packed);
enum plugin_dist_status pd_publish(struct pd_fixture *f, const char *leaf,
                                   uint64_t sequence, struct plugin_dist_published *out);
bool pd_pump_tick(struct pd_fixture *f, uint64_t now, unsigned limit, unsigned *replies,
                  bool *stopped);
/* Register the peer handles on both engines (receiver sees the publisher as 11). */
bool pd_peers(struct pd_fixture *f);
bool pd_transfer_start(struct pd_fixture *f, const uint8_t root[32]);
bool pd_transfer(struct pd_fixture *f, const uint8_t root[32], unsigned limit, bool first);
bool pd_selection(const struct pd_fixture *f, const char *generation);
bool pd_generation_stored(const struct pd_fixture *f, const char *generation);
enum plugin_dist_status pd_receive(struct pd_fixture *f, const uint8_t root[32],
                                   const uint8_t *delivered, bool allow,
                                   struct plugin_dist_received *out);
bool pd_scratch_empty(const struct pd_fixture *f);

#endif
