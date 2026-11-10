/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0
 * purpose: Share the existing Tor control connection within the integration module. */
#ifndef ZCL_TOR_INTEGRATION_PRIV_H
#define ZCL_TOR_INTEGRATION_PRIV_H
#include "platform/socket_compat.h"
#include "util/thread_liveness.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

extern _Atomic bool g_tor_running;
extern platform_socket_t g_tor_control, g_tor_control_peer;
extern struct thread_liveness_child g_tor_monitor_liveness;
extern _Atomic uint64_t g_tor_monitor_poll_count;
extern _Atomic int64_t g_claim_ms, g_network_enabled_ms, g_enable_retry_ms;
extern _Atomic unsigned g_enable_failures;
#if defined(ZCL_TESTING) && !defined(_WIN32)
#include <sys/stat.h>
extern struct stat g_tor_control_peer_id;
#endif

typedef struct tor_main_configuration_t tor_main_configuration_t;
extern tor_main_configuration_t *tor_main_configuration_new(void);
extern int tor_main_configuration_set_command_line(
    tor_main_configuration_t *cfg, int argc, char *argv[]);
extern void tor_main_configuration_free(tor_main_configuration_t *cfg);
extern int tor_run_main(const tor_main_configuration_t *);

/* Tor retains argv and its strings until configuration_free. */
struct tor_launch_config {
    tor_main_configuration_t *configuration;
    char owner_fd[32];
    char *argv[8];
};
void tor_launch_config_init(struct tor_launch_config *launch, char *torrc_path,
                            bool private_defaults, bool has_owner, platform_socket_t owner);

bool tor_is_linked(void);

int64_t tor_wall_ms(void);
bool tor_control_open(void);
void tor_request_exit(void);
int tor_bootstrap_query(void);
bool tor_control_exchange(const char *cmd, char *reply, size_t reply_size);
const char *tor_control_enable(void);
bool tor_enable_network(void);
#endif
