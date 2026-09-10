/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Boot wiring for the optional zclassicd beta6 bootstrap snapshot server.
 *
 * Dormant by default. One flag arms it, with an environment fallback so a
 * service unit can set it without rewriting an argv line:
 *
 *   -beta6-bootstrap-source=<ABSOLUTE dir>   ZCL_BETA6_BOOTSTRAP_SOURCE
 *
 * That alone is the production path: the node advertises NODE_BOOTSTRAP and
 * answers the eight messages IN-BAND on its ordinary P2P peers, which is the
 * only place a stock beta6 client looks. A second, optional flag additionally
 * opens the legacy side listener, for hosts that want the service on its own
 * address:
 *
 *   -beta6-bootstrap-listen=<ip>:<port>      ZCL_BETA6_BOOTSTRAP_LISTEN
 *
 * With the source unset this service starts nothing and changes no behaviour: the
 * NODE_BOOTSTRAP bit stays unadvertised and the eight beta6 messages stay
 * unanswered, exactly as before. Arming SHA-256-hashes the whole serve tree
 * once, here at boot, so no request path ever hashes; a failure is named and
 * degrades the node rather than stopping it.
 *
 * The listen address is deliberately explicit rather than defaulted: this
 * service exists to answer strangers, and an operator should have to say which
 * interface it answers on.
 */

#include "config/boot_internal.h"
#include "services/beta6_bootstrap.h"
#include "chain/chainparams.h"
#include "net/msgprocessor.h"
#include "base/log_macros.h"
#include "util/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A flag's value from argv, else its environment fallback, else "".
 *
 * The caller passes the already-read environment value rather than its name so
 * the getenv("ZCL_...") text stays at the call site, where the closed flag
 * catalog (tools/lint/lintc/gate_flag_registry.c) can see which flags this
 * file actually reads. */
static const char *flag_or_env(const char *flag, const char *from_env)
{
    const char *value = GetArg(flag, NULL);
    if (value && value[0])
        return value;
    return from_env ? from_env : "";
}

/* "<ipv4>:<port>". Both halves are required — see the header note on why the
 * interface is not defaulted. */
static bool parse_listen(const char *spec, char *ip, size_t ip_size, uint16_t *port)
{
    const char *colon = strrchr(spec, ':');
    if (!colon || colon == spec)
        return false;
    size_t ip_len = (size_t)(colon - spec);
    if (ip_len >= ip_size)
        return false;
    memcpy(ip, spec, ip_len);
    ip[ip_len] = '\0';
    long parsed = strtol(colon + 1, NULL, 10);
    if (parsed <= 0 || parsed > 65535)
        return false;
    *port = (uint16_t)parsed;
    return true;
}

/* core/modules/net's seam is a plain bool query and a plain bool handler —
 * net knows nothing about struct zcl_result, which lives above it in the
 * module order. These two adapters are the whole conversion: the engine side
 * keeps its named reasons, the wire side keeps its two-state answer. */
static bool beta6_inband_armed_hook(void)
{
    return beta6_bs_inband_status().ok;
}

static bool beta6_inband_message_hook(struct msg_processor *mp, struct p2p_node *node,
                                      const char *command,
                                      const unsigned char *payload, size_t payload_len)
{
    struct zcl_result served =
        beta6_bs_inband_serve(mp, node, command, payload, payload_len);
    if (!served.ok)
        LOG_WARN("beta6boot", "beta6 %s not answered: %s", command, served.message);
    return served.ok;
}

/* The optional side listener, for hosts that want the service on its own
 * address. Split out so the start hook stays inside the complexity cap. */
static void start_side_listener(struct boot_svc_ctx *svc)
{
    const char *listen =
        flag_or_env("-beta6-bootstrap-listen", getenv("ZCL_BETA6_BOOTSTRAP_LISTEN"));
    if (!listen[0])
        return;
    char ip[64] = { 0 };
    uint16_t port = 0;
    if (!parse_listen(listen, ip, sizeof(ip), &port)) {
        LOG_WARN("beta6boot", "-beta6-bootstrap-listen must be <ip>:<port>, got '%s'",
                 listen);
        return;
    }
    struct zcl_result started =
        beta6_bs_listen_start(ip, port, svc->params->pchMessageStart,
                              svc->params->strNetworkID, svc->app_ctx->params_dir);
    if (!started.ok)
        LOG_WARN("beta6boot", "beta6 bootstrap listener did not start: %s",
                 started.message);
}

/* The production path: advertise NODE_BOOTSTRAP and answer the eight messages
 * on this node's ORDINARY P2P peers, because that is the only port a stock
 * beta6 client will fast-sync from. Installed before the optional side
 * listener so a node that names only a source directory already serves stock
 * clients. */
static void install_inband_seam(struct boot_svc_ctx *svc)
{
    struct zcl_result armed =
        beta6_bs_inband_arm(svc->params->strNetworkID, svc->app_ctx->params_dir);
    if (!armed.ok) {
        LOG_WARN("beta6boot", "in-band beta6 bootstrap serving NOT armed: %s",
                 armed.message);
        return;
    }
    msg_processor_set_beta6_bootstrap(svc->msg_processor, beta6_inband_armed_hook,
                                      beta6_inband_message_hook);
    LOG_INFO("beta6boot",
             "serving beta6 bootstrap snapshots in-band on the P2P port "
             "(NODE_BOOTSTRAP advertised)");
}

static bool boot_beta6_bootstrap_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx || !svc->params)
        return true;

    const char *source =
        flag_or_env("-beta6-bootstrap-source", getenv("ZCL_BETA6_BOOTSTRAP_SOURCE"));
    if (!source[0])
        return true;

    struct zcl_result armed = beta6_bs_arm(source, svc->params->strNetworkID);
    if (!armed.ok) {
        LOG_WARN("beta6boot", "beta6 bootstrap serve NOT armed: %s", armed.message);
        return true;
    }
    const struct beta6_bs_manifest *manifest = beta6_bs_manifest();
    LOG_INFO("beta6boot",
             "armed from %s: manifest v%d height=%d files=%zu bytes=%llu", source,
             (int)manifest->version, (int)manifest->height, manifest->file_count,
             (unsigned long long)manifest->snapshot_bytes);

    install_inband_seam(svc);
    start_side_listener(svc);
    return true;
}

static void boot_beta6_bootstrap_stop(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    /* Uninstall the seam BEFORE releasing what it reads: with the hooks
     * cleared the dispatch table ignores the eight commands again and the
     * services word drops NODE_BOOTSTRAP, exactly as on a node that never
     * configured a source. */
    if (svc && svc->msg_processor)
        msg_processor_set_beta6_bootstrap(svc->msg_processor, NULL, NULL);
    beta6_bs_inband_disarm();
    beta6_bs_listen_stop();
    beta6_bs_disarm();
}

struct zcl_service_spec boot_beta6_bootstrap_spec(struct boot_svc_ctx *svc)
{
    return (struct zcl_service_spec){
        .name = "beta6_bootstrap",
        .start = boot_beta6_bootstrap_start,
        .stop = boot_beta6_bootstrap_stop,
        .ctx = svc,
        .flags = ZCL_SERVICE_OPTIONAL,
    };
}
