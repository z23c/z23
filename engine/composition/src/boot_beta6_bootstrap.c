/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Boot wiring for the optional zclassicd beta6 bootstrap snapshot server.
 *
 * Dormant by default. Two flags arm it, each with an environment fallback so a
 * service unit can set it without rewriting an argv line:
 *
 *   -beta6-bootstrap-source=<ABSOLUTE dir>   ZCL_BETA6_BOOTSTRAP_SOURCE
 *   -beta6-bootstrap-listen=<ip>:<port>      ZCL_BETA6_BOOTSTRAP_LISTEN
 *
 * With neither set this service starts nothing and changes no behaviour: the
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
#include "base/log_macros.h"
#include "util/util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* A flag's value from argv, else its environment fallback, else "". */
static const char *flag_or_env(const char *flag, const char *env_name)
{
    const char *value = GetArg(flag, NULL);
    if (value && value[0])
        return value;
    const char *from_env = getenv(env_name);
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

static bool boot_beta6_bootstrap_start(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    if (!svc || !svc->app_ctx || !svc->params)
        return true;

    const char *source =
        flag_or_env("-beta6-bootstrap-source", "ZCL_BETA6_BOOTSTRAP_SOURCE");
    if (!source[0])
        return true;

    char err[512] = { 0 };
    if (!beta6_bs_arm(source, svc->params->strNetworkID, err, sizeof(err))) {
        LOG_WARN("beta6boot", "beta6 bootstrap serve NOT armed: %s", err);
        return true;
    }
    const struct beta6_bs_manifest *manifest = beta6_bs_manifest();
    LOG_INFO("beta6boot",
             "armed from %s: manifest v%d height=%d files=%zu bytes=%llu", source,
             (int)manifest->version, (int)manifest->height, manifest->file_count,
             (unsigned long long)manifest->snapshot_bytes);

    const char *listen =
        flag_or_env("-beta6-bootstrap-listen", "ZCL_BETA6_BOOTSTRAP_LISTEN");
    if (!listen[0]) {
        LOG_INFO("beta6boot",
                 "no -beta6-bootstrap-listen=<ip>:<port>; snapshot armed but not served");
        return true;
    }
    char ip[64] = { 0 };
    uint16_t port = 0;
    if (!parse_listen(listen, ip, sizeof(ip), &port)) {
        LOG_WARN("beta6boot", "-beta6-bootstrap-listen must be <ip>:<port>, got '%s'",
                 listen);
        return true;
    }
    if (!beta6_bs_listen_start(ip, port, svc->params->pchMessageStart,
                               svc->params->strNetworkID, svc->app_ctx->params_dir, err,
                               sizeof(err)))
        LOG_WARN("beta6boot", "beta6 bootstrap listener did not start: %s", err);
    return true;
}

static void boot_beta6_bootstrap_stop(void *ctx)
{
    (void)ctx;
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
