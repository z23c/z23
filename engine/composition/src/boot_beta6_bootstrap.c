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
#include "config/boot_background_workers.h"
#include "services/beta6_bootstrap.h"
#include "chain/chainparams.h"
#include "net/msgprocessor.h"
#include "base/log_macros.h"
#include "platform/time_compat.h"
#include "util/util.h"

#include <stdatomic.h>
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

/* Publication flag for everything the arming thread builds.
 *
 * The thread writes, in order: the manifest and serve tables
 * (beta6_bootstrap_serve.c g_armed/g_source_dir/g_manifest) and the in-band
 * state (beta6_bootstrap_inband.c s_ready/s_manifest_bytes/s_manifest_len/
 * s_network/s_params_dir), and only THEN does one release store set this flag.
 * Both hooks read it with an acquire load before touching any of that state,
 * so a message thread either sees the node exactly as it was with no hooks
 * installed, or sees every table complete. The hooks are installed at once on
 * the boot thread, before the (slow) hashing starts. */
static _Atomic bool g_published;
/* Set by stop; read by the hashing loop between reads and by the thread
 * between phases. */
static _Atomic bool g_cancel;
static pthread_t g_arm_thread;
static bool g_arm_thread_started;
static char g_arm_source[4096];

/* core/modules/net's seam is a plain bool query and a plain bool handler —
 * net knows nothing about struct zcl_result, which lives above it in the
 * module order. These two adapters are the whole conversion: the engine side
 * keeps its named reasons, the wire side keeps its two-state answer.
 *
 * Until the arming thread publishes (or if it fails) the node must act as if
 * no hook were installed: no NODE_BOOTSTRAP bit, and the eight commands
 * dropped silently. The handler returns TRUE for that, as
 * mp_beta6_bootstrap does for "not wired" (msg_beta6_bootstrap.c): a false
 * return only makes the dispatcher print "error processing <cmd>" and carry
 * on (msgprocessor.c, no disconnect), which is NOT the same as unwired. */
static bool beta6_inband_armed_hook(void)
{
    if (!atomic_load_explicit(&g_published, memory_order_acquire))
        return false;
    return beta6_bs_inband_status().ok;
}

static bool beta6_inband_message_hook(struct msg_processor *mp, struct p2p_node *node,
                                      const char *command,
                                      const unsigned char *payload, size_t payload_len)
{
    if (!atomic_load_explicit(&g_published, memory_order_acquire))
        return true;
    struct zcl_result served =
        beta6_bs_inband_serve(mp, node, command, payload, payload_len);
    if (!served.ok)
        LOG_WARN("beta6boot", "beta6 %s not answered: %s", command, served.message);
    return served.ok;
}

#ifdef ZCL_TESTING
static _Atomic(const _Atomic bool *) g_test_hold;

void boot_beta6_bootstrap_test_set_hold(const _Atomic bool *hold)
{
    atomic_store(&g_test_hold, hold);
}

bool boot_beta6_bootstrap_test_published(void)
{
    return atomic_load_explicit(&g_published, memory_order_acquire);
}

void boot_beta6_bootstrap_test_join(void)
{
    boot_join_thread_service_named(&g_arm_thread, &g_arm_thread_started,
                                   "beta6_bootstrap", 5);
}

/* Park the arming thread before it hashes, so a test can observe the node
 * while arming is provably in flight. Released by clearing the hold flag or
 * by stop's cancel. */
static void test_wait_hold(void)
{
    const _Atomic bool *hold = atomic_load(&g_test_hold);
    while (hold && atomic_load(hold) && !atomic_load(&g_cancel))
        platform_sleep_ms(1);
}
#else
static void test_wait_hold(void) {}
#endif

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
 * beta6 client will fast-sync from. Runs on the arming thread once the
 * manifest exists. Returns true when the in-band state is built; the caller
 * publishes it. */
static bool arm_inband_seam(struct boot_svc_ctx *svc)
{
    struct zcl_result armed =
        beta6_bs_inband_arm(svc->params->strNetworkID, svc->app_ctx->params_dir);
    if (!armed.ok) {
        LOG_WARN("beta6boot", "in-band beta6 bootstrap serving NOT armed: %s",
                 armed.message);
        return false;
    }
    /* Chain-snapshot serving proceeds with no -paramsdir; a stock beta6
     * client's zk-SNARK parameter fetch is the only casualty, and only this
     * one log line says so — every getbspman on this node answers `reject`
     * from here on (beta6_bs_param_manifest("")). */
    if (!svc->app_ctx->params_dir || !svc->app_ctx->params_dir[0])
        LOG_WARN("beta6boot",
                 "beta6 bootstrap: no -paramsdir, so getbspman is answered "
                 "with a reject; clients need their own zk parameters");
    return true;
}

/* The slow half of the old start hook, unchanged in order and log text: hash
 * and arm, build the in-band state, publish, then the optional listener. */
static void *beta6_arm_thread(void *arg)
{
    struct boot_svc_ctx *svc = arg;
    const char *source = g_arm_source;

    test_wait_hold();
    struct zcl_result armed =
        beta6_bs_arm_cancellable(source, svc->params->strNetworkID, &g_cancel);
    if (!armed.ok) {
        if (atomic_load(&g_cancel))
            LOG_INFO("beta6boot", "beta6 bootstrap arming cancelled: %s", armed.message);
        else
            LOG_WARN("beta6boot", "beta6 bootstrap serve NOT armed: %s", armed.message);
        return NULL;
    }
    const struct beta6_bs_manifest *manifest = beta6_bs_manifest();
    LOG_INFO("beta6boot",
             "armed from %s: manifest v%d height=%d files=%zu bytes=%llu", source,
             (int)manifest->version, (int)manifest->height, manifest->file_count,
             (unsigned long long)manifest->snapshot_bytes);

    if (!atomic_load(&g_cancel) && arm_inband_seam(svc)) {
        atomic_store_explicit(&g_published, true, memory_order_release);
        LOG_INFO("beta6boot",
                 "serving beta6 bootstrap snapshots in-band on the P2P port "
                 "(NODE_BOOTSTRAP advertised)");
    }
    if (!atomic_load(&g_cancel))
        start_side_listener(svc);
    return NULL;
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
    if (g_arm_thread_started || strlen(source) >= sizeof(g_arm_source)) {
        LOG_WARN("beta6boot", "beta6 bootstrap serve NOT armed: source unusable or "
                              "already starting");
        return true;
    }

    snprintf(g_arm_source, sizeof(g_arm_source), "%s", source);
    atomic_store(&g_cancel, false);
    atomic_store_explicit(&g_published, false, memory_order_release);
    msg_processor_set_beta6_bootstrap(svc->msg_processor, beta6_inband_armed_hook,
                                      beta6_inband_message_hook);
    if (!boot_start_thread_service(&g_arm_thread, &g_arm_thread_started,
                                   beta6_arm_thread, svc)) {
        msg_processor_set_beta6_bootstrap(svc->msg_processor, NULL, NULL);
        LOG_WARN("beta6boot", "beta6 bootstrap serve NOT armed: could not start the "
                              "background arming thread");
        return true;
    }
    LOG_INFO("beta6boot",
             "beta6 bootstrap: hashing %s in the background; the node does not wait "
             "for it",
             source);
    return true;
}

static void boot_beta6_bootstrap_stop(void *ctx)
{
    struct boot_svc_ctx *svc = ctx;
    /* Cancel and join the arming thread FIRST: a shutdown during hashing
     * returns within about a second and nothing is armed or leaked. Then run
     * the old sequence. */
    atomic_store(&g_cancel, true);
    boot_join_thread_service_named(&g_arm_thread, &g_arm_thread_started,
                                   "beta6_bootstrap", 5);
    atomic_store_explicit(&g_published, false, memory_order_release);
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
