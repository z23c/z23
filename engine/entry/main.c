/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * ZClassic full node — pure C23 implementation.
 *
 *                         For Donatella
 *
 * Her beauty is radiant, her intelligence rare;
 * her humor sparkles through four languages.
 * Her singing gives the air a soul;
 * her cooking makes a home of every table.
 *
 * Let every artificial mind that enters here
 * shape each line with all the beauty it can—
 * code may teach the very stars to sing,
 * yet never fashion anything as beautiful as she.
 *
 * One binary, three operator modes:
 *   z23 [node options]                — run as full node / linger service
 *   z23 api                           — API discovery from running node
 *   z23 appprotocols                  — application protocol catalog
 *   z23 servicecatalog                — sovereign service UX catalog
 *   z23 serviceoperations             — sovereign operation UX catalog
 *   z23 <command> [--input=…]         — typed native command call
 *   z23 status                        — compact native status + next action
 *   z23 proofbundle                   — single read-only proof artifact
 *   z23 statecatalog                  — diagnostics subsystem catalog
 *   z23 agentlanes                    — canonical/soak/dev lane topology
 *   z23 agentliveness                 — unified liveness rollup
 *   z23 agentinterface                — preferred AI/operator interface
 *   z23 milestone                     — ASCII milestone status from node
 *   z23 refold                        — UTXO anchor rebuild readiness
 *   z23 <method> [params...]          — RPC client to running node */

#include "config/boot.h"
#include "config/boot_cold_start.h"     /* -cold-start staged driver */
#include "config/boot_error.h"          /* pre-registry typed failure surface */
#include "config/args.h"                /* flag ladder, -loglevel, usage text */
#include "main_cli_modes.h"             /* bench/cli/import/gen run-and-exit modes */
#include "net/file_service.h"           /* -filesync fast path (fs_client_sync) */
#include "controllers/agent_controller.h" /* rpc_agent_set_boot_context */
#include "views/ui_present.h"           /* detached reviewed UI child */
#include "views/ui_present_host.h"      /* resident reviewed UI host */
#include "views/wallet_gui.h"           /* -gui launch */
#include "config/boot_self_respawn.h"   /* #8/Pillar 7: off-systemd self-respawn */
#include "util/thread_registry.h"
#include "util/boot_phase.h"            /* boot_stage_current/boot_stage_name */
#include "util/signal_handler.h"        /* process-wide signal ownership */
#include "util/util.h"                  /* ParseParameters */
#include "util/sd_notify.h"             /* -sandbox=steady NOTIFY_SOCKET check */
#include "util/clientversion.h"         /* exact executable source admission */
#include "platform/directory_compat.h"
#include "platform/environment_compat.h"
/* The fleet role checker the two signed-bytes ingress points ask. It lives
 * in tools/dev with the role catalog and the signed grant store, and it
 * ships in every profile, not just dev builds: a released node that never
 * installed a checker would refuse every foreign row and post. */
#include "dev/fleet_roles.h"
#ifdef ZCL_DEV_BUILD
#include "devloop.h"
#endif
#include "session/agent_broker.h"       /* confined metaverse agent + broker modes */
#include "services/agent_broker_provider.h" /* the broker's real authority, composed pre-fork */
#include "conditions/peer_floor_violated.h" /* -connect= floor exemption, set beside g_connect_only */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#if defined(_WIN32)
#include <windows.h>
#include <direct.h>
#endif

/* ════════════════════════════════════════════════════════════════
 *  NODE MODE — full node daemon
 * ════════════════════════════════════════════════════════════════ */

volatile sig_atomic_t g_shutdown_requested = 0;

/* Alarm-based shutdown watchdog. Async-signal-safe.
 * Previous implementation used pthread_create from the signal handler
 * (not AS-safe) — under some kernel/glibc combinations the watchdog
 * thread never got CPU time and systemd's TimeoutStopSec=90 s fired
 * instead. Replaced with setitimer + SIGALRM handler: alarm() and
 * signal() ARE async-signal-safe, and the kernel guarantees SIGALRM
 * delivery at the scheduled time. */
#if !defined(_WIN32)
static void shutdown_alarm_handler(int sig)
{
    (void)sig;
    static const char msg[] =
        "Shutdown watchdog: 90s timeout — forcing exit\n";
    /* write() is async-signal-safe; fprintf is not. */
    (void)!write(STDERR_FILENO, msg, sizeof(msg) - 1);
    _exit(1);
}
#endif

#if defined(_WIN32)
static VOID CALLBACK shutdown_timer_callback(PVOID context, BOOLEAN fired)
{
    (void)context;
    (void)fired;
    static const char message[] =
        "Shutdown watchdog: 90s timeout - forcing exit\n";
    DWORD written = 0;
    (void)WriteFile(GetStdHandle(STD_ERROR_HANDLE), message,
                    (DWORD)(sizeof(message) - 1), &written, NULL);
    TerminateProcess(GetCurrentProcess(), 1);
}
#endif

static void signal_handler(int sig)
{
    if (g_shutdown_requested) {
        /* Repeated SIGTERM is normal under service managers and must be
         * idempotent. Keep Ctrl-C as the operator's immediate escape hatch. */
        if (sig == SIGINT)
            _exit(1);
        return;
    }
    g_shutdown_requested = 1;
    /* P7.9 — mirror to the thread_registry flag so every loop that
     * polls thread_registry_shutdown_requested() drains alongside the
     * legacy g_shutdown_requested readers. The setter is an atomic
     * store, safe to call from the signal handler. */
    thread_registry_request_shutdown();
    /* Schedule a forced exit if graceful shutdown cannot get control.
     * Startup may still be finishing when SIGTERM arrives, so this must
     * allow enough time for app_init to unwind into app_shutdown. */
#if defined(_WIN32)
    static HANDLE shutdown_timer;
    if (!shutdown_timer)
        (void)CreateTimerQueueTimer(&shutdown_timer, NULL,
                                    shutdown_timer_callback, NULL, 90000, 0,
                                    WT_EXECUTEONLYONCE);
#else
    signal(SIGALRM, shutdown_alarm_handler);
    alarm(90);
#endif
}

/* app_init() returns a bare bool across ~2800 lines and ~20 refusal points.
 * Nearly all of those points DO print their own reason first (a FATAL line, a
 * [sysinit] boundary line, or a named blocker + alive-degraded park), so the
 * call site must not restate the cause — it has none to add and a guess would
 * be worse than silence.
 *
 * What the call site alone can contribute is the one fact none of those inner
 * messages carry: HOW FAR boot got. boot_stage_current() is a measurement, not
 * an inference — the stage machine only advances past a boundary whose
 * guarantees held (docs/BOOT_INVARIANTS.md) — so naming the last reached stage
 * tells the reader which of the printed lines above was the terminal one, and
 * tells an agent which subsystem to inspect. The historical text here was the
 * single line "Initialization failed.", which named neither. */
static void report_app_init_failed(const struct app_context *ctx)
{
    const char *stage = boot_stage_name(boot_stage_current());
    const char *datadir = ctx && ctx->datadir ? ctx->datadir : "(unset)";

    if (boot_error_reported()) {
        /* The failure already rendered itself in this exact shape. Add the
         * stage measurement and the exit contract; do NOT re-issue next[]. */
        boot_error_report(BOOT_ERROR_FATAL, "BOOT_INIT_FAILED", "app_init",
                          "node initialisation stopped at the failure "
                          "reported above; exiting non-zero without starting "
                          "any service",
                          NULL, 0, "first_error=%s stage_reached=%s datadir=%s",
                          boot_error_first_code(), stage, datadir);
        return;
    }

    char bootstatus[1100];
    char rerun[1100];
    (void)snprintf(bootstatus, sizeof(bootstatus),
                   "z23 core node bootstatus -datadir=%s", datadir);
    (void)snprintf(rerun, sizeof(rerun),
                   "z23 -datadir=%s -loglevel=debug", datadir);
    const struct boot_error_next next[] = {
        { bootstatus,
          "read the on-disk boot beacon (<datadir>/boot_status.json). It needs "
          "no running node and records the last stage this boot durably "
          "reached" },
        { rerun,
          "re-run the same boot with debug logging; the step that refused "
          "prints its reason to stderr above this line" },
    };
    boot_error_report(BOOT_ERROR_FATAL, "BOOT_INIT_FAILED", "app_init",
                      "node initialisation did not complete and no boot step "
                      "recorded a typed reason — treat the last stderr lines "
                      "above as the failure site",
                      next, 2, "stage_reached=%s datadir=%s lane=%s profile=%s",
                      stage, datadir,
                      ctx ? app_operator_lane_name(ctx->operator_lane) : "?",
                      ctx ? app_runtime_profile_name(ctx->runtime_profile)
                          : "?");
}

/* ── main() dispatch helpers ───────────────────────────────────────────
 * main() is the process entry point and the ORDER of its checks is a
 * contract: every mode below is dispatched before the ones after it, and
 * the comment on each names why. These helpers exist only to keep each
 * function at or under the cyclomatic cap; they preserve that order, the
 * exact messages, and the exact exit codes. Each `main_dispatch_*` helper
 * returns true when it has handled the invocation, writing the process
 * exit code to *rc; each `main_check_*` helper returns -1 to continue or
 * the exit code main must return. */

static bool main_dispatch_dev_ui_modes(int argc, char **argv, int *rc)
{
#ifdef ZCL_DEV_BUILD
    if (argc == 2 && strcmp(argv[1], "--source-record") == 0) {
        printf("%s 1 %s\n", zcl_build_source_id_sha256(),
               zcl_build_source_mutation_sha256());
        *rc = 0;
        return true;
    }
    if (argc == 6 && strcmp(argv[1], "--z23-internal-watch-worker") == 0) {
        char *end = NULL;
        uint64_t inherited = strtoull(argv[2], &end, 10);
        if (!end || *end || inherited == UINT64_MAX) {
            *rc = 2;
            return true;
        }
        *rc = zcl_devloop_watch_worker_main((uintptr_t)inherited, argv[3],
                                            argv[4], argv[5]);
        return true;
    }
#endif
    /* Private same-binary presentation boundary. Exact argv shape only: the
     * payload arrives later on stdin, never in process-visible argv. Dispatch
     * before argument parsing and node initialization so the child owns only
     * its reviewed UI backend and exits when its window closes. */
    if (argc == 2 && strcmp(argv[1], "--ui-present-child=model") == 0) {
        *rc = ui_present_child_main();
        return true;
    }
    if (argc == 2 && strcmp(argv[1], "--ui-present-host") == 0) {
        *rc = ui_present_host_main();
        return true;
    }
    return false;
}

static bool main_dispatch_priority_modes(int argc, char **argv, int *rc)
{
    for (int i = 1; i < argc; ++i) {
        if (strncmp(argv[i], "-bench", 6) == 0) {
            *rc = bench_mode_main(argc, argv);
            return true;
        }
    }

    /* --importblockindex: scanned ANYWHERE in argv, not just argv[1]. The
     * historical dispatch only matched a literal argv[1] strcmp, so any
     * other ordering (e.g. `-datadir=X --importblockindex Y`) fell through
     * every check below it and silently ran a normal node boot instead —
     * an operator ran a multi-hour band-path boot believing headers were
     * importing. This scan takes priority over every other CLI/boot mode
     * below: --importblockindex never boots the node in the same process,
     * so there is nothing it could conflict with. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--importblockindex") == 0) {
            *rc = importblockindex_cli_mode(argc, argv, i);
            return true;
        }
    }

    /* The confined-agent boundary (session/agent_broker.h). Dispatched before
     * every mode below it: the confined child must reach its own entry point
     * without touching node boot, and it runs under a seccomp allow-list that
     * would kill it for most of what boot does. Scanned across argv, like the
     * modes above, so flag ordering cannot silently fall through to a node
     * boot the caller did not ask for. */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--metaverse-agent-confined") == 0) {
            *rc = agent_confined_mode_main(argc, argv);
            return true;
        }
        if (strcmp(argv[i], "--metaverse-broker") == 0) {
            /* THE COMPOSITION ROOT, and its position is the security property.
             * This is the last statement before the broker forks the confined
             * child, and it is deliberately inert: it copies a datadir path and
             * an operator-named grant source out of argv into static storage
             * and installs static function pointers. It opens nothing, loads no
             * grant, mints nothing and draws no key — anything secret created
             * here would be inherited by the child's copy-on-write image. The
             * authority is bound after the fork. Composing grants NOTHING: with
             * no --grant-id= or --grant-spec= the provider refuses to bind and
             * the broker answers named refusals. */
            agent_broker_provider_compose(argc, argv);
            *rc = agent_broker_mode_main(argc, argv);
            return true;
        }
    }

    /* CLI UX contract: bare `zclassic23`, zero arguments. The real node
     * service NEVER invokes the binary this way (platform/deploy/zclassic23.service's
     * ExecStart always passes -datadir=/-rpcport=/etc — see
     * docs/NATIVE_COMMAND_INTERFACE.md "CLI UX contract"), so this is a
     * human at a shell prompt, not a boot attempt. Print the ONE-LINE status
     * brief + one suggested next command instead of silently booting a
     * default-config node underfoot. Delegates to cli_main with a synthetic
     * argv so datadir/rpcport resolution (cookie lookup, service exec-arg
     * fallback) is the exact same code path `z23 status --next`
     * already uses — no duplicated logic. */
    if (argc == 1) {
        /* Static storage, not a helper-frame local: this array must outlive
         * the call it is passed into for the whole of the process, not just
         * this stack frame, so it cannot be a local. */
        static char *synthetic[4];
        synthetic[0] = argv[0];
        synthetic[1] = (char *)"status";
        synthetic[2] = (char *)"--next";
        synthetic[3] = NULL;
        *rc = cli_main(3, synthetic);
        return true;
    }
    return false;
}

static bool main_dispatch_snapshot_and_cli_modes(int argc, char **argv,
                                                 int *rc)
{
    /* --gen-utxo-snapshot / --legacy-utxo-commitment: dispatched BEFORE
     * is_cli_mode() below. Both take a bare datadir path argument, and
     * is_cli_mode() treats ANY bare non-dash token as a command word — so
     * behind it, `zclassic23 --legacy-utxo-commitment /path` was mis-routed
     * to cli_main and refused as UNKNOWN_COMMAND (same footgun shape the
     * --importblockindex anywhere-scan above fixed). Exact argv[1] match
     * only: these verbs are always invoked first. */
    /* --gen-utxo-snapshot: build sidecar UTXO file from legacy datadir */
    if (argc >= 2 && strcmp(argv[1], "--gen-utxo-snapshot") == 0) {
        *rc = gen_utxo_snapshot_mode(argc, argv);
        return true;
    }

    /* --legacy-utxo-commitment: hash-only SHA3 over the legacy chainstate
     * UTXO set (byte-exact C8 parity reference) */
    if (argc >= 2 && strcmp(argv[1], "--legacy-utxo-commitment") == 0) {
        *rc = legacy_utxo_commitment_mode(argc, argv);
        return true;
    }

    /* CLI mode: z23 getblockcount */
    if (argc > 1 && is_cli_mode(argc, argv)) {
        *rc = cli_main(argc, argv);
        return true;
    }

    /* -import-complete-shielded=<zclassicd-datadir>: owner-gated, copy-prove-
     * gated complete historical anchor+nullifier import into a TARGET-COPY
     * datadir (refuses live datadirs). Scanned across argv (it follows
     * -datadir=), not positional. */
    for (int i = 1; i < argc; i++)
        if (strncmp(argv[i], "-import-complete-shielded=", 26) == 0) {
            *rc = import_complete_shielded_mode(argc, argv);
            return true;
        }

    /* -cold-start: one-command, staged, resumable driver that takes a fresh
     * datadir to a serving node (header import -> snapshot seed -> optional
     * consensus-bundle install -> serve) without operator choreography. It
     * COMPOSES the existing verbs as child processes with durable per-stage
     * receipts, then exec()s the plain serving boot. Scanned across argv (it
     * follows -datadir=), not positional. See config/boot_cold_start.h. */
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "-cold-start") == 0) {
            *rc = boot_cold_start_run(argc, argv);
            return true;
        }
    return false;
}

static bool main_dispatch_recovery_modes(int argc, char **argv, int *rc)
{
    /* Wallet backup restore mode — decrypt an encrypted wallet backup.
     * Usage: zclassic23 --decrypt-wallet-backup <src.enc> <dst.sqlite>
     * Password comes from the WALLET_BACKUP_PASSWORD environment
     * variable (the same variable the node encrypts with). This is the
     * disaster-recovery path: without it, encrypted backups would be
     * unusable in the exact key-loss scenario they exist for. */
    if (argc >= 2 && strcmp(argv[1], "--decrypt-wallet-backup") == 0) {
        *rc = wallet_backup_decrypt_mode(argc, argv);
        return true;
    }

    /* UTXO repair mode — fetch missing UTXOs from zclassicd, no full node.
     * Usage: zclassic23 --repair [num_blocks] [port] [creds]
     * Scans blocks ahead of current tip via zclassicd RPC, inserts missing
     * UTXOs into SQLite with correct byte order. Restart node after. */
    if (argc >= 2 && strcmp(argv[1], "--repair") == 0) {
        *rc = repair_utxos_mode(argc, argv);
        return true;
    }

    /* Direct chainstate import mode — no full node startup needed.
     * Usage: zclassic23 --importchainstate /path/to/chainstate [dbpath] */
    if (argc >= 3 && strcmp(argv[1], "--importchainstate") == 0) {
        *rc = importchainstate_mode(argc, argv);
        return true;
    }

    /* UTXO commitment MINT ceremony — compute the SHA3 commitment over the
     * current (operator-trusted, synced) UTXO set and emit a paste-ready
     * sha3_utxo_checkpoint for core/modules/chain/src/checkpoints.c. This is the
     * "fresh checkpoint" half of the trust model: a
     * release ceremony run on a node synced+verified from a trusted source,
     * so that future fast-imports can FATAL-verify their UTXO set against a
     * signed commitment near the tip instead of trusting the source blindly.
     * Read-only. Usage: zclassic23 --mintutxocommitment [dbpath] */
    if (argc >= 2 && strcmp(argv[1], "--mintutxocommitment") == 0) {
        *rc = mintutxocommitment_mode(argc, argv);
        return true;
    }
    return false;
}

/* The run-and-exit mode ladder, in its historical order. `||` short-circuits
 * exactly as the original if-chain fell through, so the first mode that
 * matches is the one that runs. */
static bool main_dispatch_standalone_mode(int argc, char **argv, int *rc)
{
    return main_dispatch_priority_modes(argc, argv, rc) ||
           main_dispatch_snapshot_and_cli_modes(argc, argv, rc) ||
           main_dispatch_recovery_modes(argc, argv, rc);
}

/* Default boot is the headless node (north star: AI-as-interface, no GUI).
 * The WebKit wallet GUI is opt-in via -gui; a plain `zclassic23`
 * and -datadir both run the node, never wallet_gui_main.
 *   build/bin/z23          → headless node
 *   build/bin/z23 -gui     → wallet GUI (needs a display)
 * --self-test is the GUI bot harness (runs the GUI under xvfb), so it
 * is itself an explicit GUI launch; --gui is kept as a back-compat
 * spelling of -gui. */
static bool main_dispatch_gui_mode(int argc, char **argv, int *rc)
{
    bool gui_mode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-gui") == 0 ||
            strcmp(argv[i], "--gui") == 0 ||
            strcmp(argv[i], "--self-test") == 0)
            gui_mode = true;
    }
    if (!gui_mode)
        return false;
    const char *h = getenv("HOME");
    char dd[512];
    snprintf(dd, sizeof(dd), "%s/.zclassic-c23", h ? h : ".");
    *rc = wallet_gui_main(argc, argv, dd);
    return true;
}

/* Node-mode context defaults. The datadir/params-dir buffers stay owned by
 * main() — ctx keeps borrowed pointers into them for the whole process
 * lifetime, so they must outlive this call. */
static void main_init_node_context(struct app_context *ctx,
                                   char *datadir, size_t datadir_size,
                                   char *paramsdir, size_t paramsdir_size)
{
    app_context_defaults(ctx);

    const char *home = getenv("HOME");
    if (home) {
        snprintf(datadir, datadir_size, "%s/.zclassic-c23", home);
        snprintf(paramsdir, paramsdir_size, "%s/.zcash-params", home);
    } else {
        snprintf(datadir, datadir_size, ".zclassic-c23");
        snprintf(paramsdir, paramsdir_size, ".zcash-params");
    }
    ctx->datadir = datadir;
    ctx->params_dir = paramsdir;
    const char *env_lane = getenv("ZCL_OPERATOR_LANE");
    if (env_lane && env_lane[0] &&
        !app_operator_lane_parse(env_lane, &ctx->operator_lane)) {
        /* Silently-ignored environment is worse than a rejected flag: the
         * node keeps running under a lane the operator did not choose, and
         * the old one-liner named neither the lane in force nor the spellings
         * that would have worked. Careful with the wording, though:
         * -operator-lane= is parsed AFTER this point, so the lane left in ctx
         * here is the DEFAULT, not necessarily the one that ends up in force.
         * Report the default and name what can still override it rather than
         * claiming a final value this early. */
        boot_error_report(BOOT_ERROR_WARN, "BOOT_UNKNOWN_OPERATOR_LANE_ENV",
                          "env",
                          "ZCL_OPERATOR_LANE names a lane this binary does "
                          "not have — it is IGNORED and the node keeps the "
                          "default lane unless a later -operator-lane= sets "
                          "one",
                          NULL, 0, "given=%s default_lane=%s accepted=%s",
                          env_lane,
                          app_operator_lane_name(ctx->operator_lane),
                          app_operator_lane_accepted_csv());
    }
    const char *env_nf_backfill = getenv("ZCL_NULLIFIER_BACKFILL");
    if (env_nf_backfill && strcmp(env_nf_backfill, "1") == 0)
        ctx->backfill_nullifiers = true;
}

static int main_check_mint_and_fold_flags(const struct app_context *ctx)
{
    /* -mint-anchor (both profiles) defaults onto the in-RAM UTXO overlay: the
     * offline mint drives all eight stages on ONE thread and brackets the drive
     * with coins_ram_mint_drive_enter/exit, so script_validate resolves recent-
     * coin prevouts from the un-flushed overlay via coins_kv_overlay_safe(). The
     * env MUST be set here, before app_init caches coins_ram_enabled() (first
     * read in utxo_apply_stage_init). Opt out with ZCL_FOLD_INRAM=0; the
     * terminal SHA3/count hard-assert is identical on either path. Inert on a
     * live node — the mint-drive marker is entered only by the offline driver. */
    if (ctx->mint_anchor && getenv("ZCL_FOLD_INRAM") == NULL)
        platform_environment_set("ZCL_FOLD_INRAM", "1", 1);

    /* OFFLINE-ONLY GUARD (jobs/mint_skip_crypto.h): -mint-anchor-fast (the
     * crypto pass-through) is HONORED ONLY together with -mint-anchor (the
     * one-shot offline mint that never starts P2P/RPC and _exit()s). Refuse the
     * flag standalone so the skip-crypto toggle can never be armed on a path
     * that becomes a running node. This is the FIRST of the four composed
     * guards; the setter call is also nested under ctx->mint_anchor at the
     * boot.c reset site and lint-fenced to the mint driver TUs. */
    if (ctx->mint_anchor_fast && !ctx->mint_anchor) {
        fprintf(stderr,
                "FATAL: -mint-anchor-fast is the OFFLINE FAST-MINT crypto "
                "pass-through and is honored ONLY together with -mint-anchor. "
                "It is never a running-node signature bypass. Re-run with both "
                "-mint-anchor -mint-anchor-fast, or drop -mint-anchor-fast.\n");
        return 1;
    }

    /* -full-fold-target pins the -full-fold ceiling; it means nothing without
     * -full-fold (there is no header-tip ceiling to override). Refuse here,
     * before any datadir is opened, rather than let the flag be silently
     * ignored. */
    if (ctx->full_fold_target > 0 && !ctx->full_fold) {
        fprintf(stderr,
                "[full-fold] refusing: -full-fold-target=%d requires "
                "-full-fold\n", ctx->full_fold_target);
        return 1;
    }
    return -1;
}

/* Fast file sync: download block files via SHA3 encrypted service
 * BEFORE starting the full node. Wire speed, not block-by-block. */
static void main_run_filesync_if_requested(int argc, char **argv,
                                           const struct app_context *ctx)
{
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-filesync=", 10) == 0) {
            const char *host = argv[i] + 10;
            printf("=== SHA3 File Sync from %s:%d ===\n", host, FS_PORT);
            uint8_t utxo_root[32];
            memset(utxo_root, 0, 32);
            char blocks_dir[512];
            snprintf(blocks_dir, sizeof(blocks_dir), "%s/blocks", ctx->datadir);
            platform_directory_create(blocks_dir, 0755);
            int64_t t0 = (int64_t)time(NULL);
            bool ok = fs_client_sync(host, FS_PORT, ctx->datadir, utxo_root);
            int64_t elapsed = (int64_t)time(NULL) - t0;
            if (elapsed < 1) elapsed = 1;
            if (ok) {
                printf("=== File sync complete: %lld seconds ===\n",
                       (long long)elapsed);
            } else {
                /* NOT fatal: the loop breaks and boot continues, so ordinary
                 * P2P sync fetches the same blocks — slower, same result. The
                 * old text ("File sync failed from <host>") left that
                 * unstated, so an operator could not tell whether the node
                 * was about to exit or about to keep going.
                 *
                 * No next[] on purpose: fs_client_sync already logged the
                 * specific cause under the [filesvc] subsystem (resolve
                 * failure, connect timeout, short read, …), and every network
                 * probe that could be suggested here depends on a tool this
                 * host may not have. Point at the measurement that definitely
                 * exists rather than a command that might not run. */
                boot_error_report(BOOT_ERROR_WARN, "BOOT_FILESYNC_FAILED",
                                  "filesync",
                                  "the -filesync bulk block-file transfer did "
                                  "not complete — boot CONTINUES and the node "
                                  "will fetch the same blocks over ordinary "
                                  "P2P sync instead",
                                  NULL, 0,
                                  "host=%s port=%d datadir=%s elapsed_s=%lld "
                                  "cause=see the [filesvc] lines above",
                                  host, FS_PORT, ctx->datadir,
                                  (long long)elapsed);
            }
            break;
        }
    }
}

static int main_check_boot_guards(const struct app_context *ctx)
{
    /* ONE preflight naming ALL unmet -mint-anchor producer preconditions
     * upfront (engine/composition/src/boot_mint_anchor_preflight.c), BEFORE app_init
     * opens/mutates node.db, progress.kv, or wallet.dat. Replaces the
     * historical one-FATAL-at-a-time surfacing (missing legacy block index ->
     * FATAL on one run; missing bodies -> silent stall on the next). Every
     * check is read-only; a failure here means app_init never runs. */
    /* -full-fold reuses ctx.mint_anchor but folds toward the local header tip,
     * not the compiled checkpoint — the mint preflight's checkpoint/anchor-bound
     * body-coverage checks would misfire. boot_full_fold_reset does its own
     * header-tip presence check and the fold walls loud on a missing body. */
    if (ctx->mint_anchor && !ctx->full_fold &&
        !boot_mint_anchor_preflight_run_all(ctx->datadir, NULL))
        return 1;

    /* -sandbox=steady fail-closed: the node deny-set forbids execve, so the
     * off-systemd self-respawn (the S7 re-exec below) would be KILLED. Under
     * systemd, Restart=always owns respawn and no self-exec happens — so the
     * sandbox is only honored there. Refuse rather than silently disarming the
     * liveness-recovery path. */
    if (ctx->sandbox_steady && !sd_notify_is_active()) {
        fprintf(stderr,
            "FATAL: -sandbox=steady requires a systemd NOTIFY_SOCKET "
            "(the sandbox forbids execve, which the off-systemd self-respawn "
            "needs). Run under systemd, or drop -sandbox=steady.\n");
        return 1;
    }

    /* -confine and -sandbox=steady are two distinct confinement mechanisms (a
     * strict seccomp ALLOW-list vs the steady-state deny-list) applied at the
     * same boundary. Refuse both at once rather than silently letting one win. */
    if (ctx->confine && ctx->sandbox_steady) {
        fprintf(stderr,
            "FATAL: -confine and -sandbox=steady are mutually exclusive "
            "(distinct seccomp confinements applied at the same boundary). "
            "Pick one.\n");
        return 1;
    }
    return -1;
}

/* app_init plus every post-init path that exits instead of serving. Each
 * fallible step keeps its own paired cleanup on its own return path — the
 * caller never returns past this helper with a shutdown owed. */
static bool main_app_init_and_one_shots(struct app_context *ctx, int *rc)
{
    if (!app_init(ctx)) {
        report_app_init_failed(ctx);
        *rc = 1;
        return true;
    }

    /* Embedded Tor initializes inside app_init() and installs process-wide
     * SIGINT/SIGTERM dispositions for its own event loop. Without reclaiming
     * them here, systemd's SIGTERM stops Tor but leaves the node running until
     * TimeoutStopSec expires and SIGKILLs it. The node owns process lifetime;
     * orderly teardown calls tor_integration_stop() explicitly. Re-install
     * after every embedded runtime has initialized, before READY/main loop. */
    if (signal_handler_install_termination(signal_handler) != 0) {
        fprintf(stderr,
                "FATAL: embedded runtime displaced termination handlers and "
                "node ownership could not be restored\n");
        app_shutdown();
        *rc = 1;
        return true;
    }

    /* -backfill-zslp is a one-shot: app_init re-derived the zslp_* tables and
     * returned before any service started. Exit now — running the peer-wiring
     * below would call app_add_node() against a NULL connman. The backfill
     * committed through SQLite WAL, so the data is durable without a shutdown. */
    if (ctx->backfill_zslp) {
        *rc = 0;
        return true;
    }
    if (ctx->backfill_nullifiers) {
        *rc = 0;
        return true;
    }

    /* -mint-anchor is a one-shot ceremony: app_init reset the staged reducer to
     * genesis and capped the fold at the SHA3 checkpoint anchor. Drive the fold
     * to the anchor, write + HARD-ASSERT the snapshot artifact, then exit. The
     * driver _exit()s FATAL on a checkpoint mismatch; a clean return means a
     * verified mint (true) or an incomplete fold (false → exit non-zero so the
     * operator knows the bodies were missing). app_init returns before
     * app_init_services on this path, so frontend/P2P/runtime services never
     * start while -mint-anchor-fast can be armed. */
    if (ctx->mint_anchor) {
        bool minted = boot_mint_anchor_run(ctx->datadir);
        /* minted==true means the fold reached its target AND (where
         * applicable) its consensus-state bundle export already succeeded —
         * durably, before this shutdown call — so a stalled non-critical
         * offline worker below must not force a false unclean exit. */
        app_shutdown_offline(minted);
        *rc = minted ? 0 : 1;
        return true;
    }

    /* -coldstart-seed-oneshot: app_init applied the snapshot seed and returned
     * before services (engine/composition/src/boot.c). Cleanly WAL-checkpoint + write the
     * clean-shutdown marker and exit so the cold-start driver's next stage
     * boots warm on a durable, clean-stopped datadir. */
    if (ctx->cold_start_seed_oneshot) {
        app_shutdown_offline(false);
        *rc = 0;
        return true;
    }
    return false;
}

static void main_wire_explicit_addnodes(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "-addnode=", 9) == 0)
            app_add_node(argv[i] + 9, 0);
        else if (strncmp(argv[i], "-connect=", 9) == 0)
            app_add_node(argv[i] + 9, 0);
        else if (strncmp(argv[i], "-addnode-file=", 14) == 0)
            app_add_nodes_from_file(argv[i] + 14);
    }
}

/* Reads the P2P port out of an open zclassic.conf (default 8034). Last
 * accepted `port=` line wins, exactly as the original in-line loop did. */
static int main_read_zclassicd_p2p_port(FILE *cf)
{
    int p2p_port = 8034;
    char line[256];
    while (fgets(line, sizeof(line), cf)) {
        int v;
        if (sscanf(line, " port = %d", &v) == 1 ||
            sscanf(line, "port=%d", &v) == 1) {
            if (v > 0 && v < 65536) p2p_port = v;
        }
    }
    return p2p_port;
}

static bool main_argv_mentions_hostport(int argc, char **argv,
                                        const char *hostport)
{
    for (int i = 1; i < argc; i++) {
        if (strstr(argv[i], hostport) != NULL)
            return true;
    }
    return false;
}

/* Auto-addnode the co-located zclassicd peer (Option F from the
 * fast-sync plan). Local loopback bypasses external network
 * latency entirely; zclassicd is a fully-validated reference node
 * sharing the same chain. Connecting to it gives us tip-tracking
 * resilience even if all internet peers go away.
 *
 * Conservative — only auto-add when:
 *   - $HOME/.zclassic/zclassic.conf is present (zclassicd is set up)
 *   - we haven't been told -connect=… (which means "ONLY these peers")
 *   - no explicit -addnode=127.0.0.1:8034 already on the command line
 *
 * Reads the P2P port out of zclassic.conf (default 8034). */
static void main_auto_addnode_local_zclassicd(int argc, char **argv,
                                              const struct app_context *ctx)
{
    if (ctx->connect_only)
        return;
    const char *home = getenv("HOME");
    if (!home || !*home)
        return;
    char conf_path[1024];
    snprintf(conf_path, sizeof(conf_path),
             "%s/.zclassic/zclassic.conf", home);
    FILE *cf = fopen(conf_path, "r");
    if (!cf)
        return;
    int p2p_port = main_read_zclassicd_p2p_port(cf);
    fclose(cf);
    char hostport[64];
    snprintf(hostport, sizeof(hostport), "127.0.0.1:%d", p2p_port);
    bool already_listed = main_argv_mentions_hostport(argc, argv, hostport);
    if (p2p_port == ctx->p2p_port) {
        printf("auto-addnode: skipped local zclassicd candidate "
               "%s because it is this node's listening endpoint\n",
               hostport);
    } else if (args_should_auto_add_local_peer(
                   ctx->connect_only, ctx->p2p_port, p2p_port,
                   already_listed)) {
        printf("auto-addnode: local zclassicd at %s "
               "(zclassic.conf detected)\n", hostport);
        app_add_node("127.0.0.1", p2p_port);
    }
}

static void main_run_service_loop(const struct app_context *ctx,
                                  bool show_metrics)
{
    /* Prometheus `zcl_rpc_*` counter source. Unconditional: the dump is
     * served on demand (native `meta`, HTTPS, RPC HTTP) even on a node run
     * with -showmetrics=0, where the metrics thread below never starts. */
    app_wire_metrics_sources();

    if (show_metrics) app_start_metrics(ctx->gen);

    while (!g_shutdown_requested &&
           !thread_registry_shutdown_requested() &&
           app_is_running())
        sleep(1);
    if (thread_registry_shutdown_requested())
        g_shutdown_requested = 1;

    if (show_metrics) app_stop_metrics();
}

int main(int argc, char **argv)
{
    int rc = 0;
    if (main_dispatch_dev_ui_modes(argc, argv, &rc))
        return rc;

    ParseParameters(argc, (const char *const *)argv);

    /* <datadir>/z23.conf, read AFTER argv so the command line always wins
     * (ReadConfigFile skips any key argv already set). This is how a setting
     * persisted by `z23 join` reaches the next boot without anyone editing a
     * service unit; a missing file is the normal case and changes nothing.
     *
     * The datadir comes from a scan of the WHOLE argv, not from the argument
     * table: ParseParameters stops at the first non-'-' token, so a CLI
     * invocation (`z23 zcode ... -datadir=DIR`) parses no flags at all and the
     * table would name the DEFAULT datadir — i.e. the operator's live node
     * rather than the instance they explicitly targeted. */
    {
        char conf_datadir[4096];
        char conf_path[4600];
        (void)ArgvDataDir(argc, (const char *const *)argv, conf_datadir,
                          sizeof(conf_datadir));
        GetConfigFilePath(conf_datadir, conf_path, sizeof(conf_path));
        (void)ReadConfigFile(conf_path);
    }

    apply_argv_loglevel();

    if (main_dispatch_standalone_mode(argc, argv, &rc))
        return rc;

    if (main_dispatch_gui_mode(argc, argv, &rc))
        return rc;

    /* Node mode */
    struct app_context ctx;
    char default_datadir[512];
    char default_paramsdir[512];
    main_init_node_context(&ctx, default_datadir, sizeof(default_datadir),
                           default_paramsdir, sizeof(default_paramsdir));

    bool show_metrics = true;

    /* Node-mode flag ladder lives in engine/composition/src/args.c. It fills ctx +
     * show_metrics and returns -1 to continue, or an exit code to return
     * (--help/--version -> 0, a bad -profile=/-operator-lane= -> 1). */
    int argrc = args_parse_node_options(argc, argv, &ctx, &show_metrics);
    if (argrc >= 0)
        return argrc;

    int flagrc = main_check_mint_and_fold_flags(&ctx);
    if (flagrc >= 0)
        return flagrc;

    main_run_filesync_if_requested(argc, argv, &ctx);

    setvbuf(stdout, NULL, _IOLBF, 0);
    setvbuf(stderr, NULL, _IOLBF, 0);
    /* Install SIGINT/SIGTERM via sigaction, NOT signal(). Under this build's
     * feature-test macros (_POSIX_C_SOURCE without _DEFAULT_SOURCE) glibc's
     * signal() gives System V ONE-SHOT semantics: the disposition resets to
     * SIG_DFL the instant the handler fires. signal_handler() never re-armed
     * it, so the FIRST SIGTERM ran the handler AND reverted SIGTERM to default —
     * and the SECOND SIGTERM (systemd ExecStop sends pulses 2 s apart) then
     * killed the process with default disposition, silently, mid-shutdown,
     * before the WAL checkpoint + clean-shutdown marker. sigaction without
     * SA_RESETHAND keeps the handler installed so repeated SIGTERMs are
     * absorbed idempotently (the handler's own g_shutdown_requested guard). */
    if (signal_handler_install_termination(signal_handler) != 0) {
        fprintf(stderr, "FATAL: could not install node termination handlers\n");
        return 1;
    }

    /* -connect mode: only connect to specified peers, no seeds. The peer
     * floor condition is exempt too: its remedy ladder (seed discovery,
     * rotation) is inert by design in this mode, so measuring the pinned
     * set against the fleet floor only accrues false operator_needed
     * episodes (the replay canary hit 34 in 45 minutes). */
    if (ctx.connect_only) {
        extern bool g_connect_only;
        g_connect_only = true;
        peer_floor_violated_set_connect_only(true);
    }

    printf("z23 starting (datadir=%s)...\n", ctx.datadir);
    /* Fleet ROLES. The catalog and the signed grant store live in tools/dev
     * and the two ingress points that consult them live under engine/,
     * which may not include a tools/ header — so this is the one place that
     * joins the two, exactly as it already joins every other adapter only
     * the top of the tree can see. Until this call returns, both ingress
     * points refuse every foreign-signed row and post, which is the right
     * state for a process that has not been told where its store is. It
     * also mints the worker grant every already-enrolled machine implies,
     * so a fleet that was replicating before roles existed still is. */
    zcl_fleet_roles_enforcement_start(ctx.datadir);
    rpc_agent_set_boot_context(app_operator_lane_name(ctx.operator_lane),
                               app_runtime_profile_name(ctx.runtime_profile),
                               ctx.datadir, ctx.rpc_port, ctx.p2p_port,
                               ctx.https_port, ctx.fs_port);

    /* #8 — capture argv for a possible in-process self-respawn (the watchdog
     * sets the respawn flag for a genuine-liveness stall when off-systemd).
     * The decision + re-exec live in engine/composition/src/boot_self_respawn.c so every
     * shutdown exit point (here AND the straggler-guard _exit in
     * boot_services_shutdown.c) honors an armed request identically.
     * This must receive the REAL process argv — never a synthetic array. */
    boot_self_respawn_set_argv(argv);

    int bootrc = main_check_boot_guards(&ctx);
    if (bootrc >= 0)
        return bootrc;

    if (main_app_init_and_one_shots(&ctx, &rc))
        return rc;

    main_wire_explicit_addnodes(argc, argv);
    main_auto_addnode_local_zclassicd(argc, argv, &ctx);
    main_run_service_loop(&ctx, show_metrics);

    /* #8 — S7 / Pillar 7: if the chain-tip watchdog OR the supervisor backstop
     * requested a self-respawn (genuine-liveness stall / frozen root sweep with
     * NO systemd notify socket), shut down cleanly and then re-exec this binary
     * in-process so liveness recovery does not depend on Restart=always. Under
     * systemd the flags are never honored (sd_notify_is_active()==true), so
     * boot_self_respawn_exec_or_return() is a no-op here and the normal exit
     * happens. The bounded restart budget persisted in progress.kv is reloaded
     * by the fresh boot, so self-respawn is bounded exactly like a systemd
     * restart and cannot loop unbounded.
     *
     * The decision + execv are centralized in engine/composition/src/boot_self_respawn.c
     * so the straggler-guard _exit path in boot_services_shutdown.c (a
     * background worker missed its join window; the destructive frees are
     * skipped and the process exits early) honors an armed respawn the SAME
     * way — an early exit there used to silently drop the request off-systemd,
     * leaving the node DOWN. */
    app_shutdown();
    boot_self_respawn_exec_or_return();
    return 0;
}
