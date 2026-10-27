/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Node-mode flag/argv parsing surface (engine/composition/src/args.c). Split out of
 * engine/entry/main.c (pure code motion); called from engine/entry/main.c's main() and, for
 * print_usage(), from the CLI client in src/main_cli_modes.c.
 */
#ifndef ZCLASSIC23_CONFIG_ARGS_H
#define ZCLASSIC23_CONFIG_ARGS_H

#include <stdbool.h>
#include <stddef.h>

struct app_context;

/* ── Operator-target flag policy (shared: daemon WARN + CLI-client refusal) ──
 *
 * A double-dash typo of an operator-target flag (e.g. `--port=39071` for
 * `-port=`) with no `-datadir=` must never make
 * `is_cli_mode()` bail out and boot a full node against the DEFAULT
 * datadir — the live node's directory. The seven flags below are the ones
 * that select WHICH node an invocation targets (datadir/rpcport/port/
 * httpsport/fsport/operator-lane/profile) and therefore the ones whose
 * silent mis-typing is genuinely dangerous — not the much larger set of
 * opaque RPC/native-command params (`--input=`, `--next`, `--format=json`,
 * `field=...`) that must keep working unexamined. cli_flag_classify()
 * recognizes exactly two malformed shapes of these seven: a double-dash
 * variant (`--rpcport=...`) and a bare single-dash form missing its `=value`
 * (`-rpcport` alone) — both are unambiguous typos of a known flag, never a
 * legitimate opaque param. Anything else returns CLI_FLAG_OK, including a
 * flag this policy simply doesn't know about (e.g. `-tor`) — refusing those
 * too is out of scope; they don't create the default-datadir hazard. */
enum cli_flag_kind {
    CLI_FLAG_OK = 0,           /* not one of the seven flags, or correctly
                                 * formed (single dash + value) — no action. */
    CLI_FLAG_DOUBLE_DASH_TYPO, /* "--datadir=..." / "--datadir" (bare) */
    CLI_FLAG_MISSING_VALUE,    /* "-datadir" with no "=value" at all */
};

/* Classify one argv token. On CLI_FLAG_DOUBLE_DASH_TYPO / CLI_FLAG_MISSING_
 * VALUE, writes the correctly-formed flag (e.g. "-rpcport=PORT") into
 * `suggest` (size >= 24; ignored if NULL/suggest_cap == 0). Pure — no side
 * effects, safe to call from both engine/composition/src/args.c (daemon WARN) and
 * engine/entry/main_cli_modes.c (CLI-client hard refusal). */
enum cli_flag_kind cli_flag_classify(const char *arg, char *suggest,
                                     size_t suggest_cap);

/* The client spells two target flags with either dash count: `--datadir=DIR`
 * and `--rpcport=N` mean exactly `-datadir=DIR` and `-rpcport=N`. Returns the
 * single-dash form of such a well-formed token (a pointer into `arg`), and
 * `arg` itself for every other token, including a value-less `--datadir`,
 * which stays a typo. cli_flag_classify() is unchanged and still reports the
 * double-dash form for the daemon WARN. */
char *cli_flag_normalize_target(char *arg);

/* Comma-joined "-name=PLACEHOLDER" listing of every operator-target flag
 * cli_flag_classify() recognizes, for refusal/diagnostic text. Returns a
 * static internal buffer — read-only, single-threaded CLI process only. */
const char *cli_flag_client_whitelist_csv(void);

/* Length bound of the operator-target datadir buffer the CLI clients
 * copy -datadir= / ZCL_DATADIR into. The env path refuses over this
 * bound already; the argv flag is validated next to cli_flag_classify
 * so cli_main's exact complexity pin does not move. */
#define CLI_TARGET_DATADIR_CAP 512

/* True when arg is a well-formed -datadir= whose value cannot fit the
 * operator-target path buffer. */
bool cli_flag_value_overflows_path_buffer(const char *arg);

/* Refuse the whole CLI-client invocation when a -datadir= flag value
 * does not fit the operator-target path buffer: a chopped cookie
 * directory can name another node's directory, so the client must
 * never authenticate from a truncated path. Prints the
 * error=DATADIR_TOO_LONG diagnostic and returns
 * ZCL_COMMAND_EXIT_INVALID; never returns to let the caller continue. */
int cli_refuse_overlong_datadir(const char *arg);

/* Decide whether node mode may auto-add the co-located legacy peer.  A
 * zclassic.conf whose P2P port equals this process's listening port describes
 * this node (or a stale/shared config), not an independent oracle.  Dialling
 * it creates a permanent self-connection retry loop, so equality is an
 * unconditional refusal.  Pure and exported so the production decision is
 * covered without starting a daemon. */
bool args_should_auto_add_local_peer(bool connect_only, int own_p2p_port,
                                     int legacy_p2p_port,
                                     bool already_listed);

/* Whether the -onion-persist default (no explicit -onion-persist or
 * -onion-persist=0/1 on the command line) should resolve to ON: true when
 * -tor is given together with at least one -addnode= peer whose value
 * contains ".onion". There is no separate "-fleet"/devfleet profile flag in
 * this binary, so pinning at least one peer by onion address is the
 * existing signal for "this node needs peers to find it at a fixed
 * address" — the same reason -onion-persist exists at all. Pure and
 * exported so the default is covered without booting Tor. */
bool args_onion_persist_default(bool tor, const char *const *addnode_peers,
                                int n_addnode_peers);

/* The -help / --help usage text. */
void print_usage(const char *prog);
void print_usage_all(const char *prog);

/* Apply -loglevel=<all|info|warn|error|fatal|off> if present (default: no
 * change). An unrecognized value warns, never aborts. */
void apply_argv_loglevel(void);

/* The node-mode strcmp(argv) flag ladder. Fills *ctx and *show_metrics.
 * Returns -1 to continue booting; a value >= 0 is an exit code the caller
 * must return from main() (e.g. --help / --version -> 0, a bad -profile= or
 * -operator-lane= or the removed -assumevalid -> 1). The silent-ignore of
 * unrecognized flags (with a loud one-line WARNING) is preserved exactly. */
int args_parse_node_options(int argc, char **argv, struct app_context *ctx,
                            bool *show_metrics);

#endif /* ZCLASSIC23_CONFIG_ARGS_H */
