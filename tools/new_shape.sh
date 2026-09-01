#!/usr/bin/env bash
# new_shape.sh — Workstream A5 shape-skeleton generator (FRAMEWORK.md Law 3:
# "declare the spec; generate the code. The easy path is the correct path.")
#
# Emits a correct, compiling, *readable* skeleton for one of four shapes into
# the right shape folder under app/. The output is plain committed C a human
# can read and gdb can step — NOT metaprogramming. Each skeleton matches the
# exemplar for its shape exactly so it passes the framework lint gates the day
# it lands:
#
#   condition  -> engine/conditions/src/<name>.c
#                 ({detect,remedy,witness} struct + register fn; E3 shape
#                  header "framework/condition.h")
#   model      -> engine/models/src/<name>.c
#                 (DEFINE_MODEL_CALLBACKS + validates_* + AR_*_SAVE lifecycle;
#                  E3 "models/" header, Move-11 validation coverage)
#   job        -> engine/jobs/src/<name>_stage.c
#                 (cursor-stamped advance-or-block step; E5 JOB_BLOCKED/IDLE +
#                  cursor reference)
#   controller -> engine/controllers/src/<name>_controller.c
#                 (parse -> one service call -> return; route table)
#   scenario   -> tools/sim/scenarios/<name>.scenario
#                 (chaos DSL skeleton: mode simnet + a small honest cluster +
#                  a mint/relay/deliver round + the standard convergence
#                  expects; see docs/CHAOS_HARNESS.md and `make chaos`)
#
# Usage (normally via the Makefile targets, but callable directly):
#   tools/new_shape.sh <shape> <NAME>
#     shape = condition | model | job | controller | scenario
#     NAME  = lowercase snake_case entity, e.g. utxo_drift_detected, peer
#             (for scenario: the .scenario basename, e.g. detective_80_honest)
#
# It refuses to overwrite an existing file. After writing it prints the one
# manual wiring step (add to the shape's registry) — the generator never edits
# a registry for you, because that is a reviewed decision, not boilerplate.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

die() { echo "new_shape: $*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: new_shape.sh <condition|model|job|controller> <name>"

SHAPE="$1"
NAME="$2"

# Validate NAME: lowercase, digits, underscores; must start with a letter.
[[ "$NAME" =~ ^[a-z][a-z0-9_]*$ ]] || \
    die "NAME must be lowercase snake_case starting with a letter (got: '$NAME')"

YEAR="$(date +%Y)"
LICENSE="/* Copyright ${YEAR} Rhett Creighton - Apache License 2.0 */"

# Refuse to clobber. $1 = absolute target path.
guard_new() {
    if [ -e "$1" ]; then
        die "refusing to overwrite existing file: $1"
    fi
}

emit_condition() {
    local out="$ROOT/engine/conditions/src/${NAME}.c"
    guard_new "$out"
    mkdir -p "$(dirname "$out")"
    cat > "$out" <<EOF
${LICENSE}
/*
 * Condition: ${NAME}
 *
 * One file per halt class (FRAMEWORK.md §3.6). The engine owns poll,
 * backoff, max-attempts, witness, and EV_OPERATOR_NEEDED paging — this
 * file is only the three honest predicates plus the registration.
 *
 *   detect()  reads model/projection state; true => symptom present.
 *   remedy()  calls ONE service to fix it; returns OK/FAILED/SKIP.
 *   witness() observable post-condition; true => the symptom is gone.
 *
 * Doctrine (Law 7): a remedy that returns OK without moving the symptom is
 * a lie. The engine downgrades an un-witnessed OK to UNWITNESSED for you;
 * make witness() observe the real effect, not the attempt.
 */

#include "framework/condition.h"
#include "util/log_macros.h"

#include <stdatomic.h>

/* Snapshot of what detect() saw, so remedy()/witness() act on the same
 * target rather than re-reading a moving tip. */
static _Atomic int64_t g_target_at_detect = -1;

static bool detect_${NAME}(void)
{
    /* TODO: read model/projection state. Return true when the symptom is
     * present. On true, stash the target so remedy/witness agree. */
    struct main_state *ms = condition_engine_main_state();
    (void)ms;

    bool symptom_present = false; /* TODO: real predicate */
    if (symptom_present) {
        atomic_store(&g_target_at_detect, /* TODO target */ -1);
        return true;
    }
    return false;
}

static enum condition_remedy_result remedy_${NAME}(void)
{
    /* TODO: call ONE service to remediate. Return:
     *   COND_REMEDY_OK     — remedy applied (witness still confirms it),
     *   COND_REMEDY_FAILED — remedy attempted and failed,
     *   COND_REMEDY_SKIP   — nothing to do this poll (no attempt charged).
     * Never return COND_REMEDY_UNWITNESSED — the engine synthesises that. */
    int64_t target = atomic_load(&g_target_at_detect);
    LOG_WARN("condition", "[condition:${NAME}] remedy target=%lld", (long long)target);
    return COND_REMEDY_SKIP;
}

static bool witness_${NAME}(int64_t target_at_detect)
{
    (void)target_at_detect;
    /* TODO: observe that the symptom is actually gone. Must be the EFFECT,
     * not the attempt. Return true once cleared. */
    return false;
}

static struct condition c_${NAME} = {
    .name                = "${NAME}",
    .severity            = COND_WARN,   /* TODO: COND_INFO/WARN/CRITICAL */
    .poll_secs           = 5,
    .backoff_secs        = 30,
    .max_attempts        = 5,
    .detect              = detect_${NAME},
    .remedy              = remedy_${NAME},
    .witness             = witness_${NAME},
    .witness_window_secs = 60,
};

void register_${NAME}(void)
{
    (void)condition_register(&c_${NAME});
}
EOF
    echo "wrote $out"
    cat <<EOF

NEXT — add one ordered manifest row (it generates declaration, registration,
and regression expectations):
  engine/conditions/include/conditions/condition_registry.def
    add:  ZCL_CONDITION(${NAME})
EOF
}

emit_model() {
    local out="$ROOT/engine/models/src/${NAME}.c"
    guard_new "$out"
    mkdir -p "$(dirname "$out")"
    cat > "$out" <<EOF
${LICENSE}
/*
 * ActiveRecord model: ${NAME}
 *
 * The only reader/writer of its persistent table (Law 2: one way in, one
 * way out). Every write goes through the AR lifecycle:
 *   validate -> before_save -> AR_*_SAVE (the ONLY step path)
 *   -> after_save.
 * A raw sqlite3 step in app code is a compile error.
 *
 * validates :id, presence: true
 * validates :height, numericality: { >= 0 }
 */

#include "models/activerecord.h"   /* E3 shape header: AR lifecycle + validates_* */
#include "util/log_macros.h"
#include <string.h>
#include <stdio.h>

/* A dense, POD record (Law 5: fat models, lean structs). Replace these
 * fields with the real columns; keep it cache-friendly. Lives in a model
 * header (engine/models/include/models/${NAME}.h) once the table is real. */
struct db_${NAME} {
    int64_t id;
    int     height;
};

/* Generates db_${NAME}_callbacks() — the per-model hook registry. */
DEFINE_MODEL_CALLBACKS(${NAME})

/* before_save: reject records that violate an invariant the schema can't. */
static bool ${NAME}_before_save(void *record, void *ctx)
{
    (void)ctx;
    const struct db_${NAME} *r = record;
    if (r->height < 0) {
        LOG_WARN("${NAME}", "[${NAME}] before_save REJECTED: negative height %d", r->height);
        return false;
    }
    return true;
}

static void ${NAME}_init_hooks(void)
{
    static bool done = false;
    if (done) return;
    struct ar_callbacks *cbs = db_${NAME}_callbacks();
    ar_register_before_save(cbs, ${NAME}_before_save);
    done = true;
}

/* ── Validation ────────────────────────────────────────────────── */

bool db_${NAME}_validate(const struct db_${NAME} *r, struct ar_errors *errors)
{
    ar_errors_clear(errors);
    validates_non_negative(errors, r, height);
    /* TODO: add validates_presence_of / validates_max / validates_custom. */
    return !ar_errors_any(errors);
}

/* ── Save ──────────────────────────────────────────────────────── */

/* TODO: take the real handle (struct node_db * or a progress_store/kernel-db
 * wrapper), prepare/bind the INSERT, and step it through an AR_*_SAVE macro — never a
 * raw sqlite3 step call. The skeleton below shows the lifecycle shape with the
 * AR_BEGIN_SAVE guard; fill in the bind + step against your statement.
 *
 * Example (cached-statement form):
 *   struct ar_callbacks *cbs = db_${NAME}_callbacks();
 *   AR_BEGIN_SAVE(cbs, "${NAME}", r, db_${NAME}_validate);
 *   AR_CACHED_SAVE(handle, stmt, r, AR_BIND_INT(stmt, 1, r->height); ...);
 *   ar_run_after_save(cbs, (void *)r);
 */
bool db_${NAME}_save(const struct db_${NAME} *r)
{
    if (!r) return false;
    ${NAME}_init_hooks();

    struct ar_errors errors;
    if (!db_${NAME}_validate(r, &errors)) {
        LOG_WARN("${NAME}", "[${NAME}] save validation failed: %s", ar_errors_full(&errors));
        return false;
    }

    /* TODO: AR_*_SAVE against the real statement, then ar_run_after_save. */
    return true;
}
EOF
    echo "wrote $out"
    cat <<EOF

NEXT — for a model with a persistent table:
  - declare struct db_${NAME} and the public fns in a header under
    engine/models/include/models/${NAME}.h (it must #include "models/activerecord.h").
  - prepare/cache the INSERT statement on your db handle (node_db or a
    progress_store/kernel-db wrapper) and step it through an AR_*_SAVE macro.
  - critical models (utxo/block/wallet_*) must keep a before_save hook
    (check-before-save-hooks gate).
EOF
}

emit_job() {
    # Jobs are always *_stage.c (the lint gate and folder convention expect it).
    local base="${NAME%_stage}_stage"
    local out="$ROOT/engine/jobs/src/${base}.c"
    local stage_name="${NAME%_stage}"
    guard_new "$out"
    mkdir -p "$(dirname "$out")"
    cat > "$out" <<EOF
${LICENSE}
/*
 * Job stage: ${stage_name}
 *
 * A Job (FRAMEWORK.md §3.4) is the single-purpose, idempotent step the
 * supervisor ticks. Its only verb is advance-a-durable-cursor or
 * name-a-typed-blocker. Re-running at the same cursor is a no-op. The F-2
 * stage primitive (sync/stage.h) owns the cursor persistence and replay;
 * this file is just the step body + init/shutdown glue.
 *
 * Contract (E5 gate, HARD): the step MUST be honest about non-progress —
 * return JOB_BLOCKED (with a typed blocker) or JOB_IDLE on any non-advancing
 * path, and it MUST reason about its cursor. It never spins forward silently.
 */

#include "sync/stage.h"
#include "util/blocker.h"
#include "util/log_macros.h"
#include "storage/progress_store.h"
#include "platform/time_compat.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

#define STAGE_NAME "${stage_name}"

static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static stage_t *g_stage = NULL;
static _Atomic uint64_t g_advanced_total = 0;
static _Atomic int64_t  g_last_step_unix = 0;

/* ── Step body ─────────────────────────────────────────────────────── */

static job_result_t step_${stage_name}(struct stage_step_ctx *c)
{
    atomic_store(&g_last_step_unix, platform_time_wall_unix());

    /* c->cursor_in is this stage's durable position (the height/index it is
     * about to process). Read the input fact for that position. */
    int64_t pos = (int64_t)c->cursor_in;
    if (pos < 0) return JOB_FATAL;

    bool input_ready = false;  /* TODO: is the fact for `pos` available? */
    if (!input_ready) {
        /* Nothing to do yet — IDLE (not an error, not a stall). */
        return JOB_IDLE;
    }

    bool can_make_progress = true;  /* TODO: real predicate */
    if (!can_make_progress) {
        /* Name the gap precisely so the stall is visible at a known cursor. */
        blocker_init(&c->blocker, STAGE_NAME,
                     "missing_input",
                     BLOCKER_TRANSIENT,
                     "describe exactly what is missing at this cursor");
        return JOB_BLOCKED;
    }

    /* TODO: do the work for `pos` (validate + append fact / write delta). */

    c->cursor_out = c->cursor_in + 1;     /* advance the durable cursor */
    atomic_fetch_add(&g_advanced_total, 1);
    return JOB_ADVANCED;
}

/* ── Public API ────────────────────────────────────────────────────── */

bool ${stage_name}_stage_init(void)
{
    if (!progress_store_db())
        LOG_FAIL("${stage_name}", "init: progress_store not open");

    pthread_mutex_lock(&g_lock);
    if (g_stage != NULL) {
        pthread_mutex_unlock(&g_lock);
        return true;  /* idempotent */
    }
    stage_t *s = stage_create(STAGE_NAME, step_${stage_name}, NULL);
    if (!s) {
        pthread_mutex_unlock(&g_lock);
        LOG_FAIL("${stage_name}", "init: stage_create failed");
    }
    g_stage = s;
    pthread_mutex_unlock(&g_lock);
    LOG_INFO("${stage_name}", "[${stage_name}] stage initialised");
    return true;
}

job_result_t ${stage_name}_stage_step_once(void)
{
    if (!g_stage) return JOB_IDLE;
    sqlite3 *db = progress_store_db();
    if (!db) return JOB_IDLE;
    return stage_run_once(g_stage, db);
}

void ${stage_name}_stage_shutdown(void)
{
    pthread_mutex_lock(&g_lock);
    if (g_stage) {
        stage_destroy(g_stage);
        g_stage = NULL;
    }
    atomic_store(&g_advanced_total, (uint64_t)0);
    atomic_store(&g_last_step_unix, (int64_t)0);
    pthread_mutex_unlock(&g_lock);
}

uint64_t ${stage_name}_stage_cursor(void)
{
    return g_stage ? stage_cursor(g_stage) : 0;
}
EOF
    echo "wrote $out"
    cat <<EOF

NEXT — wire the stage into its supervisor and (optionally) the diagnostics dump:
  - call ${stage_name}_stage_init() from the staged-sync supervisor
    (engine/supervisors/src/staged_sync_supervisor.c) and tick
    ${stage_name}_stage_step_once() on its schedule.
  - declare the public fns in a header under engine/jobs/include/jobs/${base}.h.
  - to expose runtime state via z23 dumpstate, add a *_dump_state_json and register
    it (see CLAUDE.md "Adding state introspection").
EOF
}

emit_controller() {
    local out="$ROOT/engine/controllers/src/${NAME}_controller.c"
    guard_new "$out"
    mkdir -p "$(dirname "$out")"
    local upper
    upper="$(echo "$NAME" | tr '[:lower:]' '[:upper:]')"
    cat > "$out" <<EOF
${LICENSE}
/*
 * ${NAME} Controller — parse -> authorize -> call ONE service -> return.
 *
 * Dumb glue (FRAMEWORK.md §3, Controller contract): no business logic, no
 * direct storage, no swallowing errors. It only marshals request params into
 * a typed service call and renders the service's result as JSON. Keep the
 * business rules in the service.
 */

#include "rpc/server.h"
#include "controllers/strong_params.h"   /* RPC_HELP + param parsing */
#include "json/json.h"
#include "util/log_macros.h"

/* TODO: #include "services/${NAME}_service.h" — the one service this
 * controller delegates to. */

/* ── RPC: ${NAME} ───────────────────────────────────────────────── */

static bool rpc_${NAME}(const struct json_value *params, bool help,
                        struct json_value *result)
{
    RPC_HELP(help, result,
        "${NAME}\n"
        "\nTODO: one-line description of what this returns.\n"
        "\nResult: object.");

    (void)params;
    json_set_object(result);

    /* TODO: parse params -> call ONE service -> render result. On failure,
     * set an explanatory error body and return false (never a bare return). */

    json_push_kv_str(result, "status", "ok");
    return true;
}

/* ── Registration ────────────────────────────────────────────────── */

void register_${NAME}_rpc_commands(struct rpc_table *t)
{
    struct rpc_command cmds[] = {
        { "${NAME}", "${NAME}", rpc_${NAME}, true },
    };
    for (size_t i = 0; i < sizeof(cmds) / sizeof(cmds[0]); i++)
        rpc_table_must_append(t, &cmds[i]);
}
EOF
    echo "wrote $out"
    cat <<EOF

NEXT — wire the controller into RPC registration:
  - declare void register_${NAME}_rpc_commands(struct rpc_table *t); in a
    header under engine/controllers/include/controllers/${NAME}_controller.h
  - call register_${NAME}_rpc_commands(t) where the other controllers are
    registered (grep for register_health_rpc_commands).
  - (used the placeholder category "${NAME}" / "${upper}"; rename to a real
    RPC group as appropriate.)
EOF
}

emit_scenario() {
    local out="$ROOT/tools/sim/scenarios/${NAME}.scenario"
    guard_new "$out"
    mkdir -p "$(dirname "$out")"
    cat > "$out" <<EOF
# Scenario: ${NAME}
#
# TODO: describe what this scenario demonstrates — which invariant, which
# honest/byzantine mix, which fault (partition/heal, reorg, ...), and what
# convergence property is being proven. See docs/CHAOS_HARNESS.md and the
# checked-in examples (simnet_partition_heal.scenario,
# simnet_competing_reorg.scenario, detective_100_80.scenario) for the
# real-cluster (mode simnet) verb set:
#   simnet_nodes N [honest=<permille>]   create an N-node cluster; permille
#                                         0..1000 (1000=all honest, default);
#                                         node 0 is always honest
#   simnet_mint node=I                   mint on node I (byzantine nodes
#                                         forge an invalid block instead)
#   simnet_relay node=I                  broadcast node I's un-relayed mints
#   simnet_deliver                       drain the deterministic delivery queue
#   simnet_partition a=I b=J             sever the I<->J link
#   simnet_heal a=I b=J                  restore I<->J + resync both ways

seed 0xDEADBEEF00000000
mode simnet
simnet_nodes 4 honest=1000

simnet_mint node=0
simnet_relay node=0
simnet_deliver

expect simnet_converged == 1
expect simnet_tip_monotonic == 1
expect no_crash
EOF
    echo "wrote $out"
    cat <<EOF

NEXT — fill in the TODO header, tune simnet_nodes/honest= and the
mint/relay/deliver/partition/heal sequence for what you're proving, then
run it standalone:
  build/bin/zclassic23-chaos --scenario="$out"
It is picked up automatically by \`make chaos\` (every
tools/sim/scenarios/*.scenario must pass) — no registry edit needed.
EOF
}

case "$SHAPE" in
    condition)  emit_condition ;;
    model)      emit_model ;;
    job)        emit_job ;;
    controller) emit_controller ;;
    scenario)   emit_scenario ;;
    *) die "unknown shape '$SHAPE' (expected: condition | model | job | controller | scenario)" ;;
esac
