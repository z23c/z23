/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * The `make_lint_gates` self-test family: it runs the self-test of every lint
 * gate, so a loosened gate pattern cannot silently stop catching violations.
 * Every check has the same shape:
 *
 *   1. Copy a known-bad fixture into the scanned tree under a unique temp name.
 *   2. Run the gate.
 *   3. Assert exit code != 0 (the gate caught the fixture).
 *   4. Remove the temp file and rerun to confirm the gate passes again.
 *
 * The checks live in the sibling lint_gate_*.c files, grouped by gate family;
 * lint_gate_selftests.h is the map and shared surface. This file owns the
 * entry table (g_lint_gate_entries, the partitioned checks and their lanes),
 * the partition that hands each entry to exactly one registered test group,
 * and the per-lane runners.
 *
 * ── Lanes and registered groups ───────────────────────────────────────────
 * Each entry declares what it needs, so the family runs as several groups
 * instead of one exclusive group:
 *
 *   LINT_LANE_SANDBOX    plants fixtures, but runs entirely inside a private
 *                        reflink-or-copy clone of the worktree, leaving the
 *                        live tree untouched. Pool-eligible; spread over
 *                        LINT_GATE_SHARD_COUNT shard groups.
 *   LINT_LANE_REALROOT   needs the real .git (git grep / git ls-files /
 *                        .git/hooks) or is hermetic (its own mktemp sandbox),
 *                        but never mutates a tracked path. Pool-eligible.
 *   LINT_LANE_EXCLUSIVE  the root-file check and stale sandbox cleanup. Keeps
 *                        the name `make_lint_gates` and stays the exclusive
 *                        pre-pass, so the tree is quiet while shards build
 *                        their sandboxes.
 *
 * The group name `make_lint_gates` is kept and the shards are named
 * `make_lint_gates_shard_NN`, because --only is a substring match
 * (test_parallel.c): `make t ONLY=make_lint_gates` runs the whole family and
 * the agent_impact_rules.def rows plus agent_controller.c naming it keep
 * resolving.
 *
 * Gated by `ZCL_TESTING` so the shell-out + make invocation only fires when
 * the suite is built by `make test`; standalone compilations of test_zcl
 * without the macro silently turn this into a no-op pass. */

#define _POSIX_C_SOURCE 200809L

#include "test/test_core.h"

#include <string.h>

/* How many pool-eligible shard groups the sandbox lane is spread over; each
 * is a registered catalog row (LINT_SHARD_LIST) with its own sandbox. */
#define LINT_GATE_SHARD_COUNT 8
#define LINT_SHARD_LIST(X) \
    X(01, 0) X(02, 1) X(03, 2) X(04, 3) \
    X(05, 4) X(06, 5) X(07, 6) X(08, 7)

/* Which of this family's registered group names must run alone. The
 * scheduler (test_parallel.c) asks this file so the policy lives next to the
 * table. The match is EXACT: a prefix/substring test would mark every shard
 * exclusive and re-serialise the split. test_make_lint_gates_partition asserts
 * this predicate in both directions.
 *
 * Defined outside ZCL_TESTING: the scheduler links against it either way. */
bool lint_gates_group_is_exclusive(const char *group_name)
{
    if (!group_name) return false;
    if (strncmp(group_name, "test_", 5) == 0) group_name += 5;
    return strcmp(group_name, "make_lint_gates") == 0;
}

/* The eight private-sandbox shards are safe together, but each copies and
 * scans a source tree; keep the family in one bounded parallel quiet phase
 * before unrelated suite work. */
bool lint_gates_group_requires_quiet_pool(const char *group_name)
{
    if (!group_name) return false;
    if (strncmp(group_name, "test_", 5) == 0) group_name += 5;
#define LINT_QUIET_MATCH(tag, idx) \
    if (strcmp(group_name, "make_lint_gates_shard_" #tag) == 0) return true;
    LINT_SHARD_LIST(LINT_QUIET_MATCH)
#undef LINT_QUIET_MATCH
    return false;
}

#if defined(ZCL_TESTING) && !defined(_WIN32)

#include "lint_gate_selftests.h"
#include "platform/os_proc.h"
#include "platform/time_compat.h"

#include "devloop.h"
#include "dev_proof_observation.h"
#include "test/testcache.h"
#include "util/spawn.h"
#include "json/json.h"
#include "kernel/command_registry.h"
#include <fcntl.h>

/* Builder identities distinguish independent single-goal dispatches. */
static const char build_needs_fixture_setup[] =
    "set -eu\n"
    "stage=setup; mode=none\n"
    "trap 'status=$?; if [ \"$status\" != 0 ]; then printf \"build-needs: mode=%s stage=%s exit=%s\\n\" \"$mode\" \"$stage\" \"$status\" >&2; fi' EXIT\n"
    "for tool in make bash flock sed grep sort wc awk; do command -v \"$tool\" >/dev/null; done\n"
    "cd \"$2\"\n"
    "mkdir -p tools/dev\n"
    "cp \"$1/tools/dev/test-build-needs.mk\" tools/dev/\n"
    "sed -n '/^ZCL_TEST_BUILD_NEEDS_RUN = /,/^$/p' \"$1/Makefile\" > Makefile\n"
    "grep -q '^ZCL_TEST_BUILD_NEEDS_RUN = ' Makefile\n"
    "cat >> Makefile <<'MAKE'\n"
    "SHELL := bash\n"
    "MAKE = $(CURDIR)/build_need\n"
    "profile = $(if $(filter fixture-a,$(MAKECMDGOALS)),a,$(if $(filter fixture-b,$(MAKECMDGOALS)),b,none))\n"
    ".PHONY: run fixture-a fixture-b\n"
    "run: shared\n"
    "\t+@$(call ZCL_TEST_BUILD_NEEDS_RUN,sh ./runner,--exact=fixture)\n"
    "shared:\n\t@echo shared >> count && touch shared\n"
    "fixture-a fixture-b: shared\n"
    "\t@PROFILE=$(profile) sh ./helper $@\n"
    ".PHONY: fixture-c fixture-d fixture-e fixture-f\n"
    "fixture-c fixture-d fixture-e fixture-f: shared\n"
    "\t@PROFILE=$(profile) sh ./helper $@\n"
    "dev-bin dev-package-verifier-ensure: shared\n"
    "\t@PROFILE=$(profile) sh ./helper $@\n"
    ".PHONY: z23 zclassic23\n"
    "z23: shared\n\t@PROFILE=$(profile) sh ./helper z23\n"
    "zclassic23: z23\n"
    "MAKE\n"
    "cat > runner <<'RUNNER'\n"
    "set -eu\n"
    "[ \"$1\" = --list-build-needs ] && [ \"$2\" = --exact=fixture ] || exit 2\n"
    "if [ \"$BUILD_NEEDS_FIXTURE_MODE\" = fanout ]; then for name in a b c d e f; do printf 'fixture-%s path-%s\\n' \"$name\" \"$name\"; done; exit 0; fi\n"
    "case $BUILD_NEEDS_FIXTURE_MODE in empty) exit 0;; selector) exit 2;; covered*) printf 'dev-bin path-node\\ndev-package-verifier-ensure path-verifier\\n'; exit 0;; ensure-only) printf 'dev-package-verifier-ensure path-verifier\\n'; exit 0;; node-*) printf 'z23 path-public\\nzclassic23 path-alias\\nfixture-a path-a\\n'; exit 0;; overlap|failed|absent|missing-result) ;; *) exit 2;; esac\n"
    "printf 'fixture-a path-a\\nfixture-b path-b\\n'\n"
    "RUNNER\n"
    "cat > helper <<'HELPER'\n"
    "set -eu\n"
    "[ \"${ZCL_CHECKOUT_LOCK_HELD:-}\" = 1 ]\n"
    "case ${BUILD_NEEDS_EXPECT_JOBS:-}:$MAKEFLAGS in 1:*|*jobserver*) ;; *) echo missing-jobserver >&2; exit 3;; esac\n"
    "case $1:$PROFILE in fixture-a:a) path=path-a;; fixture-b:b) path=path-b;; fixture-[cdef]:none) path=path-${1#fixture-};; dev-bin:none) path=path-node;; dev-package-verifier-ensure:none) path=path-verifier;; z23:none) path=path-public;; *) echo wrong-profile >&2; exit 3;; esac\n"
    "echo \"$1\" >> count; touch \"$1\"\n"
    "if [ \"$1\" = z23 ]; then\n"
    "  exec 8>node-lock; flock -n 8 || { echo overlapping-node-producer >&2; exit 9; }\n"
    "  echo node >> node-producers\n"
    "  case $BUILD_NEEDS_FIXTURE_MODE in node-producer-fail) exit 5;; node-public-absent) touch path-alias; exit 0;; node-alias-absent) touch path-public; exit 0;; esac\n"
    "  touch path-public path-alias; exit 0\n"
    "fi\n"
    "case $BUILD_NEEDS_FIXTURE_MODE:$1 in covered-dev-fail:dev-bin) exit 5;; covered-fail:dev-package-verifier-ensure) exit 5;; covered-absent:dev-package-verifier-ensure) exit 0;; esac\n"
    "case $1 in dev-bin) touch producer-done;; dev-package-verifier-ensure) case $BUILD_NEEDS_FIXTURE_MODE in covered*) [ -e producer-done ];; esac;; esac\n"
    "case $BUILD_NEEDS_FIXTURE_MODE:$1 in failed:fixture-a) exit 5;; absent:fixture-a) exit 0;; esac\n"
    "if [ \"$BUILD_NEEDS_FIXTURE_MODE:$1\" = missing-result:fixture-a ]; then for record in \"$ZCL_TEST_NEED_DIR\"/*.target; do if [ \"$(cat \"$record\")\" = fixture-a ]; then mkdir \"${record%.target}.rc\"; fi; done; fi\n"
    "touch \"$path\"\n"
    "HELPER\n";

/* Measure the number of recursive builds admitted before their Makefiles are
 * parsed. A short fixture delay makes the unbounded parent fanout observable;
 * correctness requires the maximum not exceed the requested job count. */
static const char build_needs_fixture_wrapper[] =
    "cat > build_need <<'WRAPPER'\n"
    "#!/bin/sh\n"
    "set -eu\n"
    "for target do :; done\n"
    "if [ \"$target\" = all ]; then exec make \"$@\"; fi\n"
    "printf '%s\\n' \"$$\" >> dispatchers; printf '%s\\n' \"$target\" >> phases\n"
    "if [ \"$BUILD_NEEDS_FIXTURE_MODE\" != fanout ]; then exec make \"$@\"; fi\n"
    "{ flock 9; active=$(cat parse-active); active=$((active + 1)); printf '%s\\n' \"$active\" > parse-active; maximum=$(cat parse-max); if [ \"$active\" -gt \"$maximum\" ]; then printf '%s\\n' \"$active\" > parse-max; fi; } 9>parse-lock\n"
    "sleep 0.1\n"
    "rc=0; make \"$@\" || rc=$?\n"
    "{ flock 9; active=$(cat parse-active); printf '%s\\n' \"$((active - 1))\" > parse-active; } 9>parse-lock\n"
    "exit \"$rc\"\n"
    "WRAPPER\n"
    "chmod +x build_need\n";

static const char build_needs_fixture_cases[] =
    "for mode in overlap failed absent empty selector covered covered-fail covered-absent covered-dev-fail ensure-only node-aliases node-producer-fail node-public-absent node-alias-absent missing-result; do\n"
    "  stage=reset\n"
    "  rm -f count shared fixture-a fixture-b path-a path-b dispatchers phases dev-bin dev-package-verifier-ensure path-node path-verifier producer-done z23 path-public path-alias node-producers node-lock\n"
    "  case $mode in node-producer-fail) touch path-public path-alias;; esac\n"
    "  rc=0; stage=dispatch\n"
    "  BUILD_NEEDS_FIXTURE_MODE=\"$mode\" \"$1/build/bin/checkout-lock\" foreground \"$2/lock\" -- make -j2 --no-print-directory run > log 2>&1 || rc=$?\n"
    "  cat log\n"
    "  stage=outcome\n"
    "  case $mode in\n"
    "    overlap) [ \"$rc\" = 0 ]; [ -e path-a ] && [ -e path-b ];;\n"
    "    failed|absent) [ \"$rc\" != 0 ]; grep -q 'FAIL test_need_unbuildable_fixture-a' log; [ -e path-b ];;\n"
    "    missing-result) [ \"$rc\" != 0 ]; grep -q 'FAIL test_need_unbuildable_fixture-a: build result missing' log; [ -e path-a ] && [ -e path-b ];;\n"
    "    empty) [ \"$rc\" = 0 ]; [ ! -e fixture-a ] && [ ! -e fixture-b ] && [ ! -e dispatchers ];;\n"
    "    selector) [ \"$rc\" != 0 ]; [ ! -e fixture-a ] && [ ! -e fixture-b ] && [ ! -e dispatchers ];;\n"
    "    covered) [ \"$rc\" = 0 ]; [ -e path-node ] && [ -e path-verifier ];;\n"
    "    covered-fail|covered-absent) [ \"$rc\" != 0 ]; grep -q 'FAIL test_need_unbuildable_dev-package-verifier-ensure' log; [ -e path-node ];;\n"
    "    covered-dev-fail) [ \"$rc\" != 0 ]; grep -q 'FAIL test_need_unbuildable_dev-bin' log; [ ! -e dev-package-verifier-ensure ];;\n"
    "    ensure-only) [ \"$rc\" = 0 ]; [ -e path-verifier ]; [ ! -e dev-bin ];;\n"
    "    node-aliases) [ \"$rc\" = 0 ]; [ -e path-public ] && [ -e path-alias ];;\n"
    "    node-producer-fail) [ \"$rc\" != 0 ]; grep -q 'FAIL test_need_unbuildable_z23:' log; grep -q 'FAIL test_need_unbuildable_zclassic23:' log;;\n"
    "    node-public-absent) [ \"$rc\" != 0 ]; grep -q 'FAIL test_need_unbuildable_z23:' log; [ -e path-alias ];;\n"
    "    node-alias-absent) [ \"$rc\" != 0 ]; grep -q 'FAIL test_need_unbuildable_zclassic23:' log; [ -e path-public ];;\n"
    "  esac\n"
    "  case $mode in node-*)\n"
    "    stage=single-node-producer; [ \"$(wc -l < node-producers)\" -eq 1 ]\n"
    "    [ -e path-a ]; [ \"$(wc -l < dispatchers)\" -eq 2 ]\n"
    "    [ \"$(sort -u dispatchers | wc -l)\" -eq 2 ]\n"
    "    grep -qx z23 phases; grep -qx fixture-a phases;;\n"
    "  esac\n"
    "  stage=shared-once\n"
    "  [ \"$(grep -c '^shared$' count)\" = 1 ]\n"
    "  case $mode in overlap|failed|absent)\n"
    "    stage=joined-builders; [ \"$(wc -l < count)\" -eq 3 ]\n"
    "    [ \"$(wc -l < dispatchers)\" -eq 2 ]\n"
    "    stage=independent-dispatch; [ \"$(sort -u dispatchers | wc -l)\" -eq 2 ];;\n"
    "  esac\n"
    "  case $mode in covered|covered-fail|covered-absent)\n"
    "    stage=deferred-verifier; grep -qx dev-package-verifier-ensure phases; [ -e producer-done ];;\n"
    "  esac\n"
    "  stage=jobserver\n"
    "  if grep -E 'jobserver unavailable|forced in submake' log; then exit 1; fi\n"
    "  printf 'build-needs: %s OK\\n' \"$mode\"\n"
    "done\n";

static const char build_needs_fixture_parallel[] =
    "for jobs in 1 2 4; do\n"
    "  stage=parallel-reset; mode=fanout\n"
    "  rm -f path-a path-b path-c path-d path-e path-f dispatchers phases\n"
    "  printf '0\\n' > parse-active; printf '0\\n' > parse-max\n"
    "  stage=parallel-dispatch\n"
    "  BUILD_NEEDS_FIXTURE_MODE=fanout BUILD_NEEDS_EXPECT_JOBS=\"$jobs\" \"$1/build/bin/checkout-lock\" foreground \"$2/lock\" -- make -j\"$jobs\" --no-print-directory run > log 2>&1\n"
    "  cat log\n"
    "  maximum=$(cat parse-max); active=$(cat parse-active)\n"
    "  printf 'build-needs: jobs=%s max-dispatch=%s active-after=%s\\n' \"$jobs\" \"$maximum\" \"$active\"\n"
    "  stage=parallel-bound; [ \"$maximum\" -le \"$jobs\" ]; [ \"$maximum\" -ge 1 ]; [ \"$active\" = 0 ]\n"
    "  [ \"$(wc -l < dispatchers)\" -eq 6 ]\n"
    "  for name in a b c d e f; do [ -e \"path-$name\" ]; done\n"
    "  if grep -E 'jobserver unavailable|forced in submake' log; then exit 1; fi\n"
    "done\n";

static_assert(sizeof(build_needs_fixture_setup) <= 4096);
static_assert(sizeof(build_needs_fixture_cases) <= 4096);
static_assert(sizeof(build_needs_fixture_wrapper) <= 4096);
static_assert(sizeof(build_needs_fixture_parallel) <= 4096);

static int build_needs_fixture_result(bool ran,
    const struct zcl_devloop_process_result *run, int restored)
{
    int bad = !ran || run->timed_out || run->cancelled || run->output_truncated ||
              run->term_signal != 0 || run->exit_code != 0 || restored != 0;
    if (bad)
        fprintf(stderr, "build-needs: ran=%d exit=%d signal=%d timeout=%d "
            "cancelled=%d truncated=%d restored=%d output=%s\n",
            ran, run->exit_code, run->term_signal, run->timed_out,
            run->cancelled, run->output_truncated, restored, run->output);
    return bad;
}

static int build_needs_fixture_run(const char *root, const char *fixture,
    const char *script)
{
    char saved[4096];
    const char *prior = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    bool had_prior = prior != NULL;
    if (prior && strlen(prior) >= sizeof(saved)) {
        fprintf(stderr, "build-needs: process opt-in too long\n");
        return 1;
    }
    if (prior) memcpy(saved, prior, strlen(prior) + 1);
    const char *argv[] = {"env", "-i",
        "PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin", "LC_ALL=C",
        "bash", "-c", script, "build-needs",
        root, fixture, NULL};
    struct zcl_devloop_process_result run = {0};
    bool opted = setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0;
    /* The script runs about fifteen fixture makes plus a 1/2/4-job
     * dispatch loop. The bound only stops a wedge: 30 s killed a healthy
     * run at load ~100 on the gate host (11-01: timeout=1 signal=15 with
     * every printed case OK). Fixed, under the runner's 300 s silence
     * watchdog; the case assertions are unchanged. */
    enum { BUILD_NEEDS_FIXTURE_DEADLINE_MS = 180 * 1000 };
    bool ran = opted && zcl_devloop_process_run(root, argv,
                                                BUILD_NEEDS_FIXTURE_DEADLINE_MS, &run);
    int restored = had_prior ? setenv("ZCL_DEVLOOP_TEST_PROCESS", saved, 1)
                         : unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    return build_needs_fixture_result(ran, &run, restored);
}

static int t_build_needs_overlap(void)
{
    char script[sizeof(build_needs_fixture_setup) +
                sizeof(build_needs_fixture_wrapper) +
                sizeof(build_needs_fixture_cases) +
                sizeof(build_needs_fixture_parallel) - 3];
    memcpy(script, build_needs_fixture_setup, sizeof(build_needs_fixture_setup) - 1);
    memcpy(script + sizeof(build_needs_fixture_setup) - 1,
           build_needs_fixture_wrapper, sizeof(build_needs_fixture_wrapper) - 1);
    memcpy(script + sizeof(build_needs_fixture_setup) + sizeof(build_needs_fixture_wrapper) - 2,
           build_needs_fixture_cases, sizeof(build_needs_fixture_cases) - 1);
    memcpy(script + sizeof(build_needs_fixture_setup) + sizeof(build_needs_fixture_wrapper) + sizeof(build_needs_fixture_cases) - 3,
           build_needs_fixture_parallel, sizeof(build_needs_fixture_parallel));
    char fixture[PATH_MAX] = {0};
    struct stat st;
    test_make_tmpdir(fixture, sizeof(fixture), "build_needs", "overlap");
    int bad = 1;
    if (stat(fixture, &st) == 0 && S_ISDIR(st.st_mode))
        bad = build_needs_fixture_run(repo_root(), fixture, script);
    else
        fprintf(stderr, "build-needs: fixture directory setup failed: %s\n", fixture);
    if (bad) {
        if (stat(fixture, &st) == 0 && S_ISDIR(st.st_mode))
            fprintf(stderr, "build-needs: failed fixture retained: %s\n", fixture);
        return bad;
    }
    if (test_rm_rf_recursive(fixture) != 0) {
        fprintf(stderr, "build-needs: fixture cleanup failed: %s\n", fixture);
        bad = 1;
    }
    return bad;
}

/* Exercise the maintained opt-in recipe with explicit child environments.
 * No generated shell driver, desktop service, Z23 launch or real profile. */
#if defined(__linux__)
struct dti_fixture {
    char root[PATH_MAX], home[PATH_MAX], config[PATH_MAX], state[PATH_MAX];
    char cache[PATH_MAX], runtime[PATH_MAX], tools[PATH_MAX], data[PATH_MAX];
};
static bool dti_path(char out[PATH_MAX], const char *base, const char *leaf)
{
    int n = snprintf(out, PATH_MAX, "%s/%s", base, leaf);
    return n > 0 && n < PATH_MAX;
}
static bool dti_absent(const char *path)
{
    struct stat st;
    return lstat(path, &st) != 0 && errno == ENOENT;
}
static bool dti_root(struct dti_fixture *f)
{
    char fixture[PATH_MAX], cwd[PATH_MAX];
    test_make_tmpdir(fixture, sizeof(fixture), "desktop_receive", "install");
    if (fixture[0] == '/') {
        memcpy(f->root, fixture, strlen(fixture) + 1);
        return true;
    }
    return getcwd(cwd, sizeof(cwd)) && dti_path(f->root, cwd, fixture);
}
static bool dti_write(const char *path, const void *bytes, size_t size)
{
    FILE *file = fopen(path, "wb");
    if (!file) return false;
    bool ok = fwrite(bytes, 1, size, file) == size;
    return fclose(file) == 0 && ok;
}
static bool dti_equal(const char *a, const char *b)
{
    char *left = NULL, *right = NULL;
    bool ok = read_entire_file(a, &left) == 0 && read_entire_file(b, &right) == 0 &&
              !strcmp(left, right);
    free(left); free(right); return ok;
}
static bool dti_run(const struct dti_fixture *f, const char *const argv[],
    const char *data, bool restricted, struct zcl_devloop_process_result *run)
{
    const char *keys[] = {"HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME",
        "XDG_CACHE_HOME", "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "PATH"};
    const char *values[] = {f->home, f->config, f->state, f->cache, f->runtime,
        data, restricted ? f->tools : "/usr/bin:/bin"};
    char storage[7][PATH_MAX + 32]; const char *env[9];
    for (size_t i = 0; i < 7; ++i) {
        int n = snprintf(storage[i], sizeof(storage[i]), "%s=%s", keys[i], values[i]);
        if (n <= 0 || (size_t)n >= sizeof(storage[i])) return false;
        env[i] = storage[i];
    }
    env[7] = "LC_ALL=C"; env[8] = NULL;
    bool ran = zcl_devloop_process_run_env(f->root, argv, env, 30000, run);
    bool ok = ran && !run->timed_out && !run->cancelled &&
        !run->output_truncated && run->term_signal == 0;
    if (!ok || run->exit_code != 0)
        fprintf(stderr, "desktop receive: argv0=%s ran=%d exit=%d signal=%d timeout=%d output=%s\n",
                argv[0], ran, run->exit_code, run->term_signal, run->timed_out, run->output);
    return ok;
}
static bool dti_recipe(const struct dti_fixture *f)
{
    char path[PATH_MAX], *text = NULL;
    if (!dti_path(path, repo_root(), "Makefile") || read_entire_file(path, &text)) return false;
    const char *start = strstr(text, "# Explicit per-user Linux packaging.");
    const char *end = start ? strstr(start, "# Current maintainer host") : NULL;
    bool ok = start && end && dti_path(path, f->root, "Makefile") &&
              dti_write(path, start, (size_t)(end - start));
    free(text); return ok;
}
static bool dti_inputs(const struct dti_fixture *f)
{
    static const char *const files[] = {"org.zclassic.ZClassic23.desktop",
        "org.zclassic.SkyCombat.desktop",
        "org.zclassic.ZClassic23.svg", "org.zclassic.ZClassic23.xml"};
    char source[PATH_MAX], target[PATH_MAX], rel[256];
    for (size_t i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
        int n = snprintf(rel, sizeof(rel), "platform/packaging/linux/%s", files[i]);
        if (n <= 0 || (size_t)n >= sizeof(rel) ||
            !dti_path(source, repo_root(), rel) || !dti_path(target, f->root, rel) ||
            copy_file(source, target) != 0) return false;
    }
    return dti_recipe(f);
}
static bool dti_setup(struct dti_fixture *f)
{
    static const char *const dirs[] = {"config", "state", "cache", "runtime",
        "tools", "platform", "platform/packaging", "platform/packaging/linux"};
    char path[PATH_MAX];
    for (size_t i = 0; i < sizeof(dirs)/sizeof(dirs[0]); ++i)
        if (!dti_path(path, f->root, dirs[i]) || mkdir(path, 0700) != 0) return false;
    bool ok = dti_path(f->home, f->root, "home space ' \" `touch HOME_PWNED` $(shell touch HOME_MAKE)") &&
        mkdir(f->home, 0700) == 0 && dti_path(f->config, f->root, "config") &&
        dti_path(f->state, f->root, "state") && dti_path(f->cache, f->root, "cache") &&
        dti_path(f->runtime, f->root, "runtime") && dti_path(f->tools, f->root, "tools") &&
        dti_path(f->data, f->root, "xdg space % ' \" `touch TICK_PWNED` $(touch DOLLAR_PWNED) $(shell touch MAKE_PWNED);");
    return ok && dti_inputs(f);
}
static bool dti_preferences(const struct dti_fixture *f, bool create)
{
    static const char text[] = "[Default Applications]\napplication/x-z23-share=fixture-other.desktop;\n";
    char path[PATH_MAX], *read = NULL;
    if (!dti_path(path, f->config, "mimeapps.list")) return false;
    if (create) return dti_write(path, text, sizeof(text) - 1);
    bool ok = read_entire_file(path, &read) == 0 && !strcmp(read, text);
    free(read); return ok;
}
static bool dti_tools(const struct dti_fixture *f)
{
    char path[PATH_MAX];
    if (access("/usr/bin/make", X_OK) || access("/usr/bin/install", X_OK) ||
        access("/usr/bin/gio", X_OK) || access("/usr/bin/update-mime-database", X_OK) ||
        access("/usr/bin/printf", X_OK) || access("/usr/bin/false", X_OK)) {
        fputs("desktop receive fixture requires make/install/Gio/shared-mime-info/printf/false\n", stderr);
        return false;
    }
    return dti_path(path, f->tools, "printf") && symlink("/usr/bin/printf", path) == 0 &&
        dti_path(path, f->tools, "install") && symlink("/usr/bin/install", path) == 0 &&
        dti_path(path, f->tools, "update-mime-database") &&
        symlink("/usr/bin/update-mime-database", path) == 0;
}
static bool dti_no_markers(const struct dti_fixture *f)
{
    static const char *const names[] = {"PWNED", "TICK_PWNED", "DOLLAR_PWNED",
        "MAKE_PWNED", "HOME_PWNED", "HOME_MAKE"};
    char path[PATH_MAX];
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i)
        if (!dti_path(path, f->root, names[i]) || !dti_absent(path)) return false;
    return dti_preferences(f, false);
}
static bool dti_make(const struct dti_fixture *f, const char *data,
    const char *override, bool success)
{
    const char *argv[] = {"/usr/bin/make", "--no-print-directory",
        "presentation-desktop-install", override, NULL};
    struct zcl_devloop_process_result run = {0};
    if (!dti_run(f, argv, data, true, &run)) return false;
    bool passed = run.exit_code == 0;
    return passed == success && (success || !strstr(run.output, "identity installed")) &&
        dti_no_markers(f);
}
static bool dti_installed(const struct dti_fixture *f, const char *data)
{
    static const char *const sources[] = {"org.zclassic.ZClassic23.desktop",
        "org.zclassic.SkyCombat.desktop",
        "org.zclassic.ZClassic23.svg", "org.zclassic.ZClassic23.xml"};
    static const char *const destinations[] = {"applications/org.zclassic.ZClassic23.desktop",
        "applications/org.zclassic.SkyCombat.desktop",
        "icons/hicolor/scalable/apps/org.zclassic.ZClassic23.svg",
        "mime/packages/org.zclassic.ZClassic23.xml"};
    _Static_assert(sizeof(sources) / sizeof(sources[0]) ==
                   sizeof(destinations) / sizeof(destinations[0]), "desktop install pairs");
    char source[PATH_MAX], target[PATH_MAX], rel[256]; struct stat st;
    for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); ++i) {
        int n = snprintf(rel, sizeof(rel), "platform/packaging/linux/%s", sources[i]);
        if (n <= 0 || (size_t)n >= sizeof(rel) || !dti_path(source, f->root, rel) ||
            !dti_path(target, data, destinations[i]) || !dti_equal(source, target)) return false;
    }
    return dti_path(target, data, "mime/mime.cache") && stat(target, &st) == 0 && st.st_size > 0;
}
static bool dti_mime_one(const struct dti_fixture *f, const char *name,
    const void *bytes, size_t size, bool share)
{
    char path[PATH_MAX];
    if (!dti_path(path, f->root, name) || !dti_write(path, bytes, size)) return false;
    const char *argv[] = {"/usr/bin/gio", "info", "-a", "standard::content-type", path, NULL};
    struct zcl_devloop_process_result run = {0};
    bool ok = dti_run(f, argv, f->data, false, &run) && run.exit_code == 0 &&
        (strstr(run.output, "standard::content-type: application/x-z23-share\n") != NULL) == share;
    if (!ok) fprintf(stderr, "desktop receive: MIME case=%s bytes=%zu expected_share=%d exit=%d output_len=%zu output=%s\n",
                     name, size, share, run.exit_code, run.output_len, run.output);
    return ok;
}
static bool dti_mime(const struct dti_fixture *f)
{
    static const unsigned char magic[] = {'Z','2','3','S','H','A','R','E',1,0,0,0};
    static const unsigned char wrong[] = {'N','O','T','S','H','A','R','E',1,0,0,0};
    static const char extension_only[] = "extension-only fixture\n";
    return dti_mime_one(f, "magic.bin", magic, sizeof(magic), true) &&
        dti_mime_one(f, "named.z23share", extension_only, sizeof(extension_only) - 1, true) &&
        dti_mime_one(f, "empty.z23share", "", 0, false) &&
        dti_mime_one(f, "not-share.bin", wrong, sizeof(wrong), false);
}
static bool dti_validate(const struct dti_fixture *f, const char *path)
{
    if (access("/usr/bin/desktop-file-validate", X_OK) != 0) return true;
    const char *argv[] = {"/usr/bin/desktop-file-validate", path, NULL};
    struct zcl_devloop_process_result run = {0};
    return dti_run(f, argv, f->data, false, &run) && run.exit_code == 0;
}
static bool dti_descriptor(const struct dti_fixture *f, char **text)
{
    char path[PATH_MAX];
    if (!dti_path(path, f->data, "applications/org.zclassic.ZClassic23.desktop") ||
        read_entire_file(path, text)) return false;
    if (!strstr(*text, "\nExec=z23 app receive --preview --file=%f\n") ||
        !strstr(*text, "\nTerminal=false\n") || !strstr(*text, "\nNoDisplay=true\n") ||
        !strstr(*text, "\nMimeType=application/x-z23-share;\n")) return false;
    return dti_validate(f, path);
}
static bool dti_gio(const struct dti_fixture *f)
{
    char *text = NULL, *probe = NULL; char desktop[PATH_MAX], file[PATH_MAX], expected[PATH_MAX + 64];
    bool ok = dti_descriptor(f, &text);
    if (ok) probe = str_replace_once(text, "Exec=z23 ", "Exec=/usr/bin/printf [%%s] ");
    ok = ok && probe && dti_path(desktop, f->root, "argv.desktop") &&
        dti_write(desktop, probe, strlen(probe));
    free(text); free(probe);
    if (!ok || !dti_path(file, f->root, "space % \"quote\" 'single' $(touch PWNED);literal.z23share") ||
        !dti_write(file, "", 0)) return false;
    int n = snprintf(expected, sizeof(expected), "[app][receive][--preview][--file=%s]", file);
    if (n <= 0 || (size_t)n >= sizeof(expected)) return false;
    const char *argv[] = {"/usr/bin/gio", "launch", desktop, file, NULL};
    struct zcl_devloop_process_result run = {0};
    return dti_run(f, argv, f->data, false, &run) && run.exit_code == 0 &&
        run.output_len == strlen(expected) && !memcmp(run.output, expected, run.output_len) &&
        dti_no_markers(f);
}
static bool dti_game_descriptor(const struct dti_fixture *f, char **text)
{
    char path[PATH_MAX];
    if (!dti_path(path, f->data, "applications/org.zclassic.SkyCombat.desktop") ||
        read_entire_file(path, text)) return false;
    return strstr(*text, "\nName=Sky Combat\n") &&
        strstr(*text, "\nExec=z23 app open skycombat\n") &&
        strstr(*text, "\nIcon=org.zclassic.ZClassic23\n") &&
        strstr(*text, "\nTerminal=false\n") && strstr(*text, "\nNoDisplay=false\n") &&
        strstr(*text, "\nCategories=Game;Simulation;\n") && !strstr(*text, "TryExec=") &&
        !strstr(*text, "MimeType=") && dti_validate(f, path);
}
static bool dti_game_launch(const struct dti_fixture *f, const char *desktop, const char *file)
{
    const char *argv[] = {"/usr/bin/gio", "launch", desktop, file, NULL};
    char expected[PATH_MAX + 64];
    int n = file ? snprintf(expected, sizeof(expected), "[app][open][skycombat][%s]", file)
                 : snprintf(expected, sizeof(expected), "[app][open][skycombat]");
    if (n <= 0 || (size_t)n >= sizeof(expected)) return false;
    struct zcl_devloop_process_result run = {0};
    bool ok = dti_run(f, argv, f->data, false, &run) && run.exit_code == 0 &&
        run.output_len == (size_t)n && !memcmp(run.output, expected, (size_t)n);
    if (!ok) fprintf(stderr, "desktop game: file=%s exit=%d output=%s\n",
                     file ? file : "(none)", run.exit_code, run.output);
    return ok && dti_no_markers(f);
}
static bool dti_game_refusal_wire(const struct zcl_devloop_process_result *run)
{
    struct json_value doc; json_init(&doc);
    bool parsed = json_read(&doc, run->output, run->output_len);
    const struct json_value *error = json_get(&doc, "error");
    const char *code = json_get_str(json_get(error, "code"));
    const char *phase = json_get_str(json_get(error, "phase"));
    const struct json_value *ok = json_get(&doc, "ok"), *mutated = json_get(error, "mutated");
    bool refused = parsed && code && phase && !strcmp(code, "TOO_MANY_ARGS") &&
        !strcmp(phase, "normalize") && ok && ok->type == JSON_BOOL && !json_get_bool(ok) &&
        mutated && mutated->type == JSON_BOOL && !json_get_bool(mutated);
    json_free(&doc); return refused;
}
static bool dti_game_extra_refused(const struct dti_fixture *f, const char *file)
{
    char executable[PATH_MAX];
    if (!dti_path(executable, repo_root(), "build/bin/z23-dev")) return false;
    const char *argv[] = {executable, "app", "open", "skycombat", file, NULL};
    struct zcl_devloop_process_result run = {0};
    /* Same argv Gio emits; actual normalization must refuse before dispatch. */
    bool ok = dti_run(f, argv, f->data, false, &run) &&
        run.exit_code == ZCL_COMMAND_EXIT_INVALID && dti_game_refusal_wire(&run);
    if (!ok) fprintf(stderr, "desktop game: extra-file refusal exit=%d output=%s\n",
                     run.exit_code, run.output);
    return ok && dti_no_markers(f);
}
static bool dti_game_gio(const struct dti_fixture *f)
{
    char *text = NULL, *probe = NULL; char desktop[PATH_MAX], file[PATH_MAX];
    bool ok = dti_game_descriptor(f, &text);
    /* Only replace the executable with the existing argv observer, as in the
     * Receive probe. Gio expands the maintained descriptor; no shell/game runs. */
    if (ok) probe = str_replace_once(text, "Exec=z23 ", "Exec=/usr/bin/printf [%%s] ");
    ok = ok && probe && dti_path(desktop, f->root, "game-argv.desktop") &&
        dti_write(desktop, probe, strlen(probe));
    free(text); free(probe);
    if (!ok || !dti_path(file, f->root, "game space % \"quote\" 'single' $(touch PWNED);literal.z23share") ||
        !dti_write(file, "not a game argument\n", 20)) return false;
    /* Gio appends an explicitly supplied file even without an Exec fieldcode.
     * It stays one literal argument; the native app.open leaf rejects it. */
    return dti_game_launch(f, desktop, NULL) && dti_game_launch(f, desktop, file) &&
        dti_game_extra_refused(f, file);
}

static bool dti_failures(const struct dti_fixture *f)
{
    char path[PATH_MAX], output[PATH_MAX];
    if (!dti_make(f, "relative", NULL, false) ||
        !dti_path(path, f->root, "relative") || !dti_absent(path)) return false;
    if (!dti_path(path, f->tools, "update-mime-database") || unlink(path) != 0 ||
        !dti_path(output, f->root, "missing-tool") || !dti_make(f, output, NULL, false) ||
        !dti_absent(output) || symlink("/usr/bin/false", path) != 0) return false;
    return dti_path(output, f->root, "failed-update") && dti_make(f, output, NULL, false);
}
static bool dti_override(const struct dti_fixture *f)
{
    char override[PATH_MAX + 32], unused[PATH_MAX];
    int n = snprintf(override, sizeof(override), "XDG_DATA_HOME=%s", f->data);
    return n > 0 && (size_t)n < sizeof(override) && dti_path(unused, f->root, "unused-data") &&
        dti_make(f, unused, override, true) && dti_installed(f, f->data) && dti_absent(unused);
}
static bool dti_cases(const struct dti_fixture *f)
{
    char fallback[PATH_MAX];
    if (!dti_make(f, f->data, NULL, true) || !dti_installed(f, f->data) ||
        !dti_path(fallback, f->home, ".local") || !dti_absent(fallback)) return false;
    if (!dti_mime(f) || !dti_gio(f) || !dti_game_gio(f) || !dti_override(f)) return false;
    return dti_make(f, "", NULL, true) && dti_path(fallback, f->home, ".local/share") &&
        dti_installed(f, fallback) && dti_failures(f);
}
#endif
static int t_desktop_receive_install(void)
{
#if !defined(__linux__)
    puts("SKIP (desktop receive packaging fixture requires Linux)");
    return 0;
#else
    struct dti_fixture f = {0};
    if (!dti_root(&f)) return 1;
    const char *prior = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    char *saved = prior ? strdup(prior) : NULL;
    if (prior && !saved) return 1;
    bool opted = setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0;
    bool ok = opted && dti_setup(&f) && dti_preferences(&f, true) && dti_tools(&f) && dti_cases(&f);
    int restored = prior ? setenv("ZCL_DEVLOOP_TEST_PROCESS", saved, 1) : unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    free(saved); ok = ok && restored == 0;
    if (!ok) {
        fprintf(stderr, "desktop receive: failed fixture retained: %s\n", f.root);
        return 1;
    }
    return test_rm_rf_recursive(f.root) != 0;
#endif
}

/* Builds the receipt binary into the fixture the way Make does, from the
 * checkout sources, so the fixture needs no copy of those sources. */
#define RECEIPT_FIXTURE_PREAMBLE \
    "set -euo pipefail; cd \"$2\"\n" \
    "for tool in cc git bash mkfifo; do command -v \"$tool\" >/dev/null; done\n" \
    "mkdir -p build/bin receipts\n" \
    "inc=(-I\"$1/platform/modules/sha3/include\" -I\"$1/core/modules/crypto/include\" -I\"$1/platform/modules/support/include\" -I\"$1/platform/modules/base/include\")\n" \
    "cc -std=c23 -O2 -Wall -Wextra -Werror \"${inc[@]}\" -o build/bin/gate_receipt \"$1\"/tools/agent/gate_receipt.c \"$1\"/tools/agent/gate_receipt_proc.c \"$1\"/tools/agent/gate_receipt_text.c \"$1/platform/modules/sha3/src/sha3.c\" \"$1/platform/modules/base/src/safe_alloc.c\"\n" \
    "cc -std=c23 -O2 -Wall -Wextra -Werror \"${inc[@]}\" -o build/bin/agent_sha3 \"$1/tools/agent/agent_sha3.c\" \"$1/platform/modules/sha3/src/sha3.c\"\n" \
    "git init -q; git -c user.name=fixture -c user.email=fixture@example.invalid -c commit.gpgsign=false commit -qm fixture --allow-empty\n" \
    "head=$(git rev-parse HEAD)\n"

static const char receipt_overlap_script[] =
    RECEIPT_FIXTURE_PREAMBLE
    "mkfifo ready release-A release-B; exec 3<>ready 4<>release-A 5<>release-B\n"
    "for tag in A B; do\n"
    "  build/bin/gate_receipt \"$PWD\" --quiet --gate custom --dir receipts -- bash -c 'echo ready >&3; read -r go < \"release-$1\"; echo \"$1\"' child \"$tag\" >\"$tag.out\" 2>&1 &\n"
    "  case $tag in A) a=$!;; B) b=$!;; esac\n"
    "done\n"
    "read -r first <&3; read -r second <&3; [ \"$first:$second\" = ready:ready ]\n"
    "echo go >&4; echo go >&5; wait \"$a\"; wait \"$b\"\n"
    "set -- receipts/*.receipt; [ \"$#\" = 2 ]; first=$1; second=$2\n"
    "set -- receipts/*.log; [ \"$#\" = 2 ]; [ \"$(cat \"$1\" \"$2\" | sort)\" = $'A\\nB' ]\n"
    "grep -qx chain_index=0 \"$first\"; grep -qx prev_receipt=NONE \"$first\"; grep -qx prev_receipt_sha3=GENESIS \"$first\"\n"
    "grep -qx chain_index=1 \"$second\"; grep -qx \"prev_receipt=$(basename \"$first\")\" \"$second\"\n"
    "digest=$(build/bin/agent_sha3 \"$first\"); grep -qx \"prev_receipt_sha3=${digest%% *}\" \"$second\"\n"
    "for receipt in \"$first\" \"$second\"; do\n"
    "  grep -qx verdict=PASS \"$receipt\"; grep -qx \"head_sha=$head\" \"$receipt\"\n"
    "  log=$(sed -n 's/^output_path=//p' \"$receipt\"); id=$(sed -n 's/^receipt_id=//p' \"$receipt\")\n"
    "  [[ \"$log\" =~ ^$id-custom-[0-9]{8}T[0-9]{6}Z\\.log$ ]]; digest=$(build/bin/agent_sha3 \"receipts/$log\")\n"
    "  grep -qx \"output_sha3=${digest%% *}\" \"$receipt\"; grep -qx output_bytes=2 \"$receipt\"\n"
    "  seal=$(sed '$d' \"$receipt\" | build/bin/agent_sha3 -); grep -qx \"receipt_sha3=$seal\" \"$receipt\"\n"
    "done\n";

/* Root rejection must precede every gate effect; valid roots must still
 * produce evidence accepted by the independent strict checker. */
static const char receipt_root_script[] =
    RECEIPT_FIXTURE_PREAMBLE
    /* Reject unusable roots before creating output, compiling a helper or
     * starting the gate. The binary receives the root as its first argument. */
    "mv build/bin/agent_sha3 build/bin/agent_sha3.saved\n"
    "for root in '' '.' 'tools/..' 'missing-relative-root'; do\n"
    "  rc=0; CC=/nonexistent/compiler build/bin/gate_receipt \"$root\" --dir rejected-receipts --gate custom -- sh -c 'touch child-started; echo child-output' >rejected.out 2>rejected.err || rc=$?\n"
    "  [ \"$rc\" = 2 ]; grep -q 'REPO_ROOT.*nonempty absolute path' rejected.err\n"
    "  [ ! -s rejected.out ]; [ ! -e child-started ]; [ ! -e rejected-receipts ]; [ ! -e build/bin/agent_sha3 ]\n"
    "done\n"
    "build/bin/gate_receipt . --help >help.out; grep -q 'REPO_ROOT.*nonempty absolute root path' help.out\n"
    "mv build/bin/agent_sha3.saved build/bin/agent_sha3\n"
    /* A valid absolute root must produce evidence accepted by the actual
     * strict verifier, not just a writer-local PASS flag. */
    "cc -std=c23 -O2 -Wall -Wextra -Werror \"${inc[@]}\" -o build/bin/check_claims \"$1/tools/agent/check_claims.c\" \"$1/platform/modules/sha3/src/sha3.c\" \"$1/platform/modules/base/src/safe_alloc.c\"\n"
    "build/bin/gate_receipt \"$PWD\" --dir absolute-receipts --gate custom -- sh -c 'touch child-started; echo absolute-output' >absolute.out 2>absolute.err\n"
    "[ -e child-started ]; grep -qx absolute-output absolute.out\n"
    "build/bin/check_claims --strict --require custom --dir absolute-receipts >strict.out\n";

/* Exit status, merged output, receipt fields, default tokens, the shell
 * quoting of the recorded command and the strictness of option parsing. */
static const char receipt_contract_script[] =
    RECEIPT_FIXTURE_PREAMBLE
    "w() { build/bin/gate_receipt \"$PWD\" --dir receipts \"$@\"; }\n"
    "newest() { ls receipts/*.receipt | sort | tail -n1; }\n"
    "rc=0; out=$(w --gate custom -- sh -c 'echo out; echo err >&2; exit 3' 2>stderr.txt) || rc=$?\n"
    "[ \"$rc\" = 3 ]; [ \"$out\" = $'out\\nerr' ]; r=$(newest)\n"
    "grep -qx exit_status=3 \"$r\"; grep -qx verdict=FAIL \"$r\"; grep -q '^gate-receipt: custom FAIL (exit 3, ' stderr.txt\n"
    "first=$r\n"
    "argv=(echo '' 'a b' '~x' '#y' \"it's\" '$HOME' $'t\\tn' $'nl\\nx')\n"
    "w --gate custom --label 'two words' -- \"${argv[@]}\" >/dev/null 2>&1; r=$(newest)\n"
    "want=$(printf '%q ' \"${argv[@]}\"); grep -qxF \"command_display=${want% }\" \"$r\"; grep -qx command_argc=${#argv[@]} \"$r\"\n"
    "grep -qx chain_index=1 \"$r\"; grep -qx \"prev_receipt=$(basename \"$first\")\" \"$r\"; d=$(build/bin/agent_sha3 \"$first\"); grep -qx \"prev_receipt_sha3=${d%% *}\" \"$r\"\n"
    "grep -qx 'label=two words' \"$r\"; seal=$(sed '$d' \"$r\" | build/bin/agent_sha3 -); grep -qx \"receipt_sha3=$seal\" \"$r\"\n"
    "w --gate lint -- echo 'LINT: all checks passed' >/dev/null 2>&1; grep -qx verdict=PASS \"$(newest)\"\n"
    "rc=0; w --gate lint -- true >/dev/null 2>&1 || rc=$?; [ \"$rc\" = 0 ]; r=$(newest); grep -qx verdict=FAIL \"$r\"; grep -qx expect_missing=1 \"$r\"\n"
    "w --gate t-fast -- sh -c 'echo ALL TESTS PASSED; echo SOME TESTS FAILED' >/dev/null 2>&1; r=$(newest); grep -qx verdict=FAIL \"$r\"; grep -qx forbid_present=1 \"$r\"\n"
    "w --gate custom --expect $'zzz\\nhi' -- echo hi >/dev/null 2>&1; grep -qx verdict=PASS \"$(newest)\"\n"
    "rc=0; w --gate custom -- /nonexistent/gate >/dev/null 2>&1 || rc=$?; [ \"$rc\" = 127 ]; grep -qx exit_status=127 \"$(newest)\"\n"
    "rc=0; w --gate custom -- sh -c 'kill -9 $$' >/dev/null 2>&1 || rc=$?; [ \"$rc\" = 137 ]\n"
    "mkdir borrowed; ln -s \"../$(newest)\" borrowed/other.receipt\n"
    "rc=0; build/bin/gate_receipt \"$PWD\" --dir borrowed --gate custom -- true >borrowed.out 2>borrowed.err || rc=$?\n"
    "[ \"$rc\" != 0 ]; [ -L borrowed/other.receipt ]; set -- borrowed/*.receipt; [ \"$#\" = 1 ]\n"
    "count=$(ls receipts/*.receipt | wc -l)\n"
    "for args in '--bogus' '--gate' '--gate x' '--gate x --' '--gate a/b -- true' '--gate x --expect' '-- true'; do\n"
    "  rc=0; out=$(w $args 2>/dev/null) || rc=$?; [ \"$rc\" = 2 ]; [ -z \"$out\" ]\n"
    "done\n"
    "[ \"$(ls receipts/*.receipt | wc -l)\" = \"$count\" ]\n";

static int receipt_fixture_run(const char *name, const char *script)
{
    char fixture[PATH_MAX] = {0};
    struct stat st;
    test_make_tmpdir(fixture, sizeof(fixture), "receipts", name);
    int bad = 1;
    if (stat(fixture, &st) == 0 && S_ISDIR(st.st_mode))
        bad = build_needs_fixture_run(repo_root(), fixture, script);
    else fprintf(stderr, "receipt %s: fixture setup failed\n", name);
    if (test_rm_rf_recursive(fixture) != 0) {
        fprintf(stderr, "receipt %s: fixture cleanup failed\n", name); bad = 1;
    }
    return bad;
}

static int t_receipt_overlap(void)
{ return receipt_fixture_run("overlap", receipt_overlap_script); }

static int t_receipt_contract(void)
{ return receipt_fixture_run("contract", receipt_contract_script); }

static int t_receipt_root(void)
{ return receipt_fixture_run("root", receipt_root_script); }

/* Pure wait deadlines for the observation children: a child that needs a few
 * seconds idle can need minutes on a host at load 300. Nothing asserts on
 * elapsed time, so the deadlines only bound a hung child. */
#define OBSERVATION_CHILD_DEADLINE_MS 600000
#define OBSERVATION_CHILD_GROUP_TIMEOUT_S "300"

#if defined(__linux__)
static void observation_failure(const struct zcl_devloop_process_result *run,
                                const char *expectation)
{
    size_t n = strnlen(run->output, sizeof(run->output));
    size_t start = n > 4096 ? n - 4096 : 0;
    fprintf(stderr, "observation child: expectation=%s exit=%d signal=%d timeout=%d "
        "cancelled=%d truncated=%d output_bytes=%zu excerpt_start=%zu\n%.*s\n",
        expectation, run->exit_code, run->term_signal, run->timed_out,
        run->cancelled, run->output_truncated, run->output_len, start,
        (int)(n - start), run->output + start);
}
#define OBSERVATION_ASSERT(condition) do { \
    bool observation_ok = !!(condition); \
    if (!observation_ok) observation_failure(&run, #condition); \
    ASSERT(observation_ok); \
} while (0)
static bool observation_child_complete(const struct zcl_devloop_process_result *run)
{
    return !run->timed_out && !run->cancelled && !run->output_truncated;
}

static bool observation_bounded_event_log(const char *const argv[],
    int image_fd, struct zcl_devloop_process_result *run)
{
    char saved[4096];
    const char *prior = getenv("ZCL_EVENT_LOG_BENCH");
    bool present = prior != NULL;
    memset(run, 0, sizeof(*run));
    if (present) {
        int n = snprintf(saved, sizeof(saved), "%s", prior);
        if (n < 0 || (size_t)n >= sizeof(saved)) {
            fprintf(stderr, "observation fixture: standalone setting too long\n");
            return false;
        }
    }
    if (unsetenv("ZCL_EVENT_LOG_BENCH") != 0) {
        fprintf(stderr, "observation fixture: cannot clear standalone setting\n");
        return false;
    }
    bool started = zcl_devloop_process_run_fd(".", image_fd, argv, OBSERVATION_CHILD_DEADLINE_MS, run);
    int restored = present ? setenv("ZCL_EVENT_LOG_BENCH", saved, 1)
                           : unsetenv("ZCL_EVENT_LOG_BENCH");
    if (restored != 0) {
        fprintf(stderr, "observation fixture: cannot restore standalone setting\n");
        return false;
    }
    return started;
}

/* Open the mapped image once and use the existing descriptor-bound executor.
 * These selections cannot recurse into this group; every child is bounded. */
static int t_dev_proof_runner_observations(void)
{
    int failures = 0;
    char root[4096] = {0}, store[4096];
    int image_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    const char *prior = getenv("ZCL_DEVLOOP_TEST_PROCESS");
    char *saved = prior ? strdup(prior) : NULL;
    TEST_CASE("[lint-gate] actual observation runner ordinary, activated, denylisted and CAS failure") {
        ASSERT(image_fd >= 0);
        ASSERT(!prior || saved != NULL);
        ASSERT(setenv("ZCL_DEVLOOP_TEST_PROCESS", "1", 1) == 0);
        test_make_tmpdir(root, sizeof(root), "proof_obs_env", "runner");
        ASSERT(snprintf(store, sizeof(store), "%s/observations", root) > 0);
        ASSERT(mkdir(store, 0700) == 0);
        ASSERT(setenv(ZCL_DEV_OBSERVATION_STORE_ENV, store, 1) == 0);
        ASSERT(setenv("ZCL_TESTCACHE_STORE_ROOT", root, 1) == 0);
        const char *argv[] = {"/proc/self/exe", "--exact=test_hex_codec", "--jobs=1",
            "--timeout=" OBSERVATION_CHILD_GROUP_TIMEOUT_S, "--cold-audit", "--emit-observations", NULL, NULL};
        struct zcl_devloop_process_result run = {0};
        OBSERVATION_ASSERT(zcl_devloop_process_run_fd(".", image_fd, argv, OBSERVATION_CHILD_DEADLINE_MS, &run));
        OBSERVATION_ASSERT(observation_child_complete(&run));
        OBSERVATION_ASSERT(strstr(run.output, "groups_ran=1 groups_cached=0") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0") != NULL);
        OBSERVATION_ASSERT(run.exit_code == 0);
        OBSERVATION_ASSERT(strstr(run.output, "mode=complete eligible=1 emitted=1 unqualified=0 refused=0 complete=1") != NULL);
        argv[5] = "--collect-observations";
        argv[1] = "--exact=test_make_lint_gates_partition";
        OBSERVATION_ASSERT(zcl_devloop_process_run_fd(".", image_fd, argv, OBSERVATION_CHILD_DEADLINE_MS, &run));
        OBSERVATION_ASSERT(observation_child_complete(&run));
        OBSERVATION_ASSERT(strstr(run.output, "groups_ran=1 groups_cached=0") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0") != NULL);
        OBSERVATION_ASSERT(run.exit_code == 0);
        OBSERVATION_ASSERT(strstr(run.output, "OBSERVATION UNQUALIFIED group=test_make_lint_gates") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "eligible=0 emitted=0 unqualified=1 refused=0 complete=0") != NULL);
        argv[5] = "--emit-observations";
        OBSERVATION_ASSERT(zcl_devloop_process_run_fd(".", image_fd, argv, OBSERVATION_CHILD_DEADLINE_MS, &run));
        OBSERVATION_ASSERT(observation_child_complete(&run));
        OBSERVATION_ASSERT(strstr(run.output, "groups_ran=1 groups_cached=0") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0") != NULL);
        OBSERVATION_ASSERT(run.exit_code == 1);
        OBSERVATION_ASSERT(strstr(run.output, "observation_input_closure_incomplete") != NULL);
        argv[1] = "--exact=test_event_log_benchmark";
        argv[5] = "--collect-observations";
        argv[6] = "--activate-proof-contracts";
        OBSERVATION_ASSERT(observation_bounded_event_log(argv, image_fd, &run));
        OBSERVATION_ASSERT(observation_child_complete(&run));
        OBSERVATION_ASSERT(strstr(run.output,
            "event_log: bounded push proof completed: counts=136,64,64 flushes=0,0,2") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "groups_ran=1 groups_cached=0") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0") != NULL);
        OBSERVATION_ASSERT(run.exit_code == 0);
        OBSERVATION_ASSERT(strstr(run.output, "eligible=1 emitted=1 unqualified=0 refused=0 complete=1") != NULL);
        argv[1] = "--exact=test_build_profile";
        argv[6] = NULL;
        OBSERVATION_ASSERT(!testcache_group_is_denylisted("test_build_profile"));
        OBSERVATION_ASSERT(zcl_devloop_process_run_fd(".", image_fd, argv, OBSERVATION_CHILD_DEADLINE_MS, &run));
        OBSERVATION_ASSERT(observation_child_complete(&run));
        OBSERVATION_ASSERT(run.exit_code == 1);
        OBSERVATION_ASSERT(strstr(run.output, "groups_ran=1 groups_cached=0") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "OBSERVATION REFUSE group=test_build_profile reason=observation_input_closure_incomplete") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "eligible=0 emitted=0 unqualified=0 refused=1 complete=0") != NULL);
        argv[1] = "--exact=test_hex_codec";
        ASSERT_EQ(test_rm_rf_recursive(store), 0);
        FILE *file = fopen(store, "wb");
        OBSERVATION_ASSERT(file != NULL);
        OBSERVATION_ASSERT(fclose(file) == 0);
        OBSERVATION_ASSERT(zcl_devloop_process_run_fd(".", image_fd, argv, OBSERVATION_CHILD_DEADLINE_MS, &run));
        OBSERVATION_ASSERT(observation_child_complete(&run));
        OBSERVATION_ASSERT(strstr(run.output, "groups_ran=1 groups_cached=0") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "groups_failed=0 self_skips=0 env_unobserved=0 load_flaky=0") != NULL);
        OBSERVATION_ASSERT(run.exit_code == 1);
        OBSERVATION_ASSERT(strstr(run.output, "OBSERVATION REFUSE group=test_hex_codec") != NULL);
        OBSERVATION_ASSERT(strstr(run.output, "eligible=1 emitted=0 unqualified=0 refused=1 complete=0") != NULL);
    }
    TEST_END
    if (image_fd >= 0) (void)close(image_fd);
    if (saved) (void)setenv("ZCL_DEVLOOP_TEST_PROCESS", saved, 1);
    else (void)unsetenv("ZCL_DEVLOOP_TEST_PROCESS");
    free(saved);
    (void)unsetenv("ZCL_TESTCACHE_STORE_ROOT");
    (void)unsetenv(ZCL_DEV_OBSERVATION_STORE_ENV);
    (void)test_rm_rf_recursive(root);
    return failures;
}
#undef OBSERVATION_ASSERT
#endif

/* Per-process sandbox-root override. A shard group chdir()s into its private
 * sandbox and calls repo_root_set_override() with that path; every
 * repo_path()/run_gate_script()/fixture-plant then resolves INTO the sandbox
 * (including the sandbox's own copy of the gate script). Checked BEFORE the
 * cache so it wins over a cached real-root value. */
static char g_repo_root_override[PATH_MAX];
static int g_repo_root_override_set = 0;

void repo_root_set_override(const char *path)
{
    if (!path) { g_repo_root_override_set = 0; return; }
    snprintf(g_repo_root_override, sizeof(g_repo_root_override), "%s", path);
    g_repo_root_override_set = 1;
}

const char *repo_root(void)
{
    static char root[PATH_MAX];
    static int cached = 0;

    if (g_repo_root_override_set)
        return g_repo_root_override[0] ? g_repo_root_override : NULL;

    if (cached) return root[0] ? root : NULL;

    char exe[PATH_MAX];
    /* One exe-path shim for both hosts: /proc/self/exe on Linux,
     * _NSGetExecutablePath on Darwin (platform/os_proc.h). */
    if (!os_proc_exe_path(exe, sizeof(exe))) {
        cached = 1;
        root[0] = '\0';
        return NULL;
    }

    /* The binary lives at <root>/build/bin/<name>; walk UP from the exe until
     * a directory holding both the Makefile and the raw-sqlite fixture
     * appears. Bounded so a stray Makefile high in the tree cannot misroot the
     * shell-outs. */
    for (int depth = 0; depth < 6; depth++) {
        char *slash = strrchr(exe, '/');
        if (!slash || slash == exe) break;
        *slash = '\0';

        char probe[PATH_MAX];
        struct stat st;
        if (snprintf(probe, sizeof(probe), "%s/Makefile", exe)
                >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;
        if (snprintf(probe, sizeof(probe), "%s/%s", exe, FIXTURE_SRC_REL)
                >= (int)sizeof(probe))
            break;
        if (stat(probe, &st) != 0) continue;

        if (snprintf(root, sizeof(root), "%s", exe) >= (int)sizeof(root))
            break;
        cached = 1;
        return root;
    }

    cached = 1;
    root[0] = '\0';
    return NULL;
}

int repo_path(char *out, size_t outsz, const char *rel)
{
    const char *root = repo_root();
    if (!root || !out || outsz == 0 || !rel) return -1;
    return snprintf(out, outsz, "%s/%s", root, rel) >= (int)outsz ? -1 : 0;
}

static int tmpl_capture(const char *const args[], const char *cwd, char *out, size_t cap)
{
    struct sigaction saved, normal = {.sa_handler = SIG_DFL};
    out[0] = '\0';
    if (sigemptyset(&normal.sa_mask) != 0 || sigaction(SIGCHLD, &normal, &saved) != 0)
        return -1;
    bool timeout = false;
    int rc = zcl_spawn_capture_merged_in_dir_observed(args, cwd, out, cap, 60000, &timeout);
    if (sigaction(SIGCHLD, &saved, NULL) != 0) return -1;
    return timeout || strlen(out) == cap - 1u ? -1 : rc;
}

static bool tmpl_fixture_file(const char *root, const char *rel, const char *text)
{
    char path[PATH_MAX + 32];
    int n = snprintf(path, sizeof path, "%s/%s", root, rel);
    return n > 0 && (size_t)n < sizeof path && write_file(path, text) == 0;
}

static bool tmpl_build_fixture(const char *root)
{
    const char *cc = getenv("CC");
    const char *rels[] = {"tools/gen_templates.c", "platform/modules/base/src/safe_alloc.c",
                         "platform/modules/platform/src/path_replace.c"};
    const char *dirs[] = {"platform/modules/base/include", "platform/modules/util/include",
                         "platform/modules/platform/include"};
    char sources[3][PATH_MAX], paths[3][PATH_MAX], inc[3][PATH_MAX + 2];
    char binary[PATH_MAX + 32], out[4096];
    snprintf(binary, sizeof binary, "%s/generator", root);
    for (size_t i = 0; i < 3; i++) {
        if (repo_path(sources[i], sizeof sources[i], rels[i]) != 0 ||
            repo_path(paths[i], sizeof paths[i], dirs[i]) != 0) return false;
        snprintf(inc[i], sizeof inc[i], "-I%s", paths[i]);
    }
    const char *args[] = {cc && *cc ? cc : "cc", "-std=c23", "-O2", "-Wall", "-Wextra",
        inc[0], inc[1], inc[2], "-o", binary, sources[0], sources[1], sources[2], NULL};
    int rc = tmpl_capture(args, NULL, out, sizeof out);
    if (rc != 0) fprintf(stderr, "template fixture compile rc%d: %s\n", rc, out);
    return rc == 0;
}

static bool tmpl_no_stages(const char *root)
{
    char path[PATH_MAX + 32];
    snprintf(path, sizeof path, "%s/build/identity", root);
    DIR *d = opendir(path);
    if (!d) return false;
    bool empty = true;
    struct dirent *ent;
    errno = 0;
    while ((ent = readdir(d)) != NULL)
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0) empty = false;
    if (errno != 0) empty = false;
    if (closedir(d) != 0) empty = false;
    return empty;
}

static bool tmpl_root_case(const char *root, const char *input, const char *css,
                           int expected, const char *token)
{
    static const char sentinel[] = "original output sentinel\n";
    if (!tmpl_fixture_file(root, "out.h", sentinel)) return false;
    const char *args[] = {"./generator", input, "out.h", css, NULL};
    char out[4096], path[PATH_MAX + 32], *bytes = NULL;
    int rc = tmpl_capture(args, root, out, sizeof out);
    if (rc != expected) {
        fprintf(stderr, "template root %s rc%d expected%d: %s\n", input, rc, expected, out);
        return false;
    }
    const char *diagnostic = token ? token : "cannot open template directory";
    if (expected != 0 && (!strstr(out, diagnostic) || !strstr(out, input)))
        return false;
    snprintf(path, sizeof path, "%s/out.h", root);
    if (read_entire_file(path, &bytes) != 0) return false;
    bool ok = expected ? strcmp(bytes, sentinel) == 0 : strstr(bytes, token) != NULL;
    free(bytes);
    return ok && tmpl_no_stages(root);
}

/* A dangling selected name forces the same read_file failure as EACCES,
 * including when tests run as root. It sorts after good.chtml, so a stage
 * already contains a valid template when the required read fails. */
static bool tmpl_selected_read_case(const char *root)
{
    char path[PATH_MAX + 32];
    snprintf(path, sizeof path, "%s/templates/z-blocked.chtml", root);
    if (symlink("not-present", path) != 0) return false;
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return false; }
    if (errno != ENOENT) return false;
    if (!tmpl_root_case(root, "templates", NULL, 1,
                        "cannot read template templates/z-blocked.chtml")) return false;
    if (unlink(path) != 0 ||
        !tmpl_fixture_file(root, "templates/z-blocked.chtml", "<p>blocked</p>\n"))
        return false;
    if (!tmpl_root_case(root, "templates", NULL, 0, "TMPL_PARTIAL_COUNT 2")) return false;
    snprintf(path, sizeof path, "%s/out.h", root);
    char *bytes = NULL;
    if (read_entire_file(path, &bytes) != 0) return false;
    bool both = strstr(bytes, "TMPL_GOOD[]") && strstr(bytes, "TMPL_Z_BLOCKED[]");
    free(bytes);
    if (!both) return false;
    /* Optional CSS keeps its existing skip-on-read-failure behavior. */
    snprintf(path, sizeof path, "%s/css/z-blocked.ccss", root);
    if (symlink("not-present", path) != 0) return false;
    return tmpl_root_case(root, "templates", "css", 0, "TMPL_PARTIAL_COUNT 2");
}

static int t_template_required_root(void)
{
    int failures = 0;
    char root[PATH_MAX], path[PATH_MAX + 32];
    if (!test_mkdtemp(root, sizeof root, "template_root")) return 1;
    TEST("gen_templates actual CLI refuses unavailable roots and selected reads without replacing output or leaking stages") {
        const char *dirs[] = {"build", "build/identity", "templates", "empty", "css"};
        for (size_t i = 0; i < sizeof dirs / sizeof dirs[0]; i++) {
            snprintf(path, sizeof path, "%s/%s", root, dirs[i]);
            ASSERT(mkdir(path, 0700) == 0);
        }
        ASSERT(tmpl_fixture_file(root, "templates/good.chtml", "<p>good</p>\n"));
        ASSERT(tmpl_fixture_file(root, "blocker", "regular file\n"));
        ASSERT(tmpl_build_fixture(root));
        ASSERT(tmpl_root_case(root, "templates", NULL, 0, "TMPL_GOOD[]"));
        ASSERT(tmpl_root_case(root, "empty", NULL, 0, "TMPL_PARTIAL_COUNT 0"));
        ASSERT(tmpl_root_case(root, "absent", NULL, 1, NULL));
        ASSERT(tmpl_root_case(root, "blocker/child", NULL, 1, NULL));
        ASSERT(tmpl_root_case(root, "templates", "absent-css", 0, "TMPL_GOOD[]"));
        ASSERT(tmpl_root_case(root, "templates", "css", 0, "TMPL_GOOD[]"));
        ASSERT(tmpl_selected_read_case(root));
        PASS();
    } _test_next:;
    if (test_rm_rf_recursive(root) != 0) failures++;
    return failures;
}

/* ── The one entry table ──────────────────────────────────────────────────
 * Every check appears here exactly once, tagged with the lane it needs. The
 * partition below is a pure function of this table, so adding a check is a
 * one-line edit and it lands in a shard automatically. */

typedef int (*lint_gate_fn)(void);

enum lint_lane {
    LINT_LANE_SANDBOX = 0,
    LINT_LANE_REALROOT,
    /* Real-root-safe like REALROOT, but slow enough (fresh-boot-weld ~46s,
     * import-copy-prove ~25s) that each gets its own registered group. */
    LINT_LANE_HEAVY,
    LINT_LANE_EXCLUSIVE,
};

struct lint_gate_entry {
    lint_gate_fn   fn;
    enum lint_lane lane;
};

#define S_(f) { (f), LINT_LANE_SANDBOX }
#define N_(f) { (f), LINT_LANE_REALROOT }
#define H_(f) { (f), LINT_LANE_HEAVY }
#define X_(f) { (f), LINT_LANE_EXCLUSIVE }
static const struct lint_gate_entry g_lint_gate_entries[] = {
    S_(t_template_required_root),
    N_(t_receipt_overlap),
    N_(t_receipt_contract),
    N_(t_receipt_root),
    N_(t_receipt_signals),
    S_(t_baseline_passes),
    S_(t_fixture_trips_gate),
    S_(t_node_db_exec_fixture_trips_gate),
    S_(t_gate_recovers_after_removal),
    S_(t_coins_guard_baseline_passes),
    S_(t_coins_guard_fixture_trips_gate),
    S_(t_coins_guard_gate_recovers),
    S_(t_coins_guard_gate_fails_loud_on_no_lookup_surface),
    S_(t_observability_fixture_trips_gate),
    S_(t_observability_positive_controls_pass),
    S_(t_raw_malloc_fixture_trips_gate),
    S_(t_raw_malloc_zcl_fixture_passes),
    S_(t_raw_malloc_gate_recovers),
    S_(t_service_tip_mutation_gate),
    S_(t_legacy_candidate_source_has_no_override_scope),
    N_(t_deprecated_tools_z_is_absent),          /* git grep, read-only */
    S_(t_canonical_operator_diagnostics_contract),
    S_(t_canonical_deploy_proof_binding_contract),
    S_(t_legacy_unit_guard_contract),
    S_(t_dev_lane_deploy_contract),
    /* Hermetic: each script proves itself inside its own mktemp sandbox and
     * no tracked path is written, so this needs no worktree clone. */
    N_(t_slow_disk_progress_verdicts_contract),
    /* Reads tracked docs and exercises only disposable claim ledgers. */
    N_(t_native_operator_docs_contract),
    S_(t_remote_node_update_contract),
    S_(t_native_agent_api_contract),
    S_(t_mvp_reporters_resolve_live_service_rpc_contract),
    S_(t_soak_assert_requires_known_mirror_lag),
    S_(t_boot_chain_advance_diagnostics_contract),
    S_(t_boot_core_liveness_precedes_frontend_contract),
    S_(t_boot_addrman_persistence_contract),
    S_(t_lib_runtime_gauges_are_callback_injected),
    S_(t_boot_shutdown_persistence_order_contract),
    S_(t_boot_shutdown_connman_holders_stop_first),
    S_(t_hodl_history_uses_runtime_db_service),
    S_(t_db_service_query_handle_is_canonical),
    S_(t_txindex_releases_node_db_between_batches),
    S_(t_peer_save_busy_reports_db_error),
    S_(t_handshake_peer_save_is_async),
    S_(t_p2p_app_persistence_is_callback_injected),
    S_(t_tx_wallet_sync_is_callback_injected),
    S_(t_p2p_block_submit_is_callback_injected),
    S_(t_flyclient_proof_builder_is_callback_injected),
    S_(t_fast_sync_uses_lib_sqlite_helpers),
    S_(t_framework_reexport_headers_stay_deleted),
    S_(t_utxo_reimport_flag_is_storage_owned),
    S_(t_boot_progress_store_step_is_timed),
    S_(t_net_sync_planners_are_lib_owned),
    S_(t_header_peer_votes_are_callback_injected),
    S_(t_process_block_node_db_access_is_runtime_owned),
    S_(t_process_block_split_uses_reducer_language),
    S_(t_production_comments_do_not_carry_refactor_scaffold_labels),
    S_(t_wallet_view_never_invents_rpc_credentials),
    S_(t_deleted_engine_names_absent_from_production_sources),
    S_(t_build_commit_macro_stays_behind_getter),
    N_(t_fortify_combined_measurement),
    S_(t_boot_repaired_index_persistence_contract),
    S_(t_chain_evidence_reconstruct_uses_retry_persistence),
    S_(t_boot_genesis_init_preserves_restored_authority_contract),
    S_(t_refold_from_anchor_explicit_span_gate_contract),
    S_(t_sha3_window_tool_check_contract),
    S_(t_make_ignores_ephemeral_lint_fixture_sources),
    S_(t_block_index_flat_atomic_save_contract),
    S_(t_projection_deferral_is_not_block_rejected_contract),
    S_(t_trusted_peer_stall_guard_contract),
    S_(t_gap_fill_wakes_connman_dispatch_contract),
    S_(t_msg_process_yields_to_send_phase_contract),
    S_(t_e1_file_size_bands),
    S_(t_e1_file_size_baseline_and_hollow_scan),
    S_(t_long_functions_enforced_ratchet),
    S_(t_long_functions_lib_warn_tier),
    S_(t_no_new_repair_rung),
    S_(t_no_new_coordination_shell),
    S_(t_no_new_borrowed_seed_caller),
    S_(t_no_new_coin_backfill_caller),
    S_(t_no_writer_below_sealed_frontier),
    S_(t_e9_operator_needed_sink),
    S_(t_systemd_memory_budget),
    S_(t_quality_job_guard),
    /* Hermetic: each driver fakes its inputs inside its own `mktemp -d`
     * sandbox and touches nothing in the worktree. HEAVY, so one group each
     * — heavy_01 and heavy_02 in table order. */
    H_(t_import_copy_prove_selftest),
    H_(t_fresh_boot_weld_prove_selftest),
    S_(t_e14_condition_cooldown_gate),
    S_(t_fuzz_artifact_ledger_gate),  /* plants a fixture in tests/harness/fuzz_seeds */
    N_(t_markdown_links_gate),                   /* git ls-files, read-only */
    N_(t_git_hooks_gate_enforces_tracked_pre_push),  /* reads .git/hooks */
    N_(t_git_hooks_gate_rejects_noop_pre_push),      /* writes only test-tmp/ */
    N_(t_git_hooks_gate_rejects_noop_pre_commit),    /* writes only test-tmp/ */
    N_(t_git_hooks_installer_scope),                 /* private repo under test-tmp/ */
    N_(t_git_hooks_installer_relative_hooks_path),   /* private repo under test-tmp/ */
    N_(t_git_hooks_installer_idempotent),            /* private repo under test-tmp/ */
    N_(t_git_hooks_refresh_updates_armed_only),      /* private repo under test-tmp/ */
    N_(t_git_hooks_quiet_stale_residue),             /* private repo under test-tmp/ */
    N_(t_git_hooks_quiet_env_suppresses),            /* private repo under test-tmp/ */
    N_(t_git_hooks_quiet_held_ready_notifies),       /* private repo under test-tmp/ */
    N_(t_git_hooks_bootstrap_goal_filter),           /* make -s in a test-tmp/ fixture */
    N_(t_desktop_receive_install),                  /* isolated desktop/MIME install and Gio argv */
    S_(t_telemetry_ontology_gate),
    /* Hermetic: the script's --selftest builds its scan root and baseline in
     * its own mktemp dir and never mutates a tracked path. */
    N_(t_dumper_never_blocks_gate),
    S_(t_e10_framework_shape_ratchet),
    S_(t_e10_no_raw_sqlite_ratchet),
    S_(t_gate22_framework_filename_suffix),
    S_(t_gate_p2_group_purpose),
    S_(t_gate_p1_file_purpose),
    N_(t_gate_p3_orphan_placement),   /* judges a path list, nothing on disk */
    S_(t_e13_consensus_parity_fixture),
    S_(t_silent_errors_bool_fixture),
    S_(t_log_macro_return_type_gate),
    S_(t_e11_doc_accuracy),
    S_(t_model_ar_lifecycle_gate),
    S_(t_e2_one_result_type),
    S_(t_service_result_convergence_ratchet),
    S_(t_thread_supervision_ratchet),
    S_(t_supervisor_registration_widened_ratchet),
    S_(t_e3_shape_includes_header),
    S_(t_e4_projections_pure),
    S_(t_domain_purity),
    S_(t_shape_include_direction),
    S_(t_e5_stage_advances_or_blocks),
    S_(t_e6_one_write_path),
    S_(t_e7_no_authoritative_ram_state),
    S_(t_e12_honest_witness),
    S_(t_gate21_supervisor_worker_lockin),
    S_(t_hotswap_eligible_scope_gate),
    S_(t_hotswap_swappable_shape_gate),
    S_(t_hotswap_swappable_leaf_contract_gate),
    S_(t_hotswap_static_state_gate),
    S_(t_hotswap_static_state_covers_swappable),
    S_(t_hotswap_service_island_gate),
    S_(t_privileged_transition_receipt_gate),
    S_(t_blocker_escape_registered_gate),
    /* Read-only real scan plus a private Git-backed fixture repository. */
    N_(t_sync_state_no_ordinal_gate),
    S_(t_lint_gates_fail_loud_on_empty_scan),
    /* Hermetic: builds its fixture trees under TMPDIR and reads Makefile /
     * gate_commands.def, never writing into the worktree. */
    N_(t_lint_gate_wiring_gate),
    N_(t_lint_umbrellas_share_built_prereqs),
    /* Dispatch regression runs directly in the exact base group below. */
    N_(t_dev_proof_helpers_include_lint_tool),
    N_(t_dev_proof_prefork_runs_before_the_dimensions),
#if defined(__linux__)
    N_(t_dev_proof_runner_observations),
#endif
    S_(t_no_dev_history_in_contracts),
    S_(t_no_uncited_victory),
    /* Read-only root probe retained in the historical base group. */
    X_(t_no_stray_root_files),
    /* Slow, hermetic epoch fixtures own a group in the normal worker pool.
     * Append after existing heavy entries to preserve heavy_01/02 IDs. */
    H_(t_agent_fast_ci_contract),
};
#undef S_
#undef N_
#undef H_
#undef X_
#define LINT_GATE_ENTRY_COUNT \
    (sizeof(g_lint_gate_entries) / sizeof(g_lint_gate_entries[0]))

/* ── Partition ────────────────────────────────────────────────────────────
 * Owner of every entry: a shard index in [0, LINT_GATE_SHARD_COUNT) for the
 * sandbox lane, or one of the two negative tags. A pure function of the table,
 * so every process computes the same partition. */

#define LINT_OWNER_REALROOT   (-1)
#define LINT_OWNER_EXCLUSIVE  (-2)
#define LINT_OWNER_NONE       (-3)
/* Heavy lane owners are LINT_OWNER_HEAVY_BASE + k for the k-th HEAVY entry in
 * table order. */
#define LINT_OWNER_HEAVY_BASE (100)
#define LINT_GATE_HEAVY_COUNT (3)

/* Per-check cost in milliseconds, used to balance the shards. Measured: run
 * the family under ZCL_LINT_GATE_TIMING=1 and read the `[lint-gate-timing]
 * ... ms=` lines, taken with the whole family running concurrently. Values
 * only need to RANK correctly. Anything not listed is sub-500ms noise. */
static int lint_entry_weight_medium(lint_gate_fn fn);
static int lint_entry_weight_small(lint_gate_fn fn);

static int lint_entry_weight(lint_gate_fn fn)
{
    if (fn == t_silent_errors_bool_fixture)              return 59651;
    if (fn == t_no_dev_history_in_contracts)             return 51629;
    if (fn == t_agent_fast_ci_contract)                  return 26287;
    /* The cutover selftest's slow-box cases poll real clocks (~14s), plus the
     * host-watchdog and deploy_verify selftests. */
    if (fn == t_slow_disk_progress_verdicts_contract)    return 15500;
    if (fn == t_lint_gates_fail_loud_on_empty_scan)      return 21827;
    if (fn == t_gate22_framework_filename_suffix)        return 12435;
    if (fn == t_e1_file_size_bands)                      return 10960;
    if (fn == t_e1_file_size_baseline_and_hollow_scan)   return 7211;
    if (fn == t_long_functions_enforced_ratchet)         return 5180;
    if (fn == t_baseline_passes)                         return 4893;
    if (fn == t_gate_recovers_after_removal)             return 4889;
    if (fn == t_node_db_exec_fixture_trips_gate)         return 4889;
    if (fn == t_fixture_trips_gate)                      return 4885;
    if (fn == t_supervisor_registration_widened_ratchet) return 4749;
    return lint_entry_weight_medium(fn);
}

static int lint_entry_weight_medium(lint_gate_fn fn)
{
    if (fn == t_log_macro_return_type_gate)              return 3728;
    if (fn == t_long_functions_lib_warn_tier)            return 3608;
    if (fn == t_e12_honest_witness)                      return 2202;
    /* Measured standalone: a real-tree run ~1.17s plus the script's 6-case
     * --selftest ~1.33s. Re-measure under ZCL_LINT_GATE_TIMING=1 if shards
     * skew. */
    if (fn == t_dumper_never_blocks_gate)                return 2500;
    if (fn == t_blocker_escape_registered_gate)          return 2198;
    if (fn == t_shape_include_direction)                 return 1874;
    if (fn == t_e14_condition_cooldown_gate)             return 1654;
    if (fn == t_e2_one_result_type)                      return 1582;
    if (fn == t_systemd_memory_budget)                   return 1412;
    if (fn == t_e3_shape_includes_header)                return 1153;
    return lint_entry_weight_small(fn);
}

static int lint_entry_weight_small(lint_gate_fn fn)
{
    if (fn == t_privileged_transition_receipt_gate)      return 1030;
    if (fn == t_e5_stage_advances_or_blocks)             return 754;
    if (fn == t_no_uncited_victory)                      return 607;
    if (fn == t_hotswap_swappable_shape_gate)            return 540;
    if (fn == t_hotswap_swappable_leaf_contract_gate)    return 519;
    if (fn == t_hotswap_service_island_gate)             return 100;
    return 100;
}

/* Longest-processing-time-first bin packing: walk the sandbox entries
 * heaviest-first, dropping each into the currently lightest shard. Recomputed
 * per query so no cached state can drift from the table. */
static int lint_sandbox_owner_of(size_t idx)
{
    int order[LINT_GATE_ENTRY_COUNT];
    int n = 0;
    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++)
        if (g_lint_gate_entries[i].lane == LINT_LANE_SANDBOX)
            order[n++] = (int)i;

    for (int a = 1; a < n; a++) {   /* stable insertion sort, weight DESC */
        int cur = order[a];
        int cw = lint_entry_weight(g_lint_gate_entries[cur].fn);
        int b = a - 1;
        while (b >= 0 &&
               lint_entry_weight(g_lint_gate_entries[order[b]].fn) < cw) {
            order[b + 1] = order[b];
            b--;
        }
        order[b + 1] = cur;
    }

    long load[LINT_GATE_SHARD_COUNT];
    for (int b = 0; b < LINT_GATE_SHARD_COUNT; b++) load[b] = 0;

    int owner = LINT_OWNER_NONE;
    for (int k = 0; k < n; k++) {
        int lightest = 0;
        for (int b = 1; b < LINT_GATE_SHARD_COUNT; b++)
            if (load[b] < load[lightest]) lightest = b;
        load[lightest] += lint_entry_weight(g_lint_gate_entries[order[k]].fn);
        if ((size_t)order[k] == idx) owner = lightest;
    }
    return owner;
}

static int lint_owner_of(size_t idx)
{
    if (idx >= LINT_GATE_ENTRY_COUNT) return LINT_OWNER_NONE;
    switch (g_lint_gate_entries[idx].lane) {
    case LINT_LANE_REALROOT:  return LINT_OWNER_REALROOT;
    case LINT_LANE_EXCLUSIVE: return LINT_OWNER_EXCLUSIVE;
    case LINT_LANE_HEAVY: {
        int k = 0;
        for (size_t i = 0; i < idx; i++)
            if (g_lint_gate_entries[i].lane == LINT_LANE_HEAVY) k++;
        /* A HEAVY entry with no group would vanish; the partition test
         * asserts the count. */
        if (k >= LINT_GATE_HEAVY_COUNT) return LINT_OWNER_NONE;
        return LINT_OWNER_HEAVY_BASE + k;
    }
    case LINT_LANE_SANDBOX:   break;
    }
    return lint_sandbox_owner_of(idx);
}

static int lint_owner_for_check(lint_gate_fn fn)
{
    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++)
        if (g_lint_gate_entries[i].fn == fn)
            return lint_owner_of(i);
    return LINT_OWNER_NONE;
}

/* ── Runners ──────────────────────────────────────────────────────────── */

/* Run every entry this owner owns, in table order. Under ZCL_LINT_GATE_TIMING=1
 * each check's wall time goes to stderr (the data lint_entry_weight() uses). */
static int lint_run_owned(int owner)
{
    const char *timing = getenv("ZCL_LINT_GATE_TIMING");
    int report = (timing && *timing && strcmp(timing, "0") != 0);
    int failures = 0;

    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++) {
        if (lint_owner_of(i) != owner) continue;
        int64_t t0 = clock_now_monotonic_ns();
        failures += g_lint_gate_entries[i].fn();
        if (report) {
            long long ms =
                (long long)((clock_now_monotonic_ns() - t0) / 1000000);
            fprintf(stderr, "[lint-gate-timing] owner=%d entry=%zu ms=%lld\n",
                    owner, i, ms);
        }
    }
    return failures;
}

/* Build an inode-independent clone ("sandbox") of the worktree at sb_root.
 * Everything except build/.git/.cache/.codeindex/test-tmp/.claude is copied with
 * --reflink=auto (CoW where supported, else a regular copy). Hardlinks are
 * forbidden: creating/removing one changes the live inode ctime and falsely
 * supersedes source proof epochs. test-tmp is created fresh. Returns 0.
 *
 * build/ is skipped except build/bin/file_size_policy (the E1 file-size gate)
 * and build/bin/z23-lint (the shared lint runtime several gate scripts exec);
 * both are binaries, so they do not ride in with the source tree. Both copies
 * are best-effort: an unbuilt tree must not fail every shard's construction.
 *
 * Uses fork_with_retry(), not a bare fork(): this runs concurrently per shard
 * from the large test_zcl process and needs the same EAGAIN/ENOMEM retry
 * margin documented in lint_gate_helpers.c. */
static int lint_sandbox_build(const char *real_root, const char *sb_root)
{
    pid_t pid = fork_with_retry();
    if (pid < 0) {
        fprintf(stderr, "[lint-gate] lint_sandbox_build: fork failed: %s\n",
                strerror(errno));
        return -1;
    }
    if (pid == 0) {
        static const char *script =
            "set -e\n"
            "rm -rf \"$2\"\n"
            "mkdir -p \"$2\"\n"
            "for e in \"$1\"/* \"$1\"/.[!.]*; do\n"
            "  [ -e \"$e\" ] || continue\n"
            "  b=${e##*/}\n"
            "  case \"$b\" in build|.git|.cache|.codeindex|test-tmp|.claude) continue;; esac\n"
            "  cp -a --reflink=auto \"$e\" \"$2\"/\n"
            "done\n"
            "mkdir -p \"$2\"/test-tmp \"$2\"/build/bin\n"
            "cp -a --reflink=auto \"$1\"/build/bin/file_size_policy \"$2\"/build/bin/ 2>/dev/null || :\n"
            "cp -a --reflink=auto \"$1\"/build/bin/z23-lint \"$2\"/build/bin/ 2>/dev/null || :\n";
        execl("/bin/sh", "sh", "-c", script, "sh",
              real_root, sb_root, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "[lint-gate] lint_sandbox_build: waitpid failed: %s\n",
                strerror(errno));
        return -1;
    }
    return (WIFEXITED(st) && WEXITSTATUS(st) == 0) ? 0 : -1;
}

/* Length of the sandbox-kind tag at the start of kind (".lint_sb_" or
 * ".lint_meta_"), or 0 when the entry is not a sandbox base of ours. */
static size_t lint_stale_kind_len(const char *kind)
{
    if (strncmp(kind, ".lint_sb_", 9) == 0) return 9;
    if (strncmp(kind, ".lint_meta_", 11) == 0) return 11;
    return 0;
}

/* Minimum age before a dead-owner sandbox of ANOTHER base is reaped. */
#define LINT_STALE_OTHER_AGE_S (6 * 3600)

/* True when pidstr names a process that is GONE, so its base is stale. */
static bool lint_stale_owner_is_dead(const char *pidstr)
{
    /* Exactly what lint_run_shard and the metadata test write: decimal
     * digits only (no sign or blank strtol would take), within int. */
    size_t ndig = strspn(pidstr, "0123456789");
    if (ndig == 0 || ndig > 10 || pidstr[ndig] != '\0') return false;
    long long owner_pid = strtoll(pidstr, NULL, 10);
    if (owner_pid <= 0 || owner_pid > INT_MAX) return false;
    /* Alive — or alive but owned by another user (EPERM) — leave it be.
     * A copy child orphaned by a kill may still write for a few seconds
     * after its owner is gone; whatever it recreates past this purge has
     * the same dead owner and goes on the next run. */
    errno = 0;
    return kill((pid_t)owner_pid, 0) != 0 && errno == ESRCH;
}

/* Pid text of a sandbox entry name, or NULL. Our own base matches by prefix;
 * any other base by the first ".lint_sb_"/".lint_meta_" tag after a name. */
static const char *lint_stale_pid_text(const char *name, const char *base,
                                       size_t blen, bool *own)
{
    *own = strncmp(name, base, blen) == 0 &&
           lint_stale_kind_len(name + blen) != 0;
    const char *tag = name + blen;
    if (!*own) {
        tag = strstr(name, ".lint_sb_");
        if (!tag) tag = strstr(name, ".lint_meta_");
        if (!tag || tag == name) return NULL;
    }
    return tag + lint_stale_kind_len(tag);
}

/* Our own base: a dead owner is enough. Any other base (one-shot gate copies
 * are never run again under the same name): the owner must be dead AND the
 * entry older than LINT_STALE_OTHER_AGE_S, so a reused pid cannot make a
 * live neighbour's sandbox look stale. Fills victim with the full path. */
static bool lint_stale_is_reapable(const char *parent, const char *name,
                                   const char *base, size_t blen,
                                   char *victim, size_t vsz)
{
    bool own;
    const char *pidstr = lint_stale_pid_text(name, base, blen, &own);
    if (!pidstr || pidstr == name || !lint_stale_owner_is_dead(pidstr))
        return false;
    if (snprintf(victim, vsz, "%s/%s", parent, name) >= (int)vsz) return false;
    if (own) return true;
    struct stat vst;
    return lstat(victim, &vst) == 0 && S_ISDIR(vst.st_mode) &&
           time(NULL) - vst.st_mtime >= LINT_STALE_OTHER_AGE_S;
}

/* Remove sandbox bases leaked by a killed run: shard bases (.lint_sb_) and
 * the metadata test's base (.lint_meta_), each a full tree copy. Only bases
 * whose owning process is GONE are reaped (shards run concurrently). Called
 * from the exclusive lane, which runs before any shard starts. */
static void lint_purge_stale_sandboxes(const char *real_root)
{
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s", real_root) >= (int)sizeof(tmp))
        return;
    char *slash = strrchr(tmp, '/');
    if (!slash || slash == tmp) return;
    *slash = '\0';
    const char *parent = tmp;
    const char *base = slash + 1;
    size_t blen = strlen(base);

    DIR *d = opendir(parent);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        char victim[PATH_MAX];
        if (!lint_stale_is_reapable(parent, e->d_name, base, blen, victim,
                                    sizeof(victim)))
            continue;
        (void)test_rm_rf_recursive(victim);
    }
    closedir(d);
}

/* Resolve the required source root. A missing root cannot qualify any lane:
 * return 0 to proceed and -1 when the registered entry must fail. */
static int lint_resolve_real_root(char *out, size_t outsz)
{
    struct stat st;
    char fixture_src[PATH_MAX];
    char makefile[PATH_MAX];
    if (repo_path(fixture_src, sizeof(fixture_src), FIXTURE_SRC_REL) != 0 ||
        repo_path(makefile, sizeof(makefile), "Makefile") != 0 ||
        stat(fixture_src, &st) != 0 || stat(makefile, &st) != 0) {
        fprintf(stderr, "[lint-gate] FAIL: required source root is unavailable\n");
        return -1;
    }
    const char *root = repo_root();
    if (!root) {
        fprintf(stderr, "[lint-gate] FAIL: required source root is unavailable\n");
        return -1;
    }
    if (snprintf(out, outsz, "%s", root) >= (int)outsz) {
        fprintf(stderr, "[lint-gate] FAIL: required source root path is too long\n");
        return -1;
    }
    return 0;
}

/* One shard: build a private sandbox, run this shard's slice inside it, tear
 * it down. Any sandbox failure FAILS LOUD instead of falling back to the real
 * worktree: planting fixtures in the live tree while other groups run is the
 * flake the split avoids. */
static int lint_run_shard(int shard)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 1;

    printf("\n=== make_lint_gates shard %d tests ===\n", shard);

    char sb_base[PATH_MAX], sb_root[PATH_MAX];
    if (snprintf(sb_base, sizeof(sb_base), "%s.lint_sb_%d",
                 real_root, (int)getpid()) >= (int)sizeof(sb_base) ||
        snprintf(sb_root, sizeof(sb_root), "%s/w%d", sb_base, shard) >=
            (int)sizeof(sb_root)) {
        printf("[lint-gate] FAIL: shard %d sandbox path too long\n", shard);
        return 1;
    }

    if (mkdir(sb_base, 0700) != 0 && errno != EEXIST) {
        printf("[lint-gate] FAIL: shard %d could not create sandbox base %s "
               "(%s)\n", shard, sb_base, strerror(errno));
        return 1;
    }
    if (lint_sandbox_build(real_root, sb_root) != 0) {
        printf("[lint-gate] FAIL: shard %d could not build its sandbox at %s "
               "— refusing to plant fixtures into the live worktree\n",
               shard, sb_root);
        (void)test_rm_rf_recursive(sb_base);
        return 1;
    }

    /* Enter the sandbox: repo_root_set_override points repo_path() into it and
     * chdir() makes RELATIVE-path checks land in the same tree the gate scans. */
    if (chdir(sb_root) != 0) {
        printf("[lint-gate] FAIL: shard %d could not enter its sandbox %s "
               "(%s)\n", shard, sb_root, strerror(errno));
        (void)test_rm_rf_recursive(sb_base);
        return 1;
    }
    repo_root_set_override(sb_root);
    unlink_lint_fixtures();          /* defensive clean start in this sandbox */

    /* The sandbox has .git deliberately EXCLUDED (see lint_sandbox_build).
     * Gates that verify their scan coverage against a git-derived expectation
     * (gate_lib.sh gate_git_oracle) fail closed without a git index, so opt
     * them out here for every gate this shard runs; each gate's own
     * `--selftest` proves coverage where the oracle exists. A new git-oracle
     * gate belongs on this list. */
    (void)setenv("ZCL_SUPDOM_COVERAGE",    "0", 1);
    (void)setenv("ZCL_THREADSUP_COVERAGE", "0", 1);
    (void)setenv("ZCL_SUPREG_COVERAGE",    "0", 1);
    (void)setenv("ZCL_LONGFN_COVERAGE",    "0", 1);
    (void)setenv("ZCL_NDH_COVERAGE",       "0", 1);

    int failures = lint_run_owned(shard);

    (void)unsetenv("ZCL_SUPDOM_COVERAGE");
    (void)unsetenv("ZCL_THREADSUP_COVERAGE");
    (void)unsetenv("ZCL_SUPREG_COVERAGE");
    (void)unsetenv("ZCL_LONGFN_COVERAGE");
    (void)unsetenv("ZCL_NDH_COVERAGE");

    repo_root_set_override(NULL);
    if (chdir(real_root) != 0)
        fprintf(stderr, "[lint-gate] shard %d: chdir back to %s failed: %s\n",
                shard, real_root, strerror(errno));
    (void)test_rm_rf_recursive(sb_base);
    return failures;
}

/* ── Registered entry points ──────────────────────────────────────────────
 * The shard bodies are generated from ONE list; adding or removing a shard is
 * one edit here plus the ZCL_TEST_GROUP row in tools/dev/test_group_catalog.def.
 * check-test-registration only treats a FILENAME-matching `int test_<name>(void)`
 * as an entry point, so these definitions are invisible to it while the
 * catalog rows bind name -> symbol. */

#define LINT_SHARD_ENTRY(tag, idx) \
    int test_make_lint_gates_shard_##tag(void) { return lint_run_shard(idx); }
LINT_SHARD_LIST(LINT_SHARD_ENTRY)
#undef LINT_SHARD_ENTRY

/* Exercise the actual Makefile in a tiny private tree: the overlay replaces
 * unrelated build tools and makes Tor readiness an observable refusal. */
static int t_lint_fast_tor_graph(void)
{
    static const char script[] =
        "set -eu; cd \"$2\"\n"
        "mkdir -p platform/modules/platform/tests engine/composition tools/dev tools/lint home tmp\n"
        "cp \"$1/Makefile\" Makefile\n"
        "mkdir -p apps/skycombat; cp \"$1/apps/skycombat/skycombat.mk\" apps/skycombat/\n"
        "cp \"$1/platform/modules/platform/tests/windows_acceptance.mk\" platform/modules/platform/tests/\n"
        "cp \"$1/platform/modules/platform/tests/android_acceptance.mk\" platform/modules/platform/tests/\n"
        "cp \"$1/engine/composition/lib_module_order.def\" engine/composition/\n"
        "if [ -f \"$1/tools/retrieval_pair_sources.mk\" ]; then cp \"$1/tools/retrieval_pair_sources.mk\" tools/; fi\n"
        "printf '#!/bin/sh\\necho compiler >> \"$HOME/compiler-calls\"\\nexit 0\\n' > tools/dev/check-toolchain.sh\n"
        "printf '#!/bin/sh\\necho epoch >> \"$HOME/epoch-calls\"\\nprintf fixture\\n' > tools/dev/process-start-token.sh\n"
        "printf '#!/bin/sh\\necho \"$1\" >> \"$HOME/calls\"\\nif [ \"$1\" = run ]; then printf \"%%s\\\\n\" \"$@\" > \"$HOME/args\"; fi\\n[ \"${FAIL_STAGE:-}\" != \"$1\" ]\\n' > stub-lint\n"
        "chmod +x tools/dev/check-toolchain.sh tools/dev/process-start-token.sh stub-lint\n"
        "printf '%s\\n' '.PHONY: tor-provenance-ready check-native-tunnel-export-binding' 'tor-provenance-ready:' '\t@printf called > \"$(HOME)/tor\"; exit 77' 'check-native-tunnel-export-binding:' '\t@printf binding > \"$(HOME)/binding\"' 'fixture-print-gates:' '\t@printf \"%s\\\\n\" $(LINT_FAST_GATES)' > overlay.mk\n"
        "HOME=\"$2/home\" TMPDIR=\"$2/tmp\"; export HOME TMPDIR\n"
        "fixture_make() { make --no-print-directory -o /dev/null -o ./stub-lint -f Makefile -f overlay.mk ZCL_LINT_FAST_PRECHECK=1 ZCL_LINT_SERIAL=0 ZCL_USE_CCACHE=0 MAKE_RESTARTS=1 LIB_MODULES=platform LIB_TREE_MODULES=platform ZCL_EPOCH_PROFILES= ZCL_DEPFILE_PROFILES= TEST_GROUP_LIST_BIN=/bin/echo TEST_GROUP_LIST_SRCS=/dev/null TEST_GROUP_LIST_HDRS=/dev/null TEST_GROUP_LIST_BUILD=: 'BUILD_SOURCE_RECORD=0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000' EQUIHASH_FACT_TOOL=/dev/null LINTC_TOOL=./stub-lint FILE_SIZE_POLICY_BIN=/dev/null TOOLGEN_BIN=/dev/null TOR_PROVENANCE_BIN=/dev/null HOTSWAP_ACTION_PLAN=/dev/null CAPABILITY_INVENTORY_TOOL=/dev/null ZCODE_PACKAGE_REGISTRY_CHECK_BIN=/dev/null REPRO_NETWORK_POLICY_SELFTEST_BIN=/dev/null BUILD_EPOCH_INTEGRITY_LINT_BIN=/dev/null CHECKOUT_LOCK_SELFTEST_LINT_BIN=/dev/null \"$@\"; }\n"
        "if ! fixture_make fixture-print-gates > expected 2>parse.log; then cat parse.log >&2; exit 1; fi\n"
        "if ! fixture_make lint-fast > run.log 2>&1; then cat run.log >&2; exit 1; fi\n"
        "[ ! -e \"$HOME/tor\" ]; [ -e \"$HOME/binding\" ]; [ -s \"$HOME/args\" ]\n"
        "tail -n +6 \"$HOME/args\" > actual; cmp expected actual\n"
        "grep -qx check-vendor-provenance actual\n"
        "fixture_make -n -p ZCL_LINT_SERIAL=1 lint-fast > serial.db 2>&1 || :\n"
        "grep -E '^lint-fast: .*check-vendor-provenance' serial.db >/dev/null\n"
        "grep -E '^check-vendor-provenance: .*tor-provenance-ready' serial.db >/dev/null\n"
        "grep -E '^check-tor-provenance: .*tor-provenance-ready' serial.db >/dev/null\n"
        "grep -E '^lint: .*check-tor-provenance' serial.db >/dev/null\n"
        "fixture_make -n -p lint-land > land.db 2>&1 || :\n"
        "grep -E '^lint-land: .*tor-provenance-ready' land.db >/dev/null\n";
    static const char checks[] =
        "printf '%s\\n' '.PHONY: fixture-fast' 'fixture-fast:' '\t@test \"$(FAIL_GATE)\" != 1' >> overlay.mk\n"
        "rm -f \"$HOME/calls\"\n"
        "if FAIL_STAGE=run fixture_make lint-fast > fail.log 2>&1; then echo 'fast failure accepted' >&2; exit 1; fi\n"
        "[ \"$(grep -c '^precheck$' \"$HOME/calls\" || :)\" = 0 ] || { echo 'precheck ran after fast failure' >&2; exit 1; }\n"
        "grep -F 'lint-fast: precheck skipped after fast subset failure' fail.log >/dev/null\n"
        "rm -f \"$HOME/calls\"; fixture_make lint-fast > pass.log 2>&1\n"
        "[ \"$(grep -c '^precheck$' \"$HOME/calls\")\" = 1 ]\n"
        "rm -f \"$HOME/calls\"; if FAIL_STAGE=precheck fixture_make lint-fast > precheck-fail.log 2>&1; then exit 1; fi\n"
        "[ \"$(grep -c '^precheck$' \"$HOME/calls\")\" = 1 ]\n"
        "rm -f \"$HOME/calls\"; fixture_make lint-fast ZCL_LINT_FAST_PRECHECK=0 > optout.log 2>&1\n"
        "[ \"$(grep -c '^precheck$' \"$HOME/calls\" || :)\" = 0 ]\n"
        "rm -f \"$HOME/calls\"; if fixture_make lint-fast ZCL_LINT_SERIAL=1 LINT_FAST_GATES=fixture-fast FAIL_GATE=1 > serial-fail.log 2>&1; then exit 1; fi\n"
        "[ ! -e \"$HOME/calls\" ]\n"
        "fixture_make lint-fast ZCL_LINT_SERIAL=1 LINT_FAST_GATES=fixture-fast > serial-pass.log 2>&1\n"
        "[ \"$(grep -c '^precheck$' \"$HOME/calls\")\" = 1 ]\n"
        "rm -f \"$HOME/calls\"; if FAIL_STAGE=precheck fixture_make lint-fast ZCL_LINT_SERIAL=1 LINT_FAST_GATES=fixture-fast > serial-precheck-fail.log 2>&1; then exit 1; fi\n"
        "[ \"$(grep -c '^precheck$' \"$HOME/calls\")\" = 1 ]\n"
        "rm -f \"$HOME/calls\"; fixture_make lint-fast ZCL_LINT_SERIAL=1 LINT_FAST_GATES=fixture-fast ZCL_LINT_FAST_PRECHECK=0 > serial-optout.log 2>&1\n"
        "[ ! -e \"$HOME/calls\" ]\n";
    static const char epoch_checks[] =
        "rm -f \"$HOME/epoch-calls\" \"$HOME/compiler-calls\"\n"
        "for fast in t-fast t-fast-exact; do for build in dev-bin z23-dev zclassic23-dev z23 zclassic23; do\n"
        "  for order in first second; do\n"
        "    if [ \"$order\" = first ]; then set -- \"$fast\" \"$build\"; else set -- \"$build\" \"$fast\"; fi\n"
        "    if fixture_make \"$@\" ONLY=models > mixed.log 2>&1; then echo 'mixed goals accepted' >&2; exit 1; fi\n"
        "    grep -F 'mixed fast-test and dev/node build goals cannot share one Make' mixed.log >/dev/null\n"
        "    [ ! -e \"$HOME/epoch-calls\" ] && [ ! -e \"$HOME/compiler-calls\" ] && [ ! -e build/test-obj ] || { echo 'mixed goals entered compiler or epoch setup' >&2; exit 1; }\n"
        "  done\n"
        "done; done\n"
        "printf '%s\\n' '.DEFAULT:' '\t@:' >> overlay.mk\n"
        "for goal in t-fast t-fast-exact dev-bin z23-dev zclassic23-dev z23 zclassic23 agent-verify dev-proof-bundle-prefork; do\n"
        "  rc=0; fixture_make -n -p -q \"$goal\" ONLY=models > single.log 2>&1 || rc=$?\n"
        "  if [ \"$rc\" -gt 1 ] || grep -F 'mixed fast-test and dev/node build goals cannot share one Make' single.log >/dev/null; then echo \"single goal refused: $goal rc=$rc\" >&2; exit 1; fi\n"
        "  if [ \"$goal\" = dev-proof-bundle-prefork ]; then grep '^dev-proof-bundle-prefork:' single.log >/dev/null; fi\n"
        "done\n"
        "rc=0; fixture_make -n -p -q dev-bin z23 > pair.log 2>&1 || rc=$?\n"
        "if [ \"$rc\" -gt 1 ] || grep -F 'mixed fast-test and dev/node build goals cannot share one Make' pair.log >/dev/null; then echo \"direct build pair refused rc=$rc\" >&2; exit 1; fi\n"
        "grep '^dev-bin:' pair.log >/dev/null; grep '^z23:' pair.log >/dev/null\n";
    static const char union_checks[] =
        "printf '#!/bin/sh\\nprintf \"%%s\\\\n\" \"$1\" >> \"$HOME/calls\"\\nprintf \"%%s\\\\n\" \"$@\" > \"$HOME/$1-args\"\\nprintf \"%%s\\\\n\" \"${ZCL_CAP_CLOSURE_SOURCE_RECORD:-}\" > \"$HOME/$1-record\"\\n[ \"${FAIL_STAGE:-}\" != \"$1\" ]\\n' > stub-lint\n"
        "chmod +x stub-lint\n"
        "printf '%s\\n' '.PHONY: fixture-a fixture-b fixture-c' 'fixture-a fixture-b fixture-c:' '\t@printf \"%s\\\\n\" \"$@\" >> \"$(HOME)/serial-calls\"; test \"$(FAIL_GATE)\" != 1' >> overlay.mk\n"
        "union_make() { fixture_make -o lint-preflight-epoch-verify -o check-native-tunnel-export-binding Z23_DEV_BIN=/dev/null DEV_PACKAGE_VERIFY_BIN=/dev/null CAPABILITY_STANDALONE_OBJS= 'LINT_FAST_GATES=fixture-a fixture-b' 'LINT_PREFLIGHT_GATES=fixture-b fixture-c' 'LINT_FAST_PRECHECK_NATIVE=fixture-a fixture-b fixture-c' \"$@\"; }\n"
        "rm -f \"$HOME/calls\"; union_make lint-fast-preflight > union.log 2>&1 || { cat union.log >&2; exit 1; }\n"
        "printf 'run\\nprecheck\\n' > expected-calls; cmp expected-calls \"$HOME/calls\"\n"
        "printf 'fixture-a\\nfixture-b\\nfixture-c\\n' > expected-union; tail -n +6 \"$HOME/run-args\" > actual-union; cmp expected-union actual-union\n"
        "grep -Fx -- '--skip=fixture-a,fixture-b,fixture-c' \"$HOME/precheck-args\" >/dev/null\n"
        "grep -F '0000000000000000' \"$HOME/run-record\" >/dev/null\n"
        "rm -f \"$HOME/calls\"; if FAIL_STAGE=run union_make lint-fast-preflight > union-fail.log 2>&1; then exit 1; fi\n"
        "[ \"$(grep -c '^precheck$' \"$HOME/calls\" || :)\" = 0 ]\n"
        "rm -f \"$HOME/calls\"; if FAIL_STAGE=precheck union_make lint-fast-preflight > union-precheck-fail.log 2>&1; then exit 1; fi\n"
        "rm -f \"$HOME/calls\" \"$HOME/serial-calls\"; union_make -j1 lint-fast-preflight ZCL_LINT_SERIAL=1 > union-serial.log 2>&1\n"
        "cmp expected-union \"$HOME/serial-calls\"; [ \"$(grep -c '^precheck$' \"$HOME/calls\")\" = 1 ]\n"
        "rm -f \"$HOME/calls\"; if union_make -j1 lint-fast-preflight ZCL_LINT_SERIAL=1 FAIL_GATE=1 > union-serial-fail.log 2>&1; then exit 1; fi\n"
        "[ ! -e \"$HOME/calls\" ]\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "lint_fast", "tor_graph");
    char combined[sizeof(script) + sizeof(checks) + sizeof(epoch_checks) + sizeof(union_checks)];
    int n = snprintf(combined, sizeof(combined), "%s%s%s%s", script, checks, union_checks, epoch_checks);
    if (n < 0 || (size_t)n >= sizeof(combined)) return 1;
    int bad = build_needs_fixture_run(repo_root(), fixture, combined);
    if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

/* Exercise the real bootstrap conditional with a private readiness oracle.
 * The oracle models legacy migration, reuse and refusal; Tor's provenance
 * checker has its own fixtures for the validity of those decisions. */
static int t_tor_ready_before_link(void)
{
    static const char script[] =
        "set -eu; cd \"$2\"\n"
        "mkdir -p build/identity tools/scripts\n"
        "printf '#!/bin/sh\\necho probe >> events\\ntest -f ready-marker\\n' > tools/scripts/tor_archives_ready.sh; chmod +x tools/scripts/tor_archives_ready.sh\n"
        "printf '%s\\n' 'ZCL_TOR ?= full' 'ZCL_TOR_LINK_REQUESTED := link' 'TOR_BOOTSTRAP_MK := build/identity/tor-inputs-ready.mk' 'TOR_MISSING_ARCHIVES :=' > Makefile\n"
        "sed -n '/^ifeq ($(ZCL_TOR),full)/,/^# The stub/{ /^# The stub/d; p; }' \"$1/Makefile\" >> Makefile\n"
        "sed -n '/^tor-ready: /p' \"$1/Makefile\" >> Makefile\n"
        "cat >> Makefile <<'MAKE'\n"
        "$(shell echo parse >> parse-events)\n"
        ".PHONY: tor-ready link\n"
        ".PHONY: vendor-ready\n"
        "vendor-ready:\n\t@echo vendor >> events; : > vendor-marker\n"
        "tor-ready:\n\t@test -f vendor-marker; echo ready >> events; case \"$(STATE)\" in legacy) echo rebuilt >> events ;; stale|missing|valid) : ;; *) exit 1 ;; esac; : > ready-marker\n"
        "$(TOR_BOOTSTRAP_MK): tor-ready\n\t@echo '# ready' > $@\n"
        "link:\n\t@echo link:$(MAKE_RESTARTS) >> events\n"
        "MAKE\n"
        "printf '# old stamp\\n' > build/identity/tor-inputs-ready.mk\n"
        "touch -t 200001010000 build/identity/tor-inputs-ready.mk\n"
        "make --no-print-directory STATE=legacy link > run.log 2>&1\n"
        "printf 'probe\\nvendor\\nready\\nrebuilt\\nlink:1\\n' > expected; cmp expected events\n"
        "[ \"$(wc -l < parse-events)\" -eq 2 ]\n"
        ": > events; : > parse-events; make --no-print-directory STATE=valid link > run.log 2>&1\n"
        "printf 'probe\\nlink:\\n' > expected; cmp expected events\n"
        "[ \"$(wc -l < parse-events)\" -eq 1 ]\n"
        ": > events; : > parse-events; rm ready-marker vendor-marker; touch -t 200001010000 build/identity/tor-inputs-ready.mk; make --no-print-directory -j2 STATE=stale link > run.log 2>&1\n"
        "printf 'probe\\nvendor\\nready\\nlink:1\\n' > expected; cmp expected events\n"
        "[ \"$(wc -l < parse-events)\" -eq 2 ]\n"
        ": > events; : > parse-events; rm ready-marker vendor-marker; touch -t 200001010000 build/identity/tor-inputs-ready.mk; make --no-print-directory -j2 STATE=missing link > run.log 2>&1\n"
        "printf 'probe\\nvendor\\nready\\nlink:1\\n' > expected; cmp expected events\n"
        "[ \"$(wc -l < parse-events)\" -eq 2 ]\n"
        ": > events; : > parse-events; rm ready-marker vendor-marker; if make --no-print-directory STATE=refuse link > run.log 2>&1; then exit 1; fi\n"
        "printf 'probe\\nvendor\\nready\\n' > expected; cmp expected events\n"
        "[ \"$(wc -l < parse-events)\" -eq 1 ]\n"
        ": > events; : > parse-events; make --no-print-directory ZCL_TOR=stub STATE=refuse link > run.log 2>&1\n"
        "printf 'link:\\n' > expected; cmp expected events\n"
        "[ \"$(wc -l < parse-events)\" -eq 1 ]\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "tor_ready", "bootstrap");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

/* Exercise the real target edges with parallel bootstrap requests. */
static int t_tor_waits_for_vendor(void)
{
    static const char script[] =
        "set -eu; cd \"$2\"\n"
        "{ printf 'ZCL_TOR ?= full\\n.PHONY: all vendor-ready tor-ready tor-full\\n'; "
        "sed -n '/^tor-full: /p; /^tor-ready: /p' \"$1/Makefile\"; "
        "printf 'all: tor-ready tor-full\\nvendor-ready:\\n\\t@printf ready > vendor-marker\\n'; "
        "printf 'tor-ready tor-full:\\n\\t@test -s vendor-marker\\n'; } > Makefile\n"
        "make --no-print-directory -j2 all > run.log 2>&1\n"
        "rm vendor-marker; make --no-print-directory -n ZCL_TOR=stub tor-ready > stub.log 2>&1\n"
        "! grep -q 'printf ready' stub.log\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "tor_ready", "vendor_order");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

/* The real-worktree read-only lane: git grep / git ls-files / .git/hooks
 * probes. Mutates no tracked path, so it is pool-eligible. */
/* Exercise the actual ci-install recipe and its two nested make commands in
 * a private tree, without starting a node or running the installation gate. */
static int t_ci_install_jobserver(void)
{
    static const char script[] =
        "set -eu; cd \"$2\"; mkdir -p tools/scripts bin\n"
        "REAL_MAKE=$(command -v make); export REAL_MAKE; REPO_ROOT=$PWD; export REPO_ROOT\n"
        "sed -n '/^ZCL_MAKE_SHORT_FLAGS :=/,/^$/p' \"$1/Makefile\" > Makefile\n"
        "printf '.PHONY: ci-install zclassic23 zcl-rpc z23-package-verify z23-package-sign install\\n' >> Makefile\n"
        "printf 'zclassic23 zcl-rpc z23-package-verify z23-package-sign install:\\n\\t@printf nested\\\\n >> events\\n' >> Makefile\n"
        "sed -n '/^ci-install: /,+1p' \"$1/Makefile\" >> Makefile\n"
        "printf '#!/bin/bash\\nset -e\\nPREFIX=/tmp/fixture\\ngate_die() { exit 1; }\\n' > tools/scripts/ci_install_gate.sh\n"
        "sed -n '/^set --$/,/|| gate_die/p; /^make -C .* install DESTDIR=/,/|| gate_die/p' \"$1/tools/scripts/ci_install_gate.sh\" >> tools/scripts/ci_install_gate.sh\n"
        "[ \"$(grep -c '^make -C ' tools/scripts/ci_install_gate.sh)\" = 2 ] || { echo 'nested command extraction failed' >&2; exit 1; }\n"
        "printf 'LIVE_HOME=/tmp FAKE_BIN=/tmp STAGED_HOME=/tmp\\n' >> tools/scripts/ci_install_gate.sh\n"
        "sed -n '/^live_install() {/,/^}/p; /^HOME=\"$STAGED_HOME\" PATH=/,/|| gate_die/p' \"$1/tools/scripts/ci_install_gate.sh\" >> tools/scripts/ci_install_gate.sh\n"
        "printf 'live_install\\nlive_install\\n' >> tools/scripts/ci_install_gate.sh\n"
        "printf '#!/bin/sh\\nprintf \"%%s\\\\n\" \"$MAKEFLAGS\" >> makeflags\\n[ \"${FAIL_NESTED:-0}\" = 0 ] || exit 7\\nexec \"$REAL_MAKE\" \"$@\"\\n' > bin/make; chmod +x bin/make\n"
        "PATH=$PWD/bin:$PATH; export PATH\n"
        "\"$REAL_MAKE\" -j8 ci-install > run.log 2>&1 || { cat run.log; exit 1; }\n"
        "[ \"$(wc -l < makeflags)\" = 5 ] && [ \"$(grep -c jobserver-auth makeflags)\" = 5 ]\n"
        "if grep -E 'jobserver unavailable|forced in submake' run.log; then exit 1; fi\n"
        "rm -f events makeflags; for flag in -n -q -t; do rc=0; \"$REAL_MAKE\" \"$flag\" ci-install > dry.log 2>&1 || rc=$?; [ \"$rc\" -le 1 ] && [ ! -e events ] && [ ! -e makeflags ]; done\n"
        "rc=0; FAIL_NESTED=1 \"$REAL_MAKE\" -j8 ci-install > failure.log 2>&1 || rc=$?; [ \"$rc\" != 0 ]\n"
        "rm -f events makeflags; env -u MAKEFLAGS -u MFLAGS -u MAKELEVEL bash tools/scripts/ci_install_gate.sh > standalone.log 2>&1 || { cat standalone.log; exit 1; }; [ \"$(wc -l < makeflags)\" = 5 ]\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "lint_fast", "ci_install_jobserver");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

/* Run the actual target recipe with private stubs; the production ratchet must
 * run after its fixtures and a refusal must propagate through Make. */
static int t_shell_host_assumptions_recipe(void)
{
    static const char script[] =
        "set -eu; cd \"$2\"; mkdir -p build/bin tools/scripts\n"
        "printf '.PHONY: check-shell-host-assumptions\\ncheck-shell-host-assumptions:\\n' > Makefile\n"
        "awk '/^check-shell-host-assumptions:/{f=1;next} f && /^\\t/{print;next} f{exit}' \"$1/Makefile\" >> Makefile\n"
        "printf '#!/bin/sh\\nprintf \"%%s\\\\n\" \"$*\" >> calls\\n[ \"${FAIL_RATCHET:-0}\" = 0 ] || [ \"$#\" != 1 ]\\n' > build/bin/z23-lint\n"
        "printf '#!/bin/sh\\nexit 0\\n' > build/bin/isolated-readiness-selftest; cp build/bin/isolated-readiness-selftest build/bin/service-args\n"
        "cp build/bin/isolated-readiness-selftest tools/scripts/port_probe.sh; cp build/bin/isolated-readiness-selftest tools/scripts/commons_fix_admit.sh; cp build/bin/isolated-readiness-selftest tools/scripts/two_node_peer_tip_selftest.sh\n"
        "chmod +x build/bin/* tools/scripts/*\n"
        "make --no-print-directory BIN_DIR=build/bin check-shell-host-assumptions > pass.log 2>&1 || { cat pass.log; exit 1; }\n"
        "printf 'check-shell-host-assumptions --selftest\\ncheck-shell-host-assumptions\\n' > expected; cmp expected calls\n"
        "rm calls; if FAIL_RATCHET=1 make --no-print-directory BIN_DIR=build/bin check-shell-host-assumptions > fail.log 2>&1; then echo 'ratchet failure accepted' >&2; exit 1; fi\n"
        "cmp expected calls\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "lint_fast", "shell_host");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

int test_make_lint_gates_realroot(void)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 1;
    printf("\n=== make_lint_gates real-worktree tests ===\n");
    return t_shell_host_assumptions_recipe() + t_lint_fast_tor_graph() + t_tor_ready_before_link() + t_tor_waits_for_vendor() + t_ci_install_jobserver() +
           lint_run_owned(LINT_OWNER_REALROOT);
}

/* One group per HEAVY check: heavy_01 is import-copy-prove, heavy_02 is
 * fresh-boot-weld, and heavy_03 is the exact epoch contract; all hermetic. */
int test_make_lint_gates_heavy_01(void)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 1;
    printf("\n=== make_lint_gates heavy 1 tests ===\n");
    return lint_run_owned(LINT_OWNER_HEAVY_BASE + 0);
}

int test_make_lint_gates_heavy_02(void)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 1;
    printf("\n=== make_lint_gates heavy 2 tests ===\n");
    return lint_run_owned(LINT_OWNER_HEAVY_BASE + 1);
}

int test_make_lint_gates_heavy_03(void)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 1;
    printf("\n=== make_lint_gates heavy 3 tests ===\n");
    return lint_run_owned(LINT_OWNER_HEAVY_BASE + 2);
}

/* The exclusive lane: dispatch regressions, stale sandbox cleanup and root probe.
 * Keeps the group name `make_lint_gates` so `--only=make_lint_gates` (a
 * substring match) selects it plus every shard. */
static int t_lint_table_rebuild(void)
{
    static const char script[] =
        "set -eu; cd \"$2\"\n"
        "mkdir -p tools/lint/lintc build/lintc-obj\n"
        "for f in lintc.h gates.def precheck_base.h; do : > tools/lint/lintc/$f; done\n"
        "printf '#define LINT_ROW(n,c) c,\\nconst char *rows[] = {\\n#include \"gate_commands.def\"\\n};\\n' > tools/lint/lintc/run_table.c\n"
        "printf '#include <stdio.h>\\nextern const char *rows[]; int main(void) { return puts(rows[0]) < 0; }\\n' > main.c\n"
        "printf 'LINT_ROW(\"check-fixture\", \"old\")\\n' > tools/lint/lintc/gate_commands.def\n"
        "printf 'LINTC_OBJS := build/lintc-obj/run_table.o\\n' > Fixture.mk\n"
        "if grep -q '^# LINTC_DEPENDENCIES_BEGIN' \"$1/Makefile\"; then\n"
        "  awk '/^# LINTC_DEPENDENCIES_BEGIN/{on=1} on{print} /^# LINTC_DEPENDENCIES_END/{on=0} /^# LINTC_OBJECT_RULES_BEGIN/{on=1} /^# LINTC_OBJECT_RULES_END/{print; on=0}' \"$1/Makefile\" >> Fixture.mk\n"
        "else awk '/^build\\/lintc-obj\\/%.o:/{print; getline; print; getline; print; getline; print}' \"$1/Makefile\" >> Fixture.mk; fi\n"
        "awk '/^build\\/lintc-obj\\/run_table.o:.*gate_commands.def/{print}' \"$1/Makefile\" >> Fixture.mk\n"
        "printf '\\nCC=cc\\nHOST_CC=cc\\nLINTC_CFLAGS=\\nLINTC_CLANG=\\n' >> Fixture.mk\n"
        "make -s -f Fixture.mk build/lintc-obj/run_table.o >log 2>&1\n"
        "cc main.c build/lintc-obj/run_table.o -o probe; test \"$(./probe)\" = old\n"
        "touch -t 200001010000 tools/lint/lintc/*\n"
        "touch -t 200101010000 build/lintc-obj/run_table.o\n"
        "printf 'LINT_ROW(\"check-fixture\", \"new\")\\n' > tools/lint/lintc/gate_commands.def\n"
        "make -s -f Fixture.mk build/lintc-obj/run_table.o >>log 2>&1\n"
        "cc main.c build/lintc-obj/run_table.o -o probe; test \"$(./probe)\" = new\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "lint_table", "rebuild");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

static int t_engine_unit_identity_rebuild(void)
{
    static const char script[] =
        "set -eu; cd \"$2\"\n"
        "mkdir -p engine/composition engine/modules/engine/include/engine tools/dev\n"
        "for f in fixture.c source-identity.stamp engine/composition/prompt_templates.def engine/modules/engine/include/engine/prompt_sections.def; do : > \"$f\"; done\n"
        "cat > Fixture.mk <<'MAKE'\n"
        "BUILD_DIR := build\nBIN_DIR := build/bin\nBUILD_IDENTITY_STAMP := source-identity.stamp\n"
        "BUILD_IDENTITY_CPPFLAGS = -DZCL_BUILD_SOURCE_ID=\\\"$(BUILD_SOURCE_ID)\\\" -DZCL_BUILD_CLEAN=$(BUILD_CLEAN)\n"
        ".PHONY: FORCE\nFORCE:\nMAKE\n"
        "awk '/^ENGINE_UNIT_BIN =/{on=1; found=1} /^# .*z23-loop-tick:/{on=0} on{print} END{if(!found) exit 1}' \"$1/Makefile\" >> Fixture.mk\n"
        "cat > tools/dev/source-identity.sh <<'VERIFY'\n"
        "#!/bin/sh\nset -eu\ntest $# -eq 4; test \"$1\" = verify-record; test \"$2\" = \"$EXPECT_SOURCE\"; test \"$3\" = 1; test \"$4\" = \"$EXPECT_MUTATION\"\nVERIFY\n"
        "chmod +x tools/dev/source-identity.sh\n"
        "cat > compiler <<'COMPILER'\n"
        "set -eu\nsource=\nclean=\nout=\n"
        "while [ $# -gt 0 ]; do case $1 in -DZCL_BUILD_SOURCE_ID=*) source=$1;; -DZCL_BUILD_CLEAN=*) clean=$1;; -o) shift; out=$1;; esac; shift; done\n"
        "test -n \"$source\"; test -n \"$clean\"; test -n \"$out\"\n"
        "printf '%s\\n' \"$source\" \"$clean\" > \"$out\"\n"
        "printf 'compile\\n' >> calls\nCOMPILER\n"
        "a=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
        "b=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
        "EXPECT_MUTATION=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc; export EXPECT_MUTATION\n"
        "build() { EXPECT_SOURCE=$1; export EXPECT_SOURCE; make -s -f Fixture.mk engine-unit 'ENGINE_UNIT_SRCS=fixture.c' 'ENGINE_UNIT_INCLUDES=' 'NODE_VENDOR_LIBS=' 'SPAWN_BINARY_HEADERS=' 'CC=sh ./compiler' \"BUILD_SOURCE_ID=$1\" \"BUILD_CLEAN=$2\" \"BUILD_MUTATION=$EXPECT_MUTATION\" >> log 2>&1; }\n"
        "check() {\n"
        "  build \"$1\" \"$2\" || { cat log >&2; return 1; }\n"
        "  test \"$(wc -l < calls)\" -eq \"$3\" || { echo \"engine identity compile count: expected $3\" >&2; cat log >&2; return 1; }\n"
        "  printf '%s\\n' \"-DZCL_BUILD_SOURCE_ID=\\\"$1\\\"\" \"-DZCL_BUILD_CLEAN=$2\" > expected\n"
        "  cmp expected build/bin/z23-engine-unit\n"
        "}\n"
        "check \"$a\" 1 1; check \"$a\" 1 1\n"
        "check \"$b\" 1 2; check \"$b\" 1 2\n"
        "check \"$a\" 1 3; check \"$a\" 1 3\n"
        "if build \"$a\" 0; then echo 'engine identity accepted incomplete source record' >&2; exit 1; fi\n"
        "test \"$(wc -l < calls)\" -eq 3; check \"$a\" 1 3\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "engine_identity", "rebuild");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (bad) fprintf(stderr, "engine identity fixture retained: %s\n", fixture);
    else if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

static int t_secure_release_host_support_rebuild(void)
{
    static const char script[] =
        "set -eu; cd \"$2\"\n"
        "mkdir -p tools/dev platform/modules/platform/src build/bin\n"
        "for f in tools/dev/secure_release_regressions.c tools/dev/secure_release_regressions_main.c tools/dev/secure_release_regressions.h tools/dev/dev_script_dir.c tools/dev/dev_script_dir.h platform/modules/platform/src/os_proc.c; do : > \"$f\"; touch -t 200101010000 \"$f\"; done\n"
        ": > build/bin/secure-release-regressions-selftest; touch -t 200201010000 build/bin/secure-release-regressions-selftest\n"
        "printf 'BIN_DIR := build/bin\\nHOST_CC := cc\\n' > Fixture.mk\n"
        "awk '/^\\$\\(BIN_DIR\\)\\/secure-release-regressions-selftest:/{on=1; found=1} on && /^$/{exit} on{print} END{if(!found) exit 1}' \"$1/Makefile\" >> Fixture.mk\n"
        "make -s -n -f Fixture.mk -W tools/dev/secure_release_regressions.c build/bin/secure-release-regressions-selftest > control.log 2>&1\n"
        "grep -F 'platform/modules/platform/src/os_proc.c' control.log >/dev/null || { echo 'secure release control missing compile' >&2; exit 1; }\n"
        "make -s -n -f Fixture.mk -W platform/modules/platform/src/os_proc.c build/bin/secure-release-regressions-selftest > changed.log 2>&1\n"
        "grep -F 'platform/modules/platform/src/os_proc.c' changed.log >/dev/null || { echo 'secure release os_proc change did not rebuild wrapper' >&2; exit 1; }\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "secure_release", "host_support");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (bad) fprintf(stderr, "secure release host support fixture retained: %s\n", fixture);
    else if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

static int t_registry_query_scope(void)
{
    static const char setup[] =
        "set -eu; root=$1; work=$2; cd \"$root\"\n"
        "mkdir -p \"$work/tmp\"; TMPDIR=$work/tmp; export TMPDIR\n"
        "fail() { echo \"registry-query: $1\" >&2; exit 1; }\n"
        "printf '%s\\n' '$(info EPOCH=[$(ZCL_EPOCH_PROFILES)])' '$(info DEP=[$(ZCL_DEPFILE_PROFILES)])' '.PHONY: fixture-expected fixture-unknown' 'fixture-expected:' '\t@printf \"%s\\n\" $(LIB_SRCS)' 'fixture-unknown:' '\t@:' > \"$work/probe.mk\"\n"
        "printf '%s\\n' '$(error VENDOR_SENTINEL)' > \"$work/vendor.mk\"\n"
        "make_probe() { make --no-print-directory -s -f \"$root/Makefile\" -f \"$work/probe.mk\" -o /dev/null -o z23 -o contexts/explorer/views/include/views/site_css.h \"BUILD_DIR=$work/build\" \"BIN_DIR=$work/build/bin\" VIEW_BOOTSTRAP_MK=/dev/null VIEW_GEN_HEADERS= VIEW_GEN_HEADERS_EARLY= 'BUILD_SOURCE_RECORD=0000000000000000000000000000000000000000000000000000000000000000 1 0000000000000000000000000000000000000000000000000000000000000000' BUILD_COMPILER_ID=0000000000000000000000000000000000000000000000000000000000000000 BUILD_SYSTEM_ID=0000000000000000000000000000000000000000000000000000000000000000 zcl_compile_epoch=0000000000000000000000000000000000000000000000000000000000000000 \"$@\"; }\n";
    static const char checks[] =
        "make_probe VENDOR_LIBS= ZCL_TOR=stub print-zcode-monolith-lib-sources > \"$work/query\" 2>\"$work/query.err\" || fail query\n"
        "grep -Fx 'EPOCH=[]' \"$work/query\" >/dev/null || fail query-epoch\n"
        "grep -Fx 'DEP=[]' \"$work/query\" >/dev/null || fail query-dep\n"
        "grep -v -e '^EPOCH=' -e '^DEP=' \"$work/query\" > \"$work/sources\"; test -s \"$work/sources\" || fail source-empty\n"
        "make_probe VENDOR_LIBS= ZCL_TOR=stub fixture-expected > \"$work/expected\" 2>\"$work/expected.err\" || fail expected\n"
        "grep -v -e '^EPOCH=' -e '^DEP=' \"$work/expected\" > \"$work/expected-sources\"; cmp \"$work/sources\" \"$work/expected-sources\" || fail source-list\n"
        "make_probe -n VENDOR_LIBS= ZCL_TOR=stub contexts/explorer/views/include/views/site_css.h print-zcode-monolith-lib-sources > \"$work/header\" 2>&1 || fail header\n"
        "grep -Fx 'EPOCH=[]' \"$work/header\" >/dev/null && grep -Fx 'DEP=[]' \"$work/header\" >/dev/null || fail header-profile\n"
        "for goal in z23 fixture-unknown; do make_probe -n VENDOR_LIBS= ZCL_TOR=stub print-zcode-monolith-lib-sources \"$goal\" > \"$work/mixed\" 2>&1 || fail mixed; grep -Fx 'EPOCH=[build-only dev dev-asan dev-tsan test-fast test-strict test-asan test-tsan coverage node-c23]' \"$work/mixed\" >/dev/null || fail mixed-epoch; grep -Fx 'DEP=[build-only dev test-fast test-strict coverage fuzz node-c23]' \"$work/mixed\" >/dev/null || fail mixed-dep; done\n"
        "make_probe -n VENDOR_LIBS= ZCL_TOR=stub > \"$work/default\" 2>&1 || fail default; grep -Fx 'EPOCH=[node-c23]' \"$work/default\" >/dev/null && grep -Fx 'DEP=[node-c23]' \"$work/default\" >/dev/null || fail default-profile\n";
    static const char query_profiles[] =
        "for goal in help print-CFLAGS; do make_probe -n VENDOR_LIBS= ZCL_TOR=stub \"$goal\" > \"$work/pure-$goal\" 2>&1 || fail \"$goal-run\"; grep -Fx 'EPOCH=[]' \"$work/pure-$goal\" >/dev/null && grep -Fx 'DEP=[]' \"$work/pure-$goal\" >/dev/null || fail \"$goal-profile\"; done\n"
        "for goals in 'contexts/explorer/views/include/views/site_css.h print-node-c23-srcs' 'print-game-closure contexts/explorer/views/include/views/site_css.h'; do make_probe -n VENDOR_LIBS= ZCL_TOR=stub $goals > \"$work/pure-header\" 2>&1 || fail pure-header; grep -Fx 'EPOCH=[]' \"$work/pure-header\" >/dev/null && grep -Fx 'DEP=[]' \"$work/pure-header\" >/dev/null || fail pure-header-profile; done\n";
    static const char x11_profiles[] =
        "for goal in zcl-x11-baseline zcl-x11-cover; do make_probe -n -o \"$goal\" VENDOR_LIBS= ZCL_TOR=stub \"$goal\" > \"$work/x11\" 2>&1 || fail x11-run; grep -Fx 'EPOCH=[]' \"$work/x11\" >/dev/null && grep -Fx 'DEP=[]' \"$work/x11\" >/dev/null || fail x11-profile; done\n"
        "for goals in 'zcl-x11-baseline z23' 'zcl-x11-cover fixture-unknown' 'zcl-x11-baseline contexts/explorer/views/include/views/site_css.h' 'zcl-x11-cover zcl-x11-cover' 'zcl-x11-baseline zcl-x11-cover'; do make_probe -n -o zcl-x11-baseline -o zcl-x11-cover VENDOR_LIBS= ZCL_TOR=stub ZCL_X11_PROBE_ONLY=1 $goals > \"$work/x11-mixed\" 2>&1 || fail x11-mixed-run; grep -Fx 'EPOCH=[build-only dev dev-asan dev-tsan test-fast test-strict test-asan test-tsan coverage node-c23]' \"$work/x11-mixed\" >/dev/null && grep -Fx 'DEP=[build-only dev test-fast test-strict coverage fuzz node-c23]' \"$work/x11-mixed\" >/dev/null || fail x11-mixed-profile; done\n"
        "if make_probe -n -o zcl-x11-cover VENDOR_LIBS= ZCL_TOR=stub CC=/bin/false zcl-x11-cover > \"$work/x11-compiler\" 2>&1; then fail x11-compiler-accepted; fi; grep -F 'C23 toolchain check failed' \"$work/x11-compiler\" >/dev/null || fail x11-compiler-reason\n";
    static const char bootstrap[] =
        "make_probe -n VENDOR_LIBS=/missing/z23-vendor \"VENDOR_BOOTSTRAP_MK=$work/vendor.mk\" ZCL_TOR=stub print-zcode-monolith-lib-sources >\"$work/vendor-query\" 2>&1 || fail vendor-query\n"
        "for goal in z23 fixture-unknown; do if make_probe -n VENDOR_LIBS=/missing/z23-vendor \"VENDOR_BOOTSTRAP_MK=$work/vendor.mk\" ZCL_TOR=stub print-zcode-monolith-lib-sources \"$goal\" >\"$work/vendor-mixed\" 2>&1; then fail vendor-mixed-accepted; fi; grep -F VENDOR_SENTINEL \"$work/vendor-mixed\" >/dev/null || fail vendor-mixed-reason; done\n"
        "make_probe -n VENDOR_LIBS= ZCL_TOR=full 'ZCL_TOR_READY_PROBE=$(error TOR_SENTINEL)' print-zcode-monolith-lib-sources >\"$work/tor-query\" 2>&1 || fail tor-query\n"
        "for goal in z23 fixture-unknown; do if make_probe -n VENDOR_LIBS= ZCL_TOR=full 'ZCL_TOR_READY_PROBE=$(error TOR_SENTINEL)' print-zcode-monolith-lib-sources \"$goal\" >\"$work/tor-mixed\" 2>&1; then fail tor-mixed-accepted; fi; grep -F TOR_SENTINEL \"$work/tor-mixed\" >/dev/null || fail tor-mixed-reason; done\n";
    char script[sizeof(setup) + sizeof(checks) + sizeof(query_profiles) + sizeof(x11_profiles) + sizeof(bootstrap) - 4];
    memcpy(script, setup, sizeof(setup) - 1);
    memcpy(script + sizeof(setup) - 1, checks, sizeof(checks) - 1);
    memcpy(script + sizeof(setup) + sizeof(checks) - 2, query_profiles, sizeof(query_profiles) - 1);
    memcpy(script + sizeof(setup) + sizeof(checks) + sizeof(query_profiles) - 3, x11_profiles, sizeof(x11_profiles) - 1);
    memcpy(script + sizeof(setup) + sizeof(checks) + sizeof(query_profiles) + sizeof(x11_profiles) - 4, bootstrap, sizeof(bootstrap));
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "registry_query", "scope");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (bad) fprintf(stderr, "registry query fixture retained: %s\n", fixture);
    else if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

static int t_lint_private_header_rebuild(void)
{
    static const char setup[] =
        "set -eu; cd \"$2\"\n"
        "fail() { echo \"private-header: $1\" >&2; exit 1; }\n"
        "mkdir -p tools/lint/lintc build/lintc-obj platform\n"
        "for f in lintc.h gates.def precheck_base.h; do : > tools/lint/lintc/$f; done\n"
        "printf '#include \"gates.def\"\\n' > tools/lint/lintc/lintc.h; printf '#define GATE_VALUE 0\\n' > tools/lint/lintc/gates.def\n"
        "printf '#ifdef LINT_FIXTURE_CHECKER\n#include \"checker_only.h\"\n#endif\n#include \"direct.h\"\nint value(void) { return VALUE + EXTRA + GATE_VALUE; }\n' > tools/lint/lintc/one.c\n"
        "printf '/* valid */\\n' > tools/lint/lintc/checker_only.h\n"
        "printf '#include <stdio.h>\\nint value(void); int main(void) { return printf(\"%%d\\\\n\", value()) < 0; }\\n' > tools/lint/lintc/two.c\n"
        "printf '#include \"precheck_base.h\"\\n#define EXTRA 1\\n' > tools/lint/lintc/direct.h\n"
        "printf '#include \"lintc.h\"\\n#define VALUE 1\\n' > tools/lint/lintc/precheck_base.h\n"
        "printf '#!/bin/sh\\necho \"$*\" >> cc.log\\n[ ! -f cc.fail ] || exit 1\\nif [ -f cc.empty ]; then exit 0; fi\\nif [ -f cc.emptyobj ] || [ -f cc.emptydep ]; then\\n  prev=; for arg do case \"$prev\" in -o) obj=$arg;; -MF) dep=$arg;; esac; prev=$arg; done\\n  cc \"$@\" || exit; if [ -f cc.emptyobj ]; then : > \"$obj\"; else : > \"$dep\"; fi; exit 0\\nfi\\nexec cc \"$@\"\\n' > cc-trace; chmod +x cc-trace\n"
        "printf '#!/bin/sh\\n[ ! -f clang.fail ] || exit 1\\nif [ -f clang.empty ]; then prev=; for arg do [ \"$prev\" != -MF ] || : > \"$arg\"; prev=$arg; done; exit 0; fi\\nexec cc -DLINT_FIXTURE_CHECKER \"$@\"\\n' > clang-check; chmod +x clang-check\n"
        "printf 'LINTC_OBJS := build/lintc-obj/one.o build/lintc-obj/two.o\\nLINTC_NODE_OBJS := build/lintc-obj/node/platform/node.o\\n' > Fixture.mk\n"
        "if grep -q '^# LINTC_DEPENDENCIES_BEGIN' \"$1/Makefile\"; then\n"
        "  awk '/^# LINTC_DEPENDENCIES_BEGIN/{on=1} on{print} /^# LINTC_DEPENDENCIES_END/{on=0} /^# LINTC_OBJECT_RULES_BEGIN/{on=1} /^# LINTC_OBJECT_RULES_END/{print; on=0}' \"$1/Makefile\" >> Fixture.mk\n"
        "else awk '/^build\\/lintc-obj\\/%.o:/{print; getline; print; getline; print; getline; print}' \"$1/Makefile\" >> Fixture.mk; fi\n"
        "printf '\\nCC=./cc-trace\\nHOST_CC=./cc-trace\\nLINTC_CFLAGS=-Itools/lint/lintc\\nLINTC_CLANG=./clang-check\\n' >> Fixture.mk\n"
        "touch -t 200001010000 tools/lint/lintc/*\n";
    static const char checks[] =
        "make -s -f Fixture.mk build/lintc-obj/one.o build/lintc-obj/two.o >log 2>&1 || fail initial\n"
        "cc build/lintc-obj/one.o build/lintc-obj/two.o -o probe; test \"$(./probe)\" = 2 || fail initial-output\n"
        "touch -t 200101010000 build/lintc-obj/one.o build/lintc-obj/two.o\n"
        "printf '#include \"precheck_base.h\"\\n#define EXTRA 2\\n' > tools/lint/lintc/direct.h; touch -t 200201010000 tools/lint/lintc/direct.h\n"
        ": > cc.log; make -s -f Fixture.mk build/lintc-obj/one.o build/lintc-obj/two.o >>log 2>&1 || fail direct-make\n"
        "cc build/lintc-obj/one.o build/lintc-obj/two.o -o probe; test \"$(./probe)\" = 3 || fail direct-output\n"
        "grep -q 'one.c' cc.log && ! grep -q 'two.c' cc.log || fail direct-scope\n"
        "touch -t 200301010000 build/lintc-obj/one.o; printf '#include \"lintc.h\"\\n#define VALUE 5\\n' > tools/lint/lintc/precheck_base.h; touch -t 200401010000 tools/lint/lintc/precheck_base.h\n"
        ": > cc.log; make -s -f Fixture.mk build/lintc-obj/one.o build/lintc-obj/two.o >>log 2>&1 || fail transitive-make\n"
        "cc build/lintc-obj/one.o build/lintc-obj/two.o -o probe; test \"$(./probe)\" = 7 || fail transitive-output\n"
        "grep -q 'one.c' cc.log && ! grep -q 'two.c' cc.log || fail transitive-scope\n"
        "rm -f build/lintc-obj/one.d; : > cc.log; make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1 || fail legacy-make\n"
        "test -s build/lintc-obj/one.d && grep -q 'one.c' cc.log || fail legacy-bootstrap\n"
        ": > cc.log; make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1 || fail warm-make; test ! -s cc.log || fail warm-recompile\n"
        "rm -f build/lintc-obj/one.d; : > cc.log; make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1 || fail deleted-make\n"
        "test -s build/lintc-obj/one.d && grep -q 'one.c' cc.log || fail deleted-dep\n"
        "cp build/lintc-obj/one.o saved.o; touch -t 200401010000 build/lintc-obj/one.o; touch -t 200501010000 tools/lint/lintc/direct.h\n"
        ": > cc.fail; if make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1; then fail cc-accepted; fi; rm cc.fail\n"
        "cmp -s saved.o build/lintc-obj/one.o && test ! -e build/lintc-obj/one.d || fail cc-publication\n"
        "make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1 || fail cc-recovery\n"
        "cp build/lintc-obj/one.o saved.o; touch -t 200501010000 build/lintc-obj/one.o; touch -t 200601010000 tools/lint/lintc/direct.h\n"
        ": > clang.fail; if make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1; then fail clang-accepted; fi; rm clang.fail\n"
        "cmp -s saved.o build/lintc-obj/one.o && test ! -e build/lintc-obj/one.d || fail clang-publication\n"
        ": > cc.empty; if make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1; then fail empty-accepted; fi; rm cc.empty\n"
        "cmp -s saved.o build/lintc-obj/one.o && test ! -e build/lintc-obj/one.d || fail empty-publication\n"
        ": > cc.emptyobj; if make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1; then fail empty-object-accepted; fi; rm cc.emptyobj\n"
        "cmp -s saved.o build/lintc-obj/one.o && test ! -e build/lintc-obj/one.d || fail empty-object-publication\n"
        ": > cc.emptydep; if make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1; then fail empty-dep-accepted; fi; rm cc.emptydep\n"
        "cmp -s saved.o build/lintc-obj/one.o && test ! -e build/lintc-obj/one.d || fail empty-dep-publication\n";
    static const char recovery[] =
        "make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1 || fail deleted-header-setup\n"
        "test -s build/lintc-obj/one.d || fail deleted-header-no-dep\n"
        "cp build/lintc-obj/one.o saved.o; rm tools/lint/lintc/precheck_base.h; : > cc.log\n"
        "if make -s -f Fixture.mk build/lintc-obj/one.o >deleted-header.log 2>&1; then fail deleted-header-accepted; fi\n"
        "grep -q 'one.c' cc.log && grep -q 'precheck_base.h' deleted-header.log || fail deleted-header-diagnostic\n"
        "cmp -s saved.o build/lintc-obj/one.o && test ! -e build/lintc-obj/one.d || fail deleted-header-publication\n"
        "printf '#include \"lintc.h\"\\n#define VALUE 5\\n' > tools/lint/lintc/precheck_base.h; touch -t 200401010000 tools/lint/lintc/precheck_base.h\n"
        "make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1 || fail deleted-header-recovery\n"
        "cc build/lintc-obj/one.o build/lintc-obj/two.o -o probe; test \"$(./probe)\" = 7 || fail deleted-header-output\n"
        "printf '#include \"direct.h\"\\nint node_value(void) { return VALUE + EXTRA; }\\n' > platform/node.c\n"
        "touch -t 200001010000 platform/node.c\n"
        "printf '#include <stdio.h>\\nint node_value(void); int main(void) { return printf(\"%%d\\\\n\", node_value()) < 0; }\\n' > node_main.c\n"
        "make -s -f Fixture.mk build/lintc-obj/node/platform/node.o >>log 2>&1 || fail node-initial\n"
        "cc node_main.c build/lintc-obj/node/platform/node.o -o node-probe; test \"$(./node-probe)\" = 7 || fail node-initial-output\n"
        "touch -t 200701010000 build/lintc-obj/node/platform/node.o; printf '#include \"precheck_base.h\"\\n#define EXTRA 9\\n' > tools/lint/lintc/direct.h; touch -t 200801010000 tools/lint/lintc/direct.h\n"
        ": > cc.log; make -s -f Fixture.mk build/lintc-obj/node/platform/node.o build/lintc-obj/two.o >>log 2>&1 || fail node-change\n"
        "cc node_main.c build/lintc-obj/node/platform/node.o -o node-probe; test \"$(./node-probe)\" = 14 || fail node-output\n"
        "grep -q 'platform/node.c' cc.log && ! grep -q 'two.c' cc.log || fail node-scope\n"
        "rm -f build/lintc-obj/node/platform/node.d; : > cc.log; make -s -f Fixture.mk build/lintc-obj/node/platform/node.o >>log 2>&1 || fail node-legacy\n"
        "test -s build/lintc-obj/node/platform/node.d && grep -q 'platform/node.c' cc.log || fail node-legacy-dep\n"
        ": > cc.log; make -s -f Fixture.mk build/lintc-obj/node/platform/node.o >>log 2>&1 || fail node-warm; test ! -s cc.log || fail node-warm-recompile\n";
    static const char checker[] =
        "cp build/lintc-obj/one.o saved.o; touch -t 200901010000 build/lintc-obj/one.o\n"
        "printf 'invalid syntax here\\n' > tools/lint/lintc/checker_only.h; touch -t 201001010000 tools/lint/lintc/checker_only.h\n"
        "if make -s -f Fixture.mk build/lintc-obj/one.o >checker-invalid.log 2>&1; then fail checker-invalid-accepted; fi\n"
        "cmp -s saved.o build/lintc-obj/one.o && test ! -e build/lintc-obj/one.d && test ! -e build/lintc-obj/one.o.cmd || fail checker-invalid-publication\n"
        "printf '/* valid */\\n' > tools/lint/lintc/checker_only.h; make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1 || fail checker-retry\n"
        "grep -q checker_only.h build/lintc-obj/one.d || fail checker-dep\n"
        ": > cc.log; make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1 || fail checker-warm; test ! -s cc.log || fail checker-warm-recompile\n"
        "cp build/lintc-obj/one.o saved.o; : > clang.empty; touch -t 200901010000 build/lintc-obj/one.o; touch -t 201101010000 tools/lint/lintc/direct.h\n"
        "if make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1; then fail checker-empty-accepted; fi; rm clang.empty\n"
        "cmp -s saved.o build/lintc-obj/one.o && test ! -e build/lintc-obj/one.d && test ! -e build/lintc-obj/one.o.cmd || fail checker-empty-publication\n"
        "make -s -f Fixture.mk build/lintc-obj/one.o >>log 2>&1 || fail checker-empty-retry\n"
        "rm tools/lint/lintc/checker_only.h; make -s -f Fixture.mk LINTC_CLANG= build/lintc-obj/one.o >>log 2>&1 || fail checker-disable\n"
        ": > cc.log; make -s -f Fixture.mk LINTC_CLANG= build/lintc-obj/one.o >>log 2>&1 || fail checker-disable-warm; test ! -s cc.log || fail checker-disable-recompile\n";
    static const char shared[] =
        "make -s -f Fixture.mk LINTC_CLANG= build/lintc-obj/one.o build/lintc-obj/two.o >>log 2>&1 || fail shared-setup\n"
        "touch -t 201201010000 tools/lint/lintc/lintc.h tools/lint/lintc/gates.def; touch -t 202001010000 build/lintc-obj/one.o build/lintc-obj/two.o\n"
        "printf '#define GATE_VALUE 1\\n' > tools/lint/lintc/gates.def; touch -t 202101010000 tools/lint/lintc/gates.def\n"
        ": > cc.log; make -s -f Fixture.mk LINTC_CLANG= build/lintc-obj/one.o build/lintc-obj/two.o >>log 2>&1 || fail gates-make\n"
        "grep -q 'one.c' cc.log && ! grep -q 'two.c' cc.log || fail gates-scope\n"
        "cc build/lintc-obj/one.o build/lintc-obj/two.o -o probe; test \"$(./probe)\" = 15 || fail gates-output\n"
        "touch -t 202201010000 build/lintc-obj/one.o build/lintc-obj/two.o; touch -t 202301010000 tools/lint/lintc/lintc.h\n"
        ": > cc.log; make -s -f Fixture.mk LINTC_CLANG= build/lintc-obj/one.o build/lintc-obj/two.o >>log 2>&1 || fail lintc-make\n"
        "grep -q 'one.c' cc.log && ! grep -q 'two.c' cc.log || fail lintc-scope\n"
        "cc build/lintc-obj/one.o build/lintc-obj/two.o -o probe; test \"$(./probe)\" = 15 || fail lintc-output\n";
    /* Keep each literal below the strict compiler's 4095-byte limit. */
    char script[sizeof(setup) + sizeof(checks) + sizeof(recovery) + sizeof(checker) + sizeof(shared) - 4];
    memcpy(script, setup, sizeof(setup) - 1);
    memcpy(script + sizeof(setup) - 1, checks, sizeof(checks) - 1);
    memcpy(script + sizeof(setup) + sizeof(checks) - 2,
           recovery, sizeof(recovery) - 1);
    memcpy(script + sizeof(setup) + sizeof(checks) + sizeof(recovery) - 3, checker, sizeof(checker) - 1);
    memcpy(script + sizeof(setup) + sizeof(checks) + sizeof(recovery) + sizeof(checker) - 4, shared, sizeof(shared));
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "lint_header", "rebuild");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

static int t_lint_inventory_dispatch(void)
{
    static const char script[] =
        "set -eu; cd \"$2\"\n"
        "mkdir -p tools/lint bin fake build/gen build/bin\n"
        "printf '#!/bin/sh\necho generator >> calls\nexit ${GEN_RC:-0}\n' > bin/gen_capability_inventory.exe\n"
        "printf '#!/bin/sh\necho make >> calls\nexit 0\n' > fake/make\n"
        "printf '#!/bin/sh\necho worker >> calls\n' > bin/z23-lint\n"
        "chmod +x bin/gen_capability_inventory.exe bin/z23-lint fake/make; cp bin/z23-lint build/bin/z23-lint\n"
        "export PATH=\"$2/fake:$PATH\" ZCL_HOST_EXEEXT=.exe\n"
        "\"$1/build/bin/z23-lint\" run --jobs 1 --bin-dir bin check-capability-inventory-generated >log 2>&1\n"
        "printf 'make\nworker\n' > expected; cmp expected calls\n"
        ": > calls\n"
        "ZCL_LINT_INVENTORY_TOOL=bin/gen_capability_inventory.exe \"$1/build/bin/z23-lint\" run --jobs 1 --bin-dir bin check-capability-inventory-generated >log 2>&1\n"
        "printf 'generator\nworker\n' > expected; cmp expected calls\n"
        ": > calls; GEN_RC=9; export GEN_RC\n"
        "if ZCL_LINT_INVENTORY_TOOL=bin/gen_capability_inventory.exe \"$1/build/bin/z23-lint\" run --jobs 1 --bin-dir bin check-capability-inventory-generated >log 2>&1; then exit 1; fi\n"
        "printf 'generator\n' > expected; cmp expected calls\n"
        "rm bin/gen_capability_inventory.exe; : > calls; GEN_RC=0\n"
        "\"$1/build/bin/z23-lint\" run --jobs 1 --bin-dir bin check-capability-inventory-generated >log 2>&1\n"
        "printf 'make\nworker\n' > expected; cmp expected calls\n"
        "printf '#!/bin/sh\ntouch driver-ran\n' > stub-lint\n"
        "chmod +x stub-lint\n"
        "awk '/^lint-fast: .*EQUIHASH_FACT_TOOL/{f=1; next} /^lint-land: .*EQUIHASH_FACT_TOOL/{f=2; next} /^lint: .*LINTC_TOOL.*NETWORK_TOOL_HARDENING_BINS/{f=3; next} f && /^\\t@.*LINTC_TOOL\\) run --jobs/{print (f==1 ? \"fast:\" : f==2 ? \"land:\" : \"full:\"); print; f=0}' \"$1/Makefile\" > Fixture.mk\n"
        "printf '.PHONY: fast land full\nLINT_PARALLEL_GATES=x\nLINTC_TOOL=./stub-lint\n' >> Fixture.mk\n"
        "for target in fast land full; do for mode in n t q; do /usr/bin/make -f Fixture.mk -$mode $target >/dev/null 2>&1 || [ $mode = q ]; test ! -e driver-ran; done; done\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "lint_inventory", "dispatch");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

static const char lint_command_part_0[] =
    "set -eu\n"
    "umask 022\n"
    "cd \"$2\"\n"
    "fail() { echo \"command-fixture: $1\" >&2; exit 1; }\n"
    "mkdir -p tools/lint/lintc platform build/bin\n"
    "for f in lintc.h gates.def precheck_base.h; do : > \"tools/lint/lintc/$f\"; done\n"
    "printf '#define EXTRA 0\\n' > tools/lint/lintc/private.h\n"
    "printf '#include \"private.h\"\\nint value(void) { return VALUE + EXTRA; }\\n' > tools/lint/lintc/one.c\n"
    "printf '#include <stdio.h>\\nint value(void); int node_value(void); int main(void) { return printf(\"%%d %%d\\\\n\", value(), node_value()) < 0; }\\n' > tools/lint/lintc/two.c\n"
    "printf '#ifndef NODE_VALUE\n"
    "#define NODE_VALUE 17\n"
    "#endif\n"
    "int node_value(void) { return NODE_VALUE; }\\n' > platform/node.c\n"
    "cat > cc-one <<'WRAPPER'\n"
    "#!/bin/sh\n"
    "printf 'one %s\\n' \"$*\" >> compiler.trace\n"
    "[ ! -f fail-cc ] || exit 1\n"
    "link=1\n"
    "prev=\n"
    "for arg do\n"
;
static const char lint_command_part_1[] =
    "    [ \"$arg\" != -c ] || link=0\n"
    "    [ \"$prev\" != -o ] || output=$arg\n"
    "    prev=$arg\n"
    "done\n"
    "if [ \"$link\" = 1 ] && [ -f fail-link ]; then exit 1; fi\n"
    "if [ \"$link\" = 1 ] && [ -f empty-link ]; then : > \"$output\"; exit 0; fi\n"
    "exec cc \"$@\"\n"
    "WRAPPER\n"
    "cat > cc-two <<'WRAPPER'\n"
    "#!/bin/sh\n"
    "printf 'two %s\\n' \"$*\" >> compiler.trace\n"
    "exec cc \"$@\"\n"
    "WRAPPER\n"
    "cat > clang-one <<'WRAPPER'\n"
    "#!/bin/sh\n"
    "printf 'clang-one %s\\n' \"$*\" >> clang.trace\n"
    "exec cc -DLINT_FIXTURE_CHECKER \"$@\"\n"
    "WRAPPER\n"
    "cat > clang-two <<'WRAPPER'\n"
    "#!/bin/sh\n"
;
static const char lint_command_part_2[] =
    "printf 'clang-two %s\\n' \"$*\" >> clang.trace\n"
    "[ ! -f fail-clang ] || exit 1\n"
    "exec cc -DLINT_FIXTURE_CHECKER \"$@\"\n"
    "WRAPPER\n"
    "chmod +x cc-one cc-two clang-one clang-two\n"
    "cat > Fixture.mk <<'MAKE'\n"
    "HOST_CC = ./cc-one\n"
    "LINTC_CFLAGS = -std=c2x $(GLOBAL)\n"
    "LINTC_CLANG =\n"
    "LINTC_TOOL = build/bin/lint-fixture\n"
    "LINTC_OBJS = build/lintc-obj/one.o build/lintc-obj/two.o\n"
    "LINTC_NODE_OBJS = build/lintc-obj/node/platform/node.o\n"
    "AFLAG ?= -DVALUE=1\n"
    "build/lintc-obj/one.o: LINTC_CFLAGS += $(AFLAG)\n"
    "build/lintc-obj/node/platform/node.o: LINTC_CFLAGS += $(NFLAG)\n"
    "MAKE\n"
    "awk '/^# LINTC_DEPENDENCIES_BEGIN/{on=1} on{print} /^# LINTC_DEPENDENCIES_END/{on=0} /^# LINTC_OBJECT_RULES_BEGIN/{on=1} /^# LINTC_OBJECT_RULES_END/{print; on=0} /^# LINTC_LINK_RULES_BEGIN/{link=1; on=1} /^# LINTC_LINK_RULES_END/{print; on=0} END{if(!link) exit 1}' \"$1/Makefile\" >> Fixture.mk || {\n"
    "  awk '/^\\$\\(LINTC_TOOL\\):/{print; getline; print; getline; print}' \"$1/Makefile\" >> Fixture.mk\n"
    "}\n"
    "touch -t 200001010000 tools/lint/lintc/* platform/node.c\n"
    "make -j2 -s -f Fixture.mk build/bin/lint-fixture > make.log 2>&1 || fail initial\n"
;
static const char lint_command_part_3[] =
    "[ \"$(build/bin/lint-fixture)\" = '1 17' ] || fail initial-output\n"
    "cc -std=c2x -DVALUE=1 -c tools/lint/lintc/one.c -o direct-022.o\n"
    "cc build/lintc-obj/one.o build/lintc-obj/two.o build/lintc-obj/node/platform/node.o -o direct-022\n"
    "[ \"$(ls -ld direct-022.o | awk '{print $1}')\" = \"$(ls -ld build/lintc-obj/one.o | awk '{print $1}')\" ] || fail object-mode-022\n"
    "[ \"$(ls -ld direct-022 | awk '{print $1}')\" = \"$(ls -ld build/bin/lint-fixture | awk '{print $1}')\" ] || fail binary-mode-022\n"
    "touch -t 200101010000 build/lintc-obj/one.o build/lintc-obj/two.o build/lintc-obj/node/platform/node.o build/lintc-obj/one.d build/lintc-obj/two.d build/lintc-obj/node/platform/node.d\n"
    "for f in build/lintc-obj/one.o.cmd build/lintc-obj/two.o.cmd build/lintc-obj/node/platform/node.o.cmd; do [ ! -e \"$f\" ] || touch -t 200101010000 \"$f\"; done\n"
    "touch -t 200201010000 build/bin/lint-fixture\n"
    "[ ! -e build/bin/lint-fixture.cmd ] || touch -t 200201010000 build/bin/lint-fixture.cmd\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk build/bin/lint-fixture >>make.log 2>&1 || fail warm\n"
    "[ ! -s compiler.trace ] || fail warm-compiler\n"
    "make -q -f Fixture.mk build/bin/lint-fixture || fail warm-question\n"
    "make -n -f Fixture.mk build/bin/lint-fixture >dryrun.log 2>&1 || fail warm-dryrun\n"
    "[ \"$(cat dryrun.log)\" = \"make: 'build/bin/lint-fixture' is up to date.\" ] || fail warm-dryrun-commands\n"
    "[ ! -s compiler.trace ] || fail dryrun-executed\n"
    "# Old unversioned newline-terminated records require one complete migration.\n"
    "for record in build/lintc-obj/one.o.cmd build/lintc-obj/two.o.cmd build/lintc-obj/node/platform/node.o.cmd build/bin/lint-fixture.cmd; do\n"
    "  grep -q '^lintc-command-v1:' \"$record\" || fail record-prefix\n"
    "  [ \"$(wc -l < \"$record\")\" -eq 0 ] || fail record-newline\n"
;
static const char lint_command_part_4[] =
    "  printf '%s\\n' \"$(sed 's/^lintc-command-v1://' \"$record\")\" > \"$record.old\"\n"
    "  [ \"$(wc -l < \"$record.old\")\" -eq 1 ] || fail legacy-newline\n"
    "  mv \"$record.old\" \"$record\"\n"
    "done\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk build/bin/lint-fixture >>make.log 2>&1 || fail legacy-migration\n"
    "[ \"$(grep -c ' -c ' compiler.trace)\" = 3 ] || fail legacy-compile-count\n"
    "[ \"$(wc -l < compiler.trace)\" = 4 ] || fail legacy-link-count\n"
    "[ \"$(build/bin/lint-fixture)\" = '1 17' ] || fail legacy-output\n"
    "for record in build/lintc-obj/one.o.cmd build/lintc-obj/two.o.cmd build/lintc-obj/node/platform/node.o.cmd build/bin/lint-fixture.cmd; do\n"
    "  grep -q '^lintc-command-v1:' \"$record\" || fail migrated-prefix\n"
    "  [ \"$(wc -l < \"$record\")\" -eq 0 ] || fail migrated-newline\n"
    "done\n"
    ": > compiler.trace\n"
    "make -q -f Fixture.mk build/bin/lint-fixture || fail migrated-q\n"
    "make -n -f Fixture.mk build/bin/lint-fixture >migrated-dryrun.log 2>&1 || fail migrated-n\n"
    "[ \"$(cat migrated-dryrun.log)\" = \"make: 'build/bin/lint-fixture' is up to date.\" ] || fail migrated-n-work\n"
    "[ ! -s compiler.trace ] || fail migrated-work\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk AFLAG=-DVALUE=2 build/bin/lint-fixture >>make.log 2>&1 || fail flag-change\n"
    "[ \"$(build/bin/lint-fixture)\" = '2 17' ] || fail flag-output\n"
;
static const char lint_command_part_5[] =
    "grep -q 'tools/lint/lintc/one.c' compiler.trace || fail flag-not-compiled\n"
    "! grep -q 'tools/lint/lintc/two.c' compiler.trace || fail flag-extra-tu\n"
    "! grep -q 'platform/node.c' compiler.trace || fail flag-extra-node\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk build/bin/lint-fixture >>make.log 2>&1 || fail flag-back\n"
    "[ \"$(build/bin/lint-fixture)\" = '1 17' ] || fail flag-back-output\n"
    "! grep -q 'tools/lint/lintc/two.c' compiler.trace || fail flag-back-extra\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk GLOBAL=-DGLOBAL=1 build/bin/lint-fixture >>make.log 2>&1 || fail global\n"
    "[ \"$(grep -c ' -c ' compiler.trace)\" = 3 ] || fail global-count\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk GLOBAL=-DGLOBAL=1 HOST_CC=./cc-two build/bin/lint-fixture >>make.log 2>&1 || fail host-cc\n"
    "[ \"$(grep -c '^two .* -c ' compiler.trace)\" = 3 ] || fail host-cc-count\n"
    "rm build/lintc-obj/one.o.cmd\n"
    ": > build/lintc-obj/two.o.cmd\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk GLOBAL=-DGLOBAL=1 HOST_CC=./cc-two build/bin/lint-fixture >>make.log 2>&1 || fail missing-command\n"
    "[ \"$(grep -c ' -c ' compiler.trace)\" = 2 ] || fail missing-command-count\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk GLOBAL=-DGLOBAL=1 HOST_CC=./cc-two 'LINTC_OBJS=build/lintc-obj/two.o build/lintc-obj/one.o' build/bin/lint-fixture >>make.log 2>&1 || fail link-order\n"
;
static const char lint_command_part_6[] =
    "! grep -q ' -c ' compiler.trace || fail link-order-compile\n"
    "[ \"$(wc -l < compiler.trace)\" = 1 ] || fail link-order-count\n"
    "make -j2 -s -f Fixture.mk build/bin/lint-fixture >>make.log 2>&1 || fail restore\n"
    "cp build/lintc-obj/one.o saved.o\n"
    "cp build/bin/lint-fixture saved.bin\n"
    ": > fail-cc\n"
    "if make -j2 -s -f Fixture.mk AFLAG=-DVALUE=4 build/bin/lint-fixture >>make.log 2>&1; then fail compiler-accepted; fi\n"
    "cmp -s saved.o build/lintc-obj/one.o && cmp -s saved.bin build/bin/lint-fixture || fail compiler-publication\n"
    "[ ! -e build/lintc-obj/one.o.cmd ] || fail compiler-record\n"
    "rm fail-cc\n"
    "make -j2 -s -f Fixture.mk AFLAG=-DVALUE=4 build/bin/lint-fixture >>make.log 2>&1 || fail compiler-retry\n"
    "[ \"$(build/bin/lint-fixture)\" = '4 17' ] || fail compiler-retry-output\n"
    ": > compiler.trace\n"
    ": > clang.trace\n"
    "make -j2 -s -f Fixture.mk AFLAG=-DVALUE=4 LINTC_CLANG=./clang-one build/bin/lint-fixture >>make.log 2>&1 || fail clang-on\n"
    "[ \"$(grep -c ' -c ' compiler.trace)\" = 2 ] && [ \"$(wc -l < clang.trace)\" = 2 ] || fail clang-scope\n"
    "cp build/bin/lint-fixture saved.bin\n"
    ": > fail-clang\n"
    "if make -j2 -s -f Fixture.mk AFLAG=-DVALUE=4 LINTC_CLANG=./clang-two build/bin/lint-fixture >>make.log 2>&1; then fail clang-accepted; fi\n"
    "cmp -s saved.bin build/bin/lint-fixture || fail clang-publication\n"
;
static const char lint_command_part_7[] =
    "rm fail-clang\n"
    "make -j2 -s -f Fixture.mk AFLAG=-DVALUE=4 LINTC_CLANG=./clang-two build/bin/lint-fixture >>make.log 2>&1 || fail clang-retry\n"
    "cp build/bin/lint-fixture saved.bin\n"
    ": > fail-link\n"
    "if make -j2 -s -f Fixture.mk AFLAG=-DVALUE=4 LINTC_CLANG=./clang-two 'LINTC_OBJS=build/lintc-obj/two.o build/lintc-obj/one.o' build/bin/lint-fixture >>make.log 2>&1; then fail link-accepted; fi\n"
    "cmp -s saved.bin build/bin/lint-fixture && [ ! -e build/bin/lint-fixture.cmd ] || fail link-publication\n"
    "rm fail-link\n"
    ": > empty-link\n"
    "if make -j2 -s -f Fixture.mk AFLAG=-DVALUE=4 LINTC_CLANG=./clang-two build/bin/lint-fixture >>make.log 2>&1; then fail empty-link-accepted; fi\n"
    "cmp -s saved.bin build/bin/lint-fixture && [ ! -e build/bin/lint-fixture.cmd ] || fail empty-link-publication\n"
    "rm empty-link\n"
    "make -j2 -s -f Fixture.mk AFLAG=-DVALUE=4 LINTC_CLANG=./clang-two build/bin/lint-fixture >>make.log 2>&1 || fail link-retry\n"
    "quote=$(printf '\\047')\n"
    "arg=\"-DVALUE=5 -DLABEL=${quote}quote # \\$\\$HOME ; touch injected${quote}\"\n"
    "make -j2 -s -f Fixture.mk \"AFLAG=$arg\" build/bin/lint-fixture >>make.log 2>&1 || fail quoted\n"
    "[ \"$(build/bin/lint-fixture)\" = '5 17' ] && [ ! -e injected ] || fail quoted-output\n"
    "grep -Fq 'quote # $HOME ; touch injected' build/lintc-obj/one.o.cmd || fail quoted-record\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk \"AFLAG=$arg\" build/bin/lint-fixture >>make.log 2>&1 || fail quoted-warm\n"
    "[ ! -s compiler.trace ] && [ ! -e injected ] || fail quoted-warm-work\n"
;
static const char lint_command_part_8[] =
    "# Direct and parent requests must agree on the effective per-object command.\n"
    ": > compiler.trace\n"
    "make -s -f Fixture.mk AFLAG=-DVALUE=6 build/lintc-obj/one.o >>make.log 2>&1 || fail direct-lint\n"
    "[ \"$(grep -c 'tools/lint/lintc/one.c' compiler.trace)\" = 1 ] || fail direct-lint-trace\n"
    ": > compiler.trace\n"
    "make -s -f Fixture.mk AFLAG=-DVALUE=6 build/bin/lint-fixture >>make.log 2>&1 || fail direct-lint-parent\n"
    "[ \"$(build/bin/lint-fixture)\" = '6 17' ] || fail direct-lint-output\n"
    "! grep -q ' -c ' compiler.trace || fail direct-lint-parent-recompile\n"
    "make -q -f Fixture.mk AFLAG=-DVALUE=6 build/lintc-obj/one.o || fail direct-lint-q\n"
    "make -n -f Fixture.mk AFLAG=-DVALUE=6 build/lintc-obj/one.o >direct-dryrun.log 2>&1 || fail direct-lint-n\n"
    "[ \"$(cat direct-dryrun.log)\" = \"make: 'build/lintc-obj/one.o' is up to date.\" ] || fail direct-lint-n-work\n"
    ": > compiler.trace\n"
    "make -s -f Fixture.mk AFLAG=-DVALUE=6 NFLAG=-DNODE_VALUE=19 build/lintc-obj/node/platform/node.o >>make.log 2>&1 || fail direct-node\n"
    "[ \"$(grep -c 'platform/node.c' compiler.trace)\" = 1 ] || fail direct-node-trace\n"
    ": > compiler.trace\n"
    "make -s -f Fixture.mk AFLAG=-DVALUE=6 NFLAG=-DNODE_VALUE=19 build/bin/lint-fixture >>make.log 2>&1 || fail direct-node-parent\n"
    "[ \"$(build/bin/lint-fixture)\" = '6 19' ] || fail direct-node-output\n"
    "! grep -q ' -c ' compiler.trace || fail direct-node-parent-recompile\n"
    "make -q -f Fixture.mk AFLAG=-DVALUE=6 NFLAG=-DNODE_VALUE=19 build/lintc-obj/node/platform/node.o || fail direct-node-q\n"
    "make -n -f Fixture.mk AFLAG=-DVALUE=6 NFLAG=-DNODE_VALUE=19 build/lintc-obj/node/platform/node.o >direct-dryrun.log 2>&1 || fail direct-node-n\n"
;
static const char lint_command_part_9[] =
    "[ \"$(cat direct-dryrun.log)\" = \"make: 'build/lintc-obj/node/platform/node.o' is up to date.\" ] || fail direct-node-n-work\n"
    ": > compiler.trace\n"
    "make -s -f Fixture.mk AFLAG=-DVALUE=8 NFLAG=-DNODE_VALUE=21 build/bin/lint-fixture >>make.log 2>&1 || fail parent-first\n"
    "[ \"$(build/bin/lint-fixture)\" = '8 21' ] || fail parent-first-output\n"
    "[ \"$(grep -c ' -c ' compiler.trace)\" = 2 ] || fail parent-first-count\n"
    ": > compiler.trace\n"
    "for obj in build/lintc-obj/one.o build/lintc-obj/node/platform/node.o; do\n"
    "  make -q -f Fixture.mk AFLAG=-DVALUE=8 NFLAG=-DNODE_VALUE=21 \"$obj\" || fail parent-direct-q\n"
    "  make -n -f Fixture.mk AFLAG=-DVALUE=8 NFLAG=-DNODE_VALUE=21 \"$obj\" >direct-dryrun.log 2>&1 || fail parent-direct-n\n"
    "  [ \"$(cat direct-dryrun.log)\" = \"make: '$obj' is up to date.\" ] || fail parent-direct-n-work\n"
    "done\n"
    "[ ! -s compiler.trace ] || fail parent-direct-work\n"
    "# A record is untrusted data, never an expression to evaluate.\n"
    "printf '%s' '$(shell touch injected-read)' > build/lintc-obj/one.o.cmd\n"
    ": > compiler.trace\n"
    "make -s -f Fixture.mk AFLAG=-DVALUE=8 NFLAG=-DNODE_VALUE=21 build/bin/lint-fixture >>make.log 2>&1 || fail corrupt-record\n"
    "[ ! -e injected-read ] || fail corrupt-record-executed\n"
    "[ \"$(grep -c 'tools/lint/lintc/one.c' compiler.trace)\" = 1 ] || fail corrupt-record-miss\n"
    "! grep -Fq '$(shell touch injected-read)' build/lintc-obj/one.o.cmd || fail corrupt-record-retained\n"
    "pad=$(awk 'BEGIN { for (i = 0; i < 3000; i++) printf \"a\" }')\n"
;
static const char lint_command_part_10[] =
    "arg=\"-DVALUE=5 -DPADDING=$pad\"\n"
    "make -j2 -s -f Fixture.mk \"AFLAG=$arg\" build/bin/lint-fixture >>make.log 2>&1 || fail long-command\n"
    "[ \"$(wc -c < build/lintc-obj/one.o.cmd)\" -gt 2048 ] || fail long-record\n"
    "[ \"$(build/bin/lint-fixture)\" = '5 17' ] || fail long-output\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk \"AFLAG=$arg\" build/bin/lint-fixture >>make.log 2>&1 || fail long-warm\n"
    "[ ! -s compiler.trace ] || fail long-warm-compiler\n"
    "make -q -f Fixture.mk \"AFLAG=$arg\" build/bin/lint-fixture || fail long-warm-question\n"
    "make -n -f Fixture.mk \"AFLAG=$arg\" build/bin/lint-fixture >long-dryrun.log 2>&1 || fail long-warm-dryrun\n"
    "[ \"$(cat long-dryrun.log)\" = \"make: 'build/bin/lint-fixture' is up to date.\" ] || fail long-dryrun-commands\n"
    "touch -t 200301010000 build/lintc-obj/one.o\n"
    "printf '#define EXTRA 2\\n' > tools/lint/lintc/private.h\n"
    "touch -t 200401010000 tools/lint/lintc/private.h\n"
    ": > compiler.trace\n"
    "make -j2 -s -f Fixture.mk \"AFLAG=$arg\" build/bin/lint-fixture >>make.log 2>&1 || fail header-change\n"
    "[ \"$(build/bin/lint-fixture)\" = '7 17' ] || fail header-output\n"
    "grep -q 'tools/lint/lintc/one.c' compiler.trace && ! grep -q 'tools/lint/lintc/two.c' compiler.trace && ! grep -q 'platform/node.c' compiler.trace || fail header-scope\n"
    "umask 077\n"
    "rm -f build/lintc-obj/one.o build/lintc-obj/two.o build/lintc-obj/node/platform/node.o\n"
    "rm -f build/lintc-obj/one.d build/lintc-obj/two.d build/lintc-obj/node/platform/node.d\n"
;
static const char lint_command_part_11[] =
    "rm -f build/lintc-obj/one.o.cmd build/lintc-obj/two.o.cmd build/lintc-obj/node/platform/node.o.cmd\n"
    "rm -f build/bin/lint-fixture build/bin/lint-fixture.cmd\n"
    "make -j2 -s -f Fixture.mk \"AFLAG=$arg\" build/bin/lint-fixture >>make.log 2>&1 || fail mode-077-build\n"
    "cc -std=c2x -DVALUE=5 -c tools/lint/lintc/one.c -o direct-077.o\n"
    "cc build/lintc-obj/one.o build/lintc-obj/two.o build/lintc-obj/node/platform/node.o -o direct-077\n"
    "[ \"$(ls -ld direct-077.o | awk '{print $1}')\" = \"$(ls -ld build/lintc-obj/one.o | awk '{print $1}')\" ] || fail object-mode-077\n"
    "[ \"$(ls -ld direct-077 | awk '{print $1}')\" = \"$(ls -ld build/bin/lint-fixture | awk '{print $1}')\" ] || fail binary-mode-077\n"
    "[ \"$(build/bin/lint-fixture)\" = '7 17' ] || fail mode-077-output\n"
    "printf 'command-fixture PASS\\n'\n"
;
static int t_lint_command_rebuild(void)
{
    char script[sizeof lint_command_part_0 + sizeof lint_command_part_1 + sizeof lint_command_part_2 + sizeof lint_command_part_3 + sizeof lint_command_part_4 + sizeof lint_command_part_5 + sizeof lint_command_part_6 + sizeof lint_command_part_7 + sizeof lint_command_part_8 + sizeof lint_command_part_9 + sizeof lint_command_part_10 + sizeof lint_command_part_11];
    int n = snprintf(script, sizeof script, "%s%s%s%s%s%s%s%s%s%s%s%s",
                     lint_command_part_0,
                     lint_command_part_1,
                     lint_command_part_2,
                     lint_command_part_3,
                     lint_command_part_4,
                     lint_command_part_5,
                     lint_command_part_6,
                     lint_command_part_7,
                     lint_command_part_8,
                     lint_command_part_9,
                     lint_command_part_10,
                     lint_command_part_11);
    if (n < 0 || (size_t)n >= sizeof script) return 1;
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "lint_command", "rebuild");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (bad) fprintf(stderr, "lint command fixture retained: %s\n", fixture);
    else if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

static int t_proof_plan_metadata(void)
{
    static const char setup[] =
        "set -eu; root=$1; work=$2; cd \"$work\"\n"
        "fail() { echo \"proof-plan fixture: $1\" >&2; exit 1; }\n"
        "awk '/^# DEV_BUILD_PLAN_BEGIN$/{on=1; next} /^# DEV_BUILD_PLAN_END$/{end=1; exit} on{print} END{if (!on || !end) exit 1}' \"$root/Makefile\" > block.mk || fail missing-block\n"
        "cat > Fixture.mk <<'MAKE'\n"
        "DEV_PROOF_PLAN=build/dev-proof/plan.env\nDEV_RESTART_PLAN=build/dev-loop/restart.env\n"
        "BUILD_EPOCH_KEY_TOOL=./key\nBUILD_EPOCH_SESSION_TOOL=./session\n"
        "BUILD_SOURCE_ID=source\nBUILD_CLEAN=1\nBUILD_MUTATION=mutation\nBUILD_COMPILER_ID=compiler\nBUILD_SYSTEM_ID=system\n"
        "DEV_PROFILE=dev-v2\nTEST_FAST_PROFILE=test-fast-v2\nDEV_COMPILE_EPOCH=dev-epoch\nTEST_FAST_COMPILE_EPOCH=test-epoch\nDEV_EPOCH_COMPILE_FLAGS=devcompile\nDEV_EPOCH_LINK_FLAGS=devlinkepoch\nTEST_FAST_EPOCH_COMPILE_FLAGS=testcompile\nTEST_FAST_EPOCH_LINK_FLAGS=testlinkepoch\n"
        "CC=cc\nCXX=cxx\nDEV_RESTART_CFLAGS=devflags\nDEV_RESTART_LDFLAGS=devlink\nDEV_LINK_LIBS=devlibs\nDEV_OBJ_DIR=build/devobj\nDEV_LINK_RSP=build/dev.rsp\nDEV_RESTART_BASE_RELOC=build/devreloc\n"
        "TEST_FAST_CFLAGS=testflags\nTEST_FAST_LDFLAGS=testlink\nTOR_LIBS=tor\nLIBS=libs\nGTK_LIBS=gtk\nWEBKIT_LIBS=web\nTEST_FAST_OBJ_DIR=build/testobj\nTEST_PARALLEL_FAST_LINK_RSP=build/test.rsp\nTEST_RESTART_BASE_RELOC=build/testreloc\nDEV_OBJ_COMPLETE=build/devcomplete\n"
        ".PHONY: FORCE\nFORCE:\n"
        "build/devcomplete build/dev.rsp build/devreloc build/test.rsp build/testreloc:\n\t@mkdir -p build; echo artifact >> artifacts; touch $@\n"
        "include block.mk\nMAKE\n"
        "touch Makefile\n"
        "printf '%s\\n' '#!/bin/sh' 'case \"$1\" in' 'compiler-id) case \"${DRIFT:-}\" in compiler) echo bad;; compiler-fail) exit 1;; compiler-empty) :;; *) echo compiler;; esac;;' 'build-system-id) test \"${DRIFT:-}\" != system || { echo bad; exit 0; }; echo system;;' 'key) case \"${DRIFT:-}\" in key-fail) exit 1;; key-empty) exit 0;; esac; case \"$3\" in dev-v2) test \"${DRIFT:-}\" != dev-epoch || { echo bad; exit 0; }; echo dev-epoch;; test-fast-v2) test \"${DRIFT:-}\" != test-epoch || { echo bad; exit 0; }; echo test-epoch;; *) exit 1;; esac;;' '*) exit 1;; esac' > key; chmod +x key\n"
        "printf '%s\\n' '#!/bin/sh' 'echo session >> sessions' 'test \"${DRIFT:-}\" != session' > session; chmod +x session\n"
        "mkdir -p tools/dev; printf '%s\\n' '#!/bin/sh' 'test \"$1\" = verify-record && test \"$2\" = source && test \"$3\" = 1 && test \"$4\" = mutation && test \"${DRIFT:-}\" != source' > tools/dev/source-identity.sh; chmod +x tools/dev/source-identity.sh\n";
    static const char checks[] =
        "make -s -f Fixture.mk build/dev-proof/plan.env || fail proof\n"
        "test ! -e artifacts && test ! -e sessions || fail proof-built-objects\n"
        "test \"$(wc -l < build/dev-proof/plan.env)\" -eq 15 || fail fields\n"
        "make -s -f Fixture.mk build/dev-loop/restart.env || fail restart\n"
        "test \"$(wc -l < artifacts)\" -eq 5 && test \"$(wc -l < sessions)\" -eq 1 || fail restart-deps\n"
        "cmp build/dev-proof/plan.env build/dev-loop/restart.env || fail parity\n"
        "make -s -f Fixture.mk DEV_RESTART_CFLAGS=changed build/dev-proof/plan.env || fail refresh\n"
        "grep -Fx 'DEV_CFLAGS=changed' build/dev-proof/plan.env >/dev/null || fail changed-flags\n"
        "cp build/dev-proof/plan.env old\n"
        "for drift in source compiler system dev-epoch test-epoch compiler-fail compiler-empty key-fail key-empty; do if DRIFT=$drift make -s -f Fixture.mk build/dev-proof/plan.env >out 2>&1; then fail \"$drift-accepted\"; fi; cmp old build/dev-proof/plan.env || fail \"$drift-replaced\"; done\n"
        "if DRIFT=session make -s -f Fixture.mk build/dev-loop/restart.env >out 2>&1; then fail session-accepted; fi\n";
    static const char race[] =
        "unset GIT_DIR GIT_INDEX_FILE GIT_WORK_TREE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES\n"
        "cp \"$root/tools/dev/source-identity.sh\" tools/dev/source-identity.sh\n"
        "printf 'build/\\n' > .gitignore; printf 'int original = 1;\\n' > sample.c\n"
        "cat >> Fixture.mk <<'MAKE'\n"
        "ZCL_SOURCE_IDENTITY_SESSION := $(shell echo $$PPID):1\n"
        "BUILD_SOURCE_RECORD := $(shell ZCL_SOURCE_IDENTITY_SESSION='$(ZCL_SOURCE_IDENTITY_SESSION)' ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1 tools/dev/source-identity.sh capture-record)\n"
        "BUILD_SOURCE_ID := $(word 1,$(BUILD_SOURCE_RECORD))\n"
        "BUILD_CLEAN := $(word 2,$(BUILD_SOURCE_RECORD))\n"
        "BUILD_MUTATION := $(word 3,$(BUILD_SOURCE_RECORD))\n"
        ".PHONY: mutate\nmutate:\n\t@printf 'int changed = 2;\\n' > sample.c\n"
        "$(DEV_PROOF_PLAN): mutate\nMAKE\n"
        "git init -q && git config user.name fixture && git config user.email fixture@invalid && git config commit.gpgsign false && git add . && git commit -qm fixture || fail race-setup\n"
        "printf 'prior-plan\\n' > build/dev-proof/plan.env; cp build/dev-proof/plan.env old-race\n"
        "if ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1 make -s -f Fixture.mk build/dev-proof/plan.env >build/race.log 2>&1; then fail source-race-accepted; fi\n"
        "cmp old-race build/dev-proof/plan.env || fail source-race-replaced\n"
        "printf 'int original = 1;\\n' > sample.c\n"
        "ZCL_SOURCE_IDENTITY_BATCH_DISABLE=1 make -s -o mutate -f Fixture.mk build/dev-proof/plan.env || fail source-unchanged\n";
    char script[sizeof(setup) + sizeof(checks) + sizeof(race) - 2];
    memcpy(script, setup, sizeof(setup) - 1);
    memcpy(script + sizeof(setup) - 1, checks, sizeof(checks) - 1);
    memcpy(script + sizeof(setup) + sizeof(checks) - 2, race, sizeof(race));
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "proof_plan", "metadata");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (bad) fprintf(stderr, "proof plan fixture retained: %s\n", fixture);
    else if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

static int t_test_debug_profile(void)
{
    static const char script[] =
        "set -eu; root=$1; work=$2; cd \"$work\"\n"
        "fail() { echo \"test debug profile: $1\" >&2; exit 1; }\n"
        "awk '/^define zcl_compile_epoch$/{on=1} on{print} on && /^endef$/{found=1; exit} END{if(!found) exit 1}' \"$root/Makefile\" > epoch.mk || fail epoch-block\n"
        "awk '/^# Test profiles drop -Werror/{on=1} on && /^TEST_FAST_OBJ_DIR =/{found=1; exit} on{print} END{if(!found) exit 1}' \"$root/Makefile\" > profile.mk || fail profile-block\n"
        "awk '/^define zcl_dev_plan_fields$/{on=1} on{print} on && /^endef$/{found=1; exit} END{if(!found) exit 1}' \"$root/Makefile\" > plan.mk || fail plan-block\n"
        "zero=0000000000000000000000000000000000000000000000000000000000000000\n"
        "printf 'BUILD_EPOCH_KEY_TOOL := %s/tools/dev/build-epoch-key.sh\\n' \"$root\" > Fixture.mk\n"
        "cat >> Fixture.mk <<'MAKE'\n"
        ".DEFAULT_GOAL := all\n"
        "CACHED_CFLAGS := -O2 -g -gno-record-gcc-switches -DPROFILE_FIXTURE -Werror\nZCL_LTO_FLAG := -flto\nZCL_EPOCH_DEPFILE_ID := deps=-MMD,-MP\n"
        "ZCL_EPOCH_PROFILES := test-fast\nZCL_TEST_WINDOWS_COMPAT_FLAGS :=\n"
        "BUILD_COMPILER_ID := 0000000000000000000000000000000000000000000000000000000000000000\n"
        "BUILD_SYSTEM_ID := 0000000000000000000000000000000000000000000000000000000000000000\n"
        "include epoch.mk\ninclude profile.mk\ninclude plan.mk\n"
        "all:\n\t@printf '%s\\n' '$(TEST_FAST_CFLAGS)' > flags\n"
        "\t@printf '%s\\n' '$(TEST_FAST_EPOCH_COMPILE_FLAGS)' > epoch-flags\n"
        "\t@printf '%s\\n' '$(TEST_FAST_COMPILE_EPOCH)' > epoch\n"
        "\t@$(zcl_dev_plan_fields) > plan\nMAKE\n"
        "hasflag() { awk -v flag=\"$2\" '{for(i=1;i<=NF;i++) if($i==flag) found=1} END{exit !found}' \"$1\"; }\n"
        "checkflags() { hasflag flags \"$1\" || fail missing-debug; if hasflag flags \"$2\"; then fail wrong-debug; fi; hasflag flags -gno-record-gcc-switches && hasflag flags -DPROFILE_FIXTURE || fail lost-input-flags; grep -Fx \"TEST_CFLAGS=$(cat flags)\" plan >/dev/null || fail plan-flags; grep -F -- \"$1\" epoch-flags >/dev/null || fail epoch-flags; }\n"
        "make -s -f Fixture.mk || fail default; checkflags -g1 -g; if hasflag flags -Werror; then fail unexpected-werror; fi; cp flags flags-default; cp epoch epoch-default\n"
        "test -s epoch && test \"$(cat epoch)\" != \"$zero\" || fail epoch-empty\n"
        "make -s -f Fixture.mk ZCL_TEST_DEBUG_LEVEL=1 || fail explicit-one; checkflags -g1 -g; cmp flags-default flags || fail flags-default-one; cmp epoch-default epoch || fail epoch-default-one\n"
        "make -s -f Fixture.mk ZCL_TEST_DEBUG_LEVEL=2 || fail explicit-two; checkflags -g -g1; awk '{for(i=1;i<=NF;i++) {if($i==\"-g1\") $i=\"-g\"} $1=$1; print}' flags-default > normalized-default; awk '{$1=$1; print}' flags > normalized-two; cmp normalized-default normalized-two || fail changed-unrelated-flags; if cmp -s epoch-default epoch; then fail same-epoch; fi\n"
        "make -s -f Fixture.mk ZCL_TEST_WERROR=1 || fail werror; hasflag flags -Werror || fail missing-werror; checkflags -g1 -g\n"
        "for bad in '' 0 3 text '1 2'; do if make -s -f Fixture.mk \"ZCL_TEST_DEBUG_LEVEL=$bad\" > bad.log 2>&1; then fail invalid-accepted; fi; grep -F 'ZCL_TEST_DEBUG_LEVEL must be 1 or 2' bad.log >/dev/null || fail wrong-invalid-reason; done\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "test_debug", "profile");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (bad) fprintf(stderr, "test debug profile fixture retained: %s\n", fixture);
    else if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

static int t_hotswap_ledger_dependencies(void)
{
    static const char script[] =
        "set -eu; root=$1; work=$2; cd \"$work\"\n"
        "mkdir -p build/bin\n"
        "printf '%s\\n' 'LINTC_TOOL=build/bin/z23-lint' 'Z23_DEV_BIN=build/bin/z23-dev' 'JSONQ_BIN=build/bin/jsonq' > Fixture.mk\n"
        "awk '/^check-hotswap-candidates-ledger:/{on=1; found=1} on && /^$/{exit} on{print} END{if(!found) exit 1}' \"$root/Makefile\" >> Fixture.mk\n"
        "printf 'build/bin/z23-dev build/bin/jsonq:\\n\\t@mkdir -p build/bin; touch $@; chmod +x $@\\n' >> Fixture.mk\n"
        "printf 'build/bin/z23-lint:\\n\\t@mkdir -p build/bin; printf \"#!/bin/sh\\\\n[ -x build/bin/z23-dev ] && [ -x build/bin/jsonq ] || exit 9\\\\necho called >> calls\\\\n\" > $@; chmod +x $@\\n' >> Fixture.mk\n"
        "make -s -f Fixture.mk check-hotswap-candidates-ledger || exit 1\n"
        "test \"$(wc -l < calls)\" -eq 2\n";
    char fixture[PATH_MAX] = {0};
    test_make_tmpdir(fixture, sizeof(fixture), "hotswap_ledger", "needs");
    int bad = build_needs_fixture_run(repo_root(), fixture, script);
    if (bad) fprintf(stderr, "hotswap ledger needs fixture retained: %s\n", fixture);
    else if (test_rm_rf_recursive(fixture) != 0) bad = 1;
    return bad;
}

int test_make_lint_gates(void)
{
    char real_root[PATH_MAX];
    if (lint_resolve_real_root(real_root, sizeof(real_root)) != 0)
        return 1;

    printf("\n=== make_lint_gates tests ===\n");

    if (t_lint_table_rebuild() != 0 || t_lint_private_header_rebuild() != 0) return 1;
    if (t_engine_unit_identity_rebuild() != 0) return 1;
    if (t_secure_release_host_support_rebuild() != 0) return 1;
    if (t_registry_query_scope() != 0) return 1;
    if (t_proof_plan_metadata() != 0) return 1;
    if (t_test_debug_profile() != 0) return 1;
    if (t_hotswap_ledger_dependencies() != 0) return 1;
    if (t_lint_command_rebuild() != 0) return 1;
    if (t_lint_inventory_dispatch() != 0) return 1;
    if (t_build_needs_overlap() != 0) return 1;
    if (t_lint_explicit_gates_run_once() != 0) return 1;
    /* Reap leaked sandbox bases; safe only here, before any shard exists. */
    lint_purge_stale_sandboxes(real_root);

    return lint_run_owned(LINT_OWNER_EXCLUSIVE);
}

/* ── The coverage proof ───────────────────────────────────────────────────
 * The partition is itself a registered test (no gate executes). Dropping an
 * entry, mis-tagging a lane, or widening lint_gates_group_is_exclusive fails
 * one of these. */

static int t_partition_covers_every_check(void)
{
    int failures = 0;
    unsigned char seen[LINT_GATE_ENTRY_COUNT];
    memset(seen, 0, sizeof(seen));

    int owned_total = 0, bad_owner = 0;
    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++) {
        int owner = lint_owner_of(i);
        if ((owner >= 0 && owner < LINT_GATE_SHARD_COUNT) ||
            (owner >= LINT_OWNER_HEAVY_BASE &&
             owner < LINT_OWNER_HEAVY_BASE + LINT_GATE_HEAVY_COUNT) ||
            owner == LINT_OWNER_REALROOT || owner == LINT_OWNER_EXCLUSIVE) {
            seen[i]++;
            owned_total++;
        } else {
            bad_owner++;
        }
    }

    int uncovered = 0, doubled = 0;
    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++) {
        if (seen[i] == 0) uncovered++;
        if (seen[i] > 1) doubled++;
    }

    TEST("[lint-gate] partition owns every check exactly once") {
        /* Fail-loud floor: a table that shrank to nothing is not clean. */
        ASSERT(LINT_GATE_ENTRY_COUNT >= 100);
        ASSERT(bad_owner == 0);
        ASSERT(uncovered == 0);
        ASSERT(doubled == 0);
        ASSERT(owned_total == (int)LINT_GATE_ENTRY_COUNT);
        PASS();
    } _test_next:;
    return failures;
}

static int lint_empty_shard_count(const int shard_counts[LINT_GATE_SHARD_COUNT])
{
    int empty_shards = 0;
    for (int s = 0; s < LINT_GATE_SHARD_COUNT; s++)
        if (shard_counts[s] == 0) empty_shards++;
    return empty_shards;
}

static int lint_empty_heavy_count(const int heavy_counts[LINT_GATE_HEAVY_COUNT])
{
    int empty_heavy = 0;
    for (int h = 0; h < LINT_GATE_HEAVY_COUNT; h++)
        if (heavy_counts[h] != 1) empty_heavy++;
    return empty_heavy;
}

static int t_partition_shards_all_carry_work(void)
{
    int failures = 0;
    int shard_counts[LINT_GATE_SHARD_COUNT];
    for (int s = 0; s < LINT_GATE_SHARD_COUNT; s++) shard_counts[s] = 0;
    int heavy_counts[LINT_GATE_HEAVY_COUNT];
    for (int h = 0; h < LINT_GATE_HEAVY_COUNT; h++) heavy_counts[h] = 0;
    int realroot_count = 0, exclusive_count = 0, heavy_lane_entries = 0;
    int trust_order_owner = LINT_OWNER_NONE, stray_root_owner = LINT_OWNER_NONE;
    int import_owner = lint_owner_for_check(t_import_copy_prove_selftest);
    int weld_owner = lint_owner_for_check(t_fresh_boot_weld_prove_selftest);
    int epoch_owner = lint_owner_for_check(t_agent_fast_ci_contract);

    for (size_t i = 0; i < LINT_GATE_ENTRY_COUNT; i++) {
        if (g_lint_gate_entries[i].lane == LINT_LANE_HEAVY) heavy_lane_entries++;
        int owner = lint_owner_of(i);
        if (g_lint_gate_entries[i].fn == t_sync_state_no_ordinal_gate)
            trust_order_owner = owner;
        if (g_lint_gate_entries[i].fn == t_no_stray_root_files)
            stray_root_owner = owner;
        if (owner >= 0 && owner < LINT_GATE_SHARD_COUNT) shard_counts[owner]++;
        else if (owner >= LINT_OWNER_HEAVY_BASE &&
                 owner < LINT_OWNER_HEAVY_BASE + LINT_GATE_HEAVY_COUNT)
            heavy_counts[owner - LINT_OWNER_HEAVY_BASE]++;
        else if (owner == LINT_OWNER_REALROOT) realroot_count++;
        else if (owner == LINT_OWNER_EXCLUSIVE) exclusive_count++;
    }

    int empty_shards = lint_empty_shard_count(shard_counts);
    int empty_heavy = lint_empty_heavy_count(heavy_counts);

    TEST("[lint-gate] every group carries work; the root probe retains its base group") {
        ASSERT(empty_shards == 0);
        /* Every heavy group owns exactly one check, and every HEAVY entry has
         * a group (an ungrouped one makes lint_owner_of() return NONE). */
        ASSERT(empty_heavy == 0);
        ASSERT(heavy_lane_entries == LINT_GATE_HEAVY_COUNT);
        ASSERT(import_owner == LINT_OWNER_HEAVY_BASE);
        ASSERT(weld_owner == LINT_OWNER_HEAVY_BASE + 1);
        ASSERT(epoch_owner == LINT_OWNER_HEAVY_BASE + 2);
        /* Pin both owners so coverage stays stable across fixture isolation. */
        ASSERT(trust_order_owner == LINT_OWNER_REALROOT);
        ASSERT(stray_root_owner == LINT_OWNER_EXCLUSIVE);
        ASSERT(exclusive_count == 1);
        ASSERT(realroot_count >= 1);
        PASS();
    } _test_next:;
    return failures;
}

static int t_partition_only_base_group_is_exclusive(void)
{
    int failures = 0;
    TEST("[lint-gate] only the base group is scheduled exclusively") {
        ASSERT(lint_gates_group_is_exclusive("test_make_lint_gates"));
        ASSERT(lint_gates_group_is_exclusive("make_lint_gates"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_shard_01"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_shard_08"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_realroot"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_heavy_01"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_heavy_02"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_heavy_03"));
        ASSERT(!lint_gates_group_is_exclusive("test_make_lint_gates_partition"));
        ASSERT(!lint_gates_group_is_exclusive(NULL));
        ASSERT(lint_gates_group_requires_quiet_pool(
            "test_make_lint_gates_shard_01"));
        ASSERT(lint_gates_group_requires_quiet_pool(
            "make_lint_gates_shard_08"));
        ASSERT(!lint_gates_group_requires_quiet_pool(
            "test_make_lint_gates_realroot"));
        ASSERT(!lint_gates_group_requires_quiet_pool(NULL));
        PASS();
    } _test_next:;
    return failures;
}

/* Build the metadata copy at `sb_root` and always remove `sb_base`, so a
 * failed build never leaves a tree-sized copy beside the worktree. Returns
 * the removal status; the build status goes to *built. */
static int lint_meta_copy_once(const char *real_root, const char *sb_base,
                               const char *sb_root, int *built)
{
    *built = lint_sandbox_build(real_root, sb_root);
    return test_rm_rf_recursive(sb_base);
}

static int t_sandbox_preserves_live_source_metadata(void)
{
    int failures = 0;
    TEST("[lint-gate] sandbox construction does not mutate live source metadata") {
        char real_root[PATH_MAX];
        char makefile[PATH_MAX];
        char sb_base[PATH_MAX];
        char sb_root[PATH_MAX];
        struct stat before;
        struct stat after;
        ASSERT(lint_resolve_real_root(real_root, sizeof(real_root)) == 0);
        ASSERT(snprintf(makefile, sizeof(makefile), "%s/Makefile", real_root) <
               (int)sizeof(makefile));
        ASSERT(snprintf(sb_base, sizeof(sb_base), "%s.lint_meta_%d",
                        real_root, (int)getpid()) < (int)sizeof(sb_base));
        ASSERT(snprintf(sb_root, sizeof(sb_root), "%s/w0", sb_base) <
               (int)sizeof(sb_root));
        ASSERT(stat(makefile, &before) == 0);
        int built = -1;
        ASSERT(lint_meta_copy_once(real_root, sb_base, sb_root, &built) == 0);
        ASSERT(built == 0);
        ASSERT(stat(makefile, &after) == 0);
        ASSERT(before.st_dev == after.st_dev);
        ASSERT(before.st_ino == after.st_ino);
        ASSERT(before.st_mode == after.st_mode);
        ASSERT(before.st_size == after.st_size);
        ASSERT(before.st_mtim.tv_sec == after.st_mtim.tv_sec);
        ASSERT(before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
        ASSERT(before.st_ctim.tv_sec == after.st_ctim.tv_sec);
        ASSERT(before.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
        PASS();
    } _test_next:;
    return failures;
}

/* Make `<dir>/<name>` with one file inside, so a reap must recurse. */
static int lint_plant_copy(const char *dir, const char *name)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", dir, name) >= (int)sizeof(path) ||
        mkdir(path, 0700) != 0)
        return -1;
    if (snprintf(path, sizeof(path), "%s/%s/Makefile", dir, name) >=
        (int)sizeof(path))
        return -1;
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    return fclose(f);
}

static bool lint_copy_exists(const char *dir, const char *name)
{
    char path[PATH_MAX];
    struct stat st;
    return snprintf(path, sizeof(path), "%s/%s", dir, name) < (int)sizeof(path) &&
           stat(path, &st) == 0;
}

static int t_purge_reaps_dead_owner_copies(void)
{
    int failures = 0;
    TEST("[lint-gate] sandbox copies source without the generated code index") {
        char fixture[PATH_MAX] = {0}, source[PATH_MAX], sandbox[PATH_MAX];
        test_make_tmpdir(fixture, sizeof(fixture), "lint_copy", "index");
        ASSERT(lint_plant_copy(fixture, "source") == 0);
        ASSERT(snprintf(source, sizeof(source), "%s/source", fixture) < (int)sizeof(source));
        ASSERT(snprintf(sandbox, sizeof(sandbox), "%s/sandbox", fixture) < (int)sizeof(sandbox));
        ASSERT(lint_plant_copy(source, ".codeindex") == 0);
        ASSERT(lint_sandbox_build(source, sandbox) == 0);
        ASSERT(lint_copy_exists(sandbox, "Makefile"));
        ASSERT(!lint_copy_exists(sandbox, ".codeindex"));
        ASSERT(lint_copy_exists(source, ".codeindex/Makefile"));
        ASSERT(test_rm_rf_recursive(fixture) == 0);
        PASS();
    }
    TEST("[lint-gate] purge reaps both sandbox kinds of a dead owner only") {
        char fixture[PATH_MAX] = {0};
        char root[PATH_MAX];
        char live_sb[64];
        char live_meta[64];
        test_make_tmpdir(fixture, sizeof(fixture), "lint_purge", "reap");
        ASSERT(snprintf(root, sizeof(root), "%s/tree", fixture) <
               (int)sizeof(root));
        ASSERT(snprintf(live_sb, sizeof(live_sb), "tree.lint_sb_%d",
                        (int)getpid()) < (int)sizeof(live_sb));
        ASSERT(snprintf(live_meta, sizeof(live_meta), "tree.lint_meta_%d",
                        (int)getpid()) < (int)sizeof(live_meta));
        /* 2147483647 is above any pid_max, so its owner is gone. */
        ASSERT(lint_plant_copy(fixture, "tree") == 0);
        ASSERT(lint_plant_copy(fixture, "tree.lint_sb_2147483647") == 0);
        ASSERT(lint_plant_copy(fixture, "tree.lint_meta_2147483647") == 0);
        ASSERT(lint_plant_copy(fixture, live_sb) == 0);
        ASSERT(lint_plant_copy(fixture, live_meta) == 0);
        ASSERT(lint_plant_copy(fixture, "tree.lint_meta_x") == 0);
        ASSERT(lint_plant_copy(fixture, "tree.lint_meta_+2147483647") == 0);
        ASSERT(lint_plant_copy(fixture, "tree.lint_sb_ 2147483647") == 0);
        ASSERT(lint_plant_copy(fixture, "tree.lint_meta_99999999999") == 0);
        ASSERT(lint_plant_copy(fixture, "other.lint_meta_2147483647") == 0);
        /* Other bases (leaked by killed one-shot gate copies): an aged
         * dead-owner sandbox is reaped, an aged live-owner one, a fresh
         * dead-owner one and a non-sandbox name are kept. */
        char aged_live[80];
        ASSERT(snprintf(aged_live, sizeof(aged_live), "gone.lint_sb_%d",
                        (int)getpid()) < (int)sizeof(aged_live));
        ASSERT(lint_plant_copy(fixture, "gone.lint_sb_2147483647") == 0);
        ASSERT(lint_plant_copy(fixture, "gone2.lint_meta_2147483647") == 0);
        ASSERT(lint_plant_copy(fixture, aged_live) == 0);
        ASSERT(lint_plant_copy(fixture, "notes.lint_sb_x") == 0);
        ASSERT(lint_plant_copy(fixture, "gone3.lint_sb_2147483647") == 0);
        const char *aged[] = {"gone.lint_sb_2147483647",
                              "gone2.lint_meta_2147483647", aged_live,
                              "notes.lint_sb_x"};
        for (size_t i = 0; i < sizeof(aged) / sizeof(aged[0]); i++) {
            char p[PATH_MAX];
            ASSERT(snprintf(p, sizeof(p), "%s/%s", fixture, aged[i]) <
                   (int)sizeof(p));
            struct timespec ts[2] = {{.tv_sec = time(NULL) - 7 * 3600},
                                     {.tv_sec = time(NULL) - 7 * 3600}};
            ASSERT(utimensat(AT_FDCWD, p, ts, 0) == 0);
        }
        lint_purge_stale_sandboxes(root);
        ASSERT(!lint_copy_exists(fixture, "gone.lint_sb_2147483647"));
        ASSERT(!lint_copy_exists(fixture, "gone2.lint_meta_2147483647"));
        ASSERT(lint_copy_exists(fixture, aged_live));
        ASSERT(lint_copy_exists(fixture, "notes.lint_sb_x"));
        ASSERT(lint_copy_exists(fixture, "gone3.lint_sb_2147483647"));
        ASSERT(!lint_copy_exists(fixture, "tree.lint_sb_2147483647"));
        ASSERT(!lint_copy_exists(fixture, "tree.lint_meta_2147483647"));
        ASSERT(lint_copy_exists(fixture, "tree"));
        ASSERT(lint_copy_exists(fixture, live_sb));
        ASSERT(lint_copy_exists(fixture, live_meta));
        ASSERT(lint_copy_exists(fixture, "tree.lint_meta_x"));
        ASSERT(lint_copy_exists(fixture, "tree.lint_meta_+2147483647"));
        ASSERT(lint_copy_exists(fixture, "tree.lint_sb_ 2147483647"));
        ASSERT(lint_copy_exists(fixture, "tree.lint_meta_99999999999"));
        ASSERT(lint_copy_exists(fixture, "other.lint_meta_2147483647"));
        ASSERT(test_rm_rf_recursive(fixture) == 0);
        PASS();
    }
    TEST("[lint-gate] a failed metadata copy build still removes its base") {
        char fixture[PATH_MAX] = {0};
        char sb_base[PATH_MAX];
        char sb_root[PATH_MAX];
        test_make_tmpdir(fixture, sizeof(fixture), "lint_purge", "failed");
        ASSERT(snprintf(sb_base, sizeof(sb_base), "%s/tree.lint_meta_%d",
                        fixture, (int)getpid()) < (int)sizeof(sb_base));
        ASSERT(snprintf(sb_root, sizeof(sb_root), "%s/w0", sb_base) <
               (int)sizeof(sb_root));
        /* A base that is a plain file: making w0 inside it fails for any
         * user, root included. */
        FILE *f = fopen(sb_base, "w");
        ASSERT(f != NULL);
        ASSERT(fclose(f) == 0);
        int built = 0;
        int removed = lint_meta_copy_once(fixture, sb_base, sb_root, &built);
        struct stat st;
        bool left = stat(sb_base, &st) == 0;
        ASSERT(test_rm_rf_recursive(fixture) == 0);
        ASSERT(built != 0);
        ASSERT(removed == 0);
        ASSERT(!left);
        PASS();
    } _test_next:;
    return failures;
}

static int t_missing_root_refuses_every_lane(void)
{
    int failures = 0, accepted = 0;
    int (*const entries[])(void) = {
        test_make_lint_gates, test_make_lint_gates_realroot,
        test_make_lint_gates_heavy_01, test_make_lint_gates_heavy_02,
        test_make_lint_gates_heavy_03,
#define LINT_MISSING_ROOT_ENTRY(tag, idx) test_make_lint_gates_shard_##tag,
        LINT_SHARD_LIST(LINT_MISSING_ROOT_ENTRY)
#undef LINT_MISSING_ROOT_ENTRY
    };
    char saved[PATH_MAX];
    memcpy(saved, g_repo_root_override, sizeof saved);
    int had_override = g_repo_root_override_set;
    repo_root_set_override("");
    printf("[lint-gate] exercising expected missing-root refusals\n");
    for (size_t i = 0; i < sizeof entries / sizeof entries[0]; i++)
        if (entries[i]() == 0) accepted++;
    repo_root_set_override(had_override ? saved : NULL);
    TEST("[lint-gate] every POSIX lane refuses a missing required source root") {
        ASSERT(accepted == 0);
        PASS();
    } _test_next:;
    return failures;
}

int test_make_lint_gates_partition(void)
{
    printf("\n=== make_lint_gates partition tests ===\n");
    int failures = 0;
    failures += t_missing_root_refuses_every_lane();
    failures += t_partition_covers_every_check();
    failures += t_partition_shards_all_carry_work();
    failures += t_partition_only_base_group_is_exclusive();
    failures += t_sandbox_preserves_live_source_metadata();
    failures += t_purge_reaps_dead_owner_copies();
    return failures;
}

#else  /* !ZCL_TESTING, or _WIN32 */

#if defined(_WIN32)

#include <stdio.h>

/* These groups fork+exec POSIX shell lint scripts against planted fixtures;
 * native Windows has no such contract. Catalog symbols stay present and report
 * the unobserved family explicitly; the Windows lane runs `make lint` itself. */
static int lint_gate_skip_windows(const char *group)
{
    printf("[lint-gate] SKIP (Windows): %s requires POSIX fork/exec; "
           "run make lint under MSYS2 for the Windows lint contract\n", group);
    return 0;
}

int test_make_lint_gates(void)
{ return lint_gate_skip_windows("make_lint_gates"); }
int test_make_lint_gates_realroot(void)
{ return lint_gate_skip_windows("make_lint_gates_realroot"); }
int test_make_lint_gates_heavy_01(void)
{ return lint_gate_skip_windows("make_lint_gates_heavy_01"); }
int test_make_lint_gates_heavy_02(void)
{ return lint_gate_skip_windows("make_lint_gates_heavy_02"); }
int test_make_lint_gates_heavy_03(void)
{ return lint_gate_skip_windows("make_lint_gates_heavy_03"); }
int test_make_lint_gates_partition(void)
{ return lint_gate_skip_windows("make_lint_gates_partition"); }

#define LINT_SHARD_SKIP(tag, idx) \
    int test_make_lint_gates_shard_##tag(void) \
    { \
        (void)idx; \
        return lint_gate_skip_windows("make_lint_gates_shard_" #tag); \
    }
LINT_SHARD_LIST(LINT_SHARD_SKIP)
#undef LINT_SHARD_SKIP

#else  /* !ZCL_TESTING */

/* No-ops when the lint-gate integration test is disabled. */
int test_make_lint_gates(void) { return 0; }
int test_make_lint_gates_realroot(void) { return 0; }
int test_make_lint_gates_heavy_01(void) { return 0; }
int test_make_lint_gates_heavy_02(void) { return 0; }
int test_make_lint_gates_heavy_03(void) { return 0; }
int test_make_lint_gates_partition(void) { return 0; }

#define LINT_SHARD_STUB(tag) \
    int test_make_lint_gates_shard_##tag(void) { return 0; }
LINT_SHARD_STUB(01) LINT_SHARD_STUB(02) LINT_SHARD_STUB(03) LINT_SHARD_STUB(04)
LINT_SHARD_STUB(05) LINT_SHARD_STUB(06) LINT_SHARD_STUB(07) LINT_SHARD_STUB(08)
#undef LINT_SHARD_STUB

#endif /* _WIN32 */

#endif /* ZCL_TESTING */
