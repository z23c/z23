/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Gates: check-macos-acceptance
 * Three-file family under the 700-line ceiling: this file holds the die/
 * slurp helpers, the validate() reimplementation's row/contract checks,
 * the Makefile/script reachability text scans, and the verdict;
 * gate_macos_acceptance_parse.c holds the matrix/registry text parser;
 * gate_macos_acceptance_selftest.c holds --selftest.
 *
 * Byte-parity C23 port of tools/lint/check_macos_acceptance.sh's check_root
 * — the STATIC half of the macOS acceptance contract, run for real; the
 * NATIVE half (tools/scripts/macos_acceptance.sh --run, which builds and
 * executes the derived test groups on a darwin-arm64 host) is untouched
 * and stays reachable only through `make macos-acceptance`, exactly as
 * before.
 *
 * Spawn-free reimplementation, not a wrapper: the shell original spawns
 * `tools/scripts/macos_acceptance.sh --check` and `--groups` as two
 * subprocesses per run. This port does not spawn either — the STATIC
 * validate() logic those subcommands run (matrix_rows / required_groups /
 * registered_groups / exact_groups, all pure text over
 * engine/composition/platform/macos_capabilities.def and
 * tools/dev/test_group_catalog.def) is reimplemented natively in C once,
 * and both the "--check" leg and the "--groups" leg the shell gate
 * consumed are answers this port derives from that single native pass
 * rather than two subprocess round-trips. tools/scripts/macos_acceptance.sh
 * itself is untouched: its own --check/--groups/--run dispatch keeps
 * working exactly as before for anyone invoking it directly or through
 * `make macos-acceptance`.
 *
 * Field semantics preserved from macos_acceptance.sh's validate():
 * - A capability row's id/state/reason/groups fields have ALL whitespace
 *   stripped (not merely trimmed) before use, matching bash's
 *   `${var//[[:space:]]/}`.
 * - `groups` for a row is everything from the 4th comma-separated field
 *   onward, commas included — bash `read` with more input fields than
 *   variables leaves the remainder, delimiters and all, in the last one.
 * - The capability-id actual set is a plain sort (not sort -u) of the
 *   per-row id, matching the shell exactly (a genuine duplicate id would
 *   show up twice and fail the exact-string comparison either way).
 * - Required-group membership is checked in FILE order (first miss wins);
 * the required/global unions are checked with dedup + sort.
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <ctype.h>
#include <regex.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>
#include "lintc.h"
#include "gate_macos_acceptance_priv.h"

static const char k_gate[] = "check-macos-acceptance";
static const char k_accept[] = "tools/scripts/macos_acceptance.sh";
static const char k_matrix[] = "engine/composition/platform/macos_capabilities.def";
static const char k_catalog[] = "tools/dev/test_group_catalog.def";
static const char k_release_cutter[] =
    "platform/packaging/release/build_release.sh";
enum { MAC_EXPECTED_GROUPS = 42 };

static const char k_expected_caps[] =
    "arm_acceleration hot_activation kqueue launchd node noise "
    "package_execution release_packaging resident_confinement "
    "scheduler_qos snapshot_export tor wallet";
static const char k_expected_required[] =
    "test_binary_staleness test_cold_join_sovereign test_crypto "
    "test_dev_platform test_os_proc test_rng test_self_backtrace test_sqlite";
static const char k_expected_union[] =
    "test_arm_hw_tiers,test_binary_ab_fallback,test_binary_staleness,"
    "test_blake2b_batch_parity,test_boot_shutdown_marker_persistence,"
    "test_chacha20_isa_parity,test_cold_join_sovereign,test_confine,"
    "test_crypto,test_dev_activation,test_dev_platform,"
    "test_directory_watcher,test_encoding,test_fast_sync_coins_export,"
    "test_hw_profile,test_net,test_noise_nk_handshake,"
    "test_noise_transport_parity,test_noise_xx_handshake,test_os_proc,"
    "test_os_sandbox,test_platform_toolchain,test_rng,test_rpc,"
    "test_sandbox_process_budget,test_self_backtrace,test_service_state,"
    "test_service_state_driver,test_sha256_isa_parity,test_sha3_256_x4,"
    "test_sha3_512_x4,test_sha512_isa_parity,test_sqlite,test_thread_qos,"
    "test_tor,test_wallet,test_wallet_backup,test_watcher_lease,"
    "test_watcher_record,test_z23_front_door,test_zcode_package_dev,test_zcode_verify";

enum { MAC_OUT = 4096 };
enum { MAC_MATRIX_BUF = 1 << 14, MAC_CATALOG_BUF = 1 << 18,
      MAC_FILE_BUF = 1 << 20 };


static void mac_die(struct mac_result *r, const char *fmt, ...)
{
    static const char pfx[] = "macos-acceptance: FAIL: ";
    size_t plen = sizeof pfx - 1;
    snprintf(r->out, sizeof r->out, "%s", pfx);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->out + plen, sizeof r->out - plen, fmt, ap);
    va_end(ap);
    r->rc = 1;
}

/* A file that stat() finds (it exists) but fopen() cannot read is neither
 * "missing" (a clean FAIL) nor a validated pass — it is UNPROVEN, and the
 * gate says so with the path, at a distinct rc (2) from an ordinary
 * validation failure (1), so mac_check_root can exit 2 rather than 1. */
static void mac_die_unproven(struct mac_result *r, const char *path)
{
    snprintf(r->out, sizeof r->out,
            "macos-acceptance: UNPROVEN — present but unreadable: %s", path);
    r->rc = 2;
}

/* ── validate(): the whole shell function, inlined (row/registry loading
 * itself lives in gate_macos_acceptance_parse.c) ───────────────────────── */

struct mac_vstate {
    struct mac_rows rows;
    struct mac_reg registered;
    struct mac_names required;
    struct mac_union u;
};

static int mac_validate_slurp(const char *matrix_path, const char *catalog_path,
                              struct mac_result *r, char *matrix_text,
                              size_t mcap, char *catalog_text, size_t ccap)
{
    struct stat st;
    if (stat(matrix_path, &st) != 0) {
        mac_die(r, "missing capability matrix: %s", matrix_path);
        return 1;
    }
    if (stat(catalog_path, &st) != 0) {
        mac_die(r, "missing registered-test catalog: %s", catalog_path);
        return 1;
    }
    if (mac_slurp(matrix_path, matrix_text, mcap)) {
        mac_die_unproven(r, matrix_path);
        return 1;
    }
    if (mac_slurp(catalog_path, catalog_text, ccap)) {
        mac_die_unproven(r, catalog_path);
        return 1;
    }
    return 0;
}

static int mac_validate_rows_and_caps(const char *matrix_text,
                                      struct mac_result *r,
                                      struct mac_vstate *vs)
{
    if (mac_load_rows(matrix_text, &vs->rows)) { r->rc = 2; return 1; }
    if (vs->rows.n == 0) {
        mac_die(r, "capability matrix yielded no rows");
        return 1;
    }
    static char ids[MAC_MAXROWS][MAC_ID];
    for (int i = 0; i < vs->rows.n; i++) {
        struct mac_row parsed;
        mac_split_row(vs->rows.r[i].groups, &parsed);
        snprintf(ids[i], MAC_ID, "%s", parsed.id);
    }
    char actual_ids[1024];
    mac_join_sorted(ids, vs->rows.n, 0, actual_ids, sizeof actual_ids, " ");
    if (strcmp(actual_ids, k_expected_caps) != 0) {
        mac_die(r, "capability set drift: expected '%s'; observed '%s'",
               k_expected_caps, actual_ids);
        return 1;
    }
    return 0;
}

static int mac_validate_registered(const char *catalog_text,
                                   struct mac_result *r,
                                   struct mac_vstate *vs)
{
    if (mac_load_registered(catalog_text, &vs->registered)) {
        r->rc = 2;
        return 1;
    }
    if (vs->registered.n_used == 0) {
        mac_die(r, "registered-test catalog yielded no groups");
        return 1;
    }
    return 0;
}

static int mac_validate_required(const char *matrix_text,
                                 struct mac_result *r,
                                 struct mac_vstate *vs)
{
    if (mac_load_required(matrix_text, &vs->required)) { r->rc = 2; return 1; }
    if (vs->required.n_used == 0) {
        mac_die(r, "required test set yielded no groups");
        return 1;
    }
    if (vs->required.n_used != 8) {
        mac_die(r, "required test set drift: expected 8 rows; observed %d",
               vs->required.n_used);
        return 1;
    }
    for (int i = 0; i < vs->required.n_used; i++) {
        if (!mac_reg_has(&vs->registered, vs->required.n[i])) {
            mac_die(r, "required test set names unregistered group '%s'",
                   vs->required.n[i]);
            return 1;
        }
    }
    char req_actual[1024];
    mac_join_sorted(vs->required.n, vs->required.n_used, 1, req_actual,
                    sizeof req_actual, " ");
    if (strcmp(req_actual, k_expected_required) != 0) {
        mac_die(r, "required test set drift: expected '%s'; observed '%s'",
               k_expected_required, req_actual);
        return 1;
    }
    return 0;
}

/* The two hand-carved contract checks the shell hard-codes for the two
 * capabilities whose exact state/reason/evidence tuple is pinned. */
static int mac_validate_row_contract(const struct mac_row *row,
                                     const char *tuple, struct mac_result *r)
{
    if (strcmp(row->id, "package_execution") == 0) {
        if (strcmp(tuple,
                   "package_execution:available:"
                   "seatbelt_scopes_filesystem_denies_network_and_enforces_rlimits:"
                   "test_os_sandbox,test_platform_toolchain,"
                   "test_sandbox_process_budget,test_zcode_package_dev,test_zcode_verify") != 0) {
            mac_die(r, "package_execution contract drift: expected "
                   "available/seatbelt_scopes_filesystem_denies_network_and_enforces_rlimits "
                   "with its exact five evidence groups; observed %s/%s/%s",
                   row->state, row->reason, row->groups);
            return 1;
        }
    } else if (strcmp(row->id, "resident_confinement") == 0) {
        if (strcmp(tuple,
                   "resident_confinement:unavailable:"
                   "landlock_and_seccomp_are_linux_only:"
                   "test_os_sandbox,test_confine") != 0) {
            mac_die(r, "resident_confinement contract drift: expected "
                   "unavailable/landlock_and_seccomp_are_linux_only with "
                   "its exact two evidence groups; observed %s/%s/%s",
                   row->state, row->reason, row->groups);
            return 1;
        }
    }
    return 0;
}

/* Walks one row's comma-separated evidence groups, requiring each to be a
 * registered group, and folds each into the running union. */
static int mac_validate_row_groups(const struct mac_row *row,
                                   struct mac_reg *registered,
                                   struct mac_union *u, struct mac_result *r)
{
    const char *p = row->groups;
    while (*p) {
        const char *comma = strchr(p, ',');
        size_t n = comma ? (size_t)(comma - p) : strlen(p);
        char group[MAC_ID];
        if (n >= sizeof group) n = sizeof group - 1;
        memcpy(group, p, n);
        group[n] = '\0';
        if (!mac_reg_has(registered, group)) {
            mac_die(r, "%s names unregistered group '%s'", row->id, group);
            return 1;
        }
        mac_union_add(u, group);
        p += n;
        if (comma) p++; else break;
    }
    return 0;
}

static int mac_validate_row(struct mac_row *row, struct mac_reg *registered,
                            struct mac_union *u, struct mac_result *r)
{
    if (strcmp(row->state, "available") != 0
        && strcmp(row->state, "degraded") != 0
        && strcmp(row->state, "unavailable") != 0) {
        mac_die(r, "%s has invalid state '%s'", row->id, row->state);
        return 1;
    }
    if (row->reason[0] == '\0') {
        mac_die(r, "%s has no typed reason", row->id);
        return 1;
    }
    if (row->groups[0] == '\0') {
        mac_die(r, "%s has no refusal/availability evidence group", row->id);
        return 1;
    }
    char tuple[MAC_GROUPS + MAC_ID + MAC_STATE + MAC_REASON];
    snprintf(tuple, sizeof tuple, "%s:%s:%s:%s", row->id, row->state,
            row->reason, row->groups);
    if (mac_validate_row_contract(row, tuple, r))
        return 1;
    return mac_validate_row_groups(row, registered, u, r);
}

static int mac_validate_rows_loop(struct mac_rows *rows,
                                  struct mac_reg *registered,
                                  struct mac_union *u, struct mac_result *r)
{
    for (int i = 0; i < rows->n; i++) {
        struct mac_row row;
        mac_split_row(rows->r[i].groups, &row);
        if (mac_validate_row(&row, registered, u, r))
            return 1;
    }
    return 0;
}

static int mac_validate_union_finalize(struct mac_union *u, char *union_csv,
                                       size_t union_cap, int *union_count,
                                       struct mac_result *r)
{
    mac_join_sorted(u->n, u->n_used, 1, union_csv, union_cap, ",");
    int cnt = 0;
    const char *p = union_csv;
    if (*p) {
        cnt = 1;
        for (; *p; p++)
            if (*p == ',')
                cnt++;
    }
    *union_count = cnt;
    if (*union_count != MAC_EXPECTED_GROUPS) {
        mac_die(r, "exact evidence union drift: expected %d groups; observed %d",
               MAC_EXPECTED_GROUPS, *union_count);
        return 1;
    }
    if (strcmp(union_csv, k_expected_union) != 0) {
        mac_die(r, "exact evidence set drift: expected '%s'; observed '%s'",
               k_expected_union, union_csv);
        return 1;
    }
    return 0;
}

static void mac_validate(const char *matrix_path, const char *catalog_path,
                         struct mac_result *r, int *union_count,
                         char *union_csv, size_t union_cap)
{
    r->rc = 0;
    r->out[0] = '\0';
    static struct mac_vstate vs;
    static char matrix_text[MAC_MATRIX_BUF];
    static char catalog_text[MAC_CATALOG_BUF];

    if (mac_validate_slurp(matrix_path, catalog_path, r, matrix_text,
                           sizeof matrix_text, catalog_text,
                           sizeof catalog_text))
        return;
    if (mac_validate_rows_and_caps(matrix_text, r, &vs))
        return;
    if (mac_validate_registered(catalog_text, r, &vs))
        return;
    if (mac_validate_required(matrix_text, r, &vs))
        return;

    vs.u.n_used = 0;
    for (int i = 0; i < vs.required.n_used; i++)
        mac_union_add(&vs.u, vs.required.n[i]);

    if (mac_validate_rows_loop(&vs.rows, &vs.registered, &vs.u, r))
        return;
    if (mac_validate_union_finalize(&vs.u, union_csv, union_cap, union_count,
                                    r))
        return;

    snprintf(r->out, sizeof r->out,
            "macos-acceptance: capability matrix + required baseline PASS "
            "(%d exact groups)", MAC_EXPECTED_GROUPS);
    r->rc = 0;
}

/* ── Leg 1c: the Make target must still reach the script. ──────────────── */

static int mac_make_target_reachable(const char *makefile_path)
{
    static char text[MAC_FILE_BUF];
    if (mac_slurp(makefile_path, text, sizeof text))
        return 0;
    regex_t re_start, re_recipe, re_next;
    int bad = reg_fail(&re_start, regcomp(&re_start,
        "^macos-acceptance:[[:space:]]+z23[[:space:]]+"
        "zclassic23-package-verify[[:space:]]+zclassic23-acme[[:space:]]*$",
        REG_EXTENDED | REG_NOSUB));
    bad |= reg_fail(&re_recipe, regcomp(&re_recipe,
        "^\t@?\\./tools/scripts/macos_acceptance\\.sh --run[[:space:]]*$",
        REG_EXTENDED | REG_NOSUB));
    bad |= reg_fail(&re_next, regcomp(&re_next, "^[^[:space:]#][^:]*:",
        REG_EXTENDED | REG_NOSUB));
    if (bad) return 0;
    int in_target = 0, found = 0;
    char *save = NULL;
    for (char *ln = strtok_r(text, "\n", &save); ln;
         ln = strtok_r(NULL, "\n", &save)) {
        if (regexec(&re_start, ln, 0, NULL, 0) == 0) {
            in_target = 1;
            continue;
        }
        if (in_target && regexec(&re_recipe, ln, 0, NULL, 0) == 0) {
            found = 1;
            continue;
        }
        if (in_target && regexec(&re_next, ln, 0, NULL, 0) == 0)
            in_target = 0;
    }
    drop3(&re_start, &re_recipe, &re_next);
    return found;
}

static int mac_only_binding_present(const char *accept_text)
{
    return strstr(accept_text,
                  "ONLY=\"$groups\" EXACT_ONLY_MATCHED=\"$groups\"") != NULL;
}

static int mac_runtime_package_reachable(const char *accept_text)
{
    return strstr(accept_text,
                  "\"$REPO_ROOT/platform/packaging/release/build_release.sh\" "
                  "--bin \"$REPO_ROOT/build/bin\" --out \"$package_root/runtime\" "
                  "--platform darwin-arm64") != NULL
        && strstr(accept_text,
                  "\"$package_root/runtime/z23\" code guide "
                  ">\"$package_root/code-guide.json\"") != NULL;
}

/* ── check_root(): the gate body ───────────────────────────────────────── */

static int mac_check_root(void)
{
    struct stat st;
    const char *inputs[] = { k_accept, k_matrix, k_catalog, k_release_cutter };
    for (int i = 0; i < 4; i++) {
        if (stat(inputs[i], &st) != 0) {
            fprintf(stderr, "%s: FATAL — missing %s.\n", k_gate, inputs[i]);
            fputs("  This gate is a thin driver over "
                  "tools/scripts/macos_acceptance.sh;\n"
                  "  with any of its four inputs gone there is nothing to "
                  "check and\n  a silent pass would be a lie.\n", stderr);
            return 2;
        }
    }
    if (access(k_accept, X_OK) != 0) {
        fprintf(stderr, "%s: FATAL — %s is not executable.\n", k_gate,
               k_accept);
        return 2;
    }

    struct mac_result res;
    int union_count = 0;
    static char union_csv[MAC_OUT];
    mac_validate(k_matrix, k_catalog, &res, &union_count, union_csv,
                sizeof union_csv);
    if (res.rc == 2) {
        fprintf(stderr, "%s: %s\n", k_gate, res.out);
        fputs("  A file that exists but cannot be read is not evidence of "
              "either a\n  pass or a violation; this gate refuses to guess "
              "and stops here.\n  Fix the file's permissions and re-run.\n",
              stderr);
        return 2;
    }
    if (res.rc != 0) {
        fprintf(stderr,
                "  %s: FAIL — the macOS capability matrix does not validate:\n",
                k_gate);
        fprintf(stderr, "    %s\n", res.out);
        fputs("\n"
              "  engine/composition/platform/macos_capabilities.def is the "
              "closed, declarative truth about what this product\n"
              "  does and does not do on darwin-arm64. Every row must name a "
              "legal\n"
              "  state, a typed reason code, and at least one REGISTERED "
              "test group\n"
              "  that proves the claim (an 'unavailable' row proves its "
              "refusal\n"
              "  path; that still counts as evidence). Fix the row, or "
              "register\n"
              "  the group in tools/dev/test_group_catalog.def — do not "
              "delete the evidence field.\n", stderr);
        return 1;
    }

    if (union_count != MAC_EXPECTED_GROUPS) {
        fprintf(stderr,
                "  %s: FAIL — expected %d exact macOS groups; derived %d.\n",
                k_gate, MAC_EXPECTED_GROUPS, union_count);
        fputs("  The capability evidence and required platform baseline form "
              "a\n  closed union; deletion must not degrade into a smaller "
              "pass.\n", stderr);
        return 1;
    }

    if (!mac_make_target_reachable("Makefile")) {
        fprintf(stderr,
                "  %s: FAIL — macos-acceptance does not depend on the "
                "complete\n  darwin-arm64 runtime member set\n", k_gate);
        fputs("  whose recipe invokes tools/scripts/macos_acceptance.sh "
              "--run.\n"
              "  The native (Darwin) leg is then unreachable from any "
              "command a\n"
              "  person would type. Restore the exact 'macos-acceptance: z23\n"
              "  zclassic23-package-verify zclassic23-acme' target and its "
              "tabbed\n  acceptance recipe.\n", stderr);
        return 1;
    }

    static char accept_text[MAC_FILE_BUF];
    if (mac_slurp(k_accept, accept_text, sizeof accept_text)) {
        fprintf(stderr, "%s: FATAL — cannot read %s.\n", k_gate, k_accept);
        return 2;
    }
    if (!mac_only_binding_present(accept_text)) {
        fprintf(stderr,
                "  %s: FAIL — %s does not bind its derived union equally\n"
                "  to t-fast-exact's parse guard and exact selector; the "
                "native\n  target could validate 38 groups while executing "
                "an empty set.\n", k_gate, k_accept);
        return 1;
    }
    if (!mac_runtime_package_reachable(accept_text)) {
        fprintf(stderr,
                "  %s: FAIL — %s does not cut and execute the real\n"
                "  temporary darwin-arm64 runtime after its exact test "
                "verdict.\n"
                "  Restore the canonical build_release.sh invocation and "
                "packaged\n"
                "  'z23 code guide' execution; source-test binaries alone do "
                "not\n  prove that the bytes a Mac user receives are "
                "acceptable.\n", k_gate, k_accept);
        return 1;
    }

    printf("  %s\n", res.out);
    printf("  %s: OK — capability matrix validates; %d evidence group(s), "
          "every one registered.\n", k_gate, union_count);

    struct utsname uts;
    const char *host_os = "unknown", *host_arch = "unknown";
    if (uname(&uts) == 0) { host_os = uts.sysname; host_arch = uts.machine; }
    printf("  %s: UNOBSERVED — the native leg (%d exact groups plus an\n",
          k_gate, union_count);
    printf("  audited/checksummed temporary runtime cut and packaged-node "
          "execution on\n  darwin-arm64) did NOT run here; this host is "
          "%s/%s.\n", host_os, host_arch);
    if (strcmp(host_os, "Darwin") == 0 && strcmp(host_arch, "arm64") == 0) {
        fputs("  This host CAN run it, and lint deliberately does not: it "
              "builds and\n"
              "  executes the derived test groups. Run 'make "
              "macos-acceptance'.\n", stdout);
    } else {
        fputs("  UNOBSERVED is not a pass. It is a leg no machine in this "
              "run could\n"
              "  observe. Run 'make macos-acceptance' on a darwin-arm64 host "
              "to\n  close it.\n", stdout);
    }
    return 0;
}

int check_macos_acceptance_run(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    printf("══ LINT: macOS acceptance (capability matrix + evidence "
          "registration) ══\n");
    return mac_check_root();
}

/* Exposed for --selftest's fixture probes (this port's replacement for the
 * shell original's `ZCL_MACOS_CAPABILITY_MATRIX=<fixture> "$ACCEPT" --check`
 * env-pointed re-exec: run the same native validate() against an alternate
 * matrix file, in-process); prototypes in gate_macos_acceptance_priv.h. */
void mac_validate_pub(const char *matrix_path, const char *catalog_path,
                      struct mac_result *r)
{
    int uc = 0;
    static char csv[MAC_OUT];
    mac_validate(matrix_path, catalog_path, r, &uc, csv, sizeof csv);
}

int mac_make_target_reachable_pub(const char *makefile_path)
{
    return mac_make_target_reachable(makefile_path);
}

int mac_runtime_package_reachable_text_pub(const char *accept_text)
{
    return mac_runtime_package_reachable(accept_text);
}
