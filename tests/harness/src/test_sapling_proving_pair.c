/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Sapling proving from the two Sapling parameter files alone, loaded on demand.
 *
 * A phone carries sapling-spend.params and sapling-output.params and not the
 * 725 MB sprout-groth16.params. Holding 51 MB resident and running a Groth16
 * self-test at every node start costs memory and heat, so boot only notes the
 * directory and stats the files; the SHA-512 pins, the compiled-in
 * verifying-key prefix check, the arm and the prover self-test run at the
 * first proving context of a send, and the proving bytes are released when
 * the send ends. A failure refuses that send and leaves the node running.
 *
 * What this group pins:
 *
 *   1. Boot: noting a directory and asking for status reads no proving byte.
 *      Files of the exact size and zero content are status pair_present and
 *      nothing is resident; a missing file, a single file or a wrong size is
 *      status none.
 *   2. First proof: one flipped byte in either file, in the verifying-key
 *      prefix or the last byte, refuses that send with a reason code and the
 *      node keeps validating. The prefix comparison refuses a planted prefix.
 *   3. A pair arms at the first proof: the prover self-test creates a real
 *      Spend + Output + binding bundle that this node's consensus verifier
 *      accepts. Status is pair_armed during the send, the proving bytes are
 *      freed when the last context ends, and the next send arms again.
 *   4. Files copied in or replaced after boot are used with no restart.
 *   5. A failing self-test refuses the send and keeps no key.
 *   6. A full four-file set still loads through sapling_init_params, reports
 *      full_set, and is not released when a send ends.
 *   7. The boot gate selects the pair only when both Sapling files are
 *      present, on every network, and otherwise behaves as before.
 *   8. The self-test runs once per proven pair: a second send of the same
 *      files skips it, replaced files are tested again, and a failure is never
 *      remembered as a pass.
 *
 * Legs that need real parameter bytes read ~/.zcash-params and never write to
 * it: staged directories hold symlinks, plus private copies for the planted
 * corruptions. Without that directory those legs print UNOBSERVED and the
 * params-free legs still run.
 */

#include "test/test_core.h"

#include "chain/chainparams.h"
#include "chain/chainparamsbase.h"
#include "config/boot.h"
#include "config/boot_params_gate.h"
#include "sapling/bn254.h"
#include "sapling/params_init.h"
#include "sapling/params_vk_embedded.h"
#include "sapling/sapling.h"
#include "sapling/sapling_prover.h"
#include "sapling/sprout.h"
#include "controllers/wallet_controller_internal.h"
#include "json/json.h"
#include "services/wallet_telemetry.h"
#include "util/blocker.h"
#include "util/safe_alloc.h"
#include "util/telemetry_ontology.h"
#include "util/telemetry_render.h"
#include "util/telemetry_snapshots.h"

#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#define PAIR_CHECK(name, expr) do { \
    printf("sapling_proving_pair: %s... ", (name)); \
    if ((expr)) printf("OK\n"); \
    else { printf("FAIL\n"); failures++; } \
} while (0)

static const char *const kSpend = "sapling-spend.params";
static const char *const kOutput = "sapling-output.params";
#define SPEND_SIZE 47958396
#define OUTPUT_SIZE 3592860

static void pair_reset(void)
{
    sapling_free_params();
    sprout_phgr_set_vk(NULL);
    zclassic_test_prover_reset();
}

static void pair_path(char *out, size_t cap, const char *dir, const char *name)
{
    snprintf(out, cap, "%s/%s", dir, name);
}

static bool pair_make_dir(char *dir, size_t cap)
{
    return test_mkdtemp(dir, cap, "sapling_pair") != NULL;
}

static void pair_remove_dir(const char *dir)
{
    DIR *d = opendir(dir);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            char p[1400];
            pair_path(p, sizeof(p), dir, e->d_name);
            (void)unlink(p);
        }
        closedir(d);
    }
    (void)rmdir(dir);
}

static bool pair_link(const char *real_dir, const char *dir, const char *name)
{
    char src[1400], dst[1400];
    pair_path(src, sizeof(src), real_dir, name);
    pair_path(dst, sizeof(dst), dir, name);
    return symlink(src, dst) == 0;
}

/* Private copy of one real file with the byte at `offset` flipped; a negative
 * offset counts from the end. */
static bool pair_copy_flipped(const char *real_dir, const char *dir,
                              const char *name, long offset)
{
    char src[1400], dst[1400];
    pair_path(src, sizeof(src), real_dir, name);
    pair_path(dst, sizeof(dst), dir, name);
    FILE *in = fopen(src, "rb");
    if (!in)
        return false;
    bool ok = fseek(in, 0, SEEK_END) == 0;
    long len = ok ? ftell(in) : -1;
    ok = ok && len > 0 && fseek(in, 0, SEEK_SET) == 0;
    uint8_t *buf = ok ? malloc((size_t)len) : NULL;
    ok = buf && fread(buf, 1, (size_t)len, in) == (size_t)len;
    fclose(in);
    if (ok) {
        long at = offset < 0 ? len + offset : offset;
        buf[at] ^= 0x01;
        FILE *out = fopen(dst, "wb");
        ok = out && fwrite(buf, 1, (size_t)len, out) == (size_t)len;
        if (out && fclose(out) != 0)
            ok = false;
    }
    free(buf);
    return ok;
}

/* Private byte-exact copy of one real file: a new inode, the same content. */
static bool pair_copy_exact(const char *real_dir, const char *dir,
                            const char *name)
{
    char src[1400], dst[1400];
    pair_path(src, sizeof(src), real_dir, name);
    pair_path(dst, sizeof(dst), dir, name);
    FILE *in = fopen(src, "rb");
    FILE *out = in ? fopen(dst, "wb") : NULL;
    bool ok = out != NULL;
    uint8_t buf[65536];
    size_t n;
    while (ok && (n = fread(buf, 1, sizeof(buf), in)) > 0)
        ok = fwrite(buf, 1, n, out) == n;
    if (in)
        fclose(in);
    if (out && fclose(out) != 0)
        ok = false;
    return ok;
}

static bool pair_blocker_present(const char *id)
{
    struct blocker_snapshot s[BLOCKER_CAP];
    int n = blocker_snapshot_all(s, BLOCKER_CAP);
    for (int i = 0; i < n; i++)
        if (strcmp(s[i].id, id) == 0)
            return true;
    return false;
}

static enum chain_network pair_network_of(const struct chain_params *p)
{
    if (!p) return CHAIN_MAIN;
    if (strcmp(p->strNetworkID, "test") == 0) return CHAIN_TESTNET;
    if (strcmp(p->strNetworkID, "regtest") == 0) return CHAIN_REGTEST;
    return CHAIN_MAIN;
}

/* Nothing resident: no key, prover not ready. */
static bool pair_unarmed(void)
{
    return sapling_get_spend_pk(NULL) == NULL &&
           sapling_get_output_pk(NULL) == NULL &&
           !zclassic_sapling_prover_is_ready();
}

static bool pair_status_is(enum sapling_proving_status want, const char *name)
{
    return sapling_proving_status() == want &&
           strcmp(sapling_proving_status_name(), name) == 0;
}

static bool pair_refusal_is(const char *code)
{
    const char *r = sapling_proving_last_refusal();
    return r && strcmp(r, code) == 0 &&
           strcmp(zclassic_sapling_prover_status(), code) == 0;
}

/* A refused load leaves validation armed on the compiled-in keys. */
static bool pair_validation_armed(void)
{
    return sapling_params_loaded() &&
           sapling_test_published_spend_vk() != NULL &&
           sapling_test_published_output_vk() != NULL;
}

/* A zero-filled sparse file of exactly `size` bytes: right size, no valid
 * content, so anything that reads and pins it refuses. */
static bool pair_sparse(const char *dir, const char *name, off_t size)
{
    char p[1400];
    pair_path(p, sizeof(p), dir, name);
    int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0)
        return false;
    bool ok = ftruncate(fd, size) == 0;
    return close(fd) == 0 && ok;
}

/* The prefix comparison, on the production code. */
static int pair_prefix_unit_legs(void)
{
    int failures = 0;
    const struct zcl_embedded_vk *es = &zcl_embedded_vks[0];
    const struct zcl_embedded_vk *eo = &zcl_embedded_vks[1];
    uint8_t *spend = calloc(1, es->len + 64);
    uint8_t *output = calloc(1, eo->len + 64);
    if (spend && output) {
        memcpy(spend, es->bytes, es->len);
        memcpy(output, eo->bytes, eo->len);
        PAIR_CHECK("matching verifying-key prefixes are accepted",
                   sapling_test_pair_prefix_ok(spend, es->len + 64, output,
                                               eo->len + 64));
        spend[7] ^= 0x01;
        PAIR_CHECK("a flipped spend prefix byte is refused",
                   !sapling_test_pair_prefix_ok(spend, es->len + 64, output,
                                                eo->len + 64));
        spend[7] ^= 0x01;
        output[eo->len - 1] ^= 0x01;
        PAIR_CHECK("a flipped output prefix byte is refused",
                   !sapling_test_pair_prefix_ok(spend, es->len + 64, output,
                                                eo->len + 64));
        output[eo->len - 1] ^= 0x01;
        PAIR_CHECK("a truncated spend file is refused",
                   !sapling_test_pair_prefix_ok(spend, es->len - 1, output,
                                                eo->len + 64));
    } else {
        PAIR_CHECK("prefix fixtures allocated", false);
    }
    free(spend);
    free(output);
    return failures;
}

static int pair_params_free_legs(void)
{
    int failures = 0;
    char dir[1200];

    pair_reset();
    sapling_note_proving_pair_dir(NULL);
    PAIR_CHECK("baseline: status none", pair_status_is(SAPLING_PROVING_NONE, "none"));
    PAIR_CHECK("baseline: nothing resident", pair_unarmed());
    PAIR_CHECK("no directory noted: not available", !sapling_proving_available());
    PAIR_CHECK("no directory noted: a proving context is refused",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("no_proving_parameters_installed"));

    sapling_note_proving_pair_dir("/nonexistent/zcl_pair_none");
    PAIR_CHECK("a missing directory is status none",
               pair_status_is(SAPLING_PROVING_NONE, "none") &&
               !sapling_proving_available());
    PAIR_CHECK("a missing directory refuses the send and keeps validating",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("sapling_proving_files_missing_or_wrong_size") &&
               pair_unarmed());

    /* Boot reads no byte: files of the exact size but zero content are
     * reported as present, which a pin or prefix check would refuse. */
    PAIR_CHECK("fixture dir", pair_make_dir(dir, sizeof(dir)));
    sapling_note_proving_pair_dir(dir);
    PAIR_CHECK("noting a directory reads nothing and records no refusal",
               sapling_proving_last_refusal() == NULL);
    PAIR_CHECK("an empty directory is status none",
               pair_status_is(SAPLING_PROVING_NONE, "none"));
    PAIR_CHECK("spend file alone is status none",
               pair_sparse(dir, kSpend, SPEND_SIZE) &&
               pair_status_is(SAPLING_PROVING_NONE, "none") &&
               !sapling_proving_available());
    PAIR_CHECK("a wrong-size output file is status none",
               pair_sparse(dir, kOutput, OUTPUT_SIZE - 1) &&
               pair_status_is(SAPLING_PROVING_NONE, "none"));
    PAIR_CHECK("both files at their exact sizes are status pair_present",
               pair_sparse(dir, kOutput, OUTPUT_SIZE) &&
               pair_status_is(SAPLING_PROVING_PAIR_PRESENT, "pair_present") &&
               sapling_proving_available());
    PAIR_CHECK("noting and status checking loaded no proving byte",
               pair_unarmed() && sapling_proving_session_acquire() == false);
    PAIR_CHECK("content checks happen at the first proof: pin refuses",
               pair_refusal_is("sapling_output_params_failed_sha512_pin") &&
               pair_unarmed() && pair_validation_armed() &&
               pair_status_is(SAPLING_PROVING_NONE, "none"));
    pair_remove_dir(dir);

    failures += pair_prefix_unit_legs();

    pair_reset();
    return failures;
}

/* A pair file that cannot be read or allocated is not a hash mismatch: the
 * send names what went wrong. Sparse files of the exact size are enough for
 * the output side, which is read first; the spend side stages the real output
 * file so the loader reaches it. */
static int pair_read_failure_output_legs(void)
{
    int failures = 0;
    char dir[1200], p[1400];
    const bool can_deny = geteuid() != 0;

    pair_reset();
    PAIR_CHECK("read-failure fixture", pair_make_dir(dir, sizeof(dir)) &&
                                       pair_sparse(dir, kOutput, OUTPUT_SIZE) &&
                                       pair_sparse(dir, kSpend, SPEND_SIZE));
    sapling_note_proving_pair_dir(dir);
    zcl_alloc_fault_fail_nth("zcl_read_whole_file", 1);
    PAIR_CHECK("a failed output read buffer is not a hash mismatch",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("sapling_output_params_unreadable") &&
               pair_unarmed());
    zcl_alloc_fault_clear();

    pair_path(p, sizeof(p), dir, kOutput);
    if (can_deny) {
        PAIR_CHECK("output file made unreadable", chmod(p, 0) == 0);
        PAIR_CHECK("an unreadable output file has its own reason",
                   zclassic_sapling_proving_ctx_init() == NULL &&
                   pair_refusal_is("sapling_output_params_unreadable") &&
                   pair_unarmed());
        (void)chmod(p, 0600);
    } else {
        printf("sapling_proving_pair: running as root - UNOBSERVED "
               "(unreadable-file legs)\n");
    }
    PAIR_CHECK("a zero-filled output file is still a pin mismatch",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("sapling_output_params_failed_sha512_pin"));
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

static int pair_read_failure_spend_legs(const char *real)
{
    int failures = 0;
    char dir[1200], p[1400];
    const bool can_deny = geteuid() != 0;

    pair_reset();
    PAIR_CHECK("spend-side fixture", pair_make_dir(dir, sizeof(dir)) &&
                                     pair_link(real, dir, kOutput) &&
                                     pair_sparse(dir, kSpend, SPEND_SIZE));
    sapling_note_proving_pair_dir(dir);
    zcl_alloc_fault_fail_nth("zcl_read_whole_file", 2);
    PAIR_CHECK("a failed spend read buffer is not a hash mismatch",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("sapling_spend_params_unreadable") &&
               pair_unarmed());
    zcl_alloc_fault_clear();
    pair_path(p, sizeof(p), dir, kSpend);
    if (can_deny) {
        PAIR_CHECK("spend file made unreadable", chmod(p, 0) == 0);
        PAIR_CHECK("an unreadable spend file has its own reason",
                   zclassic_sapling_proving_ctx_init() == NULL &&
                   pair_refusal_is("sapling_spend_params_unreadable") &&
                   pair_unarmed());
        (void)chmod(p, 0600);
    }
    PAIR_CHECK("a zero-filled spend file is still a pin mismatch",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("sapling_spend_params_failed_sha512_pin"));
    PAIR_CHECK("none of the refusals stopped validation",
               pair_validation_armed());
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

/* What an app and an operator read between sends: a pair-only node is idle,
 * not unable to send, so readiness and telemetry report that a send could
 * arm. */
static bool pair_readiness_prover_ready(void)
{
    struct json_value res;
    json_init(&res);
    json_set_object(&res);
    wallet_readiness_append_sapling(&res);
    bool ready = json_get_bool(
        json_get(json_get(&res, "sapling"), "prover_ready"));
    json_free(&res);
    return ready;
}

static bool pair_telemetry_can_spend(void)
{
    const struct telemetry_domain_schema *s = telemetry_domain_find("wallet");
    struct wallet_snapshot snap;
    struct json_value doc;
    bool value = false;
    if (!s || !wallet_dump_state_fill(&snap))
        return false;
    json_init(&doc);
    if (telemetry_render(s, &snap, TLV_FULL, NULL, &doc))
        value = json_get_bool(json_get(json_get(json_get(&doc, "values"),
                                                "security"),
                                       "can_spend_shielded"));
    json_free(&doc);
    return value;
}

static void pair_settle(void)
{
    struct timespec ts = {0, 30 * 1000 * 1000};
    (void)nanosleep(&ts, NULL);
}

/* Readiness, journey inputs and the status name agree that a send would be
 * refused again while the refused files are unchanged. */
static bool pair_reports_refused(void)
{
    return pair_status_is(SAPLING_PROVING_NONE, "none") &&
           !sapling_proving_available() && !pair_readiness_prover_ready() &&
           !pair_telemetry_can_spend();
}

static bool pair_reports_loadable(void)
{
    return pair_status_is(SAPLING_PROVING_PAIR_PRESENT, "pair_present") &&
           sapling_proving_available() && pair_readiness_prover_ready() &&
           pair_telemetry_can_spend();
}

/* A standing refusal is not "ready": the same files would fail the next send.
 * Replacing or repairing a file ends the refusal with no restart. */
static int pair_standing_refusal_legs(void)
{
    int failures = 0;
    char dir[1200], p[1400];

    pair_reset();
    PAIR_CHECK("standing-refusal fixture",
               pair_make_dir(dir, sizeof(dir)) &&
               pair_sparse(dir, kOutput, OUTPUT_SIZE) &&
               pair_sparse(dir, kSpend, SPEND_SIZE));
    sapling_note_proving_pair_dir(dir);
    PAIR_CHECK("before any send the pair is reported loadable",
               pair_reports_loadable());
    PAIR_CHECK("a pin mismatch refuses the send",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("sapling_output_params_failed_sha512_pin"));
    PAIR_CHECK("after a pin refusal nothing reports a send could arm",
               pair_reports_refused());
    pair_settle();
    PAIR_CHECK("replacing the refused file ends the refusal",
               pair_sparse(dir, kOutput, OUTPUT_SIZE) &&
               pair_reports_loadable());
    PAIR_CHECK("the replacement is tried and refused on its own content",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_reports_refused());

    if (geteuid() != 0) {
        pair_path(p, sizeof(p), dir, kOutput);
        pair_settle();
        PAIR_CHECK("output file made unreadable", chmod(p, 0) == 0);
        PAIR_CHECK("an unreadable file refuses the send",
                   zclassic_sapling_proving_ctx_init() == NULL &&
                   pair_refusal_is("sapling_output_params_unreadable") &&
                   pair_reports_refused());
        pair_settle();
        PAIR_CHECK("repairing the permissions ends the refusal",
                   chmod(p, 0600) == 0 && pair_reports_loadable());
    } else {
        printf("sapling_proving_pair: running as root - UNOBSERVED "
               "(unreadable standing-refusal legs)\n");
    }
    PAIR_CHECK("no refusal stopped validation", pair_validation_armed());
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

/* Descriptor exhaustion for the calling process: every free descriptor is
 * taken, so the next open fails with EMFILE. Returns the saved limit state to
 * pair_release_descriptors. */
struct pair_fd_hold {
    struct rlimit saved;
    int fds[512];
    int n;
    bool restore;
};

static void pair_exhaust_descriptors(struct pair_fd_hold *h)
{
    struct rlimit lim;
    h->n = 0;
    h->restore = false;
    if (getrlimit(RLIMIT_NOFILE, &h->saved) != 0)
        return;
    lim = h->saved;
    if (lim.rlim_cur > 256) {
        lim.rlim_cur = 256;
        if (setrlimit(RLIMIT_NOFILE, &lim) != 0)
            return;
        h->restore = true;
    }
    while (h->n < 512) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0)
            break;
        h->fds[h->n++] = fd;
    }
}

static void pair_release_descriptors(struct pair_fd_hold *h)
{
    for (int i = 0; i < h->n; i++)
        (void)close(h->fds[i]);
    if (h->restore)
        (void)setrlimit(RLIMIT_NOFILE, &h->saved);
    h->n = 0;
}

/* A passing failure (no memory, no descriptor) refuses that send only: the
 * same files are loadable again, and a lasting refusal after it still
 * stands. */
static int pair_transient_refusal_legs(void)
{
    int failures = 0;
    char dir[1200];

    pair_reset();
    PAIR_CHECK("transient-refusal fixture",
               pair_make_dir(dir, sizeof(dir)) &&
               pair_sparse(dir, kOutput, OUTPUT_SIZE) &&
               pair_sparse(dir, kSpend, SPEND_SIZE));
    sapling_note_proving_pair_dir(dir);
    zcl_alloc_fault_fail_nth("zcl_read_whole_file", 1);
    PAIR_CHECK("a failed allocation refuses the send",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("sapling_output_params_unreadable"));
    zcl_alloc_fault_clear();
    PAIR_CHECK("a failed allocation does not stand", pair_reports_loadable());

    struct pair_fd_hold hold;
    pair_exhaust_descriptors(&hold);
    void *held_ctx = zclassic_sapling_proving_ctx_init();
    bool refused = held_ctx == NULL;
    const char *why = sapling_proving_last_refusal();
    pair_release_descriptors(&hold);
    if (held_ctx)
        zclassic_sapling_proving_ctx_free(held_ctx);
    PAIR_CHECK("a descriptor limit refuses the send",
               refused && why &&
               strcmp(why, "sapling_output_params_unreadable") == 0);
    PAIR_CHECK("a descriptor limit does not stand", pair_reports_loadable());
    PAIR_CHECK("the retry reaches the content check and that one stands",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("sapling_output_params_failed_sha512_pin") &&
               pair_reports_refused());
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

/* A self-test that fails for want of memory (the first proving-context
 * allocation is made by the self-test itself) is a passing failure on a
 * phone: the same real pair loads on the next send with no restart. */
static int pair_selftest_memory_legs(const char *real)
{
    int failures = 0;
    char dir[1200];

    pair_reset();
    PAIR_CHECK("self-test memory fixture",
               pair_make_dir(dir, sizeof(dir)) &&
               pair_link(real, dir, kSpend) && pair_link(real, dir, kOutput));
    sapling_note_proving_pair_dir(dir);
    zcl_alloc_fault_fail_nth("native_sapling_proving_ctx", 1);
    PAIR_CHECK("a self-test out of memory refuses that send, saying it retries",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("proving_could_not_start_self_test_failed_try_again") &&
               pair_unarmed());
    zcl_alloc_fault_clear();
    PAIR_CHECK("it does not stand: the pair is loadable", pair_reports_loadable());
    /* The retry runs the self-test again: a second out-of-memory is refused
     * the same way, so no refusal was cached between the wallet and here. */
    zcl_alloc_fault_fail_nth("native_sapling_proving_ctx", 1);
    PAIR_CHECK("the next send reaches the self-test again",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("proving_could_not_start_self_test_failed_try_again") && pair_reports_loadable());
    zcl_alloc_fault_clear();
    void *ctx = zclassic_sapling_proving_ctx_init();
    PAIR_CHECK("the next send arms with no restart",
               ctx != NULL && zclassic_sapling_prover_is_ready() &&
               sapling_proving_last_refusal() == NULL);
    zclassic_sapling_proving_ctx_free(ctx);
    PAIR_CHECK("and nothing stays resident", pair_unarmed());
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

static int pair_refusal_legs(const char *real)
{
    int failures = 0;
    char dir[1200];

    const struct {
        const char *label;
        bool spend;
        long offset;
        const char *code;
    } flips[] = {
        {"spend verifying-key prefix", true, 5,
         "sapling_spend_params_failed_sha512_pin"},
        {"spend last byte", true, -1,
         "sapling_spend_params_failed_sha512_pin"},
        {"output verifying-key prefix", false, 5,
         "sapling_output_params_failed_sha512_pin"},
        {"output last byte", false, -1,
         "sapling_output_params_failed_sha512_pin"},
    };

    for (size_t i = 0; i < sizeof(flips) / sizeof(flips[0]); i++) {
        const char *bad = flips[i].spend ? kSpend : kOutput;
        const char *good = flips[i].spend ? kOutput : kSpend;
        char label[160];

        pair_reset();
        snprintf(label, sizeof(label), "fixture: flipped %s", flips[i].label);
        PAIR_CHECK(label, pair_make_dir(dir, sizeof(dir)) &&
                          pair_copy_flipped(real, dir, bad, flips[i].offset) &&
                          pair_link(real, dir, good));
        sapling_note_proving_pair_dir(dir);
        snprintf(label, sizeof(label),
                 "boot cannot see the flipped byte (%s): status pair_present",
                 flips[i].label);
        PAIR_CHECK(label, pair_status_is(SAPLING_PROVING_PAIR_PRESENT,
                                         "pair_present"));
        snprintf(label, sizeof(label),
                 "the first proof refuses a flipped byte (%s)", flips[i].label);
        PAIR_CHECK(label, zclassic_sapling_proving_ctx_init() == NULL &&
                          pair_refusal_is(flips[i].code) && pair_unarmed());
        PAIR_CHECK("the refusal leaves the node running on its keys",
                   pair_validation_armed() &&
                   pair_status_is(SAPLING_PROVING_NONE, "none"));
        pair_remove_dir(dir);
    }

    /* A replaced file is picked up with no restart. */
    pair_reset();
    char p[1400];
    PAIR_CHECK("replace fixture",
               pair_make_dir(dir, sizeof(dir)) &&
               pair_copy_flipped(real, dir, kSpend, -1) &&
               pair_link(real, dir, kOutput));
    sapling_note_proving_pair_dir(dir);
    PAIR_CHECK("the flipped file refuses the first send",
               zclassic_sapling_proving_ctx_init() == NULL);
    pair_path(p, sizeof(p), dir, kSpend);
    PAIR_CHECK("the app replaces the file",
               unlink(p) == 0 && pair_link(real, dir, kSpend));
    void *ctx = zclassic_sapling_proving_ctx_init();
    PAIR_CHECK("the next send arms with no restart",
               ctx != NULL && zclassic_sapling_prover_is_ready() &&
               sapling_proving_last_refusal() == NULL);
    zclassic_sapling_proving_ctx_free(ctx);
    pair_remove_dir(dir);

    /* Files copied in after boot. */
    pair_reset();
    PAIR_CHECK("late-copy fixture", pair_make_dir(dir, sizeof(dir)));
    sapling_note_proving_pair_dir(dir);
    PAIR_CHECK("before the copy: status none",
               pair_status_is(SAPLING_PROVING_NONE, "none"));
    PAIR_CHECK("the app copies the pair in",
               pair_link(real, dir, kSpend) && pair_link(real, dir, kOutput));
    PAIR_CHECK("after the copy: status pair_present with no restart",
               pair_status_is(SAPLING_PROVING_PAIR_PRESENT, "pair_present"));
    ctx = zclassic_sapling_proving_ctx_init();
    PAIR_CHECK("and the next send arms", ctx != NULL);
    zclassic_sapling_proving_ctx_free(ctx);
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

/* Between sends a pair-only node is idle, not unable to send. */
static int pair_report_idle_legs(const char *dir)
{
    int failures = 0;
    PAIR_CHECK("boot: readiness and telemetry report a send could arm",
               pair_readiness_prover_ready() && pair_telemetry_can_spend());
    sapling_note_proving_pair_dir(NULL);
    PAIR_CHECK("no pair noted: readiness and telemetry report no send",
               !pair_readiness_prover_ready() && !pair_telemetry_can_spend());
    sapling_note_proving_pair_dir(dir);
    return failures;
}

static int pair_arm_legs(const char *real)
{
    int failures = 0;
    char dir[1200], p[1400];

    pair_reset();
    PAIR_CHECK("pair fixture", pair_make_dir(dir, sizeof(dir)) &&
                               pair_link(real, dir, kSpend) &&
                               pair_link(real, dir, kOutput));
    pair_path(p, sizeof(p), dir, "sprout-groth16.params");
    PAIR_CHECK("the pair directory holds no Sprout proving file",
               access(p, F_OK) != 0);
    pair_path(p, sizeof(p), dir, "sprout-verifying.key");
    PAIR_CHECK("the pair directory holds no Sprout verifying key",
               access(p, F_OK) != 0);

    sapling_note_proving_pair_dir(dir);
    PAIR_CHECK("boot: status pair_present",
               pair_status_is(SAPLING_PROVING_PAIR_PRESENT, "pair_present"));
    PAIR_CHECK("boot: no proving byte is resident", pair_unarmed());
    failures += pair_report_idle_legs(dir);

    void *ctx = zclassic_sapling_proving_ctx_init();
    PAIR_CHECK("the first proving context arms the pair", ctx != NULL);
    PAIR_CHECK("the prover self-test (real Spend+Output+binding bundle "
               "accepted by the consensus verifier) passed",
               zclassic_sapling_prover_is_ready());
    PAIR_CHECK("status is pair_armed during the send",
               pair_status_is(SAPLING_PROVING_PAIR_ARMED, "pair_armed"));
    size_t spend_len = 0, output_len = 0;
    PAIR_CHECK("both proving keys are resident during the send",
               sapling_get_spend_pk(&spend_len) != NULL && spend_len > 0 &&
               sapling_get_output_pk(&output_len) != NULL && output_len > 0);
    PAIR_CHECK("verification runs on the compiled-in keys",
               pair_validation_armed() && sapling_vks_are_embedded());

    void *ctx2 = zclassic_sapling_proving_ctx_init();
    PAIR_CHECK("a second context shares the armed pair", ctx2 != NULL);
    zclassic_sapling_proving_ctx_free(ctx);
    PAIR_CHECK("one context ending keeps the pair armed for the other",
               zclassic_sapling_prover_is_ready() &&
               sapling_get_spend_pk(NULL) != NULL);
    zclassic_sapling_proving_ctx_free(ctx2);
    PAIR_CHECK("the proving bytes are freed when the send ends",
               pair_unarmed());
    PAIR_CHECK("status returns to pair_present",
               pair_status_is(SAPLING_PROVING_PAIR_PRESENT, "pair_present"));
    PAIR_CHECK("validation is untouched by the release", pair_validation_armed());

    ctx = zclassic_sapling_proving_ctx_init();
    PAIR_CHECK("the next send arms again with no restart",
               ctx != NULL && zclassic_sapling_prover_is_ready());
    zclassic_sapling_proving_ctx_free(ctx);
    PAIR_CHECK("and frees again", pair_unarmed());
    pair_remove_dir(dir);
    pair_reset();

    /* The self-test is the last gate: with the spend verifier unpublished the
     * consensus verifier rejects the bundle, so nothing may arm. */
    PAIR_CHECK("self-test fixture", pair_make_dir(dir, sizeof(dir)) &&
                                    pair_link(real, dir, kSpend) &&
                                    pair_link(real, dir, kOutput) &&
                                    sapling_install_embedded_vks());
    sapling_note_proving_pair_dir(dir);
    sapling_set_spend_vk(NULL);
    PAIR_CHECK("a failing self-test refuses that send",
               zclassic_sapling_proving_ctx_init() == NULL &&
               pair_refusal_is("proving_could_not_start_self_test_failed_try_again"));
    PAIR_CHECK("no spend is allowed after a failed self-test, no key kept",
               pair_unarmed());
    PAIR_CHECK("the node keeps running: status pair_present",
               pair_status_is(SAPLING_PROVING_PAIR_PRESENT, "pair_present"));
    PAIR_CHECK("a failed self-test does not stand: the pair is loadable",
               pair_reports_loadable());
    pair_reset();
    PAIR_CHECK("verifying keys restored", sapling_install_embedded_vks());
    ctx = zclassic_sapling_proving_ctx_init();
    PAIR_CHECK("once the verifier is whole again the send is accepted",
               ctx != NULL && sapling_proving_last_refusal() == NULL);
    zclassic_sapling_proving_ctx_free(ctx);
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

static int pair_full_set_leg(const char *real)
{
    int failures = 0;
    char dir[1200];
    static const char *const names[] = {
        "sapling-spend.params", "sapling-output.params",
        "sprout-groth16.params", "sprout-verifying.key",
    };

    pair_reset();
    sapling_note_proving_pair_dir(NULL);
    bool staged = pair_make_dir(dir, sizeof(dir));
    for (size_t i = 0; i < 4 && staged; i++)
        staged = pair_link(real, dir, names[i]);
    if (!staged) {
        PAIR_CHECK("full-set fixture", false);
        pair_remove_dir(dir);
        return failures;
    }
    PAIR_CHECK("a full set loads through sapling_init_params",
               sapling_init_params(dir));
    PAIR_CHECK("the full set arms proving at boot",
               zclassic_sapling_prover_is_ready());
    PAIR_CHECK("status is full_set",
               pair_status_is(SAPLING_PROVING_FULL_SET, "full_set"));
    void *ctx = zclassic_sapling_proving_ctx_init();
    PAIR_CHECK("a send on a full set gets a context", ctx != NULL);
    zclassic_sapling_proving_ctx_free(ctx);
    PAIR_CHECK("a send ending does not release a full set",
               zclassic_sapling_prover_is_ready() &&
               sapling_get_spend_pk(NULL) != NULL &&
               pair_status_is(SAPLING_PROVING_FULL_SET, "full_set"));
    PAIR_CHECK("the full set published parsed keys, not the compiled-in ones",
               !sapling_vks_are_embedded() && pair_validation_armed());
    /* A full set whose self-test failed leaves its keys resident and the
     * prover latched; a pair load must neither overwrite them nor arm. */
    pair_reset();
    PAIR_CHECK("failed-full-set fixture: embedded keys", sapling_install_embedded_vks());
    sapling_set_spend_vk(NULL);
    PAIR_CHECK("the full set loads but its self-test fails",
               sapling_init_params(dir) && !zclassic_sapling_prover_is_ready());
    const uint8_t *resident = sapling_get_spend_pk(NULL);
    PAIR_CHECK("its proving keys are resident", resident != NULL);
    sapling_note_proving_pair_dir(dir);
    PAIR_CHECK("proving is not available and status is none",
               !sapling_proving_available() &&
               pair_status_is(SAPLING_PROVING_NONE, "none"));
    PAIR_CHECK("a send is refused without touching the resident keys",
               zclassic_sapling_proving_ctx_init() == NULL &&
               sapling_proving_last_refusal() &&
               strcmp(sapling_proving_last_refusal(),
                      "full_set_loaded_but_self_test_failed") == 0 &&
               sapling_get_spend_pk(NULL) == resident);
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

static int pair_gate_legs(const char *real)
{
    int failures = 0;
    char dir[1200];
    struct app_context ctx = {0};
    const struct chain_params *prev = chain_params_get();
    enum chain_network prev_net = pair_network_of(prev);
    chain_params_select(CHAIN_MAIN);
    pair_reset();
    sapling_note_proving_pair_dir(NULL);

    PAIR_CHECK("gate fixture", pair_make_dir(dir, sizeof(dir)));
    ctx.params_dir = dir;
    PAIR_CHECK("an empty directory is not a pair",
               boot_params_gate_evaluate(&ctx, chain_params_get(), dir) ==
               BOOT_PARAMS_GATE_EMBEDDED);
    blocker_clear("shielded_spend_unavailable");

    PAIR_CHECK("spend file alone is not a pair",
               pair_link(real, dir, kSpend) &&
               boot_params_gate_evaluate(&ctx, chain_params_get(), dir) ==
               BOOT_PARAMS_GATE_EMBEDDED);
    blocker_clear("shielded_spend_unavailable");

    char out_path[1400];
    pair_path(out_path, sizeof(out_path), dir, kOutput);
    PAIR_CHECK("a wrong-size output file does not select the pair",
               pair_sparse(dir, kOutput, OUTPUT_SIZE - 1) &&
               boot_params_gate_evaluate(&ctx, chain_params_get(), dir) ==
               BOOT_PARAMS_GATE_EMBEDDED &&
               pair_status_is(SAPLING_PROVING_NONE, "none"));
    PAIR_CHECK("the wrong-size file is replaced", unlink(out_path) == 0);
    blocker_clear("shielded_spend_unavailable");

    PAIR_CHECK("both Sapling files select the pair",
               pair_link(real, dir, kOutput) &&
               boot_params_gate_evaluate(&ctx, chain_params_get(), dir) ==
               BOOT_PARAMS_GATE_PAIR);
    PAIR_CHECK("selecting the pair raises no spend-unavailable blocker",
               !pair_blocker_present("shielded_spend_unavailable"));
    PAIR_CHECK("the gate itself loads no proving byte", pair_unarmed());
    PAIR_CHECK("the gate noted the directory: status pair_present",
               pair_status_is(SAPLING_PROVING_PAIR_PRESENT, "pair_present"));
    void *pc = zclassic_sapling_proving_ctx_init();
    PAIR_CHECK("the first send arms spends", pc != NULL &&
               zclassic_sapling_prover_is_ready());
    zclassic_sapling_proving_ctx_free(pc);

    pair_remove_dir(dir);
    pair_reset();
    chain_params_select(prev_net);
    return failures;
}


int simnet_shielded_wallet_e2e_run_parts(int (*after_send)(const char *send));

/* Open and close one proving context; true when it armed. */
static bool pair_send_once(void)
{
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    void *c = zclassic_sapling_proving_ctx_init();
    clock_gettime(CLOCK_MONOTONIC, &t1);
    printf("sapling_proving_pair: send context setup %ld ms\n",
           (long)((t1.tv_sec - t0.tv_sec) * 1000 +
                  (t1.tv_nsec - t0.tv_nsec) / 1000000));
    bool armed = c != NULL && zclassic_sapling_prover_is_ready();
    zclassic_sapling_proving_ctx_free(c);
    return armed;
}

/* The self-test runs once per proven pair, not once per send: a second send
 * of the same files skips it, replaced files are tested again, and a failure
 * is never remembered as a pass. */
static int pair_cache_pass_legs(const char *real)
{
    int failures = 0;
    char dir[1200], p[1400];
    pair_reset();
    PAIR_CHECK("cache fixture", pair_make_dir(dir, sizeof(dir)) &&
                                pair_link(real, dir, kSpend) &&
                                pair_link(real, dir, kOutput));
    sapling_note_proving_pair_dir(dir);
    int runs = zclassic_test_prover_self_test_runs();

    PAIR_CHECK("the first send arms and runs the self-test",
               pair_send_once() &&
               zclassic_test_prover_self_test_runs() == runs + 1);
    PAIR_CHECK("a second send of the same files arms without the self-test",
               pair_send_once() &&
               zclassic_test_prover_self_test_runs() == runs + 1);
    PAIR_CHECK("a third send still skips it and nothing stays resident",
               pair_send_once() &&
               zclassic_test_prover_self_test_runs() == runs + 1 &&
               pair_unarmed());

    pair_path(p, sizeof(p), dir, kSpend);
    PAIR_CHECK("replacing the spend file", unlink(p) == 0 &&
               pair_copy_exact(real, dir, kSpend));
    PAIR_CHECK("a replaced file is self-tested again",
               pair_send_once() &&
               zclassic_test_prover_self_test_runs() == runs + 2);
    PAIR_CHECK("and the new files then skip it",
               pair_send_once() &&
               zclassic_test_prover_self_test_runs() == runs + 2);
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

static int pair_cache_fail_legs(const char *real)
{
    int failures = 0;
    char dir[1200];
    pair_reset();
    PAIR_CHECK("failure fixture", pair_make_dir(dir, sizeof(dir)) &&
                                  pair_link(real, dir, kSpend) &&
                                  pair_link(real, dir, kOutput) &&
                                  sapling_install_embedded_vks());
    sapling_note_proving_pair_dir(dir);
    sapling_set_spend_vk(NULL);
    int runs = zclassic_test_prover_self_test_runs();
    PAIR_CHECK("a failing self-test refuses the send",
               !pair_send_once() &&
               zclassic_test_prover_self_test_runs() == runs + 1);
    PAIR_CHECK("a failure is not remembered as a pass: it is tested and "
               "refused again",
               !pair_send_once() &&
               zclassic_test_prover_self_test_runs() == runs + 2 &&
               pair_unarmed());
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

static int pair_cache_legs(const char *real)
{
    return pair_cache_pass_legs(real) + pair_cache_fail_legs(real);
}

/* A node with only the Sapling pair, on a network other than mainnet. */
static int pair_net_legs(const char *real, enum chain_network net)
{
    int failures = 0;
    char dir[1200], empty[1200];
    struct app_context ctx = {0};
    enum chain_network prev = pair_network_of(chain_params_get());
    chain_params_select(net);
    pair_reset();
    sapling_note_proving_pair_dir(NULL);
    blocker_clear("shielded_spend_unavailable");

    PAIR_CHECK("net fixture", pair_make_dir(dir, sizeof(dir)) &&
                              pair_make_dir(empty, sizeof(empty)) &&
                              pair_link(real, dir, kSpend) &&
                              pair_link(real, dir, kOutput));
    ctx.params_dir = empty;
    PAIR_CHECK("no pair: the gate leaves the full-set loader to run",
               boot_params_gate_evaluate(&ctx, chain_params_get(), empty) ==
               BOOT_PARAMS_GATE_PRESENT);
    ctx.params_dir = dir;
    PAIR_CHECK("a pair-only directory selects the pair on this network",
               boot_params_gate_evaluate(&ctx, chain_params_get(), dir) ==
               BOOT_PARAMS_GATE_PAIR);
    PAIR_CHECK("shielded verification is armed from the compiled-in keys",
               pair_validation_armed());
    PAIR_CHECK("no spend-unavailable blocker is raised",
               !pair_blocker_present("shielded_spend_unavailable"));
    PAIR_CHECK("nothing is resident before the first send", pair_unarmed());
    PAIR_CHECK("the first send arms and proves the self-test bundle",
               pair_send_once());
    PAIR_CHECK("and nothing stays resident after it", pair_unarmed());
    pair_remove_dir(dir);
    pair_remove_dir(empty);
    pair_reset();
    chain_params_select(prev);
    return failures;
}

/* Reads one whole file; the caller frees. */
static uint8_t *pair_slurp(const char *real, const char *name, size_t *len)
{
    char p[1400];
    pair_path(p, sizeof(p), real, name);
    FILE *f = fopen(p, "rb");
    if (!f)
        return NULL;
    uint8_t *buf = NULL;
    long n = (fseek(f, 0, SEEK_END) == 0) ? ftell(f) : -1;
    if (n > 0 && fseek(f, 0, SEEK_SET) == 0 && (buf = malloc((size_t)n)) &&
        fread(buf, 1, (size_t)n, f) == (size_t)n)
        *len = (size_t)n;
    else {
        free(buf);
        buf = NULL;
    }
    fclose(f);
    return buf;
}

/* The prefix check stands alone: buffers that skip every pin and differ from
 * the real files by one verifying-key byte must still be refused. */
static int pair_prefix_arm_legs(const char *real)
{
    int failures = 0;
    size_t sl = 0, ol = 0;
    uint8_t *spend = pair_slurp(real, kSpend, &sl);
    uint8_t *output = pair_slurp(real, kOutput, &ol);
    PAIR_CHECK("prefix-arm fixture: real files read", spend && output);
    if (!spend || !output) {
        free(spend); free(output);
        return failures;
    }

    pair_reset();
    spend[5] ^= 0x01;
    PAIR_CHECK("arming refuses a spend buffer whose prefix differs",
               !sapling_test_pair_arm_buffers(spend, sl, output, ol) &&
               pair_unarmed() &&
               sapling_proving_last_refusal() != NULL &&
               strcmp(sapling_proving_last_refusal(),
                      "params_do_not_match_compiled_in_verifying_keys") == 0);
    spend[5] ^= 0x01;
    output[5] ^= 0x01;
    pair_reset();
    PAIR_CHECK("arming refuses an output buffer whose prefix differs",
               !sapling_test_pair_arm_buffers(spend, sl, output, ol) &&
               pair_unarmed());
    output[5] ^= 0x01;
    pair_reset();
    PAIR_CHECK("the same buffers unflipped arm",
               sapling_test_pair_arm_buffers(spend, sl, output, ol) &&
               zclassic_sapling_prover_is_ready());
    pair_reset();
    free(spend);
    free(output);
    return failures;
}

/* After each send of the production e2e on a pair-only directory, nothing
 * proving-related may stay resident. */
static int pair_e2e_after_send(const char *send)
{
    char label[96];
    int failures = 0;
    snprintf(label, sizeof(label), "after the %s send: nothing is resident", send);
    PAIR_CHECK(label, pair_unarmed());
    snprintf(label, sizeof(label), "after the %s send: status pair_present", send);
    PAIR_CHECK(label, pair_status_is(SAPLING_PROVING_PAIR_PRESENT, "pair_present"));
    return failures;
}

/* Parts A and B of the production shielded wallet e2e, with only the pair. */
static int pair_e2e_leg(const char *real)
{
    int failures = 0;
    char dir[1200];
    pair_reset();
    PAIR_CHECK("e2e pair fixture", pair_make_dir(dir, sizeof(dir)) &&
                                   pair_link(real, dir, kSpend) &&
                                   pair_link(real, dir, kOutput));
    sapling_note_proving_pair_dir(dir);
    PAIR_CHECK("e2e: nothing resident before the first send", pair_unarmed());
    failures += simnet_shielded_wallet_e2e_run_parts(pair_e2e_after_send);
    PAIR_CHECK("e2e: nothing resident after the run", pair_unarmed());
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}

struct pair_thread {
    int iterations;
    int bad;
};

static void *pair_thread_main(void *arg)
{
    struct pair_thread *t = arg;
    for (int i = 0; i < t->iterations; i++) {
        void *ctx = zclassic_sapling_proving_ctx_init();
        if (!ctx || !zclassic_sapling_prover_is_ready() ||
            sapling_get_spend_pk(NULL) == NULL)
            t->bad++;
        zclassic_sapling_proving_ctx_free(ctx);
    }
    return NULL;
}

/* Two threads open and close proving contexts while the pair arms and
 * releases under them: every context sees armed keys, and the last close
 * leaves nothing resident. */
static int pair_threads_leg(const char *real)
{
    int failures = 0;
    char dir[1200];
    pair_reset();
    PAIR_CHECK("threads fixture", pair_make_dir(dir, sizeof(dir)) &&
                                  pair_link(real, dir, kSpend) &&
                                  pair_link(real, dir, kOutput));
    sapling_note_proving_pair_dir(dir);
    struct pair_thread a = {4, 0}, b = {4, 0};
    pthread_t ta, tb;
    bool started = pthread_create(&ta, NULL, pair_thread_main, &a) == 0;
    bool started_b = pthread_create(&tb, NULL, pair_thread_main, &b) == 0;
    if (started)
        pthread_join(ta, NULL);
    if (started_b)
        pthread_join(tb, NULL);
    PAIR_CHECK("two threads started", started && started_b);
    PAIR_CHECK("every context in both threads saw an armed prover",
               a.bad == 0 && b.bad == 0);
    PAIR_CHECK("the last close left nothing resident", pair_unarmed());
    PAIR_CHECK("the session count is balanced: status pair_present",
               pair_status_is(SAPLING_PROVING_PAIR_PRESENT, "pair_present"));
    pair_remove_dir(dir);
    pair_reset();
    return failures;
}
int test_sapling_proving_pair(void);
int test_sapling_proving_pair(void)
{
    int failures = 0;
    printf("\n=== sapling proving from the Sapling pair, loaded on demand ===\n");

    failures += pair_params_free_legs();

    const char *home = getenv("HOME");
    char real[1100];
    snprintf(real, sizeof(real), "%s/.zcash-params", home ? home : "");
    char probe[1200], probe2[1200];
    pair_path(probe, sizeof(probe), real, kSpend);
    pair_path(probe2, sizeof(probe2), real, kOutput);
    if (access(probe, R_OK) != 0 || access(probe2, R_OK) != 0) {
        printf("sapling_proving_pair: ~/.zcash-params Sapling files absent - "
               "UNOBSERVED (real-file legs)\n");
        return failures;
    }

    failures += pair_refusal_legs(real);
    failures += pair_read_failure_output_legs();
    failures += pair_read_failure_spend_legs(real);
    failures += pair_standing_refusal_legs();
    failures += pair_transient_refusal_legs();
    failures += pair_selftest_memory_legs(real);
    failures += pair_arm_legs(real);
    failures += pair_gate_legs(real);
    failures += pair_cache_legs(real);
    failures += pair_net_legs(real, CHAIN_REGTEST);
    failures += pair_net_legs(real, CHAIN_TESTNET);
    failures += pair_prefix_arm_legs(real);
    failures += pair_threads_leg(real);
    failures += pair_e2e_leg(real);

    char sprout[1200], key[1200];
    pair_path(sprout, sizeof(sprout), real, "sprout-groth16.params");
    pair_path(key, sizeof(key), real, "sprout-verifying.key");
    if (access(sprout, R_OK) == 0 && access(key, R_OK) == 0)
        failures += pair_full_set_leg(real);
    else
        printf("sapling_proving_pair: Sprout files absent - UNOBSERVED "
               "(full-set leg)\n");
    return failures;
}
