/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * THE TWELVE WORDS MUST NEVER REACH A LOG FILE.
 *
 * A wallet created from here on is born with a twelve-word recovery
 * phrase, shown exactly once, at creation, on stdout. On the owner's
 * install the node runs as a systemd service and that service redirects
 * stdout to node.log. So the shipped configuration turned "show the user
 * their words once" into "write the wallet's entire spending authority
 * into a plaintext file" — a file that is rotated, copied into backups,
 * and read back on demand with `z23 ops logs`. Anyone who ever
 * reads that file owns the money in that wallet, forever, and nothing in
 * the wallet can be changed to take it back.
 *
 * The rule is therefore: if stdout is not a terminal, the node does not
 * create the wallet at all. Not "creates it and skips the print" — that
 * would leave a wallet whose one and only backup the owner never saw, and
 * no command can ever print those words again. It refuses, before a phrase
 * is drawn or a key is minted, and says why.
 *
 * WHAT IS ASSERTED — the observable property, on disk and on the wire:
 *
 *   1. boot_wallet_phrase_stdout_is_a_terminal() tells the truth about a
 *      redirected fd and about a pty. Everything below rests on it.
 *   2. boot_wallet_create_new() with stdout redirected to a file returns
 *      FALSE, writes ZERO bytes to that file, and mints NOTHING — no keys
 *      in the keystore, no wallet_keys rows, no wallet_seed row. There is
 *      no half-made wallet to clean up.
 *   3. The refusal is loud: it names the problem on stderr.
 *   4. boot_wallet_show_recovery_phrase_once() — the one function that can
 *      print a phrase — prints nothing to a redirected stdout, even when
 *      called directly with a phrase in hand.
 *   5. ANTI-VACUOUS: the same capture harness, handed the same phrase
 *      through a plain printf, DOES find it. Without this the "no phrase
 *      in the capture" assertions would pass over a harness that could not
 *      see a leak if one happened.
 */

#define _GNU_SOURCE

#include "test/test_core.h"

#include "config/boot.h"              /* wallet_at_rest_boot_decision */
#include "config/boot_wallet_phrase.h"
#include "models/database.h"
#include "models/wallet_key.h"
#include "util/boot_phase.h"
#include "util/boot_status.h"
#include "wallet/wallet.h"
#include "wallet/wallet_keystore.h"   /* wallet_at_rest_creation_policy */
#include "wallet/wallet_sqlite.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>

#define WPL_CHECK(name, expr) do {                                     \
    printf("wallet_phrase_never_logged: %s... ", (name));              \
    if (expr) { printf("OK\n"); }                                      \
    else { printf("FAIL\n"); failures++; }                             \
} while (0)

/* Same shape, for the pure-policy matrix below (no capture, no fixture). */
#define WRS_PLAN_CHECK(name, expr) WPL_CHECK(name, expr)

/* A syntactically real BIP39 phrase. It is never installed anywhere; it
 * exists so the leak scanner has something specific to hunt for. */
#define WPL_PHRASE \
    "abandon abandon abandon abandon abandon abandon " \
    "abandon abandon abandon abandon abandon about"

/* ── stdout/stderr capture ─────────────────────────────────────────── */

struct wpl_capture {
    int  saved_out, saved_err;
    int  fd_out, fd_err;
    char path_out[1200], path_err[1200];
};

/* Redirect stdout and stderr into two files, exactly as the systemd unit
 * redirects the node's stdout into node.log. */
static bool wpl_capture_begin(struct wpl_capture *c, const char *dir,
                              const char *tag)
{
    memset(c, 0, sizeof(*c));
    c->saved_out = c->saved_err = c->fd_out = c->fd_err = -1;
    snprintf(c->path_out, sizeof(c->path_out), "%s/%s.out", dir, tag);
    snprintf(c->path_err, sizeof(c->path_err), "%s/%s.err", dir, tag);

    fflush(stdout);
    fflush(stderr);
    c->saved_out = dup(STDOUT_FILENO);
    c->saved_err = dup(STDERR_FILENO);
    c->fd_out = open(c->path_out, O_RDWR | O_CREAT | O_TRUNC, 0600);
    c->fd_err = open(c->path_err, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (c->saved_out < 0 || c->saved_err < 0 || c->fd_out < 0 ||
        c->fd_err < 0)
        return false;
    return dup2(c->fd_out, STDOUT_FILENO) >= 0 &&
           dup2(c->fd_err, STDERR_FILENO) >= 0;
}

static void wpl_capture_end(struct wpl_capture *c)
{
    fflush(stdout);
    fflush(stderr);
    if (c->saved_out >= 0) { dup2(c->saved_out, STDOUT_FILENO); close(c->saved_out); }
    if (c->saved_err >= 0) { dup2(c->saved_err, STDERR_FILENO); close(c->saved_err); }
    if (c->fd_out >= 0) close(c->fd_out);
    if (c->fd_err >= 0) close(c->fd_err);
    c->saved_out = c->saved_err = c->fd_out = c->fd_err = -1;
}

/* Whole file into `buf`, NUL-terminated. Returns bytes read, -1 on a file
 * that could not be read (never silently 0 — "I could not look" and "it
 * was empty" are the two answers this whole file exists to keep apart). */
static long wpl_slurp(const char *path, char *buf, size_t cap)
{
    if (cap)
        buf[0] = '\0';
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    size_t n = fread(buf, 1, cap - 1, f);
    fclose(f);
    buf[n] = '\0';
    return (long)n;
}

/* ── the cases ─────────────────────────────────────────────────────── */

static int t_terminal_probe_tells_the_truth(const char *dir)
{
    int failures = 0;

    /* A redirected stdout is not a terminal. */
    struct wpl_capture cap;
    bool began = wpl_capture_begin(&cap, dir, "probe");
    bool redirected_says_no =
        began && !boot_wallet_phrase_stdout_is_a_terminal();
    wpl_capture_end(&cap);
    WPL_CHECK("capture harness installed", began);
    WPL_CHECK("a file on stdout is NOT reported as a terminal",
              redirected_says_no);

    /* A pty is. Opened and probed only — nothing is ever written to it, so
     * there is no way for this to block on a full pty buffer. */
#if defined(_WIN32)
    /* No posix_openpt/grantpt/ptsname on Windows, and no capturable
     * terminal fixture exists here (ConPTY presents pipes to the child, so
     * CRT isatty stays false) — the "yes" half cannot run on this lane. */
    printf("wallet_phrase_never_logged: a terminal on stdout IS reported "
           "as a terminal... SKIP (Windows): no posix_openpt pty lane\n");
#else
    int master = posix_openpt(O_RDWR | O_NOCTTY);
    bool pty_says_yes = false;
    bool pty_ready = false;
    if (master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0) {
        const char *slave_path = ptsname(master);
        int slave = slave_path ? open(slave_path, O_RDWR | O_NOCTTY) : -1;
        if (slave >= 0) {
            pty_ready = true;
            int saved = dup(STDOUT_FILENO);
            if (saved >= 0 && dup2(slave, STDOUT_FILENO) >= 0) {
                pty_says_yes = boot_wallet_phrase_stdout_is_a_terminal();
                dup2(saved, STDOUT_FILENO);
            }
            if (saved >= 0)
                close(saved);
            close(slave);
        }
    }
    if (master >= 0)
        close(master);
    /* Anti-vacuous: without a pty the "yes" half proves nothing, so say so
     * rather than passing on an untaken branch. */
    WPL_CHECK("a pty was available to probe against", pty_ready);
    WPL_CHECK("a terminal on stdout IS reported as a terminal",
              pty_says_yes);
#endif
    return failures;
}

static int t_capture_would_catch_a_leak(const char *dir)
{
    int failures = 0;
    struct wpl_capture cap;
    if (!wpl_capture_begin(&cap, dir, "vacuity")) {
        wpl_capture_end(&cap);
        WPL_CHECK("anti-vacuous: capture harness installed", false);
        return failures;
    }
    /* Exactly the shape of the defect: a phrase printed to a stdout that
     * is really a file. */
    printf("  %s\n", WPL_PHRASE);
    fflush(stdout);
    wpl_capture_end(&cap);

    char buf[8192];
    long n = wpl_slurp(cap.path_out, buf, sizeof(buf));
    WPL_CHECK("anti-vacuous: the capture file was readable", n > 0);
    WPL_CHECK("anti-vacuous: a phrase printed to a redirected stdout IS "
              "found by this test's scanner",
              n > 0 && strstr(buf, WPL_PHRASE) != NULL);
    return failures;
}

static int t_creation_refuses_and_leaves_nothing(const char *dir)
{
    int failures = 0;

    char db_path[1200];
    snprintf(db_path, sizeof(db_path), "%s/node.db", dir);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool db_ok = node_db_open(&ndb, db_path) && ndb.open;
    WPL_CHECK("fixture node.db opened", db_ok);
    if (!db_ok)
        return failures;

    struct wallet_sqlite ws;
    struct zcl_result wr = wallet_sqlite_open_r(&ws, ndb.db);
    WPL_CHECK("fixture wallet tables opened", wr.ok);
    if (!wr.ok) {
        node_db_close(&ndb);
        return failures;
    }

    struct wallet *w = calloc(1, sizeof(*w));
    WPL_CHECK("fixture wallet allocated", w != NULL);
    if (!w) {
        wallet_sqlite_close(&ws);
        node_db_close(&ndb);
        return failures;
    }
    wallet_init(w);

    WPL_CHECK("fixture starts with an empty wallet",
              w->keystore.num_keys == 0 && db_wallet_key_count(&ndb) == 0);

    /* THE CALL, with stdout pointed at a file — a node.log by any other
     * name. */
    struct wpl_capture cap;
    bool began = wpl_capture_begin(&cap, dir, "create");
    bool created = true;
    if (began)
        /* CANONICAL lane, -allow-plaintext-wallet given: an explicit
         * at-rest opt-in is NOT a declaration that this wallet is
         * disposable, so this is still somebody's spendable wallet and
         * still refuses. */
        created = boot_wallet_create_new(w, &ws, &ndb,
                                         WALLET_BOOT_CREATE_PLAINTEXT,
                                         ZCL_OPERATOR_LANE_CANONICAL);
    wpl_capture_end(&cap);
    WPL_CHECK("capture harness installed for the creation call", began);

    WPL_CHECK("creating a wallet is REFUSED when stdout is not a terminal",
              began && !created);

    char out[16384], err[16384];
    long n_out = wpl_slurp(cap.path_out, out, sizeof(out));
    long n_err = wpl_slurp(cap.path_err, err, sizeof(err));

    if (n_out > 0)
        printf("    stdout capture (%ld bytes): %.400s\n", n_out, out);

    WPL_CHECK("the capture files were readable", n_out >= 0 && n_err >= 0);
    /* The strongest form: not "no phrase on stdout" but NOTHING on stdout.
     * A print that is never reached cannot leak. */
    WPL_CHECK("NOTHING at all was written to the redirected stdout",
              n_out == 0);
    WPL_CHECK("no recovery phrase reached the redirected stdout",
              n_out >= 0 && strstr(out, WPL_PHRASE) == NULL &&
              strstr(out, "WRITE THESE 12 WORDS DOWN") == NULL);

    /* Loud, and in plain English, on the channel a person still sees. */
    WPL_CHECK("the refusal says the wallet was not created",
              n_err > 0 && strstr(err, "WALLET NOT CREATED") != NULL);
    WPL_CHECK("the refusal says why — this output is not a terminal",
              n_err > 0 && strstr(err, "NOT going to a terminal") != NULL);
    WPL_CHECK("the refusal says what to do about it",
              n_err > 0 && strstr(err, "from a terminal") != NULL);
    WPL_CHECK("the refusal itself carries no phrase",
              n_err >= 0 && strstr(err, WPL_PHRASE) == NULL);

    /* NO HALF-MADE WALLET. This is the half that stops a user being left
     * with keys whose only backup they were never shown. */
    WPL_CHECK("no key was minted into the keystore",
              w->keystore.num_keys == 0);
    WPL_CHECK("no wallet_keys row was written", db_wallet_key_count(&ndb) == 0);
    {
        uint8_t seed[32];
        bool has_seed = wallet_sqlite_read_sapling_seed(&ws, seed);
        memset(seed, 0, sizeof(seed));
        WPL_CHECK("no wallet_seed row was written", !has_seed);
    }

    wallet_free(w);
    free(w);
    wallet_sqlite_close(&ws);
    node_db_close(&ndb);
    return failures;
}

static int t_direct_print_is_also_refused(const char *dir)
{
    int failures = 0;
    struct wpl_capture cap;
    bool began = wpl_capture_begin(&cap, dir, "direct");
    if (began)
        boot_wallet_show_recovery_phrase_once(WPL_PHRASE);
    wpl_capture_end(&cap);
    WPL_CHECK("capture harness installed for the direct print", began);

    char out[16384], err[16384];
    long n_out = wpl_slurp(cap.path_out, out, sizeof(out));
    long n_err = wpl_slurp(cap.path_err, err, sizeof(err));

    if (n_out > 0)
        printf("    stdout capture (%ld bytes): %.400s\n", n_out, out);

    /* Defence in depth: even called directly, with a phrase already in
     * hand, the one function that can print words prints none of them. */
    WPL_CHECK("show_recovery_phrase_once writes nothing to a redirected "
              "stdout", n_out == 0);
    WPL_CHECK("show_recovery_phrase_once leaks no phrase",
              n_out >= 0 && strstr(out, WPL_PHRASE) == NULL);
    WPL_CHECK("show_recovery_phrase_once explains itself on stderr",
              n_err > 0 && strstr(err, "WALLET NOT CREATED") != NULL);
    return failures;
}

/* ── the refusal must be SCOPED, and it must name itself ────────────── */

/* The rule above is right for somebody's spendable wallet and was applied
 * to every wallet, so every headless first boot exited 1 — a fresh
 * mint-anchor producer, every declared dev/soak/test/copy/standby lane, and
 * a service with ZCL_WALLET_PASSPHRASE set, which is the recommended secure
 * configuration AND what the shipped canonical unit is run with. Under a unit
 * with Restart= that is a crash loop, and boot_status.json was left at
 * phase=loading / stage=db_open with no reason in it at all.
 *
 * The property asserted here is the whole matrix, not one row: the words
 * are unreachable from a non-terminal in EVERY case, and the difference
 * between the cases is only whether a wallet gets created at all. */
static int t_refusal_is_scoped_to_a_spendable_wallet(void)
{
    int failures = 0;

    /* A terminal: always show, whatever else is true. */
    WRS_PLAN_CHECK("with a terminal, the words are shown",
        boot_wallet_phrase_plan_for(true, WALLET_BOOT_CREATE_ENCRYPTED,
                                    ZCL_OPERATOR_LANE_CANONICAL, false)
        == BOOT_WALLET_PHRASE_SHOW);

    /* No terminal, and nobody has decided ANYTHING about this wallet: refuse.
     * This is the security property, and it must survive every fix.
     * -allow-plaintext-wallet does not buy a pass — a decision about
     * ENCRYPTION AT REST is not a declaration that the wallet is disposable,
     * and the plaintext keys it produces are the only copy there is. */
    WRS_PLAN_CHECK("no terminal + -allow-plaintext-wallet on a canonical "
                   "node is STILL a refusal",
        boot_wallet_phrase_plan_for(false, WALLET_BOOT_CREATE_PLAINTEXT,
                                    ZCL_OPERATOR_LANE_CANONICAL, false)
        == BOOT_WALLET_PHRASE_REFUSE);
    WRS_PLAN_CHECK("no terminal + -allow-plaintext-wallet on an UNKNOWN lane "
                   "(the interactive default) is STILL a refusal",
        boot_wallet_phrase_plan_for(false, WALLET_BOOT_CREATE_PLAINTEXT,
                                    ZCL_OPERATOR_LANE_UNKNOWN, false)
        == BOOT_WALLET_PHRASE_REFUSE);

    /* ZCL_WALLET_PASSPHRASE set (CREATE_ENCRYPTED) is an at-rest decision the
     * operator made by hand, and it counts as consent to a wallet whose backup
     * is not twelve written words. Refusing it is what made a fresh install of
     * the shipped canonical unit crash-loop: -operator-lane=canonical plus
     * Restart=always plus exit(1) forever. No phrase is drawn on the SKIP
     * plan, so nothing can leak. */
    WRS_PLAN_CHECK("no terminal + canonical lane + a passphrase: create "
                   "without a phrase (the shipped unit's first boot)",
        boot_wallet_phrase_plan_for(false, WALLET_BOOT_CREATE_ENCRYPTED,
                                    ZCL_OPERATOR_LANE_CANONICAL, false)
        == BOOT_WALLET_PHRASE_SKIP);
    WRS_PLAN_CHECK("no terminal + UNKNOWN lane + a passphrase: create "
                   "without a phrase",
        boot_wallet_phrase_plan_for(false, WALLET_BOOT_CREATE_ENCRYPTED,
                                    ZCL_OPERATOR_LANE_UNKNOWN, false)
        == BOOT_WALLET_PHRASE_SKIP);

    /* The cases the codebase already declares throwaway: create, with no
     * phrase drawn at all. */
    WRS_PLAN_CHECK("no terminal + the offline mint-anchor producer: create "
                   "without a phrase",
        boot_wallet_phrase_plan_for(false, WALLET_BOOT_CREATE_MINT_EXEMPT,
                                    ZCL_OPERATOR_LANE_UNKNOWN, false)
        == BOOT_WALLET_PHRASE_SKIP);
    static const enum zcl_operator_lane declared[] = {
        ZCL_OPERATOR_LANE_DEV, ZCL_OPERATOR_LANE_SOAK,
        ZCL_OPERATOR_LANE_TEST, ZCL_OPERATOR_LANE_COPY,
        ZCL_OPERATOR_LANE_STANDBY,
    };
    bool every_declared_lane_proceeds = true;
    for (size_t i = 0; i < sizeof(declared) / sizeof(declared[0]); i++)
        if (boot_wallet_phrase_plan_for(false, WALLET_BOOT_CREATE_PLAINTEXT,
                                        declared[i], false)
            != BOOT_WALLET_PHRASE_SKIP)
            every_declared_lane_proceeds = false;
    WRS_PLAN_CHECK("no terminal + every declared non-canonical lane "
                   "(dev/soak/test/copy/standby): create without a phrase",
                   every_declared_lane_proceeds);
    WRS_PLAN_CHECK("no terminal + an explicit 'I accept no phrase backup': "
                   "create without a phrase",
        boot_wallet_phrase_plan_for(false, WALLET_BOOT_CREATE_ENCRYPTED,
                                    ZCL_OPERATOR_LANE_CANONICAL, true)
        == BOOT_WALLET_PHRASE_SKIP);

    /* The waiver is read from the same kind of env var the plaintext
     * opt-in uses, and "0" must not disarm the gate. */
    unsetenv("ZCL_WALLET_NO_PHRASE_BACKUP");
    WRS_PLAN_CHECK("unset means not waived", !boot_wallet_phrase_backup_waived());
    setenv("ZCL_WALLET_NO_PHRASE_BACKUP", "0", 1);
    WRS_PLAN_CHECK("\"0\" means not waived", !boot_wallet_phrase_backup_waived());
    setenv("ZCL_WALLET_NO_PHRASE_BACKUP", "1", 1);
    WRS_PLAN_CHECK("\"1\" means waived", boot_wallet_phrase_backup_waived());
    unsetenv("ZCL_WALLET_NO_PHRASE_BACKUP");
    return failures;
}

/* ── THE OTHER HALF: a real terminal DOES get the words, and the warning ──
 *
 * Every assertion above is a negative — nothing printed, nothing leaked. Taken
 * alone they would all pass over a print that had been deleted. This is the
 * positive: on a real pty the twelve words appear, and so does the sentence the
 * owner approved for this surface ("...in Z23 only... will not work in
 * Electrum..."). That sentence has to be READABLE on both surfaces; the other
 * surface is core.wallet.recovery.restore's help text, held by
 * tools/lint/check_describe_budget.sh + the catalog test group.
 *
 * The print runs in a forked child so the parent can drain the pty master
 * continuously — the phrase block is ~1.5 KB and a child writing into an
 * un-drained pty buffer would be a hung test. The slave is opened BEFORE the
 * fork so the parent can never see EIO before the child has anything to say. */
static int t_a_real_terminal_gets_the_words_and_the_warning(void)
{
#if defined(_WIN32)
    /* Windows lane: this case is built on posix_openpt/grantpt/ptsname plus
     * fork(), none of which exist on Windows, and no Windows fixture can put
     * a captureable terminal behind isatty() (ConPTY presents pipes to the
     * child, so CRT isatty stays false; a real CREATE_NEW_CONSOLE window is
     * a terminal but cannot be drained by the parent). The NEGATIVE half of
     * this contract — nothing leaks to a redirected stdout — is fully tested
     * by the other cases in this group, which do run here. */
    printf("wallet_phrase_never_logged: a real terminal DOES get the "
           "twelve words... SKIP (Windows): no posix_openpt/fork pty lane; "
           "the leak-negative cases above cover the custody invariant\n");
    return 0;
#else
    int failures = 0;
    char seen[32768];
    seen[0] = '\0';
    bool ran = false;

    int master = posix_openpt(O_RDWR | O_NOCTTY);
    if (master >= 0 && grantpt(master) == 0 && unlockpt(master) == 0) {
        const char *slave_path = ptsname(master);
        int slave = slave_path ? open(slave_path, O_RDWR | O_NOCTTY) : -1;
        if (slave >= 0) {
            fflush(stdout);
            fflush(stderr);
            pid_t pid = fork();
            if (pid == 0) {
                /* The child IS the "person watching stdout" case. */
                if (dup2(slave, STDOUT_FILENO) < 0)
                    _exit(2);
                close(slave);
                close(master);
                boot_wallet_show_recovery_phrase_once(WPL_PHRASE);
                fflush(stdout);
                _exit(0);
            }
            close(slave);   /* the child holds the only slave fd now */
            if (pid > 0) {
                size_t used = 0;
                while (used < sizeof(seen) - 1) {
                    ssize_t r = read(master, seen + used,
                                     sizeof(seen) - 1 - used);
                    if (r <= 0)
                        break;      /* EIO once the child's slave fd closes */
                    used += (size_t)r;
                }
                seen[used] = '\0';
                int st = 0;
                ran = waitpid(pid, &st, 0) == pid && WIFEXITED(st) &&
                      WEXITSTATUS(st) == 0;
            }
        }
    }
    if (master >= 0)
        close(master);

    /* Anti-vacuous: without a pty and a clean child exit the assertions below
     * would pass over an empty capture. */
    WPL_CHECK("a pty was available and the print ran on it", ran);
    WPL_CHECK("a real terminal DOES get the twelve words",
              ran && strstr(seen, WPL_PHRASE) != NULL);
    WPL_CHECK("and is told they are shown only once",
              ran && strstr(seen, "ONLY TIME THEY WILL EVER BE SHOWN") != NULL);
    /* The owner's approved wording, on the creation surface. Matched in
     * single-line fragments because a pty rewrites the line endings. */
    WPL_CHECK("and is told the words restore money in Z23 ONLY",
              ran && strstr(seen,
                  "These words restore your money in Z23 only.") != NULL);
    WPL_CHECK("and that they will not work in other wallet software",
              ran && strstr(seen, "not work in Electrum") != NULL &&
              strstr(seen, "wallet software") != NULL);
    return failures;
#endif
}

/* A declared throwaway lane, headless, end to end: a wallet IS created, and
 * not one word of a phrase reaches the redirected stdout. */
static int t_declared_lane_creates_without_a_phrase(const char *dir)
{
    int failures = 0;

    char sub[1200];
    snprintf(sub, sizeof(sub), "%s/lane", dir);
    mkdir(sub, 0700);
    char db_path[1400];
    snprintf(db_path, sizeof(db_path), "%s/node.db", sub);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool db_ok = node_db_open(&ndb, db_path) && ndb.open;
    WPL_CHECK("lane fixture node.db opened", db_ok);
    if (!db_ok)
        return failures;

    struct wallet_sqlite ws;
    struct zcl_result wr = wallet_sqlite_open_r(&ws, ndb.db);
    WPL_CHECK("lane fixture wallet tables opened", wr.ok);
    if (!wr.ok) { node_db_close(&ndb); return failures; }

    struct wallet *w = calloc(1, sizeof(*w));
    if (!w) {
        WPL_CHECK("lane fixture wallet allocated", false);
        wallet_sqlite_close(&ws);
        node_db_close(&ndb);
        return failures;
    }
    wallet_init(w);

    struct wpl_capture cap;
    bool began = wpl_capture_begin(&cap, dir, "lane");
    bool created = false;
    if (began)
        created = boot_wallet_create_new(w, &ws, &ndb,
                                         WALLET_BOOT_CREATE_PLAINTEXT,
                                         ZCL_OPERATOR_LANE_DEV);
    wpl_capture_end(&cap);
    WPL_CHECK("capture harness installed for the declared-lane creation",
              began);

    /* THE REGRESSION. This returned false, and boot turned it into exit(1)
     * on every restart. */
    WPL_CHECK("a DECLARED dev lane creates its wallet headlessly",
              began && created);
    WPL_CHECK("and it has real keys", w->keystore.num_keys > 0);
    WPL_CHECK("which reached the database", db_wallet_key_count(&ndb) > 0);

    char out[16384], err[16384];
    long n_out = wpl_slurp(cap.path_out, out, sizeof(out));
    long n_err = wpl_slurp(cap.path_err, err, sizeof(err));

    /* And the security property is intact: no phrase was drawn, so no
     * phrase can be in the capture — and no seed row was written either,
     * which is what "no phrase was drawn" means on disk. */
    WPL_CHECK("no phrase block reached the redirected stdout",
              n_out >= 0 && strstr(out, "WRITE THESE 12 WORDS DOWN") == NULL);
    WPL_CHECK("no recovery phrase was drawn at all (no wallet_seed row)",
              !wallet_sqlite_read_sapling_seed(&ws, (uint8_t[32]){0}));
    WPL_CHECK("the operator is told, loudly, that this wallet has no "
              "written backup",
              n_err > 0 && strstr(err, "NO RECOVERY PHRASE") != NULL);

    wallet_free(w);
    free(w);
    wallet_sqlite_close(&ws);
    node_db_close(&ndb);
    return failures;
}

/* ── THE SHIPPED UNIT'S OWN FIRST BOOT ──────────────────────────────────
 *
 * Nothing covered this, and that is why the crash loop shipped twice. The
 * canonical unit (platform/deploy/zclassic23.service) passes -operator-lane=canonical
 * and carries Restart=always, and the secure way to run it is with
 * ZCL_WALLET_PASSPHRASE set. On a brand-new data directory that combination
 * ran the refusal, exit(1), restart, forever — no wallet, ever.
 *
 * This walks the same three links a first boot walks, in order:
 *   1. the unit really does declare the canonical lane and really does restart
 *      always (asserted from the file, so this test cannot drift away from the
 *      thing it claims to cover);
 *   2. ZCL_WALLET_PASSPHRASE set resolves, on the canonical lane, to
 *      CREATE_ENCRYPTED — which is NOT WALLET_BOOT_REFUSE, so engine/composition/src/boot.c
 *      calls boot_wallet_create_new rather than booting keyless;
 *   3. that call, with stdout pointed at a file the way the unit points it at
 *      node.log, creates a real persisted wallet AND draws no phrase.
 *
 * What it does not do is fork the node binary — it drives the boot function
 * the boot path drives, on a fresh datadir, with the boot path's own inputs. */
static int t_canonical_service_first_boot_creates_a_wallet(const char *dir)
{
    int failures = 0;

    /* 1. The premise, read from the shipped unit. */
    char unit[65536];
    long n_unit = wpl_slurp("platform/deploy/zclassic23.service", unit, sizeof(unit));
    WPL_CHECK("the shipped unit file was readable", n_unit > 0);
    WPL_CHECK("the shipped unit declares the CANONICAL operator lane",
              n_unit > 0 && strstr(unit, "-operator-lane=canonical") != NULL);
    WPL_CHECK("the shipped unit restarts always (so a refusal is a crash "
              "loop, not a one-off)",
              n_unit > 0 && strstr(unit, "Restart=always") != NULL);
    WPL_CHECK("the shipped unit does NOT need -wallet-no-phrase-backup to "
              "come up",
              n_unit > 0 && strstr(unit, "wallet-no-phrase-backup") == NULL);

    /* 2. A passphrase, on the canonical lane, must reach a CREATE action —
     *    boot.c only calls the wallet creator when the decision is not
     *    WALLET_BOOT_REFUSE. */
    char *saved_pass = getenv("ZCL_WALLET_PASSPHRASE");
    char saved_copy[256] = "";
    bool had_pass = saved_pass != NULL;
    if (had_pass)
        snprintf(saved_copy, sizeof(saved_copy), "%s", saved_pass);
    setenv("ZCL_WALLET_PASSPHRASE", "a-real-operator-passphrase", 1);

    enum wallet_at_rest_policy policy = wallet_at_rest_creation_policy();
    WPL_CHECK("ZCL_WALLET_PASSPHRASE set means encrypt-at-rest",
              policy == WALLET_AT_REST_ENCRYPTED);
    enum wallet_boot_wallet_action act =
        wallet_at_rest_boot_decision(policy, /*is_mint=*/false,
                                     ZCL_OPERATOR_LANE_CANONICAL);
    WPL_CHECK("which on the canonical lane resolves to CREATE_ENCRYPTED",
              act == WALLET_BOOT_CREATE_ENCRYPTED);
    WPL_CHECK("and is therefore NOT the keyless no-spend path — boot.c does "
              "call the wallet creator", act != WALLET_BOOT_REFUSE);

    /* 3. The call itself, on a fresh datadir, stdout redirected to a file. */
    char sub[1200];
    snprintf(sub, sizeof(sub), "%s/canonical", dir);
    mkdir(sub, 0700);
    char db_path[1400];
    snprintf(db_path, sizeof(db_path), "%s/node.db", sub);

    struct node_db ndb;
    memset(&ndb, 0, sizeof(ndb));
    bool db_ok = node_db_open(&ndb, db_path) && ndb.open;
    WPL_CHECK("canonical fixture node.db opened", db_ok);
    if (!db_ok)
        goto restore_env;

    struct wallet_sqlite ws;
    struct zcl_result wr = wallet_sqlite_open_r(&ws, ndb.db);
    WPL_CHECK("canonical fixture wallet tables opened", wr.ok);
    if (!wr.ok) { node_db_close(&ndb); goto restore_env; }

    struct wallet *w = calloc(1, sizeof(*w));
    if (!w) {
        WPL_CHECK("canonical fixture wallet allocated", false);
        wallet_sqlite_close(&ws);
        node_db_close(&ndb);
        goto restore_env;
    }
    wallet_init(w);
    WPL_CHECK("the fixture datadir starts with no wallet at all",
              w->keystore.num_keys == 0 && db_wallet_key_count(&ndb) == 0);

    struct wpl_capture cap;
    bool began = wpl_capture_begin(&cap, dir, "canonical");
    bool created = false;
    if (began)
        created = boot_wallet_create_new(w, &ws, &ndb, act,
                                         ZCL_OPERATOR_LANE_CANONICAL);
    wpl_capture_end(&cap);
    WPL_CHECK("capture harness installed for the canonical first boot",
              began);

    /* THE REGRESSION. This returned false, and boot turned it into exit(1)
     * under Restart=always. */
    WPL_CHECK("a CANONICAL-lane node with a passphrase creates its wallet "
              "headlessly on a fresh datadir", began && created);
    WPL_CHECK("and comes up with a full keypool",
              w->keystore.num_keys == DEFAULT_KEYPOOL_SIZE);
    WPL_CHECK("which is on disk, not just in RAM",
              db_wallet_key_count(&ndb) == DEFAULT_KEYPOOL_SIZE);

    char out[16384], err[16384];
    long n_out = wpl_slurp(cap.path_out, out, sizeof(out));
    long n_err = wpl_slurp(cap.path_err, err, sizeof(err));

    /* The security property, unchanged: no phrase was drawn, so there is
     * nothing in the capture and no seed row on disk. */
    WPL_CHECK("no phrase block reached the redirected stdout",
              n_out >= 0 && strstr(out, "WRITE THESE 12 WORDS DOWN") == NULL);
    WPL_CHECK("no recovery phrase was drawn at all (no wallet_seed row)",
              !wallet_sqlite_read_sapling_seed(&ws, (uint8_t[32]){0}));
    WPL_CHECK("the operator is told, loudly, that this wallet has no "
              "written backup",
              n_err > 0 && strstr(err, "NO RECOVERY PHRASE") != NULL);
    WPL_CHECK("and is told which decision let it through",
              n_err > 0 && strstr(err, "ZCL_WALLET_PASSPHRASE") != NULL);
    WPL_CHECK("and is told how to get a wallet that HAS twelve words",
              n_err > 0 && strstr(err, "before any coins arrive") != NULL);
    WPL_CHECK("and the notice itself carries no phrase",
              n_err >= 0 && strstr(err, WPL_PHRASE) == NULL);

    wallet_free(w);
    free(w);
    wallet_sqlite_close(&ws);
    node_db_close(&ndb);

restore_env:
    if (had_pass)
        setenv("ZCL_WALLET_PASSPHRASE", saved_copy, 1);
    else
        unsetenv("ZCL_WALLET_PASSPHRASE");
    return failures;
}

/* Whatever still refuses must NAME the blocker where a node-free reader
 * finds it. A boot that exits leaving phase=loading / stage=db_open and no
 * reason is the silent halt this project says is unreachable. */
static int t_the_refusal_names_a_blocker(const char *dir)
{
    int failures = 0;

    char sub[1200];
    snprintf(sub, sizeof(sub), "%s/blocked", dir);
    mkdir(sub, 0700);

    /* An earlier case in this group drives the same refusal path, which
     * leaves the writer's blocker globals set. Clear them so "carries no
     * blocker yet" is a real precondition and not an accident of order. */
    boot_status_set_blocker(NULL, NULL);
    boot_status_init(sub);
    boot_status_note_stage((int)BOOT_STAGE_DB_OPEN);

    struct boot_status_snapshot before;
    char e1[128] = "";
    bool read_before = boot_status_read(sub, &before, e1, sizeof(e1));
    WPL_CHECK("a beacon exists before the refusal", read_before);
    WPL_CHECK("and it carries no blocker yet (else the check below is "
              "vacuous)", read_before && before.blocker[0] == '\0');

    /* The call boot.c makes immediately before exit(1). */
    boot_wallet_creation_blocked();

    struct boot_status_snapshot after;
    char e2[128] = "";
    bool read_after = boot_status_read(sub, &after, e2, sizeof(e2));
    WPL_CHECK("the beacon is still readable after the refusal", read_after);
    if (read_after)
        printf("    blocker=%s\n    reason=%.200s\n", after.blocker,
               after.blocker_reason);
    WPL_CHECK("boot_status.json now NAMES the blocker",
              read_after &&
              strcmp(after.blocker, "wallet_phrase_no_terminal") == 0);
    WPL_CHECK("and says, in plain English, what to do about it",
              read_after && strstr(after.blocker_reason, "terminal") != NULL &&
              strstr(after.blocker_reason, "-operator-lane") != NULL);
    /* And the way out SURVIVED the round trip. blocker_reason is char[256] and
     * the writer truncates silently, so a reason that outgrows it loses its
     * tail — which is exactly the half that tells the operator what to do. A
     * reason that no longer ends in a full stop was cut. */
    WPL_CHECK("and the reason was not silently truncated on the way to disk",
              read_after && after.blocker_reason[0] != '\0' &&
              after.blocker_reason[strlen(after.blocker_reason) - 1] == '.');

    boot_status_init(NULL);   /* disarm; leave no writer pointed at a tmpdir */
    return failures;
}

int test_wallet_phrase_never_logged(void);
int test_wallet_phrase_never_logged(void)
{
    printf("\n=== the twelve words never reach a log file ===\n");
    int failures = 0;

    char dir[256];
    test_fmt_tmpdir(dir, sizeof(dir), "wallet_phrase_log", "main");
    mkdir("./test-tmp", 0700);
    test_rm_rf(dir);
    if (mkdir(dir, 0700) != 0) {
        printf("wallet_phrase_never_logged: could not make %s... FAIL\n", dir);
        return 1;
    }

    failures += t_terminal_probe_tells_the_truth(dir);
    failures += t_capture_would_catch_a_leak(dir);
    failures += t_creation_refuses_and_leaves_nothing(dir);
    failures += t_direct_print_is_also_refused(dir);
    failures += t_a_real_terminal_gets_the_words_and_the_warning();
    failures += t_refusal_is_scoped_to_a_spendable_wallet();
    failures += t_declared_lane_creates_without_a_phrase(dir);
    failures += t_canonical_service_first_boot_creates_a_wallet(dir);
    failures += t_the_refusal_names_a_blocker(dir);

    test_rm_rf(dir);
    return failures;
}
