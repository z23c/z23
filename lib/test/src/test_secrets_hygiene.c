/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Secrets hygiene audit — the single most embarrassing bug we could
 * ship is logging a private key, seed phrase, or wallet secret to
 * stdout / stderr / the event log / an RPC response.
 *
 * This test file is the runtime half of the audit. The static half is
 * tools/scripts/check_no_secret_printf.sh, a grep-based scan for
 * printf-family calls that reference variables with key-shaped
 * identifier names. The shell script is the first line of defence (it
 * catches new leaks at CI time); the tests here are the second (they
 * catch leaks that the grep heuristic would miss — e.g. a secret
 * threaded through several function calls before being logged).
 *
 * Strategy:
 *   1. Build a "golden corpus" of fake secrets — strings that would
 *      obviously be catastrophic if they appeared in any log output.
 *      These strings are never used as real keys, so any code path
 *      that echoes them has a genuine hygiene bug.
 *   2. Run the known-clean surfaces (native command registry menu/describe
 *      JSON, event log after innocuous activity) and assert that none of
 *      the corpus strings appear.
 *   3. Run the check_no_secret_printf.sh script via system(3) and
 *      require exit code 0.
 *   4. Positive control: verify the scanner WOULD catch a secret if
 *      one were injected. This is how we know the test isn't silently
 *      green because the scan logic is broken.
 */

#include "test/test_core.h"
#include "config/command_catalog.h"
#include "kernel/command_registry.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if !defined(_WIN32)
#include <sys/wait.h>
#endif
#include <unistd.h>
#include "util/safe_alloc.h"

#if defined(_WIN32)
/* The UCRT system() returns the child's raw exit code, not a wait(2)
 * status word; map the two macros onto that honestly. cmd.exe cannot run
 * the POSIX lint script, so it is dispatched through the MSYS2 sh on the
 * lane's PATH. */
#define WIFEXITED(s) ((s) >= 0)
#define WEXITSTATUS(s) (s)
#endif

/* ── Golden corpus ─────────────────────────────────────────── */

/* Fake WIF-shaped string (starts with the mainnet "L" prefix). Not a
 * real key — constructed from a deterministic pattern so we can scan
 * for it without worrying about accidental collisions. */
#define CORPUS_WIF      "L5HygienePLACEHOLDERwifNEVERrealKEY111111"

/* Fake 64-hex private key. */
#define CORPUS_PRIVHEX  "deadbeefcafebabe0123456789abcdef" \
                        "fedcba9876543210deadbeefcafebabe"

/* Fake 24-word BIP39 mnemonic. Each word is "hygiene". Real mnemonics
 * use real words; this is obviously synthetic but matches the shape
 * (space-separated tokens) a scanner might look for. */
#define CORPUS_MNEMONIC "hygiene hygiene hygiene hygiene hygiene "   \
                        "hygiene hygiene hygiene hygiene hygiene "   \
                        "hygiene hygiene hygiene hygiene hygiene "   \
                        "hygiene hygiene hygiene hygiene hygiene "   \
                        "hygiene hygiene hygiene hygiene"

/* Fake Sapling extended spending key (extspk) — starts with zxviews*/
#define CORPUS_EXTSPK   "secret-extended-key-test-HYGIENEplaceholder"

/* Fake RPC cookie contents. */
#define CORPUS_COOKIE   "__cookie__:HYGIENEcookieNEVERrealXXXXXXXX"

/* Fake Tor onion service private key (first line of hs_ed25519_secret_key). */
#define CORPUS_HS_PRIV  "== ed25519v1-secret: type0 ==HYGIENEonionkey"

static const char *const g_corpus[] = {
    CORPUS_WIF,
    CORPUS_PRIVHEX,
    CORPUS_MNEMONIC,
    CORPUS_EXTSPK,
    CORPUS_COOKIE,
    CORPUS_HS_PRIV,
};

static const size_t g_corpus_count = sizeof(g_corpus) / sizeof(g_corpus[0]);

/* Portable substring search — avoids the glibc-specific memmem so we
 * work under strict _POSIX_C_SOURCE. Returns a pointer into haystack
 * or NULL. */
static const char *find_sub(const char *haystack, size_t h_len,
                             const char *needle, size_t n_len)
{
    if (n_len == 0 || n_len > h_len) return NULL;
    for (size_t i = 0; i + n_len <= h_len; i++) {
        if (memcmp(haystack + i, needle, n_len) == 0)
            return haystack + i;
    }
    return NULL;
}

/* Scan a buffer for every corpus member. Returns the number of hits.
 * On a hit, prints the matched corpus member (but not the surrounding
 * context, to avoid leaking whatever was wrongly printed to the test
 * log itself). */
static int scan_for_corpus(const char *buf, size_t len, const char *label)
{
    int hits = 0;
    for (size_t i = 0; i < g_corpus_count; i++) {
        size_t nlen = strlen(g_corpus[i]);
        if (find_sub(buf, len, g_corpus[i], nlen) != NULL) {
            printf("LEAK[%s]: corpus entry %zu found\n", label, i);
            hits++;
        }
    }
    return hits;
}

/* ── Individual tests ──────────────────────────────────────── */

static int test_corpus_setup(void)
{
    int failures = 0;
    TEST("secrets_hygiene: golden corpus is non-empty and non-trivial") {
        ASSERT(g_corpus_count >= 5);
        for (size_t i = 0; i < g_corpus_count; i++) {
            ASSERT(g_corpus[i] != NULL);
            /* Every corpus string should be long enough that an accidental
             * substring match against arbitrary output is improbable. */
            ASSERT(strlen(g_corpus[i]) >= 20);
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_positive_control(void)
{
    int failures = 0;
    TEST("secrets_hygiene: positive control — scanner catches a leak") {
        /* Build a buffer that contains one of the corpus entries and
         * make sure the scanner reports it. If this fails, the rest of
         * the test file is lying to us — every "clean" result would be
         * a false negative. */
        char buf[1024];
        snprintf(buf, sizeof(buf),
                 "some prefix %s some suffix", CORPUS_WIF);
        int hits = scan_for_corpus(buf, strlen(buf), "positive_control");
        ASSERT(hits >= 1);
        PASS();
    } _test_next:;
    return failures;
}

/* The native command registry's menu/describe JSON is the most widely
 * inspected JSON surface the agent sees — a corpus leak here would be the
 * loudest possible bug. */
static int test_native_registry_clean(void)
{
    int failures = 0;
    TEST("secrets_hygiene: native command registry JSON has no corpus "
         "leaks") {
        const struct zcl_command_registry *reg = zcl_command_catalog();
        ASSERT(reg != NULL);
        char *buf = zcl_malloc(256 * 1024, "test_native_registry_buf");
        ASSERT(buf != NULL);
        int hits = 0;

        size_t n = zcl_command_registry_menu_json(reg, "root", buf,
                                                   256 * 1024);
        ASSERT(n > 0);
        hits += scan_for_corpus(buf, n, "native_root_menu");

        static const char *const branches[] = {
            "core", "app", "dev", "ops", "discover", "code", "status",
        };
        for (size_t i = 0; i < sizeof(branches) / sizeof(branches[0]);
             i++) {
            n = zcl_command_registry_menu_json(reg, branches[i], buf,
                                               256 * 1024);
            if (n == 0)
                continue;
            hits += scan_for_corpus(buf, n, "native_branch_menu");
        }

        for (size_t i = 0; i < reg->count; i++) {
            n = zcl_command_registry_describe_json(
                reg, reg->commands[i].path, buf, 256 * 1024);
            if (n == 0)
                continue;
            hits += scan_for_corpus(buf, n, "native_describe");
        }

        ASSERT_EQ(hits, 0);
        free(buf);
        PASS();
    } _test_next:;
    return failures;
}

/* Resolve the path to tools/scripts/check_no_secret_printf.sh relative
 * to the current working directory. Test is invoked from the repo root
 * via build/bin/test_zcl. */
static int test_check_no_secret_printf_script(void)
{
    int failures = 0;
    TEST("secrets_hygiene: check_no_secret_printf.sh runs clean") {
        const char *path = "tools/scripts/check_no_secret_printf.sh";
        struct stat st;
        ASSERT(stat(path, &st) == 0);
        /* Must be executable — CI runs it directly. */
        ASSERT(st.st_mode & S_IXUSR);

        /* Run silently and inspect the exit code. If the script ever
         * flags a real leak, the test blows up with a clear signal. */
#if defined(_WIN32)
        int rc = system("sh -c \"tools/scripts/check_no_secret_printf.sh"
                        " >/dev/null 2>&1\"");
#else
        int rc = system("tools/scripts/check_no_secret_printf.sh >/dev/null 2>&1");
#endif
        ASSERT(WIFEXITED(rc));
        int exit_status = WEXITSTATUS(rc);
        if (exit_status != 0) {
            printf("FAIL (check_no_secret_printf.sh exited %d)\n",
                   exit_status);
            failures++;
            /* Re-run with output so the diff is visible. */
#if defined(_WIN32)
            (void)system("sh -c \"tools/scripts/check_no_secret_printf.sh"
                         " 2>&1 | head -40\"");
#else
            (void)system("tools/scripts/check_no_secret_printf.sh 2>&1 "
                         "| head -40");
#endif
            goto _test_next;
        }
        PASS();
    } _test_next:;
    return failures;
}

static int test_recover_tool_path_documented(void)
{
    int failures = 0;
    TEST("secrets_hygiene: every key-printing allowlist entry names a real file") {
        /* tools/wallet_dump.c is the only file that legitimately prints
         * raw key material, and only because offline key export is its
         * whole purpose. The allowlist in check_no_secret_printf.sh names
         * it explicitly.
         *
         * This test used to assert a fixed set of names. That was the weak
         * shape: tools/wallet_recover.c was retired upstream, its allowlist
         * entry was correctly removed with it, and the test then failed for
         * naming a file that no longer exists — pointing at the wrong side.
         * The assertion that actually protects us is structural: every
         * allowlist entry must name a file that EXISTS. A stale entry is a
         * standing permission to print secrets from a path nobody reviews
         * any more, and if that path is ever recreated it arrives
         * pre-approved. So the allowlist must not outlive its files. */
        FILE *f = fopen("tools/scripts/check_no_secret_printf.sh", "r");
        ASSERT(f != NULL);
        char line[512];
        bool saw_wallet_dump = false;
        int allowlist_entries = 0;
        int missing_files = 0;
        bool in_allowlist = false;
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, "ALLOWLIST_RE=(")) {
                in_allowlist = true;
                continue;
            }
            if (!in_allowlist)
                continue;
            /* Allowlist ends at a line whose first non-whitespace char is
             * ')'. We can't key off any ')' because the justification
             * comments may contain parentheses. */
            const char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == ')') {
                in_allowlist = false;
                continue;
            }
            /* Only lines that start with a single quote are regex entries;
             * the rest are explanatory comments. */
            if (*p != '\'')
                continue;
            allowlist_entries++;
            if (strstr(line, "wallet_dump"))
                saw_wallet_dump = true;
            /* Turn the regex back into a path. These entries are literal
             * paths with '.' escaped; anything with a real metacharacter
             * is not a plain path and is not resolved here — it is counted
             * as missing so that a wildcard entry, which would silently
             * widen the allowlist, cannot pass this check either. */
            char path[512];
            size_t n = 0;
            const char *q = p + 1;
            bool literal = true;
            while (*q && *q != '\'' && n + 1 < sizeof(path)) {
                if (*q == '\\') {
                    q++;
                    if (*q != '.') { literal = false; break; }
                } else if (strchr("*?+[](){}|^$", *q) != NULL) {
                    literal = false;
                    break;
                }
                path[n++] = *q++;
            }
            path[n] = '\0';
            if (!literal || n == 0 || access(path, F_OK) != 0) {
                printf("\n  stale or non-literal allowlist entry: %s", path);
                missing_files++;
            }
        }
        fclose(f);
        /* A zero-entry allowlist would satisfy "no stale entries"
         * vacuously, so pin the floor too. */
        ASSERT(allowlist_entries >= 1);
        ASSERT(saw_wallet_dump);
        ASSERT(missing_files == 0);
        /* Allowlist growing past 5 is a smell — someone is papering
         * over a class of leak instead of fixing call sites. */
        ASSERT(allowlist_entries <= 5);
        PASS();
    } _test_next:;
    return failures;
}

/* ── Entry point ─────────────────────────────────────────── */

int test_secrets_hygiene(void);

int test_secrets_hygiene(void)
{
    int failures = 0;

    printf("\n=== secrets_hygiene ===\n");

    failures += test_corpus_setup();
    failures += test_positive_control();
    failures += test_native_registry_clean();
    failures += test_check_no_secret_printf_script();
    failures += test_recover_tool_path_documented();

    return failures;
}
