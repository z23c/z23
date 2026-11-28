/* purpose: exercise real-node regtest and Ironwood sync and restart. */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
#include "test/regtest_node_fixture.h"

#define IW_BALLOT "bb447e1ae3827c976f4ff08a5b5ac7379fa486ce1bc13480f3e9db7e0dc733af"
#define IW_FIXTURE "tests/fixtures/ironwood/selected-manifest.json"
#define IW_CMD_MS 120000L
#define IW_SYNC_MS 180000L

struct iw_state {
    struct rnf miner, follower;
    char raw[RNF_RAW], address[256], tip[80];
    bool research;
};

static struct iw_state iw;
static volatile sig_atomic_t iw_miner_pid, iw_follower_pid;
static struct sigaction iw_old_int, iw_old_term;
static bool iw_armed;
static volatile sig_atomic_t iw_interrupted;

static void iw_signal(int sig)
{
    if (iw_miner_pid > 0) kill(-(pid_t)iw_miner_pid, SIGKILL);
    if (iw_follower_pid > 0) kill(-(pid_t)iw_follower_pid, SIGKILL);
    iw_interrupted = sig;
}

static void iw_cleanup(void)
{
    rnf_node_stop(&iw.miner);
    iw_miner_pid = 0;
    rnf_node_stop(&iw.follower);
    iw_follower_pid = 0;
    if (iw_armed) {
        sigaction(SIGINT, &iw_old_int, NULL);
        sigaction(SIGTERM, &iw_old_term, NULL);
        iw_armed = false;
    }
    if (iw.miner.work[0]) test_rm_rf(iw.miner.work);
    if (iw.follower.work[0]) test_rm_rf(iw.follower.work);
    iw.miner.work[0] = iw.follower.work[0] = '\0';
}

static void iw_arm(void)
{
    struct sigaction sa = {0};
    sa.sa_handler = iw_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, &iw_old_int);
    sigaction(SIGTERM, &sa, &iw_old_term);
    iw_armed = true;
}

static bool iw_write(const char *path, const char *text)
{
    FILE *f = fopen(path, "wb");
    if (!f) return false;
    bool ok = fputs(text, f) >= 0;
    return fclose(f) == 0 && ok;
}

static bool iw_copy_ballot(const char *path)
{
    FILE *in = fopen(IW_FIXTURE, "rb");
    if (!in) return false;
    FILE *out = fopen(path, "wb");
    if (!out) { fclose(in); return false; }
    char buf[4096];
    size_t n;
    bool ok = true;
    while ((n = fread(buf, 1, sizeof(buf), in)) != 0)
        if (fwrite(buf, 1, n, out) != n) { ok = false; break; }
    if (ferror(in)) ok = false;
    if (fclose(in) != 0) ok = false;
    if (fclose(out) != 0) ok = false;
    return ok;
}

static bool iw_prepare(struct rnf *e, const char *tag)
{
    if (!rnf_setup(e, tag)) return false;
    if (!iw.research) return true;
    char dir[PATH_MAX + 64], path[PATH_MAX + 160];
    snprintf(dir, sizeof(dir), "%s/datadir/ironwood-research", e->work);
    if (mkdir(dir, 0700) != 0) return false;
    snprintf(path, sizeof(path), "%s/.z23-research-profile", dir);
    if (!iw_write(path, "z23-research-profile:ironwood:v1\n")) return false;
    snprintf(path, sizeof(path), "%s/ballots", dir);
    if (mkdir(path, 0700) != 0) return false;
    snprintf(path, sizeof(path), "%s/ballots/%s.json", dir, IW_BALLOT);
    if (!iw_copy_ballot(path)) return false;
    int n = snprintf(e->dd_flag, sizeof(e->dd_flag), "-datadir=%s", dir);
    return n > 0 && (size_t)n < sizeof(e->dd_flag);
}

static void iw_env(const struct rnf *e, char *home, size_t home_cap,
                   char *cred, size_t cred_cap, char **env)
{
    snprintf(home, home_cap, "HOME=%s", e->work);
    snprintf(cred, cred_cap, "CREDENTIALS_DIRECTORY=%s", e->cred);
    env[0] = home;
    env[1] = (char *)"PATH=/usr/bin:/bin";
    env[2] = cred;
    env[3] = (char *)"ZCL_CLI_TEST_NO_SERVICE_LOOKUP=1";
    env[4] = NULL;
}

static void iw_node_child(const struct rnf *e, uint16_t peer, pid_t parent)
{
    if (!rnf_child_die_with_parent(parent)) _exit(127);
    setpgid(0, 0);
    char log[PATH_MAX + 16], dd[PATH_MAX + 32], port[32], connect[64];
    char home[PATH_MAX + 16], cred[PATH_MAX + 64], *env[5];
    snprintf(log, sizeof(log), "%s/node.log", e->work);
    int fd = open(log, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) _exit(127);
    if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) _exit(127);
    close(fd);
    snprintf(dd, sizeof(dd), "-datadir=%s/datadir", e->work);
    snprintf(port, sizeof(port), "-port=%u", e->port[0]);
    snprintf(connect, sizeof(connect), "-connect=127.0.0.1:%u", peer ? peer : 1);
    iw_env(e, home, sizeof(home), cred, sizeof(cred), env);
    char *argv[] = { (char *)RNF_BIN, (char *)"-testnet-profile=ironwood",
        dd, (char *)"-testballotcatalog=" IW_BALLOT, port, (char *)e->rpc_flag,
        (char *)"-operator-lane=dev", (char *)"-wallet-no-phrase-backup",
        (char *)"-walletbackup=0", (char *)"-nobgvalidation",
        (char *)"-showmetrics=0", (char *)"-packagehost=0",
        (char *)"-private-listeners", (char *)"-bind=127.0.0.1",
        (char *)"-no-tor", connect, NULL };
    if (!iw.research) {
        argv[1] = (char *)"-regtest";
        argv[3] = (char *)"-regtest";
    }
    execve(RNF_BIN, argv, env);
    _exit(127);
}

static bool iw_start(struct rnf *e, uint16_t peer, volatile sig_atomic_t *slot)
{
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) iw_node_child(e, peer, parent);
    setpgid(pid, pid);
    e->node = pid;
    *slot = (sig_atomic_t)pid;
    return true;
}

static void iw_exec_child(const struct rnf *e, const char *const *words, int *p)
{
    if (dup2(p[1], STDOUT_FILENO) < 0 || dup2(p[1], STDERR_FILENO) < 0) _exit(127);
    close(p[0]);
    close(p[1]);
    char home[PATH_MAX + 16], cred[PATH_MAX + 64], *env[5];
    iw_env(e, home, sizeof(home), cred, sizeof(cred), env);
    char *argv[RNF_MAX_WORDS + 4];
    size_t n = 0;
    argv[n++] = (char *)RNF_BIN;
    argv[n++] = (char *)e->dd_flag;
    argv[n++] = (char *)e->rpc_flag;
    for (size_t i = 0; words[i] && n < RNF_MAX_WORDS + 3; i++)
        argv[n++] = (char *)words[i];
    argv[n] = NULL;
    execve(RNF_BIN, argv, env);
    _exit(127);
}

static int iw_wait_child(pid_t pid, long deadline)
{
    int status = 0;
    while (rnf_now_ms() < deadline) {
        pid_t got = waitpid(pid, &status, WNOHANG);
        if (got == pid) return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (got < 0) return -1;
        if (iw_interrupted) break;
        rnf_sleep_ms(50);
    }
    printf("RPC deadline expired, terminating pid %ld\n", (long)pid);
    kill(pid, SIGKILL);
    (void)waitpid(pid, &status, 0);
    return -1;
}

static int iw_call(struct rnf *e, const char *const *words)
{
    int p[2];
    iw.raw[0] = '\0';
    printf("RPC %s waiting\n", words[0]);
    fflush(stdout);
    if (pipe(p) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); return -1; }
    if (pid == 0) iw_exec_child(e, words, p);
    close(p[1]);
    /* real-clock: bound the external RPC and report its reply or timeout. */
    long deadline = rnf_now_ms() + IW_CMD_MS;
    rnf_read_until(p[0], iw.raw, sizeof(iw.raw), deadline);
    close(p[0]);
    int rc = iw_wait_child(pid, deadline);
    printf("RPC %s rc=%d raw:\n%s\n", words[0], rc, iw.raw);
    fflush(stdout);
    return rc;
}

static bool iw_clean_reply(int rc)
{
    return rc == 0 && strstr(iw.raw, "error") == NULL &&
           strstr(iw.raw, "Error") == NULL;
}

static bool iw_scalar(char *dst, size_t cap)
{
    size_t n = strcspn(iw.raw, "\r\n");
    if (n == 0 || n >= cap || iw.raw[n + strspn(iw.raw + n, "\r\n")] != '\0')
        return false;
    memcpy(dst, iw.raw, n);
    dst[n] = '\0';
    return true;
}

static bool iw_hashes(size_t count)
{
    struct json_value doc;
    if (!rnf_parse(iw.raw, &doc)) return false;
    bool ok = doc.type == JSON_ARR && doc.num_children == count;
    for (size_t i = 0; ok && i < doc.num_children; i++) {
        const char *hash = json_get_str(&doc.children[i]);
        if (!hash || strlen(hash) != 64) ok = false;
    }
    json_free(&doc);
    return ok;
}

static bool iw_wait_up(struct rnf *e)
{
    const char *const words[] = { "getblockchaininfo", NULL };
    for (int attempt = 0; attempt < 240; attempt++) {
        int status;
        if (waitpid(e->node, &status, WNOHANG) == e->node) {
            printf("node exited before ready: status=%d\n", status);
            e->node = 0;
            return false;
        }
        int rc = iw_call(e, words);
        struct json_value doc;
        if (rc == 0) {
            if (!iw_clean_reply(rc) || !rnf_parse(iw.raw, &doc)) return false;
            bool up = strcmp(rnf_str(&doc, "chain"),
                             iw.research ? "ironwood" : "regtest") == 0;
            const struct json_value *blocks = rnf_at(&doc, "blocks");
            up = up && blocks && blocks->type == JSON_INT;
            json_free(&doc);
            return up;
        }
        if (iw_interrupted) return false;
        rnf_sleep_ms(500);
    }
    printf("readiness deadline: waiting for chain=ironwood\n");
    return false;
}

static bool iw_chain(struct rnf *e, int *height, char *hash, size_t cap)
{
    const char *const count[] = { "getblockcount", NULL };
    const char *const best[] = { "getbestblockhash", NULL };
    if (!iw_clean_reply(iw_call(e, count))) return false;
    char text[32], *end;
    if (!iw_scalar(text, sizeof(text))) return false;
    long n = strtol(text, &end, 10);
    if (*end || n < 0 || n > INT32_MAX) return false;
    *height = (int)n;
    if (!iw_clean_reply(iw_call(e, best)) || !iw_scalar(hash, cap)) return false;
    return strlen(hash) == 64;
}

static bool iw_agree(int expected, const char *expected_hash)
{
    /* real-clock: bound independent-node synchronization polling. */
    long deadline = rnf_now_ms() + IW_SYNC_MS;
    while (rnf_now_ms() < deadline) {
        int a = -1, b = -1;
        char ah[80] = "", bh[80] = "";
        bool miner = iw_chain(&iw.miner, &a, ah, sizeof(ah));
        bool follower = iw_chain(&iw.follower, &b, bh, sizeof(bh));
        printf("sync poll miner=%d %s follower=%d %s expected=%d %s\n",
               a, ah, b, bh, expected, expected_hash);
        if (miner && follower && a == expected && b == expected &&
            strcmp(ah, expected_hash) == 0 && strcmp(ah, bh) == 0) return true;
        if (iw_interrupted) return false;
        rnf_sleep_ms(500);
    }
    printf("sync deadline: waiting for height %d hash %s\n", expected, expected_hash);
    return false;
}

static bool iw_stop(struct rnf *node, volatile sig_atomic_t *slot)
{
    pid_t pid = node->node;
    if (pid <= 0) return false;
    kill(-pid, SIGTERM);
    /* real-clock: bound clean shutdown before reporting its exit status. */
    long deadline = rnf_now_ms() + 60000L;
    int rc = iw_wait_child(pid, deadline);
    node->node = 0;
    *slot = 0;
    printf("node clean-stop exit=%d\n", rc);
    return rc == 0;
}

static uint16_t iw_free_port(const uint16_t *used, size_t n)
{
    for (int attempt = 0; attempt < 100; attempt++) {
        uint16_t port = rnf_reserve_port();
        if (!port || port == 28023 || port == 28033) continue;
        bool unique = true;
        for (size_t i = 0; i < n; i++)
            if (port == used[i]) unique = false;
        if (unique) return port;
    }
    return 0;
}

static bool iw_ports(void)
{
    uint16_t ports[4];
    for (size_t i = 0; i < 4; i++) {
        ports[i] = iw_free_port(ports, i);
        if (!ports[i]) return false;
    }
    iw.miner.port[0] = ports[0];
    iw.miner.port[1] = ports[1];
    iw.follower.port[0] = ports[2];
    iw.follower.port[1] = ports[3];
    snprintf(iw.miner.rpc_flag, sizeof(iw.miner.rpc_flag), "-rpcport=%u", ports[1]);
    snprintf(iw.follower.rpc_flag, sizeof(iw.follower.rpc_flag), "-rpcport=%u", ports[3]);
    return true;
}

static int iw_boot(void)
{
    int failures = 0, height = -1;
    char hash[80];
    TEST(iw.research ? "research boot" : "regtest boot") {
        ASSERT(iw_prepare(&iw.miner, "ironwood_miner"));
        ASSERT(iw_prepare(&iw.follower, "ironwood_follower"));
        ASSERT(iw_ports());
        ASSERT(iw_start(&iw.miner, 0, &iw_miner_pid));
        ASSERT(iw_wait_up(&iw.miner));
        ASSERT(iw_chain(&iw.miner, &height, hash, sizeof(hash)));
        ASSERT_EQ(height, 0);
        PASS();
    } _test_next:;
    return failures;
}

static bool iw_mine_batch(const char *amount, size_t expected)
{
    const char *const mine[] = { "generatetoaddress", amount, iw.address, NULL };
    return iw_clean_reply(iw_call(&iw.miner, mine)) && iw_hashes(expected);
}

static int iw_mine(void)
{
    int failures = 0, height = -1;
    char hash[80];
    const char *const address[] = { "getnewaddress", NULL };
    const char *const balance[] = { "getbalance", NULL };
    TEST(iw.research ? "research mine" : "regtest mine") {
        ASSERT(iw_clean_reply(iw_call(&iw.miner, address)));
        ASSERT(iw_scalar(iw.address, sizeof(iw.address)));
        ASSERT(iw_mine_batch("1", 1));
        for (int i = 0; i < 10; i++) {
            ASSERT(iw_mine_batch("10", 10));
        }
        ASSERT(iw_chain(&iw.miner, &height, hash, sizeof(hash)));
        ASSERT_EQ(height, 101);
        ASSERT(iw_clean_reply(iw_call(&iw.miner, balance)));
        ASSERT(rnf_zats(iw.raw) > 0);
        snprintf(iw.tip, sizeof(iw.tip), "%s", hash);
        PASS();
    } _test_next:;
    return failures;
}

static int iw_sync(void)
{
    int failures = 0;
    TEST(iw.research ? "research sync" : "regtest sync") {
        ASSERT(iw_start(&iw.follower, iw.miner.port[0], &iw_follower_pid));
        ASSERT(iw_wait_up(&iw.follower));
        ASSERT(iw_agree(101, iw.tip));
        printf("SYNC height=101 hash=%s\n", iw.tip);
        PASS();
    } _test_next:;
    return failures;
}

static int iw_restart(void)
{
    int failures = 0, height = -1;
    char hash[80];
    TEST(iw.research ? "research restart" : "regtest restart") {
        ASSERT(iw_stop(&iw.follower, &iw_follower_pid));
        ASSERT(iw_stop(&iw.miner, &iw_miner_pid));
        ASSERT(iw_start(&iw.miner, 0, &iw_miner_pid));
        ASSERT(iw_wait_up(&iw.miner));
        ASSERT(iw_start(&iw.follower, iw.miner.port[0], &iw_follower_pid));
        ASSERT(iw_wait_up(&iw.follower));
        ASSERT(iw_chain(&iw.miner, &height, hash, sizeof(hash)));
        ASSERT_EQ(height, 101);
        ASSERT_STR_EQ(hash, iw.tip);
        ASSERT(iw_agree(101, iw.tip));
        printf("RESTART height=101 hash=%s\n", iw.tip);
        PASS();
    } _test_next:;
    return failures;
}

static int iw_run_profile(bool research)
{
    memset(&iw, 0, sizeof(iw));
    iw.research = research;
    int failures = iw_boot();
    if (!failures) failures += iw_mine();
    if (!failures) failures += iw_sync();
    if (!failures) failures += iw_restart();
    if (failures) { rnf_log_tail(&iw.miner); rnf_log_tail(&iw.follower); }
    iw_cleanup();
    return failures;
}

int test_ironwood_node_e2e(void);
int test_ironwood_node_e2e(void)
{
    printf("\n=== Real-node sync and restart ===\n");
    if (access(RNF_BIN, X_OK) != 0) {
        printf("  UNOBSERVED (%s absent - build it with make z23)\n", RNF_BIN);
        return 0;
    }
    atexit(iw_cleanup);
    iw_arm();
    int failures = iw_run_profile(false);
    if (!iw_interrupted) {
        iw_arm();
        failures += iw_run_profile(true);
    }
    return failures;
}
